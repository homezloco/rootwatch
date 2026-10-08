const {
  app,
  BrowserWindow,
  Tray,
  Menu,
  ipcMain,
  shell,
  Notification,
  safeStorage,
  nativeImage,
  session,
  screen,
} = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const collector = require("./collector.cjs");
const device = require("./device.cjs");
const db = require("./db.cjs");
const navGuard = require("./nav-guard.cjs");

const DEFAULT_URL = "https://rootwatch.dev";
const CONFIG_PATH = path.join(app.getPath("userData"), "connection.json");
const POLL_MS = 60_000;

// Both directions of this bug exist in the wild: Wayland+Vulkan on some
// drivers (GNOME/NVIDIA) renders an invisible window ("--ozone-platform=
// wayland is not compatible with Vulkan"), while the forced-X11 fallback
// produces the same invisible window on other stacks. Let Chromium pick
// the session's native platform ("auto" → wayland on wayland); force the
// X11/software path only via ROOTWATCH_X11=1 or an explicit flag.
if (
  process.platform === "linux" &&
  !process.env.ELECTRON_OZONE_PLATFORM_HINT &&
  !process.argv.some((a) => a.startsWith("--ozone-platform"))
) {
  if (process.env.ROOTWATCH_X11 === "1") {
    app.commandLine.appendSwitch("ozone-platform", "x11");
    // XWayland + some driver stacks segfault the GPU process (exit 139 →
    // crash loop) — go straight to software rendering.
    app.disableHardwareAcceleration();
  } else {
    app.commandLine.appendSwitch("ozone-platform-hint", "auto");
  }
}

const LOG_PATH = path.join(app.getPath("userData"), "device.log");
/** Rolling one-file log (~256 KiB) — the only diagnostics support can ask for. */
function log(...args) {
  const line = `${new Date().toISOString()} ${args.join(" ")}`;
  console.log(line);
  try {
    const st = fs.existsSync(LOG_PATH) ? fs.statSync(LOG_PATH) : null;
    if (st && st.size > 256 * 1024) fs.truncateSync(LOG_PATH);
    fs.appendFileSync(LOG_PATH, line + "\n");
  } catch {
    /* logging must never crash the app */
  }
}

let mainWindow = null;
let tray = null;
let config = null;
let pollTimer = null;
let seenEventIds = new Set();
let pollBaselineSet = false;
let lastScore = null;
let driftTimer = null;
let listenerBaseline = null; // Set<'pid:port:proto'> — null until first pass seeds it
let knownListenerNames = null; // Set<string> — exe names seen listening before this tick

// ---------------------------------------------------------------------------
// Connection config — token is encrypted at rest via the OS keychain
// (safeStorage → org.freedesktop.secrets). If no keychain is available the
// token is kept in memory only and the tray simply has less to work with.
// ---------------------------------------------------------------------------

function decryptField(entry, key) {
  const enc = entry[key];
  if (!enc || !safeStorage.isEncryptionAvailable()) return null;
  try {
    return safeStorage.decryptString(Buffer.from(enc, "base64"));
  } catch {
    return null;
  }
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
    raw.token = decryptField(raw, "tokenEnc");
    // The device's write-scope enrollment token — separate from the
    // dashboard-connection token above.
    raw.deviceToken = decryptField(raw, "deviceTokenEnc");
    return raw;
  } catch {
    return null;
  }
}

function saveConfig(url, token, extras = {}) {
  const entry = { url };
  if (token && safeStorage.isEncryptionAvailable()) {
    entry.tokenEnc = safeStorage.encryptString(token).toString("base64");
  }
  // Preserve the paired-device token across connection saves on the same
  // instance; extras.deviceToken explicitly sets (string) or clears (null).
  const deviceToken = Object.hasOwn(extras, "deviceToken")
    ? extras.deviceToken
    : config?.deviceToken;
  if (deviceToken && safeStorage.isEncryptionAvailable()) {
    entry.deviceTokenEnc = safeStorage.encryptString(deviceToken).toString("base64");
  }
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(entry, null, 2), { mode: 0o600 });
  return { ...entry, token: token || null, deviceToken: deviceToken || null };
}

function clearConfig() {
  try {
    fs.unlinkSync(CONFIG_PATH);
  } catch {}
}

function normalizeUrl(input) {
  let u = String(input || "").trim();
  if (!u) u = DEFAULT_URL;
  if (!/^https?:\/\//i.test(u)) u = `https://${u}`;
  u = u.replace(/\/+$/, "");
  const parsed = new URL(u); // throws on malformed
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("URL must be http or https");
  }
  return parsed.origin;
}

/** Prove the URL is a RootWatch instance. /api/v1/org must answer 401 with
 *  our error envelope when no token is supplied, 200 with a valid one. */
async function checkInstance(url, token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  let res;
  try {
    res = await fetch(`${url}/api/v1/org`, {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new Error(
      `Could not reach ${url} — is the server running? (${err?.name === "TimeoutError" ? "timed out" : err?.cause?.code || err?.message || "network error"})`,
    );
  }
  const body = await res.json().catch(() => null);
  if (res.status === 401 && body?.error?.code === "unauthorized") {
    if (token) throw new Error("API token was rejected (invalid or revoked)");
    return { ok: true, org: null };
  }
  if (res.ok && body?.data) return { ok: true, org: body.data.org };
  throw new Error(`Unexpected response (${res.status}) — is this a RootWatch server?`);
}

// ---------------------------------------------------------------------------
// Window + navigation hardening
// ---------------------------------------------------------------------------

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 900,
    minHeight: 600,
    title: "RootWatch",
    icon: path.join(__dirname, "icon.png"),
    backgroundColor: "#0a0f14",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const allowedOrigin = () => (config?.url ? new URL(config.url).origin : null);

  // Keep navigation on the configured instance — exact origin match, so
  // https://rootwatch.dev.evil.com can't ride the preload IPC bridge.
  // Anything else is blocked; only http(s) is handed to the system browser
  // (file:/javascript:/data: are dropped, never opened externally).
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (navGuard.isAllowedOrigin(url, allowedOrigin())) return;
    event.preventDefault();
    if (navGuard.isExternallyOpenable(url)) shell.openExternal(url);
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (navGuard.isAllowedOrigin(url, allowedOrigin())) {
      return { action: "allow" };
    }
    if (navGuard.isExternallyOpenable(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  if (config?.url) {
    log(`window → ${new URL(config.url).origin}`);
    mainWindow.loadURL(config.url);
  } else {
    log("window → connect screen (no instance configured)");
    mainWindow.loadFile(path.join(__dirname, "connect.html"));
  }
}

// ---------------------------------------------------------------------------
// Tray + posture polling
// ---------------------------------------------------------------------------

function trayLabel() {
  if (!config?.token) return "RootWatch";
  if (lastScore == null) return "RootWatch — connecting…";
  return `RootWatch — score ${lastScore.score}`;
}

function rebuildTrayMenu() {
  if (!tray) return;
  const items = [{ label: "Open RootWatch", click: showWindow }, { type: "separator" }];
  if (lastScore) {
    items.push({
      label: `Security score: ${lastScore.score}   Open criticals: ${lastScore.openCriticals}   Events 24h: ${lastScore.events24h}`,
      enabled: false,
    });
  } else {
    items.push({
      label: config?.token ? "Awaiting first poll…" : "No API token — tray stats disabled",
      enabled: false,
    });
  }
  let deviceLabel = "This device…";
  if (config?.deviceToken) {
    const ds = device.deviceStatus();
    deviceLabel =
      ds.state === "offline-queued"
        ? "This device — offline (queueing reports)"
        : ds.reporting
          ? "This device — reporting"
          : "This device — paired";
    if (ds.queued > 0) deviceLabel += ` · ${ds.queued} queued`;
  }
  items.push(
    { type: "separator" },
    { label: deviceLabel, click: showDevicePage },
    { label: "Change server / token…", click: showConnectScreen },
    { label: "Quit", click: () => app.quit() },
  );
  tray.setContextMenu(Menu.buildFromTemplate(items));
  tray.setToolTip(trayLabel());
}

async function poll() {
  if (!config?.url || !config?.token) return;
  const headers = { Authorization: `Bearer ${config.token}` };
  try {
    const scoreRes = await fetch(`${config.url}/api/v1/score`, { headers });
    if (scoreRes.status === 401) {
      lastScore = null;
      rebuildTrayMenu();
      tray?.setToolTip("RootWatch — API token rejected");
      return;
    }
    if (scoreRes.ok) {
      lastScore = (await scoreRes.json()).data;
      rebuildTrayMenu();
    }

    // Notify on new Critical/High events. First poll only seeds the
    // baseline so a backlog doesn't firehose the user.
    const evRes = await fetch(`${config.url}/api/v1/events?limit=25`, { headers });
    if (evRes.ok) {
      const events = (await evRes.json()).data ?? [];
      const fresh = events.filter(
        (e) =>
          ["critical", "high"].includes(String(e.severity).toLowerCase()) &&
          !seenEventIds.has(e.id),
      );
      for (const e of fresh) seenEventIds.add(e.id);
      if (pollBaselineSet) {
        for (const e of fresh.slice(0, 3).reverse()) {
          new Notification({
            title: `RootWatch: ${e.severity} event`,
            body: `${e.event} (${e.source ?? "unknown source"})`,
            icon: path.join(__dirname, "icon.png"),
          }).show();
        }
      }
      pollBaselineSet = true;
    }
  } catch {
    // Offline / server down — keep last state, retry next tick.
  }
}

function startPolling() {
  clearInterval(pollTimer);
  seenEventIds = new Set();
  pollBaselineSet = false;
  poll();
  pollTimer = setInterval(poll, POLL_MS);
}

// ---------------------------------------------------------------------------
// Listener drift — watches the local socket inventory (same ~60s cache the
// "This Device" page uses) and notifies when a process starts listening on a
// new port. Local utility: runs whenever the app is running, paired or not.
// The first pass silently seeds the baseline; gone keys just leave their
// last_seen stale in the sightings table — exits are normal, not alertable.
// ---------------------------------------------------------------------------

async function listenerDrift() {
  let items;
  try {
    items = await collector.collectListeners({ force: false });
  } catch {
    return; // collector failed — try again next tick
  }
  try {
    await db.recordListeners(items);
  } catch {
    /* persistence is best-effort — drift detection still runs */
  }

  const current = new Map(); // key → { listener, port }
  for (const l of items) {
    for (const p of l.ports) {
      current.set(`${l.pid}:${p.port}:${p.protocol}`, { listener: l, port: p });
    }
  }
  if (listenerBaseline === null) {
    listenerBaseline = new Set(current.keys());
    return;
  }

  // Names that have ever listened on this box — seeded once from sighting
  // history so a reinstall doesn't re-alert every existing process.
  if (knownListenerNames === null) {
    try {
      knownListenerNames = new Set(
        (await db.getListenerHistory()).map((r) => r.name).filter(Boolean),
      );
    } catch {
      knownListenerNames = new Set();
    }
  }

  const fresh = [...current.keys()].filter((k) => !listenerBaseline.has(k));
  listenerBaseline = new Set(current.keys());
  if (!fresh.length) return;

  // Ephemeral loopback binds from known processes are background noise on a
  // dev machine (browsers, language servers re-bind constantly). Only a
  // non-loopback bind, a high/critical-risk listener, or an exe name we've
  // never seen listening earns a notification.
  const notable = fresh.filter((key) => {
    const { listener: l, port: p } = current.get(key);
    if (l.risk === "critical" || l.risk === "high") return true;
    if (p.scope !== "loopback") return true;
    return l.name == null || !knownListenerNames.has(l.name);
  });
  for (const l of items) {
    if (l.name) knownListenerNames.add(l.name);
  }
  if (!notable.length) {
    log(`drift: ${fresh.length} new bind(s), none notable`);
    return;
  }
  if (notable.length < fresh.length) {
    log(`drift: ${fresh.length} new bind(s), ${notable.length} notable`);
  }

  // One notification per process (a listener can open several fresh ports);
  // capped at 3 so a burst doesn't firehose the user.
  const seen = new Set();
  let notified = 0;
  for (const key of notable) {
    if (notified >= 3) break;
    const { listener: l, port: p } = current.get(key);
    const group = l.key ?? String(l.pid);
    if (seen.has(group)) continue;
    seen.add(group);
    notified++;
    const highRisk = l.risk === "critical" || l.risk === "high";
    new Notification({
      title: highRisk ? "RootWatch: new PUBLIC/high-risk listener" : "RootWatch: new listener",
      body: `${l.name ?? `pid ${l.pid}`} — ${p.address}:${p.port}`,
      icon: path.join(__dirname, "icon.png"),
    }).show();
  }
}

function showWindow() {
  if (mainWindow) {
    // A window mapped fully offscreen (dead display/workspace) stays
    // invisible on plain show() — recenter it before raising.
    const wb = mainWindow.getBounds();
    const wa = screen.getDisplayMatching(wb).workArea;
    if (
      wb.x + wb.width < wa.x ||
      wb.y + wb.height < wa.y ||
      wb.x > wa.x + wa.width ||
      wb.y > wa.y + wa.height
    ) {
      log(`window offscreen (${wb.x},${wb.y} ${wb.width}x${wb.height}) — recentering`);
      mainWindow.center();
    }
    // GNOME Wayland drops show()/focus() raises from tray clicks — a
    // window mapped on another workspace never comes forward. Mark it
    // visible-on-all-workspaces so it lands on the current one, then
    // restore normal workspace binding after it's shown.
    mainWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
    mainWindow.show();
    mainWindow.moveTop();
    mainWindow.focus();
    mainWindow.setVisibleOnAllWorkspaces(false);
  } else {
    createWindow();
  }
}

function showConnectScreen() {
  showWindow();
  mainWindow.loadFile(path.join(__dirname, "connect.html"));
}

// GNOME/headless panels hide tray icons — the menubar (Alt toggles, since the
// window uses autoHideMenuBar) and `--device` argv keep "This device"
// reachable when no tray exists.
function buildAppMenu() {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: "RootWatch",
        submenu: [
          { label: "This device…", click: showDevicePage },
          { label: "Change server / token…", click: showConnectScreen },
          { type: "separator" },
          { label: "Quit", click: () => app.quit() },
        ],
      },
      {
        label: "View",
        submenu: [
          { role: "reload" },
          { role: "togglefullscreen" },
          { type: "separator" },
          { role: "resetZoom" },
          { role: "zoomIn" },
          { role: "zoomOut" },
          { type: "separator" },
          { role: "toggleDevTools" },
        ],
      },
    ]),
  );
}

// Packaged Electron rejects unknown "--" flags before app code sees argv
// ("bad option: --device") — the positional form works in both dev and
// packaged builds. Accept both.
const wantsDevicePage = (argv) => argv.slice(1).some((a) => a === "device" || a === "--device");

function showDevicePage() {
  showWindow();
  mainWindow.loadFile(path.join(__dirname, "device.html"));
}

/** (Re)start the watched-device reporter when pairing + connection align. */
function syncReporter() {
  if (config?.url && config?.deviceToken) {
    device.startReporter({ url: config.url, token: config.deviceToken });
    log(`reporter → ${config.url}`);
  } else {
    device.stopReporter();
  }
}

// ---------------------------------------------------------------------------
// IPC from the bundled pages. The preload bridge is attached to every page
// the window loads — including the remote dashboard — so every handler
// refuses frames that aren't a bundled file:// page.
// ---------------------------------------------------------------------------

const bundledOnly = (event) => {
  const u = event.senderFrame?.url ?? "";
  if (!u.startsWith("file://")) throw new Error("bridge unavailable on remote origin");
};

// The UI only ever passes a listener's cwd, but the channel takes a bare
// string — scan.cjs's resolveScanDir re-checks that the REALPATH stays
// inside the user's home before the scanner walks it (a `~/link -> /`
// cwd passes a string-prefix check but escapes home entirely; a remote
// page can't reach this at all post-gate).

ipcMain.handle("rw:connection:get", (event) => {
  bundledOnly(event);
  return {
    url: config?.url ?? DEFAULT_URL,
    hasToken: Boolean(config?.token),
    encryptionAvailable: safeStorage.isEncryptionAvailable(),
  };
});

ipcMain.handle("rw:connection:save", async (event, opts) => {
  bundledOnly(event);
  try {
    const url = normalizeUrl(opts?.url);
    const token = String(opts?.token || "").trim() || null;
    const check = await checkInstance(url, token);
    // A device pairing is scoped to the instance it enrolled on — switching
    // servers invalidates it.
    const keepDevice = config?.url === url;
    config = saveConfig(url, token, {
      deviceToken: keepDevice ? undefined : null,
    });
    lastScore = null;
    startPolling();
    syncReporter();
    rebuildTrayMenu();
    mainWindow?.loadURL(config.url);
    return { ok: true, org: check.org?.name ?? null };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle("rw:connection:disconnect", (event) => {
  bundledOnly(event);
  clearConfig();
  clearInterval(pollTimer);
  device.stopReporter();
  device.cancelEnrollment();
  config = null;
  lastScore = null;
  rebuildTrayMenu();
  showConnectScreen();
});

// ---------------------------------------------------------------------------
// This-device surface: local listener inventory, pairing, and sync status.
// ---------------------------------------------------------------------------

ipcMain.handle("rw:device:status", async (event) => {
  bundledOnly(event);
  await device.deviceHostId();
  return {
    ...device.deviceStatus(),
    paired: Boolean(config?.deviceToken),
    url: config?.url ?? null,
  };
});

ipcMain.handle("rw:device:listeners", async (event, { force } = {}) => {
  bundledOnly(event);
  const listeners = await collector.collectListeners({ force: force === true });
  return { supported: true, count: listeners.length, listeners };
});

ipcMain.handle("rw:device:performance", async (event, { force } = {}) => {
  bundledOnly(event);
  try {
    const perf = require("./perf.cjs");
    return { ok: true, report: await perf.collectPerformance({ force: force === true }) };
  } catch (error) {
    return { ok: false, error: error?.message ?? "performance report unavailable" };
  }
});

ipcMain.handle("rw:device:checks", async (event) => {
  bundledOnly(event);
  try {
    const checks = require("./checks.cjs");
    return { ok: true, checks: await checks.runLocalChecks() };
  } catch (error) {
    return { ok: false, error: error?.message ?? "checks unavailable" };
  }
});

ipcMain.handle("rw:device:stop", async (event, { pid, confirmSystem, disable } = {}) => {
  bundledOnly(event);
  if (!Number.isInteger(pid) || pid <= 0) return { status: "refused", message: "invalid pid" };
  return collector.stopListener(pid, {
    confirmSystem: confirmSystem === true,
    disable: disable === true,
  });
});

ipcMain.handle("rw:device:enroll:start", async (event) => {
  bundledOnly(event);
  if (!config?.url) return { ok: false, error: "connect to an instance first" };
  try {
    const r = await device.enrollStart(config.url);
    return { ok: true, ...r };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle("rw:device:enroll:poll", async (event) => {
  bundledOnly(event);
  if (!config?.url) return { status: "failed", message: "no instance configured" };
  const r = await device.enrollPollClaim(config.url);
  if (r.status === "approved") {
    config = saveConfig(config.url, config.token, { deviceToken: r.token });
    syncReporter();
  }
  return { status: r.status, message: r.message };
});

ipcMain.handle("rw:device:unpair", (event) => {
  bundledOnly(event);
  device.stopReporter();
  device.cancelEnrollment();
  if (config?.url) config = saveConfig(config.url, config.token, { deviceToken: null });
});

ipcMain.handle("rw:device:history", async (event) => {
  bundledOnly(event);
  try {
    return { ok: true, items: await db.getListenerHistory() };
  } catch (error) {
    return { ok: false, error: error?.message ?? "history unavailable" };
  }
});

ipcMain.handle("rw:device:queue", async (event) => {
  bundledOnly(event);
  return { queued: await device.queueSize() };
});

// Credential posture — keys.cjs returns fingerprinted records only (sha256
// fp + last4 + "~/…" paths); secret values never cross this bridge. The
// vault list rides along for "contained" marking — metadata only.
ipcMain.handle("rw:device:keys", async (event, { force } = {}) => {
  bundledOnly(event);
  let keys;
  try {
    keys = require("./keys.cjs");
  } catch {
    return { ok: false, error: "key scanner unavailable" };
  }
  try {
    return {
      ok: true,
      items: await keys.listKeys({ force: force === true }),
      vault: await keys.vaultList(),
    };
  } catch (error) {
    return { ok: false, error: error?.message ?? "key scan unavailable" };
  }
});

const KEY_FP_RE = /^[0-9a-f]{64}$/;

ipcMain.handle("rw:device:keys:contain", async (event, { fingerprint, copy } = {}) => {
  bundledOnly(event);
  if (typeof fingerprint !== "string" || !KEY_FP_RE.test(fingerprint)) {
    return { status: "failed", message: "invalid fingerprint" };
  }
  try {
    return await require("./keys.cjs").containKey(fingerprint, { copy: copy === true });
  } catch (error) {
    return { status: "failed", message: error?.message ?? "contain failed" };
  }
});

ipcMain.handle("rw:device:keys:probe", async (event, { fingerprint } = {}) => {
  bundledOnly(event);
  if (typeof fingerprint !== "string" || !KEY_FP_RE.test(fingerprint)) {
    return { status: "failed", message: "invalid fingerprint" };
  }
  try {
    return await require("./keys.cjs").probeKey(fingerprint);
  } catch (error) {
    return { status: "failed", message: error?.message ?? "probe failed" };
  }
});

ipcMain.handle("rw:device:keys:probe-all", async (event, { provider } = {}) => {
  bundledOnly(event);
  try {
    return await require("./keys.cjs").probeAll(typeof provider === "string" ? { provider } : {});
  } catch (error) {
    return { probed: 0, live: 0, dead: 0, unknown: 0, error: error?.message ?? "probe-all failed" };
  }
});

// Malware posture — the cached summary the reporter maintains (a stale cache
// gets a background refresh; the renderer never blocks on a full pass).
ipcMain.handle("rw:device:malware", async (event) => {
  bundledOnly(event);
  try {
    const malware = require("./malware.cjs");
    malware.refreshInBackground();
    return { ok: true, summary: malware.getCachedSummary() };
  } catch (error) {
    return { ok: false, error: error?.message ?? "malware scanner unavailable" };
  }
});

// Forced full pass — can take a minute+ when ClamAV is installed; the UI
// shows a busy state while the invoke resolves.
ipcMain.handle("rw:device:malware:scan", async (event) => {
  bundledOnly(event);
  try {
    return { ok: true, summary: await require("./malware.cjs").scanNow() };
  } catch (error) {
    return { ok: false, error: error?.message ?? "malware scan failed" };
  }
});

// Local repo scan — scan.cjs is an optional bundled module; a broken/missing
// build degrades to an honest 'scanner unavailable' instead of failing IPC.
ipcMain.handle("rw:device:scan", async (event, { dir } = {}) => {
  bundledOnly(event);
  let scanner;
  try {
    scanner = require("./scan.cjs");
  } catch {
    return { ok: false, error: "scanner unavailable" };
  }
  try {
    return { ok: true, ...(await scanner.scanPath(scanner.resolveScanDir(dir))) };
  } catch (error) {
    return { ok: false, error: error?.message ?? "scan failed" };
  }
});

ipcMain.handle("rw:open-external", (event, url) => {
  bundledOnly(event);
  try {
    const u = new URL(String(url));
    if (u.protocol === "https:" || u.protocol === "http:") return shell.openExternal(u.toString());
  } catch {
    /* malformed — drop */
  }
});

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

// Auto-update — GitHub provider against the public releases-only repo
// (electron-builder.yml publish config). AppImage only: .deb upgrades are
// manual downloads (no repo), snap/flatpak update through their stores.
// Failures are silent — the app still works, it just stays on its version.
function initAutoUpdater() {
  if (!app.isPackaged || !process.env.APPIMAGE || process.env.SNAP) return;
  try {
    const { autoUpdater } = require("electron-updater");
    autoUpdater.autoDownload = true;
    autoUpdater.logger = {
      info() {},
      warn() {},
      error(m) {
        const msg = m instanceof Error ? m.message : String(m);
        console.log(`[updater] ${msg.split("\n")[0].slice(0, 160)}`);
      },
      debug() {},
    };
    autoUpdater.on("update-downloaded", (info) => {
      new Notification({
        title: "RootWatch update ready",
        body: `v${info.version} downloaded — restart to apply.`,
        icon: path.join(__dirname, "icon.png"),
      }).show();
    });
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    setInterval(() => autoUpdater.checkForUpdates().catch(() => {}), 6 * 3600_000).unref();
  } catch {
    /* updater not bundled — skip */
  }
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", (_e, argv) => {
    if (wantsDevicePage(argv)) showDevicePage();
    else showWindow();
  });

  app.whenReady().then(() => {
    app.setAppUserModelId("dev.rootwatch.RootWatch");
    log(
      `start v${app.getVersion()} session=${process.env.XDG_SESSION_TYPE ?? "?"} ` +
        `ozone=${process.env.ELECTRON_OZONE_PLATFORM_HINT ?? (process.env.ROOTWATCH_X11 === "1" ? "x11" : "auto")}`,
    );

    // Default-deny all permission requests from the loaded page.
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, callback) => callback(false));

    config = loadConfig();
    try {
      db.init(app.getPath("userData"));
    } catch {
      /* store unavailable — reporting/drift continue without persistence */
    }
    buildAppMenu();
    if (wantsDevicePage(process.argv)) {
      showDevicePage();
    } else {
      createWindow();
    }
    syncReporter();

    tray = new Tray(nativeImage.createFromPath(path.join(__dirname, "icon.png")));
    tray.on("click", showWindow);
    rebuildTrayMenu();
    startPolling();
    initAutoUpdater();
    listenerDrift();
    driftTimer = setInterval(listenerDrift, POLL_MS);
  });

  app.on("before-quit", () => {
    clearInterval(driftTimer);
    db.close().catch(() => {});
  });

  app.on("window-all-closed", () => {
    // Keep the tray + poller alive; quit via the tray menu.
  });
}
