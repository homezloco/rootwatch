/**
 * Local host collector for the "This Device" surface.
 *
 * Zero-PG port of the server-side listener inventory: every LISTEN socket is
 * grouped by pid and identified through the same honest-confidence waterfall
 * (cgroup unit → container runtime → cmdline class → HTTP probe → port table →
 * unknown), with bind scope and a compact risk score. Stops are same-uid
 * SIGTERM→SIGKILL with a pid↔socket re-verification guard — the desktop app
 * has no privileged helper, so foreign-uid targets get an honest
 * 'elevated_required' + the exact manual command.
 *
 * Requires systeminformation (bundled dep) plus a per-platform socket
 * source: `ss` (iproute2) on Linux, `lsof` on macOS, `netstat -ano` on
 * Windows. Host checks and persistence detection are Linux-only — on
 * other platforms they degrade to honest "not evaluable" results.
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { readdir, readFile } = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const si = require("systeminformation");

const { detectPersistence } = require("./persistence.cjs");

const execFileP = promisify(execFile);

const HTTP_PROBE_TIMEOUT_MS = 300;
const KILL_GRACE_MS = 3000;
const ABANDONED_SECONDS = 7 * 24 * 60 * 60;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Socket inventory — platform dispatch to a per-OS source. All sources
// return the normalized shape [{protocol:'tcp'|'udp', address, port, pid}]
// (plus `process` where the tool reports a command name). An unmapped
// platform returns [] so callers degrade honestly instead of guessing.
// ---------------------------------------------------------------------------

function listSockets() {
  if (process.platform === "darwin") return require("./sockets-macos.cjs").listSockets();
  if (process.platform === "win32") return require("./sockets-win.cjs").listSockets();
  if (process.platform !== "linux") return Promise.resolve([]);
  return listSocketsLinux();
}

// `ss -H -tulpn` lists TCP LISTEN + UDP UNCONN sockets with owning process
// where readable (same-user pids resolve without privileges; foreign pids
// come back unnamed — honest unknown, not a guess).
async function listSocketsLinux() {
  const { stdout } = await execFileP("ss", ["-H", "-tulpn"], {
    timeout: 10_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  return parseSsRows(stdout);
}

// Established TCP connections — the "is anything using this" evidence plus
// pid attribution for egress. null = the table couldn't be read (honest
// "not evaluable"), [] = readable and empty.
function listEstablished() {
  const mod =
    process.platform === "darwin"
      ? require("./sockets-macos.cjs")
      : process.platform === "win32"
        ? require("./sockets-win.cjs")
        : null;
  if (mod) {
    if (typeof mod.listEstablished !== "function") return Promise.resolve(null);
    return mod.listEstablished().catch(() => null);
  }
  if (process.platform !== "linux") return Promise.resolve(null);
  return listEstablishedLinux().catch(() => null);
}

async function listEstablishedLinux() {
  const { stdout } = await execFileP("ss", ["-H", "-tnp", "state", "established"], {
    timeout: 10_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  return parseSsEstablished(stdout);
}

// `ss -H -tnp state established` rows: `tcp ESTAB r s local peer [users]`.
// pid resolves only for same-uid sockets — null elsewhere, which is what
// makes egress honestly "not evaluable" for foreign-uid listeners.
function parseSsEstablished(stdout) {
  const rows = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    if (f[0].toLowerCase() !== "tcp") continue;
    const local = splitAddrPort(f[4] ?? "");
    const peer = splitAddrPort(f[5] ?? "");
    if (!local || !peer) continue;
    let pid = null;
    const m = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (m) pid = Number(m[2]);
    rows.push({
      localAddress: local.address,
      localPort: local.port,
      peerAddress: peer.address,
      peerPort: peer.port,
      pid,
    });
  }
  return rows;
}

// Pure parse of `ss -H -tulpn` stdout → normalized socket rows. Exported
// (below) so tests can feed fixture output without a live socket table.
function parseSsRows(stdout) {
  const rows = [];
  for (const line of String(stdout ?? "").split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const proto = f[0].toLowerCase();
    if (proto !== "tcp" && proto !== "udp") continue;
    const state = f[1].toUpperCase();
    if (proto === "tcp" ? state !== "LISTEN" : !(state === "UNCONN" || state === "LISTEN"))
      continue;

    // Local field is f[4] for `ss -H` output: proto state recv send local peer
    const local = f[4] ?? "";
    const addrPort = splitAddrPort(local);
    if (!addrPort) continue;

    let pid = null;
    let pname = null;
    const m = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (m) {
      pname = m[1];
      pid = Number(m[2]);
    }
    rows.push({
      protocol: proto,
      address: addrPort.address,
      port: addrPort.port,
      pid,
      process: pname,
    });
  }
  return rows;
}

function splitAddrPort(local) {
  const idx = local.lastIndexOf(":");
  if (idx < 0) return null;
  const port = Number(local.slice(idx + 1));
  if (!Number.isInteger(port) || port <= 0) return null;
  let address = local.slice(0, idx).replace(/^\[|\]$/g, "");
  address = address.split("%")[0]; // drop zone index (127.0.0.54%lo)
  return { address, port };
}

/** Mirror of server collectors.ts classifyBindAddress. */
function classifyBindAddress(addr) {
  const a = String(addr ?? "")
    .trim()
    .replace(/^\[|\]$/g, "")
    .split("%")[0];
  if (a === "" || a === "*" || a === "0.0.0.0" || a === "::") return "public";
  const lower = a.toLowerCase();
  if (lower === "localhost" || lower === "::1" || lower.startsWith("127.")) return "loopback";
  if (lower.startsWith("fe80:")) return "private";
  if (lower.startsWith("fd") || lower.startsWith("fc")) return "tailscale"; // ULA
  if (/^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\.|^169\.254\./.test(lower)) return "private";
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(lower)) return "tailscale"; // CGNAT
  return "public";
}

// ---------------------------------------------------------------------------
// Identification — same waterfall order as server/services/listeners.ts.
// ---------------------------------------------------------------------------

const DEV_SERVER_RE =
  /\b(vite|next|nuxt|astro|remix|gatsby|ng serve|nodemon|tsx|ts-node|bun|deno|webpack(-dev-server)?|parcel|uvicorn|gunicorn|flask|django|rails|puma|artisan serve|streamlit|jupyter|http-server|serve|live-server|lite-server|storybook|json-server|expo|wrangler|miniflare|ngrok)\b/i;

const DATABASE_PORTS = new Set([
  3306, 5432, 6379, 27017, 9200, 9300, 11211, 2181, 5984, 9042, 8086, 9000,
]);
const PORT_NAMES = {
  22: "ssh",
  25: "smtp",
  53: "dns",
  80: "http",
  443: "https",
  3000: "dev server",
  3306: "mysql",
  5173: "vite dev",
  5432: "postgresql",
  6379: "redis",
  8000: "dev server",
  8080: "http-proxy",
  9200: "elasticsearch",
  27017: "mongodb",
  11211: "memcached",
  2375: "docker api",
  5353: "mdns",
};

const CONTAINER_RE = /docker-proxy|containerd-shim|com\.docker|podman/i;
const SENSITIVE_PUBLIC = new Set([3306, 5432, 6379, 27017, 9200, 9300, 11211, 2181, 2375, 5984]);

// user@<uid>.service is the SESSION WRAPPER — the systemd --user manager
// for a whole login session, not a unit of the process beneath it. It may
// be recorded for identification but must never be suggested (or run) as a
// systemctl stop/disable target: stopping it kills the user's session.
const isSessionWrapper = (unit) => unit != null && /^user@\d+\.service$/.test(unit);

// ---------------------------------------------------------------------------
// Live activity — inbound established conns matched to this listener's
// bound ports; outbound conns attributed to the owning pid. Same honesty
// rules as the server build: null = not evaluable, never "zero".
// ---------------------------------------------------------------------------

const MAX_PEERS = 8;
const normAddr = (a) =>
  String(a ?? "")
    .replace(/^\[|\]$/g, "")
    .split("%")[0]
    .toLowerCase();
const isWildcardAddr = (a) =>
  ["", "*", "0.0.0.0", "::", "0:0:0:0:0:0:0:0", "[::]"].includes(normAddr(a));

/** Established conns whose LOCAL side is one of this listener's bound
 *  TCP sockets. null for UDP-only records — datagrams have no "in use". */
function activityFor(ports, conns) {
  if (conns === null || conns === undefined) return null;
  const tcpPorts = ports.filter((p) => p.protocol === "tcp");
  if (tcpPorts.length === 0) return null;
  const peers = new Map();
  let established = 0;
  const seen = new Set();
  for (const c of conns) {
    const owned = tcpPorts.some(
      (p) =>
        p.port === c.localPort &&
        (isWildcardAddr(p.address) || normAddr(c.localAddress) === normAddr(p.address)),
    );
    if (!owned) continue;
    const key = `${c.localAddress}:${c.localPort}>${c.peerAddress}:${c.peerPort}`;
    if (seen.has(key)) continue;
    seen.add(key);
    established++;
    const peer = normAddr(c.peerAddress);
    if (peer && !peers.has(peer) && peers.size < MAX_PEERS) {
      peers.set(peer, { address: peer, scope: classifyBindAddress(peer) });
    }
  }
  return { established, peers: Array.from(peers.values()) };
}

/** Outbound conns from the owning pid — established rows whose local port
 *  isn't a bound listen port. null when the pid can't own conn rows
 *  (pid-less record, or conns carry no pid for it). */
function egressFor(pid, ports, conns) {
  if (conns == null || pid == null || pid <= 0) return null;
  const boundPorts = new Set(ports.map((p) => p.port));
  const peers = new Map();
  let count = 0;
  const seen = new Set();
  for (const c of conns) {
    if (c.pid !== pid) continue;
    if (boundPorts.has(c.localPort)) continue; // inbound side of the listen socket
    const key = `${c.localAddress}:${c.localPort}>${c.peerAddress}:${c.peerPort}`;
    if (seen.has(key)) continue;
    seen.add(key);
    count++;
    const addr = normAddr(c.peerAddress);
    const pkey = `${addr}:${c.peerPort}`;
    if (addr && !peers.has(pkey) && peers.size < MAX_PEERS) {
      peers.set(pkey, {
        address: addr,
        port: c.peerPort ?? null,
        scope: classifyBindAddress(addr),
      });
    }
  }
  return { count, peers: Array.from(peers.values()) };
}

// ---------------------------------------------------------------------------
// Firewall overlay (Linux only — other platforms leave firewall:null, the
// honest "not evaluable"). Per-port admission derives only from rules we
// can actually read; unreadable rulesets yield allowed:null, never a guess.
// ---------------------------------------------------------------------------

async function firewallView() {
  const none = (detail) => ({
    backend: null,
    readable: true,
    detail,
    allows: () => true, // no active firewall → the bind is genuinely reachable
  });
  const unreadable = (backend, detail) => ({
    backend,
    readable: false,
    detail,
    allows: () => null,
  });

  const fw = await firewallStatus().catch(() => ({ supported: false, active: false }));
  if (fw.supported && fw.active === null && fw.backend) {
    // Backend present but state unreadable — admission is genuinely
    // unknown, not "reachable" (none() would claim it is).
    return unreadable(
      fw.backend,
      `${fw.backend} present; firewall state unreadable without privilege`,
    );
  }
  if (!fw.supported || !fw.active || !fw.backend) {
    return none("no active host firewall detected");
  }

  if (fw.backend === "ufw") {
    try {
      const { stdout } = await execFileP("ufw", ["status"], { timeout: 5_000 });
      const allowedPorts = new Set();
      const deniedPorts = new Set();
      for (const line of stdout.split("\n")) {
        const m = line.match(/^(\d+)(?:\/(tcp|udp))?\s+(ALLOW|DENY|LIMIT|REJECT)/i);
        if (!m) continue;
        const key = `${m[1]}/${(m[2] ?? "tcp").toLowerCase()}`;
        if (/ALLOW|LIMIT/i.test(m[3])) allowedPorts.add(key);
        else deniedPorts.add(key);
      }
      const defaultAllow = /default:\s*allow\s*\(incoming\)/i.test(stdout);
      return {
        backend: "ufw",
        readable: true,
        detail: `ufw active; default incoming ${defaultAllow ? "allow" : "deny"}`,
        allows: (proto, port) => {
          const key = `${port}/${proto}`;
          if (deniedPorts.has(key)) return false;
          if (allowedPorts.has(key) || allowedPorts.has(`${port}/tcp`)) return true;
          return defaultAllow;
        },
      };
    } catch {
      return unreadable("ufw", "ufw active; rules unreadable without privilege");
    }
  }

  if (fw.backend === "firewalld") {
    try {
      const { stdout } = await execFileP("firewall-cmd", ["--list-all"], { timeout: 5_000 });
      const portsLine = stdout.match(/^ *ports:\s*(.+)$/m)?.[1] ?? "";
      const open = new Set(portsLine.split(/\s+/).filter((t) => /^\d+\/(tcp|udp)$/.test(t)));
      return {
        backend: "firewalld",
        readable: true,
        detail: `firewalld running; default-zone ports: ${Array.from(open).join(" ") || "none"}`,
        allows: (proto, port) => open.has(`${port}/${proto}`),
      };
    } catch {
      return unreadable("firewalld", "firewalld running; zone rules unreadable without privilege");
    }
  }

  try {
    const { stdout } = await execFileP("iptables", ["-S", "INPUT"], { timeout: 5_000 });
    const policyDrop = /^-P INPUT (DROP|REJECT)/m.test(stdout);
    const accepted = new Set();
    for (const m of Array.from(stdout.matchAll(/-A INPUT\s+.*--dport (\d+).*ACCEPT/g))) {
      accepted.add(Number(m[1]));
    }
    return {
      backend: "iptables",
      readable: true,
      detail: `iptables active; INPUT policy ${policyDrop ? "DROP/REJECT" : "ACCEPT"}`,
      allows: (_proto, port) => (accepted.has(port) ? true : policyDrop ? false : true),
    };
  } catch {
    return unreadable("iptables", "iptables active; rules unreadable without privilege");
  }
}

/** Roll per-port verdicts into one listener-level firewall record. */
function firewallFor(ports, view) {
  const exposed = ports.filter((p) => p.scope !== "loopback");
  if (exposed.length === 0) return null; // firewalls never filter loopback
  const verdicts = exposed.map((p) => {
    const v = view.allows(p.protocol, p.port);
    return `${p.port}/${p.protocol}: ${v === true ? "admitted" : v === false ? "blocked" : "unknown"}`;
  });
  const admitted = exposed.some((p) => view.allows(p.protocol, p.port) === true);
  const allBlocked = exposed.every((p) => view.allows(p.protocol, p.port) === false);
  return {
    backend: view.backend,
    allowed: admitted ? true : allBlocked ? false : null,
    detail: `${view.detail} — ${verdicts.join(", ")}`,
  };
}

// ---------------------------------------------------------------------------
// Duplicate services — ≥2 pids sharing one identity (exe basename, else
// resolved name). Generic runtimes are excluded: "3 node processes" is
// noise, not the deb+snap cupsd double-stack this exists to catch.
// ---------------------------------------------------------------------------

const GENERIC_EXE_BASENAMES = new Set([
  "node",
  "nodejs",
  "python",
  "python2",
  "python3",
  "ruby",
  "java",
  "perl",
  "bun",
  "deno",
  "php",
  "sh",
  "bash",
  "zsh",
  "fish",
  "dotnet",
  "pwsh",
  "npm",
  "npx",
  "docker-proxy",
  // Directory basenames — when the proc table resolves `path` to a dir
  // (…/bin) instead of the binary, the basename carries no identity at all.
  "bin",
  "sbin",
  "lib",
  "lib64",
  "libexec",
  "usr",
  "opt",
  "share",
]);
const NAME_BASIS_OK = new Set(["systemd", "container", "cmdline", "unknown"]);

function flagDuplicates(records, procs) {
  const groups = new Map();
  for (const l of records) {
    if (l.pid == null || l.pid <= 0) continue;
    const exeBase = l.exe?.split("/").pop()?.toLowerCase() ?? null;
    const nameKey = l.name?.toLowerCase().replace(/\.service$/, "") ?? null;
    let basis = null;
    let key = null;
    if (exeBase && l.class !== "container" && !GENERIC_EXE_BASENAMES.has(exeBase)) {
      basis = "exe";
      key = exeBase;
    } else if (
      nameKey &&
      !GENERIC_EXE_BASENAMES.has(nameKey) &&
      NAME_BASIS_OK.has(l.identifiedBy)
    ) {
      basis = "name";
      key = nameKey;
    }
    if (!basis || !key) continue;
    const gkey = `${basis}:${key}`;
    const g = groups.get(gkey) ?? { basis, key, recs: [] };
    g.recs.push(l);
    groups.set(gkey, g);
  }
  const ancestorsOf = (pid) => {
    const seen = new Set();
    let cur = procs.get(pid)?.parentPid;
    for (let i = 0; i < 64 && cur != null && cur > 1 && !seen.has(cur); i++) {
      seen.add(cur);
      cur = procs.get(cur)?.parentPid;
    }
    return seen;
  };
  for (const g of groups.values()) {
    if (g.recs.length < 2) continue;
    // Helper pids share exe+name with their parent app (Electron GPU/
    // network helpers, language servers) — one instance, not a duplicate
    // service. Two members count as independent only when their ancestor
    // sets share nothing below init: deb+snap cupsd meet only at pid 1.
    const trees = g.recs.map((r) => {
      const a = ancestorsOf(r.pid);
      a.add(r.pid); // member pid itself counts as shared tree
      return a;
    });
    const independent = [];
    for (let i = 0; i < g.recs.length; i++) {
      const sharesTree = independent.some((j) => [...trees[i]].some((p) => trees[j].has(p)));
      if (!sharesTree) independent.push(i);
    }
    if (independent.length < 2) continue;
    for (const i of independent) {
      g.recs[i].duplicate = {
        basis: g.basis,
        key: g.key,
        pids: independent.filter((j) => j !== i).map((j) => g.recs[j].pid),
      };
    }
  }
}

// Mirrors server/services/listeners.ts unitFromCgroup: a cgroup path can
// nest several units (system-getty.slice/getty@tty1.service,
// user@UID.service/app.slice/<name>.service) — match every .service name
// and take the first one that isn't the user@<uid>.service session
// wrapper (it identifies nothing about the process). Falls back to the
// lone user@ match when that's all there is — it's real, just not an
// identity.
function unitFromCgroup(cgroup) {
  if (!cgroup) return null;
  const m = cgroup.match(/([A-Za-z0-9_@:.-]+\.service)\b/g);
  const unit = (m ?? []).find((u) => !/^user@\d+\.service$/.test(u));
  return unit ?? m?.[0] ?? null;
}

async function unitForPid(pid) {
  try {
    const cg = await readFile(`/proc/${pid}/cgroup`, "utf8");
    const unit = unitFromCgroup(cg);
    if (!unit) return { unit: null, userScoped: false };
    // Units under user.slice belong to the user manager — disable goes
    // through `systemctl --user` (server parity: rec.userUnit).
    return { unit, userScoped: cg.includes("/user.slice/") };
  } catch {
    /* unreadable */
  }
  return { unit: null, userScoped: false };
}

async function httpProbe(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/`, {
      signal: AbortSignal.timeout(HTTP_PROBE_TIMEOUT_MS),
      redirect: "manual",
    });
    const head = (await res.text()).slice(0, 64 * 1024);
    const title = head.match(/<title[^>]*>([^<]{1,120})<\/title>/i)?.[1]?.trim() ?? null;
    return { status: res.status, title, server: res.headers.get("server") };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// collectListeners — grouped, enriched, scored records
// ---------------------------------------------------------------------------

let snapshot = null; // { at, listeners, selfAncestors }

async function ancestorChain(pid) {
  // Walk /proc/<pid>/stat ppid up to pid 1 — used for the self/ancestor
  // refusal guard, no si dependency on the stop path.
  const chain = new Set();
  let cur = pid;
  for (let i = 0; i < 64 && cur > 1; i++) {
    try {
      const stat = await readFile(`/proc/${cur}/stat`, "utf8");
      const ppid = Number(
        stat
          .slice(stat.lastIndexOf(")") + 1)
          .trim()
          .split(/\s+/)[1],
      );
      if (!Number.isInteger(ppid) || ppid <= 0) break;
      chain.add(ppid);
      cur = ppid;
    } catch {
      break;
    }
  }
  return chain;
}

// `fixtures` is a test seam: { sockets, processes, conns, firewall } replaces
// the live `ss`+si.processes() probes so grouping/identification/evidence can
// be exercised without a real host. `conns` defaults to a readable-but-empty
// table; pass null to simulate an unreadable one. `firewall` injects a
// view object ({backend, allows(proto,port), detail}); absent → no overlay.
// Fixture runs never populate the cached snapshot.
async function collectListeners({ force = false, fixtures = null } = {}) {
  if (snapshot && !force && !fixtures && Date.now() - snapshot.at < 60_000)
    return snapshot.listeners;

  const [sockets, procList, conns, fwView] = fixtures
    ? [
        fixtures.sockets ?? [],
        { list: fixtures.processes ?? [] },
        fixtures.conns === undefined ? [] : fixtures.conns,
        fixtures.firewall ?? null,
      ]
    : await Promise.all([
        listSockets().catch(() => []),
        si.processes().catch(() => ({ list: [] })),
        listEstablished(),
        process.platform === "linux" ? firewallView() : Promise.resolve(null),
      ]);
  const procs = new Map((procList.list ?? []).map((p) => [p.pid, p]));

  // Group sockets under their owning pid; unidentified sockets stand alone.
  const byPid = new Map();
  for (const s of sockets) {
    const key = s.pid ?? `unowned:${s.protocol}:${s.address}:${s.port}`;
    if (!byPid.has(key)) byPid.set(key, []);
    byPid.get(key).push(s);
  }

  const selfPid = process.pid;
  const selfAncestors = await ancestorChain(selfPid);
  const selfUid = typeof process.getuid === "function" ? process.getuid() : null;
  const now = Date.now();

  // Persistence probes cache within a single pass (unit/exe → result, plus
  // shared autostart/crontab reads) — never across collection passes.
  const persistenceCache = new Map();
  const persistenceProbes = {};

  const records = [];
  for (const [key, socks] of byPid) {
    const pid = typeof key === "number" ? key : null;
    const proc = pid != null ? procs.get(pid) : null;

    const ports = socks.map((s) => ({
      protocol: s.protocol,
      address: s.address,
      port: s.port,
      scope: classifyBindAddress(s.address),
      url:
        s.protocol === "tcp" && classifyBindAddress(s.address) !== "public"
          ? `http://${s.address === "0.0.0.0" || s.address === "::" ? "127.0.0.1" : s.address}:${s.port}`
          : null,
    }));

    const cmdline = proc ? [proc.command, proc.params].filter(Boolean).join(" ") : null;
    const exe = proc?.path ?? null;
    const pname = proc?.command ?? socks[0]?.process ?? null;

    // --- identification waterfall -------------------------------------------
    let identifiedBy = "unknown";
    let name = null;
    let unit = null;
    let userUnit = false;
    let container = null;
    let cls = "unknown";
    let http = null;

    if (pid != null) {
      const u = await unitForPid(pid);
      if (u.unit) {
        unit = u.unit;
        userUnit = u.userScoped;
        // user@<uid>.service is recorded (it's real, and needed for stop
        // honesty) but is a session wrapper, not an identity — the
        // waterfall continues past it, same as the server's identUnit.
        if (!isSessionWrapper(u.unit)) {
          name = u.unit.replace(/\.service$/, "");
          identifiedBy = "systemd";
          cls = u.userScoped ? "unknown" : "system";
        }
      }
      if (!name && pname && CONTAINER_RE.test(pname)) {
        identifiedBy = "container";
        name = pname;
        cls = "container";
        container = { runtime: pname.includes("docker") ? "docker" : "other" };
      }
      if (!name && cmdline && DEV_SERVER_RE.test(cmdline)) {
        identifiedBy = "cmdline";
        cls = "dev-server";
        name = (cmdline.match(DEV_SERVER_RE)?.[1] ?? "dev server").toLowerCase();
      }
      if (pid === selfPid || selfAncestors.has(pid)) cls = "this-app";

      const hasHttpBind = ports.some(
        (p) => p.protocol === "tcp" && (p.scope === "loopback" || p.scope === "private"),
      );
      if (hasHttpBind && cls !== "this-app") {
        const p = ports.find((q) => q.protocol === "tcp");
        http = await httpProbe(p.port);
        if (http && !name) {
          identifiedBy = "http-probe";
          name = http.title || http.server || `http on :${p.port}`;
          if (cls === "unknown") cls = "dev-server";
        }
      }
      if (!name && pname) {
        identifiedBy = "cmdline";
        name = pname;
      }
    }
    if (!name) {
      const p = ports[0];
      const guess = PORT_NAMES[p.port];
      if (guess) {
        identifiedBy = "port-table";
        name = `${guess} (by port)`;
      }
    }

    // --- risk ---------------------------------------------------------------
    const scopes = new Set(ports.map((p) => p.scope));
    const reasons = [];
    let risk = "info";
    if (scopes.has("public")) {
      if (ports.some((p) => SENSITIVE_PUBLIC.has(p.port))) {
        risk = "critical";
        reasons.push(
          "database/control-plane port bound publicly — unauthenticated-by-default exposure",
        );
      } else if (identifiedBy === "unknown" || identifiedBy === "port-table") {
        risk = "high";
        reasons.push("public bind with no confident identification");
      } else {
        risk = "medium";
        reasons.push("reachable from the public internet");
      }
    } else if (scopes.has("tailscale")) {
      risk = "low";
      reasons.push("reachable across the tailnet");
    }
    if (cls === "dev-server" && pid != null) {
      const parent = proc?.parentPid != null ? procs.get(proc.parentPid) : null;
      if (proc?.parentPid && !parent) {
        reasons.push("spawning process is gone — likely abandoned");
        if (risk === "info" || risk === "low") risk = "medium";
      }
    }
    if (DATABASE_PORTS.has(ports[0]?.port) && !scopes.has("public") && risk === "info") {
      reasons.push("database port — verify it should be listening");
    }
    if (reasons.length === 0) {
      reasons.push(
        scopes.has("loopback")
          ? identifiedBy === "unknown"
            ? "loopback-only, unidentified"
            : `loopback/local bind, identified via ${identifiedBy}`
          : `identified via ${identifiedBy}`,
      );
    }

    // --- stoppable ------------------------------------------------------------
    let stoppable = "yes";
    let stopReason = null;
    let suggestedFix = null;
    if (pid == null || pid <= 1) {
      stoppable = "no";
      stopReason = pid == null ? "no owning pid reported for this socket" : "init/kernel pid";
    } else if (pid === selfPid || selfAncestors.has(pid) || cls === "this-app") {
      stoppable = "no";
      stopReason = "this process or an ancestor of it — stopping it would kill RootWatch";
    } else if (selfUid === null || proc?.uid == null || proc.uid !== selfUid) {
      stoppable = "elevated";
      stopReason = cls === "system" ? "system service — confirm before stopping" : null;
      // Only a real system unit is an honest `systemctl stop` suggestion —
      // user units live in another manager, and the session wrapper would
      // tear down the user's session. Both signal the pid instead.
      const stopUnit = unit && !userUnit && !isSessionWrapper(unit) ? unit : null;
      suggestedFix = stopUnit ? `sudo systemctl stop ${stopUnit}` : `sudo kill ${pid}`;
    } else if (cls === "system") {
      stopReason = "system service — confirm before stopping";
    }

    // --- persistence — resolved after pid→unit, since systemd detection
    // needs the resolved unit. null = "can't tell", never a guess.
    let persistence = null;
    if (pid != null && (unit || cmdline)) {
      if (!persistenceCache.has(pid)) {
        persistenceCache.set(
          pid,
          await detectPersistence({ pid, cmdline, systemdUnit: unit }, persistenceProbes),
        );
      }
      persistence = persistenceCache.get(pid);
    }

    const started = proc?.started ? Date.parse(proc.started) : null;
    records.push({
      key: String(key),
      pid,
      ports,
      name,
      identifiedBy,
      class: cls,
      risk,
      riskReasons: reasons,
      user: proc?.user ?? null,
      uid: proc?.uid ?? null,
      exe,
      cmdline,
      unit,
      container,
      spawnedBy:
        proc?.parentPid != null
          ? `${procs.get(proc.parentPid)?.command ?? "unknown"} (pid ${proc.parentPid})`
          : null,
      ageSeconds: started ? Math.max(0, Math.round((now - started) / 1000)) : null,
      cpu: proc?.cpu ?? 0,
      mem: proc?.mem ?? 0,
      // Resource cost per listener: cumulative %CPU (ps-style, like `top`),
      // resident set size in MB, and process uptime in seconds.
      cpuPercent: Number.isFinite(proc?.cpu) ? proc.cpu : null,
      memRssMb: Number.isFinite(proc?.memRss) ? Math.round((proc.memRss / 1024) * 10) / 10 : null,
      uptimeSec: started ? Math.max(0, Math.round((now - started) / 1000)) : null,
      persistence,
      http,
      userUnit,
      // Live-usage evidence: null means "not evaluable" (UDP-only, unreadable
      // conn table, unobservable pid) — never an implicit zero.
      activity: activityFor(ports, conns),
      egress: egressFor(pid, ports, conns),
      firewall: fwView ? firewallFor(ports, fwView) : null,
      duplicate: null, // flagged after all records exist (flagDuplicates)
      lastActiveAt: null, // merged from sighting history below
      stoppable,
      stopReason,
      suggestedFix,
    });
  }

  flagDuplicates(records, procs);

  // Idle-duration memory: the drift tick's sighting writes carry a
  // last_active timestamp; merge it so "active now" vs "idle 12d" are
  // distinguishable. db.cjs is lazily required — outside Electron it falls
  // back to a tmpdir store, and fixture runs skip the merge entirely.
  if (!fixtures) {
    try {
      const db = require("./db.cjs");
      const history = await db.getListenerHistory();
      const lastActive = new Map(
        history.filter((s) => s.lastActive).map((s) => [s.key, s.lastActive]),
      );
      for (const l of records) {
        l.lastActiveAt = lastActive.get(db.sightingKey(l)) ?? null;
      }
    } catch {
      /* no store — lastActiveAt stays null, honest "not tracked yet" */
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  records.sort((a, b) => order[a.risk] - order[b.risk] || a.pid - b.pid);
  if (!fixtures) snapshot = { at: Date.now(), listeners: records, selfAncestors };
  return records;
}

// ---------------------------------------------------------------------------
// Stop — same-uid direct signal; foreign-uid reports elevated_required.
// ---------------------------------------------------------------------------

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

async function stopListener(pid, { confirmSystem = false, disable = false } = {}) {
  const refuse = (message) => ({ status: "refused", message });
  if (!Number.isInteger(pid) || pid <= 1) {
    return refuse(`refusing to signal pid ${pid} (init/kernel/invalid)`);
  }
  const listeners = await collectListeners({ force: true });
  const rec = listeners.find((l) => l.pid === pid);
  if (!rec) return refuse("pid owns no listener in the current snapshot");
  if (pid === process.pid || rec.class === "this-app" || snapshot?.selfAncestors.has(pid)) {
    return refuse("refusing to stop this process or an ancestor of it");
  }
  if (rec.class === "system" && !confirmSystem) {
    return refuse(`${rec.name ?? "process"} is a system service — confirm to stop`);
  }

  // Stop & disable: a plain stop on a persistent service is a fake fix.
  // `systemctl disable --now` resolves the unit's cgroup itself, so this
  // path is immune to pid reuse — no socket re-verification needed.
  // user@<uid>.service is skipped: it's the session wrapper, not a unit of
  // this service — there is nothing to disable and it must never be a
  // systemctl target (mutating it would kill the user's session).
  if (disable && rec.unit && !isSessionWrapper(rec.unit) && process.platform === "linux") {
    const selfUid = typeof process.getuid === "function" ? process.getuid() : null;
    if (rec.userUnit && selfUid !== null && rec.uid === selfUid) {
      try {
        await execFileP("systemctl", ["--user", "disable", "--now", rec.unit], {
          timeout: 15_000,
        });
        return {
          status: "stopped",
          message: `stopped and disabled user unit ${rec.unit} — will not return on login`,
          method: "systemctl-user-disable",
        };
      } catch (e) {
        return refuse(`systemctl --user disable --now ${rec.unit} failed: ${e.message}`);
      }
    }
    return {
      status: "elevated_required",
      message: `${rec.unit} runs in the ${rec.userUnit ? "another user's" : "system"} manager — the desktop app has no privileged helper; run the command manually`,
      suggestedFix: rec.userUnit
        ? `run as that user: systemctl --user disable --now ${rec.unit}`
        : `sudo systemctl disable --now ${rec.unit}`,
    };
  }

  // PID-reuse guard: pid must still own exactly the sockets we listed.
  const expected = new Set(rec.ports.map((p) => `${p.protocol}:${p.address}:${p.port}`));
  const live = new Set(
    (await listSockets().catch(() => []))
      .filter((s) => s.pid === pid)
      .map((s) => `${s.protocol}:${s.address}:${s.port}`),
  );
  if (live.size === 0 || ![...live].some((k) => expected.has(k))) {
    return refuse("pid no longer owns the listed sockets — process exited or rebound");
  }
  if ([...live].some((k) => !expected.has(k))) {
    return refuse("pid now owns sockets not in the listing — possible pid reuse, refusing");
  }

  // `disable` with no resolvable unit (or only the session wrapper): stop
  // still proceeds — the note just keeps the outcome honest about
  // persistence we couldn't remove.
  const disableNote =
    disable && (!rec.unit || isSessionWrapper(rec.unit))
      ? " — no systemd unit to disable; autostart/cron persistence (if any) needs manual removal"
      : "";

  const selfUid = typeof process.getuid === "function" ? process.getuid() : null;
  if (selfUid === null || rec.uid == null || rec.uid !== selfUid) {
    // A session-wrapper or user unit is never a `systemctl stop` target on
    // the system bus — the honest manual command signals the pid.
    const stopUnit = rec.unit && !rec.userUnit && !isSessionWrapper(rec.unit) ? rec.unit : null;
    return {
      status: "elevated_required",
      message:
        "owned by another user — the desktop app runs without root; run the command manually",
      suggestedFix: stopUnit ? `sudo systemctl stop ${stopUnit}` : `sudo kill ${pid}`,
    };
  }

  try {
    process.kill(pid, "SIGTERM");
  } catch (e) {
    if (e.code === "ESRCH")
      return { status: "stopped", message: "process already exited", method: "sigterm" };
    if (e.code === "EPERM")
      return {
        status: "elevated_required",
        message: "signal refused — insufficient privileges",
        suggestedFix: `sudo kill ${pid}`,
      };
    return refuse(`SIGTERM failed: ${e.message}`);
  }
  const deadline = Date.now() + KILL_GRACE_MS;
  while (Date.now() < deadline && pidAlive(pid)) await sleep(100);
  if (!pidAlive(pid)) {
    return {
      status: "stopped",
      message: `terminated ${rec.name ?? `pid ${pid}`} with SIGTERM${disableNote}`,
      method: "sigterm",
    };
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch (e) {
    return refuse(`SIGKILL failed: ${e.message}`);
  }
  await sleep(150);
  if (!pidAlive(pid)) {
    return {
      status: "stopped",
      message: `killed ${rec.name ?? `pid ${pid}`} with SIGKILL${disableNote}`,
      method: "sigkill",
    };
  }
  return {
    status: "elevated_required",
    message: "process survived SIGTERM/SIGKILL — manual intervention required",
    suggestedFix: `sudo kill -9 ${pid}`,
  };
}

// ---------------------------------------------------------------------------
// Fleet report snapshot — same shape the server fleet-reporter builds, plus a
// bounded listenerItems[] the control plane can surface per-device.
// ---------------------------------------------------------------------------

async function buildReport() {
  // checks.cjs requires this module back for the status helpers — require
  // lazily here so neither side sees a half-initialized module.
  const { runLocalChecks } = require("./checks.cjs");
  const [listeners, host, metrics, updates, fw, ssh, localChecks] = await Promise.all([
    collectListeners(),
    si.osInfo().catch(() => null),
    Promise.all([
      si.currentLoad().catch(() => null),
      si.mem().catch(() => null),
      si.fsSize().catch(() => null),
    ]),
    pendingUpdates().catch(() => ({ supported: false })),
    firewallStatus().catch(() => ({ supported: false })),
    sshStatus().catch(() => ({ supported: false })),
    runLocalChecks().catch(() => []),
  ]);

  const [load, mem, fs] = metrics;
  const publicPorts = listeners
    .flatMap((l) => l.ports)
    .filter((p) => p.scope === "public")
    .map((p) => ({ port: p.port, protocol: p.protocol, process: undefined }));

  // Compact honest check set for the device card: the locally-measured
  // public-listeners check plus the ported host checks (runLocalChecks is
  // a no-op off Linux — total then reflects only what could be evaluated).
  const checkResults = [
    {
      id: "public-listeners",
      name:
        publicPorts.length === 0
          ? "No public listeners"
          : `${publicPorts.length} public listener(s)`,
      severity: "high",
      passed: publicPorts.length === 0,
      detail:
        publicPorts.length === 0
          ? "No sockets bound to public addresses."
          : `Public binds: ${publicPorts.map((p) => `${p.port}/${p.protocol}`).join(", ")}.`,
    },
    ...localChecks,
  ];
  const checks = {
    total: checkResults.length,
    passed: checkResults.filter((c) => c.passed).length,
    failing: checkResults
      .filter((c) => !c.passed)
      .map((c) => ({ id: c.id, name: c.name, severity: c.severity })),
  };

  const root = (fs ?? []).find((f) => f.mount === "/") ?? (fs ?? [])[0];
  return {
    uptimeSeconds: Math.round(os.uptime()),
    metrics: {
      cpuPercent: load ? Math.round(load.currentLoad * 10) / 10 : null,
      memPercent: mem ? Math.round((1 - mem.available / mem.total) * 1000) / 10 : null,
      diskPercent: root ? Math.round(root.use * 10) / 10 : null,
    },
    checks,
    firewall: {
      supported: fw.supported === true,
      // null = backend present but state unreadable — report unknown, not
      // a fabricated "inactive".
      active: fw.active === true ? true : fw.active === null ? null : false,
      backend: fw.backend ?? null,
    },
    ssh: {
      supported: ssh.supported === true,
      serviceActive: ssh.active ?? null,
      permitRootLogin: ssh.permitRootLogin ?? null,
      passwordAuthentication: ssh.passwordAuthentication ?? null,
    },
    listeners: {
      total: listeners.reduce((n, l) => n + l.ports.length, 0),
      publicCount: publicPorts.length,
      internalCount: listeners.reduce((n, l) => n + l.ports.length, 0) - publicPorts.length,
      publicPorts,
      items: listeners.slice(0, 100).map((l) => ({
        pid: l.pid,
        name: l.name,
        identifiedBy: l.identifiedBy,
        class: l.class,
        risk: l.risk,
        ports: l.ports.map((p) => ({
          protocol: p.protocol,
          address: p.address,
          port: p.port,
          scope: p.scope,
        })),
        cpuPercent: l.cpuPercent,
        memRssMb: l.memRssMb,
        uptimeSec: l.uptimeSec,
        persistence: l.persistence,
        established: l.activity?.established ?? null,
        lastActiveAt: l.lastActiveAt,
        duplicate: l.duplicate,
      })),
    },
    updates: {
      supported: updates.supported === true,
      count: updates.count ?? null,
      securityCount: updates.securityCount ?? null,
      manager: updates.manager ?? null,
    },
    os: host ? `${host.distro ?? ""} ${host.release ?? ""}`.trim() : null,
  };
}

async function pendingUpdates() {
  if (os.platform() !== "linux") return { supported: false };
  try {
    const { stdout } = await execFileP("apt", ["list", "--upgradable", "-qq"], { timeout: 15_000 });
    // Lines look like: "pkg/noble-security 1.2.3 amd64 [upgradable from: 1.2.2]"
    const entries = stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("Listing"))
      .map((l) => ({
        name: l.split("/")[0],
        pocket: l.split("/")[1]?.split(/\s+/)[0] ?? "",
      }))
      .filter((e) => e.name);
    const security = entries.filter((e) => /security|esm/i.test(e.pocket));
    return {
      supported: true,
      count: entries.length,
      packages: entries.map((e) => e.name).slice(0, 50),
      securityCount: security.length,
      securityPackages: security.map((e) => e.name).slice(0, 50),
      manager: "apt",
    };
  } catch {
    return { supported: false };
  }
}

async function firewallStatus() {
  if (os.platform() !== "linux") return { supported: false, active: false, backend: null };
  try {
    const { stdout } = await execFileP("ufw", ["status"], { timeout: 5_000 });
    return { supported: true, active: /status:\s*active/i.test(stdout), backend: "ufw" };
  } catch (err) {
    // `ufw status` refuses non-root users even when the firewall is
    // enabled. If the binary exists (ENOENT means absent), fall back to
    // unprivileged signals: /etc/ufw/ufw.conf ENABLED=yes.
    if (err?.code !== "ENOENT") {
      try {
        const conf = await readFile("/etc/ufw/ufw.conf", "utf8");
        return { supported: true, active: /^ENABLED=yes/m.test(conf), backend: "ufw" };
      } catch {
        /* config unreadable — report ufw present, state unknown */
      }
      // ufw present but status and config both unreadable — active:null is
      // "unevaluable", NOT "no firewall" (a non-observation must not read
      // as an inactive ruleset).
      return { supported: true, active: null, backend: "ufw" };
    }
  }
  try {
    const { stdout } = await execFileP("firewall-cmd", ["--state"], { timeout: 5_000 });
    return { supported: true, active: stdout.trim() === "running", backend: "firewalld" };
  } catch {
    /* firewalld unavailable */
  }
  try {
    const { stdout } = await execFileP("iptables", ["-L", "-n"], { timeout: 5_000 });
    // Any rule line beyond chain/policy headers counts as an active ruleset
    const ruleLines = stdout.split("\n").filter((l) => {
      const t = l.trim();
      return t && !t.startsWith("Chain ") && !t.startsWith("target ") && !t.startsWith("pkts ");
    });
    return { supported: true, active: ruleLines.length > 0, backend: "iptables" };
  } catch {
    return { supported: false, active: false, backend: null };
  }
}

// ---------------------------------------------------------------------------
// sshd status — port of server/services/collectors.ts collectSshStatus:
// effective global settings with OpenSSH first-match semantics across
// sshd_config + Include'd drop-ins, plus unit activity where systemctl is
// present. supported:false when no sshd config/unit is readable.
// ---------------------------------------------------------------------------

const SSHD_BASE = "/etc/ssh";

// Expand an sshd Include glob (e.g. `/etc/ssh/sshd_config.d/*.conf`).
// Relative patterns resolve against /etc/ssh per sshd_config(5); OpenSSH
// applies included files in lexical order via glob(3).
async function expandSshdInclude(pattern) {
  const abs = pattern.startsWith("/") ? pattern : path.join(SSHD_BASE, pattern);
  if (!/[*?[]/.test(abs)) return [abs];
  const dir = path.dirname(abs);
  const rx = new RegExp(
    "^" +
      path
        .basename(abs)
        .replace(/[.+^$(){}|\\]/g, "\\$&")
        .replace(/\*/g, "[^/]*")
        .replace(/\?/g, "[^/]") +
      "$",
  );
  try {
    return (await readdir(dir))
      .filter((f) => rx.test(f))
      .sort()
      .map((f) => path.join(dir, f));
  } catch {
    return []; // included dir absent/read-protected — sshd ignores it too
  }
}

// Record the FIRST obtained value of each global directive — OpenSSH uses
// first-match semantics, and Include directives expand inline at the point
// they appear. Global parsing stops at the first Match block.
async function sshdGlobalSettings(confPath, visited, out, depth) {
  if (depth > 4 || visited.has(confPath)) return;
  visited.add(confPath);
  const raw = await readFile(confPath, "utf8").catch(() => null);
  if (raw === null) return;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = trimmed.match(/^(\S+)\s+(.+)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const arg = m[2].trim();
    if (key === "match") return;
    if (key === "include") {
      for (const pat of arg.split(/\s+/)) {
        for (const f of await expandSshdInclude(pat)) {
          await sshdGlobalSettings(f, visited, out, depth + 1);
        }
      }
      continue;
    }
    if (!(key in out)) out[key] = arg.toLowerCase();
  }
}

async function sshStatus() {
  const status = {
    supported: false,
    active: null,
    service: null,
    permitRootLogin: null,
    passwordAuthentication: null,
  };
  if (os.platform() !== "linux") return status;

  try {
    await readFile("/etc/ssh/sshd_config", "utf8"); // throws if unreadable → unsupported
    const settings = {};
    await sshdGlobalSettings("/etc/ssh/sshd_config", new Set(), settings, 0);
    status.supported = true;
    status.permitRootLogin = settings["permitrootlogin"] ?? null;
    status.passwordAuthentication = settings["passwordauthentication"] ?? null;
  } catch {
    /* no sshd_config readable */
  }

  for (const unit of ["sshd", "ssh"]) {
    try {
      const { stdout } = await execFileP("systemctl", ["is-active", unit], { timeout: 5_000 });
      status.service = unit;
      status.active = stdout.trim() === "active";
      status.supported = true;
      break;
    } catch {
      /* try next unit */
    }
  }
  return status;
}

module.exports = {
  collectListeners,
  stopListener,
  buildReport,
  classifyBindAddress,
  // Pure ss-output parser — test seam for the socket inventory.
  parseSsRows,
  // Pure cgroup→unit resolver — test seam for the systemd identity layer.
  unitFromCgroup,
  // Status helpers shared with checks.cjs (server collectors.ts ports).
  pendingUpdates,
  firewallStatus,
  sshStatus,
};
