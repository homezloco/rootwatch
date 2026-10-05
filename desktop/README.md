# RootWatch Desktop (Linux)

Electron client + local sensor for RootWatch — "the dev security control
panel". Two roles in one app:

1. **Client** — the window loads a RootWatch instance
   (`https://rootwatch.dev` by default, or any self-hosted deployment) in a
   hardened, sandboxed renderer; the tray polls the versioned `/api/v1`
   API with an org-scoped `rw_` token for a live security score +
   Critical/High event notifications.
2. **Local sensor** — a "This device" surface (`device.html` +
   `collector.cjs`) that inventories this machine's open listeners,
   evaluates a subset of the host security checks, and — once paired —
   reports posture to the connected instance so the laptop appears as a
   watched device in the fleet views.

The server stays the trust boundary — this app does **not** bundle the
Express server or a database.

## What it does

### Connected instance (client)

- Connect screen → validates the URL is a RootWatch instance
  (`/api/v1/org` probe), then loads it in a hardened window (sandboxed,
  context-isolated, same-origin navigation only, external links open in
  the browser).
- System tray icon: live security score, open criticals, 24h event count
  (polls `GET /api/v1/score` every 60s).
- Desktop notifications for new Critical/High events.
- API token encrypted at rest via `safeStorage` (OS keychain /
  `org.freedesktop.secrets`). If no keychain is available the token is
  held in memory only — never written to disk plaintext.

### This device (local sensor)

Reachable via tray → _This device…_, the app menu (Alt → RootWatch →
_This device…_), `rootwatch device`, or the launcher "This device"
desktop action — no tray icon required.

- **Listener inventory** — every TCP/UDP LISTEN socket grouped by pid,
  identified through the same honest-confidence waterfall as the server
  (systemd → container → cmdline → http-probe → port-table → unknown,
  recorded on `identifiedBy`). `sockets-{linux,macos,win}.cjs` provide
  the platform socket source (`ss` / `lsof` / `netstat -ano`).
- **Cost + persistence** — per-listener cpu%/RSS/uptime, plus a
  "returns on boot" badge when `persistence.cjs` finds the process in an
  enabled systemd unit, XDG autostart entry, or `@reboot` crontab.
- **Security checks** — `checks.cjs` ports the host-check subset
  (firewall, sshd config, pending security updates) with the server's
  canonical check ids.
- **Project scan** — `scan.cjs` ports the CLI secrets+hygiene scanner;
  per-listener "Scan" audits the owning process's working directory.
  Findings carry kind+location only — secrets are never emitted.
- **Stops** — same-user processes: SIGTERM → 3s → SIGKILL with a
  pid↔socket re-verification right before signalling (PID-reuse guard);
  refuses self/ancestors/pid ≤1/system units without confirm. Foreign-uid
  targets return `elevated_required` + the exact `sudo` command — the app
  has no privileged helper by design.
- **Drift alerts** — a 60s tick diffs socket ownership and raises a
  native notification on new binds (first pass seeds a silent baseline).
- **History** — `db.cjs` (`node:sqlite` with a JSONL fallback) anchors
  first-seen timestamps across restarts.
- **Offline queue** — failed reports persist locally and drain
  oldest-first on reconnect (cap 200, >24h dropped, 4xx dropped rather
  than poisoned).

### Fleet sync

`device.cjs` pairs via the Tailscale-style enrollment flow — _Pair this
device_ prints an `RW-XXXX-XXXX` code, an org admin approves it in the
web app (Add device → enter code), and the app claims a write-scope
token once. It then POSTs `report` snapshots to
`/api/v1/devices/report` every 60s and executes claimed commands:
`stop-listener` (through the same guarded `stopListener`) and `refresh`
(immediate re-report); other command types ack `unsupported` honestly.
hostId = `sha256("rootwatch-host:" + machine-id)` — the same derivation
the server's fleet reporter uses, so an `install.sh` host and the
desktop app converge on one device row. The raw machine-id never leaves
the host.

## Auto-update

Packaged builds check GitHub releases (`publish.provider: github` in
`electron-builder.yml`) on launch and every 6h via `electron-updater`,
and notify when a download is ready. Releasing = `npm run
dist` + `gh release create vX.Y.Z release/RootWatch-X.Y.Z.AppImage
release/rootwatch-desktop_X.Y.Z_amd64.deb release/latest-linux.yml`
(`latest-linux.yml` is required — the updater reads it).

## Develop

```bash
npm install   # in this directory
npm run dev   # electron .
```

Needs a display; on headless machines use `xvfb-run`.

## Build packages

```bash
npm run dist        # AppImage + deb + snap → ../release/
npm run dist:dir    # unpacked dir (fast sanity check)
```

## Flatpak

An experimental manifest lives in `flatpak/` — the sandbox restricts
procfs/`ss` access, so the local sensor features degrade to the
web-client role only.
