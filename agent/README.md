# RootWatch fleet agent

`agent.mjs` is a zero-dependency, single-file Node 18+ posture reporter. It
collects real host state (listening ports, firewall, sshd config, pending
updates, file-integrity hashes, process/log detections, metrics), evaluates
the same check verdicts the server rule engine produces, and POSTs one
snapshot to the control plane's `POST /api/v1/devices/report`. No database,
no inbound listeners — outbound HTTPS only, on a 5-minute systemd timer
(cron on Termux).

## Install

```bash
# Linux (systemd)
curl -fsSL https://rootwatch.dev/agent/install.sh | sudo bash -s -- <control-url> [credential]

# Android / Termux
curl -fsSL https://rootwatch.dev/agent/install-termux.sh | bash -s -- <control-url> [credential]
```

`credential` is either an `RW-XXXX-XXXX:secret` bootstrap pair (one-shot
claim of a pre-approved token), an `rw_…` write-scope API token, or omitted
to pair interactively with an enrollment code approved in the web UI.

## Run standalone

```bash
CONTROL_PLANE_URL=https://your-instance CONTROL_PLANE_TOKEN=rw_... node agent.mjs
node agent.mjs enroll <control-url>          # RW_ENV_FILE=/path to persist the minted token
node agent.mjs claim <control-url> <code> <secret>
```

An HTTP 401/403 from the report endpoint means the credential was revoked —
the agent self-uninstalls (units, env file, state) and exits.

## Remote commands

The report response may carry claimed commands; each is executed once and
its outcome rides back in `commandResults` on a single follow-up report
(the follow-up's own commands are ignored — no loops).

| Command | Payload | Behavior |
| --- | --- | --- |
| `refresh` | — | Follow-up report is a fresh snapshot. |
| `update` | `{url}` | Downloads a new agent build, syntax-vets it via `node --check` on a probe copy, then atomically replaces `agent.mjs`. |
| `uninstall` | — | Removes units/crontab entry, env file, and state. |
| `apply-updates` | — | Runs the host package manager upgrade (root required). |
| `fix-check` | `{checkId}` | Remediates one of `pending-security-updates`, `firewall-active`, `auto-security-updates` (root required). |
| `stop-listener` | `{pid}` | Guarded SIGTERM→SIGKILL of a listening process — see below. |
| `remediate` | `{actionId?, phase, steps:[{label, argv}]}` | Runs a validated argv plan — see below. |
| anything else | — | Honestly acked `unsupported`. |

### `remediate` guards

The plan's argv is re-validated on the device with the same discipline as
the privileged helper `packaging/rootwatch-remediate` — binary allowlist
(`apt-get`, `dnf`, `ufw`, `systemctl`, `sshd`, `dpkg`, `kill`; **no `bash`** —
there is no root-owned `libexec` on agent devices), exact per-binary flag
allowlists (blocks option smuggling like `apt-get -o APT::...=cmd`),
per-binary verb requirements, a metacharacter/charset screen on every arg,
and the session-manager guard (`user@<uid>.service` only with
`is-active`/`is-enabled` — mutating it kills the user's session). Steps run
sequentially via `execFile` — never a shell — stop at the first non-zero
exit, and require root (uid 0).

Outcome shape: `commandResults[].result` is `{actionId?, phase, steps:
[{label, argv, exitCode, stdout?, stderr?, signal?}], reason?}` with output
tail-capped at ~8KB. All steps at exit 0 → `done`; first non-zero exit or a
validation refusal → `failed`; non-root, a binary class the agent doesn't
support, or an uninstalled binary → `unsupported`. `phase` (`execute`|
`rollback`) is informational and passed straight through.

### `stop-listener` guards

Mirrors the desktop collector's stop semantics — the payload is only a pid,
so every safety check is re-evaluated at execution time, not trusted from
whatever the control plane saw earlier:

- **Validation** — `payload.pid` must be an integer `> 1`; anything else is
  `refused: invalid pid`. pid 1 can never be signalled.
- **Self-protection** — the agent's own pid and every ancestor reached by
  walking `/proc/<pid>/status` PPid links up to init are refused (killing
  one would take the agent down mid-report).
- **PID-reuse guard** — before any signal, socket enumeration is re-run
  (`ss -tlnuHp`, the same `ss` source the report's listener inventory uses,
  plus `-p` for ownership). If the pid no longer owns a listening socket the
  command fails honestly (`pid no longer owns a listener`) — a reused pid
  is never signalled on stale information. If ownership can't be verified
  at all (no `ss`), it fails rather than signalling blind.
- **Ownership** — `/proc/<pid>/status` `Uid` is compared to the agent's
  `getuid()`. A foreign-uid target with a non-root agent returns
  `elevated_required` with `suggestedFix: "sudo kill <pid>"`; an unreadable
  owner is refused too — never signalled on a guess.
- **Stop sequence** — SIGTERM, up to ~3s polling liveness (`/proc` state,
  zombies count as dead), then SIGKILL if it's still alive.

Outcome shape: `{status: stopped|failed|refused|elevated_required, message,
method: "signal", suggestedFix?}` in `commandResults[].result`; `stopped`
maps to command status `done`, everything else to `failed` with the detail
preserved in the result object. `elevated_required` is an honest
capability answer, not a fabricated failure — the systemd install runs the
agent as root, so it only appears on unprivileged (e.g. Termux/manual)
deployments, or when a process survives SIGKILL.

## Honesty rules

Every collector degrades to `supported: false` or omits its field rather
than fabricating data: unsupported checks don't count as passes, an
unreachable probe is "can't evaluate", and detection evidence is the actual
observed line/cmdline (truncated), never inferred.
