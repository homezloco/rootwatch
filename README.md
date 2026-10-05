# RootWatch — the parts that run on your machines

RootWatch is a host-security control panel for developers. This repo
contains the client side — the fleet agent, the CLI, the desktop app, the
privileged packaging helpers, and the self-host installer — under
Apache-2.0 so you can audit every byte that gets `sudo`'d onto your boxes.

The control plane (web dashboard, REST API, MCP server) is closed-source.
It's available as hosted SaaS at [app.rootwatch.dev](https://app.rootwatch.dev),
or self-hosted from the verified server tarball published to
[homezloco/rootwatch-releases](https://github.com/homezloco/rootwatch-releases/releases)
— `scripts/install.sh` downloads it and checks the sha256 before touching
your system.

## Layout

| Dir          | What                                                                        |
| ------------ | --------------------------------------------------------------------------- |
| `agent/`     | Zero-dep Node 18+ posture reporter + systemd/Termux installers              |
| `cli/`       | `rootwatch`/`rw` — terminal client, local project scanner, MCP stdio bridge |
| `desktop/`   | Electron client + "This device" local sensor (AppImage / deb / snap)        |
| `packaging/` | Root-owned remediation helpers + sudoers fragment the installer drops       |
| `scripts/`   | `install.sh` self-host installer, `start.sh` service entrypoint             |
| `docs/`      | The [rootwatch.dev](https://rootwatch.dev) site (GitHub Pages)              |

## Quick start

| Goal                 | Command / link                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| Watch a host (agent) | `curl -fsSL https://rootwatch.dev/agent/install.sh \| sudo bash -s -- <control-url>`                    |
| Self-host the server | `curl -fsSL https://raw.githubusercontent.com/homezloco/rootwatch/main/scripts/install.sh \| sudo bash` |
| Desktop app          | [Releases](https://github.com/homezloco/rootwatch-releases/releases) — AppImage / deb / snap            |
| CLI                  | Not yet on npm — `cd cli && npm install && npm run build && npm link`                                   |

Every client authenticates to a control plane with an org-scoped `rw_…`
Bearer token; the server is the only trust boundary. The agent and
installers also support code-based pairing — no token handling required.

## Honesty rules

The code in this repo follows the platform's real-data-only contract:
collectors degrade to `supported: false` or honest `unsupported`/`refused`
answers rather than fabricating results, privileged operations re-verify
their target right before acting (PID-reuse guards, argv allowlists), and
no shell string is ever built across the privilege boundary.

## Contributing / security

Development happens in a private monorepo; this repo is a release-time
mirror. Issues and PRs here are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately via
[SECURITY.md](SECURITY.md).
