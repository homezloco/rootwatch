# Security Policy

The code in this repo runs with real privilege — `scripts/install.sh`
expects to be piped to `sudo bash`, the `packaging/` helpers execute under
sudo as root, and the agent reports host posture to a control plane. We
take vulnerabilities in it seriously.

## Reporting a vulnerability

**Do not file a public issue for an exploitable bug.**

- Preferred: open a private advisory via this repo's
  [GitHub Security Advisories](../../security/advisories/new) page.
- Email fallback: `hello@rootwatch.dev` (subject: "RootWatch security").

Include the affected component and version/commit, reproduction steps, and
impact. We aim to acknowledge within 72 hours and will credit reporters
unless you ask us not to.

## Scope

In scope here: `agent/`, `cli/`, `desktop/`, `packaging/`, `scripts/`,
and this repo's release workflows.

Vulnerabilities in the hosted control plane (app.rootwatch.dev) or the
self-hosted server bundle are handled in the private development trunk —
report them to the same address; they still get fixed.

## Design notes for auditors

- `scripts/install.sh` verifies the server tarball against the release's
  published `SHA256SUMS` and refuses unverified or mismatched downloads.
- `packaging/rootwatch-remediate` is the only binary sudo can invoke; step
  argv is screened against per-binary allowlists on both the app side and
  inside the helper, and executed with `exec` — never a shell.
- Listener kills re-verify pid↔socket ownership immediately before
  signalling (PID-reuse guard), refuse self/ancestors/pid ≤ 1, and route
  elevated stops through the allowlisted helper.
- API tokens are sha256-hashed at rest server-side; agent/desktop store
  them chmod-600 or via OS keychain (`safeStorage`).
