# RootWatch packaging — privileged remediation executor

RootWatch never runs remediation commands as the service user. Each approved
plan step goes to a **root-owned helper** through `sudo -n`:

```
app (rootwatch user) ──► sudo -n /opt/rootwatch/libexec/rootwatch-remediate --step <base64-json>
                              │
                              ├─ re-validates: binary allowlist, per-binary
                              │   flag allowlist, verb allowlist, strict arg
                              │   charset, no shell metacharacters
                              └─ exec argv (no shell, ever)
```

## Files

| File                         | Install target                                      | Owner     | Mode   |
| ---------------------------- | --------------------------------------------------- | --------- | ------ |
| `rootwatch-remediate`        | `/opt/rootwatch/libexec/rootwatch-remediate`        | root:root | `0750` |
| `write-sshd-dropin`          | `/opt/rootwatch/libexec/write-sshd-dropin`          | root:root | `0750` |
| `remove-sshd-dropin`         | `/opt/rootwatch/libexec/remove-sshd-dropin`         | root:root | `0750` |
| `write-docker-no-tcp-dropin` | `/opt/rootwatch/libexec/write-docker-no-tcp-dropin` | root:root | `0750` |
| `fix-docker-daemon-json`     | `/opt/rootwatch/libexec/fix-docker-daemon-json`     | root:root | `0750` |
| `remove-docker-dropin`       | `/opt/rootwatch/libexec/remove-docker-dropin`       | root:root | `0750` |
| `sudoers.d/rootwatch`        | `/etc/sudoers.d/rootwatch`                          | root:root | `0440` |

`rootwatch-remediate` is the only binary sudo can invoke. The other helpers
are called _by_ `rootwatch-remediate` (already root) for multi-step plans —
`bash` steps are only permitted for scripts under `/opt/rootwatch/libexec/`.

- `write-sshd-dropin` / `remove-sshd-dropin` manage whitelisted directives in
  `/etc/ssh/sshd_config.d/00-rootwatch.conf`, validating syntax with
  `sshd -t` AND the effective value with `sshd -T` (first-match semantics —
  the 00- name sorts ahead of vendor drop-ins like `50-cloud-init.conf`;
  a stale `99-rootwatch.conf` from older installs is migrated and removed),
  restoring the previous file on failure. **Requires**
  `Include /etc/ssh/sshd_config.d/*.conf` near the top of `sshd_config`
  (OpenSSH takes the first obtained value — the Include must precede
  conflicting global settings).
- `write-docker-no-tcp-dropin` writes a `docker.service` systemd override
  re-binding dockerd to `fd://` only; `fix-docker-daemon-json` strips a
  `"hosts"` key from `/etc/docker/daemon.json` (with a timestamped backup);
  `remove-docker-dropin` deletes the override (its path is hardcoded —
  it can remove nothing else).

Runtime dependency: `python3` (present on Ubuntu) or `jq` to decode step
payloads.

## Install

```bash
# service account the app runs as (adjust to your deployment)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rootwatch

for f in rootwatch-remediate write-sshd-dropin remove-sshd-dropin \
         write-docker-no-tcp-dropin fix-docker-daemon-json remove-docker-dropin; do
  sudo install -D -o root -g root -m 0750 "packaging/$f" "/opt/rootwatch/libexec/$f"
done

# validate FIRST — a broken sudoers file can break sudo for the whole box
sudo install -D -o root -g root -m 0440 \
  packaging/sudoers.d/rootwatch /etc/sudoers.d/rootwatch
sudo visudo -cf /etc/sudoers.d/rootwatch
```

If the service user is not `rootwatch`, edit `/etc/sudoers.d/rootwatch`
accordingly and re-run `visudo -cf`.

## Verify

As the service user:

```bash
# should print the NOPASSWD entry; exits non-zero if unconfigured
sudo -n -l /opt/rootwatch/libexec/rootwatch-remediate

# harmless smoke test — validates sshd config syntax only
sudo -n /opt/rootwatch/libexec/rootwatch-remediate \
  --step "$(printf '%s' '{"label":"check sshd config","argv":["sshd","-t"]}' | base64 -w0)"
```

The app performs the same `sudo -n -l` probe; when it fails, remediations land
in the honest `executor-unavailable` status with these instructions.

## Security notes

- The sudoers entry allows the helper **with any arguments** — argument
  validation lives inside the helper (and again app-side). The helper must
  stay `root:root 0750`; the app refuses to use it if it is group/world
  writable.
- No arbitrary commands cross the privilege boundary: argv is screened
  twice, every option must be in a per-binary allowlist, and execution is
  `exec "${ARGV[@]}"` — no shell string is ever built.
- `kill` is allowlisted only as `kill [-TERM|-KILL|-15|-9] <numeric-pid>`
  (init/pid 0 refused) — it exists so the listener inventory can stop a
  foreign-uid listener after the app re-verifies pid↔socket ownership.
- Step stdout/stderr is captured, secret-redacted (RootWatch `rw_` tokens and
  `password|token|secret`-style assignments), truncated to 8 KB per step, and
  stored in `remediation_actions.result`. The helper also echoes the argv to
  stderr for the audit trail.

## ⚠ `ROOTWATCH_EXECUTOR_DRY_RUN=1` — dev/test only, NEVER production

Setting this env var makes `runPlan()` skip sudo entirely and fabricate
successful results (`[dry-run] would run: <argv>`). It exists so the engine,
routes, and tests can exercise the propose → execute flow on machines
without the helper installed. **It makes the executor lie.** Never set it on
a real deployment.
