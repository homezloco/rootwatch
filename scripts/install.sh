#!/usr/bin/env bash
# RootWatch server installer — idempotent.
#
# Default path: downloads the latest published server bundle
# (rootwatch-server-<ver>-linux-x64.tar.gz + SHA256SUMS, sha256-verified)
# from the PUBLIC releases-only repo homezloco/rootwatch-releases — no
# git/npm needed on the host. REPO_URL is a maintainer escape hatch: when
# set, the installer instead clones that repo (normally the PRIVATE source
# repo — the public homezloco/rootwatch repo carries no server source) and
# builds on the host with `npm ci` + `npm run build`.
#
# Installs:
#   - app bundle at $INSTALL_DIR/app (native — collectors must see the host,
#     so the app itself does NOT run in a container)
#   - Postgres 16 in a docker container bound to localhost
#   - privileged remediation helpers + sudoers allowlist
#   - systemd service `rootwatch` (migrations run on every start via start.sh)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/homezloco/rootwatch/main/scripts/install.sh | sudo bash
#   sudo BIND_ADDR=100.66.221.81 bash scripts/install.sh     # tailnet-only bind
#
# Knobs (env): SERVER_VERSION REPO_URL REPO_REF INSTALL_DIR SERVICE_USER BIND_ADDR
#              APP_PORT PG_PORT SKIP_HELPERS=1 TAILSCALE_SERVE=1
#              CONTROL_PLANE_URL CONTROL_PLANE_TOKEN
#              INSTALL_CLAMAV=1|0  — signature engine for malware scans.
#              Unset + interactive terminal → prompted (default yes);
#              unset + non-interactive → skipped (heuristics-only scans)
#
# Production sessions use Secure cookies — the UI is only usable over HTTPS
# or from a browser on the same machine (localhost is a secure context).
# For remote access, TAILSCALE_SERVE=1 publishes https://<host>.<tailnet>.ts.net
# → 127.0.0.1:$APP_PORT via `tailscale serve` (tailnet-only, real TLS cert).
set -euo pipefail

REPO_URL="${REPO_URL:-}"   # set → maintainer source build (clone+npm); unset → release tarball
REPO_REF="${REPO_REF:-main}"
RELEASES_REPO="${RELEASES_REPO:-homezloco/rootwatch-releases}"
INSTALL_DIR="${INSTALL_DIR:-/opt/rootwatch}"
SERVICE_USER="${SERVICE_USER:-rootwatch}"
SERVICE_HOME="/var/lib/${SERVICE_USER}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
APP_PORT="${APP_PORT:-5000}"
PG_PORT="${PG_PORT:-5432}"
PG_CONTAINER="rootwatch-pg"
APP_DIR="${INSTALL_DIR}/app"
ENV_FILE="${INSTALL_DIR}/.env"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

TMP=""   # set by the tarball path; cleaned up on exit
trap 'if [ -n "${TMP:-}" ]; then rm -rf "$TMP"; fi' EXIT

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash scripts/install.sh"

# ---- dependencies -----------------------------------------------------------
# Minimal posture: tarball installs don't need git/npm — those are only
# required for the REPO_URL source-build path.
need="node docker curl openssl tar sha256sum"
[ -n "$REPO_URL" ] && need="$need git npm"
missing=()
for cmd in $need; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if ((${#missing[@]})); then
  die "missing: ${missing[*]} — on Ubuntu/Debian: apt install -y curl docker.io nodejs (node >= 20 required)"
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 20 ] || die "node >= 20 required (found $(node --version))"
docker info >/dev/null 2>&1 || die "docker daemon not running (systemctl start docker)"
ss -tln | grep -q ":${PG_PORT} " && ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER" \
  && die "port ${PG_PORT} already in use — set PG_PORT=<free port>"
command -v sshd >/dev/null 2>&1 && SSHD_OK=1 || SSHD_OK=0

# ---- optional ClamAV signature engine ----------------------------------------
# Malware scans always run the heuristics legs; a local ClamAV turns the pass
# into a real signature sweep of the staging dirs. Recommended — offer to
# install it here. Non-interactive installs take INSTALL_CLAMAV=1|0 and
# default to skipping; the dashboard honestly reports "heuristics only".
CLAMAV_STATUS="heuristics only (no ClamAV)"
if command -v clamdscan >/dev/null 2>&1 || command -v clamscan >/dev/null 2>&1; then
  CLAMAV_STATUS="ClamAV already installed — signature scanning enabled"
elif [ "${INSTALL_CLAMAV:-}" = "0" ]; then
  :
else
  install_clamav="${INSTALL_CLAMAV:-}"
  if [ -z "$install_clamav" ] && [ -e /dev/tty ]; then
    printf '\033[1m==> Install ClamAV? It enables malware signature scanning (recommended). [Y/n] \033[0m'
    answer=""
    read -r answer < /dev/tty || answer="y"
    case "$answer" in n|N|no|NO) install_clamav=0 ;; *) install_clamav=1 ;; esac
  fi
  if [ "$install_clamav" = "1" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      say "installing ClamAV (clamav-daemon — signature updates via freshclam)"
      DEBIAN_FRONTEND=noninteractive apt-get update -qq \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav-daemon \
        || echo "WARN: clamav install failed — malware scans stay heuristics-only"
    elif command -v dnf >/dev/null 2>&1; then
      say "installing ClamAV (dnf)"
      dnf install -y clamav clamav-update clamd \
        || echo "WARN: clamav install failed — malware scans stay heuristics-only"
      # freshclam config ships with a FRESHCLAM_DELAY/"Example" guard on Fedora
      sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
      systemctl enable --now clamav-freshclam >/dev/null 2>&1 || true
    else
      echo "WARN: no apt/dnf — install clamav manually for signature scanning"
    fi
    if command -v clamdscan >/dev/null 2>&1 || command -v clamscan >/dev/null 2>&1; then
      # clamd answers scans as soon as freshclam's first DB lands; until
      # then runs degrade to heuristics honestly.
      systemctl enable --now clamav-daemon >/dev/null 2>&1 \
        || systemctl enable --now clamd >/dev/null 2>&1 || true
      CLAMAV_STATUS="ClamAV installed — signature scanning enabled (first DB download may take a minute)"
    fi
  fi
fi

# ---- service user -----------------------------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  say "creating service user ${SERVICE_USER}"
  useradd --system --create-home --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ---- app payload ------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
if [ -n "$REPO_URL" ]; then
  # Maintainer source-build path — clones whatever repo REPO_URL points at
  # (normally the PRIVATE source repo; the public repo ships no server
  # source). Self-hosted installs should leave REPO_URL unset.
  if [ -d "$APP_DIR/.git" ]; then
    say "updating existing checkout in $APP_DIR"
    sudo -u "$SERVICE_USER" git -C "$APP_DIR" fetch --quiet origin "$REPO_REF"
    sudo -u "$SERVICE_USER" git -C "$APP_DIR" reset --hard --quiet "origin/$REPO_REF"
  else
    say "cloning $REPO_URL ($REPO_REF) → $APP_DIR"
    git clone --quiet --depth 1 --branch "$REPO_REF" "$REPO_URL" "$APP_DIR"
  fi
else
  # Default path: published release tarball from the public releases repo.
  RELEASES_API="https://api.github.com/repos/${RELEASES_REPO}/releases"
  RELEASES_URL="https://github.com/${RELEASES_REPO}/releases"
  if [ -n "${SERVER_VERSION:-}" ]; then
    # Accept "1.2.3", "v1.2.3" or a full tag "server-v1.2.3"
    VERSION="${SERVER_VERSION#server-v}"; VERSION="${VERSION#v}"
    RELEASE_TAG="server-v${VERSION}"
  else
    say "resolving latest server release from ${RELEASES_URL}"
    # Unauthenticated API — releases are listed newest-first; take the first
    # server-v* tag. sed-only parse, no jq assumption on a fresh host. (No
    # `| head -1` here: under pipefail, head exiting early could SIGPIPE sed
    # and masquerade as a network failure.)
    RELEASE_TAGS="$(curl -fsSL "$RELEASES_API" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(server-v[^"]*\)".*/\1/p')" \
      || die "cannot reach api.github.com — set SERVER_VERSION=<ver> or check network"
    RELEASE_TAG="${RELEASE_TAGS%%$'\n'*}"
    [ -n "$RELEASE_TAG" ] \
      || die "No self-hosted release found — check ${RELEASES_URL}"
    VERSION="${RELEASE_TAG#server-v}"
  fi
  ASSET="rootwatch-server-${VERSION}-linux-x64.tar.gz"
  DL="${RELEASES_URL}/download/${RELEASE_TAG}"
  say "installing RootWatch server ${RELEASE_TAG} → ${APP_DIR}"

  TMP="$(mktemp -d)"
  curl -fsSL --retry 3 -o "$TMP/$ASSET" "$DL/$ASSET" \
    || die "download failed: ${DL}/${ASSET}"
  curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$DL/SHA256SUMS" \
    || die "release ${RELEASE_TAG} has no SHA256SUMS — refusing to install unverified bits"
  # SHA256SUMS covers every asset on the release — keep only our tarball's
  # line (exact last-field match; a leading '*' binary marker is tolerated)
  # so `sha256sum -c` doesn't fail on assets we didn't download.
  awk -v a="$ASSET" '{n=$NF; sub(/^\*/,"",n); if(n==a) print}' "$TMP/SHA256SUMS" \
    > "$TMP/checksum.txt"
  [ -s "$TMP/checksum.txt" ] \
    || die "SHA256SUMS has no entry for ${ASSET} — refusing to install"
  (cd "$TMP" && sha256sum -c checksum.txt) \
    || die "sha256 mismatch for ${ASSET} — download corrupted or tampered, aborting"

  mkdir -p "$TMP/x"; tar -xzf "$TMP/$ASSET" -C "$TMP/x"
  # Archives may or may not wrap everything in one top-level dir — normalize
  # so $APP_DIR itself is the app root (scripts/start.sh at its top).
  app_root="$TMP/x"
  if [ ! -f "$app_root/scripts/start.sh" ]; then
    app_root="$(find "$TMP/x" -mindepth 1 -maxdepth 1 -type d | head -1)"
  fi
  for p in scripts/start.sh dist/index.js dist/migrate.js; do
    [ -f "$app_root/$p" ] \
      || die "tarball lacks ${p} — not a RootWatch server bundle"
  done
  [ -d "$APP_DIR/.git" ] && say "replacing existing source checkout with release bundle"
  rm -rf "$APP_DIR"; mv "$app_root" "$APP_DIR"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

# ---- secrets / env ----------------------------------------------------------
DB_PASSWORD=""
if [ -f "$ENV_FILE" ]; then
  say "preserving existing $ENV_FILE"
  # shellcheck disable=SC1090
  DB_PASSWORD="$(grep '^DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  SESSION_SECRET="$(grep '^SESSION_SECRET=' "$ENV_FILE" | cut -d= -f2-)"
  ADMIN_PASSWORD="$(grep '^ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
fi
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -hex 16)}"
SESSION_SECRET="${SESSION_SECRET:-$(openssl rand -hex 32)}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(openssl rand -hex 8)}"
cat > "$ENV_FILE" <<EOF
DATABASE_URL=postgresql://rootwatch:${DB_PASSWORD}@127.0.0.1:${PG_PORT}/rootwatch
DB_PASSWORD=${DB_PASSWORD}
SESSION_SECRET=${SESSION_SECRET}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
NODE_ENV=production
HOST=${BIND_ADDR}
PORT=${APP_PORT}
DEPLOYMENT_MODE=local
EOF
# Fleet reporting: this install becomes a watched device on a control-plane
# dashboard when both are set (CONTROL_PLANE_TOKEN = org rw_… token, write scope)
if [ -n "${CONTROL_PLANE_URL:-}" ] && [ -n "${CONTROL_PLANE_TOKEN:-}" ]; then
  say "enabling fleet reporting to ${CONTROL_PLANE_URL}"
  {
    echo "CONTROL_PLANE_URL=${CONTROL_PLANE_URL}"
    echo "CONTROL_PLANE_TOKEN=${CONTROL_PLANE_TOKEN}"
  } >> "$ENV_FILE"
fi
chown "root:$SERVICE_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"

# ---- postgres container -----------------------------------------------------
if ! docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  say "starting postgres container ${PG_CONTAINER} (127.0.0.1:${PG_PORT})"
  docker run -d --name "$PG_CONTAINER" --restart unless-stopped \
    -e POSTGRES_USER=rootwatch -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB=rootwatch \
    -p "127.0.0.1:${PG_PORT}:5432" -v rootwatch-pgdata:/var/lib/postgresql/data \
    postgres:16-alpine >/dev/null
else
  docker start "$PG_CONTAINER" >/dev/null
fi
say "waiting for postgres"
for _ in $(seq 30); do
  docker exec "$PG_CONTAINER" pg_isready -U rootwatch -d rootwatch >/dev/null 2>&1 && break
  sleep 1
done

# ---- build (source path only) ------------------------------------------------
NODE_BIN_DIR="$(dirname "$(command -v node)")"
if [ -n "$REPO_URL" ]; then
  say "npm ci + build + migrate (this takes a minute)"
  # Build WITHOUT the env file — NODE_ENV=production would make npm ci skip
  # devDependencies (vite, typescript) and the build would fail.
  sudo -u "$SERVICE_USER" env "PATH=${NODE_BIN_DIR}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "HOME=$SERVICE_HOME" bash -c "cd '$APP_DIR' && npm ci --include=dev --no-audit --no-fund && npm run build"
  sudo -u "$SERVICE_USER" env "PATH=${NODE_BIN_DIR}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "HOME=$SERVICE_HOME" bash -c "set -a; . '$ENV_FILE'; set +a; cd '$APP_DIR' && node dist/migrate.js"
else
  say "prebuilt bundle — migrations run on first service start (scripts/start.sh)"
fi

# ---- remediation helpers + sudoers ------------------------------------------
if [ "${SKIP_HELPERS:-0}" != "1" ]; then
  [ -d "$APP_DIR/packaging" ] \
    || die "$APP_DIR/packaging missing — bundle incomplete (or set SKIP_HELPERS=1)"
  say "installing remediation helpers + sudoers allowlist"
  for f in rootwatch-remediate write-sshd-dropin remove-sshd-dropin \
           write-docker-no-tcp-dropin fix-docker-daemon-json remove-docker-dropin; do
    install -D -o root -g root -m 0750 "$APP_DIR/packaging/$f" "${INSTALL_DIR}/libexec/$f"
  done
  install -D -o root -g root -m 0440 "$APP_DIR/packaging/sudoers.d/rootwatch" /etc/sudoers.d/rootwatch
  if [ "$SERVICE_USER" != "rootwatch" ]; then
    sed -i "s/^rootwatch /${SERVICE_USER} /" /etc/sudoers.d/rootwatch
  fi
  if ! visudo -cf /etc/sudoers.d/rootwatch >/dev/null; then
    rm -f /etc/sudoers.d/rootwatch
    die "sudoers file failed validation — removed, sudo untouched"
  fi
fi

# ---- systemd ----------------------------------------------------------------
say "installing systemd unit"
cat > /etc/systemd/system/rootwatch.service <<EOF
[Unit]
Description=RootWatch security control panel
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
Environment=PATH=${NODE_BIN_DIR}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/bin/sh scripts/start.sh
Restart=always
RestartSec=5
# NOTE: no NoNewPrivileges — remediation uses `sudo -n` (setuid) deliberately.

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now rootwatch >/dev/null 2>&1

# ---- healthcheck ------------------------------------------------------------
say "waiting for http://${BIND_ADDR}:${APP_PORT}"
ok=""
for _ in $(seq 30); do
  curl -fsS -o /dev/null "http://${BIND_ADDR}:${APP_PORT}/" 2>/dev/null \
    || curl -fsS -o /dev/null "http://127.0.0.1:${APP_PORT}/" 2>/dev/null \
    || { sleep 1; continue; }
  ok=1; break
done
if [ -z "$ok" ]; then
  journalctl -u rootwatch -n 30 --no-pager >&2 || true
  die "service did not come up — see logs above"
fi

# ---- optional tailscale serve (tailnet-only HTTPS front door) ---------------
SERVE_URL=""
if [ "${TAILSCALE_SERVE:-0}" = "1" ]; then
  if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
    tailscale serve --bg --set-path / "http://127.0.0.1:${APP_PORT}" >/dev/null
    SERVE_URL="https://$(tailscale status --json | sed -n 's/.*"DNSName": *"\([^"]*\)\..*"/\1/p' | head -1)"
    say "tailscale serve → ${SERVE_URL}"
  else
    echo "WARN: TAILSCALE_SERVE=1 but tailscale isn't up — run: sudo tailscale up && sudo tailscale serve --bg --set-path / http://127.0.0.1:${APP_PORT}"
  fi
fi

cat <<EOF

$(printf '\033[32m')RootWatch is up: http://${BIND_ADDR}:${APP_PORT}$(printf '\033[0m')
  admin / ${ADMIN_PASSWORD}   (also in ${ENV_FILE} — rotate after first login)
  malware scanning: ${CLAMAV_STATUS}
  logs: journalctl -u rootwatch -f
$( [ "$BIND_ADDR" != "127.0.0.1" ] && echo "  bound to ${BIND_ADDR} — reachable only from that interface" )
$( [ -n "$SERVE_URL" ] && echo "  tailnet HTTPS: ${SERVE_URL}" )
EOF
