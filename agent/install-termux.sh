#!/usr/bin/env bash
# RootWatch agent installer for Android via Termux — no root, no systemd.
# Scheduling is a cron job (cronie via termux-services); the agent self-
# uninstalls (crontab entry + files) if its credential is revoked.
#
#   curl -fsSL https://rootwatch.dev/agent/install-termux.sh | bash -s -- <control-url> [credential]
#
# credential: 'RW-XXXX-XXXX:secret' bootstrap pair, or an 'rw_…' write-scope
# token, or omit for interactive code pairing.
#
# Requires Termux from F-Droid (the Play Store build is unmaintained).
set -euo pipefail

AGENT_URL="${AGENT_URL:-https://rootwatch.dev/agent/agent.mjs}"
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
INSTALL_DIR="$PREFIX/opt/rootwatch-agent"
ENV_FILE="$PREFIX/etc/rootwatch-agent"
RUNNER="$INSTALL_DIR/run.sh"
CRON_TAG="rootwatch-agent"

CONTROL_PLANE_URL="${1:-${CONTROL_PLANE_URL:-}}"
CONTROL_PLANE_TOKEN="${2:-${CONTROL_PLANE_TOKEN:-}}"

[ -d "$PREFIX/bin" ] || { echo "Termux not detected — use install.sh on Linux" >&2; exit 1; }
if [ -z "$CONTROL_PLANE_URL" ]; then
  echo "usage: $0 <control-plane-url> [RW-…:secret bootstrap | rw_ token]" >&2
  echo "  omit the credential to pair via a code you'll approve in the web UI" >&2
  exit 2
fi

# Refresh repos first — a fresh Termux has no package lists, and stale
# lists are the usual cause of dpkg error code 1 below.
echo "==> updating package lists"
if ! pkg update -y; then
  echo "pkg update failed — if repo URLs 404, this is the unmaintained Play Store" >&2
  echo "build; reinstall Termux from F-Droid. Otherwise run: dpkg --configure -a" >&2
  exit 1
fi

echo "==> installing nodejs + cronie + termux-services"
if ! pkg install -y nodejs cronie termux-services; then
  echo "package install failed — run: dpkg --configure -a && pkg upgrade -y, then retry" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR" "$PREFIX/etc"
echo "==> fetching agent from $AGENT_URL"
curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/agent.mjs"
chmod 755 "$INSTALL_DIR/agent.mjs"

# Runner keeps cron env sane and sources credentials — crontab calls this.
cat > "$RUNNER" <<EOF
#!/usr/bin/env bash
set -a; . "$ENV_FILE"; set +a
exec "$PREFIX/bin/node" "$INSTALL_DIR/agent.mjs"
EOF
chmod 755 "$RUNNER"

# Credential materialization — same three flows as the Linux installer.
if [ -n "$CONTROL_PLANE_TOKEN" ] && [[ "$CONTROL_PLANE_TOKEN" == *:* ]]; then
  BOOT_CODE="${CONTROL_PLANE_TOKEN%%:*}"
  BOOT_SECRET="${CONTROL_PLANE_TOKEN#*:}"
  RW_ENV_FILE="$ENV_FILE" node "$INSTALL_DIR/agent.mjs" claim "$CONTROL_PLANE_URL" "$BOOT_CODE" "$BOOT_SECRET"
elif [ -n "$CONTROL_PLANE_TOKEN" ]; then
  printf 'CONTROL_PLANE_URL=%s\nCONTROL_PLANE_TOKEN=%s\n' "$CONTROL_PLANE_URL" "$CONTROL_PLANE_TOKEN" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
else
  RW_ENV_FILE="$ENV_FILE" node "$INSTALL_DIR/agent.mjs" enroll "$CONTROL_PLANE_URL"
fi

# Scheduling: crond via termux-services. On a fresh termux-services install
# the service dir only binds after a session restart — say so honestly.
if ! sv-enable crond 2>/dev/null; then
  echo "note: restart Termux, then run: sv-enable crond (termux-services needs one session restart)"
fi
( crontab -l 2>/dev/null | grep -v "$CRON_TAG" || true; echo "*/5 * * * * $RUNNER # $CRON_TAG" ) | crontab -

echo "==> running first report"
"$RUNNER"

cat <<EOF
done — this device reports to ${CONTROL_PLANE_URL} every 5min via crond.
  check the Watched Devices card on the control-plane dashboard.

  battery: Android will suspend Termux unless battery optimization is
  disabled for the app (Settings → Apps → Termux → Battery → unrestricted),
  and reports only flow while Termux services are running.

  uninstall: crontab -l | grep -v $CRON_TAG | crontab - && rm -rf $INSTALL_DIR $ENV_FILE
EOF
