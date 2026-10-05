#!/usr/bin/env bash
# RootWatch fleet agent installer — makes this host a "watched device" on a
# RootWatch control plane's dashboard.
#
#   curl -fsSL https://rootwatch.dev/agent/install.sh | sudo bash -s -- <control-url> [rw_ token]
#
# Omit the token to pair interactively: the script prints an enrollment
# code, you approve it at <control-url>/devices/enroll, the agent's token
# is minted and delivered automatically.
#
# or with env:
#   sudo CONTROL_PLANE_URL=... CONTROL_PLANE_TOKEN=... bash install.sh
#   sudo bash install.sh --uninstall
#
# Installs a zero-dependency Node agent that POSTs a posture snapshot to
# <control-url>/api/v1/devices/report every 5 minutes. No database, no
# dashboard, no inbound listeners — just a systemd timer.
set -euo pipefail

AGENT_URL="${AGENT_URL:-https://rootwatch.dev/agent/agent.mjs}"
INSTALL_DIR=/opt/rootwatch-agent
ENV_FILE=/etc/default/rootwatch-agent
UNIT_DIR=/etc/systemd/system

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now rootwatch-agent.timer 2>/dev/null || true
  rm -f "$UNIT_DIR"/rootwatch-agent.{service,timer} "$ENV_FILE"
  rm -rf "$INSTALL_DIR"
  systemctl daemon-reload
  echo "rootwatch-agent removed"
  exit 0
fi

CONTROL_PLANE_URL="${1:-${CONTROL_PLANE_URL:-}}"
CONTROL_PLANE_TOKEN="${2:-${CONTROL_PLANE_TOKEN:-}}"

if [ -z "$CONTROL_PLANE_URL" ]; then
  echo "usage: $0 <control-plane-url> [rw_ write-scope token]" >&2
  echo "  omit the token to pair via a code you'll approve in the web UI" >&2
  exit 2
fi

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl required: apt install curl" >&2; exit 1; }

if ! command -v node >/dev/null; then
  echo "node not found — installing nodejs"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y nodejs
  elif command -v dnf >/dev/null; then
    dnf install -y nodejs
  else
    echo "no supported package manager — install Node 18+ and re-run" >&2; exit 1
  fi
fi
NODE_MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])')"
[ "$NODE_MAJOR" -ge 18 ] || { echo "Node $NODE_MAJOR too old — agent needs 18+ (fetch API)" >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
echo "fetching agent from $AGENT_URL"
curl -fsSL "$AGENT_URL" -o "$INSTALL_DIR/agent.mjs"
chmod 755 "$INSTALL_DIR/agent.mjs"

if [ -n "$CONTROL_PLANE_TOKEN" ] && [[ "$CONTROL_PLANE_TOKEN" == *:* ]]; then
  # Bootstrap credential (RW-XXXX-XXXX:secret) minted by "Add device" —
  # claims its pre-approved token once, no UI round-trip.
  BOOT_CODE="${CONTROL_PLANE_TOKEN%%:*}"
  BOOT_SECRET="${CONTROL_PLANE_TOKEN#*:}"
  RW_ENV_FILE="$ENV_FILE" node "$INSTALL_DIR/agent.mjs" claim "$CONTROL_PLANE_URL" "$BOOT_CODE" "$BOOT_SECRET"
elif [ -n "$CONTROL_PLANE_TOKEN" ]; then
  cat > "$ENV_FILE" <<EOF
CONTROL_PLANE_URL=${CONTROL_PLANE_URL}
CONTROL_PLANE_TOKEN=${CONTROL_PLANE_TOKEN}
EOF
  chmod 600 "$ENV_FILE"
else
  # Code-based pairing: the agent asks the control plane for an enrollment
  # code, you approve it in the web UI, the minted token lands in ENV_FILE.
  RW_ENV_FILE="$ENV_FILE" node "$INSTALL_DIR/agent.mjs" enroll "$CONTROL_PLANE_URL"
fi

cat > "$UNIT_DIR/rootwatch-agent.service" <<EOF
[Unit]
Description=RootWatch fleet agent (host posture reporter)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/env node $INSTALL_DIR/agent.mjs
EOF

cat > "$UNIT_DIR/rootwatch-agent.timer" <<EOF
[Unit]
Description=RootWatch fleet agent reporting interval

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now rootwatch-agent.timer

echo "running first report..."
systemctl start rootwatch-agent.service
sleep 2
if systemctl is-failed --quiet rootwatch-agent.service; then
  echo "first report failed — check: journalctl -u rootwatch-agent.service -n 20" >&2
  journalctl -u rootwatch-agent.service -n 10 --no-pager >&2 || true
  exit 1
fi
echo "done — this host now reports to ${CONTROL_PLANE_URL} every 5min"
echo "check the Watched Devices card on the control-plane dashboard"
