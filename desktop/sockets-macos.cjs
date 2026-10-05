/**
 * macOS socket inventory — `lsof -nP -iTCP -sTCP:LISTEN -iUDP` lists TCP
 * LISTEN sockets plus every UDP socket (UDP is stateless, so lsof prints
 * no (LISTEN) state for those rows). Returns the normalized shape
 * [{protocol:'tcp'|'udp', address, port, pid}] — `process` carries the
 * COMMAND column as an identification hint.
 *
 * lsof only reports owning pids for sockets the calling user can see;
 * foreign-uid rows still appear with their pid, so identification falls
 * through the honest-confidence waterfall as usual.
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileP = promisify(execFile);

async function listSockets() {
  const { stdout } = await execFileP("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP"], {
    timeout: 15_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const rows = [];
  for (const line of stdout.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 9 || f[0] === "COMMAND") continue;

    // Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME…
    // The NODE column is literally "TCP" or "UDP"; NAME follows it and may
    // carry a trailing "(LISTEN)" state annotation.
    const nodeIdx = f.findIndex((t, i) => i >= 3 && (t === "TCP" || t === "UDP"));
    if (nodeIdx < 0 || nodeIdx === f.length - 1) continue;

    const name = f
      .slice(nodeIdx + 1)
      .join(" ")
      .replace(/\s*\([^)]*\)\s*$/, "");
    const addrPort = splitAddrPort(name);
    if (!addrPort) continue;

    const pid = Number(f[1]);
    rows.push({
      protocol: f[nodeIdx].toLowerCase(),
      address: addrPort.address,
      port: addrPort.port,
      pid: Number.isInteger(pid) && pid > 0 ? pid : null,
      process: f[0] ?? null,
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
  address = address.split("%")[0]; // drop zone index (fe80::1%en0)
  return { address, port };
}

// Established TCP connections — `lsof -sTCP:ESTABLISHED` prints NAME as
// `local->peer` and always attributes a pid (lsof shows it even for
// foreign-uid sockets). Same normalized conn shape as the Linux source.
async function listEstablished() {
  const { stdout } = await execFileP("lsof", ["-nP", "-iTCP", "-sTCP:ESTABLISHED"], {
    timeout: 15_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const rows = [];
  for (const line of stdout.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 9 || f[0] === "COMMAND") continue;
    const nodeIdx = f.findIndex((t, i) => i >= 3 && t === "TCP");
    if (nodeIdx < 0 || nodeIdx === f.length - 1) continue;
    const name = f
      .slice(nodeIdx + 1)
      .join(" ")
      .replace(/\s*\([^)]*\)\s*$/, "");
    const arrow = name.indexOf("->");
    if (arrow < 0) continue;
    const local = splitAddrPort(name.slice(0, arrow));
    const peer = splitAddrPort(name.slice(arrow + 2));
    if (!local || !peer) continue;
    const pid = Number(f[1]);
    rows.push({
      localAddress: local.address,
      localPort: local.port,
      peerAddress: peer.address,
      peerPort: peer.port,
      pid: Number.isInteger(pid) && pid > 0 ? pid : null,
    });
  }
  return rows;
}

module.exports = { listSockets, listEstablished };
