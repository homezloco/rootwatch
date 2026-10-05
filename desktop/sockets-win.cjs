/**
 * Windows socket inventory — `netstat -ano` lists TCP rows with a State
 * column (only LISTENING rows count as listeners) and UDP rows with no
 * state (all count — UDP is stateless). The last column is the owning pid.
 * Returns the normalized shape [{protocol:'tcp'|'udp', address, port, pid}];
 * netstat reports no process name, so `process` stays null.
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileP = promisify(execFile);

async function listSockets() {
  const { stdout } = await execFileP("netstat", ["-ano"], {
    timeout: 15_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const rows = [];
  for (const line of stdout.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4) continue;
    const proto = f[0].toLowerCase();
    if (proto !== "tcp" && proto !== "udp") continue;

    // TCP: proto local foreign state pid — keep LISTENING only.
    // UDP: proto local foreign pid — keep all rows.
    if (proto === "tcp" && f[f.length - 2].toUpperCase() !== "LISTENING") continue;

    const addrPort = splitAddrPort(f[1]);
    if (!addrPort) continue;
    const pid = Number(f[f.length - 1]);
    rows.push({
      protocol: proto,
      address: addrPort.address,
      port: addrPort.port,
      pid: Number.isInteger(pid) && pid > 0 ? pid : null,
      process: null,
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
  address = address.split("%")[0]; // drop zone index
  return { address, port };
}

// Established TCP connections — `netstat -ano` ESTABLISHED rows carry the
// owning pid in the last column for every socket, so egress attribution
// works across users. Same normalized conn shape as the Linux source.
async function listEstablished() {
  const { stdout } = await execFileP("netstat", ["-ano"], {
    timeout: 15_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  const rows = [];
  for (const line of stdout.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5) continue;
    if (f[0].toLowerCase() !== "tcp") continue;
    if (f[f.length - 2].toUpperCase() !== "ESTABLISHED") continue;
    const local = splitAddrPort(f[1]);
    const peer = splitAddrPort(f[2]);
    if (!local || !peer) continue;
    const pid = Number(f[f.length - 1]);
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
