/**
 * stopListener refusal-guard tests. Every path asserted here returns
 * {status:'refused'} BEFORE any signal is sent — no test in this file ever
 * reaches process.kill.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const net = require("node:net");
const { once } = require("node:events");
const { execFileSync, spawnSync } = require("node:child_process");
const path = require("node:path");

const { stopListener } = require("../collector.cjs");

const COLLECTOR = path.resolve(__dirname, "..", "collector.cjs");

function ssAvailable() {
  const r = spawnSync("ss", ["-H", "-tulpn"], { timeout: 10_000 });
  return r.status === 0;
}

test("refuses init/kernel/invalid pids before any lookup", async () => {
  for (const pid of [0, 1, -5, 1.5, NaN, "1234", null, undefined]) {
    const r = await stopListener(pid);
    assert.equal(r.status, "refused", `pid=${pid} should be refused`);
    assert.match(r.message, /refusing to signal pid/i);
  }
});

test(
  "refuses own pid while it owns a live listener",
  { skip: process.platform !== "linux" || !ssAvailable() },
  async () => {
    // Own a real socket so the snapshot ties our pid to a listener.
    const server = net.createServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const r = await stopListener(process.pid);
      assert.equal(r.status, "refused");
      assert.match(r.message, /this process or an ancestor/i);
    } finally {
      server.close();
    }
  },
);

test(
  "refuses to signal an ancestor of the calling process",
  { skip: process.platform !== "linux" || !ssAvailable() },
  async () => {
    // The ancestor guard is relative to the caller's pid, so exercise it
    // from a child: this process owns a listener; the child tries to stop
    // its parent (us) and must be refused before signalling.
    const server = net.createServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const script =
        `require(${JSON.stringify(COLLECTOR)})` +
        ".stopListener(process.ppid)" +
        ".then((r) => { console.log(JSON.stringify(r)); })" +
        ".catch((e) => { console.log(JSON.stringify({ status: 'error', message: String(e) })); });";
      const out = execFileSync(process.execPath, ["-e", script], {
        timeout: 60_000,
        encoding: "utf8",
      });
      const r = JSON.parse(out.trim().split("\n").pop());
      assert.equal(r.status, "refused");
      assert.match(r.message, /this process or an ancestor/i);
    } finally {
      server.close();
    }
  },
);

test(
  "refuses a live pid that owns no listener",
  { skip: process.platform !== "linux" || !ssAvailable() },
  async () => {
    // A running process with no LISTEN sockets — must be refused by the
    // "owns no listener in the current snapshot" guard, never signalled.
    const { spawn } = require("node:child_process");
    const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 60_000)"]);
    try {
      // Give the child a moment so it's definitely alive (pid resolvable).
      await new Promise((r) => setTimeout(r, 300));
      const r = await stopListener(child.pid);
      assert.equal(r.status, "refused");
      assert.match(r.message, /owns no listener|ancestor/i);
    } finally {
      child.kill("SIGKILL");
    }
  },
);
