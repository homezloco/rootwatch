/**
 * collector.cjs unit tests — fixture `ss` output through the pure parser,
 * and fixture socket/process tables through collectListeners' grouping +
 * identification waterfall. Nothing here opens a socket or signals a pid;
 * collectListeners is driven via its `fixtures` test seam.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  parseSsRows,
  classifyBindAddress,
  collectListeners,
  unitFromCgroup,
} = require("../collector.cjs");

// Fixture shaped like real `ss -H -tulpn` output (proto state recv send
// local peer [process]). Non-LISTEN rows, malformed lines, and sockets
// without a users:(...) tuple are included on purpose.
const SS_FIXTURE = [
  'tcp   LISTEN 0      511        127.0.0.1:45173        0.0.0.0:*    users:(("node",pid=4194305,fd=29))',
  'tcp   LISTEN 0      511        [::1]:45174            [::]:*         users:(("node",pid=4194305,fd=30))',
  'tcp   LISTEN 0      128        0.0.0.0:5432           0.0.0.0:*    users:(("postgres",pid=4194306,fd=5))',
  'udp   UNCONN 0      0          127.0.0.53%lo:53       0.0.0.0:*    users:(("systemd-resolve",pid=4194307,fd=12))',
  'tcp   LISTEN 0      100        192.168.1.10:8080      0.0.0.0:*    users:(("docker-proxy",pid=4194308,fd=6))',
  "tcp   LISTEN 0      128        100.64.1.5:22          0.0.0.0:*", // no users tuple — foreign uid
  'tcp   ESTAB  0      0          10.0.0.1:5555          10.0.0.2:443 users:(("curl",pid=4194309,fd=3))',
  "udp   UNCONN 0      0          [::]:5353              [::]:*", // unowned wildcard udp
  "this is not an ss row",
  "",
].join("\n");

test("parseSsRows normalizes ss output into socket rows", () => {
  const rows = parseSsRows(SS_FIXTURE);

  // 7 socket lines parsed; ESTAB + garbage + blank dropped.
  assert.equal(rows.length, 7);

  const byPort = new Map(rows.map((r) => [r.port, r]));
  assert.deepEqual(byPort.get(45173), {
    protocol: "tcp",
    address: "127.0.0.1",
    port: 45173,
    pid: 4194305,
    process: "node",
  });

  // IPv6 brackets stripped, zone index dropped.
  assert.equal(byPort.get(45174).address, "::1");
  assert.equal(byPort.get(53).address, "127.0.0.53");

  // No users:(...) tuple → honest null pid, not a guess.
  assert.equal(byPort.get(22).pid, null);
  assert.equal(byPort.get(5353).pid, null);
});

test("parseSsRows tolerates empty/garbage input", () => {
  assert.deepEqual(parseSsRows(""), []);
  assert.deepEqual(parseSsRows(null), []);
  assert.deepEqual(parseSsRows("tcp\nudp   \n"), []);
});

test("classifyBindAddress maps binds to honest scopes", () => {
  assert.equal(classifyBindAddress("127.0.0.1"), "loopback");
  assert.equal(classifyBindAddress("::1"), "loopback");
  assert.equal(classifyBindAddress("localhost"), "loopback");
  assert.equal(classifyBindAddress("0.0.0.0"), "public");
  assert.equal(classifyBindAddress("::"), "public");
  assert.equal(classifyBindAddress("*"), "public");
  assert.equal(classifyBindAddress("8.8.8.8"), "public");
  assert.equal(classifyBindAddress("192.168.1.10"), "private");
  assert.equal(classifyBindAddress("10.0.0.4"), "private");
  assert.equal(classifyBindAddress("172.16.0.9"), "private");
  assert.equal(classifyBindAddress("169.254.1.1"), "private");
  assert.equal(classifyBindAddress("100.64.1.5"), "tailscale"); // CGNAT
  assert.equal(classifyBindAddress("fd00::1"), "tailscale"); // ULA
  assert.equal(classifyBindAddress("fe80::1"), "private"); // link-local
  // Brackets + zone index stripped before classification.
  assert.equal(classifyBindAddress("[fe80::1]"), "private");
  assert.equal(classifyBindAddress("127.0.0.54%lo"), "loopback");
});

// si.processes()-shaped fixture rows for collectListeners.
function procRow(over) {
  return {
    pid: over.pid,
    parentPid: over.parentPid ?? 1,
    command: over.command,
    params: over.params ?? "",
    path: over.path ?? null,
    uid: over.uid ?? process.getuid?.() ?? 0,
    user: over.user ?? "test",
    started: new Date(Date.now() - 60_000).toISOString(),
    cpu: 0,
    mem: 0,
    memRss: 0,
  };
}

test("collectListeners groups sockets by pid and classifies scopes", async () => {
  const sockets = parseSsRows(SS_FIXTURE);
  const processes = [
    procRow({ pid: 4194305, command: "node", params: "vite --host 127.0.0.1" }),
    procRow({ pid: 4194306, command: "postgres", uid: 999_999 }),
    procRow({ pid: 4194308, command: "docker-proxy" }),
  ];

  const records = await collectListeners({ fixtures: { sockets, processes } });
  const byPid = new Map(records.filter((r) => r.pid != null).map((r) => [r.pid, r]));

  // Both 4194305 sockets collapse into one record with two ports.
  const vite = byPid.get(4194305);
  assert.ok(vite, "expected a record for pid 4194305");
  assert.equal(vite.ports.length, 2);
  assert.deepEqual(vite.ports.map((p) => p.scope).sort(), ["loopback", "loopback"]);

  // Scope classification lands on each port entry.
  assert.equal(byPid.get(4194306).ports[0].scope, "public"); // 0.0.0.0
  assert.equal(byPid.get(4194308).ports[0].scope, "private"); // 192.168.x
  assert.equal(byPid.get(4194307).ports[0].scope, "loopback"); // 127.0.0.53

  // Unowned sockets stand alone under unowned:* keys.
  const unowned = records.filter((r) => r.pid == null);
  assert.equal(unowned.length, 2);
  assert.ok(unowned.every((r) => r.key.startsWith("unowned:")));
  const tailnet = unowned.find((r) => r.ports[0].address === "100.64.1.5");
  assert.equal(tailnet.ports[0].scope, "tailscale");
});

test("identifiedBy waterfall reports the layer that resolved, never more", async () => {
  const sockets = parseSsRows(SS_FIXTURE);
  const processes = [
    procRow({ pid: 4194305, command: "node", params: "vite --host 127.0.0.1" }),
    procRow({ pid: 4194306, command: "postgres", uid: 999_999 }),
    procRow({ pid: 4194308, command: "docker-proxy" }),
  ];

  const records = await collectListeners({ fixtures: { sockets, processes } });
  const byPid = new Map(records.filter((r) => r.pid != null).map((r) => [r.pid, r]));

  // cmdline match on a dev-server pattern → identifiedBy 'cmdline'.
  assert.equal(byPid.get(4194305).identifiedBy, "cmdline");
  assert.equal(byPid.get(4194305).class, "dev-server");
  assert.equal(byPid.get(4194305).name, "vite");

  // container-runtime process name → 'container', not 'cmdline'.
  assert.equal(byPid.get(4194308).identifiedBy, "container");
  assert.equal(byPid.get(4194308).class, "container");

  // Named process, no other signal → 'cmdline' fallback on the pname.
  assert.equal(byPid.get(4194306).identifiedBy, "cmdline");
  assert.equal(byPid.get(4194306).name, "postgres");

  // Unowned sockets: port-table is an admitted guess, or honest unknown.
  const tailnet = records.find((r) => r.ports[0]?.address === "100.64.1.5");
  assert.equal(tailnet.identifiedBy, "port-table");
  assert.match(tailnet.name, /\(by port\)$/);
  const mdns = records.find((r) => r.ports[0]?.port === 5353);
  assert.equal(mdns.identifiedBy, "port-table"); // 5353 is in the port table
});

test("unknown port + no identity stays honestly unknown", async () => {
  const sockets = parseSsRows("tcp   LISTEN 0      128        0.0.0.0:43210          0.0.0.0:*");
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [] } });
  assert.equal(rec.identifiedBy, "unknown");
  assert.equal(rec.name, null);
  // Public bind with no confident identification → high risk.
  assert.equal(rec.risk, "high");
});

test("sensitive port bound publicly scores critical", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        0.0.0.0:5432           0.0.0.0:*    users:(("postgres",pid=4194306,fd=5))',
  );
  const processes = [procRow({ pid: 4194306, command: "postgres" })];
  const [rec] = await collectListeners({ fixtures: { sockets, processes } });
  assert.equal(rec.risk, "critical");
  assert.ok(rec.riskReasons.some((r) => /public/i.test(r)));
});

test("own pid is marked this-app and unstoppable", async () => {
  const sockets = [
    { protocol: "tcp", address: "127.0.0.1", port: 45199, pid: process.pid, process: "node" },
  ];
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [] } });
  assert.equal(rec.class, "this-app");
  assert.equal(rec.stoppable, "no");
  assert.match(rec.stopReason, /ancestor|this process/i);
});

test("foreign-uid listener is stoppable only with elevation", async () => {
  const foreignUid = (process.getuid?.() ?? 0) === 0 ? 999_999 : 0;
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        127.0.0.1:43211        0.0.0.0:*    users:(("redis-server",pid=4194310,fd=7))',
  );
  const processes = [procRow({ pid: 4194310, command: "redis-server", uid: foreignUid })];
  const [rec] = await collectListeners({ fixtures: { sockets, processes } });
  assert.equal(rec.stoppable, "elevated");
  assert.ok(rec.suggestedFix, "expected a manual stop suggestion");
});

test("pid-less socket is never stoppable", async () => {
  const sockets = parseSsRows("tcp   LISTEN 0      128        127.0.0.1:43212        0.0.0.0:*");
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [] } });
  assert.equal(rec.stoppable, "no");
  assert.match(rec.stopReason, /no owning pid/i);
});

// ---------------------------------------------------------------------------
// Live-usage evidence — conns fixture rows carry the normalized shape
// {localAddress, localPort, peerAddress, peerPort, pid}.
// ---------------------------------------------------------------------------

const conn = (over) => ({
  localAddress: "127.0.0.1",
  localPort: 43220,
  peerAddress: "127.0.0.1",
  peerPort: 55000,
  pid: 999,
  ...over,
});

test("activity counts inbound conns matched to the bound socket", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        0.0.0.0:43220          0.0.0.0:*    users:(("app",pid=4194320,fd=5))',
  );
  const processes = [procRow({ pid: 4194320, command: "app" })];
  const conns = [
    // Wildcard bind matches any local-address conn on the port.
    conn({ localAddress: "192.168.1.5", peerAddress: "192.168.1.9", pid: 555 }),
    conn({ localAddress: "127.0.0.1", pid: 556 }),
    // Exact duplicate of the first row — deduped, not counted twice.
    conn({ localAddress: "192.168.1.5", peerAddress: "192.168.1.9", pid: 555 }),
    // Different port — belongs to some other socket.
    conn({ localPort: 9999 }),
  ];
  const [rec] = await collectListeners({ fixtures: { sockets, processes, conns } });
  assert.equal(rec.activity.established, 2);
  assert.ok(rec.activity.peers.some((p) => p.address === "192.168.1.9" && p.scope === "private"));
  assert.ok(rec.activity.peers.some((p) => p.address === "127.0.0.1" && p.scope === "loopback"));
});

test("udp-only listeners report activity null — datagrams have no 'in use'", async () => {
  const sockets = [{ protocol: "udp", address: "0.0.0.0", port: 5353, pid: 4194321 }];
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [] } });
  assert.equal(rec.activity, null);
});

test("unreadable conn table is honest null, not zero", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        127.0.0.1:43221        0.0.0.0:*    users:(("app",pid=4194322,fd=5))',
  );
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [], conns: null } });
  assert.equal(rec.activity, null);
  assert.equal(rec.egress, null);
});

test("egress attributes outbound conns to the owning pid only", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        127.0.0.1:43222        0.0.0.0:*    users:(("agent",pid=4194323,fd=5))',
  );
  const processes = [procRow({ pid: 4194323, command: "agent" })];
  const conns = [
    // Outbound from the listener's pid — different local port.
    conn({ localPort: 51001, peerAddress: "8.8.8.8", peerPort: 443, pid: 4194323 }),
    // Inbound TO the listener (local port == bound port) — not egress.
    conn({ localPort: 43222, pid: 4194323 }),
    // Outbound but owned by another pid.
    conn({ localPort: 51002, peerAddress: "1.1.1.1", peerPort: 443, pid: 777 }),
  ];
  const [rec] = await collectListeners({ fixtures: { sockets, processes, conns } });
  assert.equal(rec.egress.count, 1);
  assert.deepEqual(rec.egress.peers, [{ address: "8.8.8.8", port: 443, scope: "public" }]);
});

test("pid-less records report egress null — nothing to attribute to", async () => {
  const sockets = parseSsRows("tcp   LISTEN 0      128        127.0.0.1:43223        0.0.0.0:*");
  const [rec] = await collectListeners({ fixtures: { sockets, processes: [], conns: [] } });
  assert.equal(rec.egress, null);
});

// ---------------------------------------------------------------------------
// Duplicate services — exe basename basis, generic runtimes excluded.
// ---------------------------------------------------------------------------

test("two pids sharing an exe basename are flagged duplicates", async () => {
  const sockets = [
    { protocol: "tcp", address: "127.0.0.1", port: 631, pid: 4194330 },
    { protocol: "tcp", address: "127.0.0.1", port: 8631, pid: 4194331 },
  ];
  const processes = [
    procRow({ pid: 4194330, command: "cupsd", path: "/usr/sbin/cupsd" }),
    procRow({ pid: 4194331, command: "cupsd", path: "/snap/cups/123/sbin/cupsd" }),
  ];
  const records = await collectListeners({ fixtures: { sockets, processes } });
  const cups = records.filter((r) => r.pid === 4194330 || r.pid === 4194331);
  assert.equal(cups.length, 2);
  for (const c of cups) {
    assert.ok(c.duplicate, `pid ${c.pid} should be flagged duplicate`);
    assert.equal(c.duplicate.basis, "exe");
    assert.equal(c.duplicate.key, "cupsd");
    assert.equal(c.duplicate.pids.length, 1);
  }
});

test("generic runtimes never flag — several node processes is not a service dupe", async () => {
  const sockets = [
    { protocol: "tcp", address: "127.0.0.1", port: 43230, pid: 4194340 },
    { protocol: "tcp", address: "127.0.0.1", port: 43231, pid: 4194341 },
  ];
  const processes = [
    procRow({ pid: 4194340, command: "node", params: "server-a.js", path: "/usr/bin/node" }),
    procRow({ pid: 4194341, command: "node", params: "server-b.js", path: "/usr/bin/node" }),
  ];
  const records = await collectListeners({ fixtures: { sockets, processes } });
  assert.ok(records.every((r) => r.duplicate == null));
});

// ---------------------------------------------------------------------------
// Firewall overlay — fixture view injects the backend probe result.
// ---------------------------------------------------------------------------

const fwView = (allows) => ({
  backend: "ufw",
  detail: "ufw active; default incoming deny",
  allows,
});

test("non-loopback bind gets a per-port firewall verdict", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        192.168.1.5:43240      0.0.0.0:*    users:(("app",pid=4194350,fd=5))',
  );
  const processes = [procRow({ pid: 4194350, command: "app" })];
  const [blocked] = await collectListeners({
    fixtures: { sockets, processes, firewall: fwView(() => false) },
  });
  assert.equal(blocked.firewall.allowed, false);
  assert.equal(blocked.firewall.backend, "ufw");
  assert.match(blocked.firewall.detail, /43240\/tcp: blocked/);

  const [admitted] = await collectListeners({
    fixtures: { sockets, processes, firewall: fwView(() => true) },
  });
  assert.equal(admitted.firewall.allowed, true);
});

// ---------------------------------------------------------------------------
// cgroup → systemd unit — mirrors server unitFromCgroup: nested slices and
// user-manager units resolve; user@<uid>.service is a session wrapper, not
// an identity.
// ---------------------------------------------------------------------------

test("unitFromCgroup resolves units in nested slices", () => {
  // Direct system.slice unit (the only case the old parser handled).
  assert.equal(unitFromCgroup("0::/system.slice/sshd.service"), "sshd.service");
  // Nested slice inside system.slice.
  assert.equal(
    unitFromCgroup("0::/system.slice/system-getty.slice/getty@tty1.service"),
    "getty@tty1.service",
  );
  // User unit nested under app.slice inside the session wrapper.
  assert.equal(
    unitFromCgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/mydev.service"),
    "mydev.service",
  );
  // cgroup v1-style multi-line content: unit can come from any line.
  assert.equal(unitFromCgroup("1:name=systemd:/system.slice/cron.service\n0::/"), "cron.service");
});

test("unitFromCgroup skips the user@<uid>.service session wrapper", () => {
  // Only the wrapper present → recorded (it's real) but flagged so the
  // waterfall doesn't claim it as identity.
  assert.equal(
    unitFromCgroup("0::/user.slice/user-1000.slice/user@1000.service/session-3.scope"),
    "user@1000.service",
  );
  // Wrapper + real unit → the real unit wins.
  assert.equal(
    unitFromCgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service"),
    "x.service",
  );
});

test("unitFromCgroup ignores scopes and non-service paths", () => {
  assert.equal(unitFromCgroup("0::/user.slice/user-1000.slice/session-1.scope"), null);
  assert.equal(unitFromCgroup("0::/system.slice/docker-abcdef123456.scope"), null);
  assert.equal(unitFromCgroup("0::/"), null);
  assert.equal(unitFromCgroup(""), null);
  assert.equal(unitFromCgroup(null), null);
});

test("loopback-only listeners get firewall null — never filtered", async () => {
  const sockets = parseSsRows(
    'tcp   LISTEN 0      128        127.0.0.1:43241        0.0.0.0:*    users:(("app",pid=4194351,fd=5))',
  );
  const [rec] = await collectListeners({
    fixtures: { sockets, processes: [], firewall: fwView(() => false) },
  });
  assert.equal(rec.firewall, null);
});
