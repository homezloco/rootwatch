/**
 * device.cjs tests — only the no-network surface is exercised.
 *
 * Command validation coverage note: the stop-listener/refresh dispatch and
 * the 24h stale-drop live in module-private runCommand/drainQueue, which
 * are only reachable through the (also private) reportOnce loop. Testing
 * them would require either a live control plane or a refactor of
 * device.cjs's exports — out of scope here, so this file pins the exported
 * enrollment/status surface instead. The stale-drop's underlying contract
 * (queuedAt delivery) is covered in db.test.cjs.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const device = require("../device.cjs");

test("enrollPollClaim fails honestly with no pending enrollment", async () => {
  device.cancelEnrollment(); // ensure clean state
  const r = await device.enrollPollClaim("http://127.0.0.1:1");
  assert.equal(r.status, "failed");
  assert.match(r.message, /no pending enrollment/i);
});

test("enrollStart surfaces a failure when the instance is unreachable", async () => {
  // Port 1 is closed — the fetch rejects fast; enrollStart must throw,
  // and must not leave a pending enrollment behind.
  await assert.rejects(() => device.enrollStart("http://127.0.0.1:1"));
  assert.equal(device.deviceStatus().enrollmentPending, false);
});

test("deviceHostId is a stable sha256", async () => {
  const a = await device.deviceHostId();
  const b = await device.deviceHostId();
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test("deviceStatus reports an honest idle state", () => {
  const s = device.deviceStatus();
  assert.equal(s.reporting, false);
  assert.equal(s.state, "idle");
  assert.equal(typeof s.hostname, "string");
  assert.equal(s.enrollmentPending, false);
});

test("stopReporter on a stopped reporter is a no-op", () => {
  device.stopReporter();
  assert.equal(device.deviceStatus().state, "idle");
});
