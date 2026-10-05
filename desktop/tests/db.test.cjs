/**
 * db.cjs queue/sighting tests — focused on the JSONL fallback backend.
 *
 * The module picks node:sqlite when available and falls back to append-only
 * device.jsonl otherwise. To force the JSONL path on runtimes that ship
 * node:sqlite (Node >= 22.5), we create `device.db` as a *directory* in the
 * temp dir — DatabaseSync can't open it, so tryOpen() falls through to
 * JSONL exactly as it does when the builtin is absent.
 *
 * Note on the "24h stale drop": the drop decision itself lives in
 * device.cjs's drainQueue callback (not exported — it checks the queuedAt
 * metadata age before replaying). These tests pin the contract that policy
 * relies on: drainReports delivers each row oldest-first with its original
 * queuedAt, and deletes the row when the callback returns normally.
 */

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const db = require("../db.cjs");

let dir;

function freshDir({ forceJsonl = true } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "rootwatch-dbtest-"));
  if (forceJsonl) {
    // Block the sqlite backend so the JSONL fallback opens instead.
    fs.mkdirSync(path.join(d, "device.db"));
  }
  return d;
}

beforeEach(() => {
  dir = freshDir();
  db.init(dir);
});

afterEach(async () => {
  await db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("JSONL fallback: queue/drain delivers reports oldest-first", async () => {
  await db.queueReport({ n: 1 });
  await db.queueReport({ n: 2 });
  await db.queueReport({ n: 3 });
  assert.equal(await db.queueSize(), 3);
  assert.ok(fs.existsSync(path.join(dir, "device.jsonl")), "expected JSONL backend");

  const delivered = [];
  const metas = [];
  await db.drainReports(async (body, meta) => {
    delivered.push(body);
    metas.push(meta);
  });
  assert.deepEqual(delivered, [{ n: 1 }, { n: 2 }, { n: 3 }]);
  assert.equal(await db.queueSize(), 0);
  // queuedAt metadata is what device.cjs's 24h-stale drop evaluates.
  for (const m of metas) {
    assert.ok(Number.isFinite(Date.parse(m.queuedAt)), "queuedAt must parse");
  }
});

test("drain stops at the first failure; the failing row and later rows stay queued", async () => {
  for (const n of [1, 2, 3, 4]) await db.queueReport({ n });

  const delivered = [];
  await db.drainReports(async (body) => {
    delivered.push(body.n);
    if (body.n === 2) throw new Error("server 500");
  });
  assert.deepEqual(delivered, [1, 2]);
  // Row 1 drained; the failing row (2) and everything after it stays queued.
  assert.equal(await db.queueSize(), 3);

  // Rows after the failure replay next drain, in order.
  const rest = [];
  await db.drainReports(async (body) => rest.push(body.n));
  assert.deepEqual(rest, [2, 3, 4]);
  assert.equal(await db.queueSize(), 0);
});

test("queue is capped at 200 — oldest rows are dropped first", async () => {
  for (let n = 1; n <= 205; n++) await db.queueReport({ n });
  assert.equal(await db.queueSize(), 200);

  const delivered = [];
  await db.drainReports(async (body) => delivered.push(body.n));
  assert.equal(delivered.length, 200);
  // n=1..5 evicted; the retained window is n=6..205, oldest first.
  assert.equal(delivered[0], 6);
  assert.equal(delivered[199], 205);
});

test("queued reports survive a reopen (JSONL replay at open)", async () => {
  await db.queueReport({ n: 42 });
  await db.close();
  db.init(dir); // same dir — replays device.jsonl
  assert.equal(await db.queueSize(), 1);
  const delivered = [];
  await db.drainReports(async (body) => delivered.push(body.n));
  assert.deepEqual(delivered, [42]);
});

test("corrupt JSONL lines are skipped at open, valid rows still replay", async () => {
  // Seed the file directly before init replays it.
  const file = path.join(dir, "device.jsonl");
  fs.writeFileSync(
    file,
    [
      '{"op":"report","id":1,"queuedAt":"2020-01-01T00:00:00.000Z","body":{"n":7}}',
      "{not json at all",
      '{"op":"report","id":2,"queuedAt":"2020-01-01T00:00:01.000Z","body":{"n":8}}',
    ].join("\n") + "\n",
  );
  await db.close();
  db.init(dir);
  assert.equal(await db.queueSize(), 2);

  // A stale-dated row (queuedAt > 24h ago) is still delivered to the
  // callback with its original timestamp — the staleness check lives in
  // device.cjs's drainQueue; drainReports itself delivers + deletes.
  const seen = [];
  await db.drainReports(async (body, meta) => {
    seen.push({ n: body.n, ageMs: Date.now() - Date.parse(meta.queuedAt) });
  });
  assert.deepEqual(
    seen.map((s) => s.n),
    [7, 8],
  );
  assert.ok(seen[0].ageMs > 24 * 60 * 60 * 1000);
  assert.equal(await db.queueSize(), 0);
});

test("listener sightings upsert by key and report first/last seen", async () => {
  await db.recordListeners([
    { pid: 1234, ports: [{ port: 8080 }, { port: 3000 }], name: "vite", risk: "low" },
  ]);
  const first = await db.getListenerHistory();
  assert.equal(first.length, 1);
  assert.equal(first[0].ports, "3000,8080"); // sorted csv
  assert.equal(first[0].firstSeen, first[0].lastSeen);

  // Same pid+ports key → last_seen bumps, first_seen anchors.
  await new Promise((r) => setTimeout(r, 5));
  await db.recordListeners([
    { pid: 1234, ports: [{ port: 3000 }, { port: 8080 }], name: "vite", risk: "low" },
    { pid: 1234, ports: [{ port: 9999 }], name: "other", risk: "info" },
  ]);
  const hist = await db.getListenerHistory();
  assert.equal(hist.length, 2);
  const bumped = hist.find((h) => h.ports === "3000,8080");
  assert.ok(Date.parse(bumped.lastSeen) >= Date.parse(first[0].lastSeen));
});

test("sightings track last_active only when established conns were observed", async () => {
  const item = (established) => ({
    pid: 1234,
    ports: [{ port: 8080 }],
    name: "vite",
    risk: "low",
    activity: { established, peers: [] },
  });

  await db.recordListeners([item(0)]);
  let [s] = await db.getListenerHistory();
  assert.equal(s.lastActive, null); // never seen active — not "idle since epoch"

  await new Promise((r) => setTimeout(r, 5));
  await db.recordListeners([item(3)]);
  [s] = (await db.getListenerHistory()).filter((h) => h.pid === 1234);
  const activeAt = s.lastActive;
  assert.ok(activeAt, "activity should stamp last_active");

  // A later idle pass must NOT erase the timestamp.
  await new Promise((r) => setTimeout(r, 5));
  await db.recordListeners([item(0)]);
  [s] = (await db.getListenerHistory()).filter((h) => h.pid === 1234);
  assert.equal(s.lastActive, activeAt);
});
