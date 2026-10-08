/**
 * Local persistence for the desktop shell.
 *
 * Feature-detected backend: node:sqlite's DatabaseSync where the runtime
 * ships it (Electron's Node >= 22.5); otherwise an append-only device.jsonl
 * in the same directory, replayed into an in-memory index at open. Both
 * expose an identical contract — callers never branch on which one answered.
 *
 * All exports use async signatures over synchronous implementations: the
 * writes are small (a 60s heartbeat), Electron's main process tolerates them,
 * and the async surface leaves room for a real async driver later.
 *
 * Nothing here stores secrets — sightings are {pid, ports, name, risk} and
 * queued rows are report bodies already bound for the control plane. The
 * vault table holds safeStorage-sealed ciphertext only (OS-keychain keyed):
 * a DB dump exposes fingerprints + metadata, nothing usable as a secret.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const QUEUE_CAP = 200;
// JSONL files grow by append — rewrite from the in-memory index once the op
// count since the last compaction passes this bound.
const COMPACT_AFTER_OPS = 2_000;

let dbDir = null; // set via init(); resolved lazily otherwise
let backend = null; // 'sqlite' | 'jsonl' once opened, null while unopened
let sqlite = null; // DatabaseSync
let jsonl = null; // { file, sightings: Map, reports: Map, nextId, appended }

/** Point the store at the app data dir. Optional — every export lazily
 *  resolves Electron's userData (or a tmpdir outside Electron) on first use,
 *  so main.cjs calling init() early is a nicety, not a requirement. */
function init(dir) {
  dbDir = dir;
  tryOpen();
}

function resolveDir() {
  if (dbDir) return dbDir;
  try {
    // Outside Electron `require('electron')` resolves to the binary-path
    // string export — .app is undefined and we fall through to tmpdir.
    const dir = require("electron")?.app?.getPath?.("userData");
    if (dir) return dir;
  } catch {
    /* not an Electron runtime */
  }
  return path.join(os.tmpdir(), "rootwatch-desktop");
}

function ensure() {
  if (!backend) tryOpen();
}

function tryOpen() {
  if (backend) return;
  let dir;
  try {
    dir = resolveDir();
    fs.mkdirSync(dir, { recursive: true });
  } catch {
    return; // no writable location — callers degrade on a null backend
  }
  try {
    const { DatabaseSync } = require("node:sqlite");
    const s = new DatabaseSync(path.join(dir, "device.db"));
    s.exec(`
      CREATE TABLE IF NOT EXISTS listener_sightings (
        key         TEXT PRIMARY KEY,
        pid         INTEGER,
        ports       TEXT NOT NULL DEFAULT '',
        name        TEXT,
        risk        TEXT,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        last_active TEXT
      );
      CREATE TABLE IF NOT EXISTS queued_reports (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        queued_at TEXT NOT NULL,
        body      TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS vault (
        fingerprint TEXT PRIMARY KEY,
        sealed      TEXT NOT NULL,
        label       TEXT,
        provider    TEXT,
        sealed_at   TEXT
      );
    `);
    sqlite = s;
    backend = "sqlite";
    try {
      // Pre-last_active databases: add the column in place (duplicate-column
      // error means it's already there — nothing else can throw usefully).
      s.exec("ALTER TABLE listener_sightings ADD COLUMN last_active TEXT");
    } catch {
      /* column already present */
    }
    return;
  } catch {
    /* builtin missing or DB unwritable — JSONL below */
  }
  try {
    jsonl = openJsonl(path.join(dir, "device.jsonl"));
    backend = "jsonl";
  } catch {
    /* stays unopened — every call degrades to its caller's fallback */
  }
}

// ---------------------------------------------------------------------------
// JSONL backend — append-only op log replayed into Maps at open, compacted by
// rewrite+rename once it grows past COMPACT_AFTER_OPS.
// ---------------------------------------------------------------------------

function openJsonl(file) {
  const state = {
    file,
    sightings: new Map(),
    reports: new Map(),
    vault: new Map(),
    nextId: 1,
    appended: 0,
  };
  let lines = 0;
  try {
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      lines++;
      try {
        applyJsonlOp(state, JSON.parse(line));
      } catch {
        /* corrupt line — skip it */
      }
    }
  } catch {
    /* first run — no file yet */
  }
  if (lines > COMPACT_AFTER_OPS) compactJsonl(state);
  return state;
}

function applyJsonlOp(state, op) {
  if (op?.op === "sighting" && typeof op.key === "string") {
    state.sightings.set(op.key, {
      key: op.key,
      pid: op.pid ?? null,
      ports: op.ports ?? "",
      name: op.name ?? null,
      risk: op.risk ?? null,
      firstSeen: op.firstSeen ?? null,
      lastSeen: op.lastSeen ?? null,
      lastActive: op.lastActive ?? null,
    });
  } else if (op?.op === "report" && Number.isInteger(op.id)) {
    state.reports.set(op.id, { id: op.id, queuedAt: op.queuedAt, body: op.body });
    if (op.id >= state.nextId) state.nextId = op.id + 1;
  } else if (op?.op === "report-del" && Number.isInteger(op.id)) {
    state.reports.delete(op.id);
  } else if (op?.op === "vault-put" && typeof op.fingerprint === "string") {
    state.vault.set(op.fingerprint, {
      fingerprint: op.fingerprint,
      sealed: op.sealed ?? "",
      label: op.label ?? null,
      provider: op.provider ?? null,
      sealedAt: op.sealedAt ?? null,
    });
  } else if (op?.op === "vault-del" && typeof op.fingerprint === "string") {
    state.vault.delete(op.fingerprint);
  }
}

function appendJsonl(state, op) {
  fs.appendFileSync(state.file, JSON.stringify(op) + "\n");
  state.appended++;
  if (state.appended > COMPACT_AFTER_OPS) compactJsonl(state);
}

function compactJsonl(state) {
  const tmp = `${state.file}.tmp`;
  const lines = [];
  for (const s of state.sightings.values()) lines.push(JSON.stringify({ op: "sighting", ...s }));
  for (const r of state.reports.values()) lines.push(JSON.stringify({ op: "report", ...r }));
  for (const v of state.vault.values()) lines.push(JSON.stringify({ op: "vault-put", ...v }));
  fs.writeFileSync(tmp, lines.length ? lines.join("\n") + "\n" : "");
  fs.renameSync(tmp, state.file);
  state.appended = 0;
}

// ---------------------------------------------------------------------------
// Listener sightings — upsert keyed by `${pid}:${ports-sorted-csv}` with
// first_seen anchored at first observation and last_seen bumped each pass.
// ---------------------------------------------------------------------------

/** Sighting key — `${pid}:${sorted-ports-csv}`. Shared with collector.cjs,
 *  which merges lastActiveAt back onto live records by this key. */
function sightingKey(l) {
  const ports = (Array.isArray(l?.ports) ? l.ports : [])
    .map((p) => p?.port)
    .filter((n) => Number.isInteger(n))
    .sort((a, b) => a - b);
  return `${l?.pid}:${ports.join(",")}`;
}

function sightingRows(items) {
  return (Array.isArray(items) ? items : []).map((l) => {
    const ports = (Array.isArray(l?.ports) ? l.ports : [])
      .map((p) => p?.port)
      .filter((n) => Number.isInteger(n))
      .sort((a, b) => a - b);
    return {
      key: `${l?.pid}:${ports.join(",")}`,
      pid: Number.isInteger(l?.pid) ? l.pid : null,
      ports: ports.join(","),
      name: l?.name ?? null,
      risk: l?.risk ?? null,
      // Established inbound conns observed this pass → bump last_active.
      active: (l?.activity?.established ?? 0) > 0,
    };
  });
}

async function recordListeners(items) {
  ensure();
  if (!backend) return;
  const now = new Date().toISOString();
  if (backend === "sqlite") {
    const stmt = sqlite.prepare(`
      INSERT INTO listener_sightings (key, pid, ports, name, risk, first_seen, last_seen, last_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        last_seen   = excluded.last_seen,
        name        = excluded.name,
        risk        = excluded.risk,
        last_active = COALESCE(excluded.last_active, last_active)
    `);
    for (const r of sightingRows(items)) {
      stmt.run(r.key, r.pid, r.ports, r.name, r.risk, now, now, r.active ? now : null);
    }
    return;
  }
  for (const r of sightingRows(items)) {
    const prev = jsonl.sightings.get(r.key);
    const s = {
      ...r,
      firstSeen: prev?.firstSeen ?? now,
      lastSeen: now,
      lastActive: r.active ? now : (prev?.lastActive ?? null),
    };
    delete s.active;
    jsonl.sightings.set(r.key, s);
    appendJsonl(jsonl, { op: "sighting", ...s });
  }
}

/** All sightings, newest last_seen first. [] when persistence is down. */
async function getListenerHistory() {
  ensure();
  if (!backend) return [];
  if (backend === "sqlite") {
    return sqlite
      .prepare(
        `SELECT key, pid, ports, name, risk,
                first_seen AS firstSeen, last_seen AS lastSeen,
                last_active AS lastActive
         FROM listener_sightings ORDER BY last_seen DESC`,
      )
      .all();
  }
  return [...jsonl.sightings.values()].sort((a, b) =>
    String(b.lastSeen).localeCompare(String(a.lastSeen)),
  );
}

// ---------------------------------------------------------------------------
// Offline report queue — report bodies that couldn't be POSTed, replayed
// oldest-first by drainReports once a report lands. Capped at QUEUE_CAP rows,
// oldest dropped first.
// ---------------------------------------------------------------------------

async function queueReport(body) {
  ensure();
  if (!backend) throw new Error("no persistence backend available");
  const queuedAt = new Date().toISOString();
  if (backend === "sqlite") {
    sqlite
      .prepare("INSERT INTO queued_reports (queued_at, body) VALUES (?, ?)")
      .run(queuedAt, JSON.stringify(body));
    sqlite
      .prepare(
        `DELETE FROM queued_reports WHERE id NOT IN
           (SELECT id FROM queued_reports ORDER BY id DESC LIMIT ?)`,
      )
      .run(QUEUE_CAP);
    return;
  }
  const id = jsonl.nextId++;
  jsonl.reports.set(id, { id, queuedAt, body });
  appendJsonl(jsonl, { op: "report", id, queuedAt, body });
  while (jsonl.reports.size > QUEUE_CAP) {
    const oldest = Math.min(...jsonl.reports.keys());
    jsonl.reports.delete(oldest);
    appendJsonl(jsonl, { op: "report-del", id: oldest });
  }
}

/**
 * Replay queued reports oldest-first: fn(body, {queuedAt}) per row, deleting
 * on success and stopping at the first failure (the failing row and
 * everything after it stays queued). Corrupt rows are dropped — they can
 * never be delivered anyway.
 */
async function drainReports(fn) {
  ensure();
  if (!backend) return;
  if (backend === "sqlite") {
    const rows = sqlite
      .prepare("SELECT id, queued_at AS queuedAt, body FROM queued_reports ORDER BY id ASC")
      .all();
    const del = sqlite.prepare("DELETE FROM queued_reports WHERE id = ?");
    for (const row of rows) {
      let body;
      try {
        body = JSON.parse(row.body);
      } catch {
        del.run(row.id);
        continue;
      }
      try {
        await fn(body, { queuedAt: row.queuedAt });
      } catch {
        break;
      }
      del.run(row.id);
    }
    return;
  }
  const rows = [...jsonl.reports.values()].sort((a, b) => a.id - b.id);
  for (const row of rows) {
    try {
      await fn(row.body, { queuedAt: row.queuedAt });
    } catch {
      break;
    }
    jsonl.reports.delete(row.id);
    appendJsonl(jsonl, { op: "report-del", id: row.id });
  }
}

async function queueSize() {
  ensure();
  if (!backend) return 0;
  if (backend === "sqlite") {
    return sqlite.prepare("SELECT COUNT(*) AS n FROM queued_reports").get().n;
  }
  return jsonl.reports.size;
}

// ---------------------------------------------------------------------------
// Vault — safeStorage-sealed credential blobs keyed by fingerprint (the
// keysha). sealed is opaque base64 ciphertext; plaintext is never stored.
// ---------------------------------------------------------------------------

async function vaultPut(entry) {
  ensure();
  if (!backend) throw new Error("no persistence backend available");
  const row = {
    fingerprint: String(entry?.fingerprint ?? ""),
    sealed: String(entry?.sealed ?? ""),
    label: entry?.label ?? null,
    provider: entry?.provider ?? null,
    sealedAt: new Date().toISOString(),
  };
  if (backend === "sqlite") {
    sqlite
      .prepare(
        `INSERT INTO vault (fingerprint, sealed, label, provider, sealed_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(fingerprint) DO UPDATE SET
           sealed    = excluded.sealed,
           label     = excluded.label,
           provider  = excluded.provider,
           sealed_at = excluded.sealed_at`,
      )
      .run(row.fingerprint, row.sealed, row.label, row.provider, row.sealedAt);
    return;
  }
  jsonl.vault.set(row.fingerprint, row);
  appendJsonl(jsonl, { op: "vault-put", ...row });
}

async function vaultGet(fingerprint) {
  ensure();
  if (!backend) return null;
  if (backend === "sqlite") {
    return (
      sqlite
        .prepare(
          `SELECT fingerprint, sealed, label, provider, sealed_at AS sealedAt
           FROM vault WHERE fingerprint = ?`,
        )
        .get(String(fingerprint ?? "")) ?? null
    );
  }
  return jsonl.vault.get(String(fingerprint ?? "")) ?? null;
}

async function vaultDelete(fingerprint) {
  ensure();
  if (!backend) return;
  const fp = String(fingerprint ?? "");
  if (backend === "sqlite") {
    sqlite.prepare("DELETE FROM vault WHERE fingerprint = ?").run(fp);
    return;
  }
  if (jsonl.vault.delete(fp)) appendJsonl(jsonl, { op: "vault-del", fingerprint: fp });
}

/** Vault metadata — the sealed blob never leaves this layer in a listing. */
async function vaultList() {
  ensure();
  if (!backend) return [];
  if (backend === "sqlite") {
    return sqlite
      .prepare(
        `SELECT fingerprint, label, provider, sealed_at AS sealedAt
         FROM vault ORDER BY sealed_at DESC`,
      )
      .all();
  }
  return [...jsonl.vault.values()]
    .map(({ fingerprint, label, provider, sealedAt }) => ({
      fingerprint,
      label,
      provider,
      sealedAt,
    }))
    .sort((a, b) => String(b.sealedAt).localeCompare(String(a.sealedAt)));
}

async function close() {
  if (backend === "sqlite") {
    try {
      sqlite.close();
    } catch {
      /* already closed */
    }
  }
  sqlite = null;
  jsonl = null;
  backend = null;
}

module.exports = {
  init,
  recordListeners,
  getListenerHistory,
  sightingKey,
  queueReport,
  drainReports,
  queueSize,
  vaultPut,
  vaultGet,
  vaultDelete,
  vaultList,
  close,
};
