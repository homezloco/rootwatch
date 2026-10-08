/**
 * This-device sync — enrollment (code pairing) plus the periodic report loop
 * that makes this host a watched device on the connected RootWatch instance.
 *
 * Mirrors server/services/fleet-reporter.ts conventions:
 *  - hostId = sha256("rootwatch-host:" + machine-id), so a host running both
 *    the installed server and the desktop app upserts one device row
 *  - the report blob matches the shape DeviceDetail renders, plus a bounded
 *    listeners.items[] snapshot
 *  - the claimed enrollment token is a write-scope rw_ token; it lives in
 *    connection.json encrypted via safeStorage (never plaintext at rest)
 */

const { createHash } = require("node:crypto");
const { readFile } = require("node:fs/promises");
const os = require("node:os");
const collector = require("./collector.cjs");
const db = require("./db.cjs");

const REPORT_INTERVAL_MS = 60_000;

let cachedHostId = null;
async function deviceHostId() {
  if (cachedHostId) return cachedHostId;
  let basis = os.hostname();
  try {
    const mid = (await readFile("/etc/machine-id", "utf8")).trim();
    if (mid) basis = mid;
  } catch {
    /* non-Linux/container — hostname fallback, same as server reporter */
  }
  cachedHostId = createHash("sha256").update(`rootwatch-host:${basis}`).digest("hex");
  return cachedHostId;
}

// ---------------------------------------------------------------------------
// Enrollment — POST /api/v1/enroll/start (unauth'd; code+secret IS the
// credential), poll /claim until the user approves in the web UI.
// ---------------------------------------------------------------------------

let pendingEnroll = null; // { code, secret, verifyUrl, expiresAt }

async function enrollStart(baseUrl) {
  const res = await fetch(`${baseUrl}/api/v1/enroll/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname: os.hostname(), os: `${os.type()} ${os.release()}` }),
    signal: AbortSignal.timeout(15_000),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.code || !body?.secret) {
    throw new Error(body?.error?.message ?? `enroll/start failed (HTTP ${res.status})`);
  }
  pendingEnroll = {
    code: body.code,
    secret: body.secret,
    verifyUrl: body.verifyUrl,
    expiresAt: body.expiresAt,
  };
  return { code: body.code, verifyUrl: body.verifyUrl, expiresAt: body.expiresAt };
}

/**
 * One claim attempt. Returns:
 *   {status:'pending'} | {status:'approved', token} | {status:'expired'|'rejected'|'failed', message}
 */
async function enrollPollClaim(baseUrl) {
  if (!pendingEnroll) return { status: "failed", message: "no pending enrollment" };
  try {
    const res = await fetch(`${baseUrl}/api/v1/enroll/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: pendingEnroll.code, secret: pendingEnroll.secret }),
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status === 202) return { status: "pending" };
    const body = await res.json().catch(() => null);
    if (res.ok && body?.status === "approved" && body.token) {
      const token = body.token;
      pendingEnroll = null;
      return { status: "approved", token };
    }
    if (res.status === 404) {
      pendingEnroll = null;
      return { status: "expired", message: "enrollment expired — start again" };
    }
    return {
      status: "failed",
      message: body?.error?.message ?? `claim failed (HTTP ${res.status})`,
    };
  } catch (err) {
    return { status: "pending", error: err?.message };
  }
}

function cancelEnrollment() {
  pendingEnroll = null;
}

// ---------------------------------------------------------------------------
// Report loop — POST /api/v1/devices/report every minute. The response's
// data.commands[] are claimed by that POST: 'stop-listener' runs against the
// local collector and 'refresh' triggers one immediate re-report; everything
// else is acknowledged 'unsupported' (the desktop reporter doesn't execute
// privileged or self-mutating actions). Results ride back in the NEXT
// report's commandResults[]. A failed/5xx POST is persisted to the offline
// queue and replayed oldest-first after the next successful report; queued
// bodies older than 24h are dropped rather than replayed.
// ---------------------------------------------------------------------------

const QUEUE_STALE_MS = 24 * 60 * 60 * 1000;

let reportTimer = null;
let tickRunning = false; // refresh + drain can stretch a tick — never overlap
let pendingResults = [];
let reporterState = {
  lastReportAt: null,
  lastError: null,
  reporting: false,
  offline: false,
  queued: 0,
};

function postReport(baseUrl, token, body) {
  return fetch(`${baseUrl}/api/v1/devices/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
}

/**
 * Persist a report that couldn't be delivered. Best-effort: if the local
 * store is down, any command results embedded in the body go back onto
 * pendingResults so the next successful report still carries them.
 */
async function queueOffline(body) {
  reporterState.offline = true;
  try {
    await db.queueReport(body);
    reporterState.queued = await db.queueSize();
  } catch {
    if (Array.isArray(body?.commandResults)) pendingResults.unshift(...body.commandResults);
  }
}

/**
 * Execute one claimed command and push its result for the next report.
 * Returns true when the command asked for an immediate re-report.
 */
const KNOWN_COMMANDS = new Set([
  "refresh",
  "stop-listener",
  "keys-contain",
  "keys-probe",
  "keys-probe-all",
  "malware-scan",
]);

async function runCommand(c) {
  const result = { status: "unsupported", result: { reason: "unsupported on desktop reporter" } };
  if (Number.isInteger(c?.id)) result.commandId = c.id;
  try {
    if (typeof c?.type !== "string" || !KNOWN_COMMANDS.has(c.type)) {
      // update / uninstall / apply-updates / fix-check / unknown — acknowledged
      // 'unsupported' so they don't pile up on the server's claimed queue.
    } else if (c.type === "refresh") {
      result.status = "done";
      result.result = undefined;
    } else if (c.type === "keys-contain" || c.type === "keys-probe") {
      // Credential actions — the fingerprint is a sha256 keysha, never a
      // secret; validate strictly so a malformed command fails honestly
      // instead of reaching the scanner (same as the stop-listener gate).
      const payload = c.payload;
      const fp = payload?.fingerprint;
      const malformed =
        typeof payload !== "object" ||
        payload === null ||
        typeof fp !== "string" ||
        !/^[0-9a-f]{64}$/.test(fp) ||
        (c.type === "keys-contain" &&
          payload.copy !== undefined &&
          typeof payload.copy !== "boolean");
      if (malformed) {
        result.status = "failed";
        result.result = { error: `malformed ${c.type} payload` };
      } else {
        const keys = require("./keys.cjs");
        const outcome =
          c.type === "keys-contain"
            ? await keys.containKey(fp, { copy: payload.copy === true })
            : await keys.probeKey(fp);
        result.status =
          outcome?.status === "contained" || outcome?.status === "probed" ? "done" : "failed";
        result.result = outcome;
      }
    } else if (c.type === "keys-probe-all") {
      // Bulk liveness pass — optional {provider} filter; the payload is
      // metadata only (no fingerprint, no secret).
      const payload = c.payload;
      const provider = payload?.provider;
      const malformed =
        payload !== undefined &&
        (typeof payload !== "object" ||
          payload === null ||
          (provider !== undefined && typeof provider !== "string"));
      if (malformed) {
        result.status = "failed";
        result.result = { error: "malformed keys-probe-all payload" };
      } else {
        const keys = require("./keys.cjs");
        result.result = await keys.probeAll(typeof provider === "string" ? { provider } : {});
        result.status = "done";
      }
    } else if (c.type === "malware-scan") {
      // Forced full pass — bounded (~seconds heuristics, ≤180s ClamAV); the
      // summary also lands in the next report's report.malware.
      result.result = await require("./malware.cjs").scanNow();
      result.status = "done";
    } else {
      // stop-listener — validate the payload fully before it can reach the
      // collector; a malformed command fails honestly instead of signalling.
      const payload = c.payload;
      const pid = payload?.pid;
      if (
        typeof payload !== "object" ||
        payload === null ||
        !Number.isSafeInteger(pid) ||
        pid <= 1
      ) {
        result.status = "failed";
        result.result = { error: "malformed stop-listener payload" };
      } else {
        const outcome = await collector.stopListener(pid);
        result.status = outcome?.status === "stopped" ? "done" : "failed";
        result.result = outcome;
      }
    }
  } catch (err) {
    result.status = "failed";
    result.result = { error: err?.message ?? String(err) };
  }
  pendingResults.push(result);
  return c?.type === "refresh";
}

/**
 * Replay offline-queued reports oldest-first after a successful POST.
 * A replayed report's own response can carry commands — run them, but a
 * replay never triggers another refresh cycle. 4xx on a replay means the
 * body will never be accepted — the row drains as delivered-and-rejected
 * rather than poisoning the queue head forever.
 */
async function drainQueue(baseUrl, token) {
  await db.drainReports(async (queued, meta) => {
    const at = Date.parse(meta?.queuedAt ?? "");
    if (Number.isFinite(at) && Date.now() - at > QUEUE_STALE_MS) return; // stale — drop
    const res = await postReport(baseUrl, token, queued);
    if (!res.ok) {
      if (res.status >= 500) throw new Error(`replay rejected (HTTP ${res.status})`);
      return; // permanent rejection — drop the row
    }
    const data = await res.json().catch(() => null);
    const commands = Array.isArray(data?.data?.commands) ? data.data.commands : [];
    for (const c of commands) await runCommand(c);
  });
}

async function reportOnce(baseUrl, token, { allowRefresh = true } = {}) {
  const hostId = await deviceHostId();
  const malware = require("./malware.cjs");
  malware.refreshInBackground(); // stale-cache kickoff — never blocks the report
  const report = await collector.buildReport();
  const malwareSummary = malware.getCachedSummary();
  if (malwareSummary) report.malware = malwareSummary;
  // Newly-seen malware findings ride the agent detections channel → they
  // land as security_events rows via the existing recordDetections ingest.
  const malwareDetections = malware.drainDetections();
  if (malwareDetections.length) {
    report.detections = [...(report.detections ?? []), ...malwareDetections];
  }
  const body = {
    hostId,
    hostname: os.hostname(),
    os: `${os.type()} ${os.release()}`,
    platform: os.platform(),
    agentVersion: "desktop-1",
    report,
    ...(pendingResults.length ? { commandResults: pendingResults.splice(0) } : {}),
  };

  let res;
  try {
    res = await postReport(baseUrl, token, body);
  } catch (err) {
    await queueOffline(body); // network failure — replay later
    throw err;
  }
  if (!res.ok) {
    const errBody = await res.json().catch(() => null);
    if (res.status >= 500) await queueOffline(body); // server-side failure — replay later
    throw new Error(errBody?.error?.message ?? `report rejected (HTTP ${res.status})`);
  }

  reporterState.lastReportAt = new Date().toISOString();
  reporterState.lastError = null;
  reporterState.offline = false;

  const data = await res.json().catch(() => null);
  const commands = Array.isArray(data?.data?.commands) ? data.data.commands : [];
  let wantsRefresh = false;
  for (const c of commands) {
    if (await runCommand(c)) wantsRefresh = true;
  }

  try {
    await drainQueue(baseUrl, token);
    reporterState.queued = await db.queueSize();
  } catch {
    /* persistence down — reporting continues regardless */
  }

  // 'refresh' asks for a fresh snapshot right away — once, never a loop.
  if (wantsRefresh && allowRefresh) {
    await reportOnce(baseUrl, token, { allowRefresh: false });
  }
}

function startReporter({ url, token }) {
  stopReporter();
  if (!url || !token) return;
  reporterState.reporting = true;
  db.queueSize()
    .then((n) => (reporterState.queued = n))
    .catch(() => {});
  const tick = async () => {
    if (tickRunning) return;
    tickRunning = true;
    try {
      await reportOnce(url, token);
    } catch (err) {
      reporterState.lastError = err?.message ?? String(err);
    } finally {
      tickRunning = false;
    }
  };
  tick();
  reportTimer = setInterval(tick, REPORT_INTERVAL_MS);
}

function stopReporter() {
  if (reportTimer) clearInterval(reportTimer);
  reportTimer = null;
  reporterState.reporting = false;
}

/** Queued offline reports — cached snapshot from reporterState if the
 *  store itself can't be read. */
async function queueSize() {
  try {
    reporterState.queued = await db.queueSize();
  } catch {
    /* keep last known count */
  }
  return reporterState.queued;
}

function deviceStatus() {
  return {
    hostId: cachedHostId ? cachedHostId.slice(0, 12) : null,
    hostname: os.hostname(),
    reporting: reporterState.reporting,
    state: reporterState.reporting
      ? reporterState.offline
        ? "offline-queued"
        : "reporting"
      : "idle",
    queued: reporterState.queued,
    lastReportAt: reporterState.lastReportAt,
    lastError: reporterState.lastError,
    enrollmentPending: Boolean(pendingEnroll),
    enrollmentCode: pendingEnroll?.code ?? null,
    verifyUrl: pendingEnroll?.verifyUrl ?? null,
  };
}

module.exports = {
  deviceHostId,
  enrollStart,
  enrollPollClaim,
  cancelEnrollment,
  startReporter,
  stopReporter,
  queueSize,
  deviceStatus,
};
