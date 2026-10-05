// perf.cjs — "This Device" performance/reclaim report. Same sections and
// null-honest degradation as server/services/performance.ts, minus the DB
// (reclaim rides collector.collectListeners). Parsers mirrored from
// server/services/perf-parsers.ts — keep them in sync.

"use strict";

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const fs = require("node:fs");
const { homedir, userInfo } = require("node:os");
const si = require("systeminformation");
const collector = require("./collector.cjs");

const execFileP = promisify(execFile);
const EXEC_TIMEOUT_MS = 15_000;
const FIND_TIMEOUT_MS = 20_000;
const MAX_TOP = 15;

// ── parsers (mirrored from perf-parsers.ts) ──────────────────────────────

const BLAME_TIME = /^([\d.]+)(min|ms|us|s)$/;
const BLAME_MULT = { us: 1e-6, ms: 1e-3, s: 1, min: 60 };

function parseBlame(stdout) {
  const out = [];
  for (const line of String(stdout).split("\n")) {
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 2) continue;
    let seconds = 0;
    let i = 0;
    for (; i < tokens.length - 1; i++) {
      const m = tokens[i].match(BLAME_TIME);
      if (!m) break;
      seconds += Number(m[1]) * BLAME_MULT[m[2]];
    }
    if (i === 0 || i !== tokens.length - 1) continue;
    out.push({ unit: tokens[i], seconds: Math.round(seconds * 100) / 100 });
  }
  return out;
}

function durSeconds(s) {
  const m = s.match(/^(?:(\d+)min\s+)?([\d.]+)s$/);
  return m ? (m[1] ? Number(m[1]) * 60 : 0) + Number(m[2]) : null;
}

function parseBootTotal(stdout) {
  const m = stdout.match(/=\s*([\d.]+)s\b/) ?? stdout.match(/([\d.]+)s\s*\.?\s*$/);
  return m ? Number(m[1]) : null;
}

function parseBootPhases(stdout) {
  const phase = (label) => {
    const m = String(stdout).match(new RegExp(`(\\d+min\\s+[\\d.]+s|[\\d.]+s)\\s*\\(${label}\\)`));
    return m ? durSeconds(m[1]) : null;
  };
  return {
    firmware: phase("firmware"),
    loader: phase("loader"),
    kernel: phase("kernel"),
    userspace: phase("userspace"),
  };
}

function parseDockerDf(stdout) {
  const out = [];
  for (const line of String(stdout).split("\n")) {
    const cols = line
      .trim()
      .split(/\s{2,}/)
      .filter(Boolean);
    if (cols.length < 3 || /^type$/i.test(cols[0])) continue;
    const reclaimable = cols[cols.length - 1].replace(/\s*\(.*\)\s*$/, "").trim();
    out.push({ type: cols[0], total: cols[1] ?? "", reclaimable });
  }
  return out.length ? out : null;
}

function parseJournalMb(stdout) {
  const m = String(stdout).match(/take up\s+([\d.]+)([KMGTP]?)/i);
  if (!m) return null;
  const mult = { K: 1 / 1024, M: 1, G: 1024, T: 1e6, P: 1e9, "": 1 / 1048576 }[m[2].toUpperCase()];
  return Math.round(Number(m[1]) * mult * 10) / 10;
}

function parseDisabledSnaps(stdout) {
  const out = [];
  for (const line of String(stdout).split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5 || f[0] === "Name") continue;
    if (!/disabled/i.test(f[f.length - 1])) continue;
    out.push({ name: f[0], version: f[1], revision: f[2] });
  }
  return out;
}

function parseSnapList(stdout) {
  return String(stdout)
    .split("\n")
    .map((l) => l.trim().split(/\s+/))
    .filter((f) => f.length >= 3 && f[0] !== "Name")
    .map((f) => ({ name: f[0], version: f[1] }));
}

function stackDupes(dpkgList, snapList) {
  const snapByName = new Map(snapList.map((s) => [s.name, s.version]));
  const seen = new Set();
  const out = [];
  for (const d of dpkgList) {
    const name = d.split(/[\s:]/)[0];
    if (!name || seen.has(name)) continue;
    const sv = snapByName.get(name);
    if (sv === undefined) continue;
    seen.add(name);
    out.push({ name, debVersion: d.split(/\s+/)[1] ?? "", snapVersion: sv });
  }
  return out;
}

function parseAutoremove(stdout) {
  return String(stdout)
    .split("\n")
    .map((l) => l.match(/^Remv\s+(\S+)/)?.[1])
    .filter(Boolean);
}

function parseUpgradableCount(stdout) {
  return String(stdout)
    .split("\n")
    .filter((l) => l.includes("[upgradable")).length;
}

function parseResidualPackages(dpkgL) {
  return String(dpkgL)
    .split("\n")
    .filter((l) => l.startsWith("rc"))
    .map((l) => l.trim().split(/\s+/)[1])
    .filter(Boolean);
}

function parseDuBytes(stdout) {
  const field = String(stdout).trim().split(/\s+/)[0];
  if (!field) return null;
  const n = Number(field);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function parseTimerUnitFiles(stdout) {
  const map = {};
  for (const line of String(stdout).split("\n")) {
    const p = line.trim().split(/\s+/);
    if (p.length >= 2 && p[0].endsWith(".timer")) map[p[0]] = p[1];
  }
  return map;
}

function parseListTimersJson(stdout) {
  try {
    const rows = JSON.parse(String(stdout));
    if (!Array.isArray(rows)) return [];
    return rows
      .filter((r) => r && typeof r.unit === "string")
      .map((r) => ({
        unit: r.unit,
        activates: typeof r.activates === "string" ? r.activates : "",
        next:
          Number.isFinite(r.next) && r.next > 0
            ? new Date(Math.floor(r.next / 1000)).toISOString()
            : null,
        last:
          Number.isFinite(r.last) && r.last > 0
            ? new Date(Math.floor(r.last / 1000)).toISOString()
            : null,
      }));
  } catch {
    return [];
  }
}

function showTimeMs(v) {
  if (!v) return null;
  const us = Number(v);
  if (Number.isFinite(us) && us > 0) return us / 1000;
  const m = v.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
  if (!m) return null;
  const ms = Date.parse(m[1].replace(" ", "T"));
  return Number.isFinite(ms) ? ms : null;
}

function parseTimerShow(stdout, enabledMap) {
  const units = [];
  let cur = {};
  for (const line of String(stdout).split("\n")) {
    if (!line.trim()) {
      if (cur.Id) units.push(cur);
      cur = {};
      continue;
    }
    const eq = line.indexOf("=");
    if (eq > 0) cur[line.slice(0, eq)] = line.slice(eq + 1);
  }
  if (cur.Id) units.push(cur);
  return units.map((u) => {
    const nextMs = showTimeMs(u.NextElapseUSecRealtime);
    const lastMs = showTimeMs(u.LastTriggerUSec);
    return {
      name: u.Id ?? "",
      enabled: enabledMap[u.Id ?? ""] ?? "unknown",
      active: u.ActiveState === "active",
      activates: (u.Triggers ?? "").trim(),
      next: nextMs != null ? new Date(nextMs).toISOString() : null,
      last: lastMs != null ? new Date(lastMs).toISOString() : null,
    };
  });
}

function parsePressure(stdout) {
  const some = String(stdout)
    .split("\n")
    .find((l) => l.startsWith("some"));
  const full = String(stdout)
    .split("\n")
    .find((l) => l.startsWith("full"));
  if (!some) return null;
  const some10 = Number(some.match(/avg10=([\d.]+)/)?.[1] ?? NaN);
  const some60 = Number(some.match(/avg60=([\d.]+)/)?.[1] ?? NaN);
  if (!Number.isFinite(some10)) return null;
  const full10 = full ? Number(full.match(/avg10=([\d.]+)/)?.[1] ?? NaN) : null;
  return { some10, some60, full10: Number.isFinite(full10) ? full10 : null };
}

function throttleDelta(prev, cur) {
  if (!prev) return null;
  const deltaMs = cur.packageTimeMs - prev.packageTimeMs;
  const windowSec = (cur.at - prev.at) / 1000;
  if (deltaMs < 0 || windowSec <= 0) return null;
  return { deltaMs, windowSec: Math.round(windowSec) };
}

// ── sections ─────────────────────────────────────────────────────────────

async function collectReclaim() {
  const [listeners, procList] = await Promise.all([
    collector.collectListeners(),
    si.processes().catch(() => null),
  ]);
  const memByPid = new Map();
  for (const p of procList?.list ?? []) {
    memByPid.set(p.pid, {
      memMb: Number.isFinite(p.memRss) ? Math.round((p.memRss / 1024) * 10) / 10 : null,
      cpu: Number.isFinite(p.cpu) ? p.cpu : null,
    });
  }
  const now = Date.now();
  const candidates = [];
  for (const l of listeners) {
    if (l.stoppable === "no") continue;
    if (l.activity == null || l.activity.established > 0) continue;
    const idleSec =
      l.lastActiveAt != null
        ? Math.max(0, (now - Date.parse(l.lastActiveAt)) / 1000)
        : (l.ageSeconds ?? null);
    const cost = memByPid.get(l.pid);
    candidates.push({
      pid: l.pid,
      name: l.name,
      ports: l.ports.map((p) => `${p.port}/${p.protocol}`).join(", "),
      memMb: cost?.memMb ?? null,
      cpuPercent: cost?.cpu ?? null,
      idleSec,
      stoppable: l.stoppable,
      unit: l.unit,
      suggestedFix: l.suggestedFix ?? null,
    });
  }
  candidates.sort((a, b) => (b.memMb ?? 0) - (a.memMb ?? 0));
  return {
    totalMemMb: Math.round(candidates.reduce((n, c) => n + (c.memMb ?? 0), 0) * 10) / 10,
    candidates: candidates.slice(0, MAX_TOP),
  };
}

async function collectOrphans() {
  const procList = await si.processes().catch(() => null);
  if (!procList) return [];
  const pids = new Set(procList.list.map((p) => p.pid));
  let selfUser = null;
  try {
    selfUser = userInfo().username;
  } catch {
    /* not evaluable */
  }
  const now = Date.now();
  return procList.list
    .filter((p) => {
      if (p.pid <= 1 || p.parentPid == null || p.parentPid <= 1) return false;
      if (pids.has(p.parentPid)) return false;
      if (selfUser === null || p.user !== selfUser) return false;
      const age = p.started ? (now - Date.parse(p.started)) / 1000 : Infinity;
      if (age < 3600) return false;
      const memMb = Number.isFinite(p.memRss) ? p.memRss / 1024 : 0;
      return memMb >= 64 || p.cpu >= 5;
    })
    .map((p) => ({
      pid: p.pid,
      name: p.name ?? p.command ?? "unknown",
      command: [p.command, p.params].filter(Boolean).join(" ").slice(0, 120),
      memMb: Number.isFinite(p.memRss) ? Math.round((p.memRss / 1024) * 10) / 10 : null,
      cpuPercent: Number.isFinite(p.cpu) ? p.cpu : 0,
      ageSec: p.started ? Math.max(0, Math.round((now - Date.parse(p.started)) / 1000)) : null,
    }))
    .sort((a, b) => (b.memMb ?? 0) - (a.memMb ?? 0))
    .slice(0, MAX_TOP);
}

async function collectBoot() {
  if (process.platform !== "linux") return null;
  try {
    const [{ stdout: total }, { stdout: blame }] = await Promise.all([
      execFileP("systemd-analyze", [], { timeout: EXEC_TIMEOUT_MS }),
      execFileP("systemd-analyze", ["blame"], { timeout: EXEC_TIMEOUT_MS }),
    ]);
    return {
      totalSeconds: parseBootTotal(total),
      phases: parseBootPhases(total),
      blame: parseBlame(blame).slice(0, 10),
    };
  } catch {
    return null;
  }
}

async function findNodeModules() {
  const { stdout } = await execFileP(
    "find",
    [homedir(), "-maxdepth", "4", "-type", "d", "-name", "node_modules", "-prune"],
    { timeout: FIND_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 },
  );
  const dirs = stdout.split("\n").filter(Boolean).slice(0, 25);
  const rows = [];
  const now = Date.now();
  for (const dir of dirs) {
    try {
      const { stdout: du } = await execFileP("du", ["-sm", dir], { timeout: EXEC_TIMEOUT_MS });
      const sizeMb = Number(du.split(/\s+/)[0]);
      if (!Number.isFinite(sizeMb) || sizeMb < 50) continue;
      const st = await fs.promises.stat(dir);
      rows.push({ path: dir, sizeMb, idleDays: Math.floor((now - st.mtimeMs) / 86400000) });
    } catch {
      /* vanished or unreadable */
    }
  }
  return rows.sort((a, b) => b.sizeMb - a.sizeMb).slice(0, 10);
}

async function collectAptHealth() {
  const tryCmd = (cmd, args) =>
    execFileP(cmd, args, { timeout: EXEC_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 });
  const [cache, autoremove, dpkgL, upgradable] = await Promise.all([
    tryCmd("du", ["-sb", "/var/cache/apt/archives"]).then(
      (r) => parseDuBytes(r.stdout),
      (e) => parseDuBytes(e?.stdout ?? ""),
    ),
    tryCmd("apt-get", ["-s", "autoremove"]).then(
      (r) => parseAutoremove(r.stdout),
      () => null,
    ),
    tryCmd("dpkg", ["-l"]).then(
      (r) => parseResidualPackages(r.stdout),
      () => null,
    ),
    tryCmd("apt", ["list", "--upgradable"]).then(
      (r) => parseUpgradableCount(r.stdout),
      () => null,
    ),
  ]);
  if (cache === null && autoremove === null && dpkgL === null && upgradable === null) return null;
  return {
    cacheMb: cache != null ? Math.round((cache / 1048576) * 10) / 10 : null,
    autoremove: autoremove ?? [],
    residual: dpkgL ?? [],
    upgradable: upgradable ?? 0,
  };
}

async function collectDisk() {
  const [docker, journal, nodeModules, snaps, apt] = await Promise.all([
    execFileP("docker", ["system", "df"], { timeout: EXEC_TIMEOUT_MS })
      .then((r) => parseDockerDf(r.stdout))
      .catch(() => null),
    execFileP("journalctl", ["--disk-usage"], { timeout: EXEC_TIMEOUT_MS })
      .then((r) => parseJournalMb(r.stdout))
      .catch(() => null),
    findNodeModules().catch(() => null),
    execFileP("snap", ["list", "--all"], { timeout: EXEC_TIMEOUT_MS })
      .then((r) => parseDisabledSnaps(r.stdout))
      .catch(() => null),
    collectAptHealth(),
  ]);
  return { docker, journalMb: journal, nodeModules, disabledSnaps: snaps, apt };
}

async function collectTimers() {
  if (process.platform !== "linux") return null;
  try {
    const { stdout: files } = await execFileP(
      "systemctl",
      ["list-unit-files", "--type=timer", "--no-pager", "--no-legend"],
      { timeout: EXEC_TIMEOUT_MS },
    );
    const enabledMap = parseTimerUnitFiles(files);
    if (!Object.keys(enabledMap).length) return [];

    let timers;
    try {
      const { stdout: json } = await execFileP(
        "systemctl",
        ["list-timers", "--all", "--output=json", "--no-pager"],
        { timeout: EXEC_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024 },
      );
      timers = parseListTimersJson(json).map((r) => ({
        name: r.unit,
        enabled: enabledMap[r.unit] ?? "unknown",
        active: r.next != null,
        activates: r.activates,
        next: r.next,
        last: r.last,
      }));
      if (!timers.length) throw new Error("empty list-timers");
    } catch {
      const names = Object.keys(enabledMap).slice(0, 64);
      const { stdout: show } = await execFileP(
        "systemctl",
        [
          "show",
          ...names,
          "--property=Id,ActiveState,NextElapseUSecRealtime,LastTriggerUSec,Triggers",
        ],
        { timeout: EXEC_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024 },
      );
      timers = parseTimerShow(show, enabledMap).filter((t) => t.name);
    }
    return timers
      .sort(
        (a, b) =>
          (a.next ? Date.parse(a.next) : Infinity) - (b.next ? Date.parse(b.next) : Infinity),
      )
      .slice(0, 25);
  } catch {
    return null;
  }
}

async function collectPressure() {
  const read = async (f) =>
    fs.promises
      .readFile(`/proc/pressure/${f}`, "utf8")
      .then(parsePressure)
      .catch(() => null);
  const [cpu, memory, io, mem] = await Promise.all([
    read("cpu"),
    read("memory"),
    read("io"),
    si.mem().catch(() => null),
  ]);
  return {
    cpu: cpu ? { some10: cpu.some10, some60: cpu.some60 } : null,
    memory: memory ? { some10: memory.some10, full10: memory.full10 ?? 0 } : null,
    io: io ? { some10: io.some10, full10: io.full10 ?? 0 } : null,
    memPercent: mem ? Math.round(((mem.total - mem.available) / mem.total) * 1000) / 10 : null,
    swapPercent:
      mem && mem.swaptotal > 0 ? Math.round((mem.swapused / mem.swaptotal) * 1000) / 10 : 0,
  };
}

const readSys = (p) => fs.promises.readFile(p, "utf8").then((s) => s.trim());
const readSysInt = async (p) => {
  const s = await readSys(p).catch(() => "");
  if (!s) return null; // Number("") is 0 — an absent file must not fake a reading
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
};

let lastThrottleSample = null;

async function collectThermal() {
  if (process.platform !== "linux") return null;
  const temps = [];
  const fans = [];
  try {
    for (const hw of await fs.promises.readdir("/sys/class/hwmon")) {
      const base = `/sys/class/hwmon/${hw}`;
      const name = await readSys(`${base}/name`).catch(() => "");
      for (let i = 1; ; i++) {
        const raw = await readSysInt(`${base}/temp${i}_input`);
        if (raw === null) break;
        if (raw > 0) {
          const label = (await readSys(`${base}/temp${i}_label`).catch(() => "")) || name;
          temps.push({ label, celsius: Math.round(raw / 100) / 10 });
        }
      }
      for (let f = 1; ; f++) {
        const rpm = await readSysInt(`${base}/fan${f}_input`);
        if (rpm === null) break;
        if (rpm > 0) fans.push({ label: `${name} fan ${f}`, rpm });
      }
    }
  } catch {
    /* no hwmon */
  }

  let cpuMinMhz = null;
  let cpuMaxMhz = null;
  try {
    const freqs = [];
    for (const cpu of await fs.promises.readdir("/sys/devices/system/cpu")) {
      if (!/^cpu\d+$/.test(cpu)) continue;
      const khz = await readSysInt(`/sys/devices/system/cpu/${cpu}/cpufreq/scaling_cur_freq`);
      if (khz && khz > 0) freqs.push(khz / 1000);
    }
    if (freqs.length) {
      cpuMinMhz = Math.round(Math.min(...freqs));
      cpuMaxMhz = Math.round(Math.max(...freqs));
    }
  } catch {
    /* no cpufreq */
  }
  const turboEnabled = await readSys("/sys/devices/system/cpu/intel_pstate/no_turbo")
    .then((v) => v !== "1")
    .catch(() => null);

  let throttle = null;
  const pkgEvents = await readSysInt(
    "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count",
  );
  const pkgTime = await readSysInt(
    "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_total_time_ms",
  );
  if (pkgEvents !== null && pkgTime !== null) {
    let coreEvents = 0;
    try {
      for (const cpu of await fs.promises.readdir("/sys/devices/system/cpu")) {
        if (!/^cpu\d+$/.test(cpu)) continue;
        coreEvents +=
          (await readSysInt(
            `/sys/devices/system/cpu/${cpu}/thermal_throttle/core_throttle_count`,
          )) ?? 0;
      }
    } catch {
      /* no per-cpu counters */
    }
    const uptimeSec =
      Number((await fs.promises.readFile("/proc/uptime", "utf8")).split(/\s+/)[0]) || 0;
    const fraction = uptimeSec > 0 ? pkgTime / (uptimeSec * 1000) : 0;
    const now = Date.now();
    const delta = throttleDelta(lastThrottleSample, { at: now, packageTimeMs: pkgTime });
    lastThrottleSample = { at: now, packageTimeMs: pkgTime };
    throttle = {
      packageEvents: pkgEvents,
      packageTimeMs: pkgTime,
      coreEvents,
      fractionOfUptime: Math.round(fraction * 1000) / 1000,
      notable: pkgTime >= 60_000 || fraction >= 0.05,
      deltaMs: delta?.deltaMs ?? null,
      deltaWindowSec: delta?.windowSec ?? null,
    };
  }

  if (!temps.length && !fans.length && cpuMinMhz === null && !throttle) return null;
  return { temps, fans, cpuMinMhz, cpuMaxMhz, turboEnabled, throttle };
}

async function collectStackDupes() {
  if (process.platform !== "linux") return null;
  try {
    const [{ stdout: dpkg }, { stdout: snap }] = await Promise.all([
      execFileP("dpkg-query", ["-W", "-f=${Package}\t${Version}\n"], {
        timeout: EXEC_TIMEOUT_MS,
        maxBuffer: 4 * 1024 * 1024,
      }),
      execFileP("snap", ["list"], { timeout: EXEC_TIMEOUT_MS }),
    ]);
    return stackDupes(dpkg.split("\n").filter(Boolean), parseSnapList(snap));
  } catch {
    return null;
  }
}

// ── report ───────────────────────────────────────────────────────────────

let cache = null;
const CACHE_MS = 60_000;

async function collectPerformance({ force = false } = {}) {
  if (cache && !force && Date.now() - cache.at < CACHE_MS) return cache.report;
  const [reclaim, orphans, boot, disk, pressure, dupes, timers, thermal] = await Promise.all([
    collectReclaim().catch(() => null),
    collectOrphans().catch(() => null),
    collectBoot().catch(() => null),
    collectDisk().catch(() => null),
    collectPressure().catch(() => null),
    collectStackDupes().catch(() => null),
    collectTimers().catch(() => null),
    collectThermal().catch(() => null),
  ]);
  const report = {
    reclaim,
    orphans,
    boot,
    disk,
    pressure,
    stackDupes: dupes,
    timers,
    thermal,
  };
  cache = { at: Date.now(), report };
  return report;
}

module.exports = {
  collectPerformance,
  // exported for tests — mirrored parsers from server perf-parsers.ts
  parseBlame,
  parseBootTotal,
  parseBootPhases,
  parseDockerDf,
  parseJournalMb,
  parseAutoremove,
  parseResidualPackages,
  parseDuBytes,
  parseListTimersJson,
  parseTimerShow,
  parseTimerUnitFiles,
  parsePressure,
  throttleDelta,
  stackDupes,
};
