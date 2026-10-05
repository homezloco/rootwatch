/**
 * Persistence detection for listener-owning processes ("This Device").
 *
 * Answers "will this come back after a reboot?" by checking three real
 * mechanism families:
 *   (a) systemd — `systemctl is-enabled <unit>` at the system manager, or
 *       the owning user's manager (`--user`, `-M <uid>@`) for user.slice
 *       units;
 *   (b) XDG autostart — Exec= lines in ~/.config/autostart and
 *       /etc/xdg/autostart .desktop files matching the process binary;
 *   (c) cron — @reboot entries in the current user's `crontab -l`
 *       referencing the binary.
 *
 * Honesty rules: every exec has a 3s timeout, every probe failure or
 * "not found" returns null — the result means "a mechanism we could
 * verify", never "definitely not persistent". Own-user autostart/crontab
 * are the only ones readable without privileges; other users' entries
 * simply don't surface. Linux-only — returns null elsewhere.
 */

const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { readdir, readFile, readlink } = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");

const execFileP = promisify(execFile);
const PROBE_TIMEOUT_MS = 3_000;

// Unit states that mean "starts at boot without manual action" — `enabled`
// is the explicit opt-in; static/generated/indirect/transient units are
// pulled in by dependencies or generated at boot.
const PERSISTENT_UNIT_STATES = new Set([
  "enabled",
  "enabled-runtime",
  "static",
  "generated",
  "indirect",
  "transient",
]);

// Desktop-entry field codes (%f %u %F %U ...) that expand to file lists —
// stripped before comparing Exec lines to a binary path.
const FIELD_CODE_RE = /%[a-zA-Z]/g;

async function exeForPid(pid, cmdline) {
  // Prefer the resolved binary; fall back to the cmdline's first token.
  if (pid != null) {
    try {
      const p = await readlink(`/proc/${pid}/exe`);
      if (p) return p;
    } catch {
      /* unreadable — foreign uid or process gone */
    }
  }
  const first = (cmdline ?? "").trim().split(/\s+/)[0] ?? "";
  return first || null;
}

async function systemdPersistence(unit, pid) {
  const cg = pid != null ? await readFile(`/proc/${pid}/cgroup`, "utf8").catch(() => "") : "";
  const attempts = [["is-enabled", unit]];
  const uidMatch = cg.match(/user-(\d+)\.slice/);
  if (/\/user\.slice\//.test(cg)) {
    const uid = uidMatch?.[1] ?? null;
    const selfUid = typeof process.getuid === "function" ? process.getuid() : null;
    if (uid != null && String(selfUid) === uid) {
      attempts.push(["--user", "is-enabled", unit]);
    }
    if (uid != null) {
      // -M <uid>@ hosts into that user's per-user service manager.
      attempts.push(["--user", "-M", `${uid}@`, "is-enabled", unit]);
    }
  }
  for (const args of attempts) {
    try {
      const { stdout } = await execFileP("systemctl", args, {
        timeout: PROBE_TIMEOUT_MS,
      });
      const state = stdout.trim().toLowerCase();
      if (PERSISTENT_UNIT_STATES.has(state)) {
        const scope = args.includes("--user") ? "user manager" : "system manager";
        return { mechanism: "systemd", detail: `${unit} is ${state} in the ${scope}` };
      }
    } catch {
      /* manager unreachable, unit absent, or permission denied */
    }
  }
  return null;
}

// Exec= lines from XDG autostart .desktop files we can actually read —
// own homedir plus the world-readable /etc/xdg/autostart.
async function autostartEntries(cache) {
  if (cache.autostart) return cache.autostart;
  const dirs = [path.join(os.homedir(), ".config", "autostart"), "/etc/xdg/autostart"];
  const entries = [];
  for (const dir of dirs) {
    let files;
    try {
      files = await readdir(dir);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!f.endsWith(".desktop")) continue;
      const raw = await readFile(path.join(dir, f), "utf8").catch(() => null);
      if (raw == null) continue;
      for (const line of raw.split("\n")) {
        const m = line.match(/^Exec=(.+)$/);
        if (m) {
          entries.push({ file: path.join(dir, f), exec: m[1].trim() });
          break;
        }
      }
    }
  }
  cache.autostart = entries;
  return entries;
}

// True when any token of a command line resolves to the process binary —
// absolute path match, or basename match for PATH-lookup invocations.
function execMatchesBinary(commandLine, exe) {
  if (!exe) return false;
  const base = path.basename(exe);
  if (!base) return false;
  return commandLine
    .replace(FIELD_CODE_RE, " ")
    .split(/\s+/)
    .filter(Boolean)
    .some((t) => t === exe || path.basename(t) === base);
}

// Current user's crontab only — other users' crontabs need root.
async function crontabLines(cache) {
  if (cache.crontab) return cache.crontab;
  try {
    const { stdout } = await execFileP("crontab", ["-l"], { timeout: PROBE_TIMEOUT_MS });
    cache.crontab = stdout.split("\n");
  } catch {
    cache.crontab = [];
  }
  return cache.crontab;
}

/**
 * Detect a reboot-survival mechanism for a listener-owning process.
 * Returns {mechanism, detail} for the first verifiable mechanism
 * (systemd → autostart → cron), or null when nothing is found or a probe
 * can't run — "can't tell" is honest, never fabricated.
 *
 * `cache` optionally shares autostart/crontab probe results across calls
 * within one collection pass (collector.cjs passes a fresh object per
 * pass; nothing persists across passes).
 */
async function detectPersistence({ pid, cmdline, systemdUnit }, cache = {}) {
  if (process.platform !== "linux") return null;

  // user@<uid>.service is the session wrapper — every logged-in process is
  // under it, so it carries no boot-survival signal for THIS service
  // (server parity: persistenceFor excludes it the same way).
  if (systemdUnit && !/^user@\d+\.service$/.test(systemdUnit)) {
    const s = await systemdPersistence(systemdUnit, pid);
    if (s) return s;
  }

  const exe = await exeForPid(pid, cmdline);
  if (!exe) return null;

  const autostart = await autostartEntries(cache);
  const hit = autostart.find((e) => execMatchesBinary(e.exec, exe));
  if (hit) {
    return { mechanism: "autostart", detail: `${hit.file} Exec=${hit.exec}` };
  }

  for (const line of await crontabLines(cache)) {
    const t = line.trim();
    if (!t.startsWith("@reboot")) continue;
    const cmd = t.slice("@reboot".length);
    if (execMatchesBinary(cmd, exe)) {
      return { mechanism: "cron", detail: `crontab @reboot: ${t}` };
    }
  }
  return null;
}

module.exports = { detectPersistence };
