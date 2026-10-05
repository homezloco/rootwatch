"use strict";
/**
 * RootWatch desktop — local project scanner.
 *
 * Port of cli/src/scan/{walk,secrets,hygiene}.ts to a zero-dependency
 * CommonJS module for Electron's main process. Findings, rules and
 * severities mirror `rw scan` on the same tree (CLI severities are
 * reported lowercased per the desktop contract).
 *
 * Intentionally NOT ported: cli/src/scan/deps.ts. It shells out to
 * `npm audit --json`, which requires an npm binary on PATH and makes
 * network requests to the npm registry — it is not pure local file
 * analysis and has no place in an offline-capable scanner. Lockfiles
 * remain skipped from text scanning exactly as the CLI does.
 *
 * Safety contract (differs deliberately from the CLI walker):
 *  - finding paths are RELATIVE to the scanned root, never absolute
 *    (absolute paths leak user dirnames into fleet reports)
 *  - `note` is a fixed rule title — matched content/secret values are
 *    never copied into a finding
 *  - traversal is capped at maxFiles (default 5000) and findings at 200
 *  - symlinks are followed only when their realpath stays inside the
 *    root; anything resolving outside is skipped, as are symlink cycles
 *  - node_modules is not traversed except for package-level
 *    `node_modules/<pkg>/package.json` manifests (dependency inventory)
 *  - this module never throws: bad input yields {scanned:0, error:...}
 */

const { promises: fsp, realpathSync } = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const MAX_FILE_BYTES = 512 * 1024; // same as cli/src/scan/walk.ts
const DEFAULT_MAX_FILES = 5000;
const MAX_FINDINGS = 200;
const MAX_PER_RULE_PER_FILE = 10; // same as cli/src/scan/secrets.ts
const READ_CONCURRENCY = 16;

// Same skip set as cli/src/scan/walk.ts, minus node_modules (handled
// separately so package-level package.json manifests are still seen).
const SKIP_DIRS = new Set([
  ".git", // covers .git/objects and the rest of the VCS internals
  ".hg",
  ".svn",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  "coverage",
  "vendor",
  "target",
  ".venv",
  "venv",
  "__pycache__",
]);

const BINARY_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".icns",
  ".bmp",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  ".tar",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".wav",
  ".webm",
  ".wasm",
  ".so",
  ".dll",
  ".exe",
  ".dylib",
  ".bin",
  ".dat",
  ".jar",
  ".class",
  ".pyc",
  ".pyo",
  ".o",
  ".a",
  ".sqlite",
  ".db",
  ".lockb",
  ".snap",
]);

// Lockfiles: the CLI routes these to the deps scanner (npm audit), which
// this port omits — so they are skipped from text scanning as upstream.
const SKIP_FILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "composer.lock",
  "poetry.lock",
  "cargo.lock",
  "go.sum",
]);

function isSkippableFile(name) {
  if (SKIP_FILES.has(name)) return true;
  if (name.endsWith(".min.js") || name.endsWith(".min.css")) return true;
  if (name.endsWith(".map")) return true;
  return BINARY_EXTS.has(path.extname(name).toLowerCase());
}

/** Could this dirent possibly produce a scanned file? (cheap, name-only) */
function entryCouldYield(entry) {
  if (entry.isSymbolicLink()) return true; // unknown until resolved
  if (entry.isDirectory()) return !SKIP_DIRS.has(entry.name);
  if (entry.isFile()) return !isSkippableFile(entry.name);
  return false;
}

function relPathOf(rootAbs, abs) {
  return path.relative(rootAbs, abs).split(path.sep).join("/");
}

function isInside(rootReal, real) {
  return real === rootReal || real.startsWith(rootReal + path.sep);
}

/**
 * The scan-root gate: a listener's cwd must resolve inside the user's
 * home. Both sides are realpath'd first — a `~/link -> /` cwd passes a
 * lexical prefix check but would walk the whole disk (same discipline
 * the walker applies to symlinked entries). A realpath failure falls
 * back to the lexical path; scanning a nonexistent target then fails
 * honestly instead of escaping.
 */
function realpathOrResolved(p) {
  try {
    return realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

function resolveScanDir(dir, homeDir = os.homedir()) {
  const home = realpathOrResolved(homeDir);
  const target = realpathOrResolved(typeof dir === "string" && dir ? dir : home);
  if (!isInside(home, target)) {
    throw new Error("scan dir must be under your home directory");
  }
  return target;
}

async function statSize(abs) {
  try {
    return (await fsp.stat(abs)).size;
  } catch {
    return null;
  }
}

/**
 * Collect `node_modules/<pkg>/package.json` and
 * `node_modules/<scope>/<pkg>/package.json` manifests — nothing deeper.
 * Package dirs that resolve outside the root (e.g. pnpm global store
 * links) are skipped by the same containment rule as other symlinks.
 */
async function collectNodeModulesManifests(nmAbs, state) {
  let entries;
  try {
    entries = await fsp.readdir(nmAbs, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (state.files.length >= state.maxFiles) {
      if (entryCouldYield(entry)) state.truncated = true;
      continue; // keep looking so `truncated` reflects real leftovers
    }
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    const pkgDir = path.join(nmAbs, entry.name);
    if (entry.name.startsWith("@")) {
      // scoped packages: @scope/<pkg>/package.json
      let scoped;
      try {
        scoped = await fsp.readdir(pkgDir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const sub of scoped) {
        if (!sub.isDirectory() && !sub.isSymbolicLink()) continue;
        await addManifest(state, path.join(pkgDir, sub.name));
        if (state.truncated) break;
      }
    } else {
      await addManifest(state, pkgDir);
    }
  }
}

async function addManifest(state, pkgDir) {
  if (state.files.length >= state.maxFiles) {
    state.truncated = true;
    return;
  }
  let real;
  try {
    real = await fsp.realpath(pkgDir);
  } catch {
    return;
  }
  if (!isInside(state.rootReal, real)) return; // link escaping the root
  const manifest = path.join(pkgDir, "package.json");
  const size = await statSize(manifest);
  if (size === null || size > MAX_FILE_BYTES) return;
  state.files.push({
    absPath: manifest,
    relPath: relPathOf(state.rootAbs, manifest),
    size,
  });
}

/** Async iterative walker — mirrors walkProject() with the desktop caps. */
async function walkProject(rootAbs, rootReal, maxFiles) {
  const state = {
    files: [],
    truncated: false,
    maxFiles,
    rootAbs,
    rootReal,
    visited: new Set([rootReal]),
  };
  const stack = [rootAbs];

  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable dir — skip quietly
    }
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (state.files.length >= maxFiles) {
        // Cap hit: flag truncated only if real work remains here or below.
        if (entries.slice(i).some(entryCouldYield) || stack.length > 0) {
          state.truncated = true;
        }
        break; // stop scanning this dir
      }
      const abs = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === "node_modules") {
          // Shallow manifest pass only; never recurse into packages.
          const nmReal = await realpathOrNull(abs);
          if (nmReal && isInside(state.rootReal, nmReal)) {
            await collectNodeModulesManifests(abs, state);
          }
          continue;
        }
        if (SKIP_DIRS.has(entry.name)) continue;
        // Realpath dedup: prevents bind-mount/hardlink cycles and gives
        // containment for free alongside the symlink branch below.
        const real = await realpathOrNull(abs);
        if (!real || !isInside(state.rootReal, real) || state.visited.has(real)) {
          continue;
        }
        state.visited.add(real);
        stack.push(abs);
        continue;
      }

      let size = null;
      if (entry.isSymbolicLink()) {
        // Follow only links whose target stays inside the root.
        const real = await realpathOrNull(abs);
        if (!real || !isInside(state.rootReal, real)) continue;
        let st;
        try {
          st = await fsp.stat(abs); // stat follows the link
        } catch {
          continue;
        }
        if (st.isDirectory()) {
          // Name-based rules apply to link names too (dist, .git, …);
          // node_modules links get the same shallow manifest pass.
          if (entry.name === "node_modules") {
            await collectNodeModulesManifests(abs, state);
            continue;
          }
          if (SKIP_DIRS.has(entry.name)) continue;
          if (!state.visited.has(real)) {
            state.visited.add(real);
            stack.push(abs); // traverse via link path for stable rel paths
          }
          continue;
        }
        if (!st.isFile()) continue;
        size = st.size;
      } else {
        if (!entry.isFile()) continue; // sockets, fifos, devices
      }

      if (isSkippableFile(entry.name)) continue;
      if (size === null) {
        size = await statSize(abs);
        if (size === null) continue;
      }
      if (size > MAX_FILE_BYTES) continue;
      state.files.push({ absPath: abs, relPath: relPathOf(rootAbs, abs), size });
    }
  }

  state.files.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return state;
}

async function realpathOrNull(abs) {
  try {
    return await fsp.realpath(abs);
  } catch {
    return null;
  }
}

/** Cheap binary check: NUL byte inside the first chunk => not text. */
async function readText(absPath) {
  let buf;
  try {
    buf = await fsp.readFile(absPath);
  } catch {
    return null;
  }
  if (buf.subarray(0, Math.min(buf.length, 1024)).includes(0)) return null;
  return buf.toString("utf8");
}

/* ------------------------------------------------------------------ */
/* secrets.ts — identical rules, severities lowercased                 */
/* ------------------------------------------------------------------ */

const SECRET_RULES = [
  {
    kind: "secret/aws-access-key",
    severity: "critical",
    note: "AWS access key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    kind: "secret/github-token",
    severity: "critical",
    note: "GitHub personal access token",
    pattern: /\b(?:github_pat_[A-Za-z0-9_]{22,}|gh[pousr]_[A-Za-z0-9]{20,})\b/,
  },
  {
    kind: "secret/private-key",
    severity: "critical",
    note: "Private key material",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
  },
  {
    kind: "secret/openai-api-key",
    severity: "high",
    note: "OpenAI-style API key (sk-…)",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    kind: "secret/generic-credential",
    severity: "high",
    note: "Hard-coded credential in source",
    pattern:
      /(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["'`][^"'`\n]{20,}["'`]/i,
  },
];

/* ------------------------------------------------------------------ */
/* hygiene.ts — identical rules, severities lowercased                 */
/* ------------------------------------------------------------------ */

const CODE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]);

const DEBUG_RE = /\bDEBUG\b\s*[:=]\s*["'`]?true\b/;
const CORS_STAR_RE = /\bcors\s*\(\s*\{[^}\n]*\borigin\s*:\s*["'`]\*["'`]/;
const CORS_BARE_RE = /\b(?:use|all)\s*\(\s*cors\s*\(\s*\)/;

function extOf(name) {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i).toLowerCase();
}

function isEnvFile(name) {
  const base = path.basename(name);
  if (base === ".env") return true;
  if (/^\.env\..+/.test(base)) {
    // .env.example / .env.sample / .env.template are docs, not secrets
    return !/^\.env\.(example|sample|template|dist)$/i.test(base);
  }
  return false;
}

function gitignoreCoversEnv(lines) {
  return lines.some((raw) => {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) return false;
    const pat = line.replace(/^\//, "").replace(/\/$/, "");
    return (
      pat === ".env" ||
      pat === ".env.*" ||
      pat === "*.env" ||
      pat === ".env*" ||
      pat === "**/.env" ||
      pat === "**/.env*" ||
      pat === "**/*.env"
    );
  });
}

async function exists(p) {
  try {
    await fsp.access(p);
    return true;
  } catch {
    return false;
  }
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Scan a project directory for committed secrets and hygiene gaps.
 * Never throws — failures return an `error` field on the result.
 *
 * @param {string} dir
 * @param {{maxFiles?: number}} [opts]
 * @returns {Promise<{scanned:number, truncated:boolean,
 *   findings:{severity:string,kind:string,path:string,line?:number,note:string}[],
 *   error?:string}>}
 */
async function scanPath(dir, opts = {}) {
  try {
    if (typeof dir !== "string" || !dir.trim()) {
      return {
        scanned: 0,
        truncated: false,
        findings: [],
        error: "dir must be a non-empty path",
      };
    }
    const maxFiles =
      Number.isFinite(opts.maxFiles) && opts.maxFiles >= 1
        ? Math.floor(opts.maxFiles)
        : DEFAULT_MAX_FILES;

    const rootAbs = path.resolve(dir);
    let st;
    try {
      st = await fsp.stat(rootAbs);
    } catch (e) {
      return {
        scanned: 0,
        truncated: false,
        findings: [],
        error:
          e && e.code === "ENOENT"
            ? "path does not exist"
            : `path unavailable (${(e && e.code) || "error"})`,
      };
    }
    if (!st.isDirectory()) {
      return {
        scanned: 0,
        truncated: false,
        findings: [],
        error: "not a directory",
      };
    }

    const rootReal = (await realpathOrNull(rootAbs)) || rootAbs;
    const { files, truncated } = await walkProject(rootAbs, rootReal, maxFiles);

    const secretFindings = [];
    const hygieneFindings = [];

    // --- hygiene pass 1: committed .env files -----------------------------
    const envFiles = files.filter((f) => isEnvFile(f.relPath));
    for (const f of envFiles) {
      hygieneFindings.push({
        severity: "high",
        kind: "hygiene/dotenv-committed",
        path: f.relPath,
        note: "Environment file committed to the repo — may contain secrets",
      });
    }

    // --- hygiene pass 2: .gitignore missing a .env entry ------------------
    const gitignore = files.find((f) => path.basename(f.relPath) === ".gitignore");
    const gitignoreText = gitignore ? await readText(gitignore.absPath) : null;
    const coversEnv = gitignoreCoversEnv(gitignoreText === null ? [] : gitignoreText.split("\n"));
    if (
      !coversEnv &&
      (envFiles.length > 0 || (await exists(path.join(rootAbs, ".git"))) || gitignore)
    ) {
      hygieneFindings.push({
        severity: "medium",
        kind: "hygiene/gitignore-missing-env",
        path: gitignore ? gitignore.relPath : ".gitignore",
        note: ".gitignore does not exclude .env files",
      });
    }

    // --- per-file text scans (secrets on all text; DEBUG/CORS on code) ----
    for (let i = 0; i < files.length; i += READ_CONCURRENCY) {
      const chunk = files.slice(i, i + READ_CONCURRENCY);
      const texts = await Promise.all(chunk.map((f) => readText(f.absPath)));
      for (let j = 0; j < chunk.length; j++) {
        const text = texts[j];
        if (text === null) continue;
        const file = chunk[j];
        const lines = text.split("\n");

        for (const rule of SECRET_RULES) {
          let hits = 0;
          for (let li = 0; li < lines.length; li++) {
            rule.pattern.lastIndex = 0;
            if (!rule.pattern.test(lines[li])) continue;
            secretFindings.push({
              severity: rule.severity,
              kind: rule.kind,
              path: file.relPath,
              line: li + 1,
              note: rule.note,
            });
            if (++hits >= MAX_PER_RULE_PER_FILE) break;
          }
        }

        const isCode = CODE_EXTS.has(extOf(file.relPath));
        const isEnv = isEnvFile(file.relPath);
        if (!isCode && !isEnv) continue;
        for (let li = 0; li < lines.length; li++) {
          const line = lines[li];
          if (DEBUG_RE.test(line)) {
            hygieneFindings.push({
              severity: "medium",
              kind: "hygiene/debug-enabled",
              path: file.relPath,
              line: li + 1,
              note: "DEBUG=true left enabled",
            });
          }
          if (isCode && (CORS_STAR_RE.test(line) || CORS_BARE_RE.test(line))) {
            hygieneFindings.push({
              severity: "medium",
              kind: "hygiene/cors-wildcard",
              path: file.relPath,
              line: li + 1,
              note: "Permissive CORS configuration (any origin)",
            });
          }
        }
      }
    }

    // CLI order is secrets → deps → hygiene; deps is omitted (network).
    const findings = [...secretFindings, ...hygieneFindings];
    findings.sort((a, b) => (SEV_RANK[a.severity] ?? 4) - (SEV_RANK[b.severity] ?? 4));

    return {
      scanned: files.length,
      truncated,
      findings: findings.slice(0, MAX_FINDINGS),
    };
  } catch (e) {
    // Last-resort guard — scanPath must never reject into the IPC layer.
    return {
      scanned: 0,
      truncated: false,
      findings: [],
      error: `scan failed (${(e && e.code) || (e && e.message) || "error"})`,
    };
  }
}

module.exports = { scanPath, resolveScanDir };
