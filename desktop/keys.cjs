"use strict";
/**
 * RootWatch desktop — credential posture (API keys on this host).
 *
 * Zero-dependency CommonJS port of server/services/keyscan.ts — the
 * canonical implementation. Same RULES table, KNOWN_FILES, SHELL_RC,
 * HISTORY_FILES, SKIP_DIRS, bounded .env* walk under the project roots,
 * ~/.ssh private-key detection (wholeFile → hash content), the same-uid
 * /proc/<pid>/environ pass on Linux, extractSpecial
 * (.git-credentials/.netrc/docker config.json), and git committed /
 * check-ignore flags via execFileSync. Records carry
 * sha256(value) fingerprint + last4 + home-relative ("~/…") locations —
 * a secret value NEVER appears in scan output, report payloads, logs, or
 * IPC responses.
 *
 * Safety contract (same as scan.cjs): this module never throws. Bad
 * input or a failed probe yields an empty result, null, or an honest
 * {status:'refused'|'failed', message} object — never an exception.
 *
 * Desktop-only additions over the scanner:
 *  - listKeys({force}) — 5min cached scan (it runs on a 60s report tick)
 *  - vault — safeStorage-sealed ciphertext persisted via db.cjs;
 *    vaultList() exposes metadata only, vaultGet() unseals for the
 *    probe/contain paths and its result never crosses a boundary
 *  - containKey() — seal into the vault, then (unless copy) strip the
 *    secret line from its source file
 *  - probeKey() — provider liveness check via fetch; the value is used
 *    as a request credential and is never returned or logged
 */

const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  statSync,
  writeFileSync,
} = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const MAX_FILE_BYTES = 512 * 1024;
const MAX_PROJECT_FILES = 400;
const MAX_ENV_WALK_DEPTH = 4;
const MAX_FINDINGS = 500;
const LIST_TTL_MS = 5 * 60 * 1000;
const PROBE_TIMEOUT_MS = 10_000;
const CONTAIN_STUB = "# contained by rootwatch";

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
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
  "snap",
  ".cargo",
  ".rustup",
  ".npm",
  ".local",
]);

// Provider-tagged, high-precision patterns — the gitleaks top ~25. Keep in
// sync with server/services/keyscan.ts and cli/src/scan/keyscan.ts.
const RULES = [
  {
    ruleId: "key/aws-access-key-id",
    provider: "aws",
    kind: "api-key",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    ruleId: "key/aws-secret",
    provider: "aws",
    kind: "api-key",
    pattern: /aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})/i,
  },
  {
    ruleId: "key/github-pat",
    provider: "github",
    kind: "token",
    pattern: /\b(?:github_pat_[A-Za-z0-9_]{22,}|gh[pousr]_[A-Za-z0-9]{20,})\b/,
  },
  {
    ruleId: "key/gitlab-pat",
    provider: "gitlab",
    kind: "token",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "key/stripe-secret",
    provider: "stripe",
    kind: "api-key",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  },
  {
    ruleId: "key/stripe-webhook",
    provider: "stripe",
    kind: "token",
    pattern: /\bwhsec_[A-Za-z0-9]{16,}\b/,
  },
  // Specific sk- prefixes MUST precede the generic openai rule — first
  // match claims the fingerprint's provider (and its probe adapter).
  {
    ruleId: "key/anthropic",
    provider: "anthropic",
    kind: "api-key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "key/openrouter",
    provider: "openrouter",
    kind: "api-key",
    pattern: /\bsk-or-v1-[0-9a-zA-Z]{32,}\b/,
  },
  {
    ruleId: "key/openai",
    provider: "openai",
    kind: "api-key",
    pattern: /\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "key/google-api",
    provider: "google",
    kind: "api-key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    ruleId: "key/slack",
    provider: "slack",
    kind: "token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  { ruleId: "key/npm", provider: "npm", kind: "token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { ruleId: "key/pypi", provider: "pypi", kind: "token", pattern: /\bpypi-[A-Za-z0-9_-]{20,}\b/ },
  {
    ruleId: "key/sendgrid",
    provider: "sendgrid",
    kind: "api-key",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
  },
  { ruleId: "key/twilio", provider: "twilio", kind: "api-key", pattern: /\bSK[0-9a-f]{32}\b/ },
  {
    ruleId: "key/square",
    provider: "square",
    kind: "token",
    pattern: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "key/digitalocean",
    provider: "digitalocean",
    kind: "token",
    pattern: /\bdop_v1_[0-9a-f]{64}\b/,
  },
  {
    ruleId: "key/linear",
    provider: "linear",
    kind: "api-key",
    pattern: /\blin_api_[A-Za-z0-9]{30,}\b/,
  },
  {
    ruleId: "key/discord",
    provider: "discord",
    kind: "token",
    pattern: /\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{20,}\b/,
  },
  {
    ruleId: "key/heroku",
    provider: "heroku",
    kind: "api-key",
    pattern:
      /\b(?:HEROKU[A-Z0-9_]*)\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/,
  },
  {
    ruleId: "key/env-assignment",
    provider: null,
    kind: "token",
    pattern:
      /\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)\s*=\s*["']?([^\s"'`;#]{12,})/,
  },
  {
    ruleId: "key/generic-credential",
    provider: null,
    kind: "password",
    pattern:
      /(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["'`]([^"'`\n]{16,})["'`]/i,
  },
];

const PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/;

const KNOWN_FILES = [
  { rel: ".aws/credentials", provider: "aws", label: "aws-credentials" },
  { rel: ".aws/config", provider: "aws" },
  { rel: ".netrc", kind: "password", label: "netrc" },
  { rel: ".git-credentials", kind: "password", label: "git-credentials" },
  { rel: ".docker/config.json", provider: "docker", label: "docker-auths" },
  { rel: ".kube/config", provider: "kubernetes", label: "kubeconfig" },
  { rel: ".npmrc", provider: "npm", label: "npmrc" },
  { rel: ".yarnrc.yml", provider: "npm" },
  { rel: ".pypirc", provider: "pypi", label: "pypirc" },
  { rel: ".gem/credentials", provider: "rubygems", label: "gem-credentials" },
  { rel: ".cargo/credentials.toml", provider: "crates", label: "cargo-credentials" },
  { rel: ".config/gh/hosts.yml", provider: "github", label: "gh-cli" },
  { rel: ".config/hub", provider: "github", label: "hub-cli" },
  { rel: ".config/stripe/config.toml", provider: "stripe", label: "stripe-cli" },
  { rel: ".config/vercel/auth.json", provider: "vercel", label: "vercel-cli" },
  { rel: ".config/netlify/config.json", provider: "netlify" },
  {
    rel: ".config/gcloud/application_default_credentials.json",
    provider: "gcloud",
    label: "gcloud-adc",
  },
  { rel: ".azure/accessTokens.json", provider: "azure", label: "azure-cli" },
  { rel: ".openai", provider: "openai" },
  { rel: ".anthropic", provider: "anthropic" },
  { rel: ".env", label: "dotenv" },
  { rel: ".env.local", label: "dotenv" },
];

const SHELL_RC = [".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"];
const HISTORY_FILES = [".bash_history", ".zsh_history"];
const SSH_DIR = ".ssh";

const DEFAULT_PROJECT_ROOTS = [
  "Development",
  "code",
  "projects",
  "src",
  "work",
  "repos",
  "dev",
  "devops",
];

const ENV_NAME_RE = /^[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*$/;

// The label ("OPENROUTER_API_KEY") often identifies the provider when the
// value's shape doesn't. Fills provider only where rules left it null.
const LABEL_PROVIDER = [
  [/anthropic|claude/i, "anthropic"],
  [/openrouter/i, "openrouter"],
  [/openai/i, "openai"],
  [/stripe/i, "stripe"],
  [/github/i, "github"],
  [/gitlab/i, "gitlab"],
  [/aws|amazon/i, "aws"],
  [/gemini|google/i, "google"],
  [/slack/i, "slack"],
  [/sendgrid/i, "sendgrid"],
  [/twilio/i, "twilio"],
  [/digital_?ocean|digitalocean/i, "digitalocean"],
  [/linear/i, "linear"],
  [/discord/i, "discord"],
  [/heroku/i, "heroku"],
  [/npm/i, "npm"],
  [/pypi/i, "pypi"],
  [/resend/i, "resend"],
  [/replicate/i, "replicate"],
  [/vercel/i, "vercel"],
  [/netlify/i, "netlify"],
  [/supabase/i, "supabase"],
];

function providerFromLabel(label) {
  if (!label) return null;
  for (const [re, p] of LABEL_PROVIDER) if (re.test(label)) return p;
  return null;
}

// ---------------------------------------------------------------------------

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

function homeRel(abs, home) {
  if (abs === home) return "~";
  return abs.startsWith(home + path.sep) ? `~${abs.slice(home.length)}` : abs;
}

/** Expand ~/… or bare-relative extra paths against home. */
function resolveExtra(p, home) {
  if (p.startsWith("~/")) return path.join(home, p.slice(2));
  if (path.isAbsolute(p)) return p;
  return path.join(home, p);
}

function readText(abs) {
  try {
    const st = statSync(abs);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    const buf = readFileSync(abs);
    if (buf.subarray(0, Math.min(buf.length, 1024)).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function permOf(abs) {
  try {
    return (statSync(abs).mode & 0o777).toString(8).padStart(4, "0");
  } catch {
    return undefined;
  }
}

function matchValue(m) {
  // env-assignment rule: group1=NAME group2=value; other rules group1=value
  // or whole match.
  if (m.length >= 3 && m[1] && m[2]) return { value: m[2], label: m[1], prefer: true };
  return { value: m[1] ?? m[0], label: null, prefer: false };
}

function extractFromText(text, fileProvider, fileLabel) {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      const m = line.match(rule.pattern);
      if (!m) continue;
      const { value, label, prefer } = matchValue(m);
      if (value.length < 8) continue;
      out.push({
        value: value.trim(),
        provider: rule.provider ?? fileProvider,
        kind: rule.kind,
        label: label ?? fileLabel,
        preferLabel: prefer,
        line: i + 1,
      });
    }
  }
  return out;
}

/** Format-specific extractors for files the regex rules can't cover. */
function extractSpecial(abs, rel, text) {
  const out = [];
  const base = path.basename(rel);

  if (base === ".git-credentials") {
    // https://user:token@host lines
    for (const m of text.matchAll(/^[a-z]+:\/\/([^:\s]+):([^@\s]+)@/gim)) {
      out.push({
        value: m[2],
        provider: "git",
        kind: "password",
        label: `git-credentials:${m[1]}`,
      });
    }
  } else if (base === ".netrc") {
    for (const m of text.matchAll(/\bpassword\s+(\S+)/g)) {
      out.push({ value: m[1], provider: null, kind: "password", label: "netrc" });
    }
  } else if (base === "config.json" && rel.includes(".docker")) {
    try {
      const j = JSON.parse(text);
      for (const [registry, entry] of Object.entries(j.auths ?? {})) {
        const decoded = entry?.auth ? Buffer.from(entry.auth, "base64").toString("utf8") : "";
        const secret = decoded.split(":")[1];
        if (secret && secret.length >= 8) {
          out.push({
            value: secret,
            provider: "docker",
            kind: "password",
            label: `docker:${registry}`,
          });
        }
      }
    } catch {
      /* not json — rules already ran */
    }
  }
  return out;
}

/** Whole-file credentials (private keys under ~/.ssh, *.pem). */
function isPrivateKeyFile(abs, rel) {
  const prefix = `~/${SSH_DIR}/`; // rel is home-relative
  if (!rel.startsWith(prefix)) return false;
  if (rel.endsWith(".pub") || rel.includes("known_hosts") || rel === `${prefix}config`)
    return false;
  const text = readText(abs);
  return text !== null && PRIVATE_KEY_RE.test(text);
}

// -- git posture ------------------------------------------------------------

const repoRootCache = new Map();
function repoRootFor(abs) {
  let dir = path.dirname(abs);
  for (;;) {
    if (repoRootCache.has(dir)) return repoRootCache.get(dir);
    if (existsSync(path.join(dir, ".git"))) {
      repoRootCache.set(dir, dir);
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      repoRootCache.set(dir, null);
      return null;
    }
    dir = parent;
  }
}

function git(abs, root, args) {
  try {
    execFileSync("git", ["-C", root, ...args, "--", abs], {
      stdio: "ignore",
      timeout: 5_000,
    });
    return true;
  } catch {
    return false;
  }
}

// -- file collection ---------------------------------------------------------

function collectFiles(opts) {
  const home = opts.homeDir;
  const files = [];
  const history = [];
  const seen = new Set();

  const add = (abs, via, known, intoHistory = false) => {
    if (seen.has(abs)) return;
    try {
      if (!statSync(abs).isFile()) return;
    } catch {
      return;
    }
    seen.add(abs);
    (intoHistory ? history : files).push({
      abs,
      rel: homeRel(abs, home),
      known,
      via,
    });
  };

  for (const k of KNOWN_FILES) add(path.join(home, k.rel), "known-file", k);
  for (const rc of SHELL_RC) add(path.join(home, rc), "shell-rc");
  for (const h of HISTORY_FILES) add(path.join(home, h), "history", undefined, true);

  // ~/.ssh private keys — every regular file that contains a PEM header.
  const sshDir = path.join(home, SSH_DIR);
  try {
    for (const name of readdirSync(sshDir)) {
      const abs = path.join(sshDir, name);
      const rel = homeRel(abs, home);
      try {
        if (statSync(abs).isFile() && isPrivateKeyFile(abs, rel)) {
          add(abs, "known-file", {
            rel,
            kind: "private-key",
            label: name,
            wholeFile: true,
          });
        }
      } catch {
        /* unreadable entry — skip */
      }
    }
  } catch {
    /* no ~/.ssh */
  }

  // Bounded .env* walk under project roots.
  const roots = opts.projectRoots ?? DEFAULT_PROJECT_ROOTS;
  let walked = 0;
  const walk = (dir, depth) => {
    if (depth > MAX_ENV_WALK_DEPTH || walked >= MAX_PROJECT_FILES) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (walked >= MAX_PROJECT_FILES) return;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) walk(abs, depth + 1);
      } else if (e.isFile() && /^\.env(\..+)?$/.test(e.name)) {
        try {
          if (lstatSync(abs).isSymbolicLink()) continue;
        } catch {
          continue;
        }
        walked++;
        add(abs, "file", { rel: homeRel(abs, home), label: "dotenv" });
      }
    }
  };
  for (const r of roots) walk(path.join(home, r), 0);

  // User-configured extra paths (files or dirs — dirs walked shallow).
  for (const extra of opts.extraPaths ?? []) {
    const abs = resolveExtra(extra, home);
    try {
      if (statSync(abs).isDirectory()) {
        for (const e of readdirSync(abs, { withFileTypes: true })) {
          if (e.isFile() && walked < MAX_PROJECT_FILES) {
            walked++;
            add(path.join(abs, e.name), "file");
          }
        }
      } else {
        add(abs, "file");
      }
    } catch {
      /* missing extra path — not an error */
    }
  }

  return { files, history };
}

// -- /proc/*/environ ---------------------------------------------------------

function procEnvCandidates() {
  const out = [];
  const uid = typeof process.getuid === "function" ? process.getuid() : -1;
  let pids;
  try {
    pids = readdirSync("/proc").filter((d) => /^\d+$/.test(d));
  } catch {
    return out; // non-Linux
  }
  for (const pid of pids) {
    const environ = `/proc/${pid}/environ`;
    try {
      if (statSync(`/proc/${pid}`).uid !== uid) continue; // same-uid only
      const raw = readFileSync(environ);
      let comm = "";
      try {
        comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
      } catch {
        /* process exited */
      }
      for (const entry of raw.toString("utf8").split("\0")) {
        const eq = entry.indexOf("=");
        if (eq <= 0) continue;
        const name = entry.slice(0, eq);
        const value = entry.slice(eq + 1);
        if (!value || value.length < 8) continue;
        const named = ENV_NAME_RE.test(name);
        const matched = RULES.find((r) => {
          r.pattern.lastIndex = 0;
          return r.pattern.test(value);
        });
        if (!named && !matched) continue;
        out.push({
          cand: {
            value: value.trim(),
            provider: matched?.provider ?? null,
            kind: matched?.kind ?? "token",
            label: name,
          },
          loc: {
            path: `/proc/${pid}/environ`,
            exposedVia: "proc-env",
            proc: comm || undefined,
          },
        });
      }
    } catch {
      /* unreadable/gone — skip */
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

/**
 * Scan the host for visible credentials. Returns deduped records keyed by
 * sha256 fingerprint — secret values never appear in the output.
 * (Port of server/services/keyscan.ts scanHostKeys.)
 */
async function scanKeys(opts = {}) {
  const home = opts.homeDir ?? os.homedir();
  const { files, history } = collectFiles({ ...opts, homeDir: home });
  const byFp = new Map();

  const ingest = (cand, loc, extraFlags = {}) => {
    const value = cand.value.trim();
    if (value.length < 8 || byFp.size >= MAX_FINDINGS) return;
    const fp = sha256(value);
    let rec = byFp.get(fp);
    if (!rec) {
      rec = {
        fingerprint: fp,
        provider: cand.provider,
        kind: cand.kind,
        label: cand.label,
        last4: value.slice(-4),
        locations: [],
        flags: {},
      };
      byFp.set(fp, rec);
    }
    if (cand.label && (cand.preferLabel || !rec.label)) rec.label = cand.label;
    if (!rec.provider && cand.provider) rec.provider = cand.provider;
    if (!rec.locations.some((l) => l.path === loc.path && l.line === loc.line)) {
      rec.locations.push(loc);
    }
    Object.assign(rec.flags, extraFlags);
  };

  for (const f of files) {
    const perm = permOf(f.abs);
    const locBase = { path: f.rel, perm, exposedVia: f.via };

    const flags = {};
    if (perm && (parseInt(perm, 8) & 0o077) !== 0) flags.worldReadable = true;
    const repo = repoRootFor(f.abs);
    if (repo) {
      if (git(f.abs, repo, ["ls-files", "--error-unmatch"])) flags.committed = true;
      else if (git(f.abs, repo, ["check-ignore", "-q"])) flags.gitignored = true;
    }
    if (opts.listenerCwds) {
      for (const l of opts.listenerCwds) {
        if (f.abs === l.cwd || f.abs.startsWith(l.cwd + path.sep)) {
          flags.served = l.name;
          break;
        }
      }
    }

    if (f.known?.wholeFile) {
      const text = readText(f.abs);
      if (text) {
        ingest(
          {
            value: text.trim(),
            provider: f.known.provider ?? null,
            kind: "private-key",
            label: f.known.label ?? path.basename(f.rel),
          },
          locBase,
          flags,
        );
      }
      continue;
    }

    const text = readText(f.abs);
    if (text === null) continue;
    const cands = extractFromText(text, f.known?.provider ?? null, f.known?.label ?? null).concat(
      extractSpecial(f.abs, f.rel, text),
    );

    for (const cand of cands) {
      ingest(cand, { ...locBase, line: cand.line }, flags);
    }
  }

  // History pass — same fingerprint found here ⇒ leakedToHistory on the rec.
  const historyFps = new Set();
  for (const f of history) {
    const text = readText(f.abs);
    if (text === null) continue;
    for (const cand of extractFromText(text, null, null)) {
      const fp = sha256(cand.value.trim());
      historyFps.add(fp);
      // A key that only exists in history is still worth recording.
      ingest(cand, { path: f.rel, line: cand.line, exposedVia: "history" });
    }
  }
  for (const fp of historyFps) {
    const rec = byFp.get(fp);
    if (rec) rec.flags.leakedToHistory = true;
  }

  // Live evidence — same-uid process environments.
  if (!opts.skipProcEnv) {
    for (const { cand, loc } of procEnvCandidates()) ingest(cand, loc);
  }

  // Provider hints from the label fill what value-shape couldn't resolve.
  byFp.forEach((rec) => {
    if (!rec.provider) rec.provider = providerFromLabel(rec.label);
  });

  return [...byFp.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}

/**
 * Re-read the given locations and return the plaintext matching one
 * fingerprint. LOCAL USE ONLY (containment/probe) — the returned value must
 * never cross an API boundary, reach a log, or be persisted unsealed.
 */
async function recoverSecret(fingerprint, locations, opts = {}) {
  try {
    const home = opts.homeDir ?? os.homedir();
    for (const loc of Array.isArray(locations) ? locations : []) {
      const abs = loc.path.startsWith("~/") ? path.join(home, loc.path.slice(2)) : loc.path;
      const cands = [];
      if (loc.exposedVia === "proc-env") {
        try {
          const raw = readFileSync(abs).toString("utf8");
          for (const entry of raw.split("\0")) {
            const eq = entry.indexOf("=");
            if (eq <= 0) continue;
            const value = entry.slice(eq + 1);
            if (value.length >= 8) {
              cands.push({ value, provider: null, kind: "token", label: entry.slice(0, eq) });
            }
          }
        } catch {
          /* process gone */
        }
      } else {
        const text = readText(abs);
        if (text === null) continue;
        if (PRIVATE_KEY_RE.test(text)) {
          cands.push({ value: text.trim(), provider: null, kind: "private-key", label: null });
        } else {
          cands.push(...extractFromText(text, null, null), ...extractSpecial(abs, loc.path, text));
        }
      }
      for (const c of cands) {
        const value = c.value.trim();
        if (sha256(value) === fingerprint) return { value, location: loc };
      }
    }
    return null;
  } catch {
    return null; // never throw
  }
}

// ---------------------------------------------------------------------------
// Cached listing + listener-cwd correlation ('served' flag)
// ---------------------------------------------------------------------------

let listCache = null; // { at, records } — default-scan only
let lastError = null;

/** cwds of same-uid listening processes → 'served' correlation. Linux only;
 *  anywhere else (or if the collector can't load) the flag is simply unset. */
async function defaultListenerCwds() {
  if (process.platform !== "linux") return [];
  try {
    const collector = require("./collector.cjs");
    const listeners = await collector.collectListeners({ force: false });
    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    const out = [];
    for (const l of Array.isArray(listeners) ? listeners : []) {
      const pid = l?.pid;
      if (!Number.isInteger(pid) || pid <= 1) continue;
      try {
        if (statSync(`/proc/${pid}`).uid !== uid) continue;
        const cwd = readlinkSync(`/proc/${pid}/cwd`);
        if (cwd && !cwd.endsWith(" (deleted)")) {
          out.push({ cwd, name: l.name ?? `pid ${pid}` });
        }
      } catch {
        /* process gone or foreign uid */
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Cached scan — 5min TTL since it runs on the 60s report tick. Options
 * ({homeDir, projectRoots, extraPaths, skipProcEnv, listenerCwds}) are a
 * test/embedding seam: any explicit scan option bypasses the cache.
 * Never throws — a failed scan returns [] with lastScanError() set.
 */
async function listKeys(opts = {}) {
  const defaulted =
    opts.homeDir === undefined &&
    opts.projectRoots === undefined &&
    opts.extraPaths === undefined &&
    opts.skipProcEnv === undefined &&
    opts.listenerCwds === undefined;
  if (defaulted && listCache && !opts.force && Date.now() - listCache.at < LIST_TTL_MS) {
    return listCache.records;
  }
  try {
    const listenerCwds = opts.listenerCwds ?? (await defaultListenerCwds());
    const records = await scanKeys({ ...opts, listenerCwds });
    lastError = null;
    if (defaulted) listCache = { at: Date.now(), records };
    return records;
  } catch (err) {
    lastError = err?.message ?? String(err);
    return [];
  }
}

function lastScanError() {
  return lastError;
}

/** Report-bound projection: truncated fingerprint, no absolute home paths,
 *  no secret material — what report.keys.items[] carries (≤ limit items). */
function reportItems(records, limit = 100) {
  return (Array.isArray(records) ? records : []).slice(0, limit).map((r) => ({
    fp: typeof r?.fingerprint === "string" ? r.fingerprint.slice(0, 12) : null,
    provider: r?.provider ?? null,
    kind: r?.kind ?? null,
    label: r?.label ?? null,
    last4: r?.last4 ?? null,
    locations: Array.isArray(r?.locations) ? r.locations : [],
    flags: r?.flags ?? {},
  }));
}

// ---------------------------------------------------------------------------
// Vault — safeStorage-sealed ciphertext persisted via db.cjs. The plaintext
// exists only inside seal/unseal calls; vaultList() is metadata-only.
// ---------------------------------------------------------------------------

function safeStorageOrNull() {
  try {
    const ss = require("electron")?.safeStorage;
    if (
      ss &&
      typeof ss.encryptString === "function" &&
      typeof ss.decryptString === "function" &&
      ss.isEncryptionAvailable()
    ) {
      return ss;
    }
  } catch {
    /* not an Electron runtime (tests) or no keychain */
  }
  return null;
}

async function vaultSeal(fingerprint, value, meta = {}) {
  const ss = safeStorageOrNull();
  if (!ss) {
    return {
      status: "refused",
      message: "OS keychain unavailable — safeStorage cannot seal on this system",
    };
  }
  if (typeof value !== "string" || value.length === 0) {
    return { status: "refused", message: "no secret value to seal" };
  }
  try {
    const sealed = ss.encryptString(value).toString("base64");
    await require("./db.cjs").vaultPut({
      fingerprint,
      sealed,
      label: meta.label ?? null,
      provider: meta.provider ?? null,
    });
    return { status: "sealed" };
  } catch (err) {
    return { status: "failed", message: err?.message ?? "vault write failed" };
  }
}

/** Unseal for probe/contain internals — the value never leaves this module. */
async function vaultGet(fingerprint) {
  const ss = safeStorageOrNull();
  if (!ss) return null;
  try {
    const row = await require("./db.cjs").vaultGet(fingerprint);
    if (!row?.sealed) return null;
    try {
      return {
        value: ss.decryptString(Buffer.from(row.sealed, "base64")),
        label: row.label ?? null,
        provider: row.provider ?? null,
      };
    } catch {
      return { value: null, error: "vault entry present but unseal failed" };
    }
  } catch {
    return null;
  }
}

/** Metadata only — fingerprints/labels/providers/timestamps, never sealed. */
async function vaultList() {
  try {
    return await require("./db.cjs").vaultList();
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Contain — seal the secret into the vault, then (unless copy) strip it from
// its source file. Whole-file credentials (private keys) and proc-env
// locations can't be rewritten — those refuse honestly; copy still seals.
// ---------------------------------------------------------------------------

const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

async function containKey(fingerprint, { copy = false, scanOpts = null } = {}) {
  if (typeof fingerprint !== "string" || !FINGERPRINT_RE.test(fingerprint)) {
    return { status: "refused", message: "invalid fingerprint" };
  }
  try {
    const records = await listKeys({ force: true, ...(scanOpts ?? {}) });
    const rec = records.find((r) => r.fingerprint === fingerprint);
    if (!rec) return { status: "failed", message: "key not found in the current scan" };

    const recovered = await recoverSecret(
      fingerprint,
      rec.locations,
      scanOpts?.homeDir ? { homeDir: scanOpts.homeDir } : {},
    );
    if (!recovered?.value) {
      return {
        status: "failed",
        message: "secret could not be re-read from its recorded locations",
      };
    }

    // Non-rewriteable carriers — the file path can't be "cleaned" for these.
    let copyOnlyReason = null;
    if (rec.kind === "private-key") {
      copyOnlyReason =
        "private key is a whole-file credential — sealing copies only; remove the file yourself";
    } else if (recovered.location.exposedVia === "proc-env") {
      copyOnlyReason =
        `secret lives in a process environment (${recovered.location.path}) — ` +
        "sealing copies only; unset the env var and restart the process";
    }
    if (!copy && copyOnlyReason) return { status: "refused", message: copyOnlyReason };

    // Seal BEFORE touching the file — a failed rewrite still leaves the
    // secret recoverable from the vault.
    const sealed = await vaultSeal(fingerprint, recovered.value, {
      label: rec.label,
      provider: rec.provider,
    });
    if (sealed.status !== "sealed") return sealed; // refused or failed honestly

    if (copy) {
      return {
        status: "contained",
        message: "sealed into the vault; source left untouched",
      };
    }

    const loc = recovered.location;
    const abs = loc.path.startsWith("~/") ? path.join(os.homedir(), loc.path.slice(2)) : loc.path;
    try {
      const text = readFileSync(abs, "utf8");
      let touched = 0;
      const next = text
        .split("\n")
        .map((l) => (l.includes(recovered.value) ? (touched++, CONTAIN_STUB) : l))
        .join("\n");
      if (!touched) {
        return {
          status: "failed",
          message: "sealed into the vault, but the source line was not found for rewriting",
        };
      }
      writeFileSync(abs, next); // existing mode is preserved (no truncate+chmod)
      return {
        status: "contained",
        message: `sealed into the vault; removed from ${loc.path}`,
      };
    } catch (err) {
      return {
        status: "failed",
        message: `sealed into the vault, but rewriting ${loc.path} failed: ${err?.message ?? err}`,
      };
    }
  } catch (err) {
    return { status: "failed", message: err?.message ?? String(err) };
  }
}

// ---------------------------------------------------------------------------
// Probe — provider liveness adapters. The value goes into a request header
// and nowhere else; results carry live/detail/scopes/balance, never the key.
// ---------------------------------------------------------------------------

const PROBE_HEADERS = { "User-Agent": "rootwatch-desktop" };

async function probeProvider(provider, value) {
  const rejected = (res) => ({ live: false, detail: `rejected (HTTP ${res.status})` });
  const httpVerdict = (res) =>
    res.status === 401 || res.status === 403
      ? rejected(res)
      : res.ok
        ? null // fall through to the adapter's success payload
        : { live: null, detail: `HTTP ${res.status}` };
  const opts = (headers) => ({
    headers: { ...PROBE_HEADERS, ...headers },
    signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
  });
  try {
    switch (provider) {
      case "github": {
        const res = await fetch(
          "https://api.github.com/user",
          opts({ Authorization: `Bearer ${value}`, Accept: "application/vnd.github+json" }),
        );
        const v = httpVerdict(res);
        if (v) return v;
        const scopes = res.headers.get("x-oauth-scopes");
        // fine-grained PATs carry a real expiry date in a response header
        const expiry = res.headers.get("github-authentication-token-expiration");
        return {
          live: true,
          detail: `token accepted${expiry ? ` — expires ${expiry.split(" ")[0]}` : ""}`,
          scopes: scopes || undefined,
        };
      }
      case "openrouter": {
        const res = await fetch(
          "https://openrouter.ai/api/v1/auth/key",
          opts({ Authorization: `Bearer ${value}` }),
        );
        const v = httpVerdict(res);
        if (v) return v;
        const body = await res.json().catch(() => null);
        const d = body?.data;
        const balance =
          d && typeof d.usage === "number"
            ? `${d.usage} used${d.limit != null ? ` / ${d.limit} limit` : ""} credits`
            : undefined;
        return { live: true, detail: "key accepted", balance };
      }
      case "stripe": {
        // whsec_ secrets sign webhooks — they never authenticate API calls.
        if (value.startsWith("whsec_")) {
          return { live: null, detail: "webhook signing secret — not an API credential" };
        }
        // pk_ keys are publishable — /v1/balance 401s on them by design.
        if (/^pk_(live|test)_/.test(value)) {
          return { live: null, detail: "publishable key — not probeable" };
        }
        const res = await fetch(
          "https://api.stripe.com/v1/balance",
          opts({ Authorization: `Bearer ${value}` }),
        );
        const v = httpVerdict(res);
        if (v) return v;
        const body = await res.json().catch(() => null);
        const avail = body?.available?.[0];
        return {
          live: true,
          detail: "key accepted",
          balance: avail
            ? `${(avail.amount / 100).toFixed(2)} ${String(avail.currency ?? "").toUpperCase()}`
            : undefined,
        };
      }
      case "openai": {
        const res = await fetch(
          "https://api.openai.com/v1/models",
          opts({ Authorization: `Bearer ${value}` }),
        );
        const v = httpVerdict(res);
        if (v) return v;
        return { live: true, detail: "key accepted" };
      }
      case "anthropic": {
        const res = await fetch(
          "https://api.anthropic.com/v1/models",
          opts({ "x-api-key": value, "anthropic-version": "2023-06-01" }),
        );
        const v = httpVerdict(res);
        if (v) return v;
        return { live: true, detail: "key accepted" };
      }
      default:
        return { live: null, detail: "no probe adapter" };
    }
  } catch (err) {
    return {
      live: null,
      detail: err?.name === "TimeoutError" ? "probe timed out" : (err?.message ?? "probe failed"),
    };
  }
}

async function probeKey(fingerprint, { scanOpts = null } = {}) {
  if (typeof fingerprint !== "string" || !FINGERPRINT_RE.test(fingerprint)) {
    return { status: "refused", message: "invalid fingerprint" };
  }
  try {
    // Prefer the vault — a contained key may no longer exist on disk.
    let value = null;
    let provider = null;
    const sealed = await vaultGet(fingerprint);
    if (sealed?.error) return { status: "failed", message: sealed.error };
    if (sealed?.value) {
      value = sealed.value;
      provider = sealed.provider;
    } else {
      const records = await listKeys({ force: true, ...(scanOpts ?? {}) });
      const rec = records.find((r) => r.fingerprint === fingerprint);
      if (!rec) {
        return { status: "failed", message: "key not found in the current scan or vault" };
      }
      provider = rec.provider;
      // Same gate as the server service: non-bearer credentials get an
      // honest verdict without touching the provider — a 401 would
      // fabricate 'dead' on something never usable as a key.
      const notBearer = nonBearerReason(rec);
      if (notBearer) {
        return { status: "probed", live: null, detail: notBearer };
      }
      const recovered = await recoverSecret(
        fingerprint,
        rec.locations,
        scanOpts?.homeDir ? { homeDir: scanOpts.homeDir } : {},
      );
      if (!recovered?.value) {
        return { status: "failed", message: "secret could not be re-read" };
      }
      value = recovered.value;
    }
    const probe = await probeProvider(provider, value);
    return { status: "probed", ...probe };
  } catch (err) {
    return { status: "failed", message: err?.message ?? String(err) };
  }
}

// Providers with a real adapter in probeProvider's switch — everything
// else honestly reports "no probe adapter" per key.
const PROBEABLE_PROVIDERS = new Set(["github", "openrouter", "stripe", "openai", "anthropic"]);

// Same contract as the server service (keyprobes.ts): credentials that
// aren't bearer tokens — client secrets, private keys, publishable keys —
// must never get a fabricated 'dead' verdict.
const NON_BEARER_LABEL =
  /client[_-]?secret|client[_-]?id|private[_-]?key|publishable|public[_-]?key|signing|webhook/i;

function nonBearerReason(rec) {
  if (rec?.kind === "private-key") {
    return "private key — not a bearer credential";
  }
  if (rec?.label && NON_BEARER_LABEL.test(rec.label)) {
    return `${rec.label} — not a bearer credential`;
  }
  return null;
}

/**
 * Bulk liveness pass — probes every adapter-covered credential in the
 * current scan (bounded at 5 concurrent outbound calls). Non-bearer
 * records and adapterless providers land in `skipped`, not `results`.
 */
async function probeAll({ provider = null, scanOpts = null } = {}) {
  const records = await listKeys({ force: true, ...(scanOpts ?? {}) });
  const skipped = { noAdapter: 0, notBearer: 0 };
  const targets = [];
  for (const rec of records) {
    if (provider && rec.provider !== provider) continue;
    if (!PROBEABLE_PROVIDERS.has(rec.provider)) {
      skipped.noAdapter++;
      continue;
    }
    if (nonBearerReason(rec)) {
      skipped.notBearer++;
      continue;
    }
    targets.push(rec);
  }
  const results = [];
  const queue = targets.slice();
  const worker = async () => {
    for (;;) {
      const rec = queue.shift();
      if (!rec) return;
      const r = await probeKey(rec.fingerprint, { scanOpts });
      results.push({
        fingerprint: rec.fingerprint,
        provider: rec.provider,
        label: rec.label,
        last4: rec.last4,
        ...r,
      });
    }
  };
  await Promise.all(Array.from({ length: Math.min(5, queue.length) }, () => worker()));
  return {
    probed: results.length,
    live: results.filter((r) => r.live === true).length,
    dead: results.filter((r) => r.live === false).length,
    unknown: results.filter((r) => r.live == null).length,
    skipped,
    results,
  };
}

module.exports = {
  listKeys,
  containKey,
  probeKey,
  probeAll,
  nonBearerReason,
  vaultList,
  // Internal seams — used by contain/probe, collector.cjs's report
  // projection, and tests. Not part of the IPC surface.
  scanKeys,
  recoverSecret,
  reportItems,
  lastScanError,
  vaultSeal,
  vaultGet,
};
