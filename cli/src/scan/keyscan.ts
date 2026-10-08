/**
 * Host credential scanner — CLI port of server/services/keyscan.ts.
 *
 * The CLI is published standalone to npm (@rootwatch/cli) and cannot import
 * from ../server — this file is a verbatim port. Keep the RULES table,
 * KNOWN_FILES, SHELL_RC, HISTORY_FILES, SKIP_DIRS, the bounded .env* walk,
 * and the /proc environ pass in sync with the server copy (and
 * desktop/keys.cjs) so all surfaces produce identical records.
 *
 * Differences from the server copy: the `listenerCwds` option (server-side
 * listener-cwd correlation → 'served' flag) is dropped — there are no
 * listeners to correlate against in a standalone scan.
 *
 * Inventories API keys / tokens / private keys / passwords visible on this
 * host without ever storing the secret value: records carry
 * sha256(value) fingerprint + last4 + redacted (home-relative) location
 * metadata only.
 *
 * Passes:
 *  A — known locations: credential files by convention (~/.aws/credentials,
 *      ~/.netrc, ~/.ssh, kubeconfig, package-manager configs, provider CLIs)
 *  B — pattern sweep: provider-tagged regex rules over the same file set,
 *      shell rc files, bounded .env* walk under common project roots
 *  C — live evidence: /proc/<pid>/environ for same-uid processes (env is
 *      where most dev keys actually live), shell history
 *
 * Posture flags annotate each record: committed (git-tracked),
 * worldReadable (mode & 077), leakedToHistory, gitignored.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_FILE_BYTES = 512 * 1024;
const MAX_PROJECT_FILES = 400;
const MAX_ENV_WALK_DEPTH = 4;
const MAX_FINDINGS = 500;

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

export type KeyKind = "api-key" | "token" | "private-key" | "password";
export type ExposedVia = "known-file" | "file" | "shell-rc" | "history" | "proc-env";

export interface KeyLocation {
  /** Home-relative ("~/…") or /proc/<pid>/environ — never leaks the username. */
  path: string;
  line?: number;
  /** Octal string, e.g. "0644" — for real files only. */
  perm?: string;
  exposedVia: ExposedVia;
  /** Process name for proc-env locations. */
  proc?: string;
}

export interface KeyFlags {
  /** File is tracked by a git repo. */
  committed?: boolean;
  /** Credential file mode has group/other bits set. */
  worldReadable?: boolean;
  /** Same fingerprint also found in shell history. */
  leakedToHistory?: boolean;
  /** cwd of a listening process that contains this path. */
  served?: string;
  /** Matched by the repo's own ignore rules (untracked + ignored). */
  gitignored?: boolean;
}

export interface KeyRecord {
  /** sha256 hex of the secret value — dedupe key across locations. */
  fingerprint: string;
  provider: string | null;
  kind: KeyKind;
  /** env var name / profile / filename — never the value. */
  label: string | null;
  last4: string;
  locations: KeyLocation[];
  flags: KeyFlags;
}

export interface KeyScanOptions {
  homeDir?: string;
  /** User-configured extra files/dirs (absolute or ~/…). */
  extraPaths?: string[];
  /** Roots for the bounded .env* walk (defaults below). */
  projectRoots?: string[];
  /** Skip the /proc environ pass (tests / constrained envs). */
  skipProcEnv?: boolean;
}

interface SecretRule {
  ruleId: string;
  provider: string | null;
  kind: KeyKind;
  /** Group 1 captures the secret when present; otherwise match[0]. */
  pattern: RegExp;
}

// Provider-tagged, high-precision patterns — the gitleaks top ~25. Keep in
// sync with server/services/keyscan.ts and desktop/keys.cjs.
const RULES: SecretRule[] = [
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

interface KnownFile {
  rel: string; // home-relative
  provider?: string;
  kind?: KeyKind;
  label?: string;
  /** Whole file is the credential (private keys) — hash content, not lines. */
  wholeFile?: boolean;
}

const KNOWN_FILES: KnownFile[] = [
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
const LABEL_PROVIDER: [RegExp, string][] = [
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

function providerFromLabel(label: string | null): string | null {
  if (!label) return null;
  for (const [re, p] of LABEL_PROVIDER) if (re.test(label)) return p;
  return null;
}

// ---------------------------------------------------------------------------

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function homeRel(abs: string, home: string): string {
  if (abs === home) return "~";
  return abs.startsWith(home + path.sep) ? `~${abs.slice(home.length)}` : abs;
}

/** Expand ~/… or bare-relative extra paths against home. */
function resolveExtra(p: string, home: string): string {
  if (p.startsWith("~/")) return path.join(home, p.slice(2));
  if (path.isAbsolute(p)) return p;
  return path.join(home, p);
}

function readText(abs: string): string | null {
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

function permOf(abs: string): string | undefined {
  try {
    return (statSync(abs).mode & 0o777).toString(8).padStart(4, "0");
  } catch {
    return undefined;
  }
}

interface Candidate {
  value: string;
  provider: string | null;
  kind: KeyKind;
  label: string | null;
  /** label came from a name-capture (env var) — beats a generic file label. */
  preferLabel?: boolean;
  line?: number;
}

function matchValue(m: RegExpMatchArray): { value: string; label: string | null; prefer: boolean } {
  // env-assignment rule: group1=NAME group2=value; other rules group1=value
  // or whole match.
  if (m.length >= 3 && m[1] && m[2]) return { value: m[2], label: m[1], prefer: true };
  return { value: m[1] ?? m[0], label: null, prefer: false };
}

function extractFromText(
  text: string,
  fileProvider: string | null,
  fileLabel: string | null,
): Candidate[] {
  const out: Candidate[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
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
function extractSpecial(abs: string, rel: string, text: string): Candidate[] {
  const out: Candidate[] = [];
  const base = path.basename(rel);

  if (base === ".git-credentials") {
    // https://user:token@host lines
    for (const m of text.matchAll(/^[a-z]+:\/\/([^:\s]+):([^@\s]+)@/gim)) {
      out.push({
        value: m[2]!,
        provider: "git",
        kind: "password",
        label: `git-credentials:${m[1]}`,
      });
    }
  } else if (base === ".netrc") {
    for (const m of text.matchAll(/\bpassword\s+(\S+)/g)) {
      out.push({ value: m[1]!, provider: null, kind: "password", label: "netrc" });
    }
  } else if (base === "config.json" && rel.includes(".docker")) {
    try {
      const j = JSON.parse(text) as { auths?: Record<string, { auth?: string }> };
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
function isPrivateKeyFile(abs: string, rel: string): boolean {
  const prefix = `~/${SSH_DIR}/`; // rel is home-relative
  if (!rel.startsWith(prefix)) return false;
  if (rel.endsWith(".pub") || rel.includes("known_hosts") || rel === `${prefix}config`)
    return false;
  const text = readText(abs);
  return text !== null && PRIVATE_KEY_RE.test(text);
}

// -- git posture ------------------------------------------------------------

const repoRootCache = new Map<string, string | null>();
function repoRootFor(abs: string): string | null {
  let dir = path.dirname(abs);
  for (;;) {
    if (repoRootCache.has(dir)) return repoRootCache.get(dir)!;
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

function git(abs: string, root: string, args: string[]): boolean {
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

interface FileEntry {
  abs: string;
  rel: string; // home-relative
  known?: KnownFile;
  via: ExposedVia;
}

function collectFiles(opts: Required<Pick<KeyScanOptions, "homeDir">> & KeyScanOptions): {
  files: FileEntry[];
  history: FileEntry[];
} {
  const home = opts.homeDir;
  const files: FileEntry[] = [];
  const history: FileEntry[] = [];
  const seen = new Set<string>();

  const add = (abs: string, via: ExposedVia, known?: KnownFile, intoHistory = false) => {
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
  const walk = (dir: string, depth: number) => {
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

function procEnvCandidates(): { cand: Candidate; loc: KeyLocation }[] {
  const out: { cand: Candidate; loc: KeyLocation }[] = [];
  const uid = typeof process.getuid === "function" ? process.getuid() : -1;
  let pids: string[];
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
 */
export async function scanHostKeys(opts: KeyScanOptions = {}): Promise<KeyRecord[]> {
  const home = opts.homeDir ?? os.homedir();
  const { files, history } = collectFiles({ ...opts, homeDir: home });
  const byFp = new Map<string, KeyRecord>();

  const ingest = (cand: Candidate, loc: KeyLocation, extraFlags: KeyFlags = {}) => {
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
    const locBase: KeyLocation = { path: f.rel, perm, exposedVia: f.via };

    const flags: KeyFlags = {};
    if (perm && (parseInt(perm, 8) & 0o077) !== 0) flags.worldReadable = true;
    const repo = repoRootFor(f.abs);
    if (repo) {
      if (git(f.abs, repo, ["ls-files", "--error-unmatch"])) flags.committed = true;
      else if (git(f.abs, repo, ["check-ignore", "-q"])) flags.gitignored = true;
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
  const historyFps = new Set<string>();
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
export async function recoverSecret(
  fingerprint: string,
  locations: KeyLocation[],
  opts: { homeDir?: string } = {},
): Promise<{ value: string; location: KeyLocation } | null> {
  const home = opts.homeDir ?? os.homedir();
  for (const loc of locations) {
    const abs = loc.path.startsWith("~/") ? path.join(home, loc.path.slice(2)) : loc.path;
    const cands: Candidate[] = [];
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
}
