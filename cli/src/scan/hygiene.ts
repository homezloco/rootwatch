/**
 * Repo-hygiene scanner: committed .env files, .gitignore gaps,
 * debug flags left on, permissive CORS.
 */

import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { ScannedFile } from "./walk.js";
import type { Finding } from "./index.js";

const CODE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]);

function ext(name: string): string {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i).toLowerCase();
}

function isEnvFile(name: string): boolean {
  const base = basename(name);
  if (base === ".env") return true;
  if (/^\.env\..+/.test(base)) {
    // .env.example / .env.sample / .env.template are documentation, not secrets
    return !/^\.env\.(example|sample|template|dist)$/i.test(base);
  }
  return false;
}

/** Does a .gitignore line cover .env files? (.env, .env.*, star-suffixed variants) */
function gitignoreCoversEnv(lines: string[]): boolean {
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

function readText(path: string): string | null {
  try {
    const buf = readFileSync(path);
    if (buf.subarray(0, Math.min(buf.length, 1024)).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

const DEBUG_RE = /\bDEBUG\b\s*[:=]\s*["'`]?true\b/;
const CORS_STAR_RE = /\bcors\s*\(\s*\{[^}\n]*\borigin\s*:\s*["'`]\*["'`]/;
const CORS_BARE_RE = /\b(?:use|all)\s*\(\s*cors\s*\(\s*\)/;

export function scanHygiene(
  dir: string,
  files: ScannedFile[],
): Finding[] {
  const findings: Finding[] = [];
  const envFiles = files.filter((f) => isEnvFile(f.relPath));

  // 1. Committed .env files
  for (const f of envFiles) {
    findings.push({
      ruleId: "hygiene/dotenv-committed",
      severity: "High",
      title: "Environment file committed to the repo — may contain secrets",
      file: f.relPath,
    });
  }

  // 2. .gitignore missing a .env entry (only when the repo could plausibly have env files)
  const gitignore = files.find((f) => basename(f.relPath) === ".gitignore");
  const gitignoreLines = gitignore
    ? (readText(gitignore.absPath) ?? "").split("\n")
    : [];
  const coversEnv = gitignoreCoversEnv(gitignoreLines);
  if (
    !coversEnv &&
    (envFiles.length > 0 || existsSync(join(dir, ".git")) || gitignore)
  ) {
    findings.push({
      ruleId: "hygiene/gitignore-missing-env",
      severity: "Medium",
      title: ".gitignore does not exclude .env files",
      file: gitignore?.relPath ?? ".gitignore",
    });
  }

  // 3 & 4. Per-line source checks
  for (const f of files) {
    const name = f.relPath;
    const isCode = CODE_EXTS.has(ext(name));
    if (!isCode && !isEnvFile(name)) continue; // DEBUG/CORS checks only on code; .env handled above

    const text = readText(f.absPath);
    if (text === null) continue;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (DEBUG_RE.test(line)) {
        findings.push({
          ruleId: "hygiene/debug-enabled",
          severity: "Medium",
          title: "DEBUG=true left enabled",
          file: f.relPath,
          line: i + 1,
        });
      }
      if (isCode && (CORS_STAR_RE.test(line) || CORS_BARE_RE.test(line))) {
        findings.push({
          ruleId: "hygiene/cors-wildcard",
          severity: "Medium",
          title: "Permissive CORS configuration (any origin)",
          file: f.relPath,
          line: i + 1,
        });
      }
    }
  }

  return findings;
}
