/**
 * Project-directory walker shared by the local scanners.
 * Skips VCS/build/dependency dirs, known binary extensions, symlinks,
 * and files over 512 KiB.
 */

import { readdirSync, statSync, type Dirent } from "node:fs";
import { extname, join, relative } from "node:path";

export const MAX_FILE_BYTES = 512 * 1024;

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
]);

const BINARY_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".bmp",
  ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".mp3", ".mp4", ".mov", ".avi", ".wav", ".webm",
  ".wasm", ".so", ".dll", ".exe", ".dylib", ".bin", ".dat",
  ".jar", ".class", ".pyc", ".pyo", ".o", ".a",
  ".sqlite", ".db", ".lockb", ".snap",
]);

/** Lockfiles are handled by the deps scanner, not the text scanners. */
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

export interface ScannedFile {
  absPath: string;
  /** path relative to the scanned root, forward-slashed */
  relPath: string;
  size: number;
}

function isSkippableFile(name: string): boolean {
  if (SKIP_FILES.has(name)) return true;
  if (name.endsWith(".min.js") || name.endsWith(".min.css")) return true;
  if (name.endsWith(".map")) return true;
  return BINARY_EXTS.has(extname(name).toLowerCase());
}

export function walkProject(root: string): ScannedFile[] {
  const out: ScannedFile[] = [];
  const stack: string[] = [root];

  while (stack.length) {
    const dir = stack.pop()!;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue; // skip symlinks, sockets, fifos
      if (isSkippableFile(entry.name)) continue;
      let size: number;
      try {
        size = statSync(abs).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES) continue;
      out.push({
        absPath: abs,
        relPath: relative(root, abs).split("\\").join("/"),
        size,
      });
    }
  }
  return out.sort((a, b) => a.relPath.localeCompare(b.relPath));
}
