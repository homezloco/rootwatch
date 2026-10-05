/**
 * Local project scanner orchestrator: walks the tree, runs the
 * secrets/deps/hygiene scanners, and derives the project identity
 * posted to POST /api/v1/findings.
 */

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";
import { slugify, type Severity } from "../util.js";
import { scanDeps } from "./deps.js";
import { scanHygiene } from "./hygiene.js";
import { scanSecrets } from "./secrets.js";
import { walkProject } from "./walk.js";

const execFileAsync = promisify(execFile);

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  file?: string;
  line?: number;
  metadata?: Record<string, unknown>;
}

export interface Project {
  name: string;
  slug: string;
  repoUrl?: string;
}

export interface LocalScanResult {
  project: Project;
  findings: Finding[];
  scannedFiles: number;
}

export async function detectProject(dir: string): Promise<Project> {
  let name = basename(dir);
  try {
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
      name?: string;
    };
    if (pkg.name && typeof pkg.name === "string") name = pkg.name;
  } catch {
    /* no package.json — use dir name */
  }

  let repoUrl: string | undefined;
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["remote", "get-url", "origin"],
      { cwd: dir, timeout: 5000 },
    );
    const url = stdout.trim();
    if (url) repoUrl = url;
  } catch {
    /* not a git repo or no origin — fine */
  }

  return { name, slug: slugify(name), ...(repoUrl ? { repoUrl } : {}) };
}

export async function scanLocalProject(dir: string): Promise<LocalScanResult> {
  const root = resolve(dir);
  if (!existsSync(root)) {
    throw new Error(`path does not exist: ${root}`);
  }
  const files = walkProject(root);
  const [deps, secrets, hygiene] = await Promise.all([
    scanDeps(root),
    Promise.resolve(scanSecrets(files)),
    Promise.resolve(scanHygiene(root, files)),
  ]);
  const project = await detectProject(root);
  return {
    project,
    findings: [...secrets, ...deps, ...hygiene],
    scannedFiles: files.length,
  };
}

/** Exact body posted to /api/v1/findings. */
export function findingsPayload(
  project: Project,
  findings: Finding[],
): {
  project: Project;
  source: "cli";
  findings: Finding[];
} {
  return { project, source: "cli", findings };
}
