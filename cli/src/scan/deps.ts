/**
 * Dependency scanner — runs `npm audit --json` when a package-lock.json
 * is present. Tolerates npm being missing and audit's nonzero exit code
 * (npm exits 1 precisely when vulnerabilities exist).
 */

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { normalizeSeverity } from "../util.js";
import type { Finding } from "./index.js";

const execFileAsync = promisify(execFile);

/** npm severity -> RootWatch severity (low/moderate -> Medium per spec). */
function mapSeverity(npmSeverity: string): Finding["severity"] {
  const s = npmSeverity.toLowerCase();
  if (s === "critical") return "Critical";
  if (s === "high") return "High";
  if (s === "info") return "Low";
  return normalizeSeverity("medium"); // low | moderate | unknown -> Medium
}

interface AuditVuln {
  severity?: string;
  via?: (string | { title?: string; name?: string; url?: string })[];
  fixAvailable?: boolean | { name?: string; version?: string };
  range?: string;
}

export async function scanDeps(dir: string): Promise<Finding[]> {
  if (!existsSync(join(dir, "package-lock.json"))) return [];

  let stdout: string;
  try {
    const res = await execFileAsync("npm", ["audit", "--json"], {
      cwd: dir,
      timeout: 120_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, npm_config_audit: "true" },
    });
    stdout = res.stdout;
  } catch (e) {
    // npm audit exits nonzero when vulns are found — stdout is still valid JSON.
    const err = e as { stdout?: string; code?: number | string };
    if (typeof err.stdout === "string" && err.stdout.trim().startsWith("{")) {
      stdout = err.stdout;
    } else {
      return []; // npm unavailable or blew up — tolerate silently
    }
  }

  let audit: { vulnerabilities?: Record<string, AuditVuln> };
  try {
    audit = JSON.parse(stdout);
  } catch {
    return [];
  }

  const vulns = audit.vulnerabilities ?? {};
  const findings: Finding[] = [];
  for (const [pkg, vuln] of Object.entries(vulns)) {
    const viaTitles = (vuln.via ?? [])
      .filter((v): v is { title?: string; url?: string } => typeof v === "object")
      .map((v) => v.title)
      .filter((t): t is string => !!t);

    const fix = vuln.fixAvailable;
    findings.push({
      ruleId: `dep/${pkg}`,
      severity: mapSeverity(vuln.severity ?? "moderate"),
      title:
        `Vulnerable dependency ${pkg}` +
        (vuln.range ? ` (${vuln.range})` : "") +
        (viaTitles[0] ? `: ${viaTitles[0]}` : ""),
      file: "package-lock.json",
      metadata: {
        package: pkg,
        npmSeverity: vuln.severity,
        advisories: viaTitles.slice(0, 10),
        fixAvailable:
          typeof fix === "object" && fix !== null
            ? (fix.name ?? fix.version ?? true)
            : !!fix,
      },
    });
  }
  return findings;
}
