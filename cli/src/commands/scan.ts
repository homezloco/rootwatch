/**
 * scan — `scan remote` triggers the server-side rule engine;
 * `scan local [path]` (and bare `scan`) runs the local project scanners
 * and POSTs findings to /api/v1/findings.
 */

import type { Command } from "commander";
import chalk from "chalk";
import { CliError, requireAuth, type GlobalOpts } from "../client.js";
import { printJson, printKv, printTable, severityLabel, success } from "../output.js";
import { findingsPayload, scanLocalProject, type Finding } from "../scan/index.js";
import { isValidSeverity, severityAtLeast, truncate } from "../util.js";

const SEVERITIES: Finding["severity"][] = ["Critical", "High", "Medium", "Low"];

function checkThreshold(failOn: string | undefined): string | undefined {
  if (!failOn) return undefined;
  if (!isValidSeverity(failOn)) {
    throw new CliError(`--fail-on must be one of: low, medium, high, critical (got '${failOn}')`, {
      code: "usage",
      exitCode: 2,
    });
  }
  return failOn;
}

function severityCounts(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const s of SEVERITIES) counts[s] = 0;
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

function hasAtOrAbove(findings: Finding[], threshold: string): boolean {
  return findings.some((f) => severityAtLeast(f.severity, threshold));
}

/** --fail-on may land on the parent `scan` command when a subcommand is used. */
function failOnOption(opts: { failOn?: string }, cmd: Command): string | undefined {
  return opts.failOn ?? (cmd.parent?.opts() as { failOn?: string } | undefined)?.failOn;
}

async function runLocalScan(
  path: string | undefined,
  opts: { failOn?: string; upload?: boolean },
  globals: GlobalOpts,
  cmd: Command,
): Promise<void> {
  const failOn = checkThreshold(failOnOption(opts, cmd));
  const upload = opts.upload !== false;
  const client = upload ? requireAuth(globals).client : null;

  const { project, findings, scannedFiles } = await scanLocalProject(path ?? ".");

  const counts = severityCounts(findings);
  const payload = findingsPayload(project, findings);

  if (!globals.json) {
    console.log(
      `scanning ${chalk.bold(project.name)} (${project.slug})` +
        `${project.repoUrl ? ` — ${project.repoUrl}` : ""}` +
        ` — ${scannedFiles} files`,
    );
  }

  // Post findings to the org (write scope) unless --no-upload. The local
  // report is still printed even when the upload fails.
  let posted: unknown = null;
  let postError: CliError | null = null;
  if (client) {
    try {
      const res = await client.post("/findings", payload);
      posted = res.data;
    } catch (e) {
      postError = e instanceof CliError ? e : new CliError(String(e));
    }
  }

  if (globals.json) {
    printJson({
      project,
      counts,
      findings,
      upload: client ? (postError ? "failed" : "ok") : "skipped",
      posted,
      uploadError: postError?.message ?? null,
    });
  } else {
    if (findings.length) {
      const rows = findings
        .slice(0, 50)
        .map((f) => [
          severityLabel(f.severity),
          f.ruleId,
          f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "-",
          truncate(f.title, 60),
        ]);
      printTable(["Severity", "Rule", "Location", "Finding"], rows);
      if (findings.length > 50) {
        console.log(`… and ${findings.length - 50} more`);
      }
    } else {
      success("✓ no findings");
    }
    printKv(
      SEVERITIES.map((s) => [s, String(counts[s] ?? 0)] as [string, string]).concat([
        ["Total", String(findings.length)],
      ]),
    );
    if (!client) {
      success("✓ local scan — nothing uploaded");
    } else if (postError) {
      console.log(chalk.yellow(`findings upload failed: ${postError.message}`));
    } else {
      success(`✓ reported ${findings.length} finding(s) to ${client.baseUrl}`);
    }
  }

  if (failOn && hasAtOrAbove(findings, failOn)) {
    throw new CliError(
      `scan found findings at or above '${failOn}' severity (${findings.length} total)`,
      { code: "threshold_exceeded" },
    );
  }
  if (postError) throw postError;
}

const REMOTE_TYPES = ["checks", "malware"] as const;
type RemoteType = (typeof REMOTE_TYPES)[number];

async function runRemoteScan(
  opts: { failOn?: string; type?: string },
  globals: GlobalOpts,
  cmd: Command,
): Promise<void> {
  const failOn = checkThreshold(failOnOption(opts, cmd));
  const type = (opts.type ?? "checks") as RemoteType;
  if (!REMOTE_TYPES.includes(type)) {
    throw new CliError(`--type must be one of: ${REMOTE_TYPES.join(", ")} (got '${type}')`, {
      code: "usage",
      exitCode: 2,
    });
  }
  const { client } = requireAuth(globals);
  const { data } = await client.post(
    type === "malware" ? "/scans/malware" : "/scans/security-checks",
    {},
  );

  if (type === "malware") {
    if (globals.json) {
      printJson(data);
    } else {
      const d = data as Record<string, any>;
      const findings = Array.isArray(d?.findings) ? d.findings : [];
      console.log(
        `malware scan (${d?.scanner ?? "heuristics"}): ` +
          `${findings.length === 0 ? chalk.green("no findings") : chalk.red(`${findings.length} finding(s)`)}` +
          (d?.filesScanned != null ? `, ${d.filesScanned} files signature-scanned` : "") +
          (d?.clamavAvailable === false ? chalk.dim(" — clamav not installed") : ""),
      );
      if (findings.length) {
        printTable(
          ["Severity", "Finding", "Evidence"],
          findings.map((f: any) => [
            severityLabel(f.severity),
            f.name ?? f.id ?? "-",
            truncate(f.evidence, 70),
          ]),
        );
      }
    }
    if (failOn) {
      const findings = Array.isArray((data as any)?.findings)
        ? ((data as any).findings as { severity?: string }[])
        : [];
      if (findings.some((f) => severityAtLeast(f.severity ?? "", failOn))) {
        throw new CliError(`malware scan has findings ≥ '${failOn}' severity`, {
          code: "threshold_exceeded",
        });
      }
    }
    return;
  }

  if (globals.json) {
    printJson(data);
  } else {
    const d = data as Record<string, any>;
    const results = Array.isArray(d?.results) ? d.results : [];
    console.log(
      `security checks: ${d?.total ?? results.length} total, ` +
        `${chalk.green(d?.passed ?? results.filter((r: any) => r.passed).length)} passed, ` +
        `${chalk.red(d?.failed ?? results.filter((r: any) => !r.passed).length)} failed` +
        (d?.newFindings != null ? `, ${d.newFindings} new finding(s)` : ""),
    );
    const failed = results.filter((r: any) => !r.passed);
    if (failed.length) {
      printTable(
        ["Severity", "Check", "Details"],
        failed.map((r: any) => [
          severityLabel(r.severity),
          r.name ?? r.id ?? "-",
          truncate(r.details ?? r.remediation, 70),
        ]),
      );
    }
  }

  if (failOn) {
    const results = Array.isArray((data as any)?.results)
      ? ((data as any).results as { passed?: boolean; severity?: string }[])
      : [];
    if (results.some((r) => r.passed === false && severityAtLeast(r.severity ?? "", failOn))) {
      throw new CliError(`remote scan has failures ≥ '${failOn}' severity`, {
        code: "threshold_exceeded",
      });
    }
  }
}

export function registerScan(program: Command): void {
  const scan = program
    .command("scan [path]")
    .description("Scan a local project (default) — see 'scan remote' for host checks")
    .option("--fail-on <severity>", "exit 1 when findings ≥ severity")
    .option("--no-upload", "scan only — no login required, findings never leave this machine")
    .action(
      async (
        path: string | undefined,
        opts: { failOn?: string; upload?: boolean },
        cmd: Command,
      ) => {
        await runLocalScan(path, opts, cmd.optsWithGlobals() as GlobalOpts, cmd);
      },
    );

  scan
    .command("local [path]")
    .description("Scan a local project directory and post findings")
    .option("--fail-on <severity>", "exit 1 when findings ≥ severity")
    .option("--no-upload", "scan only — no login required, findings never leave this machine")
    .action(
      async (
        path: string | undefined,
        opts: { failOn?: string; upload?: boolean },
        cmd: Command,
      ) => {
        await runLocalScan(path, opts, cmd.optsWithGlobals() as GlobalOpts, cmd);
      },
    );

  scan
    .command("remote")
    .description("Run the server-side scan engines (scan scope)")
    .option("--type <kind>", "checks (default) | malware")
    .option("--fail-on <severity>", "exit 1 when failed checks/findings ≥ severity")
    .action(async (opts: { failOn?: string; type?: string }, cmd: Command) => {
      await runRemoteScan(opts, cmd.optsWithGlobals() as GlobalOpts, cmd);
    });
}
