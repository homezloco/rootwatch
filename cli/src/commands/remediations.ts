/**
 * remediations — propose/approve/execute/rollback lifecycle for host fixes.
 *
 * Thin wrappers over the token-auth'd v1 mirror (/api/v1/remediations…).
 * Server builds that predate the mirror only expose the session-auth'd
 * /api/remediations routes — on a 404 we retry that path best-effort so
 * the CLI degrades cleanly instead of crashing.
 */

import type { Command } from "commander";
import chalk from "chalk";
import { CliError, requireAuth, type ApiClient, type GlobalOpts } from "../client.js";
import { printJson, printKv, printTable, success } from "../output.js";
import { asList, formatTime, truncate } from "../util.js";

interface PlanStep {
  label?: string;
  argv?: string[];
}

interface ResultStep {
  step?: string | number;
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
}

interface ActionRow {
  id?: number | string;
  title?: string;
  description?: string;
  category?: string;
  risk?: string;
  status?: string;
  checkId?: string;
  findingId?: number | null;
  requiresApproval?: boolean;
  plan?: PlanStep[];
  rollbackPlan?: PlanStep[] | null;
  result?: ResultStep[] | null;
  approvedBy?: number | null;
  approvedAt?: string | null;
  executedAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

/** GET/POST that prefers /api/v1 and falls back to the session path on 404. */
async function remCall<T>(
  client: ApiClient,
  method: "GET" | "POST",
  path: string, // e.g. "/remediations", "/remediations/3/approve"
  opts: { query?: Record<string, string | number | undefined>; body?: unknown } = {},
): Promise<T> {
  try {
    const res =
      method === "GET"
        ? await client.get<T>(path, opts.query)
        : await client.post<T>(path, opts.body ?? {});
    return res.data;
  } catch (e) {
    if (e instanceof CliError && e.status === 404) {
      const res = await client.raw<T>(method, `/api${path}`, {
        query: opts.query,
        body: opts.body,
      });
      return res.data;
    }
    throw e;
  }
}

function requireId(id: string): string {
  if (!/^\d+$/.test(id)) {
    throw new CliError(`invalid remediation id '${id}'`, {
      code: "usage",
      exitCode: 2,
    });
  }
  return id;
}

function riskLabel(risk: string | null | undefined): string {
  const s = (risk ?? "").toLowerCase();
  const label = s ? s[0]!.toUpperCase() + s.slice(1) : "-";
  switch (s) {
    case "critical":
      return chalk.bgRed.white.bold(` ${label} `);
    case "guarded":
      return chalk.yellow(label);
    case "safe":
      return chalk.green(label);
    default:
      return label;
  }
}

function statusLabel(status: string | null | undefined): string {
  const s = status ?? "-";
  switch (s) {
    case "succeeded":
      return chalk.green(s);
    case "failed":
      return chalk.red(s);
    case "executing":
      return chalk.magenta(s);
    case "approved":
      return chalk.blue(s);
    case "proposed":
      return chalk.cyan(s);
    case "rolled_back":
      return chalk.yellow(s);
    case "executor-unavailable":
      return chalk.yellow(s);
    default:
      return s;
  }
}

function printActionDetail(a: ActionRow): void {
  printKv([
    ["ID", String(a.id ?? "-")],
    ["Title", a.title ?? "-"],
    ["Status", statusLabel(a.status)],
    ["Risk", riskLabel(a.risk)],
    ["Category", a.category ?? "-"],
    ["Check", a.checkId ?? "-"],
    ["Finding", a.findingId != null ? String(a.findingId) : "-"],
    ["Approval", a.requiresApproval ? "required" : "not required"],
    ["Approved", a.approvedAt ? `${formatTime(a.approvedAt)}${a.approvedBy != null ? ` by user ${a.approvedBy}` : ""}` : "-"],
    ["Executed", formatTime(a.executedAt)],
    ["Created", formatTime(a.createdAt)],
    ["Updated", formatTime(a.updatedAt)],
  ]);

  if (a.description) {
    console.log(`\n${a.description}`);
  }

  if (a.status === "executor-unavailable") {
    console.log(
      chalk.yellow(
        "\nPrivileged executor not configured — see packaging/README.md",
      ),
    );
  }

  const plan = Array.isArray(a.plan) ? a.plan : [];
  if (plan.length) {
    console.log("\nplan:");
    plan.forEach((s, i) => {
      console.log(`  ${i + 1}. ${s.label ?? `step ${i + 1}`}`);
      if (Array.isArray(s.argv) && s.argv.length) {
        console.log(`     ${chalk.dim("$")} ${s.argv.join(" ")}`);
      }
    });
  }

  const rollback = Array.isArray(a.rollbackPlan) ? a.rollbackPlan : [];
  if (rollback.length) {
    console.log("\nrollback plan:");
    rollback.forEach((s, i) => {
      console.log(`  ${i + 1}. ${s.label ?? `step ${i + 1}`}`);
      if (Array.isArray(s.argv) && s.argv.length) {
        console.log(`     ${chalk.dim("$")} ${s.argv.join(" ")}`);
      }
    });
  }

  const result = Array.isArray(a.result) ? a.result : [];
  if (result.length) {
    console.log("\nexecution log:");
    result.forEach((r, i) => {
      const code = r.exitCode ?? "?";
      const mark = r.exitCode === 0 ? chalk.green("✓") : chalk.red("✗");
      console.log(`  ${mark} ${String(r.step ?? `step ${i + 1}`)} — exit ${code}`);
      if (r.stdout) console.log(chalk.dim(`     stdout: ${r.stdout}`));
      if (r.stderr) console.log(chalk.red(`     stderr: ${r.stderr}`));
    });
  }
}

export function registerRemediations(program: Command): void {
  const rem = program
    .command("remediations")
    .alias("rem")
    .description("Remediation lifecycle — propose, approve, execute, rollback");

  rem
    .command("list")
    .description("List remediation actions")
    .option("--status <status>", "filter by status (proposed|approved|executing|succeeded|failed|…)")
    .option("--risk <risk>", "filter by risk (safe|guarded|critical)")
    .option("--limit <n>", "max results", "100")
    .action(
      async (
        opts: { status?: string; risk?: string; limit: string },
        cmd: Command,
      ) => {
        const globals = cmd.optsWithGlobals() as GlobalOpts;
        const { client } = requireAuth(globals);
        const limit = Math.max(1, Number(opts.limit) || 100);
        const data = await remCall<unknown>(client, "GET", "/remediations", {
          query: { status: opts.status, risk: opts.risk },
        });
        const rows = asList<ActionRow>(data, ["remediations", "actions"]).slice(
          0,
          limit,
        );
        if (globals.json) {
          printJson(rows);
          return;
        }
        if (!rows.length) {
          console.log("no remediation actions");
          return;
        }
        printTable(
          ["ID", "Status", "Risk", "Category", "Title", "Updated"],
          rows.map((a) => [
            String(a.id ?? "-"),
            statusLabel(a.status),
            riskLabel(a.risk),
            a.category ?? "-",
            truncate(a.title, 50),
            formatTime(a.updatedAt ?? a.createdAt),
          ]),
        );
      },
    );

  rem
    .command("show <id>")
    .description("Show one remediation action incl. plan + execution log")
    .action(async (id: string, _o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const a = await remCall<ActionRow>(
        client,
        "GET",
        `/remediations/${requireId(id)}`,
      );
      if (globals.json) {
        printJson(a);
        return;
      }
      printActionDetail(a);
    });

  rem
    .command("approve <id>")
    .description("Approve a proposed action (admin scope)")
    .action(async (id: string, _o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const a = await remCall<ActionRow>(
        client,
        "POST",
        `/remediations/${requireId(id)}/approve`,
      );
      if (globals.json) {
        printJson(a);
        return;
      }
      success(`✓ remediation ${id} → ${a.status ?? "approved"}`);
    });

  rem
    .command("execute <id>")
    .description("Execute an approved action (admin scope)")
    .option(
      "--confirm-remote",
      "confirm remote-session risk for ssh/firewall actions (required by the server for those categories)",
    )
    .action(
      async (
        id: string,
        opts: { confirmRemote?: boolean },
        cmd: Command,
      ) => {
        const globals = cmd.optsWithGlobals() as GlobalOpts;
        const { client } = requireAuth(globals);
        const a = await remCall<ActionRow>(
          client,
          "POST",
          `/remediations/${requireId(id)}/execute`,
          { body: opts.confirmRemote ? { confirmRemote: true } : {} },
        );
        if (globals.json) {
          printJson(a);
          return;
        }
        if (a.status === "executor-unavailable") {
          console.log(
            chalk.yellow(
              `remediation ${id} → executor-unavailable — privileged executor not configured, see packaging/README.md`,
            ),
          );
          return;
        }
        success(`✓ remediation ${id} → ${a.status ?? "executed"}`);
      },
    );

  rem
    .command("rollback <id>")
    .description("Roll back a succeeded action via its rollback plan (admin scope)")
    .action(async (id: string, _o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const a = await remCall<ActionRow>(
        client,
        "POST",
        `/remediations/${requireId(id)}/rollback`,
      );
      if (globals.json) {
        printJson(a);
        return;
      }
      success(`✓ remediation ${id} → ${a.status ?? "rolled_back"}`);
    });

  rem
    .command("propose")
    .description("Generate remediation proposals from current open findings")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const data = await remCall<{ created?: number; proposals?: ActionRow[] }>(
        client,
        "POST",
        "/remediations/propose",
      );
      if (globals.json) {
        printJson(data);
        return;
      }
      const proposals = Array.isArray(data?.proposals) ? data.proposals : [];
      const n = data?.created ?? proposals.length;
      success(`✓ generated ${n} remediation proposal${n === 1 ? "" : "s"}`);
      if (proposals.length) {
        printTable(
          ["ID", "Risk", "Category", "Title"],
          proposals.map((a) => [
            String(a.id ?? "-"),
            riskLabel(a.risk),
            a.category ?? "-",
            truncate(a.title, 60),
          ]),
        );
      }
    });
}
