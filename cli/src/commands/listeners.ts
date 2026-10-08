/**
 * listeners (alias: ports) — enriched inventory of processes listening on
 * TCP/UDP ports on the monitored host, plus a guarded `stop` action.
 *
 * Backed by GET /api/v1/listeners and POST /api/v1/listeners/:pid/stop —
 * both require the server's local_scanning capability (a cloud-mode
 * instance returns an honest capability error).
 */

import type { Command } from "commander";
import chalk from "chalk";
import { createInterface } from "node:readline/promises";
import { CliError, requireAuth, type ApiClient, type GlobalOpts } from "../client.js";
import { info, printJson, printTable, severityLabel, success } from "../output.js";
import { asList, formatUptime, truncate } from "../util.js";

// Mirrors server/services/listeners.ts — the CLI is a standalone package
// and consumes the contract over the wire, so the shape is declared here.
interface ListenerPort {
  protocol?: "tcp" | "udp" | string;
  port?: number;
  address?: string;
  scope?: "loopback" | "private" | "tailscale" | "public" | string;
  url?: string;
}

interface ListenerInfo {
  key?: string;
  pid?: number;
  ports?: ListenerPort[];
  name?: string | null;
  identifiedBy?: string;
  class?: string;
  risk?: "critical" | "high" | "medium" | "low" | "info" | string;
  riskReasons?: string[];
  user?: string | null;
  cmdline?: string | null;
  stoppable?: "yes" | "elevated" | "no" | string;
  stopReason?: string | null;
  suggestedFix?: string | null;
  ageSeconds?: number | null;
  activity?: { established: number; peers: { address: string; scope: string }[] } | null;
  lastActiveAt?: string | null;
  persistence?: { returnsOnBoot: boolean; evidence: string[] } | null;
}

interface StopResult {
  status?: "stopped" | "escalated" | "refused" | "elevated_required" | string;
  message?: string;
  method?: string;
  suggestedFix?: string | null;
}

const HEADERS = ["Port", "Scope", "Name", "Class", "Risk", "Conns", "Boot", "User", "Age", "PID"];

function scopeLabel(scope: string | undefined): string {
  switch (scope) {
    case "public":
      return chalk.red("public");
    case "private":
      return chalk.yellow("private");
    case "tailscale":
      return chalk.blue("tailscale");
    case "loopback":
      return chalk.dim("loopback");
    default:
      return scope ?? "-";
  }
}

/** One row per bound port — a process can listen on several sockets. */
function listenerRows(listeners: ListenerInfo[]): string[][] {
  const rows: { sort: number; cells: string[] }[] = [];
  for (const l of listeners) {
    const ports = Array.isArray(l.ports) && l.ports.length ? l.ports : [{}];
    for (const p of ports) {
      rows.push({
        sort: (p.port ?? 0) * 10 + (p.protocol === "udp" ? 1 : 0),
        cells: [
          p.port != null ? `${p.port}/${p.protocol ?? "-"}` : "-",
          scopeLabel(p.scope),
          truncate(l.name, 28) || "-",
          l.class ?? "-",
          severityLabel(l.risk),
          l.activity == null
            ? "-"
            : l.activity.established > 0
              ? chalk.green(String(l.activity.established))
              : chalk.dim("0"),
          l.persistence?.returnsOnBoot ? chalk.yellow("yes") : "-",
          l.user ?? "-",
          l.ageSeconds != null ? formatUptime(l.ageSeconds) : "-",
          l.pid != null ? String(l.pid) : "-",
        ],
      });
    }
  }
  return rows.sort((a, b) => a.sort - b.sort).map((r) => r.cells);
}

async function fetchListeners(client: ApiClient): Promise<ListenerInfo[]> {
  const { data } = await client.get("/listeners");
  return asList<ListenerInfo>(data, ["listeners"]);
}

async function runList(globals: GlobalOpts): Promise<void> {
  const { client } = requireAuth(globals);
  const listeners = await fetchListeners(client);
  if (globals.json) {
    printJson(listeners);
    return;
  }
  if (!listeners.length) {
    console.log("no listeners reported");
    return;
  }
  printTable(HEADERS, listenerRows(listeners));
}

/** Ask before killing a process — skipped with --yes/--force or non-TTY. */
async function confirmStop(pid: number, client: ApiClient): Promise<void> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new CliError(
      "refusing to stop a process without confirmation — pass --yes (or --force for system processes) in non-interactive use",
      { code: "usage", exitCode: 2 },
    );
  }
  // Best-effort label for the prompt; a read-less (write-only) token just
  // prompts with the bare pid.
  let label = `pid ${pid}`;
  try {
    const hit = (await fetchListeners(client)).find((l) => l.pid === pid);
    if (hit?.name) label = `${hit.name} (pid ${pid})`;
    else if (hit) label = `pid ${pid} — ${truncate(hit.cmdline, 60) || hit.class || "unknown"}`;
  } catch {
    /* prompt with the bare pid */
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(`Stop ${label}? [y/N] `);
    if (!/^y(es)?$/i.test(answer.trim())) {
      throw new CliError("aborted", { code: "aborted", exitCode: 1 });
    }
  } finally {
    rl.close();
  }
}

export function registerListeners(program: Command): void {
  const listeners = program
    .command("listeners")
    .alias("ports")
    .description(
      "Listener inventory — processes bound to TCP/UDP ports, with identity, class, and risk",
    );

  listeners
    .command("ls", { isDefault: true })
    .description("List listening processes (port, scope, name, class, risk, pid)")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      await runList(globals);
    });

  listeners
    .command("stop <pid>")
    .description("Stop a listener process by PID — prompts for confirmation on a TTY (write scope)")
    .option("-y, --yes", "skip the interactive confirmation")
    .option("-f, --force", "also confirm stopping a system/root-owned process (implies --yes)")
    .option(
      "-d, --disable",
      "also disable the boot-survival mechanism (systemd unit → disable --now)",
    )
    .action(
      async (
        pidArg: string,
        opts: { yes?: boolean; force?: boolean; disable?: boolean },
        cmd: Command,
      ) => {
        const globals = cmd.optsWithGlobals() as GlobalOpts;
        const { client } = requireAuth(globals);
        if (!/^\d+$/.test(pidArg) || Number(pidArg) <= 0) {
          throw new CliError(`invalid pid '${pidArg}'`, {
            code: "usage",
            exitCode: 2,
          });
        }
        const pid = Number(pidArg);
        if (!opts.yes && !opts.force) {
          await confirmStop(pid, client);
        }
        const { data: result } = await client.post<StopResult>(`/listeners/${pid}/stop`, {
          confirm: true,
          confirmSystem: opts.force === true,
          disable: opts.disable === true,
        });
        if (globals.json) {
          printJson(result);
        }
        const fix = result.suggestedFix;
        switch (result.status) {
          case "stopped":
            if (!globals.json) {
              success(
                `✓ stopped pid ${pid}${result.method ? ` (${result.method})` : ""} — ${result.message ?? ""}`.trim(),
              );
            }
            return;
          case "escalated":
            if (!globals.json) {
              success(
                `✓ pid ${pid} stopped via ${result.method ?? "elevated helper"} — ${result.message ?? ""}`.trim(),
              );
            }
            return;
          case "elevated_required":
            if (fix) info(`suggested fix: ${fix}`);
            throw new CliError(
              `elevated_required: ${result.message ?? "insufficient privileges to stop this process"}`,
              { code: "elevated_required" },
            );
          case "refused":
            if (fix) info(`suggested fix: ${fix}`);
            throw new CliError(`refused: ${result.message ?? "stop refused"}`, {
              code: "refused",
            });
          default:
            throw new CliError(
              result.message ?? `unexpected stop status '${result.status ?? "?"}'`,
              { code: "api_error" },
            );
        }
      },
    );
}
