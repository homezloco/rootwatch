/**
 * status / score / hosts — read-only posture commands.
 * (`ports` is an alias of the `listeners` group in listeners.ts.)
 */

import type { Command } from "commander";
import chalk from "chalk";
import { requireAuth, type GlobalOpts } from "../client.js";
import { printJson, printKv, printTable } from "../output.js";
import { formatBytes, formatUptime } from "../util.js";

function scoreValue(data: any): number | undefined {
  const v = data?.score ?? data?.value ?? data?.current;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function scoreColor(n: number | undefined): string {
  if (n === undefined) return "-";
  const s = `${n}`;
  if (n >= 80) return chalk.green.bold(s);
  if (n >= 50) return chalk.yellow.bold(s);
  return chalk.red.bold(s);
}

function scoreTrend(data: any): string {
  const prev = Number(data?.previousScore ?? data?.previous ?? data?.trend?.previous);
  const cur = scoreValue(data);
  if (!Number.isFinite(prev) || cur === undefined) return "";
  if (cur > prev) return chalk.green(` ↑${cur - prev}`);
  if (cur < prev) return chalk.red(` ↓${prev - cur}`);
  return chalk.dim(" →0");
}

interface HostPayload {
  host?: Record<string, any>;
  metrics?: Record<string, any>;
  systemStatus?: unknown[];
}

function hostKvRows(hp: HostPayload): [string, string][] {
  const host = hp.host ?? {};
  const metrics = hp.metrics ?? {};
  const os = [host.distro, host.release].filter(Boolean).join(" ") || host.platform || "-";
  return [
    ["Hostname", host.hostname ?? metrics.hostname ?? "-"],
    ["OS", `${os} ${host.arch ? `(${host.arch})` : ""}`],
    ["Kernel", host.kernel ?? "-"],
    ["CPU", metrics.cpuPercent != null ? `${metrics.cpuPercent}%` : "-"],
    [
      "Memory",
      metrics.memPercent != null
        ? `${metrics.memPercent}% (${formatBytes(metrics.memUsed)} / ${formatBytes(metrics.memTotal)})`
        : "-",
    ],
    ["Disk", metrics.diskPercent != null ? `${metrics.diskPercent}%` : "-"],
    ["Uptime", formatUptime(metrics.uptimeSeconds ?? host.uptimeSeconds)],
    [
      "IPs",
      Array.isArray(host.ips)
        ? host.ips.map((i: any) => i.address).join(", ") || "-"
        : "-",
    ],
    ["Users", Array.isArray(host.users) ? host.users.join(", ") || "-" : "-"],
  ];
}

export function registerStatus(program: Command): void {
  program
    .command("status")
    .description("Security score + live host metrics")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const [scoreRes, hostRes] = await Promise.all([
        client.get("/score"),
        client.get("/hosts/current"),
      ]);
      if (globals.json) {
        printJson({ score: scoreRes.data, host: hostRes.data });
        return;
      }
      printKv([
        ["Security score", `${scoreColor(scoreValue(scoreRes.data))}${scoreTrend(scoreRes.data)}`],
        ...hostKvRows(hostRes.data as HostPayload),
      ]);
    });

  program
    .command("score")
    .description("Security score with breakdown")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const { data } = await client.get("/score");
      if (globals.json) {
        printJson(data);
        return;
      }
      const d = data as Record<string, any>;
      console.log(
        `Security score: ${scoreColor(scoreValue(d))}${d?.maxScore ? `/${d.maxScore}` : ""}${scoreTrend(d)}`,
      );
      const breakdown = d?.breakdown ?? d?.components ?? d?.details;
      if (Array.isArray(breakdown) && breakdown.length) {
        printTable(
          ["Component", "Score"],
          breakdown.map((b: any) => [
            b.name ?? b.key ?? b.category ?? "-",
            String(b.score ?? b.value ?? b.impact ?? "-"),
          ]),
        );
      } else {
        const parts =
          breakdown && typeof breakdown === "object"
            ? breakdown
            : (d ?? {});
        const label = (k: string) =>
          k.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
        const rows = Object.entries(parts)
          .filter(([k, v]) => v != null && typeof v !== "object" && k !== "score")
          .map(([k, v]) => [label(k), String(v)] as [string, string]);
        if (rows.length) printKv(rows);
      }
    });

  program
    .command("hosts")
    .description("Host inventory — current monitored host")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      const { data } = await client.get("/hosts/current");
      if (globals.json) {
        printJson(data);
        return;
      }
      printKv(hostKvRows(data as HostPayload));
    });
}
