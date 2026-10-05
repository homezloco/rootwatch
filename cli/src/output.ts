/**
 * Output helpers: --json passthrough, dependency-free column tables,
 * TTY-aware color, and consistent error streams.
 */

import chalk from "chalk";

export const isTTY = !!process.stdout.isTTY;

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const visible = (s: string) => s.replace(ANSI_RE, "").length;
const padEnd = (s: string, n: number) =>
  s + " ".repeat(Math.max(0, n - visible(s)));

export function printJson(data: unknown): void {
  process.stdout.write(JSON.stringify(data, null, 2) + "\n");
}

/** Single JSON line — used for --json --watch streams. */
export function printJsonLine(data: unknown): void {
  process.stdout.write(JSON.stringify(data) + "\n");
}

export function table(headers: string[], rows: string[][]): string {
  const cols = headers.length;
  const widths = new Array<number>(cols).fill(0);
  for (let i = 0; i < cols; i++) widths[i] = visible(headers[i] ?? "");
  for (const row of rows) {
    for (let i = 0; i < cols; i++) {
      widths[i] = Math.max(widths[i]!, visible(row[i] ?? ""));
    }
  }
  const lines: string[] = [];
  lines.push(
    headers.map((h, i) => padEnd(chalk.bold(h), widths[i]!)).join("  ").trimEnd(),
  );
  lines.push(
    widths.map((w) => chalk.dim("─".repeat(Math.max(3, w)))).join("  "),
  );
  for (const row of rows) {
    lines.push(
      row.map((cell, i) => padEnd(cell ?? "", widths[i]!)).join("  ").trimEnd(),
    );
  }
  return lines.join("\n");
}

export function printTable(headers: string[], rows: string[][]): void {
  process.stdout.write(table(headers, rows) + "\n");
}

/** Two-column key/value layout. */
export function printKv(rows: [string, string][]): void {
  const w = Math.max(...rows.map(([k]) => visible(k)), 0);
  for (const [k, v] of rows) {
    process.stdout.write(`${chalk.dim(padEnd(k, w))}  ${v}\n`);
  }
}

export function severityLabel(sev: string | null | undefined): string {
  const s = (sev ?? "").toLowerCase();
  const label = s ? s[0]!.toUpperCase() + s.slice(1) : "-";
  switch (s) {
    case "critical":
      return chalk.bgRed.white.bold(` ${label} `);
    case "high":
      return chalk.red(label);
    case "medium":
      return chalk.yellow(label);
    case "low":
      return chalk.blue(label);
    default:
      return label;
  }
}

export function checkMark(ok: boolean): string {
  return ok ? chalk.green("✓") : chalk.red("✗");
}

export function info(msg: string): void {
  process.stdout.write(msg + "\n");
}

export function success(msg: string): void {
  process.stdout.write(chalk.green(msg) + "\n");
}

export function warn(msg: string): void {
  process.stderr.write(chalk.yellow(`warning: ${msg}`) + "\n");
}

export function error(msg: string): void {
  process.stderr.write(chalk.red(`error: ${msg}`) + "\n");
}
