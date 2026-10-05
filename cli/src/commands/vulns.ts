/**
 * vulns — tracked vulnerabilities.
 */

import type { Command } from "commander";
import { requireAuth, type GlobalOpts } from "../client.js";
import { printJson, printTable, severityLabel } from "../output.js";
import { asList, formatTime, truncate } from "../util.js";

export function registerVulns(program: Command): void {
  program
    .command("vulns")
    .description("List tracked vulnerabilities (open first)")
    .option("--open", "only show open vulnerabilities")
    .option("--severity <severity>", "filter by severity")
    .option("--status <status>", "filter by status")
    .option("--limit <n>", "max results", "100")
    .action(
      async (
        opts: {
          open?: boolean;
          severity?: string;
          status?: string;
          limit: string;
        },
        cmd: Command,
      ) => {
        const globals = cmd.optsWithGlobals() as GlobalOpts;
        const { client } = requireAuth(globals);
        const status = opts.open ? "open" : opts.status;
        const { data } = await client.get("/vulnerabilities", {
          severity: opts.severity,
          status,
          limit: Math.max(1, Number(opts.limit) || 100),
        });
        const vulns = asList<Record<string, any>>(data, ["vulnerabilities"]);

        if (globals.json) {
          printJson(vulns);
          return;
        }
        if (!vulns.length) {
          console.log("no vulnerabilities");
          return;
        }
        printTable(
          ["Severity", "Name", "CVE", "Status", "Detected"],
          vulns.map((v) => [
            severityLabel(v.severity),
            truncate(v.name, 55),
            v.cveId ?? "-",
            v.status ?? "-",
            formatTime(v.timestamp ?? v.createdAt),
          ]),
        );
      },
    );
}
