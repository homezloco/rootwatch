/**
 * events — security event feed with --watch polling.
 */

import type { Command } from "commander";
import { requireAuth, type ApiClient, type GlobalOpts } from "../client.js";
import {
  printJson,
  printJsonLine,
  printTable,
  severityLabel,
} from "../output.js";
import { asList, formatTime, truncate } from "../util.js";

const WATCH_INTERVAL_MS = 10_000;

interface EventRow {
  id?: number | string;
  timestamp?: string;
  severity?: string;
  event?: string;
  source?: string;
  status?: string;
}

function eventRows(events: EventRow[]): string[][] {
  return events.map((e) => [
    formatTime(e.timestamp),
    severityLabel(e.severity),
    truncate(e.event, 60),
    truncate(e.source, 24),
    e.status ?? "-",
  ]);
}

const HEADERS = ["Timestamp", "Severity", "Event", "Source", "Status"];

async function fetchEvents(
  client: ApiClient,
  opts: { severity?: string; status?: string; limit: number },
): Promise<EventRow[]> {
  const { data } = await client.get("/events", {
    severity: opts.severity,
    status: opts.status,
    limit: opts.limit,
  });
  return asList<EventRow>(data, ["events"]);
}

function eventKey(e: EventRow): string {
  if (e.id != null) return `id:${e.id}`;
  return `${e.timestamp}|${e.event}|${e.source}`;
}

export function registerEvents(program: Command): void {
  program
    .command("events")
    .description("List security events")
    .option("--severity <severity>", "filter by severity (critical|high|medium|low)")
    .option("--status <status>", "filter by status")
    .option("--limit <n>", "max events", "50")
    .option("--watch", "poll every 10s and print new events")
    .action(
      async (
        opts: {
          severity?: string;
          status?: string;
          limit: string;
          watch?: boolean;
        },
        cmd: Command,
      ) => {
        const globals = cmd.optsWithGlobals() as GlobalOpts;
        const { client } = requireAuth(globals);
        const limit = Math.max(1, Number(opts.limit) || 50);
        const query = { severity: opts.severity, status: opts.status, limit };

        const initial = await fetchEvents(client, query);
        const seen = new Set(initial.map(eventKey));

        if (!opts.watch) {
          if (globals.json) {
            printJson(initial);
            return;
          }
          if (!initial.length) {
            console.log("no events");
            return;
          }
          printTable(HEADERS, eventRows(initial));
          return;
        }

        // --watch: initial batch, then only new rows each poll
        if (globals.json) {
          for (const e of initial) printJsonLine(e);
        } else {
          console.log(
            `watching for security events every ${WATCH_INTERVAL_MS / 1000}s — ctrl-c to stop`,
          );
          if (initial.length) printTable(HEADERS, eventRows(initial));
        }

        const timer = setInterval(async () => {
          try {
            const fresh = await fetchEvents(client, query);
            const newOnes = fresh.filter((e) => !seen.has(eventKey(e)));
            for (const e of newOnes) seen.add(eventKey(e));
            if (!newOnes.length) return;
            if (globals.json) {
              for (const e of newOnes) printJsonLine(e);
            } else {
              for (const row of eventRows(newOnes.reverse())) {
                console.log(row.join("  "));
              }
            }
          } catch (e) {
            console.error(
              `warning: poll failed: ${e instanceof Error ? e.message : e}`,
            );
          }
        }, WATCH_INTERVAL_MS);
        // Interval keeps the process alive until ctrl-c.
        void timer;
      },
    );
}
