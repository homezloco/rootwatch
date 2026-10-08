#!/usr/bin/env node
/**
 * rootwatch / rw — RootWatch dev security control panel CLI.
 */

import { Command, CommanderError } from "commander";
import { CLI_VERSION, CliError } from "./client.js";
import { error } from "./output.js";
import { registerAuth } from "./commands/auth.js";
import { registerStatus } from "./commands/status.js";
import { registerEvents } from "./commands/events.js";
import { registerVulns } from "./commands/vulns.js";
import { registerListeners } from "./commands/listeners.js";
import { registerKeys } from "./commands/keys.js";
import { registerRemediations } from "./commands/remediations.js";
import { registerScan } from "./commands/scan.js";
import { registerOrg } from "./commands/tokens.js";
import { registerDoctor } from "./commands/doctor.js";
import { runMcpServer } from "./mcp.js";

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("rootwatch")
    .description("RootWatch — the dev security control panel CLI")
    .version(CLI_VERSION)
    .option("--json", "output raw JSON")
    .option("--profile <name>", "config profile to use")
    .showHelpAfterError()
    .exitOverride();

  registerAuth(program);
  registerStatus(program);
  registerEvents(program);
  registerVulns(program);
  registerListeners(program);
  registerKeys(program);
  registerRemediations(program);
  registerScan(program);
  registerOrg(program);
  registerDoctor(program);

  program
    .command("mcp")
    .description("Run a stdio MCP server backed by this instance (for AI agents)")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as { profile?: string };
      await runMcpServer(globals.profile);
    });

  return program;
}

// Downstream pipe closed early (e.g. `| head`) — exit quietly.
process.stdout.on("error", (e: NodeJS.ErrnoException) => {
  if (e.code === "EPIPE") process.exit(0);
  throw e;
});

async function main(): Promise<void> {
  const program = buildProgram();
  try {
    await program.parseAsync(process.argv);
  } catch (e) {
    if (e instanceof CommanderError) {
      // help/version exit 0; usage errors exit 2
      process.exit(e.exitCode === 0 ? 0 : 2);
    }
    throw e;
  }
}

main().catch((e: unknown) => {
  if (e instanceof CliError) {
    error(e.message);
    process.exit(e.exitCode);
  }
  error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
