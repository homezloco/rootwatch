/**
 * login / logout / whoami
 */

import type { Command } from "commander";
import { createInterface, type Interface } from "node:readline";
import { ApiClient, CliError, requireAuth, type GlobalOpts } from "../client.js";
import {
  DEFAULT_URL,
  configPath,
  removeProfile,
  resolveAuth,
  saveProfile,
} from "../config.js";
import { info, printJson, printKv, success, warn } from "../output.js";
import { extractOrg } from "../util.js";

/**
 * Non-TTY stdin (pipes): read all lines up front. rl.question callbacks
 * never fire reliably for queued prompts on a closed pipe, which leaves
 * the action unsettled and the process exits silently.
 */
function readStdinLines(): Promise<string[]> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY || process.stdin.readableEnded) return resolve([]);
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (buf += c));
    process.stdin.on("end", () =>
      resolve(buf.split(/\r?\n/).map((l) => l.trim())),
    );
    process.stdin.on("error", () => resolve([]));
    process.stdin.resume();
  });
}

function ask(rl: Interface, prompt: string, fallback?: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      const v = answer.trim();
      resolve(v || (fallback ?? ""));
    });
  });
}

/** Token prompt that echoes `*` instead of the value when on a TTY. */
function askSecret(rl: Interface, prompt: string): Promise<string> {
  const w = (rl as unknown as { _writeToOutput?: (s: string) => void });
  const original = w._writeToOutput?.bind(rl);
  if (original && process.stdin.isTTY) {
    w._writeToOutput = (chunk: string) => {
      if (chunk.includes(prompt) || chunk === "\n" || chunk === "\r\n") {
        original(chunk);
      } else {
        original("*");
      }
    };
  }
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      if (original) w._writeToOutput = original;
      resolve(answer.trim());
    });
  });
}

export function registerAuth(program: Command): void {
  program
    .command("login")
    .description("Authenticate against a RootWatch instance")
    .option("--url <url>", "instance URL (default https://rootwatch.dev)")
    .option("--token <token>", "API token (rw_…)")
    .action(async (opts: { url?: string; token?: string }, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      // --profile names the profile to save under (falls back to env/default)
      const target = resolveAuth(globals.profile).profile;

      let url = opts.url;
      let token = opts.token;
      if (!url || !token) {
        if (process.stdin.isTTY) {
          const rl = createInterface({
            input: process.stdin,
            output: process.stdout,
            terminal: true,
          });
          try {
            if (!url)
              url = await ask(rl, `RootWatch URL [${DEFAULT_URL}]: `, DEFAULT_URL);
            if (!token) token = await askSecret(rl, "API token (rw_…): ");
          } finally {
            rl.close();
          }
        } else {
          // Piped input: first line = url (unless --url), next = token.
          const lines = (await readStdinLines()).filter((l) => l.length > 0);
          if (!url) url = lines.shift() || DEFAULT_URL;
          if (!token) token = lines.shift() ?? "";
        }
      }
      if (!token) {
        throw new CliError("an API token is required", {
          code: "usage",
          exitCode: 2,
        });
      }
      url = (url || DEFAULT_URL).replace(/\/+$/, "");

      // Verify the token before persisting anything.
      const client = new ApiClient(url, token);
      const { data } = await client.get("/org");
      const org = extractOrg(data);

      saveProfile(target, url, token);
      success(
        `✓ logged in to ${org.name ?? "organization"}${org.id != null ? ` (#${org.id})` : ""} at ${url}`,
      );
      info(`profile '${target}' saved to ${configPath()}`);
      if (globals.json) printJson({ profile: target, url, org });
    });

  program
    .command("logout")
    .description("Remove a stored profile")
    .action(async (_opts: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { profile } = resolveAuth(globals.profile);
      if (removeProfile(profile)) {
        success(`✓ removed profile '${profile}'`);
      } else {
        warn(`profile '${profile}' not found in ${configPath()}`);
      }
    });

  program
    .command("whoami")
    .description("Show the current org, token scopes, and active profile")
    .action(async (_opts: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client, auth } = requireAuth(globals);
      const { data } = await client.get("/org");
      const org = extractOrg(data);

      if (globals.json) {
        printJson({ profile: auth.profile, url: auth.url, ...org, raw: data });
        return;
      }
      printKv([
        ["Profile", auth.profile],
        ["URL", auth.url],
        ["Org", `${org.name ?? "-"}${org.id != null ? ` (#${org.id})` : ""}`],
        ["Role", org.role ?? "-"],
        ["Scopes", org.scopes.length ? org.scopes.join(", ") : "-"],
      ]);
    });
}
