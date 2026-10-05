/**
 * doctor — connectivity + credential self-check. Exit 1 on failure.
 */

import type { Command } from "commander";
import { ApiClient, CliError, type GlobalOpts } from "../client.js";
import { configExists, configPath, resolveAuth } from "../config.js";
import { checkMark, printJson } from "../output.js";
import { extractOrg } from "../util.js";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export function registerDoctor(program: Command): void {
  program
    .command("doctor")
    .description("Check config, connectivity, token validity, and scopes")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const checks: Check[] = [];
      const auth = resolveAuth(globals.profile);

      // 1. config present
      const hasConfig = configExists();
      checks.push({
        name: "config file",
        ok: hasConfig,
        detail: hasConfig ? configPath() : `missing — run \`rootwatch login\` (${configPath()})`,
      });

      // 2. credentials resolved
      checks.push({
        name: `profile '${auth.profile}'`,
        ok: !!auth.token,
        detail: auth.token ? auth.url : "no token — run `rootwatch login` or set ROOTWATCH_TOKEN",
      });

      // 3+4. reachable + token valid + scopes via GET /api/v1/org
      let org: ReturnType<typeof extractOrg> | null = null;
      if (auth.token) {
        const client = new ApiClient(auth.url, auth.token);
        try {
          const { data } = await client.get("/org");
          checks.push({
            name: "server reachable",
            ok: true,
            detail: `${auth.url} (GET /api/v1/org → 200)`,
          });
          checks.push({
            name: "token valid",
            ok: true,
            detail: "accepted",
          });
          org = extractOrg(data);
        } catch (e) {
          if (e instanceof CliError && e.code === "network") {
            checks.push({ name: "server reachable", ok: false, detail: e.message });
            checks.push({ name: "token valid", ok: false, detail: "could not verify — server unreachable" });
          } else {
            checks.push({ name: "server reachable", ok: true, detail: auth.url });
            checks.push({
              name: "token valid",
              ok: false,
              detail: e instanceof Error ? e.message : String(e),
            });
          }
        }
      } else {
        checks.push({ name: "server reachable", ok: false, detail: "skipped — no token" });
        checks.push({ name: "token valid", ok: false, detail: "skipped — no token" });
      }

      checks.push({
        name: "scopes",
        ok: !!org && org.scopes.length > 0,
        detail: org
          ? org.scopes.length
            ? org.scopes.join(", ")
            : "none reported"
          : "unavailable",
      });
      if (org?.name) {
        checks.push({
          name: "org",
          ok: true,
          detail: `${org.name}${org.id != null ? ` (#${org.id})` : ""}${org.role ? ` — role ${org.role}` : ""}`,
        });
      }

      const ok = checks.every((c) => c.ok);
      if (globals.json) {
        printJson({ ok, checks });
      } else {
        for (const c of checks) {
          console.log(`${checkMark(c.ok)} ${c.name} — ${c.detail}`);
        }
      }
      if (!ok) process.exit(1);
    });
}
