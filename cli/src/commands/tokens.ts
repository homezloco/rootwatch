/**
 * org tokens list|create|revoke — admin-scope token management via
 * /api/v1/tokens (added with device enrollment; requires an 'admin'-scope
 * caller token).
 */

import type { Command } from "commander";
import { CliError, requireAuth, type ApiClient, type GlobalOpts } from "../client.js";
import { printJson, printTable, success } from "../output.js";
import { asList, extractScopes, formatTime } from "../util.js";

const NEEDS_ADMIN =
  "token management requires an 'admin'-scope API token — create one in the " +
  "web dashboard (Org Settings → API tokens) or via an existing admin token";

async function adminGate(client: ApiClient): Promise<void> {
  const { data } = await client.get("/org");
  const scopes = extractScopes(data);
  // Only hard-block when the server actually reports scopes and admin is absent.
  if (scopes.length > 0 && !scopes.includes("admin")) {
    throw new CliError(NEEDS_ADMIN, { code: "forbidden" });
  }
}

async function tokensCall<T>(
  client: ApiClient,
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  try {
    const res = await client.raw<T>(method, path, { body });
    return res.data;
  } catch (e) {
    if (e instanceof CliError && (e.status === 401 || e.status === 403)) {
      throw new CliError(NEEDS_ADMIN, { code: "forbidden" });
    }
    throw e;
  }
}

interface TokenRow {
  id?: number | string;
  name?: string;
  scopes?: string[] | string;
  createdAt?: string;
  lastUsedAt?: string;
  revokedAt?: string | null;
}

export function registerOrg(program: Command): void {
  const org = program.command("org").description("Organization management");
  const tokens = org
    .command("tokens")
    .description("Manage API tokens (admin scope)");

  tokens
    .command("list")
    .description("List API tokens for the org")
    .action(async (_o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      await adminGate(client);
      const data = await tokensCall<unknown>(client, "GET", "/api/v1/tokens");
      const rows = asList<TokenRow>(data);
      if (globals.json) {
        printJson(rows);
        return;
      }
      if (!rows.length) {
        console.log("no tokens");
        return;
      }
      printTable(
        ["ID", "Name", "Scopes", "Created", "Last used", "Status"],
        rows.map((t) => [
          String(t.id ?? "-"),
          t.name ?? "-",
          Array.isArray(t.scopes) ? t.scopes.join(",") : String(t.scopes ?? "-"),
          formatTime(t.createdAt),
          formatTime(t.lastUsedAt),
          t.revokedAt ? "revoked" : "active",
        ]),
      );
    });

  tokens
    .command("create")
    .description("Create an API token")
    .requiredOption("--name <name>", "token name")
    .option("--scopes <scopes>", "comma-separated scopes (read,write,scan,admin)", "read")
    .action(async (opts: { name: string; scopes?: string }, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      await adminGate(client);
      const scopes = (opts.scopes ?? "read")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const data = await tokensCall<Record<string, any>>(
        client,
        "POST",
        "/api/v1/tokens",
        { name: opts.name, scopes },
      );
      if (globals.json) {
        printJson(data);
        return;
      }
      success(`✓ created token '${opts.name}' (id ${data?.id ?? "?"})`);
      if (data?.token) {
        console.log(`token: ${data.token}`);
        console.log("store it somewhere safe — it won't be shown again.");
      }
    });

  tokens
    .command("revoke <id>")
    .description("Revoke an API token by id")
    .action(async (id: string, _o: unknown, cmd: Command) => {
      const globals = cmd.optsWithGlobals() as GlobalOpts;
      const { client } = requireAuth(globals);
      if (!/^\d+$/.test(id)) {
        throw new CliError(`invalid token id '${id}'`, {
          code: "usage",
          exitCode: 2,
        });
      }
      await adminGate(client);
      await tokensCall(client, "DELETE", `/api/v1/tokens/${id}`);
      success(`✓ revoked token ${id}`);
    });
}
