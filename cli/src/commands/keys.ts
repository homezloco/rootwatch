/**
 * keys — credential posture: the fingerprinted inventory of API keys /
 * tokens / private keys / passwords found on the monitored host.
 *
 * Remote commands ride GET/POST /api/v1/keys* (read/scan/write scopes) —
 * secret values never cross the wire, only sha256 fingerprints + last4.
 * `keys local` runs the same scanner directly on this machine with no
 * upload and no login (like `scan --no-upload`).
 */

import type { Command } from "commander";
import chalk from "chalk";
import { CliError, requireAuth, type GlobalOpts } from "../client.js";
import { printJson, printKv, printTable, success } from "../output.js";
import { formatTime, truncate } from "../util.js";
import { scanHostKeys, type KeyFlags } from "../scan/keyscan.js";

// Mirrors the /api/v1/keys contract — the CLI consumes it over the wire.
interface ApiKeyLocation {
  path?: string;
  line?: number;
  perm?: string;
  exposedVia?: string;
  proc?: string;
}

interface ApiKeyProbe {
  live?: boolean;
  detail?: string;
  balance?: string;
  scopes?: string[];
  checkedAt?: string;
}

/** Structural superset — local KeyRecord rows satisfy this too. */
interface KeyLike {
  provider?: string | null;
  kind?: string;
  label?: string | null;
  last4?: string;
  locations?: ApiKeyLocation[];
  flags?: KeyFlags;
  status?: string;
}

interface KeysResponse {
  supported?: boolean;
  reason?: string;
  count?: number;
  keys?: KeyLike[];
}

interface ProbeResponse {
  fingerprint?: string;
  probe?: ApiKeyProbe | null;
}

interface ContainResponse {
  fingerprint?: string;
  status?: string;
  message?: string;
}

interface ProbeAllResponse {
  supported?: boolean;
  reason?: string;
  probed?: number;
  live?: number;
  dead?: number;
  unknown?: number;
  skipped?: { notOpen?: number; noAdapter?: number; notBearer?: number };
  results?: {
    fingerprint?: string;
    provider?: string | null;
    label?: string | null;
    last4?: string | null;
    probe?: ApiKeyProbe | null;
  }[];
}

const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

function requireFingerprint(arg: string): string {
  if (!FINGERPRINT_RE.test(arg)) {
    throw new CliError(
      `invalid fingerprint '${arg}' — expected a 64-char sha256 hex (see 'rw keys')`,
      { code: "usage", exitCode: 2 },
    );
  }
  return arg;
}

function locationsCell(locations: ApiKeyLocation[] | undefined): string {
  const locs = locations ?? [];
  if (!locs.length) return "-";
  const first = truncate(locs[0]?.path ?? "-", 42);
  return locs.length === 1 ? first : `${locs.length}× ${first}`;
}

function flagsCell(flags: KeyFlags | undefined): string {
  if (!flags) return "-";
  const f: string[] = [];
  if (flags.committed) f.push(chalk.red("committed"));
  if (flags.worldReadable) f.push(chalk.yellow("world-readable"));
  if (flags.leakedToHistory) f.push(chalk.yellow("history"));
  if (flags.served) f.push(chalk.yellow(`served:${truncate(flags.served, 16)}`));
  if (flags.gitignored) f.push(chalk.dim("gitignored"));
  return f.length ? f.join(",") : "-";
}

const KEY_HEADERS = ["Provider", "Label", "Last4", "Kind", "Locations", "Flags", "Status"];

function keyRows(keys: KeyLike[]): string[][] {
  return keys.map((k) => [
    k.provider ?? "-",
    truncate(k.label, 28) || "-",
    k.last4 ? `…${k.last4}` : "-",
    k.kind ?? "-",
    locationsCell(k.locations),
    flagsCell(k.flags),
    k.status ?? "-",
  ]);
}

function printKeys(keys: KeyLike[]): void {
  if (!keys.length) {
    console.log("no credentials found");
    return;
  }
  printTable(KEY_HEADERS, keyRows(keys));
}

/** GET /keys and POST /keys/scan share the {supported, reason?, count, keys[]} shape. */
function renderKeysResponse(data: KeysResponse | null | undefined, globals: GlobalOpts): void {
  if (globals.json) {
    printJson(data);
    return;
  }
  if (data?.supported === false) {
    console.log(
      `credential posture not supported on this server${data.reason ? ` — ${data.reason}` : ""}`,
    );
    return;
  }
  printKeys(data?.keys ?? []);
}

async function runList(globals: GlobalOpts): Promise<void> {
  const { client } = requireAuth(globals);
  const { data } = await client.get<KeysResponse>("/keys");
  renderKeysResponse(data, globals);
}

async function runScan(globals: GlobalOpts): Promise<void> {
  const { client } = requireAuth(globals);
  const { data } = await client.post<KeysResponse>("/keys/scan", {});
  renderKeysResponse(data, globals);
}

async function runLocal(globals: GlobalOpts, skipProcEnv: boolean): Promise<void> {
  // Local-only: scanHostKeys never returns secret values and nothing is
  // uploaded — fingerprints + last4 + redacted locations only.
  const keys = await scanHostKeys({ skipProcEnv });
  if (globals.json) {
    printJson({ supported: true, count: keys.length, keys });
    return;
  }
  console.log(`local credential scan — nothing leaves this machine`);
  printKeys(keys);
}

async function runProbe(fp: string, globals: GlobalOpts): Promise<void> {
  const fingerprint = requireFingerprint(fp);
  const { client } = requireAuth(globals);
  const { data } = await client.post<ProbeResponse>(`/keys/${fingerprint}/probe`, {});
  if (globals.json) {
    printJson(data);
    return;
  }
  const probe = data?.probe ?? {};
  printKv([
    ["Fingerprint", fingerprint],
    [
      "Live",
      probe.live === true ? chalk.green("live") : probe.live === false ? chalk.red("dead") : "-",
    ],
    ["Detail", probe.detail ?? "-"],
    ["Balance", probe.balance != null ? String(probe.balance) : "-"],
    ["Scopes", Array.isArray(probe.scopes) && probe.scopes.length ? probe.scopes.join(", ") : "-"],
    ["Checked at", formatTime(probe.checkedAt)],
  ]);
}

async function runProbeAll(opts: { provider?: string }, globals: GlobalOpts): Promise<void> {
  const { client } = requireAuth(globals);
  const body: Record<string, unknown> = {};
  if (opts.provider) body.provider = opts.provider;
  const { data } = await client.post<ProbeAllResponse>("/keys/probe-all", body);
  if (globals.json) {
    printJson(data);
    return;
  }
  if (data?.supported === false) {
    console.log(
      `credential probing not supported on this server${data.reason ? ` — ${data.reason}` : ""}`,
    );
    return;
  }
  const live = data?.live ?? 0;
  const dead = data?.dead ?? 0;
  const unknown = data?.unknown ?? 0;
  success(
    `probed ${data?.probed ?? 0}: ${chalk.green(`${live} live`)}, ${chalk.red(`${dead} dead`)}, ${unknown} unknown`,
  );
  const skipped = data?.skipped ?? {};
  const skipParts = [
    skipped.notOpen ? `${skipped.notOpen} not open` : "",
    skipped.noAdapter ? `${skipped.noAdapter} no adapter` : "",
    skipped.notBearer ? `${skipped.notBearer} not bearer` : "",
  ].filter(Boolean);
  if (skipParts.length) {
    console.log(chalk.dim(`  skipped ${skipParts.join(", ")}`));
  }
  printTable(
    ["Verdict", "Provider", "Label", "Last4", "Detail"],
    (data?.results ?? []).map((r) => {
      const live = r.probe?.live;
      return [
        live === true ? chalk.green("LIVE") : live === false ? chalk.red("DEAD") : chalk.dim("?"),
        r.provider ?? "-",
        truncate(r.label, 28) || "-",
        r.last4 ? `…${r.last4}` : "-",
        truncate(r.probe?.detail ?? "-", 50),
      ];
    }),
  );
}

async function runContain(
  fp: string,
  opts: { copy?: boolean },
  globals: GlobalOpts,
): Promise<void> {
  const fingerprint = requireFingerprint(fp);
  const { client } = requireAuth(globals);
  const { data } = await client.post<ContainResponse>(`/keys/${fingerprint}/contain`, {
    copy: opts.copy === true,
  });
  if (globals.json) {
    printJson(data);
    return;
  }
  const status = data?.status ?? "done";
  const message = data?.message ? ` — ${data.message}` : "";
  success(`✓ ${status}${message}`);
}

export function registerKeys(program: Command): void {
  const keys = program
    .command("keys")
    .description(
      "Credential posture — fingerprinted inventory of API keys/credentials on the host (values never shown)",
    );

  keys
    .command("ls", { isDefault: true })
    .description("List discovered credentials (provider, label, last4, flags, status)")
    .action(async (_o: unknown, cmd: Command) => {
      await runList(cmd.optsWithGlobals() as GlobalOpts);
    });

  keys
    .command("scan")
    .description("Re-scan the host for exposed credentials now, bypassing the cache (scan scope)")
    .action(async (_o: unknown, cmd: Command) => {
      await runScan(cmd.optsWithGlobals() as GlobalOpts);
    });

  keys
    .command("probe <fingerprint>")
    .description(
      "Validate a credential against its provider API — liveness/scopes, never the key (write scope)",
    )
    .action(async (fingerprint: string, _o: unknown, cmd: Command) => {
      await runProbe(fingerprint, cmd.optsWithGlobals() as GlobalOpts);
    });

  keys
    .command("probe-all")
    .description("Bulk liveness check — probe every adapter-covered open credential (write scope)")
    .option("-p, --provider <provider>", "probe only this provider (e.g. stripe)")
    .action(async (opts: { provider?: string }, cmd: Command) => {
      await runProbeAll(opts, cmd.optsWithGlobals() as GlobalOpts);
    });

  keys
    .command("contain <fingerprint>")
    .description(
      "Seal a credential into the server vault and remove it from its plaintext file (write scope)",
    )
    .option("-c, --copy", "seal into the vault but leave the file untouched")
    .action(async (fingerprint: string, opts: { copy?: boolean }, cmd: Command) => {
      await runContain(fingerprint, opts, cmd.optsWithGlobals() as GlobalOpts);
    });

  keys
    .command("local")
    .description("Scan this machine for exposed credentials — no login, nothing uploaded")
    .option("--skip-proc-env", "skip the /proc/<pid>/environ pass (constrained environments)")
    .action(async (opts: { skipProcEnv?: boolean }, cmd: Command) => {
      await runLocal(cmd.optsWithGlobals() as GlobalOpts, opts.skipProcEnv === true);
    });
}
