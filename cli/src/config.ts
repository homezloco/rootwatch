/**
 * CLI config: ~/.config/rootwatch/config.json (mode 0600).
 *
 * Shape:
 *   { "defaultProfile": "default",
 *     "profiles": { "<name>": { "url": "https://rootwatch.dev", "token": "rw_..." } } }
 *
 * Profile precedence: --profile flag > ROOTWATCH_PROFILE env > defaultProfile.
 * Per-profile url/token are overridden by ROOTWATCH_URL / ROOTWATCH_TOKEN.
 * ROOTWATCH_CONFIG_DIR overrides the config directory (used by tests).
 */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { CliError } from "./client.js";

export const DEFAULT_URL = "https://rootwatch.dev";

export interface Profile {
  url: string;
  token?: string;
}

export interface CliConfig {
  defaultProfile: string;
  profiles: Record<string, Profile>;
}

export function configDir(): string {
  return (
    process.env.ROOTWATCH_CONFIG_DIR || join(homedir(), ".config", "rootwatch")
  );
}

export function configPath(): string {
  return join(configDir(), "config.json");
}

export function configExists(): boolean {
  return existsSync(configPath());
}

export function loadConfig(): CliConfig {
  const path = configPath();
  if (!existsSync(path)) {
    return { defaultProfile: "default", profiles: {} };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new CliError(
      `config file is corrupt: ${path} — fix it or delete it and run \`rootwatch login\``,
      { code: "config_corrupt" },
    );
  }
  const cfg = (parsed ?? {}) as Partial<CliConfig>;
  return {
    defaultProfile: cfg.defaultProfile || "default",
    profiles: cfg.profiles && typeof cfg.profiles === "object" ? cfg.profiles : {},
  };
}

export function saveConfig(cfg: CliConfig): void {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = configPath();
  writeFileSync(path, JSON.stringify(cfg, null, 2) + "\n", {
    mode: 0o600,
  });
  // Belt & suspenders for pre-existing files with looser perms.
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort */
  }
}

export interface ResolvedAuth {
  /** Effective profile name after flag/env/default precedence. */
  profile: string;
  url: string;
  token?: string;
  /** True when a stored profile (not just env vars) backs the resolution. */
  hasProfile: boolean;
}

export function resolveAuth(profileFlag?: string): ResolvedAuth {
  const cfg = loadConfig();
  const profile =
    profileFlag || process.env.ROOTWATCH_PROFILE || cfg.defaultProfile || "default";
  const stored = cfg.profiles[profile];
  const url = process.env.ROOTWATCH_URL || stored?.url || DEFAULT_URL;
  const token = process.env.ROOTWATCH_TOKEN || stored?.token;
  return {
    profile,
    url: url.replace(/\/+$/, ""),
    token,
    hasProfile: !!stored,
  };
}

export function saveProfile(name: string, url: string, token: string): CliConfig {
  const cfg = loadConfig();
  cfg.profiles[name] = { url: url.replace(/\/+$/, ""), token };
  if (!cfg.defaultProfile || !cfg.profiles[cfg.defaultProfile]) {
    cfg.defaultProfile = name;
  }
  saveConfig(cfg);
  return cfg;
}

/** Remove a profile. Returns false when it didn't exist. */
export function removeProfile(name: string): boolean {
  const cfg = loadConfig();
  if (!cfg.profiles[name]) return false;
  delete cfg.profiles[name];
  if (cfg.defaultProfile === name) {
    cfg.defaultProfile = Object.keys(cfg.profiles)[0] ?? "default";
  }
  saveConfig(cfg);
  return true;
}
