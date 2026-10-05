/**
 * Secrets scanner — gitleaks-style regex rules over text files.
 *
 * IMPORTANT: findings never include the matched secret value.
 * Only ruleId + file + line are reported.
 */

import { readFileSync } from "node:fs";
import type { Severity } from "../util.js";
import type { ScannedFile } from "./walk.js";
import type { Finding } from "./index.js";

interface SecretRule {
  ruleId: string;
  severity: Severity;
  title: string;
  pattern: RegExp;
}

const RULES: SecretRule[] = [
  {
    ruleId: "secret/aws-access-key",
    severity: "Critical",
    title: "AWS access key ID",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    ruleId: "secret/github-token",
    severity: "Critical",
    title: "GitHub personal access token",
    pattern:
      /\b(?:github_pat_[A-Za-z0-9_]{22,}|gh[pousr]_[A-Za-z0-9]{20,})\b/,
  },
  {
    ruleId: "secret/private-key",
    severity: "Critical",
    title: "Private key material",
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
  },
  {
    ruleId: "secret/openai-api-key",
    severity: "High",
    title: "OpenAI-style API key (sk-…)",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    ruleId: "secret/generic-credential",
    severity: "High",
    title: "Hard-coded credential in source",
    pattern:
      /(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["'`][^"'`\n]{20,}["'`]/i,
  },
];

const MAX_PER_RULE_PER_FILE = 10;

/** Cheap binary check: NUL byte inside the first chunk => not text. */
function readText(path: string): string | null {
  let buf: Buffer;
  try {
    buf = readFileSync(path);
  } catch {
    return null;
  }
  if (buf.subarray(0, Math.min(buf.length, 1024)).includes(0)) return null;
  return buf.toString("utf8");
}

export function scanSecrets(files: ScannedFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    const text = readText(file.absPath);
    if (text === null) continue;
    const lines = text.split("\n");

    for (const rule of RULES) {
      let hits = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        // reset lastIndex defensively (patterns aren't global, but be safe)
        rule.pattern.lastIndex = 0;
        if (!rule.pattern.test(line)) continue;
        findings.push({
          ruleId: rule.ruleId,
          severity: rule.severity,
          title: rule.title,
          file: file.relPath,
          line: i + 1,
        });
        if (++hits >= MAX_PER_RULE_PER_FILE) break;
      }
    }
  }
  return findings;
}
