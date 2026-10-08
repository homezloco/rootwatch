/**
 * keys.cjs guard tests — the credential-posture port must never leak a
 * secret value or an absolute home path into report items, and must never
 * throw on bad input (empty result / honest status objects only).
 *
 * Fixture homes live under tmpdir; scans run with skipProcEnv + a bounded
 * projectRoots so nothing host-real is read except where a test says so.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const keys = require("../keys.cjs");

const GH_PAT = "ghp_" + "a".repeat(36);
const AWS_ID = "AKIA" + "B".repeat(16);
const AWS_SECRET = "S".repeat(40);
const STRIPE = "sk_live_" + "c".repeat(24);
const PLANTED = [GH_PAT, AWS_ID, AWS_SECRET, STRIPE];

function fixtureHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "rw-keysguard-"));
  const write = (rel, content, mode) => {
    const abs = path.join(home, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
    if (mode !== undefined) fs.chmodSync(abs, mode);
    return abs;
  };
  write(
    ".aws/credentials",
    `[default]\naws_access_key_id = ${AWS_ID}\naws_secret_access_key = ${AWS_SECRET}\n`,
  );
  write("Development/app/.env", `GITHUB_TOKEN=${GH_PAT}\nSTRIPE_SECRET_KEY=${STRIPE}\n`);
  write(".zshrc", `export GITHUB_TOKEN=${GH_PAT}\n`);
  write(".bash_history", `curl -H "Authorization: token ${GH_PAT}" https://api.github.com\n`);
  write(
    ".ssh/id_ed25519",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nfakefakefake\n-----END OPENSSH PRIVATE KEY-----\n",
    0o644,
  );
  return home;
}

const SCAN_OPTS = { force: true, skipProcEnv: true, projectRoots: ["Development"] };

test("report items carry fingerprints and ~/… paths only — never a value", async () => {
  const home = fixtureHome();
  try {
    const records = await keys.listKeys({ ...SCAN_OPTS, homeDir: home });
    assert.ok(records.length >= 4, "expected aws/github/stripe/ssh findings");

    const items = keys.reportItems(records);
    assert.equal(items.length, records.length);
    for (const item of items) {
      const blob = JSON.stringify(item);
      for (const s of PLANTED) {
        assert.ok(!blob.includes(s), `secret material leaked into report item: ${blob}`);
      }
      // fp is the truncated keysha — bounded, hex only.
      assert.match(item.fp ?? "", /^[0-9a-f]{1,16}$/);
      for (const loc of item.locations) {
        assert.ok(loc.path.startsWith("~/"), `absolute path leaked into report item: ${loc.path}`);
        assert.ok(!loc.path.startsWith(home), `home dir leaked: ${loc.path}`);
      }
    }
    // last4 may legitimately carry the secret's tail — but never more than
    // 4 chars, and nothing else in the record is the value.
    for (const item of items) assert.ok((item.last4 ?? "").length <= 4);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("scan output itself never contains a planted value", async () => {
  const home = fixtureHome();
  try {
    const records = await keys.listKeys({ ...SCAN_OPTS, homeDir: home });
    const blob = JSON.stringify(records);
    for (const s of PLANTED) {
      assert.ok(!blob.includes(s), "secret material leaked into scan records");
    }
    // flags land: .bash_history hit → leakedToHistory; 0644 ssh key → worldReadable
    const gh = records.find((r) => r.provider === "github");
    assert.ok(gh?.flags?.leakedToHistory, "expected leakedToHistory on the gh pat");
    const priv = records.find((r) => r.kind === "private-key");
    assert.ok(priv?.flags?.worldReadable, "expected worldReadable on the 0644 ssh key");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("module never throws on bad input — empty results and honest statuses", async () => {
  // Missing/unreadable homes → empty scan, not an exception.
  assert.deepEqual(
    await keys.listKeys({ ...SCAN_OPTS, homeDir: "/nonexistent/rw-keysguard-missing" }),
    [],
  );
  assert.deepEqual(
    await keys.listKeys({ ...SCAN_OPTS, homeDir: path.join(os.devNull ?? "/dev/null") }),
    [],
  );

  // recoverSecret on nothing-recoverable → null.
  assert.equal(
    await keys.recoverSecret("0".repeat(64), [{ path: "~/missing", exposedVia: "file" }], {
      homeDir: "/nonexistent",
    }),
    null,
  );
  assert.equal(await keys.recoverSecret(null, null), null);

  // Malformed fingerprints → refused, never thrown.
  assert.equal((await keys.containKey("not-a-fingerprint")).status, "refused");
  assert.equal((await keys.probeKey("nope")).status, "refused");
  assert.equal((await keys.containKey("A".repeat(64))).status, "refused"); // uppercase ≠ hex-lower

  // Unknown-but-well-formed fingerprint → failed honestly (vault is empty
  // outside Electron; the re-scan finds nothing under a missing home).
  const missing = { scanOpts: { ...SCAN_OPTS, homeDir: "/nonexistent/rw-keysguard-missing" } };
  assert.equal((await keys.probeKey("0".repeat(64), missing)).status, "failed");
  assert.equal((await keys.containKey("0".repeat(64), missing)).status, "failed");

  // vaultList is metadata-only and never throws without a store.
  const vl = await keys.vaultList();
  assert.ok(Array.isArray(vl));
  assert.ok(vl.every((v) => !("sealed" in v) && !("value" in v)));
});

test("containing a whole-file credential refuses instead of rewriting", async () => {
  const home = fixtureHome();
  try {
    const scanOpts = { ...SCAN_OPTS, homeDir: home };
    const records = await keys.listKeys({ force: true, ...scanOpts });
    const priv = records.find((r) => r.kind === "private-key");
    assert.ok(priv, "expected a private-key record");

    // Remove mode → refused (whole-file credentials can't be line-stripped).
    const r = await keys.containKey(priv.fingerprint, { scanOpts });
    assert.equal(r.status, "refused");
    assert.match(r.message ?? "", /whole-file|cop(y|ies) only/i);

    // Copy mode still can't seal outside Electron (no OS keychain) —
    // the refusal is honest, not a fabricated success.
    const rc = await keys.containKey(priv.fingerprint, { copy: true, scanOpts });
    assert.equal(rc.status, "refused");

    // The file is untouched either way.
    const abs = path.join(home, ".ssh", "id_ed25519");
    assert.match(fs.readFileSync(abs, "utf8"), /PRIVATE KEY/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
