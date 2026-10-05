/**
 * scan.cjs resolveScanDir — the scan-root gate must hold against
 * realpath escapes: a cwd that lexically sits under $HOME but symlinks
 * outside it (~/link -> /) must be refused, as must prefix-sibling dirs
 * (/home/user2 vs /home/user).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { resolveScanDir } = require("../scan.cjs");

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rw-scanguard-"));
}

test("real dirs under home resolve", () => {
  const home = tmpdir();
  const proj = path.join(home, "proj", "inner");
  fs.mkdirSync(proj, { recursive: true });
  assert.equal(resolveScanDir(proj, home), fs.realpathSync(proj));
  // Home itself is allowed; missing dir defaults to home.
  assert.equal(resolveScanDir(home, home), fs.realpathSync(home));
  assert.equal(resolveScanDir(undefined, home), fs.realpathSync(home));
});

test("a symlink under home that escapes home is refused", () => {
  const home = tmpdir();
  const outside = tmpdir();
  fs.mkdirSync(path.join(outside, "sub"));
  const link = path.join(home, "link");
  fs.symlinkSync(outside, link);
  // Lexically ~/link passes a string-prefix check — realpath says otherwise.
  assert.throws(() => resolveScanDir(link, home), /under your home/);
  assert.throws(() => resolveScanDir(path.join(link, "sub"), home), /under your home/);
});

test("a symlink to / is refused — the reported escape", () => {
  const home = tmpdir();
  const link = path.join(home, "link");
  fs.symlinkSync("/", link);
  assert.throws(() => resolveScanDir(link, home), /under your home/);
});

test("prefix-sibling dirs are refused — sep boundary, not startsWith", () => {
  const base = tmpdir();
  const home = path.join(base, "user");
  const sibling = path.join(base, "user2");
  fs.mkdirSync(home);
  fs.mkdirSync(sibling);
  assert.throws(() => resolveScanDir(sibling, home), /under your home/);
});

test("a home that is itself a symlink still gates correctly", () => {
  const real = tmpdir();
  const homeLink = path.join(tmpdir(), "home-link");
  fs.symlinkSync(real, homeLink);
  const proj = path.join(homeLink, "proj");
  fs.mkdirSync(proj);
  assert.equal(resolveScanDir(proj, homeLink), fs.realpathSync(proj));
  const outside = tmpdir();
  assert.throws(() => resolveScanDir(outside, homeLink), /under your home/);
});
