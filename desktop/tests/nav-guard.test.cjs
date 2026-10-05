/**
 * nav-guard.cjs — the pure predicates behind will-navigate and
 * setWindowOpenHandler. Exact-origin allowlisting plus an http(s)-only
 * rule for handing URLs to the system browser.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { isAllowedOrigin, isExternallyOpenable } = require("../nav-guard.cjs");

const ORIGIN = "https://rootwatch.dev";

test("allowed origin matches exactly, including path prefixes", () => {
  assert.equal(isAllowedOrigin("https://rootwatch.dev", ORIGIN), true);
  assert.equal(isAllowedOrigin("https://rootwatch.dev/", ORIGIN), true);
  assert.equal(isAllowedOrigin("https://rootwatch.dev/projects?x=1", ORIGIN), true);
});

test("lookalike origins are denied — the prefix-match hole", () => {
  assert.equal(isAllowedOrigin("https://rootwatch.dev.evil.com", ORIGIN), false);
  assert.equal(isAllowedOrigin("https://rootwatch.devx.com", ORIGIN), false);
  assert.equal(isAllowedOrigin("https://rootwatch.dev:8443", ORIGIN), false); // different origin
  assert.equal(isAllowedOrigin("http://rootwatch.dev", ORIGIN), false); // scheme downgrade
  assert.equal(isAllowedOrigin("https://evil.com/?https://rootwatch.dev", ORIGIN), false);
  // userinfo can smuggle the origin string into a prefix
  assert.equal(isAllowedOrigin("https://rootwatch.dev@evil.com/", ORIGIN), false);
});

test("non-http schemes and malformed URLs are denied, not opened", () => {
  assert.equal(isAllowedOrigin("file:///etc/passwd", ORIGIN), false);
  assert.equal(isAllowedOrigin("javascript:alert(1)", ORIGIN), false);
  assert.equal(isAllowedOrigin("data:text/html,<b>x</b>", ORIGIN), false);
  assert.equal(isAllowedOrigin("not a url", ORIGIN), false);
  assert.equal(isAllowedOrigin("https://rootwatch.dev", null), false);
  assert.equal(isAllowedOrigin("https://rootwatch.dev", ""), false);
});

test("external-open fallback is http(s)-only", () => {
  assert.equal(isExternallyOpenable("https://example.com"), true);
  assert.equal(isExternallyOpenable("http://example.com"), true);
  assert.equal(isExternallyOpenable("file:///etc/passwd"), false);
  assert.equal(isExternallyOpenable("javascript:alert(1)"), false);
  assert.equal(isExternallyOpenable("data:text/html,<b>x</b>"), false);
  assert.equal(isExternallyOpenable("mailto:a@b.c"), false);
  assert.equal(isExternallyOpenable("not a url"), false);
});
