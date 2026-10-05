"use strict";
/**
 * Navigation gating for the BrowserWindow — kept electron-free so the
 * predicates are unit-testable and shared verbatim between will-navigate
 * and setWindowOpenHandler (drift between the two was a real bug class).
 */

/**
 * Is `url` on the configured instance? Exact origin equality — a prefix
 * match would let https://rootwatch.dev.evil.com load inside the window
 * with full preload IPC. Parse failure denies.
 */
function isAllowedOrigin(url, allowedOrigin) {
  if (typeof allowedOrigin !== "string" || !allowedOrigin) return false;
  try {
    return new URL(String(url)).origin === allowedOrigin;
  } catch {
    return false;
  }
}

/**
 * May `url` be handed to the system browser? Only http/https — file:,
 * javascript:, data: and other schemes are silently dropped (the
 * navigation itself is still denied either way).
 */
function isExternallyOpenable(url) {
  try {
    const u = new URL(String(url));
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

module.exports = { isAllowedOrigin, isExternallyOpenable };
