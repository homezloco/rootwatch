"use strict";
// connect.html's form logic — external file because the page CSP is
// `default-src 'self'` (no inline scripts). The `rootwatch` bridge is
// exposed by preload.cjs.
const $ = (id) => document.getElementById(id);
(async () => {
  const conn = await window.rootwatch.getConnection();
  $("url").value = conn.url;
  $("encNote").textContent = conn.encryptionAvailable
    ? "Stored encrypted via your OS keychain. Generate at Org Settings → API tokens (read scope suffices)."
    : "No OS keychain detected — token will be kept in memory for this session only.";
})();
$("go").addEventListener("click", async () => {
  $("go").disabled = true;
  $("err").textContent = "";
  $("ok").textContent = "Checking instance…";
  const res = await window.rootwatch.saveConnection({
    url: $("url").value,
    token: $("token").value,
  });
  $("go").disabled = false;
  if (!res.ok) {
    $("ok").textContent = "";
    $("err").textContent = res.error;
  }
});
$("token").addEventListener("keydown", (e) => e.key === "Enter" && $("go").click());
