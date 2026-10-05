/**
 * Local host security checks for the "This Device" fleet report.
 *
 * A subset of server/services/security-checks.ts, ported to collector.cjs's
 * status helpers (firewallStatus / pendingUpdates / sshStatus). Same
 * pass/fail semantics as the server engine: an unevaluable probe
 * (unsupported platform, unreadable config) reports passed:true — the
 * engine treats "not evaluable" as pass/N-A, never a failure — and every
 * result carries an honest `detail` of what was actually observed.
 *
 * Result shape: {id, name, severity, passed, detail}. Severity is the
 * desktop contract's nominal severity for a failing result; passing
 * results report 'low' like the server engine. Linux-only — runLocalChecks
 * returns [] elsewhere (buildReport then reports only what it could
 * evaluate).
 */

const { existsSync } = require("node:fs");
const collector = require("./collector.cjs");

// Mirror of collectors.ts isContainerized — inside a container the host
// firewall isn't visible, so "no firewall" would be a false finding.
function isContainerized() {
  if (
    process.env.CONTAINER ||
    process.env.container ||
    process.env.RAILWAY_ENVIRONMENT ||
    process.env.KUBERNETES_SERVICE_HOST
  ) {
    return true;
  }
  try {
    return existsSync("/.dockerenv") || existsSync("/run/.containerenv");
  } catch {
    return false;
  }
}

async function checkFirewall() {
  const fw = await collector.firewallStatus();
  const base = { id: "firewall-active", name: "Firewall active" };
  if (!fw.supported) {
    if (isContainerized()) {
      return {
        ...base,
        severity: "low",
        passed: true,
        detail:
          "Containerized environment: the host firewall is not visible from inside the container. Perimeter policy is enforced by the platform edge.",
      };
    }
    return {
      ...base,
      severity: "medium",
      passed: false,
      detail:
        "No supported firewall tooling found (ufw/firewalld/iptables). Every process that binds a public address is internet-reachable — there is no host-level inbound policy.",
    };
  }
  if (fw.active === null) {
    // Backend present but status/config unreadable — a non-observation,
    // not an inactive ruleset.
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: `Firewall backend detected (${fw.backend}) but its state could not be evaluated — status and config are unreadable at this privilege level. Reporting unknown rather than failing.`,
    };
  }
  if (fw.active) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: `Firewall is active (backend: ${fw.backend}).`,
    };
  }
  return {
    ...base,
    severity: "high",
    passed: false,
    detail: `Firewall backend detected (${fw.backend}) but no active ruleset.`,
  };
}

async function checkPendingUpdates() {
  const updates = await collector.pendingUpdates();
  const base = { id: "pending-security-updates", name: "Pending security updates" };
  const pkgs = updates.packages ?? [];
  const secPkgs = updates.securityPackages ?? [];
  if (!updates.supported) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: "Could not determine pending updates (unsupported platform or package manager).",
    };
  }
  if (updates.count === 0) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: "System is up to date; no pending package updates.",
    };
  }
  // securityCount === null: the package manager can't classify updates —
  // fail on the total backlog rather than guess.
  if (updates.securityCount === null) {
    return {
      ...base,
      severity: "medium",
      passed: false,
      detail: `${updates.count} package update(s) pending via ${updates.manager} (unable to distinguish security updates): ${pkgs.slice(0, 10).join(", ")}${updates.count > 10 ? ", ..." : ""}`,
    };
  }
  if (updates.securityCount === 0) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: `No security updates pending. ${updates.count} non-security package update(s) available via ${updates.manager}: ${pkgs.slice(0, 10).join(", ")}${updates.count > 10 ? ", ..." : ""}`,
    };
  }
  return {
    ...base,
    severity: "medium",
    passed: false,
    detail: `${updates.securityCount} security update(s) pending via ${updates.manager}: ${secPkgs.slice(0, 10).join(", ")}${updates.securityCount > 10 ? ", ..." : ""} (${updates.count} total package updates pending)`,
  };
}

async function checkSshdRootLogin() {
  const ssh = await collector.sshStatus();
  const base = { id: "ssh-no-root-login", name: "SSH root login disabled" };
  if (!ssh.supported) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: "sshd configuration not readable; check not applicable.",
    };
  }
  const value = ssh.permitRootLogin ?? "prohibit-password"; // OpenSSH default
  if (value === "yes") {
    return {
      ...base,
      severity: "critical",
      passed: false,
      detail: 'PermitRootLogin is set to "yes"; direct root login over SSH is allowed.',
    };
  }
  return {
    ...base,
    severity: "low",
    passed: true,
    detail: `PermitRootLogin effective value: "${value}".`,
  };
}

async function checkSshdPasswordAuth() {
  const ssh = await collector.sshStatus();
  const base = { id: "ssh-password-auth-disabled", name: "SSH password authentication disabled" };
  if (!ssh.supported) {
    return {
      ...base,
      severity: "low",
      passed: true,
      detail: "sshd configuration not readable; check not applicable.",
    };
  }
  const value = ssh.passwordAuthentication ?? "yes"; // OpenSSH default
  if (value !== "no") {
    return {
      ...base,
      severity: "medium",
      passed: false,
      detail: `PasswordAuthentication effective value: "${value}"; key-based auth recommended.`,
    };
  }
  return {
    ...base,
    severity: "low",
    passed: true,
    detail: "PasswordAuthentication is disabled.",
  };
}

/**
 * Run the local check set. Read-only; never throws per-check — a check
 * that fails to execute reports as a passed check-error entry (same
 * semantics as the server engine's per-check catch).
 */
async function runLocalChecks() {
  if (process.platform !== "linux") return [];
  const checks = [checkFirewall, checkPendingUpdates, checkSshdRootLogin, checkSshdPasswordAuth];
  return Promise.all(
    checks.map(async (run) => {
      try {
        return await run();
      } catch (err) {
        return {
          id: "check-error",
          name: "Check execution error",
          severity: "low",
          passed: true,
          detail: `Check failed to execute: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }),
  );
}

module.exports = { runLocalChecks };
