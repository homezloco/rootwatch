#!/usr/bin/env node
/**
 * RootWatch fleet agent — zero-dependency host posture reporter.
 *
 * Reads this host's real state (ports, firewall, sshd config, pending
 * updates, metrics), computes the same check verdicts the server rule
 * engine produces, and POSTs a snapshot to the control plane's
 * POST /api/v1/devices/report.
 *
 * The report response may deliver commands (refresh/update/uninstall/
 * apply-updates/fix-check/stop-listener/remediate) which are executed once
 * and reported back in a single follow-up report; an HTTP 401/403 means the
 * credential was revoked → self-uninstall.
 *
 * Env: CONTROL_PLANE_URL, CONTROL_PLANE_TOKEN (org rw_… token, write scope)
 * Runs via systemd timer; safe to run standalone for testing:
 *   CONTROL_PLANE_URL=... CONTROL_PLANE_TOKEN=... node agent.mjs
 */
import { execFile, execFileSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { closeSync, copyFileSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readlinkSync, readSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

const exec = promisify(execFile);
const URL_ = (process.env.CONTROL_PLANE_URL || '').replace(/\/+$/, '');
const TOKEN = process.env.CONTROL_PLANE_TOKEN || '';
const AGENT_VERSION = '8';
const SELF_PATH = fileURLToPath(import.meta.url);
// Android via Termux: $PREFIX points into the app's private dir and there
// is no systemd, /etc/machine-id, or root — collectors degrade honestly.
// The dir-existence fallback catches cron jobs where $PREFIX isn't set.
const IS_TERMUX =
  (process.env.PREFIX || '').includes('com.termux') ||
  existsSync('/data/data/com.termux/files/usr');
const TERMUX_PREFIX = process.env.PREFIX || '/data/data/com.termux/files/usr';
const COMMON_PUBLIC_PORTS = new Set([22, 53, 80, 443, 853]);

const run = async (cmd, args, opts = {}) => {
  try {
    const { stdout } = await exec(cmd, args, { timeout: 8000, ...opts });
    return stdout;
  } catch {
    return null;
  }
};

/* ------------------------------- collectors ----------------------------- */

function classifyBind(addr) {
  const a = (addr || '').trim().replace(/^\[|\]$/g, '');
  if (!a || a === '0.0.0.0' || a === '::' || a === '*') return 'public';
  if (a === 'localhost' || a === '::1' || a.startsWith('127.')) return 'loopback';
  if (a.startsWith('100.')) {
    const o = Number(a.split('.')[1]);
    return o >= 64 && o <= 127 ? 'tailscale' : 'public';
  }
  if (a.startsWith('10.') || a.startsWith('192.168.') || a.startsWith('169.254.')) return 'private';
  if (a.startsWith('172.')) {
    const o = Number(a.split('.')[1]);
    return o >= 16 && o <= 31 ? 'private' : 'public';
  }
  const low = a.toLowerCase();
  if (low.startsWith('fd') || low.startsWith('fc')) return 'tailscale';
  if (low.startsWith('fe80') || low.startsWith('ff')) return 'private';
  return 'public';
}

async function hostInfo() {
  let distro = '', release = '', platform = 'linux', hostname = os.hostname();
  if (IS_TERMUX) {
    platform = 'android';
    distro = 'Android';
    release = (await run('getprop', ['ro.build.version.release']))?.trim() || '';
    // Android hostnames are usually 'localhost' — try net.hostname first,
    // then the device model so the fleet row is identifiable.
    hostname = (await run('getprop', ['net.hostname']))?.trim() || hostname;
    if (!hostname || hostname === 'localhost') {
      hostname = (await run('getprop', ['ro.product.model']))?.trim() || hostname;
    }
  } else {
    try {
      const osr = await readFile('/etc/os-release', 'utf8');
      distro = (osr.match(/^NAME="?([^"\n]+)"?/m) || [])[1] || '';
      release = (osr.match(/^VERSION_ID="?([^"\n]+)"?/m) || [])[1] || '';
    } catch {}
  }
  let uptime = 0;
  try { uptime = Math.floor(Number((await readFile('/proc/uptime', 'utf8')).split(' ')[0])); } catch {}
  return { hostname, os: [distro, release].filter(Boolean).join(' '), platform, uptimeSeconds: uptime };
}

async function machineId() {
  let basis = os.hostname();
  try {
    const mid = (await readFile('/etc/machine-id', 'utf8')).trim();
    if (mid) basis = mid;
  } catch {}
  if (IS_TERMUX) {
    // No /etc/machine-id and hostnames are often 'localhost' — persist a
    // random id so devices don't collapse onto one identity.
    const idFile = path.join(TERMUX_PREFIX, 'etc', 'rootwatch-agent-id');
    try {
      const saved = (await readFile(idFile, 'utf8')).trim();
      if (saved) basis = saved;
    } catch {
      try {
        const generated = randomBytes(16).toString('hex');
        writeFileSync(idFile, generated + '\n', { mode: 0o600 });
        basis = generated;
      } catch { /* keep hostname basis — unwritable prefix */ }
    }
  }
  return createHash('sha256').update(`rootwatch-host:${basis}`).digest('hex');
}

async function listeners() {
  // -p adds users:(("name",pid=…,fd=…)) attribution where our privileges
  // allow: root sees every socket's owner, an unprivileged agent only its
  // own uid's — the rest stay process:null (never guessed). Minimal ss
  // builds lacking -p fall back to the unattributed scan.
  const out = (await run('ss', ['-tlnuHp'])) ?? (await run('ss', ['-tlnuH']));
  if (out == null) return [];
  const ports = [];
  const seen = new Set();
  for (const line of out.split('\n')) {
    const m = line.match(/^\s*(tcp|udp)\s+.*\s+(\S+):(\d+)\s/);
    if (!m) continue;
    const key = `${m[1]}:${m[2]}:${m[3]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    ports.push({
      port: Number(m[3]), protocol: m[1], address: m[2],
      process: line.match(/users:\(\("([^"]+)"/)?.[1] ?? null,
    });
  }
  return ports;
}

async function firewall() {
  const ufw = await run('ufw', ['status']);
  if (ufw != null) {
    return { supported: true, backend: 'ufw', active: /Status:\s*active/i.test(ufw) };
  }
  // ufw may exist but deny unprivileged reads — fall back to its config file
  try {
    const conf = await readFile('/etc/ufw/ufw.conf', 'utf8');
    return { supported: true, backend: 'ufw', active: /^ENABLED=yes/m.test(conf) };
  } catch {}
  const fwd = await run('firewall-cmd', ['--state']);
  if (fwd != null) return { supported: true, backend: 'firewalld', active: /running/.test(fwd) };
  const ipt = await run('iptables', ['-S']);
  if (ipt != null) {
    const hasRules = ipt.split('\n').some((l) => l.startsWith('-A ') || l.startsWith('-P INPUT DROP'));
    return { supported: true, backend: 'iptables', active: hasRules };
  }
  return { supported: false, backend: null, active: false };
}

// OpenSSH semantics: global Include expansion, first-match wins, stop at Match.
async function sshSettings() {
  const mainPath = '/etc/ssh/sshd_config';
  if (!existsSync(mainPath)) return { supported: false };
  const settings = {};
  const seen = new Set();
  const parseFile = async (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    let text;
    try { text = await readFile(file, 'utf8'); } catch { return; }
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const [kw, ...rest] = line.split(/\s+/);
      const val = rest.join(' ');
      const k = kw.toLowerCase();
      if (k === 'include') {
        for (const pat of val.split(/\s+/)) {
          const abs = pat.startsWith('/') ? pat : path.join('/etc/ssh', pat);
          const dir = path.dirname(abs), base = path.basename(abs);
          let names = [];
          try { names = await readdir(dir); } catch { continue; }
          for (const n of names.sort()) {
            if (base === '*') {
              if (n.endsWith('.conf')) await parseFile(path.join(dir, n));
            } else if (n === base) await parseFile(path.join(dir, n));
          }
        }
        continue;
      }
      if (k === 'match') return; // global scope ends
      if (!(k in settings)) settings[k] = val;
    }
  };
  await parseFile(mainPath);
  return {
    supported: true,
    permitRootLogin: settings.permitrootlogin ?? null,
    passwordAuthentication: settings.passwordauthentication ?? null,
    port: Number(settings.port) || 22,
  };
}

async function sshServiceActive() {
  for (const svc of ['ssh', 'sshd']) {
    const out = await run('systemctl', ['is-active', svc]);
    if (out && out.trim() === 'active') return true;
  }
  return null;
}

// Which sshd unit does systemd know? 'ssh' on Debian-family, 'sshd' on
// Fedora-family — probed via LoadState, never guessed from the distro name
// ('masked' still names the real unit — a plan could unmask it). null when
// there's no systemd or no ssh unit; the control plane falls back to an
// OS-family guess only then.
async function sshUnitName() {
  for (const svc of ['ssh', 'sshd']) {
    const st = (await run('systemctl', ['show', `${svc}.service`, '-p', 'LoadState', '--value']))?.trim();
    if (st === 'loaded' || st === 'masked') return svc;
  }
  return null;
}

async function pendingUpdates() {
  const apt = await run('apt', ['list', '--upgradable']);
  if (apt != null) {
    const lines = apt.split('\n').filter((l) => l.includes('/') && !l.startsWith('Listing'));
    const sec = lines.filter((l) => /-(security|stable-security|proposed-security)\//.test(l) || /security/i.test(l.split('/')[1] || ''));
    return { supported: true, manager: 'apt', count: lines.length, securityCount: sec.length, packages: lines.map((l) => l.split('/')[0]).slice(0, 50) };
  }
  const dnf = await run('dnf', ['check-update', '-q']);
  if (dnf != null) {
    const lines = dnf.split('\n').filter((l) => /\S+\s+\S+\s+\S+/.test(l) && !l.startsWith(' '));
    return { supported: true, manager: 'dnf', count: lines.length, securityCount: null, packages: lines.map((l) => l.split(/\s+/)[0]).slice(0, 50) };
  }
  return { supported: false };
}

async function failedLogins() {
  const j = await run('journalctl', ['-u', 'ssh', '-u', 'sshd', '--since', '-60 min', '--no-pager', '-q']);
  if (j != null) {
    const failed = j.split('\n').filter((l) => /Failed password|Invalid user|Connection closed by authenticating/.test(l));
    return { supported: true, count: failed.length, source: 'journalctl' };
  }
  try {
    const log = await readFile('/var/log/auth.log', 'utf8');
    const cutoff = Date.now() - 3600e3;
    const count = log.split('\n').filter((l) => /Failed password|Invalid user/.test(l) && new Date(l.slice(0, 15)).getTime() > cutoff - 86400e3 * 365).length;
    return { supported: true, count, source: 'auth.log' };
  } catch {}
  return { supported: false, count: 0 };
}

// Is '/' backed by a LUKS (type 'crypt') device? lsblk -J on util-linux
// >=2.37; older versions fall back to plain tree parse. {supported:false}
// when the root device can't be resolved (containers, no lsblk).
async function diskEncryption() {
  const j = await run('lsblk', ['-J', '-o', 'NAME,TYPE,MOUNTPOINTS']);
  if (j != null) {
    try {
      const chain = [];
      const walk = (devs) => {
        for (const d of devs) {
          chain.push(d);
          const mps = [d.mountpoints, d.mountpoint].flat().filter(Boolean);
          if (mps.includes('/') || (d.children && walk(d.children))) return true;
          chain.pop();
        }
        return false;
      };
      if (walk(JSON.parse(j).blockdevices || [])) {
        return { supported: true, encrypted: chain.some((d) => d.type === 'crypt') };
      }
    } catch {}
  }
  const plain = await run('lsblk', ['-n', '-o', 'NAME,TYPE,MOUNTPOINT']);
  if (plain == null) return { supported: false };
  // tree depth = width of the glyph/space prefix before the device name
  const stack = [];
  let rootChain = null;
  for (const line of plain.split('\n')) {
    const m = line.match(/^([^\w/]*)(\S+)\s+(\S+)\s*(\S*)\s*$/);
    if (!m) continue;
    const depth = m[1].length >> 1;
    stack.length = depth;
    stack[depth] = m[3];
    if (m[4] === '/') rootChain = stack.slice(0, depth + 1);
  }
  if (!rootChain) return { supported: false };
  return { supported: true, encrypted: rootChain.includes('crypt') };
}

// Automatic security updates: apt → APT::Periodic::Unattended-Upgrade "1" in
// apt.conf.d (that's the actual on-switch unattended-upgrades reads); dnf →
// dnf-automatic.timer enabled or active. Unsupported pkg manager → not supported.
async function autoSecurityUpdates() {
  // Termux keeps its apt config under $PREFIX/etc.
  for (const aptDir of ['/etc/apt/apt.conf.d', `${TERMUX_PREFIX}/etc/apt/apt.conf.d`]) {
    if (!existsSync(aptDir)) continue;
    let enabled = false;
    try {
      for (const f of await readdir(aptDir)) {
        const text = await readFile(path.join(aptDir, f), 'utf8').catch(() => '');
        if (/APT::Periodic::Unattended-Upgrade\s+"?1"?\s*;/.test(text)) enabled = true;
      }
    } catch {}
    return { supported: true, manager: 'apt', enabled };
  }
  if (existsSync('/etc/dnf') || existsSync('/etc/yum')) {
    const en = (await run('systemctl', ['is-enabled', 'dnf-automatic.timer']))?.trim();
    const act = (await run('systemctl', ['is-active', 'dnf-automatic.timer']))?.trim();
    return { supported: true, manager: 'dnf', enabled: en === 'enabled' || act === 'active' };
  }
  return { supported: false };
}

async function sudoersState() {
  const files = ['/etc/sudoers'];
  try {
    for (const f of await readdir('/etc/sudoers.d')) {
      if (!f.startsWith('.') && !f.endsWith('~')) files.push(path.join('/etc/sudoers.d', f));
    }
  } catch {}
  for (const f of files) {
    const text = await readFile(f, 'utf8').catch(() => null);
    if (text == null) continue;
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (line && !line.startsWith('#') && /\bNOPASSWD\s*:/i.test(line)) return { nopasswd: true };
    }
  }
  return { nopasswd: false };
}

function dockerSocketPerms() {
  try {
    const st = statSync('/var/run/docker.sock');
    return { present: true, worldWritable: (st.mode & 0o002) !== 0 };
  } catch {
    return { present: false, worldWritable: false };
  }
}

function worldWritablePathDirs() {
  const bad = [];
  for (const dir of new Set((process.env.PATH || '').split(':').filter(Boolean))) {
    try {
      const st = statSync(dir);
      if (st.isDirectory() && (st.mode & 0o002)) bad.push(dir);
    } catch {}
  }
  return bad;
}

// Installed package inventory — the bandwidth-heavy field, sent on a
// cadence rather than every report. Probes the manager that actually
// answers; dpkg covers Debian/Ubuntu and Termux (dpkg under $PREFIX).
// null = no known manager → the report omits the field entirely.
const PKG_CAP = 5000;
function pkgTsv(out) {
  const items = [];
  for (const line of out.split('\n')) {
    const tab = line.indexOf('\t');
    if (tab < 1) continue;
    items.push({ name: line.slice(0, tab).trim(), version: line.slice(tab + 1).trim() });
  }
  return items;
}
async function packageInventory() {
  const opts = { timeout: 30000 };
  const dpkg = await run('dpkg-query', ['-W', '-f=${Package}\t${Version}\n'], opts);
  if (dpkg != null) {
    const items = pkgTsv(dpkg).slice(0, PKG_CAP);
    return IS_TERMUX
      ? { manager: 'termux', ecosystem: 'termux', items }
      : { manager: 'apt', ecosystem: 'debian', items };
  }
  const apk = await run('apk', ['info', '-v'], opts);
  if (apk != null) {
    const items = [];
    for (const line of apk.split('\n')) {
      // apk -v prints 'name-version' — version starts at the last dash
      // followed by a digit (busybox-1.36.1-r2 → 1.36.1-r2).
      const m = line.trim().match(/^(.+)-(\d.*)$/);
      if (m) items.push({ name: m[1], version: m[2] });
    }
    return { manager: 'apk', ecosystem: 'alpine', items: items.slice(0, PKG_CAP) };
  }
  const rpm = await run('rpm', ['-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n'], opts);
  if (rpm != null) return { manager: 'rpm', ecosystem: 'rhel', items: pkgTsv(rpm).slice(0, PKG_CAP) };
  return null;
}

// Mandatory access control: SELinux via getenforce or sysfs enforce flag,
// AppArmor via aa-status or the securityfs profiles list. {supported:false}
// where neither subsystem is observable (Termux, most containers).
async function macStatus() {
  let selinux = null; // 'enforcing' | 'permissive' | 'disabled'
  const ge = (await run('getenforce'))?.trim().toLowerCase();
  if (ge === 'enforcing' || ge === 'permissive' || ge === 'disabled') selinux = ge;
  else {
    try {
      selinux = (await readFile('/sys/fs/selinux/enforce', 'utf8')).trim() === '1' ? 'enforcing' : 'permissive';
    } catch {}
  }
  let apparmor = null; // 'enforcing' | 'loaded-not-enforcing'
  const aa = await run('aa-status');
  if (aa != null && /apparmor module is loaded/i.test(aa)) {
    const enforceProfiles = Number(aa.match(/(\d+)\s+profiles?\s+(?:are|is)\s+in\s+enforce\s+mode/i)?.[1] ?? 0);
    apparmor = enforceProfiles > 0 ? 'enforcing' : 'loaded-not-enforcing';
  }
  if (apparmor == null) {
    try {
      const profs = await readFile('/sys/kernel/security/apparmor/profiles', 'utf8');
      const lines = profs.split('\n').filter((l) => l.trim());
      if (lines.length > 0) {
        apparmor = lines.some((l) => /\(enforce\)\s*$/.test(l)) ? 'enforcing' : 'loaded-not-enforcing';
      }
    } catch {}
  }
  return {
    supported: selinux != null || apparmor != null,
    selinux,
    apparmor,
    enforcing: selinux === 'enforcing' || apparmor === 'enforcing',
  };
}

// Clock sync: timedatectl on systemd hosts, chronyc where chronyd runs
// without systemd. {supported:false} when neither tool exists (Termux).
async function timeSyncState() {
  const t = await run('timedatectl', ['show', '-p', 'NTPSynchronized', '--value']);
  if (t != null) return { supported: true, synced: t.trim() === 'yes', source: 'timedatectl' };
  const c = await run('chronyc', ['tracking']);
  // exit 0 means chronyd answered; 'Not synchronised' leap status means it
  // answered but isn't actually synced — report that honestly.
  if (c != null) return { supported: true, synced: !/not synchronised/i.test(c), source: 'chronyc' };
  return { supported: false, synced: false };
}

// PASS_MAX_DAYS from /etc/login.defs — the aging policy applied at password
// change. Unreadable file (Termux, minimal containers) → supported:false;
// missing/unparseable directive → maxDays:null (policy not configured → fails).
async function passwordAging() {
  let text;
  try { text = await readFile('/etc/login.defs', 'utf8'); }
  catch { return { supported: false, maxDays: null }; }
  let maxDays = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^PASS_MAX_DAYS\s+(\S+)/);
    if (!m) continue;
    const n = Number(m[1]);
    if (Number.isFinite(n)) maxDays = n; // last occurrence wins
  }
  return { supported: true, maxDays };
}

// /proc/sys/kernel/tainted — nonzero means the kernel flagged proprietary
// modules, an oops, forced loads, etc. Unreadable (Android/Termux) →
// supported:false.
async function kernelTainted() {
  try {
    const value = (await readFile('/proc/sys/kernel/tainted', 'utf8')).trim();
    return { supported: true, tainted: value !== '0', value };
  } catch {
    return { supported: false, tainted: false };
  }
}

// FIM-lite: hash a fixed set of security-critical files every report so the
// control plane can diff by path presence + sha256 + mtime (an absent entry
// means the file was unreadable/missing — never a fabricated hash). Watched
// files are tiny, so sync I/O is fine and keeps the payload deterministic.
const FILE_HASH_CAP = 64;
function watchedFilePaths() {
  const paths = [];
  const dirFiles = (dir) => {
    try {
      for (const name of readdirSync(dir)) {
        const p = path.join(dir, name);
        try { if (statSync(p).isFile()) paths.push(p); } catch {}
      }
    } catch {}
  };
  if (IS_TERMUX) {
    const etc = `${TERMUX_PREFIX}/etc`;
    paths.push(`${etc}/passwd`, `${etc}/crontab`, `${etc}/ssh/sshd_config`, `${etc}/sudoers`);
    dirFiles(`${etc}/cron.d`);
    dirFiles(`${etc}/sudoers.d`);
  } else {
    paths.push(
      '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
      '/etc/ssh/sshd_config', '/etc/ld.so.preload', '/etc/crontab',
    );
    dirFiles('/etc/sudoers.d');
    dirFiles('/etc/cron.d');
    // readable-check is implicit: an unreadable root key is skipped below
    paths.push('/root/.ssh/authorized_keys');
  }
  const home = os.homedir();
  if (home) paths.push(path.join(home, '.ssh', 'authorized_keys'));
  // Sorted + deduped so the cap skips extras deterministically.
  return [...new Set(paths)].sort().slice(0, FILE_HASH_CAP);
}
function watchedFileHashes() {
  const files = [];
  for (const p of watchedFilePaths()) {
    try {
      const st = statSync(p);
      if (!st.isFile()) continue;
      files.push({
        path: p,
        sha256: createHash('sha256').update(readFileSync(p)).digest('hex'),
        mtime: Math.round(st.mtimeMs),
      });
    } catch { /* unreadable/missing — omitted; server diffs by path */ }
  }
  // supported:false is the honest "nothing could be hashed" signal — the
  // field still ships so the server sees capability, not silence.
  return { supported: files.length > 0, files };
}

// Known rootkit artifact paths — a curated subset of the osquery
// 'ossec-rootkit' pack plus classic dot-dir tricks ('/...' hides in plain
// `ls` output). Pure existence checks, so this probe is supported on every
// platform — on Termux these paths legitimately don't exist and it passes.
const ROOTKIT_ARTIFACT_PATHS = [
  '/.sauto', '/.tmp', '/...',
  '/bin/imin', '/bin/imout',
  '/dev/ptyxx', '/dev/tux', '/dev/wd4',
  '/etc/rc.d/rsha',
  '/tmp/kidd0', '/tmp/kidd0.c', '/tmp/xp',
  '/usr/bin/ssh2d', '/usr/bin/xchk', '/usr/bin/xsf',
  '/usr/include/chk.h', '/usr/include/cron.h',
  '/usr/lib/.egcs', '/usr/lib/.kinetic', '/usr/lib/.wormie', '/usr/lib/liblog.o',
];
function rootkitArtifacts() {
  return { supported: true, found: ROOTKIT_ARTIFACT_PATHS.filter((p) => existsSync(p)) };
}

// Android device posture — only meaningful on Termux; returns null on
// regular Linux so the android-* check family reports
// passed:true + supported:false instead of probing Android-only facilities.
// getprop lives at /system/bin/getprop (on the default Termux PATH). Every
// probe degrades to null/absent: an unreadable value is "not evaluable"
// (→ supported:false on the check), never an assumed pass or failure.
const ANDROID_PROPS = [
  'ro.debuggable', 'ro.secure', 'ro.boot.verifiedbootstate',
  'ro.boot.flash.locked', 'service.adb.tcp.port', 'init.svc.adbd',
  'ro.kernel.qemu', 'ro.hardware', 'ro.build.version.security_patch',
  'ro.build.tags', 'ro.product.model',
  // the ART native-bridge prop riru/zygisk-family injectors hijack —
  // '0'/unset on stock, a loader .so path when something is hooked in
  'ro.dalvik.vm.native.bridge',
];
async function androidPosture() {
  if (!IS_TERMUX) return null;
  const props = {};
  await Promise.all(ANDROID_PROPS.map(async (name) => {
    const v = (await run('getprop', [name]))?.trim();
    props[name] = v || null; // missing/empty → null ("can't read it")
  }));
  const suPath = (await run('which', ['su']))?.trim() || null;
  const magiskPaths = [];
  for (const p of ['/data/adb/magisk', '/sbin/.magisk']) {
    // existsSync already collapses EACCES → false; the try/catch keeps that
    // contract explicit — an unreadable path is honestly reported absent.
    try { if (existsSync(p)) magiskPaths.push(p); } catch {}
  }
  const pmPath = await run('pm', ['path', 'com.topjohnwu.magisk']);
  const magiskApp = pmPath != null && /package:\s*\S+/.test(pmPath);
  const pkgList = await run('pm', ['list', 'packages']);
  const rootishPackages = pkgList == null ? [] : [...new Set(
    pkgList.split('\n')
      .map((l) => l.trim().replace(/^package:/, ''))
      .filter((n) => /magisk|zygisk|lsposed|riru|kernelsu|shizuku/i.test(n)),
  )];
  // ro.build.version.security_patch is YYYY-MM-DD; missing/unparseable →
  // patchAgeDays stays null → the patch-age check reports supported:false.
  let patchAgeDays = null;
  const pm_ = props['ro.build.version.security_patch']?.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (pm_ && Number(pm_[2]) >= 1 && Number(pm_[2]) <= 12 && Number(pm_[3]) >= 1 && Number(pm_[3]) <= 31) {
    patchAgeDays = Math.floor((Date.now() - Date.UTC(Number(pm_[1]), Number(pm_[2]) - 1, Number(pm_[3]))) / 86400000);
  }
  return { props, suPath, magiskPaths, magiskApp, rootishPackages, patchAgeDays };
}

function metrics() {
  const load = os.loadavg();
  const memTotal = os.totalmem(), memFree = os.freemem();
  let diskPercent = null;
  try {
    const df = execFileSync('df', ['-k', '/'], { timeout: 5000 }).toString();
    diskPercent = Number(df.split('\n')[1]?.match(/(\d+)%/)?.[1]) || null;
  } catch {}
  const cores = os.cpus().length || 1;
  return {
    cpuPercent: Math.min(100, Math.round((load[0] / cores) * 100)),
    memPercent: Math.round(((memTotal - memFree) / memTotal) * 100),
    diskPercent,
  };
}

/* ------------------------------ detections ------------------------------ */
// On-device detection engine — two real-observation sources:
//   1. /proc/<pid>/cmdline sweep (Linux + Termux; procfs exists on both)
//   2. bounded tail of auth-relevant logs since the last run (rootful
//      Linux only — skipped silently on Termux)
// Every detection carries the actual observed line/cmdline it matched
// (truncated to 200 chars) — nothing inferred, nothing fabricated. The
// report always includes `detections` ([] = "scanned, found nothing"),
// capped at 50 per report.
const DETECTION_CAP = 50;
const PROC_SCAN_CAP = 5000;
const LOG_READ_CAP = 256 * 1024;
const SEEN_DETECTIONS_CAP = 500;
const EVIDENCE_LEN = 200;
const AUTH_LOG_PATHS = ['/var/log/auth.log', '/var/log/secure', '/var/log/audit/audit.log'];

// cmdline regexes. `[^|]*` guards keep a pipeline's later stages from
// making an earlier innocent stage match.
const PROC_RULES = [
  {
    rule: 'reverse-shell', name: 'Reverse shell pattern in process cmdline',
    severity: 'critical', mitre: ['T1059', 'T1071'],
    patterns: [
      /\bbash\s+-i\b/,
      /\/dev\/tcp\//,
      /\bnc\b[^|]*\s-e\s/,
      /\bncat\b[^|]*--exec/,
      /\bsocat\b[^|]*EXEC:/,
    ],
  },
  {
    rule: 'pipe-to-shell', name: 'Download piped into a shell',
    severity: 'high', mitre: ['T1059'],
    patterns: [
      /(curl|wget)\b[^|]*(\||&&|;)\s*(sudo\s+)?(bash|sh|zsh)\b/,
      /\b(bash|sh)\s+-c[^|]*\b(curl|wget)\b/,
    ],
  },
  {
    rule: 'b64-pipe-exec', name: 'Base64-decoded payload piped into a shell',
    severity: 'high', mitre: ['T1027', 'T1059'],
    patterns: [/\bbase64\b[^|]*(-d|--decode)[^|]*(\||&&|;)\s*(bash|sh|zsh)\b/],
  },
  {
    rule: 'suid-abuse', name: 'SUID bit set via chmod',
    severity: 'medium', mitre: ['T1548.001'],
    patterns: [/\bchmod\b[^|]*\b(u\+s|4[0-7]{3})\b/],
  },
  {
    rule: 'miner-suspect', name: 'Known miner binary running',
    severity: 'high', mitre: ['T1496'],
    patterns: [/\b(xmrig|minerd|kdevtmpfsi|kinsing|cpuminer)\b/i],
  },
];

const LOG_RULES = [
  {
    rule: 'root-ssh-login', name: 'Accepted SSH login for root',
    severity: 'high', mitre: ['T1078', 'T1133'],
    patterns: [/Accepted \S+ for root\b/],
  },
  {
    rule: 'new-user-added', name: 'New local user account created',
    severity: 'medium', mitre: ['T1136.001'],
    patterns: [/\b(useradd|adduser)\b.*\bnew user\b/, /useradd.*account/],
  },
  {
    rule: 'sudo-abuse', name: 'Sudo misuse or authentication abuse',
    severity: 'high', mitre: ['T1548.003'],
    patterns: [/\bsudo\b.*\bNOT in sudoers\b/, /sudo:.*authentication failure.*consecutive/],
  },
  {
    rule: 'audit-log-tamper', name: 'Audit subsystem shutdown or disabled',
    severity: 'critical', mitre: ['T1070.002'],
    patterns: [/auditd.*(rotate|log file).*(?:shutdown|stopped)/, /audit.*disabled/],
  },
];

// Source 1 — /proc sweep. Bounded: own pid skipped, PROC_SCAN_CAP entries
// max, every read failure tolerated (procs exit mid-scan constantly).
// Persistent processes would re-fire every tick, so matches are deduped
// by rule + sha256(cmdline) through state.seenDetections.
function scanProcessCmdlines(pushDetection) {
  let entries;
  try { entries = readdirSync('/proc'); } catch { return; }
  let scanned = 0;
  for (const name of entries) {
    if (scanned >= PROC_SCAN_CAP) break;
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    if (pid === process.pid) continue;
    scanned++;
    const base = `/proc/${pid}`;
    let exeTarget = null;
    try { exeTarget = readlinkSync(`${base}/exe`); } catch {}
    let cmdline = '';
    try { cmdline = readFileSync(`${base}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ').trim(); } catch {}
    if (!cmdline) {
      try { cmdline = readFileSync(`${base}/comm`, 'utf8').trim(); } catch {}
    }
    // Running a deleted executable — the same check the server's malware
    // engine runs on the host, extended here to agented devices. The
    // subject of the observation is the exe target, so it keys the dedup.
    if (exeTarget && exeTarget.endsWith(' (deleted)')) {
      const key = `proc-hidden-exe:${createHash('sha256').update(`${exeTarget}|${cmdline}`).digest('hex').slice(0, 12)}`;
      pushDetection(
        { rule: 'proc-hidden-exe', name: 'Process running a deleted executable', severity: 'high', mitre: ['T1055', 'T1620'], evidence: `${exeTarget} ${cmdline}` },
        key,
      );
    }
    if (!cmdline) continue; // kernel thread / zombie — nothing real to match
    for (const r of PROC_RULES) {
      if (!r.patterns.some((p) => p.test(cmdline))) continue;
      const key = `${r.rule}:${createHash('sha256').update(cmdline).digest('hex').slice(0, 12)}`;
      pushDetection({ rule: r.rule, name: r.name, severity: r.severity, mitre: r.mitre, evidence: cmdline }, key);
    }
  }
}

// Source 2 — auth log tail. Per-file {inode, offset} persisted in the
// state file; inode change or size shrink = rotated → restart at 0.
// At most LOG_READ_CAP new bytes per file per run — when more arrived,
// the LAST cap bytes are read (tail-bounded). Returns filesRead so the
// journalctl fallback only engages when no file source is readable.
function tailAuthLogFiles(state) {
  const offsets = state.logOffsets;
  const chunks = [];
  let filesRead = 0;
  for (const file of AUTH_LOG_PATHS) {
    let st;
    try { st = statSync(file); } catch { continue; }
    if (!st.isFile()) continue;
    let fd;
    try { fd = openSync(file, 'r'); } catch { continue; }
    try {
      filesRead++;
      const prev = offsets[file];
      let start = prev && prev.inode === st.ino && st.size >= prev.offset ? prev.offset : 0;
      if (st.size - start > LOG_READ_CAP) start = st.size - LOG_READ_CAP;
      const len = st.size - start;
      let read = 0;
      if (len > 0) {
        const buf = Buffer.alloc(len);
        read = readSync(fd, buf, 0, len, start);
        if (read > 0) chunks.push(buf.subarray(0, read).toString('utf8'));
      }
      offsets[file] = { inode: st.ino, offset: start + read };
    } catch {
      // mid-read failure — leave offsets untouched so the lines retry
    } finally {
      try { closeSync(fd); } catch {}
    }
  }
  return { text: chunks.join('\n'), filesRead };
}

// Fallback when no log file is readable: journald's ssh units since the
// last run (root only — an unprivileged journal view omits sshd). Output
// tail-bounded like the file path. state.lastLogTs is the high-water mark.
async function tailJournal(state) {
  const since = Number.isFinite(state.lastLogTs) && state.lastLogTs > 0
    ? state.lastLogTs
    : Math.floor(Date.now() / 1000) - 600; // first run: one agent cadence back
  const out = await run('journalctl', [
    '-o', 'cat', '--no-pager', '-u', 'sshd', '-u', 'ssh', '--since', `@${since}`,
  ], { maxBuffer: 4 * 1024 * 1024 });
  if (out == null) return '';
  state.lastLogTs = Math.floor(Date.now() / 1000);
  return out.length > LOG_READ_CAP ? out.slice(-LOG_READ_CAP) : out;
}

async function scanAuthLogs(state, pushDetection) {
  if (IS_TERMUX) return; // no system logs on Termux — honest skip, not an error
  let { text, filesRead } = tailAuthLogFiles(state);
  if (filesRead === 0 && isRoot()) text = await tailJournal(state);
  if (!text) return;
  let failed = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (line.includes('Failed password')) failed++;
    for (const r of LOG_RULES) {
      if (!r.patterns.some((p) => p.test(line))) continue;
      // no dedup key — file offsets guarantee each line is seen once
      pushDetection({ rule: r.rule, name: r.name, severity: r.severity, mitre: r.mitre, evidence: line });
    }
  }
  if (failed >= 20) {
    // a batch-level signal can't dedup via offsets — key on the hour bucket
    pushDetection(
      { rule: 'auth-flood', name: 'Authentication failure flood', severity: 'high', mitre: ['T1110'], evidence: `${failed} failed auth attempts in window` },
      `auth-flood:${Math.floor(Date.now() / 3600e3)}`,
    );
  }
}

// Runs both sources against the persisted offset/dedup bookkeeping. The
// state object is mutated in memory; saveAgentState only persists after a
// successful POST, so a lost report replays the same findings next tick
// rather than silently dropping them.
async function collectDetections(state) {
  const st = state && typeof state === 'object' ? state : {};
  if (!st.logOffsets || typeof st.logOffsets !== 'object') st.logOffsets = {};
  if (!Array.isArray(st.seenDetections)) st.seenDetections = [];
  const seen = new Set(st.seenDetections);
  const detections = [];
  const pushDetection = (d, dedupKey) => {
    if (detections.length >= DETECTION_CAP) return;
    if (dedupKey != null) {
      if (seen.has(dedupKey)) return;
      seen.add(dedupKey);
      st.seenDetections.push(dedupKey);
      if (st.seenDetections.length > SEEN_DETECTIONS_CAP) {
        st.seenDetections.splice(0, st.seenDetections.length - SEEN_DETECTIONS_CAP); // FIFO
      }
    }
    detections.push({
      rule: d.rule,
      name: d.name,
      severity: d.severity,
      mitre: d.mitre,
      evidence: String(d.evidence ?? '').trim().slice(0, EVIDENCE_LEN),
    });
  };
  scanProcessCmdlines(pushDetection);
  await scanAuthLogs(st, pushDetection);
  return detections;
}

/* ------------------------------ check engine ---------------------------- */

function runChecks({ fw, ssh, sshUp, ports, updates, failed, disk, autoUpd, sudoers, dockerSock, pathDirs, mac, ntp, aging, tainted, rootkits, android }) {
  const results = [];
  const pub = ports.filter((p) => classifyBind(p.address) === 'public' && !COMMON_PUBLIC_PORTS.has(p.port));
  const dockerTcp = ports.filter((p) => p.port === 2375 && classifyBind(p.address) !== 'loopback');
  // `details` carries the observed evidence behind a verdict — shipped only
  // for failing checks (the report maps failing[] to {id,name,severity,
  // details}) so the control plane can build concrete remediation proposals.
  // Listener entries mirror the server's "<port>/<proto> on <bind> (<proc>)"
  // clause format — remediation.ts's LISTENER_ENTRY parses it verbatim.
  const portClause = (list) => list.slice(0, 15)
    .map((p) => `${p.port}/${p.protocol} on ${p.address}${p.process ? ` (${p.process})` : ''}`)
    .join(', ') + (list.length > 15 ? ` …and ${list.length - 15} more` : '');
  // Internal binds ride the same informational clause the host check emits —
  // deliberately WITHOUT " on <bind>" so the server's parser can never map
  // LAN-only entries into stop/firewall proposals.
  const internalListeners = ports.filter((p) =>
    ['private', 'tailscale'].includes(classifyBind(p.address)) && !COMMON_PUBLIC_PORTS.has(p.port));
  const internalNote = internalListeners.length
    ? ` Internal-only listeners (LAN/tailnet): ${internalListeners.slice(0, 15).map((p) => `${p.port}/${p.protocol}${p.process ? ` (${p.process})` : ''}`).join(', ')}.`
    : '';
  // Android posture inputs — `android` is null off-Termux, so every
  // android-* check below lands passed:true + supported:false there.
  const adbTcpPort = android?.props['service.adb.tcp.port'];
  const adbExposed = adbTcpPort != null && adbTcpPort !== '0'
    && android.props['init.svc.adbd'] === 'running';
  const nativeBridge = android?.props['ro.dalvik.vm.native.bridge'];
  const injectedBridge = nativeBridge != null && nativeBridge !== '0'; // riru/zygisk-family signal
  const rootDetected = android != null && (
    Boolean(android.suPath) || android.magiskPaths.length > 0 ||
    android.magiskApp || android.rootishPackages.length > 0 || injectedBridge
  );
  const emuHw = android?.props['ro.hardware'];
  const emulator = android != null && (
    android.props['ro.kernel.qemu'] === '1' ||
    (emuHw != null && /emu|ranchu|goldfish|vbox|geny/i.test(emuHw))
  );
  results.push(
    { id: 'pending-security-updates', name: 'Pending security updates', passed: !updates.supported || (updates.securityCount ?? 0) === 0, severity: 'medium',
      details: updates.supported
        ? `${updates.count ?? 0} upgradeable package(s) via ${updates.manager}${updates.securityCount != null ? ` (${updates.securityCount} security)` : ''}${updates.packages?.length ? `: ${updates.packages.slice(0, 15).join(', ')}` : ''}`
        : undefined },
    { id: 'firewall-active', name: 'Firewall active', passed: !fw.supported || fw.active, severity: 'high',
      details: fw.supported ? `backend=${fw.backend} active=${fw.active}` : 'no supported firewall backend detected (ufw/firewalld/iptables)' },
    { id: 'ssh-no-root-login', name: 'SSH root login disabled', passed: !ssh.supported || (ssh.permitRootLogin ?? 'prohibit-password') !== 'yes', severity: 'high',
      details: ssh.supported ? `PermitRootLogin=${ssh.permitRootLogin ?? 'prohibit-password (default)'}` : undefined },
    { id: 'ssh-password-auth-disabled', name: 'SSH password authentication disabled', passed: !ssh.supported || (ssh.passwordAuthentication ?? 'yes') === 'no', severity: 'low',
      details: ssh.supported ? `PasswordAuthentication=${ssh.passwordAuthentication ?? 'yes (default)'}` : undefined },
    { id: 'failed-login-spike', name: 'Failed login spike', passed: !failed.supported || failed.count < 20, severity: 'medium',
      details: failed.supported ? `${failed.count} failed SSH login(s) observed in the last ~hour (${failed.source})` : undefined },
    { id: 'docker-socket-tcp', name: 'Docker socket not exposed on TCP', passed: dockerTcp.length === 0, severity: 'critical',
      details: dockerTcp.length ? `dockerd API exposed on ${portClause(dockerTcp)}` : undefined },
    { id: 'unusual-listeners', name: 'Unusual public listeners', passed: pub.length === 0, severity: 'medium',
      details: pub.length ? `Non-whitelisted ports reachable from public addresses: ${portClause(pub)}.${internalNote}` : undefined },
    { id: 'disk-encryption', name: 'Disk encryption on root filesystem', passed: !disk.supported || disk.encrypted === true, severity: 'medium',
      details: disk.supported ? `root filesystem on LUKS-encrypted device=${disk.encrypted === true}` : undefined },
    { id: 'auto-security-updates', name: 'Automatic security updates', passed: !autoUpd.supported || autoUpd.enabled, severity: 'medium',
      details: autoUpd.supported ? `enabled=${autoUpd.enabled} (${autoUpd.manager})` : undefined },
    { id: 'sudo-nopasswd', name: 'No passwordless sudo rules', passed: !sudoers.nopasswd, severity: 'high',
      details: sudoers.nopasswd ? 'a sudoers file grants NOPASSWD' : undefined },
    { id: 'docker-socket-perms', name: 'Docker socket not world-writable', passed: !dockerSock.worldWritable, severity: 'high',
      details: dockerSock.present ? `/var/run/docker.sock worldWritable=${dockerSock.worldWritable}` : undefined },
    { id: 'path-world-writable', name: 'No world-writable directories in PATH', passed: pathDirs.length === 0, severity: 'high',
      details: pathDirs.length ? `world-writable PATH directories: ${pathDirs.join(', ')}` : undefined },
    // Unsupported probes report passed:true + supported:false — "can't
    // evaluate" is never a failure (server compliance map: absent = pass).
    { id: 'mac-enforcing', name: 'SELinux/AppArmor enforcing', passed: !mac.supported || mac.enforcing, severity: 'medium', supported: mac.supported,
      details: mac.supported ? `selinux=${mac.selinux ?? 'n/a'} apparmor=${mac.apparmor ?? 'n/a'}` : undefined },
    { id: 'time-synced', name: 'System clock synchronized', passed: !ntp.supported || ntp.synced, severity: 'low', supported: ntp.supported,
      details: ntp.supported ? `synchronized=${ntp.synced} (${ntp.source})` : undefined },
    { id: 'password-aging', name: 'Password aging policy configured', passed: !aging.supported || (aging.maxDays != null && aging.maxDays > 0 && aging.maxDays <= 365), severity: 'medium', supported: aging.supported,
      details: aging.supported ? `PASS_MAX_DAYS=${aging.maxDays ?? 'unset'}` : undefined },
    { id: 'kernel-tainted', name: 'Kernel not tainted', passed: !tainted.supported || !tainted.tainted, severity: 'low', supported: tainted.supported,
      details: tainted.supported ? `tainted=${tainted.tainted} (flags '${tainted.value}')` : undefined },
    // Detection only — never add to FIXABLE_CHECKS.
    { id: 'rootkit-artifacts', name: 'No known rootkit artifacts', passed: rootkits.found.length === 0, severity: 'critical', supported: true,
      details: rootkits.found.length ? `artifact paths present: ${rootkits.found.join(', ')}` : undefined },
    // Android posture family — all gated on IS_TERMUX via the collector
    // (null → supported:false + passed:true on Linux). On Termux a missing
    // getprop value additionally means "not evaluable" → supported:false;
    // props that ARE readable produce real verdicts.
    { id: 'android-debuggable', name: 'Android build not debuggable', passed: android?.props['ro.debuggable'] !== '1', severity: 'high', supported: Boolean(android && android.props['ro.debuggable'] != null),
      details: android ? `ro.debuggable=${android.props['ro.debuggable'] ?? 'unreadable'}` : undefined },
    { id: 'android-verified-boot', name: 'Verified boot enabled', passed: android?.props['ro.boot.verifiedbootstate'] == null || android.props['ro.boot.verifiedbootstate'] === 'green', severity: 'high', supported: Boolean(android && android.props['ro.boot.verifiedbootstate'] != null),
      details: android ? `ro.boot.verifiedbootstate=${android.props['ro.boot.verifiedbootstate'] ?? 'unreadable'}` : undefined },
    { id: 'android-bootloader-locked', name: 'Bootloader locked', passed: android?.props['ro.boot.flash.locked'] == null || android.props['ro.boot.flash.locked'] === '1', severity: 'high', supported: Boolean(android && android.props['ro.boot.flash.locked'] != null),
      details: android ? `ro.boot.flash.locked=${android.props['ro.boot.flash.locked'] ?? 'unreadable'}` : undefined },
    { id: 'android-adb-exposed', name: 'ADB not exposed on network', passed: !adbExposed, severity: 'medium', supported: Boolean(android && (android.props['service.adb.tcp.port'] != null || android.props['init.svc.adbd'] != null)),
      details: adbExposed ? `adbd running on tcp port ${adbTcpPort}` : undefined },
    { id: 'android-root-detected', name: 'Device not rooted', passed: !rootDetected, severity: 'medium', supported: IS_TERMUX,
      details: rootDetected
        ? `signals: ${[
            android.suPath && `su binary at ${android.suPath}`,
            android.magiskPaths.length && `magisk dirs (${android.magiskPaths.join(', ')})`,
            android.magiskApp && 'magisk app installed',
            android.rootishPackages.length && `root packages (${android.rootishPackages.join(', ')})`,
            injectedBridge && `native bridge=${nativeBridge}`,
          ].filter(Boolean).join('; ')}`
        : undefined },
    { id: 'android-patch-age', name: 'Android security patch current', passed: android?.patchAgeDays == null || android.patchAgeDays <= 90, severity: 'medium', supported: Boolean(android && android.patchAgeDays != null),
      details: android?.patchAgeDays != null ? `security patch is ${android.patchAgeDays} days old` : undefined },
    { id: 'android-emulator', name: 'Not an emulator', passed: !emulator, severity: 'low', supported: Boolean(android && (android.props['ro.kernel.qemu'] != null || android.props['ro.hardware'] != null)),
      details: android ? `ro.kernel.qemu=${android.props['ro.kernel.qemu'] ?? 'unreadable'} ro.hardware=${emuHw ?? 'unreadable'}` : undefined },
  );
  return results;
}

/* --------------------------------- enroll --------------------------------- */
// `RW_ENV_FILE=/path node agent.mjs enroll <control-url>`
// Starts code-based pairing: prints a code + approval URL, polls until a
// human (or admin token) approves it on the control plane, then writes the
// minted token to the env file (or stdout).

async function enroll(url, envFile) {
  const host = await hostInfo();
  const res = await fetch(`${url}/api/v1/enroll/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostname: host.hostname, os: host.os }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    console.error(`enroll start failed: HTTP ${res.status}`);
    process.exit(1);
  }
  const { code, secret, verifyUrl, expiresAt } = await res.json();
  console.log(`\n  Enrollment code:  ${code}`);
  console.log(`  Approve this device at: ${verifyUrl}\n`);
  console.log('Waiting for approval…');

  const deadline = Math.min(Date.now() + 15 * 60e3, new Date(expiresAt).getTime());
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000));
    const c = await fetch(`${url}/api/v1/enroll/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, secret }),
      signal: AbortSignal.timeout(15_000),
    }).catch(() => null);
    if (!c) continue;
    if (c.status === 202) continue; // still pending
    if (!c.ok) {
      const body = await c.json().catch(() => ({}));
      console.error(`enrollment ${body?.error?.message || `rejected: HTTP ${c.status}`}`);
      process.exit(1);
    }
    const { token } = await c.json();
    deliverToken(url, token, envFile);
    return;
  }
  console.error('enrollment timed out — run again for a new code');
  process.exit(1);
}

async function deliverToken(url, token, envFile) {
  if (envFile) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(envFile, `CONTROL_PLANE_URL=${url}\nCONTROL_PLANE_TOKEN=${token}\n`, { mode: 0o600 });
    console.log(`enrolled — credentials written to ${envFile}`);
  } else {
    console.log(`\nApproved. Save these as env vars for the reporter:\n\n  CONTROL_PLANE_URL=${url}\n  CONTROL_PLANE_TOKEN=${token}\n`);
  }
}

// `RW_ENV_FILE=/path node agent.mjs claim <url> <code> <secret>`
// One-shot claim of a pre-authorized bootstrap enrollment (the credential
// embedded in the "Add device" install command) — no polling.
async function claim(url, code, secret, envFile) {
  const c = await fetch(`${url}/api/v1/enroll/claim`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, secret }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!c.ok) {
    const body = await c.json().catch(() => ({}));
    console.error(`claim failed: ${body?.error?.message || `HTTP ${c.status}`}`);
    process.exit(1);
  }
  const { token } = await c.json();
  deliverToken(url, token, envFile);
}

/* -------------------------------- commands ------------------------------- */
// The control plane can push {id, type, payload} commands in the report
// response: refresh | update | uninstall | apply-updates | fix-check |
// stop-listener. Executed once, results go out in a single follow-up
// report; the follow-up's own commands are ignored (no loop). Results carry
// the server's {commandId, status, result} contract plus {type, ok, error?,
// detail?} so either side of the schema can read them.

function selfUninstall() {
  if (IS_TERMUX) {
    // crond entry + $PREFIX env/id files instead of systemd units.
    try { execFileSync('sh', ['-c', "crontab -l 2>/dev/null | grep -v 'rootwatch-agent' | crontab -"], { timeout: 15000 }); } catch {}
    for (const f of [`${TERMUX_PREFIX}/etc/rootwatch-agent`, `${TERMUX_PREFIX}/etc/rootwatch-agent-id`, `${TERMUX_PREFIX}/etc/rootwatch-agent-state.json`]) {
      try { unlinkSync(f); } catch {}
    }
  } else {
    try { execFileSync('systemctl', ['disable', '--now', 'rootwatch-agent.timer'], { timeout: 15000 }); } catch {}
    for (const f of ['/etc/systemd/system/rootwatch-agent.service', '/etc/systemd/system/rootwatch-agent.timer', '/etc/default/rootwatch-agent']) {
      try { unlinkSync(f); } catch {}
    }
    // Persisted agent state (dedicated dir is safe to wipe) + fallback path.
    try { rmSync('/var/lib/rootwatch-agent', { recursive: true, force: true }); } catch {}
    try { unlinkSync(path.join(os.homedir() || '/', '.rootwatch-agent-state.json')); } catch {}
    try { execFileSync('systemctl', ['daemon-reload'], { timeout: 15000 }); } catch {}
  }
  // only wipe a dedicated install dir — never a dev checkout or homedir
  const dir = path.dirname(SELF_PATH);
  if (path.basename(dir) === 'rootwatch-agent' || dir.startsWith('/opt/') || dir.startsWith('/usr/local/')) {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

async function selfUpdate(url) {
  if (!url || !/^https?:\/\//.test(url)) throw new Error('update payload.url missing or not http(s)');
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const src = await res.text();
  if (src.length < 1000 || !src.includes('CONTROL_PLANE_URL')) throw new Error('downloaded file does not look like the agent');
  const tmp = `${SELF_PATH}.new`;
  writeFileSync(tmp, src, { mode: 0o755 });
  // node --check resolves module type by extension — '.new' is unknown, so
  // syntax-vet a '.mjs' copy before touching the real file
  const probe = `${SELF_PATH}.probe.mjs`;
  try {
    copyFileSync(tmp, probe);
    execFileSync(process.execPath, ['--check', probe], { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    try { unlinkSync(tmp); } catch {}
    throw new Error(`downloaded agent failed node --check: ${String(e.stderr || e.message).trim().slice(0, 300)}`);
  } finally {
    try { unlinkSync(probe); } catch {}
  }
  renameSync(tmp, SELF_PATH); // atomic replace — timer runs the new code next tick
}

/* --------------------------- remote remediation --------------------------- */
// apply-updates / fix-check handlers. Every result is {ok, error?, detail?,
// unsupported?} — 'unsupported' means the capability is genuinely absent on
// this host (mapped to command status 'unsupported' at report time).

// Long-running step with output capture — 10-minute ceiling is enforced by
// the caller's deadline; err.stdout/stderr survive execFile failures.
async function runStep(cmd, args, timeoutMs = 60_000) {
  try {
    const { stdout, stderr } = await exec(cmd, args, { timeout: timeoutMs });
    return { ok: true, out: `${stdout || ''}${stderr || ''}` };
  } catch (e) {
    return { ok: false, out: `${e?.stdout || ''}${e?.stderr || ''}`, error: String(e?.message || e) };
  }
}
const tailOf = (s, n = 800) => (s || '').trim().slice(-n) || undefined;

function isRoot() {
  try { return typeof process.getuid === 'function' && process.getuid() === 0; }
  catch { return false; }
}

// Which package manager can this agent actually drive? Probes the binary,
// not the distro label.
async function detectPkgManager() {
  if (IS_TERMUX) return 'termux';
  if ((await run('apt-get', ['--version'])) != null) return 'apt';
  if ((await run('apk', ['--version'])) != null) return 'apk';
  if ((await run('dnf', ['--version'])) != null) return 'dnf';
  return null;
}

async function applyUpdates() {
  if (!isRoot()) return { ok: false, error: 'requires root (uid 0)' };
  const mgr = await detectPkgManager();
  const steps = {
    apt: [['apt-get', ['update']], ['apt-get', ['-y', 'upgrade']]],
    termux: [['apt-get', ['update']], ['apt-get', ['-y', 'upgrade']]],
    apk: [['apk', ['upgrade']]],
    dnf: [['dnf', ['-y', 'update']]],
  }[mgr];
  if (!steps) return { ok: false, unsupported: true, error: 'no supported package manager' };
  const deadline = Date.now() + 600_000; // 10-minute budget across all steps
  const log = [];
  for (const [cmd, args] of steps) {
    const r = await runStep(cmd, args, Math.max(10_000, deadline - Date.now()));
    if (r.out.trim()) log.push(r.out);
    if (!r.ok) {
      return { ok: false, error: `${cmd} ${args.join(' ')} failed: ${tailOf(r.out, 200) || r.error}`, detail: tailOf(log.join('\n')) };
    }
  }
  return { ok: true, detail: tailOf(log.join('\n')) || 'package upgrade completed' };
}

async function fixFirewallActive() {
  if ((await run('ufw', ['--version'])) != null) {
    const r = await runStep('ufw', ['--force', 'enable']);
    if (!r.ok) return { ok: false, error: `ufw enable failed: ${tailOf(r.out, 300) || r.error}` };
    return { ok: true, detail: tailOf(r.out) || 'ufw enabled' };
  }
  if ((await run('firewall-cmd', ['--version'])) != null) {
    const r = await runStep('systemctl', ['enable', '--now', 'firewalld']);
    if (!r.ok) return { ok: false, error: `systemctl enable --now firewalld failed: ${tailOf(r.out, 300) || r.error}` };
    return { ok: true, detail: tailOf(r.out) || 'firewalld enabled' };
  }
  return { ok: false, unsupported: true, error: 'no supported firewall backend' };
}

// Debian family only: install unattended-upgrades and ensure the
// APT::Periodic on-switch exists in 20auto-upgrades (the same file the
// auto-security-updates check reads).
async function fixAutoUpdates() {
  const mgr = await detectPkgManager();
  if (mgr !== 'apt') {
    return { ok: false, unsupported: true, error: `auto security updates unsupported on this platform (${mgr ?? 'no known package manager'})` };
  }
  const inst = await runStep('apt-get', ['install', '-y', 'unattended-upgrades'], 300_000);
  if (!inst.ok) return { ok: false, error: `apt-get install unattended-upgrades failed: ${tailOf(inst.out, 300) || inst.error}` };
  const confPath = '/etc/apt/apt.conf.d/20auto-upgrades';
  const current = await readFile(confPath, 'utf8').catch(() => '');
  let wrote = false;
  if (!/APT::Periodic::Unattended-Upgrade\s+"?1"?\s*;/.test(current)) {
    const enable = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n';
    writeFileSync(confPath, (current.trimEnd() ? `${current.trimEnd()}\n` : '') + enable, { mode: 0o644 });
    wrote = true;
  }
  return { ok: true, detail: `unattended-upgrades installed${wrote ? '; 20auto-upgrades configured' : '; 20auto-upgrades already enabled'}` };
}

// Keep in sync with FIXABLE_CHECK_IDS in server/routes.ts.
const FIXABLE_CHECKS = new Set(['pending-security-updates', 'firewall-active', 'auto-security-updates']);
async function fixCheck(checkId) {
  if (!FIXABLE_CHECKS.has(checkId)) return { ok: false, unsupported: true, error: 'no remediation for this check' };
  if (!isRoot()) return { ok: false, error: 'requires root (uid 0)' };
  if (checkId === 'pending-security-updates') return applyUpdates();
  if (checkId === 'firewall-active') return fixFirewallActive();
  return fixAutoUpdates();
}

/* ------------------------------ stop-listener ---------------------------- */
// Guarded kill, mirroring the semantics of desktop/collector.cjs
// stopListener: validate the pid, prove it still owns a listening socket
// (PID-reuse guard), refuse self/ancestors and foreign-uid targets, then
// SIGTERM → ~3s grace → SIGKILL. The agent has no privileged helper, so a
// foreign-uid target is an honest 'elevated_required' with the exact manual
// command — never a silent fail or a fake success. Every outcome is
// {status: stopped|failed|refused|elevated_required, message, method:
// 'signal', suggestedFix?}; the caller maps 'stopped' to the command-result
// status 'done', everything else to 'failed'.

const KILL_GRACE_MS = 3000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// `ss -tlnuH` is the socket enumeration the report collector already runs;
// -p adds the owning pid where our privileges allow it (root sees every
// socket; an unprivileged agent sees only its own uid's — foreign-owned
// listeners are present but unattributed). Returns a Set of listener-owner
// pids, or null when the tool is absent so callers can distinguish
// "verified empty" from "can't verify".
async function listenerOwnerPids() {
  const out = await run('ss', ['-tlnuHp']);
  if (out == null) return null;
  const pids = new Set();
  for (const m of out.matchAll(/\bpid=(\d+)\b/g)) pids.add(Number(m[1]));
  return pids;
}

// Real uid + parent pid from procfs. null when the pid is gone or /proc is
// absent — callers treat that as "can't confirm", never as a guess.
async function procStatus(pid) {
  try {
    const text = await readFile(`/proc/${pid}/status`, 'utf8');
    const uid = Number(text.match(/^Uid:\s*(\d+)/m)?.[1]);
    const ppid = Number(text.match(/^PPid:\s*(\d+)/m)?.[1]);
    return {
      uid: Number.isInteger(uid) ? uid : null,
      ppid: Number.isInteger(ppid) ? ppid : null,
    };
  } catch {
    return null;
  }
}

// Pids the stop path may never signal: the agent itself plus every ancestor
// reached by walking /proc/<pid>/status PPid links up toward init (signalling
// one would take the agent down mid-report). Where procfs is absent the
// chain degrades to {pid, ppid} — still a refusal, just a shallower one.
async function protectedPids() {
  const set = new Set([process.pid]);
  let cur = process.pid;
  for (let i = 0; i < 64; i++) {
    const st = await procStatus(cur);
    const ppid = st?.ppid ?? (cur === process.pid ? process.ppid : null);
    if (!Number.isInteger(ppid) || ppid <= 1) break;
    set.add(ppid);
    cur = ppid;
  }
  return set;
}

// Post-signal liveness. A /proc/<pid>/stat state of 'Z' counts as dead — a
// zombie still has an entry but is gone, and signalling it is a no-op. A
// vanished/unreadable entry falls back to kill(pid, 0), which is also the
// only check on hosts without procfs; EPERM still means "alive".
function pidAlive(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 1).trim().split(/\s+/)[0] !== 'Z';
  } catch {
    try { process.kill(pid, 0); return true; }
    catch (e) { return e.code === 'EPERM'; }
  }
}

async function stopListener(pid) {
  const refuse = (message) => ({ status: 'refused', message, method: 'signal' });
  if (!Number.isInteger(pid) || pid <= 1) {
    return refuse('refused: invalid pid');
  }
  if ((await protectedPids()).has(pid)) {
    return refuse('refusing to signal the agent or one of its ancestors');
  }

  // PID-reuse guard: enumerate now — the pid must currently own a listener,
  // or it isn't the process the control plane targeted anymore.
  const [owners, proc] = await Promise.all([listenerOwnerPids(), procStatus(pid)]);
  if (owners == null) {
    // No ownership view at all — never signal blind.
    return proc == null
      ? { status: 'failed', message: 'pid no longer owns a listener (process exited)', method: 'signal' }
      : { status: 'failed', message: 'cannot verify listener ownership — socket enumeration (ss) unavailable', method: 'signal' };
  }
  if (!owners.has(pid)) {
    if (proc == null) {
      return { status: 'failed', message: 'pid no longer owns a listener (process exited)', method: 'signal' };
    }
    // An unprivileged `ss -p` can't attribute foreign-owned sockets, so an
    // absent pid is ambiguous — resolve it via the target's uid before
    // claiming it holds no listener.
    const selfUid = typeof process.getuid === 'function' ? process.getuid() : null;
    const euid = typeof process.geteuid === 'function' ? process.geteuid() : selfUid;
    if (proc.uid != null && selfUid != null && proc.uid !== selfUid && euid !== 0) {
      return {
        status: 'elevated_required',
        message: `pid ${pid} is owned by uid ${proc.uid} — the agent runs as uid ${selfUid} and cannot inspect or signal it`,
        method: 'signal',
        suggestedFix: `sudo kill ${pid}`,
      };
    }
    return refuse('pid no longer owns a listener — possible pid reuse');
  }

  // Ownership guard: without root the target must provably be ours before
  // we signal. An unreadable owner is a refusal path, same as foreign uid.
  const selfUid = typeof process.getuid === 'function' ? process.getuid() : null;
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : selfUid;
  if (euid !== 0 && (selfUid == null || proc?.uid == null || proc.uid !== selfUid)) {
    return {
      status: 'elevated_required',
      message: proc?.uid != null
        ? `pid ${pid} is owned by uid ${proc.uid} — the agent has no privilege to signal it`
        : `cannot confirm the owner of pid ${pid} — the agent has no privilege to signal it`,
      method: 'signal',
      suggestedFix: `sudo kill ${pid}`,
    };
  }

  try {
    process.kill(pid, 'SIGTERM');
  } catch (e) {
    if (e.code === 'ESRCH') {
      return { status: 'stopped', message: 'process already exited', method: 'signal' };
    }
    if (e.code === 'EPERM') {
      return {
        status: 'elevated_required',
        message: 'signal refused — insufficient privileges',
        method: 'signal',
        suggestedFix: `sudo kill ${pid}`,
      };
    }
    return refuse(`SIGTERM failed: ${e.message}`);
  }
  const deadline = Date.now() + KILL_GRACE_MS;
  while (Date.now() < deadline && pidAlive(pid)) await sleep(100);
  if (!pidAlive(pid)) {
    return { status: 'stopped', message: `terminated pid ${pid} with SIGTERM`, method: 'signal' };
  }
  try {
    process.kill(pid, 'SIGKILL');
  } catch (e) {
    if (e.code === 'ESRCH') {
      return { status: 'stopped', message: `pid ${pid} exited during the grace period`, method: 'signal' };
    }
    return refuse(`SIGKILL failed: ${e.message}`);
  }
  await sleep(150);
  if (!pidAlive(pid)) {
    return { status: 'stopped', message: `killed pid ${pid} with SIGKILL`, method: 'signal' };
  }
  return {
    status: 'elevated_required',
    message: 'process survived SIGTERM and SIGKILL — manual intervention required',
    method: 'signal',
    suggestedFix: `sudo kill -9 ${pid}`,
  };
}

/* --------------------------------- remediate ------------------------------ */
// Server-queued remediation plans: payload {actionId?, phase, steps:[{label,
// argv}]}. Every argv is re-validated ON the device with the same discipline
// as the privileged helper packaging/rootwatch-remediate — binary allowlist,
// per-binary flag allowlist, verb requirements, metacharacter screen — then
// run via execFile, never a shell. One deliberate delta from the helper:
// `bash` is NOT allowed here — there is no root-owned /opt/rootwatch/libexec
// on agent devices, so a script step would be an unconfined interpreter.
// Refusals are honest: a rejected plan reports the reason and nothing past
// the refused step runs.

const REMEDY_ARG_RE = /^[a-zA-Z0-9_@.:/+=-]+$/;
const REMEDY_METACHARS_RE = /[;&|`$><(){} \t\r\n]/;
const REMEDY_BINARIES = new Set(['apt-get', 'dnf', 'ufw', 'systemctl', 'sshd', 'dpkg', 'kill']);
// Per-binary flag allowlists — mirror the helper's case arms exactly. An
// exact-membership check (not a prefix match) blocks option smuggling like
// `apt-get -o APT::Update::Post-Invoke=cmd`.
const REMEDY_FLAGS = {
  'apt-get': new Set(['-y', '--yes', '-q', '--quiet', '--no-install-recommends']),
  dnf: new Set(['-y', '-q', '--quiet', '--refresh']),
  systemctl: new Set(['--now', '--system', '--no-reload', '--no-ask-password', '-q', '--quiet']),
  ufw: new Set(['--force', '--dry-run']),
  sshd: new Set(['-t', '-T', '-f', '-q']),
  dpkg: new Set(['-P', '--purge', '-r', '--remove', '--configure', '-l', '--list', '-s', '--status', '--get-selections', '-V', '--verify', '--audit', '-C']),
  kill: new Set(['-TERM', '-KILL', '-15', '-9']),
};
// Positional args matching one of these keywords pass outright; anything
// else must satisfy REMEDY_ARG_RE (the helper's charset for unit names,
// package names, ports and values).
const REMEDY_KEYWORDS = new Set(
  'update upgrade dist-upgrade install remove purge autoremove allow deny reject limit delete default enable disable reload reset status verbose numbered stop mask unmask start restart try-restart reload-or-restart try-reload-or-restart daemon-reload is-active is-enabled incoming outgoing routed'.split(' '),
);
// The verb each binary must carry as its first positional arg.
const REMEDY_REQUIRED_VERB = {
  'apt-get': new Set(['update', 'upgrade', 'dist-upgrade', 'install', 'remove', 'purge', 'autoremove']),
  dnf: new Set(['upgrade', 'install', 'remove', 'autoremove']),
  ufw: new Set(['allow', 'deny', 'reject', 'limit', 'delete', 'default', 'enable', 'disable', 'reload', 'reset', 'status']),
  systemctl: new Set(['stop', 'disable', 'mask', 'unmask', 'enable', 'start', 'reload', 'restart', 'try-restart', 'reload-or-restart', 'try-reload-or-restart', 'daemon-reload', 'is-active', 'is-enabled']),
};
const DPKG_ACTIONS = new Set(['-P', '--purge', '-r', '--remove', '--configure', '-l', '--list', '-s', '--status', '--get-selections', '-V', '--verify', '--audit', '-C']);
// user@<uid>.service is a login session's systemd --user MANAGER — a
// mutating verb against it tears down the user's entire session. Only the
// read-only verbs may reference it (same guard the root helper applies).
const USER_SESSION_UNIT_RE = /^user@\d+\.service$/;

/**
 * Validate one step's argv against the on-device allowlist. Pure function —
 * exported so the rules can be exercised without running a report cycle.
 * Returns {ok:true} | {ok:false, reason, unsupported?} — 'unsupported' is
 * set only when the binary itself is outside the allowed class (the plan
 * can't run here by policy); every other refusal is a validation failure.
 */
export function validateRemediateArgv(argv) {
  const refuse = (reason, extra) => ({ ok: false, reason, ...extra });
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((a) => typeof a !== 'string' || !a)) {
    return refuse('argv must be a non-empty array of non-empty strings');
  }
  const [bin, ...args] = argv;
  if (!REMEDY_BINARIES.has(bin)) return refuse(`binary not allowed: ${bin}`, { unsupported: true });

  let verb = null;
  let prev = null;
  for (const a of args) {
    // Metacharacter screen — applied to every argument.
    if (REMEDY_METACHARS_RE.test(a)) return refuse(`forbidden character in arg: ${a}`);
    // sshd -f may only point at files under /etc/ssh/.
    if (bin === 'sshd' && prev === '-f') {
      if (!a.startsWith('/etc/ssh/')) return refuse(`sshd -f target outside /etc/ssh: ${a}`);
      if (a.includes('..')) return refuse(`path traversal in sshd -f target: ${a}`);
      if (!REMEDY_ARG_RE.test(a)) return refuse(`unsafe path characters: ${a}`);
      prev = a;
      continue;
    }
    if (a.startsWith('-')) {
      if (!REMEDY_FLAGS[bin].has(a)) return refuse(`option not allowed for ${bin}: ${a}`);
      prev = a;
      continue;
    }
    if (verb == null) verb = a;
    if (!REMEDY_KEYWORDS.has(a) && !REMEDY_ARG_RE.test(a)) {
      return refuse(`unsafe arg characters: ${a}`);
    }
    prev = a;
  }

  switch (bin) {
    case 'apt-get':
    case 'dnf':
    case 'ufw':
    case 'systemctl': {
      if (verb == null || !REMEDY_REQUIRED_VERB[bin].has(verb)) {
        return refuse(`${bin} verb not allowed: ${verb ?? '<none>'}`);
      }
      if (bin === 'systemctl' && verb !== 'is-active' && verb !== 'is-enabled') {
        for (const a of args) {
          if (USER_SESSION_UNIT_RE.test(a)) {
            return refuse(`refusing to manage session manager unit via systemctl: ${a}`);
          }
        }
      }
      break;
    }
    case 'sshd':
      // Only config validation is permitted — never run the daemon itself.
      if (!args.includes('-t') && !args.includes('-T')) return refuse('sshd may only validate config (-t/-T)');
      if (args[args.length - 1] === '-f') return refuse('sshd -f requires a path argument');
      break;
    case 'dpkg':
      if (!DPKG_ACTIONS.has(args[0])) return refuse(`dpkg action not allowed: ${args[0] ?? '<none>'}`);
      break;
    case 'kill': {
      // kill [-SIGNAL] <pid> — one numeric target; never init (1) or the
      // process-group wildcard (0). Ownership was verified when the plan
      // was queued.
      if (args.length < 1 || args.length > 2) return refuse('kill expects [-signal] <pid>');
      const last = args[args.length - 1];
      if (!/^\d+$/.test(last)) return refuse(`kill target must be a numeric pid: ${last}`);
      if (last === '0' || last === '1') return refuse('refusing to signal init/process-group');
      break;
    }
  }
  return { ok: true };
}

// Run the validated plan step-by-step via execFile — argv never rejoins
// through a shell. Output is tail-capped at ~8KB per stream (recent lines
// carry the diagnostics). Stops at the first non-zero exit; an ENOENT spawn
// means the binary isn't installed here → 'unsupported', not a fake failure.
const REMEDY_STEP_TIMEOUT_MS = 300_000;
const REMEDY_OUTPUT_CAP = 8 * 1024;
const clipOut = (s) => {
  const str = String(s ?? '');
  return str.length > REMEDY_OUTPUT_CAP ? `[truncated] ${str.slice(-REMEDY_OUTPUT_CAP)}` : str;
};
async function runRemediateSteps(steps) {
  const done = [];
  for (const step of steps) {
    const rec = { label: step.label, argv: step.argv };
    try {
      const { stdout, stderr } = await exec(step.argv[0], step.argv.slice(1), {
        timeout: REMEDY_STEP_TIMEOUT_MS,
        maxBuffer: 4 * 1024 * 1024,
      });
      rec.exitCode = 0;
      if (stdout) rec.stdout = clipOut(stdout);
      if (stderr) rec.stderr = clipOut(stderr);
    } catch (e) {
      rec.exitCode = Number.isInteger(e?.code) ? e.code : null;
      if (e?.signal) rec.signal = e.signal;
      if (e?.stdout) rec.stdout = clipOut(e.stdout);
      if (e?.stderr) rec.stderr = clipOut(e.stderr);
      done.push(rec);
      if (e?.code === 'ENOENT') {
        return { ok: false, unsupported: true, steps: done, reason: `step '${step.label}': binary not installed: ${step.argv[0]}` };
      }
      const cause = rec.exitCode != null
        ? `exit code ${rec.exitCode}`
        : String(e?.message || e).slice(0, 200);
      return { ok: false, steps: done, reason: `step '${step.label}' failed: ${cause}` };
    }
    done.push(rec);
  }
  return { ok: true, steps: done };
}

// remediate command handler. Status mapping (applied by the caller):
//   every step exits 0              → done
//   validation refusal / non-zero   → failed (result.reason explains)
//   non-root / unallowed binary
//   class / binary not installed    → unsupported (plan can't run here)
// Result rides the server's {actionId?, phase, steps:[{label, argv,
// exitCode, stdout?, stderr?, signal?}], reason?} contract — phase is
// informational and passed straight through.
async function remediateCommand(payload) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const result = (phase, steps, reason, extra = {}) => ({
    phase,
    steps,
    ...(Number.isInteger(p.actionId) ? { actionId: p.actionId } : {}),
    ...(reason ? { reason } : {}),
    ...extra,
  });
  const malformed = (phase, reason) => ({ ok: false, result: result(phase, [], reason) });

  const phase = p.phase == null ? 'execute' : p.phase;
  if (phase !== 'execute' && phase !== 'rollback') {
    return malformed(String(p.phase), `malformed payload: phase must be 'execute' or 'rollback', got ${JSON.stringify(p.phase)}`);
  }
  if (p.actionId != null && !Number.isInteger(p.actionId)) {
    return malformed(phase, 'malformed payload: actionId must be an integer');
  }
  if (!Array.isArray(p.steps) || p.steps.length === 0) {
    return malformed(phase, 'malformed payload: steps must be a non-empty array');
  }
  const steps = [];
  for (const [i, s] of p.steps.entries()) {
    if (typeof s?.label !== 'string' || !s.label) {
      return malformed(phase, `malformed payload: steps[${i}].label must be a non-empty string`);
    }
    const check = validateRemediateArgv(s.argv);
    if (!check.ok) {
      return { ok: false, unsupported: check.unsupported === true || undefined, result: result(phase, [], `step '${s.label}' refused: ${check.reason}`) };
    }
    steps.push({ label: s.label, argv: s.argv });
  }
  if (!isRoot()) {
    return { ok: false, unsupported: true, result: result(phase, [], 'requires root (uid 0)') };
  }
  const run = await runRemediateSteps(steps);
  return {
    ok: run.ok,
    unsupported: run.unsupported === true || undefined,
    // A package-mutating step that ran may have changed the inventory — same
    // dirty-flag convention as apply-updates.
    packagesDirty: run.steps.some((s) => s.argv[0] === 'apt-get' || s.argv[0] === 'dnf'),
    result: result(phase, run.steps, run.reason),
  };
}

/* --------------------------------- report -------------------------------- */

// Tiny persisted JSON state ({reportCount, packagesDirty, logOffsets,
// seenDetections, lastLogTs}) — the agent runs as a one-shot process per
// 5-min timer tick, so the package-inventory cadence and the detection
// engine's offset/dedup bookkeeping have to live on disk. Path degrades
// by writability; unwritable → reportCount stays 0 in memory, which just
// means packages ride every report (equivalent to "first report since
// agent start" on a fresh file) and detections can't dedup across runs.
function stateCandidates() {
  const list = IS_TERMUX
    ? [`${TERMUX_PREFIX}/etc/rootwatch-agent-state.json`]
    : ['/var/lib/rootwatch-agent/state.json'];
  const home = os.homedir();
  if (home) list.push(path.join(home, '.rootwatch-agent-state.json'));
  return list;
}
function loadAgentState() {
  for (const p of stateCandidates()) {
    try {
      const s = JSON.parse(readFileSync(p, 'utf8'));
      if (Number.isInteger(s?.reportCount) && s.reportCount >= 0) {
        return {
          statePath: p,
          reportCount: s.reportCount,
          packagesDirty: s.packagesDirty === true,
          logOffsets: s.logOffsets && typeof s.logOffsets === 'object' ? s.logOffsets : {},
          seenDetections: Array.isArray(s.seenDetections)
            ? s.seenDetections.filter((k) => typeof k === 'string').slice(-SEEN_DETECTIONS_CAP)
            : [],
          lastLogTs: Number.isFinite(s.lastLogTs) ? s.lastLogTs : 0,
        };
      }
    } catch {}
  }
  return { statePath: null, reportCount: 0, packagesDirty: false, logOffsets: {}, seenDetections: [], lastLogTs: 0 };
}
function saveAgentState(st) {
  const data = JSON.stringify({
    reportCount: st.reportCount,
    packagesDirty: st.packagesDirty === true,
    logOffsets: st.logOffsets && typeof st.logOffsets === 'object' ? st.logOffsets : {},
    seenDetections: Array.isArray(st.seenDetections) ? st.seenDetections.slice(-SEEN_DETECTIONS_CAP) : [],
    lastLogTs: Number.isFinite(st.lastLogTs) ? st.lastLogTs : 0,
  });
  for (const p of st.statePath ? [st.statePath] : stateCandidates()) {
    try {
      mkdirSync(path.dirname(p), { recursive: true });
      writeFileSync(p, data, { mode: 0o600 });
      st.statePath = p;
      return;
    } catch {}
  }
}

async function collect({ includePackages = false, state = null } = {}) {
  const [host, ports, updates, fw, ssh, failed, disk, autoUpd, sudoers, mac, ntp, aging, tainted, android] = await Promise.all([
    hostInfo(), listeners(), pendingUpdates(), firewall(), sshSettings(), failedLogins(),
    diskEncryption(), autoSecurityUpdates(), sudoersState(), macStatus(), timeSyncState(),
    passwordAging(), kernelTainted(), androidPosture(),
  ]);
  const [sshUp, sshUnit] = await Promise.all([sshServiceActive(), sshUnitName()]);
  const checks = runChecks({
    fw, ssh, sshUp, ports, updates, failed, disk, autoUpd, sudoers,
    dockerSock: dockerSocketPerms(), pathDirs: worldWritablePathDirs(),
    mac, ntp, aging, tainted, rootkits: rootkitArtifacts(), android,
  });
  const publicPorts = ports.filter((p) => classifyBind(p.address) === 'public');
  const detections = await collectDetections(state);
  // Totals count only evaluable checks: unsupported probes (passed:true +
  // supported:false) land in notEvaluable so "10/12" means 10 of 12
  // actually evaluated — unsupported checks neither dilute the denominator
  // nor count as phantom passes.
  const evaluable = checks.filter((c) => c.supported !== false);

  const body = {
    hostId: await machineId(),
    hostname: host.hostname,
    os: host.os || undefined,
    platform: host.platform,
    agentVersion: AGENT_VERSION,
    report: {
      uptimeSeconds: host.uptimeSeconds,
      metrics: metrics(),
      checks: {
        total: evaluable.length,
        passed: evaluable.filter((c) => c.passed).length,
        failing: checks.filter((c) => !c.passed).map((c) => ({
          id: c.id,
          name: c.name,
          severity: c.severity,
          // evidence string the check collected — capped, omitted when absent
          ...(typeof c.details === 'string' && c.details ? { details: c.details.slice(0, 2000) } : {}),
        })),
        notEvaluable: checks.length - evaluable.length,
      },
      firewall: fw,
      // port + unit feed the control plane's device-proposal builder —
      // firewall plans must allow the REAL sshd port (never assumed 22) and
      // reload/stop steps must target the detected unit name.
      // port: an observed sshd bind beats the config directive — a
      // socket-activated sshd can listen on a port sshd_config never
      // declares (and an absent directive defaults to 22, which is wrong
      // evidence for a firewall-enable plan on the control plane).
      ssh: { supported: ssh.supported, serviceActive: sshUp, permitRootLogin: ssh.permitRootLogin, passwordAuthentication: ssh.passwordAuthentication, port: ports.find((p) => (p.process || '').toLowerCase() === 'sshd')?.port ?? (ssh.supported ? ssh.port : null), unit: sshUnit },
      listeners: { total: ports.length, publicCount: publicPorts.length, publicPorts: publicPorts.map((p) => ({ port: p.port, protocol: p.protocol, address: p.address, process: p.process ?? null })) },
      updates: { supported: updates.supported, count: updates.count, securityCount: updates.securityCount, manager: updates.manager },
      // FIM-lite rides every report — small payload, the server diffs
      // hashes/path-presence against the previous stored report.
      fileHashes: watchedFileHashes(),
      // Always present — [] is the honest "scanned, found nothing".
      detections,
    },
  };
  // Full package inventory rides only when the caller opts in (first/hourly
  // report, or after a package-mutating command). Unsupported manager →
  // field omitted entirely rather than reported as empty.
  if (includePackages) {
    const pkgs = await packageInventory();
    if (pkgs) body.report.packages = pkgs;
  }
  return { body, checks };
}

const postReport = (body) => fetch(`${URL_}/api/v1/devices/report`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
  body: JSON.stringify(body),
  signal: AbortSignal.timeout(15_000),
});

async function main() {
  if (!URL_ || !TOKEN) {
    console.error('CONTROL_PLANE_URL and CONTROL_PLANE_TOKEN are required');
    process.exit(2);
  }
  const state = loadAgentState();
  // Bandwidth rule for the inventory: first report ever (count 0), every
  // 12th report (~hourly at the 5-min cadence), or while packagesDirty —
  // a previous run's apply-updates/fix-check may have changed the set and
  // its follow-up report never landed.
  const wantPkgs = state.reportCount % 12 === 0 || state.packagesDirty;
  const { body, checks } = await collect({ includePackages: wantPkgs, state });
  const res = await postReport(body);
  if (res.status === 401 || res.status === 403) {
    console.error(`credentials rejected (HTTP ${res.status}) — revoked, self-uninstalling`);
    selfUninstall();
    process.exit(0);
  }
  if (!res.ok) {
    console.error(`control plane rejected report: HTTP ${res.status} ${await res.text().catch(() => '')}`);
    process.exit(1);
  }
  // Advance the counter only on an accepted report; a dirty inventory that
  // made it through is clean again.
  state.reportCount++;
  if (wantPkgs) state.packagesDirty = false;
  saveAgentState(state);
  const evaluable = checks.filter((c) => c.supported !== false);
  console.log(`report sent: ${evaluable.filter((c) => c.passed).length}/${evaluable.length} evaluable checks passing`);

  const data = await res.json().catch(() => null);
  const commands = Array.isArray(data?.data?.commands) ? data.data.commands : [];
  const latest = data?.data?.latestAgentVersion;
  // informational only — self-update happens solely via an 'update' command
  if (latest && latest !== AGENT_VERSION && !commands.some((c) => c.type === 'update')) {
    console.log(`agent v${latest} published (running v${AGENT_VERSION}) — update is admin-gated`);
  }
  if (commands.length === 0) return;

  let exitAfter = false;
  let packagesDirty = false; // a mutating command ran → follow-up ships inventory
  const commandResults = [];
  for (const cmd of commands) {
    const r = { commandId: cmd.id, type: cmd.type, status: 'done', ok: true };
    try {
      if (cmd.type === 'refresh') { /* follow-up below carries a fresh snapshot */ }
      else if (cmd.type === 'update') { await selfUpdate(cmd.payload?.url); exitAfter = true; }
      else if (cmd.type === 'uninstall') { selfUninstall(); exitAfter = true; }
      else if (cmd.type === 'apply-updates' || cmd.type === 'fix-check') {
        packagesDirty = true; // even a partial run may have changed packages
        const out = cmd.type === 'apply-updates' ? await applyUpdates() : await fixCheck(cmd.payload?.checkId);
        if (out.ok) {
          if (out.detail) { r.detail = out.detail; r.result = out.detail; }
        } else {
          r.ok = false;
          r.status = out.unsupported ? 'unsupported' : 'failed';
          r.error = out.error;
          r.result = out.error;
        }
      }
      else if (cmd.type === 'remediate') {
        // Validated argv plan — result carries {actionId?, phase,
        // steps:[{label, argv, exitCode, stdout?, stderr?}], reason?}.
        // Executed package-mutating steps (apt-get/dnf) flag the follow-up
        // inventory the same way apply-updates does.
        const out = await remediateCommand(cmd.payload);
        if (out.packagesDirty) packagesDirty = true;
        r.ok = out.ok;
        r.status = out.ok ? 'done' : out.unsupported ? 'unsupported' : 'failed';
        r.result = out.result;
        if (!r.ok) r.error = out.result.reason || 'remediation failed';
      }
      else if (cmd.type === 'stop-listener') {
        // Outcome {status, message, method, suggestedFix?} rides in result —
        // only 'stopped' maps to the server's 'done' command status;
        // refused/elevated_required/failed are all 'failed' at that level
        // with the honest detail preserved in the result object.
        const out = await stopListener(cmd.payload?.pid);
        r.ok = out.status === 'stopped';
        r.status = r.ok ? 'done' : 'failed';
        r.result = out;
        if (!r.ok) r.error = out.message;
      }
      else {
        r.ok = false;
        r.status = 'unsupported';
        r.error = 'unsupported command type';
        r.result = r.error;
      }
    } catch (e) {
      r.ok = false;
      r.status = 'failed';
      r.error = String(e?.message || e);
      r.result = r.error;
    }
    commandResults.push(r);
  }

  // collect() re-runs the whole check battery, so remediated checks report
  // their fresh verdict in this same follow-up.
  const follow = await collect({ includePackages: packagesDirty, state });
  follow.body.commandResults = commandResults;
  const res2 = await postReport(follow.body).catch(() => null);
  if (res2?.ok) {
    state.reportCount++;
    if (packagesDirty) state.packagesDirty = false;
    saveAgentState(state);
    console.log(`command results reported: ${commandResults.map((r) => `${r.commandId ?? '?'}=${r.status}`).join(', ')}`);
  } else {
    // Follow-up lost → keep the dirty flag so the next timed run still
    // ships a fresh inventory.
    if (packagesDirty) { state.packagesDirty = true; saveAgentState(state); }
    console.error('follow-up report failed');
  }
  if (exitAfter) process.exit(0);
}

// Direct-execution entrypoint — skipped entirely when this file is imported
// (the exported validator can then be exercised without a report cycle).
// realpathSync on both sides so a symlinked install path still dispatches.
const invokedAsScript = (() => {
  try {
    return process.argv[1] != null && realpathSync(process.argv[1]) === realpathSync(SELF_PATH);
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
// Env-file path comes via RW_ENV_FILE — a `--env-file` argv flag would be
// intercepted by Node itself (>=20.6) and never reach this script.
const envFile = process.env.RW_ENV_FILE || null;
const argv = process.argv.slice(2);
if (argv[0] === '--help' || argv[0] === '-h') {
  console.log(`rootwatch agent v${AGENT_VERSION} — zero-dependency host posture reporter

usage: node agent.mjs [command]

  (no args)                              collect checks and POST a report
  enroll <control-url>                   code-based pairing (writes RW_ENV_FILE)
  claim <control-url> <code> <secret>    claim a pre-approved bootstrap credential

env: CONTROL_PLANE_URL, CONTROL_PLANE_TOKEN (required to report), RW_ENV_FILE`);
} else if (argv[0] === 'claim') {
  const [url, code, secret] = [argv[1]?.replace(/\/+$/, ''), argv[2], argv[3]];
  if (!url || !code || !secret) {
    console.error('usage: RW_ENV_FILE=/path node agent.mjs claim <control-plane-url> <code> <secret>');
    process.exit(2);
  }
  claim(url, code, secret, envFile).catch((e) => { console.error(`claim error: ${e.message}`); process.exit(1); });
} else if (argv[0] === 'enroll') {
  const url = (argv[1] || '').replace(/\/+$/, '');
  if (!url) {
    console.error('usage: RW_ENV_FILE=/path node agent.mjs enroll <control-plane-url>');
    process.exit(2);
  }
  enroll(url, envFile).catch((e) => { console.error(`enroll error: ${e.message}`); process.exit(1); });
} else {
  main().catch((e) => { console.error(`agent error: ${e.message}`); process.exit(1); });
}
}
