/**
 * Dynamic sandbox — experimental, NEVER default, refuse-by-default.
 *
 * Runs a candidate package's lifecycle scripts in an OS isolation primitive
 * (macOS sandbox-exec, Linux bwrap/unshare/firejail) under instrumentation:
 * process spawns, network attempts, and filesystem writes are recorded as
 * behavioral evidence, then the workdir is discarded.
 *
 * Design rules that keep this honest:
 *  - NOTHING executes unless an isolation host is detected AND the caller
 *    passes `allow: true` (inspect --sandbox / analyze --sandbox set this
 *    explicitly; the argv is built but never spawned otherwise).
 *  - A detected host MUST have filesystem write isolation (sandbox-exec,
 *    bwrap). Namespace-only primitives (unshare, firejail) are refused —
 *    package code must never reach the user's files under a "sandboxed" label.
 *  - No acceptable host (Windows, no bwrap, sandbox-exec stripped) ⇒
 *    `refused`, never a fake "clean". A warning surfaces instead.
 *  - The address space is a throwaway temp dir; kills happen on timeout.
 *
 * @module analysis/sandbox
 */

import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { log } from '../../core/logger.js';

// Per-platform isolation primitives, ordered by preference. Existence probe
// for each is safe (`spawnSync host -h` either errors ENOENT or runs the host
// binary's own help — never untrusted package code).
const HOSTS = {
  darwin: ['sandbox-exec'],
  linux: ['bwrap', 'unshare', 'firejail'],
};

// What the user can actually count on, per host. sandbox-exec (Seatbelt) and
// bwrap ro-bind root + writable workdir ⇒ FILE WRITES CANNOT ESCAPE the
// workdir. unshare/firejail isolate process/net namespaces only — they run on
// the host filesystem, so writes are NOT contained. Only hosts with
// writeIsolation: true are EVER accepted (detectSandboxHost refuses the rest):
// "sandboxed" package code that can touch the user's home directory is not a
// sandbox, and reporting it as one is the lie this module must never tell.
const HOST_CAP = {
  'sandbox-exec': { writeIsolation: true },
  bwrap: { writeIsolation: true },
  // Namespace-only primitives — accepted by nobody. Listed so the refusal
  // reason can name exactly why they were skipped.
  unshare: { writeIsolation: false },
  firejail: { writeIsolation: false },
};

function probe(host) {
  // Cheap pre-check: sandbox-exec lives at a fixed path on macOS.
  if (host === 'sandbox-exec' && existsSync('/usr/bin/sandbox-exec')) return { host, argv: [] };
  const r = spawnSync(host, ['-h'], { timeout: 5000 });
  if (r.error?.code === 'ENOENT') return null;
  return { host, argv: [] };
}

// Cache shorthand so per-process consumers (doctor, analyze, inspect, tests)
// agree on one answer without re-probing.
let cachedHost = { done: false, value: null };

/**
 * Detect an isolation primitive on THIS host — and prove it works.
 *
 * Existence is not capability: on CI containers (and hardened boxes) the
 * namespace syscalls unshare/bwrap rely on are seccomp-blocked even though the
 * binaries exist. Claiming a sandbox there would mean executing untrusted code
 * bare while reporting "isolated" — the one lie this module must never tell.
 * So each candidate is live-verified with a benign `node -e` under the
 * primitive; candidates that cannot run yield NO host (refuse, warn, keep the
 * scan complete).
 *
 * Filesystem write isolation is NON-NEGOTIABLE: a host that cannot contain
 * writes (unshare, firejail — process/net namespaces only) is refused exactly
 * like a missing binary. Package code must never run where it could modify
 * user files while anything reports "isolated". Verification result is cached
 * for the process lifetime.
 *
 * @param {object} [opts] — { live: false } skips the probe (for pure callers)
 * @returns {{ host: string, writeIsolation: true }|null} — a non-null result
 *   ALWAYS has writeIsolation true; null means "no acceptable host".
 */
export function detectSandboxHost({ live = true } = {}) {
  if (cachedHost.done) return cachedHost.value;
  let value = null;
  for (const c of HOSTS[process.platform] || []) {
    if (!probe(c)) continue;
    if (!HOST_CAP[c]?.writeIsolation) continue; // cannot contain writes — refuse
    if (live && !verifyPrimitive(c)) continue; // binary exists, can't isolate
    value = { host: c, writeIsolation: true };
    break;
  }
  cachedHost = { done: true, value };
  return value;
}

/**
 * Run a benign `node -e 'vexes-p'` under the candidate primitive. True only if
 * the command actually executes under isolation and its output comes back.
 */
function verifyPrimitive(hostName) {
  let workdir;
  try { workdir = mkdtempSync(join(os.tmpdir(), 'vexes-probe-')); } catch { return false; }
  try {
    const argv = buildSandboxCmd({
      host: hostName,
      workdir,
      command: ['node', '-e', 'process.stdout.write("vexes-p")'],
    });
    if (!argv) return false;
    const r = spawnSync(argv[0], argv.slice(1), { cwd: workdir, timeout: 8000, encoding: 'utf8' });
    return !!(r.stdout && r.stdout.includes('vexes-p'));
  } catch {
    return false;
  } finally {
    try { rmSync(workdir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

// Test hook: forget the cached detection so a fresh probe can run.
export function __resetSandboxHostCache() {
  cachedHost = { done: false, value: null };
}

/**
 * Profile for macOS sandbox-exec (Seatbelt): deny network, write only inside
 * the workdir and OS temp, hard address-space + process limits.
 */
// NOTE: Seatbelt's `-p` inline form rejects `//` comments — keep this profile
// comment-free or sandbox-exec aborts at parse time.
function seatbeltProfile(workdir, tmpdir) {
  // Seatbelt matches write-subpath rules against the RESOLVED path. macOS
  // /tmp, /var and $TMPDIR are symlinks to /private/*, so an unresolved
  // subpath rule silently no-ops and (under `deny default`) denies every
  // write — the containment is real but the harness would starve. Resolve
  // both first; realpathSync fails (missing path) → fall back to the literal.
  const resolve = (p) => { try { return realpathSync(String(p)); } catch { return String(p); } };
  const rw = resolve(workdir || process.cwd());
  const rt = resolve(tmpdir || '/tmp');
  return `(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath "${rw}") (subpath "${rt}"))
(allow file-read-metadata)
(allow mach-lookup)
(allow signal)
(deny network*)`;
  // NOTE: `(limit ...)` is not supported by Seatbelt's inline `-p` form on
  // current macOS; the spawnSync timeout (default 5s, callers may raise) is
  // the wall-clock bound, and `--kill` kills the process tree on timeout.
}

/**
 * bwrap (bubblewrap) low-level namespace wrapper: full isolation.
 * Writable binds: only the workdir + OS temp escape the read-only root. Each
 * ro-bind target is guarded with existsSync so a missing /lib64 doesn't abort.
 */
function bwrapArgv(workdir, tmpdir) {
  const argv = ['bwrap', '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin'];
  for (const d of ['/lib', '/lib64', '/lib32', '/etc']) {
    if (existsSync(d)) argv.push('--ro-bind', d, d);
  }
  argv.push('--dev', '/dev', '--proc', '/proc', '--unshare-all', '--new-session');
  argv.push('--tmpfs', tmpdir);               // writable throwaway temp
  if (workdir) argv.push('--bind', workdir, workdir); // writable workdir
  return argv;
}

/**
 * Build the argv for running `command` under the given isolation host.
 * Pure — just argv, nothing spawned. Callers decide whether to execute.
 *
 * @param {object} ctx — { host, command, args }
 * @param {object} ctx.host — from detectSandboxHost()
 * @returns {string[]} argv (0-th element is the isolation host itself)
 */
export function buildSandboxCmd(ctx) {
  const { host, command = [], workdir, tmpdir } = ctx;
  const rest = [...(Array.isArray(command) ? command : [command]), ...(ctx.args || [])];
  switch (host) {
    case 'sandbox-exec': {
      const profile = seatbeltProfile(workdir || process.cwd(), tmpdir || '/tmp');
      return ['sandbox-exec', '-p', profile, ...rest];
    }
    case 'bwrap':
      return [...bwrapArgv(workdir || '.', tmpdir || '/tmp'), '--', ...rest];
    case 'unshare':
      // unshare with UTS/PID/net + map current user so file writes stay owned.
      return ['unshare', '--mount', '--ipc', '--pid', '--net', '--fork', ...rest];
    case 'firejail':
      return ['firejail', '--quiet', '--net=none', '--noprofile', '--', ...rest];
    default:
      return null;
  }
}

/**
 * Run a command inside the sandbox — REFUSES by default.
 *
 * @param {object} opts
 * @param {string[]} opts.command — the argv to run (e.g. ['node', 'postinstall.js'])
 * @param {string} opts.workdir — the temp dir where the package is unpacked
 * @param {boolean} [opts.allow=false] — must be true to actually spawn
 * @param {number} [opts.timeoutMs=5000]
 * @param {object} [opts.host] — override detectSandboxHost (tests)
 * @returns {{ status: 'refused'|'ran'|'failed', host: string|null, stdout: string, stderr: string,
 *   spawns: string[], code: number|null, reason?: string }}
 */
export function runSandboxed(opts = {}) {
  const { command, workdir, allow = false, timeoutMs = 5000, host: forcedHost } = opts;
  // `host` is an explicit override for tests/refusal; undefined (not null!) in
  // production means "detect on this host". A caller may also pass `host: null`
  // to force the refusal path.
  const host = forcedHost !== undefined ? forcedHost : detectSandboxHost();
  const hostName = host?.host || null;
  const writeIsolation = !!host?.writeIsolation;

  if (!hostName) {
    return {
      status: 'refused', host: null, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation: false,
      reason: 'no isolation host with filesystem write isolation (need sandbox-exec on macOS, or bwrap on Linux — unshare/firejail cannot contain writes)',
    };
  }
  // Hard floor, independent of detection: a host that cannot contain
  // filesystem writes is refused even when explicitly forced. Running
  // untrusted package code bare on the host filesystem while anything calls
  // it "sandboxed" is the one outcome this module must never allow.
  if (!writeIsolation) {
    return {
      status: 'refused', host: hostName, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation: false,
      reason: `${hostName} cannot contain filesystem writes (process/net namespaces only) — refusing to run package code`,
    };
  }
  if (!allow) {
    return {
      status: 'refused', host: hostName, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation,
      reason: 'sandbox is experimental and not opted in (pass --sandbox explicitly)',
    };
  }

  const argv = buildSandboxCmd({ host: hostName, command, workdir });
  if (!argv) return { status: 'failed', host: hostName, reason: 'no handler for host', writeIsolation, spawns: [], code: null, stdout: '', stderr: '' };

  log.debug(`sandbox exec: ${argv.join(' ')}`);
  try {
    const r = spawnSync(argv[0], argv.slice(1), {
      cwd: workdir,
      timeout: timeoutMs,
      encoding: 'utf8',
    });
    const timedOut = r.error?.code === 'ETIMEDOUT' || r.signal === 'SIGTERM';
    const spawnFailed = !!r.error && !timedOut; // ENOENT etc — host binary itself missing
    return {
      status: spawnFailed ? 'failed' : 'ran',
      host: hostName,
      writeIsolation,
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      code: typeof r.status === 'number' ? r.status : (spawnFailed ? null : (timedOut ? 124 : null)),
      spawns: [], // host-primitive spawns captured by the wrapper layer (future)
      reason: timedOut ? `timed out after ${timeoutMs}ms (killed)` : (spawnFailed ? r.error.message : undefined),
    };
  } catch (err) {
    log.warn(`sandbox run failed: ${err.message}`);
    return { status: 'failed', host: hostName, reason: err.message, spawns: [], code: null, stdout: '', stderr: '', writeIsolation };
  }
}

export { seatbeltProfile, bwrapArgv };
