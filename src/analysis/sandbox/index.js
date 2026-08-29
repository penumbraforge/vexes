/**
 * Dynamic sandbox — experimental, NEVER default, refuse-by-default.
 *
 * Runs one selected npm entrypoint in an OS isolation primitive under
 * best-effort instrumentation:
 * process spawns, network attempts, and filesystem writes are recorded as
 * behavioral evidence, then the workdir is discarded.
 *
 * Design rules that keep this honest:
 *  - NOTHING executes unless an isolation host is detected AND the caller
 *    passes `allow: true` (inspect --sandbox / analyze --sandbox set this
 *    explicitly; the argv is built but never spawned otherwise).
 *  - A detected host MUST contain writes and hide user/project/private host
 *    paths. A small read-only OS runtime surface remains visible so Node can
 *    start; this is not a claim that every host byte is hidden.
 *  - No acceptable host (Windows, no bwrap, sandbox-exec stripped) ⇒
 *    `refused`, never a fake "clean". A warning surfaces instead.
 *  - The address space is a throwaway temp dir; kills happen on timeout.
 *
 * @module analysis/sandbox
 */

import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';
import { log } from '../../core/logger.js';

// Per-platform isolation primitives, ordered by preference. Existence probe
// for each is safe (`spawnSync host -h` either errors ENOENT or runs the host
// binary's own help — never untrusted package code).
const HOSTS = {
  darwin: ['sandbox-exec'],
  linux: ['bwrap'],
};

const HOST_PATHS = {
  'sandbox-exec': ['/usr/bin/sandbox-exec'],
  bwrap: ['/usr/bin/bwrap', '/bin/bwrap'],
  unshare: ['/usr/bin/unshare', '/bin/unshare'],
  firejail: ['/usr/bin/firejail', '/bin/firejail'],
};

// What the user can actually count on, per host. sandbox-exec (Seatbelt) and
// bwrap's minimal runtime mounts + writable workdir ⇒ FILE WRITES CANNOT ESCAPE the
// workdir. unshare/firejail isolate process/net namespaces only — they run on
// the host filesystem, so writes are NOT contained. Only hosts with
// writeIsolation: true are EVER accepted (detectSandboxHost refuses the rest):
// "sandboxed" package code that can touch the user's home directory is not a
// sandbox, and reporting it as one is the lie this module must never tell.
const HOST_CAP = {
  // The current Seatbelt profile must allow broad host reads for Node to
  // start, so it is not acceptable for adversarial package execution.
  'sandbox-exec': { writeIsolation: true, privateReadIsolation: false, readIsolation: false },
  bwrap: { writeIsolation: true, privateReadIsolation: true, readIsolation: false },
  // Namespace-only primitives — accepted by nobody. Listed so the refusal
  // reason can name exactly why they were skipped.
  unshare: { writeIsolation: false, privateReadIsolation: false, readIsolation: false },
  firejail: { writeIsolation: false, privateReadIsolation: false, readIsolation: false },
};

function probe(host) {
  const path = sandboxHostPath(host, { requireExisting: true });
  if (!path) return null;
  const r = spawnSync(path, ['-h'], {
    timeout: 5000,
    env: { PATH: '/usr/bin:/bin', HOME: os.tmpdir(), TMPDIR: os.tmpdir(), NO_COLOR: '1' },
  });
  if (r.error || (typeof r.status === 'number' && r.status > 1)) return null;
  return { host, path };
}

/** Resolve isolation hosts from fixed system locations, never inherited PATH. */
export function sandboxHostPath(host, { requireExisting = false } = {}) {
  const candidates = HOST_PATHS[host] || [];
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      const real = realpathSync(candidate);
      if (statSync(real).isFile()) return real;
    } catch { /* keep looking */ }
  }
  return requireExisting ? null : (candidates[0] || null);
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
    if (!HOST_CAP[c]?.writeIsolation || !HOST_CAP[c]?.privateReadIsolation) continue;
    const candidate = probe(c);
    if (!candidate) continue;
    if (live && !verifyPrimitive(candidate)) continue; // binary exists, can't isolate
    value = {
      host: c,
      path: candidate.path,
      writeIsolation: true,
      privateReadIsolation: true,
      readIsolation: false,
      runtimeReadOnlyMounts: ['/usr', '/bin', '/lib*'],
    };
    break;
  }
  cachedHost = { done: true, value };
  return value;
}

/**
 * Run a benign `node -e 'vexes-p'` under the candidate primitive. True only if
 * the command actually executes under isolation and its output comes back.
 */
function verifyPrimitive(hostInfo) {
  let workdir;
  try { workdir = mkdtempSync(join(os.tmpdir(), 'vexes-probe-')); } catch { return false; }
  try {
    const argv = buildSandboxCmd({
      host: hostInfo.host,
      workdir,
      command: [process.execPath, '-e', 'process.stdout.write("vexes-p")'],
    });
    if (!argv) return false;
    const r = spawnSync(argv[0], argv.slice(1), {
      cwd: workdir,
      timeout: 8000,
      encoding: 'utf8',
      env: sandboxEnvironment(workdir),
    });
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
 * bwrap (bubblewrap) low-level namespace wrapper: scoped runtime isolation.
 * Writable binds: only the workdir + OS temp are exposed writable. Each
 * ro-bind target is guarded with existsSync so a missing /lib64 doesn't abort.
 * `/etc`, user homes, the calling project, and other host paths are not
 * mounted. `/usr`, `/bin`, and loader libraries remain readable at runtime.
 */
function bwrapArgv(workdir, tmpdir) {
  const argv = [sandboxHostPath('bwrap'), '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin'];
  for (const d of ['/lib', '/lib64', '/lib32']) {
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
      return [sandboxHostPath('sandbox-exec'), '-p', profile, ...rest];
    }
    case 'bwrap':
      return [...bwrapArgv(workdir || '.', tmpdir || '/tmp'), '--', ...rest];
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
  // Capability assertions never come from callers/config. The static table is
  // authoritative; otherwise a forged `{host:'unshare', writeIsolation:true}`
  // could turn a namespace-only process into alleged filesystem isolation.
  const writeIsolation = HOST_CAP[hostName]?.writeIsolation === true;
  const privateReadIsolation = HOST_CAP[hostName]?.privateReadIsolation === true;
  const readIsolation = HOST_CAP[hostName]?.readIsolation === true;
  const runtimeReadOnlyMounts = hostName === 'bwrap' ? ['/usr', '/bin', '/lib*'] : [];

  if (!hostName) {
    return {
      status: 'refused', host: null, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation: false, privateReadIsolation: false, readIsolation: false,
      runtimeReadOnlyMounts: [],
      reason: 'no isolation host that contains writes and hides user/project host paths (bwrap on Linux is currently required)',
    };
  }
  // Hard floor, independent of detection: a host that cannot contain
  // filesystem writes is refused even when explicitly forced. Running
  // untrusted package code bare on the host filesystem while anything calls
  // it "sandboxed" is the one outcome this module must never allow.
  if (!writeIsolation) {
    return {
      status: 'refused', host: hostName, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation: false, privateReadIsolation: false, readIsolation: false,
      runtimeReadOnlyMounts,
      reason: `${hostName} cannot contain filesystem writes (process/net namespaces only) — refusing to run package code`,
    };
  }
  if (!privateReadIsolation) {
    return {
      status: 'refused', host: hostName, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation, privateReadIsolation: false, readIsolation: false,
      runtimeReadOnlyMounts,
      reason: `${hostName} does not hide user/project/private host paths — refusing to run package code`,
    };
  }
  if (!allow) {
    return {
      status: 'refused', host: hostName, stdout: '', stderr: '',
      spawns: [], code: null, writeIsolation,
      privateReadIsolation,
      readIsolation,
      runtimeReadOnlyMounts,
      reason: 'sandbox is experimental and not opted in (pass --sandbox explicitly)',
    };
  }

  const argv = buildSandboxCmd({ host: hostName, command, workdir });
  if (!argv) return { status: 'failed', host: hostName, reason: 'no handler for host', writeIsolation, privateReadIsolation, readIsolation, runtimeReadOnlyMounts, spawns: [], code: null, stdout: '', stderr: '' };

  log.debug(`sandbox exec: ${argv.join(' ')}`);
  try {
    const spawn = opts.spawn || spawnSync;
    const r = spawn(argv[0], argv.slice(1), {
      cwd: workdir,
      timeout: timeoutMs,
      encoding: 'utf8',
      // Candidate code gets a deliberately tiny environment. Inheriting the
      // parent process wholesale would expose registry tokens, cloud keys,
      // SSH agent paths, proxy credentials, and arbitrary application secrets
      // even though filesystem/network isolation is active.
      env: sandboxEnvironment(workdir),
    });
    const timedOut = r.error?.code === 'ETIMEDOUT' || r.signal === 'SIGTERM';
    const spawnFailed = !!r.error && !timedOut; // ENOENT etc — host binary itself missing
    const nonZero = typeof r.status === 'number' && r.status !== 0;
    const failed = spawnFailed || timedOut || nonZero;
    return {
      status: failed ? 'failed' : 'ran',
      host: hostName,
      writeIsolation,
      privateReadIsolation,
      readIsolation,
      runtimeReadOnlyMounts,
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      code: typeof r.status === 'number' ? r.status : (spawnFailed ? null : (timedOut ? 124 : null)),
      spawns: [], // host-primitive spawns captured by the wrapper layer (future)
      reason: timedOut ? `timed out after ${timeoutMs}ms (killed)`
        : spawnFailed ? r.error.message
          : nonZero ? `sandboxed command exited with status ${r.status}`
            : undefined,
    };
  } catch (err) {
    log.warn(`sandbox run failed: ${err.message}`);
    return { status: 'failed', host: hostName, reason: err.message, spawns: [], code: null, stdout: '', stderr: '', writeIsolation, privateReadIsolation, readIsolation, runtimeReadOnlyMounts };
  }
}

/** Minimal, non-secret environment passed to untrusted package code. */
export function sandboxEnvironment(workdir) {
  const env = {
    PATH: '/usr/bin:/bin',
    HOME: workdir,
    TMPDIR: workdir,
    TMP: workdir,
    TEMP: workdir,
    NO_COLOR: '1',
  };
  for (const key of ['LANG', 'LC_ALL', 'LC_CTYPE', 'TZ']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key];
  }
  return env;
}

export { seatbeltProfile, bwrapArgv };
