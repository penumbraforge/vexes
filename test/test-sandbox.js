import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildSandboxCmd, runSandboxed, detectSandboxHost, seatbeltProfile, bwrapArgv, sandboxEnvironment, sandboxHostPath } from '../src/analysis/sandbox/index.js';

/**
 * DYNAMIC SANDBOX (experimental, refuse-by-default).
 *
 * Command-shape tests never spawn anything. Refusal tests never execute
 * untrusted code — they assert the REFUSE path. The single execution smoke
 * test runs a BENIGN `node -e` inside the host primitive (no fixture, no
 * package code) and skips when no isolation host exists.
 */

const CMD = ['node', 'postinstall.js'];

describe('sandbox: command construction (pure, never spawns)', () => {
  it('builds a sandbox-exec argv with a network-blocking seatbelt profile', () => {
    const argv = buildSandboxCmd({ host: 'sandbox-exec', command: CMD, workdir: '/tmp/w', tmpdir: '/tmp' });
    assert.equal(argv[0], sandboxHostPath('sandbox-exec'));
    const profile = argv[argv.indexOf('-p') + 1];
    assert.match(profile, /\(deny network\*\)/);
    assert.match(profile, /\(subpath "\/tmp\/w"\)/);   // writes scoped to workdir
    assert.match(profile, /\(deny default\)/);         // everything denies unless allowed
    assert.ok(argv.slice(-2).includes('postinstall.js'));
  });

  it('builds a bwrap argv with hidden host root, read-only runtime mounts, and a writable workdir', () => {
    const argv = buildSandboxCmd({ host: 'bwrap', command: CMD, workdir: '/tmp/w' });
    assert.equal(argv[0], sandboxHostPath('bwrap'));
    assert.ok(argv.includes('--unshare-all'));
    assert.ok(argv.join(' ').includes('--bind /tmp/w /tmp/w')); // writable workdir bind
    assert.equal(argv.includes('/etc'), false, 'host configuration is not mounted into the candidate');
  });

  it('does not build argv for namespace-only hosts', () => {
    assert.equal(buildSandboxCmd({ host: 'unshare', command: CMD, workdir: '/tmp/w' }), null);
    assert.equal(buildSandboxCmd({ host: 'firejail', command: CMD, workdir: '/tmp/w' }), null);
  });

  it('returns null for an unknown host (no handler → never guessed)', () => {
    assert.equal(buildSandboxCmd({ host: 'cobalt', command: CMD }), null);
  });

  it('uses fixed host paths rather than inherited PATH names', () => {
    for (const host of ['sandbox-exec', 'bwrap', 'unshare', 'firejail']) {
      assert.match(sandboxHostPath(host), /^\/(?:usr\/)?bin\//);
    }
  });

  it('seatbelt profile always blocks network and give-way to scoped writes', () => {
    const p = seatbeltProfile('/tmp/w', '/tmp');
    assert.match(p, /\(deny network\*\)/);
    assert.match(p, /\(deny default\)/);
    assert.match(p, /\(subpath "\/tmp\/w"\)/);
  });
});

describe('sandbox: refuse-by-default (no untrusted execution)', () => {
  it('refuses when no isolation host is detected', () => {
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: null });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /no isolation host/);
  });

  it('refuses even with a valid host unless allow=true', () => {
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: false, host: { host: 'bwrap', writeIsolation: true, readIsolation: true } });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /not opted in/);
  });

  it('refuses namespace-only hosts (firejail/unshare) even when forced with allow=true', () => {
    // firejail isolates processes/network but NOT filesystem writes — package
    // code under it could modify user files. Refused before any binary probe.
    for (const h of ['firejail', 'unshare']) {
      const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: { host: h, writeIsolation: false, readIsolation: false } });
      assert.equal(r.status, 'refused');
      assert.match(r.reason, /cannot contain filesystem writes/);
      assert.equal(r.writeIsolation, false);
    }
  });

  it('ignores forged caller capability booleans', () => {
    const r = runSandboxed({
      command: CMD,
      workdir: '/tmp',
      allow: true,
      host: { host: 'unshare', writeIsolation: true, readIsolation: true },
      spawn: () => { throw new Error('must never spawn'); },
    });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /cannot contain filesystem writes/);
  });

  it('ignores omitted caller capability claims and uses the static bwrap contract', () => {
    const r = runSandboxed({
      command: CMD,
      workdir: '/tmp',
      allow: true,
      host: { host: 'bwrap' },
      spawn: () => ({ status: 0, stdout: '', stderr: '', error: null, signal: null }),
    });
    assert.equal(r.status, 'ran');
    assert.equal(r.writeIsolation, true);
    assert.equal(r.privateReadIsolation, true);
    assert.equal(r.readIsolation, false, 'runtime trees remain readable, so total read isolation is not claimed');
    assert.deepEqual(r.runtimeReadOnlyMounts, ['/usr', '/bin', '/lib*']);
  });

  it('refuses sandbox-exec because the current profile cannot hide private host paths', () => {
    const r = runSandboxed({
      command: CMD, workdir: '/tmp', allow: true,
      host: { host: 'sandbox-exec', writeIsolation: true, readIsolation: false },
    });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /does not hide user\/project\/private host paths/);
  });

  it('refuses an unknown host even when the caller forges isolation claims', () => {
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: { host: 'no-such-primitive', writeIsolation: true, readIsolation: true } });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /cannot contain filesystem writes/);
  });

  it('treats timeouts and non-zero exits as failed, never as completed runs', () => {
    const host = { host: 'bwrap', writeIsolation: true, readIsolation: true };
    const nonZero = runSandboxed({
      command: CMD, workdir: '/tmp', allow: true, host,
      spawn: () => ({ status: 7, stdout: '', stderr: 'boom', error: null, signal: null }),
    });
    assert.equal(nonZero.status, 'failed');
    assert.match(nonZero.reason, /status 7/);

    const timeout = runSandboxed({
      command: CMD, workdir: '/tmp', allow: true, host, timeoutMs: 9,
      spawn: () => ({ status: null, stdout: '', stderr: '', error: { code: 'ETIMEDOUT' }, signal: 'SIGTERM' }),
    });
    assert.equal(timeout.status, 'failed');
    assert.match(timeout.reason, /timed out/);
  });

  it('passes a minimal environment without parent secrets', () => {
    const previous = process.env.VEXES_TEST_SECRET;
    process.env.VEXES_TEST_SECRET = 'must-not-leak';
    let childEnv;
    try {
      const result = runSandboxed({
        command: CMD,
        workdir: '/tmp/vexes-env',
        allow: true,
        host: { host: 'bwrap', writeIsolation: true, readIsolation: true },
        spawn: (_cmd, _args, opts) => {
          childEnv = opts.env;
          return { status: 0, stdout: '', stderr: '', error: null, signal: null };
        },
      });
      assert.equal(result.status, 'ran');
      assert.equal(childEnv.VEXES_TEST_SECRET, undefined);
      assert.equal(childEnv.HOME, '/tmp/vexes-env');
      assert.equal(childEnv.PATH, '/usr/bin:/bin');
      assert.deepEqual(childEnv, sandboxEnvironment('/tmp/vexes-env'));
    } finally {
      if (previous === undefined) delete process.env.VEXES_TEST_SECRET;
      else process.env.VEXES_TEST_SECRET = previous;
    }
  });
});

describe('sandbox: benign execution smoke (skip when hostless)', { skip: !detectSandboxHost()?.host }, () => {
  it('never detects a host without filesystem write isolation', () => {
    // The invariant the whole module exists for: a non-null detection is
    // ALWAYS a write-isolating host, on every platform.
    const h = detectSandboxHost();
    assert.ok(h);
    assert.equal(h.writeIsolation, true);
    assert.equal(h.privateReadIsolation, true);
    assert.equal(h.readIsolation, false);
  });

  it('runs a benign node -e inside the isolation primitive', () => {
    const r = runSandboxed({
      command: ['node', '-e', 'process.stdout.write("sandbox-live")'],
      workdir: '/tmp',
      allow: true,
      timeoutMs: 10_000,
    });
    assert.equal(r.status, 'ran');
    assert.match(r.stdout, /sandbox-live/);
  });
});

// re-export guard so tree-shaking/lint keeps the import meaningful
export { buildSandboxCmd, runSandboxed, detectSandboxHost, seatbeltProfile, bwrapArgv, sandboxEnvironment, sandboxHostPath };
