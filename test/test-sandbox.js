import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildSandboxCmd, runSandboxed, detectSandboxHost, seatbeltProfile, bwrapArgv } from '../src/analysis/sandbox/index.js';

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
    assert.equal(argv[0], 'sandbox-exec');
    const profile = argv[argv.indexOf('-p') + 1];
    assert.match(profile, /\(deny network\*\)/);
    assert.match(profile, /\(subpath "\/tmp\/w"\)/);   // writes scoped to workdir
    assert.match(profile, /\(deny default\)/);         // everything denies unless allowed
    assert.ok(argv.slice(-2).includes('postinstall.js'));
  });

  it('builds a bwrap argv with ro root + writable workdir bind', () => {
    const argv = buildSandboxCmd({ host: 'bwrap', command: CMD, workdir: '/tmp/w' });
    assert.equal(argv[0], 'bwrap');
    assert.ok(argv.includes('--unshare-all'));
    assert.ok(argv.join(' ').includes('--bind /tmp/w /tmp/w')); // writable workdir bind
  });

  it('builds unshare and firejail argvs with network isolation', () => {
    const un = buildSandboxCmd({ host: 'unshare', command: CMD, workdir: '/tmp/w' });
    assert.ok(['--mount', '--pid', '--net'].every(f => un.includes(f)));
    const fj = buildSandboxCmd({ host: 'firejail', command: CMD, workdir: '/tmp/w' });
    assert.ok(fj.includes('--net=none'));
  });

  it('returns null for an unknown host (no handler → never guessed)', () => {
    assert.equal(buildSandboxCmd({ host: 'cobalt', command: CMD }), null);
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
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: false, host: { host: 'sandbox-exec', writeIsolation: true } });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /not opted in/);
  });

  it('refuses namespace-only hosts (firejail/unshare) even when forced with allow=true', () => {
    // firejail isolates processes/network but NOT filesystem writes — package
    // code under it could modify user files. Refused before any binary probe.
    for (const h of ['firejail', 'unshare']) {
      const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: { host: h, writeIsolation: false } });
      assert.equal(r.status, 'refused');
      assert.match(r.reason, /cannot contain filesystem writes/);
      assert.equal(r.writeIsolation, false);
    }
  });

  it('refuses a forced host whose writeIsolation is absent (not assumed true)', () => {
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: { host: 'bwrap' } });
    assert.equal(r.status, 'refused');
    assert.match(r.reason, /cannot contain filesystem writes/);
  });

  it('fails cleanly on a host with write isolation whose handler is missing', () => {
    const r = runSandboxed({ command: CMD, workdir: '/tmp', allow: true, host: { host: 'no-such-primitive', writeIsolation: true } });
    assert.equal(r.status, 'failed');
    assert.ok(r.reason);
  });
});

describe('sandbox: benign execution smoke (skip when hostless)', { skip: !detectSandboxHost()?.host }, () => {
  it('never detects a host without filesystem write isolation', () => {
    // The invariant the whole module exists for: a non-null detection is
    // ALWAYS a write-isolating host, on every platform.
    const h = detectSandboxHost();
    assert.ok(h);
    assert.equal(h.writeIsolation, true);
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
export { buildSandboxCmd, runSandboxed, detectSandboxHost, seatbeltProfile, bwrapArgv };
