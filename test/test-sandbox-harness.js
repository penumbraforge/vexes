import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAnalyze } from '../src/commands/analyze.js';
import { runSandboxed, detectSandboxHost } from '../src/analysis/sandbox/index.js';
import { buildRecorderShim, buildHarnessCommand, parseEvidence, readEvidenceFile, runHarnessed } from '../src/analysis/sandbox/harness.js';
import { EXIT, NPM_REGISTRY_URL, NPM_ATTESTATIONS_URL, OSV_BATCH_URL, OSV_VULN_URL } from '../src/core/constants.js';

/** Minimal fetch/response helpers (mirrors test-fail-safe.js). */
function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

function mockFetchOnce(impl) {
  const original = global.fetch;
  global.fetch = impl;
  return () => { global.fetch = original; };
}

async function captureOutput(fn) {
  let stdout = '';
  let stderr = '';
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;
  process.stdout.write = (chunk, _enc, callback) => { stdout += String(chunk); if (typeof callback === 'function') callback(); return true; };
  process.stderr.write = (chunk, _enc, callback) => { stderr += String(chunk); if (typeof callback === 'function') callback(); return true; };
  try {
    return { code: await fn(), stdout, stderr };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
}

describe('sandbox recorder shim (buildRecorderShim)', () => {
  it('is pure, strict, and only uses node: builtins', () => {
    const text = buildRecorderShim({ evidencePath: '/tmp/.ev.jsonl', workdir: '/w' }); // returns a string
    assert.match(text, /'use strict';/);
    assert.match(text, /"\/tmp\/\.ev\.jsonl"/);            // evidence path baked in
    assert.match(text, /require\('node:child_process'\)/);
    assert.match(text, /require\('node:net'\)/);
    assert.match(text, /require\('node:fs'\)/);
    assert.match(text, /require\('node:http'\)/);
    // no external requires sneak in: only node: builtins plus fs/os/path/cp/net/http/https/dgram
    const requires = [...text.matchAll(/require\('([^']+)'\)/g)].map(m => m[1]);
    for (const r of requires) assert.ok(r.startsWith('node:'), `shim must only use node: builtins (got ${r})`);
  });

  it('buildHarnessCommand injects via --require so children stay uninstrumented', () => {
    const cmd = buildHarnessCommand({ shimPath: '/w/.vexes-recorder.cjs', entryScript: '/w/index.js' });
    assert.deepEqual(cmd, ['node', '--require', '/w/.vexes-recorder.cjs', '/w/index.js']);
  });
});

describe('parseEvidence', () => {
  it('buckets a hand-written JSONL fixture correctly and skips garbage', () => {
    const jsonl = [
      JSON.stringify({ t: 'spawn', command: 'node', args: ['-e', '1'], at: 1 }),
      JSON.stringify({ t: 'network', type: 'tcp', host: 'evil.example', port: 443, at: 2 }),
      JSON.stringify({ t: 'write', path: '/etc/hosts', fn: 'appendFile', outside: true, at: 3 }),
      JSON.stringify({ t: 'write', path: 'inside.txt', fn: 'writeFile', outside: false, at: 4 }),
      JSON.stringify({ t: 'write', path: '/tmp/x', fn: 'writeFile', outside: false, at: 5 }), // tmp = inside
      'this is not json',
      '{truncated',
      '',
    ].join('\n');

    const e = parseEvidence(jsonl, '/w');
    assert.equal(e.spawns.length, 1);
    assert.equal(e.spawns[0].cmd, 'node');
    assert.equal(e.networkAttempts.length, 1);
    assert.ok(e.networkAttempts[0].host.includes('evil.example'));
    assert.equal(e.outsideWrites.length, 1);   // /etc/hosts only
    assert.equal(e.outsideWrites[0].path, '/etc/hosts');
    assert.equal(e.otherWrites.length, 2);     // inside.txt + /tmp/x
  });

  it('tolerates garbage/empty/corrupt input without throwing', () => {
    for (const bad of ['', null, undefined, 'not json\n{}bad', '{', ' ']) {
      const e = parseEvidence(bad, '/w');
      assert.deepEqual(e, { spawns: [], networkAttempts: [], outsideWrites: [], otherWrites: [], cwdChanges: [] });
    }
  });

  it('readEvidenceFile returns empty buckets for a missing file', () => {
    assert.deepEqual(readEvidenceFile(join(tmpdir(), 'nope.jsonl'), '/w'),
      { spawns: [], networkAttempts: [], outsideWrites: [], otherWrites: [], cwdChanges: [] });
  });
});

describe('sandbox refusal paths (refuse-by-default)', () => {
  it('host: null forces refusal and never spawns', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-nullhost-'));
    try {
      writeFileSync(join(dir, 'index.js'), "console.log('hi');\n");
      const child = runHarnessed({ workdir: dir, entryScript: join(dir, 'index.js'), allow: true, host: null });
      assert.equal(child.status, 'refused');
      assert.match(child.reason, /no isolation host/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('allow: false refuses even with a usable host object', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-optout-'));
    try {
      const r = runSandboxed({
        command: ['node', '--version'],
        workdir: dir,
        allow: false, // NOT opted in
        host: { host: 'bwrap', argv: [], writeIsolation: true, readIsolation: true },
      });
      assert.equal(r.status, 'refused');
      assert.match(r.reason, /not opted in/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('labels candidate-visible recorder output as positive-only evidence', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-positive-only-'));
    try {
      const entry = join(dir, 'index.js');
      writeFileSync(entry, 'module.exports = {};\n');
      const child = runHarnessed({
        workdir: dir,
        entryScript: entry,
        allow: true,
        host: { host: 'bwrap', writeIsolation: true, readIsolation: true },
        spawn: () => {
          writeFileSync(join(dir, '.vexes-evidence.jsonl'), '{"t":"recorder_ready"}\n');
          return { status: 0, stdout: '', stderr: '', error: null, signal: null };
        },
      });
      assert.equal(child.status, 'ran');
      assert.equal(child.evidenceComplete, true);
      assert.equal(child.evidenceTrusted, false);
      assert.equal(child.negativeEvidenceTrusted, false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('analyze --sandbox wiring (refusal)', () => {
  it('refuses up-front with sandboxHost:null and never downloads or runs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-sb-analyze-'));
    try {
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({ cache: { dir: join(dir, '.cache') } }));
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', dependencies: { 'sb-evil-pkg': '^1.0.0' } }));
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { 'sb-evil-pkg': '^1.0.0' } },
          'node_modules/sb-evil-pkg': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/sb-evil-pkg/-/sb-evil-pkg-1.0.0.tgz',
          },
        },
      }));

      // Stub all network touchpoints: registry metadata, OSV batch + detail,
      // Sigstore attestations (404 = normal absence). The tarball 404s — step
      // 5b's default deep-AST pass may request it for a high-risk package
      // (byte-bounded, never executed), but the SANDBOX step must refuse
      // up-front and never attempt its own download/run.
      const restore = mockFetchOnce(async (url) => {
        const u = String(url);
        if (u.startsWith(NPM_REGISTRY_URL)) {
          if (u.includes('/-/npm/v1/attestations')) return { ok: false, status: 404, async json() { return {}; }, async text() { return ''; } };
          if (u.includes('.tgz')) return { ok: false, status: 404, async json() { return {}; }, async text() { return ''; } };
          // packument — crafted to drive a HIGH/CRITICAL single-candidate pass
          return jsonResponse({
            'dist-tags': { latest: '1.0.0' },
            time: {
              created: '2023-06-01T00:00:00.000Z',
              modified: '2025-01-01T00:00:05.000Z',
              '0.5.0': '2023-06-01T00:00:00.000Z',
              '0.9.0': '2025-01-01T00:00:00.000Z',
              '1.0.0': '2025-01-01T00:00:05.000Z',
            },
            versions: {
              '0.5.0': { name: 'sb-evil-pkg', version: '0.5.0', _npmUser: { name: 'victim' } },
              '0.9.0': { name: 'sb-evil-pkg', version: '0.9.0', _npmUser: { name: 'victim' } },
              '1.0.0': { name: 'sb-evil-pkg', version: '1.0.0', scripts: { postinstall: 'node setup.js' }, _npmUser: { name: 'attacker' } },
            },
            maintainers: [{ name: 'attacker' }],
          });
        }
        if (u.startsWith(OSV_BATCH_URL)) return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-fake-0001' }] }] });
        if (u.startsWith(OSV_VULN_URL)) return jsonResponse({ id: 'GHSA-fake-0001', summary: 'stub vuln', severity: [{ type: 'CVSS_V3', score: '9.8' }], affected: [{ package: { name: 'sb-evil-pkg', ecosystem: 'npm' } }] });
        throw new Error(`unexpected fetch: ${u}`);
      });

      try {
        const { code, stdout } = await captureOutput(() =>
          runAnalyze({ path: dir, json: true, sandbox: true, sandboxHost: null }, [])
        );

        assert.equal(code, EXIT.ERROR, 'requested sandbox refusal makes the analysis incomplete');
        const payload = JSON.parse(stdout);
        assert.equal(payload.complete, false, 'sandbox refusal must mark the requested stage incomplete');
        assert.deepEqual(payload.stages.sandbox, { requested: true, complete: false });
        const warnings = payload.warnings.join('\n');
        assert.match(warnings, /sandbox/);
        assert.match(warnings, /bwrap host that contains writes and hides user\/project host paths/);

        // Honesty: refusal pre-flight attaches no evidence and claims no run.
        assert.equal(JSON.stringify(payload).includes('SANDBOX_BEHAVIOR'), false);
        const flagged = payload.extra?.results || [];
        for (const r of flagged) {
          assert.ok(!(r.sandboxEvidence), 'no sandboxEvidence attached on refusal');
        }
      } finally {
        restore();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Positive path: executes candidate code inside the OS sandbox and records
// behavior. Runs only when this host actually has a WORKING isolation
// primitive — detectSandboxHost() live-verifies the primitive before claiming
// it (a seccomp-blocked unshare on CI is refused, not trusted). The same gate
// the analyzer honors, so the test can never pretend to sandbox.
const host = detectSandboxHost();
const hasHost = !!host?.host;
const writesContained = hasHost && host.writeIsolation;

const FIXTURE = (marker) => [
  "'use strict';",
  "const fs = require('node:fs');",
  "const cp = require('node:child_process');",
  "const net = require('node:net');",
  "cp.spawnSync(process.execPath, ['-e', 'true'], { stdio: 'ignore' });",
  "fs.writeFileSync('inside.txt', 'ok');",
  "net.connect({ host: '127.0.0.1', port: 9 }).on('error', () => {});",
  `try { fs.writeFileSync('${marker}', 'x'); } catch {} // outside workdir — sandbox denies where capable`,
].join('\n');

async function runPositive() {
  const marker = '/vexes-sandbox-marker';
  const dir = mkdtempSync(join(tmpdir(), 'vexes-sb-run-'));
  try {
    writeFileSync(join(dir, 'index.js'), FIXTURE(marker));
    return {
      marker,
      dir,
      child: runHarnessed({ workdir: dir, entryScript: join(dir, 'index.js'), allow: true, timeoutMs: 10000 }),
    };
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

// Accepted write-contained host path (currently Linux bwrap). The file the
// candidate tried to write outside workdir+tmp must not exist in this fixture.
describe('sandbox positive path (write-contained host)', { skip: !writesContained }, () => {
  it('runs under the recorder, records behavior, and contains outside writes', async () => {
    const { marker, dir, child } = await runPositive();
    try {
      assert.equal(child.status, 'ran', child.reason ? `harness: ${child.reason}` : '');
      assert.equal(child.writeIsolation, true);
      assert.ok(child.evidence.spawns.length >= 1, 'spawn must be recorded');
      assert.ok(child.evidence.networkAttempts.length >= 1, 'network attempt must be recorded');
      assert.ok(child.evidence.outsideWrites.length >= 1, 'outside write must be recorded');
      assert.equal(existsSync(marker), false, 'sandbox must contain writes outside workdir+tmp');
      assert.equal(existsSync(join(dir, 'inside.txt')), true, 'inside write must succeed');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Partial hosts (unshare/firejail): process+network isolation, filesystem NOT
// contained. We still verify the recorder works there — attempts are logged
// and evidence flows — but we never claim the marker can't be written.
describe('sandbox positive path (process/net-only host)', { skip: !hasHost || writesContained }, () => {
  it('runs under the recorder and records attempts without claiming write containment', async () => {
    const { marker, dir, child } = await runPositive();
    try {
      assert.equal(child.status, 'ran', child.reason ? `harness: ${child.reason}` : '');
      assert.equal(child.writeIsolation, false, 'partial host must not advertise write containment');
      assert.ok(child.evidence.spawns.length >= 1, 'spawn must be recorded');
      assert.ok(child.evidence.networkAttempts.length >= 1, 'network attempt must be recorded');
      assert.ok(child.evidence.outsideWrites.length >= 1, 'outside write attempt must be recorded');
      assert.equal(existsSync(join(dir, 'inside.txt')), true, 'inside write must succeed');
      // Deliberately NO existsSync(marker) assertion: partial hosts run on
      // the host filesystem, so the marker may legitimately exist.
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
