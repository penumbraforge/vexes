import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseInspectTarget, printInspectText, runInspect } from '../src/commands/inspect.js';

const PACK = {
  'dist-tags': { latest: '4.17.21' },
  time: {
    created: '2015-04-07T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    '4.17.20': '2021-02-20T00:00:00Z',
    '4.17.21': '2021-07-25T00:00:00Z',
  },
  versions: {
    '4.17.21': {
      name: 'lodash', version: '4.17.21', scripts: {}, dependencies: {},
      _npmUser: { name: 'jdalton' },
      dist: {
        tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
        integrity: 'sha512-dGVzdA==',
        shasum: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
      },
    },
  },
  maintainers: [{ name: 'jdalton' }],
  repository: { url: 'https://github.com/lodash/lodash' },
};

function stubResponse(body, { ok = true, status = 200 } = {}) {
  return {
    ok, status,
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

async function stubFetch(url, opts = {}) {
  if (url.includes('osv.dev')) return stubResponse({ results: [{ vulns: [] }] });
  if (url.includes('/-/npm/v1/attestations')) {
    return stubResponse({}, { ok: false, status: 404 });
  }
  if (url.includes('registry.npmjs.org')) return stubResponse(PACK);
  return stubResponse({});
}

describe('inspect: parseInspectTarget', () => {
  it('parses name@version', () => {
    assert.deepEqual(parseInspectTarget('lodash@4.17.21'), { name: 'lodash', version: '4.17.21' });
  });
  it('allows no version (latest)', () => {
    assert.deepEqual(parseInspectTarget('express'), { name: 'express', version: null });
  });
  it('handles scoped packages correctly (split on LAST @)', () => {
    assert.deepEqual(parseInspectTarget('@babel/core@7.20.12'), { name: '@babel/core', version: '7.20.12' });
  });
  it('rejects empty input', () => {
    assert.equal(parseInspectTarget(''), null);
    assert.equal(parseInspectTarget(undefined), null);
  });
});

describe('inspect: terminal-safe text rendering', () => {
  it('strips CSI/OSC sequences from package, provenance, advisory, and signal fields', () => {
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      printInspectText({
        name: 'demo\x1b[2J',
        version: '1.0.0\x1b]0;owned\x07',
        ecosystem: 'npm\x1b[31m',
        riskLevel: 'HIGH',
        riskScore: 50,
        provenance: {
          attestationDecoded: true,
          claimedSourceRepo: 'https://example.invalid/\x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07',
        },
        signals: [{
          signal: 'TARBALL\x1b[2J',
          severity: 'HIGH',
          confidence: 'heuristic',
          description: 'entry package/\x1b]0;pwned\x07postinstall.js',
          layer: 1,
        }],
      }, [{ id: 'GHSA-test\x1b[5n' }], { osvComplete: true });
    } finally {
      process.stdout.write = originalOut;
    }

    assert.doesNotMatch(stdout, /\x1b/);
    assert.match(stdout, /demo@1\.0\.0/);
    assert.match(stdout, /entry package\/postinstall\.js/);
    assert.doesNotMatch(stdout, /owned|pwned/);
  });
});

describe('inspect: envelope output (stubbed registry + OSV)', () => {
  let restore;
  before(() => {
    const prev = global.fetch;
    restore = () => { global.fetch = prev; };
    global.fetch = stubFetch;
  });
  after(() => restore());

  it('emits the shared envelope with assessment and provenance findings', async () => {
    const code = await runInspect({ path: '.', json: true, ecosystem: 'npm' }, ['lodash@4.17.21']);
    assert.equal(code, 0); // MODERATE or NONE — no critical signals
  });

  it('exits 1 for a complete HIGH OSV finding even when the composite score is only MODERATE', async () => {
    const previousFetch = global.fetch;
    global.fetch = async (url) => {
      if (url.includes('querybatch')) {
        return stubResponse({ results: [{ vulns: [{ id: 'GHSA-inspect-high' }] }] });
      }
      if (url.includes('/v1/vulns/GHSA-inspect-high')) {
        return stubResponse({
          id: 'GHSA-inspect-high',
          summary: 'Test advisory',
          database_specific: { severity: 'HIGH' },
          affected: [],
        });
      }
      if (url.includes('/-/npm/v1/attestations')) {
        return stubResponse({}, { ok: false, status: 404 });
      }
      if (url.includes('registry.npmjs.org')) return stubResponse(PACK);
      return stubResponse({});
    };
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect(
        { path: '.', json: true, ecosystem: 'npm', severity: 'high' },
        ['lodash@4.17.21'],
      );
      assert.equal(code, 1);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, true);
    assert.equal(env.summary.high, 1);
    assert.equal(env.summary.vulnerable, 1);
    assert.equal(env.assessment.riskLevel, 'MODERATE');
  });

  it('populates version anchoring, confidence, and MISSING_PROVENANCE', async () => {
    let out;
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { out = (out || '') + String(s); return true; };
    try {
      await runInspect({ path: '.', json: true, ecosystem: 'npm' }, ['lodash@4.17.21']);
    } finally {
      process.stdout.write = originalOut;
    }
    const env = JSON.parse(out);
    assert.equal(env.schemaVersion, '1.0');
    assert.equal(env.command, 'inspect');
    assert.equal(env.package.version, '4.17.21'); // anchored, not latest-from-elsewhere
    assert.equal(env.assessment.version, '4.17.21');
    assert.equal(env.assessment.registryArtifact.integrity, 'sha512-dGVzdA==');
    assert.equal(env.assessment.registryArtifact.shasum, 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
    assert.ok(Array.isArray(env.findings));

    const prov = env.assessment.signals.find(s => s.signal === 'MISSING_PROVENANCE');
    assert.ok(prov, 'expected MISSING_PROVENANCE signal');
    assert.equal(prov.confidence, 'deterministic');

    for (const s of env.assessment.signals) {
      assert.ok(s.confidence, `signal ${s.signal} has a confidence grade`);
    }
  });

  it('defaults to latest when no version is given', async () => {
    let out;
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { out = (out || '') + String(s); return true; };
    try {
      await runInspect({ path: '.', json: true, ecosystem: 'npm' }, ['lodash']);
    } finally {
      process.stdout.write = originalOut;
    }
    const env = JSON.parse(out.trim());
    assert.equal(env.package.version, '4.17.21'); // dist-tags.latest
  });

  it('fails loud instead of substituting latest when the requested npm version is absent', async () => {
    const previousFetch = global.fetch;
    let osvCalled = false;
    global.fetch = async (url) => {
      if (url.includes('osv.dev')) osvCalled = true;
      if (url.includes('registry.npmjs.org')) return stubResponse(PACK);
      return stubResponse({});
    };
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect(
        { path: '.', json: true, ecosystem: 'npm' },
        ['lodash@0.0.0-does-not-exist'],
      );
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, false);
    assert.equal(env.package.version, '0.0.0-does-not-exist');
    assert.equal(env.assessment, null);
    assert.match(env.warnings.join('\n'), /absent from the registry packument/);
    assert.equal(osvCalled, false, 'must stop before querying a substituted version');
  });

  it('fails loud instead of substituting latest when the requested PyPI version is absent', async () => {
    const previousFetch = global.fetch;
    let osvCalled = false;
    global.fetch = async (url) => {
      if (url.includes('osv.dev')) osvCalled = true;
      if (url.includes('pypi.org/pypi/demo/json')) {
        return stubResponse({
          info: { name: 'demo', version: '2.0.0' },
          releases: { '2.0.0': [{ upload_time_iso_8601: '2026-01-01T00:00:00Z' }] },
        });
      }
      return stubResponse({});
    };
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect(
        { path: '.', json: true, ecosystem: 'pypi' },
        ['demo@1.0.0'],
      );
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, false);
    assert.equal(env.package.version, '1.0.0');
    assert.equal(env.assessment, null);
    assert.match(env.warnings.join('\n'), /absent from PyPI release metadata/);
    assert.equal(osvCalled, false);
  });

  it('emits an incomplete machine envelope when registry metadata is unavailable', async () => {
    const previousFetch = global.fetch;
    global.fetch = async () => stubResponse({}, { ok: false, status: 404 });
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect(
        { path: '.', json: true, ecosystem: 'npm' },
        ['missing-package@1.0.0'],
      );
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, false);
    assert.equal(env.assessment, null);
    assert.match(env.warnings.join('\n'), /registry returned no metadata/);
  });

  it('marks a requested sandbox refusal incomplete without an accepted private-path isolation host', async () => {
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect(
        { path: '.', json: true, ecosystem: 'npm', sandbox: true, sandboxHost: null },
        ['lodash@4.17.21'],
      );
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, false);
    assert.deepEqual(env.stages.sandbox, { requested: true, complete: false });
    assert.match(env.warnings.join('\n'), /bwrap host that contains writes and hides user\/project host paths/);
  });

  it('honors MISSING_PROVENANCE=off for command-added inspect signals', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-inspect-signal-off-'));
    writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({
      analyze: { signals: { MISSING_PROVENANCE: 'off' } },
    }));
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      await runInspect({ path: dir, json: true, ecosystem: 'npm' }, ['lodash@4.17.21']);
    } finally {
      process.stdout.write = originalOut;
      rmSync(dir, { recursive: true, force: true });
    }

    const env = JSON.parse(stdout);
    assert.equal(env.assessment.signals.some(s => s.signal === 'MISSING_PROVENANCE'), false);
  });

  it('marks present-but-undecodable provenance evidence incomplete', async () => {
    const previousFetch = global.fetch;
    global.fetch = async (url) => {
      if (url.includes('osv.dev')) return stubResponse({ results: [{ vulns: [] }] });
      if (url.includes('/-/npm/v1/attestations')) {
        return stubResponse({
          attestations: [{ bundle: { dsseEnvelope: { payload: Buffer.from('not-json').toString('base64') } } }],
        });
      }
      if (url.includes('registry.npmjs.org')) return stubResponse(PACK);
      return stubResponse({});
    };
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect({ path: '.', json: true, ecosystem: 'npm' }, ['lodash@4.17.21']);
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    const env = JSON.parse(stdout);
    assert.equal(env.complete, false);
    assert.equal(env.stages.provenance.complete, false);
    assert.equal(env.assessment.provenance.attestationStatus, 'present-undecodable');
    assert.match(env.warnings.join('\n'), /could not be decoded/);
  });

  it('does not print a clean OSV claim when the text-mode lookup is incomplete', async () => {
    const previousFetch = global.fetch;
    global.fetch = async (url) => {
      if (url.includes('osv.dev')) return stubResponse({ results: [null] });
      if (url.includes('/-/npm/v1/attestations')) return stubResponse({}, { ok: false, status: 404 });
      if (url.includes('registry.npmjs.org')) return stubResponse(PACK);
      return stubResponse({});
    };
    let stdout = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { stdout += String(s); return true; };
    try {
      const code = await runInspect({ path: '.', ecosystem: 'npm' }, ['lodash@4.17.21']);
      assert.equal(code, 2);
    } finally {
      process.stdout.write = originalOut;
      global.fetch = previousFetch;
    }

    assert.match(stdout, /vulnerability lookup incomplete/);
    assert.doesNotMatch(stdout, /no known vulnerabilities/);
  });
});
