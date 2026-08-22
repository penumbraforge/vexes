import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { parseInspectTarget, runInspect } from '../src/commands/inspect.js';

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
});
