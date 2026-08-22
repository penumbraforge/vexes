import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runLicenses } from '../src/commands/licenses.js';
import { queryLicenses, fetchVersionLicenses, systemForEcosystem } from '../src/advisories/depsdev.js';

/**
 * LICENSES — deps.dev bill of materials.
 * Hermetic: `global.fetch` is stubbed for the whole file; nothing leaves the
 * host. Asserts the throttle serializes requests, envelope fields exist, and
 * `complete:false` surfaces any package whose lookup failed (fail-loud).
 */

const realFetch = global.fetch;
let requests = []; // [{url, atMs}]

function installStub() {
  requests = [];
  global.fetch = async (url, opts) => {
    // Record wall-clock so the test can prove requests are spaced apart.
    requests.push({ url, atMs: Date.now() });
    const u = String(url);
    if (u.includes('/systems/npm/packages/lodash/versions/')) {
      return { ok: true, json: async () => ({ name: 'lodash', version: '4.17.21', licenses: ['MIT'] }) };
    }
    if (u.includes('/systems/npm/packages/deep-extend/')) {
      return { ok: true, json: async () => ({ name: 'deep-extend', version: '0.6.0', licenses: [] }) };
    }
    if (u.includes('/systems/pypi/packages/requests/')) {
      return { ok: true, json: async () => ({ name: 'requests', version: '2.31.0', licenses: ['Apache-2.0'] }) };
    }
    if (u.includes('/systems/npm/packages/boom/')) {
      throw new Error('network down');
    }
    assert.fail(`unexpected fetch: ${u}`);
  };
}

function restore() { global.fetch = realFetch; }

function fixtureFile(dir, name, content) {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
}

function fixtureDir(entries) {
  const dir = mkdtempSync(join(tmpdir(), 'vexes-licenses-'));
  for (const [rel, content] of Object.entries(entries)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

function cleanupDirs(dirs) { for (const d of dirs) rmSync(d, { recursive: true, force: true }); }

describe('deps.dev client', () => {
  before(installStub);
  after(restore);

  it('maps supported ecosystems to deps.dev systems and skips unknown ones', () => {
    assert.equal(systemForEcosystem('npm'), 'npm');
    assert.equal(systemForEcosystem('java'), 'maven');
    assert.equal(systemForEcosystem('ruby'), null);
    assert.equal(systemForEcosystem('hex'), null);
  });

  it('unwraps a license list from the version metadata payload', async () => {
    const r = await fetchVersionLicenses('npm', 'lodash', '4.17.21');
    assert.equal(r.skipped, false);
    assert.deepEqual(r.licenses, ['MIT']);
    assert.match(r.url, /\/systems\/npm\/packages\/lodash\/versions\/4\.17\.21$/);
  });

  it('treats an empty licenses array as present-but-undetermined, not an error', async () => {
    const r = await fetchVersionLicenses('npm', 'deep-extend', '0.6.0');
    assert.equal(r.skipped, false);
    assert.deepEqual(r.licenses, []);
  });

  it('degrades a failing lookup to skipped-with-reason instead of throwing', async () => {
    const r = await fetchVersionLicenses('npm', 'boom', '9.9.9');
    assert.equal(r.skipped, true);
    assert.ok(typeof r.reason === 'string' && r.reason.length > 0);
  });

  it('marks the batch incomplete when any lookup is skipped', async () => {
    const { records, skipped, complete } = await queryLicenses([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
      { ecosystem: 'npm', name: 'boom', version: '9.9.9' },
    ]);
    assert.equal(skipped, 1);
    assert.equal(complete, false);
    assert.equal(records.length, 2);
  });

  it('leaves a sanitized npm name containing a scope intact', async () => {
    const r = await fetchVersionLicenses('npm', '@babel/core', '7.24.0');
    assert.ok(r.skipped, 'no fixture for @babel/core — skipped path proves no crash on scoped names');
  });
});

describe('vexes licenses (CLI)', () => {
  let dirs = [];
  before(installStub);
  after(() => { restore(); cleanupDirs(dirs); });

  async function captureJson(dir, extraFlags = {}) {
    // NOTE: this Node version flushes the test runner's own protocol to
    // process.stdout during long async windows, so capture only the envelopes
    // out() writes (one full JSON doc per call, containing schemaVersion).
    let out = '';
    const original = process.stdout.write;
    process.stdout.write = (s) => {
      const text = String(s);
      if (text.includes('"schemaVersion"')) out = text;
      return true;
    };
    let code;
    try {
      code = await runLicenses({ path: dir, json: true, ...extraFlags }, []);
    } finally {
      process.stdout.write = original;
    }
    const env = JSON.parse(out);
    return { code, env };
  }

  it('emits a complete JSON envelope with license data in extra.licenses', async () => {
    const dir = fixtureDir({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { lodash: '^4.17.21' } },
          'node_modules/lodash': { version: '4.17.21' },
        },
      }),
    });
    dirs.push(dir);
    const { code, env } = await captureJson(dir);
    assert.equal(code, 0, 'clean project with declared licenses exits OK');
    assert.equal(env.command, 'licenses');
    assert.equal(env.schemaVersion, '1.0');
    assert.equal(env.complete, true);
    assert.equal(env.summary.total, 1);
    assert.equal(env.summary.withLicenses, 1);
    assert.equal(env.summary.missing, 0);
    assert.equal(env.summary.skipped, 0);
    const rec = env.licenses[0];
    assert.deepEqual(rec, { package: 'lodash', version: '4.17.21', ecosystem: 'npm', licenses: ['MIT'], url: env.licenses[0].url });
  });

  it('reports incomplete (exit 2) when a lookup fails — fail-loud, never a clean 0', async () => {
    const dir = fixtureDir({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { boom: '^9.9.9' } },
          'node_modules/boom': { version: '9.9.9' },
        },
      }),
    });
    dirs.push(dir);
    const { code, env } = await captureJson(dir);
    assert.equal(code, 2, 'incomplete license SBOM must exit EXIT.ERROR');
    assert.equal(env.complete, false);
    assert.equal(env.summary.total, 1);
    assert.equal(env.summary.skipped, 1);
    assert.equal(env.licenses[0].skipped, true);
  });

  it('treats missing-but-resolvable licenses as a finding, not an error', async () => {
    const dir = fixtureDir({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app', dependencies: { 'deep-extend': '^0.6.0' } },
          'node_modules/deep-extend': { version: '0.6.0' },
        },
      }),
    });
    dirs.push(dir);
    const { code, env } = await captureJson(dir);
    assert.equal(code, 1, 'missing declared license → VULNS_FOUND so CI can notice');
    assert.equal(env.complete, true); // lookup succeeded; data is simply absent
    assert.equal(env.summary.missing, 1);
  });

  it('is a no-dependency no-op: clean JSON, exit 0', async () => {
    const dir = fixtureDir({ 'unrelated.txt': 'nothing here' });
    dirs.push(dir);
    const { code, env } = await captureJson(dir);
    assert.equal(code, 0);
    assert.equal(env.complete, true);
    assert.equal(env.summary.total, 0);
  });
});
