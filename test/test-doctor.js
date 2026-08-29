import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { runDoctor, runParserChecks } from '../src/commands/doctor.js';

function stubResponse(body, { ok = true, status = 200 } = {}) {
  return {
    ok, status,
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}
async function stubFetch(url, opts = {}) {
  return stubResponse({});
}

describe('doctor: self test', () => {
  let restore;
  before(() => {
    const prev = global.fetch;
    restore = () => { global.fetch = prev; };
    global.fetch = stubFetch;
  });
  after(() => restore());

  it('passes parser + cache checks and reports network status', async () => {
    let out;
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { out = (out || '') + String(s); return true; };
    try {
      const code = await runDoctor({ path: '.', json: true }, []);
      assert.equal(code, 0);
    } finally {
      process.stdout.write = originalOut;
    }
    const env = JSON.parse(out.trim());
    assert.equal(env.command, 'doctor');
    assert.equal(env.schemaVersion, '1.0');
    assert.equal(env.complete, true);
    assert.ok(env.checks.length >= 2, 'has checks');

    const names = env.checks.map(c => c.name);
    assert.ok(names.some(n => n.startsWith('parser')), `parser checks present: ${names.join(', ')}`);
    assert.ok(names.includes('cache'), 'cache check present');

    // All non-optional checks must pass for complete:true
    const required = env.checks.filter(c => !c.optional);
    assert.ok(required.every(c => c.ok), `required checks all ok: ${JSON.stringify(required)}`);
    const parserChecks = required.filter(c => c.name.startsWith('parser '));
    assert.ok(parserChecks.every(c => c.actualCount >= c.expectedMinimum));
    assert.ok(parserChecks.every(c => typeof c.expectedCoordinate === 'string' && c.expectedCoordinate.includes('@')));
  });

  it('fails when a parser silently returns an empty result', async () => {
    let output = '';
    const originalOut = process.stdout.write;
    process.stdout.write = (s) => { output += String(s); return true; };
    let code;
    try {
      code = await runDoctor({ path: '.', json: true }, [], {
        fixturesDir: '.',
        parserChecks: [{
          name: 'regression fixture',
          file: 'ignored',
          parseFn: () => [],
          minCount: 1,
          expected: { name: 'known-package', version: '1.2.3' },
        }],
      });
    } finally {
      process.stdout.write = originalOut;
    }

    assert.equal(code, 2);
    const env = JSON.parse(output.trim());
    assert.equal(env.complete, false);
    const parserCheck = env.checks.find(c => c.name === 'parser regression fixture');
    assert.equal(parserCheck.ok, false);
    assert.match(parserCheck.detail, /returned 0 dep\(s\); expected at least 1/);
  });

  it('fails when the expected fixture coordinate disappears despite a nonempty result', async () => {
    const [check] = await runParserChecks('.', [{
      name: 'coordinate regression fixture',
      file: 'ignored',
      parseFn: () => [{ name: 'wrong-package', version: '1.2.3' }],
      minCount: 1,
      expected: { name: 'known-package', version: '1.2.3' },
    }]);
    assert.equal(check.ok, false);
    assert.match(check.detail, /missing expected coordinate known-package@1\.2\.3/);
  });

  it('supports fixtures explicitly declared as intentionally empty', async () => {
    const [check] = await runParserChecks('.', [{
      name: 'intentional empty fixture',
      file: 'ignored',
      parseFn: () => [],
      minCount: 0,
      expected: null,
      intentionalEmpty: true,
    }]);
    assert.equal(check.ok, true);
    assert.equal(check.actualCount, 0);
  });

  it('reports EXIT.ERROR when a parser check fails (fail-loud, never a fake clean)', async () => {
    const { mkdtempSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'vexes-doctor-empty-'));
    let code;
    try {
      // Fixtures resolve from the package root (not cwd), so the fail-loud
      // path is exercised by pointing doctor at a missing fixtures dir.
      code = await runDoctor({ path: dir, json: true }, [], { fixturesDir: join(dir, 'no-such-fixtures') });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    assert.equal(code, 2); // EXIT.ERROR — incomplete self test must not look clean
  });
});
