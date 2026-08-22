import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { runDoctor } from '../src/commands/doctor.js';

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
  });

  it('reports EXIT.ERROR when a parser check fails (fail-loud, never a fake clean)', async () => {
    const { mkdtempSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'vexes-doctor-empty-'));
    const cwd = process.cwd();
    process.chdir(dir); // parser fixtures are resolved from cwd — an empty dir fails them
    let code;
    try {
      code = await runDoctor({ path: dir, json: true }, []);
    } finally {
      process.chdir(cwd);
      rmSync(dir, { recursive: true, force: true });
    }
    assert.equal(code, 2); // EXIT.ERROR — incomplete self test must not look clean
  });
});
