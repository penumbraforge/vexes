import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig, validateCacheTtl } from '../src/cli/config.js';

/**
 * CLI flag → config wiring. A flag parsed but never mapped into config is a
 * silent no-op — worse than an error, because the user believes it's enforced.
 * (Regression: `scan --top` parsed in parse-args but never landed in config.)
 */

const DIR = process.cwd();

describe('loadConfig: --top wiring', () => {
  it('maps a positive integer --top into config.top', () => {
    const config = loadConfig(DIR, { top: '5' });
    assert.equal(config.top, 5);
  });

  it('rejects non-numeric and non-positive values without crashing', () => {
    for (const bad of ['zero', '0', '-3', 'abc', '']) {
      const config = loadConfig(DIR, { top: bad });
      assert.equal(config.top, undefined, `--top "${bad}" must not set config.top`);
    }
  });

  it('leaves config.top unset when the flag is absent', () => {
    const config = loadConfig(DIR, {});
    assert.equal(config.top, undefined);
  });
});

describe('loadConfig: untrusted project policy boundary', () => {
  it('cannot opt into execution, writes, stale cache, or a repository cache path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-config-boundary-'));
    try {
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({
        ecosystems: ['npm'],
        sandbox: true,
        sandboxHost: { host: 'unshare', writeIsolation: true, readIsolation: true },
        deep: true,
        fix: true,
        ai: true,
        useCache: true,
        cache: { dir, advisoryTtlMs: 'forever', metadataTtlMs: -1 },
      }));
      const config = loadConfig(dir, {});
      assert.deepEqual(config.ecosystems, ['npm']);
      for (const key of ['sandbox', 'sandboxHost', 'deep', 'fix', 'ai', 'useCache']) {
        assert.equal(config[key], undefined, `${key} must be CLI-only`);
      }
      assert.notEqual(config.cache.dir, dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('allows test host injection only alongside an explicit sandbox flag', () => {
    assert.equal(loadConfig(DIR, { sandboxHost: null }).sandboxHost, undefined);
    const config = loadConfig(DIR, { sandbox: true, sandboxHost: null });
    assert.equal(config.sandbox, true);
    assert.equal(config.sandboxHost, null);
  });

  it('rejects non-finite, nonnumeric, and negative cache TTLs', () => {
    for (const value of ['forever', NaN, Infinity, -1]) {
      assert.throws(() => validateCacheTtl(value, 'cache.advisoryTtlMs'), /finite non-negative number/);
    }
  });

  it('rejects malformed project policy values instead of silently changing scan semantics', () => {
    const cases = [
      [{ severity: 'extreme' }, /severity must be one of/],
      [{ ignore: 'left-pad' }, /ignore must be an array of strings/],
      [{ ignore: [42] }, /ignore must be an array of strings/],
      [{ output: { format: 'xml' } }, /output\.format must be one of/],
      [{ output: { color: 'sometimes' } }, /output\.color must be one of/],
      [{ analyze: { signals: { POSTINSTALL_SCRIPT: false } } }, /must be "off" when present/],
    ];

    for (const [projectConfig, expected] of cases) {
      const dir = mkdtempSync(join(tmpdir(), 'vexes-config-invalid-policy-'));
      try {
        writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify(projectConfig));
        assert.throws(() => loadConfig(dir, {}), expected);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('--no-project-config bypasses repository policy entirely', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-config-no-project-'));
    try {
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({
        severity: 'extreme',
        ignore: 'everything',
        sandbox: true,
      }));
      const config = loadConfig(dir, { 'project-config': false });
      assert.equal(config.severity, 'moderate');
      assert.deepEqual(config.ignore, []);
      assert.equal(config.sandbox, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('accepts --no-user-config as an explicit deterministic-run boundary', () => {
    // The host's real user config is intentionally not mutated in this test;
    // this assertion exercises the flag path and stable defaults.
    const config = loadConfig(DIR, { 'user-config': false, 'project-config': false });
    assert.equal(config.severity, 'moderate');
    assert.deepEqual(config.ignore, []);
  });
});
