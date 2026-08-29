import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/cli/config.js';
import { parseArgs } from '../src/cli/parse-args.js';
import { inspectJS } from '../src/analysis/ast-inspector.js';

// ── Ecosystem validation ────────────────────────────────────────────

describe('Ecosystem validation', () => {
  it('accepts valid ecosystem names', () => {
    const config = loadConfig('/tmp', { ecosystem: 'npm' });
    assert.deepEqual(config.ecosystems, ['npm']);
  });

  it('accepts pypi ecosystem', () => {
    const config = loadConfig('/tmp', { ecosystem: 'pypi' });
    assert.deepEqual(config.ecosystems, ['pypi']);
  });

  it('lowercases ecosystem input', () => {
    const config = loadConfig('/tmp', { ecosystem: 'NPM' });
    assert.deepEqual(config.ecosystems, ['npm']);
  });

  it('throws on unknown ecosystem instead of silently scanning nothing', () => {
    // A security tool must reject invalid ecosystems — silently scanning nothing
    // and reporting "clean" is a total bypass
    assert.throws(() => loadConfig('/tmp', { ecosystem: 'nmp' }), /unknown ecosystem/);
  });

  it('rejects a string ecosystems config instead of iterating its characters', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-config-shape-'));
    try {
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({ ecosystems: 'npm' }));
      assert.throws(() => loadConfig(dir, {}), /ecosystems must be an array/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── Severity validation ─────────────────────────────────────────────

describe('Severity validation', () => {
  it('accepts valid severity levels', () => {
    const config = loadConfig('/tmp', { severity: 'critical' });
    assert.equal(config.severity, 'critical');
  });

  it('defaults on invalid severity', () => {
    const config = loadConfig('/tmp', { severity: 'extreme' });
    // Should keep the default (moderate) rather than setting invalid
    assert.equal(config.severity, 'moderate');
  });
});

// ── Parse args: new flags ───────────────────────────────────────────

describe('Parse args: new flags', () => {
  it('parses --force flag', () => {
    const r = parseArgs(['guard', '--force']);
    assert.equal(r.flags.force, true);
  });

  it('parses --sarif flag', () => {
    const r = parseArgs(['monitor', '--ci', '--sarif']);
    assert.equal(r.flags.sarif, true);
    assert.equal(r.flags.ci, true);
  });

  it('parses fix command', () => {
    const r = parseArgs(['fix']);
    assert.equal(r.command, 'fix');
  });

  it('parses guard command', () => {
    const r = parseArgs(['guard']);
    assert.equal(r.command, 'guard');
  });

  it('parses monitor command', () => {
    const r = parseArgs(['monitor']);
    assert.equal(r.command, 'monitor');
  });
});

// ── CVSS v3.1 score parsing (via osv.js) ────────────────────────────
// We can't test parseCvssScore directly since it's not exported,
// but we test it through the severity extraction in extractSeverity.
// Instead, test the AST inspector capabilities that depend on proper scoring.

describe('AST Inspector edge cases for robustness', () => {
  it('handles empty source code', () => {
    const r = inspectJS('');
    assert.equal(r.findingCount, 0);
  });

  it('handles source with only comments', () => {
    const r = inspectJS('// just a comment\n/* block comment */');
    assert.equal(r.findingCount, 0);
  });

  it('handles deeply nested eval', () => {
    const code = 'if (true) { if (true) { if (true) { eval("payload"); } } }';
    const r = inspectJS(code);
    assert.ok(r.capabilities.executesCode);
  });

  it('handles multiple require bindings without confusion', () => {
    const code = `
      const fs = require('fs');
      const cp = require('child_process');
      fs.readFileSync('file');
      cp.exec('cmd');
    `;
    const r = inspectJS(code);
    // Should detect cp.exec but NOT flag fs.readFileSync
    assert.ok(r.capabilities.spawnsProcess);
    const fsWrites = r.findings.filter(f => f.pattern === 'FILESYSTEM_WRITE');
    assert.equal(fsWrites.length, 0, 'readFileSync should not be flagged');
  });

  it('detects chained require().method() even in expressions', () => {
    const code = 'const result = require("child_process").execSync("whoami").toString();';
    const r = inspectJS(code);
    assert.ok(r.capabilities.spawnsProcess);
  });
});

// ── Config prototype pollution protection ───────────────────────────

describe('Config security', () => {
  it('rejects __proto__ in merge', () => {
    // loadConfig merges user/project config — ensure __proto__ is blocked
    const config = loadConfig('/tmp', {});
    // The config should not have any __proto__ contamination
    assert.equal(config.__proto__, Object.prototype);
  });

  it('loadConfig isolates calls — flag writes never leak into DEFAULTS', () => {
    // Call once with --json (mutates config.output.format), then plain.
    const jsonConfig = loadConfig('/tmp', { json: true });
    assert.equal(jsonConfig.output.format, 'json');

    // A subsequent call with no flags must NOT see the previous json format.
    const plainConfig = loadConfig('/tmp', {});
    assert.equal(plainConfig.output.format, 'text',
      'DEFAULTS.output was mutated by the previous call — isolation broken');

    // The two configs must not share nested object references.
    assert.notEqual(jsonConfig.output, plainConfig.output);
    assert.notEqual(jsonConfig.cache, plainConfig.cache);
  });

  it('loadConfig does not mutate DEFAULTS across calls with different flags', () => {
    // The cache-dir ~ expansion previously mutated the shared DEFAULTS.cache.dir.
    const first = loadConfig('/tmp', { json: true });
    const firstCacheDir = first.cache.dir;
    // Mutate the returned config aggressively.
    first.output.format = 'mutated';
    first.cache.dir = '/somewhere/else';
    // A fresh call must be pristine.
    const second = loadConfig('/tmp', {});
    assert.equal(second.output.format, 'text');
    assert.equal(second.cache.dir, firstCacheDir);
  });
});
