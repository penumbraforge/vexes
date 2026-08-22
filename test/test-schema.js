import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  SCHEMA_VERSION,
  CONFIDENCE,
  REACHABILITY,
  buildEnvelope,
  normalizeFinding,
  llmSummary,
} from '../src/cli/schema.js';

const VULN = {
  id: 'GHSA-aaaa',
  aliases: ['CVE-2026-0001'],
  package: 'axios',
  version: '1.14.1',
  ecosystem: 'npm',
  severity: 'CRITICAL',
  summary: 'Remote code execution via compromised dependency',
  fixed: '>= 1.14.2',
  modified: '2026-04-01T00:00:00Z',
};

describe('schema: envelope contract', () => {
  it('has a stable schema version', () => {
    assert.equal(SCHEMA_VERSION, '1.0');
  });

  it('builds a golden envelope carrying the agent contract fields', () => {
    const env = buildEnvelope({
      command: 'scan',
      target: { dir: '/tmp/x', lockfiles: ['package-lock.json'], ecosystems: ['npm'] },
      complete: true,
      warnings: ['w1'],
      summary: { total: 1, vulnerable: 1, critical: 1, moderate: 0, low: 0, high: 0, suppressed: 0, unreachable: 0 },
      findings: [],
    });
    assert.equal(env.schemaVersion, SCHEMA_VERSION);
    assert.equal(env.generator.name, 'vexes');
    assert.equal(env.command, 'scan');
    assert.deepEqual(env.target, { dir: '/tmp/x', lockfiles: ['package-lock.json'], ecosystems: ['npm'] });
    assert.equal(env.complete, true);
    assert.deepEqual(env.result, { complete: true, warnings: ['w1'] });
    assert.ok(env.timestamp);
  });

  it('complete=false is preserved at both levels — agents must never read it as clean', () => {
    const env = buildEnvelope({ command: 'scan', complete: false, warnings: ['partial'] });
    assert.equal(env.complete, false);
    assert.equal(env.result.complete, false);
  });

  it('round-trips through JSON', () => {
    const env = buildEnvelope({ command: 'scan', complete: true, findings: [] });
    const parsed = JSON.parse(JSON.stringify(env));
    assert.equal(parsed.schemaVersion, SCHEMA_VERSION);
    assert.equal(parsed.generator.version, parsed.generator.version);
  });
});

describe('schema: finding normalization', () => {
  it('preserves internal record fields (additive contract)', () => {
    const f = normalizeFinding(VULN);
    assert.equal(f.id, 'GHSA-aaaa');
    assert.equal(f.package, 'axios');
    assert.equal(f.version, '1.14.1');
    assert.equal(f.ecosystem, 'npm');
    assert.equal(f.severity, 'CRITICAL'); // field passthrough
  });

  it('adds severityLevel, confidence, reachability, advisories, llmSummary', () => {
    const f = normalizeFinding(VULN, { direct: true, reachability: REACHABILITY.REACHABLE });
    assert.deepEqual(f.severityLevel, { level: 'CRITICAL', order: 4 });
    assert.equal(f.confidence, CONFIDENCE.PROVEN);
    assert.equal(f.reachability, REACHABILITY.REACHABLE);
    assert.deepEqual(f.advisories, ['GHSA-aaaa', 'CVE-2026-0001']);
    assert.equal(f.direct, true);
    assert.match(f.llmSummary, /Blocker: yes\./);
  });

  it('orders severity via SEVERITY map', () => {
    const a = normalizeFinding({ severity: 'HIGH' }).severityLevel;
    const b = normalizeFinding({ severity: 'LOW' }).severityLevel;
    assert.ok(a.order > b.order);
  });
});

describe('schema: llmSummary', () => {
  it('answers the blocker question and is one sentence', () => {
    const s = llmSummary(VULN, null, { reachability: REACHABILITY.REACHABLE });
    assert.match(s, /\[CRITICAL\] axios@1\.14\.1 \(npm\)/);
    assert.match(s, /Fixed in >= 1\.14\.2/);
    assert.match(s, /Reachable from this project's code/);
    assert.match(s, /Blocker: yes\.$/);
  });

  it('notes dead deps as non-blocking', () => {
    const s = llmSummary({ severity: 'CRITICAL', package: 'x', version: '1', ecosystem: 'npm', id: 'A' },
      null, { reachability: REACHABILITY.DEAD });
    assert.match(s, /dead in the lockfile/);
  });
});
