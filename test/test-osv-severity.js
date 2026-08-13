import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeVuln } from '../src/advisories/osv.js';

/**
 * OSV SEVERITY EXTRACTION
 *
 * OSV puts CVSS *vector strings* in severity[].score. Before the fix these
 * flowed into Math.max() as NaN, every threshold comparison went false, and
 * all PYSEC/RUSTSEC/GO advisories fell through to CRITICAL. These tests pin
 * the fixed behavior against real advisory records saved as fixtures —
 * offline, no network.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'osv');

function loadFixture(id) {
  return JSON.parse(readFileSync(join(FIXTURES, `${id}.json`), 'utf8'));
}

function severityOf(osvVuln, pkg = { name: 'x', version: '1.0.0', ecosystem: 'npm' }) {
  return normalizeVuln(osvVuln, pkg).severity;
}

describe('OSV severity: real advisory fixtures', () => {
  it('PYSEC-2024-230 (vector only, I:H) → HIGH, not CRITICAL', () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N = 7.5
    const vuln = loadFixture('PYSEC-2024-230');
    assert.equal(severityOf(vuln, { name: 'x', version: '1.0.0', ecosystem: 'PyPI' }), 'HIGH');
  });

  it('PYSEC-2023-192 (vector only, PR:L C:H I:H) → HIGH (8.1)', () => {
    const vuln = loadFixture('PYSEC-2023-192');
    assert.equal(severityOf(vuln, { name: 'x', version: '1.0.0', ecosystem: 'PyPI' }), 'HIGH');
  });

  it('GHSA-93q8-gq69-wqmw honors database_specific.severity (HIGH)', () => {
    const vuln = loadFixture('GHSA-93q8-gq69-wqmw');
    assert.equal(severityOf(vuln), 'HIGH');
  });

  it('GHSA-93q8-gq69-wqmw vector path alone also yields HIGH (A:H = 7.5)', () => {
    const vuln = loadFixture('GHSA-93q8-gq69-wqmw');
    delete vuln.database_specific;
    assert.equal(severityOf(vuln), 'HIGH');
  });

  it('GO-2022-0646 (no severity data anywhere) → CRITICAL fail-safe', () => {
    // Deliberate: a security tool assumes worst case ONLY when the advisory
    // carries no severity information at all.
    const vuln = loadFixture('GO-2022-0646');
    assert.equal(severityOf(vuln, { name: 'x', version: '1.0.0', ecosystem: 'Go' }), 'CRITICAL');
  });
});

describe('OSV severity: entry-shape dispatch', () => {
  const base = { id: 'TEST-0001', summary: 't', affected: [], references: [] };

  const withSeverity = (severity) => ({ ...base, severity });

  it('numeric score passes through (9.8 → CRITICAL)', () => {
    assert.equal(severityOf(withSeverity([{ type: 'CVSS_V3', score: 9.8 }])), 'CRITICAL');
  });

  it('numeric string score parses ("5.0" → MODERATE)', () => {
    assert.equal(severityOf(withSeverity([{ type: 'CVSS_V3', score: '5.0' }])), 'MODERATE');
  });

  it('CVSS v3.1 vector in .score computes exact spec math (9.8 → CRITICAL)', () => {
    assert.equal(
      severityOf(withSeverity([{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }])),
      'CRITICAL'
    );
  });

  it('CVSS v3.1 low-impact vector → LOW (C:L local)', () => {
    // CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 2.0
    assert.equal(
      severityOf(withSeverity([{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' }])),
      'LOW'
    );
  });

  it('CVSS v4 vector falls back to attack-vector heuristic (AV:N → HIGH)', () => {
    assert.equal(
      severityOf(withSeverity([{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }])),
      'HIGH'
    );
  });

  it('legacy .vector field still honored', () => {
    assert.equal(
      severityOf(withSeverity([{ type: 'CVSS_V3', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }])),
      'CRITICAL'
    );
  });

  it('highest of multiple entries wins', () => {
    assert.equal(
      severityOf(withSeverity([
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' }, // 2.0
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }, // 7.5
      ])),
      'HIGH'
    );
  });

  it('unparseable entries never poison the max (junk + real vector → real result)', () => {
    assert.equal(
      severityOf(withSeverity([
        { type: 'CVSS_V3', score: 'not-a-vector-or-number' },
        { type: 'WEIRD', score: {} },
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }, // 7.5
      ])),
      'HIGH'
    );
  });

  it('all entries unparseable → CRITICAL fail-safe (never NaN-driven silence)', () => {
    assert.equal(severityOf(withSeverity([{ type: 'CVSS_V3', score: 'garbage' }])), 'CRITICAL');
  });

  it('empty severity array → CRITICAL fail-safe', () => {
    assert.equal(severityOf(withSeverity([])), 'CRITICAL');
  });
});
