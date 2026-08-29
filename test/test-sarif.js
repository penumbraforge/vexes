import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { toSarif } from '../src/cli/sarif.js';
import { VERSION } from '../src/core/constants.js';

const scanResult = {
  version: VERSION,
  timestamp: '2026-08-12T00:00:00.000Z',
  command: 'scan',
  complete: true,
  summary: { total: 10, vulnerable: 4, suppressed: 0, critical: 1, high: 1, moderate: 1, low: 1 },
  warnings: ['one advisory detail could not be fetched'],
  vulnerabilities: [
    { id: 'GHSA-crit', displayId: 'GHSA-crit', aliases: ['CVE-2026-1'], summary: 'Critical RCE', severity: 'CRITICAL', package: 'lodash', version: '4.17.20', ecosystem: 'npm', fixed: '>= 4.17.21', url: 'https://osv.dev/vulnerability/GHSA-crit', references: ['https://example.com/a'] },
    { id: 'GHSA-high', displayId: 'GHSA-high', aliases: [], summary: 'High severity', severity: 'HIGH', package: 'requests', version: '2.25.0', ecosystem: 'pypi', fixed: null, url: 'https://osv.dev/vulnerability/GHSA-high', references: [] },
    { id: 'GHSA-mod', displayId: 'GHSA-mod', aliases: [], summary: 'Moderate', severity: 'MODERATE', package: 'tokio', version: '1.0.0', ecosystem: 'cargo', fixed: '1.0.1', url: 'https://osv.dev/vulnerability/GHSA-mod', references: [] },
    { id: 'GHSA-low', displayId: 'GHSA-low', aliases: [], summary: 'Low', severity: 'LOW', package: 'gopkg', version: '0.1.0', ecosystem: 'go', fixed: null, url: 'https://osv.dev/vulnerability/GHSA-low', references: [] },
  ],
};

describe('toSarif', () => {
  const doc = toSarif(scanResult);

  it('produces a valid SARIF 2.1.0 skeleton', () => {
    assert.equal(doc.version, '2.1.0');
    assert.ok(typeof doc.$schema === 'string' && doc.$schema.includes('sarif') && doc.$schema.includes('2.1.0'));
    assert.equal(doc.runs.length, 1);
    const driver = doc.runs[0].tool.driver;
    assert.equal(driver.name, 'vexes');
    assert.equal(driver.version, VERSION);
    assert.ok(driver.informationUri.startsWith('https://'));
  });

  it('emits one rule per unique advisory id', () => {
    const rules = doc.runs[0].tool.driver.rules;
    assert.equal(rules.length, 4);
    const ids = rules.map(r => r.id).sort();
    assert.deepEqual(ids, ['GHSA-crit', 'GHSA-high', 'GHSA-low', 'GHSA-mod']);
    for (const rule of rules) {
      assert.ok(rule.name);
      assert.ok(rule.shortDescription.text);
      assert.ok('helpUri' in rule);
    }
  });

  it('dedupes rules when multiple findings share an id', () => {
    const dup = { ...scanResult, vulnerabilities: [scanResult.vulnerabilities[0], { ...scanResult.vulnerabilities[0], package: 'lodash', version: '3.0.0' }] };
    const d = toSarif(dup);
    assert.equal(d.runs[0].tool.driver.rules.length, 1, 'one rule');
    assert.equal(d.runs[0].results.length, 2, 'two results');
  });

  it('emits one result per finding', () => {
    assert.equal(doc.runs[0].results.length, 4);
  });

  it('maps severity → level correctly (error/warning/note)', () => {
    const byRule = Object.fromEntries(doc.runs[0].results.map(r => [r.ruleId, r.level]));
    assert.equal(byRule['GHSA-crit'], 'error');
    assert.equal(byRule['GHSA-high'], 'error');
    assert.equal(byRule['GHSA-mod'], 'warning');
    assert.equal(byRule['GHSA-low'], 'note');
  });

  it('sets properties.security-severity from severity', () => {
    const byRule = Object.fromEntries(doc.runs[0].tool.driver.rules.map(r => [r.id, r.properties['security-severity']]));
    assert.equal(byRule['GHSA-crit'], '9.0');
    assert.equal(byRule['GHSA-high'], '7.0');
    assert.equal(byRule['GHSA-mod'], '4.0');
    assert.equal(byRule['GHSA-low'], '1.0');
  });

  it('message.text includes package@version, summary, and fix', () => {
    const crit = doc.runs[0].results.find(r => r.ruleId === 'GHSA-crit');
    assert.ok(crit.message.text.includes('lodash@4.17.20'));
    assert.ok(crit.message.text.includes('Critical RCE'));
    assert.ok(crit.message.text.includes('4.17.21'), 'fix version present');
  });

  it('locations carry a manifest physicalLocation and a package logical location', () => {
    const crit = doc.runs[0].results.find(r => r.ruleId === 'GHSA-crit');
    const loc = crit.locations[0];
    assert.equal(loc.physicalLocation.artifactLocation.uri, 'package-lock.json');
    assert.equal(loc.logicalLocations[0].name, 'lodash@4.17.20');
  });

  it('includes partialFingerprints keyed by ecosystem:package:id', () => {
    const crit = doc.runs[0].results.find(r => r.ruleId === 'GHSA-crit');
    assert.equal(crit.partialFingerprints['vexes/packageVulnerability/v1'], 'npm:lodash:GHSA-crit');
  });

  it('emits canonical direct-import evidence without using it to suppress findings', () => {
    const one = toSarif({
      ...scanResult,
      vulnerabilities: [{ ...scanResult.vulnerabilities[0], reachability: 'dead', importEvidence: 'not_found' }],
    });
    assert.equal(one.runs[0].results.length, 1);
    assert.equal(one.runs[0].results[0].properties.importEvidence, 'not_found');
    assert.equal(one.runs[0].results[0].properties.reachability, 'dead');
  });

  it('reports warnings as invocation notifications and reflects completeness', () => {
    const inv = doc.runs[0].invocations[0];
    assert.equal(inv.executionSuccessful, true);
    assert.equal(inv.toolExecutionNotifications.length, 1);
    const incomplete = toSarif({ ...scanResult, complete: false });
    assert.equal(incomplete.runs[0].invocations[0].executionSuccessful, false);
  });

  it('handles an empty scan result', () => {
    const empty = toSarif({ vulnerabilities: [], warnings: [] });
    assert.equal(empty.version, '2.1.0');
    assert.equal(empty.runs[0].results.length, 0);
    assert.equal(empty.runs[0].tool.driver.rules.length, 0);
  });

  it('serializes to valid JSON', () => {
    const round = JSON.parse(JSON.stringify(doc));
    assert.equal(round.version, '2.1.0');
  });
});
