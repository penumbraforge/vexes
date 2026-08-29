#!/usr/bin/env node
/**
 * OSV parity check: vexes scan vs Google's osv-scanner on the same lockfile.
 *
 * Both tools query OSV.dev, so on identical inputs their advisory sets should
 * agree. Differences are worth understanding either way: a vuln osv-scanner
 * reports that vexes does not is a vexes miss; the reverse is usually a
 * version-range handling difference worth pinning down.
 *
 * Dev-only diagnostic (osv-scanner must be on PATH: brew install osv-scanner).
 * Advisory-set differences are reported rather than gated, but malformed or
 * incomplete scanner output fails nonzero instead of becoming an empty set.
 *
 * Usage: node benchmark/parity.mjs [--json]
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const asJSON = process.argv.includes('--json');

// A spread of ordinary CVE-carrying versions plus the historical malicious
// pins. Not malware — these are all public advisory ranges.
const PINNED = [
  ['lodash', '4.17.20'],
  ['axios', '0.19.2'],
  ['minimist', '1.2.0'],
  ['json5', '2.2.1'],
  ['semver', '7.5.1'],
  ['qs', '6.5.2'],
  ['event-stream', '3.3.6'],
  ['ua-parser-js', '0.7.29'],
  ['coa', '2.0.3'],
  ['node-ipc', '11.3.0'],
  ['crossenv', '0.0.8'],
];

const dir = mkdtempSync(join(tmpdir(), 'vexes-parity-'));
const lockfile = join(dir, 'package-lock.json');
const packages = {
  '': {
    name: 'vexes-parity-check',
    version: '1.0.0',
    dependencies: Object.fromEntries(PINNED),
  },
};
const dependencies = {};
for (const [name, version] of PINNED) {
  const tarballName = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name;
  const resolved = `https://registry.npmjs.org/${name}/-/${tarballName}-${version}.tgz`;
  packages[`node_modules/${name}`] = { version, resolved };
  dependencies[name] = { version, resolved };
}
writeFileSync(lockfile, JSON.stringify({
  name: 'vexes-parity-check',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages,
  dependencies,
}, null, 2));

try {
  // vexes scan
  const vexesRun = spawnSync(process.execPath, [
    join(ROOT, 'bin', 'vexes.js'),
    'scan', '--path', dir, '--format', 'json', '--severity', 'low',
    '--no-project-config', '--no-user-config',
  ], { encoding: 'utf8', timeout: 120_000 });
  if (vexesRun.error) throw new Error(`vexes scan failed to start: ${vexesRun.error.message}`);
  if (![0, 1].includes(vexesRun.status)) {
    throw new Error(`vexes scan was incomplete (exit ${vexesRun.status ?? 'unknown'}): ${vexesRun.stderr.trim() || 'no diagnostic'}`);
  }
  // Advisory identity is fuzzy: the same advisory may surface as a GHSA or
  // a CVE depending on which OSV record the tool got. Match on the full
  // identifier set (id + aliases), never a single key.
  const vexesVulns = []; // [{ ids: Set, package, severity }]
  try {
    const report = JSON.parse(vexesRun.stdout);
    if (report?.schemaVersion !== '1.0' || report?.generator?.name !== 'vexes' ||
        report?.command !== 'scan' || report?.complete !== true || report?.result?.complete !== true ||
        !Array.isArray(report.findings)) {
      throw new Error('output was not a complete vexes scan envelope');
    }
    for (const f of report.findings || []) {
      if (!f.id) continue;
      vexesVulns.push({
        ids: new Set([f.id, f.displayId, ...(f.aliases || [])].filter(Boolean)),
        package: f.package,
        severity: f.severity,
      });
    }
  } catch (error) {
    throw new Error(`vexes scan output invalid: ${error.message}`);
  }

  // osv-scanner
  const osvRun = spawnSync('osv-scanner', ['--lockfile', lockfile, '--format', 'json'], { encoding: 'utf8', timeout: 120_000 });
  if (osvRun.error) throw new Error(`osv-scanner failed to start: ${osvRun.error.message}`);
  if (![0, 1].includes(osvRun.status)) {
    throw new Error(`osv-scanner failed (exit ${osvRun.status ?? 'unknown'}): ${osvRun.stderr.trim() || 'no diagnostic'}`);
  }
  // osv-scanner exits 1 when it finds vulns — parse stdout regardless.
  // Output is pretty-printed JSON; logs go to stderr.
  const osvOut = osvRun.stdout || '';
  const start = osvOut.indexOf('{');
  if (start === -1) {
    throw new Error('osv-scanner output unparseable (is it installed? brew install osv-scanner)');
  }
  const parsed = JSON.parse(osvOut.slice(start));
  const osvVulns = []; // [{ ids: Set, package }]
  for (const result of parsed.results || []) {
    for (const pkg of result.packages || []) {
      for (const group of pkg.groups || []) {
        osvVulns.push({
          ids: new Set([...(group.ids || []), ...(group.aliases || [])].filter(Boolean)),
          package: pkg.package?.name,
        });
      }
    }
  }

  const matches = (a, b) => a.package === b.package && [...a.ids].some(x => b.ids.has(x));

  // OSV can expose alias-linked records at different granularities. Collapse
  // overlapping identifier sets per package before comparing them so two raw
  // records for one advisory family do not inflate or contradict the parity
  // count. This remains a package+identity comparison, not a count-only check.
  const collapseIdentities = (records) => {
    const groups = [];
    for (const record of records) {
      const current = { package: record.package, ids: new Set(record.ids) };
      let changed = true;
      while (changed) {
        changed = false;
        for (let i = groups.length - 1; i >= 0; i--) {
          if (matches(current, groups[i])) {
            for (const id of groups[i].ids) current.ids.add(id);
            groups.splice(i, 1);
            changed = true;
          }
        }
      }
      groups.push(current);
    }
    return groups;
  };

  const vexesIdentities = collapseIdentities(vexesVulns);
  const osvIdentities = collapseIdentities(osvVulns);
  const unmatched = (aList, bList) => aList.filter(a => !bList.some(b => matches(a, b)));

  const onlyInVexes = unmatched(vexesIdentities, osvIdentities).map(v => ({
    id: [...v.ids].find(i => i.startsWith('GHSA-')) || v.ids.values().next().value,
    package: v.package,
  }));
  const onlyInOsv = unmatched(osvIdentities, vexesIdentities).map(v => ({
    id: [...v.ids].find(i => i.startsWith('GHSA-')) || v.ids.values().next().value,
    package: v.package,
  }));
  const shared = vexesIdentities.length - onlyInVexes.length;

  if (asJSON) {
    console.log(JSON.stringify({
      vexesCount: vexesIdentities.length,
      osvScannerCount: osvIdentities.length,
      vexesRawCount: vexesVulns.length,
      osvScannerRawCount: osvVulns.length,
      shared,
      onlyInVexes,
      onlyInOsvScanner: onlyInOsv,
    }, null, 2));
  } else {
    const lines = [];
    lines.push('# OSV parity: vexes scan vs osv-scanner');
    lines.push('');
    lines.push(`vexes: ${vexesIdentities.length} identities (${vexesVulns.length} raw) | osv-scanner: ${osvIdentities.length} identities (${osvVulns.length} raw) | shared: ${shared}`);
    lines.push('');
    lines.push('| advisory | package | in vexes | in osv-scanner |');
    lines.push('|---|---|---|---|');
    for (const v of onlyInVexes) {
      lines.push(`| ${v.id} | ${v.package} | ✅ | — |`);
    }
    for (const v of onlyInOsv) {
      lines.push(`| ${v.id} | ${v.package} | — | ✅ |`);
    }
    if (onlyInVexes.length === 0 && onlyInOsv.length === 0) {
      lines.push(`| all ${shared} advisories | — | ✅ | ✅ |`);
    }
    const report = lines.join('\n');
    console.log(report);
    if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, report);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
