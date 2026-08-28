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
 * Exits 0 regardless of differences — the value is the report, not a gate.
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
const packages = {};
const dependencies = {};
for (const [name, version] of PINNED) {
  packages[`node_modules/${name}`] = { version };
  dependencies[name] = { version };
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
  const vexesRun = spawnSync(process.execPath, [join(ROOT, 'bin', 'vexes.js'), 'scan', '--path', dir, '--json', '--severity', 'low'], { encoding: 'utf8', timeout: 120_000 });
  // Advisory identity is fuzzy: the same advisory may surface as a GHSA or
  // a CVE depending on which OSV record the tool got. Match on the full
  // identifier set (id + aliases), never a single key.
  const vexesVulns = []; // [{ ids: Set, package, severity }]
  try {
    const report = JSON.parse(vexesRun.stdout);
    for (const f of report.findings || []) {
      if (!f.id) continue;
      vexesVulns.push({
        ids: new Set([f.id, f.displayId, ...(f.aliases || [])].filter(Boolean)),
        package: f.package,
        severity: f.severity,
      });
    }
  } catch {
    console.error('vexes scan output unparseable');
    process.exit(1);
  }

  // osv-scanner
  const osvRun = spawnSync('osv-scanner', ['--lockfile', lockfile, '--format', 'json'], { encoding: 'utf8', timeout: 120_000 });
  // osv-scanner exits 1 when it finds vulns — parse stdout regardless.
  // Output is pretty-printed JSON; logs go to stderr.
  const osvOut = osvRun.stdout || '';
  const start = osvOut.indexOf('{');
  if (start === -1) {
    console.error('osv-scanner output unparseable (is it installed? brew install osv-scanner)');
    process.exit(1);
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

  const matches = (a, b) => [...a.ids].some(x => b.ids.has(x));
  const unmatched = (aList, bList) => aList.filter(a => !bList.some(b => matches(a, b)));

  const onlyInVexes = unmatched(vexesVulns, osvVulns).map(v => ({
    id: [...v.ids].find(i => i.startsWith('GHSA-')) || v.ids.values().next().value,
    package: v.package,
  }));
  const onlyInOsv = unmatched(osvVulns, vexesVulns).map(v => ({
    id: [...v.ids].find(i => i.startsWith('GHSA-')) || v.ids.values().next().value,
    package: v.package,
  }));
  const shared = vexesVulns.length - onlyInVexes.length;

  if (asJSON) {
    console.log(JSON.stringify({
      vexesCount: vexesVulns.length,
      osvScannerCount: osvVulns.length,
      shared,
      onlyInVexes,
      onlyInOsvScanner: onlyInOsv,
    }, null, 2));
  } else {
    const lines = [];
    lines.push('# OSV parity: vexes scan vs osv-scanner');
    lines.push('');
    lines.push(`vexes: ${vexesVulns.length} advisories | osv-scanner: ${osvVulns.length} | shared: ${shared}`);
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
