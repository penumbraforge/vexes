#!/usr/bin/env node
/**
 * vexes detection benchmark.
 *
 * Measures three things, none of which download malware:
 *
 *   Part A — KNOWN-BAD FLAGGING. Lockfiles pinning historical malicious
 *   versions (all removed from npm, all in OSV). `vexes scan` must flag
 *   each from its OSV advisory. No package is downloaded — a lockfile is
 *   just text. This gates the exit code: flagging a known compromise is
 *   the one thing vexes must never regress on.
 *
 *   Part B — TECHNIQUE FIXTURES. Attack techniques (env exfil, downloader,
 *   payload decode, typosquat, capability escalation) re-authored by us as
 *   inert source strings and fed through analyzePackage in-process. These
 *   are our own benign code. Reports per-technique which signal families
 *   fired. No gate — the heuristic layer evolves on purpose.
 *
 *   Part C — BENIGN FALSE-POSITIVE RATE. Popular real packages via
 *   `vexes inspect --deep` (tarball analyzed as text, never executed).
 *   FPs count as any CRITICAL or HIGH signal. Deliberately includes one
 *   postinstall-carrying package (esbuild) as a stressor. Reports only.
 *
 * Usage:
 *   node benchmark/run.mjs                 # all parts, markdown to stdout
 *   node benchmark/run.mjs --part a        # just known-bad flagging
 *   node benchmark/run.mjs --json          # machine-readable result
 *   node benchmark/run.mjs --report f.md   # also write markdown to a file
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VEXES = join(ROOT, 'bin', 'vexes.js');
const manifest = JSON.parse(readFileSync(join(ROOT, 'benchmark', 'manifest.json'), 'utf8'));

const args = process.argv.slice(2);
const wantPart = (p) => !args.includes('--part') || args[args.indexOf('--part') + 1] === p;
const asJSON = args.includes('--json');
const reportFile = args.includes('--report') ? args[args.indexOf('--report') + 1] : null;

// ── helpers �─────────────────────────────────────────────────────────────

function runVexes(cliArgs) {
  const r = spawnSync(process.execPath, [VEXES, ...cliArgs], {
    encoding: 'utf8',
    timeout: 120_000,
  });
  if (!r.stdout) return null;
  try {
    return JSON.parse(r.stdout);
  } catch {
    return null;
  }
}

// ── Part A: known-bad flagging via OSV ──────────────────────────────────

function runPartA() {
  const results = [];
  for (const entry of manifest.knownBad) {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-bench-a-'));
    // Lockfiles are data, not code — pinning a removed malicious version
    // here downloads nothing and runs nothing.
    const lockfile = {
      name: 'vexes-benchmark-known-bad',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        [`node_modules/${entry.name}`]: {
          version: entry.version,
          resolved: `https://registry.npmjs.org/${entry.name}/-/${entry.name}-${entry.version}.tgz`,
        },
      },
      dependencies: {
        [entry.name]: { version: entry.version },
      },
    };
    writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lockfile, null, 2));

    // --severity low: Part A measures whether the OSV intelligence layer
    // DETECTS the compromise. Some historical incidents (node-ipc ProTest)
    // carry LOW CVSS severities, and the default `moderate` display filter
    // would hide them — that's a threshold choice, not a detection miss.
    const report = runVexes(['scan', '--path', dir, '--json', '--severity', 'low']);
    // scan findings carry `package` as a plain string name.
    const findings = (report?.findings || []).filter(
      (f) => (typeof f.package === 'string' ? f.package : f.package?.name || f.name) === entry.name
    );
    const hit =
      findings.some((f) => f.signal === 'KNOWN_COMPROMISED') ||
      findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');

    results.push({ ...entry, hit, signals: findings.map((f) => f.signal) });
  }
  return results;
}

// ── Part B: technique fixtures, in-process ──────────────────────────────

async function runPartB() {
  const { analyzePackage } = await import(join(ROOT, 'src', 'analysis', 'signals.js'));
  const results = [];
  for (const t of manifest.techniques) {
    const metadata = {
      name: t.name,
      latestVersion: '2.0.0',
      previousVersion: '1.0.0',
      maintainers: [{ name: 'author' }],
      latestPublisher: 'author',
      previousPublisher: 'author',
      maintainerChanged: false,
      hasInstallScripts: Object.keys(t.scripts).length > 0,
      installScripts: t.scripts,
      previousInstallScripts: t.previousInstallScripts,
      scripts: {},
      dependencies: [],
      addedDeps: [],
      removedDeps: [],
      latestPublishTime: null,
      previousPublishTime: null,
      publishIntervalMs: null,
      packageAgeMs: 400 * 24 * 60 * 60 * 1000,
      majorJump: 0,
      dormancyMs: null,
      versionCount: 3,
      repository: `https://github.com/example/${t.name}`,
      license: 'MIT',
    };

    const { signals } = await analyzePackage(metadata, null, { ecosystem: 'npm' });
    // npm is required so the typosquat fixture checks against the npm
    // popular-name set. addedDeps is empty, so Layer 2 makes no registry
    // fetches — nothing here touches the network.
    const fired = new Set(signals.map((s) => s.signal));
    const hit = t.expectAnyOf.length === 0 || t.expectAnyOf.some((s) => fired.has(s));
    const strayFP = (t.expectNone || []).filter((s) => fired.has(s));

    results.push({
      id: t.id,
      technique: t.technique,
      hit,
      expectAnyOf: t.expectAnyOf,
      fired: [...fired],
      strayFP,
    });
  }
  return results;
}

// Part C — benign false-positive rate. `vexes inspect <name> --deep` fetches
// registry metadata + the tarball and AST-inspects it as text; it does not
// execute package code (sandboxing is an explicit, separate flag we never pass).
function runPartC() {
  const results = [];
  for (const entry of manifest.benignLive) {
    const report = runVexes(['inspect', entry.name, '--deep', '--json']);
    if (!report) {
      results.push({ ...entry, error: true, fp: null });
      continue;
    }
    const s = report.summary || {};
    const fired = (report.assessment?.signals || []).map((x) => x.signal);
    results.push({
      ...entry,
      fp: s.critical > 0 || s.high > 0,
      severities: { critical: s.critical, high: s.high, moderate: s.moderate, low: s.low },
      signals: fired,
    });
  }
  return results;
}

// ── reporting ───────────────────────────────────────────────────────────

function summarize([a, b, c]) {
  const aHit = a.filter((r) => r.hit).length;
  const bHit = b.filter((r) => r.hit).length;
  const cFP = c.filter((r) => r.fp).length;
  const cErr = c.filter((r) => r.error).length;
  const lines = [];

  lines.push(`# vexes detection benchmark`);
  lines.push('');
  lines.push(`## Part A — known-bad flagging (OSV) — ${aHit}/${a.length} flagged`);
  lines.push('');
  lines.push('| package | version | incident | advisory | flagged |');
  lines.push('|---|---|---|---|---|');
  for (const r of a) {
    lines.push(`| ${r.name} | ${r.version} | ${r.incident} | ${r.advisory} | ${r.hit ? '✅' : '❌'} |`);
  }
  lines.push('');

  lines.push(`## Part B — technique fixtures — ${bHit}/${b.length} detected`);
  lines.push('');
  lines.push('| technique | expected (any of) | fired | result |');
  lines.push('|---|---|---|---|');
  for (const r of b) {
    const mark = r.hit ? '✅' : '❌';
    const extra = r.strayFP.length ? ` (stray: ${r.strayFP.join(', ')})` : '';
    lines.push(`| ${r.id} | ${r.expectAnyOf.join(', ') || '—'} | ${r.fired.join(', ') || 'none'} | ${mark}${extra} |`);
  }
  lines.push('');

  lines.push(`## Part C — benign false positives — ${cFP}/${c.length} flagged${cErr ? ` (${cErr} errored)` : ''}`);
  lines.push('');
  lines.push('| package | HIGH/CRITICAL signals | result |');
  lines.push('|---|---|---|');
  for (const r of c) {
    if (r.error) {
      lines.push(`| ${r.name} | — | ⚠️ error |`);
    } else {
      lines.push(`| ${r.name} | ${r.signals.join(', ') || 'none'} | ${r.fp ? '🚩 FP' : '✅'} |`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

// ── main ────────────────────────────────────────────────────────────────

const [a, b, c] = [
  wantPart('a') ? runPartA() : [],
  wantPart('b') ? await runPartB() : [],
  wantPart('c') ? runPartC() : [],
];

const result = { parts: { knownBad: a, techniques: b, benignLive: c } };
const markdown = summarize([a, b, c]);

if (asJSON) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(markdown);
}

if (reportFile) writeFileSync(reportFile, markdown);
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);

// The only gate: a known compromise must be flagged. Technique detection and
// the benign FP rate are published, not gated — they're tuning targets.
const misses = a.filter((r) => !r.hit).length;
if (misses > 0) {
  console.error(`benchmark regression: ${misses} known-bad package(s) not flagged`);
  process.exit(1);
}
