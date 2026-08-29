#!/usr/bin/env node
/**
 * vexes detection benchmark.
 *
 * Part A identifies exact advisories on historical malicious versions without
 * downloading their packages. Part B analyzes inert, locally-authored technique
 * fixtures and negative controls. Part C samples digest-pinned, currently
 * low-risk npm controls without executing package code.
 *
 * Every selected part is a gate. Execution errors exit 2 and complete metric
 * regressions exit 1. Expected bounded sampling stays status INCOMPLETE but
 * exits 0 unless --require-complete is explicitly requested.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const THIS_FILE = fileURLToPath(import.meta.url);
export const ROOT = join(dirname(THIS_FILE), '..');
const VEXES = join(ROOT, 'bin', 'vexes.js');
export const defaultManifest = JSON.parse(
  readFileSync(join(ROOT, 'benchmark', 'manifest.json'), 'utf8')
);

const ADVISORY_SIGNALS = new Set([
  'KNOWN_MALICIOUS',
  'KNOWN_VULNERABILITY',
  'OSV_MATCH',
  'KNOWN_COMPROMISED', // older output remains benchmark-readable
]);
const LOUD = new Set(['CRITICAL', 'HIGH']);
const PART_NAMES = Object.freeze({ a: 'knownBad', b: 'techniques', c: 'benignLive' });

export function parseBenchmarkArgs(argv = []) {
  const partIndex = argv.indexOf('--part');
  const part = partIndex >= 0 ? argv[partIndex + 1] : null;
  if (partIndex >= 0 && !PART_NAMES[part]) {
    throw new Error(`--part must be one of a, b, or c (got ${part || 'nothing'})`);
  }
  const reportIndex = argv.indexOf('--report');
  if (reportIndex >= 0 && !argv[reportIndex + 1]) {
    throw new Error('--report requires a file path');
  }
  return {
    selectedParts: part ? [part] : ['a', 'b', 'c'],
    asJSON: argv.includes('--json'),
    reportFile: reportIndex >= 0 ? argv[reportIndex + 1] : null,
    requireComplete: argv.includes('--require-complete'),
  };
}

function isExpectedSampledDeepReport(report) {
  if (!report || report.command !== 'inspect' || report.complete !== false ||
      report.result?.complete !== false) return false;
  const coverage = report.assessment?.deepInspection?.coverage;
  const stage = report.stages?.deep;
  const inspected = report.assessment?.tarballInspected;
  const warnings = report.warnings || [];
  const expectedWarning = warning =>
    /^deep inspection: bounded source sampling inspected .*not full-package coverage$/i.test(warning);
  return stage?.requested === true && stage.complete === false &&
    stage.packageComplete === false && coverage?.mode === 'bounded-source-sampling' &&
    coverage.packageComplete === false && Array.isArray(inspected) && inspected.length > 0 &&
    warnings.length > 0 && warnings.every(expectedWarning);
}

/**
 * Invoke vexes and validate its machine contract. Exit 0 (clean) and exit 1
 * (findings) are both valid only when parseable JSON explicitly says the run
 * was complete. Part C may narrowly accept the inspect command's explicit
 * bounded-sampling contract as successful execution while retaining
 * evidenceComplete=false; no other incomplete contract is accepted.
 */
export function runVexes(cliArgs, { spawn = spawnSync, acceptSampledDeep = false } = {}) {
  let child;
  try {
    child = spawn(process.execPath, [VEXES, ...cliArgs], {
      encoding: 'utf8',
      timeout: 120_000,
    });
  } catch (error) {
    return {
      report: null,
      status: null,
      stderr: '',
      errors: [`vexes process error: ${error.message}`],
      errorCount: 1,
      complete: false,
      evidenceComplete: false,
      sampledEvidence: false,
    };
  }
  const errors = [];
  let report = null;

  if (child.error) errors.push(`vexes process error: ${child.error.message}`);
  if (child.signal) errors.push(`vexes terminated by ${child.signal}`);
  if (!child.stdout?.trim()) {
    errors.push('vexes produced no JSON output');
  } else {
    try {
      report = JSON.parse(child.stdout);
    } catch (error) {
      errors.push(`vexes produced invalid JSON: ${error.message}`);
    }
  }

  const sampledEvidence = acceptSampledDeep && isExpectedSampledDeepReport(report);
  if (child.status !== 0 && child.status !== 1 && !(sampledEvidence && child.status === 2)) {
    errors.push(`vexes exited ${child.status ?? 'without a status'}`);
  }
  if (report && (report.complete !== true || report.result?.complete !== true) && !sampledEvidence) {
    errors.push('vexes report is incomplete or omits an explicit complete=true contract');
  }

  return {
    report,
    status: child.status ?? null,
    stderr: String(child.stderr || '').trim(),
    errors: [...new Set(errors)],
    errorCount: new Set(errors).size,
    complete: errors.length === 0,
    evidenceComplete: report?.complete === true && report?.result?.complete === true,
    sampledEvidence,
  };
}

function packageNameOfFinding(finding) {
  return typeof finding?.package === 'string'
    ? finding.package
    : finding?.package?.name || finding?.name;
}

function identifiersOfFinding(finding) {
  return [
    finding?.id,
    finding?.displayId,
    ...(Array.isArray(finding?.advisories) ? finding.advisories : []),
    ...(Array.isArray(finding?.aliases) ? finding.aliases : []),
  ].filter(value => typeof value === 'string' && value.trim().length > 0);
}

export function runPartA({ manifest = defaultManifest, runner = runVexes } = {}) {
  const results = [];
  for (const entry of manifest.knownBad) {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-bench-a-'));
    try {
      const lockfile = {
        name: 'vexes-benchmark-known-bad',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'vexes-benchmark-known-bad', version: '1.0.0' },
          [`node_modules/${entry.name}`]: {
            version: entry.version,
            resolved: `https://registry.npmjs.org/${entry.name}/-/${entry.name}-${entry.version}.tgz`,
          },
        },
        dependencies: { [entry.name]: { version: entry.version } },
      };
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lockfile, null, 2));

      const invocation = runner([
        'scan', '--path', dir, '--json', '--severity', 'low',
        '--no-project-config', '--no-user-config',
      ]);
      const findings = invocation.complete
        ? (invocation.report?.findings || []).filter(f => packageNameOfFinding(f) === entry.name)
        : [];
      const advisoryIds = new Set(findings.flatMap(identifiersOfFinding));
      const hit = invocation.complete && advisoryIds.has(entry.advisory);
      const flagged = invocation.complete && findings.some(f =>
        ADVISORY_SIGNALS.has(f.signal) || LOUD.has(String(f.severity || '').toUpperCase())
      );

      results.push({
        ...entry,
        complete: invocation.complete,
        hit,
        flagged,
        signals: findings.map(f => f.signal),
        errors: invocation.errors,
        errorCount: invocation.errorCount,
      });
    } catch (error) {
      results.push({
        ...entry,
        complete: false,
        hit: false,
        flagged: false,
        signals: [],
        errors: [`benchmark fixture failed: ${error.message}`],
        errorCount: 1,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  return results;
}

function evidenceMatches(actual, expected) {
  if (Array.isArray(actual)) return actual.some(value => evidenceMatches(value, expected));
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object') return false;
    return Object.entries(expected).every(([key, value]) => evidenceMatches(actual[key], value));
  }
  return actual === expected;
}

export function signalMatchesCondition(signal, condition) {
  if (typeof condition === 'string') return signal.signal === condition;
  if (!condition || signal.signal !== condition.signal) return false;
  if (condition.severity && signal.severity !== condition.severity) return false;
  if (condition.evidence && !evidenceMatches(signal.evidence, condition.evidence)) return false;
  return true;
}

function describeCondition(condition) {
  if (typeof condition === 'string') return condition;
  const evidence = Object.entries(condition.evidence || {})
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(',');
  return `${condition.signal}${evidence ? `(${evidence})` : ''}`;
}

export async function runPartB({ manifest = defaultManifest, analyzer = null } = {}) {
  const analyze = analyzer || (await import(join(ROOT, 'src', 'analysis', 'signals.js'))).analyzePackage;
  const results = [];

  for (const fixture of manifest.techniques) {
    const isControl = fixture.kind === 'control';
    try {
      const metadata = {
        name: fixture.name,
        latestVersion: '2.0.0',
        previousVersion: '1.0.0',
        maintainers: [{ name: 'author' }],
        latestPublisher: 'author',
        previousPublisher: 'author',
        maintainerChanged: false,
        hasInstallScripts: Object.keys(fixture.scripts).length > 0,
        installScripts: fixture.scripts,
        previousInstallScripts: fixture.previousInstallScripts,
        scripts: fixture.scripts,
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
        repository: `https://github.com/example/${fixture.name}`,
        license: 'MIT',
      };
      const analyzed = await analyze(metadata, null, { ecosystem: 'npm' });
      const signals = analyzed?.signals || [];
      const warnings = analyzed?.warnings || [];
      const errors = warnings.map(w => `analysis warning: ${w}`);
      if (!analyzed || !Array.isArray(analyzed.signals)) {
        errors.push('analyzer returned no signals array');
      }

      const expected = fixture.expectAll || [];
      const forbidden = fixture.expectNone || [];
      const missing = expected.filter(condition =>
        !signals.some(signal => signalMatchesCondition(signal, condition))
      );
      const unexpected = forbidden.filter(condition =>
        signals.some(signal => signalMatchesCondition(signal, condition))
      );
      const loudSignals = signals.filter(s => LOUD.has(String(s.severity || '').toUpperCase()));
      const complete = errors.length === 0;
      const hit = complete && missing.length === 0 && unexpected.length === 0 &&
        (!isControl || loudSignals.length === 0);

      results.push({
        id: fixture.id,
        technique: fixture.technique,
        isControl,
        complete,
        hit,
        expected: expected.map(describeCondition),
        forbidden: forbidden.map(describeCondition),
        missing: missing.map(describeCondition),
        unexpected: unexpected.map(describeCondition),
        fired: [...new Set(signals.map(s => s.signal))],
        firedEvidence: signals.map(s => ({
          signal: s.signal,
          severity: s.severity,
          pattern: s.evidence?.pattern,
          capability: s.evidence?.capability,
          capabilities: s.evidence?.capabilities,
        })),
        loudSignals: loudSignals.map(s => `${s.signal}(${s.severity})`),
        errors,
        errorCount: errors.length,
      });
    } catch (error) {
      results.push({
        id: fixture.id,
        technique: fixture.technique,
        isControl,
        complete: false,
        hit: false,
        expected: (fixture.expectAll || []).map(describeCondition),
        forbidden: (fixture.expectNone || []).map(describeCondition),
        missing: (fixture.expectAll || []).map(describeCondition),
        unexpected: [],
        fired: [],
        firedEvidence: [],
        loudSignals: [],
        errors: [`analyzer failed: ${error.message}`],
        errorCount: 1,
      });
    }
  }
  return results;
}

function artifactErrors(metadata, entry) {
  const errors = [];
  if (!metadata) return ['npm metadata unavailable'];
  if (metadata.metadataComplete !== true || metadata.requestedVersionFound !== true ||
      metadata.anchoredToInstalled !== true || metadata.latestVersion !== entry.version) {
    errors.push(metadata.anchorError || `metadata was not anchored to ${entry.name}@${entry.version}`);
  }
  for (const field of ['tarball', 'integrity', 'shasum']) {
    if (!entry[field]) errors.push(`manifest omits pinned ${field}`);
    else if (!metadata[field]) errors.push(`registry metadata omits ${field}`);
    else if (metadata[field] !== entry[field]) errors.push(`${field} does not match pinned manifest value`);
  }
  return errors;
}

function deepInspectionErrors(report, entry) {
  const errors = [];
  const actualName = report?.package?.name || report?.assessment?.name;
  const actualVersion = report?.package?.version || report?.assessment?.version;
  if (actualName !== entry.name || actualVersion !== entry.version) {
    errors.push(`inspect reported ${actualName || '?'}@${actualVersion || '?'}, expected ${entry.name}@${entry.version}`);
  }
  if (!Array.isArray(report?.assessment?.tarballInspected) || report.assessment.tarballInspected.length === 0) {
    errors.push('deep tarball inspection produced no inspected-file evidence');
  }
  const artifact = report?.assessment?.registryArtifact;
  if (!artifact) {
    errors.push('inspect report omitted registry artifact identity');
  } else {
    for (const field of ['tarball', 'integrity', 'shasum']) {
      if (artifact[field] !== entry[field]) {
        errors.push(`inspect report ${field} does not match pinned manifest value`);
      }
    }
  }
  const coverage = report?.assessment?.deepInspection?.coverage;
  if (coverage?.digestVerified !== true) {
    errors.push('deep tarball bytes were not verified against the pinned registry digest');
  }
  const deepWarnings = (report?.warnings || []).filter(w => /(?:--deep|tarball).*(?:fail|skip|could not)/i.test(w));
  errors.push(...deepWarnings.map(w => `inspect warning: ${w}`));
  return errors;
}

function rawAdvisoryAssessment(report, entry) {
  if (!Array.isArray(report?.findings)) {
    return {
      advisories: [],
      blocking: [],
      errors: ['inspect report omitted the raw findings array'],
    };
  }

  const advisories = [];
  const errors = [];
  for (let index = 0; index < report.findings.length; index++) {
    const finding = report.findings[index];
    if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
      errors.push(`inspect finding ${index} is not an object`);
      continue;
    }

    const name = packageNameOfFinding(finding);
    const version = finding.version || finding.package?.version;
    const ids = [...new Set(identifiersOfFinding(finding))];
    const severity = String(finding.severity || finding.severityLevel?.level || '').toUpperCase();
    if (name !== entry.name || version !== entry.version) {
      errors.push(`inspect finding ${index} is not anchored to ${entry.name}@${entry.version}`);
      continue;
    }
    if (ids.length === 0) {
      errors.push(`inspect finding ${index} omitted an advisory ID`);
      continue;
    }
    if (!['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(severity)) {
      errors.push(`inspect finding ${ids[0]} omitted a recognized advisory severity`);
      continue;
    }
    advisories.push({ ids, severity });
  }

  return {
    advisories,
    blocking: advisories.filter(advisory => LOUD.has(advisory.severity)),
    errors,
  };
}

export async function runPartC({
  manifest = defaultManifest,
  runner = runVexes,
  metadataFetcher = null,
} = {}) {
  const fetchMetadata = metadataFetcher ||
    (await import(join(ROOT, 'src', 'advisories', 'npm-registry.js'))).fetchNpmMetadata;
  const results = [];

  for (const entry of manifest.benignLive) {
    let metadata;
    try {
      metadata = await fetchMetadata(entry.name, entry.version);
    } catch (error) {
      results.push({
        ...entry,
        complete: false,
        fp: null,
        signals: [],
        loudSignals: [],
        errors: [`npm metadata fetch failed: ${error.message}`],
        errorCount: 1,
      });
      continue;
    }

    const errors = artifactErrors(metadata, entry);
    if (errors.length > 0) {
      results.push({
        ...entry,
        complete: false,
        fp: null,
        signals: [],
        loudSignals: [],
        errors,
        errorCount: errors.length,
      });
      continue;
    }

    let invocation;
    try {
      invocation = runner(
        ['inspect', `${entry.name}@${entry.version}`, '--deep', '--json', '--no-project-config', '--no-user-config'],
        { acceptSampledDeep: true }
      );
    } catch (error) {
      invocation = {
        complete: false,
        report: null,
        errors: [`vexes invocation failed: ${error.message}`],
        errorCount: 1,
        evidenceComplete: false,
        sampledEvidence: false,
      };
    }
    errors.push(...(invocation?.errors || ['vexes runner returned no error contract']));
    const advisoryAssessment = rawAdvisoryAssessment(invocation?.report, entry);
    if (invocation?.complete) {
      errors.push(...deepInspectionErrors(invocation.report, entry));
      errors.push(...advisoryAssessment.errors);
      if (!Array.isArray(invocation.report?.assessment?.signals)) {
        errors.push('inspect report omitted the assessment signals array');
      }
    }

    const signals = Array.isArray(invocation?.report?.assessment?.signals)
      ? invocation.report.assessment.signals
      : [];
    const advisorySignals = signals.filter(s => ADVISORY_SIGNALS.has(s.signal));
    const loud = signals.filter(s =>
      !ADVISORY_SIGNALS.has(s.signal) && LOUD.has(String(s.severity || '').toUpperCase())
    );
    const complete = errors.length === 0;
    const coverage = invocation?.report?.assessment?.deepInspection?.coverage || null;

    results.push({
      ...entry,
      complete,
      fp: complete ? loud.length > 0 : null,
      currentBlockingEvidence: complete ? advisoryAssessment.blocking.length > 0 : null,
      signals: signals.map(s => s.signal),
      loudSignals: loud.map(s => `${s.signal}(${s.severity})`),
      advisorySignals: advisorySignals.map(s => `${s.signal}(${s.severity})`),
      advisories: advisoryAssessment.advisories.map(advisory =>
        `${advisory.ids[0]}(${advisory.severity})`
      ),
      blockingAdvisories: advisoryAssessment.blocking.map(advisory =>
        `${advisory.ids[0]}(${advisory.severity})`
      ),
      blockingAdvisoryIds: [...new Set(advisoryAssessment.blocking.flatMap(a => a.ids))],
      artifactVerified: complete && coverage?.digestVerified === true,
      inspectedFiles: invocation?.report?.assessment?.tarballInspected?.length || 0,
      evidenceComplete: invocation?.evidenceComplete === true && coverage?.packageComplete === true,
      sampledEvidence: invocation?.sampledEvidence === true || coverage?.mode === 'bounded-source-sampling',
      coverage,
      errors: [...new Set(errors)],
      errorCount: new Set(errors).size,
    });
  }
  return results;
}

function errorsIn(results) {
  return results.reduce((count, result) => count + (result.errorCount || result.errors?.length || 0), 0);
}

export function evaluateBenchmark(
  parts,
  selectedParts,
  manifest = defaultManifest,
  { requireComplete = false } = {}
) {
  const gates = {};
  if (selectedParts.includes('a')) {
    const rows = parts.knownBad || [];
    const complete = rows.length === manifest.knownBad.length && rows.every(r => r.complete);
    const passed = complete && rows.every(r => r.hit);
    gates.a = {
      executionComplete: complete,
      evidenceComplete: complete,
      complete,
      passed,
      errorCount: errorsIn(rows),
      failureCount: complete ? rows.filter(r => !r.hit).length : 0,
    };
  }
  if (selectedParts.includes('b')) {
    const rows = parts.techniques || [];
    const complete = rows.length === manifest.techniques.length && rows.every(r => r.complete);
    const passed = complete && rows.every(r => r.hit);
    gates.b = {
      executionComplete: complete,
      evidenceComplete: complete,
      complete,
      passed,
      errorCount: errorsIn(rows),
      failureCount: complete ? rows.filter(r => !r.hit).length : 0,
      attackFailures: complete ? rows.filter(r => !r.isControl && !r.hit).length : 0,
      controlFailures: complete ? rows.filter(r => r.isControl && !r.hit).length : 0,
    };
  }
  if (selectedParts.includes('c')) {
    const rows = parts.benignLive || [];
    const ceiling = manifest.benignPolicy?.maxHighCriticalFalsePositives;
    const policyValid = Number.isInteger(ceiling) && ceiling >= 0;
    const executionComplete = policyValid && rows.length === manifest.benignLive.length && rows.every(r => r.complete);
    const evidenceComplete = executionComplete && rows.every(r => r.evidenceComplete === true);
    const fpCount = rows.filter(r => r.fp === true).length;
    const blockingEvidenceCount = rows.filter(r => r.currentBlockingEvidence === true).length;
    const passed = executionComplete && fpCount <= ceiling && blockingEvidenceCount === 0;
    gates.c = {
      executionComplete,
      evidenceComplete,
      complete: executionComplete && evidenceComplete,
      passed,
      ceiling: policyValid ? ceiling : null,
      fpCount,
      blockingEvidenceCount,
      sampledCount: rows.filter(r => r.sampledEvidence === true).length,
      errorCount: errorsIn(rows) + (policyValid ? 0 : 1),
      failureCount: executionComplete && !passed
        ? Math.max(0, fpCount - ceiling) + blockingEvidenceCount
        : 0,
    };
  }

  const executionComplete = Object.values(gates).every(gate => gate.executionComplete);
  const evidenceComplete = executionComplete && Object.values(gates).every(gate => gate.evidenceComplete);
  const complete = executionComplete && evidenceComplete;
  const passed = executionComplete && Object.values(gates).every(gate => gate.passed);
  const errorCount = Object.values(gates).reduce((sum, gate) => sum + gate.errorCount, 0);
  const failureCount = Object.values(gates).reduce((sum, gate) => sum + gate.failureCount, 0);
  return {
    selectedParts,
    gates,
    executionComplete,
    evidenceComplete,
    complete,
    passed,
    status: !executionComplete ? 'ERROR' : (!passed ? 'FAIL' : (!evidenceComplete ? 'INCOMPLETE' : 'PASS')),
    requireComplete,
    errorCount,
    failureCount,
    exitCode: !executionComplete ? 2 : (!passed ? 1 : (requireComplete && !evidenceComplete ? 2 : 0)),
  };
}

export function summarizeMarkdown(result) {
  const lines = ['# vexes detection benchmark', ''];
  const { parts, summary } = result;

  if (summary.gates.a) {
    const rows = parts.knownBad;
    const hit = rows.filter(r => r.hit).length;
    lines.push(`## Part A — exact known-bad identification — ${hit}/${rows.length}`);
    lines.push('');
    lines.push('| package | version | advisory | result |');
    lines.push('|---|---|---|---|');
    for (const row of rows) {
      const mark = !row.complete ? `⚠️ incomplete (${row.errorCount} error${row.errorCount === 1 ? '' : 's'})` : (row.hit ? '✅' : '❌ miss');
      lines.push(`| ${row.name} | ${row.version} | ${row.advisory} | ${mark} |`);
    }
    lines.push('');
  }

  if (summary.gates.b) {
    const rows = parts.techniques;
    const attacks = rows.filter(r => !r.isControl);
    const controls = rows.filter(r => r.isControl);
    lines.push(`## Part B — technique evidence — ${attacks.filter(r => r.hit).length}/${attacks.length} attacks; ${controls.filter(r => r.hit).length}/${controls.length} controls clean`);
    lines.push('');
    lines.push('| fixture | kind | required evidence | fired | result |');
    lines.push('|---|---|---|---|---|');
    for (const row of rows) {
      const detail = [...row.missing, ...row.unexpected].join(', ') || row.loudSignals.join(', ');
      const mark = !row.complete ? `⚠️ incomplete (${row.errorCount})` : (row.hit ? '✅' : `❌ ${detail}`);
      lines.push(`| ${row.id} | ${row.isControl ? 'control' : 'attack'} | ${row.expected.join(' + ') || 'no HIGH/CRITICAL'} | ${row.fired.join(', ') || 'none'} | ${mark} |`);
    }
    lines.push('');
  }

  if (summary.gates.c) {
    const rows = parts.benignLive;
    const gate = summary.gates.c;
    lines.push(`## Part C — pinned live sampled deep evidence — ${gate.fpCount}/${rows.length} heuristic HIGH/CRITICAL (ceiling ${gate.ceiling ?? 'invalid'})`);
    lines.push('');
    lines.push('| package | pinned version | sampled files | HIGH/CRITICAL heuristic signals | current blocking advisory | result |');
    lines.push('|---|---|---:|---|---|---|');
    for (const row of rows) {
      const mark = !row.complete ? `⚠️ error (${row.errorCount})` : (row.fp || row.currentBlockingEvidence ? '🚩' : '✅ sampled');
      lines.push(`| ${row.name} | ${row.version} | ${row.inspectedFiles || 0} | ${(row.loudSignals || []).join(', ') || 'none'} | ${(row.blockingAdvisories || []).join(', ') || 'none'} | ${mark} |`);
    }
    lines.push('');
    lines.push(`Coverage: ${gate.sampledCount}/${rows.length} rows are explicitly bounded samples; package-complete evidence is ${gate.evidenceComplete ? 'available' : 'not available'}.`);
    lines.push('');
  }

  lines.push(`**Overall: ${summary.status}.** ${summary.errorCount} execution error(s); ${summary.failureCount} gate regression(s).`);
  lines.push('');
  return lines.join('\n');
}

export async function runBenchmark({
  selectedParts = ['a', 'b', 'c'],
  manifest = defaultManifest,
  runner = runVexes,
  analyzer = null,
  metadataFetcher = null,
  requireComplete = false,
} = {}) {
  const parts = {};
  if (selectedParts.includes('a')) parts.knownBad = runPartA({ manifest, runner });
  if (selectedParts.includes('b')) parts.techniques = await runPartB({ manifest, analyzer });
  if (selectedParts.includes('c')) {
    parts.benignLive = await runPartC({ manifest, runner, metadataFetcher });
  }
  const summary = evaluateBenchmark(parts, selectedParts, manifest, { requireComplete });
  return { schemaVersion: '1.0', parts, summary };
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseBenchmarkArgs(argv);
  } catch (error) {
    console.error(`benchmark usage error: ${error.message}`);
    return 2;
  }

  let result;
  try {
    result = await runBenchmark({
      selectedParts: options.selectedParts,
      requireComplete: options.requireComplete,
    });
  } catch (error) {
    console.error(`benchmark incomplete: ${error.message}`);
    return 2;
  }
  const markdown = summarizeMarkdown(result);
  console.log(options.asJSON ? JSON.stringify(result, null, 2) : markdown);
  if (options.reportFile) writeFileSync(options.reportFile, markdown);
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  if (!result.summary.executionComplete) {
    console.error(`benchmark execution error: ${result.summary.errorCount} error(s)`);
  } else if (!result.summary.passed) {
    console.error(`benchmark regression: ${result.summary.failureCount} gate failure(s)`);
  } else if (!result.summary.evidenceComplete) {
    console.error('benchmark evidence is explicitly sampled/incomplete; --require-complete makes this release-blocking');
  }
  return result.summary.exitCode;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(THIS_FILE)) {
  process.exitCode = await main();
}
