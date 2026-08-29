import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import {
  defaultManifest,
  evaluateBenchmark,
  parseBenchmarkArgs,
  runPartA,
  runPartB,
  runPartC,
  runVexes,
} from '../benchmark/run.mjs';
import { parseLockfile as parseNpmLock } from '../src/parsers/npm.js';

function minimalManifest() {
  return {
    knownBad: [{ name: 'bad', version: '1.0.0', advisory: 'MAL-1' }],
    techniques: [{
      id: 'attack',
      kind: 'attack',
      technique: 'specific AST pattern',
      name: 'attack-fixture',
      scripts: { postinstall: 'node fixture.js' },
      previousInstallScripts: null,
      expectAll: [{ signal: 'AST_DANGEROUS_PATTERN', evidence: { pattern: 'PROCESS_SPAWN' } }],
    }, {
      id: 'control',
      kind: 'control',
      technique: 'negative control',
      name: 'control-fixture',
      scripts: {},
      previousInstallScripts: {},
      expectAll: [],
      expectNone: [{ signal: 'TYPOSQUAT' }],
    }],
    benignPolicy: { maxHighCriticalFalsePositives: 0 },
    benignLive: [{
      name: 'good',
      version: '1.0.0',
      tarball: 'https://registry.npmjs.org/good/-/good-1.0.0.tgz',
      integrity: 'sha512-good',
      shasum: '1111111111111111111111111111111111111111',
    }],
  };
}

function completeInvocation(report = {}) {
  return {
    complete: true,
    status: 0,
    errors: [],
    errorCount: 0,
    report: { complete: true, result: { complete: true }, findings: [], ...report },
  };
}

describe('benchmark subprocess completeness', () => {
  it('parses independent parts and the explicit completeness policy', () => {
    assert.deepEqual(parseBenchmarkArgs(['--part', 'b', '--require-complete']), {
      selectedParts: ['b'],
      asJSON: false,
      reportFile: null,
      requireComplete: true,
    });
    assert.throws(() => parseBenchmarkArgs(['--part', 'nope']), /one of a, b, or c/);
  });

  it('accepts only explicit complete=true in both envelope locations', () => {
    const good = runVexes([], {
      spawn: () => ({
        status: 0,
        stdout: JSON.stringify({ complete: true, result: { complete: true } }),
        stderr: '',
      }),
    });
    assert.equal(good.complete, true);
    assert.equal(good.errorCount, 0);

    const missingResult = runVexes([], {
      spawn: () => ({ status: 0, stdout: JSON.stringify({ complete: true }), stderr: '' }),
    });
    assert.equal(missingResult.complete, false);
    assert.deepEqual(missingResult.errors, [
      'vexes report is incomplete or omits an explicit complete=true contract',
    ]);
  });

  it('treats invalid JSON, bad exits, and thrown process errors as incomplete', () => {
    const invalid = runVexes([], {
      spawn: () => ({ status: 0, stdout: '{broken', stderr: '' }),
    });
    assert.equal(invalid.complete, false);
    assert.equal(invalid.errorCount, 1);

    const badExit = runVexes([], {
      spawn: () => ({
        status: 2,
        stdout: JSON.stringify({ complete: false, result: { complete: false } }),
        stderr: 'network failed',
      }),
    });
    assert.equal(badExit.complete, false);
    assert.equal(badExit.errorCount, 2, 'the exit and one de-duplicated contract error are counted');

    const thrown = runVexes([], { spawn: () => { throw new Error('spawn exploded'); } });
    assert.equal(thrown.complete, false);
    assert.equal(thrown.errorCount, 1);
  });

  it('accepts only the narrowly-declared bounded sampling limitation in Part C', () => {
    const sampledReport = {
      command: 'inspect',
      complete: false,
      result: { complete: false },
      warnings: [
        'deep inspection: bounded source sampling inspected 1 of 2 selected entry/install files from 8 archive files; this is not full-package coverage',
      ],
      assessment: {
        tarballInspected: ['index.js'],
        deepInspection: {
          coverage: { mode: 'bounded-source-sampling', packageComplete: false, inspectedFiles: 1 },
        },
      },
      stages: { deep: { requested: true, complete: false, packageComplete: false } },
    };
    const sampled = runVexes([], {
      acceptSampledDeep: true,
      spawn: () => ({ status: 2, stdout: JSON.stringify(sampledReport), stderr: '' }),
    });
    assert.equal(sampled.complete, true, 'benchmark execution and sample production succeeded');
    assert.equal(sampled.evidenceComplete, false);
    assert.equal(sampled.sampledEvidence, true);
    assert.equal(sampled.errorCount, 0);

    sampledReport.warnings.push('OSV vulnerability lookup incomplete');
    const mixedFailure = runVexes([], {
      acceptSampledDeep: true,
      spawn: () => ({ status: 2, stdout: JSON.stringify(sampledReport), stderr: '' }),
    });
    assert.equal(mixedFailure.complete, false, 'an unrelated failure cannot hide behind sampled coverage');
    assert.equal(mixedFailure.sampledEvidence, false);
  });

  it('never turns a Part A scanner error into a clean or detected result', () => {
    const manifest = minimalManifest();
    const rows = runPartA({
      manifest,
      runner: () => ({ complete: false, report: null, errors: ['timeout'], errorCount: 1 }),
    });
    assert.equal(rows[0].complete, false);
    assert.equal(rows[0].hit, false);
    assert.equal(rows[0].flagged, false);
    assert.equal(rows[0].errorCount, 1);
  });

  it('builds a schema-valid Part A lockfile for the real npm parser', () => {
    const manifest = minimalManifest();
    const rows = runPartA({
      manifest,
      runner: args => {
        assert.ok(args.includes('--no-project-config'));
        assert.ok(args.includes('--no-user-config'));
        const dir = args[args.indexOf('--path') + 1];
        const deps = parseNpmLock(join(dir, 'package-lock.json'));
        assert.ok(deps.some(dep => dep.name === 'bad' && dep.version === '1.0.0'));
        return completeInvocation({
          findings: [{ package: 'bad', signal: 'KNOWN_MALICIOUS', severity: 'CRITICAL', advisories: ['MAL-1'] }],
        });
      },
    });
    assert.equal(rows[0].complete, true);
    assert.equal(rows[0].hit, true);
  });
});

describe('independent benchmark gates', () => {
  it('gates only the requested part, while a full run gates every part', () => {
    const manifest = minimalManifest();
    const parts = {
      knownBad: [{ complete: true, hit: false, errors: [], errorCount: 0 }],
      techniques: [
        { complete: true, hit: true, isControl: false, errors: [], errorCount: 0 },
        { complete: true, hit: true, isControl: true, errors: [], errorCount: 0 },
      ],
      benignLive: [{
        complete: true,
        evidenceComplete: true,
        sampledEvidence: false,
        fp: false,
        currentBlockingEvidence: false,
        errors: [],
        errorCount: 0,
      }],
    };

    const onlyB = evaluateBenchmark(parts, ['b'], manifest);
    assert.equal(onlyB.complete, true);
    assert.equal(onlyB.passed, true);
    assert.equal(onlyB.exitCode, 0);
    assert.equal(onlyB.gates.a, undefined);

    const full = evaluateBenchmark(parts, ['a', 'b', 'c'], manifest);
    assert.equal(full.complete, true);
    assert.equal(full.passed, false);
    assert.equal(full.exitCode, 1);
    assert.equal(full.gates.a.failureCount, 1);
  });

  it('uses exit 2 for incomplete evidence and reports stored errors accurately', () => {
    const manifest = minimalManifest();
    const summary = evaluateBenchmark({
      knownBad: [{ complete: false, hit: false, errors: ['one', 'two'], errorCount: 2 }],
    }, ['a'], manifest);

    assert.equal(summary.complete, false);
    assert.equal(summary.exitCode, 2);
    assert.equal(summary.errorCount, 2);
    assert.equal(summary.failureCount, 0, 'incomplete evidence is not mislabeled a detection regression');
  });

  it('reports expected sampled evidence as incomplete without hiding execution success', () => {
    const manifest = minimalManifest();
    const parts = {
      benignLive: [{
        complete: true,
        evidenceComplete: false,
        sampledEvidence: true,
        fp: false,
        currentBlockingEvidence: false,
        errors: [],
        errorCount: 0,
      }],
    };

    const normal = evaluateBenchmark(parts, ['c'], manifest);
    assert.equal(normal.executionComplete, true);
    assert.equal(normal.evidenceComplete, false);
    assert.equal(normal.complete, false);
    assert.equal(normal.passed, true);
    assert.equal(normal.status, 'INCOMPLETE');
    assert.equal(normal.exitCode, 0, 'a normal sampled FP run is useful but never called complete');

    const release = evaluateBenchmark(parts, ['c'], manifest, { requireComplete: true });
    assert.equal(release.status, 'INCOMPLETE');
    assert.equal(release.exitCode, 2, 'release mode fails closed on incomplete evidence coverage');
  });

  it('requires discriminating attack evidence and gates noisy negative controls', async () => {
    const manifest = minimalManifest();
    const rows = await runPartB({
      manifest,
      analyzer: async metadata => ({
        signals: metadata.name === 'attack-fixture'
          ? [{ signal: 'POSTINSTALL_SCRIPT', severity: 'MODERATE', evidence: {} }]
          : [{ signal: 'TYPOSQUAT', severity: 'HIGH', evidence: {} }],
        warnings: [],
      }),
    });

    assert.equal(rows[0].hit, false, 'generic script presence cannot satisfy a process-spawn expectation');
    assert.deepEqual(rows[0].missing, ['AST_DANGEROUS_PATTERN(pattern=PROCESS_SPAWN)']);
    assert.equal(rows[1].hit, false, 'a loud/forbidden control finding gates Part B');
    const summary = evaluateBenchmark({ techniques: rows }, ['b'], manifest);
    assert.equal(summary.complete, true);
    assert.equal(summary.exitCode, 1);
    assert.equal(summary.gates.b.attackFailures, 1);
    assert.equal(summary.gates.b.controlFailures, 1);
  });
});

describe('pinned benign artifact completeness', () => {
  it('pins every Part C input to an exact version and registry digest', () => {
    for (const entry of defaultManifest.benignLive) {
      assert.match(entry.version, /^\d+\.\d+\.\d+(?:[-+].+)?$/);
      assert.match(entry.tarball, new RegExp(`${entry.version.replaceAll('.', '\\.')}\\.tgz$`));
      assert.match(entry.integrity, /^sha512-/);
      assert.match(entry.shasum, /^[a-f0-9]{40}$/);
    }
  });

  it('runs the exact spec only after metadata and digests match', async () => {
    const manifest = minimalManifest();
    let receivedArgs;
    const rows = await runPartC({
      manifest,
      metadataFetcher: async (name, version) => ({
        metadataComplete: true,
        requestedVersionFound: true,
        anchoredToInstalled: true,
        latestVersion: version,
        tarball: manifest.benignLive[0].tarball,
        integrity: manifest.benignLive[0].integrity,
        shasum: manifest.benignLive[0].shasum,
      }),
      runner: args => {
        receivedArgs = args;
        return completeInvocation({
          package: { name: 'good', version: '1.0.0' },
          assessment: {
            name: 'good',
            version: '1.0.0',
            tarballInspected: ['index.js'],
            registryArtifact: {
              tarball: manifest.benignLive[0].tarball,
              integrity: manifest.benignLive[0].integrity,
              shasum: manifest.benignLive[0].shasum,
            },
            deepInspection: { coverage: { digestVerified: true, packageComplete: false, mode: 'bounded-source-sampling' } },
            signals: [{ signal: 'POSTINSTALL_SCRIPT', severity: 'MODERATE' }],
          },
          warnings: [],
        });
      },
    });

    assert.deepEqual(receivedArgs, [
      'inspect', 'good@1.0.0', '--deep', '--json', '--no-project-config', '--no-user-config',
    ]);
    assert.equal(rows[0].complete, true);
    assert.equal(rows[0].artifactVerified, true);
    assert.equal(rows[0].fp, false);
    assert.equal(rows[0].errorCount, 0);
  });

  it('derives advisory blockers from raw findings even when assessment signals are suppressed', async () => {
    const manifest = minimalManifest();
    const rows = await runPartC({
      manifest,
      metadataFetcher: async (_name, version) => ({
        metadataComplete: true,
        requestedVersionFound: true,
        anchoredToInstalled: true,
        latestVersion: version,
        tarball: manifest.benignLive[0].tarball,
        integrity: manifest.benignLive[0].integrity,
        shasum: manifest.benignLive[0].shasum,
      }),
      runner: args => {
        assert.ok(args.includes('--no-project-config'));
        assert.ok(args.includes('--no-user-config'));
        return completeInvocation({
          package: { name: 'good', version: '1.0.0' },
          findings: [{
            id: 'GHSA-raw-finding',
            aliases: ['CVE-2099-0001'],
            advisories: ['GHSA-raw-finding', 'CVE-2099-0001'],
            package: 'good',
            version: '1.0.0',
            severity: 'HIGH',
          }],
          assessment: {
            name: 'good',
            version: '1.0.0',
            tarballInspected: ['index.js'],
            registryArtifact: {
              tarball: manifest.benignLive[0].tarball,
              integrity: manifest.benignLive[0].integrity,
              shasum: manifest.benignLive[0].shasum,
            },
            deepInspection: {
              coverage: { digestVerified: true, packageComplete: false, mode: 'bounded-source-sampling' },
            },
            signals: [],
          },
          warnings: [],
        });
      },
    });

    assert.equal(rows[0].complete, true);
    assert.equal(rows[0].fp, false, 'an advisory is not mislabeled as a heuristic false positive');
    assert.equal(rows[0].currentBlockingEvidence, true);
    assert.deepEqual(rows[0].blockingAdvisories, ['GHSA-raw-finding(HIGH)']);
    assert.deepEqual(rows[0].blockingAdvisoryIds, ['GHSA-raw-finding', 'CVE-2099-0001']);

    const summary = evaluateBenchmark({ benignLive: rows }, ['c'], manifest);
    assert.equal(summary.passed, false);
    assert.equal(summary.gates.c.blockingEvidenceCount, 1);
    assert.equal(summary.exitCode, 1);
  });

  it('marks digest mismatches and missing deep evidence incomplete, never clean', async () => {
    const manifest = minimalManifest();
    let runnerCalls = 0;
    const mismatch = await runPartC({
      manifest,
      metadataFetcher: async (_name, version) => ({
        metadataComplete: true,
        requestedVersionFound: true,
        anchoredToInstalled: true,
        latestVersion: version,
        tarball: manifest.benignLive[0].tarball,
        integrity: 'sha512-different',
        shasum: manifest.benignLive[0].shasum,
      }),
      runner: () => { runnerCalls++; return completeInvocation(); },
    });
    assert.equal(runnerCalls, 0, 'an unverified artifact is not inspected as the benchmark control');
    assert.equal(mismatch[0].complete, false);
    assert.equal(mismatch[0].fp, null);
    assert.equal(mismatch[0].errorCount, 1);

    const noDeep = await runPartC({
      manifest,
      metadataFetcher: async (_name, version) => ({
        metadataComplete: true,
        requestedVersionFound: true,
        anchoredToInstalled: true,
        latestVersion: version,
        tarball: manifest.benignLive[0].tarball,
        integrity: manifest.benignLive[0].integrity,
        shasum: manifest.benignLive[0].shasum,
      }),
      runner: () => completeInvocation({
        package: { name: 'good', version: '1.0.0' },
        assessment: { name: 'good', version: '1.0.0', signals: [] },
        warnings: ['--deep tarball inspection failed: archive corrupt'],
      }),
    });
    assert.equal(noDeep[0].complete, false);
    assert.equal(noDeep[0].fp, null);
    assert.equal(noDeep[0].errorCount, 4,
      'missing sample, pinned artifact identity, digest proof, and deep failure warning are independent errors');
  });

  it('rejects a second inspect fetch that drifts from the pinned artifact', async () => {
    const manifest = minimalManifest();
    const rows = await runPartC({
      manifest,
      metadataFetcher: async (_name, version) => ({
        metadataComplete: true,
        requestedVersionFound: true,
        anchoredToInstalled: true,
        latestVersion: version,
        tarball: manifest.benignLive[0].tarball,
        integrity: manifest.benignLive[0].integrity,
        shasum: manifest.benignLive[0].shasum,
      }),
      runner: () => completeInvocation({
        package: { name: 'good', version: '1.0.0' },
        assessment: {
          name: 'good',
          version: '1.0.0',
          tarballInspected: ['index.js'],
          registryArtifact: {
            tarball: manifest.benignLive[0].tarball,
            integrity: 'sha512-drifted',
            shasum: manifest.benignLive[0].shasum,
          },
          deepInspection: { coverage: { digestVerified: true, packageComplete: false, mode: 'bounded-source-sampling' } },
          signals: [],
        },
        warnings: [],
      }),
    });

    assert.equal(rows[0].complete, false);
    assert.equal(rows[0].fp, null);
    assert.ok(rows[0].errors.some(error => error.includes('integrity does not match')));
  });
});
