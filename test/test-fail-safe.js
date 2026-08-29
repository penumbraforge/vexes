import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { queryBatch, isQueryComplete } from '../src/advisories/osv.js';
import { runFix, verifyFixVersion } from '../src/commands/fix.js';
import { evaluateGuardResults } from '../src/commands/guard.js';
import { runMonitor, parseAllEcosystems, runPollCycle } from '../src/commands/monitor.js';
import { runScan } from '../src/commands/scan.js';
import { analyzeSinglePackage, isAnalysisSignalEnabled, runAnalyze } from '../src/commands/analyze.js';
import { AdvisoryCache } from '../src/cache/advisory-cache.js';
import { EXIT, NPM_REGISTRY_URL, OSV_BATCH_URL, OSV_VULN_URL, PYPI_JSON_URL } from '../src/core/constants.js';

function mockFetchOnce(impl) {
  const original = global.fetch;
  global.fetch = impl;
  return () => {
    global.fetch = original;
  };
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

function npmRegistryResponse(packageName, version) {
  return {
    'dist-tags': { latest: version },
    time: {
      created: '2024-01-01T00:00:00.000Z',
      modified: '2024-01-02T00:00:00.000Z',
      [version]: '2024-01-02T00:00:00.000Z',
    },
    versions: {
      [version]: {
        name: packageName,
        version,
        scripts: {},
        dependencies: {},
        dist: {
          tarball: `${NPM_REGISTRY_URL}/${packageName}/-/${packageName}-${version}.tgz`,
          integrity: 'sha512-dGVzdA==',
          shasum: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
        },
      },
    },
    maintainers: [],
    repository: { url: `https://example.com/${packageName}` },
  };
}

const SIMPLE_POM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.5</version>
    </dependency>
  </dependencies>
</project>
`;

async function captureOutput(fn) {
  let stdout = '';
  let stderr = '';
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;

  process.stdout.write = (chunk, encoding, callback) => {
    stdout += String(chunk);
    if (typeof callback === 'function') callback();
    return true;
  };
  process.stderr.write = (chunk, encoding, callback) => {
    stderr += String(chunk);
    if (typeof callback === 'function') callback();
    return true;
  };

  try {
    const code = await fn();
    return { code, stdout, stderr };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
}

describe('OSV completeness handling', () => {
  it('marks partial batch responses as incomplete', async () => {
    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, OSV_BATCH_URL);
      return jsonResponse({ results: [] });
    });

    try {
      const result = await queryBatch([
        { name: 'left-pad', version: '1.3.0', ecosystem: 'npm' },
      ]);

      assert.equal(result.failedCount, 1);
      assert.equal(result.failures.length, 1);
      assert.equal(isQueryComplete(result, 1), false);
    } finally {
      restoreFetch();
    }
  });
});

describe('Fix verification', () => {
  it('fails closed when the verification query is incomplete', async () => {
    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, OSV_BATCH_URL);
      return jsonResponse({ results: [] });
    });

    try {
      const verification = await verifyFixVersion('axios', '1.14.2', 'npm');
      assert.equal(verification.safe, false);
      assert.equal(verification.incomplete, true);
    } finally {
      restoreFetch();
    }
  });

  it('confirms exact npm registry existence before making a candidate eligible', async () => {
    const restoreFetch = mockFetchOnce(async (url) => {
      if (url === OSV_BATCH_URL) return jsonResponse({ results: [{ vulns: [] }] });
      if (url === `${NPM_REGISTRY_URL}/axios/1.14.2`) {
        return jsonResponse({ name: 'axios', version: '1.14.2' });
      }
      throw new Error(`unexpected URL: ${url}`);
    });

    try {
      const verification = await verifyFixVersion('axios', '1.14.2', 'npm');
      assert.equal(verification.eligible, true);
      assert.equal(verification.osvCrossChecked, true);
      assert.equal(verification.noKnownVulnerabilities, true);
      assert.equal(verification.registryExists, true);
      assert.equal(verification.exists, true);
      assert.equal(verification.safe, false, 'candidate eligibility is not a safety verdict');
    } finally {
      restoreFetch();
    }
  });

  it('does not claim registry existence when the exact version is absent', async () => {
    const restoreFetch = mockFetchOnce(async (url) => {
      if (url === OSV_BATCH_URL) return jsonResponse({ results: [{ vulns: [] }] });
      if (url === `${NPM_REGISTRY_URL}/axios/9.9.9`) return jsonResponse({}, 404);
      throw new Error(`unexpected URL: ${url}`);
    });

    try {
      const verification = await verifyFixVersion('axios', '9.9.9', 'npm');
      assert.equal(verification.eligible, false);
      assert.equal(verification.registryExists, false);
      assert.equal(verification.exists, false);
      assert.equal(verification.incomplete, false);
    } finally {
      restoreFetch();
    }
  });

  it('labels fix output as an OSV-cross-checked candidate, not a verified remediation', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-fix-candidate-'));
    const restoreFetch = mockFetchOnce(async (url, opts = {}) => {
      if (url === OSV_BATCH_URL) {
        const [{ version }] = JSON.parse(opts.body).queries;
        return jsonResponse({ results: [{ vulns: version === '1.0.0' ? [{ id: 'GHSA-fix-test' }] : [] }] });
      }
      if (url === `${OSV_VULN_URL}/GHSA-fix-test`) {
        return jsonResponse({
          id: 'GHSA-fix-test',
          summary: 'Candidate semantics test',
          database_specific: { severity: 'HIGH' },
          affected: [{
            package: { name: 'demo', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
          }],
          references: [],
        });
      }
      if (url === `${NPM_REGISTRY_URL}/demo/1.0.1`) {
        return jsonResponse({ name: 'demo', version: '1.0.1' });
      }
      throw new Error(`unexpected URL: ${url}`);
    });

    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'app', version: '1.0.0', dependencies: { demo: '1.0.0' },
      }));
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'app', version: '1.0.0', lockfileVersion: 3,
        packages: {
          '': { name: 'app', version: '1.0.0', dependencies: { demo: '1.0.0' } },
          'node_modules/demo': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/demo/-/demo-1.0.0.tgz',
          },
        },
      }));

      const { code, stdout } = await captureOutput(() =>
        runFix({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.VULNS_FOUND, 'proposing a candidate does not remove the existing finding');
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, true);
      assert.equal(payload.minimal, false);
      assert.match(payload.selection, /OSV cross-check/);
      assert.equal(payload.fixes.length, 1);
      const rec = payload.fixes[0].recommendation;
      assert.equal(rec.status, 'osv-cross-checked-candidate');
      assert.equal(rec.osvCrossChecked, true);
      assert.equal(rec.existsOnRegistry, true);
      assert.equal(rec.registryExistence, 'confirmed');
      assert.equal(rec.verified, false);
      assert.equal(rec.remediationVerified, false);
      assert.equal(rec.requiresResolvedGraphRescan, true);
    } finally {
      restoreFetch();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('never falls back to a latest version below the advisory fixed threshold', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-fix-threshold-'));
    const restoreFetch = mockFetchOnce(async (url, opts = {}) => {
      if (url === OSV_BATCH_URL) {
        const [{ version }] = JSON.parse(opts.body).queries;
        if (version === '1.0.0') return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-threshold-test' }] }] });
        if (version === '2.0.0') return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-still-vulnerable' }] }] });
        return jsonResponse({ results: [{ vulns: [] }] });
      }
      if (url === `${OSV_VULN_URL}/GHSA-threshold-test`) {
        return jsonResponse({
          id: 'GHSA-threshold-test', summary: 'Threshold test', database_specific: { severity: 'HIGH' },
          affected: [{ package: { name: 'demo', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
          references: [],
        });
      }
      if (url === `${OSV_VULN_URL}/GHSA-still-vulnerable`) {
        return jsonResponse({
          id: 'GHSA-still-vulnerable', summary: 'Still vulnerable', database_specific: { severity: 'HIGH' },
          affected: [{ package: { name: 'demo', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }] }] }],
          references: [],
        });
      }
      if (url === `${NPM_REGISTRY_URL}/demo`) return jsonResponse({ 'dist-tags': { latest: '1.5.0' } });
      if (url === `${NPM_REGISTRY_URL}/demo/1.5.0`) return jsonResponse({ name: 'demo', version: '1.5.0' });
      throw new Error(`unexpected URL: ${url}`);
    });

    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { demo: '1.0.0' } }));
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'app', version: '1.0.0', lockfileVersion: 3,
        packages: {
          '': { name: 'app', version: '1.0.0' },
          'node_modules/demo': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/demo/-/demo-1.0.0.tgz',
          },
        },
      }));
      const { code, stdout } = await captureOutput(() => runFix({ json: true, path: dir, ecosystem: 'npm' }, []));
      assert.equal(code, EXIT.VULNS_FOUND);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, true);
      assert.equal(payload.fixes[0].recommendation, null);
      assert.match(payload.fixes[0].reason, /met every advisory fixed-version threshold/);
    } finally {
      restoreFetch();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Analyze/fix dependency-input fail-loud behavior', () => {
  it('analyze emits complete=false and exits ERROR for a malformed lockfile', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-analyze-malformed-'));
    try {
      writeFileSync(join(dir, 'package-lock.json'), '{ malformed ');
      const { code, stdout } = await captureOutput(() =>
        runAnalyze({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.equal(payload.result.complete, false);
      assert.ok(payload.warnings.some(w => w.includes('failed to parse package-lock.json')));
      assert.deepEqual(payload.results, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('analyze emits complete=false when no supported dependency input exists', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-analyze-no-input-'));
    try {
      const { code, stdout } = await captureOutput(() =>
        runAnalyze({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.match(payload.warnings.join('\n'), /no supported dependency lockfile or manifest found/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('scan fails loud when package.json contains only unresolved ranges', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-scan-range-only-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { ranged: '^1.2.3' } }));
      const { code, stdout } = await captureOutput(() =>
        runScan({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.match(payload.warnings.join('\n'), /add a lockfile or exact pins/);
      assert.equal(payload.summary.total, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('analyze fails loud when package.json contains only unresolved ranges', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-analyze-range-only-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { ranged: '^1.2.3' } }));
      const { code, stdout } = await captureOutput(() =>
        runAnalyze({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.match(payload.warnings.join('\n'), /add a lockfile or exact pins/);
      assert.deepEqual(payload.results, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fix emits complete=false and preserves parse warnings for a malformed lockfile', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-fix-malformed-'));
    try {
      writeFileSync(join(dir, 'package-lock.json'), '{ malformed ');
      const { code, stdout } = await captureOutput(() =>
        runFix({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.equal(payload.result.complete, false);
      assert.ok(payload.warnings.some(w => w.includes('failed to parse package-lock.json')));
      assert.deepEqual(payload.fixes, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fix emits a machine envelope and exits ERROR when no npm lockfile exists', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-fix-no-input-'));
    try {
      const { code, stdout } = await captureOutput(() =>
        runFix({ json: true, path: dir, ecosystem: 'npm' }, []));

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.match(payload.warnings.join('\n'), /no npm lockfile found/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Guard decisioning', () => {
  it('blocks when package analysis is unknown', () => {
    const decision = evaluateGuardResults([
      {
        name: 'mystery-package',
        version: '1.0.0',
        signals: [],
        riskLevel: 'UNKNOWN',
      },
    ], {
      failures: [],
      failedCount: 0,
      queriedCount: 1,
      checked: new Set(['npm:mystery-package@1.0.0']),
    }, 1);

    assert.equal(decision.analysisIncomplete, true);
    assert.equal(decision.unknown.length, 1);
  });

  it('blocks when OSV coverage is incomplete', () => {
    const decision = evaluateGuardResults([], {
      failures: ['OSV batch query failed'],
      failedCount: 1,
      queriedCount: 0,
      checked: new Set(),
    }, 1);

    assert.equal(decision.analysisIncomplete, true);
    assert.equal(decision.osvComplete, false);
  });
});

describe('Analyze cache safety', () => {
  it('does not cache a package result when OSV coverage is missing', async () => {
    let cacheWrites = 0;
    const cache = {
      getSignals() { return null; },
      setSignals() { cacheWrites++; },
    };

    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, `${NPM_REGISTRY_URL}/left-pad`);
      return jsonResponse(npmRegistryResponse('left-pad', '1.3.0'));
    });

    try {
      const result = await analyzeSinglePackage(
        { name: 'left-pad', version: '1.3.0', ecosystem: 'npm', isDirect: true },
        { results: new Map(), checked: new Set(), failures: ['OSV partial'], failedCount: 1 },
        {},
        cache,
      );

      assert.equal(cacheWrites, 0);
      assert.ok(result.warnings.includes('OSV vulnerability lookup incomplete'));
      assert.equal(result.registryArtifact.integrity, 'sha512-dGVzdA==');
      assert.equal(result.registryArtifact.shasum, 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
    } finally {
      restoreFetch();
    }
  });

  it('does not return cached clean signals when current registry metadata is unavailable', async () => {
    let cacheWrites = 0;
    const cache = {
      getSignals() { return { osvFingerprint: '', riskLevel: 'NONE', riskScore: 0, signals: [], warnings: [] }; },
      setSignals() { cacheWrites++; },
    };
    const restoreFetch = mockFetchOnce(async () => jsonResponse({ error: 'registry unavailable' }, 400));

    try {
      const result = await analyzeSinglePackage(
        { name: 'left-pad', version: '1.3.0', ecosystem: 'npm', isDirect: true },
        { results: new Map(), checked: new Set(['npm:left-pad@1.3.0']), failures: [], failedCount: 0 },
        {},
        cache,
      );
      assert.equal(result.riskLevel, 'UNKNOWN');
      assert.ok(result.warnings.includes('metadata unavailable'));
      assert.equal(cacheWrites, 0);
    } finally {
      restoreFetch();
    }
  });

  it('marks analysis incomplete when exact npm metadata is absent and does not trust cache', async () => {
    let cacheReads = 0;
    let cacheWrites = 0;
    const cache = {
      getSignals() {
        cacheReads++;
        return { osvFingerprint: '', riskLevel: 'NONE', warnings: [] };
      },
      setSignals() { cacheWrites++; },
    };
    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, `${NPM_REGISTRY_URL}/left-pad`);
      return jsonResponse(npmRegistryResponse('left-pad', '2.0.0'));
    });

    try {
      const result = await analyzeSinglePackage(
        { name: 'left-pad', version: '1.3.0', ecosystem: 'npm', isDirect: true },
        { results: new Map(), checked: new Set(['npm:left-pad@1.3.0']), failures: [], failedCount: 0 },
        {},
        cache,
      );

      assert.equal(cacheReads, 1);
      assert.equal(cacheWrites, 0);
      assert.ok(result.warnings.some(w => w.includes('absent from the registry packument')));
    } finally {
      restoreFetch();
    }
  });

  it('applies the same exact-version anchor contract to PyPI metadata', async () => {
    let cacheWrites = 0;
    const cache = {
      getSignals() { return { osvFingerprint: '', riskLevel: 'NONE', warnings: [] }; },
      setSignals() { cacheWrites++; },
    };
    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, `${PYPI_JSON_URL}/demo/json`);
      return jsonResponse({
        info: { name: 'demo', version: '2.0.0' },
        releases: {
          '2.0.0': [{ upload_time_iso_8601: '2026-01-01T00:00:00Z' }],
        },
      });
    });

    try {
      const result = await analyzeSinglePackage(
        { name: 'demo', version: '1.0.0', ecosystem: 'pypi', isDirect: true },
        { results: new Map(), checked: new Set(['pypi:demo@1.0.0']), failures: [], failedCount: 0 },
        {},
        cache,
      );

      assert.equal(cacheWrites, 0);
      assert.ok(result.warnings.some(w => w.includes('absent from PyPI release metadata')));
    } finally {
      restoreFetch();
    }
  });
});

describe('Command-added signal policy', () => {
  it('honors canonical and compatibility signal switches', () => {
    assert.equal(isAnalysisSignalEnabled({ analyze: { signals: { MISSING_PROVENANCE: 'off' } } }, 'MISSING_PROVENANCE'), false);
    assert.equal(isAnalysisSignalEnabled(
      { analyze: { signals: { SIGNATURE_SPOOF: 'off' } } },
      'ATTESTATION_IDENTITY_MISMATCH',
      ['SIGNATURE_SPOOF'],
    ), false);
    assert.equal(isAnalysisSignalEnabled(
      { analyze: { signals: { SIGNATURE_SPOOF: 'off', ATTESTATION_IDENTITY_MISMATCH: 'on' } } },
      'ATTESTATION_IDENTITY_MISMATCH',
      ['SIGNATURE_SPOOF'],
    ), true, 'canonical policy takes precedence over the compatibility name');
    assert.equal(isAnalysisSignalEnabled({ analyze: { signals: { SANDBOX_BEHAVIOR: 'off' } } }, 'SANDBOX_BEHAVIOR'), false);
    assert.equal(isAnalysisSignalEnabled({ analyze: { signals: { TARBALL_DANGEROUS_PATTERN: 'off' } } }, 'TARBALL_DANGEROUS_PATTERN'), false);
  });
});

describe('Manifest fallback coverage', () => {
  it('monitor parsing uses pom.xml when no gradle lockfile exists', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-manifest-monitor-'));

    try {
      writeFileSync(join(dir, 'pom.xml'), SIMPLE_POM);

      const result = parseAllEcosystems(dir, ['java']);
      assert.equal(result.parseFailures, 0);
      assert.ok(result.deps.find(d => d.name === 'org.springframework:spring-core' && d.version === '6.1.5'));
      assert.ok(result.warnings.some(w => w.includes('pom.xml')));
      assert.equal(result.unresolvedManifestInputs, 1,
        'a manifest fallback is not a resolved dependency graph');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('scan does not cache unchecked manifest-fallback packages on partial OSV responses', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-manifest-scan-'));
    const cacheDir = join(dir, '.cache');

    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, OSV_BATCH_URL);
      return jsonResponse({ results: [] });
    });

    try {
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({ cache: { dir: cacheDir } }));
      writeFileSync(join(dir, 'pom.xml'), SIMPLE_POM);

      const { code, stdout } = await captureOutput(() =>
        runScan({ json: true, path: dir, ecosystem: 'java' }, [])
      );

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);

      const cache = new AdvisoryCache(cacheDir);
      try {
        assert.equal(cache.getAdvisories('java', 'org.springframework:spring-core', '6.1.5', Infinity), null);
      } finally {
        cache.close();
      }
    } finally {
      restoreFetch();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Direct-import evidence never suppresses findings', () => {
  it('retains a vulnerable transitive dependency even with the legacy reachable-only option', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-transitive-import-evidence-'));
    const cacheDir = join(dir, '.cache');
    const lock = {
      name: 'app',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', version: '1.0.0', dependencies: { direct: '1.0.0' } },
        'node_modules/direct': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/direct/-/direct-1.0.0.tgz',
          dependencies: { transitive: '1.0.0' },
        },
        'node_modules/transitive': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/transitive/-/transitive-1.0.0.tgz',
        },
      },
    };

    const restoreFetch = mockFetchOnce(async (url, opts = {}) => {
      if (url === OSV_BATCH_URL) {
        const queries = JSON.parse(opts.body).queries;
        return jsonResponse({
          results: queries.map(q => q.package.name === 'transitive'
            ? { vulns: [{ id: 'GHSA-transitive-test' }] }
            : { vulns: [] }),
        });
      }
      if (url === `${OSV_VULN_URL}/GHSA-transitive-test`) {
        return jsonResponse({
          id: 'GHSA-transitive-test',
          summary: 'Transitive test vulnerability',
          database_specific: { severity: 'HIGH' },
          affected: [{
            package: { name: 'transitive', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
          }],
          references: [],
        });
      }
      throw new Error(`unexpected URL: ${url}`);
    });

    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'app', version: '1.0.0', main: 'index.js', dependencies: { direct: '1.0.0' },
      }));
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lock));
      writeFileSync(join(dir, 'index.js'), "import direct from 'direct';\n");
      writeFileSync(join(dir, '.vexesrc.json'), JSON.stringify({ cache: { dir: cacheDir } }));

      const { code, stdout } = await captureOutput(() => runScan({
        json: true,
        path: dir,
        ecosystem: 'npm',
        'min-reachability': 'reachable',
      }, []));

      assert.equal(code, EXIT.VULNS_FOUND);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, true);
      assert.equal(payload.findings.length, 1);
      assert.equal(payload.findings[0].package, 'transitive');
      assert.equal(payload.findings[0].importEvidence, 'not_found');
      assert.equal(payload.findings[0].reachability, 'dead', 'legacy field remains additive');
      assert.match(payload.warnings.join('\n'), /deprecated and ignored/);
    } finally {
      restoreFetch();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Monitor poll safety', () => {
  it('does not print clean output when OSV polling is incomplete', async () => {
    const restoreFetch = mockFetchOnce(async (url) => {
      assert.equal(url, OSV_BATCH_URL);
      return jsonResponse({ results: [] });
    });

    try {
      const { stdout } = await captureOutput(() =>
        runPollCycle([{ name: 'left-pad', version: '1.3.0', ecosystem: 'npm' }], { severity: 'moderate' })
      );

      assert.ok(stdout.includes('OSV results incomplete'));
      assert.ok(!stdout.includes('packages clean'));
    } finally {
      restoreFetch();
    }
  });
});

describe('Monitor CI fail-safe parsing', () => {
  it('returns EXIT.ERROR and complete=false for malformed lockfiles', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-monitor-'));

    try {
      writeFileSync(join(dir, 'package-lock.json'), '{ this is not valid json ');

      const { code, stdout } = await captureOutput(() =>
        runMonitor({ ci: true, json: true, path: dir }, [])
      );

      assert.equal(code, EXIT.ERROR);

      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.ok(payload.warnings.some(w => w.includes('failed to parse package-lock.json')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns EXIT.ERROR and complete=false for a range-only package.json', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-monitor-range-only-'));

    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { ranged: '^1.2.3' } }));
      const { code, stdout } = await captureOutput(() =>
        runMonitor({ ci: true, json: true, path: dir, ecosystem: 'npm' }, [])
      );

      assert.equal(code, EXIT.ERROR);
      const payload = JSON.parse(stdout);
      assert.equal(payload.complete, false);
      assert.match(payload.warnings.join('\n'), /add a lockfile or exact pins/);
      assert.equal(payload.summary.total, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
