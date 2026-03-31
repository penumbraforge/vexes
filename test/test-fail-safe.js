import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { queryBatch, isQueryComplete } from '../src/advisories/osv.js';
import { verifyFixVersion } from '../src/commands/fix.js';
import { evaluateGuardResults } from '../src/commands/guard.js';
import { runMonitor, parseAllEcosystems, runPollCycle } from '../src/commands/monitor.js';
import { runScan } from '../src/commands/scan.js';
import { analyzeSinglePackage } from '../src/commands/analyze.js';
import { AdvisoryCache } from '../src/cache/advisory-cache.js';
import { EXIT, NPM_REGISTRY_URL, OSV_BATCH_URL } from '../src/core/constants.js';

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
    } finally {
      restoreFetch();
    }
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
});
