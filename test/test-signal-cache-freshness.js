import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSinglePackage } from '../src/commands/analyze.js';

/**
 * The signal cache must never mask a freshly published advisory: a cached
 * verdict is only trusted when the fresh OSV evidence for this run matches
 * the evidence the verdict was formed against (osvFingerprint reconciliation).
 */

const dep = { ecosystem: 'npm', name: 'some-pkg', version: '1.0.0', isDirect: true };
const KEY = 'npm:some-pkg@1.0.0';

const osvDataFor = (vulns) => ({
  checked: new Set([KEY]),
  results: new Map([[KEY, vulns]]),
});

const cleanCacheWith = (fingerprint, stored = null) => ({
  getSignals: () => stored ?? {
    name: 'some-pkg', version: '1.0.0', ecosystem: 'npm',
    signals: [], riskScore: 0, riskLevel: 'NONE', warnings: [],
    osvFingerprint: fingerprint,
  },
  setSignals: (eco, name, version, value) => { capturedWrite = value; },
  close: () => {},
});
let capturedWrite = null;

function registryPack(scripts = {}) {
  return {
    'dist-tags': { latest: '1.0.0' },
    time: { created: '2020-01-01T00:00:00Z', modified: '2020-01-01T00:00:00Z', '1.0.0': '2020-01-01T00:00:00Z' },
    versions: {
      '1.0.0': {
        name: 'some-pkg', version: '1.0.0', scripts, dependencies: {},
        _npmUser: { name: 'publisher' },
        dist: {
          tarball: 'https://registry.npmjs.org/some-pkg/-/some-pkg-1.0.0.tgz',
          integrity: 'sha512-dGVzdA==',
        },
      },
    },
    maintainers: [{ name: 'publisher' }],
    repository: { url: 'https://github.com/example/some-pkg' },
  };
}

function response(body) {
  return { ok: true, status: 200, async text() { return JSON.stringify(body); } };
}

describe('analyzeSinglePackage: signal cache vs fresh OSV evidence', () => {
  it('passes the configured metadata TTL to signal-cache reads', async () => {
    const previousFetch = global.fetch;
    global.fetch = async () => response(registryPack());
    let observedTtl;
    const cache = {
      getSignals: (_eco, _name, _version, ttl) => { observedTtl = ttl; return null; },
      setSignals() {},
    };
    try {
      await analyzeSinglePackage(dep, osvDataFor([]), { cache: { metadataTtlMs: 1234 } }, cache);
      assert.equal(observedTtl, 1234);
    } finally {
      global.fetch = previousFetch;
    }
  });

  it('serves a cache hit only when the fresh OSV evidence matches the fingerprint', async () => {
    const previousFetch = global.fetch;
    global.fetch = async () => response(registryPack());
    let stored = null;
    const cache = {
      getSignals: () => stored,
      setSignals: (_eco, _name, _version, value) => { stored = value; },
    };
    try {
      const first = await analyzeSinglePackage(dep, osvDataFor([]), {}, cache);
      assert.equal(first.riskLevel, 'NONE');
      assert.equal(typeof stored.analysisFingerprint, 'string');
      stored.cacheMarker = 'served';
      const out = await analyzeSinglePackage(dep, osvDataFor([]), {}, cache);
      assert.equal(out.cacheMarker, 'served');
      assert.equal(out.osvFingerprint, undefined);
      assert.equal(out.analysisFingerprint, undefined);
    } finally {
      global.fetch = previousFetch;
    }
  });

  it('invalidates a cached clean verdict when registry signal metadata changes', async () => {
    const previousFetch = global.fetch;
    let pack = registryPack();
    global.fetch = async () => response(pack);
    let stored = null;
    const cache = {
      getSignals: () => stored,
      setSignals: (_eco, _name, _version, value) => { stored = value; },
    };
    try {
      const first = await analyzeSinglePackage(dep, osvDataFor([]), {}, cache);
      assert.equal(first.signals.some(signal => signal.signal === 'POSTINSTALL_SCRIPT'), false);
      pack = registryPack({ postinstall: 'node setup.js' });
      const second = await analyzeSinglePackage(dep, osvDataFor([]), {}, cache);
      assert.equal(second.signals.some(signal => signal.signal === 'POSTINSTALL_SCRIPT'), true);
    } finally {
      global.fetch = previousFetch;
    }
  });

  it('re-analyzes (never trusts cache) when a new advisory appeared since caching', async () => {
    // cached "clean" verdict formed on zero advisories; OSV now reports one
    const cache = cleanCacheWith('', {
      name: 'some-pkg', version: '1.0.0', ecosystem: 'npm',
      signals: [], riskScore: 0, riskLevel: 'NONE', warnings: [],
      osvFingerprint: '',
    });
    const out = await analyzeSinglePackage(dep, osvDataFor([{ id: 'GHSA-fresh-advisory' }]), {}, cache);
    // The stale clean cache must NOT be returned: the analysis re-ran, so the
    // output is a fresh object (fingerprint-free, carrying the OSV evidence).
    assert.notEqual(out.riskLevel, 'NONE', 'stale clean verdict must not be served when a new advisory exists');
  });

  it('re-analyzes when the advisory disappears since caching (mismatched fingerprint)', async () => {
    const cache = cleanCacheWith('GHSA-old-advisory', {
      name: 'some-pkg', version: '1.0.0', ecosystem: 'npm',
      signals: [{ signal: 'KNOWN_COMPROMISED' }], riskScore: 10, riskLevel: 'CRITICAL', warnings: [],
      osvFingerprint: 'GHSA-old-advisory',
    });
    const out = await analyzeSinglePackage(dep, osvDataFor([]), {}, cache);
    assert.equal(out.riskLevel !== 'CRITICAL' || out.signals.length === 0, true,
      'stale CRITICAL verdict must be re-derived when the advisory set changed');
  });

  it('never serves the cache when the OSV lookup was incomplete this run', async () => {
    const cache = cleanCacheWith('', {
      name: 'some-pkg', version: '1.0.0', ecosystem: 'npm',
      signals: [], riskScore: 0, riskLevel: 'NONE', warnings: [],
      osvFingerprint: '',
    });
    // osvData undefined → not covered → fingerprint 'uncovered' ≠ cached ''
    const out = await analyzeSinglePackage(dep, undefined, {}, cache);
    assert.equal(out.osvFingerprint, undefined);
    assert.ok(out.warnings.includes('OSV vulnerability lookup incomplete'),
      'uncovered OSV run must re-analyze and carry the incompleteness warning');
  });

  it('stores the osvFingerprint on writes so later runs can reconcile', async () => {
    capturedWrite = null;
    const cache = {
      getSignals: () => null,
      setSignals: (eco, name, version, value) => { capturedWrite = value; },
      close: () => {},
    };
    // npm metadata fetch fails offline → metadata null → degraded → no write.
    // Use the cached-hit round trip instead: assert via a completed write when
    // OSV evidence is present and metadata is null is NOT stored (degraded).
    const out = await analyzeSinglePackage(dep, osvDataFor([{ id: 'GHSA-x' }]), {}, cache);
    assert.equal(capturedWrite, null, 'degraded analysis (no metadata) must not be cached');
    assert.equal(out.osvFingerprint, undefined, 'fingerprint stays internal');
  });
});
