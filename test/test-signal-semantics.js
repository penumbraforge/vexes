import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzePackage,
  isExplicitMaliciousAdvisory,
  isKnownAdvisorySignal,
} from '../src/analysis/signals.js';

function baseMetadata(overrides = {}) {
  return {
    name: 'honest-widget',
    latestVersion: '2.0.0',
    previousVersion: '1.0.0',
    maintainers: [{ name: 'author' }, { name: 'reviewer' }],
    latestPublisher: 'author',
    previousPublisher: 'author',
    maintainerChanged: false,
    hasInstallScripts: false,
    installScripts: {},
    previousInstallScripts: {},
    scripts: {},
    dependencies: [],
    addedDeps: [],
    removedDeps: [],
    latestPublishTime: new Date('2026-01-02T00:00:00Z'),
    previousPublishTime: new Date('2026-01-01T00:00:00Z'),
    publishIntervalMs: 24 * 60 * 60 * 1000,
    packageAgeMs: 2 * 365 * 24 * 60 * 60 * 1000,
    majorJump: 1,
    dormancyMs: null,
    versionCount: 20,
    repository: 'https://github.com/example/honest-widget',
    license: 'MIT',
    ...overrides,
  };
}

describe('truthful OSV signal semantics', () => {
  it('labels ordinary OSV records as vulnerabilities and preserves max severity', async () => {
    const osv = [
      { id: 'GHSA-low', aliases: ['CVE-2026-1'], severity: 'LOW' },
      { id: 'GHSA-high', aliases: [], severity: 'HIGH' },
    ];
    const result = await analyzePackage(baseMetadata(), osv, { ecosystem: 'npm' });
    const signal = result.signals.find(s => s.signal === 'KNOWN_VULNERABILITY');

    assert.ok(signal);
    assert.equal(signal.severity, 'HIGH');
    assert.deepEqual(signal.evidence.ids, ['GHSA-low', 'CVE-2026-1', 'GHSA-high']);
    assert.equal(result.signals.some(s => s.signal === 'KNOWN_COMPROMISED'), false);
    assert.equal(result.signals.some(s => s.signal === 'KNOWN_MALICIOUS'), false);
  });

  it('separates explicit MAL advisories without inflating their supplied severity', async () => {
    const osv = [
      { id: 'MAL-2026-1234', aliases: [], severity: 'LOW' },
      { id: 'GHSA-ordinary', aliases: [], severity: 'MODERATE' },
    ];
    const result = await analyzePackage(baseMetadata(), osv, { ecosystem: 'npm' });

    assert.equal(isExplicitMaliciousAdvisory(osv[0]), true);
    assert.equal(isExplicitMaliciousAdvisory(osv[1]), false);
    assert.equal(result.signals.find(s => s.signal === 'KNOWN_MALICIOUS')?.severity, 'LOW');
    assert.equal(result.signals.find(s => s.signal === 'KNOWN_VULNERABILITY')?.severity, 'MODERATE');
    assert.equal(isKnownAdvisorySignal('KNOWN_MALICIOUS'), true);
    assert.equal(isKnownAdvisorySignal('KNOWN_COMPROMISED'), true, 'legacy consumers stay recognizable');
  });

  it('honors both new per-signal switches and the legacy advisory switch', async () => {
    const osv = [
      { id: 'MAL-2026-1234', aliases: [], severity: 'CRITICAL' },
      { id: 'GHSA-ordinary', aliases: [], severity: 'HIGH' },
    ];
    const individuallyDisabled = await analyzePackage(baseMetadata(), osv, {
      ecosystem: 'npm',
      config: { analyze: { signals: { KNOWN_MALICIOUS: 'off' } } },
    });
    assert.equal(individuallyDisabled.signals.some(s => s.signal === 'KNOWN_MALICIOUS'), false);
    assert.equal(individuallyDisabled.signals.some(s => s.signal === 'KNOWN_VULNERABILITY'), true);

    const legacyDisabled = await analyzePackage(baseMetadata(), osv, {
      ecosystem: 'npm',
      config: { analyze: { signals: { KNOWN_COMPROMISED: 'off' } } },
    });
    assert.equal(legacyDisabled.signals.some(s => isKnownAdvisorySignal(s.signal)), false);
  });
});

describe('signal policy and family deduplication', () => {
  it('treats install-script presence as context, not a HIGH maliciousness verdict', async () => {
    const result = await analyzePackage(baseMetadata({
      hasInstallScripts: true,
      installScripts: { postinstall: "node -e \"require('./lib/verify.js').check()\"" },
    }), null, { ecosystem: 'npm' });

    assert.equal(result.signals.find(s => s.signal === 'POSTINSTALL_SCRIPT')?.severity, 'MODERATE');
    assert.equal(result.signals.some(s => s.signal === 'AST_DANGEROUS_PATTERN'), false);
  });

  it('honors HOMOGLYPH off and emits at most one grouped finding when enabled', async () => {
    const suspicious = baseMetadata({ name: 'honest\u200b\u202e-widget' });
    const enabled = await analyzePackage(suspicious, null, { ecosystem: 'npm' });
    const grouped = enabled.signals.filter(s => s.signal === 'HOMOGLYPH');
    assert.equal(grouped.length, 1);
    assert.deepEqual(grouped[0].evidence.types, ['INVISIBLE_CHARS', 'BIDI_OVERRIDE', 'NON_ASCII']);

    const disabled = await analyzePackage(suspicious, null, {
      ecosystem: 'npm',
      config: { analyze: { signals: { HOMOGLYPH: 'off' } } },
    });
    assert.equal(disabled.signals.some(s => s.signal === 'HOMOGLYPH'), false);
  });

  it('honors an individual behavioral signal off while leaving the layer available', async () => {
    const metadata = baseMetadata({
      hasInstallScripts: true,
      installScripts: { postinstall: "node -e \"require('https').get('https://example.invalid')\"" },
      previousInstallScripts: {},
    });
    const result = await analyzePackage(metadata, null, {
      ecosystem: 'npm',
      config: { analyze: { signals: { CAPABILITY_ESCALATION: 'off' } } },
    });
    assert.equal(result.signals.some(s => s.signal === 'CAPABILITY_ESCALATION'), false);
  });

  it('honors install-script and AST switches independently', async () => {
    const metadata = baseMetadata({
      hasInstallScripts: true,
      installScripts: { postinstall: "node -e \"require('child_process').exec('id')\"" },
      previousInstallScripts: null,
    });
    const result = await analyzePackage(metadata, null, {
      ecosystem: 'npm',
      config: { analyze: { signals: {
        POSTINSTALL_SCRIPT: 'off',
        AST_DANGEROUS_PATTERN: 'off',
        INITIAL_DANGEROUS_CAPABILITY: 'off',
        CAPABILITY_ESCALATION: 'off',
      } } },
    });
    assert.equal(result.signals.some(s => s.signal === 'POSTINSTALL_SCRIPT'), false);
    assert.equal(result.signals.some(s => s.signal === 'AST_DANGEROUS_PATTERN'), false);
    assert.equal(result.signals.some(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY'), false);
  });

  it('does not run dependency profiling when every dependency-family signal is off', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      throw new Error('dependency profiling should not run');
    };
    try {
      const result = await analyzePackage(baseMetadata({
        dependencies: ['new-helper'],
        addedDeps: ['new-helper'],
      }), null, {
        ecosystem: 'npm',
        config: { analyze: { signals: {
          NEW_DEPENDENCY: 'off',
          PHANTOM_DEPENDENCY: 'off',
          CIRCULAR_STAGING: 'off',
          NEW_DEP_HAS_INSTALL_SCRIPTS: 'off',
        } } },
      });
      assert.equal(fetchCalls, 0);
      assert.equal(result.signals.some(s => s.layer === 2), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('preserves old dormancy as context without a permanent HIGH verdict', async () => {
    const day = 24 * 60 * 60 * 1000;
    const asOf = new Date('2026-08-28T00:00:00Z').getTime();
    const old = await analyzePackage(baseMetadata({
      dormancyMs: 500 * day,
      latestPublishTime: new Date(asOf - 500 * day),
    }), null, { ecosystem: 'npm', now: asOf });
    assert.equal(old.signals.find(s => s.signal === 'VERSION_ANOMALY')?.severity, 'LOW');

    const recent = await analyzePackage(baseMetadata({
      dormancyMs: 500 * day,
      latestPublishTime: new Date(asOf - 10 * day),
    }), null, { ecosystem: 'npm', now: asOf });
    assert.equal(recent.signals.find(s => s.signal === 'VERSION_ANOMALY')?.severity, 'HIGH');
  });

  it('collapses repeated capability facts and exact AST patterns', async () => {
    const payload = "require('child_process').exec('id');require('https').get('https://example.invalid');eval('1');";
    const result = await analyzePackage(baseMetadata({
      hasInstallScripts: true,
      installScripts: {
        preinstall: `node -e \"${payload}${payload}\"`,
        postinstall: `node -e \"${payload}\"`,
      },
      previousInstallScripts: null,
    }), null, { ecosystem: 'npm' });

    const initial = result.signals.filter(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY');
    assert.equal(initial.length, 1);
    assert.ok(initial[0].evidence.capabilities.length >= 2);

    const ast = result.signals.filter(s => s.signal === 'AST_DANGEROUS_PATTERN');
    const keys = ast.map(s => `${s.evidence.script}|${s.evidence.pattern}`);
    assert.equal(new Set(keys).size, keys.length, 'same script/pattern family is counted once');
  });
});
