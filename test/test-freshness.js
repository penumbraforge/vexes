import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assessNewVersion, checkOneDep, checkFreshness } from '../src/analysis/freshness.js';

/**
 * FRESHNESS LAYER (new-release detection)
 *
 * Pure-grade checks run on synthetic metadata objects (no network). checkOneDep
 * uses an injected fetchMeta so nothing touches the registry.
 */

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function meta(overrides = {}) {
  return {
    name: 'pkg',
    latestVersion: '1.0.0',
    latestAvailable: '1.0.0',
    previousVersion: '0.9.0',
    maintainerChanged: false,
    latestPublisher: 'alice',
    previousPublisher: 'alice',
    hasInstallScripts: false,
    installScripts: {},
    previousInstallScripts: {},
    addedDeps: [],
    removedDeps: [],
    publishIntervalMs: 30 * DAY,
    packageAgeMs: 2 * 365 * DAY,
    majorJump: 0,
    dormancyMs: null,
    versionCount: 5,
    ...overrides,
  };
}

describe('freshness: assessNewVersion', () => {
  it('stays silent on a clean release', () => {
    const r = assessNewVersion(meta());
    assert.equal(r.alert, false);
    assert.deepEqual(r.reasons, []);
  });

  it('flags a publisher change at HIGH', () => {
    const r = assessNewVersion(meta({ maintainerChanged: true, previousPublisher: 'alice', latestPublisher: 'mallory' }));
    assert.equal(r.alert, true);
    assert.equal(r.level, 'high');
    assert.ok(r.reasons.some(x => /publisher changed/.test(x)));
  });

  it('flags new install lifecycle scripts as HIGH', () => {
    const r = assessNewVersion(meta({ hasInstallScripts: true, installScripts: { postinstall: 'node evil.js' } }));
    assert.equal(r.alert, true);
    assert.equal(r.level, 'high');
    assert.ok(r.reasons.some(x => /install lifecycle scripts/.test(x)));
  });

  it('flags added deps + rapid publish as MODERATE', () => {
    const r = assessNewVersion(meta({ addedDeps: ['obfuscator', 'socks-proxy'], publishIntervalMs: 20 * 60 * 1000 }));
    assert.equal(r.alert, true);
    assert.equal(r.level, 'moderate');
    assert.ok(r.reasons.some(x => /added 2 new dependency/.test(x)));
    assert.ok(r.reasons.some(x => /published only 20min/.test(x)));
  });

  it('flags a dormant-but-active release', () => {
    const r = assessNewVersion(meta({ publishIntervalMs: 200 * DAY }));
    assert.equal(r.alert, true);
    assert.ok(r.reasons.some(x => /reactivated after 200 days/.test(x)));
  });

  it('flags a major jump only when no stronger signal fired', () => {
    const r = assessNewVersion(meta({ majorJump: 5 }));
    assert.equal(r.alert, true);
    assert.ok(r.reasons.some(x => /major jump/.test(x)));
  });

  it('handles null metadata as no-op', () => {
    assert.deepEqual(assessNewVersion(null), { alert: false, level: 'low', reasons: [] });
  });
});

describe('freshness: checkOneDep', () => {
  it('does not alert when the registry latest matches the installed version', async () => {
    const fetchMeta = async () => meta({ latestAvailable: '1.0.0', latestVersion: '1.0.0' });
    const r = await checkOneDep({ name: 'pkg', version: '1.0.0', ecosystem: 'npm' }, { fetchMeta });
    assert.equal(r.isNew, false);
    assert.equal(r.alert, false);
  });

  it('alerts on a new publish with dangerous deltas', async () => {
    const fetchMeta = async () => meta({
      latestAvailable: '2.0.0', latestVersion: '2.0.0',
      maintainerChanged: true, previousPublisher: 'alice', latestPublisher: 'mallory',
    });
    const r = await checkOneDep(
      { name: 'pkg', version: '1.5.0', ecosystem: 'npm' },
      { fetchMeta, lastSeenVersion: '1.5.0' },
    );
    assert.equal(r.isNew, true);
    assert.equal(r.latest, '2.0.0');
    assert.equal(r.alert, true);
    assert.equal(r.level, 'high');
  });

  it('degrades to skipped when the fetcher returns null', async () => {
    const fetchMeta = async () => null;
    const r = await checkOneDep({ name: 'pkg', version: '1.0.0', ecosystem: 'npm' }, { fetchMeta });
    assert.equal(r.skipped, true);
    assert.equal(r.alert, false);
  });

  it('establishes a baseline instead of calling an existing update newly published', async () => {
    const fetchMeta = async () => meta({ latestAvailable: '2.0.0', latestVersion: '2.0.0', maintainerChanged: true });
    const r = await checkOneDep({ name: 'pkg', version: '1.0.0', ecosystem: 'npm' }, { fetchMeta });
    assert.equal(r.baseline, true);
    assert.equal(r.updateAvailable, true);
    assert.equal(r.isNew, false);
    assert.equal(r.alert, false);
  });

  it('refuses unsupported ecosystems instead of querying them as npm', async () => {
    let fetched = false;
    const r = await checkOneDep(
      { name: 'serde', version: '1.0.0', ecosystem: 'cargo' },
      { fetchMeta: async () => { fetched = true; return meta(); } },
    );
    assert.equal(fetched, false);
    assert.equal(r.skipped, true);
    assert.match(r.warning, /does not support ecosystem cargo/);
  });
});

describe('freshness: persisted release events', () => {
  it('alerts once per newly observed latest version and reports lookup completeness', async () => {
    const states = new Map();
    const cache = {
      getFreshnessState(eco, name) { const latestVersion = states.get(`${eco}:${name}`); return latestVersion ? { latestVersion } : null; },
      setFreshnessState(eco, name, version) { states.set(`${eco}:${name}`, version); },
    };
    let latest = '2.0.0';
    const fetchMeta = async () => meta({
      latestAvailable: latest, latestVersion: latest,
      maintainerChanged: true, previousPublisher: 'alice', latestPublisher: 'mallory',
    });
    const deps = [{ name: 'pkg', version: '1.0.0', ecosystem: 'npm' }];

    const baseline = await checkFreshness(deps, { fetchMeta, cache });
    assert.equal(baseline.complete, true);
    assert.equal(baseline.alerts.length, 0);

    latest = '2.0.1';
    const changed = await checkFreshness(deps, { fetchMeta, cache });
    assert.equal(changed.alerts.length, 1);
    const repeated = await checkFreshness(deps, { fetchMeta, cache });
    assert.equal(repeated.alerts.length, 0);
  });
});
