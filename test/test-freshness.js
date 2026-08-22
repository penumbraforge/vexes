import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assessNewVersion, checkOneDep } from '../src/analysis/freshness.js';

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
    const r = assessNewVersion(meta({ dormancyMs: 200 * DAY }));
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
    const r = await checkOneDep({ name: 'pkg', version: '1.5.0', ecosystem: 'npm' }, { fetchMeta });
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
});
