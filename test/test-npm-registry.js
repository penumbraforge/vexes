import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeMetadata } from '../src/advisories/npm-registry.js';

/**
 * VERSION-ANCHORED METADATA NORMALIZATION
 *
 * `analyze` must inspect the version actually installed, not
 * dist-tags.latest. Before the fix, a lockfile pinned to a clean 1.2.3
 * inherited every Layer 3/4 signal (publisher change, install scripts,
 * dependency diff) from whatever `latest` happened to be.
 */

// A packument where the story changes dramatically between the installed
// version (1.2.3, clean, original maintainer) and latest (9.0.0, hijacked:
// new publisher, added postinstall, added dependency).
const packument = {
  'dist-tags': { latest: '9.0.0' },
  time: {
    created: '2020-01-01T00:00:00Z',
    modified: '2026-08-01T00:00:00Z',
    '1.2.2': '2021-05-01T00:00:00Z',
    '1.2.3': '2021-06-01T00:00:00Z',
    '9.0.0': '2026-08-01T00:00:00Z',
  },
  maintainers: [{ name: 'attacker' }],
  versions: {
    '1.2.2': {
      version: '1.2.2',
      _npmUser: { name: 'original-author' },
      scripts: {},
      dependencies: { lodash: '^4.0.0' },
      license: 'MIT',
    },
    '1.2.3': {
      version: '1.2.3',
      _npmUser: { name: 'original-author' },
      scripts: {},
      dependencies: { lodash: '^4.0.0' },
      license: 'MIT',
    },
    '9.0.0': {
      version: '9.0.0',
      _npmUser: { name: 'attacker' },
      scripts: { postinstall: 'node evil.js' },
      dependencies: { lodash: '^4.0.0', 'evil-helper': '^1.0.0' },
      license: 'MIT',
    },
  },
  repository: { url: 'https://github.com/example/pkg' },
};

describe('npm metadata version anchoring', () => {
  it('anchors every signal field to the installed version, not latest', () => {
    const meta = normalizeMetadata(packument, 'pkg', '1.2.3');

    assert.equal(meta.anchoredToInstalled, true);
    assert.equal(meta.latestVersion, '1.2.3');
    assert.equal(meta.latestAvailable, '9.0.0');
    assert.equal(meta.previousVersion, '1.2.2');

    // The hijack signals belong to 9.0.0 and must NOT appear here.
    assert.equal(meta.hasInstallScripts, false, 'installed 1.2.3 has no install scripts');
    assert.equal(meta.latestPublisher, 'original-author');
    assert.equal(meta.previousPublisher, 'original-author');
    assert.equal(meta.maintainerChanged, false, 'no publisher change at 1.2.3');
    assert.deepEqual(meta.addedDeps, [], 'evil-helper was added in 9.0.0, not 1.2.3');
    assert.equal(meta.majorJump, 0);
  });

  it('analyzing latest still surfaces the hijack signals', () => {
    const meta = normalizeMetadata(packument, 'pkg', '9.0.0');

    assert.equal(meta.latestVersion, '9.0.0');
    assert.equal(meta.previousVersion, '1.2.3');
    assert.equal(meta.hasInstallScripts, true);
    assert.equal(meta.maintainerChanged, true, 'original-author → attacker');
    assert.deepEqual(meta.addedDeps, ['evil-helper']);
    assert.equal(meta.majorJump, 8);
  });

  it('publish timing is computed relative to the installed version', () => {
    const meta = normalizeMetadata(packument, 'pkg', '1.2.3');
    assert.equal(meta.latestPublishTime.toISOString(), '2021-06-01T00:00:00.000Z');
    assert.equal(meta.previousPublishTime.toISOString(), '2021-05-01T00:00:00.000Z');
    assert.equal(meta.publishIntervalMs, 31 * 24 * 60 * 60 * 1000);
  });

  it('unknown installed version falls back to latest and says so', () => {
    const meta = normalizeMetadata(packument, 'pkg', '7.7.7-not-published');
    assert.equal(meta.anchoredToInstalled, false);
    assert.equal(meta.latestVersion, '9.0.0');
  });

  it('no version argument preserves the legacy latest-based behavior', () => {
    const meta = normalizeMetadata(packument, 'pkg');
    assert.equal(meta.anchoredToInstalled, false);
    assert.equal(meta.latestVersion, '9.0.0');
    assert.equal(meta.previousVersion, '1.2.3');
  });
});

describe('previousInstallScripts extraction', () => {
  // PREVIOUS-VERSION SCRIPT HISTORY
  //
  // previousInstallScripts is deliberately three-valued:
  //   null  — no previous version exists (or registry unreachable): capabilities
  //           of the previous version are UNKNOWN, no diff possible
  //   {}    — previous version exists and verifiably has no lifecycle scripts
  //   {...} — previous version's lifecycle scripts, inspectable like the current
  //           ones so behavioral diffing measures both sides the same way
  it('exposes the previous version lifecycle scripts for the anchor version', () => {
    const withScripts = {
      ...packument,
      versions: {
        ...packument.versions,
        '1.2.3': {
          ...packument.versions['1.2.3'],
          scripts: { postinstall: 'node-gyp rebuild' },
        },
      },
    };
    const meta = normalizeMetadata(withScripts, 'pkg', '9.0.0');
    assert.deepEqual(meta.previousInstallScripts, { postinstall: 'node-gyp rebuild' });
  });

  it('gives {} when the previous version verifiably has no lifecycle scripts', () => {
    const meta = normalizeMetadata(packument, 'pkg', '9.0.0');
    // 1.2.3 exists with scripts: {} — meaningful, diffable absence.
    assert.deepEqual(meta.previousInstallScripts, {});
  });

  it('gives null when there is no previous version at all', () => {
    const only = {
      'dist-tags': { latest: '1.0.0' },
      time: { created: '2026-01-01T00:00:00Z', '1.0.0': '2026-01-01T00:00:00Z' },
      versions: { '1.0.0': { version: '1.0.0', scripts: { postinstall: 'node x.js' } } },
    };
    const meta = normalizeMetadata(only, 'pkg', '1.0.0');
    assert.equal(meta.previousVersion, null);
    assert.equal(meta.previousInstallScripts, null);
  });
});
