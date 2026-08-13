import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeMetadata } from '../src/advisories/pypi-registry.js';

/**
 * PYPI METADATA NORMALIZATION
 *
 * Before the fix, fetchPypiMetadata hit the *versioned* endpoint whenever a
 * version was passed (analyze always passes one). That endpoint returns no
 * `releases` map, so previousVersion / publish timing / package age /
 * dormancy were all null and PyPI analysis silently ran on one layer
 * instead of four. These tests pin the unversioned-endpoint shape plus the
 * version-anchoring and the newly emitted signal fields.
 */

const file = (iso) => [{ upload_time_iso_8601: iso, yanked: false }];

// Shape of the UNVERSIONED endpoint: info describes the latest release,
// releases maps every version to its files.
const pypiData = {
  info: {
    name: 'demo-pkg',
    version: '3.0.0',
    author: 'author',
    author_email: 'a@example.com',
    requires_dist: ['urllib3 (>=1.26)', 'idna'],
    project_urls: { Source: 'https://github.com/example/demo-pkg' },
    license: 'Apache-2.0',
  },
  releases: {
    '1.0.0': file('2020-01-01T00:00:00Z'),
    '1.1.0': file('2020-06-01T00:00:00Z'),
    // 20-month dormancy gap here — the event-stream shape
    '2.0.0': file('2022-02-01T00:00:00Z'),
    '3.0.0': file('2022-03-01T00:00:00Z'),
  },
  vulnerabilities: [],
};

describe('PyPI metadata: release history now populated', () => {
  it('publish-history fields are non-null (the layer-4 resurrection)', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '2.0.0');
    assert.notEqual(meta.previousVersion, null);
    assert.notEqual(meta.latestPublishTime, null);
    assert.notEqual(meta.previousPublishTime, null);
    assert.notEqual(meta.publishIntervalMs, null);
    assert.notEqual(meta.packageAgeMs, null);
    assert.ok(meta.versionCount === 4);
  });

  it('anchors to the installed version', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '2.0.0');
    assert.equal(meta.anchoredToInstalled, true);
    assert.equal(meta.latestVersion, '2.0.0');
    assert.equal(meta.latestAvailable, '3.0.0');
    assert.equal(meta.previousVersion, '1.1.0');
    assert.equal(meta.latestPublishTime.toISOString(), '2022-02-01T00:00:00.000Z');
  });

  it('emits majorJump relative to the anchor', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '2.0.0');
    assert.equal(meta.majorJump, 1, '1.1.0 → 2.0.0 is a major jump');
    const meta2 = normalizeMetadata(pypiData, 'demo-pkg', '1.1.0');
    assert.equal(meta2.majorJump, 0);
  });

  it('emits dormancyMs from the release-gap history (event-stream shape)', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '2.0.0');
    const twentyMonthsMs = new Date('2022-02-01T00:00:00Z') - new Date('2020-06-01T00:00:00Z');
    assert.equal(meta.dormancyMs, twentyMonthsMs);
  });

  it('dormancy ignores releases published after the anchor', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '1.1.0');
    // Only 1.0.0 → 1.1.0 history exists at that point: a 5-month gap.
    const fiveMonthsMs = new Date('2020-06-01T00:00:00Z') - new Date('2020-01-01T00:00:00Z');
    assert.equal(meta.dormancyMs, fiveMonthsMs);
  });

  it('does not fabricate npm-only fields', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '2.0.0');
    assert.equal(meta.maintainerChanged, undefined,
      'PyPI has no per-release publisher — the field must stay absent, not be faked');
    assert.equal(meta.hasInstallScripts, undefined,
      'install-script detection on PyPI comes from --deep tarball inspection');
  });

  it('unknown installed version falls back to latest and says so', () => {
    const meta = normalizeMetadata(pypiData, 'demo-pkg', '9.9.9');
    assert.equal(meta.anchoredToInstalled, false);
    assert.equal(meta.latestVersion, '3.0.0');
  });
});
