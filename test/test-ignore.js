import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildIgnoreMatcher, isIgnored, partitionByIgnore } from '../src/core/ignore.js';

// Mirrors the scan vulnerability shape.
const vulns = [
  { id: 'GHSA-aaaa-bbbb-cccc', displayId: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2021-1111'], package: 'lodash', version: '4.17.20', ecosystem: 'npm' },
  { id: 'PYSEC-2022-1', displayId: 'CVE-2022-2222', aliases: ['CVE-2022-2222'], package: 'requests', version: '2.25.0', ecosystem: 'pypi' },
  { id: 'RUSTSEC-2023-1', displayId: 'RUSTSEC-2023-1', aliases: [], package: 'tokio', version: '1.0.0', ecosystem: 'cargo' },
  { id: 'GHSA-dddd-eeee-ffff', displayId: 'GHSA-dddd-eeee-ffff', aliases: [], package: 'lodash', version: '4.17.21', ecosystem: 'npm' },
];

const accessor = v => ({ pkg: v.package, version: v.version, ids: [v.id, v.displayId, ...v.aliases] });

describe('ignore config', () => {
  it('ignores by advisory ID (primary id)', () => {
    const { kept, suppressed } = partitionByIgnore(vulns, ['RUSTSEC-2023-1'], accessor);
    assert.equal(suppressed.length, 1);
    assert.equal(suppressed[0].package, 'tokio');
    assert.equal(kept.length, 3);
  });

  it('ignores by advisory ID (alias / displayId)', () => {
    const { suppressed } = partitionByIgnore(vulns, ['CVE-2021-1111'], accessor);
    assert.equal(suppressed.length, 1);
    assert.equal(suppressed[0].package, 'lodash');
    assert.equal(suppressed[0].version, '4.17.20');
  });

  it('ignores by package name (all versions)', () => {
    const { kept, suppressed } = partitionByIgnore(vulns, ['lodash'], accessor);
    assert.equal(suppressed.length, 2, 'both lodash versions suppressed');
    assert.ok(suppressed.every(v => v.package === 'lodash'));
    assert.equal(kept.length, 2);
  });

  it('ignores by pkg@version (one version only)', () => {
    const { kept, suppressed } = partitionByIgnore(vulns, ['lodash@4.17.20'], accessor);
    assert.equal(suppressed.length, 1);
    assert.equal(suppressed[0].version, '4.17.20');
    // The other lodash version is kept.
    assert.ok(kept.some(v => v.package === 'lodash' && v.version === '4.17.21'));
  });

  it('reports the suppressed count and leaves the rest intact', () => {
    const { kept, suppressed } = partitionByIgnore(vulns, ['lodash', 'RUSTSEC-2023-1'], accessor);
    assert.equal(suppressed.length, 3);
    assert.equal(kept.length, 1);
    assert.equal(kept[0].package, 'requests');
  });

  it('empty / missing ignore list is a no-op (same array reference)', () => {
    const result = partitionByIgnore(vulns, [], accessor);
    assert.equal(result.suppressed.length, 0);
    assert.equal(result.kept, vulns);
    const result2 = partitionByIgnore(vulns, undefined, accessor);
    assert.equal(result2.kept, vulns);
  });

  it('handles scoped package names in bare and pinned forms', () => {
    const scoped = [
      { package: '@babel/core', version: '7.0.0', id: 'X', displayId: 'X', aliases: [] },
      { package: '@babel/core', version: '7.1.0', id: 'Y', displayId: 'Y', aliases: [] },
    ];
    const bare = partitionByIgnore(scoped, ['@babel/core'], accessor);
    assert.equal(bare.suppressed.length, 2);
    const pinned = partitionByIgnore(scoped, ['@babel/core@7.0.0'], accessor);
    assert.equal(pinned.suppressed.length, 1);
    assert.equal(pinned.suppressed[0].version, '7.0.0');
  });

  it('buildIgnoreMatcher marks empty config inactive', () => {
    assert.equal(buildIgnoreMatcher([]).active, false);
    assert.equal(buildIgnoreMatcher(['GHSA-x']).active, true);
    assert.equal(isIgnored(buildIgnoreMatcher([]), { pkg: 'lodash' }), false);
  });
});
