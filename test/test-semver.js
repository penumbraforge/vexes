import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareSemver } from '../src/core/semver.js';

describe('compareSemver', () => {
  it('orders 9.0.0 below 10.0.0 (numeric, not lexicographic)', () => {
    // The whole reason this module exists: '9.0.0' > '10.0.0' is true as a
    // string, which would recommend a stale fix version.
    assert.ok(compareSemver('9.0.0', '10.0.0') < 0);
    assert.ok(compareSemver('10.0.0', '9.0.0') > 0);
  });

  it('returns 0 for equal versions', () => {
    assert.equal(compareSemver('1.2.3', '1.2.3'), 0);
  });

  it('compares minor and patch numerically', () => {
    assert.ok(compareSemver('1.2.3', '1.10.0') < 0);
    assert.ok(compareSemver('1.2.10', '1.2.9') > 0);
  });

  it('treats missing components as 0', () => {
    assert.equal(compareSemver('1', '1.0.0'), 0);
    assert.ok(compareSemver('1.1', '1.0.5') > 0);
  });

  it('strips leading range operators and v-prefix', () => {
    assert.equal(compareSemver('>= 1.2.3', '1.2.3'), 0);
    assert.equal(compareSemver('^2.0.0', 'v2.0.0'), 0);
  });

  it('ignores pre-release / build metadata for core ordering', () => {
    assert.equal(compareSemver('1.2.3-rc.1', '1.2.3'), 0);
    assert.ok(compareSemver('2.0.0-beta', '1.9.9') > 0);
  });

  it('sorts a candidate list highest-last as an Array#sort comparator', () => {
    const sorted = ['1.0.0', '10.0.0', '2.0.0', '9.0.0'].sort(compareSemver);
    assert.deepEqual(sorted, ['1.0.0', '2.0.0', '9.0.0', '10.0.0']);
  });
});
