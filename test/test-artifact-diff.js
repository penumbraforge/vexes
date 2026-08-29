import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { diffSnapshots, toSnapshot } from '../src/analysis/diff.js';

describe('artifact-aware dependency diff', () => {
  it('does not collapse two occurrences of the same package', () => {
    const before = toSnapshot([
      { ecosystem: 'npm', name: 'x', version: '1.0.0', occurrence: 'node_modules/x', integrity: 'sha512-a' },
      { ecosystem: 'npm', name: 'x', version: '2.0.0', occurrence: 'node_modules/a/node_modules/x', integrity: 'sha512-b' },
    ]);
    const after = toSnapshot([
      { ecosystem: 'npm', name: 'x', version: '9.0.0', occurrence: 'node_modules/x', integrity: 'sha512-z' },
      { ecosystem: 'npm', name: 'x', version: '2.0.0', occurrence: 'node_modules/a/node_modules/x', integrity: 'sha512-b' },
    ]);

    const diff = diffSnapshots(before, after);
    assert.equal(diff.changed.length, 1);
    assert.equal(diff.changed[0].occurrence, 'node_modules/x');
    assert.equal(diff.changed[0].fromVersion, '1.0.0');
    assert.equal(diff.changed[0].toVersion, '9.0.0');
    assert.equal(diff.unchanged.length, 1);
  });

  it('retains resolved and integrity evidence on same-version replacement', () => {
    const diff = diffSnapshots(
      [{ ecosystem: 'npm', name: 'x', version: '1.0.0', occurrence: 'node_modules/x', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-old' }],
      [{ ecosystem: 'npm', name: 'x', version: '1.0.0', occurrence: 'node_modules/x', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-new' }],
    );
    assert.equal(diff.changed.length, 1);
    assert.equal(diff.changed[0].integrityChanged, true);
    assert.equal(diff.changed[0].integrity, 'sha512-new');
    assert.equal(diff.changed[0].fromIntegrity, 'sha512-old');
  });

  for (const [label, beforeArtifact, afterArtifact, flag] of [
    ['resolved URL change', { resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz' }, { resolved: 'https://registry.npmjs.org/x/-/replacement.tgz' }, 'resolvedChanged'],
    ['resolved URL removal', { resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz' }, {}, 'resolvedChanged'],
    ['resolved URL addition', {}, { resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz' }, 'resolvedChanged'],
    ['integrity removal', { integrity: 'sha512-old' }, {}, 'integrityChanged'],
    ['integrity addition', {}, { integrity: 'sha512-new' }, 'integrityChanged'],
  ]) {
    it(`detects same-version artifact ${label}`, () => {
      const base = { ecosystem: 'npm', name: 'x', version: '1.0.0', occurrence: 'node_modules/x' };
      const diff = diffSnapshots([{ ...base, ...beforeArtifact }], [{ ...base, ...afterArtifact }]);
      assert.equal(diff.changed.length, 1);
      assert.equal(diff.changed[0][flag], true);
      assert.equal(diff.changed[0].fromVersion, '1.0.0');
      assert.equal(diff.changed[0].toVersion, '1.0.0');
      assert.equal(diff.unchanged.length, 0);
    });
  }
});
