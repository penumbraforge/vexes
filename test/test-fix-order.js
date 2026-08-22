import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { orderFixesByDependency } from '../src/commands/fix.js';

/**
 * MINIMAL UPGRADE SET ORDERING — dependency before dependent, deterministic.
 * All fixtures are written to a throwaway temp dir (no network, no repo).
 */

function writeLock(dir, content) {
  const p = join(dir, 'package-lock.json');
  writeFileSync(p, content);
  return p;
}

function mkfix(pkg, hasRecommendation = true) {
  return {
    package: pkg,
    currentVersion: '1.0.0',
    ecosystem: 'npm',
    vulnCount: 1,
    vulnIds: ['CVE-x'],
    recommendation: hasRecommendation ? { version: '2.0.0', command: `npm install ${pkg}@2.0.0` } : null,
  };
}

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'vexes-fix-order-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe('orderFixesByDependency', () => {
  it('puts a pure dependency BEFORE its dependent (v3 flat lockfile)', () => {
    withDir((dir) => {
      const lock = writeLock(dir, JSON.stringify({
        packages: {
          '': { name: 'app', dependencies: { a: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { b: '^1.0.0' } },
          'node_modules/b': { version: '1.0.0' },
        },
      }));
      const fixes = [mkfix('a', true), mkfix('b', true)];
      const { fixes: out, order } = orderFixesByDependency(fixes, { lockfiles: [lock] });
      assert.deepEqual(order, ['b', 'a']);                 // b (dependency) first
      assert.deepEqual(out.map(f => f.package), ['b', 'a']);
    });
  });

  it('keeps independent packages in deterministic name order', () => {
    withDir((dir) => {
      const lock = writeLock(dir, JSON.stringify({ packages: { '': {}, 'node_modules/z': { version: '1' }, 'node_modules/a': { version: '1' } } }));
      const fixes = [mkfix('z'), mkfix('a')];
      const { order } = orderFixesByDependency(fixes, { lockfiles: [lock] });
      assert.deepEqual(order, ['a', 'z']);
    });
  });

  it('breaks cycles deterministically without hanging', () => {
    withDir((dir) => {
      const lock = writeLock(dir, JSON.stringify({
        packages: {
          'node_modules/a': { dependencies: { b: '^1.0.0' } },
          'node_modules/b': { dependencies: { a: '^1.0.0' } },
        },
      }));
      const fixes = [mkfix('a'), mkfix('b')];
      const { fixes: out, order } = orderFixesByDependency(fixes, { lockfiles: [lock] });
      assert.equal(order.length, 2);
      assert.deepEqual([...order].sort(), ['a', 'b']);
      assert.deepEqual(out.map(f => f.package), order);
    });
  });

  it('appends unfixable records at the tail, stable', () => {
    const fixes = [mkfix('dep', true), mkfix('app', true), mkfix('orphan', false), mkfix('zzz', false)];
    const { fixes: out } = orderFixesByDependency(fixes, { lockfiles: [] });
    const names = out.map(f => f.package);
    assert.deepEqual(names.slice(0, 2).sort(), ['app', 'dep']); // fixable depend only on each other here
    assert.deepEqual(names.slice(2), ['orphan', 'zzz']);        // unfixable keep insertion order
  });

  it('respects edges from the npm v2 nested lockfile form', () => {
    withDir((dir) => {
      const lock = writeLock(dir, JSON.stringify({
        dependencies: {
          a: { version: '1.0.0', dependencies: { b: '1.0.0' } },
          b: { version: '1.0.0' },
        },
      }));
      const { order } = orderFixesByDependency([mkfix('a'), mkfix('b')], { lockfiles: [lock] });
      assert.deepEqual(order, ['b', 'a']);
    });
  });

  it('is a no-op for a single fixable record', () => {
    const { fixes, order } = orderFixesByDependency([mkfix('solo')], { lockfiles: [] });
    assert.deepEqual(order, ['solo']);
    assert.equal(fixes.length, 1);
  });
});
