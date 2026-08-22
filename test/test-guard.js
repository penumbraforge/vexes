import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { dryRunFlags, requestedNamesFromArgs, verifyLockfileDiff, buildGuardEnvelope } from '../src/commands/guard.js';
import { SCHEMA_VERSION } from '../src/cli/schema.js';

describe('guard dry-run flags (manager-correct)', () => {
  it('maps each package manager to its lockfile-only flag set', () => {
    assert.deepEqual(dryRunFlags('npm'), ['--package-lock-only', '--ignore-scripts']);
    assert.deepEqual(dryRunFlags('pnpm'), ['--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(dryRunFlags('yarn'), ['--mode=update-lockfile', '--ignore-scripts', '--non-interactive']);
    assert.deepEqual(dryRunFlags('npx'), []); // no lockfile-only mode — no flags to add
    assert.deepEqual(dryRunFlags('something-else'), dryRunFlags('npm'));
  });

  it('never includes a flag that would execute install scripts', () => {
    for (const m of ['npm', 'pnpm', 'yarn']) {
      assert.ok(dryRunFlags(m).includes('--ignore-scripts'), `${m} must ignore scripts`);
    }
  });
});

describe('requestedNamesFromArgs', () => {
  it('pulls package names out of manager install args', () => {
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', 'lodash@^4.17.21', '-D']), ['lodash']);
    assert.deepEqual(requestedNamesFromArgs(['pnpm', 'i', 'left-pad', 'rimraf@3']), ['left-pad', 'rimraf']);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '@scope/pkg@1.2.3']), ['@scope/pkg']);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '@scope/pkg']), ['@scope/pkg']);
    assert.deepEqual(requestedNamesFromArgs(['yarn', 'add', 'foo']), ['foo']);
  });

  it('ignores flags, local paths, and the current-dir target', () => {
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', './', '-D']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '../vendor/x', '--save-dev']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'run', 'build']), []);
    assert.deepEqual(requestedNamesFromArgs([]), []);
  });
});

// Fixtures: a tiny npm-style graph. `lodash` is what the install asked for;
// it depends on `is-number`. Anything else in the diff is suspicious.
const BEFORE = {
  name: 'proj', lockfileVersion: 3,
  packages: {
    '': { name: 'proj', dependencies: { lodash: '^4.17.21' } },
    'node_modules/lodash': { version: '4.17.20', dependencies: { 'is-number': '^7.0.0' } },
    'node_modules/is-number': { version: '7.0.0' },
  },
};
const AFTER = {
  name: 'proj', lockfileVersion: 3,
  packages: {
    '': { name: 'proj', dependencies: { lodash: '^4.17.21' } },
    'node_modules/lodash': { version: '4.17.21', dependencies: { 'is-number': '^7.0.0' } },
    'node_modules/is-number': { version: '7.0.0' },
    'node_modules/malicious': { version: '1.0.0', dependencies: { 'is-number': '^7.0.0' } },
  },
};

describe('guard lockfile tamper check (verifyLockfileDiff)', () => {
  it('passes when the diff is reachable from the requested install', () => {
    const diff = {
      added: [{ name: 'is-number', version: '7.0.0', ecosystem: 'npm' }],
      changed: [{ name: 'lodash', fromVersion: '4.17.20', toVersion: '4.17.21', ecosystem: 'npm' }],
      removed: [],
    };
    const reason = verifyLockfileDiff({
      beforeRaw: JSON.stringify(BEFORE),
      afterRaw: JSON.stringify(AFTER),
      diff,
      requestedNames: ['lodash'],
    });
    assert.equal(reason, null, JSON.stringify(reason));
  });

  it('flags an added package nobody asked for', () => {
    const reason = verifyLockfileDiff({
      beforeRaw: JSON.stringify(BEFORE),
      afterRaw: JSON.stringify(AFTER),
      diff: { added: [{ name: 'malicious' }], changed: [], removed: [] },
      requestedNames: ['lodash'],
    });
    assert.match(String(reason), /added package "malicious"/);
  });

  it('flags a changed package outside the requested reach', () => {
    const reason = verifyLockfileDiff({
      beforeRaw: JSON.stringify(BEFORE),
      afterRaw: JSON.stringify(AFTER),
      diff: { added: [], changed: [{ name: 'zig', toVersion: '2.0.0' }], removed: [] },
      requestedNames: ['lodash'],
    });
    assert.match(String(reason), /changed package "zig"/);
  });

  it('flags a removed package that was never reachable in the before graph', () => {
    const reason = verifyLockfileDiff({
      beforeRaw: JSON.stringify(BEFORE),
      afterRaw: JSON.stringify(AFTER),
      diff: { added: [], changed: [], removed: [{ name: 'left-pad' }] },
      requestedNames: ['lodash'],
    });
    assert.match(String(reason), /removed package "left-pad"/);
  });

  it('allows removing a package the requested install sat on (dedupe/evict)', () => {
    const reason = verifyLockfileDiff({
      beforeRaw: JSON.stringify(BEFORE),
      afterRaw: JSON.stringify(AFTER),
      diff: { added: [], changed: [], removed: [{ name: 'is-number' }] },
      requestedNames: ['lodash'],
    });
    assert.equal(reason, null, JSON.stringify(reason));
  });

  it('skips attribution when no requested names are given', () => {
    const reason = verifyLockfileDiff({
      beforeRaw: 'garbage',
      afterRaw: 'garbage',
      diff: { added: [{ name: 'anything@^9' }], changed: [], removed: [] },
      requestedNames: [],
    });
    assert.equal(reason, null);
  });
});

describe('guard JSON envelope (buildGuardEnvelope)', () => {
  it('emits the schema envelope and keeps guard-specific fields', () => {
    const diff = { added: [{ name: 'x' }], changed: [], removed: [] };
    const payload = buildGuardEnvelope({
      installCommand: 'npm install x',
      diff,
      blocked: true,
      incomplete: false,
      warnings: ['w1'],
      results: [{ name: 'x', riskLevel: 'CRITICAL' }],
    });
    assert.equal(payload.schemaVersion, SCHEMA_VERSION);
    assert.equal(payload.generator.name, 'vexes');
    assert.equal(payload.command, 'guard');
    assert.equal(payload.complete, true, 'not incomplete ⇒ complete stays true');
    assert.deepEqual(payload.warnings, ['w1']);
    assert.deepEqual(payload.summary, { added: 1, changed: 0, removed: 0, blocked: true, incomplete: false });
    // guard-specific field remained a top-level key for old consumers
    assert.deepEqual(payload.results, [{ name: 'x', riskLevel: 'CRITICAL' }]);
    assert.equal(payload.blocked, true);
    assert.equal(payload.installCommand, 'npm install x');
    assert.deepEqual(payload.diff, { added: 1, changed: 0, removed: 0 });
  });

  it('reports incomplete scans as complete:false (fail loud)', () => {
    const payload = buildGuardEnvelope({
      installCommand: 'npm install y', diff: { added: [], changed: [], removed: [] },
      blocked: false, incomplete: true, warnings: [], results: [],
    });
    assert.equal(payload.complete, false);
    assert.equal(payload.result.complete, false);
  });
});
