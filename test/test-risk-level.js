import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePackage, scoreToLevel } from '../src/analysis/signals.js';

/**
 * RISK LEVEL DERIVATION
 *
 * analyze.js mutates riskScore after analyzePackage() (provenance, deep
 * tarball findings) and must re-derive riskLevel via scoreToLevel(). These
 * tests pin the thresholds and the post-hoc recompute invariant.
 */

describe('scoreToLevel thresholds', () => {
  it('maps scores to levels at documented boundaries', () => {
    assert.equal(scoreToLevel(0), 'NONE');
    assert.equal(scoreToLevel(0.1), 'LOW');
    assert.equal(scoreToLevel(4.9), 'LOW');
    assert.equal(scoreToLevel(5), 'MODERATE');
    assert.equal(scoreToLevel(14.9), 'MODERATE');
    assert.equal(scoreToLevel(15), 'HIGH');
    assert.equal(scoreToLevel(29.9), 'HIGH');
    assert.equal(scoreToLevel(30), 'CRITICAL');
  });
});

describe('post-hoc scoring must re-derive the level', () => {
  it('deep-inspection signals added after analyzePackage change the level', async () => {
    // A quiet package: no signals, NONE level.
    const meta = {
      name: 'quiet-pkg',
      latestVersion: '1.0.0',
      previousVersion: '0.9.0',
      maintainers: [{ name: 'author' }],
      latestPublisher: 'author',
      previousPublisher: 'author',
      maintainerChanged: false,
      hasInstallScripts: false,
      installScripts: {},
      scripts: {},
      dependencies: [],
      addedDeps: [],
      removedDeps: [],
      latestPublishTime: new Date('2024-01-01T00:00:00Z'),
      previousPublishTime: new Date('2023-06-01T00:00:00Z'),
      publishIntervalMs: 200 * 24 * 60 * 60 * 1000,
      packageAgeMs: 4 * 365 * 24 * 60 * 60 * 1000,
      majorJump: 0,
      dormancyMs: null,
      versionCount: 20,
      repository: 'https://github.com/example/quiet-pkg',
      license: 'MIT',
    };

    const result = await analyzePackage(meta, null, { ecosystem: 'npm' });
    assert.equal(result.riskLevel, 'NONE');

    // Simulate what analyze.js does when --deep finds dangerous patterns:
    // push signals, bump the score... the level MUST be re-derived, exactly
    // as the recompute pass in analyze.js step 6 does.
    const pkg = { ...result, riskScore: result.riskScore + 3 * 5 }; // 3 HIGH findings × weight 5
    pkg.riskLevel = scoreToLevel(pkg.riskScore);

    assert.equal(pkg.riskLevel, 'HIGH',
      'deep findings must elevate the level, not just the score');
  });
});
