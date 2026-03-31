import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildProfile, diffProfiles } from '../src/analysis/behavioral.js';

describe('Behavioral profiling', () => {
  it('builds profile from metadata', () => {
    const profile = buildProfile({
      hasInstallScripts: true,
      dependencies: ['dep-a', 'dep-b'],
      maintainers: [{ name: 'alice' }],
      repository: 'https://github.com/x/y',
    }, null);

    assert.ok(profile.capabilities.includes('install_scripts'));
    assert.equal(profile.dependencyCount, 2);
    assert.equal(profile.maintainerCount, 1);
    assert.equal(profile.hasRepository, true);
  });

  it('incorporates AST capabilities into profile', () => {
    const profile = buildProfile({}, {
      capabilities: {
        executesCode: true,
        spawnsProcess: true,
        accessesNetwork: false,
      },
    });

    assert.ok(profile.capabilities.includes('code_execution'));
    assert.ok(profile.capabilities.includes('process_spawn'));
    assert.ok(!profile.capabilities.includes('network'));
  });

  it('handles null metadata gracefully', () => {
    const profile = buildProfile(null, null);
    assert.ok(Array.isArray(profile.capabilities));
  });
});

describe('Behavioral diff', () => {
  it('detects capability escalation', () => {
    const prev = {
      capabilities: [],
      hasInstallScripts: false,
      dependencyCount: 5,
      maintainerCount: 2,
      hasRepository: true,
    };
    const curr = {
      capabilities: ['process_spawn', 'network'],
      hasInstallScripts: true,
      dependencyCount: 5,
      maintainerCount: 2,
      hasRepository: true,
    };

    const findings = diffProfiles(curr, prev);
    assert.ok(findings.some(f => f.signal === 'CAPABILITY_ESCALATION'));
    const escalations = findings.filter(f => f.signal === 'CAPABILITY_ESCALATION');
    assert.ok(escalations.some(f => f.evidence.capability === 'process_spawn'));
    assert.ok(escalations.some(f => f.evidence.capability === 'network'));
  });

  it('detects dependency count spike', () => {
    const prev = { capabilities: [], hasInstallScripts: false, dependencyCount: 3, maintainerCount: 1, hasRepository: true };
    const curr = { capabilities: [], hasInstallScripts: false, dependencyCount: 10, maintainerCount: 1, hasRepository: true };

    const findings = diffProfiles(curr, prev);
    assert.ok(findings.some(f => f.signal === 'DEPENDENCY_SPIKE'));
  });

  it('detects repository removal', () => {
    const prev = { capabilities: [], hasInstallScripts: false, dependencyCount: 1, maintainerCount: 1, hasRepository: true };
    const curr = { capabilities: [], hasInstallScripts: false, dependencyCount: 1, maintainerCount: 1, hasRepository: false };

    const findings = diffProfiles(curr, prev);
    assert.ok(findings.some(f => f.signal === 'REPOSITORY_REMOVED'));
  });

  it('returns empty for no changes', () => {
    const profile = { capabilities: [], hasInstallScripts: false, dependencyCount: 5, maintainerCount: 2, hasRepository: true };
    const findings = diffProfiles(profile, profile);
    assert.equal(findings.length, 0);
  });

  it('handles null previous profile (first version)', () => {
    const curr = { capabilities: ['network'], hasInstallScripts: false, dependencyCount: 1, maintainerCount: 1, hasRepository: true };
    const findings = diffProfiles(curr, null);
    // Should get INITIAL_DANGEROUS_CAPABILITY, not crash
    assert.ok(Array.isArray(findings));
  });
});
