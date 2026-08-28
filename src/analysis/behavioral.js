import { log } from '../core/logger.js';

/**
 * Behavioral fingerprinting.
 *
 * Builds a capability profile per package version, then diffs against the
 * previous version. A utility library that suddenly gains process+network
 * capabilities between versions is flagged. The DIFF is what matters.
 *
 * Honesty note: registry metadata does not expose a previous version's
 * install scripts, so a fabricated "previous" profile must be marked
 * `capabilitiesKnown: false`. Only a profile built from actually-inspected
 * previous-version code sets it true; anything else degrades to
 * INITIAL_DANGEROUS_CAPABILITY (present-now, MODERATE) instead of claiming
 * a CAPABILITY_ESCALATION (gained-between-versions, CRITICAL).
 */

/**
 * Build a behavioral profile from npm registry metadata + AST inspection results.
 *
 * @param {Object} metadata — from npm-registry.js
 * @param {Object} [astResult] — from ast-inspector.js (if install scripts were inspected)
 * @returns {BehavioralProfile}
 */
export function buildProfile(metadata, astResult) {
  const capabilities = new Set();

  // From install scripts analysis
  if (astResult) {
    if (astResult.capabilities.executesCode) capabilities.add('code_execution');
    if (astResult.capabilities.spawnsProcess) capabilities.add('process_spawn');
    if (astResult.capabilities.accessesNetwork) capabilities.add('network');
    if (astResult.capabilities.writesFilesystem) capabilities.add('filesystem_write');
    if (astResult.capabilities.writesSystemPaths) capabilities.add('system_write');
    if (astResult.capabilities.readsCredentials) capabilities.add('credential_access');
    if (astResult.capabilities.decodesPayloads) capabilities.add('payload_decode');
    if (astResult.capabilities.selfDeletes) capabilities.add('self_deletion');
    if (astResult.capabilities.dynamicLoading) capabilities.add('dynamic_loading');
  }

  // From metadata signals
  if (metadata?.hasInstallScripts) capabilities.add('install_scripts');

  return {
    capabilities: [...capabilities].sort(),
    hasInstallScripts: metadata?.hasInstallScripts || false,
    dependencyCount: metadata?.dependencies?.length || 0,
    maintainerCount: metadata?.maintainers?.length || 0,
    hasRepository: !!metadata?.repository,
  };
}

/**
 * Diff two behavioral profiles to detect capability escalation.
 *
 * @param {BehavioralProfile} current — current version profile
 * @param {BehavioralProfile} previous — previous version profile (or null for first version)
 * @returns {Array<BehavioralFinding>}
 */
export function diffProfiles(current, previous) {
  const findings = [];

  if (!previous || previous.capabilitiesKnown === false) {
    // No previous-version capability data (first version, or the registry
    // gives no per-version script history). No diff is possible — flag the
    // dangerous capabilities the current version HAS, at MODERATE, without
    // claiming they appeared "between versions". Metadata-only diffs that
    // don't depend on capability data (dependency spike) still run below.
    for (const cap of current.capabilities) {
      if (DANGEROUS_CAPABILITIES.has(cap)) {
        findings.push({
          signal: 'INITIAL_DANGEROUS_CAPABILITY',
          severity: 'MODERATE',
          description: `Package has "${cap}" capability in its latest version (previous version's capabilities unknown — no diff possible)`,
          evidence: { capability: cap },
        });
      }
    }
    if (!previous) return findings;
  }

  const capsKnown = previous.capabilitiesKnown !== false;
  const prevCaps = new Set(previous.capabilities);
  const newCaps = current.capabilities.filter(c => !prevCaps.has(c));

  // Capability escalation: new dangerous capabilities appeared. Only claimed
  // when the previous version's capabilities are actually known — otherwise
  // the initial-capability path above already spoke.
  for (const cap of newCaps) {
    if (capsKnown && DANGEROUS_CAPABILITIES.has(cap)) {
      findings.push({
        signal: 'CAPABILITY_ESCALATION',
        severity: 'CRITICAL',
        description: `Package gained "${cap}" capability in latest version (was not present before)`,
        evidence: {
          capability: cap,
          previousCapabilities: previous.capabilities,
          currentCapabilities: current.capabilities,
        },
      });
    }
  }

  // Dependency count spike — packages suddenly adding many deps is suspicious
  if (previous.dependencyCount > 0 && current.dependencyCount > previous.dependencyCount * 2 && current.dependencyCount > 5) {
    findings.push({
      signal: 'DEPENDENCY_SPIKE',
      severity: 'HIGH',
      description: `Dependency count jumped from ${previous.dependencyCount} to ${current.dependencyCount}`,
      evidence: {
        previousCount: previous.dependencyCount,
        currentCount: current.dependencyCount,
      },
    });
  }

  // Maintainer count change
  if (previous.maintainerCount > 0 && current.maintainerCount < previous.maintainerCount) {
    findings.push({
      signal: 'MAINTAINER_REDUCTION',
      severity: 'MODERATE',
      description: `Maintainer count dropped from ${previous.maintainerCount} to ${current.maintainerCount}`,
      evidence: {
        previousCount: previous.maintainerCount,
        currentCount: current.maintainerCount,
      },
    });
  }

  // Repository removed
  if (previous.hasRepository && !current.hasRepository) {
    findings.push({
      signal: 'REPOSITORY_REMOVED',
      severity: 'MODERATE',
      description: 'Repository link was removed from package metadata',
      evidence: {},
    });
  }

  return findings;
}

const DANGEROUS_CAPABILITIES = new Set([
  'code_execution',
  'process_spawn',
  'network',
  'system_write',
  'credential_access',
  'self_deletion',
  'payload_decode',
]);
