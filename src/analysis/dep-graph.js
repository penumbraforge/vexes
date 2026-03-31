import { fetchJSON } from '../core/fetcher.js';
import { NPM_REGISTRY_URL } from '../core/constants.js';
import { log } from '../core/logger.js';

/**
 * Dependency graph analyzer.
 *
 * Goes beyond "did a new dep appear" — profiles WHAT the new dep is.
 * This layer would have caught the axios attack: plain-crypto-js was
 * 18 hours old, had zero dependents, and was published by the same
 * compromised account.
 */

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const TWO_DAYS_MS = 2 * 24 * 60 * 60 * 1000;

/**
 * Analyze newly added dependencies of a package for suspicious characteristics.
 *
 * @param {Object} metadata — npm registry metadata (from npm-registry.js)
 * @returns {Promise<Array<DepGraphFinding>>}
 */
export async function analyzeNewDeps(metadata) {
  const findings = [];

  if (!metadata?.addedDeps?.length) return findings;

  log.debug(`analyzing ${metadata.addedDeps.length} new deps for ${metadata.name}`);

  // Fetch metadata for each newly added dependency
  const depProfiles = await Promise.allSettled(
    metadata.addedDeps.map(depName => profileDependency(depName))
  );

  for (let i = 0; i < metadata.addedDeps.length; i++) {
    const depName = metadata.addedDeps[i];
    const result = depProfiles[i];

    if (result.status !== 'fulfilled' || !result.value) {
      // Unknown metadata on a new dep = elevated risk — we can't verify it's safe
      findings.push({
        signal: 'NEW_DEPENDENCY',
        severity: 'HIGH',
        description: `New dependency "${depName}" added — metadata unavailable, cannot assess risk`,
        evidence: { depName, metadataUnavailable: true },
      });
      continue;
    }

    const profile = result.value;

    // PHANTOM DEPENDENCY: brand new package with no ecosystem presence
    if (profile.packageAgeMs !== null && profile.packageAgeMs < SEVEN_DAYS_MS) {
      findings.push({
        signal: 'PHANTOM_DEPENDENCY',
        severity: 'CRITICAL',
        description: `New dependency "${depName}" is only ${Math.floor(profile.packageAgeMs / (3600000))} hours old on the registry`,
        evidence: {
          depName,
          age: profile.packageAgeMs,
          maintainerCount: profile.maintainerCount,
          versionCount: profile.versionCount,
        },
      });
    }

    // Single maintainer + brand new = extremely suspicious
    if (profile.maintainerCount <= 1 && profile.versionCount <= 2) {
      findings.push({
        signal: 'PHANTOM_DEPENDENCY',
        severity: 'HIGH',
        description: `New dependency "${depName}" has only ${profile.maintainerCount} maintainer(s) and ${profile.versionCount} version(s)`,
        evidence: {
          depName,
          maintainerCount: profile.maintainerCount,
          versionCount: profile.versionCount,
        },
      });
    }

    // CIRCULAR STAGING: new dep published by the same account as the parent
    if (metadata.latestPublisher && profile.latestPublisher &&
        metadata.latestPublisher === profile.latestPublisher) {
      // Check timing — same publisher within 48 hours is a staging pattern
      if (profile.latestPublishTime && metadata.latestPublishTime) {
        const timeDiff = Math.abs(metadata.latestPublishTime - profile.latestPublishTime);
        if (timeDiff < TWO_DAYS_MS) {
          findings.push({
            signal: 'CIRCULAR_STAGING',
            severity: 'CRITICAL',
            description: `New dependency "${depName}" was published by the same account (${metadata.latestPublisher}) within ${Math.floor(timeDiff / 3600000)} hours of this package`,
            evidence: {
              depName,
              sharedPublisher: metadata.latestPublisher,
              timeDiffMs: timeDiff,
            },
          });
        }
      }
    }

    // DEP HAS INSTALL SCRIPTS: new dep that runs code on install
    if (profile.hasInstallScripts) {
      findings.push({
        signal: 'NEW_DEP_HAS_INSTALL_SCRIPTS',
        severity: 'HIGH',
        description: `New dependency "${depName}" has install lifecycle scripts`,
        evidence: {
          depName,
          scripts: profile.installScripts,
        },
      });
    }

    // If none of the above, still flag it as a new dep (MODERATE)
    if (!findings.some(f => f.evidence?.depName === depName)) {
      findings.push({
        signal: 'NEW_DEPENDENCY',
        severity: 'MODERATE',
        description: `New dependency "${depName}" added in latest version`,
        evidence: { depName },
      });
    }
  }

  return findings;
}

/**
 * Fetch a lightweight profile for a dependency from npm registry.
 * Uses the abbreviated metadata endpoint (smaller response).
 */
/**
 * Encode npm package name for URLs. Scoped: @scope/name → @scope%2fname
 */
function encodeNpmName(name) {
  if (name.startsWith('@')) return '@' + encodeURIComponent(name.slice(1));
  return encodeURIComponent(name);
}

async function profileDependency(packageName) {
  try {
    const url = `${NPM_REGISTRY_URL}/${encodeNpmName(packageName)}`;
    const data = await fetchJSON(url, {
      headers: { 'Accept': 'application/json' },
      timeout: 8000,
    });

    const timeMap = data.time || {};
    const versions = Object.keys(data.versions || {});
    const created = timeMap.created ? new Date(timeMap.created) : null;
    const latestTag = data['dist-tags']?.latest;
    const latestData = latestTag ? data.versions?.[latestTag] : null;

    return {
      name: packageName,
      packageAgeMs: created ? (Date.now() - created) : null,
      maintainerCount: (data.maintainers || []).length,
      versionCount: versions.length,
      latestPublisher: latestData?._npmUser?.name || null,
      latestPublishTime: latestTag && timeMap[latestTag] ? new Date(timeMap[latestTag]) : null,
      hasInstallScripts: !!(latestData?.scripts?.preinstall || latestData?.scripts?.install || latestData?.scripts?.postinstall),
      installScripts: {
        preinstall: latestData?.scripts?.preinstall || null,
        install: latestData?.scripts?.install || null,
        postinstall: latestData?.scripts?.postinstall || null,
      },
    };
  } catch (err) {
    log.debug(`failed to profile dependency ${packageName}: ${err.message}`);
    return null;
  }
}

/**
 * Detect typosquatting by computing Levenshtein distance against popular packages.
 * Scales threshold with name length to avoid false positives on short names.
 *
 * @param {string} name — package name to check
 * @param {Set<string>} popularPackages — set of known popular package names
 * @returns {Array<{ similar: string, distance: number }>}
 */
export function detectTyposquat(name, popularPackages) {
  const matches = [];
  const lower = name.toLowerCase();

  // Scale max distance with name length — short names have too many false positives
  // length 1-3: distance 0 only (exact match, skip)
  // length 4-6: distance 1
  // length 7+:  distance 2
  const maxDistance = lower.length <= 3 ? 0 : lower.length <= 6 ? 1 : 2;
  if (maxDistance === 0) return matches;

  for (const popular of popularPackages) {
    if (lower === popular) continue;
    // Skip if popular name is also very short — too many coincidental matches
    if (popular.length <= 3 && lower.length <= 5) continue;
    const dist = levenshtein(lower, popular);
    if (dist <= maxDistance && dist > 0) {
      matches.push({ similar: popular, distance: dist });
    }
  }

  return matches.sort((a, b) => a.distance - b.distance);
}

/**
 * Standard Levenshtein distance — O(m*n), no external deps.
 */
function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Early exit for obvious non-matches
  if (Math.abs(a.length - b.length) > 2) return Math.abs(a.length - b.length);

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return matrix[b.length][a.length];
}
