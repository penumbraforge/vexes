import { NPM_REGISTRY_URL, NPM_ATTESTATIONS_URL } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

/**
 * Encode npm package name for use in registry URLs.
 * Scoped packages need special handling: @scope/name → @scope%2fname
 */
function encodeNpmName(name) {
  if (name.startsWith('@')) {
    // Only encode the slash, not the @
    return '@' + encodeURIComponent(name.slice(1));
  }
  return encodeURIComponent(name);
}

/**
 * Fetch full package metadata from the npm registry.
 * Returns structured data about maintainers, scripts, publish history, and dependencies.
 *
 * When `version` is given, every signal-feeding field (publisher, scripts,
 * dependency diff, publish timing) is anchored to THAT version — the one
 * actually installed — not dist-tags.latest. Analyzing `latest` while
 * reporting on the installed version attributes someone else's signals to
 * the artifact in the user's tree.
 *
 * @param {string} packageName
 * @param {string} [version] — installed version to anchor the analysis to
 * @returns {Promise<NpmMetadata|null>}
 */
export async function fetchNpmMetadata(packageName, version = null) {
  const url = `${NPM_REGISTRY_URL}/${encodeNpmName(packageName)}`;

  try {
    const data = await fetchJSON(url);
    return normalizeMetadata(data, packageName, version);
  } catch (err) {
    log.debug(`npm registry fetch failed for ${packageName}: ${err.message}`);
    return null;
  }
}

/**
 * Fetch provenance attestation for a specific package version.
 * Returns null if no attestation exists (most packages don't have one).
 */
export async function fetchNpmProvenance(packageName, version) {
  const url = `${NPM_ATTESTATIONS_URL}/${encodeNpmName(packageName)}@${encodeURIComponent(version)}`;

  try {
    const data = await fetchJSON(url);
    return {
      hasProvenance: true,
      attestations: data.attestations || [],
    };
  } catch (err) {
    // 404 = no attestation (normal for most packages)
    if (err.status === 404) return { hasProvenance: false, attestations: [] };
    log.debug(`provenance fetch failed for ${packageName}@${version}: ${err.message}`);
    return null;
  }
}

// Exported for tests: version anchoring must be verifiable against packument
// fixtures without network access.
export function normalizeMetadata(data, packageName, requestedVersion = null) {
  const latestTag = data['dist-tags']?.latest;
  const timeMap = data.time || {};
  const versions = data.versions || {};

  // Get the sorted version list by publish time
  const versionList = Object.keys(timeMap)
    .filter(v => v !== 'created' && v !== 'modified' && versions[v])
    .sort((a, b) => new Date(timeMap[a]) - new Date(timeMap[b]));

  const latestAvailable = latestTag || versionList[versionList.length - 1];

  // Anchor to the installed version when the packument knows it; otherwise
  // fall back to latest (and say so via anchoredToInstalled).
  const anchoredToInstalled = requestedVersion !== null && versions[requestedVersion] !== undefined;
  const latestVersion = anchoredToInstalled ? requestedVersion : latestAvailable;
  const anchorIdx = versionList.indexOf(latestVersion);

  const latestData = versions[latestVersion] || {};
  const previousVersion = anchorIdx > 0
    ? versionList[anchorIdx - 1]
    : (anchorIdx === -1 && versionList.length >= 2 ? versionList[versionList.length - 2] : null);
  const previousData = previousVersion ? versions[previousVersion] : null;

  // Extract maintainer info
  const maintainers = (data.maintainers || []).map(m => ({
    name: m.name || m.username,
    email: m.email,
  }));

  // Who published the latest version vs previous
  const latestPublisher = latestData._npmUser?.name || latestData._npmUser?.email || null;
  const previousPublisher = previousData?._npmUser?.name || previousData?._npmUser?.email || null;

  // Extract scripts from latest version.
  // Check ALL lifecycle scripts that can execute code, not just pre/install/postinstall.
  // `prepare` is critical: runs after install from git dependencies.
  const scripts = latestData.scripts || {};
  const LIFECYCLE_SCRIPTS = [
    'preinstall', 'install', 'postinstall',
    'prepare',          // Runs after install (especially from git deps)
    'prepublish',       // Deprecated but still honored
    'prepublishOnly',   // Runs only during npm publish
    'prepack', 'postpack',  // Runs around tarball creation
    'dependencies',     // npm v7+ — runs after dep tree resolved
  ];
  const installScripts = {};
  for (const hook of LIFECYCLE_SCRIPTS) {
    if (scripts[hook]) installScripts[hook] = scripts[hook];
  }
  const hasInstallScripts = Object.keys(installScripts).length > 0;

  // Previous version's lifecycle scripts — lets behavioral analysis run a
  // REAL capability diff instead of assuming the previous version was clean.
  // null = previous version unknown (no diff possible); {} = previous version
  // known to have no lifecycle scripts (a meaningful, diffable fact).
  let previousInstallScripts = null;
  if (previousData) {
    previousInstallScripts = {};
    const prevScripts = previousData.scripts || {};
    for (const hook of LIFECYCLE_SCRIPTS) {
      if (prevScripts[hook]) previousInstallScripts[hook] = prevScripts[hook];
    }
  }

  // Extract dependencies diff (latest vs previous)
  const latestDeps = Object.keys(latestData.dependencies || {});
  const previousDeps = previousData ? Object.keys(previousData.dependencies || {}) : latestDeps;
  const previousDepsSet = new Set(previousDeps);
  const addedDeps = latestDeps.filter(d => !previousDepsSet.has(d));
  const latestDepsSet = new Set(latestDeps);
  const removedDeps = previousDeps.filter(d => !latestDepsSet.has(d));

  // Publish timestamps
  const latestPublishTime = timeMap[latestVersion] ? new Date(timeMap[latestVersion]) : null;
  const previousPublishTime = previousVersion && timeMap[previousVersion]
    ? new Date(timeMap[previousVersion]) : null;

  // Time since last publish before this one
  let publishIntervalMs = null;
  if (latestPublishTime && previousPublishTime) {
    publishIntervalMs = latestPublishTime - previousPublishTime;
  }

  // Time since the FIRST publish (package age)
  const created = timeMap.created ? new Date(timeMap.created) : null;
  const packageAgeMs = created ? (Date.now() - created) : null;

  // Version jump analysis
  let majorJump = 0;
  if (previousVersion && latestVersion) {
    const prevMajor = parseInt(previousVersion.split('.')[0], 10) || 0;
    const currMajor = parseInt(latestVersion.split('.')[0], 10) || 0;
    majorJump = currMajor - prevMajor;
  }

  // Dormancy: max gap between any consecutive versions in the 5 releases up
  // to and including the anchor — releases published *after* the installed
  // version can't say anything about how it arrived.
  // This detects packages that were abandoned then suddenly reactivated
  let dormancyMs = null;
  const historyUpToAnchor = anchorIdx >= 0 ? versionList.slice(0, anchorIdx + 1) : versionList;
  if (historyUpToAnchor.length >= 2) {
    const recentVersions = historyUpToAnchor.slice(-5);
    for (let i = 1; i < recentVersions.length; i++) {
      const prev = new Date(timeMap[recentVersions[i - 1]]);
      const curr = new Date(timeMap[recentVersions[i]]);
      const gap = curr - prev;
      if (gap > 0 && (dormancyMs === null || gap > dormancyMs)) {
        dormancyMs = gap;
      }
    }
  }

  return {
    name: packageName,
    latestVersion,       // the analyzed (anchor) version — installed when known
    latestAvailable,     // dist-tags.latest, for outdated-version signals
    anchoredToInstalled,
    previousVersion,
    maintainers,
    latestPublisher,
    previousPublisher,
    maintainerChanged: latestPublisher !== null && previousPublisher !== null && latestPublisher !== previousPublisher,
    hasInstallScripts,
    installScripts,
    previousInstallScripts,
    scripts,
    dependencies: latestDeps,
    addedDeps,
    removedDeps,
    latestPublishTime,
    previousPublishTime,
    publishIntervalMs,
    packageAgeMs,
    majorJump,
    dormancyMs,
    versionCount: versionList.length,
    repository: data.repository?.url || data.repository || null,
    license: latestData.license || data.license || null,
  };
}
