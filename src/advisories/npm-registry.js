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
 * @param {string} packageName
 * @returns {Promise<NpmMetadata|null>}
 */
export async function fetchNpmMetadata(packageName) {
  const url = `${NPM_REGISTRY_URL}/${encodeNpmName(packageName)}`;

  try {
    const data = await fetchJSON(url);
    return normalizeMetadata(data, packageName);
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

function normalizeMetadata(data, packageName) {
  const latestTag = data['dist-tags']?.latest;
  const timeMap = data.time || {};
  const versions = data.versions || {};

  // Get the sorted version list by publish time
  const versionList = Object.keys(timeMap)
    .filter(v => v !== 'created' && v !== 'modified' && versions[v])
    .sort((a, b) => new Date(timeMap[a]) - new Date(timeMap[b]));

  const latestVersion = latestTag || versionList[versionList.length - 1];
  const latestData = versions[latestVersion] || {};
  const previousVersion = versionList.length >= 2 ? versionList[versionList.length - 2] : null;
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

  // Dormancy: max gap between any consecutive versions in the last 5 releases
  // This detects packages that were abandoned then suddenly reactivated
  let dormancyMs = null;
  if (versionList.length >= 2) {
    const recentVersions = versionList.slice(-5);
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
    latestVersion,
    previousVersion,
    maintainers,
    latestPublisher,
    previousPublisher,
    maintainerChanged: latestPublisher !== null && previousPublisher !== null && latestPublisher !== previousPublisher,
    hasInstallScripts,
    installScripts,
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
