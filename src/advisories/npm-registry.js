import { NPM_REGISTRY_URL, NPM_ATTESTATIONS_URL } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

// npm's package metadata contains several script families with materially
// different trust boundaries.  A registry tarball can execute only the
// dependency install hooks below when consumed normally.  `prepare` can run
// for git/file/link installs, while publish/pack hooks run on the producer's
// machine.  Treating all of them as "postinstall" made harmless release
// automation look like consumer-side code execution.
export const REGISTRY_INSTALL_HOOKS = Object.freeze([
  'preinstall', 'install', 'postinstall',
]);
export const NON_REGISTRY_INSTALL_HOOKS = Object.freeze([
  'prepare',
]);
export const PROJECT_LIFECYCLE_HOOKS = Object.freeze([
  'prepublish', 'preprepare', 'postprepare', 'dependencies',
]);
export const PUBLISH_PACK_HOOKS = Object.freeze([
  'prepublishOnly', 'prepack', 'postpack', 'publish', 'postpublish',
]);

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

  // When a caller requests an exact version, NEVER substitute dist-tags.latest.
  // A guard that asked about x@1.2.3 must not silently approve x@9.0.0's
  // metadata.  Keep latestAvailable for display, but make the missing anchor
  // explicit and leave all signal-feeding version data empty/fail-closed.
  const versionWasRequested = requestedVersion !== null;
  const requestedVersionFound = versionWasRequested
    ? Object.hasOwn(versions, requestedVersion)
    : null;
  const anchoredToInstalled = versionWasRequested && requestedVersionFound === true;
  const latestVersion = versionWasRequested ? requestedVersion : latestAvailable;
  const anchorIdx = requestedVersionFound === false ? -1 : versionList.indexOf(latestVersion);
  const latestData = requestedVersionFound === false ? {} : (versions[latestVersion] || {});
  const metadataComplete = requestedVersionFound !== false && !!latestVersion && !!versions[latestVersion];
  const anchorError = requestedVersionFound === false
    ? `requested npm version ${packageName}@${requestedVersion} is absent from the registry packument`
    : null;
  const previousVersion = anchorIdx > 0 ? versionList[anchorIdx - 1] : null;
  const previousData = previousVersion ? versions[previousVersion] : null;

  // Extract maintainer info
  const maintainers = (data.maintainers || []).map(m => ({
    name: m.name || m.username,
    email: m.email,
  }));

  // Who published the latest version vs previous
  const latestPublisher = latestData._npmUser?.name || latestData._npmUser?.email || null;
  const previousPublisher = previousData?._npmUser?.name || previousData?._npmUser?.email || null;

  // Separate consumer install hooks from producer/local lifecycle hooks.  Only
  // REGISTRY_INSTALL_HOOKS execute when this published registry artifact is
  // installed as a normal dependency.
  const scripts = latestData.scripts || {};
  const pickScripts = (hooks, source = scripts) => Object.fromEntries(
    hooks.filter(hook => source[hook]).map(hook => [hook, source[hook]])
  );
  const installScripts = pickScripts(REGISTRY_INSTALL_HOOKS);
  const nonRegistryInstallScripts = pickScripts(NON_REGISTRY_INSTALL_HOOKS);
  const projectLifecycleScripts = pickScripts(PROJECT_LIFECYCLE_HOOKS);
  const publishScripts = pickScripts(PUBLISH_PACK_HOOKS);
  const hasInstallScripts = Object.keys(installScripts).length > 0;

  // Previous version's lifecycle scripts — lets behavioral analysis run a
  // REAL capability diff instead of assuming the previous version was clean.
  // null = previous version unknown (no diff possible); {} = previous version
  // known to have no lifecycle scripts (a meaningful, diffable fact).
  let previousInstallScripts = null;
  let previousNonRegistryInstallScripts = null;
  let previousPublishScripts = null;
  if (previousData) {
    const prevScripts = previousData.scripts || {};
    previousInstallScripts = pickScripts(REGISTRY_INSTALL_HOOKS, prevScripts);
    previousNonRegistryInstallScripts = pickScripts(NON_REGISTRY_INSTALL_HOOKS, prevScripts);
    previousPublishScripts = pickScripts(PUBLISH_PACK_HOOKS, prevScripts);
  }

  // Exact artifact identity used by guard/preflight.  Expose both a grouped
  // object and stable top-level fields for simple callers.
  const artifact = {
    tarball: latestData.dist?.tarball || null,
    integrity: latestData.dist?.integrity || null,
    shasum: latestData.dist?.shasum || null,
  };

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
  // A missing exact target has no trustworthy version history anchor.  Do not
  // derive dormancy or release-gap facts from whatever happens to be latest.
  const historyUpToAnchor = requestedVersionFound === false
    ? []
    : (anchorIdx >= 0 ? versionList.slice(0, anchorIdx + 1) : versionList);
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
    latestVersion,       // analyzed target; exact requested value is never replaced
    latestAvailable,     // dist-tags.latest, for outdated-version signals
    requestedVersion,
    requestedVersionFound,
    anchoredToInstalled,
    metadataComplete,
    anchorError,
    previousVersion,
    maintainers,
    latestPublisher,
    previousPublisher,
    maintainerChanged: latestPublisher !== null && previousPublisher !== null && latestPublisher !== previousPublisher,
    hasInstallScripts,
    installScripts,
    hasNonRegistryInstallScripts: Object.keys(nonRegistryInstallScripts).length > 0,
    nonRegistryInstallScripts,
    projectLifecycleScripts,
    hasPublishScripts: Object.keys(publishScripts).length > 0,
    publishScripts,
    previousInstallScripts,
    previousNonRegistryInstallScripts,
    previousPublishScripts,
    scripts,
    artifact,
    tarball: artifact.tarball,
    integrity: artifact.integrity,
    shasum: artifact.shasum,
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
