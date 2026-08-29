import { PYPI_JSON_URL } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

/**
 * Fetch package metadata from the PyPI JSON API.
 *
 * ALWAYS fetches the unversioned endpoint: only that one returns the
 * `releases` map, and without it every publish-history signal
 * (previousVersion, publish timing, package age, dormancy) is null. The
 * versioned endpoint — used here before this fix — silently returned none
 * of that, leaving PyPI analysis running on one layer instead of four.
 * `version` is used to ANCHOR the analysis, mirroring npm-registry.js.
 *
 * PyPI API limitations (documented, not bugs): there is no per-release
 * publisher, so `maintainerChanged` is structurally unavailable (npm-only),
 * and install-script detection comes from tarball inspection (--deep), not
 * metadata.
 *
 * @param {string} packageName
 * @param {string} [version] — installed version to anchor the analysis to
 * @returns {Promise<PypiMetadata|null>}
 */
export async function fetchPypiMetadata(packageName, version) {
  const normalized = packageName.toLowerCase().replace(/[._]/g, '-');
  const url = `${PYPI_JSON_URL}/${encodeURIComponent(normalized)}/json`;

  try {
    const data = await fetchJSON(url);
    return normalizeMetadata(data, packageName, version);
  } catch (err) {
    log.debug(`PyPI fetch failed for ${packageName}: ${err.message}`);
    return null;
  }
}

// Exported for tests: PyPI signal fields must be verifiable against saved
// API fixtures without network access.
export function normalizeMetadata(data, packageName, requestedVersion) {
  const info = data.info || {};
  const releases = data.releases || {};
  const vulnerabilities = data.vulnerabilities || [];

  // Get sorted version list by upload time
  const versionList = Object.keys(releases)
    .filter(v => releases[v]?.length > 0)
    .sort((a, b) => {
      const aTime = releases[a][0]?.upload_time_iso_8601 || '';
      const bTime = releases[b][0]?.upload_time_iso_8601 || '';
      return aTime.localeCompare(bTime);
    });

  const latestAvailable = info.version || versionList[versionList.length - 1];

  // An exact request is an evidence boundary. If PyPI's release history does
  // not contain it, preserve the requested value and mark the result
  // incomplete; silently analyzing the current latest would describe a
  // different artifact from the one in the user's dependency file.
  const versionWasRequested = requestedVersion != null && String(requestedVersion).trim() !== '';
  const requestedVersionFound = versionWasRequested
    ? releases[requestedVersion]?.length > 0
    : null;
  const anchoredToInstalled = versionWasRequested && requestedVersionFound === true;
  const latestVersion = versionWasRequested ? requestedVersion : latestAvailable;
  const anchorIdx = requestedVersionFound === false ? -1 : versionList.indexOf(latestVersion);
  const metadataComplete = requestedVersionFound !== false && !!latestVersion && anchorIdx >= 0;
  const anchorError = requestedVersionFound === false
    ? `requested version ${packageName}@${requestedVersion} is absent from PyPI release metadata`
    : (!metadataComplete ? `PyPI metadata has no release artifact for ${packageName}@${latestVersion || 'unknown'}` : null);

  const previousVersion = anchorIdx > 0 ? versionList[anchorIdx - 1] : null;

  // Author / maintainer info
  const author = info.author || null;
  const authorEmail = info.author_email || null;
  const maintainer = info.maintainer || null;
  const maintainerEmail = info.maintainer_email || null;

  // Publish timestamps
  const latestRelease = metadataComplete ? releases[latestVersion] : null;
  const latestPublishTime = latestRelease?.[0]?.upload_time_iso_8601
    ? new Date(latestRelease[0].upload_time_iso_8601) : null;

  const prevRelease = previousVersion ? releases[previousVersion] : null;
  const previousPublishTime = prevRelease?.[0]?.upload_time_iso_8601
    ? new Date(prevRelease[0].upload_time_iso_8601) : null;

  let publishIntervalMs = null;
  if (latestPublishTime && previousPublishTime) {
    publishIntervalMs = latestPublishTime - previousPublishTime;
  }

  // Package age
  const firstVersion = versionList[0];
  const firstRelease = firstVersion ? releases[firstVersion] : null;
  const created = firstRelease?.[0]?.upload_time_iso_8601
    ? new Date(firstRelease[0].upload_time_iso_8601) : null;
  const packageAgeMs = created ? (Date.now() - created) : null;

  // Version jump between the previous release and the anchor
  let majorJump = 0;
  if (previousVersion && latestVersion) {
    const prevMajor = parseInt(previousVersion.split('.')[0], 10) || 0;
    const currMajor = parseInt(latestVersion.split('.')[0], 10) || 0;
    majorJump = currMajor - prevMajor;
  }

  // Dormancy: max gap between consecutive releases in the 5 up to the anchor
  // — detects packages with a long release gap followed by new activity.
  let dormancyMs = null;
  const historyUpToAnchor = anchorIdx >= 0 ? versionList.slice(0, anchorIdx + 1) : [];
  if (historyUpToAnchor.length >= 2) {
    const recentVersions = historyUpToAnchor.slice(-5);
    for (let i = 1; i < recentVersions.length; i++) {
      const prev = new Date(recentVersions[i - 1] ? releases[recentVersions[i - 1]][0]?.upload_time_iso_8601 : 0);
      const curr = new Date(recentVersions[i] ? releases[recentVersions[i]][0]?.upload_time_iso_8601 : 0);
      const gap = curr - prev;
      if (gap > 0 && (dormancyMs === null || gap > dormancyMs)) {
        dormancyMs = gap;
      }
    }
  }

  // Dependencies (requires_dist)
  const dependencies = (info.requires_dist || []).map(dep => {
    // Parse "package-name (>=1.0)" format
    const match = dep.match(/^([a-zA-Z0-9._-]+)/);
    return match ? match[1].toLowerCase().replace(/[._]/g, '-') : dep;
  });

  // Yanked versions
  const yankedVersions = versionList.filter(v => {
    return releases[v]?.some(file => file.yanked);
  });

  // Repository URL
  const projectUrls = info.project_urls || {};
  const repository = projectUrls.Source || projectUrls.Repository || projectUrls.Homepage
    || info.home_page || null;

  // Known vulnerabilities from PyPI itself
  const knownVulns = vulnerabilities.map(v => ({
    id: v.id,
    aliases: v.aliases || [],
    summary: v.summary || v.details || '',
    fixedIn: v.fixed_in || [],
    withdrawn: v.withdrawn || null,
  }));

  return {
    name: packageName,
    latestVersion,       // the analyzed (anchor) version — installed when known
    latestAvailable,     // newest release on PyPI
    requestedVersion: versionWasRequested ? requestedVersion : null,
    requestedVersionFound,
    anchoredToInstalled,
    metadataComplete,
    anchorError,
    previousVersion,
    author,
    authorEmail,
    maintainer,
    maintainerEmail,
    latestPublishTime,
    previousPublishTime,
    publishIntervalMs,
    packageAgeMs,
    majorJump,
    dormancyMs,
    dependencies,
    versionCount: versionList.length,
    yankedVersions,
    repository,
    license: info.license || null,
    knownVulns,
    requiresPython: info.requires_python || null,
    // Structurally unavailable on PyPI (no per-release publisher in the JSON
    // API): maintainerChanged. Install scripts come from --deep tarball
    // inspection, not metadata. Deliberately NOT faked here.
  };
}
