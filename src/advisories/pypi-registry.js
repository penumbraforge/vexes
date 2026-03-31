import { PYPI_JSON_URL } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

/**
 * Fetch package metadata from the PyPI JSON API.
 *
 * @param {string} packageName
 * @param {string} [version] — specific version, or omit for latest
 * @returns {Promise<PypiMetadata|null>}
 */
export async function fetchPypiMetadata(packageName, version) {
  const normalized = packageName.toLowerCase().replace(/[._]/g, '-');
  const url = version
    ? `${PYPI_JSON_URL}/${encodeURIComponent(normalized)}/${encodeURIComponent(version)}/json`
    : `${PYPI_JSON_URL}/${encodeURIComponent(normalized)}/json`;

  try {
    const data = await fetchJSON(url);
    return normalizeMetadata(data, packageName, version);
  } catch (err) {
    log.debug(`PyPI fetch failed for ${packageName}: ${err.message}`);
    return null;
  }
}

function normalizeMetadata(data, packageName, requestedVersion) {
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

  const latestVersion = info.version || versionList[versionList.length - 1];
  const previousVersion = versionList.length >= 2
    ? versionList[versionList.indexOf(latestVersion) - 1] || versionList[versionList.length - 2]
    : null;

  // Author / maintainer info
  const author = info.author || null;
  const authorEmail = info.author_email || null;
  const maintainer = info.maintainer || null;
  const maintainerEmail = info.maintainer_email || null;

  // Publish timestamps
  const latestRelease = releases[latestVersion];
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
    latestVersion,
    previousVersion,
    author,
    authorEmail,
    maintainer,
    maintainerEmail,
    latestPublishTime,
    previousPublishTime,
    publishIntervalMs,
    packageAgeMs,
    dependencies,
    versionCount: versionList.length,
    yankedVersions,
    repository,
    license: info.license || null,
    knownVulns,
    requiresPython: info.requires_python || null,
  };
}
