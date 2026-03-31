const VERSION_TOKEN_RE = /v?\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.+-]+)?/;

/**
 * Extract a concrete version token from a loose manifest spec.
 * Used for best-effort manifest fallbacks when a lockfile is unavailable.
 */
export function extractVersionFromSpec(spec) {
  if (typeof spec !== 'string') return null;

  const normalized = spec
    .trim()
    .replace(/^['"]|['"]$/g, '')
    .replace(/^[\[\]()~^<>=\s]+/, '')
    .split(',')[0]
    .trim();

  const match = normalized.match(VERSION_TOKEN_RE);
  return match ? match[0].replace(/^v(?=\d)/, '') : null;
}

/**
 * Check whether a manifest spec is pinned to exactly one version.
 */
export function isPinnedVersionSpec(spec, version) {
  if (typeof spec !== 'string' || !version) return false;
  const trimmed = spec.trim();
  return trimmed === version ||
    trimmed === `=${version}` ||
    trimmed === `==${version}` ||
    trimmed === `[${version}]` ||
    trimmed === `"${version}"` ||
    trimmed === `'${version}'`;
}
