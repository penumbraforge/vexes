/**
 * Minimal semver comparison — zero dependencies.
 *
 * Compares major.minor.patch numerically. Pre-release/build metadata and any
 * leading range operators are stripped before comparison, so `>= 1.2.3`,
 * `1.2.3`, and `1.2.3-rc.1` all compare on their numeric core.
 *
 * Returns a negative number if a < b, positive if a > b, 0 if equal — suitable
 * as an Array#sort comparator.
 *
 * This exists so string comparison never sneaks back in: `'9.0.0' > '10.0.0'`
 * is true lexicographically but wrong. Both scan's fix-command version pick and
 * fix's candidate ranking route through here.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareSemver(a, b) {
  const pa = parseCore(a);
  const pb = parseCore(b);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Extract [major, minor, patch] as numbers from a version-ish string.
 * Strips a leading range operator (>=, >, ~, ^, =, v) and any pre-release
 * or build suffix. Missing/non-numeric components become 0.
 */
function parseCore(version) {
  const core = String(version)
    .trim()
    .replace(/^[>=<~^v\s]+/, '')   // leading range operators / v-prefix
    .split(/[-+]/)[0];              // drop pre-release / build metadata
  return core.split('.').map(n => {
    const parsed = parseInt(n, 10);
    return Number.isNaN(parsed) ? 0 : parsed;
  });
}
