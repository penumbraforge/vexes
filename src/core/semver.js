/**
 * Minimal semver comparison — zero dependencies.
 *
 * Compares major.minor.patch numerically and applies SemVer pre-release
 * precedence. Build metadata is ignored. Leading range operators are accepted
 * for the few call sites that compare manifest constraints.
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
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    const diff = pa.core[i] - pb.core[i];
    if (diff !== 0) return diff;
  }

  // A release outranks any pre-release with the same numeric core.
  if (pa.prerelease.length === 0 && pb.prerelease.length > 0) return 1;
  if (pb.prerelease.length === 0 && pa.prerelease.length > 0) return -1;

  const count = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < count; i++) {
    const left = pa.prerelease[i];
    const right = pb.prerelease[i];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    if (left === right) continue;
    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric) return Number(left) - Number(right);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return left < right ? -1 : 1;
  }
  return 0;
}

/**
 * Extract [major, minor, patch] as numbers from a version-ish string.
 * Strips a leading range operator (>=, >, ~, ^, =, v) and any pre-release
 * or build suffix. Missing/non-numeric components become 0.
 */
function parseVersion(version) {
  const normalized = String(version)
    .trim()
    .replace(/^[>=<~^v\s]+/, '')
    .split('+')[0];
  const dash = normalized.indexOf('-');
  const coreText = dash === -1 ? normalized : normalized.slice(0, dash);
  const prerelease = dash === -1 ? [] : normalized.slice(dash + 1).split('.');
  const core = coreText.split('.').slice(0, 3).map(n => {
    const parsed = parseInt(n, 10);
    return Number.isNaN(parsed) ? 0 : parsed;
  });
  while (core.length < 3) core.push(0);
  return { core, prerelease };
}
