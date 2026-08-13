/**
 * Suppression filter for the documented `ignore` config key.
 *
 * Each ignore entry is a string in one of three forms:
 *   - an advisory ID   — "GHSA-xxxx-yyyy-zzzz", "CVE-2021-1234", "PYSEC-..."
 *   - a package name    — "lodash", "@scope/name"
 *   - a pinned package  — "lodash@4.17.21", "@scope/name@1.2.3"
 *
 * Bare entries (no version) match either an advisory ID or a package name —
 * package names are never advisory-ID-shaped, so a single set covers both with
 * no realistic collision. Versioned entries match "pkg@version" exactly.
 */

/**
 * @param {string[]} ignoreList
 * @returns {{ bare: Set<string>, pkgVersion: Set<string>, active: boolean }}
 */
export function buildIgnoreMatcher(ignoreList) {
  const bare = new Set();
  const pkgVersion = new Set();

  for (const raw of ignoreList || []) {
    if (typeof raw !== 'string') continue;
    const entry = raw.trim();
    if (!entry) continue;

    // lastIndexOf('@') > 0 distinguishes "pkg@version" (and scoped
    // "@scope/name@version") from a bare "@scope/name" whose only @ is at 0.
    const at = entry.lastIndexOf('@');
    if (at > 0) pkgVersion.add(entry);
    else bare.add(entry);
  }

  return { bare, pkgVersion, active: bare.size + pkgVersion.size > 0 };
}

/**
 * @param {ReturnType<typeof buildIgnoreMatcher>} matcher
 * @param {{ pkg?: string, version?: string, ids?: string[] }} subject
 * @returns {boolean}
 */
export function isIgnored(matcher, { pkg, version, ids = [] } = {}) {
  if (!matcher?.active) return false;
  if (pkg && version && matcher.pkgVersion.has(`${pkg}@${version}`)) return true;
  if (pkg && matcher.bare.has(pkg)) return true;
  for (const id of ids) {
    if (id && matcher.bare.has(id)) return true;
  }
  return false;
}

/**
 * Split a list into kept vs suppressed by the ignore config.
 *
 * @template T
 * @param {T[]} items
 * @param {string[]} ignoreList
 * @param {(item: T) => { pkg?: string, version?: string, ids?: string[] }} accessor
 * @returns {{ kept: T[], suppressed: T[] }}
 */
export function partitionByIgnore(items, ignoreList, accessor) {
  const matcher = buildIgnoreMatcher(ignoreList);
  if (!matcher.active) return { kept: items, suppressed: [] };

  const kept = [];
  const suppressed = [];
  for (const item of items) {
    if (isIgnored(matcher, accessor(item))) suppressed.push(item);
    else kept.push(item);
  }
  return { kept, suppressed };
}
