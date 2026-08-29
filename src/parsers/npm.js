import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

// Only accept concrete semver versions for OSV queries
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?$/;
const NPM_NAME_RE = /^(?:@[a-z0-9._~-]+\/[a-z0-9._~-]+|[a-z0-9][a-z0-9._~-]*)$/i;

/**
 * Parse an npm package-lock.json (v2 or v3) into a flat dependency list.
 *
 * @param {string} lockfilePath - Absolute path to package-lock.json
 * @param {{ preserveOccurrences?: boolean }} [options]
 * @returns {Array<{ name: string, version: string, ecosystem: string, isDev: boolean, isDirect: boolean }>}
 */
export function parseLockfile(lockfilePath, { preserveOccurrences = false } = {}) {
  let raw;
  try {
    raw = readFileSync(lockfilePath, 'utf8');
  } catch (err) {
    throw new Error(`cannot read ${lockfilePath}: ${err.code || err.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`invalid JSON in ${lockfilePath}: ${err.message}`);
  }

  const deps = [];
  const seen = new Set();
  let unresolvedEntries = 0;
  const dir = join(lockfilePath, '..');
  const directDeps = readDirectDeps(dir);

  const packages = data.packages;
  if (packages !== undefined) {
    if (!packages || typeof packages !== 'object' || Array.isArray(packages)) {
      throw new Error(`invalid package-lock schema in ${lockfilePath}: "packages" must be an object`);
    }
    if (!Object.prototype.hasOwnProperty.call(packages, '')) {
      throw new Error(`invalid package-lock schema in ${lockfilePath}: package root entry "" is missing`);
    }
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '') continue;
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        unresolvedEntries++;
        continue;
      }

      // `entry.name` is the artifact identity for npm aliases. Falling back to
      // the install folder would query `safe-alias@1.0.0` instead of the real
      // registry artifact named by `npm:real-package@1.0.0`.
      const folderName = key.includes('node_modules/') ? key.split('node_modules/').pop() : null;
      const rawName = typeof entry.name === 'string' && entry.name ? entry.name : folderName;
      const name = rawName?.toLowerCase();
      const sourceType = npmSourceType(entry, key, name, entry.version);
      const coordinateValid = SEMVER_RE.test(entry.version || '') && !!name && NPM_NAME_RE.test(name);
      const sourceAnchored = sourceType === 'registry' &&
        typeof entry.resolved === 'string' && entry.resolved.length > 0;
      const isTopLevelOccurrence = !!folderName && key === `node_modules/${folderName}`;

      if (!coordinateValid || !sourceAnchored) unresolvedEntries++;
      if ((!coordinateValid || !sourceAnchored) && !preserveOccurrences) continue;

      const dedupKey = preserveOccurrences ? key : `${name}@${entry.version}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      deps.push({
        name: name || folderName || key,
        version: entry.version || null,
        ecosystem: 'npm',
        isDev: entry.dev === true,
        isDirect: isTopLevelOccurrence && (directDeps.has(name) || directDeps.has(folderName)),
        ...(preserveOccurrences ? { occurrence: key } : {}),
        ...(entry.resolved ? { resolved: entry.resolved } : {}),
        ...(entry.integrity ? { integrity: entry.integrity } : {}),
        sourceType,
      });
    }

    log.debug(`parsed ${deps.length} packages from ${lockfilePath} (lockfileVersion ${data.lockfileVersion})`);
    attachParserStatus(deps, () => unresolvedEntries);
    return deps;
  }

  // Fallback: v1 lockfile with nested `dependencies` tree
  if (data.dependencies !== undefined) {
    if (!data.dependencies || typeof data.dependencies !== 'object' || Array.isArray(data.dependencies)) {
      throw new Error(`invalid package-lock schema in ${lockfilePath}: "dependencies" must be an object`);
    }
    if (preserveOccurrences) {
      throw new Error(`legacy package-lock dependency trees cannot preserve occurrence identity for guard`);
    }
    const state = { unresolvedEntries: 0 };
    walkDependencyTree(data.dependencies, deps, seen, directDeps, state);
    log.debug(`parsed ${deps.length} packages from ${lockfilePath} (legacy tree format)`);
    attachParserStatus(deps, () => state.unresolvedEntries);
    return deps;
  }

  throw new Error(`invalid package-lock schema in ${lockfilePath}: no recognized dependency graph`);
}

function npmSourceType(entry, key, name, version) {
  if (entry.link === true || (!key.includes('node_modules/') && key !== '')) return 'link';
  const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
  if (!resolved) return 'unknown';
  if (/^(?:file:|\.\.?[/\\]|[/\\])/.test(resolved)) return 'file';
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:)/i.test(resolved)) return 'git';
  return isCanonicalNpmTarball(resolved, name, version) ? 'registry' : 'remote';
}

/** Bind a public-registry URL to the exact artifact identity being queried. */
export function isCanonicalNpmTarball(
  resolved,
  name,
  version,
  { hosts = new Set(['registry.npmjs.org']) } = {},
) {
  if (typeof resolved !== 'string' || !NPM_NAME_RE.test(name || '') || !SEMVER_RE.test(version || '')) return false;
  try {
    const url = new URL(resolved);
    if (url.protocol !== 'https:' || !hosts.has(url.hostname) ||
        url.port || url.username || url.password || url.search) return false;
    const decodedPath = decodeURIComponent(url.pathname);
    const tarballName = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name;
    return decodedPath === `/${name}/-/${tarballName}-${version}.tgz`;
  } catch {
    return false;
  }
}

function attachParserStatus(deps, readUnresolved) {
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    get: readUnresolved,
  });
}

function walkDependencyTree(tree, deps, seen, directDeps, state) {
  for (const [name, entry] of Object.entries(tree)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      state.unresolvedEntries++;
      continue;
    }
    const sourceType = npmSourceType(entry, `node_modules/${name}`, name, entry.version);
    const coordinateValid = NPM_NAME_RE.test(name) && SEMVER_RE.test(entry.version || '');
    const sourceAnchored = sourceType === 'registry' &&
      typeof entry.resolved === 'string' && entry.resolved.length > 0;
    if (!coordinateValid || !sourceAnchored) state.unresolvedEntries++;

    const dedupKey = `${name}@${entry.version}`;
    if (coordinateValid && sourceAnchored && !seen.has(dedupKey)) {
      seen.add(dedupKey);
      deps.push({
        name,
        version: entry.version,
        ecosystem: 'npm',
        isDev: entry.dev === true,
        isDirect: directDeps.has(name),
        resolved: entry.resolved,
        ...(entry.integrity ? { integrity: entry.integrity } : {}),
        sourceType,
      });
    }

    if (entry.dependencies && typeof entry.dependencies === 'object' && !Array.isArray(entry.dependencies)) {
      walkDependencyTree(entry.dependencies, deps, seen, directDeps, state);
    }
  }
}

/**
 * Read direct deps from package.json. Logs a warning if parsing fails
 * rather than silently returning empty.
 */
function readDirectDeps(dir) {
  const pkgPath = join(dir, 'package.json');
  const names = new Set();
  if (!existsSync(pkgPath)) return names;

  try {
    const raw = readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(raw);
    if (pkg.dependencies && typeof pkg.dependencies === 'object') {
      Object.keys(pkg.dependencies).forEach(n => names.add(n.toLowerCase()));
    }
    if (pkg.devDependencies && typeof pkg.devDependencies === 'object') {
      Object.keys(pkg.devDependencies).forEach(n => names.add(n.toLowerCase()));
    }
  } catch (err) {
    log.warn(`could not read package.json for direct dep identification: ${err.message}`);
  }

  return names;
}

/**
 * Parse a bare package.json (no lockfile) — lower confidence since versions are ranges.
 * Skips entries that are not concrete semver versions (workspace:, file:, git+, etc.).
 */
export function parseManifest(pkgPath) {
  let raw;
  try {
    raw = readFileSync(pkgPath, 'utf8');
  } catch (err) {
    throw new Error(`cannot read ${pkgPath}: ${err.code || err.message}`);
  }

  let pkg;
  try {
    pkg = JSON.parse(raw);
  } catch (err) {
    throw new Error(`invalid JSON in ${pkgPath}: ${err.message}`);
  }

  const deps = [];

  for (const [section, isDev] of [['dependencies', false], ['devDependencies', true], ['optionalDependencies', false], ['peerDependencies', false]]) {
    const entries = pkg[section];
    if (!entries || typeof entries !== 'object') continue;

    for (const [name, versionRange] of Object.entries(entries)) {
      if (typeof versionRange !== 'string') continue;

      // Skip non-registry specifiers
      if (versionRange.startsWith('file:') ||
          versionRange.startsWith('git') ||
          versionRange.startsWith('http') ||
          versionRange.startsWith('workspace:') ||
          versionRange.startsWith('npm:') ||
          versionRange.startsWith('link:')) {
        log.debug(`skipping non-registry dep: ${name}@${versionRange}`);
        continue;
      }

      // A manifest range is not an installed version. Sending its lower bound
      // to OSV creates both false positives and false negatives, so fallback
      // scanning accepts only an explicitly pinned version. Lockfiles remain
      // the authoritative source for resolved dependency versions.
      if (!SEMVER_RE.test(versionRange)) {
        log.debug(`skipping unresolved manifest dep: ${name}@${versionRange}`);
        continue;
      }

      deps.push({
        name,
        version: versionRange,
        ecosystem: 'npm',
        isDev,
        isDirect: true,
        isRange: false,
        sourceType: 'registry',
      });
    }
  }

  log.debug(`parsed ${deps.length} direct deps from ${pkgPath} (no lockfile, lower confidence)`);
  return deps;
}

/**
 * Discover npm dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'package-lock.json');
  const pkgPath = join(dir, 'package.json');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(pkgPath)) manifests.push(pkgPath);

  return { lockfiles, manifests };
}
