import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

// Only accept concrete semver versions for OSV queries
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?$/;

/**
 * Parse an npm package-lock.json (v2 or v3) into a flat dependency list.
 *
 * @param {string} lockfilePath - Absolute path to package-lock.json
 * @returns {Array<{ name: string, version: string, ecosystem: string, isDev: boolean, isDirect: boolean }>}
 */
export function parseLockfile(lockfilePath) {
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
  const dir = join(lockfilePath, '..');
  const directDeps = readDirectDeps(dir);

  const packages = data.packages;
  if (packages) {
    for (const [key, entry] of Object.entries(packages)) {
      if (key === '') continue;
      if (!entry.version) continue;

      // Extract name after the last node_modules/ segment.
      // npm registry normalizes names to lowercase; do the same for consistent OSV queries.
      const rawName = key.split('node_modules/').pop();
      if (!rawName) continue;
      const name = rawName.toLowerCase();

      const dedupKey = `${name}@${entry.version}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      deps.push({
        name,
        version: entry.version,
        ecosystem: 'npm',
        isDev: entry.dev === true,
        isDirect: directDeps.has(name),
        ...(entry.integrity ? { integrity: entry.integrity } : {}),
      });
    }

    log.debug(`parsed ${deps.length} packages from ${lockfilePath} (lockfileVersion ${data.lockfileVersion})`);
    return deps;
  }

  // Fallback: v1 lockfile with nested `dependencies` tree
  if (data.dependencies) {
    walkDependencyTree(data.dependencies, deps, seen, directDeps);
    log.debug(`parsed ${deps.length} packages from ${lockfilePath} (legacy tree format)`);
    return deps;
  }

  log.warn(`no packages found in ${lockfilePath}`);
  return deps;
}

function walkDependencyTree(tree, deps, seen, directDeps) {
  for (const [name, entry] of Object.entries(tree)) {
    if (!entry.version) continue;

    const dedupKey = `${name}@${entry.version}`;
    if (!seen.has(dedupKey)) {
      seen.add(dedupKey);
      deps.push({
        name,
        version: entry.version,
        ecosystem: 'npm',
        isDev: entry.dev === true,
        isDirect: directDeps.has(name),
      });
    }

    if (entry.dependencies) {
      walkDependencyTree(entry.dependencies, deps, seen, directDeps);
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
      Object.keys(pkg.dependencies).forEach(n => names.add(n));
    }
    if (pkg.devDependencies && typeof pkg.devDependencies === 'object') {
      Object.keys(pkg.devDependencies).forEach(n => names.add(n));
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

      // Strip leading semver range operators to extract a concrete version
      const stripped = versionRange.replace(/^[\^~>=<\s]+/, '');
      if (!SEMVER_RE.test(stripped)) {
        log.debug(`skipping non-pinned dep: ${name}@${versionRange}`);
        continue;
      }

      deps.push({
        name,
        version: stripped,
        ecosystem: 'npm',
        isDev,
        isDirect: true,
        isRange: versionRange !== stripped,
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
