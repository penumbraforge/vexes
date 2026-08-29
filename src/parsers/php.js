import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { extractVersionFromSpec, isPinnedVersionSpec } from './version-spec.js';

const COMPOSER_PLATFORM_PACKAGES = new Set([
  'php',
  'hhvm',
  'composer-plugin-api',
  'composer-runtime-api',
  'composer-api',
]);
const COMPOSER_NAME_RE = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i;
const COMPOSER_VERSION_RE = /^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/;
const PUBLIC_PACKAGIST_NOTIFICATIONS = new Set([
  'https://packagist.org/downloads',
]);

/**
 * Parse composer.lock into dependency list.
 *
 * composer.lock is JSON with:
 *   "packages": [{ "name": "vendor/pkg", "version": "v1.2.3" }, ...]
 *   "packages-dev": [{ "name": "vendor/dev-pkg", "version": "v2.0.0" }, ...]
 *
 * Leading "v" is stripped from version strings.
 */
export function parseLockfile(filePath) {
  let raw;
  try { raw = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  let data;
  try { data = JSON.parse(raw); }
  catch (err) { throw new Error(`invalid JSON in ${filePath}: ${err.message}`); }

  if (!Object.prototype.hasOwnProperty.call(data, 'packages') &&
      !Object.prototype.hasOwnProperty.call(data, 'packages-dev')) {
    throw new Error(`invalid composer.lock schema in ${filePath}: packages arrays are missing`);
  }
  for (const section of ['packages', 'packages-dev']) {
    if (data[section] !== undefined && !Array.isArray(data[section])) {
      throw new Error(`invalid composer.lock schema in ${filePath}: ${section} must be an array`);
    }
  }

  const deps = [];
  let unresolvedEntries = 0;

  for (const [section, isDev] of [['packages', false], ['packages-dev', true]]) {
    const entries = data[section];
    if (!Array.isArray(entries)) continue;

    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
          !COMPOSER_NAME_RE.test(entry.name || '')) {
        unresolvedEntries++;
        continue;
      }

      // Strip leading "v" from version (e.g. "v1.2.3" -> "1.2.3")
      const version = typeof entry.version === 'string' ? entry.version.replace(/^v/, '') : '';
      if (!COMPOSER_VERSION_RE.test(version) || !isPublicPackagistEntry(entry)) {
        unresolvedEntries++;
        continue;
      }

      deps.push({
        name: entry.name,
        version,
        ecosystem: 'php',
        isDev,
        isDirect: false,
        isPinned: true,
        sourceType: 'registry',
      });
      // notification-url is package-controlled lock metadata, not proof that
      // these bytes originated at Packagist. Keep the advisory coordinate but
      // never call lockfile-only source coverage complete.
      unresolvedEntries++;
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachParserStatus(deps, unresolvedEntries);
  return deps;
}

function isPublicPackagistEntry(entry) {
  const notification = typeof entry['notification-url'] === 'string'
    ? entry['notification-url'].replace(/\/$/, '')
    : '';
  if (!PUBLIC_PACKAGIST_NOTIFICATIONS.has(notification)) return false;

  const sourceType = String(entry.source?.type || '').toLowerCase();
  const distType = String(entry.dist?.type || '').toLowerCase();
  const distUrl = String(entry.dist?.url || '');
  if (sourceType === 'path' || distType === 'path' || distType === 'file') return false;
  if (/^(?:file:|\.\.?[/\\]|[/\\])/.test(distUrl)) return false;
  return true;
}

/**
 * Parse composer.json into direct dependency specs.
 */
export function parseManifest(filePath) {
  let raw;
  try { raw = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  let data;
  try { data = JSON.parse(raw); }
  catch (err) { throw new Error(`invalid JSON in ${filePath}: ${err.message}`); }

  const deps = [];
  const seen = new Set();
  let unresolvedEntries = 0;
  const customRepositories = hasCustomComposerRepositories(data.repositories);

  for (const [section, isDev] of [['require', false], ['require-dev', true]]) {
    const entries = data[section];
    if (!entries || typeof entries !== 'object') continue;

    for (const [name, spec] of Object.entries(entries)) {
      if (COMPOSER_PLATFORM_PACKAGES.has(name) || name.startsWith('ext-') || name.startsWith('lib-')) continue;
      if (typeof spec !== 'string' || !COMPOSER_NAME_RE.test(name) || customRepositories) {
        unresolvedEntries++;
        continue;
      }

      const version = extractVersionFromSpec(spec);
      // Composer constraints do not identify the installed artifact. Only an
      // exact pin is safe to submit as a concrete OSV version.
      if (!version || !isPinnedVersionSpec(spec, version) || !COMPOSER_VERSION_RE.test(version.replace(/^v/, ''))) {
        unresolvedEntries++;
        continue;
      }

      const dedupKey = `${name}@${version}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      deps.push({
        name,
        version,
        ecosystem: 'php',
        isDev,
        isDirect: true,
        isPinned: true,
        sourceType: 'registry',
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachParserStatus(deps, unresolvedEntries);
  return deps;
}

function hasCustomComposerRepositories(repositories) {
  if (repositories === undefined || repositories === null) return false;
  const entries = Array.isArray(repositories)
    ? repositories
    : typeof repositories === 'object'
      ? Object.entries(repositories).map(([name, value]) => ({ name, value }))
      : [repositories];
  if (entries.length === 0) return false;

  return entries.some(entry => {
    if (entry && typeof entry === 'object' && 'name' in entry) {
      if (entry.name === 'packagist.org' && entry.value === false) return true;
      entry = entry.value;
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return true;
    const type = String(entry.type || '').toLowerCase();
    const url = String(entry.url || '').replace(/\/$/, '');
    return type !== 'composer' || url !== 'https://repo.packagist.org';
  });
}

function attachParserStatus(deps, unresolvedEntries) {
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    value: unresolvedEntries,
  });
}

/**
 * Discover PHP/Composer dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'composer.lock');
  const jsonPath = join(dir, 'composer.json');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(jsonPath)) manifests.push(jsonPath);

  return { lockfiles, manifests };
}
