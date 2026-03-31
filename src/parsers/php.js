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

  const deps = [];

  for (const [section, isDev] of [['packages', false], ['packages-dev', true]]) {
    const entries = data[section];
    if (!Array.isArray(entries)) continue;

    for (const entry of entries) {
      if (!entry.name || !entry.version) continue;

      // Strip leading "v" from version (e.g. "v1.2.3" -> "1.2.3")
      const version = entry.version.replace(/^v/, '');

      deps.push({
        name: entry.name,
        version,
        ecosystem: 'php',
        isDev,
        isDirect: false,
        isPinned: true,
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
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

  for (const [section, isDev] of [['require', false], ['require-dev', true]]) {
    const entries = data[section];
    if (!entries || typeof entries !== 'object') continue;

    for (const [name, spec] of Object.entries(entries)) {
      if (COMPOSER_PLATFORM_PACKAGES.has(name) || name.startsWith('ext-') || name.startsWith('lib-')) continue;
      if (typeof spec !== 'string') continue;

      const version = extractVersionFromSpec(spec);
      if (!version) continue;

      const dedupKey = `${name}@${version}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      deps.push({
        name,
        version,
        ecosystem: 'php',
        isDev,
        isDirect: true,
        isPinned: isPinnedVersionSpec(spec, version),
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
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
