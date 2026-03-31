import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Parse Brewfile.lock.json into dependency list.
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  let data;
  try { data = JSON.parse(content); }
  catch (err) { throw new Error(`invalid JSON in ${filePath}: ${err.message}`); }

  const deps = [];
  const entries = data.entries || {};

  for (const [type, packages] of Object.entries(entries)) {
    if (type !== 'brew' && type !== 'cask') continue;
    for (const [name, info] of Object.entries(packages || {})) {
      deps.push({
        name,
        version: info.version || 'latest',
        ecosystem: 'brew',
        isDirect: true,
        brewType: type,
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse Brewfile (plain text) into dependency list.
 */
export function parseManifest(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // brew "package", cask "package", tap "org/repo"
    const match = trimmed.match(/^(brew|cask)\s+"([^"]+)"/);
    if (match) {
      deps.push({
        name: match[2],
        version: 'latest', // Brewfile doesn't pin versions
        ecosystem: 'brew',
        isDirect: true,
        brewType: match[1],
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Discover Homebrew dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'Brewfile.lock.json');
  const mfPath = join(dir, 'Brewfile');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(mfPath)) manifests.push(mfPath);

  return { lockfiles, manifests };
}
