import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Parse Cargo.lock into dependency list.
 * Cargo.lock uses TOML with [[package]] sections — same pattern as poetry.lock.
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  let current = null;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    if (trimmed === '[[package]]') {
      if (current?.name && current?.version) {
        deps.push({
          name: current.name,
          version: current.version,
          ecosystem: 'cargo',
          isDirect: false, // Cargo.lock includes all transitive
          isPinned: true,
        });
      }
      current = {};
      continue;
    }

    if (current) {
      const m = trimmed.match(/^(name|version)\s*=\s*"(.+?)"/);
      if (m) current[m[1]] = m[2];
    }
  }

  // Last entry
  if (current?.name && current?.version) {
    deps.push({
      name: current.name,
      version: current.version,
      ecosystem: 'cargo',
      isDirect: false,
      isPinned: true,
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Discover Cargo dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'Cargo.lock');
  const tomlPath = join(dir, 'Cargo.toml');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(tomlPath)) manifests.push(tomlPath);

  return { lockfiles, manifests };
}
