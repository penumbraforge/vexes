import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Detect whether a yarn.lock file uses the Berry (v2+) format.
 * Berry lockfiles start with a `__metadata:` block.
 */
function isBerryFormat(content) {
  return /^__metadata:\s*$/m.test(content);
}

/**
 * Extract the package name from a yarn v1 header line.
 *
 * Handles formats like:
 *   express@^4.18.0:
 *   "express@^4.18.0":
 *   "@babel/core@^7.0.0", "@babel/core@^7.24.0":
 *   "string-width@^1.0.2 || 2":
 *
 * Returns the package name (e.g. "express" or "@babel/core"), or null
 * if the line isn't a valid entry header.
 */
function extractNameV1(headerLine) {
  // Strip trailing colon
  let line = headerLine.replace(/:\s*$/, '').trim();
  if (!line) return null;

  // Take the first descriptor in case of multiple comma-separated ranges
  const first = line.split(',')[0].trim();

  // Remove surrounding quotes
  const unquoted = first.replace(/^"(.*)"$/, '$1');

  // Split on last @ that isn't at position 0 (scoped packages start with @)
  const atIdx = unquoted.lastIndexOf('@');
  if (atIdx <= 0) return null; // no version range found or bare @scope

  return unquoted.slice(0, atIdx);
}

/**
 * Extract the package name from a yarn Berry (v2+) header line.
 *
 * Handles formats like:
 *   "express@npm:^4.18.0":
 *   "@babel/core@npm:^7.24.0":
 *   "express@npm:^4.18.0, express@npm:^4.17.0":
 *
 * Returns the package name, or null if not a valid entry header.
 */
function extractNameBerry(headerLine) {
  // Strip trailing colon
  let line = headerLine.replace(/:\s*$/, '').trim();
  if (!line) return null;

  // Take the first descriptor
  const first = line.split(',')[0].trim();

  // Remove surrounding quotes
  const unquoted = first.replace(/^"(.*)"$/, '$1');

  // Berry descriptors look like: name@npm:range or name@patch:... etc
  // Find the last @ before the protocol
  const atIdx = unquoted.lastIndexOf('@');
  if (atIdx <= 0) return null;

  return unquoted.slice(0, atIdx);
}

/**
 * Parse a yarn.lock v1 (classic) file.
 */
function parseV1(content) {
  const deps = [];
  const seen = new Set();
  const lines = content.split('\n');

  let currentName = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments
    if (line.startsWith('#')) continue;

    // Skip empty lines
    if (line.trim() === '') {
      currentName = null;
      continue;
    }

    // Unindented, non-empty line => entry header
    if (line[0] !== ' ' && line[0] !== '\t') {
      currentName = extractNameV1(line);
      continue;
    }

    // Indented line: look for `version "x.y.z"`
    if (currentName) {
      const trimmed = line.trim();
      const match = trimmed.match(/^version\s+"(.+)"$/);
      if (match) {
        const version = match[1];
        const dedupKey = `${currentName}@${version}`;
        if (!seen.has(dedupKey)) {
          seen.add(dedupKey);
          deps.push({
            name: currentName,
            version,
            ecosystem: 'npm',
            isDev: false,
            isDirect: false,
            isPinned: true,
          });
        }
        currentName = null; // done with this entry
      }
    }
  }

  return deps;
}

/**
 * Parse a yarn.lock v2+ (Berry) file.
 */
function parseBerry(content) {
  const deps = [];
  const seen = new Set();
  const lines = content.split('\n');

  let currentName = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments
    if (line.startsWith('#')) continue;

    // Skip empty lines
    if (line.trim() === '') {
      currentName = null;
      continue;
    }

    // Skip __metadata block entries
    if (line.startsWith('__metadata:')) {
      currentName = null;
      continue;
    }

    // Unindented, non-empty, quoted line => entry header
    if (line[0] !== ' ' && line[0] !== '\t') {
      currentName = extractNameBerry(line);
      continue;
    }

    // Indented line: look for `version: x.y.z` or `version: "x.y.z"`
    if (currentName) {
      const trimmed = line.trim();
      const match = trimmed.match(/^version:\s+"?([^"]+)"?$/);
      if (match) {
        const version = match[1];
        const dedupKey = `${currentName}@${version}`;
        if (!seen.has(dedupKey)) {
          seen.add(dedupKey);
          deps.push({
            name: currentName,
            version,
            ecosystem: 'npm',
            isDev: false,
            isDirect: false,
            isPinned: true,
          });
        }
        currentName = null;
      }
    }
  }

  return deps;
}

/**
 * Parse a yarn.lock file (v1 classic or v2+ Berry) into a flat dependency list.
 *
 * @param {string} filePath - Absolute path to yarn.lock
 * @returns {Array<{ name: string, version: string, ecosystem: string, isDev: boolean, isDirect: boolean, isPinned: boolean }>}
 */
export function parseLockfile(filePath) {
  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(`cannot read ${filePath}: ${err.code || err.message}`);
  }

  let deps;
  if (isBerryFormat(content)) {
    deps = parseBerry(content);
    log.debug(`parsed ${deps.length} packages from ${filePath} (yarn berry format)`);
  } else {
    deps = parseV1(content);
    log.debug(`parsed ${deps.length} packages from ${filePath} (yarn classic format)`);
  }

  return deps;
}

/**
 * Discover yarn lockfiles in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'yarn.lock');
  if (existsSync(lockPath)) lockfiles.push(lockPath);

  return { lockfiles, manifests };
}
