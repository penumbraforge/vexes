import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { isCanonicalNpmTarball } from './npm.js';

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NPM_NAME_RE = /^(?:@[a-z0-9._~-]+\/[a-z0-9._~-]+|[a-z0-9][a-z0-9._~-]*)$/i;
const PUBLIC_YARN_REGISTRY_HOSTS = new Set(['registry.npmjs.org', 'registry.yarnpkg.com']);

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
  let unresolvedEntries = 0;
  let current = null;

  const flush = () => {
    if (!current) return;
    const { name, header, version, resolved } = current;
    if (!name || !NPM_NAME_RE.test(name) || !SEMVER_RE.test(version || '') ||
        !v1DescriptorIsRegistry(header) || !isPublicRegistryTarball(resolved, name, version)) {
      unresolvedEntries++;
      current = null;
      return;
    }
    const dedupKey = `${name}@${version}`;
    if (!seen.has(dedupKey)) {
      seen.add(dedupKey);
      deps.push({
        name,
        version,
        ecosystem: 'npm',
        isDev: false,
        isDirect: false,
        isPinned: true,
        sourceType: 'registry',
        resolved,
      });
    }
    current = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments
    if (line.startsWith('#')) continue;

    // Skip empty lines
    if (line.trim() === '') {
      flush();
      continue;
    }

    // Unindented, non-empty line => entry header
    if (line[0] !== ' ' && line[0] !== '\t') {
      flush();
      current = { name: extractNameV1(line), header: line, version: null, resolved: null };
      continue;
    }

    if (current) {
      const trimmed = line.trim();
      const version = trimmed.match(/^version\s+"([^"]+)"$/)?.[1];
      if (version) current.version = version;
      const resolved = trimmed.match(/^resolved\s+"?([^"\s]+)"?$/)?.[1];
      if (resolved) current.resolved = resolved;
    }
  }

  flush();
  return { deps, unresolvedEntries };
}

function v1DescriptorIsRegistry(header) {
  return !/(?:^|@)(?:npm:|workspace:|file:|link:|portal:|patch:|git(?:\+|:)|github:|gitlab:|bitbucket:|https?:)/i
    .test(String(header || ''));
}

function isPublicRegistryTarball(resolved, name, version) {
  return isCanonicalNpmTarball(resolved, name, version, { hosts: PUBLIC_YARN_REGISTRY_HOSTS });
}

/**
 * Parse a yarn.lock v2+ (Berry) file.
 */
function parseBerry(content) {
  const deps = [];
  const seen = new Set();
  const lines = content.split('\n');
  let unresolvedEntries = 0;
  let current = null;

  const flush = () => {
    if (!current) return;
    const resolution = parseBerryNpmResolution(current.resolution);
    const queryable = current.name && NPM_NAME_RE.test(current.name) &&
      SEMVER_RE.test(current.version || '') && resolution &&
      resolution.name === current.name && resolution.version === current.version;
    if (!queryable) {
      unresolvedEntries++;
      current = null;
      return;
    }
    const dedupKey = `${current.name}@${current.version}`;
    if (!seen.has(dedupKey)) {
      seen.add(dedupKey);
      deps.push({
        name: current.name,
        version: current.version,
        ecosystem: 'npm',
        isDev: false,
        isDirect: false,
        isPinned: true,
        sourceType: 'unknown',
        resolution: current.resolution,
      });
      // Berry's npm: locator seals name/version, not the registry host. A
      // scoped registry or environment setting can resolve different private
      // bytes under the same locator, so advisory coordinates remain useful
      // but source coverage cannot be called complete from yarn.lock alone.
      unresolvedEntries++;
    }
    current = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments
    if (line.startsWith('#')) continue;

    // Skip empty lines
    if (line.trim() === '') {
      flush();
      continue;
    }

    // Skip __metadata block entries
    if (line.startsWith('__metadata:')) {
      flush();
      continue;
    }

    // Unindented, non-empty, quoted line => entry header
    if (line[0] !== ' ' && line[0] !== '\t') {
      flush();
      current = { name: extractNameBerry(line), version: null, resolution: null };
      continue;
    }

    if (current) {
      const trimmed = line.trim();
      const version = trimmed.match(/^version:\s+"?([^"\s]+)"?$/)?.[1];
      if (version) current.version = version;
      const resolution = trimmed.match(/^resolution:\s+"?([^"\s]+)"?$/)?.[1];
      if (resolution) current.resolution = resolution;
    }
  }

  flush();
  return { deps, unresolvedEntries };
}

function parseBerryNpmResolution(value) {
  if (typeof value !== 'string') return null;
  const marker = value.lastIndexOf('@npm:');
  if (marker <= 0) return null;
  const name = value.slice(0, marker);
  const version = value.slice(marker + '@npm:'.length);
  if (!NPM_NAME_RE.test(name) || !SEMVER_RE.test(version)) return null;
  return { name, version };
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

  let parsed;
  if (isBerryFormat(content)) {
    if (!/^__metadata:\s*$[\s\S]*?^\s{2}version:\s*\d+/m.test(content)) {
      throw new Error(`invalid Yarn Berry lockfile schema in ${filePath}: __metadata.version is missing`);
    }
    parsed = parseBerry(content);
    log.debug(`parsed ${parsed.deps.length} packages from ${filePath} (yarn berry format)`);
  } else {
    if (!/^# yarn lockfile v1\s*$/m.test(content)) {
      throw new Error(`invalid Yarn classic lockfile schema in ${filePath}: v1 header is missing`);
    }
    parsed = parseV1(content);
    log.debug(`parsed ${parsed.deps.length} packages from ${filePath} (yarn classic format)`);
  }

  Object.defineProperty(parsed.deps, 'unresolvedEntries', {
    enumerable: false,
    value: parsed.unresolvedEntries,
  });
  return parsed.deps;
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
