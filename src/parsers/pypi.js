import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

const SEMVER_LIKE = /^\d+(\.\d+)*$/;

/**
 * Normalize PyPI package name: lowercase, replace [._] with -
 */
function normalize(name) {
  return name.toLowerCase().replace(/[._]/g, '-').trim();
}

/**
 * Parse requirements.txt into dependency list.
 */
export function parseRequirements(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  for (const rawLine of content.split('\n')) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    if (line.startsWith('-') || line.startsWith('--')) continue; // options

    // Strip extras: package[extra1,extra2]
    const stripped = line.replace(/\[.*?\]/, '');

    // Parse name and version: name==1.0.0, name>=1.0.0, name~=1.0.0, name
    const match = stripped.match(/^([a-zA-Z0-9._-]+)\s*(?:([=!<>~]+)\s*(.+?))?(?:\s*;.*)?$/);
    if (!match) continue;

    const name = normalize(match[1]);
    const op = match[2] || '';
    const ver = match[3]?.trim()?.split(',')[0]?.trim() || 'latest';

    // Only extract pinned versions for OSV queries
    const version = op === '==' ? ver : ver;

    deps.push({
      name,
      version,
      ecosystem: 'pypi',
      isDirect: true,
      isPinned: op === '==',
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse poetry.lock (TOML subset — [[package]] sections).
 */
export function parsePoetryLock(filePath) {
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
          name: normalize(current.name),
          version: current.version,
          ecosystem: 'pypi',
          isDirect: false, // poetry.lock includes all transitive
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

  // Don't forget the last entry
  if (current?.name && current?.version) {
    deps.push({
      name: normalize(current.name),
      version: current.version,
      ecosystem: 'pypi',
      isDirect: false,
      isPinned: true,
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse Pipfile.lock (JSON).
 */
export function parsePipfileLock(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  let data;
  try { data = JSON.parse(content); }
  catch (err) { throw new Error(`invalid JSON in ${filePath}: ${err.message}`); }

  const deps = [];

  for (const [section, isDev] of [['default', false], ['develop', true]]) {
    const entries = data[section];
    if (!entries || typeof entries !== 'object') continue;

    for (const [name, info] of Object.entries(entries)) {
      const version = info.version?.replace(/^==/, '') || 'latest';
      deps.push({
        name: normalize(name),
        version,
        ecosystem: 'pypi',
        isDirect: true,
        isDev,
        isPinned: !!info.version,
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse pyproject.toml [project.dependencies] (TOML subset).
 */
export function parsePyprojectToml(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  let inDeps = false;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    if (trimmed === '[project]') continue;
    if (/^\[/.test(trimmed) && trimmed !== '[project]') {
      inDeps = false;
      continue;
    }

    if (/^dependencies\s*=\s*\[/.test(trimmed)) {
      inDeps = true;
      // Check for inline deps on same line
      const inlineMatch = trimmed.match(/\[(.+)\]/);
      if (inlineMatch) {
        parseDepsArray(inlineMatch[1], deps);
        inDeps = false;
      }
      continue;
    }

    if (inDeps) {
      if (trimmed === ']') { inDeps = false; continue; }
      // Each line is like: "package-name>=1.0.0",
      const m = trimmed.match(/^\s*"([^"]+)"/);
      if (m) {
        const depStr = m[1];
        const nameMatch = depStr.match(/^([a-zA-Z0-9._-]+)/);
        if (nameMatch) {
          const name = normalize(nameMatch[1]);
          const verMatch = depStr.match(/[=<>~!]+(.+)/);
          const version = verMatch ? verMatch[1].trim().split(',')[0].trim() : 'latest';
          deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: false });
        }
      }
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

function parseDepsArray(content, deps) {
  const items = content.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
  for (const item of items) {
    if (!item) continue;
    const nameMatch = item.match(/^([a-zA-Z0-9._-]+)/);
    if (nameMatch) {
      const name = normalize(nameMatch[1]);
      deps.push({ name, version: 'latest', ecosystem: 'pypi', isDirect: true, isPinned: false });
    }
  }
}

/**
 * Discover PyPI dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const candidates = [
    { file: 'Pipfile.lock', type: 'lock' },
    { file: 'poetry.lock', type: 'lock' },
    { file: 'requirements.txt', type: 'manifest' },
    { file: 'pyproject.toml', type: 'manifest' },
  ];

  for (const c of candidates) {
    const path = join(dir, c.file);
    if (existsSync(path)) {
      if (c.type === 'lock') lockfiles.push({ path, format: c.file });
      else manifests.push({ path, format: c.file });
    }
  }

  return { lockfiles, manifests };
}

/**
 * Parse any PyPI lockfile/manifest by format.
 */
export function parseFile(filePath, format) {
  switch (format) {
    case 'Pipfile.lock': return parsePipfileLock(filePath);
    case 'poetry.lock':  return parsePoetryLock(filePath);
    case 'requirements.txt': return parseRequirements(filePath);
    case 'pyproject.toml': return parsePyprojectToml(filePath);
    default: throw new Error(`unknown PyPI format: ${format}`);
  }
}
