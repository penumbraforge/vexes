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
 * Follows -r (recursive include) and -c (constraint) references.
 */
export function parseRequirements(filePath, _visited = new Set()) {
  // Prevent infinite recursion from circular -r includes
  const resolved = join(filePath, '..', '..', filePath).replace(/\/\.\.\//g, '/'); // normalize
  if (_visited.has(filePath)) return [];
  _visited.add(filePath);

  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const dir = join(filePath, '..');
  for (const rawLine of content.split('\n')) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;

    // Follow -r / --requirement includes recursively
    const reqMatch = line.match(/^(?:-r|--requirement)\s+(.+)$/);
    if (reqMatch) {
      const includePath = join(dir, reqMatch[1].trim());
      try {
        deps.push(...parseRequirements(includePath, _visited));
      } catch (err) {
        log.warn(`failed to follow -r include ${reqMatch[1]}: ${err.message}`);
      }
      continue;
    }

    // Follow -c / --constraint files (same format, just version constraints)
    const constraintMatch = line.match(/^(?:-c|--constraint)\s+(.+)$/);
    if (constraintMatch) {
      const includePath = join(dir, constraintMatch[1].trim());
      try {
        deps.push(...parseRequirements(includePath, _visited));
      } catch (err) {
        log.warn(`failed to follow -c constraint ${constraintMatch[1]}: ${err.message}`);
      }
      continue;
    }

    if (line.startsWith('-') || line.startsWith('--')) continue; // other options

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
 * Parse pyproject.toml [project.dependencies], [project.optional-dependencies],
 * and [tool.poetry.dependencies] (TOML subset).
 */
export function parsePyprojectToml(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  let inArray = false;       // inside a [...] array value
  let inSection = null;      // current [section.name]

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    // Track section headers
    const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      inArray = false;
      inSection = sectionMatch[1].trim();
      continue;
    }

    // [project] dependencies = [...]
    if (inSection === 'project' && /^dependencies\s*=\s*\[/.test(trimmed)) {
      inArray = true;
      const inlineMatch = trimmed.match(/\[(.+)\]/);
      if (inlineMatch) {
        parseDepsArray(inlineMatch[1], deps);
        inArray = false;
      }
      continue;
    }

    // [project.optional-dependencies] — any key = [...] array
    if (inSection?.startsWith('project.optional-dependencies')) {
      if (/^[a-zA-Z0-9_-]+\s*=\s*\[/.test(trimmed)) {
        inArray = true;
        const inlineMatch = trimmed.match(/\[(.+)\]/);
        if (inlineMatch) {
          parseDepsArray(inlineMatch[1], deps);
          inArray = false;
        }
        continue;
      }
    }

    // [tool.poetry.dependencies] — key = "version" or key = {version = "..."}
    if (inSection === 'tool.poetry.dependencies') {
      const poetryDep = trimmed.match(/^([a-zA-Z0-9._-]+)\s*=\s*"([^"]+)"/);
      if (poetryDep) {
        const name = normalize(poetryDep[1]);
        if (name === 'python') continue; // Skip python version constraint
        const verMatch = poetryDep[2].match(/[\d].*/);
        const version = verMatch ? verMatch[0].split(',')[0].trim() : 'latest';
        deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: false });
        continue;
      }
      // Table form: name = {version = "^1.0", ...}
      const poetryTable = trimmed.match(/^([a-zA-Z0-9._-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
      if (poetryTable) {
        const name = normalize(poetryTable[1]);
        if (name === 'python') continue;
        const verMatch = poetryTable[2].match(/[\d].*/);
        const version = verMatch ? verMatch[0].split(',')[0].trim() : 'latest';
        deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: false });
        continue;
      }
    }

    // [tool.poetry.dev-dependencies]
    if (inSection === 'tool.poetry.dev-dependencies') {
      const poetryDep = trimmed.match(/^([a-zA-Z0-9._-]+)\s*=\s*"([^"]+)"/);
      if (poetryDep) {
        const name = normalize(poetryDep[1]);
        const verMatch = poetryDep[2].match(/[\d].*/);
        const version = verMatch ? verMatch[0].split(',')[0].trim() : 'latest';
        deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isDev: true, isPinned: false });
        continue;
      }
    }

    // Inside a [...] array value (for dependencies and optional-dependencies)
    if (inArray) {
      if (trimmed === ']') { inArray = false; continue; }
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
