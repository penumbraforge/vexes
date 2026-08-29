import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

const PINNED_VERSION = /^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/;

function exactVersion(op, value) {
  const version = String(value || '').trim();
  return (op === '==' || op === '===') && PINNED_VERSION.test(version) && !version.includes('*')
    ? version
    : null;
}

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
export function parseRequirements(
  filePath,
  _visited = new Set(),
  _state = { unresolvedEntries: 0, includeFailures: [], sourceBoundaryChanged: false },
) {
  // Prevent infinite recursion from circular -r includes
  if (_visited.has(filePath)) return attachRequirementsStatus([], _state);
  _visited.add(filePath);

  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const dir = join(filePath, '..');
  for (const rawLine of content.split('\n')) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;

    // Source-changing pip options mean an exact name/version is not anchored
    // to the public PyPI artifact OSV describes. Refuse the entire manifest
    // rather than querying a potentially different private package as PyPI.
    if (/^(?:-i(?:\s|=|https?:)|--index-url(?:\s|=)|--extra-index-url(?:\s|=)|-f(?:\s|=|https?:)|--find-links(?:\s|=)|--trusted-host(?:\s|=)|--no-index\b)/i.test(line)) {
      _state.sourceBoundaryChanged = true;
      _state.unresolvedEntries++;
      _state.includeFailures.push(`source-changing pip option is outside the public-PyPI analysis boundary: ${line.split(/\s|=/, 1)[0]}`);
      continue;
    }

    // Follow -r / --requirement includes recursively
    const reqMatch = line.match(/^(?:-r|--requirement)\s+(.+)$/);
    if (reqMatch) {
      const includePath = join(dir, reqMatch[1].trim());
      try {
        deps.push(...parseRequirements(includePath, _visited, _state));
      } catch (err) {
        _state.unresolvedEntries++;
        _state.includeFailures.push(`failed to follow -r include ${reqMatch[1]}: ${err.message}`);
      }
      continue;
    }

    // A constraint file limits versions but does not itself prove that a
    // package is installed. Resolving requirements + constraints needs a real
    // package resolver, so keep usable exact requirements and mark this parse
    // incomplete instead of reporting constraint entries as packages.
    const constraintMatch = line.match(/^(?:-c|--constraint)\s+(.+)$/);
    if (constraintMatch) {
      _state.unresolvedEntries++;
      _state.includeFailures.push(`constraint include ${constraintMatch[1]} requires dependency resolution`);
      continue;
    }

    if (/^(?:-e|--editable)\b/.test(line)) {
      _state.unresolvedEntries++;
      continue;
    }
    if (line.startsWith('-') || line.startsWith('--')) continue; // non-dependency options

    // Strip extras: package[extra1,extra2]
    const stripped = line.replace(/\[.*?\]/, '');

    // Parse name and version: name==1.0.0, name>=1.0.0, name~=1.0.0, name
    const match = stripped.match(/^([a-zA-Z0-9._-]+)\s*(?:([=!<>~]+)\s*(.+?))?(?:\s*;.*)?$/);
    if (!match) {
      _state.unresolvedEntries++;
      continue;
    }

    const name = normalize(match[1]);
    const op = match[2] || '';
    const ver = match[3]?.trim()?.split(',')[0]?.trim() || '';
    const version = exactVersion(op, ver);
    if (!version) {
      log.debug(`skipping unresolved PyPI manifest dependency: ${name}${op}${ver}`);
      _state.unresolvedEntries++;
      continue;
    }

    deps.push({
      name,
      version,
      ecosystem: 'pypi',
      isDirect: true,
      isPinned: true,
    });
  }

  if (_state.sourceBoundaryChanged) deps.length = 0;
  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return attachRequirementsStatus(deps, _state);
}

function attachRequirementsStatus(deps, state) {
  Object.defineProperties(deps, {
    unresolvedEntries: { enumerable: false, get: () => state.unresolvedEntries },
    includeFailures: { enumerable: false, get: () => [...state.includeFailures] },
  });
  return deps;
}

/**
 * Parse poetry.lock (TOML subset — [[package]] sections).
 */
export function parsePoetryLock(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  if (!/^\[\[package\]\]\s*$/m.test(content) && !/^package\s*=\s*\[\s*\]\s*$/m.test(content)) {
    throw new Error(`invalid or unsupported poetry.lock schema in ${filePath}`);
  }

  const deps = [];
  let current = null;
  let inPackageSource = false;
  let unresolvedEntries = 0;

  const finishPackage = () => {
    if (!current) return;
    const coordinateValid = current.name && current.version && PINNED_VERSION.test(current.version);
    const explicitPublicSource = current.hasSource && isPublicPypiUrl(current.sourceUrl);
    const queryable = coordinateValid && (!current.hasSource || explicitPublicSource);
    if (queryable) {
      deps.push({
        name: normalize(current.name),
        version: current.version,
        ecosystem: 'pypi',
        isDirect: false, // poetry.lock includes all transitive
        isPinned: true,
        sourceType: explicitPublicSource ? 'registry' : 'unknown',
      });
      // Poetry's ordinary lock entry seals name/version but not which source
      // supplied the distribution. Project/user repository configuration may
      // select private bytes, so retain the advisory coordinate while making
      // the dependency/source coverage explicitly incomplete.
      if (!explicitPublicSource) unresolvedEntries++;
    } else {
      unresolvedEntries++;
    }
  };

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    if (trimmed === '[[package]]') {
      finishPackage();
      current = {};
      inPackageSource = false;
      continue;
    }

    if (current) {
      if (trimmed === '[package.source]') {
        current.hasSource = true;
        inPackageSource = true;
        continue;
      }
      if (/^\[.*\]$/.test(trimmed)) inPackageSource = false;

      if (inPackageSource) {
        const source = trimmed.match(/^url\s*=\s*"(.+?)"/);
        if (source) current.sourceUrl = source[1];
      } else {
        const m = trimmed.match(/^(name|version)\s*=\s*"(.+?)"/);
        if (m) current[m[1]] = m[2];
      }
    }
  }

  finishPackage();

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachUnresolvedStatus(deps, () => unresolvedEntries);
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

  if (!data._meta || typeof data._meta !== 'object' ||
      !data.default || typeof data.default !== 'object' || Array.isArray(data.default) ||
      !data.develop || typeof data.develop !== 'object' || Array.isArray(data.develop)) {
    throw new Error(`invalid Pipfile.lock schema in ${filePath}: _meta/default/develop objects are required`);
  }

  const deps = [];
  let unresolvedEntries = 0;
  const sources = Array.isArray(data._meta.sources) ? data._meta.sources : [];
  const sourcesByName = new Map(sources
    .filter(source => source && typeof source === 'object' && typeof source.name === 'string')
    .map(source => [source.name, source]));
  const defaultSource = sources.length === 1 ? sources[0] : null;

  for (const [section, isDev] of [['default', false], ['develop', true]]) {
    const entries = data[section];
    if (!entries || typeof entries !== 'object') continue;

    for (const [name, info] of Object.entries(entries)) {
      if (!info || typeof info !== 'object' || Array.isArray(info)) {
        unresolvedEntries++;
        continue;
      }
      const rawVersion = typeof info?.version === 'string' ? info.version : '';
      const version = exactVersion(rawVersion.startsWith('===') ? '===' : '==', rawVersion.replace(/^===?/, ''));
      const selectedSource = typeof info.index === 'string'
        ? sourcesByName.get(info.index)
        : defaultSource;
      const sourceAnchored = isPublicPypiUrl(selectedSource?.url);
      const nonRegistry = ['git', 'path', 'file', 'uri'].some(key => info[key] !== undefined) || info.editable === true;
      if (!version || !/^===?/.test(rawVersion) || !sourceAnchored || nonRegistry) {
        unresolvedEntries++;
        continue;
      }
      deps.push({
        name: normalize(name),
        version,
        ecosystem: 'pypi',
        isDirect: true,
        isDev,
        isPinned: true,
      });
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachUnresolvedStatus(deps, () => unresolvedEntries);
  return deps;
}

function isPublicPypiUrl(value) {
  if (typeof value !== 'string' || !value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' &&
      (url.hostname === 'pypi.org' || url.hostname === 'pypi.python.org') &&
      /^\/simple\/?$/.test(url.pathname);
  } catch {
    return false;
  }
}

function attachUnresolvedStatus(deps, readUnresolved) {
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    get: readUnresolved,
  });
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
  let unresolvedEntries = 0;
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
        unresolvedEntries += parseDepsArray(inlineMatch[1], deps);
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
          unresolvedEntries += parseDepsArray(inlineMatch[1], deps);
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
        const version = PINNED_VERSION.test(poetryDep[2]) ? poetryDep[2] : null;
        if (version) deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: true });
        else unresolvedEntries++;
        continue;
      }
      // Table form: name = {version = "^1.0", ...}
      const poetryTable = trimmed.match(/^([a-zA-Z0-9._-]+)\s*=\s*\{(.*)\}\s*$/);
      if (poetryTable) {
        const name = normalize(poetryTable[1]);
        if (name === 'python') continue;
        const body = poetryTable[2];
        const versionMatch = body.match(/(?:^|,)\s*version\s*=\s*"([^"]+)"/);
        const explicitSource = /(?:^|,)\s*(?:git|path|url|source)\s*=/.test(body);
        const version = !explicitSource && versionMatch && PINNED_VERSION.test(versionMatch[1])
          ? versionMatch[1]
          : null;
        if (version) deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: true });
        else unresolvedEntries++;
        continue;
      }
      if (/^[a-zA-Z0-9._-]+\s*=/.test(trimmed) && !/^python\s*=/.test(trimmed)) unresolvedEntries++;
    }

    // [tool.poetry.dev-dependencies]
    if (inSection === 'tool.poetry.dev-dependencies') {
      const poetryDep = trimmed.match(/^([a-zA-Z0-9._-]+)\s*=\s*"([^"]+)"/);
      if (poetryDep) {
        const name = normalize(poetryDep[1]);
        const version = PINNED_VERSION.test(poetryDep[2]) ? poetryDep[2] : null;
        if (version) deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isDev: true, isPinned: true });
        else unresolvedEntries++;
        continue;
      }
      if (/^[a-zA-Z0-9._-]+\s*=/.test(trimmed)) unresolvedEntries++;
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
          const verMatch = depStr.match(/(===?|[<>~!]+)\s*([^,;\s]+)/);
          const version = verMatch ? exactVersion(verMatch[1], verMatch[2]) : null;
          if (version) deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: true });
          else unresolvedEntries++;
        }
      }
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    get: () => unresolvedEntries,
  });
  return deps;
}

function parseDepsArray(content, deps) {
  let unresolved = 0;
  const items = content.split(',').map(s => s.trim().replace(/^"|"$/g, ''));
  for (const item of items) {
    if (!item) continue;
    const nameMatch = item.match(/^([a-zA-Z0-9._-]+)/);
    if (nameMatch) {
      const name = normalize(nameMatch[1]);
      const verMatch = item.match(/(===?|[<>~!]+)\s*([^,;\s]+)/);
      const version = verMatch ? exactVersion(verMatch[1], verMatch[2]) : null;
      if (version) deps.push({ name, version, ecosystem: 'pypi', isDirect: true, isPinned: true });
      else unresolved++;
    }
  }
  return unresolved;
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
