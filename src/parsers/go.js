import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Parse go.sum into dependency list.
 *
 * go.sum format:
 *   module version hash
 *   module version/go.mod hash
 *
 * Lines with /go.mod suffix are module checksums, not direct dependency entries.
 * Deduplicate by name@version since each module may appear with multiple hashes.
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const seen = new Set();

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) continue;

    const [name, version] = parts;

    // Skip /go.mod suffix lines — they are module-level checksums
    if (version.endsWith('/go.mod')) continue;

    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    deps.push({
      name,
      version,
      ecosystem: 'go',
      isDirect: false,
      isPinned: true,
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse go.mod into dependency list from require directives.
 */
export function parseManifest(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  if (!/^module\s+\S+\s*$/m.test(content)) {
    throw new Error(`invalid go.mod schema in ${filePath}: module directive is missing`);
  }

  const deps = [];
  const seen = new Set();
  const workspace = applicableWorkspace(filePath);
  const replacements = new Set([
    ...replacedModules(content),
    ...replacedModules(workspace?.content || ''),
  ]);
  // go.work can replace modules and make workspace modules override versioned
  // downloads. This line parser does not implement Go's full workspace module
  // selection, so an applicable workspace always keeps source coverage
  // incomplete even when its explicit replacements do not match a require.
  let unresolvedEntries = workspace ? 1 : 0;
  let inRequireBlock = false;

  const addDep = (name, version, isDirect) => {
    if (!name || !version) return;
    if (replacements.has(name)) {
      unresolvedEntries++;
      return;
    }
    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) return;
    seen.add(dedupKey);
    deps.push({
      name,
      version,
      ecosystem: 'go',
      isDirect,
      isPinned: true,
    });
  };

  for (const rawLine of content.split('\n')) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    if (trimmed === 'require (') {
      inRequireBlock = true;
      continue;
    }

    if (inRequireBlock && trimmed === ')') {
      inRequireBlock = false;
      continue;
    }

    let requireLine = null;
    if (inRequireBlock) {
      requireLine = trimmed;
    } else if (trimmed.startsWith('require ')) {
      requireLine = trimmed.slice('require '.length).trim();
    }

    if (!requireLine) continue;

    const isIndirect = /\/\/\s*indirect\b/.test(requireLine);
    const withoutComment = requireLine.replace(/\s*\/\/.*$/, '').trim();
    const match = withoutComment.match(/^([^\s]+)\s+([^\s]+)$/);
    if (!match) continue;

    addDep(match[1], match[2], !isIndirect);
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    get: () => unresolvedEntries,
  });
  return deps;
}

function applicableWorkspace(modPath) {
  if (process.env.GOWORK === 'off') return null;

  if (process.env.GOWORK) {
    const explicit = resolve(dirname(modPath), process.env.GOWORK);
    try { return { path: explicit, content: readFileSync(explicit, 'utf8') }; }
    catch { return { path: explicit, content: '' }; }
  }

  let current = dirname(modPath);
  for (let i = 0; i < 20; i++) {
    const candidate = join(current, 'go.work');
    if (existsSync(candidate)) {
      try { return { path: candidate, content: readFileSync(candidate, 'utf8') }; }
      catch { return { path: candidate, content: '' }; }
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function replacedModules(content) {
  const names = new Set();
  let inBlock = false;
  for (const raw of content.split('\n')) {
    const line = raw.replace(/\s*\/\/.*$/, '').trim();
    if (!line) continue;
    if (line === 'replace (') { inBlock = true; continue; }
    if (inBlock && line === ')') { inBlock = false; continue; }
    const spec = inBlock ? line : (line.startsWith('replace ') ? line.slice('replace '.length).trim() : null);
    if (!spec) continue;
    const match = spec.match(/^(\S+)(?:\s+v\S+)?\s+=>\s+\S+/);
    if (match) names.add(match[1]);
  }
  return names;
}

/**
 * Discover Go dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const sumPath = join(dir, 'go.sum');
  const modPath = join(dir, 'go.mod');

  if (existsSync(sumPath)) lockfiles.push(sumPath);
  if (existsSync(modPath)) manifests.push(modPath);

  return { lockfiles, manifests };
}
