import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { extractVersionFromSpec, isPinnedVersionSpec } from './version-spec.js';

const NUGET_VERSION_RE = /^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/;

/**
 * Parse packages.lock.json (NuGet) into dependency list.
 *
 * Format:
 *   { "version": 1, "dependencies": { "<framework>": { "<pkg>": { "type": "...", "resolved": "..." } } } }
 *
 * Iterates all target framework keys. Uses "resolved" as version.
 * type === "Direct" maps to isDirect: true.
 */
export function parseLockfile(filePath) {
  let raw;
  try { raw = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  let data;
  try { data = JSON.parse(raw); }
  catch (err) { throw new Error(`invalid JSON in ${filePath}: ${err.message}`); }

  const deps = [];
  const seen = new Set();
  let unresolvedEntries = 0;
  const frameworks = data.dependencies;

  if (!Number.isInteger(data.version) || !frameworks || typeof frameworks !== 'object' || Array.isArray(frameworks)) {
    throw new Error(`invalid packages.lock.json schema in ${filePath}: numeric version and dependencies object are required`);
  }

  for (const [, packages] of Object.entries(frameworks)) {
    if (!packages || typeof packages !== 'object' || Array.isArray(packages)) {
      throw new Error(`invalid packages.lock.json schema in ${filePath}: target framework entries must be objects`);
    }

    for (const [name, entry] of Object.entries(packages)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
          typeof entry.resolved !== 'string' || !NUGET_VERSION_RE.test(entry.resolved)) {
        unresolvedEntries++;
        continue;
      }

      const dedupKey = `${name}@${entry.resolved}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      deps.push({
        name,
        version: entry.resolved,
        ecosystem: 'nuget',
        isDirect: entry.type === 'Direct',
        isPinned: true,
      });
      // packages.lock.json records a content hash but not the package feed.
      // Retain the coordinate for advisory leads while keeping coverage
      // incomplete until public NuGet artifact identity can be cross-checked.
      unresolvedEntries++;
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  Object.defineProperty(deps, 'unresolvedEntries', { enumerable: false, value: unresolvedEntries });
  return deps;
}

function extractXmlAttribute(attrs, name) {
  const match = attrs.match(new RegExp(`${name}\\s*=\\s*"([^"]+)"`, 'i'));
  return match ? match[1] : null;
}

/**
 * Parse a .csproj manifest into PackageReference dependencies.
 */
export function parseManifest(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const seen = new Set();

  const addDep = (name, spec) => {
    const version = extractVersionFromSpec(spec);
    // NuGet ranges are constraints rather than installed versions. A project
    // manifest can safely contribute only exact PackageReference pins.
    if (!name || !version || !isPinnedVersionSpec(spec, version)) return;

    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) return;
    seen.add(dedupKey);

    deps.push({
      name,
      version,
      ecosystem: 'nuget',
      isDirect: true,
      isPinned: true,
    });
  };

  const selfClosingRe = /<PackageReference\b([^>]*)\/>/gi;
  let match;
  while ((match = selfClosingRe.exec(content)) !== null) {
    const attrs = match[1];
    const name = extractXmlAttribute(attrs, 'Include') || extractXmlAttribute(attrs, 'Update');
    const version = extractXmlAttribute(attrs, 'Version');
    if (name && version) addDep(name, version);
  }

  let currentName = null;
  for (const line of content.split('\n')) {
    const openMatch = line.match(/<PackageReference\b([^>]*)>/i);
    if (openMatch && !/\/>\s*$/.test(line)) {
      const attrs = openMatch[1];
      currentName = extractXmlAttribute(attrs, 'Include') || extractXmlAttribute(attrs, 'Update');
      const inlineVersion = extractXmlAttribute(attrs, 'Version');
      if (currentName && inlineVersion) {
        addDep(currentName, inlineVersion);
        currentName = null;
      }
      continue;
    }

    if (!currentName) continue;

    const versionMatch = line.match(/<Version>\s*([^<]+)\s*<\/Version>/i);
    if (versionMatch) {
      addDep(currentName, versionMatch[1]);
    }

    if (/<\/PackageReference>/i.test(line)) {
      currentName = null;
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Discover .NET/NuGet dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'packages.lock.json');
  if (existsSync(lockPath)) lockfiles.push(lockPath);

  // Look for *.csproj files as manifests
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (entry.endsWith('.csproj')) {
        const fullPath = join(dir, entry);
        if (existsSync(fullPath)) manifests.push(fullPath);
      }
    }
  } catch {
    // Directory not readable — skip manifest discovery
  }

  return { lockfiles, manifests };
}
