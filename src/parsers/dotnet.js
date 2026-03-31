import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { extractVersionFromSpec, isPinnedVersionSpec } from './version-spec.js';

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
  const frameworks = data.dependencies;

  if (!frameworks || typeof frameworks !== 'object') {
    log.warn(`no dependencies found in ${filePath}`);
    return deps;
  }

  for (const [, packages] of Object.entries(frameworks)) {
    if (!packages || typeof packages !== 'object') continue;

    for (const [name, entry] of Object.entries(packages)) {
      if (!entry.resolved) continue;

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
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
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
    if (!name || !version) return;

    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) return;
    seen.add(dedupKey);

    deps.push({
      name,
      version,
      ecosystem: 'nuget',
      isDirect: true,
      isPinned: isPinnedVersionSpec(spec, version),
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
