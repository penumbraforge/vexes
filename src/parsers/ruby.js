import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { extractVersionFromSpec, isPinnedVersionSpec } from './version-spec.js';

/**
 * Parse Gemfile.lock into dependency list.
 *
 * Gemfile.lock has sections like GEM, PLATFORMS, DEPENDENCIES.
 * Under GEM/specs, packages are at 4-space indent with version in parens:
 *     actioncable (7.1.3)
 *
 * DEPENDENCIES section lists direct dependencies:
 *   rails (~> 7.1)
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const lines = content.split('\n');
  let inSpecs = false;
  let inDependencies = false;
  const directNames = new Set();

  // First pass: collect direct dependency names from DEPENDENCIES section
  let scanDeps = false;
  for (const line of lines) {
    if (line === 'DEPENDENCIES') {
      scanDeps = true;
      continue;
    }
    if (scanDeps) {
      // A new section header (non-indented, all caps) ends DEPENDENCIES
      if (line.length > 0 && !line.startsWith(' ')) {
        scanDeps = false;
        continue;
      }
      const m = line.match(/^\s{2}(\S+)/);
      if (m) directNames.add(m[1]);
    }
  }

  // Second pass: parse GEM/specs for package entries
  for (const line of lines) {
    // Detect section transitions
    if (line === 'GEM') {
      continue;
    }
    if (/^\s{2}specs:$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (line === 'DEPENDENCIES') {
      inDependencies = true;
      inSpecs = false;
      continue;
    }
    // Any non-indented, non-empty line starts a new section
    if (line.length > 0 && !line.startsWith(' ')) {
      inSpecs = false;
      inDependencies = false;
      continue;
    }

    if (inSpecs) {
      // Package entries are at exactly 4-space indent: "    name (version)"
      // Sub-dependencies are at 6+ spaces — skip those
      const m = line.match(/^    (\S+)\s+\(([^)]+)\)$/);
      if (m) {
        const [, name, version] = m;
        deps.push({
          name,
          version,
          ecosystem: 'ruby',
          isDirect: directNames.has(name),
          isPinned: true,
        });
      }
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Parse Gemfile into direct dependency specs.
 */
export function parseManifest(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const seen = new Set();

  for (const rawLine of content.split('\n')) {
    const line = rawLine.replace(/\s+#.*$/, '').trim();
    if (!line.startsWith('gem ')) continue;

    const nameMatch = line.match(/^gem\s+['"]([^'"]+)['"]/);
    if (!nameMatch) continue;

    const name = nameMatch[1];
    const rest = line.slice(nameMatch[0].length);
    const stringArgs = [...rest.matchAll(/['"]([^'"]+)['"]/g)].map(match => match[1]);

    let versionSpec = null;
    let version = null;
    for (const candidate of stringArgs) {
      const extracted = extractVersionFromSpec(candidate);
      if (!extracted) continue;
      versionSpec = candidate;
      version = extracted;
      break;
    }

    if (!version) continue;

    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    deps.push({
      name,
      version,
      ecosystem: 'ruby',
      isDirect: true,
      isPinned: isPinnedVersionSpec(versionSpec, version),
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Discover Ruby dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'Gemfile.lock');
  const gemfilePath = join(dir, 'Gemfile');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(gemfilePath)) manifests.push(gemfilePath);

  return { lockfiles, manifests };
}
