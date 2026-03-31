import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Parse pnpm-lock.yaml into a flat dependency list.
 * Handles both v6 (package keys start with /) and v9 (no leading /) formats.
 * Uses line-by-line parsing — no external YAML parser required.
 *
 * @param {string} filePath - Absolute path to pnpm-lock.yaml
 * @returns {Array<{ name: string, version: string, ecosystem: string, isDev: boolean, isDirect: boolean, isPinned: true }>}
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const lines = content.split('\n');
  const deps = [];
  const seen = new Set();

  // Track which top-level section we're in
  let section = null;
  // Collect direct dependency names from top-level dependencies/devDependencies
  const directDeps = new Set();
  const devDeps = new Set();

  // Current package being parsed inside the `packages:` section
  let currentPkg = null;
  // Indentation depth of the package key line (to know when we leave it)
  let pkgIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimEnd();

    // Detect top-level sections (no leading whitespace)
    if (/^\S/.test(line)) {
      // Flush any in-progress package
      flushPackage(currentPkg, deps, seen, directDeps, devDeps);
      currentPkg = null;
      pkgIndent = -1;

      if (trimmed === 'dependencies:') { section = 'dependencies'; continue; }
      if (trimmed === 'devDependencies:') { section = 'devDependencies'; continue; }
      if (trimmed === 'packages:') { section = 'packages'; continue; }
      if (trimmed === 'snapshots:') { section = 'snapshots'; continue; }
      // Any other top-level key (settings:, lockfileVersion:, etc.)
      section = null;
      continue;
    }

    // Inside top-level dependencies: section — collect direct dep names
    if (section === 'dependencies') {
      const depMatch = trimmed.match(/^\s{2}(\S+):/);
      if (depMatch) {
        directDeps.add(depMatch[1]);
      }
      continue;
    }

    // Inside top-level devDependencies: section — collect dev dep names
    if (section === 'devDependencies') {
      const depMatch = trimmed.match(/^\s{2}(\S+):/);
      if (depMatch) {
        devDeps.add(depMatch[1]);
        directDeps.add(depMatch[1]);
      }
      continue;
    }

    // Inside packages: section — parse individual package entries
    if (section === 'packages') {
      const indent = line.search(/\S/);

      // A new package key line: exactly 2-space indent with a package identifier
      // v6: /express@4.18.2:  or  /@babel/core@7.24.0:
      // v9: express@4.18.2:   or  '@babel/core@7.24.0':
      const pkgKeyMatch = trimmed.match(
        /^['"]?\/?(@[^@]+\/[^@]+|[^@\s/][^@\s]*)@([^:'"\s]+)['"]?:/
      );
      if (pkgKeyMatch && indent === 2) {
        // Flush previous package
        flushPackage(currentPkg, deps, seen, directDeps, devDeps);
        currentPkg = { name: pkgKeyMatch[1], version: pkgKeyMatch[2], isDev: false };
        pkgIndent = indent;
        continue;
      }

      // Properties of the current package (deeper indentation)
      if (currentPkg && indent > pkgIndent) {
        const devMatch = trimmed.match(/^dev:\s*(true|false)/);
        if (devMatch) {
          currentPkg.isDev = devMatch[1] === 'true';
        }
        continue;
      }

      // If we're back at the same or lesser indent without matching a new key,
      // the packages section might have ended or there's unexpected content
      if (currentPkg && indent <= pkgIndent) {
        flushPackage(currentPkg, deps, seen, directDeps, devDeps);
        currentPkg = null;
        pkgIndent = -1;
      }
    }

    // We intentionally skip the snapshots: section — packages: has what we need
  }

  // Flush any trailing package
  flushPackage(currentPkg, deps, seen, directDeps, devDeps);

  log.debug(`parsed ${deps.length} packages from ${filePath}`);
  return deps;
}

/**
 * Emit a parsed package entry into deps, deduplicating by name@version.
 */
function flushPackage(pkg, deps, seen, directDeps, devDeps) {
  if (!pkg || !pkg.name || !pkg.version) return;

  const dedupKey = `${pkg.name}@${pkg.version}`;
  if (seen.has(dedupKey)) return;
  seen.add(dedupKey);

  // isDev: prefer the explicit `dev: true` flag from the lockfile;
  // fall back to checking if the package is only in devDependencies
  const isDev = pkg.isDev || (!directDeps.has(pkg.name) && devDeps.has(pkg.name));

  deps.push({
    name: pkg.name,
    version: pkg.version,
    ecosystem: 'npm',
    isDev,
    isDirect: directDeps.has(pkg.name),
    isPinned: true,
  });
}

/**
 * Discover pnpm dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'pnpm-lock.yaml');
  if (existsSync(lockPath)) lockfiles.push(lockPath);

  return { lockfiles, manifests };
}
