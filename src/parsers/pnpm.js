import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';
import { isCanonicalNpmTarball } from './npm.js';

const NPM_NAME_RE = /^(?:@[a-z0-9._~-]+\/[a-z0-9._~-]+|[a-z0-9][a-z0-9._~-]*)$/i;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NON_REGISTRY_SPEC_RE = /^(?:file:|link:|workspace:|portal:|patch:|catalog:|git(?:\+|:)|github:|gitlab:|bitbucket:|https?:|npm:)/i;

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

  const lockVersion = content.match(/^lockfileVersion:\s*['"]?([0-9]+(?:\.[0-9]+)?)['"]?\s*$/m)?.[1];
  if (!lockVersion) {
    throw new Error(`invalid pnpm lockfile schema in ${filePath}: lockfileVersion is missing`);
  }
  const lockMajor = Number(lockVersion.split('.')[0]);
  if (![6, 9].includes(lockMajor)) {
    throw new Error(`unsupported pnpm lockfileVersion ${lockVersion} in ${filePath}`);
  }

  const lines = content.split('\n');
  const deps = [];
  const seen = new Set();
  const directInfo = collectDirectDependencyInfo(lines, lockMajor);
  let unresolvedEntries = directInfo.unresolvedEntries;

  // Track which top-level section we're in.
  let section = null;

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
      unresolvedEntries += flushPackage(currentPkg, deps, seen, directInfo);
      currentPkg = null;
      pkgIndent = -1;

      if (trimmed === 'packages:') { section = 'packages'; continue; }
      if (trimmed === 'snapshots:') { section = 'snapshots'; continue; }
      // Any other top-level key (settings:, lockfileVersion:, etc.)
      section = null;
      continue;
    }

    // Inside packages: section — parse individual package entries
    if (section === 'packages') {
      const indent = line.search(/\S/);

      // A new package key line: exactly 2-space indent with a package identifier
      // v6: /express@4.18.2:  or  /@babel/core@7.24.0:
      // v9: express@4.18.2:   or  '@babel/core@7.24.0':
      if (indent === 2) {
        // Flush previous package
        unresolvedEntries += flushPackage(currentPkg, deps, seen, directInfo);
        const rawKey = parseYamlMapKey(line);
        const coordinate = rawKey === null ? null : parsePnpmPackageKey(rawKey);
        currentPkg = coordinate
          ? { ...coordinate, isDev: false, invalidSource: false, sourceAnchored: false, resolved: null }
          : { invalid: true };
        pkgIndent = indent;
        continue;
      }

      // Properties of the current package (deeper indentation)
      if (currentPkg && indent > pkgIndent) {
        const devMatch = line.trim().match(/^dev:\s*(true|false)/);
        if (devMatch) {
          currentPkg.isDev = devMatch[1] === 'true';
        }
        const resolution = classifyResolution(line.trim(), currentPkg.name, currentPkg.version);
        if (resolution.kind === 'nonregistry') {
          currentPkg.invalidSource = true;
        } else if (resolution.kind === 'public-registry') {
          currentPkg.sourceAnchored = true;
          currentPkg.resolved = resolution.url;
        }
        continue;
      }

      // If we're back at the same or lesser indent without matching a new key,
      // the packages section might have ended or there's unexpected content
      if (currentPkg && indent <= pkgIndent) {
        unresolvedEntries += flushPackage(currentPkg, deps, seen, directInfo);
        currentPkg = null;
        pkgIndent = -1;
      }
    }

    // We intentionally skip the snapshots: section — packages: has what we need
  }

  // Flush any trailing package
  unresolvedEntries += flushPackage(currentPkg, deps, seen, directInfo);

  Object.defineProperty(deps, 'unresolvedEntries', {
    value: unresolvedEntries,
    enumerable: false,
    configurable: true,
  });

  log.debug(`parsed ${deps.length} packages from ${filePath}`);
  return deps;
}

/**
 * Emit a parsed package entry into deps, deduplicating by name@version.
 */
function flushPackage(pkg, deps, seen, directInfo) {
  if (!pkg) return 0;
  if (pkg.invalid || pkg.invalidSource || !pkg.name || !pkg.version) return 1;

  const dedupKey = `${pkg.name}@${pkg.version}`;
  if (seen.has(dedupKey)) return 0;
  seen.add(dedupKey);

  const isDirect = directInfo.directCoordinates.has(dedupKey);
  // Root importer metadata is authoritative for direct dependencies. For
  // transitives, retain pnpm's explicit dev flag.
  const isDev = isDirect
    ? directInfo.devCoordinates.has(dedupKey) && !directInfo.prodCoordinates.has(dedupKey)
    : pkg.isDev;

  deps.push({
    name: pkg.name,
    version: pkg.version,
    ecosystem: 'npm',
    isDev,
    isDirect,
    isPinned: true,
    sourceType: pkg.sourceAnchored ? 'registry' : 'unknown',
    ...(pkg.resolved ? { resolved: pkg.resolved } : {}),
  });
  // Ordinary pnpm package keys and integrity hashes identify a coordinate but
  // not the registry that supplied the bytes. Environment/scoped registry
  // settings are not sealed into the lockfile, so retain the useful OSV
  // coordinate while marking source coverage incomplete unless the entry has
  // an explicit public-registry tarball URL.
  return pkg.sourceAnchored ? 0 : 1;
}

/**
 * Parse a pnpm package-map key, discarding only a well-formed peer context.
 * Example: /react-dom@18.2.0(react@18.2.0) -> react-dom@18.2.0.
 */
function parsePnpmPackageKey(rawKey) {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  let separator;

  if (key.startsWith('@')) {
    const slash = key.indexOf('/');
    separator = slash === -1 ? -1 : key.indexOf('@', slash + 1);
  } else {
    separator = key.indexOf('@');
  }

  if (separator <= 0) return null;
  const name = key.slice(0, separator);
  const version = extractConcreteVersion(key.slice(separator + 1));
  if (!NPM_NAME_RE.test(name) || !version) return null;
  return { name, version };
}

function extractConcreteVersion(rawValue) {
  const value = unquote(String(rawValue).trim());
  const contextStart = value.indexOf('(');
  const version = contextStart === -1 ? value : value.slice(0, contextStart);
  const peerContext = contextStart === -1 ? '' : value.slice(contextStart);
  if (peerContext && !/^(?:\([^()]+\))+$/.test(peerContext)) return null;
  return SEMVER_RE.test(version) ? version : null;
}

/** Return a YAML map key for the small lockfile subset this parser consumes. */
function parseYamlMapKey(line) {
  const value = line.trim();
  const quoted = value.match(/^(['"])(.*?)\1:\s*(?:.*)?$/);
  if (quoted) return quoted[2];
  const plain = value.match(/^([^:]+):\s*(?:.*)?$/);
  return plain ? plain[1].trim() : null;
}

function unquote(value) {
  if (value.length >= 2 && ((value.startsWith("'") && value.endsWith("'"))
      || (value.startsWith('"') && value.endsWith('"')))) {
    return value.slice(1, -1);
  }
  return value;
}

function isNonRegistrySpecifier(value) {
  return NON_REGISTRY_SPEC_RE.test(unquote(String(value).trim()));
}

function classifyResolution(line, name, version) {
  if (/^(?:directory|path):/i.test(line)) return { kind: 'nonregistry' };
  if (/^resolution:\s*\{[^}]*\b(?:directory|path):/i.test(line)) return { kind: 'nonregistry' };

  const tarball = line.match(/(?:^|\b)tarball:\s*([^,}\s]+)/i)?.[1];
  if (!tarball) return { kind: 'unanchored' };
  const value = unquote(tarball);
  if (isCanonicalNpmTarball(value, name, version)) {
    return { kind: 'public-registry', url: value };
  }
  return { kind: 'nonregistry' };
}

/**
 * Collect root dependency classification before parsing package records. pnpm
 * v9 moved these maps under importers["."], while v6 used top-level maps.
 */
function collectDirectDependencyInfo(lines, lockMajor) {
  const prodCoordinates = new Set();
  const devCoordinates = new Set();
  let unresolvedEntries = 0;
  let inImporters = false;
  let inRootImporter = false;
  let category = null;
  let current = null;

  const flush = () => {
    if (!current) return;
    const values = [current.scalar, current.specifier, current.version]
      .filter(value => value !== undefined && value !== '');
    const concreteVersion = extractConcreteVersion(current.version || current.scalar || '');
    const invalid = !NPM_NAME_RE.test(current.name)
      || values.length === 0
      || values.some(isNonRegistrySpecifier)
      || !concreteVersion;

    if (invalid) {
      unresolvedEntries++;
    } else if (current.category === 'devDependencies') {
      devCoordinates.add(`${current.name}@${concreteVersion}`);
    } else {
      prodCoordinates.add(`${current.name}@${concreteVersion}`);
    }
    current = null;
  };

  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const indent = line.search(/\S/);
    const mapKey = parseYamlMapKey(line);

    if (lockMajor === 9) {
      if (indent === 0) {
        flush();
        inImporters = line.trim() === 'importers:';
        inRootImporter = false;
        category = null;
        continue;
      }
      if (!inImporters) continue;
      if (indent === 2) {
        flush();
        inRootImporter = mapKey === '.';
        category = null;
        continue;
      }
      if (!inRootImporter) continue;
      if (indent === 4) {
        flush();
        category = ['dependencies', 'devDependencies', 'optionalDependencies'].includes(mapKey)
          ? mapKey
          : null;
        continue;
      }
      if (category && indent === 6) {
        flush();
        const scalarMatch = line.trim().match(/^(?:['"].*?['"]|[^:]+):\s*(.*)$/);
        current = {
          name: mapKey || '',
          scalar: scalarMatch?.[1] ? unquote(scalarMatch[1].trim()) : undefined,
          category,
        };
        continue;
      }
      if (current && indent > 6) {
        const property = line.trim().match(/^(specifier|version):\s*(.+)$/);
        if (property) current[property[1]] = unquote(property[2].trim());
      }
      continue;
    }

    // pnpm v6 uses top-level dependency maps.
    if (indent === 0) {
      flush();
      category = ['dependencies', 'devDependencies', 'optionalDependencies'].includes(mapKey)
        ? mapKey
        : null;
      continue;
    }
    if (category && indent === 2) {
      flush();
      const scalarMatch = line.trim().match(/^(?:['"].*?['"]|[^:]+):\s*(.*)$/);
      current = {
        name: mapKey || '',
        scalar: scalarMatch?.[1] ? unquote(scalarMatch[1].trim()) : undefined,
        category,
      };
      continue;
    }
    if (current && indent > 2) {
      const property = line.trim().match(/^(specifier|version):\s*(.+)$/);
      if (property) current[property[1]] = unquote(property[2].trim());
    }
  }
  flush();

  return {
    prodCoordinates,
    devCoordinates,
    directCoordinates: new Set([...prodCoordinates, ...devCoordinates]),
    unresolvedEntries,
  };
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
