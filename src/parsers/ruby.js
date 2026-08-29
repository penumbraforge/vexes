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

  if (!/^DEPENDENCIES\s*$/m.test(content) || !/^(?:GEM|GIT|PATH|PLUGIN)\s*$/m.test(content)) {
    throw new Error(`invalid Gemfile.lock schema in ${filePath}: dependency/source sections are missing`);
  }

  const deps = [];
  const lines = content.split('\n');
  let inSpecs = false;
  let sourceSection = null;
  let sourceRemotes = [];
  let unresolvedEntries = 0;
  const seen = new Set();
  const directNames = new Set();
  const checksummedArtifacts = new Set();

  // Bundler 2.6+ can seal resolved gem bytes in a CHECKSUMS section. Without
  // that digest, a configured mirror can serve different bytes for the same
  // name/version while the lockfile still appears to name rubygems.org. Such
  // legacy locks remain useful coordinates for humans, but are not a complete
  // artifact-identity input for an automated clean result.
  let scanChecksums = false;
  for (const line of lines) {
    if (line === 'CHECKSUMS') {
      scanChecksums = true;
      continue;
    }
    if (scanChecksums && line.length > 0 && !line.startsWith(' ')) {
      scanChecksums = false;
      continue;
    }
    if (!scanChecksums) continue;
    const checksum = line.match(/^\s{2}(\S+)\s+\(([^)]+)\)\s+sha256=([0-9a-f]{64})(?:\s|$)/i);
    if (checksum) checksummedArtifacts.add(`${checksum[1]}@${checksum[2]}`);
  }

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
      if (m) directNames.add(m[1].replace(/!$/, ''));
    }
  }

  // Second pass: parse source sections. Only GEM entries whose remote is the
  // canonical public RubyGems registry are OSV-addressable RubyGems artifacts.
  // GIT/PATH/PLUGIN and custom GEM remotes are recorded as unresolved.
  for (const line of lines) {
    const section = line.match(/^(GEM|GIT|PATH|PLUGIN)$/)?.[1] || null;
    if (section) {
      sourceSection = section;
      sourceRemotes = [];
      inSpecs = false;
      continue;
    }
    const remote = line.match(/^\s{2}remote:\s*(\S.*?)\s*$/)?.[1];
    if (remote && sourceSection) {
      sourceRemotes.push(remote.replace(/\/$/, ''));
      continue;
    }
    if (/^\s{2}specs:$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (line === 'DEPENDENCIES') {
      sourceSection = null;
      inSpecs = false;
      continue;
    }
    // Any non-indented, non-empty line starts a new section
    if (line.length > 0 && !line.startsWith(' ')) {
      inSpecs = false;
      sourceSection = null;
      continue;
    }

    if (inSpecs) {
      // Package entries are at exactly 4-space indent: "    name (version)"
      // Sub-dependencies are at 6+ spaces — skip those
      const m = line.match(/^    (\S+)\s+\(([^)]+)\)$/);
      if (m) {
        const [, name, version] = m;
        const publicRubyGems = sourceSection === 'GEM' && sourceRemotes.length > 0 &&
          sourceRemotes.every(value => value === 'https://rubygems.org');
        const key = `${name}@${version}`;
        if (!publicRubyGems || !/^\d+(?:\.\d+)+(?:[-.][0-9A-Za-z.\-]+)?$/.test(version) ||
            !checksummedArtifacts.has(key)) {
          unresolvedEntries++;
          continue;
        }
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push({
          name,
          version,
          ecosystem: 'ruby',
          isDirect: directNames.has(name),
          isPinned: true,
          sourceType: 'registry',
        });
      }
    }
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachParserStatus(deps, unresolvedEntries);
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
  let unresolvedEntries = 0;
  const declaredSources = [...content.matchAll(/^\s*source\s+['"]([^'"]+)['"]/gm)]
    .map(match => match[1].replace(/\/$/, ''));
  const publicGlobalSource = declaredSources.length > 0 &&
    declaredSources.every(source => source === 'https://rubygems.org');

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

    const explicitSource = rest.match(/\bsource:\s*['"]([^'"]+)['"]/)?.[1]?.replace(/\/$/, '') || null;
    const nonRegistrySource = /\b(?:git|github|gitlab|gist|path):\s*/.test(rest);
    const publicSource = explicitSource
      ? explicitSource === 'https://rubygems.org'
      : publicGlobalSource;

    // A manifest constraint is not the resolved version. Querying OSV with
    // the lower bound of `~>`, `>=`, etc. can produce both false positives and
    // false negatives, so fallback mode accepts exact pins only.
    if (!version || !isPinnedVersionSpec(versionSpec, version) || nonRegistrySource || !publicSource) {
      unresolvedEntries++;
      continue;
    }

    const dedupKey = `${name}@${version}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    deps.push({
      name,
      version,
      ecosystem: 'ruby',
      isDirect: true,
      isPinned: true,
      sourceType: 'registry',
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  attachParserStatus(deps, unresolvedEntries);
  return deps;
}

function attachParserStatus(deps, unresolvedEntries) {
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    value: unresolvedEntries,
  });
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
