import { createGunzip } from 'node:zlib';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { log } from '../core/logger.js';
import { inspectJS, inspectPython } from './ast-inspector.js';
import { FETCH_TIMEOUT_MS, USER_AGENT, PYPI_JSON_URL } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';

/**
 * Tarball source-pattern inspector — downloads an npm/PyPI archive and
 * examines a bounded set of selected entry/install-like files. This adds
 * evidence beyond inline package-manager script strings; it is not exhaustive
 * package review or malware detection.
 *
 * Uses native Node.js tar parsing (no tar dependency) — reads the raw
 * POSIX tar format from the gunzipped stream.
 */

// Files worth inspecting in a package tarball
// JS files worth inspecting in an npm tarball
const JS_INSPECTABLE = [
  /\/index\.js$/, /\/index\.mjs$/, /\/index\.cjs$/,
  /\/main\.js$/, /\/main\.mjs$/, /\/main\.cjs$/,
  /\/cli\.js$/, /\/cli\.mjs$/, /\/cli\.cjs$/,
  /\/bin\/[^/]+\.(?:js|mjs|cjs)$/,
  /\/install\.js$/, /\/postinstall\.js$/, /\/preinstall\.js$/, /\/prepare\.js$/,
  /\/setup\.js$/, /\/loader\.js$/,
  /\/dist\/index\.(?:js|mjs|cjs)$/, /\/lib\/index\.(?:js|mjs|cjs)$/,
];

// Python files worth inspecting in an sdist tarball
const PY_INSPECTABLE = [
  /\/setup\.py$/, /\/__init__\.py$/,
  /\/cli\.py$/, /\/main\.py$/,
  /\/__main__\.py$/,
  /\/conftest\.py$/,  // Can run arbitrary code on import
];

const INSPECTABLE_PATTERNS = [...JS_INSPECTABLE, ...PY_INSPECTABLE];

// Max file size to inspect (skip huge bundled files)
const MAX_INSPECT_SIZE = 512 * 1024; // 512KB
// Max total files to inspect per package
const MAX_FILES = 10;
const MAX_ARCHIVE_FILES = 5000;
const MAX_EXTRACT_FILE_SIZE = 10 * 1024 * 1024;
// Max tarball download size (compressed)
const MAX_TARBALL_SIZE = 5 * 1024 * 1024; // 5MB
// Max accepted decompressed size — bounds expansion and memory use.
const MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024; // 50MB

// Allowed tarball host domains — constrains SSRF exposure from registry responses.
const ALLOWED_TARBALL_HOSTS = new Set([
  'registry.npmjs.org',
  'files.pythonhosted.org',
]);

/**
 * Collect JavaScript runtime entrypoints from npm package metadata.
 * Conditional export maps often include `types` declarations alongside the
 * executable entry. Feeding `.d.ts` into Acorn creates a loud parse failure
 * that says nothing about runtime behavior, so type-only conditions and
 * TypeScript declaration/source paths are excluded from the JS sample.
 */
export function collectInspectableEntrypoints(pkgData = {}) {
  const entries = [];
  const add = (value) => {
    if (typeof value !== 'string') return;
    const pathOnly = value.split(/[?#]/, 1)[0];
    if (/\.(?:d\.)?(?:ts|tsx|mts|cts)$/i.test(pathOnly)) return;
    entries.push(value);
  };

  add(pkgData.main);
  if (typeof pkgData.bin === 'string') {
    add(pkgData.bin);
  } else if (pkgData.bin && typeof pkgData.bin === 'object') {
    for (const value of Object.values(pkgData.bin)) add(value);
  }

  const visitExports = (value) => {
    if (typeof value === 'string') {
      add(value);
      return;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    for (const [condition, target] of Object.entries(value)) {
      if (condition === 'types' || condition === 'typings') continue;
      visitExports(target);
    }
  };
  visitExports(pkgData.exports);
  return [...new Set(entries)];
}

/**
 * Download and inspect an npm package tarball for dangerous code patterns.
 *
 * @param {string} tarballUrl — URL from npm registry metadata (versions[ver].dist.tarball)
 * @param {string} packageName — for logging
 * @returns {Promise<TarballInspectionResult>}
 */
export async function inspectTarball(tarballUrl, packageName, artifact = {}) {
  const findings = [];
  const inspectedFiles = [];
  const warnings = [];
  let eligibleFiles = 0;
  let archiveFiles = 0;
  let oversizeFiles = 0;
  let digestVerified = false;

  try {
    const selection = await downloadAndExtractJS(tarballUrl, packageName, artifact);
    const files = selection.files;
    eligibleFiles = selection.eligibleFiles;
    archiveFiles = selection.archiveFiles;
    oversizeFiles = selection.oversizeFiles;
    digestVerified = selection.digestVerified;
    if (!digestVerified) {
      warnings.push('registry artifact digest was unavailable; downloaded bytes were not digest-verified');
    }
    warnings.push(
      `bounded source sampling inspected ${files.length} of ${selection.eligibleFiles} selected entry/install files ` +
      `from ${selection.archiveFiles} archive files` +
      `${selection.oversizeFiles ? `; ${selection.oversizeFiles} candidate file(s) exceeded ${MAX_INSPECT_SIZE} bytes` : ''}; ` +
      `this is not full-package coverage`,
    );

    if (files.length === 0) {
      log.debug(`no inspectable JS files found in tarball for ${packageName}`);
      return {
        findings, inspectedFiles, capabilities: {}, warnings,
        coverage: {
          mode: 'bounded-source-sampling', packageComplete: false, inspectedFiles: 0,
          eligibleFiles: selection.eligibleFiles, archiveFiles: selection.archiveFiles,
          oversizeFiles: selection.oversizeFiles,
          digestVerified,
        },
      };
    }

    log.debug(`inspecting ${files.length} files from ${packageName} tarball`);

    for (const file of files) {
      try {
        // Route to the appropriate inspector based on file extension
        const isPython = file.path.endsWith('.py');
        const result = isPython
          ? inspectPython(file.content, `${packageName}/${file.path}`)
          : inspectJS(file.content, `${packageName}/${file.path}`);
        inspectedFiles.push(file.path);

        for (const finding of result.findings) {
          findings.push({
            ...finding,
            file: file.path,
            description: `[${file.path}] ${finding.description}`,
          });
        }
      } catch (err) {
        log.debug(`AST inspection failed for ${packageName}/${file.path}: ${err.message}`);
        warnings.push(`inspection failed for ${file.path}: ${err.message}`);
      }
    }
  } catch (err) {
    log.debug(`tarball inspection failed for ${packageName}: ${err.message}`);
    warnings.push(`tarball download/extraction failed: ${err.message}`);
  }

  // Build aggregate capabilities from all files
  const allPatterns = new Set(findings.map(f => f.pattern));
  const capabilities = {
    executesCode: allPatterns.has('CODE_EXECUTION'),
    spawnsProcess: allPatterns.has('PROCESS_SPAWN'),
    accessesNetwork: allPatterns.has('NETWORK_ACCESS'),
    writesFilesystem: allPatterns.has('FILESYSTEM_WRITE') || allPatterns.has('SYSTEM_PATH_WRITE'),
    writesSystemPaths: allPatterns.has('SYSTEM_PATH_WRITE'),
    readsCredentials: allPatterns.has('ENV_HARVESTING'),
    decodesPayloads: allPatterns.has('BASE64_DECODE'),
    selfDeletes: allPatterns.has('SELF_DELETION'),
    dynamicLoading: allPatterns.has('DYNAMIC_REQUIRE') || allPatterns.has('DYNAMIC_IMPORT'),
    possibleObfuscation: allPatterns.has('POSSIBLE_OBFUSCATION'),
  };

  return {
    findings, inspectedFiles, capabilities, warnings,
    coverage: {
      mode: 'bounded-source-sampling',
      packageComplete: false,
      inspectedFiles: inspectedFiles.length,
      eligibleFiles,
      archiveFiles,
      oversizeFiles,
      digestVerified,
    },
  };
}

/**
 * Validate a tarball URL as one SSRF mitigation.
 * Only allows HTTPS URLs from known registry hosts.
 */
function validateTarballUrl(tarballUrl) {
  let parsed;
  try {
    parsed = new URL(tarballUrl);
  } catch {
    throw new Error(`invalid tarball URL: ${tarballUrl}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`tarball URL must use HTTPS, got ${parsed.protocol} (${tarballUrl})`);
  }

  if (!ALLOWED_TARBALL_HOSTS.has(parsed.hostname)) {
    throw new Error(`tarball host "${parsed.hostname}" is not in the allowed list (${[...ALLOWED_TARBALL_HOSTS].join(', ')})`);
  }
}

/**
 * Download + decompress a tarball in one bounded step (shared by the memory
 * AST path and the disk extraction path). Enforces the same URL allowlist
 * host/protocol restriction, Content-Length cap, streamed size cap, and expansion bound.
 */
async function fetchDecompressed(tarballUrl, packageName, artifact = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    // Follow redirects manually so every hop remains HTTPS and on an allowed
    // registry host. Native fetch's default redirect mode would validate only
    // the attacker-controlled initial URL, then happily follow Location to an
    // internal address.
    let currentUrl = tarballUrl;
    let res;
    for (let redirects = 0; redirects <= 5; redirects++) {
      validateTarballUrl(currentUrl);
      res = await fetch(currentUrl, {
        headers: { 'User-Agent': USER_AGENT },
        signal: controller.signal,
        redirect: 'manual',
      });
      if (![301, 302, 303, 307, 308].includes(res.status)) break;
      const location = res.headers.get('location');
      if (!location) throw new Error(`tarball redirect omitted Location for ${packageName}`);
      if (redirects === 5) throw new Error(`too many tarball redirects for ${packageName}`);
      currentUrl = new URL(location, currentUrl).toString();
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} fetching tarball for ${packageName}`);
    }

    // Pre-check Content-Length if available
    const contentLength = parseInt(res.headers.get('content-length') || '0', 10);
    if (contentLength > MAX_TARBALL_SIZE) {
      throw new Error(`tarball too large (${contentLength} bytes) for ${packageName}`);
    }

    // Keep the same abort signal active through body consumption. A response
    // that sends headers and then stalls must not evade the timeout.
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of res.body) {
      totalBytes += chunk.length;
      if (totalBytes > MAX_TARBALL_SIZE) {
        controller.abort();
        throw new Error(`tarball download exceeded ${MAX_TARBALL_SIZE} bytes for ${packageName} — aborted`);
      }
      chunks.push(chunk);
    }
    const compressed = Buffer.concat(chunks);
    if (artifact.integrity || artifact.shasum) {
      verifyArtifactDigest(compressed, artifact, packageName);
    }
    return gunzip(compressed);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Download a tarball and extract its files to a fresh directory on disk.
 * Used by the dynamic-sandbox harness: we need real files to run, not just
 * AST strings. Same SSRF gate + size caps as the memory path; each entry is
 * written through `safeJoin` so a malicious tar cannot escape destDir.
 *
 * @param {string} tarballUrl — from registry metadata (versions[ver].dist.tarball)
 * @param {string} packageName — for logging/errors
 * @param {string} destDir — must already exist (caller's mkdtemp)
 * @returns {Promise<string[]>} absolute paths written
 */
export async function downloadAndExtractToDisk(tarballUrl, packageName, destDir, artifact = {}) {
  if (!artifact.integrity && !artifact.shasum) {
    throw new Error(`refusing dynamic extraction for ${packageName}: registry artifact digest is unavailable`);
  }
  const decompressed = await fetchDecompressed(tarballUrl, packageName, artifact);
  const entries = parseTar(decompressed, packageName, true /* returnAll */);
  const written = [];
  for (const entry of entries) {
    const target = safeJoin(destDir, entry.path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, entry.content);
    written.push(target);
  }
  return written;
}

/**
 * Join a tar entry path onto a destination root, rejecting anything that could
 * escape it. Tar spec allows ../ and absolute paths; without this guard a
 * malicious archive would overwrite files outside the unpack dir. Also blocks
 * NULs and Windows drive escapes (belt-and-braces even on POSIX-only crates).
 * @param {string} root — absolute destination dir
 * @param {string} candidate — entry path as read from the tar header
 * @returns {string} absolute path inside root
 * @throws {Error} on any traversal / escape / NUL
 */
function safeJoin(root, candidate) {
  if (typeof candidate !== 'string' || candidate.length === 0) throw new Error('empty tar entry path');
  if (candidate.includes('\0')) throw new Error(`NUL byte in tar path: ${candidate}`);
  if (candidate.startsWith('/') || /^[A-Za-z]:[\\/]/.test(candidate)) throw new Error(`absolute tar path: ${candidate}`);
  if (candidate.split(/[/\\]+/).some(part => part === '..')) throw new Error(`traversal in tar path: ${candidate}`);
  const out = resolve(root, candidate.replace(/^\.\/+/, ''));
  if (!out.startsWith(`${resolve(root)}${'/'}`)) throw new Error(`escape from ${root}: ${candidate}`);
  return out;
}

/**
 * Download a tarball and extract JS files that match our inspection patterns.
 * Uses zero external dependencies — native gunzip + raw tar header parsing.
 *
 * Security: constrains URL destinations and bounds streamed input/memory use.
 */
async function downloadAndExtractJS(tarballUrl, packageName, artifact = {}) {
  const decompressed = await fetchDecompressed(tarballUrl, packageName, artifact);

  // Parse tar — first pass extracts package.json to find entry points,
  // second pass uses those entry points plus static patterns
  const allEntries = parseTar(decompressed, packageName, true /* returnAll */);
  const pkgJsonEntry = allEntries.find(f => f.path === 'package.json');

  // Extract additional file patterns from package.json main/bin/exports fields
  const extraPatterns = [];
  if (pkgJsonEntry) {
    try {
      const pkgData = JSON.parse(pkgJsonEntry.content.toString('utf8'));
      extraPatterns.push(...collectInspectableEntrypoints(pkgData));
    } catch { /* malformed package.json — proceed with static patterns */ }
  }

  // Build the final file list from static patterns + dynamic package.json refs
  const candidates = allEntries.filter(f => {
    if (f.path === 'package.json') return false; // Already used for metadata
    // Match static inspectable patterns
    if (INSPECTABLE_PATTERNS.some(p => p.test('/' + f.path))) return true;
    // Match dynamic patterns from package.json
    const normalized = f.path.replace(/^\.\//, '');
    return extraPatterns.some(ep => {
      const norm = ep.replace(/^\.\//, '');
      return normalized === norm || normalized.endsWith('/' + norm);
    });
  });
  const eligible = candidates.filter(file => file.size <= MAX_INSPECT_SIZE);
  const files = eligible.slice(0, MAX_FILES).map(file => ({
    ...file,
    content: file.content.toString('utf8'),
  }));

  return {
    files,
    eligibleFiles: eligible.length,
    archiveFiles: allEntries.length,
    oversizeFiles: candidates.length - eligible.length,
    digestVerified: !!(artifact.integrity || artifact.shasum),
  };
}

/**
 * Verify compressed registry bytes against npm SRI (preferred) or the legacy
 * SHA-1 shasum. Throws on malformed/unsupported evidence or any mismatch.
 */
export function verifyArtifactDigest(buffer, artifact = {}, packageName = 'package') {
  if (artifact.integrity) {
    const tokens = String(artifact.integrity).trim().split(/\s+/).filter(Boolean);
    const supported = [];
    const strength = { sha1: 1, sha256: 2, sha384: 3, sha512: 4 };
    for (const token of tokens) {
      const match = token.match(/^(sha(?:1|256|384|512))-([A-Za-z0-9+/=_-]+)(?:\?.*)?$/i);
      if (!match) continue;
      const algorithm = match[1].toLowerCase();
      const expected = Buffer.from(match[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      if (expected.length > 0) supported.push({ algorithm, expected });
    }

    if (supported.length === 0) throw new Error(`unsupported or malformed registry integrity for ${packageName}`);

    // Follow SRI's strongest-algorithm rule. A matching sha1 token must not
    // override a mismatching sha512 token in the same integrity value.
    const strongest = Math.max(...supported.map(item => strength[item.algorithm]));
    for (const { algorithm, expected } of supported) {
      if (strength[algorithm] !== strongest) continue;
      const actual = createHash(algorithm).update(buffer).digest();
      if (actual.equals(expected)) return true;
    }
    throw new Error(`registry integrity mismatch for ${packageName}`);
  }

  if (artifact.shasum) {
    const expected = String(artifact.shasum).trim().toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(expected)) {
      throw new Error(`malformed registry shasum for ${packageName}`);
    }
    const actual = createHash('sha1').update(buffer).digest('hex');
    if (actual === expected) return true;
    throw new Error(`registry shasum mismatch for ${packageName}`);
  }

  return false;
}

/**
 * Gunzip a buffer using Node's native zlib.
 * Enforces a decompressed size limit to bound archive expansion.
 */
function gunzip(buffer) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    const gunzipper = createGunzip();
    gunzipper.on('data', chunk => {
      totalSize += chunk.length;
      if (totalSize > MAX_DECOMPRESSED_SIZE) {
        gunzipper.destroy(new Error(`decompressed size exceeds ${MAX_DECOMPRESSED_SIZE} bytes — possible gzip bomb`));
        return;
      }
      chunks.push(chunk);
    });
    gunzipper.on('end', () => resolve(Buffer.concat(chunks)));
    gunzipper.on('error', reject);
    gunzipper.end(buffer);
  });
}

/**
 * Minimal POSIX tar parser — extracts files matching our inspection patterns.
 * No external dependency, just raw 512-byte header parsing.
 *
 * @param {Buffer} buffer — decompressed tar data
 * @param {string} packageName — for logging
 * @param {boolean} returnAll — if true, return ALL text files (for package.json parsing)
 */
function parseTar(buffer, packageName, returnAll = false) {
  const files = [];
  let offset = 0;
  let fileCount = 0;

  while (offset < buffer.length - 512) {
    // Read 512-byte tar header
    const header = buffer.subarray(offset, offset + 512);

    // Check for end-of-archive (two zero blocks)
    if (header.every(b => b === 0)) break;

    // Extract filename (bytes 0-99, null-terminated)
    const nameEnd = header.indexOf(0, 0);
    const name = header.subarray(0, nameEnd === -1 ? 100 : Math.min(nameEnd, 100)).toString('utf8');

    // Extract file size (bytes 124-135, octal)
    const sizeStr = header.subarray(124, 136).toString('utf8').trim();
    const size = parseInt(sizeStr, 8) || 0;

    // Guard against integer overflow — a malicious tar header with a huge size
    // would corrupt offset calculations and read from wrong positions
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_DECOMPRESSED_SIZE) {
      break; // Treat as end of archive
    }

    // Extract type flag (byte 156): '0' or '\0' = regular file
    const typeFlag = header[156];
    const isFile = typeFlag === 48 || typeFlag === 0; // '0' or NUL

    // Check prefix field (bytes 345-499) for long paths (UStar format)
    const prefixEnd = header.indexOf(0, 345);
    const prefix = header.subarray(345, prefixEnd === -1 ? 500 : Math.min(prefixEnd, 500)).toString('utf8');
    const fullPath = prefix ? `${prefix}/${name}` : name;

    // Strip the leading "package/" that npm tarballs always have
    const relativePath = fullPath.replace(/^package\//, '');

    offset += 512; // Move past header

    if (offset + size > buffer.length) break;

    if (isFile && size >= 0) {
      if (returnAll) {
        // Disk extraction needs a coherent package tree, not the first thirty
        // text files. The decompressed archive already has a global 50 MiB
        // bound; retain binary bytes and cap pathological file counts/sizes.
        if (fileCount < MAX_ARCHIVE_FILES && size <= MAX_EXTRACT_FILE_SIZE) {
          const content = Buffer.from(buffer.subarray(offset, offset + size));
          files.push({ path: relativePath, content, size });
          fileCount++;
        }
      } else {
        // Legacy mode: only extract files matching static patterns
        const shouldInspect = fileCount < MAX_FILES &&
          INSPECTABLE_PATTERNS.some(p => p.test('/' + relativePath));

        if (shouldInspect) {
          const content = buffer.subarray(offset, offset + size).toString('utf8');
          files.push({ path: relativePath, content, size });
          fileCount++;
        }
      }
    }

    // Advance past file data (padded to 512-byte blocks)
    offset += Math.ceil(size / 512) * 512;
  }

  return files;
}

/**
 * Get the tarball URL from npm registry metadata.
 */
export function getTarballUrl(registryMetadata, version) {
  const name = registryMetadata?.name;
  if (!name || !version) return null;

  // Prefer the exact artifact URL returned for the anchored registry version.
  // Constructing a conventional URL can point at a different host/path than
  // the registry actually attested in its packument.
  const anchored = registryMetadata?.tarball || registryMetadata?.artifact?.tarball;
  if (anchored) {
    try {
      validateTarballUrl(anchored);
      return anchored;
    } catch {
      return null;
    }
  }

  // npm tarball URL convention: registry.npmjs.org/{name}/-/{basename}-{version}.tgz
  const basename = name.startsWith('@') ? name.split('/')[1] : name;
  return `https://registry.npmjs.org/${name}/-/${basename}-${version}.tgz`;
}

/**
 * Get PyPI sdist tarball URL. Fetches the release files JSON to find the .tar.gz URL.
 */
export async function getPypiTarballUrl(packageName, version) {
  const normalized = packageName.toLowerCase().replace(/[._]/g, '-');
  try {
    const data = await fetchJSON(
      `${PYPI_JSON_URL}/${encodeURIComponent(normalized)}/${encodeURIComponent(version)}/json`,
      { timeout: FETCH_TIMEOUT_MS },
    );

    // Find the sdist (.tar.gz) URL — preferred for source inspection
    const urls = data.urls || [];
    const sdist = urls.find(u => u.packagetype === 'sdist');
    const url = sdist?.url || urls[0]?.url || null;

    // Validate the URL before returning — constrain destination exposure.
    if (url) {
      try { validateTarballUrl(url); } catch { return null; }
    }
    return url;
  } catch {
    return null;
  }
}
