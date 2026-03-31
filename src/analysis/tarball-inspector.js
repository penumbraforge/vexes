import { createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { log } from '../core/logger.js';
import { inspectJS, inspectPython } from './ast-inspector.js';
import { FETCH_TIMEOUT_MS, USER_AGENT } from '../core/constants.js';

/**
 * Tarball AST inspector — downloads an npm package tarball and inspects
 * the actual source code, not just install script strings.
 *
 * This catches malware that lives in the package's .js files, not in the
 * package.json scripts field. The axios RAT payload was in plain-crypto-js's
 * actual code, not in a postinstall string.
 *
 * Uses native Node.js tar parsing (no tar dependency) — reads the raw
 * POSIX tar format from the gunzipped stream.
 */

// Files worth inspecting in a package tarball
// JS files worth inspecting in an npm tarball
const JS_INSPECTABLE = [
  /\/index\.js$/, /\/index\.mjs$/,
  /\/main\.js$/, /\/cli\.js$/,
  /\/bin\/[^/]+\.js$/,
  /\/install\.js$/, /\/postinstall\.js$/, /\/preinstall\.js$/,
  /\/setup\.js$/, /\/loader\.js$/,
  /\/dist\/index\.js$/, /\/lib\/index\.js$/,
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
// Max tarball download size (compressed)
const MAX_TARBALL_SIZE = 5 * 1024 * 1024; // 5MB
// Max decompressed size — prevents gzip bombs (a 46-byte gzip can decompress to 4.5PB)
const MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024; // 50MB

/**
 * Download and inspect an npm package tarball for dangerous code patterns.
 *
 * @param {string} tarballUrl — URL from npm registry metadata (versions[ver].dist.tarball)
 * @param {string} packageName — for logging
 * @returns {Promise<TarballInspectionResult>}
 */
export async function inspectTarball(tarballUrl, packageName) {
  const findings = [];
  const inspectedFiles = [];
  const warnings = [];

  try {
    const files = await downloadAndExtractJS(tarballUrl, packageName);

    if (files.length === 0) {
      log.debug(`no inspectable JS files found in tarball for ${packageName}`);
      return { findings, inspectedFiles, capabilities: {}, warnings };
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

  return { findings, inspectedFiles, capabilities, warnings };
}

/**
 * Download a tarball and extract JS files that match our inspection patterns.
 * Uses zero external dependencies — native gunzip + raw tar header parsing.
 */
async function downloadAndExtractJS(tarballUrl, packageName) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let res;
  try {
    res = await fetch(tarballUrl, {
      headers: { 'User-Agent': USER_AGENT },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching tarball for ${packageName}`);
  }

  // Enforce size limit
  const contentLength = parseInt(res.headers.get('content-length') || '0', 10);
  if (contentLength > MAX_TARBALL_SIZE) {
    throw new Error(`tarball too large (${contentLength} bytes) for ${packageName}`);
  }

  const compressed = Buffer.from(await res.arrayBuffer());
  if (compressed.length > MAX_TARBALL_SIZE) {
    throw new Error(`tarball too large (${compressed.length} bytes) for ${packageName}`);
  }

  // Gunzip
  const decompressed = await gunzip(compressed);

  // Parse tar
  const files = parseTar(decompressed, packageName);
  return files;
}

/**
 * Gunzip a buffer using Node's native zlib.
 * Enforces a decompressed size limit to prevent gzip bombs.
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
 */
function parseTar(buffer, packageName) {
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
    const name = header.subarray(0, Math.min(nameEnd, 100)).toString('utf8');

    // Extract file size (bytes 124-135, octal)
    const sizeStr = header.subarray(124, 136).toString('utf8').trim();
    const size = parseInt(sizeStr, 8) || 0;

    // Extract type flag (byte 156): '0' or '\0' = regular file
    const typeFlag = header[156];
    const isFile = typeFlag === 48 || typeFlag === 0; // '0' or NUL

    // Check prefix field (bytes 345-499) for long paths (UStar format)
    const prefixEnd = header.indexOf(0, 345);
    const prefix = header.subarray(345, Math.min(prefixEnd, 500)).toString('utf8');
    const fullPath = prefix ? `${prefix}/${name}` : name;

    // Strip the leading "package/" that npm tarballs always have
    const relativePath = fullPath.replace(/^package\//, '');

    offset += 512; // Move past header

    if (isFile && size > 0) {
      // Check if this file matches our inspection patterns
      const shouldInspect = size <= MAX_INSPECT_SIZE &&
        fileCount < MAX_FILES &&
        INSPECTABLE_PATTERNS.some(p => p.test('/' + relativePath));

      if (shouldInspect) {
        const content = buffer.subarray(offset, offset + size).toString('utf8');
        files.push({ path: relativePath, content, size });
        fileCount++;
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
    const data = await (await fetch(
      `https://pypi.org/pypi/${encodeURIComponent(normalized)}/${encodeURIComponent(version)}/json`,
      { headers: { 'User-Agent': USER_AGENT } }
    )).json();

    // Find the sdist (.tar.gz) URL — preferred for source inspection
    const urls = data.urls || [];
    const sdist = urls.find(u => u.packagetype === 'sdist');
    if (sdist) return sdist.url;

    // Fall back to first available file
    return urls[0]?.url || null;
  } catch {
    return null;
  }
}
