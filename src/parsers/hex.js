import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

// mix.lock entry:
//   "plug": {:hex, :plug, "1.16.0", "HASH", [:mix], [], "hexpm", "CONTENT-HASH", 1714839488, %{}, []}
// We only care about `:hex` packages (git deps are not published to Hex).
const ENTRY_RE = /^[ \t]*"([^"]+)":[ \t]*\{:hex,[ \t]*:[A-Za-z0-9_@.\-!?]+,[ \t]*"([^"]+)"/gm;

/**
 * Parse an Elixir mix.lock into a dependency list (Hex ecosystem).
 * Only pinned hex packages are returned; `:git` deps are skipped — they have
 * no Hex version/release to look up in OSV.
 *
 * @param {string} lockfilePath — absolute path to mix.lock
 * @returns {Array<{name, version, ecosystem: 'hex', isDev, isDirect}>}
 */
export function parseLockfile(lockfilePath) {
  let raw;
  try {
    raw = readFileSync(lockfilePath, 'utf8');
  } catch (err) {
    throw new Error(`cannot read ${lockfilePath}: ${err.code || err.message}`);
  }

  const deps = [];
  const seen = new Set();
  let m;
  ENTRY_RE.lastIndex = 0;
  while ((m = ENTRY_RE.exec(raw)) !== null) {
    const [, name, version] = m;
    if (!/^\d+\.\d+\.\d+/.test(version)) continue; // must be a concrete pinned release
    const key = `hex:${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deps.push({ name, version, ecosystem: 'hex', isDev: false, isDirect: null });
  }
  return deps;
}

export function discover(dir) {
  const p = join(dir, 'mix.lock');
  return { lockfiles: existsSync(p) ? [p] : [], manifests: [] };
}

export function parseFile(filePath) {
  try { return parseLockfile(filePath); }
  catch (err) { log.debug(`hex parse failed: ${err.message}`); return []; }
}
