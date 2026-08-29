import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

// mix.lock entry:
//   "plug": {:hex, :plug, "1.16.0", "HASH", [:mix], [], "hexpm", "CONTENT-HASH", 1714839488, %{}, []}
// We only care about `:hex` packages (git deps are not published to Hex).
const ENTRY_START_RE = /^[ \t]*"([^"]+)":[ \t]*\{:([A-Za-z0-9_]+)/gm;
const HEX_VERSION_RE = /^\s*"[^"]+":\s*\{:hex,\s*:[A-Za-z0-9_@.\-!?]+,\s*"([^"]+)"/;

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

  const trimmed = raw.trim();
  if (!trimmed.startsWith('%{') || !trimmed.endsWith('}')) {
    throw new Error(`invalid mix.lock schema in ${lockfilePath}: expected an Elixir map`);
  }

  const deps = [];
  const seen = new Set();
  let unresolvedEntries = 0;
  ENTRY_START_RE.lastIndex = 0;
  const entries = [...raw.matchAll(ENTRY_START_RE)];
  for (let i = 0; i < entries.length; i++) {
    const match = entries[i];
    const [, name, sourceType] = match;
    const segment = raw.slice(match.index, entries[i + 1]?.index ?? raw.lastIndexOf('}'));
    const version = segment.match(HEX_VERSION_RE)?.[1] || null;
    const publicHex = sourceType === 'hex' && /,\s*"hexpm"\s*,/.test(segment);
    if (!publicHex || !/^\d+\.\d+\.\d+/.test(version || '')) {
      unresolvedEntries++;
      continue;
    }
    const key = `hex:${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deps.push({ name, version, ecosystem: 'hex', isDev: false, isDirect: null });
  }
  Object.defineProperty(deps, 'unresolvedEntries', {
    enumerable: false,
    value: unresolvedEntries,
  });
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
