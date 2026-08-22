import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

// pubspec.lock is indented YAML under `packages:`. Entry shape:
//   <name>:
//     dependency: "direct main" | transitive
//     description:
//       name: <name>
//       url: "https://pub.dev"
//     source: hosted
//     version: "2.4.2"
// Line-based: two-space package names under `packages:`, four-space fields.
const PACKAGE_RE = /^ {2}([A-Za-z0-9_.-]+):\s*$/;
const VERSION_RE = /^ {4}version: "([^"]+)"/;
const DEPENDENT_RE = /^ {4}dependency: "?([A-Za-z ]+)"?/;

/**
 * Parse a Dart pubspec.lock into a dependency list (Pub ecosystem).
 *
 * @param {string} lockfilePath — absolute path to pubspec.lock
 * @returns {Array<{name, version, ecosystem: 'pub', isDev, isDirect}>}
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
  let current = null;
  for (const line of raw.split('\n')) {
    if (line === 'packages:' || line.startsWith('packages: ')) continue; // header
    if (line.startsWith('sdks:')) break;                                 // past package list

    const indent = line.match(/^ +/)?.[0].length ?? 0;
    if (indent === 2) {
      const pm = line.match(PACKAGE_RE);
      if (pm) {
        if (current?.name && current?.version) flush(current); // boundary: flush prior pkg
        current = { name: pm[1], version: null, isDirect: null };
      }
      continue;
    }
    if (indent === 4 && current) {
      const vs = line.match(VERSION_RE);
      if (vs) { current.version = vs[1]; continue; }
      const ds = line.match(DEPENDENT_RE);
      if (ds) current.isDirect = ds[1].trim().startsWith('direct');
    }
    // indent 6 (description: block) and sdks section are ignored harmlessly
  }

  if (current?.name && current?.version) flush(current);

  function flush(c) {
    if (!/^\d+\.\d+\.\d+/.test(c.version)) return; // must be a concrete release
    const key = `pub:${c.name}@${c.version}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({
      name: c.name,
      version: c.version,
      ecosystem: 'pub',
      isDev: c.isDirect === false,
      isDirect: c.isDirect,
    });
  }

  return deps;
}

export function discover(dir) {
  const p = join(dir, 'pubspec.lock');
  return { lockfiles: existsSync(p) ? [p] : [], manifests: [] };
}

export function parseFile(filePath) {
  try { return parseLockfile(filePath); }
  catch (err) { log.debug(`pub parse failed: ${err.message}`); return []; }
}
