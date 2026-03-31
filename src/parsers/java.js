import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../core/logger.js';

/**
 * Parse gradle.lockfile into dependency list.
 *
 * Format:
 *   # comment lines
 *   group:artifact:version=configurations
 *   empty=
 *
 * Skip comment lines (starting with #) and the "empty=" marker.
 * name = group:artifact, version = the version segment.
 */
export function parseLockfile(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) continue;
    if (trimmed === 'empty=' || trimmed.startsWith('empty=')) continue;

    // Format: group:artifact:version=configurations
    const eqIdx = trimmed.indexOf('=');
    const coordinate = eqIdx !== -1 ? trimmed.slice(0, eqIdx) : trimmed;

    const parts = coordinate.split(':');
    if (parts.length < 3) continue;

    const version = parts[parts.length - 1];
    const name = parts.slice(0, parts.length - 1).join(':');

    if (!name || !version) continue;

    deps.push({
      name,
      version,
      ecosystem: 'java',
      isDirect: false,
      isPinned: true,
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

/**
 * Basic pom.xml dependency extraction using regex.
 *
 * Extracts <dependency> blocks containing <groupId>, <artifactId>, and <version>.
 * No full XML parser — just simple regex matching.
 *
 * @param {string} filePath - Absolute path to pom.xml
 * @returns {Array<{ name: string, version: string, ecosystem: string, isDirect: boolean, isPinned: boolean }>}
 */
export function parsePom(filePath) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch (err) { throw new Error(`cannot read ${filePath}: ${err.code || err.message}`); }

  const deps = [];
  const depBlockRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  const groupRe = /<groupId>\s*([^<]+?)\s*<\/groupId>/;
  const artifactRe = /<artifactId>\s*([^<]+?)\s*<\/artifactId>/;
  const versionRe = /<version>\s*([^<]+?)\s*<\/version>/;

  let match;
  while ((match = depBlockRe.exec(content)) !== null) {
    const block = match[1];

    const groupMatch = groupRe.exec(block);
    const artifactMatch = artifactRe.exec(block);
    const versionMatch = versionRe.exec(block);

    if (!groupMatch || !artifactMatch || !versionMatch) continue;

    const name = `${groupMatch[1]}:${artifactMatch[1]}`;
    const version = versionMatch[1];

    // Skip property references like ${project.version}
    if (version.startsWith('${')) continue;

    deps.push({
      name,
      version,
      ecosystem: 'java',
      isDirect: true,
      isPinned: true,
    });
  }

  log.debug(`parsed ${deps.length} deps from ${filePath}`);
  return deps;
}

export const parseManifest = parsePom;

/**
 * Discover Java/Gradle/Maven dependency files in a directory.
 */
export function discover(dir) {
  const lockfiles = [];
  const manifests = [];

  const lockPath = join(dir, 'gradle.lockfile');
  const pomPath = join(dir, 'pom.xml');

  if (existsSync(lockPath)) lockfiles.push(lockPath);
  if (existsSync(pomPath)) manifests.push(pomPath);

  return { lockfiles, manifests };
}
