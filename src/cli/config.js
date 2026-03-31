import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { CACHE_DIR, ADVISORY_TTL_MS, METADATA_TTL_MS, ECOSYSTEMS } from '../core/constants.js';
import { log } from '../core/logger.js';

const VALID_ECOSYSTEMS = new Set(Object.keys(ECOSYSTEMS));
const VALID_SEVERITIES = new Set(['critical', 'high', 'moderate', 'low']);

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const DEFAULTS = Object.freeze({
  ecosystems: ['npm', 'pypi', 'cargo', 'go', 'ruby', 'php', 'nuget', 'java'],
  severity: 'moderate',
  ignore: [],
  analyze: {
    signals: {},
  },
  cache: {
    dir: CACHE_DIR,
    advisoryTtlMs: ADVISORY_TTL_MS,
    metadataTtlMs: METADATA_TTL_MS,
  },
  output: {
    color: 'auto',
    format: 'text',
  },
});

/**
 * Walk up from dir to find .vexesrc.json
 */
function findProjectConfig(dir) {
  let current = dir;
  for (let i = 0; i < 20; i++) {
    const candidate = join(current, '.vexesrc.json');
    if (existsSync(candidate)) {
      try {
        return JSON.parse(readFileSync(candidate, 'utf8'));
      } catch (err) {
        log.warn(`found .vexesrc.json at ${candidate} but failed to parse: ${err.message} — using defaults`);
        return {};
      }
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return {};
}

/**
 * Load user-level config from ~/.config/vexes/config.json
 */
function loadUserConfig() {
  const userPath = join(homedir(), '.config', 'vexes', 'config.json');
  if (existsSync(userPath)) {
    try {
      return JSON.parse(readFileSync(userPath, 'utf8'));
    } catch (err) {
      log.warn(`user config at ${userPath} failed to parse: ${err.message} — using defaults`);
      return {};
    }
  }
  return {};
}

/**
 * Deep merge with prototype pollution protection.
 * Rejects __proto__, constructor, and prototype keys.
 */
function merge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (UNSAFE_KEYS.has(key)) continue;
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = merge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

/**
 * Load config: defaults < user config < project config < CLI flags
 */
export function loadConfig(dir, flags = {}) {
  const userConf = loadUserConfig();
  const projConf = findProjectConfig(dir);

  let config = merge(DEFAULTS, userConf);
  config = merge(config, projConf);

  // CLI flag overrides with validation
  if (flags.ecosystem) {
    const eco = flags.ecosystem.toLowerCase();
    if (!VALID_ECOSYSTEMS.has(eco)) {
      const suggestion = [...VALID_ECOSYSTEMS].find(e => levenshteinClose(eco, e));
      const msg = suggestion
        ? `unknown ecosystem "${flags.ecosystem}" — did you mean "${suggestion}"?`
        : `unknown ecosystem "${flags.ecosystem}" — valid options: ${[...VALID_ECOSYSTEMS].join(', ')}`;
      // Reject invalid ecosystems instead of silently scanning nothing.
      // Using an invalid ecosystem would skip all scanning and report "clean".
      throw new Error(msg);
    }
    config.ecosystems = [eco];
  }
  if (flags.severity) {
    const sev = flags.severity.toLowerCase();
    if (!VALID_SEVERITIES.has(sev)) {
      log.warn(`unknown severity "${flags.severity}" — valid options: ${[...VALID_SEVERITIES].join(', ')}. Defaulting to moderate.`);
    } else {
      config.severity = sev;
    }
  }
  if (flags.json) config.output.format = 'json';
  if (flags.color === false) config.output.color = 'never';
  if (flags.path) config.targetPath = flags.path;
  if (flags.cached) config.useCache = true;
  if (flags.verbose) config.verbose = true;
  if (flags.strict) config.strict = true;
  if (flags.deep) config.deep = true;
  if (flags.fix) config.fix = true;
  if (flags.explain) config.explain = flags.explain;

  // Expand ~ in cache dir
  if (typeof config.cache?.dir === 'string' && config.cache.dir.startsWith('~')) {
    config.cache.dir = config.cache.dir.replace('~', homedir());
  }

  // Enforce cache TTL bounds — prevent config from setting absurd TTLs
  // that would cause stale (potentially false-clean) results to persist indefinitely.
  // Max 7 days for advisories, max 30 days for metadata.
  const MAX_ADVISORY_TTL = 7 * 24 * 60 * 60 * 1000;   // 7 days
  const MAX_METADATA_TTL = 30 * 24 * 60 * 60 * 1000;   // 30 days
  if (config.cache?.advisoryTtlMs > MAX_ADVISORY_TTL) {
    log.warn(`advisory cache TTL clamped to 7 days (was ${Math.round(config.cache.advisoryTtlMs / 86400000)}d)`);
    config = { ...config, cache: { ...config.cache, advisoryTtlMs: MAX_ADVISORY_TTL } };
  }
  if (config.cache?.metadataTtlMs > MAX_METADATA_TTL) {
    log.warn(`metadata cache TTL clamped to 30 days (was ${Math.round(config.cache.metadataTtlMs / 86400000)}d)`);
    config = { ...config, cache: { ...config.cache, metadataTtlMs: MAX_METADATA_TTL } };
  }

  // Validate all ecosystem names (catches invalid values from config files too)
  if (Array.isArray(config.ecosystems)) {
    const invalid = config.ecosystems.filter(e => !VALID_ECOSYSTEMS.has(e));
    if (invalid.length > 0) {
      log.warn(`ignoring unknown ecosystem(s) from config: ${invalid.join(', ')}`);
      config = { ...config, ecosystems: config.ecosystems.filter(e => VALID_ECOSYSTEMS.has(e)) };
      if (config.ecosystems.length === 0) {
        throw new Error(`no valid ecosystems configured — valid options: ${[...VALID_ECOSYSTEMS].join(', ')}`);
      }
    }
  }

  return Object.freeze(config);
}

/**
 * Quick Levenshtein distance check — returns true if distance <= 2.
 */
function levenshteinClose(a, b) {
  if (Math.abs(a.length - b.length) > 2) return false;
  let dist = 0;
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    if (a[i] !== b[i]) dist++;
    if (dist > 2) return false;
  }
  return dist > 0 && dist <= 2;
}
