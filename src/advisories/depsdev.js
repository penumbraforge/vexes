import { DEPS_DEV_URL, DEPS_DEV_MIN_INTERVAL_MS, DEPS_DEV_SUPPORTED } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

/**
 * deps.dev v3 client — declared license lookups for `vexes licenses`.
 *
 * deps.dev is Google's no-auth package metadata API (the one OSV-Scanner uses
 * for license data). It is NOT a vulnerability source — licenses here are
 * informational (SPDX id, e.g. "MIT"), used to warn before a scan commits to a
 * dependency whose licensing is missing/unknown, never as a security verdict.
 *
 * Rate limits: unauthenticated ≈ 20 req/min sustained. We serialize every
 * lookup through a shared min-interval throttle (well under that), and treat
 * per-package failures as `skipped` — one bad package must not kill a licenses
 * report. Network boundary: all requests flow through the shared bounded fetch client.
 */

let lastRequestAt = 0;
const pending = [];

// Serialize lookups so bursts never exceed DEPS_DEV_MIN_INTERVAL_MS between
// starts, regardless of concurrent callers. fetchJSON retries 429/5xx itself.
async function throttleGate() {
  const now = Date.now();
  const wait = Math.max(0, lastRequestAt + DEPS_DEV_MIN_INTERVAL_MS - now);
  lastRequestAt = now + (wait || DEPS_DEV_MIN_INTERVAL_MS);
  // Chain: each waiter resolves the previous one's completion before firing.
  let release;
  const job = new Promise((r) => (release = r));
  const prev = pending.at(-1) ?? Promise.resolve();
  pending.push(job);
  await prev;
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  release();
  const i = pending.indexOf(job);
  if (i >= 0) pending.splice(i, 1);
}

/**
 * Map an internal ecosystem name to the deps.dev system id, or null when
 * deps.dev has no data for that ecosystem (ruby/php/hex/pub today).
 * Returns null so callers can skip cleanly instead of erroring.
 */
export function systemForEcosystem(ecosystem) {
  return DEPS_DEV_SUPPORTED[ecosystem] ?? null;
}

/**
 * Fetch the declared licenses for one package version.
 *
 * @param {string} ecosystem — internal name (npm/pypi/cargo/go/nuget/java)
 * @param {string} name — package name, e.g. 'lodash' or '@babel/core'
 * @param {string} version — exact resolved version
 * @returns {Promise<{licenses: string[], url: string, skipped: false} | {skipped: true, reason: string}>}
 */
export async function fetchVersionLicenses(ecosystem, name, version, opts = {}) {
  const system = systemForEcosystem(ecosystem);
  if (!system) return { skipped: true, reason: `deps.dev has no ${ecosystem} data` };
  await throttleGate();
  try {
    const urlName = system === 'pypi'
      ? encodeURIComponent(name.toLowerCase())
      : name.startsWith('@')
        ? '@' + encodeURIComponent(name.slice(1))
        : encodeURIComponent(name);
    const url = `${DEPS_DEV_URL}/systems/${system}/packages/${urlName}/versions/${encodeURIComponent(version)}`;
    const data = await fetchJSON(url, { timeout: opts.timeout ?? 8000 });
    if (!data || typeof data !== 'object') return { skipped: true, reason: 'empty response' };
    const licenses = Array.isArray(data.licenses) ? data.licenses : [];
    return { licenses, url, skipped: false };
  } catch (err) {
    log.debug(`deps.dev lookup failed for ${name}@${version}: ${err.code || err.message}`);
    return { skipped: true, reason: err.code || err.message };
  }
}

/**
 * Bulk license lookup across packages, honoring the shared throttle.
 *
 * @param {Array<{ecosystem, name, version}>} deps — deduped dependency records
 * @returns {Promise<{records: object[], skipped: number, complete: boolean}>}
 *   records: [{ecosystem, name, version, trigger: {licenses[]|skip reason}}]
 *   complete: false if ANY lookup skipped (callers must never report a full bill
 *   of material as if it were verified — same fail-loud DNA as scan).
 */
export async function queryLicenses(deps = [], opts = {}) {
  const records = [];
  let skipped = 0;
  for (const dep of deps) {
    const r = await fetchVersionLicenses(dep.ecosystem, dep.name, dep.version, opts);
    if (r.skipped) skipped++;
    records.push({ ecosystem: dep.ecosystem, name: dep.name, version: dep.version, ...r });
  }
  return { records, skipped, complete: skipped === 0 };
}
