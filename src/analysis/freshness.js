/**
 * Freshness layer — detect suspicious NEW releases within minutes, not days.
 *
 * The 2026 supply-chain race is measured in hours: axios was malicious for ~3
 * hours, Mastra republished 140+ packages in 88 minutes. CVE databases (OSV)
 * lag those windows by definition. This module polls the *registry* — where a
 * new version is visible within minutes of publication — and grades the signal
 * deltas the metadata normalizer already computes: maintainer change, install
 * scripts, newly added deps, rapid publish, dormancy.
 *
 * Inverted from `analyze`: analyze asks "is the installed thing risky NOW?"
 * freshness asks "did something new just land, and does it walk like an
 * attack?" Persisting the last-seen version hash means a release is graded
 * ONCE — subsequent polls are no-ops until the next publish.
 *
 * @module analysis/freshness
 */

import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { log } from '../core/logger.js';

// Low bar — a fresh release is a new event in a short-lived-attack landscape.
// The window tracks the documented 2026 attacks: axios was live ~3h, Mastra's
// second-stage rollout ~88min. Flag anything published within 24h of its
// predecessor when other deltas align.
const SUSPICIOUS_INTERVAL_MS = 24 * 60 * 60 * 1000;       // < 24h since previous release
const DORMANCY_THRESHOLD_MS = 90 * 24 * 60 * 60 * 1000;   // > 90 days quiet then active again

/**
 * Grade a freshly-published release from its normalized registry metadata.
 * Pure — no I/O — so the risk judgment is unit-testable.
 *
 * @param {object} m — normalizeMetadata() output for the NEWEST release
 * @returns {{ alert: boolean, level: 'high'|'moderate'|'low', reasons: string[] }}
 */
function pushReason(reasons, levelState, level, text) {
  reasons.push(text);
  if (levelState.value === null || levelOrder(level) > levelOrder(levelState.value)) {
    levelState.value = level;
  }
}

function levelOrder(l) {
  return l === 'high' ? 2 : l === 'moderate' ? 1 : 0;
}

export function assessNewVersion(m) {
  if (!m) return { alert: false, level: 'low', reasons: [] };
  const reasons = [];
  const levelState = { value: null };

  // The highest-signal check: the publisher changed across consecutive
  // releases. Account-takeover / stolen-credentials publishes trip this.
  if (m.maintainerChanged) {
    pushReason(reasons, levelState, 'high',
      `publisher changed: ${m.previousPublisher ?? '?'} → ${m.latestPublisher ?? '?'}`);
  }

  // Install lifecycle scripts on the new release — the classic sneaky delivery.
  if (m.hasInstallScripts) {
    const hooks = Object.keys(m.installScripts || {}).join(',');
    pushReason(reasons, levelState, 'high',
      `new release carries install lifecycle scripts (${hooks})`);
  }

  // The new release pulls in dependencies it didn't have before — a staging
  // pattern (hide your payload behind a fresh transitive dep).
  if (m.addedDeps?.length) {
    pushReason(reasons, levelState, 'moderate',
      `added ${m.addedDeps.length} new dependency(ies): ${m.addedDeps.slice(0, 4).join(', ')}${m.addedDeps.length > 4 ? '…' : ''}`);
  }

  // Rapid publish — the previous release arrived suspiciously soon before this
  // one (acceleration can be a second-stage rollout).
  if (m.publishIntervalMs !== null && m.publishIntervalMs < SUSPICIOUS_INTERVAL_MS) {
    pushReason(reasons, levelState, 'moderate',
      `published only ${(m.publishIntervalMs / 60000).toFixed(0)}min after previous release`);
  }

  // Dormancy + sudden activity — hijack-after-abandon.
  if (m.dormancyMs !== null && m.dormancyMs > DORMANCY_THRESHOLD_MS) {
    pushReason(reasons, levelState, 'moderate',
      `reactivated after ${(m.dormancyMs / 86400000).toFixed(0)} days dormant`);
  }

  // A big major jump on a NEW release from an unknown/fast publisher is worth
  // flagging lightly (semver is meaningful only when the publisher is ongoing).
  if (m.majorJump >= 2 && !reasons.length) {
    pushReason(reasons, levelState, 'moderate', `major jump +${m.majorJump} in a fresh release`);
  }

  if (reasons.length === 0) return { alert: false, level: 'low', reasons: [] };
  return { alert: true, level: levelState.value || 'moderate', reasons };
}

/**
 * Detect a new release for one dependency and grade it.
 *
 * @param {object} dep — {name, version (installed), ecosystem}
 * @param {object} opts
 * @param {function} [opts.fetchMeta] — injectable registry fetcher for tests
 * @returns {Promise<object>} { name, installed, latest, isNew, alert, level,
 *   reasons, skipped }. isNew=true only when the registry's latest differs
 *   from the INSTALLED version — a healthy "you're one behind" scan does NOT
 *   fire alerts by itself; the deltas decide.
 */
export async function checkOneDep(dep, { fetchMeta } = {}) {
  const name = dep.name;
  const ecosystem = dep.ecosystem;
  const installed = dep.version;
  const fetchFn = fetchMeta || (ecosystem === 'pypi' ? fetchPypiMetadata : fetchNpmMetadata);

  const metadata = await fetchFn(name, null);
  if (!metadata) {
    log.debug(`freshness: no metadata for ${ecosystem}:${name} — skipping`);
    return { name, installed, latest: null, isNew: false, alert: false, level: 'low', reasons: [], skipped: true };
  }

  const latest = metadata.latestAvailable || metadata.latestVersion;
  const isNew = latest !== installed;
  if (!isNew) return { name, installed, latest, isNew: false, alert: false, level: 'low', reasons: [], skipped: false };

  // We called the fetcher unanchored (null version), so normalizeMetadata
  // anchored to the registry's latest — exactly the release we want to grade.
  const assessment = assessNewVersion(metadata);
  return { name, installed, latest, isNew: true, ...assessment, skipped: false };
}

/**
 * Bulk-check an array of dependencies; return only events worth alerting on.
 * Failures degrade to skipped (never crash the watcher).
 */
export async function checkFreshness(deps, opts = {}) {
  const results = [];
  for (const dep of deps || []) {
    try {
      results.push(await checkOneDep(dep, opts));
    } catch (err) {
      log.debug(`freshness check failed for ${dep.ecosystem}:${dep.name}: ${err.message}`);
    }
  }
  return results.filter(r => r.isNew);
}

// Kept for callers that want the raw threshold knobs — re-export constants.
export { SUSPICIOUS_INTERVAL_MS, DORMANCY_THRESHOLD_MS };
