/**
 * Freshness layer — detect suspicious NEW releases on a configured registry
 * polling cadence.
 *
 * Registry changes can become visible before an advisory is published. This
 * module polls the registry and grades the signal
 * deltas the metadata normalizer already computes: maintainer change, install
 * scripts, newly added deps, rapid publish, dormancy.
 *
 * Inverted from `analyze`: analyze asks "is the installed thing risky NOW?"
 * freshness asks "did the registry latest change since the last successful
 * poll, and what evidence changed with it?" Persisted last-seen versions mean
 * each release is graded once. The initial poll establishes a baseline and
 * never treats an already-outdated project as a newly published event.
 *
 * @module analysis/freshness
 */

import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { log } from '../core/logger.js';

// Low bar: a new release is an event worth comparing to the persisted baseline.
// Flag publication within 24h of its predecessor when other deltas align.
const SUSPICIOUS_INTERVAL_MS = 24 * 60 * 60 * 1000;       // < 24h since previous release
const DORMANCY_THRESHOLD_MS = 90 * 24 * 60 * 60 * 1000;   // > 90 days quiet then active again
const SUPPORTED_ECOSYSTEMS = new Set(['npm', 'pypi']);

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

  // Only newly introduced or changed consumer install hooks are a release
  // delta. A longstanding postinstall script is not itself a fresh event.
  const previousScripts = m.previousInstallScripts;
  const changedHooks = previousScripts && typeof previousScripts === 'object'
    ? Object.entries(m.installScripts || {})
      .filter(([hook, command]) => previousScripts[hook] !== command)
      .map(([hook]) => hook)
    : [];
  if (changedHooks.length > 0) {
    const hooks = changedHooks.join(',');
    pushReason(reasons, levelState, 'high',
      `new or changed consumer install lifecycle scripts (${hooks})`);
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
  if (m.publishIntervalMs !== null && m.publishIntervalMs > DORMANCY_THRESHOLD_MS) {
    pushReason(reasons, levelState, 'moderate',
      `reactivated after ${(m.publishIntervalMs / 86400000).toFixed(0)} days dormant`);
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
export async function checkOneDep(dep, { fetchMeta, lastSeenVersion } = {}) {
  const name = dep.name;
  const ecosystem = dep.ecosystem;
  const installed = dep.version;
  if (!SUPPORTED_ECOSYSTEMS.has(ecosystem)) {
    return {
      name, ecosystem, installed, latest: null, isNew: false, alert: false,
      level: 'low', reasons: [], skipped: true,
      warning: `freshness does not support ecosystem ${ecosystem}`,
    };
  }
  const fetchFn = fetchMeta || (ecosystem === 'pypi' ? fetchPypiMetadata : fetchNpmMetadata);

  const metadata = await fetchFn(name, null);
  if (!metadata) {
    log.debug(`freshness: no metadata for ${ecosystem}:${name} — skipping`);
    return { name, ecosystem, installed, latest: null, isNew: false, alert: false, level: 'low', reasons: [], skipped: true, warning: 'registry metadata unavailable' };
  }

  const latest = metadata.latestAvailable || metadata.latestVersion;
  if (!latest) {
    return { name, ecosystem, installed, latest: null, isNew: false, alert: false, level: 'low', reasons: [], skipped: true, warning: 'registry latest version unavailable' };
  }
  const updateAvailable = latest !== installed;
  const baseline = lastSeenVersion === undefined || lastSeenVersion === null;
  const isNew = !baseline && latest !== lastSeenVersion;
  if (!isNew) {
    return { name, ecosystem, installed, latest, lastSeenVersion: lastSeenVersion ?? null, baseline, updateAvailable, isNew: false, alert: false, level: 'low', reasons: [], skipped: false };
  }

  // We called the fetcher unanchored (null version), so normalizeMetadata
  // anchored to the registry's latest — exactly the release we want to grade.
  const assessment = assessNewVersion(metadata);
  return { name, ecosystem, installed, latest, lastSeenVersion, baseline: false, updateAvailable, isNew: true, ...assessment, skipped: false };
}

/**
 * Bulk-check an array of dependencies; return only events worth alerting on.
 * Failures degrade to skipped (never crash the watcher).
 */
export async function checkFreshness(deps, opts = {}) {
  const events = [];
  const warnings = [];
  let checked = 0;
  let skipped = 0;
  const cache = opts.cache;
  for (const dep of deps || []) {
    try {
      const state = cache?.getFreshnessState?.(dep.ecosystem, dep.name) || null;
      const event = await checkOneDep(dep, { ...opts, lastSeenVersion: state?.latestVersion ?? null });
      events.push(event);
      if (event.skipped) {
        skipped++;
        if (event.warning) warnings.push(`${dep.ecosystem}:${dep.name}: ${event.warning}`);
        continue;
      }
      checked++;
      cache?.setFreshnessState?.(dep.ecosystem, dep.name, event.latest);
    } catch (err) {
      const warning = `${dep.ecosystem}:${dep.name}: ${err.message}`;
      warnings.push(warning);
      skipped++;
      log.debug(`freshness check failed for ${warning}`);
    }
  }
  return {
    events,
    alerts: events.filter(r => r.isNew && r.alert),
    complete: warnings.length === 0,
    warnings,
    checked,
    skipped,
  };
}

// Kept for callers that want the raw threshold knobs — re-export constants.
export { SUSPICIOUS_INTERVAL_MS, DORMANCY_THRESHOLD_MS };
