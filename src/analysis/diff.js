import { log } from '../core/logger.js';

/**
 * Lockfile diff engine — compares two dependency snapshots.
 * Used by guard (before/after install) and monitor (current vs previous).
 *
 * @param {Array<{ name: string, version: string, ecosystem: string }>} before
 * @param {Array<{ name: string, version: string, ecosystem: string }>} after
 * @returns {DiffResult}
 */
export function diffSnapshots(before, after) {
  const beforeMap = new Map();
  for (const dep of before) {
    beforeMap.set(`${dep.ecosystem}:${dep.name}`, dep);
  }

  const afterMap = new Map();
  for (const dep of after) {
    afterMap.set(`${dep.ecosystem}:${dep.name}`, dep);
  }

  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];

  // Find added and changed
  for (const [key, dep] of afterMap) {
    const prev = beforeMap.get(key);
    if (!prev) {
      added.push(dep);
    } else if (prev.version !== dep.version) {
      changed.push({
        name: dep.name,
        ecosystem: dep.ecosystem,
        fromVersion: prev.version,
        toVersion: dep.version,
      });
    } else {
      unchanged.push(dep);
    }
  }

  // Find removed
  for (const [key, dep] of beforeMap) {
    if (!afterMap.has(key)) {
      removed.push(dep);
    }
  }

  log.debug(`diff: ${added.length} added, ${removed.length} removed, ${changed.length} changed, ${unchanged.length} unchanged`);

  return {
    added,
    removed,
    changed,
    unchanged,
    hasChanges: added.length > 0 || removed.length > 0 || changed.length > 0,
    summary: buildSummary(added, removed, changed),
  };
}

function buildSummary(added, removed, changed) {
  const parts = [];
  if (added.length > 0) parts.push(`${added.length} added`);
  if (removed.length > 0) parts.push(`${removed.length} removed`);
  if (changed.length > 0) parts.push(`${changed.length} changed`);
  return parts.join(', ') || 'no changes';
}

/**
 * Convert a parsed dependency array into a serializable snapshot.
 * Strips isDev, isDirect, etc. — just name+version+ecosystem.
 */
export function toSnapshot(deps) {
  return deps.map(d => ({
    name: d.name,
    version: d.version,
    ecosystem: d.ecosystem,
  }));
}
