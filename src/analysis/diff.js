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
    beforeMap.set(snapshotKey(dep), dep);
  }

  const afterMap = new Map();
  for (const dep of after) {
    afterMap.set(snapshotKey(dep), dep);
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
    } else {
      const fromIntegrity = artifactValue(prev.integrity);
      const toIntegrity = artifactValue(dep.integrity);
      const fromResolved = artifactValue(prev.resolved);
      const toResolved = artifactValue(dep.resolved);
      const integrityChanged = fromIntegrity !== toIntegrity;
      const resolvedChanged = fromResolved !== toResolved;

      if (prev.version !== dep.version || integrityChanged || resolvedChanged) {
        changed.push({
          ...dep,
          name: dep.name,
          ecosystem: dep.ecosystem,
          fromVersion: prev.version,
          toVersion: dep.version,
          integrityChanged,
          resolvedChanged,
          fromIntegrity,
          toIntegrity,
          fromResolved,
          toResolved,
        });
      } else {
        unchanged.push(dep);
      }
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

function artifactValue(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Lockfile occurrences are the stable identity for an installed component.
 * Falling back to ecosystem/name preserves legacy behavior for parsers that
 * cannot yet expose a path, while npm guard snapshots never collapse nested
 * versions onto one another.
 */
function snapshotKey(dep) {
  return dep.occurrence
    ? `${dep.ecosystem}:occurrence:${dep.occurrence}`
    : `${dep.ecosystem}:name:${dep.name}`;
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
 * Keeps artifact identity fields when the parser can provide them. Guard uses
 * these to bind approval to a lockfile occurrence, resolved URL and integrity,
 * rather than accepting the same name/version somewhere else in the graph.
 */
export function toSnapshot(deps) {
  return deps.map(d => ({
    name: d.name,
    version: d.version,
    ecosystem: d.ecosystem,
    ...(d.occurrence ? { occurrence: d.occurrence } : {}),
    ...(d.resolved ? { resolved: d.resolved } : {}),
    ...(d.integrity ? { integrity: d.integrity } : {}),
    ...(d.sourceType ? { sourceType: d.sourceType } : {}),
  }));
}
