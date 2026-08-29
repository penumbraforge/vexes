import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { CACHE_DIR, ADVISORY_TTL_MS, METADATA_TTL_MS } from '../core/constants.js';
import { log } from '../core/logger.js';

// Bump whenever the *shape or meaning* of cached rows changes, not just the
// table DDL. Cached advisories store normalized severities — v2 invalidates
// caches written before the CVSS vector-parsing fix, which recorded false
// CRITICALs for every PYSEC/RUSTSEC/GO advisory. v3 invalidates signal rows
// written before the osvFingerprint field existed — those carry no record of
// which advisory evidence they were formed against, so they cannot be
// reconciled with fresh OSV results and must be re-analyzed. v5 additionally
// binds signal rows to current registry metadata/config and rejects malformed
// advisory/signal records before they can influence a clean result.
const CACHE_SCHEMA_VERSION = 5;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS advisories (
    ecosystem TEXT NOT NULL,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    vulns     TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
  );
  CREATE TABLE IF NOT EXISTS metadata (
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    data       TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name)
  );
  CREATE TABLE IF NOT EXISTS signals (
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    data        TEXT NOT NULL,
    analyzed_at INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
  );
  CREATE TABLE IF NOT EXISTS freshness (
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    latest_version TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, name)
  );
`;

/**
 * No-op cache used when the real cache is unavailable (disk error, permissions, etc.).
 * The scanner degrades gracefully — every lookup is a miss, writes are discarded.
 */
export class NoOpCache {
  getAdvisories() { return null; }
  setAdvisories() {}
  getAdvisoriesAny() { return null; }
  getMetadata() { return null; }
  setMetadata() {}
  getSignals() { return null; }
  setSignals() {}
  getFreshnessState() { return null; }
  setFreshnessState() {}
  prune() {}
  stats() { return { advisories: 0, metadata: 0, signals: 0 }; }
  close() {}
}

export class AdvisoryCache {
  #db;
  #stmts = {};

  constructor(cacheDir = CACHE_DIR) {
    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true });
    }

    const dbPath = join(cacheDir, 'cache.db');
    this.#db = new DatabaseSync(dbPath);

    const { user_version: storedVersion } = this.#db.prepare('PRAGMA user_version').get();
    if (storedVersion !== CACHE_SCHEMA_VERSION) {
      this.#db.exec('DROP TABLE IF EXISTS advisories; DROP TABLE IF EXISTS metadata; DROP TABLE IF EXISTS signals; DROP TABLE IF EXISTS freshness;');
      this.#db.exec(`PRAGMA user_version = ${CACHE_SCHEMA_VERSION}`);
      if (storedVersion > 0) {
        log.debug(`cache schema ${storedVersion} → ${CACHE_SCHEMA_VERSION}, stale entries dropped`);
      }
    }

    this.#db.exec(SCHEMA);
    this.#prepareStatements();
    log.debug(`cache opened at ${dbPath}`);
  }

  #prepareStatements() {
    this.#stmts = {
      getAdvisory: this.#db.prepare(
        'SELECT vulns, fetched_at FROM advisories WHERE ecosystem = ? AND name = ? AND version = ?'
      ),
      setAdvisory: this.#db.prepare(
        `INSERT OR REPLACE INTO advisories (ecosystem, name, version, vulns, fetched_at)
         VALUES (?, ?, ?, ?, ?)`
      ),
      getMetadata: this.#db.prepare(
        'SELECT data, fetched_at FROM metadata WHERE ecosystem = ? AND name = ?'
      ),
      setMetadata: this.#db.prepare(
        `INSERT OR REPLACE INTO metadata (ecosystem, name, data, fetched_at)
         VALUES (?, ?, ?, ?)`
      ),
      getSignals: this.#db.prepare(
        'SELECT data, analyzed_at FROM signals WHERE ecosystem = ? AND name = ? AND version = ?'
      ),
      setSignals: this.#db.prepare(
        `INSERT OR REPLACE INTO signals (ecosystem, name, version, data, analyzed_at)
         VALUES (?, ?, ?, ?, ?)`
      ),
      getFreshness: this.#db.prepare(
        'SELECT latest_version, first_seen_at, last_seen_at FROM freshness WHERE ecosystem = ? AND name = ?'
      ),
      setFreshness: this.#db.prepare(
        `INSERT INTO freshness (ecosystem, name, latest_version, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(ecosystem, name) DO UPDATE SET
           latest_version = excluded.latest_version,
           last_seen_at = excluded.last_seen_at`
      ),
      countAdvisories: this.#db.prepare('SELECT COUNT(*) as count FROM advisories'),
      countMetadata: this.#db.prepare('SELECT COUNT(*) as count FROM metadata'),
      countSignals: this.#db.prepare('SELECT COUNT(*) as count FROM signals'),
      pruneAdvisories: this.#db.prepare('DELETE FROM advisories WHERE fetched_at < ?'),
      pruneMetadata: this.#db.prepare('DELETE FROM metadata WHERE fetched_at < ?'),
      pruneSignals: this.#db.prepare('DELETE FROM signals WHERE analyzed_at < ?'),
      deleteAdvisory: this.#db.prepare(
        'DELETE FROM advisories WHERE ecosystem = ? AND name = ? AND version = ?'
      ),
    };
  }

  #safeJsonParse(raw, context) {
    try {
      return JSON.parse(raw);
    } catch {
      log.debug(`corrupted cache entry (${context}), treating as miss`);
      return null;
    }
  }

  #validAdvisories(value) {
    return Array.isArray(value) && value.every(vuln =>
      vuln && typeof vuln === 'object' && !Array.isArray(vuln) &&
      typeof vuln.id === 'string' && vuln.id.trim().length > 0
    );
  }

  #validSignals(value, ecosystem, name, version) {
    const levels = new Set(['NONE', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL', 'UNKNOWN']);
    return value && typeof value === 'object' && !Array.isArray(value) &&
      value.ecosystem === ecosystem && value.name === name && value.version === version &&
      Array.isArray(value.signals) && value.signals.every(signal =>
        signal && typeof signal === 'object' && !Array.isArray(signal) &&
        typeof signal.signal === 'string' && typeof signal.severity === 'string'
      ) &&
      Number.isFinite(value.riskScore) && value.riskScore >= 0 &&
      levels.has(value.riskLevel) &&
      Array.isArray(value.warnings) && value.warnings.every(warning => typeof warning === 'string') &&
      typeof value.osvFingerprint === 'string' &&
      typeof value.analysisFingerprint === 'string';
  }

  #validTtl(ttlMs) {
    return typeof ttlMs === 'number' && Number.isFinite(ttlMs) && ttlMs >= 0;
  }

  getAdvisories(ecosystem, name, version, ttlMs = ADVISORY_TTL_MS) {
    try {
      if (!this.#validTtl(ttlMs)) return null;
      const row = this.#stmts.getAdvisory.get(ecosystem, name, version);
      if (!row) return null;
      if (Date.now() - row.fetched_at > ttlMs) return null;
      const parsed = this.#safeJsonParse(row.vulns, `${ecosystem}:${name}@${version}`);
      if (!this.#validAdvisories(parsed)) {
        // Corrupt entry — delete it
        this.#stmts.deleteAdvisory.run(ecosystem, name, version);
        return null;
      }
      return parsed;
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  setAdvisories(ecosystem, name, version, vulns) {
    if (!this.#validAdvisories(vulns)) throw new Error('advisory cache rows must be arrays of records with string ids');
    this.#stmts.setAdvisory.run(ecosystem, name, version, JSON.stringify(vulns), Date.now());
  }

  getAdvisoriesAny(ecosystem, name, version) {
    try {
      const row = this.#stmts.getAdvisory.get(ecosystem, name, version);
      if (!row) return null;
      const parsed = this.#safeJsonParse(row.vulns, `${ecosystem}:${name}@${version}`);
      if (!this.#validAdvisories(parsed)) {
        this.#stmts.deleteAdvisory.run(ecosystem, name, version);
        return null;
      }
      return parsed;
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  getMetadata(ecosystem, name, ttlMs = METADATA_TTL_MS) {
    try {
      if (!this.#validTtl(ttlMs)) return null;
      const row = this.#stmts.getMetadata.get(ecosystem, name);
      if (!row) return null;
      if (Date.now() - row.fetched_at > ttlMs) return null;
      return this.#safeJsonParse(row.data, `metadata:${ecosystem}:${name}`);
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  setMetadata(ecosystem, name, data) {
    this.#stmts.setMetadata.run(ecosystem, name, JSON.stringify(data), Date.now());
  }

  getSignals(ecosystem, name, version, ttlMs = METADATA_TTL_MS) {
    try {
      if (!this.#validTtl(ttlMs)) return null;
      const row = this.#stmts.getSignals.get(ecosystem, name, version);
      if (!row) return null;
      if (Date.now() - row.analyzed_at > ttlMs) return null;
      const parsed = this.#safeJsonParse(row.data, `signals:${ecosystem}:${name}@${version}`);
      return this.#validSignals(parsed, ecosystem, name, version) ? parsed : null;
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  setSignals(ecosystem, name, version, signals) {
    if (!this.#validSignals(signals, ecosystem, name, version)) {
      throw new Error('signal cache row failed schema validation');
    }
    this.#stmts.setSignals.run(ecosystem, name, version, JSON.stringify(signals), Date.now());
  }

  getFreshnessState(ecosystem, name) {
    try {
      const row = this.#stmts.getFreshness.get(ecosystem, name);
      if (!row) return null;
      return {
        latestVersion: row.latest_version,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
      };
    } catch (err) {
      log.debug(`freshness cache read error: ${err.message}`);
      return null;
    }
  }

  setFreshnessState(ecosystem, name, latestVersion, now = Date.now()) {
    this.#stmts.setFreshness.run(ecosystem, name, latestVersion, now, now);
  }

  prune(maxAgeMs) {
    try {
      const cutoff = Date.now() - maxAgeMs;
      const a = this.#stmts.pruneAdvisories.run(cutoff);
      const m = this.#stmts.pruneMetadata.run(cutoff);
      const s = this.#stmts.pruneSignals.run(cutoff);
      log.debug(`pruned ${a.changes + m.changes + s.changes} stale cache entries`);
    } catch (err) {
      log.debug(`cache prune error: ${err.message}`);
    }
  }

  stats() {
    try {
      return {
        advisories: this.#stmts.countAdvisories.get().count,
        metadata: this.#stmts.countMetadata.get().count,
        signals: this.#stmts.countSignals.get().count,
      };
    } catch {
      return { advisories: 0, metadata: 0, signals: 0 };
    }
  }

  close() {
    try { this.#db.close(); } catch { /* best effort */ }
  }
}
