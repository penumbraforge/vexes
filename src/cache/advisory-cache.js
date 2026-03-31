import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { CACHE_DIR, ADVISORY_TTL_MS, METADATA_TTL_MS } from '../core/constants.js';
import { log } from '../core/logger.js';

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

  getAdvisories(ecosystem, name, version, ttlMs = ADVISORY_TTL_MS) {
    try {
      const row = this.#stmts.getAdvisory.get(ecosystem, name, version);
      if (!row) return null;
      if (Date.now() - row.fetched_at > ttlMs) return null;
      const parsed = this.#safeJsonParse(row.vulns, `${ecosystem}:${name}@${version}`);
      if (parsed === null) {
        // Corrupt entry — delete it
        this.#stmts.deleteAdvisory.run(ecosystem, name, version);
      }
      return parsed;
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  setAdvisories(ecosystem, name, version, vulns) {
    this.#stmts.setAdvisory.run(ecosystem, name, version, JSON.stringify(vulns), Date.now());
  }

  getAdvisoriesAny(ecosystem, name, version) {
    try {
      const row = this.#stmts.getAdvisory.get(ecosystem, name, version);
      if (!row) return null;
      const parsed = this.#safeJsonParse(row.vulns, `${ecosystem}:${name}@${version}`);
      if (parsed === null) {
        this.#stmts.deleteAdvisory.run(ecosystem, name, version);
      }
      return parsed;
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  getMetadata(ecosystem, name, ttlMs = METADATA_TTL_MS) {
    try {
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
      const row = this.#stmts.getSignals.get(ecosystem, name, version);
      if (!row) return null;
      if (Date.now() - row.analyzed_at > ttlMs) return null;
      return this.#safeJsonParse(row.data, `signals:${ecosystem}:${name}@${version}`);
    } catch (err) {
      log.debug(`cache read error: ${err.message}`);
      return null;
    }
  }

  setSignals(ecosystem, name, version, signals) {
    this.#stmts.setSignals.run(ecosystem, name, version, JSON.stringify(signals), Date.now());
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
