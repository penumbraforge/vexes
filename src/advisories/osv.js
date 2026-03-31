import { OSV_BATCH_URL, OSV_VULN_URL, OSV_BATCH_SIZE, SEVERITY } from '../core/constants.js';
import { fetchJSON } from '../core/fetcher.js';
import { log } from '../core/logger.js';

const ECOSYSTEM_MAP = {
  'npm':       'npm',
  'pypi':      'PyPI',
  'PyPI':      'PyPI',
  'cargo':     'crates.io',
  'crates.io': 'crates.io',
};

const KNOWN_ECOSYSTEMS = new Set(Object.keys(ECOSYSTEM_MAP));

// Normalize non-standard severity strings from various advisory sources
const SEVERITY_NORMALIZE = {
  'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MODERATE': 'MODERATE', 'LOW': 'LOW',
  'MEDIUM': 'MODERATE', 'IMPORTANT': 'HIGH', 'SEVERE': 'CRITICAL',
};

/**
 * Query OSV for vulnerabilities across a batch of packages.
 *
 * Returns a result object with both vulnerability data AND failure metadata.
 * A security scanner must never silently report clean when queries failed.
 *
 * @param {Array<{ name: string, version: string, ecosystem: string }>} packages
 * @returns {Promise<{ results: Map, failures: string[], droppedVulns: string[], queriedCount: number, failedCount: number }>}
 */
export async function queryBatch(packages) {
  const results = new Map();
  const failures = [];
  const droppedVulns = [];
  let queriedCount = 0;
  let failedCount = 0;

  if (packages.length === 0) {
    return { results, failures, droppedVulns, queriedCount: 0, failedCount: 0 };
  }

  const batches = [];
  for (let i = 0; i < packages.length; i += OSV_BATCH_SIZE) {
    batches.push(packages.slice(i, i + OSV_BATCH_SIZE));
  }

  log.debug(`querying OSV: ${packages.length} packages in ${batches.length} batch(es)`);

  for (const batch of batches) {
    const queries = batch.map(pkg => {
      const mappedEco = ECOSYSTEM_MAP[pkg.ecosystem];
      if (!mappedEco) {
        log.warn(`unknown ecosystem "${pkg.ecosystem}" for ${pkg.name} — OSV may not recognize it`);
      }
      return {
        package: {
          name: pkg.name,
          ecosystem: mappedEco || pkg.ecosystem,
        },
        version: pkg.version,
      };
    });

    try {
      const response = await fetchJSON(OSV_BATCH_URL, {
        method: 'POST',
        body: { queries },
      });

      if (!response.results || !Array.isArray(response.results)) {
        const msg = `OSV returned unexpected response shape (missing results array) — ${batch.length} packages not checked`;
        log.error(msg);
        failures.push(msg);
        failedCount += batch.length;
        continue;
      }

      // Validate response length matches query length
      if (response.results.length !== batch.length) {
        log.warn(`OSV returned ${response.results.length} results for ${batch.length} queries — partial response`);
        failedCount += Math.max(0, batch.length - response.results.length);
      }

      // Collect vuln IDs that need full details
      const vulnIdsToFetch = new Set();
      const batchHits = [];

      const resultCount = Math.min(response.results.length, batch.length);
      for (let i = 0; i < resultCount; i++) {
        const osvResult = response.results[i];
        queriedCount++;
        if (osvResult?.vulns?.length > 0) {
          const ids = osvResult.vulns.map(v => v.id).filter(id => typeof id === 'string' && id.length > 0);
          if (ids.length > 0) {
            batchHits.push({ pkgIndex: i, vulnIds: ids });
            ids.forEach(id => vulnIdsToFetch.add(id));
          }
        }
      }

      // Fetch full details for all unique vuln IDs found
      const { details: fullVulns, failed: detailFailures } = await fetchVulnDetails([...vulnIdsToFetch]);

      if (detailFailures.length > 0) {
        for (const f of detailFailures) {
          droppedVulns.push(f);
          log.warn(`failed to fetch details for ${f} — vulnerability may be missing from results`);
        }
      }

      // Map results back to packages
      for (const { pkgIndex, vulnIds } of batchHits) {
        const pkg = batch[pkgIndex];
        const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;

        const pkgVulns = [];
        for (const id of vulnIds) {
          const fullData = fullVulns.get(id);
          if (fullData) {
            pkgVulns.push(normalizeVuln(fullData, pkg));
          } else {
            // Detail fetch failed — still report with abbreviated data
            pkgVulns.push({
              id,
              displayId: id,
              aliases: [],
              summary: `Vulnerability detected (details unavailable — fetch failed for ${id})`,
              severity: 'CRITICAL', // Unknown severity = assume worst
              package: pkg.name,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              fixed: null,
              url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
              references: [],
              modified: null,
              published: null,
              detailsMissing: true,
            });
          }
        }
        if (pkgVulns.length > 0) results.set(key, pkgVulns);
      }
    } catch (err) {
      const msg = `OSV batch query failed: ${err.message} — ${batch.length} packages not checked`;
      log.error(msg);
      failures.push(msg);
      failedCount += batch.length;
    }
  }

  return { results, failures, droppedVulns, queriedCount, failedCount };
}

/**
 * Fetch full vulnerability details for a list of IDs.
 * Returns both successful details and a list of IDs that failed.
 */
async function fetchVulnDetails(ids) {
  const details = new Map();
  const failed = [];

  if (ids.length === 0) return { details, failed };

  log.debug(`fetching full details for ${ids.length} vulnerabilities`);

  const CONCURRENCY = 10;
  for (let i = 0; i < ids.length; i += CONCURRENCY) {
    const chunk = ids.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      chunk.map(id =>
        fetchJSON(`${OSV_VULN_URL}/${encodeURIComponent(id)}`).then(data => ({ id, data }))
      )
    );
    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      if (r.status === 'fulfilled') {
        details.set(r.value.id, r.value.data);
      } else {
        const failedId = chunk[j];
        failed.push(failedId);
        log.debug(`vuln detail fetch failed for ${failedId}: ${r.reason?.message}`);
      }
    }
  }

  return { details, failed };
}

/**
 * Normalize an OSV vulnerability response into our internal format.
 */
function normalizeVuln(osvVuln, pkg) {
  const severity = extractSeverity(osvVuln);
  const fixed = extractFixedVersion(osvVuln, pkg);
  const aliases = osvVuln.aliases || [];

  const ghsa = aliases.find(a => a.startsWith('GHSA-'));
  const cve = aliases.find(a => a.startsWith('CVE-'));
  const displayId = ghsa || cve || osvVuln.id;

  return {
    id: osvVuln.id,
    displayId,
    aliases,
    summary: osvVuln.summary || 'No description available',
    severity,
    package: pkg.name,
    version: pkg.version,
    ecosystem: pkg.ecosystem,
    fixed,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(osvVuln.id)}`,
    references: (osvVuln.references || []).map(r => r.url).filter(Boolean),
    modified: osvVuln.modified,
    published: osvVuln.published,
  };
}

/**
 * Extract the highest severity from OSV severity data.
 * For a security tool: unknown severity = CRITICAL (assume worst).
 */
function extractSeverity(osvVuln) {
  // Check database_specific severity first
  if (osvVuln.database_specific?.severity) {
    const normalized = SEVERITY_NORMALIZE[osvVuln.database_specific.severity.toUpperCase()];
    if (normalized) return normalized;
  }

  // Check CVSS scores
  const severities = osvVuln.severity || [];
  let highestScore = 0;

  for (const s of severities) {
    if (s.score) {
      highestScore = Math.max(highestScore, s.score);
    } else if (s.type === 'CVSS_V3' && s.vector) {
      highestScore = Math.max(highestScore, parseCvssScore(s.vector));
    }
  }

  // Check affected[].ecosystem_specific.severity
  for (const affected of osvVuln.affected || []) {
    const esSeverity = affected.ecosystem_specific?.severity;
    if (esSeverity) {
      const normalized = SEVERITY_NORMALIZE[esSeverity.toUpperCase()];
      if (normalized) return normalized;
    }
  }

  if (highestScore >= 9.0) return 'CRITICAL';
  if (highestScore >= 7.0) return 'HIGH';
  if (highestScore >= 4.0) return 'MODERATE';
  if (highestScore > 0)    return 'LOW';

  // Unknown severity on a security tool = assume worst case
  return 'CRITICAL';
}

/**
 * Parse a CVSS v3.x vector string and compute the base score.
 * Implements the CVSS v3.1 specification equations (FIRST.org).
 * Falls back to heuristic scoring for malformed vectors.
 *
 * @param {string} vector — e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * @returns {number} base score (0.0 - 10.0)
 */
function parseCvssScore(vector) {
  // Parse metrics from vector string
  const metrics = {};
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key && value) metrics[key] = value;
  }

  // Metric value maps per CVSS v3.1 spec
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const AC = { L: 0.77, H: 0.44 };
  const PR_U = { N: 0.85, L: 0.62, H: 0.27 }; // Scope Unchanged
  const PR_C = { N: 0.85, L: 0.68, H: 0.50 }; // Scope Changed
  const UI = { N: 0.85, R: 0.62 };
  const CIA = { H: 0.56, L: 0.22, N: 0 };

  const av = AV[metrics.AV];
  const ac = AC[metrics.AC];
  const ui = UI[metrics.UI];
  const c = CIA[metrics.C];
  const i = CIA[metrics.I];
  const a = CIA[metrics.A];
  const scopeChanged = metrics.S === 'C';
  const pr = scopeChanged ? PR_C[metrics.PR] : PR_U[metrics.PR];

  // If any required metric is missing, fall back to heuristic
  if (av === undefined || ac === undefined || pr === undefined ||
      ui === undefined || c === undefined || i === undefined || a === undefined) {
    if (metrics.AV === 'N') return 7.5;
    if (metrics.AV === 'A') return 5.0;
    if (metrics.AV === 'L') return 4.0;
    return 5.0;
  }

  // ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

  // Impact
  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  if (impact <= 0) return 0.0;

  // Exploitability = 8.22 × AV × AC × PR × UI
  const exploitability = 8.22 * av * ac * pr * ui;

  // Base Score
  let score;
  if (scopeChanged) {
    score = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    score = Math.min(impact + exploitability, 10);
  }

  // Round up to one decimal place per spec
  return Math.ceil(score * 10) / 10;
}

function extractFixedVersion(osvVuln, pkg) {
  for (const affected of osvVuln.affected || []) {
    if (affected.package?.name !== pkg.name) continue;
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) return `>= ${event.fixed}`;
      }
    }
  }
  return null;
}

/**
 * Filter vulnerabilities by minimum severity level.
 * Unknown/unmapped severities are never filtered out.
 */
export function filterBySeverity(vulns, minSeverity) {
  const minOrder = SEVERITY[minSeverity.toUpperCase()]?.order ?? 0;
  return vulns.filter(v => {
    const order = SEVERITY[v.severity]?.order;
    // Unknown severity = never filter out (could be anything)
    if (order === undefined) return true;
    return order >= minOrder;
  });
}
