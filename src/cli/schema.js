import { VERSION, SEVERITY } from '../core/constants.js';

/**
 * Shared JSON envelope — the agent contract.
 *
 * Every vexes command that emits machine output (`scan`, `analyze`, `fix`,
 * `monitor --ci`, `inspect`, `triage`, `doctor`) emits through this schema so
 * an agent or CI system can rely on one stable, versioned shape:
 *
 *   {
 *     schemaVersion: "1.0",
 *     generator: { name: "vexes", version: "0.4.0" },
 *     timestamp, command,
 *     target: { dir, lockfiles, ecosystems },
 *     complete,            // top-level bool (backward compat with pre-schema output)
 *     warnings: [],
 *     result: { complete, warnings },
 *     summary: { ... },
 *     findings: [ ...normalizedFinding... ],
 *   }
 *
 * Contract rules (see wiki/Agent-Integration.md):
 *  - stdout is ALWAYS the JSON document in structured mode; logs/progress go
 *    to stderr. `complete === false` means the result must never be treated as
 *    "clean" — fail loud.
 *  - findings are additive: every field from the pre-schema internal record is
 *    preserved, so old consumers keep working while new fields (`severityLevel`,
 *    `confidence`, `reachability`, `importEvidence`, `advisories`, `llmSummary`) add meaning.
 *  - bump SCHEMA_VERSION on any breaking shape change. The `generator.version`
 *    tracks the CLI's own version and may change without a schema bump.
 */

export const SCHEMA_VERSION = '1.0';

/**
 * Confidence grades — how strongly the evidence backs a finding.
 *   proven        — exact match to upstream registry/OSV evidence; not proof of exploitation
 *   deterministic — derived purely from first-party inputs (your code, your lockfile)
 *   heuristic     — tuned heuristic with time-decay / popularity thresholds
 *   inferred      — best-effort inference; a lead, not a verdict (low trust)
 */
export const CONFIDENCE = Object.freeze({
  PROVEN: 'proven',
  DETERMINISTIC: 'deterministic',
  HEURISTIC: 'heuristic',
  INFERRED: 'inferred',
});

/**
 * Legacy reachability grades. These values remain for compatibility only and
 * must never be used to suppress a security finding. Prefer IMPORT_EVIDENCE.
 *   reachable — statically imported from an entry point reached through the project's own files
 *   lazy      — only ever reached via dynamic import (`import()`), gated at runtime
 *   dead      — no import found in any parsed project source file
 *   unknown   — not analyzed (non-JS ecosystem, or reachability analysis not run)
 */
export const REACHABILITY = Object.freeze({
  REACHABLE: 'reachable',
  LAZY: 'lazy',
  DEAD: 'dead',
  UNKNOWN: 'unknown',
});

/**
 * Canonical direct-import evidence. A `not_found` result is scoped to parsed
 * project source; transitive dependencies and tooling may still execute it.
 */
export const IMPORT_EVIDENCE = Object.freeze({
  FOUND_STATIC: 'found_static',
  FOUND_DYNAMIC: 'found_dynamic',
  NOT_FOUND: 'not_found',
  UNKNOWN: 'unknown',
});

/**
 * Build the top-level envelope.
 *
 * @param {object} parts
 * @param {string} parts.command — e.g. 'scan', 'inspect'
 * @param {object} [parts.target] — {dir, lockfiles: [], ecosystems: []}
 * @param {boolean} [parts.complete] — from the command's completeness logic
 * @param {string[]} [parts.warnings]
 * @param {object} [parts.summary]
 * @param {Array} [parts.findings] — already-normalized findings
 * @param {object} [parts.extra] — command-specific top-level data (e.g. fix results)
 * @returns {object} the envelope
 */
export function buildEnvelope({ command, target = {}, complete, warnings = [], summary = {}, findings = [], extra = {} }) {
  const envelope = {
    schemaVersion: SCHEMA_VERSION,
    generator: { name: 'vexes', version: VERSION, engine: process.version },
    timestamp: new Date().toISOString(),
    command,
    target: {
      dir: target.dir,
      lockfiles: target.lockfiles || [],
      ecosystems: target.ecosystems || [],
    },
    complete,
    warnings,
    result: { complete, warnings },
    summary,
    findings,
    ...extra,
  };
  // Keep insertion order stable for humans diffing output across runs.
  return envelope;
}

/**
 * Normalize one internal finding/vulnerability record into the public schema.
 * The internal record's fields are preserved (additive contract).
 *
 * @param {object} v — internal record (e.g. from osv.js normalizeVuln, or an analyze result)
 * @param {object} [opts]
 * @param {string} [opts.signal] — detection signal id (default KNOWN_COMPROMISED for OSV findings)
 * @param {string} [opts.confidence]
 * @param {string} [opts.reachability]
 * @param {string} [opts.importEvidence]
 * @param {boolean} [opts.direct] — is this a direct dependency of the project?
 * @param {string} [opts.fixCommand]
 * @returns {object} normalized finding
 */
export function normalizeFinding(v, opts = {}) {
  const level = String(v.severity ?? '').toUpperCase();
  const searchable = level || 'UNKNOWN';
  const order = level ? (SEVERITY[level]?.order ?? 0) : 0;

  const advisories = buildAdvisoryList(v);

  const legacyReachability = opts.reachability || v.reachability || REACHABILITY.UNKNOWN;
  const importEvidence = opts.importEvidence || v.importEvidence || importEvidenceFromLegacy(legacyReachability);
  const finding = {
    // Preserve the internal record wholesale (backward compat)
    ...v,
    // Public contract fields
    severityLevel: { level: searchable, order },
    signal: opts.signal || v.signal || 'KNOWN_COMPROMISED',
    confidence: opts.confidence || CONFIDENCE.PROVEN,
    reachability: legacyReachability,
    importEvidence,
    advisories,
  };

  if (opts.direct !== undefined) finding.direct = opts.direct;
  if (opts.fixCommand) {
    finding.fixCommand = opts.fixCommand; // compatibility field
    finding.fixCandidate = {
      command: opts.fixCommand,
      status: 'advisory-fixed-version-hint',
      osvCrossChecked: false,
      remediationVerified: false,
      requiresResolvedGraphRescan: true,
    };
  }
  finding.llmSummary = opts.llmSummary || llmSummary(v, finding, opts);

  return finding;
}

/**
 * De-duplicated advisory ID list for one finding (OSV id + aliases).
 */
function buildAdvisoryList(v) {
  const seen = new Set();
  const list = [];
  for (const id of [v.id, ...(v.aliases || [])]) {
    if (id && !seen.has(id)) { seen.add(id); list.push(id); }
  }
  return list;
}

/**
 * One deterministic sentence written for an LLM/agent to act on.
 * Answers: what is it, how bad, is it fixed, is it reachable, is it a blocker.
 * Never contains raw attacker-controlled source — only sanitized metadata.
 */
export function llmSummary(v, finding = null, opts = {}) {
  const level = finding?.severityLevel?.level || String(v.severity ?? '').toUpperCase() || 'UNKNOWN';
  const loc = `${v.package}@${v.version} (${v.ecosystem})`;
  const id = v.displayId || v.id || 'advisory';
  const desc = String(v.summary || v.description || id)
    .split(/[.;\n]/, 1)[0]
    .trim()
    .slice(0, 140);

  const fixed = v.fixed ? ` OSV records a fixed event at ${v.fixed.replace(/^>=\s*/, '>= ')}.` : '';
  const importEvidence = opts.importEvidence || finding?.importEvidence || importEvidenceFromLegacy(opts.reachability);
  const reach = importEvidence === IMPORT_EVIDENCE.NOT_FOUND
    ? " No direct import found in this project's source (may still load via tooling or dynamic paths)."
    : importEvidence === IMPORT_EVIDENCE.FOUND_STATIC
      ? " Imported by this project's code."
      : '';
  const blocker = level === 'CRITICAL' || level === 'HIGH' ? 'Blocker: yes.' : 'Blocker: review.';
  return `[${level}] ${loc} — ${id}: ${desc}.${fixed}${reach} ${blocker}`;
}

function importEvidenceFromLegacy(value) {
  if (value === REACHABILITY.REACHABLE) return IMPORT_EVIDENCE.FOUND_STATIC;
  if (value === REACHABILITY.LAZY) return IMPORT_EVIDENCE.FOUND_DYNAMIC;
  if (value === REACHABILITY.DEAD) return IMPORT_EVIDENCE.NOT_FOUND;
  return IMPORT_EVIDENCE.UNKNOWN;
}
