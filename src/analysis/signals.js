import { SEVERITY } from '../core/constants.js';
import { KNOWN_POSTINSTALL, POPULAR_NPM, POPULAR_PYPI } from '../core/allowlists.js';
import { inspectJS, inspectPython } from './ast-inspector.js';
import { analyzeNewDeps, detectTyposquat, detectHomoglyphs } from './dep-graph.js';
import { buildProfile, diffProfiles } from './behavioral.js';
import { log } from '../core/logger.js';

/**
 * Signal orchestrator — runs all 4 detection layers and computes composite risk.
 *
 * Layer 1: AST-based code analysis (ast-inspector.js)
 * Layer 2: Dependency graph profiling (dep-graph.js)
 * Layer 3: Behavioral fingerprinting (behavioral.js)
 * Layer 4: Registry metadata signals (this file)
 *
 * Returns signals with composite scoring that accounts for context.
 */

const TEN_MINUTES_MS = 10 * 60 * 1000;
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Confidence grade per signal — how strongly the evidence backs the claim.
 * (grades defined in src/cli/schema.js CONFIDENCE)
 *   proven        — exact match to an upstream registry/OSV fact; not proof of exploitation
 *   deterministic — derived purely from first-party registry data (publish
 *                   times, maintainer identity, script presence, Unicode)
 *   heuristic     — tuned heuristic with thresholds that can false-positive
 *   (anything unmapped defaults to 'inferred' — a lead, not a verdict)
 */
export const SIGNAL_CONFIDENCE = Object.freeze({
  KNOWN_MALICIOUS: 'proven',
  KNOWN_VULNERABILITY: 'proven',
  OSV_MATCH: 'proven', // compatibility name accepted by downstream consumers
  KNOWN_COMPROMISED: 'proven',
  MAINTAINER_CHANGE: 'deterministic',
  POSTINSTALL_SCRIPT: 'deterministic',
  RAPID_PUBLISH: 'deterministic',
  VERSION_ANOMALY: 'deterministic',
  HOMOGLYPH: 'deterministic',
  NO_REPOSITORY: 'deterministic',
  MISSING_PROVENANCE: 'deterministic',
  SIGNATURE_SPOOF: 'heuristic', // replay (subject mismatch) is deterministic, repo mismatch may false-positive on forks
  TYPOSQUAT: 'heuristic',
  PHANTOM_DEPENDENCY: 'heuristic',
  CIRCULAR_STAGING: 'heuristic',
  CAPABILITY_ESCALATION: 'heuristic',
  INITIAL_DANGEROUS_CAPABILITY: 'heuristic',
  NEW_DEPENDENCY: 'deterministic',
  NEW_DEP_HAS_INSTALL_SCRIPTS: 'deterministic',
  DEPENDENCY_SPIKE: 'heuristic', // count threshold is a judgment call
  MAINTAINER_REDUCTION: 'deterministic',
  REPOSITORY_REMOVED: 'deterministic',
  AST_DANGEROUS_PATTERN: 'heuristic',
  TARBALL_DANGEROUS_PATTERN: 'heuristic',
  SANDBOX_BEHAVIOR: 'heuristic', // observed at runtime under OS isolation — solid, but behavior can be staged/benign-in-context
});

// `KNOWN_COMPROMISED` was historically emitted for every OSV match, including
// ordinary CVEs.  Keep it only as an input/config compatibility name; new
// results use a truthful distinction between a vulnerability match and an
// advisory that explicitly identifies a malicious package/version.
export const KNOWN_ADVISORY_SIGNALS = Object.freeze([
  'KNOWN_MALICIOUS',
  'KNOWN_VULNERABILITY',
  'OSV_MATCH',
  'KNOWN_COMPROMISED',
]);

export function isKnownAdvisorySignal(signal) {
  return KNOWN_ADVISORY_SIGNALS.includes(signal);
}

const DEP_GRAPH_SIGNALS = Object.freeze([
  'NEW_DEPENDENCY',
  'PHANTOM_DEPENDENCY',
  'CIRCULAR_STAGING',
  'NEW_DEP_HAS_INSTALL_SCRIPTS',
]);

const BEHAVIOR_SIGNALS = Object.freeze([
  'INITIAL_DANGEROUS_CAPABILITY',
  'CAPABILITY_ESCALATION',
  'DEPENDENCY_SPIKE',
  'MAINTAINER_REDUCTION',
  'REPOSITORY_REMOVED',
]);

/**
 * Run all detection layers for a single package.
 *
 * @param {Object} metadata — from npm-registry.js or pypi-registry.js
 * @param {Object} [osvResult] — from osv.js (null if not run)
 * @param {Object} options
 * @param {string} options.ecosystem — 'npm' or 'pypi'
 * @param {Object} [options.config] — from .vexesrc.json (for signal overrides)
 * @param {number} [options.now] — reference timestamp for time-decay math (defaults to Date.now(); inject in tests so date-sensitive assertions can't rot)
 * @returns {Promise<{ signals: Signal[], riskScore: number, riskLevel: string }>}
 */
export async function analyzePackage(metadata, osvResult, options = {}) {
  const { ecosystem = 'npm', config, now = Date.now() } = options;
  const signals = [];
  const warnings = [];

  if (!metadata) {
    return { signals: [], riskScore: 0, riskLevel: 'UNKNOWN', warnings: ['metadata unavailable'] };
  }

  // Every documented signal switch is honored. A scanner may choose safe
  // defaults, but silently ignoring an explicit per-signal `off` makes policy
  // configuration untrustworthy. The legacy KNOWN_COMPROMISED switch applies
  // to the new advisory signal names only when their own switch is absent.
  const signalConfig = config?.analyze?.signals || {};
  const isEnabled = (signal) => {
    if (signalConfig[signal] === 'off') return false;
    if ((signal === 'KNOWN_MALICIOUS' || signal === 'KNOWN_VULNERABILITY') &&
        signalConfig[signal] === undefined && signalConfig.KNOWN_COMPROMISED === 'off') {
      return false;
    }
    return true;
  };

  // ─── Layer 4: Registry metadata signals (fast, no async) ───────────

  // OSV is a vulnerability database, not proof that every affected package
  // was compromised. Only explicit MAL-* records carry the malicious label;
  // ordinary advisories retain the highest upstream severity in their group.
  if (osvResult?.length > 0) {
    const malicious = osvResult.filter(isExplicitMaliciousAdvisory);
    const vulnerabilities = osvResult.filter(v => !isExplicitMaliciousAdvisory(v));

    if (malicious.length > 0 && isEnabled('KNOWN_MALICIOUS')) {
      signals.push(advisorySignal(
        'KNOWN_MALICIOUS',
        malicious,
        `${malicious.length} explicit malicious-package advisory match(es) in OSV`,
        'CRITICAL'
      ));
    }
    if (vulnerabilities.length > 0 && isEnabled('KNOWN_VULNERABILITY')) {
      signals.push(advisorySignal(
        'KNOWN_VULNERABILITY',
        vulnerabilities,
        `${vulnerabilities.length} known vulnerability match(es) in OSV`,
        'MODERATE'
      ));
    }
  }

  // MAINTAINER_CHANGE
  // Time-decay: transfers > 90 days ago are less suspicious (legitimate handoffs settle)
  // Also downweight if the package has many maintainers (org-managed)
  if (isEnabled('MAINTAINER_CHANGE') && metadata.maintainerChanged) {
    const daysSincePublish = metadata.latestPublishTime
      ? (now - new Date(metadata.latestPublishTime).getTime()) / (24 * 60 * 60 * 1000)
      : 0;
    const isRecent = daysSincePublish < 90;
    const isOrgManaged = (metadata.maintainers?.length || 0) >= 3;

    let severity = 'CRITICAL';
    if (!isRecent && isOrgManaged) severity = 'LOW';       // Old transfer in org = low risk
    else if (!isRecent) severity = 'MODERATE';              // Old transfer, small team
    // Recent transfer stays CRITICAL (could be account takeover)

    signals.push({
      signal: 'MAINTAINER_CHANGE',
      severity,
      description: `Publishing account changed from "${metadata.previousPublisher}" to "${metadata.latestPublisher}"${!isRecent ? ` (${Math.floor(daysSincePublish)} days ago)` : ''}`,
      evidence: {
        previous: metadata.previousPublisher,
        current: metadata.latestPublisher,
        daysSincePublish: Math.floor(daysSincePublish),
        recentTransfer: isRecent,
      },
      layer: 4,
    });
  }

  // POSTINSTALL_SCRIPT
  if (isEnabled('POSTINSTALL_SCRIPT') && metadata.hasInstallScripts) {
    const isKnownGood = KNOWN_POSTINSTALL.has(metadata.name);
    signals.push({
      signal: 'POSTINSTALL_SCRIPT',
      // Script presence is deterministic evidence of an execution surface,
      // not evidence of malicious intent. Dangerous content is scored by the
      // AST and behavioral layers rather than double-counted here.
      severity: isKnownGood ? 'LOW' : 'MODERATE',
      description: `Has install lifecycle scripts: ${Object.keys(metadata.installScripts || {}).join(', ')}`,
      evidence: { scripts: metadata.installScripts, knownGood: isKnownGood },
      layer: 4,
    });
  }

  // RAPID_PUBLISH — only flag positive intervals (negative means backport, which is normal)
  // 0s interval = CI multi-publish (sharp, esbuild publish all platform packages simultaneously)
  // Known-good packages get downweighted
  if (isEnabled('RAPID_PUBLISH') &&
      metadata.publishIntervalMs !== null &&
      metadata.publishIntervalMs >= 0 &&
      metadata.publishIntervalMs < TEN_MINUTES_MS) {
    const isKnownGood = KNOWN_POSTINSTALL.has(metadata.name);
    const isCIMultiPublish = metadata.publishIntervalMs === 0 && (metadata.maintainers?.length || 0) >= 2;

    // CI simultaneous publishes (0s) with multiple maintainers = normal automation
    if (isCIMultiPublish || isKnownGood) {
      signals.push({
        signal: 'RAPID_PUBLISH',
        severity: 'LOW',
        description: `Version published ${Math.floor(metadata.publishIntervalMs / 1000)}s after previous (likely CI automation)`,
        evidence: { intervalMs: metadata.publishIntervalMs, knownGood: isKnownGood, ciMultiPublish: isCIMultiPublish },
        layer: 4,
      });
    } else {
      signals.push({
        signal: 'RAPID_PUBLISH',
        severity: 'HIGH',
        description: `Version published only ${Math.floor(metadata.publishIntervalMs / 1000)}s after previous version`,
        evidence: { intervalMs: metadata.publishIntervalMs },
        layer: 4,
      });
    }
  }

  // VERSION_ANOMALY
  if (isEnabled('VERSION_ANOMALY')) {
    if (metadata.majorJump >= 3) {
      signals.push({
        signal: 'VERSION_ANOMALY',
        severity: 'MODERATE',
        description: `Major version jumped by ${metadata.majorJump} (${metadata.previousVersion} → ${metadata.latestVersion})`,
        evidence: { jump: metadata.majorJump },
        layer: 4,
      });
    }
    // Long dormancy then a publish is useful context, but it is not a permanent
    // HIGH verdict. A reactivation years ago has had time to accumulate review
    // and usage; preserve the fact while decaying its present-day urgency.
    if (metadata.dormancyMs && metadata.dormancyMs > ONE_YEAR_MS) {
      const daysSincePublish = metadata.latestPublishTime
        ? Math.max(0, (now - new Date(metadata.latestPublishTime).getTime()) / 86400000)
        : 0;
      const severity = daysSincePublish < 90
        ? 'HIGH'
        : (daysSincePublish < 365 ? 'MODERATE' : 'LOW');
      signals.push({
        signal: 'VERSION_ANOMALY',
        severity,
        description: `Package was dormant for ${Math.floor(metadata.dormancyMs / 86400000)} days before this version${daysSincePublish >= 90 ? ` (${Math.floor(daysSincePublish)} days ago)` : ''}`,
        evidence: { dormancyMs: metadata.dormancyMs, daysSincePublish: Math.floor(daysSincePublish) },
        layer: 4,
      });
    }
  }

  // MISSING_PROVENANCE (npm only, checked separately via provenance.js)

  // NO_REPOSITORY
  if (isEnabled('NO_REPOSITORY') && !metadata.repository) {
    signals.push({
      signal: 'NO_REPOSITORY',
      severity: 'LOW',
      description: 'No source repository link in package metadata',
      evidence: {},
      layer: 4,
    });
  }

  // HOMOGLYPH: suspicious Unicode in package name
  const homoglyphs = isEnabled('HOMOGLYPH') ? detectHomoglyphs(metadata.name) : [];
  if (homoglyphs.length > 0) {
    signals.push({
      signal: 'HOMOGLYPH',
      severity: 'CRITICAL',
      description: homoglyphs.map(h => h.description).join('; '),
      evidence: {
        type: homoglyphs[0].type, // legacy single-finding consumer compatibility
        types: homoglyphs.map(h => h.type),
        name: metadata.name,
      },
      layer: 4,
    });
  }

  // TYPOSQUAT
  if (isEnabled('TYPOSQUAT')) {
    const popularSet = ecosystem === 'pypi' ? POPULAR_PYPI : POPULAR_NPM;
    const matches = detectTyposquat(metadata.name, popularSet);
    if (matches.length > 0) {
      signals.push({
        signal: 'TYPOSQUAT',
        severity: 'HIGH',
        description: `Package name is suspiciously similar to: ${matches.map(m => `"${m.similar}" (distance ${m.distance})`).join(', ')}`,
        evidence: { matches },
        layer: 4,
      });
    }
  }

  // ─── Layer 1: AST analysis of install scripts ──────────────────────

  if (isEnabled('AST_DANGEROUS_PATTERN') && metadata.installScripts) {
    const isKnownGood = KNOWN_POSTINSTALL.has(metadata.name);
    // Always run AST analysis, even for known-good packages — a compromised version
    // of esbuild/sharp must still be caught. Findings are downweighted, not suppressed.
    try {
      for (const [scriptName, scriptBody] of Object.entries(metadata.installScripts)) {
        if (!scriptBody) continue;
        const jsSource = extractInlineJS(scriptBody);
        if (jsSource) {
          const result = inspectJS(jsSource, `${metadata.name}/${scriptName}`);
          for (const finding of result.findings) {
            signals.push({
              signal: 'AST_DANGEROUS_PATTERN',
              severity: finding.severity,
              description: `[${scriptName}] ${finding.description}`,
              evidence: { script: scriptName, pattern: finding.pattern, knownGood: isKnownGood },
              layer: 1,
            });
          }
        }
      }
    } catch (err) {
      log.warn(`AST analysis failed for ${metadata.name}: ${err.message}`);
      warnings.push(`AST analysis failed: ${err.message}`);
    }
  }

  // ─── Layer 2: Dependency graph analysis ────────────────────────────

  if (DEP_GRAPH_SIGNALS.some(isEnabled) && ecosystem === 'npm') {
    try {
      const depFindings = await analyzeNewDeps(metadata);
      for (const f of depFindings.filter(f => isEnabled(f.signal))) {
        signals.push({ ...f, layer: 2 });
      }
    } catch (err) {
      log.warn(`dep graph analysis failed for ${metadata.name}: ${err.message}`);
      warnings.push(`dependency graph analysis failed: ${err.message}`);
    }
  }

  // ─── Layer 3: Behavioral fingerprinting ────────────────────────────

  if (BEHAVIOR_SIGNALS.some(isEnabled)) {
    try {
      const astResult = metadata.installScripts
        ? inspectAllScripts(metadata.installScripts, metadata.name)
        : null;
      const currentProfile = buildProfile(metadata, astResult);
      const previousProfile = buildPreviousProfile(metadata);

      // When the registry exposed the previous version's lifecycle scripts,
      // build the previous profile from REAL data so the escalation diff is
      // genuine. Absence of scripts is itself diffable data ({}); only a
      // null previousInstallScripts leaves capabilities unknown.
      let effectivePrevious = previousProfile;
      if (previousProfile && metadata.previousInstallScripts != null) {
        const prevScripts = metadata.previousInstallScripts;
        const prevAst = Object.keys(prevScripts).length > 0
          ? inspectAllScripts(prevScripts, metadata.name)
          : null;
        effectivePrevious = buildProfile(
          { hasInstallScripts: Object.keys(prevScripts).length > 0 },
          prevAst
        );
        effectivePrevious.capabilitiesKnown = true;
        // Capability data now comes from real previous scripts; the remaining
        // profile fields stay metadata-derived (from buildPreviousProfile's
        // estimate) so DEPENDENCY_SPIKE / MAINTAINER_REDUCTION /
        // REPOSITORY_REMOVED behave exactly as before.
        effectivePrevious.dependencyCount = previousProfile.dependencyCount;
        effectivePrevious.maintainerCount = previousProfile.maintainerCount;
        effectivePrevious.hasRepository = previousProfile.hasRepository;
      }

      const behaviorFindings = diffProfiles(currentProfile, effectivePrevious);

      for (const f of collapseCapabilityFindings(
        behaviorFindings.filter(f => isEnabled(f.signal))
      )) {
        signals.push({ ...f, layer: 3 });
      }
    } catch (err) {
      log.warn(`behavioral analysis failed for ${metadata.name}: ${err.message}`);
      warnings.push(`behavioral analysis failed: ${err.message}`);
    }
  }

  // ─── Composite scoring ─────────────────────────────────────────────

  // Attach confidence grades after all layers finished, so dep-graph and
  // behavioral signals (pushed via spread) get graded too. Every consumer
  // (analyze, inspect, watch) sees the same grading without duplicating it.
  const finalSignals = deduplicateSignals(signals);
  for (const s of finalSignals) {
    s.confidence = SIGNAL_CONFIDENCE[s.signal] || 'inferred';
  }

  const riskScore = computeRiskScore(finalSignals, metadata);
  const riskLevel = scoreToLevel(riskScore);

  return { signals: finalSignals, riskScore, riskLevel, warnings };
}

function advisoryIdentifiers(advisory) {
  return [advisory?.id, advisory?.displayId, ...(advisory?.aliases || [])]
    .filter(id => typeof id === 'string' && id.length > 0);
}

export function isExplicitMaliciousAdvisory(advisory) {
  return advisoryIdentifiers(advisory).some(id => /^MAL-/i.test(id)) ||
    advisory?.databaseSpecific?.type === 'MALWARE' ||
    advisory?.database_specific?.type === 'MALWARE';
}

function highestAdvisorySeverity(advisories, fallback) {
  const highest = advisories.reduce((current, advisory) => {
    const candidate = String(advisory?.severity || '').toUpperCase();
    if (!SEVERITY[candidate]) return current;
    if (!current || SEVERITY[candidate].order > SEVERITY[current].order) return candidate;
    return current;
  }, null);
  return highest || fallback;
}

function advisorySignal(signal, advisories, description, fallbackSeverity) {
  const ids = [...new Set(advisories.flatMap(advisoryIdentifiers))];
  return {
    signal,
    severity: highestAdvisorySeverity(advisories, fallbackSeverity),
    description,
    evidence: {
      vulnCount: advisories.length,
      ids,
      advisories: advisories.map(v => ({
        id: v.id,
        displayId: v.displayId,
        aliases: v.aliases || [],
        severity: v.severity,
      })),
    },
    layer: 4,
  };
}

function collapseCapabilityFindings(findings) {
  const collapsible = new Set(['INITIAL_DANGEROUS_CAPABILITY', 'CAPABILITY_ESCALATION']);
  const grouped = new Map();
  const result = [];

  for (const finding of findings) {
    if (!collapsible.has(finding.signal)) {
      result.push(finding);
      continue;
    }
    const group = grouped.get(finding.signal) || [];
    group.push(finding);
    grouped.set(finding.signal, group);
  }

  for (const [signal, group] of grouped) {
    const capabilities = [...new Set(group.map(f => f.evidence?.capability).filter(Boolean))];
    const strongest = group.reduce((best, f) =>
      (SEVERITY[f.severity]?.order || 0) > (SEVERITY[best.severity]?.order || 0) ? f : best
    );
    result.push({
      ...strongest,
      description: group.length === 1
        ? strongest.description
        : `${signal === 'CAPABILITY_ESCALATION' ? 'Package gained' : 'Package has'} dangerous capabilities: ${capabilities.join(', ')}`,
      evidence: { ...strongest.evidence, capabilities },
    });
  }
  return result;
}

function deduplicateSignals(signals) {
  const byKey = new Map();
  for (const finding of signals) {
    const depName = finding.evidence?.depName || '';
    const script = finding.evidence?.script || '';
    const pattern = finding.evidence?.pattern || '';
    const key = depName
      ? `${finding.signal}|dep:${depName}`
      : (finding.signal === 'AST_DANGEROUS_PATTERN'
          ? `${finding.signal}|script:${script}|pattern:${pattern}`
          : `${finding.signal}|${finding.description}`);
    const existing = byKey.get(key);
    if (!existing || (SEVERITY[finding.severity]?.order || 0) > (SEVERITY[existing.severity]?.order || 0)) {
      byKey.set(key, finding);
    }
  }
  return [...byKey.values()];
}

/**
 * Compute composite risk score with context multipliers.
 */
function computeRiskScore(signals, metadata) {
  let score = 0;

  for (const signal of signals) {
    let baseWeight = SEVERITY[signal.severity]?.weight || 1;

    // Context multipliers
    if (metadata?.packageAgeMs !== null && metadata.packageAgeMs < THIRTY_DAYS_MS) {
      baseWeight *= 2.0; // New packages get extra scrutiny
    }
    if (metadata?.maintainers?.length <= 1) {
      baseWeight *= 1.5; // Single maintainer = higher risk
    }
    if (signal.evidence?.knownGood) {
      baseWeight *= 0.2; // Known-good packages are heavily downweighted
    }

    score += baseWeight;
  }

  // Signal combination bonus: multiple signals compound the risk
  const uniqueSignals = new Set(signals.map(s => s.signal));
  if (uniqueSignals.size >= 3) score *= 1.5;
  if (uniqueSignals.size >= 5) score *= 2.0;

  return Math.round(score * 10) / 10;
}

// Exported: any consumer that mutates riskScore after analyzePackage()
// (provenance checks, deep tarball findings) must re-derive riskLevel with
// this, or the added signals silently don't count toward filtering/exit codes.
export function scoreToLevel(score) {
  if (score >= 30) return 'CRITICAL';
  if (score >= 15) return 'HIGH';
  if (score >= 5)  return 'MODERATE';
  if (score > 0)   return 'LOW';
  return 'NONE';
}

/**
 * Build a baseline profile for the previous version from metadata.
 * Since we don't have the previous version's full AST, we infer from metadata diffs.
 */
function buildPreviousProfile(metadata) {
  if (!metadata?.previousVersion) return null;

  // Infer: previous version had the removed deps, didn't have the added deps
  const prevDeps = (metadata.dependencies || [])
    .filter(d => !metadata.addedDeps?.includes(d))
    .concat(metadata.removedDeps || []);

  return {
    capabilities: [], // We can't know previous capabilities without AST of previous version
    capabilitiesKnown: false, // MUST be false — diffProfiles degrades to INITIAL_DANGEROUS_CAPABILITY
    hasInstallScripts: false, // Conservative: assume previous didn't have install scripts
    dependencyCount: prevDeps.length,
    maintainerCount: metadata.maintainers?.length || 0, // Assume same maintainer count
    hasRepository: !!metadata.repository,
  };
}

/**
 * Check if a script string is or contains inspectable JavaScript.
 * Returns the JS source to inspect, or null if not JS.
 *
 * Handles shell wrappers that real malware uses:
 *   sh -c 'node -e "..."'
 *   bash -c "node -e '...'"
 *   true; node -e '...'
 *   echo | node -e '...'
 */
function extractInlineJS(script) {
  // First, try to extract node -e payload from ANYWHERE in the script
  // (handles sh -c 'node -e ...', semicolons, pipes, etc.)
  const nodeEvalAnywhere = script.match(/node\s+(?:-e|--eval)\s+'([^']+)'/);
  if (nodeEvalAnywhere) return nodeEvalAnywhere[1];

  const nodeEvalDQ = script.match(/node\s+(?:-e|--eval)\s+"([^"]+)"/);
  if (nodeEvalDQ) return nodeEvalDQ[1];

  // sh -c or bash -c with embedded commands — extract the inner command and recurse
  const shellCMatch = script.match(/(?:sh|bash)\s+-c\s+['"](.+)['"]\s*$/);
  if (shellCMatch) return extractInlineJS(shellCMatch[1]);

  // Commands that just reference files — can't inspect without the file
  // But only skip if there's NO embedded JS we could extract
  if (/^(node|\.\/|\/)\s+[^\s;|&]*\.(js|mjs|cjs)\b/.test(script)) return null;
  if (/^(python|ruby|perl)\s/.test(script)) return null;
  if (/^(npm|npx|yarn|pnpm)\s/.test(script)) return null;

  // Looks like JS if it has JS-specific syntax
  if (/[;{}()=]/.test(script) || /\brequire\b|\bimport\b|\beval\b/.test(script)) {
    return script;
  }

  return null;
}

/**
 * Inspect all install scripts and merge results.
 */
function inspectAllScripts(installScripts, packageName) {
  const allFindings = [];
  const capabilities = {};

  for (const [name, body] of Object.entries(installScripts)) {
    if (!body) continue;
    const jsSource = extractInlineJS(body);
    if (jsSource) {
      try {
        const result = inspectJS(jsSource, `${packageName}/${name}`);
        allFindings.push(...result.findings);
        for (const [key, value] of Object.entries(result.capabilities)) {
          if (value) capabilities[key] = true;
        }
      } catch (err) {
        // Per-script failure — capture what we have, don't lose other scripts' findings
        log.debug(`inspectJS failed for ${packageName}/${name}: ${err.message}`);
        allFindings.push({
          pattern: 'ANALYSIS_ERROR',
          severity: 'HIGH',
          description: `AST inspection of ${name} script failed: ${err.message}`,
          line: null,
        });
      }
    }
  }

  return { findings: allFindings, capabilities };
}
