import { SEVERITY } from '../core/constants.js';
import { KNOWN_POSTINSTALL, POPULAR_NPM, POPULAR_PYPI } from '../core/allowlists.js';
import { inspectJS, inspectPython } from './ast-inspector.js';
import { analyzeNewDeps, detectTyposquat } from './dep-graph.js';
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
 * Run all detection layers for a single package.
 *
 * @param {Object} metadata — from npm-registry.js or pypi-registry.js
 * @param {Object} [osvResult] — from osv.js (null if not run)
 * @param {Object} options
 * @param {string} options.ecosystem — 'npm' or 'pypi'
 * @param {Object} [options.config] — from .vexesrc.json (for signal overrides)
 * @returns {Promise<{ signals: Signal[], riskScore: number, riskLevel: string }>}
 */
export async function analyzePackage(metadata, osvResult, options = {}) {
  const { ecosystem = 'npm', config } = options;
  const signals = [];
  const warnings = [];

  if (!metadata) {
    return { signals: [], riskScore: 0, riskLevel: 'UNKNOWN', warnings: ['metadata unavailable'] };
  }

  // Check if signal is disabled in config
  const signalConfig = config?.analyze?.signals || {};
  const isEnabled = (signal) => signalConfig[signal] !== 'off';

  // ─── Layer 4: Registry metadata signals (fast, no async) ───────────

  // KNOWN_COMPROMISED: OSV results exist
  if (isEnabled('KNOWN_COMPROMISED') && osvResult?.length > 0) {
    signals.push({
      signal: 'KNOWN_COMPROMISED',
      severity: 'CRITICAL',
      description: `${osvResult.length} known vulnerability(ies) in OSV database`,
      evidence: { vulnCount: osvResult.length, ids: osvResult.map(v => v.id) },
      layer: 4,
    });
  }

  // MAINTAINER_CHANGE
  // Time-decay: transfers > 90 days ago are less suspicious (legitimate handoffs settle)
  // Also downweight if the package has many maintainers (org-managed)
  if (isEnabled('MAINTAINER_CHANGE') && metadata.maintainerChanged) {
    const daysSincePublish = metadata.latestPublishTime
      ? (Date.now() - new Date(metadata.latestPublishTime).getTime()) / (24 * 60 * 60 * 1000)
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
      severity: isKnownGood ? 'LOW' : 'HIGH',
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
    // Long dormancy then sudden publish
    // Dormancy: if any gap between consecutive versions exceeds 1 year, that's suspicious
    // regardless of how long ago the latest publish was
    if (metadata.dormancyMs && metadata.dormancyMs > ONE_YEAR_MS) {
      signals.push({
        signal: 'VERSION_ANOMALY',
        severity: 'HIGH',
        description: `Package was dormant for ${Math.floor(metadata.dormancyMs / (86400000))} days then suddenly published`,
        evidence: { dormancyMs: metadata.dormancyMs },
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
    if (!isKnownGood) {
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
                evidence: { script: scriptName, pattern: finding.pattern },
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
  }

  // ─── Layer 2: Dependency graph analysis ────────────────────────────

  if (isEnabled('PHANTOM_DEPENDENCY') && ecosystem === 'npm') {
    try {
      const depFindings = await analyzeNewDeps(metadata);
      for (const f of depFindings) {
        signals.push({ ...f, layer: 2 });
      }
    } catch (err) {
      log.warn(`dep graph analysis failed for ${metadata.name}: ${err.message}`);
      warnings.push(`dependency graph analysis failed: ${err.message}`);
    }
  }

  // ─── Layer 3: Behavioral fingerprinting ────────────────────────────

  if (isEnabled('CAPABILITY_ESCALATION')) {
    try {
      const astResult = metadata.installScripts
        ? inspectAllScripts(metadata.installScripts, metadata.name)
        : null;
      const currentProfile = buildProfile(metadata, astResult);
      const previousProfile = buildPreviousProfile(metadata);
      const behaviorFindings = diffProfiles(currentProfile, previousProfile);

      for (const f of behaviorFindings) {
        signals.push({ ...f, layer: 3 });
      }
    } catch (err) {
      log.warn(`behavioral analysis failed for ${metadata.name}: ${err.message}`);
      warnings.push(`behavioral analysis failed: ${err.message}`);
    }
  }

  // ─── Composite scoring ─────────────────────────────────────────────

  const riskScore = computeRiskScore(signals, metadata);
  const riskLevel = scoreToLevel(riskScore);

  return { signals, riskScore, riskLevel, warnings };
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

function scoreToLevel(score) {
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
    hasInstallScripts: false, // Conservative: assume previous didn't have install scripts
    dependencyCount: prevDeps.length,
    maintainerCount: metadata.maintainers?.length || 0, // Assume same maintainer count
    hasRepository: !!metadata.repository,
  };
}

/**
 * Check if a script string is or contains inspectable JavaScript.
 * Returns the JS source to inspect, or null if not JS.
 */
function extractInlineJS(script) {
  // node -e 'require("child_process").exec(...)' — THE most common attack vector
  // Extract the quoted JS payload from node -e or node --eval
  const nodeEvalMatch = script.match(/^node\s+(?:-e|--eval)\s+['"](.+)['"]\s*$/);
  if (nodeEvalMatch) return nodeEvalMatch[1];

  // Double-quoted variant with escapes
  const nodeEvalMatch2 = script.match(/^node\s+(?:-e|--eval)\s+"(.+)"\s*$/);
  if (nodeEvalMatch2) return nodeEvalMatch2[1];

  // Shell commands that launch node with scripts — can't inspect without the file
  if (/^(node|sh|bash|python|ruby|perl|\.\/|\/)\s/.test(script)) return null;
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
