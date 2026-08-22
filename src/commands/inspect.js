import { resolve } from 'node:path';
import { statSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope, normalizeFinding, REACHABILITY } from '../cli/schema.js';
import { C, createSpinner, out } from '../cli/output.js';
import { log } from '../core/logger.js';
import { EXIT, SEVERITY, VERSION } from '../core/constants.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { checkProvenance } from '../analysis/provenance.js';
import { analyzePackage, scoreToLevel } from '../analysis/signals.js';
import { inspectTarball, getTarballUrl, getPypiTarballUrl } from '../analysis/tarball-inspector.js';

/**
 * `vexes inspect <name>[@<version>]` — single-package on-demand assessment.
 *
 * The agent's "is it safe to add this dependency?" tool. No project required;
 * inspects a spec directly: OSV vulnerability history + registry metadata +
 * all detection layers + Sigstore provenance. `--deep` adds AST inspection of
 * the real package tarball. Emits through the shared JSON envelope.
 */

/**
 * Parse `name[@version]` — version is optional (defaults to dist-tags.latest).
 * Must split on the LAST '@' so scoped packages (@scope/name@1.2.3) work.
 */
export function parseInspectTarget(arg) {
  if (!arg) return null;
  const spec = String(arg).trim();
  if (!spec) return null;
  const atIdx = spec.lastIndexOf('@');
  if (atIdx <= 0) return { name: spec, version: null };
  const name = spec.slice(0, atIdx);
  const version = spec.slice(atIdx + 1);
  if (!name || !version) return { name: spec, version: null };
  return { name, version };
}

export async function runInspect(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const ecosystem = (flags.ecosystem || 'npm').toLowerCase();

  const parsed = parseInspectTarget(args[0]);
  if (!parsed?.name) {
    log.error('usage: vexes inspect <name>[@<version>] [--ecosystem npm|pypi] [--deep] [--json]');
    return EXIT.ERROR;
  }
  const { name, version: requestedVersion } = parsed;

  if (!['npm', 'pypi'].includes(ecosystem)) {
    log.error(`inspect supports npm and pypi (got "${ecosystem}")`);
    return EXIT.ERROR;
  }

  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { /* --path is only for config lookup in inspect mode */ }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes inspect${C.reset} v${VERSION} ${C.dim}— ${name}${requestedVersion ? ' @' + requestedVersion : ''} (${ecosystem})${C.reset}\n`);
  }

  const warnings = [];
  const spinner = isJSON ? null : createSpinner(`Fetching registry metadata for ${name}...`);

  // 1. Registry metadata (anchored to the requested version when given)
  const metadata = ecosystem === 'npm'
    ? await fetchNpmMetadata(name, requestedVersion)
    : await fetchPypiMetadata(name, requestedVersion);

  if (!metadata) {
    spinner?.stop('failed');
    log.error(`registry returned no metadata for ${name} — does this package exist?`);
    return EXIT.ERROR;
  }

  const version = requestedVersion && metadata.anchoredToInstalled !== false
    ? requestedVersion
    : metadata.latestVersion || metadata.latestAvailable;
  if (!version) {
    spinner?.stop('failed');
    log.error(`could not determine a version for ${name}`);
    return EXIT.ERROR;
  }
  if (requestedVersion && metadata.anchoredToInstalled === false) {
    warnings.push(`${name}@${requestedVersion} not found — inspecting latest (${version})`);
  }

  spinner?.stop(`${name}@${version} metadata loaded`);

  // 2. OSV vulnerability history for this exact version
  const osvSpinner = isJSON ? null : createSpinner(`Querying OSV.dev for ${name}@${version}...`);
  const osvResult = await queryBatch([{ name, version, ecosystem }]);
  osvSpinner?.stop('OSV query complete');
  const key = `${ecosystem}:${name}@${version}`;
  const osvVulns = osvResult.results.get(key) || [];
  const osvComplete = isQueryComplete(osvResult, 1);
  if (!osvComplete) warnings.push('OSV vulnerability lookup incomplete');
  warnings.push(...osvResult.failures);

  // 3. All detection layers (metadata signals + OSV)
  const analyzed = await analyzePackage(metadata, osvVulns, { ecosystem, config });

  const assessment = {
    name,
    version,
    ecosystem,
    direct: null, // inspect has no project tree to judge directness against
    signals: analyzed.signals,
    riskScore: analyzed.riskScore,
    riskLevel: analyzed.riskLevel,
  };

  // 4. Provenance (npm): detached verification of Sigstore attestation.
  //    Presence is a fact; absence is a deterministic LOW/MODERATE signal.
  if (ecosystem === 'npm') {
    const provSpinner = isJSON ? null : createSpinner('Checking Sigstore provenance...');
    let prov = null;
    try { prov = await checkProvenance(name, version); }
    catch (err) { log.debug(`provenance check failed: ${err.message}`); }
    provSpinner?.stop('provenance checked');

    if (prov?.hasProvenance === true) {
      assessment.provenance = { sourceRepo: prov.sourceRepo, buildType: prov.buildType };
    } else if (prov?.hasProvenance === false) {
      assessment.signals.push({
        signal: 'MISSING_PROVENANCE',
        severity: 'LOW',
        confidence: 'deterministic',
        description: 'No Sigstore provenance attestation — package was not verifiably built from source',
        evidence: {},
        layer: 4,
      });
      assessment.riskScore += SEVERITY.LOW.weight;
    }
  }

  // 5. --deep: AST-inspect the actual package code (no execution)
  if (flags.deep) {
    const deepSpinner = isJSON ? null : createSpinner(`Inspecting package tarball (--deep)...`);
    try {
      const url = ecosystem === 'pypi'
        ? await getPypiTarballUrl(name, version)
        : getTarballUrl(metadata, version);
      if (url) {
        const tarResult = await inspectTarball(url, name);
        for (const finding of tarResult.findings) {
          assessment.signals.push({
            signal: 'TARBALL_DANGEROUS_PATTERN',
            severity: finding.severity,
            confidence: 'heuristic',
            description: finding.description,
            evidence: { file: finding.file, pattern: finding.pattern },
            layer: 1,
          });
        }
        assessment.riskScore += tarResult.findings.length * SEVERITY.HIGH.weight;
        if (tarResult.inspectedFiles.length > 0) {
          assessment.tarballInspected = tarResult.inspectedFiles;
        }
      } else {
        warnings.push('could not determine tarball URL — --deep skipped');
      }
    } catch (err) {
      log.debug(`deep inspection failed: ${err.message}`);
      warnings.push('--deep tarball inspection failed: ' + err.message);
    }
    deepSpinner?.stop('deep inspection complete');
  }

  // Re-derive risk level — provenance/deep steps mutated riskScore after
  // analyzePackage computed it (same pattern as analyze.js).
  if (assessment.riskLevel !== 'UNKNOWN') {
    assessment.riskLevel = scoreToLevel(assessment.riskScore);
  }

  const complete = osvComplete;
  const counts = countBySeverity(osvVulns);

  // 6. Output
  if (isJSON) {
    const findings = osvVulns.map(v => normalizeFinding(v, { reachability: REACHABILITY.UNKNOWN }));
    out(JSON.stringify(buildEnvelope({
      command: 'inspect',
      target: { dir: targetDir, lockfiles: [], ecosystems: [ecosystem] },
      complete,
      warnings,
      summary: { total: 1, vulnerable: osvVulns.length, flagged: assessment.riskLevel === 'NONE' ? 0 : 1, ...counts, unreachable: 0 },
      findings,
      extra: { package: { name, version, ecosystem }, assessment },
    }), null, 2));
  } else {
    printInspectText(assessment, osvVulns);

    if (warnings.length > 0) {
      out(`\n  ${C.yellow}!${C.reset} warnings:`);
      for (const w of warnings) out(`    ${C.yellow}${w}${C.reset}`);
      out('');
    }
  }

  if (!complete) return EXIT.ERROR;
  return assessment.riskLevel === 'CRITICAL' || assessment.riskLevel === 'HIGH' ? EXIT.VULNS_FOUND : EXIT.OK;
}

function countBySeverity(vulns) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) {
    const k = String(v.severity || '').toLowerCase();
    if (k in counts) counts[k]++;
  }
  return counts;
}

function printInspectText(assessment, osvVulns) {
  const { name, version, ecosystem } = assessment;
  const rColor = assessment.riskLevel === 'CRITICAL' ? C.red
    : assessment.riskLevel === 'HIGH' ? C.yellow
      : assessment.riskLevel === 'MODERATE' ? C.cyan : C.green;
  out(`  ${C.bold}${name}@${version}${C.reset} ${C.dim}(${ecosystem})${C.reset}`);
  out(`  Risk Level: ${rColor}${assessment.riskLevel}${C.reset} (score: ${assessment.riskScore})`);

  if (assessment.provenance) {
    out(`  Provenance: ${C.green}✓ verified${C.reset} (${assessment.provenance.sourceRepo || 'unknown source'})`);
  } else if (assessment.signals.some(s => s.signal === 'MISSING_PROVENANCE')) {
    out(`  Provenance: ${C.dim}none${C.reset}`);
  }

  if (osvVulns.length > 0) {
    out(`  OSV: ${C.red}${osvVulns.length} known vulnerability(s)${C.reset} — ${osvVulns.map(v => v.id).join(', ')}`);
  } else {
    out(`  OSV: ${C.green}no known vulnerabilities${C.reset} for this version`);
  }

  if (assessment.signals.length === 0) {
    out(`\n  ${C.green}No risk signals detected.${C.reset}\n`);
    return;
  }

  const layerNames = { 1: 'AST', 2: 'Dep Graph', 3: 'Behavioral', 4: 'Metadata' };
  out(`\n  ${C.bold}Signals (${assessment.signals.length}):${C.reset}\n`);
  for (const s of assessment.signals) {
    const sColor = s.severity === 'CRITICAL' ? C.red
      : s.severity === 'HIGH' ? C.yellow
        : s.severity === 'MODERATE' ? C.cyan : C.dim;
    const conf = s.confidence ? ` ${C.dim}(${s.confidence})${C.reset}` : '';
    out(`  ${sColor}● ${s.severity}${C.reset} ${C.bold}${s.signal}${C.reset}${conf} ${C.dim}(L${s.layer}: ${layerNames[s.layer] || '?'})${C.reset}`);
    out(`    ${s.description}`);
    out('');
  }
}
