import { resolve, join } from 'node:path';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope, normalizeFinding, REACHABILITY } from '../cli/schema.js';
import { C, createSpinner, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { EXIT, SEVERITY, VERSION } from '../core/constants.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { checkProvenance } from '../analysis/provenance.js';
import { analyzePackage, scoreToLevel } from '../analysis/signals.js';
import { inspectTarball, getPypiTarballUrl, downloadAndExtractToDisk } from '../analysis/tarball-inspector.js';
import { detectSandboxHost } from '../analysis/sandbox/index.js';
import { runHarnessed, pickEntryScript, buildSandboxSignal } from '../analysis/sandbox/harness.js';
import { isAnalysisSignalEnabled } from './analyze.js';

/**
 * `vexes inspect <name>[@<version>]` — single-package on-demand assessment.
 *
 * Collects evidence for a single-package dependency decision; it does not
 * determine safety. No project is required. It inspects a spec directly: OSV vulnerability history + registry metadata +
 * supported heuristic layers + decoded npm provenance metadata. `--deep` adds
 * bounded AST inspection of the registry package tarball. Emits through the
 * shared JSON envelope.
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
    out(`\n  ${C.bold}vexes inspect${C.reset} v${VERSION} ${C.dim}— ${sanitize(name)}${requestedVersion ? ' @' + sanitize(requestedVersion) : ''} (${sanitize(ecosystem)})${C.reset}\n`);
  }

  const warnings = [];
  let sandboxIncomplete = false;
  let deepIncomplete = false;
  let provenanceIncomplete = false;
  const spinner = isJSON ? null : createSpinner(`Fetching registry metadata for ${sanitize(name)}...`);
  const emitIncomplete = (reason, failedVersion = requestedVersion || null) => {
    warnings.push(reason);
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'inspect',
        target: { dir: targetDir, lockfiles: [], ecosystems: [ecosystem] },
        complete: false,
        warnings,
        summary: { total: 1, vulnerable: 0, flagged: 0, unreachable: 0 },
        findings: [],
        extra: {
          package: { name, version: failedVersion, ecosystem },
          assessment: null,
          stages: {
            deep: { requested: !!flags.deep, complete: !flags.deep, packageComplete: !flags.deep },
            sandbox: { requested: !!flags.sandbox, complete: !flags.sandbox },
          },
        },
      }), null, 2));
    } else {
      out(`  ${C.red}! Inspection incomplete — ${sanitize(reason)}${C.reset}\n`);
    }
    return EXIT.ERROR;
  };

  // 1. Registry metadata (anchored to the requested version when given)
  const metadata = ecosystem === 'npm'
    ? await fetchNpmMetadata(name, requestedVersion)
    : await fetchPypiMetadata(name, requestedVersion);

  if (!metadata) {
    spinner?.stop('failed');
    const reason = `registry returned no metadata for ${name}`;
    log.error(reason);
    return emitIncomplete(reason);
  }

  // Registry adapters share this exact-version trust contract. Treat any
  // provider's explicit incomplete/absent anchor as fatal; never substitute
  // that provider's latest release for the version the user requested.
  const metadataAnchorIncomplete = (
    metadata.metadataComplete === false ||
    (requestedVersion && (
      metadata.requestedVersionFound === false ||
      metadata.anchoredToInstalled === false
    ))
  );
  if (metadataAnchorIncomplete) {
    spinner?.stop('exact version metadata unavailable');
    return emitIncomplete(
      metadata.anchorError || `registry metadata is not anchored to requested version ${name}@${requestedVersion}`,
      requestedVersion || metadata.latestVersion || null,
    );
  }

  const version = requestedVersion || metadata.latestVersion || metadata.latestAvailable;
  if (!version) {
    spinner?.stop('failed');
    const reason = `could not determine a version for ${name}`;
    log.error(reason);
    return emitIncomplete(reason);
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
  const registryArtifact = ecosystem === 'npm' ? registryArtifactFromMetadata(metadata) : null;
  if (registryArtifact) assessment.registryArtifact = registryArtifact;

  // 4. Provenance (npm): inspect attestation presence and decode its payload.
  //    Cryptographic verification is not implemented here.
  if (ecosystem === 'npm') {
    const provSpinner = isJSON ? null : createSpinner('Checking Sigstore provenance...');
    let prov = null;
    try { prov = await checkProvenance(name, version); }
    catch (err) { log.debug(`provenance check failed: ${err.message}`); }
    provSpinner?.stop('provenance checked');

    if (!prov || prov.attestationStatus === 'unavailable') {
      provenanceIncomplete = true;
      warnings.push(`provenance attestation lookup incomplete for ${name}@${version}`);
    } else if (prov?.hasAttestation === true) {
      if (prov.attestationDecoded !== true) {
        provenanceIncomplete = true;
        warnings.push(`provenance attestation payload could not be decoded for ${name}@${version}`);
      }
      assessment.provenance = {
        attestationStatus: prov.attestationStatus,
        attestationDecoded: prov.attestationDecoded,
        verificationStatus: prov.verificationStatus,
        cryptographicallyVerified: false,
        transparencyLogEntryPresent: prov.transparencyLogEntryPresent,
        claimedSourceRepo: prov.claimedSourceRepo,
        claimedBuildType: prov.claimedBuildType,
        sourceRepo: prov.sourceRepo,
        buildType: prov.buildType,
      };
    } else if (prov?.hasAttestation === false && isAnalysisSignalEnabled(config, 'MISSING_PROVENANCE')) {
      assessment.signals.push({
        signal: 'MISSING_PROVENANCE',
        severity: 'LOW',
        confidence: 'deterministic',
        description: 'No npm provenance attestation was published for this package version',
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
        : registryArtifact?.tarball || null;
      if (url) {
        const tarResult = await inspectTarball(url, name, ecosystem === 'npm'
          ? { integrity: registryArtifact?.integrity || null, shasum: registryArtifact?.shasum || null }
          : undefined);
        warnings.push(...(tarResult.warnings || []).map(w => `deep inspection: ${w}`));
        assessment.deepInspection = {
          requested: true,
          coverage: tarResult.coverage || { mode: 'unknown', packageComplete: false },
          packageComplete: tarResult.coverage?.packageComplete === true,
        };
        if (assessment.deepInspection.packageComplete !== true) deepIncomplete = true;
        let addedRisk = 0;
        if (isAnalysisSignalEnabled(config, 'TARBALL_DANGEROUS_PATTERN')) {
          for (const finding of tarResult.findings) {
            assessment.signals.push({
              signal: 'TARBALL_DANGEROUS_PATTERN',
              severity: finding.severity,
              confidence: 'heuristic',
              description: finding.description,
              evidence: { file: finding.file, pattern: finding.pattern },
              layer: 1,
            });
            addedRisk += SEVERITY[finding.severity]?.weight || 0;
          }
        }
        assessment.riskScore += addedRisk;
        if (tarResult.inspectedFiles.length > 0) {
          assessment.tarballInspected = tarResult.inspectedFiles;
        }
      } else {
        deepIncomplete = true;
        warnings.push('could not determine tarball URL — --deep skipped');
      }
    } catch (err) {
      deepIncomplete = true;
      log.debug(`deep inspection failed: ${err.message}`);
      warnings.push('--deep tarball inspection failed: ' + err.message);
    }
    deepSpinner?.stop('deep inspection complete');
  }

  // 5b. --sandbox: run qualified npm candidates with contained writes and
  // hidden user/project paths on the accepted bwrap host.
  // under a recorder shim. Any requested-but-incomplete dynamic stage is a
  // warning and makes the command incomplete; partial evidence is never used.
  if (flags.sandbox) {
    let tmp;
    try {
      if (ecosystem === 'pypi') {
        sandboxIncomplete = true;
        warnings.push('sandbox: PyPI dynamic extraction/execution is unsupported and was refused');
      } else {
      // Refuse-by-default pre-flight (mirrors analyze step 5c): resolve the
      // effective isolation host before downloading anything. No host ⇒ we
      // would refuse at run time regardless — so don't pull the tarball only
      // to refuse it. One honest warning; never a behavior signal.
      const effectiveHost = config.sandboxHost !== undefined ? config.sandboxHost : detectSandboxHost();
      if (!effectiveHost) {
        sandboxIncomplete = true;
        warnings.push('sandbox skipped — no bwrap host that contains writes and hides user/project host paths');
      } else if (assessment.riskScore < 15 || assessment.signals.length === 0) {
        sandboxIncomplete = true;
        warnings.push('sandbox: package below sandbox threshold (riskScore >= 15) — skipped');
      } else {
        tmp = mkdtempSync(join(tmpdir(), 'vexes-inspect-sandbox-'));
        const url = registryArtifact?.tarball || null;
        if (!url) {
          sandboxIncomplete = true;
          warnings.push('sandbox: could not determine tarball URL — skipped');
        } else {
          await downloadAndExtractToDisk(url, name, tmp,
            { integrity: registryArtifact?.integrity || null, shasum: registryArtifact?.shasum || null });
            const entry = pickEntryScript(tmp);
            if (!entry) {
              sandboxIncomplete = true;
              warnings.push(`sandbox: no runnable entrypoint in ${name}@${version} — skipped`);
            } else {
              const child = runHarnessed({ workdir: tmp, entryScript: entry, allow: true, timeoutMs: 10000, host: config.sandboxHost });
              if (child.status === 'refused') {
                sandboxIncomplete = true;
                warnings.push(`sandbox skipped — ${child.reason}`);
              } else if (child.status === 'failed') {
                sandboxIncomplete = true;
                warnings.push(`sandbox: ${name}@${version} harness failed (${child.reason || 'dynamic evidence incomplete'})`);
              } else {
                // Candidate-visible recorder hooks can provide positive
                // observations, never trustworthy negative evidence.
                sandboxIncomplete = true;
                warnings.push(`sandbox: ${name}@${version} produced positive-only behavioral observations; empty recorder evidence is not trusted as proof of benign behavior`);
                const signal = isAnalysisSignalEnabled(config, 'SANDBOX_BEHAVIOR')
                  ? buildSandboxSignal({ name, version, evidence: child.evidence })
                  : null;
                if (signal) {
                  assessment.signals.push(signal);
                  assessment.sandboxEvidence = signal.evidence.dynamic;
                  assessment.riskScore += SEVERITY[signal.severity].weight;
                }
              }
            }
        }
      }
      }
    } catch (err) {
      sandboxIncomplete = true;
      log.debug(`sandbox step failed for ${name}@${version}: ${err.message}`);
      warnings.push(`sandbox step failed: ${err.message}`);
    } finally {
      if (tmp) rmSync(tmp, { recursive: true, force: true });
    }
  }

  // Re-derive risk level — provenance/deep steps mutated riskScore after
  // analyzePackage computed it (same pattern as analyze.js).
  if (assessment.riskLevel !== 'UNKNOWN') {
    assessment.riskLevel = scoreToLevel(assessment.riskScore);
  }

  const complete = osvComplete && !sandboxIncomplete && !deepIncomplete && !provenanceIncomplete;
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
      extra: {
        package: { name, version, ecosystem },
        assessment,
        stages: {
          deep: {
            requested: !!flags.deep,
            complete: !flags.deep || !deepIncomplete,
            packageComplete: !flags.deep || assessment.deepInspection?.packageComplete === true,
          },
          sandbox: { requested: !!flags.sandbox, complete: !flags.sandbox || !sandboxIncomplete },
          provenance: {
            requested: ecosystem === 'npm',
            complete: ecosystem !== 'npm' || !provenanceIncomplete,
            cryptographicVerificationPerformed: false,
          },
        },
      },
    }), null, 2));
  } else {
    printInspectText(assessment, osvVulns, { osvComplete });

    if (warnings.length > 0) {
      out(`\n  ${C.yellow}!${C.reset} warnings:`);
      for (const w of warnings) out(`    ${C.yellow}${sanitize(w)}${C.reset}`);
      out('');
    }
  }

  if (!complete) return EXIT.ERROR;
  // OSV findings are policy findings in their own right. Do not let the
  // composite heuristic score down-weight a lone HIGH advisory into a
  // MODERATE assessment and therefore a successful process exit.
  const minAdvisoryOrder = SEVERITY[String(config.severity || 'moderate').toUpperCase()]?.order ?? SEVERITY.MODERATE.order;
  const hasAdvisoryAtThreshold = osvVulns.some(v =>
    (SEVERITY[String(v.severity || '').toUpperCase()]?.order ?? 0) >= minAdvisoryOrder
  );
  return hasAdvisoryAtThreshold || assessment.riskLevel === 'CRITICAL' || assessment.riskLevel === 'HIGH'
    ? EXIT.VULNS_FOUND
    : EXIT.OK;
}

function countBySeverity(vulns) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) {
    const k = String(v.severity || '').toLowerCase();
    if (k in counts) counts[k]++;
  }
  return counts;
}

export function printInspectText(assessment, osvVulns, { osvComplete = true } = {}) {
  const { name, version, ecosystem } = assessment;
  const rColor = assessment.riskLevel === 'CRITICAL' ? C.red
    : assessment.riskLevel === 'HIGH' ? C.yellow
      : assessment.riskLevel === 'MODERATE' ? C.cyan : C.green;
  out(`  ${C.bold}${sanitize(name)}@${sanitize(version)}${C.reset} ${C.dim}(${sanitize(ecosystem)})${C.reset}`);
  out(`  Risk Level: ${rColor}${sanitize(assessment.riskLevel)}${C.reset} (score: ${sanitize(assessment.riskScore)})`);

  if (assessment.provenance) {
    const decoded = assessment.provenance.attestationDecoded ? 'payload decoded' : 'payload not decoded';
    out(`  Attestation: ${C.cyan}present; ${sanitize(decoded)}${C.reset} (${sanitize(assessment.provenance.claimedSourceRepo || 'unknown claimed source')}; cryptographic verification not performed)`);
  } else if (assessment.signals.some(s => s.signal === 'MISSING_PROVENANCE')) {
    out(`  Provenance: ${C.dim}none${C.reset}`);
  }

  if (!osvComplete) {
    out(`  OSV: ${C.yellow}unknown — vulnerability lookup incomplete${C.reset}`);
  } else if (osvVulns.length > 0) {
    out(`  OSV: ${C.red}${osvVulns.length} known vulnerability(s)${C.reset} — ${osvVulns.map(v => sanitize(v.id)).join(', ')}`);
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
    out(`  ${sColor}● ${sanitize(s.severity)}${C.reset} ${C.bold}${sanitize(s.signal)}${C.reset}${conf} ${C.dim}(L${sanitize(s.layer)}: ${sanitize(layerNames[s.layer] || '?')})${C.reset}`);
    out(`    ${sanitize(s.description)}`);
    out('');
  }
}

function registryArtifactFromMetadata(metadata) {
  if (!metadata) return null;
  return {
    tarball: metadata.artifact?.tarball || metadata.tarball || null,
    integrity: metadata.artifact?.integrity || metadata.integrity || null,
    shasum: metadata.artifact?.shasum || metadata.shasum || null,
  };
}
