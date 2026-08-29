import { resolve, basename, join } from 'node:path';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope } from '../cli/schema.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, SEVERITY, ANALYZE_CONCURRENCY, DEEP_ANALYZE_CONCURRENCY } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock, parseManifest as parseNpmManifest } from '../parsers/npm.js';
import { discover as discoverPnpm, parseLockfile as parsePnpmLock } from '../parsers/pnpm.js';
import { discover as discoverYarn, parseLockfile as parseYarnLock } from '../parsers/yarn.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { queryBatch } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { checkProvenance, detectAttestationIdentityMismatch } from '../analysis/provenance.js';
import { analyzePackage, scoreToLevel, SIGNAL_CONFIDENCE } from '../analysis/signals.js';
import { inspectTarball, getPypiTarballUrl, downloadAndExtractToDisk } from '../analysis/tarball-inspector.js';
import { detectSandboxHost } from '../analysis/sandbox/index.js';
import { runHarnessed, pickEntryScript, buildSandboxSignal } from '../analysis/sandbox/harness.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';
import { partitionByIgnore } from '../core/ignore.js';

/** Honor explicit per-signal policy for command-added detection layers. */
export function isAnalysisSignalEnabled(config, signal, compatibilityNames = []) {
  const configured = config?.analyze?.signals || {};
  if (configured[signal] !== undefined) return configured[signal] !== 'off';
  return !compatibilityNames.some(name => configured[name] === 'off');
}

/**
 * `vexes analyze` — Deep behavioral analysis of dependency supply chain.
 *
 * 4-layer detection engine:
 *   Layer 1: AST-based code analysis (acorn)
 *   Layer 2: Dependency graph profiling (phantom deps)
 *   Layer 3: Behavioral fingerprinting (capability diff)
 *   Layer 4: Registry metadata signals (maintainer changes, timing, provenance)
 */
export async function runAnalyze(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const verbose = config.verbose;

  // Validate path
  try {
    const stat = statSync(targetDir);
    if (!stat.isDirectory()) { log.error(`not a directory: ${targetDir}`); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes${C.reset} v${VERSION} ${C.dim}\u2500\u2500 analyzing supply chain${C.reset}\n`);
  }

  const warnings = [];
  let parseFailures = 0;
  let sandboxIncomplete = false;
  let deepIncomplete = false;
  let provenanceIncomplete = false;
  let parsedDependencyFiles = 0;
  let unresolvedManifestInputs = 0;
  const dependencyFiles = new Set();

  // 1. Discover and parse lockfiles
  const allDeps = [];
  const ecosystemsFound = new Set();

  for (const ecoName of config.ecosystems) {
    if (ecoName === 'npm') {
      // Discover from all npm-ecosystem lockfiles: npm, pnpm, yarn
      let npmLockfileCount = 0;
      for (const [discFn, parseFn] of [[discoverNpm, parseNpmLock], [discoverPnpm, parsePnpmLock], [discoverYarn, parseYarnLock]]) {
        const { lockfiles } = discFn(targetDir);
        npmLockfileCount += lockfiles.length;
        for (const lf of lockfiles) {
          dependencyFiles.add(basename(lf));
          try {
            const deps = parseFn(lf);
            parsedDependencyFiles++;
            if (deps.unresolvedEntries > 0) {
              unresolvedManifestInputs++;
              warnings.push(`${basename(lf)} contains ${deps.unresolvedEntries} local, linked, remote, or unanchored npm entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not analyzed`);
            }
            // For analyze, focus on direct deps by default (transitive deps = too much noise)
            const directDeps = deps.filter(d => d.isDirect);
            const depsToAnalyze = verbose ? deps : (directDeps.length > 0 ? directDeps : deps);
            allDeps.push(...depsToAnalyze);
            ecosystemsFound.add('npm');
          } catch (err) {
            warnings.push(`failed to parse ${basename(lf)}: ${err.message}`);
            log.error(warnings[warnings.length - 1]);
            parseFailures++;
          }
        }
      }

      // Without a lockfile, exact manifest pins are usable but ranges are not.
      // Never turn a range-only package.json into a complete empty analysis.
      if (npmLockfileCount === 0) {
        const { manifests } = discoverNpm(targetDir);
        if (manifests.length > 0) {
          unresolvedManifestInputs++;
          warnings.push('no npm lockfile found — exact package.json pins can be analyzed, but resolved/transitive coverage is incomplete');
        }
        for (const mf of manifests) {
          dependencyFiles.add(basename(mf));
          try {
            const deps = parseNpmManifest(mf);
            parsedDependencyFiles++;
            if (hasUnresolvedManifestEntries(mf, 'npm', 'package.json', deps.length)) {
              unresolvedManifestInputs++;
              warnings.push(`${basename(mf)} contains dependencies without exact registry versions — add a lockfile or exact pins; those entries were not analyzed`);
            }
            const directDeps = deps.filter(d => d.isDirect);
            const depsToAnalyze = verbose ? deps : (directDeps.length > 0 ? directDeps : deps);
            allDeps.push(...depsToAnalyze);
            ecosystemsFound.add('npm');
          } catch (err) {
            warnings.push(`failed to parse ${basename(mf)}: ${err.message}`);
            log.error(warnings[warnings.length - 1]);
            parseFailures++;
          }
        }
      }
    }
    if (ecoName === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(targetDir);
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      if (lockfiles.length === 0 && manifests.length > 0) {
        unresolvedManifestInputs++;
        warnings.push('no PyPI lockfile found — exact manifest pins can be analyzed, but resolved/transitive coverage is incomplete');
      }
      for (const file of files) {
        dependencyFiles.add(basename(file.path));
        try {
          const deps = parsePypiFile(file.path, file.format);
          parsedDependencyFiles++;
          if (hasUnresolvedManifestEntries(file.path, 'pypi', file.format, deps)) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(file.path)} contains dependencies without exact public-PyPI identities — those entries were not analyzed`);
            for (const failure of deps.includeFailures || []) warnings.push(`${basename(file.path)}: ${failure}`);
          }
          const directDeps = deps.filter(d => d.isDirect);
          const depsToAnalyze = verbose ? deps : (directDeps.length > 0 ? directDeps : deps);
          allDeps.push(...depsToAnalyze);
          ecosystemsFound.add('pypi');
        } catch (err) {
          warnings.push(`failed to parse ${basename(file.path)}: ${err.message}`);
          log.error(warnings[warnings.length - 1]);
          parseFailures++;
        }
      }
    }
  }

  if (allDeps.length === 0) {
    const complete = parseFailures === 0 && parsedDependencyFiles > 0 && unresolvedManifestInputs === 0;
    if (dependencyFiles.size === 0) {
      warnings.push('no supported dependency lockfile or manifest found — analysis did not run');
    } else if (parsedDependencyFiles === 0) {
      warnings.push('no dependency file could be parsed — analysis did not run');
    }

    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'analyze',
        target: { dir: targetDir, lockfiles: [...dependencyFiles], ecosystems: [...config.ecosystems] },
        complete,
        warnings,
        summary: { total: 0, flagged: 0 },
        findings: [],
        extra: { version: VERSION, results: [] },
      }), null, 2));
    } else if (complete) {
      out(`  ${C.dim}No dependencies found in the parsed dependency file(s)${C.reset}\n`);
    } else {
      out(`  ${C.red}! Analysis incomplete — no usable dependency data was available${C.reset}`);
      for (const warning of warnings) out(`  ${C.yellow}! ${warning}${C.reset}`);
      out('');
    }
    return complete ? EXIT.OK : EXIT.ERROR;
  }

  // Deduplicate
  const dedupMap = new Map();
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const uniqueDeps = [...dedupMap.values()];

  if (!isJSON) {
    const scope = verbose ? 'all' : 'direct';
    out(`  ${C.dim}Analyzing ${uniqueDeps.length} ${scope} dependencies${C.reset}`);
  }

  // 2. Open cache
  let cache;
  try { cache = new AdvisoryCache(config.cache?.dir); }
  catch (err) {
    log.warn(`cache unavailable: ${err.message}`);
    cache = new NoOpCache();
  }

  try {
    // 3. Run OSV scan first (feeds into KNOWN_COMPROMISED signal)
    const spinner = isJSON ? null : createSpinner('Scanning for known vulnerabilities...');
    const osvData = await queryBatch(uniqueDeps);
    spinner?.stop(`Vulnerability scan complete`);

    if (osvData.failures.length > 0) {
      warnings.push(...osvData.failures);
    }

    // 4. Fetch registry metadata + run analysis (concurrency-limited)
    const analyzeSpinner = isJSON ? null : createSpinner('Fetching registry metadata and running deep analysis...');
    const results = [];
    let analyzed = 0;

    for (let i = 0; i < uniqueDeps.length; i += ANALYZE_CONCURRENCY) {
        const chunk = uniqueDeps.slice(i, i + ANALYZE_CONCURRENCY);
        const chunkResults = await Promise.allSettled(
          chunk.map(dep => analyzeSinglePackage(dep, osvData, config, cache))
        );

      for (let j = 0; j < chunk.length; j++) {
        const dep = chunk[j];
        const r = chunkResults[j];
        analyzed++;

        if (r.status === 'fulfilled' && r.value) {
          results.push(r.value);
        } else {
          const errMsg = r.status === 'rejected' ? r.reason?.message : 'analysis returned null';
          log.debug(`analysis failed for ${dep.name}: ${errMsg}`);
          results.push({
            name: dep.name,
            version: dep.version,
            ecosystem: dep.ecosystem,
            signals: [],
            riskScore: 0,
            riskLevel: 'UNKNOWN',
            warnings: [`analysis failed: ${errMsg}`],
          });
        }

        analyzeSpinner?.update(`Analyzing dependencies... (${analyzed}/${uniqueDeps.length})`);
      }
    }

    analyzeSpinner?.stop(`${uniqueDeps.length} packages analyzed`);

    // 5. Check provenance for top-risk packages (npm only, concurrent)
    const highRiskNpm = results.filter(r => r.ecosystem === 'npm' && r.riskScore >= 5);
    if (highRiskNpm.length > 0 && config.ecosystems.includes('npm')) {
      const provSpinner = isJSON ? null : createSpinner(`Checking provenance for ${highRiskNpm.length} at-risk packages...`);

      // Concurrent provenance checks (same concurrency as analysis)
      for (let i = 0; i < highRiskNpm.length; i += ANALYZE_CONCURRENCY) {
        const chunk = highRiskNpm.slice(i, i + ANALYZE_CONCURRENCY);
        const provResults = await Promise.allSettled(
          chunk.map(pkg => checkProvenance(pkg.name, pkg.version).then(prov => ({ pkg, prov })))
        );

        for (let j = 0; j < provResults.length; j++) {
          const r = provResults[j];
          if (r.status !== 'fulfilled') {
            provenanceIncomplete = true;
            chunk[j].warnings.push(`provenance attestation lookup incomplete: ${r.reason?.message || 'unknown error'}`);
            continue;
          }
          const { pkg, prov } = r.value;
          if (!prov || prov.attestationStatus === 'unavailable') {
            provenanceIncomplete = true;
            pkg.warnings.push('provenance attestation lookup incomplete');
          } else if (prov?.hasAttestation === false && isAnalysisSignalEnabled(config, 'MISSING_PROVENANCE')) {
            // Only flag at MODERATE if the package already has other signals
            // Standalone MISSING_PROVENANCE is LOW — <5% of npm has provenance
            const hasOtherSignals = pkg.signals.length > 0;
            const severity = hasOtherSignals ? 'MODERATE' : 'LOW';
            pkg.signals.push({
              signal: 'MISSING_PROVENANCE',
              severity,
              confidence: SIGNAL_CONFIDENCE.MISSING_PROVENANCE,
              description: 'No npm provenance attestation was published for this package version',
              evidence: { standalone: !hasOtherSignals },
              layer: 4,
            });
            pkg.riskScore += SEVERITY[severity].weight;
          } else if (prov?.hasAttestation === true) {
            if (prov.attestationDecoded !== true) {
              provenanceIncomplete = true;
              pkg.warnings.push('provenance attestation was present but its payload could not be decoded');
            }
            pkg.provenance = {
              attestationStatus: prov.attestationStatus,
              attestationDecoded: prov.attestationDecoded,
              verificationStatus: prov.verificationStatus,
              cryptographicallyVerified: false,
              transparencyLogEntryPresent: prov.transparencyLogEntryPresent,
              claimedSourceRepo: prov.claimedSourceRepo,
              claimedBuildType: prov.claimedBuildType,
              // Compatibility names: decoded claims, not verified facts.
              sourceRepo: prov.sourceRepo,
              buildType: prov.buildType,
            };

            // 5a. Compare decoded claims with package identity. This can find a
            // mismatch; it does not authenticate the attestation itself.
            if (isAnalysisSignalEnabled(config, 'ATTESTATION_IDENTITY_MISMATCH', ['SIGNATURE_SPOOF'])) {
              const mismatch = detectAttestationIdentityMismatch({
                packageName: pkg.name,
                subjects: prov.subjects,
                sourceRepo: prov.sourceRepo,
                declaredRepo: pkg.declaredRepository,
              });
              if (mismatch) {
                pkg.signals.push(mismatch);
                pkg.riskScore += SEVERITY[mismatch.severity].weight;
              }
            }
          }
        }
      }

      provSpinner?.stop(`Provenance checked for ${highRiskNpm.length} packages`);
    }

    // 5b. Deep tarball inspection is explicit. Default analysis stays at the
    // metadata/OSV boundary and never surprises the user with package-code
    // downloads merely because a heuristic score crossed a threshold.
    const tarballCandidates = config.deep
      ? results.filter(r => r.ecosystem === 'npm' || r.ecosystem === 'pypi')
      : [];

    if (tarballCandidates.length > 0) {
      const tarSpinner = isJSON ? null : createSpinner(`Deep code inspection for ${tarballCandidates.length} packages...`);

      for (let i = 0; i < tarballCandidates.length; i += DEEP_ANALYZE_CONCURRENCY) {
        const chunk = tarballCandidates.slice(i, i + DEEP_ANALYZE_CONCURRENCY);
        const tarResults = await Promise.allSettled(
          chunk.map(async (pkg) => {
            let tarUrl;
            if (pkg.ecosystem === 'pypi') {
              tarUrl = await getPypiTarballUrl(pkg.name, pkg.version);
            } else {
              tarUrl = pkg.registryArtifact?.tarball || null;
            }
            if (!tarUrl) return { error: 'could not determine tarball URL' };
            return inspectTarball(tarUrl, pkg.name, pkg.ecosystem === 'npm'
              ? {
                  integrity: pkg.registryArtifact?.integrity || null,
                  shasum: pkg.registryArtifact?.shasum || null,
                }
              : undefined);
          })
        );

        for (let j = 0; j < chunk.length; j++) {
          const pkg = chunk[j];
          const r = tarResults[j];
          if (r.status !== 'fulfilled') {
            warnings.push(`deep inspection: ${pkg.name}@${pkg.version}: ${r.reason?.message || 'inspection failed'}`);
            deepIncomplete = true;
            continue;
          }
          if (r.value?.error) {
            warnings.push(`deep inspection: ${pkg.name}@${pkg.version}: ${r.value.error}`);
            deepIncomplete = true;
            continue;
          }

          const tarResult = r.value;
          for (const warning of tarResult.warnings || []) {
            warnings.push(`deep inspection: ${pkg.name}@${pkg.version}: ${warning}`);
          }
          pkg.deepInspection = {
            requested: !!config.deep,
            coverage: tarResult.coverage || { mode: 'unknown', packageComplete: false },
            packageComplete: tarResult.coverage?.packageComplete === true,
          };
          if (pkg.deepInspection.packageComplete !== true) deepIncomplete = true;
          if (tarResult.findings.length > 0 && isAnalysisSignalEnabled(config, 'TARBALL_DANGEROUS_PATTERN')) {
            let addedRisk = 0;
            for (const finding of tarResult.findings) {
              pkg.signals.push({
                signal: 'TARBALL_DANGEROUS_PATTERN',
                severity: finding.severity,
                confidence: SIGNAL_CONFIDENCE.TARBALL_DANGEROUS_PATTERN,
                description: finding.description,
                evidence: { file: finding.file, pattern: finding.pattern },
                layer: 1,
              });
              addedRisk += SEVERITY[finding.severity]?.weight || 0;
            }
            pkg.riskScore += addedRisk;
          }

          if (tarResult.inspectedFiles.length > 0) {
            pkg.tarballInspected = tarResult.inspectedFiles;
          }
        }
      }

      tarSpinner?.stop(`Deep code inspection complete for ${tarballCandidates.length} packages`);
    }

    // 5c. Dynamic sandbox evidence (--sandbox, experimental, opt-in).
    // RUNS candidate code with contained writes and hidden user/project paths
    // on the accepted bwrap host, under a positive-only recorder shim.
    // and attaches captured behavior (SANDBOX_BEHAVIOR + sandboxEvidence) to
    // the record. Refuse-by-default: no isolation host / any failure pushes a
    // warning, never a signal, and marks the requested dynamic stage incomplete
    // while preserving deterministic findings. spawnSync
    // is blocking, so the pass is bounded to the top-N by risk score.
    if (config.sandbox) {
      const TOP_N = 5;
      const candidates = results
        .filter(r => r.ecosystem === 'npm' && r.riskScore >= 15 && r.signals.length > 0)
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, TOP_N);
      // Refuse-by-default pre-flight: resolve the effective isolation host
      // before downloading/copying anything. `undefined` = auto-detect on
      // this host; `null` (test-only injection) = forced refusal; object =
      // forced host. No host ⇒ every candidate would refuse at run time — so
      // don't pull ~50MB of candidate code just to refuse it.
      let hostRefusalReported = config.sandboxHost !== undefined
        ? !config.sandboxHost
        : !detectSandboxHost();
      if (results.some(r => r.ecosystem === 'pypi' && r.riskScore >= 15 && r.signals.length > 0)) {
        sandboxIncomplete = true;
        warnings.push('sandbox: PyPI dynamic extraction/execution is unsupported and was refused');
      }
      if (hostRefusalReported) {
        sandboxIncomplete = true;
        warnings.push('sandbox skipped — no bwrap host that contains writes and hides user/project host paths');
      } else if (candidates.length === 0) {
        sandboxIncomplete = true;
        warnings.push('sandbox skipped — no packages met the execution threshold (riskScore >= 15)');
      }

      for (const pkg of candidates) {
        if (hostRefusalReported) continue; // pre-flight refusal — nothing to run or download
        const label = `${pkg.name}@${pkg.version}`;
        const tmp = mkdtempSync(join(tmpdir(), 'vexes-sandbox-'));
        const sbSpinner = isJSON ? null : createSpinner(`Sandboxing ${label}...`);
        try {
          const tarUrl = pkg.registryArtifact?.tarball || null;
          if (!tarUrl) {
            sandboxIncomplete = true;
            warnings.push(`sandbox: no tarball URL for ${label} — skipped`);
            continue;
          }

          await downloadAndExtractToDisk(tarUrl, pkg.name, tmp, {
            integrity: pkg.registryArtifact?.integrity || null,
            shasum: pkg.registryArtifact?.shasum || null,
          });

          const entry = pickEntryScript(tmp);
          if (!entry) {
            sandboxIncomplete = true;
            warnings.push(`sandbox: no runnable entrypoint in ${label} — skipped`);
            continue;
          }

          const child = runHarnessed({
            workdir: tmp,
            entryScript: entry,
            allow: true,
            timeoutMs: 10000,
            host: config.sandboxHost,
          });

          if (child.status === 'refused') {
            sandboxIncomplete = true;
            // Host-wide refusal (no isolation primitive) is one report, not one
            // per candidate; an opt-in refusal is reported per candidate.
            if (/no isolation host/.test(child.reason || '')) {
              if (!hostRefusalReported) { hostRefusalReported = true; warnings.push(`sandbox skipped — ${child.reason}`); }
            } else {
              warnings.push(`sandbox: ${label} skipped — ${child.reason}`);
            }
            continue;
          }

          if (child.status === 'failed') {
            sandboxIncomplete = true;
            warnings.push(`sandbox: ${label} harness failed (${child.reason || 'dynamic evidence incomplete'})`);
            continue;
          }

          // Recorder hooks share a process and writable workdir with the
          // candidate. Positive observations are useful, but absence can be
          // bypassed or tampered with, so a requested sandbox pass never acts
          // as negative proof or makes the overall assessment complete.
          sandboxIncomplete = true;
          warnings.push(`sandbox: ${label} produced positive-only behavioral observations; empty recorder evidence is not trusted as proof of benign behavior`);

          const signal = isAnalysisSignalEnabled(config, 'SANDBOX_BEHAVIOR')
            ? buildSandboxSignal({ name: pkg.name, version: pkg.version, evidence: child.evidence })
            : null;
          if (signal) {
            pkg.signals.push(signal);
            pkg.sandboxEvidence = signal.evidence.dynamic;
            pkg.riskScore += SEVERITY[signal.severity].weight;
          } else if (config.verbose) {
            warnings.push(`sandbox: ${label} ran with no behavior recorded`);
          }
        } catch (err) {
          sandboxIncomplete = true;
          log.debug(`sandbox step failed for ${label}: ${err.message}`);
          warnings.push(`sandbox: ${label} skipped (${err.message})`);
        } finally {
          sbSpinner?.stop();
          rmSync(tmp, { recursive: true, force: true });
        }
      }
    }

    // 6. Re-derive risk levels: provenance and deep-tarball steps above
    // mutate riskScore after analyzePackage() computed riskLevel. Without
    // this pass, a package pushed over a threshold by --deep findings keeps
    // its old level and can be filtered out of the report and the exit code.
    for (const r of results) {
      if (r.riskLevel !== 'UNKNOWN') {
        r.riskLevel = scoreToLevel(r.riskScore);
      }
    }

    // Then sort by risk score descending
    results.sort((a, b) => b.riskScore - a.riskScore);

    // 7. Surface packages where any analysis step was incomplete
    const incompleteResults = results.filter(r => r.warnings?.length > 0);
    if (incompleteResults.length > 0) {
      warnings.push(`${incompleteResults.length} package(s) could not be fully analyzed`);
      for (const r of incompleteResults) {
        warnings.push(...r.warnings.map(w => `${r.name}: ${w}`));
      }
    }

    const complete = parseFailures === 0 && unresolvedManifestInputs === 0 && incompleteResults.length === 0 &&
      osvData.failures.length === 0 && !sandboxIncomplete && !deepIncomplete;

    // 8. Filter — default shows only packages with signals
    const minSeverity = config.severity?.toUpperCase() || 'MODERATE';
    const minOrder = SEVERITY[minSeverity]?.order ?? 2;
    const preIgnoreFlagged = results.filter(r => {
      if (r.riskLevel === 'NONE') return false;
      if (r.riskLevel === 'UNKNOWN') return verbose; // Show UNKNOWN in verbose mode
      const order = SEVERITY[r.riskLevel]?.order ?? 0;
      return verbose || order >= minOrder;
    });

    // 8b. Apply the `ignore` config — suppress by package name, pkg@version, or
    // any advisory ID carried on the package's KNOWN_COMPROMISED signal.
    const { kept: flaggedResults, suppressed } = partitionByIgnore(
      preIgnoreFlagged,
      config.ignore,
      r => ({ pkg: r.name, version: r.version, ids: collectAdvisoryIds(r) }),
    );

    // 8. Format output
    if (isJSON) {
      // Analyze carries its own rich result records (signals, riskScore,
      // per-signal evidence). They stay in `results` verbatim — the envelope's
      // `findings` array is reserved for OSV-style normalized records, so
      // agents that iterate findings uniformly never mis-parse analyze's shape.
      out(JSON.stringify(buildEnvelope({
        command: 'analyze',
        target: { dir: targetDir, lockfiles: [...dependencyFiles], ecosystems: [...config.ecosystems] },
        complete,
        warnings,
        summary: {
          total: uniqueDeps.length,
          flagged: flaggedResults.length,
          suppressed: suppressed.length,
          critical: flaggedResults.filter(r => r.riskLevel === 'CRITICAL').length,
          high: flaggedResults.filter(r => r.riskLevel === 'HIGH').length,
        },
        findings: [],
        extra: {
          version: VERSION,
          results: flaggedResults,
          stages: {
            deep: { requested: !!config.deep, complete: !config.deep || !deepIncomplete, packageComplete: !config.deep || !deepIncomplete },
            sandbox: { requested: !!config.sandbox, complete: !config.sandbox || !sandboxIncomplete },
            provenance: {
              requested: highRiskNpm.length > 0,
              complete: !provenanceIncomplete,
              cryptographicVerificationPerformed: false,
            },
          },
        },
      }), null, 2));
    } else {
      // Explain mode: detailed breakdown for a single package
      if (config.explain) {
        const target = results.find(r => r.name === config.explain);
        if (target) {
          printExplain(target);
        } else {
          out(`  ${C.yellow}Package "${config.explain}" not found in dependencies${C.reset}\n`);
        }
        cache.close();
        return complete ? EXIT.OK : EXIT.ERROR;
      }

      // Normal output
      if (flaggedResults.length === 0) {
        if (complete) {
          out(`\n  ${C.green}\u2713 No risk signals detected${C.reset}\n`);
        } else {
          out(`\n  ${C.yellow}! No risk signals detected, but analysis was incomplete${C.reset}\n`);
        }
      } else {
        // MISSING_PROVENANCE is true of nearly everything published before
        // Sigstore provenance existed (~2023). It still counts toward risk,
        // but displaying it per-package floods the first run \u2014 so collapse
        // it into a footer line unless verbose. JSON output is unchanged.
        const CONF_ORDER = { proven: 3, deterministic: 2, heuristic: 1, inferred: 0 };
        const bestConfidence = (r) => Math.max(...r.signals.map(s => CONF_ORDER[s.confidence] ?? 0), 0);
        const hasProvenanceOnly = (r) => r.signals.every(s => s.signal === 'MISSING_PROVENANCE');

        const displayResults = verbose ? flaggedResults : flaggedResults.filter(r => !hasProvenanceOnly(r));
        const provenanceOnlyCount = flaggedResults.length - displayResults.length;
        const topN = Number.isFinite(parseInt(flags.top, 10)) ? parseInt(flags.top, 10) : null;
        const shownResults = topN != null ? displayResults.slice(0, topN) : displayResults;

        out(header('Risk Assessment'));
        out(`  ${C.dim}${'Package'.padEnd(35)} Risk   Signals   ${C.reset}${C.dim}(* = hard evidence, ~ = heuristic only)${C.reset}`);
        out(`  ${C.dim}${'\u2500'.repeat(70)}${C.reset}`);

        for (const r of shownResults) {
          const rColor = r.riskLevel === 'CRITICAL' ? C.red :
                         r.riskLevel === 'HIGH' ? C.yellow :
                         r.riskLevel === 'MODERATE' ? C.cyan : C.dim;
          const bar = riskBar(r.riskScore);
          const displaySignals = verbose ? r.signals : r.signals.filter(s => s.signal !== 'MISSING_PROVENANCE');
          const sigNames = [...new Set(displaySignals.map(s => s.signal))].join(', ') || '\u2014';
          const nameVer = `${sanitize(r.name)} ${C.dim}${sanitize(r.version)}${C.reset}`;
          // Evidentiary marker: * when any signal rests on hard evidence
          // (OSV match, registry metadata fact); ~ when the row is heuristic-only.
          const confGlyph = bestConfidence(r) >= 2 ? `${C.cyan}*${C.reset}` : `${C.dim}~${C.reset}`;

          out(`  ${rColor}${nameVer.padEnd(45)}${C.reset} ${bar}  ${confGlyph} ${C.dim}${sanitize(sigNames)}${C.reset}`);

          // Show signal details if verbose
          if (verbose) {
            for (const s of r.signals) {
              const sColor = s.severity === 'CRITICAL' ? C.red :
                             s.severity === 'HIGH' ? C.yellow : C.dim;
              out(`    ${sColor}L${s.layer || '?'}${C.reset} ${sColor}${s.severity.padEnd(8)}${C.reset} ${sanitize(s.description)}`);
            }
            out('');
          }
        }

        const hidden = (topN != null ? displayResults.length - shownResults.length : 0);
        if (hidden > 0) {
          out(`  ${C.dim}\u2026 and ${hidden} more (raise --top or use -v to see everything)${C.reset}`);
        }
        if (provenanceOnlyCount > 0) {
          out(`  ${C.dim}${provenanceOnlyCount} package(s) flagged only for missing provenance attestation${C.reset}`);
          out(`  ${C.dim}(common for releases before ~2023 \u2014 still counted in risk; -v shows them)${C.reset}`);
        }
      }

      // Summary
      const line = '\u2500'.repeat(50);
      out(`\n  ${C.dim}${line}${C.reset}`);
      const critCount = flaggedResults.filter(r => r.riskLevel === 'CRITICAL').length;
      const highCount = flaggedResults.filter(r => r.riskLevel === 'HIGH').length;
      const modCount = flaggedResults.filter(r => r.riskLevel === 'MODERATE').length;
      const parts = [];
      if (critCount) parts.push(`${C.red}${critCount} critical${C.reset}`);
      if (highCount) parts.push(`${C.yellow}${highCount} high${C.reset}`);
      if (modCount) parts.push(`${C.cyan}${modCount} moderate${C.reset}`);

      if (flaggedResults.length > 0) {
        out(`  ${flaggedResults.length} package(s) with risk signals \u00b7 ${parts.join(' \u00b7 ')}`);
      } else if (!complete) {
        out(`  ${C.yellow}!${C.reset} ${uniqueDeps.length} packages analyzed — one or more checks were incomplete`);
      } else {
        out(`  ${C.green}\u2713${C.reset} ${uniqueDeps.length} packages analyzed — no concerning signals`);
      }
      if (suppressed.length > 0) {
        out(`  ${C.dim}${suppressed.length} suppressed by ignore config${C.reset}`);
      }
      out(`  ${C.dim}${line}${C.reset}\n`);

      if (warnings.length > 0) {
        out(header('WARNINGS'));
        for (const w of warnings) out(`  ${C.yellow}! ${w}${C.reset}`);
        out('');
      }
    }

    // Exit code
    const hasCritical = flaggedResults.some(r => r.riskLevel === 'CRITICAL');
    const hasHigh = flaggedResults.some(r => r.riskLevel === 'HIGH');

    if (!complete) return EXIT.ERROR;
    if (config.strict && flaggedResults.length > 0) return EXIT.VULNS_FOUND;
    if (hasCritical || hasHigh) return EXIT.VULNS_FOUND;
    return EXIT.OK;

  } finally {
    cache.close();
  }
}

/**
 * Analyze a single package through all layers.
 */
export async function analyzeSinglePackage(dep, osvData, config, cache) {
  const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;

  // Fresh OSV evidence for THIS run (queryBatch ran before we were called).
  // The signal cache below is only trustworthy when the fresh evidence matches
  // what the cached verdict was formed against — otherwise a cached "clean"
  // could mask an advisory published while the cache was still warm.
  const osvCovered = osvData?.checked?.has(key) === true;
  const osvResult = osvCovered ? (osvData.results.get(key) || []) : null;
  const osvFingerprint = osvCovered ? osvResult.map(v => v.id).sort().join(',') : 'uncovered';

  // Read the signal cache now, but do not return it until registry anchoring is
  // checked below. A cached verdict must never mask an exact version that is
  // absent from today's registry metadata.
  const cachedSignals = cache.getSignals(
    dep.ecosystem,
    dep.name,
    dep.version,
    config?.cache?.metadataTtlMs,
  );

  // Fetch registry metadata
  let metadata = null;
  if (dep.ecosystem === 'npm') {
    metadata = await fetchNpmMetadata(dep.name, dep.version);
  } else if (dep.ecosystem === 'pypi' || dep.ecosystem === 'PyPI') {
    metadata = await fetchPypiMetadata(dep.name, dep.version);
  }

  const metadataAnchorIncomplete = metadata !== null && (
    metadata.metadataComplete === false ||
    (dep.version && (
      metadata.requestedVersionFound === false ||
      metadata.anchoredToInstalled === false
    ))
  );
  const registryArtifact = dep.ecosystem === 'npm' ? registryArtifactFromMetadata(metadata) : null;
  const analysisFingerprint = metadata === null
    ? null
    : analysisEvidenceFingerprint(metadata, config);

  if (metadata !== null &&
      !metadataAnchorIncomplete &&
      cachedSignals &&
      cachedSignals.osvFingerprint === osvFingerprint &&
      cachedSignals.analysisFingerprint === analysisFingerprint) {
    const {
      osvFingerprint: _osvEvidence,
      analysisFingerprint: _analysisEvidence,
      ...output
    } = cachedSignals;
    return {
      ...output,
      declaredRepository: metadata?.repository || output.declaredRepository || null,
      registryArtifact,
    };
  }

  // Run all signal detectors
  const result = await analyzePackage(metadata, osvResult, {
    ecosystem: dep.ecosystem,
    config,
  });

  const output = {
    name: dep.name,
    version: dep.version,
    ecosystem: dep.ecosystem,
    isDirect: dep.isDirect,
    declaredRepository: metadata?.repository || null,
    registryArtifact,
    signals: result.signals,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    warnings: [...(result.warnings || [])],
  };

  if (!osvCovered) {
    output.warnings.push('OSV vulnerability lookup incomplete');
  }
  if (metadataAnchorIncomplete) {
    output.warnings.push(metadata.anchorError ||
      `registry metadata is not anchored to requested version ${dep.name}@${dep.version}`);
  }

  // Only cache complete results — never cache degraded analysis
  // A transient network failure must not poison the cache with false-clean for 24 hours.
  // The stored copy carries osvFingerprint so a later run can tell whether the
  // advisory landscape this verdict was formed on still matches today's.
  const isDegraded = !osvCovered || metadata === null || metadataAnchorIncomplete ||
    output.riskLevel === 'UNKNOWN' || (output.warnings?.length > 0);
  if (!isDegraded) {
    try {
      cache.setSignals(dep.ecosystem, dep.name, dep.version, {
        ...output,
        osvFingerprint,
        analysisFingerprint,
      });
    } catch (err) {
      log.debug(`cache write failed for signals ${key}: ${err.message}`);
    }
  }

  return output;
}

/**
 * Bind cached signal results to every input that can affect signal semantics.
 * Registry metadata can change without the package version changing (for
 * example, corrected publisher or install-script metadata), and local signal
 * policy can change between runs. Both must match before reusing a verdict.
 */
export function analysisEvidenceFingerprint(metadata, config = {}) {
  const stableMetadata = { ...metadata };
  if (Number.isFinite(stableMetadata.packageAgeMs)) {
    // Registry normalizers expose a relative age. Recover the stable creation
    // instant (rounded to registry timestamp precision) so two immediate
    // fetches can share a cache entry without freezing time-sensitive signals.
    stableMetadata.packageCreatedAtMs = Math.round((Date.now() - stableMetadata.packageAgeMs) / 1000) * 1000;
    delete stableMetadata.packageAgeMs;
  }
  const evidence = {
    analyzerVersion: VERSION,
    analysisClockMinute: Math.floor(Date.now() / 60_000),
    metadata: stableMetadata,
    signalPolicy: config?.analyze?.signals || {},
  };
  return createHash('sha256').update(canonicalJson(evidence)).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  ).join(',')}}`;
}

/**
 * Print detailed explanation for a single package.
 */
function printExplain(result) {
  out(`\n  ${C.bold}${sanitize(result.name)}${C.reset} ${C.dim}${sanitize(result.version)}${C.reset} ${C.dim}(${result.ecosystem})${C.reset}\n`);

  const rColor = result.riskLevel === 'CRITICAL' ? C.red :
                 result.riskLevel === 'HIGH' ? C.yellow :
                 result.riskLevel === 'MODERATE' ? C.cyan : C.green;
  out(`  Risk Level: ${rColor}${result.riskLevel}${C.reset} (score: ${result.riskScore})`);
  out(`  Direct dependency: ${result.isDirect ? 'yes' : 'no (transitive)'}`);

  if (result.provenance) {
    const source = sanitize(result.provenance.claimedSourceRepo || 'unknown claimed source');
    const decoded = result.provenance.attestationDecoded ? 'payload decoded' : 'payload not decoded';
    out(`  Attestation: ${C.cyan}present; ${decoded}${C.reset} (${source}; cryptographic verification not performed)`);
  }

  if (result.signals.length === 0) {
    out(`\n  ${C.green}No risk signals detected.${C.reset}\n`);
    return;
  }

  out(`\n  ${C.bold}Signals (${result.signals.length}):${C.reset}\n`);

  const layerNames = { 1: 'AST Analysis', 2: 'Dep Graph', 3: 'Behavioral', 4: 'Metadata' };

  for (const s of result.signals) {
    const sColor = s.severity === 'CRITICAL' ? C.red :
                   s.severity === 'HIGH' ? C.yellow :
                   s.severity === 'MODERATE' ? C.cyan : C.dim;
    out(`  ${sColor}\u25cf ${s.severity}${C.reset} ${C.bold}${s.signal}${C.reset} ${C.dim}(Layer ${s.layer}: ${layerNames[s.layer] || '?'})${C.reset}`);
    out(`    ${sanitize(s.description)}`);
    if (s.evidence && Object.keys(s.evidence).length > 0) {
      for (const [k, v] of Object.entries(s.evidence)) {
        if (v === null || v === undefined) continue;
        const display = typeof v === 'object' ? JSON.stringify(v) : String(v);
        out(`    ${C.dim}${k}: ${sanitize(display).slice(0, 120)}${C.reset}`);
      }
    }
    out('');
  }
}

/**
 * Collect advisory IDs attached to an analyze result so the `ignore` config can
 * suppress by ID. IDs live on the KNOWN_COMPROMISED signal's evidence.ids.
 */
function collectAdvisoryIds(result) {
  const ids = [];
  for (const s of result.signals || []) {
    if (Array.isArray(s.evidence?.ids)) ids.push(...s.evidence.ids);
  }
  return ids;
}

function riskBar(score) {
  const maxBars = 8;
  const filled = Math.min(maxBars, Math.ceil(score / 5));
  const empty = maxBars - filled;
  const color = filled >= 6 ? C.red : filled >= 3 ? C.yellow : C.cyan;
  return `${color}${'█'.repeat(filled)}${C.dim}${'░'.repeat(empty)}${C.reset}`;
}

/** Identify manifest declarations that could not be anchored to exact versions. */
function hasUnresolvedManifestEntries(filePath, ecosystem, format, parsed) {
  try {
    const parsedCount = Array.isArray(parsed) ? parsed.length : parsed;
    if (ecosystem === 'npm') {
      const pkg = JSON.parse(readFileSync(filePath, 'utf8'));
      let declared = 0;
      for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const entries = pkg[section];
        if (entries && typeof entries === 'object') declared += Object.keys(entries).length;
      }
      return declared > parsedCount;
    }

    const content = readFileSync(filePath, 'utf8');
    if (Array.isArray(parsed) && parsed.unresolvedEntries > 0) return true;
    if (format === 'requirements.txt') {
      return content.split('\n').some(raw => {
        const line = raw.split('#')[0].trim();
        if (!line || (/^--?/.test(line) && !/^(?:-e|--editable)\b/.test(line))) return false;
        const stripped = line.replace(/\[.*?\]/, '');
        const match = stripped.match(/^([a-zA-Z0-9._-]+)\s*(?:([=!<>~]+)\s*(.+?))?(?:\s*;.*)?$/);
        if (!match) return true;
        const op = match[2] || '';
        const value = match[3]?.trim()?.split(',')[0]?.trim() || '';
        return !((op === '==' || op === '===') && /^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(value) && !value.includes('*'));
      });
    }

    if (format === 'pyproject.toml' && parsedCount === 0) {
      return /^\s*dependencies\s*=\s*\[\s*["']/m.test(content) ||
        /^\s*\[project\.optional-dependencies\]\s*$/m.test(content) ||
        /^\s*\[tool\.poetry\.(?:dev-)?dependencies\]\s*$/m.test(content);
    }
  } catch {
    // The parser reports malformed/unreadable files separately.
  }
  return false;
}

function registryArtifactFromMetadata(metadata) {
  if (!metadata) return null;
  return {
    tarball: metadata.artifact?.tarball || metadata.tarball || null,
    integrity: metadata.artifact?.integrity || metadata.integrity || null,
    shasum: metadata.artifact?.shasum || metadata.shasum || null,
  };
}
