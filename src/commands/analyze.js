import { resolve, basename, join } from 'node:path';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope } from '../cli/schema.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, SEVERITY, ANALYZE_CONCURRENCY } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { discover as discoverPnpm, parseLockfile as parsePnpmLock } from '../parsers/pnpm.js';
import { discover as discoverYarn, parseLockfile as parseYarnLock } from '../parsers/yarn.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { queryBatch } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { fetchPypiMetadata } from '../advisories/pypi-registry.js';
import { checkProvenance, detectProvenanceSpoof } from '../analysis/provenance.js';
import { analyzePackage, scoreToLevel, SIGNAL_CONFIDENCE } from '../analysis/signals.js';
import { inspectTarball, getTarballUrl, getPypiTarballUrl, downloadAndExtractToDisk } from '../analysis/tarball-inspector.js';
import { detectSandboxHost } from '../analysis/sandbox/index.js';
import { runHarnessed, pickEntryScript, buildSandboxSignal } from '../analysis/sandbox/harness.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';
import { partitionByIgnore } from '../core/ignore.js';

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

  // 1. Discover and parse lockfiles
  const allDeps = [];
  const ecosystemsFound = new Set();

  for (const ecoName of config.ecosystems) {
    if (ecoName === 'npm') {
      // Discover from all npm-ecosystem lockfiles: npm, pnpm, yarn
      for (const [discFn, parseFn] of [[discoverNpm, parseNpmLock], [discoverPnpm, parsePnpmLock], [discoverYarn, parseYarnLock]]) {
        const { lockfiles } = discFn(targetDir);
        for (const lf of lockfiles) {
          try {
            const deps = parseFn(lf);
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
    }
    if (ecoName === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(targetDir);
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      for (const file of files) {
        try {
          const deps = parsePypiFile(file.path, file.format);
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
    if (!isJSON) out(`  ${C.dim}No dependencies found to analyze in ${targetDir}${C.reset}\n`);
    else out(JSON.stringify(buildEnvelope({
      command: 'analyze',
      target: { dir: targetDir, lockfiles: [], ecosystems: [...config.ecosystems] },
      complete: true,
      warnings,
      findings: [],
      extra: { version: VERSION, results: [] },
    }), null, 2));
    return EXIT.OK;
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

        for (const r of provResults) {
          if (r.status !== 'fulfilled') continue;
          const { pkg, prov } = r.value;
          if (prov?.hasProvenance === false) {
            // Only flag at MODERATE if the package already has other signals
            // Standalone MISSING_PROVENANCE is LOW — <5% of npm has provenance
            const hasOtherSignals = pkg.signals.length > 0;
            const severity = hasOtherSignals ? 'MODERATE' : 'LOW';
            pkg.signals.push({
              signal: 'MISSING_PROVENANCE',
              severity,
              confidence: SIGNAL_CONFIDENCE.MISSING_PROVENANCE,
              description: 'No Sigstore provenance attestation — package was not verifiably built from source',
              evidence: { standalone: !hasOtherSignals },
              layer: 4,
            });
            pkg.riskScore += SEVERITY[severity].weight;
          } else if (prov?.hasProvenance === true) {
            pkg.provenance = { sourceRepo: prov.sourceRepo, buildType: prov.buildType };

            // 5a. Provenance ≠ trust: xref the attestation's certified artifact
            // names (and claimed build repo) against the package's actual
            // identity + declared repo. Replay and repo-mismatch → signal.
            const spoof = detectProvenanceSpoof({
              packageName: pkg.name,
              subjects: prov.subjects,
              sourceRepo: prov.sourceRepo,
              declaredRepo: pkg.declaredRepository,
            });
            if (spoof) {
              pkg.signals.push(spoof);
              pkg.riskScore += SEVERITY[spoof.severity].weight;
            }
          }
        }
      }

      provSpinner?.stop(`Provenance checked for ${highRiskNpm.length} packages`);
    }

    // 5b. Deep tarball inspection
    // --deep: inspect ALL packages. Default: only high-risk (score >= 15)
    const tarballCandidates = config.deep
      ? results.filter(r => r.ecosystem === 'npm' || r.ecosystem === 'pypi')
      : results.filter(r => r.ecosystem === 'npm' && r.riskScore >= 15 && r.signals.length > 0);

    if (tarballCandidates.length > 0) {
      const label = config.deep ? 'all' : 'high-risk';
      const tarSpinner = isJSON ? null : createSpinner(`Deep code inspection for ${tarballCandidates.length} ${label} packages...`);

      for (let i = 0; i < tarballCandidates.length; i += ANALYZE_CONCURRENCY) {
        const chunk = tarballCandidates.slice(i, i + ANALYZE_CONCURRENCY);
        const tarResults = await Promise.allSettled(
          chunk.map(async (pkg) => {
            let tarUrl;
            if (pkg.ecosystem === 'pypi') {
              tarUrl = await getPypiTarballUrl(pkg.name, pkg.version);
            } else {
              tarUrl = getTarballUrl({ name: pkg.name }, pkg.version);
            }
            if (!tarUrl) return null;
            return inspectTarball(tarUrl, pkg.name);
          })
        );

        for (let j = 0; j < chunk.length; j++) {
          const pkg = chunk[j];
          const r = tarResults[j];
          if (r.status !== 'fulfilled' || !r.value) continue;

          const tarResult = r.value;
          if (tarResult.findings.length > 0) {
            for (const finding of tarResult.findings) {
              pkg.signals.push({
                signal: 'TARBALL_DANGEROUS_PATTERN',
                severity: finding.severity,
                confidence: SIGNAL_CONFIDENCE.TARBALL_DANGEROUS_PATTERN,
                description: finding.description,
                evidence: { file: finding.file, pattern: finding.pattern },
                layer: 1,
              });
            }
            // Recalculate risk score with new signals
            pkg.riskScore += tarResult.findings.length * SEVERITY.HIGH.weight;
          }

          if (tarResult.inspectedFiles.length > 0) {
            pkg.tarballInspected = tarResult.inspectedFiles;
          }
        }
      }

      tarSpinner?.stop(`Deep code inspection complete for ${tarballCandidates.length} packages`);
    }

    // 5c. Dynamic sandbox evidence (--sandbox, experimental, opt-in).
    // RUNS candidate code in the OS isolation primitive under a recorder shim
    // and attaches captured behavior (SANDBOX_BEHAVIOR + sandboxEvidence) to
    // the record. Refuse-by-default: no isolation host / any failure pushes a
    // warning, never a signal, never fails the deterministic pass. spawnSync
    // is blocking, so the pass is bounded to the top-N by risk score.
    if (config.sandbox) {
      const TOP_N = 5;
      const candidates = results
        .filter(r => (r.ecosystem === 'npm' || r.ecosystem === 'pypi') && r.riskScore >= 15 && r.signals.length > 0)
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
      if (hostRefusalReported) {
        warnings.push('sandbox skipped — no isolation host with filesystem write isolation (need sandbox-exec on macOS, or bwrap on Linux)');
      }

      for (const pkg of candidates) {
        if (hostRefusalReported) continue; // pre-flight refusal — nothing to run or download
        const label = `${pkg.name}@${pkg.version}`;
        const tmp = mkdtempSync(join(tmpdir(), 'vexes-sandbox-'));
        const sbSpinner = isJSON ? null : createSpinner(`Sandboxing ${label}...`);
        try {
          let tarUrl;
          if (pkg.ecosystem === 'pypi') tarUrl = await getPypiTarballUrl(pkg.name, pkg.version);
          else tarUrl = getTarballUrl({ name: pkg.name }, pkg.version);
          if (!tarUrl) { warnings.push(`sandbox: no tarball URL for ${label} — skipped`); continue; }

          await downloadAndExtractToDisk(tarUrl, pkg.name, tmp);

          if (pkg.ecosystem === 'pypi') {
            // v1: extraction-only. The recorder shim is Node; we never claim
            // ran behavior we didn't execute.
            warnings.push(`sandbox: ${label} (pypi) extracted but not executed — sandbox run is npm-only for now`);
            continue;
          }

          const entry = pickEntryScript(tmp);
          if (!entry) { warnings.push(`sandbox: no runnable entrypoint in ${label} — skipped`); continue; }

          const child = runHarnessed({
            workdir: tmp,
            entryScript: entry,
            allow: true,
            timeoutMs: 10000,
            host: config.sandboxHost,
          });

          if (child.status === 'refused') {
            // Host-wide refusal (no isolation primitive) is one report, not one
            // per candidate; an opt-in refusal is reported per candidate.
            if (/no isolation host/.test(child.reason || '')) {
              if (!hostRefusalReported) { hostRefusalReported = true; warnings.push(`sandbox skipped — ${child.reason}`); }
            } else {
              warnings.push(`sandbox: ${label} skipped — ${child.reason}`);
            }
            continue;
          }

          const signal = buildSandboxSignal({ name: pkg.name, version: pkg.version, evidence: child.evidence });
          if (signal) {
            pkg.signals.push(signal);
            pkg.sandboxEvidence = signal.evidence.dynamic;
            pkg.riskScore += SEVERITY[signal.severity].weight;
          } else if (child.status === 'failed' && child.reason) {
            // crash ≠ behavior; the sandbox still isolated it. Only surfaced
            // verbosely so the deterministic pass stays quiet.
            if (config.verbose) warnings.push(`sandbox: ${label} harness failed (${child.reason})`);
          } else if (config.verbose) {
            warnings.push(`sandbox: ${label} ran with no behavior recorded`);
          }
        } catch (err) {
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

    const complete = parseFailures === 0 && incompleteResults.length === 0 && osvData.failures.length === 0;

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
        target: { dir: targetDir, lockfiles: [], ecosystems: [...config.ecosystems] },
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
        extra: { version: VERSION, results: flaggedResults },
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

  // Check signal cache — a hit is valid ONLY if its OSV fingerprint matches
  // the fresh evidence ('uncovered' never matches a cached fingerprint, so a
  // degraded OSV run always re-analyzes instead of trusting stale signals).
  const cachedSignals = cache.getSignals(dep.ecosystem, dep.name, dep.version);
  if (cachedSignals && cachedSignals.osvFingerprint === osvFingerprint) {
    const { osvFingerprint: _evidence, ...output } = cachedSignals;
    return output;
  }

  // Fetch registry metadata
  let metadata = null;
  if (dep.ecosystem === 'npm') {
    metadata = await fetchNpmMetadata(dep.name, dep.version);
  } else if (dep.ecosystem === 'pypi' || dep.ecosystem === 'PyPI') {
    metadata = await fetchPypiMetadata(dep.name, dep.version);
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
    signals: result.signals,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    warnings: [...(result.warnings || [])],
  };

  if (!osvCovered) {
    output.warnings.push('OSV vulnerability lookup incomplete');
  }

  // Only cache complete results — never cache degraded analysis
  // A transient network failure must not poison the cache with false-clean for 24 hours.
  // The stored copy carries osvFingerprint so a later run can tell whether the
  // advisory landscape this verdict was formed on still matches today's.
  const isDegraded = !osvCovered || metadata === null || output.riskLevel === 'UNKNOWN' || (output.warnings?.length > 0);
  if (!isDegraded) {
    try {
      cache.setSignals(dep.ecosystem, dep.name, dep.version, { ...output, osvFingerprint });
    } catch (err) {
      log.debug(`cache write failed for signals ${key}: ${err.message}`);
    }
  }

  return output;
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
    out(`  Provenance: ${C.green}\u2713 verified${C.reset} (${sanitize(result.provenance.sourceRepo || 'unknown source')})`);
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
