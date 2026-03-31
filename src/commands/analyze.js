import { resolve, basename } from 'node:path';
import { statSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
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
import { checkProvenance } from '../analysis/provenance.js';
import { analyzePackage } from '../analysis/signals.js';
import { inspectTarball, getTarballUrl, getPypiTarballUrl } from '../analysis/tarball-inspector.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';

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
    else out(JSON.stringify({ version: VERSION, command: 'analyze', results: [], warnings }, null, 2));
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
              description: 'No Sigstore provenance attestation — package was not verifiably built from source',
              evidence: { standalone: !hasOtherSignals },
              layer: 4,
            });
            pkg.riskScore += SEVERITY[severity].weight;
          } else if (prov?.hasProvenance === true) {
            pkg.provenance = { sourceRepo: prov.sourceRepo, buildType: prov.buildType };
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

    // 6. Sort by risk score descending
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
    const flaggedResults = results.filter(r => {
      if (r.riskLevel === 'NONE') return false;
      if (r.riskLevel === 'UNKNOWN') return verbose; // Show UNKNOWN in verbose mode
      const order = SEVERITY[r.riskLevel]?.order ?? 0;
      return verbose || order >= minOrder;
    });

    // 8. Format output
    if (isJSON) {
      out(JSON.stringify({
        version: VERSION,
        timestamp: new Date().toISOString(),
        command: 'analyze',
        complete,
        summary: {
          total: uniqueDeps.length,
          flagged: flaggedResults.length,
          critical: flaggedResults.filter(r => r.riskLevel === 'CRITICAL').length,
          high: flaggedResults.filter(r => r.riskLevel === 'HIGH').length,
        },
        warnings,
        results: flaggedResults,
      }, null, 2));
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
        out(header('Risk Assessment'));
        out(`  ${C.dim}${'Package'.padEnd(35)} Risk   Signals${C.reset}`);
        out(`  ${C.dim}${'\u2500'.repeat(70)}${C.reset}`);

        for (const r of flaggedResults) {
          const rColor = r.riskLevel === 'CRITICAL' ? C.red :
                         r.riskLevel === 'HIGH' ? C.yellow :
                         r.riskLevel === 'MODERATE' ? C.cyan : C.dim;
          const bar = riskBar(r.riskScore);
          const sigNames = [...new Set(r.signals.map(s => s.signal))].join(', ');
          const nameVer = `${sanitize(r.name)} ${C.dim}${sanitize(r.version)}${C.reset}`;

          out(`  ${rColor}${nameVer.padEnd(45)}${C.reset} ${bar}  ${C.dim}${sanitize(sigNames)}${C.reset}`);

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

  // Check signal cache
  const cachedSignals = cache.getSignals(dep.ecosystem, dep.name, dep.version);
  if (cachedSignals) return cachedSignals;

  // Fetch registry metadata
  let metadata = null;
  if (dep.ecosystem === 'npm') {
    metadata = await fetchNpmMetadata(dep.name);
  } else if (dep.ecosystem === 'pypi' || dep.ecosystem === 'PyPI') {
    metadata = await fetchPypiMetadata(dep.name, dep.version);
  }

  // Get OSV results for this package
  const osvCovered = osvData?.checked?.has(key) === true;
  const osvResult = osvCovered ? (osvData.results.get(key) || []) : null;

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
    signals: result.signals,
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    warnings: [...(result.warnings || [])],
  };

  if (!osvCovered) {
    output.warnings.push('OSV vulnerability lookup incomplete');
  }

  // Only cache complete results — never cache degraded analysis
  // A transient network failure must not poison the cache with false-clean for 24 hours
  const isDegraded = !osvCovered || metadata === null || output.riskLevel === 'UNKNOWN' || (output.warnings?.length > 0);
  if (!isDegraded) {
    try {
      cache.setSignals(dep.ecosystem, dep.name, dep.version, output);
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

function riskBar(score) {
  const maxBars = 8;
  const filled = Math.min(maxBars, Math.ceil(score / 5));
  const empty = maxBars - filled;
  const color = filled >= 6 ? C.red : filled >= 3 ? C.yellow : C.cyan;
  return `${color}${'█'.repeat(filled)}${C.dim}${'░'.repeat(empty)}${C.reset}`;
}
