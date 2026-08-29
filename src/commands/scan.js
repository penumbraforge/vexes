import { resolve, basename } from 'node:path';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { toSarif } from '../cli/sarif.js';
import { buildEnvelope, normalizeFinding, REACHABILITY } from '../cli/schema.js';
import { C, createSpinner, header, formatVuln, summary, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, SEVERITY, ECOSYSTEMS } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock, parseManifest as parseNpmManifest } from '../parsers/npm.js';
import { discover as discoverPnpm, parseLockfile as parsePnpmLock } from '../parsers/pnpm.js';
import { discover as discoverYarn, parseLockfile as parseYarnLock } from '../parsers/yarn.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { discover as discoverCargo, parseLockfile as parseCargoLock } from '../parsers/cargo.js';
import { GENERIC_ECOSYSTEM_PARSERS, parseGenericFile, selectGenericFiles } from '../parsers/generic.js';
import { queryBatch, filterBySeverity, isQueryComplete } from '../advisories/osv.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';
import { compareSemver } from '../core/semver.js';
import { buildUpgradeCommand } from '../core/upgrade-command.js';
import { partitionByIgnore } from '../core/ignore.js';
import { buildAppGraph, importEvidenceOf, reachabilityOf } from '../analysis/app-graph.js';
import { triageFindings } from '../analysis/exploitability.js';

/**
 * `vexes scan` — Enumerate dependencies, query OSV, report vulnerabilities.
 *
 * Critical invariant: NEVER report "0 vulnerabilities" when queries failed.
 * A security scanner that silently reports clean on failure is worse than useless.
 */
export async function runScan(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const isSARIF = config.output?.format === 'sarif';
  // Any structured format must keep stdout clean of progress/header chatter.
  const quietStdout = isJSON || isSARIF;

  // Track warning + discovered-file state for the shared envelope. Direct-dep
  // keys are filled once the deduped set exists (npm parsers mark isDirect).
  const warnings = [];
  const seenFiles = new Set();
  let directKeys = new Set();
  let appGraph = null; // Tier A reachability — set post-dedup, used by emitStructured

  // Emit a scan-result object in whichever structured format is active. SARIF
  // may target a file (--sarif <file>); otherwise everything goes to stdout via
  // out(), the flush-safe write path. JSON flows through the shared envelope —
  // the existing flat fields are preserved verbatim (backward compat) while
  // schemaVersion/generator/target/result/findings add the agent contract.
  const emitStructured = (scanResult) => {
    if (isSARIF) {
      const doc = JSON.stringify(toSarif(scanResult), null, 2);
      if (config.output?.sarifFile) {
        writeFileSync(config.output.sarifFile, doc + '\n');
        // Confirmation to stderr so stdout/the SARIF file stay uncontaminated.
        log.info(`SARIF written to ${config.output.sarifFile}`);
      } else {
        out(doc);
      }
      return;
    }
    const fixable = buildFixCommands(scanResult.vulnerabilities || []);
    const findings = (scanResult.vulnerabilities || []).map((v) => normalizeFinding(v, {
      direct: directKeys.has(`${v.ecosystem}:${v.package}@${v.version}`),
      fixCommand: fixCommandFor(v, fixable),
      reachability: reachabilityOf(appGraph, v.ecosystem, v.package),
      importEvidence: importEvidenceOf(appGraph, v.ecosystem, v.package),
    }));
    out(JSON.stringify(buildEnvelope({
      command: 'scan',
      target: { dir: targetDir, lockfiles: [...seenFiles], ecosystems: [...ecosystemsFound] },
      complete: scanResult.complete,
      warnings: scanResult.warnings,
      summary: {
        ...scanResult.summary,
        directImportEvidence: appGraph?.importEvidenceCategories || { foundStatic: 0, foundDynamic: 0, notFound: 0, unknown: 0 },
        reachable: appGraph?.categories?.reachable ?? 0, // legacy compatibility
        lazy: appGraph?.categories?.lazy ?? 0,           // legacy compatibility
        dead: appGraph?.categories?.dead ?? 0,           // legacy compatibility; means import not found
        unreachable: 0, // no runtime-unreachable conclusion is made
      },
      findings,
      extra: { version: VERSION, vulnerabilities: scanResult.vulnerabilities },
    }), null, 2));
  };

  // Validate target path exists and is a directory
  try {
    const stat = statSync(targetDir);
    if (!stat.isDirectory()) {
      log.error(`not a directory: ${targetDir}`);
      return EXIT.ERROR;
    }
  } catch {
    log.error(`path does not exist: ${targetDir}`);
    return EXIT.ERROR;
  }

  if (!quietStdout) {
    out(`\n  ${C.bold}vexes${C.reset} v${VERSION} ${C.dim}\u2500\u2500 scanning dependencies${C.reset}\n`);
  }

  // 1. Discover dependency files
  const allDeps = [];
  const ecosystemsFound = new Set();
  let dependencyFileCount = 0;
  let parseFailures = 0;
  let unresolvedManifestInputs = 0;

  for (const ecoName of config.ecosystems) {
    if (ecoName === 'npm') {
      const { lockfiles, manifests } = discoverNpm(targetDir);

      for (const lf of lockfiles) {
        try {
          const deps = parseNpmLock(lf);
          if (deps.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(lf)} contains ${deps.unresolvedEntries} local, linked, remote, or unanchored npm entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
          seenFiles.add(basename(lf));
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }

      // Also check for pnpm and yarn lockfiles (same npm ecosystem)
      const { lockfiles: pnpmLocks } = discoverPnpm(targetDir);
      for (const lf of pnpmLocks) {
        try {
          const deps = parsePnpmLock(lf);
          if (deps.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(lf)} contains ${deps.unresolvedEntries} non-registry or unanchored npm entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
          seenFiles.add(basename(lf));
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
      const { lockfiles: yarnLocks } = discoverYarn(targetDir);
      for (const lf of yarnLocks) {
        try {
          const deps = parseYarnLock(lf);
          if (deps.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(lf)} contains ${deps.unresolvedEntries} non-registry or unanchored npm entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
          seenFiles.add(basename(lf));
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }

      // Fallback to package.json if no lockfile
      if (lockfiles.length === 0 && pnpmLocks.length === 0 && yarnLocks.length === 0) {
        if (manifests.length > 0) {
          unresolvedManifestInputs++;
          warnings.push('no npm lockfile found — package.json exact pins can be checked, but resolved/transitive coverage is incomplete');
        }
        for (const mf of manifests) {
          try {
            const deps = parseNpmManifest(mf);
            allDeps.push(...deps);
            ecosystemsFound.add('npm');
            seenFiles.add(basename(mf));
            dependencyFileCount++;
            if (!quietStdout) out(`  ${C.yellow}! no npm lockfile found — scanning exact package.json pins only${C.reset}`);
            if (hasUnresolvedManifestEntries(mf, 'npm', 'package.json', deps.length)) {
              unresolvedManifestInputs++;
              warnings.push(`${basename(mf)} contains dependencies without exact registry versions — add a lockfile or exact pins; those entries were not scanned`);
            }
          } catch (err) {
            const msg = `failed to parse ${basename(mf)}: ${err.message}`;
            log.error(msg);
            warnings.push(msg);
            parseFailures++;
          }
        }
      }
    }
    if (ecoName === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(targetDir);
      // Prefer lockfiles over manifests
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      if (lockfiles.length === 0 && manifests.length > 0) {
        unresolvedManifestInputs++;
        warnings.push('no PyPI lockfile found — exact manifest pins can be checked, but resolved/transitive coverage is incomplete');
      }
      for (const file of files) {
        try {
          const deps = parsePypiFile(file.path, file.format);
          allDeps.push(...deps);
          ecosystemsFound.add('pypi');
          seenFiles.add(basename(file.path));
          dependencyFileCount++;
          if (hasUnresolvedManifestEntries(file.path, 'pypi', file.format, deps)) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(file.path)} contains dependencies without exact public-PyPI identities — those entries were not scanned`);
            for (const failure of deps.includeFailures || []) warnings.push(`${basename(file.path)}: ${failure}`);
          }
        } catch (err) {
          const msg = `failed to parse ${basename(file.path)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
    }

    if (ecoName === 'cargo') {
      const { lockfiles } = discoverCargo(targetDir);
      for (const lf of lockfiles) {
        try {
          const deps = parseCargoLock(lf);
          if (deps.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(lf)} contains ${deps.unresolvedEntries} non-crates.io or unanchored entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          allDeps.push(...deps);
          ecosystemsFound.add('cargo');
          seenFiles.add(basename(lf));
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
    }

    if (GENERIC_ECOSYSTEM_PARSERS[ecoName]) {
      const { files, usingManifestFallback } = selectGenericFiles(targetDir, ecoName);
      if (usingManifestFallback) {
        const manifestList = files.map(file => basename(file.path)).join(', ');
        const msg = `no lockfile found — scanning exact pins from ${manifestList}; manifest fallback is not a resolved dependency graph, so coverage is incomplete`;
        warnings.push(msg);
        unresolvedManifestInputs++;
        if (!quietStdout) out(`  ${C.yellow}! ${msg}${C.reset}`);
      }

      for (const file of files) {
        try {
          const deps = parseGenericFile(ecoName, file);
          if (deps.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(file.path)} contains ${deps.unresolvedEntries} replaced or otherwise unanchored module entr${deps.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          allDeps.push(...deps);
          ecosystemsFound.add(ecoName);
          seenFiles.add(basename(file.path));
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(file.path)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
    }

  }

  // Distinguish "no dependency files found" from "files found but parsing failed"
  if (allDeps.length === 0 && (parseFailures > 0 || unresolvedManifestInputs > 0)) {
    if (quietStdout) {
      emitStructured({
        version: VERSION, timestamp: new Date().toISOString(), command: 'scan', complete: false,
        summary: { total: 0, vulnerable: 0 },
        warnings, vulnerabilities: [],
      });
    } else {
      out(`\n  ${C.red}! Dependency inputs did not provide exact resolved versions — cannot determine vulnerability status${C.reset}\n`);
      for (const warning of warnings) out(`  ${C.yellow}! ${warning}${C.reset}`);
    }
    return EXIT.ERROR;
  }

  if (allDeps.length === 0) {
    if (quietStdout) {
      emitStructured({
        version: VERSION, timestamp: new Date().toISOString(), command: 'scan', complete: true,
        summary: { total: 0, vulnerable: 0 },
        warnings: [], vulnerabilities: [],
      });
    } else {
      out(`  ${C.dim}No dependencies found in ${targetDir}${C.reset}\n`);
    }
    return EXIT.OK;
  }

  // 2. Deduplicate
  const dedupMap = new Map();
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const uniqueDeps = [...dedupMap.values()];

  // Which of the scanned packages are direct (top-level) dependencies?
  // Parsers that know (npm lockfiles) flag isDirect; the rest default false —
  // "false" is the honest answer when we don't have a manifest to judge by.
  directKeys = new Set(
    uniqueDeps.filter(d => d.isDirect).map(d => `${d.ecosystem}:${d.name}@${d.version}`),
  );

  // Tier A direct-import evidence parses only the project's OWN source, not
  // node_modules. It is context attached to findings, never a suppression rule.
  appGraph = buildAppGraph(targetDir, uniqueDeps);
  if (!quietStdout) {
    const c = appGraph.importEvidenceCategories;
    out(`  ${C.dim}direct-import evidence: ${c.foundStatic} static · ${c.foundDynamic} dynamic-only · ${c.notFound} not found · ${c.unknown} unknown${C.reset}`);
  }

  if (!quietStdout) {
    out(`  ${C.dim}Found ${uniqueDeps.length} unique packages across ${dependencyFileCount} dependency file(s)${C.reset}`);
  }

  // 3. Open cache (graceful degradation if cache fails)
  let cache;
  try {
    cache = new AdvisoryCache(config.cache?.dir);
  } catch (err) {
    log.warn(`cache unavailable (${err.message}) — proceeding without cache`);
    warnings.push(`cache unavailable: ${err.message}`);
    cache = new NoOpCache();
  }

  try {
    // 4. Check cache, partition into cached vs needs-fetch
    const needsFetch = [];
    const cachedVulns = new Map();
    let cacheHits = 0;

    const ttl = config.useCache ? Infinity : (config.cache?.advisoryTtlMs);

    for (const dep of uniqueDeps) {
      const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
      const cached = config.useCache
        ? cache.getAdvisoriesAny(dep.ecosystem, dep.name, dep.version)
        : cache.getAdvisories(dep.ecosystem, dep.name, dep.version, ttl);

      if (cached !== null) {
        if (cached.length > 0) cachedVulns.set(key, cached);
        cacheHits++;
      } else {
        const eco = ECOSYSTEMS[dep.ecosystem];
        if (eco?.osvId) needsFetch.push(dep);
      }
    }

    log.debug(`cache: ${cacheHits} hits, ${needsFetch.length} to fetch`);

    // 5. Batch query OSV for uncached packages
    let fetchedVulns = new Map();
    let queryFailures = [];
    let droppedVulns = [];
    let queryComplete = true;
    const startTime = Date.now();

    if (needsFetch.length > 0) {
      const spinner = quietStdout ? null : createSpinner(`Querying OSV.dev for ${needsFetch.length} packages...`);

      const osvResult = await queryBatch(needsFetch);
      fetchedVulns = osvResult.results;
      queryFailures = osvResult.failures;
      droppedVulns = osvResult.droppedVulns;
      queryComplete = isQueryComplete(osvResult, needsFetch.length);

      // Cache only packages that were actually checked.
      for (const dep of needsFetch) {
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        if (!osvResult.checked?.has(key)) continue;
        const vulns = fetchedVulns.get(key) || [];
        try {
          cache.setAdvisories(dep.ecosystem, dep.name, dep.version, vulns);
        } catch (err) {
          log.debug(`cache write failed for ${key}: ${err.message}`);
        }
      }

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

      if (queryFailures.length > 0) {
        spinner?.stop(`${osvResult.queriedCount} packages checked, ${osvResult.failedCount} FAILED in ${elapsed}s`);
        warnings.push(...queryFailures);
      } else {
        spinner?.stop(`${uniqueDeps.length} packages checked in ${elapsed}s (${cacheHits} cached)`);
      }

      if (droppedVulns.length > 0) {
        warnings.push(`${droppedVulns.length} vulnerability detail(s) could not be fetched — reported with reduced detail`);
      }
    } else if (!quietStdout) {
      out(`  ${C.green}\u2713${C.reset} ${uniqueDeps.length} packages checked (all cached)`);
    }

    // 6. Merge cached + fresh results
    const allVulns = [];
    for (const [, vulns] of cachedVulns) allVulns.push(...vulns);
    for (const [, vulns] of fetchedVulns) allVulns.push(...vulns);

    // 7. Filter by severity
    const minSeverity = config.severity?.toUpperCase() || 'MODERATE';
    let severityFiltered = filterBySeverity(allVulns, minSeverity);

    severityFiltered.sort((a, b) => {
      const aOrder = SEVERITY[a.severity]?.order ?? 99;
      const bOrder = SEVERITY[b.severity]?.order ?? 99;
      return bOrder - aOrder;
    });

    // Direct-import evidence must never suppress a security finding. Keep the
    // historical option as a warned no-op so existing automation fails visible
    // rather than silently losing advisories.
    if (config.minReachability) {
      warnings.push(`--min-reachability=${config.minReachability} is deprecated and ignored — direct-import evidence never filters security findings`);
    }

    // 7b. Apply the `ignore` config — suppress by advisory ID, package name,
    // or pkg@version. Suppressed findings are counted, not silently dropped.
    // `let` because the Tier B pass below may swap in AI-annotated copies.
    let filtered;
    const { kept, suppressed } = partitionByIgnore(
      severityFiltered,
      config.ignore,
      v => ({ pkg: v.package, version: v.version, ids: [v.id, v.displayId, ...(v.aliases || [])] }),
    );
    filtered = kept;

    // 7c. Annotate raw records with reachability so EVERY output path — text,
    // JSON findings, and SARIF — carries the Tier A grade. normalizeFinding
    // prefers this field when present.
    for (const v of filtered) {
      v.reachability = reachabilityOf(appGraph, v.ecosystem, v.package);
      v.importEvidence = importEvidenceOf(appGraph, v.ecosystem, v.package);
    }

    // 7d. Tier B (--ai, opt-in): LLM exploitability verdicts on TOP of the
    // deterministic Tier A grades. Advisory metadata only — records keep their
    // evidence, an AI failure never turns `complete` false, and verdicts never
    // filter a finding out. When no provider is configured we warn and proceed
    // exactly as before, so --ai is safe to bake into an agent's default loop.
    let aiTriage;
    if (config.ai) {
      const onWarning = (msg) => warnings.push(msg);
      if (quietStdout) {
        // no spinner on structured stdout; run directly, warnings carry the story
        aiTriage = await triageFindings(filtered, appGraph, { onWarning });
      } else {
        const aiSpinner = createSpinner('AI exploitability triage...');
        aiTriage = await triageFindings(filtered, appGraph, { onWarning });
        aiSpinner.stop(aiLabel(aiTriage));
      }
      filtered = aiTriage.records;
      if (aiTriage.skipped) warnings.push(aiTriage.reason);
    }

    // 8. Determine completeness — did all queries succeed?
    const isComplete = queryComplete && parseFailures === 0 && unresolvedManifestInputs === 0;

    // 9. Format output
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
    const ecoList = [...ecosystemsFound];

    if (quietStdout) {
      const counts = countBySeverity(filtered);
      const aiCounts = config.ai ? countByExploitability(filtered) : {};
      emitStructured({
        version: VERSION,
        timestamp: new Date().toISOString(),
        command: 'scan',
        complete: isComplete,
        summary: { total: uniqueDeps.length, vulnerable: filtered.length, suppressed: suppressed.length, ...counts, ...aiCounts },
        warnings,
        vulnerabilities: filtered,
      });
    } else {
      // Group by severity
      const groups = {};
      for (const v of filtered) {
        (groups[v.severity] ??= []).push(v);
      }

      // --top <n> limits TEXT output only; JSON keeps every finding. Exit
      // codes and summary counts still reflect the full result set.
      const topN = Number.isFinite(parseInt(config.top, 10)) ? parseInt(config.top, 10) : null;
      let shownCount = 0;

      for (const sev of ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']) {
        if (!groups[sev]?.length) continue;
        if (topN != null && shownCount >= topN) break;
        out(header(sev));
        for (const v of groups[sev]) {
          if (topN != null && shownCount >= topN) break;
          shownCount++;
          out(formatVuln(v));
          const importEvidence = importEvidenceOf(appGraph, v.ecosystem, v.package);
          if (importEvidence === 'not_found') {
            out(`    ${C.dim}no direct import found in project source (may still load via tooling or dynamic paths)${C.reset}`);
          } else if (importEvidence === 'found_dynamic') {
            out(`    ${C.dim}only dynamically imported (lazy)${C.reset}`);
          } else if (importEvidence === 'found_static') {
            out(`    ${C.yellow}imported by project code${C.reset}`);
          }
          // Tier B (--ai): per-finding verdict, clearly advisory — it never
          // downgrades the deterministic finding above it.
          if (v.exploitability) {
            const e = v.exploitability;
            if (e.verdict === 'reachable') {
              out(`    ${C.magenta}AI: reachable — ${sanitize(e.why)}${C.reset}`);
            } else if (e.verdict === 'plausible') {
              out(`    ${C.magenta}AI: plausible — ${sanitize(e.why)}${C.reset}`);
            } else if (e.verdict === 'unclear') {
              out(`    ${C.dim}AI: unclear — ${sanitize(e.why)}${C.reset}`);
            } else {
              out(`    ${C.red}AI: error — ${sanitize(e.why)}${C.reset}`);
            }
          }
          out('');
        }
      }

      if (topN != null && filtered.length > shownCount) {
        out(`  ${C.dim}… ${filtered.length - shownCount} more finding(s) not shown (--top ${topN}); JSON output has everything${C.reset}`);
      }

      // Show advisory-derived upgrade hints if --fix was used. These versions
      // are not registry-checked and the proposed graph has not been rescanned.
      if (config.fix && filtered.some(v => v.fixed)) {
        out(header('Advisory Upgrade Hints'));
        const fixable = new Map();
        for (const v of filtered) {
          if (!v.fixed) continue;
          const ver = v.fixed.replace(/^>=\s*/, '');
          const key = `${v.ecosystem}:${v.package}`;
          // Pick the highest fix version via numeric semver compare — string
          // '>' would rank '9.0.0' above '10.0.0' and recommend a stale fix.
          if (!fixable.has(key) || compareSemver(ver, fixable.get(key).ver) > 0) {
            fixable.set(key, { pkg: v.package, ver, ecosystem: v.ecosystem });
          }
        }
        for (const { pkg, ver, ecosystem } of fixable.values()) {
          const cmd = buildUpgradeCommand(pkg, ver, ecosystem);
          if (cmd) out(`  ${C.cyan}${sanitize(cmd)}${C.reset}`);
          else out(`  ${C.yellow}manual review required for invalid or unsupported coordinate${C.reset}`);
        }
        out(`  ${C.dim}Hints come from OSV fixed events; generate the lockfile and rescan before treating them as remediation.${C.reset}`);
        out('');
      }

      // Print warnings prominently if scan was incomplete
      if (warnings.length > 0) {
        out(header('WARNINGS'));
        for (const w of warnings) {
          out(`  ${C.yellow}! ${w}${C.reset}`);
        }
        out('');
      }

      const counts = countBySeverity(filtered);
      out(summary(counts, uniqueDeps.length, ecoList, elapsed));

      if (config.ai && aiTriage) {
        const aiC = countByExploitability(filtered);
        out(`  ${C.dim}AI (advisory): ${aiC.exploitable} exploitable · ${aiC.plausible} plausible · ${aiC.unclear} unclear · ${aiC.aiError} error${C.reset}`);
      }

      if (suppressed.length > 0) {
        out(`  ${C.dim}${suppressed.length} suppressed by ignore config${C.reset}`);
      }

      if (!isComplete) {
        out(`\n  ${C.red}${C.bold}! SCAN INCOMPLETE${C.reset} ${C.red}— some packages could not be checked. Results may be missing vulnerabilities.${C.reset}\n`);
      }

      out('');
    }

    // Exit code: ERROR if scan incomplete, VULNS_FOUND if vulns, OK if clean
    if (!isComplete) return EXIT.ERROR;
    return filtered.length > 0 ? EXIT.VULNS_FOUND : EXIT.OK;

  } finally {
    cache.close();
  }
}

function countBySeverity(vulns) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) {
    const key = v.severity?.toLowerCase();
    if (key in counts) counts[key]++;
  }
  return counts;
}

/**
 * Roll up per-verdict counts for the structured summary (additive keys):
 * exploitable / plausible / unclear / aiError (per-finding verdicts).
 */
function countByExploitability(vulns) {
  const out = { exploitable: 0, plausible: 0, unclear: 0, aiError: 0 };
  for (const v of vulns) {
    const e = v.exploitability;
    if (!e) continue;
    if (e.verdict === 'reachable') out.exploitable++;
    else if (e.verdict === 'plausible') out.plausible++;
    else if (e.verdict === 'error') out.aiError++;
    else out.unclear++; // verdict 'unclear', or malformed
  }
  return out;
}

/** One-line spinner/status label for the Tier B pass. */
function aiLabel(t) {
  if (t.skipped) return `AI triage unavailable — ${t.reason}`;
  return `AI triage: ${t.total - t.errored}/${t.total} judged${t.errored ? ` · ${t.errored} errored` : ''}`;
}

/**
 * Highest advisory fixed-event version per package, keyed `ecosystem:name`.
 * String '>' would rank '9.0.0' above '10.0.0' — use real semver compare.
 */
function buildFixCommands(vulns) {
  const fixable = new Map();
  for (const v of vulns) {
    if (!v.fixed) continue;
    const ver = v.fixed.replace(/^>=\s*/, '');
    const key = `${v.ecosystem}:${v.package}`;
    if (!fixable.has(key) || compareSemver(ver, fixable.get(key).ver) > 0) {
      fixable.set(key, { pkg: v.package, ver, ecosystem: v.ecosystem });
    }
  }
  return fixable;
}

/**
 * Human-usable upgrade command for one finding, from the per-package fix map.
 * Values go into JSON (never a terminal) so no terminal sanitization is needed;
 * text-mode output applies `sanitize` separately before rendering.
 */
function fixCommandFor(v, fixable) {
  const fix = fixable.get(`${v.ecosystem}:${v.package}`);
  if (!fix) return undefined;
  return buildUpgradeCommand(fix.pkg, fix.ver, fix.ecosystem) || undefined;
}

/**
 * Detect manifest declarations the fallback parser could not turn into exact
 * registry coordinates. A range is not evidence of an installed version, so
 * silently treating an empty fallback parse as an empty dependency graph would
 * be a false clean.
 */
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
