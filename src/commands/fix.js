import { resolve, basename } from 'node:path';
import { statSync, readFileSync, existsSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope } from '../cli/schema.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, NPM_REGISTRY_URL } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchJSON } from '../core/fetcher.js';
import { compareSemver } from '../core/semver.js';
import { buildUpgradeCommand } from '../core/upgrade-command.js';

/**
 * `vexes fix` — Generate OSV-cross-checked upgrade candidates.
 *
 * CRITICAL INVARIANT: Never present a candidate when its OSV lookup is
 * incomplete or the exact registry version cannot be confirmed. An empty OSV
 * result means "no known vulnerability in OSV", not proof that a version is
 * safe or that applying the command removes every vulnerable lockfile path.
 *
 * Strategy:
 * 1. Scan for vulnerabilities (same as `vexes scan`)
 * 2. For each vuln, extract ALL fix versions from OSV ranges
 * 3. Choose the lowest advisory candidate that clears every `>= fixed`
 *    threshold and has no known OSV advisory of its own
 * 4. Confirm that exact version exists on the npm registry
 * 5. Generate the exact install command
 */
export async function runFix(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';

  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes fix${C.reset} v${VERSION} ${C.dim}— OSV-cross-checked upgrade candidates${C.reset}\n`);
  }

  // 1. Discover and scan (npm only for now — fix verification requires registry lookup)
  if (!isJSON && config.ecosystems.some(e => e !== 'npm')) {
    out(`  ${C.dim}Note: fix currently supports npm only. Use vexes scan for other ecosystems.${C.reset}`);
  }

  const { lockfiles } = discoverNpm(targetDir);
  const warnings = [];
  if (lockfiles.length === 0) {
    warnings.push('no npm lockfile found — fix analysis did not run');
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'fix',
        target: { dir: targetDir, lockfiles: [], ecosystems: ['npm'] },
        complete: false,
        warnings,
        summary: { total: 0, candidates: 0 },
        findings: [],
        extra: { version: VERSION, fixes: [] },
      }), null, 2));
    } else {
      out(`  ${C.red}! Fix analysis incomplete — no npm lockfile found in ${targetDir}${C.reset}\n`);
    }
    return EXIT.ERROR;
  }

  const spinner = isJSON ? null : createSpinner('Scanning for vulnerabilities...');
  let allDeps = [];
  let parsedLockfiles = 0;
  let parseFailures = 0;
  let unresolvedLockInputs = 0;
  for (const lf of lockfiles) {
    try {
      const parsed = parseNpmLock(lf);
      if (parsed.unresolvedEntries > 0) {
        unresolvedLockInputs++;
        warnings.push(`${basename(lf)} contains local, linked, remote, or unanchored npm entries — fix analysis is incomplete`);
      }
      allDeps.push(...parsed);
      parsedLockfiles++;
    } catch (err) {
      const warning = `failed to parse ${basename(lf)}: ${err.message}`;
      log.error(warning);
      warnings.push(warning);
      parseFailures++;
    }
  }

  // Deduplicate
  const dedupMap = new Map();
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const uniqueDeps = [...dedupMap.values()];

  if (uniqueDeps.length === 0) {
    const complete = parseFailures === 0 && parsedLockfiles > 0 && unresolvedLockInputs === 0;
    if (!complete) warnings.push('no npm lockfile could be parsed — fix analysis did not run');
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'fix',
        target: { dir: targetDir, lockfiles: lockfiles.map(f => basename(f)), ecosystems: ['npm'] },
        complete,
        warnings,
        summary: { total: 0, candidates: 0 },
        findings: [],
        extra: { version: VERSION, fixes: [] },
      }), null, 2));
    } else if (complete) {
      out(`\n  ${C.green}\u2713 Parsed npm lockfile contains no dependencies${C.reset}\n`);
    } else {
      out(`\n  ${C.red}! Fix analysis incomplete — no usable npm lockfile${C.reset}\n`);
    }
    return complete ? EXIT.OK : EXIT.ERROR;
  }

  const osvResult = await queryBatch(uniqueDeps);
  const scanComplete = parseFailures === 0 && unresolvedLockInputs === 0 && isQueryComplete(osvResult, uniqueDeps.length);
  warnings.push(...osvResult.failures);
  spinner?.stop(`${uniqueDeps.length} packages scanned`);

  // 2. Collect vulnerabilities with fix data
  const vulnsByPackage = new Map(); // name → [vulns]
  for (const [key, vulns] of osvResult.results) {
    for (const v of vulns) {
      const existing = vulnsByPackage.get(v.package) || [];
      existing.push(v);
      vulnsByPackage.set(v.package, existing);
    }
  }

  if (vulnsByPackage.size === 0) {
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'fix',
        target: { dir: targetDir, lockfiles: lockfiles.map(f => basename(f)), ecosystems: [...config.ecosystems] },
        complete: scanComplete,
        warnings,
        summary: { total: uniqueDeps.length, vulnerable: 0, candidates: 0 },
        findings: [],
        extra: { version: VERSION, fixes: [] },
      }), null, 2));
    } else if (scanComplete) {
      out(`\n  ${C.green}\u2713 No vulnerabilities found — nothing to fix${C.reset}\n`);
    } else {
      out(`\n  ${C.red}! Fix scan incomplete — some packages could not be checked, so no candidates can be offered${C.reset}\n`);
    }
    return scanComplete ? EXIT.OK : EXIT.ERROR;
  }

  // 3. For each vulnerable package, determine the lowest candidate with a
  // complete OSV cross-check and confirmed exact registry version.
  const fixSpinner = isJSON ? null : createSpinner('Cross-checking candidate versions against OSV and npm...');
  const fixes = [];
  let hadIncompleteVerification = false;

  for (const [pkgName, vulns] of vulnsByPackage) {
    const currentVersion = vulns[0].version;
    const ecosystem = vulns[0].ecosystem;
    let verificationIncomplete = false;
    let candidateAbsentFromRegistry = false;
    let candidateBelowThreshold = false;
    let invalidCoordinate = false;

    // Collect ALL fix versions from ALL vulns for this package
    const fixCandidates = new Set();
    for (const v of vulns) {
      if (v.fixed) {
        const ver = v.fixed.replace(/^>=\s*/, '');
        fixCandidates.add(ver);
      }
    }

    if (fixCandidates.size === 0) {
      fixes.push({
        package: pkgName,
        currentVersion,
        ecosystem,
        vulnCount: vulns.length,
        vulnIds: vulns.map(v => v.displayId),
        recommendation: null,
        reason: 'No fix version available in advisories',
      });
      continue;
    }

    // The requirement every candidate must clear: the HIGHEST `>= fixed`
    // threshold across all advisories for the package. A version below it
    // fixes one advisory while leaving another open.
    const maxThreshold = [...fixCandidates].sort(compareSemver).reverse()[0];

    // Sort candidates highest-first, then pick the LOWEST eligible candidate that
    // still clears maxThreshold. That is the lowest checked candidate — no
    // arbitrary jump to latest, smallest collateral change. Deterministic.
    const sorted = [...fixCandidates].sort(compareSemver).reverse();
    let bestFix = null;
    for (const candidate of sorted) {
      const verification = await verifyFixVersion(pkgName, candidate, ecosystem);
      if (verification.incomplete) {
        verificationIncomplete = true;
        hadIncompleteVerification = true;
      }
      if (verification.registryExists === false) candidateAbsentFromRegistry = true;
      if (verification.eligible && compareSemver(candidate, maxThreshold) < 0) candidateBelowThreshold = true;
      if (verification.eligible && compareSemver(candidate, maxThreshold) >= 0) {
        if (!bestFix || compareSemver(candidate, bestFix.version) < 0) {
          bestFix = {
            version: candidate,
            osvCrossChecked: true,
            registryExists: verification.registryExists,
            ownVulns: verification.ownVulns,
          };
        } else {
          log.debug(`fix candidate ${pkgName}@${candidate} is not minimal (skipped over lower checked version)`);
        }
      } else {
        const why = verification.registryExists === false ? 'version absent from registry'
          : verification.incomplete ? 'verification incomplete'
          : verification.ownVulns.length > 0 ? verification.ownVulns.map(v => v.id).join(', ')
          : 'below threshold';
        log.debug(`fix candidate ${pkgName}@${candidate} rejected: ${why}`);
      }
    }

    if (!bestFix) {
      // If advisory fixed-event candidates do not qualify, cross-check latest.
      const latest = await getLatestVersion(pkgName, ecosystem);
      if (latest) {
        const latestVerification = await verifyFixVersion(pkgName, latest, ecosystem);
        if (latestVerification.incomplete) {
          verificationIncomplete = true;
          hadIncompleteVerification = true;
        }
        if (latestVerification.registryExists === false) candidateAbsentFromRegistry = true;
        if (latestVerification.eligible && compareSemver(latest, maxThreshold) >= 0) {
          bestFix = {
            version: latest,
            osvCrossChecked: true,
            registryExists: latestVerification.registryExists,
            ownVulns: [],
            isLatest: true,
          };
        } else if (latestVerification.eligible) {
          candidateBelowThreshold = true;
        }
      } else {
        verificationIncomplete = true;
        hadIncompleteVerification = true;
      }
    }

    const command = bestFix ? buildUpgradeCommand(pkgName, bestFix.version, ecosystem) : null;
    if (bestFix && !command) {
      invalidCoordinate = true;
      bestFix = null;
    }

    fixes.push({
      package: pkgName,
      currentVersion,
      ecosystem,
      vulnCount: vulns.length,
      vulnIds: vulns.map(v => v.displayId),
      recommendation: bestFix ? {
        version: bestFix.version,
        // Legacy field is deliberately false: the full remediation is not
        // verified until a proposed lockfile is generated and rescanned.
        verified: false,
        status: 'osv-cross-checked-candidate',
        osvCrossChecked: bestFix.osvCrossChecked,
        existsOnRegistry: bestFix.registryExists,
        registryExistence: bestFix.registryExists === true ? 'confirmed' : 'unknown',
        remediationVerified: false,
        requiresResolvedGraphRescan: true,
        command,
        isLatest: bestFix.isLatest || false,
      } : null,
      reason: bestFix ? null : verificationIncomplete
        ? 'Could not complete OSV and registry checks for an upgrade candidate'
        : invalidCoordinate
          ? 'Candidate package coordinate cannot be represented as a safe upgrade command'
        : candidateAbsentFromRegistry
          ? 'Advisory fix version was not present on the npm registry'
          : candidateBelowThreshold
            ? 'No checked registry candidate met every advisory fixed-version threshold'
          : 'Every checked candidate has a known OSV advisory — manual review required',
    });
  }

  fixSpinner?.stop(`${fixes.length} packages analyzed`);
  if (hadIncompleteVerification) {
    warnings.push('one or more candidate versions could not be fully cross-checked against OSV and the registry');
  }
  const complete = scanComplete && !hadIncompleteVerification;

  // 3b. Order the candidate upgrade set dependency-first so a dependency moves
  // before its dependents can resolve against it. Deterministic: lockfile
  // edges (npm) drive the topo order; ties fall back to package-name order;
  // cycles break on name order so output never flips between runs.
  const { fixes: orderedFixes, order } = orderFixesByDependency(fixes, { lockfiles });

  // 4. Output
  if (isJSON) {
    out(JSON.stringify(buildEnvelope({
      command: 'fix',
      target: { dir: targetDir, lockfiles: lockfiles.map(f => basename(f)), ecosystems: [...config.ecosystems] },
      complete,
      warnings,
      summary: {
        total: uniqueDeps.length,
        vulnerable: vulnsByPackage.size,
        candidates: orderedFixes.filter(f => f.recommendation).length,
        manualReview: orderedFixes.filter(f => !f.recommendation).length,
      },
      findings: [],
      extra: {
        version: VERSION,
        fixes: orderedFixes,
        upgradeOrder: order,
        minimal: false,
        selection: 'lowest advisory fixed-version candidate with complete OSV cross-check and confirmed registry existence',
        remediationVerified: false,
        requiresResolvedGraphRescan: true,
      },
    }), null, 2));
  } else {
    out(header('Upgrade Candidates'));

    const fixable = orderedFixes.filter(f => f.recommendation);
    const unfixable = orderedFixes.filter(f => !f.recommendation);

    if (fixable.length > 0) {
      for (const f of fixable) {
        const rec = f.recommendation;
        const candidateTag = `${C.green}\u2713 OSV cross-checked; registry version confirmed${C.reset}`;
        out(`  ${C.bold}${sanitize(f.package)}${C.reset} ${C.dim}${sanitize(f.currentVersion)} \u2192 ${C.reset}${C.green}${sanitize(rec.version)}${C.reset} ${candidateTag}`);
        out(`    ${C.dim}${f.vulnCount} vuln(s): ${f.vulnIds.map(id => sanitize(id)).join(', ')}${C.reset}`);
        out(`    ${C.cyan}${sanitize(rec.command)}${C.reset}`);
        out('');
      }

      // Summary command block — already in dependency-before-dependent order
      out(`  ${C.bold}Candidate upgrade set (dependency-first):${C.reset}\n`);
      for (const f of fixable) {
        out(`    ${sanitize(f.recommendation.command)}`);
      }
      out(`  ${C.dim}Generate the proposed lockfile and rescan it; candidate commands are not verified remediation.${C.reset}`);
      out('');
    }

    if (unfixable.length > 0) {
      out(`  ${C.yellow}No automated fix available:${C.reset}\n`);
      for (const f of unfixable) {
        out(`  ${C.yellow}\u25cb${C.reset} ${sanitize(f.package)}@${sanitize(f.currentVersion)} — ${f.reason}`);
        out(`    ${C.dim}${f.vulnIds.map(id => sanitize(id)).join(', ')}${C.reset}`);
      }
      out('');
    }

    const line = '\u2500'.repeat(50);
    out(`  ${C.dim}${line}${C.reset}`);
    out(`  ${fixable.length} candidate(s) \u00b7 ${unfixable.length} require manual review`);
    if (warnings.length > 0) {
      out(`  ${C.yellow}! ${warnings.length} warning(s) — results may be incomplete${C.reset}`);
    }
    out(`  ${C.dim}${line}${C.reset}\n`);

    if (!complete) {
      out(`  ${C.red}${C.bold}! FIX INCOMPLETE${C.reset} ${C.red}— some packages or candidate versions could not be cross-checked.${C.reset}\n`);
    }
  }

  if (!complete) return EXIT.ERROR;
  // This command only proposes candidates; it does not mutate or rescan the
  // resolved graph. Existing vulnerabilities therefore remain findings.
  return EXIT.VULNS_FOUND;
}

/**
 * Cross-check a candidate against OSV, then confirm the exact registry version.
 * This does not prove the candidate safe or prove that installing it removes
 * every vulnerable occurrence from the resolved dependency graph.
 */
export async function verifyFixVersion(pkgName, version, ecosystem) {
  try {
    const result = await queryBatch([{ name: pkgName, version, ecosystem }]);
    if (!isQueryComplete(result, 1)) {
      return verificationResult({ incomplete: true });
    }
    const key = `${ecosystem}:${pkgName}@${version}`;
    const vulns = result.results.get(key) || [];
    if (vulns.length > 0) {
      return verificationResult({ ownVulns: vulns, osvCrossChecked: true });
    }

    const registryExists = await verifyRegistryVersionExists(pkgName, version, ecosystem);
    if (registryExists === null) {
      return verificationResult({ osvCrossChecked: true, registryExists: null, incomplete: true });
    }
    return verificationResult({
      eligible: registryExists,
      osvCrossChecked: true,
      registryExists,
    });
  } catch {
    return verificationResult({ incomplete: true });
  }
}

function verificationResult({ eligible = false, osvCrossChecked = false, registryExists = null, ownVulns = [], incomplete = false } = {}) {
  return {
    eligible,
    noKnownVulnerabilities: osvCrossChecked && ownVulns.length === 0,
    osvCrossChecked,
    registryExists,
    ownVulns,
    incomplete,
    // Compatibility aliases. `safe` can no longer truthfully become true: an
    // OSV-empty candidate is not a verified remediation. Consumers should use
    // `eligible` for candidate selection. `exists` is null unless checked.
    safe: false,
    exists: registryExists,
  };
}

/** Confirm that the exact npm version endpoint exists. null means unavailable. */
export async function verifyRegistryVersionExists(pkgName, version, ecosystem) {
  if (ecosystem !== 'npm') return null;
  const urlName = pkgName.startsWith('@')
    ? '@' + encodeURIComponent(pkgName.slice(1))
    : encodeURIComponent(pkgName);
  try {
    const data = await fetchJSON(`${NPM_REGISTRY_URL}/${urlName}/${encodeURIComponent(version)}`, { timeout: 8000 });
    return data?.name === pkgName && data?.version === version;
  } catch (err) {
    if (err?.status === 404) return false;
    return null;
  }
}

/**
 * Get the latest version from the npm registry.
 */
async function getLatestVersion(pkgName, ecosystem) {
  if (ecosystem !== 'npm') return null;
  try {
    const urlName = pkgName.startsWith('@')
      ? '@' + encodeURIComponent(pkgName.slice(1))
      : encodeURIComponent(pkgName);
    const data = await fetchJSON(`${NPM_REGISTRY_URL}/${urlName}`, { timeout: 8000 });
    return data['dist-tags']?.latest || null;
  } catch {
    return null;
  }
}

/**
 * Order the candidate upgrade set dependency-first.
 *
 * A dependency must move before its dependents can resolve against it, so
 * list pure dependencies before the packages that depend on them. Edges come
 * from the npm lockfile's own graph (`packages` flat form, or `dependencies`
 * nested form); a fixable package that requires another fixable package is
 * ordered after it. Cycles and non-npm/unordered items fall back to package-
 * name order so the output never flips between runs.
 *
 * @param {Array} fixes — fix records ({package, recommendation})
 * @param {object} opts — { lockfiles: string[] }
 * @returns {{ fixes: Array, order: string[] }} reordered fixes + upgrade sequences
 */
export function orderFixesByDependency(fixes, { lockfiles = [] } = {}) {
  // Unfixable items keep their insertion order at the tail.
  const fixable = fixes.map((f, idx) => ({ f, idx })).filter(({ f }) => f.recommendation).map(({ f }) => f.package);
  const names = [...new Set(fixable)];
  if (names.length <= 1) {
    return { fixes: [...fixes], order: names };
  }
  const nameSet = new Set(names);

  // Edge map: package → set of package names it requires (that are also fix
  // targets). This drives "dependency before dependent".
  const requires = new Map(names.map(n => [n, new Set()]));
  for (const lf of lockfiles) {
    let raw;
    try {
      if (!existsSync(lf)) continue;
      raw = JSON.parse(readFileSync(lf, 'utf8'));
    } catch { continue; }
    // v3 flat form: key "node_modules/<name>" → entry.dependencies[].name
    if (raw.packages) {
      for (const [key, entry] of Object.entries(raw.packages)) {
        if (!key.startsWith('node_modules/')) continue;
        const name = key.slice('node_modules/'.length);
        if (!nameSet.has(name)) continue;
        for (const dep of Object.keys(entry.dependencies || {})) {
          if (nameSet.has(dep) && dep !== name) requires.get(name).add(dep);
        }
      }
    } else if (raw.dependencies) {
      // v2 nested form: walk the dependencies tree collecting edges.
      const walk = (node) => {
        for (const [name, entry] of Object.entries(node || {})) {
          if (!nameSet.has(name)) continue;
          for (const dep of Object.keys(entry.dependencies || {})) {
            if (nameSet.has(dep) && dep !== name) requires.get(name).add(dep);
          }
          walk(entry.dependencies);
        }
      };
      walk(raw.dependencies);
    }
  }

  // Kahn: repeatedly emit fix targets whose requirements are all met, alpha
  // for determinism; a leftover set means a cycle → emit alpha-sorted.
  const remaining = new Map(names.map(n => [n, new Set(requires.get(n))]));
  const order = [];
  let guard = names.length * 2 + 1;
  while (remaining.size > 0 && guard-- > 0) {
    const ready = [...remaining.entries()]
      .filter(([, reqs]) => reqs.size === 0)
      .map(([n]) => n)
      .sort();
    if (ready.length === 0) break; // cycle
    for (const n of ready) {
      order.push(n);
      remaining.delete(n);
      for (const [, reqs] of remaining) reqs.delete(n);
    }
  }
  order.push(...[...remaining.keys()].sort());

  // Stable-partition the original fixes by upgrade order (unfixable at tail).
  const pos = new Map(order.map((n, i) => [n, i]));
  const paired = fixes.map((f, i) => ({ f, i }));
  paired.sort((a, b) => {
    const ka = a.f.recommendation && pos.has(a.f.package) ? pos.get(a.f.package) : Infinity;
    const kb = b.f.recommendation && pos.has(b.f.package) ? pos.get(b.f.package) : Infinity;
    if (ka === Infinity && kb === Infinity) return a.i - b.i; // stable: keep relative order
    return ka - kb;
  });

  return { fixes: paired.map(p => p.f), order };
}
