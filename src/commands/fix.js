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

/**
 * `vexes fix` — Generate verified, safe upgrade commands for vulnerabilities.
 *
 * CRITICAL INVARIANT: Never recommend a version that is itself vulnerable.
 * We cross-check every recommended version against OSV before presenting it.
 *
 * Strategy:
 * 1. Scan for vulnerabilities (same as `vexes scan`)
 * 2. For each vuln, extract ALL fix versions from OSV ranges
 * 3. Choose the MINIMAL verified upgrade — the lowest version that clears
 *    every advisory's `>= fixed` requirement AND passes its own OSV check
 * 4. Cross-check the recommended version against OSV — is IT safe?
 * 5. Verify the version exists on the registry
 * 6. Generate the exact install command
 */
export async function runFix(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';

  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes fix${C.reset} v${VERSION} ${C.dim}— verified fix recommendations${C.reset}\n`);
  }

  // 1. Discover and scan (npm only for now — fix verification requires registry lookup)
  if (!isJSON && config.ecosystems.some(e => e !== 'npm')) {
    out(`  ${C.dim}Note: fix currently supports npm only. Use vexes scan for other ecosystems.${C.reset}`);
  }

  const { lockfiles } = discoverNpm(targetDir);
  if (lockfiles.length === 0) {
    out(`  ${C.dim}No npm lockfile found in ${targetDir}${C.reset}\n`);
    return EXIT.OK;
  }

  const spinner = isJSON ? null : createSpinner('Scanning for vulnerabilities...');
  let allDeps = [];
  for (const lf of lockfiles) {
    try { allDeps.push(...parseNpmLock(lf)); }
    catch (err) { log.error(`failed to parse ${basename(lf)}: ${err.message}`); }
  }

  // Deduplicate
  const dedupMap = new Map();
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const uniqueDeps = [...dedupMap.values()];

  const osvResult = await queryBatch(uniqueDeps);
  const scanComplete = isQueryComplete(osvResult, uniqueDeps.length);
  const warnings = [...osvResult.failures];
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
        findings: [],
        extra: { version: VERSION, fixes: [] },
      }), null, 2));
    } else if (scanComplete) {
      out(`\n  ${C.green}\u2713 No vulnerabilities found — nothing to fix${C.reset}\n`);
    } else {
      out(`\n  ${C.red}! Fix scan incomplete — some packages could not be checked, so no verified recommendations can be made${C.reset}\n`);
    }
    return scanComplete ? EXIT.OK : EXIT.ERROR;
  }

  // 3. For each vulnerable package, determine the best safe version
  const fixSpinner = isJSON ? null : createSpinner('Verifying fix versions against OSV...');
  const fixes = [];
  let hadIncompleteVerification = false;

  for (const [pkgName, vulns] of vulnsByPackage) {
    const currentVersion = vulns[0].version;
    const ecosystem = vulns[0].ecosystem;
    let verificationIncomplete = false;

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

    // Sort candidates highest-first, then pick the LOWEST safe candidate that
    // still clears maxThreshold. That is the minimal verified upgrade — no
    // arbitrary jump to latest, smallest collateral change. Deterministic.
    const sorted = [...fixCandidates].sort(compareSemver).reverse();
    let bestFix = null;
    for (const candidate of sorted) {
      const verification = await verifyFixVersion(pkgName, candidate, ecosystem);
      if (verification.incomplete) {
        verificationIncomplete = true;
        hadIncompleteVerification = true;
      }
      if (verification.safe && compareSemver(candidate, maxThreshold) >= 0) {
        if (!bestFix || compareSemver(candidate, bestFix.version) < 0) {
          bestFix = {
            version: candidate,
            verified: true,
            existsOnRegistry: verification.exists,
            ownVulns: verification.ownVulns,
          };
        } else {
          log.debug(`fix candidate ${pkgName}@${candidate} is not minimal (skipped over lower verified version)`);
        }
      } else {
        log.debug(`fix candidate ${pkgName}@${candidate} rejected: ${verification.safe ? 'below threshold' : verification.ownVulns.map(v => v.id).join(', ')}`);
      }
    }

    if (!bestFix) {
      // All candidates are themselves vulnerable — recommend latest
      const latest = await getLatestVersion(pkgName, ecosystem);
      if (latest) {
        const latestVerification = await verifyFixVersion(pkgName, latest, ecosystem);
        if (latestVerification.incomplete) {
          verificationIncomplete = true;
          hadIncompleteVerification = true;
        }
        if (latestVerification.safe) {
          bestFix = { version: latest, verified: true, existsOnRegistry: true, ownVulns: [], isLatest: true };
        }
      }
    }

    const command = bestFix ? generateCommand(pkgName, bestFix.version, ecosystem) : null;

    fixes.push({
      package: pkgName,
      currentVersion,
      ecosystem,
      vulnCount: vulns.length,
      vulnIds: vulns.map(v => v.displayId),
      recommendation: bestFix ? {
        version: bestFix.version,
        verified: bestFix.verified,
        existsOnRegistry: bestFix.existsOnRegistry,
        command,
        isLatest: bestFix.isLatest || false,
      } : null,
      reason: bestFix ? null : verificationIncomplete
        ? 'Could not verify fix version safety — OSV query incomplete'
        : 'All known fix versions are themselves vulnerable — manual review required',
    });
  }

  fixSpinner?.stop(`${fixes.length} packages analyzed`);
  if (hadIncompleteVerification) {
    warnings.push('one or more candidate fix versions could not be fully verified');
  }
  const complete = scanComplete && !hadIncompleteVerification;

  // 3b. Order the minimal upgrade set dependency-first so a dependency moves
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
      findings: [],
      extra: { version: VERSION, fixes: orderedFixes, upgradeOrder: order, minimal: true },
    }), null, 2));
  } else {
    out(header('Fix Recommendations'));

    const fixable = orderedFixes.filter(f => f.recommendation);
    const unfixable = orderedFixes.filter(f => !f.recommendation);

    if (fixable.length > 0) {
      for (const f of fixable) {
        const rec = f.recommendation;
        const verifiedTag = rec.verified ? `${C.green}\u2713 verified${C.reset}` : `${C.yellow}? unverified${C.reset}`;
        out(`  ${C.bold}${sanitize(f.package)}${C.reset} ${C.dim}${sanitize(f.currentVersion)} \u2192 ${C.reset}${C.green}${sanitize(rec.version)}${C.reset} ${verifiedTag}`);
        out(`    ${C.dim}${f.vulnCount} vuln(s): ${f.vulnIds.map(id => sanitize(id)).join(', ')}${C.reset}`);
        out(`    ${C.cyan}${sanitize(rec.command)}${C.reset}`);
        out('');
      }

      // Summary command block — already in dependency-before-dependent order
      out(`  ${C.bold}Minimal upgrade set (dependency-first):${C.reset}\n`);
      for (const f of fixable) {
        out(`    ${sanitize(f.recommendation.command)}`);
      }
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
    out(`  ${fixable.length} fixable \u00b7 ${unfixable.length} require manual review`);
    if (warnings.length > 0) {
      out(`  ${C.yellow}! ${warnings.length} warning(s) — results may be incomplete${C.reset}`);
    }
    out(`  ${C.dim}${line}${C.reset}\n`);

    if (!complete) {
      out(`  ${C.red}${C.bold}! FIX INCOMPLETE${C.reset} ${C.red}— some packages or candidate versions could not be verified.${C.reset}\n`);
    }
  }

  if (!complete) return EXIT.ERROR;
  return fixes.some(f => !f.recommendation) ? EXIT.VULNS_FOUND : EXIT.OK;
}

/**
 * Verify a fix version is safe by querying OSV for it.
 * The CRITICAL check: does the fix version itself have known vulnerabilities?
 */
export async function verifyFixVersion(pkgName, version, ecosystem) {
  try {
    const result = await queryBatch([{ name: pkgName, version, ecosystem }]);
    if (!isQueryComplete(result, 1)) {
      return { safe: false, exists: false, ownVulns: [], incomplete: true };
    }
    const key = `${ecosystem}:${pkgName}@${version}`;
    const vulns = result.results.get(key) || [];
    return {
      safe: vulns.length === 0,
      exists: true,
      ownVulns: vulns,
      incomplete: false,
    };
  } catch {
    // If we can't verify, DON'T recommend — fail safe
    return { safe: false, exists: false, ownVulns: [], incomplete: true };
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
 * Shell-escape a string to prevent command injection when copy-pasted.
 * Wraps in single quotes, escaping any existing single quotes.
 * Only applies escaping when the string contains shell-unsafe characters.
 */
function shellEscape(s) {
  // Safe: alphanumeric, @, /, ., -, _
  if (/^[a-zA-Z0-9@/._-]+$/.test(s)) return s;
  // Wrap in single quotes, escape existing single quotes
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/**
 * Generate the exact install command for a fix.
 * Package names and versions are shell-escaped to prevent injection
 * when the user copy-pastes the command.
 */
function generateCommand(pkgName, version, ecosystem) {
  const safeName = shellEscape(pkgName);
  const safeVersion = shellEscape(version);
  switch (ecosystem) {
    case 'npm':  return `npm install ${safeName}@${safeVersion}`;
    case 'pypi': return `pip install ${safeName}==${safeVersion}`;
    case 'cargo': return `cargo update -p ${safeName} --precise ${safeVersion}`;
    default: return `# upgrade ${safeName} to ${safeVersion}`;
  }
}

/**
 * Order the minimal upgrade set dependency-first.
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
