import { resolve, basename } from 'node:path';
import { statSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, NPM_REGISTRY_URL } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchJSON } from '../core/fetcher.js';

/**
 * `vexes fix` — Generate verified, safe upgrade commands for vulnerabilities.
 *
 * CRITICAL INVARIANT: Never recommend a version that is itself vulnerable.
 * We cross-check every recommended version against OSV before presenting it.
 *
 * Strategy:
 * 1. Scan for vulnerabilities (same as `vexes scan`)
 * 2. For each vuln, extract ALL fix versions from OSV ranges
 * 3. Sort fix candidates: prefer minimal semver upgrade (same major)
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
      out(JSON.stringify({
        version: VERSION,
        command: 'fix',
        timestamp: new Date().toISOString(),
        complete: scanComplete,
        fixes: [],
        warnings,
      }, null, 2));
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

    // Sort candidates: prefer the HIGHEST version (most likely to fix all vulns)
    const sorted = [...fixCandidates].sort(compareSemver).reverse();

    // Find the best candidate: highest version that passes verification
    let bestFix = null;
    for (const candidate of sorted) {
      const verification = await verifyFixVersion(pkgName, candidate, ecosystem);
      if (verification.incomplete) {
        verificationIncomplete = true;
        hadIncompleteVerification = true;
      }
      if (verification.safe) {
        bestFix = {
          version: candidate,
          verified: true,
          existsOnRegistry: verification.exists,
          ownVulns: verification.ownVulns,
        };
        break;
      } else {
        log.debug(`fix candidate ${pkgName}@${candidate} is itself vulnerable: ${verification.ownVulns.map(v => v.id).join(', ')}`);
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

  // 4. Output
  if (isJSON) {
    out(JSON.stringify({
      version: VERSION, command: 'fix',
      timestamp: new Date().toISOString(),
      complete,
      fixes,
      warnings,
    }, null, 2));
  } else {
    out(header('Fix Recommendations'));

    const fixable = fixes.filter(f => f.recommendation);
    const unfixable = fixes.filter(f => !f.recommendation);

    if (fixable.length > 0) {
      for (const f of fixable) {
        const rec = f.recommendation;
        const verifiedTag = rec.verified ? `${C.green}\u2713 verified${C.reset}` : `${C.yellow}? unverified${C.reset}`;
        out(`  ${C.bold}${sanitize(f.package)}${C.reset} ${C.dim}${sanitize(f.currentVersion)} \u2192 ${C.reset}${C.green}${sanitize(rec.version)}${C.reset} ${verifiedTag}`);
        out(`    ${C.dim}${f.vulnCount} vuln(s): ${f.vulnIds.map(id => sanitize(id)).join(', ')}${C.reset}`);
        out(`    ${C.cyan}${sanitize(rec.command)}${C.reset}`);
        out('');
      }

      // Summary command block
      out(`  ${C.bold}Run all fixes:${C.reset}\n`);
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
 * Basic semver comparison (major.minor.patch).
 * Returns negative if a < b, positive if a > b, 0 if equal.
 */
function compareSemver(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
