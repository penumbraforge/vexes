import { resolve, basename } from 'node:path';
import { statSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { C, createSpinner, header, formatVuln, summary, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, SEVERITY, ECOSYSTEMS } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock, parseManifest as parseNpmManifest } from '../parsers/npm.js';
import { discover as discoverPnpm, parseLockfile as parsePnpmLock } from '../parsers/pnpm.js';
import { discover as discoverYarn, parseLockfile as parseYarnLock } from '../parsers/yarn.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { discover as discoverCargo, parseLockfile as parseCargoLock } from '../parsers/cargo.js';
import { discover as discoverBrew, parseLockfile as parseBrewLock, parseManifest as parseBrewManifest } from '../parsers/brew.js';
import { GENERIC_ECOSYSTEM_PARSERS, parseGenericFile, selectGenericFiles } from '../parsers/generic.js';
import { queryBatch, filterBySeverity, isQueryComplete } from '../advisories/osv.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';

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

  if (!isJSON) {
    out(`\n  ${C.bold}vexes${C.reset} v${VERSION} ${C.dim}\u2500\u2500 scanning dependencies${C.reset}\n`);
  }

  // Track warnings for the final report
  const warnings = [];

  // 1. Discover dependency files
  const allDeps = [];
  const ecosystemsFound = new Set();
  let dependencyFileCount = 0;
  let parseFailures = 0;

  for (const ecoName of config.ecosystems) {
    if (ecoName === 'npm') {
      const { lockfiles, manifests } = discoverNpm(targetDir);

      for (const lf of lockfiles) {
        try {
          const deps = parseNpmLock(lf);
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
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
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
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
          allDeps.push(...deps);
          ecosystemsFound.add('npm');
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
        for (const mf of manifests) {
          try {
            const deps = parseNpmManifest(mf);
            allDeps.push(...deps);
            ecosystemsFound.add('npm');
            dependencyFileCount++;
            const msg = 'no lockfile found — scanning package.json (version ranges, lower confidence)';
            if (!isJSON) out(`  ${C.yellow}! ${msg}${C.reset}`);
            warnings.push(msg);
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
      for (const file of files) {
        try {
          const deps = parsePypiFile(file.path, file.format);
          allDeps.push(...deps);
          ecosystemsFound.add('pypi');
          dependencyFileCount++;
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
          allDeps.push(...deps);
          ecosystemsFound.add('cargo');
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
        const msg = `no lockfile found — scanning ${manifestList} (best-effort manifest fallback, lower confidence)`;
        warnings.push(msg);
        if (!isJSON) out(`  ${C.yellow}! ${msg}${C.reset}`);
      }

      for (const file of files) {
        try {
          const deps = parseGenericFile(ecoName, file);
          allDeps.push(...deps);
          ecosystemsFound.add(ecoName);
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(file.path)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
    }

    if (ecoName === 'brew') {
      const { lockfiles, manifests } = discoverBrew(targetDir);
      for (const lf of lockfiles) {
        try {
          const deps = parseBrewLock(lf);
          allDeps.push(...deps);
          ecosystemsFound.add('brew');
          dependencyFileCount++;
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg);
          warnings.push(msg);
          parseFailures++;
        }
      }
      if (lockfiles.length === 0) {
        for (const mf of manifests) {
          try {
            const deps = parseBrewManifest(mf);
            allDeps.push(...deps);
            ecosystemsFound.add('brew');
            dependencyFileCount++;
          } catch (err) {
            const msg = `failed to parse ${basename(mf)}: ${err.message}`;
            log.error(msg);
            warnings.push(msg);
            parseFailures++;
          }
        }
      }
    }
  }

  // Distinguish "no dependency files found" from "files found but parsing failed"
  if (allDeps.length === 0 && parseFailures > 0) {
    if (isJSON) {
      out(JSON.stringify({
        version: VERSION, command: 'scan', complete: false,
        summary: { total: 0, vulnerable: 0 },
        errors: warnings, vulnerabilities: [],
      }, null, 2));
    } else {
      out(`\n  ${C.red}! Dependency files were found but all failed to parse — cannot determine vulnerability status${C.reset}\n`);
    }
    return EXIT.ERROR;
  }

  if (allDeps.length === 0) {
    if (isJSON) {
      out(JSON.stringify({
        version: VERSION, command: 'scan', complete: true,
        summary: { total: 0, vulnerable: 0 },
        warnings: [], vulnerabilities: [],
      }, null, 2));
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

  if (!isJSON) {
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
      const spinner = isJSON ? null : createSpinner(`Querying OSV.dev for ${needsFetch.length} packages...`);

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
    } else if (!isJSON) {
      out(`  ${C.green}\u2713${C.reset} ${uniqueDeps.length} packages checked (all cached)`);
    }

    // 6. Merge cached + fresh results
    const allVulns = [];
    for (const [, vulns] of cachedVulns) allVulns.push(...vulns);
    for (const [, vulns] of fetchedVulns) allVulns.push(...vulns);

    // 7. Filter by severity
    const minSeverity = config.severity?.toUpperCase() || 'MODERATE';
    const filtered = filterBySeverity(allVulns, minSeverity);

    filtered.sort((a, b) => {
      const aOrder = SEVERITY[a.severity]?.order ?? 99;
      const bOrder = SEVERITY[b.severity]?.order ?? 99;
      return bOrder - aOrder;
    });

    // 8. Determine completeness — did all queries succeed?
    const isComplete = queryComplete && parseFailures === 0;

    // 9. Format output
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
    const ecoList = [...ecosystemsFound];

    if (isJSON) {
      const counts = countBySeverity(filtered);
      out(JSON.stringify({
        version: VERSION,
        timestamp: new Date().toISOString(),
        command: 'scan',
        complete: isComplete,
        summary: { total: uniqueDeps.length, vulnerable: filtered.length, ...counts },
        warnings,
        vulnerabilities: filtered,
      }, null, 2));
    } else {
      // Group by severity
      const groups = {};
      for (const v of filtered) {
        (groups[v.severity] ??= []).push(v);
      }

      for (const sev of ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']) {
        if (!groups[sev]?.length) continue;
        out(header(sev));
        for (const v of groups[sev]) {
          out(formatVuln(v));
          out('');
        }
      }

      // Show fix commands if --fix was used
      if (config.fix && filtered.some(v => v.fixed)) {
        out(header('Fix Commands'));
        const fixable = new Map();
        for (const v of filtered) {
          if (!v.fixed) continue;
          const ver = v.fixed.replace(/^>=\s*/, '');
          const key = `${v.ecosystem}:${v.package}`;
          if (!fixable.has(key) || ver > fixable.get(key).ver) {
            fixable.set(key, { pkg: v.package, ver, ecosystem: v.ecosystem });
          }
        }
        for (const { pkg, ver, ecosystem } of fixable.values()) {
          const cmd = ecosystem === 'npm' ? `npm install ${sanitize(pkg)}@${sanitize(ver)}`
                    : ecosystem === 'pypi' ? `pip install ${sanitize(pkg)}==${sanitize(ver)}`
                    : ecosystem === 'cargo' ? `cargo update -p ${sanitize(pkg)} --precise ${sanitize(ver)}`
                    : `# upgrade ${sanitize(pkg)} to ${sanitize(ver)}`;
          out(`  ${C.cyan}${cmd}${C.reset}`);
        }
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
