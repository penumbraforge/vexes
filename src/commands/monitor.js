import { resolve, basename } from 'node:path';
import { statSync, existsSync, readFileSync, watch } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { C, createSpinner, header, formatVuln, summary, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, SEVERITY, ECOSYSTEMS } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { discover as discoverPnpm, parseLockfile as parsePnpmLock } from '../parsers/pnpm.js';
import { discover as discoverYarn, parseLockfile as parseYarnLock } from '../parsers/yarn.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { discover as discoverCargo, parseLockfile as parseCargoLock } from '../parsers/cargo.js';
import { GENERIC_ECOSYSTEM_PARSERS, parseGenericFile, selectGenericFiles } from '../parsers/generic.js';
import { queryBatch, filterBySeverity, isQueryComplete } from '../advisories/osv.js';
import { diffSnapshots, toSnapshot } from '../analysis/diff.js';
import { checkFreshness } from '../analysis/freshness.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';
import { toSarif } from '../cli/sarif.js';
import { buildEnvelope, normalizeFinding, REACHABILITY } from '../cli/schema.js';

const DEFAULT_POLL_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
const MIN_POLL_INTERVAL_MS = 60 * 1000;           // 1 minute

/**
 * `vexes monitor` — Continuous dependency monitoring.
 *
 * Two modes:
 *   --ci        One-shot scan for CI pipelines. Outputs GitHub Actions annotations.
 *               Exit code 0 (clean), 1 (vulns found), 2 (error/incomplete).
 *
 *   --watch     Continuous mode. Watches lockfiles for changes + polls OSV periodically.
 *               Alerts on new vulnerabilities or suspicious lockfile changes.
 */
export async function runMonitor(flags, args) {
  if (flags.ci) return runCI(flags);
  if (flags.watch) return runWatch(flags);

  // Default: show help
  out(`
  ${C.bold}vexes monitor${C.reset} v${VERSION} ${C.dim}— continuous dependency watch${C.reset}

  ${C.bold}MODES${C.reset}
    --ci                 One-shot scan for CI pipelines (GitHub Actions annotations)
    --watch              Continuous monitoring (watches lockfiles + polls OSV)

  ${C.bold}CI OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --severity <level>   Fail threshold: critical, high, moderate ${C.dim}(default: high)${C.reset}
    --json               Machine-readable output to stdout
    --sarif              SARIF format output (for GitHub Advanced Security)

  ${C.bold}WATCH OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --interval <min>     OSV poll interval in minutes ${C.dim}(default: 60)${C.reset}
    --freshness <min>    Registry poll interval — detects suspicious NEW
                         releases within minutes (default: off). Combine with
                         --interval for the full real-time layer.

  ${C.bold}CI EXAMPLE${C.reset}
    ${C.dim}# GitHub Actions workflow step${C.reset}
    - name: Security scan
      run: npx @penumbraforge/vexes monitor --ci --severity high
`);
  return EXIT.OK;
}

/**
 * CI mode — one-shot scan with GitHub Actions annotations.
 */
async function runCI(flags) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const isSARIF = !!flags.sarif;
  const minSeverity = (flags.severity || 'high').toUpperCase();

  // Validate
  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  // Parse all lockfiles
  const parseResult = parseAllEcosystems(targetDir, config.ecosystems);
  const allDeps = parseResult.deps;
  const warnings = [...parseResult.warnings];
  if (allDeps.length === 0) {
    const complete = parseResult.parseFailures === 0;
    if (isSARIF) {
      out(JSON.stringify(toSarif({ complete, summary: { total: 0, vulnerable: 0 }, warnings, vulnerabilities: [] }), null, 2));
    } else if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'monitor',
        target: { dir: targetDir, lockfiles: [], ecosystems: [...config.ecosystems] },
        complete,
        warnings,
        summary: { total: 0, vulnerable: 0, scanned: 0, failed: parseResult.parseFailures, unreachable: 0 },
        findings: [],
        extra: { mode: 'ci', version: VERSION, vulnerabilities: [] },
      }), null, 2));
    } else if (complete) {
      out('::notice::No dependencies found to scan');
    } else {
      for (const w of warnings) {
        out(`::warning title=Scan Incomplete::${sanitize(w)}`);
      }
      out('::error title=Scan Incomplete::Lockfiles were found but could not be parsed');
    }
    return complete ? EXIT.OK : EXIT.ERROR;
  }

  // Query OSV
  const osvResult = await queryBatch(allDeps);
  warnings.push(...osvResult.failures);
  const complete = parseResult.parseFailures === 0 && isQueryComplete(osvResult, allDeps.length);

  // Collect and filter vulns
  const allVulns = [];
  for (const [, vulns] of osvResult.results) allVulns.push(...vulns);
  const filtered = filterBySeverity(allVulns, minSeverity);

  // Sort by severity
  filtered.sort((a, b) => (SEVERITY[b.severity]?.order ?? 0) - (SEVERITY[a.severity]?.order ?? 0));

  if (isSARIF) {
    out(JSON.stringify(toSarif({
      complete,
      summary: { total: allDeps.length, vulnerable: filtered.length },
      warnings,
      vulnerabilities: filtered,
    }), null, 2));
  } else if (isJSON) {
    out(JSON.stringify(buildEnvelope({
      command: 'monitor',
      target: { dir: targetDir, lockfiles: [], ecosystems: [...config.ecosystems] },
      complete,
      warnings,
      summary: {
        total: allDeps.length,
        vulnerable: filtered.length,
        scanned: osvResult.queriedCount,
        failed: osvResult.failedCount,
        unreachable: 0,
      },
      findings: filtered.map(v => normalizeFinding(v, { reachability: REACHABILITY.UNKNOWN })),
      extra: { mode: 'ci', version: VERSION, vulnerabilities: filtered },
    }), null, 2));
  } else {
    // GitHub Actions annotation format
    for (const v of filtered) {
      const level = v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning';
      const msg = `${sanitize(v.package)}@${sanitize(v.version)}: ${sanitize(v.summary)}`;
      const fix = v.fixed ? ` (fix: ${sanitize(v.fixed)})` : '';
      out(`::${level} title=${sanitize(v.displayId)}::${msg}${fix}`);
    }

    if (filtered.length === 0 && warnings.length === 0) {
      out('::notice::All dependencies passed security scan');
    }

    if (warnings.length > 0) {
      for (const w of warnings) {
        out(`::warning title=Scan Incomplete::${sanitize(w)}`);
      }
    }

    // Summary annotation
    const total = allDeps.length;
    const vulnCount = filtered.length;
    out(`::notice::Scanned ${total} packages, found ${vulnCount} vulnerabilities at ${minSeverity}+ severity`);
  }

  // Exit code
  if (!complete) return EXIT.ERROR; // Incomplete scan
  return filtered.length > 0 ? EXIT.VULNS_FOUND : EXIT.OK;
}

/**
 * Watch mode — continuous monitoring.
 */
async function runWatch(flags) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const intervalMin = parseInt(flags.interval, 10) || 60;
  const intervalMs = Math.max(intervalMin * 60 * 1000, MIN_POLL_INTERVAL_MS);

  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  out(`\n  ${C.bold}vexes monitor${C.reset} v${VERSION} ${C.dim}— watching ${targetDir}${C.reset}`);
  out(`  ${C.dim}OSV poll interval: ${intervalMin} minute(s)${C.reset}`);
  out(`  ${C.dim}Press Ctrl+C to stop${C.reset}\n`);

  // Initial scan
  const initialParse = parseAllEcosystems(targetDir, config.ecosystems);
  let currentDeps = initialParse.deps;
  let currentSnapshot = toSnapshot(currentDeps);
  out(`  ${C.dim}Baseline: ${currentDeps.length} packages${C.reset}`);
  for (const w of initialParse.warnings) {
    out(`  ${C.yellow}! ${sanitize(w)}${C.reset}`);
  }

  await runPollCycle(currentDeps, config);

  // Watch lockfiles for changes
  const lockfilePaths = findDependencyFiles(targetDir, config.ecosystems);
  const watchers = [];

  for (const lf of lockfilePaths) {
    try {
      const watcher = watch(lf, { persistent: true }, async (eventType) => {
        if (eventType !== 'change') return;
        out(`\n  ${C.cyan}\u26a1 Dependency file changed: ${basename(lf)}${C.reset}`);

        try {
          const nextParse = parseAllEcosystems(targetDir, config.ecosystems);
          if (nextParse.parseFailures > 0) {
            for (const w of nextParse.warnings) {
              out(`  ${C.yellow}! ${sanitize(w)}${C.reset}`);
            }
            out(`  ${C.yellow}! Lockfile parsing incomplete — keeping previous baseline until parsing succeeds${C.reset}`);
            return;
          }

          const newDeps = nextParse.deps;
          const newSnapshot = toSnapshot(newDeps);
          const diff = diffSnapshots(currentSnapshot, newSnapshot);

          if (diff.hasChanges) {
            out(`  ${C.dim}Changes: ${diff.summary}${C.reset}`);

            if (diff.added.length > 0) {
              out(`  ${C.bold}New packages:${C.reset}`);
              for (const d of diff.added) out(`    ${C.cyan}+ ${sanitize(d.name)}@${sanitize(d.version)}${C.reset}`);
            }
            if (diff.removed.length > 0) {
              for (const d of diff.removed) out(`    ${C.dim}- ${sanitize(d.name)}@${sanitize(d.version)}${C.reset}`);
            }

            // Scan new/changed packages
            const toCheck = [...diff.added, ...diff.changed.map(c => ({ name: c.name, version: c.toVersion, ecosystem: c.ecosystem }))];
            if (toCheck.length > 0) {
              const osvResult = await queryBatch(toCheck);
              const vulns = [];
              for (const [, v] of osvResult.results) vulns.push(...v);
              const complete = isQueryComplete(osvResult, toCheck.length);

              if (!complete) {
                for (const failure of osvResult.failures) {
                  out(`  ${C.yellow}! ${sanitize(failure)}${C.reset}`);
                }
                out(`  ${C.yellow}! OSV lookup incomplete — keeping previous baseline until changed packages are fully checked${C.reset}`);
                return;
              }

              if (vulns.length > 0) {
                out(`\n  ${C.red}${C.bold}\u26a0 ${vulns.length} vulnerability(ies) in new/changed packages:${C.reset}`);
                for (const v of vulns) {
                  out(`    ${C.red}${sanitize(v.package)}@${sanitize(v.version)}${C.reset}: ${sanitize(v.summary)}`);
                }
              } else {
                out(`  ${C.green}\u2713 New/changed packages are clean${C.reset}`);
              }
            }

            currentDeps = newDeps;
            currentSnapshot = newSnapshot;
          }
        } catch (err) {
          log.error(`lockfile change handler error: ${err.message}`);
        }
      });
      watchers.push(watcher);
      log.debug(`watching ${lf}`);
    } catch (err) {
      log.warn(`could not watch ${lf}: ${err.message}`);
    }
  }

  // Periodic OSV poll
  const pollInterval = setInterval(async () => {
    out(`\n  ${C.dim}[${new Date().toISOString().slice(11, 19)}] Polling OSV for ${currentDeps.length} packages...${C.reset}`);
    await runPollCycle(currentDeps, config);
  }, intervalMs);

  // Freshness poll — detects suspicious NEW releases before any CVE exists.
  // Polls the registry (visible within minutes of publish), not OSV (which
  // lags whole attack windows). Alerts only fire on NEW versions with
  // attacker-shaped deltas.
  let freshnessInterval = null;
  const freshnessMin = flags.freshness ? parseInt(flags.freshness, 10) : 0;
  if (freshnessMin > 0) {
    const freshnessMs = Math.max(freshnessMin * 60 * 1000, MIN_POLL_INTERVAL_MS);
    out(`  ${C.cyan}Freshness enabled: polling registry every ${freshnessMin} min for new releases${C.reset}`);
    freshnessInterval = setInterval(async () => {
      out(`\n  ${C.dim}[${new Date().toISOString().slice(11, 19)}] Freshness poll: checking ${currentDeps.length} packages for new releases...${C.reset}`);
      await runFreshnessCycle(currentDeps, config);
    }, freshnessMs);
    // Kick it off immediately too — the initial baseline is minutes of lead
    // time the attacker may have already burned.
    setTimeout(() => runFreshnessCycle(currentDeps, config), 1500);
  }

  // Keep process alive until Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(pollInterval);
    if (freshnessInterval) clearInterval(freshnessInterval);
    for (const w of watchers) w.close();
    out(`\n  ${C.dim}Monitor stopped.${C.reset}\n`);
    process.exit(EXIT.OK);
  });

  // Block forever (watchers + interval keep us alive)
  await new Promise(() => {});
}

/**
 * Run a single OSV poll cycle and print results.
 */
export async function runPollCycle(deps, config) {
  try {
    const result = await queryBatch(deps);
    const allVulns = [];
    for (const [, vulns] of result.results) allVulns.push(...vulns);

    const minSev = (config.severity || 'moderate').toUpperCase();
    const filtered = filterBySeverity(allVulns, minSev);
    const complete = isQueryComplete(result, deps.length);

    if (filtered.length > 0) {
      out(`  ${C.red}${filtered.length} vulnerability(ies) found:${C.reset}`);
      for (const v of filtered.slice(0, 10)) {
        out(`    ${C.red}${sanitize(v.package)}@${sanitize(v.version)}${C.reset}: ${sanitize(v.summary || v.id)}`);
      }
      if (filtered.length > 10) out(`    ${C.dim}... and ${filtered.length - 10} more${C.reset}`);
    } else if (complete) {
      out(`  ${C.green}\u2713 All ${deps.length} packages clean${C.reset}`);
    }

    if (!complete) {
      out(`  ${C.yellow}! OSV results incomplete — not all packages were checked${C.reset}`);
    }
    if (result.failures.length > 0) {
      out(`  ${C.yellow}! ${result.failures.length} query failure(s) — results may be incomplete${C.reset}`);
    }
    return { complete, vulnerabilities: filtered, warnings: result.failures };
  } catch (err) {
    log.error(`poll cycle failed: ${err.message}`);
    return { complete: false, vulnerabilities: [], warnings: [err.message] };
  }
}

/**
 * Run a single freshness cycle — checks the tracked package set for new
 * releases with attacker-shaped deltas and emits alerts. Emits the same
 * shared envelope as everything else when --json is active so agents can
 * consume the alerts directly.
 */
export async function runFreshnessCycle(deps, config) {
  const events = await checkFreshness(deps);
  const alerts = events.filter(e => e.isNew);
  if (alerts.length === 0) return;

  const isJSON = config.output?.format === 'json';
  if (isJSON) {
    out(JSON.stringify(buildEnvelope({
      command: 'monitor',
      target: { dir: config.targetPath || '.', lockfiles: [], ecosystems: [...config.ecosystems] },
      complete: true,
      warnings: [],
      summary: { total: deps.length, vulnerable: 0, fresh: alerts.filter(a => a.isNew).length },
      findings: [],
      extra: { mode: 'freshness', version: VERSION, alerts },
    }), null, 2));
    return;
  }

  out(`\n  ${C.red}${C.bold}⚠ Fresh release(s) detected:${C.reset}`);
  for (const a of alerts) {
    const tag = a.level === 'high' ? C.red : C.yellow;
    out(`  ${tag}${C.bold}${sanitize(a.name)}${C.reset} ${C.dim}${sanitize(a.installed)} → ${sanitize(a.latest)}${C.reset}`);
    for (const reason of a.reasons) out(`    ${tag}▸ ${sanitize(reason)}${C.reset}`);
  }
  out('');
}

/**
 * Parse all ecosystems in a directory (shared by CI and watch).
 */
export function parseAllEcosystems(dir, ecosystems) {
  const deps = [];
  const warnings = [];
  let parseFailures = 0;
  let filesFound = 0;

  for (const eco of ecosystems) {
    if (eco === 'npm') {
      // npm lockfile + pnpm + yarn (all npm ecosystem)
      for (const [discFn, parseFn] of [[discoverNpm, parseNpmLock], [discoverPnpm, parsePnpmLock], [discoverYarn, parseYarnLock]]) {
        const { lockfiles } = discFn(dir);
        filesFound += lockfiles.length;
        for (const lf of lockfiles) {
          try { deps.push(...parseFn(lf)); }
          catch (err) { const msg = `failed to parse ${basename(lf)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
        }
      }
    }
    if (eco === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(dir);
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      filesFound += files.length;
      for (const f of files) {
        try { deps.push(...parsePypiFile(f.path, f.format)); }
        catch (err) { const msg = `failed to parse ${basename(f.path)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
      }
    }
    if (eco === 'cargo') {
      const { lockfiles } = discoverCargo(dir);
      filesFound += lockfiles.length;
      for (const lf of lockfiles) {
        try { deps.push(...parseCargoLock(lf)); }
        catch (err) { const msg = `failed to parse ${basename(lf)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
      }
    }
    if (GENERIC_ECOSYSTEM_PARSERS[eco]) {
      const { files, usingManifestFallback } = selectGenericFiles(dir, eco);
      if (usingManifestFallback) {
        warnings.push(`no lockfile found — scanning ${files.map(file => basename(file.path)).join(', ')} (best-effort manifest fallback, lower confidence)`);
      }
      filesFound += files.length;
      for (const file of files) {
        try { deps.push(...parseGenericFile(eco, file)); }
        catch (err) { const msg = `failed to parse ${basename(file.path)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
      }
    }
  }

  // Deduplicate
  const seen = new Set();
  const deduped = deps.filter(d => {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    deps: deduped,
    warnings,
    parseFailures,
    filesFound,
  };
}

/**
 * Find dependency files to watch.
 */
function findDependencyFiles(dir, ecosystems) {
  const paths = new Set();

  const addPaths = (entries) => {
    for (const entry of entries) paths.add(entry);
  };

  for (const eco of ecosystems) {
    if (eco === 'npm') {
      const { lockfiles, manifests } = discoverNpm(dir);
      const { lockfiles: pnpmLocks } = discoverPnpm(dir);
      const { lockfiles: yarnLocks } = discoverYarn(dir);
      const npmFiles = [...lockfiles, ...pnpmLocks, ...yarnLocks];
      addPaths(npmFiles.length > 0 ? npmFiles : manifests);
      continue;
    }

    if (eco === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(dir);
      const files = lockfiles.length > 0 ? lockfiles.map(file => file.path) : manifests.map(file => file.path);
      addPaths(files);
      continue;
    }

    if (eco === 'cargo') {
      addPaths(discoverCargo(dir).lockfiles);
      continue;
    }

    if (GENERIC_ECOSYSTEM_PARSERS[eco]) {
      addPaths(selectGenericFiles(dir, eco).files.map(file => file.path));
    }
  }
  return [...paths].filter(path => existsSync(path));
}

// SARIF generation lives in src/cli/sarif.js (toSarif) — the single source of
// truth shared by `scan` and `monitor --ci`.
