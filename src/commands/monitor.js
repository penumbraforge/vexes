import { resolve, basename } from 'node:path';
import { statSync, existsSync, readFileSync, watch } from 'node:fs';
import { loadConfig } from '../cli/config.js';
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
    --freshness <min>    Registry poll interval — assesses newly observed
                         releases (default: off). Combine with
                         --interval to run both registry and OSV polling.

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
    const complete = parseResult.parseFailures === 0 && parseResult.unresolvedManifestInputs === 0;
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
  const complete = parseResult.parseFailures === 0 && parseResult.unresolvedManifestInputs === 0 &&
    isQueryComplete(osvResult, allDeps.length);

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
      out('::notice::Requested checks completed; no vulnerabilities found at the active threshold');
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
  let dependencyInputComplete = initialParse.parseFailures === 0 && initialParse.unresolvedManifestInputs === 0;
  out(`  ${C.dim}Baseline: ${currentDeps.length} packages${C.reset}`);
  for (const w of initialParse.warnings) {
    out(`  ${C.yellow}! ${sanitize(w)}${C.reset}`);
  }

  if (dependencyInputComplete) {
    await runPollCycle(currentDeps, config);
  } else {
    out(`  ${C.yellow}! Dependency input incomplete — OSV polling is paused until exact resolved versions are available${C.reset}`);
  }

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
          if (nextParse.parseFailures > 0 || nextParse.unresolvedManifestInputs > 0) {
            dependencyInputComplete = false;
            for (const w of nextParse.warnings) {
              out(`  ${C.yellow}! ${sanitize(w)}${C.reset}`);
            }
            out(`  ${C.yellow}! Lockfile parsing incomplete — keeping previous baseline until parsing succeeds${C.reset}`);
            return;
          }

          dependencyInputComplete = true;

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
                out(`  ${C.green}\u2713 OSV returned no findings for the new/changed packages at the active threshold${C.reset}`);
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
    if (!dependencyInputComplete) {
      out(`\n  ${C.yellow}! OSV poll skipped — dependency input is incomplete${C.reset}`);
      return;
    }
    out(`\n  ${C.dim}[${new Date().toISOString().slice(11, 19)}] Polling OSV for ${currentDeps.length} packages...${C.reset}`);
    await runPollCycle(currentDeps, config);
  }, intervalMs);

  // Freshness poll — detects suspicious NEW releases before any CVE exists.
  // Polls the registry separately from OSV. Alerts only fire on versions first
  // observed after the persisted baseline and with attacker-shaped deltas.
  let freshnessInterval = null;
  let freshnessCache = null;
  let freshnessRunning = false;
  const freshnessMin = flags.freshness ? parseInt(flags.freshness, 10) : 0;
  if (freshnessMin > 0) {
    const freshnessMs = Math.max(freshnessMin * 60 * 1000, MIN_POLL_INTERVAL_MS);
    try { freshnessCache = new AdvisoryCache(config.cache?.dir); }
    catch (err) {
      freshnessCache = new NoOpCache();
      out(`  ${C.yellow}! Freshness disabled: persistent release state is unavailable (${sanitize(err.message)})${C.reset}`);
    }
    const tickFreshness = async () => {
      if (!dependencyInputComplete || freshnessRunning || freshnessCache instanceof NoOpCache) return;
      freshnessRunning = true;
      out(`\n  ${C.dim}[${new Date().toISOString().slice(11, 19)}] Freshness poll: checking ${currentDeps.length} packages for new releases...${C.reset}`);
      try { await runFreshnessCycle(currentDeps, config, { cache: freshnessCache }); }
      finally { freshnessRunning = false; }
    };
    if (!(freshnessCache instanceof NoOpCache)) {
      out(`  ${C.cyan}Freshness enabled: polling npm/PyPI every ${freshnessMin} min; first poll establishes a baseline${C.reset}`);
      freshnessInterval = setInterval(tickFreshness, freshnessMs);
      setTimeout(tickFreshness, 1500);
    }
  }

  // Keep process alive until Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(pollInterval);
    if (freshnessInterval) clearInterval(freshnessInterval);
    freshnessCache?.close?.();
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
      out(`  ${C.green}\u2713 OSV returned no findings for ${deps.length} packages at the active threshold${C.reset}`);
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
export async function runFreshnessCycle(deps, config, opts = {}) {
  const result = await checkFreshness(deps, opts);
  const alerts = result.alerts;
  if (alerts.length === 0 && result.complete) return result;

  const isJSON = config.output?.format === 'json';
  if (isJSON) {
    out(JSON.stringify(buildEnvelope({
      command: 'monitor',
      target: { dir: config.targetPath || '.', lockfiles: [], ecosystems: [...config.ecosystems] },
      complete: result.complete,
      warnings: result.warnings,
      summary: { total: deps.length, vulnerable: 0, fresh: alerts.length, checked: result.checked, skipped: result.skipped },
      findings: [],
      extra: { mode: 'freshness', version: VERSION, alerts },
    }), null, 2));
    return result;
  }

  if (alerts.length > 0) {
    out(`\n  ${C.red}${C.bold}⚠ Newly observed release signal(s):${C.reset}`);
    for (const a of alerts) {
      const tag = a.level === 'high' ? C.red : C.yellow;
      out(`  ${tag}${C.bold}${sanitize(a.name)}${C.reset} ${C.dim}${sanitize(a.lastSeenVersion)} → ${sanitize(a.latest)}${C.reset}`);
      for (const reason of a.reasons) out(`    ${tag}▸ ${sanitize(reason)}${C.reset}`);
    }
  }
  for (const warning of result.warnings) {
    out(`  ${C.yellow}! Freshness incomplete: ${sanitize(warning)}${C.reset}`);
  }
  out('');
  return result;
}

/**
 * Parse all ecosystems in a directory (shared by CI and watch).
 */
export function parseAllEcosystems(dir, ecosystems) {
  const deps = [];
  const warnings = [];
  let parseFailures = 0;
  let filesFound = 0;
  let unresolvedManifestInputs = 0;

  for (const eco of ecosystems) {
    if (eco === 'npm') {
      // npm lockfile + pnpm + yarn (all npm ecosystem)
      let npmLockfileCount = 0;
      for (const [discFn, parseFn] of [[discoverNpm, parseNpmLock], [discoverPnpm, parsePnpmLock], [discoverYarn, parseYarnLock]]) {
        const { lockfiles } = discFn(dir);
        npmLockfileCount += lockfiles.length;
        filesFound += lockfiles.length;
        for (const lf of lockfiles) {
          try {
            const parsed = parseFn(lf);
            if (parsed.unresolvedEntries > 0) {
              unresolvedManifestInputs++;
              warnings.push(`${basename(lf)} contains ${parsed.unresolvedEntries} local, linked, remote, or unanchored npm entr${parsed.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
            }
            deps.push(...parsed);
          }
          catch (err) { const msg = `failed to parse ${basename(lf)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
        }
      }
      if (npmLockfileCount === 0) {
        const { manifests } = discoverNpm(dir);
        filesFound += manifests.length;
        if (manifests.length > 0) {
          unresolvedManifestInputs++;
          warnings.push('no npm lockfile found — exact package.json pins can be checked, but resolved/transitive coverage is incomplete');
        }
        for (const mf of manifests) {
          try {
            const parsed = parseNpmManifest(mf);
            deps.push(...parsed);
            if (hasUnresolvedManifestEntries(mf, 'npm', 'package.json', parsed.length)) {
              unresolvedManifestInputs++;
              warnings.push(`${basename(mf)} contains dependencies without exact registry versions — add a lockfile or exact pins; those entries were not scanned`);
            }
          } catch (err) {
            const msg = `failed to parse ${basename(mf)}: ${err.message}`;
            warnings.push(msg);
            parseFailures++;
            log.warn(msg);
          }
        }
      }
    }
    if (eco === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(dir);
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      filesFound += files.length;
      if (lockfiles.length === 0 && manifests.length > 0) {
        unresolvedManifestInputs++;
        warnings.push('no PyPI lockfile found — exact manifest pins can be checked, but resolved/transitive coverage is incomplete');
      }
      for (const f of files) {
        try {
          const parsed = parsePypiFile(f.path, f.format);
          deps.push(...parsed);
          if (hasUnresolvedManifestEntries(f.path, 'pypi', f.format, parsed)) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(f.path)} contains dependencies without exact public-PyPI identities — those entries were not scanned`);
            for (const failure of parsed.includeFailures || []) warnings.push(`${basename(f.path)}: ${failure}`);
          }
        }
        catch (err) { const msg = `failed to parse ${basename(f.path)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
      }
    }
    if (eco === 'cargo') {
      const { lockfiles } = discoverCargo(dir);
      filesFound += lockfiles.length;
      for (const lf of lockfiles) {
        try {
          const parsed = parseCargoLock(lf);
          if (parsed.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(lf)} contains ${parsed.unresolvedEntries} non-crates.io or unanchored entr${parsed.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          deps.push(...parsed);
        }
        catch (err) { const msg = `failed to parse ${basename(lf)}: ${err.message}`; warnings.push(msg); parseFailures++; log.warn(msg); }
      }
    }
    if (GENERIC_ECOSYSTEM_PARSERS[eco]) {
      const { files, usingManifestFallback } = selectGenericFiles(dir, eco);
      if (usingManifestFallback) {
        warnings.push(`no lockfile found — scanning exact pins from ${files.map(file => basename(file.path)).join(', ')}; manifest fallback is not a resolved dependency graph, so coverage is incomplete`);
        unresolvedManifestInputs++;
      }
      filesFound += files.length;
      for (const file of files) {
        try {
          const parsed = parseGenericFile(eco, file);
          if (parsed.unresolvedEntries > 0) {
            unresolvedManifestInputs++;
            warnings.push(`${basename(file.path)} contains ${parsed.unresolvedEntries} replaced or otherwise unanchored module entr${parsed.unresolvedEntries === 1 ? 'y' : 'ies'} — those entries were not scanned`);
          }
          deps.push(...parsed);
        }
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
    unresolvedManifestInputs,
  };
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
