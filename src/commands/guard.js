import { resolve, join } from 'node:path';
import { statSync, existsSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { loadConfig } from '../cli/config.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT } from '../core/constants.js';
import { parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { diffSnapshots, toSnapshot } from '../analysis/diff.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { analyzePackage } from '../analysis/signals.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';

/**
 * `vexes guard` — Pre-install protection.
 *
 * Unlike proxy-based tools (Socket Firewall), this works by diffing lockfiles:
 * 1. Snapshot the current lockfile
 * 2. Run `npm install --package-lock-only --ignore-scripts` (dry-run: updates lockfile without executing)
 * 3. Diff the lockfile to find new/changed packages
 * 4. Run analyze on those packages
 * 5. Block or prompt if dangerous signals found
 * 6. If approved, run the real install
 *
 * This approach works even with cached packages (no network interception needed).
 */
export async function runGuard(flags, args) {
  // Subcommands
  if (flags.setup) return runSetup(flags);
  if (flags.uninstall) return runUninstall(flags);

  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const forceInstall = !!flags.force;

  // Validate directory
  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  // Parse and validate the install command
  // Guard only allows known package managers to prevent command injection.
  // Input comes from: vexes guard -- npm install <package>
  const ALLOWED_MANAGERS = new Set(['npm', 'npx', 'yarn', 'pnpm']);
  const installArgs = args.length > 0 ? [...args] : null;
  const manager = installArgs?.[0];

  if (manager && !ALLOWED_MANAGERS.has(manager)) {
    log.error(`guard only works with known package managers (${[...ALLOWED_MANAGERS].join(', ')}), got "${manager}"`);
    return EXIT.ERROR;
  }

  const lockfilePath = join(targetDir, 'package-lock.json');

  if (!existsSync(lockfilePath)) {
    if (!isJSON) out(`  ${C.yellow}No package-lock.json found — guard requires a lockfile to diff against${C.reset}`);
    return EXIT.ERROR;
  }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes guard${C.reset} v${VERSION} ${C.dim}— pre-install protection${C.reset}\n`);
  }

  // 1. Snapshot current lockfile
  const spinner = isJSON ? null : createSpinner('Snapshotting current dependencies...');
  let beforeDeps;
  try {
    beforeDeps = parseNpmLock(lockfilePath);
  } catch (err) {
    spinner?.stop(`Failed to parse lockfile: ${err.message}`);
    return EXIT.ERROR;
  }
  const beforeSnapshot = toSnapshot(beforeDeps);
  spinner?.stop(`Snapshot: ${beforeDeps.length} packages`);

  // 2. Dry-run install: update lockfile only, no scripts
  if (!installArgs) {
    if (!isJSON) {
      out(`\n  ${C.bold}Usage:${C.reset} vexes guard -- npm install <package>`);
      out(`  ${C.dim}Or: vexes guard --setup to install shell wrappers${C.reset}\n`);
    }
    return EXIT.OK;
  }

  const installDisplay = installArgs.join(' ');
  const dryRunSpinner = isJSON ? null : createSpinner(`Dry-running: ${installDisplay} --package-lock-only --ignore-scripts`);

  // Backup the lockfile
  const lockfileBackup = readFileSync(lockfilePath, 'utf8');

  try {
    // Run the install in lockfile-only mode (no node_modules changes, no scripts)
    // Uses execFileSync (no shell) to prevent command injection
    execFileSync(manager, [...installArgs.slice(1), '--package-lock-only', '--ignore-scripts'], {
      cwd: targetDir,
      stdio: 'pipe',
      timeout: 120_000,
    });
  } catch (err) {
    dryRunSpinner?.stop('Dry-run failed');
    // Restore lockfile
    writeFileSync(lockfilePath, lockfileBackup);
    log.error(`dry-run install failed: ${err.message}`);
    return EXIT.ERROR;
  }

  // 3. Parse the updated lockfile and diff
  let afterDeps;
  try {
    afterDeps = parseNpmLock(lockfilePath);
  } catch (err) {
    dryRunSpinner?.stop('Failed to parse updated lockfile');
    writeFileSync(lockfilePath, lockfileBackup);
    return EXIT.ERROR;
  }

  const afterSnapshot = toSnapshot(afterDeps);
  const diff = diffSnapshots(beforeSnapshot, afterSnapshot);
  dryRunSpinner?.stop(`Diff: ${diff.summary}`);

  if (!diff.hasChanges) {
    // Restore original lockfile (dry-run may have reformatted it)
    writeFileSync(lockfilePath, lockfileBackup);
    if (!isJSON) out(`\n  ${C.green}\u2713 No dependency changes — install is safe${C.reset}\n`);
    return EXIT.OK;
  }

  // 4. Analyze new and changed packages
  const packagesToAnalyze = [
    ...diff.added,
    ...diff.changed.map(c => ({ name: c.name, version: c.toVersion, ecosystem: c.ecosystem })),
  ];

  if (!isJSON) {
    out(`\n  ${C.dim}Analyzing ${packagesToAnalyze.length} new/changed packages...${C.reset}`);
  }

  // Restore lockfile before analysis (we have the diff, don't need the modified file)
  writeFileSync(lockfilePath, lockfileBackup);

  let cache;
  try { cache = new AdvisoryCache(config.cache?.dir); }
  catch { cache = new NoOpCache(); }

  try {
    // OSV scan
    const analyzeSpinner = isJSON ? null : createSpinner('Checking for known vulnerabilities...');
    const osvData = await queryBatch(packagesToAnalyze);
    analyzeSpinner?.stop('Vulnerability check complete');

    // Deep analysis on each new/changed package
    const signalSpinner = isJSON ? null : createSpinner('Running behavioral analysis...');
    const results = [];

    for (const dep of packagesToAnalyze) {
      try {
        const metadata = await fetchNpmMetadata(dep.name);
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        const osvResult = osvData.results.get(key) || null;
        const analysis = await analyzePackage(metadata, osvResult, { ecosystem: dep.ecosystem, config });

        results.push({
          name: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          isNew: diff.added.some(a => a.name === dep.name),
          signals: analysis.signals,
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
        });
      } catch (err) {
        log.debug(`analysis failed for ${dep.name}: ${err.message}`);
        results.push({
          name: dep.name, version: dep.version, ecosystem: dep.ecosystem,
          isNew: true, signals: [], riskScore: 0, riskLevel: 'UNKNOWN',
        });
      }
    }

    signalSpinner?.stop(`${results.length} packages analyzed`);

    // 5. Decision: block, warn, or allow
    const decision = evaluateGuardResults(results, osvData, packagesToAnalyze.length);
    const { critical, high, hasKnownVulns, unknown, analysisIncomplete, incompleteReasons } = decision;

    if (isJSON) {
      const blocked = critical.length > 0 || hasKnownVulns || analysisIncomplete;
      out(JSON.stringify({
        version: VERSION, command: 'guard',
        installCommand: installDisplay,
        diff: { added: diff.added.length, changed: diff.changed.length, removed: diff.removed.length },
        blocked,
        incomplete: analysisIncomplete,
        warnings: [...osvData.failures, ...incompleteReasons],
        results,
      }, null, 2));

      if (!blocked) return EXIT.OK;
      return analysisIncomplete && critical.length === 0 && !hasKnownVulns ? EXIT.ERROR : EXIT.VULNS_FOUND;
    }

    // Terminal output
    if (critical.length === 0 && high.length === 0 && !hasKnownVulns && unknown.length === 0) {
      // All clear
      out(`\n  ${C.green}\u2713 All ${packagesToAnalyze.length} new/changed packages look safe${C.reset}`);
      out(`  ${C.dim}Proceeding with install...${C.reset}\n`);
      // Run the real install
      return executeRealInstall(manager, installArgs, targetDir);
    }

    // Show findings
    out(header('Guard Report'));

    if (diff.added.length > 0) {
      out(`  ${C.bold}New packages:${C.reset} ${diff.added.map(d => sanitize(d.name)).join(', ')}`);
    }
    if (diff.changed.length > 0) {
      out(`  ${C.bold}Changed:${C.reset} ${diff.changed.map(c => `${sanitize(c.name)} ${c.fromVersion} \u2192 ${c.toVersion}`).join(', ')}`);
    }
    out('');

    for (const r of [...critical, ...high]) {
      const color = r.riskLevel === 'CRITICAL' ? C.red : C.yellow;
      out(`  ${color}\u25cf ${r.riskLevel}${C.reset} ${C.bold}${sanitize(r.name)}${C.reset} ${C.dim}${sanitize(r.version)}${C.reset}`);
      for (const s of r.signals) {
        out(`    ${C.dim}${s.signal}: ${sanitize(s.description)}${C.reset}`);
      }
      out('');
    }

    if (unknown.length > 0) {
      out(`  ${C.yellow}! ${unknown.length} package(s) could not be fully analyzed${C.reset}\n`);
    }
    if (!decision.osvComplete) {
      for (const reason of incompleteReasons.filter(r => r.startsWith('OSV'))) {
        out(`  ${C.yellow}! ${sanitize(reason)}${C.reset}`);
      }
      out('');
    }

    if (critical.length > 0 || hasKnownVulns) {
      out(`  ${C.red}${C.bold}\u2717 BLOCKED${C.reset}${C.red} — ${critical.length} critical risk package(s) detected.${C.reset}`);
      out(`  ${C.dim}The install was not executed. Review the findings above.${C.reset}`);
      out(`  ${C.dim}To override: run the install command directly (at your own risk).${C.reset}\n`);
      return EXIT.VULNS_FOUND;
    }

    if (analysisIncomplete) {
      out(`  ${C.yellow}${C.bold}! INCOMPLETE${C.reset}${C.yellow} — vexes could not fully verify this install.${C.reset}`);
      for (const reason of incompleteReasons) {
        out(`    ${C.dim}${sanitize(reason)}${C.reset}`);
      }

      if (forceInstall) {
        out(`\n  ${C.yellow}--force used — proceeding despite incomplete analysis.${C.reset}\n`);
        return executeRealInstall(manager, installArgs, targetDir);
      }

      out(`\n  ${C.dim}Install blocked until analysis completes successfully. Use --force to override.${C.reset}\n`);
      return EXIT.ERROR;
    }

    if (high.length > 0) {
      out(`  ${C.yellow}${C.bold}! WARNING${C.reset}${C.yellow} — ${high.length} high-risk package(s) detected.${C.reset}`);

      if (forceInstall) {
        out(`  ${C.yellow}--force used — proceeding despite warnings.${C.reset}\n`);
        return executeRealInstall(manager, installArgs, targetDir);
      }

      // Check if we have a TTY for interactive prompt
      if (process.stdin.isTTY) {
        out(`  ${C.dim}Proceed with install? [y/N]${C.reset}`);
        const answer = await prompt();
        if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
          return executeRealInstall(manager, installArgs, targetDir);
        }
        out(`  ${C.dim}Install cancelled.${C.reset}\n`);
        return EXIT.VULNS_FOUND;
      } else {
        // Non-TTY (CI): block by default
        out(`  ${C.dim}Non-interactive mode — blocking install. Use --force to override.${C.reset}\n`);
        return EXIT.VULNS_FOUND;
      }
    }

    // Only unknown results — warn but allow
    out(`  ${C.yellow}! Some packages could not be fully analyzed — proceeding with caution.${C.reset}\n`);
    return executeRealInstall(manager, installArgs, targetDir);

  } finally {
    cache.close();
  }
}

export function evaluateGuardResults(results, osvData, expectedChecks) {
  const critical = results.filter(r => r.riskLevel === 'CRITICAL');
  const high = results.filter(r => r.riskLevel === 'HIGH');
  const hasKnownVulns = results.some(r => r.signals.some(s => s.signal === 'KNOWN_COMPROMISED'));
  const unknown = results.filter(r => r.riskLevel === 'UNKNOWN');
  const osvComplete = isQueryComplete(osvData, expectedChecks);
  const incompleteReasons = [];

  if (!osvComplete) {
    const missed = osvData?.failedCount ?? 0;
    const detail = missed > 0
      ? `${missed} package(s) were not checked`
      : 'one or more lookup errors occurred';
    incompleteReasons.push(`OSV vulnerability lookup incomplete — ${detail}`);
  }
  if (unknown.length > 0) {
    incompleteReasons.push(`${unknown.length} package(s) could not be fully analyzed`);
  }

  return {
    critical,
    high,
    hasKnownVulns,
    unknown,
    osvComplete,
    analysisIncomplete: incompleteReasons.length > 0,
    incompleteReasons,
  };
}

/**
 * Execute the real install command after guard approval.
 * Uses execFileSync (no shell) to prevent command injection.
 */
function executeRealInstall(manager, installArgs, targetDir) {
  const display = installArgs.join(' ');
  out(`  ${C.dim}Running: ${display}${C.reset}\n`);
  try {
    execFileSync(manager, installArgs.slice(1), {
      cwd: targetDir,
      stdio: 'inherit',
      timeout: 300_000,
    });
    out(`\n  ${C.green}\u2713 Install complete${C.reset}\n`);
    return EXIT.OK;
  } catch (err) {
    log.error(`install failed: ${err.message}`);
    return EXIT.ERROR;
  }
}

/**
 * Simple stdin prompt for TTY confirmation.
 */
function prompt() {
  return new Promise((resolve) => {
    process.stdin.setEncoding('utf8');
    process.stdin.once('data', (data) => {
      resolve(data.trim());
    });
    process.stdin.resume();
  });
}

/**
 * Install shell wrappers that intercept npm/pip install.
 */
function runSetup(flags) {
  const shell = flags.shell || detectShell();
  const rcFile = shell === 'zsh' ? join(homedir(), '.zshrc')
               : shell === 'fish' ? join(homedir(), '.config', 'fish', 'config.fish')
               : join(homedir(), '.bashrc');

  const marker = '# --- vexes guard start ---';
  const endMarker = '# --- vexes guard end ---';

  // Check if already installed
  if (existsSync(rcFile)) {
    const content = readFileSync(rcFile, 'utf8');
    if (content.includes(marker)) {
      out(`  ${C.yellow}Guard is already installed in ${rcFile}${C.reset}`);
      out(`  ${C.dim}Run vexes guard --uninstall to remove.${C.reset}\n`);
      return EXIT.OK;
    }
  }

  const wrapperCode = shell === 'fish' ? buildFishWrapper() : buildBashWrapper();
  const block = `\n${marker}\n${wrapperCode}\n${endMarker}\n`;

  try {
    appendFileSync(rcFile, block);
    out(`\n  ${C.green}\u2713 Guard installed in ${rcFile}${C.reset}`);
    out(`  ${C.dim}Restart your shell or run: source ${rcFile}${C.reset}`);
    out(`\n  When active, ${C.bold}npm install${C.reset} will automatically run ${C.bold}vexes guard${C.reset} first.\n`);
    return EXIT.OK;
  } catch (err) {
    log.error(`failed to write to ${rcFile}: ${err.message}`);
    return EXIT.ERROR;
  }
}

function runUninstall(flags) {
  const shell = flags.shell || detectShell();
  const rcFile = shell === 'zsh' ? join(homedir(), '.zshrc')
               : shell === 'fish' ? join(homedir(), '.config', 'fish', 'config.fish')
               : join(homedir(), '.bashrc');

  if (!existsSync(rcFile)) {
    out(`  ${C.dim}No ${rcFile} found — nothing to uninstall.${C.reset}`);
    return EXIT.OK;
  }

  const content = readFileSync(rcFile, 'utf8');
  const marker = '# --- vexes guard start ---';
  const endMarker = '# --- vexes guard end ---';

  const startIdx = content.indexOf(marker);
  const endIdx = content.indexOf(endMarker);

  if (startIdx === -1) {
    out(`  ${C.dim}Guard is not installed in ${rcFile}.${C.reset}`);
    return EXIT.OK;
  }

  const cleaned = content.slice(0, startIdx) + content.slice(endIdx + endMarker.length + 1);
  writeFileSync(rcFile, cleaned);
  out(`  ${C.green}\u2713 Guard removed from ${rcFile}${C.reset}\n`);
  return EXIT.OK;
}

function detectShell() {
  const shellEnv = process.env.SHELL || '';
  if (shellEnv.includes('zsh')) return 'zsh';
  if (shellEnv.includes('fish')) return 'fish';
  return 'bash';
}

function resolveVexesBinary() {
  // Resolve to the actual installed binary path at setup time — NOT npx at runtime.
  // npx fetches from the registry on every invocation, which means a compromised
  // registry account would let an attacker run arbitrary code on every npm install.
  try {
    const result = execFileSync('which', ['vexes'], { encoding: 'utf8', timeout: 5000 }).trim();
    if (result) return result;
  } catch { /* not in PATH */ }

  // Fall back to the path of the currently executing script
  const selfPath = process.argv[1];
  if (selfPath) return selfPath;

  // Last resort: use npx but warn the user
  log.warn('could not resolve vexes binary path — wrapper will use npx (less secure, fetches from registry on each run)');
  return 'npx @penumbraforge/vexes';
}

function buildBashWrapper() {
  const vexesBin = resolveVexesBinary();
  return `npm() {
  if [[ "$1" == "install" || "$1" == "i" || "$1" == "add" ]]; then
    command ${vexesBin} guard -- npm "$@"
  else
    command npm "$@"
  fi
}`;
}

function buildFishWrapper() {
  const vexesBin = resolveVexesBinary();
  return `function npm
  if test "$argv[1]" = "install" -o "$argv[1]" = "i" -o "$argv[1]" = "add"
    command ${vexesBin} guard -- npm $argv
  else
    command npm $argv
  end
end`;
}
