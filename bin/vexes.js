#!/usr/bin/env node

import { parseArgs } from '../src/cli/parse-args.js';
import { disableColor, C, out } from '../src/cli/output.js';
import { log } from '../src/core/logger.js';
import { VERSION, EXIT } from '../src/core/constants.js';

// Global error handlers — don't leak stack traces
process.on('uncaughtException', (err) => {
  log.error(err.message);
  process.exit(EXIT.ERROR);
});
process.on('unhandledRejection', (err) => {
  log.error(err?.message || String(err));
  process.exit(EXIT.ERROR);
});

const { command, flags, args } = parseArgs(process.argv.slice(2));

// Apply global flags
if (flags.color === false || flags['no-color']) disableColor();
if (flags.verbose && flags.quiet) {
  log.error('cannot use --verbose and --quiet together');
  process.exit(EXIT.ERROR);
}
if (flags.verbose) log.setLevel('debug');
if (flags.quiet) log.setLevel('error');

async function main() {
  // --help flag works in any context: `vexes scan --help` shows help
  if (flags.help) {
    printHelp();
    return EXIT.OK;
  }

  switch (command) {
    case 'version':
      out(`vexes v${VERSION}`);
      return EXIT.OK;

    case 'help':
      printHelp();
      return EXIT.OK;

    case 'scan': {
      const { runScan } = await import('../src/commands/scan.js');
      return await runScan(flags, args);
    }

    case 'analyze': {
      const { runAnalyze } = await import('../src/commands/analyze.js');
      return await runAnalyze(flags, args);
    }

    case 'fix': {
      const { runFix } = await import('../src/commands/fix.js');
      return await runFix(flags, args);
    }

    case 'guard': {
      const { runGuard } = await import('../src/commands/guard.js');
      return await runGuard(flags, args);
    }

    case 'monitor': {
      const { runMonitor } = await import('../src/commands/monitor.js');
      return await runMonitor(flags, args);
    }

    case 'inspect': {
      const { runInspect } = await import('../src/commands/inspect.js');
      return await runInspect(flags, args);
    }

    case 'doctor': {
      const { runDoctor } = await import('../src/commands/doctor.js');
      return await runDoctor(flags, args);
    }

    case 'licenses': {
      const { runLicenses } = await import('../src/commands/licenses.js');
      return await runLicenses(flags, args);
    }

    case 'explain':
    case 'triage': {
      const { runExplain } = await import('../src/commands/explain.js');
      return await runExplain(flags, args);
    }

    default:
      printHelp();
      return EXIT.OK;
  }
}

function printHelp() {
  out(`
  ${C.bold}vexes${C.reset} v${VERSION} — ${C.dim}shakes the tree to see what falls${C.reset}

  ${C.bold}USAGE${C.reset}
    vexes <command> [options]

  ${C.bold}COMMANDS${C.reset}
    scan       Scan dependencies for known vulnerabilities (OSV)
    analyze    Deep behavioral analysis of dependency supply chain
    fix        Verified fix recommendations with safe upgrade commands
    guard      Pre-install protection via lockfile diffing
    monitor    CI integration (GitHub Actions) + continuous watch
    explain    AI-assisted triage of findings ${C.dim}(opt-in: local or Anthropic provider)${C.reset}
    inspect    Assess a single package ${C.dim}(e.g. vexes inspect lodash@4.17.21)${C.reset}
    doctor     Self-test parsers, cache, and network
    licenses   Declared license bill of materials via deps.dev ${C.dim}(npm/pypi/cargo/go/nuget/java)${C.reset}
    help       Show this help
    version    Show version

  ${C.bold}SCAN OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --ecosystem <name>   Filter: npm, pypi, cargo, go, ruby, php, nuget, java
    --severity <level>   Minimum: critical, high, moderate, low ${C.dim}(default: moderate)${C.reset}
    --fix                Show fix commands for each vulnerability
    --min-reachability <bar>  Only report findings at/above this reachability
                          bar: reachable, lazy, dead ${C.dim}(default: dead = all)${C.reset}
    --ai                 Tier B: LLM exploitability verdict per finding
                          ${C.dim}(advisory; uses local provider, see --explain; never filters)${C.reset}
    --top <n>            Show only the first n findings in text output
    --cached             Use cached results without freshness check
    --json               Output JSON to stdout
    --format <fmt>       Output format: text, json, sarif ${C.dim}(default: text)${C.reset}
    --sarif [file]       SARIF 2.1.0 output ${C.dim}(to stdout, or to <file>)${C.reset}
    --verbose, -v        Show debug output
    --no-color           Disable ANSI colors

  ${C.bold}ANALYZE OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --ecosystem <name>   Filter: npm, pypi
    --deep               Download + AST-inspect actual package code (slower, thorough)
    --sandbox ${C.dim}(experimental, opt-in)${C.reset} Run CRITICAL/HIGH candidate
                          code in the OS sandbox and record dynamic behavior
                          evidence ${C.dim}(spawns, network, writes)${C.reset}
    --explain <package>  Detailed breakdown for a specific package
    --strict             Fail on any signal (for CI)
    --top <n>            Show only the n highest-risk packages
    --verbose, -v        Show all signals including LOW
    --json               Output JSON to stdout
    --no-color           Disable ANSI colors

  ${C.bold}FIX OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --json               Output JSON to stdout

  ${C.bold}GUARD OPTIONS${C.reset}
    vexes guard -- npm install <pkg>   Analyze before installing
    --setup              Install shell wrappers (auto-guard on npm install)
    --uninstall          Remove shell wrappers
    --force              Override HIGH-risk warnings (CRITICAL still blocked)

  ${C.bold}MONITOR OPTIONS${C.reset}
    --ci                 One-shot scan for CI (GitHub Actions annotations)
    --watch              Continuous monitoring (watches lockfiles + polls OSV)
    --severity <level>   CI fail threshold ${C.dim}(default: high)${C.reset}
    --interval <min>     Watch poll interval in minutes ${C.dim}(default: 60)${C.reset}
    --sarif              SARIF output for GitHub Advanced Security

  ${C.bold}INSPECT OPTIONS${C.reset} ${C.dim}(single-package on-demand assessment)${C.reset}
    vexes inspect lodash@4.17.21    Assess a package spec (defaults to latest)
    --ecosystem <name>   npm (default) or pypi
    --deep               Download + AST-inspect the package tarball
    --sandbox ${C.dim}(experimental, opt-in)${C.reset} Run the package in the OS
                          sandbox under a recorder shim; attach dynamic
                          behavior evidence ${C.dim}(spawns, network, writes)${C.reset}
    --json               Output JSON to stdout

  ${C.bold}DOCTOR OPTIONS${C.reset} ${C.dim}(self test)${C.reset}
    vexes doctor         Verify parsers, cache, and registry reachability
    --json               Machine-readable JSON output

  ${C.bold}EXPLAIN OPTIONS${C.reset} ${C.dim}(AI triage — opt-in, pluggable provider: VEXES_AI_BASE, or ANTHROPIC_BASE_URL+ANTHROPIC_AUTH_TOKEN, or ANTHROPIC_API_KEY)${C.reset}
    vexes scan --format json | vexes explain   Triage a piped scan
    --input <file>       Triage a saved scan JSON report
    --path <dir>         Or scan this dir first, then triage ${C.dim}(default: cwd)${C.reset}

  ${C.bold}CONFIG${C.reset}
    Project: .vexesrc.json in project root
    User:    ~/.config/vexes/config.json

  ${C.dim}Zero dependencies. github.com/penumbraforge/vexes${C.reset}
`);
}

const exitCode = await main();
await flushStdio();
process.exit(exitCode);

/**
 * Drain stdout/stderr before exiting.
 *
 * process.exit() discards buffered pipe writes larger than the OS pipe buffer
 * (~64KB), silently truncating large JSON/SARIF output. Wait for both streams
 * to flush first. A zero-length write's callback fires only after all prior
 * writes on that stream have been handled, which is the flush we need.
 */
function flushStdio() {
  const drain = (stream) => new Promise((res) => {
    if (stream.writableLength === 0) return res();
    stream.write('', res);
  });
  return Promise.all([drain(process.stdout), drain(process.stderr)]);
}
