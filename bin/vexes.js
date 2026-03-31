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
    help       Show this help
    version    Show version

  ${C.bold}SCAN OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --ecosystem <name>   Filter: npm, pypi, cargo, go, ruby, php, nuget, java, brew
    --severity <level>   Minimum: critical, high, moderate, low ${C.dim}(default: moderate)${C.reset}
    --fix                Show fix commands for each vulnerability
    --cached             Use cached results without freshness check
    --json               Output JSON to stdout
    --verbose, -v        Show debug output
    --no-color           Disable ANSI colors

  ${C.bold}ANALYZE OPTIONS${C.reset}
    --path <dir>         Target directory ${C.dim}(default: cwd)${C.reset}
    --ecosystem <name>   Filter: npm, pypi
    --deep               Download + AST-inspect actual package code (slower, thorough)
    --explain <package>  Detailed breakdown for a specific package
    --strict             Fail on any signal (for CI)
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

  ${C.bold}CONFIG${C.reset}
    Project: .vexesrc.json in project root
    User:    ~/.config/vexes/config.json

  ${C.dim}Zero dependencies. github.com/penumbraforge/vexes${C.reset}
`);
}

const exitCode = await main();
process.exit(exitCode);
