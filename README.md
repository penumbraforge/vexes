# vexes

[![CI](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml/badge.svg)](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@penumbraforge/vexes)](https://www.npmjs.com/package/@penumbraforge/vexes)

**Cross-ecosystem dependency security scanner.**

It reads package code, dependency graphs, version history, and registry metadata, then flags typosquat names, maintainer changes, capability escalation, and risky code patterns for review. Zero dependencies, pure Node.js.

> **Experimental and pre-1.0.** It runs and finds things, but it is unproven against live attacks. Detection is heuristic, so expect false positives and misses. Findings are signals for a human to review, not verdicts. The `guard` and `monitor` commands are the least exercised parts and should be treated as early work.

**Full documentation:** [penumbraforge.com/vexes/wiki](https://penumbraforge.com/vexes/wiki/)

![vexes scanning npm, PyPI, and Cargo dependencies](demo/vexes.gif)

```bash
# Try it now — no install required
npx @penumbraforge/vexes scan
```

> **[See it run](https://github.com/penumbraforge/vexes/actions/workflows/demo.yml)** — click "Run workflow" to watch vexes scan a demo project with known-vulnerable packages across npm, PyPI, and Cargo. No install needed.

```
$ vexes scan

  vexes v0.1.0 -- scanning dependencies

  Found 847 unique packages across 3 lockfile(s)
  ~ 847 packages checked in 2.1s (0 cached)

  -- CRITICAL --------------------------------------------------
  axios 1.14.1 (npm)
    GHSA-xxxx -- Remote code execution via compromised dependency
    Fixed in: >= 1.14.2
    https://osv.dev/vulnerability/GHSA-xxxx

  -- HIGH ------------------------------------------------------
  lodash 4.17.20 (npm)
    GHSA-yyyy -- Prototype pollution in lodash
    Fixed in: >= 4.17.21

  --------------------------------------------------
  2 vulnerabilities . 1 critical . 1 high
  in 847 packages across npm, pypi, cargo
  completed in 2.1s
  --------------------------------------------------
```

## What it does

vexes checks dependencies against vulnerability databases and adds four layers of heuristic analysis on top. Each layer produces signals, not conclusions — they are starting points for a person to look at:

| Layer | Detection Method | What it flags |
|-------|-----------------|----------------|
| **1. AST Analysis** | Parses JS/Python source via acorn AST | `eval()`, `child_process.exec()`, credential harvesting, obfuscated code, dynamic imports, `WebAssembly`, `setTimeout(string)`, DNS exfiltration, prototype chain escapes |
| **2. Dependency Graph** | Profiles newly added dependencies | Phantom dependencies (brand-new packages), circular staging, typosquatting, Unicode homoglyph attacks |
| **3. Behavioral Fingerprinting** | Diffs capability profiles between versions | A utility library that suddenly gains network+exec capabilities |
| **4. Registry Metadata** | Analyzes publish history, maintainers, timing | Account takeovers, rapid publishes, dormant package reactivation |

## Detection testing

The red team test suite contains hand-built, offline fixtures modeled on published write-ups of past supply chain attacks. Each fixture is a synthetic package assembled from the behaviors those write-ups describe — not a copy of the original malware — and the tests assert that vexes raises a signal on it:

- **axios RAT** (March 2026) -- Hijacked maintainer account, hidden dependency with RAT dropper
- **Shai-Hulud worm** (September 2025) -- Phished credentials, self-replicating worm via chalk/debug
- **event-stream** (November 2018) -- Social engineering, encrypted payload targeting bitcoin wallets
- **ua-parser-js** (October 2021) -- Account hijack, cryptominer + password stealer
- **litellm/TeamPCP** (March 2026) -- CI/CD compromise, 3-stage payload with K8s lateral movement
- **Typosquatting** -- `expresss`, `loadash`, `reqeusts` and similar name confusion attacks
- **Novel/hypothetical attacks** -- WASM-based payloads, DNS exfiltration, capability escalation

Passing these tests shows that vexes flags these particular fixtures. It does not show that it would flag the original attacks as they were actually published, or that it would catch a new one. There is also a false-positive suite that checks common benign patterns are not flagged, but neither suite is a substitute for evidence from real-world use, which vexes does not yet have.

## Installation

```bash
# Global install
npm install -g @penumbraforge/vexes

# Or run directly
npx @penumbraforge/vexes scan

# Or clone and run
git clone https://github.com/penumbraforge/vexes.git
cd vexes && node bin/vexes.js scan --path /your/project
```

**Requirements:** Node.js >= 22.5.0 (uses native SQLite for caching, native fetch)

## Commands

### `vexes scan` -- Vulnerability scanning

Enumerates dependencies from lockfiles, queries [OSV.dev](https://osv.dev), and reports known vulnerabilities.

```bash
vexes scan                          # Scan current directory
vexes scan --path ./my-project      # Scan a specific directory
vexes scan --ecosystem npm          # Scan only npm dependencies
vexes scan --severity critical      # Only show critical vulnerabilities
vexes scan --fix                    # Show upgrade commands for each vuln
vexes scan --json                   # Machine-readable JSON output
vexes scan --cached                 # Use cached results (skip freshness check)
```

**Ecosystems supported:** npm (package-lock.json, pnpm-lock.yaml, yarn.lock), PyPI (Pipfile.lock, poetry.lock, requirements.txt, pyproject.toml), Cargo (Cargo.lock), Go (go.sum), Ruby (Gemfile.lock), PHP (composer.lock), NuGet (packages.lock.json), Java (gradle.lockfile, pom.xml)

**Exit codes:** `0` = clean, `1` = vulnerabilities found, `2` = error/incomplete scan

### `vexes analyze` -- Behavioral analysis

Downloads registry metadata, runs AST analysis on install scripts, and profiles behavioral changes between versions. The output is a list of signals to review; expect some of them to be benign.

```bash
vexes analyze                       # Analyze direct dependencies
vexes analyze --deep                # Download + AST-inspect actual tarball code
vexes analyze --explain lodash      # Detailed breakdown for one package
vexes analyze --strict              # Fail on any signal (for CI)
vexes analyze -v                    # Show all signals including LOW
vexes analyze --json                # Machine-readable JSON output
```

**Detection signals:**
- `KNOWN_COMPROMISED` -- Package has known OSV vulnerabilities
- `MAINTAINER_CHANGE` -- Publishing account changed (possible account takeover)
- `POSTINSTALL_SCRIPT` -- Has install lifecycle scripts
- `RAPID_PUBLISH` -- Version published suspiciously quickly after previous
- `VERSION_ANOMALY` -- Major version jump or dormancy followed by sudden publish
- `TYPOSQUAT` -- Name suspiciously similar to a popular package
- `PHANTOM_DEPENDENCY` -- Brand-new dependency added (< 7 days old)
- `CIRCULAR_STAGING` -- New dep published by the same account as the parent
- `CAPABILITY_ESCALATION` -- Package gained dangerous capabilities between versions
- `AST_DANGEROUS_PATTERN` -- Dangerous code patterns in install scripts
- `TARBALL_DANGEROUS_PATTERN` -- Dangerous patterns in actual package source code
- `HOMOGLYPH` -- Package name contains suspicious Unicode (zero-width chars, RTL override, non-ASCII)
- `MISSING_PROVENANCE` -- No Sigstore provenance attestation
- `NO_REPOSITORY` -- No source repository link

### `vexes fix` -- Fix recommendations

Finds vulnerabilities and suggests upgrade commands. Each recommended version is cross-checked against OSV first, so it should not carry an advisory OSV already knows about.

```bash
vexes fix                           # Show fix recommendations
vexes fix --json                    # Machine-readable output
```

### `vexes guard` -- Pre-install check

Intercepts `npm install` and analyzes new or changed packages before they execute. Works by diffing lockfiles -- no network proxy needed. This is the least exercised command; it sits in the path of your installs, so try it on a throwaway project first.

```bash
vexes guard -- npm install axios    # Guard a specific install
vexes guard --setup                 # Install shell wrappers (auto-guard)
vexes guard --uninstall             # Remove shell wrappers
vexes guard --force -- npm install  # Override HIGH warnings (CRITICAL still blocked)
```

**How it works:**
1. Snapshots current lockfile
2. Runs `npm install --package-lock-only --ignore-scripts` (dry-run)
3. Diffs the lockfile to find new/changed packages
4. Runs behavioral analysis on those packages
5. Blocks if CRITICAL, prompts on HIGH, allows if clean
6. Runs the real install only after approval

### `vexes monitor` -- Continuous monitoring

Two modes for CI/CD and development:

```bash
# CI mode -- one-shot scan with GitHub Actions annotations
vexes monitor --ci                  # Default: fail on HIGH+
vexes monitor --ci --severity critical  # Only fail on CRITICAL
vexes monitor --ci --sarif          # SARIF output for GitHub Advanced Security
vexes monitor --ci --json           # Machine-readable JSON

# Watch mode -- continuous local monitoring
vexes monitor --watch               # Watch lockfiles + poll OSV hourly
vexes monitor --watch --interval 5  # Poll every 5 minutes
```

### `vexes explain` -- AI-assisted triage

Summarizes a long list of CVEs into a plain-English suggested order of work: what to look at first, why, and the upgrade sequence. Opt-in -- it calls the Claude API only when `ANTHROPIC_API_KEY` is set. The rest of the scanner does not use a model; this is a layer on top, not in the middle. Treat its prioritization as a draft to check, since it is a model's read of the findings.

```bash
export ANTHROPIC_API_KEY=sk-ant-...

vexes scan --format json | vexes explain   # Triage a piped scan
vexes explain --input report.json          # Triage a saved report
vexes explain --path ./my-project          # Scan, then triage
```

Findings are summarized (package, version, severity, advisory, fix) before sending -- no source code leaves your machine. Set `VEXES_AI_MODEL` to override the model (default `claude-sonnet-5`).

**GitHub Action:**
```yaml
# .github/workflows/vexes.yml
name: Dependency Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: penumbraforge/vexes@v0
        id: vexes
        with:
          command: scan
          severity: high
          sarif-file: vexes.sarif     # optional: surface in the Security tab
          fail-on-findings: 'true'     # optional: block the build on findings
      # Pair with upload-sarif to see results in GitHub code scanning:
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vexes.sarif
```

By default the action **succeeds and exposes outputs** (`vulnerabilities`, `critical`, `high`, `moderate`, `exit-code`, `sarif-file`) so you can branch on them. Set `fail-on-findings: 'true'` to make it a hard gate instead.

**Or run directly:**
```yaml
- name: Security scan
  run: npx @penumbraforge/vexes monitor --ci --severity high

# With SARIF upload to GitHub Advanced Security:
- name: Security scan (SARIF)
  run: npx @penumbraforge/vexes monitor --ci --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Configuration

### Project config: `.vexesrc.json`

Place in your project root. Walks up directories to find it.

```json
{
  "ecosystems": ["npm", "pypi"],
  "severity": "high",
  "ignore": [],
  "analyze": {
    "signals": {
      "NO_REPOSITORY": "off",
      "POSTINSTALL_SCRIPT": "off"
    }
  },
  "cache": {
    "dir": "~/.cache/vexes",
    "advisoryTtlMs": 3600000,
    "metadataTtlMs": 86400000
  },
  "output": {
    "color": "auto",
    "format": "text"
  }
}
```

### User config: `~/.config/vexes/config.json`

Same format. Project config overrides user config.

### Allowlists

vexes ships with built-in allowlists for packages with legitimate postinstall scripts (esbuild, sharp, puppeteer, etc.). Signals from these packages are downweighted rather than suppressed, so a version that introduces new dangerous patterns can still surface.

## Architecture

```
bin/vexes.js          CLI entrypoint, command router
src/
  cli/
    parse-args.js     Hand-rolled arg parser (zero deps)
    config.js         Config loading with prototype pollution protection
    output.js         Terminal output, ANSI colors, spinner, sanitization
  commands/
    scan.js           Vulnerability scanning via OSV
    analyze.js        4-layer behavioral analysis
    fix.js            Verified fix recommendations
    guard.js          Pre-install lockfile diffing
    monitor.js        CI annotations, SARIF output, watch mode
  core/
    constants.js      URLs, thresholds, exit codes
    fetcher.js        Single-point HTTP with retry/timeout/backoff
    logger.js         Leveled logger with terminal injection protection
    allowlists.js     Known-good packages, popular package sets
  parsers/
    npm.js            package-lock.json v1/v2/v3, package.json fallback
    pnpm.js           pnpm-lock.yaml v6/v9
    yarn.js           yarn.lock v1 (classic) and v2+ (Berry)
    pypi.js           requirements.txt (-r recursive), poetry.lock, Pipfile.lock, pyproject.toml
    cargo.js          Cargo.lock
    go.js             go.sum
    ruby.js           Gemfile.lock
    php.js            composer.lock
    dotnet.js         packages.lock.json (NuGet)
    java.js           gradle.lockfile, pom.xml
  advisories/
    osv.js            OSV.dev batch queries, CVSS v3.1 scoring, severity mapping
    npm-registry.js   npm registry metadata + provenance attestations
    pypi-registry.js  PyPI JSON API metadata
  analysis/
    ast-inspector.js  Acorn-based AST analysis (JS) + pattern matching (Python)
    signals.js        Signal orchestrator, composite risk scoring
    dep-graph.js      Dependency graph profiling, typosquat detection
    behavioral.js     Capability fingerprinting, version diffing
    tarball-inspector.js  Tarball download, tar parsing, source inspection
    diff.js           Lockfile snapshot diffing
    provenance.js     Sigstore provenance verification
  cache/
    advisory-cache.js SQLite-backed cache with TTL, corruption recovery
  vendor/
    acorn.mjs         Vendored acorn parser (zero npm deps)
test/
  test-ast-inspector.js   AST detection + false positive tests
  test-behavioral.js      Behavioral profiling + diffing
  test-cache.js           SQLite cache, TTL, corruption resilience
  test-dep-graph.js       Typosquat detection
  test-parse-args.js      Argument parser
  test-parsers.js         All lockfile/manifest parsers
  test-redteam.js         9 real-world attack reconstructions
  test-robustness.js      Input validation, edge cases, security
```

## Security design principles

1. **Fail loud, not clean.** A scanner that reports clean when it actually failed is misleading. If queries fail, vexes exits with code 2 and prints `SCAN INCOMPLETE`. Invalid ecosystems are rejected instead of silently scanning nothing.

2. **Zero dependencies.** The dependency chain is the attack surface. vexes has none. Acorn is vendored. SQLite is Node.js built-in.

3. **Terminal injection protection.** External data is sanitized before display, covering CSI sequences (with intermediate bytes), OSC (BEL and ST terminators), DCS/APC/PM/SOS sequences, C1 control codes (0x80-0x9F), and bare ESC bytes.

4. **Prototype pollution protection.** Config file merging rejects `__proto__`, `constructor`, and `prototype` keys.

5. **Command injection prevention.** The guard command uses `execFileSync` (no shell) with an allowlist of known package managers. Fix commands are shell-escaped before display. Guard setup resolves the vexes binary path at install time rather than using `npx` at runtime.

6. **Gzip bomb + SSRF protection.** Tarball downloads enforce streaming size limits, HTTPS-only URLs, and a registry host allowlist to prevent memory exhaustion and SSRF attacks.

7. **Cache integrity.** Corrupted entries are auto-deleted. Degraded results are not cached. TTL is clamped to prevent config-based stale data attacks (max 7 days advisory, 30 days metadata).

8. **Don't recommend a known-vulnerable fix.** The `fix` command cross-checks each recommended version against OSV before presenting it.

9. **Critical signals cannot be disabled.** `KNOWN_COMPROMISED`, `PHANTOM_DEPENDENCY`, `CIRCULAR_STAGING`, and `CAPABILITY_ESCALATION` cannot be turned off via config -- they are the signals most worth a second look, even when noisy.

10. **Allowlisted packages are still inspected.** Known-good packages (esbuild, sharp, etc.) have their signals downweighted, not suppressed. AST analysis runs on all packages regardless of allowlist status.

11. **Unicode homoglyph detection.** Package names are checked for invisible characters (zero-width spaces, BIDI overrides) and non-ASCII homoglyphs that could disguise malicious packages.

12. **Integrity-aware lockfile diffing.** Guard flags when a package tarball changes without a version bump by comparing integrity hashes.

## License

Apache-2.0

## Author

Shadoe Myers ([@penumbraforge](https://github.com/penumbraforge))
