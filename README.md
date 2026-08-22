# vexes

[![CI](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml/badge.svg)](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@penumbraforge/vexes)](https://www.npmjs.com/package/@penumbraforge/vexes)

**Cross-ecosystem dependency security scanner. Shakes the tree to see what falls.**

Zero dependencies. Pure Node.js. Catches real supply chain attacks.

**Full documentation:** [penumbraforge.com/vexes/wiki](https://penumbraforge.com/vexes/wiki/)

![vexes scanning npm, PyPI, and Cargo dependencies](demo/vexes.gif)

```bash
# Try it now — no install required
npx @penumbraforge/vexes scan
```

> **[See it in action](https://github.com/penumbraforge/vexes/actions/workflows/demo.yml)** — click "Run workflow" to watch vexes scan a demo project with real vulnerabilities across npm, PyPI, and Cargo. No install needed.

```
$ vexes scan --path demo

  vexes v0.3.0 -- scanning dependencies

  Found 33 unique packages across 3 dependency file(s)

  -- CRITICAL --------------------------------------------------
  tar 6.1.0 (npm)
    GHSA-23hp-3jrh-7fpw -- node-tar: Decompression/parse DoS via unlimited input
    Fixed in: >= 7.5.19
    https://osv.dev/vulnerability/GHSA-23hp-3jrh-7fpw
  minimist 1.2.5 (npm)
    GHSA-xvch-5gv4-984h -- Prototype Pollution in minimist
    Fixed in: >= 1.2.6
    https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h
  ...

  (real output, trimmed for the README — the demo tree carries 219 findings:
   27 critical . 108 high . 84 moderate across npm, pypi, cargo)
```

## What it does

vexes is a dependency security scanner that goes beyond vulnerability databases. It uses a **4-layer detection engine** to catch supply chain attacks that signature-based tools miss:

| Layer | Detection Method | What it catches |
|-------|-----------------|----------------|
| **1. AST Analysis** | Parses JS/Python source via acorn AST | `eval()`, `child_process.exec()`, credential harvesting, obfuscated code, dynamic imports, `WebAssembly`, `setTimeout(string)`, DNS exfiltration, prototype chain escapes |
| **2. Dependency Graph** | Profiles newly added dependencies | Phantom dependencies (brand-new packages), circular staging, typosquatting, Unicode homoglyph attacks |
| **3. Behavioral Fingerprinting** | Diffs capability profiles between versions | A utility library that suddenly gains network+exec capabilities |
| **4. Registry Metadata** | Analyzes publish history, maintainers, timing | Account takeovers, rapid publishes, dormant package reactivation |

**Two kinds of signal, weighted differently:**

- **Vulnerability layer (OSV)** — hard proof. `scan` queries OSV.dev and reports
  known-vulnerable versions with `confidence: proven`. Direct and transitive
  dependency resolution, SARIF, verified `fix` upgrades — all built on this.
- **Heuristic supply-chain signals** — `analyze` and `inspect` grade each
  signal (`deterministic` / `heuristic` / `inferred`). OSV findings (`KNOWN_COMPROMISED`)
  are `proven`; metadata facts (maintainer change, install scripts, publish
  timing) are `deterministic`; pattern/AST matches are `heuristic` and can
  false-positive. **Deep tarball analysis is npm/PyPI only** — other
  ecosystems are OSV-and-metadata only, today.

Every machine-readable command (`scan --json`, `analyze --json`,
`fix --json`, `monitor --ci --json`, `inspect --json`, `triage`, `doctor`)
emits through one versioned JSON envelope — the stable agent contract.

## Detection testing

The red team test suite reconstructs known supply chain attacks and checks that vexes flags each one:

- **axios RAT** (March 2026) -- Hijacked maintainer account, hidden dependency with RAT dropper
- **Shai-Hulud worm** (September 2025) -- Phished credentials, self-replicating worm via chalk/debug
- **event-stream** (November 2018) -- Social engineering, encrypted payload targeting bitcoin wallets
- **ua-parser-js** (October 2021) -- Account hijack, cryptominer + password stealer
- **litellm/TeamPCP** (March 2026) -- CI/CD compromise, 3-stage payload with K8s lateral movement
- **Typosquatting** -- `expresss`, `loadash`, `reqeusts` and similar name confusion attacks
- **Novel/hypothetical attacks** -- WASM-based payloads, DNS exfiltration, capability escalation

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
vexes scan --min-reachability reachable  # Only report live, imported findings
vexes scan --ai --json                   # + Tier B: LLM exploitability verdicts per finding
```

**Ecosystems supported:** npm (package-lock.json, pnpm-lock.yaml, yarn.lock), PyPI (Pipfile.lock, poetry.lock, requirements.txt, pyproject.toml), Cargo (Cargo.lock), Go (go.sum), Ruby (Gemfile.lock), PHP (composer.lock), NuGet (packages.lock.json), Java (gradle.lockfile, pom.xml), Hex (mix.lock), Dart/pub (pubspec.lock)

**Reachability (`--min-reachability`):** Tier A builds an import graph over the
project's own source (acorn for JS, light `import`/`use` scanning for Python and
Rust) and grades every dependency `reachable | lazy | dead | unknown` —
**dead** means no project code imports it (dev/test leftovers, abandoned
lockfile entries), which is the single biggest source of false positives in SCA
tools. The default keeps everything, graded; `--min-reachability reachable`
drops alarming-but-unreachable findings. Grades flow into JSON findings, the
`llmSummary`, and SARIF `properties.reachability`, so agents and CI can
prioritize by what the app can actually load. Unscannable ecosystems (Go, Ruby,
PHP, NuGet, Java) are honestly graded `unknown`, never mislabeled dead.

**Ecosystem reachability:** only `npm`/`pypi`/`cargo` have source scanners today.
A lockfile-only repo (or `--path` pointing at one with no source) grades
everything `dead` — that is correct: there is no app code importing anything.
Add app source before trusting the grade.

**Tier B exploitability (`--ai`):** the same reachability foundation, upgraded
with an optional LLM judge (reuses the pluggable local-first provider — see
`vexes explain`). Per finding, vexes sends the sanitized import evidence plus a
truncated advisory summary and asks one question: *is the vulnerable path
plausibly exploitable HERE?* The model answers `reachable | plausible | unclear`
plus a one-line reason, attached as `findings[].exploitability` with summary
roll-ups (`.exploitable`/`.plausible`/`.unclear`/`.aiError`).

```bash
vexes scan --ai --json                 # find vulns AND ask the local LLM which matter
```

Point itself at a provider with any one of:

```bash
export VEXES_AI_BASE=http://localhost:11434    # OpenAI-compatible (Ollama/Spark)
export ANTHROPIC_BASE_URL=http://cluster:8888  # Anthropic-compatible cluster (vLLM native Messages API)
export ANTHROPIC_AUTH_TOKEN=local              # Bearer token for the cluster (model auto-discovered via /v1/models)
export ANTHROPIC_API_KEY=sk-ant-...            # hosted Anthropic API
```

`VEXES_AI_BASE` wins; a bare `ANTHROPIC_BASE_URL` needs no API key. Mind the
trailing slash if you paste a URL with one — it is stripped, but the typo is
yours to check. Advisory metadata is untrusted, so the system prompt treats it
as data and ignores embedded instructions, and nothing but extracted facts ever
leaves home.
Verdicts are **advisory metadata, never a filter**: a deterministic finding is
never silenced by an AI opinion, and an AI failure never flips `complete` to
false — it degrades to a warning. If no provider is configured, `--ai` is a
transparent no-op you can keep in an agent's default loop.

**Exit codes:** `0` = clean, `1` = vulnerabilities found, `2` = error/incomplete scan

### `vexes analyze` -- Deep behavioral analysis

Goes beyond vulnerability databases. Downloads registry metadata, runs AST analysis on install scripts, profiles behavioral changes between versions.

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
- `SIGNATURE_SPOOF` -- Provenance **present and cryptographically valid** but
  the attestation certifies a *different package's artifact* (replay) or claims
  a *different source repo* than the package declares. Provenance ≠ trust: the
  TanStack worm shipped valid SLSA L3 provenance; vexes is the tool that xrefs
  what a signature actually says against who the package claims to be.
- `NO_REPOSITORY` -- No source repository link

### Dynamic sandbox (experimental)

`src/analysis/sandbox/` runs lifecycle scripts inside an OS isolation
primitive — macOS `sandbox-exec` (Seatbelt), Linux `bwrap`/`unshare`/`firejail`
— with network denied and writes scoped to a throwaway temp dir.
**Refuse-by-default:** nothing executes unless an isolation host exists *and*
the caller opts in, so a hostless or non-opted-in request returns a `refused`
status instead of a fake clean. Err on the side of "no quarantine" rather than
"quarantine, trust us." `vexes doctor` reports whether a host is available.

### `vexes fix` -- Verified fix recommendations

Finds vulnerabilities and generates **verified** upgrade commands. Every recommended version is cross-checked against OSV to ensure it isn't itself vulnerable.

```bash
vexes fix                           # Show fix recommendations
vexes fix --json                    # Machine-readable output
```

### `vexes guard` -- Pre-install protection

Intercepts `npm install` and analyzes new/changed packages **before** they execute. Works by diffing lockfiles -- no network proxy needed.

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
vexes monitor --watch --freshness 5 # + poll registry metadata every 5 min
```

**Freshness layer (`--freshness <minutes>`):** the 2026 supply-chain race is
measured in *hours* — axios was malicious ~3h, Mastra republished 140+
packages in 88 minutes. CVE databases structurally lag those windows. The
freshness layer polls the **registry**, where a new release is visible within
minutes, and runs the signal engine on every new publish: publisher/account
change (`HIGH`), new install lifecycle scripts (`HIGH`), newly added deps
(`MODERATE`), rapid re-publish (`MODERATE`), and dormancy-then-activity
(`MODERATE`). Last-seen version hashes persist in SQLite so each release is
graded once. Alerts emit in the same JSON envelope an agent can read; the
watcher never re-downloads or executes anything, it only grades metadata.

### `vexes inspect` -- Single-package assessment (agent tool)

Assess one package spec on demand — "is it safe to add this dependency?"
No project required. Combines OSV history + registry metadata + all detection
layers + Sigstore provenance in one call.

```bash
vexes inspect lodash@4.17.21 --json    # JSON envelope (agent-ready)
vexes inspect express                  # latest version
vexes inspect requests --ecosystem pypi
vexes inspect axios@1.14.1 --deep      # + AST-inspect the real tarball
```

### `vexes doctor` -- Self test

Verifies the scanner is trustworthy before an agent trusts its output:
parsers round-trip real fixtures, the SQLite cache survives a write/read,
and registries are reachable (network is a reported status, never a hard fail).

```bash
vexes doctor            # human output
vexes doctor --json     # machine output
```

### `vexes licenses` -- Declared license SBOM (deps.dev)

A license bill of materials — informational, never a security verdict. Uses
Google's deps.dev API (no key) for SPDX license IDs across
`npm` / `pypi` / `cargo` / `go` / `nuget` / `java`. Ecosystems deps.dev doesn't
cover (`ruby`, `php`, `hex`, `pub`) are skipped with a visible warning, not an
error — for those, `vexes scan` remains the vulnerability answer.

```bash
vexes licenses --path ./my-project
vexes licenses --json
```

Fail-loud by contract: if any lookup fails, `complete: false` and exit 2 — a
partial SBOM is never passed off as complete. A package with **no declared
license** exits 1 (`VULNS_FOUND` equivalent) so CI notices; it is a flagged
row, not an error. Requests are throttled under deps.dev's ~20 req/min
unauthenticated limit, and 429/5xx responses are retried with backoff.

```json
{
  "schemaVersion": "1.0",
  "command": "licenses",
  "complete": true,
  "summary": { "total": 33, "withLicenses": 33, "missing": 0, "skipped": 0 },
  "licenses": [
    { "package": "express", "version": "4.17.1", "ecosystem": "npm",
      "licenses": ["MIT"], "url": "https://api.deps.dev/..." }
  ]
}
```

### `vexes explain` -- AI-assisted triage

Turns a wall of CVEs into a prioritized, plain-English action plan: what to fix first, why it matters (blast radius), and the upgrade sequence. **Opt-in and privacy-preserving** -- it uses the same pluggable local-first provider as `scan --ai` (`VEXES_AI_BASE`, a local `ANTHROPIC_BASE_URL` cluster, or hosted `ANTHROPIC_API_KEY`). The scanner itself stays fully deterministic and offline; this is a layer on top, not in the middle.

```bash
# local OpenAI-compatible endpoint
export VEXES_AI_BASE=http://localhost:11434
# or a local Anthropic-compatible cluster (vLLM native Messages API)
export ANTHROPIC_BASE_URL=http://cluster:8888 ANTHROPIC_AUTH_TOKEN=local
# or hosted
export ANTHROPIC_API_KEY=sk-ant-...

vexes scan --format json | vexes explain   # Triage a piped scan
vexes explain --input report.json          # Triage a saved report
vexes explain --path ./my-project          # Scan, then triage
```

Findings are summarized (package, version, severity, advisory, fix) before sending -- no source code leaves your machine. Set `VEXES_AI_MODEL` (or `ANTHROPIC_MODEL`) to override the model; without either, a cluster's model is auto-discovered from `GET /v1/models`.

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

vexes ships with built-in allowlists for packages with legitimate postinstall scripts (esbuild, sharp, puppeteer, etc.). Signals from these packages are **downweighted, not suppressed** -- a compromised version still triggers if new dangerous patterns appear.

## Agent contract (JSON CLI)

Vexes is callable by agents via a **stable, versioned JSON CLI** — no MCP server
needed. Every machine command emits the same envelope:

```json
{
  "schemaVersion": "1.0",
  "generator": { "name": "vexes", "version": "0.3.0" },
  "timestamp": "...", "command": "scan",
  "target": { "dir": "...", "lockfiles": [...], "ecosystems": [...] },
  "complete": true,              // false ⇒ NEVER treat as clean
  "result": { "complete": true, "warnings": [] },
  "summary": { "total": 33, "vulnerable": 219, "critical": 27, "high": 108, "moderate": 84, "low": 0, "suppressed": 0,
    "reachable": 0, "lazy": 0, "dead": 33, "unreachable": 33 },
  "findings": [ { "id": "GHSA-23hp-3jrh-7fpw", "package": "tar", "version": "6.1.0", "ecosystem": "npm",
    "severityLevel": { "level": "CRITICAL", "order": 4 },
    "confidence": "proven", "reachability": "dead",
    "signal": "KNOWN_COMPROMISED", "advisories": ["GHSA-23hp-3jrh-7fpw", "CVE-2026-59873"],
    "fixed": ">= 7.5.19", "fixCommand": "npm install tar@7.5.21",
    "llmSummary": "[CRITICAL] tar@6.1.0 (npm) — CVE-2026-59873: node-tar: Decompression/parse DoS via unlimited input. Fixed in >= 7.5.19. Not reachable from this project's code (dead in the lockfile). Blocker: yes." } ]
}
```

The values above are a **real** `vexes scan --json --path demo` run —
`demo/` is lockfiles-only, so every dep grades `dead` (no app source imports
anything). That is correct honesty, not noise; point vexes at a real source
tree to get live `reachable`/`lazy` grades. **Rules agents rely on:** stdout is
always the JSON document (logs go to stderr); `complete: false` means fail
loud; findings preserve every internal field plus new contract fields
(additive — old consumers keep working); `schemaVersion` bumps only on
breaking shape changes. Exit codes: `0` clean, `1` findings, `2`
error/incomplete. **Run `vexes doctor` first** to confirm the tool is
trustworthy. Full contract: `wiki/Agent-Integration.md`.

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

1. **Fail loud, not clean.** A security scanner that silently reports clean on failure is worse than useless. If queries fail, vexes exits with code 2 and prints `SCAN INCOMPLETE`. Invalid ecosystems are rejected outright instead of silently scanning nothing.

2. **Zero dependencies.** The dependency chain is the attack surface. vexes has none. Acorn is vendored. SQLite is Node.js built-in.

3. **Terminal injection protection.** All external data is sanitized with a comprehensive filter covering CSI sequences (with intermediate bytes), OSC (BEL and ST terminators), DCS/APC/PM/SOS sequences, C1 control codes (0x80-0x9F), and bare ESC bytes.

4. **Prototype pollution protection.** Config file merging rejects `__proto__`, `constructor`, and `prototype` keys.

5. **Command injection prevention.** The guard command uses `execFileSync` (no shell) with an allowlist of known package managers. Fix commands are shell-escaped before display. Guard setup resolves the vexes binary path at install time rather than using `npx` at runtime.

6. **Gzip bomb + SSRF protection.** Tarball downloads enforce streaming size limits, HTTPS-only URLs, and a registry host allowlist to prevent memory exhaustion and SSRF attacks.

7. **Cache integrity.** Corrupted entries are auto-deleted. Degraded results are never cached. TTL is clamped to prevent config-based stale data attacks (max 7 days advisory, 30 days metadata).

8. **Never recommend vulnerable fixes.** The `fix` command cross-checks every recommended version against OSV before presenting it.

9. **Critical signals are undisableable.** `KNOWN_COMPROMISED`, `PHANTOM_DEPENDENCY`, `CIRCULAR_STAGING`, and `CAPABILITY_ESCALATION` cannot be turned off via config -- they detect active attacks.

10. **Allowlisted packages are still inspected.** Known-good packages (esbuild, sharp, etc.) have their signals downweighted, not suppressed. AST analysis runs on all packages regardless of allowlist status.

11. **Unicode homoglyph detection.** Package names are checked for invisible characters (zero-width spaces, BIDI overrides) and non-ASCII homoglyphs that could disguise malicious packages.

12. **Integrity-aware lockfile diffing.** Guard detects when a package tarball changes without a version bump by comparing integrity hashes.

## License

Apache-2.0

## Author

Shadoe Myers ([@penumbraforge](https://github.com/penumbraforge))
