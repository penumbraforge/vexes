# vexes

[![CI](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml/badge.svg)](https://github.com/penumbraforge/vexes/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@penumbraforge/vexes)](https://www.npmjs.com/package/@penumbraforge/vexes)

**Cross-ecosystem dependency security scanner.**

It reads lockfiles and registry metadata, and can sample selected package files, then flags known vulnerabilities and heuristic supply-chain signals for review. It has zero external runtime npm dependencies: Acorn is vendored and the rest uses Node.js built-ins.

> **Experimental and pre-1.0.** It runs and finds things, but it is unproven against live attacks. Detection is heuristic, so expect false positives and misses. Findings are signals for a human to review, not verdicts. The `guard` and `monitor` commands are the least exercised parts and should be treated as early work.

**Documentation:** [versioned in-repository reference](wiki/Home.md). Treat it
as authoritative for this source tree; external copies are not release artifacts.

![vexes scanning npm, PyPI, and Cargo dependencies](demo/vexes.gif)

```bash
# Try it without a global install
npx @penumbraforge/vexes scan
```

> **[See it run](https://github.com/penumbraforge/vexes/actions/workflows/demo.yml)** — click "Run workflow" to watch vexes scan a demo project with known-vulnerable packages across npm, PyPI, and Cargo.

```
$ vexes scan --path demo

  vexes v0.6.1 -- scanning dependencies

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

  (illustrative output from a dated demo run, trimmed for the README — 219 findings:
   27 critical . 109 high . 83 moderate across npm, pypi, cargo, as of 2026-08-28;
   counts drift as OSV data changes)
```

## What it does

vexes checks dependencies against OSV.dev and organizes its
npm/PyPI heuristic work into four layers. Individual layers run only where the
ecosystem and available metadata support them. Each result is a signal, not a
conclusion — a starting point for review:

| Layer | Detection Method | What it flags |
|-------|-----------------|----------------|
| **1. Source-pattern analysis** | Parses selected JavaScript with vendored Acorn; uses pattern matching for selected Python files | Calls and strings associated with code execution, process spawning, credentials, networking, obfuscation, and dynamic loading |
| **2. Dependency metadata** | Profiles dependencies added by the analyzed npm release relative to its previous published version | Very new packages, same-publisher staging, consumer install hooks, and names similar to a curated popular-package list |
| **3. Behavioral fingerprinting** | Compares observable install-hook capabilities when both the analyzed and previous published version's data is available | A package version that newly adds network, process, or credential-related behavior |
| **4. Registry metadata** | Analyzes publish history, maintainers, timing, and attestation fields | Publisher changes, rapid publishes, dormant-package activity, and metadata inconsistencies |

**Two kinds of signal, weighted differently:**

- **Vulnerability layer (OSV)** — an upstream advisory match. `scan` queries
  OSV.dev and reports versions that OSV places in an affected range. The
  `confidence: proven` field means the advisory match is deterministic; it does
  not prove exploitation or that a package is malicious. Dependency enumeration,
  SARIF, and OSV-cross-checked fix candidates are built on this layer.
- **Heuristic supply-chain signals** — `analyze` and `inspect` grade each
  signal (`proven` / `deterministic` / `heuristic` / `inferred`). Explicit
  malicious-package OSV records become `KNOWN_MALICIOUS`; ordinary affected-range
  matches become `KNOWN_VULNERABILITY`. Both are `proven` matches to upstream
  data, not proof of compromise or exploitation. Metadata facts (publishing-account
  change, consumer install hooks, publish timing) are `deterministic`;
  pattern/AST matches are `heuristic` and can false-positive. **Bounded tarball
  sampling is npm/PyPI only.** The `scan` command covers the other documented
  ecosystems with OSV; the heuristic analysis command currently does not.

Normal successful JSON paths for `scan`, `analyze`, `fix`, `monitor --ci`,
`inspect`, `doctor`, and `licenses` share a versioned top-level envelope.
Command-specific payloads differ, and early errors, setup/uninstall flows,
`explain`/`triage`, and long-running watch output are not yet a uniform contract.

## Detection testing

The red team test suite contains hand-built, offline fixtures for behaviors such
as environment-variable collection, downloader-shaped install scripts,
obfuscated payload strings, typosquat names, dynamic loading, DNS access, and
capability changes. They are synthetic inputs written for the tests, not copies
of malware, and the tests only assert that selected signals fire.

Passing these tests shows that vexes flags these particular fixtures. It does not show that it would flag a historical incident as actually published, or that it would catch a new one. There are also selected benign controls, but their small curated set is not a population false-positive estimate or a substitute for real-world evidence, which vexes does not yet have.

On top of the unit tests, a [detection benchmark](BENCHMARK.md) records three
dated observations. Part A matches 5/5 exact advisory identities for historical
package versions. Part B detects 5/5 technique-specific synthetic attacks and
passes 2/2 gated negative controls under their stated forbidden/HIGH+ criteria.
Part C reports HIGH/CRITICAL heuristic
flags for 1/10 exact-version, digest-pinned live samples and 0 current blocking
advisories as of 2026-08-28. The live cases inspect bounded entry/install-like
source samples, not whole packages, so the full run reports `INCOMPLETE`; that
expected coverage status exits 0 only when its integrity and policy gates pass.
Execution errors exit 2, regressions exit 1, and `--require-complete` makes the
sampled-coverage limitation blocking. The benchmark does not retrieve
known-malware artifacts or execute package code.

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

**Requirements:** Node.js >= 22.13.0. `node:sqlite` first appeared in 22.5.0
behind an experimental flag and became usable without that flag in 22.13.0.

## Commands

### `vexes scan` -- Vulnerability scanning

Enumerates supported dependency records, queries [OSV.dev](https://osv.dev),
and reports versions that OSV places in affected ranges.

```bash
vexes scan                          # Scan current directory
vexes scan --path ./my-project      # Scan a specific directory
vexes scan --ecosystem npm          # Scan only npm dependencies
vexes scan --severity critical      # Only show critical vulnerabilities
vexes scan --fix                    # Show advisory-derived upgrade hints
vexes scan --json                   # Machine-readable JSON output
vexes scan --cached                 # Accept stale cache hits; misses may still query OSV
vexes scan --min-reachability reachable  # Deprecated no-op; findings are never filtered this way
vexes scan --ai --json                   # + optional LLM import context per finding
```

**Ecosystems supported:** npm (package-lock.json, pnpm-lock.yaml, yarn.lock), PyPI (Pipfile.lock, poetry.lock, requirements.txt, pyproject.toml), Cargo (Cargo.lock), Go (go.mod preferred, go.sum fallback), Ruby (Gemfile.lock), PHP (composer.lock), NuGet (packages.lock.json), Java (gradle.lockfile, pom.xml), Hex (mix.lock), Dart/pub (pubspec.lock)

Resolved lockfiles are preferred. Ruby `Gemfile`, PHP `composer.json`, NuGet
project files, and Java `pom.xml` fallbacks can contribute exact pins but are
always marked incomplete because they are not resolved graphs. Go uses
`go.mod` when present; replaced modules are excluded and make coverage
incomplete. If only `go.sum` exists, vexes parses its checksum history, which
can include modules no longer active in the build. Unrecognized lockfile shapes
fail visibly instead of being treated as empty; the pnpm parser currently
accepts lockfile major versions 6 and 9. Ruby lock entries require the canonical
RubyGems remote and a Bundler `CHECKSUMS` SHA-256 entry; legacy unchecked locks
remain visibly incomplete because a mirror can serve different bytes for the
same coordinate.

**Direct-import evidence:** Tier A scans selected project source forms (Acorn
for JavaScript; lightweight scans for TypeScript, Python, and Rust) and adds
`importEvidence: found_static | found_dynamic | not_found | unknown` to each
finding. `not_found` means only that no matching import appeared in source vexes
successfully parsed. Tools, package binaries, plugin loaders, computed imports,
workspace siblings, skipped files, and parser failures can still load a
dependency. Unsupported ecosystems and projects with no parsable source for
that ecosystem are `unknown`. The older `reachability` values
`reachable | lazy | dead | unknown` remain for compatibility only.
`--min-reachability` is deprecated and ignored; direct-import evidence never
suppresses an advisory.

**Optional AI import context (`--ai`):** an LLM can classify the limited
direct-import evidence already collected by the scan. Per finding, vexes sends
that evidence plus a control-character-stripped, truncated advisory summary.
The model answers `reachable | plausible | unclear` with a one-line reason. A
package import is not proof that the vulnerable API or code path runs, so this
classification is context for review rather than an exploitability verdict. It
is attached under `findings[].aiImportContext`. The historical
`findings[].exploitability` field remains a deprecated alias. Summary roll-ups
use `.aiReachable`/`.plausible`/`.unclear`/`.aiError`; `.exploitable` remains a
deprecated alias for `.aiReachable` and does not prove exploitation.

```bash
vexes scan --ai --json                 # find vulns and ask the configured LLM which may matter
```

Point itself at a provider with any one of:

```bash
export VEXES_AI_BASE=http://localhost:11434    # OpenAI-compatible (Ollama/Spark)
export VEXES_AI_KEY=optional-bearer-token       # only when that endpoint requires it
export ANTHROPIC_BASE_URL=http://cluster:8888  # Anthropic-compatible cluster (vLLM native Messages API)
export ANTHROPIC_AUTH_TOKEN=local              # Bearer token for the cluster (model auto-discovered via /v1/models)
export ANTHROPIC_API_KEY=sk-ant-...            # hosted Anthropic API
```

`VEXES_AI_BASE` wins. A custom Anthropic-compatible route requires either
`ANTHROPIC_AUTH_TOKEN` (Bearer) or `ANTHROPIC_API_KEY` (x-api-key); the hosted
route requires `ANTHROPIC_API_KEY`. Advisory metadata is untrusted and is framed
as data in the prompt. A remote configured provider receives summarized
package/advisory/import facts; source files are not sent.
AI classifications are **advisory metadata, never a filter**: a deterministic finding is
never silenced by an AI opinion, and an AI failure never flips `complete` to
false — it degrades to a warning. If no provider is configured, `--ai` is
skipped, a warning is added, and the deterministic scan result is unchanged.

**Exit codes:** `0` = requested checks complete with no findings at the active
threshold, `1` = findings at the threshold, `2` = error/incomplete scan. Exit 0
is not a safety verdict.

### `vexes analyze` -- Behavioral analysis

Downloads registry metadata, pattern-checks inspectable inline install-script
content, and profiles observable changes between versions. The output is a list
of signals to review; expect both false positives and misses.

```bash
vexes analyze                       # Prefer parser-identified direct dependencies
vexes analyze --deep                # Download + inspect a bounded file sample
vexes analyze --explain lodash      # Detailed breakdown for one package
vexes analyze --strict              # Fail on reported signals at the active severity threshold
vexes analyze -v                    # Show all signals including LOW
vexes analyze --json                # Machine-readable JSON output
```

When `--deep` samples a package, its bounded coverage is reported as
`complete: false` and the command exits 2 even if sampling itself succeeds;
findings remain available for review. For npm, downloaded compressed bytes are
checked against registry SRI or shasum metadata when present. Missing npm digest
metadata is a warning on the static path; the current PyPI sdist path is not
digest-bound.

For selected at-risk npm packages, provenance lookup is another requested
stage. An unavailable lookup or a present bundle whose payload cannot be
decoded makes analysis incomplete. A decoded bundle is cross-referenced but
not cryptographically verified.

**Detection signals:**
- `KNOWN_MALICIOUS` -- OSV explicitly identifies a malicious package/version (`MAL-*` or malware-typed record)
- `KNOWN_VULNERABILITY` -- Version falls in an ordinary OSV vulnerability range; it does not imply malware or exploitation
- `KNOWN_COMPROMISED` / `OSV_MATCH` -- Compatibility names; normalized `scan`
  findings currently retain `KNOWN_COMPROMISED`, while new analysis results use
  the two names above
- `MAINTAINER_CHANGE` -- Publishing account changed (possible account takeover)
- `POSTINSTALL_SCRIPT` -- Has consumer install hooks (`preinstall`, `install`, or `postinstall`)
- `RAPID_PUBLISH` -- Version published suspiciously quickly after previous
- `VERSION_ANOMALY` -- Major version jump or dormancy followed by sudden publish
- `TYPOSQUAT` -- Name suspiciously similar to a popular package
- `PHANTOM_DEPENDENCY` -- Dependency added by the analyzed npm release is < 7 days old or has sparse registry metadata
- `CIRCULAR_STAGING` -- Such a dependency was published by the same account as the parent within 48 hours
- `CAPABILITY_ESCALATION` -- Previous version's capabilities known and the package gained dangerous ones between versions (requires a real previous-version diff)
- `INITIAL_DANGEROUS_CAPABILITY` -- Analyzed version's inspectable install scripts have dangerous capabilities, but usable previous-version script data was unavailable, so no diff is claimed
- `AST_DANGEROUS_PATTERN` -- Selected risk-associated patterns in inspectable inline install-hook content
- `TARBALL_DANGEROUS_PATTERN` -- Pattern matches in selected files from a bounded tarball sample
- `HOMOGLYPH` -- Package name contains suspicious Unicode (zero-width chars, RTL override, non-ASCII)
- `MISSING_PROVENANCE` -- No npm Sigstore provenance attestation among packages selected for that stage
- `ATTESTATION_IDENTITY_MISMATCH` -- Decoded attestation identity
  fields that disagree with the package name or declared repository. vexes
  **decodes and cross-references attested fields; it
  does not verify DSSE signatures, certificates, or transparency-log inclusion
  proofs** — so it can catch a mismatch between what an attestation says and
  what the package claims, but it cannot confirm the attestation is genuine.
  Presence or internal consistency of an attestation is not a trust verdict.
  `SIGNATURE_SPOOF` is retained only as a compatibility name.
- `NO_REPOSITORY` -- No source repository link

**Coverage caveats for name-based detection:** typosquat similarity is computed
against a curated list of ~165 npm / ~105 PyPI popular packages — a typosquat
of anything outside that list is invisible. Similarity thresholds are
length-dependent (names ≤3 chars are never compared; 4–6 chars allow distance
1; 7+ allow distance 2). Scoped names are compared as their full spelling,
including the scope, which can make the distance threshold less useful.
Homoglyph detection flags invisible Unicode, BIDI overrides, and any non-ASCII
character. Normal public-registry naming rules make that check largely dormant;
it remains a defensive primitive for malformed/synthetic metadata. It detects
"non-ASCII present," not true Unicode-confusable mapping.

### Dynamic execution telemetry (experimental)

With `--sandbox`, `analyze` may execute one selected npm entrypoint (`bin`,
`main`, or `index.js`) for each of up to five HIGH/CRITICAL candidates;
`inspect` may execute one for its target. Execution uses a bounded partial
extraction under an accepted Linux `bwrap` host. It does not run lifecycle
hooks. PyPI sandbox extraction and execution are unsupported and refused; this
does not affect static PyPI `--deep` sampling. The accepted `bwrap` layout
omits the user's home and project by default and restricts writes to the
extracted workdir and throwaway temp, but it exposes read-only host runtime
trees (`/usr`, `/bin`, and available loader-library directories). `/etc`, the
user's home, and the calling project are not mounted. This is private-data
isolation, not a guarantee that package code can read no host information. The current macOS
`sandbox-exec` profile is refused because its broad file-read rule also exposes
arbitrary user files. A launch probe checks that the primitive can start a
benign Node process, not that containment is escape-proof. The recorder observes a subset of Node
process, network, and filesystem APIs, is not inherited by child processes,
and is not tamper-resistant. The child receives a minimal environment rather
than arbitrary parent environment variables. Treat this as best-effort
telemetry, not a safe boundary for known malware. Execution is opt-in and refused when no accepted
primitive is available or when npm registry digest metadata is unavailable.
Because recorder absence is not trusted as negative evidence, a requested
sandbox stage remains `complete: false` / exit 2 even when a selected run
launches; positive observations are still retained. A timeout or nonzero child
exit is a failed stage, not behavioral evidence.

### `vexes fix` -- Upgrade candidates

For npm lockfiles, finds vulnerabilities and suggests POSIX-shell-quoted upgrade
commands. Package/version coordinates are validated before a command is shown;
the npm form uses an option boundary. At request time, a candidate is presented
only after OSV returns no matching advisory for that version. Generate the
resolved lockfile, rescan it, and test the upgrade before treating it as
remediation.

```bash
vexes fix                           # Show OSV-cross-checked upgrade candidates
vexes fix --json                    # Machine-readable output
```

### `vexes guard` -- Pre-install check

**Experimental, public-registry npm only.** Guard accepts explicit
`npm install`/`i`/`add <package>` requests with a narrow set of flags. It resolves
the proposed manifest and lockfile in a disposable project copy with lifecycle
scripts disabled, preserves individual lockfile occurrences, and requires each
new or changed artifact to have a public-registry HTTPS URL and integrity value.
It cross-checks exact-version registry metadata, analyzes the changed
occurrences, then applies an approved manifest/lockfile with
`npm install --ignore-scripts`. The final lockfile must match the approved
occurrence, version, resolved URL, and integrity fields.

This verifies npm metadata and lockfile identity, not the bytes placed in
`node_modules`, and it is not a transaction: each reviewed manifest file is
staged with an atomic same-directory replacement and restored on detected
failure or drift, but `node_modules` may be partially changed. An actively
racing same-user process remains outside this boundary.
Lifecycle scripts remain disabled for the guarded install. Bare installs,
workspaces, local/git/URL specs, `npx`, pnpm, and Yarn are refused. JSON mode is
assessment-only and never installs. Treat guard as a review boundary, not proof
that an artifact is safe.

```bash
vexes guard -- npm install axios    # Guard a specific install
vexes guard --setup                 # Currently disabled; fails closed
vexes guard --uninstall             # Remove a wrapper installed by an older release
vexes guard --force -- npm install axios  # Override HIGH only; never incomplete/known-advisory/CRITICAL blocks
```

**How it works:**
1. Copies the current manifest and lockfile into a disposable resolver directory
2. Runs npm there in lockfile-only mode with scripts disabled
3. Diffs occurrence-aware snapshots and validates each new/changed public-registry artifact identity
4. Checks exact proposed versions against OSV, registry metadata, and behavioral signals
5. Blocks any known advisory, CRITICAL evidence, or incomplete analysis; prompts on HIGH (or accepts `--force` for HIGH only)
6. In human mode, applies the approved files, installs with scripts disabled, and verifies the final manifest and lockfile identity; in JSON mode, stops after assessment

### `vexes monitor` -- Continuous monitoring

Two modes for CI/CD and development:

```bash
# CI mode -- one-shot scan with GitHub Actions annotations
vexes monitor --ci                  # Default: fail on HIGH+
vexes monitor --ci --severity critical  # Only fail on CRITICAL
vexes monitor --ci --sarif          # SARIF output for GitHub code scanning
vexes monitor --ci --json           # Machine-readable JSON

# Watch mode -- continuous local monitoring
vexes monitor --watch               # Watch lockfiles + poll OSV hourly
vexes monitor --watch --interval 5  # Poll every 5 minutes
vexes monitor --watch --freshness 5 # + poll registry metadata every 5 min
```

**Freshness layer (`--freshness <minutes>`):** an experimental npm/PyPI poll
that records each registry's latest version in the local SQLite cache. The first
successful poll establishes a baseline; later polls grade a release only when
the observed latest version changes. An alert means "new since vexes last saw
it," not proof of a new publication or attack. If persistent cache state is
unavailable, freshness polling is disabled; per-package registry failures make
a cycle incomplete. It does not download or execute package code.

### `vexes inspect` -- Single-package assessment (agent tool)

Collect evidence about one package spec on demand; it does not decide whether a
dependency is safe. No project is required. npm and PyPI support differ, and
the result combines available OSV, registry, heuristic, and decoded-attestation
evidence. For npm, an unavailable requested provenance lookup or a present but
undecodable bundle makes the result incomplete. A decoded bundle is
cross-referenced, not cryptographically verified.

```bash
vexes inspect lodash@4.17.21 --json    # JSON envelope
vexes inspect express                  # latest version
vexes inspect requests --ecosystem pypi
vexes inspect express@4.21.2 --deep    # + inspect a bounded tarball file sample
```

### `vexes doctor` -- Self test

Runs an installation smoke test: loads one fixture per parser, performs a SQLite
write/read, and reports optional registry and sandbox availability. Passing
does not attest to detection accuracy, provider readiness, or containment.

```bash
vexes doctor            # human output
vexes doctor --json     # machine output
```

### `vexes licenses` -- Declared-license inventory (deps.dev)

A flat declared-license inventory — informational, not a standardized SPDX or
CycloneDX SBOM and never a security verdict. Uses
Google's deps.dev API (no key) for its declared-license strings (vexes does not
locally validate them as SPDX expressions) across
`npm` / `pypi` / `cargo` / `go` / `nuget` / `java`. Ecosystems deps.dev doesn't
cover (`ruby`, `php`, `hex`, `pub`) are skipped with a visible warning, not an
error — for those, `vexes scan` remains the vulnerability answer.

```bash
vexes licenses --path ./my-project
vexes licenses --json
```

For supported lookups, if any lookup fails, `complete: false` and exit 2. A
package with **no declared
license** exits 1 (`VULNS_FOUND` equivalent) so CI notices; it is a flagged
row, not an error. Requests are serialized with a small client-side interval,
and 429/5xx responses are retried with backoff.

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

Turns scan findings into a draft plain-English prioritization. It is opt-in and
uses a configured OpenAI-compatible endpoint, Anthropic-compatible endpoint,
or hosted Anthropic API. Scanning still queries public OSV/registry endpoints;
AI triage is a separate layer. A remote model receives summarized findings,
not source files. Treat its output as a draft to verify.

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

Findings are summarized (package, version, severity, advisory, fix) before
sending; source files are not included in the model request. Set
`VEXES_AI_MODEL` (or `ANTHROPIC_MODEL`) to override the model; without either,
a cluster's model is auto-discovered from `GET /v1/models`.

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
          sarif-file: vexes.sarif     # optional: upload where code scanning is enabled
          fail-on-findings: 'true'     # optional: block the build on findings
      # Pair with upload-sarif to see results in GitHub code scanning:
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.vexes.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.vexes.outputs.sarif-file }}
```

On a valid structured run, the action **succeeds by default and exposes outputs**
(`vulnerabilities`, `critical`, `high`, `moderate`, `exit-code`, and a validated
fresh `sarif-file` when requested) so you can branch on them. Empty, malformed,
or non-envelope JSON exposes exit code 2 without made-up zero counts. Set
`fail-on-findings: 'true'` to make findings or incompleteness a hard gate. The
action passes both `--no-user-config` and `--no-project-config`, so neither a
self-hosted runner's user policy nor a checked-out pull request's
`.vexesrc.json` can silently change the action's result. Explicit action inputs
still apply.

**Or run directly:**
```yaml
- name: Security scan
  run: npx @penumbraforge/vexes monitor --ci --severity high --no-user-config --no-project-config

# With SARIF upload to GitHub code scanning:
- name: Security scan (SARIF)
  run: npx @penumbraforge/vexes monitor --ci --sarif --no-user-config --no-project-config > results.sarif
  continue-on-error: true  # preserve the report when findings make vexes exit 1
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
  "output": {
    "color": "auto",
    "format": "text"
  }
}
```

Project config is allowlisted to reporting policy: ecosystems, severity,
ignore entries, strict/verbose/top presentation, signal switches, and output
format/color. It cannot opt into `--sandbox`, `--deep`, `--fix`, `--ai`, or
stale-cache use, and it cannot choose the cache location or TTLs. Those
operational modes require an explicit CLI flag; cache storage policy comes
from defaults or trusted user config. Use `--no-project-config` when the
repository being scanned is not trusted to choose reporting policy. Add
`--no-user-config` when a reproducible enforcement run must also ignore the
runner account's user policy.

### User config: `~/.config/vexes/config.json`

User config can also choose the ordinary cache directory and TTLs. Operational
modes (`--sandbox`, `--deep`, `--fix`, `--ai`, and `--cached`) remain CLI-only
for each invocation. Allowed project policy overrides user policy unless
`--no-project-config` is supplied; `--no-user-config` skips the user file.

### Allowlists

vexes ships with a curated exact-name list for common packages expected to use
consumer install hooks. Signals that carry the internal `knownGood` annotation
are downweighted rather than suppressed. Inline script content may still
produce findings, but file-based
commands such as `node install.js` are not inspected by this stage.

## Agent-facing JSON

Vexes is callable by agents through its CLI; no MCP server is required. Normal
successful structured paths for `scan`, `analyze`, `fix`, `monitor --ci`,
`inspect`, `doctor`, and `licenses` use the envelope below. Payloads remain
command-specific. `explain`/`triage`, guard setup/uninstall, watch streams, and
some early errors are text paths today, so callers must check exit status and
validate JSON before trusting stdout.

```json
{
  "schemaVersion": "1.0",
  "generator": { "name": "vexes", "version": "0.6.1", "engine": "v22.13.0" },
  "timestamp": "2026-08-28T00:00:00.000Z",
  "command": "scan",
  "target": {
    "dir": "/project",
    "lockfiles": ["package-lock.json"],
    "ecosystems": ["npm"]
  },
  "complete": true,
  "result": { "complete": true, "warnings": [] },
  "summary": { "total": 33, "vulnerable": 219, "critical": 27, "high": 109, "moderate": 83, "low": 0, "suppressed": 0,
    "directImportEvidence": { "foundStatic": 0, "foundDynamic": 0, "notFound": 0, "unknown": 33 },
    "reachable": 0, "lazy": 0, "dead": 0, "unreachable": 0 },
  "findings": [ { "id": "GHSA-23hp-3jrh-7fpw", "package": "tar", "version": "6.1.0", "ecosystem": "npm",
    "severityLevel": { "level": "CRITICAL", "order": 4 },
    "confidence": "proven", "reachability": "unknown", "importEvidence": "unknown",
    "signal": "KNOWN_COMPROMISED", "advisories": ["GHSA-23hp-3jrh-7fpw", "CVE-2026-59873"],
    "fixed": ">= 7.5.19", "fixCommand": "npm install -- tar@7.5.21",
    "llmSummary": "[CRITICAL] tar@6.1.0 (npm) — CVE-2026-59873: node-tar: Decompression/parse DoS via unlimited input. Fixed in >= 7.5.19. No direct import found in this project's source (may still load via tooling or dynamic paths)." } ]
}
```

This is an abridged example based on a dated demo scan. Because `demo/` is lockfiles-only,
the current implementation emits `unknown` import evidence; absence of source
is not evidence that a dependency is unused. For documented structured paths, `complete: false`
means the result must not be treated as clean. Exit codes are normally `0` for
complete requested checks with no findings at the active threshold, `1` for
findings at the threshold, and `2` for error/incomplete; exit 0 is not a safety
verdict, and callers should still validate each command path. A scan's
`fixCommand` is derived from advisory fixed-version
events; use `vexes fix` for OSV- and registry-cross-checked candidates, then
generate and rescan the resolved lockfile. `vexes doctor` is an installation smoke test, not an accuracy or
security attestation. Full details: `wiki/Agent-Integration.md`.

## Architecture

```
bin/vexes.js          CLI entrypoint, command router
src/
  cli/
    parse-args.js     Hand-rolled argument parser
    config.js         Config loading with prototype pollution protection
    output.js         Terminal output, ANSI colors, spinner, sanitization
  commands/
    scan.js           Vulnerability scanning via OSV
    analyze.js        4-layer behavioral analysis
    fix.js            OSV-cross-checked fix candidates
    guard.js          Experimental public-npm assessment/install boundary
    monitor.js        CI annotations, SARIF output, watch mode
  core/
    constants.js      URLs, thresholds, exit codes
    fetcher.js        Shared JSON HTTP client with retry/timeout/backoff
    logger.js         Leveled logger with terminal-control sanitization
    allowlists.js     Curated install-hook names, popular package sets
  parsers/
    npm.js            package-lock.json v1/v2/v3, package.json fallback
    pnpm.js           pnpm-lock.yaml v6/v9
    yarn.js           yarn.lock v1 (classic) and v2+ (Berry)
    pypi.js           requirements.txt (-r recursive), poetry.lock, Pipfile.lock, pyproject.toml
    cargo.js          Cargo.lock
    go.js             go.mod (preferred), go.sum (fallback)
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
    provenance.js     Attestation field decoding and cross-checking
  cache/
    advisory-cache.js SQLite-backed cache with TTL, corruption recovery
  vendor/
    acorn.mjs         Vendored acorn parser (zero npm deps)
test/
  test-ast-inspector.js   AST detection + selected benign controls
  test-behavioral.js      Behavioral profiling + diffing
  test-cache.js           SQLite cache, TTL, corruption resilience
  test-dep-graph.js       Typosquat detection
  test-parse-args.js      Argument parser
  test-parsers.js         All lockfile/manifest parsers
  test-redteam.js         Synthetic attack-technique fixtures
  test-robustness.js      Input validation, edge cases, security
```

## Security design principles

1. **Fail loud, not clean.** A scanner that reports clean when it actually failed is misleading. If queries fail, vexes exits with code 2 and prints `SCAN INCOMPLETE`. Invalid ecosystems are rejected instead of silently scanning nothing.

2. **Zero external runtime npm dependencies.** Acorn is vendored; SQLite and the remaining runtime facilities come from Node.js.

3. **Terminal injection defenses.** Shared output and logger paths sanitize CSI, OSC, DCS/APC/PM/SOS, C1 controls, and bare ESC bytes. Some command-specific text paths still need complete sanitizer coverage, so terminal output is not treated as a security boundary.

4. **Prototype pollution protection.** Config merging drops `__proto__`, `constructor`, and `prototype` keys.

5. **Command-construction defenses.** Guard uses `execFileSync` (no shell) and accepts only explicit public-registry npm installs with a narrow flag grammar. Displayed upgrade commands validate package/version grammar, use POSIX-shell quoting, and add option boundaries where supported; they still require review before execution. Automatic shell-wrapper setup is currently disabled because it cannot faithfully route commands outside that narrow grammar.

6. **Bounded registry artifact fetching.** Tarball downloads enforce streamed
   compressed/decompressed size limits. The initial URL and every redirect hop
   must use HTTPS on the npm/PyPI tarball host allowlist (maximum five
   redirects). npm bytes are checked against registry SRI or shasum metadata
   when supplied; dynamic extraction refuses missing npm digest metadata.

7. **Cache resilience.** Corrupted advisory rows are deleted; corrupt metadata and signal rows are treated as misses. Degraded analysis results are not cached. Analyze fetches current registry metadata and checks evidence plus OSV fingerprints before reusing a signal row. TTL is clamped (max 7 days advisory, 30 days for the historically named metadata/analysis-signal setting).

8. **Cross-check fix candidates.** The `fix` command asks OSV about each candidate before presenting it. This means "no advisory OSV currently returned," not proof that the version is safe.

9. **Signal policy is explicit.** Every documented analysis signal can be set to `"off"`; the legacy `KNOWN_COMPROMISED` switch also controls the newer OSV signal names when they are not configured separately. Repository-local config can therefore suppress ordinary report evidence, so review committed policy or use `--no-project-config`. Use `--no-user-config` as well when runner-level policy must not affect a reproducible enforcement result. Guard clears project/user signal suppression and ignore entries before making an install decision.

10. **Allowlisting is a scoring adjustment.** Signals carrying `knownGood` evidence are downweighted, not suppressed. Inspectable inline scripts still run through the pattern analyzer; file-based install commands may not.

11. **Suspicious Unicode presence.** Package names are checked for invisible characters, BIDI overrides, and non-ASCII characters. This is not a Unicode-confusable or visual-homoglyph mapping, and normal public-registry coordinate rules make the check largely dormant on live metadata.

12. **Occurrence-aware lockfile identity.** npm guard preserves individual lockfile occurrences and binds approval to version, public-registry resolved URL, and integrity fields. It does not independently hash or verify downloaded or installed bytes.

## License

Apache-2.0

## Author

Shadoe Myers ([@penumbraforge](https://github.com/penumbraforge))
