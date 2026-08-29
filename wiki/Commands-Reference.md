# Commands Reference

## Global flags

These flags are parsed globally, but command support differs. In particular,
`--json` is not yet uniform for `explain`/`triage`, guard setup/uninstall, watch
streams, or some early error paths.

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |
| `--verbose` | `-v` | Show debug output |
| `--quiet` | `-q` | Only show errors |
| `--no-color` | | Disable ANSI colors |
| `--json` | `-j` | Machine-readable JSON output |
| `--no-user-config` | | Ignore `~/.config/vexes/config.json` for this invocation |
| `--no-project-config` | | Ignore `.vexesrc.json`; useful when the checked-out repository must not choose scan/report policy |

---

## `vexes scan`

Enumerate supported dependency inputs, query OSV.dev, and report versions that
OSV places in affected vulnerability ranges.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | Current working directory |
| `--ecosystem <name>` | Filter to one ecosystem: `npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `nuget`, `java`, `hex`, `pub` | All detected |
| `--severity <level>` | Minimum severity to report: `critical`, `high`, `moderate`, `low` | `moderate` |
| `--fix` | Show advisory-derived upgrade hints; rescan the resolved result | Off |
| `--cached` | Use cached results without freshness check | Off |
| `--min-reachability <grade>` | Deprecated compatibility option; validated, warned, and ignored so import evidence never filters findings | Off |

### Supported lockfiles

| Ecosystem | Preferred input | Fallback or partial input |
|-----------|-----------------|---------------------------|
| npm | `package-lock.json` (v1, v2, v3), `pnpm-lock.yaml` (v6, v9), `yarn.lock` (v1, v2+) | `package.json` (lower confidence) |
| PyPI | `Pipfile.lock`, `poetry.lock` | `requirements.txt` (with `-r` recursive), `pyproject.toml` (PEP 621 + Poetry) |
| Cargo | `Cargo.lock` | |
| Go | `go.mod` | `go.sum` (checksum history) |
| Ruby | `Gemfile.lock` | `Gemfile` |
| PHP | `composer.lock` | `composer.json` |
| NuGet | `packages.lock.json` | `*.csproj` |
| Java | `gradle.lockfile` | `pom.xml` |
| Hex | `mix.lock` | |
| Dart/pub | `pubspec.lock` | |

Ruby/PHP/NuGet/Java manifest fallbacks can yield exact pins but are always
reported incomplete because they are not resolved graphs. `go.mod` is preferred
over checksum history when present; replaced modules are excluded and make the
scan incomplete. When only `go.sum` exists, its checksum history can include
modules no longer active in the build. An unrecognized lockfile schema is a
parse error, not an empty dependency list. pnpm lockfile major versions 6 and 9
are supported; other majors fail visibly. Ruby lock entries require both the
canonical RubyGems remote and a matching Bundler `CHECKSUMS` SHA-256 entry;
legacy unchecked locks are incomplete.

### JSON output schema

`scan --json` emits the versioned envelope (`schemaVersion`, `generator`, `target`, `findings[]`, ...) described in [Agent-Integration](Agent-Integration.md). The fields below are preserved inside it for backward compatibility.

```json
{
  "version": "0.6.1",
  "timestamp": "2026-03-31T...",
  "command": "scan",
  "complete": true,
  "summary": { "total": 124, "vulnerable": 3, "critical": 1, "high": 1, "moderate": 1, "low": 0 },
  "warnings": [],
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx",
      "displayId": "GHSA-xxxx",
      "aliases": ["CVE-2024-xxxx"],
      "summary": "Description of the vulnerability",
      "severity": "CRITICAL",
      "package": "express",
      "version": "4.17.1",
      "ecosystem": "npm",
      "fixed": ">= 4.19.2",
      "url": "https://osv.dev/vulnerability/GHSA-xxxx",
      "references": []
    }
  ]
}
```

Each normalized `findings[]` record also carries canonical direct-import
evidence: `found_static`, `found_dynamic`, `not_found`, or `unknown`. The legacy
`reachability` field remains for compatibility. Neither field suppresses an
advisory. Commands shown by `scan --fix` come directly from OSV fixed-version
events; use `vexes fix` for candidate cross-checking.

---

## `vexes analyze`

Heuristic registry, install-script, dependency-metadata, and bounded source-pattern analysis.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | cwd |
| `--ecosystem <name>` | Filter: `npm` or `pypi` | npm and PyPI inputs |
| `--deep` | Download a tarball and inspect a bounded selected-file sample | Off |
| `--explain <pkg>` | Detailed breakdown for a specific package | |
| `--strict` | Exit 1 when a non-ignored result meets the active severity filter | Off |
| `--verbose` | Show all signals including LOW | Off |

`--deep` is deliberately non-exhaustive. When it samples a package, JSON marks
the requested stage and top-level result incomplete and the command exits 2,
while retaining any findings. npm tarballs are checked against registry SRI or
shasum metadata when available; missing npm digest metadata is reported. The
current PyPI sdist path is not digest-bound.

`analyze` currently performs registry analysis only for npm and PyPI inputs.
Use `scan` for advisory matching in the other supported ecosystems.

An unavailable npm provenance lookup for a package selected for that stage, or
a present bundle whose payload cannot be decoded, makes analyze/inspect
incomplete. Decoded bundles are compared, not cryptographically verified.

### Risk scoring

Composite scores account for context:
- **New packages** (< 30 days): 2x weight
- **Single maintainer**: 1.5x weight
- **Eligible allowlisted signals** (for exact-name entries such as esbuild and
  sharp): 0.2x weight for the signal carrying `knownGood`, not the whole package
- **3+ unique signals**: 1.5x multiplier
- **5+ unique signals**: 2x multiplier

Risk levels: `NONE` (0), `LOW` (> 0), `MODERATE` (>= 5), `HIGH` (>= 15), `CRITICAL` (>= 30)

> **Also shipped, documented in [Agent-Integration](Agent-Integration.md):** `inspect` (single-package evidence), `doctor` (installation smoke test), `licenses` (flat declared-license inventory), and `explain` (AI-assisted triage, opt-in). `analyze` and `inspect` also accept experimental `--sandbox` telemetry.

`--sandbox` may execute one selected npm entrypoint per candidate from a bounded
partial extraction under an accepted Linux `bwrap` host; analyze considers at
most five HIGH/CRITICAL candidates and inspect considers its target. It does
not run lifecycle hooks. PyPI
dynamic extraction and execution are unsupported and refused; static PyPI
`--deep` sampling remains available. The accepted Linux `bwrap` layout omits
the user's home/project and contains writes to the extracted workdir and
throwaway temp, but exposes `/usr`, `/bin`, and loader libraries read-only;
`/etc` is not mounted. This is private-path isolation, not total read isolation.
The current macOS profile is refused because its broad read rule also exposes
arbitrary user files. The recorder observes selected Node APIs, receives a
minimal child environment, and is not
tamper-resistant or inherited by child processes. Do not use it as an
escape-proof boundary for known malware.
Dynamic npm extraction also refuses to proceed without registry SRI or shasum
metadata. Because empty recorder output is not trusted as negative evidence, a
requested sandbox stage remains incomplete / exit 2 even when execution
launches; positive observations are retained. A timeout or nonzero child exit
is a failed stage, not behavioral evidence.

---

## `vexes fix`

Generate npm fix candidates. Each candidate is checked against the advisories
OSV returns at request time and for registry existence. This is not a guarantee
of compatibility, future safety, or absence of undisclosed vulnerabilities.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | cwd |
| `--json` | Machine-readable output | Off |

### How candidate cross-checking works

1. Scan for vulnerabilities (same as `vexes scan`)
2. Extract the fix versions present in the returned OSV advisory ranges
3. Determine the highest fix threshold across the package's advisories
4. Cross-check candidates against OSV and select the lowest candidate that clears that threshold
5. Confirm that the version is present in registry metadata
6. Validate the coordinate and generate a POSIX-shell-quoted candidate command
   (with an option boundary where supported)

If all known fix versions are themselves vulnerable, vexes checks the `latest`
tag as a fallback. These are OSV- and registry-cross-checked candidates, not
verified remediation: generate the resolved lockfile, rescan it, and test the
upgrade.

**Currently supports:** npm. PyPI and Cargo fixes are unsupported.

---

## `vexes guard`

**Experimental, public-registry npm only.** Guard accepts explicit
`npm install`/`i`/`add <package>` requests with a narrow flag grammar. It copies
`package.json` and `package-lock.json` into a disposable resolver project, runs
npm there in lockfile-only mode with scripts disabled, and analyzes every new
or changed lockfile occurrence at the exact proposed version. Each changed
artifact must have a public-registry HTTPS URL and integrity value, with
available registry metadata agreeing.

In human mode, an approved resolution is applied with
`npm install --ignore-scripts --no-audit --no-fund`; lifecycle scripts stay
disabled. The final manifest and lockfile must match approved occurrence,
version, resolved URL, and integrity fields. JSON mode is assessment-only and
does not install. This does not independently hash installed bytes and is not a
transaction: manifest/lockfile replacements are atomic per file and restored
on detected failure or drift, but `node_modules` may be partially changed and
an actively racing same-user process is outside the boundary. Bare installs,
workspaces, local/git/URL specs, `npx`, pnpm, and Yarn are refused.

### Usage

```bash
vexes guard -- npm install <package>
```

### Options

| Flag | Description |
|------|-------------|
| `--setup` | Currently disabled and fails closed; use explicit guard invocation |
| `--uninstall` | Remove a shell wrapper installed by an older release (with rc-file backup/refusal checks) |
| `--force` | Override HIGH heuristic evidence only; known advisories, CRITICAL evidence, and incomplete analysis still block |
| `--path <dir>` | Target directory |

### Decision matrix

| Finding | TTY | Non-TTY (CI) | --force |
|---------|-----|-------------|---------|
| CRITICAL | Block | Block | Block |
| Any known OSV advisory | Block | Block | Block |
| HIGH | Prompt y/N | Block | Allow |
| Incomplete analysis | Block | Block | Block |
| No blocking evidence in completed requested checks | Allow | Allow | Allow |

### Shell wrappers

Automatic wrapper setup is disabled in the current hardening release because a
general `npm install` wrapper would intercept commands outside guard's supported
grammar. Use the explicit form above. `vexes guard --uninstall` remains available
to remove bash, zsh, or fish wrapper blocks written by an older release; it
backs up the rc file and refuses malformed marker ranges.

---

## `vexes monitor`

Continuous dependency monitoring for CI and development.

### CI mode

```bash
vexes monitor --ci                      # GitHub Actions annotations
vexes monitor --ci --severity critical  # Only fail on critical
vexes monitor --ci --sarif              # SARIF for GitHub code scanning
vexes monitor --ci --json               # Machine-readable JSON
```

### Watch mode

```bash
vexes monitor --watch                   # Watch lockfiles + poll OSV
vexes monitor --watch --interval 5      # Poll every 5 minutes
vexes monitor --watch --freshness 5     # Also poll npm/PyPI release metadata
```

Watch mode:
- Monitors lockfiles for changes using `fs.watch`
- Periodically polls OSV for new vulnerabilities
- Alerts when new/changed packages have vulnerabilities
- With `--freshness`, persists each registry latest-version baseline in SQLite;
  the first poll establishes state and later changes are graded as evidence
- Runs until Ctrl+C

### SARIF output

vexes emits SARIF 2.1.0 output intended for GitHub Code Scanning and other
SARIF consumers:

```yaml
- name: Security scan
  run: npx @penumbraforge/vexes monitor --ci --sarif --no-user-config --no-project-config > results.sarif
  continue-on-error: true
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```
