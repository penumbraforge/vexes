# Commands Reference

## Global flags

These flags work with any command:

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |
| `--verbose` | `-v` | Show debug output |
| `--quiet` | `-q` | Only show errors |
| `--no-color` | | Disable ANSI colors |
| `--json` | `-j` | Machine-readable JSON output |

---

## `vexes scan`

Enumerate dependencies from lockfiles, query OSV.dev, and report known vulnerabilities.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | Current working directory |
| `--ecosystem <name>` | Filter to one ecosystem: `npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `nuget`, `java`, `brew` | All detected |
| `--severity <level>` | Minimum severity to report: `critical`, `high`, `moderate`, `low` | `moderate` |
| `--fix` | Show upgrade commands for fixable vulnerabilities | Off |
| `--cached` | Use cached results without freshness check | Off |

### Supported lockfiles

| Ecosystem | Lockfiles | Manifests (fallback) |
|-----------|-----------|---------------------|
| npm | `package-lock.json` (v1, v2, v3), `pnpm-lock.yaml` (v6, v9), `yarn.lock` (v1, v2+) | `package.json` (lower confidence) |
| PyPI | `Pipfile.lock`, `poetry.lock` | `requirements.txt` (with `-r` recursive), `pyproject.toml` (PEP 621 + Poetry) |
| Cargo | `Cargo.lock` | |
| Go | `go.sum` | `go.mod` |
| Ruby | `Gemfile.lock` | `Gemfile` |
| PHP | `composer.lock` | `composer.json` |
| NuGet | `packages.lock.json` | `*.csproj` |
| Java | `gradle.lockfile` | `pom.xml` |
| Homebrew | `Brewfile.lock.json` | `Brewfile` |

### JSON output schema

```json
{
  "version": "0.1.0",
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

---

## `vexes analyze`

Deep behavioral analysis of the dependency supply chain using the 4-layer detection engine.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | cwd |
| `--ecosystem <name>` | Filter: `npm`, `pypi` (deep analysis requires registry metadata) | All detected |
| `--deep` | Download + AST-inspect actual package source code | Off |
| `--explain <pkg>` | Detailed breakdown for a specific package | |
| `--strict` | Exit code 1 on any signal (for CI) | Off |
| `--verbose` | Show all signals including LOW | Off |

### Risk scoring

Composite scores account for context:
- **New packages** (< 30 days): 2x weight
- **Single maintainer**: 1.5x weight
- **Known-good packages** (esbuild, sharp, etc.): 0.2x weight
- **3+ unique signals**: 1.5x multiplier
- **5+ unique signals**: 2x multiplier

Risk levels: `NONE` (0), `LOW` (> 0), `MODERATE` (>= 5), `HIGH` (>= 15), `CRITICAL` (>= 30)

---

## `vexes fix`

Generate verified fix recommendations. Every recommended version is cross-checked against OSV.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--path <dir>` | Target directory | cwd |
| `--json` | Machine-readable output | Off |

### How verification works

1. Scan for vulnerabilities (same as `vexes scan`)
2. Extract ALL fix versions from OSV advisory ranges
3. Sort candidates: prefer the highest version
4. **Cross-check** each candidate against OSV -- is it safe?
5. Verify the version exists on the registry
6. Generate the exact install command

If all known fix versions are themselves vulnerable, vexes checks the `latest` tag as a fallback.

**Currently supports:** npm. PyPI and Cargo support is planned.

---

## `vexes guard`

Pre-install protection via lockfile diffing. Analyzes new/changed packages before they execute.

### Usage

```bash
vexes guard -- npm install <package>
```

### Options

| Flag | Description |
|------|-------------|
| `--setup` | Install shell wrappers that auto-intercept `npm install` |
| `--uninstall` | Remove shell wrappers |
| `--force` | Override HIGH-risk warnings (CRITICAL findings still block) |
| `--path <dir>` | Target directory |

### Decision matrix

| Finding | TTY | Non-TTY (CI) | --force |
|---------|-----|-------------|---------|
| CRITICAL | Block | Block | Block |
| HIGH | Prompt y/N | Block | Allow |
| UNKNOWN | Allow with warning | Allow with warning | Allow |
| Clean | Allow | Allow | Allow |

### Shell wrappers

`vexes guard --setup` adds a shell function that intercepts `npm install`:

```bash
npm() {
  if [[ "$1" == "install" || "$1" == "i" || "$1" == "add" ]]; then
    command /path/to/vexes guard -- npm "$@"
  else
    command npm "$@"
  fi
}
```

The binary path is resolved at setup time (via `which vexes`) rather than using `npx` at runtime. This prevents a compromised registry from injecting code on every guarded install.

Supports bash, zsh, and fish. Remove with `vexes guard --uninstall`.

---

## `vexes monitor`

Continuous dependency monitoring for CI and development.

### CI mode

```bash
vexes monitor --ci                      # GitHub Actions annotations
vexes monitor --ci --severity critical  # Only fail on critical
vexes monitor --ci --sarif              # SARIF for GitHub Advanced Security
vexes monitor --ci --json               # Machine-readable JSON
```

### Watch mode

```bash
vexes monitor --watch                   # Watch lockfiles + poll OSV
vexes monitor --watch --interval 5      # Poll every 5 minutes
```

Watch mode:
- Monitors lockfiles for changes using `fs.watch`
- Periodically polls OSV for new vulnerabilities
- Alerts when new/changed packages have vulnerabilities
- Runs until Ctrl+C

### SARIF output

SARIF (Static Analysis Results Interchange Format) output conforms to the OASIS 2.1.0 specification and integrates with GitHub Code Scanning:

```yaml
- name: Security scan
  run: npx @penumbraforge/vexes monitor --ci --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```
