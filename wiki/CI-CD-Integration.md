# CI/CD Integration

## GitHub Actions

### Basic vulnerability scanning

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22.13'
      - name: Security scan
        run: npx @penumbraforge/vexes monitor --ci --severity high --no-user-config --no-project-config
```

This will:
- Scan the supported dependency records vexes extracts from your lockfiles
- Output GitHub Actions annotations (errors/warnings on the PR)
- Fail the workflow if any HIGH or CRITICAL vulnerabilities are found

Unsupported lockfile schemas and partial dependency inputs exit 2. In
particular, Ruby/PHP/NuGet/Java manifest fallbacks are not treated as resolved
graphs, Ruby locks without Bundler SHA-256 `CHECKSUMS` remain unresolved,
replaced Go modules are excluded, and pnpm support is limited to lockfile major
versions 6 and 9.

`--no-project-config` is intentional for pull-request enforcement: it prevents
the checked-out branch from changing the run through `.vexesrc.json`.
`--no-user-config` also removes runner-account policy so results do not vary
with a self-hosted runner's trusted config. Omit either flag only when that
configuration source is part of the policy you intend to trust. The composite
`action.yml` supplies both flags internally.

### SARIF upload to GitHub code scanning

```yaml
name: Security Scan (SARIF)
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22.13'
      - name: Run vexes
        run: npx @penumbraforge/vexes monitor --ci --sarif --no-user-config --no-project-config > results.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Where GitHub code scanning is enabled, uploaded SARIF results appear in the
repository's **Security** tab under Code Scanning Alerts.

### Deep analysis on PRs

```yaml
name: Supply Chain Analysis
on: [pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22.13'
      - name: Deep analysis
        id: vexes-analysis
        run: npx @penumbraforge/vexes analyze --deep --strict --json --no-user-config --no-project-config > analysis.json
        continue-on-error: true
      - name: Upload analysis
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vexes-analysis
          path: analysis.json
```

`--deep` is bounded rather than whole-package coverage, so a sampled run marks
itself incomplete and exits 2 even when the sampling operation succeeds. The
example uses `continue-on-error` so the evidence artifact is still uploaded;
your policy should decide whether that expected coverage status blocks the job.

### Scan only npm dependencies

```yaml
- name: npm security scan
  run: npx @penumbraforge/vexes scan --ecosystem npm --severity critical --no-user-config --no-project-config
```

## JSON output for custom integrations

Normal successful JSON paths for `scan`, `analyze`, and `monitor --ci` support
machine-readable output. Other commands are documented in
[Agent Integration](Agent-Integration.md); early error paths and
`explain`/`triage` are not uniformly JSON yet.

```bash
# Scan
vexes scan --json | jq '.vulnerabilities[] | {package, severity, fixed}'

# Analyze
vexes analyze --json | jq '.results[] | select(.riskLevel == "CRITICAL")'

# Monitor
vexes monitor --ci --json | jq '.summary'
```

## Exit codes

| Code | Meaning | CI interpretation |
|------|---------|------------------|
| `0` | Requested checks complete, no findings at active threshold; not a safety verdict | Pass |
| `1` | Vulnerabilities/signals found | Fail (configurable via `--severity`) |
| `2` | Error or incomplete scan | Fail (the requested checks did not all complete) |

**Exit code 2 is intentionally a failure.** A partial requested check must not
be reported as clean. If you see exit code 2, investigate the warnings.

## Caching in CI

By default, vexes caches scan advisory results for 1 hour and analyze signal
rows for 24 hours in `~/.cache/vexes/`. Analyze still fetches current registry
metadata and requires its evidence fingerprint plus current OSV evidence to
match before reusing a signal row. In CI:

- **Ephemeral runners:** Cache is rebuilt each run. Consider `--cached` only if you persist the cache directory between runs; cache misses still query OSV.
- **Self-hosted runners:** A persistent cache can reduce repeated OSV and
  analysis work. Registry metadata is still fetched for analyze.

To persist the cache in GitHub Actions:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/vexes
    key: vexes-cache-${{ hashFiles('**/package-lock.json') }}
    restore-keys: vexes-cache-
```

## Severity thresholds

Thresholds filter which severities produce findings/CI failure; choose policy
based on your repository rather than treating these as safety levels:

| Threshold | Reported severities |
|-----------|---------------------|
| `--severity critical` | CRITICAL only |
| `--severity high` | HIGH and CRITICAL |
| `--severity moderate` | MODERATE, HIGH, and CRITICAL |
| `--severity low` | LOW and above; highest expected volume |
