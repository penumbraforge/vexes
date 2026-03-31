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
          node-version: '22'
      - name: Security scan
        run: npx @penumbraforge/vexes monitor --ci --severity high
```

This will:
- Scan all dependencies in your lockfiles
- Output GitHub Actions annotations (errors/warnings on the PR)
- Fail the workflow if any HIGH or CRITICAL vulnerabilities are found

### SARIF upload to GitHub Advanced Security

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
          node-version: '22'
      - name: Run vexes
        run: npx @penumbraforge/vexes monitor --ci --sarif > results.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

SARIF results appear in the **Security** tab of your repository under Code Scanning Alerts.

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
          node-version: '22'
      - name: Deep analysis
        run: npx @penumbraforge/vexes analyze --strict --json > analysis.json
      - name: Upload analysis
        uses: actions/upload-artifact@v4
        with:
          name: vexes-analysis
          path: analysis.json
```

### Scan only npm dependencies

```yaml
- name: npm security scan
  run: npx @penumbraforge/vexes scan --ecosystem npm --severity critical
```

## JSON output for custom integrations

All commands support `--json` for machine-readable output:

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
| `0` | Clean | Pass |
| `1` | Vulnerabilities/signals found | Fail (configurable via `--severity`) |
| `2` | Error or incomplete scan | Fail (scanner couldn't verify safety) |

**Exit code 2 is intentionally a failure.** A security scanner that reports clean when it couldn't actually check all packages is a false sense of security. If you see exit code 2, investigate the warnings.

## Caching in CI

By default, vexes caches advisory results for 1 hour and metadata for 24 hours in `~/.cache/vexes/`. In CI:

- **Ephemeral runners:** Cache is rebuilt each run. Consider `--cached` only if you persist the cache directory between runs.
- **Self-hosted runners:** Cache persists between runs, which speeds up repeated scans significantly.

To persist the cache in GitHub Actions:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/vexes
    key: vexes-cache-${{ hashFiles('**/package-lock.json') }}
    restore-keys: vexes-cache-
```

## Severity thresholds

Choose the right threshold for your workflow:

| Threshold | Use case |
|-----------|----------|
| `--severity critical` | Production deploys -- only block on critical issues |
| `--severity high` | PR checks -- catch critical and high severity (recommended default) |
| `--severity moderate` | Security-sensitive repos -- catch everything significant |
| `--severity low` | Maximum coverage -- very noisy |
