# FAQ

## General

### Why zero dependencies?

The dependency chain IS the attack surface. A security tool that depends on 500 npm packages can itself be compromised through those dependencies. vexes vendors acorn (the JS parser) and uses only Node.js built-in modules (`node:sqlite`, `node:zlib`, `node:fs`, `node:crypto`, `fetch`).

### Why does vexes require Node.js >= 22.5.0?

vexes uses `node:sqlite` (DatabaseSync) for caching, which was stabilized in Node.js 22.5.0. It also uses the built-in `fetch` API (stable since Node.js 21).

### Is this different from `npm audit`?

Yes. `npm audit` only checks npm packages against the GitHub Advisory Database. vexes:
- Scans **9 ecosystems** (npm, pnpm, Yarn, PyPI, Cargo, Go, Ruby, PHP, NuGet, Java, Homebrew)
- Uses **OSV.dev** which aggregates from multiple advisory sources
- Performs **behavioral analysis** (maintainer changes, capability escalation, typosquatting)
- Can **inspect actual source code** via tarball analysis
- Provides **pre-install protection** via the guard command

### How does vexes compare to Socket, Snyk, or Dependabot?

| Feature | vexes | Socket | Snyk | Dependabot |
|---------|-------|--------|------|------------|
| Zero dependencies | Yes | No | No | N/A |
| Self-hosted | Yes | Cloud | Cloud | GitHub |
| Behavioral analysis | Yes | Yes | No | No |
| AST code inspection | Yes | Yes | No | No |
| Lockfile diffing | Yes | No | No | No |
| Cross-ecosystem | Yes (9) | JS/Python | Many | Many |
| Cost | Free | Paid | Paid | Free |
| SARIF output | Yes | Yes | Yes | N/A |

## Scanning

### Why does scan exit with code 2?

Exit code 2 means the scan was **incomplete** -- some packages could not be checked. This happens when:
- OSV.dev API is down or rate-limiting
- Lockfile parsing failed
- Network timeout

vexes treats an incomplete scan as an error because silently reporting clean when you can't verify safety is dangerous.

### Can I scan without internet access?

Partially. If you have a populated cache (`~/.cache/vexes/`), you can use `--cached` to scan using only cached results. But the initial population requires internet access to query OSV.dev and registry APIs.

### Why are some vulnerabilities marked CRITICAL with no CVSS score?

vexes follows the principle of **fail-safe defaults for security tools**: if a vulnerability has no severity information (no CVSS score, no database_specific severity), it's assumed to be CRITICAL rather than being silently downgraded or ignored.

## Analysis

### What does "risk level UNKNOWN" mean?

UNKNOWN means vexes could not fetch the package's registry metadata (network error, package not found, etc.). The package could not be fully analyzed. In `--verbose` mode, UNKNOWN packages are shown. By default, they're hidden to reduce noise.

### Why is esbuild flagged?

esbuild has a legitimate postinstall script that downloads platform-specific binaries. vexes flags it at **LOW** severity (not HIGH) because it's in the known-good allowlist. The signal is visible in verbose mode but doesn't contribute significantly to the risk score.

### What are "phantom dependencies"?

A phantom dependency is a brand-new package (< 7 days old on the registry) that was added as a dependency. In the axios RAT attack, `plain-crypto-js` was a phantom dependency -- created hours before being added to the compromised axios version. Phantom dependencies are flagged at CRITICAL severity.

## Guard

### Does guard actually run my install?

Only if the analysis passes. Guard:
1. Takes a lockfile snapshot
2. Runs a dry-run install (`--package-lock-only --ignore-scripts`)
3. Diffs the lockfile
4. Analyzes new/changed packages
5. **Restores the original lockfile**
6. Only runs the real install if the analysis is clean

If guard blocks the install, your lockfile is unchanged and nothing was installed.

### Can I bypass guard?

- For HIGH-risk warnings: use `--force` or type `y` at the interactive prompt
- For CRITICAL findings: guard always blocks. Run the install command directly to bypass.
- To remove guard entirely: `vexes guard --uninstall`

## Troubleshooting

### "cache unavailable" warning

The SQLite cache couldn't be opened. This usually means:
- The cache directory doesn't exist and can't be created (permissions)
- The cache database is corrupted

vexes continues scanning without caching. To fix: `rm -rf ~/.cache/vexes` and let vexes recreate it.

### "lockfiles found but all failed to parse"

Your lockfile exists but is malformed JSON or an unsupported format version. Check:
- Is the lockfile valid JSON? (`cat package-lock.json | python3 -m json.tool`)
- Is it a supported version? (vexes supports package-lock.json v1, v2, v3)

### Scans are slow

First scan fetches all data from APIs. Subsequent scans use the cache (1-hour TTL for advisories). To speed things up:
- Use `--ecosystem npm` to scan only one ecosystem
- Use `--cached` to skip freshness checks
- Use `--severity critical` to reduce output processing

### Why can't I disable KNOWN_COMPROMISED?

Four critical signals are undisableable by design: `KNOWN_COMPROMISED`, `PHANTOM_DEPENDENCY`, `CIRCULAR_STAGING`, and `CAPABILITY_ESCALATION`. These detect active supply chain attacks. Allowing them to be disabled via `.vexesrc.json` would let a malicious repo config suppress all detection. If you need to ignore a specific known vulnerability, use the `ignore` field in config instead.

### Does vexes support pnpm and Yarn?

Yes. vexes automatically discovers and parses `pnpm-lock.yaml` (v6 and v9) and `yarn.lock` (v1 classic and v2+ Berry format) alongside `package-lock.json`. All three are treated as npm-ecosystem lockfiles and queried against the same OSV database.
