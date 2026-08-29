# FAQ

## General

### Why zero external runtime npm dependencies?

Vexes has zero external runtime npm dependencies. It vendors Acorn (the JS
parser) and otherwise uses Node.js built-in modules and `fetch`. That keeps its
npm dependency surface small, but does not make the tool itself risk-free.

### Why does vexes require Node.js >= 22.13.0?

vexes uses `node:sqlite` (`DatabaseSync`) for caching. The module first appeared
in Node.js 22.5.0 behind `--experimental-sqlite`; 22.13.0 is the first 22.x
release where it can be used without that flag. Built-in `fetch` is also used.

### Is this different from `npm audit`?

They overlap on npm vulnerability reporting, but vexes also:
- Scans **10 ecosystems** (npm incl. pnpm/Yarn, PyPI, Cargo, Go, Ruby, PHP,
  NuGet, Java, Hex, Pub). Analysis depth varies: dependency-staging and
  attestation checks are npm-specific, bounded file sampling supports npm/PyPI,
  and the remaining ecosystems use OSV scanning.
- Uses **OSV.dev** which aggregates from multiple advisory sources
- Surfaces **heuristic evidence** (publishing-account changes, capability
  escalation, and name similarity)
- Can inspect a bounded selected-file sample from npm/PyPI tarballs
- Provides an experimental public-npm assessment/install boundary with lifecycle scripts disabled

### How does vexes compare to other dependency tools?

Vexes' present niche is a small local CLI that combines OSV lookup with
inspectable heuristics and emits JSON/SARIF without external runtime npm
dependencies. It is experimental and does not have the production evidence,
maintained intelligence, policy breadth, hosted workflow, or support guarantees
of mature commercial and platform tools. Competitor capabilities and pricing
change frequently, so this project does not publish an uncited feature matrix.

## Scanning

### Why does scan exit with code 2?

Exit code 2 means the scan was **incomplete** -- some packages could not be checked. This happens when:
- OSV.dev API is down or rate-limiting
- Lockfile parsing failed or its schema is unsupported
- Only a partial manifest fallback was available, or a replaced Go module was excluded
- Network timeout

vexes treats an incomplete scan as an error because a partial advisory check
must not be reported as clean.

### Can I scan without internet access?

Partially. `--cached` accepts stale cache entries without refreshing them, but a
cache miss still requires OSV access. It is not a guaranteed offline mode.

### Why are some vulnerabilities marked CRITICAL with no CVSS score?

vexes follows the principle of **fail-safe defaults for security tools**: if a vulnerability has no severity information (no CVSS score, no database_specific severity), it's assumed to be CRITICAL rather than being silently downgraded or ignored.

## Analysis

### What does "risk level UNKNOWN" mean?

UNKNOWN means vexes could not fetch the package's registry metadata (network error, package not found, etc.). The package could not be fully analyzed. In `--verbose` mode, UNKNOWN packages are shown. By default, they're hidden to reduce noise.

### Why is esbuild flagged?

esbuild is a curated exact-name example of an expected install hook. Its
install-script-presence signal is labeled **LOW**, remains visible in verbose
mode, and receives the documented 0.2x allowlist multiplier. That entry is a
tuning choice, not a security endorsement of any package version.

### What are "phantom dependencies"?

This legacy signal name means a dependency added by the analyzed npm release
relative to its previous published version is very new on the registry, or has
sparse maintainer/version metadata. It does not mean the dependency was newly
added to the project being scanned. Newness is a review signal, not evidence
that the dependency is malicious.

## Guard

### Does guard actually run my install?

Guard is experimental and public-registry npm-only. It:

1. Copies the current manifest and lockfile into a disposable resolver project
2. Runs npm there in lockfile-only mode with lifecycle scripts disabled
3. Diffs individual lockfile occurrences and validates registry identity fields
4. Checks exact proposed versions against OSV, registry metadata, and behavioral signals
5. In human mode, applies an approved manifest/lockfile and installs with `--ignore-scripts`
6. Verifies the final manifest plus occurrence/version/resolved URL/integrity fields

JSON mode stops after assessment and does not install. If npm fails after
approval, `package.json` and `package-lock.json` are restored, but `node_modules`
may be partially modified. Guard does not independently hash installed bytes.

### Can I bypass guard?

- For HIGH heuristic evidence: use `--force`; HIGH can also be approved interactively
- For known advisories, CRITICAL evidence, or incomplete analysis: guard always blocks internally. Running npm directly bypasses guard.
- To remove a wrapper installed by an older release: `vexes guard --uninstall`

Automatic `guard --setup` is currently disabled; invoke guard explicitly.

## Troubleshooting

### "cache unavailable" warning

The SQLite cache couldn't be opened. This usually means:
- The cache directory doesn't exist and can't be created (permissions)
- The cache database is corrupted

vexes continues scanning without caching. After stopping running vexes
processes, move the cache directory aside (or delete only that directory) and
let vexes recreate it; keep the moved copy until the new cache opens normally.

### "lockfiles found but all failed to parse"

Your lockfile exists but is malformed JSON or an unsupported format version. Check:
- Is the lockfile valid JSON? (`cat package-lock.json | python3 -m json.tool`)
- Is it a supported version? (vexes supports package-lock.json v1, v2, v3)

### Scans are slow

An uncached scan queries OSV; analysis also queries supported registry APIs.
Subsequent runs can reuse the cache (1-hour default TTL for advisories). To
reduce work:
- Use `--ecosystem npm` to scan only one ecosystem
- Use `--cached` to accept stale hits without a freshness check (misses still use the network)

### Can I disable an analysis signal?

Yes. Every documented analysis signal can be set to `"off"` under
`analyze.signals`. The legacy `KNOWN_COMPROMISED` switch also controls
`KNOWN_MALICIOUS` and `KNOWN_VULNERABILITY` when their own switches are absent.
Because project-local config can suppress evidence, review `.vexesrc.json` in
security-sensitive repositories. The separate top-level `ignore` field accepts
an explicitly reviewed advisory, package, or package-version finding. Pass
`--no-project-config` when the checkout should not choose report policy. Guard
clears configured ignores and signal suppression before its install decision.
For reproducible CI, add `--no-user-config` so runner-account policy cannot
change the result either.

### Does vexes support pnpm and Yarn?

Yes. vexes automatically discovers `pnpm-lock.yaml` (v6/v9 forms) and
`yarn.lock` (v1 classic/v2+ Berry forms) alongside `package-lock.json` and
best-effort extracts dependency records. All three are treated as npm-ecosystem
inputs for OSV queries. pnpm lockfile majors other than 6 or 9 fail visibly;
they are not guessed as an empty dependency set.
