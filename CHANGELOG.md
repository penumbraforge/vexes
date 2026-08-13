# Changelog

All notable changes to vexes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.2.0] — 2026-08-12

The accuracy release. Severity reporting, version attribution, and PyPI
analysis are now trustworthy; CI is green and releases are unblocked.

### Fixed
- **CVSS severity extraction** — OSV puts the CVSS vector *string* in
  `severity[].score`; the parser expected a `.vector` field that never
  exists, so every PYSEC/RUSTSEC/Go advisory fell through to a false
  `CRITICAL` (87 of 219 findings on the demo fixtures). Vectors now run the
  full CVSS v3.1 spec math; numeric scores pass through; malformed entries
  can never poison the result. Demo distribution is now 26 critical /
  108 high / 84 moderate — and regression-pinned against real advisory
  fixtures.
- **`analyze` inspects the installed version** — registry metadata
  (publisher, install scripts, dependency diff, publish timing) was
  previously derived from `dist-tags.latest` regardless of the lockfile.
  All Layer 3/4 signals are now anchored to the version actually installed;
  `latestAvailable` is reported separately.
- **PyPI Layer 4 resurrected** — the versioned PyPI endpoint returns no
  `releases` map, leaving publish-history signals permanently null. vexes
  now uses the unversioned endpoint and emits `majorJump` and `dormancyMs`
  for PyPI packages. (`maintainerChanged` remains npm-only: PyPI's JSON API
  has no per-release publisher — documented, not faked.)
- **`--deep` findings count again** — risk levels are re-derived after
  provenance and deep-tarball scoring; previously a package pushed over a
  threshold by deep inspection kept its old level and could be filtered out
  of the report and the exit code.
- **Time-bomb tests defused** — red-team fixtures with historical attack
  dates crossed the 90-day maintainer-change decay window ~3 months after
  authorship and turned CI red. The analysis clock is now injectable
  (`analyzePackage(..., { now })`); attack reconstructions analyze as of
  the attack date, and boundary tests pin the decay cliff at 89/91 days.

### Changed
- **Advisory cache schema v2** — cached rows store normalized severities,
  so caches written before the CVSS fix are dropped on first use after
  upgrade (`PRAGMA user_version`). Without this, upgraded installs would
  keep serving the old false CRITICALs until TTL expiry.

## [0.1.1] — 2026-03-31

Initial public release: cross-ecosystem dependency scanning (npm incl.
pnpm/yarn lockfiles, PyPI, Cargo, Go, Ruby, PHP, NuGet, Maven) against the
OSV database, 4-layer analysis engine for npm (metadata signals, dependency
graph, behavioral diff, AST inspection), zero runtime dependencies.
