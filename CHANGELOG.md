# Changelog

All notable changes to vexes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.4.0] — 2026-08-22

The live-AI and dynamic-sandbox release. Tier B AI lands against a **local
claude-cluster** (nothing leaves home), lifecycle scripts run inside an OS
sandbox under a recorder instead of just being read, and guard is hardened.
All three keep the honesty bar: capability-verified sandboxing, refuse-by-default,
and a shared JSON envelope for every machine command.

### Added
- **Local-first AI against the claude-cluster** — `scan --ai`/`explain` detect an
  `ANTHROPIC_BASE_URL` and authenticate with a Bearer `ANTHROPIC_AUTH_TOKEN`,
  mirroring the hosted path (`ANTHROPIC_API_KEY` is still supported). The model
  is **auto-discovered** from `GET /v1/models` — no `ANTHROPIC_MODEL` needed —
  and any provider failure degrades to a per-finding error verdict without
  ever flipping the scan's `complete`. Provider precedence:
  `VEXES_AI_BASE` → `ANTHROPIC_BASE_URL` → `ANTHROPIC_API_KEY`.
- **Dynamic sandbox evidence** — `analyze --sandbox` and `inspect --sandbox`
  extract CRITICAL/HIGH candidates (npm/pyPI, top-N by risk score) to a
  throwaway dir, run their entry script inside the OS isolation primitive under
  a recorder shim (`node --require`, fd-based so it can't self-recursively
  patch), and attach a `SANDBOX_BEHAVIOR` signal plus `sandboxEvidence`
  (spawns / network attempts / outside writes) to the record. New
  `src/analysis/sandbox/harness.js` + tarball extraction to disk with a tar
  traversal guard.
- **Capability-verified sandbox detection** — `detectSandboxHost()` no longer
  trusts that a binary exists; it live-probes a benign command under each
  candidate. A seccomp-blocked `unshare` (hardened boxes, CI containers) is
  **refused**, not reported as isolated. Hosts that can't contain file writes
  (`unshare`/`firejail`) are labeled `writeIsolation: false` in the JSON;
  seatbelt and bwrap carry the full write-containment guarantee.
- **`vexes doctor`** — 14 built-in self-checks: provider reachability, model
  discovery, scan determinism, sandbox host, privilege test, internet gate.
  Reads all the config plumbing (`IGNORE_FILE`, `VEXES_*`, proxy) and answers
  "is this install trustworthy?" with a pass/fail list.
- **Shared agent envelope** (`src/cli/schema.js`, `SCHEMA_VERSION 1.0`) —
  scan, analyze, fix, monitor --ci, inspect, triage, doctor all emit the same
  `buildEnvelope` shape: `complete` (false ⇒ never "clean"), warnings,
  summary, findings-preserved verbatim. `guard` now emits through it too.

### Changed
- **Guard hardening** — manager-correct dry-run flags (`pnpm --lockfile-only`,
  `yarn --mode=update-lockfile --ignore-scripts`; npx adds none), and a
  lockfile tamper guard that verifies the post-dry-run lockfile still parses
  and any diff is reachable from the requested install; on any violation the
  backup is restored and the install is *not* executed (exit error).
- **Help-text honesty** — every formerly "needs `ANTHROPIC_API_KEY`" line now
  names the pluggable local-first reality (`VEXES_AI_BASE`, or
  `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`, or `ANTHROPIC_API_KEY`).
- **`inspect`** — dependency+file inspection with `--deep` AST scan and the
  same `--sandbox` dynamic run as analyze.

## [0.3.0] — 2026-08-12

The hardening release. SARIF output for GitHub code scanning, a rewritten
Action that can't be injection-attacked, and a batch of correctness fixes.

### Added
- **AI-assisted triage** — `vexes explain` (alias `triage`) turns a wall of
  CVEs into a prioritized, plain-English action plan: what to fix first, the
  blast radius, and the upgrade sequence. Opt-in and privacy-preserving —
  it calls the Claude API only when `ANTHROPIC_API_KEY` is set, and the
  scanner itself stays fully deterministic and offline. Composes over a scan:
  `vexes scan --format json | vexes explain`, `--input <report.json>`, or a
  fresh `--path <dir>` scan. Zero new dependencies (native fetch).
- **SARIF 2.1.0 output** — `vexes scan --format sarif` (or `--sarif <file>`
  to write a report) emits a SARIF document for
  github/codeql-action/upload-sarif and any SARIF consumer: one rule per
  advisory with `properties.security-severity`, results mapped to
  error/warning/note by severity, and `partialFingerprints` for cross-run
  dedup. `monitor --ci --sarif` shares the same generator (`src/cli/sarif.js`).
- **`ignore` config implemented** — the documented `ignore` key was never
  read. Entries may be advisory IDs (`GHSA-…`, `CVE-…`), package names, or
  `pkg@version`; matched findings are suppressed from `scan`/`analyze` and
  counted (a `suppressed` count in JSON, an "N suppressed by ignore config"
  line in text).

### Fixed
- **Config isolation** — `loadConfig()` deep-clones DEFAULTS
  (`structuredClone`) so nested `output`/`cache` objects no longer alias the
  shared template; flag writes and the cache-dir `~` expansion can no longer
  leak across calls in the same process.
- **guard rc-file safety** — `guard --uninstall` no longer splices at a
  garbage offset when the end marker is missing (which corrupted the user's
  shell rc). Missing/inverted markers now abort with manual-removal steps,
  and both setup and uninstall write a `<rcfile>.vexes-backup` before any edit.
- **Fix-command version selection** — `scan` ranked fix versions with string
  comparison, so `9.0.0` sorted above `10.0.0`. Numeric semver comparison is
  now shared from `src/core/semver.js` by both `scan` and `fix`.
- **Large output no longer truncates** — the CLI called `process.exit()`
  before large piped stdout drained, silently cutting JSON/SARIF output at
  the ~64KB OS pipe buffer. stdout/stderr are now flushed before exit.

### Changed
- **Hardened GitHub Action** — `action.yml` runs the pinned action code
  (`$GITHUB_ACTION_PATH/bin/vexes.js`) instead of `npx @latest`, passes all
  inputs through `env:` as quoted shell vars (kills the template-injection
  sink), allowlists `command` to scan/analyze/monitor (rejects `guard`), and
  exposes `vulnerabilities`/`critical`/`high`/`moderate`/`exit-code`/`sarif-file`
  outputs. New `action-test.yml` exercises it against the demo fixtures;
  `demo.yml` no longer swallows failures with `|| true`.
- **Hermetic tests** — the red-team suite no longer touches the network
  (dep-graph registry lookups are stubbed and asserted), making good on its
  "no network calls" claim. CI Node matrix moved to 22/24/26 (23 was EOL).
- **Homebrew removed** — OSV has no Homebrew ecosystem, so brew scans only
  produced advisory-free noise. `src/parsers/brew.js` and the `brew`
  ecosystem were removed (restorable from git if a real data source appears).

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
