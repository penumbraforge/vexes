# Changelog

All notable changes to vexes are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

> **Accuracy note:** release notes describe what shipped, not a security
> certification. Later review found several descriptions stronger than the
> implementation. The entries below have been corrected in place where needed;
> current limitations in README and SECURITY.md take precedence over older copy.

## [0.6.1] — 2026-08-29

Trust and correctness follow-up to 0.6.0. The changes below tighten behavior
and terminology; they are not a security certification.

### Security
- **Sandbox now requires a bounded filesystem view and contained writes.**
  `unshare` and `firejail` do not provide the required write boundary, while
  the current macOS `sandbox-exec` profile exposes arbitrary user files through
  a broad read rule. All three are refused. The accepted live-probed Linux
  `bwrap` layout omits the user's home/project and restricts writes to the
  extracted workdir and throwaway temp, while still exposing read-only host
  runtime trees (`/usr`, `/bin`, and available loader libraries). `/etc`, user
  homes, and the calling project are not mounted. The probe
  only proves a benign Node command can launch; dynamic telemetry is still
  experimental and must not be used as an escape-proof malware boundary.
- **Cached signal results are now bound to the advisory view used by analysis.**
  Cached analysis was previously served before the available OSV evidence was
  considered, so a changed advisory result could remain hidden behind the
  24-hour signal cache. Cached verdicts now carry an `osvFingerprint` and are
  reused only when it matches the OSV result supplied to that run. OSV's own
  advisory-cache policy still applies. The current cache schema is 4:
  incompatible older rows are dropped, and the schema also stores freshness
  baselines.

### Fixed
- **Guard analyzes the exact proposed version, not `latest`** — registry
  metadata is now requested and checked against the version the disposable
  resolution produced instead of silently analyzing `dist-tags.latest`.
- **Guard binds approval to a disposable resolution.** Guard now accepts only
  explicit public-registry `npm install`/`i`/`add <package>` requests, refuses
  workspaces and local/git/URL specs, and resolves in a disposable project copy
  with lifecycle scripts disabled. New/changed lockfile occurrences must carry
  a public-registry HTTPS URL and integrity value; exact-version registry
  metadata is cross-checked before analysis.
- **Approved guarded installs keep lifecycle scripts disabled.** Human mode
  applies the approved manifest/lockfile through `npm install --ignore-scripts`
  and verifies occurrence, version, resolved URL, integrity, and the manifest
  afterward. Manifest/lockfile files use atomic same-directory replacement and
  are restored on detected failure or drift, although `node_modules` may be
  partially changed and an actively racing same-user process remains outside
  the boundary. This is metadata/lockfile identity,
  not independent verification of installed bytes. JSON mode is assessment-only
  and never installs. `npx`, pnpm, and Yarn remain refused.
- **Automatic guard wrapper setup is disabled.** A general npm shell wrapper
  would intercept bare installs, workspaces, private sources, and other commands
  outside guard's supported grammar. `guard --setup` now fails closed and points
  to explicit invocation; `--uninstall` remains for older wrappers.
- **`scan --top` was a silent no-op** — parsed but never wired into
  configuration. Now mapped (and validated) in `loadConfig`.
- **Displayed vulnerabilities no longer print twice in text mode.**
- **Dependency-input fallbacks fail visibly.** Unsupported lockfile schemas are
  parse failures (pnpm support is currently v6/v9). Ruby/PHP/NuGet/Java manifest
  fallbacks may contribute exact pins but remain incomplete because they are not
  resolved graphs. Ruby lock entries without Bundler SHA-256 `CHECKSUMS` are
  unresolved because a mirror can change bytes behind a coordinate. Replaced Go
  modules are excluded and make coverage incomplete.
- **Provenance gaps are incomplete, not absence.** npm attestation lookup
  failures no longer become a clean missing/present conclusion in inspect or
  analyze, and a present bundle with an undecodable payload now also marks the
  requested stage incomplete.
- **Upgrade commands share one validated builder.** Package/version coordinates
  are constrained to the ecosystem grammar, POSIX-shell quoted, and separated
  from options where supported; scan hints still require a resolved-graph rescan.
- **The GitHub Action validates outputs before exposing them.** Empty,
  malformed, or non-envelope JSON becomes exit code 2 without fabricated zero
  counts. A requested scan SARIF report is generated fresh, checked for a
  complete vexes SARIF 2.1.0 object, and exposed only after validation; stale,
  failed, or incomplete output is not published as `sarif-file`. Both action
  runs pass `--no-user-config` and `--no-project-config`, preventing runner-user
  policy or a checked-out pull request's `.vexesrc.json` from silently changing
  the result.
- **Project configuration is restricted to report policy.** Repository-local
  config can choose ecosystems, severity, ignores, presentation, and analysis
  signal switches, but cannot enable sandbox/deep/fix/AI/stale-cache modes or
  select cache storage. Those modes require explicit CLI flags; ordinary cache
  location/TTLs may still come from trusted user config. Guard clears ignores
  and signal suppression before making an install decision.
- **`doctor` works from installed packages** — parser fixtures resolve
  relative to the package root, not the caller's cwd, and the fixture files
  ship in the npm artifact. A new packed-artifact test installs the real
  tarball into an unrelated project and exercises the actual CLI.

### Changed
- **Reachability relabeled as "direct import evidence".** Findings now expose
  canonical `importEvidence` values (`found_static`, `found_dynamic`,
  `not_found`, `unknown`). The legacy reachability key remains for compatibility
  only. Projects with no parsable source for an ecosystem are `unknown`, and
  `--min-reachability` is deprecated and ignored so source evidence can never
  suppress an advisory.
- **OSV analysis signals now distinguish malware from vulnerabilities.** Only
  explicit `MAL-*`/malware-typed records emit `KNOWN_MALICIOUS`; ordinary OSV
  affected-range matches emit `KNOWN_VULNERABILITY` at the highest available
  upstream severity. `KNOWN_COMPROMISED`/`OSV_MATCH` remain compatibility names.
- **Every documented signal switch is honored.** Repository config can suppress
  analysis evidence, so policy files must be reviewed like other security
  configuration. The legacy `KNOWN_COMPROMISED` switch controls the two newer
  OSV names when they are not configured separately.
- **Provenance output states its verification boundary.** Attestation bundles
  expose decoded/present status plus `cryptographicallyVerified: false` and
  `verificationStatus: not-performed`. Decoded claim mismatches now emit
  `ATTESTATION_IDENTITY_MISMATCH`; `SIGNATURE_SPOOF` is a compatibility name,
  not a claim that a signature was verified or forged.
- **Freshness polling uses a persistent last-seen baseline.** The first
  successful npm/PyPI poll records the registry latest version in SQLite;
  subsequent cycles grade only a changed latest value. If persistent state is
  unavailable, freshness is disabled instead of repeatedly presenting an old
  update as newly observed.
- **Benchmark scoring corrected.** Part A requires the exact manifest
  advisory identity (5/5); any unrelated loud finding is reported but not
  credited. Part B detects the required technique-specific evidence in 5/5
  synthetic attacks and passes 2/2 gated negative controls under their stated
  forbidden/HIGH+ criteria. Part C
  reports HIGH/CRITICAL heuristic flags for 1/10 exact-version, digest-pinned
  live bounded samples and 0 current blocking advisories as of 2026-08-28.
  Part C samples selected entry/install-like source rather than whole packages,
  so the full run reports `INCOMPLETE` with exit 0 when integrity and policy
  gates pass; execution errors exit 2, regressions exit 1, and
  `--require-complete` makes the coverage limitation blocking.
- **Tarball sampling no longer mistakes runtime metadata for dangerous code.**
  Acorn accepts ordinary Node hashbang entrypoints, while conditional
  `exports.types` and TypeScript declaration/source paths are excluded from the
  JavaScript runtime sample. This removes the semver and commander parser false
  positives without suppressing esbuild's real installer capabilities; the
  live false-positive ceiling is ratcheted from 4 to 1.
- **Vendored Acorn license notice ships** (`src/vendor/LICENSE-acorn.txt`) —
  its MIT license requires the notice be included with the vendored copy.

## [0.6.0] — 2026-08-28

### Added
- **SECURITY.md with an explicit threat model** — what vexes protects
  against, what it does not (no runtime protection, static analysis is
  defeatable, advisory lag), and how to report misses.
- **Detection benchmark** (`npm run bench`, `BENCHMARK.md`, CI job) — three
  fixture/spot-check sets, none of which retrieve known-malware artifacts:
  historical-version advisory matching, synthetic technique fixtures, and a
  bounded, exact-version/digest-pinned live sample. The original release
  reported 6/6 technique cases and 0/10 live flags without adequately
  separating controls or heuristic findings; 0.6.1 replaced that presentation
  with the three-part results and coverage status described above. The
  benchmark caught a fixture-level evasion immediately: inline
  `require('https').get(...)` with no variable binding evaded
  network-capability detection (fixed).

### Fixed
- **Direct-require network calls** — `require('https').get(...)` was not
  flagged as `NETWORK_ACCESS` unless the module was first bound with
  `const https = require('https')`. The direct form covered by the benchmark
  fixture is now detected.

### Changed
- **`CAPABILITY_ESCALATION` is now a real between-versions diff** — npm
  exposes per-version lifecycle scripts, so the previous version's scripts
  are inspected with the same extractor as the current version's. A new
  newly introduced inspectable dangerous capability can escalate CRITICALLY;
  without previous-version data the finding degrades to the MODERATE
  `INITIAL_DANGEROUS_CAPABILITY`.
- **`--top <n>`** for `scan` and `analyze` text output — first-run output
  can be capped after severity/risk ordering instead of showing everything.
  JSON output is unchanged.

## [0.5.0] — 2026-08-28

The first targeted honesty-audit release. It corrected three identified
claims/code mismatches plus a TypeScript reachability gap; later reviews found
additional issues documented in 0.6.1 and the current README/SECURITY.md.

### Fixed
- **TypeScript reachability** — `.ts/.tsx/.mts/.cts` files were never scanned,
  so every dependency in a TypeScript project graded `dead` — and
  `--min-reachability reachable` would have dropped *all* findings. TypeScript
  is now covered by a light import scan (regex, like Python/Rust; acorn cannot
  parse TS syntax). `import type` / `export type` correctly create no edge —
  type-only imports never execute a package.
- **`CAPABILITY_ESCALATION` no longer fires without a real diff.** At the time,
  the analyzer was not retaining usable previous-version script data, so the
  fabricated "previous profile" made every dangerous install-script capability
  report as CRITICAL "gained between versions" — including packages that had
  shipped the same script for years. That case is now
  `INITIAL_DANGEROUS_CAPABILITY` (MODERATE, "present in analyzed version;
  previous capabilities unknown"). The CRITICAL escalation signal fires only
  when a genuine previous-version diff exists.
- **`guard` refuses `npx` instead of faking it.** npx has no lockfile-only
  mode, so the "dry-run" was the real execution — the package's scripts ran
  before any analysis. guard now exits with an error pointing at
  `vexes inspect <pkg>`.

### Changed
- Confidence grades added for signals that silently fell through to
  `inferred`: `NEW_DEPENDENCY`, `NEW_DEP_HAS_INSTALL_SCRIPTS`,
  `DEPENDENCY_SPIKE`, `MAINTAINER_REDUCTION`, `REPOSITORY_REMOVED`,
  `INITIAL_DANGEROUS_CAPABILITY`.
- Docs trued up against code: provenance is described as field
  cross-referencing (vexes never verifies DSSE signatures — it didn't before
  either), typosquat/homoglyph coverage limits are stated (curated ~165/105
  popular-package list, length-dependent thresholds, scoped names compared in
  full, and normal registry naming rules making the Unicode-presence check
  largely dormant), guard's decision
  matrix now matches the code (blocks on any `KNOWN_COMPROMISED` and on
  incomplete analysis), ecosystem counts reconciled to 10, and the
  Allowlists.md worked example no longer contradicts the 0.2x downweight it
  actually applies.
- `doctor` no longer warns about a missing `-r` fixture: the fixture file now
  ships, so the recursive-include path is exercised cleanly.

## [0.4.0] — 2026-08-22

The AI-provider and experimental dynamic-telemetry release. Later review found
the original "lifecycle scripts," "capability verified," full-containment,
doctor, and universal-envelope descriptions below were too strong; the corrected
descriptions are retained here.

### Added
- **Configurable AI provider** — `scan --ai`/`explain` detect an
  `ANTHROPIC_BASE_URL` and authenticate with a Bearer `ANTHROPIC_AUTH_TOKEN`,
  mirroring the hosted path (`ANTHROPIC_API_KEY` is still supported). The model
  is **auto-discovered** from `GET /v1/models` — no `ANTHROPIC_MODEL` needed —
  and any provider failure degrades to a per-finding error verdict without
  ever flipping the scan's `complete`. Provider precedence:
  `VEXES_AI_BASE` → `ANTHROPIC_BASE_URL` → `ANTHROPIC_API_KEY`. A local endpoint
  keeps summaries local; a remote endpoint receives summarized findings.
- **Dynamic sandbox evidence** — `analyze --sandbox` and `inspect --sandbox`
  extract CRITICAL/HIGH npm candidates (top-N by risk score) to a
  throwaway dir, select and run one npm entry script inside an OS primitive under
  a recorder shim (`node --require`, with fd-based loading to avoid recursive
  self-patching), and attach a `SANDBOX_BEHAVIOR` signal plus `sandboxEvidence`
  (spawns / network attempts / outside writes) to the record. New
  `src/analysis/sandbox/harness.js` + tarball extraction to disk with a tar
  traversal guard. It does not run lifecycle hooks. Current PyPI sandbox
  requests are refused before dynamic extraction or execution; static PyPI
  `--deep` sampling is separate.
- **Sandbox launch probe** — `detectSandboxHost()` live-probes whether a benign
  Node command can start. That is not an end-to-end containment check. Current
  code refuses `unshare`/`firejail` and the current read-permissive
  `sandbox-exec` profile; recorder telemetry and the host flag are not proof of
  containment.
- **`vexes doctor`** — installation smoke checks for parser fixture loading and
  a cache write/read, plus optional endpoint and sandbox-availability reports.
  It does not test provider discovery, scan determinism, privileges, or every
  config/environment path, and is not a trust certification.
- **Shared top-level agent envelope** (`src/cli/schema.js`, `SCHEMA_VERSION 1.0`) —
  normal successful JSON paths for scan, analyze, fix, monitor --ci, inspect,
  doctor, licenses, and guard use a common top level with command-specific
  payloads. Explain/triage, setup/uninstall, watch streams, and some early errors
  remain outside the uniform JSON path.

### Changed
- **Guard hardening at the time** — added manager-specific preview flags and a
  lockfile tamper guard that attempted to relate the post-preview diff to the
  requested install; on a detected violation the backup was restored and the
  install was not executed. Later reviews found both that relationship check
  and the non-npm paths too broad to support the original claim. Current guard
  instead accepts a narrow npm-only grammar and binds changed occurrences to
  exact public-registry metadata.
- **Help-text honesty** — every formerly "needs `ANTHROPIC_API_KEY`" line now
  names the configurable provider routes (`VEXES_AI_BASE`, or
  `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`, or `ANTHROPIC_API_KEY`).
- **`inspect`** — package evidence with bounded `--deep` file sampling and the
  same experimental selected-entrypoint telemetry as analyze.

## [0.3.0] — 2026-08-12

The hardening release. SARIF output for GitHub code scanning, a rewritten
Action that removed the identified template-injection path, and a batch of
correctness fixes.

### Added
- **AI-assisted triage** — `vexes explain` (alias `triage`) asks a configured
  model to draft a prioritized plain-English plan, including suggested order
  and possible blast radius. It is opt-in:
  it calls the Claude API only when `ANTHROPIC_API_KEY` is set, and the
  remote request contains summarized findings. The model layer is separate
  from deterministic scan findings. Fresh scans still query OSV. Composes over a scan:
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
  (`$GITHUB_ACTION_PATH/bin/vexes.js`) instead of `npx @latest`, passes
  structured inputs through environment variables (the free-form `args` input
  is intentionally space-split and documented as trusted-only), removes the
  identified expression-template command sink, allowlists `command` to
  scan/analyze/monitor (rejects `guard`), and
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

The accuracy release. It fixed known severity, registry-version attribution,
and PyPI history defects; later audits identified additional limitations.

### Fixed
- **CVSS severity extraction** — OSV puts the CVSS vector *string* in
  `severity[].score`; the parser expected a `.vector` field that never
  exists, so every PYSEC/RUSTSEC/Go advisory fell through to a false
  `CRITICAL`. Vectors now run the CVSS v3.1 base-score math; numeric scores pass
  through; malformed entries fall back conservatively. The exact demo
  distribution remains a dated OSV observation rather than a stable promise.
- **`analyze` anchors registry metadata to the lockfile version** — registry metadata
  (publisher, install scripts, dependency diff, publish timing) was
  previously derived from `dist-tags.latest` regardless of the lockfile.
  Layer 3/4 registry fields are now anchored to the lockfile-resolved version
  when the registry knows it; this does not inspect installed bytes.
  `latestAvailable` is reported separately.
- **PyPI Layer 4 resurrected** — the versioned PyPI endpoint returns no
  `releases` map, leaving publish-history signals permanently null. vexes
  now uses the unversioned endpoint and emits `majorJump` and `dormancyMs`
  for PyPI packages. (The publishing-account-change signal remains npm-only:
  PyPI's JSON API has no per-release publisher — documented, not faked.)
- **`--deep` findings count again** — risk levels are re-derived after
  provenance and deep-tarball scoring; previously a package pushed over a
  threshold by deep inspection kept its old level and could be filtered out
  of the report and the exit code.
- **Time-dependent fixtures stabilized** — repository-authored technique
  fixtures with old synthetic publish dates crossed the 90-day
  maintainer-change decay window after authorship and turned CI red. The
  analysis clock is now injectable (`analyzePackage(..., { now })`); dated
  fixtures analyze as of their pinned date, and boundary tests pin the decay
  cliff at 89/91 days.

### Changed
- **Advisory cache schema v2** — cached rows store normalized severities,
  so caches written before the CVSS fix are dropped on first use after
  upgrade (`PRAGMA user_version`). Without this, upgraded installs would
  keep serving the old false CRITICALs until TTL expiry.

## [0.1.1] — 2026-03-31

Initial public release: cross-ecosystem dependency scanning (npm incl.
pnpm/yarn lockfiles, PyPI, Cargo, Go, Ruby, PHP, NuGet, Maven) against the
OSV database, 4-layer analysis engine for npm (metadata signals, dependency
graph, behavioral diff, AST inspection), and zero external runtime npm
dependencies.
