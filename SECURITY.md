# Security Policy

## Reporting a vulnerability

If you find a security issue in vexes itself (not in a package it flagged),
please open a [GitHub security advisory](https://github.com/penumbraforge/vexes/security/advisories/new)
rather than a public issue. Include reproduction steps, affected versions, and
impact where possible; the maintainer will coordinate disclosure and record
shipped fixes in the changelog.

If vexes **missed** a compromised package you know about — a false negative
on a real incident — that is exactly the report we want most. Please open a
regular GitHub issue (this is a detection-quality matter, not a
confidentiality matter) with the package name, version, and advisory link if
one exists. The [detection benchmark](BENCHMARK.md) provides versioned fixtures
and a documented comparison point for investigating such reports. Its dated
live sample is environment- and upstream-dependent rather than a universal
reproduction guarantee.

## Threat model — what vexes is and is not

The default `scan` and non-sandbox analysis paths read project files and query
public OSV/registry endpoints. Other commands have different effects: the cache
writes locally, guard can modify lockfiles and `node_modules`, legacy-wrapper
uninstall can edit shell configuration, and the opt-in sandbox can execute
selected package entrypoints.
Understanding those boundaries matters as much as the findings.

**Evidence it can surface**

- Versions that OSV places in an affected vulnerability range
- Inspectable inline install-script and sampled source patterns associated with
  process spawning, networking, credentials, payload decoding, or file writes
- Between-version install-script capability changes when both versions' script
  data is available
- Name similarity, suspicious Unicode presence, publisher changes, and missing
  or internally inconsistent attestation fields

These are evidence signals. They can false-positive and miss attacks; none is a
proof that a package is safe, malicious, or exploitable in this project.

**What it does not protect against**

- **It is not universal interception.** `guard` blocks known advisories,
  CRITICAL evidence, and incomplete analysis; `--force` can approve HIGH
  heuristic evidence. It only accepts a narrow explicit public-npm command
  grammar. Automatic wrapper setup is currently disabled, so a plain
  `npm install` bypasses vexes entirely unless an older wrapper is still active.
- **Guard binds to metadata, not installed bytes.** Resolution happens in a
  disposable copy and approved installs disable lifecycle scripts. The final
  manifest and lockfile are bound to occurrence/version/resolved URL/integrity,
  but vexes does not independently hash `node_modules`. On npm failure it
  restores the manifest and lockfile; `node_modules` may remain partially
  changed.
- **Static analysis is defeatable.** A payload split across files, fetched
  at runtime, hidden behind environment checks, outside the selected sample,
  or otherwise absent from inspectable inline strings/files can evade it.
  Detection is pattern and capability based, not proof based.
- **Dynamic telemetry is opt-in, npm-only, and experimental.** `--sandbox`
  selects one npm entrypoint per executed candidate from a bounded partial
  extraction and observes selected Node APIs under an accepted Linux `bwrap`
  host. PyPI sandbox extraction and execution are unsupported and refused
  (static PyPI `--deep` sampling remains separate). Analyze considers at most
  five HIGH/CRITICAL candidates; inspect considers its one target. The accepted
  `bwrap` layout omits the user's home/project and restricts writes to the
  extracted workdir and throwaway temp, but exposes `/usr`, `/bin`, and loader
  libraries read-only. `/etc`, the user's home, and the calling project are not
  mounted. This protects private paths, but is not a no-host-read guarantee. The current macOS
  profile is refused because its broader file-read rule exposes arbitrary user
  files. The launch probe is not containment verification, and
  the recorder is bypassable and not inherited by children. A timeout or
  nonzero child exit is a failed stage, not behavioral evidence, and every
  requested sandbox stage remains incomplete. Do not use it as a safety
  boundary for known malware.
- **No runtime protection.** Once a malicious script has run, vexes has
  nothing to offer — it does no endpoint detection, no persistence checks,
  and no cleanup. When invoked before an explicit supported npm install, guard
  can add a review point; vexes does not otherwise interpose on execution.
- **Advisory lag.** `KNOWN_MALICIOUS` and `KNOWN_VULNERABILITY` are only as
  current as OSV. A compromise that has not been disclosed is invisible to
  `scan`; heuristic layers may add leads, but they also miss things.
- **Incomplete dependency evidence remains incomplete.** Unsupported lockfile
  schemas fail visibly. Ruby/PHP/NuGet/Java manifest fallbacks are not resolved
  graphs, and replaced Go modules are excluded; these paths do not produce a
  complete scan result. When no `go.mod` exists, the `go.sum` fallback is
  checksum history and can include modules no longer active in the build.
  Ruby `Gemfile.lock` entries without Bundler SHA-256 `CHECKSUMS` are likewise
  unresolved because registry mirrors can otherwise change the artifact behind
  an unchanged name/version.
- **Provenance availability is not assumed.** A requested npm attestation lookup
  that is unavailable, or a present bundle whose payload cannot be decoded,
  makes inspect/analyze incomplete. A decoded bundle is cross-referenced but
  not cryptographically authenticated by vexes.
- **Typosquat detection is name-based.** Distance to a hardcoded
  popular-package list; a novel enough name or a list gap is a miss.
- **Repository policy is untrusted input.** `.vexesrc.json` may choose ordinary
  report ecosystems/severity/ignores and suppress analysis signals. It cannot
  enable sandbox, deep sampling, AI, fix output, stale-cache use, or choose the
  cache database. Use `--no-project-config` for an enforcement scan of an
  untrusted checkout. Add `--no-user-config` when the runner account's trusted
  policy must also be excluded for a reproducible result. Guard clears
  configured ignores and signal suppression before making its install decision.

**What vexes does with your data**

- Registry, OSV, and deps.dev requests include package coordinates. Vexes does
  not implement product-usage telemetry, and its scanner requests do not upload
  project source files.
- AI triage sends finding summaries to the provider you configure. A local
  endpoint keeps those summaries local; any remote OpenAI- or
  Anthropic-compatible endpoint is an opt-in disclosure. Source files are not
  included in the model request.

## Handling untrusted code

Treat package source and archives as untrusted input. Static inspection avoids
running sampled files, but parsers and the host runtime remain part of the
attack surface. Never install or execute a suspect package on a valued host.
Use a disposable VM or comparably isolated environment with scripts disabled,
and treat vexes' experimental sandbox telemetry as evidence rather than
containment. The repository benchmark does not retrieve known-malware artifacts.

For npm deep inspection and dynamic extraction, compressed tarball bytes are
checked against the registry-provided SRI value or legacy SHA-1 shasum before
use. Missing digest metadata is reported for static sampling and refused for
dynamic extraction. The current PyPI sampling path does not bind an sdist to a
registry digest. Every redirect hop is restricted to HTTPS on the npm/PyPI
tarball host allowlist.
