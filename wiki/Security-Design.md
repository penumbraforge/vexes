# Security Design

vexes inspects untrusted package metadata, vulnerability descriptions, and
source code. This page documents the checks it implements and their limits.

## Threat model

### What vexes trusts
- **Node.js runtime** -- vexes trusts the Node.js engine and built-in modules
- **OSV.dev API** -- advisory responses are treated as the upstream source for
  version-range matches, not as proof of exploitation or malicious intent
- **npm/PyPI registry APIs** -- metadata is used as evidence and remains
  untrusted input

### What vexes does NOT trust
- **Package names and descriptions** -- could contain terminal escape sequences, control characters, or prompt injection
- **Vulnerability summaries** -- external text that could contain injection attempts
- **Package source code** -- static paths treat it as data; the explicit
  experimental `--sandbox` path can execute one selected npm entrypoint
- **Config files** -- parsed JSON that could attempt prototype pollution
- **Tarballs** -- untrusted compressed data that could be gzip bombs

## Implemented checks

### 1. Terminal-control sanitization

Shared output and logger paths use `sanitize()` to strip escape sequences in
the following order. Some command-specific fields still bypass the shared
formatter, so complete terminal-output coverage is not claimed:

- **OSC sequences** with both BEL and ST terminators (`ESC]...BEL` and `ESC]...ESC\`)
- **DCS/SOS/PM/APC sequences** (`ESC P...ST`, `ESC X`, `ESC ^`, `ESC _`)
- **CSI sequences** with intermediate bytes (`ESC[?25h`, `ESC[ 4h`)
- **Two-character ESC sequences** (Fe sequences)
- **C1 control codes** (0x80-0x9F, single-byte equivalents of ESC sequences)
- **C0 control characters** (except tab, newline, carriage return)
- **Bare ESC bytes** as a catch-all

Both the output module (`output.js`) and the logger (`logger.js`) have independent sanitization layers.

### 2. Prototype pollution protection

Config file merging drops dangerous keys:

```javascript
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function merge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (UNSAFE_KEYS.has(key)) continue;  // Block prototype pollution
    // ... deep merge
  }
  return result;
}
```

### 3. Command-construction defenses

The `guard` command runs package manager commands on behalf of the user. Its
command-injection defenses are:

- Uses `execFileSync` (no shell invocation) instead of `execSync`
- Accepts only explicit public-registry `npm install`/`i`/`add <package>`
  requests with a narrow allowlist of flags; bare installs, workspaces,
  local/git/URL specs, `npx`, pnpm, and Yarn are refused
- Arguments are passed as an array, never interpolated into a string
- Displayed upgrade commands use POSIX-shell quoting and still require review
  before execution; package/version coordinates are grammar-validated and
  option boundaries are used where supported
- Automatic guard `--setup` is currently disabled because a general shell
  wrapper would intercept npm commands outside guard's supported grammar.
  `--uninstall` remains for older wrappers and backs up the rc file before edits.

### 4. Fail-loud security invariant

For the main vulnerability scan, incomplete OSV work must not be reported as a
clean result. The scan path enforces:

- If any OSV batch query fails, the scan is marked `INCOMPLETE` and exits with code 2
- If lockfile parsing fails, the scan reports the failure explicitly
- Unsupported lockfile schemas and partial dependency inputs (including
  Ruby/PHP/NuGet/Java manifest fallbacks, Ruby locks without artifact
  `CHECKSUMS`, and replaced Go modules) make the requested scan incomplete
- If vulnerability detail fetches fail, the vulnerability is still reported (with `CRITICAL` severity assumed)
- The `complete` field in scan JSON reflects whether requested dependency-input
  and OSV stages completed without a known gap

### 5. Gzip bomb + SSRF + memory exhaustion protection

Tarball inspection applies these input bounds and destination checks:
- **Compressed size:** 5MB maximum download, enforced while reading the stream
- **Decompressed size:** 50MB maximum after gunzip
- **SSRF restriction:** The initial tarball URL and every redirect hop (at most
  five) must use HTTPS and point to `registry.npmjs.org` or
  `files.pythonhosted.org`; off-list and internal destinations are rejected
- **npm artifact binding:** Registry SRI or legacy shasum metadata is checked
  against the compressed bytes when supplied. Missing digest metadata is
  reported for static sampling and refused for dynamic extraction. Current
  PyPI sdist sampling is not digest-bound.
- **Streaming download:** Incremental size checks bound the accepted compressed
  response even when `Content-Length` is missing or inaccurate.
- **Tar integer overflow protection:** Malicious octal sizes in tar headers are validated against `Number.MAX_SAFE_INTEGER` to prevent parser offset corruption.

### 6. Degraded cache handling

Degraded analysis results are never written to cache:
- If metadata fetch failed, the result is not cached
- If the analysis produced warnings, the result is not cached
- If the risk level is `UNKNOWN`, the result is not cached

Together with advisory fingerprints on cached analysis, this limits stale
false-clean reuse after a transient failure or an OSV evidence change.

### 7. Input validation

- **Ecosystem names** are validated strictly. Invalid values from CLI flags throw an error. Invalid values from config files are dropped with a warning. An empty ecosystem list is rejected.
- **CLI severity flags** are validated and ignored with a warning when invalid,
  leaving the configured/default severity in effect.
- **Paths** are checked for existence and type (must be a directory).
- **Package manager commands** (guard) are restricted to a narrow public-npm grammar.
- **Cache TTLs** are clamped to maximum bounds (7 days advisory, 30 days for
  the historically named metadata/analysis-signal setting), limiting but not
  eliminating stale-evidence risk.
- **Signal configuration** is honored for every documented analysis signal.
  The legacy `KNOWN_COMPROMISED` switch applies to the newer OSV signal names
  when those are not configured separately. Repository-local config can
  therefore suppress ordinary report evidence and must be reviewed as policy;
  `--no-project-config` ignores it for enforcement scans. `--no-user-config`
  also excludes runner-account policy when a reproducible result is required.
  Project config cannot enable sandbox/deep/fix/AI/stale-cache modes or choose
  cache storage. Guard clears configured ignores and signal suppression before
  deciding an install.

### 8. Suspicious Unicode presence

Package names are checked for:
- **Zero-width characters** (U+200B, U+200C, U+200D, U+FEFF) that make names appear identical to legitimate packages
- **Bidirectional override characters** (U+202A-U+202E, U+2066-U+2069) that can reverse the visual order of text
- **Any non-ASCII character.** The implementation does not map Unicode
  confusables or determine visual similarity. Normal public-registry coordinate
  rules make this defensive check largely dormant on live metadata.

### 9. Integrity-aware lockfile diffing

npm guard preserves lockfile occurrences and can flag changes to version,
`resolved`, or `integrity` fields. An approved install is bound to those fields
and the proposed manifest. It does not independently download and hash the
tarball or verify bytes in `node_modules`.

### 10. Static sampling and optional dynamic telemetry

Default scan and non-sandbox analysis paths do not execute package code.
`--deep` treats sampled files as text, is bounded to selected entry/install-like
files, and is not exhaustive.
The explicit experimental `--sandbox` option is different: when an accepted
Linux `bwrap` host is available, it executes one selected npm entrypoint and
records selected Node APIs. The child receives a minimal environment rather
than arbitrary parent environment variables. The layout omits the user's
home/project and confines writes to the extracted workdir and throwaway temp,
but mounts `/usr`, `/bin`, and loader-library directories read-only; `/etc` is
not mounted. This is private-path isolation, not complete host-read isolation.
The current macOS profile is refused because its broad
read rule also exposes arbitrary user files.
It does not run lifecycle hooks, does not execute PyPI packages, and is not a
safe boundary for known malware. PyPI sandbox extraction and execution are
unsupported and refused; static PyPI `--deep` sampling remains separate. The
recorder is bypassable and children are not instrumented. A timeout or nonzero
child exit is a failed stage, not behavioral evidence; every requested sandbox
stage remains incomplete even after a successful launch.

## What vexes does NOT do

- **Does not intercept network traffic.** Guard uses lockfile diffing, not proxy-based interception.
- **Guard resolution does not modify the target project.** Its later approved
  npm application can modify `node_modules`, but guard adds `--ignore-scripts`.
  On failure, manifest/lockfile rollback does not guarantee `node_modules`
  rollback.
- **Does not itself invoke lifecycle hooks for analysis.** Inline hook strings
  are inspected as text. Guarded installs disable them; an unguarded package
  manager command may run them normally.
- **Does not require elevated privileges.** No root/admin access needed.
- **Does not send product telemetry.** Scans send package names/versions to OSV
  and registry endpoints. Opt-in remote AI sends summarized findings to the
  configured provider; package source files are not included.
