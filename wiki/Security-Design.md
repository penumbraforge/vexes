# Security Design

vexes is a security tool that inspects untrusted data (package metadata, vulnerability descriptions, source code). Its own security posture must be rigorous.

## Threat model

### What vexes trusts
- **Node.js runtime** -- vexes trusts the Node.js engine and built-in modules
- **OSV.dev API** -- vulnerability data is trusted as authoritative (it aggregates from NVD, GitHub Advisories, etc.)
- **npm/PyPI registry APIs** -- metadata is trusted for analysis purposes but output is always sanitized

### What vexes does NOT trust
- **Package names and descriptions** -- could contain terminal escape sequences, control characters, or prompt injection
- **Vulnerability summaries** -- external text that could contain injection attempts
- **Package source code** -- analyzed but never executed
- **Config files** -- parsed JSON that could attempt prototype pollution
- **Tarballs** -- untrusted compressed data that could be gzip bombs

## Hardening measures

### 1. Terminal injection prevention

All external data is sanitized before terminal output using a comprehensive `sanitize()` function that strips escape sequences in correct order (complete sequences first, then bare control chars):

- **OSC sequences** with both BEL and ST terminators (`ESC]...BEL` and `ESC]...ESC\`)
- **DCS/SOS/PM/APC sequences** (`ESC P...ST`, `ESC X`, `ESC ^`, `ESC _`)
- **CSI sequences** with intermediate bytes (`ESC[?25h`, `ESC[ 4h`)
- **Two-character ESC sequences** (Fe sequences)
- **C1 control codes** (0x80-0x9F, single-byte equivalents of ESC sequences)
- **C0 control characters** (except tab, newline, carriage return)
- **Bare ESC bytes** as a catch-all

Both the output module (`output.js`) and the logger (`logger.js`) have independent sanitization layers.

### 2. Prototype pollution protection

Config file merging rejects dangerous keys:

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

### 3. Command injection prevention

The `guard` command runs package manager commands on behalf of the user. To prevent injection:

- Uses `execFileSync` (no shell invocation) instead of `execSync`
- Validates the command against an allowlist of known package managers (`npm`, `npx`, `yarn`, `pnpm`)
- Arguments are passed as an array, never interpolated into a string
- Fix command output is shell-escaped to prevent injection when copy-pasted
- Guard `--setup` resolves the vexes binary path at install time rather than using `npx` at runtime (prevents a compromised registry from injecting code on every guarded install)

### 4. Fail-loud security invariant

A security scanner that silently reports clean when it can't actually verify safety is worse than no scanner at all. vexes enforces:

- If any OSV batch query fails, the scan is marked `INCOMPLETE` and exits with code 2
- If lockfile parsing fails, the scan reports the failure explicitly
- If vulnerability detail fetches fail, the vulnerability is still reported (with `CRITICAL` severity assumed)
- The `complete` field in JSON output reflects whether all packages were successfully checked

### 5. Gzip bomb + SSRF + memory exhaustion protection

Tarball inspection is hardened against multiple attack vectors:
- **Compressed size:** 5MB maximum download, enforced via streaming (not buffered)
- **Decompressed size:** 50MB maximum after gunzip
- **SSRF prevention:** Tarball URLs must use HTTPS and point to a known registry host (registry.npmjs.org, files.pythonhosted.org). URLs from manipulated API responses pointing to internal services (e.g., cloud metadata at 169.254.169.254) are rejected.
- **Streaming download:** The response body is streamed with incremental size checks, preventing memory exhaustion even when `Content-Length` is missing or lying.
- **Tar integer overflow protection:** Malicious octal sizes in tar headers are validated against `Number.MAX_SAFE_INTEGER` to prevent parser offset corruption.

### 6. Cache poisoning prevention

Degraded analysis results are never written to cache:
- If metadata fetch failed, the result is not cached
- If the analysis produced warnings, the result is not cached
- If the risk level is `UNKNOWN`, the result is not cached

This prevents a transient network failure from poisoning the cache with a false-clean result for 24 hours.

### 7. Input validation

- **Ecosystem names** are validated strictly. Invalid values from CLI flags throw an error. Invalid values from config files are dropped with a warning. An empty ecosystem list is rejected.
- **Severity levels** are validated. Invalid values fall back to defaults.
- **Paths** are checked for existence and type (must be a directory).
- **Package manager commands** (guard) are validated against an allowlist.
- **Cache TTLs** are clamped to maximum bounds (7 days advisory, 30 days metadata) to prevent config-based stale data attacks.
- **Critical signals** (`KNOWN_COMPROMISED`, `PHANTOM_DEPENDENCY`, `CIRCULAR_STAGING`, `CAPABILITY_ESCALATION`) are undisableable -- config `"off"` settings are ignored for these.

### 8a. Unicode homoglyph detection

Package names are checked for:
- **Zero-width characters** (U+200B, U+200C, U+200D, U+FEFF) that make names appear identical to legitimate packages
- **Bidirectional override characters** (U+202A-U+202E, U+2066-U+2069) that can reverse the visual order of text
- **Non-ASCII characters** (Cyrillic, Greek, etc.) that are visual lookalikes for Latin characters

### 8b. Integrity-aware lockfile diffing

Guard and monitor detect when a package's content changes without a version bump by comparing `integrity` hashes from the lockfile. This catches attacks where an attacker replaces a tarball on the registry without incrementing the version number.

### 8. Source code analysis without execution

vexes never executes package code. The AST inspector parses source into an abstract syntax tree and walks it -- the code is data, never run. Even for `--deep` tarball inspection, files are downloaded, decompressed, and parsed as text.

## What vexes does NOT do

- **Does not intercept network traffic.** Guard uses lockfile diffing, not proxy-based interception.
- **Does not modify node_modules.** Guard's dry-run uses `--package-lock-only --ignore-scripts`.
- **Does not execute install scripts.** Scripts are parsed and analyzed as text.
- **Does not require elevated privileges.** No root/admin access needed.
- **Does not send telemetry.** No data leaves your machine except OSV and registry API queries for the packages you scan.
