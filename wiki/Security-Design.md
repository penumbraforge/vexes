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

All external data is sanitized before terminal output using the `sanitize()` function:

```javascript
function sanitize(s) {
  return String(s).replace(
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07/g,
    ''
  );
}
```

This strips:
- Non-printable control characters (NUL, BEL, etc.)
- ANSI CSI escape sequences (`ESC[...m`)
- OSC escape sequences (`ESC]...BEL`)

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

### 4. Fail-loud security invariant

A security scanner that silently reports clean when it can't actually verify safety is worse than no scanner at all. vexes enforces:

- If any OSV batch query fails, the scan is marked `INCOMPLETE` and exits with code 2
- If lockfile parsing fails, the scan reports the failure explicitly
- If vulnerability detail fetches fail, the vulnerability is still reported (with `CRITICAL` severity assumed)
- The `complete` field in JSON output reflects whether all packages were successfully checked

### 5. Gzip bomb protection

Tarball inspection enforces two size limits:
- **Compressed size:** 5MB maximum download
- **Decompressed size:** 50MB maximum after gunzip

The decompressed limit prevents gzip bombs (a 46-byte gzip can theoretically decompress to 4.5 petabytes).

### 6. Cache poisoning prevention

Degraded analysis results are never written to cache:
- If metadata fetch failed, the result is not cached
- If the analysis produced warnings, the result is not cached
- If the risk level is `UNKNOWN`, the result is not cached

This prevents a transient network failure from poisoning the cache with a false-clean result for 24 hours.

### 7. Input validation

- **Ecosystem names** are validated against the known set. Typos produce warnings with suggestions.
- **Severity levels** are validated. Invalid values fall back to defaults.
- **Paths** are checked for existence and type (must be a directory).
- **Package manager commands** (guard) are validated against an allowlist.

### 8. Source code analysis without execution

vexes never executes package code. The AST inspector parses source into an abstract syntax tree and walks it -- the code is data, never run. Even for `--deep` tarball inspection, files are downloaded, decompressed, and parsed as text.

## What vexes does NOT do

- **Does not intercept network traffic.** Guard uses lockfile diffing, not proxy-based interception.
- **Does not modify node_modules.** Guard's dry-run uses `--package-lock-only --ignore-scripts`.
- **Does not execute install scripts.** Scripts are parsed and analyzed as text.
- **Does not require elevated privileges.** No root/admin access needed.
- **Does not send telemetry.** No data leaves your machine except OSV and registry API queries for the packages you scan.
