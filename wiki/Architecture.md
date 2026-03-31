# Architecture

## 4-Layer Detection Engine

vexes uses a layered detection architecture. Each layer catches different attack patterns, and composite scoring combines signals from all layers:

```
                    +------------------+
                    |  Signal          |
                    |  Orchestrator    |  Composite scoring
                    |  (signals.js)    |  with context multipliers
                    +--------+---------+
                             |
            +--------+-------+-------+--------+
            |        |               |        |
      +-----+--+ +---+-----+ +------+---+ +--+-------+
      | Layer 1 | | Layer 2 | | Layer 3  | | Layer 4  |
      | AST     | | Dep     | | Behavior | | Registry |
      | Analysis| | Graph   | | Profile  | | Metadata |
      +---------+ +---------+ +----------+ +----------+
       acorn AST   npm registry  Version     Publish
       JS + Python  metadata     diffing     history
```

### Layer 1: AST Analysis (`ast-inspector.js`)

Parses JavaScript source using [acorn](https://github.com/acornjs/acorn) (vendored -- zero deps) and walks the AST to detect dangerous call patterns. For Python, uses pattern matching on joined source lines (handling line continuations).

**Key design decisions:**
- **Tracks `require()` and `import` bindings.** `const { exec } = require('child_process'); exec('cmd')` is correctly traced. The inspector maintains a binding map so destructured imports are caught.
- **Handles both module and script parse modes.** Falls back to script mode if module parse fails.
- **Error recovery.** If the walker crashes mid-traversal, partial findings are preserved.
- **Obfuscation detection.** Computed property calls (`obj[expr]()`) and string concatenation in `require()` are flagged as evasion attempts.

### Layer 2: Dependency Graph (`dep-graph.js`)

Profiles newly added dependencies by fetching their registry metadata:
- **Phantom dependencies:** Brand-new packages (< 7 days old) with no ecosystem presence
- **Circular staging:** New dep published by the same account within 48 hours (the axios RAT pattern)
- **Typosquatting:** Levenshtein distance comparison against popular package databases
- **Install scripts on new deps:** New dependencies that run code on install

### Layer 3: Behavioral Fingerprinting (`behavioral.js`)

Builds capability profiles per package version and diffs them. The **diff** is what matters -- a utility library that suddenly gains `process_spawn` + `network` + `credential_access` capabilities is flagged regardless of what those capabilities do individually.

### Layer 4: Registry Metadata (`signals.js`, `npm-registry.js`, `pypi-registry.js`)

Fastest layer -- analyzes publish history, maintainer changes, timing anomalies:
- **Maintainer change** with time-decay (recent = CRITICAL, old = MODERATE)
- **Rapid publish** with CI awareness (0s interval with multiple maintainers = legitimate)
- **Version anomaly** (major jumps, dormancy followed by sudden publish)
- **Provenance** (Sigstore attestation check via npm attestations API)

## Composite Risk Scoring

```
Base Score = Sum of (signal_weight * context_multipliers)

Context multipliers:
  - Package age < 30 days: 2.0x
  - Single maintainer: 1.5x
  - Known-good package: 0.2x

Combination bonus:
  - 3+ unique signals: 1.5x total
  - 5+ unique signals: 2.0x total

Risk Levels:
  NONE: 0     LOW: > 0     MODERATE: >= 5     HIGH: >= 15     CRITICAL: >= 30
```

## Data flow

```
Lockfiles/Manifests
        |
        v
   [ Parsers ]  npm.js, pypi.js, cargo.js, brew.js
        |
        v
  Dependency List
        |
   +----+----+
   |         |
   v         v
 [ OSV ]  [ Registry ]
 Batch     Metadata
 Query     Fetch
   |         |
   +----+----+
        |
        v
 [ Signal Engine ]
  4-layer analysis
        |
        v
 [ Composite Score ]
        |
        v
    Output
 (text/json/sarif)
```

## Caching (`advisory-cache.js`)

Uses Node.js built-in `node:sqlite` (DatabaseSync):

| Table | Key | TTL | Content |
|-------|-----|-----|---------|
| `advisories` | ecosystem + name + version | 1 hour | Vulnerability data from OSV |
| `metadata` | ecosystem + name | 24 hours | Registry metadata |
| `signals` | ecosystem + name + version | 24 hours | Analysis results |

**Corruption resilience:** Corrupted JSON entries are detected, deleted, and treated as cache misses. If the database file is unreadable, vexes falls back to a `NoOpCache` (all misses, no writes) and continues scanning.

**Cache poisoning prevention:** Degraded analysis results (metadata unavailable, warnings present) are never cached. A transient network failure cannot poison the cache with a false-clean result.

## Tarball Inspection (`tarball-inspector.js`)

For `--deep` mode, downloads npm tarballs and PyPI sdists, then inspects the actual source:

1. Download with compressed size limit (5MB)
2. Gunzip with decompressed size limit (50MB -- gzip bomb protection)
3. Parse raw POSIX tar headers (zero-dependency tar reader)
4. Extract files matching inspection patterns (index.js, setup.py, etc.)
5. Per-file size limit (512KB) and file count limit (10)
6. Run through AST inspector

## Security boundaries

- **External data sanitization:** All package names, vulnerability summaries, and other external strings are sanitized before terminal output to prevent terminal injection.
- **Config merge protection:** `__proto__`, `constructor`, `prototype` keys are rejected.
- **Command injection prevention:** Guard command uses `execFileSync` (no shell) with package manager allowlist.
- **Input validation:** Ecosystem names, severity levels, and paths are validated before use.
