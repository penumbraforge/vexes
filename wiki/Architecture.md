# Architecture

## Four heuristic evidence layers

vexes uses a layered evidence architecture. Each layer can surface different
review signals, and composite scoring combines the signals that are available:

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
      | Source  | | Dep     | | Behavior | | Registry |
      | Patterns| | Graph   | | Profile  | | Metadata |
      +---------+ +---------+ +----------+ +----------+
       Acorn JS +  npm registry  Observable  Publish
       Python text  metadata     version diff history
```

### Layer 1: Source-pattern analysis (`ast-inspector.js`)

Parses JavaScript source using [acorn](https://github.com/acornjs/acorn)
(vendored, so there is no external runtime npm dependency) and walks the AST to
detect selected call patterns. For Python, it uses pattern matching on joined
source lines (handling line continuations).

**Key design decisions:**
- **Tracks `require()` and `import` bindings.** `const { exec } = require('child_process'); exec('cmd')` is correctly traced. The inspector maintains a binding map so destructured imports (both object and array patterns) are caught.
- **Handles both module and script parse modes.** Falls back to script mode if module parse fails.
- **Error recovery.** If the walker crashes mid-traversal, partial findings are preserved.
- **Obfuscation-shaped patterns.** Computed property calls (`obj[expr]()`) and
  string concatenation in `require()` are flagged for review; the pattern alone
  does not establish evasive intent.
- **Selected evasion-shaped forms.** Recognizes patterns including indirect eval
  `(0,eval)()`, `setTimeout(string)`, `globalThis['eval']()`,
  `process.mainModule.require()`, `module.constructor._load()`,
  `WebAssembly.instantiate()`, `new Worker()`, selected prototype-chain forms,
  and DNS calls such as `dns.resolve()`.

Parser inputs fail loud on unrecognized schemas. Ruby/PHP/NuGet/Java manifest
fallbacks are partial exact-pin evidence rather than resolved graphs; replaced
Go modules are excluded and mark coverage incomplete. pnpm support is explicitly
bounded to lockfile major versions 6 and 9. Ruby lockfile coordinates are only
source-complete when the canonical RubyGems remote and a Bundler SHA-256
`CHECKSUMS` entry bind the artifact.

### Layer 2: Dependency Graph (`dep-graph.js`)

Profiles dependencies added by the analyzed npm package version relative to its
previous published version by fetching their registry metadata:
- **Very new dependencies:** Packages published less than seven days ago, with
  higher scores for sparse maintainer/version metadata
- **Same-publisher staging:** A new dependency published by the same account
  within 48 hours
- **Typosquatting:** Levenshtein distance comparison against a curated popular-package list (~165 npm / ~105 PyPI); thresholds are length-dependent and names ≤3 chars are never compared
- **Consumer install hooks on new deps:** New dependencies that declare
  `preinstall`, `install`, or `postinstall`

### Layer 3: Behavioral Fingerprinting (`behavioral.js`)

Builds capability profiles from inspectable install-script data. When previous
version scripts are available, it compares the two profiles; otherwise it emits
an initial-capability signal rather than claiming a between-version change.

### Layer 4: Registry Metadata (`signals.js`, `npm-registry.js`, `pypi-registry.js`)

Analyzes publish history, publishing-account changes, and timing metadata:
- **Publishing-account change** with time-decay (recent = CRITICAL, old = MODERATE)
- **Rapid publish** with a lower-severity likely-CI case (0s interval with multiple maintainers)
- **Version anomaly** (major jumps, dormancy followed by sudden publish)
- **Attestation fields** decoded from npm provenance bundles and compared with
  package/repository identity. An unavailable lookup or undecodable payload
  makes the requested stage incomplete. Signatures, certificates, and
  transparency-log inclusion are not cryptographically verified.

## Composite Risk Scoring

```
Base Score = Sum of (signal_weight * context_multipliers)

Context multipliers:
  - Package age < 30 days: 2.0x
  - Single maintainer: 1.5x
  - Signal carrying knownGood evidence: 0.2x

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
   [ Parsers ]  npm.js, pnpm.js, yarn.js, pypi.js, cargo.js, go.js, ruby.js, php.js, dotnet.js, java.js
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
| `metadata` | ecosystem + name | 24 hours | Reserved metadata cache API; current command paths do not populate it |
| `signals` | ecosystem + name + version | 24 hours by default | Analysis results; TTL uses the historical `metadataTtlMs` option |
| `freshness` | ecosystem + name | Persistent baseline | Last registry-latest version observed by monitor freshness polling |

**Corruption resilience:** Corrupted advisory JSON is deleted; corrupted
metadata/signal JSON is treated as a cache miss. If the database cannot be
opened, vexes falls back to a `NoOpCache` and continues without caching.

**Degraded-result handling:** Analysis results with unavailable metadata or
warnings are not cached. Analyze fetches current registry metadata before
reuse; both its evidence fingerprint and the current OSV advisory fingerprint
have to match the cached signal row, limiting stale false-clean reuse after
either changes.

## Tarball Inspection (`tarball-inspector.js`)

For `--deep` mode, downloads npm tarballs and PyPI sdists, then samples selected
source-like files. This is not exhaustive package-source review:

1. Require HTTPS on the npm/PyPI tarball host allowlist for the initial URL and every redirect hop (maximum five redirects)
2. Download with a compressed size limit (5MB)
3. For npm, compare compressed bytes with registry SRI or shasum metadata when provided
4. Gunzip with a decompressed size limit (50MB -- gzip bomb protection)
5. Parse raw POSIX tar headers (zero-dependency tar reader)
6. Retain at most 5,000 archive entries, each at most 10MB, within the global caps
7. Discard candidates larger than 512KB and select up to 10 entry/install-like files
8. Run those selected files through the JavaScript AST / Python pattern inspector

The selected sample is not a complete review of the archive.
Missing npm digest metadata is reported on the static path and refused for
dynamic extraction. The current PyPI sdist path is not digest-bound.

## Security boundaries

- **External data sanitization:** Shared output/logger paths sanitize external
  strings; complete coverage of every command-specific text path is still work
  in progress.
- **Config merge protection:** `__proto__`, `constructor`, and `prototype` keys
  are dropped.
- **Command-construction defenses:** Guard uses `execFileSync` (no shell) and a narrow explicit public-npm command grammar.
- **Displayed upgrade commands:** validate ecosystem coordinates, use
  POSIX-shell quoting, and add option boundaries where the tool supports them.
- **Input validation:** Ecosystem/severity flags are validated; scan/analyze
  target paths are checked before use.

The optional `--sandbox` path is best-effort dynamic telemetry, not proof of
containment. Under an accepted Linux `bwrap` host, analyze can execute one
selected npm entrypoint for each of up to five HIGH/CRITICAL candidates;
inspect can execute one for its target. These are not lifecycle hooks, and PyPI
dynamic extraction and execution are unsupported and refused (separate static
PyPI `--deep` sampling remains available). The accepted `bwrap` layout omits
the user's home/project and confines writes to the extracted workdir and
throwaway temp, but mounts `/usr`, `/bin`, and available loader-library
directories read-only for the runtime. `/etc` is not mounted. This is private
path isolation rather than a no-host-read boundary.
The current macOS profile is refused because its broad read rule exposes
arbitrary user files. The recorder covers selected Node APIs, is bypassable,
and is not inherited by child processes. Nonzero exits and timeouts fail the
stage, and every requested sandbox run remains incomplete because absent
recorder observations are not trusted as negative evidence.
