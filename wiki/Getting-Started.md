# Getting Started

## Installation

```bash
# Install globally
npm install -g @penumbraforge/vexes

# Or run without a global install
npx @penumbraforge/vexes scan

# Or clone the repo
git clone https://github.com/penumbraforge/vexes.git
cd vexes
node bin/vexes.js scan --path /your/project
```

**Requirements:** Node.js >= 22.13.0

vexes uses Node.js built-in `node:sqlite` for caching and built-in `fetch` for
HTTP. `node:sqlite` first appeared in 22.5.0 behind a runtime flag and became
usable without that flag in 22.13.0. Vexes has no external runtime npm
dependencies; Acorn is vendored.

## Your first scan

```bash
cd /path/to/your/project
vexes scan
```

vexes will:
1. Discover dependency inputs in the current directory (package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, Pipfile.lock, go.mod/go.sum, Gemfile.lock, composer.lock, etc.)
2. Best-effort extract supported dependency records from those files
3. Query the [OSV.dev](https://osv.dev) vulnerability database
4. Report vulnerabilities grouped by severity

Prefer resolved lockfiles. Exact pins from Ruby/PHP/NuGet/Java manifest
fallbacks may still be queried, but the result remains incomplete; replaced Go
modules and unsupported lockfile schemas are also reported as incomplete rather
than silently omitted. If only `go.sum` exists, its checksum history can include
modules no longer active in the build. pnpm support currently covers lockfile
majors 6 and 9. Ruby lock entries without Bundler SHA-256 `CHECKSUMS` are
reported incomplete rather than treating a mirrorable name/version as sealed.

### Understanding the output

```text
  vexes v0.6.1 -- scanning dependencies

  Found 124 unique packages across 1 lockfile(s)
  ~ 124 packages checked (0 cached)

  -- CRITICAL --------------------------------------------------
  express 4.17.1 (npm)
    GHSA-rv95-896h-c2yt -- Open redirect in express
    Fixed in: >= 4.19.2
    https://osv.dev/vulnerability/GHSA-rv95-896h-c2yt

  --------------------------------------------------
  1 vulnerability . 1 critical
  in 124 packages across npm
  --------------------------------------------------
```

This is illustrative output. Advisory details and counts change as OSV data is
updated.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Requested checks completed with no vulnerabilities at or above the active threshold; not a safety verdict |
| `1` | Vulnerabilities found at or above the severity threshold |
| `2` | Error -- scan was incomplete (query failures, parse errors) |

**Why exit code 2?** A security scanner that silently reports clean when queries fail is dangerous. If vexes can't check a package, it tells you.

## Deep analysis

For supply chain threat detection beyond known vulnerabilities:

```bash
vexes analyze
```

This prefers dependencies a parser identifies as direct. If that parser exposes
no direct markers, vexes falls back to its parsed set; `--verbose` always uses
the parsed set. It fetches npm/PyPI registry metadata and runs the available
analysis layers. It can
surface:
- Publishing-account changes (a possible review lead, not proof of takeover)
- Suspicious publish timing
- Install-script presence and inspectable inline patterns
- Names similar to a curated popular-package list
- Very new or sparse-metadata dependencies added by the analyzed npm release

Use `--deep` to download a tarball and inspect up to 10 selected entry/install-like
files from a bounded sample. This is slower and not an exhaustive source review:

```bash
vexes analyze --deep
```

Because that sample is not whole-package coverage, a requested deep stage is
reported as incomplete and exits 2 while preserving the sampled findings.

Use `--explain` for a detailed breakdown of a specific package:

```bash
vexes analyze --explain axios
```

## Next steps

- [Commands Reference](Commands-Reference.md) -- Command and option reference
- [CI/CD Integration](CI-CD-Integration.md) -- Set up automated scanning
- [Configuration](Configuration.md) -- Customize behavior with .vexesrc.json
