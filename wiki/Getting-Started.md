# Getting Started

## Installation

```bash
# Install globally
npm install -g @penumbraforge/vexes

# Or run without installing
npx @penumbraforge/vexes scan

# Or clone the repo
git clone https://github.com/penumbraforge/vexes.git
cd vexes
node bin/vexes.js scan --path /your/project
```

**Requirements:** Node.js >= 22.5.0

vexes uses Node.js built-in `node:sqlite` (available since v22.5.0) for caching and built-in `fetch` for HTTP requests. No npm dependencies are needed.

## Your first scan

```bash
cd /path/to/your/project
vexes scan
```

vexes will:
1. Discover lockfiles in the current directory (package-lock.json, Cargo.lock, Pipfile.lock, etc.)
2. Parse all dependencies from those lockfiles
3. Query the [OSV.dev](https://osv.dev) vulnerability database
4. Report vulnerabilities grouped by severity

### Understanding the output

```
  vexes v0.1.0 -- scanning dependencies

  Found 124 unique packages across 1 lockfile(s)
  ~ 124 packages checked in 1.3s (0 cached)

  -- CRITICAL --------------------------------------------------
  express 4.17.1 (npm)
    GHSA-rv95-896h-c2yt -- Open redirect in express
    Fixed in: >= 4.19.2
    https://osv.dev/vulnerability/GHSA-rv95-896h-c2yt

  --------------------------------------------------
  1 vulnerability . 1 critical
  in 124 packages across npm
  completed in 1.3s
  --------------------------------------------------
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean -- no vulnerabilities found |
| `1` | Vulnerabilities found at or above the severity threshold |
| `2` | Error -- scan was incomplete (query failures, parse errors) |

**Why exit code 2?** A security scanner that silently reports clean when queries fail is dangerous. If vexes can't check a package, it tells you.

## Deep analysis

For supply chain threat detection beyond known vulnerabilities:

```bash
vexes analyze
```

This fetches registry metadata for each dependency and runs the 4-layer detection engine. It checks for:
- Maintainer account changes (possible takeover)
- Suspicious publish timing
- Install scripts on packages that shouldn't have them
- Typosquatting
- Newly added phantom dependencies

Use `--deep` to download and AST-inspect actual package source code (slower but thorough):

```bash
vexes analyze --deep
```

Use `--explain` for a detailed breakdown of a specific package:

```bash
vexes analyze --explain axios
```

## Next steps

- [Commands Reference](Commands-Reference.md) -- Full documentation for all commands
- [CI/CD Integration](CI-CD-Integration.md) -- Set up automated scanning
- [Configuration](Configuration.md) -- Customize behavior with .vexesrc.json
