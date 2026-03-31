# Configuration

vexes uses a layered configuration system: **defaults < user config < project config < CLI flags**.

## Project config: `.vexesrc.json`

Place in your project root. vexes walks up directories (up to 20 levels) to find it.

```json
{
  "ecosystems": ["npm", "pypi", "cargo", "go", "ruby", "php", "nuget", "java"],
  "severity": "moderate",
  "ignore": [],
  "analyze": {
    "signals": {
      "NO_REPOSITORY": "off"
    }
  },
  "cache": {
    "dir": "~/.cache/vexes",
    "advisoryTtlMs": 3600000,
    "metadataTtlMs": 86400000
  },
  "output": {
    "color": "auto",
    "format": "text"
  }
}
```

## User config: `~/.config/vexes/config.json`

Same format as project config. Applied before project config, so project settings take priority.

## Configuration options

### `ecosystems`

Array of ecosystems to scan. Default: `["npm", "pypi", "cargo", "go", "ruby", "php", "nuget", "java"]`.

Valid values: `npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `nuget`, `java`, `brew`.

**CLI override:** `--ecosystem npm` (sets a single ecosystem)

### `severity`

Minimum severity level to report. Default: `moderate`.

Valid values: `critical`, `high`, `moderate`, `low`.

**CLI override:** `--severity critical`

### `analyze.signals`

Override signal behavior. Set to `"off"` to disable a signal entirely.

```json
{
  "analyze": {
    "signals": {
      "NO_REPOSITORY": "off",
      "POSTINSTALL_SCRIPT": "off",
      "RAPID_PUBLISH": "off"
    }
  }
}
```

### `cache`

| Option | Default | Description |
|--------|---------|-------------|
| `dir` | `~/.cache/vexes` | Cache directory (supports `~` expansion) |
| `advisoryTtlMs` | `3600000` (1 hour) | How long advisory results are cached |
| `metadataTtlMs` | `86400000` (24 hours) | How long registry metadata is cached |

The cache uses SQLite (Node.js built-in `node:sqlite`). If the cache becomes corrupted, vexes automatically degrades to a no-op cache and continues scanning.

**TTL bounds:** Advisory TTL is clamped to a maximum of 7 days, metadata TTL to 30 days. This prevents config-based attacks that set extremely long TTLs to keep stale (potentially false-clean) results cached indefinitely.

### `output`

| Option | Default | Description |
|--------|---------|-------------|
| `color` | `auto` | `auto` (detect TTY), `always`, `never` |
| `format` | `text` | `text` or `json` |

## CLI flag reference

| Flag | Config equivalent | Description |
|------|------------------|-------------|
| `--path <dir>` | `targetPath` | Target directory to scan |
| `--ecosystem <name>` | `ecosystems` | Filter to one ecosystem |
| `--severity <level>` | `severity` | Minimum severity |
| `--json` | `output.format: "json"` | JSON output |
| `--no-color` | `output.color: "never"` | Disable colors |
| `--cached` | `useCache: true` | Use cached results without TTL check |
| `--verbose` | `verbose: true` | Debug output |
| `--strict` | `strict: true` | Fail on any signal |
| `--deep` | `deep: true` | Download and inspect tarballs |
| `--fix` | `fix: true` | Show fix commands in scan |
| `--explain <pkg>` | `explain: "pkg"` | Explain analysis for one package |

## Environment variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | Disable ANSI colors (respects [no-color.org](https://no-color.org) convention) |

## Input validation

vexes validates CLI inputs:
- **Ecosystem names** are validated strictly. Invalid values via `--ecosystem` throw an error (with "did you mean?" suggestions). Invalid values from config files are silently dropped with a warning. If no valid ecosystems remain, vexes errors out rather than scanning nothing.
- **Severity levels** are validated. Invalid values fall back to `moderate` with a warning.
- **Paths** are verified to exist and be directories before scanning.
- **Critical signals** (`KNOWN_COMPROMISED`, `PHANTOM_DEPENDENCY`, `CIRCULAR_STAGING`, `CAPABILITY_ESCALATION`) cannot be disabled via config.
