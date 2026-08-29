# Configuration

vexes uses a layered configuration system: **defaults < user config < allowed
project policy < CLI flags**. Project config is deliberately narrower than user
config because it comes from the repository being inspected.

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
  "output": {
    "color": "auto",
    "format": "text"
  }
}
```

Only reporting-policy keys are accepted from `.vexesrc.json`: `ecosystems`,
`severity`, `ignore`, `strict`, `verbose`, `top`, the deprecated/no-op
`minReachability`, `analyze.signals`, and output `color`/`format`. Repository
config cannot enable sandbox execution, deep sampling, fix output, AI, or
stale-cache use, and it cannot choose the cache database or TTLs.

Pass `--no-project-config` when scanning an untrusted checkout for enforcement.
Without it, the repository can legitimately change what an ordinary report
shows by selecting ecosystems, adding ignores, or disabling signals.

## User config: `~/.config/vexes/config.json`

User config may set the reporting keys above plus ordinary cache storage and TTL
settings. It is applied before allowed project policy. Operational modes
(`--sandbox`, `--deep`, `--fix`, `--ai`, and `--cached`) are deleted from both
config sources and require an explicit flag on each invocation. Pass
`--no-user-config` when a reproducible run must ignore this runner-account
policy as well.

## Configuration options

### `ecosystems`

Array of ecosystems to scan. Default: `["npm", "pypi", "cargo", "go", "ruby", "php", "nuget", "java", "hex", "pub"]`.

Valid values: `npm`, `pypi`, `cargo`, `go`, `ruby`, `php`, `nuget`, `java`, `hex`, `pub`.

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
| `metadataTtlMs` | `86400000` (24 hours) | How long analysis-signal rows are reused (historical option name) |

The cache uses SQLite (Node.js built-in `node:sqlite`). Analyze fetches current
registry metadata before reusing a signal row and requires its evidence
fingerprint to match. The database has a metadata table/API, but current command
paths do not populate it. A corrupt advisory row is deleted; corrupt
metadata/signal rows are treated as misses. If the database cannot be opened,
vexes falls back to a no-op cache and continues without caching.

**TTL bounds:** Advisory TTL is clamped to a maximum of 7 days and the
historically named metadata/analysis-signal TTL to 30 days. This limits stale
reuse from an accidentally or deliberately large configured TTL; it does not
make cached evidence current.

### `output`

| Option | Default | Description |
|--------|---------|-------------|
| `color` | `auto` | `auto` (detect TTY), `always`, `never` |
| `format` | `text` | `text`, `json`, or `sarif` |

## CLI flag reference

| Flag | Config equivalent | Description |
|------|------------------|-------------|
| `--path <dir>` | `targetPath` | Target directory to scan |
| `--ecosystem <name>` | `ecosystems` | Filter to one ecosystem |
| `--severity <level>` | `severity` | Minimum severity |
| `--json` | `output.format: "json"` | JSON output |
| `--no-color` | `output.color: "never"` | Disable colors |
| `--no-user-config` | no config equivalent | Ignore `~/.config/vexes/config.json` for this invocation |
| `--no-project-config` | no config equivalent | Ignore `.vexesrc.json` for this invocation |
| `--cached` | `useCache: true` | Accept cache hits without TTL check; misses can still query OSV |
| `--verbose` | `verbose: true` | Verbose logging; analyze also includes the full parsed dependency set and LOW/UNKNOWN results |
| `--strict` | `strict: true` | Fail on non-ignored results meeting the active severity filter |
| `--deep` | `deep: true` | Download and inspect a bounded selected-file tarball sample |
| `--fix` | `fix: true` | Show advisory-derived upgrade hints in scan |
| `--explain <pkg>` | `explain: "pkg"` | Explain analysis for one package |
| `--min-reachability <grade>` | `minReachability` | Deprecated: accepted for compatibility, warned, and ignored; import evidence never filters findings |
| `--freshness <minutes>` | command flag | In monitor watch mode, poll npm/PyPI metadata using a persistent last-seen baseline |

## Environment variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | Disable ANSI colors (respects [no-color.org](https://no-color.org) convention) |

## Input validation

vexes validates CLI inputs:
- **Ecosystem names** are validated strictly. Invalid values via `--ecosystem` throw an error (with "did you mean?" suggestions). Invalid values from config files are dropped with a warning. If no valid ecosystems remain, vexes errors out rather than scanning nothing.
- **CLI severity flags** are validated. An invalid flag is ignored with a
  warning, leaving the configured/default severity in effect.
- **Paths** are verified to exist and be directories before scanning.
- **Signal switches** are all honored. The legacy `KNOWN_COMPROMISED` switch
  also controls `KNOWN_MALICIOUS` and `KNOWN_VULNERABILITY` when their own
  switches are absent. Project-local configuration can therefore suppress
  ordinary report evidence; review it as policy or use `--no-project-config`.
  Add `--no-user-config` when trusted runner-level policy must also be excluded.
- **Operational modes** cannot be enabled from project or user config. Sandbox,
  deep sampling, fix output, AI, and stale-cache use require explicit CLI flags.
  Guard additionally clears configured ignores and signal suppression before
  making its install decision.
