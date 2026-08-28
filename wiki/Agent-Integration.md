# Agent Integration — the vexes JSON contract

Vexes is agent-callable via a **stable, versioned JSON CLI**. No MCP server,
no SDK, no API key for scanning: an agent shells out to `vexes <command> --json`
and gets one machine-readable document back. This document is the contract.

## 1. Streams

- **stdout** is ALWAYS the JSON document in structured mode. Nothing else.
  No banners, no spinners, no progress.
- **stderr** carries logs and progress. Rewrap stderr when capturing.
- SARIF (`--sarif`/`--format sarif`) may target a file; then stdout carries
  only the SARIF warning-free confirmation on stderr.

## 2. The envelope

Every machine command emits the same shape (`src/cli/schema.js`):

```
schemaVersion   "1.0"  — semver string; agents gate on this (change = breaking)
generator       { name: "vexes", version, engine }
timestamp       ISO-8601
command         scan | analyze | fix | monitor | inspect | doctor | licenses | triage
target          { dir, lockfiles: [], ecosystems: [] }
complete        boolean  — FALSE ⇒ never read the result as "clean"
warnings        string[]
result          { complete, warnings }   — nested copy for old consumers
summary         { total, vulnerable, critical, high, moderate, low, suppressed, unreachable, ... }
findings        []      — normalized OSV-style records with contract fields
(extra)         command-specific data, e.g. { fixes } for fix, { assessment } for inspect
```

`findings[]` items add contract fields to the full internal record:

```
severityLevel   { level, order }
signal          detection signal id (KNOWN_COMPROMISED, ...)
confidence      proven | deterministic | heuristic | inferred
reachability    reachable | lazy | dead | unknown   (Tier A: computed from the app-graph on every scan)
direct          boolean — false means "known transitive", undefined = unknown
advisories      [osvId, ...aliases] deduped
fixed           ">= x.y.z" when a fix range is known
fixCommand      exact upgrade command for the best verified fix, when available
llmSummary      ONE sentence for an agent to act on — answers "is this a blocker?"
```

Raw pre-schema fields (`vulnerabilities`, `version`, `complete`) are preserved
verbatim on the same object, so legacy consumers keep working.

## 3. Fail-loud rules

- `complete: false` (or exit code `2`) means "could not fully check".
  An agent MUST NOT report "no vulnerabilities" from this — report
  `scan incomplete` instead.
- `warnings` explain why: failed OSV batches, unparseable lockfiles, degraded
  cache, dropped vulnerability details.
- `vexes doctor` self-tests parsers + cache + network. Run it before relying
  on output; a failing doctor = untrustworthy scanner.

## 4. Exit codes

```
0  OK / no findings
1  findings at/above threshold (vulnerabilities, critical signals)
2  error or incomplete scan
```

## 5. Schema versioning policy

- Bump `schemaVersion` only on **breaking** shape changes
  (removing/renaming a field, changing semantics).
- Adding fields is non-breaking and does NOT bump.
- `generator.version` tracks the CLI version and changes freely.

## 6. Readiness & speed

- `scan` batches against OSV.dev (`POST /v1/querybatch`, up to 1000 packages),
  deduplicates, and caches in local SQLite with TTL — friendly to rate limits.
  `--cached` uses the cache without a freshness check.
- Run times are seconds against OSV thanks to batching + caching.
- `analyze --deep` and `inspect --deep` download tarballs (streamed, size
  limited) — slower by design; use only when actual code inspection is wanted.

## 7. Example agent loop

```bash
vexes doctor --json | jq -e '.result.complete == true'
vexes scan --ai --json --path ./app | jq -c '.findings[] | {pkg: .package, sev: .severityLevel.level, ai: .exploitability.verdict, why: .exploitability.why, fix: .fixCommand}'
vexes inspect lodash@4.17.21 --json     # "should I add this dep?" — no project needed
vexes fix --json --path ./app           # verified upgrade set (cross-checked against OSV)
vexes licenses --json --path ./app      # license SBOM (deps.dev; informational, never a verdict)
```

`scan --ai` demands respect for honesty rules: the Tier B `exploitability`
verdict is advisory. **Always** keep using Tier A `reachability` + severity for
blocking decisions — AI never silences a finding, and an AI failure leaves
`complete` untouched.

## Providers (pick one, first match wins)

```
VEXES_AI_BASE        → OpenAI-compatible endpoint (/v1/chat/completions)
ANTHROPIC_BASE_URL   → Anthropic-compatible cluster (vLLM native Messages API):
                       Bearer auth via ANTHROPIC_AUTH_TOKEN, model auto-discovered
                       from GET <base>/v1/models — no ANTHROPIC_API_KEY needed.
ANTHROPIC_API_KEY    → hosted Anthropic API (x-api-key auth)
```

`VEXES_AI_MODEL` (or `ANTHROPIC_MODEL`) pins the model and skips discovery.
Discovery is cached per process and never throws: a dead cluster degrades each
finding to `exploitability.verdict: "error"` with `summary.aiError` counting it
— exit path and `complete` are unaffected. An agent provisioning the cluster
can't be sure a model answers there, so keep `reachability` for blocking.

`licenses` follows the same fail-loud rules: `complete:false` / exit `2` when any
lookup fails; missing declared license → exit `1`. License data is metadata for
policy, not exploitability — never treat it as a security blocker verdict.

The `llmSummary` field is crafted so a model can triage without touching raw
advisory text: severity, package, fixed-in, reachability, and a blocker verdict
in one sentence.
