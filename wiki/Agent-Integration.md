# Agent Integration — the vexes JSON contract

Vexes is agent-callable through its CLI. No MCP server or SDK is required.
Normal successful JSON paths for `scan`, `analyze`, `fix`, `monitor --ci`,
`inspect`, `doctor`, and `licenses` use a shared top-level envelope. Payloads
are command-specific. `explain`/`triage`, guard setup/uninstall, watch streams,
and some early error paths do not yet follow this contract.

## 1. Streams

- On the documented successful structured paths, **stdout** is the JSON
  document; routine logs and progress go to stderr.
- **stderr** carries logs and progress. Rewrap stderr when capturing.
- `scan --sarif <file>` writes the report to a file and confirms on stderr.
  Other commands do not share that filename behavior.
- Validate JSON and the exit status. Early errors can still be human text.
- When inspecting an untrusted checkout for enforcement, pass
  `--no-project-config`; otherwise its `.vexesrc.json` can choose ordinary
  reporting policy, including ignores and disabled analysis signals. Add
  `--no-user-config` when the runner account's user policy must not affect a
  reproducible result.

## 2. The envelope

The documented structured command paths share this top-level shape
(`src/cli/schema.js`):

```
schemaVersion   "1.0"  — compatibility label; agents gate on breaking changes
generator       { name: "vexes", version, engine }
timestamp       ISO-8601
command         scan | analyze | fix | monitor | inspect | doctor | licenses
target          { dir, lockfiles: [], ecosystems: [] }
complete        boolean  — FALSE ⇒ never read the result as "clean"
warnings        string[]
result          { complete, warnings }   — nested copy for old consumers
summary         { total, vulnerable, critical, high, moderate, low, suppressed, directImportEvidence, aiReachable, ... }
findings        []      — normalized OSV-style records when that command uses them
(extra)         command-specific data, e.g. fixes, results, assessment, licenses
```

`findings[]` items add contract fields to the full internal record:

```
severityLevel   { level, order }
signal          detection signal id (`KNOWN_MALICIOUS` / `KNOWN_VULNERABILITY` in analysis; scan retains a legacy OSV-match name)
confidence      proven | deterministic | heuristic | inferred (`proven` means deterministic advisory match, not exploitation)
importEvidence  found_static | found_dynamic | not_found | unknown (canonical direct-import evidence)
reachability    reachable | lazy | dead | unknown   (legacy compatibility field; not runtime reachability)
direct          boolean — false means "known transitive", undefined = unknown
advisories      [osvId, ...aliases] deduped
fixed           ">= x.y.z" when a fix range is known
fixCommand      scan convenience command derived from OSV fixed events, when available; use `vexes fix` for candidate cross-checking
llmSummary      generated advisory/fix/import summary; no exploitability or blocker decision
```

Do not assume identical command payloads. For example, analyze records are under
`results` while normalized OSV findings are under `findings`.

## 3. Fail-loud rules

- `complete: false` (or exit code `2`) means "could not fully check".
  An agent MUST NOT report "no vulnerabilities" from this — report
  `scan incomplete` instead.
- `warnings` explain why: failed OSV batches, unparseable lockfiles, degraded
  cache, dropped vulnerability details, unavailable requested provenance,
  undecodable attestation payloads, or unresolved dependency-input coverage.
- `vexes doctor` smoke-tests parser fixture loading and a cache write/read, and
  reports optional endpoint/sandbox availability. Passing is not an accuracy or
  security attestation; a required-check failure means the installation is not ready.

## 4. Exit codes

```
0  requested checks complete / no findings at the active threshold (not a safety verdict)
1  findings or policy flags at/above the command's active threshold
2  error or incomplete scan
```

## 5. Schema versioning policy

- Bump `schemaVersion` only on **breaking** shape changes
  (removing/renaming a field, changing semantics).
- Adding fields is non-breaking and does NOT bump.
- `generator.version` tracks the CLI version and changes freely.

## 6. Readiness & speed

- `scan` batches against OSV.dev (`POST /v1/querybatch`, up to 1000 packages),
  deduplicates, and caches in local SQLite with TTL to reduce repeated requests.
  `--cached` accepts stale cache hits without a freshness check; cache misses
  can still require OSV access.
- Batching and caching reduce repeated OSV requests; elapsed time still depends
  on project size, cache state, and public endpoint latency.
- `analyze --deep` and `inspect --deep` download tarballs (streamed, size
  limited) and inspect a bounded selected-file sample. A requested sample is
  intentionally `complete:false` / exit `2` because it is not whole-package
  coverage; agents may retain the evidence but must not relabel it complete.
  npm bytes are checked against registry SRI/shasum metadata when available;
  current PyPI sampling is not digest-bound.
- `analyze --sandbox` and `inspect --sandbox` likewise remain incomplete / exit
  `2` when requested: recorder observations are positive-only evidence, not a
  trustworthy clean run. Retain any observations without upgrading coverage;
  a timeout or nonzero child exit is a failed stage, not behavior evidence.
- Ruby/PHP/NuGet/Java manifest fallbacks are partial exact-pin evidence rather
  than resolved graphs. Ruby lock entries without a canonical RubyGems remote
  and Bundler SHA-256 `CHECKSUMS` entry are likewise unresolved. Replaced Go
  modules and unsupported lockfile schemas also make dependency evidence
  incomplete. Do not infer a complete empty scan.

## 7. Example agent loop

```bash
vexes doctor --json | jq -e '.result.complete == true'
vexes scan --ai --json --path ./app | jq -c '.findings[] | {pkg: .package, sev: .severityLevel.level, ai: .aiImportContext.verdict, why: .aiImportContext.why, fix: .fixCommand}'
vexes inspect lodash@4.17.21 --json     # collect package evidence; no project needed
vexes fix --json --path ./app           # OSV-cross-checked upgrade candidates
vexes licenses --json --path ./app      # flat declared-license inventory
```

`scan --ai` adds advisory import-context classifications. AI never silences a
finding, and an AI failure leaves the deterministic scan's `complete` value
untouched. A `reachable` model response means the limited import evidence
supports package use; it does not establish execution of the vulnerable path.
The per-finding key is `aiImportContext`; the historical `exploitability` key
remains a deprecated compatibility alias. The summary key `aiReachable` records
the reachable-label count. `exploitable` remains a deprecated summary alias with
the same value and must not be interpreted as proof of exploitability.
`importEvidence` is scoped
to parsed project source and never suppresses findings. The older
`--min-reachability` option is deprecated and ignored.

## Providers (pick one, first match wins)

```
VEXES_AI_BASE        → OpenAI-compatible endpoint (/v1/chat/completions)
                       optional Bearer auth via VEXES_AI_KEY
ANTHROPIC_BASE_URL   → Anthropic-compatible cluster (vLLM native Messages API):
                       Bearer auth via ANTHROPIC_AUTH_TOKEN (or x-api-key via
                       ANTHROPIC_API_KEY), model auto-discovered from
                       GET <base>/v1/models.
ANTHROPIC_API_KEY    → hosted Anthropic API (x-api-key auth)
```

`VEXES_AI_MODEL` (or `ANTHROPIC_MODEL`) pins the model and skips discovery.
Discovery is cached per process and never throws: a dead cluster degrades each
finding to `aiImportContext.verdict: "error"` with `summary.aiError` counting it
— exit path and `complete` are unaffected. An agent provisioning the cluster
can't be sure a model answers there, so treat AI results as optional context.

`licenses` follows the same fail-loud rules: `complete:false` / exit `2` when any
lookup fails; missing declared license → exit `1`. License data is metadata for
policy, not exploitability — never treat it as a security blocker verdict.

The `llmSummary` field compresses severity, package, fix, and import evidence.
It does not decide whether a finding is exploitable or a policy blocker.
