# Detection Benchmark

The benchmark measures three different trust boundaries. It does not combine
them into a single “detection rate,” and it does not download or execute
malware.

| Part | Current result | What gates |
|---|---|---|
| A — exact advisory identity | **5/5** historical malicious versions matched to the expected advisory | Every requested row must complete and match its exact advisory |
| B — technique evidence | **5/5** attacks; **2/2** negative controls clean | Every attack must emit its technique-specific evidence; every control must avoid forbidden and HIGH/CRITICAL signals |
| C — pinned live sampled evidence | **1/10** controls emitted HIGH/CRITICAL heuristic signals; **0/10** had current blocking advisory evidence | Artifact identity, sample production, advisory controls, and an FP ceiling of 1 all gate; source coverage remains explicitly incomplete |

Last live run: **2026-08-28** from the v0.6.1 worktree. The full run had zero
execution errors and zero gate regressions, but its overall status was
**INCOMPLETE** because Part C is bounded source sampling, not full-package
coverage.

## Status and exit semantics

The runner distinguishes execution integrity from evidence coverage:

- `PASS`: every selected gate passed and its evidence was complete. Exit 0.
- `INCOMPLETE`: execution succeeded and the sampled measurement gates passed,
  but evidence coverage was explicitly incomplete. Exit 0 in the normal local
  benchmark so the sampled FP measurement remains usable and is never called
  complete.
- `FAIL`: execution completed, but an exact-advisory, technique/control, current
  blocking-advisory, or FP-ceiling gate regressed. Exit 1.
- `ERROR`: a process, registry, OSV, metadata anchor, digest, JSON contract, or
  analysis step failed. Exit 2. An errored row has `fp: null`; it is never
  counted as clean.

`--require-complete` turns the current Part C coverage limitation into exit 2.
That is useful for a release policy that refuses sampled evidence. It does not
change the reported status or pretend bounded sampling became exhaustive.

Each selected part gates itself:

```text
node benchmark/run.mjs --part a
node benchmark/run.mjs --part b
node benchmark/run.mjs --part c
node benchmark/run.mjs                 # all three gates
node benchmark/run.mjs --require-complete
```

Pull-request CI runs A and B as separate gates. Main pushes and the weekly
schedule run all three. Part C’s normal CI result is expected to be
`INCOMPLETE` with exit 0 while bounded sampling is the implemented coverage
mode; execution errors and metric regressions still fail CI.

## Part A — exact known-bad identification

Part A writes lockfile text containing exact historical versions and runs
`vexes scan --severity low`. No package tarball is fetched. A row passes only
when the expected advisory ID itself appears; a different HIGH/CRITICAL finding
does not count as a match.

| package | version | expected advisory | result |
|---|---|---|---|
| event-stream | 3.3.6 | GHSA-mh6f-8j2x-4483 | ✅ |
| ua-parser-js | 0.7.29 | GHSA-pjwm-rvh2-c87w | ✅ |
| coa | 2.0.3 | GHSA-73qr-pfmq-6rp8 | ✅ |
| node-ipc | 11.3.0 | GHSA-3mpp-xfvh-qh37 | ✅ |
| crossenv | 0.0.8 | GHSA-c2m4-w5hm-vqjw | ✅ |

This measures advisory-intelligence identity, not heuristic malware recall.
Removed historical npm tarballs are intentionally not recovered from malware
archives for this benchmark.

## Part B — discriminating technique fixtures

Part B analyzes inert source strings authored for this repository. Generic
install-script presence cannot satisfy an attack fixture.

| fixture | required evidence | result |
|---|---|---|
| environment exfiltration | `ENV_HARVESTING` **and** `NETWORK_ACCESS` AST patterns | ✅ |
| downloader | `PROCESS_SPAWN` AST pattern | ✅ |
| decoded payload | `CODE_EXECUTION` **and** `BASE64_DECODE` AST patterns | ✅ |
| capability escalation | verified `network` capability escalation **and** `NETWORK_ACCESS` AST pattern | ✅ |
| typosquat name | `TYPOSQUAT` | ✅ |
| benign inline build verification | no forbidden AST/escalation and no HIGH/CRITICAL signal | ✅ |
| ordinary no-hook metadata | no AST, typosquat, or homoglyph signal and no HIGH/CRITICAL signal | ✅ |

The benign postinstall control still emits deterministic
`POSTINSTALL_SCRIPT(MODERATE)`. That is intentional context: script presence is
an execution surface, while maliciousness must come from content or behavioral
evidence. Both negative controls are gates, not auto-passing rows.

## Part C — pinned live sampled deep evidence

Part C is a live false-positive control set, not a permanent declaration that
any package is safe. Before invoking `inspect`, the runner verifies the exact
requested version exists and matches the manifest’s registry tarball URL,
SHA-512 integrity, and SHA-1 shasum. A missing anchor or digest mismatch is an
execution error, never a clean result.

The advisory snapshot date is **2026-08-28**. At that snapshot, none of the ten
pinned controls had HIGH/CRITICAL advisory evidence. If one later acquires such
evidence, the current-blocking-evidence gate fails; it is not mislabeled as a
heuristic false positive.

The current `--deep` implementation samples selected entry/install-like source
files under strict file and archive bounds. It does not inspect every source
file. The benchmark records this as `bounded-source-sampling`, retains
`evidenceComplete: false`, and reports how many files were sampled.

A Part C heuristic false positive means at least one HIGH/CRITICAL
**non-advisory** signal appeared in that bounded sample:

| package | pinned version | sampled files | HIGH/CRITICAL heuristic signal |
|---|---:|---:|---|
| picocolors | 1.1.1 | 1 | none |
| express | 4.21.2 | 2 | none |
| chalk | 5.4.1 | 3 | none |
| ms | 2.1.3 | 1 | none |
| debug | 4.4.1 | 1 | none |
| semver | 7.7.2 | 3 | none |
| commander | 15.0.0 | 1 | none |
| esbuild | 0.25.9 | 3 | `TARBALL_DANGEROUS_PATTERN` (multiple findings) |
| react | 19.1.1 | 7 | none |
| zod | 4.5.2 | 10 | none |

The current measured rate is **1/10 sampled controls**. The gate ceiling is 1,
which prevents regression from this documented baseline. The remaining esbuild
finding reflects real installer capabilities (process execution and network
access), but those capabilities are not by themselves a maliciousness verdict.
Passing this ceiling does not mean the packages were exhaustively inspected.

## Historical OSV parity snapshot

`node benchmark/parity.mjs` is a separate developer check that requires
Google’s `osv-scanner` on `PATH`. It compares full identifier sets (primary IDs
plus aliases) for the same generated lockfile and fails if either scanner's
execution or structured output is incomplete. On 2026-08-28, it reported 39/39
shared package/advisory identity groups with no set differences. Vexes emitted
41 raw findings and osv-scanner emitted 39 raw groups before alias-overlap
deduplication. Advisory databases change, so this is a dated observation, not
a stable coverage claim or part of the three benchmark gates above.

## Safety

- Part A sends lockfile coordinates to OSV; it does not fetch the historical
  malicious packages.
- Part B runs only repository-authored inert fixture strings in-process.
- Part C downloads only the exact registry artifacts pinned by version and
  digest, parses them as data, and never executes package code.
- A failed download, parse, advisory query, exact-version anchor, digest check,
  or analysis stage stays visible as an error or incomplete evidence.
