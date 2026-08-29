# Detection Benchmark

vexes measures its own detection against three ground-truth sets. All numbers
below are reproducible with `node benchmark/run.mjs` — no step of the
benchmark downloads malware anywhere (see [Safety](#safety)).

| Part | Measures | Result | Gate |
|---|---|---|---|
| A — known-bad identification | Does scan match the SPECIFIC OSV advisory for each historical compromise? | **5/5** | Yes — regression fails CI |
| B — technique detection | Do the heuristic layers fire on re-authored attacks — and stay quiet on a benign control? | **5/5 attacks** · **0/1 controls clean** | No — tuning target |
| C — benign false positives | How often do popular packages draw HIGH/CRITICAL signals? | **5/10** | No — tuning target |

Last full run: **2026-08-28** (v0.6.1). CI re-runs the benchmark on every
change to `src/` — the latest numbers live in the
[benchmark workflow runs](https://github.com/penumbraforge/vexes/actions/workflows/benchmark.yml).

> **Honesty note (0.6.1):** earlier versions of this document reported Part B
> as "6/6" — the benign control auto-passed by construction — and Part C as
> "0/10", which counted only OSV advisories and ignored heuristic HIGH/CRITICAL
> signals entirely. Both numbers were overclaims. The scoring now requires an
> exact advisory-identity match (A), scores controls as must-stay-quiet (B),
> and counts any HIGH/CRITICAL signal from any layer (C).

## Part A — known-bad flagging

Lockfiles pin the exact historically-malicious versions. `vexes scan` must
flag each one from its OSV advisory (`KNOWN_COMPROMISED`). Runs with
`--severity low` so the measurement is of the *detection* layer, not the
severity display filter — some incidents (node-ipc's ProTest) are rated LOW
CVSS upstream.

| package | version | incident | advisory | flagged |
|---|---|---|---|---|
| event-stream | 3.3.6 | 2018-11 | GHSA-mh6f-8j2x-4483 | ✅ |
| ua-parser-js | 0.7.29 | 2021-10 | GHSA-pjwm-rvh2-c87w | ✅ |
| coa | 2.0.3 | 2021-11 | GHSA-73qr-pfmq-6rp8 | ✅ |
| node-ipc | 11.3.0 | 2022-03 | GHSA-3mpp-xfvh-qh37 | ✅ |
| crossenv | 0.0.8 | 2017-08 | GHSA-c2m4-w5hm-vqjw | ✅ |

**Known limitation:** this set only exercises the registry-intel layer.
npm removes malicious versions after disclosure, so the original tarballs
are no longer fetchable from the registry — there is no honest way to
benchmark against live malware samples without pulling from third-party
malware archives, which we won't do.

## Part B — technique fixtures

Attack techniques re-authored by us as inert source strings (no copied
malware), fed through the full `analyzePackage` pipeline in-process:

| technique | kind | expected (any of) | fired | result |
|---|---|---|---|---|
| env-exfil-postinstall | attack | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| downloader-postinstall | attack | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| obfuscated-payload | attack | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| capability-escalation | attack | CAPABILITY_ESCALATION | CAPABILITY_ESCALATION | ✅ |
| typosquat-name | attack | TYPOSQUAT | TYPOSQUAT | ✅ |
| clean-build-script | control (must stay quiet) | — | POSTINSTALL_SCRIPT (HIGH) | ❌ |

**The control failure is a real finding, not a benchmark bug:** a benign
`postinstall` build-verification script draws a HIGH `POSTINSTALL_SCRIPT`
signal for any package not on the hand-maintained known-good allowlist.
That is over-flagging on the heuristic layer's part — published here as a
tuning target, exactly like Part C.

The benchmark already paid for itself: the `capability-escalation` fixture
exposed that `require('https').get(...)` — a direct require with no variable
binding — evaded network-capability detection. Fixed in 0.5.0.

## Part C — benign false positives

Popular packages, analyzed with `inspect --deep` (tarball AST-inspected as
text, never executed). A false positive is any HIGH or CRITICAL signal.
esbuild is included deliberately as a stressor: it carries a real
postinstall script (platform-binary bootstrap) that must NOT draw HIGH flags.

Popular packages, analyzed with `inspect --deep` (tarball AST-inspected as
text, never executed). A false positive is **any HIGH or CRITICAL signal from
any layer** — OSV-derived or heuristic. esbuild is included deliberately as a
stressor: it carries a real postinstall script (platform-binary bootstrap).

| package | HIGH/CRITICAL signals |
|---|---|
| express, chalk, debug, semver, react | none |
| lodash | VERSION_ANOMALY (HIGH) |
| ms | VERSION_ANOMALY (HIGH) |
| typescript | MAINTAINER_CHANGE, CIRCULAR_STAGING ×20 (CRITICAL) |
| esbuild | TARBALL_DANGEROUS_PATTERN ×9 (HIGH/CRITICAL) |
| axios | POSTINSTALL_SCRIPT (HIGH) |

**5/10 flagged** — not 0/10. Earlier versions of this table counted only OSV
advisories in the envelope summary and were blind to heuristic signals; the
scoring now reads signal severities directly. These are genuine
false-positive tuning targets for the heuristic layers, published honestly:

- `VERSION_ANOMALY` on long-lived stable versions (lodash, ms) is over-flagging.
- `CIRCULAR_STAGING` firing 20× on typescript's tarball suggests the detector
  double-counts rather than deduplicating per pattern.
- `TARBALL_DANGEROUS_PATTERN` on esbuild is the documented stressor case.

MODERATE/LOW context signals (dormancy, missing provenance, maintainer
history) also appear in normal output — those are informational.

## OSV parity vs osv-scanner

`node benchmark/parity.mjs` (dev-only; requires `osv-scanner` on PATH) runs
both vexes and Google's osv-scanner against the same lockfile of 11
packages at vulnerable versions and diffs the advisory sets, matching on
full identifier sets (GHSA + CVE aliases) since the two tools may surface
different ids for the same advisory.

Last run **2026-08-28**: 41 advisories found by vexes, 41 by osv-scanner,
**41 matched, 0 differences in either direction**. vexes' OSV querying
agrees with the reference implementation.

## Safety

- **Part A** downloads nothing: a lockfile is text, and vexes matches it
  against OSV advisories.
- **Part B** runs entirely in-process on source strings we wrote.
- **Part C** fetches only well-known benign packages, and analyzes them as
  text — package code is never executed (sandboxing is a separate explicit
  flag the benchmark never passes).
- Nothing in this benchmark, its manifest, or its fixtures is malware, so
  nothing needs to be (or can be) "contained" in CI.
