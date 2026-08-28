# Detection Benchmark

vexes measures its own detection against three ground-truth sets. All numbers
below are reproducible with `node benchmark/run.mjs` — no step of the
benchmark downloads malware anywhere (see [Safety](#safety)).

| Part | Measures | Result | Gate |
|---|---|---|---|
| A — known-bad flagging | Does scan flag historical compromised packages via OSV? | **5/5** | Yes — regression fails CI |
| B — technique fixtures | Do the heuristic layers fire on re-authored attack techniques? | **6/6** | No — tuning target |
| C — benign false positives | How often do popular packages draw HIGH/CRITICAL flags? | **0/10** | No — tuning target |

Last full run: **2026-08-28** (v0.5.0). CI re-runs the benchmark on every
change to `src/` — the latest numbers live in the
[benchmark workflow runs](https://github.com/penumbraforge/vexes/actions/workflows/benchmark.yml).

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

| technique | expected (any of) | fired | result |
|---|---|---|---|
| env-exfil-postinstall | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| downloader-postinstall | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| obfuscated-payload | POSTINSTALL_SCRIPT, AST_DANGEROUS_PATTERN, INITIAL_DANGEROUS_CAPABILITY | all three | ✅ |
| capability-escalation | CAPABILITY_ESCALATION | CAPABILITY_ESCALATION | ✅ |
| typosquat-name | TYPOSQUAT | TYPOSQUAT | ✅ |
| clean-build-script (FP check) | — | none | ✅ |

The benchmark already paid for itself: the `capability-escalation` fixture
exposed that `require('https').get(...)` — a direct require with no variable
binding — evaded network-capability detection. Fixed in 0.5.0.

## Part C — benign false positives

Popular packages, analyzed with `inspect --deep` (tarball AST-inspected as
text, never executed). A false positive is any HIGH or CRITICAL signal.
esbuild is included deliberately as a stressor: it carries a real
postinstall script (platform-binary bootstrap) that must NOT draw HIGH flags.

| package | HIGH/CRITICAL signals |
|---|---|
| lodash, express, chalk, ms, debug, semver, typescript, react, axios, esbuild | none |

MODERATE/LOW context signals (dormancy, missing provenance, maintainer
history) still appear in normal output — those are informational and
expected to fire on real-world packages.

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
