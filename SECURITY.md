# Security Policy

## Reporting a vulnerability

If you find a security issue in vexes itself (not in a package it flagged),
please open a [GitHub security advisory](https://github.com/penumbraforge/vexes/security/advisories/new)
rather than a public issue. You'll get a response within a week; fixes land
as a patch release and are noted in the changelog.

If vexes **missed** a compromised package you know about — a false negative
on a real incident — that is exactly the report we want most. Please open a
regular GitHub issue (this is a detection-quality matter, not a
confidentiality matter) with the package name, version, and advisory link if
one exists. The [detection benchmark](BENCHMARK.md) exists to make those
reports reproducible.

## Threat model — what vexes is and is not

vexes is a *read-only advisory tool*. It reads lockfiles, registry metadata,
and package source as text, and tells you what looks wrong. Understanding
what it cannot do matters as much as what it can:

**What it protects against**

- Installing packages with known malicious versions (OSV advisories, via
  `scan` and `guard`)
- Install-script attacks: static analysis flags lifecycle scripts that
  spawn processes, reach the network, read credentials, decode payloads, or
  write outside the project (via `analyze`/`inspect`)
- Between-version behavior changes: a package that gains dangerous
  capabilities in a new release (real diff of both versions' install scripts)
- Identity tricks: typosquats, homoglyphs, maintainer changes, missing
  provenance

**What it does not protect against**

- **It is not an uninstall button.** `guard` warns before install and
  blocks CRITICAL findings, but a `--force`, a skipped warning, or a plain
  `npm install` in a shell without wrappers runs the package. vexes is not
  in that code path — by design, it cannot be.
- **Static analysis is defeatable.** A payload split across files, fetched
  at runtime, hidden behind environment checks, or otherwise not present as
  a literal pattern in install scripts can evade it. Detection is pattern
  and capability based, not proof based.
- **Dynamic analysis is opt-in and platform-bound.** `--sandbox` runs
  candidate code under OS isolation and records behavior, but only on
  systems where the sandbox can be verified, and it is marked experimental.
  A sample resistant to this sandbox would not be caught.
- **No runtime protection.** Once a malicious script has run, vexes has
  nothing to offer — it does no endpoint detection, no persistence checks,
  no cleanup. It is designed to move the moment of failure *before* the
  install, not to repair after.
- **Advisory lag.** `KNOWN_COMPROMISED` is only as current as OSV. A
  compromise that hasn't been disclosed yet is invisible to `scan` — that
  is what the heuristic layers are for, and heuristics miss things.
- **Typosquat detection is name-based.** Distance to a hardcoded
  popular-package list; a novel enough name or a list gap is a miss.

**What vexes does with your data**

- Registry and OSV queries contain package names and versions — never your
  code, credentials, or file contents. There is no telemetry.
- Local AI triage (`explain`) sends findings only to the local provider you
  configure; remote providers (Anthropic) are opt-in and send finding
  summaries, not your source tree.

## Running untrusted code safely yourself

If you audit malware with vexes, keep the boundary we keep: analysis as
text is safe; execution is not. Never `npm install` a suspect package
without `--ignore-scripts` in an isolated environment, and treat extracted
tarballs as text artifacts, not build inputs. vexes' own test suite and
benchmark follow this rule — see BENCHMARK.md's Safety section.
