# Allowlists

vexes ships with a curated built-in exact-name set for common packages expected
to trigger selected install-hook signals in at least some versions. Signals
carrying the internal `knownGood` annotation are
**downweighted, not suppressed**. This is a noise-control heuristic, not a
guarantee that a later compromised version will be detected.

## How allowlisting works

Selected signal paths annotate allowlisted packages with `knownGood: true`. The
composite scoring engine applies a **0.2x weight multiplier** to signals carrying
that annotation, reducing those signals' score contribution by 80%. The
allowlist is not a blanket package exemption.

**Inspectable inline scripts are still analyzed.** The allowlist does not skip
the inline-script pattern pass. File-based commands such as `node install.js`
are not opened by this stage, however, so allowlisting does not establish
coverage of all lifecycle code.

This means:
- esbuild's expected install-hook case is flagged at `LOW` severity instead of
  the non-allowlisted `MODERATE`; this is a tuning choice, not a trust verdict
- If an allowlisted package's inspectable inline postinstall string starts
  accessing `process.env.AWS_SECRET_ACCESS_KEY`, the pattern signal still fires
  and its severity *label* stays CRITICAL, while its contribution to the
  composite risk score receives the same 0.2x known-good multiplier. File-based
  script bodies remain outside this inline stage.

## Curated install-hook package names

These names are included because versions of them commonly use install hooks for
work such as downloading platform-specific binaries or installing git hooks.
The list is name-based, not version-specific evidence that a hook is present or
benign in the version being analyzed:

### Build tools
`esbuild`, selected `@esbuild/...` platform packages, `swc`, `@swc/core`,
`lightningcss`, `@parcel/watcher`, `turbo`, `@vercel/turbo`, `vite`,
`node-sass`, `sass`

### Native modules
`sharp`, selected `@img/sharp-...` and `@img/sharp-libvips-...` platform
packages, `canvas`, `better-sqlite3`, `sqlite3`, `bcrypt`, `argon2`,
`fsevents`, `keytar`

### Build systems
`node-gyp`, `node-pre-gyp`, `@mapbox/node-pre-gyp`, `prebuild-install`, `grpc`, `@grpc/grpc-js`, `protobufjs`, `protobuf`

### Browsers / testing
`puppeteer`, `playwright`, `electron`, `electron-builder`, `cypress`

### ORM / database
`prisma`, `@prisma/client`, `@prisma/engines`

### Dev tools
`lefthook`, `husky`, `simple-git-hooks`, `patch-package`, `core-js`

## Popular package databases

Used for typosquat detection. A package name within Levenshtein distance 1 (4–6 chars) or 2 (7+ chars) of a popular package is flagged; names of 3 or fewer characters are never compared.

### npm (~165 entries)
lodash, chalk, react, axios, express, debug, tslib, commander, moment, uuid, webpack, typescript, eslint, prettier, jest, next, vue, tailwindcss, prisma, zod, pino, winston, and many more.

### PyPI (~105 entries)
requests, numpy, pandas, flask, django, scipy, matplotlib, pillow, pyyaml, cryptography, pydantic, fastapi, sqlalchemy, boto3, tensorflow, torch, pytest, black, ruff, openai, anthropic, and many more.

## Extending allowlists

Allowlists are currently built into `src/core/allowlists.js`; configuration-file
extensions are not implemented. A fork can change the source list, while normal
users can disable a signal or explicitly ignore reviewed findings through
configuration. Those choices have broader semantics than adding a trusted
package, so review them as policy.
