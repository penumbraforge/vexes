# Allowlists

vexes ships with built-in allowlists for packages that legitimately trigger certain signals. Allowlisted packages are **downweighted, not suppressed** -- a compromised version of an allowlisted package still triggers if new dangerous patterns appear.

## How allowlisting works

When a signal fires for an allowlisted package, it gets a `knownGood: true` evidence flag. The composite scoring engine applies a **0.2x weight multiplier** to known-good signals, reducing their contribution to the risk score by 80%.

**AST analysis always runs.** Even for known-good packages, vexes parses and inspects install scripts via the AST inspector. The findings are produced with the `knownGood` flag so scoring can downweight them, but the analysis itself is never skipped. This ensures that a compromised version of esbuild or sharp cannot hide malicious code in install scripts.

This means:
- esbuild's legitimate postinstall is flagged at `LOW` severity instead of `HIGH`
- If esbuild's postinstall suddenly starts accessing `process.env.AWS_SECRET_ACCESS_KEY`, that new signal is NOT downweighted and fires at full severity

## Known postinstall packages

These packages have install scripts for legitimate reasons (downloading platform-specific binaries, installing git hooks, etc.):

### Build tools
`esbuild`, `@esbuild/*`, `swc`, `@swc/core`, `lightningcss`, `@parcel/watcher`, `turbo`, `@vercel/turbo`, `vite`, `node-sass`, `sass`

### Native modules
`sharp`, `@img/sharp-*`, `@img/sharp-libvips-*`, `canvas`, `better-sqlite3`, `sqlite3`, `bcrypt`, `argon2`, `fsevents`, `keytar`

### Build systems
`node-gyp`, `node-pre-gyp`, `@mapbox/node-pre-gyp`, `prebuild-install`, `grpc`, `@grpc/grpc-js`, `protobufjs`, `protobuf`

### Browsers / testing
`puppeteer`, `playwright`, `electron`, `electron-builder`, `cypress`

### ORM / database
`prisma`, `@prisma/client`, `@prisma/engines`

### Dev tools
`lefthook`, `husky`, `simple-git-hooks`, `patch-package`, `core-js`

## Popular package databases

Used for typosquat detection. A package name within Levenshtein distance 1-2 of a popular package is flagged.

### npm (~150 popular packages)
lodash, chalk, react, axios, express, debug, tslib, commander, moment, uuid, webpack, typescript, eslint, prettier, jest, next, vue, tailwindcss, prisma, zod, pino, winston, and many more.

### PyPI (~100 popular packages)
requests, numpy, pandas, flask, django, scipy, matplotlib, pillow, pyyaml, cryptography, pydantic, fastapi, sqlalchemy, boto3, tensorflow, torch, pytest, black, ruff, openai, anthropic, and many more.

## Extending allowlists

Currently, allowlists are built into the source code (`src/core/allowlists.js`). Future versions will support extending them via `.vexesrc.json`:

```json
{
  "allowlists": {
    "postinstall": ["my-internal-build-tool"]
  }
}
```

To modify the built-in allowlists, edit `src/core/allowlists.js` directly.
