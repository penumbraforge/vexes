/**
 * Tier A — build a DIRECT IMPORT EVIDENCE graph over the project's OWN source.
 *
 * Concept: a vulnerability matters more if the project's code actually imports
 * the package. The lockfile gives us the closure; the source tells us what it
 * imports. We parse the project source (acorn for JS, light scan for Python
 * and Rust `use`) to find bare-specifier imports, then classify each
 * dependency as:
 *
 *   reachable — imported statically (import/from or require) from an entrypoint
 *               reached transitively through the project's own files
 *   lazy      — only ever dynamically imported (`import()` / `require.resolve`)
 *   dead      — referenced by no project source we parsed
 *
 * HONESTY BOUNDARY: this is import evidence, not proven runtime reachability.
 * "dead" means "nothing we parsed imports it" — it does NOT mean the package
 * can never execute. Tooling, plugin loaders, binaries invoked by manifest
 * scripts, and files the scanner could not parse can all still load a "dead"
 * package. Consumers must not suppress findings on this grade alone.
 *
 * We deliberately do NOT recurse into node_modules: this tool is zero-dependency
 * and offline, and its value is separating the lockfile's imported surface
 * from the rest. Vulnerable "dead" deps still show up in the output — graded
 * with this evidence attached, not hidden.
 *
 * @module analysis/app-graph
 */

import { readFileSync, statSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve, extname, basename, sep } from 'node:path';
import { parse } from '../vendor/acorn.mjs';
import { log } from '../core/logger.js';

// Directories we never index — neither project source nor test fixtures.
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', '.next', '.nuxt',
  '.cache', 'coverage', 'vendor', 'test', 'tests', '__tests__', 'e2e',
]);

const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx']);
const TS_EXT = new Set(['.ts', '.tsx', '.mts', '.cts']);
const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.py', '.rs']);

// Ecosystems whose the source scanner can grade. Everything else returns
// "unknown" from reachabilityOf (never mislabeled dead — we didn't check).
const SCAN_ECOSYSTEMS = new Set(['npm', 'pypi', 'cargo']);

/**
 * Resolve the entrypoints of a project: package.json main/bin are canonical,
 * then `src/`, `bin/` dirs, then root `*.js` files (in that order — dedup not
 * required; BFS idempotent). Returns absolute paths.
 */
export function findEntryPoints(targetDir) {
  const entries = [];

  const pkgPath = join(targetDir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      const candidates = [];
      const mainType = typeof pkg.main === 'string' ? pkg.main
        : (pkg.exports && typeof pkg.exports === 'string' ? pkg.exports
        : (pkg.exports && typeof pkg.exports === 'object' && typeof pkg.exports.import === 'string' ? pkg.exports.import
        : (pkg.module && typeof pkg.module === 'string' ? pkg.module : null)));
      if (mainType) candidates.push(mainType);
      if (typeof pkg.bin === 'string') candidates.push(pkg.bin);
      else if (pkg.bin && typeof pkg.bin === 'object') {
        for (const p of Object.values(pkg.bin)) if (typeof p === 'string') candidates.push(p);
      }
      for (const cand of candidates) {
        const abs = resolve(targetDir, cand);
        try { if (statSync(abs).isFile()) entries.push(abs); } catch { /* missing — skip */ }
      }
    } catch (err) {
      log.warn(`could not read package.json for entry detection: ${err.message}`);
    }
  }

  for (const dirName of ['src', 'bin', 'lib']) {
    const dirAbs = join(targetDir, dirName);
    if (!existsSync(dirAbs)) continue;
    for (const f of walkFiles(dirAbs)) {
      if (SOURCE_EXT.has(extname(f)) && !f.includes(`${sep}node_modules${sep}`)) entries.push(f);
    }
  }

  try {
    for (const f of readdirSync(targetDir)) {
      if (f.startsWith('.')) continue;
      if (JS_EXT.has(extname(f))) entries.push(join(targetDir, f));
    }
  } catch { /* unreadable dir */ }

  return entries;
}

/**
 * List project files under a root, excluding skippable dirs. Absolute paths.
 */
export function walkFiles(rootAbs, out = []) {
  let entries;
  try { entries = readdirSync(rootAbs, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const abs = join(rootAbs, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walkFiles(abs, out);
    } else if (e.isFile()) {
      out.push(abs);
    }
  }
  return out;
}

/**
 * Bare specifier → dependency name. `lodash/merge` → `lodash`;
 * `@babel/core` → `@babel/core`; `node:`/relative/absolute → null.
 */
export function bareSpecifierName(spec) {
  if (!spec) return null;
  const s = String(spec);
  if (s.startsWith('.') || s.startsWith('/') || s.startsWith('#')) return null;
  if (s.startsWith('node:')) return null;
  if (s.startsWith('@') && s.includes('/')) {
    const [scope, pkg] = s.split('/');
    return `${scope}/${pkg}`; // scoped name, ignoring further subpath
  }
  return s.split('/')[0];
}

/**
 * Extract imports from one source file's text. Dispatch by extension.
 * Parsing failures degrade to an empty import set (never crash the scan).
 */
export function extractImports(src, fileAbs) {
  const file = fileAbs.replaceAll('\\', '/');
  const ext = extname(file).toLowerCase();
  if (JS_EXT.has(ext)) return extractJsImports(src, file);
  if (TS_EXT.has(ext)) return extractTsImports(src, file);
  if (ext === '.py') return extractPythonImports(src, file);
  if (ext === '.rs') return extractRustImports(src, file);
  return { file, static: [], dynamic: [] };
}

const WALK_SKIP_KEYS = new Set(['source', 'loc', 'start', 'end', 'range']);
/** Generic AST child traversal (acorn ESTree). */
function* walkNode(node) {
  const queue = [node];
  while (queue.length) {
    const cur = queue.pop();
    yield cur;
    for (const key of Object.keys(cur)) {
      if (WALK_SKIP_KEYS.has(key)) continue;
      const val = cur[key];
      if (Array.isArray(val)) { for (const item of val) if (item && typeof item === 'object') queue.push(item); }
      else if (val && typeof val === 'object') queue.push(val);
    }
  }
}

/**
 * Acorn-based static+CJS import extraction. Same vendored parser as
 * ast-inspector; we walk only for Import/Export/require/import() nodes.
 * `require(x)` counts as static, `require.resolve(x)` counts as lazy-dynamic
 * (it only ever checks existence — the target is never executed by it).
 */
function extractJsImports(src, file) {
  const imports = { file, static: [], dynamic: [] };
  const parseOpts = { ecmaVersion: 'latest', locations: true };

  const tryWalk = (options) => {
    const ast = parse(src, options);
    for (const node of walkNode(ast)) {
      if (node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
        if (typeof node.source?.value === 'string') imports.static.push(node.source.value);
      } else if (node.type === 'ImportExpression') {
        if (node.source && typeof node.source.value === 'string') imports.dynamic.push(node.source.value);
      } else if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'require') {
        if (node.arguments[0] && typeof node.arguments[0].value === 'string') imports.static.push(node.arguments[0].value);
      } else if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression' &&
                 node.callee.object?.type === 'Identifier' && node.callee.object.name === 'require' &&
                 node.callee.property?.name === 'resolve' &&
                 node.arguments[0]?.type === 'Literal' && typeof node.arguments[0].value === 'string') {
        imports.dynamic.push(node.arguments[0].value);
      }
    }
  };

  try {
    tryWalk({ ...parseOpts, sourceType: 'module' });
  } catch (modErr) {
    // CJS-heavy code (top-level await, import.meta, mixed idioms) can fail
    // module parsing; a script-sourceType retry covers most of it.
    try {
      tryWalk({ ...parseOpts, sourceType: 'script', allowAwaitOutsideFunction: true });
    } catch {
      log.debug(`cannot parse ${file}: ${modErr.message}`);
      return imports;
    }
  }

  return imports;
}

// TypeScript light scan (regex, not AST — acorn cannot parse TS syntax).
// Covers the runtime-relevant forms: `import x from 'p'` (incl. multi-line;
// `import type` is skipped — type-only imports never execute the package),
// side-effect `import 'p'`, `export ... from 'p'`, dynamic `import('p')`,
// and `require('p')`. Same honesty as the Python/Rust scanners: string and
// comment contents may produce false edges; path aliases (@/x, ~/x) resolve
// to nothing and are ignored as bare specifiers.
const TS_IMPORT_FROM_RE = /^\s*import\s+(type\s+)?[\s\S]*?from\s*['"]([^'"]+)['"]/gm;
const TS_EXPORT_FROM_RE = /^\s*export\s+(type\s+)?[\s\S]*?from\s*['"]([^'"]+)['"]/gm;
const TS_SIDE_EFFECT_RE = /^\s*import\s*['"]([^'"]+)['"]/gm;
const TS_DYNAMIC_RE = /import\(\s*['"]([^'"]+)['"]\s*\)/g;
const TS_REQUIRE_RE = /require\(\s*['"]([^'"]+)['"]\s*\)/g;

function extractTsImports(src, file) {
  const imports = { file, static: [], dynamic: [] };
  // `import type` / `export type` are erased at compile time — they never
  // execute the package, so they must not create reachability edges.
  for (const m of src.matchAll(TS_IMPORT_FROM_RE)) {
    if (!m[1]) imports.static.push(m[2]);
  }
  for (const m of src.matchAll(TS_EXPORT_FROM_RE)) {
    if (!m[1]) imports.static.push(m[2]);
  }
  for (const re of [TS_SIDE_EFFECT_RE, TS_REQUIRE_RE]) {
    for (const m of src.matchAll(re)) imports.static.push(m[1]);
  }
  for (const m of src.matchAll(TS_DYNAMIC_RE)) imports.dynamic.push(m[1]);
  return imports;
}

// Python light scan: import x / from x.y import z — skip `import _underscore`
// private modules and malformed lines. First or only segment is the package.
const PY_IMPORT_RE = /^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import.*)$/gm;
function extractPythonImports(src, file) {
  const imports = { file, static: [], dynamic: [] };
  for (const m of src.matchAll(PY_IMPORT_RE)) {
    const spec = m[1] || m[2];
    const top = spec ? spec.split('.')[0] : null;
    if (top && !top.startsWith('_')) imports.static.push(top);
  }
  return imports;
}

// Rust light scan: `use foo::` paths. Only the first segment is captured;
// `crate`/`self`/`super` are keywords, not dependency names.
const RS_USE_RE = /^\s*use\s+([\w]+)(?:::|;)/gm;
function extractRustImports(src, file) {
  const imports = { file, static: [], dynamic: [] };
  for (const m of src.matchAll(RS_USE_RE)) {
    if (['crate', 'self', 'super'].includes(m[1])) continue;
    imports.static.push(m[1]);
  }
  return imports;
}

/**
 * Build the reachability graph over a deps list for a target dir (Tier A).
 *
 * @param {string} targetDir
 * @param {Array<{name, version, ecosystem, ...}>} deps
 * @returns {{
 *   deps: Map<string, { name, ecosystem, reachability, evidence: string[] }>,
 *   sourceFiles: number, entryPoints: string[], categories: {reachable, lazy, dead, unknown}
 * }} keyed `${ecosystem}:${name}` — reachability is per-name, not per-version
 *   (code controls the name; the lockfile may carry several versions of it).
 */
export function buildAppGraph(targetDir, deps) {
  const states = new Map();
  for (const d of deps || []) {
    if (!SCAN_ECOSYSTEMS.has(d.ecosystem)) continue; // stays unknown
    const key = `${d.ecosystem}:${d.name}`;
    if (!states.has(key)) {
      states.set(key, { name: d.name, ecosystem: d.ecosystem, reachability: 'dead', evidence: [] });
    }
  }

  const entryPoints = findEntryPoints(targetDir);
  const files = walkFiles(targetDir).filter(f => SOURCE_EXT.has(extname(f)));

  // Parse every analyzable file once; track which files are project source we
  // can attribute imports to (skip node_modules that survived walkFiles).
  const perFile = new Map();
  for (const f of files) {
    let src;
    try { src = readFileSync(f, 'utf8'); } catch { continue; }
    perFile.set(f, extractImports(src, f));
  }
  const sourceFiles = perFile.size;

  // File graph: relative imports resolve to files; bare specifiers are tracked
  // separately and attributed during classification (not via the file graph).
  const fileEdges = new Map();
  for (const [f, info] of perFile) {
    const edges = [];
    const dir = join(f, '..');
    for (const spec of [...info.static, ...info.dynamic]) {
      if (bareSpecifierName(spec)) continue;
      if (!spec.startsWith('.') && !spec.startsWith('/')) continue;
      const abs = resolve(dir, spec);
      if (perFile.has(abs)) edges.push(abs);
    }
    fileEdges.set(f, edges);
  }

  // BFS over ALL import edges (static and dynamic alike) from every entrypoint
  // reached. A dynamically-imported file is still loadable code — it just runs
  // later, conditionally. To keep classification honest per plan, only fetch
  // decisions made at static edges matter for the reachable/lazy split below.
  const reachableFiles = new Set();
  const queue = entryPoints.filter(a => perFile.has(a));
  for (const e of queue) reachableFiles.add(e);
  while (queue.length) {
    const f = queue.pop();
    for (const n of fileEdges.get(f) || []) {
      if (!reachableFiles.has(n)) { reachableFiles.add(n); queue.push(n); }
    }
  }

  for (const [f, info] of perFile) {
    const editable = reachableFiles.has(f);
    for (const spec of info.static) {
      const name = bareSpecifierName(spec);
      if (!name) continue;
      const s = states.get(`${guessEco(f)}:${name}`);
      if (s) {
        if (editable) s.reachability = 'reachable';
        else if (s.reachability !== 'reachable') s.reachability = 'lazy';
        pushUnique(s.evidence, `${editable ? 'reachable' : 'unreachable'}#${spec}`);
      }
    }
    for (const spec of info.dynamic) {
      const name = bareSpecifierName(spec);
      if (!name) continue;
      const s = states.get(`${guessEco(f)}:${name}`);
      if (s && s.reachability !== 'reachable') {
        s.reachability = 'lazy';
        pushUnique(s.evidence, `dynamic#${spec}`);
      }
    }
  }

  const categories = { reachable: 0, lazy: 0, dead: 0, unknown: 0 };
  for (const s of states.values()) categories[s.reachability]++;
  const seenInGraph = new Set();
  for (const s of states.values()) seenInGraph.add(`${s.ecosystem}:${s.name}`);
  for (const d of deps || []) {
    if (!seenInGraph.has(`${d.ecosystem}:${d.name}`)) categories.unknown++;
  }

  return { deps: states, sourceFiles, entryPoints, categories };
}

function guessEco(file) {
  const ext = extname(file).toLowerCase();
  if (ext === '.py') return 'pypi';
  if (ext === '.rs') return 'cargo';
  return 'npm';
}

function pushUnique(arr, val) { if (!arr.includes(val)) arr.push(val); }

/**
 * Reachability label for one dependency finding: 'reachable' | 'lazy' |
 * 'dead' | 'unknown'. Unknown covers ecosystems we don't scan source for
 * (go, ruby, php, nuget, java) — never mislabeled dead.
 */
export function reachabilityOf(graph, ecosystem, name) {
  const s = graph?.deps?.get(`${ecosystem}:${name}`);
  if (!s) return 'unknown';
  return s.reachability;
}
