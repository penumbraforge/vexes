import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  bareSpecifierName,
  extractImports,
  findEntryPoints,
  buildAppGraph,
  importEvidenceOf,
  reachabilityOf,
} from '../src/analysis/app-graph.js';

/**
 * TIER A REACHABILITY (vexes scan --min-reachability)
 *
 * Hermetic: builds tiny temp projects on disk and asserts the import graph
 * labels. No network, no OSV, no package installs.
 */

function makeProject(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vexes-app-graph-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel);
      mkdirSync(join(abs, '..'), { recursive: true });
      writeFileSync(abs, content);
    }
  } catch {
    rmSync(dir, { recursive: true, force: true });
    throw new Error('fixture setup failed');
  }
  return dir;
}

describe('app-graph: bare specifier resolution', () => {
  it('resolves unscoped and scoped bare specifiers', () => {
    assert.equal(bareSpecifierName('lodash'), 'lodash');
    assert.equal(bareSpecifierName('lodash/merge'), 'lodash');
    assert.equal(bareSpecifierName('@babel/core'), '@babel/core');
    assert.equal(bareSpecifierName('@babel/core/lib/index'), '@babel/core');
  });
  it('ignores relative, absolute, node:-builtins, and # alias specifiers', () => {
    assert.equal(bareSpecifierName('./y'), null);
    assert.equal(bareSpecifierName('../y'), null);
    assert.equal(bareSpecifierName('/abs'), null);
    assert.equal(bareSpecifierName('node:fs'), null);
    assert.equal(bareSpecifierName('#alias'), null);
    assert.equal(bareSpecifierName(''), null);
    assert.equal(bareSpecifierName(undefined), null);
    assert.equal(bareSpecifierName(null), null);
  });
});

describe('app-graph: import extraction', () => {
  it('extracts ES static, dynamic, export, require, and require.resolve from JS', () => {
    const info = extractImports(`
      import lodash from 'lodash';
      import * as ns from '@babel/core/lib/index';
      export { x } from './local.js';
      export * from 'moment';
      const dyn = import('lazy-dep');
      const req = require('middleware');
      require.resolve('plugin');
    `, '/tmp/proj/src/index.js');
    // Order (LIFO walker) is not a contract — sets are. Compare sorted.
    assert.deepEqual([...info.static].sort(), ['./local.js', '@babel/core/lib/index', 'lodash', 'middleware', 'moment']);
    assert.deepEqual([...info.dynamic].sort(), ['lazy-dep', 'plugin']);
  });

  it('falls back to script parse for CJS-heavy files', () => {
    const info = extractImports(`module.exports = function(){ return require('config'); }\n`, '/x/index.cjs');
    assert.ok(info.static.includes('config'));
  });

  it('degrading on broken source yields empty, not a throw', () => {
    const info = extractImports('const = ;;;', '/tmp/broken.js');
    assert.deepEqual(info.static, []);
    assert.deepEqual(info.dynamic, []);
  });
});

describe('app-graph: full graph', () => {
  it('classifies deps by how project code references them', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'demo', version: '1.0.0', main: 'index.js' }),
      'index.js': "import axios from 'axios'; import('chunk');\n",
      'src/utils.js': "const _ = require('lodash');\n",
    });
    try {
      const deps = [
        { name: 'axios', version: '1.14.1', ecosystem: 'npm' },
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
        { name: 'chunk', version: '0.0.1', ecosystem: 'npm' },
        { name: 'leftpad', version: '1.0.0', ecosystem: 'npm' },
        { name: 'cargo-crate', version: '0.1.0', ecosystem: 'cargo' },
      ];
      const graph = buildAppGraph(dir, deps);
      assert.equal(reachabilityOf(graph, 'npm', 'axios'), 'reachable', 'static import');
      assert.equal(reachabilityOf(graph, 'npm', 'lodash'), 'reachable', 'static require');
      assert.equal(reachabilityOf(graph, 'npm', 'chunk'), 'lazy', 'dynamic import only');
      assert.equal(reachabilityOf(graph, 'npm', 'leftpad'), 'dead', 'no project source reference');
      assert.equal(reachabilityOf(graph, 'cargo', 'cargo-crate'), 'unknown', 'no Rust source means no evidence');
      assert.equal(importEvidenceOf(graph, 'npm', 'axios'), 'found_static');
      assert.equal(importEvidenceOf(graph, 'npm', 'chunk'), 'found_dynamic');
      assert.equal(importEvidenceOf(graph, 'npm', 'leftpad'), 'not_found');
      assert.equal(importEvidenceOf(graph, 'cargo', 'cargo-crate'), 'unknown');
      assert.ok(graph.sourceFiles >= 2, 'parses both files');
      assert.ok(graph.entryPoints.includes(join(dir, 'index.js')), 'entrypoint found via package.json');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('grades TypeScript projects honestly — imports in .ts/.tsx create real edges', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'ts-app', version: '1.0.0', main: 'src/index.ts' }),
      'src/index.ts': [
        "import express from 'express';",
        "import {",
        "  spawnSync,",
        "} from 'child_process';",
        "import type { Config } from 'config-type-only';",
        "import('later').then(() => {});",
        "const fs = require('fs-extra');",
        "export * from 're-exported';",
        "export type { T } from 'type-reexport';",
        "",
      ].join('\n'),
      'src/util.ts': "import axios from 'axios';\n",
      'src/deep/thing.tsx': "const x = await import('tsx-dynamic');\n",
    });
    try {
      const deps = [
        { name: 'express', version: '4.17.1', ecosystem: 'npm' },
        { name: 'axios', version: '1.14.1', ecosystem: 'npm' },
        { name: 'fs-extra', version: '11.0.0', ecosystem: 'npm' },
        { name: 'later', version: '1.0.0', ecosystem: 'npm' },
        { name: 're-exported', version: '1.0.0', ecosystem: 'npm' },
        { name: 'config-type-only', version: '1.0.0', ecosystem: 'npm' },
        { name: 'type-reexport', version: '1.0.0', ecosystem: 'npm' },
        { name: 'tsx-dynamic', version: '1.0.0', ecosystem: 'npm' },
        { name: 'never-mentioned', version: '1.0.0', ecosystem: 'npm' },
      ];
      const graph = buildAppGraph(dir, deps);
      assert.equal(reachabilityOf(graph, 'npm', 'express'), 'reachable', 'TS static import');
      assert.equal(reachabilityOf(graph, 'npm', 'axios'), 'reachable', 'import in .ts submodule');
      assert.equal(reachabilityOf(graph, 'npm', 'fs-extra'), 'reachable', 'TS require()');
      assert.equal(reachabilityOf(graph, 'npm', 're-exported'), 'reachable', 'TS export-from re-export');
      assert.equal(reachabilityOf(graph, 'npm', 'later'), 'lazy', 'TS dynamic import');
      assert.equal(reachabilityOf(graph, 'npm', 'tsx-dynamic'), 'lazy', 'TSX dynamic import');
      assert.equal(reachabilityOf(graph, 'npm', 'config-type-only'), 'dead', 'import type never executes the package');
      assert.equal(reachabilityOf(graph, 'npm', 'type-reexport'), 'dead', 'export type never executes the package');
      assert.equal(reachabilityOf(graph, 'npm', 'never-mentioned'), 'dead', 'unreferenced dep in a TS project is not silently reachable');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('ignores dynamics in unimported files while grading reachable imports', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'app', version: '1.0.0' }),
      'src/index.js': "import('request');\n",
      'unused/tool.js': "import('request');\n", // unused dir is under project root (no skip), but not reachable
    });
    try {
      const deps = [{ name: 'request', version: '2.88.2', ecosystem: 'npm' }];
      const graph = buildAppGraph(dir, deps);
      assert.equal(reachabilityOf(graph, 'npm', 'request'), 'lazy'); // dynamic-only
      assert.ok(graph.sourceFiles >= 2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns unknown for ecosystems outside the scanner (no code states)', () => {
    const dir = makeProject({ 'index.js': "import axios from 'axios';\n" });
    try {
      const deps = [
        { name: 'axios', version: '1.14.1', ecosystem: 'npm' },
        { name: 'github.com/some/mod', version: 'v0.1.0', ecosystem: 'go' },
      ];
      const graph = buildAppGraph(dir, deps);
      assert.equal(reachabilityOf(graph, 'npm', 'axios'), 'reachable');
      assert.equal(reachabilityOf(graph, 'go', 'github.com/some/mod'), 'unknown', 'go is never graded');
      assert.equal(graph.categories.unknown, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns unknown rather than a negative verdict when the project has zero source files', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'config-only', version: '1.0.0' }),
    });
    try {
      const deps = [{ name: 'transitive-only', version: '1.0.0', ecosystem: 'npm' }];
      const graph = buildAppGraph(dir, deps);
      assert.equal(graph.sourceFiles, 0);
      assert.equal(importEvidenceOf(graph, 'npm', 'transitive-only'), 'unknown');
      assert.equal(reachabilityOf(graph, 'npm', 'transitive-only'), 'unknown');
      assert.deepEqual(graph.importEvidenceCategories, {
        foundStatic: 0,
        foundDynamic: 0,
        notFound: 0,
        unknown: 1,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns unknown when JavaScript source exists but cannot be parsed', () => {
    const dir = makeProject({
      'package.json': JSON.stringify({ name: 'broken-source', version: '1.0.0', main: 'index.js' }),
      'index.js': 'const = ;;;',
    });
    try {
      const deps = [{ name: 'possibly-loaded', version: '1.0.0', ecosystem: 'npm' }];
      const graph = buildAppGraph(dir, deps);
      assert.equal(graph.sourceFiles, 1, 'the source file was discovered');
      assert.equal(graph.sourceFilesByEcosystem.npm, 0, 'unparsed source is not usable negative evidence');
      assert.equal(importEvidenceOf(graph, 'npm', 'possibly-loaded'), 'unknown');
      assert.equal(reachabilityOf(graph, 'npm', 'possibly-loaded'), 'unknown');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
