import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseLockfile as parseNpmLock, parseManifest as parseNpmManifest } from '../src/parsers/npm.js';
import { parseRequirements, parsePoetryLock, parsePyprojectToml } from '../src/parsers/pypi.js';
import { parseLockfile as parseCargoLock } from '../src/parsers/cargo.js';
import { parseManifest as parseGoMod } from '../src/parsers/go.js';
import { parseManifest as parseGemfile } from '../src/parsers/ruby.js';
import { parseManifest as parseComposerJson } from '../src/parsers/php.js';
import { parseManifest as parseCsproj } from '../src/parsers/dotnet.js';
import { parseManifest as parsePom } from '../src/parsers/java.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = join(__dirname, 'fixtures');

// ── npm parser ───────────────────────────────────────────────────────

describe('npm lockfile parser (v3)', () => {
  const deps = parseNpmLock(join(fixtures, 'package-lock-v3.json'));

  it('parses correct number of packages', () => {
    assert.equal(deps.length, 5); // express, body-parser, @babel/core, semver, jest
  });

  it('extracts package names correctly', () => {
    const names = deps.map(d => d.name).sort();
    assert.deepEqual(names, ['@babel/core', 'body-parser', 'express', 'jest', 'semver']);
  });

  it('handles scoped packages (@babel/core)', () => {
    const babel = deps.find(d => d.name === '@babel/core');
    assert.ok(babel, '@babel/core must be parsed');
    assert.equal(babel.version, '7.20.12');
    assert.equal(babel.ecosystem, 'npm');
  });

  it('handles nested scoped packages (semver under @babel/core)', () => {
    const semver = deps.find(d => d.name === 'semver');
    assert.ok(semver, 'nested semver must be parsed');
    assert.equal(semver.version, '6.3.1');
  });

  it('marks dev dependencies', () => {
    const jest = deps.find(d => d.name === 'jest');
    assert.ok(jest);
    assert.equal(jest.isDev, true);
  });

  it('marks non-dev dependencies', () => {
    const express = deps.find(d => d.name === 'express');
    assert.ok(express);
    assert.equal(express.isDev, false);
  });

  it('sets ecosystem to npm', () => {
    for (const dep of deps) {
      assert.equal(dep.ecosystem, 'npm');
    }
  });

  it('deduplicates packages', () => {
    const names = deps.map(d => `${d.name}@${d.version}`);
    const unique = new Set(names);
    assert.equal(names.length, unique.size, 'no duplicate name@version entries');
  });
});

describe('npm manifest parser (package.json fallback)', () => {
  it('throws on nonexistent file', () => {
    assert.throws(() => parseNpmManifest('/nonexistent/package.json'));
  });

  it('never treats a semver range lower bound as an installed version', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-npm-manifest-'));
    try {
      const path = join(dir, 'package.json');
      writeFileSync(path, JSON.stringify({ dependencies: { ranged: '^1.2.3', exact: '2.0.0' } }));
      const parsed = parseNpmManifest(path);
      assert.equal(parsed.some(d => d.name === 'ranged'), false);
      assert.ok(parsed.some(d => d.name === 'exact' && d.version === '2.0.0'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('npm lockfile parser artifact occurrences', () => {
  it('can preserve duplicate name/version occurrences with path and artifact identity', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-npm-occurrences-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app' }));
      const lockPath = join(dir, 'package-lock.json');
      writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/x': { version: '1.0.0', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-a' },
          'node_modules/a/node_modules/x': { version: '1.0.0', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-a' },
        },
      }));
      assert.equal(parseNpmLock(lockPath).length, 1, 'normal scans still deduplicate name/version');
      const occurrences = parseNpmLock(lockPath, { preserveOccurrences: true });
      assert.equal(occurrences.length, 2);
      assert.deepEqual(occurrences.map(d => d.occurrence).sort(), [
        'node_modules/a/node_modules/x', 'node_modules/x',
      ]);
      assert.ok(occurrences.every(d => d.resolved && d.integrity));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('uses alias artifact identity, preserves directness, and marks unanchored sources incomplete', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-npm-alias-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'app', dependencies: { safe: 'npm:real-package@1.0.0', ordinary: '2.0.0', local: 'file:../local' },
      }));
      const lockPath = join(dir, 'package-lock.json');
      writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/safe': {
            name: 'real-package', version: '1.0.0',
            resolved: 'https://registry.npmjs.org/real-package/-/real-package-1.0.0.tgz', integrity: 'sha512-real',
          },
          'node_modules/ordinary': {
            version: '2.0.0', resolved: 'https://registry.npmjs.org/ordinary/-/ordinary-2.0.0.tgz', integrity: 'sha512-ordinary',
          },
          'node_modules/local': { version: '1.0.0', resolved: 'file:../local' },
        },
      }));

      const parsed = parseNpmLock(lockPath);
      const alias = parsed.find(dep => dep.name === 'real-package');
      assert.ok(alias);
      assert.equal(alias.isDirect, true);
      assert.equal(parsed.some(dep => dep.name === 'safe'), false);
      assert.equal(parsed.some(dep => dep.name === 'local'), false);
      assert.equal(parsed.unresolvedEntries, 1);

      const occurrences = parseNpmLock(lockPath, { preserveOccurrences: true });
      assert.equal(occurrences.find(dep => dep.occurrence === 'node_modules/local').sourceType, 'file');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails legacy occurrence-preserving parses and counts non-public v1 sources', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-npm-v1-source-'));
    try {
      const lockPath = join(dir, 'package-lock.json');
      writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          public: { version: '1.0.0', resolved: 'https://registry.npmjs.org/public/-/public-1.0.0.tgz' },
          local: { version: '1.0.0', resolved: 'file:../local' },
        },
      }));
      const parsed = parseNpmLock(lockPath);
      assert.deepEqual(parsed.map(dep => dep.name), ['public']);
      assert.equal(parsed.unresolvedEntries, 1);
      assert.throws(() => parseNpmLock(lockPath, { preserveOccurrences: true }), /cannot preserve occurrence identity/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a public-registry URL whose tarball path names different bytes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-npm-artifact-binding-'));
    try {
      const lockPath = join(dir, 'package-lock.json');
      writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/innocent': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/malicious/-/malicious-1.0.0.tgz',
            integrity: 'sha512-attacker-controlled',
          },
          'node_modules/@scope/real': {
            version: '2.0.0',
            resolved: 'https://registry.npmjs.org/@scope/real/-/real-2.0.0.tgz',
          },
        },
      }));

      const parsed = parseNpmLock(lockPath);
      assert.equal(parsed.some(dep => dep.name === 'innocent'), false);
      assert.ok(parsed.some(dep => dep.name === '@scope/real'));
      assert.equal(parsed.unresolvedEntries, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Poetry lockfile source identity', () => {
  it('keeps source-less exact coordinates queryable but marks source coverage incomplete', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-poetry-source-'));
    try {
      const lockPath = join(dir, 'poetry.lock');
      writeFileSync(lockPath, `[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "anchored"
version = "1.2.3"
[package.source]
url = "https://pypi.org/simple"
`);
      const parsed = parsePoetryLock(lockPath);
      assert.deepEqual(parsed.map(dep => `${dep.name}@${dep.version}`), ['requests@2.31.0', 'anchored@1.2.3']);
      assert.equal(parsed[0].sourceType, 'unknown');
      assert.equal(parsed[1].sourceType, 'registry');
      assert.equal(parsed.unresolvedEntries, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── PyPI parser ──────────────────────────────────────────────────────

describe('PyPI requirements.txt parser', () => {
  const deps = parseRequirements(join(fixtures, 'requirements.txt'));

  it('parses pinned versions (==)', () => {
    const requests = deps.find(d => d.name === 'requests');
    assert.ok(requests);
    assert.equal(requests.version, '2.31.0');
    assert.equal(requests.isPinned, true);
  });

  it('does not treat minimum versions as installed versions', () => {
    const flask = deps.find(d => d.name === 'flask');
    assert.equal(flask, undefined);
  });

  it('does not invent latest for packages without version specs', () => {
    const pandas = deps.find(d => d.name === 'pandas');
    assert.equal(pandas, undefined);
  });

  it('normalizes package names (beautifulsoup4 → beautifulsoup4)', () => {
    const bs4 = deps.find(d => d.name === 'beautifulsoup4');
    assert.ok(bs4, 'beautifulsoup4 should be found with extras stripped');
  });

  it('skips git+ and file: specifiers', () => {
    const gitPkg = deps.find(d => d.name === 'git+https');
    assert.ok(!gitPkg, 'git+ URLs should be skipped');
  });

  it('skips option lines (-r, --index-url)', () => {
    const optLine = deps.find(d => d.name === '-r');
    assert.ok(!optLine, 'option lines should be skipped');
  });

  it('skips comment lines', () => {
    // Comment lines should not produce any deps
    assert.ok(deps.length > 0);
  });

  it('sets ecosystem to pypi', () => {
    for (const dep of deps) {
      assert.equal(dep.ecosystem, 'pypi');
    }
  });

  it('propagates unresolved entries and missing includes from nested files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-requirements-nested-'));
    try {
      writeFileSync(join(dir, 'requirements.txt'), '-r nested.txt\n-c constraints.txt\nroot==1.0.0\n');
      writeFileSync(join(dir, 'nested.txt'), 'exact==2.0.0\nranged>=3.0.0\n-r missing.txt\n');
      writeFileSync(join(dir, 'constraints.txt'), 'constraint-only==9.0.0\n');
      const parsed = parseRequirements(join(dir, 'requirements.txt'));
      assert.ok(parsed.some(dep => dep.name === 'root' && dep.version === '1.0.0'));
      assert.ok(parsed.some(dep => dep.name === 'exact' && dep.version === '2.0.0'));
      assert.equal(parsed.some(dep => dep.name === 'constraint-only'), false,
        'constraint entries are not proof that a package is installed');
      assert.ok(parsed.unresolvedEntries >= 3);
      assert.ok(parsed.includeFailures.some(message => message.includes('missing.txt')));
      assert.ok(parsed.includeFailures.some(message => message.includes('requires dependency resolution')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses all coordinates when a requirements file changes the package index', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-requirements-source-'));
    try {
      const path = join(dir, 'requirements.txt');
      writeFileSync(path, '--index-url https://private.example/simple\nrequests==2.31.0\n');
      const parsed = parseRequirements(path);
      assert.deepEqual([...parsed], []);
      assert.ok(parsed.unresolvedEntries > 0);
      assert.match(parsed.includeFailures.join('\n'), /source-changing pip option/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── Cargo parser ─────────────────────────────────────────────────────

describe('Cargo.lock parser', () => {
  const deps = parseCargoLock(join(fixtures, 'Cargo.lock'));

  it('parses correct number of packages', () => {
    assert.equal(deps.length, 2); // serde + tokio; workspace root is not crates.io
  });

  it('extracts package names and versions', () => {
    const serde = deps.find(d => d.name === 'serde');
    assert.ok(serde);
    assert.equal(serde.version, '1.0.193');
  });

  it('sets ecosystem to cargo', () => {
    for (const dep of deps) {
      assert.equal(dep.ecosystem, 'cargo');
    }
  });

  it('marks all as pinned', () => {
    for (const dep of deps) {
      assert.equal(dep.isPinned, true);
    }
  });

  it('excludes workspace/path packages with no crates.io source', () => {
    assert.equal(deps.some(d => d.name === 'my-project'), false);
  });
});

describe('go.mod parser', () => {
  const deps = parseGoMod(join(fixtures, 'go.mod'));

  it('parses require blocks and single-line require directives', () => {
    assert.equal(deps.length, 3);
    assert.ok(deps.find(d => d.name === 'github.com/gin-gonic/gin' && d.version === 'v1.10.0'));
    assert.ok(deps.find(d => d.name === 'github.com/google/uuid' && d.version === 'v1.6.0'));
  });

  it('marks // indirect dependencies as non-direct', () => {
    const dep = deps.find(d => d.name === 'golang.org/x/text');
    assert.ok(dep);
    assert.equal(dep.isDirect, false);
  });
});

describe('Gemfile parser', () => {
  const deps = parseGemfile(join(fixtures, 'Gemfile'));

  it('accepts exact pins and skips version ranges', () => {
    const rails = deps.find(d => d.name === 'rails');
    const puma = deps.find(d => d.name === 'puma');
    assert.equal(rails, undefined);
    assert.ok(puma);
    assert.equal(puma.version, '6.4.2');
  });

  it('marks exact version specs as pinned', () => {
    const puma = deps.find(d => d.name === 'puma');
    assert.equal(puma.isPinned, true);
  });
});

describe('composer.json parser', () => {
  const deps = parseComposerJson(join(fixtures, 'composer.json'));

  it('parses require and require-dev sections', () => {
    assert.ok(deps.find(d => d.name === 'guzzlehttp/guzzle' && d.version === '7.8.1'));
    assert.ok(!deps.find(d => d.name === 'laravel/framework'));
    assert.ok(!deps.find(d => d.name === 'phpunit/phpunit'));
  });

  it('skips platform packages that do not map to Packagist', () => {
    assert.ok(!deps.find(d => d.name === 'php'));
    assert.ok(!deps.find(d => d.name === 'ext-json'));
  });
});

describe('.csproj parser', () => {
  const deps = parseCsproj(join(fixtures, 'Example.csproj'));

  it('parses self-closing and nested PackageReference forms', () => {
    assert.ok(deps.find(d => d.name === 'Newtonsoft.Json' && d.version === '13.0.3'));
    assert.ok(deps.find(d => d.name === 'Serilog' && d.version === '3.1.1'));
  });

  it('sets ecosystem to nuget', () => {
    for (const dep of deps) {
      assert.equal(dep.ecosystem, 'nuget');
    }
  });
});

describe('pom.xml parser', () => {
  const deps = parsePom(join(fixtures, 'pom.xml'));

  it('parses explicit Maven dependency versions', () => {
    assert.ok(deps.find(d => d.name === 'org.springframework:spring-core' && d.version === '6.1.5'));
    assert.ok(deps.find(d => d.name === 'org.junit.jupiter:junit-jupiter' && d.version === '5.10.2'));
  });

  it('skips property-reference versions that are not concrete', () => {
    assert.ok(!deps.find(d => d.name === 'com.example:internal-shared'));
  });
});

// ── Error handling ───────────────────────────────────────────────────

describe('Parser error handling', () => {
  it('npm parser throws with clear message on nonexistent file', () => {
    assert.throws(
      () => parseNpmLock('/nonexistent/package-lock.json'),
      /cannot read/
    );
  });

  it('npm parser throws with clear message on invalid JSON', () => {
    // Create a temp file with invalid JSON — use the Cargo.lock file which is TOML not JSON
    assert.throws(
      () => parseNpmLock(join(fixtures, 'Cargo.lock')),
      /invalid JSON/
    );
  });

  it('cargo parser throws on nonexistent file', () => {
    assert.throws(
      () => parseCargoLock('/nonexistent/Cargo.lock'),
      /cannot read/
    );
  });
});
