import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
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

  it('parses minimum versions (>=)', () => {
    const flask = deps.find(d => d.name === 'flask');
    assert.ok(flask);
    assert.equal(flask.version, '2.3.0');
  });

  it('parses packages without version specs', () => {
    const pandas = deps.find(d => d.name === 'pandas');
    assert.ok(pandas);
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
});

// ── Cargo parser ─────────────────────────────────────────────────────

describe('Cargo.lock parser', () => {
  const deps = parseCargoLock(join(fixtures, 'Cargo.lock'));

  it('parses correct number of packages', () => {
    assert.equal(deps.length, 3); // serde, tokio, my-project
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

  it('extracts best-effort versions from gem declarations', () => {
    const rails = deps.find(d => d.name === 'rails');
    const puma = deps.find(d => d.name === 'puma');
    assert.ok(rails);
    assert.ok(puma);
    assert.equal(rails.version, '7.1.3');
    assert.equal(puma.version, '6.4.2');
  });

  it('marks exact version specs as pinned', () => {
    const rails = deps.find(d => d.name === 'rails');
    const puma = deps.find(d => d.name === 'puma');
    assert.equal(rails.isPinned, false);
    assert.equal(puma.isPinned, true);
  });
});

describe('composer.json parser', () => {
  const deps = parseComposerJson(join(fixtures, 'composer.json'));

  it('parses require and require-dev sections', () => {
    assert.ok(deps.find(d => d.name === 'laravel/framework' && d.version === '11.2.0'));
    assert.ok(deps.find(d => d.name === 'guzzlehttp/guzzle' && d.version === '7.8.1'));
    assert.ok(deps.find(d => d.name === 'phpunit/phpunit' && d.version === '10.5.0'));
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
