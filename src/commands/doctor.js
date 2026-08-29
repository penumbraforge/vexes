import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope } from '../cli/schema.js';
import { C, out } from '../cli/output.js';
import { EXIT, NPM_REGISTRY_URL, OSV_BATCH_URL, VERSION } from '../core/constants.js';
import { AdvisoryCache } from '../cache/advisory-cache.js';
import { detectSandboxHost } from '../analysis/sandbox/index.js';
import * as npmParser from '../parsers/npm.js';
import * as pypiParser from '../parsers/pypi.js';
import * as cargoParser from '../parsers/cargo.js';
import * as goParser from '../parsers/go.js';
import * as rubyParser from '../parsers/ruby.js';
import * as phpParser from '../parsers/php.js';
import * as dotnetParser from '../parsers/dotnet.js';
import * as javaParser from '../parsers/java.js';
import * as hexParser from '../parsers/hex.js';
import * as pubParser from '../parsers/pub.js';

/**
 * `vexes doctor` — self test.
 *
 * Verifies the pieces an agent depends on: every parser round-trips a fixture
 * lockfile, the cache survives a write/read cycle, and the registries are
 * reachable. Network checks are REPORTED statuses, never hard failures — a
 * scanner must still function, with warnings, when offline.
 *
 * Invariant: never report "all good" when a check failed (same fail-loud
 * invariant as scan) — an agent that gets EXIT.ERROR from doctor must not
 * trust the tool's output.
 */

const PARSER_CHECKS = [
  { name: 'npm (package-lock-v3.json)', parseFn: npmParser.parseLockfile, file: 'package-lock-v3.json', minCount: 5, expected: { name: '@babel/core', version: '7.20.12' } },
  { name: 'pypi (requirements.txt)', parseFn: pypiParser.parseRequirements, file: 'requirements.txt', minCount: 4, expected: { name: 'requests', version: '2.31.0' } },
  { name: 'cargo (Cargo.lock)', parseFn: cargoParser.parseLockfile, file: 'Cargo.lock', minCount: 2, expected: { name: 'serde', version: '1.0.193' } },
  { name: 'go (go.mod)', parseFn: goParser.parseManifest, file: 'go.mod', minCount: 3, expected: { name: 'github.com/gin-gonic/gin', version: 'v1.10.0' } },
  { name: 'ruby (Gemfile)', parseFn: rubyParser.parseManifest, file: 'Gemfile', minCount: 1, expected: { name: 'puma', version: '6.4.2' } },
  { name: 'php (composer.json)', parseFn: phpParser.parseManifest, file: 'composer.json', minCount: 1, expected: { name: 'guzzlehttp/guzzle', version: '7.8.1' } },
  { name: 'dotnet (Example.csproj)', parseFn: dotnetParser.parseManifest, file: 'Example.csproj', minCount: 2, expected: { name: 'Newtonsoft.Json', version: '13.0.3' } },
  { name: 'java (pom.xml)', parseFn: javaParser.parseManifest, file: 'pom.xml', minCount: 2, expected: { name: 'org.springframework:spring-core', version: '6.1.5' } },
  { name: 'hex (mix.lock)', parseFn: hexParser.parseLockfile, file: 'mix.lock', minCount: 3, expected: { name: 'jason', version: '1.4.4' } },
  { name: 'pub (pubspec.lock)', parseFn: pubParser.parseLockfile, file: 'pubspec.lock', minCount: 3, expected: { name: 'args', version: '2.4.2' } },
];

// Fixture paths resolve relative to the PACKAGE ROOT (this module lives at
// src/commands/doctor.js), NOT the current working directory. The old
// cwd-relative path only worked when cwd happened to be the repo — a doctor
// run from an installed package or an unrelated project failed every parser
// check and reported the tool untrustworthy.
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// `fixturesDir` and `parserChecks` are injectable so tests can exercise the
// fail-loud path without relying on the caller's cwd or mutating real fixtures.
export async function runParserChecks(
  fixturesDir = join(PACKAGE_ROOT, 'test', 'fixtures'),
  parserChecks = PARSER_CHECKS,
) {
  const checks = [];
  for (const { name, parseFn, file, minCount, expected, intentionalEmpty = false } of parserChecks) {
    const path = join(fixturesDir, file);
    const expectedCoordinate = expected ? `${expected.name}@${expected.version}` : null;
    try {
      const deps = parseFn(path);
      if (!Array.isArray(deps)) {
        throw new Error('parser returned a non-array result');
      }
      if (intentionalEmpty && deps.length !== 0) {
        throw new Error(`intentional empty fixture returned ${deps.length} dep(s)`);
      }
      if (deps.length < minCount) {
        throw new Error(`returned ${deps.length} dep(s); expected at least ${minCount}`);
      }
      if (!intentionalEmpty && !expected) {
        throw new Error('doctor fixture is missing an expected dependency coordinate');
      }
      if (expected && !deps.some(dep => dep?.name === expected.name && dep?.version === expected.version)) {
        throw new Error(`missing expected coordinate ${expectedCoordinate}`);
      }
      checks.push({
        name: `parser ${name}`,
        ok: true,
        detail: intentionalEmpty
          ? 'intentional empty fixture returned 0 dep(s)'
          : `${deps.length} dep(s); found ${expectedCoordinate}`,
        actualCount: deps.length,
        expectedMinimum: minCount,
        expectedCoordinate,
      });
    } catch (err) {
      checks.push({
        name: `parser ${name}`,
        ok: false,
        detail: err.message,
        expectedMinimum: minCount,
        expectedCoordinate,
      });
    }
  }
  return checks;
}

async function runCacheCheck() {
  const dir = mkdtempSync(join(tmpdir(), 'vexes-doctor-'));
  try {
    const cache = new AdvisoryCache(dir);
    cache.setAdvisories('npm', 'doctor-probe', '9.9.9', [{ id: 'GHSA-doctor-probe', package: 'doctor-probe' }]);
    const got = cache.getAdvisories('npm', 'doctor-probe', '9.9.9', 60_000);
    cache.close();
    const ok = Array.isArray(got) && got.some(v => v.id === 'GHSA-doctor-probe');
    return { ok, detail: ok ? 'write/read round-trip OK' : 'round-trip returned wrong data' };
  } catch (err) {
    return { ok: false, detail: err.message };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Best-effort reachability probe with a short timeout. Reports, doesn't throw.
 * Any host response (including 4xx/405) proves the host is up; only a network
 * error or timeout means it's down.
 */
async function probeReachable(url) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(url, { method: 'HEAD', signal: controller.signal });
    clearTimeout(timer);
    return { ok: true, detail: `reachable (HTTP ${res.status})` };
  } catch (err) {
    return { ok: false, detail: err.name === 'AbortError' ? 'timed out' : err.message };
  }
}

export async function runDoctor(flags, args, { fixturesDir, parserChecks } = {}) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';

  if (!isJSON) {
    out(`\n  ${C.bold}vexes doctor${C.reset} v${VERSION} ${C.dim}— self test${C.reset}\n`);
  }

  const checks = await runParserChecks(fixturesDir, parserChecks);
  const parserOk = checks.filter(c => c.name.startsWith('parser')).every(c => c.ok);

  const cacheCheck = await runCacheCheck();
  checks.push({ name: 'cache', ok: cacheCheck.ok, detail: cacheCheck.detail });

  const osv = await probeReachable(OSV_BATCH_URL.replace(/api\/.*$/, ''));
  const npm = await probeReachable(NPM_REGISTRY_URL);
  checks.push({ name: 'osv.dev', ok: osv.ok, detail: osv.detail, optional: true });
  checks.push({ name: 'registry.npmjs.org', ok: npm.ok, detail: npm.detail, optional: true });

  // Sandbox is experimental availability (reported, never a failure). A host
  // is only reported when it has filesystem write isolation — detection
  // refuses namespace-only primitives (unshare/firejail) outright.
  const sandboxHost = detectSandboxHost()?.host || null;
  checks.push({
    name: 'sandbox host',
    ok: sandboxHost !== null,
    detail: sandboxHost ? `${sandboxHost} available (network blocked, filesystem writes contained)` : 'none (no isolation primitive with filesystem write isolation)',
    optional: true,
  });

  const requiredOk = parserOk && cacheCheck.ok;
  const passed = checks.filter(c => c.ok).length + checks.filter(c => !c.ok && c.optional).length;

  if (isJSON) {
    out(JSON.stringify(buildEnvelope({
      command: 'doctor',
      target: { dir: targetDir, lockfiles: [], ecosystems: [] },
      complete: requiredOk,
      warnings: [],
      findings: [],
      summary: { total: checks.length, vulnerable: 0, unreachable: 0 },
      extra: { checks, requiredOk, network: { osv: osv.ok, npm: npm.ok }, sandbox: { host: sandboxHost } },
    }), null, 2));
  } else {
    for (const c of checks) {
      const mark = c.ok ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`;
      const optional = c.optional ? `${C.dim} (optional)${C.reset}` : '';
      out(`  ${mark} ${c.name}${optional} ${C.dim}— ${c.detail}${C.reset}`);
    }
    out(`\n  ${passed}/${checks.length} checks passed\n`);
    if (!requiredOk) {
      out(`  ${C.red}${C.bold}! DOCTOR FAILED${C.reset} ${C.red}— one or more required smoke checks failed.${C.reset}\n`);
    }
  }

  return requiredOk ? EXIT.OK : EXIT.ERROR;
}
