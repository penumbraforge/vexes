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
  ['npm (package-lock-v3.json)', npmParser.parseLockfile, 'package-lock-v3.json'],
  ['pypi (requirements.txt)', pypiParser.parseRequirements, 'requirements.txt'],
  ['cargo (Cargo.lock)', cargoParser.parseLockfile, 'Cargo.lock'],
  ['go (go.mod)', goParser.parseManifest, 'go.mod'],
  ['ruby (Gemfile)', rubyParser.parseManifest, 'Gemfile'],
  ['php (composer.json)', phpParser.parseManifest, 'composer.json'],
  ['dotnet (Example.csproj)', dotnetParser.parseManifest, 'Example.csproj'],
  ['java (pom.xml)', javaParser.parseManifest, 'pom.xml'],
  ['hex (mix.lock)', hexParser.parseLockfile, 'mix.lock'],
  ['pub (pubspec.lock)', pubParser.parseLockfile, 'pubspec.lock'],
];

// Fixture paths resolve relative to the PACKAGE ROOT (this module lives at
// src/commands/doctor.js), NOT the current working directory. The old
// cwd-relative path only worked when cwd happened to be the repo — a doctor
// run from an installed package or an unrelated project failed every parser
// check and reported the tool untrustworthy.
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// `fixturesDir` is injectable so tests can exercise the fail-loud path (all
// parser checks failing ⇒ EXIT.ERROR) without relying on the caller's cwd.
async function runParserChecks(fixturesDir = join(PACKAGE_ROOT, 'test', 'fixtures')) {
  const checks = [];
  for (const [name, parseFn, file] of PARSER_CHECKS) {
    const path = join(fixturesDir, file);
    try {
      const deps = parseFn(path);
      const count = Array.isArray(deps) ? deps.length : 'parsed';
      checks.push({ name: `parser ${name}`, ok: true, detail: `${count} dep(s)` });
    } catch (err) {
      checks.push({ name: `parser ${name}`, ok: false, detail: err.message });
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

export async function runDoctor(flags, args, { fixturesDir } = {}) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';

  if (!isJSON) {
    out(`\n  ${C.bold}vexes doctor${C.reset} v${VERSION} ${C.dim}— self test${C.reset}\n`);
  }

  const checks = await runParserChecks(fixturesDir);
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
      out(`  ${C.red}${C.bold}! DOCTOR FAILED${C.reset} ${C.red}— the scanner may not be trustworthy.${C.reset}\n`);
    }
  }

  return requiredOk ? EXIT.OK : EXIT.ERROR;
}
