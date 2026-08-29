import { resolve, join, dirname, relative, isAbsolute, sep } from 'node:path';
import {
  statSync, lstatSync, realpathSync, existsSync, readFileSync, writeFileSync,
  mkdtempSync, mkdirSync, rmSync, openSync, closeSync, fstatSync, fsyncSync,
  renameSync,
  constants as FS_CONSTANTS,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { loadConfig } from '../cli/config.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT } from '../core/constants.js';
import { parseLockfile as parseNpmLock } from '../parsers/npm.js';
import { diffSnapshots, toSnapshot } from '../analysis/diff.js';
import { queryBatch, isQueryComplete } from '../advisories/osv.js';
import { fetchNpmMetadata } from '../advisories/npm-registry.js';
import { analyzePackage } from '../analysis/signals.js';
import { AdvisoryCache, NoOpCache } from '../cache/advisory-cache.js';
import { buildEnvelope } from '../cli/schema.js';

/**
 * `vexes guard` — Pre-install protection. EXPERIMENTAL, npm only.
 *
 * The proposal is resolved in a disposable copy of the project's npm manifest
 * and lockfile, leaving the target files untouched during review. Every changed
 * lockfile occurrence is bound to its exact version, registry tarball URL, and
 * integrity value before analysis. If approved, that reviewed manifest/lock is
 * staged into the project and npm materializes it with lifecycle scripts
 * disabled; the resulting graph is re-read and checked against the approval.
 *
 * Known limits (why this stays "experimental"):
 *  - This is an assessment gate, not a package proxy or atomic transaction.
 *    `node_modules` writes cannot be rolled back completely if npm itself fails.
 *  - pnpm/yarn are refused: guard diffs package-lock.json, which they don't
 *    maintain — a "dry-run" there would analyze the wrong project state.
 */
/**
 * Lockfile-only dry-run flags. npm only — guard refuses other managers before
 * this ever matters. Never executes scripts.
 */
export function dryRunFlags(manager) {
  switch (manager) {
    case 'pnpm': return ['--lockfile-only', '--ignore-scripts'];
    case 'yarn': return ['--mode=update-lockfile', '--ignore-scripts', '--non-interactive'];
    default: return ['--package-lock-only', '--ignore-scripts'];
  }
}

const SAFE_NPM_FLAGS = new Set([
  '-D', '--save-dev', '-E', '--save-exact', '-O', '--save-optional',
  '--save', '--save-prod', '--legacy-peer-deps', '--strict-peer-deps',
]);

/** Resolve npm's CLI beside the running Node installation, never through PATH. */
export function resolveTrustedNpmCli(targetDir = process.cwd()) {
  const nodePath = realpathSync(process.execPath);
  const nodePrefix = dirname(dirname(nodePath));
  const candidates = [
    join(nodePrefix, 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(nodePath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  const cellarMarker = `${sep}Cellar${sep}`;
  const cellarIndex = nodePath.indexOf(cellarMarker);
  if (cellarIndex > 0) {
    candidates.push(join(nodePath.slice(0, cellarIndex), 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'));
  }

  const targetRoot = realpathSync(targetDir);
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    const real = realpathSync(candidate);
    const rel = relative(targetRoot, real);
    if (rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))) continue;
    const stat = statSync(real);
    if (stat.isFile()) return real;
  }
  throw new Error('trusted npm CLI was not found beside the running Node installation');
}

/** Minimal environment for npm resolution/materialization inside guard. */
export function guardNpmEnvironment(workDir) {
  const home = join(workDir, 'home');
  const cache = join(workDir, 'cache');
  const temp = join(workDir, 'tmp');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  mkdirSync(temp, { recursive: true, mode: 0o700 });
  const userconfig = join(workDir, 'user.npmrc');
  const globalconfig = join(workDir, 'global.npmrc');
  writeFileSync(userconfig, '', { mode: 0o600 });
  writeFileSync(globalconfig, '', { mode: 0o600 });

  return {
    PATH: dirname(realpathSync(process.execPath)),
    HOME: home,
    USERPROFILE: home,
    TMPDIR: temp,
    TMP: temp,
    TEMP: temp,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    npm_config_registry: 'https://registry.npmjs.org/',
    npm_config_userconfig: userconfig,
    npm_config_globalconfig: globalconfig,
    npm_config_cache: cache,
    npm_config_ignore_scripts: 'true',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    ...(process.platform === 'win32' && process.env.SystemRoot
      ? { SystemRoot: process.env.SystemRoot, ComSpec: process.env.ComSpec || '', PATHEXT: process.env.PATHEXT || '' }
      : {}),
  };
}

function npmBoundaryArgs(workDir) {
  return [
    '--registry=https://registry.npmjs.org/',
    `--userconfig=${join(workDir, 'user.npmrc')}`,
    `--globalconfig=${join(workDir, 'global.npmrc')}`,
    `--cache=${join(workDir, 'cache')}`,
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
  ];
}

/** Refuse symlinks, hardlinks, non-files, and paths escaping the project root. */
export function assertSafeProjectFile(filePath, targetDir, label = 'project file') {
  const root = realpathSync(targetDir);
  const lst = lstatSync(filePath);
  if (lst.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!lst.isFile()) throw new Error(`${label} must be a regular file`);
  if (lst.nlink !== 1) throw new Error(`${label} must not be hard-linked`);
  const real = realpathSync(filePath);
  const rel = relative(root, real);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new Error(`${label} resolves outside the target project`);
  }
  return { dev: lst.dev, ino: lst.ino };
}

export function writeOwnedProjectFile(filePath, value, identity, label, expectedRaw) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW || 0;
  const stageDir = mkdtempSync(join(dirname(filePath), '.vexes-guard-stage-'));
  const stagePath = join(stageDir, 'next');
  let stageFd;
  try {
    const originalMode = lstatSync(filePath).mode & 0o777;
    stageFd = openSync(
      stagePath,
      FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL,
      originalMode,
    );
    writeFileSync(stageFd, value);
    fsyncSync(stageFd);
    closeSync(stageFd);
    stageFd = undefined;

    // This is deliberately the last operation before the atomic rename. It
    // catches both path replacement and same-inode edits made after review,
    // while a fully-written sibling temp means an I/O failure cannot leave a
    // truncated live manifest or lockfile.
    const verifyFd = openSync(filePath, FS_CONSTANTS.O_RDONLY | noFollow);
    try {
      const current = fstatSync(verifyFd);
      if (!current.isFile() || current.nlink !== 1 ||
          current.dev !== identity.dev || current.ino !== identity.ino) {
        throw new Error(`${label} identity changed before commit`);
      }
      if (expectedRaw !== undefined && readFileSync(verifyFd, 'utf8') !== expectedRaw) {
        throw new Error(`${label} bytes changed before commit`);
      }
    } finally {
      closeSync(verifyFd);
    }
    renameSync(stagePath, filePath);
  } finally {
    if (stageFd !== undefined) closeSync(stageFd);
    rmSync(stageDir, { recursive: true, force: true });
  }
}

function assertNoProjectNpmConfig(targetDir) {
  const npmrcPath = join(targetDir, '.npmrc');
  let lst;
  try { lst = lstatSync(npmrcPath); }
  catch (err) {
    if (err.code === 'ENOENT') return;
    throw err;
  }
  if (lst.isSymbolicLink() || !lst.isFile() || lst.nlink !== 1) {
    throw new Error('project .npmrc is outside guard\'s public-registry boundary');
  }
  assertSafeProjectFile(npmrcPath, targetDir, '.npmrc');
  const active = readFileSync(npmrcPath, 'utf8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith(';'));
  if (active.length > 0) {
    throw new Error('project .npmrc settings are not supported by guard\'s public-registry boundary');
  }
}

function splitRegistrySpec(spec) {
  const text = String(spec || '');
  if (text.startsWith('@')) {
    const slash = text.indexOf('/');
    const selectorAt = text.lastIndexOf('@');
    if (slash <= 1) return null;
    return selectorAt > slash
      ? { name: text.slice(0, selectorAt), selector: text.slice(selectorAt + 1) }
      : { name: text, selector: '' };
  }
  const selectorAt = text.indexOf('@');
  return selectorAt > 0
    ? { name: text.slice(0, selectorAt), selector: text.slice(selectorAt + 1) }
    : { name: text, selector: '' };
}

/**
 * Guard deliberately supports a narrow npm grammar. Flags that can redirect
 * the install, select another workspace/registry/config, execute scripts, or
 * introduce non-registry sources are refused instead of being half-guarded.
 */
export function validateGuardCommand(args = []) {
  if (args[0] !== 'npm') return { ok: false, reason: 'guard currently supports npm only' };
  if (!['install', 'i', 'add'].includes(args[1])) {
    return { ok: false, reason: 'guard only supports "npm install <registry-package>"' };
  }

  const specs = [];
  for (const token of args.slice(2)) {
    if (token.startsWith('-')) {
      if (SAFE_NPM_FLAGS.has(token)) continue;
      if (/^--(?:include|omit)=(?:prod|dev|optional|peer)$/.test(token)) continue;
      return { ok: false, reason: `npm option "${token}" is outside guard's supported install boundary` };
    }

    const parsed = splitRegistrySpec(token);
    if (!parsed) return { ok: false, reason: `unsupported package specifier "${token}"` };
    const { name, selector } = parsed;
    const validName = name.startsWith('@')
      ? /^@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*$/i.test(name)
      : /^[a-z0-9][a-z0-9._~-]*$/i.test(name);
    // Registry selectors may be tags or semver expressions, but never paths,
    // URLs, aliases, GitHub shorthand, or other npm-package-arg source forms.
    // Keep this grammar intentionally narrower than npm's rather than crossing
    // a local-filesystem/network boundary during the disposable resolution.
    const validSelector = selector === '' || /^[a-z0-9*^~<>=|._+-]+$/i.test(selector);
    if (!validName || !validSelector || /^(?:file|link|git|git\+|https?|github|npm):/i.test(selector)) {
      return { ok: false, reason: `only public npm registry package specs are supported (got "${token}")` };
    }
    specs.push({ raw: token, name: name.toLowerCase(), selector });
  }

  if (specs.length === 0) {
    return { ok: false, reason: 'guard requires at least one explicit registry package; bare npm install is not supported' };
  }
  return { ok: true, specs, requestedNames: specs.map(s => s.name) };
}

/**
 * Extract the package names being installed from `npm install <pkg>`-style
 * args, ignoring flags, local path/dir targets, and version specs.
 * @returns {string[]} lowercased requested names (may be empty)
 */
export function requestedNamesFromArgs(args = []) {
  const verdict = validateGuardCommand(args);
  return verdict.ok ? verdict.requestedNames : [];
}

/** Parse a raw package-lock.json into its `packages` map ({} on bad JSON). */
function parseLockGraph(raw) {
  try {
    const data = JSON.parse(String(raw || ''));
    if (data && typeof data === 'object' && data.packages) return data.packages;
    return {};
  } catch { return {}; }
}

/** Flood the dependency graph from `roots` over every `node_modules/*` entry. */
function reachableNames(packages, roots) {
  const seen = new Set();
  for (const r of roots) seen.add(String(r).toLowerCase());
  let frontier = [...seen];
  while (frontier.length) {
    const next = [];
    for (const name of frontier) {
      for (const [key, entry] of Object.entries(packages)) {
        if (!key || key === '') continue;
        const entryName = key.split('node_modules/').pop();
        const visitKey = `__seen:${name}:${key}`;
        if (!entryName || entryName.toLowerCase() !== name || seen.has(visitKey)) continue;
        seen.add(visitKey); // walk this occurrence's edges once
        for (const e of ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies']) {
          if (!entry || !entry[e]) continue;
          for (const depName of Object.keys(entry[e])) {
            const n = depName.toLowerCase();
            if (!seen.has(n)) { seen.add(n); next.push(n); }
          }
        }
      }
    }
    frontier = next;
  }
  return seen;
}

/**
 * The lockfile tamper guard. After a dry-run install, verify the diff only
 * touches packages reachable from the requested install:
 *  - added/changed entries must be reachable from a requested name in the
 *    AFTER graph (something unseen appeared/moved that nobody asked for);
 *  - removed entries must be reachable in the BEFORE graph (npm dedupes and
 *    evicts while installing — an unrelated silent removal is the tamper sign).
 * Returns null when clean, or a human reason string. Empty requestedNames
 * (e.g. bare `npm install`) skips attribution — nothing to compare against.
 * The caller restores the original lockfile and fails on any non-null.
 */
export function verifyLockfileDiff({ beforeRaw, afterRaw, diff, requestedNames = [] }) {
  if (requestedNames.length === 0) return null;
  const before = reachableNames(parseLockGraph(beforeRaw), requestedNames);
  const after = reachableNames(parseLockGraph(afterRaw), requestedNames);
  for (const { name } of diff.added || []) {
    if (!after.has(String(name).toLowerCase())) return `added package "${name}" is not reachable from the requested install`;
  }
  for (const { name } of diff.changed || []) {
    if (!after.has(String(name).toLowerCase())) return `changed package "${name}" is not reachable from the requested install`;
  }
  for (const { name } of diff.removed || []) {
    if (!before.has(String(name).toLowerCase())) return `removed package "${name}" is not reachable from the requested install`;
  }
  return null;
}

/**
 * Bind the approval to what actually got installed. The analysis gate and the
 * real install are two separate resolutions of the same request — the registry
 * can answer them differently (dist-tag moved, cache expired, mirror split).
 * After the real install, re-read the lockfile and require that every analyzed
 * package is present at EXACTLY the analyzed version. Anything else means the
 * installed artifact is not the approved artifact → fail loud.
 *
 * PURE — takes the post-install lockfile text, no I/O. Returns { ok: true } or
 * { ok: false, reason } naming every package that is missing or drifted.
 */
export function verifyInstalledVersions({ afterRaw, expected, approvedRaw = null }) {
  const installed = parseLockGraph(afterRaw);
  const problems = [];
  const approvedGraph = approvedRaw !== null ? parseLockGraph(approvedRaw) : null;
  const approvedOccurrences = approvedGraph !== null
    ? new Set(Object.keys(approvedGraph).filter(Boolean))
    : new Set((expected || []).map(component => component.occurrence).filter(Boolean));

  // Approval binds the whole proposed occurrence set, not merely the entries
  // that happened to require analysis. A second npm resolution must not be
  // able to add an unreviewed nested package while keeping every expected
  // version present.
  for (const occurrence of Object.keys(installed).filter(Boolean)) {
    if (!approvedOccurrences.has(occurrence)) {
      problems.push(`unexpected lockfile occurrence ${occurrence} was installed without approval`);
    }
  }

  // Every occurrence in the approved graph must remain present with the same
  // artifact identity, including packages that were unchanged and therefore
  // did not need a fresh signal analysis. Otherwise the second npm pass could
  // silently remove or replace an already-approved transitive artifact.
  if (approvedGraph !== null) {
    for (const occurrence of approvedOccurrences) {
      const approved = approvedGraph[occurrence];
      const actual = installed[occurrence];
      if (!actual) {
        problems.push(`approved lockfile occurrence ${occurrence} disappeared during install`);
        continue;
      }
      for (const field of ['name', 'version', 'resolved', 'integrity', 'link']) {
        const approvedValue = approved?.[field] ?? null;
        const actualValue = actual?.[field] ?? null;
        if (approvedValue !== actualValue) {
          problems.push(`${occurrence} ${field} differs from the approved graph`);
        }
      }
    }
  }

  for (const component of expected || []) {
    const { name, version, occurrence, integrity, resolved: approvedResolved } = component;
    if (!occurrence) {
      problems.push(`${name}@${version} approval lacks a lockfile occurrence and cannot be bound safely`);
      continue;
    }
    const entry = installed[occurrence];
    if (!entry) { problems.push(`${name}@${version} is missing at ${occurrence}`); continue; }
    if (entry.version !== version) {
      problems.push(`${occurrence} approved as ${name}@${version} but installed as ${entry.version || 'unknown'}`);
    }
    if (integrity && entry.integrity !== integrity) {
      problems.push(`${occurrence} integrity differs from the approved artifact`);
    }
    if (approvedResolved && entry.resolved !== approvedResolved) {
      problems.push(`${occurrence} resolved URL differs from the approved artifact`);
    }
  }

  if (problems.length === 0) return { ok: true };
  return { ok: false, reason: problems.join('; ') };
}

/** Validate that every changed component is a bindable public-registry artifact. */
export function validateArtifactSet(components = []) {
  const reasons = [];
  for (const c of components) {
    const label = `${c.name}@${c.version}`;
    if (!c.occurrence) reasons.push(`${label} has no lockfile occurrence`);
    if (!c.integrity) reasons.push(`${label} has no registry integrity value`);
    if (!c.resolved) {
      reasons.push(`${label} has no resolved artifact URL`);
      continue;
    }
    try {
      const u = new URL(c.resolved);
      if (u.protocol !== 'https:' || u.hostname !== 'registry.npmjs.org') {
        reasons.push(`${label} resolves outside the supported public npm registry`);
      }
    } catch {
      reasons.push(`${label} has an invalid resolved artifact URL`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Emit guard's machine output through the shared JSON envelope (cli/schema.js)
 * so agents/CI get the same versioned shape they get from every other vexes
 * command. Command-specific fields (installCommand, blocked, incomplete,
 * diff, results) ride in `extra` — `results` stays a top-level key, so older
 * consumers of the ad-hoc guard object keep working.
 */
export function buildGuardEnvelope({ installCommand, diff, blocked, incomplete, warnings, results }) {
  const added = (diff?.added || []).length;
  const changed = (diff?.changed || []).length;
  const removed = (diff?.removed || []).length;
  return buildEnvelope({
    command: 'guard',
    complete: !incomplete,
    warnings,
    summary: { added, changed, removed, blocked, incomplete },
    findings: [],
    extra: {
      installCommand,
      packageManager: 'npm',
      experimental: true,
      assessmentOnly: true,
      resolutionIsolation: 'disposable-project-copy',
      approvedInstallMode: 'ignore-scripts',
      blocked,
      incomplete,
      diff: { added, changed, removed },
      results: results || [],
    },
  });
}

function emitGuardJsonError(reason, { installCommand = '', diff = null, results = [] } = {}) {
  out(JSON.stringify(buildGuardEnvelope({
    installCommand,
    diff: diff || { added: [], changed: [], removed: [] },
    blocked: true,
    incomplete: true,
    warnings: [String(reason)],
    results,
  }), null, 2));
  return EXIT.ERROR;
}

/** Machine-mode guard is non-interactive: HIGH is blocked, never approved. */
export function guardJsonDecision(decision) {
  const securityBlocked = decision.critical.length > 0 || decision.high.length > 0 ||
    decision.hasKnownVulns;
  const blocked = securityBlocked || decision.analysisIncomplete;
  return {
    blocked,
    exitCode: !blocked ? EXIT.OK : decision.analysisIncomplete ? EXIT.ERROR : EXIT.VULNS_FOUND,
  };
}

/**
 * Text-mode policy keeps the documented override narrow: only HIGH evidence
 * can be force-approved. CRITICAL, known OSV results, and incomplete evidence
 * remain non-overridable inside guard.
 */
export function guardTextDecision(decision, { forceInstall = false, interactive = false } = {}) {
  if (decision.analysisIncomplete) {
    return { action: 'block', exitCode: EXIT.ERROR };
  }
  if (decision.critical.length > 0 || decision.hasKnownVulns) {
    return { action: 'block', exitCode: EXIT.VULNS_FOUND };
  }
  if (decision.high.length > 0) {
    if (forceInstall) return { action: 'install', exitCode: null };
    return interactive
      ? { action: 'prompt', exitCode: null }
      : { action: 'block', exitCode: EXIT.VULNS_FOUND };
  }
  return { action: 'install', exitCode: null };
}

export async function runGuard(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const jsonRequested = flags.json === true || String(flags.format || '').toLowerCase() === 'json';
  let config;
  try {
    config = loadConfig(targetDir, flags);
  } catch (err) {
    if (jsonRequested) return emitGuardJsonError(`configuration error: ${err.message}`);
    log.error(err.message);
    return EXIT.ERROR;
  }
  const isJSON = config.output?.format === 'json';
  // Guard is an install authorization boundary. Repository policy may tune
  // ordinary reports, but it cannot suppress the evidence used to approve an
  // install, so all built-in signal detectors remain enabled here.
  config = { ...config, analyze: { ...(config.analyze || {}), signals: {} }, ignore: [] };
  const forceInstall = !!flags.force;

  // Subcommands
  if (flags.setup) {
    if (isJSON) return emitGuardJsonError('automatic guard shell setup is disabled');
    return runSetup(flags);
  }
  if (flags.uninstall) {
    if (isJSON) return emitGuardJsonError('guard shell uninstall is not available in JSON mode');
    return runUninstall(flags);
  }

  // Validate directory
  try {
    if (!statSync(targetDir).isDirectory()) {
      log.error('not a directory');
      if (isJSON) return emitGuardJsonError(`not a directory: ${targetDir}`);
      return EXIT.ERROR;
    }
  } catch {
    log.error(`path does not exist: ${targetDir}`);
    if (isJSON) return emitGuardJsonError(`path does not exist: ${targetDir}`);
    return EXIT.ERROR;
  }

  // Parse and validate the install command before touching project state.
  const installArgs = args.length > 0 ? [...args] : null;
  if (!installArgs) {
    if (isJSON) return emitGuardJsonError('guard requires an explicit npm install command');
    if (!isJSON) {
      out(`\n  ${C.bold}Usage:${C.reset} vexes guard -- npm install <package>`);
      out(`  ${C.dim}Guard currently accepts explicit public-registry packages only.${C.reset}\n`);
    }
    return EXIT.ERROR;
  }
  const commandVerdict = validateGuardCommand(installArgs);
  if (!commandVerdict.ok) {
    log.error(commandVerdict.reason);
    if (isJSON) return emitGuardJsonError(commandVerdict.reason, { installCommand: installArgs.join(' ') });
    return EXIT.ERROR;
  }
  const manager = 'npm';

  const lockfilePath = join(targetDir, 'package-lock.json');
  const packagePath = join(targetDir, 'package.json');

  if (!existsSync(lockfilePath) || !existsSync(packagePath)) {
    if (isJSON) {
      return emitGuardJsonError('guard requires both package.json and package-lock.json', {
        installCommand: installArgs.join(' '),
      });
    }
    if (!isJSON) out(`  ${C.yellow}Guard requires both package.json and package-lock.json${C.reset}`);
    return EXIT.ERROR;
  }

  if (!isJSON) {
    out(`\n  ${C.bold}vexes guard${C.reset} v${VERSION} ${C.dim}— pre-install protection (experimental — npm only)${C.reset}\n`);
  }

  // 1. Snapshot manifest + lockfile with every npm occurrence preserved.
  const spinner = isJSON ? null : createSpinner('Snapshotting current dependencies...');
  let beforeDeps;
  let packageBackup;
  let lockfileBackup;
  try {
    assertNoProjectNpmConfig(targetDir);
    assertSafeProjectFile(packagePath, targetDir, 'package.json');
    assertSafeProjectFile(lockfilePath, targetDir, 'package-lock.json');
    packageBackup = readFileSync(packagePath, 'utf8');
    lockfileBackup = readFileSync(lockfilePath, 'utf8');
    const manifest = JSON.parse(packageBackup);
    if (manifest.workspaces) {
      throw new Error('npm workspaces are not yet supported by guard; use inspect/scan and run npm directly');
    }
    beforeDeps = parseNpmLock(lockfilePath, { preserveOccurrences: true });
    if (beforeDeps.unresolvedEntries > 0 || beforeDeps.some(dep => dep.sourceType !== 'registry')) {
      throw new Error('guard requires an existing lockfile containing only public npm registry artifacts');
    }
  } catch (err) {
    spinner?.stop(`Failed to parse lockfile: ${err.message}`);
    log.error(err.message);
    if (isJSON) return emitGuardJsonError(`failed to parse project snapshot: ${err.message}`, {
      installCommand: installArgs.join(' '),
    });
    return EXIT.ERROR;
  }
  const beforeSnapshot = toSnapshot(beforeDeps);
  spinner?.stop(`Snapshot: ${beforeDeps.length} package occurrences`);

  // 2. Resolve inside a disposable project. npm's package-lock-only mode can
  // edit package.json, so running it in the target is not a dry run.
  const installDisplay = installArgs.join(' ');
  const dryFlags = dryRunFlags(manager);
  const dryRunSpinner = isJSON ? null : createSpinner(`Resolving transactionally: ${installDisplay}`);
  let resolutionDir;
  let proposedLockfileRaw;
  let proposedPackageRaw;
  let afterDeps;

  try {
    resolutionDir = mkdtempSync(join(tmpdir(), 'vexes-guard-resolve-'));
    writeFileSync(join(resolutionDir, 'package.json'), packageBackup, { mode: 0o600 });
    writeFileSync(join(resolutionDir, 'package-lock.json'), lockfileBackup, { mode: 0o600 });
    const npmCli = resolveTrustedNpmCli(targetDir);
    const npmEnv = guardNpmEnvironment(resolutionDir);
    execFileSync(process.execPath, [npmCli, ...installArgs.slice(1), ...dryFlags, ...npmBoundaryArgs(resolutionDir)], {
      cwd: resolutionDir,
      stdio: 'pipe',
      timeout: 120_000,
      env: npmEnv,
    });
    proposedLockfileRaw = readFileSync(join(resolutionDir, 'package-lock.json'), 'utf8');
    proposedPackageRaw = readFileSync(join(resolutionDir, 'package.json'), 'utf8');
    afterDeps = parseNpmLock(join(resolutionDir, 'package-lock.json'), { preserveOccurrences: true });
  } catch (err) {
    dryRunSpinner?.stop('Disposable resolution failed');
    log.error(`guard resolution failed: ${err.message}`);
    if (isJSON) return emitGuardJsonError(`guard resolution failed: ${err.message}`, {
      installCommand: installDisplay,
    });
    return EXIT.ERROR;
  } finally {
    if (resolutionDir) {
      try { rmSync(resolutionDir, { recursive: true, force: true }); } catch { /* disposable workspace */ }
    }
  }

  // 3. Diff the disposable result. The target has not been modified.
  const afterSnapshot = toSnapshot(afterDeps);
  const diff = diffSnapshots(beforeSnapshot, afterSnapshot);
  dryRunSpinner?.stop(`Diff: ${diff.summary}`);

  // --- Lockfile tamper guard ------------------------------------------------
  // The dry-run result is only as trustworthy as the registry + install hooks
  // that produced it. Verify the diff touches ONLY packages reachable from the
  // requested install; anything else (silent removal, attribute-less add) is
  // tamper → restore the original lockfile and fail loud.
  const tamperReason = verifyLockfileDiff({
    beforeRaw: lockfileBackup,
    afterRaw: proposedLockfileRaw,
    diff,
    requestedNames: commandVerdict.requestedNames,
  });
  if (tamperReason) {
    dryRunSpinner?.stop('Lockfile tamper check failed');
    log.error(`lockfile tamper check failed: ${tamperReason}`);
    if (isJSON) return emitGuardJsonError(`lockfile tamper check failed: ${tamperReason}`, {
      installCommand: installDisplay,
      diff,
    });
    if (!isJSON) out(`  ${C.red}! ${C.bold}${sanitize(tamperReason)}${C.reset} ${C.dim}— target project was not modified.${C.reset}\n`);
    return EXIT.ERROR;
  }

  // 4. Analyze new and changed packages
  const packagesToAnalyze = [
    ...diff.added,
    ...diff.changed.map(c => ({ ...c, version: c.toVersion })),
  ];

  const artifactVerdict = validateArtifactSet(packagesToAnalyze);
  if (!artifactVerdict.ok) {
    const reason = `artifact identity incomplete: ${artifactVerdict.reasons.join('; ')}`;
    log.error(reason);
    if (isJSON) return emitGuardJsonError(reason, { installCommand: installDisplay, diff });
    if (!isJSON) out(`  ${C.yellow}! ${sanitize(reason)}${C.reset}\n  ${C.dim}Target project was not modified.${C.reset}\n`);
    return EXIT.ERROR;
  }

  if (!diff.hasChanges) {
    if (isJSON) {
      out(JSON.stringify(buildGuardEnvelope({
        installCommand: installDisplay,
        diff,
        blocked: false,
        incomplete: false,
        warnings: [],
        results: [],
      }), null, 2));
      return EXIT.OK;
    }
    out(`\n  ${C.green}\u2713 No new artifact occurrences require analysis${C.reset}\n`);
    return executeApprovedInstall(manager, targetDir, {
      display: installDisplay,
      expected: afterSnapshot, lockfilePath, lockfileBackup, packagePath, packageBackup,
      proposedLockfileRaw, proposedPackageRaw,
    });
  }

  if (!isJSON) {
    out(`\n  ${C.dim}Analyzing ${packagesToAnalyze.length} new/changed packages...${C.reset}`);
  }

  let cache;
  try { cache = new AdvisoryCache(config.cache?.dir); }
  catch { cache = new NoOpCache(); }

  try {
    // OSV scan
    const analyzeSpinner = isJSON ? null : createSpinner('Checking for known vulnerabilities...');
    const osvData = await queryBatch(packagesToAnalyze);
    analyzeSpinner?.stop('Vulnerability check complete');

    // Deep analysis on each new/changed package
    const signalSpinner = isJSON ? null : createSpinner('Running behavioral analysis...');
    const results = [];

    for (const dep of packagesToAnalyze) {
      try {
        // Anchor metadata to the EXACT proposed version from the diff — never
        // dist-tags.latest. Analyzing latest while installing dep.version
        // would attribute someone else's scripts/publisher/timing to the
        // artifact the user is about to get.
        const metadata = await fetchNpmMetadata(dep.name, dep.version);
        if (!metadata || metadata.requestedVersionFound === false || metadata.anchoredToInstalled === false) {
          throw new Error(`registry metadata did not contain the proposed version ${dep.version}`);
        }
        const registryIntegrity = metadata.integrity || metadata.artifact?.integrity || null;
        const registryTarball = metadata.tarball || metadata.artifact?.tarball || null;
        if (!registryIntegrity) {
          throw new Error('registry metadata has no integrity value for the proposed artifact');
        }
        if (registryIntegrity !== dep.integrity) {
          throw new Error('registry integrity does not match the proposed lockfile artifact');
        }
        if (!registryTarball) {
          throw new Error('registry metadata has no tarball URL for the proposed artifact');
        }
        if (registryTarball !== dep.resolved) {
          throw new Error('registry tarball URL does not match the proposed lockfile artifact');
        }
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        const osvResult = osvData.results.get(key) || null;
        const analysis = await analyzePackage(metadata, osvResult, { ecosystem: dep.ecosystem, config });

        results.push({
          name: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          occurrence: dep.occurrence,
          resolved: dep.resolved,
          integrity: dep.integrity,
          artifact: {
            occurrence: dep.occurrence,
            resolved: dep.resolved,
            integrity: dep.integrity,
            registryMetadataMatched: true,
          },
          isNew: diff.added.some(a => a.occurrence === dep.occurrence),
          signals: analysis.signals,
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
          warnings: Array.isArray(analysis.warnings) ? analysis.warnings : [],
        });
      } catch (err) {
        log.debug(`analysis failed for ${dep.name}: ${err.message}`);
        results.push({
          name: dep.name, version: dep.version, ecosystem: dep.ecosystem,
          occurrence: dep.occurrence, resolved: dep.resolved, integrity: dep.integrity,
          isNew: true, signals: [], riskScore: 0, riskLevel: 'UNKNOWN',
          analysisError: err.message,
          warnings: [err.message],
        });
      }
    }

    signalSpinner?.stop(`${results.length} packages analyzed`);

    // 5. Decision: block, warn, or allow
    const decision = evaluateGuardResults(results, osvData, packagesToAnalyze.length);
    const {
      critical, high, hasKnownVulns, unknown,
      analysisIncomplete, incompleteReasons,
    } = decision;

    if (isJSON) {
      const machineDecision = guardJsonDecision(decision);
      const payload = buildGuardEnvelope({
        installCommand: installDisplay,
        diff,
        blocked: machineDecision.blocked,
        incomplete: analysisIncomplete,
        warnings: [...osvData.failures, ...incompleteReasons],
        results,
      });
      out(JSON.stringify(payload, null, 2));
      return machineDecision.exitCode;
    }

    // Terminal output
    const textDecision = guardTextDecision(decision, {
      forceInstall,
      interactive: !!process.stdin.isTTY,
    });
    if (critical.length === 0 && high.length === 0 &&
        !hasKnownVulns && unknown.length === 0 && !analysisIncomplete) {
      // All clear
      out(`\n  ${C.green}\u2713 No blocking evidence in ${packagesToAnalyze.length} new/changed package occurrences${C.reset}`);
      out(`  ${C.dim}Installing the approved lockfile with lifecycle scripts disabled...${C.reset}\n`);
      return executeApprovedInstall(manager, targetDir, {
        display: installDisplay, expected: afterSnapshot,
        lockfilePath, lockfileBackup, packagePath, packageBackup,
        proposedLockfileRaw, proposedPackageRaw,
      });
    }

    // Show findings
    out(header('Guard Report'));

    if (diff.added.length > 0) {
      out(`  ${C.bold}New packages:${C.reset} ${diff.added.map(d => sanitize(d.name)).join(', ')}`);
    }
    if (diff.changed.length > 0) {
      out(`  ${C.bold}Changed:${C.reset} ${diff.changed.map(c => `${sanitize(c.name)} ${c.fromVersion} \u2192 ${c.toVersion}`).join(', ')}`);
    }
    out('');

    const reportResults = [...new Set([...critical, ...high])];
    for (const r of reportResults) {
      const rawSeverity = highestRawSignalSeverity(r.signals);
      const displayedSeverity = rawSeverity || r.riskLevel;
      const color = displayedSeverity === 'CRITICAL' ? C.red : C.yellow;
      out(`  ${color}\u25cf ${displayedSeverity}${C.reset} ${C.bold}${sanitize(r.name)}${C.reset} ${C.dim}${sanitize(r.version)}${C.reset}`);
      for (const s of r.signals) {
        out(`    ${C.dim}${s.signal}: ${sanitize(s.description)}${C.reset}`);
      }
      out('');
    }

    if (unknown.length > 0) {
      out(`  ${C.yellow}! ${unknown.length} package(s) could not be fully analyzed${C.reset}\n`);
    }
    if (!decision.osvComplete) {
      for (const reason of incompleteReasons.filter(r => r.startsWith('OSV'))) {
        out(`  ${C.yellow}! ${sanitize(reason)}${C.reset}`);
      }
      out('');
    }

    if (critical.length > 0 || hasKnownVulns) {
      const blockerCount = critical.length;
      const reasons = [];
      if (blockerCount > 0) reasons.push(`${blockerCount} package(s) with HIGH/CRITICAL evidence`);
      if (hasKnownVulns) reasons.push('known OSV vulnerabilities');
      for (const reason of incompleteReasons.filter(r => r.startsWith('Analysis warning'))) {
        out(`  ${C.yellow}! ${sanitize(reason)}${C.reset}`);
      }
      out(`  ${C.red}${C.bold}\u2717 BLOCKED${C.reset}${C.red} — ${reasons.join(' and ')} detected.${C.reset}`);
      out(`  ${C.dim}The install was not executed. Review the findings above.${C.reset}`);
      out(`  ${C.dim}To override: run the install command directly (at your own risk).${C.reset}\n`);
      return EXIT.VULNS_FOUND;
    }

    if (analysisIncomplete) {
      out(`  ${C.yellow}${C.bold}! INCOMPLETE${C.reset}${C.yellow} — vexes could not fully verify this install.${C.reset}`);
      for (const reason of incompleteReasons) {
        out(`    ${C.dim}${sanitize(reason)}${C.reset}`);
      }

      out(`\n  ${C.dim}Incomplete analysis cannot be overridden inside guard. Run npm directly to bypass the boundary explicitly.${C.reset}\n`);
      return EXIT.ERROR;
    }

    if (high.length > 0) {
      out(`  ${C.yellow}${C.bold}! WARNING${C.reset}${C.yellow} — ${high.length} high-risk package(s) detected.${C.reset}`);

      if (textDecision.action === 'install') {
        out(`  ${C.yellow}--force used — proceeding despite warnings.${C.reset}\n`);
        return executeApprovedInstall(manager, targetDir, {
          display: installDisplay, expected: afterSnapshot,
          lockfilePath, lockfileBackup, packagePath, packageBackup,
          proposedLockfileRaw, proposedPackageRaw,
        });
      }

      // Check if we have a TTY for interactive prompt
      if (textDecision.action === 'prompt') {
        out(`  ${C.dim}Proceed with install? [y/N]${C.reset}`);
        const answer = await prompt();
        if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
          return executeApprovedInstall(manager, targetDir, {
            display: installDisplay, expected: afterSnapshot,
            lockfilePath, lockfileBackup, packagePath, packageBackup,
            proposedLockfileRaw, proposedPackageRaw,
          });
        }
        out(`  ${C.dim}Install cancelled.${C.reset}\n`);
        return EXIT.VULNS_FOUND;
      } else {
        // Non-TTY (CI): block by default
        out(`  ${C.dim}Non-interactive mode — blocking install. Use --force to override.${C.reset}\n`);
        return EXIT.VULNS_FOUND;
      }
    }

    // Unknown is incomplete, never an implicit allow.
    out(`  ${C.yellow}! Some package occurrences could not be fully analyzed; install blocked.${C.reset}\n`);
    return EXIT.ERROR;

  } catch (err) {
    log.error(`guard analysis failed: ${err.message}`);
    if (isJSON) {
      return emitGuardJsonError(`guard analysis failed: ${err.message}`, {
        installCommand: installDisplay,
        diff,
      });
    }
    return EXIT.ERROR;
  } finally {
    cache.close();
  }
}

export function evaluateGuardResults(results, osvData, expectedChecks) {
  // Composite scoring is useful for prioritization, but it must never dilute
  // a single HIGH/CRITICAL piece of evidence into a lower policy bucket.
  const rawCritical = results.filter(r => highestRawSignalSeverity(r.signals) === 'CRITICAL');
  const rawHigh = results.filter(r => highestRawSignalSeverity(r.signals) === 'HIGH');
  const critical = [...new Set([
    ...results.filter(r => r.riskLevel === 'CRITICAL'),
    ...rawCritical,
  ])];
  const criticalSet = new Set(critical);
  const high = [...new Set([
    ...results.filter(r => r.riskLevel === 'HIGH'),
    ...rawHigh,
  ])].filter(r => !criticalSet.has(r));
  // The install boundary must not depend on presentation policy. Explicitly
  // disabling advisory signals may suppress emitted findings, but it cannot
  // authorize a coordinate for which OSV returned one or more records.
  const hasKnownVulns = hasNonemptyOsvResults(osvData?.results);
  const unknown = results.filter(r => r.riskLevel === 'UNKNOWN');
  const osvComplete = isQueryComplete(osvData, expectedChecks);
  const incompleteReasons = [];

  if (!osvComplete) {
    const missed = osvData?.failedCount ?? 0;
    const detail = missed > 0
      ? `${missed} package(s) were not checked`
      : 'one or more lookup errors occurred';
    incompleteReasons.push(`OSV vulnerability lookup incomplete — ${detail}`);
  }
  if (unknown.length > 0) {
    incompleteReasons.push(`${unknown.length} package(s) could not be fully analyzed`);
  }
  for (const result of results) {
    for (const warning of Array.isArray(result.warnings) ? result.warnings : []) {
      incompleteReasons.push(
        `Analysis warning for ${result.occurrence || `${result.name}@${result.version}`}: ${warning}`
      );
    }
  }

  return {
    critical,
    high,
    rawCritical,
    rawHigh,
    hasKnownVulns,
    unknown,
    osvComplete,
    analysisIncomplete: incompleteReasons.length > 0,
    incompleteReasons,
  };
}

function highestRawSignalSeverity(signals) {
  let highest = null;
  for (const signal of Array.isArray(signals) ? signals : []) {
    const severity = String(signal?.severity || '').toUpperCase();
    if (severity === 'CRITICAL') return 'CRITICAL';
    if (severity === 'HIGH') highest = 'HIGH';
  }
  return highest;
}

function hasNonemptyOsvResults(results) {
  if (results instanceof Map) {
    return [...results.values()].some(value => Array.isArray(value) ? value.length > 0 : Boolean(value));
  }
  if (Array.isArray(results)) {
    return results.some(value => Array.isArray(value) ? value.length > 0 : Boolean(value));
  }
  if (results && typeof results === 'object') {
    return Object.values(results).some(value => Array.isArray(value) ? value.length > 0 : Boolean(value));
  }
  return false;
}

/**
 * Compare the project files to a byte-for-byte snapshot. JSON semantic
 * equality is intentionally insufficient: any edit means guard no longer
 * owns the transaction boundary it reviewed.
 */
export function verifyProjectSnapshot({
  packagePath, lockfilePath, expectedPackageRaw, expectedLockfileRaw,
}) {
  const changed = [];
  try {
    assertSafeProjectFile(packagePath, dirname(packagePath), 'package.json');
    if (readFileSync(packagePath, 'utf8') !== expectedPackageRaw) changed.push('package.json');
  } catch (err) {
    changed.push(`package.json (${err.message})`);
  }
  try {
    assertSafeProjectFile(lockfilePath, dirname(lockfilePath), 'package-lock.json');
    if (readFileSync(lockfilePath, 'utf8') !== expectedLockfileRaw) changed.push('package-lock.json');
  } catch (err) {
    changed.push(`package-lock.json (${err.message})`);
  }
  return changed.length === 0
    ? { ok: true }
    : { ok: false, reason: `${changed.join(' and ')} changed after guard took its snapshot` };
}

/**
 * Restore each original independently while that file still contains either
 * the exact bytes guard staged or its untouched original bytes. This matters
 * because staging two files is not atomic: if the second write fails, the
 * already-staged manifest must be recoverable without touching a divergent
 * lockfile. Newer npm or user edits are always preserved.
 */
export function restoreProjectSnapshotIfUnchanged({
  packagePath, lockfilePath,
  expectedPackageRaw, expectedLockfileRaw,
  originalPackageRaw, originalLockfileRaw,
}) {
  const restoreFile = (label, path, expectedRaw, originalRaw) => {
    let currentRaw;
    try {
      currentRaw = readFileSync(path, 'utf8');
    } catch (err) {
      return { status: 'error', restored: false, reason: `${label} could not be read: ${err.message}` };
    }

    if (currentRaw === originalRaw) {
      return { status: 'already-original', restored: false };
    }
    if (currentRaw !== expectedRaw) {
      return {
        status: 'preserved',
        restored: false,
        reason: `${label} changed after guard staged it`,
      };
    }

    try {
      const identity = assertSafeProjectFile(path, dirname(path), label);
      writeOwnedProjectFile(path, originalRaw, identity, label, expectedRaw);
      return { status: 'restored', restored: true };
    } catch (err) {
      return { status: 'error', restored: false, reason: `${label} rollback failed: ${err.message}` };
    }
  };

  const files = {
    packageJson: restoreFile('package.json', packagePath, expectedPackageRaw, originalPackageRaw),
    packageLock: restoreFile('package-lock.json', lockfilePath, expectedLockfileRaw, originalLockfileRaw),
  };
  const notOriginal = Object.values(files).filter(result =>
    result.status !== 'restored' && result.status !== 'already-original'
  );
  return {
    restored: notOriginal.length === 0,
    files,
    ...(notOriginal.length > 0
      ? { reason: notOriginal.map(result => result.reason).filter(Boolean).join('; ') }
      : {}),
  };
}

/**
 * Apply an approved resolution with lifecycle scripts disabled, then bind the
 * resulting lockfile to the approved occurrence/resolved/integrity graph.
 *
 * @param {object} ctx
 * @param {string[]} ctx.expected \u2014 packagesToAnalyze ({name, version, ...})
 * @param {string} ctx.lockfilePath \u2014 path to package-lock.json
 * @param {string} ctx.lockfileBackup \u2014 original lockfile text (for rollback)
 */
function executeApprovedInstall(manager, targetDir, {
  display, expected = [], lockfilePath, lockfileBackup,
  packagePath, packageBackup, proposedLockfileRaw, proposedPackageRaw,
} = {}) {
  if (!proposedLockfileRaw || !proposedPackageRaw) {
    log.error('approved install is missing its proposed manifest/lockfile transaction');
    return EXIT.ERROR;
  }
  out(`  ${C.dim}Applying approved resolution for: ${display}${C.reset}`);
  out(`  ${C.dim}Lifecycle scripts are disabled for this guarded install.${C.reset}\n`);

  const restoreProjectFiles = () => restoreProjectSnapshotIfUnchanged({
    packagePath,
    lockfilePath,
    expectedPackageRaw: proposedPackageRaw,
    expectedLockfileRaw: proposedLockfileRaw,
    originalPackageRaw: packageBackup,
    originalLockfileRaw: lockfileBackup,
  });

  // Resolution and review can take time. Refuse to stage over any project edit
  // made since the original byte snapshots were captured.
  const preStage = verifyProjectSnapshot({
    packagePath,
    lockfilePath,
    expectedPackageRaw: packageBackup,
    expectedLockfileRaw: lockfileBackup,
  });
  if (!preStage.ok) {
    log.error(`approved install aborted: ${preStage.reason}`);
    out(`  ${C.yellow}! Project files changed during guard review; approved install was not staged.${C.reset}`);
    out(`  ${C.dim}${sanitize(preStage.reason)}${C.reset}\n`);
    return EXIT.ERROR;
  }

  const describeRollback = (rollback) => {
    const labels = { packageJson: 'package.json', packageLock: 'package-lock.json' };
    for (const [key, result] of Object.entries(rollback.files || {})) {
      const label = labels[key] || key;
      if (result.status === 'restored') {
        out(`  ${C.yellow}! ${label} was restored.${C.reset}`);
      } else if (result.status === 'already-original') {
        out(`  ${C.dim}${label} remained at its original snapshot.${C.reset}`);
      } else {
        out(`  ${C.yellow}! ${label} was not restored: ${sanitize(result.reason)}; newer bytes were preserved.${C.reset}`);
      }
    }
  };

  let failed = false;
  let npmContextDir;
  try {
    assertNoProjectNpmConfig(targetDir);
    const packageIdentity = assertSafeProjectFile(packagePath, targetDir, 'package.json');
    const lockIdentity = assertSafeProjectFile(lockfilePath, targetDir, 'package-lock.json');
    writeOwnedProjectFile(packagePath, proposedPackageRaw, packageIdentity, 'package.json', packageBackup);
    writeOwnedProjectFile(lockfilePath, proposedLockfileRaw, lockIdentity, 'package-lock.json', lockfileBackup);
    npmContextDir = mkdtempSync(join(tmpdir(), 'vexes-guard-install-'));
    const npmCli = resolveTrustedNpmCli(targetDir);
    const npmEnv = guardNpmEnvironment(npmContextDir);
    execFileSync(process.execPath, [npmCli, 'install', ...npmBoundaryArgs(npmContextDir)], {
      cwd: targetDir,
      stdio: 'inherit',
      timeout: 300_000,
      env: npmEnv,
    });
  } catch (err) {
    log.error(`install failed: ${err.message}`);
    failed = true;
  } finally {
    if (npmContextDir) {
      try { rmSync(npmContextDir, { recursive: true, force: true }); } catch { /* private npm context */ }
    }
  }

  if (failed) {
    const rollback = restoreProjectFiles();
    out(`  ${C.yellow}! Install failed.${C.reset}`);
    describeRollback(rollback);
    out(`  ${C.dim}node_modules may be partially modified, but lifecycle scripts were not run.${C.reset}\n`);
    return EXIT.ERROR;
  }

  let afterRaw = '';
  try { afterRaw = readFileSync(lockfilePath, 'utf8'); } catch { /* missing lockfile \u2192 verification fails below */ }
  const verdict = verifyInstalledVersions({ afterRaw, expected, approvedRaw: proposedLockfileRaw });
  let manifestMatches = false;
  try {
    manifestMatches = JSON.stringify(JSON.parse(readFileSync(packagePath, 'utf8'))) ===
      JSON.stringify(JSON.parse(proposedPackageRaw));
  } catch { manifestMatches = false; }

  if (!verdict.ok || !manifestMatches) {
    const rollback = restoreProjectFiles();
    out(`  ${C.red}${C.bold}\u2717 INSTALL DOES NOT MATCH APPROVAL${C.reset}`);
    if (!verdict.ok) out(`  ${C.red}${sanitize(verdict.reason)}${C.reset}`);
    if (!manifestMatches) out(`  ${C.red}package.json differs from the approved manifest${C.reset}`);
    describeRollback(rollback);
    out(`  ${C.dim}node_modules may differ, but no lifecycle scripts ran.${C.reset}\n`);
    return EXIT.ERROR;
  }

  out(`\n  ${C.green}\u2713 Guarded install complete${C.reset}`);
  out(`  ${C.dim}Every lockfile occurrence, resolved URL, and available integrity value matches the approved graph.${C.reset}`);
  out(`  ${C.dim}Lifecycle scripts were not executed. Run an explicit reviewed rebuild only if the package requires one.${C.reset}\n`);
  return EXIT.OK;
}

/**
 * Simple stdin prompt for TTY confirmation.
 */
function prompt() {
  return new Promise((resolve) => {
    process.stdin.setEncoding('utf8');
    process.stdin.once('data', (data) => {
      resolve(data.trim());
    });
    process.stdin.resume();
  });
}

// Shell rc markers that delimit the vexes-managed block. Shared by setup and
// uninstall so the two can never drift apart.
const GUARD_MARKER = '# --- vexes guard start ---';
const GUARD_END_MARKER = '# --- vexes guard end ---';

/**
 * Remove the vexes-managed block from shell rc content \u2014 PURE, no I/O.
 *
 * Returns one of:
 *   { status: 'absent' }               \u2014 start marker not present
 *   { status: 'corrupt', reason }      \u2014 end marker missing or before start;
 *                                        splicing here would corrupt the file
 *   { status: 'ok', cleaned }          \u2014 content with the block removed
 *
 * The corrupt case is the bug this guards against: with `endIdx === -1`,
 * `content.slice(endIdx + endMarker.length + 1)` splices at a garbage offset
 * and shreds the user's rc file.
 */
export function stripGuardBlock(content, marker = GUARD_MARKER, endMarker = GUARD_END_MARKER) {
  const startIdx = content.indexOf(marker);
  if (startIdx === -1) return { status: 'absent' };

  const endIdx = content.indexOf(endMarker);
  if (endIdx === -1) {
    return { status: 'corrupt', reason: `end marker "${endMarker}" is missing` };
  }
  if (endIdx < startIdx) {
    return { status: 'corrupt', reason: 'markers are inverted (end appears before start)' };
  }

  const after = endIdx + endMarker.length;
  // Consume a single trailing newline if present so we don't leave a blank line;
  // never over-read into following content when the newline is absent.
  const tail = content[after] === '\n' ? after + 1 : after;
  const cleaned = content.slice(0, startIdx) + content.slice(tail);
  return { status: 'ok', cleaned };
}

/**
 * Write a one-shot backup of an rc file before we touch it. If the backup
 * can't be written, the caller aborts rather than risk an unrecoverable edit.
 */
function backupRc(rcFile, content) {
  const backupPath = `${rcFile}.vexes-backup`;
  writeFileSync(backupPath, content);
  return backupPath;
}

/**
 * Install shell wrappers that intercept npm/pip install.
 */
function runSetup(flags) {
  // Automatic shell interception would catch npm commands outside guard's
  // deliberately narrow grammar (bare installs, workspaces, private sources,
  // global/prefix installs). Refuse setup until those flows can be routed or
  // bypassed without surprising the user.
  out(`  ${C.yellow}Automatic guard shell setup is disabled in this trust-hardening release.${C.reset}`);
  out(`  ${C.dim}Use the explicit form: vexes guard -- npm install <public-registry-package>${C.reset}\n`);
  return EXIT.ERROR;
}

function runUninstall(flags) {
  const shell = flags.shell || detectShell();
  const rcFile = shell === 'zsh' ? join(homedir(), '.zshrc')
               : shell === 'fish' ? join(homedir(), '.config', 'fish', 'config.fish')
               : join(homedir(), '.bashrc');

  if (!existsSync(rcFile)) {
    out(`  ${C.dim}No ${rcFile} found — nothing to uninstall.${C.reset}`);
    return EXIT.OK;
  }

  const content = readFileSync(rcFile, 'utf8');
  const result = stripGuardBlock(content);

  if (result.status === 'absent') {
    out(`  ${C.dim}Guard is not installed in ${rcFile}.${C.reset}`);
    return EXIT.OK;
  }

  if (result.status === 'corrupt') {
    // Refuse to splice \u2014 a bad offset would shred the rc file.
    log.error(`cannot safely remove guard from ${rcFile}: ${result.reason}`);
    out(`  ${C.red}! Refusing to edit ${rcFile} \u2014 ${result.reason}.${C.reset}`);
    out(`  ${C.dim}Remove the block manually: delete everything from${C.reset}`);
    out(`  ${C.dim}  ${GUARD_MARKER}${C.reset}`);
    out(`  ${C.dim}down to${C.reset}`);
    out(`  ${C.dim}  ${GUARD_END_MARKER}${C.reset}`);
    out(`  ${C.dim}(restore the missing marker first if it was deleted).${C.reset}\n`);
    return EXIT.ERROR;
  }

  // Back up BEFORE writing, so the removal is recoverable.
  let backupPath;
  try {
    backupPath = backupRc(rcFile, content);
  } catch (err) {
    log.error(`could not write backup for ${rcFile}: ${err.message} \u2014 aborting to avoid an unrecoverable edit`);
    return EXIT.ERROR;
  }

  writeFileSync(rcFile, result.cleaned);
  out(`  ${C.green}\u2713 Guard removed from ${rcFile}${C.reset}`);
  out(`  ${C.dim}Backup saved to ${backupPath}${C.reset}\n`);
  return EXIT.OK;
}

function detectShell() {
  const shellEnv = process.env.SHELL || '';
  if (shellEnv.includes('zsh')) return 'zsh';
  if (shellEnv.includes('fish')) return 'fish';
  return 'bash';
}
