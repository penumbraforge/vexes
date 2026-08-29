import { resolve, basename } from 'node:path';
import { statSync } from 'node:fs';
import { loadConfig } from '../cli/config.js';
import { buildEnvelope } from '../cli/schema.js';
import { C, createSpinner, header, out, sanitize } from '../cli/output.js';
import { log } from '../core/logger.js';
import { VERSION, EXIT, DEPS_DEV_SUPPORTED } from '../core/constants.js';
import { discover as discoverNpm, parseLockfile as parseNpmLock, parseManifest as parseNpmManifest } from '../parsers/npm.js';
import { discover as discoverPypi, parseFile as parsePypiFile } from '../parsers/pypi.js';
import { discover as discoverCargo, parseLockfile as parseCargoLock } from '../parsers/cargo.js';
import { GENERIC_ECOSYSTEM_PARSERS, parseGenericFile, selectGenericFiles } from '../parsers/generic.js';
import { queryLicenses } from '../advisories/depsdev.js';

/**
 * `vexes licenses` — flat declared-license inventory via deps.dev (no key).
 *
 * Informational, never a security verdict: licenses are metadata for policy and
 * compliance (missing/unknown SPDX id → flag), not vulnerability evidence.
 * Works for npm/pypi/cargo/go/nuget/java (deps.dev systems only); ecosystems
 * deps.dev doesn't cover are skipped with a warning, not an error.
 *
 * Fail-loud, same DNA as scan: if ANY selected lookup fails, complete=false.
 * This is not a dependency-resolved SBOM. All I/O flows through fetchJSON with
 * a shared throttle under deps.dev's unauthenticated rate limit.
 */
export async function runLicenses(flags, args) {
  const targetDir = resolve(flags.path || process.cwd());
  const config = loadConfig(targetDir, flags);
  const isJSON = config.output?.format === 'json';
  const quietStdout = isJSON;

  try {
    if (!statSync(targetDir).isDirectory()) { log.error('not a directory'); return EXIT.ERROR; }
  } catch { log.error(`path does not exist: ${targetDir}`); return EXIT.ERROR; }

  if (!isJSON) out(`\n  ${C.bold}vexes licenses${C.reset} v${VERSION} ${C.dim}— declared licenses via deps.dev${C.reset}\n`);

  // 1. Discover only ecosystems deps.dev can answer for.
  const warnings = [];
  const seenFiles = new Set();
  const ecosystemsFound = new Set();
  const allDeps = [];
  let parseFailures = 0;
  let manifestFallbackIncomplete = false;
  const unsupported = [];

  for (const ecoName of config.ecosystems) {
    if (!DEPS_DEV_SUPPORTED[ecoName]) { unsupported.push(ecoName); continue; }

    if (ecoName === 'npm') {
      const { lockfiles, manifests } = discoverNpm(targetDir);
      for (const lf of lockfiles) {
        try {
          const parsed = parseNpmLock(lf);
          if (parsed.unresolvedEntries > 0) {
            manifestFallbackIncomplete = true;
            warnings.push(`${basename(lf)} contains local, linked, remote, or unanchored npm entries — declared-license inventory is incomplete`);
          }
          allDeps.push(...parsed);
          ecosystemsFound.add('npm');
          seenFiles.add(basename(lf));
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg); warnings.push(msg); parseFailures++;
        }
      }
      if (lockfiles.length === 0) {
        if (manifests.length > 0) manifestFallbackIncomplete = true;
        for (const mf of manifests) {
          try {
            allDeps.push(...parseNpmManifest(mf));
            ecosystemsFound.add('npm');
            seenFiles.add(basename(mf));
            const msg = 'no npm lockfile found — package.json can provide exact direct pins only; resolved/transitive license inventory is incomplete';
            if (!quietStdout) out(`  ${C.yellow}! ${msg}${C.reset}`);
            warnings.push(msg);
          } catch (err) {
            const msg = `failed to parse ${basename(mf)}: ${err.message}`;
            log.error(msg); warnings.push(msg); parseFailures++;
          }
        }
      }
      continue;
    }
    if (ecoName === 'pypi') {
      const { lockfiles, manifests } = discoverPypi(targetDir);
      const files = lockfiles.length > 0 ? lockfiles : manifests;
      if (lockfiles.length === 0 && manifests.length > 0) {
        manifestFallbackIncomplete = true;
        warnings.push('no PyPI lockfile found — manifest fallback can inventory exact direct pins only');
      }
      for (const file of files) {
        try {
          const parsed = parsePypiFile(file.path, file.format);
          if (parsed.unresolvedEntries > 0) {
            manifestFallbackIncomplete = true;
            warnings.push(`${basename(file.path)} contains unanchored dependency entries — declared-license inventory is incomplete`);
          }
          allDeps.push(...parsed);
          ecosystemsFound.add('pypi');
          seenFiles.add(basename(file.path));
        } catch (err) {
          const msg = `failed to parse ${basename(file.path)}: ${err.message}`;
          log.error(msg); warnings.push(msg); parseFailures++;
        }
      }
      continue;
    }
    if (ecoName === 'cargo') {
      const { lockfiles } = discoverCargo(targetDir);
      for (const lf of lockfiles) {
        try {
          const parsed = parseCargoLock(lf);
          if (parsed.unresolvedEntries > 0) {
            manifestFallbackIncomplete = true;
            warnings.push(`${basename(lf)} contains non-crates.io or unanchored entries — declared-license inventory is incomplete`);
          }
          allDeps.push(...parsed);
          ecosystemsFound.add('cargo');
          seenFiles.add(basename(lf));
        } catch (err) {
          const msg = `failed to parse ${basename(lf)}: ${err.message}`;
          log.error(msg); warnings.push(msg); parseFailures++;
        }
      }
      continue;
    }
    // go / nuget / java through the generic registry
    const { files, usingManifestFallback } = selectGenericFiles(targetDir, ecoName);
    if (usingManifestFallback) {
      manifestFallbackIncomplete = true;
      const msg = `no lockfile found — scanning ${files.map(f => basename(f.path)).join(', ')} (best-effort fallback)`;
      warnings.push(msg);
      if (!quietStdout) out(`  ${C.yellow}! ${msg}${C.reset}`);
    }
    for (const file of files) {
      try {
        const parsed = parseGenericFile(ecoName, file);
        if (parsed.unresolvedEntries > 0) {
          manifestFallbackIncomplete = true;
          warnings.push(`${basename(file.path)} contains replaced or otherwise unanchored module entries — declared-license inventory is incomplete`);
        }
        allDeps.push(...parsed);
        ecosystemsFound.add(ecoName);
        seenFiles.add(basename(file.path));
      } catch (err) {
        const msg = `failed to parse ${basename(file.path)}: ${err.message}`;
        log.error(msg); warnings.push(msg); parseFailures++;
      }
    }
  }

  if (allDeps.length === 0 && parseFailures > 0) {
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'licenses', target: { dir: targetDir, lockfiles: [], ecosystems: [] },
        complete: false, warnings, summary: { total: 0, withLicenses: 0, missing: 0, skipped: 0 },
        extra: { licenses: [], version: VERSION },
      }), null, 2));
    } else {
      out(`\n  ${C.red}! Dependency files found but all failed to parse — cannot build a license bill of materials${C.reset}\n`);
    }
    return EXIT.ERROR;
  }

  if (allDeps.length === 0) {
    const dependencyEvidenceIncomplete = seenFiles.size > 0 && manifestFallbackIncomplete;
    if (dependencyEvidenceIncomplete) {
      warnings.push('dependency manifests were found but no resolved lockfile graph was available');
    }
    const note = unsupported.length > 0
      ? ` (deps.dev has no data for: ${unsupported.join(', ')})`
      : '';
    if (isJSON) {
      out(JSON.stringify(buildEnvelope({
        command: 'licenses', target: { dir: targetDir, lockfiles: [...seenFiles], ecosystems: [...ecosystemsFound] },
        complete: !dependencyEvidenceIncomplete, warnings: [...warnings, ...unsupported.map(e => `deps.dev has no ${e} data — skipped`)] ,
        summary: { total: 0, withLicenses: 0, missing: 0, skipped: 0 },
        extra: { licenses: [], version: VERSION },
      }), null, 2));
    } else {
      if (dependencyEvidenceIncomplete) {
        out(`  ${C.red}! License inventory incomplete — dependency manifests exist but no resolved graph was available${C.reset}\n`);
      } else {
        out(`  ${C.dim}No dependencies found in ${targetDir}${note}${C.reset}\n`);
      }
    }
    return dependencyEvidenceIncomplete ? EXIT.ERROR : EXIT.OK;
  }

  // 2. Dedupe
  const dedupMap = new Map();
  for (const dep of allDeps) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!dedupMap.has(key)) dedupMap.set(key, dep);
  }
  const uniqueDeps = [...dedupMap.values()];

  // 3. Query licenses (throttled). Each record is a license list or a skip reason.
  const spinner = isJSON ? null : createSpinner(`Querying deps.dev for license data (${uniqueDeps.length} packages)...`);
  const { records, skipped, complete: lookupsComplete } = await queryLicenses(uniqueDeps);
  const complete = lookupsComplete && !manifestFallbackIncomplete && parseFailures === 0;
  spinner?.stop(`${records.length - skipped} packages with license data`);

  const withLicenses = records.filter(r => !r.skipped && r.licenses?.length > 0);
  const missing = records.filter(r => !r.skipped && r.licenses?.length === 0);
  const skippedRecs = records.filter(r => r.skipped);

  if (!isJSON) {
    out(header('Declared Licenses'));
    if (withLicenses.length > 0) {
      for (const r of withLicenses) {
        out(`  ${C.bold}${sanitize(r.name)}${C.reset}@${sanitize(r.version)} ${C.dim}(${sanitize(r.ecosystem)})${C.reset} — ${C.green}${r.licenses.map(sanitize).join(', ')}${C.reset}`);
      }
      out('');
    }
    if (missing.length > 0) {
      out(`  ${C.yellow}No declared license:${C.reset}\n`);
      for (const r of missing) {
        out(`  ${C.yellow}○${C.reset} ${sanitize(r.name)}@${sanitize(r.version)} (${sanitize(r.ecosystem)})`);
      }
      out('');
    }
    if (skippedRecs.length > 0) {
      out(`  ${C.red}Lookup failed:${C.reset}\n`);
      for (const r of skippedRecs) {
        out(`  ${C.red}○${C.reset} ${sanitize(r.name)}@${sanitize(r.version)} (${sanitize(r.ecosystem)}) — ${sanitize(r.reason)}`);
      }
      out('');
    }

    const line = '─'.repeat(50);
    out(`  ${C.dim}${line}${C.reset}`);
    out(`  ${withLicenses.length} with license · ${missing.length} missing · ${skippedRecs.length} skipped`);
    if (unsupported.length > 0) {
      out(`  ${C.yellow}! deps.dev has no data for ${unsupported.join(', ')} — use vexes scan for vulnerability coverage${C.reset}`);
    }
    if (warnings.length > 0) {
      out(`  ${C.yellow}! ${warnings.length} warning(s)${C.reset}`);
    }
    out(`  ${C.dim}${line}${C.reset}\n`);
    if (!complete) {
      out(`  ${C.red}${C.bold}! INCOMPLETE${C.reset} ${C.red}— some selected license lookups failed; the inventory is partial.${C.reset}\n`);
    }
  } else {
    out(JSON.stringify(buildEnvelope({
      command: 'licenses',
      target: { dir: targetDir, lockfiles: [...seenFiles], ecosystems: [...ecosystemsFound] },
      complete,
      warnings: [...warnings, ...unsupported.map(e => `deps.dev has no ${e} data — skipped`)],
      summary: {
        total: uniqueDeps.length,
        withLicenses: withLicenses.length,
        missing: missing.length,
        skipped: skippedRecs.length,
      },
      findings: [],
      extra: {
        version: VERSION,
        licenses: records.map(r => ({
          package: r.name,
          version: r.version,
          ecosystem: r.ecosystem,
          ...(r.skipped
            ? { skipped: true, reason: r.reason }
            : { licenses: r.licenses, url: r.url }),
        })),
      },
    }), null, 2));
  }

  if (!complete) return EXIT.ERROR;
  return missing.length > 0 ? EXIT.VULNS_FOUND : EXIT.OK;
}
