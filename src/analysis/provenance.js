import { fetchNpmProvenance } from '../advisories/npm-registry.js';
import { log } from '../core/logger.js';

/**
 * Check npm packages for Sigstore provenance attestations.
 *
 * Provenance means the package was built by a CI system from a public
 * source repository, with a cryptographic chain linking the published
 * artifact to the source commit. Packages WITHOUT provenance could have
 * been published from any machine (including a compromised one).
 *
 * 2026 addition: we now also surface the attestation *subjects* (the artifact
 * names the signature certifies) — `SIGNATURE_SPOOF` in signals.js xrefs them
 * against the package identity. Provenance ≠ trust: the TanStack worm shipped
 * cryptographically valid SLSA L3 provenance, so "has provenance" alone proves
 * nothing. What an attestation SAYS it certified still has to match who the
 * package says it is.
 */
export async function checkProvenance(packageName, version) {
  try {
    const data = await fetchNpmProvenance(packageName, version);

    if (!data) {
      return {
        hasProvenance: null, // Could not determine (fetch failed)
        buildType: null,
        sourceRepo: null,
        transparency: null,
        subjects: [],
      };
    }

    if (!data.hasProvenance || !data.attestations?.length) {
      return {
        hasProvenance: false,
        buildType: null,
        sourceRepo: null,
        transparency: null,
        subjects: [],
      };
    }

    // Parse SLSA provenance from attestations
    let buildType = null;
    let sourceRepo = null;
    let transparency = null;
    let anyParsedSuccessfully = false;
    const subjects = new Set();

    for (const att of data.attestations) {
      try {
        if (att.bundle?.dsseEnvelope?.payload) {
          const payload = JSON.parse(
            Buffer.from(att.bundle.dsseEnvelope.payload, 'base64').toString('utf8')
          );

          buildType = payload.predicate?.buildType || buildType;
          sourceRepo = payload.predicate?.invocation?.configSource?.uri || sourceRepo;

          // SLSA statement: `subject` sits at the top of the in-toto
          // Statement, alongside `predicate` — the artifact names the
          // signature certifies. npm uses `pkg:npm/<name>@<version>`.
          for (const s of payload.subject || []) {
            if (typeof s?.name === 'string' && s.name.length > 0) subjects.add(s.name);
          }

          if (att.bundle?.verificationMaterial?.tlogEntries?.length > 0) {
            transparency = 'verified';
          }

          anyParsedSuccessfully = true;
        }
      } catch (err) {
        // Corrupted/crafted attestation that crashes parser — don't claim provenance is verified
        log.warn(`attestation parse failed for ${packageName}@${version}: ${err.message}`);
      }
    }

    return {
      // Only claim provenance if we successfully parsed at least one attestation
      hasProvenance: anyParsedSuccessfully ? true : null,
      buildType,
      sourceRepo,
      transparency,
      subjects: [...subjects],
    };
  } catch (err) {
    log.debug(`provenance check failed for ${packageName}@${version}: ${err.message}`);
    return {
      hasProvenance: null,
      buildType: null,
      sourceRepo: null,
      transparency: null,
      subjects: [],
    };
  }
}

/**
 * Detect provenance-replay / misattributed-provenance (TanStack-family vector).
 *
 * Pure — no I/O — so the spoof judgment is unit-testable. Returns a signal
 * object or null. Two independent checks:
 *
 * 1. SUBJECT MISMATCH (replay): the attestation cryptographically certifies an
 *    artifact whose name never contains THIS package's name. Valid signature,
 *    wrong package → provenance replay (attacker re-hosted someone else's
 *    attestation bundle). Deterministic.
 * 2. SOURCE/REPO MISMATCH (credible-denial): provenance claims "built in CI
 *    from repo X" but the registry declares interface repo Y and they don't
 *    agree. The TanStack worm's provenance was valid — fully-repo it, the tool
 *    can't see the token theft. What it CAN see is the package pointing at a
 *    source repo that the attestation never mentions. Heuristic: builds from
 *    org forks/mirrors false-positive.
 *
 * @param {object} ctx — { packageName, subjects: string[], sourceRepo: string|null, declaredRepo: string|null }
 * @returns {{ signal: string, severity: string, description: string, evidence: object }|null}
 */
export function detectProvenanceSpoof(ctx) {
  const { packageName, subjects = [], sourceRepo = null, declaredRepo = null } = ctx || {};
  if (!packageName) return null;
  const evidence = {};

  // 1. Subject mismatch → replay. Normalize `pkg:npm/name@version` forms.
  // Strip only a @<digits...> version tail (never the scope `@`), so both
  // `lodash@4.17.21` and `@babel/core@7.0.0` normalize cleanly.
  const normalized = (s) => s
    .replace(/^pkg:npm\//i, '')
    .replace(/^pkg:pypi\//i, '')
    .replace(/@\d.*$/, '')
    .replace(/^@/, '') // scoped names: @scope/name → scope/name for comparison
    .toLowerCase();
  const pkgKey = packageName.replace(/^@/, '').toLowerCase();
  if (subjects.length > 0) {
    const matching = subjects.filter(s => normalized(s) === pkgKey || normalized(s).startsWith(pkgKey + '/'));
    if (matching.length === 0) {
      return {
        signal: 'SIGNATURE_SPOOF',
        severity: 'HIGH',
        description: `Provenance attestation certifies artifact(s) that never match package "${packageName}" — probable replay of another package's signature`,
        evidence: { kind: 'subject-mismatch', subjects, packageName },
        confidence: 'deterministic',
        layer: 4,
      };
    }
    evidence.subjectMatch = true;
  }

  // 2. Repo mismatch — only when BOTH sides are known (missing declared repo is
  //    already NO_REPOSITORY; missing source repo doesn't prove anything).
  if (sourceRepo && declaredRepo) {
    const repoHost = (u) => {
      try { return new URL(u.replace(/^git\+/, '')).host.replace(/^www\./, ''); } catch { return null; }
    };
    const repoPath = (u) => {
      try { return new URL(u.replace(/^git\+/, '')).pathname.replace(/\.git$/, '').replace(/\/$/, ''); } catch { return null; }
    };
    const src = { host: repoHost(sourceRepo), path: repoPath(sourceRepo) };
    const dec = { host: repoHost(declaredRepo), path: repoPath(declaredRepo) };
    // Only compare when both parse; comparing host+path with .git/ www-
    // normalization avoids silly mismatches on formatting-only differences.
    if (src.host && dec.host && src.path && dec.path) {
      const differs = src.host !== dec.host ||
        (src.path !== dec.path && src.path + '.git' !== dec.path && src.path !== dec.path + '.git');
      if (differs) {
        return {
          signal: 'SIGNATURE_SPOOF',
          severity: 'HIGH',
          description: `Provenance claims build from "${sourceRepo}" but package metadata declares "${declaredRepo}"`,
          evidence: { kind: 'repo-mismatch', sourceRepo, declaredRepo },
          confidence: 'heuristic',
          layer: 4,
        };
      }
    }
  }

  return null;
}
