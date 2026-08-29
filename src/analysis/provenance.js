import { fetchNpmProvenance } from '../advisories/npm-registry.js';
import { log } from '../core/logger.js';

/**
 * Inspect npm packages for published Sigstore provenance attestations.
 *
 * This module fetches attestation bundles and decodes DSSE payload JSON. It
 * does NOT verify the DSSE signature, certificate chain, Rekor inclusion, or
 * subject digest against downloaded package bytes. Presence and decoded
 * claims are useful evidence, but they are not cryptographic verification.
 *
 * 2026 addition: we now also surface the attestation *subjects* (the artifact
 * names the payload claims as subjects) and compare those claims with package
 * identity. Provenance presence is not a trust verdict.
 */
export async function checkProvenance(packageName, version) {
  try {
    const data = await fetchNpmProvenance(packageName, version);

    if (!data) {
      return provenanceResult({ hasAttestation: null, status: 'unavailable' });
    }

    if (!data.hasProvenance || !data.attestations?.length) {
      return provenanceResult({ hasAttestation: false, status: 'absent' });
    }

    // Parse SLSA provenance from attestations
    let buildType = null;
    let sourceRepo = null;
    let transparencyLogEntryPresent = false;
    let anyParsedSuccessfully = false;
    const subjects = new Set();

    for (const att of data.attestations) {
      if (att.bundle?.verificationMaterial?.tlogEntries?.length > 0) {
        transparencyLogEntryPresent = true;
      }
      try {
        if (att.bundle?.dsseEnvelope?.payload) {
          const payload = JSON.parse(
            Buffer.from(att.bundle.dsseEnvelope.payload, 'base64').toString('utf8')
          );

          buildType = payload.predicate?.buildType || buildType;
          sourceRepo = payload.predicate?.invocation?.configSource?.uri || sourceRepo;

          // SLSA statement: `subject` sits at the top of the in-toto
          // Statement, alongside `predicate` — these are the artifact names
          // the decoded payload claims. npm uses `pkg:npm/<name>@<version>`.
          for (const s of payload.subject || []) {
            if (typeof s?.name === 'string' && s.name.length > 0) subjects.add(s.name);
          }

          anyParsedSuccessfully = true;
        }
      } catch (err) {
        // A malformed payload remains "present but undecodable".
        log.warn(`attestation parse failed for ${packageName}@${version}: ${err.message}`);
      }
    }

    return provenanceResult({
      hasAttestation: true,
      attestationDecoded: anyParsedSuccessfully,
      status: anyParsedSuccessfully ? 'decoded' : 'present-undecodable',
      buildType,
      sourceRepo,
      transparencyLogEntryPresent,
      subjects: [...subjects],
    });
  } catch (err) {
    log.debug(`provenance check failed for ${packageName}@${version}: ${err.message}`);
    return provenanceResult({ hasAttestation: null, status: 'unavailable' });
  }
}

function provenanceResult({
  hasAttestation,
  attestationDecoded = false,
  status,
  buildType = null,
  sourceRepo = null,
  transparencyLogEntryPresent = hasAttestation === true ? false : null,
  subjects = [],
}) {
  return {
    hasAttestation,
    attestationDecoded,
    attestationStatus: status,
    verificationStatus: 'not-performed',
    cryptographicallyVerified: false,
    transparencyLogEntryPresent,
    claimedBuildType: buildType,
    claimedSourceRepo: sourceRepo,
    claimedSubjects: subjects,

    // Compatibility fields. `hasProvenance` means an attestation payload was
    // present and decoded; it must not be read as signature verification.
    hasProvenance: hasAttestation === false ? false : (attestationDecoded ? true : null),
    buildType,
    sourceRepo,
    transparency: transparencyLogEntryPresent === true ? 'entry-present' : null,
    subjects,
  };
}

/**
 * Detect identity mismatches in decoded attestation claims.
 *
 * Pure — no I/O — so the spoof judgment is unit-testable. Returns a signal
 * object or null. Two independent checks:
 *
 * 1. SUBJECT MISMATCH: the decoded subject names never match this package.
 *    This is a deterministic metadata mismatch, not proof of signature replay.
 * 2. SOURCE/REPO MISMATCH: the decoded payload claims "built in CI
 *    from repo X" but the registry declares repo Y and they do not agree.
 *    This only compares decoded fields; it does not cryptographically verify
 *    the bundle. Builds from legitimate forks or mirrors can false-positive.
 *
 * @param {object} ctx — { packageName, subjects: string[], sourceRepo: string|null, declaredRepo: string|null }
 * @returns {{ signal: string, severity: string, description: string, evidence: object }|null}
 */
export function detectAttestationIdentityMismatch(ctx) {
  const { packageName, subjects = [], sourceRepo = null, declaredRepo = null } = ctx || {};
  if (!packageName) return null;
  const evidence = {};

  // 1. Subject mismatch. Normalize `pkg:npm/name@version` forms; do not infer replay.
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
        signal: 'ATTESTATION_IDENTITY_MISMATCH',
        legacySignal: 'SIGNATURE_SPOOF',
        severity: 'HIGH',
        description: `Decoded attestation subject name(s) do not match package "${packageName}"`,
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
          signal: 'ATTESTATION_IDENTITY_MISMATCH',
          legacySignal: 'SIGNATURE_SPOOF',
          severity: 'HIGH',
          description: `Decoded attestation claims source "${sourceRepo}" but package metadata declares "${declaredRepo}"`,
          evidence: { kind: 'repo-mismatch', sourceRepo, declaredRepo },
          confidence: 'heuristic',
          layer: 4,
        };
      }
    }
  }

  return null;
}

// Backward-compatible export name. The returned signal uses the truthful
// ATTESTATION_IDENTITY_MISMATCH identifier.
export const detectProvenanceSpoof = detectAttestationIdentityMismatch;
