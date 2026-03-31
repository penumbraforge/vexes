import { fetchNpmProvenance } from '../advisories/npm-registry.js';
import { log } from '../core/logger.js';

/**
 * Check npm packages for Sigstore provenance attestations.
 *
 * Provenance means the package was built by a CI system from a public
 * source repository, with a cryptographic chain linking the published
 * artifact to the source commit. Packages WITHOUT provenance could have
 * been published from any machine (including a compromised one).
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
      };
    }

    if (!data.hasProvenance || !data.attestations?.length) {
      return {
        hasProvenance: false,
        buildType: null,
        sourceRepo: null,
        transparency: null,
      };
    }

    // Parse SLSA provenance from attestations
    let buildType = null;
    let sourceRepo = null;
    let transparency = null;
    let anyParsedSuccessfully = false;

    for (const att of data.attestations) {
      try {
        if (att.bundle?.dsseEnvelope?.payload) {
          const payload = JSON.parse(
            Buffer.from(att.bundle.dsseEnvelope.payload, 'base64').toString('utf8')
          );

          buildType = payload.predicate?.buildType || buildType;
          sourceRepo = payload.predicate?.invocation?.configSource?.uri || sourceRepo;

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
    };
  } catch (err) {
    log.debug(`provenance check failed for ${packageName}@${version}: ${err.message}`);
    return {
      hasProvenance: null,
      buildType: null,
      sourceRepo: null,
      transparency: null,
    };
  }
}
