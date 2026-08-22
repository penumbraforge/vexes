import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectProvenanceSpoof, checkProvenance } from '../src/analysis/provenance.js';

/**
 * PROVENANCE-SPOOF LAYER (TanStack-family vector: valid signature, wrong
 * package / wrong repo). Pure detector tests below touch no network; the
 * checkProvenance subject-capture test stubs global.fetch so the registry is
 * never reached.
 */

function spoofCtx(overrides = {}) {
  return {
    packageName: 'tar',
    subjects: ['pkg:npm/tar@6.1.2'],
    sourceRepo: 'https://github.com/isaacs/node-tar',
    declaredRepo: 'https://github.com/isaacs/node-tar',
    ...overrides,
  };
}

describe('detectProvenanceSpoof', () => {
  it('is silent when the attestation certifies this exact package', () => {
    assert.equal(detectProvenanceSpoof(spoofCtx()), null);
  });

  it('is silent for scoped packages with a matching subject', () => {
    const ctx = spoofCtx({
      packageName: '@babel/core',
      subjects: ['pkg:npm/@babel/core@7.0.0'],
      sourceRepo: 'https://github.com/babel/babel.git',
      declaredRepo: 'https://github.com/babel/babel',
    });
    assert.equal(detectProvenanceSpoof(ctx), null);
  });

  it('flags a replayed attestation (subject = a DIFFERENT package) as HIGH', () => {
    const r = detectProvenanceSpoof(spoofCtx({ subjects: ['pkg:npm/lodash@4.17.21'] }));
    assert.ok(r, 'expected a signal');
    assert.equal(r.signal, 'SIGNATURE_SPOOF');
    assert.equal(r.severity, 'HIGH');
    assert.equal(r.confidence, 'deterministic');
    assert.equal(r.evidence.kind, 'subject-mismatch');
  });

  it('flags repo mismatch (provenance built from a different repo) as HIGH', () => {
    const r = detectProvenanceSpoof(spoofCtx({
      subjects: ['pkg:npm/tar@6.1.2'],
      sourceRepo: 'https://github.com/shadow-corps/node-tar-ws',
      declaredRepo: 'https://github.com/isaacs/node-tar',
    }));
    assert.ok(r);
    assert.equal(r.evidence.kind, 'repo-mismatch');
    assert.equal(r.confidence, 'heuristic');
  });

  it('ignores formatting-only repo differences (.git suffix, www.)', () => {
    const ctx = spoofCtx({
      declaredRepo: 'git+https://www.github.com/isaacs/node-tar.git',
    });
    assert.equal(detectProvenanceSpoof(ctx), null);
  });

  it('fires subject-mismatch even when repo matches (replay with honest source)', () => {
    const r = detectProvenanceSpoof(spoofCtx({ subjects: ['pkg:npm/socket.io@4.8.0'] }));
    assert.ok(r);
    assert.equal(r.evidence.kind, 'subject-mismatch');
  });

  it('does not fire when either repo side is unknown', () => {
    assert.equal(detectProvenanceSpoof(spoofCtx({ sourceRepo: null, declaredRepo: 'x' })), null);
    assert.equal(detectProvenanceSpoof(spoofCtx({ sourceRepo: 'x', declaredRepo: null })), null);
  });

  it('does not fire with no subjects and no repos', () => {
    assert.equal(detectProvenanceSpoof({ packageName: 'tar' }), null);
  });

  it('survives malformed URLs without crashing', () => {
    const r = detectProvenanceSpoof(spoofCtx({ sourceRepo: 'not a url', declaredRepo: 'also :: not' }));
    assert.equal(r, null);
  });

  it('is a no-op on empty context', () => {
    assert.equal(detectProvenanceSpoof(null), null);
    assert.equal(detectProvenanceSpoof({}), null);
  });
});

describe('checkProvenance: subject capture (stubbed fetch)', () => {
  function stubResponse(body, { ok = true, status = 200 } = {}) {
    return {
      ok,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  }

  function attestationPayload({ subjectName, sourceRepo, buildType }) {
    return Buffer.from(JSON.stringify({
      _type: 'https://in-toto.io/Statement/v0.1',
      subject: [{ name: subjectName, digest: { sha512: 'abc' } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildType,
        invocation: { configSource: { uri: sourceRepo } },
      },
    })).toString('base64');
  }

  function makeFetch({ subjectName, sourceRepo, buildType }) {
    return async (url) => {
      if (String(url).includes('/attestations/')) {
        return stubResponse({
          attestations: [{
            bundle: {
              dsseEnvelope: {
                payload: attestationPayload({ subjectName, sourceRepo, buildType }),
              },
              verificationMaterial: { tlogEntries: [{ logIndex: 1 }] },
            },
          }],
        });
      }
      return stubResponse({});
    };
  }

  it('extracts the certified subject name from a verified attestation', async () => {
    const prev = global.fetch;
    global.fetch = makeFetch({ subjectName: 'pkg:npm/tar@6.1.2', sourceRepo: 'https://github.com/isaacs/node-tar', buildType: 'slsa-github-generator' });
    try {
      const prov = await checkProvenance('tar', '6.1.2');
      assert.equal(prov.hasProvenance, true);
      assert.deepEqual(prov.subjects, ['pkg:npm/tar@6.1.2']);
      assert.equal(prov.sourceRepo, 'https://github.com/isaacs/node-tar');
      assert.equal(prov.transparency, 'verified');
    } finally {
      global.fetch = prev;
    }
  });

  it('wires straight into the spoof detector (evidence chain stays hermetic)', async () => {
    const prev = global.fetch;
    global.fetch = makeFetch({ subjectName: 'pkg:npm/lodash@4.17.21', sourceRepo: 'https://github.com/evilcorp/oops', buildType: 'slsa-github-generator' });
    try {
      const prov = await checkProvenance('tar', '6.1.2');
      const spoof = detectProvenanceSpoof({
        packageName: 'tar',
        subjects: prov.subjects,
        sourceRepo: prov.sourceRepo,
        declaredRepo: 'https://github.com/isaacs/node-tar',
      });
      assert.ok(spoof);
      assert.equal(spoof.signal, 'SIGNATURE_SPOOF');
      assert.equal(spoof.evidence.kind, 'subject-mismatch');
    } finally {
      global.fetch = prev;
    }
  });

  it('returns empty subjects on missing provenance', async () => {
    const prev = global.fetch;
    global.fetch = async () => stubResponse({ attestations: [] });
    try {
      const prov = await checkProvenance('tar', '6.1.2');
      assert.equal(prov.hasProvenance, false); // no attestations → not verified
      assert.deepEqual(prov.subjects, []);
    } finally {
      global.fetch = prev;
    }
  });
});
