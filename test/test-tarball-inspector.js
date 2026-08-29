import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  collectInspectableEntrypoints,
  inspectTarball,
  verifyArtifactDigest,
} from '../src/analysis/tarball-inspector.js';

describe('tarball runtime entrypoint selection', () => {
  it('keeps executable export targets and excludes type-only declarations', () => {
    assert.deepEqual(collectInspectableEntrypoints({
      main: './index.js',
      bin: { demo: './bin/demo' },
      exports: {
        '.': {
          types: './typings/index.d.ts',
          import: './esm/index.mjs',
          require: './cjs/index.cjs',
        },
        './feature': './feature.js',
      },
    }), [
      './index.js',
      './bin/demo',
      './esm/index.mjs',
      './cjs/index.cjs',
      './feature.js',
    ]);
  });
});

describe('tarball artifact digest binding', () => {
  const bytes = Buffer.from('exact compressed artifact bytes');

  it('accepts matching SRI and legacy shasum evidence', () => {
    const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
    const shasum = createHash('sha1').update(bytes).digest('hex');
    assert.equal(verifyArtifactDigest(bytes, { integrity }, 'demo'), true);
    assert.equal(verifyArtifactDigest(bytes, { shasum }, 'demo'), true);
  });

  it('fails closed on mismatched or malformed registry evidence', () => {
    const other = Buffer.from('different bytes');
    const integrity = `sha512-${createHash('sha512').update(other).digest('base64')}`;
    assert.throws(() => verifyArtifactDigest(bytes, { integrity }, 'demo'), /integrity mismatch/);
    assert.throws(() => verifyArtifactDigest(bytes, { integrity: 'md5-nope' }, 'demo'), /unsupported or malformed/);
    assert.throws(() => verifyArtifactDigest(bytes, { shasum: 'not-a-sha1' }, 'demo'), /malformed/);
  });

  it('requires a match from the strongest algorithm present', () => {
    const other = Buffer.from('different bytes');
    const goodSha1 = createHash('sha1').update(bytes).digest('base64');
    const badSha512 = createHash('sha512').update(other).digest('base64');
    const goodSha512 = createHash('sha512').update(bytes).digest('base64');
    const badSha1 = createHash('sha1').update(other).digest('base64');

    assert.throws(
      () => verifyArtifactDigest(bytes, { integrity: `sha1-${goodSha1} sha512-${badSha512}` }, 'demo'),
      /integrity mismatch/,
    );
    assert.equal(
      verifyArtifactDigest(bytes, { integrity: `sha1-${badSha1} sha512-${goodSha512}` }, 'demo'),
      true,
    );
  });

  it('reports absent digest evidence without pretending verification', () => {
    assert.equal(verifyArtifactDigest(bytes, {}, 'demo'), false);
  });
});

describe('tarball redirect boundary', () => {
  it('revalidates redirect targets and refuses an off-allowlist hop', async () => {
    const previousFetch = global.fetch;
    let calls = 0;
    global.fetch = async () => {
      calls++;
      return {
        ok: false,
        status: 302,
        headers: new Headers({ location: 'http://127.0.0.1/private' }),
      };
    };
    try {
      const result = await inspectTarball(
        'https://registry.npmjs.org/demo/-/demo-1.0.0.tgz',
        'demo',
      );
      assert.equal(calls, 1, 'the forbidden redirect target must never be fetched');
      assert.match(result.warnings.join('\n'), /tarball URL must use HTTPS|not in the allowed list/);
    } finally {
      global.fetch = previousFetch;
    }
  });
});
