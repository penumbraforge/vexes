import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLockfile as parseHex, discover as discoverHex } from '../src/parsers/hex.js';
import { parseLockfile as parsePub, discover as discoverPub } from '../src/parsers/pub.js';
import { selectGenericFiles, parseGenericFile } from '../src/parsers/generic.js';
import { ecosystemToOsv } from '../src/advisories/osv.js';

const DIR = join(fileURLToPath(new URL('..', import.meta.url)), 'test', 'fixtures');

/**
 * HEX + PUB PARSERS (breadth): mix.lock and pubspec.lock must produce
 * concrete, OSV-addressable deps; git dependencies are not Hex releases and
 * must be skipped.
 */

describe('hex (mix.lock)', () => {
  it('parses pinned hex packages and skips :git deps', () => {
    const deps = parseHex(join(DIR, 'mix.lock'));
    assert.equal(deps.length, 3);
    assert.deepEqual(
      deps.map(d => d.name).sort(),
      ['jason', 'phoenix', 'plug'],
      'git deps are not returnable Hex versions'
    );
    for (const d of deps) {
      assert.equal(d.ecosystem, 'hex');
      assert.match(d.version, /^\d+\.\d+\.\d+$/);
    }
    assert.ok(deps.some(d => d.name === 'jason' && d.version === '1.4.4'));
  });

  it('discovers mix.lock and routes through the generic registry', () => {
    const { files } = selectGenericFiles(DIR, 'hex');
    assert.ok(files.some(f => f.path.endsWith('mix.lock')), 'mix.lock discovered');
    const deps = parseGenericFile('hex', files.find(f => f.path.endsWith('mix.lock')));
    assert.ok(Array.isArray(deps) && deps.length === 3);
  });

  it('returns an empty list when the file is missing', () => {
    const { files } = selectGenericFiles(join(DIR, 'does-not-exist'), 'hex');
    assert.deepEqual(files, []);
    assert.deepEqual(discoverHex('/nope'), { lockfiles: [], manifests: [] });
  });
});

describe('pub (pubspec.lock)', () => {
  it('parses packages with correct direct/transitive classification', () => {
    const deps = parsePub(join(DIR, 'pubspec.lock'));
    assert.equal(deps.length, 3);
    assert.deepEqual(deps.map(d => d.name).sort(), ['args', 'collection', 'meta']);
    const args = deps.find(d => d.name === 'args');
    assert.equal(args.isDirect, true);
    assert.equal(args.isDev, false);
    const coll = deps.find(d => d.name === 'collection');
    assert.equal(coll.isDirect, false);
    assert.equal(coll.isDev, true);
    for (const d of deps) assert.match(d.version, /^\d+\.\d+\.\d+/);
  });

  it('discovers pubspec.lock and routes through the generic registry', () => {
    const { files } = selectGenericFiles(DIR, 'pub');
    assert.ok(files.some(f => f.path.endsWith('pubspec.lock')));
  });
});

describe('ecosystem identity for OSV', () => {
  it('maps hex → Hex and pub → Pub', () => {
    assert.equal(ecosystemToOsv('hex'), 'Hex');
    assert.equal(ecosystemToOsv('pub'), 'Pub');
  });
});
