import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseLockfile } from '../src/parsers/pnpm.js';

function parseFixture(content) {
  const dir = mkdtempSync(join(tmpdir(), 'vexes-pnpm-parser-'));
  try {
    const file = join(dir, 'pnpm-lock.yaml');
    writeFileSync(file, content);
    return parseLockfile(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('pnpm lockfile parser', () => {
  it('strips v6 peer-context suffixes from concrete package versions', () => {
    const parsed = parseFixture(`lockfileVersion: '6.0'
dependencies:
  react-dom:
    specifier: 18.2.0
    version: 18.2.0(react@18.2.0)
packages:
  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-example}
    peerDependencies:
      react: 18.2.0
  /react@18.2.0:
    resolution: {integrity: sha512-example}
`);

    assert.deepEqual(
      parsed.map(dep => [dep.name, dep.version]),
      [['react-dom', '18.2.0'], ['react', '18.2.0']],
    );
    assert.equal(parsed[0].isDirect, true);
    assert.equal(parsed.unresolvedEntries, 2, 'integrity-only rows do not prove registry origin');
  });

  it('uses the v9 root importer for direct and development classification', () => {
    const parsed = parseFixture(`lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
    devDependencies:
      vite:
        specifier: ^5.4.0
        version: 5.4.10
  packages/example-workspace:
    dependencies:
      kleur:
        specifier: ^4.1.5
        version: 4.1.5
packages:
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-example}
  react-dom@17.0.2(react@17.0.2):
    resolution: {integrity: sha512-example}
  react@18.2.0:
    resolution: {integrity: sha512-example}
  vite@5.4.10:
    resolution: {integrity: sha512-example}
  kleur@4.1.5:
    resolution: {integrity: sha512-example}
snapshots: {}
`);

    const byName = Object.fromEntries(parsed
      .filter(dep => dep.name !== 'react-dom')
      .map(dep => [dep.name, dep]));
    const directReactDom = parsed.find(dep => dep.name === 'react-dom' && dep.version === '18.2.0');
    const transitiveReactDom = parsed.find(dep => dep.name === 'react-dom' && dep.version === '17.0.2');
    assert.deepEqual(
      { direct: directReactDom.isDirect, dev: directReactDom.isDev },
      { direct: true, dev: false },
    );
    assert.equal(transitiveReactDom.isDirect, false, 'only the importer-resolved occurrence is direct');
    assert.deepEqual(
      { direct: byName.vite.isDirect, dev: byName.vite.isDev },
      { direct: true, dev: true },
    );
    assert.equal(byName.react.isDirect, false);
    assert.equal(byName.kleur.isDirect, false, 'non-root importers must not make app dependencies direct');
    assert.equal(parsed.unresolvedEntries, 5, 'each integrity-only coordinate keeps source coverage incomplete');
  });

  it('omits and counts malformed and non-registry importer/package entries', () => {
    const parsed = parseFixture(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
      local-tool:
        specifier: link:../local-tool
        version: link:../local-tool
      broken:
        specifier: ^1.0.0
        version: not-a-version
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-example}
  'local-tool@file:../local-tool':
    resolution: {directory: ../local-tool, type: directory}
  broken@not-a-version: {}
  'peer-broken@1.2.3(peer@2.0.0': {}
  'remote@https://example.invalid/remote.tgz': {}
`);

    assert.deepEqual(parsed.map(dep => `${dep.name}@${dep.version}`), ['lodash@4.17.21']);
    assert.equal(parsed.unresolvedEntries, 7);
    assert.equal(Object.keys(parsed).includes('unresolvedEntries'), false);
  });

  it('only treats an explicit public npm tarball URL as source-anchored', () => {
    const parsed = parseFixture(`lockfileVersion: '9.0'
importers:
  .: {}
packages:
  anchored@1.2.3:
    resolution: {tarball: https://registry.npmjs.org/anchored/-/anchored-1.2.3.tgz}
`);

    assert.deepEqual(parsed.map(dep => `${dep.name}@${dep.version}`), ['anchored@1.2.3']);
    assert.equal(parsed[0].sourceType, 'registry');
    assert.equal(parsed.unresolvedEntries, 0);
  });

  it('does not anchor a tarball URL whose path names a different artifact', () => {
    const parsed = parseFixture(`lockfileVersion: '9.0'
importers:
  .: {}
packages:
  innocent@1.2.3:
    resolution: {tarball: https://registry.npmjs.org/evil/-/evil-9.9.9.tgz}
`);

    assert.deepEqual([...parsed], []);
    assert.equal(parsed.unresolvedEntries, 1);
  });

  it('stays source-incomplete when project registry config can redirect ordinary keys', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vexes-pnpm-private-registry-'));
    try {
      const file = join(dir, 'pnpm-lock.yaml');
      writeFileSync(join(dir, '.npmrc'), 'registry=https://packages.example/\n');
      writeFileSync(file, `lockfileVersion: '9.0'
importers:
  .: {}
packages:
  private-name@1.2.3:
    resolution: {integrity: sha512-example}
`);
      const parsed = parseLockfile(file);
      assert.deepEqual(parsed.map(dep => `${dep.name}@${dep.version}`), ['private-name@1.2.3']);
      assert.equal(parsed[0].sourceType, 'unknown');
      assert.equal(parsed.unresolvedEntries, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
