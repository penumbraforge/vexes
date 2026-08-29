import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * PACKED-ARTIFACT test — the repo is not the product; the tarball is.
 *
 * `vexes doctor` used to resolve its parser fixtures relative to the CURRENT
 * WORKING DIRECTORY, which only worked inside the repo (test/ fixtures are
 * cwd-relative there). This test packs the real npm artifact, installs it
 * into an unrelated temporary project, and exercises the actual CLI from
 * there — proving the shipped package is self-sufficient.
 */

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('packed artifact (npm pack + install + real CLI)', { timeout: 120_000 }, () => {
  it('ships a self-sufficient package: doctor passes from an unrelated cwd', () => {
    const packDir = mkdtempSync(join(tmpdir(), 'vexes-pack-'));
    const projDir = mkdtempSync(join(tmpdir(), 'vexes-installed-'));
    try {
      // 1. Pack the real artifact (respects the "files" allowlist).
      const pack = spawnSync('npm', ['pack', '--pack-destination', packDir], {
        cwd: ROOT, encoding: 'utf8', timeout: 60_000,
      });
      assert.equal(pack.status, 0, `npm pack failed: ${pack.stderr}`);
      const tarball = readdirSync(packDir).find(f => f.endsWith('.tgz'));
      assert.ok(tarball, 'npm pack produced no tarball');

      // 2. The vendored Acorn MIT notice must ship — its license requires it.
      const listing = spawnSync('tar', ['-tzf', join(packDir, tarball)], { encoding: 'utf8' });
      assert.equal(listing.status, 0);
      assert.ok(
        listing.stdout.split('\n').some(l => l.includes('src/vendor/LICENSE-acorn.txt')),
        'packed tarball must include the vendored Acorn license notice'
      );

      // 3. Install into an unrelated project (no scripts, no network needed:
      //    zero dependencies).
      writeFileSync(join(projDir, 'package.json'), JSON.stringify({ name: 'unrelated-project', version: '1.0.0' }));
      const install = spawnSync('npm', ['install', join(packDir, tarball)], {
        cwd: projDir, encoding: 'utf8', timeout: 60_000,
      });
      assert.equal(install.status, 0, `npm install failed: ${install.stderr}`);

      const pkgDir = join(projDir, 'node_modules', '@penumbraforge', 'vexes');
      assert.ok(existsSync(join(pkgDir, 'test', 'fixtures', 'package-lock-v3.json')),
        'installed package must carry the parser fixtures doctor depends on');
      assert.ok(existsSync(join(pkgDir, 'src', 'vendor', 'LICENSE-acorn.txt')),
        'installed package must carry the vendored Acorn license notice');

      // 4. Exercise the real CLI from the unrelated cwd. doctor's JSON
      //    contract: requiredOk must be true — parsers + cache all pass.
      const bin = join(pkgDir, 'bin', 'vexes.js');
      const run = spawnSync(process.execPath, [bin, 'doctor', '--json'], {
        cwd: projDir, encoding: 'utf8', timeout: 60_000,
      });
      assert.equal(run.status, 0, `doctor exited nonzero from installed package: ${run.stderr}`);
      const report = JSON.parse(run.stdout);
      assert.equal(report.requiredOk ?? report.extra?.requiredOk, true,
        `doctor from installed package must be fully ok: ${JSON.stringify(report.warnings || report)}`);
      const parserChecks = (report.checks || report.extra?.checks || []).filter(c => c.name.startsWith('parser '));
      assert.ok(parserChecks.length >= 10, 'doctor ran all parser checks');
      assert.ok(parserChecks.every(c => c.ok),
        `every parser check must pass from the installed package: ${JSON.stringify(parserChecks.filter(c => !c.ok))}`);
    } finally {
      rmSync(packDir, { recursive: true, force: true });
      rmSync(projDir, { recursive: true, force: true });
    }
  });
});
