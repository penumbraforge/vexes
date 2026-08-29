import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildUpgradeCommand, posixShellEscape } from '../src/core/upgrade-command.js';

describe('upgrade command safety', () => {
  it('builds validated commands with option boundaries', () => {
    assert.equal(buildUpgradeCommand('@scope/pkg', '1.2.3-beta.1', 'npm'),
      'npm install -- @scope/pkg@1.2.3-beta.1');
    assert.equal(buildUpgradeCommand('requests', '2.32.4', 'pypi'),
      'pip install -- requests==2.32.4');
    assert.equal(buildUpgradeCommand('serde_json', '1.0.1', 'cargo'),
      'cargo update --package serde_json --precise 1.0.1');
  });

  it('refuses option, shell, and control-character injection coordinates', () => {
    for (const bad of ['--help', 'pkg;touch /tmp/x', 'pkg\nnext', "pkg'quoted"]) {
      assert.equal(buildUpgradeCommand(bad, '1.0.0', 'npm'), null);
    }
    assert.equal(buildUpgradeCommand('safe', '1.0.0;whoami', 'npm'), null);
    assert.equal(buildUpgradeCommand('safe', '1.0.0', 'unknown'), null);
  });

  it('uses standard POSIX single-quote escaping for arbitrary display values', () => {
    assert.equal(posixShellEscape("a'b"), "'a'\\''b'");
  });
});
