import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../src/cli/parse-args.js';

describe('Argument parser', () => {
  it('defaults to help command', () => {
    const r = parseArgs([]);
    assert.equal(r.command, 'help');
  });

  it('parses scan command', () => {
    const r = parseArgs(['scan']);
    assert.equal(r.command, 'scan');
  });

  it('parses analyze command', () => {
    const r = parseArgs(['analyze']);
    assert.equal(r.command, 'analyze');
  });

  it('parses --path flag with value', () => {
    const r = parseArgs(['scan', '--path', '/tmp/project']);
    assert.equal(r.flags.path, '/tmp/project');
  });

  it('parses --severity flag', () => {
    const r = parseArgs(['scan', '--severity', 'critical']);
    assert.equal(r.flags.severity, 'critical');
  });

  it('parses boolean flags', () => {
    const r = parseArgs(['scan', '--json', '--verbose', '--cached']);
    assert.equal(r.flags.json, true);
    assert.equal(r.flags.verbose, true);
    assert.equal(r.flags.cached, true);
  });

  it('parses --no- boolean negation', () => {
    const r = parseArgs(['scan', '--no-color']);
    assert.equal(r.flags.color, false);
  });

  it('does NOT allow --no- on value flags', () => {
    const r = parseArgs(['scan', '--no-severity']);
    // --no-severity should be ignored for value flags
    assert.ok(!('severity' in r.flags) || r.flags.severity !== false);
  });

  it('parses short flags -v -q -j', () => {
    const r = parseArgs(['scan', '-v']);
    assert.equal(r.flags.verbose, true);
  });

  it('handles --help flag in any position', () => {
    const r = parseArgs(['scan', '--help']);
    assert.equal(r.flags.help, true);
  });

  it('handles --version flag', () => {
    const r = parseArgs(['--version']);
    assert.equal(r.command, 'version');
  });

  it('handles -- separator', () => {
    const r = parseArgs(['scan', '--', 'extra', 'args']);
    assert.deepEqual(r.args, ['extra', 'args']);
  });

  it('collects positional args', () => {
    const r = parseArgs(['scan', 'file1.js', 'file2.js']);
    assert.deepEqual(r.args, ['file1.js', 'file2.js']);
  });

  it('case-insensitive commands', () => {
    const r = parseArgs(['SCAN']);
    assert.equal(r.command, 'scan');
  });
});
