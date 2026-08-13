import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { stripGuardBlock } from '../src/commands/guard.js';

const MARKER = '# --- vexes guard start ---';
const END = '# --- vexes guard end ---';

const WRAPPER = 'npm() { echo hi; }';
const PRELUDE = 'export PATH=$PATH:/usr/local/bin\nalias ll="ls -la"\n';
const EPILOGUE = '\nexport EDITOR=vim\n';

function rcWithBlock() {
  return `${PRELUDE}\n${MARKER}\n${WRAPPER}\n${END}\n${EPILOGUE}`;
}

describe('guard rc safety: stripGuardBlock', () => {
  it('happy path: removes the block and preserves surrounding content', () => {
    const content = rcWithBlock();
    const result = stripGuardBlock(content);
    assert.equal(result.status, 'ok');
    assert.ok(!result.cleaned.includes(MARKER), 'start marker must be gone');
    assert.ok(!result.cleaned.includes(END), 'end marker must be gone');
    assert.ok(!result.cleaned.includes(WRAPPER), 'wrapper body must be gone');
    // User's own lines survive.
    assert.ok(result.cleaned.includes('alias ll="ls -la"'));
    assert.ok(result.cleaned.includes('export EDITOR=vim'));
  });

  it('missing end marker: aborts as corrupt, never splices', () => {
    // The exact bug: endIdx === -1 → negative slice offset shreds the file.
    const content = `${PRELUDE}\n${MARKER}\n${WRAPPER}\n${EPILOGUE}`;
    const result = stripGuardBlock(content);
    assert.equal(result.status, 'corrupt');
    assert.ok(/end marker/.test(result.reason));
    assert.equal(result.cleaned, undefined, 'must not produce a spliced result');
  });

  it('inverted markers: aborts as corrupt', () => {
    const content = `${PRELUDE}\n${END}\nsome junk\n${MARKER}\n${EPILOGUE}`;
    const result = stripGuardBlock(content);
    assert.equal(result.status, 'corrupt');
    assert.ok(/inverted/.test(result.reason));
  });

  it('absent block: reports absent, makes no changes', () => {
    const content = `${PRELUDE}${EPILOGUE}`;
    const result = stripGuardBlock(content);
    assert.equal(result.status, 'absent');
  });

  it('no trailing newline after end marker: does not over-read', () => {
    const content = `${PRELUDE}\n${MARKER}\n${WRAPPER}\n${END}`;
    const result = stripGuardBlock(content);
    assert.equal(result.status, 'ok');
    assert.ok(result.cleaned.includes('alias ll="ls -la"'));
    assert.ok(!result.cleaned.includes(END));
  });
});
