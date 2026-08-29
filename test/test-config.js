import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/cli/config.js';

/**
 * CLI flag → config wiring. A flag parsed but never mapped into config is a
 * silent no-op — worse than an error, because the user believes it's enforced.
 * (Regression: `scan --top` parsed in parse-args but never landed in config.)
 */

const DIR = process.cwd();

describe('loadConfig: --top wiring', () => {
  it('maps a positive integer --top into config.top', () => {
    const config = loadConfig(DIR, { top: '5' });
    assert.equal(config.top, 5);
  });

  it('rejects non-numeric and non-positive values without crashing', () => {
    for (const bad of ['zero', '0', '-3', 'abc', '']) {
      const config = loadConfig(DIR, { top: bad });
      assert.equal(config.top, undefined, `--top "${bad}" must not set config.top`);
    }
  });

  it('leaves config.top unset when the flag is absent', () => {
    const config = loadConfig(DIR, {});
    assert.equal(config.top, undefined);
  });
});
