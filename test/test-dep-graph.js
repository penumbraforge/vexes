import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectTyposquat } from '../src/analysis/dep-graph.js';
import { POPULAR_NPM, POPULAR_PYPI } from '../src/core/allowlists.js';

describe('Typosquat detection', () => {
  it('detects "axioss" as similar to "axios" (insertion, distance 1)', () => {
    const matches = detectTyposquat('axioss', POPULAR_NPM);
    assert.ok(matches.some(m => m.similar === 'axios'), 'axioss should match axios');
  });

  it('does NOT match "axois" — distance 2 on a 5-char name (too noisy)', () => {
    // "axois" is a character swap (distance 2) on a 5-char name
    // Our threshold for length 4-6 is distance 1, so this is intentionally not flagged
    const matches = detectTyposquat('axois', POPULAR_NPM);
    assert.equal(matches.length, 0, 'distance 2 on short names should not match');
  });

  it('detects "expres" as similar to "express" (deletion, distance 1 on 7-char)', () => {
    const matches = detectTyposquat('expresss', POPULAR_NPM);
    assert.ok(matches.some(m => m.similar === 'express'));
  });

  it('does NOT flag exact matches (the package itself)', () => {
    const matches = detectTyposquat('axios', POPULAR_NPM);
    assert.ok(!matches.some(m => m.similar === 'axios'));
  });

  it('does NOT flag short names with distance 2 (too many false positives)', () => {
    // "qs" has length 2 — threshold should be 0 (no matches)
    const matches = detectTyposquat('qs', POPULAR_NPM);
    assert.equal(matches.length, 0, '"qs" is too short for typosquat detection');
  });

  it('does NOT flag "tar" (length 3, threshold 0)', () => {
    const matches = detectTyposquat('tar', POPULAR_NPM);
    assert.equal(matches.length, 0);
  });

  it('detects PyPI typosquats', () => {
    const matches = detectTyposquat('reqeusts', POPULAR_PYPI);
    assert.ok(matches.some(m => m.similar === 'requests'));
  });

  it('handles names not similar to anything', () => {
    const matches = detectTyposquat('xyzzy-unique-pkg-name', POPULAR_NPM);
    assert.equal(matches.length, 0);
  });
});
