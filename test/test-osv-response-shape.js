import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { queryBatch, isQueryComplete } from '../src/advisories/osv.js';
import { OSV_BATCH_URL } from '../src/core/constants.js';

function jsonResponse(body) {
  return {
    ok: true,
    status: 200,
    async text() { return JSON.stringify(body); },
  };
}

async function withBatchResponse(body, action) {
  const originalFetch = global.fetch;
  global.fetch = async (url) => {
    assert.equal(url, OSV_BATCH_URL);
    return jsonResponse(body);
  };
  try {
    return await action();
  } finally {
    global.fetch = originalFetch;
  }
}

const PACKAGE = { name: 'shape-probe', version: '1.0.0', ecosystem: 'npm' };
const KEY = 'npm:shape-probe@1.0.0';

describe('OSV batch result row validation', () => {
  for (const [label, row, expectedReason] of [
    ['null row', null, /non-array object/],
    ['array row', [], /non-array object/],
    ['primitive row', 'clean', /non-array object/],
    ['null vulns', { vulns: null }, /vulns must be an array/],
    ['object vulns', { vulns: {} }, /vulns must be an array/],
    ['string vulns', { vulns: 'none' }, /vulns must be an array/],
    ['empty vulnerability object', { vulns: [{}] }, /nonempty string id/],
    ['numeric vulnerability id', { vulns: [{ id: 42 }] }, /nonempty string id/],
    ['mixed valid and malformed vulnerabilities', { vulns: [{ id: 'OSV-1' }, null] }, /nonempty string id/],
  ]) {
    it(`marks a ${label} incomplete instead of clean`, async () => {
      const result = await withBatchResponse({ results: [row] }, () => queryBatch([PACKAGE]));

      assert.equal(result.queriedCount, 0);
      assert.equal(result.failedCount, 1);
      assert.equal(result.checked.has(KEY), false);
      assert.equal(result.results.size, 0);
      assert.equal(result.failures.length, 1);
      assert.match(result.failures[0], expectedReason);
      assert.equal(isQueryComplete(result, 1), false);
    });
  }

  it('counts valid and malformed rows independently in a mixed batch', async () => {
    const packages = [
      PACKAGE,
      { name: 'bad-row', version: '2.0.0', ecosystem: 'npm' },
    ];
    const result = await withBatchResponse({ results: [{ vulns: [] }, { vulns: false }] },
      () => queryBatch(packages));

    assert.equal(result.queriedCount, 1);
    assert.equal(result.failedCount, 1);
    assert.deepEqual([...result.checked], [KEY]);
    assert.equal(isQueryComplete(result, 2), false);
  });

  it('accepts an object row with absent or empty-array vulns', async () => {
    for (const row of [{}, { vulns: [] }]) {
      const result = await withBatchResponse({ results: [row] }, () => queryBatch([PACKAGE]));
      assert.equal(result.queriedCount, 1);
      assert.equal(result.failedCount, 0);
      assert.deepEqual([...result.checked], [KEY]);
      assert.equal(result.failures.length, 0);
      assert.equal(isQueryComplete(result, 1), true);
    }
  });
});
