import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchJSON } from '../src/core/fetcher.js';
import { MAX_JSON_RESPONSE_BYTES } from '../src/core/constants.js';

function response({ status = 200, text = '{}', headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get(name) { return headers[String(name).toLowerCase()] ?? null; } },
    async text() { return text; },
  };
}

describe('bounded JSON fetcher', () => {
  it('keeps the timeout active while consuming the response body', async () => {
    const original = global.fetch;
    global.fetch = async (_url, { signal }) => ({
      ok: true,
      status: 200,
      headers: { get() { return null; } },
      body: {
        async *[Symbol.asyncIterator]() {
          await new Promise((resolve, reject) => {
            const timer = setTimeout(resolve, 100);
            signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('aborted')); }, { once: true });
          });
          yield Buffer.from('{}');
        },
      },
    });
    try {
      await assert.rejects(fetchJSON('https://example.invalid/slow', { timeout: 10, retries: 1 }), /aborted|invalid JSON/i);
    } finally {
      global.fetch = original;
    }
  });

  it('rejects oversized JSON bodies before parsing them', async () => {
    const original = global.fetch;
    global.fetch = async () => response({ text: 'x'.repeat(MAX_JSON_RESPONSE_BYTES + 1) });
    try {
      await assert.rejects(fetchJSON('https://example.invalid/large', { retries: 1 }), /exceeded/);
    } finally {
      global.fetch = original;
    }
  });

  it('honors Retry-After while retrying a rate limit', async () => {
    const original = global.fetch;
    let calls = 0;
    global.fetch = async () => {
      calls++;
      return calls === 1
        ? response({ status: 429, text: 'slow down', headers: { 'retry-after': '0' } })
        : response({ text: '{"ok":true}' });
    };
    try {
      assert.deepEqual(await fetchJSON('https://example.invalid/retry', { retries: 2, backoff: 1000 }), { ok: true });
      assert.equal(calls, 2);
    } finally {
      global.fetch = original;
    }
  });
});
