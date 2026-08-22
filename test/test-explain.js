import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { complete, hasApiKey } from '../src/ai/claude.js';

/**
 * AI TRIAGE (vexes explain)
 *
 * The Claude client is exercised with an injected fetch — no network, no key
 * required for the request-shaping tests. hasApiKey() gates the feature.
 */

function mockFetch(responseBody, { ok = true, status = 200 } = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return {
      ok,
      status,
      async json() { return responseBody; },
      async text() { return JSON.stringify(responseBody); },
    };
  };
  fn.calls = calls;
  return fn;
}

// Mitigate cross-test/env leakage from the claude-cluster trio: these tests
// exercise the HOSTED (api.anthropic.com) path, so ANTHROPIC_BASE_URL /
// ANTHROPIC_AUTH_TOKEN / ANTHROPIC_MODEL must be cleared no matter what the
// shell exports (the user's cluster config lives in ~/.zshrc).
const TRIO = ['ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_MODEL'];
const scrubTrio = () => TRIO.map((k) => [k, process.env[k]]);
const withKey = async (fn) => {
  const prev = process.env.ANTHROPIC_API_KEY;
  const trio = scrubTrio();
  TRIO.forEach((k) => { if (process.env[k] !== undefined) delete process.env[k]; });
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  try { return await fn(); }
  finally {
    if (prev === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prev;
    restoreTrio(trio);
  }
};

const withoutKey = async (fn) => {
  const prev = process.env.ANTHROPIC_API_KEY;
  const trio = scrubTrio();
  TRIO.forEach((k) => { if (process.env[k] !== undefined) delete process.env[k]; });
  delete process.env.ANTHROPIC_API_KEY;
  try { return await fn(); }
  finally {
    if (prev !== undefined) process.env.ANTHROPIC_API_KEY = prev;
    restoreTrio(trio);
  }
};

function restoreTrio(saved) {
  for (const [k, v] of saved) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

describe('claude client: key gating', () => {
  it('hasApiKey reflects the env var', async () => {
    await withKey(() => assert.equal(hasApiKey(), true));
    await withoutKey(() => assert.equal(hasApiKey(), false));
  });

  it('complete throws NO_API_KEY when the key is absent', async () => {
    await withoutKey(async () => {
      await assert.rejects(
        () => complete({ system: 's', user: 'u', fetchImpl: mockFetch({}) }),
        (err) => err.code === 'NO_API_KEY'
      );
    });
  });
});

describe('claude client: request shaping', () => {
  it('sends model, system, and user with the right headers', async () => {
    await withKey(async () => {
      const fetch = mockFetch({ content: [{ type: 'text', text: 'triage output' }] });
      const text = await complete({ system: 'SYS', user: 'USER', model: 'claude-sonnet-5', fetchImpl: fetch });

      assert.equal(text, 'triage output');
      assert.equal(fetch.calls.length, 1);
      const { url, opts } = fetch.calls[0];
      assert.equal(url, 'https://api.anthropic.com/v1/messages');
      assert.equal(opts.headers['x-api-key'], 'sk-ant-test');
      assert.equal(opts.headers['anthropic-version'], '2023-06-01');
      const body = JSON.parse(opts.body);
      assert.equal(body.model, 'claude-sonnet-5');
      assert.equal(body.system, 'SYS');
      assert.deepEqual(body.messages, [{ role: 'user', content: 'USER' }]);
    });
  });

  it('concatenates multiple text blocks and trims', async () => {
    await withKey(async () => {
      const fetch = mockFetch({ content: [{ type: 'text', text: '  part1 ' }, { type: 'text', text: 'part2  ' }] });
      const text = await complete({ system: 's', user: 'u', fetchImpl: fetch });
      assert.equal(text, 'part1 part2');
    });
  });

  it('surfaces API errors with status', async () => {
    await withKey(async () => {
      const fetch = mockFetch({ error: { message: 'overloaded' } }, { ok: false, status: 529 });
      await assert.rejects(
        () => complete({ system: 's', user: 'u', fetchImpl: fetch }),
        (err) => err.code === 'API_ERROR' && err.status === 529 && /overloaded/.test(err.message)
      );
    });
  });

  it('rejects an empty completion', async () => {
    await withKey(async () => {
      const fetch = mockFetch({ content: [] });
      await assert.rejects(
        () => complete({ system: 's', user: 'u', fetchImpl: fetch }),
        (err) => err.code === 'EMPTY_RESPONSE'
      );
    });
  });

  it('respects VEXES_AI_MODEL override', async () => {
    await withKey(async () => {
      const prev = process.env.VEXES_AI_MODEL;
      process.env.VEXES_AI_MODEL = 'claude-opus-5';
      try {
        const fetch = mockFetch({ content: [{ type: 'text', text: 'x' }] });
        await complete({ system: 's', user: 'u', fetchImpl: fetch });
        assert.equal(JSON.parse(fetch.calls[0].opts.body).model, 'claude-opus-5');
      } finally {
        if (prev === undefined) delete process.env.VEXES_AI_MODEL;
        else process.env.VEXES_AI_MODEL = prev;
      }
    });
  });
});
