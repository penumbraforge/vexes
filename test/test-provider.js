import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectProvider, hasProvider, complete, completeOpenAI, providerLabel,
  PROVIDERS, buildReachabilityPrompt, __resetModelDiscovery,
} from '../src/ai/provider.js';

/**
 * PLUGGABLE AI PROVIDER (vexes explain)
 *
 * The provider module is exercised with an injected fetch — no network, no
 * provider required for shape/detection. Complete requests route to either
 * provider based on env; the scanner itself never calls out (deterministic,
 * offline core; this is an opt-in layer).
 */

function mockFetch(responseBody, { ok = true, status = 200 } = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return {
      ok, status,
      async json() { return responseBody; },
      async text() { return JSON.stringify(responseBody); },
    };
  };
  fn.calls = calls;
  return fn;
}

const envTrap = (() => {
  let saved;
  return {
    save() {
      saved = {
        VEXES_AI_BASE: process.env.VEXES_AI_BASE,
        VEXES_AI_MODEL: process.env.VEXES_AI_MODEL,
        VEXES_AI_KEY: process.env.VEXES_AI_KEY,
        ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
        ANTHROPIC_BASE_URL: process.env.ANTHROPIC_BASE_URL,
        ANTHROPIC_AUTH_TOKEN: process.env.ANTHROPIC_AUTH_TOKEN,
        ANTHROPIC_MODEL: process.env.ANTHROPIC_MODEL,
      };
      delete process.env.VEXES_AI_BASE;
      delete process.env.VEXES_AI_MODEL;
      delete process.env.VEXES_AI_KEY;
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.ANTHROPIC_BASE_URL;
      delete process.env.ANTHROPIC_AUTH_TOKEN;
      delete process.env.ANTHROPIC_MODEL;
    },
    restore() {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    },
  };
})();

/** Answering stub for an Anthropic-compatible cluster (name => vLLM body). */
function clusterStub({ message = 'ok', messagesStatus = 200, modelsDown = false } = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url: String(url), opts });
    if (modelsDown && String(url).endsWith('/v1/models')) throw new Error('cluster unreachable');
    if (String(url).endsWith('/v1/models')) {
      return { ok: true, status: 200, async json() { return { data: [{ id: 'cluster-model-1' }] }; }, async text() { return ''; } };
    }
    if (messagesStatus !== 200) {
      return { ok: false, status: messagesStatus, async json() { return { error: { message: 'down' } }; }, async text() { return ''; } };
    }
    return { ok: true, status: 200, async json() { return { content: [{ type: 'text', text: message }] }; }, async text() { return ''; } };
  };
  fn.calls = calls;
  return fn;
}

describe('provider: detection', () => {
  beforeEach(() => envTrap.save());
  afterEach(() => envTrap.restore());

  it('returns null with no provider configured', () => {
    assert.equal(detectProvider(), null);
    assert.equal(hasProvider(), false);
  });

  it('prefers the local OpenAI-compatible endpoint when VEXES_AI_BASE is set', () => {
    process.env.VEXES_AI_BASE = 'http://localhost:11434';
    assert.equal(detectProvider(), PROVIDERS.OPENAI_COMPAT);
    assert.equal(hasProvider(), true);
  });

  it('falls back to Anthropic when only ANTHROPIC_API_KEY is set', () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
    assert.equal(detectProvider(), PROVIDERS.ANTHROPIC);
    assert.ok(providerLabel().startsWith('Anthropic'));
  });
});

describe('provider: complete routing', () => {
  beforeEach(() => envTrap.save());
  afterEach(() => envTrap.restore());

  it('throws NO_PROVIDER when nothing is configured', async () => {
    await assert.rejects(
      () => complete({ system: 's', user: 'u', fetchImpl: mockFetch({}) }),
      (err) => err.code === 'NO_PROVIDER'
    );
  });

  it('routes to Anthropic when only ANTHROPIC_API_KEY is set', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
    const fetch = mockFetch({ content: [{ type: 'text', text: 'hello' }] });
    const text = await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    assert.equal(text, 'hello');
    assert.equal(fetch.calls[0].url, 'https://api.anthropic.com/v1/messages');
  });

  it('routes to the OpenAI-compatible endpoint when VEXES_AI_BASE is set', async () => {
    process.env.VEXES_AI_BASE = 'http://localhost:11434';
    process.env.VEXES_AI_MODEL = 'qwen2.5-coder:7b';
    const fetch = mockFetch({ choices: [{ message: { content: 'triaged' } }] });
    const text = await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    assert.equal(text, 'triaged');
    const { url, opts } = fetch.calls[0];
    assert.equal(url, 'http://localhost:11434/v1/chat/completions');
    const body = JSON.parse(opts.body);
    assert.equal(body.model, 'qwen2.5-coder:7b');
    assert.equal(body.messages[0].role, 'system');
    assert.equal(body.messages[0].content, 'S');
    assert.equal(body.messages[1].role, 'user');
    assert.equal(body.messages[1].content, 'U');
    assert.equal(opts.headers.authorization, undefined, 'no key ⇒ no auth header');
  });
});

describe('provider: claude-cluster (ANTHROPIC_BASE_URL)', () => {
  beforeEach(() => { envTrap.save(); __resetModelDiscovery(); });
  afterEach(() => { __resetModelDiscovery(); envTrap.restore(); });

  it('detects the cluster from ANTHROPIC_BASE_URL alone (no key needed)', () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    assert.equal(detectProvider(), PROVIDERS.ANTHROPIC);
    assert.equal(hasProvider(), true);
  });

  it('keeps VEXES_AI_BASE as the explicit winner over a cluster', () => {
    process.env.VEXES_AI_BASE = 'http://local:11434';
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_API_KEY = 'sk-ant';
    assert.equal(detectProvider(), PROVIDERS.OPENAI_COMPAT);
  });

  it('providerLabel names the cluster host without network', () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_MODEL = 'deepseek';
    assert.match(providerLabel(), /Anthropic-compatible \(cluster\.test:8888 · deepseek\)/);
  });

  it('routes messages to the cluster with Bearer auth and no x-api-key', async () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888/'; // trailing slash stripped
    process.env.ANTHROPIC_AUTH_TOKEN = 'local';
    process.env.VEXES_AI_MODEL = 'cluster-model-1';
    const fetch = clusterStub();
    const text = await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    assert.equal(text, 'ok');
    assert.equal(fetch.calls.length, 1, 'model pinned ⇒ no discovery round trip');
    const { url, opts } = fetch.calls[0];
    assert.equal(url, 'http://cluster.test:8888/v1/messages');
    assert.equal(opts.headers.authorization, 'Bearer local');
    assert.equal(opts.headers['x-api-key'], undefined, 'cluster path sends no x-api-key');
    assert.equal(opts.headers['anthropic-version'], '2023-06-01');
    const body = JSON.parse(opts.body);
    assert.equal(body.model, 'cluster-model-1');
    assert.equal(body.system, 'S');
    assert.equal(body.messages[0].content, 'U');
  });

  it('honours ANTHROPIC_MODEL over discovery', async () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_AUTH_TOKEN = 'local';
    process.env.ANTHROPIC_MODEL = 'pinned-model';
    const fetch = clusterStub();
    await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    assert.equal(fetch.calls.length, 1, 'ANTHROPIC_MODEL pins ⇒ no discovery');
    assert.equal(JSON.parse(fetch.calls[0].opts.body).model, 'pinned-model');
  });

  it('auto-discovers the model from /v1/models and caches it across calls', async () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_AUTH_TOKEN = 'local';
    const fetch = clusterStub();
    await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    const models = fetch.calls.filter((c) => c.url.endsWith('/v1/models'));
    const messages = fetch.calls.filter((c) => c.url.endsWith('/v1/messages'));
    assert.equal(models.length, 1, 'discovery deduped across concurrent calls');
    assert.equal(messages.length, 2);
    for (const m of messages) assert.equal(JSON.parse(m.opts.body).model, 'cluster-model-1');
  });

  it('degrades to the default model when discovery fails — never throws', async () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_AUTH_TOKEN = 'local';
    const fetch = clusterStub({ modelsDown: true });
    const text = await complete({ system: 'S', user: 'U', fetchImpl: fetch });
    assert.equal(text, 'ok');
    const msg = fetch.calls.find((c) => c.url.endsWith('/v1/messages'));
    assert.ok(msg, 'messages still attempted after discovery failure');
    assert.equal(JSON.parse(msg.opts.body).model, 'claude-sonnet-5', 'discovery failure ⇒ DEFAULT_MODEL');
  });

  it('surfaces an API error with status from the cluster', async () => {
    process.env.ANTHROPIC_BASE_URL = 'http://cluster.test:8888';
    process.env.ANTHROPIC_AUTH_TOKEN = 'local';
    const fetch = clusterStub({ messagesStatus: 503 });
    await assert.rejects(
      () => complete({ system: 'S', user: 'U', fetchImpl: fetch }),
      (err) => err.code === 'API_ERROR' && err.status === 503 && /down/.test(err.message)
    );
  });
});

describe('provider: openai-compat client', () => {
  beforeEach(() => envTrap.save());
  afterEach(() => envTrap.restore());

  const withBase = (fn) => {
    process.env.VEXES_AI_BASE = 'http://localhost:11434';
    return fn();
  };

  it('requires VEXES_AI_BASE (NO_BASE_URL)', async () => {
    await assert.rejects(
      () => completeOpenAI({ system: 's', user: 'u', fetchImpl: mockFetch({}) }),
      (err) => err.code === 'NO_BASE_URL'
    );
  });

  it('sends key as Bearer when VEXES_AI_KEY is set', async () => {
    await withBase(async () => {
      process.env.VEXES_AI_KEY = 'sk-local';
      const fetch = mockFetch({ choices: [{ message: { content: 'x' } }] });
      await completeOpenAI({ system: 's', user: 'u', fetchImpl: fetch });
      assert.equal(fetch.calls[0].opts.headers.authorization, 'Bearer sk-local');
    });
  });

  it('adds system only when provided', async () => {
    await withBase(async () => {
      const fetch = mockFetch({ choices: [{ message: { content: 'y' } }] });
      await completeOpenAI({ user: 'U', fetchImpl: fetch });
      const body = JSON.parse(fetch.calls[0].opts.body);
      assert.equal(body.messages.length, 1);
      assert.equal(body.messages[0].role, 'user');
    });
  });

  it('surfaces API errors with status', async () => {
    await withBase(async () => {
      const fetch = mockFetch({ error: { message: 'down' } }, { ok: false, status: 503 });
      await assert.rejects(
        () => completeOpenAI({ system: 's', user: 'u', fetchImpl: fetch }),
        (err) => err.code === 'API_ERROR' && err.status === 503 && /down/.test(err.message)
      );
    });
  });

  it('rejects empty completions', async () => {
    await withBase(async () => {
      const fetch = mockFetch({ choices: [] });
      await assert.rejects(
        () => completeOpenAI({ system: 's', user: 'u', fetchImpl: fetch }),
        (err) => err.code === 'EMPTY_RESPONSE'
      );
    });
  });
});

describe('provider: reachability prompt builder', () => {
  it('builds a bounded, injection-safe prompt shape', () => {
    const p = buildReachabilityPrompt({
      graph: { imports: ['./src/index.js'] },
      advisory: { package: 'axios', version: '1.14.1', ecosystem: 'npm', summary: '*injected* \x1b[31mred\x1b[0m text' },
    });
    assert.ok(p.user.includes('axios'));
    assert.ok(!p.user.includes('\x1b['), 'no escape sequences reach the model');
  });
});
