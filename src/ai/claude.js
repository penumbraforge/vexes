/**
 * Claude Messages API client for AI-assisted triage.
 *
 * Zero dependencies — native fetch only. Supports two Anthropic-compatible
 * endpoints:
 *
 *  - hosted api.anthropic.com, gated on ANTHROPIC_API_KEY (x-api-key auth);
 *  - a local/self-hosted cluster (vLLM native Messages API, Ollama, ...) gated
 *    on ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN (Bearer auth). The model is
 *    auto-discovered from `GET $BASE/v1/models` (no ANTHROPIC_MODEL needed),
 *    mirroring the user's claude-cluster config.
 *
 * Gated entirely on env: with no key/token/base configured, vexes makes no AI
 * calls at all (the caller degrades to a pointer message). The scanner's core
 * is deterministic and offline; this is strictly an opt-in layer on top.
 *
 * @module ai/claude
 */

const DEFAULT_BASE = 'https://api.anthropic.com';
const ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_MODEL = 'claude-sonnet-5';
const DEFAULT_MAX_TOKENS = 2048;
const DISCOVERY_TIMEOUT_MS = 5000;

export function hasApiKey() {
  return typeof process.env.ANTHROPIC_API_KEY === 'string' && process.env.ANTHROPIC_API_KEY.length > 0;
}

/** Resolve the base URL (trailing slashes stripped), defaulting to hosted. */
function baseUrl() {
  const base = (process.env.ANTHROPIC_BASE_URL || '').trim().replace(/\/+$/, '');
  return base || DEFAULT_BASE;
}

let _modelDiscovery = null; // shared promise — dedupes concurrent discovers

/** Test hook: forget a cached model so the next resolve re-discovers. */
export function __resetModelDiscovery() {
  _modelDiscovery = null;
}

/**
 * Resolve which model to use. Precedence: caller-provided model, then
 * VEXES_AI_MODEL, then ANTHROPIC_MODEL, then live discovery against the
 * cluster's `GET /v1/models` (only when ANTHROPIC_BASE_URL is set), then
 * DEFAULT_MODEL. Cached in module state via a shared promise so concurrent
 * asks resolve at most one discover. Never throws: a dead/absent cluster
 * degrades to DEFAULT_MODEL, which the caller handles — the per-finding
 * 'error' path in exploitability.js never flips `complete`.
 *
 * @param {object} opts
 * @param {string} [opts.model]      — explicit override from the caller
 * @param {typeof fetch} [opts.fetchImpl] — injectable for tests
 * @returns {Promise<string>}
 */
export async function resolveAnthropicModel({ model, fetchImpl } = {}) {
  if (model) return model;
  if (process.env.VEXES_AI_MODEL) return process.env.VEXES_AI_MODEL;
  if (process.env.ANTHROPIC_MODEL) return process.env.ANTHROPIC_MODEL;
  if (!process.env.ANTHROPIC_BASE_URL) return DEFAULT_MODEL;
  _modelDiscovery ||= discoverModel({ fetchImpl }).catch(() => DEFAULT_MODEL);
  return _modelDiscovery;
}

async function discoverModel({ fetchImpl }) {
  const doFetch = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DISCOVERY_TIMEOUT_MS);
  try {
    const res = await doFetch(`${baseUrl()}/v1/models`, { signal: controller.signal });
    if (!res.ok) {
      const e = new Error(`Model discovery failed: HTTP ${res.status}`);
      e.code = 'API_ERROR';
      throw e;
    }
    const data = await res.json();
    const id = data?.data?.[0]?.id;
    if (!id) {
      const e = new Error('Model discovery returned no data[0].id');
      e.code = 'EMPTY_RESPONSE';
      throw e;
    }
    return id;
  } catch {
    return DEFAULT_MODEL; // never throw — a dead cluster degrades gracefully
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Send a single-turn message and return the assistant's text.
 *
 * @param {object} opts
 * @param {string} opts.system   — system prompt
 * @param {string} opts.user     — user message
 * @param {string} [opts.model]  — overrides VEXES_AI_MODEL / ANTHROPIC_MODEL / discovery
 * @param {number} [opts.maxTokens]
 * @param {number} [opts.timeoutMs]
 * @param {typeof fetch} [opts.fetchImpl] — injectable for tests
 * @returns {Promise<string>} the assistant's text content
 */
export async function complete({ system, user, model, maxTokens, timeoutMs = 60000, fetchImpl } = {}) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const authToken = process.env.ANTHROPIC_AUTH_TOKEN;
  if (!apiKey && !authToken) {
    const err = new Error('No Anthropic credentials configured (ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN)');
    err.code = 'NO_API_KEY';
    throw err;
  }

  const headers = {
    'content-type': 'application/json',
    'anthropic-version': ANTHROPIC_VERSION,
  };
  // Cluster Bearer token wins; hosted falls back to x-api-key (existing hosted
  // tests stay byte-identical, and the cluster path sends no x-api-key at all).
  if (authToken) headers.authorization = `Bearer ${authToken}`;
  else if (apiKey) headers['x-api-key'] = apiKey;

  const doFetch = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    const resolvedModel = await resolveAnthropicModel({ model, fetchImpl });
    res = await doFetch(`${baseUrl()}/v1/messages`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: resolvedModel,
        max_tokens: maxTokens || DEFAULT_MAX_TOKENS,
        system,
        messages: [{ role: 'user', content: user }],
      }),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') {
      const e = new Error(`Claude API request timed out after ${timeoutMs}ms`);
      e.code = 'TIMEOUT';
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.json();
      detail = body?.error?.message ? `: ${body.error.message}` : '';
    } catch { /* non-JSON error body */ }
    const err = new Error(`Claude API returned ${res.status}${detail}`);
    err.code = 'API_ERROR';
    err.status = res.status;
    throw err;
  }

  const data = await res.json();
  const text = (data.content || [])
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('')
    .trim();

  if (!text) {
    const err = new Error('Claude API returned an empty response');
    err.code = 'EMPTY_RESPONSE';
    throw err;
  }

  return text;
}
