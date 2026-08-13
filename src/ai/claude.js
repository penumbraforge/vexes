/**
 * Minimal Claude API client for AI-assisted triage.
 *
 * Zero dependencies — native fetch only. Gated entirely on ANTHROPIC_API_KEY:
 * with no key set, vexes makes no AI calls at all (the caller degrades to a
 * pointer message). The scanner's core is deterministic and offline; this is
 * strictly an opt-in layer on top.
 *
 * @module ai/claude
 */

const API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_MODEL = 'claude-sonnet-5';
const DEFAULT_MAX_TOKENS = 2048;

export function hasApiKey() {
  return typeof process.env.ANTHROPIC_API_KEY === 'string' && process.env.ANTHROPIC_API_KEY.length > 0;
}

/**
 * Send a single-turn message and return the assistant's text.
 *
 * @param {object} opts
 * @param {string} opts.system   — system prompt
 * @param {string} opts.user     — user message
 * @param {string} [opts.model]  — overrides VEXES_AI_MODEL / default
 * @param {number} [opts.maxTokens]
 * @param {number} [opts.timeoutMs]
 * @param {typeof fetch} [opts.fetchImpl] — injectable for tests
 * @returns {Promise<string>} the assistant's text content
 */
export async function complete({ system, user, model, maxTokens, timeoutMs = 60000, fetchImpl } = {}) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    const err = new Error('ANTHROPIC_API_KEY is not set');
    err.code = 'NO_API_KEY';
    throw err;
  }

  const doFetch = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await doFetch(API_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': ANTHROPIC_VERSION,
      },
      body: JSON.stringify({
        model: model || process.env.VEXES_AI_MODEL || DEFAULT_MODEL,
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
