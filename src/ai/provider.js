/**
 * Pluggable, local-first LLM provider for AI-assisted triage.
 *
 * Supersedes claude.js as the client `explain` uses, while keeping it intact
 * (its tests import `complete`/`hasApiKey` directly — we re-export below so
 * nothing breaks).
 *
 * Selection order (first match wins):
 *   1. VEXES_AI_BASE set            → OpenAI-compatible endpoint (can be local:
 *                                     Spark / Ollama / vLLM / LM Studio...).
 *   2. ANTHROPIC_BASE_URL set       → Anthropic-compatible cluster (vLLM native
 *                                     Messages API, model auto-discovered).
 *   3. ANTHROPIC_API_KEY set        → Anthropic Messages API (hosted claude.js).
 *   4. neither                      → degrade with NO_PROVIDER — no model call.
 *                                     AI is opt-in independently of the OSV and
 *                                     registry requests made by scanner commands.
 *
 * Nothing is ever sent to a provider except the extracted findings payload we
 * build — never raw downloaded package source, never advisory HTML. Callers
 * that need package code for "reachability" reasoning send only a spec-derived
 * summary (see `buildReachabilityPrompt`).
 *
 * @module ai/provider
 */

import { hasApiKey as _anthropicHasKey, complete as anthropicComplete } from './claude.js';
import { log } from '../core/logger.js';

export const PROVIDERS = {
  OPENAI_COMPAT: 'openai-compat',
  ANTHROPIC: 'anthropic',
};

const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TIMEOUT_MS = 60000;

/** Provider is keyed on env only — free of side effects and fetch. */
export function detectProvider() {
  if (typeof process.env.VEXES_AI_BASE === 'string' && process.env.VEXES_AI_BASE.trim() !== '') {
    return PROVIDERS.OPENAI_COMPAT;
  }
  if (typeof process.env.ANTHROPIC_BASE_URL === 'string' && process.env.ANTHROPIC_BASE_URL.trim() !== '') {
    return PROVIDERS.ANTHROPIC;
  }
  if (typeof process.env.ANTHROPIC_API_KEY === 'string' && process.env.ANTHROPIC_API_KEY.length > 0) {
    return PROVIDERS.ANTHROPIC;
  }
  return null;
}

/** True when at least one AI provider is configured. */
export function hasProvider() {
  return detectProvider() !== null;
}

// Re-export for old callers/tests (explain historically used these names);
// they now resolve through the router in complete().
export { hasApiKey } from './claude.js';
export { complete as claudeComplete } from './claude.js';
export { resolveAnthropicModel, __resetModelDiscovery } from './claude.js';

/**
 * OpenAI-compatible chat completions client.
 *
 * @param {object} opts
 * @param {string} opts.system
 * @param {string} opts.user
 * @param {number} [opts.maxTokens]
 * @param {number} [opts.timeoutMs]
 * @param {typeof fetch} [opts.fetchImpl] — injectable for tests
 * @returns {Promise<string>}
 * @throws {Error} with `.code`: NO_BASE_URL | TIMEOUT | API_ERROR | EMPTY_RESPONSE
 */
export async function completeOpenAI({ system, user, maxTokens, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl } = {}) {
  const base = process.env.VEXES_AI_BASE;
  if (!base) {
    const err = new Error('VEXES_AI_BASE is not set');
    err.code = 'NO_BASE_URL';
    throw err;
  }

  const model = process.env.VEXES_AI_MODEL || 'local';
  const key = process.env.VEXES_AI_KEY || '';
  const url = `${base.replace(/\/+$/, '')}/v1/chat/completions`;
  const doFetch = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const headers = { 'content-type': 'application/json' };
  if (key) headers.authorization = `Bearer ${key}`;

  let res;
  try {
    res = await doFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model,
        max_tokens: maxTokens || DEFAULT_MAX_TOKENS,
        messages: [
          ...(system ? [{ role: 'system', content: system }] : []),
          { role: 'user', content: user },
        ],
        stream: false,
      }),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') {
      const e = new Error(`AI request timed out after ${timeoutMs}ms`);
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
    const err = new Error(`AI endpoint returned ${res.status}${detail}`);
    err.code = 'API_ERROR';
    err.status = res.status;
    throw err;
  }

  const data = await res.json();
  const text = Array.isArray(data?.choices)
    ? data.choices.map(c => c?.message?.content ?? '').join('').trim()
    : '';

  if (!text) {
    const err = new Error('AI endpoint returned an empty response');
    err.code = 'EMPTY_RESPONSE';
    throw err;
  }

  return text;
}

/**
 * Route a single-turn completion to whatever provider is configured.
 * Keeps the claude.js call signature so existing callers need no change.
 */
export async function complete(opts = {}) {
  const provider = opts.provider || detectProvider();
  if (provider === PROVIDERS.OPENAI_COMPAT) return completeOpenAI(opts);
  if (provider === PROVIDERS.ANTHROPIC) return anthropicComplete(opts);
  const err = new Error('No AI provider configured (set VEXES_AI_BASE, or ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN, or ANTHROPIC_API_KEY)');
  err.code = 'NO_PROVIDER';
  throw err;
}

/**
 * Whether embedding model names is useful depends on the caller — helpers the
 * commands use:
 */

/** Human label for the active provider (for status output). */
export function providerLabel() {
  const p = detectProvider();
  if (p === PROVIDERS.OPENAI_COMPAT) return `local/OpenAI-compatible (${process.env.VEXES_AI_MODEL || 'model'})`;
  if (p === PROVIDERS.ANTHROPIC) {
    if (process.env.ANTHROPIC_BASE_URL) {
      // Cluster case: env-only, no network. Host shown so agents can tell where
      // AI ran (local cluster vs hosted).
      let host = 'cluster';
      try { host = new URL(process.env.ANTHROPIC_BASE_URL).host; } catch { /* malformed base — keep fallback */ }
      return `Anthropic-compatible (${host} · ${process.env.VEXES_AI_MODEL || process.env.ANTHROPIC_MODEL || 'model'})`;
    }
    return `Anthropic (${process.env.VEXES_AI_MODEL || 'claude'})`;
  }
  return 'none configured';
}

/**
 * Build a prompt input for Tier B import-context reasoning.
 * Only accepts OUR extracted package spec + advisory summaries — a caller
 * passing in raw package source would violate the privacy boundary, so this
 * is the single entry point for that flow.
 */
export function buildReachabilityPrompt({ graph, advisory }) {
  const rows = Array.isArray(graph?.imports) ? graph.imports.join(', ') : '(no import data)';
  const safeSummary = String(advisory?.summary || '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 200);
  return {
    user: [
      'Limited import-context question for a dependency security scanner.',
      `Package: ${advisory?.package ?? '?'} ${advisory?.version ?? ''} (${advisory?.ecosystem ?? '?'})`,
      `Advisory summary: ${safeSummary}`,
      `Selected project direct-import evidence (not vulnerable-path evidence): ${rows}`,
      'Classify this limited context as reachable|plausible|unclear in one line, then one short reason. Do not claim exploitation, runtime reachability, or safety.',
    ].join('\n'),
  };
}

// Silence an unused import lint if loggerless builds strip it; keep log for
// diagnostics when a provider silently fails over.
if (process.env.VEXES_AI_DEBUG) log.debug('ai/provider: provider module loaded');
