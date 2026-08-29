import { FETCH_TIMEOUT_MS, FETCH_RETRIES, FETCH_BACKOFF_MS, MAX_JSON_RESPONSE_BYTES, USER_AGENT } from './constants.js';
import { log } from './logger.js';

// Only retry on server errors and rate limits — not client errors
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

async function readBoundedText(res, controller, limit = MAX_JSON_RESPONSE_BYTES) {
  if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      const bytes = Buffer.from(chunk);
      total += bytes.length;
      if (total > limit) {
        controller.abort();
        throw new Error(`HTTP response exceeded ${limit} bytes`);
      }
      chunks.push(bytes);
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  const text = typeof res.text === 'function' ? await res.text() : JSON.stringify(await res.json());
  if (Buffer.byteLength(text) > limit) throw new Error(`HTTP response exceeded ${limit} bytes`);
  return text;
}

function retryDelay(res, fallback) {
  const raw = res?.headers?.get?.('retry-after');
  if (!raw) return fallback;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 60_000);
  const at = Date.parse(raw);
  if (Number.isFinite(at)) return Math.min(Math.max(0, at - Date.now()), 60_000);
  return fallback;
}

/**
 * Fetch JSON with timeout, retry, and user-agent.
 * All HTTP traffic in vexes flows through this single point.
 *
 * Only retries on 429 (rate limit) and 5xx (server error).
 * Client errors (400-499 except 429) fail immediately.
 */
export async function fetchJSON(url, opts = {}) {
  const {
    timeout = FETCH_TIMEOUT_MS,
    retries = FETCH_RETRIES,
    backoff = FETCH_BACKOFF_MS,
    method = 'GET',
    body = undefined,
    headers = {},
  } = opts;

  const reqHeaders = {
    'User-Agent': USER_AGENT,
    'Accept': 'application/json',
    ...headers,
  };

  if (body && !reqHeaders['Content-Type']) {
    reqHeaders['Content-Type'] = 'application/json';
  }

  let lastError;

  for (let attempt = 0; attempt < retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(url, {
        method,
        headers: reqHeaders,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await readBoundedText(res, controller).catch(() => '');
        const err = new Error(`HTTP ${res.status} from ${url}: ${text.slice(0, 200)}`);
        err.status = res.status;

        // Only retry on retryable status codes
        if (!RETRYABLE_STATUS.has(res.status)) throw err;

        lastError = err;
        clearTimeout(timer);
        if (attempt < retries - 1) {
          const delay = retryDelay(res, backoff * Math.pow(2, attempt));
          log.debug(`fetch retry ${attempt + 1}/${retries} for ${url} (${res.status}) in ${delay}ms`);
          await new Promise(r => setTimeout(r, delay));
        }
        continue;
      }

      try {
        const text = await readBoundedText(res, controller);
        const parsed = JSON.parse(text);
        clearTimeout(timer);
        return parsed;
      } catch (parseErr) {
        throw new Error(`invalid JSON response from ${url}: ${parseErr.message}`);
      }
    } catch (err) {
      clearTimeout(timer);

      // Non-retryable errors (client errors, JSON parse) — throw immediately
      if (err.status && !RETRYABLE_STATUS.has(err.status)) throw err;

      lastError = err;

      if (attempt < retries - 1) {
        const delay = backoff * Math.pow(2, attempt);
        log.debug(`fetch retry ${attempt + 1}/${retries} for ${url} in ${delay}ms: ${err.message}`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  throw lastError;
}
