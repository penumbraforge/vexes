import { FETCH_TIMEOUT_MS, FETCH_RETRIES, FETCH_BACKOFF_MS, USER_AGENT } from './constants.js';
import { log } from './logger.js';

// Only retry on server errors and rate limits — not client errors
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

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

      clearTimeout(timer);

      if (!res.ok) {
        const text = await res.text().catch(() => '');
        const err = new Error(`HTTP ${res.status} from ${url}: ${text.slice(0, 200)}`);
        err.status = res.status;

        // Only retry on retryable status codes
        if (!RETRYABLE_STATUS.has(res.status)) throw err;

        lastError = err;
        if (attempt < retries - 1) {
          const delay = backoff * Math.pow(2, attempt);
          log.debug(`fetch retry ${attempt + 1}/${retries} for ${url} (${res.status}) in ${delay}ms`);
          await new Promise(r => setTimeout(r, delay));
        }
        continue;
      }

      try {
        return await res.json();
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
