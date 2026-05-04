/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Centralized Feed Authentication Manager v5.2
 *  backend/services/feed-auth.js
 *
 *  ROOT CAUSE of "HTTP 401 — Missing or invalid Authorization header":
 *  ──────────────────────────────────────────────────────────────────
 *  The 401 error originates from TWO distinct places:
 *
 *  1. FRONTEND → BACKEND 401:
 *     The frontend's "Sync" button calls POST /api/ingest/run or
 *     POST /api/collectors/sync without attaching the JWT token to
 *     the Authorization header. The token lookup was reading from
 *     'tp_access_token' but the auth system writes to 'wadjet_access_token'.
 *     Key mismatch → empty token → backend verifyToken() returns 401.
 *
 *  2. BACKEND → EXTERNAL FEED 401:
 *     Some external feeds (AbuseIPDB, OTX) require API keys as headers.
 *     The headers were being built correctly in code BUT the .env key
 *     names had inconsistent casing / were undefined at runtime, causing
 *     axios to send requests without auth headers → external API 401.
 *
 *  FIXES in this file:
 *  ───────────────────
 *  A. FeedAuthManager: centralized per-feed auth header builder
 *     - Validates key presence BEFORE the HTTP call
 *     - Returns structured error with clear message if key missing
 *     - Supports: Bearer, API-Key, X-OTX-API-KEY, Basic, No-Auth
 *
 *  B. feedFetch(): authenticated HTTP client for external feeds
 *     - Auto-injects correct headers per feed type
 *     - Retry logic (up to 3 attempts with exponential backoff)
 *     - Detailed error logging: HTTP status + response body
 *     - Returns { ok, data, error, authError } shape
 *
 *  C. validateFeedConfigs(): startup check — logs which feeds are
 *     misconfigured so operators know immediately on deploy.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const axios = require('axios');

// ── Feed authentication configurations ─────────────────────────────
// Each entry defines how to authenticate with a specific external feed.
// 'envKey' is the .env variable name; if null, no auth is required.
const FEED_AUTH_CONFIGS = {
  'AlienVault OTX': {
    authType:   'otx-api-key',            // X-OTX-API-KEY header
    envKey:     'OTX_API_KEY',
    required:   true,
    buildHeaders: (key) => ({
      'X-OTX-API-KEY': key,
      'Content-Type': 'application/json',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'AbuseIPDB': {
    authType:   'api-key',                // Key: <key> header
    envKey:     'ABUSEIPDB_API_KEY',
    required:   true,
    buildHeaders: (key) => ({
      'Key':          key,
      'Accept':       'application/json',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'VirusTotal': {
    authType:   'vt-api-key',             // x-apikey header
    envKey:     'VIRUSTOTAL_API_KEY',
    required:   false,                    // enrichment only, not ingestion
    buildHeaders: (key) => ({
      'x-apikey':     key,
      'Content-Type': 'application/json',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'Shodan': {
    authType:   'query-param',            // ?key=... (handled in URL)
    envKey:     'SHODAN_API_KEY',
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2',
    }),
    buildUrl: (baseUrl, key) => `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}key=${key}`,
  },

  'URLhaus': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'ThreatFox': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'Content-Type': 'application/json',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'MalwareBazaar': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent':   'wadjet-eye-ai/5.2',
    }),
  },

  'Feodo Tracker': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2',
    }),
  },

  'CISA KEV': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'Accept':     'application/json',
      'User-Agent': 'wadjet-eye-ai/5.2',
    }),
  },

  'PhishTank': {
    authType:   'optional-api-key',
    envKey:     'PHISHTANK_API_KEY',
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2 (security-research)',
      'Accept':     'application/json',
    }),
    buildUrl: (baseUrl, key) => key
      ? baseUrl.replace('/data/', `/data/${key}/`)
      : baseUrl,
  },

  'OpenPhish': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2',
    }),
  },

  'CIRCL MISP': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2',
      'Accept':     'application/json',
    }),
  },

  'Ransomware.live': {
    authType:   'no-auth',
    envKey:     null,
    required:   false,
    buildHeaders: () => ({
      'User-Agent': 'wadjet-eye-ai/5.2',
      'Accept':     'application/json',
    }),
  },
};

// ── FeedAuthManager class ─────────────────────────────────────────
class FeedAuthManager {
  /**
   * Get auth headers for a named feed.
   * @param {string} feedName - Must match a key in FEED_AUTH_CONFIGS
   * @returns {{ ok: boolean, headers: object, error?: string, missingKey?: string }}
   */
  static getHeaders(feedName) {
    const config = FEED_AUTH_CONFIGS[feedName];

    if (!config) {
      // Unknown feed — return generic headers, don't block
      console.warn(`[FeedAuth] Unknown feed '${feedName}' — using default headers`);
      return {
        ok: true,
        headers: { 'User-Agent': 'wadjet-eye-ai/5.2', 'Content-Type': 'application/json' },
      };
    }

    // No-auth feeds
    if (!config.envKey || config.authType === 'no-auth') {
      return { ok: true, headers: config.buildHeaders() };
    }

    // Optional API key feeds
    const key = process.env[config.envKey];
    if (!key) {
      if (config.authType === 'optional-api-key') {
        return { ok: true, headers: config.buildHeaders() };
      }
      if (config.required) {
        const msg = `Feed '${feedName}' requires API key: set ${config.envKey} in backend/.env`;
        console.error(`[FeedAuth] ✗ ${msg}`);
        return { ok: false, headers: {}, error: msg, missingKey: config.envKey };
      }
      // Not required — return base headers without key
      return { ok: true, headers: config.buildHeaders() };
    }

    return { ok: true, headers: config.buildHeaders(key) };
  }

  /**
   * Modify URL if the feed requires key in query string (e.g. Shodan).
   */
  static buildUrl(feedName, baseUrl) {
    const config = FEED_AUTH_CONFIGS[feedName];
    if (!config?.buildUrl) return baseUrl;

    const key = config.envKey ? process.env[config.envKey] : null;
    if (!key && config.authType !== 'optional-api-key') return baseUrl;

    return config.buildUrl(baseUrl, key);
  }

  /**
   * Check all required feeds have their keys set.
   * Call on server startup to give operators early warning.
   */
  static validateAll() {
    const issues = [];
    const ok     = [];

    for (const [name, config] of Object.entries(FEED_AUTH_CONFIGS)) {
      if (!config.envKey) {
        ok.push(`${name} (no auth required)`);
        continue;
      }
      const key = process.env[config.envKey];
      if (key) {
        ok.push(`${name} ✓ (${config.envKey} set)`);
      } else if (config.required) {
        issues.push({ feed: name, key: config.envKey, severity: 'ERROR' });
      } else {
        ok.push(`${name} ⚠ (${config.envKey} not set — optional)`);
      }
    }

    if (issues.length > 0) {
      console.error('[FeedAuth] ══ CONFIGURATION ISSUES ══════════════════');
      for (const issue of issues) {
        console.error(`[FeedAuth] ✗ ${issue.feed}: set ${issue.key} in backend/.env`);
      }
      console.error('[FeedAuth] ══════════════════════════════════════════');
    }

    console.log('[FeedAuth] Feed auth status:');
    for (const msg of ok) console.log(`[FeedAuth]   ${msg}`);

    return { ok: issues.length === 0, issues };
  }
}

// ── feedFetch: authenticated HTTP client with retry ───────────────
/**
 * Makes an authenticated HTTP request to an external feed endpoint.
 *
 * @param {string}  feedName  - Named feed (key in FEED_AUTH_CONFIGS)
 * @param {string}  url       - Full URL (will be modified for query-param auth)
 * @param {object}  options   - axios options (method, data, params, timeout, etc.)
 * @param {number}  maxRetries - Number of retry attempts (default 2)
 * @returns {{ ok, data, error, status, authError, attempts }}
 */
async function feedFetch(feedName, url, options = {}, maxRetries = 2) {
  // 1. Validate auth for this feed
  const auth = FeedAuthManager.getHeaders(feedName);

  if (!auth.ok) {
    return {
      ok:        false,
      data:      null,
      error:     auth.error,
      status:    null,
      authError: true,
      missingKey: auth.missingKey,
      attempts:  0,
    };
  }

  // 2. Build URL (handles query-param auth like Shodan)
  const finalUrl = FeedAuthManager.buildUrl(feedName, url);

  // 3. Merge headers
  const mergedHeaders = {
    ...auth.headers,
    ...(options.headers || {}),
  };

  // 4. Execute with retry + exponential backoff
  let lastError = null;
  let lastStatus = null;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      const response = await axios({
        method:   options.method || 'GET',
        url:      finalUrl,
        headers:  mergedHeaders,
        data:     options.data,
        params:   options.params,
        timeout:  options.timeout || 25000,
        maxContentLength: options.maxContentLength || 20 * 1024 * 1024,
        validateStatus: null, // Don't throw on HTTP error codes
      });

      // ── Handle HTTP error responses ──────────────────────────
      if (response.status === 401) {
        const errMsg = `[FeedAuth][${feedName}] HTTP 401 — Check API key: ${auth.headers ? 'headers sent' : 'no headers'}.`;
        console.error(errMsg, 'Response:', JSON.stringify(response.data).slice(0, 200));
        return {
          ok:        false,
          data:      response.data,
          error:     `Authentication failed (HTTP 401). Verify ${FEED_AUTH_CONFIGS[feedName]?.envKey || 'API key'} is correct.`,
          status:    401,
          authError: true,
          attempts:  attempt,
        };
      }

      if (response.status === 403) {
        console.error(`[FeedAuth][${feedName}] HTTP 403 — Permission denied.`);
        return {
          ok:     false,
          data:   response.data,
          error:  `Permission denied (HTTP 403). Check API key permissions.`,
          status: 403,
          authError: true,
          attempts: attempt,
        };
      }

      if (response.status === 429) {
        // Hard-cap the wait at 60 seconds regardless of what Retry-After says.
        // AbuseIPDB free tier can return Retry-After: 86400 (24 h) or even
        // ~20 000 s on the free blacklist endpoint.  Waiting that long would
        // pin the event loop and starve every other scheduler job.
        // Strategy: if the retry window exceeds our cap we bail out immediately
        // and let the scheduler pick it up on the next normal interval.
        const rawRetryAfter = parseInt(response.headers['retry-after'] || '60', 10);
        const MAX_WAIT_S    = 60; // never block the process for more than 60 s
        const waitS         = Math.min(rawRetryAfter, MAX_WAIT_S);

        console.warn(`[FeedAuth][${feedName}] HTTP 429 — Rate limited. Retry-After=${rawRetryAfter}s (capped at ${waitS}s). attempt=${attempt}`);

        // If the real retry-after exceeds our cap, bail out now — no point retrying
        if (rawRetryAfter > MAX_WAIT_S) {
          return {
            ok:     false,
            data:   response.data,
            error:  `Rate limited (HTTP 429). Retry-After=${rawRetryAfter}s exceeds cap — skipping until next scheduled run.`,
            status: 429,
            attempts: attempt,
          };
        }

        if (attempt <= maxRetries) {
          await sleep(waitS * 1000);
          continue;
        }
        return {
          ok:     false,
          data:   response.data,
          error:  `Rate limited (HTTP 429). Retry in ${rawRetryAfter}s.`,
          status: 429,
          attempts: attempt,
        };
      }

      if (response.status >= 500) {
        lastStatus = response.status;
        lastError  = `Server error (HTTP ${response.status})`;
        if (attempt <= maxRetries) {
          await sleep(attempt * 2000); // exponential backoff
          continue;
        }
      }

      if (response.status >= 200 && response.status < 300) {
        return { ok: true, data: response.data, status: response.status, attempts: attempt };
      }

      return {
        ok:     false,
        data:   response.data,
        error:  `HTTP ${response.status}: ${JSON.stringify(response.data).slice(0, 200)}`,
        status: response.status,
        attempts: attempt,
      };

    } catch (err) {
      lastError = err.message;
      if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
        console.warn(`[FeedAuth][${feedName}] Timeout on attempt ${attempt}`);
        if (attempt <= maxRetries) {
          await sleep(attempt * 1500);
          continue;
        }
      }
      if (attempt <= maxRetries) {
        await sleep(attempt * 1000);
        continue;
      }
    }
  }

  console.error(`[FeedAuth][${feedName}] All ${maxRetries + 1} attempts failed: ${lastError}`);
  return {
    ok:       false,
    data:     null,
    error:    lastError || 'Unknown error after retries',
    status:   lastStatus,
    attempts: maxRetries + 1,
  };
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Feed Config Status for API endpoint ──────────────────────────
function getFeedConfigStatus() {
  const status = {};
  for (const [name, config] of Object.entries(FEED_AUTH_CONFIGS)) {
    const hasKey = config.envKey ? !!process.env[config.envKey] : true;
    status[name] = {
      auth_type:   config.authType,
      requires_key: !!config.envKey,
      env_key_name: config.envKey || null,
      key_configured: hasKey,
      required:    config.required || false,
      ready:       !config.required || hasKey,
    };
  }
  return status;
}

module.exports = {
  FeedAuthManager,
  feedFetch,
  getFeedConfigStatus,
  FEED_AUTH_CONFIGS,
};
