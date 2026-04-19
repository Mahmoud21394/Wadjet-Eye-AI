/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Backend-Only Provider Adapter Layer (Phase 4)
 *  backend/services/adapters/provider-adapter.js
 *
 *  Wraps llm-provider.js MultiProvider with:
 *   - Quota tracking per tenant per day (in-memory + optional DB)
 *   - Retry with exponential back-off (up to MAX_RETRIES attempts)
 *   - Response caching for identical deterministic queries (TTL 5 min)
 *   - Circuit-breaker awareness (delegates to MultiProvider CB)
 *   - Provider selection logging with reason
 *   - No direct API key exposure — all keys from process.env
 *
 *  This module is BACKEND-ONLY. It must never be loaded in the browser.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');
const { createMultiProvider } = require('../llm-provider');

// ── Constants ─────────────────────────────────────────────────────
const MAX_RETRIES     = 3;
const RETRY_BASE_MS   = 500;
const CACHE_TTL_MS    = 5 * 60 * 1000;     // 5 minutes
const QUOTA_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_QUOTA   = parseInt(process.env.TENANT_DAILY_AI_QUOTA || '1000', 10);

// ── In-memory cache ───────────────────────────────────────────────
const _cache = new Map(); // hash → { data, expires }

function _cacheKey(messages, opts) {
  const raw = JSON.stringify({ messages, opts });
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

function _cacheGet(key) {
  const entry = _cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) { _cache.delete(key); return null; }
  return entry.data;
}

function _cacheSet(key, data) {
  _cache.set(key, { data, expires: Date.now() + CACHE_TTL_MS });
  // Evict old entries (basic LRU approximation — keep ≤ 500 entries)
  if (_cache.size > 500) {
    const oldest = _cache.keys().next().value;
    _cache.delete(oldest);
  }
}

// ── Per-tenant quota ──────────────────────────────────────────────
const _quotaMap = new Map(); // tenantId → { count, windowStart }

function _checkQuota(tenantId) {
  if (!tenantId || tenantId === 'mock' || tenantId === 'service') return true;

  const now = Date.now();
  const rec = _quotaMap.get(tenantId) || { count: 0, windowStart: now };

  // Reset window if expired
  if (now - rec.windowStart > QUOTA_WINDOW_MS) {
    rec.count       = 0;
    rec.windowStart = now;
  }

  if (rec.count >= DEFAULT_QUOTA) return false;

  rec.count++;
  _quotaMap.set(tenantId, rec);
  return true;
}

// ── Retry helper ──────────────────────────────────────────────────
async function _withRetry(fn, maxAttempts = MAX_RETRIES) {
  let lastErr;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      // Do not retry auth errors, quota errors, or validation errors
      const status = err.status || err.statusCode;
      if (status === 401 || status === 403 || status === 400 || status === 402) {
        throw err;
      }
      if (attempt < maxAttempts - 1) {
        const delay = RETRY_BASE_MS * Math.pow(2, attempt) * (0.8 + Math.random() * 0.4);
        console.log(`[ProviderAdapter] Retry ${attempt + 1}/${maxAttempts - 1} in ${Math.round(delay)}ms — ${err.message}`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }
  throw lastErr;
}

// ── Provider adapter singleton ────────────────────────────────────
let _providerInstance = null;

function _getProvider() {
  if (!_providerInstance) {
    _providerInstance = createMultiProvider({});
    console.log('[ProviderAdapter] MultiProvider initialised');
  }
  return _providerInstance;
}

// ── Main adapter API ──────────────────────────────────────────────

/**
 * chat(messages, tools, opts, context)
 *
 * @param {Array}  messages - Conversation messages
 * @param {Array}  tools    - Available tool definitions
 * @param {object} opts     - Provider options (temperature, max_tokens, etc.)
 * @param {object} context  - { tenantId, userId, sessionId, requestId }
 * @returns {Promise<object>} Provider response
 */
async function chat(messages, tools = [], opts = {}, context = {}) {
  const { tenantId = 'default', userId = '-', requestId = '-', useCache = false } = context;

  // Quota check
  if (!_checkQuota(tenantId)) {
    const err = new Error(`Daily AI quota exceeded for tenant ${tenantId} (limit: ${DEFAULT_QUOTA})`);
    err.status = 429;
    err.code   = 'QUOTA_EXCEEDED';
    throw err;
  }

  // Cache lookup (only for deterministic non-tool queries)
  const cacheKey = useCache ? _cacheKey(messages, opts) : null;
  if (cacheKey) {
    const cached = _cacheGet(cacheKey);
    if (cached) {
      console.log(`[ProviderAdapter] Cache HIT reqId=${requestId} tenant=${tenantId}`);
      return { ...cached, _cached: true };
    }
  }

  const t0 = Date.now();
  let result;

  try {
    result = await _withRetry(async (attempt) => {
      const provider = _getProvider();
      console.log(`[ProviderAdapter] chat attempt=${attempt + 1} reqId=${requestId} tenant=${tenantId} user=${userId}`);
      return provider.chat(messages, tools, opts);
    });
  } catch (err) {
    console.error(`[ProviderAdapter] chat FAILED reqId=${requestId} tenant=${tenantId}: ${err.message}`);
    throw err;
  }

  const latency = Date.now() - t0;
  console.log(`[ProviderAdapter] chat OK reqId=${requestId} provider=${result._provider || '?'} latency=${latency}ms degraded=${!!result._degraded}`);

  // Cache successful non-degraded results
  if (cacheKey && !result._degraded) {
    _cacheSet(cacheKey, result);
  }

  return result;
}

/**
 * chatStream(messages, tools, opts, context, onChunk)
 *
 * Streaming variant — calls onChunk for each token chunk.
 */
async function chatStream(messages, tools = [], opts = {}, context = {}, onChunk) {
  const { tenantId = 'default', userId = '-', requestId = '-' } = context;

  if (!_checkQuota(tenantId)) {
    const err = new Error(`Daily AI quota exceeded for tenant ${tenantId}`);
    err.status = 429;
    err.code   = 'QUOTA_EXCEEDED';
    throw err;
  }

  const t0     = Date.now();
  const result = await _withRetry(async (attempt) => {
    const provider = _getProvider();
    console.log(`[ProviderAdapter] stream attempt=${attempt + 1} reqId=${requestId} tenant=${tenantId}`);
    return provider.chatStream(messages, tools, opts, onChunk);
  });

  const latency = Date.now() - t0;
  console.log(`[ProviderAdapter] stream OK reqId=${requestId} provider=${result?._provider || '?'} latency=${latency}ms`);

  return result;
}

/**
 * getStatus()
 * Returns provider chain status for health/diagnostic endpoints.
 */
function getStatus() {
  try {
    return _getProvider().getStatus();
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * invalidateProvider()
 * Force re-initialization of the provider singleton (e.g., after env update).
 */
function invalidateProvider() {
  _providerInstance = null;
  console.log('[ProviderAdapter] Provider singleton invalidated — will reinitialize on next call');
}

/**
 * getCacheStats()
 * Returns cache metrics for observability.
 */
function getCacheStats() {
  return {
    size:    _cache.size,
    maxSize: 500,
  };
}

/**
 * getQuotaStats(tenantId)
 * Returns remaining quota for a tenant.
 */
function getQuotaStats(tenantId) {
  const rec = _quotaMap.get(tenantId);
  if (!rec) return { used: 0, limit: DEFAULT_QUOTA, remaining: DEFAULT_QUOTA };
  const now  = Date.now();
  if (now - rec.windowStart > QUOTA_WINDOW_MS) return { used: 0, limit: DEFAULT_QUOTA, remaining: DEFAULT_QUOTA };
  return {
    used:      rec.count,
    limit:     DEFAULT_QUOTA,
    remaining: DEFAULT_QUOTA - rec.count,
    resetsIn:  Math.max(0, QUOTA_WINDOW_MS - (now - rec.windowStart)),
  };
}

module.exports = {
  chat,
  chatStream,
  getStatus,
  invalidateProvider,
  getCacheStats,
  getQuotaStats,
};
