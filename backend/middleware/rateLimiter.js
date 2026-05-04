/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Redis-Backed Rate Limiter (SEC-003 Fix)
 *  backend/middleware/rateLimiter.js
 *
 *  Implements per-user, per-tenant, and per-IP sliding-window rate
 *  limiting using Redis. Falls back to in-memory if Redis unavailable.
 *
 *  Audit finding: SEC-003 — No Rate Limiting on LLM/Enrichment endpoints
 *  OWASP: A04:2021 Insecure Design
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const rateLimit = require('express-rate-limit');

// ── Redis store (optional — graceful fallback to memory) ──────────
let RedisStore;
let redisClient;

async function initRedis() {
  try {
    const { createClient } = require('redis');
    const { RedisStore: RS } = require('rate-limit-redis');
    RedisStore = RS;
    redisClient = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
    redisClient.on('error', (err) => console.warn('[RateLimit] Redis error:', err.message));
    await redisClient.connect();
    console.log('[RateLimit] Redis connected — using persistent rate-limit store');
    return true;
  } catch (err) {
    console.warn('[RateLimit] Redis unavailable — using in-memory store:', err.message);
    return false;
  }
}

// Initialize Redis asynchronously (non-blocking startup)
const redisReady = initRedis();

// ── Key generators ────────────────────────────────────────────────

/** Per-user key: combines user ID + IP for multi-layer protection */
function userKey(req) {
  const userId = req.user?.id || 'anon';
  const ip     = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  return `rl:user:${userId}:${ip}`;
}

/** Per-tenant key: limits total tenant API spend */
function tenantKey(req) {
  const tenantId = req.user?.tenant_id || req.tenantId || 'default';
  return `rl:tenant:${tenantId}`;
}

/** Per-IP key: protects unauthenticated endpoints */
function ipKey(req) {
  return `rl:ip:${req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown'}`;
}

// ── Store factory ─────────────────────────────────────────────────
function makeStore(prefix) {
  if (RedisStore && redisClient?.isReady) {
    return new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args), prefix });
  }
  return undefined; // express-rate-limit uses memory store as fallback
}

// ── Rate limit configurations ─────────────────────────────────────

/**
 * llmRateLimit — very strict limits for LLM/AI endpoints
 * Prevents API credit exhaustion from compromised accounts.
 * 20 requests per minute per user.
 */
const llmRateLimit = rateLimit({
  windowMs:         60 * 1000,        // 1 minute window
  max:              20,               // 20 LLM calls/min per user
  keyGenerator:     userKey,
  store:            makeStore('rl:llm:'),
  standardHeaders:  true,
  legacyHeaders:    false,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    console.warn(`[RateLimit] LLM limit exceeded — user=${req.user?.id} ip=${req.ip}`);
    res.status(429).json({
      error:      'LLM rate limit exceeded. Maximum 20 requests per minute.',
      code:       'RATE_LIMIT_LLM',
      retryAfter: Math.ceil(req.rateLimit?.resetTime / 1000) || 60,
      limit:      20,
      windowMs:   60000,
    });
  },
});

/**
 * enrichmentRateLimit — limits for enrichment proxy endpoints (VT, Shodan, etc.)
 * 60 requests per minute per user.
 */
const enrichmentRateLimit = rateLimit({
  windowMs:     60 * 1000,
  max:          60,
  keyGenerator: userKey,
  store:        makeStore('rl:enrichment:'),
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    console.warn(`[RateLimit] Enrichment limit exceeded — user=${req.user?.id} ip=${req.ip}`);
    res.status(429).json({
      error:      'Enrichment API rate limit exceeded. Maximum 60 requests per minute.',
      code:       'RATE_LIMIT_ENRICHMENT',
      retryAfter: 60,
      limit:      60,
    });
  },
});

/**
 * tenantRateLimit — per-tenant daily quota (cross-user protection)
 * 1000 API calls per tenant per hour.
 */
const tenantRateLimit = rateLimit({
  windowMs:     60 * 60 * 1000,   // 1 hour
  max:          1000,
  keyGenerator: tenantKey,
  store:        makeStore('rl:tenant-hourly:'),
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    console.warn(`[RateLimit] Tenant hourly limit exceeded — tenant=${req.user?.tenant_id}`);
    res.status(429).json({
      error:      'Tenant API quota exceeded. Maximum 1000 requests per hour.',
      code:       'RATE_LIMIT_TENANT',
      retryAfter: 3600,
    });
  },
});

/**
 * authRateLimit — protects login/auth endpoints from brute force
 * 10 attempts per 15 minutes per IP.
 */
const authRateLimit = rateLimit({
  windowMs:     15 * 60 * 1000,   // 15 minutes
  max:          10,
  keyGenerator: ipKey,
  store:        makeStore('rl:auth:'),
  standardHeaders: true,
  legacyHeaders:   false,
  skipSuccessfulRequests: true,   // Only count failed requests
  handler: (req, res) => {
    console.warn(`[RateLimit] Auth brute-force detected — ip=${req.ip}`);
    res.status(429).json({
      error:      'Too many authentication attempts. Try again in 15 minutes.',
      code:       'RATE_LIMIT_AUTH',
      retryAfter: 900,
    });
  },
});

/**
 * globalApiRateLimit — blanket API protection
 * 500 requests per minute per user (catch-all).
 */
const globalApiRateLimit = rateLimit({
  windowMs:     60 * 1000,
  max:          500,
  keyGenerator: userKey,
  store:        makeStore('rl:global:'),
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({
      error:      'Global rate limit exceeded.',
      code:       'RATE_LIMIT_GLOBAL',
      retryAfter: 60,
    });
  },
});

/**
 * nvdRateLimit — NVD-specific rate limiting (NVD enforces 5 req/30s without key)
 */
const nvdRateLimit = rateLimit({
  windowMs:     30 * 1000,         // 30-second window (matches NVD)
  max:          process.env.NVD_API_KEY ? 45 : 4,  // Stay just under NVD limits
  keyGenerator: ipKey,
  store:        makeStore('rl:nvd:'),
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({
      error:      'NVD API rate limit reached. Retry after 30 seconds.',
      code:       'RATE_LIMIT_NVD',
      retryAfter: 30,
    });
  },
});

/**
 * circuitBreaker — simple per-service circuit breaker
 * Tracks failure counts and opens circuit after threshold.
 */
class CircuitBreaker {
  constructor(serviceName, { failureThreshold = 5, resetTimeoutMs = 60000 } = {}) {
    this.service   = serviceName;
    this.threshold = failureThreshold;
    this.resetMs   = resetTimeoutMs;
    this.failures  = 0;
    this.state     = 'CLOSED';   // CLOSED | OPEN | HALF_OPEN
    this.openedAt  = null;
  }

  /** Call before proxying to external service */
  async execute(fn) {
    if (this.state === 'OPEN') {
      const age = Date.now() - this.openedAt;
      if (age < this.resetMs) {
        throw Object.assign(new Error(`Circuit OPEN for ${this.service}`), { code: 'CIRCUIT_OPEN', retryAfter: Math.ceil((this.resetMs - age) / 1000) });
      }
      this.state = 'HALF_OPEN';
      console.log(`[CircuitBreaker] ${this.service} → HALF_OPEN (testing recovery)`);
    }

    try {
      const result = await fn();
      if (this.state === 'HALF_OPEN') {
        this.reset();
        console.log(`[CircuitBreaker] ${this.service} → CLOSED (recovered)`);
      }
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  recordFailure() {
    this.failures++;
    if (this.failures >= this.threshold) {
      this.state    = 'OPEN';
      this.openedAt = Date.now();
      console.error(`[CircuitBreaker] ${this.service} → OPEN after ${this.failures} failures`);
    }
  }

  reset() {
    this.failures  = 0;
    this.state     = 'CLOSED';
    this.openedAt  = null;
  }

  status() {
    return { service: this.service, state: this.state, failures: this.failures };
  }
}

// ── Circuit breakers per external service ─────────────────────────
const breakers = {
  virustotal:   new CircuitBreaker('VirusTotal',   { failureThreshold: 3, resetTimeoutMs: 120000 }),
  shodan:       new CircuitBreaker('Shodan',       { failureThreshold: 3, resetTimeoutMs: 120000 }),
  abuseipdb:    new CircuitBreaker('AbuseIPDB',    { failureThreshold: 3, resetTimeoutMs: 60000  }),
  otx:          new CircuitBreaker('OTX',          { failureThreshold: 3, resetTimeoutMs: 60000  }),
  openai:       new CircuitBreaker('OpenAI',       { failureThreshold: 5, resetTimeoutMs: 300000 }),
  claude:       new CircuitBreaker('Claude',       { failureThreshold: 5, resetTimeoutMs: 300000 }),
  nvd:          new CircuitBreaker('NVD',          { failureThreshold: 3, resetTimeoutMs: 60000  }),
};

module.exports = {
  llmRateLimit,
  enrichmentRateLimit,
  tenantRateLimit,
  authRateLimit,
  globalApiRateLimit,
  nvdRateLimit,
  CircuitBreaker,
  breakers,
  redisReady,
  getRedisClient: () => redisClient,
};
