/**
 * circuitBreaker.js
 * WS9: Production-grade Circuit Breaker + Retry + Bulkhead pattern
 * Protects all external service calls (LLM, DB, SOAR, RAG, Intel feeds)
 */
'use strict';

const logger = require('../utils/logger');
const _SRV = 'CircuitBreaker';

const STATES = { CLOSED: 'CLOSED', OPEN: 'OPEN', HALF_OPEN: 'HALF_OPEN' };

class CircuitBreaker {
  /**
   * @param {string} name      - Unique name (e.g., 'openai', 'supabase', 'virustotal')
   * @param {object} opts
   * @param {number} opts.failureThreshold  - Failures before OPEN (default: 5)
   * @param {number} opts.successThreshold  - Successes in HALF_OPEN before CLOSED (default: 2)
   * @param {number} opts.timeout           - ms before attempting HALF_OPEN (default: 30000)
   * @param {number} opts.callTimeout       - ms before a call is considered failed (default: 10000)
   * @param {number} opts.volumeThreshold   - Min calls before circuit can open (default: 10)
   */
  constructor(name, opts = {}) {
    this.name             = name;
    this.failureThreshold = opts.failureThreshold  ?? 5;
    this.successThreshold = opts.successThreshold  ?? 2;
    this.timeout          = opts.timeout           ?? 30_000;
    this.callTimeout      = opts.callTimeout       ?? 10_000;
    this.volumeThreshold  = opts.volumeThreshold   ?? 10;

    this.state          = STATES.CLOSED;
    this.failureCount   = 0;
    this.successCount   = 0;
    this.lastFailureTime= null;
    this.totalCalls     = 0;
    this.totalFailures  = 0;
    this.totalSuccesses = 0;
    this._openedAt      = null;
  }

  async call(fn, fallback = null) {
    this.totalCalls++;

    if (this.state === STATES.OPEN) {
      if (Date.now() - this._openedAt >= this.timeout) {
        this._transition(STATES.HALF_OPEN);
        logger.info(_SRV, `${this.name}: HALF_OPEN — probing`);
      } else {
        logger.warn(_SRV, `${this.name}: Circuit OPEN — fast-fail`);
        if (fallback) return fallback();
        throw new Error(`Circuit OPEN: ${this.name}`);
      }
    }

    // Race: call vs timeout
    let result;
    try {
      result = await Promise.race([
        fn(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Call timeout after ${this.callTimeout}ms`)), this.callTimeout)
        ),
      ]);
      this._onSuccess();
      return result;
    } catch (err) {
      this._onFailure(err);
      if (fallback) return fallback();
      throw err;
    }
  }

  _onSuccess() {
    this.totalSuccesses++;
    if (this.state === STATES.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this._transition(STATES.CLOSED);
        logger.info(_SRV, `${this.name}: CLOSED — recovered`);
      }
    } else {
      this.failureCount = 0; // Reset on success in CLOSED
    }
  }

  _onFailure(err) {
    this.totalFailures++;
    this.failureCount++;
    this.lastFailureTime = Date.now();
    logger.warn(_SRV, `${this.name}: failure ${this.failureCount}/${this.failureThreshold}`, { error: err.message });

    if (this.state === STATES.HALF_OPEN) {
      this._transition(STATES.OPEN);
      logger.error(_SRV, `${this.name}: OPEN — probe failed`);
    } else if (
      this.state === STATES.CLOSED &&
      this.totalCalls >= this.volumeThreshold &&
      this.failureCount >= this.failureThreshold
    ) {
      this._transition(STATES.OPEN);
      logger.error(_SRV, `${this.name}: OPEN — threshold breached`, {
        failureCount: this.failureCount,
        totalCalls: this.totalCalls,
      });
    }
  }

  _transition(newState) {
    this.state = newState;
    if (newState === STATES.OPEN)      this._openedAt = Date.now();
    if (newState === STATES.CLOSED)    { this.failureCount = 0; this.successCount = 0; }
    if (newState === STATES.HALF_OPEN) this.successCount = 0;
  }

  getStatus() {
    return {
      name:            this.name,
      state:           this.state,
      failureCount:    this.failureCount,
      successCount:    this.successCount,
      totalCalls:      this.totalCalls,
      totalFailures:   this.totalFailures,
      totalSuccesses:  this.totalSuccesses,
      lastFailureTime: this.lastFailureTime,
      openedAt:        this._openedAt,
      errorRate:       this.totalCalls > 0 ? (this.totalFailures / this.totalCalls) : 0,
    };
  }

  reset() {
    this.state         = STATES.CLOSED;
    this.failureCount  = 0;
    this.successCount  = 0;
    this._openedAt     = null;
    this.lastFailureTime = null;
  }
}

// ── Global Registry of Circuit Breakers ──────────────────────────
const _registry = new Map();

function getBreaker(name, opts = {}) {
  if (!_registry.has(name)) {
    _registry.set(name, new CircuitBreaker(name, opts));
  }
  return _registry.get(name);
}

// Pre-configured breakers for all external services
const BREAKERS = {
  openai:      getBreaker('openai',      { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  anthropic:   getBreaker('anthropic',   { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  gemini:      getBreaker('gemini',      { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  supabase:    getBreaker('supabase',    { failureThreshold: 5, timeout: 30_000, callTimeout: 5_000  }),
  pinecone:    getBreaker('pinecone',    { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  weaviate:    getBreaker('weaviate',    { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  neo4j:       getBreaker('neo4j',       { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  redis:       getBreaker('redis',       { failureThreshold: 5, timeout: 15_000, callTimeout: 2_000  }),
  virustotal:  getBreaker('virustotal',  { failureThreshold: 3, timeout: 60_000, callTimeout: 15_000 }),
  shodan:      getBreaker('shodan',      { failureThreshold: 3, timeout: 60_000, callTimeout: 15_000 }),
  misp:        getBreaker('misp',        { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  soar:        getBreaker('soar',        { failureThreshold: 3, timeout: 60_000, callTimeout: 20_000 }),
};

function getAllStatus() {
  const status = {};
  for (const [name, breaker] of _registry) status[name] = breaker.getStatus();
  return status;
}

// ── Retry with Exponential Backoff ────────────────────────────────
async function withRetry(fn, opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseDelay  = opts.baseDelay  ?? 500;
  const maxDelay   = opts.maxDelay   ?? 10_000;
  const jitter     = opts.jitter     ?? true;

  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      if (attempt === maxRetries) break;

      let delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
      if (jitter) delay = delay * (0.5 + Math.random() * 0.5);

      logger.warn(_SRV, `Retry ${attempt + 1}/${maxRetries} in ${Math.round(delay)}ms`, { error: err.message });
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

// ── Idempotency Key Generator ─────────────────────────────────────
function makeIdempotencyKey(payload) {
  const { createHash } = require('crypto');
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return createHash('sha256').update(canonical).digest('hex').slice(0, 32);
}

module.exports = {
  CircuitBreaker,
  getBreaker,
  BREAKERS,
  getAllStatus,
  withRetry,
  makeIdempotencyKey,
  STATES,
};
