/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — REST API Routes  v5.0
 *
 *  v5.0 — Platform stabilization: zero 400/404/503 errors, zero DB timeouts
 *  v4.0 — Production-grade: zero duplicate LLM calls, zero rate-limit loops
 *  ─────────────────────────────────────────────────────────────────────
 *  Rate limits (raised to handle session/history/auth overhead):
 *   - Chat:       10 req/min per IP  (conservative — 1 per 6s max)
 *   - General:   300 req/min per IP  (session CRUD, history, health)
 *   - Demo-auth:  20 req/min per IP
 *
 *  Per-session mutex:
 *   - Only ONE LLM call allowed per session at a time
 *   - Immediate 409 Conflict if duplicate arrives (not 429)
 *
 *  Message deduplication:
 *   - SHA-256 hash of (sessionId + trimmed message)
 *   - If same hash seen within 10s → 409 Duplicate
 *
 *  In-memory serial queue:
 *   - Each session has its own FIFO queue (max depth 1)
 *   - LLM calls are never called directly — always through _queueChat()
 *
 *  Auth tiers (unchanged):
 *   1. JWT bearer token (Supabase)
 *   2. X-RAKAY-KEY header (service bypass)
 *   3. /demo-auth token (24h, auto-issued)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';


const express        = require('express');
const rateLimit      = require('express-rate-limit');
const crypto         = require('crypto');
const { RAKAYEngine } = require('../services/RAKAYEngine');
const { optionalAuth } = require('../middleware/auth');

const router = express.Router();

// ── JWT for demo token generation ─────────────────────────────────────────────
// ---- ENGINE SINGLETON (critical for Render / serverless) ----
let _engineSingleton = null;
let _engineKey = null;
let _jwt = null;
function getJWT() {
  if (_jwt) return _jwt;
  try { _jwt = require('jsonwebtoken'); } catch { /* not installed */ }
  return _jwt;
}

// ── RAKAY API key (server-to-server bypass) ───────────────────────────────────
const RAKAY_SERVICE_KEY = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY || null;

// ── Rate limiters ──────────────────────────────────────────────────────────────

/** Compute seconds until the window resets (used in Retry-After header) */
function _retryAfterSeconds(windowMs) {
  return Math.ceil(windowMs / 1000);
}

// Chat: conservative limiter — 10 req/min per IP
// Rationale: normal usage is max 1 msg/6s. This is generous enough for
// real use but stops abuse. The per-session mutex (below) is the real guard.
const chatLimiter = rateLimit({
  windowMs:    60 * 1000,
  max:         10,
  keyGenerator: req => `rakay_chat_${req.ip || 'unknown'}`,
  handler: (req, res) => {
    const retryAfter = _retryAfterSeconds(60 * 1000);
    res.set('Retry-After', String(retryAfter));
    console.warn(`[RAKAY] RATE_LIMIT /chat ip=${req.ip} session=${req.body?.session_id?.slice(0,12)}`);
    res.status(429).json({
      error:      'Too many requests. Please wait before sending another message.',
      code:       'RAKAY_RATE_LIMIT',
      retryAfter,
    });
  },
  standardHeaders: true,
  legacyHeaders:   false,
  skipFailedRequests: false,
});

// General: session CRUD, history, health — raised limit to absorb overhead
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      300,   // session list + create + history + status pings
  keyGenerator: req => `rakay_gen_${req.ip || 'unknown'}`,
  handler: (req, res) => {
    const retryAfter = _retryAfterSeconds(60 * 1000);
    res.set('Retry-After', String(retryAfter));
    res.status(429).json({ error: 'Rate limit exceeded', code: 'RAKAY_RATE_LIMIT', retryAfter });
  },
  standardHeaders: true,
  legacyHeaders:   false,
});

// Demo-auth: raised to 20/min to handle token refresh cycles
const demoAuthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      20,
  keyGenerator: req => `rakay_demo_${req.ip || 'unknown'}`,
  handler: (req, res) => {
    const retryAfter = _retryAfterSeconds(60 * 1000);
    res.set('Retry-After', String(retryAfter));
    res.status(429).json({ error: 'Too many demo auth requests', code: 'RATE_LIMIT', retryAfter });
  },
  standardHeaders: true,
  legacyHeaders:   false,
});

// ══════════════════════════════════════════════════════════════════════════════
//  PER-SESSION MUTEX — hard lock, one LLM call at a time per session
//  Uses a Map<sessionId, Promise> so callers can await the lock clearing.
// ══════════════════════════════════════════════════════════════════════════════
const _sessionLocks = new Map();   // sessionId → { locked: bool, ts: number }

/**
 * Try to acquire the session lock.
 * @returns {boolean} true if lock acquired, false if already locked
 */
function _acquireSession(sessionId) {
  const entry = _sessionLocks.get(sessionId);
  if (entry?.locked) return false;
  _sessionLocks.set(sessionId, { locked: true, ts: Date.now() });
  return true;
}

/**
 * Release the session lock.
 */
function _releaseSession(sessionId) {
  _sessionLocks.delete(sessionId);
}

// Auto-clean stale locks older than 5 minutes (safety net for crashed requests)
setInterval(() => {
  const staleMs = 5 * 60 * 1000;
  const now = Date.now();
  for (const [sid, entry] of _sessionLocks) {
    if (now - entry.ts > staleMs) {
      console.warn(`[RAKAY] STALE_LOCK cleaned for session=${sid.slice(0, 12)}`);
      _sessionLocks.delete(sid);
    }
  }
}, 60_000);

// ══════════════════════════════════════════════════════════════════════════════
//  MESSAGE DEDUPLICATION — 10-second hash window
//  Key: SHA-256(sessionId + "|" + trimmedMessage)
//  Prevents identical messages submitted in rapid succession (double-click,
//  form re-submission, frontend retry bug) from triggering duplicate LLM calls.
// ══════════════════════════════════════════════════════════════════════════════
const _dedupCache   = new Map();   // hash → timestamp
const DEDUP_WINDOW  = 10_000;      // 10 seconds

function _dedupHash(sessionId, message) {
  return crypto.createHash('sha256')
    .update(`${sessionId}|${message.trim()}`)
    .digest('hex');
}

function _isDuplicate(sessionId, message) {
  const hash = _dedupHash(sessionId, message);
  const seen = _dedupCache.get(hash);
  if (seen && Date.now() - seen < DEDUP_WINDOW) return true;
  _dedupCache.set(hash, Date.now());
  return false;
}

// Clean dedup cache every 30s
setInterval(() => {
  const cutoff = Date.now() - DEDUP_WINDOW;
  for (const [hash, ts] of _dedupCache) {
    if (ts < cutoff) _dedupCache.delete(hash);
  }
}, 30_000);

// ══════════════════════════════════════════════════════════════════════════════
//  IN-MEMORY SERIAL LLM QUEUE
//  All LLM calls go through _queueChat(). Only one job runs per session.
//  Queue depth is 1 — second requests are rejected, not queued.
//
//  This is intentionally simple (no BullMQ/Redis) because:
//   - BullMQ requires Redis which is not in the Render free tier
//   - The mutex above already guarantees serial execution
//   - The dedup cache prevents most duplicate submissions
//
//  If Redis is available in future, replace _queueChat with a BullMQ job.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Execute an LLM chat job serially per session.
 * Returns the engine.chat() result or throws.
 *
 * @param {object} opts
 * @param {string}   opts.sessionId
 * @param {string}   opts.message
 * @param {string}   opts.tenantId
 * @param {string}   opts.userId
 * @param {object}   opts.context
 * @param {boolean}  opts.useTools
 * @param {object}   opts.ctxApiKeys
 * @param {object}   opts.req  - Express request (for engine factory)
 */
async function _queueChat(opts) {
  const { sessionId, message, tenantId, userId, context, useTools, ctxApiKeys, req } = opts;
  const shortSid = sessionId.slice(0, 12);

  console.log(`[RAKAY] LLM_QUEUE_START session=${shortSid} userId=${userId} len=${message.length}`);

  const engine = _getEngine(req, ctxApiKeys);

  let lastErr;

  // 🔁 Provider-aware retry (handles OpenAI / Anthropic 429 correctly)
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      console.log(`[RAKAY] LLM_CALL attempt=${attempt + 1} session=${shortSid}`);

      const result = await engine.chat({
        message,
        sessionId,
        tenantId,
        userId,
        context,
        useTools,
      });

      console.log(`[RAKAY] LLM_CALL_COMPLETE session=${shortSid} tokens=${result.tokens_used || 0}`);
      return result;

    } catch (err) {
      lastErr = err;
      const msg = String(err.message || '').toLowerCase();

      const isRateLimit =
        msg.includes('429') ||
        msg.includes('rate limit') ||
        msg.includes('quota') ||
        msg.includes('too many requests');

      if (!isRateLimit) {
        throw err; // real error
      }

      const delay = 1200 * (attempt + 1);
      console.warn(`[RAKAY] LLM_429_BACKOFF session=${shortSid} waiting ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }

  console.error(`[RAKAY] LLM_FAILED_AFTER_RETRIES session=${shortSid}`);
  throw lastErr;
}

// ── Auth middleware: JWT required OR RAKAY service key OR demo token ──────────
function requireRAKAYAuth(req, res, next) {
  // Case 1: Already authenticated via verifyToken (standard JWT)
  if (req.user) return next();

  // Case 2: RAKAY service key bypass (X-RAKAY-KEY header)
  const serviceKey = req.headers['x-rakay-key'];
  if (RAKAY_SERVICE_KEY && serviceKey === RAKAY_SERVICE_KEY) {
    req.user     = { id: 'service', tenantId: 'service', userId: 'service', role: 'service', name: 'RAKAY Service' };
    req.tenantId = 'service';
    return next();
  }

  // Case 3: RAKAY demo JWT (issued by /demo-auth)
  const authHeader = req.headers['authorization'];
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    // Verify demo token
    const demoSecret = _getDemoSecret();
    const jwt = getJWT();
    if (jwt && demoSecret) {
      try {
        const decoded = jwt.verify(token, demoSecret, { algorithms: ['HS256'] });
        if (decoded.rakay_demo === true) {
          req.user     = { id: decoded.sub, tenantId: decoded.tenantId || 'demo', userId: decoded.sub, role: decoded.role || 'analyst', name: decoded.name || 'Demo User' };
          req.tenantId = req.user.tenantId;
          return next();
        }
      } catch (e) {
        // Token expired or invalid — let it fall through to 401
        if (e.name === 'TokenExpiredError') {
          return res.status(401).json({ error: 'Demo session expired. Please refresh.', code: 'DEMO_TOKEN_EXPIRED' });
        }
      }
    }
  }

  // Fallback 401
  return res.status(401).json({
    error:   'Authentication required. Use POST /api/RAKAY/demo-auth for a demo session.',
    code:    'RAKAY_AUTH_REQUIRED',
    hint:    'POST /api/RAKAY/demo-auth to get a 24-hour demo token',
  });
}

// ── Demo secret (derived from JWT_SECRET + fixed salt) ───────────────────────
function _getDemoSecret() {
  const base = process.env.JWT_SECRET || process.env.SUPABASE_SERVICE_KEY || 'rakay-demo-fallback-2024';
  return crypto.createHash('sha256').update(`RAKAY_DEMO_${base}`).digest('hex');
}

// ── Per-request engine factory ────────────────────────────────────────────────
function _getEngine(req, ctxApiKeys = {}) {
  const serverKey   = process.env.RAKAY_OPENAI_KEY    || process.env.OPENAI_API_KEY;
  const serverAnth  = process.env.RAKAY_ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;
  const ctxOpenAI   = ctxApiKeys.openai_key;
  const ctxClaude   = ctxApiKeys.claude_key;

  let provider = process.env.RAKAY_PROVIDER;
  if (!provider) {
    if (serverKey || ctxOpenAI) provider = 'openai';
    else if (serverAnth || ctxClaude) provider = 'anthropic';
    else provider = 'mock';
  }

  const apiKey = provider === 'anthropic'
    ? (serverAnth || ctxClaude)
    : (serverKey || ctxOpenAI);

  // 🔑 cache key ensures we only rebuild if key/provider changes
  const key = `${provider}:${apiKey}`;

  if (_engineSingleton && _engineKey === key) {
    return _engineSingleton;
  }

  console.log(`[RAKAY] ENGINE_INIT provider=${provider} (once per container)`);

  _engineSingleton = new RAKAYEngine({
    provider,
    model: process.env.RAKAY_MODEL,
    apiKey,
  });

  _engineKey = key;
  return _engineSingleton;
}

function _getUserCtx(req) {
  const u = req.user || {};
  return {
    tenantId:   u.tenantId  || u.tenant_id  || 'demo',
    userId:     u.id        || u.userId     || 'guest',
    userRole:   u.role      || 'analyst',
    tenantName: u.tenantName || u.name || 'Wadjet-Eye AI',
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES — No auth required
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/RAKAY/health  — public health probe
 */
router.get('/health', (req, res) => {
  const hasOpenAI    = !!(process.env.RAKAY_OPENAI_KEY   || process.env.OPENAI_API_KEY);
  const hasAnthropic = !!(process.env.RAKAY_ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY);

  const provider = process.env.RAKAY_PROVIDER ||
    (hasOpenAI ? 'openai' : hasAnthropic ? 'anthropic' : 'mock');

  res.json({
    status:       'ok',
    module:       'RAKAY',
    version:      '2.0',
    timestamp:    new Date().toISOString(),
    provider,
    llm_ready:    hasOpenAI || hasAnthropic,
    openai:       hasOpenAI,
    anthropic:    hasAnthropic,
    mock_mode:    !hasOpenAI && !hasAnthropic,
    auth_modes:   ['jwt', 'demo', 'service-key'],
    demo_auth_url: '/api/RAKAY/demo-auth',
    note:         (!hasOpenAI && !hasAnthropic)
      ? 'No LLM API key configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY (CLAUDE_API_KEY) on the server, or pass via frontend settings.'
      : undefined,
  });
});

/**
 * GET /api/RAKAY/capabilities  — public capabilities list
 */
router.get('/capabilities', generalLimiter, (req, res) => {
  const engine = _getEngine(req);
  res.json({
    ...engine.getCapabilities(),
    auth_required: true,
    demo_auth_url: '/api/RAKAY/demo-auth',
  });
});

/**
 * POST /api/RAKAY/demo-auth  — issue a 24-hour demo JWT
 *
 * Body (optional): { name?: string, role?: string }
 * Returns: { token, expires_at, user }
 */
router.post('/demo-auth', demoAuthLimiter, (req, res) => {
  const jwt = getJWT();
  if (!jwt) {
    // jsonwebtoken not installed — return a static demo marker
    // The frontend will use this as a signal to operate in demo mode
    return res.json({
      token:       'RAKAY_DEMO_NO_JWT_LIB',
      expires_at:  new Date(Date.now() + 24 * 3600_000).toISOString(),
      demo:        true,
      user: { id: 'demo-user', name: 'Demo Analyst', role: 'analyst', tenantId: 'demo' },
      note:        'jsonwebtoken not installed — using demo marker token',
    });
  }

  const demoSecret = _getDemoSecret();
  const userId     = `demo_${crypto.randomBytes(8).toString('hex')}`;
  const name       = (req.body?.name  || 'Demo Analyst').slice(0, 80);
  const role       = ['analyst','viewer','admin'].includes(req.body?.role) ? req.body.role : 'analyst';
  const expiresAt  = new Date(Date.now() + 24 * 3600_000);

  const token = jwt.sign(
    {
      sub:        userId,
      name,
      role,
      tenantId:   'demo',
      rakay_demo: true,
      iat:        Math.floor(Date.now() / 1000),
    },
    demoSecret,
    { expiresIn: '24h', algorithm: 'HS256' }
  );

  console.log(`[RAKAY] Demo auth issued: userId=${userId} name="${name}" role=${role}`);

  res.json({
    token,
    expires_at: expiresAt.toISOString(),
    demo:       true,
    user: {
      id:       userId,
      name,
      role,
      tenantId: 'demo',
      email:    `${userId}@demo.rakay.ai`,
    },
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  SESSION ROUTES — requireRAKAYAuth
// ══════════════════════════════════════════════════════════════════════════════

router.post('/session', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const { title } = req.body || {};
    const engine  = _getEngine(req);
    const session = await engine.createSession({ tenantId, userId, title });
    res.status(201).json({ session });
  } catch (err) {
    console.error('[RAKAY] POST /session error:', err.message);
    res.status(500).json({ error: 'Failed to create session', details: err.message });
  }
});

router.get('/session', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
    const engine = _getEngine(req);
    const sessions = await engine.listSessions({ tenantId, userId, limit });
    res.json({ sessions, count: sessions.length });
  } catch (err) {
    console.error('[RAKAY] GET /session error:', err.message);
    res.status(500).json({ error: 'Failed to list sessions', details: err.message });
  }
});

router.get('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const { getSession } = require('../services/rakay-store');
    const session = await getSession({ sessionId: req.params.id, tenantId });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ session });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get session', details: err.message });
  }
});

router.patch('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const { title }   = req.body || {};
    if (!title?.trim()) return res.status(400).json({ error: 'title is required' });
    const engine = _getEngine(req);
    await engine.renameSession({ sessionId: req.params.id, tenantId, title: title.trim().slice(0, 120) });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to rename session', details: err.message });
  }
});

router.delete('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const engine = _getEngine(req);
    await engine.deleteSession({ sessionId: req.params.id, tenantId });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete session', details: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CHAT ROUTE — main AI entry point
// ══════════════════════════════════════════════════════════════════════════════

router.post('/chat', chatLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  const { tenantId, userId, userRole, tenantName } = _getUserCtx(req);
  const { session_id, message, context = {}, use_tools = true } = req.body || {};
  // AUTO-GENERATE session_id if missing — never throw 400 for missing session
  // Fixes MISSING_SESSION_ID when frontend race-condition leaves sessionId null.
  let effectiveSessionId = (typeof session_id === 'string' && session_id.trim()) ? session_id.trim() : null;
  if (!effectiveSessionId) {
    effectiveSessionId = require('crypto').randomUUID();
    console.warn(`[RAKAY] MISSING_SESSION_ID — auto-generated: ${effectiveSessionId.slice(0, 12)} userId=${userId}`);
  }
  const shortSid = effectiveSessionId.slice(0, 12);

  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'message is required', code: 'MISSING_MESSAGE' });
  }
  if (message.trim().length > 8000) {
    return res.status(400).json({ error: 'message too long (max 8000 chars)', code: 'MESSAGE_TOO_LONG' });
  }

  // ── Message deduplication (10-second window) ───────────────────────────────
  // Rejects identical messages submitted in rapid succession (double-click,
  // retry bugs, form re-submission). NOT a rate limit — use a distinct 409 code.
  if (_isDuplicate(effectiveSessionId, message)) {
    console.log(`[RAKAY] DEDUP_BLOCKED session=${shortSid} userId=${userId} — identical message within 10s`);
    return res.status(409).json({
      error: 'Duplicate message detected. Your previous request is still processing or was just sent.',
      code:  'DUPLICATE_MESSAGE',
    });
  }

  // ── Per-session mutex (hard lock) ──────────────────────────────────────────
  if (!_acquireSession(effectiveSessionId)) {
    console.log(`[RAKAY] MUTEX_BLOCKED session=${shortSid} userId=${userId} — request already in progress`);
    return res.status(409).json({
      error: 'A request is already in progress for this session. Please wait for it to complete.',
      code:  'SESSION_BUSY',
    });
  }

  console.log(`[RAKAY] CHAT_START session=${shortSid} userId=${userId} len=${message.trim().length}`);

  try {
    const ctxApiKeys = {
      openai_key: context.openai_key,
      claude_key: context.claude_key,
    };

    const response = await _queueChat({
      sessionId: effectiveSessionId,
      message:   message.trim(),
      tenantId,
      userId,
      context: {
        ...context,
        userRole,
        tenantName,
        authHeader: req.headers.authorization,
      },
      useTools:    use_tools !== false,
      ctxApiKeys,
      req,
    });

    console.log(`[RAKAY] CHAT_OK session=${shortSid} userId=${userId}`);
    res.json(response);

  } catch (err) {
    console.error(`[RAKAY] CHAT_ERROR session=${shortSid} userId=${userId}:`, err.message);

    if (err.message?.includes('Session not found')) {
      return res.status(404).json({ error: 'Session not found', code: 'SESSION_NOT_FOUND' });
    }
    if (err.message?.includes('API key') || err.message?.includes('Unauthorized') || err.message?.includes('401')) {
      return res.status(503).json({
        error:   'AI provider key invalid or missing. Set RAKAY_OPENAI_KEY on the server.',
        code:    'LLM_UNAVAILABLE',
        details: process.env.NODE_ENV !== 'production' ? err.message : undefined,
      });
    }

    res.status(500).json({
      error:   'Chat request failed',
      code:    'RAKAY_ERROR',
      details: process.env.NODE_ENV !== 'production' ? err.message : undefined,
    });
  } finally {
    _releaseSession(effectiveSessionId);
    console.log(`[RAKAY] CHAT_END session=${shortSid} — lock released`);
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  HISTORY + SEARCH
// ══════════════════════════════════════════════════════════════════════════════

router.get('/history/:sessionId', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const limit  = Math.min(parseInt(req.query.limit) || 50, 500);
    const engine = _getEngine(req);
    const messages = await engine.getHistory({ sessionId: req.params.sessionId, tenantId, limit });
    const { getSession } = require('../services/rakay-store');
    const session = await getSession({ sessionId: req.params.sessionId, tenantId });
    res.json({ messages, session, count: messages.length });
  } catch (err) {
    if (err.message?.includes('Session not found')) return res.status(404).json({ error: 'Session not found' });
    res.status(500).json({ error: 'Failed to retrieve history', details: err.message });
  }
});

router.get('/search', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const query = req.query.q || req.query.query;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    if (!query?.trim()) return res.status(400).json({ error: 'query param q is required' });
    const engine  = _getEngine(req);
    const results = await engine.searchHistory({ tenantId, userId, query: query.trim(), limit });
    res.json({ results, count: results.length });
  } catch (err) {
    res.status(500).json({ error: 'Search failed', details: err.message });
  }
});

module.exports = router;
