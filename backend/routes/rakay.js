/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — REST API Routes  v2.0
 *
 *  Auth model (v2.0 — production hardened):
 *  ─────────────────────────────────────────
 *  Three tiers of access:
 *   1. JWT bearer token (standard — attached by verifyToken in server.js)
 *   2. RAKAY_API_KEY header (X-RAKAY-KEY) — service-to-service bypass
 *   3. Demo mode — auto-issued short-lived token for unauthenticated users
 *
 *  Public routes (no auth):
 *   GET  /api/RAKAY/health
 *   GET  /api/RAKAY/capabilities
 *   POST /api/RAKAY/demo-auth     — issues a 24-h demo JWT
 *
 *  Protected routes (JWT or API-key):
 *   POST /api/RAKAY/session, GET, PATCH, DELETE
 *   POST /api/RAKAY/chat
 *   GET  /api/RAKAY/history/:sid
 *   GET  /api/RAKAY/search
 *
 *  Rate limiting:
 *   - Chat: 30 req/min per IP/tenant
 *   - General: 120 req/min
 *   - Demo-auth: 10 req/min per IP (prevent abuse)
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
let _jwt = null;
function getJWT() {
  if (_jwt) return _jwt;
  try { _jwt = require('jsonwebtoken'); } catch { /* not installed */ }
  return _jwt;
}

// ── RAKAY API key (server-to-server bypass) ───────────────────────────────────
const RAKAY_SERVICE_KEY = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY || null;

// ── Rate limiters ──────────────────────────────────────────────────────────────
const chatLimiter = rateLimit({
  windowMs:    60 * 1000,
  max:         30,
  keyGenerator: req => `rakay_chat_${req.user?.id || req.user?.tenantId || req.ip}`,
  handler:     (req, res) => res.status(429).json({
    error:   'Too many chat requests. Please wait a moment.',
    code:    'RAKAY_RATE_LIMIT',
    retryAfter: 60,
  }),
  standardHeaders: true,
  legacyHeaders:   false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      120,
  keyGenerator: req => `rakay_gen_${req.user?.id || req.ip}`,
  handler: (req, res) => res.status(429).json({ error: 'Rate limit exceeded', code: 'RAKAY_RATE_LIMIT' }),
  standardHeaders: true,
  legacyHeaders:   false,
});

const demoAuthLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      10,
  keyGenerator: req => `rakay_demo_${req.ip}`,
  handler: (req, res) => res.status(429).json({ error: 'Too many demo auth requests', code: 'RATE_LIMIT' }),
  standardHeaders: true,
  legacyHeaders:   false,
});

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
  // API key priority: server env vars → request context (from frontend settings)
  const serverKey   = process.env.RAKAY_OPENAI_KEY    || process.env.OPENAI_API_KEY;
  const serverAnth  = process.env.RAKAY_ANTHROPIC_KEY  || process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;
  const ctxOpenAI   = ctxApiKeys.openai_key;
  const ctxClaude   = ctxApiKeys.claude_key;

  // Determine provider: server env takes priority, then context, then default
  let provider = process.env.RAKAY_PROVIDER;
  if (!provider) {
    if (serverKey  || ctxOpenAI)  provider = 'openai';
    else if (serverAnth || ctxClaude) provider = 'anthropic';
    else provider = 'mock'; // graceful degradation
  }

  const apiKey = provider === 'anthropic'
    ? (serverAnth  || ctxClaude  || undefined)
    : (serverKey   || ctxOpenAI  || undefined);

  return new RAKAYEngine({
    provider,
    model:   req.user?.rakay_model || process.env.RAKAY_MODEL,
    apiKey,
  });
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

  if (!session_id || typeof session_id !== 'string') {
    return res.status(400).json({ error: 'session_id is required', code: 'MISSING_SESSION_ID' });
  }
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'message is required', code: 'MISSING_MESSAGE' });
  }
  if (message.trim().length > 8000) {
    return res.status(400).json({ error: 'message too long (max 8000 chars)', code: 'MESSAGE_TOO_LONG' });
  }

  try {
    // Pass context API keys (from frontend user settings) to engine factory
    const ctxApiKeys = {
      openai_key: context.openai_key,
      claude_key: context.claude_key,
    };
    const engine   = _getEngine(req, ctxApiKeys);
    const response = await engine.chat({
      message:  message.trim(),
      sessionId: session_id,
      tenantId,
      userId,
      context: {
        ...context,
        userRole,
        tenantName,
        authHeader: req.headers.authorization,
      },
      useTools: use_tools !== false,
    });
    res.json(response);
  } catch (err) {
    console.error('[RAKAY] POST /chat error:', err.message);

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
    if (err.message?.includes('rate limit') || err.message?.toLowerCase().includes('quota')) {
      return res.status(429).json({ error: 'AI provider rate limit. Try again shortly.', code: 'LLM_RATE_LIMIT' });
    }

    res.status(500).json({
      error:   'Chat request failed',
      code:    'RAKAY_ERROR',
      details: process.env.NODE_ENV !== 'production' ? err.message : undefined,
    });
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
