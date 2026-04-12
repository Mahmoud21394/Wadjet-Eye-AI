/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — REST API Routes  v1.0
 *
 *  Endpoints:
 *   POST /api/RAKAY/session          — create a new session
 *   GET  /api/RAKAY/session          — list sessions for the user
 *   GET  /api/RAKAY/session/:id      — get session details
 *   PATCH /api/RAKAY/session/:id     — rename session
 *   DELETE /api/RAKAY/session/:id    — delete session
 *
 *   POST /api/RAKAY/chat             — send a message (main entry point)
 *
 *   GET  /api/RAKAY/history/:sessionId — get conversation history
 *   GET  /api/RAKAY/search           — search across all sessions
 *
 *   GET  /api/RAKAY/capabilities     — list available tools & model info
 *
 *  Auth: verifyToken middleware is applied in server.js before mounting.
 *        Each route extracts tenantId / userId from req.user.
 *
 *  Rate limiting:
 *   - Chat: 30 req/min per tenant (configurable)
 *   - History/session: 120 req/min per tenant
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const { RAKAYEngine } = require('../services/RAKAYEngine');

const router = express.Router();

// ── Rate limiters ──────────────────────────────────────────────────────────────
const chatLimiter = rateLimit({
  windowMs:    60 * 1000,  // 1 minute
  max:         30,
  keyGenerator: req => `rakay_chat_${req.user?.tenantId || req.ip}`,
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
  keyGenerator: req => `rakay_gen_${req.user?.tenantId || req.ip}`,
  handler: (req, res) => res.status(429).json({ error: 'Rate limit exceeded', code: 'RAKAY_RATE_LIMIT' }),
  standardHeaders: true,
  legacyHeaders:   false,
});

// ── Per-request engine factory (uses env config; can be overridden per-tenant) ──
function _getEngine(req) {
  // Could be extended to load per-tenant model/API-key config from DB
  return new RAKAYEngine({
    provider: process.env.RAKAY_PROVIDER || 'openai',
    model:    req.user?.rakay_model || process.env.RAKAY_MODEL,
    apiKey:   process.env.RAKAY_OPENAI_KEY || process.env.OPENAI_API_KEY,
  });
}

function _getUserCtx(req) {
  return {
    tenantId:   req.user?.tenantId  || req.user?.tenant_id  || 'default',
    userId:     req.user?.userId    || req.user?.id          || 'anon',
    userRole:   req.user?.role      || 'analyst',
    tenantName: req.user?.tenantName,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  SESSION ROUTES
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/RAKAY/session
 * Body: { title?: string }
 * Returns: { session }
 */
router.post('/session', generalLimiter, async (req, res) => {
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

/**
 * GET /api/RAKAY/session
 * Query: limit?=50
 * Returns: { sessions: SessionRecord[] }
 */
router.get('/session', generalLimiter, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);

    const engine   = _getEngine(req);
    const sessions = await engine.listSessions({ tenantId, userId, limit });

    res.json({ sessions, count: sessions.length });
  } catch (err) {
    console.error('[RAKAY] GET /session error:', err.message);
    res.status(500).json({ error: 'Failed to list sessions', details: err.message });
  }
});

/**
 * GET /api/RAKAY/session/:id
 * Returns: { session }
 */
router.get('/session/:id', generalLimiter, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const engine  = _getEngine(req);

    // Validate session belongs to tenant
    const { getSession } = require('../services/rakay-store');
    const session = await getSession({ sessionId: req.params.id, tenantId });

    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ session });
  } catch (err) {
    console.error('[RAKAY] GET /session/:id error:', err.message);
    res.status(500).json({ error: 'Failed to get session', details: err.message });
  }
});

/**
 * PATCH /api/RAKAY/session/:id
 * Body: { title: string }
 * Returns: { ok: true }
 */
router.patch('/session/:id', generalLimiter, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const { title }    = req.body || {};

    if (!title || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ error: 'title is required' });
    }

    const engine = _getEngine(req);
    await engine.renameSession({ sessionId: req.params.id, tenantId, title: title.trim().slice(0, 120) });

    res.json({ ok: true });
  } catch (err) {
    console.error('[RAKAY] PATCH /session/:id error:', err.message);
    res.status(500).json({ error: 'Failed to rename session', details: err.message });
  }
});

/**
 * DELETE /api/RAKAY/session/:id
 * Returns: { ok: true }
 */
router.delete('/session/:id', generalLimiter, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const engine       = _getEngine(req);
    await engine.deleteSession({ sessionId: req.params.id, tenantId });
    res.json({ ok: true });
  } catch (err) {
    console.error('[RAKAY] DELETE /session/:id error:', err.message);
    res.status(500).json({ error: 'Failed to delete session', details: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CHAT ROUTE
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/RAKAY/chat
 * Body: {
 *   session_id: string,          — required
 *   message:    string,          — required
 *   context?: {                  — optional
 *     currentPage?: string,
 *     platform_context?: object,
 *   },
 *   use_tools?: boolean,         — default true
 * }
 * Returns: {
 *   id, session_id, content, role,
 *   tool_trace, tokens_used, model, latency_ms, created_at
 * }
 */
router.post('/chat', chatLimiter, async (req, res) => {
  const { tenantId, userId, userRole, tenantName } = _getUserCtx(req);
  const { session_id, message, context = {}, use_tools = true } = req.body || {};

  // ── Input validation ────────────────────────────────────────────────────────
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
    const engine   = _getEngine(req);
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

    // Categorise errors
    if (err.message?.includes('Session not found')) {
      return res.status(404).json({ error: 'Session not found', code: 'SESSION_NOT_FOUND' });
    }
    if (err.message?.includes('API key') || err.message?.includes('Unauthorized')) {
      return res.status(503).json({
        error:   'AI provider unavailable. Check RAKAY_OPENAI_KEY environment variable.',
        code:    'LLM_UNAVAILABLE',
        details: err.message,
      });
    }
    if (err.message?.includes('rate limit') || err.message?.toLowerCase().includes('quota')) {
      return res.status(429).json({
        error: 'AI provider rate limit hit. Please try again shortly.',
        code:  'LLM_RATE_LIMIT',
      });
    }

    res.status(500).json({
      error:   'Chat request failed',
      code:    'RAKAY_ERROR',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  HISTORY ROUTES
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/RAKAY/history/:sessionId
 * Query: limit?=50
 * Returns: { messages: MessageRecord[], session }
 */
router.get('/history/:sessionId', generalLimiter, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const limit  = Math.min(parseInt(req.query.limit) || 50, 500);
    const engine = _getEngine(req);

    const messages = await engine.getHistory({
      sessionId: req.params.sessionId,
      tenantId,
      limit,
    });

    // Also return session metadata
    const { getSession } = require('../services/rakay-store');
    const session = await getSession({ sessionId: req.params.sessionId, tenantId });

    res.json({ messages, session, count: messages.length });
  } catch (err) {
    console.error('[RAKAY] GET /history error:', err.message);
    if (err.message?.includes('Session not found')) {
      return res.status(404).json({ error: 'Session not found' });
    }
    res.status(500).json({ error: 'Failed to retrieve history', details: err.message });
  }
});

/**
 * GET /api/RAKAY/search
 * Query: q=<search>, limit?=20
 * Returns: { results: SearchResult[] }
 */
router.get('/search', generalLimiter, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const query  = req.query.q || req.query.query;
    const limit  = Math.min(parseInt(req.query.limit) || 20, 100);

    if (!query || !query.trim()) {
      return res.status(400).json({ error: 'query parameter q is required' });
    }

    const engine  = _getEngine(req);
    const results = await engine.searchHistory({ tenantId, userId, query: query.trim(), limit });

    res.json({ results, count: results.length });
  } catch (err) {
    console.error('[RAKAY] GET /search error:', err.message);
    res.status(500).json({ error: 'Search failed', details: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CAPABILITIES
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/RAKAY/capabilities
 * Returns: { provider, model, tools, context_window, max_iterations }
 */
router.get('/capabilities', generalLimiter, (req, res) => {
  const engine = _getEngine(req);
  res.json(engine.getCapabilities());
});

// ══════════════════════════════════════════════════════════════════════════════
//  HEALTH (unauthenticated OK for load-balancer probes)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    module:    'RAKAY',
    version:   '1.0',
    timestamp: new Date().toISOString(),
    provider:  process.env.RAKAY_PROVIDER || 'openai',
    llm_ready: !!(process.env.RAKAY_OPENAI_KEY || process.env.OPENAI_API_KEY ||
                  process.env.RAKAY_ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY),
  });
});

module.exports = router;
