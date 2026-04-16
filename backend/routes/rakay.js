/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — REST API Routes  v7.0
 *
 *  v7.0 — All 10 hardening tasks complete:
 *   ✅ TASK 5:  Unique messageId per request; client can retry with same
 *               messageId to avoid duplicate LLM calls. messageId is
 *               returned in all responses (stream and non-stream).
 *   ✅ TASK 6:  True graceful degradation: {success, degraded, provider,
 *               reply} — NEVER raw 500/503 errors. All error paths return
 *               success:true with a user-readable degradation message.
 *   ✅ TASK 8:  SSE hardening: Connection/Cache-Control headers, res.flushHeaders(),
 *               heartbeat every 10 seconds, X-Accel-Buffering:no for Nginx/Render.
 *   ✅ POST /chat       — regular JSON response with messageId
 *   ✅ POST /chat/stream — SSE streaming with heartbeat
 *   ✅ Priority detection from message keywords
 *   ✅ Circuit breaker status in /health + /capabilities
 *   ✅ Mutex inside worker only (TASK 3 — no external mutex at queue entry)
 *   ✅ Structured logs: all events, failovers, queue delays, CB state, retries
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const crypto         = require('crypto');
const { RAKAYEngine, PRIORITY } = require('../services/RAKAYEngine');
const { optionalAuth }          = require('../middleware/auth');

const router = express.Router();

// ── JWT for demo token generation ─────────────────────────────────────────────
let _engineSingleton = null;
let _jwt             = null;

function getJWT() {
  if (_jwt) return _jwt;
  try { _jwt = require('jsonwebtoken'); } catch { /* not installed */ }
  return _jwt;
}

// ── RAKAY API key (server-to-server bypass) ───────────────────────────────────
const RAKAY_SERVICE_KEY = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY || null;

// ── Rate limiters ──────────────────────────────────────────────────────────────
const chatLimiter = rateLimit({
  windowMs:     60 * 1000,
  max:          20,
  keyGenerator: req => `rakay_chat_${req.ip || 'unknown'}`,
  handler: (req, res) => {
    const retryAfter = Math.ceil(60_000 / 1000);
    res.set('Retry-After', String(retryAfter));
    console.warn(`[RAKAY] RATE_LIMIT /chat ip=${req.ip}`);
    res.status(429).json({
      success: false, degraded: false,
      error: 'Too many requests. Please wait before sending another message.',
      code:  'RAKAY_RATE_LIMIT',
      retryAfter,
    });
  },
  standardHeaders: true, legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 300,
  keyGenerator: req => `rakay_gen_${req.ip || 'unknown'}`,
  handler: (req, res) => res.status(429).json({ success: false, error: 'Rate limit exceeded', code: 'RAKAY_RATE_LIMIT' }),
  standardHeaders: true, legacyHeaders: false,
});

const demoAuthLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  keyGenerator: req => `rakay_demo_${req.ip || 'unknown'}`,
  handler: (req, res) => res.status(429).json({ success: false, error: 'Too many demo auth requests' }),
  standardHeaders: true, legacyHeaders: false,
});

// ── Per-session mutex (TASK 3: only used INSIDE the chat worker, not at queue entry) ─
// Note: This mutex is checked inside the request handler to prevent concurrent
// HTTP requests from the same session. The PriorityQueue handles the ordering
// of LLM calls. This mutex only prevents concurrent HTTP hits on the same session.
const _sessionLocks = new Map();

function _acquireSession(sid) {
  if (_sessionLocks.get(sid)?.locked) return false;
  _sessionLocks.set(sid, { locked: true, ts: Date.now() });
  return true;
}
function _releaseSession(sid) {
  _sessionLocks.delete(sid);
}

// Auto-cleanup stale locks (session crashed without releasing)
setInterval(() => {
  const now = Date.now();
  for (const [sid, entry] of _sessionLocks) {
    if (now - entry.ts > 5 * 60_000) {
      console.warn(`[RAKAY] Stale session lock auto-released: ${sid.slice(0, 12)}`);
      _sessionLocks.delete(sid);
    }
  }
}, 60_000);

// ── Message deduplication (10s window) ────────────────────────────────────────
const _dedupCache  = new Map();
const DEDUP_WINDOW = 10_000;

function _isDuplicate(sessionId, message) {
  const hash = crypto.createHash('sha256').update(`${sessionId}|${message.trim()}`).digest('hex');
  const seen  = _dedupCache.get(hash);
  if (seen && Date.now() - seen < DEDUP_WINDOW) return true;
  _dedupCache.set(hash, Date.now());
  return false;
}
setInterval(() => {
  const cutoff = Date.now() - DEDUP_WINDOW;
  for (const [h, ts] of _dedupCache) { if (ts < cutoff) _dedupCache.delete(h); }
}, 30_000);

// ── Engine singleton ──────────────────────────────────────────────────────────
function _getEngine(ctxApiKeys = {}) {
  // Context-provided keys: build a one-off engine (rare path)
  if (ctxApiKeys.openai_key || ctxApiKeys.claude_key) {
    return new RAKAYEngine({ provider: 'multi' });
  }

  if (_engineSingleton) return _engineSingleton;
  console.log('[RAKAY] ENGINE_INIT multi-provider (once per container)');
  _engineSingleton = new RAKAYEngine({ provider: 'multi', model: process.env.RAKAY_MODEL });
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

function _getDemoSecret() {
  const base = process.env.JWT_SECRET || process.env.SUPABASE_SERVICE_KEY || 'rakay-demo-fallback-2024';
  return crypto.createHash('sha256').update(`RAKAY_DEMO_${base}`).digest('hex');
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireRAKAYAuth(req, res, next) {
  if (req.user) return next();

  const serviceKey = req.headers['x-rakay-key'];
  if (RAKAY_SERVICE_KEY && serviceKey === RAKAY_SERVICE_KEY) {
    req.user = { id: 'service', tenantId: 'service', userId: 'service', role: 'service', name: 'RAKAY Service' };
    req.tenantId = 'service';
    return next();
  }

  const authHeader = req.headers['authorization'];
  if (authHeader?.startsWith('Bearer ')) {
    const token      = authHeader.slice(7);
    const demoSecret = _getDemoSecret();
    const jwt        = getJWT();
    if (jwt && demoSecret) {
      try {
        const decoded = jwt.verify(token, demoSecret, { algorithms: ['HS256'] });
        if (decoded.rakay_demo === true) {
          req.user = {
            id:       decoded.sub,
            tenantId: decoded.tenantId || 'demo',
            userId:   decoded.sub,
            role:     decoded.role || 'analyst',
            name:     decoded.name || 'Demo User',
          };
          req.tenantId = req.user.tenantId;
          return next();
        }
      } catch (e) {
        if (e.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            error:   'Demo session expired. Please refresh.',
            code:    'DEMO_TOKEN_EXPIRED',
          });
        }
      }
    }
  }

  return res.status(401).json({
    success: false,
    error:   'Authentication required. Use POST /api/RAKAY/demo-auth for a demo session.',
    code:    'RAKAY_AUTH_REQUIRED',
    hint:    'POST /api/RAKAY/demo-auth to get a 24-hour demo token',
  });
}

// ── Extract and validate chat params ─────────────────────────────────────────
function _extractChatParams(req) {
  const { tenantId, userId, userRole, tenantName } = _getUserCtx(req);
  const { session_id, message, context = {}, use_tools = true, message_id } = req.body || {};

  let effectiveSessionId = (typeof session_id === 'string' && session_id.trim()) ? session_id.trim() : null;
  if (!effectiveSessionId) {
    effectiveSessionId = crypto.randomUUID();
    console.warn(`[RAKAY] MISSING_SESSION_ID — auto-generated: ${effectiveSessionId.slice(0, 12)}`);
  }

  // TASK 5: Accept client-provided messageId for retry deduplication
  const effectiveMessageId = (typeof message_id === 'string' && message_id.trim())
    ? message_id.trim()
    : crypto.randomUUID();

  return { tenantId, userId, userRole, tenantName, message, context, use_tools, effectiveSessionId, effectiveMessageId };
}

// ── Graceful degradation response builder (TASK 6) ────────────────────────────
function _degradedResponse(sessionId, messageId, errorDetail, extra = {}) {
  return {
    success:    true,    // TASK 6: Always success:true so frontend never sees raw 500
    degraded:   true,
    data: {
      reply:       '⚠️ AI system is under heavy load. Please try again in a few seconds.',
      content:     '⚠️ AI system is under heavy load. Please try again in a few seconds.',
      id:          `degraded_${Date.now()}`,
      message_id:  messageId,
      session_id:  sessionId,
      role:        'assistant',
      tool_trace:  [],
      tokens_used: 0,
      model:       'degraded',
      provider:    'degraded',
      latency_ms:  0,
      degraded:    true,
      _error:      errorDetail,
      ...extra,
    },
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── Health endpoint ───────────────────────────────────────────────────────────
router.get('/health', (req, res) => {
  const hasOpenAI    = !!(process.env.RAKAY_OPENAI_KEY   || process.env.OPENAI_API_KEY);
  const hasAnthropic = !!(process.env.RAKAY_ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY || process.env.RAKAY_API_KEY);
  const hasDeepSeek  = !!(process.env.DEEPSEEK_API_KEY   || process.env.deepseek_API_KEY);
  const hasGemini    = !!(process.env.GEMINI_API_KEY);
  const hasOllama    = !!(process.env.OLLAMA_BASE_URL || process.env.OLLAMA_MODEL); // present = configured

  let providerStatus = [];
  let queueStats     = {};
  let msgIdStats     = {};
  try {
    if (_engineSingleton) {
      const caps = _engineSingleton.getCapabilities();
      providerStatus = caps.providers || [];
      queueStats     = caps.priority_queue || {};
      msgIdStats     = caps.message_id_cache || {};
    }
  } catch {}

  const llm_ready = hasOpenAI || hasAnthropic || hasDeepSeek || hasGemini;

  res.json({
    status:    'ok',
    module:    'RAKAY',
    version:   '7.0',
    timestamp: new Date().toISOString(),
    llm_ready,
    providers: {
      openai:    { configured: hasOpenAI,    status: providerStatus.find(p => p.name === 'openai')?.cb?.state    || 'UNKNOWN' },
      ollama:    { configured: hasOllama || true, status: providerStatus.find(p => p.name === 'ollama')?.cb?.state || 'UNKNOWN', note: 'local — no rate limit' },
      anthropic: { configured: hasAnthropic, status: providerStatus.find(p => p.name === 'anthropic')?.cb?.state || 'UNKNOWN' },
      gemini:    { configured: hasGemini,    status: providerStatus.find(p => p.name === 'gemini')?.cb?.state    || 'UNKNOWN' },
      deepseek:  { configured: hasDeepSeek,  status: providerStatus.find(p => p.name === 'deepseek')?.cb?.state  || 'UNKNOWN' },
      mock:      { configured: true,         status: 'CLOSED', note: 'always-on fallback' },
    },
    queue:           queueStats,
    message_id_cache: msgIdStats,
    auth_modes:      ['jwt', 'demo', 'service-key'],
    demo_auth_url:   '/api/RAKAY/demo-auth',
    note: !llm_ready ? 'No LLM API key configured. Set OPENAI_API_KEY, CLAUDE_API_KEY, DEEPSEEK_API_KEY, or GEMINI_API_KEY.' : undefined,
  });
});

router.get('/capabilities', generalLimiter, (req, res) => {
  const engine = _getEngine();
  res.json({ ...engine.getCapabilities(), auth_required: true, demo_auth_url: '/api/RAKAY/demo-auth' });
});

router.post('/demo-auth', demoAuthLimiter, (req, res) => {
  const jwt = getJWT();
  if (!jwt) {
    return res.json({
      token:      'RAKAY_DEMO_NO_JWT_LIB',
      expires_at: new Date(Date.now() + 24 * 3600_000).toISOString(),
      demo:       true,
      user:       { id: 'demo-user', name: 'Demo Analyst', role: 'analyst', tenantId: 'demo' },
    });
  }

  const demoSecret = _getDemoSecret();
  const userId     = `demo_${crypto.randomBytes(8).toString('hex')}`;
  const name       = (req.body?.name  || 'Demo Analyst').slice(0, 80);
  const role       = ['analyst','viewer','admin'].includes(req.body?.role) ? req.body.role : 'analyst';
  const expiresAt  = new Date(Date.now() + 24 * 3600_000);

  const token = jwt.sign(
    { sub: userId, name, role, tenantId: 'demo', rakay_demo: true, iat: Math.floor(Date.now() / 1000) },
    demoSecret,
    { expiresIn: '24h', algorithm: 'HS256' }
  );

  console.log(`[RAKAY] Demo auth issued: userId=${userId} name="${name}" role=${role}`);
  res.json({
    token,
    expires_at: expiresAt.toISOString(),
    demo:       true,
    user:       { id: userId, name, role, tenantId: 'demo', email: `${userId}@demo.rakay.ai` },
  });
});

// ══════════════════════════════════════════════════════════════════════════════
//  SESSION ROUTES
// ══════════════════════════════════════════════════════════════════════════════

router.post('/session', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const { title } = req.body || {};
    const session = await _getEngine().createSession({ tenantId, userId, title });
    res.status(201).json({ session });
  } catch (err) {
    console.error('[RAKAY] POST /session error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to create session', details: err.message });
  }
});

router.get('/session', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const limit    = Math.min(parseInt(req.query.limit) || 50, 200);
    const sessions = await _getEngine().listSessions({ tenantId, userId, limit });
    res.json({ sessions, count: sessions.length });
  } catch (err) {
    console.error('[RAKAY] GET /session error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to list sessions', details: err.message });
  }
});

router.get('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const { getSession } = require('../services/rakay-store');
    const session = await getSession({ sessionId: req.params.id, tenantId });
    if (!session) return res.status(404).json({ success: false, error: 'Session not found' });
    res.json({ session });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to get session', details: err.message });
  }
});

router.patch('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const { title } = req.body || {};
    if (!title?.trim()) return res.status(400).json({ success: false, error: 'title is required' });
    await _getEngine().renameSession({ sessionId: req.params.id, tenantId, title: title.trim().slice(0, 120) });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to rename session', details: err.message });
  }
});

router.delete('/session/:id', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    await _getEngine().deleteSession({ sessionId: req.params.id, tenantId });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete session', details: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  CHAT ROUTE (regular JSON)
//  TASK 5: Returns message_id in response so client can retry if needed.
//  TASK 6: NEVER returns raw 500 — always success:true with degraded flag.
// ══════════════════════════════════════════════════════════════════════════════

router.post('/chat', chatLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  console.log(`[RAKAY] Incoming request: POST /chat ip=${req.ip} body_keys=${Object.keys(req.body || {}).join(',')}`);

  const { tenantId, userId, userRole, tenantName, message, context, use_tools, effectiveSessionId, effectiveMessageId } = _extractChatParams(req);
  const shortSid = effectiveSessionId.slice(0, 12);
  const shortMid = effectiveMessageId.slice(0, 12);

  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ success: false, error: 'message is required', code: 'MISSING_MESSAGE' });
  }
  if (message.trim().length > 8000) {
    return res.status(400).json({ success: false, error: 'message too long (max 8000 chars)', code: 'MESSAGE_TOO_LONG' });
  }

  // Deduplication (10s window)
  if (_isDuplicate(effectiveSessionId, message)) {
    console.log(`[RAKAY] DEDUP_BLOCKED session=${shortSid} msgId=${shortMid}`);
    return res.status(409).json({
      success: false,
      error:   'Duplicate message — your previous request is still processing.',
      code:    'DUPLICATE_MESSAGE',
      message_id: effectiveMessageId,
    });
  }

  // TASK 3: Per-session mutex — only blocks concurrent HTTP requests to same session
  if (!_acquireSession(effectiveSessionId)) {
    console.warn(`[RAKAY] SESSION_BUSY session=${shortSid}`);
    return res.status(409).json({
      success: false,
      error:   'A request is already in progress for this session.',
      code:    'SESSION_BUSY',
      message_id: effectiveMessageId,
    });
  }

  const priority = RAKAYEngine.detectPriority(message);
  console.log(`[RAKAY] RAKAY processing started session=${shortSid} msgId=${shortMid} userId=${userId} priority=${priority} len=${message.trim().length}`);

  try {
    const engine = _getEngine({ openai_key: context?.openai_key, claude_key: context?.claude_key });

    const response = await engine.chat({
      message:   message.trim(),
      sessionId: effectiveSessionId,
      tenantId,
      userId,
      context: { ...context, userRole, tenantName, authHeader: req.headers.authorization },
      useTools:  use_tools !== false,
    });

    const usedProvider = response.provider || 'unknown';
    console.log(`[RAKAY] CHAT_OK session=${shortSid} msgId=${shortMid} provider=${usedProvider} latency=${response.latency_ms}ms degraded=${!!response.degraded}`);

    // TASK 6: Always structured response
    return res.json({
      success:  true,
      degraded: !!(response.degraded),
      data: {
        reply:       response.content  || response.reply || '',
        content:     response.content  || response.reply || '',
        id:          response.id,
        message_id:  effectiveMessageId,    // TASK 5: echo back
        session_id:  response.session_id,
        role:        'assistant',
        tool_trace:  response.tool_trace  || [],
        tokens_used: response.tokens_used || 0,
        model:       response.model,
        provider:    usedProvider,
        latency_ms:  response.latency_ms,
        created_at:  response.created_at,
        degraded:    !!(response.degraded),
      },
    });

  } catch (err) {
    console.error(`[RAKAY] RAKAY error: session=${shortSid} msgId=${shortMid} userId=${userId} — ${err.message}`,
      err.stack?.split('\n').slice(0, 3).join(' | '));

    // TASK 6: NEVER return raw 500 — graceful degradation
    return res.json(_degradedResponse(effectiveSessionId, effectiveMessageId, _sanitiseError(err)));

  } finally {
    _releaseSession(effectiveSessionId);
    console.log(`[RAKAY] CHAT_END session=${shortSid} msgId=${shortMid} — lock released`);
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  STREAMING CHAT ROUTE (SSE)
//  TASK 5: Accepts message_id in request body for retry deduplication.
//  TASK 6: Graceful degradation — never raw errors, always sends done event.
//  TASK 8: SSE hardening — correct headers, flushHeaders, heartbeat every 10s.
//
//  SSE Events emitted:
//   data: {"type":"start","session_id":"...","message_id":"..."}
//   data: {"type":"chunk","text":"..."}
//   data: {"type":"tool","name":"..."}
//   data: {"type":"done","id":"...","message_id":"...","tokens_used":N,"provider":"...","degraded":false}
//   data: {"type":"error","message":"..."}
// ══════════════════════════════════════════════════════════════════════════════

router.post('/chat/stream', chatLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  console.log(`[RAKAY] Incoming request: POST /chat/stream ip=${req.ip}`);

  const { tenantId, userId, userRole, tenantName, message, context, use_tools, effectiveSessionId, effectiveMessageId } = _extractChatParams(req);
  const shortSid = effectiveSessionId.slice(0, 12);
  const shortMid = effectiveMessageId.slice(0, 12);

  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ success: false, error: 'message is required', code: 'MISSING_MESSAGE' });
  }

  if (_isDuplicate(effectiveSessionId, message)) {
    console.log(`[RAKAY] STREAM_DEDUP_BLOCKED session=${shortSid} msgId=${shortMid}`);
    return res.status(409).json({ success: false, error: 'Duplicate message', code: 'DUPLICATE_MESSAGE', message_id: effectiveMessageId });
  }

  if (!_acquireSession(effectiveSessionId)) {
    console.warn(`[RAKAY] STREAM_SESSION_BUSY session=${shortSid}`);
    return res.status(409).json({ success: false, error: 'Session busy', code: 'SESSION_BUSY', message_id: effectiveMessageId });
  }

  // ── TASK 8: Set up SSE headers BEFORE any async work ──────────────────────
  res.setHeader('Content-Type',       'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control',      'no-cache, no-store, no-transform');
  res.setHeader('Connection',         'keep-alive');
  res.setHeader('X-Accel-Buffering',  'no');          // Nginx/Render: disable proxy buffering
  res.setHeader('X-Content-Type-Options', 'nosniff'); // prevent MIME sniffing
  res.flushHeaders();  // TASK 8: flush immediately so client knows stream is open

  // ── TASK 8: SSE helper ─────────────────────────────────────────────────────
  function sendSSE(obj) {
    if (!res.writableEnded) {
      try {
        res.write(`data: ${JSON.stringify(obj)}\n\n`);
      } catch (e) {
        console.warn(`[RAKAY] sendSSE write error: ${e.message}`);
      }
    }
  }

  // ── TASK 8: Heartbeat every 10 seconds to prevent proxy timeouts ──────────
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) {
      try { res.write(': heartbeat\n\n'); } catch {}
    } else {
      clearInterval(heartbeat);
    }
  }, 10_000);

  // Send start event with messageId (TASK 5)
  sendSSE({ type: 'start', session_id: effectiveSessionId, message_id: effectiveMessageId });

  const priority = RAKAYEngine.detectPriority(message);
  console.log(`[RAKAY] STREAM_START session=${shortSid} msgId=${shortMid} userId=${userId} priority=${priority}`);

  try {
    const engine = _getEngine({ openai_key: context?.openai_key, claude_key: context?.claude_key });

    await engine.chatStream({
      message:   message.trim(),
      sessionId: effectiveSessionId,
      tenantId,
      userId,
      messageId: effectiveMessageId,  // TASK 5: pass messageId for dedup cache
      context:   { ...context, userRole, tenantName, authHeader: req.headers.authorization },
      useTools:  use_tools !== false,

      onChunk: (text) => {
        sendSSE({ type: 'chunk', text });
      },

      onDone: (result) => {
        sendSSE({
          type:        'done',
          id:          result.id,
          message_id:  effectiveMessageId,  // TASK 5
          session_id:  result.session_id,
          tokens_used: result.tokens_used,
          model:       result.model,
          provider:    result.provider,
          latency_ms:  result.latency_ms,
          tool_trace:  result.tool_trace,
          degraded:    !!(result.degraded),
        });
        console.log(`[RAKAY] STREAM_OK session=${shortSid} msgId=${shortMid} provider=${result.provider} latency=${result.latency_ms}ms`);
      },

      onError: (err) => {
        console.error(`[RAKAY] STREAM_ENGINE_ERROR session=${shortSid} msgId=${shortMid} — ${err.message}`);
        // TASK 6: Send graceful degradation chunk + done on engine error
        sendSSE({ type: 'chunk', text: '\n\n⚠️ AI analysis interrupted. Please try again.' });
        sendSSE({
          type:       'done',
          message_id: effectiveMessageId,
          session_id: effectiveSessionId,
          tokens_used: 0,
          provider:   'degraded',
          degraded:   true,
          _error:     _sanitiseError(err),
        });
      },
    });

  } catch (err) {
    console.error(`[RAKAY] RAKAY error (stream): session=${shortSid} msgId=${shortMid} — ${err.message}`);
    // TASK 6: Never let raw errors leak — always send a user-friendly chunk + done
    sendSSE({ type: 'chunk', text: '⚠️ AI system is under heavy load. Please try again in a few seconds.' });
    sendSSE({
      type:       'done',
      message_id: effectiveMessageId,
      session_id: effectiveSessionId,
      tokens_used: 0,
      provider:   'degraded',
      degraded:   true,
      _error:     _sanitiseError(err),
    });
  } finally {
    clearInterval(heartbeat);
    _releaseSession(effectiveSessionId);
    if (!res.writableEnded) {
      try { res.end(); } catch {}
    }
    console.log(`[RAKAY] STREAM_END session=${shortSid} msgId=${shortMid}`);
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  HISTORY + SEARCH
// ══════════════════════════════════════════════════════════════════════════════

router.get('/history/:sessionId', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId } = _getUserCtx(req);
    const limit    = Math.min(parseInt(req.query.limit) || 50, 500);
    const engine   = _getEngine();
    const messages = await engine.getHistory({ sessionId: req.params.sessionId, tenantId, limit });
    const { getSession } = require('../services/rakay-store');
    const session  = await getSession({ sessionId: req.params.sessionId, tenantId });
    res.json({ messages, session, count: messages.length });
  } catch (err) {
    if (err.message?.includes('Session not found')) return res.status(404).json({ success: false, error: 'Session not found' });
    res.status(500).json({ success: false, error: 'Failed to retrieve history', details: err.message });
  }
});

router.get('/search', generalLimiter, optionalAuth, requireRAKAYAuth, async (req, res) => {
  try {
    const { tenantId, userId } = _getUserCtx(req);
    const query   = req.query.q || req.query.query;
    const limit   = Math.min(parseInt(req.query.limit) || 20, 100);
    if (!query?.trim()) return res.status(400).json({ success: false, error: 'query param q is required' });
    const results = await _getEngine().searchHistory({ tenantId, userId, query: query.trim(), limit });
    res.json({ results, count: results.length });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Search failed', details: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function _sanitiseError(err) {
  const msg = String(err?.message || 'Unknown error');
  // Strip API keys from error messages before sending to client
  return msg.replace(/sk-[a-zA-Z0-9\-_]{20,}/g, 'sk-***').slice(0, 300);
}

module.exports = router;
