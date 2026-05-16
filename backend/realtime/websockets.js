'use strict';

/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — WebSocket Server  v5.0  (Security Hardened)
 *  backend/realtime/websockets.js
 *
 *  Security fixes (Audit Phase 0):
 *  ─────────────────────────────────────────────────────────────────
 *  FIX-002: Demo/marker token bypass REMOVED.
 *    • resolveRakayDemoToken() removed entirely — the
 *      `RAKAY_DEMO_NO_JWT_LIB` opaque marker and any unauthenticated
 *      "demo" path no longer exist.
 *    • Missing JWT_SECRET on startup is now a FATAL ERROR: the process
 *      exits with code 1 rather than silently degrading to insecure
 *      behaviour.  This ensures misconfigured deployments are caught
 *      immediately at boot, not silently in production.
 *    • Unknown tokens are now REJECTED with code 4401 (not silently
 *      accepted as "guest").  The previous guest fallback allowed any
 *      anonymous WebSocket connection to receive live intelligence data.
 *    • Service-key bypass is retained for internal microservice
 *      communication but now requires the key to be at least 32 chars.
 *
 *  Dual-mode WebSocket support retained:
 *   1. Socket.IO  — for the main detection/alert stream (io)
 *   2. Native WS  — raw ws endpoint at /ws/detections
 *                   (required by RAKAY frontend v2.0+)
 *
 *  v5.0 Changes vs v4.0:
 *   ✅ Demo token bypass removed — hard auth required
 *   ✅ Startup fatal error if JWT_SECRET absent
 *   ✅ Anonymous guest connections rejected (code 4401)
 *   ✅ Service-key minimum length enforced (32 chars)
 *   ✅ Connection origin validated against CORS allowlist
 *   ✅ All auth decisions logged with structured fields
 * ══════════════════════════════════════════════════════════════════
 */

const { WebSocketServer } = require('ws');
const url    = require('url');
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

// ── FIX-002: Fatal error on missing JWT_SECRET ─────────────────────
// This block runs at module load time (server startup).
// If neither JWT secret is configured, the server cannot safely verify
// WebSocket tokens — so we fail fast rather than run insecurely.
const _WS_JWT_SECRET     = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;
const _WS_ALT_JWT_SECRET = (() => {
  const s = process.env.SUPABASE_JWT_SECRET;
  const c = process.env.JWT_SECRET;
  return (s && c && s !== c) ? (s ? c : s) : null;
})();

if (!_WS_JWT_SECRET) {
  // Non-recoverable configuration error — exit immediately.
  console.error('[WS] FATAL: JWT_SECRET (or SUPABASE_JWT_SECRET) is not set.');
  console.error('[WS] WebSocket connections cannot be authenticated without a JWT secret.');
  console.error('[WS] Set JWT_SECRET in your environment and restart the server.');
  process.exit(1);
}

// ── Allowed WebSocket origins ───────────────────────────────────────
const _WS_ALLOWED_ORIGINS = new Set(
  (process.env.CORS_ALLOWED_ORIGINS || 'https://wadjet-eye.vercel.app,http://localhost:3000,http://localhost:5173')
    .split(',').map(s => s.trim()).filter(Boolean)
);

// ── Service key (internal microservices only) ──────────────────────
const _SERVICE_KEY = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY || null;

// ── Lazy Supabase (not available during unit tests) ──────────────────
let _supabase = null;
function getSupabase() {
  if (_supabase) return _supabase;
  try { _supabase = require('../config/supabase').supabase; } catch {}
  return _supabase;
}

/* ─────────────────────────────────────────────── */
/*  Helpers                                        */
/* ─────────────────────────────────────────────── */

function randomIP() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255)).join('.');
}

async function withTimeout(promise, ms = 3000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

/**
 * validateOrigin — check the WebSocket connection's Origin header.
 * @param {import('http').IncomingMessage} request
 * @returns {boolean}
 */
function validateOrigin(request) {
  const origin = request.headers['origin'] || '';
  if (!origin) return true; // same-origin or server-to-server (no header)
  if (_WS_ALLOWED_ORIGINS.has(origin)) return true;
  // Allow vercel.app preview deployments
  if (/^https:\/\/[a-z0-9-]+-[a-z0-9]+\.vercel\.app$/.test(origin)) return true;
  console.warn(`[WS] Rejected origin: "${origin}"`);
  return false;
}

/* ─────────────────────────────────────────────── */
/*  Detection event generation                     */
/* ─────────────────────────────────────────────── */
const DETECTION_TYPES = ['Malware C2', 'Brute Force', 'SQL Injection', 'Port Scan', 'Phishing'];
const SEVERITIES      = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function makeDetectionEvent(tenantId) {
  const type     = DETECTION_TYPES[Math.floor(Math.random() * DETECTION_TYPES.length)];
  const severity = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
  const ip       = randomIP();
  return {
    id:         `DET-${Date.now()}`,
    title:      `${type} detected`,
    severity,
    source_ip:  ip,
    ioc_value:  ip,
    ioc_type:   'ip',
    tenant_id:  tenantId,
    timestamp:  new Date().toISOString(),
  };
}

/* ─────────────────────────────────────────────── */
/*  Auth helpers  (FIX-002)                        */
/* ─────────────────────────────────────────────── */

/**
 * resolveJwtLocal — verify a JWT locally without network calls.
 * Tries primary secret first, then alt secret if the first fails
 * with a non-expiry error.
 *
 * @param {string} token
 * @returns {{ user: object, authType: string } | null}
 */
function resolveJwtLocal(token) {
  const opts = { algorithms: ['HS256'], clockTolerance: 60 };

  let decoded = null;
  let lastErr = null;

  try {
    decoded = jwt.verify(token, _WS_JWT_SECRET, opts);
  } catch (err1) {
    lastErr = err1;
    if (err1.name !== 'TokenExpiredError' && _WS_ALT_JWT_SECRET) {
      try {
        decoded = jwt.verify(token, _WS_ALT_JWT_SECRET, opts);
        lastErr = null;
      } catch (err2) {
        lastErr = err2.name === 'TokenExpiredError' ? err2 : err1;
      }
    }
  }

  if (!decoded) {
    if (lastErr?.name === 'TokenExpiredError') {
      console.warn('[WS] Token expired');
    }
    return null;
  }

  return {
    userId:   decoded.sub || 'unknown',
    tenantId: decoded.tenant_id || decoded.tenantId || 'default',
    email:    decoded.email || null,
    role:     decoded.role || 'viewer',
    authType: 'jwt-local',
  };
}

/**
 * resolveSocketUser — verify via Supabase auth service (network).
 * Only used when local JWT check is inconclusive.
 *
 * @param {string} token
 * @returns {Promise<object|null>}
 */
async function resolveSocketUser(token) {
  if (!token) return null;
  const supabase = getSupabase();
  if (!supabase) return null;

  try {
    const { data: { user } } = await withTimeout(supabase.auth.getUser(token), 3000);
    if (!user) return null;

    const { data: profile } = await withTimeout(
      supabase.from('users').select('id, name, role, tenant_id').eq('auth_id', user.id).single(),
      3000
    );
    if (!profile) return null;

    return {
      userId:   profile.id,
      tenantId: profile.tenant_id,
      email:    user.email,
      role:     profile.role,
      authType: 'supabase',
    };
  } catch {
    return null;
  }
}

/**
 * resolveToken — authenticate a WebSocket connection token.
 *
 * FIX-002: Demo bypass removed. Resolution order:
 *  1. Service key (internal microservices)
 *  2. JWT local verification (fast, zero-network)
 *  3. Supabase auth service (network fallback)
 *  4. REJECT — returns null (caller closes connection with 4401)
 *
 * @param {string|null} token
 * @returns {Promise<object|null>}  null = not authenticated
 */
async function resolveToken(token) {
  if (!token) return null;

  // 1. Service key (internal only, minimum 32 chars)
  if (_SERVICE_KEY && _SERVICE_KEY.length >= 32 && token === _SERVICE_KEY) {
    return { userId: 'service', tenantId: 'service', email: null, role: 'service', authType: 'service-key' };
  }

  // 2. Local JWT (fast path — covers 99% of requests)
  const localUser = resolveJwtLocal(token);
  if (localUser) return localUser;

  // 3. Supabase auth network fallback
  const supabaseUser = await resolveSocketUser(token);
  if (supabaseUser) return supabaseUser;

  // 4. All strategies failed — reject
  return null;
}

/* ─────────────────────────────────────────────── */
/*  Real IOC fetch                                 */
/* ─────────────────────────────────────────────── */
async function getRealIOC(tenantId) {
  const supabase = getSupabase();
  if (!supabase) return null;

  try {
    const { data } = await supabase
      .from('iocs')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('last_seen', { ascending: false })
      .limit(1);

    if (data && data.length > 0) {
      return {
        id:        `IOC-${Date.now()}`,
        title:     `IOC detected: ${data[0].value}`,
        severity:  data[0].risk_score > 70 ? 'HIGH' : 'MEDIUM',
        ioc_value: data[0].value,
        ioc_type:  data[0].type,
        tenant_id: tenantId,
        timestamp: new Date().toISOString(),
      };
    }
  } catch (err) {
    console.warn('[WS] IOC fetch failed:', err.message);
  }
  return null;
}

/* ═══════════════════════════════════════════════ */
/*  SOCKET.IO HANDLER                             */
/* ═══════════════════════════════════════════════ */
function initSocketIO(io) {

  /* AUTH MIDDLEWARE */
  io.use(async (socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.['x-access-token'];
    const user  = await resolveToken(token);

    if (!user) {
      console.warn(`[SIO] AUTH_FAILED — closing connection id=${socket.id}`);
      return next(new Error('Authentication required'));
    }

    Object.assign(socket, user);
    socket._isGuest = false;
    console.log(`[SIO] AUTH_OK userId=${user.userId} tenant=${user.tenantId} auth=${user.authType} id=${socket.id}`);
    next();
  });

  /* CONNECTION */
  io.on('connection', (socket) => {
    let room = `tenant:${socket.tenantId}`;
    socket.join(room);

    console.log(`[SIO] CONNECT userId=${socket.userId} tenant=${socket.tenantId} auth=${socket.authType} id=${socket.id}`);

    /* DETECTION STREAM */
    socket.on('detections:start', () => {
      if (socket._interval) return;
      socket._interval = setInterval(async () => {
        try {
          let event = await getRealIOC(socket.tenantId);
          if (!event) event = makeDetectionEvent(socket.tenantId);
          socket.emit('detection:event', event);
        } catch (err) {
          console.error('[SIO] Detection emit error:', err.message);
        }
      }, 2000);
    });

    socket.on('detections:stop', () => {
      clearInterval(socket._interval);
      socket._interval = null;
    });

    /* IOC BROADCAST */
    socket.on('ioc:broadcast', (ioc) => {
      io.to(`tenant:${socket.tenantId}`).emit('detection:event', {
        ...ioc,
        broadcast: true,
        timestamp: new Date().toISOString(),
      });
    });

    /* AUTH REFRESH */
    socket.on('auth:refresh', async ({ token }) => {
      const user = await resolveToken(token);
      if (!user) {
        socket.emit('auth:refresh_failed', { reason: 'invalid token' });
        return;
      }
      socket.leave(room);
      Object.assign(socket, user);
      room = `tenant:${user.tenantId}`;
      socket.join(room);
      socket.emit('auth:refreshed', { userId: user.userId, tenantId: user.tenantId });
      console.log(`[SIO] AUTH_REFRESH userId=${user.userId} tenant=${user.tenantId}`);
    });

    /* DISCONNECT */
    socket.on('disconnect', (reason) => {
      clearInterval(socket._interval);
      console.log(`[SIO] DISCONNECT userId=${socket.userId} reason=${reason}`);
    });

    /* ERROR */
    socket.on('error', (err) => {
      console.error(`[SIO] ERROR userId=${socket.userId}:`, err.message);
    });
  });

  console.log('[SIO] Socket.IO v5.0 initialized (auth required, demo bypass removed)');
}

/* ═══════════════════════════════════════════════ */
/*  NATIVE WebSocket SERVER (/ws/detections)      */
/* ═══════════════════════════════════════════════ */

const _wsRegistry        = new Map();
const MAX_CONNS_PER_USER = 5;
const PING_INTERVAL_MS   = 30_000;

function _wsRegistryAdd(userId, ws) {
  if (!_wsRegistry.has(userId)) _wsRegistry.set(userId, new Set());
  const set = _wsRegistry.get(userId);
  if (set.size >= MAX_CONNS_PER_USER) {
    const [oldest] = set;
    oldest.terminate();
    set.delete(oldest);
    console.warn(`[NWS] Evicted oldest connection for userId=${userId} (limit=${MAX_CONNS_PER_USER})`);
  }
  set.add(ws);
}

function _wsRegistryRemove(userId, ws) {
  const set = _wsRegistry.get(userId);
  if (set) {
    set.delete(ws);
    if (set.size === 0) _wsRegistry.delete(userId);
  }
}

/**
 * initNativeWS — attach a native WebSocket server at /ws/detections.
 * FIX-002: Unknown tokens close with code 4401 instead of guest fallback.
 *
 * @param {import('http').Server} httpServer
 */
function initNativeWS(httpServer) {
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', async (request, socket, head) => {
    const parsedUrl = url.parse(request.url, true);

    if (parsedUrl.pathname !== '/ws/detections') return;

    // FIX-002: validate connection origin before upgrading
    if (!validateOrigin(request)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request, parsedUrl.query);
    });
  });

  wss.on('connection', async (ws, request, query) => {
    const token = query.token || null;
    const user  = await resolveToken(token);

    // FIX-002: Reject unauthenticated connections
    if (!user) {
      console.warn(`[NWS] AUTH_FAILED — closing unauthenticated connection`);
      _wsSend(ws, { type: 'auth_failed', reason: 'Authentication required', code: 4401 });
      ws.close(4401, 'Authentication required');
      return;
    }

    ws._user     = user;
    ws._alive    = true;
    ws._interval = null;
    ws._pingTimer = null;

    _wsRegistryAdd(user.userId, ws);

    const clientId = `${user.userId.slice(0, 16)}-${Date.now().toString(36)}`;
    console.log(`[NWS] CONNECT clientId=${clientId} userId=${user.userId} tenant=${user.tenantId} auth=${user.authType}`);

    _wsSend(ws, {
      type:    'connected',
      message: 'WebSocket connected to Wadjet-Eye AI',
      userId:  user.userId,
      tenant:  user.tenantId,
      auth:    user.authType,
    });

    // ── Heartbeat ─────────────────────────────────────────────────
    ws._pingTimer = setInterval(() => {
      if (!ws._alive) {
        console.warn(`[NWS] HEARTBEAT_TIMEOUT clientId=${clientId} — terminating`);
        ws.terminate();
        return;
      }
      ws._alive = false;
      try { ws.ping(); } catch {}
    }, PING_INTERVAL_MS);

    ws.on('pong', () => { ws._alive = true; });

    // ── Message handling ──────────────────────────────────────────
    ws.on('message', async (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      switch (msg.type) {
        case 'auth': {
          const refreshedUser = await resolveToken(msg.token);
          if (refreshedUser) {
            ws._user = refreshedUser;
            _wsSend(ws, { type: 'auth_ok', userId: refreshedUser.userId, tenant: refreshedUser.tenantId });
            console.log(`[NWS] AUTH_OK clientId=${clientId} userId=${refreshedUser.userId}`);
          } else {
            _wsSend(ws, { type: 'auth_failed', reason: 'invalid token', code: 4401 });
          }
          break;
        }

        case 'detections:start':
        case 'subscribe': {
          if (ws._interval) break;
          ws._interval = setInterval(async () => {
            if (ws.readyState !== ws.OPEN) return;
            try {
              let event = await getRealIOC(ws._user.tenantId);
              if (!event) event = makeDetectionEvent(ws._user.tenantId);
              _wsSend(ws, { type: 'detection:event', ...event });
            } catch (err) {
              console.error('[NWS] Emit error:', err.message);
            }
          }, 2500);
          _wsSend(ws, { type: 'subscribed', message: 'Detection stream started' });
          break;
        }

        case 'detections:stop':
        case 'unsubscribe': {
          clearInterval(ws._interval);
          ws._interval = null;
          _wsSend(ws, { type: 'unsubscribed' });
          break;
        }

        case 'ping': {
          _wsSend(ws, { type: 'pong', ts: Date.now() });
          break;
        }

        default:
          break;
      }
    });

    // ── Disconnect cleanup ────────────────────────────────────────
    ws.on('close', (code, reason) => {
      clearInterval(ws._interval);
      clearInterval(ws._pingTimer);
      _wsRegistryRemove(user.userId, ws);
      ws._interval  = null;
      ws._pingTimer = null;
      console.log(`[NWS] DISCONNECT clientId=${clientId} code=${code} reason="${reason?.toString() || ''}" userId=${user.userId}`);
      if (code !== 1000 && code !== 1001) {
        console.info(`[NWS] Abnormal close code=${code} — client should apply exponential backoff`);
      }
    });

    ws.on('error', (err) => {
      console.error(`[NWS] ERROR clientId=${clientId} userId=${user.userId}:`, err.message);
    });
  });

  console.log('[NWS] Native WebSocket v5.0 initialized at /ws/detections (demo bypass removed)');
  return wss;
}

/* ─────────────────────────────────────────────── */
/*  Safe JSON send helper                          */
/* ─────────────────────────────────────────────── */
function _wsSend(ws, data) {
  if (ws.readyState !== ws.OPEN) return;
  try { ws.send(JSON.stringify(data)); } catch {}
}

/* ═══════════════════════════════════════════════ */
/*  MAIN EXPORT                                    */
/* ═══════════════════════════════════════════════ */

/**
 * initWebSockets — initialize Socket.IO and native WS servers.
 *
 * @param {import('socket.io').Server} io
 * @param {import('http').Server}      httpServer
 */
function initWebSockets(io, httpServer) {
  initSocketIO(io);
  if (httpServer) initNativeWS(httpServer);
  console.log('[WS] v5.0 initialized — Socket.IO + Native WS (/ws/detections)');
}

module.exports = { initWebSockets };
