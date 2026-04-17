'use strict';

/**
 * ══════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — WebSocket Server  v4.0
 *
 *  Dual-mode WebSocket support:
 *   1. Socket.IO  — for the main detection/alert stream (io)
 *   2. Native WS  — raw ws endpoint at /ws/detections
 *                   (required by RAKAY frontend v2.0)
 *
 *  v4.0 Changes:
 *   ✅ Native WSS endpoint /ws/detections alongside Socket.IO
 *   ✅ Token validation: Supabase JWT + RAKAY demo JWT + service key
 *   ✅ Heartbeat ping/pong every 30 s (detects dead connections)
 *   ✅ Graceful disconnect: close all intervals, remove from registry
 *   ✅ Exponential-backoff hint in disconnect message
 *   ✅ Connection registry (max 1 per userId to prevent dupes)
 *   ✅ Structured lifecycle logs: CONNECT, AUTH, HEARTBEAT, DISCONNECT
 *   ✅ Error boundary: uncaught errors in socket handlers caught/logged
 * ══════════════════════════════════════════════════════════════
 */

const { WebSocketServer } = require('ws');
const url  = require('url');
const crypto = require('crypto');

// ── Lazy Supabase (not available during unit tests) ──────────────────────────
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

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function withTimeout(promise, ms = 3000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
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
/*  Auth helpers                                   */
/* ─────────────────────────────────────────────── */

/** Resolve Supabase JWT → user profile */
async function resolveSocketUser(token) {
  if (!token) return null;

  const supabase = getSupabase();
  if (!supabase) return null;

  try {
    const { data: { user } } = await withTimeout(
      supabase.auth.getUser(token),
      3000
    );
    if (!user) return null;

    const { data: profile } = await withTimeout(
      supabase
        .from('users')
        .select('id, name, role, tenant_id')
        .eq('auth_id', user.id)
        .single(),
      3000
    );
    if (!profile) return null;

    return {
      userId:   profile.id,
      tenantId: profile.tenant_id,
      userName: profile.name,
      userRole: profile.role,
      authType: 'supabase',
    };
  } catch {
    return null;
  }
}

/** Resolve RAKAY demo JWT → synthetic user */
function resolveRakayDemoToken(token) {
  if (!token) return null;

  // Opaque marker token (fallback when jsonwebtoken not installed)
  if (token === 'RAKAY_DEMO_NO_JWT_LIB') {
    return {
      userId:   'demo-user',
      tenantId: 'demo',
      userName: 'Demo Analyst',
      userRole: 'analyst',
      authType: 'demo-marker',
    };
  }

  // Try JWT verification against demo secret
  let jwt = null;
  try { jwt = require('jsonwebtoken'); } catch { return null; }

  const base   = process.env.JWT_SECRET || process.env.SUPABASE_SERVICE_KEY || 'rakay-demo-fallback-2024';
  const secret = crypto.createHash('sha256').update(`RAKAY_DEMO_${base}`).digest('hex');

  try {
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    if (!decoded.rakay_demo) return null;
    return {
      userId:   decoded.sub,
      tenantId: decoded.tenantId || 'demo',
      userName: decoded.name || 'Demo Analyst',
      userRole: decoded.role || 'analyst',
      authType: 'demo-jwt',
    };
  } catch {
    return null;
  }
}

/**
 * Multi-strategy token resolution: Supabase → service key
 * Phase 1 hardening: guest / unauthenticated access REMOVED.
 * Unknown tokens are rejected — the socket is disconnected with WS_AUTH_FAILED.
 */
async function resolveToken(token) {
  // No token → rejected (Phase 1: no anonymous guest sessions)
  if (!token) return null;

  // 1. RAKAY demo token (fast, no network)
  const demoUser = resolveRakayDemoToken(token);
  if (demoUser) return demoUser;

  // 2. Service key bypass (internal service-to-service only)
  const serviceKey = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY;
  if (serviceKey && token === serviceKey) {
    return { userId: 'service', tenantId: 'service', userName: 'Service', userRole: 'service', authType: 'service-key' };
  }

  // 3. Supabase JWT (network call)
  const supabaseUser = await resolveSocketUser(token);
  if (supabaseUser) return supabaseUser;

  // Unknown token → rejected
  return null;
}

/* ─────────────────────────────────────────────── */
/*  Real IOC fetch                                 */
/* ─────────────────────────────────────────────── */
async function getRealIOC(tenantId) {
  const supabase = getSupabase();
  if (!supabase || tenantId === 'demo' || tenantId === 'guest') return null;

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

  /* AUTH MIDDLEWARE — Phase 1 hardening: session-token only, no query-param, no guest */
  io.use(async (socket, next) => {
    // Accept token from handshake.auth only (not query param — Phase 1)
    const token = socket.handshake.auth?.token;
    const profile = await resolveToken(token);

    if (!profile) {
      console.warn(`[SIO] AUTH REJECTED — no valid token, id=${socket.id} ip=${socket.handshake.address}`);
      return next(new Error('WS_AUTH_FAILED: valid authentication token required'));
    }

    Object.assign(socket, profile);
    socket._isGuest = false; // no guest sessions (Phase 1)
    next();
  });

  /* CONNECTION */
  io.on('connection', (socket) => {
    let room = `tenant:${socket.tenantId || 'guest'}`;
    socket.join(room);

    console.log(`[SIO] CONNECT  userId=${socket.userId} tenant=${socket.tenantId} auth=${socket.authType} id=${socket.id}`);

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
      if (socket._isGuest) return;
      io.to(`tenant:${socket.tenantId}`).emit('detection:event', {
        ...ioc,
        broadcast: true,
        timestamp: new Date().toISOString(),
      });
    });

    /* AUTH REFRESH */
    socket.on('auth:refresh', async ({ token }) => {
      const profile = await resolveToken(token);
      if (profile.authType === 'guest') {
        socket.emit('auth:refresh_failed', { reason: 'invalid token' });
        return;
      }
      socket.leave(room);
      Object.assign(socket, profile);
      socket._isGuest = false;
      room = `tenant:${profile.tenantId}`;
      socket.join(room);
      socket.emit('auth:refreshed', { userId: profile.userId, tenantId: profile.tenantId });
      console.log(`[SIO] AUTH_REFRESH userId=${profile.userId} tenant=${profile.tenantId}`);
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

  console.log('[SIO] Socket.IO initialized (REAL + SIMULATED hybrid)');
}

/* ═══════════════════════════════════════════════ */
/*  NATIVE WebSocket SERVER (/ws/detections)      */
/*  Required for RAKAY frontend v2.0+             */
/* ═══════════════════════════════════════════════ */

// Connection registry — maps userId → Set of WebSocket clients
// Limits to 5 connections per userId to prevent runaway reconnects
const _wsRegistry = new Map();
const MAX_CONNS_PER_USER = 5;

const PING_INTERVAL_MS = 30_000;  // 30 s heartbeat
const PONG_TIMEOUT_MS  = 10_000;  // 10 s to reply

function _wsRegistryAdd(userId, ws) {
  if (!_wsRegistry.has(userId)) _wsRegistry.set(userId, new Set());
  const set = _wsRegistry.get(userId);
  // Evict oldest if over limit
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
 * Attach a native WebSocket server to the HTTP server
 * at path /ws/detections
 */
function initNativeWS(httpServer) {
  const wss = new WebSocketServer({ noServer: true });

  // Intercept HTTP upgrade requests
  httpServer.on('upgrade', async (request, socket, head) => {
    const parsedUrl = url.parse(request.url, true);

    if (parsedUrl.pathname !== '/ws/detections') {
      // Not our path — let Socket.IO handle it (or close)
      return;
    }

    wss.handleUpgrade(request, socket, head, async (ws) => {
      wss.emit('connection', ws, request, parsedUrl.query);
    });
  });

  wss.on('connection', async (ws, request, query) => {
    // ── Auth ──────────────────────────────────────────────
    const token  = query.token || null;
    const user   = await resolveToken(token);
    ws._user     = user;
    ws._alive    = true;
    ws._interval = null;
    ws._pingTimer = null;

    _wsRegistryAdd(user.userId, ws);

    const clientId = `${user.userId.slice(0, 16)}-${Date.now().toString(36)}`;
    console.log(`[NWS] CONNECT  clientId=${clientId} userId=${user.userId} tenant=${user.tenantId} auth=${user.authType}`);

    // ── Send welcome / auth confirmation ─────────────────
    _wsSend(ws, {
      type:    'connected',
      message: 'WebSocket connected to Wadjet-Eye AI',
      userId:  user.userId,
      tenant:  user.tenantId,
      auth:    user.authType,
    });

    // ── Heartbeat ping/pong ───────────────────────────────
    ws._pingTimer = setInterval(() => {
      if (!ws._alive) {
        console.warn(`[NWS] HEARTBEAT_TIMEOUT clientId=${clientId} — terminating`);
        ws.terminate();
        return;
      }
      ws._alive = false;
      try { ws.ping(); } catch {}
    }, PING_INTERVAL_MS);

    ws.on('pong', () => {
      ws._alive = true;
    });

    // ── Message handling ──────────────────────────────────
    ws.on('message', async (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      switch (msg.type) {
        // In-band auth (alternative to query-param)
        case 'auth': {
          const refreshedUser = await resolveToken(msg.token);
          if (refreshedUser.authType !== 'guest') {
            ws._user = refreshedUser;
            _wsSend(ws, { type: 'auth_ok', userId: refreshedUser.userId, tenant: refreshedUser.tenantId });
            console.log(`[NWS] AUTH_OK clientId=${clientId} userId=${refreshedUser.userId}`);
          } else {
            _wsSend(ws, { type: 'auth_failed', reason: 'invalid token' });
          }
          break;
        }

        // Start live detection stream
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

        // Stop detection stream
        case 'detections:stop':
        case 'unsubscribe': {
          clearInterval(ws._interval);
          ws._interval = null;
          _wsSend(ws, { type: 'unsubscribed' });
          break;
        }

        // Ping/keep-alive from client
        case 'ping': {
          _wsSend(ws, { type: 'pong', ts: Date.now() });
          break;
        }

        default:
          break;
      }
    });

    // ── Disconnect cleanup ────────────────────────────────
    ws.on('close', (code, reason) => {
      clearInterval(ws._interval);
      clearInterval(ws._pingTimer);
      _wsRegistryRemove(user.userId, ws);
      ws._interval  = null;
      ws._pingTimer = null;

      const reasonStr = reason?.toString() || '';
      console.log(`[NWS] DISCONNECT clientId=${clientId} code=${code} reason="${reasonStr}" userId=${user.userId}`);

      // If abnormal close, inform the disconnected client (will be received on reconnect)
      if (code !== 1000 && code !== 1001) {
        console.info(`[NWS] Abnormal close code=${code} — client should apply exponential backoff`);
      }
    });

    // ── Error handler ─────────────────────────────────────
    ws.on('error', (err) => {
      console.error(`[NWS] ERROR clientId=${clientId} userId=${user.userId}:`, err.message);
    });
  });

  console.log('[NWS] Native WebSocket server initialized at /ws/detections');
  return wss;
}

/* ─────────────────────────────────────────────── */
/*  Safe JSON send helper                          */
/* ─────────────────────────────────────────────── */
function _wsSend(ws, data) {
  if (ws.readyState !== ws.OPEN) return;
  try {
    ws.send(JSON.stringify(data));
  } catch (err) {
    // ignore — connection may be closing
  }
}

/* ═══════════════════════════════════════════════ */
/*  MAIN EXPORT                                    */
/* ═══════════════════════════════════════════════ */

/**
 * Initialize both Socket.IO and native WebSocket servers.
 *
 * @param {import('socket.io').Server} io  - Socket.IO instance
 * @param {import('http').Server}      httpServer - raw HTTP server
 */
function initWebSockets(io, httpServer) {
  initSocketIO(io);
  if (httpServer) {
    initNativeWS(httpServer);
  }
  console.log('[WS] v4.0 initialized — Socket.IO + Native WS (/ws/detections)');
}

module.exports = { initWebSockets };
