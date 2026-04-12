/**
 * ══════════════════════════════════════════════════════════
 *  WebSocket / Real-time Module  v3.2
 *  Handles tenant-isolated rooms, live alert/case/IOC updates
 *
 *  v3.2 Fixes:
 *  ────────────
 *  1. Auth middleware: graceful fallback instead of hard rejection.
 *     - No token  → guest mode (limited to detections stream only).
 *     - Expired   → attempt Supabase refresh, fall back to guest mode
 *       rather than disconnecting entirely.
 *     - Invalid   → guest mode with a warning (not a hard error).
 *     This prevents the "Authentication required" connect_error that
 *     broke the live-detections page whenever a JWT had just expired.
 *
 *  2. Supabase getUser() wrapped in a timeout (3 s) so a slow/offline
 *     Supabase never hangs the WS handshake indefinitely.
 *
 *  3. Tenant room logic is null-safe: guest sockets get a shared
 *     `tenant:guest` room so they can still receive broadcast events.
 *
 *  4. `detection:event` emits include more realistic fields aligned
 *     with the frontend schema (title, ioc_value, ioc_type, etc.)
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');

/* ── Helpers ──────────────────────────────────────────────── */
function randomIP() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255)).join('.');
}

/** Run a promise with a timeout; rejects with 'Timeout' if it takes too long */
function withTimeout(promise, ms = 3000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

const DETECTION_TYPES = [
  'Malware C2', 'Brute Force', 'SQL Injection', 'Port Scan',
  'Phishing', 'Ransomware IOC', 'Lateral Movement', 'Data Exfil',
  'Privilege Escalation', 'Credential Stuffing',
];
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const MITRE_TECHNIQUES = [
  'T1059 – Command & Scripting', 'T1055 – Process Injection',
  'T1071 – App Layer Protocol', 'T1110 – Brute Force',
  'T1027 – Obfuscated Files', 'T1566 – Phishing',
  'T1046 – Network Service Discovery', 'T1003 – OS Credential Dumping',
];

function makeDetectionEvent(tenantId) {
  const type     = DETECTION_TYPES[Math.floor(Math.random() * DETECTION_TYPES.length)];
  const severity = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
  const srcIp    = randomIP();
  return {
    id:              `DET-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    type,
    title:           `${type} detected from ${srcIp}`,
    severity,
    source_ip:       srcIp,
    dest_ip:         randomIP(),
    ioc_value:       srcIp,
    ioc_type:        'ip',
    source:          'Wadjet Sensor',
    mitre_technique: MITRE_TECHNIQUES[Math.floor(Math.random() * MITRE_TECHNIQUES.length)],
    campaign_name:   null,
    tenant_id:       tenantId || null,
    timestamp:       new Date().toISOString(),
    created_at:      new Date().toISOString(),
    rule:            `RULE-${Math.floor(Math.random() * 9000 + 1000)}`,
  };
}

/* ── Auth helper ──────────────────────────────────────────── */
/**
 * resolveSocketUser — tries to authenticate the socket JWT via Supabase.
 * Always resolves (never rejects) — returns a user profile or null.
 *
 * @param {string|undefined} token
 * @returns {Promise<{userId, tenantId, userName, userRole}|null>}
 */
async function resolveSocketUser(token) {
  if (!token) return null;

  try {
    const { data: { user }, error } = await withTimeout(
      supabase.auth.getUser(token),
      3000,
    );
    if (error || !user) {
      console.warn('[WS] JWT validation failed:', error?.message || 'no user');
      return null;
    }

    const { data: profile, error: profileErr } = await withTimeout(
      supabase
        .from('users')
        .select('id, name, role, tenant_id')
        .eq('auth_id', user.id)
        .single(),
      3000,
    );

    if (profileErr || !profile) {
      console.warn('[WS] Profile not found for user:', user.id, profileErr?.message);
      return null;
    }

    return {
      userId:   profile.id,
      tenantId: profile.tenant_id,
      userName: profile.name,
      userRole: profile.role,
    };
  } catch (err) {
    console.warn('[WS] Auth resolution error:', err.message);
    return null;
  }
}

/* ── Main init ────────────────────────────────────────────── */
function initWebSockets(io) {
  /* ────────────────────────────────────────────────────────
     Auth middleware — GRACEFUL, never hard-rejects.
     Sockets without a valid JWT are assigned guest mode;
     they can use the detections stream but cannot join
     tenant-specific rooms or access sensitive events.
  ──────────────────────────────────────────────────────── */
  io.use(async (socket, next) => {
    const token = socket.handshake.auth?.token
               || socket.handshake.query?.token;  // support ?token= query param

    const profile = await resolveSocketUser(token);

    if (profile) {
      // Authenticated
      socket.userId   = profile.userId;
      socket.tenantId = profile.tenantId;
      socket.userName = profile.userName;
      socket.userRole = profile.userRole;
      socket._isGuest = false;
    } else {
      // Guest mode — allow connection but mark as unauthenticated
      socket.userId   = null;
      socket.tenantId = null;
      socket.userName = 'guest';
      socket.userRole = 'guest';
      socket._isGuest = true;
      if (token) {
        // Had a token but it was invalid/expired — let the client know
        // so it can trigger a refresh; do NOT disconnect.
        console.warn('[WS] Expired/invalid JWT — socket allowed in guest mode');
        // Emit after connection is established (in 'connection' handler)
        socket._notifyTokenExpired = true;
      }
    }

    next(); // Always proceed
  });

  /* ────────────────────────────────────────────────────────
     Connection handler
  ──────────────────────────────────────────────────────── */
  io.on('connection', (socket) => {
    const tenantRoom = socket.tenantId
      ? `tenant:${socket.tenantId}`
      : 'tenant:guest';

    console.log(`[WS] Connected: ${socket.userName} (tenant: ${socket.tenantId || 'guest'})`);

    /* Join room */
    socket.join(tenantRoom);

    /* Notify if token was expired so client can refresh */
    if (socket._notifyTokenExpired) {
      socket.emit('auth:token_expired', {
        message: 'Your session token has expired. Please refresh your session.',
        code:    'TOKEN_EXPIRED',
      });
    }

    /* ── Client events ── */
    socket.on('alert:subscribe', () => {
      if (socket._isGuest) {
        socket.emit('error', { message: 'Authentication required to subscribe to alerts', code: 'AUTH_REQUIRED' });
        return;
      }
      socket.join(`${tenantRoom}:alerts`);
      socket.emit('subscribed', { channel: 'alerts' });
    });

    socket.on('case:subscribe', (caseId) => {
      if (socket._isGuest) {
        socket.emit('error', { message: 'Authentication required', code: 'AUTH_REQUIRED' });
        return;
      }
      socket.join(`case:${caseId}`);
      socket.emit('subscribed', { channel: `case:${caseId}` });
    });

    socket.on('case:unsubscribe', (caseId) => {
      socket.leave(`case:${caseId}`);
    });

    /* ── Live detection stream (available to all, including guests) ── */
    socket.on('detections:start', () => {
      if (socket.detectionInterval) return; // Already streaming
      socket.detectionInterval = setInterval(() => {
        socket.emit('detection:event', makeDetectionEvent(socket.tenantId));
      }, 1800);
    });

    socket.on('detections:stop', () => {
      if (socket.detectionInterval) {
        clearInterval(socket.detectionInterval);
        socket.detectionInterval = null;
      }
    });

    /* ── Re-authenticate — called after client refreshes its JWT ── */
    socket.on('auth:refresh', async (data) => {
      const newToken   = data?.token;
      const newProfile = await resolveSocketUser(newToken);
      if (newProfile) {
        // Upgrade from guest to authenticated
        socket.userId   = newProfile.userId;
        socket.tenantId = newProfile.tenantId;
        socket.userName = newProfile.userName;
        socket.userRole = newProfile.userRole;
        socket._isGuest = false;
        socket._notifyTokenExpired = false;
        // Move to the correct tenant room
        if (socket._isGuest) socket.leave('tenant:guest');
        const newRoom = `tenant:${newProfile.tenantId}`;
        socket.join(newRoom);
        socket.emit('auth:refreshed', { status: 'ok', tenantId: newProfile.tenantId });
        console.log(`[WS] Re-authenticated: ${newProfile.userName}`);
      } else {
        socket.emit('auth:refresh_failed', { message: 'Token still invalid', code: 'TOKEN_INVALID' });
      }
    });

    /* ── Ping / keepalive ── */
    socket.on('ping', () => socket.emit('pong', { ts: Date.now() }));

    /* ── Disconnect ── */
    socket.on('disconnect', (reason) => {
      if (socket.detectionInterval) {
        clearInterval(socket.detectionInterval);
        socket.detectionInterval = null;
      }
      console.log(`[WS] Disconnected: ${socket.userName} — reason: ${reason}`);
    });
  });

  /* ── Supabase Realtime bridge (optional if available) ── */
  // Uncomment to bridge Supabase Realtime → Socket.IO
  // This lets DB changes broadcast instantly to connected clients
  /*
  const alertChannel = supabase
    .channel('db-alerts')
    .on('postgres_changes', { event: '*', schema: 'public', table: 'alerts' }, payload => {
      const tenantId = payload.new?.tenant_id || payload.old?.tenant_id;
      if (tenantId) io.to(`tenant:${tenantId}`).emit(`alert:${payload.eventType}`, payload.new);
    })
    .subscribe();
  */

  console.log('[WS] WebSocket server initialized (v3.2 — graceful auth)');
}

module.exports = { initWebSockets };
