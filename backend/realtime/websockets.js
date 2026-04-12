'use strict';

const { supabase } = require('../config/supabase');

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
const DETECTION_TYPES = ['Malware C2','Brute Force','SQL Injection','Port Scan','Phishing'];
const SEVERITIES = ['LOW','MEDIUM','HIGH','CRITICAL'];

function makeDetectionEvent(tenantId) {
  const type = DETECTION_TYPES[Math.floor(Math.random() * DETECTION_TYPES.length)];
  const severity = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
  const ip = randomIP();

  return {
    id: `DET-${Date.now()}`,
    title: `${type} detected`,
    severity,
    source_ip: ip,
    ioc_value: ip,
    ioc_type: 'ip',
    tenant_id: tenantId,
    timestamp: new Date().toISOString(),
  };
}

/* ─────────────────────────────────────────────── */
/* AUTH */
async function resolveSocketUser(token) {
  if (!token) return null;

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
      userId: profile.id,
      tenantId: profile.tenant_id,
      userName: profile.name,
      userRole: profile.role,
    };

  } catch {
    return null;
  }
}

/* ─────────────────────────────────────────────── */
/* 🔥 REAL IOC FETCH (NEW) */
async function getRealIOC(tenantId) {
  try {
    const { data } = await supabase
      .from('iocs')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('last_seen', { ascending: false })
      .limit(1);

    if (data && data.length > 0) {
      return {
        id: `IOC-${Date.now()}`,
        title: `IOC detected: ${data[0].value}`,
        severity: data[0].risk_score > 70 ? 'HIGH' : 'MEDIUM',
        ioc_value: data[0].value,
        ioc_type: data[0].type,
        tenant_id: tenantId,
        timestamp: new Date().toISOString(),
      };
    }
  } catch (err) {
    console.warn('[WS] IOC fetch failed:', err.message);
  }

  return null;
}

/* ─────────────────────────────────────────────── */
function initWebSockets(io) {

  /* AUTH MIDDLEWARE */
  io.use(async (socket, next) => {
    const token = socket.handshake.auth?.token;

    const profile = await resolveSocketUser(token);

    if (profile) {
      Object.assign(socket, profile, { _isGuest: false });
    } else {
      socket.userName = 'guest';
      socket._isGuest = true;
      socket.tenantId = null;
    }

    next();
  });

  /* CONNECTION */
  io.on('connection', (socket) => {

    let room = socket.tenantId ? `tenant:${socket.tenantId}` : 'tenant:guest';
    socket.join(room);

    console.log(`[WS] Connected: ${socket.userName}`);

    /* ───────────────────────────── */
    /* 🔥 DETECTION STREAM (UPGRADED) */
    socket.on('detections:start', () => {
      if (socket._interval) return;

      socket._interval = setInterval(async () => {

        let event = null;

        if (socket.tenantId) {
          event = await getRealIOC(socket.tenantId);
        }

        if (!event) {
          event = makeDetectionEvent(socket.tenantId);
        }

        socket.emit('detection:event', event);

      }, 2000);
    });

    socket.on('detections:stop', () => {
      clearInterval(socket._interval);
      socket._interval = null;
    });

    /* ───────────────────────────── */
    /* 🔥 REAL BROADCAST (NEW) */
    socket.on('ioc:broadcast', (ioc) => {
      if (socket._isGuest) return;

      io.to(`tenant:${socket.tenantId}`).emit('detection:event', {
        ...ioc,
        broadcast: true,
        timestamp: new Date().toISOString(),
      });
    });

    /* ───────────────────────────── */
    /* AUTH REFRESH (FIXED) */
    socket.on('auth:refresh', async ({ token }) => {
      const profile = await resolveSocketUser(token);

      if (!profile) {
        socket.emit('auth:refresh_failed');
        return;
      }

      // leave old room safely
      socket.leave(room);

      Object.assign(socket, profile, { _isGuest: false });

      room = `tenant:${profile.tenantId}`;
      socket.join(room);

      socket.emit('auth:refreshed');
    });

    /* ───────────────────────────── */
    socket.on('disconnect', () => {
      clearInterval(socket._interval);
      console.log(`[WS] Disconnected: ${socket.userName}`);
    });

  });

  console.log('[WS] v3.3 initialized (REAL + SIMULATED hybrid)');
}

module.exports = { initWebSockets };
