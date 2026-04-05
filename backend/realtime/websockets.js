/**
 * ══════════════════════════════════════════════════════════
 *  WebSocket / Real-time Module
 *  Handles tenant-isolated rooms, live alert/case/IOC updates
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');

function initWebSockets(io) {
  /* ── Auth middleware for socket connections ── */
  io.use(async (socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication required'));

    try {
      const { data: { user }, error } = await supabase.auth.getUser(token);
      if (error || !user) return next(new Error('Invalid token'));

      const { data: profile } = await supabase
        .from('users')
        .select('id, name, role, tenant_id')
        .eq('auth_id', user.id)
        .single();

      if (!profile) return next(new Error('User not found'));

      socket.userId   = profile.id;
      socket.tenantId = profile.tenant_id;
      socket.userName = profile.name;
      socket.userRole = profile.role;
      next();
    } catch (err) {
      next(new Error('Auth error'));
    }
  });

  /* ── Connection handler ── */
  io.on('connection', (socket) => {
    const tenantRoom = `tenant:${socket.tenantId}`;
    console.log(`[WS] Connected: ${socket.userName} (${socket.tenantId})`);

    /* Join tenant-isolated room */
    socket.join(tenantRoom);

    /* ── Client events ── */
    socket.on('alert:subscribe', () => {
      socket.join(`${tenantRoom}:alerts`);
      socket.emit('subscribed', { channel: 'alerts' });
    });

    socket.on('case:subscribe', (caseId) => {
      socket.join(`case:${caseId}`);
      socket.emit('subscribed', { channel: `case:${caseId}` });
    });

    socket.on('case:unsubscribe', (caseId) => {
      socket.leave(`case:${caseId}`);
    });

    /* ── Live detection stream ── */
    socket.on('detections:start', () => {
      if (socket.detectionInterval) return;
      const detectionTypes = ['Malware C2', 'Brute Force', 'SQL Injection', 'Port Scan', 'Phishing', 'Ransomware IOC', 'Lateral Movement', 'Data Exfil'];
      const severities     = ['LOW','MEDIUM','HIGH','CRITICAL'];

      socket.detectionInterval = setInterval(() => {
        const event = {
          id:        `DET-${Date.now()}`,
          type:      detectionTypes[Math.floor(Math.random() * detectionTypes.length)],
          severity:  severities[Math.floor(Math.random() * severities.length)],
          source_ip: randomIP(),
          dest_ip:   randomIP(),
          timestamp: new Date().toISOString(),
          rule:      `RULE-${Math.floor(Math.random() * 9000 + 1000)}`
        };
        socket.emit('detection:event', event);
      }, 1800);
    });

    socket.on('detections:stop', () => {
      if (socket.detectionInterval) {
        clearInterval(socket.detectionInterval);
        socket.detectionInterval = null;
      }
    });

    /* ── Ping / keepalive ── */
    socket.on('ping', () => socket.emit('pong', { ts: Date.now() }));

    /* ── Disconnect ── */
    socket.on('disconnect', () => {
      if (socket.detectionInterval) clearInterval(socket.detectionInterval);
      console.log(`[WS] Disconnected: ${socket.userName}`);
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

  console.log('[WS] WebSocket server initialized');
}

function randomIP() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255)).join('.');
}

module.exports = { initWebSockets };
