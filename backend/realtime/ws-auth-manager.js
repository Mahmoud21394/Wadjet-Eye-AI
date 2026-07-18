/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — WebSocket Auth Manager  v1.0
 *  backend/realtime/ws-auth-manager.js
 *
 *  PROBLEM SOLVED
 *  ─────────────────────────────────────────────────────────────────────
 *  Current behaviour (v5.0):
 *   • Token expires mid-session → JWT verify fails → connection closes 4401
 *   • Client receives AUTH_FAILED → no automatic reconnect logic
 *   • User must manually reload the page to re-establish the stream
 *   • Logs show: "[WS] Token expired", "AUTH_FAILED — closing connection"
 *
 *  Root cause:
 *   1. resolveJwtLocal() correctly rejects expired tokens (TokenExpiredError)
 *   2. But wss.on('connection') rejects the initial auth without a retry path
 *   3. Socket.IO middleware also rejects immediately with no reconnect window
 *   4. Neither the Socket.IO nor native WS client gets a "please refresh and
 *      reconnect" signal with enough information to know it's recoverable
 *
 *  Solution (this module):
 *   1. WsAuthManager class — manages token refresh lifecycle for WS sessions
 *   2. Proactive pre-expiry warning: fire 'auth:expiring' event 2min before
 *      token expires, giving the client time to silently refresh
 *   3. Cooperative token replacement: client sends 'auth:refresh' with new
 *      token; server validates and updates the socket's auth context
 *   4. Graceful disconnect: when token expires server sends 'auth:expired'
 *      with reconnect hint before closing (not immediate close)
 *   5. Client-side reconnect helper (ws-reconnect.js): automatic exponential
 *      backoff reconnect with fresh token from UnifiedTokenStore
 *
 *  SERVER-SIDE PROTOCOL (new events):
 *   → auth:expiring   { expiresIn: seconds }     Server → Client: "refresh now"
 *   → auth:expired    { reconnect: true }         Server → Client: "get new token + reconnect"
 *   → auth:refreshed  { userId, tenantId }        Server → Client: "refresh accepted"
 *   ← auth:refresh    { token }                   Client → Server: "here is my new token"
 *
 *  BACKWARD COMPATIBLE: All existing Socket.IO and native WS event handling
 *  in websockets.js is unchanged. This module is additive only.
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const jwt = require('jsonwebtoken');

const _WS_JWT_SECRET     = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;
const _WS_ALT_JWT_SECRET = (() => {
  const s = process.env.SUPABASE_JWT_SECRET;
  const c = process.env.JWT_SECRET;
  return (s && c && s !== c) ? (s === _WS_JWT_SECRET ? c : s) : null;
})();

// How many seconds before expiry to warn client to refresh
const EXPIRY_WARN_SECONDS = 120;   // 2 minutes

// How long to wait after sending auth:expired before closing connection
const GRACEFUL_CLOSE_DELAY_MS = 5000;  // 5 seconds

// ──────────────────────────────────────────────────────────────────────────────
//  getTokenExpiry — extract expiry timestamp from a JWT without full verification
// ──────────────────────────────────────────────────────────────────────────────

/**
 * getTokenExpiry — decode JWT and return { exp, iat, sub }.
 * Does NOT verify signature — just extracts claims.
 *
 * @param {string} token
 * @returns {{ exp: number|null, sub: string|null, email: string|null }}
 */
function getTokenExpiry(token) {
  try {
    const decoded = jwt.decode(token);
    return {
      exp:   decoded?.exp   || null,
      sub:   decoded?.sub   || null,
      email: decoded?.email || null,
    };
  } catch {
    return { exp: null, sub: null, email: null };
  }
}

/**
 * verifyTokenFresh — fully verify a JWT token (signature + expiry).
 * Returns user object or null.
 *
 * @param {string} token
 * @returns {object|null}
 */
function verifyTokenFresh(token) {
  if (!token || !_WS_JWT_SECRET) return null;
  const opts = { algorithms: ['HS256'], clockTolerance: 30 };

  let decoded = null;
  try {
    decoded = jwt.verify(token, _WS_JWT_SECRET, opts);
  } catch (err1) {
    if (err1.name !== 'TokenExpiredError' && _WS_ALT_JWT_SECRET) {
      try {
        decoded = jwt.verify(token, _WS_ALT_JWT_SECRET, opts);
      } catch {
        return null;
      }
    } else {
      return null;
    }
  }

  if (!decoded) return null;
  return {
    userId:   decoded.sub        || 'unknown',
    tenantId: decoded.tenant_id  || decoded.tenantId || 'default',
    email:    decoded.email      || null,
    role:     decoded.role       || 'viewer',
    exp:      decoded.exp        || null,
    authType: 'jwt-local',
  };
}

// ──────────────────────────────────────────────────────────────────────────────
//  WsAuthManager — per-socket auth lifecycle manager
// ──────────────────────────────────────────────────────────────────────────────

class WsAuthManager {
  /**
   * @param {object}   socket        Socket.IO socket or native WS wrapper
   * @param {string}   token         Initial JWT token
   * @param {object}   user          Resolved user from initial auth
   * @param {Function} sendFn        Function to send a message to the client
   * @param {Function} closeFn       Function to close/disconnect the socket
   */
  constructor(socket, token, user, sendFn, closeFn) {
    this._socket    = socket;
    this._token     = token;
    this._user      = { ...user };
    this._sendFn    = sendFn;
    this._closeFn   = closeFn;

    this._expiryWarnTimer   = null;
    this._expiryCloseTimer  = null;
    this._destroyed         = false;

    // Schedule expiry warning based on token exp claim
    this._scheduleExpiryWarning(token);
  }

  /**
   * _scheduleExpiryWarning — compute time-to-expiry and set timers.
   * @param {string} token
   */
  _scheduleExpiryWarning(token) {
    this._clearTimers();

    const { exp } = getTokenExpiry(token);
    if (!exp) return;  // no expiry claim — skip (never-expiring token)

    const nowSec        = Math.floor(Date.now() / 1000);
    const ttlSec        = exp - nowSec;
    const warnInSec     = ttlSec - EXPIRY_WARN_SECONDS;
    const expireInMs    = ttlSec * 1000;
    const warnInMs      = warnInSec * 1000;

    if (ttlSec <= 0) {
      // Already expired at connection time — fire immediately
      this._handleExpired();
      return;
    }

    if (warnInMs > 0) {
      this._expiryWarnTimer = setTimeout(() => {
        if (this._destroyed) return;
        const remaining = exp - Math.floor(Date.now() / 1000);
        this._send({
          type:      'auth:expiring',
          expiresIn: Math.max(0, remaining),
          message:   `Token expires in ${Math.max(0, remaining)} seconds. Please refresh.`,
        });
        console.info(
          `[WsAuthManager] auth:expiring sent userId=${this._user.userId} ` +
          `expiresIn=${remaining}s`
        );
      }, warnInMs);
    }

    // Schedule the actual expiry handler
    if (expireInMs > 0) {
      this._expiryCloseTimer = setTimeout(() => {
        if (this._destroyed) return;
        this._handleExpired();
      }, expireInMs);
    }
  }

  /**
   * _handleExpired — token has expired. Notify client and schedule graceful close.
   */
  _handleExpired() {
    if (this._destroyed) return;
    console.warn(
      `[WsAuthManager] Token EXPIRED userId=${this._user.userId} ` +
      `— sending auth:expired, closing in ${GRACEFUL_CLOSE_DELAY_MS}ms`
    );

    // Notify client: "your token expired, get a new one and reconnect"
    this._send({
      type:      'auth:expired',
      reconnect: true,
      message:   'Session expired. Please refresh token and reconnect.',
      code:      4401,
    });

    // Graceful close: give client GRACEFUL_CLOSE_DELAY_MS to receive the event
    setTimeout(() => {
      if (!this._destroyed) {
        this.destroy();
        try { this._closeFn(4401, 'Token expired'); } catch {}
      }
    }, GRACEFUL_CLOSE_DELAY_MS);
  }

  /**
   * handleRefresh — called when client sends 'auth:refresh' with new token.
   * Validates the new token and updates internal state if valid.
   *
   * @param {string} newToken
   * @returns {{ ok: boolean, user?: object, error?: string }}
   */
  handleRefresh(newToken) {
    if (this._destroyed) return { ok: false, error: 'Connection closed' };

    const freshUser = verifyTokenFresh(newToken);
    if (!freshUser) {
      console.warn(`[WsAuthManager] auth:refresh REJECTED — invalid token userId=${this._user.userId}`);
      return { ok: false, error: 'Invalid or expired token' };
    }

    // Security check: refreshed token must be for the same user
    if (freshUser.userId !== this._user.userId) {
      console.warn(
        `[WsAuthManager] auth:refresh USER MISMATCH — ` +
        `existing=${this._user.userId} new=${freshUser.userId}`
      );
      return { ok: false, error: 'User identity mismatch in refresh token' };
    }

    // Accept new token — update state and reschedule expiry timers
    this._token = newToken;
    this._user  = { ...freshUser };
    this._scheduleExpiryWarning(newToken);

    console.info(
      `[WsAuthManager] auth:refresh ACCEPTED userId=${freshUser.userId} ` +
      `tenant=${freshUser.tenantId}`
    );

    return { ok: true, user: freshUser };
  }

  /**
   * getUser — return current authenticated user context.
   * @returns {object}
   */
  getUser() {
    return { ...this._user };
  }

  /**
   * _send — safe send to client.
   * @param {object} data
   */
  _send(data) {
    try { this._sendFn(data); } catch {}
  }

  /**
   * _clearTimers — cancel scheduled timers.
   */
  _clearTimers() {
    clearTimeout(this._expiryWarnTimer);
    clearTimeout(this._expiryCloseTimer);
    this._expiryWarnTimer  = null;
    this._expiryCloseTimer = null;
  }

  /**
   * destroy — clean up all timers. Call on socket disconnect.
   */
  destroy() {
    this._destroyed = true;
    this._clearTimers();
  }
}

// ──────────────────────────────────────────────────────────────────────────────
//  attachToSocketIO — attach WsAuthManager to a Socket.IO socket
// ──────────────────────────────────────────────────────────────────────────────

/**
 * attachToSocketIO — wrap a Socket.IO socket with auth lifecycle management.
 * Call this inside io.on('connection', (socket) => ...) AFTER auth succeeds.
 *
 * @param {import('socket.io').Socket} socket
 * @param {string}  token   Initial JWT
 * @param {object}  user    Resolved user from initial auth
 * @returns {WsAuthManager}
 */
function attachToSocketIO(socket, token, user) {
  const manager = new WsAuthManager(
    socket,
    token,
    user,
    (data)        => socket.emit(data.type, data),
    (code, reason)=> socket.disconnect(true),
  );

  // Handle client-initiated refresh
  socket.on('auth:refresh', async ({ token: newToken }) => {
    const result = manager.handleRefresh(newToken);
    if (result.ok) {
      // Update socket's tenant room if tenantId changed
      socket.emit('auth:refreshed', {
        userId:   result.user.userId,
        tenantId: result.user.tenantId,
        message:  'Token refreshed successfully',
      });
    } else {
      socket.emit('auth:refresh_failed', {
        reason: result.error,
        code:   4401,
      });
    }
  });

  socket.on('disconnect', () => {
    manager.destroy();
  });

  return manager;
}

// ──────────────────────────────────────────────────────────────────────────────
//  attachToNativeWS — attach WsAuthManager to a native WebSocket
// ──────────────────────────────────────────────────────────────────────────────

/**
 * attachToNativeWS — wrap a native WebSocket with auth lifecycle management.
 * Call inside wss.on('connection', ...) AFTER auth succeeds.
 *
 * @param {import('ws').WebSocket} ws
 * @param {string}  token   Initial JWT
 * @param {object}  user    Resolved user from initial auth
 * @param {Function} sendFn  Function to send JSON to client
 * @returns {WsAuthManager}
 */
function attachToNativeWS(ws, token, user, sendFn) {
  const manager = new WsAuthManager(
    ws,
    token,
    user,
    sendFn,
    (code, reason) => {
      try { ws.close(code || 4401, reason || 'Session expired'); } catch {}
    },
  );

  // Listen for client 'auth' messages (includes token refresh)
  // The native WS message handler in websockets.js calls this:
  //   case 'auth': { const result = manager.handleRefresh(msg.token); ... }
  // So we just expose the manager and let the existing handler use it.

  ws.on('close', () => {
    manager.destroy();
  });

  return manager;
}

module.exports = {
  WsAuthManager,
  attachToSocketIO,
  attachToNativeWS,
  verifyTokenFresh,
  getTokenExpiry,
};
