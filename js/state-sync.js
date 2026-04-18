/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Central State Synchronizer v1.0
 *  FILE: js/state-sync.js
 *
 *  MUST BE LOADED FIRST — before api-client.js, auth-interceptor.js,
 *  ai-orchestrator-v5.js, rakay-module.js, and any other module.
 *
 *  ┌─────────────────────── STARTUP SEQUENCE ─────────────────────────────┐
 *  │  1. state-sync.js  →  exposes AuthReadyPromise                        │
 *  │  2. auth-interceptor.js  →  resolves AuthReadyPromise after sync      │
 *  │  3. api-client.js (WS)   →  awaits AuthReadyPromise                   │
 *  │  4. ai-orchestrator-v5.js →  awaits AuthReadyPromise                  │
 *  │  5. rakay-module.js       →  awaits AuthReadyPromise + sessionReady   │
 *  └───────────────────────────────────────────────────────────────────────┘
 *
 *  GUARANTEES:
 *  - No module initializes before tokens are restored from storage.
 *  - Refresh token is ALWAYS read from localStorage — never lost on reload.
 *  - Single AuthReadyPromise — all modules share the same resolution.
 *  - StateSync.sessionReady resolves AFTER auth AND session restore.
 *  - StateSync.providerReady resolves AFTER first /api/ai/status call.
 *  - Cross-module event bus via StateSync.on / StateSync.emit.
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function _installStateSync() {

  /* ══════════════════════════════════════════════════════════════════════
     INTERNAL RESOLVER HANDLES
  ══════════════════════════════════════════════════════════════════════ */
  let _resolveAuth,    _rejectAuth;
  let _resolveSession, _rejectSession;
  let _resolveProvider;

  /* ══════════════════════════════════════════════════════════════════════
     PUBLIC PROMISES — awaited by all modules
  ══════════════════════════════════════════════════════════════════════ */
  const authReady     = new Promise((res, rej) => { _resolveAuth    = res; _rejectAuth    = rej; });
  const sessionReady  = new Promise((res, rej) => { _resolveSession = res; _rejectSession = rej; });
  const providerReady = new Promise((res)       => { _resolveProvider = res; });

  /* ══════════════════════════════════════════════════════════════════════
     SHARED STATE — read by all modules, written by auth-interceptor only
  ══════════════════════════════════════════════════════════════════════ */
  const _state = {
    authDone:          false,   // true after first auth sync completes
    sessionDone:       false,   // true after RAKAY session is restored
    providerDone:      false,   // true after first provider status fetch

    isAuthenticated:   false,   // live auth state
    user:              null,    // current user profile
    tenantId:          null,

    wsConnected:       false,   // live WS state
    wsToken:           null,    // token that established the WS connection

    providerStatus:    null,    // cached /api/ai/status response
    providerCachedAt:  0,       // ms timestamp
    PROVIDER_TTL_MS:   60_000,  // 60 s cache
  };

  /* ══════════════════════════════════════════════════════════════════════
     EVENT BUS — lightweight pub/sub for cross-module communication
     Usage:
       StateSync.on('auth:ready', ({ user }) => { ... });
       StateSync.emit('auth:ready', { user });
  ══════════════════════════════════════════════════════════════════════ */
  const _listeners = {};

  function _on(event, handler) {
    if (!_listeners[event]) _listeners[event] = [];
    _listeners[event].push(handler);
    return () => { _listeners[event] = _listeners[event].filter(h => h !== handler); };
  }

  function _emit(event, detail) {
    // Internal listeners
    (_listeners[event] || []).forEach(h => { try { h(detail); } catch(e) { console.warn('[StateSync] Event handler error:', e); } });
    // Also dispatch as DOM events for legacy code
    try {
      window.dispatchEvent(new CustomEvent(event, { detail, bubbles: false }));
    } catch(_) {}
  }

  /* ══════════════════════════════════════════════════════════════════════
     AUTH COORDINATION
  ══════════════════════════════════════════════════════════════════════ */

  /**
   * Called by auth-interceptor.js once token sync is complete.
   * Resolves authReady for ALL waiting modules simultaneously.
   */
  function _markAuthReady({ isAuthenticated, user, tenantId } = {}) {
    if (_state.authDone) return;      // idempotent
    _state.authDone       = true;
    _state.isAuthenticated = !!isAuthenticated;
    _state.user           = user || null;
    _state.tenantId       = tenantId || null;

    _resolveAuth({ isAuthenticated: _state.isAuthenticated, user, tenantId });
    _emit('auth:ready', { isAuthenticated: _state.isAuthenticated, user, tenantId });
  }

  function _markAuthFailed(reason) {
    if (_state.authDone) return;
    _state.authDone       = true;
    _state.isAuthenticated = false;
    console.warn('[StateSync] Auth sync failed:', reason);
    // Resolve (not reject) so modules don't hang — they just start unauthenticated
    _resolveAuth({ isAuthenticated: false, reason });
    _emit('auth:failed', { reason });
  }

  function _updateAuthState({ isAuthenticated, user, tenantId }) {
    _state.isAuthenticated = !!isAuthenticated;
    if (user)     _state.user     = user;
    if (tenantId) _state.tenantId = tenantId;
    _emit('auth:changed', { isAuthenticated: _state.isAuthenticated, user: _state.user });
  }

  /* ══════════════════════════════════════════════════════════════════════
     SESSION COORDINATION
  ══════════════════════════════════════════════════════════════════════ */

  function _markSessionReady({ sessionId } = {}) {
    if (_state.sessionDone) return;
    _state.sessionDone = true;
    _resolveSession({ sessionId });
    _emit('session:ready', { sessionId });
  }

  function _markSessionFailed(reason) {
    if (_state.sessionDone) return;
    _state.sessionDone = true;
    _resolveSession({ sessionId: null, reason });
    _emit('session:failed', { reason });
  }

  /* ══════════════════════════════════════════════════════════════════════
     PROVIDER COORDINATION
  ══════════════════════════════════════════════════════════════════════ */

  function _markProviderReady(status) {
    _state.providerStatus  = status;
    _state.providerCachedAt = Date.now();

    if (!_state.providerDone) {
      _state.providerDone = true;
      _resolveProvider(status);
    }
    _emit('provider:status', status);
  }

  function _isProviderCacheValid() {
    return _state.providerStatus !== null &&
           (Date.now() - _state.providerCachedAt) < _state.PROVIDER_TTL_MS;
  }

  /* ══════════════════════════════════════════════════════════════════════
     WS STATE TRACKING
  ══════════════════════════════════════════════════════════════════════ */

  function _markWsConnected(token) {
    _state.wsConnected = true;
    _state.wsToken     = token;
    _emit('ws:connected', { token });
  }

  function _markWsDisconnected(reason) {
    _state.wsConnected = false;
    _emit('ws:disconnected', { reason });
  }

  /* ══════════════════════════════════════════════════════════════════════
     GLOBAL AUTH EXPIRY COORDINATION
     Prevents duplicate expiry handling across modules
  ══════════════════════════════════════════════════════════════════════ */
  let _expiryHandled = false;
  let _expiryTimer   = null;

  function _handleAuthExpiry(detail = {}) {
    if (_expiryHandled) return;
    _expiryHandled = true;
    _expiryTimer   = setTimeout(() => { _expiryHandled = false; }, 15_000);

    _state.isAuthenticated = false;
    console.warn('[StateSync] 🔒 Auth expiry detected — path:', detail.path || 'unknown');
    _emit('auth:expired', detail);

    // Reset session state so modules can restart cleanly on next login
    _state.sessionDone = false;
  }

  /* ══════════════════════════════════════════════════════════════════════
     TIMEOUT SAFETY — resolve auth after 10s if interceptor never fires
     Prevents modules from hanging if auth-interceptor.js fails to load
  ══════════════════════════════════════════════════════════════════════ */
  const _AUTH_TIMEOUT_MS = 10_000;
  const _authTimeoutTimer = setTimeout(() => {
    if (!_state.authDone) {
      console.warn('[StateSync] ⚠️  Auth ready timeout — resolving unauthenticated (10s elapsed)');
      _markAuthFailed('timeout');
    }
  }, _AUTH_TIMEOUT_MS);

  authReady.then(() => clearTimeout(_authTimeoutTimer));

  /* ══════════════════════════════════════════════════════════════════════
     EXPORT — window.StateSync
  ══════════════════════════════════════════════════════════════════════ */
  /* ══════════════════════════════════════════════════════════════════════
     EXPORT — window.StateSync
     NOTE: Object.freeze() prevents adding properties post-creation,
     so we use a plain object with getters for live state access.
  ══════════════════════════════════════════════════════════════════════ */
  window.StateSync = {
    // Promises
    authReady,
    sessionReady,
    providerReady,

    // Auth
    markAuthReady:     _markAuthReady,
    markAuthFailed:    _markAuthFailed,
    updateAuthState:   _updateAuthState,
    handleAuthExpiry:  _handleAuthExpiry,

    // Session
    markSessionReady:  _markSessionReady,
    markSessionFailed: _markSessionFailed,

    // Provider
    markProviderReady:      _markProviderReady,
    isProviderCacheValid:   _isProviderCacheValid,
    getProviderStatus:      () => _state.providerStatus,
    getProviderCachedAt:    () => _state.providerCachedAt,

    // WS
    markWsConnected:    _markWsConnected,
    markWsDisconnected: _markWsDisconnected,

    // Event bus
    on:   _on,
    emit: _emit,

    // State read-only snapshot
    getState:        () => ({ ..._state }),
    isAuthDone:      () => _state.authDone,
    isAuthenticated: () => _state.isAuthenticated,
    getUser:         () => _state.user,
    getTenantId:     () => _state.tenantId,
    isWsConnected:   () => _state.wsConnected,
  };

  // Add live getter properties so modules can read StateSync.providerStatus,
  // StateSync.isAuthenticated (as boolean property), etc. without calling methods.
  // These are defined AFTER the object is created so we can use defineProperty.
  Object.defineProperty(window.StateSync, 'providerStatus', {
    get: () => _state.providerStatus,
    enumerable: true,
    configurable: true,
  });
  Object.defineProperty(window.StateSync, 'authState', {
    get: () => ({ isAuthenticated: _state.isAuthenticated, user: _state.user, tenantId: _state.tenantId }),
    enumerable: true,
    configurable: true,
  });

  Object.freeze(window.StateSync);

})();
