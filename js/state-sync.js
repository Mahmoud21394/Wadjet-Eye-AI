/**
 * State Sync — Stub for auth-interceptor compatibility
 * Provides StateSync interface required by auth-interceptor.js
 *
 * v7.5 FIX: Added isAuthDone() method.
 *   auth-interceptor.js PersistentAuth_onLogin calls window.StateSync.isAuthDone()
 *   to decide whether to markAuthReady() or updateAuthState().
 *   Without this method the call throws "window.StateSync.isAuthDone is not a function"
 *   which surfaces as "[SecureLogin] Authentication failed: window.StateSync.isAuthDone
 *   is not a function" and causes an immediate logout after a successful login response.
 *
 * ROOT-CAUSE FIX v9.0: Added persistent listener support for re-login flows.
 *   PROBLEM: markAuthReady() called _listeners.forEach then set _listeners = [] (fire-once).
 *   On the SECOND login (after a session expiry + re-login), the listeners array was
 *   already empty, so any module that registered via onAuthReady() for its initial
 *   setup never received the second auth-ready notification.  Result: after re-login
 *   modules stayed in "waiting for auth" limbo and never loaded their data.
 *
 *   FIX: Separate _listeners (one-shot, cleared after first fire) from
 *   _persistentListeners (never cleared, always invoked on every markAuthReady call).
 *   updateAuthState() also invokes persistent listeners on auth state changes so
 *   modules can react to re-login without needing to re-register.
 *   New method: onAuthChange(fn) — registers a persistent listener.
 */
'use strict';
window.StateSync = window.StateSync || {
  authReady: false,
  _listeners: [],
  _persistentListeners: [],
  /** Returns true once markAuthReady() has been called at least once. */
  isAuthDone()  { return this.authReady; },
  markAuthReady(state) {
    this.authReady = true;
    if (state && state.isAuthenticated !== undefined) {
      this._authState = state;
    }
    // Fire one-shot listeners then clear them
    this._listeners.forEach(fn => { try { fn(state); } catch (_) {} });
    this._listeners = [];
    // ROOT-CAUSE FIX v9.0: Also fire persistent listeners (not cleared)
    this._persistentListeners.forEach(fn => { try { fn(state); } catch (_) {} });
  },
  isAuthenticated() {
    return !!(
      localStorage.getItem('wadjet_access_token') ||
      localStorage.getItem('we_access_token')     ||
      localStorage.getItem('tp_access_token')
    );
  },
  updateAuthState(s) {
    if (s && s.isAuthenticated) {
      if (!this.authReady) {
        this.markAuthReady(s);
      } else {
        // Already ready — still notify persistent listeners so re-login is propagated
        this._authState = s;
        this._persistentListeners.forEach(fn => { try { fn(s); } catch (_) {} });
      }
    } else if (s && s.isAuthenticated === false) {
      // Explicit sign-out: reset so next login re-resolves one-shot listeners
      this.authReady = false;
      this._authState = null;
      // Notify persistent listeners of sign-out too (e.g. to clear UI state)
      this._persistentListeners.forEach(fn => { try { fn(s); } catch (_) {} });
    }
  },
  handleAuthExpiry(reason) {
    this.authReady = false;
    this._authState = null;
    console.warn('[StateSync] Auth expired:', reason);
    // FIX v8.1: Dispatch auth:expired to window so the auth-interceptor's
    // dedup + clear + doLogout handler actually runs.
    // Previously this function only reset internal state — no window event
    // was ever fired, so the login screen never appeared and every module
    // kept retrying API calls with a dead token indefinitely.
    try {
      window.dispatchEvent(new CustomEvent('auth:expired', {
        detail: typeof reason === 'object' ? reason : { reason },
      }));
    } catch (_) {}
  },
  /** One-shot: fires once when auth is ready (or immediately if already ready). */
  onAuthReady(fn) {
    if (typeof fn !== 'function') return;
    if (this.authReady) { try { fn(this._authState); } catch (_) {} }
    else this._listeners.push(fn);
  },
  /**
   * ROOT-CAUSE FIX v9.0: Persistent listener — fires on EVERY auth state change
   * (login, re-login, logout, token refresh).  Unlike onAuthReady(), it is never
   * removed from the list.  Use this for modules that need to react to re-login
   * after a session expiry without re-registering their listener.
   *
   * @param {function(state)} fn  Called with the auth state object every time
   *   markAuthReady() or updateAuthState() is invoked.
   */
  onAuthChange(fn) {
    if (typeof fn !== 'function') return;
    this._persistentListeners.push(fn);
    // If already authenticated, invoke immediately so late-registering modules
    // don't miss the current auth state.
    if (this.authReady && this._authState) {
      try { fn(this._authState); } catch (_) {}
    }
  },
  _authState: null,
};
