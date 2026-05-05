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
 */
'use strict';
window.StateSync = window.StateSync || {
  authReady: false,
  _listeners: [],
  /** Returns true once markAuthReady() has been called at least once. */
  isAuthDone()  { return this.authReady; },
  markAuthReady(state) {
    this.authReady = true;
    if (state && state.isAuthenticated !== undefined) {
      this._authState = state;
    }
    this._listeners.forEach(fn => { try { fn(state); } catch (_) {} });
    this._listeners = []; // fire-once semantics
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
      if (!this.authReady) this.markAuthReady(s);
    } else if (s && s.isAuthenticated === false) {
      // Explicit sign-out: reset so next login re-resolves listeners
      this.authReady = false;
      this._authState = null;
    }
  },
  handleAuthExpiry(reason) {
    this.authReady = false;
    this._authState = null;
    console.warn('[StateSync] Auth expired:', reason);
  },
  onAuthReady(fn) {
    if (typeof fn !== 'function') return;
    if (this.authReady) { try { fn(this._authState); } catch (_) {} }
    else this._listeners.push(fn);
  },
  _authState: null,
};
