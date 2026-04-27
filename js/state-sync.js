/**
 * State Sync — Stub for auth-interceptor compatibility
 * Provides StateSync interface required by auth-interceptor.js
 */
'use strict';
window.StateSync = window.StateSync || {
  authReady: false,
  _listeners: [],
  markAuthReady() { this.authReady = true; this._listeners.forEach(fn => fn()); },
  isAuthenticated() { return !!localStorage.getItem('wadjet_access_token'); },
  updateAuthState(s) { if (s.isAuthenticated) this.markAuthReady(); },
  handleAuthExpiry() {},
  onAuthReady(fn) { if (this.authReady) fn(); else this._listeners.push(fn); },
};
