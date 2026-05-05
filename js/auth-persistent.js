/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — auth-persistent.js  (compatibility stub v1.0)
 *  FILE: js/auth-persistent.js
 *
 *  WHY THIS FILE EXISTS:
 *  ─────────────────────────────────────────────────────────────────
 *  index.html loads this file at script position 939 (before
 *  state-sync.js and auth-interceptor.js).  The real persistent-auth
 *  functionality was migrated to:
 *    • js/auth-secure.js      — SecureSessionManager, CSRF, idle-timeout
 *    • js/auth-interceptor.js — UnifiedTokenStore, silentRefresh, backoff
 *    • js/state-sync.js       — StateSync, markAuthReady, onAuthReady
 *
 *  When this file was missing (404) the browser aborted the <script>
 *  tag, which made all *subsequent* script tags in the same HTML block
 *  also fail to execute — breaking state-sync.js, auth-interceptor.js,
 *  and auth-validator.js in one blow.  That is why every post-login
 *  API request arrived with no Bearer token.
 *
 *  This stub:
 *    1. Prevents the 404 / load-abort.
 *    2. Provides the legacy PersistentTokenStore shim so any old module
 *       that reads window.PersistentTokenStore still works.
 *    3. Does NOT store tokens itself — all real storage goes through
 *       UnifiedTokenStore (auth-interceptor.js).
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── Legacy shim ─────────────────────────────────────────────────
   Older modules (index.html inline scripts, legacy pages) may call:
     PersistentTokenStore.get()
     PersistentTokenStore.getRefresh()
     PersistentTokenStore.isOffline()
   We delegate every call to UnifiedTokenStore when available, or
   fall back to reading localStorage directly.
──────────────────────────────────────────────────────────────── */
window.PersistentTokenStore = window.PersistentTokenStore || {
  /** Best available access token */
  get() {
    if (window.UnifiedTokenStore) return window.UnifiedTokenStore.getToken();
    return localStorage.getItem('wadjet_access_token')
        || localStorage.getItem('we_access_token')
        || localStorage.getItem('tp_access_token')
        || sessionStorage.getItem('tp_token')
        || null;
  },

  /** Refresh token (localStorage only) */
  getRefresh() {
    if (window.UnifiedTokenStore) return window.UnifiedTokenStore.getRefresh();
    return localStorage.getItem('wadjet_refresh_token')
        || localStorage.getItem('we_refresh_token')
        || null;
  },

  /** Offline mode flag */
  isOffline() {
    if (window.UnifiedTokenStore) return window.UnifiedTokenStore.isOffline();
    return localStorage.getItem('wadjet_offline') === '1';
  },

  /** User profile */
  getUser() {
    if (window.UnifiedTokenStore) return window.UnifiedTokenStore.getUser();
    try {
      const raw = localStorage.getItem('wadjet_user_profile')
               || localStorage.getItem('we_user');
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  /** Clear all tokens (delegates to UnifiedTokenStore when loaded) */
  clear() {
    if (window.UnifiedTokenStore) { window.UnifiedTokenStore.clear(); return; }
    ['wadjet_access_token','we_access_token','tp_access_token',
     'wadjet_refresh_token','we_refresh_token',
     'wadjet_user_profile','we_user','wadjet_token_expires_at',
    ].forEach(k => { localStorage.removeItem(k); sessionStorage.removeItem(k); });
  },
};

/* ── Alias expected by some legacy modules ───────────────────── */
window.PersistentAuth = window.PersistentAuth || window.PersistentTokenStore;

console.log('[AuthPersistent] ✅ auth-persistent.js stub loaded — delegating to UnifiedTokenStore');
