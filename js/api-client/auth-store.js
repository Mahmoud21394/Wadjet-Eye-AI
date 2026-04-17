/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Frontend Auth Store (Phase 1/3)
 *  js/api-client/auth-store.js
 *
 *  Centralises all token read/write in one place.
 *  Security rules:
 *   - Access token stored ONLY in sessionStorage (cleared on tab close)
 *   - Refresh token stored in sessionStorage (httpOnly cookie preferred)
 *   - No AI provider keys stored here (see: never expose to JS)
 *   - Exposes getAccessToken() / getRefreshToken() / setTokens() / clear()
 *
 *  Phase 1 migration: replaces scattered localStorage key reads
 *  across 70+ frontend JS files with this single module.
 * ══════════════════════════════════════════════════════════════════
 */
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.AuthStore = factory();
    // Also expose on window for backwards compat with legacy inline scripts
    if (typeof window !== 'undefined') window.AuthStore = root.AuthStore;
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const KEYS = {
    ACCESS:  'wadjet_access_token',
    REFRESH: 'wadjet_refresh_token',
    USER:    'wadjet_user_profile',
  };

  // ── Compatibility shim — maps old localStorage keys to new store ──
  const LEGACY_KEYS = [
    'supabase_access_token', 'access_token', 'token', 'wadjet_token',
  ];

  /**
   * Migrate any legacy token found in localStorage into sessionStorage,
   * then remove the legacy key.
   */
  function _migrateLegacyTokens() {
    for (const k of LEGACY_KEYS) {
      const val = localStorage.getItem(k);
      if (val && !sessionStorage.getItem(KEYS.ACCESS)) {
        sessionStorage.setItem(KEYS.ACCESS, val);
        console.log(`[AuthStore] Migrated legacy token key "${k}" → sessionStorage`);
      }
      if (val) localStorage.removeItem(k);
    }
  }

  // Run migration once on module load
  if (typeof localStorage !== 'undefined') {
    try { _migrateLegacyTokens(); } catch (_) {}
  }

  // ── Public API ─────────────────────────────────────────────────
  const AuthStore = {
    /**
     * Get the current access token (null if not authenticated).
     */
    getAccessToken() {
      return sessionStorage.getItem(KEYS.ACCESS) || null;
    },

    /**
     * Get the current refresh token.
     */
    getRefreshToken() {
      return sessionStorage.getItem(KEYS.REFRESH) || null;
    },

    /**
     * Store new tokens after login or refresh.
     * @param {string} accessToken
     * @param {string} [refreshToken]
     */
    setTokens(accessToken, refreshToken) {
      if (accessToken)  sessionStorage.setItem(KEYS.ACCESS,  accessToken);
      if (refreshToken) sessionStorage.setItem(KEYS.REFRESH, refreshToken);
      console.log('[AuthStore] Tokens updated');
    },

    /**
     * Store user profile (non-sensitive).
     * @param {object} profile
     */
    setUser(profile) {
      sessionStorage.setItem(KEYS.USER, JSON.stringify(profile));
    },

    /**
     * Get stored user profile.
     * @returns {object|null}
     */
    getUser() {
      try {
        const raw = sessionStorage.getItem(KEYS.USER);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    },

    /**
     * Clear all auth state (logout).
     */
    clear() {
      sessionStorage.removeItem(KEYS.ACCESS);
      sessionStorage.removeItem(KEYS.REFRESH);
      sessionStorage.removeItem(KEYS.USER);
      console.log('[AuthStore] Cleared');
    },

    /**
     * Returns true if an access token is present (does not validate expiry).
     */
    isAuthenticated() {
      return !!sessionStorage.getItem(KEYS.ACCESS);
    },

    /**
     * Returns the user's role from the stored profile.
     */
    getRole() {
      return this.getUser()?.role || null;
    },

    /**
     * Returns the user's tenant_id.
     */
    getTenantId() {
      return this.getUser()?.tenant_id || null;
    },
  };

  return AuthStore;
}));
