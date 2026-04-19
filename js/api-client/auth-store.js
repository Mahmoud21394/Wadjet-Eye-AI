/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Frontend Auth Store (Phase 1/3)
 *  js/api-client/auth-store.js
 *
 *  Centralises all token read/write in one place.
 *  Security rules:
 *   - Access token stored in sessionStorage (primary) + localStorage (backup)
 *   - Refresh token stored in localStorage ONLY so it survives page reloads
 *     and tab restores (root-cause fix for the 401 loop on every reload)
 *   - No AI provider keys stored here (see: never expose to JS)
 *   - Exposes getAccessToken() / getRefreshToken() / setTokens() / clear()
 *
 *  ROOT-CAUSE FIX:
 *   The previous version stored the refresh token in sessionStorage only.
 *   sessionStorage is wiped when the tab is closed/refreshed, which meant
 *   the refresh token was lost on every page reload, producing a 401 loop.
 *   Fix: refresh token is now mirrored to localStorage.
 *   Access token stays in sessionStorage as the primary source but is also
 *   backed to localStorage so api-client/index.js can find it after reload.
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

  // ── Compatibility shim — maps OLD non-primary keys to new store ──
  // ROOT-CAUSE FIX: Do NOT include 'wadjet_access_token' or 'wadjet_refresh_token'
  // in this list. Those keys are managed by auth-interceptor.js (UnifiedTokenStore)
  // and must NOT be removed from localStorage by this migration step.
  // Only remove truly legacy / renamed keys that are no longer in use.
  const LEGACY_KEYS = [
    'supabase_access_token', 'access_token', 'token', 'wadjet_token',
  ];

  /**
   * Migrate any legacy token found in localStorage into sessionStorage,
   * then remove the legacy key.
   *
   * ROOT-CAUSE FIX: Only removes keys listed in LEGACY_KEYS (which no longer
   * includes 'wadjet_access_token'). This prevents the migration from wiping
   * the token written by auth-interceptor.js (UnifiedTokenStore.save()).
   */
  function _migrateLegacyTokens() {
    for (const k of LEGACY_KEYS) {
      const val = localStorage.getItem(k);
      if (val) {
        // Copy to sessionStorage only if we don't already have a primary token
        if (!sessionStorage.getItem(KEYS.ACCESS)) {
          sessionStorage.setItem(KEYS.ACCESS, val);
        }
        // Remove the old key from localStorage
        localStorage.removeItem(k);
      }
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
     * Reads sessionStorage first (primary), then localStorage backup.
     */
    getAccessToken() {
      return sessionStorage.getItem(KEYS.ACCESS)
          || localStorage.getItem(KEYS.ACCESS)
          || null;
    },

    /**
     * Get the current refresh token.
     * ROOT-CAUSE FIX: Reads localStorage first because that is where
     * auth-interceptor.js (UnifiedTokenStore) writes the refresh token
     * so it survives page reloads. sessionStorage is checked as fallback
     * only.
     */
    getRefreshToken() {
      return localStorage.getItem(KEYS.REFRESH)
          || sessionStorage.getItem(KEYS.REFRESH)
          || null;
    },

    /**
     * Store new tokens after login or refresh.
     * @param {string} accessToken
     * @param {string} [refreshToken]
     *
     * ROOT-CAUSE FIX: refresh token MUST be written to localStorage so it
     * survives page reloads. Access token is written to both storages:
     * sessionStorage (cleared on tab close — reduces XSS window) and
     * localStorage (backup so api-client finds it after reload).
     */
    setTokens(accessToken, refreshToken) {
      if (accessToken) {
        sessionStorage.setItem(KEYS.ACCESS, accessToken);
        localStorage.setItem(KEYS.ACCESS,   accessToken);   // backup for reload
      }
      if (refreshToken) {
        // ONLY localStorage — sessionStorage is wiped on tab close/reload
        localStorage.setItem(KEYS.REFRESH, refreshToken);
        sessionStorage.setItem(KEYS.REFRESH, refreshToken); // convenience copy
      }
    },

    /**
     * Store user profile (non-sensitive).
     * @param {object} profile
     */
    setUser(profile) {
      const json = JSON.stringify(profile);
      sessionStorage.setItem(KEYS.USER, json);
      localStorage.setItem(KEYS.USER, json);  // backup so it survives reload
    },

    /**
     * Get stored user profile.
     * @returns {object|null}
     */
    getUser() {
      try {
        const raw = sessionStorage.getItem(KEYS.USER) || localStorage.getItem(KEYS.USER);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    },

    /**
     * Clear all auth state (logout).
     * Clears both sessionStorage AND localStorage to ensure a clean slate.
     */
    clear() {
      sessionStorage.removeItem(KEYS.ACCESS);
      sessionStorage.removeItem(KEYS.REFRESH);
      sessionStorage.removeItem(KEYS.USER);
      // Also clear localStorage backups
      localStorage.removeItem(KEYS.ACCESS);
      localStorage.removeItem(KEYS.REFRESH);
      localStorage.removeItem(KEYS.USER);
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
