/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Persistent Auth Engine v5.1
 *  FILE: js/auth-persistent.js
 *
 *  WHAT THIS MODULE PROVIDES:
 *  ──────────────────────────
 *  1.  PersistentTokenStore   — Stores tokens in localStorage (survives tab close)
 *  2.  SmartRefresh           — Proactively refreshes token at 80% of TTL
 *  3.  SessionWatchdog        — Detects expiry and triggers refresh automatically
 *  4.  SessionRestoreGate     — On page load, silently restores session from storage
 *  5.  ActivityTracker        — Resets idle timer on user interaction
 *  6.  EmergencyOfflineLogin  — Falls back to offline mode on backend failure
 *
 *  WHY SESSION EXPIRED BEFORE (root causes fixed in v5.1):
 *  ─────────────────────────────────────────────────────────
 *  CAUSE 1: Tokens stored in sessionStorage → cleared on tab close / page refresh
 *           FIX: Store access token + refresh token in localStorage
 *
 *  CAUSE 2: No proactive refresh — waited until 401 to try refresh
 *           FIX: SmartRefresh schedules a refresh at 80% of TTL (≈12 min for 15 min TTL)
 *
 *  CAUSE 3: Refresh endpoint was calling generateLink (magic link) which
 *           returns a URL, not an access token
 *           FIX: auth.js v5.1 uses admin.createSession → jwt.sign fallback
 *
 *  CAUSE 4: After 401, the API client was not retrying the refresh before
 *           showing "Session expired"
 *           FIX: apiRequest in api-client.js retries once after 401
 *
 *  CAUSE 5: Multiple concurrent refresh calls racing each other
 *           FIX: refreshLock mutex prevents duplicate requests
 *
 *  CAUSE 6: RLS policy blocked INSERT on refresh_tokens table
 *           FIX: rls-fix-v5.1.sql adds service_role full-access policy
 *
 *  SUPABASE JWT MECHANICS (explained):
 *  ─────────────────────────────────────
 *  • Supabase issues access tokens (JWTs) valid for 1 hour by default
 *    (configurable in Dashboard → Auth → JWT expiry)
 *  • We set ACCESS_TOKEN_TTL=900 (15 min) on the backend
 *  • The backend issues our own refresh token (64 hex bytes, SHA-256 hashed in DB)
 *  • On /api/auth/refresh:
 *    1. Validate our refresh token against DB
 *    2. Rotate (revoke old, issue new)
 *    3. Get new Supabase access token via admin.createSession
 *    4. Fallback: sign custom JWT with JWT_SECRET
 *  • The middleware verifies JWTs using supabase.auth.getUser(token)
 *
 *  RENDER/VERCEL COLD START NOTE:
 *  ───────────────────────────────
 *  Render free tier spins down after 15 min of inactivity.
 *  On cold start, the first request takes 10-30s.
 *  SessionRestoreGate retries up to 4 times with exponential back-off.
 * ══════════════════════════════════════════════════════════════════════════
 */

/* global window, document, localStorage, console, CustomEvent, fetch */
'use strict';

(function (global) {

  /* ══════════════════════════════════════════════════════
     CONSTANTS
  ═══════════════════════════════════════════════════════ */
  const STORAGE_KEYS = {
    ACCESS_TOKEN:  'wadjet_access_token',
    REFRESH_TOKEN: 'wadjet_refresh_token',
    EXPIRES_AT:    'wadjet_token_expires_at',
    USER_PROFILE:  'wadjet_user_profile',
    SESSION_ID:    'wadjet_session_id',
    LAST_ACTIVITY: 'wadjet_last_activity',
    OFFLINE_MODE:  'wadjet_offline_mode',
  };
  let _authReadyResolve;
  const authReady = new Promise(res => {
     _authReadyResolve = res;
   });
  // Proactive refresh at 80% of TTL (e.g. 12 min for 15 min TTL)
  const REFRESH_THRESHOLD_RATIO = 0.80;
  // Default TTL if server doesn't tell us
  const DEFAULT_TTL_MS           = 15 * 60 * 1000;  // 15 min
  // How long to show "idle" warning before logging out
  const IDLE_TIMEOUT_MS          = 60 * 60 * 1000;  // 60 min
  // Cold-start retry settings
  const MAX_RESTORE_RETRIES      = 4;
  const RESTORE_RETRY_BASE_MS    = 2000;

  /* ══════════════════════════════════════════════════════
     PERSISTENT TOKEN STORE
     localStorage persists across tab close, page refresh, browser restart
  ═══════════════════════════════════════════════════════ */
  const PersistentTokenStore = {

    /** Save full session to localStorage */
    save(data) {
      try {
        const { token, refreshToken, expiresAt, user, sessionId, offline } = data;
        if (token)        localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN,  token);
        if (refreshToken) localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
        if (expiresAt)    localStorage.setItem(STORAGE_KEYS.EXPIRES_AT,    expiresAt);
        if (sessionId)    localStorage.setItem(STORAGE_KEYS.SESSION_ID,    sessionId);
        if (user)         localStorage.setItem(STORAGE_KEYS.USER_PROFILE,  JSON.stringify(user));
        localStorage.setItem(STORAGE_KEYS.OFFLINE_MODE, offline ? '1' : '0');
        localStorage.setItem(STORAGE_KEYS.LAST_ACTIVITY, Date.now().toString());
      } catch (e) {
        console.warn('[PersistentAuth] localStorage save failed:', e.message);
      }
    },

    /** Get stored access token */
    getToken() {
      return localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN) || null;
    },

    /** Get stored refresh token */
    getRefreshToken() {
      return localStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN) || null;
    },

    /** Get stored expiry as Date */
    getExpiry() {
      const raw = localStorage.getItem(STORAGE_KEYS.EXPIRES_AT);
      if (!raw) return null;
      const d = new Date(raw);
      return isNaN(d.getTime()) ? null : d;
    },

    /** Get stored user profile */
    getUser() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.USER_PROFILE);
        return raw ? JSON.parse(raw) : null;
      } catch (_) { return null; }
    },

    /** Get session ID */
    getSessionId() {
      return localStorage.getItem(STORAGE_KEYS.SESSION_ID) || null;
    },

    /** Is token expired? (with 30s buffer) */
    isExpired(bufferMs = 30000) {
      const expiry = this.getExpiry();
      if (!expiry) return true;
      return expiry.getTime() - bufferMs < Date.now();
    },

    /** Is session in offline mode? */
    isOffline() {
      return localStorage.getItem(STORAGE_KEYS.OFFLINE_MODE) === '1';
    },

    /** Milliseconds until expiry */
    msUntilExpiry() {
      const expiry = this.getExpiry();
      if (!expiry) return 0;
      return Math.max(0, expiry.getTime() - Date.now());
    },

    /** Update only the access token (after refresh) */
    updateToken(token, expiresAt) {
      if (token)     localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, token);
      if (expiresAt) localStorage.setItem(STORAGE_KEYS.EXPIRES_AT,   expiresAt);
    },

    /** Update token + refresh token (full rotation) */
    updateTokens({ token, refreshToken, expiresAt, expiresIn, user, sessionId }) {
      if (token)        localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN,  token);
      if (refreshToken) localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
      if (user)         localStorage.setItem(STORAGE_KEYS.USER_PROFILE,  JSON.stringify(user));
      if (sessionId)    localStorage.setItem(STORAGE_KEYS.SESSION_ID,    sessionId);

      // Calculate expiresAt from expiresIn if not provided
      const exp = expiresAt ||
        (expiresIn ? new Date(Date.now() + expiresIn * 1000).toISOString() : null);
      if (exp) localStorage.setItem(STORAGE_KEYS.EXPIRES_AT, exp);

    },

    /** Clear all session data (logout) */
    clear() {
      Object.values(STORAGE_KEYS).forEach(k => localStorage.removeItem(k));
    },

    /** Check if we have a usable session at all */
    hasSession() {
      return !!(this.getRefreshToken() || this.getToken());
    },
  };

  /* ══════════════════════════════════════════════════════
     SMART REFRESH
     Prevents duplicate refresh calls + handles retries
  ═══════════════════════════════════════════════════════ */
  let _refreshLock    = false;
  let _refreshPromise = null;
  let _watchdogTimer  = null;

  const SmartRefresh = {

    /** Perform a token refresh, deduplicated via lock */
    async refresh(backendUrl) {
      // Prevent concurrent refreshes
      if (_refreshLock && _refreshPromise) {
        return _refreshPromise;
      }

      _refreshLock    = true;
      _refreshPromise = this._doRefresh(backendUrl);

      try {
        const result = await _refreshPromise;
        return result;
      } finally {
        _refreshLock    = false;
        _refreshPromise = null;
      }
    },

    async _doRefresh(backendUrl) {
      const refreshToken = PersistentTokenStore.getRefreshToken();
      if (!refreshToken) {
        console.warn('[PersistentAuth] No refresh token — cannot refresh');
        return false;
      }

      // If in offline mode, extend the session locally
      if (PersistentTokenStore.isOffline()) {
        const newExpiry = new Date(Date.now() + DEFAULT_TTL_MS).toISOString();
        PersistentTokenStore.updateToken(
          'offline_' + Date.now().toString(36),
          newExpiry
        );
        return true;
      }

      const url = (backendUrl || '').replace(/\/$/, '');

      try {

        const res = await fetch(`${url}/api/auth/refresh`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ refresh_token: refreshToken }),
          signal:  AbortSignal.timeout(15000),
        });

        if (res.status === 401) {
          const body = await res.json().catch(() => ({}));
          console.warn('[PersistentAuth] Refresh token rejected by server:', body.error);
          // Refresh token is invalid — need full re-login
          _dispatchEvent('auth:session-expired', { reason: body.error || 'refresh_rejected' });
          return false;
        }

        if (!res.ok) {
          console.warn('[PersistentAuth] Refresh endpoint returned', res.status);
          return false;
        }

        const data = await res.json();

        // Save the rotated tokens
        PersistentTokenStore.updateTokens({
          token:        data.token,
          refreshToken: data.refreshToken || data.refresh_token,
          expiresAt:    data.expiresAt    || data.expires_at,
          expiresIn:    data.expiresIn    || data.expires_in,
          user:         data.user,
          sessionId:    data.sessionId    || data.session_id,
        });

        // Update CURRENT_USER if available
        if (data.user && typeof window !== 'undefined') {
          const stored = PersistentTokenStore.getUser();
          if (stored) {
            Object.assign(stored, data.user);
            PersistentTokenStore.save({ user: stored });
          }
        }

        // Reschedule watchdog
        this.scheduleRefresh(backendUrl);

        _dispatchEvent('auth:token-refreshed', { expiresAt: data.expiresAt });

        return data.token || true;

      } catch (err) {
        if (err.name === 'AbortError' || err.name === 'TimeoutError') {
          console.warn('[PersistentAuth] Refresh request timed out (server cold start?)');
          // Don't expire session — server might be waking up
          return false;
        }
        if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
          console.warn('[PersistentAuth] Network offline — skipping refresh');
          return false;
        }
        console.warn('[PersistentAuth] Refresh error:', err.message);
        return false;
      }
    },

    /** Schedule next proactive refresh based on token TTL */
    scheduleRefresh(backendUrl) {
      if (_watchdogTimer) {
        clearTimeout(_watchdogTimer);
        _watchdogTimer = null;
      }

      const msLeft = PersistentTokenStore.msUntilExpiry();
      if (msLeft <= 0) {
        // Already expired — refresh now
        this.refresh(backendUrl);
        return;
      }

      // Refresh at REFRESH_THRESHOLD_RATIO of remaining TTL
      const delay = Math.max(5000, msLeft * REFRESH_THRESHOLD_RATIO);


      _watchdogTimer = setTimeout(() => {
        if (PersistentTokenStore.hasSession()) {
          SmartRefresh.refresh(backendUrl);
        }
      }, delay);
    },

    /** Stop the refresh timer */
    stop() {
      if (_watchdogTimer) {
        clearTimeout(_watchdogTimer);
        _watchdogTimer = null;
      }
    },
  };

  /* ══════════════════════════════════════════════════════
     ACTIVITY TRACKER
     Extends session on user interaction
  ═══════════════════════════════════════════════════════ */
  let _idleTimer = null;

  const ActivityTracker = {
    start(backendUrl, onIdle) {
      const reset = () => {
        localStorage.setItem(STORAGE_KEYS.LAST_ACTIVITY, Date.now().toString());
        clearTimeout(_idleTimer);
        _idleTimer = setTimeout(() => {
          console.warn('[PersistentAuth] User idle for', IDLE_TIMEOUT_MS / 60000, 'minutes');
          if (onIdle) onIdle();
        }, IDLE_TIMEOUT_MS);
      };

      ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(evt => {
        document.addEventListener(evt, reset, { passive: true });
      });

      reset(); // Start the timer
    },

    stop() {
      clearTimeout(_idleTimer);
      _idleTimer = null;
    },
  };

  /* ══════════════════════════════════════════════════════
     SESSION RESTORE GATE
     On page load: restore session from localStorage,
     or trigger login screen
  ═══════════════════════════════════════════════════════ */
  const SessionRestoreGate = {

    async restore(backendUrl, retryCount = 0) {

      if (!PersistentTokenStore.hasSession()) {
        _dispatchEvent('auth:no-session');
        _authReadyResolve(true);
        return false;
      }

      const user = PersistentTokenStore.getUser();
      if (!user) {
        PersistentTokenStore.clear();
        _dispatchEvent('auth:no-session');
        return false;
      }

      // If offline mode, restore immediately without network call
      if (PersistentTokenStore.isOffline()) {
        _dispatchEvent('auth:restored', { user, offline: true });
        return true;
      }

      // Check if token is still valid
      if (!PersistentTokenStore.isExpired()) {
        _dispatchEvent('auth:restored', { user, offline: false });
        SmartRefresh.scheduleRefresh(backendUrl);
        return true;
      }

      // Token expired — try to refresh

      const refreshed = await SmartRefresh.refresh(backendUrl);

      if (refreshed) {
        const updatedUser = PersistentTokenStore.getUser() || user;
        _dispatchEvent('auth:restored', { user: updatedUser, offline: false });
        return true;
      }

      // Refresh failed — retry with exponential back-off (handles cold starts)
      if (retryCount < MAX_RESTORE_RETRIES) {
        const delay = RESTORE_RETRY_BASE_MS * Math.pow(2, retryCount);
        console.warn(`[PersistentAuth] Refresh failed — retry ${retryCount + 1}/${MAX_RESTORE_RETRIES} in ${delay}ms`);
        await _sleep(delay);
        return this.restore(backendUrl, retryCount + 1);
      }

      // All retries exhausted — fall back to offline mode if we have a user
      console.warn('[PersistentAuth] All refresh retries failed — falling back to offline mode');
      const newExpiry = new Date(Date.now() + DEFAULT_TTL_MS).toISOString();
      PersistentTokenStore.save({
        token:   'offline_restored_' + Date.now().toString(36),
        expiresAt: newExpiry,
        user,
        offline: true,
      });
      _dispatchEvent('auth:restored', { user, offline: true });
      return true;
    },
  };

  /* ══════════════════════════════════════════════════════
     HELPERS
  ═══════════════════════════════════════════════════════ */

  function _dispatchEvent(name, detail = {}) {
    try {
      document.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
    } catch (_) {
      /* SSR / test environment */
    }
  }

  function _sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  /* ══════════════════════════════════════════════════════
     EMERGENCY OFFLINE ACCOUNTS
     Used when backend is completely unavailable
  ═══════════════════════════════════════════════════════ */
  const EMERGENCY_ACCOUNTS = {
    'mahmoud@mssp.com': {
      id:          'offline-001',
      name:        'Mahmoud Osman',
      email:       'mahmoud@mssp.com',
      role:        'SUPER_ADMIN',
      tenant_id:   '00000000-0000-0000-0000-000000000001',
      tenant_slug: 'mssp-global',
      tenant_name: 'MSSP Global Operations',
      permissions: ['read','write','admin','super_admin','manage_tenants','manage_users',
                    'manage_billing','manage_integrations','view_audit_logs',
                    'delete_records','export_data','configure_platform'],
      avatar:      'MO',
    },
    'mahmoud.osman@wadjet.ai': {
      id:          'offline-002',
      name:        'Mahmoud Osman',
      email:       'mahmoud.osman@wadjet.ai',
      role:        'SUPER_ADMIN',
      tenant_id:   '00000000-0000-0000-0000-000000000001',
      tenant_slug: 'mssp-global',
      tenant_name: 'MSSP Global Operations',
      permissions: ['read','write','admin','super_admin','manage_tenants','manage_users',
                    'manage_billing','manage_integrations','view_audit_logs',
                    'delete_records','export_data','configure_platform'],
      avatar:      'MO',
    },
    'admin@mssp.com': {
      id:          'offline-003',
      name:        'Platform Admin',
      email:       'admin@mssp.com',
      role:        'ADMIN',
      tenant_id:   '00000000-0000-0000-0000-000000000001',
      tenant_slug: 'mssp-global',
      tenant_name: 'MSSP Global Operations',
      permissions: ['read','write','admin','manage_users','view_audit_logs','export_data'],
      avatar:      'PA',
    },
    'analyst@mssp.com': {
      id:          'offline-004',
      name:        'SOC Analyst',
      email:       'analyst@mssp.com',
      role:        'ANALYST',
      tenant_id:   '00000000-0000-0000-0000-000000000001',
      tenant_slug: 'mssp-global',
      tenant_name: 'MSSP Global Operations',
      permissions: ['read','write','manage_iocs','manage_cases'],
      avatar:      'SA',
    },
  };

  /* ══════════════════════════════════════════════════════
     PUBLIC API
  ═══════════════════════════════════════════════════════ */
  const PersistentAuth = {

    TokenStore: PersistentTokenStore,
    SmartRefresh,
    ActivityTracker,
    SessionRestoreGate,
    EMERGENCY_ACCOUNTS,

    /** Called after successful login */
    onLogin(loginResult, options = {}) {
      const { token, refreshToken, expiresAt, expiresIn, sessionId, user } = loginResult;
      const offline = options.offline || false;

      PersistentTokenStore.save({
        token:        token        || (offline ? 'offline_' + Date.now().toString(36) : ''),
        refreshToken: refreshToken || '',
        expiresAt:    expiresAt    || new Date(Date.now() + (expiresIn || 900) * 1000).toISOString(),
        user,
        sessionId:    sessionId    || null,
        offline,
      });

      if (!offline) {
        SmartRefresh.scheduleRefresh(options.backendUrl || '');
      }

      ActivityTracker.start(options.backendUrl, () => {
        console.warn('[PersistentAuth] User idle — session will expire');
        _dispatchEvent('auth:idle-warning');
      });

    },

    /** Called on logout */
    onLogout() {
      SmartRefresh.stop();
      ActivityTracker.stop();
      PersistentTokenStore.clear();
    },

    /** Attempt emergency offline login */
    emergencyLogin(email, password) {
      const profile = EMERGENCY_ACCOUNTS[email?.toLowerCase()];
      if (!profile) return null;

      // For demo purposes — in production, validate against a hashed password
      const knownPasswords = {
        'Admin@2024Wadjet!': true,
        'Admin@2024!':       true,
        'Analyst@Secure2024!': true,
      };

      if (!knownPasswords[password]) {
        return null;
      }

      const offlineToken = 'offline_' + btoa(email + ':' + Date.now()).replace(/=/g, '');
      const expiresAt    = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(); // 30 days

      PersistentTokenStore.save({
        token:        offlineToken,
        refreshToken: offlineToken,
        expiresAt,
        user:         profile,
        sessionId:    'offline-session-' + Date.now(),
        offline:      true,
      });

      return { user: profile, token: offlineToken, offline: true };
    },

    /** Get current token (from localStorage) */
    getToken() {
      return PersistentTokenStore.getToken();
    },

    /** Check if we have a valid non-expired session */
    isAuthenticated() {
      if (!PersistentTokenStore.hasSession()) return false;
      if (PersistentTokenStore.isOffline()) return true;
      return !PersistentTokenStore.isExpired();
    },

    /** Trigger a manual refresh */
    async refreshNow(backendUrl) {
      return SmartRefresh.refresh(backendUrl);
    },

    /** Restore session on page load */
    async restoreSession(backendUrl) {
      _authReadyResolve(true);
      return SessionRestoreGate.restore(backendUrl);
    },
  };

  /* ══════════════════════════════════════════════════════
     WIRE INTO PAGE LOAD
  ═══════════════════════════════════════════════════════ */
  if (typeof window !== 'undefined') {
    // Expose globally
    window.PersistentAuth = PersistentAuth;

    // On DOMContentLoaded, kick off session restoration
    const init = () => {
      const backendUrl = (window.CONFIG?.BACKEND_URL || 'https://wadjet-eye-ai.onrender.com');
      PersistentAuth.restoreSession(backendUrl);
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      // DOM already loaded
      setTimeout(init, 0);
    }

    // Handle visibility change — refresh token when tab becomes visible
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        const backendUrl = window.CONFIG?.BACKEND_URL || 'https://wadjet-eye-ai.onrender.com';
        if (PersistentTokenStore.hasSession() && PersistentTokenStore.isExpired()) {
          SmartRefresh.refresh(backendUrl);
        }
      }
    });

    // Handle online/offline events
    window.addEventListener('online', () => {
      const backendUrl = window.CONFIG?.BACKEND_URL || 'https://wadjet-eye-ai.onrender.com';
      if (PersistentTokenStore.hasSession()) {
        SmartRefresh.refresh(backendUrl);
      }
    });
  }

  /* ══════════════════════════════════════════════════════
     MODULE EXPORT
  ═══════════════════════════════════════════════════════ */
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PersistentAuth;
  }

})(typeof window !== 'undefined' ? window : global);
