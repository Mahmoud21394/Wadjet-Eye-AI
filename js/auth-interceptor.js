/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Centralized Auth Interceptor & Session Manager v5.2
 *  FILE: js/auth-interceptor.js
 *
 *  ROOT CAUSE ANALYSIS OF AUTH ISSUES:
 *  ─────────────────────────────────────
 *  1. Token key mismatch: api-client.js uses 'we_access_token' while
 *     auth-persistent.js saves to 'wadjet_access_token' → _fetch() reads
 *     the wrong key → always gets null token → 401 on every request.
 *
 *  2. Silent refresh not connected to _fetch() in live-pages.js.
 *     PersistentAuth_silentRefresh was called but never defined globally.
 *
 *  3. PersistentAuth_onLogin helper not exposed — login success
 *     in main.js didn't save tokens to the persistent store.
 *
 *  4. api-client.js TokenStore (sessionStorage) and auth-persistent.js
 *     PersistentTokenStore (localStorage) were TWO separate stores
 *     with no synchronization → refresh in one store not reflected in other.
 *
 *  5. SOAR UI and Platform Settings called fetch() directly instead of
 *     using the centralized API client → no auth headers → 401.
 *
 *  FIXES IN THIS FILE:
 *  ─────────────────────
 *  • Single source of truth: UNIFIED_TOKEN_STORE merging both stores
 *  • PersistentAuth_onLogin / PersistentAuth_onLogout / PersistentAuth_silentRefresh
 *    exposed as global helpers consumed by main.js
 *  • Proactive refresh at 80% TTL via scheduleProactiveRefresh()
 *  • auth:expired global event auto-triggers logout with 3s grace period
 *  • authFetch() — the ONE fetch wrapper all modules should use
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ═══════════════════════════════════════════════════════════════
   UNIFIED TOKEN STORE — single source of truth for ALL modules
   Keys written here are read by both api-client.js and live-pages.js
═══════════════════════════════════════════════════════════════ */
const UNIFIED_KEYS = {
  ACCESS:   'wadjet_access_token',   // primary key (PersistentAuth uses this)
  REFRESH:  'wadjet_refresh_token',
  EXPIRES:  'wadjet_token_expires_at',
  USER:     'wadjet_user_profile',
  SESSION:  'wadjet_session_id',
  OFFLINE:  'wadjet_offline_mode',
  // Legacy aliases written for backward compat
  LEGACY_ACCESS:  'we_access_token',
  LEGACY_REFRESH: 'we_refresh_token',
  LEGACY_EXP:     'we_token_expires',
  LEGACY_USER:    'we_user',
  TP_TOKEN:       'tp_access_token',
};

const UnifiedTokenStore = {
  /** Get the best available access token */
  getToken() {
    return localStorage.getItem(UNIFIED_KEYS.ACCESS)
        || localStorage.getItem(UNIFIED_KEYS.LEGACY_ACCESS)
        || localStorage.getItem(UNIFIED_KEYS.TP_TOKEN)
        || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_ACCESS)
        || sessionStorage.getItem('tp_token')
        || null;
  },

  getRefresh() {
    return localStorage.getItem(UNIFIED_KEYS.REFRESH)
        || localStorage.getItem(UNIFIED_KEYS.LEGACY_REFRESH)
        || null;
  },

  getExpiry() {
    const raw = localStorage.getItem(UNIFIED_KEYS.EXPIRES)
             || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_EXP);
    if (!raw) return null;
    const n = Number(raw);
    if (!isNaN(n) && n > 1e12) return new Date(n);          // ms timestamp
    const d = new Date(raw);
    return isNaN(d.getTime()) ? null : d;
  },

  getUser() {
    try {
      const raw = localStorage.getItem(UNIFIED_KEYS.USER)
               || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_USER)
               || localStorage.getItem(UNIFIED_KEYS.LEGACY_USER);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  isOffline() {
    return localStorage.getItem(UNIFIED_KEYS.OFFLINE) === '1';
  },

  isExpired(bufferMs = 30000) {
    if (this.isOffline()) return false;     // offline tokens never expire
    const exp = this.getExpiry();
    if (!exp) return !this.getToken();      // no expiry info, check token exists
    return exp.getTime() - bufferMs < Date.now();
  },

  msUntilExpiry() {
    const exp = this.getExpiry();
    if (!exp) return 0;
    return Math.max(0, exp.getTime() - Date.now());
  },

  hasSession() {
    return !!(this.getRefresh() || this.getToken());
  },

  /**
   * Save tokens — writes to ALL keys (primary + legacy) so every
   * module finds its token regardless of which key it reads.
   */
  save({ token, refreshToken, expiresAt, expiresIn, user, sessionId, offline = false }) {
    try {
      if (token) {
        localStorage.setItem(UNIFIED_KEYS.ACCESS, token);
        localStorage.setItem(UNIFIED_KEYS.LEGACY_ACCESS, token);
        localStorage.setItem(UNIFIED_KEYS.TP_TOKEN, token);
        sessionStorage.setItem(UNIFIED_KEYS.LEGACY_ACCESS, token);
        sessionStorage.setItem('tp_token', token);
      }
      if (refreshToken) {
        localStorage.setItem(UNIFIED_KEYS.REFRESH, refreshToken);
        localStorage.setItem(UNIFIED_KEYS.LEGACY_REFRESH, refreshToken);
      }

      // Calculate expiresAt
      let exp = expiresAt;
      if (!exp && expiresIn) {
        exp = new Date(Date.now() + Number(expiresIn) * 1000).toISOString();
      }
      if (!exp && token && !offline) {
        // Default 15 min if not provided
        exp = new Date(Date.now() + 900 * 1000).toISOString();
      }
      if (exp) {
        localStorage.setItem(UNIFIED_KEYS.EXPIRES, exp);
        sessionStorage.setItem(UNIFIED_KEYS.LEGACY_EXP, String(new Date(exp).getTime()));
      }

      if (user) {
        const json = JSON.stringify(user);
        localStorage.setItem(UNIFIED_KEYS.USER, json);
        localStorage.setItem(UNIFIED_KEYS.LEGACY_USER, json);
        sessionStorage.setItem(UNIFIED_KEYS.LEGACY_USER, json);
      }
      if (sessionId) localStorage.setItem(UNIFIED_KEYS.SESSION, sessionId);
      localStorage.setItem(UNIFIED_KEYS.OFFLINE, offline ? '1' : '0');

    } catch (e) {
      console.warn('[AuthInterceptor] Storage save failed:', e.message);
    }
  },

  clear() {
    Object.values(UNIFIED_KEYS).forEach(k => {
      try { localStorage.removeItem(k); } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    });
    // Also clear extra session keys
    ['tp_token', 'tp_refresh', 'tp_user'].forEach(k => {
      try { localStorage.removeItem(k); } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    });
  },

  updateTokens({ token, refreshToken, expiresAt, expiresIn, user, sessionId }) {
    this.save({ token, refreshToken, expiresAt, expiresIn, user, sessionId,
                offline: this.isOffline() });
  },
};

/* ═══════════════════════════════════════════════════════════════
   REFRESH ENGINE — deduplicated, with lock + retry
═══════════════════════════════════════════════════════════════ */
let _refreshLock    = false;
let _refreshPromise = null;
let _proactiveTimer = null;
const MAX_RETRY_DELAY = 30000;

async function _doTokenRefresh() {
  const backendUrl = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  const refreshToken = UnifiedTokenStore.getRefresh();

  if (!refreshToken) {
    console.warn('[AuthInterceptor] No refresh token available');
    return false;
  }

  // Offline mode — extend locally
  if (UnifiedTokenStore.isOffline()) {
    const newToken  = 'offline_' + Date.now().toString(36);
    const newExpiry = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    UnifiedTokenStore.save({ token: newToken, expiresAt: newExpiry, offline: true });
    console.log('[AuthInterceptor] 🔌 Offline token extended');
    return true;
  }

  try {
    console.log('[AuthInterceptor] 🔄 Refreshing access token...');
    const res = await fetch(`${backendUrl}/api/auth/refresh`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refreshToken }),
      signal:  AbortSignal.timeout(15000),
    });

    if (res.status === 401) {
      const body = await res.json().catch(() => ({}));
      console.warn('[AuthInterceptor] Refresh token rejected:', body.error);
      _dispatchAuthEvent('auth:session-expired', { reason: body.error || 'refresh_rejected' });
      return false;
    }

    if (!res.ok) {
      console.warn('[AuthInterceptor] Refresh endpoint returned', res.status);
      return false;
    }

    const data = await res.json();
    const newToken = data.token || data.access_token;
    if (!newToken) {
      console.warn('[AuthInterceptor] Refresh response missing token');
      return false;
    }

    UnifiedTokenStore.updateTokens({
      token:        newToken,
      // ONLY overwrite refresh token if backend actually sent a new one
      refreshToken: data.refreshToken || data.refresh_token || UnifiedTokenStore.getRefresh(),
      expiresAt:    data.expiresAt    || data.expires_at,
      expiresIn:    data.expiresIn    || data.expires_in,
      user:         data.user,
      sessionId:    data.sessionId    || data.session_id,
    });

    // Sync with CURRENT_USER
    if (data.user && window.CURRENT_USER) {
      Object.assign(window.CURRENT_USER, data.user);
    }

    // Sync with api-client.js TokenStore if available
    if (typeof window.TokenStore !== 'undefined') {
      window.TokenStore.set(
        newToken,
        data.refreshToken || data.refresh_token,
        data.expiresAt || data.expiresIn
      );
    }
    // Sync with PersistentTokenStore if available
    if (typeof window.PersistentAuth !== 'undefined') {
      window.PersistentAuth.TokenStore.updateTokens({
        token:        newToken,
        refreshToken: data.refreshToken || data.refresh_token,
        expiresAt:    data.expiresAt,
        expiresIn:    data.expiresIn,
      });
    }

    _scheduleProactiveRefresh();
    _dispatchAuthEvent('auth:token-refreshed', { token: newToken });
    console.log('[AuthInterceptor] ✅ Token refreshed OK');
    return true;

  } catch (err) {
    if (err.name === 'AbortError' || err.name === 'TimeoutError') {
      console.warn('[AuthInterceptor] Refresh timeout (cold start?) — keeping session alive');
      return false;
    }
    if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
      console.warn('[AuthInterceptor] Network offline — skip refresh');
      return false;
    }
    console.warn('[AuthInterceptor] Refresh error:', err.message);
    return false;
  }
}

async function silentRefresh() {
  if (_refreshLock && _refreshPromise) {
    return _refreshPromise;
  }
  _refreshLock    = true;
  _refreshPromise = _doTokenRefresh();
  try {
    return await _refreshPromise;
  } finally {
    _refreshLock    = false;
    _refreshPromise = null;
  }
}

function _scheduleProactiveRefresh() {
  if (_proactiveTimer) { clearTimeout(_proactiveTimer); _proactiveTimer = null; }
  const msLeft = UnifiedTokenStore.msUntilExpiry();
  if (msLeft <= 0) { silentRefresh(); return; }
  const delay = Math.max(5000, msLeft * 0.80);
  console.log(`[AuthInterceptor] ⏱ Next proactive refresh in ${Math.round(delay / 60000)} min`);
  _proactiveTimer = setTimeout(() => {
    if (UnifiedTokenStore.hasSession()) silentRefresh();
  }, delay);
}

/* ═══════════════════════════════════════════════════════════════
   AUTH FETCH — unified fetch wrapper for ALL modules
   Replaces: _fetch() in live-pages.js, direct fetch() in soar-ui.js,
   direct fetch() in platform-settings.js
═══════════════════════════════════════════════════════════════ */
async function authFetch(path, opts = {}) {
  const base = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

  // Pre-flight refresh if token is expiring
  if (!UnifiedTokenStore.isOffline() &&
      UnifiedTokenStore.isExpired(60000) &&
      UnifiedTokenStore.hasSession()) {
    await silentRefresh();
  }

  const token = UnifiedTokenStore.getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };

  const fetchOpts = {
    method:      opts.method || 'GET',
    headers,
    credentials: 'include',
    ...(opts.body ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) } : {}),
  };

  const fullUrl = path.startsWith('http') ? path : `${base}/api${path}`;

  let resp;
  try {
    resp = await fetch(fullUrl, fetchOpts);
  } catch (netErr) {
    console.warn('[AuthFetch] Network error for', path, '—', netErr.message);
    return { data: [], total: 0, page: 1, limit: 25, _offline: true };
  }

  // 401 → silent refresh → one retry
  if (resp.status === 401 || resp.status === 403) {
    console.warn(`[AuthFetch] ${resp.status} on ${path} — attempting token refresh`);
    const refreshed = await silentRefresh();

    if (refreshed) {
      const newToken = UnifiedTokenStore.getToken();
      try {
        resp = await fetch(fullUrl, {
          ...fetchOpts,
          headers: { ...headers, Authorization: `Bearer ${newToken}` },
        });
      } catch { /* fall through to error handling */ }
    }

    // Still 401 after refresh → session truly expired
    if (!resp || resp.status === 401 || resp.status === 403) {
      _dispatchAuthEvent('auth:expired', { path });
      throw new Error('AUTH_EXPIRED: Session expired. Please log in again.');
    }
  }

  if (resp.status === 204) return null;

  if (resp.status === 404) {
    console.warn(`[AuthFetch] 404 on ${path}`);
    return { data: [], total: 0, page: 1, limit: 25 };
  }

  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`HTTP ${resp.status} — ${txt.slice(0, 120)}`);
  }

  try {
    return await resp.json();
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════════════════════════
   GLOBAL HELPERS — consumed by main.js, soar-ui.js, etc.
═══════════════════════════════════════════════════════════════ */

/**
 * Called by main.js after successful login.
 * Saves tokens to UnifiedTokenStore and schedules proactive refresh.
 */
window.PersistentAuth_onLogin = function(user, token, refreshToken, expiresAt, isOffline) {
  UnifiedTokenStore.save({
    token,
    refreshToken,
    expiresAt: typeof expiresAt === 'number'
      ? new Date(Date.now() + expiresAt * 1000).toISOString()
      : expiresAt || new Date(Date.now() + 900 * 1000).toISOString(),
    user,
    offline: !!isOffline,
  });

  if (!isOffline) _scheduleProactiveRefresh();

  // Also sync with api-client.js TokenStore
  if (typeof window.TokenStore !== 'undefined') {
    window.TokenStore.set(token, refreshToken, expiresAt);
    if (user) window.TokenStore.setUser(user);
  }

  // Also sync with PersistentAuth
  if (typeof window.PersistentAuth !== 'undefined') {
    window.PersistentAuth.onLogin({
      token, refreshToken, expiresAt,
      user, offline: !!isOffline,
    });
  }

  console.log('[AuthInterceptor] ✅ Login recorded for', user?.email);
};

/**
 * Called by main.js on logout.
 */
window.PersistentAuth_onLogout = function() {
  if (_proactiveTimer) { clearTimeout(_proactiveTimer); _proactiveTimer = null; }
  UnifiedTokenStore.clear();
  if (typeof window.PersistentAuth !== 'undefined') window.PersistentAuth.onLogout();
  console.log('[AuthInterceptor] 👋 Logged out — all tokens cleared');
};

/**
 * Silent refresh wrapper — exposed for live-pages.js _fetch() and other modules.
 */
window.PersistentAuth_silentRefresh = silentRefresh;

/**
 * Get current token — exposed globally for modules that need raw token.
 */
window.getAuthToken = () => UnifiedTokenStore.getToken();

/**
 * Check if there's a valid (non-expired) session.
 */
window.isAuthenticated = () => {
  if (!UnifiedTokenStore.hasSession()) return false;
  if (UnifiedTokenStore.isOffline()) return true;
  return !UnifiedTokenStore.isExpired();
};

/* ═══════════════════════════════════════════════════════════════
   AUTH EVENT DISPATCHER
═══════════════════════════════════════════════════════════════ */
function _dispatchAuthEvent(name, detail = {}) {
  try {
    window.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
    document.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
  } catch (_) {}
}

/* ═══════════════════════════════════════════════════════════════
   GLOBAL AUTH:EXPIRED HANDLER
   Gracefully redirects to login after session truly expires.
═══════════════════════════════════════════════════════════════ */
let _expiredHandled = false;
window.addEventListener('auth:expired', () => {
  if (_expiredHandled) return;
  _expiredHandled = true;
  setTimeout(() => { _expiredHandled = false; }, 10000); // reset after 10s

  console.warn('[AuthInterceptor] 🔒 Session expired — redirecting to login');
  if (typeof window.showToast === 'function') {
    window.showToast('Session expired. Please log in again.', 'error', 4000);
  }

  setTimeout(() => {
    if (typeof window.doLogout === 'function') {
      window.doLogout();
    } else {
      UnifiedTokenStore.clear();
      const mainApp     = document.getElementById('mainApp');
      const loginScreen = document.getElementById('loginScreen');
      if (mainApp)     mainApp.style.display = 'none';
      if (loginScreen) { loginScreen.style.display = 'flex'; loginScreen.style.opacity = '1'; }
    }
  }, 3000);
});

/* ═══════════════════════════════════════════════════════════════
   PAGE VISIBILITY — refresh on tab focus if token near-expired
═══════════════════════════════════════════════════════════════ */
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && UnifiedTokenStore.hasSession()) {
    const msLeft = UnifiedTokenStore.msUntilExpiry();
    if (msLeft <= 120000 && msLeft > 0) {  // < 2 min left
      console.log('[AuthInterceptor] Tab visible with token expiring soon — refreshing');
      silentRefresh();
    }
  }
});

/* ═══════════════════════════════════════════════════════════════
   ONLINE/OFFLINE EVENTS
═══════════════════════════════════════════════════════════════ */
window.addEventListener('online', () => {
  if (UnifiedTokenStore.hasSession() && !UnifiedTokenStore.isOffline()) {
    console.log('[AuthInterceptor] Network restored — refreshing token');
    silentRefresh();
  }
});

/* ═══════════════════════════════════════════════════════════════
   STARTUP — sync stores on load
═══════════════════════════════════════════════════════════════ */
(function _syncStoresOnLoad() {
  // If api-client.js TokenStore has a token but UnifiedTokenStore doesn't,
  // copy it over (handles migration from old sessions).
  const legacyToken = localStorage.getItem('we_access_token')
                   || sessionStorage.getItem('we_access_token');
  const primaryToken = localStorage.getItem('wadjet_access_token');

  if (legacyToken && !primaryToken) {
    localStorage.setItem('wadjet_access_token', legacyToken);
    localStorage.setItem('wadjet_tp_token', legacyToken);
    console.log('[AuthInterceptor] Migrated legacy token to unified store');
  }

  // Schedule proactive refresh if we have a valid session
  if (UnifiedTokenStore.hasSession() && !UnifiedTokenStore.isExpired()) {
    _scheduleProactiveRefresh();
  }
})();

/* ═══════════════════════════════════════════════════════════════
   EXPORT
═══════════════════════════════════════════════════════════════ */
window.UnifiedTokenStore    = UnifiedTokenStore;
window.authFetch            = authFetch;
window.silentRefresh        = silentRefresh;

console.log('[AuthInterceptor] ✅ Auth Interceptor v5.2 loaded');
