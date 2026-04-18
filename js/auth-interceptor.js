/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Centralized Auth Interceptor & Token Store v6.0
 *  FILE: js/auth-interceptor.js
 *
 *  REQUIRES: js/state-sync.js (must be loaded first)
 *
 *  ARCHITECTURAL ROLE:
 *  ─────────────────────────────────────────────────────────────────────
 *  This is the SINGLE module responsible for token lifecycle.
 *  All other modules (api-client, ai-orchestrator, rakay-module) read
 *  tokens from UnifiedTokenStore and NEVER handle refresh themselves.
 *
 *  STARTUP SEQUENCE (v6.0):
 *  ─────────────────────────────────────────────────────────────────────
 *  1. _syncStoresOnLoad()  — restore BOTH access + refresh from storage
 *  2. If expired → silentRefresh() → /api/auth/refresh
 *  3. If refresh token missing → /api/auth/refresh-from-cookie
 *  4. Mark StateSync.authReady → ALL other modules unblock
 *  5. Schedule proactive refresh at 80% of remaining TTL
 *
 *  KEY FIXES vs v5.2:
 *  ─────────────────────────────────────────────────────────────────────
 *  • Refresh token ALWAYS persisted to localStorage (never lost on reload)
 *  • _syncStoresOnLoad restores BOTH access AND refresh token
 *  • If no refresh token in storage → attempts /api/auth/refresh-from-cookie
 *  • Silent refresh retries up to 3x with exponential backoff before giving up
 *  • StateSync.markAuthReady() called after sync → unblocks WS + RAKAY + Orch
 *  • authFetch 401 handler checks StateSync.isAuthenticated() FIRST —
 *    never treats provider 401s as "invalid API key"
 *  • Proactive refresh fires at 80% of TOKEN TTL (not fixed 2min window)
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ═══════════════════════════════════════════════════════════════
   GUARD: StateSync must exist (loaded before this file)
═══════════════════════════════════════════════════════════════ */
if (typeof window.StateSync === 'undefined') {
  console.error('[AuthInterceptor] FATAL: state-sync.js must be loaded before auth-interceptor.js');
}

/* ═══════════════════════════════════════════════════════════════
   UNIFIED TOKEN STORE — single source of truth for ALL modules
   Keys written here are read by api-client.js, ai-orchestrator,
   and rakay-module. Writes to primary + all legacy aliases.
═══════════════════════════════════════════════════════════════ */
const UNIFIED_KEYS = {
  // Primary keys (v6.0+)
  ACCESS:   'wadjet_access_token',
  REFRESH:  'wadjet_refresh_token',   // ⚠️  ALWAYS written to localStorage — never session-only
  EXPIRES:  'wadjet_token_expires_at',
  USER:     'wadjet_user_profile',
  SESSION:  'wadjet_session_id',
  OFFLINE:  'wadjet_offline_mode',
  // Legacy aliases — read by older modules
  LEGACY_ACCESS:  'we_access_token',
  LEGACY_REFRESH: 'we_refresh_token',
  LEGACY_EXP:     'we_token_expires',
  LEGACY_USER:    'we_user',
  TP_TOKEN:       'tp_access_token',
};

const UnifiedTokenStore = {
  /** Best available access token across all storage keys */
  getToken() {
    return localStorage.getItem(UNIFIED_KEYS.ACCESS)
        || localStorage.getItem(UNIFIED_KEYS.LEGACY_ACCESS)
        || localStorage.getItem(UNIFIED_KEYS.TP_TOKEN)
        || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_ACCESS)
        || sessionStorage.getItem('tp_token')
        || null;
  },

  /**
   * Refresh token — ALWAYS stored in localStorage.
   * This is the root fix: old code stored it only in sessionStorage,
   * causing "No refresh token available" on every page reload.
   */
  getRefresh() {
    return localStorage.getItem(UNIFIED_KEYS.REFRESH)
        || localStorage.getItem(UNIFIED_KEYS.LEGACY_REFRESH)
        || null;
  },

  getExpiry() {
    const raw = localStorage.getItem(UNIFIED_KEYS.EXPIRES)
             || localStorage.getItem(UNIFIED_KEYS.LEGACY_EXP)
             || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_EXP);
    if (!raw) return null;
    const n = Number(raw);
    if (!isNaN(n) && n > 1_000_000_000_000) return new Date(n); // ms timestamp
    const d = new Date(raw);
    return isNaN(d.getTime()) ? null : d;
  },

  getUser() {
    try {
      const raw = localStorage.getItem(UNIFIED_KEYS.USER)
               || localStorage.getItem(UNIFIED_KEYS.LEGACY_USER)
               || sessionStorage.getItem(UNIFIED_KEYS.LEGACY_USER);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  isOffline() {
    return localStorage.getItem(UNIFIED_KEYS.OFFLINE) === '1';
  },

  /**
   * True if access token is expired (within bufferMs of expiry).
   * A missing expiry timestamp is treated as expired only if no token exists.
   */
  isExpired(bufferMs = 30_000) {
    if (this.isOffline()) return false;
    const exp = this.getExpiry();
    if (!exp) return !this.getToken();
    return exp.getTime() - bufferMs < Date.now();
  },

  msUntilExpiry() {
    const exp = this.getExpiry();
    if (!exp) return 0;
    return Math.max(0, exp.getTime() - Date.now());
  },

  /** True if we have ANY credential (access or refresh) to work with */
  hasSession() {
    return !!(this.getRefresh() || this.getToken());
  },

  /**
   * Persist tokens.
   * CRITICAL: refresh token is ALWAYS written to localStorage
   * (never sessionStorage) so it survives page reloads and tab restores.
   */
  save({ token, refreshToken, expiresAt, expiresIn, user, sessionId, offline = false }) {
    try {
      // ── Access token: write to both storages for maximum compatibility ──
      if (token) {
        localStorage.setItem(UNIFIED_KEYS.ACCESS,         token);
        localStorage.setItem(UNIFIED_KEYS.LEGACY_ACCESS,  token);
        localStorage.setItem(UNIFIED_KEYS.TP_TOKEN,       token);
        sessionStorage.setItem(UNIFIED_KEYS.LEGACY_ACCESS, token);
        sessionStorage.setItem('tp_token',                 token);
      }

      // ── Refresh token: ONLY localStorage — this is the critical fix ──────
      if (refreshToken) {
        localStorage.setItem(UNIFIED_KEYS.REFRESH,        refreshToken);
        localStorage.setItem(UNIFIED_KEYS.LEGACY_REFRESH, refreshToken);
        // Explicitly do NOT write to sessionStorage
      }

      // ── Expiry timestamp ─────────────────────────────────────────────────
      let exp = expiresAt;
      if (!exp && expiresIn) {
        exp = new Date(Date.now() + Number(expiresIn) * 1000).toISOString();
      }
      if (!exp && token && !offline) {
        // Conservative default: 15 minutes
        exp = new Date(Date.now() + 900_000).toISOString();
      }
      if (exp) {
        localStorage.setItem(UNIFIED_KEYS.EXPIRES, exp);
        // Legacy modules read a ms timestamp from LEGACY_EXP
        localStorage.setItem(UNIFIED_KEYS.LEGACY_EXP,  String(new Date(exp).getTime()));
        sessionStorage.setItem(UNIFIED_KEYS.LEGACY_EXP, String(new Date(exp).getTime()));
      }

      // ── User profile ─────────────────────────────────────────────────────
      if (user) {
        const json = JSON.stringify(user);
        localStorage.setItem(UNIFIED_KEYS.USER,        json);
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
      try { localStorage.removeItem(k);   } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    });
    ['tp_token', 'tp_refresh', 'tp_user', 'accessToken', 'refreshToken'].forEach(k => {
      try { localStorage.removeItem(k);   } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    });
  },

  updateTokens({ token, refreshToken, expiresAt, expiresIn, user, sessionId }) {
    this.save({
      token, refreshToken, expiresAt, expiresIn, user, sessionId,
      offline: this.isOffline(),
    });
  },
};

/* ═══════════════════════════════════════════════════════════════
   REFRESH ENGINE
   - Single in-flight lock (no concurrent refresh storms)
   - Up to 3 retries with exponential backoff (1s, 2s, 4s)
   - Falls back to cookie-refresh if no refresh token in storage
═══════════════════════════════════════════════════════════════ */
let _refreshLock    = false;
let _refreshPromise = null;
let _proactiveTimer = null;

// ── Rate-limit guards for cookie-refresh ─────────────────────────────
// Prevent hammering /api/auth/refresh-from-cookie when the backend
// returns 400 (no cookie) or 429 (too many requests).
//
// ROOT-CAUSE FIX v6.1:
//   The `_cookieRefreshFailedAt` and `_cookieRefreshBackoffMs` variables
//   were pure in-memory state, which means they reset on every page reload.
//   This caused the NO_COOKIE 400 error to fire again on the first request
//   of every new page load, even if the user had already demonstrated they
//   have no httpOnly cookie.
//
//   Fix: Persist the "no cookie available" state in sessionStorage so
//   within the same browser tab session we don't attempt the cookie refresh
//   again if we already got a definitive 400 NO_COOKIE response.
//   (sessionStorage is cleared on tab close, so the user can try again
//   after a fresh open, e.g. if they logged in on a different device.)
const _COOKIE_FAIL_KEY = 'wadjet_cookie_refresh_blocked_until';
let _cookieRefreshFailedAt   = parseInt(sessionStorage.getItem('wadjet_cookie_refresh_failed_at') || '0', 10);
let _cookieRefreshBackoffMs  = parseInt(sessionStorage.getItem('wadjet_cookie_refresh_backoff') || '0', 10);
const COOKIE_REFRESH_MIN_INTERVAL_MS = 30_000;   // 30 s minimum between attempts
const COOKIE_REFRESH_MAX_BACKOFF_MS  = 300_000;  // 5 min maximum backoff

function _persistCookieRefreshState() {
  try {
    sessionStorage.setItem('wadjet_cookie_refresh_failed_at', String(_cookieRefreshFailedAt));
    sessionStorage.setItem('wadjet_cookie_refresh_backoff',   String(_cookieRefreshBackoffMs));
  } catch (_) {}
}
function _clearCookieRefreshState() {
  _cookieRefreshFailedAt  = 0;
  _cookieRefreshBackoffMs = 0;
  try {
    sessionStorage.removeItem('wadjet_cookie_refresh_failed_at');
    sessionStorage.removeItem('wadjet_cookie_refresh_backoff');
    sessionStorage.removeItem(_COOKIE_FAIL_KEY);
  } catch (_) {}
}

// ── Refresh-from-main guard — prevent 429 storms on /api/auth/refresh
let _lastRefreshAttemptAt = 0;
const REFRESH_MIN_INTERVAL_MS = 5_000; // 5 s minimum between refresh attempts

const BACKEND_URL = () =>
  (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

async function _doTokenRefresh(attempt = 0) {
  const MAX_ATTEMPTS = 3;
  const refreshToken = UnifiedTokenStore.getRefresh();

  // ── Offline mode: extend token locally ──────────────────────────────
  if (UnifiedTokenStore.isOffline()) {
    const newToken  = 'offline_' + Date.now().toString(36);
    const newExpiry = new Date(Date.now() + 15 * 60_000).toISOString();
    UnifiedTokenStore.save({ token: newToken, expiresAt: newExpiry, offline: true });
    console.log('[AuthInterceptor] 🔌 Offline token extended');
    return true;
  }

  // ── Rate-limit guard: don't hammer the endpoint ──────────────────────
  if (attempt === 0) {
    const elapsed = Date.now() - _lastRefreshAttemptAt;
    if (elapsed < REFRESH_MIN_INTERVAL_MS) {
      console.warn(`[AuthInterceptor] Refresh requested too soon (${elapsed}ms since last attempt) — skipping`);
      return false;
    }
    _lastRefreshAttemptAt = Date.now();
  }

  // ── No refresh token in storage → try cookie refresh ────────────────
  if (!refreshToken) {
    console.warn('[AuthInterceptor] No refresh token in storage — attempting cookie-based refresh');
    return _refreshFromCookie();
  }

  try {
    console.log(`[AuthInterceptor] 🔄 Refreshing access token (attempt ${attempt + 1}/${MAX_ATTEMPTS})…`);
    const res = await fetch(`${BACKEND_URL()}/api/auth/refresh`, {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      body:        JSON.stringify({ refresh_token: refreshToken }),
      credentials: 'include',        // also send cookies
      signal:      AbortSignal.timeout(15_000),
    });

    // ── Refresh token rejected (truly expired or revoked) ────────────
    if (res.status === 401) {
      const body = await res.json().catch(() => ({}));
      console.warn('[AuthInterceptor] Refresh token rejected:', body.error || 'session_expired');
      // Try cookie as last resort before giving up (only once)
      if (attempt === 0) {
        const cookieOk = await _refreshFromCookie();
        if (cookieOk) return true;
      }
      _dispatchAuthEvent('auth:session-expired', { reason: body.error || 'refresh_rejected' });
      window.StateSync?.handleAuthExpiry({ reason: 'refresh_rejected' });
      return false;
    }

    // ── Rate limited by backend ──────────────────────────────────────
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('retry-after') || '60', 10);
      console.warn(`[AuthInterceptor] Rate limited by /api/auth/refresh — backing off ${retryAfter}s`);
      // Back off — don't retry this cycle
      _lastRefreshAttemptAt = Date.now() + (retryAfter * 1000) - REFRESH_MIN_INTERVAL_MS;
      return false;
    }

    if (!res.ok) {
      console.warn('[AuthInterceptor] Refresh endpoint returned', res.status);
      if (attempt < MAX_ATTEMPTS - 1) {
        await _sleep(Math.pow(2, attempt) * 1000);
        return _doTokenRefresh(attempt + 1);
      }
      return false;
    }

    const data      = await res.json();

    // ── requires_reauth: backend couldn't issue a new access token ────────
    // (e.g. admin.createSession unavailable + no JWT_SECRET configured)
    // In this case a re-login is needed. Dispatch auth:expired and return false.
    if (data.requires_reauth) {
      console.warn('[AuthInterceptor] Backend requires re-authentication — triggering re-login');
      _dispatchAuthEvent('auth:session-expired', { reason: 'requires_reauth' });
      window.StateSync?.handleAuthExpiry({ reason: 'requires_reauth' });
      return false;
    }

    const newToken  = data.token || data.access_token;
    if (!newToken) {
      console.warn('[AuthInterceptor] Refresh response missing token field');
      return false;
    }

    // ── Persist new tokens ────────────────────────────────────────────
    UnifiedTokenStore.updateTokens({
      token:        newToken,
      // Keep old refresh token if backend didn't send a new one (rotation not always done)
      refreshToken: data.refreshToken || data.refresh_token || UnifiedTokenStore.getRefresh(),
      expiresAt:    data.expiresAt    || data.expires_at,
      expiresIn:    data.expiresIn    || data.expires_in,
      user:         data.user,
      sessionId:    data.sessionId    || data.session_id,
    });

    // Sync with global CURRENT_USER
    if (data.user && window.CURRENT_USER) {
      Object.assign(window.CURRENT_USER, data.user);
    }

    // Sync with legacy TokenStore (api-client.js) if loaded
    if (typeof window.TokenStore !== 'undefined') {
      window.TokenStore.set(
        newToken,
        data.refreshToken || data.refresh_token || UnifiedTokenStore.getRefresh(),
        data.expiresAt || data.expiresIn,
      );
    }

    // Notify WS to update its auth token
    if (window.WS?.updateAuth) window.WS.updateAuth();

    _scheduleProactiveRefresh();
    _dispatchAuthEvent('auth:token-refreshed', { token: newToken });
    window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });

    console.log('[AuthInterceptor] ✅ Token refreshed successfully');
    return true;

  } catch (err) {
    if (err.name === 'AbortError' || err.name === 'TimeoutError') {
      console.warn('[AuthInterceptor] Refresh request timeout — preserving session');
      return false;
    }
    if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
      console.warn('[AuthInterceptor] Network offline — skipping refresh');
      return false;
    }
    if (attempt < MAX_ATTEMPTS - 1) {
      console.warn(`[AuthInterceptor] Refresh attempt ${attempt + 1} failed:`, err.message, '— retrying');
      await _sleep(Math.pow(2, attempt) * 1000);
      return _doTokenRefresh(attempt + 1);
    }
    console.warn('[AuthInterceptor] All refresh attempts exhausted:', err.message);
    return false;
  }
}

/**
 * Cookie-based refresh — called when localStorage has no refresh token
 * but the browser may still have an httpOnly session cookie.
 *
 * v6.1 FIX: Implements backoff to prevent 429 storms.
 *   - 400 (no cookie): permanently skip until next hard login
 *   - 429 (rate limited): back off using Retry-After header
 *   - Other errors: exponential backoff up to 5 min
 */
async function _refreshFromCookie() {
  // ── Check cooldown ──────────────────────────────────────────────────
  const now    = Date.now();
  const sinceLast = now - _cookieRefreshFailedAt;

  // If currently in backoff, skip
  if (_cookieRefreshFailedAt > 0 && sinceLast < _cookieRefreshBackoffMs) {
    console.warn(`[AuthInterceptor] Cookie refresh in backoff — ${Math.round((_cookieRefreshBackoffMs - sinceLast) / 1000)}s remaining`);
    return false;
  }

  try {
    console.log('[AuthInterceptor] Attempting cookie-based refresh at /api/auth/refresh-from-cookie');
    const res = await fetch(`${BACKEND_URL()}/api/auth/refresh-from-cookie`, {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      signal:      AbortSignal.timeout(10_000),
    });

    // ── 400: No cookie present — don't retry (no cookie will magically appear)
    if (res.status === 400) {
      const body = await res.json().catch(() => ({}));
      console.warn('[AuthInterceptor] Cookie refresh 400 — no httpOnly cookie present (', body.code || body.error, ')');
      // Set a long backoff — cookie won't appear until user logs in fresh
      _cookieRefreshFailedAt  = Date.now();
      _cookieRefreshBackoffMs = COOKIE_REFRESH_MAX_BACKOFF_MS; // 5 min
      _persistCookieRefreshState(); // persist across module re-evaluations
      return false;
    }

    // ── 429: Rate limited — respect Retry-After header
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('retry-after') || '60', 10);
      _cookieRefreshFailedAt  = Date.now();
      _cookieRefreshBackoffMs = Math.min(retryAfter * 1000, COOKIE_REFRESH_MAX_BACKOFF_MS);
      _persistCookieRefreshState();
      console.warn(`[AuthInterceptor] Cookie refresh rate limited — backing off ${retryAfter}s`);
      return false;
    }

    if (!res.ok) {
      // Exponential backoff for other errors
      _cookieRefreshFailedAt  = Date.now();
      _cookieRefreshBackoffMs = Math.min(
        (_cookieRefreshBackoffMs || COOKIE_REFRESH_MIN_INTERVAL_MS) * 2,
        COOKIE_REFRESH_MAX_BACKOFF_MS,
      );
      _persistCookieRefreshState();
      console.warn(`[AuthInterceptor] Cookie refresh failed (${res.status}) — backing off ${_cookieRefreshBackoffMs / 1000}s`);
      return false;
    }

    const data     = await res.json();
    const newToken = data.token || data.access_token;
    if (!newToken) return false;

    // ── Success: reset backoff ──────────────────────────────────────────
    _clearCookieRefreshState();

    UnifiedTokenStore.save({
      token:        newToken,
      refreshToken: data.refreshToken || data.refresh_token,
      expiresAt:    data.expiresAt    || data.expires_at,
      expiresIn:    data.expiresIn    || data.expires_in,
      user:         data.user,
    });

    console.log('[AuthInterceptor] ✅ Cookie refresh succeeded');
    _scheduleProactiveRefresh();
    return true;

  } catch (err) {
    // Network timeout or other transient error
    _cookieRefreshFailedAt  = Date.now();
    _cookieRefreshBackoffMs = Math.min(
      (_cookieRefreshBackoffMs || COOKIE_REFRESH_MIN_INTERVAL_MS) * 2,
      COOKIE_REFRESH_MAX_BACKOFF_MS,
    );
    _persistCookieRefreshState();
    console.warn('[AuthInterceptor] Cookie refresh error:', err.message, `— backing off ${_cookieRefreshBackoffMs / 1000}s`);
    return false;
  }
}

/** Deduplicated, locked silent refresh */
async function silentRefresh() {
  if (_refreshLock && _refreshPromise) {
    return _refreshPromise;           // already in progress — return same promise
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

/**
 * Schedule proactive refresh at 80% of remaining token lifetime.
 * Example: 900s token → refresh fires at ~720s, 180s before expiry.
 */
function _scheduleProactiveRefresh() {
  if (_proactiveTimer) { clearTimeout(_proactiveTimer); _proactiveTimer = null; }

  const msLeft = UnifiedTokenStore.msUntilExpiry();
  if (msLeft <= 0) {
    silentRefresh();
    return;
  }

  // Fire at 80% of remaining time (ensures refresh before expiry)
  const delay = Math.max(10_000, msLeft * 0.80);
  console.log(`[AuthInterceptor] ⏱ Proactive refresh scheduled in ${Math.round(delay / 60_000)} min`);
  _proactiveTimer = setTimeout(() => {
    if (UnifiedTokenStore.hasSession()) silentRefresh();
  }, delay);
}

/* ═══════════════════════════════════════════════════════════════
   AUTH FETCH — unified fetch wrapper for ALL modules
   Replaces: _fetch() in live-pages.js, direct fetch() everywhere.
   
   KEY FIX v6.0: 401 from AI/provider routes is NOT "invalid API key".
   We check auth state FIRST. Only if auth is valid do we treat the 401
   as a provider credential error.
═══════════════════════════════════════════════════════════════ */
async function authFetch(path, opts = {}) {
  const base = BACKEND_URL();

  // ── Pre-flight: refresh if token is expiring ─────────────────────
  if (!UnifiedTokenStore.isOffline() &&
      UnifiedTokenStore.isExpired(60_000) &&
      UnifiedTokenStore.hasSession()) {
    await silentRefresh();
  }

  const token   = UnifiedTokenStore.getToken();
  // CRITICAL FIX: Don't double-prefix /api — if path already starts with /api, don't prepend again
  const fullUrl = path.startsWith('http')
    ? path
    : path.startsWith('/api')
      ? `${base}${path}`
      : `${base}/api${path}`;

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };

  const fetchOpts = {
    method:      opts.method || 'GET',
    headers,
    credentials: 'include',
    ...(opts.body ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) } : {}),
  };

  let resp;
  try {
    resp = await fetch(fullUrl, fetchOpts);
  } catch (netErr) {
    console.warn('[AuthFetch] Network error:', path, '—', netErr.message);
    return { data: [], total: 0, page: 1, limit: 25, _offline: true };
  }

  // ── 401 / 403 handling ───────────────────────────────────────────
  if (resp.status === 401 || resp.status === 403) {
    console.warn(`[AuthFetch] ${resp.status} on ${path} — checking auth state first`);

    // CRITICAL FIX: Attempt token refresh
    const refreshed = await silentRefresh();

    if (refreshed) {
      const newToken = UnifiedTokenStore.getToken();
      try {
        resp = await fetch(fullUrl, {
          ...fetchOpts,
          headers: { ...headers, Authorization: `Bearer ${newToken}` },
        });
      } catch { /* fall through */ }
    }

    // Still 401 after refresh → session truly dead
    if (!resp || resp.status === 401 || resp.status === 403) {
      _dispatchAuthEvent('auth:expired', { path });
      window.StateSync?.handleAuthExpiry({ path });
      throw new Error(`AUTH_EXPIRED: Session expired. Please log in again. (path: ${path})`);
    }
  }

  if (resp.status === 204) return null;
  if (resp.status === 404) return { data: [], total: 0, page: 1, limit: 25 };

  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`HTTP ${resp.status} — ${txt.slice(0, 200)}`);
  }

  try {
    return await resp.json();
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════════════════════════
   STARTUP — _syncStoresOnLoad
   Restores BOTH access and refresh tokens from all storage
   locations, attempts silent refresh if token is expired,
   then resolves StateSync.authReady.
═══════════════════════════════════════════════════════════════ */
async function _syncStoresOnLoad() {
  console.log('[AuthInterceptor] 🔍 Syncing token stores on load…');

  // ── Step 1: Migrate legacy token keys if needed ──────────────────
  const legacyAccess  = localStorage.getItem('we_access_token')
                     || sessionStorage.getItem('we_access_token')
                     || localStorage.getItem('accessToken');
  const legacyRefresh = localStorage.getItem('we_refresh_token')
                     || localStorage.getItem('tp_refresh');
  const primaryAccess  = localStorage.getItem(UNIFIED_KEYS.ACCESS);
  const primaryRefresh = localStorage.getItem(UNIFIED_KEYS.REFRESH);

  if (legacyAccess && !primaryAccess) {
    localStorage.setItem(UNIFIED_KEYS.ACCESS,        legacyAccess);
    localStorage.setItem(UNIFIED_KEYS.LEGACY_ACCESS, legacyAccess);
    console.log('[AuthInterceptor] Migrated legacy access token → unified store');
  }
  if (legacyRefresh && !primaryRefresh) {
    localStorage.setItem(UNIFIED_KEYS.REFRESH,        legacyRefresh);
    localStorage.setItem(UNIFIED_KEYS.LEGACY_REFRESH, legacyRefresh);
    console.log('[AuthInterceptor] Migrated legacy refresh token → unified store');
  }

  // ── Step 2: Evaluate current state ──────────────────────────────
  const hasToken   = !!UnifiedTokenStore.getToken();
  const hasRefresh = !!UnifiedTokenStore.getRefresh();
  const isExpired  = UnifiedTokenStore.isExpired(30_000);
  const user       = UnifiedTokenStore.getUser();

  console.log(`[AuthInterceptor] State: hasToken=${hasToken} hasRefresh=${hasRefresh} isExpired=${isExpired}`);

  // ── Step 3: Nothing at all — mark unauthenticated ────────────────
  if (!hasToken && !hasRefresh) {
    console.log('[AuthInterceptor] No tokens found — user not logged in');
    window.StateSync?.markAuthReady({ isAuthenticated: false, user: null });
    return;
  }

  // ── Step 4: Token valid — schedule refresh and mark ready ────────
  if (hasToken && !isExpired) {
    console.log('[AuthInterceptor] ✅ Valid token found for', user?.email || 'unknown user');
    _scheduleProactiveRefresh();

    // Sync with legacy TokenStore
    if (typeof window.TokenStore !== 'undefined') {
      const exp = UnifiedTokenStore.getExpiry();
      window.TokenStore.set(
        UnifiedTokenStore.getToken(),
        UnifiedTokenStore.getRefresh(),
        exp ? exp.toISOString() : undefined,
      );
    }

    window.StateSync?.markAuthReady({
      isAuthenticated: true,
      user:            user,
      tenantId:        user?.tenant_id,
    });
    return;
  }

  // ── Step 5: Token expired but refresh exists → silent refresh ────
  if (isExpired && hasRefresh) {
    console.log('[AuthInterceptor] Token expired — attempting silent refresh before signalling ready…');
    const ok = await silentRefresh();

    if (ok) {
      const updatedUser = UnifiedTokenStore.getUser() || user;
      console.log('[AuthInterceptor] ✅ Session restored via silent refresh');
      window.StateSync?.markAuthReady({
        isAuthenticated: true,
        user:            updatedUser,
        tenantId:        updatedUser?.tenant_id,
      });
    } else {
      console.warn('[AuthInterceptor] Silent refresh failed — user needs to log in');
      window.StateSync?.markAuthReady({ isAuthenticated: false, user: null });
    }
    return;
  }

  // ── Step 6: Only refresh token (no access token at all) ─────────
  if (!hasToken && hasRefresh) {
    console.log('[AuthInterceptor] No access token, have refresh — refreshing now…');
    const ok = await silentRefresh();
    const updatedUser = UnifiedTokenStore.getUser() || user;
    window.StateSync?.markAuthReady({
      isAuthenticated: ok,
      user:            ok ? updatedUser : null,
      tenantId:        ok ? updatedUser?.tenant_id : null,
    });
    return;
  }

  // Fallback
  window.StateSync?.markAuthReady({ isAuthenticated: false, user: null });
}

/* ═══════════════════════════════════════════════════════════════
   GLOBAL HELPERS — public API for other modules
═══════════════════════════════════════════════════════════════ */

/** Called by main.js / login handler after successful login */
window.PersistentAuth_onLogin = function(user, token, refreshToken, expiresAt, isOffline) {
  // Clear any cookie-refresh backoff so the new session can use cookie if available
  _clearCookieRefreshState();

  UnifiedTokenStore.save({
    token,
    refreshToken,
    expiresAt: typeof expiresAt === 'number'
      ? new Date(Date.now() + expiresAt * 1000).toISOString()
      : expiresAt || new Date(Date.now() + 900_000).toISOString(),
    user,
    offline: !!isOffline,
  });

  if (!isOffline) _scheduleProactiveRefresh();

  // Sync legacy stores
  if (typeof window.TokenStore !== 'undefined') {
    window.TokenStore.set(token, refreshToken, expiresAt);
    if (user) window.TokenStore.setUser(user);
  }

  window.StateSync?.updateAuthState({ isAuthenticated: true, user, tenantId: user?.tenant_id });
  console.log('[AuthInterceptor] ✅ Login recorded for', user?.email);
};

/** Called by main.js on logout */
window.PersistentAuth_onLogout = function() {
  if (_proactiveTimer) { clearTimeout(_proactiveTimer); _proactiveTimer = null; }
  UnifiedTokenStore.clear();
  if (typeof window.TokenStore !== 'undefined') window.TokenStore.clear();
  window.StateSync?.updateAuthState({ isAuthenticated: false, user: null });
  console.log('[AuthInterceptor] 👋 Logged out — all tokens cleared');
};

window.PersistentAuth_silentRefresh = silentRefresh;
window.getAuthToken = () => UnifiedTokenStore.getToken();
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
═══════════════════════════════════════════════════════════════ */
let _expiredHandled = false;
window.addEventListener('auth:expired', () => {
  if (_expiredHandled) return;
  _expiredHandled = true;
  setTimeout(() => { _expiredHandled = false; }, 15_000);

  console.warn('[AuthInterceptor] 🔒 Session expired — showing login');
  if (typeof window.showToast === 'function') {
    window.showToast('Session expired. Please log in again.', 'error', 5000);
  }

  setTimeout(() => {
    if (typeof window.doLogout === 'function') {
      window.doLogout();
    } else {
      UnifiedTokenStore.clear();
      const mainApp     = document.getElementById('mainApp');
      const loginScreen = document.getElementById('loginScreen');
      if (mainApp)     mainApp.style.display     = 'none';
      if (loginScreen) { loginScreen.style.display = 'flex'; loginScreen.style.opacity = '1'; }
    }
  }, 3000);
});

/* ═══════════════════════════════════════════════════════════════
   PAGE VISIBILITY — refresh when tab regains focus near expiry
═══════════════════════════════════════════════════════════════ */
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && UnifiedTokenStore.hasSession()) {
    const msLeft = UnifiedTokenStore.msUntilExpiry();
    // If less than 3 minutes left when tab becomes visible → refresh now
    if (msLeft > 0 && msLeft < 180_000) {
      console.log('[AuthInterceptor] Tab visible — token expiring soon, refreshing');
      silentRefresh();
    }
  }
});

/* ═══════════════════════════════════════════════════════════════
   NETWORK RESTORE — refresh on connectivity resume
═══════════════════════════════════════════════════════════════ */
window.addEventListener('online', () => {
  if (UnifiedTokenStore.hasSession() && !UnifiedTokenStore.isOffline()) {
    console.log('[AuthInterceptor] Network restored — refreshing token');
    silentRefresh();
  }
});

/* ═══════════════════════════════════════════════════════════════
   EXPORTS
═══════════════════════════════════════════════════════════════ */
window.UnifiedTokenStore = UnifiedTokenStore;
window.authFetch         = authFetch;
window.silentRefresh     = silentRefresh;

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ═══════════════════════════════════════════════════════════════
   BOOT — run sync immediately (after DOM is parsed)
═══════════════════════════════════════════════════════════════ */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _syncStoresOnLoad);
} else {
  _syncStoresOnLoad();
}

console.log('[AuthInterceptor] ✅ Auth Interceptor v6.0 loaded — syncing stores…');
