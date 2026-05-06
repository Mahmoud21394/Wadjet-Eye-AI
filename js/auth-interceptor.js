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
    // ROOT-CAUSE FIX v8.2: also clear the _at-suffix variant written by
    // older versions of login-secure-patch.js so stale expiry never lingers.
    ['tp_token', 'tp_refresh', 'tp_user', 'accessToken', 'refreshToken',
     'we_token_expires_at', 'wadjet_token_expires_at'].forEach(k => {
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
// ROOT-CAUSE FIX v8.5: Cookie-backoff sessionStorage state poisoning after login.
//
// PROBLEM (observed in video — "Cookie refresh in backoff — Xs remaining" immediately
// after a fresh successful login):
//   1. Page loads with NO valid tokens → _syncStoresOnLoad → _refreshFromCookie → 400 NO_COOKIE
//      → writes 5-min backoff to sessionStorage AND in-memory vars.
//   2. User logs in successfully → PersistentAuth_onLogin clears in-memory vars AND
//      sessionStorage keys via _clearCookieRefreshState().
//   3. User navigates / page reloads → auth-interceptor.js is re-evaluated.
//   4. The module-init code (this block) reads from sessionStorage BEFORE PersistentAuth_onLogin
//      can run — so it re-poisons in-memory vars from the stale sessionStorage values.
//
// FIX: At module init time, also check whether we have VALID tokens in localStorage.
//   If the user has a real access+refresh token, they have logged in successfully and
//   the cookie-backoff state is stale — clear it immediately.  Only restore the backoff
//   if the user is genuinely unauthenticated (no tokens at all).
(function _initCookieBackoff() {
  const hasRealToken = !!(
    localStorage.getItem('wadjet_access_token') ||
    localStorage.getItem('we_access_token')     ||
    localStorage.getItem('tp_access_token')
  );
  if (hasRealToken) {
    // User has logged in — any stored cookie-backoff is from a PRE-LOGIN page load and
    // is now stale.  Wipe it so post-login page reloads don't re-enter backoff.
    try {
      sessionStorage.removeItem('wadjet_cookie_refresh_failed_at');
      sessionStorage.removeItem('wadjet_cookie_refresh_backoff');
      sessionStorage.removeItem('wadjet_cookie_refresh_blocked_until');
    } catch (_) {}
  }
})();
const _storedFailedAt   = parseInt(sessionStorage.getItem('wadjet_cookie_refresh_failed_at') || '0', 10);
const _storedBackoffMs  = parseInt(sessionStorage.getItem('wadjet_cookie_refresh_backoff') || '0', 10);
// Only honour the stored backoff if the deadline is still in the future (prevents
// stale backoffs from surviving a page reload where the user re-logged in).
const _storedDeadline   = _storedFailedAt + _storedBackoffMs;
let _cookieRefreshFailedAt   = (_storedDeadline > Date.now()) ? _storedFailedAt  : 0;
let _cookieRefreshBackoffMs  = (_storedDeadline > Date.now()) ? _storedBackoffMs : 0;
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
// FIX v7.6: Increased minimum interval from 3s → 15s.
// Root cause: api-client.js, auth-interceptor.js AND auth-validator.js all
// independently detect a 401 and each call silentRefresh() within milliseconds
// of each other.  The 3 s window was too narrow to catch concurrent callers
// that arrive at the same tick, causing 3–5 refresh requests to hit the backend
// in quick succession → backend returns 429 → logout called 3× → logout POST
// itself hits 429.  15 s is wide enough to deduplicate all concurrent module
// refresh attempts within a single 401-storm cycle.
let _lastRefreshAttemptAt = 0;
const REFRESH_MIN_INTERVAL_MS = 15_000; // 15 s minimum between refresh attempts (was 3 s)

const BACKEND_URL = () =>
  (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

async function _doTokenRefresh(attempt = 0) {
  // FIX v11.1: 3 attempts is enough for cold-start recovery (2s, 4s backoff).
  // 5 retries produced a visible 401 storm lasting ~30s in the console.
  const MAX_ATTEMPTS = 3;
  const refreshToken = UnifiedTokenStore.getRefresh();

  // ── Offline mode: extend token locally ──────────────────────────────
  if (UnifiedTokenStore.isOffline()) {
    const newToken  = 'offline_' + Date.now().toString(36);
    const newExpiry = new Date(Date.now() + 15 * 60_000).toISOString();
    UnifiedTokenStore.save({ token: newToken, expiresAt: newExpiry, offline: true });
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
  // ROOT-CAUSE FIX v6.2: Only attempt cookie refresh if we actually had a
  // session at some point (i.e., there IS an access token, it's just expired).
  // If there's NO access token AND no refresh token, the user is not logged
  // in at all — skip the cookie attempt entirely to avoid the NO_COOKIE 400 loop.
  if (!refreshToken) {
    const hasAnyToken = !!(UnifiedTokenStore.getToken() ||
                           localStorage.getItem('wadjet_access_token') ||
                           localStorage.getItem('we_access_token'));
    if (!hasAnyToken) {
      // Completely unauthenticated — no point trying cookie refresh
      return false;
    }
    return _refreshFromCookie();
  }

  try {

    const res = await fetch(`${BACKEND_URL()}/api/auth/refresh`, {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      body:        JSON.stringify({ refresh_token: refreshToken }),
      credentials: 'include',        // also send cookies
      signal:      AbortSignal.timeout(45_000),   // 45s allows for Render cold-start (10-30s)
    });

    // ── Refresh token rejected (truly expired or revoked) ────────────
    if (res.status === 401) {
      const body = await res.json().catch(() => ({}));
      const errCode = body.code || 'refresh_rejected';
      console.warn('[AuthInterceptor] Refresh token rejected:', body.error || errCode);

      // v7.4 FIX: SESSION_VALIDATION_UNAVAILABLE means DB is down, not token invalid.
      // Retry with backoff rather than expiring the session.
      if (errCode === 'SESSION_VALIDATION_UNAVAILABLE') {
        console.warn('[AuthInterceptor] Session validation DB unavailable — will retry');
        if (attempt < MAX_ATTEMPTS - 1) {
          await _sleep(Math.min(Math.pow(2, attempt) * 1_000, 30_000));
          return _doTokenRefresh(attempt + 1);
        }
        return false;
      }

      // FIX v11.1: Distinguish transient DB errors from genuine token rejection.
      // INVALID_REFRESH_TOKEN / REFRESH_TOKEN_EXPIRED with code = hard failure
      // → do NOT retry; the token is gone.  Only retry on SESSION_VALIDATION_UNAVAILABLE
      // (already handled above) or within the post-login grace window.
      const isHardFailure = (
        errCode === 'REFRESH_TOKEN_EXPIRED' ||
        errCode === 'INVALID_REFRESH_TOKEN' ||
        errCode === 'ACCOUNT_SUSPENDED'
      );

      // ROOT-CAUSE FIX v10.0 (kept): Grace window — if user just logged in (<90s ago)
      // and refresh is already returning 401, this can be the RLS / memory-store path
      // that failed; retry with short backoff.
      // FIX v11.1: Read _lastLoginAt from sessionStorage too, in case the variable
      // wasn't set in this module instance (e.g. if login was handled by a different
      // script instance on the same tab).
      const _storedLoginAt = parseInt(sessionStorage.getItem('_wadjet_last_login_at') || '0', 10);
      const _effectiveLoginAt = Math.max(_lastLoginAt, _storedLoginAt);
      const msSinceLoginOnReject = Date.now() - _effectiveLoginAt;
      const isWithinGrace = _effectiveLoginAt > 0 && msSinceLoginOnReject < 90_000;

      if (!isHardFailure && isWithinGrace && attempt < MAX_ATTEMPTS - 1) {
        console.warn(
          `[AuthInterceptor] Refresh 401 within ${Math.round(msSinceLoginOnReject/1000)}s of login (${errCode}) — ` +
          `retrying (attempt ${attempt + 1}/${MAX_ATTEMPTS})`,
        );
        await _sleep(Math.min(Math.pow(2, attempt) * 2_000, 10_000));
        return _doTokenRefresh(attempt + 1);
      }

      // Try cookie as last resort before giving up (only once, only if not a hard failure)
      if (attempt === 0 && !isHardFailure) {
        const cookieOk = await _refreshFromCookie();
        if (cookieOk) return true;
      }
      // FIX v8.1: alias auth:session-expired → auth:expired so the logout handler fires.
      _dispatchAuthEvent('auth:expired',         { reason: body.error || errCode });
      _dispatchAuthEvent('auth:session-expired', { reason: body.error || errCode });
      window.StateSync?.handleAuthExpiry({ reason: errCode });
      return false;
    }

    // ── 503: Auth/DB service temporarily unavailable — retry with backoff ──
    // v7.4 FIX: A 503 on /refresh means the backend is starting up, not that
    // the token is invalid. Retry with backoff respecting the retryIn hint.
    if (res.status === 503) {
      const body = await res.json().catch(() => ({}));
      const serverRetryIn = body.retryIn || body.retryAfter || 5;
      console.warn(`[AuthInterceptor] Refresh endpoint 503 (${body.code || 'unavailable'}) — ` +
        `retrying in ${serverRetryIn}s (attempt ${attempt + 1}/${MAX_ATTEMPTS})`);
      if (attempt < MAX_ATTEMPTS - 1) {
        await _sleep(Math.min(serverRetryIn * 1000, 30_000));
        return _doTokenRefresh(attempt + 1);
      }
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
        await _sleep(Math.min(Math.pow(2, attempt) * 1_000, 30_000));
        return _doTokenRefresh(attempt + 1);
      }
      return false;
    }

    const data      = await res.json();

    // ── requires_reauth: backend couldn't issue a new access token ────────
    // ROOT-CAUSE FIX v14.0: Backend v14+ no longer sends requires_reauth=true.
    // This block is kept as a safety net for old backend deployments still in
    // service during rolling upgrades, but is now ALWAYS treated as non-fatal:
    // keep the existing access token and only update the refresh token.
    // The old behaviour of dispatching auth:expired → forced logout when
    // requires_reauth=true was the primary cause of the 401 storm — users
    // were logged out every ~15 minutes on cold-start, even with a valid session.
    if (data.requires_reauth) {
      const existingToken = UnifiedTokenStore.getToken();
      console.warn('[AuthInterceptor] requires_reauth received — keeping existing token (never force logout on cold-start)');
      if (data.refreshToken || data.refresh_token) {
        UnifiedTokenStore.updateTokens({
          token:        existingToken || undefined,
          refreshToken: data.refreshToken || data.refresh_token,
          sessionId:    data.sessionId    || data.session_id,
          // Preserve existing expiry — don't reset the countdown
          expiresAt:    UnifiedTokenStore.getExpiry()?.toISOString(),
          user:         data.user,
        });
        if (typeof window.TokenStore !== 'undefined') {
          window.TokenStore.set(
            existingToken,
            data.refreshToken || data.refresh_token,
            UnifiedTokenStore.getExpiry()?.toISOString(),
          );
        }
      }
      if (existingToken) {
        _scheduleProactiveRefresh();
        window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });
        return true; // session is still alive — don't trigger auth:expired
      }
      // Truly no token anywhere — session is dead
      console.warn('[AuthInterceptor] requires_reauth and no existing token — session is dead');
      _dispatchAuthEvent('auth:expired',         { reason: 'requires_reauth_no_token' });
      _dispatchAuthEvent('auth:session-expired', { reason: 'requires_reauth_no_token' });
      window.StateSync?.handleAuthExpiry({ reason: 'requires_reauth_no_token' });
      return false;
    }

    // ROOT-CAUSE FIX v14.0: Backend now omits the token field when both
    // admin.createSession and JWT_SECRET signing fail (Render cold-start).
    // Previously we returned false here which caused the 401-storm:
    //   silentRefresh() → false → authFetch throws AUTH_EXPIRED → auth:expired
    //   → logout — immediately after a perfectly valid refresh-token rotation.
    //
    // New behaviour: if token is absent, keep the existing access token and
    // only update the refresh token + user data.  The existing access token
    // (from login) is still valid; it will expire naturally and the next
    // /refresh call will succeed once the cold-start is over.
    const newToken = data.token || data.access_token;
    if (!newToken) {
      const existingToken = UnifiedTokenStore.getToken();
      if (existingToken) {
        console.warn('[AuthInterceptor] Refresh response has no new access token — keeping existing token (cold-start fallback)');
        // Update only the refresh token and user data; preserve existing access token + expiry
        if (data.refreshToken || data.refresh_token) {
          UnifiedTokenStore.updateTokens({
            token:        existingToken,  // keep existing
            refreshToken: data.refreshToken || data.refresh_token,
            // Preserve existing expiry — don't reset the clock
            expiresAt:    UnifiedTokenStore.getExpiry()?.toISOString(),
            user:         data.user,
            sessionId:    data.sessionId || data.session_id,
          });
          // Sync legacy TokenStore
          if (typeof window.TokenStore !== 'undefined') {
            window.TokenStore.set(
              existingToken,
              data.refreshToken || data.refresh_token,
              UnifiedTokenStore.getExpiry()?.toISOString(),
            );
          }
          _scheduleProactiveRefresh();
          window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });
        }
        return true; // session still alive — don't trigger auth:expired
      }
      console.warn('[AuthInterceptor] Refresh response missing token field and no existing token');
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
    // ROOT-CAUSE FIX v6.3: Dispatch BOTH event name variants.
    // api-client.js listens to 'auth:token_refreshed' (underscore).
    // auth-persistent.js and campaign/soc modules listen to 'auth:token-refreshed' (hyphen).
    // Both must fire so all modules react consistently.
    _dispatchAuthEvent('auth:token-refreshed',  { token: newToken });
    _dispatchAuthEvent('auth:token_refreshed',  { token: newToken });
    window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });

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
      await _sleep(Math.min(Math.pow(2, attempt) * 1_000, 30_000));
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
    const res = await fetch(`${BACKEND_URL()}/api/auth/refresh-from-cookie`, {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      signal:      AbortSignal.timeout(30_000),   // 30s allows for backend cold-start
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

    // FIX v15.0: Backend may omit the token field on cold-start
    // (admin.createSession + JWT_SECRET both unavailable).  Keep the existing
    // access token and only update the refresh token, same as _doTokenRefresh().
    if (!newToken) {
      const existingToken = UnifiedTokenStore.getToken();
      if (existingToken && (data.refreshToken || data.refresh_token)) {
        _clearCookieRefreshState();
        UnifiedTokenStore.updateTokens({
          token:        existingToken, // keep existing
          refreshToken: data.refreshToken || data.refresh_token,
          expiresAt:    UnifiedTokenStore.getExpiry()?.toISOString(),
          user:         data.user,
          sessionId:    data.sessionId || data.session_id,
        });
        if (typeof window.TokenStore !== 'undefined') {
          window.TokenStore.set(existingToken, data.refreshToken || data.refresh_token, null);
        }
        _scheduleProactiveRefresh();
        window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });
        console.warn('[AuthInterceptor] Cookie refresh: no new token — keeping existing (cold-start fallback)');
        return true;
      }
      return false;
    }

    // ── Success: reset backoff ──────────────────────────────────────────
    _clearCookieRefreshState();

    UnifiedTokenStore.save({
      token:        newToken,
      refreshToken: data.refreshToken || data.refresh_token,
      expiresAt:    data.expiresAt    || data.expires_at,
      expiresIn:    data.expiresIn    || data.expires_in,
      user:         data.user,
    });

    // Sync legacy TokenStore if loaded
    if (typeof window.TokenStore !== 'undefined') {
      window.TokenStore.set(
        newToken,
        data.refreshToken || data.refresh_token,
        data.expiresAt || data.expiresIn,
      );
    }

    // Notify WS
    if (window.WS?.updateAuth) window.WS.updateAuth();

    _scheduleProactiveRefresh();
    // ROOT-CAUSE FIX v6.3: Cookie-based refresh also dispatches token events
    // so that StateSync + WS + ai-orchestrator all receive the updated token.
    _dispatchAuthEvent('auth:token-refreshed', { token: newToken });
    _dispatchAuthEvent('auth:token_refreshed', { token: newToken });
    window.StateSync?.updateAuthState({ isAuthenticated: true, user: data.user });
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

/** Deduplicated, locked silent refresh
 *
 * FIX v7.6: Expose a cross-module global lock via window.__wadjetRefreshLock.
 * Both auth-interceptor.js AND auth-validator.js call silentRefresh();
 * without a shared lock they each acquire their own local _refreshLock
 * simultaneously, resulting in two concurrent /api/auth/refresh POSTs.
 * window.__wadjetRefreshLock is the single authoritative flag shared by
 * ALL modules — any module that checks it before attempting a refresh will
 * serialise correctly.
 */
async function silentRefresh() {
  // Check both local lock AND cross-module global lock
  if ((_refreshLock && _refreshPromise) || window.__wadjetRefreshLock) {
    // Return the in-flight promise if available, else a resolved false
    return _refreshPromise || Promise.resolve(false);
  }
  _refreshLock              = true;
  window.__wadjetRefreshLock = true;   // block all other modules
  _refreshPromise = _doTokenRefresh();
  try {
    return await _refreshPromise;
  } finally {
    _refreshLock               = false;
    window.__wadjetRefreshLock = false;
    _refreshPromise            = null;
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
/* ========================= AUTH FETCH (FIXED) ========================= */

async function authFetch(path, opts = {}) {
  const base = BACKEND_URL();

  // ROOT-CAUSE FIX v17.0: Previous URL builder had a gap:
  //   paths like '/cti/timeline' (no leading '/api') → built as
  //   `${base}/api/cti/timeline` which is correct, BUT the
  //   isAuthRoute check used fullUrl.includes(p) where p is
  //   '/api/auth/login' etc. — that is fine.
  //
  //   The REAL bug: when path already starts with '/api/' but does NOT
  //   start with 'http', the URL is built correctly.  However, if the
  //   caller passes a bare path like 'cti/timeline' (no leading slash),
  //   it became `${base}/apicti/timeline` — invalid URL → 404 / no auth.
  //
  //   Fix: normalise all paths to have a leading slash before building.
  const _normPath = path.startsWith('http') ? path
    : ('/' + path.replace(/^\/+/, ''));   // ensure exactly one leading slash

  const fullUrl = _normPath.startsWith('http')
    ? _normPath
    : _normPath.startsWith('/api')
      ? `${base}${_normPath}`
      : `${base}/api${_normPath}`;

  // ───────── AUTH BYPASS (CRITICAL FIX) ─────────
  const AUTH_BYPASS = [
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/auth/logout'
  ];

  const isAuthRoute = AUTH_BYPASS.some(p => fullUrl.includes(p));

  // ───────── PRE-FLIGHT REFRESH (SKIP FOR AUTH ROUTES) ─────────
  // ROOT-CAUSE FIX v17.0: If the token is missing entirely (not just
  // expired) AND a refresh token exists, trigger a silent refresh so the
  // first post-login API call after a cold page-load always has a valid
  // token.  The previous check only fired when isExpired() was true, but
  // isExpired() returns false when the expiry timestamp is absent — common
  // on the very first request after a session restore where only the
  // refresh token was in storage and the access token was not yet fetched.
  if (!isAuthRoute && !UnifiedTokenStore.isOffline() && UnifiedTokenStore.hasSession()) {
    const needsRefresh = UnifiedTokenStore.isExpired(60_000) || !UnifiedTokenStore.getToken();
    if (needsRefresh) {
      await silentRefresh();
    }
  }

  const token = UnifiedTokenStore.getToken();

  // ROOT-CAUSE FIX v17.0: If we STILL have no token after silentRefresh()
  // and this is NOT an auth route, log a warning so the MISSING_TOKEN error
  // is traceable to the exact call site rather than producing a cryptic 401.
  if (!token && !isAuthRoute && UnifiedTokenStore.hasSession()) {
    console.warn(`[AuthFetch] ⚠️  No access token available for ${path} — session exists but token missing. Proceeding (will get 401 if backend requires auth).`);
  }

  const headers = {
    'Content-Type': 'application/json',
    ...(opts.headers || {}),
  };

  // ───────── ONLY ATTACH TOKEN FOR NON-AUTH ROUTES ─────────
  if (token && !isAuthRoute) {
    headers.Authorization = `Bearer ${token}`;
  }

  const fetchOpts = {
    method: opts.method || 'GET',
    headers,
    credentials: 'include',
    ...(opts.body
      ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) }
      : {}),
  };

  let resp;

  try {
    resp = await fetch(fullUrl, fetchOpts);
  } catch (netErr) {
    console.warn('[AuthFetch] Network error:', path, netErr.message);
    return { data: [], total: 0, page: 1, limit: 25, _offline: true };
  }

  // ── 401 / 403 handling ─────────────────────────────────────────────
  // Skip for auth routes (login/refresh/logout handle their own errors).
  if ((resp.status === 401 || resp.status === 403) && !isAuthRoute) {
    // ROOT-CAUSE FIX v6.3: If the user has NO session at all, the request was
    // already unauthenticated — don't trigger cookie-refresh NO_COOKIE loop.
    if (!UnifiedTokenStore.hasSession()) {
      throw new Error(`Not authenticated (HTTP ${resp.status}) — no session present. Path: ${path}`);
    }

    // ROOT-CAUSE FIX v17.0: Check if the 401 is MISSING_TOKEN (no token was
    // sent at all) vs INVALID_TOKEN (wrong token sent).  If we had no token
    // to begin with, silentRefresh() is the right first step.  But if we DID
    // send a token and it was rejected, only retry once after refresh.
    // Capture the token that was sent so we can detect a stale-token retry.
    const tokenSentOnFirst = token; // captured before refresh

    // Has a session → attempt one silent refresh, then retry
    const refreshed = await silentRefresh();

    if (refreshed) {
      const newToken = UnifiedTokenStore.getToken();
      // Only retry if we actually got a NEW token (or had none before)
      if (newToken && newToken !== tokenSentOnFirst || !tokenSentOnFirst) {
        resp = await fetch(fullUrl, {
          ...fetchOpts,
          headers: { ...headers, Authorization: `Bearer ${newToken}` },
        });
      }
    }

    // Still 401 after refresh → session truly dead (revoked / expired)
    if (!resp || resp.status === 401 || resp.status === 403) {
      // FIX v17.0: Read the response body for better error logging
      const errBody = await resp?.json().catch(() => ({}));
      const errCode = errBody?.code || 'unknown';
      console.warn(`[AuthFetch] Session dead after refresh attempt on ${path} — code: ${errCode}`);
      _dispatchAuthEvent('auth:expired', { path, code: errCode });
      window.StateSync?.handleAuthExpiry({ path });
      throw new Error(`AUTH_EXPIRED: Session expired. Please log in again. (${path})`);
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
  }
  if (legacyRefresh && !primaryRefresh) {
    localStorage.setItem(UNIFIED_KEYS.REFRESH,        legacyRefresh);
    localStorage.setItem(UNIFIED_KEYS.LEGACY_REFRESH, legacyRefresh);
  }

  // ── Step 2: Evaluate current state ──────────────────────────────
  const hasToken   = !!UnifiedTokenStore.getToken();
  const hasRefresh = !!UnifiedTokenStore.getRefresh();
  const isExpired  = UnifiedTokenStore.isExpired(30_000);
  const user       = UnifiedTokenStore.getUser();

  // ── Step 3: Nothing at all — mark unauthenticated ────────────────
   if (!hasToken && !hasRefresh) {
      UnifiedTokenStore.clear();   // ← FIX: clears stale UI/auth state
      window.StateSync?.markAuthReady({ isAuthenticated: false, user: null });
      return;
   }

  // ── Step 4: Token valid — schedule refresh and mark ready ────────
  if (hasToken && !isExpired) {
    // ROOT-CAUSE FIX v8.5: Clear any cookie-backoff state left over from a
    // previous page-load silent-refresh attempt that got 400 NO_COOKIE.
    // Now that we have a real valid token, the backoff is stale and must be
    // wiped so that a future genuine-expiry can use cookie-refresh if needed.
    _clearCookieRefreshState();
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
    // ROOT-CAUSE FIX v8.5: Clear cookie-backoff before attempting — we have a
    // real refresh token so this is a genuine session restore, not an anonymous
    // cookie-probe. Any stale backoff from a previous unauthenticated page load
    // must not block the /api/auth/refresh call.
    _clearCookieRefreshState();
    // FIX v16.0: Reset the rate-limit guard so a page-load session restore is
    // never blocked by a stale timestamp from the previous page cycle.
    _lastRefreshAttemptAt = 0;
    const ok = await silentRefresh();

    if (ok) {
      const updatedUser = UnifiedTokenStore.getUser() || user;
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
    // FIX v16.0: _syncStoresOnLoad runs at DOMContentLoaded which is typically
    // within 15s of the previous page load.  The REFRESH_MIN_INTERVAL_MS guard
    // (15s) can block this refresh if the last attempt timestamp was set during
    // the previous page's silent-refresh cycle.  Reset the guard so a genuine
    // session-restore on page-load is never silently skipped.
    _lastRefreshAttemptAt = 0;
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

// ── RC-FIX v7.5: _expiredHandled declared HERE (top of public-API section) ──
// Must be ABOVE both PersistentAuth_onLogin and PersistentAuth_onLogout because
// `var` is function-scoped and module-scoped code runs top-to-bottom.  Even
// though `var` hoists the declaration, placing it here makes the intent
// explicit and prevents linters from flagging "used before defined".
var _expiredHandled = false;  // eslint-disable-line no-var
// ROOT-CAUSE FIX v10.0: Track the last successful login timestamp so that
// requires_reauth and rapid auth:expired dispatches within the first 30 s
// after a fresh login are suppressed — they indicate a backend cold-start
// issue (admin.createSession unavailable) rather than a truly expired session.
var _lastLoginAt = 0;  // eslint-disable-line no-var

/** Called by main.js / login handler after successful login */
window.PersistentAuth_onLogin = function(user, token, refreshToken, expiresAt, isOffline) {
  // P5 FIX v8.0: Reset ALL refresh-rate guards so a fresh login session is
  // never locked out by a stale backoff timer that accumulated during the
  // page-load silent-refresh attempt (which failed because the old refresh
  // token was already expired or missing).
  // Without this reset the 15 s REFRESH_MIN_INTERVAL_MS guard fires
  // immediately after login ("Refresh requested too soon — skipping"),
  // meaning the very first 401 on a post-login API call cannot be healed.
  _lastRefreshAttemptAt = 0;   // reset main-refresh rate-limit guard
  _clearCookieRefreshState();  // reset cookie-refresh backoff + sessionStorage keys

  // ROOT-CAUSE FIX v8.2: also clear any stale in-flight refresh lock so the
  // first post-login silentRefresh() is never blocked by a lock that was set
  // during the page-load _syncStoresOnLoad() attempt (which may have timed out
  // or failed before releasing the lock).
  _refreshLock               = false;
  window.__wadjetRefreshLock = false;
  _refreshPromise            = null;
  _expiredHandled            = false; // allow auth:expired to fire again in new session
  _lastLoginAt               = Date.now(); // ROOT-CAUSE FIX v10.0: stamp login time
  // FIX v11.1: also persist to sessionStorage so _doTokenRefresh can read it
  // even if this module instance was not the one that called PersistentAuth_onLogin
  // (e.g. login was finalised by login-secure-patch.js on a different code path).
  try { sessionStorage.setItem('_wadjet_last_login_at', String(_lastLoginAt)); } catch (_) {}

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

  // ROOT-CAUSE FIX v6.2: If StateSync.authReady is not yet resolved (e.g. login
  // happened before _syncStoresOnLoad completed), resolve it now so all modules
  // that await StateSync.authReady can proceed immediately.
  if (window.StateSync) {
    if (!window.StateSync.isAuthDone()) {
      window.StateSync.markAuthReady({ isAuthenticated: true, user, tenantId: user?.tenant_id });
    } else {
      window.StateSync.updateAuthState({ isAuthenticated: true, user, tenantId: user?.tenant_id });
    }
  }
};

/** Called by main.js on logout */
window.PersistentAuth_onLogout = function() {
  if (_proactiveTimer) { clearTimeout(_proactiveTimer); _proactiveTimer = null; }
  UnifiedTokenStore.clear();
  if (typeof window.TokenStore !== 'undefined') window.TokenStore.clear();
  window.StateSync?.updateAuthState({ isAuthenticated: false, user: null });

  // Reset expired-event dedup flag so a fresh login after logout
  // isn't blocked by the 15-second cooldown.
  _expiredHandled = false;

  // Remove any stale session-expired banners left from the previous session
  try { document.getElementById('session-expired-banner')?.remove(); } catch (_) {}

  // Persist cookie-refresh state to prevent immediate re-attempt after logout
  _clearCookieRefreshState();
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
   _expiredHandled is declared at the top of the GLOBAL HELPERS
   section (above PersistentAuth_onLogin) so it is always available.
═══════════════════════════════════════════════════════════════ */
window.addEventListener('auth:expired', () => {
  if (_expiredHandled) return;
  _expiredHandled = true;
  // FIX v7.6: Extended dedup window 15s → 30s.
  // The old 15 s window expired before doLogout() finished its own 401-retry
  // cycle, allowing a second auth:expired handler to fire and call doLogout()
  // again while the first was still executing.  30 s covers the worst-case
  // Render cold-start + retry latency so only ONE logout ever runs per session.
  setTimeout(() => { _expiredHandled = false; }, 30_000);

  // FIX v7.6: Clear tokens IMMEDIATELY before any async work so that any
  // in-flight authFetch() calls that complete after this point will find no
  // token and skip their own 401 → silentRefresh() → auth:expired re-entry.
  UnifiedTokenStore.clear();

  console.warn('[AuthInterceptor] 🔒 Session expired — showing login');
  if (typeof window.showToast === 'function') {
    window.showToast('Session expired. Please log in again.', 'error', 5000);
  }

  // FIX v7.6: Use a longer delay (1 s instead of 3 s) so the toast is visible
  // before the screen transition, but the tokens are already cleared above so
  // no further 401 requests will be attempted in the meantime.
  setTimeout(() => {
    if (typeof window.doLogout === 'function') {
      // Pass flag so doLogout() knows tokens are already cleared and can skip
      // the backend logout POST (which would just get a 401/429 itself).
      window.doLogout({ skipBackendCall: true });
    } else {
      const mainApp     = document.getElementById('mainApp');
      const loginScreen = document.getElementById('loginScreen');
      if (mainApp)     mainApp.style.display     = 'none';
      if (loginScreen) { loginScreen.style.display = 'flex'; loginScreen.style.opacity = '1'; }
    }
  }, 1_000);
});

/* ═══════════════════════════════════════════════════════════════
   PAGE VISIBILITY — refresh when tab regains focus near expiry
═══════════════════════════════════════════════════════════════ */
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && UnifiedTokenStore.hasSession()) {
    const msLeft = UnifiedTokenStore.msUntilExpiry();
    // If less than 3 minutes left when tab becomes visible → refresh now.
    // FIX v16.0: Clear the rate-limit guard before attempting.  When the tab
    // was hidden for > 15s (very common) the guard timer has reset naturally,
    // but if the tab was hidden for exactly 15s and the user switches back the
    // guard can still block.  Tab-focus refresh is user-triggered and must
    // never be blocked by the rate-limit guard.
    if (msLeft >= 0 && msLeft < 180_000) {
      _lastRefreshAttemptAt = 0; // allow refresh immediately
      silentRefresh();
    }
  }
});

/* ═══════════════════════════════════════════════════════════════
   NETWORK RESTORE — refresh on connectivity resume
═══════════════════════════════════════════════════════════════ */
window.addEventListener('online', () => {
  if (UnifiedTokenStore.hasSession() && !UnifiedTokenStore.isOffline()) {
    // FIX v16.0: Network restore is a system event — reset the rate-limit guard
    // so the refresh always fires immediately after going back online, even if
    // the previous attempt was less than 15 s ago.
    _lastRefreshAttemptAt = 0;
    silentRefresh();
  }
});

/* ═══════════════════════════════════════════════════════════════
   EXPORTS
═══════════════════════════════════════════════════════════════ */
window.UnifiedTokenStore = UnifiedTokenStore;
window.authFetch         = authFetch;
window.silentRefresh     = silentRefresh;
// ROOT-CAUSE FIX v8.3: Signal to auth-validator.js that the superior
// authFetch (with pre-flight refresh + full 401 handling) is installed.
// auth-validator.js checks this flag before overwriting window.authFetch.
window.__wadjetAuthInterceptorLoaded = true;

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ═══════════════════════════════════════════════════════════════
   BOOT — run sync immediately (after DOM is parsed)
═══════════════════════════════════════════════════════════════ */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _syncStoresOnLoad);
} else {
  _syncStoresOnLoad();
}
