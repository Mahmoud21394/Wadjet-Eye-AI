/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Global Auth Validator & API Health Monitor v5.4
 *  js/auth-validator.js
 *
 *  Round 21 fixes:
 *  ────────────────
 *  FIX R21-A: Banner suppression window 5 s → 90 s (matches grace window)
 *  FIX R21-B: checkFeedAuthStatus delegates to window.authFetch when available
 *             (uses auth-interceptor's INVALID_TOKEN grace window path)
 *  FIX R21-C: auth:login listener delay 3 s → 30 s (cold-start Render warmup)
 *  FIX R21-D: auth:restored listener delay 5 s → 35 s
 *  FIX R21-E: Internal authFetch 401 handler — INVALID_TOKEN grace window check
 *             before unconditionally calling _show401Banner()
 *
 *  PURPOSE:
 *  ─────────
 *  1. On app startup, validates that a JWT token exists and is not expired
 *  2. Shows clear error messages when API calls return 401
 *  3. Intercepts ALL failed fetch() calls and shows toast notifications
 *  4. Provides window.authFetch() as a centralized, auth-aware fetch wrapper
 *  5. Auto-retries with refreshed token on 401 responses
 *  6. Shows "Session expired — please log in" banner for hard 401s
 *
 *  USAGE (from any module):
 *  ─────────────────────────
 *    const data = await authFetch('/api/iocs?limit=50');
 *    const data = await authFetch('/api/ingest/run', { method: 'POST', body: JSON.stringify({}) });
 *
 *  ROOT CAUSE FIX for 401 loops:
 *  ───────────────────────────────
 *  The token is stored in 5 different keys across the history of this app.
 *  This module reads ALL of them in priority order:
 *    1. wadjet_access_token  (current)
 *    2. we_access_token      (legacy v4)
 *    3. tp_access_token      (legacy v3)
 *    4. sessionStorage keys  (tab-only session)
 *    5. window.getAuthToken()  (auth-interceptor.js live getter)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

const API_BASE = () =>
  (global.THREATPILOT_API_URL || global.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

/* ── Token reader — reads from all known storage locations ──────*/
function getToken() {
  // Prefer live getter from auth-interceptor.js (most up-to-date)
  if (typeof global.getAuthToken === 'function') {
    const t = global.getAuthToken();
    if (t) return t;
  }
  // Fallback: read all known keys in priority order
  const keys = [
    'wadjet_access_token', 'we_access_token', 'tp_access_token',
  ];
  for (const k of keys) {
    const t = localStorage.getItem(k) || sessionStorage.getItem(k);
    if (t) return t;
  }
  return null;
}

/* ── 401 Toast state (prevent toast spam) ───────────────────────*/
let _last401Toast = 0;
let _refreshInProgress = false;

// FIX v7.6: _show401Banner dedup — extend window from 8s → 30s so the banner
// is not re-created if a second module fires auth:expired within the same cycle.
let _bannerShownAt = 0;

function _show401Banner() {
  const now = Date.now();
  // FIX v7.6: Use 30s dedup (was 8s) to cover the full 401-storm cycle.
  if (now - _last401Toast < 30_000) return;
  _last401Toast = now;

  // FIX R21-A: Extend banner suppression window 5 s → 90 s.
  // Root cause of Round 21 bug: the suppression only covered 5 s after login,
  // but Render cold-start session propagation takes up to 90 s.  During that
  // window INVALID_TOKEN 401s are transient — the session IS valid, the DB just
  // hasn't committed the row yet.  Showing the "Session expired" banner during
  // this window was actively misleading and caused users to log out + back in,
  // restarting the whole cold-start cycle.
  //
  // The 90 s window is consistent with:
  //   • auth-interceptor.js Fix v20.0 INVALID_TOKEN grace window (90 s)
  //   • login-secure-patch.js _wadjet_last_login_at timestamp
  //   • checkFeedAuthStatus delay (30 s, see FIX R21-C below)
  const _graceMs = 90_000;
  const _loginTimestamp = window._wadjetLastLoginAt
    || parseInt(sessionStorage.getItem('_wadjet_last_login_at') || '0', 10)
    || 0;
  if (_loginTimestamp > 0 && (now - _loginTimestamp) < _graceMs) {
    console.warn(
      `[AuthValidator] Suppressing session-expired banner — ${Math.round((now - _loginTimestamp) / 1000)}s` +
      ' after login (within 90 s cold-start grace window)'
    );
    return;
  }

  if (typeof global.showToast === 'function') {
    global.showToast('🔒 Session expired. Please log in again.', 'error', 5000);
  }

  // Also show a prominent banner if on the main app
  const banner = document.getElementById('session-expired-banner');
  if (banner) return; // Already shown

  const mainApp = document.getElementById('mainApp');
  if (!mainApp || mainApp.style.display === 'none') return; // Not logged in yet

  const div = document.createElement('div');
  div.id = 'session-expired-banner';
  div.style.cssText = [
    'position:fixed;top:0;left:0;right:0;z-index:9999;',
    'background:#dc2626;color:#fff;padding:12px 20px;',
    'display:flex;align-items:center;justify-content:space-between;',
    'font-size:14px;font-weight:500;box-shadow:0 2px 10px rgba(0,0,0,.3)',
  ].join('');
  div.innerHTML = [
    '<span>\u{1F512} Your session has expired. Please log in again to continue.</span>',
    '<div style="display:flex;gap:10px">',
    // FIX v7.6: Pass skipBackendCall so doLogout() does NOT POST /api/auth/logout
    // when tokens are already cleared — that POST was the source of the 429.
    '  <button onclick="window.doLogout?.({skipBackendCall:true})"',
    '    style="background:#fff;color:#dc2626;border:none;padding:5px 14px;',
    '    border-radius:4px;cursor:pointer;font-size:13px;font-weight:600">Log In</button>',
    '  <button onclick="this.closest(\'#session-expired-banner\').remove()"',
    '    style="background:transparent;border:1px solid #ffffff80;color:#fff;',
    '    padding:5px 10px;border-radius:4px;cursor:pointer;font-size:13px">Dismiss</button>',
    '</div>',
  ].join('');
  document.body.prepend(div);

  // Auto-remove after 30s
  setTimeout(() => { try { div.remove(); } catch (_) {} }, 30_000);
}

/* ── Centralized auth-aware fetch wrapper ───────────────────────*/
// ROOT-CAUSE FIX v8.3: auth-validator.js loaded AFTER auth-interceptor.js (see
// index.html load order). auth-interceptor.js exports window.authFetch which has
// pre-flight token refresh, a 401→silentRefresh→retry cycle, and full error handling.
// auth-validator.js was overwriting it with a simpler version that:
//   1. Had a URL double-/api bug (/api/iocs → https://host/api/api/iocs)
//   2. Lacked pre-flight refresh (sent expired tokens, always got 401)
//   3. Missing credentials:'include' (httpOnly cookie not sent to backend)
// Fix: keep the internal authFetch implementation for fallback use, but only
// expose it globally if auth-interceptor's version is NOT already present.
async function authFetch(pathOrUrl, opts = {}) {
  // ROOT-CAUSE FIX v8.3: Correct URL construction.
  // Callers use paths like '/api/iocs', '/ingest/feeds', '/health', 'https://…'.
  // If path already starts with 'http' → use as-is.
  // If path starts with '/api' → prepend only the base host (not /api again).
  // If path starts with '/' (but not '/api') → prepend base + '/api'.
  // This eliminates the https://host/api/api/iocs double-prefix bug.
  const base = API_BASE();
  const url = pathOrUrl.startsWith('http')
    ? pathOrUrl
    : pathOrUrl.startsWith('/api')
      ? `${base}${pathOrUrl}`
      : `${base}/api${pathOrUrl}`;

  const token = getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };

  let response;
  try {
    // ROOT-CAUSE FIX v8.3: Add credentials:'include' so httpOnly refresh cookie
    // is sent on requests to the same origin backend.
    response = await fetch(url, { credentials: 'include', ...opts, headers });
  } catch (networkErr) {
    console.warn('[AuthFetch] Network error:', networkErr.message);
    throw new Error(`Network error: ${networkErr.message}. Check your connection.`);
  }

  // ── 401 Handler ──────────────────────────────────────────────
  if (response.status === 401) {
    // FIX R21-E: Read the 401 response body to get the error code BEFORE
    // deciding whether to call _show401Banner().  The previous implementation
    // called _show401Banner() unconditionally on the fallback path (line after
    // the refresh block), which meant INVALID_TOKEN during cold-start always
    // showed the banner even when the session was genuinely still valid.
    let _errBody401 = {};
    try { _errBody401 = await response.clone().json(); } catch (_) {}
    const _errCode401 = _errBody401?.code || 'unknown';

    // FIX R21-E: INVALID_TOKEN within 90 s post-login grace window.
    // Mirrors the same logic in auth-interceptor.js Fix v20.0.
    // If we're inside the grace window: return a soft placeholder so the
    // caller's next poll cycle retries naturally — do NOT show the banner.
    const _now401   = Date.now();
    const _loginTs401 = window._wadjetLastLoginAt
      || parseInt(sessionStorage.getItem('_wadjet_last_login_at') || '0', 10)
      || 0;
    const _msSinceLogin401 = _now401 - _loginTs401;
    const _inGrace401 = _loginTs401 > 0 && _msSinceLogin401 < 90_000;

    if (_errCode401 === 'INVALID_TOKEN' && _inGrace401) {
      console.warn(
        `[AuthFetch/Validator] INVALID_TOKEN on ${url} — ` +
        `${Math.round(_msSinceLogin401 / 1000)}s after login (within 90 s grace).` +
        ' Backend session write still propagating — returning cold-start placeholder.'
      );
      return { data: [], total: 0, page: 1, limit: 25, _offline: true, _coldStart: true };
    }

    // FIX v7.6: Check both local _refreshInProgress AND the cross-module global
    // lock window.__wadjetRefreshLock before attempting a refresh.  Without this
    // check, auth-validator and auth-interceptor each hold their own local flag
    // and both think they are the first to attempt a refresh, causing two
    // concurrent /api/auth/refresh POSTs and a 429 cascade.
    const alreadyRefreshing = _refreshInProgress || !!window.__wadjetRefreshLock;

    // ROOT-CAUSE FIX v8.4: PersistentAuth_silentRefresh is the legacy name;
    // auth-interceptor.js v6+ exports window.silentRefresh directly.
    // Try both so the 401-retry path works regardless of which version is loaded.
    const _silentRefreshFn = global.PersistentAuth_silentRefresh || global.silentRefresh || null;

    if (!alreadyRefreshing && typeof _silentRefreshFn === 'function') {
      _refreshInProgress = true;
      try {
        const refreshed = await _silentRefreshFn();
        if (refreshed) {
          const newToken = getToken();
          const retryHeaders = {
            ...headers,
            ...(newToken ? { Authorization: `Bearer ${newToken}` } : {}),
          };
          const retryResp = await fetch(url, { ...opts, headers: retryHeaders });
          if (retryResp.ok) {
            const ct = retryResp.headers.get('content-type') || '';
            return ct.includes('application/json') ? retryResp.json() : retryResp.text();
          }
          if (retryResp.status === 401) {
            _show401Banner();
            throw new Error('Session expired. Please log in again.');
          }
        }
      } catch (e) {
        if (!e.message.includes('expired')) {
          console.warn('[AuthFetch] Silent refresh failed:', e.message);
        }
      } finally {
        _refreshInProgress = false;
      }
    }

    _show401Banner();
    throw new Error('Authentication required. Please log in. (HTTP 401)');
  }

  // ── 403 Handler ──────────────────────────────────────────────
  if (response.status === 403) {
    throw new Error('Access denied. You do not have permission for this action. (HTTP 403)');
  }

  // ── 404 Handler ──────────────────────────────────────────────
  if (response.status === 404) {
    return { data: [], total: 0, _notfound: true };
  }

  // ── Rate limit ────────────────────────────────────────────────
  if (response.status === 429) {
    const retryAfter = response.headers.get('retry-after') || '60';
    throw new Error(`Rate limited. Retry in ${retryAfter}s.`);
  }

  // ── 5xx errors ───────────────────────────────────────────────
  if (response.status >= 500) {
    const body = await response.text().catch(() => '');
    throw new Error(`Server error (HTTP ${response.status})${body ? ': ' + body.slice(0, 100) : ''}`);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Request failed (HTTP ${response.status})${body ? ': ' + body.slice(0, 100) : ''}`);
  }

  // Parse response
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

/* ── API Health Check — runs once on app init ───────────────────*/
async function checkAPIHealth() {
  // ROOT-CAUSE FIX v9.0: Replace the invalid { timeout: 8000 } fetch option
  // (fetch API does not accept a 'timeout' key — it was silently ignored,
  // meaning health checks could hang indefinitely on a cold Render start).
  // Fix: use AbortController with an 8 s hard deadline.
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), 8000);
  try {
    const url = `${API_BASE()}/health`;
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    console.info('[AuthValidator] ✅ Backend health OK:', data.status || 'healthy');
    global._WADJET_BACKEND_HEALTHY = true;
    return true;
  } catch (err) {
    clearTimeout(timeoutId);
    const reason = err.name === 'AbortError' ? 'timed out after 8s' : err.message;
    console.warn('[AuthValidator] ⚠️ Backend health check failed:', reason);
    console.warn('[AuthValidator]    This may be normal on cold start (Render sleeps after 15min).');
    global._WADJET_BACKEND_HEALTHY = false;
    return false;
  }
}

/* ── Feed Auth Status — shows which feeds have keys configured ──*/
async function checkFeedAuthStatus() {
  const token = getToken();
  if (!token) return;

  // FIX R21-B: Delegate to window.authFetch (auth-interceptor) when available.
  // Root cause of Round 21 three-path 401 problem:
  //   The internal authFetch (defined above) bypassed ALL of auth-interceptor's
  //   grace window fixes — Round 20 patched auth-interceptor.js but this call
  //   site was a completely separate code path that still hit the backend with
  //   the raw token and got INVALID_TOKEN during cold-start.  By delegating to
  //   window.authFetch (which IS auth-interceptor's version when loaded), we
  //   automatically inherit the INVALID_TOKEN 90 s grace window, the no-token
  //   early-abort, and the silentRefresh retry chain — no duplicate logic.
  //   Fall back to internal authFetch only when auth-interceptor is absent.
  const _fetchFn = (global.__wadjetAuthInterceptorLoaded && typeof global.authFetch === 'function')
    ? global.authFetch
    : authFetch;

  try {
    const resp = await _fetchFn('/ingest/feeds');
    // If the interceptor returned a cold-start placeholder, skip silently
    if (resp && (resp._coldStart || resp._offline || resp._dbUnavailable)) {
      console.info('[FeedAuth] Skipping feed auth check — backend cold-start placeholder received');
      return;
    }
    const { feeds = {} } = resp;
    const issues = Object.entries(feeds)
      .filter(([, f]) => f.required && !f.key_configured)
      .map(([name]) => name);

    if (issues.length > 0) {
      console.warn(`[FeedAuth] ⚠️ Missing required API keys for: ${issues.join(', ')}`);
      if (typeof global.showToast === 'function') {
        global.showToast(
          `⚠️ ${issues.length} feed(s) missing API keys: ${issues.join(', ')}. Set them in backend/.env`,
          'warning',
          8000
        );
      }
    } else {
      console.info('[FeedAuth] ✅ All required feed API keys are configured');
    }
    return resp;
  } catch (err) {
    console.warn('[FeedAuth] Could not check feed auth status:', err.message);
  }
}

/* ── Expose globally ─────────────────────────────────────────────*/
// ROOT-CAUSE FIX v8.3: Only install validator's authFetch if auth-interceptor's
// superior version (with pre-flight refresh + full 401 handling) is NOT present.
// auth-interceptor.js is loaded BEFORE auth-validator.js per index.html order,
// so window.authFetch is already set by the time we get here — preserve it.
if (!global.authFetch || !global.__wadjetAuthInterceptorLoaded) {
  global.authFetch = authFetch;
}
global._authFetchValidator = authFetch; // keep validator version accessible internally
global.getToken    = getToken;
global.checkAPIHealth = checkAPIHealth;
global.checkFeedAuthStatus = checkFeedAuthStatus;

// Run health check on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  // Delay slightly to not slow initial paint
  setTimeout(checkAPIHealth, 2000);
});

// Listen for auth:login event to check feed status
// FIX R21-C: Delay 3 s → 30 s on auth:login.
// Root cause: the original 3 s delay fired checkFeedAuthStatus well before the
// Render backend finished its cold-start (10–30 s).  The session write to
// Supabase is also async — the JWT the frontend has is valid but the backend's
// profile cache hasn't caught up yet, so every /api/ingest/feeds call returned
// 401 INVALID_TOKEN.  Even though the Round 20 grace window in auth-interceptor
// covered this, auth-validator was calling its OWN authFetch (not interceptor's),
// so it bypassed the grace window entirely.
//
// With FIX R21-B in place (delegate to window.authFetch), the grace window IS
// applied — but a 30 s delay is still the right default because:
//   1. Feed auth status is informational (not critical path)
//   2. Waiting 30 s avoids even the first retry attempt during cold-start
//   3. Matches Render's documented cold-start window (15–30 s)
window.addEventListener('auth:login', () => {
  setTimeout(checkFeedAuthStatus, 30_000);
});
// FIX R21-D: Delay 5 s → 35 s on auth:restored (page-reload session restore).
// auth:restored fires on page-load _syncStoresOnLoad, meaning the backend may
// still be cold.  35 s gives the same buffer as auth:login but with an extra
// 5 s offset to avoid colliding with any auth:login-triggered checks.
window.addEventListener('auth:restored', () => {
  setTimeout(checkFeedAuthStatus, 35_000);
});

console.log('[AuthValidator] ✅ Auth validator loaded v5.4 — authFetch() available globally (R21: grace window + delegated checkFeedAuthStatus)');

})(window);
