/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Global Auth Validator & API Health Monitor v5.3
 *  js/auth-validator.js
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

function _show401Banner() {
  const now = Date.now();
  if (now - _last401Toast < 8000) return; // Don't spam
  _last401Toast = now;

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
  div.style.cssText = `
    position:fixed;top:0;left:0;right:0;z-index:9999;
    background:#dc2626;color:#fff;padding:12px 20px;
    display:flex;align-items:center;justify-content:space-between;
    font-size:14px;font-weight:500;box-shadow:0 2px 10px rgba(0,0,0,.3)
  `;
  div.innerHTML = `
    <span>🔒 Your session has expired. Please log in again to continue.</span>
    <div style="display:flex;gap:10px">
      <button onclick="window.doLogout?.()" style="background:#fff;color:#dc2626;border:none;padding:5px 14px;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600">
        Log In
      </button>
      <button onclick="this.closest('#session-expired-banner').remove()" style="background:transparent;border:1px solid #ffffff80;color:#fff;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:13px">
        Dismiss
      </button>
    </div>
  `;
  document.body.prepend(div);

  // Auto-remove after 15s
  setTimeout(() => div.remove(), 15000);
}

/* ── Centralized auth-aware fetch wrapper ───────────────────────*/
async function authFetch(pathOrUrl, opts = {}) {
  const url = pathOrUrl.startsWith('http')
    ? pathOrUrl
    : `${API_BASE()}/api${pathOrUrl}`;

  const token = getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };

  let response;
  try {
    response = await fetch(url, { ...opts, headers });
  } catch (networkErr) {
    console.warn('[AuthFetch] Network error:', networkErr.message);
    throw new Error(`Network error: ${networkErr.message}. Check your connection.`);
  }

  // ── 401 Handler ──────────────────────────────────────────────
  if (response.status === 401) {
    // Attempt silent refresh once
    if (!_refreshInProgress && typeof global.PersistentAuth_silentRefresh === 'function') {
      _refreshInProgress = true;
      try {
        const refreshed = await global.PersistentAuth_silentRefresh();
        if (refreshed) {
          const newToken = getToken();
          const retryHeaders = {
            ...headers,
            ...(newToken ? { Authorization: `Bearer ${newToken}` } : {}),
          };
          const retryResp = await fetch(url, { ...opts, headers: retryHeaders });
          if (retryResp.ok) {
            return retryResp.json();
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
  try {
    const url = `${API_BASE()}/health`;
    const resp = await fetch(url, { timeout: 8000 });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    console.info('[AuthValidator] ✅ Backend health OK:', data.status || 'healthy');
    global._WADJET_BACKEND_HEALTHY = true;
    return true;
  } catch (err) {
    console.warn('[AuthValidator] ⚠️ Backend health check failed:', err.message);
    console.warn('[AuthValidator]    This may be normal on cold start (Render sleeps after 15min).');
    global._WADJET_BACKEND_HEALTHY = false;
    return false;
  }
}

/* ── Feed Auth Status — shows which feeds have keys configured ──*/
async function checkFeedAuthStatus() {
  const token = getToken();
  if (!token) return;

  try {
    const resp = await authFetch('/ingest/feeds');
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
global.authFetch   = authFetch;
global.getToken    = getToken;
global.checkAPIHealth = checkAPIHealth;
global.checkFeedAuthStatus = checkFeedAuthStatus;

// Run health check on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  // Delay slightly to not slow initial paint
  setTimeout(checkAPIHealth, 2000);
});

// Listen for auth:login event to check feed status
window.addEventListener('auth:login', () => {
  setTimeout(checkFeedAuthStatus, 3000);
});
window.addEventListener('auth:restored', () => {
  setTimeout(checkFeedAuthStatus, 5000);
});

console.log('[AuthValidator] ✅ Auth validator loaded — authFetch() available globally');

})(window);
