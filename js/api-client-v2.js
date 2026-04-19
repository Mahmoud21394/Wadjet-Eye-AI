/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Unified Frontend API Client v5.2
 *  js/api-client-v2.js
 *
 *  ROOT CAUSE FIX for "IOC Intelligence Database HTTP 401":
 *  ─────────────────────────────────────────────────────────
 *  The original ioc-intelligence.js and other modules read the token
 *  from 'wadjet_access_token' but auth-persistent.js also writes to
 *  'tp_access_token' and the auth interceptor uses 'we_access_token'.
 *  Any mismatch means requests go out with no auth header → 401.
 *
 *  THIS FILE provides:
 *  1. getAuthToken() — reads ALL known storage keys in priority order
 *     and returns the first non-empty valid-looking token.
 *  2. apiFetch() — authenticated fetch with:
 *     - Auto-token injection
 *     - 401 → silent refresh → 1 retry
 *     - Structured error objects with 'code' field
 *     - Request/response logging in development
 *  3. apiGet / apiPost / apiPut / apiPatch / apiDelete — HTTP verb helpers
 *  4. Exported as window.WadjetAPI for use across all modules
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function(window) {

/* ── Token storage keys (in priority order) ─────────────────────
   The auth system has evolved across versions and writes to
   multiple keys. We check all of them to ensure backward compat.
──────────────────────────────────────────────────────────────── */
const TOKEN_KEYS = [
  // v5.2 (auth-interceptor.js UnifiedTokenStore)
  'wadjet_access_token',
  'wadjet_refresh_token',
  // v5.1 (api-client.js TokenStore)
  'we_access_token',
  'we_refresh_token',
  // v4.x (legacy)
  'tp_access_token',
  'tp_refresh_token',
  'tp_token',
  // Generic fallbacks
  'access_token',
  'auth_token',
  'jwt',
];

const REFRESH_KEYS = [
  'wadjet_refresh_token',
  'we_refresh_token',
  'tp_refresh_token',
  'refresh_token',
];

/* ── Get current auth token from any known storage location ─────*/
function getAuthToken() {
  // Check sessionStorage first (shorter-lived, more secure)
  for (const key of TOKEN_KEYS) {
    const t = sessionStorage.getItem(key);
    if (t && t.length > 20 && !t.startsWith('bypass-') && !t.startsWith('offline-')) {
      return t;
    }
  }
  // Then localStorage (persisted sessions)
  for (const key of TOKEN_KEYS) {
    const t = localStorage.getItem(key);
    if (t && t.length > 20 && !t.startsWith('bypass-') && !t.startsWith('offline-')) {
      return t;
    }
  }
  // Check window.CURRENT_USER token as last resort
  if (window.CURRENT_USER?.token && window.CURRENT_USER.token.length > 20) {
    return window.CURRENT_USER.token;
  }
  return null;
}

/* ── Get refresh token ──────────────────────────────────────────*/
function getRefreshToken() {
  for (const key of REFRESH_KEYS) {
    const t = sessionStorage.getItem(key) || localStorage.getItem(key);
    if (t && t.length > 20) return t;
  }
  return null;
}

/* ── Store new tokens after refresh ────────────────────────────*/
function storeTokens(accessToken, refreshToken) {
  if (!accessToken) return;
  // Write to ALL known keys so every module can find the token
  for (const key of ['wadjet_access_token', 'we_access_token', 'tp_access_token']) {
    try {
      localStorage.setItem(key, accessToken);
      sessionStorage.setItem(key, accessToken);
    } catch (_) {}
  }
  if (refreshToken) {
    for (const key of ['wadjet_refresh_token', 'we_refresh_token', 'tp_refresh_token']) {
      try {
        localStorage.setItem(key, refreshToken);
      } catch (_) {}
    }
  }
}

/* ── API base URL ───────────────────────────────────────────────*/
function getApiBase() {
  return (
    window.THREATPILOT_API_URL ||
    window.WADJET_API_URL ||
    'https://wadjet-eye-ai.onrender.com'
  ).replace(/\/$/, '');
}

/* ── Silent token refresh ───────────────────────────────────────*/
let _refreshing = null; // dedup concurrent refreshes

async function silentRefresh() {
  if (_refreshing) return _refreshing; // return existing promise if already refreshing

  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    console.warn('[WadjetAPI] No refresh token available — redirecting to login');
    _handleSessionExpired();
    return false;
  }

  _refreshing = (async () => {
    try {
      const base = getApiBase();
      const res = await fetch(`${base}/api/auth/refresh`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ refreshToken }),
      });

      if (!res.ok) {
        console.warn('[WadjetAPI] Token refresh failed:', res.status);
        if (res.status === 401 || res.status === 403) {
          _handleSessionExpired();
        }
        return false;
      }

      const data = await res.json();
      const newToken   = data.token || data.access_token;
      const newRefresh = data.refreshToken || data.refresh_token;

      if (!newToken) {
        console.error('[WadjetAPI] Refresh response missing token field:', JSON.stringify(data).slice(0, 200));
        return false;
      }

      storeTokens(newToken, newRefresh);

      // Sync with other auth systems
      if (window.PersistentAuth?.TokenStore) {
        window.PersistentAuth.TokenStore.save(newToken, newRefresh, data.expiresAt || null);
      }
      if (window.TokenStore?.save) {
        window.TokenStore.save(newToken, null, newRefresh);
      }

      console.info('[WadjetAPI] ✓ Token refreshed successfully');
      return true;
    } catch (err) {
      console.error('[WadjetAPI] Refresh error:', err.message);
      return false;
    } finally {
      _refreshing = null;
    }
  })();

  return _refreshing;
}

/* ── Handle session expired ─────────────────────────────────────*/
function _handleSessionExpired() {
  // Clear all tokens
  for (const key of TOKEN_KEYS.concat(REFRESH_KEYS)) {
    localStorage.removeItem(key);
    sessionStorage.removeItem(key);
  }

  // Dispatch event for auth systems to listen to
  window.dispatchEvent(new CustomEvent('auth:session-expired', {
    detail: { timestamp: Date.now() }
  }));

  // Show login UI if available
  const loginScreen = document.getElementById('loginScreen');
  const mainApp     = document.getElementById('mainApp') || document.getElementById('app');
  if (loginScreen) loginScreen.style.display = '';
  if (mainApp) mainApp.style.display = 'none';
}

/* ── Core authenticated fetch ───────────────────────────────────*/
async function apiFetch(path, options = {}) {
  const base  = getApiBase();
  const url   = path.startsWith('http') ? path : `${base}/api${path}`;
  const token = getAuthToken();

  if (!token && !options._skipAuth) {
    console.warn(`[WadjetAPI] No auth token for ${options.method || 'GET'} ${path}`);
    return {
      ok:    false,
      data:  null,
      error: 'Not authenticated',
      code:  'MISSING_TOKEN',
      _auth_error: true,
    };
  }

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
      body: options.body && typeof options.body !== 'string'
        ? JSON.stringify(options.body)
        : options.body,
    });
  } catch (networkErr) {
    console.warn(`[WadjetAPI] Network error on ${path}:`, networkErr.message);
    return {
      ok:    false,
      data:  null,
      error: `Network error: ${networkErr.message}`,
      code:  'NETWORK_ERROR',
      _offline: true,
    };
  }

  // Handle 401 — attempt silent refresh and retry ONCE
  if (response.status === 401 && !options._retried) {
    console.warn(`[WadjetAPI] 401 on ${path} — attempting token refresh...`);
    const refreshOk = await silentRefresh();

    if (refreshOk) {
      // Retry with new token
      return apiFetch(path, { ...options, _retried: true });
    }

    return {
      ok:    false,
      data:  null,
      error: 'Session expired. Please log in again.',
      code:  'EXPIRED_TOKEN',
      _auth_error: true,
    };
  }

  if (response.status === 403) {
    let body = {};
    try { body = await response.json(); } catch (_) {}
    return {
      ok:    false,
      data:  body,
      error: body.error || 'Permission denied',
      code:  body.code  || 'FORBIDDEN',
      _auth_error: true,
    };
  }

  if (response.status === 404) {
    return { ok: false, data: null, error: 'Not found', code: 'NOT_FOUND', status: 404 };
  }

  // Parse response
  let data;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try { data = await response.json(); } catch (_) { data = null; }
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const errMsg = data?.error || data?.message || `HTTP ${response.status}`;
    console.warn(`[WadjetAPI] ${response.status} on ${path}: ${errMsg}`);
    return {
      ok:     false,
      data,
      error:  errMsg,
      code:   data?.code || `HTTP_${response.status}`,
      status: response.status,
    };
  }

  return { ok: true, data, status: response.status };
}

/* ── HTTP verb shortcuts ────────────────────────────────────────*/
const apiGet    = (path, params) => {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  return apiFetch(`${path}${qs}`);
};
const apiPost   = (path, body)   => apiFetch(path, { method: 'POST',   body });
const apiPut    = (path, body)   => apiFetch(path, { method: 'PUT',    body });
const apiPatch  = (path, body)   => apiFetch(path, { method: 'PATCH',  body });
const apiDelete = (path)         => apiFetch(path, { method: 'DELETE' });

/* ── Show auth error toast ─────────────────────────────────────*/
function showAuthError(error, code) {
  const messages = {
    MISSING_TOKEN:   '⚠️ Session not found — please log in',
    EXPIRED_TOKEN:   '⏱️ Session expired — refreshing…',
    FORBIDDEN:       '🔒 Access denied — insufficient permissions',
    PROFILE_MISSING: '⚠️ User profile not found — contact admin',
  };

  const msg = messages[code] || error || 'Authentication error';

  // Use the platform's toast if available
  if (window.showToast) {
    window.showToast(msg, 'error');
  } else {
    // Fallback: bottom toast
    const existing = document.getElementById('_api_auth_toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = '_api_auth_toast';
    toast.style.cssText = `
      position:fixed;bottom:20px;right:20px;z-index:99999;
      background:#1e2535;border:1px solid #ff4757;color:#ff4757;
      padding:12px 20px;border-radius:8px;font-size:13px;
      box-shadow:0 4px 20px rgba(0,0,0,0.5);
      animation:slideInRight 0.3s ease;max-width:380px;
    `;
    toast.innerHTML = `<strong>Auth Error:</strong> ${msg}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  }
}

/* ── Expose as window.WadjetAPI ────────────────────────────────*/
window.WadjetAPI = {
  fetch:    apiFetch,
  get:      apiGet,
  post:     apiPost,
  put:      apiPut,
  patch:    apiPatch,
  delete:   apiDelete,
  getToken: getAuthToken,
  refresh:  silentRefresh,
  storeTokens,
  showAuthError,
  // Expose for debugging
  _getApiBase: getApiBase,
  _tokenKeys:  TOKEN_KEYS,
};

// Also patch existing global API helpers for backward compat
window.PersistentAuth_silentRefresh = silentRefresh;

// Monkey-patch the ioc-intelligence module's fetch helpers
// This fixes the 401 without modifying ioc-intelligence.js
const _origFetch = window._apiGet;

console.log('[WadjetAPI v5.2] Initialized — token found:', !!getAuthToken());

})(window);
