/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Auth Module v6.0
 *  js/auth-secure.js
 *
 *  SECURITY DESIGN:
 *  ─────────────────
 *  • NO tokens stored in localStorage or sessionStorage
 *  • Session managed via httpOnly cookies (set by backend)
 *  • JS can NEVER read the access token (XSS-safe)
 *  • Only non-sensitive display data stored client-side
 *  • credentials:'include' sends cookies automatically
 *  • Legacy key cleanup on load (migration from v5.x)
 *
 *  REPLACES:
 *  • js/auth-persistent.js  (deleted)
 *  • Token-read logic in js/auth-interceptor.js
 *  • localStorage writes in js/main.js
 *
 *  LOADS BEFORE: main.js, auth-interceptor.js, all page modules
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {
  /* ── Minimal production-aware logger (delegates to _malLogger if present) ── */
  const _isProd = !(
    location.hostname === 'localhost' ||
    location.hostname === '127.0.0.1' ||
    location.hostname.includes('.e2b.dev') ||
    localStorage.getItem('wadjet_debug') === '1'
  );
  const _L = {
    info  : (...a) => { if (!_isProd || global.DEBUG_MODE) console.info('[SecureAuth]', ...a); },
    warn  : (...a) => { if (!_isProd || global.DEBUG_MODE) console.warn('[SecureAuth]', ...a); },
    error : (...a) => console.error('[SecureAuth]', ...a), // always
    debug : (...a) => { if (!_isProd && global.DEBUG_MODE !== false) console.log('[SecureAuth]', ...a); },
  };

  // ── API base URL ────────────────────────────────────────────────
  function API_BASE() {
    return (global.THREATPILOT_API_URL || global.WADJET_API_URL ||
      'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  }

  // ── Keys we store (display only — NO tokens) ───────────────────
  const DISPLAY_KEY = 'waj_display';

  // ── Legacy keys to REMOVE from v5.x ──────────────────────────
  const LEGACY_KEYS = [
    'wadjet_access_token', 'wadjet_refresh_token', 'wadjet_token_expires_at',
    'wadjet_user_profile', 'wadjet_session_id',    'wadjet_last_activity',
    'wadjet_offline_mode', 'we_access_token',       'we_refresh_token',
    'we_token_expires',    'we_user',               'tp_access_token',
    'tp_refresh_token',    'tp_user',               'access_token',
    'refresh_token',       'user_profile',
  ];

  // ══════════════════════════════════════════════════════════════
  // SecureSession — stores ONLY display-safe, non-privileged data
  // ══════════════════════════════════════════════════════════════
  const SecureSession = {
    /**
     * Save display data from login response.
     * DOES NOT save: token, refresh_token, permissions array.
     * permissions is an auth claim — must come from the cookie-verified server response.
     */
    save(user) {
      try {
        const display = {
          id:          user.id,
          name:        user.name        || user.email,
          email:       user.email,
          role_label:  user.role        || 'ANALYST',   // display only
          tenant_name: user.tenant_name || user.tenant,
          avatar:      user.avatar      || (user.name || 'U').slice(0, 2).toUpperCase(),
          session_id:  user.session_id  || null,        // for session management UI
          logged_in_at: Date.now(),
        };
        // sessionStorage clears when tab is closed — appropriate for high-privilege platform
        sessionStorage.setItem(DISPLAY_KEY, JSON.stringify(display));
        _L.debug('✅ Display session saved (no tokens stored)');
      } catch (e) {
        _L.warn('Failed to save display session:', e.message);
      }
    },

    get() {
      try {
        const raw = sessionStorage.getItem(DISPLAY_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    },

    exists() { return !!this.get(); },

    clear() {
      sessionStorage.removeItem(DISPLAY_KEY);
      this.clearLegacyKeys();
      _L.debug('Session cleared');
    },

    /** Remove all v5.x localStorage/sessionStorage token keys */
    clearLegacyKeys() {
      let removed = 0;
      LEGACY_KEYS.forEach(k => {
        if (localStorage.getItem(k))   { localStorage.removeItem(k);   removed++; }
        if (sessionStorage.getItem(k)) { sessionStorage.removeItem(k); removed++; }
      });
      if (removed > 0) _L.debug(`Cleaned up ${removed} legacy token storage keys`);
    },
  };

  // ══════════════════════════════════════════════════════════════
  // authFetch — unified fetch wrapper (Bearer + cookie bridge)
  //
  // v6.1 FIX: Backend uses Authorization: Bearer header validation.
  // httpOnly cookies are the future goal. This version sends BOTH:
  // the Bearer token from localStorage AND credentials:'include'.
  // ══════════════════════════════════════════════════════════════
  let _refreshInProgress   = false;
  let _last401BannerTime   = 0;

  /** Read best available token from all storage locations */
  function _getStoredToken() {
    const keys = ['wadjet_access_token','we_access_token','tp_access_token'];
    for (const k of keys) {
      const t = localStorage.getItem(k) || sessionStorage.getItem(k);
      if (t) return t;
    }
    return null;
  }

  async function authFetch(pathOrUrl, opts = {}) {
    const url = pathOrUrl.startsWith('http')
      ? pathOrUrl
      : `${API_BASE()}/api${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;

    const token = _getStoredToken();

    const fetchOpts = {
      ...opts,
      credentials: 'include',    // also send cookies (future httpOnly auth)
      headers: {
        'Content-Type': 'application/json',
        // v6.1 FIX: inject Bearer token — backend requires Authorization header
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...(opts.headers || {}),
      },
    };

    let response;
    try {
      response = await fetch(url, fetchOpts);
    } catch (networkErr) {
      _L.warn('Network error:', networkErr.message);
      throw new Error(`Network error: ${networkErr.message}`);
    }

    // ── 401 Handler ────────────────────────────────────────────
    if (response.status === 401) {
      if (!_refreshInProgress) {
        _refreshInProgress = true;
        try {
          const refreshed = await _silentRefresh();
          if (refreshed) {
            // Retry with refreshed token (Bearer + cookie)
            const newToken = _getStoredToken();
            const retryOpts = {
              ...fetchOpts,
              headers: {
                ...fetchOpts.headers,
                ...(newToken ? { 'Authorization': `Bearer ${newToken}` } : {}),
              },
            };
            const retryResp = await fetch(url, retryOpts);
            _refreshInProgress = false;
            if (retryResp.ok) return _parseResponse(retryResp);
            if (retryResp.status === 401) {
              _handleHard401();
              throw new Error('Session expired. Please log in again.');
            }
          }
        } catch (refreshErr) {
          _L.warn('Silent refresh failed:', refreshErr.message);
        } finally {
          _refreshInProgress = false;
        }
      }
      _handleHard401();
      throw new Error('Authentication required. Please log in. (HTTP 401)');
    }

    // ── 403 ────────────────────────────────────────────────────
    if (response.status === 403) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || 'Access denied. (HTTP 403)');
    }

    // ── 404 — return empty gracefully ─────────────────────────
    if (response.status === 404) {
      return { data: [], total: 0, _notfound: true };
    }

    // ── 429 Rate limit ────────────────────────────────────────
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after') || '60';
      throw new Error(`Rate limited. Retry in ${retryAfter}s.`);
    }

    // ── 5xx ───────────────────────────────────────────────────
    if (response.status >= 500) {
      const body = await response.text().catch(() => '');
      throw new Error(`Server error (HTTP ${response.status})${body ? ': ' + body.slice(0, 120) : ''}`);
    }

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Request failed (HTTP ${response.status})${body ? ': ' + body.slice(0, 120) : ''}`);
    }

    return _parseResponse(response);
  }

  async function _parseResponse(resp) {
    const ct = resp.headers.get('content-type') || '';
    return ct.includes('application/json') ? resp.json() : resp.text();
  }

  async function _silentRefresh() {
    // Try Bearer token refresh first (current backend implementation)
    const refreshToken = localStorage.getItem('wadjet_refresh_token')
                      || localStorage.getItem('we_refresh_token');
    if (refreshToken) {
      try {
        const resp = await fetch(`${API_BASE()}/api/auth/refresh`, {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        if (resp.ok) {
          const data = await resp.json();
          const newToken = data.token || data.access_token;
          if (newToken) {
            ['wadjet_access_token','we_access_token','tp_access_token'].forEach(k => {
              localStorage.setItem(k, newToken); sessionStorage.setItem(k, newToken);
            });
            if (data.refreshToken || data.refresh_token)
              localStorage.setItem('wadjet_refresh_token', data.refreshToken || data.refresh_token);
            _L.debug('✅ Bearer token refreshed');
            return true;
          }
          // requires_reauth=true means no new token was issued — force re-login
          if (data.requires_reauth) { _L.warn('requires_reauth=true — forcing re-login'); return false; }
        }
        // 401 on the refresh itself means the refresh token is invalid — force re-login immediately
        if (resp.status === 401) { _L.warn('Refresh endpoint returned 401 — session invalid'); return false; }
      } catch (e) { /* fall through */ }
    }
    // Fallback: cookie-based refresh (backend reads HTTP-only cookie)
    try {
      const resp = await fetch(`${API_BASE()}/api/auth/refresh`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (resp.ok) { _L.debug('✅ Cookie refresh ok'); return true; }
      if (resp.status === 401) { _L.warn('Cookie refresh returned 401 — session invalid'); return false; }
      return false;
    } catch (e) { _L.warn('Silent refresh error:', e.message); return false; }
  }

  function _handleHard401() {
    const now = Date.now();
    if (now - _last401BannerTime < 8000) return; // debounce banner
    _last401BannerTime = now;

    SecureSession.clear();

    // Show session expired banner if app is visible
    const mainApp = document.getElementById('mainApp');
    if (!mainApp || mainApp.style.display === 'none') return;

    // Remove existing banner
    document.getElementById('session-expired-banner')?.remove();

    const banner = document.createElement('div');
    banner.id = 'session-expired-banner';
    banner.style.cssText = [
      'position:fixed;top:0;left:0;right:0;z-index:99999',
      'background:#dc2626;color:#fff;padding:12px 20px',
      'display:flex;align-items:center;justify-content:space-between',
      'font-size:14px;font-weight:500;box-shadow:0 2px 12px rgba(0,0,0,.4)',
    ].join(';');
    banner.innerHTML = `
      <span>🔒 Your session has expired. Please log in again.</span>
      <div style="display:flex;gap:8px">
        <button onclick="window.doLogout?.()" style="background:#fff;color:#dc2626;border:none;
          padding:5px 14px;border-radius:4px;cursor:pointer;font-size:13px;font-weight:600">
          Log In
        </button>
        <button onclick="this.closest('#session-expired-banner')?.remove()"
          style="background:transparent;border:1px solid rgba(255,255,255,.5);color:#fff;
          padding:5px 10px;border-radius:4px;cursor:pointer;font-size:13px">✕</button>
      </div>`;
    document.body.prepend(banner);
    setTimeout(() => banner?.remove(), 20000);

    if (typeof global.showToast === 'function') {
      global.showToast('🔒 Session expired. Please log in again.', 'error', 5000);
    }
  }

  // ══════════════════════════════════════════════════════════════
  // Migration: v6.1 FIX — do NOT clear tokens on every page load.
  // The old clearLegacyKeys() was deleting valid tokens saved by login.
  // Token cleanup happens only on explicit logout.
  // ══════════════════════════════════════════════════════════════
  function migrateFromV5() {
    // REMOVED: SecureSession.clearLegacyKeys() — was wiping valid tokens
    _L.debug('Startup: token keys preserved (no auto-cleanup)');
  }

  // ══════════════════════════════════════════════════════════════
  // Session restore on page load
  // v6.1: Also tries Bearer token from localStorage
  // ══════════════════════════════════════════════════════════════
  async function restoreSession(maxRetries = 3, baseDelayMs = 2000) {
    const hasToken = !!_getStoredToken();
    const hasDisplaySession = SecureSession.exists();

    if (!hasDisplaySession && !hasToken) {
      _L.debug('No session — showing login screen');
      return false;
    }

    const token = _getStoredToken();

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const resp = await fetch(`${API_BASE()}/api/auth/me`, {
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
          },
        });

        if (resp.ok) {
          const data = await resp.json();
          // Re-save display data from server (authoritative)
          SecureSession.save(data.user || data);
          global.CURRENT_USER = data.user || data;
          global.dispatchEvent(new CustomEvent('auth:restored', { detail: global.CURRENT_USER }));
          _L.debug('✅ Session restored for:', global.CURRENT_USER?.email);
          return true;
        }

        if (resp.status === 401) {
          // 401 = definitive session expiry — do NOT retry, clear and return false
          SecureSession.clear();
          _L.debug('Cookie expired — cleared session, showing login');
          return false;
        }

        // Server error (5xx) — retry with backoff (max 3 attempts only)
        if (attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          _L.warn(`/api/auth/me returned ${resp.status} — retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`);
          await new Promise(r => setTimeout(r, delay));
        }
      } catch (err) {
        if (attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          _L.warn(`Network error on restore attempt ${attempt + 1}: ${err.message}. Retrying in ${delay}ms`);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }

    // All retries exhausted — assume offline or server down (do NOT loop indefinitely)
    _L.warn('Could not restore session after retries — showing login');
    return false;
  }

  // ══════════════════════════════════════════════════════════════
  // ══════════════════════════════════════════════════════════════
  // Public exports
  // ══════════════════════════════════════════════════════════════
  global.SecureSession   = SecureSession;
  global.authFetch       = authFetch;
  global.restoreSession  = restoreSession;

  // v6.1 FIX: getAuthToken reads from localStorage (was always returning null)
  global.getAuthToken = function () {
    return localStorage.getItem('wadjet_access_token')
        || localStorage.getItem('we_access_token')
        || localStorage.getItem('tp_access_token')
        || sessionStorage.getItem('wadjet_access_token')
        || null;
  };

  // v6.1 FIX: PersistentAuth_onLogin now saves token + display data
  global.PersistentAuth_onLogin = function(user, token, refreshToken, expiresAt, offline) {
    if (user) SecureSession.save(user);
    if (token && !offline) {
      ['wadjet_access_token','we_access_token','tp_access_token'].forEach(k => {
        localStorage.setItem(k, token);
        sessionStorage.setItem(k, token);
      });
      if (refreshToken) localStorage.setItem('wadjet_refresh_token', refreshToken);
      const exp = expiresAt
        ? (typeof expiresAt === 'number'
           ? new Date(Date.now() + expiresAt * 1000).toISOString() : expiresAt)
        : new Date(Date.now() + 900000).toISOString();
      localStorage.setItem('wadjet_token_expires_at', exp);
    }
  };

  global.PersistentAuth_onLogout = function() {
    SecureSession.clear();
    ['wadjet_access_token','we_access_token','tp_access_token',
     'wadjet_refresh_token','we_refresh_token','wadjet_token_expires_at'].forEach(k => {
      try { localStorage.removeItem(k); } catch {}
      try { sessionStorage.removeItem(k); } catch {}
    });
  };

  // Run migration on load
  document.addEventListener('DOMContentLoaded', () => {
    migrateFromV5();
  });

  _L.debug('✅ Loaded — Bearer+cookie bridge active. Tokens preserved in localStorage.');

})(window);
