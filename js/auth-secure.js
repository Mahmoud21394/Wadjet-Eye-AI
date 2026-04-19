/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Auth Module v6.2
 *  js/auth-secure.js
 *
 *  v6.2 CRITICAL FIXES:
 *  ─────────────────────────────────────────────────────────────────
 *  FIX 1: Does NOT override window.authFetch — auth-interceptor.js
 *          (loaded before this file) already defines the canonical
 *          authFetch with full silent-refresh + retry logic.
 *          This file only defines authFetch as a FALLBACK when
 *          auth-interceptor.js is not loaded.
 *
 *  FIX 2: _silentRefresh() sends the refresh_token in the request
 *          body (was sending empty body → 400 Bad Request).
 *
 *  FIX 3: _handleHard401() no longer calls SecureSession.clear()
 *          which was wiping ALL tokens from localStorage, making
 *          every subsequent request fail immediately.
 *          It now shows the banner WITHOUT clearing live tokens —
 *          token cleanup happens only on explicit logout.
 *
 *  FIX 4: SecureSession.clearLegacyKeys() is NEVER called
 *          automatically on page load — tokens must be preserved.
 *
 *  ROLE OF THIS FILE:
 *  ─────────────────────────────────────────────────────────────────
 *  • Provides SecureSession (display-safe user data in sessionStorage)
 *  • Provides PersistentAuth_onLogin / PersistentAuth_onLogout hooks
 *  • Provides getAuthToken() reading from localStorage
 *  • Provides a fallback authFetch() (only used if auth-interceptor
 *    is not loaded — normally it is already defined)
 *  • Does NOT clear tokens on load or on 401
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

  // ── API base URL ────────────────────────────────────────────────
  function API_BASE() {
    return (global.THREATPILOT_API_URL || global.WADJET_API_URL ||
      'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  }

  // ── Keys we store (display only — NO tokens) ───────────────────
  const DISPLAY_KEY = 'waj_display';

  // ── Legacy keys — only removed on explicit logout ─────────────
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
    save(user) {
      try {
        const display = {
          id:          user.id,
          name:        user.name        || user.email,
          email:       user.email,
          role_label:  user.role        || 'ANALYST',
          tenant_name: user.tenant_name || user.tenant,
          avatar:      user.avatar      || (user.name || 'U').slice(0, 2).toUpperCase(),
          session_id:  user.session_id  || null,
          logged_in_at: Date.now(),
        };
        sessionStorage.setItem(DISPLAY_KEY, JSON.stringify(display));
        console.info('[SecureSession] ✅ Display session saved (no tokens stored)');
      } catch (e) {
        console.warn('[SecureSession] Failed to save display session:', e.message);
      }
    },

    get() {
      try {
        const raw = sessionStorage.getItem(DISPLAY_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    },

    exists() { return !!this.get(); },

    /**
     * v6.2 FIX: clear() does NOT call clearLegacyKeys().
     * Token keys are only wiped by PersistentAuth_onLogout (explicit logout).
     * Calling clearLegacyKeys() on every 401 banner was deleting valid tokens,
     * making the next page load fail immediately with no session.
     */
    clear() {
      sessionStorage.removeItem(DISPLAY_KEY);
    },

    /** Remove all v5.x localStorage/sessionStorage token keys — LOGOUT ONLY */
    clearLegacyKeys() {
      let removed = 0;
      LEGACY_KEYS.forEach(k => {
        if (localStorage.getItem(k))   { localStorage.removeItem(k);   removed++; }
        if (sessionStorage.getItem(k)) { sessionStorage.removeItem(k); removed++; }
      });
      if (removed > 0) {
      }
    },
  };

  // ══════════════════════════════════════════════════════════════
  // Read best available token from all storage locations
  // ══════════════════════════════════════════════════════════════
  function _getStoredToken() {
    // Prefer UnifiedTokenStore (auth-interceptor v6.0) if available
    if (typeof global.UnifiedTokenStore !== 'undefined') {
      const t = global.UnifiedTokenStore.getToken();
      if (t) return t;
    }
    const keys = ['wadjet_access_token', 'we_access_token', 'tp_access_token'];
    for (const k of keys) {
      const t = localStorage.getItem(k) || sessionStorage.getItem(k);
      if (t) return t;
    }
    return null;
  }

  // ══════════════════════════════════════════════════════════════
  // authFetch — FALLBACK ONLY
  //
  // v6.2 FIX: auth-interceptor.js defines the canonical window.authFetch
  // with full silent-refresh, retry, and StateSync integration.
  // This fallback is only installed if auth-interceptor.js is NOT loaded
  // (e.g., in unit tests or when loading sequence is wrong).
  //
  // DO NOT move this before auth-interceptor.js in the script loading order.
  // ══════════════════════════════════════════════════════════════
  let _refreshInProgress = false;
  let _last401BannerTime = 0;

  async function _fallbackAuthFetch(pathOrUrl, opts = {}) {
    const url = pathOrUrl.startsWith('http')
      ? pathOrUrl
      : `${API_BASE()}/api${pathOrUrl.startsWith('/') ? '' : '/'}${pathOrUrl}`;

    const token = _getStoredToken();

    const fetchOpts = {
      ...opts,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...(opts.headers || {}),
      },
    };

    let response;
    try {
      response = await fetch(url, fetchOpts);
    } catch (networkErr) {
      console.warn('[authFetch-fallback] Network error:', networkErr.message);
      throw new Error(`Network error: ${networkErr.message}`);
    }

    if (response.status === 401) {
      if (!_refreshInProgress) {
        _refreshInProgress = true;
        try {
          const refreshed = await _silentRefresh();
          if (refreshed) {
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
          console.warn('[authFetch-fallback] Silent refresh failed:', refreshErr.message);
        } finally {
          _refreshInProgress = false;
        }
      }
      _handleHard401();
      throw new Error('Authentication required. Please log in. (HTTP 401)');
    }

    if (response.status === 403) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || 'Access denied. (HTTP 403)');
    }

    if (response.status === 404) return { data: [], total: 0, _notfound: true };
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after') || '60';
      throw new Error(`Rate limited. Retry in ${retryAfter}s.`);
    }

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

  /**
   * v6.2 FIX: _silentRefresh() now properly includes refresh_token in body.
   * Old code sent empty body to /api/auth/refresh → 400 Bad Request.
   * Now delegates to window.silentRefresh (auth-interceptor) if available.
   */
  async function _silentRefresh() {
    // Prefer auth-interceptor's silentRefresh — it has full retry + StateSync integration
    if (typeof global.silentRefresh === 'function') {
      try {
        return await global.silentRefresh();
      } catch (_) { /* fall through to manual refresh */ }
    }

    const refreshToken = localStorage.getItem('wadjet_refresh_token')
                      || localStorage.getItem('we_refresh_token');
    if (refreshToken) {
      try {
        const resp = await fetch(`${API_BASE()}/api/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),  // v6.2 FIX: include body
        });
        if (resp.ok) {
          const data = await resp.json();
          const newToken = data.token || data.access_token;
          if (newToken) {
            ['wadjet_access_token', 'we_access_token', 'tp_access_token'].forEach(k => {
              localStorage.setItem(k, newToken);
              sessionStorage.setItem(k, newToken);
            });
            if (data.refreshToken || data.refresh_token) {
              localStorage.setItem('wadjet_refresh_token', data.refreshToken || data.refresh_token);
            }
            return true;
          }
        }
      } catch (e) { /* fall through */ }
    }

    return false;
  }

  /**
   * v6.2 FIX: _handleHard401() shows a session-expired banner WITHOUT
   * clearing tokens from localStorage. The old SecureSession.clear() call
   * triggered clearLegacyKeys() which deleted all tokens, causing every
   * subsequent request to fail immediately with no session to restore.
   *
   * Tokens are only cleared by PersistentAuth_onLogout (explicit logout).
   */
  function _handleHard401() {
    const now = Date.now();
    if (now - _last401BannerTime < 8000) return; // debounce
    _last401BannerTime = now;

    // v6.2: Only clear the display session (sessionStorage), NOT the tokens
    sessionStorage.removeItem(DISPLAY_KEY);

    const mainApp = document.getElementById('mainApp');
    if (!mainApp || mainApp.style.display === 'none') return;

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
  // v6.2: Migration — do NOT clear tokens on load
  // ══════════════════════════════════════════════════════════════
  function migrateFromV5() {
    console.info('[SecureAuth v6.2] Startup: token keys preserved (no auto-cleanup)');
  }

  // ══════════════════════════════════════════════════════════════
  // Session restore on page load
  // ══════════════════════════════════════════════════════════════
  async function restoreSession(maxRetries = 3, baseDelayMs = 2000) {
    const hasToken = !!_getStoredToken();
    const hasDisplaySession = SecureSession.exists();

    if (!hasDisplaySession && !hasToken) {
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
          SecureSession.save(data.user || data);
          global.CURRENT_USER = data.user || data;
          global.dispatchEvent(new CustomEvent('auth:restored', { detail: global.CURRENT_USER }));
          return true;
        }

        if (resp.status === 401) {
          // v6.2: Only clear display session, NOT tokens
          sessionStorage.removeItem(DISPLAY_KEY);
          return false;
        }

        if (attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          console.warn(`[SecureSession] /api/auth/me returned ${resp.status} — retrying in ${delay}ms`);
          await new Promise(r => setTimeout(r, delay));
        }
      } catch (err) {
        if (attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          console.warn(`[SecureSession] Network error on restore attempt ${attempt + 1}: ${err.message}. Retrying in ${delay}ms`);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }

    console.warn('[SecureSession] Could not restore session after retries');
    return false;
  }

  // ══════════════════════════════════════════════════════════════
  // Public exports
  // ══════════════════════════════════════════════════════════════
  global.SecureSession  = SecureSession;
  global.restoreSession = restoreSession;

  // v6.2 FIX: Only install authFetch as FALLBACK if not already defined
  // by auth-interceptor.js (which should always be loaded first).
  if (typeof global.authFetch !== 'function') {
    console.warn('[SecureAuth v6.2] auth-interceptor.js not loaded — installing fallback authFetch');
    global.authFetch = _fallbackAuthFetch;
  } else {
  }

  // getAuthToken reads from UnifiedTokenStore first, then localStorage
  global.getAuthToken = function () {
    return _getStoredToken();
  };

  // PersistentAuth_onLogin — save display data + tokens
  // v6.2: Only sets if not already set by auth-interceptor.js
  if (typeof global.PersistentAuth_onLogin !== 'function') {
    global.PersistentAuth_onLogin = function(user, token, refreshToken, expiresAt, offline) {
      if (user) SecureSession.save(user);
      if (token && !offline) {
        ['wadjet_access_token', 'we_access_token', 'tp_access_token'].forEach(k => {
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
  }

  // PersistentAuth_onLogout — ONLY place that clears tokens
  if (typeof global.PersistentAuth_onLogout !== 'function') {
    global.PersistentAuth_onLogout = function() {
      SecureSession.clearLegacyKeys();  // full cleanup on explicit logout only
      sessionStorage.removeItem(DISPLAY_KEY);
    };
  }

  document.addEventListener('DOMContentLoaded', () => {
    migrateFromV5();
  });

})(window);
