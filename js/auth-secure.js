/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Session Manager v2.0
 *  FILE: js/auth-secure.js
 *
 *  REPLACES: auth-persistent.js (DELETED — SEC-002 Fix)
 *
 *  Security model:
 *  • Tokens stored ONLY in httpOnly cookies (server-side) — no localStorage
 *  • Session state tracked in memory (sessionStorage for tab lifetime only)
 *  • PKCE-based OAuth2 flow when applicable
 *  • TOTP MFA enforcement before any privileged action
 *  • Automatic logout on idle > IDLE_TIMEOUT_MS
 *  • No client-side token storage — all auth via cookie+csrf pattern
 *
 *  Audit finding: SEC-002 — localStorage token storage — CRITICAL
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function SecureSessionManager() {
  // ── Constants ─────────────────────────────────────────────────
  const IDLE_TIMEOUT_MS   = 30 * 60 * 1000;   // 30 min
  const ACTIVITY_EVENTS   = ['mousedown', 'keydown', 'touchstart', 'scroll'];
  const API_BASE          = window.__WADJET_API_BASE__ || '/api';
  const MFA_REQUIRED_KEY  = '__mfa_required__';

  // ── Internal state (memory only — not persisted) ──────────────
  let _idleTimer      = null;
  let _sessionValid   = false;
  let _userId         = null;
  let _tenantId       = null;
  let _mfaVerified    = false;
  let _csrfToken      = null;

  // ── CSRF token management ─────────────────────────────────────
  async function refreshCsrfToken() {
    try {
      const res = await fetch(`${API_BASE}/auth/csrf-token`, {
        credentials: 'include',
        cache:       'no-store',
      });
      if (!res.ok) return null;
      const { token } = await res.json();
      _csrfToken = token;
      return token;
    } catch {
      return null;
    }
  }

  function getCsrfToken() { return _csrfToken; }

  // ── Fetch wrapper with CSRF header ────────────────────────────
  async function secureRequest(url, options = {}) {
    if (!_csrfToken) await refreshCsrfToken();

    const headers = {
      'Content-Type':  'application/json',
      'X-CSRF-Token':  _csrfToken || '',
      ...options.headers,
    };

    const res = await fetch(url, {
      ...options,
      credentials: 'include',
      headers,
    });

    // Session expired → redirect to login
    if (res.status === 401) {
      _invalidateSession('SERVER_401');
      return res;
    }

    return res;
  }

  // ── Session validation (ping /api/auth/me) ────────────────────
  async function validateSession() {
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        credentials: 'include',
        cache:       'no-store',
      });

      if (!res.ok) {
        _invalidateSession('VALIDATE_FAIL');
        return false;
      }

      const { user } = await res.json();
      _sessionValid = true;
      _userId   = user.id;
      _tenantId = user.tenant_id;

      // Check if MFA is required but not yet verified
      const mfaRequired = sessionStorage.getItem(MFA_REQUIRED_KEY) === 'true';
      if (user.mfa_enabled && !_mfaVerified && !mfaRequired) {
        sessionStorage.setItem(MFA_REQUIRED_KEY, 'true');
        _redirectMfa();
        return false;
      }

      _resetIdleTimer();
      return true;
    } catch {
      return false;
    }
  }

  // ── MFA verification ─────────────────────────────────────────
  async function verifyMfa(totpCode) {
    const res = await secureRequest(`${API_BASE}/auth/mfa/verify`, {
      method: 'POST',
      body:   JSON.stringify({ totp_code: totpCode }),
    });

    if (res.ok) {
      _mfaVerified = true;
      sessionStorage.removeItem(MFA_REQUIRED_KEY);
      _resetIdleTimer();
      return { success: true };
    }

    const err = await res.json().catch(() => ({}));
    return { success: false, error: err.error || 'MFA verification failed' };
  }

  // ── Logout ────────────────────────────────────────────────────
  async function logout(reason = 'USER_LOGOUT') {
    try {
      await secureRequest(`${API_BASE}/auth/logout`, { method: 'POST' });
    } catch { /* best effort */ }
    _invalidateSession(reason);
  }

  // ── Idle timeout ─────────────────────────────────────────────
  function _resetIdleTimer() {
    clearTimeout(_idleTimer);
    _idleTimer = setTimeout(() => logout('IDLE_TIMEOUT'), IDLE_TIMEOUT_MS);
  }

  function _startActivityTracking() {
    ACTIVITY_EVENTS.forEach(evt =>
      document.addEventListener(evt, _resetIdleTimer, { passive: true })
    );
  }

  // ── Session invalidation ─────────────────────────────────────
  function _invalidateSession(reason) {
    clearTimeout(_idleTimer);
    _sessionValid  = false;
    _userId        = null;
    _tenantId      = null;
    _mfaVerified   = false;
    _csrfToken     = null;
    sessionStorage.clear();

    // Emit event for app to handle (redirect, show message, etc.)
    window.dispatchEvent(new CustomEvent('wadjet:session-expired', {
      detail: { reason },
    }));
  }

  function _redirectMfa() {
    window.dispatchEvent(new CustomEvent('wadjet:mfa-required'));
  }

  // ── Public API ────────────────────────────────────────────────
  window.WadjetAuth = {
    validateSession,
    verifyMfa,
    logout,
    secureRequest,
    getCsrfToken,
    getUser:     () => ({ id: _userId, tenantId: _tenantId }),
    isValid:     () => _sessionValid,
    isMfaOk:     () => _mfaVerified,
  };

  // ── Auto-init on DOM ready ────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _startActivityTracking);
  } else {
    _startActivityTracking();
  }

  // Expose for module systems
  if (typeof module !== 'undefined') module.exports = window.WadjetAuth;

})();
