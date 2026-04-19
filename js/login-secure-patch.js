/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Login Patch v6.2 (v7.4 retryIn fix)
 *  js/login-secure-patch.js
 *
 *  v6.1 FIX — Auth Token NOT FOUND after login (root cause):
 *  ────────────────────────────────────────────────────────────
 *  v6.0 _finalizeLogin() intentionally stored NO tokens — it was
 *  designed for httpOnly cookie auth. But the backend still returns
 *  JWT tokens in JSON (Bearer flow) and does NOT set cookies.
 *
 *  Result: after login success, localStorage had zero tokens.
 *  Every subsequent API call got 401 because getToken() → null.
 *
 *  FIX in v6.1:
 *  • _finalizeLogin() now writes token to ALL storage keys via
 *    UnifiedTokenStore.save() (auth-interceptor.js)
 *  • Falls back to direct localStorage writes if interceptor not loaded
 *  • Display data still saved to SecureSession (no regression)
 *  • httpOnly cookie path ready when backend implements SET-COOKIE
 *
 *  ✅ KEPT (security fixes from v6.0):
 *  • No _EMERGENCY_ACCOUNTS in browser JS
 *  • No client-side auth bypass
 *  • MFA challenge step (TOTP)
 *  • Clear, honest error messages
 *
 *  LOAD ORDER: after auth-interceptor.js and auth-persistent.js,
 *  before main.js (so window.doLogin is overridden correctly)
 *
 *  ⚠️  DEPLOYMENT NOTE:
 *  Immediately rotate credentials for all accounts previously in
 *  _EMERGENCY_ACCOUNTS. The break-glass path is server-side only.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// Override doLogin with the secure version when this script loads
window.addEventListener('DOMContentLoaded', function () {
  // Replace the potentially vulnerable doLogin with the secure version
  window.doLogin = secureDoLogin;
});

/* ══════════════════════════════════════════════════════════════════
   SECURE LOGIN — server-only authentication
   No client-side fallback. No emergency accounts in browser.
   If the server is down, the user cannot log in. Full stop.
════════════════════════════════════════════════════════════════ */
async function secureDoLogin() {
  // Clear any stale tokens before attempting login.
  // Guard prevents ReferenceError when auth-interceptor.js is not yet loaded.
  if (typeof window.UnifiedTokenStore !== 'undefined') {
    window.UnifiedTokenStore.clear();
  }
  const emailEl  = document.getElementById('loginEmail');
  const passEl   = document.getElementById('loginPassword');
  const tenantEl = document.getElementById('loginTenant');
  const errEl    = document.getElementById('loginError');
  const btn      = document.querySelector('.login-btn');

  const email    = emailEl?.value?.trim()?.toLowerCase();
  const password = passEl?.value;
  const tenant   = tenantEl?.value || 'mssp-global';

  // ── Input validation ─────────────────────────────────────────
  if (!email || !password) {
    _showLoginError(errEl, '⚠️ Email and password are required.');
    return;
  }

  if (!email.includes('@') || !email.includes('.')) {
    _showLoginError(errEl, '⚠️ Please enter a valid email address.');
    return;
  }

  _setBtnLoading(btn, true);
  _clearLoginError(errEl);

  try {
    // ── ONLY path: real backend authentication ────────────────
    if (typeof API === 'undefined' || typeof API.auth?.login !== 'function') {
      throw new Error('API client not loaded. Check your network connection and refresh the page.');
    }

    const data = await API.auth.login(email, password, tenant);

    // ── MFA Required — show TOTP challenge screen ────────────
    if (data?.mfa_required && data?.mfa_session_token) {
      _setBtnLoading(btn, false);
      _showMFAChallenge(data.mfa_session_token, email);
      return;
    }

    // ── Full login success ────────────────────────────────────
    if (!data?.user) {
      throw new Error('Invalid response from authentication server. Please try again.');
    }

    await _finalizeLogin(data);
    // Reset retry counter on success
    secureDoLogin._autoRetryCount = 0;
    secureDoLogin._retrying = false;

  } catch (err) {
    _setBtnLoading(btn, false);

    const msg = err.message || 'Login failed';
    // v7.4 FIX: Parse retryIn from API response if available
    const serverRetryIn = err._retryIn || null;
    const display = _mapLoginError(msg);

    _showLoginError(errEl, display);
    console.warn('[SecureLogin] Authentication failed:', msg);

    // ── Auto-retry for 503 AUTH_SERVICE_UNAVAILABLE ────────────────────────
    // v7.4: The backend returns retryIn: 5 in the response body.
    // Frontend respects that value (clamped: min 5s, max 20s).
    // Cap at 2 total auto-retries to prevent infinite loops.
    const isTransient = msg.toLowerCase().includes('temporarily unavailable') ||
                        msg.toLowerCase().includes('auth_service_unavailable') ||
                        msg.toLowerCase().includes('db_timeout')               ||
                        msg.toLowerCase().includes('request aborted')          ||
                        msg.toLowerCase().includes('service unavailable')      ||
                        msg.toLowerCase().includes('try again in');

    secureDoLogin._autoRetryCount = (secureDoLogin._autoRetryCount || 0);

    if (isTransient && secureDoLogin._autoRetryCount < 2 && !secureDoLogin._retrying) {
      secureDoLogin._autoRetryCount += 1;
      secureDoLogin._retrying = true;
      // v7.4 FIX: Respect server's retryIn guidance (clamped 5–20s)
      const defaultDelay = secureDoLogin._autoRetryCount === 1 ? 8 : 15;
      const retryIn = serverRetryIn
        ? Math.min(Math.max(serverRetryIn, 5), 20)
        : defaultDelay;
      _showLoginError(errEl,
        `⏳ Server warming up (attempt ${secureDoLogin._autoRetryCount}/2)… retrying in ${retryIn}s.`
      );
      setTimeout(() => {
        secureDoLogin._retrying = false;
        secureDoLogin();
      }, retryIn * 1000);
      return;
    }

    // Reset counter on final failure or non-transient error
    secureDoLogin._retrying = false;
    if (!isTransient) secureDoLogin._autoRetryCount = 0;

    // On persistent 503, show actionable guidance
    if (isTransient) {
      _showLoginError(errEl,
        '❌ Authentication service is currently unavailable. ' +
        'This may be a temporary Render/Supabase cold-start issue. ' +
        'Please wait 30 seconds and try again manually, or contact support.'
      );
      secureDoLogin._autoRetryCount = 0;
    }

    // ── NO FALLBACK. No emergency accounts. No offline mode. ─
    // If the server is unreachable, the user sees a clear message.
    // Break-glass access is handled server-side via /api/auth/break-glass
  }
}

/* ══════════════════════════════════════════════════════════════════
   MFA Challenge UI
════════════════════════════════════════════════════════════════ */
function _showMFAChallenge(mfaSessionToken, email) {
  // Hide password login form
  const loginForm = document.getElementById('loginForm') ||
                    document.querySelector('.login-form-container');
  if (loginForm) loginForm.style.display = 'none';

  // Show or create MFA challenge panel
  let mfaPanel = document.getElementById('mfaChallengePanel');
  if (!mfaPanel) {
    mfaPanel = document.createElement('div');
    mfaPanel.id = 'mfaChallengePanel';
    mfaPanel.innerHTML = `
      <div style="text-align:center;padding:32px 24px;max-width:380px;margin:0 auto">
        <div style="font-size:48px;margin-bottom:16px">🔐</div>
        <h2 style="color:#fff;font-size:20px;margin-bottom:8px">Two-Factor Authentication</h2>
        <p style="color:#8892a4;font-size:14px;margin-bottom:24px">
          Enter the 6-digit code from your authenticator app for<br>
          <strong style="color:#e2e8f0">${_escapeHtml(email)}</strong>
        </p>
        <input id="totpCodeInput" type="text" inputmode="numeric" pattern="\\d{6}"
          maxlength="6" placeholder="000 000" autocomplete="one-time-code"
          style="width:100%;padding:14px;border-radius:8px;border:1px solid #2e3a54;
          background:#111520;color:#fff;font-size:24px;letter-spacing:8px;
          text-align:center;margin-bottom:16px;box-sizing:border-box"
          oninput="this.value=this.value.replace(/\\D/g,'').slice(0,6)">
        <div id="mfaError" style="color:#ef4444;font-size:13px;margin-bottom:12px;display:none"></div>
        <button id="submitMFABtn"
          style="width:100%;padding:12px;border-radius:8px;border:none;
          background:#4f8ef7;color:#fff;font-size:15px;font-weight:600;cursor:pointer;
          margin-bottom:12px">
          Verify Code
        </button>
        <button id="backToLoginBtn"
          style="background:none;border:none;color:#8892a4;font-size:13px;cursor:pointer;
          text-decoration:underline">
          ← Back to login
        </button>
      </div>`;
    const loginScreen = document.getElementById('loginScreen');
    if (loginScreen) loginScreen.appendChild(mfaPanel);
    else document.body.appendChild(mfaPanel);
  }

  mfaPanel.style.display = 'block';

  // Auto-focus the code input
  setTimeout(() => document.getElementById('totpCodeInput')?.focus(), 100);

  // Wire submit button
  const submitBtn = document.getElementById('submitMFABtn');
  const backBtn   = document.getElementById('backToLoginBtn');
  const codeInput = document.getElementById('totpCodeInput');
  const mfaErr    = document.getElementById('mfaError');

  // Auto-submit when 6 digits entered
  codeInput?.addEventListener('input', () => {
    if (codeInput.value.length === 6) submitBtn?.click();
  });

  submitBtn?.addEventListener('click', async () => {
    const code = codeInput?.value?.trim();
    if (!code || code.length !== 6) {
      if (mfaErr) { mfaErr.textContent = 'Enter the 6-digit code from your authenticator app.'; mfaErr.style.display = 'block'; }
      return;
    }

    submitBtn.textContent = 'Verifying…';
    submitBtn.disabled = true;
    if (mfaErr) mfaErr.style.display = 'none';

    try {
      const result = await fetch(`${window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com'}/api/auth/mfa/challenge`, {
        method:      'POST',
        credentials: 'include',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ mfa_session_token: mfaSessionToken, totp_code: code }),
      }).then(r => r.json());

      if (result?.user) {
        mfaPanel.style.display = 'none';
        await _finalizeLogin(result);
      } else {
        throw new Error(result?.error || 'Invalid code');
      }
    } catch (e) {
      submitBtn.textContent = 'Verify Code';
      submitBtn.disabled = false;
      if (codeInput) codeInput.value = '';
      if (mfaErr) { mfaErr.textContent = '❌ ' + (e.message || 'Invalid code. Try again.'); mfaErr.style.display = 'block'; }
    }
  });

  backBtn?.addEventListener('click', () => {
    mfaPanel.style.display = 'none';
    if (loginForm) loginForm.style.display = '';
  });
}

/* ══════════════════════════════════════════════════════════════════
   Finalize Login — called after password auth OR MFA challenge

   v6.1 FIX: Now writes JWT token to localStorage so all existing
   auth modules (auth-validator.js, ioc-intelligence.js, etc.)
   can read it via their getToken() calls.
════════════════════════════════════════════════════════════════ */
async function _finalizeLogin(data) {
  const displayUser    = data.user;
  const accessToken    = data.token    || data.access_token    || null;
  const refreshToken   = data.refreshToken || data.refresh_token || null;
  const expiresAt      = data.expiresAt || data.expires_at      || null;
  const expiresIn      = data.expiresIn || data.expires_in      || null;

  // ── STEP 1: Token storage — handled via PersistentAuth_onLogin in STEP 5 ──
  //
  // ROOT-CAUSE FIX v6.2: PersistentAuth_onLogin (auth-interceptor.js) is now
  // the SINGLE point of truth for all token storage + StateSync coordination.
  // It calls UnifiedTokenStore.save() internally, schedules proactive refresh,
  // and calls StateSync.markAuthReady(). We do NOT call UnifiedTokenStore.save()
  // directly here anymore to avoid bypassing the StateSync coordination step.
  //
  // Absolute fallback: only write direct if BOTH PersistentAuth_onLogin AND
  // UnifiedTokenStore are unavailable (e.g., interceptor script failed to load).
  if (typeof window.PersistentAuth_onLogin !== 'function' &&
      typeof window.UnifiedTokenStore?.save !== 'function' &&
      accessToken) {
    const TOKEN_KEYS = [
      'wadjet_access_token', 'we_access_token', 'tp_access_token',
    ];
    TOKEN_KEYS.forEach(k => {
      localStorage.setItem(k, accessToken);
      sessionStorage.setItem(k, accessToken);
    });
    if (refreshToken) {
      localStorage.setItem('wadjet_refresh_token', refreshToken);
      localStorage.setItem('we_refresh_token', refreshToken);
    }
    const exp = expiresAt ||
      (expiresIn ? new Date(Date.now() + Number(expiresIn) * 1000).toISOString()
                 : new Date(Date.now() + 900 * 1000).toISOString());
    localStorage.setItem('wadjet_token_expires_at', exp);
    if (displayUser) {
      const userJson = JSON.stringify(displayUser);
      localStorage.setItem('wadjet_user_profile', userJson);
      localStorage.setItem('we_user', userJson);
    }
  }

  // ── STEP 2: Sync with legacy TokenStore (api-client.js) ──────────
  if (accessToken && typeof window.TokenStore !== 'undefined') {
    window.TokenStore.set(accessToken, refreshToken, expiresAt || expiresIn);
    if (displayUser) window.TokenStore.setUser(displayUser);
  }

  // ── STEP 3: Save display data (SecureSession — no regression) ────
  if (typeof window.SecureSession?.save === 'function') {
    window.SecureSession.save(displayUser);
  }

  // ── STEP 4: Build global CURRENT_USER ────────────────────────────
  window.CURRENT_USER = {
    id:          displayUser.id,
    email:       displayUser.email,
    name:        displayUser.name       || displayUser.email,
    role:        displayUser.role       || 'ANALYST',
    tenant:      displayUser.tenant_id  || displayUser.tenant,
    tenant_id:   displayUser.tenant_id,
    tenant_name: displayUser.tenant_name || '',
    avatar:      displayUser.avatar     || (displayUser.name || 'U').slice(0, 2).toUpperCase(),
    permissions: displayUser.permissions || ['read'],
    mfa_enabled: displayUser.mfa_enabled || false,
    session_id:  displayUser.session_id  || null,
    is_super_admin: displayUser.role === 'SUPER_ADMIN' || displayUser.role === 'super_admin',
    _offline:    false,
  };

  // ── STEP 5: Notify auth-interceptor (handles StateSync + proactive refresh) ──
  // ROOT-CAUSE FIX v6.2: _finalizeLogin MUST call PersistentAuth_onLogin so that
  //  1. auth-interceptor schedules the proactive refresh
  //  2. StateSync.markAuthReady() is called (unblocks orchestrator + WS + RAKAY)
  //  3. Window.isAuthenticated() returns true immediately after login
  // Previously UnifiedTokenStore.save() was called directly — this bypassed the
  // StateSync coordination step, leaving all awaiting modules blocked.
  if (typeof window.PersistentAuth_onLogin === 'function') {
    window.PersistentAuth_onLogin(
      displayUser,
      accessToken,
      refreshToken,
      expiresAt || expiresIn,
      false,
    );
  }

  // ── STEP 6: Dispatch DOM events ──────────────────────────────────
  window.dispatchEvent(new CustomEvent('auth:login',    { detail: window.CURRENT_USER }));
  // Also dispatch auth:restored so _onAuthReady() in ai-orchestrator fires
  // (it listens to BOTH auth:login AND auth:restored)
  window.dispatchEvent(new CustomEvent('auth:restored', { detail: window.CURRENT_USER }));

  if (typeof showToast === 'function') {
    showToast(`✅ Welcome, ${window.CURRENT_USER.name}`, 'success');
  }

  // ── STEP 7: Animate into app ──────────────────────────────────────
  _enterApp();
}

/* ══════════════════════════════════════════════════════════════════
   UI Helpers
════════════════════════════════════════════════════════════════ */
function _enterApp() {
  const loginScreen = document.getElementById('loginScreen');
  if (loginScreen) {
    loginScreen.style.opacity    = '0';
    loginScreen.style.transition = 'opacity 0.4s ease';
    setTimeout(() => {
      loginScreen.style.display = 'none';
      const mainApp = document.getElementById('mainApp');
      if (mainApp) mainApp.style.display = 'flex';
      if (typeof initApp === 'function') initApp();
    }, 400);
  }
}

function _showLoginError(el, msg) {
  if (!el) return;
  el.textContent  = msg;
  el.style.display = 'block';
}

function _clearLoginError(el) {
  if (!el) return;
  el.textContent  = '';
  el.style.display = 'none';
}

function _setBtnLoading(btn, loading) {
  if (!btn) return;
  if (loading) {
    btn._originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in…';
    btn.disabled  = true;
  } else {
    btn.innerHTML = btn._originalText || 'Sign In';
    btn.disabled  = false;
  }
}

function _mapLoginError(msg) {
  const m = (msg || '').toLowerCase();
  if (m.includes('invalid email') || m.includes('invalid credentials') || m.includes('wrong password') || m.includes('invalid login') || m.includes('invalid email or password'))
    return '❌ Invalid email or password. Please try again.';
  if (m.includes('email not confirmed') || m.includes('not confirmed') || m.includes('email_not_confirmed'))
    return '⚠️ Email not confirmed. Please check your inbox and click the confirmation link before logging in.';
  if (m.includes('suspended') || m.includes('inactive'))
    return '⚠️ This account has been suspended. Contact your administrator.';
  if (m.includes('tenant'))
    return '⚠️ You do not have access to this workspace.';
  if (m.includes('profile') || m.includes('not found'))
    return '⚠️ User profile not found. Contact your administrator to set up your account.';
  if (m.includes('network') || m.includes('failed to fetch') || m.includes('err_connection') || m.includes('load failed'))
    return '🔌 Cannot reach the authentication server. Check your network and try again.';
  if (m.includes('timeout') || m.includes('timed out'))
    return '⏱ Request timed out. The server may be starting up — try again in 30 seconds.';
  if (m.includes('api client not loaded'))
    return '🔌 Cannot reach the server. Check your network connection and refresh the page.';
  // RC-BACKEND-1: Supabase AbortError → backend returns 503 AUTH_SERVICE_UNAVAILABLE
  if (m.includes('temporarily unavailable') || m.includes('auth_service_unavailable') ||
      m.includes('aborted') || m.includes('503'))
    return '⏱ Authentication service temporarily unavailable. Please try again in a few seconds.';
  return `❌ ${msg}`;
}

function _escapeHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
