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

// ROOT-CAUSE FIX v8.3: Override doLogin IMMEDIATELY at script-parse time.
// Previously, the override ran inside DOMContentLoaded which fires ONCE and
// only if the listener is registered BEFORE the event fires.  When this script
// is loaded late (after DOMContentLoaded has already fired), the listener never
// ran and window.doLogin remained the insecure main.js version.
// Also: login-v20.js _patchLoginBtn() wraps window.doLogin in a setInterval —
// if it captures the old doLogin before our DOMContentLoaded runs, the v20
// wrapper calls the wrong function forever.
// Fix: assign immediately so both early and late callers always get secureDoLogin.
window.doLogin = secureDoLogin;

// Also assign on DOMContentLoaded in case a very early assignment was overwritten
// by a subsequent script (belt + suspenders).
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function () {
    window.doLogin = secureDoLogin;
  });
}

/* ══════════════════════════════════════════════════════════════════
   SECURE LOGIN — server-only authentication
   No client-side fallback. No emergency accounts in browser.
   If the server is down, the user cannot log in. Full stop.
════════════════════════════════════════════════════════════════ */
async function secureDoLogin() {
  // ROOT-CAUSE FIX v8.5: Reset ALL backoff/lock state BEFORE clearing tokens.
  // Order matters: if PersistentAuth_onLogin is called after a successful login it
  // resets the rate-limit guards — but here, at login START, we also need to clear
  // those guards so the very first silentRefresh() attempt after login isn't blocked
  // by backoff state left from the pre-login _syncStoresOnLoad() cookie-probe.
  if (typeof window.PersistentAuth_onLogin === 'function') {
    // Temporarily reset guards by calling with empty args won't work, so we call
    // the interceptor's public clear helpers directly if available.
    if (window.__wadjetAuthInterceptorLoaded) {
      // These session-storage keys cause the "Cookie refresh in backoff — Xs remaining"
      // log that blocks /api/auth/refresh-from-cookie after a fresh login on a new page load.
      try {
        sessionStorage.removeItem('wadjet_cookie_refresh_failed_at');
        sessionStorage.removeItem('wadjet_cookie_refresh_backoff');
        sessionStorage.removeItem('wadjet_cookie_refresh_blocked_until');
      } catch (_) {}
      // Also clear the global refresh lock in case it was left set by a timed-out
      // pre-login _syncStoresOnLoad attempt.
      window.__wadjetRefreshLock = false;
    }
  }
  // Clear any stale tokens before attempting login.
  // Guard prevents ReferenceError when auth-interceptor.js is not yet loaded.
  if (typeof window.UnifiedTokenStore !== 'undefined') {
    window.UnifiedTokenStore.clear();
  }
  const emailEl  = document.getElementById('loginEmail');
  const passEl   = document.getElementById('loginPassword');
  const tenantEl = document.getElementById('loginTenant');
  const errEl    = document.getElementById('loginError');
  // ROOT-CAUSE FIX v8.4: login-v20.js replaces the DOM with a new button id=loginBtn.
  // Fall back through multiple selectors so we always find the visible button.
  const btn      = document.getElementById('loginBtn') ||
                   document.querySelector('.lv20-btn') ||
                   document.querySelector('.login-btn');

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

  // ── P3: Warn if backend did not return a refresh token ─────────────
  // Root cause of Issue 3: /api/auth/login response body doesn't include
  // refreshToken / refresh_token, so storage is empty and /api/auth/refresh
  // later returns 401 "Invalid or expired refresh token".
  if (!refreshToken) {
    console.warn(
      '[SecureLogin] ⚠️ Backend login response did NOT include a refresh token. ' +
      'Silent refresh will fail. Check that /api/auth/login returns ' +
      '{ token, refreshToken, expiresIn } and that CORS allows credentials.',
    );
  }

  // ── STEP 1 (P1 — PRIORITY FIX): Write tokens to ALL storage layers ──
  // ROOT-CAUSE FIX v8.0: Tokens MUST be committed to localStorage before
  // ANY async post-login code runs.  Previously this was deferred to STEP 5
  // (PersistentAuth_onLogin), but event listeners on 'auth:login' / 'auth:restored'
  // (ioc-intelligence.js, campaign-correlation.js, etc.) fire SYNCHRONOUSLY
  // during window.dispatchEvent(), which is still inside _finalizeLogin.
  // Those listeners immediately call authFetch() / renderIOCDatabase() / etc.
  // The token had not yet been written → every request arrived with no Bearer.
  //
  // Fix: write tokens eagerly here (STEP 1) AND keep the PersistentAuth_onLogin
  // call in STEP 5 for StateSync coordination and proactive-refresh scheduling.
  if (accessToken) {
    const TOKEN_KEYS = [
      'wadjet_access_token', 'we_access_token', 'tp_access_token',
    ];
    TOKEN_KEYS.forEach(k => {
      localStorage.setItem(k, accessToken);
      sessionStorage.setItem(k, accessToken);
    });
  }
  if (refreshToken) {
    localStorage.setItem('wadjet_refresh_token',   refreshToken);  // UNIFIED_KEYS.REFRESH
    localStorage.setItem('we_refresh_token',        refreshToken);  // UNIFIED_KEYS.LEGACY_REFRESH
    // ROOT-CAUSE FIX v9.0: Removed stale key 'wadjet_unified_refresh' — that key
    // does not exist in UNIFIED_KEYS; the correct primary key is 'wadjet_refresh_token'.
    // Writing an unknown key meant UnifiedTokenStore.getRefresh() could not find the
    // token on the next page load, causing needless cookie-probe → 400 NO_COOKIE storms.
  }
  if (accessToken) {
    // Compute and persist expiry so isExpired() works immediately
    const expIso = expiresAt ||
      (expiresIn ? new Date(Date.now() + Number(expiresIn) * 1000).toISOString()
                 : new Date(Date.now() + 900_000).toISOString());
    localStorage.setItem('wadjet_token_expires_at', expIso);  // UNIFIED_KEYS.EXPIRES
    // ROOT-CAUSE FIX v8.2: UNIFIED_KEYS.LEGACY_EXP = 'we_token_expires' (no _at suffix).
    // api-client.js TokenStore._EXP_KEY = 'we_token_expires'.
    // Previous code wrote 'we_token_expires_at' which neither reader looked up,
    // so TokenStore.isValid() always saw expiry=0 and api-client.js called
    // refreshAccessToken() on every request → 429 storm.
    localStorage.setItem('we_token_expires',
      String(new Date(expIso).getTime()));                     // UNIFIED_KEYS.LEGACY_EXP
    sessionStorage.setItem('we_token_expires',
      String(new Date(expIso).getTime()));
    // Also write the _at variant for any module that may still read it
    localStorage.setItem('we_token_expires_at',
      String(new Date(expIso).getTime()));
    sessionStorage.setItem('we_token_expires_at',
      String(new Date(expIso).getTime()));
  }
  if (displayUser) {
    const userJson = JSON.stringify(displayUser);
    localStorage.setItem('wadjet_user_profile', userJson);  // UNIFIED_KEYS.USER
    localStorage.setItem('we_user',             userJson);  // UNIFIED_KEYS.LEGACY_USER
    sessionStorage.setItem('we_user',           userJson);
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

  // ── STEP 5: Notify auth-interceptor (StateSync + proactive refresh) ──
  // This must come AFTER the eager writes in STEP 1 (above) so that
  // PersistentAuth_onLogin finds the tokens already in localStorage when it
  // calls UnifiedTokenStore.save() — preventing a double-write that would
  // be harmless but could race with an in-flight silent refresh.
  if (typeof window.PersistentAuth_onLogin === 'function') {
    window.PersistentAuth_onLogin(
      displayUser,
      accessToken,
      refreshToken,
      expiresAt || expiresIn,
      false,
    );
  } else if (typeof window.UnifiedTokenStore?.save === 'function') {
    // auth-interceptor not loaded — call UnifiedTokenStore directly
    window.UnifiedTokenStore.save({
      token: accessToken, refreshToken,
      expiresAt: expiresAt || expiresIn, user: displayUser,
    });
  }

  // ── STEP 5b: Token readback verification ─────────────────────────────────
  // ROOT-CAUSE FIX v9.0: Verify that the access token is actually readable from
  // localStorage before entering the app.  On some browsers (private mode / quota
  // exceeded / Safari ITP), localStorage.setItem() silently fails.  Without this
  // check the user sees the main app but every API call returns 401 because all
  // getToken() implementations return null — an extremely confusing UX failure.
  //
  // If the token is NOT readable we abort here (re-show error, don't enter app),
  // giving the user a clear message rather than a flood of 401 errors.
  if (accessToken) {
    const stored = localStorage.getItem('wadjet_access_token')
                || localStorage.getItem('we_access_token')
                || sessionStorage.getItem('we_access_token');
    if (!stored) {
      console.error('[SecureLogin] ❌ Token write to localStorage FAILED — storage may be full or blocked.');
      // Surface to the user
      const errEl2 = document.getElementById('loginError');
      _showLoginError(errEl2,
        '⚠️ Your browser blocked token storage (private/incognito mode or full storage). ' +
        'Please allow localStorage or switch to a regular browser window.'
      );
      // Re-show login screen so the user can act
      const loginScreen = document.getElementById('loginScreen');
      if (loginScreen) {
        loginScreen.style.display  = 'flex';
        loginScreen.style.opacity  = '1';
      }
      // Reset the button so the user can retry
      const btn2 = document.getElementById('loginBtn') ||
                   document.querySelector('.lv20-btn') ||
                   document.querySelector('.login-btn');
      _setBtnLoading(btn2, false);
      return; // abort — do NOT enter app with a missing token
    }
  }

  // ── STEP 6 (P2 — PRIORITY FIX): Gate all post-login init behind authReady ──
  // Problem: auth:login / auth:restored listeners (ioc-intelligence, campaign-
  // correlation, auth-validator) fire synchronously inside dispatchEvent() and
  // immediately call API endpoints.  StateSync.authReady is marked true by
  // PersistentAuth_onLogin in STEP 5, but every module that reads tokens via
  // getToken() / authFetch() now gets them from localStorage (STEP 1 above).
  // The remaining race is for modules that call their own async init chains
  // before StateSync settles.  We stamp _wadjetAuthReadyAt here so any module
  // can check window._wadjetAuthReadyAt > 0 instead of racing.
  window._wadjetLastLoginAt  = Date.now();
  window._wadjetAuthReadyAt  = Date.now();  // P2 gate — modules check this

  // ROOT-CAUSE FIX v9.0: DEFER auth:login / auth:restored until AFTER the app
  // UI is visible (i.e. after _enterApp + initApp() complete).
  //
  // PROBLEM (observed as wave of 401s immediately after login):
  //   window.dispatchEvent('auth:login') fires synchronously, which means every
  //   listener (ioc-intelligence, campaign-correlation, live-detections, etc.)
  //   executes INSIDE this dispatchEvent() call — before _enterApp() has run,
  //   before the DOM panels are rendered, and before initApp() has initialised
  //   any data-loading state machines.
  //   Those listeners fire authFetch() calls; some of them complete before the
  //   first proactive-refresh timer fires and, if the token expiry window is
  //   tight, they get 401 → silentRefresh storm.
  //
  // FIX: Move both dispatches to a deferred callback passed into _enterApp().
  //   _enterApp() calls initApp() inside its 400ms opacity transition; we
  //   dispatch AFTER that settles (via setTimeout 0 inside the callback).
  //   This ensures:
  //     1. The Bearer token is firmly committed to localStorage (STEP 1 ✓)
  //     2. StateSync.authReady is resolved (STEP 5 via PersistentAuth_onLogin ✓)
  //     3. The proactive-refresh timer is scheduled (STEP 5 ✓)
  //     4. initApp() DOM setup is done before any module tries to render
  //     5. All listeners see a stable, ready application
  //
  // Welcome toast is also deferred by the same tick so it appears after the
  // UI transition rather than on the login screen.
  _enterApp(function _postInitDispatch() {
    // Dispatch events in next tick so any synchronous code in _enterApp / initApp
    // completes before listeners fire their first API requests.
    setTimeout(function() {
      window.dispatchEvent(new CustomEvent('auth:login',    { detail: window.CURRENT_USER }));
      window.dispatchEvent(new CustomEvent('auth:restored', { detail: window.CURRENT_USER }));
      if (typeof showToast === 'function') {
        showToast(`✅ Welcome, ${window.CURRENT_USER.name}`, 'success');
      }
    }, 0);
  });
}

/* ══════════════════════════════════════════════════════════════════
   UI Helpers
════════════════════════════════════════════════════════════════ */
function _enterApp(onReady) {
  const loginScreen = document.getElementById('loginScreen');
  if (loginScreen) {
    loginScreen.style.opacity    = '0';
    loginScreen.style.transition = 'opacity 0.4s ease';
    setTimeout(() => {
      loginScreen.style.display = 'none';
      const mainApp = document.getElementById('mainApp');
      if (mainApp) mainApp.style.display = 'flex';
      if (typeof initApp === 'function') initApp();
      // ROOT-CAUSE FIX v9.0: invoke the optional post-init callback AFTER initApp()
      // so that auth:login / auth:restored are dispatched once the app is ready.
      if (typeof onReady === 'function') onReady();
    }, 400);
  } else {
    // Fallback: no loginScreen element (unit tests / minimal pages)
    const mainApp = document.getElementById('mainApp');
    if (mainApp) mainApp.style.display = 'flex';
    if (typeof initApp === 'function') initApp();
    if (typeof onReady === 'function') onReady();
  }
}

function _showLoginError(el, msg) {
  // Always update the legacy loginError div (hidden but observed by v20 MutationObserver)
  if (el) {
    el.textContent   = msg;
    el.style.display = 'block';
  }
  // ROOT-CAUSE FIX v8.4: Also write directly to the v20 error box so the error
  // is visible even when the MutationObserver hasn't fired yet.
  const lv20Err  = document.getElementById('lv20Error');
  const lv20Tx   = document.getElementById('lv20ErrorText');
  if (lv20Err && lv20Tx) {
    lv20Tx.textContent  = msg.replace(/^[⚠️❌⏳🔌⏱]\s*/u, '');
    lv20Err.style.display = 'flex';
  }
}

function _clearLoginError(el) {
  if (el) {
    el.textContent   = '';
    el.style.display = 'none';
  }
  // Also clear the v20 error box
  const lv20Err = document.getElementById('lv20Error');
  if (lv20Err) lv20Err.style.display = 'none';
}

function _setBtnLoading(btn, loading) {
  if (!btn) return;
  if (loading) {
    btn._originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in…';
    btn.disabled  = true;
    btn.classList.add('loading');
  } else {
    // ROOT-CAUSE FIX v8.4: Restore the correct label for both login-v20 and
    // the legacy login button.  login-v20 uses "Authenticate Securely" while
    // the original uses "Sign In".  Prefer the stored original if available.
    const isV20 = btn.classList.contains('lv20-btn') || btn.id === 'loginBtn';
    btn.innerHTML = btn._originalText ||
      (isV20 ? '<i class="fas fa-eye"></i> Authenticate Securely' : 'Sign In');
    btn.disabled  = false;
    btn.classList.remove('loading');
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
