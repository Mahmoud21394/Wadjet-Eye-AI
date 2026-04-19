const fs = require('fs');
const results = [];
let pass = 0, fail = 0;

function check(id, label, cond) {
  const ok = !!cond;
  results.push({ id, label, ok });
  if (ok) pass++; else fail++;
}

const server     = fs.readFileSync('backend/server.js', 'utf8');
const authRoute  = fs.readFileSync('backend/routes/auth.js', 'utf8');
const authMW     = fs.readFileSync('backend/middleware/auth.js', 'utf8');
const interceptor= fs.readFileSync('js/auth-interceptor.js', 'utf8');
const apiClient  = (() => { try { return fs.readFileSync('js/api-client/index.js', 'utf8'); } catch { return ''; } })();
const loginPatch = fs.readFileSync('js/login-secure-patch.js', 'utf8');
const loginV20   = fs.readFileSync('js/login-v20.js', 'utf8');
const mainJs     = fs.readFileSync('js/main.js', 'utf8');
// The OLD top-level api-client.js (the one referenced in screenshots)
const oldApiClient = fs.readFileSync('js/api-client.js', 'utf8');

// ── BACKEND ──────────────────────────────────────────────────────────────────
const authIdx  = server.indexOf("app.use('/api/auth'");
const vtIdx    = server.indexOf('app.use(verifyToken)');
check('BE-01', 'auth routes before verifyToken',        authIdx > -1 && vtIdx > -1 && authIdx < vtIdx);
check('BE-02', 'refresh route has no inline verifyToken', !authRoute.includes("router.post('/refresh', verifyToken"));
check('BE-03', 'login route has no inline verifyToken',   !authRoute.includes("router.post('/login', verifyToken"));
check('BE-04', 'logout route is public (no verifyToken)', authRoute.includes("router.post('/logout',") && !authRoute.includes("router.post('/logout', verifyToken"));
check('BE-05', 'hard-reset: signOut fire-and-forget (NOT awaited — prevents AbortError)',
  authRoute.includes('signOut().catch(') &&
  !authRoute.includes('await supabase.auth.signOut()'));
check('BE-06', 'Supabase login has 20s timeout',  authRoute.includes('20_000'));
check('BE-07', 'admin.createSession has 6s timeout', authRoute.includes('ADMIN_SESSION_TIMEOUT_MS') || authRoute.includes('6_000'));
check('BE-08', 'verifyToken has 8s timeout',      authMW.includes('VERIFY_TIMEOUT_MS') || authMW.includes('8_000'));
const healthIdx = server.indexOf("app.get('/health'");
check('BE-09', '/health is public (before verifyToken)', healthIdx > -1 && healthIdx < vtIdx);
check('BE-10', '/api/ping exists and is public',   server.includes("app.get('/api/ping'") && server.indexOf("app.get('/api/ping'") < vtIdx);

// RC-BACKEND-1: AbortError explicitly caught and returned as 503 (not thrown as 500/401)
// v6.1 update: now uses isAbortError() utility function instead of inline name check
check('BE-11-CRIT', 'RC-BACKEND-1: AbortError caught in login → 503 (not re-thrown)',
  (authRoute.includes("supabaseErr.name === 'AbortError'") ||
   authRoute.includes("supabaseErr.message?.includes('This operation was aborted')") ||
   authRoute.includes('isAbortError(supabaseErr)') ||
   authRoute.includes('isAbortError(loginError)')) &&
  authRoute.includes('AUTH_SERVICE_UNAVAILABLE'));
check('BE-12', 'login handler returns 503 for aborted/timeout Supabase calls',
  authRoute.includes("res.status(503).json") && authRoute.includes('AUTH_SERVICE_UNAVAILABLE'));

// BE-13: logActivity non-blocking after login failure (fire-and-forget)
// Line should read: logActivity(null, null, 'LOGIN_FAILED', ... .catch(() => {})
// and should NOT be: await logActivity(null, null, 'LOGIN_FAILED', ...
check('BE-13', 'loginError logActivity is fire-and-forget (non-blocking)',
  (() => {
    const lines = authRoute.split('\n');
    // Find the first logActivity(null, null, 'LOGIN_FAILED' call
    const idx = lines.findIndex(l => l.includes("logActivity(null, null, 'LOGIN_FAILED'"));
    if (idx < 0) return false;
    const line = lines[idx].trim();
    // Must NOT have leading 'await'
    return !line.startsWith('await ');
  })());

// BE-14: email-not-confirmed error mapped explicitly
check('BE-14', 'login handler maps email-not-confirmed to specific error code',
  authRoute.includes('EMAIL_NOT_CONFIRMED') && authRoute.includes('email not confirmed'));

// BE-15: diagnostics endpoint exists
check('BE-15', 'GET /api/auth/diagnostics endpoint exists',
  authRoute.includes("router.get('/diagnostics'"));

// BE-16 NEW: supabaseAuth imported in auth.js (dedicated auth client)
check('BE-16-CRIT', 'CRITICAL: auth.js imports supabaseAuth (dedicated auth client)',
  authRoute.includes('supabaseAuth') &&
  authRoute.includes("require('../config/supabase')") &&
  /\{\s*supabase\s*,\s*supabaseAuth/.test(authRoute) || /\{\s*supabaseAuth/.test(authRoute));

// BE-17 NEW: signInWithPassword uses supabaseAuth (not supabase DB client)
check('BE-17-CRIT', 'CRITICAL: signInWithPassword uses supabaseAuth (not supabase DB client)',
  authRoute.includes('supabaseAuth.auth.signInWithPassword') &&
  !authRoute.includes('supabase.auth.signInWithPassword'));

// BE-18 NEW: signOut uses supabaseAuth
check('BE-18-CRIT', 'CRITICAL: signOut uses supabaseAuth (not supabase DB client)',
  authRoute.includes('supabaseAuth.auth.signOut') &&
  !authRoute.includes('supabase.auth.signOut'));

// BE-19 NEW: loginError checked for AbortError BEFORE generic 401 mapping
check('BE-19-CRIT', 'CRITICAL: AbortError in loginError field detected → 503 (not 401)',
  authRoute.includes('isAbortError(loginError)') &&
  authRoute.includes("failure_reason: `AbortError:"));

// BE-20 NEW: middleware auth.js uses supabaseAuth for getUser
check('BE-20-CRIT', 'CRITICAL: verifyToken uses supabaseAuth.auth.getUser (not supabase)',
  authMW.includes('supabaseAuth.auth.getUser') &&
  !authMW.includes('supabase.auth.getUser'));

// BE-21 NEW: structured logging in login handler
check('BE-21', 'Structured logging in login handler (auth:login:start/result/abort/ok)',
  authRoute.includes('[auth:login:start]') &&
  authRoute.includes('[auth:login:result]') &&
  authRoute.includes('[auth:login:abort]') &&
  authRoute.includes('[auth:login:ok]'));

// ── FRONTEND: api-client.js (top-level) ──────────────────────────────────────
check('FE-01', 'api-client.js has public auth path list (_isPublicAuthPath)',
  oldApiClient.includes('_isPublicAuthPath') || apiClient.includes('skipAuth: true'));
check('FE-02', 'api-client _doRefresh singleton lock',
  oldApiClient.includes('_refreshing') && oldApiClient.includes('if (_refreshing) return _refreshPromise'));
check('FE-03', 'api-client TokenStore reads sessionStorage', oldApiClient.includes('sessionStorage.getItem'));
check('FE-04', 'api-client TokenStore reads localStorage for refresh', oldApiClient.includes('localStorage.getItem'));

// CRITICAL: api-client must read a correct token key
const apiTokenKey = oldApiClient.includes("'we_access_token'") || oldApiClient.includes("wadjet_access_token");
check('FE-05-CRIT', 'CRITICAL: api-client reads correct token keys (we_access_token or wadjet_access_token)',  apiTokenKey);

// CRITICAL: interceptor refresh token stored in localStorage (not sessionStorage)
const authStoreRefreshInLS = interceptor.includes("localStorage.setItem(UNIFIED_KEYS.REFRESH");
check('FE-06-CRIT', 'CRITICAL: auth-interceptor refresh in localStorage (survives reload)', authStoreRefreshInLS);

check('FE-07', 'UnifiedTokenStore exposed globally', interceptor.includes('window.UnifiedTokenStore'));

// ── FRONTEND: auth-interceptor.js ─────────────────────────────────────────────
check('FE-08', 'interceptor writes refresh token to localStorage', interceptor.includes("localStorage.setItem(UNIFIED_KEYS.REFRESH"));
check('FE-09', 'interceptor single refresh lock',       interceptor.includes('_refreshLock') && interceptor.includes('if (_refreshLock && _refreshPromise)'));
check('FE-10', 'authFetch skips auth headers for /auth routes', interceptor.includes('AUTH_BYPASS') && interceptor.includes('isAuthRoute'));
check('FE-11', 'both token-refresh events dispatched',  interceptor.includes("'auth:token-refreshed'") && interceptor.includes("'auth:token_refreshed'"));
check('FE-12', 'WS.updateAuth called after refresh',    interceptor.includes('WS?.updateAuth'));
const cookieParts = interceptor.split('_refreshFromCookie');
const cookieBody  = cookieParts[3] || '';
check('FE-13', 'cookie-refresh success dispatches token events', cookieBody.includes("'auth:token-refreshed'"));
check('FE-14', 'cookie-refresh updates StateSync',      cookieBody.includes('updateAuthState'));
check('FE-15', 'silentRefresh releases lock in finally', interceptor.includes('_refreshLock    = false') || interceptor.includes('_refreshLock = false'));
check('FE-16', 'proactive refresh at 80% TTL',          interceptor.includes('0.80') || interceptor.includes('* 0.8'));
check('FE-17', 'visibilitychange triggers silentRefresh',interceptor.includes('visibilitychange') && interceptor.includes('silentRefresh'));
check('FE-18', 'online listener triggers silentRefresh', interceptor.includes("addEventListener('online'"));
check('FE-19', 'auth:expired listener has debounce',    interceptor.includes('_expiredHandled') && interceptor.includes('setTimeout'));
check('FE-20', 'hasSession checks both tokens',         interceptor.includes('getRefresh() || this.getToken()'));

// ── FRONTEND: login-secure-patch.js ───────────────────────────────────────────
check('FE-21', '_finalizeLogin calls PersistentAuth_onLogin', loginPatch.includes('PersistentAuth_onLogin'));
check('FE-22', '_finalizeLogin dispatches auth:login',   loginPatch.includes("'auth:login'"));
check('FE-23', '_finalizeLogin dispatches auth:restored',loginPatch.includes("'auth:restored'"));
check('FE-24', 'secureDoLogin clears tokens at start',   loginPatch.includes('UnifiedTokenStore.clear()'));

// CRITICAL: no stale wadjet_token key read outside comments
const oldApiLines = oldApiClient.split('\n');
const hasLiveWadjetToken = oldApiLines.some(line => {
  const trimmed = line.trim();
  return !trimmed.startsWith('//') && trimmed.includes("localStorage.getItem('wadjet_token'");
});
check('FE-25-CRIT', 'CRITICAL: no live localStorage.getItem(wadjet_token) in api-client (comment-only OK)',
  !hasLiveWadjetToken);

// login-v20.js
check('FE-26', 'login-v20 wraps doLogin without replacing auth logic', loginV20.includes('origDoLogin') && loginV20.includes('window.doLogin'));

// RC-1/2/3 fixes in old api-client.js
check('FE-27-CRIT', 'RC-1 FIX: api-client.js pre-flight refresh skipped for auth routes',
  oldApiClient.includes('_isPublicAuthPath') &&
  oldApiClient.includes('!isPublicAuth && !TokenStore.isValid()'));
check('FE-28-CRIT', 'RC-2 FIX: api-client.js attaches Authorization header before first fetch',
  oldApiClient.includes('!isPublicAuth && token') &&
  oldApiClient.includes("headers['Authorization'] = `Bearer ${token}`"));
check('FE-29-CRIT', 'RC-3 FIX: api-client.js 401 handler bypassed for public auth paths',
  oldApiClient.includes('response.status === 401 && !isPublicAuth'));
check('FE-30', 'api-client.js _AUTH_PUBLIC_PATHS includes login/refresh/logout',
  oldApiClient.includes("'/auth/login'") &&
  oldApiClient.includes("'/auth/refresh'") &&
  oldApiClient.includes("'/auth/logout'"));

// login-secure-patch.js additional checks
check('FE-31-CRIT', 'secureDoLogin UnifiedTokenStore.clear scope fixed (typeof guard)',
  loginPatch.includes("typeof window.UnifiedTokenStore !== 'undefined'") &&
  loginPatch.includes('window.UnifiedTokenStore.clear()'));
check('FE-32', '_mapLoginError handles temporarily unavailable / 503',
  loginPatch.includes('temporarily unavailable') && loginPatch.includes('auth_service_unavailable'));
check('FE-33', 'secureDoLogin auto-retries on 503 transient error',
  loginPatch.includes('isTransient') && loginPatch.includes('secureDoLogin._retrying') && loginPatch.includes('setTimeout'));

// main.js security checks - check non-comment lines only
// Strip both // and /* */ block comments using a simple approach:
// Remove all content between /* and */ and all // to end-of-line
const mainJsNoComments = mainJs
  .replace(/\/\*[\s\S]*?\*\//gm, '')  // remove block comments
  .replace(/\/\/.*/g, '');             // remove line comments
check('FE-34-CRIT', 'CRITICAL: _EMERGENCY_ACCOUNTS removed from main.js (code, not comments)',
  !mainJsNoComments.includes('_EMERGENCY_ACCOUNTS') && !mainJsNoComments.includes('offline_emergency_'));
check('FE-35', 'main.js doLogin delegates to secureDoLogin when available',
  mainJs.includes('secureDoLogin') && mainJs.includes('return secureDoLogin()'));

// email-not-confirmed handled in frontend
check('FE-36', '_mapLoginError handles email-not-confirmed',
  loginPatch.includes('email not confirmed') || loginPatch.includes('not confirmed'));

// ── PRINT ─────────────────────────────────────────────────────────────────────
console.log('\n══════ AUTH FORENSIC AUDIT RESULTS ══════');
results.forEach(r => {
  const icon = r.ok ? '✅' : '❌';
  console.log(`  ${icon} ${r.id}: ${r.label}`);
});
console.log(`\n  TOTAL: ${pass}/${pass+fail} checks passed`);
if (fail > 0) {
  console.log('\n  ── FAILURES (need fixes) ──');
  results.filter(r=>!r.ok).forEach(r => console.log(`     ❌ ${r.id}: ${r.label}`));
}
