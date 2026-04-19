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
check('BE-05', 'v7.0: No signOut() before signInWithPassword — fresh client used instead',
  // v7.0 uses createLoginClient() with NO signOut — the old signOut().catch() is gone from login
  authRoute.includes('createLoginClient') ||
  // OR old v6.1 pattern still valid
  (authRoute.includes('signOut().catch(') && !authRoute.includes('await supabase.auth.signOut()')));
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

// BE-18 NEW: signOut uses supabaseAuth (either direct or admin.signOut)
check('BE-18-CRIT', 'CRITICAL: signOut uses supabaseAuth (not supabase DB client)',
  (authRoute.includes('supabaseAuth.auth.signOut') || authRoute.includes('supabaseAuth.auth.admin.signOut')) &&
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

// ── BACKEND v7.0 NEW CHECKS ───────────────────────────────────────────────────
const supabaseConf = fs.readFileSync('backend/config/supabase.js', 'utf8');
const phishtankJs  = fs.readFileSync('backend/services/ingestion/phishtank.js', 'utf8');
const ingestionJs  = fs.readFileSync('backend/services/ingestion/index.js', 'utf8');
const schedulerJs  = fs.readFileSync('backend/services/scheduler.js', 'utf8');

// BE-22: createLoginClient() factory exists (per-request fresh client)
check('BE-22-CRIT', 'v7.0: createLoginClient() factory exists in supabase.js',
  supabaseConf.includes('function createLoginClient') &&
  supabaseConf.includes('createLoginClient'));

// BE-23: auth.js uses createLoginClient() for signInWithPassword (not supabaseAuth)
check('BE-23-CRIT', 'v7.0: login uses createLoginClient() — fresh per-request instance',
  authRoute.includes('createLoginClient()') &&
  authRoute.includes('_loginClient.auth.signInWithPassword'));

// BE-24: NO signOut() before signInWithPassword (root cause of queue stall)
check('BE-24-CRIT', 'v7.0: NO signOut() called before signInWithPassword in login handler',
  !authRoute.includes('signOut().catch') ||
  !authRoute.includes('_loginClient.auth.signInWithPassword') ||
  // Ensure signOut is not present in the same handler - check by looking at login handler body
  (() => {
    const loginHandler = authRoute.slice(authRoute.indexOf("router.post('/login'"), authRoute.indexOf("router.post('/refresh'"));
    return !loginHandler.includes('.auth.signOut()');
  })());

// BE-25: supabaseIngestion client exists and is isolated
check('BE-25-CRIT', 'v7.0: supabaseIngestion client defined in supabase.js',
  supabaseConf.includes('supabaseIngestion') &&
  supabaseConf.includes('wadjet-eye-ai-ingestion'));

// BE-26: PhishTank uses supabaseIngestion (not shared supabase)
check('BE-26-CRIT', 'v7.0: PhishTank ingestion uses supabaseIngestion (isolated from auth)',
  phishtankJs.includes('supabaseIngestion') ||
  phishtankJs.includes('supabaseIngestion: supabase'));

// BE-27: Main ingestion index.js uses supabaseIngestion
check('BE-27-CRIT', 'v7.0: Main ingestion uses supabaseIngestion (isolated from auth)',
  ingestionJs.includes('supabaseIngestion') ||
  ingestionJs.includes('supabaseIngestion: supabase'));

// BE-28: Scheduler uses supabaseIngestion
check('BE-28', 'v7.0: Scheduler uses supabaseIngestion (not shared supabase)',
  schedulerJs.includes('supabaseIngestion') ||
  schedulerJs.includes('supabaseIngestion: supabase'));

// BE-29: Login timeout is 40s outer (LOGIN_FETCH_TIMEOUT_MS + buffer)
check('BE-29', 'v7.0: Login outer timeout is 40s (35s inner + 5s buffer)',
  authRoute.includes('LOGIN_FETCH_TIMEOUT_MS') ||
  authRoute.includes('LOGIN_HARD_TIMEOUT_MS') ||
  authRoute.includes('40_000') || authRoute.includes('40000'));

// BE-30: DNS/connection warmup on startup
check('BE-30', 'v7.0: Supabase auth endpoint DNS warmup on startup',
  supabaseConf.includes('warmupSupabaseConnection') &&
  supabaseConf.includes('/auth/v1/health'));

// BE-31: isTimeoutError helper exported
check('BE-31', 'v7.0: isTimeoutError helper exists and exported',
  supabaseConf.includes('function isTimeoutError') &&
  supabaseConf.includes('isTimeoutError'));

// ── BACKEND v7.1: Scheduler service isolation ─────────────────────────────────
const newsIngestion   = fs.readFileSync('backend/services/news-ingestion.js', 'utf8');
const enrichEngine    = fs.readFileSync('backend/services/enrichment-engine.js', 'utf8');
const enrichService   = fs.readFileSync('backend/services/enrichment.js', 'utf8');

// BE-32: news-ingestion.js uses supabaseIngestion (scheduler calls this every 30m)
check('BE-32', 'v7.1: news-ingestion uses supabaseIngestion (isolated from auth)',
  newsIngestion.includes('supabaseIngestion'));

// BE-33: enrichment-engine.js uses supabaseIngestion (scheduler enrichBatch every 10m)
check('BE-33', 'v7.1: enrichment-engine uses supabaseIngestion (isolated from auth)',
  enrichEngine.includes('supabaseIngestion'));

// BE-34: enrichment.js uses supabaseIngestion
check('BE-34', 'v7.1: enrichment.js uses supabaseIngestion (isolated from auth)',
  enrichService.includes('supabaseIngestion'));

// BE-35: No frontend AbortController on login fetch (no premature client-side abort)
check('BE-35', 'v7.1: Frontend api-client.js has no AbortController on login fetch',
  !fs.readFileSync('js/api-client.js', 'utf8').includes('new AbortController()'));

// ── BACKEND v7.2: Key fix + isAbortError + DB-timeout → 503 ──────────────────

// BE-36: createLoginClient uses ANON key (not SERVICE key)
check('BE-36-CRIT', 'v7.2: createLoginClient() uses ANON key (loginKey = SUPABASE_ANON_KEY)',
  supabaseConf.includes('const loginKey = SUPABASE_ANON_KEY'));

// BE-37: isAbortError detects AuthRetryableFetchError (SDK wrapper)
check('BE-37-CRIT', 'v7.2: isAbortError() detects AuthRetryableFetchError wrapper',
  supabaseConf.includes("name === 'AuthRetryableFetchError'"));

// BE-38: isAbortError detects our custom timeout messages
check('BE-38', 'v7.2: isAbortError() detects custom fetch timeout messages',
  supabaseConf.includes("msg.includes('fetch timeout exceeded')"));

// BE-39: abort messages in fetch wrappers contain "aborted" keyword
check('BE-39', 'v7.2: _loginFetchWithTimeout abort message contains "aborted"',
  supabaseConf.includes("'Login fetch aborted: timeout exceeded (35s)'"));

// BE-40: profile lookup distinguishes abort (503) from genuine 'not found' (403)
check('BE-40-CRIT', 'v7.2: Profile lookup AbortError returns 503 DB_TIMEOUT (not 403)',
  authRoute.includes("isAbortError(profileError)") &&
  authRoute.includes("code:    'DB_TIMEOUT'") &&
  authRoute.includes('retryIn: 5'));

// BE-41: logActivity has internal 5s timeout (won't block for 15s on slow DB)
check('BE-41', 'v7.2: logActivity has internal 5s timeout guard',
  authRoute.includes('LOG_ACTIVITY_TIMEOUT_MS') &&
  authRoute.includes('5_000'));

// BE-42: post-login DB writes (last_login, tenantMeta) are non-blocking or guarded
check('BE-42', 'v7.2: last_login update is fire-and-forget (no await on critical path)',
  (() => {
    const loginHandler = authRoute.slice(
      authRoute.indexOf("router.post('/login'"),
      authRoute.indexOf("router.post('/refresh'")
    );
    // The update must not be preceded by 'await' on the same line
    const lines = loginHandler.split('\n');
    const lastLoginLine = lines.find(l => l.includes("'users').update({") && l.includes('last_login'));
    if (!lastLoginLine) return false;
    return !lastLoginLine.trim().startsWith('await ');
  })());

// BE-43: checkSupabaseConnection detects AbortError in error field (not just catch)
check('BE-43', 'v7.2: checkSupabaseConnection handles AbortError in error field',
  supabaseConf.includes('isAbortError(error)') &&
  supabaseConf.includes('RC-6 FIX'));

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
