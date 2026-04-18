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
const apiClient  = fs.readFileSync('js/api-client/index.js', 'utf8');
const authStore  = fs.readFileSync('js/api-client/auth-store.js', 'utf8');
const loginPatch = fs.readFileSync('js/login-secure-patch.js', 'utf8');
const loginV20   = fs.readFileSync('js/login-v20.js', 'utf8');
// The OLD top-level api-client.js (the one referenced in the screenshots)
const oldApiClient = fs.readFileSync('js/api-client.js', 'utf8');

// ── BACKEND ──────────────────────────────────────────────────────────────────
const authIdx  = server.indexOf("app.use('/api/auth'");
const vtIdx    = server.indexOf('app.use(verifyToken)');
check('BE-01', 'auth routes before verifyToken',        authIdx > -1 && vtIdx > -1 && authIdx < vtIdx);
check('BE-02', 'refresh route has no inline verifyToken', !authRoute.includes("router.post('/refresh', verifyToken"));
check('BE-03', 'login route has no inline verifyToken',   !authRoute.includes("router.post('/login', verifyToken"));
check('BE-04', 'logout route is public (no verifyToken)', authRoute.includes("router.post('/logout',") && !authRoute.includes("router.post('/logout', verifyToken"));
check('BE-05', 'hard-reset: signOut before signInWithPassword',
  authRoute.includes('supabase.auth.signOut()') &&
  authRoute.indexOf('signOut()') < authRoute.indexOf('signInWithPassword'));
check('BE-06', 'Supabase login has 20s timeout',  authRoute.includes('20_000'));
check('BE-07', 'admin.createSession has 6s timeout', authRoute.includes('ADMIN_SESSION_TIMEOUT_MS') || authRoute.includes('6_000'));
check('BE-08', 'verifyToken has 8s timeout',      authMW.includes('VERIFY_TIMEOUT_MS') || authMW.includes('8_000'));
const healthIdx = server.indexOf("app.get('/health'");
check('BE-09', '/health is public (before verifyToken)', healthIdx > -1 && healthIdx < vtIdx);
check('BE-10', '/api/ping exists and is public',   server.includes("app.get('/api/ping'") && server.indexOf("app.get('/api/ping'") < vtIdx);

// ── FRONTEND: api-client/index.js ─────────────────────────────────────────────
check('FE-01', 'api-client login uses skipAuth:true',   apiClient.includes('skipAuth: true') || apiClient.includes('skipAuth:true'));
check('FE-02', 'api-client _doRefresh singleton lock',  apiClient.includes('_refreshing') && apiClient.includes('if (_refreshing) return _refreshing'));
check('FE-03', 'api-client _getToken reads sessionStorage', apiClient.includes('sessionStorage.getItem'));
check('FE-04', 'api-client _getRefreshToken reads localStorage', apiClient.includes('localStorage.getItem'));

// CRITICAL BUG: api-client reads localStorage key 'wadjet_token' but interceptor writes 'wadjet_access_token'
const apiTokenKey = apiClient.includes("localStorage.getItem('wadjet_access_token')");
check('FE-05-CRIT', 'CRITICAL: api-client reads correct key wadjet_access_token',  apiTokenKey);

// CRITICAL BUG: auth-store stores refresh in sessionStorage — wiped on tab close
const authStoreRefreshInLS = authStore.includes("localStorage.setItem") && authStore.includes("REFRESH");
check('FE-06-CRIT', 'CRITICAL: auth-store refresh in localStorage (survives reload)', authStoreRefreshInLS);

check('FE-07', 'api-client uses window.AuthStore',      apiClient.includes('window.AuthStore'));

// ── FRONTEND: auth-interceptor.js ─────────────────────────────────────────────
check('FE-08', 'interceptor writes refresh token to localStorage', interceptor.includes("localStorage.setItem(UNIFIED_KEYS.REFRESH"));
check('FE-09', 'interceptor single refresh lock',       interceptor.includes('_refreshLock') && interceptor.includes('if (_refreshLock && _refreshPromise)'));
check('FE-10', 'authFetch skips auth headers for /auth routes', interceptor.includes('AUTH_BYPASS') && interceptor.includes('isAuthRoute'));
check('FE-11', 'both token-refresh events dispatched',  interceptor.includes("'auth:token-refreshed'") && interceptor.includes("'auth:token_refreshed'"));
check('FE-12', 'WS.updateAuth called after refresh',    interceptor.includes('WS?.updateAuth'));
// Split on function definition (4th occurrence = function body)
const cookieParts = interceptor.split('_refreshFromCookie');
const cookieBody  = cookieParts[3] || '';
check('FE-13', 'cookie-refresh success dispatches token events', cookieBody.includes("'auth:token-refreshed'"));
check('FE-14', 'cookie-refresh updates StateSync',      cookieBody.includes('updateAuthState'));
check('FE-15', 'silentRefresh releases lock in finally',interceptor.includes('_refreshLock    = false') || interceptor.includes('_refreshLock = false'));
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

// CRITICAL BUG: api-client/index.js _getToken must NOT use localStorage 'wadjet_token' as a live read
// The interceptor writes to 'wadjet_access_token', not 'wadjet_token'.
// Check: the string localStorage.getItem('wadjet_token') must not appear OUTSIDE a comment line.
const apiClientLines = apiClient.split('\n');
const hasLiveWadjetToken = apiClientLines.some(line => {
  const trimmed = line.trim();
  return !trimmed.startsWith('//') && trimmed.includes("localStorage.getItem('wadjet_token'");
});
check('FE-25-CRIT', 'CRITICAL: no live localStorage.getItem(wadjet_token) in api-client (comment-only OK)',
  !hasLiveWadjetToken);

// ── login-v20.js ─────────────────────────────────────────────────────────────
check('FE-26', 'login-v20 wraps doLogin without replacing auth logic', loginV20.includes('origDoLogin') && loginV20.includes('window.doLogin'));

// ── OLD api-client.js (top-level) — RC-1/2/3 fixes ───────────────────────────
// RC-1: Pre-flight refresh must be bypassed for public auth paths
check('FE-27-CRIT', 'RC-1 FIX: api-client.js pre-flight refresh skipped for auth routes',
  oldApiClient.includes('_isPublicAuthPath') &&
  oldApiClient.includes('!isPublicAuth && !TokenStore.isValid()'));

// RC-2: Authorization header must be attached BEFORE first fetch (not only on retry)
check('FE-28-CRIT', 'RC-2 FIX: api-client.js attaches Authorization header before first fetch',
  oldApiClient.includes('!isPublicAuth && token') &&
  oldApiClient.includes("headers['Authorization'] = `Bearer ${token}`"));

// RC-3: 401 handler must be bypassed for login/refresh/logout paths
check('FE-29-CRIT', 'RC-3 FIX: api-client.js 401 handler bypassed for public auth paths',
  oldApiClient.includes('response.status === 401 && !isPublicAuth'));

// _AUTH_PUBLIC_PATHS list must include login, refresh, logout
check('FE-30', 'api-client.js _AUTH_PUBLIC_PATHS includes login/refresh/logout',
  oldApiClient.includes("'/auth/login'") &&
  oldApiClient.includes("'/auth/refresh'") &&
  oldApiClient.includes("'/auth/logout'"));

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
