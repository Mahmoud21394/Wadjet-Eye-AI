/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Supabase Client v7.4 (Timeout Root-Cause Fix)
 *  backend/config/supabase.js
 *
 *  v7.0 ROOT-CAUSE FIX — SUPABASE_TIMEOUT elapsed=25000ms:
 *  ─────────────────────────────────────────────────────────
 *
 *  CONFIRMED ROOT CAUSES (from production logs):
 *
 *  1. GoTrueClient._acquireLock QUEUE STALL:
 *     @supabase/auth-js v2.103 uses an internal lock queue (pendingInLock).
 *     In Node.js (no Web Locks API), lockNoOp is used — but operations still
 *     queue serially via pendingInLock. When supabaseAuth.auth.signOut() is
 *     called (fire-and-forget) BEFORE signInWithPassword, signOut takes the
 *     lock first. If signOut stalls (cold-start DNS + TLS takes 8-15s), the
 *     signInWithPassword waits in the queue. Our 25s timeout fires on the
 *     COMBINED wait, not just the signIn request.
 *     FIX: Do NOT call signOut on the auth client before signIn. Use a
 *     fresh per-request auth client that has NO prior queue state.
 *
 *  2. RENDER COLD-START + SUPABASE FREE-TIER STACK:
 *     Cold start (3-8s) + DNS resolution (2-5s) + TLS handshake (1-3s)
 *     + PgBouncer pool warmup (2-5s) + GoTrueClient lock overhead
 *     = 8-21s before signInWithPassword even sends the HTTP request.
 *     FIX: Increase auth timeout to 35s. Add connection warmup on startup.
 *
 *  3. CONCURRENT SCHEDULER SATURATING THE EVENT LOOP:
 *     Scheduler starts 15+ jobs 30s after boot. PhishTank upserts 2000+
 *     IOCs in 100-row chunks, each with a 15s AbortController. These
 *     saturate Node.js event loop, delaying auth response delivery.
 *     FIX: PhishTank/ingestion workers use a SEPARATE supabaseIngestion
 *     client with longer timeouts and explicit scheduling controls.
 *
 *  4. FETCH WRAPPER: _authFetchWithTimeout STILL FIRES AT 25s
 *     The 25s timeout in _authFetchWithTimeout is not reset between retries
 *     and includes time spent waiting in the GoTrueClient lock queue.
 *     FIX: Each login attempt gets a FRESH supabaseAuth instance created
 *     via createLoginClient(). This guarantees clean queue state.
 *
 *  ARCHITECTURE (v7.0):
 *  ─────────────────────
 *  supabase          DB queries — service role, _dbFetchWithTimeout (15s)
 *  supabaseAuth      Default auth client — used for admin ops (createSession, etc.)
 *  createLoginClient Per-request login client factory — fresh instance per login
 *  supabaseAnon      RLS-aware reads — anon key
 *  supabaseForUser   User-scoped factory
 *
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { createClient } = require('@supabase/supabase-js');

// ── WebSocket transport for Supabase Realtime ─────────────────────
// @supabase/realtime-js ≥ 2.10 uses WebSocketFactory which requires
// a WebSocket constructor available at module-load time.  Node.js < 22
// has no native globalThis.WebSocket.  The globalThis polyfill in
// server.js covers the normal startup path, but supabase.js may also
// be required directly in workers or tests where server.js never runs.
// Passing `ws` explicitly via `realtime.transport` on every createClient
// call is the belt-and-suspenders defence: it works regardless of the
// globalThis state and is the pattern explicitly recommended by the
// Supabase SDK docs for Node.js < 22.
// Reference: https://supabase.com/docs/reference/javascript/initializing
let _wsTransport;
try {
  _wsTransport = require('ws');
} catch (_) {
  // ws not installed — Realtime features will rely on the globalThis polyfill
  _wsTransport = undefined;
}
const _realtimeOpts = _wsTransport ? { transport: _wsTransport } : {};

// ── Environment ────────────────────────────────────────────────────
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY       = process.env.SUPABASE_SERVICE_KEY
                       || process.env.SUPABASE_SECRET_KEY;

// ── Startup validation ────────────────────────────────────────────
// NOTE: In development/demo mode we operate with a null Supabase client.
// Routes that need Supabase will check for null and return appropriate errors.
if (!SUPABASE_URL) {
  console.error('[Supabase] ❌ MISSING: SUPABASE_URL is not set in environment');
  console.error('[Supabase]    Add to Render Dashboard → Environment');
  if (process.env.NODE_ENV === 'production') process.exit(1);
  // In development: continue with null client (demo mode)
}

if (!SERVICE_KEY) {
  if (SUPABASE_URL) {
    console.error('[Supabase] ❌ MISSING: SUPABASE_SERVICE_KEY is not set in environment');
    console.error('[Supabase]    Get the "Secret Key" (sb_secret_...) from:');
    console.error('[Supabase]    https://supabase.com/dashboard/project/_/settings/api');
    if (process.env.NODE_ENV === 'production') process.exit(1);
  }
  // In development: continue with null client (demo mode)
}

// ── Key format detection ──────────────────────────────────────────
function detectKeyFormat(key, name) {
  if (!key) return;
  if (key.startsWith('sb_secret_'))           console.log(`[Supabase] ✅ ${name}: new sb_secret_* format`);
  else if (key.startsWith('sb_publishable_')) console.log(`[Supabase] ✅ ${name}: new sb_publishable_* format`);
  else if (key.startsWith('eyJ'))             console.log(`[Supabase] ℹ️  ${name}: legacy JWT format (eyJ...) — consider migrating`);
  else                                         console.warn(`[Supabase] ⚠️  ${name}: unrecognized key format`);
}

detectKeyFormat(SERVICE_KEY,       'SUPABASE_SERVICE_KEY');
detectKeyFormat(SUPABASE_ANON_KEY, 'SUPABASE_ANON_KEY   ');

// ══════════════════════════════════════════════════════════════════
// TIMEOUT CONSTANTS
// ══════════════════════════════════════════════════════════════════
// v7.5 FREE-TIER FIX: Supabase free-tier PgBouncer pools are shared across
// all projects. During peak hours the pool takes 8-20s to assign a connection
// slot.  15s was insufficient for complex dashboard queries (multiple joins).
// Increased to 25s so that legitimate slow queries aren't prematurely aborted,
// which caused the AbortError / statement-timeout cascade in the logs.
const DB_FETCH_TIMEOUT_MS        = 25_000; // 25s for database queries (was 15s — too short for free tier)
const AUTH_FETCH_TIMEOUT_MS      = 35_000; // 35s for auth — accounts for Render cold-start + DNS + TLS
const LOGIN_FETCH_TIMEOUT_MS     = 35_000; // 35s for per-request login client
const INGESTION_FETCH_TIMEOUT_MS = 45_000; // 45s for ingestion workers (was 30s — large upserts need more)

// Export for use in route handlers
module.exports.AUTH_FETCH_TIMEOUT_MS  = AUTH_FETCH_TIMEOUT_MS;
module.exports.DB_FETCH_TIMEOUT_MS    = DB_FETCH_TIMEOUT_MS;
module.exports.LOGIN_FETCH_TIMEOUT_MS = LOGIN_FETCH_TIMEOUT_MS;

// ══════════════════════════════════════════════════════════════════
// ABORT ERROR HELPERS
// Supabase SDK returns AbortError in the error FIELD, not thrown:
//   { data: null, error: DOMException { name: 'AbortError' } }
// Must check BOTH thrown AND returned forms.
// ══════════════════════════════════════════════════════════════════
/**
 * isAbortError — detect abort/timeout errors in ALL their forms:
 *
 * 1. Native DOMException with name 'AbortError'
 * 2. AuthRetryableFetchError wrapping an AbortError (Supabase SDK wraps
 *    DOMException AbortError into AuthRetryableFetchError in _handleRequest)
 * 3. Our custom timeout messages from _loginFetchWithTimeout,
 *    _authFetchWithTimeout, _dbFetchWithTimeout, _ingestionFetchWithTimeout
 * 4. Standard abort/signal messages from Node.js fetch
 * 5. Axios timeout errors (ECONNABORTED, ETIMEDOUT)
 */
function isAbortError(err) {
  if (!err) return false;
  const name = err.name || '';
  const code = err.code || '';
  const msg  = (err.message || '').toLowerCase();
  return (
    name === 'AbortError'                            ||
    name === 'AuthRetryableFetchError'               ||  // Supabase SDK wrapper
    code === 'ECONNABORTED'                          ||  // axios timeout
    code === 'ETIMEDOUT'                             ||  // axios/node timeout
    (typeof DOMException !== 'undefined' && err instanceof DOMException && name === 'AbortError') ||
    msg.includes('this operation was aborted')       ||
    msg.includes('signal is aborted')                ||
    msg.includes('aborted without reason')           ||
    msg.includes('aborted')                          ||
    msg.includes('fetch timeout exceeded')           ||  // our custom _*FetchWithTimeout messages
    msg.includes('login fetch timeout')              ||
    msg.includes('auth fetch timeout')               ||
    msg.includes('db fetch timeout')                 ||
    msg.includes('ingestion fetch timeout')          ||
    msg.includes('timeout of')                       ||  // axios: "timeout of Xms exceeded"
    msg.includes('network error')                    ||  // axios network errors
    msg.includes('connect etimedout')                ||
    // v7.4 FIX: Also catch AUTH_SERVICE_UNAVAILABLE and SERVER_ERROR codes
    // returned by signInWithPasswordDirect when all retries are exhausted.
    (err.code === 'AUTH_SERVICE_UNAVAILABLE')         ||
    (err.code === 'SERVER_ERROR')                     ||
    msg.includes('auth_service_unavailable')         ||
    msg.includes('login service unavailable')
  );
}

function isNetworkError(err) {
  if (!err) return false;
  const m   = (err.message || '').toLowerCase();
  const code = err.code || '';
  return (
    m.includes('failed to fetch')       ||
    m.includes('networkerror')           ||
    m.includes('econnrefused')           ||
    m.includes('enotfound')              ||
    m.includes('etimedout')              ||
    m.includes('network request failed') ||
    m.includes('fetch error')            ||
    m.includes('fetch failed')           ||
    m.includes('ssl')                    ||
    m.includes('certificate')            ||
    code === 'ECONNREFUSED'              ||
    code === 'ENOTFOUND'                 ||
    code === 'ECONNRESET'                ||
    code === 'EPIPE'
  );
}

function isTimeoutError(err) {
  if (!err) return false;
  const msg = (err.message || '').toLowerCase();
  return (
    isAbortError(err)                      ||
    err.message === 'SUPABASE_TIMEOUT'     ||
    err.message === 'REFRESH_TIMEOUT'      ||
    msg.includes('timed out')              ||
    msg.includes('timeout exceeded')
  );
}

module.exports.isAbortError    = isAbortError;
module.exports.isNetworkError  = isNetworkError;
module.exports.isTimeoutError  = isTimeoutError;

// ══════════════════════════════════════════════════════════════════
// FETCH WRAPPERS
// ══════════════════════════════════════════════════════════════════

/**
 * _dbFetchWithTimeout — for database queries (NOT auth operations)
 * 15s timeout. Safe because DB queries don't share GoTrueClient state.
 */
function _dbFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('DB fetch aborted: timeout exceeded (15s)', 'AbortError'));
  }, DB_FETCH_TIMEOUT_MS);

  let signal = ctrl.signal;
  if (init.signal) {
    try {
      signal = AbortSignal.any
        ? AbortSignal.any([ctrl.signal, init.signal])
        : ctrl.signal;
    } catch (_) {
      signal = ctrl.signal;
    }
  }

  return fetch(input, { ...init, signal })
    .finally(() => clearTimeout(timer));
}

/**
 * _authFetchWithTimeout — for admin auth operations (createSession, getUser, etc.)
 * 35s timeout to account for Render cold-start + DNS + TLS + PgBouncer warmup.
 */
function _authFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('Auth fetch aborted: timeout exceeded (35s)', 'AbortError'));
  }, AUTH_FETCH_TIMEOUT_MS);

  let signal = ctrl.signal;
  if (init.signal) {
    try {
      signal = AbortSignal.any
        ? AbortSignal.any([ctrl.signal, init.signal])
        : ctrl.signal;
    } catch (_) {
      signal = ctrl.signal;
    }
  }

  return fetch(input, { ...init, signal })
    .finally(() => clearTimeout(timer));
}

/**
 * _loginFetchWithTimeout — for per-request login clients
 * 35s timeout. Created fresh per login attempt — NO shared queue state.
 */
function _loginFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => {
    // Message MUST contain 'aborted' so isAbortError() catches it even
    // when Supabase SDK wraps it in AuthRetryableFetchError
    ctrl.abort(new DOMException('Login fetch aborted: timeout exceeded (35s)', 'AbortError'));
  }, LOGIN_FETCH_TIMEOUT_MS);

  let signal = ctrl.signal;
  if (init.signal) {
    try {
      signal = AbortSignal.any
        ? AbortSignal.any([ctrl.signal, init.signal])
        : ctrl.signal;
    } catch (_) {
      signal = ctrl.signal;
    }
  }

  return fetch(input, { ...init, signal })
    .finally(() => clearTimeout(timer));
}

/**
 * _ingestionFetchWithTimeout — for ingestion workers
 * 30s timeout. Isolated from auth clients entirely.
 */
function _ingestionFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => {
    ctrl.abort(new DOMException('Ingestion fetch aborted: timeout exceeded (30s)', 'AbortError'));
  }, INGESTION_FETCH_TIMEOUT_MS);

  let signal = ctrl.signal;
  if (init.signal) {
    try {
      signal = AbortSignal.any
        ? AbortSignal.any([ctrl.signal, init.signal])
        : ctrl.signal;
    } catch (_) {
      signal = ctrl.signal;
    }
  }

  return fetch(input, { ...init, signal })
    .finally(() => clearTimeout(timer));
}

// ══════════════════════════════════════════════════════════════════
// CLIENT 1: supabase — SERVICE ROLE client for DB queries
// NOT for auth operations. Uses _dbFetchWithTimeout (15s).
// null when SUPABASE_URL/SERVICE_KEY are not set (development/demo mode).
// ══════════════════════════════════════════════════════════════════
const supabase = (SUPABASE_URL && SERVICE_KEY) ? createClient(
  SUPABASE_URL,
  SERVICE_KEY,
  {
    auth: {
      autoRefreshToken:   false,
      persistSession:     false,
      detectSessionInUrl: false,
    },
    db: { schema: 'public' },
    global: {
      fetch:   _dbFetchWithTimeout,
      headers: { 'x-application-name': 'wadjet-eye-ai-backend' },
    },
    realtime: _realtimeOpts,
  }
) : null;

// ══════════════════════════════════════════════════════════════════
// CLIENT 2: supabaseAuth — DEDICATED AUTH client
// For admin operations: createSession, getUser, admin.signOut, etc.
// Uses _authFetchWithTimeout (35s). Separate from DB client.
//
// ⚠️  DO NOT use this client for signInWithPassword (login).
// Use createLoginClient() instead — it creates a fresh per-request
// client with NO prior lock queue state, preventing queue stalls.
// ══════════════════════════════════════════════════════════════════
const supabaseAuth = (SUPABASE_URL && SERVICE_KEY) ? createClient(
  SUPABASE_URL,
  SERVICE_KEY,
  {
    auth: {
      autoRefreshToken:   false,
      persistSession:     false,
      detectSessionInUrl: false,
    },
    global: {
      fetch:   _authFetchWithTimeout,
      headers: { 'x-application-name': 'wadjet-eye-ai-auth' },
    },
    realtime: _realtimeOpts,
  }
) : null;

// ══════════════════════════════════════════════════════════════════
// createLoginClient() — PER-REQUEST LOGIN CLIENT FACTORY
//
// ROOT CAUSE FIX v7.0 (queue) + v7.2 (key):
//
// KEY FIX (v7.2): signInWithPassword MUST use the ANON/PUBLISHABLE key.
// The SupabaseClient sets BOTH Authorization and apikey headers to
// supabaseKey. Supabase Auth endpoint /auth/v1/token expects the
// ANON key (sb_publishable_* or legacy eyJ anon JWT) — NOT the
// service role key (sb_secret_*). Using SERVICE_KEY causes
// INVALID_CREDENTIALS even with correct user credentials because
// the API key header identifies the client to Supabase Auth.
//
// QUEUE FIX (v7.0): GoTrueClient maintains an internal pendingInLock
// queue. Fresh client per login = empty queue = no stall from prior ops.
//
// The caller MUST use this client ONLY for signInWithPassword.
// ══════════════════════════════════════════════════════════════════
function createLoginClient() {
  // RC-1 FIX: Use ANON KEY for signInWithPassword.
  // SERVICE_KEY is for admin/DB ops only. Auth endpoint requires ANON key.
  const loginKey = SUPABASE_ANON_KEY || SERVICE_KEY;
  if (!SUPABASE_ANON_KEY) {
    console.warn('[Supabase] ⚠️  createLoginClient: SUPABASE_ANON_KEY not set — ' +
      'falling back to SERVICE_KEY for login. Set SUPABASE_ANON_KEY in Render env.');
  }
  return createClient(
    SUPABASE_URL,
    loginKey,
    {
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
      global: {
        fetch:   _loginFetchWithTimeout,
        headers: { 'x-application-name': 'wadjet-eye-ai-login' },
      },
      realtime: _realtimeOpts,
    }
  );
}

// ══════════════════════════════════════════════════════════════════
// CLIENT 3: supabaseAnon — ANON/PUBLISHABLE client for RLS reads
// ══════════════════════════════════════════════════════════════════
const supabaseAnon = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
      realtime: _realtimeOpts,
    })
  : supabase;

if (!SUPABASE_ANON_KEY) {
  console.warn('[Supabase] ⚠️  SUPABASE_ANON_KEY not set — using service client for anon ops (bypasses RLS)');
}

// ══════════════════════════════════════════════════════════════════
// CLIENT 4: supabaseIngestion — INGESTION WORKER client
// Isolated from auth clients. Uses _ingestionFetchWithTimeout (30s).
// Prevents scheduler workers from interfering with auth operations.
// ══════════════════════════════════════════════════════════════════
const supabaseIngestion = (SUPABASE_URL && SERVICE_KEY) ? createClient(
  SUPABASE_URL,
  SERVICE_KEY,
  {
    auth: {
      autoRefreshToken:   false,
      persistSession:     false,
      detectSessionInUrl: false,
    },
    db: { schema: 'public' },
    global: {
      fetch:   _ingestionFetchWithTimeout,
      headers: { 'x-application-name': 'wadjet-eye-ai-ingestion' },
    },
    realtime: _realtimeOpts,
  }
) : null;

// ══════════════════════════════════════════════════════════════════
// supabaseForUser — user-scoped client factory
// ══════════════════════════════════════════════════════════════════
function supabaseForUser(accessToken) {
  if (!accessToken) return supabaseAnon;

  return createClient(
    SUPABASE_URL,
    SUPABASE_ANON_KEY || SERVICE_KEY,
    {
      global: {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
      realtime: _realtimeOpts,
    }
  );
}

// ══════════════════════════════════════════════════════════════════
// signInWithPasswordDirect — DIRECT AXIOS LOGIN (bypasses GoTrueClient)
//
// ROOT CAUSE v7.3:
// On Render free-tier, the Node.js native fetch / GoTrueClient TCP connection
// to Supabase Auth HANGS for exactly 35s before our AbortController fires.
// The TCP connection establishes and TLS handshakes, but the HTTP response body
// is never received. This is a Render → Supabase free-tier connectivity issue
// (likely idle connection reset, or Render's outbound proxy hanging).
//
// SOLUTION: Use axios with its own socket-level timeout (`timeout` option sets
// both connect and response timeout independently of AbortController). Axios
// uses Node.js http.Agent directly, bypassing the undici-based native fetch.
// Additionally retry up to 3 times with 2s backoff before giving up.
//
// RETURNS: { data: { user, session }, error: null }
//       OR { data: null, error: { message, status, code } }
// Compatible with the existing loginData/loginError destructuring in auth.js.
// ══════════════════════════════════════════════════════════════════
const axios = (() => {
  try { return require('axios'); } catch (_) { return null; }
})();

const LOGIN_DIRECT_TIMEOUT_MS  = 12_000; // 12s per attempt via axios
const LOGIN_DIRECT_MAX_RETRIES = 3;       // up to 3 attempts
const LOGIN_DIRECT_RETRY_DELAY = 2_000;  // 2s between retries

async function signInWithPasswordDirect(email, password) {
  if (!axios) {
    // Fallback to SDK if axios not available
    const client = createLoginClient();
    return client.auth.signInWithPassword({ email, password });
  }

  const loginKey = SUPABASE_ANON_KEY || SERVICE_KEY;
  const authUrl  = `${SUPABASE_URL}/auth/v1/token?grant_type=password`;

  let lastErr = null;

  for (let attempt = 1; attempt <= LOGIN_DIRECT_MAX_RETRIES; attempt++) {
    const attemptStart = Date.now();
    try {
      console.log(`[supabase:login:direct] attempt=${attempt}/${LOGIN_DIRECT_MAX_RETRIES} email=${email}`);

      const resp = await axios.post(
        authUrl,
        { email, password },
        {
          timeout: LOGIN_DIRECT_TIMEOUT_MS,      // axios timeout covers BOTH connect + response
          headers: {
            'Content-Type':  'application/json',
            'apikey':        loginKey,
            'Authorization': `Bearer ${loginKey}`,
            'X-Client-Info': 'wadjet-eye-ai-backend/7.3',
          },
          validateStatus: () => true,            // don't throw on 4xx — we handle manually
          maxRedirects: 2,
        }
      );

      const elapsed = Date.now() - attemptStart;
      console.log(`[supabase:login:direct] attempt=${attempt} status=${resp.status} elapsed=${elapsed}ms`);

      const body = resp.data || {};

      // ── HTTP 200: successful login ──
      if (resp.status === 200 && body.access_token) {
        // Build a response shape compatible with Supabase SDK
        const session = {
          access_token:  body.access_token,
          refresh_token: body.refresh_token,
          expires_in:    body.expires_in,
          expires_at:    body.expires_at,
          token_type:    body.token_type || 'bearer',
        };
        const user = body.user || null;
        if (user && session) {
          session.user = user;
        }
        return { data: { user, session }, error: null };
      }

      // ── HTTP 4xx: auth error from Supabase (wrong credentials, not confirmed, etc.) ──
      if (resp.status >= 400 && resp.status < 500) {
        const errMsg = body.error_description || body.message || body.error || `Auth error ${resp.status}`;
        // Do NOT retry on 4xx — these are definitive auth failures
        return {
          data:  { user: null, session: null },
          error: { message: errMsg, status: resp.status, code: body.error || 'AUTH_ERROR' },
        };
      }

      // ── HTTP 5xx: Supabase server error — retry ──
      const serverErrMsg = body.error_description || body.message || `Server error ${resp.status}`;
      lastErr = { message: serverErrMsg, status: resp.status, code: 'SERVER_ERROR' };
      console.warn(`[supabase:login:direct] attempt=${attempt} server error ${resp.status}: ${serverErrMsg}`);

    } catch (axiosErr) {
      const elapsed = Date.now() - attemptStart;
      const isAxiosTimeout = axiosErr.code === 'ECONNABORTED' ||
                             axiosErr.code === 'ETIMEDOUT'    ||
                             (axiosErr.message || '').toLowerCase().includes('timeout');
      const isAxiosNetwork = axiosErr.code === 'ECONNREFUSED' ||
                             axiosErr.code === 'ENOTFOUND'    ||
                             axiosErr.code === 'ECONNRESET';

      console.warn(`[supabase:login:direct] attempt=${attempt} axios error: ${axiosErr.code} ${axiosErr.message?.slice(0,80)} elapsed=${elapsed}ms`);
      lastErr = {
        name:    isAxiosTimeout ? 'AbortError' : (isAxiosNetwork ? 'NetworkError' : axiosErr.name),
        message: axiosErr.message || 'Network error',
        code:    axiosErr.code || 'NETWORK_ERROR',
        status:  axiosErr.response?.status || 0,
      };
    }

    // Wait before retry (except on last attempt)
    if (attempt < LOGIN_DIRECT_MAX_RETRIES) {
      await new Promise(resolve => setTimeout(resolve, LOGIN_DIRECT_RETRY_DELAY));
    }
  }

  // All retries exhausted
  console.error(`[supabase:login:direct] all ${LOGIN_DIRECT_MAX_RETRIES} attempts failed. Last error:`, lastErr?.message);
  return {
    data:  { user: null, session: null },
    error: lastErr || { message: 'Login service unavailable after retries', code: 'AUTH_SERVICE_UNAVAILABLE' },
  };
}

// Export constants for audit checks
module.exports.LOGIN_DIRECT_TIMEOUT_MS  = LOGIN_DIRECT_TIMEOUT_MS;
module.exports.LOGIN_DIRECT_MAX_RETRIES = LOGIN_DIRECT_MAX_RETRIES;
module.exports.LOGIN_DIRECT_RETRY_DELAY = LOGIN_DIRECT_RETRY_DELAY;
module.exports.signInWithPasswordDirect = signInWithPasswordDirect;

// ══════════════════════════════════════════════════════════════════
// Startup connectivity test — non-blocking, uses DB client
// ══════════════════════════════════════════════════════════════════
async function checkSupabaseConnection() {
  try {
    const start = Date.now();
    const { error } = await supabase.from('users').select('id').limit(1);
    const ms = Date.now() - start;

    if (error) {
      // RC-6 FIX: AbortError is returned in the error FIELD (not thrown)
      // when _dbFetchWithTimeout fires. Must detect it explicitly here.
      if (isAbortError(error)) {
        console.warn(`[Supabase] ⚠️  DB connection check timed out (${ms}ms) — ` +
          'Supabase free-tier may be warming up (expected on cold start)');
        return; // Non-fatal — DB will be available after warmup
      }

      const isKeyError = error.message?.includes('JWT')
                      || error.message?.includes('token')
                      || error.message?.includes('Invalid API key')
                      || error.message?.includes('apikey')
                      || error.code === 'PGRST301';

      if (isKeyError) {
        console.error('[Supabase] 🔑 API KEY ERROR — service key may be invalid or revoked');
        console.error('[Supabase]    Fix: Supabase Dashboard → Settings → API → Service Key');
        console.error('[Supabase]    Update SUPABASE_SERVICE_KEY in Render → Environment → redeploy');
        console.error('[Supabase]    Error:', error.message);
      } else {
        console.warn(`[Supabase] ⚠️  DB connection test error (${ms}ms): ${error.message}`);
      }
    } else {
      console.log(`[Supabase] ✅ DB connection OK (${ms}ms)`);
    }
  } catch (err) {
    if (isAbortError(err)) {
      console.warn('[Supabase] ⚠️  DB connection check timed out — Supabase may be warming up');
    } else {
      console.error('[Supabase] ❌ DB connection check threw:', err.message);
    }
  }
}

// ══════════════════════════════════════════════════════════════════
// DNS WARMUP — pre-resolve Supabase hostname at startup
// Prevents the first login from paying the cold-start DNS cost.
// Runs in background — does NOT block server startup.
// ══════════════════════════════════════════════════════════════════
async function warmupSupabaseConnection() {
  try {
    const url = new URL(SUPABASE_URL);
    const hostname = url.hostname;

    // DNS warmup: Make a lightweight HEAD request to trigger DNS resolution
    // and TCP/TLS handshake. Even if this fails, it warms the OS DNS cache.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8_000);

    try {
      await fetch(`${SUPABASE_URL}/auth/v1/health`, {
        method: 'GET',
        signal: ctrl.signal,
        headers: { 'x-application-name': 'wadjet-eye-ai-warmup' },
      });
      console.log(`[Supabase] ✅ Auth endpoint warmup OK (hostname: ${hostname})`);
    } catch (err) {
      // Even a 404/401 means DNS + TLS is warmed up
      if (isAbortError(err)) {
        console.warn(`[Supabase] ⚠️  Auth endpoint warmup timed out (8s) — cold start expected`);
      } else {
        // Non-abort errors (401, 404, network) still mean DNS is warmed up
        console.log(`[Supabase] ✅ Auth endpoint reachable (DNS+TLS warm) — ${err.message?.slice(0,60)}`);
      }
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    // Non-fatal — just means warmup failed
    console.warn('[Supabase] ⚠️  Connection warmup error:', err.message?.slice(0, 80));
  }
}

// Run both checks on startup (non-blocking)
setImmediate(async () => {
  await warmupSupabaseConnection();
  await checkSupabaseConnection();
});

// ══════════════════════════════════════════════════════════════════
// Exports
// ══════════════════════════════════════════════════════════════════
module.exports = Object.assign(module.exports, {
  supabase,           // DB queries (service role)
  supabaseAuth,       // Auth admin operations (getUser, createSession, admin.signOut)
  supabaseIngestion,  // Ingestion workers ONLY — isolated from auth
  supabaseAnon,       // RLS-aware reads (anon key)
  supabaseForUser,    // Per-user scoped factory
  createLoginClient,  // Per-request login client factory — FRESH per login
  signInWithPasswordDirect, // v7.3: Direct axios login — bypasses GoTrueClient TCP hang
  isAbortError,
  isNetworkError,
  isTimeoutError,
  AUTH_FETCH_TIMEOUT_MS,
  DB_FETCH_TIMEOUT_MS,
  LOGIN_FETCH_TIMEOUT_MS,
  LOGIN_DIRECT_TIMEOUT_MS,
  LOGIN_DIRECT_MAX_RETRIES,
});
