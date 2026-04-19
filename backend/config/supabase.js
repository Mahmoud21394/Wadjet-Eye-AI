/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Supabase Client v7.0 (Timeout Root-Cause Fix)
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

// ── Environment ────────────────────────────────────────────────────
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_KEY       = process.env.SUPABASE_SERVICE_KEY
                       || process.env.SUPABASE_SECRET_KEY;

// ── Startup validation ────────────────────────────────────────────
if (!SUPABASE_URL) {
  console.error('[Supabase] ❌ MISSING: SUPABASE_URL is not set in environment');
  console.error('[Supabase]    Add to Render Dashboard → Environment');
  process.exit(1);
}

if (!SERVICE_KEY) {
  console.error('[Supabase] ❌ MISSING: SUPABASE_SERVICE_KEY is not set in environment');
  console.error('[Supabase]    Get the "Secret Key" (sb_secret_...) from:');
  console.error('[Supabase]    https://supabase.com/dashboard/project/_/settings/api');
  process.exit(1);
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
const DB_FETCH_TIMEOUT_MS        = 15_000; // 15s for database queries
const AUTH_FETCH_TIMEOUT_MS      = 35_000; // 35s for auth — accounts for Render cold-start + DNS + TLS
const LOGIN_FETCH_TIMEOUT_MS     = 35_000; // 35s for per-request login client
const INGESTION_FETCH_TIMEOUT_MS = 30_000; // 30s for ingestion workers

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
function isAbortError(err) {
  if (!err) return false;
  return (
    err.name === 'AbortError' ||
    (typeof DOMException !== 'undefined' && err instanceof DOMException && err.name === 'AbortError') ||
    err.message?.includes('This operation was aborted') ||
    err.message?.includes('signal is aborted') ||
    err.message?.includes('aborted without reason') ||
    err.message?.toLowerCase?.().includes('aborted')
  );
}

function isNetworkError(err) {
  if (!err) return false;
  const m = (err.message || '').toLowerCase();
  return (
    m.includes('failed to fetch') ||
    m.includes('networkerror') ||
    m.includes('econnrefused') ||
    m.includes('enotfound') ||
    m.includes('etimedout') ||
    m.includes('network request failed') ||
    m.includes('fetch error') ||
    m.includes('fetch failed') ||
    m.includes('ssl') ||
    m.includes('certificate')
  );
}

function isTimeoutError(err) {
  if (!err) return false;
  return isAbortError(err) || err.message === 'SUPABASE_TIMEOUT';
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
    ctrl.abort(new DOMException('DB fetch timeout exceeded', 'AbortError'));
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
    ctrl.abort(new DOMException('Auth fetch timeout exceeded (35s)', 'AbortError'));
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
    ctrl.abort(new DOMException('Login fetch timeout exceeded (35s)', 'AbortError'));
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
    ctrl.abort(new DOMException('Ingestion fetch timeout exceeded (30s)', 'AbortError'));
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
// ══════════════════════════════════════════════════════════════════
const supabase = createClient(
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
  }
);

// ══════════════════════════════════════════════════════════════════
// CLIENT 2: supabaseAuth — DEDICATED AUTH client
// For admin operations: createSession, getUser, admin.signOut, etc.
// Uses _authFetchWithTimeout (35s). Separate from DB client.
//
// ⚠️  DO NOT use this client for signInWithPassword (login).
// Use createLoginClient() instead — it creates a fresh per-request
// client with NO prior lock queue state, preventing queue stalls.
// ══════════════════════════════════════════════════════════════════
const supabaseAuth = createClient(
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
  }
);

// ══════════════════════════════════════════════════════════════════
// createLoginClient() — PER-REQUEST LOGIN CLIENT FACTORY
//
// ROOT CAUSE FIX v7.0:
// GoTrueClient maintains an internal pendingInLock queue. In Node.js,
// lockNoOp is used (no Web Locks API), but operations still queue
// serially. When supabaseAuth.auth.signOut() is called before
// signInWithPassword, the signOut takes the internal queue first.
// If signOut stalls (cold-start DNS + TLS), signInWithPassword
// waits in the queue — the combined wait hits our 25s timeout.
//
// SOLUTION: Create a FRESH Supabase client for EACH login attempt.
// A brand-new client has:
//   - lockAcquired = false (no active lock)
//   - pendingInLock = [] (empty queue)
//   - No prior signOut in the queue
//   - Clean GoTrueClient state
//
// The caller is responsible for calling this client ONLY for
// signInWithPassword and NOT calling signOut on it beforehand.
// ══════════════════════════════════════════════════════════════════
function createLoginClient() {
  return createClient(
    SUPABASE_URL,
    SERVICE_KEY,
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
const supabaseIngestion = createClient(
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
  }
);

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
    }
  );
}

// ══════════════════════════════════════════════════════════════════
// Startup connectivity test — non-blocking, uses DB client
// ══════════════════════════════════════════════════════════════════
async function checkSupabaseConnection() {
  try {
    const start = Date.now();
    const { error } = await supabase.from('users').select('id').limit(1);
    const ms = Date.now() - start;

    if (error) {
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
  isAbortError,
  isNetworkError,
  isTimeoutError,
  AUTH_FETCH_TIMEOUT_MS,
  DB_FETCH_TIMEOUT_MS,
  LOGIN_FETCH_TIMEOUT_MS,
});
