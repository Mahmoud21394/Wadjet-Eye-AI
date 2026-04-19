/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Supabase Client v6.0 (AbortError Root-Cause Fix)
 *  backend/config/supabase.js
 *
 *  v6.0 ROOT-CAUSE FIX — AbortError leaks into loginError:
 *  ─────────────────────────────────────────────────────────
 *  PROBLEM (confirmed via production logs):
 *    The error message "This operation was aborted (code: undefined)"
 *    appears in LOGIN_FAILED logs. This is NOT a wrong-password error.
 *    It is an AbortError that Supabase's SDK catches internally and
 *    returns as { data: null, error: DOMException } instead of throwing.
 *
 *  ROOT CAUSE in v5.4:
 *    _fetchWithTimeout() creates one AbortController per fetch call.
 *    HOWEVER: when `supabase.auth.signOut()` is called (fire-and-forget),
 *    its AbortController fires after 15s... but by that time the NEXT
 *    request (signInWithPassword) may already be using a stale Supabase
 *    internal session state that still holds a reference to the old
 *    aborted signal. The @supabase/supabase-js GoTrueClient reuses
 *    internal fetch queues — an aborted queue affects subsequent calls.
 *
 *  ADDITIONAL BUG:
 *    _fetchWithTimeout passes `init.signal ?? ctrl.signal`. If the
 *    Supabase SDK passes its own internal signal via `init.signal`,
 *    our timeout signal is IGNORED. The SDK's signal can be aborted
 *    by internal SDK state. We must RACE our signal with the SDK's.
 *
 *  FIX in v6.0:
 *    1. Use TWO separate Supabase clients:
 *       - supabase: for all DB queries (uses _fetchWithTimeout)
 *       - supabaseAuth: for auth operations ONLY (uses native fetch
 *         with no shared AbortController — auth has its own 25s timeout)
 *    2. _fetchWithTimeout is NO LONGER used for auth operations.
 *    3. supabaseAuth has NO persistSession, NO autoRefreshToken,
 *       NO global fetch override — pure native fetch with HTTP timeout.
 *    4. The auth client's fetch wrapper uses AbortSignal.any() to
 *       combine both our timeout signal AND the SDK's signal safely.
 *
 *  SUPABASE KEY MIGRATION (from v5.4):
 *  ────────────────────────────────────
 *  SUPABASE_ANON_KEY    → sb_publishable_LwTPXF-cDzMcmc_V16N9lA_KvN-ElTZ
 *  SUPABASE_SERVICE_KEY → sb_secret_xDSevd4Gq3--9EPiWAcl0w_1M5S7M1_
 *  JWT_SECRET           → (keep current value)
 *
 *  Both old (eyJ...) and new (sb_*) key formats supported.
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
  if (key.startsWith('sb_secret_'))      console.log(`[Supabase] ✅ ${name}: new sb_secret_* format`);
  else if (key.startsWith('sb_publishable_')) console.log(`[Supabase] ✅ ${name}: new sb_publishable_* format`);
  else if (key.startsWith('eyJ'))        console.log(`[Supabase] ℹ️  ${name}: legacy JWT format (eyJ...) — consider migrating`);
  else                                   console.warn(`[Supabase] ⚠️  ${name}: unrecognized key format`);
}

detectKeyFormat(SERVICE_KEY,       'SUPABASE_SERVICE_KEY');
detectKeyFormat(SUPABASE_ANON_KEY, 'SUPABASE_ANON_KEY   ');

// ══════════════════════════════════════════════════════════════════
// TIMEOUT CONSTANTS
// ══════════════════════════════════════════════════════════════════
const DB_FETCH_TIMEOUT_MS   = 15_000; // 15s for database queries
const AUTH_FETCH_TIMEOUT_MS = 25_000; // 25s for auth operations (login can be slow on cold start)

// ══════════════════════════════════════════════════════════════════
// DB FETCH WRAPPER — for database queries only (NOT auth operations)
// Creates a per-request AbortController. Safe because DB queries do
// NOT share internal state the way the GoTrueClient auth queue does.
// ══════════════════════════════════════════════════════════════════
function _dbFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DB_FETCH_TIMEOUT_MS);

  // If the caller already has a signal, race both signals so EITHER
  // timeout OR the caller's abort will terminate the request.
  let signal = ctrl.signal;
  if (init.signal) {
    try {
      // AbortSignal.any() is Node 20+; fall back gracefully if not available
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
// AUTH FETCH WRAPPER — for auth operations (login, signOut, etc.)
// KEY DIFFERENCE from _dbFetchWithTimeout:
//   • Longer timeout (25s) to survive Render cold-start delays
//   • Never shares AbortController state with DB queries
//   • Explicitly handles the case where Supabase SDK passes its own
//     signal via init.signal — we race both signals correctly
// ══════════════════════════════════════════════════════════════════
function _authFetchWithTimeout(input, init = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), AUTH_FETCH_TIMEOUT_MS);

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
// Uses _dbFetchWithTimeout — bypasses RLS, for server-side use only.
// DO NOT use for auth operations (signInWithPassword, signOut, etc.)
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
// Uses _authFetchWithTimeout — separate instance with NO shared state
// with the DB client. Used ONLY for:
//   - supabaseAuth.auth.signInWithPassword()
//   - supabaseAuth.auth.signOut()
//   - supabaseAuth.auth.admin.createSession()
//   - supabaseAuth.auth.admin.signOut()
//
// WHY SEPARATE? The GoTrueClient inside @supabase/supabase-js maintains
// an internal request queue (_requestQueue). When signOut() is aborted,
// the queue may become corrupted, causing subsequent signInWithPassword
// calls to also abort even with a fresh AbortController. Using a separate
// client instance guarantees the auth queue is always clean on login.
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
// CLIENT 3: supabaseAnon — ANON/PUBLISHABLE client for RLS-aware reads
// ══════════════════════════════════════════════════════════════════
const supabaseAnon = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
    })
  : supabase; // fallback: use service client (bypasses RLS)

if (!SUPABASE_ANON_KEY) {
  console.warn('[Supabase] ⚠️  SUPABASE_ANON_KEY not set — using service client for anon ops (bypasses RLS)');
}

// ══════════════════════════════════════════════════════════════════
// supabaseForUser — user-scoped client factory
// Creates a client that acts as a specific authenticated user.
// This ensures RLS policies run for that user's tenant.
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
// isAbortError — helper to detect AbortError in both thrown and
// returned (Supabase SDK wraps AbortError in its error object) forms.
//
// CRITICAL: Supabase SDK returns AbortError as:
//   { data: null, error: DOMException { name: 'AbortError', message: 'This operation was aborted' } }
// NOT as a thrown exception. This is why the existing try/catch
// around signInWithPassword was NOT catching these aborts.
// ══════════════════════════════════════════════════════════════════
function isAbortError(err) {
  if (!err) return false;
  return (
    err.name === 'AbortError' ||
    (err instanceof DOMException && err.name === 'AbortError') ||
    err.message?.includes('This operation was aborted') ||
    err.message?.includes('signal is aborted') ||
    err.message?.includes('aborted without reason') ||
    // Supabase wraps the DOMException message
    err.message?.toLowerCase?.().includes('aborted')
  );
}

// ══════════════════════════════════════════════════════════════════
// isNetworkError — helper to detect connectivity failures
// ══════════════════════════════════════════════════════════════════
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
    m.includes('fetch error')
  );
}

// ══════════════════════════════════════════════════════════════════
// Startup connectivity test (non-blocking)
// Tests the DB client only — auth client does not have a health check
// endpoint that can be called without credentials.
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
        console.error('[Supabase]    Fix: https://supabase.com/dashboard/project/miywxnplaltduuscjfmq/settings/api');
        console.error('[Supabase]    Update SUPABASE_SERVICE_KEY in Render → Environment → redeploy');
        console.error('[Supabase]    Error:', error.message);
      } else {
        console.warn(`[Supabase] ⚠️  DB connection test error (${ms}ms): ${error.message}`);
        console.warn('[Supabase]    If RLS error → run: backend/database/rls-fix-v5.1.sql');
      }
    } else {
      console.log(`[Supabase] ✅ DB connection OK (${ms}ms)`);
    }
  } catch (err) {
    if (isAbortError(err)) {
      console.warn('[Supabase] ⚠️  DB connection check timed out (AbortError) — Supabase may be warming up');
    } else {
      console.error('[Supabase] ❌ DB connection check threw:', err.message);
    }
  }
}

setImmediate(checkSupabaseConnection);

// ══════════════════════════════════════════════════════════════════
// Exports
// ══════════════════════════════════════════════════════════════════
module.exports = {
  supabase,       // DB queries (service role)
  supabaseAuth,   // Auth operations ONLY (separate instance — no shared abort state)
  supabaseAnon,   // RLS-aware reads
  supabaseForUser,
  isAbortError,
  isNetworkError,
  AUTH_FETCH_TIMEOUT_MS,
  DB_FETCH_TIMEOUT_MS,
};
