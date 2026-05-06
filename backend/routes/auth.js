/**
 * ══════════════════════════════════════════════════════════
 *  Enterprise Auth Routes v7.4 — Timeout Root-Cause Fix
 *  backend/routes/auth.js
 *
 *  POST  /api/auth/login          — Email/password login
 *  POST  /api/auth/logout         — Revoke session
 *  POST  /api/auth/refresh        — Silent token refresh (rotate)
 *  GET   /api/auth/me             — Current user profile
 *  POST  /api/auth/register       — Admin creates user
 *  GET   /api/auth/sessions       — User's active sessions
 *  DELETE /api/auth/sessions/:id  — Revoke specific session
 *  DELETE /api/auth/sessions      — Revoke all sessions (sign out all devices)
 *  GET   /api/auth/activity       — Login history
 *  GET   /api/auth/diagnostics    — Supabase health check
 *
 *  Security:
 *   - Refresh token rotation (new token on every use)
 *   - Token stored as SHA-256 hash in DB
 *   - Device fingerprinting
 *   - Login activity logged with IP + UA
 *   - RLS-safe: service_role bypass for refresh_tokens + login_activity
 *   - JWT signed with Supabase JWT_SECRET for proper token validation
 *   - Rate limiting applied at server.js level
 *
 *  v6.1 ROOT-CAUSE FIX — AbortError leaks into loginError:
 *  ────────────────────────────────────────────────────────
 *  PROBLEM: The 401 with message "This operation was aborted (code: undefined)"
 *  was caused by auth.js using `supabase` (DB client, _dbFetchWithTimeout/15s)
 *  for ALL auth operations. The DB client's AbortController fired and corrupted
 *  the GoTrueClient's internal request queue.
 *
 *  FIX:
 *    1. Import `supabaseAuth` (dedicated auth client, _authFetchWithTimeout/25s,
 *       separate GoTrueClient instance — no shared abort state with DB client).
 *    2. ALL auth operations (signInWithPassword, signOut, admin.createSession,
 *       admin.signOut, getUser, admin.createUser, admin.deleteUser) now use
 *       `supabaseAuth` instead of `supabase`.
 *    3. `loginError` field is now checked for AbortError BEFORE the generic 401
 *       handler, so abort errors return 503 instead of being silently masked.
 *    4. Structured logging added: [auth:login:start], [auth:login:supabase],
 *       [auth:login:result], [auth:login:abort], [auth:login:ok].
 *    5. isAbortError() utility imported from supabase.js for consistent detection.
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router  = require('express').Router();
const crypto  = require('crypto');
const logger  = require('../utils/logger');
const {
  supabase,
  supabaseAuth,
  supabaseIngestion,
  createLoginClient,
  signInWithPasswordDirect,
  isAbortError,
  isNetworkError,
  isTimeoutError,
  LOGIN_FETCH_TIMEOUT_MS,
} = require('../config/supabase');
const { verifyToken, requireRole, evictProfileCache } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// jsonwebtoken — optional dependency for custom JWT signing on refresh
// Run: npm install jsonwebtoken   (in backend/)
let jwt = null;
try {
  jwt = require('jsonwebtoken');
} catch (_) {
  logger.warn('Auth', 'jsonwebtoken not installed — custom JWT fallback disabled. Run: cd backend && npm install jsonwebtoken');
}

/* ════════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════ */
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS || '30');
const ACCESS_TOKEN_EXPIRY_SEC   = parseInt(process.env.ACCESS_TOKEN_TTL || '900');

// Supabase JWT Secret — used to sign custom access tokens on refresh.
// ROOT-CAUSE FIX v10.0: Use SUPABASE_JWT_SECRET as primary (same key the
// middleware verifies with), fall back to JWT_SECRET.  This ensures Strategy-2
// signed tokens pass the middleware's jwt.verify() without a re-login loop.
const JWT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;

if (!JWT_SECRET) {
  logger.warn('Auth', '⚠️  Neither SUPABASE_JWT_SECRET nor JWT_SECRET is set. Get it from Supabase Dashboard → Settings → API → JWT Settings. Add SUPABASE_JWT_SECRET to your .env');
} else {
  logger.info('Auth', `✅ JWT signing enabled (source: ${process.env.SUPABASE_JWT_SECRET ? 'SUPABASE_JWT_SECRET' : 'JWT_SECRET'})`);
}

/* ── HTTP-only cookie name for refresh token ──────────────────── */
const RT_COOKIE = 'waj_rt';
// FIX v11.1: sameSite was 'strict' which silently drops cookies on EVERY
// cross-site request (Vercel frontend → Render backend = cross-site).
// 'none' + secure=true is the only value that works cross-origin in production.
// In development (HTTP, no HTTPS) use 'lax' so the cookie still arrives.
// Also removed path:'/api/auth' — restricting to that path meant the cookie
// was not sent when the browser first navigated to any other /api/* endpoint.
const _IS_PROD   = process.env.NODE_ENV === 'production';
const RT_COOKIE_OPTS = {
  httpOnly : true,
  secure   : _IS_PROD,
  sameSite : _IS_PROD ? 'none' : 'lax',
  maxAge   : parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS || '30') * 86400 * 1000,
  // No path restriction — cookie must be sent to ALL /api/* endpoints
};

/* ════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════ */

/** Generate a cryptographically random 64-byte refresh token */
function generateRefreshToken() {
  return crypto.randomBytes(64).toString('hex');
}

/** SHA-256 hash a token for safe DB storage */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Extract device fingerprint from request */
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  return {
    ip:         req.ip || req.connection?.remoteAddress || 'unknown',
    user_agent: ua.slice(0, 256),
    browser:    ua.includes('Chrome') ? 'Chrome' :
                ua.includes('Firefox') ? 'Firefox' :
                ua.includes('Safari')  ? 'Safari'  : 'Unknown',
    os:         ua.includes('Windows') ? 'Windows' :
                ua.includes('Mac OS')  ? 'macOS'   :
                ua.includes('Linux')   ? 'Linux'    :
                ua.includes('Android') ? 'Android'  :
                ua.includes('iOS')     ? 'iOS'      : 'Unknown',
  };
}

/**
 * logActivity — fire-and-forget audit logging.
 *
 * RC-4 FIX: This function MUST be called without await on the hot login path,
 * or with .catch(() => {}) to prevent blocking the response. It has its own
 * internal 5s timeout so it never blocks for 15s on a slow DB.
 * Never throws — all errors are silently swallowed.
 */
const LOG_ACTIVITY_TIMEOUT_MS = 5_000;
async function logActivity(userId, tenantId, action, req, extras = {}) {
  // Internal timeout so DB latency never delays the response
  const logTimer = new Promise((resolve) =>
    setTimeout(resolve, LOG_ACTIVITY_TIMEOUT_MS)
  );

  const logPromise = (async () => {
    try {
      const { error } = await supabase.from('login_activity').insert({
        user_id:        userId   || null,
        tenant_id:      tenantId || null,
        email:          extras.email || null,
        action,
        ip_address:     req.ip || null,
        user_agent:     (req.headers['user-agent'] || '').slice(0, 256),
        device_info:    getDeviceInfo(req),
        success:        extras.success !== false,
        failure_reason: extras.failure_reason || null,
        session_id:     extras.session_id || null,
      });
      if (error) {
        // RC-4 FIX: AbortError returned in error field — treat as non-fatal
        if (isAbortError(error)) return;
        // Silently ignore RLS / missing table errors for audit log
        if (!error.message?.includes('row-level security') &&
            !error.message?.includes('does not exist')) {
          logger.warn('Auth', 'Failed to log activity:', error.message);
        }
      }
    } catch (err) {
      // Non-fatal — never block login if audit logging fails
      if (!isAbortError(err)) {
        logger.warn('Auth', 'logActivity error:', err.message);
      }
    }
  })();

  // Race: complete within 5s or give up silently
  await Promise.race([logPromise, logTimer]);
}

// ROOT-CAUSE FIX v10.0: In-memory refresh-token registry for when the DB/RLS
// blocks inserts into the refresh_tokens table.  Keyed by token_hash → {userId,
// tenantId, expiresAt, user}.  Falls back to this map so rotateRefreshToken()
// can still validate the token without a DB row.  Cleared on process restart
// (acceptable — user will need to log in again on cold restart).
const _rtMemoryStore = new Map();

/** Store a new refresh token in DB (with in-memory fallback when RLS blocks).
 *  ROOT-CAUSE FIX v10.0: When RLS/missing-table prevents the DB insert, store
 *  the token hash in _rtMemoryStore so the /refresh endpoint can validate it.
 *  This replaces the previous "return fake UUID" approach that caused every
 *  subsequent /api/auth/refresh call to return "Invalid or expired refresh token".
 */
async function storeRefreshToken(userId, tenantId, token, req) {
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000).toISOString();

  try {
    const { data, error } = await supabase.from('refresh_tokens').insert({
      user_id:     userId,
      tenant_id:   tenantId,
      token_hash:  hashToken(token),
      device_info: getDeviceInfo(req),
      expires_at:  expiresAt,
    }).select('id').single();

    if (error) {
      // ── RLS or table-missing error → non-fatal, log and continue ──
      const isRLS     = error.message?.includes('row-level security') ||
                        error.message?.includes('policy') ||
                        error.code === '42501';
      const noTable   = error.message?.includes('does not exist') ||
                        error.code === '42P01';

      if (isRLS) {
        logger.warn('Auth', '⚠️  refresh_tokens RLS blocked insert. FIX: Run backend/database/rls-fix-v5.1.sql. Storing token in memory fallback so refresh still works this session.');
        // ROOT-CAUSE FIX v10.0: Store in memory so rotateRefreshToken() can
        // validate this token even without a DB row.
        const fallbackId = crypto.randomUUID();
        _rtMemoryStore.set(hashToken(token), { userId, tenantId, expiresAt, sessionId: fallbackId });
        return fallbackId;
      }
      if (noTable) {
        logger.warn('Auth', '⚠️  refresh_tokens table missing. FIX: Run backend/database/migration-v5.0-auth-tables.sql first. Storing token in memory fallback.');
        const fallbackId = crypto.randomUUID();
        _rtMemoryStore.set(hashToken(token), { userId, tenantId, expiresAt, sessionId: fallbackId });
        return fallbackId;
      }
      // Other errors — throw to surface them
      throw new Error('Failed to store refresh token: ' + error.message);
    }

    return data.id;
  } catch (err) {
    // Catch network errors too
    if (err.message?.includes('Failed to store refresh token')) throw err;
    logger.warn('Auth', 'storeRefreshToken unexpected error:', err.message);
    // ROOT-CAUSE FIX v10.0: In-memory fallback so refresh still works this session
    const fallbackId = crypto.randomUUID();
    _rtMemoryStore.set(hashToken(token), { userId, tenantId, expiresAt, sessionId: fallbackId });
    return fallbackId;
  }
}

/** Validate + rotate a refresh token
 *
 * FIX v15.0: Added 8-second timeout guards to EVERY DB query in this function.
 * Previously ALL Supabase calls here had NO timeout guard.  On Render free-tier
 * cold-start any one of these queries could hang for the full 15 s statement
 * timeout, causing the outer 20 s rotate-timeout to fire → 503
 * REFRESH_SERVICE_UNAVAILABLE → client retry storm → 429 cascade.
 * Each query is now individually guarded so they fail fast and surface as
 * SESSION_VALIDATION_UNAVAILABLE (retriable) rather than causing a full 503.
 */
async function rotateRefreshToken(oldToken, req) {
  const hash = hashToken(oldToken);
  const _DB_QUERY_TIMEOUT_MS = 8_000; // 8 s per DB query — tight enough to fail fast

  // Helper: wrap any Supabase promise in a per-query timeout
  function _withDbTimeout(promise, label) {
    return Promise.race([
      promise,
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`rotateRefreshToken DB timeout: ${label}`)), _DB_QUERY_TIMEOUT_MS)
      ),
    ]);
  }

  // FIX v11.1: Check the in-memory fallback BEFORE touching the DB.
  // When storeRefreshToken() was blocked by RLS on login, the token was
  // written only to _rtMemoryStore — there is no DB row at all.
  // The previous code ran the DB query first, got PGRST116 (row not found),
  // then checked memEntry but only after the error gate, which always threw
  // 'Invalid or expired refresh token' for PGRST116 (not an RLS error).
  const memEntry = _rtMemoryStore.get(hash);
  if (memEntry) {
    // Validate expiry
    if (new Date(memEntry.expiresAt) < new Date()) {
      _rtMemoryStore.delete(hash);
      throw new Error('Refresh token has expired. Please log in again.');
    }
    // Fetch live user record for status check — with timeout guard
    let memUser = null;
    try {
      const { data } = await _withDbTimeout(
        supabase
          .from('users')
          .select('id, name, email, role, tenant_id, status, permissions, avatar')
          .eq('id', memEntry.userId)
          .single(),
        'memEntry user fetch'
      );
      memUser = data || null;
    } catch (dbErr) {
      // DB timeout during memory-store path — throw SESSION_VALIDATION_UNAVAILABLE
      // so the client retries rather than treating the session as permanently dead.
      _rtMemoryStore.delete(hash);
      logger.warn('Auth:Refresh', `memEntry user fetch timed out: ${dbErr.message}`);
      throw new Error('Session validation unavailable. Please log in again.');
    }
    if (!memUser || memUser.status !== 'active') {
      _rtMemoryStore.delete(hash);
      throw new Error('Account is suspended or not found');
    }
    // Rotate: remove old token from memory, issue new one
    _rtMemoryStore.delete(hash);
    const newToken     = generateRefreshToken();
    // FIX v16.0: storeRefreshToken() for the new token had no timeout guard.
    // On free-tier cold-start the DB insert can hang, blocking the entire
    // rotation result and causing the outer 20s timeout to fire → 503 storm.
    // Wrap in the same 8s _withDbTimeout used for the lookup above.
    let newSessionId;
    try {
      newSessionId = await _withDbTimeout(
        (async () => storeRefreshToken(memUser.id, memUser.tenant_id, newToken, req))(),
        'storeRefreshToken (memory path)'
      );
    } catch (storeErr) {
      // Non-fatal: memory fallback — store directly and continue
      logger.warn('Auth:Refresh', `storeRefreshToken (memory path) timed out: ${storeErr.message}`);
      const fbId = crypto.randomUUID();
      const exp  = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000).toISOString();
      _rtMemoryStore.set(hashToken(newToken), { userId: memUser.id, tenantId: memUser.tenant_id, expiresAt: exp, sessionId: fbId });
      newSessionId = fbId;
    }
    logger.info('Auth:Refresh', `✅ Rotated from memory store for user=${memUser.id}`);
    return { newToken, newSessionId, user: memUser, tenantId: memUser.tenant_id };
  }

  // No memory entry — try the DB (with timeout guard)
  let rt, rtError;
  try {
    const result = await _withDbTimeout(
      supabase
        .from('refresh_tokens')
        .select('*, users(id, name, email, role, tenant_id, status, permissions, avatar)')
        .eq('token_hash', hash)
        .eq('is_revoked', false)
        .single(),
      'refresh_token lookup'
    );
    rt      = result.data;
    rtError = result.error;
  } catch (dbErr) {
    // Hard DB timeout — return SESSION_VALIDATION_UNAVAILABLE so client retries
    logger.warn('Auth:Refresh', `refresh_token lookup timed out: ${dbErr.message}`);
    throw new Error('Session validation unavailable. Please log in again.');
  }

  if (rtError) {
    const isRLS      = rtError.message?.includes('row-level security') || rtError.code === '42501';
    const noTable    = rtError.message?.includes('does not exist')     || rtError.code === '42P01';
    const notFound   = rtError.code === 'PGRST116'; // PostgREST: 0 rows returned by .single()
    if (isRLS || noTable) {
      logger.warn('Auth:Refresh', `DB unavailable for token lookup (${rtError.code}): ${rtError.message}`);
      throw new Error('Session validation unavailable. Please log in again.');
    }
    if (notFound) {
      // Row doesn't exist — token was never stored or already rotated
      throw new Error('Invalid or expired refresh token');
    }
    // Unexpected DB error
    logger.error('Auth:Refresh', `Unexpected DB error on token lookup: ${rtError.message}`);
    throw new Error('Invalid or expired refresh token');
  }

  if (!rt) {
    throw new Error('Invalid or expired refresh token');
  }

  if (new Date(rt.expires_at) < new Date()) {
    // Clean up expired token — fire-and-forget, don't block on it
    supabase.from('refresh_tokens').delete().eq('id', rt.id).then(() => {}).catch(() => {});
    throw new Error('Refresh token has expired. Please log in again.');
  }

  if (rt.users?.status !== 'active') {
    throw new Error('Account is suspended');
  }

  // ── Rotate: revoke old, issue new ──
  const newToken = generateRefreshToken();

  // Revoke the old token — with timeout guard (fire-and-forget on timeout)
  try {
    await _withDbTimeout(
      supabase.from('refresh_tokens').update({
        is_revoked:   true,
        last_used_at: new Date().toISOString(),
      }).eq('id', rt.id),
      'revoke old refresh_token'
    );
  } catch (revokeErr) {
    // Non-fatal: old token will expire naturally; proceed with issuing new one
    logger.warn('Auth:Refresh', `revoke old token timed out (non-fatal): ${revokeErr.message}`);
  }

  // FIX v16.0: storeRefreshToken() for the new token had no timeout guard.
  // Wrap in the same 8s _withDbTimeout used for all other DB queries here.
  let newSessionId;
  try {
    newSessionId = await _withDbTimeout(
      (async () => storeRefreshToken(rt.user_id, rt.tenant_id, newToken, req))(),
      'storeRefreshToken (DB path)'
    );
  } catch (storeErr) {
    // Non-fatal timeout — use in-memory fallback so the rotation still completes
    logger.warn('Auth:Refresh', `storeRefreshToken (DB path) timed out: ${storeErr.message}`);
    const fbId = crypto.randomUUID();
    const exp  = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000).toISOString();
    _rtMemoryStore.set(hashToken(newToken), { userId: rt.user_id, tenantId: rt.tenant_id, expiresAt: exp, sessionId: fbId });
    newSessionId = fbId;
  }

  return { newToken, newSessionId, user: rt.users, tenantId: rt.tenant_id };
}

/* ════════════════════════════════════════════════
   POST /api/auth/login
═══════════════════════════════════════════════ */
router.post('/login', asyncHandler(async (req, res) => {
  const { email, password, tenant_id } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // ── Structured logging: mark start of login attempt ──────────────
  const loginStart = Date.now();
  logger.info('Auth:Login', `${email} from ${req.ip || 'unknown'}`);

  // ── v7.3 FIX: Use direct axios call instead of GoTrueClient ───────────────
  // ROOT CAUSE: On Render free-tier, Node.js native fetch / GoTrueClient TCP
  // connection to Supabase Auth HANGS for exactly 35s. The TCP connects + TLS
  // handshakes, but the HTTP response body never arrives before our timeout.
  // GoTrueClient uses undici (Node built-in fetch) which lacks socket-level
  // keepalive timeout control.
  //
  // FIX: signInWithPasswordDirect uses axios with its own socket timeout
  // (12s per attempt, 3 retries with 2s backoff = max 42s total but typically
  // succeeds on attempt 1 in < 500ms when Supabase is healthy).
  // Axios uses Node.js http.Agent directly, bypassing undici.
  logger.debug('Auth:Login', `using direct axios login for ${email}`);

  let loginData, loginError;
  try {
    ({ data: loginData, error: loginError } = await signInWithPasswordDirect(
      email.trim().toLowerCase(),
      password.trim()
    ));
    logger.debug('Auth:Login', `result elapsed=${Date.now()-loginStart}ms loginError=${loginError ? loginError.message : 'none'} session=${loginData?.session ? 'present' : 'absent'}`);
  } catch (supabaseErr) {
    // signInWithPasswordDirect should not throw (it returns errors), but
    // catch any unexpected throws here
    const isAbort   = isAbortError(supabaseErr);
    const isTimeout = supabaseErr.message === 'SUPABASE_TIMEOUT';
    const isNetwork = isNetworkError(supabaseErr);

    const elapsed = Date.now() - loginStart;
    logger.error('Auth:Login', `THROWN ${supabaseErr.name}: ${supabaseErr.message} elapsed=${elapsed}ms`);

    if (isAbort || isTimeout || isNetwork) {
      const reason = isTimeout ? `timeout after ${elapsed}ms` :
                     isAbort   ? `aborted after ${elapsed}ms` :
                                 `network error after ${elapsed}ms`;
      logger.error('Auth:Login', `Returning 503 — ${reason}`);
      logActivity(null, null, 'LOGIN_FAILED', req, {
        email, success: false,
        failure_reason: `${supabaseErr.name}: ${supabaseErr.message} (${reason})`,
      }).catch(() => {});
      return res.status(503).json({
        error:   'Authentication service temporarily unavailable. Please try again in a few seconds.',
        code:    'AUTH_SERVICE_UNAVAILABLE',
        detail:  process.env.NODE_ENV !== 'production' ? reason : undefined,
        retryIn: 5,
      });
    }
    throw supabaseErr; // re-throw truly unexpected errors
  }

  if (loginError) {
    // v7.4 FIX: Check for timeout/abort/network/server errors BEFORE credential checks.
    // signInWithPasswordDirect returns these in the error object with matching names/codes.
    // isAbortError() now catches AUTH_SERVICE_UNAVAILABLE + SERVER_ERROR (v7.4).
    if (isAbortError(loginError) || isNetworkError(loginError) ||
        loginError.code === 'ECONNABORTED' || loginError.code === 'ETIMEDOUT' ||
        loginError.code === 'ECONNREFUSED'  || loginError.code === 'ECONNRESET'  ||
        loginError.code === 'AUTH_SERVICE_UNAVAILABLE' ||
        loginError.code === 'SERVER_ERROR') {
      const elapsed = Date.now() - loginStart;
      logger.error('Auth:Login', `RETURNED error in loginError: ${loginError.message} code=${loginError.code} elapsed=${elapsed}ms`);
      logActivity(null, null, 'LOGIN_FAILED', req, {
        email, success: false,
        failure_reason: `ServiceError: ${loginError.message} (code:${loginError.code})`,
      }).catch(() => {});
      return res.status(503).json({
        error:   'Authentication service temporarily unavailable. Please try again in a few seconds.',
        code:    'AUTH_SERVICE_UNAVAILABLE',
        detail:  process.env.NODE_ENV !== 'production' ? loginError.message : undefined,
        retryIn: 5,
      });
    }

    // Log asynchronously — don't await so we don't hang on Supabase issues
    logActivity(null, null, 'LOGIN_FAILED', req, {
      email,
      success: false,
      failure_reason: loginError.message,
    }).catch(() => {});

    logger.warn('Auth:Login', `LOGIN_FAILED for ${email}: "${loginError.message}" (status=${loginError.status} code=${loginError.code}) elapsed=${Date.now()-loginStart}ms`);

    // Map Supabase-specific errors to actionable messages
    const errMsg  = (loginError.message || '').toLowerCase();
    const errCode = loginError.status || loginError.code;

    if (errMsg.includes('email not confirmed') || errMsg.includes('not confirmed')) {
      return res.status(401).json({
        error: 'Email not confirmed. Please check your inbox and confirm your email address before logging in.',
        code:  'EMAIL_NOT_CONFIRMED',
      });
    }

    if (errMsg.includes('invalid login credentials') ||
        errMsg.includes('invalid email or password') ||
        errMsg.includes('invalid credentials')       ||
        errCode === 400) {
      return res.status(401).json({
        error: 'Invalid email or password',
        code:  'INVALID_CREDENTIALS',
        _supabaseMsg: process.env.NODE_ENV !== 'production' ? loginError.message : undefined,
      });
    }

    if (errMsg.includes('too many requests') || errCode === 429) {
      return res.status(429).json({
        error: 'Too many login attempts. Please wait a few minutes and try again.',
        code:  'RATE_LIMITED',
      });
    }

    if (errMsg.includes('user not found') || errMsg.includes('no user found')) {
      return res.status(401).json({
        error: 'Invalid email or password',
        code:  'INVALID_CREDENTIALS',
      });
    }

    // v7.4 FIX: Detect Supabase 5xx / unexpected errors that should be 503, not 401.
    // Only return 401 INVALID_CREDENTIALS when we are confident this is a real auth failure.
    // IMPORTANT: Match only SPECIFIC credential-failure phrases, not generic words like "wrong"
    // (which could appear in unrelated error messages like "Something went wrong").
    const isDefiniteAuthError =
      errMsg.includes('invalid login') ||
      errMsg.includes('invalid email') ||
      errMsg.includes('invalid password') ||
      errMsg.includes('invalid credentials') ||
      errMsg.includes('wrong password') ||
      errMsg.includes('wrong email') ||
      errMsg.includes('incorrect password') ||
      errMsg.includes('user not found') ||
      errMsg.includes('no user found') ||
      errMsg.includes('not confirmed') ||
      errMsg.includes('not verified') ||
      errCode === 400 || errCode === 401;

    if (!isDefiniteAuthError) {
      // Unknown Supabase error — safer to return 503 than a misleading 401
      const elapsed503 = Date.now() - loginStart;
      logger.error('Auth:Login', `503-fallback: Unknown loginError: "${loginError.message}" code=${loginError.code} status=${loginError.status} elapsed=${elapsed503}ms`);
      logActivity(null, null, 'LOGIN_FAILED', req, {
        email, success: false,
        failure_reason: `UnknownError: ${loginError.message}`,
      }).catch(() => {});
      return res.status(503).json({
        error:   'Authentication service temporarily unavailable. Please try again in a few seconds.',
        code:    'AUTH_SERVICE_UNAVAILABLE',
        retryIn: 5,
      });
    }

    // Generic 401 for definitive credential failures only
    return res.status(401).json({
      error: 'Invalid email or password',
      code:  'INVALID_CREDENTIALS',
      _supabaseMsg: process.env.NODE_ENV !== 'production' ? loginError.message : undefined,
    });
  }

  logger.info('Auth:Login', `✅ Supabase auth OK for ${email} elapsed=${Date.now()-loginStart}ms`);

  // ── Fetch user profile ──
  // RC-3 FIX: If DB times out, the Supabase client returns AbortError in the
  // error FIELD (not thrown). Must check for abort BEFORE treating as
  // 'profile not found'. An abort means the DB is slow/cold, not that
  // the user doesn't exist. Return 503 so the client can retry.
  const { data: profile, error: profileError } = await supabase
    .from('users')
    .select('id, name, email, role, tenant_id, avatar, permissions, status, mfa_enabled')
    .eq('auth_id', loginData.user.id)
    .single();

  if (profileError) {
    // RC-3: Distinguish timeout/abort from genuine 'not found'
    if (isAbortError(profileError)) {
      const profileMs = Date.now() - loginStart;
      logger.error('Auth:Login', `DB timeout on profile lookup after ${profileMs}ms for ${email}`);
      logActivity(null, null, 'LOGIN_FAILED', req, {
        email, success: false,
        failure_reason: `DB timeout on profile lookup: ${profileError.message}`,
      }).catch(() => {});
      return res.status(503).json({
        error:   'Database temporarily unavailable. Your credentials were accepted — please try again in a few seconds.',
        code:    'DB_TIMEOUT',
        retryIn: 5,
      });
    }
    // Genuine profile error (e.g., auth_id not in users table)
    logActivity(null, null, 'LOGIN_FAILED', req, {
      email, success: false,
      failure_reason: `Profile error: ${profileError.message}`,
    }).catch(() => {});
    logger.warn('Auth:Login', `No users row for auth_id=${loginData.user.id} email=${email}: ${profileError.message}`);
    return res.status(403).json({ error: 'User profile not found. Contact your administrator.' });
  }

  if (!profile) {
    logActivity(null, null, 'LOGIN_FAILED', req, {
      email, success: false,
      failure_reason: 'Profile not found (null)',
    }).catch(() => {});
    return res.status(403).json({ error: 'User profile not found. Contact your administrator.' });
  }

  if (profile.status !== 'active') {
    logActivity(profile.id, profile.tenant_id, 'LOGIN_FAILED', req, {
      email, success: false,
      failure_reason: 'Account suspended',
    }).catch(() => {});
    return res.status(403).json({ error: 'Your account has been suspended.' });
  }

  // ── Tenant validation ──
  if (tenant_id) {
    const isUUID = /^[0-9a-f-]{36}$/i.test(tenant_id);
    if (isUUID) {
      if (profile.tenant_id !== tenant_id) {
        return res.status(403).json({ error: 'You do not have access to this tenant.' });
      }
    } else {
      const { data: tenantRow } = await supabase
        .from('tenants')
        .select('id')
        .eq('short_name', tenant_id.toLowerCase())
        .single();
      if (!tenantRow || profile.tenant_id !== tenantRow.id) {
        return res.status(403).json({ error: 'Tenant not found or access denied.' });
      }
    }
  }

  // ── Issue our own refresh token (in addition to Supabase's) ──
  const refreshToken = generateRefreshToken();
  const sessionId    = await storeRefreshToken(profile.id, profile.tenant_id, refreshToken, req);

  // ── Update last login (fire-and-forget — non-critical) ──
  // RC-7 FIX: Don't await non-critical DB writes on the login response path.
  supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', profile.id)
    .then(({ error: ulErr }) => {
      if (ulErr && !isAbortError(ulErr)) logger.warn('Auth:Login', 'last_login update failed:', ulErr.message);
    }).catch(() => {});

  // ── Fetch tenant meta (with fallback on timeout) ──
  let tenantMeta = null;
  try {
    const { data: tm, error: tmErr } = await supabase
      .from('tenants')
      .select('short_name, name')
      .eq('id', profile.tenant_id)
      .single();
    if (tmErr && !isAbortError(tmErr)) {
      logger.warn('Auth:Login', 'tenantMeta fetch error:', tmErr.message);
    }
    tenantMeta = tm || null;
  } catch (_) {
    // Non-fatal — tenant slug/name will be empty strings
  }

  // Fire-and-forget login success audit
  logActivity(profile.id, profile.tenant_id, 'LOGIN_SUCCESS', req, {
    email, session_id: sessionId,
  }).catch(() => {});

  // FIX v15.0: Evict the profile cache entry on login so the fresh profile
  // data (role, permissions, status) is always fetched on the very first
  // authenticated request after login rather than returning stale cached data
  // from a previous session.
  if (evictProfileCache && loginData?.user?.id) {
    evictProfileCache(loginData.user.id); // auth_id = Supabase user UUID
  }

  // ── Set refresh token in HTTP-only cookie ──────────────────────────
  // This is the secure, XSS-safe storage path. The token is also
  // returned in the body for clients that cannot use cookies (native apps).
  res.cookie(RT_COOKIE, refreshToken, RT_COOKIE_OPTS);

  res.json({
    token:        loginData.session.access_token,
    refreshToken,          // Our own refresh token (not Supabase's) — also in httpOnly cookie
    expiresIn:    ACCESS_TOKEN_EXPIRY_SEC,
    expiresAt:    new Date(Date.now() + ACCESS_TOKEN_EXPIRY_SEC * 1000).toISOString(),
    sessionId,
    user: {
      id:          profile.id,
      name:        profile.name,
      email:       profile.email,
      role:        profile.role,
      tenant_id:   profile.tenant_id,
      tenant_slug: tenantMeta?.short_name  || '',
      tenant_name: tenantMeta?.name        || '',
      avatar:      profile.avatar,
      permissions: profile.permissions,
      mfa_enabled: profile.mfa_enabled,
    },
  });
}));

/* ════════════════════════════════════════════════
   POST /api/auth/refresh
   Silent token refresh — rotates refresh token
═══════════════════════════════════════════════ */
router.post('/refresh', asyncHandler(async (req, res) => {
  // Accept refresh token from: (1) HTTP-only cookie [preferred], (2) request body [legacy]
  const oldRefreshToken = req.cookies?.[RT_COOKIE] || req.body.refresh_token || req.cookies?.rt;

  if (!oldRefreshToken) {
    return res.status(400).json({ error: 'refresh_token is required' });
  }

  let rotated;
  try {
    const _rotateTimeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('REFRESH_TIMEOUT')), 20_000)
    );
    rotated = await Promise.race([
      rotateRefreshToken(oldRefreshToken, req),
      _rotateTimeout,
    ]);
  } catch (err) {
    const isTimeout  = err.message === 'REFRESH_TIMEOUT';
    const isNetwork  = err.message?.includes('Failed to fetch') ||
                       err.message?.includes('ECONNREFUSED');
    if (isTimeout || isNetwork) {
      return res.status(503).json({
        error:   'Token refresh service temporarily unavailable. Please try again.',
        code:    'REFRESH_SERVICE_UNAVAILABLE',
        retryIn: 5,
      });
    }
    // v7.4 FIX: Return structured 401 with code field so frontend can distinguish
    // refresh-token-expired from invalid-token and show appropriate UX.
    const refreshErrCode = err.message?.includes('expired')
      ? 'REFRESH_TOKEN_EXPIRED'
      : err.message?.includes('suspended')
      ? 'ACCOUNT_SUSPENDED'
      : err.message?.includes('Session validation')
      ? 'SESSION_VALIDATION_UNAVAILABLE'
      : 'INVALID_REFRESH_TOKEN';

    await logActivity(null, null, 'TOKEN_REFRESH_FAILED', req, {
      success: false,
      failure_reason: err.message,
    });
    return res.status(401).json({
      error: err.message,
      code:  refreshErrCode,
    });
  }

  const { newToken, newSessionId, user, tenantId } = rotated;

  // ── Issue a new access token ──────────────────────────────────────────
  // Strategy 1: Supabase admin.createSession → fresh Supabase JWT (best)
  // Strategy 2: Custom JWT signed with JWT_SECRET (fallback)
  // Strategy 3: Keep original refresh — NEVER return requires_reauth=true
  //
  // ROOT-CAUSE FIX v14.0: requires_reauth=true was the #1 cause of the
  // 401 storm.  When admin.createSession + JWT_SECRET both fail (cold-start
  // or misconfiguration), the old code returned requires_reauth=true which
  // told auth-interceptor to dispatch auth:expired → logout immediately after
  // a successful refresh-token rotation.  The user was forcibly logged out
  // every ~15 minutes even though their session was perfectly valid.
  //
  // FIX: Never send requires_reauth=true.  If we cannot issue a new access
  // token we simply do NOT return a token field — the client keeps its
  // existing access token until it expires naturally, then re-tries /refresh.
  // The rotated refresh token is always returned so the next cycle works.
  let accessToken = '';
  let expiresAt   = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_SEC * 1000).toISOString();

  // ROOT-CAUSE FIX v14.0: Wrap userRow fetch in a 5-second timeout.
  // This DB query previously had NO timeout guard — on Supabase free-tier
  // cold-start it could hang for the full 15 s statement timeout, blocking
  // the entire refresh response and causing the client's 20 s timeout to
  // fire, returning a 503 REFRESH_SERVICE_UNAVAILABLE on every cold-start.
  let userRow = null;
  try {
    const userRowTimeout = new Promise((_, rej) =>
      setTimeout(() => rej(new Error('userRow fetch timed out')), 5_000)
    );
    const userRowPromise = supabase
      .from('users')
      .select('auth_id, email, name, role, permissions, tenant_id')
      .eq('id', user.id)
      .single();
    const { data: _userRow } = await Promise.race([userRowPromise, userRowTimeout]);
    userRow = _userRow || null;
  } catch (uErr) {
    logger.warn('Auth:Refresh', `userRow fetch failed (non-fatal): ${uErr.message}`);
    // Continue with user data from the refresh token rotation result
  }

  const authId = userRow?.auth_id || user.auth_id;

  if (authId) {
    try {
      // Strategy 1: Try Supabase admin to create a session for the auth user.
      // Wrap in a 6-second timeout to avoid hanging on Render cold-start / Supabase
      // connectivity issues that produce AbortError in the backend logs.
      const ADMIN_SESSION_TIMEOUT_MS = 6_000;
      const adminSessionPromise = supabaseAuth.auth.admin.createSession({ user_id: authId }); // ← FIXED: use supabaseAuth
      const timeoutPromise = new Promise((_, rej) =>
        setTimeout(() => rej(new Error('admin.createSession timed out')), ADMIN_SESSION_TIMEOUT_MS)
      );

      const { data: adminSession, error: adminErr } = await Promise.race([
        adminSessionPromise,
        timeoutPromise,
      ]);

      if (!adminErr && adminSession?.session?.access_token) {
        accessToken = adminSession.session.access_token;
        expiresAt   = adminSession.session.expires_at
          ? new Date(adminSession.session.expires_at * 1000).toISOString()
          : expiresAt;
      } else {
        throw new Error(adminErr?.message || 'admin.createSession returned no token');
      }
    } catch (adminErr) {
      logger.warn('Auth:Refresh', `admin.createSession failed: ${adminErr.message} — trying custom JWT signing`);

      // Strategy 2: Sign a custom JWT using JWT_SECRET
      if (JWT_SECRET && jwt) {
        try {
          const payload = {
            iss:  'supabase',
            sub:  authId,
            aud:  'authenticated',
            role: 'authenticated',
            exp:  Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRY_SEC,
            iat:  Math.floor(Date.now() / 1000),
            email:        userRow?.email || user.email,
            app_metadata: {
              provider:    'email',
              providers:   ['email'],
            },
            user_metadata: {
              name:      userRow?.name      || user.name,
              role:      userRow?.role      || user.role,
              tenant_id: userRow?.tenant_id || user.tenant_id,
            },
          };
          accessToken = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
          logger.info('Auth:Refresh', '✅ Custom JWT signed with JWT_SECRET');
        } catch (jwtErr) {
          logger.warn('Auth:Refresh', 'Custom JWT signing failed:', jwtErr.message);
        }
      } else {
        logger.warn('Auth:Refresh', 'JWT_SECRET not configured — Strategy 2 skipped');
      }
    }
  } else {
    logger.warn('Auth:Refresh', `No auth_id found for user ${user.id} — cannot issue new access token`);
  }

  // ROOT-CAUSE FIX v14.0: If we still have no access token (both strategies
  // failed), do NOT set requires_reauth=true.  Instead omit the token field
  // entirely — the client will keep using its existing access token until
  // that expires, then call /refresh again (which will succeed once the
  // backend cold-start is over).  This breaks the logout-on-cold-start loop.
  if (!accessToken) {
    logger.warn('Auth:Refresh', `⚠️  No access token issued for user ${user.id} — returning rotated refresh token only (client keeps existing access token)`);
  }

  await logActivity(user.id, tenantId, 'TOKEN_REFRESH', req, { session_id: newSessionId });

  // Rotate the HTTP-only cookie with the new refresh token
  res.cookie(RT_COOKIE, newToken, RT_COOKIE_OPTS);

  // Build the response object — only include token field when we actually have one.
  // ROOT-CAUSE FIX v14.0: NEVER include requires_reauth=true — it triggers an
  // immediate auth:expired → logout on the client, which is the wrong behaviour
  // when both access-token strategies fail due to cold-start (transient issue).
  const refreshResponse = {
    // Only include token when non-empty — client treats missing token as "keep existing"
    ...(accessToken ? { token: accessToken } : {}),
    refreshToken: newToken,
    expiresIn:    ACCESS_TOKEN_EXPIRY_SEC,
    expiresAt,
    sessionId:    newSessionId,
    user: {
      id:          user.id,
      name:        userRow?.name        || user.name,
      email:       userRow?.email       || user.email,
      role:        userRow?.role        || user.role,
      tenant_id:   userRow?.tenant_id   || user.tenant_id || tenantId,
      permissions: userRow?.permissions || user.permissions,
    },
    // requires_reauth intentionally OMITTED — see ROOT-CAUSE FIX v14.0 above
  };
  res.json(refreshResponse);
}));

/* ════════════════════════════════════════════════
   POST /api/auth/logout
═══════════════════════════════════════════════ */
router.post('/logout', asyncHandler(async (req, res) => {
  // Accept refresh token from HTTP-only cookie or request body
  const refreshToken = req.cookies?.[RT_COOKIE] || req.body.refresh_token;
  const accessToken  = req.headers.authorization?.split(' ')[1];

  // Clear the HTTP-only refresh cookie immediately
  res.clearCookie(RT_COOKIE, { ...RT_COOKIE_OPTS, maxAge: 0 });

  // Revoke refresh token in DB
  if (refreshToken) {
    await supabase
      .from('refresh_tokens')
      .update({ is_revoked: true })
      .eq('token_hash', hashToken(refreshToken));
  }

  // Revoke Supabase session
  if (accessToken) {
    try {
      await supabaseAuth.auth.admin.signOut(accessToken); // ← FIXED: use supabaseAuth
    } catch { /* non-fatal */ }
  }

  await logActivity(req.user?.id || null, req.user?.tenant_id || null, 'LOGOUT', req);

  res.json({ message: 'Logged out successfully' });
}));

/* ════════════════════════════════════════════════
   GET /api/auth/me — current user profile
═══════════════════════════════════════════════ */
router.get('/me', verifyToken, asyncHandler(async (req, res) => {
  const { data: profile } = await supabase
    .from('users')
    .select('id, name, email, role, tenant_id, avatar, permissions, status, mfa_enabled, last_login')
    .eq('id', req.user.id)
    .single();

  const { data: tenantMeta } = await supabase
    .from('tenants')
    .select('short_name, name')
    .eq('id', req.user.tenant_id)
    .single();

  res.json({
    user: {
      ...profile,
      tenant_slug: tenantMeta?.short_name || '',
      tenant_name: tenantMeta?.name       || '',
    }
  });
}));

/* ════════════════════════════════════════════════
   POST /api/auth/register — Admin creates a user
═══════════════════════════════════════════════ */
router.post('/register',
  verifyToken,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { email, password, name, role = 'ANALYST', permissions } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'email, password, and name are required' });
    }

    if (password.length < 12) {
      return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }

    // Create Supabase auth user
    const { data: authUser, error: authErr } = await supabaseAuth.auth.admin.createUser({ // ← FIXED: use supabaseAuth
      email,
      password,
      email_confirm: true,
    });

    if (authErr) {
      return res.status(400).json({ error: authErr.message });
    }

    // Create profile row
    const defaultPerms = role === 'ADMIN'
      ? ['read','write','admin','manage_users','view_audit_logs','export_data']
      : role === 'ANALYST'
      ? ['read','write','manage_iocs','manage_cases']
      : ['read'];

    const { data: profile, error: profileErr } = await supabase
      .from('users')
      .insert({
        auth_id:     authUser.user.id,
        tenant_id:   req.user.tenant_id,
        email,
        name,
        role,
        permissions: permissions || defaultPerms,
        status:      'active',
        created_by:  req.user.id,
      })
      .select()
      .single();

    if (profileErr) {
      // Rollback Supabase auth user
      await supabaseAuth.auth.admin.deleteUser(authUser.user.id); // ← FIXED: use supabaseAuth
      throw new Error(profileErr.message);
    }

    await logActivity(req.user.id, req.user.tenant_id, 'USER_CREATED', req, {
      email: `Created user: ${email}`,
    });

    res.status(201).json({ user: profile });
  })
);

/* ════════════════════════════════════════════════
   GET /api/auth/sessions — User's active sessions
═══════════════════════════════════════════════ */
router.get('/sessions', verifyToken, asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('refresh_tokens')
    .select('id, device_info, created_at, last_used_at, expires_at')
    .eq('user_id', req.user.id)
    .eq('is_revoked', false)
    .gt('expires_at', new Date().toISOString())
    .order('last_used_at', { ascending: false });

  if (error) throw new Error(error.message);
  res.json({ sessions: data || [] });
}));

/* ════════════════════════════════════════════════
   DELETE /api/auth/sessions/:id — Revoke session
═══════════════════════════════════════════════ */
router.delete('/sessions/:id', verifyToken, asyncHandler(async (req, res) => {
  const { error } = await supabase
    .from('refresh_tokens')
    .update({ is_revoked: true })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id); // Ensure user owns this session

  if (error) throw new Error(error.message);
  res.json({ message: 'Session revoked' });
}));

/* ════════════════════════════════════════════════
   DELETE /api/auth/sessions — Revoke ALL sessions
═══════════════════════════════════════════════ */
router.delete('/sessions', verifyToken, asyncHandler(async (req, res) => {
  await supabase
    .from('refresh_tokens')
    .update({ is_revoked: true })
    .eq('user_id', req.user.id);

  res.json({ message: 'All sessions revoked' });
}));

/* ════════════════════════════════════════════════
   GET /api/auth/activity — Login history
═══════════════════════════════════════════════ */
router.get('/activity', verifyToken, asyncHandler(async (req, res) => {
  const limit = Math.min(100, parseInt(req.query.limit) || 20);

  const { data, error } = await supabase
    .from('login_activity')
    .select('id, action, ip_address, device_info, success, failure_reason, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) throw new Error(error.message);
  res.json({ activity: data || [] });
}));

/* ════════════════════════════════════════════════
   POST /api/auth/refresh-from-cookie
   Cookie-based token refresh (no body needed).
   Called by auth-interceptor.js when:
     - No refresh token is found in localStorage
     - The browser may still hold an httpOnly session cookie
   Strategy: Use the httpOnly session cookie (set by Supabase/login)
   to get a new access token via Supabase's admin createSession.
═══════════════════════════════════════════════ */
router.post('/refresh-from-cookie', asyncHandler(async (req, res) => {
  // Try to find a Supabase session token in the httpOnly cookie
  const cookieToken = req.cookies?.access_token || req.cookies?.token || req.cookies?.sb_access_token;

  if (!cookieToken) {
    return res.status(400).json({
      error: 'No session cookie found. Please log in again.',
      code:  'NO_COOKIE',
    });
  }

  // Validate the cookie token to get the user
  try {
    const { data: { user }, error: authError } = await supabaseAuth.auth.getUser(cookieToken); // ← FIXED: use supabaseAuth

    if (authError || !user) {
      return res.status(401).json({
        error: 'Cookie session expired. Please log in again.',
        code:  'COOKIE_EXPIRED',
      });
    }

    // Fetch user profile
    const { data: profile } = await supabase
      .from('users')
      .select('id, name, email, role, tenant_id, auth_id, permissions, status')
      .eq('auth_id', user.id)
      .single();

    if (!profile || profile.status !== 'active') {
      return res.status(403).json({ error: 'Account inactive or not found.', code: 'ACCOUNT_INACTIVE' });
    }

    // Issue new tokens: access + refresh
    let accessToken = cookieToken; // reuse the valid cookie token as access token
    let expiresAt   = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_SEC * 1000).toISOString();

    // Try to create a fresh Supabase session
    try {
      const { data: adminSession, error: adminErr } = await supabaseAuth.auth.admin.createSession({ // ← FIXED: use supabaseAuth
        user_id: user.id,
      });
      if (!adminErr && adminSession?.session?.access_token) {
        accessToken = adminSession.session.access_token;
        expiresAt   = adminSession.session.expires_at
          ? new Date(adminSession.session.expires_at * 1000).toISOString()
          : expiresAt;
      }
    } catch (adminErr) {
      // Fall back to the cookie token — it's still valid per getUser() above
      logger.warn('Auth:CookieRefresh', `admin.createSession failed, using cookie token: ${adminErr.message}`);
    }

    // Issue a new refresh token
    const refreshToken = generateRefreshToken();
    const sessionId    = await storeRefreshToken(profile.id, profile.tenant_id, refreshToken, req);

    await logActivity(profile.id, profile.tenant_id, 'TOKEN_REFRESH_FROM_COOKIE', req, { session_id: sessionId });

    logger.info('Auth:CookieRefresh', `✅ succeeded for ${profile.email}`);

    return res.json({
      token:        accessToken,
      refreshToken,
      expiresIn:    ACCESS_TOKEN_EXPIRY_SEC,
      expiresAt,
      sessionId,
      user: {
        id:          profile.id,
        name:        profile.name,
        email:       profile.email,
        role:        profile.role,
        tenant_id:   profile.tenant_id,
        permissions: profile.permissions,
      },
    });

  } catch (err) {
    logger.warn('Auth:CookieRefresh', 'error:', err.message);
    return res.status(401).json({
      error: 'Session restoration failed. Please log in again.',
      code:  'REFRESH_FAILED',
    });
  }
}));

/* ════════════════════════════════════════════════
   GET /api/auth/diagnostics
   Public endpoint — returns Supabase auth health
   Used to diagnose login failures without exposing secrets
═══════════════════════════════════════════════ */
router.get('/diagnostics', asyncHandler(async (req, res) => {
  const start = Date.now();
  const diag  = {
    timestamp: new Date().toISOString(),
    supabase: { reachable: false, latencyMs: null, error: null, method: 'direct-axios' },
    config: {
      hasJwtSecret:     !!JWT_SECRET,
      hasSupabaseUrl:   !!process.env.SUPABASE_URL,
      hasServiceKey:    !!(process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY),
      hasAnonKey:       !!process.env.SUPABASE_ANON_KEY,
    },
    authRoutePublic: true,
    version: '7.4',
  };

  try {
    // v7.3: Use direct axios to test Supabase reachability (not GoTrueClient)
    // This tells us whether the auth endpoint responds within 8s via axios
    const ax = require('axios');
    const loginKey = process.env.SUPABASE_ANON_KEY ||
                     process.env.SUPABASE_SERVICE_KEY ||
                     process.env.SUPABASE_SECRET_KEY || '';
    const supabaseUrl = process.env.SUPABASE_URL || '';

    const diagResp = await ax.get(`${supabaseUrl}/auth/v1/health`, {
      timeout: 8_000,
      headers: { 'apikey': loginKey, 'Content-Type': 'application/json' },
      validateStatus: () => true,
    });

    diag.supabase.latencyMs = Date.now() - start;

    if (diagResp.status === 200) {
      diag.supabase.reachable    = true;
      diag.supabase.authService  = 'operational';
    } else if (diagResp.status === 401) {
      // 401 = auth service IS up but key is invalid/missing
      diag.supabase.reachable    = true;
      diag.supabase.authService  = diag.config.hasAnonKey ? 'operational' : 'key-missing';
      diag.supabase.error        = `Auth endpoint returned 401 — check SUPABASE_ANON_KEY`;
    } else {
      diag.supabase.reachable    = false;
      diag.supabase.error        = `Unexpected status ${diagResp.status}`;
      diag.supabase.authService  = 'error';
    }
  } catch (err) {
    diag.supabase.latencyMs   = Date.now() - start;
    diag.supabase.reachable   = false;
    diag.supabase.error       = err.message;
    diag.supabase.authService = 'unreachable';
    diag.supabase.errorCode   = err.code;
  }

  const status = diag.supabase.reachable && diag.config.hasSupabaseUrl && diag.config.hasServiceKey
    ? 200 : 503;

  return res.status(status).json(diag);
}));

module.exports = router;
