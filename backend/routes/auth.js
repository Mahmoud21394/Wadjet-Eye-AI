/**
 * ══════════════════════════════════════════════════════════
 *  Enterprise Auth Routes v7.0 — Timeout Root-Cause Fix
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
const {
  supabase,
  supabaseAuth,
  supabaseIngestion,
  createLoginClient,
  isAbortError,
  isNetworkError,
  isTimeoutError,
  LOGIN_FETCH_TIMEOUT_MS,
} = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// jsonwebtoken — optional dependency for custom JWT signing on refresh
// Run: npm install jsonwebtoken   (in backend/)
let jwt = null;
try {
  jwt = require('jsonwebtoken');
} catch (_) {
  console.warn('[Auth] jsonwebtoken not installed — custom JWT fallback disabled.');
  console.warn('[Auth] Run: cd backend && npm install jsonwebtoken');
}

/* ════════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════ */
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS || '30');
const ACCESS_TOKEN_EXPIRY_SEC   = parseInt(process.env.ACCESS_TOKEN_TTL || '900');

// Supabase JWT Secret — used to sign custom access tokens on refresh
// MUST match the value in Supabase Dashboard → Settings → API → JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || null;

if (!JWT_SECRET) {
  console.warn('[Auth] ⚠️  JWT_SECRET not set in .env!');
  console.warn('[Auth]    Get it from: Supabase Dashboard → Settings → API → JWT Settings');
  console.warn('[Auth]    Add to backend/.env:  JWT_SECRET=<your-supabase-jwt-secret>');
}

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
          console.warn('[Auth] Failed to log activity:', error.message);
        }
      }
    } catch (err) {
      // Non-fatal — never block login if audit logging fails
      if (!isAbortError(err)) {
        console.warn('[Auth] logActivity error:', err.message);
      }
    }
  })();

  // Race: complete within 5s or give up silently
  await Promise.race([logPromise, logTimer]);
}

/** Store a new refresh token in DB
 *  RLS-safe: if the insert fails due to RLS policy (e.g. table not yet
 *  migrated or policy missing), we log a warning and return a fallback UUID
 *  so the LOGIN still succeeds. The refresh token will just not be persisted.
 *  Fix: run backend/database/rls-fix-v5.1.sql in Supabase SQL Editor.
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
        console.warn('[Auth] ⚠️  refresh_tokens RLS blocked insert.');
        console.warn('[Auth]    FIX: Run backend/database/rls-fix-v5.1.sql in Supabase SQL Editor');
        console.warn('[Auth]    Login will proceed without persisted refresh token.');
        return crypto.randomUUID(); // Return a fake session ID so login continues
      }
      if (noTable) {
        console.warn('[Auth] ⚠️  refresh_tokens table missing.');
        console.warn('[Auth]    FIX: Run backend/database/migration-v5.0-auth-tables.sql first.');
        return crypto.randomUUID();
      }
      // Other errors — throw to surface them
      throw new Error('Failed to store refresh token: ' + error.message);
    }

    return data.id;
  } catch (err) {
    // Catch network errors too
    if (err.message?.includes('Failed to store refresh token')) throw err;
    console.warn('[Auth] storeRefreshToken unexpected error:', err.message);
    return crypto.randomUUID(); // Non-fatal fallback
  }
}

/** Validate + rotate a refresh token */
async function rotateRefreshToken(oldToken, req) {
  const hash = hashToken(oldToken);

  const { data: rt, error } = await supabase
    .from('refresh_tokens')
    .select('*, users(id, name, email, role, tenant_id, status, permissions, avatar)')
    .eq('token_hash', hash)
    .eq('is_revoked', false)
    .single();

  if (error) {
    const isRLS   = error.message?.includes('row-level security') || error.code === '42501';
    const noTable = error.message?.includes('does not exist') || error.code === '42P01';
    if (isRLS || noTable) {
      // RLS / missing table — token can't be verified in DB, force re-login
      throw new Error('Session validation unavailable. Please log in again.');
    }
    throw new Error('Invalid or expired refresh token');
  }

  if (!rt) {
    throw new Error('Invalid or expired refresh token');
  }

  if (new Date(rt.expires_at) < new Date()) {
    // Clean up expired token
    await supabase.from('refresh_tokens').delete().eq('id', rt.id);
    throw new Error('Refresh token has expired. Please log in again.');
  }

  if (rt.users?.status !== 'active') {
    throw new Error('Account is suspended');
  }

  // ── Rotate: revoke old, issue new ──
  const newToken = generateRefreshToken();

  await supabase.from('refresh_tokens').update({
    is_revoked:   true,
    last_used_at: new Date().toISOString(),
  }).eq('id', rt.id);

  const newSessionId = await storeRefreshToken(rt.user_id, rt.tenant_id, newToken, req);

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
  console.log(`[auth:login:start] ${email} from ${req.ip || 'unknown'} at ${new Date().toISOString()}`);

  // ── v7.0 FIX: Create a FRESH per-request Supabase client for login ─────────
  // ROOT CAUSE: GoTrueClient._acquireLock uses an internal pendingInLock queue.
  // In Node.js (no Web Locks API), operations queue serially. When signOut()
  // is called before signInWithPassword on the SAME client instance, signOut
  // takes the lock first. If signOut stalls (DNS + TLS cold-start: 8-15s),
  // signInWithPassword waits in queue — combined wait hits our 25s timeout.
  //
  // SOLUTION: Fresh client per login = empty pendingInLock queue = no queue stall.
  // DO NOT call signOut() on this client — that is the whole point of a fresh instance.
  const _loginClient = createLoginClient();
  console.log(`[auth:login:supabase] created fresh login client for ${email}`);

  // ── Authenticate via Supabase ────────────────────────────────────────────────
  // 35s timeout = Render cold-start (8s) + DNS (5s) + TLS (3s) + PgBouncer (5s)
  //              + network latency (2s) + signInWithPassword processing (5s)
  //              + 7s safety margin
  const LOGIN_HARD_TIMEOUT_MS = LOGIN_FETCH_TIMEOUT_MS + 5_000; // 40s hard outer timeout
  const _supabaseLoginTimeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('SUPABASE_TIMEOUT')), LOGIN_HARD_TIMEOUT_MS)
  );
  let loginData, loginError;
  try {
    ({ data: loginData, error: loginError } = await Promise.race([
      _loginClient.auth.signInWithPassword({  // ← v7.0: fresh per-request client
        email:    email.trim().toLowerCase(),
        password: password.trim(),
      }),
      _supabaseLoginTimeout,
    ]));
    console.log(`[auth:login:result] elapsed=${Date.now()-loginStart}ms ` +
      `loginError=${loginError ? loginError.message : 'none'} ` +
      `session=${loginData?.session ? 'present' : 'absent'}`);
  } catch (supabaseErr) {
    // Catch AbortError/timeout/network in THROWN form.
    // AbortError returned in ERROR FIELD is handled below (loginError check).
    const isAbort   = isAbortError(supabaseErr);
    const isTimeout = supabaseErr.message === 'SUPABASE_TIMEOUT';
    const isNetwork = isNetworkError(supabaseErr);

    const elapsed = Date.now() - loginStart;
    console.error(`[auth:login:abort] THROWN ${supabaseErr.name}: ${supabaseErr.message} elapsed=${elapsed}ms`);

    if (isAbort || isTimeout || isNetwork) {
      const reason = isTimeout ? `timeout after ${elapsed}ms` :
                     isAbort   ? `aborted after ${elapsed}ms` :
                                 `network error after ${elapsed}ms`;
      console.error(`[auth:login:503] Returning 503 — ${reason}`);
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
    // v6.1 FIX: Check if loginError IS an AbortError BEFORE treating it as bad credentials.
    // The Supabase SDK returns AbortError in the error FIELD (not thrown):
    //   { data: null, error: DOMException { name: 'AbortError', message: 'This operation was aborted' } }
    // Previously this fell through to the generic 401 handler, masking the real cause.
    if (isAbortError(loginError)) {
      console.error(`[auth:login:abort] RETURNED AbortError in loginError: ${loginError.message} ` +
        `elapsed=${Date.now()-loginStart}ms`);
      logActivity(null, null, 'LOGIN_FAILED', req, {
        email, success: false, failure_reason: `AbortError: ${loginError.message}`,
      }).catch(() => {});
      return res.status(503).json({
        error:   'Authentication service temporarily unavailable (request aborted). Please try again in a few seconds.',
        code:    'AUTH_SERVICE_UNAVAILABLE',
        retryIn: 5,
      });
    }

    // Log asynchronously — don't await so we don't hang on Supabase issues
    logActivity(null, null, 'LOGIN_FAILED', req, {
      email,
      success: false,
      failure_reason: loginError.message,
    }).catch(() => {});

    console.warn(`[auth:login:fail] LOGIN_FAILED for ${email}: ` +
      `"${loginError.message}" (status=${loginError.status} code=${loginError.code}) ` +
      `elapsed=${Date.now()-loginStart}ms`);

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

    // Generic 401 for any other Supabase auth failure
    return res.status(401).json({
      error: 'Invalid email or password',
      code:  'INVALID_CREDENTIALS',
      _supabaseMsg: process.env.NODE_ENV !== 'production' ? loginError.message : undefined,
    });
  }

  console.log(`[auth:login:ok] Supabase auth OK for ${email} elapsed=${Date.now()-loginStart}ms`);

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
      console.error(`[auth:login:db-timeout] Profile lookup timed out after ${profileMs}ms for ${email}`);
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
    console.warn(`[auth:login:no-profile] No users row for auth_id=${loginData.user.id} email=${email}: ${profileError.message}`);
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
      if (ulErr && !isAbortError(ulErr)) console.warn('[auth:login] last_login update failed:', ulErr.message);
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
      console.warn('[auth:login] tenantMeta fetch error:', tmErr.message);
    }
    tenantMeta = tm || null;
  } catch (_) {
    // Non-fatal — tenant slug/name will be empty strings
  }

  // Fire-and-forget login success audit
  logActivity(profile.id, profile.tenant_id, 'LOGIN_SUCCESS', req, {
    email, session_id: sessionId,
  }).catch(() => {});

  res.json({
    token:        loginData.session.access_token,
    refreshToken,          // Our own refresh token (not Supabase's)
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
  const oldRefreshToken = req.body.refresh_token || req.cookies?.rt;

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
    await logActivity(null, null, 'TOKEN_REFRESH_FAILED', req, {
      success: false,
      failure_reason: err.message,
    });
    return res.status(401).json({ error: err.message });
  }

  const { newToken, newSessionId, user, tenantId } = rotated;

  // ── Issue a new access token ──────────────────────────────────────────
  // Strategy 1: Re-authenticate via Supabase signInWithPassword using
  //             admin API to get a fresh Supabase JWT (best approach)
  // Strategy 2: Sign a custom JWT using JWT_SECRET (fallback)
  // Strategy 3: Return empty token — client will use refresh token only
  let accessToken = '';
  let expiresAt   = new Date(Date.now() + ACCESS_TOKEN_EXPIRY_SEC * 1000).toISOString();

  // Fetch auth_id for the user
  const { data: userRow } = await supabase
    .from('users')
    .select('auth_id, email, name, role, permissions, tenant_id')
    .eq('id', user.id)
    .single();

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
      console.warn('[Auth] admin.createSession failed:', adminErr.message);
      console.warn('[Auth] Trying custom JWT signing as fallback...');

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
          console.log('[Auth] ✅ Refresh: Custom JWT signed with JWT_SECRET');
        } catch (jwtErr) {
          console.warn('[Auth] Custom JWT signing failed:', jwtErr.message);
        }
      } else {
        console.warn('[Auth] JWT_SECRET not configured — cannot sign custom JWT');
        console.warn('[Auth] Client will retry login to get a fresh Supabase token');
      }
    }
  } else {
    console.warn('[Auth] No auth_id found for user', user.id, '— cannot issue new access token');
  }

  await logActivity(user.id, tenantId, 'TOKEN_REFRESH', req, { session_id: newSessionId });

  // Always return the rotated refresh token even if access token is empty.
  // The client can call /api/auth/me with the old access token or trigger re-login.
  res.json({
    token:        accessToken,
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
    // Tell client if they need to re-authenticate (no new access token)
    requires_reauth: !accessToken,
  });
}));

/* ════════════════════════════════════════════════
   POST /api/auth/logout
═══════════════════════════════════════════════ */
router.post('/logout', asyncHandler(async (req, res) => {
  const refreshToken = req.body.refresh_token;
  const accessToken  = req.headers.authorization?.split(' ')[1];

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
      console.warn('[Auth] refresh-from-cookie: admin.createSession failed, using cookie token:', adminErr.message);
    }

    // Issue a new refresh token
    const refreshToken = generateRefreshToken();
    const sessionId    = await storeRefreshToken(profile.id, profile.tenant_id, refreshToken, req);

    await logActivity(profile.id, profile.tenant_id, 'TOKEN_REFRESH_FROM_COOKIE', req, { session_id: sessionId });

    console.log('[Auth] ✅ refresh-from-cookie succeeded for', profile.email);

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
    console.warn('[Auth] refresh-from-cookie error:', err.message);
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
    supabase: { reachable: false, latencyMs: null, error: null },
    config: {
      hasJwtSecret:     !!JWT_SECRET,
      hasSupabaseUrl:   !!process.env.SUPABASE_URL,
      hasServiceKey:    !!(process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY),
      hasAnonKey:       !!process.env.SUPABASE_ANON_KEY,
    },
    authRoutePublic: true,
    version: '5.1',
  };

  try {
    // Test Supabase auth by doing a no-op sign-in with invalid creds
    // This tells us whether the Supabase Auth service is reachable
    const { error } = await Promise.race([
      supabaseAuth.auth.signInWithPassword({ email: 'diag-probe@noreply.test', password: 'x' }), // ← FIXED: use supabaseAuth
      new Promise((_, rej) => setTimeout(() => rej(new Error('DIAG_TIMEOUT')), 8_000)),
    ]);
    diag.supabase.latencyMs = Date.now() - start;

    if (error) {
      // If we get an auth error (Invalid credentials, etc.), Supabase IS reachable
      // Only timeout / network / abort = not reachable
      const msg = error.message?.toLowerCase() || '';
      if (msg.includes('invalid') || msg.includes('not found') || msg.includes('credentials')) {
        diag.supabase.reachable = true;
        diag.supabase.authService = 'operational';
      } else {
        diag.supabase.reachable = false;
        diag.supabase.error = error.message;
        diag.supabase.authService = 'error';
      }
    } else {
      diag.supabase.reachable = true;
      diag.supabase.authService = 'operational';
    }
  } catch (err) {
    diag.supabase.latencyMs = Date.now() - start;
    diag.supabase.reachable = false;
    diag.supabase.error     = err.message;
    diag.supabase.authService = 'unreachable';
  }

  const status = diag.supabase.reachable && diag.config.hasSupabaseUrl && diag.config.hasServiceKey
    ? 200 : 503;

  return res.status(status).json(diag);
}));

module.exports = router;
