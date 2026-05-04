/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Auth Middleware v6.1 (v7.4 abort fix)
 *  backend/middleware/auth.js
 *
 *  Phase 1 Security Hardening:
 *  ──────────────────────────
 *  1. Token extraction priority: httpOnly Cookie → Authorization header → X-Access-Token
 *     Query-param tokens REMOVED (leaked in server logs / browser history).
 *
 *  2. Added requireTenant() — tenant isolation guard that verifies
 *     req.user.tenant_id matches the :tenantId route param (or body field).
 *
 *  3. Enhanced logging: every 401/403 includes method, path, IP.
 *
 *  4. verifyToken() returns structured error JSON with 'code' field.
 *
 *  5. optionalAuth() — non-blocking; sets req.user when token present.
 *
 *  6. authInfo() — returns sanitized token status (for debug endpoints).
 *
 *  Breaking changes vs v5:
 *   - Query param token extraction REMOVED. WebSocket handshake must
 *     use socket.handshake.auth.token (not query.token).
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const jwt = require('jsonwebtoken');
const { supabase, supabaseAuth, isAbortError, isTimeoutError } = require('../config/supabase'); // v7.0

// ── JWT_SECRET for local fast-path decode ────────────────────────
// Supabase JWTs are signed with the project's JWT secret.
// SUPABASE_JWT_SECRET (preferred) or JWT_SECRET (fallback).
// This lets us verify token signature and expiry locally — without a
// Supabase network round-trip — so cold-start latency never causes 503.
const _JWT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;

// ── Token extraction ───────────────────────────────────────────
// Priority: httpOnly cookie → Authorization header → X-Access-Token header
// Query-param tokens intentionally excluded (Phase 1 hardening).
function extractToken(req) {
  // 1. httpOnly secure cookie (preferred — not accessible from JS)
  const cookieToken = req.cookies?.access_token || req.cookies?.token;
  if (cookieToken) {
    return { token: cookieToken, source: 'httpOnly-cookie' };
  }

  // 2. Standard Authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return { token: authHeader.split(' ')[1], source: 'Authorization-header' };
  }

  // 3. X-Access-Token header (legacy frontend support)
  const xToken = req.headers['x-access-token'];
  if (xToken) {
    return { token: xToken, source: 'X-Access-Token-header' };
  }

  // NOTE: query param extraction intentionally removed (Phase 1).
  // If you see MISSING_TOKEN for WebSocket, ensure socket.handshake.auth.token is set.
  return { token: null, source: null };
}

/**
 * verifyToken — primary auth middleware
 *
 * Attaches to req:
 *   req.user     — full user profile (id, email, name, role, tenant_id, permissions)
 *   req.tenantId — tenant_id shortcut
 *   req.token    — raw JWT string
 *
 * Returns structured 401/403 with 'code' field:
 *   MISSING_TOKEN    — no token at all → redirect to login
 *   INVALID_TOKEN    — token can't be decoded → force re-login
 *   EXPIRED_TOKEN    — token expired → try refresh endpoint
 *   PROFILE_MISSING  — auth OK but no user record → contact support
 *   ACCOUNT_INACTIVE — user suspended → show suspension message
 */
async function verifyToken(req, res, next) {
  const { token, source } = extractToken(req);
  const reqId = req.id || req.headers['x-request-id'] || '-';

  // ── Guard: Supabase not configured (no env vars set) ──────────────
  // In development/demo mode the Supabase client is null.
  // Rather than crashing with "Cannot read properties of null", return a
  // clear 503 so callers know to configure the backend.
  if (!supabaseAuth) {
    console.warn(`[Auth] 503 SUPABASE_NOT_CONFIGURED reqId=${reqId} ${req.method} ${req.path}`);
    return res.status(503).json({
      error:   'Authentication service not configured. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in environment.',
      code:    'SUPABASE_NOT_CONFIGURED',
      hint:    'Copy backend/.env.example → backend/.env and fill in Supabase credentials.',
    });
  }

  if (!token) {
    console.warn(`[Auth] 401 MISSING_TOKEN reqId=${reqId} ${req.method} ${req.path} ip=${_ip(req)}`);
    return res.status(401).json({
      error:   'Missing or invalid Authorization header',
      code:    'MISSING_TOKEN',
      hint:    'Include: Authorization: Bearer <your_token>  OR  use httpOnly cookie',
      path:    req.path,
    });
  }

  // ── v8.0: JWT LOCAL FAST-PATH ────────────────────────────────────
  // ROOT CAUSE of 503 VERIFY_TIMEOUT cascade:
  //   supabaseAuth.auth.getUser(token) makes a NETWORK CALL to Supabase
  //   on every single request. During Render cold-start or Supabase free-
  //   tier hibernation (0-8 s latency), this times out → every request
  //   gets 503 → the entire platform appears down for minutes.
  //
  // SOLUTION:
  //   1. Verify the JWT signature LOCALLY with jsonwebtoken (zero network).
  //      This catches 99% of requests instantly (<1ms).
  //   2. Only fall back to supabaseAuth.getUser() when local verify fails
  //      (which means the token was not issued by Supabase, i.e. truly invalid).
  //   3. Then fetch the user profile from the DB (supabase) — this IS still
  //      a network call, but: (a) it uses the service-role client which has
  //      a connection pool, (b) profile fetches are fast DB reads, not auth
  //      network calls, and (c) failures here give a clean 401 not 503.
  //
  // SECURITY: JWT signature + expiry verified locally. The secret used is
  // SUPABASE_JWT_SECRET (your Supabase project JWT secret from Settings →
  // API). If not set, falls back to JWT_SECRET.  If neither is set, we
  // keep the old supabaseAuth path as last resort.
  if (_JWT_SECRET) {
    let localDecoded;
    try {
      localDecoded = jwt.verify(token, _JWT_SECRET, { algorithms: ['HS256'] });
    } catch (jwtErr) {
      // Local verify failed → token is invalid or expired
      const isExpired = jwtErr.name === 'TokenExpiredError';
      if (isExpired) {
        return res.status(401).json({
          error: 'Token has expired. Please refresh your session.',
          code:  'EXPIRED_TOKEN',
        });
      }
      return res.status(401).json({
        error: 'Invalid token. Please log in again.',
        code:  'INVALID_TOKEN',
      });
    }

    // Token is cryptographically valid — extract Supabase user id
    // Supabase JWTs store the user UUID in the 'sub' claim.
    const authUserId = localDecoded.sub;
    const userEmail  = localDecoded.email || null;

    // Fetch user profile from DB (fast pool connection — not auth network)
    try {
      const { data: profile, error: profileError } = await supabase
        .from('users')
        .select('id, name, email, role, tenant_id, status, permissions, avatar, mfa_enabled')
        .eq('auth_id', authUserId)
        .single();

      if (!profileError && profile) {
        if (profile.status === 'suspended' || profile.status === 'inactive') {
          console.warn(`[Auth] 403 ACCOUNT_INACTIVE user=${profile.email} status=${profile.status}`);
          return res.status(403).json({
            error:  `Account is ${profile.status}. Contact your administrator.`,
            code:   'ACCOUNT_INACTIVE',
            status: profile.status,
          });
        }
        req.user     = { ...profile, authId: authUserId };
        req.tenantId = profile.tenant_id;
        req.token    = token;
        return next();
      }

      // Profile not found by auth_id → try email fallback
      if (userEmail) {
        const { data: profileByEmail } = await supabase
          .from('users')
          .select('id, name, email, role, tenant_id, status, permissions, avatar')
          .eq('email', userEmail)
          .single();

        if (profileByEmail) {
          req.user     = { ...profileByEmail, authId: authUserId };
          req.tenantId = profileByEmail.tenant_id;
          req.token    = token;
          return next();
        }
      }

      // Profile truly missing — return 401 not 503
      console.warn(`[Auth] 401 PROFILE_MISSING auth_id=${authUserId} email=${userEmail}`);
      return res.status(401).json({
        error: 'User profile not found. Please contact your administrator.',
        code:  'PROFILE_MISSING',
        email: userEmail,
      });
    } catch (dbErr) {
      // DB error during profile fetch — return 503 with retry hint
      // (This is a DB issue, not an auth issue — don't cascade to login)
      if (isAbortError(dbErr) || isTimeoutError(dbErr)) {
        console.error(`[Auth] 503 DB_ABORT profile fetch reqId=${reqId}: ${dbErr.message}`);
        return res.status(503).json({
          error: 'Database temporarily unavailable. Please retry in a moment.',
          code:  'DB_SERVICE_UNAVAILABLE',
          retryAfter: 3,
        });
      }
      console.error(`[Auth] 500 profile fetch error reqId=${reqId}:`, dbErr.message);
      return res.status(500).json({
        error: 'Authentication service error. Please try again.',
        code:  'AUTH_SERVICE_ERROR',
      });
    }
  }

  // ── FALLBACK: supabaseAuth.getUser() path ───────────────────────
  // Only reached when _JWT_SECRET is not set (i.e. SUPABASE_JWT_SECRET
  // and JWT_SECRET are both absent from env).
  // Wrap in timeout to limit cold-start damage.
  const VERIFY_TIMEOUT_MS = 12_000;
  let _verifyTimeoutId;
  const _timeoutPromise = new Promise((_, rej) => {
    _verifyTimeoutId = setTimeout(
      () => rej(new Error('Supabase auth verification timed out')),
      VERIFY_TIMEOUT_MS
    );
  });

  try {
    const { data: { user }, error: authError } = await Promise.race([
      supabaseAuth.auth.getUser(token),
      _timeoutPromise,
    ]);
    clearTimeout(_verifyTimeoutId);

    if (authError) {
      if (isAbortError(authError) || isTimeoutError(authError)) {
        console.error(`[Auth] 503 AUTH_ABORT src=${source} reqId=${reqId} ${req.method} ${req.path}: ${authError.message}`);
        clearTimeout(_verifyTimeoutId);
        return res.status(503).json({
          error: 'Authentication service temporarily unavailable. Please retry in a moment.',
          code:  'AUTH_SERVICE_UNAVAILABLE',
          retryAfter: 5,
        });
      }
      const isExpired = authError.message?.toLowerCase().includes('expired') ||
                        authError.message?.toLowerCase().includes('jwt expired');
      const code = isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN';
      console.warn(`[Auth] 401 ${code} src=${source} reqId=${reqId} ${req.method} ${req.path}: ${authError.message}`);
      return res.status(401).json({
        error: isExpired ? 'Token has expired. Please refresh your session.' : 'Invalid token. Please log in again.',
        code,
        message: authError.message,
      });
    }

    if (!user) {
      console.warn(`[Auth] 401 INVALID_TOKEN src=${source} reqId=${reqId} ${req.method} ${req.path}`);
      return res.status(401).json({ error: 'Token verification failed', code: 'INVALID_TOKEN' });
    }

    // Fetch user profile
    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('id, name, email, role, tenant_id, status, permissions, avatar, mfa_enabled')
      .eq('auth_id', user.id)
      .single();

    if (profileError || !profile) {
      const { data: profileByEmail } = await supabase
        .from('users')
        .select('id, name, email, role, tenant_id, status, permissions, avatar')
        .eq('email', user.email)
        .single();

      if (profileByEmail) {
        req.user     = { ...profileByEmail, authId: user.id };
        req.tenantId = profileByEmail.tenant_id;
        req.token    = token;
        return next();
      }

      console.warn(`[Auth] 401 PROFILE_MISSING auth_id=${user.id} email=${user.email}`);
      return res.status(401).json({
        error: 'User profile not found. Please contact your administrator.',
        code:  'PROFILE_MISSING',
        email: user.email,
      });
    }

    if (profile.status === 'suspended' || profile.status === 'inactive') {
      console.warn(`[Auth] 403 ACCOUNT_INACTIVE user=${profile.email} status=${profile.status}`);
      return res.status(403).json({
        error:  `Account is ${profile.status}. Contact your administrator.`,
        code:   'ACCOUNT_INACTIVE',
        status: profile.status,
      });
    }

    req.user     = { ...profile, authId: user.id };
    req.tenantId = profile.tenant_id;
    req.token    = token;
    next();

  } catch (err) {
    clearTimeout(_verifyTimeoutId);
    if (isAbortError(err)) {
      console.error(`[Auth] 503 verifyToken AbortError reqId=${reqId}: ${err.message}`);
      return res.status(503).json({
        error: 'Auth service temporarily unavailable (aborted). Please retry.',
        code:  'AUTH_SERVICE_UNAVAILABLE',
        retryAfter: 3,
      });
    }
    if (err.message?.includes('timed out')) {
      console.warn(`[Auth] 503 VERIFY_TIMEOUT reqId=${reqId} ${req.method} ${req.path} — add SUPABASE_JWT_SECRET to env to eliminate this`);
      return res.status(503).json({
        error: 'Authentication service temporarily unavailable. Please retry in a moment.',
        code:  'AUTH_SERVICE_TIMEOUT',
        retryAfter: 5,
      });
    }
    console.error(`[Auth] Exception reqId=${reqId} ${req.method} ${req.path}:`, err.message);
    return res.status(500).json({
      error: 'Authentication service error. Please try again.',
      code:  'AUTH_SERVICE_ERROR',
    });
  }
}

/**
 * optionalAuth — non-blocking auth middleware
 * Sets req.user if token is valid, continues even if not.
 */
async function optionalAuth(req, res, next) {
  const { token } = extractToken(req);
  if (!token || !supabaseAuth) return next();

  try {
    const { data: { user } } = await supabaseAuth.auth.getUser(token); // v6.1: use supabaseAuth
    if (user) {
      const { data: profile } = await supabase
        .from('users')
        .select('id, name, email, role, tenant_id, status, permissions')
        .eq('auth_id', user.id)
        .single();

      if (profile && profile.status === 'active') {
        req.user     = { ...profile, authId: user.id };
        req.tenantId = profile.tenant_id;
        req.token    = token;
      }
    }
  } catch (_) { /* silent — optional auth never blocks */ }

  next();
}

/**
 * requireRole — RBAC middleware factory
 * @param {string|string[]} roles - Allowed role names
 */
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    }
    const roleList = Array.isArray(roles) ? roles : [roles];
    if (!roleList.includes(req.user.role)) {
      console.warn(`[Auth] 403 INSUFFICIENT_ROLE user=${req.user.email} role=${req.user.role} required=${roleList.join(',')}`);
      return res.status(403).json({
        error:    `Access denied. Required role: ${roleList.join(' or ')}`,
        code:     'INSUFFICIENT_ROLE',
        yourRole: req.user.role,
        required: roleList,
      });
    }
    next();
  };
}

/**
 * requirePermission — fine-grained permission check
 * @param {string} permission - Permission key from user.permissions object
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    }
    const perms = req.user.permissions || {};
    const hasPerm = perms[permission] === true ||
                    req.user.role === 'SUPER_ADMIN' ||
                    req.user.role === 'ADMIN';

    if (!hasPerm) {
      console.warn(`[Auth] 403 MISSING_PERMISSION user=${req.user.email} permission=${permission}`);
      return res.status(403).json({
        error:      `Permission denied: '${permission}' required`,
        code:       'MISSING_PERMISSION',
        permission,
      });
    }
    next();
  };
}

/**
 * requireTenant — tenant isolation guard (Phase 1)
 * Verifies the authenticated user's tenant_id matches the request context.
 *
 * Checks (in order):
 *   1. req.params.tenantId
 *   2. req.body.tenant_id
 *   3. req.query.tenant_id
 *
 * SUPER_ADMIN bypasses tenant isolation (can access all tenants).
 */
function requireTenant() {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    }

    // SUPER_ADMIN can access any tenant
    if (req.user.role === 'SUPER_ADMIN') return next();

    const requestedTenant = req.params?.tenantId || req.body?.tenant_id || req.query?.tenant_id;

    // If no tenant specified in the request, use the user's own tenant
    if (!requestedTenant) {
      req.tenantId = req.user.tenant_id;
      return next();
    }

    if (requestedTenant !== req.user.tenant_id) {
      console.warn(`[Auth] 403 TENANT_MISMATCH user=${req.user.email} userTenant=${req.user.tenant_id} requestedTenant=${requestedTenant}`);
      return res.status(403).json({
        error: 'Access denied: cross-tenant access not permitted',
        code:  'TENANT_MISMATCH',
      });
    }

    req.tenantId = req.user.tenant_id;
    next();
  };
}

/**
 * authInfo — extract auth status without blocking (for debug endpoints)
 */
async function authInfo(req) {
  const { token, source } = extractToken(req);
  if (!token) return { authenticated: false, source: null };
  if (!supabaseAuth) return { authenticated: false, source: null, error: 'Supabase not configured' };

  try {
    const { data: { user }, error } = await supabaseAuth.auth.getUser(token); // v6.1: use supabaseAuth
    if (error || !user) return { authenticated: false, error: error?.message };

    return {
      authenticated: true,
      source,
      user_id:   user.id,
      email:     user.email,
      token_exp: user.exp ? new Date(user.exp * 1000).toISOString() : null,
    };
  } catch (_) {
    return { authenticated: false, error: 'Service unavailable' };
  }
}

// ── Internal helpers ───────────────────────────────────────────
function _ip(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.socket?.remoteAddress || 'unknown';
}

module.exports = {
  verifyToken,
  optionalAuth,
  requireRole,
  requirePermission,
  requireTenant,
  authInfo,
  extractToken,
};
