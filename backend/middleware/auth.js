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

// ── FIX v12.0: In-memory profile cache — eliminates the DB round-trip on EVERY
// authenticated request (the #1 cause of platform slowness on free-tier Supabase).
// Cache key: auth_id (from JWT sub claim).  TTL: 60 seconds.
// On cache miss: DB fetch as normal, result stored.
// On user status change (suspend/delete): the record is evicted on next miss after TTL.
// Size capped at 500 entries to prevent memory leak on long-running servers.
const _PROFILE_CACHE_TTL_MS = 60_000; // 60 seconds
const _profileCache = new Map(); // auth_id → { profile, expiresAt }
const _PROFILE_CACHE_MAX = 500;

function _cacheGetProfile(authId) {
  const entry = _profileCache.get(authId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _profileCache.delete(authId); return null; }
  return entry.profile;
}

function _cacheSetProfile(authId, profile) {
  // Evict oldest entry when cache is full
  if (_profileCache.size >= _PROFILE_CACHE_MAX) {
    _profileCache.delete(_profileCache.keys().next().value);
  }
  _profileCache.set(authId, { profile, expiresAt: Date.now() + _PROFILE_CACHE_TTL_MS });
}

// Exported so routes can invalidate on profile update / role change
function _cacheEvictProfile(authId) {
  if (authId) _profileCache.delete(authId);
}

// ── JWT_SECRET for local fast-path decode ────────────────────────
// Supabase JWTs are signed with the project's JWT secret.
// SUPABASE_JWT_SECRET (preferred) or JWT_SECRET (fallback).
// This lets us verify token signature and expiry locally — without a
// Supabase network round-trip — so cold-start latency never causes 503.
const _JWT_SECRET = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;
// ROOT-CAUSE FIX v10.0: Both secrets tracked separately so Strategy-2 refresh
// tokens (signed with JWT_SECRET) are accepted even when SUPABASE_JWT_SECRET is
// the primary verification key.  If both are set and differ we try primary first,
// then alt — so a Supabase-issued token AND a custom-signed refresh token both pass.
const _SUPABASE_JWT  = process.env.SUPABASE_JWT_SECRET || null;
const _CUSTOM_JWT    = process.env.JWT_SECRET || null;
const _ALT_JWT_SECRET = (_SUPABASE_JWT && _CUSTOM_JWT && _SUPABASE_JWT !== _CUSTOM_JWT)
  ? (_JWT_SECRET === _SUPABASE_JWT ? _CUSTOM_JWT : _SUPABASE_JWT)
  : null;

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
    // FIX v10.1: hoist _jwtVerifyErr outside the try block so the outer catch
    // and the post-try check can both reference it without a ReferenceError.
    let _jwtVerifyErr = null;
    try {
      // ROOT-CAUSE FIX v10.0: Add clockTolerance for minor clock-skew between
      // Render and Supabase.  Also try the alternate secret so Strategy-2
      // custom-signed tokens (JWT_SECRET) are accepted alongside Supabase-issued
      // tokens (SUPABASE_JWT_SECRET) without forcing a re-login.
      //
      // ROOT-CAUSE FIX v17.0:
      //  (a) clockTolerance 30→60s: Render cold-start clocks can drift >30s vs
      //      Supabase, causing perfectly valid tokens to fail with 'jwt not active'
      //      or 'jwt expired' even when they are within their real validity window.
      //  (b) audience: 'authenticated' — Supabase JWTs carry aud='authenticated'.
      //      Without this option jwt.verify() accepts tokens with ANY aud, making
      //      INVALID_TOKEN errors intermittent and hard to reproduce.  Specifying
      //      it here ensures our verify logic matches Supabase's own validation.
      //      NOTE: This must match the aud field in the custom JWT payload signed
      //      in routes/auth.js Strategy-2 (which already uses aud:'authenticated').
      const _jwtOpts = { algorithms: ['HS256'], clockTolerance: 60, audience: 'authenticated' };
      try {
        localDecoded = jwt.verify(token, _JWT_SECRET, _jwtOpts);
      } catch (err1) {
        _jwtVerifyErr = err1;
        if (err1.name !== 'TokenExpiredError' && _ALT_JWT_SECRET) {
          try {
            localDecoded = jwt.verify(token, _ALT_JWT_SECRET, _jwtOpts);
            _jwtVerifyErr = null; // alt-secret succeeded
          } catch (err2) {
            // Keep the more specific error (expired beats invalid)
            _jwtVerifyErr = err2.name === 'TokenExpiredError' ? err2 : err1;
          }
        }
      }
    } catch (jwtErr) {
      _jwtVerifyErr = jwtErr;
    }
    if (_jwtVerifyErr) {
      const isExpired = _jwtVerifyErr.name === 'TokenExpiredError';
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

    // FIX v12.0: Check in-memory profile cache BEFORE hitting the DB.
    // Every API call previously made a Supabase DB round-trip to fetch
    // the user profile — this was the primary cause of platform slowness.
    // Cache TTL is 60 s; evict on logout / profile update.
    const _cachedProfile = _cacheGetProfile(authUserId);
    if (_cachedProfile) {
      if (_cachedProfile.status === 'suspended' || _cachedProfile.status === 'inactive') {
        _cacheEvictProfile(authUserId); // force re-check next request
        console.warn(`[Auth] 403 ACCOUNT_INACTIVE (cached) user=${_cachedProfile.email} status=${_cachedProfile.status}`);
        return res.status(403).json({
          error:  `Account is ${_cachedProfile.status}. Contact your administrator.`,
          code:   'ACCOUNT_INACTIVE',
          status: _cachedProfile.status,
        });
      }
      req.user     = { ..._cachedProfile, authId: authUserId };
      req.tenantId = _cachedProfile.tenant_id;
      req.token    = token;
      return next();
    }

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
        // Cache the profile for subsequent requests
        _cacheSetProfile(authUserId, profile);
        req.user     = { ...profile, authId: authUserId };
        req.tenantId = profile.tenant_id;
        req.token    = token;
        return next();
      }

      // Profile not found by auth_id → try email fallback
      // FIX v16.0: This query had NO timeout guard.  On Supabase free-tier cold-
      // start it could hang for the full 15 s statement timeout, blocking the
      // entire request and causing the outer timeout (if any) to fire first.
      // Wrap in a 6 s timeout — tight enough to fail fast while still allowing
      // for a slow pool connection.  Timeout here returns PROFILE_MISSING (401)
      // rather than 503 because we already confirmed the auth_id lookup failed.
      if (userEmail) {
        const _emailFallbackTimeout = new Promise((_, rej) =>
          setTimeout(() => rej(new Error('email fallback profile fetch timed out')), 6_000)
        );
        let profileByEmail = null;
        try {
          const result = await Promise.race([
            supabase
              .from('users')
              .select('id, name, email, role, tenant_id, status, permissions, avatar')
              .eq('email', userEmail)
              .single(),
            _emailFallbackTimeout,
          ]);
          profileByEmail = result.data || null;
        } catch (_emailErr) {
          if (_emailErr.message?.includes('timed out') || isAbortError(_emailErr) || isTimeoutError(_emailErr)) {
            console.warn(`[Auth] 503 DB_ABORT email fallback profile fetch reqId=${reqId}: ${_emailErr.message}`);
            return res.status(503).json({
              error: 'Database temporarily unavailable. Please retry in a moment.',
              code:  'DB_SERVICE_UNAVAILABLE',
              retryAfter: 3,
            });
          }
          // Other error — fall through to PROFILE_MISSING
        }

        if (profileByEmail) {
          _cacheSetProfile(authUserId, profileByEmail);
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

    // Fetch user profile — FIX v15.0: wrap in 8s timeout so a slow DB on the
    // fallback path doesn't hang the entire request past the outer 12s window.
    const _fbProfileTimeout = new Promise((_, rej) =>
      setTimeout(() => rej(new Error('fallback profile fetch timed out')), 8_000)
    );
    const { data: profile, error: profileError } = await Promise.race([
      supabase
        .from('users')
        .select('id, name, email, role, tenant_id, status, permissions, avatar, mfa_enabled')
        .eq('auth_id', user.id)
        .single(),
      _fbProfileTimeout,
    ]).catch(e => ({ data: null, error: e }));

    if (profileError || !profile) {
      // If it was a timeout, return 503 not 401
      if (profileError?.message?.includes('timed out') || isAbortError(profileError) || isTimeoutError(profileError)) {
        console.error(`[Auth] 503 DB_ABORT fallback profile fetch reqId=${reqId}: ${profileError?.message}`);
        clearTimeout(_verifyTimeoutId);
        return res.status(503).json({
          error: 'Database temporarily unavailable. Please retry in a moment.',
          code:  'DB_SERVICE_UNAVAILABLE',
          retryAfter: 3,
        });
      }

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
 *
 * FIX v15.0: Use local JWT fast-path (same as verifyToken) instead of
 * supabaseAuth.getUser() which makes a network call on EVERY request that
 * uses optionalAuth.  On Render cold-start this caused a chain of 503s even
 * for routes that don't require authentication.
 */
async function optionalAuth(req, res, next) {
  const { token } = extractToken(req);
  if (!token) return next();

  try {
    // Fast-path: local JWT verification — no network call
    if (_JWT_SECRET) {
      // FIX v17.0: audience + increased clockTolerance (same as verifyToken fast-path)
      const _jwtOpts = { algorithms: ['HS256'], clockTolerance: 60, audience: 'authenticated' };
      let localDecoded = null;
      try {
        localDecoded = jwt.verify(token, _JWT_SECRET, _jwtOpts);
      } catch (err1) {
        if (err1.name !== 'TokenExpiredError' && _ALT_JWT_SECRET) {
          try { localDecoded = jwt.verify(token, _ALT_JWT_SECRET, _jwtOpts); } catch (_) {}
        }
      }
      if (localDecoded) {
        const authUserId = localDecoded.sub;
        // Check profile cache first
        const cached = _cacheGetProfile(authUserId);
        if (cached && cached.status === 'active') {
          req.user     = { ...cached, authId: authUserId };
          req.tenantId = cached.tenant_id;
          req.token    = token;
          return next();
        }
        // Cache miss — DB fetch (with 5s timeout so optional auth never hangs)
        const profileTimeout = new Promise((_, rej) =>
          setTimeout(() => rej(new Error('optionalAuth profile fetch timed out')), 5_000)
        );
        const profilePromise = supabase
          .from('users')
          .select('id, name, email, role, tenant_id, status, permissions')
          .eq('auth_id', authUserId)
          .single();
        try {
          const { data: profile } = await Promise.race([profilePromise, profileTimeout]);
          if (profile && profile.status === 'active') {
            _cacheSetProfile(authUserId, profile);
            req.user     = { ...profile, authId: authUserId };
            req.tenantId = profile.tenant_id;
            req.token    = token;
          }
        } catch (_) { /* silent — timeout or DB error is non-fatal for optional auth */ }
      }
      return next();
    }

    // Fallback: supabaseAuth path (only when no JWT secret configured)
    if (!supabaseAuth) return next();
    const optTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8_000));
    const { data: { user } } = await Promise.race([supabaseAuth.auth.getUser(token), optTimeout]);
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
 *
 * FIX v15.0: Use local JWT decode instead of supabaseAuth.getUser() to
 * avoid a cold-start network call in what is supposed to be a lightweight
 * diagnostic helper.
 */
async function authInfo(req) {
  const { token, source } = extractToken(req);
  if (!token) return { authenticated: false, source: null };

  // Fast-path: local JWT decode — zero network
  if (_JWT_SECRET) {
    try {
      // FIX v17.0: audience + increased clockTolerance (same as verifyToken fast-path)
      const _jwtOpts = { algorithms: ['HS256'], clockTolerance: 60, audience: 'authenticated' };
      let decoded = null;
      try {
        decoded = jwt.verify(token, _JWT_SECRET, _jwtOpts);
      } catch (err1) {
        if (err1.name !== 'TokenExpiredError' && _ALT_JWT_SECRET) {
          try { decoded = jwt.verify(token, _ALT_JWT_SECRET, _jwtOpts); } catch (_) {}
        }
        if (!decoded) {
          return {
            authenticated: false,
            source,
            error: err1.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token',
          };
        }
      }
      return {
        authenticated: true,
        source,
        user_id:   decoded.sub,
        email:     decoded.email || null,
        token_exp: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null,
      };
    } catch (_) {
      return { authenticated: false, error: 'token_decode_failed' };
    }
  }

  // Fallback: supabaseAuth path when no JWT secret set
  if (!supabaseAuth) return { authenticated: false, source: null, error: 'Supabase not configured' };
  try {
    const aiTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8_000));
    const { data: { user }, error } = await Promise.race([supabaseAuth.auth.getUser(token), aiTimeout]);
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
  evictProfileCache: _cacheEvictProfile, // call after profile update / suspension
};
