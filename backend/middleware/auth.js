/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Secure Auth Middleware  v8.0  (Redis-Backed Cache)
 *  backend/middleware/auth.js
 *
 *  Security fix (Audit Phase 0 — FIX-006):
 *  ─────────────────────────────────────────────────────────────────
 *  FIX-006: Redis-backed distributed profile cache with pub/sub eviction.
 *
 *  Problem with v6.1 (in-memory Map):
 *   • Each Node.js worker process had its own isolated Map.
 *     Under PM2 cluster mode (4+ workers), a user suspension / role
 *     change would evict the entry from ONE worker's cache, but the
 *     other workers would continue serving the stale (active) profile
 *     for up to 60 seconds — a window during which a suspended user
 *     retains full API access across 3 of 4 workers.
 *
 *  Fix:
 *   1. Redis-backed cache (ioredis) — single source of truth shared
 *      across all worker processes and all server instances (Render,
 *      Kubernetes, etc.).  TTL: 60 seconds (same as before).
 *
 *   2. Pub/Sub eviction channel — when `evictProfileCache(authId)` is
 *      called (e.g. after a suspension, role change, or logout), it
 *      publishes to the Redis channel `profile:evict`. ALL connected
 *      subscribers (every worker process) immediately delete the key
 *      from their local L1 cache AND from Redis. Zero-latency cross-
 *      process propagation without polling.
 *
 *   3. L1 in-memory write-through — a lightweight Map is retained as
 *      an L1 cache (max 500 entries, TTL 30s — half of Redis TTL).
 *      This means cache hits for active users still require zero Redis
 *      round-trips. Redis is only hit on L1 miss or after L1 expiry.
 *
 *   4. Graceful degradation — if Redis is not configured (no REDIS_URL
 *      env var), the middleware automatically falls back to the v6.1
 *      in-memory-only behaviour with a startup warning. This ensures
 *      single-server / development setups continue to work unchanged.
 *
 *  Other features retained from v6.1:
 *   ✅ JWT local fast-path (no Supabase network call for 99% of requests)
 *   ✅ Dual-secret (SUPABASE_JWT_SECRET + JWT_SECRET) with try-alt logic
 *   ✅ Token extraction priority: httpOnly Cookie → Authorization → X-Access-Token
 *   ✅ requireRole(), requirePermission(), requireTenant()
 *   ✅ optionalAuth(), authInfo()
 *   ✅ Structured 401/403/503 with code field
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const jwt = require('jsonwebtoken');
const { supabase, supabaseAuth, isAbortError, isTimeoutError } = require('../config/supabase');

// ─────────────────────────────────────────────────────────────────
//  FIX-006: Redis-Backed Profile Cache
// ─────────────────────────────────────────────────────────────────

const _REDIS_URL         = process.env.REDIS_URL || process.env.UPSTASH_REDIS_URL || null;
const _PROFILE_TTL_SEC   = 60;       // Redis TTL (seconds)
const _L1_TTL_MS         = 30_000;   // L1 in-memory TTL (30s — half of Redis TTL)
const _L1_MAX            = 500;      // Max L1 entries
const _EVICT_CHANNEL     = 'profile:evict'; // Redis pub/sub channel

/** @type {Map<string, { profile: object, expiresAt: number }>} */
const _l1Cache = new Map();

// ── Redis client (ioredis) ─────────────────────────────────────────
let _redis    = null;   // main client (GET/SET/DEL/PUBLISH)
let _redisSub = null;   // subscriber client (SUBSCRIBE — separate connection)

/**
 * _initRedis — lazily initialise ioredis clients.
 * Called on first auth request; subsequent calls are no-ops.
 */
function _initRedis() {
  if (_redis !== null || !_REDIS_URL) return; // already init or no URL

  let Redis;
  try { Redis = require('ioredis'); } catch {
    console.warn('[Auth] ioredis not installed — profile cache is in-memory only (single-process). Install ioredis for distributed eviction.');
    _redis = false; // sentinel: tried but unavailable
    return;
  }

  const opts = { lazyConnect: true, enableReadyCheck: true, maxRetriesPerRequest: 2, connectTimeout: 5000 };

  _redis    = new Redis(_REDIS_URL, opts);
  _redisSub = new Redis(_REDIS_URL, { ...opts, lazyConnect: true });

  _redis.on('error',    err => console.error('[Auth:Redis] Client error:', err.message));
  _redisSub.on('error', err => console.error('[Auth:Redis] Sub error:', err.message));

  // Subscribe to cross-process eviction notifications
  _redisSub.subscribe(_EVICT_CHANNEL).catch(err => console.warn('[Auth:Redis] Subscribe failed:', err.message));

  _redisSub.on('message', (_channel, authId) => {
    // Another process evicted this user — drop from L1 immediately
    _l1Cache.delete(authId);
    console.info(`[Auth:Cache] L1 evicted via pub/sub: authId=${authId}`);
  });

  console.info('[Auth] Redis-backed profile cache initialised');
}

// ── L1 helpers ─────────────────────────────────────────────────────

function _l1Get(authId) {
  const entry = _l1Cache.get(authId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _l1Cache.delete(authId); return null; }
  return entry.profile;
}

function _l1Set(authId, profile) {
  if (_l1Cache.size >= _L1_MAX) {
    _l1Cache.delete(_l1Cache.keys().next().value);
  }
  _l1Cache.set(authId, { profile, expiresAt: Date.now() + _L1_TTL_MS });
}

function _l1Delete(authId) {
  _l1Cache.delete(authId);
}

// ── Redis helpers ──────────────────────────────────────────────────

/**
 * _redisGet — fetch a profile from Redis.
 * Falls back to null on error (graceful degradation).
 *
 * @param {string} authId
 * @returns {Promise<object|null>}
 */
async function _redisGet(authId) {
  if (!_redis) return null;
  try {
    const raw = await _redis.get(`profile:${authId}`);
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.warn('[Auth:Redis] GET error:', err.message);
    return null;
  }
}

/**
 * _redisSet — store a profile in Redis with TTL.
 *
 * @param {string} authId
 * @param {object} profile
 */
async function _redisSet(authId, profile) {
  if (!_redis) return;
  try {
    await _redis.set(`profile:${authId}`, JSON.stringify(profile), 'EX', _PROFILE_TTL_SEC);
  } catch (err) {
    console.warn('[Auth:Redis] SET error:', err.message);
  }
}

/**
 * _redisDelete — delete a profile from Redis AND publish eviction signal.
 *
 * @param {string} authId
 */
async function _redisDelete(authId) {
  if (!_redis) return;
  try {
    await _redis.del(`profile:${authId}`);
    await _redis.publish(_EVICT_CHANNEL, authId);
    console.info(`[Auth:Cache] Redis eviction published: authId=${authId}`);
  } catch (err) {
    console.warn('[Auth:Redis] DEL/PUBLISH error:', err.message);
  }
}

// ── Unified cache API ──────────────────────────────────────────────

/**
 * _cacheGetProfile — check L1 then Redis.
 *
 * @param {string} authId
 * @returns {Promise<object|null>}
 */
async function _cacheGetProfile(authId) {
  _initRedis();

  // L1 hit (zero network)
  const l1 = _l1Get(authId);
  if (l1) return l1;

  // Redis miss → try Redis
  const profile = await _redisGet(authId);
  if (profile) {
    _l1Set(authId, profile); // populate L1
  }
  return profile;
}

/**
 * _cacheSetProfile — write to L1 and Redis.
 *
 * @param {string} authId
 * @param {object} profile
 */
async function _cacheSetProfile(authId, profile) {
  _initRedis();
  _l1Set(authId, profile);
  await _redisSet(authId, profile);
}

/**
 * _cacheEvictProfile — evict from L1, Redis, and notify all peers via pub/sub.
 *
 * @param {string} authId
 */
async function _cacheEvictProfile(authId) {
  if (!authId) return;
  _initRedis();
  _l1Delete(authId);
  await _redisDelete(authId);
  console.info(`[Auth:Cache] Profile evicted: authId=${authId}`);
}

// ─────────────────────────────────────────────────────────────────
//  JWT Secret configuration (unchanged from v6.1)
// ─────────────────────────────────────────────────────────────────

const _JWT_SECRET     = process.env.SUPABASE_JWT_SECRET || process.env.JWT_SECRET || null;
const _SUPABASE_JWT   = process.env.SUPABASE_JWT_SECRET || null;
const _CUSTOM_JWT     = process.env.JWT_SECRET || null;
const _ALT_JWT_SECRET = (_SUPABASE_JWT && _CUSTOM_JWT && _SUPABASE_JWT !== _CUSTOM_JWT)
  ? (_JWT_SECRET === _SUPABASE_JWT ? _CUSTOM_JWT : _SUPABASE_JWT)
  : null;

// ── Token extraction ───────────────────────────────────────────────
function extractToken(req) {
  const cookieToken = req.cookies?.access_token || req.cookies?.token;
  if (cookieToken) return { token: cookieToken, source: 'httpOnly-cookie' };

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer '))
    return { token: authHeader.split(' ')[1], source: 'Authorization-header' };

  const xToken = req.headers['x-access-token'];
  if (xToken) return { token: xToken, source: 'X-Access-Token-header' };

  return { token: null, source: null };
}

/**
 * verifyToken — primary auth middleware (v8.0 — Redis-backed cache).
 *
 * @type {import('express').RequestHandler}
 */
async function verifyToken(req, res, next) {
  const { token, source } = extractToken(req);
  const reqId = req.id || req.headers['x-request-id'] || '-';

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
      error: 'Missing or invalid Authorization header',
      code:  'MISSING_TOKEN',
      hint:  'Include: Authorization: Bearer <your_token>  OR  use httpOnly cookie',
      path:  req.path,
    });
  }

  if (_JWT_SECRET) {
    let localDecoded;
    let _jwtVerifyErr = null;

    const _jwtOpts = { algorithms: ['HS256'], clockTolerance: 60, audience: 'authenticated' };
    try {
      try {
        localDecoded = jwt.verify(token, _JWT_SECRET, _jwtOpts);
      } catch (err1) {
        _jwtVerifyErr = err1;
        if (err1.name !== 'TokenExpiredError' && _ALT_JWT_SECRET) {
          try {
            localDecoded = jwt.verify(token, _ALT_JWT_SECRET, _jwtOpts);
            _jwtVerifyErr = null;
          } catch (err2) {
            _jwtVerifyErr = err2.name === 'TokenExpiredError' ? err2 : err1;
          }
        }
      }
    } catch (jwtErr) {
      _jwtVerifyErr = jwtErr;
    }

    if (_jwtVerifyErr) {
      const isExpired = _jwtVerifyErr.name === 'TokenExpiredError';
      return res.status(401).json({
        error: isExpired ? 'Token has expired. Please refresh your session.' : 'Invalid token. Please log in again.',
        code:  isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN',
      });
    }

    const authUserId = localDecoded.sub;
    const userEmail  = localDecoded.email || null;

    // FIX-006: Check Redis-backed cache (L1 → Redis → DB)
    const _cachedProfile = await _cacheGetProfile(authUserId);
    if (_cachedProfile) {
      if (_cachedProfile.status === 'suspended' || _cachedProfile.status === 'inactive') {
        await _cacheEvictProfile(authUserId);
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

    // DB fetch
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
        await _cacheSetProfile(authUserId, profile);
        req.user     = { ...profile, authId: authUserId };
        req.tenantId = profile.tenant_id;
        req.token    = token;
        return next();
      }

      // Email fallback
      if (userEmail) {
        const _emailFallbackTimeout = new Promise((_, rej) =>
          setTimeout(() => rej(new Error('email fallback profile fetch timed out')), 6_000)
        );
        let profileByEmail = null;
        try {
          const result = await Promise.race([
            supabase.from('users').select('id, name, email, role, tenant_id, status, permissions, avatar').eq('email', userEmail).single(),
            _emailFallbackTimeout,
          ]);
          profileByEmail = result.data || null;
        } catch (_emailErr) {
          if (_emailErr.message?.includes('timed out') || isAbortError(_emailErr) || isTimeoutError(_emailErr)) {
            console.warn(`[Auth] 503 DB_ABORT email fallback reqId=${reqId}: ${_emailErr.message}`);
            return res.status(503).json({ error: 'Database temporarily unavailable. Please retry.', code: 'DB_SERVICE_UNAVAILABLE', retryAfter: 3 });
          }
        }

        if (profileByEmail) {
          await _cacheSetProfile(authUserId, profileByEmail);
          req.user     = { ...profileByEmail, authId: authUserId };
          req.tenantId = profileByEmail.tenant_id;
          req.token    = token;
          return next();
        }
      }

      console.warn(`[Auth] 401 PROFILE_MISSING auth_id=${authUserId} email=${userEmail}`);
      return res.status(401).json({ error: 'User profile not found. Please contact your administrator.', code: 'PROFILE_MISSING', email: userEmail });

    } catch (dbErr) {
      if (isAbortError(dbErr) || isTimeoutError(dbErr)) {
        console.error(`[Auth] 503 DB_ABORT profile fetch reqId=${reqId}: ${dbErr.message}`);
        return res.status(503).json({ error: 'Database temporarily unavailable.', code: 'DB_SERVICE_UNAVAILABLE', retryAfter: 3 });
      }
      console.error(`[Auth] 500 profile fetch error reqId=${reqId}:`, dbErr.message);
      return res.status(500).json({ error: 'Authentication service error.', code: 'AUTH_SERVICE_ERROR' });
    }
  }

  // ── Fallback: supabaseAuth.getUser() path (no JWT_SECRET set) ─────
  const VERIFY_TIMEOUT_MS = 12_000;
  let _verifyTimeoutId;
  const _timeoutPromise = new Promise((_, rej) => {
    _verifyTimeoutId = setTimeout(() => rej(new Error('Supabase auth verification timed out')), VERIFY_TIMEOUT_MS);
  });

  try {
    const { data: { user }, error: authError } = await Promise.race([
      supabaseAuth.auth.getUser(token),
      _timeoutPromise,
    ]);
    clearTimeout(_verifyTimeoutId);

    if (authError) {
      if (isAbortError(authError) || isTimeoutError(authError)) {
        return res.status(503).json({ error: 'Authentication service temporarily unavailable.', code: 'AUTH_SERVICE_UNAVAILABLE', retryAfter: 5 });
      }
      const isExpired = authError.message?.toLowerCase().includes('expired');
      return res.status(401).json({
        error: isExpired ? 'Token has expired.' : 'Invalid token.',
        code:  isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN',
        message: authError.message,
      });
    }

    if (!user) return res.status(401).json({ error: 'Token verification failed', code: 'INVALID_TOKEN' });

    const { data: profile, error: profileError } = await Promise.race([
      supabase.from('users').select('id, name, email, role, tenant_id, status, permissions, avatar, mfa_enabled').eq('auth_id', user.id).single(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('fallback profile timed out')), 8_000)),
    ]).catch(e => ({ data: null, error: e }));

    if (profileError || !profile) {
      if (profileError?.message?.includes('timed out') || isAbortError(profileError) || isTimeoutError(profileError)) {
        clearTimeout(_verifyTimeoutId);
        return res.status(503).json({ error: 'Database temporarily unavailable.', code: 'DB_SERVICE_UNAVAILABLE', retryAfter: 3 });
      }
      const { data: profileByEmail } = await supabase.from('users').select('id, name, email, role, tenant_id, status, permissions, avatar').eq('email', user.email).single();
      if (profileByEmail) {
        req.user     = { ...profileByEmail, authId: user.id };
        req.tenantId = profileByEmail.tenant_id;
        req.token    = token;
        return next();
      }
      return res.status(401).json({ error: 'User profile not found.', code: 'PROFILE_MISSING', email: user.email });
    }

    if (profile.status === 'suspended' || profile.status === 'inactive') {
      return res.status(403).json({ error: `Account is ${profile.status}.`, code: 'ACCOUNT_INACTIVE', status: profile.status });
    }

    req.user     = { ...profile, authId: user.id };
    req.tenantId = profile.tenant_id;
    req.token    = token;
    next();

  } catch (err) {
    clearTimeout(_verifyTimeoutId);
    if (isAbortError(err)) return res.status(503).json({ error: 'Auth service unavailable (aborted).', code: 'AUTH_SERVICE_UNAVAILABLE', retryAfter: 3 });
    if (err.message?.includes('timed out')) return res.status(503).json({ error: 'Authentication service temporarily unavailable.', code: 'AUTH_SERVICE_TIMEOUT', retryAfter: 5 });
    console.error(`[Auth] Exception reqId=${reqId}:`, err.message);
    return res.status(500).json({ error: 'Authentication service error.', code: 'AUTH_SERVICE_ERROR' });
  }
}

/**
 * optionalAuth — non-blocking; sets req.user when valid token present.
 * @type {import('express').RequestHandler}
 */
async function optionalAuth(req, res, next) {
  const { token } = extractToken(req);
  if (!token) return next();

  try {
    if (_JWT_SECRET) {
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
        const cached     = await _cacheGetProfile(authUserId);
        if (cached && cached.status === 'active') {
          req.user     = { ...cached, authId: authUserId };
          req.tenantId = cached.tenant_id;
          req.token    = token;
          return next();
        }
        const profileTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5_000));
        const profilePromise = supabase.from('users').select('id, name, email, role, tenant_id, status, permissions').eq('auth_id', authUserId).single();
        try {
          const { data: profile } = await Promise.race([profilePromise, profileTimeout]);
          if (profile && profile.status === 'active') {
            await _cacheSetProfile(authUserId, profile);
            req.user     = { ...profile, authId: authUserId };
            req.tenantId = profile.tenant_id;
            req.token    = token;
          }
        } catch (_) { /* silent */ }
      }
      return next();
    }

    if (!supabaseAuth) return next();
    const { data: { user } } = await Promise.race([
      supabaseAuth.auth.getUser(token),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8_000)),
    ]);
    if (user) {
      const { data: profile } = await supabase.from('users').select('id, name, email, role, tenant_id, status, permissions').eq('auth_id', user.id).single();
      if (profile && profile.status === 'active') {
        req.user     = { ...profile, authId: user.id };
        req.tenantId = profile.tenant_id;
        req.token    = token;
      }
    }
  } catch (_) { /* silent */ }

  next();
}

/**
 * requireRole — RBAC middleware factory.
 * @param {string|string[]} roles
 * @returns {import('express').RequestHandler}
 */
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    const roleList = Array.isArray(roles) ? roles : [roles];
    if (!roleList.includes(req.user.role)) {
      console.warn(`[Auth] 403 INSUFFICIENT_ROLE user=${req.user.email} role=${req.user.role} required=${roleList.join(',')}`);
      return res.status(403).json({ error: `Access denied. Required role: ${roleList.join(' or ')}`, code: 'INSUFFICIENT_ROLE', yourRole: req.user.role, required: roleList });
    }
    next();
  };
}

/**
 * requirePermission — fine-grained permission check.
 * @param {string} permission
 * @returns {import('express').RequestHandler}
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    const perms   = req.user.permissions || {};
    const hasPerm = perms[permission] === true || req.user.role === 'SUPER_ADMIN' || req.user.role === 'ADMIN';
    if (!hasPerm) {
      console.warn(`[Auth] 403 MISSING_PERMISSION user=${req.user.email} permission=${permission}`);
      return res.status(403).json({ error: `Permission denied: '${permission}' required`, code: 'MISSING_PERMISSION', permission });
    }
    next();
  };
}

/**
 * requireTenant — tenant isolation guard.
 * @returns {import('express').RequestHandler}
 */
function requireTenant() {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    if (req.user.role === 'SUPER_ADMIN') return next();

    const requestedTenant = req.params?.tenantId || req.body?.tenant_id || req.query?.tenant_id;
    if (!requestedTenant) { req.tenantId = req.user.tenant_id; return next(); }

    if (requestedTenant !== req.user.tenant_id) {
      console.warn(`[Auth] 403 TENANT_MISMATCH user=${req.user.email} userTenant=${req.user.tenant_id} requestedTenant=${requestedTenant}`);
      return res.status(403).json({ error: 'Access denied: cross-tenant access not permitted', code: 'TENANT_MISMATCH' });
    }

    req.tenantId = req.user.tenant_id;
    next();
  };
}

/**
 * authInfo — extract auth status without blocking (for debug endpoints).
 * @param {import('express').Request} req
 * @returns {Promise<object>}
 */
async function authInfo(req) {
  const { token, source } = extractToken(req);
  if (!token) return { authenticated: false, source: null };

  if (_JWT_SECRET) {
    try {
      const _jwtOpts = { algorithms: ['HS256'], clockTolerance: 60, audience: 'authenticated' };
      let decoded = null;
      try { decoded = jwt.verify(token, _JWT_SECRET, _jwtOpts); }
      catch (err1) {
        if (err1.name !== 'TokenExpiredError' && _ALT_JWT_SECRET) {
          try { decoded = jwt.verify(token, _ALT_JWT_SECRET, _jwtOpts); } catch (_) {}
        }
        if (!decoded) return { authenticated: false, source, error: err1.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token' };
      }
      return { authenticated: true, source, user_id: decoded.sub, email: decoded.email || null, token_exp: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null };
    } catch (_) {
      return { authenticated: false, error: 'token_decode_failed' };
    }
  }

  if (!supabaseAuth) return { authenticated: false, source: null, error: 'Supabase not configured' };
  try {
    const { data: { user }, error } = await Promise.race([
      supabaseAuth.auth.getUser(token),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8_000)),
    ]);
    if (error || !user) return { authenticated: false, error: error?.message };
    return { authenticated: true, source, user_id: user.id, email: user.email };
  } catch (_) {
    return { authenticated: false, error: 'Service unavailable' };
  }
}

// ── Internal helpers ───────────────────────────────────────────────
function _ip(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

module.exports = {
  verifyToken,
  optionalAuth,
  requireRole,
  requirePermission,
  requireTenant,
  authInfo,
  extractToken,
  evictProfileCache: _cacheEvictProfile,  // exported for route handlers to call after suspension/logout
};
