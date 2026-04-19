/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Enhanced Auth Middleware v5.2
 *  backend/middleware/auth.js
 *
 *  ROOT CAUSE FIXES (v5.2):
 *  ─────────────────────────
 *  1. verifyToken() now returns structured error JSON with 'code' field
 *     so frontend can distinguish MISSING_TOKEN vs EXPIRED_TOKEN vs
 *     INVALID_TOKEN and take appropriate action (redirect vs refresh).
 *
 *  2. Added optionalAuth() middleware — for routes that work both
 *     authenticated and unauthenticated (e.g. public feed status).
 *
 *  3. Enhanced logging: every 401/403 logs which token key was
 *     attempted, helping debug key-name mismatches.
 *
 *  4. Token extraction order matches ALL known frontend storage keys:
 *     - Authorization header (Bearer)
 *     - X-Access-Token header (legacy)
 *     - 'token' query param (WebSocket handshake)
 *
 *  5. Added authInfo() — returns sanitized token status without
 *     blocking the request. Used by /api/auth/debug endpoint.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');

// ── Token extraction: try all known locations ──────────────────────
function extractToken(req) {
  // 1. Standard Authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return { token: authHeader.split(' ')[1], source: 'Authorization header' };
  }

  // 2. X-Access-Token header (legacy support)
  const xToken = req.headers['x-access-token'];
  if (xToken) {
    return { token: xToken, source: 'X-Access-Token header' };
  }

  // 3. Query param (WebSocket + SSE handshake)
  if (req.query?.token) {
    return { token: req.query.token, source: 'query param' };
  }

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
 *   MISSING_TOKEN   — no Bearer header at all → redirect to login
 *   INVALID_TOKEN   — token can't be decoded → force re-login
 *   EXPIRED_TOKEN   — token expired → try refresh endpoint
 *   PROFILE_MISSING — auth OK but no user record → contact support
 *   ACCOUNT_INACTIVE — user suspended → show suspension message
 */
async function verifyToken(req, res, next) {
  const { token, source } = extractToken(req);

  if (!token) {
    // Detailed log to help debug frontend key mismatches
    console.warn(`[Auth] 401 MISSING_TOKEN — ${req.method} ${req.path}`,
      `Headers present: ${Object.keys(req.headers).filter(h => h.toLowerCase().includes('auth') || h.toLowerCase().includes('token')).join(', ') || 'none'}`
    );
    return res.status(401).json({
      error:   'Missing or invalid Authorization header',
      code:    'MISSING_TOKEN',
      hint:    'Include: Authorization: Bearer <your_token>',
      path:    req.path,
    });
  }

  try {
    // Verify token with Supabase Auth
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError) {
      const isExpired = authError.message?.toLowerCase().includes('expired') ||
                        authError.message?.toLowerCase().includes('jwt expired');
      const code = isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN';

      console.warn(`[Auth] 401 ${code} from ${source} — ${req.method} ${req.path}: ${authError.message}`);
      return res.status(401).json({
        error: isExpired ? 'Token has expired. Please refresh your session.' : 'Invalid token. Please log in again.',
        code,
        message: authError.message,
      });
    }

    if (!user) {
      console.warn(`[Auth] 401 INVALID_TOKEN — no user returned from ${source} — ${req.method} ${req.path}`);
      return res.status(401).json({
        error: 'Token verification failed',
        code:  'INVALID_TOKEN',
      });
    }

    // Fetch user profile from our users table
    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('id, name, email, role, tenant_id, status, permissions, avatar, mfa_enabled')
      .eq('auth_id', user.id)
      .single();

    if (profileError || !profile) {
      // Profile missing but Supabase auth is valid — likely new user
      // Create a minimal profile from auth data so they're not locked out
      console.warn(`[Auth] Profile not found for auth_id=${user.id} — using minimal profile`);

      // Attempt to find by email as fallback
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

      return res.status(401).json({
        error: 'User profile not found. Please contact your administrator.',
        code:  'PROFILE_MISSING',
        email: user.email,
      });
    }

    if (profile.status === 'suspended' || profile.status === 'inactive') {
      console.warn(`[Auth] 403 ACCOUNT_INACTIVE — user=${profile.email} status=${profile.status}`);
      return res.status(403).json({
        error: `Account is ${profile.status}. Contact your administrator.`,
        code:  'ACCOUNT_INACTIVE',
        status: profile.status,
      });
    }

    // Attach to request
    req.user     = { ...profile, authId: user.id };
    req.tenantId = profile.tenant_id;
    req.token    = token;

    next();

  } catch (err) {
    console.error('[Auth] Token verification exception:', err.message);
    return res.status(500).json({
      error: 'Authentication service error. Please try again.',
      code:  'AUTH_SERVICE_ERROR',
    });
  }
}

/**
 * optionalAuth — non-blocking auth middleware
 * Sets req.user if token is valid, continues even if not.
 * Use for routes that are publicly accessible but offer more data when authenticated.
 */
async function optionalAuth(req, res, next) {
  const { token } = extractToken(req);
  if (!token) return next();

  try {
    const { data: { user } } = await supabase.auth.getUser(token);
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
 * @param {string[]} roles - Allowed role names
 */
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
    }
    const roleList = Array.isArray(roles) ? roles : [roles];
    if (!roleList.includes(req.user.role)) {
      console.warn(`[Auth] 403 INSUFFICIENT_ROLE — user=${req.user.email} role=${req.user.role} required=${roleList.join(',')}`);
      return res.status(403).json({
        error:     `Access denied. Required role: ${roleList.join(' or ')}`,
        code:      'INSUFFICIENT_ROLE',
        yourRole:  req.user.role,
        required:  roleList,
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
      console.warn(`[Auth] 403 MISSING_PERMISSION — user=${req.user.email} permission=${permission}`);
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
 * authInfo — extract auth status without blocking (for debug endpoints)
 */
async function authInfo(req) {
  const { token, source } = extractToken(req);
  if (!token) return { authenticated: false, source: null };

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
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

module.exports = {
  verifyToken,
  optionalAuth,
  requireRole,
  requirePermission,
  authInfo,
  extractToken,
};
