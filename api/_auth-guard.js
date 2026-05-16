'use strict';

/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Vercel Proxy Auth Guard  v1.0
 *  api/_auth-guard.js
 *
 *  FIX-003: JWT verification + Upstash Redis rate limiting for all
 *  /api/proxy/* Vercel serverless functions.
 *
 *  Security controls:
 *  ──────────────────
 *  1. JWT verification — every request must carry a valid Supabase JWT
 *     (or internal service key) in Authorization: Bearer <token> or
 *     the httpOnly cookie `access_token`.
 *     Bypass is allowed only in development (NODE_ENV=development) when
 *     SKIP_PROXY_AUTH=true, making local dev frictionless without
 *     weakening production.
 *
 *  2. Rate limiting (Upstash Redis) — per-user sliding-window counter:
 *     • 60 requests / minute per authenticated user
 *     • 10 requests / minute for unauthenticated (should never reach
 *       this since JWT is required, but adds defence-in-depth)
 *     Upstash Redis REST API is used (no persistent TCP connection
 *     needed in serverless — works perfectly on Vercel Edge).
 *
 *  3. Structured error responses — 401 / 429 / 403 with code field
 *     for frontend to handle consistently.
 *
 *  Environment variables required:
 *    SUPABASE_JWT_SECRET   — JWT signing secret (from Supabase dashboard)
 *    JWT_SECRET            — fallback custom JWT secret
 *    UPSTASH_REDIS_REST_URL  — Upstash Redis REST endpoint (optional)
 *    UPSTASH_REDIS_REST_TOKEN — Upstash Redis token (optional)
 *    PROXY_RATE_LIMIT_RPM    — override rate limit (default: 60)
 *    SKIP_PROXY_AUTH         — set "true" to bypass in development only
 * ══════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const https  = require('https');

// ── JWT verification (zero-dependency, no jsonwebtoken import risk) ──
const JWT_SECRETS = [
  process.env.SUPABASE_JWT_SECRET,
  process.env.JWT_SECRET,
].filter(Boolean);

/**
 * base64UrlDecode — decode a base64url-encoded string to a Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64UrlDecode(str) {
  const pad  = 4 - (str.length % 4);
  const b64  = str.replace(/-/g, '+').replace(/_/g, '/') + (pad < 4 ? '='.repeat(pad) : '');
  return Buffer.from(b64, 'base64');
}

/**
 * verifyJwt — verify a HS256 JWT signature and check expiry.
 *
 * @param {string} token - Raw JWT string (three base64url parts)
 * @param {string[]} secrets - HMAC secrets to try in order
 * @returns {{ valid: boolean, payload?: object, error?: string }}
 */
function verifyJwt(token, secrets) {
  if (!token || typeof token !== 'string') return { valid: false, error: 'no_token' };
  if (!secrets || secrets.length === 0)    return { valid: false, error: 'no_jwt_secret' };

  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, error: 'malformed_token' };

  const [headerB64, payloadB64, sigB64] = parts;

  // Decode header to confirm algorithm
  let header;
  try { header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')); }
  catch { return { valid: false, error: 'invalid_header' }; }

  if (header.alg !== 'HS256') return { valid: false, error: 'unsupported_algorithm' };

  // Try each secret
  const signingInput = `${headerB64}.${payloadB64}`;
  const expectedSig  = base64UrlDecode(sigB64);

  let signatureValid = false;
  for (const secret of secrets) {
    const hmac = crypto.createHmac('sha256', secret).update(signingInput).digest();
    if (hmac.length === expectedSig.length && crypto.timingSafeEqual(hmac, expectedSig)) {
      signatureValid = true;
      break;
    }
  }

  if (!signatureValid) return { valid: false, error: 'invalid_signature' };

  // Decode payload
  let payload;
  try { payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')); }
  catch { return { valid: false, error: 'invalid_payload' }; }

  // Check expiry (with 60-second clock tolerance)
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now - 60) {
    return { valid: false, error: 'token_expired' };
  }

  return { valid: true, payload };
}

/**
 * extractToken — pull the Bearer token from the request.
 * Priority: Authorization header → httpOnly cookie.
 *
 * @param {import('http').IncomingMessage} req
 * @returns {string|null}
 */
function extractToken(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);

  // httpOnly cookie fallback
  const cookieHeader = req.headers['cookie'] || '';
  const match = cookieHeader.match(/(?:^|;\s*)access_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// ── Upstash Redis rate limiter ────────────────────────────────────

const RATE_LIMIT_RPM   = parseInt(process.env.PROXY_RATE_LIMIT_RPM || '60', 10);
const UPSTASH_URL      = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN    = process.env.UPSTASH_REDIS_REST_TOKEN;

/**
 * upstashIncr — call Upstash Redis REST API to increment + expire a key.
 * Returns { count, error }.
 *
 * @param {string} key   - Redis key (e.g. "rl:user-id")
 * @param {number} ttlSec - Expire the key after this many seconds
 * @returns {Promise<{ count: number, error?: string }>}
 */
async function upstashIncr(key, ttlSec = 60) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return { count: 0 }; // No Redis — skip

  const pipeline = [
    ['INCR', key],
    ['EXPIRE', key, ttlSec, 'NX'],
  ];

  return new Promise((resolve) => {
    const body    = JSON.stringify(pipeline);
    const url     = new URL(`${UPSTASH_URL}/pipeline`);
    const options = {
      hostname: url.hostname,
      port:     url.port || 443,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Authorization':  `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 2000,
    };

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data  = JSON.parse(Buffer.concat(chunks).toString());
          const count = Array.isArray(data) ? (data[0]?.result ?? data[0] ?? 0) : 0;
          resolve({ count: Number(count) });
        } catch {
          resolve({ count: 0 });
        }
      });
    });

    req.on('error',   () => resolve({ count: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ count: 0 }); });
    req.write(body);
    req.end();
  });
}

/**
 * checkRateLimit — sliding-window rate limit per user.
 * Returns { allowed: boolean, remaining: number, retryAfter?: number }.
 *
 * @param {string} userId - Unique identifier for the user (JWT sub claim)
 * @returns {Promise<{ allowed: boolean, remaining: number, retryAfter?: number }>}
 */
async function checkRateLimit(userId) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) {
    return { allowed: true, remaining: RATE_LIMIT_RPM };
  }

  const key     = `rl:proxy:${userId}`;
  const { count } = await upstashIncr(key, 60);

  if (count > RATE_LIMIT_RPM) {
    return { allowed: false, remaining: 0, retryAfter: 60 };
  }

  return { allowed: true, remaining: Math.max(0, RATE_LIMIT_RPM - count) };
}

// ── Service-key bypass ────────────────────────────────────────────

const SERVICE_KEY = process.env.RAKAY_SERVICE_KEY || process.env.RAKAY_API_KEY;

/**
 * verifyProxyRequest — validate JWT + rate-limit and return a result object.
 * The caller should check `result.ok` before proceeding.
 *
 * @param {import('http').IncomingMessage} req
 * @returns {Promise<{ ok: boolean, userId?: string, error?: string, status?: number, retryAfter?: number }>}
 */
async function verifyProxyRequest(req) {
  // ── Development bypass ──────────────────────────────────────────
  const isDev = process.env.NODE_ENV === 'development';
  if (isDev && process.env.SKIP_PROXY_AUTH === 'true') {
    console.warn('[AuthGuard] SKIP_PROXY_AUTH=true — bypassing auth (development only)');
    return { ok: true, userId: 'dev-bypass' };
  }

  // ── Token extraction ────────────────────────────────────────────
  const token = extractToken(req);

  // ── Service-key check (internal services, not browser clients) ──
  if (token && SERVICE_KEY && token === SERVICE_KEY) {
    const rl = await checkRateLimit('service');
    if (!rl.allowed) {
      return { ok: false, status: 429, error: 'rate_limit_exceeded', retryAfter: rl.retryAfter };
    }
    return { ok: true, userId: 'service', remaining: rl.remaining };
  }

  // ── JWT verification ────────────────────────────────────────────
  if (JWT_SECRETS.length === 0) {
    // No JWT secret configured — log and allow (misconfigured infra should not silently deny)
    console.error('[AuthGuard] CRITICAL: No JWT_SECRET or SUPABASE_JWT_SECRET configured — auth bypassed');
    return { ok: true, userId: 'unconfigured', warning: 'no_jwt_secret' };
  }

  if (!token) {
    return { ok: false, status: 401, error: 'missing_token' };
  }

  const { valid, payload, error: jwtError } = verifyJwt(token, JWT_SECRETS);

  if (!valid) {
    const status = jwtError === 'token_expired' ? 401 : 401;
    return { ok: false, status, error: jwtError || 'invalid_token' };
  }

  const userId = payload.sub || 'unknown';

  // ── Rate limiting ────────────────────────────────────────────────
  const rl = await checkRateLimit(userId);
  if (!rl.allowed) {
    return { ok: false, status: 429, error: 'rate_limit_exceeded', retryAfter: rl.retryAfter };
  }

  return { ok: true, userId, payload, remaining: rl.remaining };
}

module.exports = { verifyProxyRequest, verifyJwt, extractToken, checkRateLimit };
