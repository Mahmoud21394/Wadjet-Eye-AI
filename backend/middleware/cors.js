/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Strict CORS Middleware (SEC-001 Fix)
 *  backend/middleware/cors.js
 *
 *  Replaces wildcard Access-Control-Allow-Origin: * with an explicit
 *  origin allowlist. Supports dynamic allowlists via environment variable.
 *
 *  Audit finding: SEC-001 — Wildcard CORS on API Proxy — CRITICAL
 *  OWASP: A05:2021 Security Misconfiguration
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Origin allowlist ──────────────────────────────────────────────
// Add production domains here. CORS_ALLOWED_ORIGINS env var is a
// comma-separated list that overrides defaults at runtime.
const DEFAULT_ALLOWED_ORIGINS = [
  'https://wadjet-eye-ai.vercel.app',
  'https://www.genspark.ai',
  'https://wadjet-eye.io',
  'https://app.wadjet-eye.io',
  'http://localhost:3000',
  'http://localhost:5173',  // Vite dev server
  'http://localhost:4000',  // backend dev
];

function getAllowedOrigins() {
  if (process.env.CORS_ALLOWED_ORIGINS) {
    return process.env.CORS_ALLOWED_ORIGINS
      .split(',')
      .map(o => o.trim())
      .filter(Boolean);
  }
  return DEFAULT_ALLOWED_ORIGINS;
}

/**
 * corsMiddleware — strict origin-based CORS
 * Handles preflight OPTIONS and attaches headers to all responses.
 *
 * Security model:
 *   • Explicit allowlist — no wildcards
 *   • Origin must match exactly (scheme + host + port)
 *   • Credentials-safe (Access-Control-Allow-Credentials: true for allowlisted origins)
 *   • Rejects unrecognized origins with 403 (no CORS headers = browser blocks response)
 */
function corsMiddleware(req, res, next) {
  const origin        = req.headers['origin'];
  const allowedOrigins = getAllowedOrigins();

  // No Origin header → same-origin request or server-to-server → allow
  if (!origin) return next();

  const isAllowed = allowedOrigins.includes(origin);

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');  // Prevent caching cross-origin responses
  }
  // If origin is NOT in allowlist: do not set CORS headers.
  // Browser will block the response. Intentional security behaviour.

  // Preflight
  if (req.method === 'OPTIONS') {
    if (isAllowed) {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Request-ID, X-Tenant-ID, X-Client-Version, x-access-token'
      );
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.sendStatus(204);
    }
    // Unknown origin preflight — reject
    return res.status(403).json({
      error: 'CORS: Origin not allowed',
      code:  'CORS_ORIGIN_REJECTED',
    });
  }

  next();
}

/**
 * proxyCorsMw — CORS for the proxy-server.js (local dev proxy).
 * More permissive: allows localhost variants but still NO wildcard.
 */
function proxyCorsMw(req, res, next) {
  const origin         = req.headers['origin'] || '';
  const allowedOrigins = getAllowedOrigins();

  // Allow any localhost origin in development
  const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const isAllowed   = allowedOrigins.includes(origin) || (process.env.NODE_ENV !== 'production' && isLocalhost);

  if (isAllowed && origin) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  } else if (!origin) {
    // No origin header — server-to-server, allow
  } else {
    // Unknown origin in production → reject
    if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'CORS: Origin not allowed', code: 'CORS_ORIGIN_REJECTED' });
    }
  }

  if (req.method === 'OPTIONS') {
    if (isAllowed || !origin) {
      res.setHeader('Access-Control-Allow-Methods',  'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers',
        'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, ' +
        'anthropic-dangerous-direct-browser-access, X-OTX-API-KEY, Key, Accept, Auth-Key, ' +
        'X-Client-VT-Key, X-Client-Abuse-Key, X-Client-Shodan-Key, X-Client-OTX-Key, X-Request-ID'
      );
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.sendStatus(204);
    }
    return res.status(403).json({ error: 'CORS: Origin not allowed' });
  }

  next();
}

module.exports = { corsMiddleware, proxyCorsMw, getAllowedOrigins };
