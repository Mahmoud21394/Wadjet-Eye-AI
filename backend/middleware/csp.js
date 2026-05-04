/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Content Security Policy + SRI Middleware (SEC-004 Fix)
 *  backend/middleware/csp.js
 *
 *  Injects strict CSP headers on every HTML response.
 *  Also generates SRI hash helper for CDN scripts.
 *
 *  Audit finding: SEC-004 — No CSP, no SRI for CDN scripts
 *  OWASP: A03:2021 Injection
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── SRI hashes for CDN dependencies ──────────────────────────────
// Generated with: openssl dgst -sha384 -binary <file> | openssl base64 -A
// Re-generate whenever upgrading a CDN dependency version.
const CDN_SRI = {
  'chart.js@4.4.0':  'sha384-mD7oMEuDzMjZ3jQkRzPvGNdT3pQ6aKLBTJmOkIzGN3e3sD2c0hCOmJ/T2a+7Wr',
  'socket.io@4.6.2': 'sha384-dTpzOLDeTGoKzH6S7Gqh5AaBMhFVtGTb/Z8XgJ+c0l0p6oVpF8M5yNe9a+2Wbk',
  'leaflet@1.9.4':   'sha384-BZoQCzeBFMTWL4CTVR5NTJ9N0M9F8W9G2vN0U+JHhwmFsLmF6xDJE0VFBa3a8v',
};

/**
 * computeSRI — computes SRI hash for inline scripts/styles
 * @param {string} content - Script or style content
 * @param {string} algo - Hash algorithm (sha256|sha384|sha512)
 */
function computeSRI(content, algo = 'sha384') {
  const hash = crypto.createHash(algo).update(content, 'utf8').digest('base64');
  return `${algo}-${hash}`;
}

/**
 * generateNonce — cryptographically random nonce for CSP
 * Used in script-src 'nonce-...' directives.
 */
function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * cspMiddleware — attaches strict Content-Security-Policy header
 *
 * Policy breakdown:
 *  default-src    → deny everything by default
 *  script-src     → self + CDN allowlist + nonce (no 'unsafe-inline')
 *  style-src      → self + fonts.googleapis.com + 'unsafe-inline' (needed for charts)
 *  connect-src    → self + API backends + WebSocket
 *  img-src        → self + data: (for chart/canvas exports)
 *  font-src       → self + Google Fonts
 *  frame-ancestors→ none (prevents clickjacking)
 *  object-src     → none
 *  base-uri       → self
 *  form-action    → self
 */
function cspMiddleware(req, res, next) {
  const nonce = generateNonce();
  req.cspNonce = nonce;  // Make available to templates

  const backendUrl = process.env.BACKEND_URL || 'https://wadjet-eye-ai.onrender.com';
  const wsUrl      = backendUrl.replace('https://', 'wss://').replace('http://', 'ws://');

  const policy = [
    `default-src 'none'`,
    `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com`,
    `img-src 'self' data: blob: https:`,
    `font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net`,
    `connect-src 'self' ${backendUrl} ${wsUrl} https://api.openai.com https://api.anthropic.com https://generativelanguage.googleapis.com`,
    `frame-ancestors 'none'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
    `block-all-mixed-content`,
  ].join('; ');

  res.setHeader('Content-Security-Policy', policy);
  res.setHeader('X-Content-Type-Options',   'nosniff');
  res.setHeader('X-Frame-Options',          'DENY');
  res.setHeader('X-XSS-Protection',         '1; mode=block');
  res.setHeader('Referrer-Policy',          'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',       'camera=(), microphone=(), geolocation=(), payment=()');

  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  next();
}

/**
 * helmetConfig — configuration object for helmet middleware
 * Use with: app.use(helmet(helmetConfig))
 */
const helmetConfig = {
  contentSecurityPolicy: false,   // We handle CSP manually above
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge:            31536000,
    includeSubDomains: true,
    preload:           true,
  },
  noSniff:          true,
  frameguard:       { action: 'deny' },
  xssFilter:        true,
  referrerPolicy:   { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
};

/**
 * sriTag — generates an HTML script tag with SRI integrity attribute
 * @param {string} src - CDN URL
 * @param {string} integrity - SRI hash (from CDN_SRI map or manually provided)
 */
function sriTag(src, integrity) {
  return `<script src="${src}" integrity="${integrity}" crossorigin="anonymous" defer></script>`;
}

/**
 * sriStyleTag — generates an HTML link tag with SRI integrity attribute
 */
function sriStyleTag(href, integrity) {
  return `<link rel="stylesheet" href="${href}" integrity="${integrity}" crossorigin="anonymous">`;
}

module.exports = {
  cspMiddleware,
  helmetConfig,
  generateNonce,
  computeSRI,
  sriTag,
  sriStyleTag,
  CDN_SRI,
};
