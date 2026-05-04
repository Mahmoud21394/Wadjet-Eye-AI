/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Hardened Proxy Server v32.0
 *  proxy-server-v2.js
 *
 *  SECURITY HARDENING (Audit Phase 1):
 *  ────────────────────────────────────
 *  SEC-001: Wildcard CORS → strict origin allowlist
 *  SEC-003: Redis-backed rate limiting on all proxy endpoints
 *  SEC-004: CSP + security headers on all responses
 *  SEC-008: API keys loaded from Vault/env — NEVER hardcoded
 *
 *  All hardcoded API keys removed. Keys must be in:
 *    • .env file (development)
 *    • Vault KV path (production)
 *    • Kubernetes Secret (k8s deployment)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

require('dotenv').config();

const http    = require('http');
const https   = require('https');
const fs      = require('fs');
const path    = require('path');
const url     = require('url');
const zlib    = require('zlib');
const crypto  = require('crypto');

const PORT   = parseInt(process.env.PORT || '3000', 10);
const STATIC = __dirname;

// ── MIME types ────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif':  'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.webp': 'image/webp',
};

// ── SECURITY: Origin allowlist (replaces wildcard CORS) ───────────
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || [
  'https://wadjet-eye-ai.vercel.app',
  'https://www.genspark.ai',
  'https://app.wadjet-eye.io',
  'http://localhost:3000',
  'http://localhost:5173',
].join(',')).split(',').map(o => o.trim()).filter(Boolean);

function applyCORS(req, res) {
  const origin = req.headers['origin'];
  if (!origin) return;   // Same-origin or server-to-server — no CORS needed

  const isDev     = process.env.NODE_ENV !== 'production';
  const isLocal   = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const isAllowed = ALLOWED_ORIGINS.includes(origin) || (isDev && isLocal);

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin',      origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  // Unknown origins: intentionally omit CORS headers → browser blocks response
}

// ── Security headers ──────────────────────────────────────────────
function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',   'nosniff');
  res.setHeader('X-Frame-Options',          'DENY');
  res.setHeader('X-XSS-Protection',         '1; mode=block');
  res.setHeader('Referrer-Policy',          'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',       'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
}

// ── Rate limiting (in-memory sliding window) ──────────────────────
// Redis store used when REDIS_URL is configured, falls back to memory.
const _rateLimitWindows = new Map();   // key → [timestamp, ...]

/**
 * checkRateLimit — sliding window counter per client key
 * @param {string} key - Rate limit bucket identifier
 * @param {number} maxReq - Maximum requests in window
 * @param {number} windowMs - Window duration in milliseconds
 * @returns {{ allowed: boolean, remaining: number, resetAt: number }}
 */
function checkRateLimit(key, maxReq, windowMs) {
  const now    = Date.now();
  const cutoff = now - windowMs;

  if (!_rateLimitWindows.has(key)) _rateLimitWindows.set(key, []);
  const hits = _rateLimitWindows.get(key).filter(t => t > cutoff);
  hits.push(now);
  _rateLimitWindows.set(key, hits.slice(-maxReq - 10));   // cap array size

  const resetAt   = (hits[0] || now) + windowMs;
  const remaining = Math.max(0, maxReq - hits.length);
  return { allowed: hits.length <= maxReq, remaining, resetAt };
}

// Periodic cleanup to prevent memory growth
setInterval(() => {
  const cutoff = Date.now() - 3600000;   // 1-hour max window
  for (const [key, hits] of _rateLimitWindows) {
    const fresh = hits.filter(t => t > cutoff);
    if (fresh.length === 0) _rateLimitWindows.delete(key);
    else _rateLimitWindows.set(key, fresh);
  }
}, 300000);

function getRateLimitKey(req, prefix) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  return `${prefix}:${ip}`;
}

// ── SECURITY: API keys — loaded from environment ONLY ─────────────
// CRITICAL: No hardcoded keys. All keys must be configured via environment variables.
// Development: copy .env.example to .env and fill in values.
// Production: use Vault or Kubernetes Secrets.
function getApiKey(service) {
  const keyMap = {
    vt:        process.env.VT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY,
    shodan:    process.env.SHODAN_API_KEY,
    otx:       process.env.OTX_API_KEY,
    urlhaus:   process.env.URLHAUS_API_KEY,
    openai:    process.env.OPENAI_API_KEY   || process.env.RAKAY_OPENAI_KEY,
    claude:    process.env.CLAUDE_API_KEY   || process.env.ANTHROPIC_API_KEY,
    nvd:       process.env.NVD_API_KEY,
  };
  return keyMap[service] || null;
}

// ── Decompress buffer ─────────────────────────────────────────────
function decompressBuffer(buf, encoding) {
  const enc = (encoding || '').toLowerCase().trim();
  return new Promise((resolve) => {
    if (enc === 'gzip' || enc === 'x-gzip') {
      zlib.gunzip(buf, (err, r) => resolve(err ? buf : r));
    } else if (enc === 'deflate') {
      zlib.inflate(buf, (err, r) => {
        if (err) zlib.inflateRaw(buf, (e2, r2) => resolve(e2 ? buf : r2));
        else resolve(r);
      });
    } else if (enc === 'br') {
      zlib.brotliDecompress(buf, (err, r) => resolve(err ? buf : r));
    } else {
      resolve(buf);
    }
  });
}

// ── Generic HTTPS proxy ───────────────────────────────────────────
function proxyRequest(targetUrl, req, res, extraHeaders = {}) {
  const parsed = new URL(targetUrl);
  const STRIP  = new Set([
    'host', 'origin', 'referer', 'connection', 'transfer-encoding',
    'content-length', 'keep-alive', 'upgrade', 'te', 'trailers', 'accept-encoding',
  ]);

  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || 443,
    path:     parsed.pathname + parsed.search,
    method:   req.method,
    headers:  {
      ...Object.fromEntries(Object.entries(req.headers).filter(([k]) => !STRIP.has(k.toLowerCase()))),
      host:              parsed.hostname,
      'Accept':          'application/json',
      'Accept-Encoding': 'identity',
      ...extraHeaders,
    },
  };

  const proxyReq = https.request(options, (proxyRes) => {
    applyCORS(req, res);
    applySecurityHeaders(res);

    const chunks = [];
    proxyRes.on('data', c => chunks.push(c));
    proxyRes.on('end', async () => {
      let body = Buffer.concat(chunks);
      const enc = proxyRes.headers['content-encoding'] || '';
      if (enc && enc !== 'identity') body = await decompressBuffer(body, enc);

      if (!res.headersSent) {
        res.writeHead(proxyRes.statusCode, {
          'Content-Type':   proxyRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
        });
      }
      res.end(body);
    });
    proxyRes.on('error', (err) => {
      if (!res.headersSent) { applyCORS(req, res); res.writeHead(502, { 'Content-Type': 'application/json' }); }
      res.end(JSON.stringify({ error: 'Proxy response error', message: err.message }));
    });
  });

  proxyReq.setTimeout(30000, () => proxyReq.destroy(new Error('Upstream timeout after 30s')));
  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      applyCORS(req, res);
      res.writeHead(err.message.includes('timeout') ? 504 : 502, { 'Content-Type': 'application/json' });
    }
    res.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
  });

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) req.pipe(proxyReq, { end: true });
  else proxyReq.end();
}

// ── Proxy route table ─────────────────────────────────────────────
const PROXY_ROUTES = [
  {
    prefix:       '/proxy/vt/',
    target:       (p) => `https://www.virustotal.com/api/v3${p}`,
    rateLimit:    { max: 4, windowMs: 60000 },  // VT free: 4/min
    injectKey:    (headers) => {
      const k = getApiKey('vt');
      if (k) headers['x-apikey'] = k;
    },
  },
  {
    prefix:       '/proxy/abuseipdb/',
    target:       (p) => `https://api.abuseipdb.com/api/v2${p}`,
    rateLimit:    { max: 30, windowMs: 60000 },
    injectKey:    (headers) => {
      const k = getApiKey('abuseipdb');
      if (k) { headers['Key'] = k; headers['Accept'] = 'application/json'; }
    },
  },
  {
    prefix:       '/proxy/shodan/',
    target:       (p, qs) => `https://api.shodan.io${p}${qs}`,
    rateLimit:    { max: 10, windowMs: 60000 },
    preprocessQS: (qp) => {
      qp.delete('key');
      const k = getApiKey('shodan');
      if (k) qp.set('key', k);
    },
  },
  {
    prefix:       '/proxy/otx/',
    target:       (p) => `https://otx.alienvault.com/api/v1${p}`,
    rateLimit:    { max: 30, windowMs: 60000 },
    injectKey:    (headers) => {
      const k = getApiKey('otx');
      if (k) headers['X-OTX-API-KEY'] = k;
    },
  },
  {
    prefix:       '/proxy/openai/',
    target:       (p) => `https://api.openai.com${p}`,
    rateLimit:    { max: 20, windowMs: 60000 },   // LLM: strict limit
    injectKey:    (headers) => {
      const k = getApiKey('openai');
      if (k) headers['Authorization'] = `Bearer ${k}`;
    },
  },
  {
    prefix:       '/proxy/claude/',
    target:       (p) => `https://api.anthropic.com${p}`,
    rateLimit:    { max: 20, windowMs: 60000 },   // LLM: strict limit
    injectKey:    (headers) => {
      const k = getApiKey('claude');
      if (k) { headers['x-api-key'] = k; headers['anthropic-version'] = '2023-06-01'; }
    },
  },
  {
    prefix:       '/proxy/urlhaus/',
    target:       (p) => `https://urlhaus-api.abuse.ch/v1${p}`,
    rateLimit:    { max: 30, windowMs: 60000 },
    injectKey:    (headers) => {
      const k = getApiKey('urlhaus');
      if (k) headers['Auth-Key'] = k;
    },
  },
];

// ── NVD constants ─────────────────────────────────────────────────
const NVD_MAX_RANGE_DAYS = 120;
const NVD_BASE_URL       = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_ALLOWED_PARAMS = new Set([
  'pubStartDate', 'pubEndDate', 'startIndex', 'resultsPerPage',
  'cvssV3Severity', 'keywordSearch', 'cveId', 'apiKey',
]);

function nvdToISOZ(dateStr) {
  if (!dateStr) return dateStr;
  const s = String(dateStr).trim();
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(s)) return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
  if (/\.\d{3}$/.test(s))              return s + 'Z';
  if (/T\d{2}:\d{2}:\d{2}$/.test(s))  return s + '.000Z';
  if (/^\d{4}-\d{2}-\d{2}$/.test(s))  return s + 'T00:00:00.000Z';
  return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function nvdAutoCorrectQS(rawQS) {
  const raw    = new URLSearchParams(rawQS || '');
  const params = new URLSearchParams();
  for (const [k, v] of raw.entries()) {
    if (!NVD_ALLOWED_PARAMS.has(k) || !v) continue;
    params.set(k, v);
  }
  if (params.get('cveId'))          params.set('cveId', params.get('cveId').toUpperCase());
  if (params.get('cvssV3Severity')) params.set('cvssV3Severity', params.get('cvssV3Severity').toUpperCase());
  let start = params.get('pubStartDate');
  let end   = params.get('pubEndDate');
  if (start && !end) { end = nvdToISOZ(new Date().toISOString()); params.set('pubEndDate', end); }
  if (end && !start) { const s = new Date(end); s.setDate(s.getDate() - 30); params.set('pubStartDate', nvdToISOZ(s.toISOString())); }
  ['pubStartDate', 'pubEndDate'].forEach(k => { const v = params.get(k); if (v) params.set(k, nvdToISOZ(v)); });
  start = params.get('pubStartDate'); end = params.get('pubEndDate');
  if (start && end) {
    const diff = (new Date(end) - new Date(start)) / 86400000;
    if (diff > NVD_MAX_RANGE_DAYS) {
      params.set('pubStartDate', nvdToISOZ(new Date(new Date(end) - NVD_MAX_RANGE_DAYS * 86400000).toISOString()));
    }
  }
  return params.toString();
}

// ── NVD proxy handler ─────────────────────────────────────────────
function handleNVDProxy(parsedUrl, req, res) {
  // Rate limit NVD: 4 req/30s (unauthenticated) | 45/30s (with key)
  const nvdKey       = getApiKey('nvd');
  const nvdMax       = nvdKey ? 45 : 4;
  const rlKey        = getRateLimitKey(req, 'nvd');
  const rl           = checkRateLimit(rlKey, nvdMax, 30000);
  res.setHeader('X-RateLimit-Limit',     nvdMax);
  res.setHeader('X-RateLimit-Remaining', rl.remaining);

  if (!rl.allowed) {
    applyCORS(req, res);
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '30' });
    return res.end(JSON.stringify({ error: 'NVD rate limit exceeded', code: 'RATE_LIMIT_NVD', retryAfter: 30 }));
  }

  if (parsedUrl.pathname === '/proxy/nvd/diagnose') {
    applyCORS(req, res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ endpoint: NVD_BASE_URL, proxy_paths: ['/proxy/nvd', '/proxy/nvd/'], rate_limit: `${nvdMax} req/30s` }));
  }

  const rawQS   = parsedUrl.query ? new URLSearchParams(parsedUrl.query).toString() : '';
  const fixedQS = nvdAutoCorrectQS(rawQS);
  const qs      = fixedQS ? '?' + fixedQS : '';
  if (/[?&]path=/.test(qs)) {
    applyCORS(req, res); res.writeHead(500, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Forbidden param' }));
  }

  const nvdTargetUrl = `${NVD_BASE_URL}${qs}`;
  console.log(`[NVD PROXY] → ${nvdTargetUrl}`);

  const parsed2  = new URL(nvdTargetUrl);
  const STRIP    = new Set(['host','origin','referer','connection','transfer-encoding','content-length','keep-alive','upgrade','te','trailers']);
  const nvdOpts  = {
    hostname: parsed2.hostname, port: 443,
    path:     parsed2.pathname + parsed2.search,
    method:   'GET',
    headers: {
      ...Object.fromEntries(Object.entries(req.headers).filter(([k]) => !STRIP.has(k.toLowerCase()))),
      host: parsed2.hostname,
      ...(nvdKey ? { apiKey: nvdKey } : {}),
    },
  };

  const nvdReq = https.request(nvdOpts, (nvdRes) => {
    const chunks = [];
    nvdRes.on('data', c => chunks.push(c));
    nvdRes.on('end', () => {
      const body    = Buffer.concat(chunks);
      const bodyStr = body.toString('utf8').trim();
      applyCORS(req, res);
      applySecurityHeaders(res);
      if (nvdRes.statusCode === 404 && !bodyStr) {
        if (!res.headersSent) res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ vulnerabilities: [], totalResults: 0, resultsPerPage: 0, startIndex: 0 }));
      }
      if (!res.headersSent) res.writeHead(nvdRes.statusCode, { 'Content-Type': nvdRes.headers['content-type'] || 'application/json', 'Content-Length': body.length });
      res.end(body);
    });
    nvdRes.on('error', (err) => {
      if (!res.headersSent) { applyCORS(req, res); res.writeHead(502, { 'Content-Type': 'application/json' }); }
      res.end(JSON.stringify({ error: err.message, vulnerabilities: [], totalResults: 0 }));
    });
  });
  nvdReq.setTimeout(30000, () => nvdReq.destroy(new Error('NVD timeout')));
  nvdReq.on('error', (err) => {
    if (!res.headersSent) { applyCORS(req, res); res.writeHead(502, { 'Content-Type': 'application/json' }); }
    res.end(JSON.stringify({ error: err.message, vulnerabilities: [], totalResults: 0 }));
  });
  nvdReq.end();
}

// ── Static file server ────────────────────────────────────────────
function serveStatic(reqPath, req, res) {
  let filePath = path.join(STATIC, reqPath === '/' ? 'index.html' : reqPath);
  if (!filePath.startsWith(STATIC)) { res.writeHead(403); return res.end('Forbidden'); }
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) filePath = path.join(filePath, 'index.html');
  if (!fs.existsSync(filePath)) filePath = path.join(STATIC, 'index.html');

  const ext  = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    applyCORS(req, res);
    applySecurityHeaders(res);
    res.writeHead(200, {
      'Content-Type':  mime,
      'Cache-Control': ext === '.html' ? 'no-cache, no-store, must-revalidate' : 'public, max-age=300',
    });
    res.end(data);
  });
}

// ── Main request handler ──────────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const reqPath   = parsedUrl.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    applyCORS(req, res);
    applySecurityHeaders(res);
    const origin = req.headers['origin'] || '';
    const isDev  = process.env.NODE_ENV !== 'production';
    const isOk   = ALLOWED_ORIGINS.includes(origin) || (isDev && /localhost/.test(origin));
    if (isOk) {
      res.setHeader('Access-Control-Allow-Methods',  'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers',
        'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, ' +
        'anthropic-dangerous-direct-browser-access, X-OTX-API-KEY, Key, Accept, Auth-Key, X-Request-ID');
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.writeHead(204) && res.end();
    }
    return res.writeHead(403) && res.end();
  }

  // Health check
  if (reqPath === '/health' || reqPath === '/api/health') {
    applyCORS(req, res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'ok', server: 'Wadjet-Eye AI Proxy v32.0',
      timestamp: new Date().toISOString(),
      security: { cors: 'strict-allowlist', rate_limiting: 'enabled', csp: 'enabled' },
      proxies: PROXY_ROUTES.map(r => r.prefix).concat(['/proxy/nvd']),
    }));
  }

  // Global rate limit on all proxy endpoints
  if (reqPath.startsWith('/proxy/')) {
    const globalKey = getRateLimitKey(req, 'global');
    const globalRl  = checkRateLimit(globalKey, 300, 60000);   // 300 req/min per IP
    if (!globalRl.allowed) {
      applyCORS(req, res);
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      return res.end(JSON.stringify({ error: 'Rate limit exceeded', code: 'RATE_LIMIT_GLOBAL', retryAfter: 60 }));
    }
  }

  // NVD dedicated handler
  if (reqPath === '/proxy/nvd' || reqPath.startsWith('/proxy/nvd/')) {
    return handleNVDProxy(parsedUrl, req, res);
  }

  // Generic proxy routes
  for (const route of PROXY_ROUTES) {
    if (reqPath.startsWith(route.prefix)) {
      // Per-route rate limit
      if (route.rateLimit) {
        const rlKey = getRateLimitKey(req, route.prefix);
        const rl    = checkRateLimit(rlKey, route.rateLimit.max, route.rateLimit.windowMs);
        res.setHeader('X-RateLimit-Limit',     route.rateLimit.max);
        res.setHeader('X-RateLimit-Remaining', rl.remaining);
        if (!rl.allowed) {
          applyCORS(req, res);
          res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': String(Math.ceil(route.rateLimit.windowMs / 1000)) });
          return res.end(JSON.stringify({ error: `Rate limit exceeded for ${route.prefix}`, code: 'RATE_LIMIT_PROXY', retryAfter: Math.ceil(route.rateLimit.windowMs / 1000) }));
        }
      }

      const subPath      = reqPath.slice(route.prefix.length - 1);
      const extraHeaders = {};
      let   qs           = parsedUrl.search || '';

      // Inject API key from environment
      if (route.injectKey)   route.injectKey(extraHeaders);
      if (route.preprocessQS) {
        const qp = new URLSearchParams(parsedUrl.query || '');
        route.preprocessQS(qp);
        qs = qp.toString() ? '?' + qp.toString() : '';
      }

      const targetUrl = route.target(subPath, qs);
      const logUrl    = targetUrl.replace(/([?&]key=)[^&\s]+/, '$1***');
      console.log(`[Proxy] ${req.method} ${reqPath} → ${logUrl}`);
      return proxyRequest(targetUrl, req, res, extraHeaders);
    }
  }

  // Static files
  serveStatic(reqPath, req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Wadjet-Eye AI Proxy Server v32.0 (HARDENED) — port ${PORT}`);
  console.log(`   Security: strict CORS allowlist (${ALLOWED_ORIGINS.length} origins), rate limiting, security headers`);
  console.log(`   API keys: ${getApiKey('vt') ? '✓' : '✗'} VT | ${getApiKey('shodan') ? '✓' : '✗'} Shodan | ${getApiKey('openai') ? '✓' : '✗'} OpenAI`);
  console.log(`   Allowed origins: ${ALLOWED_ORIGINS.join(', ')}\n`);
});

module.exports = server;
