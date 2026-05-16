'use strict';

/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Proxy Utilities  v3.0  (Security Hardened)
 *  api/_proxy-utils.js
 *
 *  Security fixes applied (Audit Phase 0):
 *  ─────────────────────────────────────────────────────────────────
 *  FIX-001: Origin-validated CORS — wildcard '*' removed.
 *           Allowed origins sourced from CORS_ALLOWED_ORIGINS env var
 *           (comma-separated list). Requests from unknown origins
 *           receive a 403 with no CORS headers.
 *
 *  FIX-004: SSRF protection — all upstream URLs validated through
 *           isPrivateAddress() before any outbound HTTP/HTTPS request.
 *           Blocks RFC 1918 (10.x, 172.16-31.x, 192.168.x), loopback
 *           (127.0.0.0/8, ::1), link-local (169.254.x), Carrier-grade
 *           NAT (100.64.0.0/10), and Unique Local (fc00::/7).
 *           Uses node's built-in dns.lookup for hostname resolution so
 *           DNS rebinding is also mitigated (resolve then check).
 *
 *  NOTE ON API KEYS: Hard-coded keys in individual proxy handlers are
 *  a separate finding (SEC-003). They should be rotated and moved to
 *  Vault (ARCH-002). This file does NOT modify those values; it only
 *  adds CORS and SSRF protection layers.
 * ══════════════════════════════════════════════════════════════════
 */

const https = require('https');
const http  = require('http');
const zlib  = require('zlib');
const dns   = require('dns').promises;
const net   = require('net');

// ─────────────────────────────────────────────────────────────────
//  FIX-001: Origin-Validated CORS
//  ─────────────────────────────
//  Allowed origins: comma-separated list in CORS_ALLOWED_ORIGINS env.
//  Falls back to vercel.app + localhost in development when not set.
//  The header "Vary: Origin" is always sent so CDN caches differentiate.
// ─────────────────────────────────────────────────────────────────

/** @type {Set<string>} */
const _ALLOWED_ORIGINS = new Set(
  (process.env.CORS_ALLOWED_ORIGINS || 'https://wadjet-eye.vercel.app,http://localhost:3000,http://localhost:5173')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);

/**
 * resolveOrigin — determine the correct Access-Control-Allow-Origin value
 * for the incoming request, or null if the origin is not permitted.
 *
 * @param {import('http').IncomingMessage} req
 * @returns {string|null}
 */
function resolveOrigin(req) {
  const origin = req.headers.origin || '';

  // Pre-flight or same-origin requests have no Origin header — allow them.
  if (!origin) return null;

  if (_ALLOWED_ORIGINS.has(origin)) return origin;

  // Also allow any vercel.app subdomain for preview deployments
  if (/^https:\/\/[a-z0-9-]+-[a-z0-9]+\.vercel\.app$/.test(origin)) return origin;

  return null; // Deny
}

/**
 * setCORS — attach CORS headers to a response.
 * Returns false if origin is not allowed (caller should abort with 403).
 *
 * @param {import('http').IncomingMessage}  req
 * @param {import('http').ServerResponse}   res
 * @param {boolean} [preflight=false]
 * @returns {boolean} true = allowed, false = denied
 */
function setCORS(req, res, preflight = false) {
  const allowedOrigin = resolveOrigin(req);

  // Add Vary regardless so CDN caches behave correctly
  res.setHeader('Vary', 'Origin');

  if (!allowedOrigin) {
    const origin = req.headers.origin || '';
    if (origin) {
      // Unknown origin — deny CORS but do NOT leak allowed list
      console.warn(`[CORS] Rejected origin: ${origin} ${req.method} ${req.url}`);
      return false;
    }
    // No Origin header — same-origin or server-to-server, allow without CORS headers
    return true;
  }

  res.setHeader('Access-Control-Allow-Origin',      allowedOrigin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (preflight) {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, X-OTX-API-KEY, Key, Accept, Auth-Key, X-Client-VT-Key, X-Client-Abuse-Key, X-Client-Shodan-Key, X-Client-OTX-Key'
    );
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  return true;
}

/**
 * handlePreflight — respond to OPTIONS pre-flight with validated CORS headers.
 * Returns true if the request was handled (caller should return immediately).
 *
 * @param {import('http').IncomingMessage}  req
 * @param {import('http').ServerResponse}   res
 * @returns {boolean}
 */
function handlePreflight(req, res) {
  if (req.method !== 'OPTIONS') return false;

  const allowed = setCORS(req, res, true);
  if (!allowed) {
    res.writeHead(403); res.end('Forbidden origin');
    return true;
  }
  res.writeHead(204); res.end();
  return true;
}

// ─────────────────────────────────────────────────────────────────
//  FIX-004: SSRF Protection
//  ────────────────────────
//  Block requests to private / loopback / link-local address spaces.
//  Resolves hostnames via DNS before checking so DNS rebinding is
//  also prevented.
// ─────────────────────────────────────────────────────────────────

/**
 * PRIVATE_RANGES — list of [networkAddress, prefixLength] for IPv4/IPv6 ranges
 * that must never be reached from this proxy.
 */
const PRIVATE_RANGES_V4 = [
  ['10.0.0.0',      8],   // RFC 1918
  ['172.16.0.0',   12],   // RFC 1918
  ['192.168.0.0',  16],   // RFC 1918
  ['127.0.0.0',     8],   // Loopback
  ['169.254.0.0',  16],   // Link-local (AWS metadata 169.254.169.254)
  ['100.64.0.0',   10],   // Carrier-grade NAT (RFC 6598)
  ['192.0.2.0',    24],   // TEST-NET-1 (RFC 5737)
  ['198.51.100.0', 24],   // TEST-NET-2 (RFC 5737)
  ['203.0.113.0',  24],   // TEST-NET-3 (RFC 5737)
  ['0.0.0.0',       8],   // "This" network
  ['240.0.0.0',     4],   // Reserved (RFC 1112)
];

const PRIVATE_RANGES_V6 = [
  ['::1',          128],  // Loopback
  ['fc00::',         7],  // Unique Local (fc00::/7 covers fc00:: and fd00::)
  ['fe80::',        10],  // Link-local
  ['::ffff:0:0',   96],   // IPv4-mapped
];

/**
 * ipv4ToLong — convert dotted-decimal IPv4 to unsigned 32-bit integer.
 * @param {string} ip
 * @returns {number}
 */
function ipv4ToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * isPrivateIPv4 — check if an IPv4 address falls in a restricted range.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIPv4(ip) {
  const long = ipv4ToLong(ip);
  for (const [network, prefix] of PRIVATE_RANGES_V4) {
    const netLong = ipv4ToLong(network);
    const mask    = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    if ((long & mask) === (netLong & mask)) return true;
  }
  return false;
}

/**
 * expandIPv6 — expand a compressed IPv6 address to full 8-group form.
 * @param {string} ip
 * @returns {bigint}
 */
function ipv6ToBigInt(ip) {
  // Strip brackets if present
  ip = ip.replace(/^\[|\]$/g, '');

  // Handle IPv4-mapped: ::ffff:1.2.3.4
  if (ip.includes('.')) {
    const parts = ip.split(':');
    const ipv4  = parts.pop();
    const v4num = ipv4ToLong(ipv4);
    const hi    = v4num >>> 16;
    const lo    = v4num & 0xffff;
    parts.push(hi.toString(16), lo.toString(16));
    ip = parts.join(':');
  }

  const halves = ip.split('::');
  let left  = halves[0] ? halves[0].split(':') : [];
  let right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  const middle  = Array(missing).fill('0');
  const groups  = [...left, ...middle, ...right];

  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g || '0', 16)), 0n);
}

/**
 * isPrivateIPv6 — check if an IPv6 address falls in a restricted range.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIPv6(ip) {
  const addr = ipv6ToBigInt(ip);
  for (const [network, prefix] of PRIVATE_RANGES_V6) {
    const net  = ipv6ToBigInt(network);
    const mask = prefix === 0 ? 0n : (~0n << BigInt(128 - prefix));
    if ((addr & mask) === (net & mask)) return true;
  }
  return false;
}

/**
 * isPrivateAddress — resolve hostname and check if it resolves to a private IP.
 * Throws an error (which callers convert to 400/403) if SSRF risk detected.
 *
 * @param {string} hostname
 * @returns {Promise<void>}
 * @throws {Error} If the address is private/reserved
 */
async function assertNotPrivateAddress(hostname) {
  // Block metadata services by hostname
  const BLOCKED_HOSTS = new Set([
    'metadata.google.internal',
    'instance-data',
    '169.254.169.254', // AWS/GCP/Azure IMDS
    'fd00:ec2::254',   // AWS IPv6 IMDS
  ]);

  if (BLOCKED_HOSTS.has(hostname.toLowerCase())) {
    throw new Error(`SSRF: blocked hostname "${hostname}"`);
  }

  // Pure numeric IP — check without DNS
  if (net.isIPv4(hostname)) {
    if (isPrivateIPv4(hostname)) {
      throw new Error(`SSRF: private IPv4 address "${hostname}" is not allowed`);
    }
    return;
  }

  if (net.isIPv6(hostname)) {
    if (isPrivateIPv6(hostname)) {
      throw new Error(`SSRF: private IPv6 address "${hostname}" is not allowed`);
    }
    return;
  }

  // Hostname — resolve and check each returned address
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (err) {
    throw new Error(`SSRF: DNS resolution failed for "${hostname}": ${err.message}`);
  }

  for (const { address, family } of addresses) {
    if (family === 4 && isPrivateIPv4(address)) {
      throw new Error(`SSRF: hostname "${hostname}" resolves to private IPv4 ${address}`);
    }
    if (family === 6 && isPrivateIPv6(address)) {
      throw new Error(`SSRF: hostname "${hostname}" resolves to private IPv6 ${address}`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────
//  Core HTTP helpers
// ─────────────────────────────────────────────────────────────────

/**
 * sendJSON — send a JSON response with CORS headers.
 *
 * @param {import('http').IncomingMessage}  req
 * @param {import('http').ServerResponse}   res
 * @param {number} status
 * @param {object} body
 */
function sendJSON(req, res, status, body) {
  const json = JSON.stringify(body);

  const allowedOrigin = resolveOrigin(req);
  const corsHeaders   = allowedOrigin
    ? { 'Access-Control-Allow-Origin': allowedOrigin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' }
    : { 'Vary': 'Origin' };

  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
    ...corsHeaders,
  });
  res.end(json);
}

/**
 * readBody — collect the request body as a Buffer.
 *
 * @param {import('http').IncomingMessage} req
 * @returns {Promise<Buffer>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Decompress buffer (gzip / deflate / br) ───────────────────────
function decompressBody(buf, encoding) {
  const enc = (encoding || '').toLowerCase().trim();
  return new Promise((resolve, reject) => {
    if (enc === 'gzip' || enc === 'x-gzip') {
      zlib.gunzip(buf, (err, r) => err ? reject(err) : resolve(r));
    } else if (enc === 'deflate') {
      zlib.inflate(buf, (err, r) => {
        if (err) zlib.inflateRaw(buf, (e2, r2) => e2 ? reject(e2) : resolve(r2));
        else resolve(r);
      });
    } else if (enc === 'br') {
      zlib.brotliDecompress(buf, (err, r) => err ? reject(err) : resolve(r));
    } else {
      resolve(buf);
    }
  });
}

// ── Auto-detect gzip by magic bytes and decompress ─────────────────
async function ensureDecompressed(buf, contentEncoding) {
  if (contentEncoding && contentEncoding !== 'identity') {
    try { return await decompressBody(buf, contentEncoding); }
    catch (_) { /* fall through */ }
  }
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try { return await decompressBody(buf, 'gzip'); } catch (_) {}
  }
  return buf;
}

// ─────────────────────────────────────────────────────────────────
//  Generic upstream proxy request (SSRF-protected)
// ─────────────────────────────────────────────────────────────────

/**
 * proxyUpstream — forward the request to targetUrl with SSRF protection.
 *
 * FIX-004: Validates the target hostname against private IP ranges before
 * making any outbound connection.  Also validates CORS origin before
 * attaching response headers (FIX-001).
 *
 * @param {string}  targetUrl    - Full upstream URL to forward to
 * @param {import('http').IncomingMessage}  req
 * @param {import('http').ServerResponse}   res
 * @param {object}  [extraHeaders={}]       - Additional headers to inject
 * @param {Buffer|null} [bodyOverride=null] - Override request body
 */
async function proxyUpstream(targetUrl, req, res, extraHeaders = {}, bodyOverride = null) {
  const parsed  = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const lib     = isHttps ? https : http;

  // ── FIX-004: SSRF guard ──────────────────────────────────────────
  try {
    await assertNotPrivateAddress(parsed.hostname);
  } catch (ssrfErr) {
    console.error(`[Proxy] SSRF attempt blocked: ${ssrfErr.message} — ${req.method} ${req.url}`);
    sendJSON(req, res, 400, { error: 'invalid_target', message: 'Target address not permitted' });
    return;
  }

  // Headers stripped from incoming request before forwarding
  const STRIP_REQ = new Set([
    'host', 'origin', 'referer', 'connection', 'transfer-encoding',
    'content-length', 'keep-alive', 'upgrade', 'te', 'trailers',
    'accept-encoding',
  ]);

  let bodyBuf = bodyOverride;
  if (bodyBuf === null && ['POST', 'PUT', 'PATCH'].includes(req.method)) {
    bodyBuf = await readBody(req);
  }

  const fwdHeaders = {
    ...Object.fromEntries(
      Object.entries(req.headers || {}).filter(([k]) => !STRIP_REQ.has(k.toLowerCase()))
    ),
    host:              parsed.hostname,
    'Accept':          'application/json',
    'Accept-Encoding': 'identity',
    ...extraHeaders,
  };

  if (bodyBuf && bodyBuf.length) {
    fwdHeaders['content-length'] = String(bodyBuf.length);
  }

  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || (isHttps ? 443 : 80),
    path:     parsed.pathname + parsed.search,
    method:   req.method || 'GET',
    headers:  fwdHeaders,
    timeout:  30000,
  };

  return new Promise((resolve) => {
    const upReq = lib.request(options, async (upRes) => {
      const chunks = [];
      upRes.on('data',  c => chunks.push(c));
      upRes.on('end', async () => {
        let body = Buffer.concat(chunks);

        const enc = upRes.headers['content-encoding'] || '';
        body = await ensureDecompressed(body, enc);

        // ── FIX-001: Validated CORS headers ─────────────────────────
        const allowedOrigin = resolveOrigin(req);
        const corsHdrs = allowedOrigin
          ? { 'Access-Control-Allow-Origin': allowedOrigin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' }
          : { 'Vary': 'Origin' };

        res.writeHead(upRes.statusCode || 200, {
          'Content-Type':   upRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
          ...corsHdrs,
        });
        res.end(body);
        resolve();
      });

      upRes.on('error', () => {
        if (!res.headersSent) sendJSON(req, res, 502, { error: 'upstream_read_error' });
        resolve();
      });
    });

    upReq.on('timeout', () => {
      upReq.destroy();
      if (!res.headersSent)
        sendJSON(req, res, 504, { error: 'upstream_timeout', message: 'Upstream API timed out after 30s' });
      resolve();
    });

    upReq.on('error', (err) => {
      if (!res.headersSent)
        sendJSON(req, res, 502, { error: 'upstream_error', message: err.message });
      resolve();
    });

    if (bodyBuf && bodyBuf.length) upReq.write(bodyBuf);
    upReq.end();
  });
}

// ── NVD helpers ──────────────────────────────────────────────────
const NVD_MAX_RANGE_DAYS = 120;

function nvdToISOZ(dateStr) {
  const s = String(dateStr || '').trim();
  if (!s) return s;
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(s)) return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + 'T00:00:00.000Z';
  return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

const NVD_PARAM_WHITELIST = new Set([
  'pubStartDate', 'pubEndDate', 'startIndex', 'resultsPerPage',
  'cvssV3Severity', 'keywordSearch', 'cveId',
]);

function nvdAutoCorrect(rawQS) {
  const raw = new URLSearchParams(rawQS || '');
  const p   = new URLSearchParams();
  for (const [k, v] of raw.entries()) {
    if (!NVD_PARAM_WHITELIST.has(k) || !v) continue;
    p.set(k, v);
  }
  if (p.get('cveId'))          p.set('cveId',          p.get('cveId').toUpperCase());
  if (p.get('cvssV3Severity')) p.set('cvssV3Severity', p.get('cvssV3Severity').toUpperCase());
  ['pubStartDate', 'pubEndDate'].forEach(k => {
    const v = p.get(k);
    if (v) p.set(k, nvdToISOZ(v));
  });
  return p.toString();
}

// ── extractSubPath ────────────────────────────────────────────────
function extractSubPath(req) {
  const rawUrl = req.url || '';
  const qIndex = rawUrl.indexOf('?');
  const qsPart = qIndex >= 0 ? rawUrl.slice(qIndex + 1) : '';
  const params = new URLSearchParams(qsPart);

  const injectedPath = params.get('_path');
  params.delete('_path');

  let subPath = '/';
  if (injectedPath) {
    let decoded = injectedPath;
    try { decoded = decodeURIComponent(injectedPath); } catch (_) {}
    subPath = decoded.startsWith('/') ? decoded : '/' + decoded;
  }

  const remainingQS = params.toString();
  return remainingQS ? `${subPath}?${remainingQS}` : subPath;
}

module.exports = {
  // CORS helpers
  setCORS,
  handlePreflight,
  resolveOrigin,
  // SSRF helpers
  assertNotPrivateAddress,
  isPrivateIPv4,
  isPrivateIPv6,
  // Core HTTP
  sendJSON,
  readBody,
  proxyUpstream,
  decompressBody,
  ensureDecompressed,
  // NVD
  nvdAutoCorrect,
  nvdToISOZ,
  extractSubPath,
};
