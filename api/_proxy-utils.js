'use strict';

const https = require('https');
const http  = require('http');
const zlib  = require('zlib');

// ── CORS ──────────────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, PATCH, DELETE',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, X-OTX-API-KEY, Key, Accept, Auth-Key, X-Client-VT-Key, X-Client-Abuse-Key, X-Client-Shodan-Key, X-Client-OTX-Key',
  'Access-Control-Max-Age':       '86400',
};

function setCORS(res) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
}

function sendJSON(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
    ...CORS_HEADERS,
  });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Decompress buffer (gzip / deflate / br) ───────────────────
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

// ── Auto-detect gzip by magic bytes and decompress ────────────
async function ensureDecompressed(buf, contentEncoding) {
  // First try declared encoding
  if (contentEncoding && contentEncoding !== 'identity') {
    try {
      return await decompressBody(buf, contentEncoding);
    } catch (_) { /* fall through to magic-byte detection */ }
  }
  // Detect gzip magic bytes: 0x1f 0x8b
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try { return await decompressBody(buf, 'gzip'); } catch (_) {}
  }
  // Detect brotli (no reliable magic, skip)
  return buf;
}

// ── Generic upstream request ───────────────────────────────────
async function proxyUpstream(targetUrl, req, res, extraHeaders = {}, bodyOverride = null) {
  const parsed  = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const lib     = isHttps ? https : http;

  // Headers stripped from incoming request before forwarding
  const STRIP_REQ = new Set([
    'host', 'origin', 'referer', 'connection', 'transfer-encoding',
    'content-length', 'keep-alive', 'upgrade', 'te', 'trailers',
    'accept-encoding',   // strip so upstream returns plain JSON
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
    'Accept-Encoding': 'identity',   // ask upstream for no compression
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

        // Decompress — handles both declared and undeclared (magic-byte) gzip
        const enc = upRes.headers['content-encoding'] || '';
        body = await ensureDecompressed(body, enc);

        // Reply to client — never send Content-Encoding (body is now plain)
        setCORS(res);
        res.writeHead(upRes.statusCode || 200, {
          'Content-Type':   upRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
          ...CORS_HEADERS,
        });
        res.end(body);
        resolve();
      });

      upRes.on('error', () => {
        if (!res.headersSent) sendJSON(res, 502, { error: 'upstream_read_error' });
        resolve();
      });
    });

    upReq.on('timeout', () => {
      upReq.destroy();
      if (!res.headersSent)
        sendJSON(res, 504, { error: 'upstream_timeout', message: 'Upstream API timed out after 30s' });
      resolve();
    });

    upReq.on('error', (err) => {
      if (!res.headersSent)
        sendJSON(res, 502, { error: 'upstream_error', message: err.message });
      resolve();
    });

    if (bodyBuf && bodyBuf.length) upReq.write(bodyBuf);
    upReq.end();
  });
}

// ── NVD helpers ───────────────────────────────────────────────
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
  if (p.get('cveId'))        p.set('cveId',        p.get('cveId').toUpperCase());
  if (p.get('cvssV3Severity')) p.set('cvssV3Severity', p.get('cvssV3Severity').toUpperCase());
  ['pubStartDate', 'pubEndDate'].forEach(k => {
    const v = p.get(k);
    if (v) p.set(k, nvdToISOZ(v));
  });
  return p.toString();
}

// ── extractSubPath ────────────────────────────────────────────
// Works with both Vercel rewrites (?_path=...) and routes ($1 capture groups)
function extractSubPath(req) {
  const rawUrl = req.url || '';
  const qIndex = rawUrl.indexOf('?');
  const qsPart = qIndex >= 0 ? rawUrl.slice(qIndex + 1) : '';
  const params = new URLSearchParams(qsPart);

  const injectedPath = params.get('_path');
  params.delete('_path');

  let subPath = '/';
  if (injectedPath) {
    // decode but preserve slashes (don't double-decode)
    let decoded = injectedPath;
    try { decoded = decodeURIComponent(injectedPath); } catch (_) {}
    subPath = decoded.startsWith('/') ? decoded : '/' + decoded;
  }

  const remainingQS = params.toString();
  return remainingQS ? `${subPath}?${remainingQS}` : subPath;
}

module.exports = {
  setCORS,
  sendJSON,
  readBody,
  proxyUpstream,
  decompressBody,
  ensureDecompressed,
  nvdAutoCorrect,
  nvdToISOZ,
  extractSubPath,
};
