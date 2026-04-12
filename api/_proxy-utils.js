/**
 * Wadjet-Eye AI — Vercel Proxy Utilities v1.0
 * Shared helpers used by all /api/proxy/* serverless functions.
 *
 * Responsibilities:
 *   - CORS headers
 *   - Upstream HTTPS forwarding with full response buffering
 *   - Safe JSON error responses (proxy never crashes the frontend)
 *   - API key retrieval from environment variables ONLY (never from client)
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── CORS ──────────────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, PATCH, DELETE',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, X-OTX-API-KEY, Key, Accept',
  'Access-Control-Max-Age':       '86400',
};

function setCORS(res) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
}

// ── Safe JSON response ─────────────────────────────────────────
function sendJSON(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
    ...CORS_HEADERS,
  });
  res.end(json);
}

// ── Collect request body ───────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Generic upstream HTTPS/HTTP request ───────────────────────
/**
 * proxyUpstream — forwards a request to targetUrl, buffers the full
 * response, and writes it back to the Vercel response object.
 *
 * @param {string}  targetUrl    Full URL of the upstream API.
 * @param {object}  req          Incoming Vercel/Node req.
 * @param {object}  res          Vercel/Node res.
 * @param {object}  extraHeaders Additional headers to send upstream.
 * @param {Buffer}  bodyOverride Override request body (for POST forwarding).
 */
async function proxyUpstream(targetUrl, req, res, extraHeaders = {}, bodyOverride = null) {
  const parsed  = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const STRIP = new Set([
    'host','origin','referer','connection','transfer-encoding',
    'content-length','keep-alive','upgrade','te','trailers',
  ]);

  // Build body buffer
  let bodyBuf = bodyOverride;
  if (bodyBuf === null && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
    bodyBuf = await readBody(req);
  }

  const fwdHeaders = {
    ...Object.fromEntries(
      Object.entries(req.headers || {}).filter(([k]) => !STRIP.has(k.toLowerCase()))
    ),
    host: parsed.hostname,
    ...extraHeaders,
  };
  if (bodyBuf && bodyBuf.length > 0) {
    fwdHeaders['content-length'] = bodyBuf.length;
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
    const upReq = lib.request(options, (upRes) => {
      const chunks = [];
      upRes.on('data', c => chunks.push(c));
      upRes.on('end', () => {
        const body    = Buffer.concat(chunks);
        const bodyStr = body.toString('utf8').trim();
        const status  = upRes.statusCode || 502;
        const ct      = upRes.headers['content-type'] || 'application/json';

        setCORS(res);

        // Upstream 404 with empty body → safe fallback JSON
        if (status === 404 && !bodyStr) {
          console.warn(`[Proxy] Upstream 404 empty body for: ${targetUrl}`);
          sendJSON(res, 200, {
            data: [], results: [], vulnerabilities: [],
            totalResults: 0,
            message: `No data or invalid query (upstream HTTP 404). URL: ${targetUrl}`,
          });
          return resolve();
        }

        // Non-2xx → dynamic error, always parseable JSON
        if (status >= 400) {
          const dynamicMsg = `HTTP ${status}: ${bodyStr.slice(0, 300) || 'empty response'}`;
          console.warn(`[Proxy] Upstream error for ${targetUrl}: ${dynamicMsg}`);
          let outBody;
          try {
            const parsed2 = JSON.parse(bodyStr);
            outBody = { ...parsed2, _proxy_error: dynamicMsg };
          } catch (_) {
            outBody = { error: dynamicMsg, data: [], results: [], totalResults: 0 };
          }
          sendJSON(res, status, outBody);
          return resolve();
        }

        // Success — forward transparently
        if (!res.headersSent) {
          res.writeHead(status, {
            'Content-Type':   ct,
            'Content-Length': body.length,
            ...CORS_HEADERS,
          });
        }
        res.end(body);
        resolve();
      });
      upRes.on('error', (err) => {
        console.error('[Proxy] Response stream error:', err.message);
        if (!res.headersSent) {
          sendJSON(res, 502, { error: 'Proxy response error', message: err.message });
        }
        resolve();
      });
    });

    upReq.on('timeout', () => {
      upReq.destroy(new Error('Upstream timeout after 30s'));
    });
    upReq.on('error', (err) => {
      console.error('[Proxy] Request error:', err.message);
      if (!res.headersSent) {
        sendJSON(res, err.message.includes('timeout') ? 504 : 502, {
          error: 'Proxy error', message: err.message, data: [], totalResults: 0,
        });
      }
      resolve();
    });

    if (bodyBuf && bodyBuf.length > 0) {
      upReq.write(bodyBuf);
    }
    upReq.end();
  });
}

// ── NVD date helpers ───────────────────────────────────────────
const NVD_MAX_RANGE_DAYS = 120;

function nvdToISOZ(dateStr) {
  if (!dateStr) return dateStr;
  const s = String(dateStr).trim();
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(s)) return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
  if (/\.\d{3}$/.test(s)) return s + 'Z';
  if (/T\d{2}:\d{2}:\d{2}$/.test(s)) return s + '.000Z';
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + 'T00:00:00.000Z';
  return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function nvdAutoCorrect(params) {
  const p = new URLSearchParams(params);

  if (p.get('cveId')) p.set('cveId', p.get('cveId').toUpperCase());

  let pubStart = p.get('pubStartDate');
  let pubEnd   = p.get('pubEndDate');

  if (pubStart && !pubEnd) { pubEnd = nvdToISOZ(new Date().toISOString()); p.set('pubEndDate', pubEnd); }
  if (pubEnd && !pubStart) { const s = new Date(pubEnd); s.setDate(s.getDate()-30); pubStart = nvdToISOZ(s.toISOString()); p.set('pubStartDate', pubStart); }

  ['pubStartDate','pubEndDate'].forEach(k => { const v=p.get(k); if(v){ const f=nvdToISOZ(v); if(f!==v) p.set(k,f); } });

  pubStart = p.get('pubStartDate'); pubEnd = p.get('pubEndDate');
  if (pubStart && pubEnd) {
    const diff = (new Date(pubEnd) - new Date(pubStart)) / 86400000;
    if (diff > NVD_MAX_RANGE_DAYS) {
      p.set('pubStartDate', nvdToISOZ(new Date(new Date(pubEnd) - NVD_MAX_RANGE_DAYS*86400000).toISOString()));
    }
  }

  return p.toString();
}

module.exports = { setCORS, sendJSON, readBody, proxyUpstream, nvdAutoCorrect, nvdToISOZ, extractSubPath };

/**
 * extractSubPath — resolve the sub-path for a proxy handler.
 *
 * Vercel rewrites pass `/proxy/vt/ip_addresses/1.2.3.4?foo=bar` as:
 *   req.url = "/api/proxy/vt?_path=ip_addresses%2F1.2.3.4&foo=bar"
 *
 * We reconstruct the full sub-path + original query string from:
 *   1. _path param   → the path segment (URL-decoded)
 *   2. All other query params → forwarded as-is (minus _path itself)
 *
 * @param {object} req     Vercel/Node req
 * @param {string} prefix  Route prefix to strip (e.g. '/proxy/vt')
 * @returns {string}  Sub-path starting with '/', including original query string
 */
function extractSubPath(req, prefix) {
  const rawUrl  = req.url || '';
  const qIndex  = rawUrl.indexOf('?');
  const pathPart = qIndex >= 0 ? rawUrl.slice(0, qIndex) : rawUrl;
  const qsPart   = qIndex >= 0 ? rawUrl.slice(qIndex + 1) : '';
  const params   = new URLSearchParams(qsPart);

  // _path is injected by Vercel rewrite; it contains the captured :path* segment
  const injectedPath = params.get('_path') || '';
  params.delete('_path'); // don't forward Vercel's internal param upstream

  // Reconstruct sub-path: prefer _path over stripping the function prefix
  let subPath;
  if (injectedPath) {
    subPath = '/' + injectedPath;
  } else {
    // Fallback: strip the function route prefix from the URL path
    const stripped = pathPart.replace(new RegExp(`^${prefix}`, 'i'), '') || '/';
    subPath = stripped.startsWith('/') ? stripped : '/' + stripped;
  }

  const remainingQS = params.toString();
  return remainingQS ? `${subPath}?${remainingQS}` : subPath;
}

