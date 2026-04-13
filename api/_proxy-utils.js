'use strict';

const https = require('https');
const http  = require('http');

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

// ── Generic upstream request ───────────────────────────────────
async function proxyUpstream(targetUrl, req, res, extraHeaders = {}, bodyOverride = null) {
  const parsed  = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const STRIP = new Set([
    'host','origin','referer','connection','transfer-encoding',
    'content-length','keep-alive','upgrade','te','trailers',
  ]);

  let bodyBuf = bodyOverride;
  if (bodyBuf === null && ['POST','PUT','PATCH'].includes(req.method)) {
    bodyBuf = await readBody(req);
  }

  const fwdHeaders = {
    ...Object.fromEntries(
      Object.entries(req.headers || {}).filter(([k]) => !STRIP.has(k.toLowerCase()))
    ),
    host: parsed.hostname,
    Accept: 'application/json',   // ✅ critical
    ...extraHeaders,
  };

  if (bodyBuf?.length) {
    fwdHeaders['content-length'] = bodyBuf.length;
  }

  const options = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: req.method || 'GET',
    headers: fwdHeaders,
    timeout: 30000,
  };

  return new Promise((resolve) => {
    const upReq = lib.request(options, (upRes) => {
      const chunks = [];
      upRes.on('data', c => chunks.push(c));
      upRes.on('end', () => {
        const body = Buffer.concat(chunks);
        setCORS(res);
        res.writeHead(upRes.statusCode || 200, {
          'Content-Type': upRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
          ...CORS_HEADERS,
        });
        res.end(body);
        resolve();
      });
    });

    upReq.on('error', () => resolve());
    if (bodyBuf?.length) upReq.write(bodyBuf);
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

// ✅ apiKey REMOVED from whitelist
const NVD_PARAM_WHITELIST = new Set([
  'pubStartDate','pubEndDate','startIndex','resultsPerPage',
  'cvssV3Severity','keywordSearch','cveId'
]);

function nvdAutoCorrect(rawQS) {
  const raw = new URLSearchParams(rawQS || '');
  const p = new URLSearchParams();

  for (const [k,v] of raw.entries()) {
    if (!NVD_PARAM_WHITELIST.has(k)) continue;
    if (!v) continue;
    p.set(k,v);
  }

  if (p.get('cveId')) p.set('cveId', p.get('cveId').toUpperCase());
  if (p.get('cvssV3Severity')) p.set('cvssV3Severity', p.get('cvssV3Severity').toUpperCase());

  ['pubStartDate','pubEndDate'].forEach(k=>{
    const v=p.get(k);
    if(v)p.set(k,nvdToISOZ(v));
  });

  return p.toString();
}

// ── extractSubPath (defined BEFORE export) ───────────────────
function extractSubPath(req) {
  const rawUrl = req.url || '';
  const qIndex = rawUrl.indexOf('?');
  const qsPart = qIndex >= 0 ? rawUrl.slice(qIndex + 1) : '';
  const params = new URLSearchParams(qsPart);

  const injectedPath = params.get('_path');
  params.delete('_path');

  let subPath = '/';
  if (injectedPath) {
    const decoded = decodeURIComponent(injectedPath);
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
  nvdAutoCorrect,
  nvdToISOZ,
  extractSubPath,
};
