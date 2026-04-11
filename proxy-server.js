/**
 * Wadjet-Eye AI — Local Proxy Server v31.1
 * Serves static files + proxies NVD, OpenAI, Claude, VT, AbuseIPDB, Shodan, OTX
 * Logic: Streamlined NVD handler with auto-correction and CORS bypass.
 */
'use strict';

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');

const PORT   = 3000;
const STATIC = __dirname;
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_MAX_RANGE_DAYS = 120;

// ── MIME types ────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.webp': 'image/webp',
};

// ── CORS headers ──────────────────────────────────────────────
function addCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key, apiKey, x-apikey, anthropic-version, anthropic-dangerous-direct-browser-access, X-OTX-API-KEY, Key, Accept');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// ── NVD Parameter Auto-Correction ────────────────────────────
function nvdToISOZ(dateStr) {
  if (!dateStr) return dateStr;
  try {
    const s = String(dateStr).trim();
    const date = new Date(s);
    // Ensure .000Z format required by NVD
    return date.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  } catch (e) { return dateStr; }
}

function nvdAutoCorrectQS(rawQS) {
  const params = new URLSearchParams(rawQS);
  
  // Fix 1: CVE ID Case
  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  if (pubStart || pubEnd) {
    // Fix 2: Ensure paired dates
    if (pubStart && !pubEnd) pubEnd = new Date().toISOString();
    if (pubEnd && !pubStart) {
      let s = new Date(pubEnd);
      s.setDate(s.getDate() - 30);
      pubStart = s.toISOString();
    }
    
    // Fix 3: Normalize to ISO UTC
    pubStart = nvdToISOZ(pubStart);
    pubEnd = nvdToISOZ(pubEnd);
    
    // Fix 4: Clamp to 120 days
    const diff = (new Date(pubEnd) - new Date(pubStart)) / 86400000;
    if (diff > NVD_MAX_RANGE_DAYS) {
      pubStart = nvdToISOZ(new Date(new Date(pubEnd).getTime() - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
    }
    
    params.set('pubStartDate', pubStart);
    params.set('pubEndDate', pubEnd);
  }
  return params.toString();
}

// ── Dedicated NVD Proxy Handler ───────────────────────────────
function handleNVDProxy(parsedUrl, req, res) {
  const rawQS = parsedUrl.query ? new URLSearchParams(parsedUrl.query).toString() : '';
  const fixedQS = nvdAutoCorrectQS(rawQS);
  const target = fixedQS ? `${NVD_BASE_URL}?${fixedQS}` : NVD_BASE_URL;

  console.log('[NVD PROXY]', target);

  const u = new URL(target);
  const options = {
    hostname: u.hostname,
    path: u.pathname + u.search,
    method: 'GET',
    headers: {
      'User-Agent': 'wadjet-eye-ai-proxy',
      // Pass through apiKey if present in original request
      ...(req.headers['apikey'] && { 'apiKey': req.headers['apikey'] })
    }
  };

  const pReq = https.request(options, pRes => {
    let chunks = [];
    pRes.on('data', d => chunks.push(d));
    pRes.on('end', () => {
      addCORS(res);
      const body = Buffer.concat(chunks);
      const bodyStr = body.toString('utf8').trim();

      // Upstream 404 with empty body fallback
      if (pRes.statusCode === 404 && !bodyStr) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ vulnerabilities: [], totalResults: 0, message: "No data (NVD 404)" }));
      }

      res.writeHead(pRes.statusCode, {
        'Content-Type': pRes.headers['content-type'] || 'application/json'
      });
      res.end(body);
    });
  });

  pReq.on('error', e => {
    addCORS(res);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: e.message }));
  });

  pReq.end();
}

// ── Generic HTTPS Proxy ───────────────────────────────────────
function proxyRequest(targetUrl, req, res, extraHeaders = {}) {
  const parsed = new URL(targetUrl);
  const STRIP = new Set(['host','origin','referer','connection','content-length','transfer-encoding']);

  const options = {
    hostname: parsed.hostname,
    port: parsed.port || 443,
    path: parsed.pathname + parsed.search,
    method: req.method,
    headers: {
      ...Object.fromEntries(
        Object.entries(req.headers).filter(([k]) => !STRIP.has(k.toLowerCase()))
      ),
      host: parsed.hostname,
      ...extraHeaders,
    },
  };

  const proxyReq = https.request(options, (proxyRes) => {
    addCORS(res);
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    addCORS(res);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Proxy Error', message: err.message }));
  });

  req.pipe(proxyReq);
}

// ── Route Configuration ──────────────────────────────────────
const PROXY_ROUTES = [
  { prefix: '/proxy/vt/',       target: (p) => `https://www.virustotal.com/api/v3${p}` },
  { prefix: '/proxy/abuseipdb/', target: (p) => `https://api.abuseipdb.com/api/v2${p}` },
  { prefix: '/proxy/shodan/',    target: (p) => `https://api.shodan.io${p}` },
  { prefix: '/proxy/otx/',       target: (p) => `https://otx.alienvault.com/api/v1${p}` },
  { prefix: '/proxy/openai/',    target: (p) => `https://api.openai.com${p}` },
  { prefix: '/proxy/claude/',    target: (p) => `https://api.anthropic.com${p}` },
];

// ── Static File Server ────────────────────────────────────────
function serveStatic(reqPath, res) {
  let filePath = path.join(STATIC, reqPath === '/' ? 'index.html' : reqPath);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  }

  if (!fs.existsSync(filePath)) {
    filePath = path.join(STATIC, 'index.html'); // SPA fallback
  }

  const ext = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    addCORS(res);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

// ── Main Server ───────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const reqPath = parsedUrl.pathname;

  if (req.method === 'OPTIONS') {
    addCORS(res);
    res.writeHead(204);
    return res.end();
  }

  // Health check
  if (reqPath === '/health') {
    addCORS(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', version: '31.1' }));
  }

  // NVD dedicated handler
  if (reqPath === '/proxy/nvd' || reqPath.startsWith('/proxy/nvd/')) {
    return handleNVDProxy(parsedUrl, req, res);
  }

  // Generic proxy routes
  for (const route of PROXY_ROUTES) {
    if (reqPath.startsWith(route.prefix)) {
      const subPath = reqPath.slice(route.prefix.length - 1);
      const target = route.target(subPath + (parsedUrl.search || ''));
      return proxyRequest(target, req, res);
    }
  }

  // Static files
  serveStatic(reqPath, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Wadjet-Eye AI Proxy Server v31.1`);
  console.log(`Listening on port ${PORT}`);
});
