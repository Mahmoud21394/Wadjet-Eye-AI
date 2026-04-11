/**
 * Wadjet-Eye AI — Local Proxy Server
 * Serves static files + proxies NVD API, OpenAI, Claude, VT, AbuseIPDB, Shodan, OTX
 * to bypass browser CORS restrictions.
 */
'use strict';

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');

const PORT   = 3000;
const STATIC = __dirname;

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

// ── Generic HTTPS proxy ───────────────────────────────────────
function proxyRequest(targetUrl, req, res, extraHeaders = {}) {
  const parsed = new URL(targetUrl);

  // Strip headers that cause issues when proxying
  const STRIP_HEADERS = new Set([
    'host','origin','referer','connection','transfer-encoding',
    'content-length','keep-alive','upgrade','te','trailers',
  ]);

  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || 443,
    path:     parsed.pathname + parsed.search,
    method:   req.method,
    headers:  {
      ...Object.fromEntries(
        Object.entries(req.headers).filter(([k]) =>
          !STRIP_HEADERS.has(k.toLowerCase())
        )
      ),
      host: parsed.hostname,
      ...extraHeaders,
    },
  };

  const proxyReq = https.request(options, (proxyRes) => {
    addCORS(res);

    // Buffer the full response body, then forward.
    // This avoids transfer-encoding/chunked issues with piping large responses.
    const chunks = [];
    proxyRes.on('data', chunk => chunks.push(chunk));
    proxyRes.on('end', () => {
      const body = Buffer.concat(chunks);
      if (!res.headersSent) {
        res.writeHead(proxyRes.statusCode, {
          'Content-Type':   proxyRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
        });
      }
      res.end(body);
    });
    proxyRes.on('error', (err) => {
      console.error('[Proxy Response Error]', targetUrl, err.message);
      if (!res.headersSent) {
        addCORS(res);
        res.writeHead(502, { 'Content-Type': 'application/json' });
      }
      res.end(JSON.stringify({ error: 'Proxy response error', message: err.message }));
    });
  });

  // 30-second timeout for slow upstream APIs (e.g. OTX for large result sets)
  proxyReq.setTimeout(30000, () => {
    proxyReq.destroy(new Error('Upstream timeout after 30s'));
  });

  proxyReq.on('error', (err) => {
    console.error('[Proxy Error]', targetUrl, err.message);
    if (!res.headersSent) {
      addCORS(res);
      res.writeHead(err.message.includes('timeout') ? 504 : 502,
        { 'Content-Type': 'application/json' });
    }
    res.end(JSON.stringify({ error: 'Proxy error', message: err.message }));
  });

  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    req.pipe(proxyReq, { end: true });
  } else {
    proxyReq.end();
  }
}

// ── Route table ───────────────────────────────────────────────
const PROXY_ROUTES = [
  // NVD CVE API
  { prefix: '/proxy/nvd/', target: (p) => `https://services.nvd.nist.gov/rest/json/cves/2.0${p}` },
  // VirusTotal
  { prefix: '/proxy/vt/', target: (p) => `https://www.virustotal.com/api/v3${p}` },
  // AbuseIPDB
  { prefix: '/proxy/abuseipdb/', target: (p) => `https://api.abuseipdb.com/api/v2${p}` },
  // Shodan
  { prefix: '/proxy/shodan/', target: (p) => `https://api.shodan.io${p}` },
  // OTX AlienVault
  { prefix: '/proxy/otx/', target: (p) => `https://otx.alienvault.com/api/v1${p}` },
  // OpenAI
  { prefix: '/proxy/openai/', target: (p) => `https://api.openai.com${p}` },
  // Anthropic Claude
  { prefix: '/proxy/claude/', target: (p) => `https://api.anthropic.com${p}` },
];

// ── Static file server ────────────────────────────────────────
function serveStatic(reqPath, res) {
  let filePath = path.join(STATIC, reqPath === '/' ? 'index.html' : reqPath);

  // Security: prevent path traversal
  if (!filePath.startsWith(STATIC)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  // Directory → index.html
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  }

  if (!fs.existsSync(filePath)) {
    // SPA fallback — serve index.html for unknown paths
    filePath = path.join(STATIC, 'index.html');
  }

  const ext  = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    addCORS(res);
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
    });
    res.end(data);
  });
}

// ── NVD parameter auto-correction ────────────────────────────
const NVD_MAX_RANGE_DAYS = 120; // NVD rejects date ranges > 120 days with 404

/**
 * nvdToISOZ — normalises a date string to ISO-8601 with trailing Z (UTC).
 * NVD requires timezone info; missing Z causes intermittent 404 on date-range queries.
 */
function nvdToISOZ(dateStr) {
  if (!dateStr) return dateStr;
  const s = String(dateStr).trim();
  // Already has Z or offset → re-parse to canonical form
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(s)) {
    return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
  }
  if (/\.\d{3}$/.test(s)) return s + 'Z';
  if (/T\d{2}:\d{2}:\d{2}$/.test(s)) return s + '.000Z';
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + 'T00:00:00.000Z';
  return new Date(s).toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function nvdAutoCorrectQS(rawQS) {
  // Parse query params and auto-fix known NVD 404 causes:
  // 1. pubStartDate without pubEndDate → add pubEndDate = now
  // 2. cveId not uppercase → uppercase it
  // 3. Missing timezone (no Z) on dates → append Z for unambiguous UTC
  // 4. Missing .000 milliseconds on dates → add them
  // 5. Date range > 120 days → clamp to 120 days (NVD hard limit)
  const params = new URLSearchParams(rawQS);

  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
    console.log('[NVD Auto-fix] Added missing pubEndDate:', pubEnd);
  }
  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    pubStart = nvdToISOZ(s.toISOString());
    params.set('pubStartDate', pubStart);
    console.log('[NVD Auto-fix] Added missing pubStartDate:', pubStart);
  }

  // Normalise dates to ISO-8601 UTC (Z suffix)
  ['pubStartDate','pubEndDate'].forEach(k => {
    const v = params.get(k);
    if (v) {
      const fixed = nvdToISOZ(v);
      if (fixed !== v) {
        params.set(k, fixed);
        console.log(`[NVD Auto-fix] Normalised date timezone for ${k}: "${v}" → "${fixed}"`);
      }
    }
  });

  // Enforce ≤120 day range (NVD returns 404 for wider ranges)
  pubStart = params.get('pubStartDate');
  pubEnd   = params.get('pubEndDate');
  if (pubStart && pubEnd) {
    const startMs  = new Date(pubStart).getTime();
    const endMs    = new Date(pubEnd).getTime();
    const diffDays = (endMs - startMs) / 86400000;
    if (diffDays > NVD_MAX_RANGE_DAYS) {
      const clampedStart = nvdToISOZ(new Date(endMs - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
      params.set('pubStartDate', clampedStart);
      console.log(`[NVD Auto-fix] Clamped date range from ${Math.round(diffDays)} to ${NVD_MAX_RANGE_DAYS} days → pubStartDate=${clampedStart}`);
    }
  }

  return params.toString();
}

// ── Main request handler ──────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const reqPath   = parsedUrl.pathname;

  // Handle preflight
  if (req.method === 'OPTIONS') {
    addCORS(res);
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check endpoint
  if (reqPath === '/health' || reqPath === '/api/health') {
    addCORS(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      server: 'Wadjet-Eye AI Proxy',
      timestamp: new Date().toISOString(),
      proxies: PROXY_ROUTES.map(r => r.prefix),
      nvd_endpoint: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    }));
    return;
  }

  // NVD diagnostics endpoint
  if (reqPath === '/proxy/nvd/diagnose') {
    addCORS(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      endpoint: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      proxy: '/proxy/nvd/',
      valid_params: ['resultsPerPage','startIndex','pubStartDate','pubEndDate','cvssV3Severity','keywordSearch','cveId'],
      date_format: 'YYYY-MM-DDThh:mm:ss.000 (both pubStartDate AND pubEndDate required)',
      cve_format: 'CVE-YYYY-NNNNN (uppercase)',
      severity_values: ['CRITICAL','HIGH','MEDIUM','LOW'],
      rate_limit: '5 req/30s (unauthenticated) | 50 req/30s (with apiKey)',
      example_urls: [
        '/proxy/nvd/?resultsPerPage=20',
        '/proxy/nvd/?cvssV3Severity=CRITICAL&resultsPerPage=10',
        '/proxy/nvd/?cveId=CVE-2024-21762',
        '/proxy/nvd/?pubStartDate=2026-01-01T00:00:00.000&pubEndDate=2026-04-11T23:59:59.000&resultsPerPage=20',
      ],
    }));
    return;
  }

  // Check proxy routes
  for (const route of PROXY_ROUTES) {
    if (reqPath.startsWith(route.prefix)) {
      const subPath = reqPath.slice(route.prefix.length - 1); // keep leading /

      // Auto-correct NVD query parameters to prevent 404 errors
      let qs = parsedUrl.search || '';
      if (route.prefix === '/proxy/nvd/') {
        const rawQS = parsedUrl.query ? new URLSearchParams(parsedUrl.query).toString() : '';
        const fixedQS = nvdAutoCorrectQS(rawQS);
        qs = fixedQS ? '?' + fixedQS : '';
      }

      const targetUrl = route.target(subPath + qs);
      console.log(`[Proxy] ${req.method} ${reqPath}${qs} → ${targetUrl}`);
      proxyRequest(targetUrl, req, res);
      return;
    }
  }

  // Serve static files
  serveStatic(reqPath, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Wadjet-Eye AI Proxy Server running on port ${PORT}`);
  console.log(`   Static: ${STATIC}`);
  console.log(`   Proxy routes: /proxy/nvd/ /proxy/vt/ /proxy/abuseipdb/ /proxy/shodan/ /proxy/otx/ /proxy/openai/ /proxy/claude/\n`);
});
