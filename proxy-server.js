/**
 * Wadjet-Eye AI — Local Proxy Server  v31.0
 * Serves static files + proxies NVD API, OpenAI, Claude, VT, AbuseIPDB, Shodan, OTX
 * to bypass browser CORS restrictions.
 *
 * NVD routing changes (v31):
 *   • Dedicated NVD handler matches BOTH `/proxy/nvd` (no trailing slash) AND `/proxy/nvd/...`
 *   • Forwards ALL query parameters unchanged (after auto-correction) using URLSearchParams
 *   • Debug logs: incoming query, constructed NVD URL, and response HTTP status
 *   • Dynamic error messages: `NVD HTTP <status>: <actual response>` (no hard-coded "Check date format")
 *   • Upstream 404 with empty body → safe fallback JSON (prevents UI parse crashes)
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

// ── Route table (non-NVD routes) ──────────────────────────────
// NVD has its own dedicated handler below that matches both
// `/proxy/nvd` (no trailing slash) and `/proxy/nvd/` (with slash).
const PROXY_ROUTES = [
  // VirusTotal
  { prefix: '/proxy/vt/',         target: (p) => `https://www.virustotal.com/api/v3${p}` },
  // AbuseIPDB
  { prefix: '/proxy/abuseipdb/',  target: (p) => `https://api.abuseipdb.com/api/v2${p}` },
  // Shodan
  { prefix: '/proxy/shodan/',     target: (p) => `https://api.shodan.io${p}` },
  // OTX AlienVault
  { prefix: '/proxy/otx/',        target: (p) => `https://otx.alienvault.com/api/v1${p}` },
  // OpenAI
  { prefix: '/proxy/openai/',     target: (p) => `https://api.openai.com${p}` },
  // Anthropic Claude
  { prefix: '/proxy/claude/',     target: (p) => `https://api.anthropic.com${p}` },
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
const NVD_BASE_URL       = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

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

/**
 * nvdAutoCorrectQS — auto-fixes common NVD 404 causes in a raw query string.
 * Returns a corrected URLSearchParams string.
 *
 * Fixes applied:
 *   1. cveId not uppercase → uppercase
 *   2. pubStartDate without pubEndDate → add pubEndDate = now
 *   3. pubEndDate without pubStartDate → add pubStartDate = 30 days ago
 *   4. Missing Z timezone on dates → append Z
 *   5. Date range > 120 days → clamp to 120 days
 */
function nvdAutoCorrectQS(rawQS) {
  const params = new URLSearchParams(rawQS);

  // Fix 1: cveId uppercase
  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  // Fix 2: pubStartDate without pubEndDate
  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
    console.log('[NVD Auto-fix] Added missing pubEndDate:', pubEnd);
  }

  // Fix 3: pubEndDate without pubStartDate
  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    pubStart = nvdToISOZ(s.toISOString());
    params.set('pubStartDate', pubStart);
    console.log('[NVD Auto-fix] Added missing pubStartDate:', pubStart);
  }

  // Fix 4: Normalise dates to ISO-8601 UTC (Z suffix)
  ['pubStartDate', 'pubEndDate'].forEach(k => {
    const v = params.get(k);
    if (v) {
      const fixed = nvdToISOZ(v);
      if (fixed !== v) {
        params.set(k, fixed);
        console.log(`[NVD Auto-fix] Normalised date for ${k}: "${v}" → "${fixed}"`);
      }
    }
  });

  // Fix 5: Enforce ≤120 day range
  pubStart = params.get('pubStartDate');
  pubEnd   = params.get('pubEndDate');
  if (pubStart && pubEnd) {
    const startMs  = new Date(pubStart).getTime();
    const endMs    = new Date(pubEnd).getTime();
    const diffDays = (endMs - startMs) / 86400000;
    if (diffDays > NVD_MAX_RANGE_DAYS) {
      const clampedStart = nvdToISOZ(new Date(endMs - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
      params.set('pubStartDate', clampedStart);
      console.log(`[NVD Auto-fix] Clamped ${Math.round(diffDays)} day range to ${NVD_MAX_RANGE_DAYS} days → pubStartDate=${clampedStart}`);
    }
  }

  return params.toString();
}

// ── Dedicated NVD proxy handler ───────────────────────────────
/**
 * handleNVDProxy — handles all /proxy/nvd and /proxy/nvd/* requests.
 *
 * 1. Logs the incoming query string verbatim.
 * 2. Runs nvdAutoCorrectQS() on it.
 * 3. Constructs the final NVD URL using URLSearchParams.
 * 4. Logs the final NVD URL.
 * 5. Forwards the request transparently.
 * 6. Logs the HTTP response status.
 * 7. On upstream 404 with empty body → returns safe fallback JSON.
 * 8. Dynamic error message: `NVD HTTP <status>: <actual response text>`.
 */
function handleNVD(req, res) {
  const parsed = url.parse(req.url, true);
  const qs = new URLSearchParams(parsed.query).toString();
  const target = qs ? `${NVD_BASE}?${qs}` : NVD_BASE;

  console.log('[NVD PROXY]', target);

  const u = new URL(target);

  const options = {
    hostname: u.hostname,
    path: u.pathname + u.search,
    method: 'GET',
    headers: {
      'User-Agent': 'cve-proxy'
    }
  };

  const pReq = https.request(options, pRes => {
    let chunks = [];

    pRes.on('data', d => chunks.push(d));
    pRes.on('end', () => {
      cors(res);

      // ✅ forward real NVD status & headers
      res.writeHead(pRes.statusCode, {
        'Content-Type': pRes.headers['content-type'] || 'application/json'
      });

      res.end(Buffer.concat(chunks));
    });
  });

  pReq.on('error', e => {
    cors(res);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: e.message }));
  });

  pReq.end();
}

  // ── Build query string ────────────────────────────────────
  const rawQS = parsedUrl.query
    ? new URLSearchParams(parsedUrl.query).toString()
    : '';

  // MANDATORY DEBUG LOG 1: incoming query
  console.log(`[NVD Proxy] Incoming query: "${rawQS || '(none)'}"`);

  const fixedQS      = nvdAutoCorrectQS(rawQS);
  const qs           = fixedQS ? '?' + fixedQS : '';

  // MANDATORY DEBUG LOG 2: constructed NVD URL
  const nvdTargetUrl = `${NVD_BASE_URL}${qs}`;
  console.log(`[NVD Proxy] Constructed NVD URL: ${nvdTargetUrl}`);

  // ── Forward request ───────────────────────────────────────
  const parsed2 = new URL(nvdTargetUrl);
  const STRIP   = new Set([
    'host','origin','referer','connection','transfer-encoding',
    'content-length','keep-alive','upgrade','te','trailers',
  ]);

  const nvdOptions = {
    hostname: parsed2.hostname,
    port:     443,
    path:     parsed2.pathname + parsed2.search,
    method:   'GET',
    headers:  {
      ...Object.fromEntries(
        Object.entries(req.headers).filter(([k]) => !STRIP.has(k.toLowerCase()))
      ),
      host: parsed2.hostname,
    },
  };

  const nvdReq = https.request(nvdOptions, (nvdRes) => {
    // MANDATORY DEBUG LOG 3: response status
    console.log(`[NVD Proxy] Response status: ${nvdRes.statusCode} for ${nvdTargetUrl}`);

    const chunks = [];
    nvdRes.on('data', c => chunks.push(c));
    nvdRes.on('end', () => {
      const body    = Buffer.concat(chunks);
      const bodyStr = body.toString('utf8').trim();

      // ── Upstream 404 with empty body → safe fallback (prevents UI crash) ──
      if (nvdRes.statusCode === 404 && !bodyStr) {
        console.warn(`[NVD Proxy] Upstream 404 with empty body — returning safe fallback. URL: ${nvdTargetUrl}`);
        addCORS(res);
        if (!res.headersSent) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
        }
        res.end(JSON.stringify({
          vulnerabilities: [],
          totalResults:    0,
          resultsPerPage:  0,
          startIndex:      0,
          message:         `No data or invalid query (NVD HTTP 404). URL: ${nvdTargetUrl}`,
        }));
        return;
      }

      // ── Non-2xx with content → dynamic error message (no hard-coded text) ─
      if (nvdRes.statusCode >= 400) {
        // Dynamic: "NVD HTTP <status>: <actual response>"
        const dynamicMsg = `NVD HTTP ${nvdRes.statusCode}: ${bodyStr.slice(0, 300) || 'empty response'}`;
        console.warn(`[NVD Proxy] ${dynamicMsg}`);

        // Always return parseable JSON so the frontend never crashes
        addCORS(res);
        if (!res.headersSent) {
          res.writeHead(nvdRes.statusCode, { 'Content-Type': 'application/json' });
        }
        // If upstream body is already JSON, try to pass it through; otherwise wrap it
        let outBody;
        try {
          const parsed3 = JSON.parse(bodyStr);
          // Merge error metadata into existing JSON
          outBody = JSON.stringify({ ...parsed3, _proxy_error: dynamicMsg, vulnerabilities: parsed3.vulnerabilities || [], totalResults: parsed3.totalResults || 0 });
        } catch (_) {
          outBody = JSON.stringify({ error: dynamicMsg, vulnerabilities: [], totalResults: 0 });
        }
        res.end(outBody);
        return;
      }

      // ── Success — forward transparently ──────────────────────────────────
      addCORS(res);
      if (!res.headersSent) {
        res.writeHead(nvdRes.statusCode, {
          'Content-Type':   nvdRes.headers['content-type'] || 'application/json',
          'Content-Length': body.length,
        });
      }
      res.end(body);
    });

    nvdRes.on('error', (err) => {
      console.error('[NVD Proxy] Response stream error:', err.message);
      if (!res.headersSent) {
        addCORS(res);
        res.writeHead(502, { 'Content-Type': 'application/json' });
      }
      res.end(JSON.stringify({
        error:           'NVD proxy response error',
        message:         err.message,
        vulnerabilities: [],
        totalResults:    0,
      }));
    });
  });

  nvdReq.setTimeout(30000, () => nvdReq.destroy(new Error('NVD upstream timeout after 30s')));

  nvdReq.on('error', (err) => {
    console.error('[NVD Proxy] Request error:', err.message);
    if (!res.headersSent) {
      addCORS(res);
      res.writeHead(err.message.includes('timeout') ? 504 : 502, { 'Content-Type': 'application/json' });
    }
    res.end(JSON.stringify({
      error:           'NVD proxy error',
      message:         err.message,
      vulnerabilities: [],
      totalResults:    0,
    }));
  });

  nvdReq.end();
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
      status:       'ok',
      server:       'Wadjet-Eye AI Proxy',
      timestamp:    new Date().toISOString(),
      nvd_proxy:    ['/proxy/nvd', '/proxy/nvd/'],
      nvd_endpoint: NVD_BASE_URL,
      proxies:      PROXY_ROUTES.map(r => r.prefix),
    }));
    return;
  }

  // ── NVD — dedicated handler (matches `/proxy/nvd` AND `/proxy/nvd/...`) ──
  // Must be checked BEFORE the generic PROXY_ROUTES loop.
  if (reqPath === '/proxy/nvd' || reqPath.startsWith('/proxy/nvd/')) {
    handleNVDProxy(parsedUrl, req, res);
    return;
  }

  // ── Generic proxy routes ──────────────────────────────────
  for (const route of PROXY_ROUTES) {
    if (reqPath.startsWith(route.prefix)) {
      const subPath   = reqPath.slice(route.prefix.length - 1); // keep leading /
      const qs        = parsedUrl.search || '';
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
  console.log(`\n🚀 Wadjet-Eye AI Proxy Server v31.0 running on port ${PORT}`);
  console.log(`   Static: ${STATIC}`);
  console.log(`   NVD proxy: /proxy/nvd (no slash) + /proxy/nvd/ (with slash) → ${NVD_BASE_URL}`);
  console.log(`   Other proxies: /proxy/vt/ /proxy/abuseipdb/ /proxy/shodan/ /proxy/otx/ /proxy/openai/ /proxy/claude/\n`);
});
