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

// ── NVD parameter whitelist ────────────────────────────────────────────────────
// ROOT CAUSE FIX: Any key NOT in this set is dropped before building the
// upstream NVD URL. This permanently blocks 'path', '_path', and any other
// stray params that would cause NVD API to return HTTP 404.
const NVD_ALLOWED_PARAMS = new Set([
  'pubStartDate', 'pubEndDate', 'startIndex', 'resultsPerPage',
  'cvssV3Severity', 'keywordSearch', 'cveId', 'apiKey',
]);

/**
 * nvdAutoCorrectQS — applies whitelist + auto-fixes common NVD 404 causes.
 *
 * Fixes applied:
 *   0. WHITELIST: drop any key not in NVD_ALLOWED_PARAMS (incl. 'path', '_path')
 *   1. cveId not uppercase → uppercase
 *   2. cvssV3Severity not uppercase → uppercase
 *   3. pubStartDate without pubEndDate → add pubEndDate = now
 *   4. pubEndDate without pubStartDate → add pubStartDate = 30 days ago
 *   5. Missing Z timezone on dates → append Z
 *   6. Date range > 120 days → clamp to 120 days
 */
function nvdAutoCorrectQS(rawQS) {
  const raw = new URLSearchParams(rawQS || '');

  // Fix 0: Whitelist — build a clean params object with ONLY allowed keys
  const params = new URLSearchParams();
  for (const [k, v] of raw.entries()) {
    if (!NVD_ALLOWED_PARAMS.has(k)) {
      if (k) console.warn(`[NVD Proxy] Dropped non-NVD param: "${k}" = "${v}"`);
      continue;
    }
    if (v === '' || v === null || v === undefined) continue;
    params.set(k, v);
  }

  // Fix 1: cveId uppercase
  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  // Fix 2: severity uppercase
  if (params.get('cvssV3Severity')) {
    params.set('cvssV3Severity', params.get('cvssV3Severity').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  // Fix 3: pubStartDate without pubEndDate
  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
    console.log('[NVD Auto-fix] Added missing pubEndDate:', pubEnd);
  }

  // Fix 4: pubEndDate without pubStartDate
  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    pubStart = nvdToISOZ(s.toISOString());
    params.set('pubStartDate', pubStart);
    console.log('[NVD Auto-fix] Added missing pubStartDate:', pubStart);
  }

  // Fix 5: Normalise dates to ISO-8601 UTC (Z suffix)
  ['pubStartDate', 'pubEndDate'].forEach(k => {
    const v = params.get(k);
    if (v) {
      const fixed = nvdToISOZ(v);
      if (fixed !== v) {
        params.set(k, fixed);
        console.log(`[NVD Auto-fix] Normalised ${k}: "${v}" → "${fixed}"`);
      }
    }
  });

  // Fix 6: Enforce ≤120 day range
  pubStart = params.get('pubStartDate');
  pubEnd   = params.get('pubEndDate');
  if (pubStart && pubEnd) {
    const startMs  = new Date(pubStart).getTime();
    const endMs    = new Date(pubEnd).getTime();
    const diffDays = (endMs - startMs) / 86400000;
    if (diffDays > NVD_MAX_RANGE_DAYS) {
      const clampedStart = nvdToISOZ(new Date(endMs - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
      params.set('pubStartDate', clampedStart);
      console.log(`[NVD Auto-fix] Clamped ${Math.round(diffDays)}-day range → pubStartDate=${clampedStart}`);
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
function handleNVDProxy(parsedUrl, req, res) {
  // ── Diagnostics sub-endpoint ──────────────────────────────
  if (parsedUrl.pathname === '/proxy/nvd/diagnose') {
    addCORS(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      endpoint:      NVD_BASE_URL,
      proxy_paths:   ['/proxy/nvd', '/proxy/nvd/'],
      valid_params:  ['resultsPerPage','startIndex','pubStartDate','pubEndDate','cvssV3Severity','keywordSearch','cveId'],
      date_format:   'YYYY-MM-DDThh:mm:ss.000Z (both pubStartDate AND pubEndDate required)',
      cve_format:    'CVE-YYYY-NNNNN (uppercase)',
      severity_values: ['CRITICAL','HIGH','MEDIUM','LOW'],
      rate_limit:    '5 req/30s (unauthenticated) | 50 req/30s (with apiKey)',
      example_urls:  [
        '/proxy/nvd?resultsPerPage=20',
        '/proxy/nvd?cvssV3Severity=CRITICAL&resultsPerPage=10',
        '/proxy/nvd?cveId=CVE-2024-21762',
        '/proxy/nvd?pubStartDate=2026-01-01T00:00:00.000Z&pubEndDate=2026-04-11T23:59:59.000Z&resultsPerPage=20',
      ],
    }));
    return;
  }

  // ── Build query string ────────────────────────────────────
  // Use parsedUrl.query (already parsed object from url.parse(req.url, true))
  // to get the raw params, then pass as URLSearchParams string to nvdAutoCorrectQS.
  // nvdAutoCorrectQS will apply the whitelist and drop any 'path' / '_path' keys.
  const rawQS = parsedUrl.query
    ? new URLSearchParams(parsedUrl.query).toString()
    : '';

  // MANDATORY LOG 1: show exactly what arrived (before whitelist)
  console.log(`[NVD PROXY] Incoming query  : "${rawQS || '(none)'}"`);

  const fixedQS      = nvdAutoCorrectQS(rawQS); // whitelist + date correction
  const qs           = fixedQS ? '?' + fixedQS : '';

  // MANDATORY LOG 2: show the PARAMS after whitelist + correction
  const cleanParamsObj = Object.fromEntries(new URLSearchParams(fixedQS));
  console.log(`[NVD PROXY] PARAMS (clean)  :`, JSON.stringify(cleanParamsObj));

  // MANDATORY LOG 3: show the final NVD URL
  const nvdTargetUrl = `${NVD_BASE_URL}${qs}`;
  console.log(`[NVD PROXY] FINAL URL       :`, nvdTargetUrl);

  // Safety check: 'path=' must NEVER appear in the URL sent to NVD
  if (/[?&]path=/.test(nvdTargetUrl)) {
    console.error('[NVD PROXY] ❌ CRITICAL: "path=" in final NVD URL — aborting!');
    addCORS(res);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: false, source: 'nvd',
      error: 'Internal proxy error: forbidden "path" param would cause NVD 404',
      httpStatus: 500,
    }));
    return;
  }

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
      // Inject NVD API key from env to get 50 req/30s (vs 5 req/30s unauthenticated)
      ...(process.env.NVD_API_KEY ? { 'apiKey': process.env.NVD_API_KEY } : {}),
    },
  };

  const nvdReq = https.request(nvdOptions, (nvdRes) => {
    // MANDATORY LOG 4: response status from NVD
    console.log(`[NVD PROXY] STATUS          : ${nvdRes.statusCode} for ${nvdTargetUrl}`);

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
  // SECURITY: API keys are injected from env vars server-side.
  // Client requests MUST NOT include API keys in URLs or headers —
  // the proxy strips and replaces them from process.env.
  for (const route of PROXY_ROUTES) {
    if (reqPath.startsWith(route.prefix)) {
      const subPath      = reqPath.slice(route.prefix.length - 1); // keep leading /
      let   qs           = parsedUrl.search || '';
      const extraHeaders = {};

      // Strip client-sent Shodan key from URL; inject from env
      if (route.prefix === '/proxy/shodan/') {
        const qp = new URLSearchParams(parsedUrl.query || '');
        qp.delete('key');
        const shodanKey = process.env.SHODAN_API_KEY;
        if (!shodanKey) {
          addCORS(res);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'missing_api_key', status: 'missing_api_key', message: 'SHODAN_API_KEY not configured on server' }));
          return;
        }
        qp.set('key', shodanKey);
        qs = qp.toString() ? '?' + qp.toString() : '';
      }
      // Inject VT key from env (never from client)
      if (route.prefix === '/proxy/vt/') {
        const vtKey = process.env.VT_API_KEY;
        if (!vtKey) {
          addCORS(res);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'missing_api_key', status: 'missing_api_key', message: 'VT_API_KEY not configured on server' }));
          return;
        }
        extraHeaders['x-apikey'] = vtKey;
      }
      // Inject AbuseIPDB key from env
      if (route.prefix === '/proxy/abuseipdb/') {
        const abuseKey = process.env.ABUSEIPDB_API_KEY;
        if (!abuseKey) {
          addCORS(res);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'missing_api_key', status: 'missing_api_key', message: 'ABUSEIPDB_API_KEY not configured on server' }));
          return;
        }
        extraHeaders['Key'] = abuseKey; extraHeaders['Accept'] = 'application/json';
      }
      // Inject OTX key from env (optional — public endpoint works without)
      if (route.prefix === '/proxy/otx/') {
        const otxKey = process.env.OTX_API_KEY;
        if (otxKey) extraHeaders['X-OTX-API-KEY'] = otxKey;
      }
      // Inject OpenAI key from env
      if (route.prefix === '/proxy/openai/') {
        const openaiKey = process.env.OPENAI_API_KEY;
        if (openaiKey) extraHeaders['Authorization'] = `Bearer ${openaiKey}`;
      }
      // Inject Claude key from env
      if (route.prefix === '/proxy/claude/') {
        const claudeKey = process.env.CLAUDE_API_KEY;
        if (claudeKey) { extraHeaders['x-api-key'] = claudeKey; extraHeaders['anthropic-version'] = '2023-06-01'; }
      }

      const targetUrl = route.target(subPath + qs);
      const logUrl    = targetUrl.replace(/([?&]key=)[^&\s]+/, '$1***');
      console.log(`[Proxy] ${req.method} ${reqPath} → ${logUrl}`);
      proxyRequest(targetUrl, req, res, extraHeaders);
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
  console.log(`   NVD rate limit: ${process.env.NVD_API_KEY ? '50 req/30s (authenticated)' : '5 req/30s (unauthenticated — set NVD_API_KEY for higher limits)'}`);
  console.log(`   Other proxies: /proxy/vt/ /proxy/abuseipdb/ /proxy/shodan/ /proxy/otx/ /proxy/openai/ /proxy/claude/\n`);
});
