/**
 * Vercel Serverless Function — NVD CVE API Proxy  v2.0
 * Route: /proxy/nvd  (matched by vercel.json rewrite)
 *
 * ROOT CAUSE FIX (v2.0):
 *   The previous implementation used extractSubPath() which tried to reconstruct
 *   query params from req.url after stripping the route prefix.  When Vercel rewrites
 *   injected additional params (_path, path, etc.) those leaked through to NVD producing
 *   invalid URLs like "?...&path=" that NVD rejects with HTTP 404.
 *
 *   v2.0 reads query params DIRECTLY from req.query (Vercel populates this from the
 *   final merged query string) and enforces a strict whitelist of the ONLY parameters
 *   NVD API 2.0 actually accepts.  Any other key — including 'path', '_path', or any
 *   Vercel-injected metadata — is silently dropped before the upstream request is built.
 *
 * Allowed NVD params (whitelist):
 *   pubStartDate, pubEndDate, startIndex, resultsPerPage,
 *   cvssV3Severity, keywordSearch, cveId, apiKey
 *
 * Environment variables:
 *   NVD_API_KEY  — optional; raises rate limit from 5 to 50 req/30s
 */
'use strict';

const { sendJSON, proxyUpstream, nvdAutoCorrect, nvdToISOZ } = require('../_proxy-utils');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// ── Strict whitelist of NVD API 2.0 accepted parameters ───────────────────────
// ANY key not in this set is DROPPED before building the upstream URL.
// This permanently blocks 'path', '_path', and any other Vercel routing metadata.
const NVD_ALLOWED_PARAMS = new Set([
  'pubStartDate',
  'pubEndDate',
  'startIndex',
  'resultsPerPage',
  'cvssV3Severity',
  'keywordSearch',
  'cveId',
]);

// ── NVD_MAX_RANGE_DAYS ────────────────────────────────────────────────────────
const NVD_MAX_RANGE_DAYS = 120;

/**
 * buildCleanNVDParams — reads from req.query (Vercel-merged QS), applies the
 * whitelist, injects the NVD API key from env, and runs date auto-correction.
 *
 * @param {object} reqQuery   req.query from Vercel (already parsed URLSearchParams)
 * @returns {URLSearchParams} clean, NVD-safe parameters
 */
function buildCleanNVDParams(reqQuery) {
  // Step 1: Build a URLSearchParams from ONLY whitelisted keys
  const clean = new URLSearchParams();
  const source = reqQuery || {};

  for (const key of NVD_ALLOWED_PARAMS) {
    const val = source[key];
    // Skip empty/null/undefined/false — never send empty params to NVD
    if (val === undefined || val === null || val === '' || val === false) continue;
    clean.set(key, String(val));
  }

  // Step 2: Inject NVD API key from environment (NEVER from client)
  // Client-supplied apiKey is intentionally excluded from the whitelist above
  const nvdKey = process.env.NVD_API_KEY;
  if (nvdKey) {
    clean.set('apiKey', nvdKey);
  }

  // Step 3: Run date auto-correction (same logic as before)
  // Apply directly to the clean URLSearchParams
  return applyDateCorrections(clean);
}

/**
 * applyDateCorrections — normalises date params and enforces the 120-day limit.
 * Operates on a URLSearchParams object in-place and returns it.
 */
function applyDateCorrections(params) {
  // Uppercase cveId
  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  // pubStartDate without pubEndDate → add now as pubEndDate
  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
    console.log('[NVD Proxy] Auto-fix: Added missing pubEndDate →', pubEnd);
  }

  // pubEndDate without pubStartDate → add 30 days before pubEndDate
  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    pubStart = nvdToISOZ(s.toISOString());
    params.set('pubStartDate', pubStart);
    console.log('[NVD Proxy] Auto-fix: Added missing pubStartDate →', pubStart);
  }

  // Normalise dates to ISO-8601 UTC (Z suffix required by NVD)
  for (const key of ['pubStartDate', 'pubEndDate']) {
    const v = params.get(key);
    if (v) {
      const fixed = nvdToISOZ(v);
      if (fixed !== v) {
        params.set(key, fixed);
        console.log(`[NVD Proxy] Auto-fix: Normalised ${key}: "${v}" → "${fixed}"`);
      }
    }
  }

  // Uppercase severity
  if (params.get('cvssV3Severity')) {
    params.set('cvssV3Severity', params.get('cvssV3Severity').toUpperCase());
  }

  // Enforce ≤120-day date range
  pubStart = params.get('pubStartDate');
  pubEnd   = params.get('pubEndDate');
  if (pubStart && pubEnd) {
    const startMs  = new Date(pubStart).getTime();
    const endMs    = new Date(pubEnd).getTime();
    const diffDays = (endMs - startMs) / 86400000;
    if (diffDays > NVD_MAX_RANGE_DAYS) {
      const clamped = nvdToISOZ(new Date(endMs - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
      params.set('pubStartDate', clamped);
      console.log(`[NVD Proxy] Auto-fix: Clamped ${Math.round(diffDays)}-day range → pubStartDate=${clamped}`);
    }
  }

  return params;
}

module.exports = async function handler(req, res) {
  // ── Preflight ────────────────────────────────────────────────────────────────
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, apiKey, Authorization, Accept');
    res.writeHead(204);
    res.end();
    return;
  }

  // ── Diagnostics endpoint ─────────────────────────────────────────────────────
  // Matches when _path=diagnose was injected by Vercel rewrite OR req.query has it
  const reqQuery = req.query || {};
  const pathHint = reqQuery._path || '';
  if (pathHint === 'diagnose' || pathHint.includes('diagnose')) {
    sendJSON(res, 200, {
      endpoint:        NVD_BASE,
      proxy_path:      '/proxy/nvd',
      allowed_params:  [...NVD_ALLOWED_PARAMS],
      date_format:     'YYYY-MM-DDThh:mm:ss.000Z (both pubStartDate AND pubEndDate required)',
      cve_format:      'CVE-YYYY-NNNNN (uppercase)',
      severity_values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      rate_limit:      process.env.NVD_API_KEY
        ? '50 req/30s (authenticated — NVD_API_KEY set)'
        : '5 req/30s (unauthenticated — set NVD_API_KEY env var for higher limits)',
      example_urls: [
        '/proxy/nvd?resultsPerPage=20',
        '/proxy/nvd?cvssV3Severity=CRITICAL&resultsPerPage=10',
        '/proxy/nvd?cveId=CVE-2024-21762',
        '/proxy/nvd?pubStartDate=2026-01-01T00:00:00.000Z&pubEndDate=2026-04-11T23:59:59.000Z&resultsPerPage=20',
      ],
    });
    return;
  }

  // ── MANDATORY LOG 1: Show exactly what the incoming request contains ─────────
  // Log BEFORE any filtering so we can see if Vercel injected 'path', '_path', etc.
  console.log('[NVD Proxy] ── Incoming request ──────────────────────────────');
  console.log('[NVD Proxy] req.url    :', req.url);
  console.log('[NVD Proxy] req.query  :', JSON.stringify(reqQuery));

  // ── Build clean params (whitelist + date correction) ─────────────────────────
  const cleanParams = buildCleanNVDParams(reqQuery);

  // ── MANDATORY LOG 2: Show the clean params that will be forwarded ─────────────
  const cleanParamsObj = Object.fromEntries(cleanParams.entries());
  console.log('[NVD Proxy] PARAMS (clean, whitelisted):', JSON.stringify(cleanParamsObj));

  // ── Construct final NVD URL ───────────────────────────────────────────────────
  const qStr      = cleanParams.toString();
  const targetUrl = qStr ? `${NVD_BASE}?${qStr}` : NVD_BASE;

  // ── MANDATORY LOG 3: Final URL that will be sent to NVD ──────────────────────
  console.log('[NVD Proxy] FINAL URL →', targetUrl);

  // Sanity check: the word 'path' must NOT appear as a query key
  if (/[?&]path=/.test(targetUrl)) {
    console.error('[NVD Proxy] ❌ CRITICAL: "path=" detected in final URL — aborting to prevent NVD 404!');
    console.error('[NVD Proxy]    URL:', targetUrl);
    sendJSON(res, 500, {
      success:     false,
      source:      'nvd',
      error:       'Internal proxy error: forbidden "path" param would cause NVD 404',
      httpStatus:  500,
      url_attempted: targetUrl,
    });
    return;
  }

  // ── Forward to NVD ───────────────────────────────────────────────────────────
  // proxyUpstream handles buffering, CORS, 404 fallback and error wrapping.
  // We pass an empty extraHeaders because apiKey was already added to the URL params.
  try {
    await proxyUpstreamNVD(targetUrl, req, res);
    console.log('[NVD Proxy] STATUS → forwarded for:', targetUrl);
  } catch (err) {
    console.error('[NVD Proxy] Unhandled error:', err.message);
    if (!res.headersSent) {
      sendJSON(res, 502, {
        success:    false,
        source:     'nvd',
        error:      'NVD proxy internal error',
        message:    err.message,
        httpStatus: 502,
        vulnerabilities: [],
        totalResults: 0,
      });
    }
  }
};

// ── NVD-specific upstream forwarder ────────────────────────────────────────────
// Overrides _proxy-utils proxyUpstream to give NVD-specific structured error responses
// that match the shape the frontend expects (vulnerabilities[], totalResults).
const https = require('https');

async function proxyUpstreamNVD(targetUrl, req, res) {
  const parsed = new URL(targetUrl);

  const STRIP = new Set([
    'host', 'origin', 'referer', 'connection', 'transfer-encoding',
    'content-length', 'keep-alive', 'upgrade', 'te', 'trailers',
  ]);

  const fwdHeaders = {
    ...Object.fromEntries(
      Object.entries(req.headers || {}).filter(([k]) => !STRIP.has(k.toLowerCase()))
    ),
    host:   parsed.hostname,
    Accept: 'application/json',
  };

  const options = {
    hostname: parsed.hostname,
    port:     443,
    path:     parsed.pathname + parsed.search,
    method:   'GET',
    headers:  fwdHeaders,
    timeout:  30000,
  };

  const CORS = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
  };

  return new Promise((resolve) => {
    const upReq = https.request(options, (upRes) => {
      const status = upRes.statusCode || 502;
      console.log(`[NVD Proxy] STATUS → ${status} for ${targetUrl}`);

      const chunks = [];
      upRes.on('data', c => chunks.push(c));
      upRes.on('end', () => {
        const body    = Buffer.concat(chunks);
        const bodyStr = body.toString('utf8').trim();

        // ── 404 with empty body: safe fallback (prevents UI crash) ────────────
        if (status === 404 && !bodyStr) {
          console.warn('[NVD Proxy] ⚠️  Upstream 404 with empty body — returning structured fallback');
          res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({
            success:         false,
            source:          'nvd',
            error:           'Upstream NVD request failed',
            httpStatus:      404,
            vulnerabilities: [],
            totalResults:    0,
            message:         `NVD returned 404. Check date range and params. URL: ${targetUrl}`,
          }));
          return resolve();
        }

        // ── 429 rate limit ────────────────────────────────────────────────────
        if (status === 429) {
          console.warn('[NVD Proxy] ⚠️  NVD rate limit (429) — advising retry');
          res.writeHead(429, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({
            success:         false,
            source:          'nvd',
            error:           'NVD rate limit reached. Wait ~30 seconds and retry.',
            httpStatus:      429,
            vulnerabilities: [],
            totalResults:    0,
          }));
          return resolve();
        }

        // ── Other non-2xx ─────────────────────────────────────────────────────
        if (status >= 400) {
          const errMsg = `Upstream NVD request failed`;
          console.warn(`[NVD Proxy] ⚠️  HTTP ${status}: ${bodyStr.slice(0, 200)}`);
          let outBody;
          try {
            const parsed2 = JSON.parse(bodyStr);
            outBody = {
              success:         false,
              source:          'nvd',
              error:           errMsg,
              httpStatus:      status,
              vulnerabilities: parsed2.vulnerabilities || [],
              totalResults:    parsed2.totalResults    || 0,
              _upstream:       parsed2,
            };
          } catch (_) {
            outBody = {
              success:         false,
              source:          'nvd',
              error:           errMsg,
              httpStatus:      status,
              vulnerabilities: [],
              totalResults:    0,
              detail:          bodyStr.slice(0, 300),
            };
          }
          res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify(outBody));
          return resolve();
        }

        // ── Success — forward transparently ───────────────────────────────────
        if (!res.headersSent) {
          res.writeHead(status, {
            'Content-Type':   upRes.headers['content-type'] || 'application/json',
            'Content-Length': body.length,
            ...CORS,
          });
        }
        res.end(body);
        resolve();
      });

      upRes.on('error', (err) => {
        console.error('[NVD Proxy] Response stream error:', err.message);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({
            success:         false,
            source:          'nvd',
            error:           'NVD proxy response error',
            httpStatus:      502,
            message:         err.message,
            vulnerabilities: [],
            totalResults:    0,
          }));
        }
        resolve();
      });
    });

    upReq.on('timeout', () => upReq.destroy(new Error('NVD upstream timeout after 30s')));
    upReq.on('error', (err) => {
      console.error('[NVD Proxy] Request error:', err.message);
      if (!res.headersSent) {
        res.writeHead(err.message.includes('timeout') ? 504 : 502, {
          'Content-Type': 'application/json', ...CORS,
        });
        res.end(JSON.stringify({
          success:         false,
          source:          'nvd',
          error:           'NVD proxy request error',
          httpStatus:      err.message.includes('timeout') ? 504 : 502,
          message:         err.message,
          vulnerabilities: [],
          totalResults:    0,
        }));
      }
      resolve();
    });

    upReq.end();
  });
}
