/**
 * Vercel Serverless Function — NVD CVE API Proxy
 * Route: /proxy/nvd  (also /proxy/nvd/ via vercel.json rewrite)
 *
 * Forwards all query parameters to:
 *   https://services.nvd.nist.gov/rest/json/cves/2.0
 * after auto-correcting common issues (date format, range clamp, cveId case).
 *
 * Environment variables:
 *   NVD_API_KEY  — optional, increases rate limit from 5 to 50 req/30s
 */
'use strict';

const { sendJSON, proxyUpstream, nvdAutoCorrect, extractSubPath } = require('../_proxy-utils');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

module.exports = async function handler(req, res) {
  // Preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, apiKey, Authorization, Accept');
    res.writeHead(204); res.end(); return;
  }

  // Diagnostics sub-path
  const subPath = extractSubPath(req, '/proxy/nvd');
  if (subPath.includes('/diagnose') || subPath.includes('diagnose')) {
    sendJSON(res, 200, {
      endpoint:     NVD_BASE,
      proxy_paths:  ['/proxy/nvd', '/proxy/nvd/'],
      date_format:  'YYYY-MM-DDThh:mm:ss.000Z (both pubStartDate AND pubEndDate required)',
      cve_format:   'CVE-YYYY-NNNNN (uppercase)',
      severity_values: ['CRITICAL','HIGH','MEDIUM','LOW'],
      rate_limit:   '5 req/30s (unauthenticated) | 50 req/30s (with NVD_API_KEY env var)',
    });
    return;
  }

  // Parse incoming query string (from subPath after '?')
  const rawQS = subPath.includes('?') ? subPath.split('?').slice(1).join('?') : '';
  console.log(`[NVD Proxy] Incoming query: "${rawQS || '(none)'}"`);

  // Auto-correct parameters
  const fixedQS = nvdAutoCorrect(rawQS);
  const qs      = fixedQS ? '?' + fixedQS : '';

  const targetUrl = `${NVD_BASE}${qs}`;
  console.log(`[NVD Proxy] Constructed NVD URL: ${targetUrl}`);

  // Extra headers — NVD API key from environment (server-side only, never from client)
  const extraHeaders = {};
  const nvdKey = process.env.NVD_API_KEY;
  if (nvdKey) extraHeaders['apiKey'] = nvdKey;

  await proxyUpstream(targetUrl, req, res, extraHeaders);
  console.log(`[NVD Proxy] Response forwarded for: ${targetUrl}`);
};
