/**
 * Vercel Serverless Function — URLhaus API Proxy
 * Route: /proxy/urlhaus/*
 *
 * Forwards requests to https://urlhaus-api.abuse.ch/v1/*
 * No API key required — URLhaus is a free public API.
 * This proxy exists solely to avoid browser CORS blocks.
 *
 * Root cause (BUG-5):
 *   The frontend called https://urlhaus-api.abuse.ch/v1/host/ directly
 *   from the browser. URLhaus does NOT send CORS headers, so the browser
 *   blocks the request with a CORS error / 401.
 *   Fix: route through this server-side proxy — server-to-server calls
 *   are not subject to CORS restrictions.
 *
 * URLhaus API:
 *   POST /v1/host/  — body: host=<ip_or_domain>  (form-encoded)
 *   POST /v1/url/   — body: url=<url>             (form-encoded)
 */
'use strict';

const { proxyUpstream, extractSubPath, sendJSON, readBody } = require('../_proxy-utils');

const URLHAUS_BASE = 'https://urlhaus-api.abuse.ch/v1';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
    res.writeHead(204); res.end(); return;
  }

  // Only accept POST (URLhaus v1 uses POST for all queries)
  if (req.method !== 'POST' && req.method !== 'GET') {
    sendJSON(res, 405, { error: 'Method not allowed', status: 'error' });
    return;
  }

  // Extract sub-path from Vercel rewrite (_path param)
  // e.g. /proxy/urlhaus/host/ → _path=host/ → afterProxy = /host/
  const afterProxy = extractSubPath(req);
  const targetUrl  = `${URLHAUS_BASE}${afterProxy}`;
  console.log(`[URLhaus Proxy] ${req.method} ${targetUrl}`);

  // Read the POST body (form-encoded) that the frontend sends
  let bodyBuf = null;
  if (req.method === 'POST') {
    bodyBuf = await readBody(req);
  }

  // Forward to URLhaus — preserve Content-Type from the request
  await proxyUpstream(targetUrl, req, res, {
    'Accept': 'application/json',
    'Content-Type': req.headers['content-type'] || 'application/x-www-form-urlencoded',
  }, bodyBuf);
};
