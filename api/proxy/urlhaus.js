/**
 * Vercel Serverless Function — URLhaus API Proxy
 * Route: /proxy/urlhaus/*
 *
 * Forwards requests to https://urlhaus-api.abuse.ch/v1/*
 * Requires Auth-Key header for authenticated access.
 * Proxy exists to avoid browser CORS restrictions on cross-origin POST.
 *
 * URLhaus API:
 *   POST /v1/host/  — body: host=<ip_or_domain>  (form-encoded)
 *   POST /v1/url/   — body: url=<url>             (form-encoded)
 */
'use strict';

const { proxyUpstream, extractSubPath, readBody, sendJSON } = require('../_proxy-utils');

const URLHAUS_BASE    = 'https://urlhaus-api.abuse.ch/v1';
// Hardcoded Auth-Key for URLhaus authenticated API access
const URLHAUS_API_KEY = 'a635f5b8ca93ae4863cdd7e8179f62d0edb1b6c57b3f291d';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Auth-Key');
    res.writeHead(204); res.end(); return;
  }

  if (req.method !== 'POST' && req.method !== 'GET') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  // Key resolution: env var → hardcoded fallback
  const urlhausKey = process.env.URLHAUS_API_KEY || URLHAUS_API_KEY;

  // Extract sub-path: /proxy/urlhaus/host/ → _path=host/ → afterProxy=/host/
  const afterProxy = extractSubPath(req);
  const targetUrl  = `${URLHAUS_BASE}${afterProxy}`;
  console.log(`[URLhaus Proxy] ${req.method} ${targetUrl}`);

  // Read POST body before forwarding (form-encoded by the frontend)
  let bodyBuf = null;
  if (req.method === 'POST') {
    bodyBuf = await readBody(req);
  }

  await proxyUpstream(targetUrl, req, res, {
    'Accept':       'application/json',
    'Content-Type': req.headers['content-type'] || 'application/x-www-form-urlencoded',
    'Auth-Key':     urlhausKey,
  }, bodyBuf);
};
