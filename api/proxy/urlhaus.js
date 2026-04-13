/**
 * Vercel Serverless Function — URLhaus API Proxy
 * Route: /proxy/urlhaus/*
 *
 * Forwards requests to https://urlhaus-api.abuse.ch/v1/*
 * No API key required — URLhaus is a free public API.
 * This proxy exists solely to avoid browser CORS blocks.
 *
 * Root cause fixed (2026-04-13 BUG-5):
 *   The frontend was calling https://urlhaus-api.abuse.ch/v1/host/ directly
 *   from the browser. The browser enforces CORS on cross-origin POST requests
 *   and URLhaus does NOT send Access-Control-Allow-Origin headers.
 *   Result: CORS block → 401 Unauthorized in the console.
 *   Fix: route through this server-side proxy so the API call is
 *   origin-to-origin (no CORS restriction applies).
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const URLHAUS_BASE = 'https://urlhaus-api.abuse.ch/v1';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
    res.writeHead(204); res.end(); return;
  }

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req, '/proxy/urlhaus');
  const targetUrl  = `${URLHAUS_BASE}${afterProxy}`;
  console.log(`[URLhaus Proxy] ${req.method} ${targetUrl}`);

  // URLhaus uses form-encoded POST bodies — forward as-is, no auth header needed
  await proxyUpstream(targetUrl, req, res, {
    Accept: 'application/json',
  });
};
