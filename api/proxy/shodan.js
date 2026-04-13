/**
 * Vercel Serverless Function — Shodan API Proxy
 * Route: /proxy/shodan/*
 *
 * Forwards requests to https://api.shodan.io/*
 *
 * Key resolution (in order):
 *   1. SHODAN_API_KEY      — server-side environment variable (Vercel dashboard)
 *   2. X-Client-Shodan-Key — header sent by the browser from localStorage
 *
 * The ?key= parameter is REMOVED from client requests and replaced
 * with the resolved key — no key exposure in frontend URLs.
 *
 * If neither is present → returns { status: 'missing_api_key' } (200)
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const SHODAN_BASE = 'https://api.shodan.io';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, Accept, X-Client-Shodan-Key');
    res.writeHead(204); res.end(); return;
  }

  // Resolve API key: server env var takes priority, then client-provided header
  const shodanKey = process.env.SHODAN_API_KEY || req.headers['x-client-shodan-key'] || '';

  if (!shodanKey) {
    sendJSON(res, 200, {
      error:   'missing_api_key',
      status:  'missing_api_key',
      message: 'Shodan API key not configured. Add it via the API Keys button in the UI, or set SHODAN_API_KEY in Vercel environment variables.',
    });
    return;
  }

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req);

  // Parse existing query string and strip any client-sent key
  const [pathname, ...qsParts] = afterProxy.split('?');
  const clientQS = new URLSearchParams(qsParts.join('?') || '');
  clientQS.delete('key'); // Remove any client-sent key (SECURITY)
  clientQS.set('key', shodanKey); // Inject resolved key

  const targetUrl = `${SHODAN_BASE}${pathname}?${clientQS.toString()}`;
  console.log(`[Shodan Proxy] ${req.method} ${targetUrl.replace(shodanKey, '***')}`);

  await proxyUpstream(targetUrl, req, res, {});
};
