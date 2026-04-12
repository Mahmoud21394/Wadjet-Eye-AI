/**
 * Vercel Serverless Function — Shodan API Proxy
 * Route: /proxy/shodan/*
 *
 * Forwards requests to https://api.shodan.io/*
 * API key injected server-side from SHODAN_API_KEY env var.
 * The ?key= parameter is REMOVED from client requests and replaced
 * with the server-side key — no key exposure in frontend URLs.
 *
 * Environment variables:
 *   SHODAN_API_KEY — required
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const SHODAN_BASE = 'https://api.shodan.io';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
    res.writeHead(204); res.end(); return;
  }

  const shodanKey = process.env.SHODAN_API_KEY;
  if (!shodanKey) {
    sendJSON(res, 200, {
      error:  'missing_api_key',
      status: 'missing_api_key',
      message: 'SHODAN_API_KEY environment variable is not set. Add it in Vercel Dashboard → Settings → Environment Variables.',
    });
    return;
  }

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req, '/proxy/shodan');

  // Parse existing query string and strip any client-sent key
  const [pathname, ...qsParts] = afterProxy.split('?');
  const clientQS = new URLSearchParams(qsParts.join('?') || '');
  clientQS.delete('key'); // Remove any client-sent key (SECURITY)
  clientQS.set('key', shodanKey); // Inject server-side key

  const targetUrl = `${SHODAN_BASE}${pathname}?${clientQS.toString()}`;
  console.log(`[Shodan Proxy] ${req.method} ${targetUrl.replace(shodanKey, '***')}`);

  await proxyUpstream(targetUrl, req, res, {});
};
