/**
 * Vercel Serverless Function — AbuseIPDB API Proxy
 * Route: /proxy/abuseipdb/*
 *
 * Forwards requests to https://api.abuseipdb.com/api/v2/*
 *
 * Key resolution (in order):
 *   1. ABUSEIPDB_API_KEY — server-side environment variable (Vercel dashboard)
 *   2. X-Client-Abuse-Key — header sent by the browser from localStorage
 *
 * If neither is present → returns { status: 'missing_api_key' } (200)
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, Key, Accept, X-Client-Abuse-Key');
    res.writeHead(204); res.end(); return;
  }

  // Resolve API key: server env var takes priority, then client-provided header
  const abuseKey = process.env.ABUSEIPDB_API_KEY || req.headers['x-client-abuse-key'] || '';

  if (!abuseKey) {
    sendJSON(res, 200, {
      error:   'missing_api_key',
      status:  'missing_api_key',
      message: 'AbuseIPDB API key not configured. Add it via the API Keys button in the UI, or set ABUSEIPDB_API_KEY in Vercel environment variables.',
      data:    null,
    });
    return;
  }

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req);
  const targetUrl  = `${ABUSEIPDB_BASE}${afterProxy}`;
  console.log(`[AbuseIPDB Proxy] ${req.method} ${targetUrl}`);

  const extraHeaders = {
    'Key':    abuseKey,
    'Accept': 'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
