/**
 * Vercel Serverless Function — AbuseIPDB API Proxy
 * Route: /proxy/abuseipdb/*
 *
 * Forwards requests to https://api.abuseipdb.com/api/v2/*
 * API key injected server-side from ABUSEIPDB_API_KEY env var.
 *
 * Environment variables:
 *   ABUSEIPDB_API_KEY — required
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Key, Accept');
    res.writeHead(204); res.end(); return;
  }

  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  if (!abuseKey) {
    sendJSON(res, 200, {
      error:  'missing_api_key',
      status: 'missing_api_key',
      message: 'ABUSEIPDB_API_KEY environment variable is not set. Add it in Vercel Dashboard → Settings → Environment Variables.',
      data:   null,
    });
    return;
  }

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req, '/proxy/abuseipdb');
  const targetUrl  = `${ABUSEIPDB_BASE}${afterProxy}`;
  console.log(`[AbuseIPDB Proxy] ${req.method} ${targetUrl}`);

  const extraHeaders = {
    'Key':    abuseKey,
    'Accept': 'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
