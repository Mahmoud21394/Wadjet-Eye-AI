/**
 * Vercel Serverless Function — AlienVault OTX API Proxy
 * Route: /proxy/otx/*
 *
 * Forwards requests to https://otx.alienvault.com/api/v1/*
 *
 * Key resolution (in order):
 *   1. OTX_API_KEY        — server-side environment variable (optional — public endpoints work without it)
 *   2. X-Client-OTX-Key  — header sent by the browser from localStorage
 *
 * OTX /indicators/{type}/{value}/general is a PUBLIC endpoint that works without any key.
 * Providing a key grants higher rate limits.
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const OTX_BASE = 'https://otx.alienvault.com/api/v1';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, X-OTX-API-KEY, Accept, X-Client-OTX-Key');
    res.writeHead(204); res.end(); return;
  }

  // Resolve API key: server env var OR client header — OTX is optional
  const otxKey = process.env.OTX_API_KEY || req.headers['x-client-otx-key'] || '';

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req);
  const targetUrl  = `${OTX_BASE}${afterProxy}`;
  console.log(`[OTX Proxy] ${req.method} ${targetUrl}`);

  // Include key only if available (public endpoint works without it)
  const extraHeaders = {};
  if (otxKey) extraHeaders['X-OTX-API-KEY'] = otxKey;

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
