/**
 * Vercel Serverless Function — AlienVault OTX API Proxy
 * Route: /proxy/otx/*
 *
 * Forwards requests to https://otx.alienvault.com/api/v1/*
 * OTX public endpoint works without a key; key grants higher rate limits.
 * API key is hardcoded — no env var or user input needed.
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const OTX_BASE = 'https://otx.alienvault.com/api/v1';
// Hardcoded API key — always available (optional but improves rate limits)
const OTX_API_KEY = 'a635f5b8ca93ae4863cdd7e8179f62d0edb1b6c57b3f291d';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, X-OTX-API-KEY, Accept, X-Client-OTX-Key');
    res.writeHead(204); res.end(); return;
  }

  // Key resolution: env var → hardcoded fallback
  const otxKey = process.env.OTX_API_KEY || OTX_API_KEY;

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${OTX_BASE}${afterProxy}`;
  console.log(`[OTX Proxy] ${req.method} ${targetUrl}`);

  await proxyUpstream(targetUrl, req, res, {
    'X-OTX-API-KEY': otxKey,
  });
};
