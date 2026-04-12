/**
 * Vercel Serverless Function — AlienVault OTX API Proxy
 * Route: /proxy/otx/*
 *
 * Forwards requests to https://otx.alienvault.com/api/v1/*
 * OTX /indicators/{type}/{value}/general is a PUBLIC endpoint.
 * API key from OTX_API_KEY env var is sent if available (higher rate limits).
 *
 * Environment variables:
 *   OTX_API_KEY — optional (grants higher rate limits)
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const OTX_BASE = 'https://otx.alienvault.com/api/v1';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-OTX-API-KEY, Accept');
    res.writeHead(204); res.end(); return;
  }

  const otxKey = process.env.OTX_API_KEY; // Optional

  // Extract sub-path (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req, '/proxy/otx');
  const targetUrl = `${OTX_BASE}${afterProxy}`;
  console.log(`[OTX Proxy] ${req.method} ${targetUrl}`);

  // Include key only if available (public endpoint works without it)
  const extraHeaders = {};
  if (otxKey) extraHeaders['X-OTX-API-KEY'] = otxKey;

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
