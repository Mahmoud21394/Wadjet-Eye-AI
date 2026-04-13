/**
 * Vercel Serverless Function — AbuseIPDB API Proxy
 * Route: /proxy/abuseipdb/*
 *
 * Forwards requests to https://api.abuseipdb.com/api/v2/*
 * API key is hardcoded — no env var or user input needed.
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';
// Hardcoded API key — always available
const ABUSEIPDB_API_KEY = 'c5708a7dd63b526a1d293e13d06f1d66f9d50fe673171ed36af277f408b72be057ed7c8f1311eb4d';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, Key, Accept, X-Client-Abuse-Key');
    res.writeHead(204); res.end(); return;
  }

  // Key resolution: env var → hardcoded fallback
  const abuseKey = process.env.ABUSEIPDB_API_KEY || ABUSEIPDB_API_KEY;

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${ABUSEIPDB_BASE}${afterProxy}`;
  console.log(`[AbuseIPDB Proxy] ${req.method} ${targetUrl}`);

  await proxyUpstream(targetUrl, req, res, {
    'Key':    abuseKey,
    'Accept': 'application/json',
  });
};
