/**
 * Vercel Serverless Function — VirusTotal API Proxy
 * Route: /proxy/vt/*
 *
 * Forwards requests to https://www.virustotal.com/api/v3/*
 * API key is hardcoded — no env var or user input needed.
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const VT_BASE   = 'https://www.virustotal.com/api/v3';
// Hardcoded API key — always available regardless of env vars
const VT_API_KEY = 'ebe28cff859d6364a86124619de26a2b9c5e2874789f8a9165ed38fb8c8c9ae0';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, x-apikey, Authorization, Accept, X-Client-VT-Key');
    res.writeHead(204); res.end(); return;
  }

  // Key resolution: env var (Vercel dashboard) → hardcoded fallback
  const vtKey = process.env.VT_API_KEY || VT_API_KEY;

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${VT_BASE}${afterProxy}`;
  console.log(`[VT Proxy] ${req.method} ${targetUrl}`);

  await proxyUpstream(targetUrl, req, res, {
    'x-apikey': vtKey,
    'accept':   'application/json',
  });
};
