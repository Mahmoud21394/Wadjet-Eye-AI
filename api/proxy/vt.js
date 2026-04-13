/**
 * Vercel Serverless Function — VirusTotal API Proxy
 * Route: /proxy/vt/*
 *
 * Forwards requests to https://www.virustotal.com/api/v3/*
 *
 * Key resolution (in order):
 *   1. VT_API_KEY  — server-side environment variable (Vercel dashboard)
 *   2. X-Client-VT-Key — header sent by the browser from localStorage
 *
 * If neither is present → returns { status: 'missing_api_key' } (200)
 * so the UI can show the "Add API Key" prompt gracefully.
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const VT_BASE = 'https://www.virustotal.com/api/v3';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, x-apikey, Authorization, Accept, X-Client-VT-Key');
    res.writeHead(204); res.end(); return;
  }

  // Resolve API key: server env var takes priority, then client-provided header
  const vtKey = process.env.VT_API_KEY || req.headers['x-client-vt-key'] || '';

  if (!vtKey) {
    sendJSON(res, 200, {
      error:   'missing_api_key',
      status:  'missing_api_key',
      message: 'VirusTotal API key not configured. Add it via the API Keys button in the UI, or set VT_API_KEY in Vercel environment variables.',
      data:    null,
    });
    return;
  }

  // Extract the sub-path after /proxy/vt (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req);
  const targetUrl  = `${VT_BASE}${afterProxy}`;
  console.log(`[VT Proxy] ${req.method} ${targetUrl}`);

  // Always inject the resolved key; strip any other key headers for security
  const extraHeaders = {
    'x-apikey': vtKey,
    'accept':   'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
