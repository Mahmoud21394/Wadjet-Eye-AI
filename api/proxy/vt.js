/**
 * Vercel Serverless Function — VirusTotal API Proxy
 * Route: /proxy/vt/*
 *
 * Forwards requests to https://www.virustotal.com/api/v3/*
 * API key injected server-side from VT_API_KEY env var.
 * Client MUST NOT send keys — they are ignored and replaced.
 *
 * Environment variables:
 *   VT_API_KEY — required for all VirusTotal endpoints
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const VT_BASE = 'https://www.virustotal.com/api/v3';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-apikey, Authorization, Accept');
    res.writeHead(204); res.end(); return;
  }

  const vtKey = process.env.VT_API_KEY;
  if (!vtKey) {
    sendJSON(res, 200, {
      error:  'missing_api_key',
      status: 'missing_api_key',
      message: 'VT_API_KEY environment variable is not set on the server. Add it in Vercel Dashboard → Settings → Environment Variables.',
      data:   null,
    });
    return;
  }

  // Extract the sub-path after /proxy/vt (handles Vercel rewrite with _path param)
  const afterProxy = extractSubPath(req, '/proxy/vt');
  const targetUrl = `${VT_BASE}${afterProxy}`;
  console.log(`[VT Proxy] ${req.method} ${targetUrl}`);

  // Always inject the server-side key; strip any client-sent key header
  const extraHeaders = {
    'x-apikey':      vtKey,
    'accept':        'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
