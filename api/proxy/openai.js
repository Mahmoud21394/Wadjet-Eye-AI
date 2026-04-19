/**
 * Vercel Serverless Function — OpenAI API Proxy
 * Route: /proxy/openai/*
 *
 * Forwards requests to https://api.openai.com/*
 * API key injected server-side from OPENAI_API_KEY env var.
 *
 * Environment variables:
 *   OPENAI_API_KEY — required
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const OPENAI_BASE = 'https://api.openai.com';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
    res.writeHead(204); res.end(); return;
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (!openaiKey) {
    sendJSON(res, 200, {
      error:  'missing_api_key',
      status: 'missing_api_key',
      message: 'OPENAI_API_KEY environment variable is not set. Add it in Vercel Dashboard → Settings → Environment Variables.',
    });
    return;
  }

  // Extract sub-path (e.g. /v1/chat/completions), handles Vercel _path param
  const afterProxy = extractSubPath(req, '/proxy/openai');
  const targetUrl  = `${OPENAI_BASE}${afterProxy}`;
  console.log(`[OpenAI Proxy] ${req.method} ${targetUrl}`);

  const extraHeaders = {
    'Authorization': `Bearer ${openaiKey}`,
    'Content-Type':  'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
