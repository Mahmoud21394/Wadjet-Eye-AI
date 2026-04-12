/**
 * Vercel Serverless Function — Anthropic Claude API Proxy
 * Route: /proxy/claude/*
 *
 * Forwards requests to https://api.anthropic.com/*
 * API key injected server-side from CLAUDE_API_KEY env var.
 *
 * Environment variables:
 *   CLAUDE_API_KEY — required
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath } = require('../_proxy-utils');

const CLAUDE_BASE = 'https://api.anthropic.com';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key, anthropic-version, Accept');
    res.writeHead(204); res.end(); return;
  }

  const claudeKey = process.env.CLAUDE_API_KEY;
  if (!claudeKey) {
    sendJSON(res, 200, {
      error:  'missing_api_key',
      status: 'missing_api_key',
      message: 'CLAUDE_API_KEY environment variable is not set. Add it in Vercel Dashboard → Settings → Environment Variables.',
    });
    return;
  }

  // Extract sub-path (e.g. /v1/messages), handles Vercel _path param
  const afterProxy = extractSubPath(req, '/proxy/claude');
  const targetUrl  = `${CLAUDE_BASE}${afterProxy}`;
  console.log(`[Claude Proxy] ${req.method} ${targetUrl}`);

  const extraHeaders = {
    'x-api-key':          claudeKey,
    'anthropic-version':  '2023-06-01',
    'Content-Type':       'application/json',
  };

  await proxyUpstream(targetUrl, req, res, extraHeaders);
};
