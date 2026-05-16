/**
 * Vercel Serverless Function — Anthropic Claude API Proxy
 * Route: /proxy/claude/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards requests to https://api.anthropic.com/*
 * API key injected server-side from CLAUDE_API_KEY env var.
 *
 * @module api/proxy/claude
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath, handlePreflight } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const CLAUDE_BASE = 'https://api.anthropic.com';

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const claudeKey = process.env.CLAUDE_API_KEY;
  if (!claudeKey) {
    return sendJSON(req, res, 503, {
      error:   'missing_api_key',
      code:    'CLAUDE_KEY_MISSING',
      message: 'CLAUDE_API_KEY not configured. Set it in Vercel Environment Variables.',
    });
  }

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${CLAUDE_BASE}${afterProxy}`;
  console.log(`[Claude Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  await proxyUpstream(targetUrl, req, res, {
    'x-api-key':          claudeKey,
    'anthropic-version':  '2023-06-01',
    'Content-Type':       'application/json',
  });
};
