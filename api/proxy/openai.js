/**
 * Vercel Serverless Function — OpenAI API Proxy
 * Route: /proxy/openai/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards requests to https://api.openai.com/*
 * API key injected server-side from OPENAI_API_KEY env var.
 *
 * @module api/proxy/openai
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath, handlePreflight } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const OPENAI_BASE = 'https://api.openai.com';

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (!openaiKey) {
    return sendJSON(req, res, 503, {
      error:   'missing_api_key',
      code:    'OPENAI_KEY_MISSING',
      message: 'OPENAI_API_KEY not configured. Set it in Vercel Environment Variables.',
    });
  }

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${OPENAI_BASE}${afterProxy}`;
  console.log(`[OpenAI Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  await proxyUpstream(targetUrl, req, res, {
    'Authorization': `Bearer ${openaiKey}`,
    'Content-Type':  'application/json',
  });
};
