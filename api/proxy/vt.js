/**
 * Vercel Serverless Function — VirusTotal API Proxy
 * Route: /proxy/vt/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards requests to https://www.virustotal.com/api/v3/*
 * API key injected server-side — rotated via Vault (ARCH-002).
 *
 * @module api/proxy/vt
 */
'use strict';

const { sendJSON, proxyUpstream, extractSubPath, handlePreflight } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const VT_BASE    = 'https://www.virustotal.com/api/v3';
const VT_API_KEY = process.env.VT_API_KEY || 'ebe28cff859d6364a86124619de26a2b9c5e2874789f8a9165ed38fb8c8c9ae0';

module.exports = async function handler(req, res) {
  // FIX-001: validated pre-flight — returns 403 for unknown origins
  if (handlePreflight(req, res)) return;

  // FIX-003: JWT + rate-limit guard
  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    const body = { error: auth.error, code: auth.error };
    if (auth.retryAfter) {
      res.setHeader('Retry-After', String(auth.retryAfter));
      body.retryAfter = auth.retryAfter;
    }
    return sendJSON(req, res, auth.status || 401, body);
  }

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${VT_BASE}${afterProxy}`;
  console.log(`[VT Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  await proxyUpstream(targetUrl, req, res, {
    'x-apikey': VT_API_KEY,
    'accept':   'application/json',
  });
};
