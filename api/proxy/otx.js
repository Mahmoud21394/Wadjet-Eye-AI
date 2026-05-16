/**
 * Vercel Serverless Function — AlienVault OTX API Proxy
 * Route: /proxy/otx/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards requests to https://otx.alienvault.com/api/v1/*
 *
 * @module api/proxy/otx
 */
'use strict';

const { proxyUpstream, extractSubPath, handlePreflight, sendJSON } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const OTX_BASE    = 'https://otx.alienvault.com/api/v1';
const OTX_API_KEY = process.env.OTX_API_KEY || 'a635f5b8ca93ae4863cdd7e8179f62d0edb1b6c57b3f291d';

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${OTX_BASE}${afterProxy}`;
  console.log(`[OTX Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  await proxyUpstream(targetUrl, req, res, {
    'X-OTX-API-KEY': OTX_API_KEY,
  });
};
