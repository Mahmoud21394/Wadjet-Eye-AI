/**
 * Vercel Serverless Function — URLhaus API Proxy
 * Route: /proxy/urlhaus/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards to https://urlhaus-api.abuse.ch/v1/*
 *
 * @module api/proxy/urlhaus
 */
'use strict';

const { proxyUpstream, extractSubPath, readBody, sendJSON, handlePreflight } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const URLHAUS_BASE    = 'https://urlhaus-api.abuse.ch/v1';
const URLHAUS_API_KEY = process.env.URLHAUS_API_KEY || 'a635f5b8ca93ae4863cdd7e8179f62d0edb1b6c57b3f291d';

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  if (req.method !== 'POST' && req.method !== 'GET') {
    return sendJSON(req, res, 405, { error: 'method_not_allowed' });
  }

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const afterProxy = extractSubPath(req);
  const targetUrl  = `${URLHAUS_BASE}${afterProxy}`;
  console.log(`[URLhaus Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  let bodyBuf = null;
  if (req.method === 'POST') {
    bodyBuf = await readBody(req);
  }

  await proxyUpstream(targetUrl, req, res, {
    'Accept':       'application/json',
    'Content-Type': req.headers['content-type'] || 'application/x-www-form-urlencoded',
    'Auth-Key':     URLHAUS_API_KEY,
  }, bodyBuf);
};
