/**
 * Vercel Serverless Function — Shodan InternetDB Proxy
 * Route: /proxy/shodan/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection — IP validated against private ranges
 *            before proxying (extra check on top of proxyUpstream guard)
 *
 * Uses internetdb.shodan.io (free, no API key).
 *
 * @module api/proxy/shodan
 */
'use strict';

const https = require('https');
const { sendJSON, handlePreflight, resolveOrigin, isPrivateIPv4 } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

function extractIP(req) {
  const raw    = req.url || '';
  const qIdx   = raw.indexOf('?');
  const qs     = qIdx >= 0 ? raw.slice(qIdx + 1) : '';
  const params = new URLSearchParams(qs);
  const path   = params.get('_path') || '';
  const clean  = path.replace(/^\//, '').replace(/^shodan\/host\//, '');
  return clean.split(/[/?]/)[0] || null;
}

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const ip = extractIP(req);
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return sendJSON(req, res, 400, { error: 'invalid_ip', message: 'Valid IPv4 address required' });
  }

  // FIX-004: Extra SSRF guard — block private IPs before making request
  if (isPrivateIPv4(ip)) {
    console.warn(`[Shodan Proxy] SSRF attempt blocked — private IP: ${ip} user=${auth.userId}`);
    return sendJSON(req, res, 400, { error: 'invalid_ip', message: 'Private IP addresses not permitted' });
  }

  const targetUrl = `https://internetdb.shodan.io/${ip}`;
  console.log(`[Shodan/InternetDB] GET ${targetUrl} user=${auth.userId}`);

  return new Promise((resolve) => {
    const req2 = https.request(targetUrl, {
      method:  'GET',
      headers: { 'Accept': 'application/json', 'User-Agent': 'wadjet-eye-proxy/2.0' },
      timeout: 15000,
    }, (upstream) => {
      const chunks = [];
      upstream.on('data',  c => chunks.push(c));
      upstream.on('end', () => {
        const body        = Buffer.concat(chunks).toString();
        const allowedOrigin = resolveOrigin(req);
        const corsHdrs    = allowedOrigin
          ? { 'Access-Control-Allow-Origin': allowedOrigin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' }
          : { 'Vary': 'Origin' };

        res.writeHead(upstream.statusCode || 200, {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...corsHdrs,
        });
        res.end(body);
        resolve();
      });
      upstream.on('error', () => { sendJSON(req, res, 502, { error: 'upstream_error' }); resolve(); });
    });

    req2.on('timeout', () => { req2.destroy(); sendJSON(req, res, 504, { error: 'upstream_timeout', message: 'InternetDB timed out' }); resolve(); });
    req2.on('error',   (err) => { sendJSON(req, res, 502, { error: 'request_error', message: err.message }); resolve(); });
    req2.end();
  });
};
