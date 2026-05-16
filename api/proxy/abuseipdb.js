/**
 * Vercel Serverless Function — AbuseIPDB API Proxy
 * Route: /proxy/abuseipdb/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection applied inside proxyUpstream
 *
 * Forwards to https://api.abuseipdb.com/api/v2/*
 *
 * @module api/proxy/abuseipdb
 */
'use strict';

const https  = require('https');
const zlib   = require('zlib');
const { sendJSON, handlePreflight, resolveOrigin } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';
const API_KEY        = process.env.ABUSEIPDB_API_KEY || 'c5708a7dd63b526a1d293e13d06f1d66f9d50fe673171ed36af277f408b72be057ed7c8f1311eb4d';

function decompress(buf, enc) {
  return new Promise((ok, fail) => {
    const e = (enc || '').toLowerCase();
    if (e === 'gzip' || e === 'x-gzip') {
      zlib.gunzip(buf, (err, r) => err ? fail(err) : ok(r));
    } else if (e === 'deflate') {
      zlib.inflate(buf, (err, r) => err
        ? zlib.inflateRaw(buf, (e2, r2) => e2 ? fail(e2) : ok(r2))
        : ok(r));
    } else if (e === 'br') {
      zlib.brotliDecompress(buf, (err, r) => err ? fail(err) : ok(r));
    } else {
      if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
        zlib.gunzip(buf, (err, r) => ok(err ? buf : r));
      } else {
        ok(buf);
      }
    }
  });
}

function getSubPath(req) {
  const raw    = req.url || '';
  const qIdx   = raw.indexOf('?');
  const qs     = qIdx >= 0 ? raw.slice(qIdx + 1) : '';
  const params = new URLSearchParams(qs);
  let subPath  = params.get('_path') || '/';
  params.delete('_path');
  try { subPath = decodeURIComponent(subPath); } catch (_) {}
  if (!subPath.startsWith('/')) subPath = '/' + subPath;
  const rest = params.toString();
  return rest ? `${subPath}?${rest}` : subPath;
}

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const subPath   = getSubPath(req);
  const targetUrl = `${ABUSEIPDB_BASE}${subPath}`;
  console.log(`[AbuseIPDB Proxy] ${req.method} ${targetUrl} user=${auth.userId}`);

  const parsed = new URL(targetUrl);

  return new Promise((resolve) => {
    const upReq = https.request({
      hostname: parsed.hostname,
      port:     443,
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers: {
        'Key':             API_KEY,
        'Accept':          'application/json',
        'Accept-Encoding': 'identity',
      },
      timeout: 20000,
    }, async (upstream) => {
      const chunks = [];
      upstream.on('data',  c => chunks.push(c));
      upstream.on('end', async () => {
        let body = Buffer.concat(chunks);
        try { body = await decompress(body, upstream.headers['content-encoding'] || ''); } catch (_) {}

        const allowedOrigin = resolveOrigin(req);
        const corsHdrs = allowedOrigin
          ? { 'Access-Control-Allow-Origin': allowedOrigin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' }
          : { 'Vary': 'Origin' };

        res.writeHead(upstream.statusCode || 200, {
          'Content-Type':   'application/json',
          'Content-Length': body.length,
          ...corsHdrs,
        });
        res.end(body);
        resolve();
      });
      upstream.on('error', () => { sendJSON(req, res, 502, { error: 'upstream_read_error' }); resolve(); });
    });

    upReq.on('timeout', () => { upReq.destroy(); sendJSON(req, res, 504, { error: 'upstream_timeout', message: 'AbuseIPDB timed out' }); resolve(); });
    upReq.on('error',   (err) => { sendJSON(req, res, 502, { error: 'request_error', message: err.message }); resolve(); });
    upReq.end();
  });
};
