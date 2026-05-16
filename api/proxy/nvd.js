/**
 * Vercel Serverless Function — NVD CVE API Proxy
 * Route: /proxy/nvd/*
 *
 * Security (Audit Phase 0):
 *   FIX-001: Origin-validated CORS via handlePreflight / sendJSON
 *   FIX-003: JWT verification via verifyProxyRequest
 *   FIX-004: SSRF protection — NVD_BASE is a fixed allowlisted domain
 *
 * Forwards to https://services.nvd.nist.gov/rest/json/cves/2.0
 *
 * @module api/proxy/nvd
 */
'use strict';

const https  = require('https');
const { sendJSON, nvdToISOZ, handlePreflight, resolveOrigin } = require('../_proxy-utils');
const { verifyProxyRequest } = require('../_auth-guard');

const NVD_BASE           = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_MAX_RANGE_DAYS = 120;

const NVD_ALLOWED_PARAMS = new Set([
  'pubStartDate', 'pubEndDate', 'startIndex', 'resultsPerPage',
  'cvssV3Severity', 'keywordSearch', 'cveId',
]);

function buildCleanNVDParams(reqQuery) {
  const clean  = new URLSearchParams();
  const source = reqQuery || {};

  for (const key of NVD_ALLOWED_PARAMS) {
    const val = source[key];
    if (val === undefined || val === null || val === '' || val === false) continue;
    clean.set(key, String(val));
  }

  return applyDateCorrections(clean);
}

function applyDateCorrections(params) {
  if (params.get('cveId')) params.set('cveId', params.get('cveId').toUpperCase());

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
  }

  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    params.set('pubStartDate', nvdToISOZ(s.toISOString()));
  }

  for (const key of ['pubStartDate', 'pubEndDate']) {
    const v = params.get(key);
    if (v) params.set(key, nvdToISOZ(v));
  }

  if (params.get('cvssV3Severity')) {
    params.set('cvssV3Severity', params.get('cvssV3Severity').toUpperCase());
  }

  pubStart = params.get('pubStartDate');
  pubEnd   = params.get('pubEndDate');

  if (pubStart && pubEnd) {
    const diffDays = (new Date(pubEnd).getTime() - new Date(pubStart).getTime()) / 86400000;
    if (diffDays > NVD_MAX_RANGE_DAYS) {
      params.set('pubStartDate', nvdToISOZ(new Date(new Date(pubEnd).getTime() - NVD_MAX_RANGE_DAYS * 86400000).toISOString()));
    }
  }

  return params;
}

module.exports = async function handler(req, res) {
  if (handlePreflight(req, res)) return;

  const auth = await verifyProxyRequest(req);
  if (!auth.ok) {
    if (auth.retryAfter) res.setHeader('Retry-After', String(auth.retryAfter));
    return sendJSON(req, res, auth.status || 401, { error: auth.error, code: auth.error });
  }

  const reqQuery    = req.query || {};
  const cleanParams = buildCleanNVDParams(reqQuery);
  const qStr        = cleanParams.toString();
  const targetUrl   = qStr ? `${NVD_BASE}?${qStr}` : NVD_BASE;

  console.log(`[NVD Proxy] FINAL URL → ${targetUrl} user=${auth.userId}`);

  const parsed = new URL(targetUrl);
  const headers = {
    Accept: 'application/json',
  };
  if (process.env.NVD_API_KEY) headers['apiKey'] = process.env.NVD_API_KEY;

  return new Promise((resolve) => {
    const upReq = https.request({
      hostname: parsed.hostname,
      port:     443,
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers,
      timeout:  30000,
    }, (upRes) => {
      const chunks = [];
      upRes.on('data', c => chunks.push(c));
      upRes.on('end', () => {
        const body          = Buffer.concat(chunks);
        const allowedOrigin = resolveOrigin(req);
        const corsHdrs      = allowedOrigin
          ? { 'Access-Control-Allow-Origin': allowedOrigin, 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' }
          : { 'Vary': 'Origin' };

        res.writeHead(upRes.statusCode || 200, {
          'Content-Type': 'application/json',
          ...corsHdrs,
        });
        res.end(body);
        resolve();
      });
      upRes.on('error', () => resolve());
    });

    upReq.on('error',   () => resolve());
    upReq.on('timeout', () => { upReq.destroy(); resolve(); });
    upReq.end();
  });
};
