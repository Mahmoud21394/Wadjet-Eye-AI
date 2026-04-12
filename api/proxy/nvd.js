'use strict';

const { sendJSON, nvdToISOZ } = require('../_proxy-utils');
const https = require('https');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const NVD_ALLOWED_PARAMS = new Set([
  'pubStartDate',
  'pubEndDate',
  'startIndex',
  'resultsPerPage',
  'cvssV3Severity',
  'keywordSearch',
  'cveId',
]);

const NVD_MAX_RANGE_DAYS = 120;

function buildCleanNVDParams(reqQuery) {
  const clean = new URLSearchParams();
  const source = reqQuery || {};

  for (const key of NVD_ALLOWED_PARAMS) {
    const val = source[key];
    if (val === undefined || val === null || val === '' || val === false) continue;
    clean.set(key, String(val));
  }

  return applyDateCorrections(clean);
}

function applyDateCorrections(params) {
  if (params.get('cveId')) {
    params.set('cveId', params.get('cveId').toUpperCase());
  }

  let pubStart = params.get('pubStartDate');
  let pubEnd   = params.get('pubEndDate');

  if (pubStart && !pubEnd) {
    pubEnd = nvdToISOZ(new Date().toISOString());
    params.set('pubEndDate', pubEnd);
  }

  if (pubEnd && !pubStart) {
    const s = new Date(pubEnd);
    s.setDate(s.getDate() - 30);
    pubStart = nvdToISOZ(s.toISOString());
    params.set('pubStartDate', pubStart);
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
    const startMs  = new Date(pubStart).getTime();
    const endMs    = new Date(pubEnd).toISOString();
    const diffDays = (new Date(pubEnd).getTime() - startMs) / 86400000;

    if (diffDays > NVD_MAX_RANGE_DAYS) {
      const clamped = nvdToISOZ(new Date(new Date(pubEnd).getTime() - NVD_MAX_RANGE_DAYS * 86400000).toISOString());
      params.set('pubStartDate', clamped);
    }
  }

  return params;
}

module.exports = async function handler(req, res) {
  const reqQuery = req.query || {};

  const cleanParams = buildCleanNVDParams(reqQuery);
  const qStr = cleanParams.toString();
  const targetUrl = qStr ? `${NVD_BASE}?${qStr}` : NVD_BASE;

  console.log('[NVD Proxy] FINAL URL →', targetUrl);

  await proxyUpstreamNVD(targetUrl, req, res);
};

async function proxyUpstreamNVD(targetUrl, req, res) {
  const parsed = new URL(targetUrl);

  const STRIP = new Set([
    'host','origin','referer','connection','transfer-encoding',
    'content-length','keep-alive','upgrade','te','trailers',
  ]);

  const headers = {
    ...Object.fromEntries(
      Object.entries(req.headers || {}).filter(([k]) => !STRIP.has(k.toLowerCase()))
    ),
    host: parsed.hostname,
    Accept: 'application/json',
  };

  // ✅ FIX: API KEY MUST BE HEADER, NOT QUERY
  if (process.env.NVD_API_KEY) {
    headers['apiKey'] = process.env.NVD_API_KEY;
  }

  const options = {
    hostname: parsed.hostname,
    port: 443,
    path: parsed.pathname + parsed.search,
    method: 'GET',
    headers,
    timeout: 30000,
  };

  return new Promise((resolve) => {
    const upReq = https.request(options, (upRes) => {
      const chunks = [];
      upRes.on('data', c => chunks.push(c));
      upRes.on('end', () => {
        const body = Buffer.concat(chunks);
        res.writeHead(upRes.statusCode || 200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        });
        res.end(body);
        resolve();
      });
    });

    upReq.on('error', () => resolve());
    upReq.end();
  });
}
