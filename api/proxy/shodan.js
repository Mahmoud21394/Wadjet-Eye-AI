/**
 * Vercel Serverless Function — Shodan InternetDB Proxy
 * Route: /proxy/shodan/*
 *
 * Uses internetdb.shodan.io (free, no API key, works from any IP).
 * api.shodan.io blocks cloud/Vercel IPs on the free plan.
 *
 * InternetDB endpoint: GET https://internetdb.shodan.io/{ip}
 * Returns: { ip, ports, cpes, hostnames, tags, vulns }
 */
'use strict';

const https = require('https');

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
};

function sendJSON(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
    ...CORS,
  });
  res.end(json);
}

function extractIP(req) {
  // Vercel rewrite: /proxy/shodan/:path* → ?_path=:path*
  // Frontend calls: /proxy/shodan/185.220.101.45
  const raw    = req.url || '';
  const qIdx   = raw.indexOf('?');
  const qs     = qIdx >= 0 ? raw.slice(qIdx + 1) : '';
  const params = new URLSearchParams(qs);
  const path   = params.get('_path') || '';

  // path might be "185.220.101.45" or "/185.220.101.45" or "shodan/host/185.220.101.45"
  // strip leading slash + any "shodan/host/" prefix
  const clean = path.replace(/^\//, '').replace(/^shodan\/host\//, '');
  // take only the IP part (before any slash or query)
  return clean.split(/[/?]/)[0] || null;
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));
    res.writeHead(204); res.end(); return;
  }

  const ip = extractIP(req);
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return sendJSON(res, 400, { error: 'invalid_ip', message: 'Valid IPv4 address required' });
  }

  const targetUrl = `https://internetdb.shodan.io/${ip}`;
  console.log(`[Shodan/InternetDB] GET ${targetUrl}`);

  return new Promise((resolve) => {
    const req2 = https.request(targetUrl, {
      method:  'GET',
      headers: { 'Accept': 'application/json', 'User-Agent': 'wadjet-eye-proxy/1.0' },
      timeout: 15000,
    }, (upstream) => {
      const chunks = [];
      upstream.on('data',  c => chunks.push(c));
      upstream.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));
        res.writeHead(upstream.statusCode || 200, {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...CORS,
        });
        res.end(body);
        resolve();
      });
      upstream.on('error', () => {
        sendJSON(res, 502, { error: 'upstream_error' });
        resolve();
      });
    });

    req2.on('timeout', () => {
      req2.destroy();
      sendJSON(res, 504, { error: 'upstream_timeout', message: 'InternetDB timed out' });
      resolve();
    });
    req2.on('error', (err) => {
      sendJSON(res, 502, { error: 'request_error', message: err.message });
      resolve();
    });
    req2.end();
  });
};
