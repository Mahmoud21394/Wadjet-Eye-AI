/**
 * Vercel Serverless Function — Shodan API Proxy
 * Route: /proxy/shodan/*
 *
 * Forwards requests to https://api.shodan.io/*
 * API key is hardcoded — no env var or user input needed.
 */
'use strict';

const { proxyUpstream, extractSubPath } = require('../_proxy-utils');

const SHODAN_BASE = 'https://api.shodan.io';
// Hardcoded API key — always available
const SHODAN_API_KEY = '0sDDXz5M0275ddF1nQwH0zlGyVdfB380';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      'Content-Type, Accept, X-Client-Shodan-Key');
    res.writeHead(204); res.end(); return;
  }

  // Key resolution: env var → hardcoded fallback
  const shodanKey = process.env.SHODAN_API_KEY || SHODAN_API_KEY;

  const afterProxy = extractSubPath(req);

  // Strip any client-sent key param; inject resolved key
  const [pathname, ...qsParts] = afterProxy.split('?');
  const clientQS = new URLSearchParams(qsParts.join('?') || '');
  clientQS.delete('key');
  clientQS.set('key', shodanKey);

  const targetUrl = `${SHODAN_BASE}${pathname}?${clientQS.toString()}`;
  console.log(`[Shodan Proxy] ${req.method} ${targetUrl.replace(shodanKey, '***')}`);

  await proxyUpstream(targetUrl, req, res, {});
};
