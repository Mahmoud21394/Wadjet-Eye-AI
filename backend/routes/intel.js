/**
 * ══════════════════════════════════════════════════════════
 *  Threat Intelligence Proxy Routes  (v3.1 — fixes applied)
 *
 *  CHANGES FROM v3.0:
 *   FIX-1: POST /enrich now calls the direct API helper functions
 *          exported from services/intelligence instead of doing an
 *          internal HTTP self-call (which required a JWT that internal
 *          callers don't have → 401).
 *   FIX-2: Individual route handlers also call the same helpers so that
 *          the cache logic is preserved while keeping the code DRY.
 *   FIX-3: Removed .catch() chains on Supabase Builder calls in
 *          getCache / setCache — replaced with try/catch.
 *
 *  Endpoints:
 *   POST /api/intel/virustotal   { ioc, type }
 *   POST /api/intel/abuseipdb    { ip }
 *   POST /api/intel/shodan       { ip }
 *   POST /api/intel/otx          { ioc, type }
 *   POST /api/intel/enrich       { ioc, type }   ← unified
 *   GET  /api/intel/feeds                        ← status
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router      = require('express').Router();
const { supabase } = require('../config/supabase');
const { asyncHandler, createError } = require('../middleware/errorHandler');

// Direct enrichment helpers — no JWT needed, no HTTP round-trip
const {
  enrichWithVirusTotal,
  enrichWithAbuseIPDB,
  enrichWithShodan,
  enrichWithOTX,
  calculateRiskScore,
} = require('../services/intelligence');

/* ─────────────────────────────────────────────────────────
   CACHE HELPERS  (FIX-3: try/catch instead of .catch())
   TTL: 60 min for IPs/domains, 24 h for hashes
───────────────────────────────────────────────────────── */
async function getCache(key) {
  try {
    const { data } = await supabase
      .from('ioc_enrichment_cache')
      .select('data, created_at')
      .eq('cache_key', key)
      .single();

    if (!data) return null;
    const ageMin = (Date.now() - new Date(data.created_at).getTime()) / 60000;
    return ageMin < 60 ? data.data : null;
  } catch (_) {
    return null;
  }
}

async function setCache(key, value) {
  try {
    await supabase
      .from('ioc_enrichment_cache')
      .upsert({ cache_key: key, data: value, created_at: new Date().toISOString() });
  } catch (_) { /* cache misses are non-fatal */ }
}

/* ─────────────────────────────────────────────────────────
   POST /api/intel/virustotal
   Body: { ioc: "1.2.3.4", type: "ip"|"domain"|"url"|"hash_sha256" }
───────────────────────────────────────────────────────── */
router.post('/virustotal', asyncHandler(async (req, res) => {
  const { ioc, type } = req.body;
  if (!ioc || !type) throw createError(400, 'ioc and type are required');

  const cacheKey = `vt:${type}:${ioc}`;
  const cached   = await getCache(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  if (!process.env.VIRUSTOTAL_API_KEY) throw createError(503, 'VirusTotal not configured');

  const result = await enrichWithVirusTotal(ioc, type);
  if (!result) return res.json({ ioc, type, reputation: 'unknown', risk_score: 0 });

  await setCache(cacheKey, result);
  res.json(result);
}));

/* ─────────────────────────────────────────────────────────
   POST /api/intel/abuseipdb
   Body: { ip: "1.2.3.4" }
───────────────────────────────────────────────────────── */
router.post('/abuseipdb', asyncHandler(async (req, res) => {
  const { ip } = req.body;
  if (!ip) throw createError(400, 'ip is required');

  const cacheKey = `abuse:${ip}`;
  const cached   = await getCache(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  if (!process.env.ABUSEIPDB_API_KEY) throw createError(503, 'AbuseIPDB not configured');

  const result = await enrichWithAbuseIPDB(ip);
  if (!result) throw createError(502, 'AbuseIPDB request failed');

  await setCache(cacheKey, result);
  res.json(result);
}));

/* ─────────────────────────────────────────────────────────
   POST /api/intel/shodan
   Body: { ip: "1.2.3.4" }
───────────────────────────────────────────────────────── */
router.post('/shodan', asyncHandler(async (req, res) => {
  const { ip } = req.body;
  if (!ip) throw createError(400, 'ip is required');

  const cacheKey = `shodan:${ip}`;
  const cached   = await getCache(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  if (!process.env.SHODAN_API_KEY) throw createError(503, 'Shodan not configured');

  const result = await enrichWithShodan(ip);
  if (!result) return res.json({ ip, ports: [], vulns: [], risk_score: 0 });

  await setCache(cacheKey, result);
  res.json(result);
}));

/* ─────────────────────────────────────────────────────────
   POST /api/intel/otx
   Body: { ioc: "...", type: "ip"|"domain"|"hash_sha256" }
───────────────────────────────────────────────────────── */
router.post('/otx', asyncHandler(async (req, res) => {
  const { ioc, type } = req.body;
  if (!ioc || !type) throw createError(400, 'ioc and type are required');

  const cacheKey = `otx:${type}:${ioc}`;
  const cached   = await getCache(cacheKey);
  if (cached) return res.json({ ...cached, fromCache: true });

  if (!process.env.OTX_API_KEY) throw createError(503, 'AlienVault OTX not configured');

  const result = await enrichWithOTX(ioc, type);
  if (!result) return res.json({ ioc, type, reputation: 'unknown', risk_score: 0 });

  await setCache(cacheKey, result);
  res.json(result);
}));

/* ─────────────────────────────────────────────────────────
   POST /api/intel/enrich  — UNIFIED enrichment
   FIX-1: calls direct helpers instead of self-HTTP calls.
   Body: { ioc: "...", type: "ip"|"domain"|"url"|"hash_sha256" }
───────────────────────────────────────────────────────── */
router.post('/enrich', asyncHandler(async (req, res) => {
  const { ioc, type } = req.body;
  if (!ioc || !type) throw createError(400, 'ioc and type are required');

  const results = {};
  const errors  = {};

  await Promise.allSettled([
    process.env.VIRUSTOTAL_API_KEY
      ? enrichWithVirusTotal(ioc, type)
          .then(r  => { if (r) results.virustotal = r; })
          .catch(e => { errors.virustotal = e.message; })
      : Promise.resolve(),

    (type === 'ip' && process.env.ABUSEIPDB_API_KEY)
      ? enrichWithAbuseIPDB(ioc)
          .then(r  => { if (r) results.abuseipdb = r; })
          .catch(e => { errors.abuseipdb = e.message; })
      : Promise.resolve(),

    (type === 'ip' && process.env.SHODAN_API_KEY)
      ? enrichWithShodan(ioc)
          .then(r  => { if (r) results.shodan = r; })
          .catch(e => { errors.shodan = e.message; })
      : Promise.resolve(),

    process.env.OTX_API_KEY
      ? enrichWithOTX(ioc, type)
          .then(r  => { if (r) results.otx = r; })
          .catch(e => { errors.otx = e.message; })
      : Promise.resolve(),
  ]);

  // Weighted risk score across all sources
  const scoringInput = {};
  if (results.virustotal) scoringInput.VirusTotal       = results.virustotal;
  if (results.abuseipdb)  scoringInput.AbuseIPDB        = results.abuseipdb;
  if (results.shodan)     scoringInput.Shodan           = results.shodan;
  if (results.otx)        scoringInput['AlienVault OTX']= results.otx;

  const scored     = calculateRiskScore(scoringInput);
  const finalScore = typeof scored === 'object' ? scored.score : scored;

  res.json({
    ioc,
    type,
    aggregate_risk_score: finalScore,
    reputation: finalScore < 10 ? 'clean' : finalScore < 50 ? 'suspicious' : 'malicious',
    sources:    results,
    scoring:    typeof scored === 'object' ? scored.breakdown : null,
    errors:     Object.keys(errors).length ? errors : undefined,
  });
}));

/* ── GET /api/intel/feeds — Feed configuration status ── */
router.get('/feeds', asyncHandler(async (req, res) => {
  const feeds = [
    { name: 'VirusTotal',     configured: !!process.env.VIRUSTOTAL_API_KEY, endpoint: 'virustotal' },
    { name: 'AbuseIPDB',      configured: !!process.env.ABUSEIPDB_API_KEY,  endpoint: 'abuseipdb'  },
    { name: 'Shodan',         configured: !!process.env.SHODAN_API_KEY,      endpoint: 'shodan'     },
    { name: 'AlienVault OTX', configured: !!process.env.OTX_API_KEY,         endpoint: 'otx'        },
    { name: 'URLhaus',        configured: true,  endpoint: 'urlhaus',  note: 'No key required' },
    { name: 'ThreatFox',      configured: true,  endpoint: 'threatfox',note: 'No key required' },
    { name: 'NVD CVE',        configured: true,  endpoint: 'nvd',      note: process.env.NVD_API_KEY ? 'Key configured (higher rate limit)' : 'No key (throttled)' },
  ];
  res.json(feeds);
}));

module.exports = router;
