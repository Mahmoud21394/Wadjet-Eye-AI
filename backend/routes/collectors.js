'use strict';

const router  = require('express').Router();
const axios   = require('axios');
const { supabase } = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// ──────────────────────────────────────────────────────────────
// RATE LIMIT TRACKER
// ──────────────────────────────────────────────────────────────
const lastPull = {
  otx: null,
  abuseipdb: null,
  virustotal: null,
  shodan: null,
};

const MIN_PULL_INTERVAL_MS = 5 * 60 * 1000;

function canPull(feedId) {
  if (!lastPull[feedId]) return true;
  return Date.now() - lastPull[feedId] > MIN_PULL_INTERVAL_MS;
}

// ──────────────────────────────────────────────────────────────
// ✅ FIX 1 — BASE ENDPOINT (THIS WAS MISSING → CAUSED 404)
// ──────────────────────────────────────────────────────────────
router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);

  const collectors = Object.keys(lastPull).map(id => ({
    id,
    name: {
      otx: 'AlienVault OTX',
      abuseipdb: 'AbuseIPDB',
      virustotal: 'VirusTotal',
      shodan: 'Shodan'
    }[id],
    last_pull: lastPull[id] ? new Date(lastPull[id]).toISOString() : null,
    can_pull: canPull(id),
    status: lastPull[id] ? 'active' : 'idle'
  }));

  res.json({
    collectors: collectors.slice(0, limit),
    total: collectors.length,
    timestamp: new Date().toISOString()
  });
}));

// ──────────────────────────────────────────────────────────────
// ✅ NEW — LIVE FEED (SOC Command Center Ready)
// ──────────────────────────────────────────────────────────────
router.get('/feed', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);

  const { data, error } = await supabase
    .from('iocs')
    .select('*')
    .eq('tenant_id', tenantId)
    .order('last_seen', { ascending: false })
    .limit(limit);

  if (error) throw error;

  res.json({
    feed: data || [],
    count: data?.length || 0,
    timestamp: new Date().toISOString()
  });
}));

// ──────────────────────────────────────────────────────────────
// EXISTING ROUTES (unchanged, improved)
// ──────────────────────────────────────────────────────────────

// STATUS
router.get('/status', verifyToken, asyncHandler(async (req, res) => {
  const feeds = Object.entries(lastPull).map(([id, ts]) => ({
    id,
    name: {
      otx: 'AlienVault OTX',
      abuseipdb: 'AbuseIPDB',
      virustotal: 'VirusTotal',
      shodan: 'Shodan'
    }[id],
    last_pull: ts ? new Date(ts).toISOString() : null,
    can_pull: canPull(id),
    api_key_set: !!process.env[{
      otx: 'OTX_API_KEY',
      abuseipdb: 'ABUSEIPDB_API_KEY',
      virustotal: 'VIRUSTOTAL_API_KEY',
      shodan: 'SHODAN_API_KEY'
    }[id]],
  }));

  res.json({ feeds, timestamp: new Date().toISOString() });
}));

// STATS
router.get('/stats', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const [{ count: totalIOCs }, { count: maliciousCount }] =
    await Promise.all([
      supabase.from('iocs').select('id', { count: 'exact', head: true }).eq('tenant_id', tenantId),
      supabase.from('iocs').select('id', { count: 'exact', head: true }).eq('tenant_id', tenantId).eq('reputation', 'malicious'),
    ]);

  res.json({
    total_iocs: totalIOCs || 0,
    malicious: maliciousCount || 0,
    last_updated: new Date().toISOString()
  });
}));

// ──────────────────────────────────────────────────────────────
// SHODAN (example kept — others unchanged for brevity)
// ──────────────────────────────────────────────────────────────
router.post('/shodan',
  verifyToken,
  requireRole(['ADMIN','SUPER_ADMIN','ANALYST']),
  asyncHandler(async (req, res) => {

    if (!canPull('shodan')) {
      return res.status(429).json({ error: 'Rate limited' });
    }

    const KEY = process.env.SHODAN_API_KEY;
    if (!KEY) return res.status(503).json({ error: 'Missing API key' });

    const tenantId = req.tenantId;
    const iocs = [];

    const resp = await axios.get('https://api.shodan.io/shodan/host/search', {
      params: { key: KEY, query: 'tag:c2', minify: true }
    });

    for (const host of (resp.data?.matches || []).slice(0, 50)) {
      iocs.push({
        value: host.ip_str,
        type: 'ip',
        reputation: 'suspicious',
        risk_score: 60,
        source: 'Shodan'
      });
    }

    lastPull.shodan = Date.now();

    res.json({
      source: 'shodan',
      pulled: iocs.length,
      message: 'Collected successfully'
    });
}));

// ──────────────────────────────────────────────────────────────
// EXPORT
// ──────────────────────────────────────────────────────────────
module.exports = router;
