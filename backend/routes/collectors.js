/**
 * ══════════════════════════════════════════════════════════
 *  ThreatPilot AI — Live Threat Feed Collectors
 *  Route: /api/collectors/*
 *
 *  Pulls real IOC data from:
 *    POST /api/collectors/otx       — AlienVault OTX pulses
 *    POST /api/collectors/abuseipdb — AbuseIPDB blacklist
 *    POST /api/collectors/virustotal— VirusTotal live feed
 *    POST /api/collectors/shodan    — Shodan exposed hosts
 *    GET  /api/collectors/status    — Feed status + last pull times
 *    GET  /api/collectors/stats     — Aggregated IOC stats
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router  = require('express').Router();
const axios   = require('axios');
const { supabase } = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// ── Rate-limit tracker ──────────────────────────────────────────
const lastPull = {
  otx:        null,
  abuseipdb:  null,
  virustotal: null,
  shodan:     null,
};
const MIN_PULL_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes between pulls

function canPull(feedId) {
  if (!lastPull[feedId]) return true;
  return Date.now() - lastPull[feedId] > MIN_PULL_INTERVAL_MS;
}

// ── Upsert IOCs into database ───────────────────────────────────
async function upsertIOCs(tenantId, iocs) {
  if (!iocs || iocs.length === 0) return 0;

  // Filter valid types
  const validTypes = ['ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','filename','cve'];
  const filtered = iocs
    .filter(ioc => ioc.value && ioc.type && validTypes.includes(ioc.type))
    .map(ioc => ({
      tenant_id:   tenantId,
      value:       String(ioc.value).trim().toLowerCase(),
      type:        ioc.type,
      reputation:  ioc.reputation  || 'unknown',
      risk_score:  Math.min(100, Math.max(0, Number(ioc.risk_score) || 0)),
      source:      ioc.source      || 'collector',
      country:     ioc.country     || null,
      asn:         ioc.asn         || null,
      threat_actor:ioc.threat_actor|| null,
      tags:        ioc.tags        || [],
      notes:       ioc.notes       || null,
      status:      'active',
      last_seen:   new Date().toISOString(),
      enrichment_data: ioc.enrichment_data || {},
    }));

  if (filtered.length === 0) return 0;

  // Batch upsert in chunks of 100
  let imported = 0;
  const CHUNK = 100;
  for (let i = 0; i < filtered.length; i += CHUNK) {
    const chunk = filtered.slice(i, i + CHUNK);
    const { error, data } = await supabase
      .from('iocs')
      .upsert(chunk, {
        onConflict: 'tenant_id,value',
        ignoreDuplicates: false,  // update last_seen on duplicates
      })
      .select('id');

    if (error) {
      console.error('[Collectors] upsert error:', error.message);
    } else {
      imported += data?.length || chunk.length;
    }
  }

  // Also insert into threat_feeds table for audit trail
  const feedRows = filtered.slice(0, 50).map(ioc => ({
    tenant_id:   tenantId,
    feed_name:   ioc.source,
    feed_type:   ioc.source?.toLowerCase() || 'manual',
    ioc_value:   ioc.value,
    ioc_type:    ioc.type,
    risk_score:  ioc.risk_score,
    reputation:  ioc.reputation,
    raw_data:    ioc.enrichment_data,
    processed:   true,
  }));
  try { await supabase.from('threat_feeds').insert(feedRows); } catch (_) { /* non-fatal */ }

  return imported;
}

// ── GET /api/collectors  — root listing (aliases /status) ────────
// Fixes 404 when frontend calls GET /api/collectors without a sub-path.
// Returns same shape as /status plus a `collectors` array for compatibility.
router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const feeds = Object.entries(lastPull).map(([id, ts]) => ({
    id,
    name:      { otx:'AlienVault OTX', abuseipdb:'AbuseIPDB', virustotal:'VirusTotal', shodan:'Shodan' }[id],
    last_pull: ts ? new Date(ts).toISOString() : null,
    can_pull:  canPull(id),
    api_key_set: !!process.env[{
      otx:'OTX_API_KEY', abuseipdb:'ABUSEIPDB_API_KEY',
      virustotal:'VIRUSTOTAL_API_KEY', shodan:'SHODAN_API_KEY'
    }[id]],
    status: ts ? 'active' : 'idle',
  }));
  console.log(`[COLLECTORS] GET / — listing ${feeds.length} collectors`);
  res.json({
    collectors: feeds,  // frontend expects `collectors` array
    feeds,              // alias for compatibility
    count:     feeds.length,
    timestamp: new Date().toISOString(),
  });
}));

// ── GET /api/collectors/status ──────────────────────────────────
router.get('/status', verifyToken, asyncHandler(async (req, res) => {
  const feeds = Object.entries(lastPull).map(([id, ts]) => ({
    id,
    name:      { otx:'AlienVault OTX', abuseipdb:'AbuseIPDB', virustotal:'VirusTotal', shodan:'Shodan' }[id],
    last_pull: ts ? new Date(ts).toISOString() : null,
    can_pull:  canPull(id),
    api_key_set: !!process.env[{
      otx:'OTX_API_KEY', abuseipdb:'ABUSEIPDB_API_KEY',
      virustotal:'VIRUSTOTAL_API_KEY', shodan:'SHODAN_API_KEY'
    }[id]],
  }));
  res.json({ feeds, timestamp: new Date().toISOString() });
}));

// ── GET /api/collectors/stats ───────────────────────────────────
router.get('/stats', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const [{ count: totalIOCs }, { count: maliciousCount }, { data: recentFeeds }] =
    await Promise.all([
      supabase.from('iocs').select('id', { count: 'exact', head: true }).eq('tenant_id', tenantId),
      supabase.from('iocs').select('id', { count: 'exact', head: true }).eq('tenant_id', tenantId).eq('reputation', 'malicious'),
      supabase.from('threat_feeds').select('feed_type, created_at').eq('tenant_id', tenantId)
        .order('created_at', { ascending: false }).limit(100),
    ]);

  const feedStats = {};
  (recentFeeds || []).forEach(f => {
    feedStats[f.feed_type] = (feedStats[f.feed_type] || 0) + 1;
  });

  res.json({
    total_iocs:    totalIOCs || 0,
    malicious:     maliciousCount || 0,
    by_feed:       feedStats,
    last_updated:  new Date().toISOString(),
  });
}));

// ── POST /api/collectors/otx — AlienVault OTX ──────────────────
router.post('/otx', verifyToken, requireRole(['ADMIN','SUPER_ADMIN','ANALYST']),
asyncHandler(async (req, res) => {
  if (!canPull('otx')) {
    const wait = Math.ceil((MIN_PULL_INTERVAL_MS - (Date.now() - lastPull.otx)) / 60000);
    return res.status(429).json({ error: `Rate limited. Try again in ${wait} minutes.` });
  }

  const OTX_KEY = process.env.OTX_API_KEY;
  if (!OTX_KEY) return res.status(503).json({ error: 'OTX_API_KEY not configured' });

  const tenantId = req.tenantId;
  const iocs = [];

  try {
    // Pull recent malicious IPs from OTX subscribed pulses
    const [ipsResp, domainsResp] = await Promise.all([
      axios.get('https://otx.alienvault.com/api/v1/indicators/export', {
        params: { type: 'IPv4', modified_since: new Date(Date.now() - 24*3600*1000).toISOString() },
        headers: { 'X-OTX-API-KEY': OTX_KEY },
        timeout: 15000,
      }).catch(() => null),
      axios.get('https://otx.alienvault.com/api/v1/indicators/export', {
        params: { type: 'domain', modified_since: new Date(Date.now() - 24*3600*1000).toISOString() },
        headers: { 'X-OTX-API-KEY': OTX_KEY },
        timeout: 15000,
      }).catch(() => null),
    ]);

    // Parse IP indicators
    if (ipsResp?.data?.results) {
      for (const ind of ipsResp.data.results.slice(0, 200)) {
        if (ind.indicator && ind.type === 'IPv4') {
          iocs.push({
            value:       ind.indicator,
            type:        'ip',
            reputation:  ind.pulse_info?.count > 2 ? 'malicious' : 'suspicious',
            risk_score:  Math.min(100, (ind.pulse_info?.count || 1) * 15),
            source:      'AlienVault OTX',
            tags:        ind.pulse_info?.pulses?.slice(0,3).map(p => p.name) || ['OTX'],
            notes:       `OTX pulse count: ${ind.pulse_info?.count || 0}`,
            enrichment_data: { otx_pulse_count: ind.pulse_info?.count, references: ind.pulse_info?.references },
          });
        }
      }
    }

    // Parse domain indicators
    if (domainsResp?.data?.results) {
      for (const ind of domainsResp.data.results.slice(0, 100)) {
        if (ind.indicator) {
          iocs.push({
            value:       ind.indicator.toLowerCase(),
            type:        'domain',
            reputation:  'malicious',
            risk_score:  Math.min(100, (ind.pulse_info?.count || 1) * 20),
            source:      'AlienVault OTX',
            tags:        ['OTX', 'Malicious Domain'],
            enrichment_data: { otx_pulse_count: ind.pulse_info?.count },
          });
        }
      }
    }

    // Fallback: if export API fails, try pulses API
    if (iocs.length === 0) {
      const pulsesResp = await axios.get(
        'https://otx.alienvault.com/api/v1/pulses/subscribed',
        { headers: { 'X-OTX-API-KEY': OTX_KEY }, timeout: 10000 }
      ).catch(() => null);

      if (pulsesResp?.data?.results) {
        for (const pulse of pulsesResp.data.results.slice(0, 5)) {
          for (const ind of (pulse.indicators || []).slice(0, 50)) {
            const typeMap = { IPv4: 'ip', domain: 'domain', URL: 'url', FileHash_SHA256: 'hash_sha256', FileHash_MD5: 'hash_md5' };
            const mappedType = typeMap[ind.type];
            if (mappedType && ind.indicator) {
              iocs.push({
                value:       ind.indicator.toLowerCase(),
                type:        mappedType,
                reputation:  'malicious',
                risk_score:  75,
                source:      'AlienVault OTX',
                tags:        [pulse.name?.slice(0, 40) || 'OTX'],
                enrichment_data: { pulse_id: pulse.id, pulse_name: pulse.name },
              });
            }
          }
        }
      }
    }

    lastPull.otx = Date.now();
    const imported = await upsertIOCs(tenantId, iocs);
    console.info(`[Collectors][OTX] Pulled ${iocs.length} indicators, imported ${imported}`);
    res.json({ source: 'otx', pulled: iocs.length, imported });

  } catch (err) {
    console.error('[Collectors][OTX] Error:', err.message);
    res.status(502).json({ error: 'OTX API error: ' + err.message });
  }
}));

// ── POST /api/collectors/abuseipdb ─────────────────────────────
router.post('/abuseipdb', verifyToken, requireRole(['ADMIN','SUPER_ADMIN','ANALYST']),
asyncHandler(async (req, res) => {
  if (!canPull('abuseipdb')) {
    return res.status(429).json({ error: 'Rate limited. Please wait before pulling again.' });
  }

  const KEY = process.env.ABUSEIPDB_API_KEY;
  if (!KEY) return res.status(503).json({ error: 'ABUSEIPDB_API_KEY not configured' });

  const tenantId = req.tenantId;
  const iocs = [];

  try {
    // Pull blacklisted IPs (confidence >= 90)
    const resp = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
      params: { confidenceMinimum: 85, limit: 500 },
      headers: { Key: KEY, Accept: 'application/json' },
      timeout: 15000,
    });

    for (const entry of (resp.data?.data || []).slice(0, 300)) {
      iocs.push({
        value:       entry.ipAddress,
        type:        'ip',
        reputation:  'malicious',
        risk_score:  Math.min(100, entry.abuseConfidenceScore),
        source:      'AbuseIPDB',
        country:     entry.countryCode || null,
        tags:        ['AbuseIPDB', `Confidence:${entry.abuseConfidenceScore}%`],
        notes:       `Reports: ${entry.totalReports}, Last: ${entry.lastReportedAt}`,
        enrichment_data: {
          abuse_confidence: entry.abuseConfidenceScore,
          total_reports:    entry.totalReports,
          last_reported:    entry.lastReportedAt,
          usage_type:       entry.usageType,
          isp:              entry.isp,
        },
      });
    }

    lastPull.abuseipdb = Date.now();
    const imported = await upsertIOCs(tenantId, iocs);
    console.info(`[Collectors][AbuseIPDB] Pulled ${iocs.length} IPs, imported ${imported}`);
    res.json({ source: 'abuseipdb', pulled: iocs.length, imported });

  } catch (err) {
    const status = err.response?.status;
    if (status === 429) return res.status(429).json({ error: 'AbuseIPDB rate limit hit' });
    if (status === 401) return res.status(503).json({ error: 'Invalid AbuseIPDB API key' });
    res.status(502).json({ error: 'AbuseIPDB API error: ' + err.message });
  }
}));

// ── POST /api/collectors/virustotal ────────────────────────────
router.post('/virustotal', verifyToken, requireRole(['ADMIN','SUPER_ADMIN','ANALYST']),
asyncHandler(async (req, res) => {
  if (!canPull('virustotal')) {
    return res.status(429).json({ error: 'Rate limited. Please wait before pulling again.' });
  }

  const KEY = process.env.VIRUSTOTAL_API_KEY;
  if (!KEY) return res.status(503).json({ error: 'VIRUSTOTAL_API_KEY not configured' });

  const tenantId  = req.tenantId;
  const iocs      = [];
  const { ioc_values = [], ioc_type = 'ip' } = req.body;

  // If specific IOCs provided — enrich them
  const targets = ioc_values.length > 0
    ? ioc_values.slice(0, 10)
    : ['185.220.101.45', '91.243.44.130', '194.165.16.77']; // default known bad IPs for demo

  for (const value of targets) {
    try {
      const typeMap = { ip: 'ip_addresses', domain: 'domains', url: 'urls', hash_sha256: 'files' };
      const endpoint = typeMap[ioc_type] || 'ip_addresses';
      const cleanValue = ioc_type === 'url' ? encodeURIComponent(btoa(value)) : value;

      const resp = await axios.get(
        `https://www.virustotal.com/api/v3/${endpoint}/${cleanValue}`,
        { headers: { 'x-apikey': KEY }, timeout: 10000 }
      );

      const attrs = resp.data?.data?.attributes;
      if (!attrs) continue;

      const malCount = attrs.last_analysis_stats?.malicious || 0;
      const totalEngines = Object.values(attrs.last_analysis_stats || {}).reduce((a, b) => a + b, 0);
      const riskScore = totalEngines > 0 ? Math.round((malCount / totalEngines) * 100) : 0;

      iocs.push({
        value,
        type:           ioc_type,
        reputation:     malCount >= 5 ? 'malicious' : malCount >= 2 ? 'suspicious' : 'clean',
        risk_score:     riskScore,
        source:         'VirusTotal',
        country:        attrs.country || null,
        asn:            attrs.asn ? `AS${attrs.asn} ${attrs.as_owner || ''}` : null,
        tags:           ['VirusTotal', `${malCount}/${totalEngines} detections`],
        notes:          attrs.tags?.join(', ') || '',
        enrichment_data:{
          vt_stats:      attrs.last_analysis_stats,
          vt_score:      malCount,
          vt_total:      totalEngines,
          categories:    attrs.categories,
          reputation:    attrs.reputation,
        },
      });

      await sleep(250); // VT rate limit: ~4 req/s on free tier
    } catch (err) {
      if (err.response?.status === 429) {
        console.warn('[Collectors][VT] Rate limited — stopping batch');
        break;
      }
      console.warn(`[Collectors][VT] Failed for ${value}:`, err.message);
    }
  }

  lastPull.virustotal = Date.now();
  const imported = await upsertIOCs(tenantId, iocs);
  console.info(`[Collectors][VirusTotal] Enriched ${iocs.length}, imported ${imported}`);
  res.json({ source: 'virustotal', pulled: iocs.length, imported });
}));

// ── POST /api/collectors/shodan ─────────────────────────────────
router.post('/shodan', verifyToken, requireRole(['ADMIN','SUPER_ADMIN','ANALYST']),
asyncHandler(async (req, res) => {
  if (!canPull('shodan')) {
    return res.status(429).json({ error: 'Rate limited. Please wait before pulling again.' });
  }

  const KEY = process.env.SHODAN_API_KEY;
  if (!KEY) return res.status(503).json({ error: 'SHODAN_API_KEY not configured' });

  const tenantId = req.tenantId;
  const iocs     = [];

  try {
    // Search for known malicious infrastructure (C2, botnet)
    const queries = [
      'tag:c2',
      'tag:botnet',
      'port:4444 os:Windows',  // Metasploit default port
    ];

    for (const q of queries.slice(0, 1)) { // 1 query to stay in API budget
      const resp = await axios.get('https://api.shodan.io/shodan/host/search', {
        params: { key: KEY, query: q, minify: true },
        timeout: 15000,
      });

      for (const host of (resp.data?.matches || []).slice(0, 50)) {
        iocs.push({
          value:       host.ip_str,
          type:        'ip',
          reputation:  'suspicious',
          risk_score:  60,
          source:      'Shodan',
          country:     host.location?.country_code || null,
          asn:         host.asn ? `${host.asn} ${host.org || ''}` : null,
          tags:        ['Shodan', q.replace('tag:',''), ...(host.tags || [])].filter(Boolean),
          notes:       `Ports: ${(host.ports || []).join(', ')} | Org: ${host.org || 'N/A'}`,
          enrichment_data: {
            shodan_ports: host.ports,
            shodan_org:   host.org,
            shodan_isp:   host.isp,
            shodan_query: q,
            hostnames:    host.hostnames,
          },
        });
      }

      await sleep(1000); // Shodan rate limit
    }

    lastPull.shodan = Date.now();
    const imported = await upsertIOCs(tenantId, iocs);
    console.info(`[Collectors][Shodan] Pulled ${iocs.length} hosts, imported ${imported}`);
    res.json({ source: 'shodan', pulled: iocs.length, imported });

  } catch (err) {
    const status = err.response?.status;
    if (status === 401) return res.status(503).json({ error: 'Invalid Shodan API key' });
    if (status === 429) return res.status(429).json({ error: 'Shodan rate limit hit' });
    res.status(502).json({ error: 'Shodan API error: ' + err.message });
  }
}));

// ── Helper (also used in VT route) ─────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

module.exports = router;
