/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Direct Enrichment Service v3.1
 *  backend/services/enrichment-direct.js
 *
 *  Calls threat intel APIs DIRECTLY (no HTTP loopback).
 *  Used by SOAR and intelligence service to avoid the
 *  401 error caused by calling /api/intel/* without JWT.
 *
 *  Functions:
 *   enrichIP(ip)         → VirusTotal + AbuseIPDB + Shodan + OTX
 *   enrichDomain(domain) → VirusTotal + OTX
 *   enrichHash(hash)     → VirusTotal + OTX
 *   enrichIOC(ioc)       → auto-dispatch by type
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios      = require('axios');
const { supabase } = require('../config/supabase');

// ── Cache helpers ─────────────────────────────────────────
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
  } catch (_) { return null; }
}

async function setCache(key, value) {
  try {
    await supabase
      .from('ioc_enrichment_cache')
      .upsert({ cache_key: key, data: value, created_at: new Date().toISOString() },
               { onConflict: 'cache_key' });
  } catch (_) { /* non-fatal */ }
}

// ── VirusTotal direct call ────────────────────────────────
async function queryVirusTotal(ioc, type) {
  const KEY = process.env.VIRUSTOTAL_API_KEY;
  if (!KEY) return null;

  const cacheKey = `vt:${type}:${ioc}`;
  const cached   = await getCache(cacheKey);
  if (cached) return cached;

  try {
    const endpointMap = {
      ip:           `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
      domain:       `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
      url:          `https://www.virustotal.com/api/v3/urls/${Buffer.from(ioc).toString('base64url')}`,
      hash_sha256:  `https://www.virustotal.com/api/v3/files/${ioc}`,
      hash_md5:     `https://www.virustotal.com/api/v3/files/${ioc}`,
      hash_sha1:    `https://www.virustotal.com/api/v3/files/${ioc}`,
    };
    const url = endpointMap[type];
    if (!url) return null;

    const resp = await axios.get(url, {
      headers: { 'x-apikey': KEY },
      timeout: 15000,
    });

    const attr     = resp.data?.data?.attributes || {};
    const lastStats= attr.last_analysis_stats || {};
    const malCount = (lastStats.malicious || 0) + (lastStats.suspicious || 0);
    const total    = Object.values(lastStats).reduce((s, v) => s + (v || 0), 0);

    const result = {
      source:           'VirusTotal',
      ioc, type,
      malicious_count:  malCount,
      total_engines:    total,
      reputation:       attr.reputation || 0,
      risk_score:       total > 0 ? Math.round((malCount / total) * 100) : 0,
      country:          attr.country || null,
      asn:              attr.asn ? `AS${attr.asn}` : null,
      owner:            attr.as_owner || attr.registrar || null,
      categories:       Object.values(attr.categories || {}).slice(0, 3),
      last_analysis_date: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
    };

    await setCache(cacheKey, result);
    return result;
  } catch (err) {
    if (err.response?.status !== 404) {
      console.warn(`[EnrichDirect] VT error for ${ioc}: ${err.message}`);
    }
    return null;
  }
}

// ── AbuseIPDB direct call ─────────────────────────────────
async function queryAbuseIPDB(ip) {
  const KEY = process.env.ABUSEIPDB_API_KEY;
  if (!KEY) return null;

  const cacheKey = `abuse:${ip}`;
  const cached   = await getCache(cacheKey);
  if (cached) return cached;

  try {
    const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: false },
      headers: { Key: KEY, Accept: 'application/json' },
      timeout: 10000,
    });

    const d = resp.data?.data || {};
    const result = {
      source:        'AbuseIPDB',
      ip,
      abuse_score:   d.abuseConfidenceScore || 0,
      total_reports: d.totalReports || 0,
      distinct_users:d.numDistinctUsers || 0,
      country:       d.countryCode || null,
      isp:           d.isp || null,
      domain:        d.domain || null,
      is_tor:        d.isTor || false,
      is_public:     d.isPublic !== false,
      usage_type:    d.usageType || null,
      last_reported: d.lastReportedAt || null,
      risk_score:    d.abuseConfidenceScore || 0,
      reputation:    d.abuseConfidenceScore >= 70 ? 'malicious' :
                     d.abuseConfidenceScore >= 30 ? 'suspicious' : 'clean',
    };

    await setCache(cacheKey, result);
    return result;
  } catch (err) {
    console.warn(`[EnrichDirect] AbuseIPDB error for ${ip}: ${err.message}`);
    return null;
  }
}

// ── OTX direct call ───────────────────────────────────────
async function queryOTX(ioc, type) {
  const KEY = process.env.OTX_API_KEY;
  if (!KEY) return null;

  const cacheKey = `otx:${type}:${ioc}`;
  const cached   = await getCache(cacheKey);
  if (cached) return cached;

  try {
    const sectionMap = {
      ip:           `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`,
      domain:       `https://otx.alienvault.com/api/v1/indicators/domain/${ioc}/general`,
      url:          `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(ioc)}/general`,
      hash_sha256:  `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`,
      hash_md5:     `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`,
    };
    const url = sectionMap[type];
    if (!url) return null;

    const resp = await axios.get(url, {
      headers: { 'X-OTX-API-KEY': KEY },
      timeout: 10000,
    });

    const d = resp.data || {};
    const pulses = (d.pulse_info?.pulses || []).slice(0, 5);
    const result = {
      source:       'AlienVault OTX',
      ioc, type,
      pulse_count:  d.pulse_info?.count || 0,
      pulses:       pulses.map(p => ({ id: p.id, name: p.name, tlp: p.tlp })),
      threat_score: Math.min(100, (d.pulse_info?.count || 0) * 10),
      risk_score:   Math.min(100, (d.pulse_info?.count || 0) * 10),
      reputation:   d.pulse_info?.count > 5 ? 'malicious' :
                    d.pulse_info?.count > 0 ? 'suspicious' : 'clean',
      country:      d.country_name || null,
      asn:          d.asn || null,
    };

    await setCache(cacheKey, result);
    return result;
  } catch (err) {
    if (err.response?.status !== 404) {
      console.warn(`[EnrichDirect] OTX error for ${ioc}: ${err.message}`);
    }
    return null;
  }
}

// ── Shodan direct call ────────────────────────────────────
async function queryShodan(ip) {
  const KEY = process.env.SHODAN_API_KEY;
  if (!KEY) return null;

  const cacheKey = `shodan:${ip}`;
  const cached   = await getCache(cacheKey);
  if (cached) return cached;

  try {
    const resp = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params:  { key: KEY },
      timeout: 15000,
    });
    const d = resp.data || {};
    const result = {
      source:     'Shodan',
      ip,
      org:        d.org || null,
      isp:        d.isp || null,
      country:    d.country_code || null,
      city:       d.city || null,
      asn:        d.asn || null,
      os:         d.os || null,
      ports:      (d.ports || []).slice(0, 10),
      hostnames:  (d.hostnames || []).slice(0, 5),
      vulns:      Object.keys(d.vulns || {}).slice(0, 10),
      tags:       d.tags || [],
      last_update:d.last_update || null,
      risk_score: Math.min(100, (Object.keys(d.vulns || {}).length * 10) + Math.min(20, (d.ports || []).length)),
    };
    await setCache(cacheKey, result);
    return result;
  } catch (err) {
    if (err.response?.status !== 404) {
      console.warn(`[EnrichDirect] Shodan error for ${ip}: ${err.message}`);
    }
    return null;
  }
}

// ══════════════════════════════════════════════════════════
//  MAIN: enrichIOC — auto-dispatch by type
// ══════════════════════════════════════════════════════════
async function enrichIOC(ioc) {
  if (!ioc?.value || !ioc?.type) return {};

  const { value, type } = ioc;
  const results = {};

  const calls = [];

  // VirusTotal — works for IP, domain, URL, hashes
  if (['ip','domain','url','hash_sha256','hash_md5','hash_sha1'].includes(type)) {
    calls.push(
      queryVirusTotal(value, type).then(r => { if (r) results.VirusTotal = r; })
    );
  }

  // AbuseIPDB — IPs only
  if (type === 'ip') {
    calls.push(
      queryAbuseIPDB(value).then(r => { if (r) results.AbuseIPDB = r; })
    );
    calls.push(
      queryShodan(value).then(r => { if (r) results.Shodan = r; })
    );
  }

  // OTX — IP, domain, URL, hashes
  if (['ip','domain','url','hash_sha256','hash_md5'].includes(type)) {
    calls.push(
      queryOTX(value, type).then(r => { if (r) results['AlienVault OTX'] = r; })
    );
  }

  await Promise.allSettled(calls);
  return results;
}

// ── Aggregate risk score across all sources ───────────────
function aggregateRiskScore(enrichmentResults) {
  const SOURCE_WEIGHTS = {
    VirusTotal:       0.95,
    AbuseIPDB:        0.85,
    'AlienVault OTX': 0.80,
    Shodan:           0.70,
  };

  const scores = [];
  for (const [source, data] of Object.entries(enrichmentResults)) {
    if (!data) continue;
    const weight = SOURCE_WEIGHTS[source] || 0.5;
    const score  = data.risk_score || data.abuse_score || data.threat_score || 0;
    scores.push(score * weight);
  }

  if (scores.length === 0) return 0;

  const avg    = scores.reduce((s, v) => s + v, 0) / scores.length;
  const crossFeed = Math.min(15, (scores.length - 1) * 5);
  return Math.min(100, Math.round(avg + crossFeed));
}

module.exports = {
  enrichIOC,
  queryVirusTotal,
  queryAbuseIPDB,
  queryOTX,
  queryShodan,
  aggregateRiskScore,
};
