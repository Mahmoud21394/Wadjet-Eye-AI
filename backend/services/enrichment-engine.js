/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Intelligence Enrichment Engine v5.2
 *  backend/services/enrichment-engine.js
 *
 *  Enriches IOCs with:
 *    - VirusTotal (reputation, scan results, file info)
 *    - AbuseIPDB  (IP reputation, abuse confidence score)
 *    - IPInfo     (GeoIP — free tier, no key required)
 *    - Shodan     (open ports, banners, org info)
 *    - CIRCL CVE  (CVE details for hash→malware lookups)
 *
 *  Architecture:
 *    - Rate-limited per-provider queues (avoid 429)
 *    - Results stored in iocs.enrichment_data (JSON)
 *    - Risk score recalculated after enrichment
 *    - Logging to detection_timeline
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios      = require('axios');
// v7.0: Use supabaseIngestion — isolated from auth clients, prevents event-loop
// saturation during enrichment batch runs from interfering with auth operations.
const { supabaseIngestion: supabase } = require('../config/supabase');

// ── API Keys from environment ─────────────────────────────────
const VT_KEY       = process.env.VIRUSTOTAL_API_KEY;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;
const SHODAN_KEY   = process.env.SHODAN_API_KEY;

// ── Rate limit tracking (simple in-memory per-process) ────────
const _lastCall = {};
const MIN_INTERVAL = {
  virustotal: 15100,  // VT free: 4 req/min
  abuseipdb:  1000,   // AbuseIPDB: 1000/day
  shodan:     1000,   // Shodan free: 100/month → conservative
  ipinfo:     100,    // IPInfo free: 50k/month
};

async function _rateWait(provider) {
  const last = _lastCall[provider] || 0;
  const wait = MIN_INTERVAL[provider] - (Date.now() - last);
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  _lastCall[provider] = Date.now();
}

// ══════════════════════════════════════════════
//  VirusTotal Enrichment
// ══════════════════════════════════════════════
async function enrichWithVirusTotal(ioc) {
  if (!VT_KEY) return null;

  await _rateWait('virustotal');

  try {
    let url;
    const encoded = encodeURIComponent(
      Buffer.from(ioc.value).toString('base64').replace(/=+$/, '')
    );

    if (ioc.type === 'ip') {
      url = `https://www.virustotal.com/api/v3/ip_addresses/${ioc.value}`;
    } else if (ioc.type === 'domain') {
      url = `https://www.virustotal.com/api/v3/domains/${ioc.value}`;
    } else if (ioc.type === 'url') {
      url = `https://www.virustotal.com/api/v3/urls/${encoded}`;
    } else if (['hash_md5','hash_sha1','hash_sha256'].includes(ioc.type)) {
      url = `https://www.virustotal.com/api/v3/files/${ioc.value}`;
    } else {
      return null;
    }

    const { data } = await axios.get(url, {
      headers: { 'x-apikey': VT_KEY },
      timeout: 15000,
    });

    const attrs  = data?.data?.attributes || {};
    const stats  = attrs.last_analysis_stats || {};
    const total  = Object.values(stats).reduce((a, b) => a + b, 0);
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const malRate   = total > 0 ? malicious / total : 0;
    const suspRate  = total > 0 ? suspicious / total : 0;

    let vtRisk = Math.round((malRate * 0.7 + suspRate * 0.3) * 100);
    let reputation = 'unknown';
    if (malRate > 0.1) reputation = 'malicious';
    else if (malRate > 0.02 || suspRate > 0.1) reputation = 'suspicious';
    else if (total > 5) reputation = 'clean';

    return {
      provider:       'VirusTotal',
      risk_score:     vtRisk,
      reputation,
      malicious_votes: malicious,
      total_scanners:  total,
      community_score: attrs.reputation || 0,
      tags:            (attrs.tags || []).slice(0, 5),
      categories:      attrs.categories || {},
      country:         attrs.country || attrs.network?.country || null,
      asn:             attrs.asn || String(attrs.network?.asn || ''),
      threat_names:    attrs.popular_threat_names || [],
      last_analysis:   attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
    };
  } catch (err) {
    if (err.response?.status === 404) return { provider: 'VirusTotal', not_found: true };
    console.warn('[Enrichment][VT] Error:', err.message);
    return null;
  }
}

// ══════════════════════════════════════════════
//  AbuseIPDB Enrichment (IPs only)
// ══════════════════════════════════════════════
async function enrichWithAbuseIPDB(ioc) {
  if (!ABUSEIPDB_KEY || ioc.type !== 'ip') return null;

  await _rateWait('abuseipdb');

  try {
    const { data } = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ioc.value, maxAgeInDays: 30, verbose: true },
      headers: { Key: ABUSEIPDB_KEY, Accept: 'application/json' },
      timeout: 10000,
    });

    const d = data?.data || {};
    return {
      provider:          'AbuseIPDB',
      abuse_score:       d.abuseConfidenceScore || 0,
      total_reports:     d.totalReports || 0,
      country:           d.countryCode || null,
      isp:               d.isp || null,
      domain:            d.domain || null,
      usage_type:        d.usageType || null,
      is_tor:            d.isTor || false,
      is_public:         d.isPublic || false,
      last_reported_at:  d.lastReportedAt || null,
      risk_score:        d.abuseConfidenceScore || 0,
    };
  } catch (err) {
    console.warn('[Enrichment][AbuseIPDB] Error:', err.message);
    return null;
  }
}

// ══════════════════════════════════════════════
//  IPInfo GeoIP (free — no key for basic)
// ══════════════════════════════════════════════
async function enrichWithGeoIP(ioc) {
  if (!['ip'].includes(ioc.type)) return null;

  // Skip private/reserved IPs
  const privateRanges = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0)/;
  if (privateRanges.test(ioc.value)) return null;

  await _rateWait('ipinfo');

  try {
    const key = process.env.IPINFO_API_KEY || '';
    const url = key
      ? `https://ipinfo.io/${ioc.value}/json?token=${key}`
      : `https://ipinfo.io/${ioc.value}/json`;

    const { data } = await axios.get(url, { timeout: 8000 });

    return {
      provider: 'IPInfo',
      country:  data.country || null,
      region:   data.region  || null,
      city:     data.city    || null,
      org:      data.org     || null,
      asn:      data.org?.split(' ')[0] || null,
      hostname: data.hostname || null,
      loc:      data.loc     || null,
      timezone: data.timezone || null,
    };
  } catch (err) {
    console.warn('[Enrichment][GeoIP] Error:', err.message);
    return null;
  }
}

// ══════════════════════════════════════════════
//  Shodan Enrichment (IPs — requires API key)
// ══════════════════════════════════════════════
async function enrichWithShodan(ioc) {
  if (!SHODAN_KEY || ioc.type !== 'ip') return null;

  await _rateWait('shodan');

  try {
    const { data } = await axios.get(
      `https://api.shodan.io/shodan/host/${ioc.value}?key=${SHODAN_KEY}`,
      { timeout: 10000 }
    );

    return {
      provider:    'Shodan',
      open_ports:  data.ports || [],
      hostnames:   data.hostnames || [],
      country:     data.country_code || null,
      city:        data.city || null,
      org:         data.org || null,
      isp:         data.isp || null,
      asn:         data.asn || null,
      os:          data.os || null,
      vulns:       Object.keys(data.vulns || {}).slice(0, 10),
      tags:        data.tags || [],
      last_update: data.last_update || null,
    };
  } catch (err) {
    if (err.response?.status === 404) return { provider: 'Shodan', not_found: true };
    console.warn('[Enrichment][Shodan] Error:', err.message);
    return null;
  }
}

// ══════════════════════════════════════════════
//  Composite Risk Score Calculation
// ══════════════════════════════════════════════
function computeCompositeRisk(existingScore, vtData, abuseData) {
  let score = existingScore || 50;
  let weight = 1;

  if (vtData && !vtData.not_found) {
    score  = score * weight + (vtData.risk_score || 0) * 2;
    weight = weight + 2;
  }
  if (abuseData) {
    score  = score + (abuseData.abuse_score || 0) * 1.5;
    weight = weight + 1.5;
  }

  return Math.min(100, Math.round(score / weight));
}

// ══════════════════════════════════════════════
//  Main Enrichment Function
// ══════════════════════════════════════════════
async function enrichIOC(iocRecord) {
  const results = {};
  let newRisk   = iocRecord.risk_score || 50;
  let newRep    = iocRecord.reputation || 'unknown';
  let country   = iocRecord.country || null;
  let asn       = iocRecord.asn || null;

  // Run enrichment based on IOC type
  if (['ip','domain','url','hash_md5','hash_sha1','hash_sha256'].includes(iocRecord.type)) {
    const vt = await enrichWithVirusTotal(iocRecord);
    if (vt) {
      results.virustotal = vt;
      if (vt.risk_score > 0) newRisk = computeCompositeRisk(newRisk, vt, null);
      if (vt.reputation && vt.reputation !== 'unknown') newRep = vt.reputation;
      if (vt.country) country = vt.country;
      if (vt.asn) asn = vt.asn;
    }
  }

  if (iocRecord.type === 'ip') {
    const [abuse, geo, shodan] = await Promise.allSettled([
      enrichWithAbuseIPDB(iocRecord),
      enrichWithGeoIP(iocRecord),
      enrichWithShodan(iocRecord),
    ]);

    const abuseData  = abuse.status  === 'fulfilled' ? abuse.value  : null;
    const geoData    = geo.status    === 'fulfilled' ? geo.value    : null;
    const shodanData = shodan.status === 'fulfilled' ? shodan.value : null;

    if (abuseData)  { results.abuseipdb = abuseData; newRisk = computeCompositeRisk(newRisk, null, abuseData); if (!country) country = abuseData.country; }
    if (geoData)    { results.geoip = geoData; if (!country) country = geoData.country; if (!asn) asn = geoData.asn; }
    if (shodanData) { results.shodan = shodanData; }

    if (abuseData?.abuse_score > 50) newRep = 'malicious';
    else if (abuseData?.abuse_score > 20) newRep = newRep === 'malicious' ? 'malicious' : 'suspicious';
  }

  // Update the IOC record in Supabase
  const { error } = await supabase
    .from('iocs')
    .update({
      enrichment_data:   { ...iocRecord.enrichment_data, ...results },
      risk_score:        Math.max(newRisk, iocRecord.risk_score || 0),
      reputation:        newRep,
      country,
      asn,
      enriched_at:       new Date().toISOString(),
      last_seen:         new Date().toISOString(),
    })
    .eq('id', iocRecord.id);

  if (error) console.error('[Enrichment] DB update error:', error.message);

  return {
    ioc_id:      iocRecord.id,
    value:       iocRecord.value,
    type:        iocRecord.type,
    risk_score:  newRisk,
    reputation:  newRep,
    enrichments: results,
  };
}

// ══════════════════════════════════════════════
//  Batch Enrichment (for background workers)
// ══════════════════════════════════════════════
async function enrichBatch(tenantId, limit = 20) {
  // Fetch IOCs that have never been enriched (or enriched >24h ago)
  const cutoff = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

  const { data: iocs, error } = await supabase
    .from('iocs')
    .select('*')
    .eq('tenant_id', tenantId || process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001')
    .or(`enriched_at.is.null,enriched_at.lt.${cutoff}`)
    .in('type', ['ip','domain','url','hash_md5','hash_sha1','hash_sha256'])
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error || !iocs || iocs.length === 0) {
    console.info('[Enrichment] No IOCs to enrich');
    return { enriched: 0 };
  }

  console.info(`[Enrichment] Enriching ${iocs.length} IOCs...`);
  let enriched = 0;

  for (const ioc of iocs) {
    try {
      await enrichIOC(ioc);
      enriched++;
      // Throttle: 2 sec between each IOC to avoid rate limits
      await new Promise(r => setTimeout(r, 2000));
    } catch (err) {
      console.warn(`[Enrichment] Failed for ${ioc.value}:`, err.message);
    }
  }

  console.info(`[Enrichment] ✓ Enriched ${enriched}/${iocs.length} IOCs`);
  return { enriched };
}

module.exports = {
  enrichIOC,
  enrichBatch,
  enrichWithVirusTotal,
  enrichWithAbuseIPDB,
  enrichWithGeoIP,
  enrichWithShodan,
};
