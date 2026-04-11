/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Normalisation, Scoring & MITRE Engine
 *  services/intelligence/index.js  (v3.1 — fixes applied)
 *
 *  BUG FIXES IN THIS VERSION:
 *   FIX-1: autoEnrichIOCObject / autoEnrichIOC now call external
 *           APIs **directly** (axios → external service) instead of
 *           round-tripping through http://localhost/api/intel/*.
 *           That removes the 401 Unauthorized errors caused by the
 *           internal routes requiring a JWT the background service
 *           does not have.
 *   FIX-2: Removed all `.catch()` chains on Supabase Builder objects.
 *           Supabase JS v2 does NOT expose .catch() on query builders;
 *           use try/catch or destructured {error} instead.
 *   FIX-3: buildRelationships used `.catch()` on a Builder — replaced
 *           with try/catch.
 *   FIX-4: detection_timeline insert in autoEnrichIOC used a bare
 *           .catch(() => {}) on the builder — wrapped in try/catch.
 *   FIX-5: ThreatFox "no_results" is a valid (empty) response, not
 *           an error — handled in ingestion worker.
 *
 *  Functions:
 *   normalizeIOC()          — unified IOC schema
 *   calculateRiskScore()    — weighted multi-source scoring
 *   mapToMITRE()            — IOC → ATT&CK technique mapping
 *   buildRelationships()    — create graph edges
 *   correlateIOC()          — cross-feed correlation
 *   autoEnrichIOC()         — DB-backed enrichment by iocId
 *   autoEnrichIOCObject()   — lightweight enrichment by plain object
 *   enrichWithVirusTotal()  — direct VT API call (no HTTP proxy)
 *   enrichWithAbuseIPDB()   — direct AbuseIPDB API call
 *   enrichWithShodan()      — direct Shodan API call
 *   enrichWithOTX()         — direct OTX API call
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios        = require('axios');
const { supabase } = require('../../config/supabase');

// ── Source reliability weights (0–1) ────────────────────────────
const SOURCE_WEIGHTS = {
  VirusTotal:       0.95,
  AbuseIPDB:        0.85,
  'AlienVault OTX': 0.80,
  URLhaus:          0.90,
  ThreatFox:        0.88,
  Shodan:           0.70,
  NVD:              1.00,
  CIRCL:            0.85,
  manual:           0.60,
};

// ── MITRE technique keyword patterns ────────────────────────────
const MITRE_PATTERNS = [
  { iocTypes: ['ip'],                          keywords: ['c2','botnet','malware'],        techniques: ['T1071.001','T1095'] },
  { iocTypes: ['ip'],                          keywords: ['scanner','shodan','masscan'],   techniques: ['T1046'] },
  { iocTypes: ['ip'],                          keywords: ['brute','ssh','rdp'],            techniques: ['T1110'] },
  { iocTypes: ['domain'],                      keywords: ['phishing','lure','spear'],      techniques: ['T1566.002','T1566.001'] },
  { iocTypes: ['domain'],                      keywords: ['c2','command','control'],       techniques: ['T1071.001'] },
  { iocTypes: ['domain'],                      keywords: ['dga','generated','random'],     techniques: ['T1568.002'] },
  { iocTypes: ['url'],                         keywords: ['phishing','login','harvest'],   techniques: ['T1566.002','T1078'] },
  { iocTypes: ['url'],                         keywords: ['exploit','payload','download'], techniques: ['T1190','T1059'] },
  { iocTypes: ['hash_sha256','hash_md5'],      keywords: ['ransomware','encrypt'],         techniques: ['T1486','T1490'] },
  { iocTypes: ['hash_sha256','hash_md5'],      keywords: ['rat','remote','trojan'],        techniques: ['T1021','T1055'] },
  { iocTypes: ['hash_sha256','hash_md5'],      keywords: ['loader','dropper'],             techniques: ['T1059','T1027'] },
  { iocTypes: ['email'],                       keywords: ['phishing','spear'],             techniques: ['T1566.001','T1566.002'] },
  { iocTypes: ['filename'],                    keywords: ['lsass','mimikatz','dump'],      techniques: ['T1003.001','T1003'] },
  { iocTypes: ['filename'],                    keywords: ['powershell','ps1','encoded'],   techniques: ['T1059.001'] },
];

// ── Known malware → MITRE technique map ─────────────────────────
const MALWARE_TECHNIQUES = {
  lockbit:    ['T1486','T1490','T1489','T1078'],
  ransomware: ['T1486','T1490','T1489'],
  mimikatz:   ['T1003.001','T1550.002'],
  cobalt:     ['T1071.001','T1055','T1059.001'],
  metasploit: ['T1059','T1055','T1021'],
  emotet:     ['T1566.001','T1059','T1027'],
  trickbot:   ['T1566.001','T1003','T1021'],
  apt29:      ['T1071.001','T1566.002','T1078','T1003.001'],
  apt28:      ['T1059.001','T1566.001','T1550.002'],
};

// ══════════════════════════════════════════════
//  DIRECT EXTERNAL API HELPERS
//  These call the external services without going
//  through http://localhost so no JWT is needed.
// ══════════════════════════════════════════════

/**
 * FIX-1a: Call VirusTotal API directly.
 * Returns normalised object or null on missing key / error.
 */
async function enrichWithVirusTotal(iocValue, iocType) {
  const API_KEY = process.env.VIRUSTOTAL_API_KEY;
  if (!API_KEY) return null;

  const endpoints = {
    ip:          `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(iocValue)}`,
    domain:      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(iocValue)}`,
    hash_sha256: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(iocValue)}`,
    hash_md5:    `https://www.virustotal.com/api/v3/files/${encodeURIComponent(iocValue)}`,
    hash_sha1:   `https://www.virustotal.com/api/v3/files/${encodeURIComponent(iocValue)}`,
    url:         `https://www.virustotal.com/api/v3/urls/${Buffer.from(iocValue).toString('base64url')}`,
  };

  const url = endpoints[iocType];
  if (!url) return null;

  try {
    const { data } = await axios.get(url, {
      headers: { 'x-apikey': API_KEY },
      timeout: 12000,
    });

    const attr     = data.data?.attributes || {};
    const stats    = attr.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total    = Object.values(stats).reduce((a, b) => a + b, 0);

    return {
      source:          'VirusTotal',
      malicious_count: malicious,
      total_engines:   total,
      risk_score:      Math.min(100, Math.round((malicious / Math.max(total, 1)) * 100)),
      reputation:      malicious === 0 ? 'clean' : malicious < 5 ? 'suspicious' : 'malicious',
      country:         attr.country || attr.network?.country || null,
      asn:             attr.asn     || null,
      owner:           attr.as_owner || null,
      categories:      attr.categories ? Object.values(attr.categories).join(', ') : null,
      last_analysis_date: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
    };
  } catch (err) {
    if (err.response?.status === 404) return { source: 'VirusTotal', risk_score: 0, reputation: 'unknown' };
    console.warn('[Intel] VirusTotal error:', err.message);
    return null;
  }
}

/**
 * FIX-1b: Call AbuseIPDB API directly.
 */
async function enrichWithAbuseIPDB(ip) {
  const API_KEY = process.env.ABUSEIPDB_API_KEY;
  if (!API_KEY) return null;

  try {
    const { data } = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params:  { ipAddress: ip, maxAgeInDays: 90, verbose: true },
      headers: { Key: API_KEY, Accept: 'application/json' },
      timeout: 10000,
    });

    const d = data.data;
    return {
      source:         'AbuseIPDB',
      abuse_score:    d.abuseConfidenceScore,
      total_reports:  d.totalReports,
      distinct_users: d.numDistinctUsers,
      country:        d.countryCode,
      isp:            d.isp,
      domain:         d.domain,
      is_tor:         d.isTor,
      usage_type:     d.usageType,
      last_reported:  d.lastReportedAt,
      risk_score:     d.abuseConfidenceScore,
      reputation:     d.abuseConfidenceScore < 10 ? 'clean'
                    : d.abuseConfidenceScore < 50 ? 'suspicious' : 'malicious',
    };
  } catch (err) {
    console.warn('[Intel] AbuseIPDB error:', err.message);
    return null;
  }
}

/**
 * FIX-1c: Call Shodan API directly.
 */
async function enrichWithShodan(ip) {
  const API_KEY = process.env.SHODAN_API_KEY;
  if (!API_KEY) return null;

  try {
    const { data } = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params:  { key: API_KEY },
      timeout: 12000,
    });

    return {
      source:      'Shodan',
      org:         data.org,
      isp:         data.isp,
      country:     data.country_code,
      city:        data.city,
      asn:         data.asn,
      os:          data.os,
      ports:       data.ports || [],
      hostnames:   data.hostnames || [],
      vulns:       data.vulns ? Object.keys(data.vulns) : [],
      tags:        data.tags  || [],
      last_update: data.last_update,
      risk_score:  Math.min(100, (data.vulns ? Object.keys(data.vulns).length * 15 : 0)
                               + (data.ports?.length > 10 ? 20 : 0)),
    };
  } catch (err) {
    if (err.response?.status === 404) return { source: 'Shodan', ports: [], vulns: [], risk_score: 0 };
    console.warn('[Intel] Shodan error:', err.message);
    return null;
  }
}

/**
 * FIX-1d: Call AlienVault OTX API directly.
 */
async function enrichWithOTX(iocValue, iocType) {
  const API_KEY = process.env.OTX_API_KEY;
  if (!API_KEY) return null;

  const sectionMap = {
    ip:          `IPv4/${iocValue}/general`,
    domain:      `domain/${iocValue}/general`,
    hash_sha256: `file/${iocValue}/general`,
    hash_md5:    `file/${iocValue}/general`,
    hash_sha1:   `file/${iocValue}/general`,
  };

  const section = sectionMap[iocType];
  if (!section) return null;

  try {
    const { data } = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/${section}`,
      {
        headers: { 'X-OTX-API-KEY': API_KEY },
        timeout: 12000,
      }
    );

    return {
      source:       'AlienVault OTX',
      pulse_count:  data.pulse_info?.count || 0,
      pulses:       (data.pulse_info?.pulses || []).slice(0, 5).map(p => ({
        name: p.name, tags: p.tags, created: p.created,
      })),
      threat_score: data.pulse_info?.count > 0
        ? Math.min(100, data.pulse_info.count * 10) : 0,
      reputation:   data.pulse_info?.count > 0 ? 'malicious' : 'unknown',
      country:      data.country_code,
      asn:          data.asn,
      risk_score:   Math.min(100, (data.pulse_info?.count || 0) * 10),
    };
  } catch (err) {
    console.warn('[Intel] OTX error:', err.message);
    return null;
  }
}

// ══════════════════════════════════════════════
//  1. NORMALIZE IOC to unified schema
// ══════════════════════════════════════════════
function normalizeIOC(raw, source) {
  const value = String(raw.value || raw.ioc || raw.indicator || '').trim().toLowerCase();
  if (!value) return null;

  const type = raw.type || detectIOCType(value);
  if (!type) return null;

  return {
    value,
    type,
    reputation:     raw.reputation   || 'unknown',
    risk_score:     Math.min(100, Math.max(0, Math.round(raw.risk_score  || 0))),
    confidence:     Math.min(100, Math.max(0, Math.round(raw.confidence  || 50))),
    source:         source || raw.source || 'unknown',
    feed_source:    raw.feed_source || (source || 'manual').toLowerCase(),
    country:        raw.country      || null,
    asn:            raw.asn          || null,
    threat_actor:   raw.threat_actor || null,
    malware_family: raw.malware_family || null,
    tags:           Array.isArray(raw.tags) ? raw.tags.filter(Boolean).slice(0, 10) : [],
    notes:          raw.notes        || null,
    enrichment_data:raw.enrichment_data || raw.raw_data || {},
  };
}

function detectIOCType(value) {
  if (!value) return null;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
  if (/^[0-9a-f:]{7,39}$/.test(value) && value.includes(':')) return 'ip';
  if (/^[0-9a-f]{64}$/i.test(value)) return 'hash_sha256';
  if (/^[0-9a-f]{32}$/i.test(value)) return 'hash_md5';
  if (/^[0-9a-f]{40}$/i.test(value)) return 'hash_sha1';
  if (/^cve-\d{4}-\d{4,}$/i.test(value)) return 'cve';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
  if (/^https?:\/\//.test(value)) return 'url';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(value) && !value.includes('/')) return 'domain';
  return null;
}

// ══════════════════════════════════════════════
//  2. RISK SCORE CALCULATION
//     Weighted: source reliability × base score
//     + recency bonus + frequency + cross-feed
// ══════════════════════════════════════════════
function calculateRiskScore(enrichmentResults, existingIOC = null) {
  if (!enrichmentResults || Object.keys(enrichmentResults).length === 0) {
    return existingIOC?.risk_score || 0;
  }

  const now    = Date.now();
  const scores = [];

  for (const [source, data] of Object.entries(enrichmentResults)) {
    if (!data || typeof data !== 'object') continue;
    const weight   = SOURCE_WEIGHTS[source] || 0.5;
    const rawScore = data.risk_score || data.abuse_score || data.threat_score || 0;
    scores.push({ source, score: rawScore, weight });
  }

  if (scores.length === 0) return existingIOC?.risk_score || 0;

  const totalWeight = scores.reduce((s, x) => s + x.weight, 0);
  const weightedSum = scores.reduce((s, x) => s + x.score * x.weight, 0);
  const baseScore   = totalWeight > 0 ? weightedSum / totalWeight : 0;

  let recencyBonus = 0;
  if (existingIOC?.last_seen) {
    const ageHours = (now - new Date(existingIOC.last_seen).getTime()) / 3600000;
    recencyBonus   = ageHours < 24 ? 10 : ageHours < 72 ? 5 : 0;
  }

  const crossFeedBonus = Math.min(15, (scores.length - 1) * 5);

  const abuseData  = enrichmentResults['AbuseIPDB'];
  const freqBonus  = abuseData?.total_reports > 100 ? 10 :
                     abuseData?.total_reports > 20  ? 5  : 0;

  const finalScore = Math.min(100, Math.round(baseScore + recencyBonus + crossFeedBonus + freqBonus));

  return {
    score: finalScore,
    breakdown: {
      base_weighted: Math.round(baseScore),
      recency_bonus: recencyBonus,
      cross_feed:    crossFeedBonus,
      frequency:     freqBonus,
      sources_count: scores.length,
      source_scores: scores,
    }
  };
}

// ══════════════════════════════════════════════
//  3. MITRE ATT&CK MAPPING
// ══════════════════════════════════════════════
async function mapToMITRE(ioc) {
  const techniques = new Set();
  const { type, value = '', tags = [], malware_family, threat_actor, enrichment_data = {} } = ioc;

  const searchText = [
    value,
    malware_family,
    threat_actor,
    ...(tags || []),
    enrichment_data?.threat_type,
    enrichment_data?.malware,
    enrichment_data?.pulse_name,
  ].filter(Boolean).join(' ').toLowerCase();

  for (const pattern of MITRE_PATTERNS) {
    if (!pattern.iocTypes.includes(type)) continue;
    if (pattern.keywords.some(kw => searchText.includes(kw))) {
      pattern.techniques.forEach(t => techniques.add(t));
    }
  }

  for (const [malware, techs] of Object.entries(MALWARE_TECHNIQUES)) {
    if (searchText.includes(malware)) {
      techs.forEach(t => techniques.add(t));
    }
  }

  const techIds = [...techniques];
  if (techIds.length === 0) return [];

  try {
    const { data: validTechs } = await supabase
      .from('mitre_techniques')
      .select('technique_id, name, tactic')
      .in('technique_id', techIds);

    return validTechs || [];
  } catch (_) {
    return techIds.map(id => ({ technique_id: id, name: id, tactic: 'unknown' }));
  }
}

// ══════════════════════════════════════════════
//  4. RELATIONSHIP BUILDER
// ══════════════════════════════════════════════
async function buildRelationships(tenantId, ioc, enrichmentData) {
  const relationships = [];
  const iocId = ioc.id;

  if (!iocId) return 0;

  // IP → Domain (Shodan hostnames / reverse DNS)
  if (ioc.type === 'ip' && enrichmentData?.Shodan?.hostnames) {
    for (const hostname of (enrichmentData.Shodan.hostnames || []).slice(0, 5)) {
      relationships.push({
        tenant_id:    tenantId,
        source_type:  'ioc',
        source_id:    iocId,
        source_value: ioc.value,
        target_type:  'ioc',
        target_id:    hostname.toLowerCase(),
        target_value: hostname.toLowerCase(),
        relationship: 'resolves_to',
        confidence:   70,
        source:       'Shodan',
      });
    }
  }

  // IOC → Campaign (via threat actor)
  if (ioc.threat_actor) {
    try {
      const { data: actor } = await supabase
        .from('threat_actors')
        .select('id, name')
        .ilike('name', `%${ioc.threat_actor}%`)
        .single();

      if (actor) {
        relationships.push({
          tenant_id:    tenantId,
          source_type:  'ioc',
          source_id:    iocId,
          source_value: ioc.value,
          target_type:  'actor',
          target_id:    actor.id,
          target_value: actor.name,
          relationship: 'attributed_to',
          confidence:   65,
          source:       ioc.source,
        });
      }
    } catch (_) { /* actor lookup is non-fatal */ }
  }

  // IOC → MITRE Techniques
  const techniques = await mapToMITRE(ioc);
  for (const tech of techniques) {
    relationships.push({
      tenant_id:    tenantId,
      source_type:  'ioc',
      source_id:    iocId,
      source_value: ioc.value,
      target_type:  'technique',
      target_id:    tech.technique_id,
      target_value: tech.name,
      relationship: 'uses',
      confidence:   60,
      source:       'auto',
    });
  }

  if (relationships.length === 0) return 0;

  // FIX-3: NO .catch() on Builder — use try/catch
  try {
    await supabase
      .from('ioc_relationships')
      .upsert(relationships, {
        onConflict:       'tenant_id,source_type,source_id,target_type,target_id,relationship',
        ignoreDuplicates: true,
      });
  } catch (err) {
    console.warn('[Intelligence] Relationship upsert error:', err.message);
  }

  return relationships.length;
}

// ══════════════════════════════════════════════
//  5. CROSS-FEED CORRELATION
// ══════════════════════════════════════════════
async function correlateIOC(tenantId, iocValue) {
  const { data: ioc } = await supabase
    .from('iocs')
    .select('id, value, type, risk_score, enrichment_data, source, tags, threat_actor, last_seen')
    .eq('tenant_id', tenantId)
    .eq('value', iocValue.toLowerCase())
    .single();

  if (!ioc) return { found: false };

  const { data: rels } = await supabase
    .from('ioc_relationships')
    .select('*')
    .eq('tenant_id', tenantId)
    .or(`source_id.eq.${ioc.id},target_id.eq.${ioc.id}`)
    .limit(20);

  const { data: alerts } = await supabase
    .from('alerts')
    .select('id, title, severity, status, created_at')
    .eq('tenant_id', tenantId)
    .eq('ioc_value', iocValue)
    .order('created_at', { ascending: false })
    .limit(5);

  const { data: cases } = await supabase
    .from('cases')
    .select('id, title, severity, status')
    .eq('tenant_id', tenantId)
    .contains('tags', [iocValue.slice(0, 30)])
    .limit(3);

  const techniques = await mapToMITRE(ioc);

  return {
    found:        true,
    ioc,
    relationships: rels || [],
    alerts:       alerts || [],
    cases:        cases  || [],
    techniques,
    correlation_summary: {
      relationship_count: (rels    || []).length,
      alert_count:        (alerts  || []).length,
      case_count:         (cases   || []).length,
      technique_count:    techniques.length,
      risk_score:         ioc.risk_score,
    }
  };
}

// ══════════════════════════════════════════════
//  6. AUTO-ENRICH IOC (full pipeline, by iocId)
//     FIX-1: calls external APIs directly —
//     no HTTP round-trip → no 401 errors
// ══════════════════════════════════════════════
async function autoEnrichIOC(tenantId, iocId) {
  const { data: ioc } = await supabase
    .from('iocs')
    .select('*')
    .eq('id', iocId)
    .single();

  if (!ioc) return { error: 'IOC not found' };

  const enrichment = {};

  // Run all configured sources in parallel (direct API calls)
  await Promise.allSettled([
    enrichWithVirusTotal(ioc.value, ioc.type)
      .then(r => { if (r) enrichment.VirusTotal = r; }),

    (ioc.type === 'ip'
      ? enrichWithAbuseIPDB(ioc.value)
      : Promise.resolve(null))
      .then(r => { if (r) enrichment.AbuseIPDB = r; }),

    (ioc.type === 'ip'
      ? enrichWithShodan(ioc.value)
      : Promise.resolve(null))
      .then(r => { if (r) enrichment.Shodan = r; }),

    enrichWithOTX(ioc.value, ioc.type)
      .then(r => { if (r) enrichment['AlienVault OTX'] = r; }),
  ]);

  const scored   = calculateRiskScore(enrichment, ioc);
  const newScore = typeof scored === 'object' ? scored.score : scored;
  const reputation = newScore >= 70 ? 'malicious' : newScore >= 30 ? 'suspicious' : 'clean';

  const techniques = await mapToMITRE(ioc);

  // Update IOC record
  const { data: updated } = await supabase
    .from('iocs')
    .update({
      risk_score:      newScore,
      reputation,
      enrichment_data: { ...ioc.enrichment_data, ...enrichment, scoring: scored?.breakdown },
      enriched_at:     new Date().toISOString(),
      last_seen:       new Date().toISOString(),
    })
    .eq('id', iocId)
    .select()
    .single();

  // Build graph relationships
  await buildRelationships(tenantId, { ...ioc, ...updated }, enrichment);

  // Timeline event — FIX-4: use try/catch, not .catch() on Builder
  try {
    await supabase.from('detection_timeline').insert({
      tenant_id:    tenantId,
      event_type:   'ioc_enriched',
      title:        `IOC enriched: ${ioc.value}`,
      description:  `Risk score updated to ${newScore}. MITRE: ${techniques.map(t => t.technique_id).join(', ') || 'none'}`,
      severity:     newScore >= 80 ? 'HIGH' : newScore >= 50 ? 'MEDIUM' : 'LOW',
      entity_type:  'ioc',
      entity_id:    iocId,
      entity_value: ioc.value,
      source:       'auto-enrichment',
      metadata:     { risk_score: newScore, techniques: techniques.map(t => t.technique_id) },
    });
  } catch (_) { /* timeline insert is non-fatal */ }

  return {
    ioc:                  updated || ioc,
    enrichment,
    risk_score:           newScore,
    reputation,
    techniques,
    relationships_created: true,
  };
}

// ══════════════════════════════════════════════
//  7. AUTO-ENRICH BY IOC OBJECT (used by SOAR)
//     FIX-1: direct API calls — no 401 errors
// ══════════════════════════════════════════════
async function autoEnrichIOCObject(ioc) {
  if (!ioc?.value || !ioc?.type) return null;

  const enrichment = {};

  await Promise.allSettled([
    enrichWithVirusTotal(ioc.value, ioc.type)
      .then(r => { if (r) enrichment.VirusTotal = r; }),

    (ioc.type === 'ip'
      ? enrichWithAbuseIPDB(ioc.value)
      : Promise.resolve(null))
      .then(r => { if (r) enrichment.AbuseIPDB = r; }),

    (ioc.type === 'ip'
      ? enrichWithShodan(ioc.value)
      : Promise.resolve(null))
      .then(r => { if (r) enrichment.Shodan = r; }),

    enrichWithOTX(ioc.value, ioc.type)
      .then(r => { if (r) enrichment['AlienVault OTX'] = r; }),
  ]);

  return Object.keys(enrichment).length > 0 ? { enrichment } : null;
}

// ── Module exports ───────────────────────────────────────────────
module.exports = {
  // Core pipeline
  normalizeIOC,
  detectIOCType,
  calculateRiskScore,
  mapToMITRE,
  buildRelationships,
  correlateIOC,

  // Enrichment functions
  autoEnrichIOC,
  autoEnrichIOCObject,

  // Direct API helpers (used by intel routes + SOAR)
  enrichWithVirusTotal,
  enrichWithAbuseIPDB,
  enrichWithShodan,
  enrichWithOTX,
};
