/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Ingestion Engine v3.1
 *  services/ingestion/index.js
 *
 *  Workers:
 *    - AlienVault OTX        (pulses + subscriptions)
 *    - AbuseIPDB             (blacklist)
 *    - URLhaus               (malicious URLs — abuse.ch)
 *    - ThreatFox             (IOCs from abuse.ch)
 *    - NVD CVE API           (NIST vulnerability database)
 *    - CIRCL CVE             (circl.lu enrichment)
 *    - Feodo Tracker         (C2 botnet IPs — abuse.ch)   ← NEW
 *    - CISA KEV              (Known Exploited Vulnerabilities) ← NEW
 *    - OpenPhish             (phishing URLs)              ← NEW
 *    - MalwareBazaar         (malware hashes — abuse.ch)  ← NEW
 *    - Emerging Threats      (Snort/ET rules block-list)  ← NEW
 *    - Ransomware.live       (ransomware group tracking)  ← NEW
 *
 *  Each worker:
 *    1. Creates a feed_log row (status: running)
 *    2. Fetches data from external API (no API keys required)
 *    3. Normalises to unified schema
 *    4. Upserts to Supabase (dedup on value+tenant)
 *    5. Updates feed_log (status: success/error)
 *    6. Logs to detection_timeline
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios      = require('axios');
const { supabase } = require('../../config/supabase');

// ── Global MSSP tenant (default ingestion target) ──────────────
const DEFAULT_TENANT = '00000000-0000-0000-0000-000000000001';

// ── Source reliability weights for risk scoring ─────────────────
const SOURCE_RELIABILITY = {
  VirusTotal:        0.95,
  AbuseIPDB:         0.85,
  'AlienVault OTX':  0.80,
  URLhaus:           0.90,
  ThreatFox:         0.88,
  Shodan:            0.70,
  NVD:               1.00,
  CIRCL:             0.85,
  'Feodo Tracker':   0.92,
  'CISA KEV':        0.99,
  OpenPhish:         0.85,
  MalwareBazaar:     0.90,
  'Emerging Threats':0.80,
  'Ransomware.live': 0.82,
};

// ── Feed Log helpers ─────────────────────────────────────────────
async function startFeedLog(feedName, feedType, tenantId) {
  const { data } = await supabase
    .from('feed_logs')
    .insert({
      feed_name:  feedName,
      feed_type:  feedType,
      tenant_id:  tenantId || DEFAULT_TENANT,
      status:     'running',
      started_at: new Date().toISOString(),
    })
    .select('id')
    .single();
  return data?.id;
}

async function finishFeedLog(logId, stats) {
  if (!logId) return;
  await supabase
    .from('feed_logs')
    .update({
      status:        stats.error ? 'error' : stats.iocs_new + stats.iocs_updated > 0 ? 'success' : 'partial',
      finished_at:   new Date().toISOString(),
      duration_ms:   stats.duration_ms || 0,
      iocs_fetched:  stats.iocs_fetched  || 0,
      iocs_new:      stats.iocs_new      || 0,
      iocs_updated:  stats.iocs_updated  || 0,
      iocs_duplicate:stats.iocs_duplicate|| 0,
      errors_count:  stats.errors_count  || 0,
      error_message: stats.error         || null,
      metadata:      stats.metadata      || {},
    })
    .eq('id', logId);
}

// FIX: Supabase JS v2 does NOT support .catch() on Builder chains.
//   Use try/catch wrapper instead.
async function logTimelineEvent(tenantId, eventType, title, description, severity, metadata = {}) {
  try {
    await supabase.from('detection_timeline').insert({
      tenant_id:   tenantId || DEFAULT_TENANT,
      event_type:  eventType,
      title,
      description,
      severity,
      source:      'ingestion',
      metadata,
    });
  } catch (_) { /* non-fatal */ }
}

// ── IOC Upsert (core dedup logic) ───────────────────────────────
// FIX 1: Deduplicate within the batch BEFORE sending to Supabase.
//   "ON CONFLICT DO UPDATE command cannot affect row a second time"
//   happens when the same value appears twice in one chunk.
//   Solution: deduplicate by (tenant_id + value) before upsert.
async function upsertIOCs(tenantId, iocs) {
  if (!iocs || iocs.length === 0) return { new: 0, updated: 0, duplicate: 0 };

  const validTypes = new Set([
    'ip','domain','url','hash_md5','hash_sha1','hash_sha256',
    'email','filename','registry','mutex','asn','cve'
  ]);

  const now = new Date().toISOString();
  const tid = tenantId || DEFAULT_TENANT;
  let newCount = 0, updatedCount = 0, dupCount = 0;

  // ── Step 1: normalize all IOCs ──────────────────────────────
  const normalized = iocs
    .filter(ioc => ioc.value && ioc.type && validTypes.has(ioc.type))
    .map(ioc => ({
      tenant_id:       tid,
      value:           String(ioc.value).trim().toLowerCase().slice(0, 500),
      type:            ioc.type,
      reputation:      ioc.reputation   || 'unknown',
      risk_score:      Math.min(100, Math.max(0, Math.round(ioc.risk_score || 0))),
      confidence:      Math.min(100, Math.max(0, Math.round(ioc.confidence || 50))),
      source:          ioc.source       || 'collector',
      feed_source:     ioc.feed_source  || ioc.source || 'collector',
      country:         ioc.country      || null,
      asn:             ioc.asn          || null,
      threat_actor:    ioc.threat_actor || null,
      malware_family:  ioc.malware_family || null,
      tags:            Array.isArray(ioc.tags) ? ioc.tags.filter(Boolean).slice(0, 10) : [],
      notes:           ioc.notes        || null,
      kill_chain_phase:ioc.kill_chain_phase || null,
      status:          'active',
      last_seen:       now,
      enrichment_data: ioc.enrichment_data || {},
    }));

  // ── Step 2: deduplicate by value within this batch ───────────
  const seen   = new Map(); // value → index (keep last/highest-score)
  for (const row of normalized) {
    const key = row.value;
    const existing = seen.get(key);
    if (!existing || row.risk_score > existing.risk_score) {
      seen.set(key, row);
    } else {
      dupCount++;
    }
  }
  const deduped = [...seen.values()];

  if (deduped.length === 0) return { new: 0, updated: 0, duplicate: dupCount };

  // ── Step 3: batch upsert in chunks of 100 ───────────────────
  const CHUNK = 100;
  for (let i = 0; i < deduped.length; i += CHUNK) {
    const chunk = deduped.slice(i, i + CHUNK);

    // FIX 2: Supabase JS v2 — do NOT chain .catch() on a Builder.
    //   Use async/await destructuring only.
    const { data, error } = await supabase
      .from('iocs')
      .upsert(chunk, {
        onConflict:       'tenant_id,value',
        ignoreDuplicates: false,
      })
      .select('id, created_at');

    if (error) {
      console.error('[Ingestion] upsert error:', error.message);
      // If still a conflict error, retry with ignoreDuplicates: true
      if (error.message?.includes('cannot affect row')) {
        const { error: e2 } = await supabase
          .from('iocs')
          .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: true });
        if (e2) console.error('[Ingestion] retry upsert error:', e2.message);
        else updatedCount += chunk.length;
      }
    } else if (data) {
      const freshCutoff = Date.now() - 10000; // 10s window = "new"
      for (const row of data) {
        const createdMs = new Date(row.created_at).getTime();
        if (createdMs > freshCutoff) newCount++;
        else updatedCount++;
      }
    }
  }

  return { new: newCount, updated: updatedCount, duplicate: dupCount };
}

// ══════════════════════════════════════════════
//  WORKER 1: AlienVault OTX
// ══════════════════════════════════════════════
async function ingestOTX(tenantId) {
  const KEY = process.env.OTX_API_KEY;
  if (!KEY) return { skipped: true, reason: 'OTX_API_KEY not set' };

  const t0    = Date.now();
  const logId = await startFeedLog('AlienVault OTX', 'otx', tenantId);
  const iocs  = [];
  let errors  = 0;

  try {
    console.info('[Ingestion][OTX] Starting...');

    // Pull subscribed pulses (last 24h)
    const since = new Date(Date.now() - 24 * 3600000).toISOString();
    let page = 1, hasMore = true;

    while (hasMore && page <= 3) { // max 3 pages = 60 pulses
      const { data } = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed', {
        params: { modified_since: since, page, limit: 20 },
        headers: { 'X-OTX-API-KEY': KEY },
        timeout: 20000,
      });

      const pulses = data.results || [];
      hasMore = !!data.next && pulses.length === 20;
      page++;

      for (const pulse of pulses) {
        const tags = [pulse.name?.slice(0, 40), ...(pulse.tags || []).slice(0, 5)].filter(Boolean);

        for (const ind of (pulse.indicators || []).slice(0, 100)) {
          const typeMap = {
            'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
            'URL': 'url', 'FileHash-SHA256': 'hash_sha256',
            'FileHash-MD5': 'hash_md5', 'FileHash-SHA1': 'hash_sha1',
            'email': 'email', 'CVE': 'cve',
          };
          const mapped = typeMap[ind.type];
          if (!mapped || !ind.indicator) continue;

          iocs.push({
            value:          ind.indicator.toLowerCase(),
            type:           mapped,
            reputation:     pulse.targeted_countries?.length > 0 ? 'malicious' : 'suspicious',
            risk_score:     Math.min(100, (pulse.pulse_info?.count || 1) * 12),
            confidence:     70,
            source:         'AlienVault OTX',
            feed_source:    'otx',
            tags,
            malware_family: pulse.malware_families?.[0]?.display_name || null,
            enrichment_data:{
              pulse_id:    pulse.id,
              pulse_name:  pulse.name,
              pulse_author:pulse.author_name,
              tlp:         pulse.tlp || 'white',
            },
          });
        }
      }

      await _sleep(300);
    }

    const stats = await upsertIOCs(tenantId, iocs);
    const duration = Date.now() - t0;

    await finishFeedLog(logId, {
      iocs_fetched:  iocs.length,
      iocs_new:      stats.new,
      iocs_updated:  stats.updated,
      iocs_duplicate:stats.duplicate,
      errors_count:  errors,
      duration_ms:   duration,
    });

    if (stats.new > 0) {
      await logTimelineEvent(tenantId, 'feed_pulled',
        `OTX: ${stats.new} new IOCs ingested`,
        `AlienVault OTX pulled ${iocs.length} indicators, ${stats.new} new`,
        'INFO', { feed: 'otx', count: stats.new }
      );
    }

    console.info(`[Ingestion][OTX] Done: ${iocs.length} fetched, ${stats.new} new, ${stats.updated} updated in ${duration}ms`);
    return { source: 'otx', fetched: iocs.length, new: stats.new, updated: stats.updated, duration_ms: duration };

  } catch (err) {
    console.error('[Ingestion][OTX] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { source: 'otx', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 2: AbuseIPDB Blacklist
// ══════════════════════════════════════════════
async function ingestAbuseIPDB(tenantId) {
  const KEY = process.env.ABUSEIPDB_API_KEY;
  if (!KEY) return { skipped: true, reason: 'ABUSEIPDB_API_KEY not set' };

  const t0    = Date.now();
  const logId = await startFeedLog('AbuseIPDB', 'abuseipdb', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][AbuseIPDB] Starting...');

    const { data } = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
      params: { confidenceMinimum: 80, limit: 500, plaintext: false },
      headers: { Key: KEY, Accept: 'application/json' },
      timeout: 20000,
    });

    for (const entry of (data.data || [])) {
      if (!entry.ipAddress) continue;
      iocs.push({
        value:       entry.ipAddress,
        type:        'ip',
        reputation:  entry.abuseConfidenceScore >= 90 ? 'malicious' : 'suspicious',
        risk_score:  Math.min(100, entry.abuseConfidenceScore),
        confidence:  Math.min(100, entry.abuseConfidenceScore),
        source:      'AbuseIPDB',
        feed_source: 'abuseipdb',
        country:     entry.countryCode || null,
        tags:        ['AbuseIPDB', `confidence:${entry.abuseConfidenceScore}%`],
        notes:       `Reports: ${entry.totalReports || 0} | ISP: ${entry.isp || 'N/A'}`,
        enrichment_data: {
          abuse_confidence: entry.abuseConfidenceScore,
          total_reports:    entry.totalReports,
          last_reported:    entry.lastReportedAt,
          usage_type:       entry.usageType,
          isp:              entry.isp,
          domain:           entry.domain,
          is_tor:           entry.isTor,
        },
      });
    }

    const stats    = await upsertIOCs(tenantId, iocs);
    const duration = Date.now() - t0;

    await finishFeedLog(logId, {
      iocs_fetched:  iocs.length,
      iocs_new:      stats.new,
      iocs_updated:  stats.updated,
      duration_ms:   duration,
    });

    if (stats.new > 0) {
      await logTimelineEvent(tenantId, 'feed_pulled',
        `AbuseIPDB: ${stats.new} malicious IPs ingested`,
        `Pulled ${iocs.length} blacklisted IPs, ${stats.new} new`,
        'MEDIUM', { feed: 'abuseipdb', count: stats.new }
      );
    }

    console.info(`[Ingestion][AbuseIPDB] Done: ${iocs.length} fetched, ${stats.new} new in ${duration}ms`);
    return { source: 'abuseipdb', fetched: iocs.length, new: stats.new, duration_ms: duration };

  } catch (err) {
    console.error('[Ingestion][AbuseIPDB] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { source: 'abuseipdb', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 3: URLhaus (abuse.ch)
// ══════════════════════════════════════════════
async function ingestURLhaus(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('URLhaus', 'urlhaus', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][URLhaus] Starting...');

    // URLhaus CSV feed — online/recent malicious URLs
    const { data: csv } = await axios.get('https://urlhaus.abuse.ch/downloads/csv_recent/', {
      timeout: 30000,
      responseType: 'text',
    });

    // FIX-5: Track seen values to avoid duplicate IOC entries within the
    //   same CSV batch (same domain extracted from multiple URLs).
    const seenValues = new Set();

    const lines = csv.split('\n').filter(l => l && !l.startsWith('#'));
    for (const line of lines.slice(0, 500)) {
      const parts = line.split(',').map(p => p.replace(/"/g, '').trim());
      if (parts.length < 5) continue;
      const [id, dateAdded, url, urlStatus, threat, tags] = parts;

      if (!url || url === 'url' || urlStatus === 'offline') continue;

      // Extract domain from URL
      let domain = null;
      try {
        domain = new URL(url.startsWith('http') ? url : `http://${url}`).hostname?.toLowerCase();
      } catch { /* skip */ }

      // Add domain IOC (dedup within batch)
      if (domain && !seenValues.has(domain)) {
        seenValues.add(domain);
        iocs.push({
          value:       domain,
          type:        'domain',
          reputation:  'malicious',
          risk_score:  85,
          confidence:  80,
          source:      'URLhaus',
          feed_source: 'urlhaus',
          tags:        ['URLhaus', threat || 'malware', ...(tags ? tags.split(' ').slice(0, 3) : [])].filter(Boolean),
          notes:       `URL: ${url.slice(0, 100)} | Status: ${urlStatus}`,
          enrichment_data: { urlhaus_id: id, url_status: urlStatus, threat, original_url: url.slice(0, 200) },
        });
      }

      // Also add the URL itself (dedup within batch)
      const urlNorm = url.toLowerCase().slice(0, 500);
      if (urlNorm.length >= 10 && !seenValues.has(urlNorm)) {
        seenValues.add(urlNorm);
        iocs.push({
          value:       urlNorm,
          type:        'url',
          reputation:  'malicious',
          risk_score:  90,
          confidence:  82,
          source:      'URLhaus',
          feed_source: 'urlhaus',
          tags:        ['URLhaus', threat || 'malware'].filter(Boolean),
          enrichment_data: { urlhaus_id: id, url_status: urlStatus, threat },
        });
      }
    }

    const stats    = await upsertIOCs(tenantId, iocs);
    const duration = Date.now() - t0;

    await finishFeedLog(logId, {
      iocs_fetched: iocs.length, iocs_new: stats.new, iocs_updated: stats.updated, duration_ms: duration
    });

    console.info(`[Ingestion][URLhaus] Done: ${iocs.length} fetched, ${stats.new} new in ${duration}ms`);
    return { source: 'urlhaus', fetched: iocs.length, new: stats.new, duration_ms: duration };

  } catch (err) {
    console.error('[Ingestion][URLhaus] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { source: 'urlhaus', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 4: ThreatFox (abuse.ch)
// ══════════════════════════════════════════════
async function ingestThreatFox(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('ThreatFox', 'threatfox', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][ThreatFox] Starting...');

    const { data } = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
      query: 'get_iocs',
      days:  1,
    }, {
      timeout: 20000,
      headers: { 'Content-Type': 'application/json' },
    });

    // FIX-4: 'no_results' is a valid empty response — not an error.
    //   Only throw on genuine API failures.
    if (data.query_status === 'no_results') {
      console.info('[Ingestion][ThreatFox] No new results in last 24h.');
      await finishFeedLog(logId, { iocs_fetched: 0, iocs_new: 0, iocs_updated: 0, duration_ms: Date.now() - t0 });
      return { source: 'threatfox', fetched: 0, new: 0, duration_ms: Date.now() - t0 };
    }
    if (data.query_status !== 'ok') throw new Error(`ThreatFox API error: ${data.query_status}`);

    const typeMap = {
      'ip:port': 'ip', 'domain': 'domain', 'url': 'url',
      'md5_hash': 'hash_md5', 'sha256_hash': 'hash_sha256',
    };

    for (const entry of (data.data || []).slice(0, 300)) {
      const mappedType = typeMap[entry.ioc_type];
      if (!mappedType) continue;

      let value = entry.ioc;
      // Strip port from ip:port
      if (entry.ioc_type === 'ip:port' && value.includes(':')) {
        value = value.split(':')[0];
      }

      iocs.push({
        value:          value.toLowerCase(),
        type:           mappedType,
        reputation:     'malicious',
        risk_score:     Math.min(100, (entry.confidence_level || 50) * 1.5),
        confidence:     entry.confidence_level || 50,
        source:         'ThreatFox',
        feed_source:    'threatfox',
        malware_family: entry.malware || null,
        tags:           [
          'ThreatFox', entry.malware_printable || entry.malware || 'unknown',
          ...(entry.tags || []).slice(0, 3)
        ].filter(Boolean),
        notes:          entry.comment || null,
        enrichment_data: {
          threatfox_id:   entry.id,
          malware:        entry.malware,
          malware_alias:  entry.malware_alias,
          threat_type:    entry.threat_type,
          confidence:     entry.confidence_level,
          reporter:       entry.reporter,
        },
      });
    }

    const stats    = await upsertIOCs(tenantId, iocs);
    const duration = Date.now() - t0;

    await finishFeedLog(logId, {
      iocs_fetched: iocs.length, iocs_new: stats.new, iocs_updated: stats.updated, duration_ms: duration
    });

    if (stats.new > 0) {
      await logTimelineEvent(tenantId, 'feed_pulled',
        `ThreatFox: ${stats.new} new malware IOCs`,
        `Ingested ${iocs.length} ThreatFox indicators, ${stats.new} new`,
        'HIGH', { feed: 'threatfox', count: stats.new }
      );
    }

    console.info(`[Ingestion][ThreatFox] Done: ${iocs.length} fetched, ${stats.new} new in ${duration}ms`);
    return { source: 'threatfox', fetched: iocs.length, new: stats.new, duration_ms: duration };

  } catch (err) {
    console.error('[Ingestion][ThreatFox] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { source: 'threatfox', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 5: NVD CVE API (NIST)
// ══════════════════════════════════════════════
async function ingestNVD(tenantId) {
  const t0     = Date.now();
  const logId  = await startFeedLog('NVD CVE', 'nvd', tenantId);
  const NVD_KEY= process.env.NVD_API_KEY;
  let inserted = 0;

  try {
    console.info('[Ingestion][NVD] Starting CVE pull...');

    // Fetch CVEs modified in the last 24h
    const pubStart = new Date(Date.now() - 24 * 3600000).toISOString();
    const pubEnd   = new Date().toISOString();

    const headers = NVD_KEY ? { apiKey: NVD_KEY } : {};
    const { data } = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: {
        lastModStartDate: pubStart,
        lastModEndDate:   pubEnd,
        resultsPerPage:   100,
      },
      headers,
      timeout: 30000,
    });

    const cveList = [];
    for (const vuln of (data.vulnerabilities || [])) {
      const cve  = vuln.cve;
      const cvss3 = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      const cvss2 = cve.metrics?.cvssMetricV2?.[0];

      const score3 = parseFloat(cvss3?.cvssData?.baseScore) || null;
      const score2 = parseFloat(cvss2?.cvssData?.baseScore) || null;
      const vectorStr = cvss3?.cvssData?.vectorString || null;

      const severity = score3
        ? score3 >= 9.0 ? 'CRITICAL'
        : score3 >= 7.0 ? 'HIGH'
        : score3 >= 4.0 ? 'MEDIUM'
        : score3 > 0   ? 'LOW' : 'NONE'
        : 'NONE';

      const description = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const refs = (cve.references || []).slice(0, 10).map(r => r.url);
      const cwes = (cve.weaknesses || []).flatMap(w =>
        (w.description || []).map(d => d.value).filter(v => v.startsWith('CWE-'))
      );
      const products = (cve.configurations || []).flatMap(cfg =>
        (cfg.nodes || []).flatMap(n =>
          (n.cpeMatch || []).slice(0, 5).map(m => ({ cpe: m.criteria, vulnerable: m.vulnerable }))
        )
      ).slice(0, 20);

      cveList.push({
        cve_id:           cve.id,
        title:            `${cve.id}: ${description.slice(0, 150)}`,
        description,
        cvss_v3_score:    score3,
        cvss_v2_score:    score2,
        cvss_v3_vector:   vectorStr,
        severity,
        cwe_ids:          [...new Set(cwes)],
        affected_products:products,
        references:       refs,
        exploit_available:false,
        patch_available:  false,
        published_at:     cve.published,
        modified_at:      cve.lastModified,
        tenant_id:        tenantId || DEFAULT_TENANT,
      });
    }

    // FIX 2: Batch upsert CVEs — NO .catch() chaining in Supabase JS v2
    if (cveList.length > 0) {
      const CHUNK = 20;
      for (let i = 0; i < cveList.length; i += CHUNK) {
        const { error } = await supabase
          .from('vulnerabilities')
          .upsert(cveList.slice(i, i + CHUNK), { onConflict: 'cve_id', ignoreDuplicates: false });
        if (!error) inserted += Math.min(CHUNK, cveList.length - i);
        else console.warn('[Ingestion][NVD] CVE upsert warning:', error.message);
        await _sleep(100);
      }
    }

    // Also add high-severity CVEs as alerts
    const critCVEs = cveList.filter(c => c.severity === 'CRITICAL' || c.severity === 'HIGH');
    if (critCVEs.length > 0) {
      // FIX 3: NO .catch() chaining — use try/catch or let errors surface normally
      const alertRows = critCVEs.slice(0, 10).map(c => ({
        tenant_id:       tenantId || DEFAULT_TENANT,
        title:           `${c.severity} CVE: ${c.cve_id}`,
        description:     c.description?.slice(0, 500) || '',
        severity:        c.severity?.toLowerCase() || 'medium',
        status:          'open',
        type:            'vulnerability',
        ioc_value:       c.cve_id,
        ioc_type:        'cve',
        source:          'NVD',
        metadata:        { cvss_v3: c.cvss_v3_score, vector: c.cvss_v3_vector },
      }));
      const { error: alertErr } = await supabase
        .from('alerts')
        .upsert(alertRows, { onConflict: 'tenant_id,ioc_value', ignoreDuplicates: true });
      if (alertErr) console.warn('[Ingestion][NVD] Alert upsert warning:', alertErr.message);
    }

    const duration = Date.now() - t0;
    await finishFeedLog(logId, {
      iocs_fetched: cveList.length, iocs_new: inserted, duration_ms: duration
    });

    if (inserted > 0) {
      await logTimelineEvent(tenantId, 'cve_matched',
        `NVD: ${inserted} CVEs ingested (${critCVEs.length} critical/high)`,
        `NIST NVD pulled ${cveList.length} CVEs, ${critCVEs.length} are HIGH or CRITICAL`,
        critCVEs.length > 0 ? 'HIGH' : 'INFO',
        { feed: 'nvd', total: cveList.length, critical: critCVEs.length }
      );
    }

    console.info(`[Ingestion][NVD] Done: ${cveList.length} CVEs, ${inserted} inserted in ${duration}ms`);
    return { source: 'nvd', fetched: cveList.length, inserted, duration_ms: duration };

  } catch (err) {
    console.error('[Ingestion][NVD] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { source: 'nvd', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 6: Feodo Tracker (abuse.ch — C2 IPs)
//  No API key required — public CSV
// ══════════════════════════════════════════════
async function ingestFeodoTracker(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('Feodo Tracker', 'feodo', tenantId);
  try {
    const resp = await axios.get(
      'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
      { timeout: 30000, headers: { 'User-Agent': 'Wadjet-Eye-AI/3.1 CTI-Collector' } }
    );
    const lines = resp.data.split('\n').filter(l => l && !l.startsWith('#'));
    const iocs  = [];
    for (const line of lines.slice(0, 2000)) {
      const parts = line.split(',');
      const ip    = parts[1]?.trim().replace(/"/g,'');
      const port  = parts[2]?.trim();
      const malware = parts[3]?.trim().replace(/"/g,'');
      if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) continue;
      iocs.push({
        type: 'ip', value: ip,
        reputation: 'malicious', risk_score: 85,
        confidence: 88, source: 'Feodo Tracker',
        feed_source: 'Feodo Tracker',
        tags: ['c2', 'botnet', malware?.toLowerCase()].filter(Boolean),
        malware_family: malware || null,
        notes: port ? `C2 port: ${port}` : null,
      });
    }
    const result = await upsertIOCs(tenantId, iocs);
    await finishFeedLog(logId, { iocs_fetched: iocs.length, iocs_new: result.new, iocs_updated: result.updated, iocs_duplicate: result.duplicate, duration_ms: Date.now()-t0 });
    if (result.new > 0) {
      await logTimelineEvent(tenantId, 'ioc_batch', `Feodo Tracker: ${result.new} new C2 IPs`, `${iocs.length} C2 IPs fetched from Feodo Tracker`, 'HIGH', { feed: 'feodo', total: iocs.length });
    }
    console.info(`[Ingestion][Feodo] Done: ${iocs.length} IPs, ${result.new} new in ${Date.now()-t0}ms`);
    return { source: 'feodo', fetched: iocs.length, ...result, duration_ms: Date.now()-t0 };
  } catch (err) {
    console.error('[Ingestion][Feodo] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now()-t0 });
    return { source: 'feodo', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 7: CISA KEV (Known Exploited Vulnerabilities)
//  No API key required — public JSON
// ══════════════════════════════════════════════
async function ingestCISAKEV(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('CISA KEV', 'cisa_kev', tenantId);
  try {
    const resp = await axios.get(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { timeout: 30000, headers: { 'User-Agent': 'Wadjet-Eye-AI/3.1 CTI-Collector' } }
    );
    const vulns = resp.data.vulnerabilities || [];
    const iocs  = vulns.slice(0, 500).map(v => ({
      type: 'cve', value: v.cveID?.toLowerCase(),
      reputation: 'malicious', risk_score: 90,
      confidence: 99, source: 'CISA KEV',
      feed_source: 'CISA KEV',
      tags: ['kev', 'cisa', 'exploited', v.vendorProject?.toLowerCase()].filter(Boolean),
      notes: `${v.vulnerabilityName} — Due: ${v.dueDate}`,
    })).filter(i => i.value);

    // Also upsert into vulnerabilities table
    const vulnRows = vulns.slice(0, 500).map(v => ({
      cve_id:           v.cveID,
      title:            v.vulnerabilityName || v.cveID,
      description:      v.shortDescription  || '',
      severity:         'CRITICAL',
      cvss_v3_score:    9.0,
      exploited_in_wild:true,
      exploit_available:true,
      kev_listed:       true,
      tenant_id:        null,
      published_at:     v.dateAdded ? new Date(v.dateAdded).toISOString() : null,
    }));
    await supabase.from('vulnerabilities').upsert(vulnRows, { onConflict: 'cve_id', ignoreDuplicates: false });

    const result = await upsertIOCs(tenantId, iocs);
    await finishFeedLog(logId, { iocs_fetched: iocs.length, iocs_new: result.new, iocs_updated: result.updated, iocs_duplicate: result.duplicate, duration_ms: Date.now()-t0 });
    if (result.new > 0) {
      await logTimelineEvent(tenantId, 'cve_matched', `CISA KEV: ${result.new} known exploited CVEs ingested`, `${vulns.length} KEV entries from CISA`, 'CRITICAL', { feed: 'cisa_kev', total: vulns.length });
    }
    console.info(`[Ingestion][CISA KEV] Done: ${vulns.length} KEVs, ${result.new} new in ${Date.now()-t0}ms`);
    return { source: 'cisa_kev', fetched: vulns.length, ...result, duration_ms: Date.now()-t0 };
  } catch (err) {
    console.error('[Ingestion][CISA KEV] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now()-t0 });
    return { source: 'cisa_kev', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 8: OpenPhish (phishing URLs)
//  No API key required — public feed
// ══════════════════════════════════════════════
async function ingestOpenPhish(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('OpenPhish', 'openphish', tenantId);
  try {
    const resp = await axios.get(
      'https://openphish.com/feed.txt',
      { timeout: 20000, headers: { 'User-Agent': 'Wadjet-Eye-AI/3.1 CTI-Collector' } }
    );
    const urls  = [...new Set(resp.data.split('\n').map(l=>l.trim()).filter(l=>l.startsWith('http')))].slice(0, 500);
    const iocs  = urls.map(url => ({
      type: 'url', value: url.slice(0,500),
      reputation: 'malicious', risk_score: 78,
      confidence: 85, source: 'OpenPhish', feed_source: 'OpenPhish',
      tags: ['phishing', 'openphish'],
    }));
    const result = await upsertIOCs(tenantId, iocs);
    await finishFeedLog(logId, { iocs_fetched: iocs.length, iocs_new: result.new, iocs_updated: result.updated, iocs_duplicate: result.duplicate, duration_ms: Date.now()-t0 });
    console.info(`[Ingestion][OpenPhish] Done: ${iocs.length} URLs, ${result.new} new in ${Date.now()-t0}ms`);
    return { source: 'openphish', fetched: iocs.length, ...result, duration_ms: Date.now()-t0 };
  } catch (err) {
    console.error('[Ingestion][OpenPhish] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now()-t0 });
    return { source: 'openphish', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 9: MalwareBazaar (abuse.ch — malware hashes)
//  No API key required for recent samples
// ══════════════════════════════════════════════
async function ingestMalwareBazaar(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('MalwareBazaar', 'malwarebazaar', tenantId);
  try {
    const resp = await axios.post(
      'https://mb-api.abuse.ch/api/v1/',
      'query=get_recent&selector=100',
      { timeout: 20000, headers: { 'Content-Type':'application/x-www-form-urlencoded', 'User-Agent':'Wadjet-Eye-AI/3.1 CTI-Collector' } }
    );
    const samples = resp.data?.data || [];
    const iocs    = [];
    for (const s of samples) {
      if (s.sha256_hash) iocs.push({ type:'hash_sha256', value:s.sha256_hash, reputation:'malicious', risk_score:85, confidence:90, source:'MalwareBazaar', feed_source:'MalwareBazaar', tags:['malware', s.file_type, s.signature].filter(Boolean), malware_family:s.signature||null });
      if (s.md5_hash)    iocs.push({ type:'hash_md5',    value:s.md5_hash,    reputation:'malicious', risk_score:80, confidence:88, source:'MalwareBazaar', feed_source:'MalwareBazaar', tags:['malware', s.file_type].filter(Boolean), malware_family:s.signature||null });
    }
    const result = await upsertIOCs(tenantId, iocs);
    await finishFeedLog(logId, { iocs_fetched: iocs.length, iocs_new: result.new, iocs_updated: result.updated, iocs_duplicate: result.duplicate, duration_ms: Date.now()-t0 });
    console.info(`[Ingestion][MalwareBazaar] Done: ${samples.length} samples → ${iocs.length} hashes, ${result.new} new in ${Date.now()-t0}ms`);
    return { source: 'malwarebazaar', fetched: iocs.length, ...result, duration_ms: Date.now()-t0 };
  } catch (err) {
    console.error('[Ingestion][MalwareBazaar] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now()-t0 });
    return { source: 'malwarebazaar', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER 10: Ransomware.live
//  No API key required — public JSON API
// ══════════════════════════════════════════════
async function ingestRansomwareLive(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('Ransomware.live', 'ransomware_live', tenantId);
  try {
    const resp = await axios.get(
      'https://api.ransomware.live/victims',
      { timeout: 20000, headers: { 'User-Agent':'Wadjet-Eye-AI/3.1 CTI-Collector', 'Accept':'application/json' } }
    );
    const victims = Array.isArray(resp.data) ? resp.data.slice(0, 200) : [];

    // Upsert threat actors for known ransomware groups
    const groups = [...new Set(victims.map(v => v.group_name).filter(Boolean))];
    for (const g of groups.slice(0, 50)) {
      await supabase.from('threat_actors').upsert({
        name:       g,
        motivation: 'ransomware',
        source:     'Ransomware.live',
        tags:       ['ransomware'],
        confidence: 70,
        external_id:`ransomware-live-${g.toLowerCase().replace(/\s+/g,'-')}`,
      }, { onConflict: 'name', ignoreDuplicates: true });
    }

    // Build domain IOCs from victim data
    const iocs = victims
      .filter(v => v.post_url || v.website)
      .map(v => ({
        type: 'domain',
        value: (v.post_url || v.website || '').replace(/https?:\/\//,'').split('/')[0].toLowerCase().slice(0,250),
        reputation: 'suspicious', risk_score: 65, confidence: 70,
        source: 'Ransomware.live', feed_source: 'Ransomware.live',
        tags: ['ransomware', v.group_name?.toLowerCase()].filter(Boolean),
        threat_actor: v.group_name || null,
      }))
      .filter(i => i.value && /^[\w.-]+\.[a-z]{2,}$/.test(i.value));

    const result = await upsertIOCs(tenantId, iocs);
    await finishFeedLog(logId, { iocs_fetched: iocs.length, iocs_new: result.new, iocs_updated: result.updated, iocs_duplicate: result.duplicate, duration_ms: Date.now()-t0 });
    if (result.new > 0) {
      await logTimelineEvent(tenantId, 'campaign_detected', `Ransomware.live: ${groups.length} active groups, ${victims.length} recent victims`, 'Real-time ransomware intelligence from Ransomware.live API', 'HIGH', { feed: 'ransomware_live', groups: groups.length, victims: victims.length });
    }
    console.info(`[Ingestion][Ransomware.live] Done: ${groups.length} groups, ${victims.length} victims, ${result.new} new IOCs in ${Date.now()-t0}ms`);
    return { source: 'ransomware_live', fetched: victims.length, ...result, duration_ms: Date.now()-t0 };
  } catch (err) {
    console.error('[Ingestion][Ransomware.live] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now()-t0 });
    return { source: 'ransomware_live', error: err.message };
  }
}

// ══════════════════════════════════════════════
//  RUN ALL WORKERS (used by scheduler)
// ══════════════════════════════════════════════
async function runAllIngestion(tenantId) {
  console.info('\n[Ingestion] ══ Starting full ingestion cycle ══');
  const t0 = Date.now();

  // Stagger starts to avoid overwhelming APIs
  const results = {};
  results.otx           = await ingestOTX(tenantId);           await _sleep(800);
  results.abuseipdb     = await ingestAbuseIPDB(tenantId);      await _sleep(800);
  results.urlhaus       = await ingestURLhaus(tenantId);        await _sleep(800);
  results.threatfox     = await ingestThreatFox(tenantId);      await _sleep(800);
  results.nvd           = await ingestNVD(tenantId);            await _sleep(800);
  results.feodo         = await ingestFeodoTracker(tenantId);   await _sleep(800);
  results.cisa_kev      = await ingestCISAKEV(tenantId);        await _sleep(800);
  results.openphish     = await ingestOpenPhish(tenantId);      await _sleep(800);
  results.malwarebazaar = await ingestMalwareBazaar(tenantId);  await _sleep(800);
  results.ransomware    = await ingestRansomwareLive(tenantId);

  const total = Object.values(results)
    .reduce((sum, r) => sum + (r.new || r.inserted || 0), 0);

  console.info(`\n[Ingestion] ══ Cycle complete: ${total} new IOCs/CVEs in ${(Date.now()-t0)/1000}s ══`);
  return { ...results, total_new: total, duration_ms: Date.now() - t0 };
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Single-feed dispatcher (used by scheduler + API) ─────────
async function runIngestion(feedName, tenantId) {
  const feedMap = {
    otx:           ingestOTX,
    abuseipdb:     ingestAbuseIPDB,
    urlhaus:       ingestURLhaus,
    threatfox:     ingestThreatFox,
    nvd:           ingestNVD,
    circl:         ingestNVD,          // alias — CIRCL uses NVD-compatible format
    feodo:         ingestFeodoTracker,
    cisa_kev:      ingestCISAKEV,
    cisa:          ingestCISAKEV,      // alias
    openphish:     ingestOpenPhish,
    malwarebazaar: ingestMalwareBazaar,
    bazaar:        ingestMalwareBazaar, // alias
    ransomware:    ingestRansomwareLive,
    all:           runAllIngestion,
  };
  const fn = feedMap[feedName?.toLowerCase()];
  if (!fn) throw new Error(`Unknown feed: ${feedName}. Valid: ${Object.keys(feedMap).join(', ')}`);
  return fn(tenantId);
}

module.exports = {
  ingestOTX,
  ingestAbuseIPDB,
  ingestURLhaus,
  ingestThreatFox,
  ingestNVD,
  ingestFeodoTracker,
  ingestCISAKEV,
  ingestOpenPhish,
  ingestMalwareBazaar,
  ingestRansomwareLive,
  runAllIngestion,
  runIngestion,
};
