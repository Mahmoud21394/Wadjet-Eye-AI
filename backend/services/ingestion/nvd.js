/**
 * ══════════════════════════════════════════════════════════
 *  NVD / CISA KEV Ingestion Service v2.0
 *  backend/services/ingestion/nvd.js
 *
 *  Exported functions:
 *    syncNVD({ days, startDate, endDate })  — Pull NVD CVE API
 *    syncCISAKEV()                          — Pull CISA KEV JSON
 *    syncExploitDB()                        — Pull Exploit-DB CSV
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios = require('axios');
const { supabase } = require('../../config/supabase');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT || '00000000-0000-0000-0000-000000000001';

/* ════════════════════════════════════════════
   NVD CVE API v2.0 — Sync vulnerabilities
═════════════════════════════════════════════ */
async function syncNVD({ days = 7, startDate, endDate } = {}) {
  const NVD_KEY = process.env.NVD_API_KEY;
  const t0      = Date.now();

  const lastMod = startDate
    ? new Date(startDate)
    : new Date(Date.now() - days * 86400000);
  const pubEnd = endDate ? new Date(endDate) : new Date();

  console.info(`[NVD] Syncing CVEs from ${lastMod.toISOString()} to ${pubEnd.toISOString()}`);

  const headers = {};
  if (NVD_KEY) headers['apiKey'] = NVD_KEY;

  let totalInserted = 0;
  let startIndex    = 0;
  const resultsPerPage = 100;
  let hasMore = true;

  while (hasMore) {
    let resp;
    try {
      resp = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
        params: {
          lastModStartDate: lastMod.toISOString().replace('Z', '+00:00'),
          lastModEndDate:   pubEnd.toISOString().replace('Z', '+00:00'),
          startIndex,
          resultsPerPage,
        },
        headers,
        timeout: 30000,
      });
    } catch (err) {
      console.error('[NVD] Request failed:', err.message);
      break;
    }

    const body  = resp.data;
    const vulns = body.vulnerabilities || [];
    totalInserted += await _upsertNVDVulns(vulns);

    const totalResults = body.totalResults || 0;
    startIndex += resultsPerPage;
    hasMore = startIndex < totalResults && vulns.length === resultsPerPage;

    if (hasMore) await _sleep(500); // NVD rate limit
  }

  console.info(`[NVD] Sync complete: ${totalInserted} CVEs upserted in ${Date.now()-t0}ms`);
  return { inserted: totalInserted, duration_ms: Date.now()-t0 };
}

async function _upsertNVDVulns(vulnList) {
  if (!vulnList?.length) return 0;

  const rows = [];
  for (const entry of vulnList) {
    const cve   = entry.cve;
    if (!cve?.id) continue;

    const cvss3 = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
    const cvss2 = cve.metrics?.cvssMetricV2?.[0];
    const score3 = parseFloat(cvss3?.cvssData?.baseScore) || null;
    const score2 = parseFloat(cvss2?.cvssData?.baseScore) || null;

    const severity = score3
      ? score3 >= 9.0 ? 'CRITICAL'
      : score3 >= 7.0 ? 'HIGH'
      : score3 >= 4.0 ? 'MEDIUM'
      : score3 > 0   ? 'LOW' : 'NONE'
      : 'UNKNOWN';

    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const refs  = (cve.references || []).slice(0, 10).map(r => r.url);
    const cwes  = (cve.weaknesses || []).flatMap(w =>
      (w.description || []).map(d => d.value).filter(v => v?.startsWith('CWE-'))
    );
    const products = (cve.configurations || []).flatMap(cfg =>
      (cfg.nodes || []).flatMap(n =>
        (n.cpeMatch || []).slice(0, 5).map(m => ({ cpe: m.criteria }))
      )
    ).slice(0, 20);

    rows.push({
      cve_id:           cve.id,
      title:            `${cve.id}: ${description.slice(0, 200)}`,
      description,
      severity,
      cvss_v3_score:    score3,
      cvss_v2_score:    score2,
      cvss_vector:      cvss3?.cvssData?.vectorString || null,
      exploited:        false,  // Will be enriched by CISA KEV sync
      in_cisa_kev:      false,
      affected_products:products,
      references:       refs,
      cwe_ids:          [...new Set(cwes)],
      attack_vector:    cvss3?.cvssData?.attackVector || null,
      attack_complexity:cvss3?.cvssData?.attackComplexity || null,
      privileges_required: cvss3?.cvssData?.privilegesRequired || null,
      user_interaction: cvss3?.cvssData?.userInteraction || null,
      scope:            cvss3?.cvssData?.scope || null,
      published_at:     cve.published?.split('T')[0] || null,
      modified_at:      cve.lastModified?.split('T')[0] || null,
      source:           'NVD',
      raw_data:         { nvd_id: cve.id },
    });
  }

  if (!rows.length) return 0;
  let inserted = 0;

  const CHUNK = 20;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const { error } = await supabase
      .from('vulnerabilities')
      .upsert(rows.slice(i, i + CHUNK), { onConflict: 'cve_id', ignoreDuplicates: false });

    if (!error) inserted += Math.min(CHUNK, rows.length - i);
    else console.warn('[NVD] upsert warning:', error.message);

    await _sleep(50);
  }

  return inserted;
}

/* ════════════════════════════════════════════
   CISA KEV — Known Exploited Vulnerabilities
═════════════════════════════════════════════ */
async function syncCISAKEV() {
  const t0 = Date.now();
  console.info('[CISA KEV] Starting sync…');

  try {
    const resp = await axios.get(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { timeout: 30000, headers: { 'User-Agent': 'WadjetEye-AI/4.0 CTI-Collector' } }
    );

    const vulns = resp.data.vulnerabilities || [];
    console.info(`[CISA KEV] Fetched ${vulns.length} known exploited vulnerabilities`);

    // Mark KEV CVEs in our DB
    let marked = 0;
    const CHUNK = 50;

    for (let i = 0; i < vulns.length; i += CHUNK) {
      const chunk = vulns.slice(i, i + CHUNK);
      const cveIds = chunk.map(v => v.cveID).filter(Boolean);

      const updateRows = chunk
        .filter(v => v.cveID)
        .map(v => ({
          cve_id:                v.cveID,
          in_cisa_kev:           true,
          exploited:             true,
          cisa_kev_date:         v.dateAdded     || null,
          cisa_remediation_due:  v.dueDate        || null,
          // Ensure record exists (upsert with minimal data if not present)
          title:                 v.vulnerabilityName || v.cveID,
          description:           v.shortDescription  || '',
          severity:              'CRITICAL',
          cvss_v3_score:         9.0,
          source:                'CISA_KEV',
        }));

      const { error } = await supabase
        .from('vulnerabilities')
        .upsert(updateRows, { onConflict: 'cve_id', ignoreDuplicates: false });

      if (!error) marked += chunk.length;
      else console.warn('[CISA KEV] upsert warning:', error.message);

      await _sleep(100);
    }

    // Also add as IOCs (CVE type)
    const iocRows = vulns.slice(0, 500).map(v => ({
      tenant_id:   DEFAULT_TENANT,
      type:        'cve',
      value:       v.cveID?.toLowerCase(),
      reputation:  'malicious',
      risk_score:  95,
      confidence:  99,
      source:      'CISA KEV',
      feed_source: 'CISA KEV',
      tags:        ['kev', 'cisa', 'exploited', v.product?.toLowerCase()].filter(Boolean),
      notes:       `${v.vulnerabilityName} | Due: ${v.dueDate || 'N/A'}`,
      status:      'active',
      last_seen:   new Date().toISOString(),
    })).filter(r => r.value);

    if (iocRows.length > 0) {
      for (let i = 0; i < iocRows.length; i += 100) {
        await supabase.from('iocs').upsert(iocRows.slice(i, i+100), { onConflict: 'tenant_id,value', ignoreDuplicates: false });
      }
    }

    console.info(`[CISA KEV] Sync complete: ${marked} CVEs marked, ${iocRows.length} IOCs upserted in ${Date.now()-t0}ms`);
    return { marked, iocs: iocRows.length, duration_ms: Date.now()-t0 };

  } catch (err) {
    console.error('[CISA KEV] Error:', err.message);
    throw err;
  }
}

/* ════════════════════════════════════════════
   EXPLOIT-DB — Public exploit reference
═════════════════════════════════════════════ */
async function syncExploitDB() {
  const t0 = Date.now();
  console.info('[Exploit-DB] Starting sync…');

  try {
    // Exploit-DB provides a CSV of all exploits
    const resp = await axios.get(
      'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
      { timeout: 60000, headers: { 'User-Agent': 'WadjetEye-AI/4.0' } }
    );

    const lines   = resp.data.split('\n').filter(l => l.trim() && !l.startsWith('id'));
    const recent  = lines.slice(0, 500); // Most recent 500 exploits
    let   updated = 0;

    for (const line of recent) {
      const parts = line.split(',');
      const edbId = parts[0]?.trim();
      const desc  = parts[2]?.trim().replace(/^"|"$/g, '');
      const date  = parts[3]?.trim();
      const type  = parts[5]?.trim();

      if (!edbId || !desc) continue;

      // Try to find a CVE reference in the description
      const cveMatch = desc.match(/CVE-\d{4}-\d{4,}/i);
      if (cveMatch) {
        const { error } = await supabase
          .from('vulnerabilities')
          .update({ exploited: true })
          .eq('cve_id', cveMatch[0].toUpperCase());

        if (!error) updated++;
      }
    }

    console.info(`[Exploit-DB] Sync complete: ${updated} CVEs marked exploited in ${Date.now()-t0}ms`);
    return { updated, duration_ms: Date.now()-t0 };

  } catch (err) {
    console.warn('[Exploit-DB] Sync failed (non-fatal):', err.message);
    return { updated: 0, error: err.message };
  }
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

module.exports = { syncNVD, syncCISAKEV, syncExploitDB };
