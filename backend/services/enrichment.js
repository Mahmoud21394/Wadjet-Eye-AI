/**
 * ══════════════════════════════════════════════════════════
 *  IOC Enrichment Service  (v3.1 — fixed)
 *
 *  FIX: Replaced HTTP self-calls to localhost/api/intel/*
 *       with direct helper calls from services/intelligence.
 *       This removes the 401 Unauthorized errors that occurred
 *       because the HTTP routes require a JWT token.
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabaseIngestion: supabase } = require('../config/supabase');
// v7.0: Use supabaseIngestion — isolated from auth clients
const {
  enrichWithVirusTotal,
  enrichWithAbuseIPDB,
  enrichWithShodan,
  enrichWithOTX,
} = require('./intelligence');

/**
 * enrichIOC — fetch enrichment from all configured sources
 * and update the IOC record in the database.
 * Uses direct API helpers — no HTTP round-trip, no JWT needed.
 */
async function enrichIOC(iocId, value, type, tenantId) {
  const enrichmentData = {};
  let aggregateScore   = 0;
  let country          = null;
  let asn              = null;

  // Run all available sources in parallel
  await Promise.allSettled([

    /* VirusTotal */
    process.env.VIRUSTOTAL_API_KEY
      ? enrichWithVirusTotal(value, type).then(data => {
          if (!data) return;
          enrichmentData.virustotal = data;
          aggregateScore = Math.max(aggregateScore, data.risk_score || 0);
          country = country || data.country || null;
          asn     = asn     || data.asn     || null;
        })
      : Promise.resolve(),

    /* AbuseIPDB (IPs only) */
    (type === 'ip' && process.env.ABUSEIPDB_API_KEY)
      ? enrichWithAbuseIPDB(value).then(data => {
          if (!data) return;
          enrichmentData.abuseipdb = data;
          aggregateScore = Math.max(aggregateScore, data.risk_score || 0);
          country = country || data.country || null;
        })
      : Promise.resolve(),

    /* Shodan (IPs only) */
    (type === 'ip' && process.env.SHODAN_API_KEY)
      ? enrichWithShodan(value).then(data => {
          if (!data) return;
          enrichmentData.shodan = data;
          if (data.vulns?.length) aggregateScore = Math.min(100, aggregateScore + data.vulns.length * 5);
          asn = asn || data.asn || null;
        })
      : Promise.resolve(),

    /* OTX */
    process.env.OTX_API_KEY
      ? enrichWithOTX(value, type).then(data => {
          if (!data) return;
          enrichmentData.otx = data;
          aggregateScore = Math.max(aggregateScore, data.risk_score || 0);
        })
      : Promise.resolve(),

  ]);

  const reputation = aggregateScore < 10 ? 'clean'
                   : aggregateScore < 50 ? 'suspicious' : 'malicious';

  // Update IOC record — no .catch() on builder (Supabase JS v2)
  try {
    await supabase
      .from('iocs')
      .update({
        risk_score:      Math.round(aggregateScore),
        reputation,
        country:         country || null,
        asn:             asn     || null,
        enrichment_data: enrichmentData,
        enriched_at:     new Date().toISOString(),
        updated_at:      new Date().toISOString(),
      })
      .eq('id', iocId)
      .eq('tenant_id', tenantId);
  } catch (err) {
    console.warn('[Enrichment] IOC update error:', err.message);
  }

  return { risk_score: aggregateScore, reputation, country, asn, enrichment_data: enrichmentData };
}

module.exports = { enrichIOC };
