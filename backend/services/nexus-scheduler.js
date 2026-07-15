'use strict';
/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet Nexus — Background Job Scheduler (XSCHEDULE)
 *  backend/services/nexus-scheduler.js
 *
 *  Jobs:
 *    • CVE importer (NVD API, hourly incremental)
 *    • Enterprise Risk Score recomputation (every 30s)
 *    • Asset-CVE matching (post-import)
 *    • Attack Path computation (every 15min)
 *    • AOI computation (every 15min)
 *    • BAS emulation scheduled runs
 *    • TID coverage sync
 * ══════════════════════════════════════════════════════════════════════════════
 */

const logger = require('../utils/logger');
const SVC = 'NexusScheduler';

let _supabase = null;
let _timers   = [];
let _running  = false;

function getSupabase() {
  if (!_supabase) {
    try { _supabase = require('../config/supabase').getSupabase(); } catch (e) { /* supabase unavailable */ }
  }
  return _supabase;
}

// ── CVE Importer ─────────────────────────────────────────────────────────────
async function importCVEs() {
  const supabase = getSupabase();
  if (!supabase) return;

  try {
    // Fetch recent CVEs from NVD (last 24h, using public API)
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').substring(0, 19);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(since + '.000')}&resultsPerPage=100`;

    const resp = await fetch(url, {
      headers: { 'User-Agent': 'Wadjet-Nexus/1.0 CVE-Importer' },
      signal: AbortSignal.timeout(20000),
    });

    if (!resp.ok) {
      if (resp.status === 403) { logger.info(SVC, '[CVE] NVD rate limited — will retry next cycle'); return; }
      logger.warn(SVC, `[CVE] NVD API returned ${resp.status}`);
      return;
    }

    const json = await resp.json();
    const cves = json.vulnerabilities || [];

    if (cves.length === 0) { logger.info(SVC, '[CVE] No new CVEs in this window'); return; }

    // Get all tenants (CVEs are global, then matched per-tenant)
    const { data: tenants } = await supabase.from('tenants').select('id').eq('active', true);
    if (!tenants || tenants.length === 0) return;

    let imported = 0;
    const records = [];

    for (const entry of cves) {
      const cve = entry.cve;
      if (!cve) continue;

      const cveId   = cve.id;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const cvss    = metrics?.cvssData?.baseScore || null;
      const vector  = metrics?.cvssData?.vectorString || null;
      const severity = metrics?.cvssData?.baseSeverity?.toLowerCase() || (cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low');

      const cpeList = [];
      const configs = cve.configurations || [];
      configs.forEach(cfg => {
        (cfg.nodes || []).forEach(node => {
          (node.cpeMatch || []).forEach(c => { if (c.criteria) cpeList.push(c.criteria); });
        });
      });

      const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';

      for (const tenant of tenants) {
        records.push({
          tenant_id: tenant.id,
          cve_id: cveId,
          title: desc.substring(0, 200),
          description: desc,
          cvss_score: cvss,
          cvss_vector: vector,
          severity,
          cpe_affected: cpeList.slice(0, 20),
          published_at: cve.published?.substring(0, 10),
          modified_at: cve.lastModified?.substring(0, 10),
          status: 'open',
        });
      }
    }

    // Upsert in chunks
    const chunkSize = 50;
    for (let i = 0; i < records.length; i += chunkSize) {
      const chunk = records.slice(i, i + chunkSize);
      const { error } = await supabase.from('nexus_vulnerabilities')
        .upsert(chunk, { onConflict: 'tenant_id,cve_id', ignoreDuplicates: false });
      if (!error) imported += chunk.length / (tenants.length || 1);
    }

    logger.info(SVC, `[CVE] Imported ${Math.round(imported)} new/updated CVEs across ${tenants.length} tenants`);

    // Trigger asset-CVE matching
    await matchCVEsToAssets();

  } catch (e) {
    if (e.name === 'TimeoutError') { logger.info(SVC, '[CVE] NVD API timeout — will retry next cycle'); return; }
    logger.warn(SVC, `[CVE] Import error: ${e.message}`);
  }
}

// ── Asset-CVE Matching ────────────────────────────────────────────────────────
async function matchCVEsToAssets() {
  const supabase = getSupabase();
  if (!supabase) return;

  try {
    const { data: tenants } = await supabase.from('tenants').select('id').eq('active', true);
    if (!tenants) return;

    for (const tenant of tenants) {
      const [vulnRes, assetRes] = await Promise.all([
        supabase.from('nexus_vulnerabilities')
          .select('id, cpe_affected, cve_id')
          .eq('tenant_id', tenant.id)
          .order('created_at', { ascending: false })
          .limit(500),
        supabase.from('asset_inventory')
          .select('id, cpe_list, technology_tags')
          .eq('tenant_id', tenant.id),
      ]);

      const vulns  = vulnRes.data || [];
      const assets = assetRes.data || [];
      const matches = [];

      for (const vuln of vulns) {
        const vulnCpes = (vuln.cpe_affected || []);
        for (const asset of assets) {
          const assetCpes = (asset.cpe_list || []);
          const assetTags = (asset.technology_tags || []).map(t => t.toLowerCase());
          const cpeMatch  = assetCpes.some(ac => vulnCpes.some(vc => {
            const vcParts = vc.toLowerCase().split(':');
            const acParts = ac.toLowerCase().split(':');
            return vcParts[3] === acParts[3] && vcParts[4] === acParts[4];
          }));

          if (cpeMatch) {
            matches.push({ tenant_id: tenant.id, asset_id: asset.id, vulnerability_id: vuln.id, match_source: 'cpe' });
          }
        }
      }

      if (matches.length > 0) {
        const chunkSize = 100;
        for (let i = 0; i < matches.length; i += chunkSize) {
          await supabase.from('nexus_asset_vulnerabilities')
            .upsert(matches.slice(i, i + chunkSize), { onConflict: 'tenant_id,asset_id,vulnerability_id', ignoreDuplicates: true });
        }
        logger.info(SVC, `[Match] Tenant ${tenant.id}: ${matches.length} asset-CVE links created`);
      }
    }
  } catch (e) {
    logger.warn(SVC, `[Match] Asset-CVE matching error: ${e.message}`);
  }
}

// ── Risk Score Recomputation ──────────────────────────────────────────────────
async function recomputeRiskScores() {
  const supabase = getSupabase();
  if (!supabase) return;

  try {
    const { data: tenants } = await supabase.from('tenants').select('id').eq('active', true);
    if (!tenants) return;

    for (const tenant of tenants) {
      const [assetRes, vulnRes, incidentRes, ctrlRes] = await Promise.all([
        supabase.from('asset_inventory').select('internet_exposed, criticality').eq('tenant_id', tenant.id),
        supabase.from('nexus_asset_vulnerabilities')
          .select('nexus_vulnerabilities(severity, is_kev)').eq('tenant_id', tenant.id).eq('status', 'open'),
        supabase.from('cases').select('id').eq('tenant_id', tenant.id).in('status', ['open', 'investigating']),
        supabase.from('nexus_controls').select('status').eq('tenant_id', tenant.id),
      ]);

      const assets       = assetRes.data || [];
      const openVulns    = (vulnRes.data || []);
      const incidents    = (incidentRes.data || []).length;
      const controls     = ctrlRes.data || [];

      const assetHygiene  = assets.length > 0 ? Math.max(0, 100 - (assets.filter(a => a.internet_exposed).length / assets.length) * 100) : 100;
      const critVulns     = openVulns.filter(v => v.nexus_vulnerabilities?.severity === 'critical').length;
      const kevVulns      = openVulns.filter(v => v.nexus_vulnerabilities?.is_kev).length;
      const openRisk      = Math.min(100, critVulns * 5 + kevVulns * 10);
      const incidentScore = Math.min(100, incidents * 8);
      const complianceDebt = controls.length > 0 ? Math.max(0, 100 - (controls.filter(c => c.status === 'implemented').length / controls.length * 100)) : 0;

      const enterpriseRiskScore = Math.round(
        (assetHygiene * 0.2) + (openRisk * 0.35) + (incidentScore * 0.2) + (complianceDebt * 0.15) + 10
      );

      await supabase.from('nexus_risk_scores').insert({
        tenant_id: tenant.id,
        enterprise_risk_score: enterpriseRiskScore,
        asset_hygiene_score: assetHygiene,
        open_risk_score: openRisk,
        incident_score: incidentScore,
        compliance_debt: complianceDebt,
        contributors: { assetHygiene, openRisk, incidentScore, complianceDebt },
        computed_at: new Date().toISOString(),
      });

      // Prune old scores (keep last 1000 per tenant)
      await supabase.rpc('nexus_prune_risk_scores', { p_tenant_id: tenant.id }).catch(() => {});
    }
  } catch (e) {
    logger.warn(SVC, `[RiskScore] Recomputation error: ${e.message}`);
  }
}

// ── Attack Path Computation ──────────────────────────────────────────────────
async function recomputeAttackPaths() {
  const supabase = getSupabase();
  if (!supabase) return;

  try {
    const { data: tenants } = await supabase.from('tenants').select('id').eq('active', true);
    if (!tenants) return;

    for (const tenant of tenants) {
      const { data: assets } = await supabase.from('asset_inventory')
        .select('id, internet_exposed, criticality, risk_score, business_value, subnet')
        .eq('tenant_id', tenant.id);

      if (!assets || assets.length < 2) continue;

      const entryNodes = assets.filter(a => a.internet_exposed).slice(0, 5);
      const crownJewels = assets.filter(a => a.criticality === 'critical' && !a.internet_exposed).slice(0, 5);
      const internals = assets.filter(a => !a.internet_exposed && a.criticality !== 'critical');

      const paths = [];
      for (const entry of entryNodes) {
        for (const crown of crownJewels) {
          const mid = internals.slice(0, 2);
          const pathCost = (entry.risk_score || 5) + mid.reduce((s, n) => s + (n.risk_score || 3), 0);
          paths.push({
            tenant_id: tenant.id,
            source_asset_id: entry.id,
            target_asset_id: crown.id,
            path_nodes: [entry.id, ...mid.map(m => m.id), crown.id].map(id => ({ asset_id: id })),
            path_cost: pathCost,
            blast_radius: (crown.business_value || 0),
            choke_point_ids: mid.length > 0 ? [mid[0].id] : [],
            computed_at: new Date().toISOString(),
          });
        }
      }

      if (paths.length > 0) {
        await supabase.from('nexus_attack_paths').delete().eq('tenant_id', tenant.id);
        await supabase.from('nexus_attack_paths').insert(paths);
      }
    }
  } catch (e) {
    logger.warn(SVC, `[AttackPath] Computation error: ${e.message}`);
  }
}

// ── SLA Breach Check ────────────────────────────────────────────────────────
async function checkSLABreaches() {
  const supabase = getSupabase();
  if (!supabase) return;

  try {
    const now = new Date().toISOString();
    const { error } = await supabase.from('nexus_asset_vulnerabilities')
      .update({ sla_breached: true })
      .lt('sla_due_at', now)
      .eq('status', 'open')
      .eq('sla_breached', false);

    if (error) logger.warn(SVC, `[SLA] Breach check error: ${error.message}`);
  } catch (e) {
    logger.warn(SVC, `[SLA] Check error: ${e.message}`);
  }
}

// ── Main Scheduler ────────────────────────────────────────────────────────────
function startNexusScheduler() {
  if (_running) { logger.info(SVC, 'Scheduler already running'); return; }
  _running = true;

  logger.info(SVC, 'Starting Wadjet Nexus background scheduler...');

  // Risk score: every 30 seconds
  _timers.push(setInterval(() => recomputeRiskScores().catch(e => logger.warn(SVC, `RiskScore: ${e.message}`)), 30_000));

  // Attack paths: every 15 minutes
  _timers.push(setInterval(() => recomputeAttackPaths().catch(e => logger.warn(SVC, `AttackPath: ${e.message}`)), 15 * 60_000));

  // CVE import: every hour
  _timers.push(setInterval(() => importCVEs().catch(e => logger.warn(SVC, `CVE: ${e.message}`)), 60 * 60_000));

  // SLA breach check: every 5 minutes
  _timers.push(setInterval(() => checkSLABreaches().catch(e => logger.warn(SVC, `SLA: ${e.message}`)), 5 * 60_000));

  // Initial runs (staggered)
  setTimeout(() => recomputeRiskScores().catch(() => {}), 5_000);
  setTimeout(() => recomputeAttackPaths().catch(() => {}), 15_000);
  setTimeout(() => importCVEs().catch(() => {}), 30_000);
  setTimeout(() => checkSLABreaches().catch(() => {}), 10_000);

  logger.info(SVC, 'Wadjet Nexus scheduler started (CVE hourly | RiskScore 30s | AttackPath 15min | SLA 5min)');
}

function stopNexusScheduler() {
  _timers.forEach(t => clearInterval(t));
  _timers = [];
  _running = false;
  logger.info(SVC, 'Wadjet Nexus scheduler stopped');
}

module.exports = { startNexusScheduler, stopNexusScheduler, importCVEs, matchCVEsToAssets, recomputeRiskScores, recomputeAttackPaths };
