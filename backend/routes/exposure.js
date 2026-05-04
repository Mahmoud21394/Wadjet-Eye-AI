/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Exposure Assessment Engine v5.2
 *  backend/routes/exposure.js
 *
 *  REAL endpoint — no mock data.
 *  Correlates ingested IOCs with internal asset inventory
 *  to compute true exposure risk.
 *
 *  Endpoints:
 *   GET  /api/exposure/summary        — KPI tiles + risk score
 *   GET  /api/exposure/assets         — Asset inventory with exposure status
 *   GET  /api/exposure/cves           — CVEs from iocs + vulnerabilities tables
 *   GET  /api/exposure/mappings       — IOC↔Asset correlation results
 *   GET  /api/exposure/attack-surface — External-facing assets
 *   POST /api/exposure/scan           — Trigger correlation run
 *   GET  /api/exposure/news           — Related threat news
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const express  = require('express');
const router   = express.Router();
const axios    = require('axios');
const { supabase } = require('../config/supabase');
const { verifyToken }   = require('../middleware/auth');
const { asyncHandler }  = require('../middleware/errorHandler');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ── All exposure routes require auth ────────────────────────
router.use(verifyToken);

// ── Helper: get tenant ID safely ────────────────────────────
function tid(req) {
  return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT;
}

// ══════════════════════════════════════════════════════════════
//  EXPOSURE CORRELATION ENGINE
//  Matches IOCs against asset_inventory:
//    ip_match     — IOC.value matches asset.ip_address
//    domain_match — IOC.value matches asset.hostname
//    hash_match   — IOC hash found in asset services/metadata
//    cve_match    — IOC cve matches vulnerability on asset
//    port_match   — IOC-associated port open on asset
// ══════════════════════════════════════════════════════════════
async function runExposureCorrelation(tenantId) {
  const t0 = Date.now();
  console.info(`[Exposure] Running correlation for tenant ${tenantId}...`);

  try {
    // 1. Get all active malicious/suspicious IOCs
    const { data: iocs, error: iocErr } = await supabase
      .from('iocs')
      .select('id, value, type, risk_score, reputation, tags, kill_chain_phase')
      .eq('tenant_id', tenantId)
      .in('reputation', ['malicious','suspicious'])
      .eq('status', 'active')
      .order('risk_score', { ascending: false })
      .limit(2000);

    if (iocErr) {
      console.warn('[Exposure] Failed to fetch IOCs:', iocErr.message);
      return { correlated: 0, error: iocErr.message };
    }

    // No IOCs yet — this is normal for a fresh tenant, not an error
    if (!iocs || iocs.length === 0) {
      console.info('[Exposure] No active IOCs found for tenant — skipping correlation (normal on first run)');
      return { correlated: 0, skipped: true, reason: 'no_iocs' };
    }

    // 2. Get all active assets
    const { data: assets, error: assetErr } = await supabase
      .from('asset_inventory')
      .select('id, name, ip_address, hostname, open_ports, services, criticality, type')
      .eq('tenant_id', tenantId)
      .eq('status', 'active');

    if (assetErr) {
      console.warn('[Exposure] Failed to fetch assets:', assetErr.message);
      return { correlated: 0, error: assetErr.message };
    }
    if (!assets || assets.length === 0) {
      console.info('[Exposure] No active assets found for tenant — skipping correlation (add assets to asset_inventory)');
      return { correlated: 0, skipped: true, reason: 'no_assets' };
    }

    // 3. Build lookup maps for fast matching
    const assetByIP       = new Map();
    const assetByHostname = new Map();
    for (const asset of assets) {
      if (asset.ip_address) {
        assetByIP.set(String(asset.ip_address).toLowerCase(), asset);
      }
      if (asset.hostname) {
        assetByHostname.set(asset.hostname.toLowerCase(), asset);
      }
    }

    // 4. Correlate IOCs with assets
    const mappings = [];
    const existingKeys = new Set();

    for (const ioc of iocs) {
      const val = ioc.value.toLowerCase();
      let matchedAssets = [];

      if (ioc.type === 'ip' && assetByIP.has(val)) {
        matchedAssets.push({ asset: assetByIP.get(val), matchType: 'ip_match' });
      }

      if (['domain','url'].includes(ioc.type)) {
        // Extract hostname from URL if needed
        let hostname = val;
        try { hostname = new URL(val.startsWith('http') ? val : 'https://' + val).hostname; } catch (_) {}
        if (assetByHostname.has(hostname)) {
          matchedAssets.push({ asset: assetByHostname.get(hostname), matchType: 'domain_match' });
        }
      }

      // Check if IOC tag contains a port number that's open on any asset
      if (ioc.tags && ioc.type === 'ip') {
        const portTag = ioc.tags.find(t => /^port:\d+$/.test(t));
        if (portTag) {
          const port = parseInt(portTag.split(':')[1]);
          for (const asset of assets) {
            if (asset.open_ports?.includes(port)) {
              matchedAssets.push({ asset, matchType: 'port_match' });
            }
          }
        }
      }

      for (const { asset, matchType } of matchedAssets) {
        const key = `${ioc.id}:${asset.id}`;
        if (existingKeys.has(key)) continue;
        existingKeys.add(key);

        const critMultiplier = { critical: 1.4, high: 1.2, medium: 1.0, low: 0.8 };
        const riskScore = Math.min(100, Math.round(
          ioc.risk_score * (critMultiplier[asset.criticality] || 1.0)
        ));

        let severity = 'low';
        if (riskScore >= 80)  severity = 'critical';
        else if (riskScore >= 60) severity = 'high';
        else if (riskScore >= 40) severity = 'medium';

        mappings.push({
          tenant_id:  tenantId,
          ioc_id:     ioc.id,
          asset_id:   asset.id,
          match_type: matchType,
          risk_score: riskScore,
          severity,
          status:     'open',
          last_seen:  new Date().toISOString(),
          metadata: {
            ioc_value:       ioc.value,
            ioc_type:        ioc.type,
            asset_name:      asset.name,
            asset_type:      asset.type,
            kill_chain_phase: ioc.kill_chain_phase,
          },
        });
      }
    }

    // 5. Upsert mappings in chunks
    let upserted = 0;
    for (let i = 0; i < mappings.length; i += 100) {
      const chunk = mappings.slice(i, i + 100);
      const { error } = await supabase
        .from('exposure_mapping')
        .upsert(chunk, {
          onConflict: 'ioc_id,asset_id',
          ignoreDuplicates: false,
        });
      if (!error) upserted += chunk.length;
    }

    console.info(`[Exposure] ✓ Correlation done: ${upserted} mappings in ${Date.now() - t0}ms`);
    return { correlated: upserted, assets_checked: assets.length, iocs_checked: iocs.length };

  } catch (err) {
    console.error('[Exposure] Correlation error:', err.message);
    return { error: err.message };
  }
}

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/summary
// ══════════════════════════════════════════════════════════════
router.get('/summary', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  // Parallel queries
  const [
    { data: iocData,    error: iocErr    },
    { data: alertData,  error: alertErr  },
    { data: caseData,   error: caseErr   },
    { data: exposures,  error: expErr    },
    { data: assets,     error: assetErr  },
    { data: vulns,      error: vulnErr   },
  ] = await Promise.all([
    supabase.from('iocs').select('reputation, risk_score, type', { count: 'exact' })
      .eq('tenant_id', tenantId).eq('status', 'active'),
    supabase.from('alerts').select('severity', { count: 'exact' })
      .eq('tenant_id', tenantId).eq('status', 'open'),
    supabase.from('cases').select('severity', { count: 'exact' })
      .eq('tenant_id', tenantId).neq('status', 'closed'),
    supabase.from('exposure_mapping').select('severity, risk_score', { count: 'exact' })
      .eq('tenant_id', tenantId).eq('status', 'open'),
    supabase.from('asset_inventory').select('criticality', { count: 'exact' })
      .eq('tenant_id', tenantId).eq('status', 'active'),
    supabase.from('iocs').select('id', { count: 'exact' })
      .eq('tenant_id', tenantId).eq('type', 'cve').eq('status', 'active'),
  ]);

  // Compute risk score from exposure mappings
  const expList = exposures || [];
  const critCount = expList.filter(e => e.severity === 'critical').length;
  const highCount = expList.filter(e => e.severity === 'high').length;
  const medCount  = expList.filter(e => e.severity === 'medium').length;
  const lowCount  = expList.filter(e => e.severity === 'low').length;

  const rawRisk = (critCount * 25) + (highCount * 10) + (medCount * 3) + lowCount;
  const riskScore = Math.min(100, rawRisk);

  let riskLevel = 'LOW';
  if (riskScore >= 75) riskLevel = 'CRITICAL';
  else if (riskScore >= 50) riskLevel = 'HIGH';
  else if (riskScore >= 25) riskLevel = 'MEDIUM';

  const iocList  = iocData || [];
  const malicious  = iocList.filter(i => i.reputation === 'malicious').length;
  const suspicious = iocList.filter(i => i.reputation === 'suspicious').length;

  const alertList = alertData || [];
  const critAlerts = alertList.filter(a => a.severity === 'critical').length;
  const highAlerts = alertList.filter(a => a.severity === 'high').length;

  const assetList  = assets || [];
  const critAssets = assetList.filter(a => a.criticality === 'critical').length;

  // Also check Shodan/external scan data
  let shodanAssets = 0;
  if (process.env.SHODAN_API_KEY) {
    try {
      const { data: external } = await axios.get(
        `https://api.shodan.io/shodan/host/count?key=${process.env.SHODAN_API_KEY}&query=org:"${encodeURIComponent(process.env.ORG_NAME || 'Wadjet')}"`,
        { timeout: 5000 }
      );
      shodanAssets = external?.total || 0;
    } catch (_) {}
  }

  res.json({
    risk_score:          riskScore,
    risk_level:          riskLevel,
    total_exposures:     expList.length,
    critical_exposures:  critCount,
    high_exposures:      highCount,
    medium_exposures:    medCount,
    low_exposures:       lowCount,
    total_iocs:          iocList.length,
    malicious_iocs:      malicious,
    suspicious_iocs:     suspicious,
    total_cves:          vulns?.length || 0,
    critical_alerts:     critAlerts,
    high_alerts:         highAlerts,
    open_cases:          caseData?.length || 0,
    total_assets:        assetList.length,
    critical_assets:     critAssets,
    external_hosts:      shodanAssets,
    last_scan_at:        new Date().toISOString(),
    _real_data:          true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/assets
// ══════════════════════════════════════════════════════════════
router.get('/assets', asyncHandler(async (req, res) => {
  const tenantId = tid(req);
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 20);
  const from  = (page - 1) * limit;

  let q = supabase
    .from('asset_inventory')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .order('criticality', { ascending: true })
    .range(from, from + limit - 1);

  if (req.query.type)        q = q.eq('type', req.query.type);
  if (req.query.criticality) q = q.eq('criticality', req.query.criticality);
  if (req.query.search)      q = q.ilike('name', `%${req.query.search}%`);

  const { data, count, error } = await q;
  if (error) throw error;

  // For each asset, get its exposure count
  const assetIds = (data || []).map(a => a.id);
  let exposureCounts = {};

  if (assetIds.length > 0) {
    const { data: expData } = await supabase
      .from('exposure_mapping')
      .select('asset_id, severity')
      .in('asset_id', assetIds)
      .eq('status', 'open');

    for (const e of (expData || [])) {
      if (!exposureCounts[e.asset_id]) {
        exposureCounts[e.asset_id] = { total: 0, critical: 0, high: 0 };
      }
      exposureCounts[e.asset_id].total++;
      if (e.severity === 'critical') exposureCounts[e.asset_id].critical++;
      if (e.severity === 'high')     exposureCounts[e.asset_id].high++;
    }
  }

  const enriched = (data || []).map(a => ({
    ...a,
    exposure_count:    exposureCounts[a.id]?.total    || 0,
    critical_exposures: exposureCounts[a.id]?.critical || 0,
    high_exposures:    exposureCounts[a.id]?.high     || 0,
  }));

  res.json({
    data:  enriched,
    total: count || 0,
    page,
    limit,
    _real_data: true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/cves
// ══════════════════════════════════════════════════════════════
router.get('/cves', asyncHandler(async (req, res) => {
  const tenantId = tid(req);
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 25);
  const from  = (page - 1) * limit;

  // Try vulnerabilities table first, fall back to iocs with type=cve
  let query = supabase
    .from('vulnerabilities')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .order('cvss_score', { ascending: false })
    .range(from, from + limit - 1);

  if (req.query.severity) query = query.eq('severity', req.query.severity);
  if (req.query.exploited === 'true') query = query.eq('is_kev', true);
  if (req.query.search)   query = query.ilike('cve_id', `%${req.query.search}%`);

  const { data, count, error } = await query;

  if (error || !data || data.length === 0) {
    // Fallback: query iocs table for CVE type
    const { data: iocCves, count: iocCount } = await supabase
      .from('iocs')
      .select('id, value, risk_score, reputation, tags, notes, enrichment_data, created_at, last_seen', { count: 'exact' })
      .eq('tenant_id', tenantId)
      .eq('type', 'cve')
      .order('risk_score', { ascending: false })
      .range(from, from + limit - 1);

    // Map to vulnerability-like shape
    const cveRecords = (iocCves || []).map(ioc => ({
      id:           ioc.id,
      cve_id:       ioc.value.toUpperCase(),
      severity:     ioc.risk_score >= 90 ? 'CRITICAL' : ioc.risk_score >= 70 ? 'HIGH' : ioc.risk_score >= 40 ? 'MEDIUM' : 'LOW',
      cvss_score:   (ioc.risk_score / 10).toFixed(1),
      epss_score:   null,
      description:  ioc.notes || '',
      is_kev:       ioc.tags?.includes('kev') || false,
      is_exploited: ioc.tags?.includes('exploited') || ioc.tags?.includes('kev') || false,
      published_date: ioc.created_at,
      modified_date:  ioc.last_seen,
      references:    [],
      remediation:   null,
      _source:       'iocs_table',
    }));

    return res.json({
      data:  cveRecords,
      total: iocCount || 0,
      page,
      limit,
      _real_data: true,
    });
  }

  res.json({
    data:  data || [],
    total: count || 0,
    page,
    limit,
    _real_data: true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/mappings
// ══════════════════════════════════════════════════════════════
router.get('/mappings', asyncHandler(async (req, res) => {
  const tenantId = tid(req);
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 25);
  const from  = (page - 1) * limit;

  let q = supabase
    .from('exposure_mapping')
    .select(`
      *,
      iocs!ioc_id(value, type, reputation, risk_score, source),
      asset_inventory!asset_id(name, type, ip_address, criticality)
    `, { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('risk_score', { ascending: false })
    .range(from, from + limit - 1);

  if (req.query.severity) q = q.eq('severity', req.query.severity);
  if (req.query.status)   q = q.eq('status', req.query.status);
  else                    q = q.eq('status', 'open');

  const { data, count, error } = await q;
  if (error) throw error;

  res.json({
    data:  data || [],
    total: count || 0,
    page,
    limit,
    _real_data: true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/attack-surface
// ══════════════════════════════════════════════════════════════
router.get('/attack-surface', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  // Get internet-facing assets (those with public IPs or cloud instances)
  const { data: assets } = await supabase
    .from('asset_inventory')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .or('type.eq.cloud_instance,type.eq.network_device,type.eq.service');

  // Get external IPs from Shodan if key available
  let shodanData = [];
  if (process.env.SHODAN_API_KEY && assets && assets.length > 0) {
    const publicIPs = assets
      .filter(a => a.ip_address && !String(a.ip_address).startsWith('10.') &&
                   !String(a.ip_address).startsWith('172.') &&
                   !String(a.ip_address).startsWith('192.168.'))
      .map(a => a.ip_address)
      .slice(0, 5); // Shodan credits are precious

    for (const ip of publicIPs) {
      try {
        const { data: sh } = await axios.get(
          `https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`,
          { timeout: 8000 }
        );
        shodanData.push({
          ip,
          open_ports:  sh.ports || [],
          hostnames:   sh.hostnames || [],
          vulns:       Object.keys(sh.vulns || {}).slice(0, 5),
          org:         sh.org,
          os:          sh.os,
          last_update: sh.last_update,
        });
        await new Promise(r => setTimeout(r, 1000));
      } catch (_) {}
    }
  }

  // Get recent exposure mappings for these assets
  const assetIds = (assets || []).map(a => a.id);
  let exposures = [];
  if (assetIds.length > 0) {
    const { data: expData } = await supabase
      .from('exposure_mapping')
      .select('*, iocs!ioc_id(value, type, reputation)')
      .in('asset_id', assetIds)
      .eq('status', 'open')
      .order('risk_score', { ascending: false })
      .limit(50);
    exposures = expData || [];
  }

  res.json({
    assets:       assets || [],
    exposures,
    shodan_scans: shodanData,
    total_assets: assets?.length || 0,
    total_exposures: exposures.length,
    _real_data: true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  POST /api/exposure/scan
//  Trigger manual correlation run
// ══════════════════════════════════════════════════════════════
router.post('/scan', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  // Respond immediately, run async
  res.json({ status: 'started', message: 'Exposure correlation scan initiated', tenant_id: tenantId });

  // Run in background
  setImmediate(async () => {
    try {
      const result = await runExposureCorrelation(tenantId);
      console.info('[Exposure] Manual scan complete:', result);
    } catch (err) {
      console.error('[Exposure] Manual scan error:', err.message);
    }
  });
}));

// ══════════════════════════════════════════════════════════════
//  GET /api/exposure/news
//  Recent threat news relevant to exposure
// ══════════════════════════════════════════════════════════════
router.get('/news', asyncHandler(async (req, res) => {
  const tenantId = tid(req);
  const limit = Math.min(50, parseInt(req.query.limit) || 10);

  const { data, error } = await supabase
    .from('news_articles')
    .select('id, title, url, source, severity, cves, threat_actors, malware_families, published_at, tags')
    .or(`tenant_id.eq.${tenantId},tenant_id.eq.00000000-0000-0000-0000-000000000001`)
    .order('published_at', { ascending: false })
    .limit(limit);

  if (error) throw error;

  res.json({
    data:  data || [],
    total: data?.length || 0,
    _real_data: true,
  });
}));

// ══════════════════════════════════════════════════════════════
//  Export correlation function for scheduler
// ══════════════════════════════════════════════════════════════
module.exports = router;
module.exports.runExposureCorrelation = runExposureCorrelation;
