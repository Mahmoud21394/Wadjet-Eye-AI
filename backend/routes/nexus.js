'use strict';
/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet Nexus — Cyber Risk & Exposure Management
 *  Express Router: /api/nexus/*
 *
 *  Brand: Wadjet Nexus (formerly XORCISM integration)
 *  Modules covered:
 *    • Asset Management & CTEM
 *    • Vulnerability Management (VOC, KEV, EPSS, CVE)
 *    • Attack Path Analysis
 *    • Enterprise Risk Score
 *    • GRC / Compliance
 *    • Risk Register (FAIR/CRQ)
 *    • TPRM
 *    • SBOM/SCA
 *    • Sigma Rules
 *    • YARA Rules
 *    • BAS/Adversary Emulation
 *    • Threat Hunting
 *    • DFIR Forensics
 *    • Connectors Catalog
 *    • Background Scheduler
 *    • Threat Modeling (STRIDE)
 *    • Business Impact Analysis
 *    • EBIOS RM
 *    • NIST 800-30
 *    • PQCMM Quantum Readiness
 *    • Crisis Management & TTX
 *    • Ransomware Scenario
 *    • Adversary Opportunity Index
 *    • Cyber Insurance Readiness
 *    • AI Guardrails
 *    • CTEM Exposure Taxonomy
 *    • Threat-Informed Defense
 *    • Configuration Management
 *    • Policies & Documents
 *    • Bug Bounty
 *    • Pentest Engagements
 *    • Identity Management
 *
 *  Auth: verifyToken (all routes)
 *  Tenant isolation: tenant_id from JWT / X-Tenant-ID header
 * ══════════════════════════════════════════════════════════════════════════════
 */

const express        = require('express');
const router         = express.Router();
const { verifyToken }  = require('../middleware/auth');
const { auditLog }     = require('../middleware/audit');
const { getSupabase }  = require('../config/supabase');
const logger           = require('../utils/logger');

const SVC = 'NexusAPI';

// ── Helpers ──────────────────────────────────────────────────────────────────
function getTenant(req) {
  return req.user?.tenant_id || req.headers['x-tenant-id'];
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function ok(res, data, meta = {}) {
  return res.json({ success: true, data, ...meta });
}

function err(res, message, status = 400, details = null) {
  const payload = { success: false, error: message };
  if (details) payload.details = details;
  return res.status(status).json(payload);
}

// All nexus routes require authentication
router.use(verifyToken);

// ══════════════════════════════════════════════════════════════════════════════
//  DASHBOARD — Enterprise Risk Score + KPIs
// ══════════════════════════════════════════════════════════════════════════════
router.get('/dashboard', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  if (!tenantId) return err(res, 'Tenant ID required', 400);

  const supabase = getSupabase();

  // Parallel fetch: risk scores, vuln counts, asset stats, recent incidents
  const [riskRes, vulnRes, assetRes, huntRes, ctrlRes] = await Promise.all([
    supabase.from('nexus_risk_scores')
      .select('*').eq('tenant_id', tenantId)
      .order('computed_at', { ascending: false }).limit(1).maybeSingle(),

    supabase.from('nexus_asset_vulnerabilities')
      .select('status, vulnerability_id, nexus_vulnerabilities(severity, is_kev, cvss_score)')
      .eq('tenant_id', tenantId).eq('status', 'open'),

    supabase.from('asset_inventory')
      .select('id, criticality, internet_exposed, risk_score, status')
      .eq('tenant_id', tenantId),

    supabase.from('nexus_hunts')
      .select('id, status, priority, created_at')
      .eq('tenant_id', tenantId).in('status', ['open', 'in_progress']),

    supabase.from('nexus_controls')
      .select('status')
      .eq('tenant_id', tenantId),
  ]);

  // Compute live KPIs
  const vulns = vulnRes.data || [];
  const assets = assetRes.data || [];
  const controls = ctrlRes.data || [];

  const kpis = {
    total_assets: assets.length,
    internet_exposed: assets.filter(a => a.internet_exposed).length,
    critical_assets: assets.filter(a => a.criticality === 'critical').length,
    total_vulns: vulns.length,
    critical_vulns: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'critical').length,
    high_vulns: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'high').length,
    kev_vulns: vulns.filter(v => v.nexus_vulnerabilities?.is_kev).length,
    open_hunts: (huntRes.data || []).length,
    controls_total: controls.length,
    controls_implemented: controls.filter(c => c.status === 'implemented').length,
    controls_pct: controls.length > 0 
      ? Math.round((controls.filter(c => c.status === 'implemented').length / controls.length) * 100)
      : 0,
    enterprise_risk_score: riskRes.data?.enterprise_risk_score || 0,
    maturity_radar: riskRes.data?.maturity_radar || {},
    risk_heatmap: riskRes.data?.risk_heatmap || [],
  };

  // Severity breakdown
  const severityBreakdown = {
    critical: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'critical').length,
    high: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'high').length,
    medium: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'medium').length,
    low: vulns.filter(v => v.nexus_vulnerabilities?.severity === 'low').length,
  };

  return ok(res, {
    kpis,
    severity_breakdown: severityBreakdown,
    recent_risk_score: riskRes.data,
    top_risky_assets: assets
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
      .slice(0, 10),
  });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ASSET MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
router.get('/assets', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { page = 1, limit = 50, search, criticality, internet_exposed, status } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const supabase = getSupabase();
  let query = supabase.from('asset_inventory')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('risk_score', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (search) query = query.or(`hostname.ilike.%${search}%,ip_address.ilike.%${search}%,name.ilike.%${search}%`);
  if (criticality) query = query.eq('criticality', criticality);
  if (internet_exposed !== undefined) query = query.eq('internet_exposed', internet_exposed === 'true');
  if (status) query = query.eq('status', status);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);

  return ok(res, data, { total: count, page: parseInt(page), limit: parseInt(limit) });
}));

router.get('/assets/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data, error } = await supabase.from('asset_inventory')
    .select('*').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (error) return err(res, error.message, 500);
  if (!data) return err(res, 'Asset not found', 404);

  // Fetch related vulnerabilities
  const { data: vulns } = await supabase.from('nexus_asset_vulnerabilities')
    .select('*, nexus_vulnerabilities(*)')
    .eq('asset_id', req.params.id)
    .eq('tenant_id', tenantId)
    .order('fusion_score', { ascending: false })
    .limit(20);

  return ok(res, { ...data, vulnerabilities: vulns || [] });
}));

router.post('/assets', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const body = { ...req.body, tenant_id: tenantId, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };

  const { data, error } = await supabase.from('asset_inventory').insert(body).select().single();
  if (error) return err(res, error.message, 500);

  await auditLog(req, 'nexus.asset.create', { asset_id: data.id });
  return ok(res, data);
}));

router.put('/assets/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('asset_inventory')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();

  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.asset.update', { asset_id: req.params.id });
  return ok(res, data);
}));

router.delete('/assets/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { error } = await supabase.from('asset_inventory')
    .delete().eq('id', req.params.id).eq('tenant_id', tenantId);

  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.asset.delete', { asset_id: req.params.id });
  return ok(res, { deleted: true });
}));

// Asset surface graph data
router.get('/assets/:id/surface-graph', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: asset } = await supabase.from('asset_inventory')
    .select('*').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (!asset) return err(res, 'Asset not found', 404);

  const { data: vulns } = await supabase.from('nexus_asset_vulnerabilities')
    .select('vulnerability_id, fusion_score, nexus_vulnerabilities(cve_id, severity, cvss_score)')
    .eq('asset_id', req.params.id).eq('tenant_id', tenantId).limit(30);

  const nodes = [{ id: asset.id, type: 'asset', label: asset.hostname || asset.ip_address, data: asset }];
  const edges = [];

  (vulns || []).forEach(av => {
    if (av.nexus_vulnerabilities) {
      const vid = av.vulnerability_id;
      nodes.push({ id: vid, type: 'vuln', label: av.nexus_vulnerabilities.cve_id, severity: av.nexus_vulnerabilities.severity });
      edges.push({ source: asset.id, target: vid, weight: av.fusion_score });
    }
  });

  return ok(res, { nodes, edges, center: asset.id });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  VULNERABILITY MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
router.get('/vulnerabilities', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { page = 1, limit = 50, severity, is_kev, search, status } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const supabase = getSupabase();
  let query = supabase.from('nexus_vulnerabilities')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('cvss_score', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (severity) query = query.eq('severity', severity);
  if (is_kev === 'true') query = query.eq('is_kev', true);
  if (status) query = query.eq('status', status);
  if (search) query = query.or(`cve_id.ilike.%${search}%,title.ilike.%${search}%`);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count, page: parseInt(page), limit: parseInt(limit) });
}));

router.get('/vulnerabilities/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data, error } = await supabase.from('nexus_vulnerabilities')
    .select('*').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (error) return err(res, error.message, 500);
  if (!data) return err(res, 'Vulnerability not found', 404);

  const { data: affected } = await supabase.from('nexus_asset_vulnerabilities')
    .select('*, asset_inventory(id, hostname, ip_address, criticality)')
    .eq('vulnerability_id', req.params.id).eq('tenant_id', tenantId);

  return ok(res, { ...data, affected_assets: affected || [] });
}));

// Top exposure (fusion score) — "fix this first" worklist
router.get('/exposure-worklist', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { limit = 50 } = req.query;
  const supabase = getSupabase();

  const { data, error } = await supabase.from('nexus_asset_vulnerabilities')
    .select(`
      id, fusion_score, status, sla_due_at, sla_breached,
      asset_inventory(id, hostname, ip_address, criticality, business_value, internet_exposed),
      nexus_vulnerabilities(cve_id, severity, cvss_score, epss_score, is_kev, has_exploit, title)
    `)
    .eq('tenant_id', tenantId)
    .eq('status', 'open')
    .order('fusion_score', { ascending: false })
    .limit(parseInt(limit));

  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// CVE match against assets (trigger manual or post-import)
router.post('/vulnerabilities/match-assets', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: vulns } = await supabase.from('nexus_vulnerabilities')
    .select('id, cpe_affected, cve_id')
    .eq('tenant_id', tenantId);

  const { data: assets } = await supabase.from('asset_inventory')
    .select('id, cpe_list, technology_tags')
    .eq('tenant_id', tenantId);

  let matchCount = 0;
  const matches = [];

  for (const vuln of (vulns || [])) {
    for (const asset of (assets || [])) {
      const assetCpes = asset.cpe_list || [];
      const vulnCpes  = vuln.cpe_affected || [];
      const hasMatch  = assetCpes.some(ac => vulnCpes.some(vc => ac.toLowerCase().includes(vc.toLowerCase().split(':').slice(0, 4).join(':'))));
      if (hasMatch) {
        matches.push({ tenant_id: tenantId, asset_id: asset.id, vulnerability_id: vuln.id, match_source: 'cpe' });
        matchCount++;
      }
    }
  }

  if (matches.length > 0) {
    await supabase.from('nexus_asset_vulnerabilities').upsert(matches, { onConflict: 'tenant_id,asset_id,vulnerability_id', ignoreDuplicates: true });
  }

  await auditLog(req, 'nexus.vuln.match_assets', { matched: matchCount });
  return ok(res, { matched: matchCount });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ATTACK PATH ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/attack-paths', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data, error } = await supabase.from('nexus_attack_paths')
    .select('*').eq('tenant_id', tenantId)
    .order('path_cost', { ascending: true }).limit(100);

  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// Compute attack paths (Dijkstra-inspired over asset graph)
router.post('/attack-paths/compute', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: assets } = await supabase.from('asset_inventory')
    .select('id, hostname, ip_address, subnet, internet_exposed, business_value, criticality, risk_score')
    .eq('tenant_id', tenantId);

  if (!assets || assets.length === 0) return ok(res, { paths_computed: 0 });

  // Build adjacency from subnet similarity
  const entryNodes = assets.filter(a => a.internet_exposed);
  const crownJewels = assets.filter(a => a.criticality === 'critical' && !a.internet_exposed);

  const paths = [];

  for (const entry of entryNodes.slice(0, 5)) {
    for (const crown of crownJewels.slice(0, 5)) {
      // Simple path via intermediate nodes
      const intermediates = assets.filter(a => a.id !== entry.id && a.id !== crown.id).slice(0, 3);
      const pathNodes = [entry.id, ...intermediates.map(i => i.id), crown.id];
      const pathCost = entry.risk_score + intermediates.reduce((sum, n) => sum + (n.risk_score || 0), 0);
      const blastRadius = (crown.business_value || 0) + intermediates.reduce((sum, n) => sum + (n.business_value || 0), 0);

      paths.push({
        tenant_id: tenantId,
        source_asset_id: entry.id,
        target_asset_id: crown.id,
        path_nodes: pathNodes.map(id => ({ asset_id: id })),
        path_cost: pathCost,
        exploitability: Math.min(99, pathCost / 10),
        blast_radius: blastRadius,
        choke_point_ids: intermediates.length > 0 ? [intermediates[0].id] : [],
        computed_at: new Date().toISOString(),
      });
    }
  }

  if (paths.length > 0) {
    await supabase.from('nexus_attack_paths').delete().eq('tenant_id', tenantId);
    await supabase.from('nexus_attack_paths').insert(paths);
  }

  await auditLog(req, 'nexus.attack_path.compute', { paths_count: paths.length });
  return ok(res, { paths_computed: paths.length, paths });
}));

// Attack surface graph for force-directed D3 visualization
router.get('/attack-surface-graph', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const [assetsRes, pathsRes] = await Promise.all([
    supabase.from('asset_inventory')
      .select('id, hostname, ip_address, criticality, internet_exposed, risk_score, business_value, type')
      .eq('tenant_id', tenantId).limit(200),
    supabase.from('nexus_attack_paths')
      .select('source_asset_id, target_asset_id, path_cost, choke_point_ids')
      .eq('tenant_id', tenantId).limit(500),
  ]);

  const nodes = (assetsRes.data || []).map(a => ({
    id: a.id,
    label: a.hostname || a.ip_address || 'Unknown',
    type: a.internet_exposed ? 'entry' : (a.criticality === 'critical' ? 'crown_jewel' : 'internal'),
    criticality: a.criticality,
    risk_score: a.risk_score || 0,
    business_value: a.business_value || 0,
    internet_exposed: a.internet_exposed,
  }));

  const allChokePoints = new Set();
  (pathsRes.data || []).forEach(p => (p.choke_point_ids || []).forEach(c => allChokePoints.add(c)));

  nodes.forEach(n => { if (allChokePoints.has(n.id)) n.type = 'choke_point'; });

  const edges = (pathsRes.data || []).map(p => ({
    source: p.source_asset_id,
    target: p.target_asset_id,
    weight: p.path_cost || 1,
  }));

  return ok(res, { nodes, edges, choke_points: [...allChokePoints] });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ENTERPRISE RISK SCORE
// ══════════════════════════════════════════════════════════════════════════════
router.get('/risk-score', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data, error } = await supabase.from('nexus_risk_scores')
    .select('*').eq('tenant_id', tenantId)
    .order('computed_at', { ascending: false }).limit(30);

  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/risk-score/compute', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  // Gather signals
  const [assetRes, vulnRes, incidentRes, ctrlRes, riskRegRes] = await Promise.all([
    supabase.from('asset_inventory').select('risk_score, internet_exposed, criticality').eq('tenant_id', tenantId),
    supabase.from('nexus_asset_vulnerabilities').select('fusion_score, nexus_vulnerabilities(severity, is_kev)').eq('tenant_id', tenantId).eq('status', 'open'),
    supabase.from('cases').select('id, status, severity').eq('tenant_id', tenantId).in('status', ['open', 'investigating']).limit(100),
    supabase.from('nexus_controls').select('status').eq('tenant_id', tenantId),
    supabase.from('nexus_risk_register').select('current_score, residual_score').eq('tenant_id', tenantId),
  ]);

  const assets      = assetRes.data || [];
  const openVulns   = vulnRes.data || [];
  const incidents   = incidentRes.data || [];
  const controls    = ctrlRes.data || [];
  const risks       = riskRegRes.data || [];

  // Compute component scores (0-100 each)
  const assetHygiene  = assets.length > 0 ? Math.max(0, 100 - (assets.filter(a => a.internet_exposed).length / assets.length) * 100) : 100;
  const criticalVulns = openVulns.filter(v => v.nexus_vulnerabilities?.severity === 'critical').length;
  const kevVulns      = openVulns.filter(v => v.nexus_vulnerabilities?.is_kev).length;
  const openRisk      = Math.min(100, (criticalVulns * 5 + kevVulns * 10));
  const incidentScore = Math.min(100, incidents.length * 8);
  const complianceDebt = controls.length > 0 ? Math.max(0, 100 - (controls.filter(c => c.status === 'implemented').length / controls.length * 100)) : 0;
  const assuranceCredits = risks.length > 0 ? risks.reduce((s, r) => s + (r.current_score - r.residual_score), 0) / risks.length : 0;

  // Enterprise Risk Score: weighted composite
  const enterpriseRiskScore = Math.round(
    (assetHygiene * 0.2) + (openRisk * 0.35) + (incidentScore * 0.2) + (complianceDebt * 0.15) + Math.max(0, 10 - assuranceCredits * 0.1)
  );

  const maturityRadar = {
    detection:    controls.filter(c => c.framework === 'detection' && c.status === 'implemented').length * 10,
    mitigation:   Math.max(0, 100 - openRisk),
    validation:   50,
    compliance:   100 - complianceDebt,
    crisis_ready: 60,
    risk_treated: Math.min(100, assuranceCredits * 10),
  };

  const riskRecord = {
    tenant_id: tenantId,
    enterprise_risk_score: enterpriseRiskScore,
    asset_hygiene_score: assetHygiene,
    open_risk_score: openRisk,
    incident_score: incidentScore,
    compliance_debt: complianceDebt,
    assurance_credits: assuranceCredits,
    contributors: { assetHygiene, openRisk, incidentScore, complianceDebt, assuranceCredits },
    maturity_radar: maturityRadar,
    computed_at: new Date().toISOString(),
  };

  const { data, error } = await supabase.from('nexus_risk_scores').insert(riskRecord).select().single();
  if (error) return err(res, error.message, 500);

  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  VULNERABILITY OPERATIONS CENTER (VOC)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/voc/policies', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_voc_policies').select('*').eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/voc/policies', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_voc_policies')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/voc/campaigns', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_remediation_campaigns')
    .select('*').eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/voc/campaigns', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_remediation_campaigns')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/voc/risk-acceptances', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_risk_acceptances')
    .select('*, nexus_vulnerabilities(cve_id, severity)').eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/voc/risk-acceptances', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_risk_acceptances')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.voc.risk_accepted', { id: data.id });
  return ok(res, data);
}));

// VOC KPIs
router.get('/voc/kpis', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const [openVulns, policyRes, remediatedRes] = await Promise.all([
    supabase.from('nexus_asset_vulnerabilities')
      .select('sla_due_at, sla_breached, status, nexus_vulnerabilities(severity, is_kev)')
      .eq('tenant_id', tenantId),
    supabase.from('nexus_voc_policies').select('*').eq('tenant_id', tenantId).eq('active', true).limit(1).maybeSingle(),
    supabase.from('nexus_asset_vulnerabilities')
      .select('remediated_at, created_at')
      .eq('tenant_id', tenantId).eq('status', 'remediated').limit(500),
  ]);

  const vulns = openVulns.data || [];
  const remediatedList = remediatedRes.data || [];

  const mttrMs = remediatedList.length > 0 ? remediatedList.reduce((sum, v) => {
    if (v.remediated_at && v.created_at) return sum + (new Date(v.remediated_at) - new Date(v.created_at));
    return sum;
  }, 0) / remediatedList.length : 0;

  const kpis = {
    open_vulns: vulns.filter(v => v.status === 'open').length,
    sla_breached: vulns.filter(v => v.sla_breached).length,
    sla_compliance_pct: vulns.length > 0 ? Math.round((1 - vulns.filter(v => v.sla_breached).length / vulns.length) * 100) : 100,
    mttr_days: Math.round(mttrMs / (1000 * 60 * 60 * 24)),
    kev_open: vulns.filter(v => v.nexus_vulnerabilities?.is_kev && v.status === 'open').length,
    active_policy: policyRes.data,
  };

  return ok(res, kpis);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  GRC — CONTROLS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/controls', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { framework, status, page = 1, limit = 100 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_controls').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).range(offset, offset + parseInt(limit) - 1);

  if (framework) query = query.eq('framework', framework);
  if (status) query = query.eq('status', status);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.put('/controls/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_controls')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.control.update', { id: req.params.id });
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  AUDITS & FINDINGS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/audits', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_audits').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/audits', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_audits')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.audit.create', { id: data.id });
  return ok(res, data);
}));

router.get('/audits/:id/findings', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_audit_findings')
    .select('*').eq('audit_id', req.params.id).eq('tenant_id', tenantId)
    .order('severity');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/audits/:id/findings', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_audit_findings')
    .insert({ ...req.body, audit_id: req.params.id, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  RISK REGISTER (FAIR/CRQ)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/risk-register', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { status, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_risk_register').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).order('priority_score', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (status) query = query.eq('status', status);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/risk-register', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const body = req.body;

  // Compute priority score: inherent × treatment gap
  const severityMap = { very_high: 5, high: 4, medium: 3, low: 2, very_low: 1 };
  const likelihood  = severityMap[body.current_likelihood] || 3;
  const impact      = severityMap[body.current_impact] || 3;
  const priorityScore = likelihood * impact * 4;

  const { data, error } = await supabase.from('nexus_risk_register')
    .insert({ ...body, tenant_id: tenantId, priority_score: priorityScore }).select().single();

  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.risk_register.create', { id: data.id });
  return ok(res, data);
}));

router.put('/risk-register/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_risk_register')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  TPRM
// ══════════════════════════════════════════════════════════════════════════════
router.get('/tprm/vendors', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_third_parties').select('*')
    .eq('tenant_id', tenantId).order('risk_score', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/tprm/vendors', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_third_parties')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/tprm/assessments', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_tprm_assessments')
    .select('*, nexus_third_parties(name, risk_tier)').eq('tenant_id', tenantId)
    .order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  SBOM / SCA
// ══════════════════════════════════════════════════════════════════════════════
router.get('/sbom', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_sboms')
    .select('*, asset_inventory(hostname, ip_address)')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/sbom/import', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { sbom_format = 'cyclonedx', raw_data, asset_id, name } = req.body;

  let components = [];
  let componentCount = 0;

  try {
    if (sbom_format === 'cyclonedx' && raw_data?.components) {
      components = raw_data.components.map(c => ({
        tenant_id: tenantId,
        name: c.name || 'Unknown',
        version: c.version,
        purl: c.purl,
        cpe: c.cpe,
        license: c.licenses?.[0]?.expression || c.licenses?.[0]?.license?.id,
        supplier: c.supplier?.name,
        hash_sha256: c.hashes?.find(h => h.alg === 'SHA-256')?.content,
        component_type: c.type || 'library',
      }));
    } else if (sbom_format === 'spdx' && raw_data?.packages) {
      components = raw_data.packages.map(p => ({
        tenant_id: tenantId,
        name: p.name || 'Unknown',
        version: p.versionInfo,
        purl: p.externalRefs?.find(r => r.referenceType === 'purl')?.referenceLocator,
        license: p.licenseConcluded,
        supplier: p.supplier,
        hash_sha256: p.checksums?.find(c => c.algorithm === 'SHA256')?.checksumValue,
        component_type: 'library',
      }));
    }
    componentCount = components.length;
  } catch (parseErr) {
    logger.warn(SVC, `SBOM parse error: ${parseErr.message}`);
  }

  const { data: sbomRecord, error: sbomErr } = await supabase.from('nexus_sboms')
    .insert({ tenant_id: tenantId, name: name || 'Imported SBOM', sbom_format, asset_id, component_count: componentCount, raw_data })
    .select().single();

  if (sbomErr) return err(res, sbomErr.message, 500);

  if (components.length > 0) {
    const compsWithSbom = components.map(c => ({ ...c, sbom_id: sbomRecord.id }));
    const chunkSize = 200;
    for (let i = 0; i < compsWithSbom.length; i += chunkSize) {
      await supabase.from('nexus_sbom_components').insert(compsWithSbom.slice(i, i + chunkSize));
    }
  }

  await auditLog(req, 'nexus.sbom.import', { id: sbomRecord.id, components: componentCount });
  return ok(res, { sbom: sbomRecord, components_imported: componentCount });
}));

router.get('/sbom/:id/components', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_sbom_components')
    .select('*').eq('sbom_id', req.params.id).eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  SIGMA RULES
// ══════════════════════════════════════════════════════════════════════════════
router.get('/sigma-rules', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { page = 1, limit = 100, level, status, search, technique } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_sigma_rules').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).order('level').range(offset, offset + parseInt(limit) - 1);

  if (level) query = query.eq('level', level);
  if (status) query = query.eq('status', status);
  if (search) query = query.ilike('title', `%${search}%`);
  if (technique) query = query.contains('attack_techniques', [technique]);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/sigma-rules', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_sigma_rules')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.sigma.create', { id: data.id });
  return ok(res, data);
}));

router.put('/sigma-rules/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_sigma_rules')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.delete('/sigma-rules/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { error } = await supabase.from('nexus_sigma_rules')
    .delete().eq('id', req.params.id).eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, { deleted: true });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  THREAT HUNTING
// ══════════════════════════════════════════════════════════════════════════════
router.get('/hunts', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { status, priority, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_hunts').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (status) query = query.eq('status', status);
  if (priority) query = query.eq('priority', priority);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/hunts', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_hunts')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.hunt.create', { id: data.id });
  return ok(res, data);
}));

router.put('/hunts/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_hunts')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ADVERSARY EMULATION / BAS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/emulation/scenarios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_emulation_scenarios')
    .select('*').eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/emulation/scenarios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_emulation_scenarios')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/emulation/scenarios/:id/tests', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_emulation_tests')
    .select('*').eq('scenario_id', req.params.id).eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/emulation/scenarios/:id/run', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: tests } = await supabase.from('nexus_emulation_tests')
    .select('*').eq('scenario_id', req.params.id).eq('tenant_id', tenantId);

  if (!tests || tests.length === 0) return err(res, 'No tests in scenario', 400);

  // Simulate safe-by-design execution
  const results = tests.map(t => ({
    test_id: t.id,
    technique_id: t.technique_id,
    status: t.safe_by_design ? 'passed' : 'skipped',
    detection_status: Math.random() > 0.4 ? 'detected' : 'undetected',
    ran_at: new Date().toISOString(),
  }));

  const detected    = results.filter(r => r.detection_status === 'detected').length;
  const coverage    = Math.round((detected / results.length) * 100);

  const { data: runResult, error } = await supabase.from('nexus_emulation_results')
    .insert({
      tenant_id: tenantId,
      scenario_id: req.params.id,
      total_tests: tests.length,
      passed: results.filter(r => r.status === 'passed').length,
      skipped: results.filter(r => r.status === 'skipped').length,
      detected,
      undetected: results.length - detected,
      coverage_pct: coverage,
      technique_results: results,
      run_at: new Date().toISOString(),
    }).select().single();

  if (error) return err(res, error.message, 500);

  await auditLog(req, 'nexus.emulation.run', { scenario_id: req.params.id, coverage_pct: coverage });
  return ok(res, { run: runResult, coverage_pct: coverage, results });
}));

router.get('/emulation/results', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_emulation_results')
    .select('*, nexus_emulation_scenarios(name)').eq('tenant_id', tenantId)
    .order('run_at', { ascending: false }).limit(50);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  DFIR — FORENSICS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/dfir/cases', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_forensic_cases')
    .select('*').eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/dfir/cases', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_forensic_cases')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.dfir.case_create', { id: data.id });
  return ok(res, data);
}));

router.put('/dfir/cases/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_forensic_cases')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/dfir/cases/:id/artifacts', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_forensic_artifacts')
    .select('*').eq('case_id', req.params.id).eq('tenant_id', tenantId);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/dfir/cases/:id/artifacts', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_forensic_artifacts')
    .insert({ ...req.body, case_id: req.params.id, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// Timeline event append
router.post('/dfir/cases/:id/timeline', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: fc } = await supabase.from('nexus_forensic_cases')
    .select('timeline').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (!fc) return err(res, 'Case not found', 404);

  const timeline = [...(fc.timeline || []), { ...req.body, ts: new Date().toISOString(), analyst: req.user?.email }];

  const { data, error } = await supabase.from('nexus_forensic_cases')
    .update({ timeline, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();

  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  CONNECTORS CATALOG
// ══════════════════════════════════════════════════════════════════════════════
router.get('/connectors', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { category, enabled, search, page = 1, limit = 100 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_connectors').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).range(offset, offset + parseInt(limit) - 1);

  if (category) query = query.eq('category', category);
  if (enabled !== undefined) query = query.eq('enabled', enabled === 'true');
  if (search) query = query.ilike('display_name', `%${search}%`);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/connectors', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_connectors')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.connector.create', { name: data.name });
  return ok(res, data);
}));

router.put('/connectors/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_connectors')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.post('/connectors/:id/run', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: connector } = await supabase.from('nexus_connectors')
    .select('*').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (!connector) return err(res, 'Connector not found', 404);
  if (!connector.enabled) return err(res, 'Connector is disabled', 400);

  // Update last_run_at
  await supabase.from('nexus_connectors')
    .update({ last_run_at: new Date().toISOString(), last_status: 'running', run_count: (connector.run_count || 0) + 1 })
    .eq('id', req.params.id).eq('tenant_id', tenantId);

  await auditLog(req, 'nexus.connector.run', { id: req.params.id, name: connector.name });

  // Connector execution is async — return job ID
  return ok(res, { job_id: `nexus-${connector.id}-${Date.now()}`, status: 'queued', connector: connector.name });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  SCHEDULED JOBS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/jobs', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_scheduled_jobs')
    .select('*').eq('tenant_id', tenantId).order('next_run_at');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/jobs', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_scheduled_jobs')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.put('/jobs/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_scheduled_jobs')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  THREAT-INFORMED DEFENSE (TID) COCKPIT
// ══════════════════════════════════════════════════════════════════════════════
router.get('/tid/coverage', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { tactic, detect_status, page = 1, limit = 200 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_tid_coverage').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).order('adversary_prevalence', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (tactic) query = query.eq('tactic', tactic);
  if (detect_status) query = query.eq('detect_status', detect_status);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.get('/tid/summary', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data, error } = await supabase.from('nexus_tid_coverage')
    .select('tactic, detect_status, test_status, adversary_prevalence, program_score')
    .eq('tenant_id', tenantId);

  if (error) return err(res, error.message, 500);
  const records = data || [];

  const summary = {
    total_techniques: records.length,
    detect_covered: records.filter(r => r.detect_status === 'covered').length,
    detect_partial: records.filter(r => r.detect_status === 'partial').length,
    detect_none: records.filter(r => r.detect_status === 'none').length,
    false_coverage: records.filter(r => r.detect_status === 'false_coverage').length,
    test_validated: records.filter(r => r.test_status === 'validated').length,
    test_executed: records.filter(r => r.test_status === 'executed').length,
    detection_drift: records.filter(r => r.detection_drift).length,
    avg_program_score: records.length > 0 ? records.reduce((s, r) => s + (r.program_score || 0), 0) / records.length : 0,
    by_tactic: {},
  };

  records.forEach(r => {
    if (!summary.by_tactic[r.tactic]) summary.by_tactic[r.tactic] = { total: 0, covered: 0 };
    summary.by_tactic[r.tactic].total++;
    if (r.detect_status === 'covered') summary.by_tactic[r.tactic].covered++;
  });

  return ok(res, summary);
}));

router.put('/tid/coverage/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_tid_coverage')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ATT&CK Navigator layer export
router.get('/tid/navigator-export', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data } = await supabase.from('nexus_tid_coverage')
    .select('technique_id, detect_status, adversary_prevalence, program_score')
    .eq('tenant_id', tenantId);

  const colorMap = { covered: '#00cc00', partial: '#ffaa00', none: '#cccccc', false_coverage: '#ff0000', drift: '#ff6600' };

  const layer = {
    name: 'Wadjet Nexus TID Coverage',
    versions: { attack: '14', navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Generated by Wadjet Nexus Threat-Informed Defense Cockpit',
    techniques: (data || []).map(t => ({
      techniqueID: t.technique_id,
      color: colorMap[t.detect_status] || '#cccccc',
      score: Math.round((t.adversary_prevalence || 0) * 100),
      comment: `Status: ${t.detect_status} | Program: ${Math.round(t.program_score || 0)}%`,
    })),
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="nexus_tid_layer.json"');
  return res.json(layer);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  EBIOS RM
// ══════════════════════════════════════════════════════════════════════════════
router.get('/ebios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ebios_studies').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/ebios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ebios_studies')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.put('/ebios/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ebios_studies')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  NIST 800-30
// ══════════════════════════════════════════════════════════════════════════════
router.get('/nist-800-30', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_nist_assessments').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/nist-800-30', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_nist_assessments')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  CRISIS MANAGEMENT & TABLETOP EXERCISES
// ══════════════════════════════════════════════════════════════════════════════
router.get('/crisis/scenarios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_crisis_scenarios').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/crisis/scenarios', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_crisis_scenarios')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/crisis/exercises', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_crisis_exercises')
    .select('*, nexus_crisis_scenarios(name, scenario_type)')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/crisis/exercises', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_crisis_exercises')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.crisis.exercise_create', { id: data.id });
  return ok(res, data);
}));

// Launch exercise from scenario
router.post('/crisis/scenarios/:id/launch-exercise', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const { data: scenario } = await supabase.from('nexus_crisis_scenarios')
    .select('*').eq('id', req.params.id).eq('tenant_id', tenantId).maybeSingle();

  if (!scenario) return err(res, 'Scenario not found', 404);

  const { data, error } = await supabase.from('nexus_crisis_exercises')
    .insert({
      tenant_id: tenantId,
      scenario_id: scenario.id,
      title: `${scenario.name} — Tabletop Exercise`,
      status: 'planned',
      participants: scenario.participants || [],
    }).select().single();

  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.crisis.exercise_launch', { exercise_id: data.id, scenario_id: req.params.id });
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  RANSOMWARE SCENARIO (FAIR + ATT&CK)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/ransomware', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ransomware_scenarios').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/ransomware/compute', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { threat_actor, ttps = [], aro_estimate = 0.1 } = req.body;

  const { data: assets } = await supabase.from('asset_inventory')
    .select('id, hostname, business_value, criticality, internet_exposed')
    .eq('tenant_id', tenantId).eq('criticality', 'critical');

  const affectedAssets = (assets || []).map(a => ({
    asset_id: a.id,
    asset_name: a.hostname || 'Unknown',
    value_at_risk: a.business_value || 100000,
    internet_exposed: a.internet_exposed,
  }));

  const totalAssetValue = affectedAssets.reduce((s, a) => s + a.value_at_risk, 0);
  const ransomEstimate  = totalAssetValue * 0.05;  // 5% of asset value
  const recoveryCost    = totalAssetValue * 0.03;
  const sle = totalAssetValue + ransomEstimate + recoveryCost;
  const ale = sle * aro_estimate;
  const residual = ale * 0.6;  // 40% reduction with backups + segmentation

  const { data, error } = await supabase.from('nexus_ransomware_scenarios')
    .insert({
      tenant_id: tenantId,
      threat_actor: threat_actor || 'Generic Ransomware',
      ttps,
      affected_assets: affectedAssets,
      total_sle: sle,
      total_ale: ale,
      residual_with_controls: residual,
      ransom_estimate: ransomEstimate,
      recovery_cost: recoveryCost,
      aro_estimate,
      blast_radius_count: affectedAssets.length,
      computed_at: new Date().toISOString(),
    }).select().single();

  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.ransomware.compute', { id: data.id, ale });
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ADVERSARY OPPORTUNITY INDEX (AOI)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/aoi', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_aoi_records')
    .select('*').eq('tenant_id', tenantId).order('computed_at', { ascending: false }).limit(30);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/aoi/compute', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const [pathsRes, vulnRes] = await Promise.all([
    supabase.from('nexus_attack_paths').select('path_cost, choke_point_ids, blast_radius').eq('tenant_id', tenantId),
    supabase.from('nexus_asset_vulnerabilities')
      .select('fusion_score, nexus_vulnerabilities(is_kev, cvss_score)')
      .eq('tenant_id', tenantId).eq('status', 'open'),
  ]);

  const paths = pathsRes.data || [];
  const vulns = vulnRes.data || [];

  // AOI = sum of (path opportunities weighted by exploitability × blast_radius) / normalization
  const aoiRaw = paths.reduce((sum, p) => sum + ((p.blast_radius || 0) * 0.5 + (p.path_cost || 0) * 0.3), 0)
    + vulns.reduce((sum, v) => sum + ((v.nexus_vulnerabilities?.is_kev ? 50 : 0) + (v.fusion_score || 0)), 0);

  const aoiScore = Math.min(1000, Math.round(aoiRaw / 10));

  const chokePoints = [...new Set(paths.flatMap(p => p.choke_point_ids || []))].slice(0, 10);

  const { data, error } = await supabase.from('nexus_aoi_records')
    .insert({
      tenant_id: tenantId,
      aoi_score: aoiScore,
      choke_points: chokePoints,
      attack_path_gaps: paths.slice(0, 5),
      computed_at: new Date().toISOString(),
    }).select().single();

  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  INSURANCE READINESS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/insurance-readiness', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_insurance_readiness')
    .select('*').eq('tenant_id', tenantId).order('computed_at', { ascending: false }).limit(1).maybeSingle();
  if (error) return err(res, error.message, 500);
  return ok(res, data || {});
}));

router.post('/insurance-readiness/assess', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { controls_status = {}, policy_limit, renewal_date, insurer } = req.body;

  const controlsChecked = Object.values(controls_status).filter(v => v === true).length;
  const totalControls   = 7;  // MFA, backups, EDR/SIEM, PAM, patching, tested IR, segmentation
  const overallScore    = Math.round((controlsChecked / totalControls) * 100);

  // Fetch FAIR ransomware ALE
  const { data: ransomwareRes } = await supabase.from('nexus_ransomware_scenarios')
    .select('total_ale').eq('tenant_id', tenantId).order('computed_at', { ascending: false }).limit(1).maybeSingle();

  const fairLoss = ransomwareRes?.total_ale || 0;
  const coverageAdequate = policy_limit ? policy_limit >= fairLoss : false;

  const { data, error } = await supabase.from('nexus_insurance_readiness')
    .insert({
      tenant_id: tenantId,
      overall_score: overallScore,
      controls_status,
      policy_limit,
      fair_ransomware_loss: fairLoss,
      coverage_adequate: coverageAdequate,
      renewal_date,
      insurer,
      computed_at: new Date().toISOString(),
    }).select().single();

  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  AI GUARDRAILS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/ai-guardrails', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ai_guardrail_assessments')
    .select('*, asset_inventory(hostname, ip_address)')
    .eq('tenant_id', tenantId).order('score');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/ai-guardrails', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ai_guardrail_assessments')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  POLICIES & DOCUMENTS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/policies', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { status, framework, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_policies').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).order('updated_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (status) query = query.eq('status', status);
  if (framework) query = query.eq('framework', framework);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/policies', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_policies')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.policy.create', { id: data.id, title: data.title });
  return ok(res, data);
}));

router.put('/policies/:id', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_policies')
    .update({ ...req.body, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).eq('tenant_id', tenantId).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  PQCMM — POST-QUANTUM READINESS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/pqcmm', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_pqcmm_assessments').select('*')
    .eq('tenant_id', tenantId).order('current_level');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/pqcmm', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_pqcmm_assessments')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  BIA — BUSINESS IMPACT ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/bia', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_bia_entries').select('*')
    .eq('tenant_id', tenantId).order('criticality');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/bia', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_bia_entries')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// BIA dependency graph
router.get('/bia/graph', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data } = await supabase.from('nexus_bia_entries').select('*').eq('tenant_id', tenantId);

  const nodes = (data || []).map(e => ({
    id: e.id,
    label: e.name,
    criticality: e.criticality,
    rto: e.rto_hours,
    rpo: e.rpo_hours,
    financial_impact: e.financial_impact,
  }));

  const edges = [];
  (data || []).forEach(e => {
    (e.dependencies || []).forEach(depId => {
      edges.push({ source: e.id, target: depId, type: 'depends_on' });
    });
  });

  return ok(res, { nodes, edges });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  CONFIGURATION MANAGEMENT (OVAL)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/config-baselines', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_config_baselines').select('*')
    .eq('tenant_id', tenantId).order('health_score');
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/config-baselines', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_config_baselines')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  PENTEST ENGAGEMENTS
// ══════════════════════════════════════════════════════════════════════════════
router.get('/pentest', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_pentest_engagements').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/pentest', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_pentest_engagements')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  await auditLog(req, 'nexus.pentest.create', { id: data.id, title: data.title });
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  IDENTITY MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
router.get('/identities', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { identity_type, is_stale, page = 1, limit = 100 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const supabase = getSupabase();

  let query = supabase.from('nexus_identities').select('*', { count: 'exact' })
    .eq('tenant_id', tenantId).range(offset, offset + parseInt(limit) - 1);

  if (identity_type) query = query.eq('identity_type', identity_type);
  if (is_stale === 'true') query = query.eq('is_stale', true);

  const { data, error, count } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data, { total: count });
}));

router.post('/identities', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_identities')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  CTEM EXPOSURE TAXONOMY
// ══════════════════════════════════════════════════════════════════════════════
router.get('/ctem', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { stage, severity } = req.query;
  const supabase = getSupabase();

  let query = supabase.from('nexus_ctem_exposures')
    .select('*, asset_inventory(hostname, ip_address)')
    .eq('tenant_id', tenantId);

  if (stage) query = query.eq('stage', stage);
  if (severity) query = query.eq('severity', severity);

  const { data, error } = await query;
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/ctem', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_ctem_exposures')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  FAIR-MAM MATERIALITY
// ══════════════════════════════════════════════════════════════════════════════
router.get('/fair-mam', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_fair_mam_assessments').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/fair-mam', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { cost_categories = {}, materiality_threshold, ...rest } = req.body;

  // Compute PERT-based expected SLE from 10 cost categories
  let expectedSle = 0;
  let primaryLoss = 0;
  let secondaryLoss = 0;

  Object.entries(cost_categories).forEach(([cat, vals]) => {
    if (vals && vals.min !== undefined) {
      const pert = (vals.min + 4 * vals.most_likely + vals.max) / 6;
      expectedSle += pert;
      if (['incident_response', 'asset_restoration', 'business_interruption', 'cyber_extortion'].includes(cat)) {
        primaryLoss += pert;
      } else {
        secondaryLoss += pert;
      }
    }
  });

  const isMaterial = materiality_threshold ? expectedSle >= materiality_threshold : false;

  const { data, error } = await supabase.from('nexus_fair_mam_assessments')
    .insert({ ...rest, tenant_id: tenantId, cost_categories, materiality_threshold, expected_sle: expectedSle, primary_loss: primaryLoss, secondary_loss: secondaryLoss, is_material: isMaterial })
    .select().single();

  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  BUG BOUNTY
// ══════════════════════════════════════════════════════════════════════════════
router.get('/bug-bounty/programs', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_bug_bounty_programs').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/bug-bounty/programs', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_bug_bounty_programs')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

router.get('/bug-bounty/submissions', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_bug_bounty_submissions')
    .select('*, nexus_bug_bounty_programs(name)')
    .eq('tenant_id', tenantId).order('submitted_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  ATTACK SURFACE DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════
router.get('/discovery', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_discovery_runs')
    .select('*').eq('tenant_id', tenantId).order('created_at', { ascending: false }).limit(20);
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/discovery/run', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { seed_domain, run_mode = 'simulate' } = req.body;

  if (!seed_domain) return err(res, 'seed_domain is required', 400);

  // Create discovery run record
  const { data: run, error } = await supabase.from('nexus_discovery_runs')
    .insert({
      tenant_id: tenantId,
      seed_domain,
      status: 'running',
      run_mode,
      tools_used: run_mode === 'simulate' ? ['simulate'] : ['subfinder', 'theHarvester', 'httpx', 'nmap'],
      started_at: new Date().toISOString(),
    }).select().single();

  if (error) return err(res, error.message, 500);

  // In simulate mode, generate mock results
  if (run_mode === 'simulate') {
    const mockResults = [
      { host: `www.${seed_domain}`, ip: '1.2.3.4', ports: [80, 443], services: ['http', 'https'] },
      { host: `api.${seed_domain}`, ip: '1.2.3.5', ports: [443, 8080], services: ['https', 'http-alt'] },
      { host: `mail.${seed_domain}`, ip: '1.2.3.6', ports: [25, 587], services: ['smtp', 'submission'] },
    ];

    await supabase.from('nexus_discovery_runs')
      .update({ status: 'completed', discovered_hosts: mockResults.length, new_assets: 2, results: mockResults, completed_at: new Date().toISOString() })
      .eq('id', run.id).eq('tenant_id', tenantId);

    await auditLog(req, 'nexus.discovery.run', { id: run.id, seed_domain, mode: run_mode });
    return ok(res, { run_id: run.id, status: 'completed', discovered: mockResults });
  }

  await auditLog(req, 'nexus.discovery.run', { id: run.id, seed_domain, mode: run_mode });
  return ok(res, { run_id: run.id, status: 'running', message: 'Discovery run queued' });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  THREAT MODELING (STRIDE)
// ══════════════════════════════════════════════════════════════════════════════
router.get('/threat-models', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_threat_models').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/threat-models', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_threat_models')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  SEED — default data for new tenants
// ══════════════════════════════════════════════════════════════════════════════
router.post('/seed', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  // Only ADMIN can seed
  if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user?.role)) {
    return err(res, 'Insufficient permissions', 403);
  }

  const seeded = { voc_policy: false, connectors: false, sigma_rules: false, crisis_scenarios: false };

  // Default VOC policy
  const vocResult = await supabase.from('nexus_voc_policies')
    .upsert([{ tenant_id: tenantId, name: 'Default SLA Policy', critical_days: 7, high_days: 30, medium_days: 90, low_days: 180, informational_days: 365, active: true }], { onConflict: 'tenant_id,name', ignoreDuplicates: true });
  seeded.voc_policy = !vocResult.error;

  // Default crisis scenarios
  const scenarios = [
    { tenant_id: tenantId, name: 'Ransomware Attack', scenario_type: 'ransomware', description: 'Organization-wide ransomware deployment scenario' },
    { tenant_id: tenantId, name: 'Data Breach', scenario_type: 'data_breach', description: 'Sensitive data exfiltration and public disclosure' },
    { tenant_id: tenantId, name: 'DDoS Attack', scenario_type: 'ddos', description: 'Large-scale distributed denial of service' },
    { tenant_id: tenantId, name: 'Insider Threat', scenario_type: 'insider', description: 'Malicious insider data theft or sabotage' },
    { tenant_id: tenantId, name: 'Supply Chain Compromise', scenario_type: 'supply_chain', description: 'Third-party software supply chain attack' },
    { tenant_id: tenantId, name: 'Business Email Compromise', scenario_type: 'bec', description: 'Executive email fraud and wire transfer' },
  ];
  const crisisResult = await supabase.from('nexus_crisis_scenarios').upsert(scenarios, { onConflict: 'tenant_id,name', ignoreDuplicates: true });
  seeded.crisis_scenarios = !crisisResult.error;

  await auditLog(req, 'nexus.seed', seeded);
  return ok(res, { seeded, message: 'Default data seeded for Wadjet Nexus module' });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  KILL CHAIN VISUALIZATION DATA
// ══════════════════════════════════════════════════════════════════════════════
router.get('/kill-chain', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const { actor } = req.query;
  const supabase = getSupabase();

  const attackPhases = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
  ];

  const { data: tidData } = await supabase.from('nexus_tid_coverage')
    .select('technique_id, tactic, detect_status, adversary_prevalence')
    .eq('tenant_id', tenantId);

  const phaseData = attackPhases.map(phase => {
    const phaseTacticKey = phase.toLowerCase().replace(/\s+/g, '-');
    const techniques = (tidData || []).filter(t => {
      const tactic = (t.tactic || '').toLowerCase().replace(/\s+/g, '-');
      return tactic === phaseTacticKey || tactic.includes(phaseTacticKey.substring(0, 8));
    });

    return {
      phase,
      technique_count: techniques.length,
      covered: techniques.filter(t => t.detect_status === 'covered').length,
      uncovered: techniques.filter(t => t.detect_status === 'none').length,
      techniques: techniques.slice(0, 5),
    };
  });

  return ok(res, { phases: phaseData, actor: actor || 'generic' });
}));

// ══════════════════════════════════════════════════════════════════════════════
//  YARA RULES
// ══════════════════════════════════════════════════════════════════════════════
router.get('/yara-rules', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_yara_rules').select('*')
    .eq('tenant_id', tenantId).order('created_at', { ascending: false });
  if (error) return err(res, error.message, 500);
  return ok(res, data || []);
}));

router.post('/yara-rules', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();
  const { data, error } = await supabase.from('nexus_yara_rules')
    .insert({ ...req.body, tenant_id: tenantId }).select().single();
  if (error) return err(res, error.message, 500);
  return ok(res, data);
}));

// ══════════════════════════════════════════════════════════════════════════════
//  VM EXECUTIVE REPORT DATA
// ══════════════════════════════════════════════════════════════════════════════
router.get('/vm-report', asyncHandler(async (req, res) => {
  const tenantId = getTenant(req);
  const supabase = getSupabase();

  const [vulnRes, riskRes, vocRes] = await Promise.all([
    supabase.from('nexus_vulnerabilities').select('severity, is_kev, cvss_score, created_at').eq('tenant_id', tenantId),
    supabase.from('nexus_risk_scores').select('*').eq('tenant_id', tenantId).order('computed_at', { ascending: false }).limit(10),
    supabase.from('nexus_voc_policies').select('*').eq('tenant_id', tenantId).eq('active', true).limit(1).maybeSingle(),
  ]);

  const vulns = vulnRes.data || [];
  const riskHistory = riskRes.data || [];

  const report = {
    generated_at: new Date().toISOString(),
    summary: {
      total_vulns: vulns.length,
      critical: vulns.filter(v => v.severity === 'critical').length,
      high: vulns.filter(v => v.severity === 'high').length,
      kev_count: vulns.filter(v => v.is_kev).length,
      avg_cvss: vulns.length > 0 ? (vulns.reduce((s, v) => s + (v.cvss_score || 0), 0) / vulns.length).toFixed(2) : '0.00',
    },
    risk_trend: riskHistory.map(r => ({ score: r.enterprise_risk_score, date: r.computed_at })),
    sla_policy: vocRes.data,
    executive_narrative: `Your organization currently has ${vulns.length} tracked vulnerabilities across your asset estate. ` +
      `${vulns.filter(v => v.is_kev).length} are actively exploited (CISA KEV) requiring immediate attention. ` +
      `The enterprise risk score trend ${riskHistory.length > 1 && riskHistory[0].enterprise_risk_score < riskHistory[riskHistory.length - 1].enterprise_risk_score ? 'shows improvement' : 'requires focus'}.`,
  };

  return ok(res, report);
}));

module.exports = router;
