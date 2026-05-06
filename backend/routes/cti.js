/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — CTI REST API Routes v3.0
 *  backend/routes/cti.js
 *
 *  Endpoints:
 *   Threat Actors   GET/POST/PATCH/DELETE /api/cti/actors
 *   Campaigns       GET/POST/PATCH/DELETE /api/cti/campaigns
 *   Vulnerabilities GET/POST/PATCH/DELETE /api/cti/vulnerabilities
 *   MITRE Techniques GET /api/cti/mitre
 *   Relationships   GET/POST/DELETE /api/cti/relationships
 *   Feed Logs       GET /api/cti/feed-logs
 *   Detection Timeline GET /api/cti/timeline
 *   Ingestion Trigger POST /api/cti/ingest/:feed
 *   AI Agent Query  POST /api/cti/ai/query
 *   Risk Score      POST /api/cti/risk-score
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const express    = require('express');
const router     = express.Router();
const { supabase } = require('../config/supabase');
const { verifyToken } = require('../middleware/auth');

// ── Apply authentication to ALL /api/cti/* routes ────────
// FIX: Without this guard req.tenantId was undefined on every handler,
// causing all Supabase queries to silently return 0 rows (404-like).
// Every CTI endpoint requires a valid JWT — unauthenticated requests
// get a structured 401 before any DB query is attempted.
router.use(verifyToken);

// ── Helpers ──────────────────────────────────────────────
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function createError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function paginate(req) {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(200, parseInt(req.query.limit) || 50);
  return { page, limit, from: (page - 1) * limit, to: (page - 1) * limit + limit - 1 };
}

// ══════════════════════════════════════════════════════════
//  THREAT ACTORS
// ══════════════════════════════════════════════════════════

// GET /api/cti/actors
router.get('/actors', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  let q = supabase
    .from('threat_actors')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('updated_at', { ascending: false })
    .range(from, to);

  if (req.query.search) {
    q = q.ilike('name', `%${req.query.search}%`);
  }
  if (req.query.motivation) {
    q = q.eq('motivation', req.query.motivation);
  }
  if (req.query.sophistication) {
    q = q.eq('sophistication', req.query.sophistication);
  }
  if (req.query.origin_country) {
    q = q.eq('origin_country', req.query.origin_country);
  }
  if (req.query.active_only === 'true') {
    const d30 = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
    q = q.gte('last_seen', d30);
  }

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit });
}));

// GET /api/cti/actors/:id
router.get('/actors/:id', asyncHandler(async (req, res) => {
  const tid = req.tenantId;
  const { data, error } = await supabase
    .from('threat_actors')
    .select('*, campaigns(*), iocs(id, value, type, risk_score, reputation, last_seen)')
    .eq('id', req.params.id)
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .single();

  if (error || !data) throw createError(404, 'Threat actor not found');
  res.json(data);
}));

// POST /api/cti/actors
router.post('/actors', asyncHandler(async (req, res) => {
  const { name, description, motivation, sophistication, origin_country,
          active_since, target_sectors, target_countries, ttps, tools,
          malware, aliases, tags, confidence, external_id } = req.body;

  if (!name) throw createError(400, 'name is required');

  const { data, error } = await supabase
    .from('threat_actors')
    .insert({
      tenant_id: req.tenantId,
      name, description, motivation, sophistication,
      origin_country, active_since, target_sectors: target_sectors || [],
      target_countries: target_countries || [], ttps: ttps || [],
      tools: tools || [], malware: malware || [],
      aliases: aliases || [], tags: tags || [],
      confidence: confidence || 50, external_id,
      source: 'manual',
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

// PATCH /api/cti/actors/:id
router.patch('/actors/:id', asyncHandler(async (req, res) => {
  const allowed = ['name','description','motivation','sophistication','origin_country',
    'active_since','last_seen','target_sectors','target_countries','ttps','tools',
    'malware','aliases','tags','confidence','external_id'];
  const updates = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) updates[k] = req.body[k];
  }
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('threat_actors')
    .update(updates)
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Actor not found or access denied');
  res.json(data);
}));

// DELETE /api/cti/actors/:id
router.delete('/actors/:id', asyncHandler(async (req, res) => {
  const { error } = await supabase
    .from('threat_actors')
    .delete()
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId);

  if (error) throw createError(500, error.message);
  res.status(204).send();
}));

// ══════════════════════════════════════════════════════════
//  CAMPAIGNS
// ══════════════════════════════════════════════════════════

// GET /api/cti/campaigns
router.get('/campaigns', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  let q = supabase
    .from('campaigns')
    .select('*, threat_actors(id, name, origin_country, sophistication)', { count: 'exact' })
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('updated_at', { ascending: false })
    .range(from, to);

  if (req.query.status)   q = q.eq('status', req.query.status);
  if (req.query.actor_id) q = q.eq('actor_id', req.query.actor_id);
  if (req.query.search)   q = q.ilike('name', `%${req.query.search}%`);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit });
}));

// GET /api/cti/campaigns/:id
router.get('/campaigns/:id', asyncHandler(async (req, res) => {
  const tid = req.tenantId;
  const { data, error } = await supabase
    .from('campaigns')
    .select(`
      *,
      threat_actors(id, name, origin_country, sophistication, motivation),
      iocs(id, value, type, risk_score, reputation, country, last_seen)
    `)
    .eq('id', req.params.id)
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .single();

  if (error || !data) throw createError(404, 'Campaign not found');
  res.json(data);
}));

// POST /api/cti/campaigns
router.post('/campaigns', asyncHandler(async (req, res) => {
  const { name, description, status, actor_id, start_date, end_date,
          target_sectors, target_countries, ttps, malware, tags,
          confidence, external_id } = req.body;

  if (!name) throw createError(400, 'name is required');

  const { data, error } = await supabase
    .from('campaigns')
    .insert({
      tenant_id: req.tenantId,
      name, description, status: status || 'active',
      actor_id, start_date, end_date,
      target_sectors: target_sectors || [],
      target_countries: target_countries || [],
      ttps: ttps || [], malware: malware || [],
      tags: tags || [], confidence: confidence || 50,
      external_id, source: 'manual',
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

// PATCH /api/cti/campaigns/:id
router.patch('/campaigns/:id', asyncHandler(async (req, res) => {
  const allowed = ['name','description','status','actor_id','start_date','end_date',
    'target_sectors','target_countries','ttps','malware','tags','confidence','external_id','ioc_count'];
  const updates = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) updates[k] = req.body[k];
  }
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('campaigns')
    .update(updates)
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Campaign not found or access denied');
  res.json(data);
}));

// DELETE /api/cti/campaigns/:id
router.delete('/campaigns/:id', asyncHandler(async (req, res) => {
  const { error } = await supabase
    .from('campaigns')
    .delete()
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId);

  if (error) throw createError(500, error.message);
  res.status(204).send();
}));

// ══════════════════════════════════════════════════════════
//  VULNERABILITIES (CVE data)
// ══════════════════════════════════════════════════════════

// GET /api/cti/vulnerabilities
router.get('/vulnerabilities', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  let q = supabase
    .from('vulnerabilities')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('cvss_v3_score', { ascending: false })
    .range(from, to);

  if (req.query.severity) q = q.eq('severity', req.query.severity);
  if (req.query.exploited !== undefined) q = q.eq('exploited_in_wild', req.query.exploited === 'true');
  if (req.query.search)   q = q.or(`cve_id.ilike.%${req.query.search}%,description.ilike.%${req.query.search}%`);
  if (req.query.min_cvss) q = q.gte('cvss_v3_score', parseFloat(req.query.min_cvss));

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit });
}));

// GET /api/cti/vulnerabilities/:id
router.get('/vulnerabilities/:id', asyncHandler(async (req, res) => {
  // Accept either DB UUID or CVE ID
  const isCVE = /^cve-/i.test(req.params.id);
  const q = supabase
    .from('vulnerabilities')
    .select('*')
    .eq(isCVE ? 'cve_id' : 'id', req.params.id)
    .single();

  const { data, error } = await q;
  if (error || !data) throw createError(404, 'Vulnerability not found');
  res.json(data);
}));

// POST /api/cti/vulnerabilities
router.post('/vulnerabilities/sync', asyncHandler(async (req, res) => {
  const { cve_id, description, severity, cvss_score, cvss_vector,
          affected_products, references, patch_available, exploited_in_wild,
          threat_actors, campaigns, mitre_techniques, tags } = req.body;

  if (!cve_id) throw createError(400, 'cve_id is required');

  const { data, error } = await supabase
    .from('vulnerabilities')
    .insert({
      tenant_id: req.tenantId,
      cve_id: cve_id.toUpperCase(),
      description, severity,
      cvss_score: cvss_score || 0,
      cvss_vector, affected_products: affected_products || [],
      references: references || [],
      patch_available: patch_available || false,
      exploited_in_wild: exploited_in_wild || false,
      threat_actors: threat_actors || [],
      campaigns: campaigns || [],
      mitre_techniques: mitre_techniques || [],
      tags: tags || [],
      source: 'manual',
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

// ══════════════════════════════════════════════════════════
//  MITRE ATT&CK TECHNIQUES
// ══════════════════════════════════════════════════════════

// GET /api/cti/mitre
router.get('/mitre', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  let q = supabase
    .from('mitre_techniques')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('technique_id')
    .range(from, to);

  if (req.query.tactic)  q = q.contains('tactics', [req.query.tactic]);
  if (req.query.search)  q = q.or(`technique_id.ilike.%${req.query.search}%,name.ilike.%${req.query.search}%`);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit });
}));

// GET /api/cti/mitre/coverage — aggregate coverage stats per tenant
router.get('/mitre/coverage', asyncHandler(async (req, res) => {
  const tid = req.tenantId;

  // Count alerts grouped by MITRE technique
  const { data: alertData, error: aErr } = await supabase
    .from('alerts')
    .select('mitre_technique')
    .eq('tenant_id', tid)
    .not('mitre_technique', 'is', null);

  if (aErr) throw createError(500, aErr.message);

  // Build coverage map
  const coverage = {};
  for (const a of (alertData || [])) {
    if (a.mitre_technique) {
      coverage[a.mitre_technique] = (coverage[a.mitre_technique] || 0) + 1;
    }
  }

  // Get technique details for covered items
  const techniques = Object.keys(coverage);
  let details = [];
  if (techniques.length > 0) {
    const { data } = await supabase
      .from('mitre_techniques')
      .select('technique_id, name, tactics, description')
      .in('technique_id', techniques);
    details = data || [];
  }

  const coverageWithDetails = details.map(t => ({
    ...t,
    alert_count: coverage[t.technique_id] || 0,
  }));

  // Tactic breakdown
  const tacticBreakdown = {};
  for (const t of coverageWithDetails) {
    for (const tactic of (t.tactics || [])) {
      if (!tacticBreakdown[tactic]) tacticBreakdown[tactic] = { covered: 0, alert_count: 0 };
      tacticBreakdown[tactic].covered++;
      tacticBreakdown[tactic].alert_count += t.alert_count;
    }
  }

  res.json({
    total_covered: techniques.length,
    techniques: coverageWithDetails,
    tactic_breakdown: tacticBreakdown,
  });
}));

// ══════════════════════════════════════════════════════════
//  IOC RELATIONSHIPS (graph edges)
// ══════════════════════════════════════════════════════════

// GET /api/cti/relationships
router.get('/relationships', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  let q = supabase
    .from('ioc_relationships')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tid)
    .order('created_at', { ascending: false })
    .range(from, to);

  if (req.query.source_id) q = q.eq('source_id', req.query.source_id);
  if (req.query.rel_type)  q = q.eq('relationship_type', req.query.rel_type);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit });
}));

// POST /api/cti/relationships
router.post('/relationships', asyncHandler(async (req, res) => {
  const { source_id, source_type, target_id, target_type, relationship_type, confidence, metadata } = req.body;

  if (!source_id || !target_id || !relationship_type) {
    throw createError(400, 'source_id, target_id, relationship_type required');
  }

  const { data, error } = await supabase
    .from('ioc_relationships')
    .insert({
      tenant_id: req.tenantId,
      source_id, source_type: source_type || 'ioc',
      target_id, target_type: target_type || 'ioc',
      relationship_type,
      confidence: confidence || 50,
      metadata: metadata || {},
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

// GET /api/cti/relationships/graph — graph data for visualisation
router.get('/relationships/graph', asyncHandler(async (req, res) => {
  const tid = req.tenantId;
  const limit = Math.min(500, parseInt(req.query.limit) || 200);

  // Fetch top IOCs by risk score
  const { data: iocs } = await supabase
    .from('iocs')
    .select('id, value, type, risk_score, reputation, threat_actor, malware_family')
    .eq('tenant_id', tid)
    .order('risk_score', { ascending: false })
    .limit(100);

  // Fetch relationships
  const { data: rels } = await supabase
    .from('ioc_relationships')
    .select('*')
    .eq('tenant_id', tid)
    .order('confidence', { ascending: false })
    .limit(limit);

  // Fetch top actors
  const { data: actors } = await supabase
    .from('threat_actors')
    .select('id, name, sophistication, motivation')
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .limit(20);

  // Build nodes + edges for force graph
  const nodes = [];
  const nodeSet = new Set();

  const addNode = (id, label, type, data = {}) => {
    if (!nodeSet.has(id)) {
      nodeSet.add(id);
      nodes.push({ id, label, type, ...data });
    }
  };

  for (const ioc of (iocs || [])) {
    addNode(ioc.id, ioc.value, ioc.type, {
      risk_score: ioc.risk_score,
      reputation: ioc.reputation,
    });
  }
  for (const actor of (actors || [])) {
    addNode(actor.id, actor.name, 'actor', {
      sophistication: actor.sophistication,
      motivation: actor.motivation,
    });
  }

  const edges = (rels || []).map(r => ({
    source: r.source_id,
    target: r.target_id,
    type: r.relationship_type,
    confidence: r.confidence,
  }));

  res.json({ nodes, edges, ioc_count: iocs?.length || 0, actor_count: actors?.length || 0 });
}));

// ══════════════════════════════════════════════════════════
//  FEED LOGS
// ══════════════════════════════════════════════════════════

// GET /api/cti/feed-logs
// NOTE: Two tables exist for feed logs:
//   feed_logs     — written by services/ingestion/index.js (OTX, AbuseIPDB, URLhaus, etc.)
//   cti_feed_logs — written by routes/ioc-ingestion.js v5.2 (same feeds, newer path)
// We query both tables and merge results to provide a complete view.
router.get('/feed-logs', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  // Build base query filters
  const buildQuery = (table) => {
    let q = supabase
      .from(table)
      .select('*', { count: 'exact' })
      .eq('tenant_id', tid)
      .order('finished_at', { ascending: false })
      .range(from, to);
    if (req.query.status)    q = q.eq('status', req.query.status);
    if (req.query.feed_name) q = q.eq('feed_name', req.query.feed_name);
    return q;
  };

  // Query both tables in parallel; ignore errors on tables that don't exist yet
  const [legacyRes, newRes] = await Promise.allSettled([
    buildQuery('feed_logs'),
    buildQuery('cti_feed_logs'),
  ]);

  const legacyData = (legacyRes.status === 'fulfilled' && !legacyRes.value.error)
    ? legacyRes.value.data || [] : [];
  const newData    = (newRes.status === 'fulfilled' && !newRes.value.error)
    ? newRes.value.data || [] : [];

  // Merge: deduplicate by (feed_name + finished_at) — prefer cti_feed_logs entries
  const seen = new Map();
  for (const row of [...newData, ...legacyData]) {
    const key = `${row.feed_name}:${row.finished_at}`;
    if (!seen.has(key)) seen.set(key, row);
  }
  const data = [...seen.values()]
    .sort((a, b) => new Date(b.finished_at) - new Date(a.finished_at))
    .slice(from, to + 1);

  const total = seen.size;

  // Summary stats: latest run per feed
  const latest = {};
  for (const log of data) {
    if (!latest[log.feed_name]) latest[log.feed_name] = log;
  }

  res.json({
    data,
    total,
    page, limit,
    feed_status: Object.values(latest),
  });
}));

// ══════════════════════════════════════════════════════════
//  DETECTION TIMELINE
// ══════════════════════════════════════════════════════════

// GET /api/cti/timeline
router.get('/timeline', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  const days = Math.min(90, parseInt(req.query.days) || 7);
  const since = new Date(Date.now() - days * 86400000).toISOString();

  let q = supabase
    .from('detection_timeline')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tid)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .range(from, to);

  if (req.query.severity)   q = q.eq('severity', req.query.severity);
  if (req.query.event_type) q = q.eq('event_type', req.query.event_type);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({ data: data || [], total: count || 0, page, limit, days });
}));

// GET /api/cti/detection-timeline  (alias for /api/cti/timeline)
router.get('/detection-timeline', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = req.tenantId;

  const days = Math.min(90, parseInt(req.query.days) || 7);
  const since = new Date(Date.now() - days * 86400000).toISOString();

  let q = supabase
    .from('detection_timeline')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tid)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .range(from, to);

  if (req.query.severity)   q = q.eq('severity', req.query.severity);
  if (req.query.event_type) q = q.eq('event_type', req.query.event_type);

  const { data, error, count } = await q;
  // If table doesn't exist yet, return empty gracefully
  if (error) {
    console.warn('[CTI] detection_timeline query error:', error.message);
    return res.json({ data: [], total: 0, page, limit, days });
  }

  res.json({ data: data || [], total: count || 0, page, limit, days });
}));

// ══════════════════════════════════════════════════════════
//  DETECTIONS — /api/cti/detections
//  Frontend live-detections-soc.js calls:
//    GET  /cti/detections?limit=200
//    GET  /cti/detections?limit=10&sort=created_at&order=desc
//    POST /cti/detections/:id/correlate
//
//  This maps to the iocs table (live detections with risk data)
//  since a dedicated detections table may not exist yet.
//  Falls back gracefully so the UI never sees a 500.
// ══════════════════════════════════════════════════════════

// GET /api/cti/detections
router.get('/detections', asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid  = req.tenantId;
  const sort  = req.query.sort  || 'created_at';
  const order = req.query.order === 'asc';

  // Filter params
  const severity   = req.query.severity;
  const status     = req.query.status;
  const type       = req.query.type;
  const search     = req.query.search;
  const fromDate   = req.query.from;
  const toDate     = req.query.to;

  // Primary: try a dedicate detections table (if it exists)
  // Secondary: fall back to iocs with risk enrichment as detection feed
  let q = supabase
    .from('iocs')
    .select('id, value, type, reputation, risk_score, status, threat_actor, tags, created_at, last_seen, enrichment_data', { count: 'exact' })
    .eq('tenant_id', tid)
    .order(sort, { ascending: order })
    .range(from, to);

  if (severity) q = q.eq('reputation', severity.toLowerCase());
  if (status)   q = q.eq('status', status);
  if (type)     q = q.eq('type', type);
  if (fromDate) q = q.gte('created_at', fromDate);
  if (toDate)   q = q.lte('created_at', toDate);
  if (search)   q = q.or(`value.ilike.%${search}%,threat_actor.ilike.%${search}%`);

  const { data, error, count } = await q;

  if (error) {
    // Never 500 — return empty list so UI stays functional
    console.warn('[CTI] /detections query error:', error.message);
    return res.json({ data: [], total: 0, page, limit });
  }

  // Shape data to match what live-detections-soc.js expects
  const detections = (data || []).map(ioc => ({
    id:           ioc.id,
    title:        `${ioc.type?.toUpperCase() || 'IOC'} detected: ${ioc.value}`,
    ioc_value:    ioc.value,
    ioc_type:     ioc.type,
    severity:     ioc.reputation === 'malicious'  ? 'HIGH'
                : ioc.reputation === 'suspicious' ? 'MEDIUM'
                : ioc.risk_score > 70             ? 'HIGH'
                : ioc.risk_score > 40             ? 'MEDIUM' : 'LOW',
    status:       ioc.status || 'open',
    risk_score:   ioc.risk_score,
    threat_actor: ioc.threat_actor,
    tags:         ioc.tags || [],
    source_ip:    ioc.type === 'ip' ? ioc.value : null,
    created_at:   ioc.created_at,
    last_seen:    ioc.last_seen,
    tenant_id:    tid,
    correlated:   false,
  }));

  res.json({
    data:  detections,
    total: count || 0,
    page,
    limit,
  });
}));

// POST /api/cti/detections/:id/correlate
router.post('/detections/:id/correlate', asyncHandler(async (req, res) => {
  const { id } = req.params;
  const tid     = req.tenantId;
  const auto    = req.body?.auto !== false;

  // Fetch the IOC to correlate
  const { data: ioc, error: fetchErr } = await supabase
    .from('iocs')
    .select('*')
    .eq('id', id)
    .eq('tenant_id', tid)
    .maybeSingle();

  if (fetchErr || !ioc) {
    // Return accepted response even if IOC not found — never 500
    console.warn('[CTI] /detections/:id/correlate — IOC not found:', id);
    return res.json({
      id,
      correlated: false,
      message: 'IOC not found or correlation skipped',
      correlated_at: new Date().toISOString(),
    });
  }

  // Mark as correlated (update enrichment_data)
  const { error: updateErr } = await supabase
    .from('iocs')
    .update({
      enrichment_data: {
        ...(ioc.enrichment_data || {}),
        correlated:    true,
        correlated_at: new Date().toISOString(),
        auto_correlated: auto,
      },
    })
    .eq('id', id)
    .eq('tenant_id', tid);

  if (updateErr) {
    console.warn('[CTI] /detections/:id/correlate update error:', updateErr.message);
  }

  res.json({
    id,
    ioc_value:     ioc.value,
    correlated:    true,
    auto:          auto,
    correlated_at: new Date().toISOString(),
    message:       'Correlation complete',
  });
}));

// ══════════════════════════════════════════════════════════
//  INGESTION TRIGGERS (manual run of feed workers)
// ══════════════════════════════════════════════════════════

// POST /api/cti/ingest/:feed
router.post('/ingest/:feed', asyncHandler(async (req, res) => {
  const { feed } = req.params;
  const tid = req.tenantId;

  // Main ingestion feeds (services/ingestion/index.js)
  const MAIN_FEEDS = ['otx', 'abuseipdb', 'urlhaus', 'threatfox', 'nvd', 'circl',
    'feodo', 'cisa_kev', 'cisa', 'openphish', 'malwarebazaar', 'bazaar',
    'ransomware', 'emerging_threats', 'emerging', 'all'];
  // Phishtank module feeds (services/ingestion/phishtank.js)
  const PHISH_FEEDS = ['phishtank', 'misp', 'misp_circl', 'botvrij', 'sslbl'];

  const allValid = [...MAIN_FEEDS, ...PHISH_FEEDS];
  if (!allValid.includes(feed)) {
    throw createError(400, `Unknown feed. Valid: ${allValid.join(', ')}`);
  }

  // Return immediately; run ingestion asynchronously
  res.json({
    message: `Ingestion job for '${feed}' started`,
    feed,
    started_at: new Date().toISOString(),
    status: 'running',
    note: 'Check /api/cti/feed-logs for progress',
  });

  // Fire ingestion asynchronously (don't await)
  setImmediate(async () => {
    try {
      if (PHISH_FEEDS.includes(feed)) {
        // Route phishtank-module feeds to their dedicated module
        const phishModule = require('../services/ingestion/phishtank');
        const phishMap = {
          phishtank:  phishModule.ingestPhishTank,
          misp:       phishModule.ingestMISPCircl,
          misp_circl: phishModule.ingestMISPCircl,
          botvrij:    phishModule.ingestBotvrij,
          sslbl:      phishModule.ingestSSLBlacklist,
        };
        const fn = phishMap[feed];
        if (fn) await fn(tid);
      } else {
        const { runIngestion } = require('../services/ingestion');
        await runIngestion(feed, tid);
      }
    } catch (err) {
      console.error(`[CTI] Ingestion failed for ${feed}:`, err.message);
    }
  });
}));

// ══════════════════════════════════════════════════════════
//  STATISTICS & SUMMARY
// ══════════════════════════════════════════════════════════

// GET /api/cti/stats
router.get('/stats', asyncHandler(async (req, res) => {
  const tid = req.tenantId;

  // ROOT-CAUSE FIX v14.0: Wrap each query in a per-query 8s timeout.
  // On Supabase free-tier cold-start any single query can hang 8-15s,
  // blocking the entire Promise.all and causing 401/timeout cascades.
  const _ct = (p, fb = { data: null, count: 0 }) =>
    Promise.race([
      p.then(r => r).catch(() => fb),
      new Promise(resolve => setTimeout(() => resolve(fb), 8_000)),
    ]);

  // Query feed logs from both tables (see /feed-logs route comment for explanation)
  const [actors, campaigns, vulns, iocs, feedLogsNew, feedLogsLegacy] = await Promise.all([
    _ct(supabase.from('threat_actors').select('id', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`), { count: 0 }),
    _ct(supabase.from('campaigns').select('id', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`), { count: 0 }),
    _ct(supabase.from('vulnerabilities').select('id', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`), { count: 0 }),
    _ct(supabase.from('iocs').select('id, risk_score, reputation', { count: 'exact' })
      .eq('tenant_id', tid).eq('status', 'active').limit(1000), { data: [], count: 0 }),
    _ct(supabase.from('cti_feed_logs').select('feed_name, status, finished_at, iocs_new')
      .eq('tenant_id', tid).order('finished_at', { ascending: false }).limit(20), { data: [] }),
    _ct(supabase.from('feed_logs').select('feed_name, status, finished_at, iocs_new')
      .eq('tenant_id', tid).order('finished_at', { ascending: false }).limit(20), { data: [] }),
  ]);
  // Merge both feed-log result sets
  const allFeedLogs = [
    ...(feedLogsNew.data || []),
    ...(feedLogsLegacy.data || []),
  ];
  const feedLogs = { data: allFeedLogs };

  const iocData = iocs.data || [];
  const maliciousCount = iocData.filter(i => i.reputation === 'malicious').length;
  const highRiskCount  = iocData.filter(i => i.risk_score >= 70).length;
  const avgRisk        = iocData.length > 0
    ? Math.round(iocData.reduce((s, i) => s + (i.risk_score || 0), 0) / iocData.length)
    : 0;

  // Last ingestion per feed
  const lastIngestion = {};
  for (const log of (feedLogs.data || [])) {
    if (!lastIngestion[log.feed_name] || new Date(log.finished_at) > new Date(lastIngestion[log.feed_name].finished_at)) {
      lastIngestion[log.feed_name] = log;
    }
  }

  res.json({
    threat_actors:   actors.count   || 0,
    campaigns:       campaigns.count || 0,
    vulnerabilities: vulns.count    || 0,
    total_iocs:      iocs.count     || 0,
    malicious_iocs:  maliciousCount,
    high_risk_iocs:  highRiskCount,
    avg_risk_score:  avgRisk,
    last_ingestion:  Object.values(lastIngestion),
  });
}));

// ══════════════════════════════════════════════════════════
//  RISK SCORING API
// ══════════════════════════════════════════════════════════

// POST /api/cti/risk-score
router.post('/risk-score', asyncHandler(async (req, res) => {
  const { ioc_value, ioc_type, enrichment_data } = req.body;
  if (!ioc_value) throw createError(400, 'ioc_value required');

  const intel = require('../services/intelligence');
  const score = await intel.calculateRiskScore(enrichment_data || {});
  const mitre = await intel.mapToMITRE({
    value: ioc_value,
    type: ioc_type || 'ip',
    tags: [], enrichment_data: enrichment_data || {},
  });

  res.json({
    ioc_value,
    ioc_type,
    risk_score: typeof score === 'object' ? score.score : score,
    breakdown: typeof score === 'object' ? score.breakdown : null,
    mitre_techniques: mitre,
    computed_at: new Date().toISOString(),
  });
}));

// ══════════════════════════════════════════════════════════
//  AI AGENT QUERY
// ══════════════════════════════════════════════════════════

// POST /api/cti/ai/query
router.post('/ai/query', asyncHandler(async (req, res) => {
  const { query, context } = req.body;
  if (!query || typeof query !== 'string') {
    throw createError(400, 'query (string) required');
  }

  const agent = require('../services/ai-agent');
  const result = await agent.query(query.trim(), {
    tenantId: req.tenantId,
    user: req.user,
    context: context || {},
  });

  res.json(result);
}));

// POST /api/cti/ai/sessions — save AI session
router.post('/ai/sessions', asyncHandler(async (req, res) => {
  const { title, messages } = req.body;

  const { data, error } = await supabase
    .from('ai_sessions')
    .insert({
      tenant_id: req.tenantId,
      user_id:   req.user?.id,
      title:     title || 'AI Query Session',
      messages:  messages || [],
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

// GET /api/cti/ai/sessions — list sessions for current user
router.get('/ai/sessions', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('ai_sessions')
    .select('id, title, created_at, updated_at, messages')
    .eq('tenant_id', req.tenantId)
    .eq('user_id', req.user?.id)
    .order('updated_at', { ascending: false })
    .limit(50);

  if (error) throw createError(500, error.message);
  res.json({ data: data || [] });
}));

module.exports = router;
