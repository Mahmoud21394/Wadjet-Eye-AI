/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Detection Engine Routes (Phase 3 + 7)
 *  backend/routes/detection.js
 *
 *  GET  /api/detection/rules              — List detection rules
 *  POST /api/detection/rules              — Create rule
 *  PUT  /api/detection/rules/:id          — Update rule
 *  DELETE /api/detection/rules/:id        — Disable rule
 *  POST /api/detection/rules/:id/test     — Test rule against sample
 *  POST /api/detection/feedback           — Submit analyst feedback (FP/TP)
 *  GET  /api/detection/feedback/stats     — Feedback statistics
 *  POST /api/detection/cluster            — Cluster alert batch (DBSCAN/HDBSCAN)
 *  GET  /api/detection/clusters           — List alert clusters
 *  GET  /api/detection/health             — Engine health check
 *  POST /api/detection/tune               — Trigger auto-tuning cycle
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const detectionEngine = require('../services/detection/detection-engine');
const selfLearning    = require('../services/detection/self-learning');
const dbscanClustering = require('../services/detection/dbscan-clustering');
const { supabase } = require('../config/supabase');
const { z } = require('zod');

router.use(verifyToken);

// ── Schemas ───────────────────────────────────────────────────────
const CreateRuleSchema = z.object({
  rule_id:         z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/),
  name:            z.string().min(3).max(255),
  description:     z.string().max(2000).optional(),
  rule_type:       z.enum(['sigma','custom','ml','composite']).default('custom'),
  severity:        z.enum(['critical','high','medium','low','informational']).default('medium'),
  mitre_tactic:    z.string().max(100).optional(),
  mitre_technique: z.string().max(50).optional(),
  logic:           z.record(z.unknown()),
  sigma_yaml:      z.string().max(50000).optional(),
  enabled:         z.boolean().default(true),
  threshold:       z.number().min(0).max(100).default(50),
  auto_tune:       z.boolean().default(true),
  tags:            z.array(z.string().max(50)).max(20).default([]),
});

const FeedbackSchema = z.object({
  alert_id:   z.string().uuid(),
  rule_id:    z.string().max(100).optional(),
  outcome:    z.enum(['true_positive','false_positive','duplicate','benign']),
  confidence: z.number().min(0).max(100).optional(),
  notes:      z.string().max(2000).optional(),
});

const ClusterSchema = z.object({
  alert_ids:       z.array(z.string().uuid()).min(2).max(10000).optional(),
  since:           z.string().datetime({ offset: true }).optional(),
  algorithm:       z.enum(['dbscan','hdbscan']).default('hdbscan'),
  min_cluster_size: z.number().int().min(2).max(100).default(3),
  min_samples:     z.number().int().min(1).max(50).default(2),
  epsilon:         z.number().min(0.01).max(10).default(0.5),
  use_python_service: z.boolean().default(false),
});

// ══════════════════════════════════════════════════════════════════
//  DETECTION RULES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/detection/rules
 */
router.get('/rules', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit    = Math.min(parseInt(req.query.limit || '100', 10), 500);
  const offset   = (Math.max(parseInt(req.query.page || '1', 10), 1) - 1) * limit;
  const enabled  = req.query.enabled !== 'false';
  const severity = req.query.severity;
  const search   = req.query.q;

  let query = supabase
    .from('detection_rules')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('enabled', enabled)
    .order('severity', { ascending: false })
    .order('trigger_count', { ascending: false })
    .range(offset, offset + limit - 1);

  if (severity) query = query.eq('severity', severity);
  if (search)   query = query.or(`name.ilike.%${search}%,rule_id.ilike.%${search}%`);

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message);

  res.json({
    success: true,
    total:   count || 0,
    page:    Math.floor(offset / limit) + 1,
    limit,
    data:    data || [],
  });
}));

/**
 * GET /api/detection/rules/:id
 */
router.get('/rules/:id', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('detection_rules')
    .select('*')
    .eq('rule_id', req.params.id)
    .or(`tenant_id.eq.${req.tenantId},tenant_id.is.null`)
    .single();

  if (error || !data) throw createError(404, 'Rule not found');
  res.json({ success: true, data });
}));

/**
 * POST /api/detection/rules
 */
router.post(
  '/rules',
  requireRole(['ADMIN', 'SUPER_ADMIN', 'TEAM_LEAD']),
  asyncHandler(async (req, res) => {
    const parsed = CreateRuleSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const rule = { ...parsed.data, tenant_id: req.tenantId };

    // Validate Sigma YAML if provided
    if (rule.sigma_yaml) {
      const validation = await selfLearning.validateSigmaRule(rule.sigma_yaml);
      if (!validation.valid) {
        throw createError(422, `Invalid Sigma rule: ${validation.error}`);
      }
      rule.logic = validation.parsed || rule.logic;
    }

    const { data, error } = await supabase
      .from('detection_rules')
      .insert(rule)
      .select('*')
      .single();

    if (error) {
      if (error.code === '23505') throw createError(409, `Rule ID '${rule.rule_id}' already exists`);
      throw createError(500, error.message);
    }

    res.status(201).json({ success: true, data });
  })
);

/**
 * PUT /api/detection/rules/:id
 */
router.put(
  '/rules/:id',
  requireRole(['ADMIN', 'SUPER_ADMIN', 'TEAM_LEAD']),
  asyncHandler(async (req, res) => {
    const tenantId = req.tenantId;

    // Validate rule belongs to tenant (not global rules)
    const { data: existing } = await supabase
      .from('detection_rules')
      .select('id, tenant_id')
      .eq('rule_id', req.params.id)
      .single();

    if (!existing) throw createError(404, 'Rule not found');
    if (existing.tenant_id && existing.tenant_id !== tenantId) {
      throw createError(403, 'Cannot modify rules belonging to other tenants');
    }

    const parsed = CreateRuleSchema.partial().safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { data, error } = await supabase
      .from('detection_rules')
      .update({ ...parsed.data, updated_at: new Date().toISOString() })
      .eq('rule_id', req.params.id)
      .select('*')
      .single();

    if (error) throw createError(500, error.message);
    res.json({ success: true, data });
  })
);

/**
 * DELETE /api/detection/rules/:id
 * Soft-disable (not hard delete — preserves audit trail)
 */
router.delete(
  '/rules/:id',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { data, error } = await supabase
      .from('detection_rules')
      .update({ enabled: false, updated_at: new Date().toISOString() })
      .eq('rule_id', req.params.id)
      .eq('tenant_id', req.tenantId)
      .select('rule_id')
      .single();

    if (error || !data) throw createError(404, 'Rule not found or not owned by tenant');
    res.json({ success: true, message: `Rule ${req.params.id} disabled` });
  })
);

/**
 * POST /api/detection/rules/:id/test
 * Test a detection rule against a sample event payload
 */
router.post('/rules/:id/test', asyncHandler(async (req, res) => {
  const { sample_event } = req.body || {};
  if (!sample_event || typeof sample_event !== 'object') {
    throw createError(400, 'sample_event object required');
  }

  const { data: rule } = await supabase
    .from('detection_rules')
    .select('*')
    .eq('rule_id', req.params.id)
    .or(`tenant_id.eq.${req.tenantId},tenant_id.is.null`)
    .single();

  if (!rule) throw createError(404, 'Rule not found');

  const result = await detectionEngine.testRule(rule, sample_event);

  res.json({
    success: true,
    rule_id: req.params.id,
    matched:     result.matched,
    confidence:  result.confidence,
    score:       result.score,
    details:     result.details,
    execution_ms: result.execution_ms,
  });
}));

// ══════════════════════════════════════════════════════════════════
//  ANALYST FEEDBACK (Self-learning loop)
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/detection/feedback
 * Submit analyst verdict on alert (TP/FP/duplicate/benign)
 */
router.post('/feedback', asyncHandler(async (req, res) => {
  const parsed = FeedbackSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { alert_id, rule_id, outcome, confidence, notes } = parsed.data;
  const tenantId  = req.tenantId;
  const analystId = req.user?.id;

  // Verify alert belongs to tenant
  const { data: alert } = await supabase
    .from('alerts')
    .select('id, rule_id, severity, confidence, risk_score')
    .eq('id', alert_id)
    .eq('tenant_id', tenantId)
    .single();

  if (!alert) throw createError(404, 'Alert not found');

  // Persist feedback
  const { data: feedback, error } = await supabase
    .from('analyst_feedback')
    .insert({
      tenant_id:   tenantId,
      alert_id,
      rule_id:     rule_id || alert.rule_id,
      analyst_id:  analystId,
      outcome,
      confidence,
      notes,
      features: {
        alert_severity:  alert.severity,
        alert_confidence: alert.confidence,
        alert_risk_score: alert.risk_score,
      },
    })
    .select('id')
    .single();

  if (error) throw createError(500, error.message);

  // Update alert status with outcome
  const statusMap = {
    true_positive:  'true_positive',
    false_positive: 'false_positive',
    duplicate:      'duplicate',
    benign:         'closed',
  };
  await supabase
    .from('alerts')
    .update({ status: statusMap[outcome] || 'closed', outcome, updated_at: new Date().toISOString() })
    .eq('id', alert_id);

  // Trigger self-learning update (non-blocking)
  selfLearning.recordAnalystFeedback({
    alert_id, rule_id: rule_id || alert.rule_id,
    analyst_id: analystId, outcome, confidence, notes, tenant_id: tenantId,
  }).catch(err => console.warn('[Detection] Feedback learning error:', err.message));

  res.status(201).json({
    success:     true,
    feedback_id: feedback?.id,
    alert_id,
    outcome,
    message:     'Feedback recorded — detection model will be updated',
  });
}));

/**
 * GET /api/detection/feedback/stats
 */
router.get('/feedback/stats', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const since    = req.query.since || new Date(Date.now() - 30 * 24 * 3600000).toISOString();

  const { data, error } = await supabase
    .from('analyst_feedback')
    .select('outcome, rule_id, created_at')
    .eq('tenant_id', tenantId)
    .gte('created_at', since);

  if (error) throw createError(500, error.message);

  const feedback = data || [];
  const total    = feedback.length;
  const byOutcome = {};
  const byRule    = {};

  for (const f of feedback) {
    byOutcome[f.outcome] = (byOutcome[f.outcome] || 0) + 1;
    if (f.rule_id) {
      byRule[f.rule_id] = byRule[f.rule_id] || { tp: 0, fp: 0, total: 0 };
      byRule[f.rule_id].total++;
      if (f.outcome === 'true_positive')  byRule[f.rule_id].tp++;
      if (f.outcome === 'false_positive') byRule[f.rule_id].fp++;
    }
  }

  const fp_count = byOutcome['false_positive'] || 0;
  const tp_count = byOutcome['true_positive'] || 0;

  // Build worst FP rules
  const worstFpRules = Object.entries(byRule)
    .map(([rule_id, stats]) => ({
      rule_id,
      fp_rate: stats.total > 0 ? Math.round((stats.fp / stats.total) * 100) : 0,
      ...stats,
    }))
    .filter(r => r.fp_rate > 0)
    .sort((a, b) => b.fp_rate - a.fp_rate)
    .slice(0, 10);

  res.json({
    success:      true,
    period:       { since, until: new Date().toISOString() },
    total,
    by_outcome:   byOutcome,
    fp_rate:      total > 0 ? Math.round((fp_count / total) * 100) / 100 : 0,
    tp_rate:      total > 0 ? Math.round((tp_count / total) * 100) / 100 : 0,
    worst_fp_rules: worstFpRules,
    rules_tracked: Object.keys(byRule).length,
  });
}));

// ══════════════════════════════════════════════════════════════════
//  ALERT CLUSTERING
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/detection/cluster
 * Cluster a batch of alerts using DBSCAN/HDBSCAN
 */
router.post('/cluster', asyncHandler(async (req, res) => {
  const parsed = ClusterSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { alert_ids, since, algorithm, min_cluster_size, min_samples, epsilon, use_python_service } = parsed.data;
  const tenantId = req.tenantId;

  // Fetch alerts to cluster
  let query = supabase
    .from('alerts')
    .select('id, title, severity, risk_score, confidence, category, mitre_tactic, mitre_technique, host, username, source_ip, tenant_id, created_at, ioc_count, tags')
    .eq('tenant_id', tenantId)
    .in('status', ['open', 'in_progress'])
    .limit(10000);

  if (alert_ids?.length) {
    query = query.in('id', alert_ids);
  } else if (since) {
    query = query.gte('created_at', since);
  } else {
    // Default: last 24 hours
    const defaultSince = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    query = query.gte('created_at', defaultSince);
  }

  const { data: alerts, error } = await query;
  if (error) throw createError(500, error.message);
  if (!alerts || alerts.length < 2) {
    return res.json({ success: true, message: 'Insufficient alerts for clustering', clusters: [], noise: 0 });
  }

  let clusterResult;

  if (use_python_service && process.env.CLUSTERING_SERVICE_URL) {
    // Delegate to Python clustering service
    const https = require('https');
    const http  = require('http');
    const url   = new URL(`${process.env.CLUSTERING_SERVICE_URL}/cluster`);
    const payload = JSON.stringify({ alerts, algorithm, min_cluster_size, min_samples, epsilon });
    const transport = url.protocol === 'https:' ? https : http;

    clusterResult = await new Promise((resolve, reject) => {
      const req2 = transport.request({
        hostname: url.hostname, port: url.port,
        path: url.pathname, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      }, (res2) => {
        const chunks = [];
        res2.on('data', c => chunks.push(c));
        res2.on('end', () => {
          try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
          catch (e) { reject(e); }
        });
      });
      req2.on('error', reject);
      req2.write(payload);
      req2.end();
    });
  } else {
    // Run built-in JS DBSCAN
    clusterResult = await dbscanClustering.clusterAlerts(alerts, { algorithm, min_cluster_size, min_samples, epsilon });
  }

  // Update alerts with cluster IDs
  if (clusterResult.clusters?.length) {
    const updates = [];
    for (const cluster of clusterResult.clusters) {
      for (const alert_id of cluster.alert_ids || []) {
        updates.push(supabase
          .from('alerts')
          .update({ cluster_id: cluster.cluster_id, updated_at: new Date().toISOString() })
          .eq('id', alert_id)
        );
      }
    }
    await Promise.allSettled(updates);
  }

  res.json({
    success:        true,
    input_alerts:   alerts.length,
    clusters:       clusterResult.clusters?.length || 0,
    noise_alerts:   clusterResult.noise_alerts || 0,
    algorithm:      clusterResult.algorithm || algorithm,
    data:           clusterResult.clusters || [],
    execution_ms:   clusterResult.execution_ms,
  });
}));

/**
 * GET /api/detection/clusters
 * List current alert clusters (alerts grouped by cluster_id)
 */
router.get('/clusters', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const since    = req.query.since || new Date(Date.now() - 24 * 3600000).toISOString();

  const { data: alerts, error } = await supabase
    .from('alerts')
    .select('id, title, severity, risk_score, mitre_tactic, cluster_id, created_at')
    .eq('tenant_id', tenantId)
    .not('cluster_id', 'is', null)
    .gte('created_at', since)
    .order('created_at', { ascending: false });

  if (error) throw createError(500, error.message);

  // Group by cluster_id
  const clusterMap = {};
  for (const alert of (alerts || [])) {
    if (!clusterMap[alert.cluster_id]) {
      clusterMap[alert.cluster_id] = {
        cluster_id:    alert.cluster_id,
        alert_count:   0,
        alert_ids:     [],
        max_severity:  'unknown',
        max_risk:      0,
        mitre_tactics: new Set(),
        first_seen:    alert.created_at,
      };
    }
    const c = clusterMap[alert.cluster_id];
    c.alert_count++;
    c.alert_ids.push(alert.id);
    c.max_risk = Math.max(c.max_risk, alert.risk_score || 0);
    if (alert.mitre_tactic) c.mitre_tactics.add(alert.mitre_tactic);
  }

  const clusters = Object.values(clusterMap).map(c => ({
    ...c,
    mitre_tactics: [...c.mitre_tactics],
    alert_ids: c.alert_ids.slice(0, 20),   // Limit for response size
  }));

  res.json({
    success:    true,
    period:     { since },
    total:      clusters.length,
    clusters:   clusters.sort((a, b) => b.max_risk - a.max_risk),
  });
}));

/**
 * GET /api/detection/health
 */
router.get('/health', asyncHandler(async (req, res) => {
  const health = await detectionEngine.healthCheck();
  res.json({ success: true, data: health });
}));

/**
 * POST /api/detection/tune
 * Trigger an auto-tuning cycle for all rules with sufficient feedback data
 */
router.post(
  '/tune',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const tenantId = req.tenantId;
    const result   = await selfLearning.runAutoTuningCycle(tenantId);

    res.json({
      success:       true,
      rules_tuned:   result.tuned || 0,
      rules_skipped: result.skipped || 0,
      adjustments:   result.adjustments || [],
      duration_ms:   result.duration_ms,
    });
  })
);

module.exports = router;
