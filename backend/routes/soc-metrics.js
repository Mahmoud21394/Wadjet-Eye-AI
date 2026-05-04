/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Metrics & Dashboard Routes (Phase 9)
 *  backend/routes/soc-metrics.js
 *
 *  GET  /api/soc-metrics/dashboard        — Full SOC operational dashboard
 *  GET  /api/soc-metrics/mttd             — Mean Time to Detect time-series
 *  GET  /api/soc-metrics/mttr             — Mean Time to Respond time-series
 *  GET  /api/soc-metrics/workload         — Analyst workload & burnout risk
 *  GET  /api/soc-metrics/sla              — SLA compliance breakdown
 *  GET  /api/soc-metrics/quality          — Detection quality (FPR/TPR per rule)
 *  GET  /api/soc-metrics/mitre-coverage   — ATT&CK coverage heatmap
 *  GET  /api/soc-metrics/burnout          — Analyst burnout detection
 *  POST /api/soc-metrics/snapshot         — Persist daily metrics snapshot
 *  GET  /api/soc-metrics/history          — Historical metrics trend
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const {
  buildDashboardMetrics,
  computeMttd,
  computeMttr,
  computeAnalystWorkload,
  computeSlaCompliance,
  computeInvestigationQuality,
  computeFprTpr,
  computeMitreCoverage,
  detectBurnoutRisk,
  persistMetricsSnapshot,
} = require('../services/metrics/soc-metrics');
const { supabase } = require('../config/supabase');

// All SOC metrics require authentication
router.use(verifyToken);

// ── Helper: parse date window ─────────────────────────────────────
function parseDateWindow(query) {
  const now   = new Date();
  const days  = Math.min(parseInt(query.days || '7', 10), 365);
  const since = query.since
    ? new Date(query.since)
    : new Date(now.getTime() - days * 24 * 3600 * 1000);
  const until = query.until ? new Date(query.until) : now;
  return { since: since.toISOString(), until: until.toISOString(), days };
}

// ── Helper: fetch alerts in window ───────────────────────────────
async function fetchAlerts(tenantId, since, until, limit = 50000) {
  const { data, error } = await supabase
    .from('alerts')
    .select([
      'id', 'severity', 'category', 'status', 'outcome',
      'rule_id', 'rule_name', 'confidence', 'risk_score',
      'created_at', 'event_time', 'ticket_created_at', 'closed_at',
      'assignee_id', 'mitre_tactic', 'mitre_technique',
      'host', 'username', 'incident_id', 'cluster_id',
    ].join(', '))
    .eq('tenant_id', tenantId)
    .gte('created_at', since)
    .lte('created_at', until)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) throw createError(500, `Alert fetch failed: ${error.message}`);
  return data || [];
}

// ── Helper: fetch analysts ────────────────────────────────────────
async function fetchAnalysts(tenantId) {
  const { data, error } = await supabase
    .from('users')
    .select('id, display_name, role')
    .eq('tenant_id', tenantId)
    .eq('active', true)
    .in('role', ['ANALYST', 'TEAM_LEAD', 'ADMIN']);

  if (error) return [];
  return data || [];
}

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/soc-metrics/dashboard
 * Full SOC operational dashboard — single call for all KPIs
 */
router.get('/dashboard', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);

  const [alerts, analysts] = await Promise.all([
    fetchAlerts(tenantId, since, until),
    fetchAnalysts(tenantId),
  ]);

  const dashboard = await buildDashboardMetrics(alerts, analysts, {
    tenantId,
    since,
    until,
    days,
  });

  res.json({
    success: true,
    period:  { since, until, days },
    data:    dashboard,
    generated_at: new Date().toISOString(),
  });
}));

/**
 * GET /api/soc-metrics/mttd
 * Mean Time to Detect — daily time-series over query window
 */
router.get('/mttd', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);
  const granularity = req.query.granularity || 'daily';  // hourly | daily | weekly

  const alerts = await fetchAlerts(tenantId, since, until);
  const mttd   = computeMttd(alerts, { granularity });

  res.json({
    success:     true,
    metric:      'mttd',
    unit:        'seconds',
    granularity,
    period:      { since, until, days },
    data:        mttd,
  });
}));

/**
 * GET /api/soc-metrics/mttr
 * Mean Time to Respond — daily time-series over query window
 */
router.get('/mttr', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);
  const granularity = req.query.granularity || 'daily';

  const alerts = await fetchAlerts(tenantId, since, until);
  const mttr   = computeMttr(alerts, { granularity });

  res.json({
    success:     true,
    metric:      'mttr',
    unit:        'seconds',
    granularity,
    period:      { since, until, days },
    data:        mttr,
  });
}));

/**
 * GET /api/soc-metrics/workload
 * Analyst workload distribution and queue depth
 */
router.get('/workload', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);

  const [alerts, analysts] = await Promise.all([
    fetchAlerts(tenantId, since, until),
    fetchAnalysts(tenantId),
  ]);

  const workload = computeAnalystWorkload(alerts, analysts);

  res.json({
    success:  true,
    period:   { since, until, days },
    data:     workload,
  });
}));

/**
 * GET /api/soc-metrics/sla
 * SLA compliance by severity tier
 */
router.get('/sla', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);

  // SLA targets (seconds) — configurable via env or tenant settings
  const slaTargets = {
    critical: parseInt(process.env.SLA_CRITICAL_S || '3600',   10),  // 1h
    high:     parseInt(process.env.SLA_HIGH_S     || '14400',  10),  // 4h
    medium:   parseInt(process.env.SLA_MEDIUM_S   || '86400',  10),  // 24h
    low:      parseInt(process.env.SLA_LOW_S       || '259200', 10),  // 72h
  };

  const alerts = await fetchAlerts(tenantId, since, until);
  const sla    = computeSlaCompliance(alerts, slaTargets);

  res.json({
    success:      true,
    period:       { since, until, days },
    sla_targets:  slaTargets,
    data:         sla,
  });
}));

/**
 * GET /api/soc-metrics/quality
 * Detection quality scores: FPR, TPR per rule
 */
router.get('/quality', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);

  const alerts  = await fetchAlerts(tenantId, since, until);
  const quality = computeInvestigationQuality(alerts, { limit });

  // Also fetch stored rule-level FPR/TPR from detection_rules table
  const { data: rules } = await supabase
    .from('detection_rules')
    .select('rule_id, name, false_positive_rate, true_positive_rate, trigger_count, fp_count, tp_count, threshold, auto_tune')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('enabled', true)
    .order('trigger_count', { ascending: false })
    .limit(limit);

  res.json({
    success:   true,
    period:    { since, until, days },
    data:      quality,
    rules:     rules || [],
  });
}));

/**
 * GET /api/soc-metrics/fpr-tpr
 * False positive / true positive rates per rule (last 30 days)
 */
router.get('/fpr-tpr', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow({ ...req.query, days: req.query.days || '30' });

  const alerts = await fetchAlerts(tenantId, since, until, 100000);
  const rates  = computeFprTpr(alerts);

  res.json({
    success: true,
    period:  { since, until, days },
    data:    rates,
  });
}));

/**
 * GET /api/soc-metrics/mitre-coverage
 * ATT&CK tactic/technique coverage heatmap
 */
router.get('/mitre-coverage', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow(req.query);

  const alerts   = await fetchAlerts(tenantId, since, until);
  const coverage = computeMitreCoverage(alerts);

  // Fetch enabled rules and their MITRE mappings
  const { data: rules } = await supabase
    .from('detection_rules')
    .select('rule_id, mitre_tactic, mitre_technique, enabled, severity')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('enabled', true);

  // Build coverage matrix from rules
  const ruleMatrix = {};
  for (const rule of (rules || [])) {
    const tactic = rule.mitre_tactic || 'unknown';
    if (!ruleMatrix[tactic]) ruleMatrix[tactic] = [];
    if (rule.mitre_technique) ruleMatrix[tactic].push(rule.mitre_technique);
  }

  res.json({
    success:         true,
    period:          { since, until, days },
    alert_coverage:  coverage,
    rule_coverage:   ruleMatrix,
    total_rules:     (rules || []).length,
  });
}));

/**
 * GET /api/soc-metrics/burnout
 * Analyst burnout risk detection
 */
router.get('/burnout', requireRole(['TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { since, until, days } = parseDateWindow({ ...req.query, days: req.query.days || '30' });

  const [alerts, analysts] = await Promise.all([
    fetchAlerts(tenantId, since, until),
    fetchAnalysts(tenantId),
  ]);

  const burnout = detectBurnoutRisk(alerts, analysts, { days });

  res.json({
    success: true,
    period:  { since, until, days },
    data:    burnout,
  });
}));

/**
 * POST /api/soc-metrics/snapshot
 * Persist a daily metrics snapshot to soc_metrics table
 */
router.post(
  '/snapshot',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const tenantId    = req.tenantId;
    const periodType  = req.body?.period_type || 'daily';
    const periodStart = req.body?.period_start
      ? new Date(req.body.period_start)
      : new Date(Date.now() - 24 * 3600 * 1000);
    const periodEnd = req.body?.period_end ? new Date(req.body.period_end) : new Date();

    const since = periodStart.toISOString();
    const until = periodEnd.toISOString();

    const [alerts, analysts] = await Promise.all([
      fetchAlerts(tenantId, since, until),
      fetchAnalysts(tenantId),
    ]);

    const dashboard = await buildDashboardMetrics(alerts, analysts, {
      tenantId, since, until,
    });

    const snapshot = await persistMetricsSnapshot(tenantId, {
      period_start: since,
      period_end:   until,
      period_type:  periodType,
      dashboard,
    });

    res.json({
      success:    true,
      snapshot_id: snapshot.id,
      period:     { since, until, period_type: periodType },
    });
  })
);

/**
 * GET /api/soc-metrics/history
 * Retrieve historical metrics snapshots for trending
 */
router.get('/history', asyncHandler(async (req, res) => {
  const tenantId   = req.tenantId;
  const periodType = req.query.period_type || 'daily';
  const limit      = Math.min(parseInt(req.query.limit || '30', 10), 365);
  const since      = req.query.since || new Date(Date.now() - 90 * 24 * 3600000).toISOString();

  const { data, error } = await supabase
    .from('soc_metrics')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('period_type', periodType)
    .gte('period_start', since)
    .order('period_start', { ascending: false })
    .limit(limit);

  if (error) throw createError(500, error.message);

  res.json({
    success:     true,
    period_type: periodType,
    count:       (data || []).length,
    data:        data || [],
  });
}));

/**
 * GET /api/soc-metrics/summary
 * Quick summary: today vs yesterday comparison
 */
router.get('/summary', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const now      = new Date();
  const today    = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1).toISOString();
  const week      = new Date(now.getTime() - 7 * 24 * 3600000).toISOString();

  const [todayAlerts, yestAlerts, weekAlerts] = await Promise.all([
    fetchAlerts(tenantId, today, now.toISOString(), 10000),
    fetchAlerts(tenantId, yesterday, today, 10000),
    fetchAlerts(tenantId, week, now.toISOString(), 100000),
  ]);

  const countBySeverity = (alerts) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const a of alerts) counts[a.severity] = (counts[a.severity] || 0) + 1;
    return counts;
  };

  const openAlerts = todayAlerts.filter(a => !['closed','false_positive','true_positive','duplicate'].includes(a.status));
  const weekAvgPerDay = (weekAlerts.length / 7).toFixed(1);

  res.json({
    success: true,
    today: {
      total:       todayAlerts.length,
      open:        openAlerts.length,
      by_severity: countBySeverity(todayAlerts),
    },
    yesterday: {
      total:       yestAlerts.length,
      by_severity: countBySeverity(yestAlerts),
    },
    week_avg_per_day: parseFloat(weekAvgPerDay),
    trend: todayAlerts.length > yestAlerts.length ? 'increasing' : 'decreasing',
    generated_at: now.toISOString(),
  });
}));

module.exports = router;
