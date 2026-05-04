/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Metrics API Routes v2 (Phase 9)
 *  backend/routes/v2/metrics.js
 *
 *  GET  /api/v2/metrics/dashboard        — Full SOC dashboard
 *  GET  /api/v2/metrics/mttd             — MTTD time-series
 *  GET  /api/v2/metrics/mttr             — MTTR time-series
 *  GET  /api/v2/metrics/analyst-workload — Per-analyst workload
 *  GET  /api/v2/metrics/sla              — SLA compliance breakdown
 *  GET  /api/v2/metrics/quality          — Investigation quality scores
 *  GET  /api/v2/metrics/fpr-tpr          — FP/TP rates per rule
 *  POST /api/v2/metrics/snapshot         — Persist daily snapshot
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../../middleware/auth');
const { asyncHandler, createError } = require('../../middleware/errorHandler');
const {
  buildDashboardMetrics,
  computeMttd,
  computeMttr,
  computeAnalystWorkload,
  computeSlaCompliance,
  computeInvestigationQuality,
  computeFprTpr,
} = require('../../services/metrics/soc-metrics');

// All routes require authentication
router.use(verifyToken);

const { supabase } = require('../../config/supabase');

// ── Helper: fetch alerts with date window ─────────────────────────
async function fetchAlerts(tenantId, since, limit = 5000) {
  const { data, error } = await supabase
    .from('alerts')
    .select('id, severity, category, status, outcome, rule_id, confidence, created_at, event_time, ticket_created_at, closed_at')
    .eq('tenant_id', tenantId)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw createError(error.message, 500, 'DB_ERROR');
  return data || [];
}

async function fetchCases(tenantId, since, limit = 2000) {
  const { data, error } = await supabase
    .from('cases')
    .select('id, severity, priority, status, created_at, closed_at, escalated, assignee_id, sla_due_at, sla_breached')
    .eq('tenant_id', tenantId)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw createError(error.message, 500, 'DB_ERROR');
  return data || [];
}

// ── GET /api/v2/metrics/dashboard ────────────────────────────────
router.get('/dashboard', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 365);
  const tenantId   = req.user.tenant_id;

  const metrics = await buildDashboardMetrics(supabase, { windowDays });
  res.json(metrics);
}));

// ── GET /api/v2/metrics/mttd ──────────────────────────────────────
router.get('/mttd', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 90);
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const alerts = await fetchAlerts(req.user.tenant_id, since);
  const mttd   = computeMttd(alerts);

  // Daily buckets for trend chart
  const trend = _dailyBuckets(alerts, windowDays, (a) => {
    if (!a.event_time || !a.created_at) return null;
    return Math.max(0, (new Date(a.created_at) - new Date(a.event_time)) / 60000);
  });

  res.json({
    ...mttd,
    unit:        'minutes',
    window_days: windowDays,
    trend,
  });
}));

// ── GET /api/v2/metrics/mttr ──────────────────────────────────────
router.get('/mttr', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 90);
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const cases = await fetchCases(req.user.tenant_id, since);
  const mttr  = computeMttr(cases);

  const trend = _dailyBuckets(cases, windowDays, (c) => {
    if (!c.created_at || !c.closed_at) return null;
    return Math.max(0, (new Date(c.closed_at) - new Date(c.created_at)) / 60000);
  });

  res.json({
    ...mttr,
    unit:        'minutes',
    window_days: windowDays,
    trend,
  });
}));

// ── GET /api/v2/metrics/analyst-workload ─────────────────────────
router.get('/analyst-workload', asyncHandler(async (req, res) => {
  const tenantId = req.user.tenant_id;
  const since    = new Date(Date.now() - 30 * 86_400_000).toISOString();

  const { data: assignments, error } = await supabase
    .from('case_assignments')
    .select('analyst_id, analyst_name, is_current, cases(severity, priority, created_at, closed_at, escalated, status)')
    .eq('is_current', true);

  if (error) throw createError(error.message, 500, 'DB_ERROR');

  const flat = (assignments || []).map(a => ({
    analyst_id:   a.analyst_id,
    analyst_name: a.analyst_name,
    severity:     a.cases?.severity,
    priority:     a.cases?.priority,
    created_at:   a.cases?.created_at,
    closed_at:    a.cases?.closed_at,
    escalated:    a.cases?.escalated,
  })).filter(a => a.severity);

  const workload      = computeAnalystWorkload(flat);
  const atRisk        = workload.filter(a => a.burnout_risk === 'CRITICAL' || a.burnout_risk === 'HIGH');

  res.json({
    analysts:       workload,
    total_analysts: workload.length,
    at_risk:        atRisk.length,
    at_risk_list:   atRisk.map(a => ({ analyst_id: a.analyst_id, analyst_name: a.analyst_name, burnout_risk: a.burnout_risk, workload_score: a.workload_score })),
    generated_at:   new Date().toISOString(),
  });
}));

// ── GET /api/v2/metrics/sla ───────────────────────────────────────
router.get('/sla', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 90);
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const cases = await fetchCases(req.user.tenant_id, since);
  const sla   = computeSlaCompliance(cases);

  // Historical trend (week-over-week)
  const { data: snapshots } = await supabase
    .from('soc_metrics_snapshots')
    .select('snapshot_date, sla_compliance')
    .eq('tenant_id', req.user.tenant_id)
    .order('snapshot_date', { ascending: false })
    .limit(12);

  res.json({
    ...sla,
    window_days: windowDays,
    history:     (snapshots || []).map(s => ({ date: s.snapshot_date, rate: s.sla_compliance })),
    generated_at: new Date().toISOString(),
  });
}));

// ── GET /api/v2/metrics/quality ───────────────────────────────────
router.get('/quality', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 90);
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const { data: investigations, error } = await supabase
    .from('investigations')
    .select('*')
    .eq('tenant_id', req.user.tenant_id)
    .gte('created_at', since)
    .order('created_at', { ascending: false })
    .limit(500);

  if (error) throw createError(error.message, 500, 'DB_ERROR');

  const quality = computeInvestigationQuality(investigations || []);
  const avg     = quality.length
    ? Math.round(quality.reduce((s, q) => s + q.overall, 0) / quality.length)
    : null;

  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const q of quality) gradeDistribution[q.grade] = (gradeDistribution[q.grade] || 0) + 1;

  res.json({
    average_score:        avg,
    grade_distribution:   gradeDistribution,
    total_investigations: quality.length,
    flagged:              quality.filter(q => q.flags.length > 0).length,
    items:                quality.slice(0, 50),
    window_days:          windowDays,
    generated_at:         new Date().toISOString(),
  });
}));

// ── GET /api/v2/metrics/fpr-tpr ───────────────────────────────────
router.get('/fpr-tpr', asyncHandler(async (req, res) => {
  const windowDays = Math.min(parseInt(req.query.window_days, 10) || 30, 90);
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const alerts = await fetchAlerts(req.user.tenant_id, since, 10000);
  const rates  = computeFprTpr(alerts);

  // Per-rule breakdown
  const ruleMap = {};
  for (const alert of alerts) {
    if (!alert.rule_id || !alert.outcome) continue;
    const rid = alert.rule_id;
    if (!ruleMap[rid]) ruleMap[rid] = { rule_id: rid, tp: 0, fp: 0, total: 0 };
    ruleMap[rid].total++;
    if (alert.outcome === 'true_positive')  ruleMap[rid].tp++;
    if (alert.outcome === 'false_positive') ruleMap[rid].fp++;
  }

  const perRule = Object.values(ruleMap)
    .map(r => ({
      ...r,
      fp_rate:  r.total > 0 ? Math.round((r.fp / r.total) * 100) : null,
      tp_rate:  r.total > 0 ? Math.round((r.tp / r.total) * 100) : null,
    }))
    .filter(r => r.total >= 3)
    .sort((a, b) => (b.fp_rate || 0) - (a.fp_rate || 0));

  res.json({
    ...rates,
    per_rule:    perRule.slice(0, 30),
    window_days: windowDays,
    generated_at: new Date().toISOString(),
  });
}));

// ── POST /api/v2/metrics/snapshot — Persist daily snapshot ────────
router.post('/snapshot', requireRole('admin', 'analyst'), asyncHandler(async (req, res) => {
  const tenantId   = req.user.tenant_id;
  const windowDays = 30;
  const since      = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const [alerts, cases] = await Promise.all([
    fetchAlerts(tenantId, since),
    fetchCases(tenantId, since),
  ]);

  const mttd    = computeMttd(alerts);
  const mttr    = computeMttr(cases);
  const sla     = computeSlaCompliance(cases);
  const fprTpr  = computeFprTpr(alerts);

  const snapshot = {
    tenant_id:     tenantId,
    snapshot_date: new Date().toISOString().substring(0, 10),
    window_days:   windowDays,
    mttd_mean:     mttd.mean,
    mttd_median:   mttd.median,
    mttd_p95:      mttd.p95,
    mttr_mean:     mttr.mean,
    mttr_median:   mttr.median,
    mttr_p95:      mttr.p95,
    sla_compliance: sla.rate,
    fpr:           fprTpr.fpr,
    tpr:           fprTpr.tpr,
    precision:     fprTpr.precision,
    total_alerts:  alerts.length,
    total_cases:   cases.length,
    open_cases:    cases.filter(c => !c.closed_at).length,
    critical_alerts: alerts.filter(a => a.severity === 'CRITICAL').length,
    raw_metrics:   JSON.stringify({ mttd, mttr, sla, fprTpr }),
  };

  const { error } = await supabase
    .from('soc_metrics_snapshots')
    .upsert(snapshot, { onConflict: 'tenant_id,snapshot_date' });

  if (error) throw createError(error.message, 500, 'SNAPSHOT_FAILED');

  res.json({ saved: true, snapshot_date: snapshot.snapshot_date, ...snapshot });
}));

// ── Helper: daily bucket trend ────────────────────────────────────
function _dailyBuckets(items, windowDays, extractValue) {
  const now    = Date.now();
  const result = [];

  for (let d = windowDays - 1; d >= 0; d--) {
    const startMs = now - (d + 1) * 86_400_000;
    const endMs   = now - d       * 86_400_000;
    const date    = new Date(endMs).toISOString().substring(0, 10);

    const dayItems = items.filter(item => {
      const t = new Date(item.created_at).getTime();
      return t >= startMs && t < endMs;
    });

    const values = dayItems.map(extractValue).filter(v => v !== null);
    const mean   = values.length > 0
      ? Math.round((values.reduce((s, v) => s + v, 0) / values.length) * 10) / 10
      : null;

    result.push({ date, mean, count: dayItems.length });
  }

  return result;
}

module.exports = router;
