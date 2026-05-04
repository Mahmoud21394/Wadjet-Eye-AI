/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Metrics Engine (Phase 9)
 *  backend/services/metrics/soc-metrics.js
 *
 *  Computes:
 *  • MTTD  — Mean Time To Detect
 *  • MTTR  — Mean Time To Respond / Remediate
 *  • Alert-to-ticket time
 *  • Analyst workload scoring
 *  • Burnout risk index (alert velocity × avg hours × escalation rate)
 *  • Investigation quality scoring (completeness, accuracy, speed)
 *  • SLA compliance rates
 *  • False-positive / true-positive ratios
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── MTTD: Mean Time To Detect ────────────────────────────────────
// event_time → created_at (alert creation) gap in minutes.
// Supports both the legacy `alert_created_at` field name and the
// actual DB column `created_at` so that both old and new alert rows
// produce valid deltas instead of always returning 0.
function computeMttd(events) {
  if (!events || events.length === 0) return { mean: 0, median: 0, p95: 0, count: 0 };
  const deltas = events
    .filter(e => e.event_time && (e.created_at || e.alert_created_at))
    .map(e => {
      const eventTs = new Date(e.event_time).getTime();
      const alertTs = new Date(e.alert_created_at || e.created_at).getTime();
      return Math.max(0, (alertTs - eventTs) / 60000); // minutes
    })
    .filter(d => d >= 0 && d < 10080); // cap at 7 days

  return _stats(deltas);
}

// ── MTTR: Mean Time To Respond ────────────────────────────────────
// alert_created_at → case_closed_at gap in minutes
function computeMttr(cases) {
  if (!cases || cases.length === 0) return { mean: 0, median: 0, p95: 0, count: 0 };
  const deltas = cases
    .filter(c => c.created_at && c.closed_at)
    .map(c => {
      const created = new Date(c.created_at).getTime();
      const closed  = new Date(c.closed_at).getTime();
      return Math.max(0, (closed - created) / 60000);
    })
    .filter(d => d >= 0);

  return _stats(deltas);
}

// ── Alert-to-Ticket time ──────────────────────────────────────────
function computeAlertToTicket(alerts) {
  if (!alerts || alerts.length === 0) return { mean: 0, median: 0, p95: 0, count: 0 };
  const deltas = alerts
    .filter(a => a.created_at && a.ticket_created_at)
    .map(a => Math.max(0, (new Date(a.ticket_created_at) - new Date(a.created_at)) / 60000));

  return _stats(deltas);
}

// ── Analyst workload score ────────────────────────────────────────
// Returns per-analyst workload metrics
function computeAnalystWorkload(assignments) {
  const analystMap = new Map();

  for (const a of assignments) {
    const id = a.analyst_id;
    if (!analystMap.has(id)) {
      analystMap.set(id, {
        analyst_id:      id,
        analyst_name:    a.analyst_name || id,
        open_cases:      0,
        total_cases:     0,
        critical_cases:  0,
        high_cases:      0,
        avg_age_hours:   0,
        oldest_case_hours: 0,
        total_age_hours: 0,
        escalations:     0,
        burnout_risk:    'LOW',
        workload_score:  0,
      });
    }

    const entry = analystMap.get(id);
    const ageH  = a.closed_at
      ? (new Date(a.closed_at) - new Date(a.created_at)) / 3_600_000
      : (Date.now() - new Date(a.created_at).getTime()) / 3_600_000;

    entry.total_cases++;
    if (!a.closed_at) entry.open_cases++;
    if (a.severity === 'CRITICAL') entry.critical_cases++;
    if (a.severity === 'HIGH') entry.high_cases++;
    entry.total_age_hours += ageH;
    entry.oldest_case_hours = Math.max(entry.oldest_case_hours, ageH);
    if (a.escalated) entry.escalations++;
  }

  for (const [, entry] of analystMap) {
    entry.avg_age_hours = entry.total_cases > 0
      ? Math.round((entry.total_age_hours / entry.total_cases) * 10) / 10
      : 0;

    // Workload score: weighted sum of case severity × age factor
    entry.workload_score = Math.min(100, Math.round(
      (entry.open_cases * 5) +
      (entry.critical_cases * 15) +
      (entry.high_cases * 8) +
      (entry.avg_age_hours * 0.5) +
      (entry.escalations * 10)
    ));

    entry.burnout_risk = _burnoutRisk(entry);
    delete entry.total_age_hours;
  }

  return Array.from(analystMap.values())
    .sort((a, b) => b.workload_score - a.workload_score);
}

// ── Burnout risk index ────────────────────────────────────────────
function _burnoutRisk(entry) {
  const score = entry.workload_score;
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

// ── Investigation quality score ───────────────────────────────────
function computeInvestigationQuality(investigations) {
  if (!investigations || investigations.length === 0) return [];

  return investigations.map(inv => {
    const scores = {
      completeness: _completenessScore(inv),
      timeliness:   _timelinessScore(inv),
      accuracy:     _accuracyScore(inv),
      coverage:     _coverageScore(inv),
    };

    const overall = Math.round(
      (scores.completeness * 0.35) +
      (scores.timeliness  * 0.25) +
      (scores.accuracy    * 0.25) +
      (scores.coverage    * 0.15)
    );

    return {
      investigation_id: inv.id,
      analyst_id:       inv.analyst_id,
      case_id:          inv.case_id,
      scores,
      overall,
      grade:  _grade(overall),
      flags:  _qualityFlags(inv, scores),
    };
  });
}

function _completenessScore(inv) {
  // Check required fields are populated
  const required = ['timeline', 'iocs', 'attack_vector', 'affected_assets', 'root_cause', 'recommendations'];
  const filled   = required.filter(f => {
    const v = inv[f];
    return v && (Array.isArray(v) ? v.length > 0 : String(v).trim().length > 10);
  });
  return Math.round((filled.length / required.length) * 100);
}

function _timelinessScore(inv) {
  if (!inv.created_at || !inv.completed_at) return 50;
  const sla_hours = inv.priority === 'P1' ? 4 : inv.priority === 'P2' ? 24 : 72;
  const actual_h  = (new Date(inv.completed_at) - new Date(inv.created_at)) / 3_600_000;
  if (actual_h <= sla_hours * 0.5)  return 100;
  if (actual_h <= sla_hours)        return 80;
  if (actual_h <= sla_hours * 1.5)  return 60;
  if (actual_h <= sla_hours * 2)    return 40;
  return 20;
}

function _accuracyScore(inv) {
  // Based on peer review score and false-positive flags
  if (typeof inv.peer_review_score === 'number') return Math.round(inv.peer_review_score);
  if (inv.outcome === 'true_positive')   return 90;
  if (inv.outcome === 'false_positive')  return inv.escalated ? 30 : 60;
  return 70;
}

function _coverageScore(inv) {
  // ATT&CK mapping, lateral movement trace, persistence check
  let score = 0;
  if (inv.mitre_techniques && inv.mitre_techniques.length > 0) score += 40;
  if (inv.lateral_movement_traced) score += 30;
  if (inv.persistence_checked)     score += 20;
  if (inv.data_exfil_assessed)     score += 10;
  return score;
}

function _grade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function _qualityFlags(inv, scores) {
  const flags = [];
  if (scores.completeness < 60) flags.push('INCOMPLETE_REPORT');
  if (scores.timeliness   < 40) flags.push('SLA_BREACH');
  if (scores.accuracy     < 50) flags.push('LOW_ACCURACY');
  if (!inv.mitre_techniques || inv.mitre_techniques.length === 0) flags.push('NO_MITRE_MAPPING');
  if (!inv.recommendations || (Array.isArray(inv.recommendations) && inv.recommendations.length === 0)) flags.push('NO_RECOMMENDATIONS');
  return flags;
}

// ── SLA compliance ────────────────────────────────────────────────
function computeSlaCompliance(cases) {
  const slaMap = { P1: 4, P2: 24, P3: 72, P4: 168 };
  const result = { total: 0, compliant: 0, breached: 0, rate: 0, by_priority: {} };

  for (const [p, sla] of Object.entries(slaMap)) {
    const group = cases.filter(c => c.priority === p && c.closed_at);
    const met   = group.filter(c => {
      const hours = (new Date(c.closed_at) - new Date(c.created_at)) / 3_600_000;
      return hours <= sla;
    });
    result.by_priority[p] = {
      total:     group.length,
      compliant: met.length,
      rate:      group.length > 0 ? Math.round((met.length / group.length) * 100) : null,
      sla_hours: sla,
    };
    result.total     += group.length;
    result.compliant += met.length;
  }

  result.breached = result.total - result.compliant;
  result.rate     = result.total > 0 ? Math.round((result.compliant / result.total) * 100) : null;
  return result;
}

// ── False positive rate ───────────────────────────────────────────
function computeFprTpr(alerts) {
  const total     = alerts.length;
  const tp        = alerts.filter(a => a.outcome === 'true_positive').length;
  const fp        = alerts.filter(a => a.outcome === 'false_positive').length;
  const tn        = alerts.filter(a => a.outcome === 'true_negative').length;
  const fn        = alerts.filter(a => a.outcome === 'false_negative').length;
  const labeled   = tp + fp + tn + fn;

  return {
    total,
    labeled,
    unlabeled:   total - labeled,
    true_positive:  tp,
    false_positive: fp,
    true_negative:  tn,
    false_negative: fn,
    fpr:  (fp + tn) > 0 ? Math.round((fp / (fp + tn)) * 100) / 100 : null,
    tpr:  (tp + fn) > 0 ? Math.round((tp / (tp + fn)) * 100) / 100 : null,
    precision: (tp + fp) > 0 ? Math.round((tp / (tp + fp)) * 100) / 100 : null,
    f1:   null, // computed below
  };
}

// ── Full SOC dashboard metrics ────────────────────────────────────
// Accepts two calling conventions:
//   1. buildDashboardMetrics(alerts, analysts, opts)  ← route style
//   2. buildDashboardMetrics(db, opts)                ← legacy style
//
// In convention 1, alerts and analysts arrays are passed directly by
// the route (which already fetched them), so no extra DB call is made.
// In convention 2, a Supabase client is passed and data is fetched here.
async function buildDashboardMetrics(alertsOrDb, analystsOrOpts = {}, opts = {}) {
  const now = new Date();

  let alerts, analysts, cases, investigations, flatAssignments;

  // Detect calling convention: if first arg is an Array, it's (alerts, analysts, opts)
  if (Array.isArray(alertsOrDb)) {
    // Convention 1 — route pre-fetched alerts/analysts
    alerts   = alertsOrDb;
    analysts = Array.isArray(analystsOrOpts) ? analystsOrOpts : [];
    const { since, until, tenantId } = opts;
    const window = opts.days || opts.windowDays || 30;

    // Fetch cases and investigations using the Supabase client from config
    let db = null;
    try { ({ supabase: db } = require('../../config/supabase')); } catch (_) {}

    if (db && tenantId) {
      const sinceTs = since || new Date(now - window * 86_400_000).toISOString();
      const untilTs = until || now.toISOString();

      const [casesRes, invRes, assignRes] = await Promise.allSettled([
        db.from('cases').select('id,severity,priority,status,created_at,closed_at,escalated,assignee_id')
          .eq('tenant_id', tenantId).gte('created_at', sinceTs).lte('created_at', untilTs).limit(10000),
        db.from('investigations').select('id,case_id,analyst_id,created_at,completed_at,outcome,priority,mitre_techniques,peer_review_score,lateral_movement_traced,persistence_checked,data_exfil_assessed,recommendations,timeline,iocs,attack_vector,affected_assets,root_cause')
          .eq('tenant_id', tenantId).gte('created_at', sinceTs).limit(5000),
        db.from('case_assignments').select('analyst_id,analyst_name,cases(severity,priority,created_at,closed_at,escalated)')
          .gte('created_at', sinceTs).limit(5000),
      ]);

      cases         = casesRes.status === 'fulfilled'  ? (casesRes.value.data   || []) : [];
      investigations = invRes.status === 'fulfilled'   ? (invRes.value.data     || []) : [];
      const rawAssign = assignRes.status === 'fulfilled' ? (assignRes.value.data || []) : [];
      flatAssignments = rawAssign.map(a => ({
        analyst_id:   a.analyst_id,
        analyst_name: a.analyst_name,
        severity:     a.cases?.severity,
        priority:     a.cases?.priority,
        created_at:   a.cases?.created_at,
        closed_at:    a.cases?.closed_at,
        escalated:    a.cases?.escalated,
      })).filter(a => a.severity);
    } else {
      cases          = [];
      investigations = [];
      flatAssignments = analysts.map(a => ({
        analyst_id: a.id || a.auth_id,
        analyst_name: a.display_name || a.name || a.email,
        severity: null, created_at: null, closed_at: null, escalated: false,
      })).filter(a => a.analyst_id);
    }

  } else {
    // Convention 2 — db client passed directly (legacy)
    const db     = alertsOrDb;
    const window = (analystsOrOpts.windowDays || 30);
    const since  = new Date(now - window * 86_400_000).toISOString();

    const [alertsRes, casesRes, investigationsRes, assignmentsRes] = await Promise.allSettled([
      db.from('alerts').select('*').gte('created_at', since),
      db.from('cases').select('*').gte('created_at', since),
      db.from('investigations').select('*').gte('created_at', since),
      db.from('case_assignments')
        .select('*, cases(severity, priority, created_at, closed_at, escalated)')
        .gte('created_at', since),
    ]);

    alerts        = alertsRes.status === 'fulfilled'         ? (alertsRes.value.data        || []) : [];
    analysts      = [];
    cases         = casesRes.status === 'fulfilled'          ? (casesRes.value.data          || []) : [];
    investigations = investigationsRes.status === 'fulfilled' ? (investigationsRes.value.data || []) : [];
    const rawAssign = assignmentsRes.status === 'fulfilled'   ? (assignmentsRes.value.data   || []) : [];
    flatAssignments = rawAssign.map(a => ({
      analyst_id:   a.analyst_id,
      analyst_name: a.analyst_name,
      severity:     a.cases?.severity,
      priority:     a.cases?.priority,
      created_at:   a.cases?.created_at,
      closed_at:    a.cases?.closed_at,
      escalated:    a.cases?.escalated,
    })).filter(a => a.severity);
  }

  const window = opts.days || opts.windowDays ||
    (Array.isArray(alertsOrDb) ? (opts.days || 30) : (analystsOrOpts.windowDays || 30));

  const mttd       = computeMttd(alerts);
  const mttr       = computeMttr(cases);
  const a2t        = computeAlertToTicket(alerts);
  const workload   = computeAnalystWorkload(flatAssignments);
  const sla        = computeSlaCompliance(cases);
  const fprTpr     = computeFprTpr(alerts);
  const quality    = computeInvestigationQuality(investigations);

  const avgQuality = quality.length > 0
    ? Math.round(quality.reduce((s, q) => s + q.overall, 0) / quality.length)
    : null;

  const criticalBurnout = workload.filter(a => a.burnout_risk === 'CRITICAL').length;

  return {
    generated_at:   now.toISOString(),
    window_days:    window,
    period_start:   opts.since || new Date(now - window * 86_400_000).toISOString(),
    period_end:     opts.until || now.toISOString(),

    overview: {
      total_alerts:      alerts.length,
      total_cases:       cases.length,
      open_cases:        cases.filter(c => !c.closed_at).length,
      critical_alerts:   alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'critical').length,
      sla_compliance:    sla.rate,
      avg_quality_score: avgQuality,
      analysts_at_risk:  criticalBurnout,
    },

    mttd: {
      ...mttd,
      unit:  'minutes',
      label: 'Mean Time To Detect',
    },
    mttr: {
      ...mttr,
      unit:  'minutes',
      label: 'Mean Time To Respond',
    },
    alert_to_ticket: {
      ...a2t,
      unit:  'minutes',
      label: 'Alert to Ticket Time',
    },

    sla_compliance: sla,
    detection_accuracy: fprTpr,
    analyst_workload:  workload,
    investigation_quality: {
      average_score: avgQuality,
      grade_distribution: _gradeDistribution(quality),
      flagged_investigations: quality.filter(q => q.flags.length > 0).length,
      items: quality.slice(0, 20),
    },

    trends: _computeTrends(alerts, cases, window),
  };
}

function _gradeDistribution(quality) {
  const dist = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const q of quality) dist[q.grade] = (dist[q.grade] || 0) + 1;
  return dist;
}

function _computeTrends(alerts, cases, windowDays) {
  const buckets = [];
  const now     = Date.now();
  const bucketH = 24; // daily buckets

  for (let d = windowDays - 1; d >= 0; d--) {
    const startMs = now - (d + 1) * 86_400_000;
    const endMs   = now - d       * 86_400_000;
    const date    = new Date(endMs).toISOString().substring(0, 10);

    const dayAlerts = alerts.filter(a => {
      const t = new Date(a.created_at).getTime();
      return t >= startMs && t < endMs;
    });
    const dayCases = cases.filter(c => {
      const t = new Date(c.created_at).getTime();
      return t >= startMs && t < endMs;
    });

    buckets.push({
      date,
      alerts:   dayAlerts.length,
      cases:    dayCases.length,
      critical: dayAlerts.filter(a => a.severity === 'CRITICAL').length,
      closed:   dayCases.filter(c => c.closed_at && new Date(c.closed_at).getTime() >= startMs && new Date(c.closed_at).getTime() < endMs).length,
    });
  }

  return buckets;
}

// ── Statistics helpers ────────────────────────────────────────────
function _stats(arr) {
  if (!arr || arr.length === 0) return { mean: 0, median: 0, p95: 0, count: 0 };
  const sorted = [...arr].sort((a, b) => a - b);
  const n      = sorted.length;
  const mean   = Math.round((arr.reduce((s, v) => s + v, 0) / n) * 10) / 10;
  const median = n % 2 === 0
    ? Math.round(((sorted[n / 2 - 1] + sorted[n / 2]) / 2) * 10) / 10
    : sorted[Math.floor(n / 2)];
  const p95    = sorted[Math.ceil(n * 0.95) - 1] || sorted[n - 1];

  return { mean, median, p95: Math.round(p95 * 10) / 10, count: n };
}

// ── computeMitreCoverage ────────────────────────────────────────────
// Builds a tactic→technique coverage map from an array of alert objects.
// Each alert is expected to have optional mitre_tactic / mitre_technique fields.
function computeMitreCoverage(alerts = []) {
  const tactics = {};
  for (const a of alerts) {
    const tactic    = a.mitre_tactic    || a.metadata?.mitre_tactic    || 'unknown';
    const technique = a.mitre_technique || a.metadata?.mitre_technique || null;
    if (!tactics[tactic]) tactics[tactic] = { count: 0, techniques: new Set() };
    tactics[tactic].count++;
    if (technique) tactics[tactic].techniques.add(technique);
  }
  // Convert Sets to arrays for JSON serialisation
  const result = {};
  for (const [tactic, data] of Object.entries(tactics)) {
    result[tactic] = { count: data.count, techniques: [...data.techniques] };
  }
  return result;
}

// ── detectBurnoutRisk ──────────────────────────────────────────────
// Analyses alert assignments per analyst and flags burnout risk.
// Returns an array of { analyst_id, email, alert_count, avg_resolution_ms,
//   cases_per_day, risk_level } entries.
function detectBurnoutRisk(alerts = [], analysts = [], { days = 30 } = {}) {
  const workload = {};
  const now = Date.now();
  const windowMs = days * 24 * 3600 * 1000;

  for (const a of alerts) {
    const assignee = a.assigned_to || a.assignee_id;
    if (!assignee) continue;
    const age = now - new Date(a.created_at || 0).getTime();
    if (age > windowMs) continue;
    if (!workload[assignee]) workload[assignee] = { alert_count: 0, resolution_times: [] };
    workload[assignee].alert_count++;
    if (a.resolved_at && a.created_at) {
      const res = new Date(a.resolved_at).getTime() - new Date(a.created_at).getTime();
      if (res > 0) workload[assignee].resolution_times.push(res);
    }
  }

  return (analysts || []).map(analyst => {
    const id   = analyst.id || analyst.auth_id;
    const data = workload[id] || { alert_count: 0, resolution_times: [] };
    const alertsPerDay = data.alert_count / Math.max(days, 1);
    const avgRes = data.resolution_times.length
      ? data.resolution_times.reduce((s, v) => s + v, 0) / data.resolution_times.length
      : null;
    let risk_level = 'LOW';
    if (alertsPerDay > 20)      risk_level = 'CRITICAL';
    else if (alertsPerDay > 10) risk_level = 'HIGH';
    else if (alertsPerDay > 5)  risk_level = 'MEDIUM';
    return {
      analyst_id:          id,
      email:               analyst.email,
      name:                analyst.name || analyst.email,
      alert_count:         data.alert_count,
      alerts_per_day:      Math.round(alertsPerDay * 10) / 10,
      avg_resolution_ms:   avgRes ? Math.round(avgRes) : null,
      risk_level,
    };
  });
}

// ── persistMetricsSnapshot ─────────────────────────────────────────
// Persists a SOC metrics snapshot to the soc_metrics table.
// Returns the inserted row (with .id).
async function persistMetricsSnapshot(tenantId, { period_start, period_end, period_type, dashboard }) {
  const { supabase } = require('../../config/supabase');
  if (!supabase) return { id: null, error: 'Supabase not configured' };

  const row = {
    tenant_id:    tenantId,
    period_start,
    period_end,
    period_type:  period_type || 'daily',
    metrics:      dashboard || {},
    created_at:   new Date().toISOString(),
  };

  const { data, error } = await supabase
    .from('soc_metrics')
    .insert(row)
    .select('id')
    .single();

  if (error) {
    console.error('[SocMetrics] persistMetricsSnapshot error:', error.message);
    return { id: null, error: error.message };
  }
  return { id: data?.id };
}

module.exports = {
  computeMttd,
  computeMttr,
  computeAlertToTicket,
  computeAnalystWorkload,
  computeInvestigationQuality,
  computeSlaCompliance,
  computeFprTpr,
  buildDashboardMetrics,
  computeMitreCoverage,
  detectBurnoutRisk,
  persistMetricsSnapshot,
};
