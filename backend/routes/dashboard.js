/**
 * ══════════════════════════════════════════════════════════
 *  Dashboard Routes — KPIs, charts, summary stats
 *  GET /api/dashboard/overview
 *  GET /api/dashboard/trends
 *  GET /api/dashboard/top-iocs
 *  GET /api/dashboard/recent-alerts
 *  GET /api/dashboard/stats-live   ← NEW: unified KPI endpoint
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase }    = require('../config/supabase');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── GET /api/dashboard/overview — main KPI cards ── */
router.get('/overview', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const since24h = new Date(Date.now() - 24 * 3600000).toISOString();

  const [
    { data: alertsData,    error: ae },
    { data: casesData,     error: ce },
    { data: iocsData,      error: ie },
    { count: alertsToday,  error: ate },
  ] = await Promise.all([
    supabase.from('alerts').select('severity, status').eq('tenant_id', tenantId),
    supabase.from('cases').select('severity, status').eq('tenant_id', tenantId),
    supabase.from('iocs').select('reputation, risk_score').eq('tenant_id', tenantId).eq('status', 'active'),
    supabase.from('alerts').select('*', { count: 'exact', head: true }).eq('tenant_id', tenantId).gte('created_at', since24h),
  ]);

  // Log errors but NEVER return 500 — use empty arrays as fallback
  if (ae) console.error('[Dashboard/overview] alerts error:', ae.message);
  if (ce) console.error('[Dashboard/overview] cases error:', ce.message);
  if (ie) console.error('[Dashboard/overview] iocs error:', ie.message);

  const alerts = alertsData || [];
  const cases  = casesData  || [];
  const iocs   = iocsData   || [];

  res.json({
    alerts: {
      total:       alerts.length,
      critical:    alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'critical').length,
      high:        alerts.filter(a => a.severity === 'HIGH' || a.severity === 'high').length,
      open:        alerts.filter(a => a.status   === 'open').length,
      in_progress: alerts.filter(a => a.status   === 'in_progress').length,
      today:       alertsToday || 0,
    },
    cases: {
      total:       cases.length,
      critical:    cases.filter(c => c.severity === 'CRITICAL' || c.severity === 'critical').length,
      open:        cases.filter(c => c.status   === 'open').length,
      in_progress: cases.filter(c => c.status   === 'in_progress').length,
    },
    iocs: {
      total:     iocs.length,
      malicious: iocs.filter(i => i.reputation === 'malicious').length,
      high_risk: iocs.filter(i => i.risk_score >= 80).length,
      avg_score: iocs.length
        ? Math.round(iocs.reduce((s, i) => s + (i.risk_score || 0), 0) / iocs.length)
        : 0,
    },
    threat_pressure: Math.min(100, Math.round(
      alerts.filter(a => a.status === 'open').length * 2 +
      iocs.filter(i => i.risk_score >= 80).length * 3
    )),
  });
}));

/* ── GET /api/dashboard/stats-live — unified KPI for Command Center ──
   Returns all metrics needed for the 6 KPI cards + sidebar badges in
   a single request to minimise round-trips. Cached for 30 seconds
   at the HTTP layer via Cache-Control header.
──────────────────────────────────────────────────────────────────── */
router.get('/stats-live', asyncHandler(async (req, res) => {
  const tid      = req.tenantId;
  const since24h = new Date(Date.now() - 24 * 3600000).toISOString();

  const [
    alertsRes,
    iocsRes,
    casesRes,
    feedLogsRes,
    aiSessionsRes,
    actorsRes,
  ] = await Promise.all([
    // Alerts: all open/in-progress, last 24h count
    supabase.from('alerts')
      .select('id, severity, status, created_at')
      .eq('tenant_id', tid)
      .in('status', ['open', 'in_progress']),

    // IOCs: total active + malicious count
    supabase.from('iocs')
      .select('id, reputation, risk_score')
      .eq('tenant_id', tid)
      .eq('status', 'active'),

    // Cases: open count
    supabase.from('cases')
      .select('id, severity, status')
      .eq('tenant_id', tid)
      .in('status', ['open', 'in_progress']),

    // Feed logs: latest run per feed (determines "active feeds")
    supabase.from('feed_logs')
      .select('feed_name, status, finished_at, iocs_new, iocs_fetched')
      .eq('tenant_id', tid)
      .order('finished_at', { ascending: false })
      .limit(50),

    // AI sessions (investigations count)
    supabase.from('ai_sessions')
      .select('id', { count: 'exact', head: true })
      .eq('tenant_id', tid),

    // Threat actors count
    supabase.from('threat_actors')
      .select('id', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`),
  ]);

  const alerts     = alertsRes.data  || [];
  const iocs       = iocsRes.data    || [];
  const cases      = casesRes.data   || [];
  const feedLogs   = feedLogsRes.data || [];
  const aiCount    = aiSessionsRes.count || 0;
  const actorCount = actorsRes.count || 0;

  // Deduplicate feed logs — one entry per feed_name, keep most recent
  const latestPerFeed = {};
  for (const log of feedLogs) {
    if (!latestPerFeed[log.feed_name] ||
        new Date(log.finished_at) > new Date(latestPerFeed[log.feed_name].finished_at)) {
      latestPerFeed[log.feed_name] = log;
    }
  }
  const feedList       = Object.values(latestPerFeed);
  const activeFeeds    = feedList.filter(f => f.status === 'success' || f.status === 'partial').length;

  // New IOCs in last 24h
  const iocsTodayCount = feedLogs
    .filter(f => f.finished_at && new Date(f.finished_at) > new Date(since24h))
    .reduce((sum, f) => sum + (f.iocs_new || 0), 0);

  // KPI calculations
  const criticalAlerts = alerts.filter(a =>
    a.severity === 'critical' || a.severity === 'CRITICAL').length;
  const highAlerts     = alerts.filter(a =>
    a.severity === 'high'     || a.severity === 'HIGH').length;
  const totalFindings  = alerts.length + cases.length;
  const maliciousIOCs  = iocs.filter(i => i.reputation === 'malicious').length;
  const highRiskIOCs   = iocs.filter(i => (i.risk_score || 0) >= 70).length;
  const avgRisk        = iocs.length
    ? Math.round(iocs.reduce((s, i) => s + (i.risk_score || 0), 0) / iocs.length) : 0;

  // Threat pressure index (0-100)
  const threatPressure = Math.min(100, Math.round(
    criticalAlerts * 8 + highAlerts * 3 + highRiskIOCs * 2
  ));

  // Set 30-second cache so frequent tab switches don't spam the DB
  res.set('Cache-Control', 'private, max-age=30');

  res.json({
    // ── 6 KPI cards ────────────────────────────────────────
    kpis: {
      critical_threats:   criticalAlerts,
      high_severity:      highAlerts,
      total_findings:     totalFindings,
      active_feeds:       activeFeeds,
      iocs_collected:     iocs.length,
      ai_investigations:  aiCount,
    },
    // ── Deltas (24h change) ─────────────────────────────────
    deltas: {
      iocs_today:    iocsTodayCount,
      alerts_today:  alerts.filter(a => a.created_at > since24h).length,
    },
    // ── Extra context for sidebar badges ───────────────────
    sidebar: {
      critical_badge:  criticalAlerts,
      findings_badge:  totalFindings,
      ioc_badge:       iocs.length,
      cases_badge:     cases.length,
      actors_badge:    actorCount,
    },
    // ── Threat pressure ────────────────────────────────────
    threat_pressure: threatPressure,
    threat_level:    threatPressure >= 75 ? 'CRITICAL' :
                     threatPressure >= 50 ? 'HIGH' :
                     threatPressure >= 25 ? 'MEDIUM' : 'LOW',
    // ── Feed status list (for mini-collector panel) ─────────
    feed_status: feedList.slice(0, 10),
    // ── IOC distribution (for pie chart) ───────────────────
    ioc_distribution: {
      malicious:  maliciousIOCs,
      suspicious: iocs.filter(i => i.reputation === 'suspicious').length,
      clean:      iocs.filter(i => i.reputation === 'clean').length,
      unknown:    iocs.filter(i => !i.reputation || i.reputation === 'unknown').length,
    },
    generated_at: new Date().toISOString(),
  });
}));

/* ── GET /api/dashboard/trends — 7-day alert trend ── */
router.get('/trends', asyncHandler(async (req, res) => {
  const days = parseInt(req.query.days, 10) || 7;
  if (days < 1 || days > 90) throw createError(400, 'days must be between 1 and 90');

  const since = new Date(Date.now() - days * 86400000).toISOString();

  const { data, error } = await supabase
    .from('alerts')
    .select('created_at, severity')
    .eq('tenant_id', req.tenantId)
    .gte('created_at', since)
    .order('created_at', { ascending: true });

  // NEVER return 500 — use empty data on DB error
  if (error) { console.error('[Dashboard/trends] error:', error.message); }

  const byDay = {};
  (data || []).forEach(alert => {
    const day = alert.created_at.split('T')[0];
    if (!byDay[day]) byDay[day] = { date: day, total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    byDay[day].total++;
    byDay[day][alert.severity?.toLowerCase() || 'low']++;
  });

  res.json({ trends: Object.values(byDay), period_days: days });
}));

/* ── GET /api/dashboard/top-iocs — highest risk IOCs ── */
router.get('/top-iocs', asyncHandler(async (req, res) => {
  const limit = Math.min(20, parseInt(req.query.limit, 10) || 10);

  const { data, error } = await supabase
    .from('iocs')
    .select('id, value, type, reputation, risk_score, country, threat_actor, last_seen')
    .eq('tenant_id', req.tenantId)
    .eq('status', 'active')
    .order('risk_score', { ascending: false })
    .limit(limit);

  // NEVER return 500 — return empty array on DB error
  if (error) console.error('[Dashboard/top-iocs] error:', error.message);
  res.json(data || []);
}));

/* ── GET /api/dashboard/recent-alerts — latest alerts ── */
router.get('/recent-alerts', asyncHandler(async (req, res) => {
  const limit = Math.min(50, parseInt(req.query.limit, 10) || 10);

  const { data, error } = await supabase
    .from('alerts')
    .select('id, title, severity, status, type, ioc_value, created_at')
    .eq('tenant_id', req.tenantId)
    .order('created_at', { ascending: false })
    .limit(limit);

  // NEVER return 500 — return empty array on DB error
  if (error) console.error('[Dashboard/recent-alerts] error:', error.message);
  res.json(data || []);
}));

module.exports = router;
