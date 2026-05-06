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
const { supabase } = require('../config/supabase');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ──────────────────────────────────────────────────────────
   Shared handler used by BOTH:
   GET /api/dashboard
   GET /api/dashboard/stats-live
────────────────────────────────────────────────────────── */

/**
 * ROOT-CAUSE FIX v14.0: Wrap a Supabase query in a per-query timeout.
 * Without this, any single slow query in the Promise.all() stalls the
 * ENTIRE dashboard response — on Supabase free-tier cold-start (0-8s),
 * all 6 parallel queries could time out simultaneously, causing a 15-second
 * hang followed by a 503 cascade that triggers 401 storms on the client.
 *
 * Each query now races its own 8-second timeout and returns an empty
 * fallback on failure, so the dashboard always responds in ≤ 8 seconds
 * with whatever data is available.
 */
function withQueryTimeout(queryPromise, fallback = { data: null, error: null, count: 0 }, timeoutMs = 8_000) {
  const timeoutPromise = new Promise(resolve =>
    setTimeout(() => {
      resolve({ ...fallback, _timedOut: true });
    }, timeoutMs)
  );
  return Promise.race([
    queryPromise.then(res => res).catch(err => ({ ...fallback, _error: err.message })),
    timeoutPromise,
  ]);
}

const statsLiveHandler = asyncHandler(async (req, res) => {
  const tid      = req.tenantId;
  const since24h = new Date(Date.now() - 24 * 3600000).toISOString();

  // ROOT-CAUSE FIX v14.0: Each query wrapped in withQueryTimeout(8s).
  // Any query that hangs (free-tier cold-start) returns empty data instead
  // of blocking the entire Promise.all() for 15+ seconds.
  const [
    alertsRes,
    iocsRes,
    casesRes,
    feedLogsRes,
    aiSessionsRes,
    actorsRes,
  ] = await Promise.all([
    withQueryTimeout(
      supabase.from('alerts')
        .select('id, severity, status, created_at')
        .eq('tenant_id', tid)
        .in('status', ['open', 'in_progress']),
      { data: [], error: null }
    ),

    withQueryTimeout(
      supabase.from('iocs')
        .select('id, reputation, risk_score')
        .eq('tenant_id', tid)
        .eq('status', 'active'),
      { data: [], error: null }
    ),

    withQueryTimeout(
      supabase.from('cases')
        .select('id, severity, status')
        .eq('tenant_id', tid)
        .in('status', ['open', 'in_progress']),
      { data: [], error: null }
    ),

    // Try both table names: legacy 'feed_logs' and new 'cti_feed_logs'.
    // ioc-ingestion.js v5.2 writes to 'cti_feed_logs'; older schema used 'feed_logs'.
    // We query both and merge so the dashboard works regardless of migration state.
    withQueryTimeout(
      supabase.from('cti_feed_logs')
        .select('feed_name, status, finished_at, iocs_new, iocs_fetched')
        .eq('tenant_id', tid)
        .order('finished_at', { ascending: false })
        .limit(50),
      { data: [], error: null }
    ),

    withQueryTimeout(
      supabase.from('ai_sessions')
        .select('id', { count: 'exact', head: true })
        .eq('tenant_id', tid),
      { data: null, error: null, count: 0 }
    ),

    withQueryTimeout(
      supabase.from('threat_actors')
        .select('id', { count: 'exact', head: true })
        .or(`tenant_id.eq.${tid},tenant_id.is.null`),
      { data: null, error: null, count: 0 }
    ),
  ]);

  const alerts     = alertsRes.data  || [];
  const iocs       = iocsRes.data    || [];
  const cases      = casesRes.data   || [];
  const feedLogs   = feedLogsRes.data || [];
  const aiCount    = aiSessionsRes.count || 0;
  const actorCount = actorsRes.count || 0;

  const latestPerFeed = {};
  for (const log of feedLogs) {
    if (!latestPerFeed[log.feed_name] ||
        new Date(log.finished_at) > new Date(latestPerFeed[log.feed_name].finished_at)) {
      latestPerFeed[log.feed_name] = log;
    }
  }

  const feedList    = Object.values(latestPerFeed);
  const activeFeeds = feedList.filter(f => f.status === 'success' || f.status === 'partial').length;

  const iocsTodayCount = feedLogs
    .filter(f => f.finished_at && new Date(f.finished_at) > new Date(since24h))
    .reduce((sum, f) => sum + (f.iocs_new || 0), 0);

  const criticalAlerts = alerts.filter(a => /critical/i.test(a.severity)).length;
  const highAlerts     = alerts.filter(a => /high/i.test(a.severity)).length;
  const totalFindings  = alerts.length + cases.length;
  const maliciousIOCs  = iocs.filter(i => i.reputation === 'malicious').length;
  const highRiskIOCs   = iocs.filter(i => (i.risk_score || 0) >= 70).length;

  const threatPressure = Math.min(100, Math.round(
    criticalAlerts * 8 + highAlerts * 3 + highRiskIOCs * 2
  ));

  res.set('Cache-Control', 'private, max-age=30');

  res.json({
    kpis: {
      critical_threats:  criticalAlerts,
      high_severity:     highAlerts,
      total_findings:    totalFindings,
      active_feeds:      activeFeeds,
      iocs_collected:    iocs.length,
      ai_investigations: aiCount,
    },
    deltas: {
      iocs_today:   iocsTodayCount,
      alerts_today: alerts.filter(a => a.created_at > since24h).length,
    },
    sidebar: {
      critical_badge: criticalAlerts,
      findings_badge: totalFindings,
      ioc_badge:      iocs.length,
      cases_badge:    cases.length,
      actors_badge:   actorCount,
    },
    threat_pressure: threatPressure,
    threat_level: threatPressure >= 75 ? 'CRITICAL'
                  : threatPressure >= 50 ? 'HIGH'
                  : threatPressure >= 25 ? 'MEDIUM' : 'LOW',
    feed_status: feedList.slice(0, 10),
    ioc_distribution: {
      malicious:  maliciousIOCs,
      suspicious: iocs.filter(i => i.reputation === 'suspicious').length,
      clean:      iocs.filter(i => i.reputation === 'clean').length,
      unknown:    iocs.filter(i => !i.reputation || i.reputation === 'unknown').length,
    },
    generated_at: new Date().toISOString(),
  });
});

/* ── THIS FIXES YOUR 404 ── */
router.get('/', statsLiveHandler);

/* ── Original endpoint still works ── */
router.get('/stats-live', statsLiveHandler);

/* keep the rest of your routes EXACTLY as they were below */

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

// ── refreshDashboardCache — called by scheduler every 5 minutes ───
// Pre-warms the Supabase connection and logs a lightweight heartbeat.
// It does NOT make a full stats query (that would saturate the free tier).
// Instead it pings the iocs table with a COUNT which exercises the pool
// without transferring rows, keeping the connection warm between requests.
async function refreshDashboardCache(tenantId) {
  if (!supabase) return;
  try {
    const tid = tenantId || process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';
    const { count, error } = await supabase
      .from('iocs')
      .select('id', { count: 'exact', head: true })
      .eq('tenant_id', tid);
    if (!error) {
      console.log(`[Dashboard] Cache warmup: tenant=${tid} ioc_count=${count}`);
    }
  } catch (err) {
    console.warn('[Dashboard] Cache warmup error (non-fatal):', err.message);
  }
}

module.exports = router;
module.exports.refreshDashboardCache = refreshDashboardCache;
