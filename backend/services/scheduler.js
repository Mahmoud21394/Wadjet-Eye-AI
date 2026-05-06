/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Ingestion Scheduler v5.2
 *  backend/services/scheduler.js
 *
 *  Cron-based scheduler using setInterval (no extra deps).
 *  Runs all ingestion workers on configurable intervals.
 *
 *  Schedule (ENV configurable, defaults in minutes):
 *   OTX_INTERVAL_MIN       60   (every hour)
 *   URLHAUS_INTERVAL_MIN   15   (every 15m)
 *   THREATFOX_INTERVAL_MIN 30   (every 30m)
 *   ABUSEIPDB_INTERVAL_MIN 120  (every 2h)
 *   MALWAREBAZAAR_MIN      30   (every 30m)
 *   FEODO_INTERVAL_MIN     15   (every 15m)
 *   CISA_INTERVAL_MIN      360  (every 6h)
 *   NVD_INTERVAL_MIN       360  (every 6h)
 *   PHISHTANK_MIN          60   (every 1h)
 *   OPENPHISH_MIN          30   (every 30m)
 *   MISP_INTERVAL_MIN      240  (every 4h)
 *   NEWS_INTERVAL_MIN      30   (every 30m)
 *   ENRICH_INTERVAL_MIN    10   (every 10m)
 *   EXPOSURE_INTERVAL_MIN  15   (every 15m)
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');

// ── Lazy-load ingestion modules to avoid circular deps ──────
let _ingestion = null;
let _phishtank = null;
let _news      = null;
let _enrichment = null;
let _exposure  = null;

function getIngestion()  { return _ingestion  || (_ingestion  = require('./ingestion')); }
function getPhishtank()  { return _phishtank  || (_phishtank  = require('./ingestion/phishtank')); }
function getNews()       { return _news       || (_news       = require('./news-ingestion')); }
function getEnrichment() { return _enrichment || (_enrichment = require('./enrichment-engine')); }
// exposure correlation loaded separately

// ── Default MSSP tenant ──────────────────────────────────────
const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ── Track running jobs to avoid overlaps ────────────────────
const runningJobs = new Set();

// ── Helper: safe job wrapper with overlap guard ──────────────
async function safeRun(name, fn) {
  if (runningJobs.has(name)) {
    console.log(`[Scheduler] ${name} already running — skipping`);
    return;
  }
  runningJobs.add(name);
  const t0 = Date.now();
  try {
    console.log(`[Scheduler] ▶ Starting ${name}...`);
    const result = await fn();
    console.log(`[Scheduler] ✓ ${name} done in ${((Date.now() - t0) / 1000).toFixed(1)}s`, result || '');
  } catch (err) {
    console.error(`[Scheduler] ✗ ${name} failed:`, err.message);
  } finally {
    runningJobs.delete(name);
  }
}

// ── Fetch all active tenant IDs ──────────────────────────────
async function getActiveTenants() {
  try {
    const { data, error } = await supabase
      .from('tenants')
      .select('id')
      .eq('active', true);
    if (error || !data || data.length === 0) return [DEFAULT_TENANT];
    return data.map(t => t.id);
  } catch (_) {
    return [DEFAULT_TENANT];
  }
}

// ── Run ingestion across all active tenants ──────────────────
async function runForAllTenants(workerFn, workerName) {
  const tenants = await getActiveTenants();
  for (const tenantId of tenants) {
    try {
      await workerFn(tenantId);
    } catch (err) {
      console.error(`[Scheduler] ${workerName} failed for tenant ${tenantId}:`, err.message);
    }
  }
}

// ── Record ingestion metrics ─────────────────────────────────
async function recordMetric(feedName, feedType, stats) {
  try {
    await supabase.from('ingestion_metrics').upsert({
      tenant_id:       DEFAULT_TENANT,
      feed_name:       feedName,
      feed_type:       feedType,
      date:            new Date().toISOString().slice(0, 10),
      last_run_at:     new Date().toISOString(),
      total_runs:      1,
      success_runs:    stats.error ? 0 : 1,
      failed_runs:     stats.error ? 1 : 0,
      iocs_ingested:   stats.iocs_fetched || 0,
      iocs_new:        stats.iocs_new     || 0,
      avg_duration_ms: stats.duration_ms  || 0,
    }, {
      onConflict: 'tenant_id,feed_name,date',
      // Use raw SQL increment when updating
      ignoreDuplicates: false,
    });
  } catch (_) { /* non-fatal */ }
}

// ══════════════════════════════════════════════════════════════
//  SCHEDULER MAIN: startScheduler()
//
//  Called once from server.js after all routes are mounted.
//  Returns a cleanup function for graceful shutdown.
// ══════════════════════════════════════════════════════════════
function startScheduler() {
  const MIN = 60 * 1000; // 1 minute in ms
  const intervals = [];

  // ── Helper to create a guarded interval ─────────────────────
  // FIX v11.0: Each job gets its own stagger slot so startup bursts are
  // spread across 2-10 minutes instead of all firing within 90s.
  // This eliminates the Supabase statement-timeout storm on server boot.
  let _staggerSlot = 0;
  const STAGGER_BASE_MS  = 2 * 60 * 1000;  // 2 min minimum before first run
  const STAGGER_STEP_MS  = 20 * 1000;      // 20 s between consecutive jobs

  function every(minutes, name, fn) {
    const ms = minutes * MIN;
    // Stagger: each job starts at STAGGER_BASE + slot * STAGGER_STEP
    const delayMs = STAGGER_BASE_MS + (_staggerSlot++ * STAGGER_STEP_MS);
    const initial = setTimeout(() => safeRun(name, fn), delayMs);
    // Then repeat on the full interval
    const timer = setInterval(() => safeRun(name, fn), ms);
    intervals.push(timer, initial);
    console.log(`[Scheduler] Registered: ${name} every ${minutes}m (first run in ${Math.round(delayMs/1000)}s)`);
  }

  // ── Stagger initial runs to avoid hammering APIs ────────────

  // AlienVault OTX — every 60m
  every(
    parseInt(process.env.OTX_INTERVAL_MIN) || 60,
    'OTX',
    () => runForAllTenants(getIngestion().ingestOTX, 'OTX')
  );

  // URLhaus — every 15m
  every(
    parseInt(process.env.URLHAUS_INTERVAL_MIN) || 15,
    'URLhaus',
    () => runForAllTenants(getIngestion().ingestURLhaus, 'URLhaus')
  );

  // ThreatFox — every 30m
  every(
    parseInt(process.env.THREATFOX_INTERVAL_MIN) || 30,
    'ThreatFox',
    () => runForAllTenants(getIngestion().ingestThreatFox, 'ThreatFox')
  );

  // AbuseIPDB — every 2h
  every(
    parseInt(process.env.ABUSEIPDB_INTERVAL_MIN) || 120,
    'AbuseIPDB',
    () => runForAllTenants(getIngestion().ingestAbuseIPDB, 'AbuseIPDB')
  );

  // MalwareBazaar — every 30m
  every(
    parseInt(process.env.MALWAREBAZAAR_MIN) || 30,
    'MalwareBazaar',
    () => runForAllTenants(getIngestion().ingestMalwareBazaar, 'MalwareBazaar')
  );

  // Feodo Tracker — every 15m
  every(
    parseInt(process.env.FEODO_INTERVAL_MIN) || 15,
    'FeodoTracker',
    () => runForAllTenants(getIngestion().ingestFeodoTracker, 'FeodoTracker')
  );

  // CISA KEV — every 6h
  every(
    parseInt(process.env.CISA_INTERVAL_MIN) || 360,
    'CISA-KEV',
    () => runForAllTenants(getIngestion().ingestCISAKEV, 'CISA-KEV')
  );

  // NVD CVEs — every 6h
  every(
    parseInt(process.env.NVD_INTERVAL_MIN) || 360,
    'NVD-CVE',
    async () => {
      const { ingestNVD } = require('./ingestion/nvd');
      await runForAllTenants(ingestNVD, 'NVD-CVE');
    }
  );

  // PhishTank — every 1h (free tier)
  every(
    parseInt(process.env.PHISHTANK_MIN) || 60,
    'PhishTank',
    () => runForAllTenants(getPhishtank().ingestPhishTank, 'PhishTank')
  );

  // OpenPhish — every 30m
  every(
    parseInt(process.env.OPENPHISH_MIN) || 30,
    'OpenPhish',
    () => runForAllTenants(getPhishtank().ingestOpenPhish, 'OpenPhish')
  );

  // MISP CIRCL — every 4h
  every(
    parseInt(process.env.MISP_INTERVAL_MIN) || 240,
    'MISP-CIRCL',
    () => runForAllTenants(getPhishtank().ingestMISPCircl, 'MISP-CIRCL')
  );

  // Abuse.ch SSL Blacklist — every 30m
  every(
    30,
    'SSLBL',
    () => runForAllTenants(getPhishtank().ingestSSLBlacklist, 'SSLBL')
  );

  // Botvrij.eu — every 4h
  every(
    240,
    'Botvrij',
    () => runForAllTenants(getPhishtank().ingestBotvrij, 'Botvrij')
  );

  // Ransomware.live — every 2h
  every(
    parseInt(process.env.RANSOMWARE_INTERVAL_MIN) || 120,
    'Ransomware.live',
    () => runForAllTenants(getIngestion().ingestRansomwareLive, 'Ransomware.live')
  );

  // Emerging Threats — every 4h
  every(
    240,
    'EmergingThreats',
    () => runForAllTenants(getIngestion().ingestEmergingThreats, 'EmergingThreats')
  );

  // ── Cyber News RSS — every 30m ──────────────────────────────
  every(
    parseInt(process.env.NEWS_INTERVAL_MIN) || 30,
    'CyberNews',
    () => runForAllTenants(getNews().ingestCyberNews, 'CyberNews')
  );

  // ── IOC Enrichment — every 10m ─────────────────────────────
  every(
    parseInt(process.env.ENRICH_INTERVAL_MIN) || 10,
    'IOCEnrichment',
    async () => {
      const tenants = await getActiveTenants();
      for (const tid of tenants) {
        await getEnrichment().enrichBatch(tid, 10); // 10 IOCs per cycle
      }
    }
  );

  // ── Exposure Correlation — every 15m ───────────────────────
  every(
    parseInt(process.env.EXPOSURE_INTERVAL_MIN) || 15,
    'ExposureCorrelation',
    async () => {
      try {
        const { runExposureCorrelation } = require('../routes/exposure');
        const tenants = await getActiveTenants();
        for (const tid of tenants) {
          await runExposureCorrelation(tid);
        }
      } catch (_) {} // exposure route may not export this
    }
  );

  // ── Dashboard stats cache refresh — every 5m ───────────────
  every(
    5,
    'DashboardCache',
    async () => {
      try {
        const { refreshDashboardCache } = require('../routes/dashboard');
        if (typeof refreshDashboardCache === 'function') {
          await refreshDashboardCache(DEFAULT_TENANT);
        }
      } catch (_) {}
    }
  );

  console.log('[Scheduler] ✓ All jobs registered. Running on Render free tier.');

  // Return cleanup function for graceful shutdown
  return function stopScheduler() {
    for (const timer of intervals) {
      clearInterval(timer);
      clearTimeout(timer);
    }
    console.log('[Scheduler] All jobs stopped.');
  };
}

module.exports = { startScheduler };
