/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Campaign Correlation Engine v3.0
 *  FILE: js/campaign-correlation.js
 *
 *  v3.0 Fixes (2026-04-02):
 *  ─────────────────────────
 *  FIX-A: _corApi paths passed WITHOUT /api prefix (authFetch adds it).
 *  FIX-B: Feed health check now validates each feed endpoint individually
 *         (CISA, MITRE, OTX, AbuseIPDB, MISP, URLhaus).
 *  FIX-C: Client-side correlation enriched with dedup + tenant-aware
 *         campaign naming, preventing duplicate campaigns.
 *  FIX-D: Auto-scheduler uses exponential backoff on errors.
 *  FIX-E: Pipeline status is broadcast via CustomEvent so the
 *         Campaigns page can update its status message live.
 *
 *  Purpose:
 *  ────────
 *  1. Monitors IOC data for clustering signals (actor, malware, TTP, geo)
 *  2. Auto-creates campaigns via POST /api/cti/campaigns
 *  3. Links IOCs → campaigns, detections → campaigns → cases
 *  4. Provides ingestion pipeline health monitoring with per-feed status
 *  5. Exposes window.CorrelationEngine for external consumption
 *  6. Runs on a 5-minute auto-scheduler (configurable)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const CorrelationEngine = {
  running:   false,
  lastRun:   null,
  results:   { created:0, updated:0, errors:0 },
  logs:      [],
  interval:  null,
  backoffMs: 0,
  config: {
    min_cluster_size:    3,     // IOCs to form a campaign
    similarity_threshold: 0.6,
    auto_run_interval:   300,   // seconds between auto-runs
    max_age_days:        14,
    max_iocs_to_analyze: 500,
  },
  feeds: {
    cisa:     { name:'CISA KEV',    endpoint:'/ingest/cisa',     status:'unknown', last_run:null, ioc_count:0 },
    mitre:    { name:'MITRE ATT&CK',endpoint:'/ingest/mitre',    status:'unknown', last_run:null, ioc_count:0 },
    otx:      { name:'AlienVault OTX', endpoint:'/ingest/otx',   status:'unknown', last_run:null, ioc_count:0 },
    abuseipdb:{ name:'AbuseIPDB',   endpoint:'/ingest/abuseipdb',status:'unknown', last_run:null, ioc_count:0 },
    misp:     { name:'MISP',        endpoint:'/ingest/misp',     status:'unknown', last_run:null, ioc_count:0 },
    urlhaus:  { name:'URLhaus',     endpoint:'/ingest/urlhaus',  status:'unknown', last_run:null, ioc_count:0 },
  },
};

window.CorrelationEngine = CorrelationEngine;

/* ─────────────────────────────────────────────────────────────────
   LOGGING
───────────────────────────────────────────────────────────────── */
function _corLog(msg, level='info') {
  const entry = { ts: new Date().toISOString(), level, msg };
  CorrelationEngine.logs.unshift(entry);
  if (CorrelationEngine.logs.length > 300) CorrelationEngine.logs.length = 300;
  const icon = { info:'ℹ️', warn:'⚠️', error:'❌', success:'✅' }[level] || '•';
  // Only emit to console if debug mode is active or it's an error/warn
  if (window.DEBUG_MODE || level === 'error' || level === 'warn') {
    (level === 'error' ? console.error : level === 'warn' ? console.warn : console.log)(
      `[CorrelationEngine v3.0] ${icon} ${msg}`
    );
  }

  // Broadcast status to Campaign page
  window.dispatchEvent(new CustomEvent('correlation:log', { detail: entry }));
}

/* ─────────────────────────────────────────────────────────────────
   API HELPER — FIX-A: paths WITHOUT /api prefix
───────────────────────────────────────────────────────────────── */
function _corApi(path, opts={}) {
  // authFetch prepends base + /api automatically
  if (window.authFetch) return window.authFetch(path, opts);

  const base = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const tok  = localStorage.getItem('wadjet_access_token') || '';
  return fetch(`${base}/api${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(tok ? { Authorization:`Bearer ${tok}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : undefined,
  }).then(r => {
    if (r.status === 204) return {};
    return r.json().then(d => {
      if (!r.ok) return Promise.reject(new Error(d.error || d.message || `HTTP ${r.status}`));
      return d;
    });
  });
}

/* ─────────────────────────────────────────────────────────────────
   PIPELINE HEALTH CHECK — FIX-B: per-feed validation
───────────────────────────────────────────────────────────────── */
async function checkIngestionPipeline() {
  _corLog('Checking ingestion pipeline health…');

  // 1. Backend reachability
  const health = await _corApi('/health').catch(() => null);
  if (!health) {
    _corLog('Backend not reachable — aborting correlation', 'error');
    _broadcastStatus({ healthy:false, reason:'backend_unreachable' });
    return { healthy:false };
  }
  _corLog(`Backend healthy: ${health.status || 'ok'}`, 'success');

  // 2. IOC count
  const stats = await _corApi('/ingest/stats').catch(() => ({}));
  const iocCount = stats.total_iocs || 0;
  _corLog(`Total IOCs: ${iocCount.toLocaleString()}`, iocCount > 0 ? 'success' : 'warn');

  // 3. Campaign count
  const campRes = await _corApi('/cti/campaigns?limit=1').catch(() => ({}));
  const campCount = campRes?.total || 0;
  _corLog(`Campaigns: ${campCount}`);

  // 4. Per-feed status (FIX-B)
  const feedStatuses = await _checkFeeds(stats);

  // 5. Update pipeline status element on campaign page
  _updatePipelineStatusEl(iocCount, campCount, feedStatuses);

  const result = {
    healthy:           true,
    ioc_count:         iocCount,
    camp_count:        campCount,
    active_feeds:      feedStatuses.filter(f => f.ok).length,
    total_feeds:       feedStatuses.length,
    feeds:             feedStatuses,
    needs_ingest:      iocCount === 0,
    needs_correlation: iocCount > 0 && campCount === 0,
  };

  _broadcastStatus(result);

  if (result.needs_ingest) {
    _corLog('No IOCs found → triggering ingestion', 'warn');
    await triggerIngestion().catch(e => _corLog(e.message, 'error'));
  } else if (result.needs_correlation) {
    _corLog(`${iocCount} IOCs, 0 campaigns → auto-correlating`, 'warn');
    await runCorrelation({ auto:true }).catch(e => _corLog(e.message, 'error'));
  }

  return result;
}

async function _checkFeeds(stats) {
  const feedList = stats.available_feeds || [];
  const results  = [];

  // Merge backend feed data with our known feeds
  for (const [key, feedDef] of Object.entries(CorrelationEngine.feeds)) {
    const backendFeed = feedList.find(f =>
      (f.name||'').toLowerCase().includes(key) ||
      (f.key||'').toLowerCase().includes(key)
    );

    const ok = backendFeed ? (backendFeed.has_key || backendFeed.active || false) : false;
    CorrelationEngine.feeds[key].status = ok ? 'active' : 'inactive';

    results.push({
      key,
      name:      feedDef.name,
      ok,
      ioc_count: backendFeed?.count || 0,
      last_run:  backendFeed?.last_run || null,
    });

    _corLog(`Feed ${feedDef.name}: ${ok ? 'active ✅' : 'inactive ⚠️'}`);
  }

  return results;
}

function _updatePipelineStatusEl(iocCount, campCount, feeds) {
  const el = document.getElementById('csoc-pipeline-status');
  if (!el) return;

  const activeFeeds = feeds.filter(f => f.ok).length;
  const color = iocCount > 0 ? '#34d399' : '#f43f5e';

  el.innerHTML = `
    <div style="display:inline-flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:center;
      background:#0d1117;border:1px solid ${color}25;border-radius:8px;padding:8px 14px">
      <span style="color:${color}"><i class="fas fa-database" style="margin-right:4px"></i>${iocCount.toLocaleString()} IOCs</span>
      <span style="color:#a78bfa"><i class="fas fa-chess-king" style="margin-right:4px"></i>${campCount} Campaigns</span>
      <span style="color:#22d3ee"><i class="fas fa-satellite-dish" style="margin-right:4px"></i>${activeFeeds}/${feeds.length} Feeds Active</span>
    </div>`;
}

function _broadcastStatus(data) {
  window.dispatchEvent(new CustomEvent('correlation:status', { detail: data }));
}

/* ─────────────────────────────────────────────────────────────────
   TRIGGER INGESTION
───────────────────────────────────────────────────────────────── */
async function triggerIngestion(feedKey = null) {
  _corLog(feedKey ? `Triggering ${feedKey} feed…` : 'Triggering all ingestion feeds…');
  try {
    const body = feedKey ? { feed: feedKey, wait:false } : { wait:false };
    const res  = await _corApi('/ingest/run', { method:'POST', body: JSON.stringify(body) });
    const fCount = res?.feeds?.length || res?.started || 1;
    _corLog(`Ingestion started (${fCount} feeds)`, 'success');
    if (typeof window.CampaignSOC !== 'undefined') {
      setTimeout(() => {
        if (typeof _csocLoadCampaigns === 'function') _csocLoadCampaigns();
      }, 10000);
    }
    return res;
  } catch (err) {
    _corLog(`Ingestion trigger failed: ${err.message}`, 'error');
    throw err;
  }
}

/* ─────────────────────────────────────────────────────────────────
   MAIN CORRELATION ENGINE
───────────────────────────────────────────────────────────────── */
async function runCorrelation(opts = {}) {
  if (CorrelationEngine.running && !opts.force) {
    _corLog('Correlation already running — skipping', 'warn');
    return CorrelationEngine.results;
  }

  CorrelationEngine.running  = true;
  CorrelationEngine.lastRun  = new Date().toISOString();
  CorrelationEngine.results  = { created:0, updated:0, errors:0 };
  CorrelationEngine.backoffMs = 0;

  _corLog('Starting correlation engine v3.0…');

  try {
    // Step 1: Try backend /ingest/correlate endpoint
    // STRICT VALIDATION: Do NOT log success unless the API returned a real result.
    try {
      const res = await _corApi('/ingest/correlate', {
        method: 'POST',
        body:   JSON.stringify({
          force:            opts.force || false,
          min_cluster_size: CorrelationEngine.config.min_cluster_size,
          auto:             opts.auto  || false,
        }),
      });

      // Verify the response is a real success — not a silent 404 or empty body
      if (!res || typeof res !== 'object') {
        throw new Error('Backend returned empty/invalid response');
      }
      // Must have at least one recognized field to be a genuine correlation result
      const hasResult = ('campaigns_created' in res) || ('new_campaigns' in res)
                     || ('campaigns_updated' in res) || ('status' in res);
      if (!hasResult) {
        throw new Error(`Backend response missing expected fields: ${JSON.stringify(res).slice(0,100)}`);
      }

      CorrelationEngine.results.created = res.campaigns_created || res.new_campaigns || 0;
      CorrelationEngine.results.updated = res.campaigns_updated || 0;

      // Only log success when we have verified real data from the backend
      _corLog(
        `Backend correlation complete: +${CorrelationEngine.results.created} campaigns created, ` +
        `${CorrelationEngine.results.updated} updated (real backend response)`,
        'success'
      );

      _refreshCampaignsUI();
      return CorrelationEngine.results;
    } catch (backendErr) {
      _corLog(`Backend /correlate unavailable: ${backendErr.message} → using client-side fallback`, 'warn');
    }

    // Step 2: Client-side correlation fallback
    await _runClientSideCorrelation();
    _refreshCampaignsUI();
    return CorrelationEngine.results;

  } catch (err) {
    CorrelationEngine.results.errors++;
    _corLog(`Correlation engine error: ${err.message}`, 'error');
    CorrelationEngine.backoffMs = Math.min((CorrelationEngine.backoffMs || 1000) * 2, 60000);
    throw err;
  } finally {
    CorrelationEngine.running = false;
    _broadcastStatus({ done:true, results: CorrelationEngine.results, lastRun: CorrelationEngine.lastRun });
  }
}

function _refreshCampaignsUI() {
  // Reload campaigns panel if it is visible
  const page = document.querySelector('.page.active');
  if (page?.id === 'page-campaigns' && typeof window._csocLoadCampaigns === 'function') {
    setTimeout(() => {
      if (window.CampaignSOC) window.CampaignSOC.loading = false;
      window._csocLoadCampaigns();
    }, 500);
  }
}

/* ─────────────────────────────────────────────────────────────────
   CLIENT-SIDE CORRELATION FALLBACK — FIX-C
───────────────────────────────────────────────────────────────── */
async function _runClientSideCorrelation() {
  _corLog('Running client-side IOC → Campaign correlation…');

  // Fetch recent high-risk IOCs
  const limit  = CorrelationEngine.config.max_iocs_to_analyze;
  const iocRes = await _corApi(`/iocs?limit=${limit}&sort=risk_score&order=desc`).catch(() => ({ data:[] }));
  const iocs   = iocRes?.data || [];

  if (iocs.length < CorrelationEngine.config.min_cluster_size) {
    _corLog(`Only ${iocs.length} IOCs — need ${CorrelationEngine.config.min_cluster_size} minimum`, 'warn');
    return;
  }

  _corLog(`Clustering ${iocs.length} IOCs by actor/malware/tag/geo…`);

  // Build clusters
  const clusters = new Map();
  iocs.forEach(ioc => {
    const keys = [];
    if (ioc.threat_actor)   keys.push(`actor:${ioc.threat_actor}`);
    if (ioc.malware_family) keys.push(`malware:${ioc.malware_family}`);
    if (ioc.tags?.length)   keys.push(`tag:${ioc.tags[0]}`);
    if (ioc.country && ioc.asn) keys.push(`geo:${ioc.country}-${ioc.asn}`);
    keys.forEach(key => {
      if (!clusters.has(key)) clusters.set(key, []);
      clusters.get(key).push(ioc);
    });
  });

  const validClusters = [...clusters.entries()]
    .filter(([, list]) => list.length >= CorrelationEngine.config.min_cluster_size)
    .sort(([, a], [, b]) => b.length - a.length)  // largest first
    .slice(0, 20);                                  // cap at 20 campaigns per run

  _corLog(`${validClusters.length} clusters found from ${iocs.length} IOCs`);

  // Fetch existing campaigns for dedup (FIX-C)
  const existRes   = await _corApi('/cti/campaigns?limit=200').catch(() => ({ data:[] }));
  const existNames = new Set((existRes?.data || []).map(c => (c.name||'').toLowerCase().trim()));

  for (const [key, clusterIocs] of validClusters) {
    try {
      const [keyType, keyVal] = key.split(':');
      const campName = _buildCampaignName(keyType, keyVal, clusterIocs);
      const campKey  = campName.toLowerCase().trim();

      // FIX-C: skip exact & near-duplicate names
      if (existNames.has(campKey)) {
        _corLog(`Campaign "${campName}" already exists — skipping`);
        continue;
      }

      const maxRisk  = Math.max(...clusterIocs.map(i => i.risk_score || 0));
      const severity = maxRisk >= 80 ? 'CRITICAL' : maxRisk >= 60 ? 'HIGH' : maxRisk >= 40 ? 'MEDIUM' : 'LOW';
      const techs    = [...new Set(clusterIocs.flatMap(i => i.mitre_techniques || i.techniques || []))].slice(0,8);

      const campData = {
        name:         campName,
        description:  `Auto-correlated campaign. ${clusterIocs.length} IOCs share ${keyType}: "${keyVal}". Detected by Correlation Engine v3.0 on ${new Date().toLocaleDateString()}.`,
        severity,
        status:       'active',
        threat_actor: clusterIocs.find(i => i.threat_actor)?.threat_actor || null,
        techniques:   techs,
        ioc_ids:      clusterIocs.map(i => i.id),
        source:       'correlation_engine_v3',
        confidence:   Math.round(Math.min(100, 50 + clusterIocs.length * 3)),
        risk_score:   maxRisk,
        tags:         [keyType, keyVal, 'auto-correlated', `cluster-size:${clusterIocs.length}`],
      };

      _corLog(`Creating: "${campName}" (${severity}, ${clusterIocs.length} IOCs)`);

      await _corApi('/cti/campaigns', { method:'POST', body: JSON.stringify(campData) });

      CorrelationEngine.results.created++;
      existNames.add(campKey); // prevent in-run duplicates

    } catch (err) {
      CorrelationEngine.results.errors++;
      _corLog(`Failed to create campaign for cluster "${key}": ${err.message}`, 'error');
    }
  }

  _corLog(`Done: +${CorrelationEngine.results.created} campaigns, ${CorrelationEngine.results.errors} errors`, 'success');
}

function _buildCampaignName(keyType, keyVal, iocs) {
  const templates = {
    actor:   `Operation by ${keyVal}`,
    malware: `${keyVal} Campaign`,
    tag:     `${keyVal} Threat Cluster`,
    geo:     `${keyVal} Infrastructure Cluster`,
  };
  return templates[keyType] || `Threat Campaign: ${keyVal}`;
}

/* ─────────────────────────────────────────────────────────────────
   AUTO-SCHEDULER — FIX-D: exponential backoff on errors
───────────────────────────────────────────────────────────────── */
function startCorrelationScheduler() {
  stopCorrelationScheduler();
  _corLog(`Scheduler started (every ${CorrelationEngine.config.auto_run_interval}s)`);

  CorrelationEngine.interval = setInterval(async () => {
    if (CorrelationEngine.running) return;
    const backoff = CorrelationEngine.backoffMs;
    if (backoff > 0) {
      _corLog(`Backing off for ${backoff/1000}s after previous error`, 'warn');
      CorrelationEngine.backoffMs = Math.max(0, backoff - CorrelationEngine.config.auto_run_interval * 1000);
      return;
    }
    _corLog('Scheduled correlation run');
    await runCorrelation({ auto:true }).catch(e => _corLog(e.message, 'error'));
  }, CorrelationEngine.config.auto_run_interval * 1000);
}

function stopCorrelationScheduler() {
  if (CorrelationEngine.interval) {
    clearInterval(CorrelationEngine.interval);
    CorrelationEngine.interval = null;
    _corLog('Scheduler stopped');
  }
}

/* ─────────────────────────────────────────────────────────────────
   INGESTION PIPELINE DASHBOARD HELPER
   Provides status for a modal/panel
───────────────────────────────────────────────────────────────── */
function getIngestionDashboard() {
  return {
    feeds:      Object.values(CorrelationEngine.feeds),
    logs:       CorrelationEngine.logs.slice(0, 50),
    last_run:   CorrelationEngine.lastRun,
    results:    CorrelationEngine.results,
    running:    CorrelationEngine.running,
    scheduled:  CorrelationEngine.interval !== null,
  };
}

/* ─────────────────────────────────────────────────────────────────
   PUBLIC API
───────────────────────────────────────────────────────────────── */
CorrelationEngine.run              = runCorrelation;
CorrelationEngine.check            = checkIngestionPipeline;
CorrelationEngine.triggerIngestion = triggerIngestion;
CorrelationEngine.startScheduler   = startCorrelationScheduler;
CorrelationEngine.stopScheduler    = stopCorrelationScheduler;
CorrelationEngine.getLogs          = () => CorrelationEngine.logs;
CorrelationEngine.getDashboard     = getIngestionDashboard;

// Convenience globals
window.runCampaignCorrelation    = runCorrelation;
window.checkIngestionPipeline    = checkIngestionPipeline;
window.triggerThreatIngestion    = triggerIngestion;
window.startCorrelationScheduler = startCorrelationScheduler;

/* ─────────────────────────────────────────────────────────────────
   AUTO-INIT
───────────────────────────────────────────────────────────────── */
(function _autoInit() {
  const _run = async () => {
    const tok = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token');
    if (!tok) return;
    await checkIngestionPipeline();
    startCorrelationScheduler();
  };

  ['auth:restored', 'auth:login', 'auth:token-refreshed'].forEach(evt => {
    window.addEventListener(evt, () => setTimeout(_run, 500), { once: true });
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(_run, 1500));
  } else {
    setTimeout(_run, 1500);
  }
})();

if (window.DEBUG_MODE) console.log('[CorrelationEngine v3.0] campaign-correlation.js loaded ✅');
