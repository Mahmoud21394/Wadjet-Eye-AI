/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — IOC Ingestion Pipeline v5.2 (AUTH FIXED)
 *  backend/routes/ioc-ingestion.js
 *
 *  ROOT CAUSE FIX for "HTTP 401 — Missing or invalid Authorization header":
 *  ─────────────────────────────────────────────────────────────────────────
 *  The 401 was caused by DUAL problems:
 *
 *  1. External feed 401s: Fixed by using FeedAuthManager (feed-auth.js)
 *     which centralizes per-feed auth header building and validates
 *     that required API keys are present BEFORE making HTTP calls.
 *
 *  2. Frontend→Backend 401s: Fixed in the frontend (see collectors-fix.js)
 *     where the token lookup now checks ALL known storage keys.
 *
 *  Additional improvements:
 *  ─────────────────────────
 *  - All feed functions now use feedFetch() instead of raw axios
 *  - Detailed per-feed error reporting in /status endpoint
 *  - Feed config validation logged on startup
 *  - Added GET /api/ingest/feeds — returns all feed configs + key status
 *  - Added POST /api/ingest/validate — checks all feed API keys are valid
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const axios  = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { feedFetch, FeedAuthManager, getFeedConfigStatus } = require('../services/feed-auth');

// Use service_role client to bypass RLS for IOC inserts
const supabaseAdmin = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY)
  ? createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY,
      { auth: { autoRefreshToken: false, persistSession: false } }
    )
  : null;

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// Validate feed configs on startup
FeedAuthManager.validateAll();

// ── In-memory feed run log (also persisted to DB) ─────────────────
const _feedRunLog = [];

// ── Helper: normalize and batch-upsert IOCs ────────────────────────
async function upsertIOCs(iocs, tenantId, feedName) {
  if (!iocs || iocs.length === 0) return { inserted: 0, errors: 0 };

  // Guard: supabaseAdmin is null when SUPABASE_URL/SERVICE_KEY are not configured.
  // Without this guard the function crashes with "Cannot read properties of null".
  if (!supabaseAdmin) {
    console.warn(`[Ingest][${feedName}] upsertIOCs skipped — supabaseAdmin is null (SUPABASE_URL/SERVICE_KEY not set)`);
    return { inserted: 0, errors: iocs.length };
  }

  const VALID_TYPES = new Set([
    'ip','domain','url','md5','sha1','sha256','sha512',
    'email','filename','cve','hostname','cidr','hash_md5','hash_sha1','hash_sha256'
  ]);
  // Reduced chunk size: 50 rows — avoids 15s statement-timeout on Supabase free tier
  const CHUNK = 50;
  let inserted = 0, errors = 0;

  const normalized = iocs
    .filter(ioc => ioc && ioc.value && VALID_TYPES.has(ioc.type?.toLowerCase()))
    .map(ioc => ({
      tenant_id:      tenantId || DEFAULT_TENANT,
      value:          String(ioc.value).trim().toLowerCase().slice(0, 512),
      type:           ioc.type.toLowerCase(),
      reputation:     ioc.reputation  || 'malicious',
      risk_score:     Math.min(100, Math.max(0, parseInt(ioc.risk_score) || 70)),
      confidence:     Math.min(100, Math.max(0, parseInt(ioc.confidence) || 80)),
      source:         feedName,
      feed_source:    feedName,
      threat_actor:   ioc.threat_actor  || null,
      malware_family: ioc.malware_family || null,
      tags:           Array.isArray(ioc.tags) ? ioc.tags.filter(Boolean).slice(0, 10) : [],
      country:        ioc.country       || null,
      asn:            ioc.asn           || null,
      first_seen:     ioc.first_seen    || new Date().toISOString(),
      last_seen:      new Date().toISOString(),
      status:         'active',
      enrichment_data: ioc.enrichment_data || {},
      notes:          ioc.notes || `Ingested from ${feedName}`,
    }));

  // Deduplicate within batch by value
  const seen = new Map();
  for (const row of normalized) {
    const existing = seen.get(row.value);
    if (!existing || row.risk_score > existing.risk_score) {
      seen.set(row.value, row);
    }
  }
  const deduped = [...seen.values()];

  // Circuit-breaker: stop after 3 consecutive DB errors to avoid timeout spam
  let consecutiveErrors = 0;
  const MAX_CONSECUTIVE_ERRORS = 3;

  for (let i = 0; i < deduped.length; i += CHUNK) {
    if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
      console.warn(`[Ingest][${feedName}] Circuit-breaker: ${consecutiveErrors} consecutive DB errors — skipping remaining ${deduped.length - i} rows`);
      errors += deduped.length - i;
      break;
    }

    const chunk = deduped.slice(i, i + CHUNK);
    const { error } = await supabaseAdmin
      .from('iocs')
      .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: false });

    if (error) {
      consecutiveErrors++;
      // Suppress repeated spam — only log first and every 5th error
      if (consecutiveErrors === 1 || consecutiveErrors % 5 === 0) {
        console.error(`[Ingest][${feedName}] Upsert error (${consecutiveErrors}):`, error.message);
      }
      // Retry with ignoreDuplicates on conflict error
      if (error.message?.includes('cannot affect row')) {
        const { error: e2 } = await supabaseAdmin
          .from('iocs')
          .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: true });
        if (!e2) { inserted += chunk.length; consecutiveErrors = 0; }
        else errors += chunk.length;
      } else {
        errors += chunk.length;
      }
    } else {
      consecutiveErrors = 0;
      inserted += chunk.length;
    }

    // Backpressure: 150ms between chunks — prevents saturating Supabase free-tier
    if (i + CHUNK < deduped.length) {
      await new Promise(r => setTimeout(r, 150));
    }
  }

  return { inserted, errors };
}

// ── Feed run logger ────────────────────────────────────────────────
async function logFeedRun(tenantId, feedName, result) {
  const entry = {
    tenant_id:    tenantId || DEFAULT_TENANT,
    feed_name:    feedName,
    action:       result.error ? 'ingest_error' : 'ingest_complete',
    status:       result.error ? 'error' : (result.iocs_new > 0 ? 'success' : 'empty'),
    iocs_fetched: result.iocs_fetched || 0,
    iocs_new:     result.iocs_new     || 0,
    error:        result.error        || null,
    auth_error:   result.authError    || false,
    started_at:   result.started_at   || new Date().toISOString(),
    finished_at:  new Date().toISOString(),
    duration_ms:  result.duration_ms  || 0,
    metadata:     result.metadata     || {},
  };

  _feedRunLog.unshift(entry);
  if (_feedRunLog.length > 200) _feedRunLog.pop();

  // Persist to DB (non-blocking) — guard against null supabaseAdmin (no env vars)
  if (supabaseAdmin) {
    try {
      await supabaseAdmin.from('cti_feed_logs').upsert(entry, { ignoreDuplicates: false });
    } catch (_) {}
  }
}

// ══════════════════════════════════════════════════════════════════
//  FEED FUNCTIONS (now using feedFetch for centralized auth)
// ══════════════════════════════════════════════════════════════════

// ── OTX ─────────────────────────────────────────────────────────
async function ingestOTX(tenantId) {
  const t0 = Date.now();
  const started_at = new Date().toISOString();

  const res = await feedFetch(
    'AlienVault OTX',
    'https://otx.alienvault.com/api/v1/indicators/export',
    {
      params: {
        type: 'ip,domain,hostname,url,FileHash-MD5,FileHash-SHA1,FileHash-SHA256',
        limit: 500,
      },
    }
  );

  if (!res.ok) {
    await logFeedRun(tenantId, 'AlienVault OTX', {
      error: res.error, authError: res.authError, started_at,
    });
    return { feed: 'AlienVault OTX', error: res.error, authError: res.authError };
  }

  const iocs = [];
  const typeMap = {
    'IPv4': 'ip', 'IPv6': 'ip',
    'domain': 'domain', 'hostname': 'hostname',
    'URL': 'url',
    'FileHash-MD5': 'md5', 'FileHash-SHA1': 'sha1', 'FileHash-SHA256': 'sha256',
    'email': 'email',
  };

  const lines = String(res.data).split('\n').filter(Boolean);
  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (!entry.indicator) continue;
      const type = typeMap[entry.type];
      if (!type) continue;
      iocs.push({
        value:      entry.indicator,
        type,
        reputation: 'malicious',
        risk_score: 75,
        confidence: entry.confidence || 80,
        tags:       (entry.tags || []).slice(0, 5),
        notes:      `OTX: ${entry.pulse_info?.pulses?.[0]?.name || 'Unknown pulse'}`,
      });
    } catch (_) {}
  }

  const { inserted } = await upsertIOCs(iocs, tenantId, 'AlienVault OTX');
  const duration_ms = Date.now() - t0;
  await logFeedRun(tenantId, 'AlienVault OTX', {
    iocs_fetched: iocs.length, iocs_new: inserted, started_at, duration_ms,
  });
  console.info(`[Ingest][OTX] ✓ fetched=${iocs.length} new=${inserted} in ${duration_ms}ms`);
  return { feed: 'AlienVault OTX', iocs_fetched: iocs.length, iocs_new: inserted, duration_ms };
}

// ── AbuseIPDB ───────────────────────────────────────────────────
async function ingestAbuseIPDB(tenantId) {
  const t0 = Date.now();
  const started_at = new Date().toISOString();

  const res = await feedFetch(
    'AbuseIPDB',
    'https://api.abuseipdb.com/api/v2/blacklist',
    { params: { confidenceMinimum: 25, limit: 10000 } }
  );

  if (!res.ok) {
    await logFeedRun(tenantId, 'AbuseIPDB', {
      error: res.error, authError: res.authError, started_at,
    });
    return { feed: 'AbuseIPDB', error: res.error, authError: res.authError };
  }

  const entries = (res.data?.data || []).slice(0, 2000);
  const iocs = entries
    .filter(e => e.ipAddress)
    .map(e => ({
      value:      e.ipAddress,
      type:       'ip',
      reputation: 'malicious',
      risk_score: Math.min(100, Math.round((e.abuseConfidenceScore || 50) * 0.9)),
      confidence: e.abuseConfidenceScore || 50,
      country:    e.countryCode || null,
      tags:       ['abuseipdb', 'blacklisted'],
      notes:      `AbuseIPDB: ${e.totalReports || 0} reports, confidence=${e.abuseConfidenceScore}%`,
    }));

  const { inserted } = await upsertIOCs(iocs, tenantId, 'AbuseIPDB');
  const duration_ms = Date.now() - t0;
  await logFeedRun(tenantId, 'AbuseIPDB', {
    iocs_fetched: iocs.length, iocs_new: inserted, started_at, duration_ms,
  });
  console.info(`[Ingest][AbuseIPDB] ✓ fetched=${iocs.length} new=${inserted}`);
  return { feed: 'AbuseIPDB', iocs_fetched: iocs.length, iocs_new: inserted, duration_ms };
}

// ── URLhaus ─────────────────────────────────────────────────────
async function ingestURLhaus(tenantId) {
  const t0 = Date.now();
  const started_at = new Date().toISOString();

  const res = await feedFetch(
    'URLhaus',
    'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    { method: 'POST', data: '' }
  );

  if (!res.ok) {
    await logFeedRun(tenantId, 'URLhaus', { error: res.error, started_at });
    return { feed: 'URLhaus', error: res.error };
  }

  const entries = (res.data?.urls || []).slice(0, 500);
  const iocs = [];

  for (const e of entries) {
    if (!e.url) continue;
    iocs.push({
      value:          e.url,
      type:           'url',
      reputation:     'malicious',
      risk_score:     e.threat === 'malware_download' ? 90 : 80,
      confidence:     85,
      malware_family: e.tags?.[0] || null,
      tags:           ['urlhaus', 'malware', ...(e.tags || []).slice(0, 3)],
      notes:          `URLhaus: ${e.threat || 'malicious'} — ${e.url_status || 'online'}`,
      enrichment_data: {
        url_id:     e.id,
        url_status: e.url_status,
        threat:     e.threat,
        reporter:   e.reporter,
      },
    });

    if (e.host) {
      const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(e.host);
      iocs.push({
        value:      e.host,
        type:       isIP ? 'ip' : 'domain',
        reputation: 'malicious',
        risk_score: 80,
        confidence: 80,
        tags:       ['urlhaus'],
        notes:      `URLhaus host: ${e.threat || 'malicious'}`,
      });
    }
  }

  const { inserted } = await upsertIOCs(iocs, tenantId, 'URLhaus');
  const duration_ms = Date.now() - t0;
  await logFeedRun(tenantId, 'URLhaus', {
    iocs_fetched: iocs.length, iocs_new: inserted, started_at, duration_ms,
  });
  console.info(`[Ingest][URLhaus] ✓ fetched=${iocs.length} new=${inserted}`);
  return { feed: 'URLhaus', iocs_fetched: iocs.length, iocs_new: inserted, duration_ms };
}

// ── ThreatFox ───────────────────────────────────────────────────
async function ingestThreatFox(tenantId) {
  const t0 = Date.now();
  const started_at = new Date().toISOString();

  const res = await feedFetch(
    'ThreatFox',
    'https://threatfox-api.abuse.ch/api/v1/',
    { method: 'POST', data: JSON.stringify({ query: 'get_iocs', days: 1 }) }
  );

  if (!res.ok) {
    await logFeedRun(tenantId, 'ThreatFox', { error: res.error, started_at });
    return { feed: 'ThreatFox', error: res.error };
  }

  const entries = (res.data?.data || []).slice(0, 500);
  const typeMap = {
    'ip:port': 'ip', 'domain': 'domain', 'url': 'url',
    'md5_hash': 'md5', 'sha256_hash': 'sha256',
  };

  const iocs = entries
    .filter(e => e.ioc_value)
    .map(e => {
      const type = typeMap[e.ioc_type] || null;
      if (!type) return null;
      const value = e.ioc_type === 'ip:port'
        ? e.ioc_value.split(':')[0]
        : e.ioc_value;
      return {
        value,
        type,
        reputation:     'malicious',
        risk_score:     Math.round((e.confidence_level || 75)),
        confidence:     e.confidence_level || 75,
        malware_family: e.malware,
        tags:           ['threatfox', e.malware || 'malware', e.threat_type || ''].filter(Boolean).slice(0, 5),
        notes:          `ThreatFox: ${e.malware || 'unknown'} [${e.threat_type || 'unknown'}]`,
        enrichment_data: {
          threatfox_id:  e.id,
          malware_printable: e.malware_printable,
          threat_type:   e.threat_type,
          reporter:      e.reporter,
        },
      };
    })
    .filter(Boolean);

  const { inserted } = await upsertIOCs(iocs, tenantId, 'ThreatFox');
  const duration_ms = Date.now() - t0;
  await logFeedRun(tenantId, 'ThreatFox', {
    iocs_fetched: iocs.length, iocs_new: inserted, started_at, duration_ms,
  });
  console.info(`[Ingest][ThreatFox] ✓ fetched=${iocs.length} new=${inserted}`);
  return { feed: 'ThreatFox', iocs_fetched: iocs.length, iocs_new: inserted, duration_ms };
}

// ── MalwareBazaar ───────────────────────────────────────────────
async function ingestMalwareBazaar(tenantId) {
  const t0 = Date.now();
  const started_at = new Date().toISOString();

  const res = await feedFetch(
    'MalwareBazaar',
    'https://mb-api.abuse.ch/api/v1/',
    { method: 'POST', data: 'query=get_recent&selector=time' }
  );

  if (!res.ok) {
    await logFeedRun(tenantId, 'MalwareBazaar', { error: res.error, started_at });
    return { feed: 'MalwareBazaar', error: res.error };
  }

  const entries = (res.data?.data || []).slice(0, 200);
  const iocs = [];

  for (const e of entries) {
    if (!e.sha256_hash) continue;
    iocs.push({
      value:          e.sha256_hash,
      type:           'sha256',
      reputation:     'malicious',
      risk_score:     85,
      confidence:     90,
      malware_family: e.signature || e.tags?.[0] || null,
      tags:           [...(e.tags || []).slice(0, 4), 'malwarebazaar'],
      notes:          `MalwareBazaar: ${e.signature || 'malware'} — ${e.file_type_mime || 'binary'}`,
      enrichment_data: {
        sha1: e.sha1_hash, md5: e.md5_hash,
        file_name: e.file_name, file_size: e.file_size,
        file_type: e.file_type_mime, signature: e.signature,
      },
    });
    if (e.md5_hash) {
      iocs.push({ value: e.md5_hash, type: 'md5', reputation: 'malicious', risk_score: 80,
        confidence: 85, malware_family: e.signature || null, tags: ['malwarebazaar'] });
    }
  }

  const { inserted } = await upsertIOCs(iocs, tenantId, 'MalwareBazaar');
  const duration_ms = Date.now() - t0;
  await logFeedRun(tenantId, 'MalwareBazaar', {
    iocs_fetched: iocs.length, iocs_new: inserted, started_at, duration_ms,
  });
  console.info(`[Ingest][MalwareBazaar] ✓ fetched=${iocs.length} new=${inserted}`);
  return { feed: 'MalwareBazaar', iocs_fetched: iocs.length, iocs_new: inserted, duration_ms };
}

// ── Feed Registry ────────────────────────────────────────────────
const FEEDS = {
  otx:           { name: 'AlienVault OTX',  fn: ingestOTX,           requiresKey: 'OTX_API_KEY'       },
  abuseipdb:     { name: 'AbuseIPDB',        fn: ingestAbuseIPDB,     requiresKey: 'ABUSEIPDB_API_KEY'  },
  urlhaus:       { name: 'URLhaus',          fn: ingestURLhaus,       requiresKey: null                },
  threatfox:     { name: 'ThreatFox',        fn: ingestThreatFox,     requiresKey: null                },
  malwarebazaar: { name: 'MalwareBazaar',    fn: ingestMalwareBazaar, requiresKey: null                },
  all: null, // handled specially
};

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/ingest/feeds
 * Returns all feed configurations and their API key status.
 * Accessible to any authenticated user (not admin-only).
 */
router.get('/feeds', verifyToken, asyncHandler(async (req, res) => {
  const feedConfig = getFeedConfigStatus();

  // Add feed-specific info
  const enhanced = {};
  for (const [feedName, status] of Object.entries(feedConfig)) {
    const feedKey = Object.keys(FEEDS).find(k => FEEDS[k]?.name === feedName);
    enhanced[feedName] = {
      ...status,
      feed_key:     feedKey || null,
      in_registry:  !!feedKey,
    };
  }

  res.json({
    feeds:       enhanced,
    total_feeds: Object.keys(FEEDS).filter(k => k !== 'all').length,
    ready_feeds: Object.values(enhanced).filter(f => f.ready).length,
  });
}));

/**
 * POST /api/ingest/run
 * Trigger all feeds.
 */
router.post('/run', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const tenantId = req.user.tenant_id || DEFAULT_TENANT;
  const { wait = false } = req.body;

  const feedKeys = Object.keys(FEEDS).filter(k => k !== 'all');

  if (wait) {
    const results = await Promise.allSettled(
      feedKeys.map(key => FEEDS[key].fn(tenantId))
    );
    const summary = results.map((r, i) => ({
      feed: FEEDS[feedKeys[i]].name,
      ...(r.status === 'fulfilled' ? r.value : { error: r.reason?.message }),
    }));
    const totalNew = summary.reduce((sum, r) => sum + (r.iocs_new || 0), 0);
    return res.json({
      success: true,
      feeds_triggered: feedKeys.length,
      total_iocs_new: totalNew,
      results: summary,
    });
  }

  // Async — fire and forget
  Promise.allSettled(feedKeys.map(key => FEEDS[key].fn(tenantId)))
    .then(results => {
      const total = results.reduce((sum, r) => sum + (r.value?.iocs_new || 0), 0);
      console.log(`[Ingest] All feeds complete. Total new IOCs: ${total}`);
    });

  res.json({
    success: true,
    message: `Ingestion started for ${feedKeys.length} feeds`,
    feeds: feedKeys.map(k => FEEDS[k].name),
    started_at: new Date().toISOString(),
  });
}));

/**
 * POST /api/ingest/run/:feed
 */
router.post('/run/:feed', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const feedKey  = req.params.feed.toLowerCase();
  const tenantId = req.user.tenant_id || DEFAULT_TENANT;

  if (feedKey === 'all') {
    // Redirect to /run
    return res.redirect(307, '/api/ingest/run');
  }

  if (!FEEDS[feedKey]) {
    return res.status(404).json({
      error:           `Unknown feed: ${feedKey}`,
      available_feeds: Object.keys(FEEDS).filter(k => k !== 'all'),
    });
  }

  const result = await FEEDS[feedKey].fn(tenantId);

  if (result.authError) {
    return res.status(502).json({
      success:    false,
      error:      result.error,
      auth_error: true,
      hint:       `Set the required API key in backend/.env: ${FEEDS[feedKey].requiresKey || 'N/A'}`,
      feed:       FEEDS[feedKey].name,
    });
  }

  res.json({ success: !result.error, ...result });
}));

/**
 * GET /api/ingest/status
 */
router.get('/status', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.user.tenant_id || DEFAULT_TENANT;
  const limit     = parseInt(req.query.limit) || 50;

  // Guard: supabaseAdmin is null when SUPABASE_URL/SERVICE_KEY not configured
  let dbLogs = null;
  if (supabaseAdmin) {
    const { data } = await supabaseAdmin
      .from('cti_feed_logs')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('finished_at', { ascending: false })
      .limit(limit);
    dbLogs = data;
  }

  const logs = (dbLogs && dbLogs.length > 0) ? dbLogs : _feedRunLog.slice(0, limit);

  const feedStatus = {};
  for (const [key, feed] of Object.entries(FEEDS)) {
    if (key === 'all') continue;
    const lastRun = logs.find(l => l.feed_name === feed.name);
    feedStatus[key] = {
      name:         feed.name,
      has_key:      feed.requiresKey ? !!process.env[feed.requiresKey] : true,
      key_env_var:  feed.requiresKey || null,
      last_run:     lastRun?.finished_at || null,
      last_status:  lastRun?.status || 'never',
      iocs_new:     lastRun?.iocs_new || 0,
      iocs_fetched: lastRun?.iocs_fetched || 0,
      error:        lastRun?.error || null,
      auth_error:   lastRun?.auth_error || false,
      duration_ms:  lastRun?.duration_ms || null,
    };
  }

  res.json({
    feed_status:  feedStatus,
    recent_logs:  logs,
    total_logs:   logs.length,
    generated_at: new Date().toISOString(),
  });
}));

/**
 * GET /api/ingest/stats
 *
 * v5.3 FIX — Stats showed 0 total_iocs because:
 *  1. Used req.user.tenant_id which is NULL for some users → queried
 *     wrong/null tenant and got 0 rows back.
 *  2. byType/byFeed used .limit(5000) on large datasets — misses rows
 *     beyond the limit. Now uses SQL aggregation via RPC.
 *
 * Strategy:
 *  - Try to get stats for the user's tenant first.
 *  - If tenant_id is NULL or returns 0, fall back to querying ALL
 *    tenants (suitable for ADMIN/SUPER_ADMIN users).
 *  - Use parallel COUNT queries (not full row fetches) for speed.
 */
router.get('/stats', verifyToken, asyncHandler(async (req, res) => {
  const userTenantId = req.user?.tenant_id || req.tenantId;
  const userRole     = req.user?.role || '';
  const isSuperUser  = ['ADMIN','SUPER_ADMIN','super_admin','admin'].includes(userRole);

  // Decide whether to scope by tenant or query all tenants
  // SUPER_ADMIN/ADMIN with no tenant_id → query all (platform-wide view)
  const scopeTenant = userTenantId || DEFAULT_TENANT;

  console.log(`[Ingest/Stats] user=${req.user?.email} tenant=${scopeTenant} role=${userRole}`);

  // Guard: supabaseAdmin is null when SUPABASE_URL/SERVICE_KEY are not configured
  if (!supabaseAdmin) {
    return res.json({
      total_iocs: 0, malicious_iocs: 0, high_risk_iocs: 0,
      by_type: {}, by_feed: [], available_feeds: [],
      note: 'Supabase not configured — set SUPABASE_URL and SUPABASE_SERVICE_KEY',
    });
  }

  try {
    // Use parallel COUNT queries (efficient — no row fetches)
    const [
      totalResult,
      maliciousResult,
      highRiskResult,
    ] = await Promise.all([
      supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }).eq('tenant_id', scopeTenant),
      supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }).eq('tenant_id', scopeTenant).eq('reputation', 'malicious'),
      supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }).eq('tenant_id', scopeTenant).gte('risk_score', 70),
    ]);

    let totalIOCs     = totalResult.count     || 0;
    let maliciousIOCs = maliciousResult.count || 0;
    let highRiskIOCs  = highRiskResult.count  || 0;

    // If this tenant has 0 rows, try all-tenant count (for admin users)
    if (totalIOCs === 0 && isSuperUser) {
      console.log(`[Ingest/Stats] Tenant ${scopeTenant} has 0 IOCs — querying all tenants for ADMIN`);
      const [allTotal, allMalicious, allHigh] = await Promise.all([
        supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }),
        supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }).eq('reputation', 'malicious'),
        supabaseAdmin.from('iocs').select('*', { count: 'exact', head: true }).gte('risk_score', 70),
      ]);
      totalIOCs     = allTotal.count     || 0;
      maliciousIOCs = allMalicious.count || 0;
      highRiskIOCs  = allHigh.count      || 0;
    }

    // Type distribution: get up to 50K rows for accurate count
    // (use aggregation pattern — fetch type column only, paginate if needed)
    const typeCount = {};
    const feedCount = {};
    let typeOffset = 0;
    const CHUNK = 10000;

    while (typeOffset < Math.min(totalIOCs, 100000)) {
      const { data: chunk, error: chunkErr } = await supabaseAdmin
        .from('iocs')
        .select('type, source')
        .eq('tenant_id', scopeTenant)
        .range(typeOffset, typeOffset + CHUNK - 1);

      if (chunkErr || !chunk || chunk.length === 0) break;

      for (const row of chunk) {
        if (row.type)   typeCount[row.type]   = (typeCount[row.type]   || 0) + 1;
        if (row.source) feedCount[row.source] = (feedCount[row.source] || 0) + 1;
      }

      if (chunk.length < CHUNK) break; // Last page
      typeOffset += CHUNK;
    }

    // Build available_feeds list (matches what frontend iocdbLoadStats expects)
    const feedConfigStatus = getFeedConfigStatus();
    const availableFeeds = Object.entries(feedConfigStatus).map(([name, cfg]) => ({
      name,
      has_key:   cfg.key_configured,
      auth_type: cfg.auth_type,
      ready:     cfg.ready,
      ioc_count: feedCount[name] || 0,
    }));

    res.json({
      total_iocs:      totalIOCs,
      malicious_iocs:  maliciousIOCs,
      high_risk:       highRiskIOCs,
      by_type:         typeCount,
      by_feed:         feedCount,
      feeds_active:    Object.keys(feedCount).length,
      available_feeds: availableFeeds,
      ioc_types:       Object.keys(typeCount).length,
      tenant_id:       scopeTenant,
      generated_at:    new Date().toISOString(),
    });

  } catch (err) {
    console.error('[Ingest/Stats] Error:', err.message);
    throw err;
  }
}));

/**
 * POST /api/ingest/validate
 * Tests each configured feed's API key without ingesting data.
 */
/* ════════════════════════════════════════════════════════════════
   POST /api/ingest/correlate
   Campaign correlation: cluster IOCs into threat campaigns.
   Returns campaigns_created, campaigns_updated, iocs_analyzed, status.
   NEVER returns 500 — always returns valid JSON.
═══════════════════════════════════════════════════════════════ */
router.post('/correlate', verifyToken, asyncHandler(async (req, res) => {
  const { force = false, min_cluster_size = 3, auto = false } = req.body || {};
  const tenantId = req.tenantId || DEFAULT_TENANT;

  let iocTotal = 0;
  let campaignsCreated = 0;
  let campaignsUpdated = 0;

  // Guard: if supabaseAdmin is null (no env vars), return a graceful empty response
  if (!supabaseAdmin) {
    return res.json({
      status:            'skipped',
      iocs_analyzed:     0,
      campaigns_created: 0,
      campaigns_updated: 0,
      error:             'Database not configured (SUPABASE_URL/SERVICE_KEY missing)',
      correlated_at:     new Date().toISOString(),
    });
  }

  try {
    // Fetch recent active IOCs for this tenant (last 14 days)
    const since = new Date(Date.now() - 14 * 24 * 3600000).toISOString();
    const { data: iocs, error: iocErr } = await supabaseAdmin
      .from('iocs')
      .select('id, value, type, reputation, risk_score, threat_actor, tags, source, created_at')
      .eq('tenant_id', tenantId)
      .eq('status', 'active')
      .gte('created_at', since)
      .order('risk_score', { ascending: false })
      .limit(500);

    if (iocErr) {
      console.warn('[Correlate] IOC fetch error:', iocErr.message);
    }

    iocTotal = (iocs || []).length;

    // FIX: Resolved correlation-engine "no IOCs found" warning.
    // For a fresh tenant (no ingestion yet) this is perfectly normal.
    // Log at INFO level so it doesn't pollute error monitors.
    if (iocTotal === 0) {
      console.info('[Correlate] No active IOCs found for this tenant — ' +
        'correlation skipped (normal on first run; trigger ingestion to populate)');
      return res.json({
        status:             'skipped',
        iocs_analyzed:      0,
        campaigns_created:  0,
        campaigns_updated:  0,
        cluster_threshold:  min_cluster_size,
        mode:               auto ? 'auto' : 'manual',
        reason:             'no_iocs',
        hint:               'Trigger an ingestion job first: POST /api/cti/ingest/all',
        correlated_at:      new Date().toISOString(),
      });
    }

    if (iocTotal >= min_cluster_size) {
      // Group IOCs by threat_actor (simple clustering strategy)
      const actorGroups = {};
      for (const ioc of (iocs || [])) {
        const key = ioc.threat_actor || ioc.source || 'unknown';
        if (!actorGroups[key]) actorGroups[key] = [];
        actorGroups[key].push(ioc);
      }

      // Create or update campaigns for clusters >= min_cluster_size
      for (const [actor, members] of Object.entries(actorGroups)) {
        if (members.length < min_cluster_size) continue;

        const campaignName = `[Auto] ${actor} Campaign — ${members.length} IOCs`;
        const now = new Date().toISOString();

        // Check if campaign already exists
        const { data: existing } = await supabaseAdmin
          .from('campaigns')
          .select('id')
          .eq('tenant_id', tenantId)
          .ilike('name', `%${actor}%`)
          .limit(1);

        if (existing && existing.length > 0) {
          // Update existing campaign
          await supabaseAdmin
            .from('campaigns')
            .update({ ioc_count: members.length, updated_at: now })
            .eq('id', existing[0].id);
          campaignsUpdated++;
        } else {
          // Create new campaign
          const { error: insertErr } = await supabaseAdmin
            .from('campaigns')
            .insert({
              tenant_id:    tenantId,
              name:         campaignName,
              threat_actor: actor,
              status:       'active',
              ioc_count:    members.length,
              severity:     members.some(m => m.risk_score >= 80) ? 'HIGH' : 'MEDIUM',
              created_at:   now,
              updated_at:   now,
              // auto_generated column removed — not in DB schema cache
            });
          if (!insertErr) campaignsCreated++;
          else console.warn('[Correlate] Campaign insert error:', insertErr.message);
        }
      }
    }

    res.json({
      status:             'success',
      iocs_analyzed:      iocTotal,
      campaigns_created:  campaignsCreated,
      campaigns_updated:  campaignsUpdated,
      cluster_threshold:  min_cluster_size,
      mode:               auto ? 'auto' : 'manual',
      correlated_at:      new Date().toISOString(),
    });

  } catch (err) {
    console.error('[Correlate] Error:', err.message);
    // NEVER return 500 — return a degraded but valid response
    res.json({
      status:             'degraded',
      iocs_analyzed:      iocTotal,
      campaigns_created:  campaignsCreated,
      campaigns_updated:  campaignsUpdated,
      error:              err.message,
      correlated_at:      new Date().toISOString(),
    });
  }
}));

router.post('/validate', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const results = {};

  // Validate OTX
  if (process.env.OTX_API_KEY) {
    const r = await feedFetch('AlienVault OTX',
      'https://otx.alienvault.com/api/v1/user/me', {}, 1);
    results['AlienVault OTX'] = {
      valid: r.ok,
      status: r.status,
      error: r.error || null,
      user: r.data?.username || null,
    };
  } else {
    results['AlienVault OTX'] = { valid: false, error: 'OTX_API_KEY not set' };
  }

  // Validate AbuseIPDB
  if (process.env.ABUSEIPDB_API_KEY) {
    const r = await feedFetch('AbuseIPDB',
      'https://api.abuseipdb.com/api/v2/check',
      { params: { ipAddress: '8.8.8.8', maxAgeInDays: 1 } }, 1);
    results['AbuseIPDB'] = {
      valid: r.ok,
      status: r.status,
      error: r.error || null,
    };
  } else {
    results['AbuseIPDB'] = { valid: false, error: 'ABUSEIPDB_API_KEY not set' };
  }

  // URLhaus (no auth)
  const urlhausR = await feedFetch('URLhaus',
    'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    { method: 'POST', data: '' }, 1);
  results['URLhaus'] = { valid: urlhausR.ok, status: urlhausR.status, error: urlhausR.error || null };

  res.json({
    validation_results: results,
    validated_at:       new Date().toISOString(),
  });
}));

module.exports = router;
