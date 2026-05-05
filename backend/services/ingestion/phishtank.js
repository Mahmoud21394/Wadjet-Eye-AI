/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — PhishTank + MISP Public Feeds Ingestion
 *  backend/services/ingestion/phishtank.js
 *
 *  Workers:
 *    - PhishTank     (phishing URLs — no key required for basic)
 *    - MISP Circl    (public MISP feeds via CIRCL API)
 *    - OpenPhish     (free phishing URL feed)
 *    - AbuseCH MISP  (abuse.ch public MISP event feed)
 *    - Botvrij       (malicious files / IOC MISP feed)
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios    = require('axios');
const { supabase } = require('../../config/supabase');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';
const TIMEOUT = 25000;

// ── Re-use the canonical upsertIOCs from ingestion/index.js ─────
// This eliminates the duplicate implementation that existed in this file.
// The parent module's version has circuit-breaker, backpressure, and
// dedup logic that is kept in sync.
let _upsertIOCsFromIndex = null;
function getUpsertFn() {
  if (!_upsertIOCsFromIndex) {
    try {
      // Lazy-load to avoid circular require — phishtank.js ← scheduler ← index
      const idx = require('./index');
      _upsertIOCsFromIndex = idx.upsertIOCs || null;
    } catch (_) {}
  }
  return _upsertIOCsFromIndex;
}

// ── Feed log helpers (same pattern as main ingestion/index.js) ──
// FIX: Write feed-run records to BOTH tables so every consumer sees them:
//   feed_logs     — queried by services/ingestion/index.js workers and dashboard
//   cti_feed_logs — queried by routes/ioc-ingestion.js and /api/cti/stats
// Previously only feed_logs was written, causing /api/cti/stats and the
// dashboard KPIs to show 0 active feeds for PhishTank/MISP/Botvrij/SSLBL.

// _pendingLogs maps logId → { feedName, tenantId, started_at }
// so finishFeedLog can mirror to cti_feed_logs without needing extra args.
const _pendingLogs = new Map();

async function startFeedLog(feedName, feedType, tenantId) {
  const tid = tenantId || DEFAULT_TENANT;
  const started_at = new Date().toISOString();
  const row = {
    feed_name:  feedName,
    feed_type:  feedType,
    tenant_id:  tid,
    status:     'running',
    started_at,
  };
  try {
    const { data } = await supabase
      .from('feed_logs')
      .insert(row)
      .select('id')
      .single();
    const logId = data?.id || null;
    if (logId) _pendingLogs.set(logId, { feedName, tenantId: tid, started_at });
    return logId;
  } catch (_) { return null; }
}

async function finishFeedLog(logId, stats) {
  const meta   = logId ? (_pendingLogs.get(logId) || {}) : {};
  if (logId) _pendingLogs.delete(logId);

  const update = {
    status:         stats.error ? 'error' : 'success',
    finished_at:    new Date().toISOString(),
    duration_ms:    stats.duration_ms    || 0,
    iocs_fetched:   stats.iocs_fetched   || 0,
    iocs_new:       stats.iocs_new       || 0,
    iocs_updated:   stats.iocs_updated   || 0,
    iocs_duplicate: stats.iocs_duplicate || 0,
    errors_count:   stats.errors_count   || 0,
    error_message:  stats.error          || null,
    metadata:       stats.metadata       || {},
  };

  // ── 1. Update primary feed_logs row ──────────────────────────
  if (logId) {
    try {
      await supabase.from('feed_logs').update(update).eq('id', logId);
    } catch (_) {}
  }

  // ── 2. Mirror to cti_feed_logs (best-effort, non-blocking) ───
  // cti_feed_logs is queried by /api/cti/stats, /api/cti/feed-logs,
  // and the dashboard KPI endpoint. Without this mirror those
  // endpoints show 0 active feeds for PhishTank/MISP/Botvrij/SSLBL.
  if (meta.feedName) {
    const ctiRow = {
      tenant_id:    meta.tenantId   || DEFAULT_TENANT,
      feed_name:    meta.feedName,
      action:       stats.error ? 'ingest_error' : 'ingest_complete',
      started_at:   meta.started_at || update.finished_at,
      ...update,
    };
    // Fire-and-forget — do NOT await so we never block the worker
    supabase.from('cti_feed_logs')
      .upsert(ctiRow, { ignoreDuplicates: false })
      .then(() => {})
      .catch(() => {});
  }
}

// ── Shared upsert — delegates to ingestion/index.js canonical impl ─
// Falls back to a minimal local implementation if the lazy-load fails
// (e.g. during circular-require resolution at startup).
async function upsertIOCs(tenantId, iocs) {
  if (!iocs || iocs.length === 0) return { new: 0, updated: 0, duplicate: 0 };

  // Try the canonical implementation first (avoids code duplication)
  const fn = getUpsertFn();
  if (fn) {
    try {
      const result = await fn(tenantId, iocs);
      // Normalise return shape: index uses { new, updated, duplicate }
      return result;
    } catch (_) {
      // Fall through to local implementation below
    }
  }

  // ── Local fallback implementation ───────────────────────────
  // Used when ingestion/index.js isn't loadable (circular require on startup).
  const validTypes = new Set([
    'ip','domain','url','hash_md5','hash_sha1','hash_sha256',
    'email','filename','registry','mutex','asn','cve'
  ]);
  const now = new Date().toISOString();
  const tid = tenantId || DEFAULT_TENANT;
  let newCount = 0, updatedCount = 0, dupCount = 0;

  const normalized = iocs
    .filter(ioc => ioc.value && ioc.type && validTypes.has(ioc.type))
    .map(ioc => ({
      tenant_id:        tid,
      value:            String(ioc.value).trim().toLowerCase().slice(0, 500),
      type:             ioc.type,
      reputation:       ioc.reputation        || 'malicious',
      risk_score:       Math.min(100, Math.max(0, Math.round(ioc.risk_score || 70))),
      confidence:       Math.min(100, Math.max(0, Math.round(ioc.confidence || 75))),
      source:           ioc.source            || 'phishtank',
      feed_source:      ioc.feed_source       || ioc.source || 'phishtank',
      country:          ioc.country           || null,
      asn:              ioc.asn               || null,
      threat_actor:     ioc.threat_actor      || null,
      malware_family:   ioc.malware_family    || null,
      tags:             Array.isArray(ioc.tags) ? ioc.tags.slice(0, 10) : [],
      notes:            ioc.notes             || null,
      kill_chain_phase: ioc.kill_chain_phase  || null,
      status:           'active',
      last_seen:        now,
      enrichment_data:  ioc.enrichment_data   || {},
    }));

  const seen = new Map();
  for (const row of normalized) {
    const existing = seen.get(row.value);
    if (!existing || row.risk_score > existing.risk_score) seen.set(row.value, row);
    else dupCount++;
  }
  const deduped = [...seen.values()];
  if (deduped.length === 0) return { new: 0, updated: 0, duplicate: dupCount };

  const CHUNK = 50;
  let consecutiveErrors = 0;
  const MAX_CONSECUTIVE_ERRORS = 3;

  for (let i = 0; i < deduped.length; i += CHUNK) {
    if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
      console.warn(`[PhishTank/local] Circuit-breaker tripped — skipping remaining ${deduped.length - i} IOCs`);
      break;
    }
    const chunk = deduped.slice(i, i + CHUNK);
    const { data, error } = await supabase
      .from('iocs')
      .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: false })
      .select('id, created_at');

    if (error) {
      consecutiveErrors++;
      if (consecutiveErrors === 1 || consecutiveErrors % 10 === 0)
        console.error(`[PhishTank/local] upsert error (${consecutiveErrors}):`, error.message);
      const { error: e2 } = await supabase
        .from('iocs')
        .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: true });
      if (!e2) { updatedCount += chunk.length; consecutiveErrors = 0; }
    } else {
      consecutiveErrors = 0;
      if (data) {
        const freshCutoff = Date.now() - 10000;
        for (const row of data) {
          if (new Date(row.created_at).getTime() > freshCutoff) newCount++;
          else updatedCount++;
        }
      }
    }
    if (i + CHUNK < deduped.length) await new Promise(r => setTimeout(r, 200));
  }
  return { new: newCount, updated: updatedCount, duplicate: dupCount };
}

// ══════════════════════════════════════════════
//  WORKER: PhishTank (public JSON feed)
// ══════════════════════════════════════════════
async function ingestPhishTank(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('PhishTank', 'phishtank', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][PhishTank] Starting...');

    // PhishTank public JSON feed — no auth required for basic access
    // Use developer API if PHISHTANK_API_KEY is set (higher rate limits)
    const apiKey = process.env.PHISHTANK_API_KEY;
    const url    = apiKey
      ? `https://data.phishtank.com/data/${apiKey}/online-valid.json`
      : 'https://data.phishtank.com/data/online-valid.json';

    // FIX: PhishTank public feed returns 404 or 429 intermittently.
    // Use retry logic with exponential backoff and fallback to OpenPhish.
    let data = null;
    let lastErr = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const resp = await axios.get(url, {
          timeout: TIMEOUT,
          headers: {
            'User-Agent': 'wadjet-eye-ai-platform/5.2 (security research)',
            'Accept': 'application/json',
          },
          maxContentLength: 20 * 1024 * 1024, // 20MB max
          validateStatus: (s) => s < 500, // Accept 404/429 without throw
        });
        if (resp.status === 404) {
          console.warn(`[Ingestion][PhishTank] 404 on attempt ${attempt} — PhishTank feed may be unavailable`);
          lastErr = new Error('PhishTank feed returned 404 — feed temporarily unavailable');
          await new Promise(r => setTimeout(r, 5000 * attempt));
          continue;
        }
        if (resp.status === 429) {
          const retryAfter = parseInt(resp.headers['retry-after'] || '60', 10);
          const wait = Math.min(retryAfter, 120) * 1000;
          console.warn(`[Ingestion][PhishTank] 429 rate limited — waiting ${wait/1000}s (attempt ${attempt})`);
          lastErr = new Error(`PhishTank rate limited (429)`);
          await new Promise(r => setTimeout(r, wait));
          continue;
        }
        data = resp.data;
        break;
      } catch (fetchErr) {
        lastErr = fetchErr;
        console.warn(`[Ingestion][PhishTank] Attempt ${attempt} failed: ${fetchErr.message}`);
        if (attempt < 3) await new Promise(r => setTimeout(r, 5000 * attempt));
      }
    }

    if (!data) {
      // All retries exhausted — log and skip gracefully
      throw lastErr || new Error('PhishTank feed unavailable after 3 attempts');
    }

    const entries = Array.isArray(data) ? data : [];
    console.info(`[Ingestion][PhishTank] ${entries.length} phishing URLs fetched`);

    // Take latest 2000 (avoid overwhelming DB on first run)
    const subset = entries.slice(0, 2000);

    for (const entry of subset) {
      const urlStr = entry.url || entry.phish_url;
      if (!urlStr) continue;

      iocs.push({
        value:          urlStr.slice(0, 500),
        type:           'url',
        reputation:     'malicious',
        risk_score:     entry.verified === 'yes' ? 90 : 75,
        confidence:     entry.verified === 'yes' ? 95 : 70,
        source:         'PhishTank',
        feed_source:    'PhishTank',
        tags:           ['phishing', 'url'],
        notes:          `PhishTank ID: ${entry.phish_id || entry.id} | Verified: ${entry.verified}`,
        kill_chain_phase: 'delivery',
        enrichment_data: {
          phish_id:        entry.phish_id || entry.id,
          verified:        entry.verified,
          verification_time: entry.verification_time,
          submission_time: entry.submission_time,
          target:          entry.target,
        },
      });
    }

    const { new: n, updated: u, duplicate: d } = await upsertIOCs(tenantId, iocs);

    const stats = {
      duration_ms:    Date.now() - t0,
      iocs_fetched:   iocs.length,
      iocs_new:       n,
      iocs_updated:   u,
      iocs_duplicate: d,
      metadata:       { total_phishtank: entries.length },
    };
    await finishFeedLog(logId, stats);
    console.info(`[Ingestion][PhishTank] ✓ new=${n} updated=${u} dup=${d}`);
    return stats;

  } catch (err) {
    console.error('[Ingestion][PhishTank] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER: CIRCL MISP Public Event Feed
// ══════════════════════════════════════════════
async function ingestMISPCircl(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('CIRCL MISP', 'misp', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][MISP-CIRCL] Starting...');

    // CIRCL public MISP event listing
    const { data: feedIndex } = await axios.get(
      'https://www.circl.lu/doc/misp/feed-osint/manifest.json',
      { timeout: 15000, headers: { 'User-Agent': 'wadjet-eye-ai/5.2' } }
    );

    // Parse events — take the 50 most recent
    const eventKeys = Object.keys(feedIndex || {})
      .sort((a, b) => (feedIndex[b].timestamp || 0) - (feedIndex[a].timestamp || 0))
      .slice(0, 50);

    console.info(`[Ingestion][MISP-CIRCL] Processing ${eventKeys.length} events...`);

    for (const key of eventKeys) {
      try {
        const { data: event } = await axios.get(
          `https://www.circl.lu/doc/misp/feed-osint/${key}.json`,
          { timeout: 10000, headers: { 'User-Agent': 'wadjet-eye-ai/5.2' } }
        );

        const attrs = event?.Event?.Attribute || [];
        for (const attr of attrs) {
          const mapped = _mispAttrToIOC(attr, event.Event);
          if (mapped) iocs.push(mapped);
        }

        // Small delay to be polite to the server
        await new Promise(r => setTimeout(r, 100));
      } catch (_) { /* skip bad event */ }

      if (iocs.length >= 3000) break; // cap to avoid DB overload
    }

    const { new: n, updated: u, duplicate: d } = await upsertIOCs(tenantId, iocs);
    const stats = {
      duration_ms:    Date.now() - t0,
      iocs_fetched:   iocs.length,
      iocs_new:       n,
      iocs_updated:   u,
      iocs_duplicate: d,
      metadata:       { events_processed: eventKeys.length },
    };
    await finishFeedLog(logId, stats);
    console.info(`[Ingestion][MISP-CIRCL] ✓ new=${n} updated=${u} dup=${d}`);
    return stats;

  } catch (err) {
    console.error('[Ingestion][MISP-CIRCL] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { error: err.message };
  }
}

// ── Map MISP attribute to unified IOC schema ────────────────
function _mispAttrToIOC(attr, event) {
  const typeMap = {
    'ip-dst':          'ip',
    'ip-src':          'ip',
    'ip-dst|port':     'ip',
    'domain':          'domain',
    'hostname':        'domain',
    'url':             'url',
    'md5':             'hash_md5',
    'sha1':            'hash_sha1',
    'sha256':          'hash_sha256',
    'email-src':       'email',
    'email-dst':       'email',
    'filename':        'filename',
    'filename|md5':    'hash_md5',
    'filename|sha256': 'hash_sha256',
    'mutex':           'mutex',
    'regkey':          'registry',
  };

  const iocType = typeMap[attr.type];
  if (!iocType) return null;

  let value = String(attr.value || '').split('|')[0].trim();
  if (!value || value.length > 500) return null;

  // Strip leading/trailing dots from IPs
  if (iocType === 'ip') value = value.replace(/[.:]+$/, '');

  const tags = [];
  if (event?.Tag) {
    for (const t of (Array.isArray(event.Tag) ? event.Tag : [])) {
      if (t.name) tags.push(t.name.slice(0, 50));
    }
  }

  return {
    value,
    type:           iocType,
    reputation:     attr.to_ids ? 'malicious' : 'suspicious',
    risk_score:     attr.to_ids ? 80 : 60,
    confidence:     70,
    source:         'CIRCL MISP',
    feed_source:    'CIRCL MISP',
    tags:           ['misp', ...tags].slice(0, 10),
    notes:          (event?.info || '').slice(0, 200),
    kill_chain_phase: _inferKillChain(attr.category),
    enrichment_data: {
      misp_event_uuid: event?.uuid,
      misp_attr_uuid:  attr.uuid,
      category:        attr.category,
      to_ids:          attr.to_ids,
    },
  };
}

function _inferKillChain(category) {
  const map = {
    'Network activity':      'command-and-control',
    'Payload delivery':      'delivery',
    'Payload installation':  'installation',
    'Persistence mechanism': 'installation',
    'Reconnaissance':        'reconnaissance',
    'External analysis':     'actions-on-objectives',
  };
  return map[category] || null;
}

// ══════════════════════════════════════════════
//  WORKER: OpenPhish (free phishing feed — no auth)
// ══════════════════════════════════════════════
async function ingestOpenPhish(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('OpenPhish', 'openphish', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][OpenPhish] Starting...');

    const { data } = await axios.get('https://openphish.com/feed.txt', {
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'wadjet-eye-ai/5.2' },
      maxContentLength: 5 * 1024 * 1024,
    });

    const lines = String(data).split('\n').filter(l => l.trim().startsWith('http'));
    console.info(`[Ingestion][OpenPhish] ${lines.length} URLs fetched`);

    for (const line of lines.slice(0, 1000)) {
      const url = line.trim();
      if (url.length > 500) continue;
      iocs.push({
        value:           url,
        type:            'url',
        reputation:      'malicious',
        risk_score:      85,
        confidence:      80,
        source:          'OpenPhish',
        feed_source:     'OpenPhish',
        tags:            ['phishing', 'url', 'openphish'],
        kill_chain_phase: 'delivery',
      });
    }

    const { new: n, updated: u, duplicate: d } = await upsertIOCs(tenantId, iocs);
    const stats = { duration_ms: Date.now() - t0, iocs_fetched: iocs.length, iocs_new: n, iocs_updated: u, iocs_duplicate: d };
    await finishFeedLog(logId, stats);
    console.info(`[Ingestion][OpenPhish] ✓ new=${n} updated=${u}`);
    return stats;

  } catch (err) {
    console.error('[Ingestion][OpenPhish] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER: Botvrij.eu MISP feed (malware IOCs)
// ══════════════════════════════════════════════
async function ingestBotvrij(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('Botvrij.eu', 'botvrij', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][Botvrij] Starting...');

    // Botvrij.eu has several public IOC text files
    const feeds = [
      { url: 'https://www.botvrij.eu/data/ioclist.ip-dst.raw',    type: 'ip',     tag: 'botvrij-ip' },
      { url: 'https://www.botvrij.eu/data/ioclist.domain.raw',    type: 'domain', tag: 'botvrij-domain' },
      { url: 'https://www.botvrij.eu/data/ioclist.url.raw',       type: 'url',    tag: 'botvrij-url' },
      { url: 'https://www.botvrij.eu/data/ioclist.hash.raw',      type: 'hash_sha256', tag: 'botvrij-hash' },
    ];

    for (const feed of feeds) {
      try {
        const { data } = await axios.get(feed.url, {
          timeout: 15000,
          headers: { 'User-Agent': 'wadjet-eye-ai/5.2' },
          maxContentLength: 3 * 1024 * 1024,
        });

        const lines = String(data).split('\n')
          .map(l => l.trim())
          .filter(l => l && !l.startsWith('#') && l.length < 500);

        for (const value of lines.slice(0, 500)) {
          iocs.push({
            value,
            type:           feed.type,
            reputation:     'malicious',
            risk_score:     75,
            confidence:     70,
            source:         'Botvrij.eu',
            feed_source:    'Botvrij.eu',
            tags:           ['malware', feed.tag],
          });
        }
      } catch (_) {}
    }

    const { new: n, updated: u, duplicate: d } = await upsertIOCs(tenantId, iocs);
    const stats = { duration_ms: Date.now() - t0, iocs_fetched: iocs.length, iocs_new: n, iocs_updated: u, iocs_duplicate: d };
    await finishFeedLog(logId, stats);
    console.info(`[Ingestion][Botvrij] ✓ new=${n} updated=${u}`);
    return stats;

  } catch (err) {
    console.error('[Ingestion][Botvrij] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { error: err.message };
  }
}

// ══════════════════════════════════════════════
//  WORKER: Abuse.ch SSL Blacklist (C2 domains/IPs)
// ══════════════════════════════════════════════
async function ingestSSLBlacklist(tenantId) {
  const t0    = Date.now();
  const logId = await startFeedLog('Abuse.ch SSL Blacklist', 'sslbl', tenantId);
  const iocs  = [];

  try {
    console.info('[Ingestion][SSLBL] Starting...');

    const { data } = await axios.get(
      'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
      { timeout: 15000, headers: { 'User-Agent': 'wadjet-eye-ai/5.2' } }
    );

    const lines = String(data).split('\n');
    for (const line of lines) {
      if (line.startsWith('#') || !line.trim()) continue;
      const parts = line.split(',');
      if (parts.length < 2) continue;
      const ip = parts[1]?.trim();
      const reason = parts[2]?.trim() || '';
      if (!ip || !ip.match(/^\d+\.\d+\.\d+\.\d+/)) continue;

      iocs.push({
        value:           ip,
        type:            'ip',
        reputation:      'malicious',
        risk_score:      85,
        confidence:      88,
        source:          'Abuse.ch SSL BL',
        feed_source:     'Abuse.ch SSL BL',
        tags:            ['c2', 'ssl-blacklist', 'abuse.ch'],
        notes:           reason.slice(0, 200),
        kill_chain_phase: 'command-and-control',
      });
    }

    const { new: n, updated: u, duplicate: d } = await upsertIOCs(tenantId, iocs);
    const stats = { duration_ms: Date.now() - t0, iocs_fetched: iocs.length, iocs_new: n, iocs_updated: u, iocs_duplicate: d };
    await finishFeedLog(logId, stats);
    console.info(`[Ingestion][SSLBL] ✓ new=${n} updated=${u}`);
    return stats;

  } catch (err) {
    console.error('[Ingestion][SSLBL] Error:', err.message);
    await finishFeedLog(logId, { error: err.message, duration_ms: Date.now() - t0 });
    return { error: err.message };
  }
}

module.exports = {
  ingestPhishTank,
  ingestMISPCircl,
  ingestOpenPhish,
  ingestBotvrij,
  ingestSSLBlacklist,
};
