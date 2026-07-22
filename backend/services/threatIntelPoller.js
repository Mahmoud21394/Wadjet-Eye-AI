/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Intelligence Poller  (Phase 3 / Task 4)
 *  backend/services/threatIntelPoller.js
 *
 *  Ported from AiSOC v7.6.0:
 *    services/threatintel/app/clients/cisa_kev.py
 *    services/threatintel/app/clients/otx.py
 *    services/threatintel/app/feeds/handlers.py
 *    services/threatintel/app/main.py  (scheduling pattern)
 *
 *  Design decisions (no-new-services constraint):
 *  ─────────────────────────────────────────────────────────────────────
 *  • All persistence goes to Supabase `we_ioc_catalog` (no Redis Bloom,
 *    no OpenSearch, no Qdrant, no Neo4j, no Kafka).
 *  • In-Postgres dedup: `source_ref TEXT UNIQUE` — ON CONFLICT DO UPDATE
 *    replaces AiSOC's Redis Bloom filter.
 *  • Poll log in `we_ti_poll_log` for observability.
 *  • IOC-alert hit tracking deferred to `we_ioc_alert_hits` via post-insert.
 *  • Shadow mode: TI enrichment columns set but feature-flagged.
 *
 *  Feature flag: ENABLE_THREAT_INTEL_POLLING (default FALSE)
 *  OTX requires OTX_API_KEY env var; skipped silently if absent.
 *
 *  Exports:
 *    normalizeKevEntry(entry)            → IOC plain object
 *    normalizeOtxIndicator(ind, pulse)   → IOC plain object | null
 *    pollCisaKev(supabase)               → Promise<PollStats>
 *    pollOtx(supabase)                   → Promise<PollStats>
 *    upsertIoc(supabase, ioc)            → Promise<{isNew, isUpdated}>
 *    pollAll(supabase)                   → Promise<{ cisaKev, otx }>
 *    startPoller(supabase)               → { stop() }
 *    pollNow(supabase, feedName)         → Promise<PollStats>
 *    isPollingEnabled()                  → boolean
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── Feature flag ────────────────────────────────────────────────────── */
function isPollingEnabled () {
  const v = (process.env.ENABLE_THREAT_INTEL_POLLING || 'false').toLowerCase();
  return v === 'true' || v === '1' || v === 'yes';
}

/* ── Intervals (ms) — same as AiSOC FeedScheduler defaults ───────────── */
const CISA_KEV_INTERVAL_MS = 6 * 60 * 60 * 1000;   // 6 h
const OTX_INTERVAL_MS      = 1 * 60 * 60 * 1000;   // 1 h
const STARTUP_DELAY_MS     = 30 * 1000;             // 30 s after server start

/* ── CISA KEV endpoint ────────────────────────────────────────────────── */
const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/* ── OTX endpoint ─────────────────────────────────────────────────────── */
const OTX_BASE_URL     = 'https://otx.alienvault.com';
const OTX_PAGE_SIZE    = 50;
const OTX_MAX_PAGES    = 100;  // safety cap

/* ── Supported OTX indicator types → we_ioc_catalog.ioc_type mapping ─── */
const OTX_TYPE_MAP = {
  'IPv4':         'ip',
  'IPv6':         'ip',
  'domain':       'domain',
  'hostname':     'domain',
  'URL':          'url',
  'FileHash-MD5': 'file_hash',
  'FileHash-SHA1':'file_hash',
  'FileHash-SHA256':'file_hash',
  'email':        'email',
  'CVE':          'vulnerability',
  'Mutex':        'mutex',
};

/* ═══════════════════════════════════════════════════════════════════════
 *  normalizeKevEntry(entry)
 *  Ported verbatim from CisaKevClient.to_ioc() in cisa_kev.py
 *  Returns a plain object ready for we_ioc_catalog insertion.
 * ═══════════════════════════════════════════════════════════════════════ */
function normalizeKevEntry (entry) {
  if (!entry || typeof entry !== 'object') return null;

  const cveId = (entry.cveID || entry.cve_id || '').trim();
  if (!cveId) return null;

  return {
    ioc_type:        'vulnerability',
    ioc_value:       cveId,
    source:          'cisa-kev',
    source_ref:      `cisa-kev:${cveId}`,           // dedup key — matches UNIQUE constraint
    description:     entry.vulnerabilityName || entry.shortDescription || cveId,
    vendor_project:  entry.vendorProject || null,
    product:         entry.product        || null,
    required_action: entry.requiredAction  || null,
    due_date:        entry.dueDate         || null,
    date_added:      entry.dateAdded       || null,
    known_ransomware:(entry.knownRansomwareCampaignUse || '').toLowerCase() === 'known'
                      ? 'known' : (entry.knownRansomwareCampaignUse || null),
    tlp:             'white',
    tags:            ['kev', 'cisa', 'exploited'],
    confidence:      90,                             // CISA KEV = high-confidence
    raw_payload:     entry,
  };
}

/* ═══════════════════════════════════════════════════════════════════════
 *  normalizeOtxIndicator(indicator, pulse)
 *  Ported from OtxClient + handle_otx_feed() pattern in handlers.py
 *  Returns null if the indicator type is unsupported.
 * ═══════════════════════════════════════════════════════════════════════ */
function normalizeOtxIndicator (indicator, pulse) {
  if (!indicator || !indicator.indicator) return null;

  const iocType = OTX_TYPE_MAP[indicator.type];
  if (!iocType) return null;   // unsupported indicator type — skip

  const pulseId  = (pulse && pulse.id) ? String(pulse.id) : 'unknown';
  const indHash  = _hashShort(indicator.indicator);
  const srcRef   = `otx:${pulseId}:${indHash}`;

  // Tags: pulse tags + TLP tag
  const pulseTags = Array.isArray(pulse?.tags) ? pulse.tags.map(String) : [];
  const tags      = Array.from(new Set(['otx', ...pulseTags])).slice(0, 20);

  // TLP: OTX pulses expose TLP in pulse.TLP (string 'white'|'green'|'amber'|'red')
  const tlpRaw = (pulse?.TLP || pulse?.tlp || 'white').toLowerCase();
  const tlp    = ['white','green','amber','red'].includes(tlpRaw) ? tlpRaw : 'white';

  // Confidence: OTX doesn't provide per-indicator confidence.
  // Use pulse adversary score if present, else moderate default.
  const confidence = Math.min(
    Math.max(
      typeof pulse?.adversary === 'string' ? 60 : (pulse?.confidence || 50),
      10
    ),
    95
  );

  return {
    ioc_type:       iocType,
    ioc_value:      indicator.indicator,
    source:         'otx',
    source_ref:     srcRef,
    description:    indicator.description || pulse?.name || null,
    vendor_project: null,
    product:        null,
    required_action:null,
    due_date:       null,
    date_added:     pulse?.created ? pulse.created.substring(0, 10) : null,
    known_ransomware: null,
    tlp,
    tags,
    confidence,
    raw_payload: {
      indicator_type: indicator.type,
      pulse_id:       pulseId,
      pulse_name:     pulse?.name || null,
      pulse_tlp:      tlp,
      pulse_created:  pulse?.created || null,
      pulse_modified: pulse?.modified || null,
    },
  };
}

/* ── Short deterministic hash for OTX source_ref sub-key ─────────────── */
function _hashShort (str) {
  // FNV-1a 32-bit (fast, no crypto needed for a non-security hash)
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h  = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/* ═══════════════════════════════════════════════════════════════════════
 *  upsertIoc(supabase, ioc)
 *  Insert or update one IOC in we_ioc_catalog.
 *  Uses ON CONFLICT (source_ref) DO UPDATE (Supabase upsert).
 *  Returns { isNew: bool, isUpdated: bool }.
 * ═══════════════════════════════════════════════════════════════════════ */
async function upsertIoc (supabase, ioc) {
  if (!ioc || !ioc.source_ref) {
    return { isNew: false, isUpdated: false };
  }

  // Check existence first so we can return isNew/isUpdated accurately
  const { data: existing } = await supabase
    .from('we_ioc_catalog')
    .select('id, last_seen_at')
    .eq('source_ref', ioc.source_ref)
    .maybeSingle();

  const now = new Date().toISOString();

  const row = {
    ioc_type:        ioc.ioc_type,
    ioc_value:       ioc.ioc_value,
    source:          ioc.source,
    source_ref:      ioc.source_ref,
    description:     ioc.description     || null,
    vendor_project:  ioc.vendor_project  || null,
    product:         ioc.product         || null,
    required_action: ioc.required_action || null,
    due_date:        ioc.due_date        || null,
    date_added:      ioc.date_added      || null,
    known_ransomware:ioc.known_ransomware|| null,
    tlp:             ioc.tlp             || 'white',
    tags:            ioc.tags            || [],
    confidence:      ioc.confidence      || 50,
    is_active:       true,
    last_seen_at:    now,
    raw_payload:     ioc.raw_payload     || {},
    // tenant_id: null — global IOCs are tenant-agnostic
  };

  if (!existing) {
    row.first_seen_at = now;
    const { error } = await supabase.from('we_ioc_catalog').insert(row);
    if (error) throw new Error(`upsertIoc insert failed: ${error.message}`);
    return { isNew: true, isUpdated: false };
  } else {
    const { error } = await supabase
      .from('we_ioc_catalog')
      .update({
        description:     row.description,
        vendor_project:  row.vendor_project,
        product:         row.product,
        required_action: row.required_action,
        due_date:        row.due_date,
        date_added:      row.date_added,
        known_ransomware:row.known_ransomware,
        tlp:             row.tlp,
        tags:            row.tags,
        confidence:      row.confidence,
        is_active:       true,
        last_seen_at:    now,
        raw_payload:     row.raw_payload,
      })
      .eq('source_ref', ioc.source_ref);
    if (error) throw new Error(`upsertIoc update failed: ${error.message}`);
    return { isNew: false, isUpdated: true };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  _writePollLog(supabase, feedName) → { logId, finish(stats, errMsg) }
 *  Opens a poll log row, returns a closer function.
 * ═══════════════════════════════════════════════════════════════════════ */
async function _writePollLog (supabase, feedName) {
  const { data } = await supabase
    .from('we_ti_poll_log')
    .insert({ feed_name: feedName, status: 'running' })
    .select('id')
    .single();

  const logId = data?.id || null;

  const finish = async (stats, errMsg) => {
    if (!logId) return;
    await supabase
      .from('we_ti_poll_log')
      .update({
        finished_at:   new Date().toISOString(),
        status:        errMsg ? 'error' : 'success',
        iocs_fetched:  stats.fetched  || 0,
        iocs_new:      stats.newCount || 0,
        iocs_updated:  stats.updated  || 0,
        iocs_skipped:  stats.skipped  || 0,
        error_message: errMsg || null,
      })
      .eq('id', logId);
  };

  return { logId, finish };
}

/* ═══════════════════════════════════════════════════════════════════════
 *  pollCisaKev(supabase)
 *  Fetches CISA KEV JSON, normalizes entries, upserts into we_ioc_catalog.
 *  Ported from CisaKevClient.fetch() + handle_cisa_kev_feed() in handlers.py.
 *  Returns PollStats { fetched, newCount, updated, skipped, feedName }.
 * ═══════════════════════════════════════════════════════════════════════ */
async function pollCisaKev (supabase) {
  const feedName = 'cisa-kev';
  const { finish } = await _writePollLog(supabase, feedName);

  let fetched = 0, newCount = 0, updated = 0, skipped = 0;

  try {
    const resp = await fetch(CISA_KEV_URL, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'WadjetEye-TI/1.0' },
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      throw new Error(`CISA KEV HTTP ${resp.status}: ${resp.statusText}`);
    }

    const body = await resp.json();
    const vulnerabilities = Array.isArray(body.vulnerabilities) ? body.vulnerabilities : [];
    fetched = vulnerabilities.length;

    for (const entry of vulnerabilities) {
      const ioc = normalizeKevEntry(entry);
      if (!ioc) { skipped++; continue; }

      try {
        const { isNew, isUpdated } = await upsertIoc(supabase, ioc);
        if (isNew)     newCount++;
        else if (isUpdated) updated++;
        else           skipped++;
      } catch (upsertErr) {
        console.error(`[ti-poller] KEV upsert error for ${ioc.source_ref}:`, upsertErr.message);
        skipped++;
      }
    }

    const stats = { fetched, newCount, updated, skipped, feedName };
    await finish(stats, null);
    console.log(`[ti-poller] CISA KEV poll complete — fetched:${fetched} new:${newCount} updated:${updated} skipped:${skipped}`);
    return stats;

  } catch (err) {
    const stats = { fetched, newCount, updated, skipped, feedName };
    await finish(stats, err.message);
    console.error('[ti-poller] CISA KEV poll failed:', err.message);
    return { ...stats, error: err.message };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  pollOtx(supabase)
 *  Fetches OTX subscribed pulses (paginated), extracts indicators,
 *  normalizes, upserts into we_ioc_catalog.
 *  Ported from OtxClient.get_subscribed_pulses() + handle_otx_feed().
 *  Skipped automatically if OTX_API_KEY is not set.
 *  Returns PollStats.
 * ═══════════════════════════════════════════════════════════════════════ */
async function pollOtx (supabase) {
  const feedName = 'otx';

  const apiKey = process.env.OTX_API_KEY || '';
  if (!apiKey) {
    console.log('[ti-poller] OTX_API_KEY not set — skipping OTX poll');
    return { fetched: 0, newCount: 0, updated: 0, skipped: 0, feedName, skippedReason: 'no_api_key' };
  }

  const { finish } = await _writePollLog(supabase, feedName);
  let fetched = 0, newCount = 0, updated = 0, skipped = 0;

  try {
    // Determine modified_since: last successful poll time from poll_log, else 7 days ago
    const { data: lastPoll } = await supabase
      .from('we_ti_poll_log')
      .select('finished_at')
      .eq('feed_name', 'otx')
      .eq('status', 'success')
      .order('finished_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    const modifiedSince = lastPoll?.finished_at
      ? new Date(lastPoll.finished_at).toISOString()
      : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

    // Paginate through OTX subscribed pulses
    let nextUrl = `${OTX_BASE_URL}/api/v1/pulses/subscribed?limit=${OTX_PAGE_SIZE}&modified_since=${encodeURIComponent(modifiedSince)}`;
    let pages   = 0;

    while (nextUrl && pages < OTX_MAX_PAGES) {
      const resp = await fetch(nextUrl, {
        headers: {
          'X-OTX-API-KEY': apiKey,
          'Accept':        'application/json',
          'User-Agent':    'WadjetEye-TI/1.0',
        },
        signal: AbortSignal.timeout(30_000),
      });

      if (!resp.ok) {
        throw new Error(`OTX HTTP ${resp.status}: ${resp.statusText}`);
      }

      const body   = await resp.json();
      const pulses = Array.isArray(body.results) ? body.results : [];
      pages++;

      for (const pulse of pulses) {
        const indicators = Array.isArray(pulse.indicators) ? pulse.indicators : [];

        for (const ind of indicators) {
          fetched++;
          const ioc = normalizeOtxIndicator(ind, pulse);
          if (!ioc) { skipped++; continue; }

          try {
            const { isNew, isUpdated } = await upsertIoc(supabase, ioc);
            if (isNew)          newCount++;
            else if (isUpdated) updated++;
            else                skipped++;
          } catch (upsertErr) {
            console.error(`[ti-poller] OTX upsert error for ${ioc?.source_ref}:`, upsertErr.message);
            skipped++;
          }
        }
      }

      // OTX returns `next` as an absolute URL or null
      nextUrl = body.next || null;
    }

    const stats = { fetched, newCount, updated, skipped, feedName };
    await finish(stats, null);
    console.log(`[ti-poller] OTX poll complete — pages:${pages} fetched:${fetched} new:${newCount} updated:${updated} skipped:${skipped}`);
    return stats;

  } catch (err) {
    const stats = { fetched, newCount, updated, skipped, feedName };
    await finish(stats, err.message);
    console.error('[ti-poller] OTX poll failed:', err.message);
    return { ...stats, error: err.message };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  pollAll(supabase)
 *  Runs both feeds in sequence (KEV first, then OTX).
 *  Returns { cisaKev: PollStats, otx: PollStats }.
 * ═══════════════════════════════════════════════════════════════════════ */
async function pollAll (supabase) {
  const cisaKev = await pollCisaKev(supabase);
  const otx     = await pollOtx(supabase);
  return { cisaKev, otx };
}

/* ═══════════════════════════════════════════════════════════════════════
 *  pollNow(supabase, feedName)
 *  Trigger an immediate poll of one specific feed (or 'all').
 *  Used by REST endpoints or admin tools.
 * ═══════════════════════════════════════════════════════════════════════ */
async function pollNow (supabase, feedName) {
  const name = (feedName || 'all').toLowerCase();
  if (name === 'cisa-kev' || name === 'cisa_kev') return pollCisaKev(supabase);
  if (name === 'otx')                              return pollOtx(supabase);
  if (name === 'all')                              return pollAll(supabase);
  throw new Error(`Unknown feed name: ${feedName}. Supported: cisa-kev, otx, all`);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  enrichAlertWithTI(supabase, alertBody)
 *  Look up alert IOC fields in we_ioc_catalog.
 *  Returns { hits: IOCRow[], hitCount: number } — empty if no matches.
 *  Called from alerts POST route in shadow mode.
 * ═══════════════════════════════════════════════════════════════════════ */
async function enrichAlertWithTI (supabase, alertBody) {
  const candidates = [];

  // Collect searchable values from alert
  if (alertBody.ioc_value) candidates.push(alertBody.ioc_value);
  if (alertBody.src_ip)    candidates.push(alertBody.src_ip);
  if (alertBody.dst_ip)    candidates.push(alertBody.dst_ip);
  if (alertBody.hostname)  candidates.push(alertBody.hostname);
  if (alertBody.file_hash) candidates.push(alertBody.file_hash);

  // Add CVEs from metadata
  const meta = alertBody.metadata || {};
  if (meta.cve_id)           candidates.push(meta.cve_id);
  if (Array.isArray(meta.cves)) candidates.push(...meta.cves);

  const searchValues = [...new Set(candidates.filter(Boolean).map(String))];
  if (!searchValues.length) return { hits: [], hitCount: 0 };

  // Query we_ioc_catalog — match any of the search values
  const { data: hits, error } = await supabase
    .from('we_ioc_catalog')
    .select('id, ioc_type, ioc_value, source, source_ref, description, tlp, tags, confidence, due_date')
    .in('ioc_value', searchValues)
    .eq('is_active', true)
    .limit(20);

  if (error) {
    console.error('[ti-poller] TI enrichment query error (non-fatal):', error.message);
    return { hits: [], hitCount: 0 };
  }

  return { hits: hits || [], hitCount: (hits || []).length };
}

/* ═══════════════════════════════════════════════════════════════════════
 *  startPoller(supabase)
 *  Starts the background polling scheduler.
 *  Feature-flagged: does nothing if ENABLE_THREAT_INTEL_POLLING != true.
 *  Returns { stop() } handle to cancel intervals.
 *
 *  Schedule (ported from AiSOC FeedScheduler intervals):
 *    • CISA KEV — every 6 hours
 *    • OTX      — every 1 hour
 *    • Both fire once 30 s after startup to warm up the catalog.
 * ═══════════════════════════════════════════════════════════════════════ */
function startPoller (supabase) {
  if (!isPollingEnabled()) {
    console.log('[ti-poller] ENABLE_THREAT_INTEL_POLLING=false — poller not started (shadow mode)');
    return { stop: () => {} };
  }

  console.log('[ti-poller] Starting threat intel poller (CISA KEV every 6h, OTX every 1h)');

  // Startup warm-up — run once after server is fully ready
  const startupTimer = setTimeout(async () => {
    console.log('[ti-poller] Running startup poll...');
    try { await pollAll(supabase); }
    catch (err) { console.error('[ti-poller] Startup poll error:', err.message); }
  }, STARTUP_DELAY_MS);

  // Recurring intervals
  const kevInterval = setInterval(async () => {
    try { await pollCisaKev(supabase); }
    catch (err) { console.error('[ti-poller] Scheduled CISA KEV error:', err.message); }
  }, CISA_KEV_INTERVAL_MS);

  const otxInterval = setInterval(async () => {
    try { await pollOtx(supabase); }
    catch (err) { console.error('[ti-poller] Scheduled OTX error:', err.message); }
  }, OTX_INTERVAL_MS);

  return {
    stop () {
      clearTimeout(startupTimer);
      clearInterval(kevInterval);
      clearInterval(otxInterval);
      console.log('[ti-poller] Poller stopped');
    },
  };
}

/* ── Module export (Node.js only — server-side) ────────────────────────── */
module.exports = {
  isPollingEnabled,
  normalizeKevEntry,
  normalizeOtxIndicator,
  upsertIoc,
  pollCisaKev,
  pollOtx,
  pollAll,
  pollNow,
  enrichAlertWithTI,
  startPoller,
  // Expose constants for tests
  _CISA_KEV_URL:      CISA_KEV_URL,
  _OTX_BASE_URL:      OTX_BASE_URL,
  _OTX_TYPE_MAP:      OTX_TYPE_MAP,
  _hashShort,
};
