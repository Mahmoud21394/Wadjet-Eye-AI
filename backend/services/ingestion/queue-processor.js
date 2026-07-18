/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Queue-Based IOC Ingestion Engine  v1.0
 *  backend/services/ingestion/queue-processor.js
 *
 *  ARCHITECTURE OVERVIEW
 *  ─────────────────────────────────────────────────────────────────────
 *  Replaces the circuit-breaker pattern (MAX_CONSECUTIVE_ERRORS=3) that
 *  caused thousands of IOCs to be silently dropped when 3 consecutive
 *  Supabase upserts timed out.
 *
 *  NEW DESIGN:
 *  ┌─────────────────────────────────────────────────────────────────┐
 *  │  Feed Worker (OTX, URLhaus, etc.)                               │
 *  │    ↓ enqueueIOCs()                                              │
 *  │  ioc_queue table (PostgreSQL — durable, survives crashes)       │
 *  │    ↓ QueueProcessor.processBatch()                              │
 *  │  Batch Worker (claims SKIP LOCKED, processes 50 at a time)     │
 *  │    ↓ success → mark done                                        │
 *  │    ↓ failure → exponential backoff retry (up to 5 attempts)    │
 *  │    ↓ exhausted → dead_letter queue (logged, inspectable)       │
 *  └─────────────────────────────────────────────────────────────────┘
 *
 *  KEY PROPERTIES:
 *  • Durable: IOCs survive server restarts (stored in DB, not memory)
 *  • Concurrent-safe: SKIP LOCKED prevents double-processing
 *  • Configurable: BATCH_SIZE, MAX_ATTEMPTS, BACKOFF_BASE_MS all env-driven
 *  • Observability: every attempt logged with error history
 *  • Dead-letter: failed IOCs land in inspectable queue, not discarded
 *  • Back-pressure: configurable inter-batch delay prevents DB overload
 *  • Bulk upsert: uses PostgreSQL UPSERT (INSERT ... ON CONFLICT) via RPC
 *    for maximum throughput without N+1 queries
 *
 *  TIMEOUT FIX:
 *  • Uses supabaseIngestion client (45s timeout) — isolated from auth
 *  • Batch size defaults to 50 rows — tunable via INGESTION_BATCH_SIZE env
 *  • Inter-batch delay defaults to 200ms — prevents connection pool saturation
 *  • On timeout error: reduces batch size to 10 and retries with 3s delay
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const { v4: uuidv4 }         = require('uuid');
const { supabaseIngestion }   = require('../../config/supabase');

// ── Configuration (all env-overridable) ──────────────────────────────────────
const BATCH_SIZE         = parseInt(process.env.INGESTION_BATCH_SIZE   || '50',  10);
const MAX_ATTEMPTS       = parseInt(process.env.INGESTION_MAX_ATTEMPTS  || '5',   10);
const BACKOFF_BASE_MS    = parseInt(process.env.INGESTION_BACKOFF_MS    || '2000',10);
const BACKOFF_MAX_MS     = parseInt(process.env.INGESTION_BACKOFF_MAX   || '60000',10);
const INTER_BATCH_DELAY  = parseInt(process.env.INGESTION_INTER_BATCH_MS|| '200', 10);
const TIMEOUT_BATCH_SIZE = 10;     // reduced batch size on timeout errors
const TIMEOUT_DELAY_MS   = 3000;   // extra delay after a timeout error
const DEFAULT_TENANT     = '00000000-0000-0000-0000-000000000001';

// ── Active processor state ────────────────────────────────────────────────────
let _processorRunning = false;

/**
 * _sleep — await-able delay.
 * @param {number} ms
 */
function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
}

/**
 * _backoffMs — exponential backoff with jitter.
 * attempt=1 → ~2s, attempt=2 → ~4s, attempt=3 → ~8s, attempt=4 → ~16s, attempt=5 → ~32s
 *
 * @param {number} attempt  (1-based)
 * @returns {number} milliseconds to wait
 */
function _backoffMs(attempt) {
  const exp = Math.min(
    BACKOFF_BASE_MS * Math.pow(2, attempt - 1),
    BACKOFF_MAX_MS
  );
  // ±20% jitter to prevent thundering herd
  const jitter = exp * 0.2 * (Math.random() - 0.5);
  return Math.floor(exp + jitter);
}

/**
 * _isTimeoutError — detect DB timeout / abort errors.
 * @param {Error|object} err
 */
function _isTimeoutError(err) {
  if (!err) return false;
  const msg = ((err.message || '') + (err.code || '')).toLowerCase();
  return (
    msg.includes('statement timeout')       ||
    msg.includes('canceling statement')     ||
    msg.includes('query_canceled')          ||
    msg.includes('timeout')                 ||
    msg.includes('econnaborted')            ||
    msg.includes('etimedout')               ||
    msg.includes('aborted')
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  ENQUEUE — Feed workers call this instead of upsertIOCs()
//  Inserts IOCs into the durable queue table in one bulk INSERT.
//  Uses onConflict:'tenant_id,batch_id,ioc_value' to safely handle
//  duplicate IOC values within a single feed run.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * enqueueIOCs — push IOCs from a feed worker into the durable queue.
 *
 * @param {string}   tenantId    UUID of the target tenant
 * @param {string}   feedSource  Feed name (e.g. 'otx', 'urlhaus')
 * @param {object[]} iocs        Array of IOC objects from feed workers
 * @param {object}   [opts]
 * @param {number}   [opts.priority=5]       Lower = higher priority (0-10)
 * @param {string}   [opts.batchId]          Caller-supplied batch UUID (auto-generated if absent)
 * @returns {Promise<{ batchId: string, enqueued: number, skipped: number }>}
 */
async function enqueueIOCs(tenantId, feedSource, iocs, opts = {}) {
  if (!iocs || iocs.length === 0) {
    return { batchId: opts.batchId || uuidv4(), enqueued: 0, skipped: 0 };
  }

  const batchId  = opts.batchId || uuidv4();
  const priority = opts.priority !== undefined ? opts.priority : 5;
  const now      = new Date().toISOString();

  // Deduplicate IOCs within the batch by value (same value, different row = skip)
  const seen    = new Set();
  const dedupd  = [];
  for (const ioc of iocs) {
    const v = (ioc.value || '').toString().toLowerCase().trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    dedupd.push(ioc);
  }

  // Build queue rows
  const rows = dedupd.map(ioc => ({
    tenant_id:       tenantId || DEFAULT_TENANT,
    batch_id:        batchId,
    feed_source:     feedSource,
    ioc_value:       (ioc.value || '').toString().toLowerCase().trim().slice(0, 2048),
    ioc_type:        ioc.type || 'unknown',
    priority,
    status:          'pending',
    attempts:        0,
    max_attempts:    MAX_ATTEMPTS,
    next_attempt_at: now,
    payload:         {
      type:           ioc.type,
      value:          ioc.value,
      reputation:     ioc.reputation     || 'unknown',
      risk_score:     ioc.risk_score     || 0,
      confidence:     ioc.confidence     || 0,
      source:         ioc.source         || feedSource,
      feed_source:    ioc.feed_source    || feedSource,
      tags:           ioc.tags           || [],
      notes:          ioc.notes          || null,
      malware_family: ioc.malware_family || null,
      enrichment_data:ioc.enrichment_data|| {},
      country:        ioc.country        || null,
      threat_actor:   ioc.threat_actor   || null,
    },
  }));

  // Bulk-insert in chunks of 500 to stay within Supabase request size limits
  const CHUNK = 500;
  let enqueued = 0;
  let skipped  = 0;

  for (let i = 0; i < rows.length; i += CHUNK) {
    const chunk = rows.slice(i, i + CHUNK);
    const { data, error } = await supabaseIngestion
      .from('ioc_queue')
      .insert(chunk, { onConflict: 'tenant_id,batch_id,ioc_value', ignoreDuplicates: true });

    if (error) {
      console.warn(`[Queue][${feedSource}] Enqueue chunk ${i}–${i+CHUNK} error:`, error.message);
      skipped += chunk.length;
    } else {
      enqueued += chunk.length;
    }

    if (i + CHUNK < rows.length) await _sleep(50); // small delay between insert chunks
  }

  console.info(`[Queue][${feedSource}] Enqueued: ${enqueued} IOCs, skipped: ${skipped}, batchId=${batchId}`);
  return { batchId, enqueued, skipped };
}

// ══════════════════════════════════════════════════════════════════════════════
//  PROCESS BATCH — Claim and process a batch of pending queue items
//  Uses PostgreSQL SKIP LOCKED to safely run multiple workers concurrently.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * _claimBatch — atomically claim a batch of pending queue items.
 * Uses the claim_ioc_queue_batch() DB function (created in migration).
 *
 * @param {string}  tenantId
 * @param {number}  batchSize
 * @returns {Promise<object[]>}
 */
async function _claimBatch(tenantId, batchSize) {
  const { data, error } = await supabaseIngestion.rpc('claim_ioc_queue_batch', {
    p_tenant_id:  tenantId,
    p_batch_size: batchSize,
  });

  if (error) {
    // Fallback: direct query if RPC not available (migration not run yet)
    console.warn('[Queue] RPC claim_ioc_queue_batch failed, using direct query:', error.message);
    const fallback = await supabaseIngestion
      .from('ioc_queue')
      .select('*')
      .eq('tenant_id', tenantId)
      .eq('status', 'pending')
      .lte('next_attempt_at', new Date().toISOString())
      .lt('attempts', MAX_ATTEMPTS)
      .order('priority', { ascending: true })
      .order('next_attempt_at', { ascending: true })
      .limit(batchSize);

    if (fallback.error) {
      throw new Error(`Queue claim failed: ${fallback.error.message}`);
    }
    return fallback.data || [];
  }

  return data || [];
}

/**
 * _upsertBulk — perform a bulk upsert of IOC payloads.
 * Uses INSERT ... ON CONFLICT (tenant_id, value) DO UPDATE SET ...
 * This is ~10-20x faster than row-by-row upserts because:
 *   1. Single round-trip to Supabase
 *   2. PostgreSQL can use the UNIQUE index efficiently
 *   3. No N+1 SELECT queries
 *
 * @param {string}   tenantId
 * @param {object[]} items     Queue items (each has .payload)
 * @returns {Promise<{ new: number, updated: number, failed: number }>}
 */
async function _upsertBulk(tenantId, items) {
  if (items.length === 0) return { new: 0, updated: 0, failed: 0 };

  const rows = items.map(item => {
    const p = item.payload || {};
    return {
      tenant_id:       tenantId,
      value:           item.ioc_value,
      type:            item.ioc_type,
      reputation:      p.reputation     || 'unknown',
      risk_score:      p.risk_score     || 0,
      confidence:      p.confidence     || 0,
      source:          p.source         || item.feed_source,
      feed_source:     p.feed_source    || item.feed_source,
      tags:            p.tags           || [],
      notes:           p.notes          || null,
      malware_family:  p.malware_family || null,
      enrichment_data: p.enrichment_data|| {},
      country:         p.country        || null,
      threat_actor:    p.threat_actor   || null,
      status:          'active',
      last_seen:       new Date().toISOString(),
    };
  });

  // Supabase upsert — requires UNIQUE INDEX on (tenant_id, value)
  const { data, error } = await supabaseIngestion
    .from('iocs')
    .upsert(rows, {
      onConflict:       'tenant_id,value',
      ignoreDuplicates: false,          // merge enrichment fields on conflict
    })
    .select('id');

  if (error) {
    throw error;
  }

  return {
    new:     data ? data.length : 0,  // approximate (upsert doesn't distinguish new vs updated)
    updated: 0,
    failed:  0,
  };
}

/**
 * _markDone — mark queue items as successfully processed.
 * @param {string[]} ids  Queue item UUIDs
 */
async function _markDone(ids) {
  if (!ids.length) return;
  await supabaseIngestion
    .from('ioc_queue')
    .update({
      status:       'done',
      processed_at: new Date().toISOString(),
    })
    .in('id', ids);
}

/**
 * _markFailed — mark queue items as failed, with error history appended.
 * Items that reach max_attempts are moved to dead_letter.
 *
 * @param {object[]} items   Queue items that failed this attempt
 * @param {string}   errMsg  Error message to record
 */
async function _markFailed(items, errMsg) {
  if (!items.length) return;
  const now = new Date().toISOString();

  for (const item of items) {
    const newAttempts = (item.attempts || 0);  // already incremented by claim
    const isDead      = newAttempts >= (item.max_attempts || MAX_ATTEMPTS);

    const nextAttempt = isDead
      ? null
      : new Date(Date.now() + _backoffMs(newAttempts)).toISOString();

    const errorHistory = [...(item.error_history || []), {
      attempt:   newAttempts,
      error:     errMsg,
      timestamp: now,
    }].slice(-10); // keep last 10 error entries

    await supabaseIngestion
      .from('ioc_queue')
      .update({
        status:          isDead ? 'dead_letter' : 'pending',
        last_error:      errMsg,
        error_history:   errorHistory,
        next_attempt_at: isDead ? null : nextAttempt,
      })
      .eq('id', item.id);
  }

  const deadCount = items.filter(i => (i.attempts || 0) >= (i.max_attempts || MAX_ATTEMPTS)).length;
  if (deadCount > 0) {
    console.warn(`[Queue] ${deadCount} IOCs moved to dead_letter queue after ${MAX_ATTEMPTS} attempts`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  processBatch — process one batch of queue items for a given tenant
//  Called in a loop by the queue processor scheduler.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * processBatch — process one batch of pending IOC queue items.
 *
 * @param {string}  tenantId
 * @param {object}  [opts]
 * @param {number}  [opts.batchSize]   Override BATCH_SIZE for this call
 * @returns {Promise<{ processed: number, failed: number, dead: number }>}
 */
async function processBatch(tenantId, opts = {}) {
  const batchSize = opts.batchSize || BATCH_SIZE;

  let items;
  try {
    items = await _claimBatch(tenantId, batchSize);
  } catch (claimErr) {
    console.error('[Queue] Failed to claim batch:', claimErr.message);
    return { processed: 0, failed: 0, dead: 0 };
  }

  if (!items || items.length === 0) {
    return { processed: 0, failed: 0, dead: 0 };
  }

  console.info(`[Queue][${tenantId}] Processing batch of ${items.length} IOCs`);

  try {
    const result = await _upsertBulk(tenantId, items);
    await _markDone(items.map(i => i.id));
    console.info(`[Queue][${tenantId}] Batch done: ${items.length} processed`);
    return { processed: items.length, failed: 0, dead: 0, ...result };

  } catch (upsertErr) {
    const isTimeout = _isTimeoutError(upsertErr);
    console.error(
      `[Queue][${tenantId}] Batch upsert ${isTimeout ? 'TIMEOUT' : 'ERROR'}: ${upsertErr.message}`
    );

    // On timeout: fail all items in this batch so they retry individually
    // with smaller batches next time (handled by _markFailed backoff)
    await _markFailed(items, upsertErr.message);

    if (isTimeout) {
      // Extra delay after timeout before next batch — let DB recover
      await _sleep(TIMEOUT_DELAY_MS);
    }

    const deadCount = items.filter(i => (i.attempts || 0) >= (i.max_attempts || MAX_ATTEMPTS)).length;
    return { processed: 0, failed: items.length - deadCount, dead: deadCount };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  processAllPending — drain all pending items for a tenant
//  Runs batches in sequence until queue is empty.
//  Respects INTER_BATCH_DELAY to prevent DB overload.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * processAllPending — process all pending IOC queue items for a tenant.
 * Runs until queue is empty or an error count threshold is reached.
 *
 * @param {string}  tenantId
 * @param {object}  [opts]
 * @param {number}  [opts.maxErrors=10]    Stop after this many consecutive errors
 * @param {number}  [opts.maxBatches=200]  Safety limit on total batches
 * @returns {Promise<{ totalProcessed: number, totalFailed: number, totalDead: number, batches: number }>}
 */
async function processAllPending(tenantId, opts = {}) {
  const maxErrors  = opts.maxErrors  || 10;
  const maxBatches = opts.maxBatches || 200;

  let totalProcessed = 0;
  let totalFailed    = 0;
  let totalDead      = 0;
  let batches        = 0;
  let consecutiveErrors = 0;
  let currentBatchSize  = BATCH_SIZE;

  console.info(`[Queue][${tenantId}] Starting processAllPending (maxBatches=${maxBatches})`);

  while (batches < maxBatches) {
    const result = await processBatch(tenantId, { batchSize: currentBatchSize });

    totalProcessed    += result.processed || 0;
    totalFailed       += result.failed    || 0;
    totalDead         += result.dead      || 0;
    batches++;

    if (result.processed === 0 && result.failed === 0 && result.dead === 0) {
      // Queue is empty
      console.info(`[Queue][${tenantId}] Queue drained after ${batches} batches`);
      break;
    }

    if (result.failed > 0) {
      consecutiveErrors++;
      // Reduce batch size on errors to lighten DB load
      currentBatchSize = Math.max(TIMEOUT_BATCH_SIZE, Math.floor(currentBatchSize / 2));
      console.warn(`[Queue] Consecutive errors: ${consecutiveErrors}, reduced batch to ${currentBatchSize}`);

      if (consecutiveErrors >= maxErrors) {
        console.error(`[Queue] Reached maxErrors=${maxErrors}, pausing queue processing`);
        break;
      }
    } else {
      consecutiveErrors = 0;
      // Gradually restore batch size after successful batches
      if (currentBatchSize < BATCH_SIZE) {
        currentBatchSize = Math.min(BATCH_SIZE, currentBatchSize + 10);
      }
    }

    // Inter-batch delay — prevents saturating the DB connection pool
    await _sleep(INTER_BATCH_DELAY);
  }

  console.info(
    `[Queue][${tenantId}] Completed: processed=${totalProcessed} failed=${totalFailed} ` +
    `dead=${totalDead} batches=${batches}`
  );

  return { totalProcessed, totalFailed, totalDead, batches };
}

// ══════════════════════════════════════════════════════════════════════════════
//  getQueueStats — queue health metrics for monitoring/dashboard
// ══════════════════════════════════════════════════════════════════════════════

/**
 * getQueueStats — return queue depth and dead-letter count for a tenant.
 *
 * @param {string} tenantId
 * @returns {Promise<object>}
 */
async function getQueueStats(tenantId) {
  const { data, error } = await supabaseIngestion
    .from('ioc_queue')
    .select('status')
    .eq('tenant_id', tenantId);

  if (error) {
    return { error: error.message };
  }

  const counts = (data || []).reduce((acc, row) => {
    acc[row.status] = (acc[row.status] || 0) + 1;
    return acc;
  }, {});

  return {
    pending:     counts.pending     || 0,
    processing:  counts.processing  || 0,
    done:        counts.done        || 0,
    failed:      counts.failed      || 0,
    dead_letter: counts.dead_letter || 0,
    total:       (data || []).length,
  };
}

/**
 * requeueDeadLetter — move dead-letter items back to pending for manual retry.
 * Resets attempt count and next_attempt_at.
 *
 * @param {string}  tenantId
 * @param {object}  [opts]
 * @param {string}  [opts.feedSource]  Filter to specific feed (optional)
 * @param {number}  [opts.limit=100]   Max items to requeue
 * @returns {Promise<number>}  Count of requeued items
 */
async function requeueDeadLetter(tenantId, opts = {}) {
  const query = supabaseIngestion
    .from('ioc_queue')
    .update({
      status:          'pending',
      attempts:        0,
      next_attempt_at: new Date().toISOString(),
      last_error:      null,
    })
    .eq('tenant_id', tenantId)
    .eq('status', 'dead_letter');

  if (opts.feedSource) {
    query.eq('feed_source', opts.feedSource);
  }

  if (opts.limit) {
    // Supabase doesn't support LIMIT on UPDATE — use IDs approach
    const { data: deadItems } = await supabaseIngestion
      .from('ioc_queue')
      .select('id')
      .eq('tenant_id', tenantId)
      .eq('status', 'dead_letter')
      .limit(opts.limit || 100);

    if (!deadItems || deadItems.length === 0) return 0;

    const { error } = await supabaseIngestion
      .from('ioc_queue')
      .update({
        status:          'pending',
        attempts:        0,
        next_attempt_at: new Date().toISOString(),
        last_error:      null,
      })
      .in('id', deadItems.map(i => i.id));

    if (error) throw error;
    return deadItems.length;
  }

  const { error } = await query;
  if (error) throw error;
  return -1; // unknown count without limit
}

// ══════════════════════════════════════════════════════════════════════════════
//  DROP-IN REPLACEMENT for old upsertIOCs()
//  Feed workers can call this exactly like the old function.
//  Instead of directly upserting, this enqueues IOCs and then
//  immediately processes the queue for that tenant.
//  Returns the same { new, updated, duplicate } shape for compatibility.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * upsertIOCsQueued — drop-in replacement for old upsertIOCs().
 * Enqueues IOCs durably, then immediately processes the queue.
 * Falls back to direct upsert if queue table unavailable.
 *
 * @param {string}   tenantId
 * @param {object[]} iocs
 * @param {string}   feedSource
 * @returns {Promise<{ new: number, updated: number, duplicate: number }>}
 */
async function upsertIOCsQueued(tenantId, iocs, feedSource = 'unknown') {
  if (!iocs || iocs.length === 0) {
    return { new: 0, updated: 0, duplicate: 0 };
  }

  // 1. Enqueue into durable queue
  let enqueueResult;
  try {
    enqueueResult = await enqueueIOCs(tenantId, feedSource, iocs);
  } catch (enqueueErr) {
    console.error('[Queue] Enqueue failed, falling back to direct upsert:', enqueueErr.message);
    // Fallback to legacy direct upsert
    return _directUpsertFallback(tenantId, iocs);
  }

  // 2. Immediately process pending items for this tenant
  let processResult;
  try {
    processResult = await processAllPending(tenantId);
  } catch (processErr) {
    console.error('[Queue] Processing failed:', processErr.message);
    return { new: 0, updated: 0, duplicate: enqueueResult.skipped };
  }

  return {
    new:       processResult.totalProcessed,
    updated:   0,
    duplicate: enqueueResult.skipped,
  };
}

/**
 * _directUpsertFallback — legacy direct upsert used when queue table unavailable.
 * Mirrors the original upsertIOCs() logic with chunking and timeout reduction.
 *
 * @param {string}   tenantId
 * @param {object[]} iocs
 * @returns {Promise<{ new: number, updated: number, duplicate: number }>}
 */
async function _directUpsertFallback(tenantId, iocs) {
  let chunkSize         = 25;
  let consecutiveErrors = 0;
  const MAX_ERRORS      = 10;  // raised from 3 — don't trip on transient errors
  let totalNew          = 0;
  let totalDup          = 0;

  // Deduplicate within batch
  const seen  = new Map();
  const dedup = [];
  for (const ioc of iocs) {
    const key = `${ioc.type || ''}:${(ioc.value || '').toLowerCase().trim()}`;
    if (!ioc.value || seen.has(key)) { totalDup++; continue; }
    seen.set(key, true);
    dedup.push(ioc);
  }

  const rows = dedup.map(ioc => ({
    tenant_id:       tenantId,
    value:           (ioc.value || '').toString().toLowerCase().trim().slice(0, 2048),
    type:            ioc.type       || 'unknown',
    reputation:      ioc.reputation || 'unknown',
    risk_score:      ioc.risk_score || 0,
    confidence:      ioc.confidence || 0,
    source:          ioc.source     || 'manual',
    feed_source:     ioc.feed_source|| null,
    tags:            ioc.tags       || [],
    notes:           ioc.notes      || null,
    malware_family:  ioc.malware_family || null,
    enrichment_data: ioc.enrichment_data || {},
    country:         ioc.country    || null,
    threat_actor:    ioc.threat_actor || null,
    status:          'active',
    last_seen:       new Date().toISOString(),
  }));

  for (let i = 0; i < rows.length; i += chunkSize) {
    if (consecutiveErrors >= MAX_ERRORS) {
      console.error(`[Fallback] MAX_ERRORS=${MAX_ERRORS} reached at IOC ${i}/${rows.length} — stopping`);
      break;
    }

    const chunk = rows.slice(i, i + chunkSize);
    let   attempts = 0;

    while (attempts < 3) {
      try {
        const { error } = await supabaseIngestion
          .from('iocs')
          .upsert(chunk, { onConflict: 'tenant_id,value', ignoreDuplicates: false });

        if (error) {
          if (_isTimeoutError({ message: error.message })) {
            console.warn(`[Fallback] Timeout on chunk ${i} attempt ${attempts+1} — reducing chunk to ${TIMEOUT_BATCH_SIZE}`);
            chunkSize = TIMEOUT_BATCH_SIZE;
            consecutiveErrors++;
            attempts++;
            await _sleep(_backoffMs(attempts));
            continue;
          }
          console.warn('[Fallback] Upsert error:', error.message);
          consecutiveErrors++;
          break;
        }

        totalNew += chunk.length;
        consecutiveErrors = 0;
        break;

      } catch (err) {
        attempts++;
        consecutiveErrors++;
        console.warn(`[Fallback] Exception attempt ${attempts}:`, err.message);
        if (attempts < 3) await _sleep(_backoffMs(attempts));
      }
    }

    // Inter-chunk delay
    const delay = consecutiveErrors > 0 ? TIMEOUT_DELAY_MS : 200;
    if (i + chunkSize < rows.length) await _sleep(delay);
  }

  return { new: totalNew, updated: 0, duplicate: totalDup };
}

// ══════════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ══════════════════════════════════════════════════════════════════════════════

module.exports = {
  enqueueIOCs,
  processBatch,
  processAllPending,
  getQueueStats,
  requeueDeadLetter,
  upsertIOCsQueued,       // drop-in replacement for old upsertIOCs()
  _directUpsertFallback,  // exported for testing
};
