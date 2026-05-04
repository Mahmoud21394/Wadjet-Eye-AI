/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Kafka Background Worker (Phase 2)
 *  backend/workers/kafka-worker.js
 *
 *  Runs as a separate process consuming all Kafka topics:
 *    raw-events        → normalize → publish normalized-events
 *    normalized-events → detect   → publish detections
 *    detections        → enrich   → publish enrichments
 *    enrichments       → cluster  → publish alerts
 *    alerts            → soar     → auto-respond / ticket
 *    dark-web-intel    → fanout   → SIEM connectors
 *    audit-log         → persist  → Supabase
 *
 *  Start: node backend/workers/kafka-worker.js
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

require('dotenv').config();

const { createConsumer, disconnectAll } = require('../services/streaming/kafka-consumer');
const { publish, TOPICS }              = require('../services/streaming/kafka-producer');
const logger                           = require('../utils/logger');
const crypto                           = require('crypto');

const SVC = 'KafkaWorker';

// ── Lazy service imports (avoid loading unused modules) ───────────
let _detectionEngine, _enrichmentEngine, _clusterEngine, _soarEngine,
    _siemFanout, _selfLearning, _supabase;

function detectionEngine() {
  if (!_detectionEngine) _detectionEngine = require('../services/detection/detection-engine');
  return _detectionEngine;
}
function enrichmentEngine() {
  if (!_enrichmentEngine) _enrichmentEngine = require('../services/enrichment-engine');
  return _enrichmentEngine;
}
function clusterEngine() {
  if (!_clusterEngine) _clusterEngine = require('../services/detection/dbscan-clustering');
  return _clusterEngine;
}
function siemFanout() {
  if (!_siemFanout) _siemFanout = require('../services/integrations/splunk-connector');
  return _siemFanout;
}
function selfLearning() {
  if (!_selfLearning) _selfLearning = require('../services/detection/self-learning');
  return _selfLearning;
}
function supabase() {
  if (!_supabase) {
    const cfg = require('../config/supabase');
    _supabase  = cfg.supabase || cfg;
  }
  return _supabase;
}

// ── Metric counters ───────────────────────────────────────────────
const counters = {
  rawEvents:       0,
  normalized:      0,
  detections:      0,
  enrichments:     0,
  alerts:          0,
  clusters:        0,
  soarActions:     0,
  darkwebFindings: 0,
  errors:          0,
};

// ── 1. Raw events → Normalize ─────────────────────────────────────
async function handleRawEvent(topic, partition, message) {
  let event;
  try {
    event = JSON.parse(message.value.toString());
  } catch {
    logger.warn(SVC, 'Invalid JSON in raw-events');
    return;
  }

  counters.rawEvents++;

  // Normalize: add standard fields if missing
  const normalized = {
    event_id:     event.id         || crypto.randomUUID(),
    tenant_id:    event.tenant_id  || process.env.DEFAULT_TENANT_ID || '',
    source:       event.source     || 'unknown',
    src_ip:       event.src_ip     || event.sourceAddress || event.src || null,
    dst_ip:       event.dst_ip     || event.destAddress   || event.dst || null,
    src_port:     event.src_port   || event.sourcePort    || null,
    dst_port:     event.dst_port   || event.destPort      || null,
    protocol:     event.protocol   || null,
    username:     event.username   || event.user          || null,
    process_name: event.process    || event.processName   || null,
    hostname:     event.hostname   || event.host          || null,
    event_type:   event.event_type || event.type          || 'generic',
    severity:     _normalizeSeverity(event.severity       || event.level || 'INFO'),
    raw:          event,
    normalized_at: new Date().toISOString(),
  };

  await publish(TOPICS.NORMALIZED_EVENTS, normalized, { key: normalized.tenant_id });
  counters.normalized++;
}

// ── 2. Normalized events → Detection ─────────────────────────────
async function handleNormalizedEvent(topic, partition, message) {
  let event;
  try {
    event = JSON.parse(message.value.toString());
  } catch { return; }

  let detections = [];
  try {
    const engine = detectionEngine();
    if (typeof engine.evaluateEvent === 'function') {
      detections = await engine.evaluateEvent(event);
    } else if (typeof engine.detect === 'function') {
      detections = await engine.detect(event);
    }
  } catch (err) {
    logger.error(SVC, `Detection error: ${err.message}`);
    counters.errors++;
    return;
  }

  for (const det of detections) {
    await publish(TOPICS.DETECTIONS, det, { key: det.tenant_id || event.tenant_id });
    counters.detections++;
  }
}

// ── 3. Detections → Enrichment ────────────────────────────────────
async function handleDetection(topic, partition, message) {
  let detection;
  try {
    detection = JSON.parse(message.value.toString());
  } catch { return; }

  let enriched = { ...detection };
  try {
    const eng = enrichmentEngine();
    if (typeof eng.enrich === 'function') {
      enriched = await eng.enrich(detection);
    }
  } catch (err) {
    logger.warn(SVC, `Enrichment error: ${err.message}`);
  }

  await publish(TOPICS.ENRICHMENTS, enriched, { key: enriched.tenant_id });
  counters.enrichments++;
}

// ── 4. Enrichments → Alert creation ──────────────────────────────
async function handleEnrichment(topic, partition, message) {
  let enriched;
  try {
    enriched = JSON.parse(message.value.toString());
  } catch { return; }

  // Write alert to Supabase
  const alert = {
    id:              crypto.randomUUID(),
    tenant_id:       enriched.tenant_id,
    rule_id:         enriched.rule_id   || null,
    title:           enriched.title     || `${enriched.severity || 'MEDIUM'} Detection — ${enriched.event_type || 'Unknown'}`,
    description:     enriched.description || '',
    severity:        enriched.severity  || 'MEDIUM',
    category:        enriched.category  || null,
    status:          'open',
    confidence:      enriched.confidence || 70,
    src_ip:          enriched.src_ip    || null,
    dst_ip:          enriched.dst_ip    || null,
    src_port:        enriched.src_port  || null,
    dst_port:        enriched.dst_port  || null,
    username:        enriched.username  || null,
    mitre_tactic:    enriched.mitre_tactic    || null,
    mitre_technique: enriched.mitre_technique || null,
    mitre_techniques: enriched.mitre_techniques || [],
    iocs:            JSON.stringify(enriched.iocs || []),
    enrichment:      JSON.stringify(enriched.enrichment || {}),
    event_time:      enriched.event_time || enriched.normalized_at,
    created_at:      new Date().toISOString(),
  };

  try {
    const db = supabase();
    const { error } = await db.from('alerts').insert(alert);
    if (error) logger.warn(SVC, `Alert insert error: ${error.message}`);
  } catch (err) {
    logger.error(SVC, `Supabase alert insert failed: ${err.message}`);
  }

  await publish(TOPICS.ALERTS, alert, { key: alert.tenant_id });
  counters.alerts++;

  // Also fan out to SIEM connectors
  try {
    await siemFanout().fanoutAlert(alert);
  } catch (err) {
    logger.warn(SVC, `SIEM fanout error: ${err.message}`);
  }
}

// ── 5. Alerts → SOAR / Clustering ────────────────────────────────
// Batch alerts periodically for clustering (event-driven batching)
const _alertBatch = new Map(); // tenantId → Alert[]
const CLUSTER_BATCH_SIZE  = 50;
const CLUSTER_BATCH_MS    = 30_000; // 30s window

async function handleAlert(topic, partition, message) {
  let alert;
  try {
    alert = JSON.parse(message.value.toString());
  } catch { return; }

  const tid = alert.tenant_id || 'default';
  if (!_alertBatch.has(tid)) _alertBatch.set(tid, []);
  _alertBatch.get(tid).push(alert);

  // Flush batch if large enough
  if (_alertBatch.get(tid).length >= CLUSTER_BATCH_SIZE) {
    await _flushClusterBatch(tid);
  }
}

async function _flushClusterBatch(tid) {
  const batch = _alertBatch.get(tid);
  if (!batch || batch.length < 3) return;  // need ≥3 for DBSCAN
  _alertBatch.set(tid, []);

  try {
    const { clusters } = clusterEngine().clusterAlerts(batch, { algorithm: 'dbscan', epsilon: 0.3, minPts: 3 });

    for (const cluster of clusters) {
      cluster.tenant_id = tid;

      // Persist cluster to Supabase
      try {
        const db = supabase();
        await db.from('alert_clusters').upsert({
          cluster_id:   cluster.cluster_id,
          tenant_id:    tid,
          alert_count:  cluster.alert_count,
          severity:     cluster.severity,
          risk_score:   cluster.risk_score,
          first_seen:   cluster.first_seen,
          last_seen:    cluster.last_seen,
          narrative:    cluster.narrative,
          is_campaign:  cluster.is_campaign,
          campaign_confidence: cluster.campaign_confidence,
          mitre_techniques: cluster.mitre_techniques || [],
          updated_at:   new Date().toISOString(),
        }, { onConflict: 'cluster_id' });
      } catch (err) {
        logger.warn(SVC, `Cluster persist error: ${err.message}`);
      }

      counters.clusters++;
    }
  } catch (err) {
    logger.error(SVC, `Clustering error: ${err.message}`);
    counters.errors++;
  }
}

// ── 6. Dark web intel → Persist + alert ──────────────────────────
async function handleDarkwebIntel(topic, partition, message) {
  let scan;
  try {
    scan = JSON.parse(message.value.toString());
  } catch { return; }

  const findings = scan.findings || [];
  counters.darkwebFindings += findings.length;

  for (const finding of findings) {
    try {
      const db = supabase();
      await db.from('dark_web_findings').insert({
        id:           crypto.randomUUID(),
        source:       finding.source,
        group_name:   finding.group,
        url:          finding.url,
        severity:     finding.severity,
        relevance:    finding.relevance,
        finding_type: finding.type,
        iocs:         JSON.stringify(finding.iocs || {}),
        snippet:      finding.snippet,
        scan_id:      scan.scanId,
        discovered:   finding.discovered || new Date().toISOString(),
      });
    } catch (err) {
      logger.warn(SVC, `Dark web finding persist error: ${err.message}`);
    }
  }
}

// ── 7. Audit log → Persist ────────────────────────────────────────
async function handleAuditLog(topic, partition, message) {
  let entry;
  try {
    entry = JSON.parse(message.value.toString());
  } catch { return; }

  try {
    const db = supabase();
    await db.from('audit_logs').insert({
      id:          crypto.randomUUID(),
      tenant_id:   entry.tenant_id   || null,
      user_id:     entry.user_id     || null,
      action:      entry.action,
      resource:    entry.resource    || null,
      resource_id: entry.resource_id || null,
      ip_address:  entry.ip          || null,
      request_id:  entry.request_id  || null,
      status_code: entry.status_code || null,
      details:     JSON.stringify(entry.details || {}),
      created_at:  entry.created_at  || new Date().toISOString(),
    });
  } catch (err) {
    logger.warn(SVC, `Audit log persist error: ${err.message}`);
  }
}

// ── Helpers ───────────────────────────────────────────────────────
function _normalizeSeverity(raw) {
  const s = String(raw).toUpperCase();
  if (s === 'CRITICAL' || s === '5') return 'CRITICAL';
  if (s === 'HIGH'     || s === '4') return 'HIGH';
  if (s === 'MEDIUM'   || s === '3') return 'MEDIUM';
  if (s === 'LOW'      || s === '2') return 'LOW';
  return 'INFO';
}

// ── Start all consumers ───────────────────────────────────────────
async function start() {
  logger.info(SVC, '═══ Kafka Worker starting ═══');
  logger.info(SVC, `Brokers: ${process.env.KAFKA_BROKERS || 'kafka:9092'}`);

  await createConsumer('raw-events-normalizer',       [TOPICS.RAW_EVENTS],        handleRawEvent);
  await createConsumer('normalized-events-detector',  [TOPICS.NORMALIZED_EVENTS], handleNormalizedEvent);
  await createConsumer('detections-enricher',         [TOPICS.DETECTIONS],        handleDetection);
  await createConsumer('enrichments-alerter',         [TOPICS.ENRICHMENTS],       handleEnrichment);
  await createConsumer('alerts-soar-cluster',         [TOPICS.ALERTS],            handleAlert);
  await createConsumer('darkweb-intel-processor',     [TOPICS.DARK_WEB_INTEL],    handleDarkwebIntel);
  await createConsumer('audit-log-persister',         [TOPICS.AUDIT_LOG],         handleAuditLog);

  logger.info(SVC, '✓ All consumers started');

  // Periodic cluster batch flush
  setInterval(async () => {
    for (const tid of _alertBatch.keys()) {
      await _flushClusterBatch(tid);
    }
  }, CLUSTER_BATCH_MS);

  // Metrics reporting every 60s
  setInterval(() => {
    logger.info(SVC, `Counters: raw=${counters.rawEvents} norm=${counters.normalized} det=${counters.detections} enr=${counters.enrichments} alerts=${counters.alerts} clusters=${counters.clusters} dw=${counters.darkwebFindings} err=${counters.errors}`);
  }, 60_000);
}

// ── Graceful shutdown ─────────────────────────────────────────────
async function shutdown(signal) {
  logger.warn(SVC, `${signal} — shutting down gracefully...`);
  // Flush pending clusters
  for (const tid of _alertBatch.keys()) {
    await _flushClusterBatch(tid).catch(() => {});
  }
  await disconnectAll().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  logger.error(SVC, `Uncaught exception: ${err.message}\n${err.stack}`);
  counters.errors++;
});
process.on('unhandledRejection', (reason) => {
  logger.error(SVC, `Unhandled rejection: ${reason}`);
  counters.errors++;
});

start().catch((err) => {
  logger.error(SVC, `Worker startup failed: ${err.message}`);
  process.exit(1);
});
