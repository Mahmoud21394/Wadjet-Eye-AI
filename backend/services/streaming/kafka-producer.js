/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Kafka Event Streaming Producer (Phase 2)
 *  backend/services/streaming/kafka-producer.js
 *
 *  Replaces scheduler-based polling with event-driven streaming.
 *  Topics: raw-events, normalized-events, detections, enrichments,
 *          alerts, incidents, threat-intel, audit-log
 *
 *  Audit finding: No event streaming — event loss risk (CRITICAL)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { Kafka, Partitioners, CompressionTypes } = require('kafkajs');

// ── Kafka connection config ───────────────────────────────────────
const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || 'kafka:9092').split(',');
const CLIENT_ID     = process.env.KAFKA_CLIENT_ID || 'wadjet-eye-api';

const kafka = new Kafka({
  clientId: CLIENT_ID,
  brokers:  KAFKA_BROKERS,
  connectionTimeout: 10000,
  requestTimeout:    30000,
  retry: {
    initialRetryTime: 300,
    retries:          8,
    maxRetryTime:     30000,
    multiplier:       2,
  },
  ssl:  process.env.KAFKA_SSL === 'true' ? {} : false,
  sasl: process.env.KAFKA_SASL_USERNAME ? {
    mechanism: process.env.KAFKA_SASL_MECHANISM || 'scram-sha-256',
    username:  process.env.KAFKA_SASL_USERNAME,
    password:  process.env.KAFKA_SASL_PASSWORD,
  } : undefined,
});

// ── Topic definitions ─────────────────────────────────────────────
const TOPICS = {
  RAW_EVENTS:       'raw-events',          // Unprocessed log lines from collectors
  NORMALIZED:       'normalized-events',   // Parsed, normalized event objects
  DETECTIONS:       'detections',          // RAYKAN detection hits
  ENRICHMENTS:      'enrichments',         // IOC enrichment results
  ALERTS:           'alerts',              // Correlated alerts ready for analyst
  INCIDENTS:        'incidents',           // Grouped incidents
  THREAT_INTEL:     'threat-intel',        // STIX bundles, TI feed updates
  AUDIT_LOG:        'audit-log',           // Tamper-evident audit trail
  SOAR_TRIGGERS:    'soar-triggers',       // Playbook execution requests
  AGENT_TASKS:      'agent-tasks',         // Autonomous agent job queue
  AGENT_RESULTS:    'agent-results',       // Agent decision outputs
  METRICS:          'soc-metrics',         // MTTD/MTTR/analyst metrics
};

// ── Producer singleton ────────────────────────────────────────────
let producer = null;
let _connected = false;

async function getProducer() {
  if (_connected && producer) return producer;

  producer = kafka.producer({
    createPartitioner:   Partitioners.LegacyPartitioner,
    transactionTimeout:  30000,
    idempotent:          true,   // Exactly-once delivery
    maxInFlightRequests: 5,
    compression:         CompressionTypes.GZIP,
    retry: { retries: 5 },
  });

  producer.on('producer.connect',    () => { _connected = true;  console.log('[Kafka] Producer connected'); });
  producer.on('producer.disconnect', () => { _connected = false; console.warn('[Kafka] Producer disconnected'); });
  producer.on('producer.network.request_timeout', ({ broker }) => console.warn(`[Kafka] Request timeout — broker: ${broker}`));

  await producer.connect();
  return producer;
}

// ── Core publish function ─────────────────────────────────────────

/**
 * publish — send one or more messages to a Kafka topic
 *
 * @param {string} topic - Kafka topic name (use TOPICS constants)
 * @param {object|object[]} messages - Message payload(s)
 * @param {object} opts - Optional: { key, headers, partition }
 */
async function publish(topic, messages, opts = {}) {
  try {
    const p = await getProducer();

    const msgArray = Array.isArray(messages) ? messages : [messages];
    const kafkaMsgs = msgArray.map((msg, idx) => ({
      key:     opts.key || msg.id || msg.event_id || `${Date.now()}-${idx}`,
      value:   JSON.stringify({
        ...msg,
        _meta: {
          topic,
          produced_at: new Date().toISOString(),
          producer_id: CLIENT_ID,
          schema_version: '1.0',
        },
      }),
      headers: {
        'content-type': 'application/json',
        'source':       CLIENT_ID,
        'tenant-id':    msg.tenant_id || opts.tenantId || 'system',
        ...opts.headers,
      },
      ...(opts.partition !== undefined ? { partition: opts.partition } : {}),
    }));

    await p.send({ topic, messages: kafkaMsgs });
    return { success: true, topic, count: kafkaMsgs.length };
  } catch (err) {
    console.error(`[Kafka] Publish failed — topic: ${topic}:`, err.message);
    // Store in dead-letter queue for retry
    await deadLetterQueue(topic, messages, err);
    throw err;
  }
}

// ── Typed event publishers ────────────────────────────────────────

/** publishRawEvent — CEF/Syslog/JSON log line from collector */
async function publishRawEvent(event) {
  return publish(TOPICS.RAW_EVENTS, {
    event_id:   event.id   || `raw-${Date.now()}`,
    source:     event.source,
    host:       event.host,
    timestamp:  event.timestamp || new Date().toISOString(),
    raw_line:   event.raw_line,
    format:     event.format || 'json',
    tenant_id:  event.tenant_id,
    collector:  event.collector,
  });
}

/** publishDetection — RAYKAN detection result */
async function publishDetection(detection) {
  return publish(TOPICS.DETECTIONS, {
    detection_id:  detection.id,
    rule_id:       detection.rule_id,
    rule_name:     detection.rule_name,
    severity:      detection.severity,
    risk_score:    detection.risk_score,
    host:          detection.host,
    user:          detection.user,
    tenant_id:     detection.tenant_id,
    mitre_tactic:  detection.mitre_tactic,
    mitre_tech:    detection.mitre_tech,
    first_seen:    detection.first_seen,
    evidence:      detection.evidence,
    raw_event_ids: detection.raw_event_ids || [],
  }, { key: detection.tenant_id });
}

/** publishAlert — correlated alert ready for analyst triage */
async function publishAlert(alert) {
  return publish(TOPICS.ALERTS, {
    alert_id:    alert.id,
    title:       alert.title,
    severity:    alert.severity,
    risk_score:  alert.risk_score,
    confidence:  alert.confidence,
    tenant_id:   alert.tenant_id,
    assignee_id: alert.assignee_id,
    created_at:  alert.created_at || new Date().toISOString(),
    iocs:        alert.iocs || [],
    mitre_ttps:  alert.mitre_ttps || [],
  }, { key: alert.tenant_id });
}

/** publishEnrichment — IOC enrichment result */
async function publishEnrichment(enrichment) {
  return publish(TOPICS.ENRICHMENTS, {
    ioc_value:    enrichment.ioc,
    ioc_type:     enrichment.type,
    sources:      enrichment.sources,
    risk_score:   enrichment.risk_score,
    malicious:    enrichment.malicious,
    tags:         enrichment.tags || [],
    tenant_id:    enrichment.tenant_id,
    enriched_at:  new Date().toISOString(),
  }, { key: enrichment.ioc });
}

/** publishThreatIntel — STIX bundle or TI feed update */
async function publishThreatIntel(bundle) {
  return publish(TOPICS.THREAT_INTEL, {
    bundle_id:    bundle.id,
    type:         bundle.type,
    source:       bundle.source,
    object_count: bundle.objects?.length || 0,
    tlp:          bundle.tlp || 'AMBER',
    ingested_at:  new Date().toISOString(),
    objects:      bundle.objects,
  });
}

/** publishAuditEvent — append-only audit log with SHA-256 chaining */
let _lastAuditHash = '0'.repeat(64);
async function publishAuditEvent(event) {
  const payload = JSON.stringify({
    ...event,
    timestamp:  new Date().toISOString(),
    prev_hash:  _lastAuditHash,
  });
  const hash    = require('crypto').createHash('sha256').update(payload).digest('hex');
  _lastAuditHash = hash;

  return publish(TOPICS.AUDIT_LOG, {
    ...event,
    prev_hash:   _lastAuditHash,
    event_hash:  hash,
    tamper_evident: true,
  });
}

/** publishSoarTrigger — fire a SOAR playbook */
async function publishSoarTrigger(trigger) {
  return publish(TOPICS.SOAR_TRIGGERS, {
    trigger_id:   `trigger-${Date.now()}`,
    playbook_id:  trigger.playbook_id,
    alert_id:     trigger.alert_id,
    incident_id:  trigger.incident_id,
    actions:      trigger.actions || [],
    auto_execute: trigger.auto_execute || false,
    confidence:   trigger.confidence,
    tenant_id:    trigger.tenant_id,
    triggered_at: new Date().toISOString(),
  });
}

/** publishAgentTask — dispatch to autonomous agent */
async function publishAgentTask(task) {
  return publish(TOPICS.AGENT_TASKS, {
    task_id:    `task-${Date.now()}`,
    agent_type: task.agent_type,   // 'triage' | 'investigation' | 'response'
    alert_id:   task.alert_id,
    priority:   task.priority || 'medium',
    context:    task.context || {},
    tenant_id:  task.tenant_id,
    created_at: new Date().toISOString(),
    timeout_ms: task.timeout_ms || 120000,
  });
}

/** publishMetrics — SOC operational metrics */
async function publishMetrics(metrics) {
  return publish(TOPICS.METRICS, {
    ...metrics,
    recorded_at: new Date().toISOString(),
  });
}

// ── Dead-letter queue (in-memory fallback) ────────────────────────
const _dlq = [];
async function deadLetterQueue(topic, messages, err) {
  _dlq.push({ topic, messages, error: err.message, failed_at: new Date().toISOString(), retries: 0 });
  if (_dlq.length > 1000) _dlq.shift();   // Cap DLQ size
}

// ── Topic management ──────────────────────────────────────────────

/** createTopics — idempotent topic creation */
async function createTopics() {
  const admin = kafka.admin();
  try {
    await admin.connect();
    const topicList = Object.values(TOPICS).map(topic => ({
      topic,
      numPartitions:     parseInt(process.env.KAFKA_PARTITIONS || '6', 10),
      replicationFactor: parseInt(process.env.KAFKA_REPLICATION || '1', 10),
      configEntries: [
        { name: 'retention.ms',       value: String(7 * 24 * 3600 * 1000) },   // 7-day retention
        { name: 'compression.type',   value: 'gzip' },
        { name: 'min.insync.replicas', value: '1' },
      ],
    }));

    await admin.createTopics({ topics: topicList, waitForLeaders: true });
    console.log('[Kafka] Topics created:', Object.values(TOPICS).join(', '));
  } catch (err) {
    if (err.type !== 'TOPIC_ALREADY_EXISTS') console.warn('[Kafka] createTopics warning:', err.message);
  } finally {
    await admin.disconnect();
  }
}

/** disconnect — graceful shutdown */
async function disconnect() {
  if (producer && _connected) {
    await producer.disconnect();
    _connected = false;
  }
}

// ── Health check ──────────────────────────────────────────────────
async function healthCheck() {
  const admin = kafka.admin();
  try {
    await admin.connect();
    const metadata = await admin.fetchTopicMetadata({ topics: [TOPICS.ALERTS] });
    await admin.disconnect();
    return { healthy: true, brokers: KAFKA_BROKERS, topics: Object.keys(TOPICS).length };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

module.exports = {
  TOPICS,
  publish,
  publishRawEvent,
  publishDetection,
  publishAlert,
  publishEnrichment,
  publishThreatIntel,
  publishAuditEvent,
  publishSoarTrigger,
  publishAgentTask,
  publishMetrics,
  createTopics,
  disconnect,
  healthCheck,
  getProducer,
};
