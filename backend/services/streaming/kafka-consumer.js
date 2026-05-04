/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Kafka Consumer Workers (Phase 2)
 *  backend/services/streaming/kafka-consumer.js
 *
 *  Consumer groups for real-time event processing pipeline:
 *  raw-events → normalize → detect → enrich → alert → soar
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Lazy-load kafkajs ─────────────────────────────────────────────
// Matches the pattern in kafka-producer.js — see that file for rationale.
let _KafkaLib = null;
let _kafkaLoadError = null;

function _requireKafka() {
  if (_KafkaLib) return _KafkaLib;
  if (_kafkaLoadError) return null;
  try {
    _KafkaLib = require('kafkajs');
    return _KafkaLib;
  } catch (err) {
    _kafkaLoadError = err.message;
    console.warn('[KafkaConsumer] kafkajs not available:', err.message);
    return null;
  }
}

const { TOPICS } = require('./kafka-producer');

const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || 'kafka:9092').split(',');
const CLIENT_ID     = process.env.KAFKA_CLIENT_ID || 'wadjet-eye-api';

// Build lazily — returns null when kafkajs is unavailable
let kafka = null;
function _getKafkaInstance() {
  if (kafka) return kafka;
  const lib = _requireKafka();
  if (!lib) return null;
  const { Kafka } = lib;
  kafka = new Kafka({
    clientId: `${CLIENT_ID}-consumer`,
    brokers:  KAFKA_BROKERS,
    retry: { retries: 5, initialRetryTime: 300 },
  });
  return kafka;
}

// ── Consumer registry ─────────────────────────────────────────────
const _consumers = new Map();

/**
 * createConsumer — create a named consumer group
 * @param {string} groupId - Consumer group ID
 * @param {string[]} topics - Topics to subscribe to
 * @param {Function} handler - async (topic, partition, message) => void
 */
async function createConsumer(groupId, topics, handler) {
  const ki = _getKafkaInstance();
  if (!ki) throw new Error('[Kafka] kafkajs not available — set KAFKA_BROKERS to enable streaming');
  const consumer = ki.consumer({
    groupId,
    sessionTimeout:    30000,
    heartbeatInterval: 3000,
    maxBytesPerPartition: 1048576,  // 1MB
    retry: { retries: 5 },
  });

  consumer.on('consumer.crash',      ({ payload }) => console.error(`[Kafka Consumer] ${groupId} crashed:`, payload.error));
  consumer.on('consumer.rebalancing', ()            => console.log(`[Kafka Consumer] ${groupId} rebalancing`));

  await consumer.connect();
  await consumer.subscribe({ topics, fromBeginning: false });

  await consumer.run({
    partitionsConsumedConcurrently: 4,
    eachMessage: async ({ topic, partition, message }) => {
      try {
        const value = JSON.parse(message.value.toString());
        await handler(topic, partition, value, message);
      } catch (err) {
        console.error(`[Kafka Consumer] ${groupId} handler error — topic:${topic}:`, err.message);
      }
    },
  });

  _consumers.set(groupId, consumer);
  console.log(`[Kafka Consumer] ${groupId} started — topics: ${topics.join(', ')}`);
  return consumer;
}

// ── Detection Pipeline Consumer ───────────────────────────────────

/**
 * startDetectionPipeline — RAYKAN engine consumer
 * Reads normalized events and runs detection rules in real-time.
 */
async function startDetectionPipeline(raykanEngine) {
  return createConsumer(
    'wadjet-eye-detection',
    [TOPICS.NORMALIZED],
    async (topic, partition, event) => {
      const { publishDetection } = require('./kafka-producer');

      try {
        // Run all active detection rules against the normalized event
        const detections = await raykanEngine.processEvent(event);

        for (const detection of detections) {
          await publishDetection({ ...detection, tenant_id: event.tenant_id });
        }
      } catch (err) {
        console.error('[Detection Pipeline] Error processing event:', err.message);
      }
    }
  );
}

// ── Enrichment Consumer ───────────────────────────────────────────

/**
 * startEnrichmentWorker — reads detections, enriches IOCs in parallel
 */
async function startEnrichmentWorker(enrichmentEngine) {
  return createConsumer(
    'wadjet-eye-enrichment',
    [TOPICS.DETECTIONS],
    async (topic, partition, detection) => {
      const { publishEnrichment } = require('./kafka-producer');

      const iocs = extractIocsFromDetection(detection);
      await Promise.allSettled(
        iocs.map(async (ioc) => {
          try {
            const result = await enrichmentEngine.enrich(ioc.value, ioc.type);
            await publishEnrichment({ ioc: ioc.value, type: ioc.type, ...result, tenant_id: detection.tenant_id });
          } catch (err) {
            console.warn(`[Enrichment Worker] Failed to enrich ${ioc.value}:`, err.message);
          }
        })
      );
    }
  );
}

// ── Alert Correlation Consumer ────────────────────────────────────

/**
 * startAlertCorrelator — groups detections into incidents using BCE
 */
async function startAlertCorrelator(correlationEngine) {
  const _windowBuffer = new Map();  // tenant_id → detection[]
  const WINDOW_MS     = 300000;     // 5-minute correlation window

  return createConsumer(
    'wadjet-eye-correlator',
    [TOPICS.DETECTIONS, TOPICS.ENRICHMENTS],
    async (topic, partition, event) => {
      const { publishAlert } = require('./kafka-producer');
      const tenantId = event.tenant_id;

      if (!_windowBuffer.has(tenantId)) _windowBuffer.set(tenantId, []);
      _windowBuffer.get(tenantId).push(event);

      // Trigger correlation when we have enough events or window expires
      const buffer = _windowBuffer.get(tenantId);
      if (buffer.length >= 10 || (buffer[0]?._meta?.produced_at && Date.now() - new Date(buffer[0]._meta.produced_at) > WINDOW_MS)) {
        try {
          const incidents = await correlationEngine.correlate(buffer);
          for (const incident of incidents) {
            await publishAlert({ ...incident, tenant_id: tenantId });
          }
          _windowBuffer.set(tenantId, []);  // Clear buffer after correlation
        } catch (err) {
          console.error('[Alert Correlator] Correlation error:', err.message);
        }
      }
    }
  );
}

// ── SOAR Consumer ─────────────────────────────────────────────────

/**
 * startSoarWorker — executes playbooks from soar-triggers topic
 */
async function startSoarWorker(soarEngine) {
  return createConsumer(
    'wadjet-eye-soar',
    [TOPICS.SOAR_TRIGGERS],
    async (topic, partition, trigger) => {
      try {
        if (trigger.auto_execute) {
          await soarEngine.executePlaybook(trigger.playbook_id, trigger);
          console.log(`[SOAR Worker] Executed playbook ${trigger.playbook_id} for alert ${trigger.alert_id}`);
        } else {
          // Queue for human approval
          await soarEngine.queueForApproval(trigger);
        }
      } catch (err) {
        console.error('[SOAR Worker] Playbook execution error:', err.message);
      }
    }
  );
}

// ── Agent Task Consumer ───────────────────────────────────────────

/**
 * startAgentWorker — dispatches tasks to autonomous SOC agents
 */
async function startAgentWorker(agentOrchestrator) {
  return createConsumer(
    'wadjet-eye-agents',
    [TOPICS.AGENT_TASKS],
    async (topic, partition, task) => {
      const { publish } = require('./kafka-producer');

      try {
        const result = await agentOrchestrator.dispatch(task);
        // Publish agent result back to results topic
        await publish(TOPICS.AGENT_RESULTS, {
          task_id:    task.task_id,
          agent_type: task.agent_type,
          result,
          completed_at: new Date().toISOString(),
          tenant_id: task.tenant_id,
        });
      } catch (err) {
        console.error(`[Agent Worker] Task ${task.task_id} failed:`, err.message);
      }
    }
  );
}

// ── Metrics Consumer ──────────────────────────────────────────────

/**
 * startMetricsAggregator — computes MTTD/MTTR and analyst metrics
 */
async function startMetricsAggregator(metricsService) {
  return createConsumer(
    'wadjet-eye-metrics',
    [TOPICS.METRICS, TOPICS.ALERTS, TOPICS.INCIDENTS],
    async (topic, partition, event) => {
      await metricsService.record(topic, event);
    }
  );
}

// ── Helpers ───────────────────────────────────────────────────────

function extractIocsFromDetection(detection) {
  const iocs = [];
  if (detection.evidence) {
    const ev = detection.evidence;
    if (ev.src_ip) iocs.push({ value: ev.src_ip, type: 'ip' });
    if (ev.dst_ip) iocs.push({ value: ev.dst_ip, type: 'ip' });
    if (ev.domain) iocs.push({ value: ev.domain, type: 'domain' });
    if (ev.url)    iocs.push({ value: ev.url,    type: 'url' });
    if (ev.hash)   iocs.push({ value: ev.hash,   type: 'hash' });
  }
  return iocs;
}

// ── Graceful shutdown ─────────────────────────────────────────────

async function disconnectAll() {
  await Promise.allSettled(
    Array.from(_consumers.values()).map(c => c.disconnect())
  );
  _consumers.clear();
  console.log('[Kafka Consumers] All disconnected');
}

process.on('SIGTERM', disconnectAll);
process.on('SIGINT',  disconnectAll);

module.exports = {
  createConsumer,
  startDetectionPipeline,
  startEnrichmentWorker,
  startAlertCorrelator,
  startSoarWorker,
  startAgentWorker,
  startMetricsAggregator,
  disconnectAll,
};
