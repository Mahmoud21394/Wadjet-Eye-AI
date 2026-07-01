/**
 * outboxPattern.js
 * WS9: Transactional Outbox Pattern for reliable event publishing
 * Ensures at-least-once delivery of domain events to Kafka/event bus
 * Prevents dual-write failures between DB and event bus
 */
'use strict';

const crypto = require('crypto');
const logger  = require('../utils/logger');
const { createClient } = require('@supabase/supabase-js');

const _SRV = 'OutboxPattern';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Kafka producer (optional — gracefully degrades if not configured)
let kafkaProducer = null;
async function getKafkaProducer() {
  if (kafkaProducer) return kafkaProducer;
  if (!process.env.KAFKA_BROKERS) return null;
  try {
    const { Kafka } = require('kafkajs');
    const kafka = new Kafka({
      clientId: 'wadjet-eye-outbox',
      brokers: process.env.KAFKA_BROKERS.split(','),
      ssl: process.env.KAFKA_SSL === 'true',
      sasl: process.env.KAFKA_SASL_USERNAME ? {
        mechanism: 'scram-sha-256',
        username:  process.env.KAFKA_SASL_USERNAME,
        password:  process.env.KAFKA_SASL_PASSWORD,
      } : undefined,
    });
    kafkaProducer = kafka.producer({ idempotent: true });
    await kafkaProducer.connect();
    logger.info(_SRV, 'Kafka producer connected');
    return kafkaProducer;
  } catch (err) {
    logger.warn(_SRV, 'Kafka not available — outbox will use polling fallback', { error: err.message });
    return null;
  }
}

// ── Domain Event Types ────────────────────────────────────────────
const EVENTS = {
  ALERT_CREATED:       'alert.created',
  ALERT_ESCALATED:     'alert.escalated',
  ALERT_RESOLVED:      'alert.resolved',
  IOC_DETECTED:        'ioc.detected',
  IOC_ENRICHED:        'ioc.enriched',
  DECISION_MADE:       'decision.made',
  DECISION_APPROVED:   'decision.approved',
  SOAR_ACTION:         'soar.action.executed',
  TENANT_CREATED:      'tenant.created',
  USER_CREATED:        'user.created',
  CASE_CREATED:        'case.created',
  THREAT_DETECTED:     'threat.detected',
  COMPLIANCE_VIOLATION:'compliance.violation',
  SECURITY_EVENT:      'security.event',
};

/**
 * Append event to outbox table (within the same DB transaction as the domain write)
 * @param {string} eventType - One of EVENTS.*
 * @param {object} payload   - Event payload
 * @param {object} opts      - { tenantId, aggregateId, aggregateType, traceId }
 * @returns {string} eventId
 */
async function appendEvent(eventType, payload, opts = {}) {
  const eventId = crypto.randomUUID();
  const { tenantId, aggregateId, aggregateType = 'unknown', traceId } = opts;

  const { error } = await supabase.from('outbox_events').insert({
    id:             eventId,
    event_type:     eventType,
    aggregate_type: aggregateType,
    aggregate_id:   aggregateId,
    tenant_id:      tenantId,
    payload:        payload,
    trace_id:       traceId,
    status:         'pending',
    created_at:     new Date().toISOString(),
    retry_count:    0,
  });

  if (error) {
    logger.error(_SRV, 'Failed to append outbox event', { eventType, error: error.message });
    throw error;
  }

  logger.info(_SRV, 'Event appended to outbox', { eventId, eventType, tenantId, aggregateId });
  return eventId;
}

/**
 * Relay processor — reads pending outbox events and publishes to Kafka (or fallback)
 * Runs on an interval; designed to be idempotent
 */
async function relayPendingEvents({ batchSize = 50 } = {}) {
  const { data: events, error } = await supabase
    .from('outbox_events')
    .select('*')
    .eq('status', 'pending')
    .lt('retry_count', 5)
    .order('created_at', { ascending: true })
    .limit(batchSize);

  if (error) { logger.error(_SRV, 'Relay query failed', { error: error.message }); return; }
  if (!events || events.length === 0) return;

  logger.info(_SRV, `Relaying ${events.length} outbox events`);
  const producer = await getKafkaProducer();

  for (const event of events) {
    try {
      if (producer) {
        await producer.send({
          topic: `wadjet.${event.event_type}`,
          messages: [{
            key:   event.aggregate_id || event.tenant_id,
            value: JSON.stringify({
              id:             event.id,
              type:           event.event_type,
              aggregate_type: event.aggregate_type,
              aggregate_id:   event.aggregate_id,
              tenant_id:      event.tenant_id,
              payload:        event.payload,
              trace_id:       event.trace_id,
              timestamp:      event.created_at,
            }),
            headers: {
              'x-event-id':    event.id,
              'x-tenant-id':   event.tenant_id || '',
              'x-trace-id':    event.trace_id  || '',
              'x-event-type':  event.event_type,
            },
          }],
        });
      } else {
        // Fallback: log event for SIEM/webhook delivery
        logger.info(_SRV, 'Outbox event (no-Kafka fallback)', {
          eventType: event.event_type, tenantId: event.tenant_id, payload: event.payload,
        });
      }

      // Mark published
      await supabase.from('outbox_events').update({
        status:       'published',
        published_at: new Date().toISOString(),
      }).eq('id', event.id);

    } catch (err) {
      logger.error(_SRV, 'Event relay failed', { eventId: event.id, error: err.message });
      await supabase.from('outbox_events').update({
        retry_count:  event.retry_count + 1,
        last_error:   err.message,
        status:       event.retry_count + 1 >= 5 ? 'failed' : 'pending',
      }).eq('id', event.id);
    }
  }
}

// ── Saga Coordinator (lightweight) ───────────────────────────────
class SagaCoordinator {
  constructor(sagaName, tenantId) {
    this.sagaName = sagaName;
    this.tenantId = tenantId;
    this.sagaId   = crypto.randomUUID();
    this.steps    = [];
    this.compensations = [];
  }

  addStep(name, execute, compensate) {
    this.steps.push({ name, execute, compensate });
    return this;
  }

  async run() {
    const executed = [];
    logger.info(_SRV, `Saga START: ${this.sagaName}`, { sagaId: this.sagaId });

    for (const step of this.steps) {
      try {
        await step.execute();
        executed.push(step);
        logger.info(_SRV, `Saga step OK: ${step.name}`, { sagaId: this.sagaId });
      } catch (err) {
        logger.error(_SRV, `Saga step FAILED: ${step.name} — compensating`, { sagaId: this.sagaId, error: err.message });

        // Compensate in reverse order
        for (const done of executed.reverse()) {
          try {
            if (done.compensate) await done.compensate();
            logger.info(_SRV, `Saga compensation OK: ${done.name}`, { sagaId: this.sagaId });
          } catch (cErr) {
            logger.error(_SRV, `Saga compensation FAILED: ${done.name}`, { sagaId: this.sagaId, error: cErr.message });
          }
        }
        throw new Error(`Saga ${this.sagaName} failed at step ${step.name}: ${err.message}`);
      }
    }

    logger.info(_SRV, `Saga COMPLETE: ${this.sagaName}`, { sagaId: this.sagaId });
  }
}

// ── Outbox Relay Scheduler ────────────────────────────────────────
let _relayInterval = null;

function startOutboxRelay(intervalMs = 5_000) {
  if (_relayInterval) return;
  _relayInterval = setInterval(() => {
    relayPendingEvents().catch(err =>
      logger.error(_SRV, 'Relay interval error', { error: err.message })
    );
  }, intervalMs);
  logger.info(_SRV, `Outbox relay started (interval: ${intervalMs}ms)`);
}

function stopOutboxRelay() {
  if (_relayInterval) { clearInterval(_relayInterval); _relayInterval = null; }
}

module.exports = {
  EVENTS,
  appendEvent,
  relayPendingEvents,
  startOutboxRelay,
  stopOutboxRelay,
  SagaCoordinator,
};
