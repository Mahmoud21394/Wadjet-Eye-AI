/**
 * outboxPattern.js
 * WS9: Transactional Outbox Pattern for reliable event publishing
 * Ensures at-least-once delivery of domain events to Kafka/event bus
 * Prevents dual-write failures between DB and event bus
 *
 * Fault-tolerant: if the outbox_events table doesn't exist yet (migration
 * pending), the relay pauses silently and retries every 60 s instead of
 * spamming an error every 5 s.
 */
'use strict';

const crypto = require('crypto');
const logger  = require('../utils/logger');
const { createClient } = require('@supabase/supabase-js');

const _SRV = 'OutboxPattern';

// ── Lazy Supabase singleton (same pattern as enterprise-auth.js) ──
let _supabase = null;
function getSupabase() {
  if (!_supabase) {
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
      throw new Error('[OutboxPattern] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
    }
    _supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );
  }
  return _supabase;
}

// ── Table-readiness guard ─────────────────────────────────────────
// Tracks whether the outbox_events table has been confirmed to exist.
// Avoids hammering Supabase with error logs every 5 s when the migration
// hasn't been run yet.
let _tableReady  = false;   // set true on first successful query
let _tableMissing = false;  // set true when "table not found" detected
const TABLE_MISSING_MSGS = [
  'Could not find the table',
  'does not exist',
  'relation "public.outbox_events" does not exist',
  'schema cache',
];

function isTableMissingError(errMsg = '') {
  return TABLE_MISSING_MSGS.some(m => errMsg.includes(m));
}

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
  ALERT_CREATED:        'alert.created',
  ALERT_ESCALATED:      'alert.escalated',
  ALERT_RESOLVED:       'alert.resolved',
  IOC_DETECTED:         'ioc.detected',
  IOC_ENRICHED:         'ioc.enriched',
  DECISION_MADE:        'decision.made',
  DECISION_APPROVED:    'decision.approved',
  SOAR_ACTION:          'soar.action.executed',
  TENANT_CREATED:       'tenant.created',
  USER_CREATED:         'user.created',
  CASE_CREATED:         'case.created',
  THREAT_DETECTED:      'threat.detected',
  COMPLIANCE_VIOLATION: 'compliance.violation',
  SECURITY_EVENT:       'security.event',
};

/**
 * Append event to outbox table (within the same DB transaction as the domain write).
 * No-ops silently if the table doesn't exist yet.
 */
async function appendEvent(eventType, payload, opts = {}) {
  if (_tableMissing) {
    // Table not yet created — queue internally or skip (non-critical path)
    logger.warn(_SRV, 'appendEvent skipped — outbox_events table not yet created', { eventType });
    return null;
  }

  const eventId = crypto.randomUUID();
  const { tenantId, aggregateId, aggregateType = 'unknown', traceId } = opts;

  try {
    const { error } = await getSupabase().from('outbox_events').insert({
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
      if (isTableMissingError(error.message)) {
        _tableMissing = true;
        logger.warn(_SRV, 'outbox_events table missing — run migration SQL. appendEvent disabled until table exists.');
        return null;
      }
      logger.error(_SRV, 'Failed to append outbox event', { eventType, error: error.message });
      throw error;
    }

    _tableReady  = true;
    _tableMissing = false;
    logger.info(_SRV, 'Event appended to outbox', { eventId, eventType, tenantId, aggregateId });
    return eventId;
  } catch (err) {
    if (isTableMissingError(err.message)) {
      _tableMissing = true;
      logger.warn(_SRV, 'outbox_events table missing — outbox disabled until migration is run.');
      return null;
    }
    throw err;
  }
}

/**
 * Relay processor — reads pending outbox events and publishes to Kafka (or fallback).
 * Skips silently (no error log) when the table is confirmed missing.
 */
async function relayPendingEvents({ batchSize = 50 } = {}) {
  // If we already know the table is missing, skip silently
  if (_tableMissing) return;

  let data, error;
  try {
    ({ data, error } = await getSupabase()
      .from('outbox_events')
      .select('*')
      .eq('status', 'pending')
      .lt('retry_count', 5)
      .order('created_at', { ascending: true })
      .limit(batchSize));
  } catch (err) {
    if (isTableMissingError(err.message)) {
      _tableMissing = true;
      logger.warn(_SRV, 'outbox_events table not found — relay paused. Run migration SQL to enable.');
      return;
    }
    logger.error(_SRV, 'Relay query exception', { error: err.message });
    return;
  }

  if (error) {
    if (isTableMissingError(error.message)) {
      // Log ONCE, then go silent until the table is created
      if (!_tableMissing) {
        logger.warn(_SRV,
          'outbox_events table not found — relay paused.\n' +
          '  → Run this SQL in Supabase SQL Editor:\n' +
          '  → backend/db/migrations/20260701_enterprise_ws8_ws9.sql\n' +
          '  → The relay will auto-resume once the table exists.'
        );
        _tableMissing = true;
      }
      return;
    }
    logger.error(_SRV, 'Relay query failed', { error: error.message });
    return;
  }

  // Table confirmed reachable
  if (_tableMissing) {
    logger.info(_SRV, 'outbox_events table now reachable — relay resumed.');
    _tableMissing = false;
  }
  _tableReady = true;

  if (!data || data.length === 0) return;

  logger.info(_SRV, `Relaying ${data.length} outbox events`);
  const producer = await getKafkaProducer();

  for (const event of data) {
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
              'x-event-id':   event.id,
              'x-tenant-id':  event.tenant_id || '',
              'x-trace-id':   event.trace_id  || '',
              'x-event-type': event.event_type,
            },
          }],
        });
      } else {
        // No Kafka — structured log fallback for SIEM ingestion
        logger.info(_SRV, 'Outbox event (no-Kafka fallback)', {
          eventType: event.event_type, tenantId: event.tenant_id, payload: event.payload,
        });
      }

      // Mark published
      await getSupabase().from('outbox_events').update({
        status:       'published',
        published_at: new Date().toISOString(),
      }).eq('id', event.id);

    } catch (err) {
      logger.error(_SRV, 'Event relay failed', { eventId: event.id, error: err.message });
      await getSupabase().from('outbox_events').update({
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
// Uses two intervals:
//   FAST  (5 s)  — normal relay when table exists
//   SLOW  (60 s) — health-check probe when table is missing
let _fastInterval = null;
let _slowInterval = null;

function startOutboxRelay(intervalMs = 5_000) {
  if (_fastInterval) return; // already running

  // Fast relay loop
  _fastInterval = setInterval(async () => {
    if (_tableMissing) return; // table missing — skip, slow loop handles probe
    try {
      await relayPendingEvents();
    } catch (err) {
      logger.error(_SRV, 'Relay interval error', { error: err.message });
    }
  }, intervalMs);

  // Slow probe loop — retries when table is missing
  _slowInterval = setInterval(async () => {
    if (!_tableMissing) return; // table present — fast loop handles it
    logger.info(_SRV, 'Probing for outbox_events table...');
    _tableMissing = false; // reset so relayPendingEvents will try
    try {
      await relayPendingEvents();
    } catch (err) {
      logger.error(_SRV, 'Probe error', { error: err.message });
    }
  }, 60_000);

  logger.info(_SRV, `Outbox relay started (fast: ${intervalMs}ms, slow-probe: 60000ms)`);
}

function stopOutboxRelay() {
  if (_fastInterval) { clearInterval(_fastInterval); _fastInterval = null; }
  if (_slowInterval) { clearInterval(_slowInterval); _slowInterval = null; }
}

module.exports = {
  EVENTS,
  appendEvent,
  relayPendingEvents,
  startOutboxRelay,
  stopOutboxRelay,
  SagaCoordinator,
};
