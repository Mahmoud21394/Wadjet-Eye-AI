/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Scheduler Worker (Phase 4)
 *  backend/workers/scheduler-worker.js
 *
 *  Replaces plain setInterval with a robust job queue model.
 *
 *  Architecture:
 *   - Uses BullMQ if Redis is available (REDIS_URL env var)
 *   - Falls back to an in-process PriorityQueue (no Redis needed)
 *   - All jobs have: retries, backoff, timeout, concurrency limits
 *   - Structured logs for every job event (started, success, failed, retry)
 *
 *  To enable BullMQ (recommended for production):
 *    1. Set REDIS_URL in Render Dashboard
 *    2. npm install bullmq ioredis  (in backend/)
 *
 *  Job types: FEED_SYNC, THREAT_CORRELATION, CVE_ENRICH, ALERT_SCORE,
 *             DASHBOARD_CACHE, EXPOSURE_SCAN
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── Try to load BullMQ ────────────────────────────────────────────
let Queue, Worker, QueueEvents;
try {
  const bullmq = require('bullmq');
  Queue       = bullmq.Queue;
  Worker      = bullmq.Worker;
  QueueEvents = bullmq.QueueEvents;
  console.log('[Scheduler] BullMQ loaded — using Redis-backed job queue');
} catch {
  console.warn('[Scheduler] BullMQ not installed — using in-process fallback queue');
  console.warn('[Scheduler] To enable BullMQ: cd backend && npm install bullmq ioredis');
}

// ── Job definitions ───────────────────────────────────────────────
const JOB_DEFINITIONS = {
  FEED_SYNC: {
    cronExpression: '*/30 * * * *',  // every 30 min
    intervalMs:     30 * 60 * 1000,
    retries:        3,
    backoffMs:      5000,
    timeoutMs:      120000,
    concurrency:    2,
    description:    'Sync threat intelligence feeds (OTX, ThreatFox, etc.)',
  },
  CVE_ENRICH: {
    cronExpression: '0 */2 * * *',   // every 2 hours
    intervalMs:     2 * 60 * 60 * 1000,
    retries:        2,
    backoffMs:      10000,
    timeoutMs:      60000,
    concurrency:    1,
    description:    'Enrich CVEs from NVD and CVSS sources',
  },
  THREAT_CORRELATION: {
    cronExpression: '*/15 * * * *',  // every 15 min
    intervalMs:     15 * 60 * 1000,
    retries:        2,
    backoffMs:      3000,
    timeoutMs:      30000,
    concurrency:    1,
    description:    'Correlate IOCs with threat actors and campaigns',
  },
  DASHBOARD_CACHE: {
    cronExpression: '*/5 * * * *',   // every 5 min
    intervalMs:     5 * 60 * 1000,
    retries:        1,
    backoffMs:      1000,
    timeoutMs:      15000,
    concurrency:    2,
    description:    'Pre-compute dashboard metrics for fast UI load',
  },
  ALERT_SCORE: {
    cronExpression: '*/10 * * * *',  // every 10 min
    intervalMs:     10 * 60 * 1000,
    retries:        2,
    backoffMs:      2000,
    timeoutMs:      30000,
    concurrency:    3,
    description:    'Re-score active alerts with latest threat intelligence',
  },
  EXPOSURE_SCAN: {
    cronExpression: '0 */6 * * *',   // every 6 hours
    intervalMs:     6 * 60 * 60 * 1000,
    retries:        1,
    backoffMs:      30000,
    timeoutMs:      300000,
    concurrency:    1,
    description:    'Scan asset exposure against current threat landscape',
  },
};

// ── In-process fallback queue ─────────────────────────────────────
class InProcessQueue {
  constructor(name) {
    this.name    = name;
    this._jobs   = new Map();
    this._timers = new Map();
    this._handlers = new Map();
    console.log(`[InProcessQueue] Initialised queue: ${name}`);
  }

  registerHandler(jobType, handler) {
    this._handlers.set(jobType, handler);
  }

  schedule(jobType, options = {}) {
    const def = JOB_DEFINITIONS[jobType];
    if (!def) throw new Error(`Unknown job type: ${jobType}`);
    if (this._timers.has(jobType)) return; // already scheduled

    const run = async () => {
      const jobId = `${jobType}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
      const handler = this._handlers.get(jobType);

      if (!handler) {
        console.warn(`[InProcessQueue] No handler for job type: ${jobType}`);
        return;
      }

      const t0 = Date.now();
      console.log(`[Job] START jobType=${jobType} jobId=${jobId}`);

      let attempt = 0;
      let lastErr;

      while (attempt <= def.retries) {
        try {
          const result = await Promise.race([
            handler({ jobId, attempt, data: options.data || {} }),
            new Promise((_, rej) => setTimeout(() => rej(new Error(`Job timeout after ${def.timeoutMs}ms`)), def.timeoutMs)),
          ]);

          const latency = Date.now() - t0;
          console.log(`[Job] COMPLETE jobType=${jobType} jobId=${jobId} attempt=${attempt + 1} latency=${latency}ms result=${JSON.stringify(result || {}).slice(0, 100)}`);
          return;

        } catch (err) {
          lastErr = err;
          attempt++;
          if (attempt <= def.retries) {
            const backoff = def.backoffMs * Math.pow(2, attempt - 1);
            console.warn(`[Job] RETRY jobType=${jobType} jobId=${jobId} attempt=${attempt}/${def.retries} backoff=${backoff}ms error=${err.message}`);
            await new Promise(r => setTimeout(r, backoff));
          }
        }
      }

      const latency = Date.now() - t0;
      console.error(`[Job] FAILED jobType=${jobType} jobId=${jobId} latency=${latency}ms error=${lastErr?.message}`);
    };

    // First run after a brief delay to avoid startup contention
    const startDelay = options.startDelay ?? Math.random() * 10000;
    const timer = setTimeout(() => {
      run();
      this._timers.set(jobType, setInterval(run, def.intervalMs));
    }, startDelay);

    this._timers.set(jobType, timer);
    console.log(`[InProcessQueue] Scheduled ${jobType} every ${def.intervalMs / 1000}s (startDelay=${Math.round(startDelay)}ms)`);
  }

  stop(jobType) {
    const timer = this._timers.get(jobType);
    if (timer) {
      clearInterval(timer);
      clearTimeout(timer);
      this._timers.delete(jobType);
      console.log(`[InProcessQueue] Stopped ${jobType}`);
    }
  }

  stopAll() {
    for (const jobType of this._timers.keys()) this.stop(jobType);
  }

  getStatus() {
    return {
      backend:   'in-process',
      scheduled: [...this._timers.keys()],
      jobs:      JOB_DEFINITIONS,
    };
  }
}

// ── BullMQ-backed queue ───────────────────────────────────────────
class BullMQScheduler {
  constructor(redisUrl) {
    const { Redis } = require('ioredis');
    this.redis      = new Redis(redisUrl, { maxRetriesPerRequest: null });
    this._queues    = new Map();
    this._workers   = new Map();
    console.log(`[BullMQScheduler] Connected to Redis: ${redisUrl.replace(/:[^@]+@/, ':***@')}`);
  }

  _getQueue(name) {
    if (!this._queues.has(name)) {
      const q = new Queue(name, { connection: this.redis });
      this._queues.set(name, q);
    }
    return this._queues.get(name);
  }

  registerHandler(jobType, handler) {
    const def = JOB_DEFINITIONS[jobType];
    if (!def) throw new Error(`Unknown job type: ${jobType}`);

    const worker = new Worker(
      `scheduler-${jobType}`,
      async (job) => {
        console.log(`[BullMQ] START jobType=${jobType} jobId=${job.id} attempt=${job.attemptsMade + 1}`);
        const t0     = Date.now();
        const result = await handler({ jobId: job.id, attempt: job.attemptsMade, data: job.data });
        console.log(`[BullMQ] COMPLETE jobType=${jobType} jobId=${job.id} latency=${Date.now() - t0}ms`);
        return result;
      },
      {
        connection:  this.redis,
        concurrency: def.concurrency,
      }
    );

    worker.on('failed', (job, err) => {
      console.error(`[BullMQ] FAILED jobType=${jobType} jobId=${job?.id} attempt=${job?.attemptsMade} error=${err.message}`);
    });

    this._workers.set(jobType, worker);
  }

  async schedule(jobType, options = {}) {
    const def   = JOB_DEFINITIONS[jobType];
    const queue = this._getQueue(`scheduler-${jobType}`);

    await queue.add(
      jobType,
      options.data || {},
      {
        repeat:   { every: def.intervalMs },
        attempts: def.retries + 1,
        backoff:  { type: 'exponential', delay: def.backoffMs },
        timeout:  def.timeoutMs,
        removeOnComplete: { count: 10 },
        removeOnFail:     { count: 20 },
      }
    );

    console.log(`[BullMQScheduler] Scheduled ${jobType} every ${def.intervalMs / 1000}s via BullMQ`);
  }

  async stopAll() {
    for (const worker of this._workers.values()) await worker.close();
    for (const queue  of this._queues.values())  await queue.close();
    await this.redis.quit();
  }

  getStatus() {
    return {
      backend:   'bullmq',
      scheduled: [...this._queues.keys()],
      jobs:      JOB_DEFINITIONS,
    };
  }
}

// ── Scheduler factory ─────────────────────────────────────────────
let _instance = null;

function createScheduler() {
  if (_instance) return _instance;

  const redisUrl = process.env.REDIS_URL;
  if (redisUrl && Queue) {
    try {
      _instance = new BullMQScheduler(redisUrl);
      return _instance;
    } catch (err) {
      console.warn(`[Scheduler] BullMQ init failed (${err.message}) — falling back to in-process`);
    }
  }

  _instance = new InProcessQueue('wadjet-eye');
  return _instance;
}

module.exports = {
  createScheduler,
  JOB_DEFINITIONS,
  InProcessQueue,
};
