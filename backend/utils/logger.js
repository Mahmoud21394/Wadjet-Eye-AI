/**
 * ═══════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Centralized Backend Logger v1.0
 *  backend/utils/logger.js
 *
 *  Log Levels (ascending verbosity):
 *    ERROR = 0  — API failures, crashes, auth errors (always shown)
 *    WARN  = 1  — Security warnings, CORS blocks, config issues
 *    INFO  = 2  — Startup banners, key lifecycle events only
 *    DEBUG = 3  — Request traces, provider calls, timing data
 *
 *  Production:  CURRENT_LOG_LEVEL = ERROR (0)  → only errors shown
 *  Development: CURRENT_LOG_LEVEL = DEBUG (3)  → all logs shown
 *
 *  Environment override:
 *    LOG_LEVEL=debug  → force DEBUG even in production
 *    LOG_LEVEL=info   → force INFO
 *    LOG_LEVEL=warn   → force WARN
 *    LOG_LEVEL=error  → force ERROR (default production)
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

/* ─── Log Level constants ───────────────────────────────────────── */
const LOG_LEVELS = Object.freeze({
  ERROR: 0,
  WARN:  1,
  INFO:  2,
  DEBUG: 3,
});

/* ─── Determine current log level ───────────────────────────────── */
function _resolveLevel() {
  const envLevel = (process.env.LOG_LEVEL || '').toLowerCase();
  if (envLevel === 'debug')  return LOG_LEVELS.DEBUG;
  if (envLevel === 'info')   return LOG_LEVELS.INFO;
  if (envLevel === 'warn')   return LOG_LEVELS.WARN;
  if (envLevel === 'error')  return LOG_LEVELS.ERROR;
  // Default: production = ERROR only, development = DEBUG
  return process.env.NODE_ENV === 'production' ? LOG_LEVELS.ERROR : LOG_LEVELS.DEBUG;
}

let CURRENT_LOG_LEVEL = _resolveLevel();

/* ─── Module-noise suppression list ─────────────────────────────── */
// Auto-suppress these tokens even in DEBUG when in production
const SUPPRESS_IN_PRODUCTION = [
  'module loaded', 'initialized', 'ready', 'patched',
  'connected', 'scheduler started', 'route registered',
  'middleware registered', 'listening on',
];

/* ─── Deduplication (logOnce) ────────────────────────────────────── */
const _seenMessages = new Set();

function logOnce(level, prefix, msg) {
  const key = `${level}:${prefix}:${msg}`;
  if (_seenMessages.has(key)) return;
  _seenMessages.add(key);
  logger[level](prefix, msg);
}

/* ─── Timestamp helper ──────────────────────────────────────────── */
function _ts() {
  return new Date().toISOString();
}

/* ─── Format args to string ─────────────────────────────────────── */
function _fmt(args) {
  return args.map(a =>
    (typeof a === 'object' && a !== null) ? JSON.stringify(a) : String(a)
  ).join(' ');
}

/* ─── Suppress check ────────────────────────────────────────────── */
function _shouldSuppress(msg) {
  if (CURRENT_LOG_LEVEL >= LOG_LEVELS.DEBUG) return false;  // dev: never suppress
  const lower = msg.toLowerCase();
  return SUPPRESS_IN_PRODUCTION.some(token => lower.includes(token));
}

/* ─── Core logger ────────────────────────────────────────────────── */
const logger = {
  /**
   * Always logs — API failures, crashes, auth errors.
   * Never suppressed regardless of log level.
   */
  error(prefix, ...args) {
    const msg = _fmt(args);
    console.error(`[${_ts()}] ❌ ERROR [${prefix}] ${msg}`);
  },

  /**
   * Logs when CURRENT_LOG_LEVEL >= WARN (1).
   * Security warnings, CORS blocks, missing config.
   */
  warn(prefix, ...args) {
    if (CURRENT_LOG_LEVEL < LOG_LEVELS.WARN) return;
    const msg = _fmt(args);
    if (_shouldSuppress(msg)) return;
    console.warn(`[${_ts()}] ⚠️  WARN  [${prefix}] ${msg}`);
  },

  /**
   * Logs when CURRENT_LOG_LEVEL >= INFO (2).
   * Startup banners, provider connection status, key lifecycle.
   */
  info(prefix, ...args) {
    if (CURRENT_LOG_LEVEL < LOG_LEVELS.INFO) return;
    const msg = _fmt(args);
    if (_shouldSuppress(msg)) return;
    console.log(`[${_ts()}] ℹ️  INFO  [${prefix}] ${msg}`);
  },

  /**
   * Logs when CURRENT_LOG_LEVEL >= DEBUG (3).
   * Request traces, provider calls, per-engine timing.
   * Never appears in production unless LOG_LEVEL=debug forced.
   */
  debug(prefix, ...args) {
    if (CURRENT_LOG_LEVEL < LOG_LEVELS.DEBUG) return;
    const msg = _fmt(args);
    console.log(`[${_ts()}] 🔍 DEBUG [${prefix}] ${msg}`);
  },

  /**
   * Request-scoped debug — only logs if X-Debug-Mode: 1 header
   * is present OR LOG_LEVEL >= DEBUG. Never logged in production
   * unless explicitly enabled per-request.
   */
  req(req, prefix, ...args) {
    const debugHeader = req?.headers?.['x-debug-mode'] === '1';
    if (!debugHeader && CURRENT_LOG_LEVEL < LOG_LEVELS.DEBUG) return;
    const msg = _fmt(args);
    console.log(`[${_ts()}] 🔍 REQ   [${prefix}] ${msg}`);
  },

  /* ── Grouped logging (dev only) ─────────────────────────────── */
  group(label, fn) {
    if (CURRENT_LOG_LEVEL < LOG_LEVELS.DEBUG) { fn(); return; }
    if (typeof console.groupCollapsed === 'function') {
      console.groupCollapsed(`[MalProxy] ${label}`);
      fn();
      console.groupEnd();
    } else {
      fn();
    }
  },

  /* ── Level setters ──────────────────────────────────────────── */
  setLevel(level) {
    if (typeof level === 'string') {
      const k = level.toUpperCase();
      if (k in LOG_LEVELS) { CURRENT_LOG_LEVEL = LOG_LEVELS[k]; return; }
    }
    if (typeof level === 'number' && level >= 0 && level <= 3) {
      CURRENT_LOG_LEVEL = level;
    }
  },

  getLevel()  { return CURRENT_LOG_LEVEL; },
  getLevels() { return LOG_LEVELS; },
  logOnce,

  /* ── Constants re-exported for convenience ───────────────────── */
  LEVELS: LOG_LEVELS,
};

/* ─── Export ────────────────────────────────────────────────────── */
module.exports = logger;
