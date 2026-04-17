/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Structured Logger (Phase 5)
 *  backend/middleware/logger.js
 *
 *  Provides structured JSON logging with:
 *   - Request correlation IDs (req.id)
 *   - Log levels: debug, info, warn, error
 *   - Automatic secret masking (API keys, JWT tokens)
 *   - Response time logging middleware
 *   - Provider/job/socket event helpers
 *
 *  Uses pino if installed, falls back to JSON-to-console.
 *  To enable pino: cd backend && npm install pino pino-pretty
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Try to load pino ──────────────────────────────────────────────
let pino;
try {
  pino = require('pino');
  console.log('[Logger] pino loaded — structured logging active');
} catch {
  console.warn('[Logger] pino not installed — using JSON console logger');
  console.warn('[Logger] To enable pino: cd backend && npm install pino pino-pretty');
}

// ── Secret masking patterns ───────────────────────────────────────
const SECRET_PATTERNS = [
  { pattern: /(sk-proj-[A-Za-z0-9_-]{20})[A-Za-z0-9_-]*/g,   mask: '$1***' },
  { pattern: /(sk-ant-api03-[A-Za-z0-9_-]{10})[A-Za-z0-9_-]*/g, mask: '$1***' },
  { pattern: /(AIzaSy[A-Za-z0-9_-]{10})[A-Za-z0-9_-]*/g,      mask: '$1***' },
  { pattern: /(sk-[a-f0-9]{8})[a-f0-9]*/g,                    mask: '$1***' },
  { pattern: /(Bearer\s+[A-Za-z0-9._-]{10})[A-Za-z0-9._-]*/g, mask: '$1***' },
  { pattern: /("password"\s*:\s*")[^"]+/g,                     mask: '$1[REDACTED]' },
  { pattern: /("api_key"\s*:\s*")[^"]+/g,                      mask: '$1[REDACTED]' },
];

function _maskSecrets(str) {
  if (typeof str !== 'string') str = JSON.stringify(str);
  for (const { pattern, mask } of SECRET_PATTERNS) {
    str = str.replace(pattern, mask);
  }
  return str;
}

// ── Pino-based logger ─────────────────────────────────────────────
function _createPinoLogger() {
  const isProd = process.env.NODE_ENV === 'production';
  return pino({
    level:     process.env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
    base:      { pid: process.pid, service: 'wadjet-eye-backend' },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact:    {
      paths:   ['*.password', '*.api_key', '*.apiKey', '*.token', '*.secret'],
      censor:  '[REDACTED]',
    },
    ...(isProd ? {} : { transport: { target: 'pino-pretty', options: { colorize: true } } }),
  });
}

// ── Console fallback logger ───────────────────────────────────────
function _createConsoleLogger() {
  const LEVEL_ORDER = { debug: 0, info: 1, warn: 2, error: 3 };
  const minLevel    = process.env.LOG_LEVEL || 'info';
  const minNum      = LEVEL_ORDER[minLevel] ?? 1;

  function _log(level, obj, msg) {
    if (LEVEL_ORDER[level] < minNum) return;
    const entry = {
      level,
      time:    new Date().toISOString(),
      service: 'wadjet-eye-backend',
      pid:     process.pid,
      ...(typeof obj === 'object' ? obj : { msg: obj }),
      ...(msg !== undefined ? { msg } : {}),
    };
    const safe = _maskSecrets(JSON.stringify(entry));
    // eslint-disable-next-line no-console
    (level === 'error' ? console.error : level === 'warn' ? console.warn : console.log)(safe);
  }

  return {
    debug: (o, m) => _log('debug', o, m),
    info:  (o, m) => _log('info',  o, m),
    warn:  (o, m) => _log('warn',  o, m),
    error: (o, m) => _log('error', o, m),
    child: (bindings) => {
      const childLog = { ..._createConsoleLogger() };
      const origInfo = childLog.info.bind(childLog);
      ['debug','info','warn','error'].forEach(lvl => {
        const orig = childLog[lvl].bind(childLog);
        childLog[lvl] = (o, m) => orig(typeof o === 'object' ? { ...bindings, ...o } : { ...bindings, msg: o }, m);
      });
      return childLog;
    },
  };
}

// ── Create logger instance ────────────────────────────────────────
const logger = pino ? _createPinoLogger() : _createConsoleLogger();

// ── Request logging middleware ────────────────────────────────────
/**
 * requestLogger — logs every request with method, path, status, latency, reqId
 */
function requestLogger(req, res, next) {
  const t0     = Date.now();
  const reqId  = req.id || '-';
  const method = req.method;
  const path   = req.path;
  const ip     = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '-';

  res.on('finish', () => {
    const latency = Date.now() - t0;
    const log     = res.statusCode >= 500 ? logger.error.bind(logger) :
                    res.statusCode >= 400 ? logger.warn.bind(logger)  :
                    logger.info.bind(logger);

    log({
      event:      'HTTP_REQUEST',
      reqId,
      method,
      path,
      status:     res.statusCode,
      latency_ms: latency,
      ip,
      userAgent:  req.headers['user-agent']?.slice(0, 100),
    });
  });

  next();
}

// ── Specialized event loggers ─────────────────────────────────────

const providerLogger = logger.child ? logger.child({ component: 'provider' }) : logger;
const schedulerLogger = logger.child ? logger.child({ component: 'scheduler' }) : logger;
const wsLogger = logger.child ? logger.child({ component: 'websocket' }) : logger;
const authLogger = logger.child ? logger.child({ component: 'auth' }) : logger;

module.exports = {
  logger,
  requestLogger,
  maskSecrets: _maskSecrets,
  providerLogger,
  schedulerLogger,
  wsLogger,
  authLogger,
};
