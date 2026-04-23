/**
 * ═══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Structured Observability Middleware v1.0
 *  FILE: backend/middleware/observability.js
 *
 *  PURPOSE:
 *  ─────────────────────────────────────────────────────────────────
 *  Provides structured logging and metrics for:
 *    1. Authentication failures (401/403) with code, path, user hint
 *    2. API errors (4xx/5xx) with request context
 *    3. Slow requests (>3s) for performance monitoring
 *    4. Token refresh lifecycle events
 *
 *  USAGE in server.js:
 *    const { authFailureLogger, apiErrorLogger, slowRequestLogger }
 *      = require('./middleware/observability');
 *    app.use(authFailureLogger);   // after verifyToken
 *    app.use(apiErrorLogger);      // in error handler chain
 * ═══════════════════════════════════════════════════════════════════
 */
'use strict';

const logger = require('../utils/logger');

/* ───────────────────────────────────────────────────────────────────
   AUTH FAILURE LOGGER
   Intercepts 401/403 responses and emits structured log lines that
   can be ingested by Render's log drain, Datadog, Logtail, etc.
─────────────────────────────────────────────────────────────────── */
function authFailureLogger(req, res, next) {
  const _write = res.json.bind(res);

  res.json = function interceptedJson(body) {
    const status = res.statusCode;

    if (status === 401 || status === 403) {
      logger.warn('Auth', JSON.stringify({
        event:      status === 401 ? 'AUTH_FAILURE'  : 'AUTH_FORBIDDEN',
        status,
        method:     req.method,
        path:       req.path,
        code:       body?.code   || 'UNKNOWN',
        error:      body?.error  || null,
        user_id:    req.user?.id  || null,
        tenant_id:  req.user?.tenant_id || req.tenantId || null,
        ip:         req.ip,
        request_id: req.id,
        ts:         new Date().toISOString(),
      }));
    }

    return _write(body);
  };

  next();
}

/* ───────────────────────────────────────────────────────────────────
   API ERROR LOGGER
   Logs all 4xx (client errors) and 5xx (server errors) with context.
   Works alongside the global errorHandler in errorHandler.js.
─────────────────────────────────────────────────────────────────── */
function apiErrorLogger(err, req, res, next) {
  const status = err.status || err.statusCode || 500;

  if (status >= 400) {
    const level = status >= 500 ? 'error' : 'warn';
    logger[level]('API', JSON.stringify({
      event:      status >= 500 ? 'SERVER_ERROR' : 'CLIENT_ERROR',
      status,
      method:     req.method,
      path:       req.path,
      code:       err.code  || 'UNKNOWN',
      message:    err.message,
      user_id:    req.user?.id  || null,
      tenant_id:  req.user?.tenant_id || req.tenantId || null,
      ip:         req.ip,
      request_id: req.id,
      ts:         new Date().toISOString(),
    }));
  }

  next(err);
}

/* ───────────────────────────────────────────────────────────────────
   SLOW REQUEST LOGGER
   Detects requests that exceed SLOW_THRESHOLD_MS and logs them.
   Useful for catching cold-start delays and N+1 DB query regressions.
─────────────────────────────────────────────────────────────────── */
const SLOW_THRESHOLD_MS = 3000; // 3 seconds

function slowRequestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    if (duration > SLOW_THRESHOLD_MS) {
      logger.warn('Perf', JSON.stringify({
        event:      'SLOW_REQUEST',
        method:     req.method,
        path:       req.path,
        status:     res.statusCode,
        duration_ms: duration,
        request_id: req.id,
        ts:         new Date().toISOString(),
      }));
    }
  });

  next();
}

/* ───────────────────────────────────────────────────────────────────
   TOKEN REFRESH EVENT LOGGER
   Called explicitly by the /api/auth/refresh handler to log
   token lifecycle events (success, failure, rotation).
─────────────────────────────────────────────────────────────────── */
function logTokenRefreshEvent(event, detail = {}) {
  const level = event === 'REFRESH_SUCCESS' ? 'info' : 'warn';
  logger[level]('TokenRefresh', JSON.stringify({
    event,
    ...detail,
    ts: new Date().toISOString(),
  }));
}

/* ───────────────────────────────────────────────────────────────────
   ROUTE NOT FOUND LOGGER
   Logs 404s that are likely frontend misconfiguration issues.
   (Does NOT log favicon.ico or assets.)
─────────────────────────────────────────────────────────────────── */
function routeNotFoundLogger(req, res, next) {
  if (req.path.startsWith('/api/')) {
    logger.warn('Router', JSON.stringify({
      event:      'ROUTE_NOT_FOUND',
      method:     req.method,
      path:       req.path,
      ip:         req.ip,
      user_agent: req.headers['user-agent']?.slice(0, 80) || null,
      request_id: req.id,
      ts:         new Date().toISOString(),
    }));
  }
  next();
}

module.exports = {
  authFailureLogger,
  apiErrorLogger,
  slowRequestLogger,
  logTokenRefreshEvent,
  routeNotFoundLogger,
};
