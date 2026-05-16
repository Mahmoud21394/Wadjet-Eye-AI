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

// ══════════════════════════════════════════════════════════════════
//  INFRA-003: Security Observability Metrics (Prometheus/Grafana)
//  Appended to existing observability middleware.
//
//  Adds Prometheus-compatible /metrics endpoint data for:
//  - Security event counters (auth failures, injection attempts, etc.)
//  - Rate limit violations
//  - SSRF attempt counters
//  - Prompt injection detections
//  - Dark web findings (via scraping darkweb-monitor /metrics)
// ══════════════════════════════════════════════════════════════════

/** @type {Map<string, number>} Security event counters */
const _securityCounters = new Map([
  ['auth_failures_total',       0],
  ['auth_missing_token_total',  0],
  ['auth_expired_token_total',  0],
  ['auth_invalid_token_total',  0],
  ['rate_limit_violations_total', 0],
  ['ssrf_attempts_total',       0],
  ['cors_rejections_total',     0],
  ['prompt_injection_total',    0],
  ['ws_auth_failures_total',    0],
  ['agent_mock_decisions_total',0],
  ['agent_injection_blocks_total', 0],
]);

/**
 * incrementSecurityCounter — atomically increment a security metric.
 * @param {string} name - Counter name (must be in _securityCounters)
 * @param {number} [by=1]
 */
function incrementSecurityCounter(name, by = 1) {
  if (_securityCounters.has(name)) {
    _securityCounters.set(name, _securityCounters.get(name) + by);
  }
}

/**
 * getSecurityMetrics — returns Prometheus text format for security counters.
 * Mount this at GET /metrics/security or integrate into existing /metrics.
 * @returns {string}
 */
function getSecurityMetrics() {
  const lines = ['# Wadjet-Eye Security Metrics — generated at ' + new Date().toISOString()];
  for (const [name, value] of _securityCounters.entries()) {
    lines.push(`# HELP ${name} Security event counter`);
    lines.push(`# TYPE ${name} counter`);
    lines.push(`${name} ${value}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * securityMetricsMiddleware — Express middleware that intercepts responses
 * to automatically increment security counters based on HTTP status codes
 * and request context.
 *
 * @type {import('express').RequestHandler}
 */
function securityMetricsMiddleware(req, res, next) {
  const origWriteHead = res.writeHead.bind(res);

  res.writeHead = function (statusCode, ...args) {
    // Auth failures
    if (statusCode === 401) incrementSecurityCounter('auth_failures_total');
    if (statusCode === 429) incrementSecurityCounter('rate_limit_violations_total');

    // Track CORS rejections (403 from CORS middleware)
    if (statusCode === 403 && res.getHeader && !res.getHeader('Access-Control-Allow-Origin')) {
      incrementSecurityCounter('cors_rejections_total');
    }

    // Prompt injection blocks (set by promptGuardMiddleware)
    if (req.promptGuard?.blocked) incrementSecurityCounter('prompt_injection_total');

    return origWriteHead(statusCode, ...args);
  };

  next();
}

/**
 * Grafana Dashboard JSON — pre-configured security dashboard.
 * Returned by GET /api/admin/grafana-dashboard (admin-only endpoint).
 */
const GRAFANA_DASHBOARD = {
  title: 'Wadjet-Eye Security Observability',
  uid:   'wadjet-security-v1',
  panels: [
    { title: 'Auth Failures / min',         expr: 'rate(auth_failures_total[1m]) * 60',         type: 'timeseries' },
    { title: 'Rate Limit Violations / min',  expr: 'rate(rate_limit_violations_total[1m]) * 60', type: 'timeseries' },
    { title: 'SSRF Attempts',                expr: 'ssrf_attempts_total',                         type: 'stat' },
    { title: 'Prompt Injections Blocked',    expr: 'prompt_injection_total',                      type: 'stat' },
    { title: 'CORS Rejections',              expr: 'cors_rejections_total',                       type: 'stat' },
    { title: 'Mock Agent Decisions',         expr: 'agent_mock_decisions_total',                  type: 'stat' },
    { title: 'WS Auth Failures',             expr: 'ws_auth_failures_total',                      type: 'stat' },
    { title: 'Injection Blocks (Agent)',     expr: 'agent_injection_blocks_total',                type: 'stat' },
  ],
};

module.exports = {
  ...module.exports,
  incrementSecurityCounter,
  getSecurityMetrics,
  securityMetricsMiddleware,
  GRAFANA_DASHBOARD,
};
