/**
 * ══════════════════════════════════════════════════════════
 *  Audit Logging Middleware
 *  Records every authenticated API action to audit_logs table
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');

/* Methods that mutate data — always log */
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/* Paths to skip (health checks, static assets) */
const SKIP_PATHS = ['/health', '/favicon'];

/**
 * auditLog middleware — fires AFTER route completes (via res.on('finish'))
 */
function auditLog(req, res, next) {
  if (SKIP_PATHS.some(p => req.path.startsWith(p))) return next();
  if (!MUTATING_METHODS.has(req.method) && !req.path.includes('export')) return next();

  const startTime = Date.now();

  res.on('finish', async () => {
    try {
      const entry = {
        user_id:     req.user?.id       || null,
        tenant_id:   req.tenantId       || null,
        user_email:  req.user?.email    || 'anonymous',
        user_role:   req.user?.role     || 'unknown',
        action:      `${req.method} ${req.route?.path || req.path}`,
        resource:    extractResource(req.path),
        resource_id: req.params?.id     || null,
        method:      req.method,
        path:        req.path,
        status_code: res.statusCode,
        ip_address:  req.ip || req.connection?.remoteAddress,
        user_agent:  req.headers['user-agent'] || '',
        duration_ms: Date.now() - startTime,
        request_body: sanitizeBody(req.body),
        created_at:  new Date().toISOString()
      };

      await supabase.from('audit_logs').insert(entry);
    } catch (err) {
      /* Audit failures must never crash the app */
      console.error('[Audit] Failed to write audit log:', err.message);
    }
  });

  next();
}

/**
 * Write an explicit audit event (for login, logout, sensitive ops)
 */
async function writeAuditEvent(userId, tenantId, action, details = {}) {
  try {
    await supabase.from('audit_logs').insert({
      user_id:    userId,
      tenant_id:  tenantId,
      action,
      resource:   details.resource    || null,
      resource_id:details.resourceId  || null,
      method:     details.method      || 'SYSTEM',
      path:       details.path        || '/system',
      status_code:details.statusCode  || 200,
      ip_address: details.ip          || null,
      request_body: details.body      || null,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Audit] writeAuditEvent failed:', err.message);
  }
}

/* ── Helpers ── */
function extractResource(path) {
  const parts = path.split('/').filter(Boolean);
  return parts[1] || parts[0] || 'unknown'; // /api/alerts/123 → alerts
}

function sanitizeBody(body) {
  if (!body || typeof body !== 'object') return null;
  const safe = { ...body };
  /* Strip sensitive fields before logging */
  ['password', 'token', 'api_key', 'secret', 'authorization'].forEach(k => {
    if (safe[k]) safe[k] = '[REDACTED]';
  });
  return JSON.stringify(safe).substring(0, 1000); // cap at 1KB
}

module.exports = { auditLog, writeAuditEvent };
