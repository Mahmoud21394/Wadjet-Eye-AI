/**
 * ══════════════════════════════════════════════════════════
 *  Alerts Routes — Full CRUD + filtering + realtime push
 *  GET    /api/alerts
 *  GET    /api/alerts/:id
 *  POST   /api/alerts
 *  PATCH  /api/alerts/:id
 *  DELETE /api/alerts/:id
 *  POST   /api/alerts/:id/assign
 *  POST   /api/alerts/:id/escalate
 *  GET    /api/alerts/stats
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase } = require('../config/supabase');
const { requireRole, requirePermission } = require('../middleware/auth');
const { asyncHandler, createError }      = require('../middleware/errorHandler');

/* ── Phase 2: Fusion + UEBA (shadow mode, feature-flagged) ── */
let _fusion = null;
let _ueba   = null;
try {
  _fusion = require('../../js/alert-fusion.js');
} catch (_) {
  console.warn('[alerts] alert-fusion.js not loadable — fusion disabled');
}
try {
  _ueba = require('../../js/ueba.js');
} catch (_) {
  console.warn('[alerts] ueba.js not loadable — UEBA disabled');
}

/* ──────────────────────────────────────────────
   GET /api/alerts — List with filters + pagination
────────────────────────────────────────────── */
router.get('/', asyncHandler(async (req, res) => {
  const {
    page = 1, limit = 25,
    severity, status, type,
    search, from, to, sort = 'created_at', order = 'desc'
  } = req.query;

  const offset = (parseInt(page) - 1) * parseInt(limit);

  let query = supabase
    .from('alerts')
    .select('*', { count: 'exact' })
    .eq('tenant_id', req.tenantId)        // ← Tenant isolation
    .order(sort, { ascending: order === 'asc' })
    .range(offset, offset + parseInt(limit) - 1);

  if (severity) query = query.eq('severity', severity.toUpperCase());
  if (status)   query = query.eq('status', status);
  if (type)     query = query.eq('type', type);
  if (from)     query = query.gte('created_at', from);
  if (to)       query = query.lte('created_at', to);
  if (search) {
    query = query.or(`title.ilike.%${search}%,description.ilike.%${search}%,ioc_value.ilike.%${search}%`);
  }

  const { data, error, count } = await query;

  if (error) throw createError(500, error.message, 'DB_ERROR');

  res.json({
    data,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: count,
      pages: Math.ceil(count / parseInt(limit))
    }
  });
}));

/* ──────────────────────────────────────────────
   GET /api/alerts/stats — Dashboard KPIs
────────────────────────────────────────────── */
router.get('/stats', asyncHandler(async (req, res) => {
  // ROOT-CAUSE FIX v14.0: Wrap with 8s timeout so free-tier cold-start
  // never blocks the entire alerts stats response (causes 401 cascades).
  const queryPromise = supabase
    .from('alerts')
    .select('severity, status')
    .eq('tenant_id', req.tenantId);

  const timeoutPromise = new Promise(resolve =>
    setTimeout(() => resolve({ data: [], error: null, _timedOut: true }), 8_000)
  );

  const { data, error } = await Promise.race([queryPromise, timeoutPromise]);

  if (error) throw createError(500, error.message);

  const stats = {
    total:    data.length,
    critical: data.filter(a => a.severity === 'CRITICAL').length,
    high:     data.filter(a => a.severity === 'HIGH').length,
    medium:   data.filter(a => a.severity === 'MEDIUM').length,
    low:      data.filter(a => a.severity === 'LOW').length,
    open:     data.filter(a => a.status   === 'open').length,
    resolved: data.filter(a => a.status   === 'resolved').length,
    in_progress: data.filter(a => a.status === 'in_progress').length
  };

  res.json(stats);
}));

/* ──────────────────────────────────────────────
   GET /api/alerts/:id
────────────────────────────────────────────── */
router.get('/:id', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('alerts')
    .select(`
      *,
      users!alerts_assigned_to_fkey(id, name, avatar),
      iocs(id, value, type, risk_score)
    `)
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !data) throw createError(404, 'Alert not found');
  res.json(data);
}));

/* ──────────────────────────────────────────────
   POST /api/alerts — Create alert
────────────────────────────────────────────── */
router.post('/', requirePermission('create_alerts'), asyncHandler(async (req, res) => {
  const {
    title, description, severity, type,
    ioc_value, ioc_type, source, mitre_technique,
    affected_assets, metadata
  } = req.body;

  if (!title || !severity) {
    throw createError(400, 'title and severity are required');
  }

  /* ── Phase 2: Pre-insert Fusion + UEBA (shadow mode) ────────────────────
   *  Both modules run BEFORE the Supabase insert so their metadata columns
   *  land in the same row.  Errors are non-fatal: alert insertion never
   *  blocked by fusion failures (fail-open for availability).
   *  Shadow mode (we_fusion_shadow=TRUE) means fusion output is recorded
   *  but NOT yet used to suppress or re-route alerts.
   * ─────────────────────────────────────────────────────────────────────── */
  let fusionResult  = null;
  let uebaResult    = null;
  let fusionColumns = {};

  // ── UEBA scoring (uses entity extracted from alert) ──
  if (_ueba) {
    try {
      const entityId   = (metadata && (metadata.username || metadata.src_ip || metadata.hostname)) ||
                         req.user.id;
      const entityType = metadata && metadata.src_ip ? 'ip' :
                         metadata && metadata.hostname ? 'host' : 'user';
      const features   = _ueba.extractAlertFeatures(req.body);

      uebaResult = await _ueba.scoreEntityEvent({
        supabase,
        tenantId:   req.tenantId,
        entityType,
        entityId:   String(entityId),
        features,
        // alertId not available yet (pre-insert); will be filled via anomaly row
      });
    } catch (uebaErr) {
      console.error('[alerts] UEBA error (non-fatal):', uebaErr.message);
    }
  }

  // ── Alert Fusion: fingerprint + dedup check + confidence score ──
  if (_fusion) {
    try {
      fusionResult = await _fusion.fuseAlert({
        supabase,
        tenantId:  req.tenantId,
        alertBody: req.body,
        uebaResult,
      });
      fusionColumns = fusionResult.alertColumns || {};
    } catch (fusErr) {
      console.error('[alerts] Fusion error (non-fatal):', fusErr.message);
    }
  }

  /* ── Insert alert with fusion metadata columns ── */
  const { data, error } = await supabase
    .from('alerts')
    .insert({
      tenant_id:       req.tenantId,
      title,
      description,
      severity:        severity.toUpperCase(),
      type:            type || 'threat',
      ioc_value,
      ioc_type,
      source:          source || 'manual',
      mitre_technique,
      affected_assets: affected_assets || [],
      metadata:        metadata || {},
      status:          'open',
      created_by:      req.user.id,
      // Phase 2 shadow columns (all default to null / TRUE if fusion didn't run)
      ...fusionColumns,
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);

  /* ── Post-insert Fusion: register fingerprint + build incident ── */
  if (_fusion && fusionResult) {
    _fusion.postFuseAlert({
      supabase,
      tenantId:    req.tenantId,
      alertId:     data.id,
      alertBody:   req.body,
      fusionResult,
    }).catch(err => console.error('[alerts] postFuseAlert error (non-fatal):', err.message));
  }

  /* Emit real-time event to tenant room */
  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('alert:new', data);

  res.status(201).json(data);
}));

/* ──────────────────────────────────────────────
   PATCH /api/alerts/:id — Update alert
────────────────────────────────────────────── */
router.patch('/:id', asyncHandler(async (req, res) => {
  const allowed = ['status','severity','assigned_to','notes','resolution'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  if (updates.status === 'resolved') {
    updates.resolved_at = new Date().toISOString();
    updates.resolved_by = req.user.id;
  }

  const { data, error } = await supabase
    .from('alerts')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Alert not found or update failed');

  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('alert:updated', data);

  res.json(data);
}));

/* ──────────────────────────────────────────────
   DELETE /api/alerts/:id (ADMIN only)
────────────────────────────────────────────── */
router.delete('/:id',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { error } = await supabase
      .from('alerts')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', req.tenantId);

    if (error) throw createError(500, error.message);
    res.status(204).send();
  })
);

/* ──────────────────────────────────────────────
   POST /api/alerts/:id/assign
────────────────────────────────────────────── */
router.post('/:id/assign', asyncHandler(async (req, res) => {
  const { assigned_to } = req.body;

  const { data, error } = await supabase
    .from('alerts')
    .update({ assigned_to, status: 'in_progress', updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Alert not found');

  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('alert:assigned', { alertId: req.params.id, assignedTo: assigned_to });

  res.json(data);
}));

/* ──────────────────────────────────────────────
   POST /api/alerts/:id/escalate
────────────────────────────────────────────── */
router.post('/:id/escalate', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('alerts')
    .update({
      severity: 'CRITICAL',
      status: 'escalated',
      escalated_at: new Date().toISOString(),
      escalated_by: req.user.id,
      updated_at: new Date().toISOString()
    })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Alert not found');

  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('alert:escalated', data);

  res.json(data);
}));

module.exports = router;
