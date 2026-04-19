/**
 * ══════════════════════════════════════════════════════════
 *  Audit Logs Routes — Read-only access to audit trail
 *  GET  /api/audit          — list with filters
 *  GET  /api/audit/stats    — summary counts per action
 *  GET  /api/audit/:id      — single entry
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase }    = require('../config/supabase');
const { requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── GET /api/audit — list audit logs with filters ── */
router.get('/', requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const {
    page = 1, limit = 50,
    user_id, action, resource,
    from, to, search,
  } = req.query;

  const pageNum  = Math.max(1, parseInt(page, 10)  || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
  const offset   = (pageNum - 1) * limitNum;

  let query = supabase
    .from('audit_logs')
    .select('*', { count: 'exact' })
    .eq('tenant_id', req.tenantId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limitNum - 1);

  if (user_id)  query = query.eq('user_id', user_id);
  if (action)   query = query.eq('action', action.toUpperCase());
  if (resource) query = query.eq('resource', resource);
  if (from)     query = query.gte('created_at', from);
  if (to)       query = query.lte('created_at', to);
  if (search) {
    query = query.or(
      `action.ilike.%${search}%,user_email.ilike.%${search}%,resource.ilike.%${search}%`
    );
  }

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message, 'DB_ERROR');

  res.json({
    data,
    pagination: {
      page:  pageNum,
      limit: limitNum,
      total: count,
      pages: Math.ceil((count || 0) / limitNum),
    },
  });
}));

/* ── GET /api/audit/stats — summary counts (last 30 days) ── */
router.get('/stats', requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('audit_logs')
    .select('action, user_role')
    .eq('tenant_id', req.tenantId)
    .gte('created_at', new Date(Date.now() - 30 * 24 * 3600000).toISOString());

  if (error) throw createError(500, error.message);

  const by_action = data.reduce((acc, row) => {
    acc[row.action] = (acc[row.action] || 0) + 1;
    return acc;
  }, {});

  const by_role = data.reduce((acc, row) => {
    if (row.user_role) acc[row.user_role] = (acc[row.user_role] || 0) + 1;
    return acc;
  }, {});

  res.json({ total_events: data.length, by_action, by_role, period_days: 30 });
}));

/* ── GET /api/audit/:id — single log entry ── */
router.get('/:id', requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw createError(400, 'Invalid ID format');

  const { data, error } = await supabase
    .from('audit_logs')
    .select('*')
    .eq('id', id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !data) throw createError(404, 'Audit log entry not found');
  res.json(data);
}));

module.exports = router;
