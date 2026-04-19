/**
 * ══════════════════════════════════════════════════════════
 *  Tenants Routes — Multi-tenant management
 *  GET    /api/tenants          (SUPER_ADMIN sees all)
 *  GET    /api/tenants/:id
 *  POST   /api/tenants          (SUPER_ADMIN)
 *  PATCH  /api/tenants/:id      (SUPER_ADMIN or own-tenant ADMIN)
 *  DELETE /api/tenants/:id      (SUPER_ADMIN)
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase }    = require('../config/supabase');
const { requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── GET /api/tenants ── */
router.get('/', requireRole(['SUPER_ADMIN', 'ADMIN']), asyncHandler(async (req, res) => {
  let query = supabase
    .from('tenants')
    .select('id, name, short_name, domain, plan, risk_level, active, created_at, settings')
    .order('created_at', { ascending: false });

  if (req.user.role === 'ADMIN') query = query.eq('id', req.tenantId);

  const { data, error } = await query;
  if (error) throw createError(500, error.message, 'DB_ERROR');
  res.json(data);
}));

/* ── GET /api/tenants/:id ── */
router.get('/:id', asyncHandler(async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN' && req.params.id !== req.tenantId) {
    throw createError(403, 'Access denied');
  }

  const { data, error } = await supabase
    .from('tenants')
    .select('*')
    .eq('id', req.params.id)
    .single();

  if (error || !data) throw createError(404, 'Tenant not found');
  res.json(data);
}));

/* ── POST /api/tenants ── */
router.post('/', requireRole(['SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { name, short_name, domain, plan, contact_email, settings } = req.body;

  if (!name || !domain) throw createError(400, 'name and domain are required');

  const validPlans = ['free', 'starter', 'professional', 'enterprise'];
  if (plan && !validPlans.includes(plan)) {
    throw createError(400, `plan must be one of: ${validPlans.join(', ')}`);
  }

  const { data: existing } = await supabase
    .from('tenants').select('id').eq('domain', domain.trim().toLowerCase()).single();
  if (existing) throw createError(409, 'Domain already in use');

  const { data, error } = await supabase
    .from('tenants')
    .insert({
      name:          name.trim(),
      short_name:    short_name?.trim().toUpperCase() || name.slice(0, 4).toUpperCase(),
      domain:        domain.trim().toLowerCase(),
      plan:          plan || 'starter',
      risk_level:    'medium',
      contact_email: contact_email?.trim().toLowerCase(),
      active:        true,
      settings:      settings || { alerts_enabled: true, auto_playbooks: false },
    })
    .select().single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

/* ── PATCH /api/tenants/:id ── */
router.patch('/:id', requireRole(['SUPER_ADMIN', 'ADMIN']), asyncHandler(async (req, res) => {
  if (req.user.role === 'ADMIN' && req.params.id !== req.tenantId) {
    throw createError(403, 'Access denied');
  }

  const superFields = ['name', 'short_name', 'domain', 'plan', 'risk_level', 'active', 'contact_email', 'settings'];
  const adminFields = ['settings', 'contact_email'];
  const allowed     = req.user.role === 'SUPER_ADMIN' ? superFields : adminFields;

  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  if (Object.keys(updates).length === 0) throw createError(400, 'No valid fields provided');

  const { data, error } = await supabase
    .from('tenants')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .select().single();

  if (error || !data) throw createError(404, 'Tenant not found');
  res.json(data);
}));

/* ── DELETE /api/tenants/:id ── */
router.delete('/:id', requireRole(['SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { count } = await supabase
    .from('tenants').select('*', { count: 'exact', head: true }).eq('active', true);

  if ((count || 0) <= 1) throw createError(400, 'Cannot delete the last active tenant');

  const { error } = await supabase.from('tenants').delete().eq('id', req.params.id);
  if (error) throw createError(500, error.message);
  res.status(204).send();
}));

module.exports = router;
