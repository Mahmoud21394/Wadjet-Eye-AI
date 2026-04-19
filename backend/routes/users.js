/**
 * ══════════════════════════════════════════════════════════
 *  User Management Routes
 *  GET    /api/users
 *  GET    /api/users/:id
 *  POST   /api/users           (ADMIN)
 *  PATCH  /api/users/:id       (ADMIN or self)
 *  DELETE /api/users/:id       (ADMIN)
 *  POST   /api/users/:id/reset-password
 *  PATCH  /api/users/:id/status
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase }   = require('../config/supabase');
const { requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { writeAuditEvent } = require('../middleware/audit');

/* ── GET /api/users ── */
router.get('/', requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { tenant_id } = req.query;

  /* SUPER_ADMIN can query any tenant; ADMIN only their own */
  const targetTenant = req.user.role === 'SUPER_ADMIN' && tenant_id
    ? tenant_id
    : req.tenantId;

  const { data, error } = await supabase
    .from('users')
    .select('id, name, email, role, tenant_id, avatar, status, mfa_enabled, last_login, created_at, permissions')
    .eq('tenant_id', targetTenant)
    .order('created_at', { ascending: false });

  if (error) throw createError(500, error.message);
  res.json(data);
}));

/* ── GET /api/users/:id ── */
router.get('/:id', asyncHandler(async (req, res) => {
  const isSelf = req.user.id === req.params.id;
  const isAdmin = ['ADMIN','SUPER_ADMIN'].includes(req.user.role);

  if (!isSelf && !isAdmin) throw createError(403, 'Access denied');

  const { data, error } = await supabase
    .from('users')
    .select('id, name, email, role, tenant_id, avatar, status, mfa_enabled, last_login, permissions, created_at')
    .eq('id', req.params.id)
    .single();

  if (error || !data) throw createError(404, 'User not found');
  res.json(data);
}));

/* ── POST /api/users — Create user ── */
router.post('/', requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { name, email, password, role, tenant_id, permissions } = req.body;

  if (!name || !email || !password) {
    throw createError(400, 'name, email, and password are required');
  }

  /* ADMIN cannot create SUPER_ADMIN */
  if (req.user.role === 'ADMIN' && role === 'SUPER_ADMIN') {
    throw createError(403, 'ADMINs cannot create SUPER_ADMIN accounts');
  }

  const targetTenant = req.user.role === 'SUPER_ADMIN' ? (tenant_id || req.tenantId) : req.tenantId;

  /* Create auth user in Supabase */
  const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
    email: email.trim().toLowerCase(),
    password,
    email_confirm: true
  });

  if (authErr) throw createError(400, authErr.message);

  /* Determine default permissions */
  const defaultPerms = {
    'SUPER_ADMIN': ['all'],
    'ADMIN':       ['all'],
    'ANALYST':     ['read', 'investigate', 'create_alerts', 'manage_iocs'],
    'VIEWER':      ['read']
  };

  /* Create profile in our users table */
  const { data: profile, error: profileErr } = await supabase
    .from('users')
    .insert({
      auth_id:     authData.user.id,
      name:        name.trim(),
      email:       email.trim().toLowerCase(),
      role:        role || 'ANALYST',
      tenant_id:   targetTenant,
      avatar:      name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
      permissions: permissions || defaultPerms[role || 'ANALYST'] || ['read'],
      status:      'active',
      mfa_enabled: false
    })
    .select()
    .single();

  if (profileErr) {
    /* Rollback auth user */
    await supabase.auth.admin.deleteUser(authData.user.id);
    throw createError(500, profileErr.message);
  }

  await writeAuditEvent(req.user.id, req.tenantId, 'USER_CREATED', {
    resource: 'users', resourceId: profile.id,
    body: { email, role, tenant_id: targetTenant }
  });

  res.status(201).json(profile);
}));

/* ── PATCH /api/users/:id ── */
router.patch('/:id', asyncHandler(async (req, res) => {
  const isSelf  = req.user.id === req.params.id;
  const isAdmin = ['ADMIN','SUPER_ADMIN'].includes(req.user.role);
  if (!isSelf && !isAdmin) throw createError(403, 'Access denied');

  const allowed = isSelf
    ? ['name', 'avatar', 'mfa_enabled']          // Self: limited fields
    : ['name', 'role', 'permissions', 'status', 'avatar']; // Admin: full edit

  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  const { data, error } = await supabase
    .from('users')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'User not found');
  res.json(data);
}));

/* ── POST /api/users/:id/reset-password ── */
router.post('/:id/reset-password',
  requireRole(['ADMIN','SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { new_password } = req.body;
    if (!new_password || new_password.length < 8) {
      throw createError(400, 'Password must be at least 8 characters');
    }

    /* Get auth_id */
    const { data: user } = await supabase
      .from('users')
      .select('auth_id, email')
      .eq('id', req.params.id)
      .eq('tenant_id', req.tenantId)
      .single();

    if (!user) throw createError(404, 'User not found');

    const { error } = await supabase.auth.admin.updateUserById(user.auth_id, {
      password: new_password
    });
    if (error) throw createError(500, error.message);

    await writeAuditEvent(req.user.id, req.tenantId, 'PASSWORD_RESET', {
      resource: 'users', resourceId: req.params.id
    });

    res.json({ message: 'Password reset successfully' });
  })
);

/* ── PATCH /api/users/:id/status ── */
router.patch('/:id/status',
  requireRole(['ADMIN','SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { status } = req.body; // 'active' | 'suspended'
    if (!['active','suspended'].includes(status)) {
      throw createError(400, 'status must be active or suspended');
    }

    const { data, error } = await supabase
      .from('users')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', req.params.id)
      .eq('tenant_id', req.tenantId)
      .select()
      .single();

    if (error || !data) throw createError(404, 'User not found');

    await writeAuditEvent(req.user.id, req.tenantId, `USER_${status.toUpperCase()}`, {
      resource: 'users', resourceId: req.params.id
    });

    res.json(data);
  })
);

/* ── DELETE /api/users/:id ── */
router.delete('/:id',
  requireRole(['SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    /* Get auth_id first */
    const { data: user } = await supabase
      .from('users')
      .select('auth_id')
      .eq('id', req.params.id)
      .single();

    if (user?.auth_id) {
      await supabase.auth.admin.deleteUser(user.auth_id);
    }

    await supabase.from('users').delete().eq('id', req.params.id);

    res.status(204).send();
  })
);

module.exports = router;
