/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — RBAC Administration API v3.0
 *  FILE: backend/routes/rbac.js
 *
 *  Full RBAC backend with:
 *    - Role schema (Admin, SOC L1/L2/L3, IR, Viewer, + custom)
 *    - Permission matrix (granular permissions per module)
 *    - User-role assignment
 *    - Audit logging for all RBAC changes
 *    - Access enforcement middleware
 *
 *  Endpoints:
 *    GET    /api/rbac/roles           — List all roles
 *    POST   /api/rbac/roles           — Create role
 *    GET    /api/rbac/roles/:id       — Get role detail
 *    PUT    /api/rbac/roles/:id       — Update role + permissions
 *    DELETE /api/rbac/roles/:id       — Delete role
 *    GET    /api/rbac/permissions     — Permission matrix
 *    POST   /api/rbac/assign          — Assign role to user
 *    GET    /api/rbac/users           — List users with roles
 *    GET    /api/rbac/audit-log       — RBAC audit log
 *    GET    /api/rbac/stats           — RBAC statistics
 *    POST   /api/rbac/check           — Check if user has permission
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express = require('express');
const router  = express.Router();
const { asyncHandler, createError } = require('../middleware/errorHandler');

// Supabase
let supabase;
try { ({ supabase } = require('../config/supabase')); } catch (_) {}

// Auth middleware
let verifyToken, requireRole;
try {
  ({ verifyToken, requireRole } = require('../middleware/auth'));
} catch (_) {
  verifyToken = (req, res, next) => next();
  requireRole = () => (req, res, next) => next();
}

// Audit middleware
let writeAuditEvent;
try { ({ writeAuditEvent } = require('../middleware/audit')); } catch (_) { writeAuditEvent = async () => {}; }

// ─────────────────────────────────────────────────────────────────────
//  DEFAULT ROLE SCHEMA
// ─────────────────────────────────────────────────────────────────────
const DEFAULT_ROLES = [
  {
    id: 'super_admin', name: 'Super Admin', slug: 'super_admin', color: '#ef4444',
    description: 'Full platform access. Can manage all tenants, users, billing and system config.',
    permissions: ['*'],
    modules: ['*'],
    level: 10,
    isSystem: true,
  },
  {
    id: 'admin', name: 'Admin', slug: 'admin', color: '#f97316',
    description: 'Tenant-level admin. Can manage users within their tenant and access all intel modules.',
    permissions: ['read','write','delete','export','manage_users','manage_roles','manage_settings'],
    modules: ['dashboard','alerts','iocs','cases','reports','users','settings','collectors'],
    level: 9,
    isSystem: true,
  },
  {
    id: 'soc_l3', name: 'SOC Analyst L3', slug: 'soc_l3', color: '#dc2626',
    description: 'Senior SOC analyst. Full investigation, detection engineering, threat hunting.',
    permissions: ['read','write','delete','export','investigate','hunt','build_detections'],
    modules: ['dashboard','alerts','iocs','cases','reports','threat-hunting','detection-engineering','playbooks','mitre-attack'],
    level: 7,
    isSystem: true,
  },
  {
    id: 'soc_l2', name: 'SOC Analyst L2', slug: 'soc_l2', color: '#3b82f6',
    description: 'Tier 2 SOC analyst. Triage + investigation, can escalate to L3.',
    permissions: ['read','write','export','investigate'],
    modules: ['dashboard','alerts','iocs','cases','reports','playbooks','mitre-attack'],
    level: 6,
    isSystem: true,
  },
  {
    id: 'soc_l1', name: 'SOC Analyst L1', slug: 'soc_l1', color: '#22d3ee',
    description: 'Tier 1 SOC analyst. Alert triage, basic investigation, escalation.',
    permissions: ['read','write'],
    modules: ['dashboard','alerts','cases','playbooks'],
    level: 5,
    isSystem: true,
  },
  {
    id: 'ir', name: 'Incident Responder', slug: 'ir', color: '#7c3aed',
    description: 'Incident response specialist. Full forensic and containment access.',
    permissions: ['read','write','delete','export','investigate','contain'],
    modules: ['dashboard','alerts','iocs','cases','reports','threat-hunting','playbooks','forensics'],
    level: 7,
    isSystem: true,
  },
  {
    id: 'analyst', name: 'Analyst', slug: 'analyst', color: '#2563eb',
    description: 'Security analyst with read/write access to intel modules.',
    permissions: ['read','write','export','investigate'],
    modules: ['dashboard','alerts','iocs','cases','reports','mitre-attack'],
    level: 5,
    isSystem: false,
  },
  {
    id: 'threat_hunter', name: 'Threat Hunter', slug: 'threat_hunter', color: '#a855f7',
    description: 'Dedicated threat hunting analyst.',
    permissions: ['read','write','export','investigate','hunt'],
    modules: ['dashboard','alerts','iocs','cases','threat-hunting','detection-engineering','mitre-attack'],
    level: 6,
    isSystem: false,
  },
  {
    id: 'viewer', name: 'Viewer', slug: 'viewer', color: '#22c55e',
    description: 'Read-only access. Can view dashboards and reports only.',
    permissions: ['read'],
    modules: ['dashboard','reports'],
    level: 1,
    isSystem: true,
  },
  {
    id: 'executive', name: 'Executive', slug: 'executive', color: '#f59e0b',
    description: 'C-level executive dashboard access only.',
    permissions: ['read'],
    modules: ['dashboard','reports'],
    level: 2,
    isSystem: true,
  },
  {
    id: 'auditor', name: 'Auditor', slug: 'auditor', color: '#ec4899',
    description: 'Compliance and audit access. Read-only with audit log access.',
    permissions: ['read','audit'],
    modules: ['dashboard','reports','audit-log','settings'],
    level: 3,
    isSystem: true,
  },
];

// ─────────────────────────────────────────────────────────────────────
//  ALL AVAILABLE PERMISSIONS
// ─────────────────────────────────────────────────────────────────────
const ALL_PERMISSIONS = {
  read:              { label: 'Read', description: 'View resources',     category: 'data' },
  write:             { label: 'Write', description: 'Create and update resources', category: 'data' },
  delete:            { label: 'Delete', description: 'Delete resources', category: 'data' },
  export:            { label: 'Export', description: 'Export data',      category: 'data' },
  investigate:       { label: 'Investigate', description: 'Run AI investigations', category: 'investigation' },
  hunt:              { label: 'Threat Hunt', description: 'Run threat hunts', category: 'investigation' },
  build_detections:  { label: 'Build Detections', description: 'Create Sigma/KQL/SPL rules', category: 'engineering' },
  contain:           { label: 'Contain', description: 'Execute containment actions', category: 'response' },
  manage_users:      { label: 'Manage Users', description: 'Create/edit/delete users', category: 'admin' },
  manage_roles:      { label: 'Manage Roles', description: 'Create/edit roles', category: 'admin' },
  manage_settings:   { label: 'Manage Settings', description: 'Edit platform settings', category: 'admin' },
  audit:             { label: 'Audit Access', description: 'View audit logs', category: 'compliance' },
};

// ─────────────────────────────────────────────────────────────────────
//  ALL MODULES
// ─────────────────────────────────────────────────────────────────────
const ALL_MODULES = [
  'dashboard', 'alerts', 'iocs', 'cases', 'reports', 'users', 'settings',
  'collectors', 'playbooks', 'threat-hunting', 'detection-engineering',
  'mitre-attack', 'news', 'cve-intel', 'ai-analyst', 'siem', 'soar',
  'threat-actors', 'dark-web', 'geo-threats', 'audit-log', 'forensics',
];

// ─────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────

async function _getRoles(tenantId) {
  if (!supabase) return DEFAULT_ROLES;

  const { data, error } = await supabase
    .from('roles')
    .select('*')
    .or(`tenant_id.eq.${tenantId},is_system.eq.true`)
    .order('level', { ascending: false });

  if (error || !data || data.length === 0) {
    return DEFAULT_ROLES; // fallback
  }
  return data;
}

async function _auditRBACChange(userId, tenantId, action, resource, details) {
  try {
    if (supabase) {
      await supabase.from('audit_logs').insert({
        user_id:   userId,
        tenant_id: tenantId,
        action:    `RBAC_${action}`,
        resource,
        details,
        created_at: new Date().toISOString(),
      });
    }
  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────────────────────────────

/* ── GET /api/rbac/health — Public health/status endpoint (no auth required) ──
   Returns the default role schema, all permissions, and all modules.
   Useful for testing RBAC availability and for the frontend to pre-load
   role metadata before the user authenticates.                              */
router.get('/health', asyncHandler(async (req, res) => {
  res.json({
    status:       'operational',
    roles:        DEFAULT_ROLES.map(r => ({ id: r.id, name: r.name, slug: r.slug, level: r.level, color: r.color })),
    permissions:  Object.keys(ALL_PERMISSIONS),
    modules:      ALL_MODULES,
    schemaVersion: '3.0',
    timestamp:    new Date().toISOString(),
  });
}));

/* ── GET /api/rbac/roles ── */
router.get('/roles', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;
  const roles = await _getRoles(tenantId);
  res.json({ roles, total: roles.length });
}));

/* ── POST /api/rbac/roles — Create custom role ── */
router.post('/roles', verifyToken, asyncHandler(async (req, res) => {
  const userRole = req.user?.role || '';
  if (!['SUPER_ADMIN', 'ADMIN', 'super_admin', 'admin'].includes(userRole)) {
    throw createError(403, 'Only ADMIN or SUPER_ADMIN can create roles');
  }

  const { name, slug, description, permissions = [], modules = [], color = '#6b7280', level = 5 } = req.body;

  if (!name || !slug) throw createError(400, 'name and slug are required');

  // Validate permissions
  const validPerms = permissions.filter(p => Object.keys(ALL_PERMISSIONS).includes(p) || p === '*');
  const validModules = modules.filter(m => ALL_MODULES.includes(m) || m === '*');

  const tenantId = req.tenantId || req.user?.tenant_id;

  let savedRole;
  if (supabase) {
    const { data, error } = await supabase
      .from('roles')
      .insert({
        name,
        slug: slug.toLowerCase().replace(/\s+/g, '_'),
        description,
        permissions: validPerms,
        modules:     validModules,
        color,
        level,
        tenant_id:   tenantId,
        is_system:   false,
        created_by:  req.user?.id,
      })
      .select('*')
      .single();

    if (error) throw createError(400, error.message);
    savedRole = data;
  } else {
    savedRole = { id: `custom-${Date.now()}`, name, slug, description, permissions: validPerms, modules: validModules, color, level, isSystem: false };
  }

  await _auditRBACChange(req.user?.id, tenantId, 'CREATE_ROLE', 'roles', { roleName: name, slug, permissions: validPerms });

  res.status(201).json({ role: savedRole });
}));

/* ── GET /api/rbac/roles/:id ── */
router.get('/roles/:id', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;

  // Check default roles first
  const defaultRole = DEFAULT_ROLES.find(r => r.id === req.params.id || r.slug === req.params.id);
  if (defaultRole) return res.json(defaultRole);

  if (!supabase) throw createError(404, 'Role not found');

  const { data, error } = await supabase
    .from('roles')
    .select('*')
    .or(`id.eq.${req.params.id},slug.eq.${req.params.id}`)
    .or(`tenant_id.eq.${tenantId},is_system.eq.true`)
    .single();

  if (error || !data) throw createError(404, 'Role not found');
  res.json(data);
}));

/* ── PUT /api/rbac/roles/:id — Update role + permissions ── */
router.put('/roles/:id', verifyToken, asyncHandler(async (req, res) => {
  const userRole = req.user?.role || '';
  if (!['SUPER_ADMIN', 'ADMIN', 'super_admin', 'admin'].includes(userRole)) {
    throw createError(403, 'Only ADMIN or SUPER_ADMIN can update roles');
  }

  const { name, description, permissions, modules, color, level } = req.body;
  const tenantId = req.tenantId || req.user?.tenant_id;

  if (!supabase) {
    return res.json({ message: 'Role updated (in-memory only — DB not configured)', id: req.params.id });
  }

  const updates = {};
  if (name)        updates.name        = name;
  if (description) updates.description = description;
  if (permissions) updates.permissions = permissions.filter(p => Object.keys(ALL_PERMISSIONS).includes(p) || p === '*');
  if (modules)     updates.modules     = modules.filter(m => ALL_MODULES.includes(m) || m === '*');
  if (color)       updates.color       = color;
  if (level !== undefined) updates.level = level;
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('roles')
    .update(updates)
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .select('*')
    .single();

  if (error) throw createError(400, error.message);

  await _auditRBACChange(req.user?.id, tenantId, 'UPDATE_ROLE', 'roles', { roleId: req.params.id, updates });

  res.json({ role: data });
}));

/* ── DELETE /api/rbac/roles/:id ── */
router.delete('/roles/:id', verifyToken, asyncHandler(async (req, res) => {
  const userRole = req.user?.role || '';
  if (!['SUPER_ADMIN', 'ADMIN', 'super_admin', 'admin'].includes(userRole)) {
    throw createError(403, 'Only ADMIN or SUPER_ADMIN can delete roles');
  }

  const tenantId = req.tenantId || req.user?.tenant_id;

  // Cannot delete system roles
  const systemRole = DEFAULT_ROLES.find(r => r.id === req.params.id && r.isSystem);
  if (systemRole) throw createError(403, 'Cannot delete system roles');

  if (supabase) {
    // Check if role has users assigned
    const { count } = await supabase
      .from('users')
      .select('id', { count: 'exact' })
      .eq('role', req.params.id)
      .eq('tenant_id', tenantId);

    if (count > 0) {
      throw createError(409, `Cannot delete role — ${count} user(s) have this role assigned`);
    }

    const { error } = await supabase
      .from('roles')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', tenantId)
      .eq('is_system', false);

    if (error) throw createError(400, error.message);
  }

  await _auditRBACChange(req.user?.id, tenantId, 'DELETE_ROLE', 'roles', { roleId: req.params.id });
  res.json({ success: true, message: 'Role deleted.' });
}));

/* ── GET /api/rbac/permissions — Full permission matrix ── */
router.get('/permissions', verifyToken, asyncHandler(async (req, res) => {
  const matrix = [];

  for (const [key, perm] of Object.entries(ALL_PERMISSIONS)) {
    const roleAssignments = {};
    for (const role of DEFAULT_ROLES) {
      roleAssignments[role.slug] = role.permissions.includes('*') || role.permissions.includes(key);
    }
    matrix.push({
      id:          key,
      label:       perm.label,
      description: perm.description,
      category:    perm.category,
      roles:       roleAssignments,
    });
  }

  res.json({
    matrix,
    permissions: ALL_PERMISSIONS,
    modules:     ALL_MODULES,
    roles:       DEFAULT_ROLES.map(r => ({ id: r.id, name: r.name, slug: r.slug, level: r.level })),
  });
}));

/* ── POST /api/rbac/assign — Assign role to user ── */
router.post('/assign', verifyToken, asyncHandler(async (req, res) => {
  const userRole = req.user?.role || '';
  if (!['SUPER_ADMIN', 'ADMIN', 'super_admin', 'admin'].includes(userRole)) {
    throw createError(403, 'Only ADMIN or SUPER_ADMIN can assign roles');
  }

  const { userId, roleId, permissions } = req.body;
  if (!userId || !roleId) throw createError(400, 'userId and roleId are required');

  const tenantId = req.tenantId || req.user?.tenant_id;

  // Validate target role exists
  const targetRole = DEFAULT_ROLES.find(r => r.id === roleId || r.slug === roleId);

  // Prevent ADMIN from assigning SUPER_ADMIN
  if (userRole === 'admin' && (roleId === 'super_admin' || roleId === 'SUPER_ADMIN')) {
    throw createError(403, 'Admins cannot assign Super Admin role');
  }

  if (supabase) {
    const updates = {
      role:       roleId,
      updated_at: new Date().toISOString(),
    };
    if (permissions) updates.permissions = permissions;

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', userId)
      .eq('tenant_id', tenantId)
      .select('id, name, email, role')
      .single();

    if (error) throw createError(400, error.message);

    await _auditRBACChange(req.user?.id, tenantId, 'ASSIGN_ROLE', 'users', {
      targetUserId: userId, targetUser: data?.name || data?.email,
      newRole: roleId, previousRole: data?.role,
    });

    res.json({
      success: true,
      user: data,
      assignedRole: targetRole?.name || roleId,
      message: `Role ${roleId} assigned to user ${userId}`,
    });
  } else {
    res.json({ success: true, message: `Role ${roleId} assigned (in-memory — DB not configured)` });
  }
}));

/* ── GET /api/rbac/users — Users with roles ── */
router.get('/users', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;
  const { role, page = 1, limit = 20 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  if (!supabase) {
    // Return mock data
    return res.json({
      users: [
        { id: '1', name: 'Admin User',  email: 'admin@wadjet.ai',   role: 'admin',   status: 'active' },
        { id: '2', name: 'SOC Analyst', email: 'analyst@wadjet.ai', role: 'soc_l2',  status: 'active' },
        { id: '3', name: 'Viewer',      email: 'viewer@wadjet.ai',  role: 'viewer',  status: 'active' },
      ],
      total: 3, page: 1, limit: 20,
    });
  }

  let q = supabase
    .from('users')
    .select('id, name, email, role, status, avatar, last_login, created_at, permissions, mfa_enabled', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (role) q = q.eq('role', role);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  // Enrich with role details
  const allRoles = await _getRoles(tenantId);
  const usersWithRoles = (data || []).map(u => {
    const roleDetail = allRoles.find(r => r.id === u.role || r.slug === u.role?.toLowerCase());
    return {
      ...u,
      roleDetail: roleDetail ? {
        name:        roleDetail.name,
        color:       roleDetail.color,
        level:       roleDetail.level,
        permissions: roleDetail.permissions,
      } : null,
    };
  });

  res.json({
    users:      usersWithRoles,
    total:      count || 0,
    page:       parseInt(page),
    limit:      parseInt(limit),
    totalPages: Math.ceil((count || 0) / parseInt(limit)),
  });
}));

/* ── GET /api/rbac/audit-log — RBAC audit log ── */
router.get('/audit-log', verifyToken, asyncHandler(async (req, res) => {
  const userRole = req.user?.role || '';
  if (!['SUPER_ADMIN', 'ADMIN', 'AUDITOR', 'super_admin', 'admin', 'auditor'].includes(userRole)) {
    throw createError(403, 'Access denied. Requires ADMIN or AUDITOR role.');
  }

  const tenantId = req.tenantId || req.user?.tenant_id;
  const { page = 1, limit = 50, action } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  if (!supabase) {
    // Return sample audit log using Shape A field names (consistent with Supabase DB format)
    // Shape A: { id, user_name, action, resource, details, created_at, ip, severity }
    return res.json({
      events: [
        { id: 'AL001', user_name: 'Admin',   action: 'RBAC_CREATE_ROLE',  resource: 'roles',  details: { info: 'Created role SOC L3' },           created_at: new Date(Date.now() - 60000).toISOString(),  ip: '127.0.0.1', severity: 'info' },
        { id: 'AL002', user_name: 'Admin',   action: 'RBAC_ASSIGN_ROLE',  resource: 'users',  details: { info: 'Assigned ANALYST to user@company.com' }, created_at: new Date(Date.now() - 120000).toISOString(), ip: '127.0.0.1', severity: 'warning' },
        { id: 'AL003', user_name: 'System',  action: 'RBAC_DELETE_ROLE',  resource: 'roles',  details: { info: 'Deleted custom role' },             created_at: new Date(Date.now() - 180000).toISOString(), ip: '0.0.0.0',   severity: 'error' },
      ],
      total: 3, page: 1, limit: 50,
    });
  }

  let q = supabase
    .from('audit_logs')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .like('action', 'RBAC_%')
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (action) q = q.eq('action', `RBAC_${action.toUpperCase()}`);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({
    events:     data || [],
    total:      count || 0,
    page:       parseInt(page),
    limit:      parseInt(limit),
    totalPages: Math.ceil((count || 0) / parseInt(limit)),
  });
}));

/* ── GET /api/rbac/stats ── */
router.get('/stats', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;

  if (!supabase) {
    return res.json({
      roleCount:       DEFAULT_ROLES.length,
      userCount:       0,
      permissionCount: Object.keys(ALL_PERMISSIONS).length,
      moduleCount:     ALL_MODULES.length,
      systemRoles:     DEFAULT_ROLES.filter(r => r.isSystem).length,
      customRoles:     0,
    });
  }

  const [usersRes, rolesRes, logsRes] = await Promise.allSettled([
    supabase.from('users').select('id, role', { count: 'exact' }).eq('tenant_id', tenantId),
    supabase.from('roles').select('id, is_system', { count: 'exact' }).or(`tenant_id.eq.${tenantId},is_system.eq.true`),
    supabase.from('audit_logs').select('id', { count: 'exact' }).eq('tenant_id', tenantId).like('action', 'RBAC_%'),
  ]);

  const users = usersRes.status === 'fulfilled' ? usersRes.value.data || [] : [];
  const roles = rolesRes.status === 'fulfilled' ? rolesRes.value.data || [] : DEFAULT_ROLES;

  // Role distribution
  const roleDistribution = {};
  for (const u of users) {
    roleDistribution[u.role] = (roleDistribution[u.role] || 0) + 1;
  }

  res.json({
    roleCount:        roles.length || DEFAULT_ROLES.length,
    userCount:        usersRes.status === 'fulfilled' ? (usersRes.value.count || 0) : 0,
    permissionCount:  Object.keys(ALL_PERMISSIONS).length,
    moduleCount:      ALL_MODULES.length,
    systemRoles:      DEFAULT_ROLES.filter(r => r.isSystem).length,
    customRoles:      roles.filter(r => !r.is_system).length,
    roleDistribution,
    auditEvents:      logsRes.status === 'fulfilled' ? (logsRes.value.count || 0) : 0,
  });
}));

/* ── POST /api/rbac/check — Check permission ── */
router.post('/check', verifyToken, asyncHandler(async (req, res) => {
  const { userId, permission, module: moduleName, resource } = req.body;
  if (!permission) throw createError(400, 'permission is required');

  // Check current user's permissions
  const checkUserId = userId || req.user?.id;
  const userRole = req.user?.role || 'viewer';

  // Find role
  const roleDetail = DEFAULT_ROLES.find(r =>
    r.id === userRole || r.slug === userRole?.toLowerCase()
  );

  if (!roleDetail) {
    return res.json({ allowed: false, reason: `Role '${userRole}' not found` });
  }

  const hasWildcard = roleDetail.permissions.includes('*');
  const hasPermission = hasWildcard || roleDetail.permissions.includes(permission);
  const hasModuleAccess = !moduleName || roleDetail.modules.includes('*') || roleDetail.modules.includes(moduleName);

  res.json({
    allowed:     hasPermission && hasModuleAccess,
    userId:      checkUserId,
    role:        userRole,
    permission,
    module:      moduleName || null,
    reason:      !hasPermission ? `Role '${userRole}' lacks '${permission}' permission`
               : !hasModuleAccess ? `Role '${userRole}' lacks access to module '${moduleName}'`
               : 'Access granted',
    roleDetails: { name: roleDetail.name, level: roleDetail.level, permissions: roleDetail.permissions },
  });
}));

module.exports = router;
