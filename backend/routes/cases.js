/**
 * ══════════════════════════════════════════════════════════
 *  Cases Routes — Incident & Case Management
 *  GET    /api/cases
 *  GET    /api/cases/:id
 *  POST   /api/cases
 *  PATCH  /api/cases/:id
 *  DELETE /api/cases/:id
 *  POST   /api/cases/:id/notes
 *  POST   /api/cases/:id/iocs
 *  POST   /api/cases/:id/timeline
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase } = require('../config/supabase');
const { requireRole }     = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── GET /api/cases ── */
router.get('/', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, status, severity, assigned_to, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let query = supabase
    .from('cases')
    .select(`
      *,
      assignee:users!cases_assigned_to_fkey(id, name, avatar),
      _count:case_iocs(count)
    `, { count: 'exact' })
    .eq('tenant_id', req.tenantId)
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (status)      query = query.eq('status', status);
  if (severity)    query = query.eq('severity', severity);
  if (assigned_to) query = query.eq('assigned_to', assigned_to);
  if (search)      query = query.ilike('title', `%${search}%`);

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message);

  res.json({ data, pagination: { page: +page, limit: +limit, total: count } });
}));

/* ── GET /api/cases/:id — Full case with timeline + IOCs ── */
router.get('/:id', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('cases')
    .select(`
      *,
      assignee:users!cases_assigned_to_fkey(id, name, avatar, role),
      creator:users!cases_created_by_fkey(id, name, avatar),
      case_notes(id, content, created_by, created_at, users(name, avatar)),
      case_iocs(id, ioc_id, added_at, iocs(value, type, risk_score, country)),
      case_timeline(id, event_type, description, actor, created_at)
    `)
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !data) throw createError(404, 'Case not found');
  res.json(data);
}));

/* ── POST /api/cases — Create case ── */
router.post('/', asyncHandler(async (req, res) => {
  const { title, description, severity, assigned_to, tags, alert_ids, sla_hours = 72 } = req.body;

  if (!title) throw createError(400, 'title is required');

  const sla_deadline = new Date(Date.now() + sla_hours * 3600000).toISOString();

  const { data: caseData, error } = await supabase
    .from('cases')
    .insert({
      tenant_id:    req.tenantId,
      title,
      description:  description || '',
      severity:     severity?.toUpperCase() || 'MEDIUM',
      status:       'open',
      assigned_to:  assigned_to || null,
      created_by:   req.user.id,
      tags:         tags || [],
      sla_deadline,
      alert_ids:    alert_ids || [],
      evidence:     []
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);

  /* Add initial timeline event */
  await supabase.from('case_timeline').insert({
    case_id:     caseData.id,
    event_type:  'created',
    description: `Case created by ${req.user.name}`,
    actor:       req.user.name,
    created_at:  new Date().toISOString()
  });

  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('case:new', caseData);

  res.status(201).json(caseData);
}));

/* ── PATCH /api/cases/:id ── */
router.patch('/:id', asyncHandler(async (req, res) => {
  const allowed = ['title','description','severity','status','assigned_to','tags','resolution','evidence'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  if (updates.status === 'closed') updates.closed_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('cases')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'Case not found');

  /* Timeline event */
  await supabase.from('case_timeline').insert({
    case_id:     req.params.id,
    event_type:  'updated',
    description: `Case updated by ${req.user.name}: ${Object.keys(updates).join(', ')}`,
    actor:       req.user.name,
    created_at:  new Date().toISOString()
  });

  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('case:updated', data);

  res.json(data);
}));

/* ── POST /api/cases/:id/notes ── */
router.post('/:id/notes', asyncHandler(async (req, res) => {
  const { content } = req.body;
  if (!content) throw createError(400, 'Note content is required');

  const { data, error } = await supabase
    .from('case_notes')
    .insert({
      case_id:    req.params.id,
      content,
      created_by: req.user.id,
      created_at: new Date().toISOString()
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

/* ── POST /api/cases/:id/iocs — Link IOC to case ── */
router.post('/:id/iocs', asyncHandler(async (req, res) => {
  const { ioc_id } = req.body;
  if (!ioc_id) throw createError(400, 'ioc_id is required');

  const { data, error } = await supabase
    .from('case_iocs')
    .insert({ case_id: req.params.id, ioc_id, added_at: new Date().toISOString(), added_by: req.user.id })
    .select()
    .single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

/* ── DELETE /api/cases/:id ── */
router.delete('/:id',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { error } = await supabase
      .from('cases')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', req.tenantId);

    if (error) throw createError(500, error.message);
    res.status(204).send();
  })
);

module.exports = router;
