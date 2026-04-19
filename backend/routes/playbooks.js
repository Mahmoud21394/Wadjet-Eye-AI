/**
 * ══════════════════════════════════════════════════════════
 *  Playbooks Routes — SOAR automation playbooks
 *  GET    /api/playbooks
 *  GET    /api/playbooks/:id
 *  POST   /api/playbooks
 *  PATCH  /api/playbooks/:id
 *  DELETE /api/playbooks/:id
 *  POST   /api/playbooks/:id/execute
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase }    = require('../config/supabase');
const { requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── GET /api/playbooks ── */
router.get('/', asyncHandler(async (req, res) => {
  const { category, active, search } = req.query;

  let query = supabase
    .from('playbooks')
    .select('id, title, description, category, trigger, mitre_techniques, active, steps, created_at, updated_at')
    .eq('tenant_id', req.tenantId)
    .order('created_at', { ascending: false });

  if (category) query = query.eq('category', category);
  if (active !== undefined) query = query.eq('active', active === 'true');
  if (search)   query = query.ilike('title', `%${search}%`);

  const { data, error } = await query;
  if (error) throw createError(500, error.message);
  res.json(data || []);
}));

/* ── GET /api/playbooks/:id ── */
router.get('/:id', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('playbooks')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !data) throw createError(404, 'Playbook not found');
  res.json(data);
}));

/* ── POST /api/playbooks ── */
router.post('/', requireRole(['ADMIN', 'SUPER_ADMIN', 'ANALYST']), asyncHandler(async (req, res) => {
  const { title, description, category, trigger, mitre_techniques, steps } = req.body;

  if (!title || !category) throw createError(400, 'title and category are required');
  if (!Array.isArray(steps) || steps.length === 0) {
    throw createError(400, 'steps must be a non-empty array');
  }

  // Validate step structure
  const validatedSteps = steps.map((step, index) => {
    if (!step.title) throw createError(400, `Step ${index + 1} is missing a title`);
    return {
      order:      step.order || index + 1,
      title:      step.title.trim(),
      desc:       step.desc || '',
      tool:       step.tool || 'manual',
      duration_s: Math.max(1, parseInt(step.duration_s, 10) || 30),
    };
  });

  const { data, error } = await supabase
    .from('playbooks')
    .insert({
      tenant_id:        req.tenantId,
      title:            title.trim(),
      description:      description || '',
      category:         category.trim(),
      trigger:          trigger || '',
      mitre_techniques: mitre_techniques || [],
      steps:            validatedSteps,
      active:           true,
      created_by:       req.user.id,
    })
    .select().single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

/* ── PATCH /api/playbooks/:id ── */
router.patch('/:id', requireRole(['ADMIN', 'SUPER_ADMIN', 'ANALYST']), asyncHandler(async (req, res) => {
  const allowed = ['title', 'description', 'category', 'trigger', 'mitre_techniques', 'steps', 'active'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  if (Object.keys(updates).length === 0) throw createError(400, 'No valid fields provided');

  const { data, error } = await supabase
    .from('playbooks')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .select().single();

  if (error || !data) throw createError(404, 'Playbook not found');
  res.json(data);
}));

/* ── POST /api/playbooks/:id/execute — simulate execution ── */
router.post('/:id/execute', asyncHandler(async (req, res) => {
  const { data: playbook, error } = await supabase
    .from('playbooks')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !playbook) throw createError(404, 'Playbook not found');
  if (!playbook.active) throw createError(400, 'Playbook is disabled');

  const { alert_id, case_id, ioc_value } = req.body;

  // Build execution record
  const execution = {
    playbook_id:  playbook.id,
    alert_id:     alert_id || null,
    case_id:      case_id  || null,
    ioc_value:    ioc_value || null,
    triggered_by: req.user.id,
    started_at:   new Date().toISOString(),
    status:       'running',
    step_results: playbook.steps.map(step => ({
      step:    step.order,
      title:   step.title,
      tool:    step.tool,
      status:  'pending',
      output:  null,
    })),
  };

  // Emit via Socket.IO (real-time progress tracking)
  const io = req.app.get('io');
  io?.to(`tenant:${req.tenantId}`).emit('playbook:started', {
    playbookId: playbook.id,
    title:      playbook.title,
    steps:      playbook.steps.length,
    triggeredBy: req.user.name,
  });

  res.json({
    message:   `Playbook "${playbook.title}" execution initiated`,
    execution,
    steps:     playbook.steps.length,
    estimated_duration_s: playbook.steps.reduce((s, step) => s + (step.duration_s || 30), 0),
  });
}));

/* ── DELETE /api/playbooks/:id ── */
router.delete('/:id', requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { error } = await supabase
    .from('playbooks')
    .delete()
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId);

  if (error) throw createError(500, error.message);
  res.status(204).send();
}));

module.exports = router;
