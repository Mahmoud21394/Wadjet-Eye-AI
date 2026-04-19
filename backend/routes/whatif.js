/**
 * What-If Simulations Backend
 * POST /api/whatif/simulations — Save simulation result
 * GET  /api/whatif/simulations — List recent simulations
 */
'use strict';
const express = require('express');
const router  = express.Router();
const { supabase }    = require('../config/supabase');
const { verifyToken } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';
function tid(req) { return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT; }

router.use(verifyToken);

router.post('/simulations', asyncHandler(async (req, res) => {
  const { scenario_id, scenario_name, user_inputs, outcome, risk_reduction, recommendations } = req.body;
  if (!scenario_id) throw createError(400, 'scenario_id required');
  const { data, error } = await supabase.from('whatif_simulations').insert({
    tenant_id:      tid(req),
    scenario_id,
    scenario_name:  scenario_name || scenario_id,
    user_inputs:    user_inputs || {},
    outcome,
    risk_reduction: risk_reduction || 0,
    recommendations: recommendations || [],
    run_by: req.user?.id,
  }).select().single();
  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

router.get('/simulations', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('whatif_simulations').select('id,scenario_id,scenario_name,outcome,risk_reduction,run_at')
    .eq('tenant_id', tid(req)).order('run_at', { ascending: false }).limit(50);
  if (error) throw createError(500, error.message);
  res.json({ simulations: data || [] });
}));

module.exports = router;
