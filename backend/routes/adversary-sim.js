/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Adversary Simulation + Threat Graph Backend v1.0
 *  FILE: backend/routes/adversary-sim.js
 *
 *  Endpoints:
 *  GET  /api/adversary-sim/scenarios           — List scenarios
 *  POST /api/adversary-sim/sessions            — Save session
 *  GET  /api/adversary-sim/sessions            — List sessions
 *  GET  /api/threat-graph                      — Threat graph nodes+edges
 *  POST /api/threat-graph/nodes                — Add node
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express  = require('express');
const router   = express.Router();
const { supabase }     = require('../config/supabase');
const { verifyToken }  = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';
function tid(req) { return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT; }

router.use(verifyToken);

/* ── GET /api/adversary-sim/scenarios ── */
router.get('/scenarios', asyncHandler(async (req, res) => {
  // Return metadata only (full data lives in frontend)
  const scenarios = [
    { id: 'apt29-solorigate', name: 'APT29 — SolarWinds Supply Chain', difficulty: 'CRITICAL', actor: 'APT29', phases: 7 },
    { id: 'lazarus-financial', name: 'Lazarus — Financial Heist', difficulty: 'HIGH', actor: 'Lazarus', phases: 6 },
    { id: 'lockbit-ransomware', name: 'LockBit 3.0 — Enterprise Ransomware', difficulty: 'HIGH', actor: 'LockBit', phases: 6 },
    { id: 'apt41-espionage', name: 'APT41 — IP Theft', difficulty: 'CRITICAL', actor: 'APT41', phases: 5 },
    { id: 'fin7-retail', name: 'FIN7 — Retail POS Compromise', difficulty: 'HIGH', actor: 'FIN7', phases: 5 },
  ];
  res.json({ scenarios });
}));

/* ── POST /api/adversary-sim/sessions ── */
router.post('/sessions', asyncHandler(async (req, res) => {
  const { scenario_id, scenario_name, threat_actor, mitre_tactics, attack_chain, status, outcome, results } = req.body;
  if (!scenario_id) throw createError(400, 'scenario_id required');

  const { data, error } = await supabase
    .from('adversary_sim_sessions')
    .insert({
      tenant_id:     tid(req),
      scenario_id,
      scenario_name: scenario_name || scenario_id,
      threat_actor,
      mitre_tactics: mitre_tactics || [],
      attack_chain:  attack_chain || [],
      status:        status || 'completed',
      outcome:       outcome || 'partial',
      results:       results || {},
      start_time:    new Date().toISOString(),
      end_time:      new Date().toISOString(),
      created_by:    req.user?.id,
    })
    .select().single();

  if (error) throw createError(500, error.message);
  res.status(201).json(data);
}));

/* ── GET /api/adversary-sim/sessions ── */
router.get('/sessions', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('adversary_sim_sessions')
    .select('id, scenario_id, scenario_name, threat_actor, status, outcome, created_at')
    .eq('tenant_id', tid(req))
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) throw createError(500, error.message);
  res.json({ sessions: data || [] });
}));

module.exports = router;
