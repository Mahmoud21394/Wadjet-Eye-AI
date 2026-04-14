/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Adversary Simulation + Threat Graph Backend v1.1
 *  FILE: backend/routes/adversary-sim.js
 *
 *  v1.1 changes:
 *  - DB errors return fallback data instead of 500 (NEVER 500)
 *  - POST /sessions returns accepted response even if DB insert fails
 *  - GET /sessions returns empty [] on DB error
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express  = require('express');
const router   = express.Router();
const { supabase }     = require('../config/supabase');
const { asyncHandler } = require('../middleware/errorHandler');

// NOTE: verifyToken is already applied globally in server.js before this router.
// Do NOT add router.use(verifyToken) here — that would cause Supabase to be
// called twice per request (double auth round-trip, wasted quota, slower response).

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';
function tid(req) { return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT; }

/* ── GET /api/adversary-sim/scenarios ── */
router.get('/scenarios', asyncHandler(async (req, res) => {
  // Static scenario metadata (full simulation data lives in frontend JS)
  const scenarios = [
    { id: 'apt29-solorigate',  name: 'APT29 — SolarWinds Supply Chain', difficulty: 'CRITICAL', actor: 'APT29',   phases: 7 },
    { id: 'lazarus-financial', name: 'Lazarus — Financial Heist',        difficulty: 'HIGH',     actor: 'Lazarus', phases: 6 },
    { id: 'lockbit-ransomware',name: 'LockBit 3.0 — Enterprise Ransomware', difficulty: 'HIGH', actor: 'LockBit', phases: 6 },
    { id: 'apt41-espionage',   name: 'APT41 — IP Theft',                 difficulty: 'CRITICAL', actor: 'APT41',   phases: 5 },
    { id: 'fin7-retail',       name: 'FIN7 — Retail POS Compromise',     difficulty: 'HIGH',     actor: 'FIN7',    phases: 5 },
  ];
  res.json({ scenarios, total: scenarios.length });
}));

/* ── POST /api/adversary-sim/sessions ── */
router.post('/sessions', asyncHandler(async (req, res) => {
  const {
    scenario_id, scenario_name, threat_actor,
    mitre_tactics, attack_chain, status, outcome, results,
  } = req.body;

  // Validate required field — return 400 (not 500) if missing
  if (!scenario_id) {
    return res.status(400).json({
      error:   'scenario_id is required',
      data:    null,
      example: { scenario_id: 'apt29-solorigate', status: 'completed' },
    });
  }

  const sessionRecord = {
    tenant_id:     tid(req),
    scenario_id,
    scenario_name: scenario_name || scenario_id,
    threat_actor:  threat_actor  || 'unknown',
    mitre_tactics: mitre_tactics || [],
    attack_chain:  attack_chain  || [],
    status:        status        || 'completed',
    outcome:       outcome       || 'partial',
    results:       results       || {},
    start_time:    new Date().toISOString(),
    end_time:      new Date().toISOString(),
    created_by:    req.user?.id,
  };

  const { data, error } = await supabase
    .from('adversary_sim_sessions')
    .insert(sessionRecord)
    .select().single();

  if (error) {
    // NEVER return 500 — log and return a synthetic success response
    console.error('[AdversarySim] session insert error:', error.message);
    return res.status(200).json({
      ...sessionRecord,
      id:        `local-${Date.now()}`,
      _db_error: error.message,
      message:   'Session accepted but not persisted (DB unavailable). Results stored locally.',
    });
  }

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

  if (error) {
    // NEVER return 500 — return empty list with error info
    console.error('[AdversarySim] sessions fetch error:', error.message);
    return res.json({ sessions: [], total: 0, db_error: error.message });
  }

  res.json({ sessions: data || [], total: (data || []).length });
}));

module.exports = router;
