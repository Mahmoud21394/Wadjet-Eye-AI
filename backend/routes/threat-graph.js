/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Graph Backend v1.1
 *  FILE: backend/routes/threat-graph.js
 *
 *  v1.1 changes:
 *  - DB errors return empty fallback data instead of 500 (NEVER return 500)
 *  - GET /api/threat-graph always returns {nodes:[], edges:[], ...}
 *  - POST /api/threat-graph/nodes returns fallback on insert failure
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

/* ── GET /api/threat-graph ── */
router.get('/', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  const [nodesRes, edgesRes] = await Promise.all([
    supabase.from('threat_graph_nodes').select('*').eq('tenant_id', tenantId).eq('active', true).order('risk_score', { ascending: false }),
    supabase.from('threat_graph_edges').select('*').eq('tenant_id', tenantId),
  ]);

  // NEVER return 500 — log errors and return empty fallback data
  if (nodesRes.error) {
    console.error('[ThreatGraph] nodes fetch error:', nodesRes.error.message);
  }
  if (edgesRes.error) {
    console.error('[ThreatGraph] edges fetch error:', edgesRes.error.message);
  }

  res.json({
    nodes:     nodesRes.data  || [],
    edges:     edgesRes.data  || [],
    fetchedAt: new Date().toISOString(),
    db_error:  nodesRes.error?.message || edgesRes.error?.message || null,
    // If db_error is present, UI should show "data unavailable" not crash
  });
}));

/* ── POST /api/threat-graph/nodes ── */
router.post('/nodes', asyncHandler(async (req, res) => {
  const { node_id, node_type, label, data, region, risk_score } = req.body;
  if (!node_id || !node_type || !label) {
    return res.status(400).json({ error: 'node_id, node_type, label required', data: null });
  }

  const { data: result, error } = await supabase
    .from('threat_graph_nodes')
    .upsert({
      tenant_id:  tid(req),
      node_id,
      node_type,
      label,
      data:       data || {},
      region,
      risk_score: risk_score || 50,
      last_seen:  new Date().toISOString(),
    }, { onConflict: 'tenant_id,node_id' })
    .select().single();

  if (error) {
    console.error('[ThreatGraph] node upsert error:', error.message);
    // Return partial success with error info instead of 500
    return res.status(200).json({
      node_id, node_type, label,
      _db_error: error.message,
      message: 'Node not persisted (DB error) but accepted for processing',
    });
  }
  res.status(201).json(result);
}));

module.exports = router;
