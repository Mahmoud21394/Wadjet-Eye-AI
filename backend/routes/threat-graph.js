/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Graph Backend v1.0
 *  FILE: backend/routes/threat-graph.js
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

  if (nodesRes.error) throw createError(500, nodesRes.error.message);
  if (edgesRes.error) throw createError(500, edgesRes.error.message);

  res.json({
    nodes: nodesRes.data || [],
    edges: edgesRes.data || [],
    fetchedAt: new Date().toISOString(),
  });
}));

/* ── POST /api/threat-graph/nodes ── */
router.post('/nodes', asyncHandler(async (req, res) => {
  const { node_id, node_type, label, data, region, risk_score } = req.body;
  if (!node_id || !node_type || !label) throw createError(400, 'node_id, node_type, label required');

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

  if (error) throw createError(500, error.message);
  res.status(201).json(result);
}));

module.exports = router;
