/**
 * AI Governance API Routes  v1.0
 * GET  /api/ai-governance/models         — Model registry
 * GET  /api/ai-governance/prompts        — Prompt registry
 * GET  /api/ai-governance/agents         — Agent registry
 * POST /api/ai-governance/eval           — Run evaluation harness
 * GET  /api/ai-governance/eu-ai-act/:id  — EU AI Act documentation
 * GET  /api/ai-governance/nist-rmf       — NIST AI RMF mapping
 * GET  /api/ai-governance/decisions      — Decision ledger query
 * POST /api/ai-governance/decisions/:id/approve — Approve decision
 * POST /api/ai-governance/decisions/:id/reject  — Reject decision
 */
'use strict';

const router = require('express').Router();
const { requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const registry = require('../services/aiGovernance/registry');
const ledger   = require('../services/decisionLedger');
const { supabase } = require('../config/supabase');

// All governance endpoints require admin or auditor role
router.use(requireRole(['ADMIN', 'SUPER_ADMIN', 'admin', 'super_admin', 'auditor']));

// ── Model Registry ───────────────────────────────────────────────
router.get('/models', asyncHandler(async (req, res) => {
  const models = Array.from(registry.MODEL_REGISTRY.values()).map(m => ({
    id: m.id, provider: m.provider, version: m.version,
    status: m.status, risk_level: m.risk_level,
    use_cases: m.use_cases, approved_by: m.approved_by, approved_at: m.approved_at,
  }));
  res.json({ models, total: models.length });
}));

router.get('/models/:id', asyncHandler(async (req, res) => {
  const model = registry.MODEL_REGISTRY.get(req.params.id);
  if (!model) return res.status(404).json({ error: 'Model not found' });
  res.json(model);
}));

// ── Prompt Registry ──────────────────────────────────────────────
router.get('/prompts', asyncHandler(async (req, res) => {
  const prompts = Array.from(registry.PROMPT_REGISTRY.values());
  res.json({ prompts, total: prompts.length });
}));

// ── Agent Registry ───────────────────────────────────────────────
router.get('/agents', asyncHandler(async (req, res) => {
  const agents = Array.from(registry.AGENT_REGISTRY.values());
  res.json({ agents, total: agents.length });
}));

// ── Evaluation Harness ───────────────────────────────────────────
router.post('/eval', asyncHandler(async (req, res) => {
  const report = registry.runEvalHarness();
  res.json(report);
}));

// ── EU AI Act Documentation ──────────────────────────────────────
router.get('/eu-ai-act/:modelId', asyncHandler(async (req, res) => {
  const doc = registry.generateEuAiActDoc(req.params.modelId);
  if (!doc) return res.status(404).json({ error: 'Model not found in registry' });
  res.json(doc);
}));

// ── NIST AI RMF ──────────────────────────────────────────────────
router.get('/nist-rmf', asyncHandler(async (req, res) => {
  res.json(registry.generateNistAiRmfMapping());
}));

// ── Decision Ledger ──────────────────────────────────────────────
router.get('/decisions', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit    = Math.min(parseInt(req.query.limit) || 50, 200);
  const status   = req.query.status;

  let query = supabase.from('decision_ledger')
    .select('decision_id,agent_id,action,confidence,risk_score,requires_human,status,timestamp,approved_by,rejected_by')
    .eq('tenant_id', tenantId)
    .order('timestamp', { ascending: false })
    .limit(limit);

  if (status) query = query.eq('status', status);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json({ decisions: data || [], total: (data || []).length });
}));

router.post('/decisions/:id/approve', asyncHandler(async (req, res) => {
  const result = await ledger.approveDecision(req.params.id, req.user.id, req.tenantId);
  res.json(result);
}));

router.post('/decisions/:id/reject', asyncHandler(async (req, res) => {
  const { reason } = req.body;
  const result = await ledger.rejectDecision(req.params.id, req.user.id, reason, req.tenantId);
  res.json(result);
}));

module.exports = router;
