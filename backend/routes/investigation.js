/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Investigation Pipeline Routes  (Phase 1)
 *  backend/routes/investigation.js
 *
 *  POST /api/investigation/run     — Start a new investigation pipeline run
 *  GET  /api/investigation/run/:id — Get run status + events
 *  GET  /api/investigation/runs    — List runs for a tenant
 *
 *  Feature flag: ENABLE_PIPELINE_INVESTIGATION=1 (env) enables pipeline.
 *  When disabled, POST /run returns 404 so the caller falls back to the
 *  legacy direct GPT call in soc-ai-engine.js.
 *
 *  All LLM calls are wrapped with the Phase 0 LLM Input Contract guard.
 * ══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const router = require('express').Router();
const { supabase }              = require('../config/supabase');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { guardMessages, LLMContractViolation } = require('../middleware/llmContract');

// ── Feature flag ────────────────────────────────────────────────────────────
function isPipelineEnabled() {
  const v = process.env.ENABLE_PIPELINE_INVESTIGATION;
  return v === '1' || v === 'true';
}

// ── LLM provider helper ─────────────────────────────────────────────────────
// Thin wrapper that routes through llm-provider.js with contract guard applied
async function _callLLM(messages) {
  const { messages: safeMessages, blocked, reason } =
    guardMessages(messages, 'investigation route');
  if (blocked) {
    throw new LLMContractViolation(`Investigation callLLM blocked: ${reason}`);
  }

  const llmProvider = require('../services/llm-provider');
  return llmProvider.chat(safeMessages, {
    model:       process.env.PIPELINE_MODEL || process.env.COPILOT_MODEL || 'gpt-4o',
    max_tokens:  1500,
    temperature: 0.2,
  });
}

/* ════════════════════════════════════════════════
   POST /api/investigation/run
   Start a pipeline investigation for an alert.
   Body: { alert_id?, alert: { title, description, severity, ... } }
════════════════════════════════════════════════ */
router.post('/run', asyncHandler(async (req, res) => {
  if (!isPipelineEnabled()) {
    return res.status(404).json({
      success: false,
      error: { code: 'FEATURE_DISABLED', message: 'Pipeline investigation not enabled' },
    });
  }

  const { alert_id, alert: alertBody } = req.body;
  const tenantId = req.tenantId;

  if (!alertBody && !alert_id) {
    throw createError(400, 'alert or alert_id is required');
  }

  // Fetch alert from DB if alert_id provided
  let alert = alertBody;
  if (alert_id && !alert) {
    const { data, error } = await supabase
      .from('alerts')
      .select('*')
      .eq('id', alert_id)
      .eq('tenant_id', tenantId)
      .single();
    if (error || !data) throw createError(404, 'Alert not found');
    alert = data;
  }

  // Load pipeline module
  const pipeline = require('../../js/investigation-pipeline.js');

  let result;
  try {
    result = await pipeline.runInvestigation(alert, {
      callLLM:   _callLLM,
      supabase,
      tenantId,
      model: process.env.PIPELINE_MODEL || 'gpt-4o',
    });
  } catch (err) {
    if (err.name === 'LLMContractViolation') {
      return res.status(422).json({
        success: false,
        error: { code: 'LLM_CONTRACT_VIOLATION', message: err.message },
      });
    }
    throw err;
  }

  res.status(201).json({
    success:      true,
    run_id:       result.runId,
    status:       result.status,
    early_exit:   result.earlyExit,
    early_exit_reason: result.earlyExitReason,
    stages_completed: result.completedStages,
    total_tokens:    result.totalTokens,
    total_cost_usd:  result.totalCostUsd,
    result,
  });
}));

/* ════════════════════════════════════════════════
   GET /api/investigation/run/:id
   Fetch run status + all ledger events.
════════════════════════════════════════════════ */
router.get('/run/:id', asyncHandler(async (req, res) => {
  const { id }      = req.params;
  const tenantId    = req.tenantId;

  const { data: run, error: runErr } = await supabase
    .from('we_investigation_runs')
    .select('*')
    .eq('id', id)
    .eq('tenant_id', tenantId)
    .single();

  if (runErr || !run) throw createError(404, 'Investigation run not found');

  const { data: events, error: evtErr } = await supabase
    .from('we_investigation_events')
    .select('*')
    .eq('run_id', id)
    .order('seq', { ascending: true });

  const { data: artifacts } = await supabase
    .from('we_investigation_artifacts')
    .select('id, kind, sha256, size_bytes, created_at')
    .eq('run_id', id);

  res.json({
    success:   true,
    run,
    events:    events   || [],
    artifacts: artifacts || [],
  });
}));

/* ════════════════════════════════════════════════
   GET /api/investigation/runs
   List runs for a tenant (paginated).
════════════════════════════════════════════════ */
router.get('/runs', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const { page = 1, limit = 20, status } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let query = supabase
    .from('we_investigation_runs')
    .select('id,alert_id,case_id,alert_summary,status,total_tokens,total_cost_usd,started_at,completed_at', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('started_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (status) query = query.eq('status', status);

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message);

  res.json({
    success: true,
    data,
    pagination: {
      page:  parseInt(page),
      limit: parseInt(limit),
      total: count,
      pages: Math.ceil(count / parseInt(limit)),
    },
    pipeline_enabled: isPipelineEnabled(),
  });
}));

module.exports = router;
