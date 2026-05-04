/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Autonomous SOC Agent Routes (Phase 5)
 *  backend/routes/agents.js
 *
 *  GET  /api/agents/status           — Agent framework health & stats
 *  POST /api/agents/triage           — Dispatch triage agent for alert
 *  POST /api/agents/investigate      — Dispatch investigation agent
 *  POST /api/agents/respond          — Dispatch response agent (HITL gate)
 *  GET  /api/agents/decisions        — List recent agent decisions
 *  GET  /api/agents/decisions/:id    — Get specific agent decision
 *  POST /api/agents/decisions/:id/approve — Human-in-the-loop approval
 *  POST /api/agents/decisions/:id/reject  — Reject agent decision
 *  GET  /api/agents/queue            — Current agent task queue
 *  GET  /api/agents/metrics          — Agent performance metrics
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const agentOrchestrator = require('../services/agents/agent-orchestrator');
const { supabase } = require('../config/supabase');
const { z } = require('zod');
const { llmRateLimiter } = require('../middleware/rateLimiter');

router.use(verifyToken);

// ── Schemas ───────────────────────────────────────────────────────
const TriageSchema = z.object({
  alert_id:  z.string().uuid(),
  priority:  z.enum(['low','medium','high','critical']).default('medium'),
  auto_execute: z.boolean().default(false),
});

const InvestigateSchema = z.object({
  alert_id:    z.string().uuid(),
  incident_id: z.string().uuid().optional(),
  depth:       z.enum(['shallow','standard','deep']).default('standard'),
  context:     z.record(z.unknown()).optional(),
});

const RespondSchema = z.object({
  decision_id:  z.string().uuid(),
  action_plan:  z.array(z.object({
    action:     z.string().max(100),
    target:     z.string().max(253).optional(),
    parameters: z.record(z.unknown()).optional(),
  })).max(20),
  auto_execute: z.boolean().default(false),
});

const ApprovalSchema = z.object({
  notes:  z.string().max(1000).optional(),
  modifications: z.record(z.unknown()).optional(),
});

const RejectSchema = z.object({
  reason: z.string().min(10).max(500),
  label:  z.enum(['false_positive','escalate_human','insufficient_context','other']).optional(),
});

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/agents/status
 */
router.get('/status', asyncHandler(async (req, res) => {
  const status = await agentOrchestrator.getStatus();
  res.json({ success: true, data: status });
}));

/**
 * POST /api/agents/triage
 * Dispatch triage agent for a specific alert
 */
router.post('/triage', llmRateLimiter, asyncHandler(async (req, res) => {
  const parsed = TriageSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { alert_id, priority, auto_execute } = parsed.data;
  const tenantId = req.tenantId;

  // Fetch the alert
  const { data: alert, error: alertErr } = await supabase
    .from('alerts')
    .select('*')
    .eq('id', alert_id)
    .eq('tenant_id', tenantId)
    .single();

  if (alertErr || !alert) throw createError(404, 'Alert not found');
  if (['closed','false_positive','true_positive'].includes(alert.status)) {
    throw createError(422, `Cannot triage alert in status: ${alert.status}`);
  }

  // Dispatch triage agent
  const result = await agentOrchestrator.runTriageAgent(alert, {
    auto_execute,
    priority,
    initiated_by: req.user?.id,
    tenant_id:    tenantId,
  });

  // Persist decision
  const { data: decision } = await supabase
    .from('agent_decisions')
    .insert({
      tenant_id:   tenantId,
      alert_id:    alert_id,
      agent_type:  'triage',
      decision:    result.decision,
      confidence:  result.confidence,
      reasoning:   result.reasoning,
      actions_taken: result.actions || [],
      human_approved: auto_execute && result.confidence >= 85 ? true : null,
      execution_ms: result.execution_ms,
      llm_model:   result.llm_model,
      prompt_tokens: result.prompt_tokens,
      completion_tokens: result.completion_tokens,
    })
    .select('id')
    .single();

  res.status(202).json({
    success:     true,
    decision_id: decision?.id,
    alert_id,
    agent_type:  'triage',
    decision:    result.decision,
    confidence:  result.confidence,
    reasoning:   result.reasoning,
    actions:     result.actions || [],
    auto_executed: auto_execute && result.confidence >= 85,
    requires_approval: result.confidence < 85,
    execution_ms: result.execution_ms,
  });
}));

/**
 * POST /api/agents/investigate
 * Dispatch L2 investigation agent
 */
router.post('/investigate', llmRateLimiter, asyncHandler(async (req, res) => {
  const parsed = InvestigateSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { alert_id, incident_id, depth, context } = parsed.data;
  const tenantId = req.tenantId;

  // Fetch alert + related context
  const { data: alert } = await supabase
    .from('alerts')
    .select('*')
    .eq('id', alert_id)
    .eq('tenant_id', tenantId)
    .single();

  if (!alert) throw createError(404, 'Alert not found');

  // Fetch incident if linked
  let incident = null;
  if (incident_id) {
    const { data } = await supabase
      .from('incidents')
      .select('*')
      .eq('id', incident_id)
      .eq('tenant_id', tenantId)
      .single();
    incident = data;
  }

  // Dispatch investigation agent
  const result = await agentOrchestrator.runInvestigationAgent(alert, {
    incident,
    depth,
    context: context || {},
    initiated_by: req.user?.id,
    tenant_id:    tenantId,
  });

  // Persist decision
  const { data: decision } = await supabase
    .from('agent_decisions')
    .insert({
      tenant_id:    tenantId,
      alert_id:     alert_id,
      incident_id:  incident_id || null,
      agent_type:   'investigation',
      decision:     result.decision,
      confidence:   result.confidence,
      reasoning:    result.reasoning,
      actions_taken: result.actions || [],
      execution_ms:  result.execution_ms,
      llm_model:     result.llm_model,
    })
    .select('id')
    .single();

  // Update alert with AI summary if generated
  if (result.ai_summary) {
    await supabase
      .from('alerts')
      .update({
        ai_summary:               result.ai_summary,
        ai_recommended_actions:   result.recommended_actions || [],
        updated_at:               new Date().toISOString(),
      })
      .eq('id', alert_id);
  }

  res.status(202).json({
    success:          true,
    decision_id:      decision?.id,
    alert_id,
    agent_type:       'investigation',
    decision:         result.decision,
    confidence:       result.confidence,
    reasoning:        result.reasoning,
    ai_narrative:     result.ai_narrative,
    attack_chain:     result.attack_chain,
    ioc_pivots:       result.ioc_pivots || [],
    recommendations:  result.recommended_actions || [],
    execution_ms:     result.execution_ms,
  });
}));

/**
 * POST /api/agents/respond
 * Dispatch response agent — always requires HITL for high-impact actions
 */
router.post(
  '/respond',
  requireRole(['TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  llmRateLimiter,
  asyncHandler(async (req, res) => {
    const parsed = RespondSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { decision_id, action_plan, auto_execute } = parsed.data;
    const tenantId = req.tenantId;

    // Fetch the prior decision
    const { data: priorDecision } = await supabase
      .from('agent_decisions')
      .select('*')
      .eq('id', decision_id)
      .eq('tenant_id', tenantId)
      .single();

    if (!priorDecision) throw createError(404, 'Prior decision not found');

    // Auto-execute only allowed if confidence >= threshold
    const effectiveAutoExecute = auto_execute &&
      (priorDecision.confidence || 0) >= agentOrchestrator.AUTO_EXECUTE_THRESHOLD;

    if (auto_execute && !effectiveAutoExecute) {
      throw createError(422, [
        `Auto-execute requires agent confidence ≥ ${agentOrchestrator.AUTO_EXECUTE_THRESHOLD}%.`,
        `Current confidence: ${priorDecision.confidence}%. Manual approval required.`,
      ].join(' '));
    }

    const result = await agentOrchestrator.runResponseAgent(priorDecision, action_plan, {
      auto_execute:  effectiveAutoExecute,
      initiated_by:  req.user?.id,
      tenant_id:     tenantId,
    });

    // Record response decision
    const { data: respDecision } = await supabase
      .from('agent_decisions')
      .insert({
        tenant_id:     tenantId,
        alert_id:      priorDecision.alert_id,
        incident_id:   priorDecision.incident_id,
        agent_type:    'response',
        decision:      result.decision,
        confidence:    result.confidence,
        reasoning:     result.reasoning,
        actions_taken: result.actions_executed || [],
        human_approved: effectiveAutoExecute ? true : null,
        approved_by:   effectiveAutoExecute ? req.user?.id : null,
        approved_at:   effectiveAutoExecute ? new Date().toISOString() : null,
        execution_ms:  result.execution_ms,
      })
      .select('id')
      .single();

    res.status(202).json({
      success:       true,
      decision_id:   respDecision?.id,
      agent_type:    'response',
      decision:      result.decision,
      auto_executed: effectiveAutoExecute,
      actions:       result.actions_executed || [],
      pending_approval: !effectiveAutoExecute,
      execution_ms:  result.execution_ms,
    });
  })
);

/**
 * GET /api/agents/decisions
 * List recent agent decisions
 */
router.get('/decisions', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit  = Math.min(parseInt(req.query.limit || '50', 10), 500);
  const offset = (Math.max(parseInt(req.query.page || '1', 10), 1) - 1) * limit;
  const agentType = req.query.agent_type;
  const pendingOnly = req.query.pending === 'true';

  let query = supabase
    .from('agent_decisions')
    .select('*', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (agentType)   query = query.eq('agent_type', agentType);
  if (pendingOnly) query = query.is('human_approved', null);

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message);

  res.json({
    success: true,
    total:   count || 0,
    page:    Math.floor(offset / limit) + 1,
    limit,
    data:    data || [],
  });
}));

/**
 * GET /api/agents/decisions/:id
 */
router.get('/decisions/:id', asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('agent_decisions')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (error || !data) throw createError(404, 'Decision not found');
  res.json({ success: true, data });
}));

/**
 * POST /api/agents/decisions/:id/approve
 * Human-in-the-loop approval of agent decision
 */
router.post(
  '/decisions/:id/approve',
  requireRole(['ANALYST', 'TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = ApprovalSchema.safeParse(req.body || {});
    if (!parsed.success) throw createError(400, parsed.error.message);

    const tenantId = req.tenantId;
    const { data: decision } = await supabase
      .from('agent_decisions')
      .select('*')
      .eq('id', req.params.id)
      .eq('tenant_id', tenantId)
      .single();

    if (!decision) throw createError(404, 'Decision not found');
    if (decision.human_approved !== null) {
      throw createError(422, `Decision already ${decision.human_approved ? 'approved' : 'rejected'}`);
    }

    // Execute approved actions
    const result = await agentOrchestrator.executeApprovedActions(decision, parsed.data.modifications);

    // Update decision record
    await supabase
      .from('agent_decisions')
      .update({
        human_approved: true,
        approved_by:    req.user?.id,
        approved_at:    new Date().toISOString(),
        actions_taken:  result.actions_executed || decision.actions_taken,
      })
      .eq('id', req.params.id);

    res.json({
      success:          true,
      decision_id:      req.params.id,
      approved_by:      req.user?.email,
      actions_executed: result.actions_executed || [],
      message:          'Agent decision approved and actions executed',
    });
  })
);

/**
 * POST /api/agents/decisions/:id/reject
 * Reject agent decision — returns to human queue
 */
router.post(
  '/decisions/:id/reject',
  requireRole(['ANALYST', 'TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = RejectSchema.safeParse(req.body || {});
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { reason, label } = parsed.data;
    const tenantId = req.tenantId;

    const { data: decision } = await supabase
      .from('agent_decisions')
      .select('id, human_approved')
      .eq('id', req.params.id)
      .eq('tenant_id', tenantId)
      .single();

    if (!decision) throw createError(404, 'Decision not found');
    if (decision.human_approved !== null) {
      throw createError(422, 'Decision already actioned');
    }

    await supabase
      .from('agent_decisions')
      .update({
        human_approved: false,
        override_reason: `[${label || 'rejected'}] ${reason}`,
        approved_by:     req.user?.id,
        approved_at:     new Date().toISOString(),
      })
      .eq('id', req.params.id);

    // Feed rejection as training signal to self-learning engine
    try {
      const selfLearning = require('../services/detection/self-learning');
      if (decision.alert_id) {
        await selfLearning.recordAnalystFeedback({
          alert_id:  decision.alert_id,
          analyst_id: req.user?.id,
          outcome:   label === 'false_positive' ? 'false_positive' : 'needs_review',
          notes:     reason,
          tenant_id: tenantId,
        });
      }
    } catch (_) { /* non-critical */ }

    res.json({
      success:     true,
      decision_id: req.params.id,
      rejected_by: req.user?.email,
      reason,
      message:     'Decision rejected — alert returned to human queue',
    });
  })
);

/**
 * GET /api/agents/queue
 * Current agent task queue (pending decisions requiring approval)
 */
router.get('/queue', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const { data, count } = await supabase
    .from('agent_decisions')
    .select('id, agent_type, decision, confidence, reasoning, alert_id, created_at', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .is('human_approved', null)
    .order('created_at', { ascending: true })
    .limit(100);

  res.json({
    success:        true,
    queue_depth:    count || 0,
    pending_approval: data || [],
  });
}));

/**
 * GET /api/agents/metrics
 * Agent performance metrics
 */
router.get('/metrics', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const since = new Date(Date.now() - 7 * 24 * 3600000).toISOString();

  const { data: decisions } = await supabase
    .from('agent_decisions')
    .select('agent_type, decision, confidence, human_approved, execution_ms, created_at')
    .eq('tenant_id', tenantId)
    .gte('created_at', since);

  const decisions_ = decisions || [];

  const byType = {};
  for (const d of decisions_) {
    if (!byType[d.agent_type]) {
      byType[d.agent_type] = { total: 0, auto_executed: 0, approved: 0, rejected: 0, avg_confidence: 0, avg_ms: 0 };
    }
    const t = byType[d.agent_type];
    t.total++;
    if (d.human_approved === true)  t.approved++;
    if (d.human_approved === false) t.rejected++;
    if (d.human_approved === true && d.confidence >= 85) t.auto_executed++;
    t.avg_confidence = (t.avg_confidence * (t.total - 1) + (d.confidence || 0)) / t.total;
    t.avg_ms = (t.avg_ms * (t.total - 1) + (d.execution_ms || 0)) / t.total;
  }

  // Round averages
  for (const t of Object.values(byType)) {
    t.avg_confidence = Math.round(t.avg_confidence * 10) / 10;
    t.avg_ms         = Math.round(t.avg_ms);
  }

  res.json({
    success:    true,
    period:     { since, until: new Date().toISOString() },
    total:      decisions_.length,
    by_type:    byType,
    automation_rate: decisions_.length > 0
      ? Math.round((decisions_.filter(d => d.human_approved === true && d.confidence >= 85).length / decisions_.length) * 100)
      : 0,
  });
}));

module.exports = router;
