/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Autonomous SOC Agent Orchestrator (Phase 5)
 *  backend/services/agents/agent-orchestrator.js
 *
 *  Multi-agent framework for autonomous L1/L2 SOC operations:
 *  • Agent 1 (Triage):       Alert → enrich → score → route/close
 *  • Agent 2 (Investigation): L2 escalation → pivot → chain → report
 *  • Agent 3 (Response):     Approved plan → SOAR → ticket → notify
 *
 *  Human-in-the-loop: high-confidence auto-executes, low-confidence
 *  requests analyst approval before proceeding.
 *
 *  Audit finding: No autonomous agent framework for L1/L2 triage
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');
const { buildContext }    = require('../rag/rag-pipeline');
const { reconstructAttackChain } = require('../graph/neo4j-service');

// ── LLM provider (reuses RAKAY engine) ───────────────────────────
async function llmCall(systemPrompt, userPrompt, opts = {}) {
  const provider   = process.env.AGENT_LLM_PROVIDER || 'openai';
  const apiKey     = process.env.OPENAI_API_KEY || process.env.CLAUDE_API_KEY;
  const model      = opts.model || (provider === 'openai' ? 'gpt-4o' : 'claude-opus-4-5');
  const maxTokens  = opts.maxTokens || 2000;
  const temperature = opts.temperature ?? 0.2;

  if (!apiKey) {
    console.warn('[Agent] No LLM API key — returning mock decision');
    return { content: '{"decision":"needs_review","confidence":50,"reasoning":"No LLM key configured"}', mock: true };
  }

  try {
    if (provider === 'openai') {
      const https   = require('https');
      const payload = JSON.stringify({
        model,
        max_tokens: maxTokens,
        temperature,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userPrompt },
        ],
        response_format: opts.jsonMode ? { type: 'json_object' } : undefined,
      });

      return await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.openai.com', port: 443, path: '/v1/chat/completions', method: 'POST',
          headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
        }, (res) => {
          const chunks = [];
          res.on('data', c => chunks.push(c));
          res.on('end', () => {
            try {
              const body = JSON.parse(Buffer.concat(chunks).toString());
              resolve({ content: body.choices?.[0]?.message?.content || '', usage: body.usage });
            } catch { reject(new Error('Invalid LLM response')); }
          });
        });
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('LLM timeout')); });
        req.write(payload);
        req.end();
      });
    }
  } catch (err) {
    console.error('[Agent] LLM call failed:', err.message);
    return { content: '{"decision":"needs_review","confidence":30,"reasoning":"LLM call failed"}', error: true };
  }
}

// ── Confidence thresholds ─────────────────────────────────────────
const AUTO_EXECUTE_THRESHOLD = 85;    // ≥85% → auto-execute without approval
const ESCALATE_THRESHOLD     = 40;    // <40% → escalate to senior analyst
const CLOSE_THRESHOLD        = 90;    // ≥90% false-positive confidence → auto-close

// ── Agent 1: Triage Agent ─────────────────────────────────────────

class TriageAgent {
  constructor(opts = {}) {
    this.enrichmentEngine = opts.enrichmentEngine;
    this.supabase         = opts.supabase;
  }

  /**
   * triage — process an alert through automated L1 triage
   *
   * Steps:
   *  1. Enrich all IOCs in parallel
   *  2. Retrieve RAG context (similar past alerts, MITRE info)
   *  3. LLM scores: True Positive / False Positive / Needs Review
   *  4. Route based on confidence
   */
  async triage(alert) {
    const taskId = `triage-${crypto.randomUUID()}`;
    const start  = Date.now();
    console.log(`[Triage Agent] Starting triage task ${taskId} for alert: ${alert.id}`);

    // Step 1: Enrich IOCs
    const enrichments = {};
    if (alert.iocs?.length && this.enrichmentEngine) {
      const results = await Promise.allSettled(
        alert.iocs.slice(0, 10).map(async (ioc) => {
          const result = await this.enrichmentEngine.enrich(ioc.value || ioc, ioc.type || 'unknown');
          enrichments[ioc.value || ioc] = result;
        })
      );
    }

    // Step 2: RAG context
    const { context_blocks, sources } = await buildContext(alert).catch(() => ({ context_blocks: [], sources: [] }));

    // Step 3: LLM triage decision
    const systemPrompt = `You are an expert SOC Level 1 analyst performing automated alert triage.
Your job is to determine if an alert is a True Positive, False Positive, or Needs Review.
Respond with valid JSON only. No markdown, no explanation outside the JSON.

JSON format:
{
  "decision": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0-100,
  "severity": "critical" | "high" | "medium" | "low",
  "reasoning": "concise explanation",
  "ioc_verdict": {"<ioc>": "malicious|benign|suspicious"},
  "recommended_actions": ["action1", "action2"],
  "mitre_techniques": ["T1xxx"],
  "escalate_to_l2": true/false,
  "auto_close": true/false,
  "risk_score": 0-100
}`;

    const userPrompt = `Alert Details:
Title: ${alert.title}
Severity: ${alert.severity}
Source: ${alert.source}
Host: ${alert.host || 'Unknown'}
User: ${alert.user || 'Unknown'}
MITRE Tactic: ${alert.mitre_tactic || 'Unknown'}
MITRE Technique: ${alert.mitre_tech || 'Unknown'}
Rule: ${alert.rule_name || alert.rule_id || 'Unknown'}
Description: ${alert.description || 'No description'}

IOC Enrichment Results:
${JSON.stringify(enrichments, null, 2)}

Relevant Context from Knowledge Base:
${context_blocks.slice(0, 4).join('\n\n---\n\n')}

Historical False Positive Patterns: ${alert.fp_patterns || 'None on record'}

Make a triage decision based on the above evidence.`;

    const llmResponse = await llmCall(systemPrompt, userPrompt, { jsonMode: true, temperature: 0.1 });

    let decision;
    try {
      decision = JSON.parse(llmResponse.content);
    } catch {
      decision = { decision: 'needs_review', confidence: 50, reasoning: 'LLM parse error', escalate_to_l2: true, risk_score: alert.risk_score || 50 };
    }

    // Step 4: Route based on decision + confidence
    const route = this._determineRoute(decision);

    const result = {
      task_id:      taskId,
      alert_id:     alert.id,
      agent:        'triage',
      decision:     decision.decision,
      confidence:   decision.confidence,
      severity:     decision.severity || alert.severity,
      risk_score:   decision.risk_score || alert.risk_score,
      reasoning:    decision.reasoning,
      ioc_verdict:  decision.ioc_verdict || {},
      actions:      decision.recommended_actions || [],
      mitre_ttps:   decision.mitre_techniques || [],
      route,
      escalate:     decision.escalate_to_l2 || false,
      auto_close:   decision.auto_close     || false,
      enrichments,
      sources_used: sources,
      duration_ms:  Date.now() - start,
      created_at:   new Date().toISOString(),
    };

    // Persist decision
    await this._persistDecision(result);
    return result;
  }

  _determineRoute(decision) {
    if (decision.auto_close && decision.confidence >= CLOSE_THRESHOLD)    return 'auto_closed';
    if (decision.decision === 'false_positive' && decision.confidence >= AUTO_EXECUTE_THRESHOLD) return 'auto_closed';
    if (decision.decision === 'true_positive'  && decision.confidence >= AUTO_EXECUTE_THRESHOLD) return 'auto_escalated_l2';
    if (decision.escalate_to_l2)                                           return 'escalated_l2';
    if (decision.confidence < ESCALATE_THRESHOLD)                          return 'human_review';
    return 'analyst_queue';
  }

  async _persistDecision(result) {
    if (!this.supabase) return;
    try {
      await this.supabase.from('agent_decisions').insert({
        task_id:     result.task_id,
        alert_id:    result.alert_id,
        agent_type:  'triage',
        decision:    result.decision,
        confidence:  result.confidence,
        reasoning:   result.reasoning,
        route:       result.route,
        metadata:    result,
        created_at:  result.created_at,
      });
    } catch (err) {
      console.warn('[Triage Agent] Persist failed:', err.message);
    }
  }
}

// ── Agent 2: Investigation Agent ──────────────────────────────────

class InvestigationAgent {
  constructor(opts = {}) {
    this.supabase = opts.supabase;
  }

  /**
   * investigate — deep investigation of an L2-escalated alert
   *
   * Steps:
   *  1. Graph traversal: reconstruct attack chain from IOCs
   *  2. Pivot on related entities (hosts, users, IPs)
   *  3. Timeline reconstruction
   *  4. LLM generates incident narrative and recommendations
   */
  async investigate(alert, triageResult = null) {
    const taskId = `invest-${crypto.randomUUID()}`;
    const start  = Date.now();
    console.log(`[Investigation Agent] Starting investigation ${taskId} for alert: ${alert.id}`);

    // Step 1: Graph traversal
    let attackChain = null;
    const primaryIoc = alert.iocs?.[0]?.value || alert.iocs?.[0];
    if (primaryIoc) {
      attackChain = await reconstructAttackChain(primaryIoc, 4, alert.tenant_id).catch(() => null);
    }

    // Step 2: RAG context (deeper)
    const { context_blocks } = await buildContext({
      ...alert,
      mitre_tech:  alert.mitre_tech,
      mitre_tactic: alert.mitre_tactic,
    }).catch(() => ({ context_blocks: [] }));

    // Step 3: LLM investigation
    const systemPrompt = `You are an expert SOC Level 2 security analyst conducting a deep incident investigation.
Analyze the provided alert, attack chain data, and context to produce a comprehensive investigation report.
Respond with valid JSON only.

JSON format:
{
  "incident_title": "concise title",
  "executive_summary": "2-3 sentence summary for management",
  "attack_narrative": "detailed chronological attack story",
  "kill_chain_stage": "initial-access|execution|persistence|...",
  "threat_actor_hypothesis": "APT group or campaign if identifiable",
  "affected_assets": ["host1", "host2"],
  "blast_radius": "low|medium|high|critical",
  "recommended_containment": ["action1", "action2"],
  "recommended_eradication": ["action1"],
  "recommended_recovery": ["action1"],
  "iocs_to_block": ["ioc1", "ioc2"],
  "escalate_to_ir": true/false,
  "confidence": 0-100,
  "mitre_chain": [{"id":"T1xxx","name":"...","tactic":"..."}]
}`;

    const userPrompt = `Alert: ${JSON.stringify({
      id: alert.id, title: alert.title, severity: alert.severity,
      host: alert.host, user: alert.user, description: alert.description,
      mitre_tactic: alert.mitre_tactic, mitre_tech: alert.mitre_tech,
      iocs: alert.iocs?.slice(0,10),
    }, null, 2)}

Attack Chain from Graph DB:
${JSON.stringify(attackChain?.chain?.slice(0,8) || [], null, 2)}

Related Nodes: ${attackChain?.nodes?.length || 0} nodes, ${attackChain?.edges?.length || 0} edges

Triage Result: ${JSON.stringify(triageResult || {}, null, 2)}

Context from Knowledge Base:
${context_blocks.slice(0, 5).join('\n\n---\n\n')}`;

    const llmResponse = await llmCall(systemPrompt, userPrompt, { jsonMode: true, temperature: 0.15, maxTokens: 3000 });

    let report;
    try {
      report = JSON.parse(llmResponse.content);
    } catch {
      report = {
        incident_title: alert.title,
        executive_summary: 'Investigation could not be automated. Manual review required.',
        attack_narrative: alert.description || '',
        confidence: 30,
        escalate_to_ir: true,
        recommended_containment: ['Isolate affected host', 'Reset affected user credentials'],
      };
    }

    const result = {
      task_id:      taskId,
      alert_id:     alert.id,
      agent:        'investigation',
      report,
      attack_chain: attackChain,
      duration_ms:  Date.now() - start,
      created_at:   new Date().toISOString(),
    };

    await this._persistInvestigation(result);
    return result;
  }

  async _persistInvestigation(result) {
    if (!this.supabase) return;
    try {
      await this.supabase.from('agent_investigations').insert({
        task_id:    result.task_id,
        alert_id:   result.alert_id,
        report:     result.report,
        created_at: result.created_at,
      });
    } catch (err) {
      console.warn('[Investigation Agent] Persist failed:', err.message);
    }
  }
}

// ── Agent 3: Response Agent ───────────────────────────────────────

class ResponseAgent {
  constructor(opts = {}) {
    this.soarEngine    = opts.soarEngine;
    this.supabase      = opts.supabase;
    this.notifyService = opts.notifyService;
  }

  /**
   * respond — execute approved response plan
   *
   * Steps:
   *  1. Check human-in-the-loop approval if required
   *  2. Execute SOAR playbooks
   *  3. Update ticket (Jira/ServiceNow)
   *  4. Notify stakeholders
   *  5. Record response metrics
   */
  async respond(investigationResult, approvedBy = null) {
    const taskId  = `response-${crypto.randomUUID()}`;
    const start   = Date.now();
    const report  = investigationResult.report || {};
    const actions = [];

    console.log(`[Response Agent] Executing response ${taskId}`);

    // Step 1: Human-in-the-loop check
    if (report.escalate_to_ir && !approvedBy) {
      return {
        task_id:    taskId,
        status:     'awaiting_approval',
        message:    'IR escalation requires human approval. Response paused.',
        requires_approval_from: ['IR_TEAM', 'CISO'],
      };
    }

    // Step 2: Execute containment actions
    if (report.recommended_containment && this.soarEngine) {
      for (const action of report.recommended_containment.slice(0, 5)) {
        try {
          const playbookResult = await this.soarEngine.executeAction(action, investigationResult);
          actions.push({ action, status: 'executed', result: playbookResult });
        } catch (err) {
          actions.push({ action, status: 'failed', error: err.message });
        }
      }
    }

    // Step 3: Block IOCs
    if (report.iocs_to_block?.length && this.soarEngine) {
      for (const ioc of report.iocs_to_block.slice(0, 20)) {
        try {
          await this.soarEngine.blockIoc(ioc, investigationResult.alert_id);
          actions.push({ action: `block_ioc:${ioc}`, status: 'executed' });
        } catch (err) {
          actions.push({ action: `block_ioc:${ioc}`, status: 'failed', error: err.message });
        }
      }
    }

    // Step 4: Create/update incident ticket
    let ticketId = null;
    if (this.supabase) {
      const { data: ticket } = await this.supabase.from('cases').insert({
        title:        report.incident_title || investigationResult.alert_id,
        description:  report.executive_summary,
        severity:     report.blast_radius || 'medium',
        status:       'in_progress',
        narrative:    report.attack_narrative,
        response_actions: actions,
        agent_assigned: 'response_agent',
        approved_by:  approvedBy,
        created_at:   new Date().toISOString(),
      }).select('id').single();
      ticketId = ticket?.id;
    }

    // Step 5: Notify
    if (this.notifyService) {
      await this.notifyService.notify({
        channel: 'security_team',
        message: `[Wadjet Eye] Incident Response Executed\nAlert: ${investigationResult.alert_id}\nActions: ${actions.filter(a => a.status === 'executed').length}/${actions.length} completed\nCase: ${ticketId || 'N/A'}`,
      }).catch(() => {});
    }

    const result = {
      task_id:          taskId,
      alert_id:         investigationResult.alert_id,
      agent:            'response',
      status:           'completed',
      actions_executed: actions.filter(a => a.status === 'executed').length,
      actions_failed:   actions.filter(a => a.status === 'failed').length,
      actions,
      ticket_id:        ticketId,
      approved_by:      approvedBy,
      duration_ms:      Date.now() - start,
      created_at:       new Date().toISOString(),
    };

    await this._persistResponse(result);
    return result;
  }

  async _persistResponse(result) {
    if (!this.supabase) return;
    try {
      await this.supabase.from('agent_responses').insert({
        task_id:   result.task_id,
        alert_id:  result.alert_id,
        actions:   result.actions,
        status:    result.status,
        created_at: result.created_at,
      });
    } catch (err) {
      console.warn('[Response Agent] Persist failed:', err.message);
    }
  }
}

// ── Orchestrator ──────────────────────────────────────────────────

class AgentOrchestrator {
  constructor(opts = {}) {
    this.triageAgent       = new TriageAgent(opts);
    this.investigationAgent = new InvestigationAgent(opts);
    this.responseAgent     = new ResponseAgent(opts);
    this.supabase          = opts.supabase;
  }

  /**
   * dispatch — route a task to the appropriate agent
   */
  async dispatch(task) {
    switch (task.agent_type) {
      case 'triage':
        return this.triageAgent.triage(task.context?.alert || task);

      case 'investigation':
        return this.investigationAgent.investigate(
          task.context?.alert || task,
          task.context?.triage_result
        );

      case 'response':
        return this.responseAgent.respond(
          task.context?.investigation_result || task,
          task.context?.approved_by
        );

      case 'full_pipeline':
        return this.runFullPipeline(task.context?.alert || task);

      default:
        throw new Error(`Unknown agent type: ${task.agent_type}`);
    }
  }

  /**
   * runFullPipeline — end-to-end automated processing:
   * Alert → Triage → (if escalated) Investigation → (if approved) Response
   */
  async runFullPipeline(alert) {
    const pipeline = { alert_id: alert.id, stages: [], started_at: new Date().toISOString() };

    // Stage 1: Triage
    const triage = await this.triageAgent.triage(alert);
    pipeline.stages.push({ stage: 'triage', result: triage });
    pipeline.triage = triage;

    if (triage.route === 'auto_closed') {
      pipeline.status = 'auto_closed';
      pipeline.completed_at = new Date().toISOString();
      return pipeline;
    }

    // Stage 2: Investigation (for L2 escalations)
    if (['auto_escalated_l2', 'escalated_l2', 'human_review'].includes(triage.route)) {
      const investigation = await this.investigationAgent.investigate(alert, triage);
      pipeline.stages.push({ stage: 'investigation', result: investigation });
      pipeline.investigation = investigation;

      // Stage 3: Response (auto only for high-confidence, low-risk decisions)
      const canAutoRespond = investigation.report?.confidence >= AUTO_EXECUTE_THRESHOLD
                          && !investigation.report?.escalate_to_ir;

      if (canAutoRespond) {
        const response = await this.responseAgent.respond(investigation);
        pipeline.stages.push({ stage: 'response', result: response });
        pipeline.response = response;
        pipeline.status = 'auto_responded';
      } else {
        pipeline.status = 'awaiting_approval';
        pipeline.approval_required = {
          reason:    investigation.report?.escalate_to_ir ? 'IR escalation' : 'Low confidence',
          approvers: ['SENIOR_ANALYST', 'TEAM_LEAD'],
        };
      }
    }

    pipeline.completed_at = new Date().toISOString();
    return pipeline;
  }

  /**
   * getDecisionHistory — analyst feedback for continuous learning
   */
  async getDecisionHistory(tenantId, limit = 100) {
    if (!this.supabase) return [];
    const { data } = await this.supabase
      .from('agent_decisions')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);
    return data || [];
  }

  /**
   * recordFeedback — analyst overrides feed back into learning loop
   * This data is used to retrain prompts and adjust confidence thresholds.
   */
  async recordFeedback(taskId, feedback) {
    if (!this.supabase) return;
    await this.supabase.from('agent_feedback').insert({
      task_id:     taskId,
      analyst_id:  feedback.analyst_id,
      original_decision: feedback.original_decision,
      corrected_decision: feedback.corrected_decision,
      reason:      feedback.reason,
      created_at:  new Date().toISOString(),
    });
  }
}

module.exports = {
  AgentOrchestrator,
  TriageAgent,
  InvestigationAgent,
  ResponseAgent,
};
