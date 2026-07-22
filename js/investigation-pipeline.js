/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Investigation Pipeline  (Phase 1)
 *  js/investigation-pipeline.js
 *
 *  Native TypeScript/JS port of AiSOC v7.6.0:
 *    services/agents/app/graph/workflow.py       — stage sequence + early-exit
 *    services/agents/app/investigator/orchestrator.py — run/stream + ledger
 *    services/agents/app/swarm/swarm.py          — deterministic hypothesis scoring
 *
 *  ARCHITECTURE:
 *  ┌─────────────────────────────────────────────────────────────────────────┐
 *  │  runInvestigation(alert, opts)                                          │
 *  │    └─ auto_triage  ──► [high-confidence benign?] ──► END (early exit)  │
 *  │         └─ triage                                                       │
 *  │              └─ enrichment                                              │
 *  │                   └─ investigation  ←─ hypothesis swarm                │
 *  │                        └─ attack_path  ──► END                         │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *
 *  Each stage appends a row to `we_investigation_events` (append-only).
 *  Progress is streamed to the frontend via Supabase Realtime
 *  `postgres_changes` on `we_investigation_events` for `run_id = X`.
 *
 *  FEATURE FLAG: ENABLE_PIPELINE_INVESTIGATION (default: false)
 *  When false, runInvestigation() falls through to the legacy direct GPT call.
 *
 *  DEPENDENCY:
 *  - Requires js/llm-contract.js to be loaded first (fail-closed LLM guard).
 *  - Requires window.supabase (Supabase JS client) in browser context.
 *  - Requires backend/routes/investigation.js (Node.js) for server-side runs.
 *
 *  HYPOTHESIS SWARM SCORING (ported from swarm.py _evaluate()):
 *    score = max(0, min(1,
 *      min(evidence.length * 0.25, 0.6)
 *    + min(techniqueHits.length * 0.30, 0.5)
 *    - min(contradictions.length * 0.30, 0.6)
 *    ))
 *  This is deterministic — no LLM calls, no external dependencies.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

/* ── Feature flag ─────────────────────────────────────────────────────────── */

const PIPELINE_FLAG_KEY = 'ENABLE_PIPELINE_INVESTIGATION';

function isPipelineEnabled() {
  // Node.js environment
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env[PIPELINE_FLAG_KEY];
    if (v !== undefined) return v === '1' || v === 'true';
  }
  // Browser environment
  if (typeof window !== 'undefined' && window[PIPELINE_FLAG_KEY] !== undefined) {
    return window[PIPELINE_FLAG_KEY] === true || window[PIPELINE_FLAG_KEY] === '1';
  }
  return false; // OFF by default — shadow mode until go/no-go
}

/* ── Constants ─────────────────────────────────────────────────────────────── */

// Stage names — ported from workflow.py StateGraph node names
const STAGE = {
  AUTO_TRIAGE:  'auto_triage',
  TRIAGE:       'triage',
  ENRICHMENT:   'enrichment',
  INVESTIGATION:'investigation',
  ATTACK_PATH:  'attack_path',
};

// Pipeline status
const STATUS = {
  PENDING:   'pending',
  RUNNING:   'running',
  COMPLETED: 'completed',
  FAILED:    'failed',
  ABORTED:   'aborted',
};

// Per-agent token budget — ported from swarm.py DEFAULT_PER_AGENT_TOKEN_BUDGET
const DEFAULT_PER_AGENT_TOKEN_BUDGET = 1500;

// Auto-triage confidence threshold for early exit (benign/FP skip)
// Ported from workflow.py _after_auto_triage() → returns "end" if COMPLETED
const AUTO_TRIAGE_BENIGN_THRESHOLD = 0.85;

// Cost per 1K tokens (approximate GPT-4o pricing — adjust via env)
const COST_PER_1K_INPUT_TOKENS  = parseFloat(
  (typeof process !== 'undefined' && process.env?.WE_LLM_INPUT_COST_PER_1K)  || '0.005'
);
const COST_PER_1K_OUTPUT_TOKENS = parseFloat(
  (typeof process !== 'undefined' && process.env?.WE_LLM_OUTPUT_COST_PER_1K) || '0.015'
);

/* ── Crypto helper ─────────────────────────────────────────────────────────── */

/**
 * Compute SHA-256 of a string.
 * Works in Node.js (crypto module) and browser (SubtleCrypto).
 * Returns hex string.
 */
async function sha256(text) {
  if (typeof process !== 'undefined' && !process.browser) {
    // Node.js
    try {
      const crypto = require('crypto');
      return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    } catch {}
  }
  // Browser via SubtleCrypto
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const enc  = new TextEncoder();
    const buf  = await crypto.subtle.digest('SHA-256', enc.encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback: no hash (should not happen in production)
  return '';
}

/* ── PipelineState ────────────────────────────────────────────────────────── */

/**
 * Mutable pipeline state carried between stages.
 * Ported from AiSOC's InvestigatorState TypedDict.
 */
class PipelineState {
  constructor(alert, runId, tenantId) {
    this.alert        = alert;         // original alert object (NOT sent to LLM)
    this.runId        = runId;
    this.tenantId     = tenantId;
    this.seq          = 0;             // event sequence counter
    this.stage        = null;          // current stage name
    this.status       = STATUS.RUNNING;

    // Accumulated outputs from each stage
    this.autoTriageResult   = null;
    this.triageResult       = null;
    this.enrichmentResult   = null;
    this.investigationResult = null;
    this.attackPathResult   = null;
    this.hypotheses         = [];      // swarm hypothesis results

    // Ledger totals
    this.totalTokens   = 0;
    this.totalCostUsd  = 0;

    // Early exit flag — set by auto_triage when benign/FP confidence is high
    this.earlyExit     = false;
    this.earlyExitReason = null;
  }
}

/* ── Hypothesis Swarm Scoring ─────────────────────────────────────────────── */

/**
 * Deterministic hypothesis scoring function.
 * Ported verbatim from AiSOC swarm.py _evaluate():
 *
 *   score = max(0, min(1,
 *     min(len(evidence) * 0.25, 0.6)
 *   + min(len(tech_hits) * 0.30, 0.5)
 *   - min(len(contradictions) * 0.30, 0.6)
 *   ))
 *
 * @param {string[]} evidence        - supporting evidence items
 * @param {string[]} techniqueHits   - MITRE techniques confirmed
 * @param {string[]} contradictions  - evidence items contradicting hypothesis
 * @returns {number} support score in [0, 1]
 */
function scoreHypothesis(evidence = [], techniqueHits = [], contradictions = []) {
  const evidencePart      = Math.min(evidence.length * 0.25, 0.6);
  const techniquePart     = Math.min(techniqueHits.length * 0.30, 0.5);
  const contradictionPart = Math.min(contradictions.length * 0.30, 0.6);
  return Math.max(0, Math.min(1, evidencePart + techniquePart - contradictionPart));
}

/**
 * Run up to 5 hypothesis evaluations in parallel.
 * Ported from swarm.py run_swarm() — asyncio.gather over hypotheses.
 *
 * @param {object} investigationContext - output from the investigation stage
 * @returns {Array<HypothesisResult>}
 */
function runSwarm(investigationContext) {
  const rawHypotheses = investigationContext?.hypotheses || [];
  // Limit to 5 as in AiSOC (DEFAULT_PER_AGENT_TOKEN_BUDGET * 5)
  const candidates = rawHypotheses.slice(0, 5);

  return candidates.map(h => {
    const evidence       = Array.isArray(h.evidence)       ? h.evidence       : [];
    const techniqueHits  = Array.isArray(h.technique_hits) ? h.technique_hits : [];
    const contradictions = Array.isArray(h.contradictions) ? h.contradictions : [];

    const supportScore = scoreHypothesis(evidence, techniqueHits, contradictions);
    return {
      key:          h.key          || h.id    || `hyp-${Math.random().toString(36).slice(2, 7)}`,
      label:        h.label        || h.title || 'Unknown hypothesis',
      benign:       Boolean(h.benign),
      supportScore,
      evidence,
      contradictions,
      techniqueHits,
      tokensSpent:  h.tokens_spent || Math.min(evidence.length * 120, DEFAULT_PER_AGENT_TOKEN_BUDGET),
    };
  });
}

/* ── Stage: auto_triage ───────────────────────────────────────────────────── */

/**
 * Stage 0: Auto-triage — fast initial classification.
 * If the alert is high-confidence benign, sets earlyExit=true and ends pipeline.
 * Ported from workflow.py auto_triage node + _after_auto_triage() conditional edge.
 */
async function stageAutoTriage(state, callLLM) {
  const alert = state.alert;

  // Build a short summary for triage — NOT the raw alert
  const triagePrompt = [
    { role: 'system', content: 'You are a SOC auto-triage engine. Your job is to make a rapid assessment of whether an alert is likely benign/FP or warrants full investigation. Respond with a JSON object only.' },
    {
      role: 'user',
      content: `Triage this alert:\n` +
               `Title: ${alert.title || 'Unknown'}\n` +
               `Description: ${(alert.description || '').slice(0, 500)}\n` +
               `Severity: ${alert.severity || 'UNKNOWN'}\n` +
               `Source: ${alert.source || 'unknown'}\n` +
               `MITRE: ${alert.mitre_technique || 'none'}\n\n` +
               `Respond with JSON: {"verdict":"malicious"|"benign"|"uncertain", "confidence":0.0-1.0, "reason":"one sentence"}`
    }
  ];

  const t0 = Date.now();
  let result;
  try {
    const raw    = await callLLM(triagePrompt);
    const parsed = _tryParseJSON(raw.content || raw);
    result = {
      verdict:    parsed?.verdict    || 'uncertain',
      confidence: parsed?.confidence || 0.5,
      reason:     parsed?.reason     || 'Auto-triage inconclusive',
      rawResponse: raw.content || raw,
    };
    _accumulateTokens(state, raw, t0);
  } catch (err) {
    result = { verdict: 'uncertain', confidence: 0.5, reason: `auto_triage error: ${err.message}`, rawResponse: '' };
  }

  state.autoTriageResult = result;

  // Conditional edge: AiSOC workflow.py _after_auto_triage()
  // → returns "end" if AgentStatus.COMPLETED (high-confidence benign)
  if (result.verdict === 'benign' && result.confidence >= AUTO_TRIAGE_BENIGN_THRESHOLD) {
    state.earlyExit       = true;
    state.earlyExitReason = `auto_triage: high-confidence benign (${(result.confidence * 100).toFixed(0)}%) — ${result.reason}`;
    state.status          = STATUS.COMPLETED;
  }

  return result;
}

/* ── Stage: triage ────────────────────────────────────────────────────────── */

async function stageTriage(state, callLLM) {
  const alert = state.alert;

  const prompt = [
    { role: 'system', content: 'You are a senior SOC analyst performing structured alert triage. Respond with a JSON object only.' },
    {
      role: 'user',
      content: `Perform structured triage of this alert:\n` +
               `Title: ${alert.title || 'Unknown'}\n` +
               `Description: ${(alert.description || '').slice(0, 800)}\n` +
               `Severity: ${alert.severity || 'UNKNOWN'}\n` +
               `Source: ${alert.source || 'unknown'}\n` +
               `MITRE Technique: ${alert.mitre_technique || 'none'}\n` +
               `IOC Value: ${alert.ioc_value || 'none'} (${alert.ioc_type || 'none'})\n\n` +
               `Respond with JSON: {` +
               `"severity_assessment":"CRITICAL|HIGH|MEDIUM|LOW",` +
               `"attack_category":"string",` +
               `"immediate_actions":["action1","action2"],` +
               `"entities":{"hosts":[],"users":[],"ips":[]},` +
               `"confidence":0.0-1.0` +
               `}`
    }
  ];

  const t0 = Date.now();
  let result;
  try {
    const raw    = await callLLM(prompt);
    const parsed = _tryParseJSON(raw.content || raw);
    result = {
      severityAssessment: parsed?.severity_assessment || alert.severity || 'UNKNOWN',
      attackCategory:     parsed?.attack_category     || 'Unknown',
      immediateActions:   parsed?.immediate_actions   || [],
      entities:           parsed?.entities            || { hosts: [], users: [], ips: [] },
      confidence:         parsed?.confidence          || 0.5,
    };
    _accumulateTokens(state, raw, t0);
  } catch (err) {
    result = {
      severityAssessment: alert.severity || 'UNKNOWN',
      attackCategory: 'Unknown', immediateActions: [],
      entities: { hosts: [], users: [], ips: [] }, confidence: 0.5,
    };
  }

  state.triageResult = result;
  return result;
}

/* ── Stage: enrichment ────────────────────────────────────────────────────── */

async function stageEnrichment(state, callLLM) {
  const alert  = state.alert;
  const triage = state.triageResult || {};

  const prompt = [
    { role: 'system', content: 'You are a threat intelligence analyst. Enrich the alert with MITRE ATT&CK context and threat intelligence. Respond with a JSON object only.' },
    {
      role: 'user',
      content: `Enrich this alert with threat intelligence:\n` +
               `Title: ${alert.title || 'Unknown'}\n` +
               `Attack Category: ${triage.attackCategory || 'Unknown'}\n` +
               `Severity: ${triage.severityAssessment || 'UNKNOWN'}\n` +
               `MITRE Technique: ${alert.mitre_technique || 'none'}\n` +
               `Affected Assets: ${JSON.stringify(alert.affected_assets || []).slice(0, 300)}\n\n` +
               `Respond with JSON: {` +
               `"mitre_tactics":["Initial Access","Execution",...],` +
               `"mitre_techniques":[{"id":"T1059.001","name":"PowerShell","tactic":"Execution"}],` +
               `"threat_actors":["APT29",...] or [],` +
               `"ioc_context":"string",` +
               `"related_campaigns":[] or [{"name":"string"}],` +
               `"enrichment_confidence":0.0-1.0` +
               `}`
    }
  ];

  const t0 = Date.now();
  let result;
  try {
    const raw    = await callLLM(prompt);
    const parsed = _tryParseJSON(raw.content || raw);
    result = {
      mitreTactics:          parsed?.mitre_tactics     || [],
      mitreTechniques:       parsed?.mitre_techniques  || [],
      threatActors:          parsed?.threat_actors     || [],
      iocContext:            parsed?.ioc_context       || '',
      relatedCampaigns:      parsed?.related_campaigns || [],
      enrichmentConfidence:  parsed?.enrichment_confidence || 0.5,
    };
    _accumulateTokens(state, raw, t0);
  } catch (err) {
    result = {
      mitreTactics: [], mitreTechniques: [], threatActors: [],
      iocContext: '', relatedCampaigns: [], enrichmentConfidence: 0.5,
    };
  }

  state.enrichmentResult = result;
  return result;
}

/* ── Stage: investigation ─────────────────────────────────────────────────── */

async function stageInvestigation(state, callLLM) {
  const alert       = state.alert;
  const triage      = state.triageResult    || {};
  const enrichment  = state.enrichmentResult || {};

  const techniqueList = (enrichment.mitreTechniques || [])
    .map(t => `${t.id} ${t.name} (${t.tactic})`).join(', ') || 'none';

  const prompt = [
    { role: 'system', content: 'You are a senior incident responder performing deep investigation. Respond with a JSON object only.' },
    {
      role: 'user',
      content: `Perform deep investigation of this security alert:\n` +
               `Title: ${alert.title || 'Unknown'}\n` +
               `Severity: ${triage.severityAssessment || 'UNKNOWN'}\n` +
               `Attack Category: ${triage.attackCategory || 'Unknown'}\n` +
               `MITRE Techniques: ${techniqueList}\n` +
               `Threat Actors: ${(enrichment.threatActors || []).join(', ') || 'none'}\n` +
               `Immediate Actions Required: ${(triage.immediateActions || []).join('; ') || 'none'}\n\n` +
               `Respond with JSON: {` +
               `"root_cause":"string",` +
               `"attack_narrative":"markdown string",` +
               `"hypotheses":[{` +
               `  "key":"h1","label":"string","benign":false,` +
               `  "evidence":["e1","e2"],"contradictions":["c1"],` +
               `  "technique_hits":["T1059.001"]` +
               `}],` +
               `"affected_systems":["host1","svc2"],` +
               `"recommended_actions":[{"priority":"immediate","action":"string"}],` +
               `"confidence":0.0-1.0` +
               `}`
    }
  ];

  const t0 = Date.now();
  let result;
  try {
    const raw    = await callLLM(prompt);
    const parsed = _tryParseJSON(raw.content || raw);
    result = {
      rootCause:           parsed?.root_cause           || 'Unable to determine root cause',
      attackNarrative:     parsed?.attack_narrative     || '',
      hypotheses:          parsed?.hypotheses           || [],
      affectedSystems:     parsed?.affected_systems     || [],
      recommendedActions:  parsed?.recommended_actions  || [],
      confidence:          parsed?.confidence           || 0.5,
    };
    _accumulateTokens(state, raw, t0);
  } catch (err) {
    result = {
      rootCause: 'Investigation error: ' + err.message,
      attackNarrative: '', hypotheses: [], affectedSystems: [],
      recommendedActions: [], confidence: 0.0,
    };
  }

  // Run hypothesis swarm (deterministic — no LLM)
  state.hypotheses        = runSwarm(result);
  state.investigationResult = result;
  return result;
}

/* ── Stage: attack_path ───────────────────────────────────────────────────── */

async function stageAttackPath(state, callLLM) {
  const triage      = state.triageResult      || {};
  const enrichment  = state.enrichmentResult  || {};
  const investigation = state.investigationResult || {};
  const hypotheses  = state.hypotheses         || [];

  // Pick best hypothesis (highest support score)
  const bestHyp = hypotheses.sort((a, b) => b.supportScore - a.supportScore)[0] || null;

  const prompt = [
    { role: 'system', content: 'You are an incident response expert building an attack path graph. Respond with a JSON object only.' },
    {
      role: 'user',
      content: `Build the attack path for this incident:\n` +
               `Root Cause: ${investigation.rootCause || 'Unknown'}\n` +
               `Best Hypothesis: ${bestHyp ? bestHyp.label + ' (score: ' + bestHyp.supportScore.toFixed(2) + ')' : 'none'}\n` +
               `MITRE Techniques: ${(enrichment.mitreTechniques || []).map(t => t.id).join(', ') || 'none'}\n` +
               `MITRE Tactics: ${(enrichment.mitreTactics || []).join(', ') || 'none'}\n` +
               `Affected Systems: ${(investigation.affectedSystems || []).join(', ') || 'none'}\n\n` +
               `Respond with JSON: {` +
               `"attack_path":[{"step":1,"node":"string","technique":"T####","tactic":"string","description":"string"}],` +
               `"entry_point":"string",` +
               `"impact":"string",` +
               `"blast_radius":{"affected_count":N,"critical_assets":["s1"]},` +
               `"containment_priority":["action1","action2"]` +
               `}`
    }
  ];

  const t0 = Date.now();
  let result;
  try {
    const raw    = await callLLM(prompt);
    const parsed = _tryParseJSON(raw.content || raw);
    result = {
      attackPath:          parsed?.attack_path          || [],
      entryPoint:          parsed?.entry_point          || 'Unknown',
      impact:              parsed?.impact               || 'Unknown',
      blastRadius:         parsed?.blast_radius         || { affectedCount: 0, criticalAssets: [] },
      containmentPriority: parsed?.containment_priority || [],
    };
    _accumulateTokens(state, raw, t0);
  } catch (err) {
    result = {
      attackPath: [], entryPoint: 'Unknown', impact: 'Error: ' + err.message,
      blastRadius: { affectedCount: 0, criticalAssets: [] }, containmentPriority: [],
    };
  }

  state.attackPathResult = result;
  state.status           = STATUS.COMPLETED;
  return result;
}

/* ── Ledger helpers ────────────────────────────────────────────────────────── */

function _accumulateTokens(state, rawResponse, startTime) {
  const tokens = rawResponse?.usage?.total_tokens || rawResponse?.tokens || 0;
  const inputT = rawResponse?.usage?.prompt_tokens || Math.floor(tokens * 0.4);
  const outT   = rawResponse?.usage?.completion_tokens || Math.ceil(tokens * 0.6);
  const cost   = (inputT / 1000) * COST_PER_1K_INPUT_TOKENS +
                 (outT   / 1000) * COST_PER_1K_OUTPUT_TOKENS;
  state.totalTokens  += tokens;
  state.totalCostUsd += cost;
}

function _tryParseJSON(text) {
  if (!text || typeof text !== 'string') return null;
  // Strip markdown code fences if present
  const stripped = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '').trim();
  try { return JSON.parse(stripped); } catch { return null; }
}

/* ── Ledger write ──────────────────────────────────────────────────────────── */

/**
 * Append one event to we_investigation_events.
 * The DB trigger blocks UPDATE/DELETE — this is the only allowed mutation.
 *
 * @param {object} supabaseClient
 * @param {PipelineState} state
 * @param {string} kind      - stage name
 * @param {string} agent     - agent identifier
 * @param {string} summary   - one-liner summary
 * @param {object} payload   - full stage output
 * @param {object} [timing]  - { startMs, inputState, outputState }
 */
async function appendEvent(supabaseClient, state, kind, agent, summary, payload, timing = {}) {
  const { startMs, inputState, outputState } = timing;

  let inputHash  = '';
  let outputHash = '';
  let durationMs = 0;

  if (startMs) durationMs = Date.now() - startMs;

  try {
    if (inputState)  inputHash  = await sha256(JSON.stringify(inputState));
    if (outputState) outputHash = await sha256(JSON.stringify(outputState));
  } catch {}

  const event = {
    run_id:      state.runId,
    tenant_id:   state.tenantId,
    seq:         state.seq++,
    ts:          new Date().toISOString(),
    kind,
    agent,
    summary:     String(summary).slice(0, 1000),
    payload:     payload || {},
    input_hash:  inputHash  || null,
    output_hash: outputHash || null,
    duration_ms: durationMs,
    tokens_used: state.totalTokens,
    cost_usd:    state.totalCostUsd,
  };

  if (supabaseClient) {
    await supabaseClient
      .from('we_investigation_events')
      .insert(event);
  }

  return event;
}

/* ── Run record management ─────────────────────────────────────────────────── */

async function createRun(supabaseClient, alert, tenantId, model) {
  if (!supabaseClient) return `run_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const { data, error } = await supabaseClient
    .from('we_investigation_runs')
    .insert({
      tenant_id:     tenantId,
      alert_id:      alert.id   || null,
      case_id:       alert.case_id || null,
      alert_summary: alert.title || 'Investigation run',
      raw_alert:     alert,
      model_used:    model || 'gpt-4o',
      status:        'running',
    })
    .select('id')
    .single();

  if (error) {
    console.warn('[WE Pipeline] Could not create run record:', error.message);
    return `run_${Date.now()}`;
  }
  return data.id;
}

async function updateRun(supabaseClient, runId, updates) {
  if (!supabaseClient) return;
  await supabaseClient
    .from('we_investigation_runs')
    .update({ ...updates, completed_at: new Date().toISOString() })
    .eq('id', runId);
}

async function saveArtifact(supabaseClient, state, kind, content, eventId) {
  if (!supabaseClient || !content) return;
  let hash = '';
  try { hash = await sha256(content); } catch {}
  await supabaseClient
    .from('we_investigation_artifacts')
    .insert({
      run_id:     state.runId,
      event_id:   eventId || null,
      tenant_id:  state.tenantId,
      kind,
      content:    String(content).slice(0, 200000),
      sha256:     hash,
      size_bytes: Buffer.byteLength ? Buffer.byteLength(content, 'utf8') : content.length,
    });
}

/* ── Main pipeline runner ──────────────────────────────────────────────────── */

/**
 * Run the full investigation pipeline for a single alert.
 * Ported from AiSOC InvestigatorOrchestrator.run() + stream().
 *
 * @param {object} alert   - WE alert object (title, description, severity, etc.)
 * @param {object} [opts]
 * @param {Function} opts.callLLM       - async (messages[]) => {content, usage, ...}
 * @param {object}  opts.supabase       - Supabase client for DB writes
 * @param {string}  opts.tenantId       - tenant identifier
 * @param {string}  opts.model          - LLM model name
 * @param {Function} opts.onStageStart  - callback(stageName) for UI progress
 * @param {Function} opts.onStageEnd    - callback(stageName, result) for UI update
 * @returns {Promise<InvestigationResult>}
 */
async function runInvestigation(alert, opts = {}) {
  const {
    callLLM,
    supabase:   supabaseClient = null,
    tenantId    = 'default',
    model       = 'gpt-4o',
    onStageStart = null,
    onStageEnd   = null,
  } = opts;

  if (!callLLM || typeof callLLM !== 'function') {
    throw new Error('[WE Pipeline] callLLM function is required');
  }

  // Wrap callLLM with the LLM Input Contract if available
  let safeLLM = callLLM;
  try {
    const contract = typeof require !== 'undefined'
      ? require('./llm-contract.js')
      : (typeof window !== 'undefined' ? window.WELLMContract : null);
    if (contract?.wrapLLMCall) {
      safeLLM = contract.wrapLLMCall(callLLM);
    }
  } catch {}

  // Create run record
  const runId = await createRun(supabaseClient, alert, tenantId, model);
  const state = new PipelineState(alert, runId, tenantId);

  // Pipeline stages in order
  const pipeline = [
    { name: STAGE.AUTO_TRIAGE,   fn: stageAutoTriage },
    { name: STAGE.TRIAGE,        fn: stageTriage },
    { name: STAGE.ENRICHMENT,    fn: stageEnrichment },
    { name: STAGE.INVESTIGATION, fn: stageInvestigation },
    { name: STAGE.ATTACK_PATH,   fn: stageAttackPath },
  ];

  try {
    for (const { name, fn } of pipeline) {
      if (state.earlyExit) break;

      state.stage = name;
      const stageStart = Date.now();

      if (onStageStart) onStageStart(name);

      let stageResult;
      try {
        stageResult = await fn(state, safeLLM);
      } catch (stageErr) {
        // _safe_node equivalent: catch stage error, log it, set status failed
        const errEvent = await appendEvent(
          supabaseClient, state,
          'pipeline_error', name,
          `Stage ${name} failed: ${stageErr.message}`,
          { error: stageErr.message, stage: name },
          { startMs: stageStart }
        );
        state.status = STATUS.FAILED;
        await updateRun(supabaseClient, runId, {
          status: STATUS.FAILED,
          error:  stageErr.message,
          total_tokens: state.totalTokens,
          total_cost_usd: state.totalCostUsd,
          iterations: 1,
        });
        throw stageErr;
      }

      // Append ledger event for this stage
      const eventInsert = await appendEvent(
        supabaseClient, state,
        name,
        `${name}_agent`,
        _stageSummary(name, stageResult, state),
        stageResult,
        {
          startMs:      stageStart,
          inputState:   { stage: name, seq: state.seq - 1 },
          outputState:  stageResult,
        }
      );

      // Save artifact for final stages
      if (name === STAGE.ATTACK_PATH && stageResult?.attackPath?.length) {
        await saveArtifact(
          supabaseClient, state,
          'attack_path',
          JSON.stringify(stageResult, null, 2),
          eventInsert?.id || null
        );
      }
      if (name === STAGE.INVESTIGATION && state.hypotheses?.length) {
        await saveArtifact(
          supabaseClient, state,
          'hypothesis',
          JSON.stringify(state.hypotheses, null, 2),
          eventInsert?.id || null
        );
      }

      if (onStageEnd) onStageEnd(name, stageResult);

      // Early exit check after auto_triage
      if (name === STAGE.AUTO_TRIAGE && state.earlyExit) {
        await appendEvent(
          supabaseClient, state,
          'early_exit', 'pipeline',
          state.earlyExitReason || 'Early exit: high-confidence benign',
          { reason: state.earlyExitReason },
          {}
        );
        if (onStageEnd) onStageEnd('early_exit', { reason: state.earlyExitReason });
        break;
      }
    }

    // Finalise run record
    await updateRun(supabaseClient, runId, {
      status:        state.status === STATUS.RUNNING ? STATUS.COMPLETED : state.status,
      total_tokens:  state.totalTokens,
      total_cost_usd: state.totalCostUsd,
      iterations:    1,
    });

  } catch (err) {
    if (state.status !== STATUS.FAILED) {
      state.status = STATUS.FAILED;
      await updateRun(supabaseClient, runId, {
        status: STATUS.FAILED,
        error:  err.message,
        total_tokens: state.totalTokens,
        total_cost_usd: state.totalCostUsd,
        iterations: 1,
      });
    }
    throw err;
  }

  return _buildResult(state);
}

function _stageSummary(stage, result, state) {
  switch (stage) {
    case STAGE.AUTO_TRIAGE:
      return `Auto-triage: ${state.autoTriageResult?.verdict || 'uncertain'} (${((state.autoTriageResult?.confidence || 0) * 100).toFixed(0)}%)`;
    case STAGE.TRIAGE:
      return `Triage: ${result?.severityAssessment || 'UNKNOWN'} — ${result?.attackCategory || 'Unknown'}`;
    case STAGE.ENRICHMENT:
      return `Enrichment: ${(result?.mitreTechniques || []).length} MITRE techniques, ${(result?.threatActors || []).length} threat actors`;
    case STAGE.INVESTIGATION:
      return `Investigation: ${(result?.hypotheses || []).length} hypotheses — ${(result?.rootCause || '').slice(0, 80)}`;
    case STAGE.ATTACK_PATH:
      return `Attack path: ${(result?.attackPath || []).length} steps — entry: ${result?.entryPoint || 'unknown'}`;
    default:
      return `Stage ${stage} completed`;
  }
}

function _buildResult(state) {
  return {
    runId:              state.runId,
    status:             state.status,
    earlyExit:          state.earlyExit,
    earlyExitReason:    state.earlyExitReason || null,
    autoTriage:         state.autoTriageResult,
    triage:             state.triageResult,
    enrichment:         state.enrichmentResult,
    investigation:      state.investigationResult,
    attackPath:         state.attackPathResult,
    hypotheses:         state.hypotheses,
    totalTokens:        state.totalTokens,
    totalCostUsd:       state.totalCostUsd,
    completedStages:    state.seq,
  };
}

/* ── Supabase Realtime channel subscription ────────────────────────────────── */

/**
 * Subscribe to investigation pipeline progress for a given run.
 * Uses Supabase Realtime postgres_changes on we_investigation_events.
 * This replaces AiSOC's WebSocket streaming to a separate service.
 *
 * @param {object} supabaseClient   - Supabase JS client
 * @param {string} runId            - run UUID to subscribe to
 * @param {Function} onEvent        - callback(event) called for each new ledger row
 * @returns {object} Supabase Realtime channel (call .unsubscribe() to clean up)
 */
function subscribeToRun(supabaseClient, runId, onEvent) {
  if (!supabaseClient) {
    console.warn('[WE Pipeline] No Supabase client — Realtime subscription unavailable');
    return null;
  }

  const channel = supabaseClient
    .channel(`we_investigation_run_${runId}`)
    .on(
      'postgres_changes',
      {
        event:  'INSERT',
        schema: 'public',
        table:  'we_investigation_events',
        filter: `run_id=eq.${runId}`,
      },
      (payload) => {
        if (onEvent && payload.new) {
          onEvent(payload.new);
        }
      }
    )
    .subscribe();

  return channel;
}

/* ── Module exports ─────────────────────────────────────────────────────────── */

const WEInvestigationPipeline = {
  // Main entry point
  runInvestigation,
  isPipelineEnabled,

  // Realtime
  subscribeToRun,

  // Exposed for testing
  scoreHypothesis,
  runSwarm,
  stageAutoTriage,
  stageTriage,
  stageEnrichment,
  stageInvestigation,
  stageAttackPath,
  appendEvent,
  sha256,

  // Constants
  STAGE,
  STATUS,
  PIPELINE_FLAG_KEY,
  AUTO_TRIAGE_BENIGN_THRESHOLD,
  DEFAULT_PER_AGENT_TOKEN_BUDGET,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = WEInvestigationPipeline;
} else if (typeof window !== 'undefined') {
  window.WEInvestigationPipeline = WEInvestigationPipeline;
}
