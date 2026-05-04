/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — RAG Pipeline Routes (Phase 3)
 *  backend/routes/rag.js
 *
 *  POST /api/rag/query             — Semantic search across knowledge base
 *  POST /api/rag/ingest            — Ingest document into vector DB
 *  POST /api/rag/ingest/bulk       — Bulk ingest (MITRE, CVE, reports)
 *  GET  /api/rag/documents         — List indexed documents
 *  DELETE /api/rag/documents/:id   — Remove document from index
 *  POST /api/rag/copilot           — RAKAY v2 LLM Copilot (multi-turn)
 *  GET  /api/rag/copilot/history   — Conversation history
 *  DELETE /api/rag/copilot/history — Clear conversation history
 *  GET  /api/rag/stats             — Index statistics
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { llmRateLimiter } = require('../middleware/rateLimiter');
const ragPipeline = require('../services/rag/rag-pipeline');
const { supabase }  = require('../config/supabase');
const { z }         = require('zod');

router.use(verifyToken);

// ── Schemas ───────────────────────────────────────────────────────
const QuerySchema = z.object({
  query:       z.string().min(3).max(2000),
  top_k:       z.number().int().min(1).max(50).default(10),
  doc_types:   z.array(z.string()).optional(),
  rerank:      z.boolean().default(true),
  namespace:   z.string().max(50).optional(),
  min_score:   z.number().min(0).max(1).default(0.5),
});

const IngestSchema = z.object({
  title:       z.string().min(1).max(500),
  content:     z.string().min(10).max(1000000),
  doc_type:    z.enum(['mitre','cve','threat_report','playbook','sigma','custom','news','stix']),
  source:      z.string().max(500).optional(),
  source_url:  z.string().url().optional(),
  metadata:    z.record(z.unknown()).optional(),
  namespace:   z.string().max(50).optional(),
});

const BulkIngestSchema = z.object({
  doc_type:    z.enum(['mitre','cve','threat_report','playbook','sigma']),
  options:     z.object({
    mitre_version:   z.string().optional(),
    nvd_days_back:   z.number().int().min(1).max(365).optional(),
    severity_filter: z.string().optional(),
    max_docs:        z.number().int().min(1).max(10000).optional(),
  }).optional(),
});

const CopilotSchema = z.object({
  message:        z.string().min(1).max(10000),
  session_id:     z.string().uuid().optional(),
  alert_id:       z.string().uuid().optional(),
  incident_id:    z.string().uuid().optional(),
  context_window: z.number().int().min(1).max(20).default(5),
  model:          z.string().max(100).optional(),
  stream:         z.boolean().default(false),
  use_rag:        z.boolean().default(true),
  top_k:          z.number().int().min(1).max(20).default(5),
});

// ── In-memory conversation store (use Redis in production) ────────
const _conversations = new Map();  // session_id → messages[]

function getConversation(sessionId) {
  return _conversations.get(sessionId) || [];
}

function appendConversation(sessionId, role, content) {
  const history = getConversation(sessionId);
  history.push({ role, content, timestamp: new Date().toISOString() });
  if (history.length > 40) history.splice(0, history.length - 40); // Cap at 40 turns
  _conversations.set(sessionId, history);
  return history;
}

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/rag/query
 * Semantic search across vectorised knowledge base
 */
router.post('/query', llmRateLimiter, asyncHandler(async (req, res) => {
  const parsed = QuerySchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { query, top_k, doc_types, rerank, namespace, min_score } = parsed.data;

  const results = await ragPipeline.search(query, {
    topK:       top_k,
    docTypes:   doc_types,
    rerank,
    namespace:  namespace || req.tenantId,
    minScore:   min_score,
  });

  // Log to rag_documents registry (for analytics)
  // Fire-and-forget
  supabase.from('rag_documents')
    .select('id')
    .eq('chunk_id', results?.[0]?.id || 'none')
    .limit(1)
    .then(() => {}) // Non-critical
    .catch(() => {});

  res.json({
    success:    true,
    query,
    results:    results || [],
    result_count: (results || []).length,
    top_k,
  });
}));

/**
 * POST /api/rag/ingest
 * Ingest a single document into the vector database
 */
router.post(
  '/ingest',
  requireRole(['ADMIN', 'SUPER_ADMIN', 'TEAM_LEAD']),
  asyncHandler(async (req, res) => {
    const parsed = IngestSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { title, content, doc_type, source, source_url, metadata, namespace } = parsed.data;

    const result = await ragPipeline.ingestDocument({
      title,
      content,
      docType:   doc_type,
      source,
      sourceUrl: source_url,
      metadata:  metadata || {},
      namespace: namespace || req.tenantId,
    });

    // Register in Supabase rag_documents table
    if (result.chunks?.length) {
      const dbRecords = result.chunks.map((chunk, i) => ({
        title,
        doc_type,
        source,
        source_url,
        chunk_id:     chunk.id,
        chunk_index:  i,
        chunk_text:   chunk.text,
        token_count:  chunk.token_count,
        embedding_model: process.env.EMBED_MODEL || 'text-embedding-3-large',
        metadata:     { ...metadata, ...chunk.metadata },
      }));

      await supabase.from('rag_documents').upsert(dbRecords, { onConflict: 'chunk_id' });
    }

    res.status(201).json({
      success:    true,
      title,
      doc_type,
      chunks_created: result.chunks_created || 0,
      chunk_ids:  (result.chunks || []).map(c => c.id),
      duration_ms: result.duration_ms,
    });
  })
);

/**
 * POST /api/rag/ingest/bulk
 * Bulk ingest from known sources (MITRE ATT&CK, NVD CVEs, etc.)
 */
router.post(
  '/ingest/bulk',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = BulkIngestSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { doc_type, options } = parsed.data;

    // Return immediately with job ID, run in background
    const jobId = require('crypto').randomUUID();

    res.status(202).json({
      success:  true,
      job_id:   jobId,
      doc_type,
      message:  `Bulk ingest job started for doc_type: ${doc_type}`,
      status:   'running',
    });

    // Background ingestion (non-blocking)
    setImmediate(async () => {
      try {
        let result;
        switch (doc_type) {
          case 'mitre':
            result = await ragPipeline.ingestMitreAttack(options);
            break;
          case 'cve':
            result = await ragPipeline.ingestNvdCves(options);
            break;
          case 'playbook':
            result = await ragPipeline.ingestPlaybooks(req.tenantId, options);
            break;
          case 'sigma':
            result = await ragPipeline.ingestSigmaRules(options);
            break;
          default:
            result = { error: 'Unknown doc_type' };
        }
        console.log(`[RAG] Bulk ingest job ${jobId} completed:`, result);
      } catch (err) {
        console.error(`[RAG] Bulk ingest job ${jobId} failed:`, err.message);
      }
    });
  })
);

/**
 * GET /api/rag/documents
 * List indexed documents with pagination
 */
router.get('/documents', asyncHandler(async (req, res) => {
  const limit    = Math.min(parseInt(req.query.limit || '50', 10), 500);
  const offset   = (Math.max(parseInt(req.query.page || '1', 10), 1) - 1) * limit;
  const doc_type = req.query.doc_type;
  const search   = req.query.q;

  // Get unique titles (one row per doc, not per chunk)
  let query = supabase
    .from('rag_documents')
    .select('title, doc_type, source, ingested_at, embedding_model', { count: 'exact' })
    .order('ingested_at', { ascending: false });

  if (doc_type) query = query.eq('doc_type', doc_type);
  if (search)   query = query.ilike('title', `%${search}%`);

  // Group by title (approximate — Supabase doesn't have native GROUP BY in JS client)
  const { data, error, count } = await query.range(offset, offset + limit - 1);

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
 * DELETE /api/rag/documents/:id
 * Remove a document chunk from the index
 */
router.delete(
  '/documents/:id',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const chunkId = req.params.id;

    // Remove from vector DB
    await ragPipeline.deleteDocument(chunkId);

    // Remove from Supabase registry
    await supabase
      .from('rag_documents')
      .delete()
      .eq('chunk_id', chunkId);

    res.json({ success: true, message: `Document chunk ${chunkId} removed` });
  })
);

// ══════════════════════════════════════════════════════════════════
//  RAKAY v2 COPILOT (Multi-turn, RAG-augmented LLM)
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/rag/copilot
 * RAKAY v2 Security Copilot — multi-turn conversation with RAG context
 */
router.post('/copilot', llmRateLimiter, asyncHandler(async (req, res) => {
  const parsed = CopilotSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const {
    message, session_id, alert_id, incident_id,
    context_window, model, stream, use_rag, top_k,
  } = parsed.data;

  const sessionId = session_id || require('crypto').randomUUID();
  const tenantId  = req.tenantId;

  // Fetch conversation history
  const history = getConversation(sessionId).slice(-context_window * 2);

  // Optionally fetch alert/incident context
  let alertContext = '';
  let incidentContext = '';

  if (alert_id) {
    const { data: alert } = await supabase
      .from('alerts')
      .select('title, severity, description, mitre_tactic, mitre_technique, host, username, source_ip, evidence, ai_summary, tags')
      .eq('id', alert_id)
      .eq('tenant_id', tenantId)
      .single();

    if (alert) {
      alertContext = `
CURRENT ALERT CONTEXT:
Title: ${alert.title}
Severity: ${alert.severity?.toUpperCase()}
MITRE Tactic: ${alert.mitre_tactic || 'N/A'} | Technique: ${alert.mitre_technique || 'N/A'}
Affected Host: ${alert.host || 'N/A'} | User: ${alert.username || 'N/A'}
Description: ${alert.description || 'No description'}
Tags: ${(alert.tags || []).join(', ')}
${alert.ai_summary ? `Previous AI Analysis: ${alert.ai_summary}` : ''}
`.trim();
    }
  }

  if (incident_id) {
    const { data: incident } = await supabase
      .from('incidents')
      .select('title, severity, description, mitre_tactics, affected_hosts, affected_users, ai_narrative')
      .eq('id', incident_id)
      .eq('tenant_id', tenantId)
      .single();

    if (incident) {
      incidentContext = `
CURRENT INCIDENT CONTEXT:
Title: ${incident.title}
Severity: ${incident.severity?.toUpperCase()}
MITRE Tactics: ${(incident.mitre_tactics || []).join(', ')}
Affected Hosts: ${(incident.affected_hosts || []).join(', ')}
Affected Users: ${(incident.affected_users || []).join(', ')}
${incident.ai_narrative ? `Incident Narrative: ${incident.ai_narrative}` : ''}
`.trim();
    }
  }

  // RAG retrieval for context-relevant knowledge
  let ragContext = '';
  if (use_rag) {
    try {
      const ragResults = await ragPipeline.search(message, {
        topK:      top_k,
        namespace: tenantId,
        minScore:  0.55,
      });

      if (ragResults?.length > 0) {
        ragContext = `
RELEVANT KNOWLEDGE BASE CONTEXT:
${ragResults.map((r, i) => `[${i+1}] ${r.title || r.metadata?.title || 'Document'}: ${r.text?.substring(0, 400)}`).join('\n\n')}
`.trim();
      }
    } catch (ragErr) {
      console.warn('[RAG Copilot] RAG retrieval failed:', ragErr.message);
    }
  }

  // Build system prompt
  const systemPrompt = [
    'You are RAKAY v2, the AI Security Copilot for the Wadjet-Eye AI SOC platform.',
    'You are a senior threat intelligence analyst and incident responder with deep expertise in:',
    '• MITRE ATT&CK framework, threat intelligence, malware analysis',
    '• Incident response, digital forensics, network security',
    '• SIGMA rules, detection engineering, vulnerability research',
    '• SOC operations, case management, playbook execution',
    '',
    'Communication style:',
    '• Be precise, structured, and actionable',
    '• Use markdown for code blocks, tables, and bullet points',
    '• Cite MITRE technique IDs when relevant (e.g., T1059.001)',
    '• Provide confidence levels for your assessments',
    '• Never fabricate IOCs, CVE IDs, or threat actor attributions',
    '',
    alertContext   ? alertContext   + '\n' : '',
    incidentContext ? incidentContext + '\n' : '',
    ragContext     ? ragContext     + '\n' : '',
  ].filter(Boolean).join('\n');

  // Build messages array for LLM
  const messages = [
    { role: 'system', content: systemPrompt },
    ...history.map(h => ({ role: h.role, content: h.content })),
    { role: 'user', content: message },
  ];

  // Call LLM
  const llmProvider = require('../services/llm-provider');
  const response = await llmProvider.chat(messages, {
    model:       model || process.env.COPILOT_MODEL || 'gpt-4o',
    max_tokens:  2000,
    temperature: 0.3,
    stream:      false,   // Streaming via WebSocket in next version
  });

  const assistantMessage = response.content || response.choices?.[0]?.message?.content || '';

  // Update conversation history
  appendConversation(sessionId, 'user', message);
  appendConversation(sessionId, 'assistant', assistantMessage);

  // Update alert with AI summary if this was an alert-focused query
  if (alert_id && assistantMessage.length > 100) {
    supabase.from('alerts')
      .update({ ai_summary: assistantMessage.substring(0, 5000), updated_at: new Date().toISOString() })
      .eq('id', alert_id)
      .then(() => {})
      .catch(() => {});
  }

  res.json({
    success:      true,
    session_id:   sessionId,
    message:      assistantMessage,
    alert_id:     alert_id || null,
    incident_id:  incident_id || null,
    rag_context_used: !!ragContext,
    rag_sources:  use_rag ? (await ragPipeline.search(message, { topK: 3, namespace: tenantId, minScore: 0.6 }).catch(() => [])).length : 0,
    model_used:   response.model || model || 'gpt-4o',
    tokens: {
      prompt:     response.usage?.prompt_tokens     || 0,
      completion: response.usage?.completion_tokens || 0,
      total:      response.usage?.total_tokens      || 0,
    },
    conversation_length: getConversation(sessionId).length / 2,
  });
}));

/**
 * GET /api/rag/copilot/history
 * Get conversation history for a session
 */
router.get('/copilot/history', asyncHandler(async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) throw createError(400, 'session_id query param required');

  const history = getConversation(session_id);
  res.json({
    success:    true,
    session_id,
    turn_count: Math.floor(history.length / 2),
    history,
  });
}));

/**
 * DELETE /api/rag/copilot/history
 * Clear conversation history for a session
 */
router.delete('/copilot/history', asyncHandler(async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) throw createError(400, 'session_id query param required');

  _conversations.delete(session_id);
  res.json({ success: true, session_id, message: 'Conversation cleared' });
}));

/**
 * GET /api/rag/stats
 * RAG pipeline statistics
 */
router.get('/stats', asyncHandler(async (req, res) => {
  // Count documents by type
  const { data: typeCounts } = await supabase
    .from('rag_documents')
    .select('doc_type')
    .then(({ data }) => {
      const counts = {};
      for (const row of (data || [])) {
        counts[row.doc_type] = (counts[row.doc_type] || 0) + 1;
      }
      return { data: counts };
    });

  // Active conversation count
  const activeSessions = _conversations.size;

  // Vector DB stats
  const vectorStats = await ragPipeline.getStats().catch(() => ({}));

  res.json({
    success:          true,
    documents_by_type: typeCounts || {},
    active_sessions:  activeSessions,
    vector_db:        vectorStats,
    timestamp:        new Date().toISOString(),
  });
}));

/**
 * POST /api/rag/explain-alert
 * AI explanation of a specific alert (single-turn, no history)
 */
router.post('/explain-alert', llmRateLimiter, asyncHandler(async (req, res) => {
  const { alert_id, format } = req.body || {};
  if (!alert_id) throw createError(400, 'alert_id required');

  const { data: alert } = await supabase
    .from('alerts')
    .select('*')
    .eq('id', alert_id)
    .eq('tenant_id', req.tenantId)
    .single();

  if (!alert) throw createError(404, 'Alert not found');

  // RAG-augmented alert explanation
  const ragQuery = `${alert.title} ${alert.mitre_tactic || ''} ${alert.mitre_technique || ''} ${alert.category || ''}`;
  const ragResults = await ragPipeline.search(ragQuery, {
    topK: 5, namespace: req.tenantId, minScore: 0.5,
  }).catch(() => []);

  const ragContext = ragResults.map(r => r.text?.substring(0, 300)).join('\n\n');

  const prompt = `
Analyze the following security alert and provide:
1. **What happened** — Plain-English explanation of the attack technique
2. **Why it matters** — Business impact and risk
3. **Attack chain** — Where this fits in the MITRE ATT&CK kill chain
4. **Recommended actions** — Immediate response steps (numbered)
5. **Investigation queries** — 3 log queries to investigate further

ALERT:
Title: ${alert.title}
Severity: ${alert.severity?.toUpperCase()} | Risk Score: ${alert.risk_score}/100
MITRE: ${alert.mitre_tactic || 'N/A'} / ${alert.mitre_technique || 'N/A'}
Host: ${alert.host || 'N/A'} | User: ${alert.username || 'N/A'} | Source IP: ${alert.source_ip || 'N/A'}
Description: ${alert.description || 'N/A'}
${ragContext ? `\nRELEVANT INTEL:\n${ragContext}` : ''}

Format: ${format || 'markdown'}
`.trim();

  const llmProvider = require('../services/llm-provider');
  const response = await llmProvider.chat([
    { role: 'system', content: 'You are RAKAY v2, a senior SOC analyst AI. Analyze security alerts concisely and accurately.' },
    { role: 'user', content: prompt },
  ], {
    model:       process.env.COPILOT_MODEL || 'gpt-4o',
    max_tokens:  1500,
    temperature: 0.2,
  });

  const explanation = response.content || response.choices?.[0]?.message?.content || '';

  // Cache explanation on alert
  await supabase.from('alerts')
    .update({ ai_summary: explanation.substring(0, 5000), updated_at: new Date().toISOString() })
    .eq('id', alert_id);

  res.json({
    success:     true,
    alert_id,
    explanation,
    rag_sources: ragResults.length,
    model_used:  response.model || 'gpt-4o',
  });
}));

module.exports = router;
