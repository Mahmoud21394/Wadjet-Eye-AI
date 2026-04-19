/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Real AI Backend Service v5.1
 *  FILE: backend/routes/ai.js
 *
 *  POST /api/ai/analyze   — Analyze IOC / alert / text using real LLM
 *  POST /api/ai/chat      — Interactive threat investigation chat
 *  GET  /api/ai/status    — Which AI providers are configured + active
 *  POST /api/ai/summarize — Summarize threat report or alert batch
 *
 *  Priority chain: OpenAI GPT-4o → Google Gemini → Local Ollama → Structured fallback
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const axios  = require('axios');
const { supabase }    = require('../config/supabase');
const { asyncHandler } = require('../middleware/errorHandler');

// NOTE: verifyToken is already applied globally in server.js before /api/ai routes.
// Do NOT add verifyToken per-route here — that causes double Supabase auth calls.

/* ════════════════════════════════════════════════
   AI PROVIDER CONFIGURATION
═══════════════════════════════════════════════ */
const AI_PROVIDERS = {
  openai: {
    name:    'OpenAI GPT-4o',
    key:     process.env.OPENAI_API_KEY,
    enabled: !!process.env.OPENAI_API_KEY,
    model:   process.env.OPENAI_MODEL || 'gpt-4o',
    url:     'https://api.openai.com/v1/chat/completions',
  },
  gemini: {
    name:    'Google Gemini 2.0 Flash',
    key:     process.env.GEMINI_API_KEY,
    enabled: !!process.env.GEMINI_API_KEY,
    model:   process.env.GEMINI_MODEL || 'gemini-2.0-flash',
    url:     `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`,
  },
  ollama: {
    name:    'Local Ollama',
    key:     null,
    enabled: !!process.env.OLLAMA_ENDPOINT,
    model:   process.env.OLLAMA_MODEL || 'qwen3:8b',
    url:     (process.env.OLLAMA_ENDPOINT || 'http://localhost:11434') + '/api/generate',
  },
};

// Log provider status on startup
const activeProviders = Object.entries(AI_PROVIDERS)
  .filter(([, p]) => p.enabled)
  .map(([k, p]) => `${p.name}(${k})`);

console.log('[AI] Providers configured:', activeProviders.length > 0
  ? activeProviders.join(', ')
  : 'NONE — set OPENAI_API_KEY or GEMINI_API_KEY in .env');

/* ════════════════════════════════════════════════
   SYSTEM PROMPT (SOC context)
═══════════════════════════════════════════════ */
const SYSTEM_PROMPT = `You are Wadjet-Eye AI, an expert cybersecurity analyst embedded in a SOC platform.
You specialize in:
- Threat intelligence analysis (IOCs, TTPs, MITRE ATT&CK)
- Malware analysis and reverse engineering insights
- Vulnerability assessment (CVEs, CVSS, exploitation risk)
- APT group profiling and campaign attribution
- SOAR playbook recommendations
- Incident response guidance

Response format:
- Be concise and actionable
- Use MITRE ATT&CK technique IDs (e.g., T1071.001)
- Rate severity: CRITICAL / HIGH / MEDIUM / LOW
- Provide concrete remediation steps
- Cite threat intel sources where applicable
- Always flag if data is uncertain or requires verification`;

/* ════════════════════════════════════════════════
   OPENAI CALL
═══════════════════════════════════════════════ */
async function callOpenAI(messages, options = {}) {
  const provider = AI_PROVIDERS.openai;
  if (!provider.enabled) throw new Error('OpenAI not configured');

  const response = await axios.post(provider.url, {
    model:       options.model || provider.model,
    messages,
    max_tokens:  options.max_tokens || 1500,
    temperature: options.temperature || 0.3,
    stream:      false,
  }, {
    headers: {
      'Authorization': `Bearer ${provider.key}`,
      'Content-Type':  'application/json',
    },
    timeout: 30000,
  });

  return {
    content:  response.data.choices[0].message.content,
    provider: 'openai',
    model:    response.data.model,
    tokens:   response.data.usage?.total_tokens || 0,
  };
}

/* ════════════════════════════════════════════════
   GEMINI CALL
═══════════════════════════════════════════════ */
async function callGemini(messages, options = {}) {
  const provider = AI_PROVIDERS.gemini;
  if (!provider.enabled) throw new Error('Gemini not configured');

  // Convert OpenAI message format to Gemini format
  const contents = messages
    .filter(m => m.role !== 'system')
    .map(m => ({
      role:  m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));

  // Prepend system message as first user message
  const systemMsg = messages.find(m => m.role === 'system');
  if (systemMsg) {
    contents.unshift({
      role:  'user',
      parts: [{ text: `[SYSTEM CONTEXT]\n${systemMsg.content}` }],
    });
    contents.splice(1, 0, {
      role:  'model',
      parts: [{ text: 'Understood. I am operating as Wadjet-Eye AI security analyst.' }],
    });
  }

  const response = await axios.post(
    `${provider.url}?key=${provider.key}`,
    {
      contents,
      generationConfig: {
        maxOutputTokens: options.max_tokens || 1500,
        temperature:     options.temperature || 0.3,
      },
    },
    { timeout: 30000 }
  );

  const text = response.data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  return {
    content:  text,
    provider: 'gemini',
    model:    provider.model,
    tokens:   response.data.usageMetadata?.totalTokenCount || 0,
  };
}

/* ════════════════════════════════════════════════
   OLLAMA CALL (local)
═══════════════════════════════════════════════ */
async function callOllama(messages, options = {}) {
  const provider = AI_PROVIDERS.ollama;
  if (!provider.enabled) throw new Error('Ollama not configured');

  // Combine messages into a prompt for Ollama
  const prompt = messages.map(m => {
    const role = m.role === 'assistant' ? 'Assistant' : m.role === 'system' ? 'System' : 'User';
    return `${role}: ${m.content}`;
  }).join('\n\n') + '\n\nAssistant:';

  const response = await axios.post(provider.url, {
    model:  options.model || provider.model,
    prompt,
    stream: false,
    options: {
      num_predict: options.max_tokens || 1500,
      temperature: options.temperature || 0.3,
    },
  }, { timeout: 60000 });

  return {
    content:  response.data.response || '',
    provider: 'ollama',
    model:    provider.model,
    tokens:   0,
  };
}

/* ════════════════════════════════════════════════
   PROVIDER CHAIN — Try each in order
═══════════════════════════════════════════════ */
async function callAI(messages, options = {}) {
  const errors = [];

  // 1. Try OpenAI
  if (AI_PROVIDERS.openai.enabled) {
    try {
      const result = await callOpenAI(messages, options);
      console.log('[AI] ✅ OpenAI response received');
      return result;
    } catch (err) {
      errors.push(`OpenAI: ${err.response?.data?.error?.message || err.message}`);
      console.warn('[AI] OpenAI failed:', errors[errors.length - 1]);
    }
  }

  // 2. Try Gemini
  if (AI_PROVIDERS.gemini.enabled) {
    try {
      const result = await callGemini(messages, options);
      console.log('[AI] ✅ Gemini response received');
      return result;
    } catch (err) {
      errors.push(`Gemini: ${err.response?.data?.error?.message || err.message}`);
      console.warn('[AI] Gemini failed:', errors[errors.length - 1]);
    }
  }

  // 3. Try Ollama
  if (AI_PROVIDERS.ollama.enabled) {
    try {
      const result = await callOllama(messages, options);
      console.log('[AI] ✅ Ollama response received');
      return result;
    } catch (err) {
      errors.push(`Ollama: ${err.message}`);
      console.warn('[AI] Ollama failed:', errors[errors.length - 1]);
    }
  }

  // 4. No AI available — return structured fallback instead of throwing
  // This prevents 500 errors when no AI key is configured.
  console.warn('[AI] All providers failed/unconfigured. Returning structured fallback.');
  return {
    content:  `[AI Unavailable] No AI provider is configured on the server. ` +
              `Set OPENAI_API_KEY or GEMINI_API_KEY in Render environment variables. ` +
              `Errors: ${errors.join('; ') || 'No keys configured.'}`,
    provider: 'fallback',
    model:    'none',
    tokens:   0,
  };
}

/* ════════════════════════════════════════════════
   GET /api/ai/status
═══════════════════════════════════════════════ */
router.get('/status', asyncHandler(async (req, res) => {
  const status = {};

  for (const [key, provider] of Object.entries(AI_PROVIDERS)) {
    status[key] = {
      name:      provider.name,
      enabled:   provider.enabled,
      model:     provider.model,
      has_key:   !!provider.key,
      key_prefix: provider.key ? provider.key.slice(0, 10) + '...' : null,
    };
  }

  const anyEnabled = Object.values(AI_PROVIDERS).some(p => p.enabled);

  res.json({
    providers:    status,
    any_enabled:  anyEnabled,
    demo_mode:    !anyEnabled,
    active_chain: Object.entries(AI_PROVIDERS)
      .filter(([, p]) => p.enabled)
      .map(([k]) => k),
  });
}));

/* ════════════════════════════════════════════════
   POST /api/ai/analyze
   Analyze an IOC, alert, or threat indicator
═══════════════════════════════════════════════ */
router.post('/analyze', asyncHandler(async (req, res) => {
  const { target, type = 'ioc', context = '' } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'target is required' });
  }

  // Build context from DB
  let dbContext = '';
  if (type === 'ioc' || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target) || target.includes('.')) {
    const { data: ioc } = await supabase
      .from('iocs')
      .select('value, type, reputation, risk_score, enrichment_data, tags, threat_actor')
      .eq('value', target.toLowerCase())
      .maybeSingle();

    if (ioc) {
      dbContext = `\n\nDB Record: reputation=${ioc.reputation}, risk_score=${ioc.risk_score}, threat_actor=${ioc.threat_actor || 'unknown'}, tags=${(ioc.tags || []).join(', ')}`;
      if (ioc.enrichment_data && Object.keys(ioc.enrichment_data).length > 0) {
        dbContext += `\nEnrichment: ${JSON.stringify(ioc.enrichment_data).slice(0, 500)}`;
      }
    }
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    {
      role: 'user',
      content: `Analyze this cybersecurity indicator:\n\nType: ${type}\nValue: ${target}${dbContext}${context ? '\n\nAdditional context: ' + context : ''}\n\nProvide:\n1. Threat classification\n2. Risk assessment (CRITICAL/HIGH/MEDIUM/LOW)\n3. Associated TTPs (MITRE ATT&CK IDs)\n4. Known threat actors or campaigns\n5. Recommended immediate actions\n6. IOC relationships (related indicators if known)`,
    },
  ];

  const aiResult = await callAI(messages, { max_tokens: 1200 });

  // Log the analysis
  await supabase.from('audit_logs').insert({
    user_id:    req.user.id,
    tenant_id:  req.user.tenant_id,
    action:     'AI_ANALYZE',
    resource:   'ioc',
    details:    { target, type, provider: aiResult.provider },
  }).catch(() => {});

  res.json({
    target,
    type,
    analysis:  aiResult.content,
    provider:  aiResult.provider,
    model:     aiResult.model,
    tokens:    aiResult.tokens,
    analyzed_at: new Date().toISOString(),
  });
}));

/* ════════════════════════════════════════════════
   POST /api/ai/chat
   Interactive SOC investigation session
═══════════════════════════════════════════════ */
router.post('/chat', asyncHandler(async (req, res) => {
  // Accept two payload formats:
  //   1. { message: "...", history: [...] }  — standard format
  //   2. { messages: [{role,content},...] }   — OpenAI-compatible format (sent by frontend orchestrator)
  let message  = req.body.message;
  let history  = req.body.history || [];

  if (!message && Array.isArray(req.body.messages)) {
    // OpenAI-compatible format: extract last user message as `message`, rest as history
    const msgs   = req.body.messages;
    const lastUser = [...msgs].reverse().find(m => m.role === 'user');
    message = lastUser?.content || '';
    history = msgs.filter(m => m !== lastUser && m.role !== 'system');
  }

  if (!message) {
    return res.status(400).json({
      error:   'message is required',
      formats: [
        '{ "message": "analyze 101.99.20.163", "history": [] }',
        '{ "messages": [{"role":"user","content":"analyze 101.99.20.163"}] }',
      ],
    });
  }

  // Limit history to last 10 exchanges (20 messages)
  const recentHistory = history.slice(-20);

  // Fetch recent DB context for the query
  let dbContext = '';
  const ipMatch     = message.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  const domainMatch = message.match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/i);
  const hashMatch   = message.match(/\b[0-9a-f]{32,64}\b/i);
  const cveMatch    = message.match(/CVE-\d{4}-\d+/i);

  if (ipMatch || domainMatch || hashMatch) {
    const lookupVal = (ipMatch || hashMatch || domainMatch)[0].toLowerCase();
    const { data: ioc } = await supabase.from('iocs')
      .select('value, type, reputation, risk_score, enrichment_data, threat_actor, tags')
      .eq('value', lookupVal).maybeSingle();
    if (ioc) {
      dbContext = `\n[DB: ${ioc.value} | rep=${ioc.reputation} | score=${ioc.risk_score} | actor=${ioc.threat_actor || 'unknown'}]`;
    }
  }

  if (cveMatch) {
    const { data: vuln } = await supabase.from('vulnerabilities')
      .select('cve_id, severity, cvss_score, description, exploit_available, is_kev')
      .eq('cve_id', cveMatch[0].toUpperCase()).maybeSingle();
    if (vuln) {
      dbContext += `\n[CVE DB: ${vuln.cve_id} | CVSS=${vuln.cvss_score} | ${vuln.severity} | exploit=${vuln.exploit_available} | KEV=${vuln.is_kev}]`;
    }
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    ...recentHistory,
    { role: 'user', content: message + dbContext },
  ];

  const aiResult = await callAI(messages, { max_tokens: 1000, temperature: 0.4 });

  res.json({
    message:    aiResult.content,
    provider:   aiResult.provider,
    model:      aiResult.model,
    tokens:     aiResult.tokens,
    timestamp:  new Date().toISOString(),
  });
}));

/* ════════════════════════════════════════════════
   POST /api/ai/summarize
   Summarize a batch of alerts or a threat report
═══════════════════════════════════════════════ */
router.post('/summarize', asyncHandler(async (req, res) => {
  const { type = 'alerts', period_hours = 24 } = req.body;
  const tenantId = req.user.tenant_id;

  let dataToSummarize = '';

  if (type === 'alerts') {
    const since = new Date(Date.now() - period_hours * 3600000).toISOString();
    const { data: alerts } = await supabase
      .from('alerts')
      .select('title, severity, type, status, mitre_technique, created_at')
      .eq('tenant_id', tenantId)
      .gte('created_at', since)
      .order('created_at', { ascending: false })
      .limit(30);

    if (!alerts?.length) {
      return res.json({ summary: `No alerts in the last ${period_hours} hours.`, type, period_hours });
    }

    dataToSummarize = alerts.map(a =>
      `- [${a.severity}] ${a.title} (${a.type}) | MITRE: ${a.mitre_technique || 'N/A'} | Status: ${a.status}`
    ).join('\n');
  } else if (type === 'iocs') {
    const { data: iocs } = await supabase
      .from('iocs')
      .select('value, type, reputation, risk_score, threat_actor')
      .eq('tenant_id', tenantId)
      .gte('risk_score', 70)
      .order('risk_score', { ascending: false })
      .limit(20);

    if (!iocs?.length) {
      return res.json({ summary: 'No high-risk IOCs found.', type });
    }

    dataToSummarize = iocs.map(i =>
      `- [${i.risk_score}/100] ${i.value} (${i.type}) | ${i.reputation} | Actor: ${i.threat_actor || 'unknown'}`
    ).join('\n');
  }

  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    {
      role: 'user',
      content: `Generate an executive threat summary for the SOC team:\n\nData (last ${period_hours}h):\n${dataToSummarize}\n\nProvide:\n1. Executive summary (2-3 sentences)\n2. Top 3 critical threats\n3. Recommended immediate actions\n4. Overall threat posture (CRITICAL/HIGH/MEDIUM/LOW)\n5. Trend analysis if patterns are visible`,
    },
  ];

  const aiResult = await callAI(messages, { max_tokens: 800 });

  res.json({
    summary:   aiResult.content,
    type,
    period_hours,
    provider:  aiResult.provider,
    model:     aiResult.model,
    generated_at: new Date().toISOString(),
  });
}));

module.exports = router;
