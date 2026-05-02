/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — AI Detection Layer v1.0
 *
 *  Capabilities:
 *   • LLM-powered detection enrichment (OpenAI/Claude/Gemini/Ollama)
 *   • Natural language → RQL query translation
 *   • AI-generated Sigma rule synthesis
 *   • Anomaly explanation and investigation summary
 *   • Semantic search over event embeddings (vector DB simulation)
 *   • Contextual false-positive suppression
 *   • Threat actor attribution via LLM reasoning
 *
 *  backend/services/raykan/ai-detector.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const EventEmitter   = require('events');
const crypto         = require('crypto');
const SigmaBuilder   = require('./sigma-rule-builder');   // v2.0 safe builder

// ── Central Evidence Authority (CEA) — AI post-enrichment guard ───────────────
// The AI enricher may add technique tags based on LLM reasoning.
// Those tags MUST be re-validated by CEA before they leave this module.
let _cea = null;
try {
  _cea = require('./central-evidence-authority');
} catch (e) {
  console.warn('[AI-Detector] central-evidence-authority not available — AI tag re-validation disabled');
}

// ── MITRE → LLM Context map ───────────────────────────────────────
const TECHNIQUE_DESCRIPTIONS = {
  'T1059.001': 'PowerShell command execution — attackers use encoded commands to evade detection',
  'T1003.001': 'LSASS credential dumping — extracting credentials from Windows memory',
  'T1486'    : 'Ransomware data encryption — encrypting files to extort victim',
  'T1021.002': 'SMB/Windows Admin Shares lateral movement',
  'T1071.001': 'HTTP/HTTPS C2 communication',
  'T1055'    : 'Process injection — injecting code into legitimate processes',
  'T1548.002': 'UAC bypass — bypassing Windows User Account Control',
  'T1078'    : 'Valid account abuse — using stolen legitimate credentials',
};

// ── Prompt templates ──────────────────────────────────────────────
// FIX #7 — enrichDetection now accepts chainContext as third argument.
// Prompt redesigned to weight prior chain context heavily so the LLM does
// not return ambiguous isMalicious=null/false for events that are clearly
// malicious when viewed in the context of a confirmed prior chain stage.
const PROMPTS = {
  enrichDetection: (det, evt, chainContext = {}) => {
    const priorStagesText = chainContext.priorStages && chainContext.priorStages.length > 0
      ? chainContext.priorStages.map((s, i) => `  Stage ${i + 1}: ${s.technique} -- ${s.description}`).join('\n')
      : '  No prior chain context.';
    return `You are a senior threat analyst. Assess this detection IN THE CONTEXT of the broader attack chain observed in this session.

DETECTION: ${det.ruleName} [${det.severity}]
MITRE TECHNIQUE: ${(det.mitre && det.mitre.techniques && det.mitre.techniques[0] && det.mitre.techniques[0].id) || 'Unknown'}

EVENT DETAILS:
  Host: ${evt.computer || 'N/A'}
  User: ${evt.user || 'N/A'}
  Process: ${evt.process || 'N/A'}
  Command: ${(evt.commandLine || '').slice(0, 300) || 'N/A'}
  Source IP: ${evt.srcIp || 'N/A'}
  Dest IP: ${evt.dstIp || 'N/A'}
  Bytes sent: ${evt.bytesSent || 'N/A'}

CHAIN CONTEXT (${(chainContext.priorStages && chainContext.priorStages.length) || 0} preceding stages confirmed):
${priorStagesText}

PRECEDING BEHAVIORS: ${chainContext.behaviorSummary || 'None'}

INSTRUCTION: If ANY prior chain stage is confirmed malicious, set isMalicious=true unless you have strong specific evidence of benign administrative activity. A standalone encoded PowerShell command is ambiguous. The same command following a suspicious ISO download is highly suspicious. Weight chain context heavily.

Respond ONLY in valid JSON with these exact keys:
{"summary":"2-3 sentence threat analysis","attackStage":"tactic name","isMalicious":true,"chainConfidence":0,"falsePositiveProbability":0,"recommendedAction":"string"}`;
  },

  translateToRQL: (nlQuery) => `
You are RAYKAN, an AI-powered threat hunting engine. Convert the following natural language threat hunting query into RAYKAN Query Language (RQL) format.

RQL Syntax:
  field:value — exact match
  field:value* — wildcard  
  field:/regex/ — regex
  AND, OR, NOT — boolean
  event.id:4624 — event ID
  process.name:"powershell.exe" — process
  user.name:* — any user
  ip.src:192.168.* — IP wildcard
  time.range:24h — time filter

Natural Language Query: "${nlQuery}"

Respond in JSON:
{
  "rql": "the RQL query",
  "explanation": "what this query hunts for",
  "relatedTechniques": ["T1059.001"],
  "estimatedFPRate": "low|medium|high"
}`,

  generateSigmaRule: (description, examples) => `
You are a Sigma rule expert. Create a production-grade Sigma detection rule for the following threat.

IMPORTANT CONSTRAINTS:
- CommandLine values MUST match real attacker commands or LOLBins (vssadmin, certutil, bitsadmin, psexec, etc.)
- NEVER insert any words from the user description into CommandLine values
- The detection block MUST have multiple named selections (e.g. selection_backup_deletion, selection_log_clearing)
- The condition MUST combine selections with AND/OR logic (e.g. "1 of selection_*")
- Level must be one of: critical, high, medium, low

Threat to detect: ${description}
${examples.length > 0 ? 'Example events:\n' + JSON.stringify(examples, null, 2) : ''}

Generate a complete Sigma rule in JSON format (not YAML) with fields:
id, title, description, author, level (critical/high/medium/low), status (stable/test/experimental),
tags (MITRE ATT&CK), logsource (category, product), detection (named selections + condition),
falsepositives (array), references (array).

Respond with only valid JSON.`,

  summarizeInvestigation: (evidence, chains) => `
You are a DFIR analyst. Summarize this investigation based on evidence.

Evidence Summary:
- ${evidence.detections?.length || 0} detections
- ${evidence.events?.length || 0} events analyzed
- Entities: ${JSON.stringify(evidence.entities || {})}

Attack Chains Found: ${chains.length}
${chains.map((c, i) => `Chain ${i+1}: ${c.stages?.map(s => s.technique).join(' → ') || 'Unknown'}`).join('\n')}

Provide an executive summary (3-4 sentences) covering:
1. What likely happened
2. Which systems/users were affected  
3. Recommended immediate actions

Respond in JSON: { "summary": "...", "severity": "critical|high|medium|low", "confidence": 0-100, "actions": ["..."] }`,
};

class AIDetector extends EventEmitter {
  constructor(config = {}) {
    super();
    this._config   = config;
    this._provider = this._selectProvider(config.aiProviders || {});
    this._cache    = new Map();   // simple in-memory response cache
    this._stats    = { queries: 0, hits: 0, errors: 0, cached: 0 };
    this._ready    = false;

    // Embedding store (simulated vector DB — in production use Pinecone/Qdrant)
    this._embeddingStore = [];
  }

  // ── Initialize ────────────────────────────────────────────────────
  async initialize() {
    try {
      if (this._provider) {
        // Test API connectivity
        await this._testProvider();
        this._ready = true;
        console.log(`[RAYKAN/AI] Provider: ${this._provider.name} — ready`);
      } else {
        console.warn('[RAYKAN/AI] No AI provider configured — running in rule-only mode');
        this._ready = false;
      }
    } catch (e) {
      console.warn(`[RAYKAN/AI] AI provider init failed: ${e.message} — falling back to rule-only mode`);
      this._ready = false;
    }
  }

  // ── Enrich Detections with AI Context ────────────────────────────
  // AI enrichment adds contextual analysis but MUST NOT override CEA decisions.
  // Any technique tags introduced or modified by AI are re-validated by CEA.
  //
  // FIX #7: builds chainContext from confirmed prior stages so the LLM
  // receives attack-chain context rather than evaluating each event in isolation.
  async enrichDetections(detections, events) {
    if (!this._ready) return detections;

    const enriched = [];
    for (let idx = 0; idx < detections.length; idx++) {
      const det = detections[idx];
      try {
        const evt = events.find(e => e.id === (det.event && det.event.id)) || det.event || {};

        // FIX #7 — Build chain context from confirmed malicious prior stages
        const priorConfirmed = enriched
          .filter(d => d.ai && d.ai.isMalicious === true)
          .map(d => ({
            technique  : (d.mitre && d.mitre.techniques && d.mitre.techniques[0] && d.mitre.techniques[0].id) || d.ruleId || '',
            description: (d.ai && d.ai.attackStage) || d.ruleName || '',
          }));
        const chainContext = {
          priorStages    : priorConfirmed,
          behaviorSummary: priorConfirmed.length > 0
            ? priorConfirmed.length + ' prior malicious stage(s): ' + priorConfirmed.map(s => s.technique).join(', ')
            : 'None',
        };

        const cacheKey = this._cacheKey(
          'enrich', det.ruleId,
          evt.commandLine || '', evt.process || '',
          String(priorConfirmed.length)
        );

        let analysis;
        if (this._cache.has(cacheKey)) {
          analysis = this._cache.get(cacheKey);
          this._stats.cached++;
        } else {
          // FIX #7 — pass chainContext as third argument
          const prompt = PROMPTS.enrichDetection(det, evt, chainContext);
          analysis     = await this._callLLM(prompt);
          this._cache.set(cacheKey, analysis);
        }

        // Build enriched detection — AI context only; do NOT modify tags here
        // FIX #7 — cap downward delta at -10 (was -20); only apply upward delta
        // when at least one prior chain stage is confirmed malicious.
        const hasChainCtx = priorConfirmed.length > 0;
        const enrichedDet = {
          ...det,
          ai               : analysis,
          summary          : (analysis && analysis.summary)           || null,
          attackStage      : (analysis && analysis.attackStage)       || null,
          falsePositiveProb: (analysis && analysis.falsePositiveProbability) || null,
          recommendedAction: (analysis && analysis.recommendedAction) || null,
          confidence       : analysis && analysis.isMalicious === true && hasChainCtx
            ? Math.min(100, det.confidence + 15)
            : analysis && (analysis.isMalicious === false || analysis.isMalicious === null)
              ? Math.max(10, det.confidence - 10)  // FIX #7: capped at -10 (was -20)
              : det.confidence,
        };

        // ── CEA re-validation after AI enrichment ──────────────────
        // If AI analysis added new technique tags or the detection was
        // previously un-validated, re-run CEA to strip unsupported techniques.
        // This prevents LLM hallucination from introducing invalid mappings.
        let finalDet = enrichedDet;
        if (_cea && !enrichedDet._ceaValidated) {
          const evtBatch  = Array.isArray(events) ? events : [evt];
          const evtCtx    = _cea.buildEvidence(evtBatch, [enrichedDet]);
          finalDet = _cea.validateDetection(enrichedDet, evtCtx);
        }

        enriched.push(finalDet);
        this.emit('ai:detection', finalDet);
      } catch (e) {
        this._stats.errors++;
        enriched.push(det); // Return un-enriched on error
      }
    }

    return enriched;
  }

  // ── Natural Language → RQL ────────────────────────────────────────
  async translateToRQL(nlQuery) {
    if (!this._ready) {
      // Simple keyword-based fallback translation
      return this._keywordToRQL(nlQuery);
    }

    const cacheKey = this._cacheKey('rql', nlQuery);
    if (this._cache.has(cacheKey)) {
      this._stats.cached++;
      return this._cache.get(cacheKey).rql;
    }

    const prompt = PROMPTS.translateToRQL(nlQuery);
    const result = await this._callLLM(prompt);
    this._cache.set(cacheKey, result);
    return result?.rql || this._keywordToRQL(nlQuery);
  }

  // ── Generate Sigma Rule (v2.0 — prompt-safe, template-backed) ─────
  async generateSigmaRule(description, examples = []) {
    // Step 1: Always sanitize the input first (removes instruction verbs,
    // extracts security keywords, enforces ≤3-word phrase rule)
    const { keywords, intent, sanitized } = SigmaBuilder.sanitizeDescription(description);
    console.log(`[RAYKAN/AI] Rule gen — intent=${intent} keywords=[${keywords.join(',')}]`);

    let rule;

    // Step 2: If no AI provider, go straight to the safe behavioral template
    if (!this._ready) {
      return this._safeBuildFromTemplate(description, intent, keywords);
    }

    // Step 3: Ask the LLM, but pass the sanitized description (no raw user text)
    const prompt = PROMPTS.generateSigmaRule(sanitized || description, examples);
    const llmRule = await this._callLLM(prompt);

    if (llmRule && llmRule.detection) {
      // Step 4: Validate LLM output — reject prompt leakage, meta words, bad CommandLine
      const validation = SigmaBuilder.validateRuleOutput(llmRule, description);
      if (validation.valid) {
        rule = {
          ...llmRule,
          id    : llmRule.id || `RAYKAN-AI-${Date.now()}`,
          author: `RAYKAN AI (${this._provider?.name || 'local'})`,
          status: llmRule.status || 'experimental',
        };
        console.log('[RAYKAN/AI] LLM rule passed validation');
      } else {
        console.warn('[RAYKAN/AI] LLM rule failed validation — regenerating from template:', validation.errors.slice(0,3));
        rule = null;
      }
    }

    // Step 5: Fall back to behavioral template if LLM failed or validation failed
    if (!rule) {
      rule = this._safeBuildFromTemplate(description, intent, keywords);
    }

    return rule;
  }

  // ── Safe Rule Builder (template-based, no user text in CommandLine) ──
  _safeBuildFromTemplate(description, intent, keywords) {
    const result = SigmaBuilder.buildRule(description, {
      author   : 'RAYKAN Behavioral Engine',
      extraTags: [],
    });

    // Run quality check
    const quality = SigmaBuilder.sigmaQualityCheck(result.rule);
    console.log(`[RAYKAN/AI] Template rule quality: ${quality.grade} (${quality.score}/100)`);

    return {
      ...result.rule,
      _yaml       : result.yaml,
      _quality    : quality,
      _builderMeta: result.meta,
    };
  }

  // ── Summarize Investigation ───────────────────────────────────────
  async summarizeInvestigation(evidence, chains) {
    if (!this._ready) {
      return {
        summary  : `Investigation found ${evidence.detections?.length || 0} detections across ${evidence.events?.length || 0} events. Review attached evidence for details.`,
        severity : 'medium',
        confidence: 60,
        actions  : ['Review detections', 'Isolate affected systems if critical findings confirmed'],
      };
    }

    const prompt = PROMPTS.summarizeInvestigation(evidence, chains);
    const result = await this._callLLM(prompt);
    return result || { summary: 'Analysis completed.', severity: 'medium', confidence: 50, actions: [] };
  }

  // ── Explain Query Results ─────────────────────────────────────────
  async explainQuery(rqlQuery, results) {
    if (!this._ready || !results.count) return null;
    const prompt = `Explain what this threat hunting query found: "${rqlQuery}" (${results.count} matches). Be concise — 2 sentences max.`;
    return this._callLLM(prompt, 'text');
  }

  // ── LLM Call (multi-provider) ─────────────────────────────────────
  async _callLLM(prompt, format = 'json') {
    this._stats.queries++;
    const provider = this._provider;
    if (!provider) return null;

    try {
      let response;
      // FIX #11 — dedicated Anthropic branch (was incorrectly using OpenAI
      // /chat/completions path with the Anthropic API key)
      if (provider.type === 'anthropic' || provider.name === 'Claude') {
        response = await this._callAnthropic(prompt, format, provider);
      } else {
        switch (provider.type) {
          case 'openai':
          case 'compatible':
            response = await this._callOpenAICompatible(prompt, format, provider);
            break;
          case 'ollama':
            response = await this._callOllama(prompt, format, provider);
            break;
          default:
            return null;
        }
      }
      this._stats.hits++;
      return response;
    } catch (e) {
      this._stats.errors++;
      console.warn(`[RAYKAN/AI] LLM call failed: ${e.message}`);
      return null;
    }
  }

  // FIX #11 — Anthropic Messages API (correct endpoint + auth headers)
  async _callAnthropic(prompt, format, provider) {
    const nodeFetch = (typeof fetch !== 'undefined') ? fetch : null;
    let fetchFn = nodeFetch;
    if (!fetchFn) {
      try { fetchFn = require('node-fetch'); } catch (e) {
        // node-fetch not available — fall through with null
        return null;
      }
    }
    const res = await fetchFn('https://api.anthropic.com/v1/messages', {
      method : 'POST',
      headers: {
        'Content-Type'     : 'application/json',
        'x-api-key'        : provider.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model     : provider.model || 'claude-opus-4-5',
        max_tokens: 1024,
        messages  : [{ role: 'user', content: prompt }],
      }),
    });
    const data    = await res.json();
    const content = (data.content && data.content[0] && data.content[0].text) || '';
    if (!content) return null;
    if (format !== 'json') return content;
    try {
      return JSON.parse(content);
    } catch (_) {
      // Extract first JSON object from the text
      const m = content.match(/\{[\s\S]*\}/);
      return m ? JSON.parse(m[0]) : null;
    }
  }

  async _callOpenAICompatible(prompt, format, provider) {
    const axios = require('axios');
    const resp  = await axios.post(
      `${provider.baseUrl}/chat/completions`,
      {
        model      : provider.model || 'gpt-3.5-turbo',
        messages   : [{ role: 'user', content: prompt }],
        ...(format === 'json' ? { response_format: { type: 'json_object' } } : {}),
        max_tokens : 800,
        temperature: 0.0,  // FIX #7 — changed from 0.1 to 0.0 for determinism
      },
      {
        headers : { Authorization: `Bearer ${provider.apiKey}`, 'Content-Type': 'application/json' },
        timeout : 20000,
      }
    );
    const content = (resp.data && resp.data.choices && resp.data.choices[0] &&
                     resp.data.choices[0].message && resp.data.choices[0].message.content) || '';
    return format === 'json' ? JSON.parse(content) : content;
  }

  async _callOllama(prompt, format, provider) {
    const axios = require('axios');
    const resp  = await axios.post(
      `${provider.baseUrl}/api/generate`,
      {
        model  : provider.model || 'mistral',
        prompt,
        stream : false,
        ...(format === 'json' ? { format: 'json' } : {}),
      },
      { timeout: 30000 }
    );
    const content = resp.data?.response || '';
    return format === 'json' ? JSON.parse(content) : content;
  }

  async _testProvider() {
    // Quick ping
    await this._callLLM('Say "OK" only.', 'text');
  }

  // ── Fallbacks (no AI provider) ────────────────────────────────────
  _keywordToRQL(nlQuery) {
    const q = nlQuery.toLowerCase();
    const terms = [];

    // Map common hunting phrases to RQL
    if (q.includes('powershell') || q.includes('encoded command')) terms.push('process.name:"powershell.exe"');
    if (q.includes('admin') || q.includes('privilege'))           terms.push('event.id:4728 OR event.id:4732');
    if (q.includes('lateral') || q.includes('psexec'))            terms.push('process.name:"psexec.exe"');
    if (q.includes('mimikatz') || q.includes('credential dump'))  terms.push('commandLine:*mimikatz* OR commandLine:*sekurlsa*');
    if (q.includes('ransomware') || q.includes('shadow copy'))    terms.push('commandLine:*vssadmin*delete*');
    if (q.includes('c2') || q.includes('cobalt strike'))          terms.push('process.name:*beacon* OR commandLine:*stager*');
    if (q.includes('brute force') || q.includes('failed login'))  terms.push('event.id:4625');
    if (q.includes('dns'))                                          terms.push('event.id:22');

    return terms.length > 0 ? terms.join(' OR ') : nlQuery;
  }

  // Kept as safety stub — delegates to SigmaBuilder
  _generateRuleTemplate(description) {
    const result = SigmaBuilder.buildRule(description);
    return result.rule;
  }

  // ── Provider selection ─────────────────────────────────────────────
  _selectProvider(providers) {
    if (providers.openai?.apiKey) {
      return { type: 'openai', name: 'OpenAI', baseUrl: 'https://api.openai.com/v1',
               apiKey: providers.openai.apiKey, model: providers.openai.model || 'gpt-3.5-turbo' };
    }
    if (providers.claude?.apiKey) {
      return { type: 'compatible', name: 'Claude', baseUrl: 'https://api.anthropic.com/v1',
               apiKey: providers.claude.apiKey, model: providers.claude.model || 'claude-3-haiku-20240307' };
    }
    if (providers.gemini?.apiKey) {
      return { type: 'compatible', name: 'Gemini',
               baseUrl: `https://generativelanguage.googleapis.com/v1beta/openai`,
               apiKey: providers.gemini.apiKey, model: 'gemini-1.5-flash' };
    }
    if (providers.deepseek?.apiKey) {
      return { type: 'compatible', name: 'DeepSeek', baseUrl: 'https://api.deepseek.com',
               apiKey: providers.deepseek.apiKey, model: 'deepseek-chat' };
    }
    if (providers.ollama?.baseUrl) {
      return { type: 'ollama', name: 'Ollama (local)', baseUrl: providers.ollama.baseUrl,
               model: providers.ollama.model || 'mistral' };
    }
    // Attempt to use env vars
    const envKey = process.env.OPENAI_API_KEY || process.env.CLAUDE_API_KEY || process.env.GEMINI_API_KEY;
    if (process.env.OPENAI_API_KEY) {
      return { type: 'openai', name: 'OpenAI', baseUrl: 'https://api.openai.com/v1',
               apiKey: process.env.OPENAI_API_KEY, model: 'gpt-3.5-turbo' };
    }
    return null; // No provider — rule-only mode
  }

  _cacheKey(...parts) {
    return crypto.createHash('md5').update(parts.join('|')).digest('hex');
  }

  // FIX #8 — Session state reset: clears LLM response cache so cached
  // responses from one ingest session cannot bleed into the next.
  reset() {
    this._cache.clear();
    this._stats = { queries: 0, hits: 0, errors: 0, cached: 0 };
  }

  getStatus() {
    return {
      ready       : this._ready,
      provider    : this._provider?.name || 'none',
      stats       : this._stats,
      sigmaBuilder: 'v2.0 (behavioral templates, prompt-safe)',
    };
  }
}

module.exports = AIDetector;
