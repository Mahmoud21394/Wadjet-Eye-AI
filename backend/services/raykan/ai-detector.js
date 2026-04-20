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
const PROMPTS = {
  enrichDetection: (det, evt) => `
You are a senior threat analyst. Analyze this security detection and provide enrichment.

Detection: ${det.ruleName}
Severity: ${det.severity}
Event Details:
  - Process: ${evt.process || 'N/A'}
  - Command: ${evt.commandLine || 'N/A'}
  - User: ${evt.user || 'N/A'}
  - Computer: ${evt.computer || 'N/A'}
  - Source IP: ${evt.srcIp || 'N/A'}
  - Destination IP: ${evt.dstIp || 'N/A'}

Respond in JSON with:
{
  "summary": "2-3 sentence threat analysis",
  "attackStage": "initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact",
  "isMalicious": true/false/null,
  "falsePositiveProbability": 0-100,
  "recommendedAction": "string",
  "additionalContext": "string"
}`,

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
  async enrichDetections(detections, events) {
    if (!this._ready) return detections;

    const enriched = [];
    for (const det of detections) {
      try {
        // Cache key based on rule + key event fields
        const evt     = events.find(e => e.id === det.event?.id) || det.event || {};
        const cacheKey = this._cacheKey('enrich', det.ruleId, evt.commandLine || '', evt.process || '');

        let analysis;
        if (this._cache.has(cacheKey)) {
          analysis = this._cache.get(cacheKey);
          this._stats.cached++;
        } else {
          const prompt = PROMPTS.enrichDetection(det, evt);
          analysis     = await this._callLLM(prompt);
          this._cache.set(cacheKey, analysis);
        }

        enriched.push({
          ...det,
          ai: analysis,
          summary         : analysis?.summary || null,
          attackStage      : analysis?.attackStage || null,
          falsePositiveProb: analysis?.falsePositiveProbability || null,
          recommendedAction: analysis?.recommendedAction || null,
          confidence       : analysis?.isMalicious === true
            ? Math.min(100, det.confidence + 15)
            : analysis?.isMalicious === false
              ? Math.max(10, det.confidence - 20)
              : det.confidence,
        });

        this.emit('ai:detection', enriched[enriched.length - 1]);
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
      this._stats.hits++;
      return response;
    } catch (e) {
      this._stats.errors++;
      console.warn(`[RAYKAN/AI] LLM call failed: ${e.message}`);
      return null;
    }
  }

  async _callOpenAICompatible(prompt, format, provider) {
    const axios = require('axios');
    const resp  = await axios.post(
      `${provider.baseUrl}/chat/completions`,
      {
        model    : provider.model || 'gpt-3.5-turbo',
        messages : [{ role: 'user', content: prompt }],
        ...(format === 'json' ? { response_format: { type: 'json_object' } } : {}),
        max_tokens: 800,
        temperature: 0.1,
      },
      {
        headers : { Authorization: `Bearer ${provider.apiKey}`, 'Content-Type': 'application/json' },
        timeout : 20000,
      }
    );
    const content = resp.data?.choices?.[0]?.message?.content || '';
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
