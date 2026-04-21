/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Orchestration Engine  v3.0
 *
 *  v3.0 — Production-hardened (2026-04-21):
 *   1. DEMO MODE COMPLETELY REMOVED — mock provider never used in production
 *   2. Strict API key enforcement — hard error if no real provider available
 *   3. NO module-level singleton — orchestrator built fresh per config change
 *      using live process.env values at construction time
 *   4. SOC-grade system prompt with mandatory structured CVE/threat-actor format
 *   5. Tool-result synthesis — LLM MUST synthesize tool data, never dumps raw
 *   6. Forced synthesis call if MAX_TOOL_ITERATIONS exhausted without text
 *   7. Provider key validation exposed via validateProviders()
 *   8. Full structured logging: requestId, provider, latency, tokens, errors
 *   9. getDiagnostics() returns key presence, circuit states, provider metrics
 *
 *  Architecture:
 *   RAKAYEngine (no singleton — fresh per config change)
 *   ├── MultiProviderOrchestrator (Gemini→Claude→DeepSeek→OpenAI)
 *   │   [Mock ONLY if RAKAY_ALLOW_MOCK=1 — NEVER in production]
 *   ├── RakayStore   (in-memory + optional Supabase)
 *   └── ToolRegistry (sigma, kql, ioc, mitre, cve, actor, nav)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { MultiProviderOrchestrator, getProviderMetrics, resetProviderMetrics, ALLOW_MOCK } = require('./llm-provider');
const store = require('./rakay-store');
const { executeTool, TOOL_SCHEMAS } = require('./rakay-tools');

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_TOOL_ITERATIONS  = 6;     // Max agentic loops before forced synthesis
const CONTEXT_WINDOW_MSGS  = 20;    // Messages to include in LLM context
const MAX_RESPONSE_TOKENS  = 4096;
const SYNTHESIS_TOKENS     = 4096;  // Tokens for the final forced synthesis call

// ── Production guard ──────────────────────────────────────────────────────────
// Log the production mode at module load time for visibility in server logs
console.log(`[RAKAYEngine] v3.0 loaded — mock_mode=${ALLOW_MOCK ? 'ENABLED(dev)' : 'DISABLED(production)'}`);

// ══════════════════════════════════════════════════════════════════════════════
//  SOC-GRADE SYSTEM PROMPT  v3.0
//  Enforces structured, expert-quality output. No demo, no placeholders.
// ══════════════════════════════════════════════════════════════════════════════
const SYSTEM_PROMPT = `You are RAKAY, an elite Tier-3 SOC analyst and detection engineering AI embedded in the Wadjet-Eye AI cybersecurity platform.

## IDENTITY & OPERATIONAL MODE
- **Mode:** PRODUCTION — real API calls, real intelligence, real analysis
- **Role:** Senior threat intelligence analyst at the level of CrowdStrike Falcon Intelligence, Mandiant, and Recorded Future
- **Prohibitions:** NEVER return demo content, placeholder text, or mock responses. NEVER say "I'm in demo mode". NEVER skip analysis because you think you lack data — use tools to get data.
- **Tool mandate:** You MUST invoke available tools for ANY query involving CVEs, IOCs, threat actors, IPs, domains, file hashes, Sigma rules, or MITRE ATT&CK techniques. Do NOT answer from memory when tools are available — always query first.

## MANDATORY BEHAVIOUR
1. **Use tools first** — for CVE/IOC/actor queries, call the relevant tool BEFORE writing your analysis
2. **Synthesize, never dump** — after tools run, write a complete analytical narrative; never say "see results above"
3. **Structured output always** — use the exact section formats below; no freeform walls of text
4. **Cite everything** — NVD, CISA KEV, MITRE ATT&CK, vendor advisories, threat reports
5. **No fabrication** — if a tool returns no data, say so explicitly; fall back to training knowledge ONLY when clearly labelled "⚠️ Based on training knowledge — verify with current sources"
6. **SOC-quality language** — technical depth, actionable intelligence, specific IOCs, exact MITRE IDs

## CVE QUERY OUTPUT FORMAT
For ANY query containing a CVE identifier, use this EXACT structure:

---
## {CVE-ID} — {Full Vulnerability Title}

**Severity:** {CRITICAL/HIGH/MEDIUM/LOW} | **CVSS v3.1:** {score}/10 | **EPSS:** {exploitation_probability}%
**CISA KEV Listed:** {Yes — added YYYY-MM-DD / No} | **Active Exploitation:** {Confirmed/Suspected/Not observed}

### OVERVIEW
| Field | Value |
|-------|-------|
| CVE ID | {CVE-ID} |
| Affected Product | {Vendor} {Product} {version range} |
| Vulnerability Class | {CWE-XXX — description} |
| Attack Vector | {Network/Adjacent Network/Local/Physical} |
| Privileges Required | {None/Low/High} |
| User Interaction | {None/Required} |
| Published | {YYYY-MM-DD} |
| Last Modified | {YYYY-MM-DD} |
| Patch Available | {Version X.Y.Z released YYYY-MM-DD / No patch available} |

### TECHNICAL ANALYSIS
{3-5 paragraphs of expert-level analysis:
- WHAT the vulnerability is (root cause, affected code path)
- HOW an attacker exploits it (step-by-step attack chain)
- WHY it is dangerous (impact: RCE, data exposure, privilege escalation, etc.)
- WHO is likely to exploit it (threat actor types, sophistication required)
- WHEN (exploitation complexity — is a public PoC available?)}

### MITRE ATT&CK MAPPING
| Technique | MITRE ID | Tactic |
|-----------|----------|--------|
| {technique} | {T1XXX.XXX} | {tactic} |

### DETECTION GUIDANCE

**Sigma Rule (SIEM-agnostic):**
\`\`\`yaml
title: Detect {CVE-ID} Exploitation Attempt
id: {generate-uuid}
status: experimental
description: Detects attempts to exploit {CVE-ID} in {product}
references:
  - https://nvd.nist.gov/vuln/detail/{CVE-ID}
  - {additional references}
author: RAKAY — Wadjet-Eye AI
date: {today YYYY-MM-DD}
tags:
  - attack.{tactic}
  - attack.{technique_id}
  - cve.{cve-id-lowercase}
logsource:
  category: {process_creation/network_connection/webserver/etc}
  product: {windows/linux/cloud}
detection:
  selection:
    {field}: {value}
  condition: selection
falsepositives:
  - {legitimate use case that may trigger}
level: {critical/high}
\`\`\`

**KQL (Microsoft Sentinel):**
\`\`\`kql
// Detect {CVE-ID} exploitation indicators
{TableName}
| where TimeGenerated > ago(7d)
| where {field} contains "{indicator}"
| project TimeGenerated, {relevant_fields}
| order by TimeGenerated desc
\`\`\`

**Splunk SPL:**
\`\`\`spl
index=* sourcetype={sourcetype}
{field}="{value}"
| table _time, host, {relevant_fields}
| sort -_time
\`\`\`

**IOCs to Hunt:**
- **File hashes:** {SHA256 hashes if known, else "None publicly confirmed"}
- **IPs/Domains:** {C2 infrastructure if known}
- **URLs/Paths:** {Exploit delivery or webshell paths if applicable}

### RECOMMENDED ACTIONS

**Immediate (0-24 hours):**
- {Specific, actionable step — e.g., "Apply patch version X.Y.Z from vendor advisory URL"}
- {Specific detection step}

**Short-term (1-7 days):**
- {Monitoring, threat hunting, hardening steps}

**Long-term:**
- {Architectural improvements, policy changes}

### SOURCES
- NVD: https://nvd.nist.gov/vuln/detail/{CVE-ID}
- CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK: https://attack.mitre.org/techniques/{T-ID}/
- {vendor advisory URL}
---

## THREAT ACTOR PROFILE OUTPUT FORMAT
For queries about APT groups, ransomware operations, or threat actors:

---
## Threat Actor: {Full Name} ({Common Aliases})

**Classification:** {Nation-state APT / Ransomware Group / Cybercriminal / Hacktivist}
**Attributed Origin:** {Country/Region} | **Active Since:** {Year}
**Primary Motivation:** {Espionage / Financial / Disruption / Ideology}
**Threat Level:** {CRITICAL / HIGH / MEDIUM}

### OVERVIEW
{3 paragraphs: who they are, their history, their primary targets and sectors}

### TACTICS, TECHNIQUES & PROCEDURES (TTPs)
| Kill Chain Phase | Technique | MITRE ID | Notes |
|-----------------|-----------|----------|-------|
| Initial Access | {technique} | {T1XXX} | {specific tool/method} |
| Execution | {technique} | {T1XXX.XXX} | {specific tool/method} |
| Persistence | {technique} | {T1XXX} | {specific tool/method} |
| Lateral Movement | {technique} | {T1XXX} | {specific tool/method} |
| Exfiltration | {technique} | {T1XXX} | {specific tool/method} |

### MALWARE & CUSTOM TOOLS
| Tool | Type | Description |
|------|------|-------------|
| {Tool name} | {RAT/Loader/Stealer/etc} | {Technical description} |

### RECENT CAMPAIGNS (Last 12 months)
{Specific dated campaigns with targets, TTPs, and outcomes}

### DETECTION & HUNTING

**Sigma Rule (Actor-specific TTP detection):**
\`\`\`yaml
title: Detect {Actor} TTP Indicators
id: {generate-uuid}
status: experimental
description: Detects TTPs associated with {Actor} threat group
references:
  - {threat intelligence report URL}
author: RAKAY — Wadjet-Eye AI
date: {today}
tags:
  - attack.{tactic}
  - attack.{technique_id}
logsource:
  category: {category}
  product: {product}
detection:
  selection:
    {field}: {actor-specific indicator}
  condition: selection
level: high
\`\`\`

### DEFENSIVE RECOMMENDATIONS
- {Specific mitigations targeting this actor's TTPs}
- {Recommended threat intelligence feeds and detection rules}

### INTELLIGENCE SOURCES
- MITRE ATT&CK Group: https://attack.mitre.org/groups/{group-id}/
- {vendor threat intelligence report}
---

## SIGMA RULE OUTPUT FORMAT
When generating a Sigma rule:

\`\`\`yaml
title: {Specific, descriptive title — what behavior this detects}
id: {random UUID v4}
status: {experimental/test/stable}
description: |
  {What this rule detects, why it matters, and what attack it maps to.
  2-3 sentences of technical context.}
references:
  - {CVE URL / blog / advisory}
author: RAKAY — Wadjet-Eye AI
date: {YYYY-MM-DD}
modified: {YYYY-MM-DD}
tags:
  - attack.{tactic_name}
  - attack.{technique_id}
  - detection.{category}
logsource:
  category: {process_creation/network_connection/file_event/registry_event/dns_query}
  product: {windows/linux/macos/cloud}
  service: {if applicable}
detection:
  selection_main:
    {field_1}|contains:
      - '{value_1}'
      - '{value_2}'
    {field_2}|endswith: '{value}'
  filter_legitimate:
    {false_positive_field}: '{legitimate_value}'
  condition: selection_main and not filter_legitimate
fields:
  - {key fields to include in alert context}
falsepositives:
  - {specific known legitimate use case}
level: {critical/high/medium/low}
\`\`\`

**Rule explanation:** {Technical explanation of what signals the rule catches, why those signals are suspicious, and the expected false positive rate}

## GENERAL RESPONSE RULES
- **Markdown always** — headers, tables, code blocks, bold emphasis
- **MITRE IDs** — always include exact technique IDs: T1XXX or T1XXX.XXX
- **Severity ladder** — CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL
- **No fabrication** — if data is unavailable, explicitly state it and label knowledge-based content
- **No filler** — no "I hope this helps", no "great question", no conversational padding
- **SOC analyst voice** — direct, technical, actionable

Platform: Wadjet-Eye AI | Mode: PRODUCTION | Real LLM execution | No demo/mock responses`;

// ══════════════════════════════════════════════════════════════════════════════
//  RAKAYEngine  v3.0
//  No module-level singleton, no demo mode, strict API key enforcement
// ══════════════════════════════════════════════════════════════════════════════

class RAKAYEngine {
  /**
   * @param {object} config
   * @param {string} [config.provider]        — 'auto' (default) | 'gemini' | 'anthropic' | 'deepseek' | 'openai'
   * @param {object} [config.apiKeys]         — { gemini, anthropic, deepseek, openai }
   * @param {string[]} [config.providerOrder] — override provider priority
   * @param {boolean}  [config.debug]         — enable verbose logging
   */
  constructor(config = {}) {
    this.debug = config.debug || process.env.RAKAY_DEBUG === '1';

    // Always read live env vars at construction time — keys may be set after module load
    this.apiKeys = {
      gemini:    config.apiKeys?.gemini    || process.env.GEMINI_API_KEY    || process.env.RAKAY_GEMINI_KEY    || process.env.GOOGLE_API_KEY || '',
      anthropic: config.apiKeys?.anthropic || process.env.CLAUDE_API_KEY    || process.env.ANTHROPIC_API_KEY   || process.env.RAKAY_ANTHROPIC_KEY || process.env.RAKAY_API_KEY || '',
      deepseek:  config.apiKeys?.deepseek  || process.env.DEEPSEEK_API_KEY  || process.env.RAKAY_DEEPSEEK_KEY  || '',
      openai:    config.apiKeys?.openai    || process.env.OPENAI_API_KEY    || process.env.RAKAY_OPENAI_KEY    || '',
    };

    this.providerOrder = config.providerOrder || null;
    this.providerName  = 'multi';

    // Build a fresh orchestrator with current keys.
    // We do NOT use the singleton getOrchestrator() to ensure we always
    // reflect the latest env vars — critical for Render's late key injection.
    this._orchestrator = new MultiProviderOrchestrator({
      apiKeys:       this.apiKeys,
      providerOrder: this.providerOrder,
      debug:         this.debug,
    });

    // Determine what is actually available
    const realKeys = Object.entries(this.apiKeys)
      .filter(([, v]) => v && v.length > 4)
      .map(([k]) => k);

    console.log(`[RAKAYEngine] v3.0 constructed — real_keys=[${realKeys.join(', ') || 'NONE'}] mock_allowed=${ALLOW_MOCK}`);

    if (realKeys.length === 0 && !ALLOW_MOCK) {
      // Log a prominent error — requests will fail until keys are set
      console.error('════════════════════════════════════════════════════════════════');
      console.error('[RAKAYEngine] ❌ NO AI PROVIDER KEYS CONFIGURED');
      console.error('[RAKAYEngine] All real LLM calls will fail until keys are provided:');
      console.error('[RAKAYEngine]   GEMINI_API_KEY    = Google Gemini (recommended)');
      console.error('[RAKAYEngine]   CLAUDE_API_KEY    = Anthropic Claude');
      console.error('[RAKAYEngine]   DEEPSEEK_API_KEY  = DeepSeek');
      console.error('[RAKAYEngine]   OPENAI_API_KEY    = OpenAI GPT-4');
      console.error('════════════════════════════════════════════════════════════════');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MAIN ENTRY POINT: chat()
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Process a user message through the full agentic pipeline.
   *
   * @param {object} opts
   * @param {string}   opts.message    — user message text
   * @param {string}   opts.sessionId  — conversation session ID
   * @param {string}   opts.tenantId
   * @param {string}   opts.userId
   * @param {object}   [opts.context]  — extra context (currentPage, userRole, etc.)
   * @param {boolean}  [opts.useTools] — enable tool calling (default true)
   * @returns {Promise<RAKAYResponse>}
   */
  async chat({ message, sessionId, tenantId, userId, context = {}, useTools = true }) {
    const startTime   = Date.now();
    const toolTrace   = [];
    let   totalTokens = 0;
    const reqId       = `rakay_${Date.now().toString(36)}`;

    console.log(`[RAKAYEngine:${reqId}] START session=${sessionId?.slice(0,12)} provider=multi len=${message?.length}`);
    if (this.debug) {
      const keySummary = Object.entries(this.apiKeys)
        .map(([k, v]) => `${k}:${v ? v.slice(0,8)+'...' : 'MISSING'}`)
        .join(' ');
      console.log(`[RAKAYEngine:${reqId}] Keys: ${keySummary}`);
    }

    // ── 1. Session management ─────────────────────────────────────────────────
    let session = await store.getSession({ sessionId, tenantId });
    if (!session) {
      console.warn(`[RAKAYEngine:${reqId}] Session not found — auto-creating: ${sessionId?.slice(0, 12)}`);
      session = await store.createSession({ tenantId, userId, sessionId });
      if (!session) {
        throw new Error(`Session not found and could not be created: ${sessionId}`);
      }
    }

    // ── 2. Persist user message ───────────────────────────────────────────────
    await store.appendMessage({ sessionId, role: 'user', content: message });

    // Auto-title from first message
    if (session.message_count === 0 && session.title === 'New Chat') {
      await store.updateSession({ sessionId, tenantId, updates: { title: _generateTitle(message) } });
    }

    // ── 3. Load conversation context ──────────────────────────────────────────
    const history = await store.getLLMContext({ sessionId, window: CONTEXT_WINDOW_MSGS });

    // ── 4. Build message list ─────────────────────────────────────────────────
    const systemMsg  = { role: 'system', content: _buildSystemPrompt(context) };
    let   msgHistory = [systemMsg, ...history];

    // ── 5. Agentic loop ───────────────────────────────────────────────────────
    let   iteration = 0;
    let   finalText = '';
    let   lastLLMResponse = null;

    while (iteration < MAX_TOOL_ITERATIONS) {
      iteration++;

      const llmTools    = useTools ? TOOL_SCHEMAS : [];
      console.log(`[RAKAYEngine:${reqId}] LLM call iteration=${iteration} msgs=${msgHistory.length} tools=${llmTools.length}`);

      const llmResponse = await this._orchestrator.chat(msgHistory, llmTools, {
        max_tokens: MAX_RESPONSE_TOKENS,
      });

      lastLLMResponse = llmResponse;
      totalTokens += llmResponse.usage?.totalTokens || llmResponse.usage?.total_tokens || 0;

      console.log(`[RAKAYEngine:${reqId}] LLM responded provider=${llmResponse.provider} tokens=${llmResponse.usage?.totalTokens || 0} content_len=${llmResponse.content?.length || 0}`);

      const toolCalls = llmResponse.toolCalls || llmResponse.tool_calls || [];

      // ── Case A: No tool calls — final text response ───────────────────────
      if (!toolCalls.length) {
        finalText = llmResponse.content || '';
        console.log(`[RAKAYEngine:${reqId}] Final response iteration=${iteration} len=${finalText.length}`);
        break;
      }

      // ── Case B: LLM called tools — execute and feed back ──────────────────
      console.log(`[RAKAYEngine:${reqId}] Tool calls: ${toolCalls.map(t => t.name || t.function?.name).join(', ')}`);
      const toolCallResults = [];

      for (const tc of toolCalls) {
        const toolName = tc.name || tc.function?.name;
        const rawArgs  = tc.arguments || tc.function?.arguments || {};
        const toolArgs = typeof rawArgs === 'string' ? _parseToolArgs(rawArgs) : rawArgs;
        const callId   = tc.id || `call_${Date.now()}_${toolName}`;

        let toolResult;
        try {
          toolResult = await executeTool(toolName, toolArgs, {
            tenantId,
            userId,
            authHeader: context?.authHeader,
          });
          console.log(`[RAKAYEngine:${reqId}] Tool ${toolName} → OK`);
        } catch (toolErr) {
          console.error(`[RAKAYEngine:${reqId}] Tool ${toolName} → ERROR: ${toolErr.message}`);
          toolResult = {
            result: { error: toolErr.message, tool: toolName },
            metadata: { error: true },
          };
        }

        toolTrace.push({
          iteration,
          tool:      toolName,
          args:      toolArgs,
          result:    toolResult.result,
          metadata:  toolResult.metadata,
          timestamp: new Date().toISOString(),
        });

        toolCallResults.push({
          tool_call_id: callId,
          role:         'tool',
          name:         toolName,
          content:      JSON.stringify(toolResult.result),
        });
      }

      // Append assistant tool-call turn
      msgHistory.push({
        role:       'assistant',
        content:    llmResponse.content || null,
        tool_calls: toolCalls.map(tc => ({
          id:       tc.id,
          type:     'function',
          function: {
            name:      tc.name || tc.function?.name,
            arguments: JSON.stringify(tc.arguments || tc.function?.arguments || {}),
          },
        })),
      });

      // Append tool results
      for (const tr of toolCallResults) {
        msgHistory.push(tr);
      }
    }

    // ── 6. FORCED SYNTHESIS if loop exhausted without text ────────────────────
    // This is the critical fix: if the LLM kept calling tools but never returned
    // a text response, force one final synthesis call with all accumulated data.
    if (!finalText && toolTrace.length > 0) {
      console.warn(`[RAKAYEngine:${reqId}] Loop exhausted after ${iteration} iterations — forcing synthesis`);

      // Build a synthesis instruction that gives the LLM ALL the tool data
      const toolSummary = toolTrace.map(t =>
        `### Tool: ${t.tool}\nArguments: ${JSON.stringify(t.args)}\nResult:\n${JSON.stringify(t.result, null, 2)}`
      ).join('\n\n---\n\n');

      msgHistory.push({
        role:    'user',
        content: `Based on ALL the tool results above, provide a complete, structured analysis following the SOC analyst output format. Here is a summary of all tool data collected:\n\n${toolSummary}\n\nProvide your complete analytical response now. Do NOT say "please review above" — write the full analysis yourself.`,
      });

      try {
        const synthesisResponse = await this._orchestrator.chat(msgHistory, [], {
          max_tokens: SYNTHESIS_TOKENS,
        });
        finalText = synthesisResponse.content || '';
        totalTokens += synthesisResponse.usage?.totalTokens || 0;
        console.log(`[RAKAYEngine:${reqId}] Synthesis succeeded len=${finalText.length}`);
      } catch (synthErr) {
        console.error(`[RAKAYEngine:${reqId}] Synthesis failed: ${synthErr.message}`);
        // Last resort: format the raw tool data ourselves
        finalText = _formatToolDataFallback(toolTrace, message);
      }
    }

    // ── 7. Final fallback — should never reach this ───────────────────────────
    if (!finalText) {
      if (lastLLMResponse?.content) {
        finalText = lastLLMResponse.content;
      } else {
        console.error(`[RAKAYEngine:${reqId}] CRITICAL: No response generated after full pipeline`);
        finalText = `⚠️ **Analysis incomplete** — the AI pipeline ran ${iteration} iterations but produced no text output. This indicates a provider configuration issue.\n\n**Debug info:**\n- Tools used: ${toolTrace.length}\n- Iterations: ${iteration}\n- Provider: ${lastLLMResponse?.provider || 'unknown'}\n\nPlease verify API keys are set correctly on the server: \`GEMINI_API_KEY\`, \`CLAUDE_API_KEY\`, \`DEEPSEEK_API_KEY\`, \`OPENAI_API_KEY\`.`;
      }
    }

    // ── 8. Persist assistant response ─────────────────────────────────────────
    const assistantMsg = await store.appendMessage({
      sessionId,
      role:        'assistant',
      content:     finalText,
      toolCalls:   toolTrace.length ? toolTrace.map(t => ({ tool: t.tool, args: t.args })) : undefined,
      toolResults: toolTrace.length ? toolTrace.map(t => t.result) : undefined,
      tokensUsed:  totalTokens,
      modelId:     lastLLMResponse?.model || 'auto',
    });

    const latencyMs = Date.now() - startTime;
    console.log(`[RAKAYEngine:${reqId}] COMPLETE latency=${latencyMs}ms tokens=${totalTokens} provider=${lastLLMResponse?.provider || 'unknown'}`);

    // ── 9. Return structured response ─────────────────────────────────────────
    return {
      id:          assistantMsg.id,
      session_id:  sessionId,
      content:     finalText,
      role:        'assistant',
      tool_trace:  toolTrace,
      tokens_used: totalTokens,
      model:       lastLLMResponse?.model || 'auto',
      provider:    lastLLMResponse?.provider || this.providerName,
      latency_ms:  latencyMs,
      created_at:  assistantMsg.created_at,
      _debug: this.debug ? {
        iterations: iteration,
        tools_used: toolTrace.map(t => t.tool),
        orchestrator: lastLLMResponse?.orchestrator,
      } : undefined,
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  SESSION MANAGEMENT
  // ══════════════════════════════════════════════════════════════════════════

  async createSession({ tenantId, userId, title }) {
    return store.createSession({ tenantId, userId, title });
  }

  async listSessions({ tenantId, userId, limit = 50 }) {
    return store.listSessions({ tenantId, userId, limit });
  }

  async getHistory({ sessionId, tenantId, limit = 50 }) {
    const session = await store.getSession({ sessionId, tenantId });
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    return store.getHistory({ sessionId, limit });
  }

  async deleteSession({ sessionId, tenantId }) {
    return store.deleteSession({ sessionId, tenantId });
  }

  async renameSession({ sessionId, tenantId, title }) {
    return store.updateSession({ sessionId, tenantId, updates: { title } });
  }

  async searchHistory({ tenantId, userId, query, limit = 20 }) {
    return store.searchHistory({ tenantId, userId, query, limit });
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  CAPABILITIES & DIAGNOSTICS
  // ══════════════════════════════════════════════════════════════════════════

  getCapabilities() {
    const orchCaps = this._orchestrator.getCapabilities ? this._orchestrator.getCapabilities() : {};
    return {
      provider:       this.providerName,
      model:          'auto',
      orchestrator:   orchCaps,
      tools:          TOOL_SCHEMAS.map(t => ({
        name:        t.function.name,
        description: t.function.description,
      })),
      context_window: CONTEXT_WINDOW_MSGS,
      max_iterations: MAX_TOOL_ITERATIONS,
    };
  }

  /**
   * Live-test all configured API keys with a lightweight ping call.
   * Returns per-provider { status, model, latencyMs, error? }.
   */
  async validateProviders() {
    return this._orchestrator.validateProviders();
  }

  /**
   * Reset all circuit breakers (call after fixing a broken API key).
   */
  resetCircuits() {
    return this._orchestrator.resetCircuits();
  }

  /**
   * Return comprehensive diagnostic info:
   * - API key presence and key prefix (never full key)
   * - Circuit breaker states per provider
   * - Provider-level metrics (latency, success rates)
   * - Mock mode status
   * - Orchestrator capabilities
   */
  getDiagnostics() {
    const keySummary = {};
    for (const [provider, key] of Object.entries(this.apiKeys)) {
      keySummary[provider] = key && key.length > 4
        ? { configured: true,  prefix: key.slice(0, 6) + '…' + key.slice(-4), length: key.length }
        : { configured: false, error: 'Key not set or too short' };
    }

    const orchCaps = this._orchestrator.getCapabilities();

    return {
      version:          'v3.0',
      mode:             ALLOW_MOCK ? 'development (mock enabled)' : 'production (mock disabled)',
      timestamp:        new Date().toISOString(),
      keys:             keySummary,
      orchestrator:     orchCaps,
      metrics:          getProviderMetrics(),
      capabilities:     this.getCapabilities(),
      realProviders:    orchCaps.realProviders || [],
      mockEnabled:      ALLOW_MOCK,
      readyForProduction: (orchCaps.realProviders || []).length > 0,
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INTERNAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function _buildSystemPrompt(context = {}) {
  let prompt = SYSTEM_PROMPT;
  if (context.currentPage) prompt += `\n\n**User's current page:** ${context.currentPage}`;
  if (context.userRole)    prompt += `\n**User role:** ${context.userRole}`;
  if (context.tenantName)  prompt += `\n**Organisation:** ${context.tenantName}`;
  return prompt;
}

function _parseToolArgs(argsInput) {
  if (typeof argsInput === 'object' && argsInput !== null) return argsInput;
  if (typeof argsInput === 'string') {
    try { return JSON.parse(argsInput); } catch { return {}; }
  }
  return {};
}

function _generateTitle(message) {
  const words = message.replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean);
  const title = words.slice(0, 6).join(' ');
  return title.length > 50 ? title.slice(0, 50) + '…' : (title || 'Chat');
}

/**
 * Last-resort formatter: turns raw tool data into a structured markdown report
 * when both the agentic loop AND the synthesis call fail.
 *
 * This should be extremely rare — it only triggers if:
 *  1. All MAX_TOOL_ITERATIONS tool calls completed
 *  2. The forced synthesis LLM call also failed
 *
 * In this case we format the raw tool data as best we can so the user
 * still gets some value from the query.
 */
function _formatToolDataFallback(toolTrace, originalQuery) {
  const lines = [
    `## ⚠️ Analysis — LLM Synthesis Failed`,
    '',
    `**Query:** ${originalQuery}`,
    '',
    '> **Note:** The AI analysis pipeline collected tool data but could not synthesize a response. This indicates all AI provider API keys are misconfigured or rate-limited. Raw tool results are shown below. Configure valid API keys (GEMINI_API_KEY, CLAUDE_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY) for full AI-synthesized analysis.',
    '',
    '---',
    '',
  ];

  if (toolTrace.length === 0) {
    lines.push('No tool data was collected during this request.');
    return lines.join('\n');
  }

  for (const t of toolTrace) {
    lines.push(`### Tool: \`${t.tool}\``);
    if (t.args && Object.keys(t.args).length) {
      lines.push(`**Arguments:** \`${JSON.stringify(t.args)}\``);
    }
    const result = t.result;
    if (result && typeof result === 'object') {
      if (result.error) {
        lines.push(`**Error:** ${result.error}`);
      } else if (result.rules && Array.isArray(result.rules)) {
        lines.push(`**${result.rules.length} rule(s) found:**`);
        result.rules.slice(0, 5).forEach(r => {
          lines.push('```yaml', (r.content || JSON.stringify(r, null, 2)).slice(0, 1000), '```');
        });
      } else if (result.description || result.severity) {
        if (result.severity) lines.push(`**Severity:** ${result.severity}`);
        if (result.score)    lines.push(`**CVSS Score:** ${result.score}`);
        if (result.description) lines.push(`**Description:** ${result.description}`);
      } else {
        lines.push('```json');
        lines.push(JSON.stringify(result, null, 2).slice(0, 2000));
        lines.push('```');
      }
    } else if (result !== undefined && result !== null) {
      lines.push(String(result).slice(0, 800));
    } else {
      lines.push('*(no result)*');
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ── Module exports ────────────────────────────────────────────────────────────
// NOTE: RAKAYEngine is NOT exported as a singleton.
// The route layer (_getEngine) instantiates it fresh on each config change,
// ensuring live process.env values are always used.

module.exports = { RAKAYEngine };
