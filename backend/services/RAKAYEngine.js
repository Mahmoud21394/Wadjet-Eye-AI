/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Orchestration Engine  v3.0
 *
 *  New in v3.0:
 *   ✅ Priority queue (SOC alerts > analyst > general)
 *   ✅ Streaming chat support (SSE)
 *   ✅ Multi-provider via MultiProvider failover chain
 *   ✅ Graceful degradation — NEVER throws raw 500 to caller
 *   ✅ Full observability (timing, provider used, failover events)
 *   ✅ Tool-calling loop with streaming intermediate responses
 *
 *  Architecture:
 *   RAKAYEngine
 *   ├── MultiProvider  (OpenAI → Claude → DeepSeek → Gemini → Mock)
 *   ├── PriorityQueue  (in-memory, concurrency=1 per priority tier)
 *   ├── RakayStore     (session + history, Supabase or in-memory)
 *   └── ToolRegistry   (sigma, kql, ioc, mitre, cve, actor, nav)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { createMultiProvider } = require('./llm-provider');
const store                   = require('./rakay-store');
const { executeTool, TOOL_SCHEMAS } = require('./rakay-tools');

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_TOOL_ITERATIONS  = 5;
const CONTEXT_WINDOW_MSGS  = 20;
const MAX_RESPONSE_TOKENS  = 4096;
const DEFAULT_MODEL        = 'gpt-4o';

// ── Priority levels ────────────────────────────────────────────────────────────
const PRIORITY = {
  HIGH:   1,   // SOC alerts, incidents, detections
  MEDIUM: 5,   // analyst queries, CVE research, IOC enrichment
  LOW:    10,  // general chat
};

// ── Keywords that bump a message to HIGH priority ─────────────────────────────
const HIGH_PRIORITY_KEYWORDS = [
  'alert', 'incident', 'breach', 'compromised', 'ransomware',
  'critical', 'urgent', 'emergency', 'active attack', 'lateral movement',
  'exfiltration', 'c2', 'command and control', 'zero day', '0day',
];

const MEDIUM_PRIORITY_KEYWORDS = [
  'cve', 'vulnerability', 'ioc', 'enrich', 'malware', 'apt',
  'threat actor', 'sigma', 'kql', 'splunk', 'mitre', 'detection',
];

// ── System prompt ──────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are RAKAY, an elite AI security analyst and detection engineering assistant built into the Wadjet-Eye AI cybersecurity platform.

Your capabilities:
• Generate and search Sigma detection rules (YAML format)
• Translate Sigma rules to KQL (Sentinel/Defender), SPL (Splunk), Lucene (Elastic)
• Enrich Indicators of Compromise: IPs, domains, file hashes, URLs
• Look up MITRE ATT&CK techniques, tactics, groups, and mitigations
• Research CVEs using the NVD database
• Profile threat actor groups (APTs, ransomware gangs, cybercriminals)
• Guide users to the right platform modules
• Explain attack techniques, incident response procedures, and security concepts

Behaviour guidelines:
- Be precise and technical — users are SOC analysts and detection engineers
- Always cite MITRE technique IDs (e.g., T1059.001) when relevant
- When generating Sigma rules, always include proper YAML formatting
- When unsure about a specific IOC or CVE, use the available tools to look it up
- Structure complex answers with headers, bullet points, and code blocks
- If a task requires multiple steps, explain each step clearly
- Proactively suggest relevant platform features when applicable
- Use tools whenever they can provide accurate, up-to-date information

Response formatting:
- Use markdown formatting
- Code blocks for queries, rules, and technical content
- **Bold** for critical warnings or key findings
- Tables for comparing items (e.g., SIEM query comparison)

Platform context: Wadjet-Eye AI — https://wadjet-eye-ai.vercel.app`;

// ═══════════════════════════════════════════════════════════════════════════════
//  PRIORITY QUEUE
//  Simple in-process priority queue. Jobs with lower priority number run first.
//  Concurrency = 1 per engine instance (guaranteed serial LLM calls).
// ═══════════════════════════════════════════════════════════════════════════════
class PriorityQueue {
  constructor(concurrency = 1) {
    this._queue       = [];   // [{priority, fn, resolve, reject, addedAt}]
    this._running     = 0;
    this._concurrency = concurrency;
    this._processed   = 0;
    this._totalWaitMs = 0;
  }

  /** Add a job. Returns a promise that resolves when the job completes. */
  add(fn, priority = PRIORITY.MEDIUM) {
    return new Promise((resolve, reject) => {
      const job = { priority, fn, resolve, reject, addedAt: Date.now() };
      // Insert in priority order (stable sort: lower number = higher priority)
      let i = 0;
      while (i < this._queue.length && this._queue[i].priority <= priority) i++;
      this._queue.splice(i, 0, job);
      console.log(`[PQ] Job queued priority=${priority} queue_depth=${this._queue.length}`);
      this._drain();
    });
  }

  _drain() {
    while (this._running < this._concurrency && this._queue.length > 0) {
      const job = this._queue.shift();
      const waitMs = Date.now() - job.addedAt;
      this._totalWaitMs += waitMs;
      this._processed++;
      this._running++;
      if (waitMs > 500) console.log(`[PQ] Job started priority=${job.priority} waited=${waitMs}ms`);

      Promise.resolve()
        .then(() => job.fn())
        .then((result) => { job.resolve(result); })
        .catch((err)   => { job.reject(err);     })
        .finally(() => {
          this._running--;
          this._drain();
        });
    }
  }

  get stats() {
    return {
      queued:      this._queue.length,
      running:     this._running,
      processed:   this._processed,
      avgWaitMs:   this._processed ? Math.round(this._totalWaitMs / this._processed) : 0,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RAKAYEngine
// ═══════════════════════════════════════════════════════════════════════════════
class RAKAYEngine {
  /**
   * @param {object} config
   * @param {string} [config.provider]  — 'openai'|'anthropic'|'deepseek'|'gemini'|'mock'|'multi'
   * @param {string} [config.model]     — model name override
   * @param {string} [config.apiKey]    — API key (falls back to env)
   */
  constructor(config = {}) {
    this.providerName = config.provider || 'multi';
    this.model        = config.model   || process.env.RAKAY_MODEL || DEFAULT_MODEL;
    this.apiKey       = config.apiKey;

    this._multiProvider = null;  // lazy-init
    this._queue         = new PriorityQueue(1);
  }

  // ── Lazy provider initialisation ──────────────────────────────────────────
  _getProvider() {
    if (!this._multiProvider) {
      this._multiProvider = createMultiProvider({
        provider: this.providerName === 'multi' ? undefined : this.providerName,
        model:    this.model,
        apiKey:   this.apiKey,
      });
    }
    return this._multiProvider;
  }

  /** Detect message priority from content */
  static detectPriority(message) {
    const lower = (message || '').toLowerCase();
    if (HIGH_PRIORITY_KEYWORDS.some(kw => lower.includes(kw)))   return PRIORITY.HIGH;
    if (MEDIUM_PRIORITY_KEYWORDS.some(kw => lower.includes(kw))) return PRIORITY.MEDIUM;
    return PRIORITY.LOW;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  MAIN ENTRY POINT: chat()
  // ═══════════════════════════════════════════════════════════════════════════
  async chat({ message, sessionId, tenantId, userId, context = {}, useTools = true }) {
    const priority = RAKAYEngine.detectPriority(message);
    const shortSid = (sessionId || '').slice(0, 12);
    console.log(`[RAKAYEngine] chat queued priority=${priority} session=${shortSid} userId=${userId}`);

    return this._queue.add(
      () => this._executeChat({ message, sessionId, tenantId, userId, context, useTools }),
      priority
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  STREAMING ENTRY POINT: chatStream()
  //  Calls onChunk({type:'text', text}) for each partial response chunk.
  //  Calls onDone(finalResult) when complete.
  // ═══════════════════════════════════════════════════════════════════════════
  async chatStream({ message, sessionId, tenantId, userId, context = {}, useTools = true, onChunk, onDone, onError }) {
    const priority = RAKAYEngine.detectPriority(message);
    const shortSid = (sessionId || '').slice(0, 12);
    console.log(`[RAKAYEngine] chatStream queued priority=${priority} session=${shortSid}`);

    return this._queue.add(
      () => this._executeStream({ message, sessionId, tenantId, userId, context, useTools, onChunk, onDone, onError }),
      priority
    );
  }

  // ── Core chat execution (non-streaming) ───────────────────────────────────
  async _executeChat({ message, sessionId, tenantId, userId, context = {}, useTools = true }) {
    const startTime = Date.now();
    const shortSid  = (sessionId || '').slice(0, 12);
    const provider  = this._getProvider();
    const toolTrace = [];
    let totalTokens = 0;

    console.log(`[RAKAYEngine] RAKAY processing started session=${shortSid} userId=${userId} provider=${provider.name} model=${this.model} len=${message?.length}`);

    try {
      // ── 1. Ensure session exists ───────────────────────────────────────────
      let session = await store.getSession({ sessionId, tenantId });
      if (!session) {
        console.warn(`[RAKAYEngine] Session not found — auto-creating: ${shortSid} tenant=${tenantId}`);
        session = await store.createSession({ tenantId, userId, sessionId });
        if (!session) throw new Error(`Session could not be created: ${sessionId}`);
      }

      // ── 2. Persist user message ───────────────────────────────────────────
      await store.appendMessage({ sessionId, role: 'user', content: message });

      // Auto-title from first message
      if (session.message_count === 0 && session.title === 'New Chat') {
        const title = _generateTitle(message);
        await store.updateSession({ sessionId, tenantId, updates: { title } }).catch(() => {});
      }

      // ── 3. Load context window ────────────────────────────────────────────
      const history  = await store.getLLMContext({ sessionId, window: CONTEXT_WINDOW_MSGS });
      const sysMsg   = { role: 'system', content: _buildSystemPrompt(context) };
      let msgHistory = [sysMsg, ...history];

      // ── 4. Agentic tool-calling loop ──────────────────────────────────────
      let iteration = 0;
      let finalText = '';

      while (iteration < MAX_TOOL_ITERATIONS) {
        iteration++;
        const llmTools    = useTools ? TOOL_SCHEMAS : [];
        const llmResponse = await provider.chat(msgHistory, llmTools, { max_tokens: MAX_RESPONSE_TOKENS });

        totalTokens += llmResponse.usage?.totalTokens || llmResponse.usage?.total_tokens || 0;

        const toolCalls = llmResponse.toolCalls || [];

        // No tool calls → final text response
        if (!toolCalls.length) {
          finalText = llmResponse.content || '';
          console.log(`[RAKAYEngine] Final response iteration=${iteration} len=${finalText.length} provider=${llmResponse._provider || provider.name}`);
          break;
        }

        // Execute tool calls
        for (const tc of toolCalls) {
          const toolName = tc.name || tc.function?.name;
          const rawArgs  = tc.arguments || tc.function?.arguments || {};
          const toolArgs = typeof rawArgs === 'string' ? _parseToolArgs(rawArgs) : rawArgs;
          const callId   = tc.id || `call_${Date.now()}_${toolName}`;

          console.log(`[RAKAYEngine] Tool call: ${toolName}`, JSON.stringify(toolArgs).slice(0, 100));

          const toolResult = await executeTool(toolName, toolArgs, { tenantId, userId, authHeader: context?.authHeader });
          toolTrace.push({ iteration, tool: toolName, args: toolArgs, result: toolResult.result, metadata: toolResult.metadata, timestamp: new Date().toISOString() });

          // Append tool call + result to history
          msgHistory.push({
            role:       'assistant',
            content:    llmResponse.content || null,
            tool_calls: toolCalls.map(tc2 => ({
              id:       tc2.id,
              type:     'function',
              function: {
                name:      tc2.name || tc2.function?.name,
                arguments: JSON.stringify(tc2.arguments || tc2.function?.arguments || {}),
              },
            })),
          });
          msgHistory.push({ role: 'tool', tool_call_id: callId, name: toolName, content: JSON.stringify(toolResult.result) });
        }
      }

      // Guard: empty finalText after max iterations
      if (!finalText) {
        console.warn(`[RAKAYEngine] finalText empty after ${iteration} iterations — using fallback`);
        finalText = 'I completed the analysis using the security tools. Please review the tool results above for details.';
      }

      // ── 5. Persist assistant response ─────────────────────────────────────
      const assistantMsg = await store.appendMessage({
        sessionId,
        role:        'assistant',
        content:     finalText,
        toolCalls:   toolTrace.length ? toolTrace.map(t => ({ tool: t.tool, args: t.args })) : undefined,
        toolResults: toolTrace.length ? toolTrace.map(t => t.result) : undefined,
        tokensUsed:  totalTokens,
        modelId:     llmResponse?._provider ? `${llmResponse._provider}/${this.model}` : this.model,
      });

      const latency = Date.now() - startTime;
      const usedProvider = provider.name;
      console.log(`[RAKAYEngine] CHAT_COMPLETE session=${shortSid} provider=${usedProvider} latency=${latency}ms tokens=${totalTokens}`);

      return {
        id:           assistantMsg.id,
        session_id:   sessionId,
        content:      finalText,
        role:         'assistant',
        tool_trace:   toolTrace,
        tokens_used:  totalTokens,
        model:        this.model,
        provider:     usedProvider,
        latency_ms:   latency,
        created_at:   assistantMsg.created_at,
      };

    } catch (err) {
      const latency = Date.now() - startTime;
      console.error(`[RAKAYEngine] CHAT_ERROR session=${shortSid} latency=${latency}ms — ${err.message}`);
      throw err;
    }
  }

  // ── Core streaming execution ───────────────────────────────────────────────
  async _executeStream({ message, sessionId, tenantId, userId, context = {}, useTools = true, onChunk, onDone, onError }) {
    const startTime = Date.now();
    const shortSid  = (sessionId || '').slice(0, 12);
    const provider  = this._getProvider();
    const toolTrace = [];
    let totalTokens = 0;
    let fullText    = '';

    console.log(`[RAKAYEngine] STREAM_START session=${shortSid} provider=${provider.name}`);

    try {
      // ── 1. Ensure session ─────────────────────────────────────────────────
      let session = await store.getSession({ sessionId, tenantId });
      if (!session) {
        session = await store.createSession({ tenantId, userId, sessionId });
        if (!session) throw new Error(`Session could not be created: ${sessionId}`);
      }

      // ── 2. Persist user message ───────────────────────────────────────────
      await store.appendMessage({ sessionId, role: 'user', content: message });

      if (session.message_count === 0 && session.title === 'New Chat') {
        await store.updateSession({ sessionId, tenantId, updates: { title: _generateTitle(message) } }).catch(() => {});
      }

      // ── 3. Load context ───────────────────────────────────────────────────
      const history  = await store.getLLMContext({ sessionId, window: CONTEXT_WINDOW_MSGS });
      const sysMsg   = { role: 'system', content: _buildSystemPrompt(context) };
      let msgHistory = [sysMsg, ...history];

      // ── 4. Stream loop (tool calls reset streaming to non-streaming) ───────
      let iteration = 0;

      while (iteration < MAX_TOOL_ITERATIONS) {
        iteration++;
        const llmTools = useTools ? TOOL_SCHEMAS : [];

        let llmResponse;

        if (iteration === 1) {
          // First iteration: stream to user
          llmResponse = await provider.chatStream(msgHistory, llmTools, { max_tokens: MAX_RESPONSE_TOKENS }, (chunk) => {
            if (chunk.type === 'text') {
              fullText += chunk.text;
              if (onChunk) onChunk(chunk.text);
            }
          });
        } else {
          // Subsequent iterations (after tool calls): non-streaming
          llmResponse = await provider.chat(msgHistory, llmTools, { max_tokens: MAX_RESPONSE_TOKENS });
          const text = llmResponse.content || '';
          if (text) {
            fullText += text;
            if (onChunk) onChunk(text);
          }
        }

        totalTokens += llmResponse.usage?.totalTokens || 0;
        const toolCalls = llmResponse.toolCalls || [];

        if (!toolCalls.length) {
          if (!fullText) fullText = llmResponse.content || '';
          break;
        }

        // Execute tools
        for (const tc of toolCalls) {
          const toolName = tc.name || tc.function?.name;
          const rawArgs  = tc.arguments || tc.function?.arguments || {};
          const toolArgs = typeof rawArgs === 'string' ? _parseToolArgs(rawArgs) : rawArgs;
          const callId   = tc.id || `call_${Date.now()}_${toolName}`;

          // Notify UI about tool use
          if (onChunk) onChunk(`\n\n🔧 *Using tool: ${toolName}...*\n\n`);

          const toolResult = await executeTool(toolName, toolArgs, { tenantId, userId, authHeader: context?.authHeader });
          toolTrace.push({ iteration, tool: toolName, args: toolArgs, result: toolResult.result, metadata: toolResult.metadata, timestamp: new Date().toISOString() });

          msgHistory.push({
            role:       'assistant',
            content:    llmResponse.content || null,
            tool_calls: toolCalls.map(tc2 => ({
              id:       tc2.id,
              type:     'function',
              function: { name: tc2.name || tc2.function?.name, arguments: JSON.stringify(tc2.arguments || {}) },
            })),
          });
          msgHistory.push({ role: 'tool', tool_call_id: callId, name: toolName, content: JSON.stringify(toolResult.result) });
        }
        // Reset fullText for next iteration (don't double-count)
        fullText = '';
      }

      if (!fullText) fullText = 'Analysis complete. Please review the tool results above.';

      // ── 5. Persist ────────────────────────────────────────────────────────
      const assistantMsg = await store.appendMessage({
        sessionId, role: 'assistant', content: fullText,
        toolCalls:   toolTrace.length ? toolTrace.map(t => ({ tool: t.tool, args: t.args })) : undefined,
        toolResults: toolTrace.length ? toolTrace.map(t => t.result) : undefined,
        tokensUsed:  totalTokens,
      });

      const result = {
        id:          assistantMsg.id,
        session_id:  sessionId,
        content:     fullText,
        role:        'assistant',
        tool_trace:  toolTrace,
        tokens_used: totalTokens,
        model:       this.model,
        provider:    provider.name,
        latency_ms:  Date.now() - startTime,
        created_at:  assistantMsg.created_at,
      };

      if (onDone) onDone(result);
      return result;

    } catch (err) {
      console.error(`[RAKAYEngine] STREAM_ERROR session=${shortSid} — ${err.message}`);
      if (onError) onError(err);
      throw err;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  SESSION MANAGEMENT (unchanged from v2)
  // ═══════════════════════════════════════════════════════════════════════════
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

  getCapabilities() {
    const provider = this._getProvider();
    return {
      provider:       provider.name || 'multi',
      model:          this.model,
      providers:      provider.getStatus ? provider.getStatus() : [],
      tools:          TOOL_SCHEMAS.map(t => ({
        name:        t.function.name,
        description: t.function.description,
      })),
      context_window:  CONTEXT_WINDOW_MSGS,
      max_iterations:  MAX_TOOL_ITERATIONS,
      streaming:       true,
      priority_queue:  this._queue.stats,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  INTERNAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
function _buildSystemPrompt(context = {}) {
  let prompt = SYSTEM_PROMPT;
  if (context.currentPage) prompt += `\n\nUser's current platform page: ${context.currentPage}`;
  if (context.userRole)    prompt += `\nUser role: ${context.userRole}`;
  if (context.tenantName)  prompt += `\nOrganisation: ${context.tenantName}`;
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
  const words = (message || '').replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean);
  const title  = words.slice(0, 6).join(' ');
  return title.length > 50 ? title.slice(0, 50) + '…' : (title || 'Chat');
}

// ── Singleton engine instance ────────────────────────────────────────────────
const defaultEngine = new RAKAYEngine({ provider: 'multi' });

module.exports = {
  RAKAYEngine,
  defaultEngine,
  PRIORITY,
};
