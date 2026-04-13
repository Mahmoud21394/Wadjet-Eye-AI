/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Orchestration Engine  v1.0
 *
 *  class RAKAYEngine:
 *   - Receives user messages
 *   - Retrieves and manages conversation context (memory)
 *   - Decides on tool usage via LLM function-calling
 *   - Executes tools and feeds results back to LLM
 *   - Returns final response with full execution trace
 *
 *  Architecture:
 *   RAKAYEngine
 *   ├── LLMProvider  (OpenAI / Anthropic / local)
 *   ├── RakayStore   (session + history persistence)
 *   └── ToolRegistry (sigma, kql, ioc, mitre, cve, actor, nav)
 *
 *  Conversation loop (ReAct-style):
 *   1. Load context window from store
 *   2. Prepend SYSTEM prompt
 *   3. Call LLM → may return tool_calls
 *   4. If tool_calls: execute each tool, append results, loop
 *   5. Final LLM call → text response
 *   6. Persist all new messages to store
 *   7. Return structured response to caller
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { createLLMProvider } = require('./llm-provider');
const store                 = require('./rakay-store');
const { executeTool, TOOL_SCHEMAS } = require('./rakay-tools');

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_TOOL_ITERATIONS  = 5;   // Max agentic loops before forcing response
const CONTEXT_WINDOW_MSGS  = 20;  // Messages to include in context
const MAX_RESPONSE_TOKENS  = 4096;
const DEFAULT_MODEL        = 'gpt-4o';

// ── System prompt template ─────────────────────────────────────────────────────
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

// ══════════════════════════════════════════════════════════════════════════════
//  RAKAYEngine Class
// ══════════════════════════════════════════════════════════════════════════════

class RAKAYEngine {
  /**
   * @param {object} config
   * @param {string} config.provider   — 'openai' | 'anthropic' | 'mock'
   * @param {string} [config.model]    — model name override
   * @param {string} [config.apiKey]   — API key (falls back to env)
   * @param {string} [config.baseUrl]  — base URL for compatible endpoints
   */
  constructor(config = {}) {
    this.providerName = config.provider || _detectProvider();
    this.model        = config.model   || process.env.RAKAY_MODEL   || DEFAULT_MODEL;
    this.apiKey       = config.apiKey  || _getApiKey(this.providerName);
    this.baseUrl      = config.baseUrl || process.env.RAKAY_BASE_URL;

    this._provider = null; // lazy-init
  }

  // ── Lazy provider initialisation ──────────────────────────────────────────
  _getProvider() {
    if (!this._provider) {
      this._provider = createLLMProvider({
        provider: this.providerName,
        model:    this.model,
        apiKey:   this.apiKey,
        baseUrl:  this.baseUrl,
      });
    }
    return this._provider;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MAIN ENTRY POINT: chat(message, options)
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Process a user message and return a complete response.
   * @param {object} opts
   * @param {string}   opts.message      — user message text
   * @param {string}   opts.sessionId    — conversation session ID
   * @param {string}   opts.tenantId
   * @param {string}   opts.userId
   * @param {object}   [opts.context]    — extra context (e.g. current platform page)
   * @param {boolean}  [opts.useTools]   — enable tool calling (default true)
   * @returns {Promise<RAKAYResponse>}
   */
  async chat({ message, sessionId, tenantId, userId, context = {}, useTools = true }) {
    const startTime   = Date.now();
    const toolTrace   = [];  // execution trace of tool calls
    let   totalTokens = 0;

    // ── 1. Validate session ──────────────────────────────────────────────────
    let session = await store.getSession({ sessionId, tenantId });
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    // ── 2. Persist user message ──────────────────────────────────────────────
    await store.appendMessage({
      sessionId,
      role:    'user',
      content: message,
    });

    // Auto-update session title from first message
    if (session.message_count === 0 && session.title === 'New Chat') {
      const title = _generateTitle(message);
      await store.updateSession({ sessionId, tenantId, updates: { title } });
    }

    // ── 3. Load context window ───────────────────────────────────────────────
    const history = await store.getLLMContext({ sessionId, window: CONTEXT_WINDOW_MSGS });

    // ── 4. Build message list for LLM ────────────────────────────────────────
    const systemMsg  = { role: 'system', content: _buildSystemPrompt(context) };
    let   msgHistory = [systemMsg, ...history];

    // ── 5. Agentic tool-calling loop ─────────────────────────────────────────
    const provider = this._getProvider();
    let   iteration = 0;
    let   finalText = '';

    while (iteration < MAX_TOOL_ITERATIONS) {
      iteration++;

      // Call LLM — provider.chat(messages, tools, opts)
      const llmTools    = useTools ? TOOL_SCHEMAS : [];
      const llmResponse = await provider.chat(msgHistory, llmTools, {
        max_tokens: MAX_RESPONSE_TOKENS,
      });

      totalTokens += llmResponse.usage?.total_tokens || llmResponse.usage?.totalTokens || 0;

      // Normalise: provider returns camelCase toolCalls, also handle snake_case tool_calls
      const toolCalls = llmResponse.toolCalls || llmResponse.tool_calls || [];

      // ── Case A: No tool calls — we have the final response ────────────────
      if (!toolCalls.length) {
        finalText = llmResponse.content || '';
        break;
      }

      // ── Case B: LLM requested tool calls ─────────────────────────────────
      const toolCallResults = [];

      for (const tc of toolCalls) {
        // provider normalises: { id, name, arguments }  OR  { id, function: { name, arguments } }
        const toolName   = tc.name || tc.function?.name;
        const rawArgs    = tc.arguments || tc.function?.arguments || {};
        const toolArgs   = typeof rawArgs === 'string' ? _parseToolArgs(rawArgs) : rawArgs;
        const callId     = tc.id || `call_${Date.now()}_${toolName}`;

        console.log(`[RAKAYEngine] Tool call: ${toolName}`, toolArgs);

        // Execute the tool
        const toolResult = await executeTool(toolName, toolArgs, {
          tenantId,
          userId,
          authHeader: context?.authHeader,
        });

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

      // Append assistant turn (with tool calls) to the conversation
      // OpenAI format requires tool_calls in the message for subsequent requests
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

    // ── 6. Persist assistant response ────────────────────────────────────────
    const assistantMsg = await store.appendMessage({
      sessionId,
      role:        'assistant',
      content:     finalText,
      toolCalls:   toolTrace.length ? toolTrace.map(t => ({ tool: t.tool, args: t.args })) : undefined,
      toolResults: toolTrace.length ? toolTrace.map(t => t.result) : undefined,
      tokensUsed:  totalTokens,
      modelId:     this.model,
    });

    // ── 7. Build and return structured response ───────────────────────────────
    return {
      id:           assistantMsg.id,
      session_id:   sessionId,
      content:      finalText,
      role:         'assistant',
      tool_trace:   toolTrace,
      tokens_used:  totalTokens,
      model:        this.model,
      provider:     this.providerName,
      latency_ms:   Date.now() - startTime,
      created_at:   assistantMsg.created_at,
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  SESSION MANAGEMENT
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new session.
   * @param {object} opts
   * @param {string} opts.tenantId
   * @param {string} opts.userId
   * @param {string} [opts.title]
   * @returns {Promise<SessionRecord>}
   */
  async createSession({ tenantId, userId, title }) {
    return store.createSession({ tenantId, userId, title });
  }

  /**
   * List sessions for a user.
   * @param {object} opts
   * @param {string} opts.tenantId
   * @param {string} opts.userId
   * @param {number} [opts.limit]
   * @returns {Promise<SessionRecord[]>}
   */
  async listSessions({ tenantId, userId, limit = 50 }) {
    return store.listSessions({ tenantId, userId, limit });
  }

  /**
   * Get conversation history for a session.
   * @param {object} opts
   * @param {string} opts.sessionId
   * @param {string} opts.tenantId
   * @param {number} [opts.limit]
   * @returns {Promise<MessageRecord[]>}
   */
  async getHistory({ sessionId, tenantId, limit = 50 }) {
    // Verify ownership
    const session = await store.getSession({ sessionId, tenantId });
    if (!session) throw new Error(`Session not found: ${sessionId}`);
    return store.getHistory({ sessionId, limit });
  }

  /**
   * Delete a session and all its messages.
   */
  async deleteSession({ sessionId, tenantId }) {
    return store.deleteSession({ sessionId, tenantId });
  }

  /**
   * Update session title.
   */
  async renameSession({ sessionId, tenantId, title }) {
    return store.updateSession({ sessionId, tenantId, updates: { title } });
  }

  /**
   * Search across all sessions.
   */
  async searchHistory({ tenantId, userId, query, limit = 20 }) {
    return store.searchHistory({ tenantId, userId, query, limit });
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  CAPABILITIES
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Return the list of available tools (for API consumers / UI).
   */
  getCapabilities() {
    return {
      provider:    this.providerName,
      model:       this.model,
      tools:       TOOL_SCHEMAS.map(t => ({
        name:        t.function.name,
        description: t.function.description,
      })),
      context_window: CONTEXT_WINDOW_MSGS,
      max_iterations: MAX_TOOL_ITERATIONS,
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  INTERNAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function _detectProvider() {
  if (process.env.OPENAI_API_KEY  || process.env.RAKAY_OPENAI_KEY)    return 'openai';
  if (process.env.ANTHROPIC_API_KEY || process.env.RAKAY_ANTHROPIC_KEY) return 'anthropic';
  return 'mock'; // fallback
}

function _getApiKey(provider) {
  if (provider === 'openai')    return process.env.RAKAY_OPENAI_KEY    || process.env.OPENAI_API_KEY;
  if (provider === 'anthropic') return process.env.RAKAY_ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY;
  return null;
}

function _buildSystemPrompt(context = {}) {
  let prompt = SYSTEM_PROMPT;

  if (context.currentPage) {
    prompt += `\n\nUser's current platform page: ${context.currentPage}`;
  }
  if (context.userRole) {
    prompt += `\nUser role: ${context.userRole}`;
  }
  if (context.tenantName) {
    prompt += `\nOrganisation: ${context.tenantName}`;
  }

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
  const title  = words.slice(0, 6).join(' ');
  return title.length > 50 ? title.slice(0, 50) + '…' : (title || 'Chat');
}

// ── Singleton engine instance (uses env config) ────────────────────────────────
const defaultEngine = new RAKAYEngine();

module.exports = {
  RAKAYEngine,
  defaultEngine,
};
