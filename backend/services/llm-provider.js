/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — LLM Provider Abstraction Layer  v1.0
 *  Supports: OpenAI GPT-4o, Anthropic Claude, local/compatible endpoints
 *
 *  Design:
 *   - Single factory function: createLLMProvider(config)
 *   - Uniform interface: provider.chat(messages, tools?, stream?)
 *   - Tool call extraction normalised across providers
 *   - Rate limit + retry logic built-in
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── Constants ──────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS   = 90_000;  // raised: LLM calls can take 60-90s
const MAX_RETRIES          = 2;
const RETRY_DELAY_BASE_MS  = 1_000;

// ── HTTP helper ────────────────────────────────────────────────────────────────
function httpRequest(url, options, body) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   options.method || 'POST',
      headers:  options.headers || {},
      timeout:  options.timeout || DEFAULT_TIMEOUT_MS,
    };

    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => {
        const raw  = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: raw });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('LLM request timeout'));
    });
    req.on('error', reject);

    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function retryableRequest(fn, retries = MAX_RETRIES) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < retries) {
        await new Promise(r => setTimeout(r, RETRY_DELAY_BASE_MS * Math.pow(2, i)));
      }
    }
  }
  throw lastErr;
}

// ── OpenAI provider ────────────────────────────────────────────────────────────
class OpenAIProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.OPENAI_API_KEY
      || process.env.RAKAY_OPENAI_KEY
      || '';
    this.baseUrl  = config.baseUrl || 'https://api.openai.com';
    this.model    = config.model   || 'gpt-4o';
    this.proxyUrl = config.proxyUrl || null; // e.g. '/proxy/openai'
  }

  get name() { return 'openai'; }

  /**
   * Send chat completion request.
   * @param {Array}   messages  — OpenAI message format
   * @param {Array}   [tools]   — OpenAI tool definitions
   * @param {object}  [opts]    — temperature, max_tokens, etc.
   * @returns {Promise<LLMResponse>}
   */
  async chat(messages, tools = [], opts = {}) {
    const payload = {
      model:       this.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens  ?? 4096,
    };
    if (tools && tools.length > 0) {
      // Handle both: raw function defs and already-wrapped { type, function } objects
      payload.tools = tools.map(t => {
        if (t.type === 'function' && t.function) return t; // already wrapped
        return { type: 'function', function: t };
      });
      payload.tool_choice = 'auto';
    }

    const url     = `${this.baseUrl}/v1/chat/completions`;
    const headers = {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };

    return retryableRequest(async () => {
      console.log(`[LLMProvider:openai] Sending request model=${this.model} msgs=${messages.length}`);
      const { status, body } = await httpRequest(url, { headers, timeout: DEFAULT_TIMEOUT_MS }, payload);
      console.log(`[LLMProvider:openai] Response status=${status}`);

      if (status === 429) throw new Error('OpenAI rate limit — please retry');
      if (status === 401) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`OpenAI API key invalid or unauthorized (401): ${detail}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { detail = String(body).slice(0, 300); }
        throw new Error(`OpenAI HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`OpenAI returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    });
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('OpenAI: empty choices array');

    const msg        = choice.message || {};
    const content    = msg.content || '';
    const toolCalls  = (msg.tool_calls || []).map(tc => ({
      id:        tc.id,
      name:      tc.function?.name,
      arguments: (() => {
        try { return JSON.parse(tc.function?.arguments || '{}'); }
        catch { return { _raw: tc.function?.arguments }; }
      })(),
    }));

    return {
      content,
      toolCalls,
      finishReason: choice.finish_reason || 'stop',
      usage: {
        promptTokens:     raw.usage?.prompt_tokens     || 0,
        completionTokens: raw.usage?.completion_tokens || 0,
        totalTokens:      raw.usage?.total_tokens      || 0,
      },
      model: raw.model || this.model,
      raw,
    };
  }
}

// ── Anthropic Claude provider ──────────────────────────────────────────────────
class AnthropicProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.CLAUDE_API_KEY
      || process.env.ANTHROPIC_API_KEY
      || process.env.RAKAY_ANTHROPIC_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    // claude-3-5-haiku is fastest/cheapest; override with RAKAY_MODEL for sonnet
    this.model   = config.model   || process.env.RAKAY_MODEL || 'claude-3-5-haiku-20241022';
  }

  get name() { return 'anthropic'; }

  async chat(messages, tools = [], opts = {}) {
    // Separate system from messages
    const system   = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const msgList  = messages.filter(m => m.role !== 'system');

    // Convert tool_call messages for Anthropic format
    const anthropicMessages = this._convertMessages(msgList);

    const payload = {
      model:      this.model,
      max_tokens: opts.max_tokens ?? 4096,
      messages:   anthropicMessages,
      ...(system ? { system } : {}),
    };

    if (tools.length > 0) {
      // TOOL_SCHEMAS uses OpenAI wrapper {type:'function', function:{name,description,parameters}}
      // Anthropic needs flat {name, description, input_schema}
      payload.tools = tools.map(t => {
        const fn = (t.type === 'function' && t.function) ? t.function : t;
        return {
          name:         fn.name,
          description:  fn.description || '',
          input_schema: fn.parameters || { type: 'object', properties: {} },
        };
      });
    }

    const url = `${this.baseUrl}/v1/messages`;
    const headers = {
      'Content-Type':      'application/json',
      'x-api-key':         this.apiKey,
      'anthropic-version': '2023-06-01',
    };

    return retryableRequest(async () => {
      console.log(`[LLMProvider:anthropic] Sending request model=${this.model} msgs=${messages.length}`);
      const { status, body } = await httpRequest(url, { headers, timeout: DEFAULT_TIMEOUT_MS }, payload);
      console.log(`[LLMProvider:anthropic] Response status=${status}`);

      if (status === 429) throw new Error('Claude rate limit — please retry');
      if (status === 401) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Anthropic API key invalid or unauthorized (401): ${detail}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { detail = String(body).slice(0, 300); }
        throw new Error(`Anthropic HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`Anthropic returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    });
  }

  _convertMessages(messages) {
    return messages.map(m => {
      if (m.role === 'tool') {
        return {
          role:    'user',
          content: [{ type: 'tool_result', tool_use_id: m.tool_call_id, content: m.content }],
        };
      }
      if (m.tool_calls && m.tool_calls.length > 0) {
        const content = [];
        if (m.content) content.push({ type: 'text', text: m.content });
        m.tool_calls.forEach(tc => {
          content.push({
            type:  'tool_use',
            id:    tc.id,
            name:  tc.function?.name || tc.name,
            input: (() => {
              try { return JSON.parse(tc.function?.arguments || '{}'); }
              catch { return {}; }
            })(),
          });
        });
        return { role: 'assistant', content };
      }
      return { role: m.role, content: m.content };
    });
  }

  _normalise(raw) {
    let content   = '';
    const toolCalls = [];

    (raw.content || []).forEach(block => {
      if (block.type === 'text') {
        content += block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id:        block.id,
          name:      block.name,
          arguments: block.input || {},
        });
      }
    });

    return {
      content,
      toolCalls,
      finishReason: raw.stop_reason || 'end_turn',
      usage: {
        promptTokens:     raw.usage?.input_tokens  || 0,
        completionTokens: raw.usage?.output_tokens || 0,
        totalTokens: (raw.usage?.input_tokens || 0) + (raw.usage?.output_tokens || 0),
      },
      model: raw.model || this.model,
      raw,
    };
  }
}

// ── Mock / Local provider (no API key needed, for dev/demo) ───────────────────
class MockProvider {
  constructor(config) {
    this.model = config.model || 'mock-v1';
  }

  get name() { return 'mock'; }

  async chat(messages, tools = [], opts = {}) {
    // Generate a plausible analyst response for demo purposes
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const lower   = userMsg.toLowerCase();

    let content = '';
    const toolCalls = [];

    // Only trigger tool calls when tools are provided AND keyword matches
    if (tools && tools.length > 0) {
      if (lower.includes('sigma') && !lower.includes('kql')) {
        toolCalls.push({ id: 'mock_tc_1', name: 'sigma_search', arguments: { query: userMsg.slice(0, 100) } });
      } else if (lower.includes('kql') || lower.includes('sentinel') || lower.includes('splunk')) {
        toolCalls.push({ id: 'mock_tc_1', name: 'kql_generate', arguments: { description: userMsg.slice(0, 200), siem: lower.includes('splunk') ? 'splunk' : 'sentinel' } });
      } else if (lower.includes('cve-') || lower.includes('enrich') || lower.match(/(?:\d{1,3}\.){3}\d{1,3}/)) {
        const iocMatch = userMsg.match(/CVE-[\d-]+|(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,64}/i);
        toolCalls.push({ id: 'mock_tc_1', name: 'ioc_enrich', arguments: { ioc: iocMatch?.[0] || userMsg.slice(0, 80), ioc_type: 'auto' } });
      } else if ((lower.includes('mitre') || lower.match(/t\d{4}/i)) && !lower.includes('sigma')) {
        const techId = userMsg.match(/T\d{4}(?:\.\d{3})?/i)?.[0] || 'T1059';
        toolCalls.push({ id: 'mock_tc_1', name: 'mitre_lookup', arguments: { query: techId } });
      } else if (lower.includes('apt') || lower.includes('threat actor') || lower.includes('lazarus') || lower.includes('apt29')) {
        const actorMatch = userMsg.match(/APT\s*\d+|Lazarus|Cozy Bear|Fancy Bear|Volt Typhoon|Sandworm/i)?.[0] || 'APT29';
        toolCalls.push({ id: 'mock_tc_1', name: 'threat_actor_profile', arguments: { actor: actorMatch } });
      }
    }

    // If no tool calls triggered, generate a text response
    if (!toolCalls.length) {
      if (lower.includes('sigma')) {
        content = `Here's a Sigma detection rule template:\n\n\`\`\`yaml\ntitle: Detect Suspicious Activity\nstatus: experimental\ndescription: Detects suspicious process execution\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-enc'\n      - '-encodedcommand'\n      - 'bypass'\n  condition: selection\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001\n\`\`\`\n\n*Demo mode — configure OPENAI_API_KEY or ANTHROPIC_API_KEY on the server for AI-generated rules.*`;
      } else if (lower.includes('kql')) {
        content = `Here's a KQL detection query:\n\n\`\`\`kql\nDeviceProcessEvents\n| where Timestamp > ago(1h)\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "-bypass", "hidden")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n| order by Timestamp desc\n\`\`\`\n\n*Demo mode — configure OPENAI_API_KEY for precise, context-aware queries.*`;
      } else if (lower.includes('mitre') || lower.match(/t\d{4}/i)) {
        const techId = userMsg.match(/T\d{4}(?:\.\d{3})?/i)?.[0];
        content = techId
          ? `**MITRE ATT&CK ${techId}** — Looking this up in the knowledge base...\n\nCommon techniques:\n- **T1059.001** PowerShell — adversaries use encoded commands to bypass logging\n- **T1566.001** Spearphishing Attachment — initial access via malicious documents\n- **T1190** Exploit Public-Facing Application — vulnerability exploitation\n\n*Demo mode — configure OPENAI_API_KEY for detailed technique analysis.*`
          : `**MITRE ATT&CK Framework**\n\nI can look up any technique (e.g., T1059.001) and provide:\n- Technique description and examples\n- Detection recommendations\n- Mitigation strategies\n- Real-world usage by threat actors\n\n*Demo mode — configure OPENAI_API_KEY for full analysis.*`;
      } else {
        content = `I'm **RAKAY**, your AI Security Analyst assistant.\n\n**Available capabilities:**\n- 🔍 **Sigma rules** — search and generate YAML detection rules\n- 📊 **KQL/SPL/Lucene** — Microsoft Sentinel, Splunk, Elastic queries\n- 🛡️ **IOC enrichment** — IPs, domains, hashes, CVEs\n- 🗺️ **MITRE ATT&CK** — technique details, tactics, mitigations\n- 👤 **Threat actors** — APT profiles and TTPs\n- 🐛 **CVE lookups** — NVD vulnerability database\n\n**Status:** ${tools && tools.length > 0 ? `Tool-calling enabled (${tools.length} tools available)` : 'Text-only mode'}\n\nWhat security challenge can I help you with today?`;
      }
    }

    return {
      content,
      toolCalls,
      finishReason: toolCalls.length > 0 ? 'tool_calls' : 'stop',
      usage: { promptTokens: 100, completionTokens: Math.ceil(content.length / 4), totalTokens: 150 },
      model: this.model,
    };
  }
}

// ── Factory ────────────────────────────────────────────────────────────────────
/**
 * createLLMProvider — instantiate the correct provider from config.
 *
 * @param {object} config
 * @param {string} config.provider  — 'openai' | 'anthropic' | 'mock'
 * @param {string} config.apiKey
 * @param {string} [config.model]
 * @param {string} [config.baseUrl]
 * @returns {OpenAIProvider|AnthropicProvider|MockProvider}
 */
function createLLMProvider(config = {}) {
  const provider = (config.provider || process.env.RAKAY_LLM_PROVIDER || 'openai').toLowerCase();

  switch (provider) {
    case 'openai':
      return new OpenAIProvider(config);
    case 'anthropic':
    case 'claude':
      return new AnthropicProvider(config);
    case 'mock':
    case 'local':
      return new MockProvider(config);
    default:
      throw new Error(`Unknown LLM provider: "${provider}". Use 'openai', 'anthropic', or 'mock'.`);
  }
}

module.exports = {
  createLLMProvider,
  OpenAIProvider,
  AnthropicProvider,
  MockProvider,
};
