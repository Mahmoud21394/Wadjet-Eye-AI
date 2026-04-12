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
const DEFAULT_TIMEOUT_MS   = 60_000;
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
    this.apiKey  = config.apiKey || process.env.OPENAI_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.openai.com';
    this.model   = config.model   || 'gpt-4o';
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
    if (tools.length > 0) {
      payload.tools       = tools.map(t => ({ type: 'function', function: t }));
      payload.tool_choice = 'auto';
    }

    const url     = `${this.baseUrl}/v1/chat/completions`;
    const headers = {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };

    return retryableRequest(async () => {
      const { status, body } = await httpRequest(url, { headers }, payload);

      if (status === 429) throw new Error('OpenAI rate limit — please retry');
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
        throw new Error(`OpenAI HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error('OpenAI returned invalid JSON');
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
    this.apiKey  = config.apiKey || process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    this.model   = config.model   || 'claude-3-5-sonnet-20241022';
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
      payload.tools = tools.map(t => ({
        name:         t.name,
        description:  t.description,
        input_schema: t.parameters,
      }));
    }

    const url = `${this.baseUrl}/v1/messages`;
    const headers = {
      'Content-Type':      'application/json',
      'x-api-key':         this.apiKey,
      'anthropic-version': '2023-06-01',
    };

    return retryableRequest(async () => {
      const { status, body } = await httpRequest(url, { headers }, payload);

      if (status === 429) throw new Error('Claude rate limit — please retry');
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
        throw new Error(`Anthropic HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error('Anthropic returned invalid JSON');
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

    if (lower.includes('sigma') || lower.includes('detection rule')) {
      toolCalls.push({ id: 'mock_tc_1', name: 'generate_sigma_rule', arguments: { description: userMsg } });
    } else if (lower.includes('kql')) {
      toolCalls.push({ id: 'mock_tc_1', name: 'generate_kql_query', arguments: { description: userMsg } });
    } else if (lower.includes('cve-') || lower.includes('enrich')) {
      toolCalls.push({ id: 'mock_tc_1', name: 'enrich_ioc', arguments: { value: userMsg.match(/CVE-[\d-]+|[\d.]+\.[\d.]+\.[\d.]+/)?.[0] || userMsg } });
    } else if (lower.includes('mitre') || lower.includes('t1')) {
      toolCalls.push({ id: 'mock_tc_1', name: 'lookup_mitre_technique', arguments: { technique_id: userMsg.match(/T\d{4}(?:\.\d{3})?/i)?.[0] || 'T1059' } });
    } else {
      content = `I'm RAKAY, your AI security analyst. I can help you with:
- **Sigma rule generation** from behavioral descriptions
- **KQL query generation** for Microsoft Defender / Sentinel
- **IOC enrichment** (IPs, domains, file hashes, CVEs)
- **MITRE ATT&CK** technique analysis and coverage mapping
- **Threat actor profiling** and TTPs
- **Incident response** playbook guidance

What threat or detection challenge can I help you with today?`;
    }

    return {
      content,
      toolCalls,
      finishReason: toolCalls.length > 0 ? 'tool_calls' : 'stop',
      usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
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
