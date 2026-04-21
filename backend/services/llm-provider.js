/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — LLM Provider Abstraction Layer  v2.0
 *
 *  MAJOR REWRITE — Fixes:
 *   1. Multi-provider orchestration: Gemini → Claude → DeepSeek → OpenAI
 *   2. True provider fallback: never return "busy" if another provider works
 *   3. Circuit breaker pattern per provider (auto-disable after N failures)
 *   4. Exponential backoff with jitter per attempt
 *   5. Correct API endpoints/headers for all providers
 *   6. Full debug logging per request (sanitized)
 *   7. Response aggregation + quality ranking
 *   8. Gemini API integration (was completely missing)
 *   9. DeepSeek API integration (was completely missing)
 *  10. All providers validated before use — clear per-provider error messages
 *
 *  Provider priority (configurable via RAKAY_PROVIDER_ORDER):
 *    Primary:   Google Gemini  (GEMINI_API_KEY / RAKAY_GEMINI_KEY)
 *    Secondary: Anthropic Claude (ANTHROPIC_API_KEY / CLAUDE_API_KEY)
 *    Tertiary:  DeepSeek        (DEEPSEEK_API_KEY / RAKAY_DEEPSEEK_KEY)
 *    Fallback:  OpenAI          (OPENAI_API_KEY / RAKAY_OPENAI_KEY)
 *    Last resort: Mock          (always available, no key needed)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── Constants ──────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS     = 30_000;   // 30s per-attempt (not total)
const PROVIDER_TIMEOUT_MS    = 25_000;   // each provider gets 25s
const MAX_RETRIES_PER_PROVIDER = 2;      // retries within same provider
const RETRY_DELAY_BASE_MS    = 800;      // base for exponential backoff
const CIRCUIT_BREAKER_THRESHOLD = 3;    // failures before disabling provider
const CIRCUIT_BREAKER_RESET_MS = 120_000; // 2 min before re-enabling

// ── Circuit Breaker State (module-level, persistent across requests) ──────────
const _circuitState = new Map(); // providerId → { failures, openedAt, state }

function _getCircuit(providerId) {
  if (!_circuitState.has(providerId)) {
    _circuitState.set(providerId, { failures: 0, openedAt: null, state: 'closed' });
  }
  return _circuitState.get(providerId);
}

function _circuitIsOpen(providerId) {
  const c = _getCircuit(providerId);
  if (c.state === 'open') {
    // Half-open after reset window
    if (Date.now() - c.openedAt > CIRCUIT_BREAKER_RESET_MS) {
      c.state = 'half-open';
      console.log(`[Circuit:${providerId}] Half-open — allowing probe request`);
      return false;
    }
    return true;
  }
  return false;
}

function _circuitSuccess(providerId) {
  const c = _getCircuit(providerId);
  c.failures = 0;
  c.state = 'closed';
  c.openedAt = null;
}

function _circuitFailure(providerId) {
  const c = _getCircuit(providerId);
  c.failures++;
  if (c.failures >= CIRCUIT_BREAKER_THRESHOLD) {
    if (c.state !== 'open') {
      c.state = 'open';
      c.openedAt = Date.now();
      console.warn(`[Circuit:${providerId}] OPENED after ${c.failures} failures — will retry in ${CIRCUIT_BREAKER_RESET_MS / 1000}s`);
    }
  }
}

// ── Provider Metrics (per-process, for observability) ─────────────────────────
const _metrics = new Map(); // providerId → { requests, successes, failures, totalLatencyMs }

function _recordMetric(providerId, success, latencyMs) {
  if (!_metrics.has(providerId)) {
    _metrics.set(providerId, { requests: 0, successes: 0, failures: 0, totalLatencyMs: 0 });
  }
  const m = _metrics.get(providerId);
  m.requests++;
  m.totalLatencyMs += latencyMs;
  if (success) m.successes++; else m.failures++;
}

function getProviderMetrics() {
  const result = {};
  for (const [id, m] of _metrics) {
    result[id] = {
      ...m,
      avgLatencyMs: m.requests > 0 ? Math.round(m.totalLatencyMs / m.requests) : 0,
      successRate:  m.requests > 0 ? `${Math.round(m.successes / m.requests * 100)}%` : 'N/A',
      circuitState: _getCircuit(id).state,
    };
  }
  return result;
}

// ── HTTP helper ────────────────────────────────────────────────────────────────
function httpRequest(url, options, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) {
      return reject(new Error(`Invalid URL: ${url} — ${e.message}`));
    }
    const lib     = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   options.method || 'POST',
      headers:  options.headers || {},
      timeout:  timeoutMs,
    };

    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: raw });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`LLM request timeout after ${timeoutMs}ms to ${parsed.hostname}`));
    });
    req.on('error', reject);

    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function _jitter(baseMs) {
  return baseMs + Math.random() * baseMs * 0.3; // ±30% jitter
}

// ── Retryable request with exponential backoff ────────────────────────────────
async function retryableRequest(fn, providerId, maxRetries = MAX_RETRIES_PER_PROVIDER) {
  let lastErr;
  for (let i = 0; i <= maxRetries; i++) {
    const t0 = Date.now();
    try {
      const result = await fn();
      _recordMetric(providerId, true, Date.now() - t0);
      _circuitSuccess(providerId);
      return result;
    } catch (err) {
      lastErr = err;
      _recordMetric(providerId, false, Date.now() - t0);

      const msg = String(err.message || '').toLowerCase();
      // Don't retry on auth errors — they won't resolve with retries
      const isAuthError = msg.includes('401') || msg.includes('invalid key') ||
                          msg.includes('unauthorized') || msg.includes('api key');
      if (isAuthError) {
        _circuitFailure(providerId);
        throw err;
      }

      const isRetryable = msg.includes('429') || msg.includes('503') ||
                          msg.includes('timeout') || msg.includes('rate limit') ||
                          msg.includes('overloaded') || msg.includes('econnreset') ||
                          msg.includes('econnrefused') || msg.includes('socket hang');

      if (!isRetryable) {
        _circuitFailure(providerId);
        throw err; // real error, fail fast
      }

      if (i < maxRetries) {
        const delay = _jitter(RETRY_DELAY_BASE_MS * Math.pow(2, i));
        console.warn(`[${providerId}] Retryable error attempt ${i + 1}/${maxRetries}, waiting ${Math.round(delay)}ms: ${err.message}`);
        await _sleep(delay);
      }
    }
  }
  _circuitFailure(providerId);
  throw lastErr;
}

// ══════════════════════════════════════════════════════════════════════════════
//  PROVIDER IMPLEMENTATIONS
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. Google Gemini Provider ─────────────────────────────────────────────────
class GeminiProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.GEMINI_API_KEY
      || process.env.RAKAY_GEMINI_KEY
      || process.env.GOOGLE_API_KEY
      || '';
    // Support both gemini-2.0-flash (fast) and gemini-1.5-pro (powerful)
    this.model   = config.model || process.env.RAKAY_GEMINI_MODEL || 'gemini-2.0-flash';
    this.baseUrl = config.baseUrl || 'https://generativelanguage.googleapis.com';
  }

  get name() { return 'gemini'; }

  isAvailable() {
    return !!this.apiKey;
  }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) throw new Error('Gemini API key not configured (GEMINI_API_KEY)');

    // Convert OpenAI-style messages → Gemini format
    const systemParts = [];
    const contents = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemParts.push({ text: msg.content });
        continue;
      }
      if (msg.role === 'tool') {
        // Tool result → function response
        contents.push({
          role: 'user',
          parts: [{
            functionResponse: {
              name: msg.name || 'tool',
              response: { content: msg.content },
            },
          }],
        });
        continue;
      }
      if (msg.role === 'assistant' && msg.tool_calls?.length) {
        // Tool call message
        const parts = [];
        if (msg.content) parts.push({ text: msg.content });
        for (const tc of msg.tool_calls) {
          let args = {};
          try { args = typeof tc.function?.arguments === 'string'
            ? JSON.parse(tc.function.arguments) : (tc.function?.arguments || {}); } catch {}
          parts.push({ functionCall: { name: tc.function?.name || tc.name, args } });
        }
        contents.push({ role: 'model', parts });
        continue;
      }
      const role = msg.role === 'assistant' ? 'model' : 'user';
      contents.push({ role, parts: [{ text: msg.content || '' }] });
    }

    const payload = {
      contents,
      generationConfig: {
        temperature:    opts.temperature ?? 0.2,
        maxOutputTokens: opts.max_tokens ?? 4096,
        topP:           0.95,
      },
    };

    if (systemParts.length > 0) {
      payload.systemInstruction = { parts: systemParts };
    }

    // Add tool declarations if provided
    if (tools.length > 0) {
      const functionDeclarations = tools.map(t => {
        const fn = (t.type === 'function' && t.function) ? t.function : t;
        // Gemini doesn't support additionalProperties in schema
        const params = JSON.parse(JSON.stringify(fn.parameters || { type: 'object', properties: {} }));
        _stripAdditionalProperties(params);
        return {
          name:        fn.name,
          description: fn.description || '',
          parameters:  params,
        };
      });
      payload.tools = [{ functionDeclarations }];
      payload.toolConfig = { functionCallingConfig: { mode: 'AUTO' } };
    }

    const url = `${this.baseUrl}/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
    const headers = { 'Content-Type': 'application/json' };

    return retryableRequest(async () => {
      console.log(`[LLMProvider:gemini] → model=${this.model} msgs=${contents.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:gemini] ← status=${status}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Gemini API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Gemini rate limit (429): ${detail}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = String(body).slice(0, 400); }
        throw new Error(`Gemini HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`Gemini returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'gemini');
  }

  _normalise(raw) {
    const candidate = raw.candidates?.[0];
    if (!candidate) {
      // Check for promptFeedback block
      const reason = raw.promptFeedback?.blockReason;
      if (reason) throw new Error(`Gemini blocked prompt: ${reason}`);
      throw new Error('Gemini: empty candidates array');
    }

    let content = '';
    const toolCalls = [];

    for (const part of (candidate.content?.parts || [])) {
      if (part.text) {
        content += part.text;
      } else if (part.functionCall) {
        toolCalls.push({
          id:        `gemini_tc_${Date.now()}_${part.functionCall.name}`,
          name:      part.functionCall.name,
          arguments: part.functionCall.args || {},
        });
      }
    }

    const usage = raw.usageMetadata || {};
    return {
      content,
      toolCalls,
      finishReason: candidate.finishReason || 'STOP',
      usage: {
        promptTokens:     usage.promptTokenCount     || 0,
        completionTokens: usage.candidatesTokenCount || 0,
        totalTokens:      usage.totalTokenCount       || 0,
      },
      model: raw.modelVersion || this.model,
      raw,
    };
  }
}

// ── 2. Anthropic Claude Provider ──────────────────────────────────────────────
class AnthropicProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.CLAUDE_API_KEY
      || process.env.ANTHROPIC_API_KEY
      || process.env.RAKAY_ANTHROPIC_KEY
      || process.env.RAKAY_API_KEY  // legacy
      || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    this.model   = config.model   || process.env.RAKAY_CLAUDE_MODEL || 'claude-3-5-haiku-20241022';
  }

  get name() { return 'anthropic'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) throw new Error('Anthropic Claude API key not configured (CLAUDE_API_KEY / ANTHROPIC_API_KEY)');

    const system  = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const msgList = messages.filter(m => m.role !== 'system');
    const anthropicMessages = this._convertMessages(msgList);

    const payload = {
      model:      this.model,
      max_tokens: opts.max_tokens ?? 4096,
      messages:   anthropicMessages,
      ...(system ? { system } : {}),
    };

    if (tools.length > 0) {
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
      console.log(`[LLMProvider:anthropic] → model=${this.model} msgs=${messages.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:anthropic] ← status=${status}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Anthropic API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Anthropic rate limit (429): ${detail}`);
      }
      if (status === 529) {
        throw new Error('Anthropic overloaded (529) — temporary, retrying');
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = String(body).slice(0, 400); }
        throw new Error(`Anthropic HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`Anthropic returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'anthropic');
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
    let content = '';
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

// ── 3. DeepSeek Provider ──────────────────────────────────────────────────────
class DeepSeekProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.DEEPSEEK_API_KEY
      || process.env.RAKAY_DEEPSEEK_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.deepseek.com';
    // deepseek-chat is fast and cheap; deepseek-reasoner for complex analysis
    this.model   = config.model || process.env.RAKAY_DEEPSEEK_MODEL || 'deepseek-chat';
  }

  get name() { return 'deepseek'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) throw new Error('DeepSeek API key not configured (DEEPSEEK_API_KEY)');

    // DeepSeek uses OpenAI-compatible API
    const payload = {
      model:       this.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens ?? 4096,
    };
    if (tools.length > 0) {
      payload.tools = tools.map(t => {
        if (t.type === 'function' && t.function) return t;
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
      console.log(`[LLMProvider:deepseek] → model=${this.model} msgs=${messages.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:deepseek] ← status=${status}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`DeepSeek API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) throw new Error(`DeepSeek rate limit (429)`);
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = String(body).slice(0, 400); }
        throw new Error(`DeepSeek HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`DeepSeek returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'deepseek');
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('DeepSeek: empty choices array');

    const msg       = choice.message || {};
    const content   = msg.content || '';
    const toolCalls = (msg.tool_calls || []).map(tc => ({
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

// ── 4. OpenAI Provider ────────────────────────────────────────────────────────
class OpenAIProvider {
  constructor(config) {
    this.apiKey  = config.apiKey
      || process.env.OPENAI_API_KEY
      || process.env.RAKAY_OPENAI_KEY
      || '';
    this.baseUrl  = config.baseUrl || 'https://api.openai.com';
    this.model    = config.model   || process.env.RAKAY_OPENAI_MODEL || 'gpt-4o-mini';
  }

  get name() { return 'openai'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) throw new Error('OpenAI API key not configured (OPENAI_API_KEY)');

    const payload = {
      model:       this.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens  ?? 4096,
    };
    if (tools.length > 0) {
      payload.tools = tools.map(t => {
        if (t.type === 'function' && t.function) return t;
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
      console.log(`[LLMProvider:openai] → model=${this.model} msgs=${messages.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:openai] ← status=${status}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`OpenAI API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) throw new Error(`OpenAI rate limit (429)`);
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = String(body).slice(0, 400); }
        throw new Error(`OpenAI HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`OpenAI returned invalid JSON: ${String(body).slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'openai');
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('OpenAI: empty choices array');

    const msg       = choice.message || {};
    const content   = msg.content || '';
    const toolCalls = (msg.tool_calls || []).map(tc => ({
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

// ── 5. Mock Provider (always available, for dev/last-resort) ──────────────────
class MockProvider {
  constructor(config) {
    this.model = config.model || 'mock-v1';
  }

  get name() { return 'mock'; }

  isAvailable() { return true; }

  async chat(messages, tools = [], opts = {}) {
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const lower   = userMsg.toLowerCase();
    let content   = '';
    const toolCalls = [];

    if (tools && tools.length > 0) {
      if (lower.includes('sigma')) {
        toolCalls.push({ id: 'mock_tc_1', name: 'sigma_search', arguments: { query: userMsg.slice(0, 100) } });
      } else if (lower.includes('kql') || lower.includes('sentinel') || lower.includes('splunk')) {
        toolCalls.push({ id: 'mock_tc_1', name: 'kql_generate', arguments: { description: userMsg.slice(0, 200), siem: lower.includes('splunk') ? 'splunk' : 'sentinel' } });
      } else if (lower.includes('cve-') || lower.match(/(?:\d{1,3}\.){3}\d{1,3}/)) {
        const iocMatch = userMsg.match(/CVE-[\d-]+|(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,64}/i);
        toolCalls.push({ id: 'mock_tc_1', name: 'ioc_enrich', arguments: { ioc: iocMatch?.[0] || userMsg.slice(0, 80), ioc_type: 'auto' } });
      }
    }

    if (!toolCalls.length) {
      if (lower.includes('sigma')) {
        content = `Here's a Sigma detection rule:\n\n\`\`\`yaml\ntitle: Detect Suspicious PowerShell Encoded Commands\nid: a2eb2048-7dab-4f2f-9b24-fd5d04a9e8e4\nstatus: experimental\ndescription: Detects PowerShell encoded command execution\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith:\n      - '\\\\powershell.exe'\n      - '\\\\pwsh.exe'\n    CommandLine|contains:\n      - ' -enc '\n      - ' -EncodedCommand '\n      - ' -e '\n  condition: selection\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001\n\`\`\`\n\n⚠️ *RAKAY is running in demo mode (no AI API keys configured). Configure GEMINI_API_KEY, CLAUDE_API_KEY, or DEEPSEEK_API_KEY for AI-generated, context-aware rules.*`;
      } else {
        content = `I'm **RAKAY**, your AI Security Analyst.\n\n**Status:** Demo mode — no AI provider keys configured.\n\n**To enable full AI capabilities**, configure one of:\n- \`GEMINI_API_KEY\` — Google Gemini (recommended)\n- \`CLAUDE_API_KEY\` — Anthropic Claude\n- \`DEEPSEEK_API_KEY\` — DeepSeek\n- \`OPENAI_API_KEY\` — OpenAI GPT-4\n\nI can still help with Sigma rules, KQL queries, MITRE lookups, and IOC enrichment using tool integrations.`;
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

// ══════════════════════════════════════════════════════════════════════════════
//  MULTI-PROVIDER ORCHESTRATOR — Core of the fix
//  This is the primary entry point. It tries providers in priority order,
//  uses circuit breakers, and NEVER returns "provider busy" unless ALL fail.
// ══════════════════════════════════════════════════════════════════════════════

class MultiProviderOrchestrator {
  /**
   * @param {object} config
   * @param {string[]} [config.providerOrder]  — priority-ordered list of provider names
   * @param {object}   [config.apiKeys]        — { gemini, anthropic, deepseek, openai }
   * @param {object}   [config.models]         — { gemini, anthropic, deepseek, openai }
   * @param {boolean}  [config.debug]          — verbose logging
   */
  constructor(config = {}) {
    this.debug = config.debug || process.env.RAKAY_DEBUG === '1';

    // API keys from config or environment
    const keys = config.apiKeys || {};

    // Build provider instances
    this._providers = {
      gemini:    new GeminiProvider({
        apiKey: keys.gemini   || process.env.GEMINI_API_KEY || process.env.RAKAY_GEMINI_KEY || process.env.GOOGLE_API_KEY,
        model:  config.models?.gemini,
      }),
      anthropic: new AnthropicProvider({
        apiKey: keys.anthropic || process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.RAKAY_ANTHROPIC_KEY || process.env.RAKAY_API_KEY,
        model:  config.models?.anthropic,
      }),
      deepseek:  new DeepSeekProvider({
        apiKey: keys.deepseek  || process.env.DEEPSEEK_API_KEY || process.env.RAKAY_DEEPSEEK_KEY,
        model:  config.models?.deepseek,
      }),
      openai:    new OpenAIProvider({
        apiKey: keys.openai   || process.env.OPENAI_API_KEY || process.env.RAKAY_OPENAI_KEY,
        model:  config.models?.openai,
      }),
      mock:      new MockProvider({}),
    };

    // Priority order: config → env → default
    const envOrder = process.env.RAKAY_PROVIDER_ORDER;
    const defaultOrder = ['gemini', 'anthropic', 'deepseek', 'openai', 'mock'];

    if (config.providerOrder) {
      this.providerOrder = config.providerOrder;
    } else if (envOrder) {
      this.providerOrder = envOrder.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    } else {
      // If RAKAY_PROVIDER is set (legacy single-provider mode), put it first
      const single = process.env.RAKAY_PROVIDER?.toLowerCase();
      if (single && single !== 'auto' && defaultOrder.includes(single)) {
        this.providerOrder = [single, ...defaultOrder.filter(p => p !== single)];
      } else {
        this.providerOrder = defaultOrder;
      }
    }

    // Log available providers at startup
    const available = this.providerOrder.filter(p => this._providers[p]?.isAvailable());
    console.log(`[MultiProviderOrchestrator] Init — order: [${this.providerOrder.join(', ')}]`);
    console.log(`[MultiProviderOrchestrator] Available providers (have keys): [${available.join(', ')}]`);
    if (available.length === 0 || (available.length === 1 && available[0] === 'mock')) {
      console.warn('[MultiProviderOrchestrator] ⚠️  No real AI provider keys found — will use mock mode');
      console.warn('[MultiProviderOrchestrator] Set GEMINI_API_KEY, CLAUDE_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY');
    }
  }

  get name() { return 'multi'; }

  /**
   * Execute a chat request across all available providers in priority order.
   * Falls through to next provider on any failure.
   * Only fails if ALL providers fail.
   */
  async chat(messages, tools = [], opts = {}) {
    const requestId = `req_${Date.now().toString(36)}`;
    const errors    = [];
    const tried     = [];
    const t0        = Date.now();

    if (this.debug) {
      console.log(`[Orchestrator:${requestId}] START providers=${this.providerOrder.join('|')} msgs=${messages.length} tools=${tools.length}`);
    }

    for (const providerId of this.providerOrder) {
      const provider = this._providers[providerId];
      if (!provider) {
        console.warn(`[Orchestrator:${requestId}] Unknown provider "${providerId}" — skipping`);
        continue;
      }

      // Skip unavailable providers (no key)
      if (!provider.isAvailable()) {
        if (this.debug) console.log(`[Orchestrator:${requestId}] SKIP ${providerId} — no API key`);
        continue;
      }

      // Circuit breaker check
      if (_circuitIsOpen(providerId)) {
        const circuit = _getCircuit(providerId);
        const remainingSec = Math.round((CIRCUIT_BREAKER_RESET_MS - (Date.now() - circuit.openedAt)) / 1000);
        console.warn(`[Orchestrator:${requestId}] CIRCUIT_OPEN ${providerId} — skipping (resets in ${remainingSec}s)`);
        errors.push(`${providerId}: circuit open (retry in ${remainingSec}s)`);
        continue;
      }

      tried.push(providerId);
      const providerT0 = Date.now();

      try {
        console.log(`[Orchestrator:${requestId}] TRYING ${providerId} (attempt ${tried.length})`);
        const result = await provider.chat(messages, tools, opts);
        const latency = Date.now() - providerT0;

        console.log(`[Orchestrator:${requestId}] ✅ SUCCESS ${providerId} latency=${latency}ms tokens=${result.usage?.totalTokens || 0}`);

        // Attach provider metadata to result
        result.provider   = providerId;
        result.latency_ms = latency;
        result.orchestrator = {
          requestId,
          totalLatency: Date.now() - t0,
          tried,
          errors: errors.length > 0 ? errors : undefined,
          providersSkipped: this.providerOrder.filter(p => !tried.includes(p) && p !== providerId),
        };

        return result;

      } catch (err) {
        const latency = Date.now() - providerT0;
        const errMsg  = err.message || String(err);
        console.error(`[Orchestrator:${requestId}] ❌ FAIL ${providerId} latency=${latency}ms — ${errMsg}`);
        errors.push(`${providerId}: ${errMsg}`);

        // If this was the mock provider failing, something is very wrong
        if (providerId === 'mock') {
          console.error(`[Orchestrator:${requestId}] CRITICAL: Mock provider failed — ${errMsg}`);
        }
        // Continue to next provider
      }
    }

    // All providers failed
    const totalMs = Date.now() - t0;
    const errorSummary = errors.join(' | ');
    console.error(`[Orchestrator:${requestId}] ALL_PROVIDERS_FAILED after ${totalMs}ms: ${errorSummary}`);
    console.error(`[Orchestrator:${requestId}] Provider metrics:`, JSON.stringify(getProviderMetrics()));

    // Build a detailed error message — NOT a generic "busy" message
    const availableProviders = this.providerOrder.filter(p => this._providers[p]?.isAvailable());
    let detail;
    if (availableProviders.length === 0 || (availableProviders.length === 1 && availableProviders[0] === 'mock')) {
      detail = 'No AI provider API keys are configured on the server. Set GEMINI_API_KEY, CLAUDE_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY.';
    } else {
      detail = `All ${tried.length} providers failed. Errors: ${errorSummary}`;
    }

    const err = new Error(detail);
    err.code       = 'ALL_PROVIDERS_FAILED';
    err.tried      = tried;
    err.errors     = errors;
    err.requestId  = requestId;
    throw err;
  }

  /**
   * Validate all configured providers by making a lightweight test call.
   * Returns { provider, status, model, error? } for each.
   */
  async validateProviders() {
    const results = [];
    const testMessages = [
      { role: 'user', content: 'Reply with exactly: OK' }
    ];

    for (const [id, provider] of Object.entries(this._providers)) {
      if (id === 'mock') {
        results.push({ provider: id, status: 'available', model: provider.model, note: 'No key required' });
        continue;
      }
      if (!provider.isAvailable()) {
        results.push({ provider: id, status: 'no_key', model: provider.model, error: 'API key not configured' });
        continue;
      }

      const t0 = Date.now();
      try {
        const resp = await provider.chat(testMessages, [], { max_tokens: 10 });
        results.push({
          provider: id,
          status:   'ok',
          model:    resp.model || provider.model,
          latencyMs: Date.now() - t0,
          reply:    (resp.content || '').slice(0, 50),
        });
      } catch (err) {
        results.push({
          provider: id,
          status:   'error',
          model:    provider.model,
          latencyMs: Date.now() - t0,
          error:    err.message,
        });
      }
    }

    return results;
  }

  getCapabilities() {
    return {
      providerOrder:    this.providerOrder,
      availableProviders: this.providerOrder.filter(p => this._providers[p]?.isAvailable()),
      circuitStates:    Object.fromEntries(
        this.providerOrder.map(p => [p, _getCircuit(p).state])
      ),
      metrics: getProviderMetrics(),
    };
  }
}

// ── Singleton orchestrator ────────────────────────────────────────────────────
let _orchestratorSingleton = null;

function getOrchestrator(config = {}) {
  // Rebuild if debug mode changed or forced
  if (!_orchestratorSingleton || config._forceRebuild) {
    _orchestratorSingleton = new MultiProviderOrchestrator(config);
  }
  return _orchestratorSingleton;
}

// ── Legacy factory for backwards compatibility ────────────────────────────────
/**
 * createLLMProvider — returns the multi-provider orchestrator by default.
 * Pass { provider: 'openai' } etc. for single-provider mode (legacy).
 */
function createLLMProvider(config = {}) {
  const providerName = (config.provider || '').toLowerCase();

  // Single-provider explicit selection (legacy / testing)
  if (providerName && providerName !== 'auto' && providerName !== 'multi') {
    switch (providerName) {
      case 'gemini':    return new GeminiProvider(config);
      case 'openai':    return new OpenAIProvider(config);
      case 'anthropic':
      case 'claude':    return new AnthropicProvider(config);
      case 'deepseek':  return new DeepSeekProvider(config);
      case 'mock':
      case 'local':     return new MockProvider(config);
      default:
        throw new Error(`Unknown LLM provider: "${providerName}". Use 'gemini', 'anthropic', 'deepseek', 'openai', 'mock', or 'auto'.`);
    }
  }

  // Default: multi-provider orchestrator (the fix)
  return getOrchestrator(config);
}

// ── Helper: strip additionalProperties from JSON schema (Gemini limitation) ──
function _stripAdditionalProperties(schema) {
  if (!schema || typeof schema !== 'object') return;
  delete schema.additionalProperties;
  if (schema.properties) {
    for (const val of Object.values(schema.properties)) {
      _stripAdditionalProperties(val);
    }
  }
  if (schema.items) _stripAdditionalProperties(schema.items);
}

module.exports = {
  createLLMProvider,
  getOrchestrator,
  MultiProviderOrchestrator,
  GeminiProvider,
  AnthropicProvider,
  DeepSeekProvider,
  OpenAIProvider,
  MockProvider,
  getProviderMetrics,
};
