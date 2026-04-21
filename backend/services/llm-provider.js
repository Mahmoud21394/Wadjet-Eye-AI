/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — LLM Provider Abstraction Layer  v3.0
 *
 *  v3.0 — Production-hardened (2026-04-21):
 *   1. MOCK PROVIDER COMPLETELY DISABLED IN PRODUCTION
 *      - No demo mode, no placeholder responses, no silent fallback to mock
 *      - If no real provider keys → hard error with clear instructions
 *   2. Strict API key validation at orchestrator construction time
 *   3. Multi-provider fallback: Gemini → Claude → DeepSeek → OpenAI
 *      (each real provider only — mock is NEVER in the production fallback chain)
 *   4. Circuit breaker: auto-disable a provider after 3 failures for 2 min
 *   5. Exponential backoff + jitter (1s → 2s → 4s) per provider
 *   6. Per-request structured logging: provider, latency, status, tokens
 *   7. Provider-level metrics: latency, success/failure rates, circuit states
 *   8. Debug-mode toggle: RAKAY_DEBUG=1 or window._rakayDebug(true)
 *   9. All provider errors are specific — zero generic "busy" messages
 *  10. Response includes full orchestration metadata for observability
 *
 *  Provider priority (configurable via RAKAY_PROVIDER_ORDER env var):
 *    Primary:   Google Gemini  (GEMINI_API_KEY / RAKAY_GEMINI_KEY)
 *    Secondary: Anthropic Claude (ANTHROPIC_API_KEY / CLAUDE_API_KEY)
 *    Tertiary:  DeepSeek        (DEEPSEEK_API_KEY / RAKAY_DEEPSEEK_KEY)
 *    Fallback:  OpenAI          (OPENAI_API_KEY / RAKAY_OPENAI_KEY)
 *    [REMOVED]: Mock — NEVER used in production
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── Constants ──────────────────────────────────────────────────────────────────
const PROVIDER_TIMEOUT_MS       = 20_000;  // 20s per provider attempt
const MAX_RETRIES_PER_PROVIDER  = 2;       // up to 3 total attempts per provider
const RETRY_DELAY_BASE_MS       = 1_000;   // 1s → 2s → 4s exponential backoff
const CIRCUIT_BREAKER_THRESHOLD = 3;       // consecutive failures before open
const CIRCUIT_BREAKER_RESET_MS  = 120_000; // 2 min cool-down before half-open

// ── Production mode guard ─────────────────────────────────────────────────────
// When RAKAY_ALLOW_MOCK=1 is explicitly set, mock is permitted (dev/test only).
// In all other cases, mock is completely disabled.
const ALLOW_MOCK = process.env.RAKAY_ALLOW_MOCK === '1';

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
    if (Date.now() - c.openedAt > CIRCUIT_BREAKER_RESET_MS) {
      c.state = 'half-open';
      c.failures = 0; // Reset failure count for probe
      console.log(`[Circuit:${providerId}] → HALF-OPEN (probe allowed)`);
      return false;
    }
    return true;
  }
  return false;
}

function _circuitSuccess(providerId) {
  const c = _getCircuit(providerId);
  c.failures  = 0;
  c.state     = 'closed';
  c.openedAt  = null;
}

function _circuitFailure(providerId) {
  const c = _getCircuit(providerId);
  c.failures++;
  if (c.failures >= CIRCUIT_BREAKER_THRESHOLD && c.state !== 'open') {
    c.state    = 'open';
    c.openedAt = Date.now();
    console.warn(`[Circuit:${providerId}] → OPEN after ${c.failures} failures (resets in ${CIRCUIT_BREAKER_RESET_MS / 1000}s)`);
  }
}

function _circuitReset(providerId) {
  _circuitState.set(providerId, { failures: 0, openedAt: null, state: 'closed' });
}

// ── Provider Metrics (per-process, for observability) ─────────────────────────
const _metrics = new Map(); // providerId → { requests, successes, failures, totalLatencyMs, lastError, lastSuccess }

function _recordMetric(providerId, success, latencyMs, error) {
  if (!_metrics.has(providerId)) {
    _metrics.set(providerId, {
      requests: 0, successes: 0, failures: 0,
      totalLatencyMs: 0, lastError: null, lastSuccess: null,
    });
  }
  const m = _metrics.get(providerId);
  m.requests++;
  m.totalLatencyMs += latencyMs;
  if (success) {
    m.successes++;
    m.lastSuccess = new Date().toISOString();
  } else {
    m.failures++;
    m.lastError = { message: error, timestamp: new Date().toISOString() };
  }
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

function resetProviderMetrics() {
  _metrics.clear();
  _circuitState.clear();
  console.log('[LLMProvider] Metrics and circuit states reset');
}

// ── HTTP helper ────────────────────────────────────────────────────────────────
function httpRequest(url, options, body, timeoutMs = PROVIDER_TIMEOUT_MS) {
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
    };

    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: raw });
      });
    });

    // Explicit timeout management
    const timer = setTimeout(() => {
      req.destroy();
      reject(new Error(`Request timeout after ${timeoutMs}ms to ${parsed.hostname}`));
    }, timeoutMs);

    req.on('close', () => clearTimeout(timer));
    req.on('error', (err) => { clearTimeout(timer); reject(err); });

    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function _jitter(baseMs) {
  // ±25% random jitter to avoid thundering herd
  return Math.round(baseMs + (Math.random() - 0.5) * baseMs * 0.5);
}

// ── Retryable request with exponential backoff ────────────────────────────────
async function retryableRequest(fn, providerId, maxRetries = MAX_RETRIES_PER_PROVIDER) {
  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const t0 = Date.now();
    try {
      const result = await fn();
      _recordMetric(providerId, true, Date.now() - t0, null);
      _circuitSuccess(providerId);
      return result;
    } catch (err) {
      lastErr = err;
      const latencyMs = Date.now() - t0;
      const msg = String(err.message || '').toLowerCase();

      // Auth errors: never retry — the key is wrong, retrying won't help
      const isAuthError = msg.includes('401') || msg.includes('403') ||
                          msg.includes('invalid key') || msg.includes('unauthorized') ||
                          msg.includes('api key') || msg.includes('invalid or unauthorized');
      if (isAuthError) {
        _recordMetric(providerId, false, latencyMs, err.message);
        _circuitFailure(providerId);
        throw err;
      }

      // Retryable: rate limit, server errors, timeouts, network issues
      const isRetryable = msg.includes('429') || msg.includes('503') ||
                          msg.includes('timeout') || msg.includes('rate limit') ||
                          msg.includes('overloaded') || msg.includes('econnreset') ||
                          msg.includes('econnrefused') || msg.includes('socket hang') ||
                          msg.includes('502') || msg.includes('504');

      if (!isRetryable) {
        _recordMetric(providerId, false, latencyMs, err.message);
        _circuitFailure(providerId);
        throw err;
      }

      _recordMetric(providerId, false, latencyMs, err.message);

      if (attempt < maxRetries) {
        const delay = _jitter(RETRY_DELAY_BASE_MS * Math.pow(2, attempt));
        console.warn(`[${providerId}] Retryable error (attempt ${attempt + 1}/${maxRetries + 1}), backoff=${delay}ms: ${err.message}`);
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
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.GEMINI_API_KEY
      || process.env.RAKAY_GEMINI_KEY
      || process.env.GOOGLE_API_KEY
      || '';
    this.model   = config.model   || process.env.RAKAY_GEMINI_MODEL || 'gemini-2.0-flash';
    this.baseUrl = config.baseUrl || 'https://generativelanguage.googleapis.com';
  }

  get name() { return 'gemini'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) {
      throw new Error('Gemini API key not configured. Set GEMINI_API_KEY environment variable.');
    }

    const systemParts = [];
    const contents    = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemParts.push({ text: msg.content }); continue;
      }
      if (msg.role === 'tool') {
        contents.push({
          role:  'user',
          parts: [{ functionResponse: { name: msg.name || 'tool', response: { content: msg.content } } }],
        }); continue;
      }
      if (msg.role === 'assistant' && msg.tool_calls?.length) {
        const parts = [];
        if (msg.content) parts.push({ text: msg.content });
        for (const tc of msg.tool_calls) {
          let args = {};
          try { args = typeof tc.function?.arguments === 'string'
            ? JSON.parse(tc.function.arguments) : (tc.function?.arguments || {}); } catch {}
          parts.push({ functionCall: { name: tc.function?.name || tc.name, args } });
        }
        contents.push({ role: 'model', parts }); continue;
      }
      const role = msg.role === 'assistant' ? 'model' : 'user';
      contents.push({ role, parts: [{ text: msg.content || '' }] });
    }

    // Gemini requires non-empty contents
    if (!contents.length) {
      contents.push({ role: 'user', parts: [{ text: 'Hello' }] });
    }

    const payload = {
      contents,
      generationConfig: {
        temperature:     opts.temperature ?? 0.2,
        maxOutputTokens: opts.max_tokens  ?? 4096,
        topP:            0.95,
      },
    };

    if (systemParts.length > 0) {
      payload.systemInstruction = { parts: systemParts };
    }

    if (tools.length > 0) {
      const functionDeclarations = tools.map(t => {
        const fn     = (t.type === 'function' && t.function) ? t.function : t;
        const params = JSON.parse(JSON.stringify(fn.parameters || { type: 'object', properties: {} }));
        _stripAdditionalProperties(params);
        return { name: fn.name, description: fn.description || '', parameters: params };
      });
      payload.tools      = [{ functionDeclarations }];
      payload.toolConfig = { functionCallingConfig: { mode: 'AUTO' } };
    }

    const url = `${this.baseUrl}/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;

    return retryableRequest(async () => {
      console.log(`[LLMProvider:gemini] → POST model=${this.model} msgs=${contents.length} tools=${tools.length}`);
      const { status, body } = await httpRequest(url, {
        headers: { 'Content-Type': 'application/json' },
      }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:gemini] ← status=${status} body_len=${body.length}`);

      if (status === 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { detail = body.slice(0, 300); }
        throw new Error(`Gemini HTTP 400 (bad request): ${detail}`);
      }
      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Gemini API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Gemini rate limit (429): ${detail || 'quota exceeded'}`);
      }
      if (status >= 500) {
        throw new Error(`Gemini server error (${status}): ${body.slice(0, 200)}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = body.slice(0, 400); }
        throw new Error(`Gemini HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`Gemini returned invalid JSON: ${body.slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'gemini');
  }

  _normalise(raw) {
    const candidate = raw.candidates?.[0];
    if (!candidate) {
      const reason = raw.promptFeedback?.blockReason;
      if (reason) throw new Error(`Gemini blocked prompt: ${reason}`);
      throw new Error('Gemini: empty candidates array in response');
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
        totalTokens:      usage.totalTokenCount      || 0,
      },
      model: raw.modelVersion || this.model,
      raw,
    };
  }
}

// ── 2. Anthropic Claude Provider ──────────────────────────────────────────────
class AnthropicProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.CLAUDE_API_KEY
      || process.env.ANTHROPIC_API_KEY
      || process.env.RAKAY_ANTHROPIC_KEY
      || process.env.RAKAY_API_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    this.model   = config.model   || process.env.RAKAY_CLAUDE_MODEL || 'claude-3-5-haiku-20241022';
  }

  get name() { return 'anthropic'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) {
      throw new Error('Anthropic Claude API key not configured. Set CLAUDE_API_KEY or ANTHROPIC_API_KEY environment variable.');
    }

    const system  = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const msgList = messages.filter(m => m.role !== 'system');

    const payload = {
      model:      this.model,
      max_tokens: opts.max_tokens ?? 4096,
      messages:   this._convertMessages(msgList),
      ...(system ? { system } : {}),
    };

    if (tools.length > 0) {
      payload.tools = tools.map(t => {
        const fn = (t.type === 'function' && t.function) ? t.function : t;
        return {
          name:         fn.name,
          description:  fn.description || '',
          input_schema: fn.parameters  || { type: 'object', properties: {} },
        };
      });
    }

    const url     = `${this.baseUrl}/v1/messages`;
    const headers = {
      'Content-Type':      'application/json',
      'x-api-key':         this.apiKey,
      'anthropic-version': '2023-06-01',
    };

    return retryableRequest(async () => {
      console.log(`[LLMProvider:anthropic] → POST model=${this.model} msgs=${messages.length} tools=${tools.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:anthropic] ← status=${status} body_len=${body.length}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Anthropic API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`Anthropic rate limit (429): ${detail || 'quota exceeded'}`);
      }
      if (status === 529) {
        throw new Error('Anthropic overloaded (529) — temporarily unavailable');
      }
      if (status >= 500) {
        throw new Error(`Anthropic server error (${status}): ${body.slice(0, 200)}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = body.slice(0, 400); }
        throw new Error(`Anthropic HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`Anthropic returned invalid JSON: ${body.slice(0, 200)}`);
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
      if (m.tool_calls?.length > 0) {
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
      return { role: m.role, content: m.content || '' };
    });
  }

  _normalise(raw) {
    let content = '';
    const toolCalls = [];

    (raw.content || []).forEach(block => {
      if (block.type === 'text') {
        content += block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({ id: block.id, name: block.name, arguments: block.input || {} });
      }
    });

    return {
      content,
      toolCalls,
      finishReason: raw.stop_reason || 'end_turn',
      usage: {
        promptTokens:     raw.usage?.input_tokens  || 0,
        completionTokens: raw.usage?.output_tokens || 0,
        totalTokens:     (raw.usage?.input_tokens  || 0) + (raw.usage?.output_tokens || 0),
      },
      model: raw.model || this.model,
      raw,
    };
  }
}

// ── 3. DeepSeek Provider ──────────────────────────────────────────────────────
class DeepSeekProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.DEEPSEEK_API_KEY
      || process.env.RAKAY_DEEPSEEK_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.deepseek.com';
    this.model   = config.model   || process.env.RAKAY_DEEPSEEK_MODEL || 'deepseek-chat';
  }

  get name() { return 'deepseek'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) {
      throw new Error('DeepSeek API key not configured. Set DEEPSEEK_API_KEY environment variable.');
    }

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
      console.log(`[LLMProvider:deepseek] → POST model=${this.model} msgs=${messages.length} tools=${tools.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:deepseek] ← status=${status} body_len=${body.length}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`DeepSeek API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`DeepSeek rate limit (429): ${detail || 'quota exceeded'}`);
      }
      if (status >= 500) {
        throw new Error(`DeepSeek server error (${status}): ${body.slice(0, 200)}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = body.slice(0, 400); }
        throw new Error(`DeepSeek HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`DeepSeek returned invalid JSON: ${body.slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'deepseek');
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('DeepSeek: empty choices array in response');

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
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.OPENAI_API_KEY
      || process.env.RAKAY_OPENAI_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.openai.com';
    this.model   = config.model   || process.env.RAKAY_OPENAI_MODEL || 'gpt-4o-mini';
  }

  get name() { return 'openai'; }

  isAvailable() { return !!this.apiKey; }

  async chat(messages, tools = [], opts = {}) {
    if (!this.apiKey) {
      throw new Error('OpenAI API key not configured. Set OPENAI_API_KEY environment variable.');
    }

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
      console.log(`[LLMProvider:openai] → POST model=${this.model} msgs=${messages.length} tools=${tools.length}`);
      const { status, body } = await httpRequest(url, { headers }, payload, PROVIDER_TIMEOUT_MS);
      console.log(`[LLMProvider:openai] ← status=${status} body_len=${body.length}`);

      if (status === 401 || status === 403) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`OpenAI API key invalid or unauthorized (${status}): ${detail}`);
      }
      if (status === 429) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || ''; } catch {}
        throw new Error(`OpenAI rate limit (429): ${detail || 'quota exceeded'}`);
      }
      if (status >= 500) {
        throw new Error(`OpenAI server error (${status}): ${body.slice(0, 200)}`);
      }
      if (status >= 400) {
        let detail = '';
        try { detail = JSON.parse(body)?.error?.message || body.slice(0, 400); } catch { detail = body.slice(0, 400); }
        throw new Error(`OpenAI HTTP ${status}: ${detail}`);
      }

      let parsed;
      try { parsed = JSON.parse(body); } catch {
        throw new Error(`OpenAI returned invalid JSON: ${body.slice(0, 200)}`);
      }

      return this._normalise(parsed);
    }, 'openai');
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('OpenAI: empty choices array in response');

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

// ── 5. Mock Provider — DEV ONLY, not included in production pipeline ──────────
// This provider is ONLY used when RAKAY_ALLOW_MOCK=1 is explicitly set.
// It will NEVER be in the default provider order in production.
class MockProvider {
  constructor(config = {}) {
    this.model = config.model || 'mock-v1';
  }

  get name() { return 'mock'; }

  isAvailable() {
    // In production, mock is NEVER available — explicit opt-in required
    return ALLOW_MOCK;
  }

  async chat(messages, _tools = [], _opts = {}) {
    if (!ALLOW_MOCK) {
      throw new Error('Mock provider is disabled in production. Set RAKAY_ALLOW_MOCK=1 for development only.');
    }

    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const lower   = userMsg.toLowerCase();

    // Mock mode warning — always included so engineers know this is not real
    const warning = '\n\n---\n> ⚠️ **MOCK MODE** — This response is generated by a mock provider (no real AI API keys configured). Set `GEMINI_API_KEY`, `CLAUDE_API_KEY`, `DEEPSEEK_API_KEY`, or `OPENAI_API_KEY` for real intelligence.';

    let content = `**RAKAY Mock Response**\n\nQuery received: "${userMsg.slice(0, 100)}"\n\n**Status:** Mock mode active. This is NOT a real AI response.${warning}`;

    if (lower.includes('sigma') || lower.includes('detection')) {
      content = `**[MOCK] Sigma Detection Rule:**\n\n\`\`\`yaml\ntitle: Mock Sigma Rule — Replace with Real Provider\nstatus: test\ndescription: MOCK ONLY — not a real detection rule\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\cmd.exe'\n  condition: selection\nlevel: medium\n\`\`\`${warning}`;
    } else if (lower.includes('cve-')) {
      const cve = userMsg.match(/CVE-\d{4}-\d+/i)?.[0] || 'CVE-XXXX-XXXXX';
      content = `**[MOCK] CVE Analysis: ${cve}**\n\nThis is a mock response. Configure a real AI provider for actual CVE intelligence.${warning}`;
    }

    return {
      content,
      toolCalls:   [],
      finishReason: 'stop',
      usage: { promptTokens: 50, completionTokens: 100, totalTokens: 150 },
      model: this.model,
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  MULTI-PROVIDER ORCHESTRATOR  v3.0
//  Production-hardened: no mock, strict key validation, full observability
// ══════════════════════════════════════════════════════════════════════════════

class MultiProviderOrchestrator {
  /**
   * @param {object}   config
   * @param {string[]} [config.providerOrder]  — priority list of provider names
   * @param {object}   [config.apiKeys]        — { gemini, anthropic, deepseek, openai }
   * @param {object}   [config.models]         — { gemini, anthropic, deepseek, openai }
   * @param {boolean}  [config.debug]          — verbose logging
   * @param {boolean}  [config.allowMock]      — allow mock fallback (dev only)
   */
  constructor(config = {}) {
    this.debug = config.debug || process.env.RAKAY_DEBUG === '1';

    const keys = config.apiKeys || {};

    // Build provider instances with explicit key injection
    this._providers = {
      gemini:    new GeminiProvider({
        apiKey: keys.gemini    || process.env.GEMINI_API_KEY || process.env.RAKAY_GEMINI_KEY || process.env.GOOGLE_API_KEY,
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
        apiKey: keys.openai    || process.env.OPENAI_API_KEY || process.env.RAKAY_OPENAI_KEY,
        model:  config.models?.openai,
      }),
    };

    // Mock is ONLY added if explicitly opted in (dev/test environments)
    if (ALLOW_MOCK || config.allowMock) {
      this._providers.mock = new MockProvider({});
      console.warn('[MultiProviderOrchestrator] ⚠️  Mock provider ENABLED — only for development!');
    }

    // Provider order — production default excludes mock
    const envOrder = process.env.RAKAY_PROVIDER_ORDER;
    const productionDefault = ['gemini', 'anthropic', 'deepseek', 'openai'];

    if (config.providerOrder) {
      // Honour explicit config, but strip mock unless allowed
      this.providerOrder = ALLOW_MOCK || config.allowMock
        ? config.providerOrder
        : config.providerOrder.filter(p => p !== 'mock');
    } else if (envOrder) {
      const parsed = envOrder.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      this.providerOrder = ALLOW_MOCK ? parsed : parsed.filter(p => p !== 'mock');
    } else {
      // Legacy single-provider env var support
      const single = process.env.RAKAY_PROVIDER?.toLowerCase();
      if (single && single !== 'auto' && single !== 'mock' && productionDefault.includes(single)) {
        this.providerOrder = [single, ...productionDefault.filter(p => p !== single)];
      } else {
        this.providerOrder = productionDefault;
      }
    }

    // If mock is allowed, append it as absolute last resort
    if ((ALLOW_MOCK || config.allowMock) && !this.providerOrder.includes('mock')) {
      this.providerOrder.push('mock');
    }

    // Validate and log available providers
    const realProviders = this.providerOrder.filter(p => p !== 'mock' && this._providers[p]?.isAvailable());
    const allAvailable  = this.providerOrder.filter(p => this._providers[p]?.isAvailable());

    console.log(`[MultiProviderOrchestrator] v3.0 Init`);
    console.log(`[MultiProviderOrchestrator] Order:     [${this.providerOrder.join(', ')}]`);
    console.log(`[MultiProviderOrchestrator] Real keys: [${realProviders.join(', ') || 'NONE'}]`);
    console.log(`[MultiProviderOrchestrator] Available: [${allAvailable.join(', ') || 'NONE'}]`);
    console.log(`[MultiProviderOrchestrator] Mock mode: ${ALLOW_MOCK ? 'ENABLED (dev)' : 'DISABLED (production)'}`);

    if (realProviders.length === 0) {
      const msg = '[MultiProviderOrchestrator] ❌ CRITICAL: No real AI provider API keys configured!\n' +
        '  → Set at least one: GEMINI_API_KEY, CLAUDE_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY\n' +
        '  → All requests will fail until a valid key is provided.';
      console.error(msg);
    }
  }

  get name() { return 'multi'; }

  /**
   * Execute a chat request across all available providers in priority order.
   * - Skips providers with no API key
   * - Skips providers with open circuit breakers
   * - Falls through to next provider on any failure
   * - Throws ALL_PROVIDERS_FAILED if every provider fails
   * - NEVER falls back to mock in production
   */
  async chat(messages, tools = [], opts = {}) {
    const requestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const errors    = [];
    const tried     = [];
    const skipped   = [];
    const t0        = Date.now();

    console.log(`[Orchestrator:${requestId}] START providers=[${this.providerOrder.join('|')}] msgs=${messages.length} tools=${tools.length}`);

    for (const providerId of this.providerOrder) {
      const provider = this._providers[providerId];
      if (!provider) {
        console.warn(`[Orchestrator:${requestId}] Unknown provider "${providerId}" — skipping`);
        skipped.push(`${providerId}(unknown)`);
        continue;
      }

      // Skip providers with no API key
      if (!provider.isAvailable()) {
        if (this.debug) {
          console.log(`[Orchestrator:${requestId}] SKIP ${providerId} — no API key configured`);
        }
        skipped.push(`${providerId}(no_key)`);
        continue;
      }

      // Circuit breaker check
      if (_circuitIsOpen(providerId)) {
        const circuit = _getCircuit(providerId);
        const remainingSec = Math.round((CIRCUIT_BREAKER_RESET_MS - (Date.now() - circuit.openedAt)) / 1000);
        console.warn(`[Orchestrator:${requestId}] SKIP ${providerId} — circuit OPEN (resets in ${remainingSec}s)`);
        errors.push(`${providerId}: circuit_open (retry_in=${remainingSec}s)`);
        skipped.push(`${providerId}(circuit_open)`);
        continue;
      }

      tried.push(providerId);
      const providerT0 = Date.now();

      try {
        console.log(`[Orchestrator:${requestId}] → TRYING ${providerId} (attempt ${tried.length}/${this.providerOrder.length})`);
        const result  = await provider.chat(messages, tools, opts);
        const latency = Date.now() - providerT0;

        console.log(`[Orchestrator:${requestId}] ✅ SUCCESS ${providerId} latency=${latency}ms tokens=${result.usage?.totalTokens || 0} content_len=${result.content?.length || 0}`);

        // Enrich result with orchestration metadata
        result.provider     = providerId;
        result.latency_ms   = latency;
        result.orchestrator = {
          requestId,
          totalLatency: Date.now() - t0,
          tried,
          skipped:  skipped.length > 0 ? skipped : undefined,
          errors:   errors.length  > 0 ? errors  : undefined,
        };

        return result;

      } catch (err) {
        const latency = Date.now() - providerT0;
        const errMsg  = err.message || String(err);
        console.error(`[Orchestrator:${requestId}] ❌ FAIL ${providerId} latency=${latency}ms — ${errMsg}`);
        errors.push(`${providerId}: ${errMsg}`);
        // continue to next provider
      }
    }

    // ── All providers failed ─────────────────────────────────────────────────
    const totalMs   = Date.now() - t0;
    const attempted = tried.length;
    console.error(`[Orchestrator:${requestId}] ALL_PROVIDERS_FAILED after ${totalMs}ms — tried: [${tried.join(', ')}]`);
    console.error(`[Orchestrator:${requestId}] Errors: ${errors.join(' | ')}`);
    console.error(`[Orchestrator:${requestId}] Metrics:`, JSON.stringify(getProviderMetrics()));

    // Build a specific, actionable error message
    const realProviders = this.providerOrder.filter(p => p !== 'mock' && this._providers[p]?.isAvailable());
    let detail;
    if (realProviders.length === 0) {
      detail = [
        'No AI provider API keys are configured on the server.',
        'Configure at least one of:',
        '  • GEMINI_API_KEY    — Google Gemini (recommended, free tier available)',
        '  • CLAUDE_API_KEY    — Anthropic Claude',
        '  • DEEPSEEK_API_KEY  — DeepSeek',
        '  • OPENAI_API_KEY    — OpenAI GPT-4',
      ].join('\n');
    } else if (attempted === 0) {
      detail = `All providers have open circuit breakers. Available providers: [${realProviders.join(', ')}]. Errors: ${errors.join(' | ')}`;
    } else {
      detail = `All ${attempted} provider(s) failed. Errors:\n${errors.map(e => `  • ${e}`).join('\n')}`;
    }

    const err = new Error(detail);
    err.code      = 'ALL_PROVIDERS_FAILED';
    err.tried     = tried;
    err.skipped   = skipped;
    err.errors    = errors;
    err.requestId = requestId;
    err.totalMs   = totalMs;
    throw err;
  }

  /**
   * Live-validate all configured providers with a lightweight ping call.
   * Returns an array of { provider, status, model, latencyMs, error? }
   */
  async validateProviders() {
    const results = [];
    const pingMsg = [{ role: 'user', content: 'Reply with exactly one word: OK' }];

    for (const [id, provider] of Object.entries(this._providers)) {
      if (!provider.isAvailable()) {
        results.push({
          provider: id,
          status:   'no_key',
          model:    provider.model,
          error:    'API key not configured',
          configured: false,
        });
        continue;
      }

      const t0 = Date.now();
      try {
        const resp = await provider.chat(pingMsg, [], { max_tokens: 20 });
        results.push({
          provider:  id,
          status:    'ok',
          model:     resp.model || provider.model,
          latencyMs: Date.now() - t0,
          reply:     (resp.content || '').slice(0, 80),
          configured: true,
        });
      } catch (err) {
        results.push({
          provider:  id,
          status:    'error',
          model:     provider.model,
          latencyMs: Date.now() - t0,
          error:     err.message,
          configured: true,
        });
      }
    }

    return results;
  }

  getCapabilities() {
    const available = this.providerOrder.filter(p => this._providers[p]?.isAvailable());
    const realKeys  = available.filter(p => p !== 'mock');
    return {
      providerOrder:      this.providerOrder,
      availableProviders: available,
      realProviders:      realKeys,
      mockEnabled:        ALLOW_MOCK,
      circuitStates:      Object.fromEntries(
        this.providerOrder.map(p => [p, _getCircuit(p).state])
      ),
      metrics: getProviderMetrics(),
    };
  }

  /**
   * Reset all circuit breakers (e.g. after fixing a provider's API key).
   */
  resetCircuits() {
    for (const id of this.providerOrder) {
      _circuitReset(id);
    }
    console.log('[MultiProviderOrchestrator] All circuit breakers reset');
  }
}

// ── Singleton orchestrator (for legacy compatibility) ─────────────────────────
let _orchestratorSingleton = null;

function getOrchestrator(config = {}) {
  if (!_orchestratorSingleton || config._forceRebuild) {
    _orchestratorSingleton = new MultiProviderOrchestrator(config);
  }
  return _orchestratorSingleton;
}

// ── Legacy factory ────────────────────────────────────────────────────────────
function createLLMProvider(config = {}) {
  const providerName = (config.provider || '').toLowerCase();

  if (providerName && providerName !== 'auto' && providerName !== 'multi') {
    switch (providerName) {
      case 'gemini':    return new GeminiProvider(config);
      case 'openai':    return new OpenAIProvider(config);
      case 'anthropic':
      case 'claude':    return new AnthropicProvider(config);
      case 'deepseek':  return new DeepSeekProvider(config);
      case 'mock':
      case 'local': {
        if (!ALLOW_MOCK) {
          throw new Error('Mock provider is disabled in production. Set RAKAY_ALLOW_MOCK=1 for development.');
        }
        return new MockProvider(config);
      }
      default:
        throw new Error(`Unknown LLM provider: "${providerName}". Valid options: gemini, anthropic, deepseek, openai, auto.`);
    }
  }

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
  resetProviderMetrics,
  ALLOW_MOCK,
};
