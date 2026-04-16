/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — LLM Provider Abstraction Layer  v3.0
 *
 *  Architecture:
 *   MultiProvider (failover chain)
 *   ├── CircuitBreaker  (per-provider fault isolation)
 *   ├── OpenAIProvider  (gpt-4o — primary)
 *   ├── AnthropicProvider (claude-3-5-haiku — secondary)
 *   ├── DeepSeekProvider  (deepseek-chat — tertiary)
 *   ├── GeminiProvider    (gemini-2.0-flash — quaternary)
 *   └── MockProvider      (local demo — always-on last resort)
 *
 *  Key behaviours:
 *   ✅ Circuit-breaker per provider (CLOSED → OPEN after 5 failures → HALF-OPEN after 60s)
 *   ✅ Exponential backoff + jitter on 429 / 5xx / timeout
 *   ✅ Automatic failover to next live provider
 *   ✅ Streaming chat (SSE) for all real providers
 *   ✅ Graceful degradation: MockProvider when all real providers are OPEN
 *   ✅ Full observability logs
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── Constants ──────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS     = 90_000;
const STREAM_TIMEOUT_MS      = 120_000;
const CB_FAILURE_THRESHOLD   = 5;
const CB_OPEN_DURATION_MS    = 60_000;
const RETRY_BASE_MS          = 800;
const RETRY_MAX_ATTEMPTS     = 3;

// ═══════════════════════════════════════════════════════════════════════════════
//  CIRCUIT BREAKER
// ═══════════════════════════════════════════════════════════════════════════════
class CircuitBreaker {
  constructor(name) {
    this.name     = name;
    this.state    = 'CLOSED';   // CLOSED | OPEN | HALF_OPEN
    this.failures = 0;
    this.openAt   = null;
    this.successCount = 0;      // consecutive successes in HALF_OPEN
  }

  isOpen() {
    if (this.state === 'OPEN') {
      if (Date.now() - this.openAt >= CB_OPEN_DURATION_MS) {
        this.state = 'HALF_OPEN';
        this.failures = 0;
        console.log(`[CB:${this.name}] → HALF_OPEN (probing after ${CB_OPEN_DURATION_MS / 1000}s)`);
      } else {
        return true; // still open
      }
    }
    return false;
  }

  recordSuccess() {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= 1) {
        this.state = 'CLOSED';
        this.successCount = 0;
        console.log(`[CB:${this.name}] → CLOSED (probe succeeded)`);
      }
    }
  }

  recordFailure(reason = '') {
    this.failures++;
    if (this.state === 'HALF_OPEN' || this.failures >= CB_FAILURE_THRESHOLD) {
      this.state  = 'OPEN';
      this.openAt = Date.now();
      console.warn(`[CB:${this.name}] → OPEN after ${this.failures} failure(s). Reason: ${reason}. Retry in ${CB_OPEN_DURATION_MS / 1000}s`);
    } else {
      console.warn(`[CB:${this.name}] failure ${this.failures}/${CB_FAILURE_THRESHOLD} — ${reason}`);
    }
  }

  getStatus() {
    return {
      name: this.name,
      state: this.state,
      failures: this.failures,
      openSince: this.openAt ? new Date(this.openAt).toISOString() : null,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HTTP HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
function httpRequest(url, options, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; req.destroy(); reject(new Error('LLM_TIMEOUT')); }
    }, timeoutMs);

    const parsed  = new URL(url);
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
      res.on('end', () => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve({ status: res.statusCode, headers: res.headers, body: raw });
        }
      });
      res.on('error', (e) => { clearTimeout(timer); if (!settled) { settled = true; reject(e); } });
    });

    req.on('error', (e) => { clearTimeout(timer); if (!settled) { settled = true; reject(e); } });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

/**
 * httpStream — makes an HTTP request and returns a Node.js readable response
 * so callers can consume the SSE/chunked body incrementally.
 */
function httpStream(url, options, body, timeoutMs = STREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; reject(new Error('LLM_STREAM_TIMEOUT')); }
    }, timeoutMs);

    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   options.method || 'POST',
      headers:  options.headers || {},
    };

    const req = lib.request(reqOpts, (res) => {
      clearTimeout(timer);
      if (!settled) { settled = true; resolve({ status: res.statusCode, headers: res.headers, stream: res }); }
    });
    req.on('error', (e) => { clearTimeout(timer); if (!settled) { settled = true; reject(e); } });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ── Exponential backoff + jitter ───────────────────────────────────────────────
function backoffDelay(attempt, baseMs = RETRY_BASE_MS) {
  const exp    = Math.pow(2, attempt) * baseMs;
  const jitter = Math.random() * 0.3 * exp;
  return Math.min(exp + jitter, 30_000);
}

// ── Determine if an error is retryable ────────────────────────────────────────
function isRetryable(err) {
  const msg  = String(err?.message || '').toLowerCase();
  const code = err?.statusCode || err?.status || 0;
  return (
    msg.includes('timeout')        ||
    msg.includes('econnreset')     ||
    msg.includes('enotfound')      ||
    msg.includes('econnrefused')   ||
    msg.includes('429')            ||
    msg.includes('rate limit')     ||
    msg.includes('overloaded')     ||
    code === 429                   ||
    (code >= 500 && code < 600)
  );
}

// ── Determine if error is auth/key related (non-retryable) ───────────────────
function isAuthError(err) {
  const msg  = String(err?.message || '').toLowerCase();
  const code = err?.statusCode || err?.status || 0;
  return (
    code === 401 || code === 403   ||
    msg.includes('invalid api key') ||
    msg.includes('unauthorized')    ||
    msg.includes('api key invalid') ||
    msg.includes('invalid or unauthorized')
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OPENAI PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class OpenAIProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.OPENAI_API_KEY
      || process.env.RAKAY_OPENAI_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.openai.com';
    this.model   = config.model   || process.env.OPENAI_MODEL || 'gpt-4o';
    this.cb      = new CircuitBreaker('openai');
  }

  get name() { return 'openai'; }

  _headers() {
    return {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };
  }

  _payload(messages, tools, opts = {}) {
    const p = {
      model:       this.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens  ?? 4096,
    };
    if (tools && tools.length > 0) {
      p.tools = tools.map(t => {
        if (t.type === 'function' && t.function) return t;
        return { type: 'function', function: t };
      });
      p.tool_choice = 'auto';
    }
    return p;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:openai'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('OpenAI API key not configured');

    const url     = `${this.baseUrl}/v1/chat/completions`;
    const payload = this._payload(messages, tools, opts);

    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        console.log(`[OpenAI] attempt=${attempt + 1} model=${this.model} msgs=${messages.length}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, payload);
        console.log(`[OpenAI] status=${status}`);

        if (status === 429) {
          const delay = backoffDelay(attempt);
          console.warn(`[OpenAI] 429 rate-limit — backoff ${Math.round(delay)}ms`);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure('rate-limit 429');
          throw Object.assign(new Error('OpenAI rate-limited'), { statusCode: 429 });
        }

        if (status === 401 || status === 403) {
          this.cb.recordFailure(`auth error ${status}`);
          let det = '';
          try { det = JSON.parse(body)?.error?.message || ''; } catch {}
          throw Object.assign(new Error(`OpenAI auth error ${status}: ${det}`), { statusCode: status });
        }

        if (status >= 500) {
          const delay = backoffDelay(attempt);
          console.warn(`[OpenAI] ${status} server error — backoff ${Math.round(delay)}ms`);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure(`server error ${status}`);
          throw Object.assign(new Error(`OpenAI server error ${status}`), { statusCode: status });
        }

        if (status >= 400) {
          let det = '';
          try { det = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { det = body.slice(0, 300); }
          this.cb.recordFailure(`client error ${status}`);
          throw Object.assign(new Error(`OpenAI HTTP ${status}: ${det}`), { statusCode: status });
        }

        let parsed;
        try { parsed = JSON.parse(body); } catch {
          throw new Error(`OpenAI invalid JSON response: ${body.slice(0, 100)}`);
        }

        this.cb.recordSuccess();
        return this._normalise(parsed);

      } catch (err) {
        if (err.circuitOpen || isAuthError(err)) throw err;
        if (!isRetryable(err) || attempt >= RETRY_MAX_ATTEMPTS - 1) throw err;
        const delay = backoffDelay(attempt);
        console.warn(`[OpenAI] retry ${attempt + 1} in ${Math.round(delay)}ms — ${err.message}`);
        await _sleep(delay);
      }
    }
    throw new Error('OpenAI: max retries exhausted');
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:openai'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('OpenAI API key not configured');

    const payload = { ...this._payload(messages, tools, opts), stream: true };
    const url     = `${this.baseUrl}/v1/chat/completions`;

    const { status, stream } = await httpStream(url, { headers: this._headers() }, payload);

    if (status === 429) {
      this.cb.recordFailure('rate-limit 429');
      throw Object.assign(new Error('OpenAI rate-limited'), { statusCode: 429 });
    }
    if (status >= 400) {
      this.cb.recordFailure(`error ${status}`);
      throw Object.assign(new Error(`OpenAI stream error ${status}`), { statusCode: status });
    }

    let fullContent = '';
    let toolCalls   = [];
    let usage       = { promptTokens: 0, completionTokens: 0, totalTokens: 0 };

    await _consumeSSE(stream, (line) => {
      if (line === '[DONE]') return;
      try {
        const evt = JSON.parse(line);
        const delta = evt.choices?.[0]?.delta;
        if (!delta) return;
        if (delta.content) {
          fullContent += delta.content;
          if (onChunk) onChunk({ type: 'text', text: delta.content });
        }
        if (delta.tool_calls) {
          // accumulate streaming tool calls
          for (const tc of delta.tool_calls) {
            const idx = tc.index ?? 0;
            if (!toolCalls[idx]) toolCalls[idx] = { id: tc.id || '', name: '', arguments: '' };
            if (tc.function?.name)      toolCalls[idx].name      += tc.function.name;
            if (tc.function?.arguments) toolCalls[idx].arguments += tc.function.arguments;
          }
        }
        if (evt.usage) {
          usage.promptTokens     = evt.usage.prompt_tokens || 0;
          usage.completionTokens = evt.usage.completion_tokens || 0;
          usage.totalTokens      = evt.usage.total_tokens || 0;
        }
      } catch { /* ignore malformed delta */ }
    });

    this.cb.recordSuccess();
    const normTools = toolCalls.filter(Boolean).map(tc => ({
      id:   tc.id,
      name: tc.name,
      arguments: (() => { try { return JSON.parse(tc.arguments || '{}'); } catch { return { _raw: tc.arguments }; } })(),
    }));
    return { content: fullContent, toolCalls: normTools, finishReason: normTools.length ? 'tool_calls' : 'stop', usage, model: this.model };
  }

  _normalise(raw) {
    const choice  = raw.choices?.[0];
    if (!choice) throw new Error('OpenAI: empty choices');
    const msg      = choice.message || {};
    const content  = msg.content || '';
    const toolCalls = (msg.tool_calls || []).map(tc => ({
      id:        tc.id,
      name:      tc.function?.name,
      arguments: (() => { try { return JSON.parse(tc.function?.arguments || '{}'); } catch { return { _raw: tc.function?.arguments }; } })(),
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
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ANTHROPIC CLAUDE PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class AnthropicProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.CLAUDE_API_KEY
      || process.env.ANTHROPIC_API_KEY
      || process.env.RAKAY_ANTHROPIC_KEY
      || process.env.RAKAY_API_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    this.model   = config.model   || process.env.RAKAY_MODEL || 'claude-3-5-haiku-20241022';
    this.cb      = new CircuitBreaker('anthropic');
  }

  get name() { return 'anthropic'; }

  _headers() {
    return {
      'Content-Type':      'application/json',
      'x-api-key':         this.apiKey,
      'anthropic-version': '2023-06-01',
    };
  }

  _buildPayload(messages, tools, opts = {}, stream = false) {
    const system  = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const msgList = this._convertMessages(messages.filter(m => m.role !== 'system'));
    const p = {
      model:      this.model,
      max_tokens: opts.max_tokens ?? 4096,
      messages:   msgList,
      ...(system ? { system } : {}),
      ...(stream ? { stream: true } : {}),
    };
    if (tools && tools.length > 0) {
      p.tools = tools.map(t => {
        const fn = (t.type === 'function' && t.function) ? t.function : t;
        return {
          name:         fn.name         || t.name        || 'unknown',
          description:  fn.description  || t.description || '',
          input_schema: fn.parameters   || t.parameters  || { type: 'object', properties: {} },
        };
      });
    }
    return p;
  }

  _convertMessages(messages) {
    const result = [];
    for (const m of messages) {
      if (m.role === 'tool') {
        result.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: m.tool_call_id, content: String(m.content) }] });
      } else if (m.tool_calls && m.tool_calls.length > 0) {
        const content = [];
        if (m.content) content.push({ type: 'text', text: m.content });
        for (const tc of m.tool_calls) {
          content.push({
            type:  'tool_use',
            id:    tc.id,
            name:  tc.function?.name || tc.name,
            input: (() => { try { return JSON.parse(tc.function?.arguments || '{}'); } catch { return {}; } })(),
          });
        }
        result.push({ role: 'assistant', content });
      } else {
        // Skip empty content messages (Claude rejects them)
        if (m.content != null && m.content !== '') {
          result.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content) });
        }
      }
    }
    // Merge consecutive same-role messages (Claude requires alternating)
    const merged = [];
    for (const m of result) {
      const prev = merged[merged.length - 1];
      if (prev && prev.role === m.role && typeof prev.content === 'string' && typeof m.content === 'string') {
        prev.content += '\n' + m.content;
      } else {
        merged.push({ ...m });
      }
    }
    // Ensure first message is user
    if (merged.length > 0 && merged[0].role !== 'user') {
      merged.unshift({ role: 'user', content: '(continued)' });
    }
    return merged;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:anthropic'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('Anthropic API key not configured');

    const url     = `${this.baseUrl}/v1/messages`;
    const payload = this._buildPayload(messages, tools, opts);

    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        console.log(`[Anthropic] attempt=${attempt + 1} model=${this.model} msgs=${messages.length}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, payload);
        console.log(`[Anthropic] status=${status}`);

        if (status === 529 || status === 429) {
          const delay = backoffDelay(attempt);
          console.warn(`[Anthropic] ${status} overloaded — backoff ${Math.round(delay)}ms`);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure('overloaded');
          throw Object.assign(new Error('Anthropic overloaded/rate-limited'), { statusCode: status });
        }
        if (status === 401 || status === 403) {
          this.cb.recordFailure(`auth error ${status}`);
          let det = ''; try { det = JSON.parse(body)?.error?.message || ''; } catch {}
          throw Object.assign(new Error(`Anthropic auth error ${status}: ${det}`), { statusCode: status });
        }
        if (status >= 500) {
          const delay = backoffDelay(attempt);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure(`server error ${status}`);
          throw Object.assign(new Error(`Anthropic server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { det = body.slice(0, 300); }
          this.cb.recordFailure(`client error ${status}: ${det}`);
          throw Object.assign(new Error(`Anthropic HTTP ${status}: ${det}`), { statusCode: status });
        }

        let parsed; try { parsed = JSON.parse(body); } catch {
          throw new Error(`Anthropic invalid JSON: ${body.slice(0, 100)}`);
        }
        this.cb.recordSuccess();
        return this._normalise(parsed);

      } catch (err) {
        if (err.circuitOpen || isAuthError(err)) throw err;
        if (!isRetryable(err) || attempt >= RETRY_MAX_ATTEMPTS - 1) throw err;
        await _sleep(backoffDelay(attempt));
      }
    }
    throw new Error('Anthropic: max retries exhausted');
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:anthropic'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('Anthropic API key not configured');

    const url     = `${this.baseUrl}/v1/messages`;
    const payload = this._buildPayload(messages, tools, opts, true);

    const { status, stream } = await httpStream(url, { headers: this._headers() }, payload);
    if (status === 529 || status === 429) {
      this.cb.recordFailure('overloaded stream');
      throw Object.assign(new Error('Anthropic overloaded'), { statusCode: status });
    }
    if (status >= 400) {
      this.cb.recordFailure(`stream error ${status}`);
      throw Object.assign(new Error(`Anthropic stream error ${status}`), { statusCode: status });
    }

    let fullContent = '';
    const toolCalls = [];
    let usage = { promptTokens: 0, completionTokens: 0, totalTokens: 0 };

    await _consumeSSE(stream, (line) => {
      try {
        const evt = JSON.parse(line);
        if (evt.type === 'content_block_delta') {
          const text = evt.delta?.text || '';
          if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
        }
        if (evt.type === 'content_block_start' && evt.content_block?.type === 'tool_use') {
          toolCalls.push({ id: evt.content_block.id, name: evt.content_block.name, arguments: {} });
        }
        if (evt.type === 'message_delta') {
          usage.promptTokens     = evt.usage?.input_tokens  || usage.promptTokens;
          usage.completionTokens = evt.usage?.output_tokens || usage.completionTokens;
          usage.totalTokens      = usage.promptTokens + usage.completionTokens;
        }
      } catch { /* ignore */ }
    });

    this.cb.recordSuccess();
    return { content: fullContent, toolCalls, finishReason: toolCalls.length ? 'tool_calls' : 'stop', usage, model: this.model };
  }

  _normalise(raw) {
    let content = '';
    const toolCalls = [];
    for (const block of (raw.content || [])) {
      if (block.type === 'text') content += block.text;
      else if (block.type === 'tool_use') {
        toolCalls.push({ id: block.id, name: block.name, arguments: block.input || {} });
      }
    }
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
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DEEPSEEK PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class DeepSeekProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey
      || process.env.DEEPSEEK_API_KEY
      || process.env.deepseek_API_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.deepseek.com';
    this.model   = config.model   || 'deepseek-chat';
    this.cb      = new CircuitBreaker('deepseek');
  }

  get name() { return 'deepseek'; }

  _headers() {
    return {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:deepseek'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('DeepSeek API key not configured');

    // DeepSeek uses OpenAI-compatible API
    const payload = {
      model:       this.model,
      messages:    messages.filter(m => m.role !== 'tool').map(m => ({
        role:    m.role === 'assistant' && m.tool_calls ? 'assistant' : m.role,
        content: m.content || '',
      })),
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens  ?? 4096,
      // DeepSeek does not support all tool types — disable tools to avoid 400
    };

    const url = `${this.baseUrl}/v1/chat/completions`;

    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        console.log(`[DeepSeek] attempt=${attempt + 1} model=${this.model}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, payload);
        console.log(`[DeepSeek] status=${status}`);

        if (status === 429) {
          const delay = backoffDelay(attempt);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure('rate-limit');
          throw Object.assign(new Error('DeepSeek rate-limited'), { statusCode: 429 });
        }
        if (status === 401 || status === 403) {
          this.cb.recordFailure(`auth ${status}`);
          throw Object.assign(new Error(`DeepSeek auth error ${status}`), { statusCode: status });
        }
        if (status >= 500) {
          const delay = backoffDelay(attempt);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure(`server error ${status}`);
          throw Object.assign(new Error(`DeepSeek server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
          this.cb.recordFailure(`client ${status}`);
          throw Object.assign(new Error(`DeepSeek HTTP ${status}: ${det}`), { statusCode: status });
        }

        let parsed; try { parsed = JSON.parse(body); } catch {
          throw new Error('DeepSeek invalid JSON');
        }
        this.cb.recordSuccess();
        const choice = parsed.choices?.[0];
        return {
          content:      choice?.message?.content || '',
          toolCalls:    [],
          finishReason: choice?.finish_reason || 'stop',
          usage: {
            promptTokens:     parsed.usage?.prompt_tokens     || 0,
            completionTokens: parsed.usage?.completion_tokens || 0,
            totalTokens:      parsed.usage?.total_tokens      || 0,
          },
          model: parsed.model || this.model,
        };
      } catch (err) {
        if (err.circuitOpen || isAuthError(err)) throw err;
        if (!isRetryable(err) || attempt >= RETRY_MAX_ATTEMPTS - 1) throw err;
        await _sleep(backoffDelay(attempt));
      }
    }
    throw new Error('DeepSeek: max retries exhausted');
  }

  async chatStream(messages, tools, opts, onChunk) {
    // DeepSeek streaming: use OpenAI-compatible SSE
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:deepseek'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('DeepSeek API key not configured');

    const payload = {
      model:       this.model,
      messages:    messages.filter(m => m.role !== 'tool').map(m => ({ role: m.role, content: m.content || '' })),
      temperature: opts?.temperature ?? 0.2,
      max_tokens:  opts?.max_tokens  ?? 4096,
      stream:      true,
    };

    const url = `${this.baseUrl}/v1/chat/completions`;
    const { status, stream } = await httpStream(url, { headers: this._headers() }, payload);
    if (status === 429) { this.cb.recordFailure('rate-limit stream'); throw Object.assign(new Error('DeepSeek rate-limited'), { statusCode: 429 }); }
    if (status >= 400) { this.cb.recordFailure(`stream ${status}`); throw Object.assign(new Error(`DeepSeek stream error ${status}`), { statusCode: status }); }

    let fullContent = '';
    await _consumeSSE(stream, (line) => {
      if (line === '[DONE]') return;
      try {
        const evt  = JSON.parse(line);
        const text = evt.choices?.[0]?.delta?.content || '';
        if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
      } catch {}
    });
    this.cb.recordSuccess();
    return { content: fullContent, toolCalls: [], finishReason: 'stop', usage: { totalTokens: 0 }, model: this.model };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GOOGLE GEMINI PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class GeminiProvider {
  constructor(config = {}) {
    this.apiKey  = config.apiKey || process.env.GEMINI_API_KEY || '';
    this.model   = config.model  || process.env.GEMINI_MODEL  || 'gemini-2.0-flash';
    this.baseUrl = 'https://generativelanguage.googleapis.com';
    this.cb      = new CircuitBreaker('gemini');
  }

  get name() { return 'gemini'; }

  _convertToGemini(messages) {
    const contents = [];
    for (const m of messages) {
      if (m.role === 'system') continue; // handled as systemInstruction
      const role = m.role === 'assistant' ? 'model' : 'user';
      const text = m.content || '';
      if (text) contents.push({ role, parts: [{ text }] });
    }
    // Gemini requires alternating user/model; ensure starts with user
    if (contents.length > 0 && contents[0].role === 'model') {
      contents.unshift({ role: 'user', parts: [{ text: '(start)' }] });
    }
    return contents;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:gemini'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('Gemini API key not configured');

    const systemText = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const url = `${this.baseUrl}/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;

    const payload = {
      contents: this._convertToGemini(messages),
      ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
      generationConfig: {
        temperature:     opts.temperature ?? 0.2,
        maxOutputTokens: opts.max_tokens  ?? 4096,
      },
    };

    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        console.log(`[Gemini] attempt=${attempt + 1} model=${this.model}`);
        const { status, body } = await httpRequest(url, { headers: { 'Content-Type': 'application/json' } }, payload);
        console.log(`[Gemini] status=${status}`);

        if (status === 429) {
          const delay = backoffDelay(attempt);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure('rate-limit');
          throw Object.assign(new Error('Gemini rate-limited'), { statusCode: 429 });
        }
        if (status === 401 || status === 403) {
          this.cb.recordFailure(`auth ${status}`);
          throw Object.assign(new Error(`Gemini auth error ${status}`), { statusCode: status });
        }
        if (status >= 500) {
          const delay = backoffDelay(attempt);
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(delay); continue; }
          this.cb.recordFailure(`server ${status}`);
          throw Object.assign(new Error(`Gemini server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
          this.cb.recordFailure(`client ${status}`);
          throw Object.assign(new Error(`Gemini HTTP ${status}: ${det}`), { statusCode: status });
        }

        let parsed; try { parsed = JSON.parse(body); } catch { throw new Error('Gemini invalid JSON'); }
        this.cb.recordSuccess();

        const cand    = parsed.candidates?.[0];
        const text    = cand?.content?.parts?.map(p => p.text || '').join('') || '';
        const tokens  = parsed.usageMetadata || {};
        return {
          content:      text,
          toolCalls:    [],
          finishReason: cand?.finishReason || 'stop',
          usage: {
            promptTokens:     tokens.promptTokenCount     || 0,
            completionTokens: tokens.candidatesTokenCount || 0,
            totalTokens:      tokens.totalTokenCount      || 0,
          },
          model: this.model,
        };
      } catch (err) {
        if (err.circuitOpen || isAuthError(err)) throw err;
        if (!isRetryable(err) || attempt >= RETRY_MAX_ATTEMPTS - 1) throw err;
        await _sleep(backoffDelay(attempt));
      }
    }
    throw new Error('Gemini: max retries exhausted');
  }

  async chatStream(messages, tools, opts, onChunk) {
    // Gemini streaming via SSE
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:gemini'), { circuitOpen: true });
    if (!this.apiKey) throw new Error('Gemini API key not configured');

    const systemText = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const url = `${this.baseUrl}/v1beta/models/${this.model}:streamGenerateContent?key=${this.apiKey}&alt=sse`;

    const payload = {
      contents: this._convertToGemini(messages),
      ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
      generationConfig: { temperature: opts?.temperature ?? 0.2, maxOutputTokens: opts?.max_tokens ?? 4096 },
    };

    const { status, stream } = await httpStream(url, { headers: { 'Content-Type': 'application/json' } }, payload);
    if (status === 429) { this.cb.recordFailure('rate-limit'); throw Object.assign(new Error('Gemini rate-limited'), { statusCode: 429 }); }
    if (status >= 400) { this.cb.recordFailure(`stream ${status}`); throw Object.assign(new Error(`Gemini stream error ${status}`), { statusCode: status }); }

    let fullContent = '';
    await _consumeSSE(stream, (line) => {
      try {
        const evt  = JSON.parse(line);
        const text = evt.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
        if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
      } catch {}
    });
    this.cb.recordSuccess();
    return { content: fullContent, toolCalls: [], finishReason: 'stop', usage: { totalTokens: 0 }, model: this.model };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MOCK PROVIDER (always available — last resort)
// ═══════════════════════════════════════════════════════════════════════════════
class MockProvider {
  constructor() { this.model = 'mock-security-analyst-v1'; }
  get name() { return 'mock'; }

  async chat(messages, tools = [], opts = {}) {
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const lower   = userMsg.toLowerCase();

    // Only trigger tool calls when tools are provided AND keyword matches
    const toolCalls = [];
    if (tools && tools.length > 0) {
      if (lower.match(/cve-[\d-]+/i)) {
        toolCalls.push({ id: 'mock_1', name: 'cve_lookup', arguments: { cve_id: userMsg.match(/CVE-[\d-]+/i)?.[0] || 'CVE-2024-12356' } });
      } else if (lower.includes('sigma')) {
        toolCalls.push({ id: 'mock_1', name: 'sigma_search', arguments: { query: userMsg.slice(0, 100) } });
      } else if (lower.includes('kql') || lower.includes('sentinel') || lower.includes('splunk')) {
        toolCalls.push({ id: 'mock_1', name: 'kql_generate', arguments: { description: userMsg.slice(0, 200), siem: lower.includes('splunk') ? 'splunk' : 'sentinel' } });
      } else if (lower.match(/t\d{4}/i) || lower.includes('mitre')) {
        const id = userMsg.match(/T\d{4}(?:\.\d{3})?/i)?.[0] || 'T1059';
        toolCalls.push({ id: 'mock_1', name: 'mitre_lookup', arguments: { query: id } });
      }
    }

    if (toolCalls.length) {
      return { content: '', toolCalls, finishReason: 'tool_calls', usage: { totalTokens: 50 }, model: this.model };
    }

    const content = _mockResponse(lower, tools);
    return { content, toolCalls: [], finishReason: 'stop', usage: { promptTokens: 80, completionTokens: Math.ceil(content.length / 4), totalTokens: 80 + Math.ceil(content.length / 4) }, model: this.model };
  }

  async chatStream(messages, tools, opts, onChunk) {
    const result = await this.chat(messages, tools, opts);
    // Simulate streaming by chunking the response
    if (result.content && onChunk) {
      const words = result.content.split(' ');
      for (const word of words) {
        onChunk({ type: 'text', text: word + ' ' });
        await _sleep(20);
      }
    }
    return result;
  }
}

function _mockResponse(lower, tools) {
  if (lower.match(/cve-[\d-]+/)) {
    return `**CVE Analysis (Demo Mode)**\n\nI found references to this CVE. In full AI mode, I would:\n- Query the NVD database via the \`cve_lookup\` tool\n- Show CVSS scores, affected versions, patch status\n- Provide remediation guidance\n\n*To enable real CVE lookups, ensure OPENAI_API_KEY or CLAUDE_API_KEY is set on the server.*`;
  }
  if (lower.includes('sigma')) {
    return `**Sigma Detection Rule (Demo Mode)**\n\n\`\`\`yaml\ntitle: Suspicious PowerShell Execution\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - '-enc'\n      - '-encodedcommand'\n      - '-bypass'\n  condition: selection\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001\n\`\`\`\n\n*Demo mode — configure AI provider keys for context-aware rule generation.*`;
  }
  if (lower.includes('mitre') || lower.match(/t\d{4}/i)) {
    return `**MITRE ATT&CK (Demo Mode)**\n\nI can provide detailed technique analysis. In full AI mode I would:\n- Map to specific technique IDs (e.g., T1059.001)\n- Show real-world threat actor usage\n- Provide detection and mitigation strategies\n\n*Configure AI provider for full ATT&CK analysis.*`;
  }
  const toolCount = tools ? tools.length : 0;
  return `I'm **RAKAY**, your AI Security Analyst.\n\n**Current mode:** Demo (AI provider keys not configured or all providers temporarily unavailable)\n\n**Available capabilities:** Sigma rules · KQL/SPL queries · IOC enrichment · MITRE ATT&CK · CVE research · Threat actor profiling\n\n**Tool-calling:** ${toolCount > 0 ? `${toolCount} tools available` : 'Disabled in demo mode'}\n\n⚠️ *To enable full AI capabilities, set \`OPENAI_API_KEY\` or \`CLAUDE_API_KEY\` in your Render environment variables.*`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MULTI-PROVIDER (FAILOVER CHAIN)
// ═══════════════════════════════════════════════════════════════════════════════
class MultiProvider {
  /**
   * @param {Array} providers — ordered list of provider instances
   */
  constructor(providers) {
    this.providers = providers;
    this._mockProvider = providers.find(p => p.name === 'mock') || new MockProvider();
  }

  get name() {
    // Return name of first non-open provider
    const live = this.providers.find(p => !p.cb?.isOpen?.() && p.name !== 'mock');
    return live ? live.name : 'mock';
  }

  getStatus() {
    return this.providers.map(p => ({
      name:   p.name,
      model:  p.model,
      hasKey: !!(p.apiKey),
      cb:     p.cb?.getStatus?.() || { state: 'N/A' },
    }));
  }

  async chat(messages, tools = [], opts = {}) {
    const tried = [];

    for (const provider of this.providers) {
      if (provider.cb?.isOpen?.()) {
        console.log(`[MultiProvider] Skipping ${provider.name} — circuit OPEN`);
        continue;
      }
      if (!provider.apiKey && provider.name !== 'mock') {
        console.log(`[MultiProvider] Skipping ${provider.name} — no API key`);
        continue;
      }

      tried.push(provider.name);
      console.log(`[MultiProvider] Trying ${provider.name} (${provider.model})`);

      try {
        const result = await provider.chat(messages, tools, opts);
        if (tried.length > 1) {
          console.log(`[MultiProvider] FAILOVER SUCCESS: ${tried.slice(0, -1).join('→')} failed → ${provider.name} succeeded`);
        }
        return { ...result, _provider: provider.name };
      } catch (err) {
        if (err.circuitOpen) {
          console.warn(`[MultiProvider] ${provider.name} circuit opened — trying next`);
          continue;
        }
        if (isAuthError(err)) {
          console.warn(`[MultiProvider] ${provider.name} auth error — skipping: ${err.message}`);
          continue;
        }
        if (isRetryable(err)) {
          console.warn(`[MultiProvider] ${provider.name} retryable error — trying next: ${err.message}`);
          continue;
        }
        // Non-retryable, non-auth error (bad request etc.) — log but try next
        console.warn(`[MultiProvider] ${provider.name} failed (${err.message}) — trying next`);
        continue;
      }
    }

    // All real providers failed — use mock as graceful degradation
    console.warn(`[MultiProvider] ALL_PROVIDERS_FAILED tried=[${tried.join(',')}] — using mock fallback`);
    const mockResult = await this._mockProvider.chat(messages, tools, opts);
    return { ...mockResult, _provider: 'mock', _degraded: true };
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    const tried = [];

    for (const provider of this.providers) {
      if (provider.cb?.isOpen?.()) continue;
      if (!provider.apiKey && provider.name !== 'mock') continue;

      tried.push(provider.name);
      console.log(`[MultiProvider:stream] Trying ${provider.name}`);

      try {
        const result = await provider.chatStream(messages, tools, opts, onChunk);
        return { ...result, _provider: provider.name };
      } catch (err) {
        if (err.circuitOpen || isAuthError(err) || isRetryable(err)) {
          console.warn(`[MultiProvider:stream] ${provider.name} failed — trying next: ${err.message}`);
          continue;
        }
        console.warn(`[MultiProvider:stream] ${provider.name} non-retryable — trying next: ${err.message}`);
        continue;
      }
    }

    // All real providers failed for streaming — use mock
    console.warn(`[MultiProvider:stream] All failed, using mock`);
    const mockResult = await this._mockProvider.chatStream(messages, tools, opts, onChunk);
    return { ...mockResult, _provider: 'mock', _degraded: true };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SSE CONSUMER HELPER
// ═══════════════════════════════════════════════════════════════════════════════
function _consumeSSE(stream, onLine) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop(); // last partial line stays in buffer
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('data: ')) {
          const data = trimmed.slice(6).trim();
          if (data) onLine(data);
        }
      }
    });
    stream.on('end', () => {
      // flush remaining
      if (buffer.trim().startsWith('data: ')) onLine(buffer.trim().slice(6).trim());
      resolve();
    });
    stream.on('error', reject);
  });
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ═══════════════════════════════════════════════════════════════════════════════
//  FACTORY
// ═══════════════════════════════════════════════════════════════════════════════
/**
 * createMultiProvider — builds the failover chain from environment variables.
 * Provider order: OpenAI → Claude → DeepSeek → Gemini → Mock
 *
 * @param {object} config  — optional config overrides (e.g., { apiKey, provider })
 * @returns {MultiProvider}
 */
function createMultiProvider(config = {}) {
  const providers = [];

  // Explicit single-provider override (legacy compatibility)
  if (config.provider && config.provider !== 'multi') {
    switch (config.provider.toLowerCase()) {
      case 'openai':
        providers.push(new OpenAIProvider(config));
        break;
      case 'anthropic':
      case 'claude':
        providers.push(new AnthropicProvider(config));
        break;
      case 'deepseek':
        providers.push(new DeepSeekProvider(config));
        break;
      case 'gemini':
        providers.push(new GeminiProvider(config));
        break;
      case 'mock':
      case 'local':
        providers.push(new MockProvider());
        break;
    }
    providers.push(new MockProvider());
    return new MultiProvider(providers);
  }

  // Full failover chain — add all providers that have keys
  providers.push(new OpenAIProvider(config));
  providers.push(new AnthropicProvider(config));
  providers.push(new DeepSeekProvider(config));
  providers.push(new GeminiProvider(config));
  providers.push(new MockProvider());

  return new MultiProvider(providers);
}

// Legacy compatibility — single provider factory
function createLLMProvider(config = {}) {
  return createMultiProvider(config);
}

module.exports = {
  createMultiProvider,
  createLLMProvider,   // legacy alias
  MultiProvider,
  OpenAIProvider,
  AnthropicProvider,
  DeepSeekProvider,
  GeminiProvider,
  MockProvider,
  CircuitBreaker,
  isRetryable,
  isAuthError,
  backoffDelay,
};
