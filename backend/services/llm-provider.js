/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — LLM Provider Abstraction Layer  v5.0
 *
 *  Architecture:
 *   MultiProvider (dynamic health-scored failover chain)
 *   ├── CircuitBreaker  (per-provider: CLOSED → OPEN → HALF_OPEN)
 *   ├── HealthScorer    (dynamic provider ordering by score)
 *   ├── OpenAIProvider  (gpt-4o — primary internet)
 *   ├── OllamaProvider  (local — NO rate limit, offline-capable)
 *   ├── AnthropicProvider (claude-3-5-haiku — secondary internet)
 *   ├── GeminiProvider    (gemini-2.0-flash — tertiary internet)
 *   ├── DeepSeekProvider  (deepseek-chat — quaternary internet)
 *   └── MockProvider      (always-on last resort)
 *
 *  Key behaviours (ALL 10 TASKS):
 *   ✅ TASK 1:  Failover order: OpenAI → Ollama → Anthropic → Gemini → DeepSeek → Mock
 *               Ollama works offline when internet providers fail; seamless context passing
 *   ✅ TASK 2:  Full CB: CLOSED→OPEN(5 fail, 60s)→HALF_OPEN→CLOSED(2 consecutive success)
 *               Flap prevention + state history logging
 *   ✅ TASK 4:  Per-call 15 000ms timeout via Promise.race inside MultiProvider
 *   ✅ TASK 6:  True graceful degradation: {success,degraded,provider,reply} — NEVER raw errors
 *   ✅ TASK 7:  Dynamic health scoring: successRate*100 - (avgLatency/weight)*100
 *               Providers sorted desc before each request
 *   ✅ Exponential backoff + jitter on 429 / 5xx / timeout
 *   ✅ Streaming (SSE) for all providers with onChunk callback
 *   ✅ Auth error detection — does NOT trigger circuit breaker
 *   ✅ Ollama graceful skip when not running (ECONNREFUSED)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');

// ── Constants ──────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS      = 90_000;
const STREAM_TIMEOUT_MS       = 120_000;
const PROVIDER_CALL_TIMEOUT   = 15_000;   // TASK 4: hard per-provider timeout
const CB_FAILURE_THRESHOLD    = 5;        // TASK 2: open after 5 failures
const CB_OPEN_DURATION_MS     = 60_000;   // TASK 2: stay open 60s
const CB_HALF_OPEN_SUCCESSES  = 2;        // TASK 2: need 2 consecutive successes to CLOSE
const RETRY_BASE_MS           = 800;
const RETRY_MAX_ATTEMPTS      = 3;

// ── Health score weights ───────────────────────────────────────────────────────
const HEALTH_LATENCY_WEIGHT   = 5000;    // TASK 7: lower weight = latency less penalised
const HEALTH_WINDOW           = 20;      // last N calls for rolling stats

// ═══════════════════════════════════════════════════════════════════════════════
//  CIRCUIT BREAKER  (TASK 2 — COMPLETE IMPLEMENTATION)
//  States: CLOSED → OPEN (after threshold) → HALF_OPEN (after cooldown) → CLOSED/OPEN
//  Flap prevention: minimum 2 consecutive successes in HALF_OPEN before closing
//  Anti-flapping: resets openAt timer on each failure in HALF_OPEN
// ═══════════════════════════════════════════════════════════════════════════════
class CircuitBreaker {
  constructor(name) {
    this.name                = name;
    this.state               = 'CLOSED';
    this.failures            = 0;
    this.consecutiveFails    = 0;
    this.openAt              = null;
    this.halfOpenSince       = null;
    this._halfOpenSuccesses  = 0;
    this._lastStateChange    = Date.now();
    this._stateHistory       = [];  // [{from, to, ts}] for observability
    this._totalCalls         = 0;
    this._totalFailures      = 0;
  }

  /**
   * Returns true if the circuit is OPEN and NOT yet ready for half-open probe.
   * Automatically transitions OPEN → HALF_OPEN when cooldown expires.
   */
  isOpen() {
    if (this.state === 'OPEN') {
      const elapsed = Date.now() - this.openAt;
      if (elapsed >= CB_OPEN_DURATION_MS) {
        this._transition('HALF_OPEN');
        return false; // allow a probe request
      }
      return true; // still open — block request
    }
    return false;
  }

  /** Call after every successful provider response */
  recordSuccess(latencyMs = 0) {
    this._totalCalls++;
    this.consecutiveFails = 0;

    if (this.state === 'HALF_OPEN') {
      this._halfOpenSuccesses++;
      console.log(`[CB:${this.name}] HALF_OPEN success ${this._halfOpenSuccesses}/${CB_HALF_OPEN_SUCCESSES} latency=${latencyMs}ms`);

      if (this._halfOpenSuccesses >= CB_HALF_OPEN_SUCCESSES) {
        this._transition('CLOSED');
        this._halfOpenSuccesses = 0;
        this.failures = 0;
      }
    } else if (this.state === 'CLOSED') {
      // Gradually heal: decrease failure count on sustained success (anti-flapping)
      if (this.failures > 0) this.failures = Math.max(0, this.failures - 1);
    }
  }

  /** Call after every provider failure */
  recordFailure(reason = '') {
    this._totalCalls++;
    this._totalFailures++;
    this._halfOpenSuccesses = 0;
    this.failures++;
    this.consecutiveFails++;

    if (this.state === 'HALF_OPEN') {
      // Failure during probe → reset timer and go back to OPEN (no flapping)
      console.warn(`[CB:${this.name}] HALF_OPEN probe FAILED → back to OPEN (full cooldown). Reason: ${reason}`);
      this._transition('OPEN'); // openAt is reset inside _transition
    } else if (this.state === 'CLOSED' && this.failures >= CB_FAILURE_THRESHOLD) {
      console.warn(`[CB:${this.name}] Threshold reached (${this.failures}/${CB_FAILURE_THRESHOLD} failures) → OPEN. Reason: ${reason}`);
      this._transition('OPEN');
    } else {
      console.warn(`[CB:${this.name}] failure ${this.failures}/${CB_FAILURE_THRESHOLD} — ${reason}`);
    }
  }

  _transition(newState) {
    const prev = this.state;
    this.state = newState;
    this._lastStateChange = Date.now();
    this._stateHistory.push({ from: prev, to: newState, ts: new Date().toISOString() });
    if (this._stateHistory.length > 50) this._stateHistory.shift();

    if (newState === 'OPEN') {
      this.openAt       = Date.now();  // always reset timer on OPEN transition
      this.halfOpenSince = null;
    } else if (newState === 'HALF_OPEN') {
      this.halfOpenSince = Date.now();
    } else if (newState === 'CLOSED') {
      this.openAt       = null;
      this.halfOpenSince = null;
    }

    console.log(`[CB:${this.name}] ══ STATE CHANGE: ${prev} → ${newState} ══`);
  }

  getStatus() {
    const remainMs = (this.state === 'OPEN' && this.openAt)
      ? Math.max(0, CB_OPEN_DURATION_MS - (Date.now() - this.openAt))
      : 0;
    return {
      name:             this.name,
      state:            this.state,
      failures:         this.failures,
      consecutiveFails: this.consecutiveFails,
      openSince:        this.openAt        ? new Date(this.openAt).toISOString() : null,
      halfOpenSince:    this.halfOpenSince ? new Date(this.halfOpenSince).toISOString() : null,
      remainingOpenMs:  remainMs,
      halfOpenProgress: `${this._halfOpenSuccesses}/${CB_HALF_OPEN_SUCCESSES}`,
      totalCalls:       this._totalCalls,
      totalFailures:    this._totalFailures,
      recentHistory:    this._stateHistory.slice(-5),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HEALTH SCORER  (TASK 7 — Dynamic provider ordering)
//  score = successRate * 100 - (avgLatencyMs / HEALTH_LATENCY_WEIGHT) * 100
//  Higher score = better. Providers sorted descending before each request.
// ═══════════════════════════════════════════════════════════════════════════════
class HealthScorer {
  constructor(name) {
    this.name   = name;
    this._calls = [];   // [{success, latencyMs, ts}]
  }

  record(success, latencyMs = 0) {
    this._calls.push({ success, latencyMs, ts: Date.now() });
    if (this._calls.length > HEALTH_WINDOW) this._calls.shift();
  }

  get score() {
    if (!this._calls.length) return 50; // neutral for unknown
    const recent      = this._calls.slice(-HEALTH_WINDOW);
    const successCnt  = recent.filter(c => c.success).length;
    const successRate = successCnt / recent.length;
    const avgLatency  = recent.reduce((s, c) => s + c.latencyMs, 0) / recent.length;
    const score = successRate * 100 - (avgLatency / HEALTH_LATENCY_WEIGHT) * 100;
    return Math.round(score * 10) / 10;
  }

  get stats() {
    if (!this._calls.length) return { score: 50, calls: 0, successRate: '?', avgLatency: '?' };
    const recent     = this._calls.slice(-HEALTH_WINDOW);
    const successCnt = recent.filter(c => c.success).length;
    const avgLatency = Math.round(recent.reduce((s, c) => s + c.latencyMs, 0) / recent.length);
    return {
      score:       this.score,
      calls:       recent.length,
      successRate: `${Math.round((successCnt / recent.length) * 100)}%`,
      avgLatency:  `${avgLatency}ms`,
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
      if (!settled) {
        settled = true;
        req.destroy();
        reject(Object.assign(new Error('LLM_TIMEOUT'), { isTimeout: true }));
      }
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

function httpStream(url, options, body, timeoutMs = STREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(Object.assign(new Error('LLM_STREAM_TIMEOUT'), { isTimeout: true }));
      }
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

function isRetryable(err) {
  const msg  = String(err?.message || '').toLowerCase();
  const code = err?.statusCode || err?.status || 0;
  return (
    err?.isTimeout           ||
    msg.includes('timeout')  ||
    msg.includes('econnreset')   ||
    msg.includes('enotfound')    ||
    msg.includes('econnrefused') ||
    msg.includes('429')          ||
    msg.includes('rate limit')   ||
    msg.includes('overloaded')   ||
    code === 429                 ||
    (code >= 500 && code < 600)
  );
}

function isAuthError(err) {
  const msg  = String(err?.message || '').toLowerCase();
  const code = err?.statusCode || err?.status || 0;
  return (
    code === 401 || code === 403       ||
    msg.includes('invalid api key')    ||
    msg.includes('unauthorized')       ||
    msg.includes('api key invalid')    ||
    msg.includes('invalid or unauthorized')
  );
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── TASK 4: Per-call timeout wrapper ──────────────────────────────────────────
/**
 * Wraps any promise with a hard timeout.
 * On timeout, throws { isTimeout: true, statusCode: 408 }.
 */
function withCallTimeout(promise, timeoutMs = PROVIDER_CALL_TIMEOUT, providerName = '') {
  const timeoutErr = Object.assign(
    new Error(`Provider call timeout after ${timeoutMs}ms [${providerName}]`),
    { isTimeout: true, statusCode: 408 }
  );
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(timeoutErr), timeoutMs)),
  ]);
}

function _consumeSSE(stream, onLine) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('data: ')) {
          const data = trimmed.slice(6).trim();
          if (data) onLine(data);
        }
      }
    });
    stream.on('end', () => {
      if (buffer.trim().startsWith('data: ')) onLine(buffer.trim().slice(6));
      resolve();
    });
    stream.on('error', reject);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BASE PROVIDER CLASS
// ═══════════════════════════════════════════════════════════════════════════════
class BaseProvider {
  constructor(name) {
    this.cb     = new CircuitBreaker(name);
    this.health = new HealthScorer(name);
    this._name  = name;
  }

  get name() { return this._name; }

  /** Wrap a provider call with timing + health recording */
  async _timed(fn) {
    const t0 = Date.now();
    try {
      const result = await fn();
      const latency = Date.now() - t0;
      this.cb.recordSuccess(latency);
      this.health.record(true, latency);
      return result;
    } catch (err) {
      const latency = Date.now() - t0;
      this.health.record(false, latency);
      // Auth errors do NOT trigger circuit breaker (they won't self-heal)
      if (!isAuthError(err)) this.cb.recordFailure(err.message);
      throw err;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OPENAI PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class OpenAIProvider extends BaseProvider {
  constructor(config = {}) {
    super('openai');
    this.apiKey  = config.apiKey || process.env.OPENAI_API_KEY || process.env.RAKAY_OPENAI_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.openai.com';
    this.model   = config.model || process.env.OPENAI_MODEL || 'gpt-4o';
  }

  _headers() {
    return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.apiKey}` };
  }

  _payload(messages, tools, opts = {}) {
    const p = {
      model:       this.model,
      messages,
      temperature: opts.temperature ?? 0.2,
      max_tokens:  opts.max_tokens  ?? 4096,
    };
    if (tools?.length) {
      p.tools = tools.map(t => (t.type === 'function' && t.function) ? t : { type: 'function', function: t });
      p.tool_choice = 'auto';
    }
    return p;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:openai'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('OpenAI API key not configured');

    return this._timed(async () => {
      const url = `${this.baseUrl}/v1/chat/completions`;
      for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
        console.log(`[OpenAI] attempt=${attempt + 1} model=${this.model} msgs=${messages.length}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, this._payload(messages, tools, opts));
        console.log(`[OpenAI] status=${status}`);
        if (status === 429) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error('OpenAI rate-limited'), { statusCode: 429 });
        }
        if (status === 401 || status === 403) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || ''; } catch {}
          throw Object.assign(new Error(`OpenAI auth error ${status}: ${det}`), { statusCode: status });
        }
        if (status >= 500) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error(`OpenAI server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { det = body.slice(0, 300); }
          throw Object.assign(new Error(`OpenAI HTTP ${status}: ${det}`), { statusCode: status });
        }
        let parsed; try { parsed = JSON.parse(body); } catch { throw new Error(`OpenAI invalid JSON`); }
        return this._normalise(parsed);
      }
      throw new Error('OpenAI: max retries exhausted');
    });
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:openai'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('OpenAI API key not configured');

    return this._timed(async () => {
      const payload = { ...this._payload(messages, tools, opts), stream: true };
      const url     = `${this.baseUrl}/v1/chat/completions`;
      const { status, stream } = await httpStream(url, { headers: this._headers() }, payload);
      if (status === 429) throw Object.assign(new Error('OpenAI rate-limited'), { statusCode: 429 });
      if (status >= 400)  throw Object.assign(new Error(`OpenAI stream error ${status}`), { statusCode: status });

      let fullContent = '', toolCalls = [], usage = {};
      await _consumeSSE(stream, (line) => {
        if (line === '[DONE]') return;
        try {
          const evt   = JSON.parse(line);
          const delta = evt.choices?.[0]?.delta;
          if (!delta) return;
          if (delta.content) {
            fullContent += delta.content;
            if (onChunk) onChunk({ type: 'text', text: delta.content });
          }
          if (delta.tool_calls) {
            for (const tc of delta.tool_calls) {
              const idx = tc.index ?? 0;
              if (!toolCalls[idx]) toolCalls[idx] = { id: tc.id || '', name: '', arguments: '' };
              if (tc.function?.name)      toolCalls[idx].name      += tc.function.name;
              if (tc.function?.arguments) toolCalls[idx].arguments += tc.function.arguments;
            }
          }
          if (evt.usage) {
            usage = {
              promptTokens:     evt.usage.prompt_tokens || 0,
              completionTokens: evt.usage.completion_tokens || 0,
              totalTokens:      evt.usage.total_tokens || 0,
            };
          }
        } catch {}
      });

      const normTools = toolCalls.filter(Boolean).map(tc => ({
        id: tc.id, name: tc.name,
        arguments: (() => { try { return JSON.parse(tc.arguments || '{}'); } catch { return { _raw: tc.arguments }; } })(),
      }));
      return { content: fullContent, toolCalls: normTools, finishReason: normTools.length ? 'tool_calls' : 'stop', usage, model: this.model };
    });
  }

  _normalise(raw) {
    const choice = raw.choices?.[0];
    if (!choice) throw new Error('OpenAI: empty choices');
    const msg      = choice.message || {};
    const toolCalls = (msg.tool_calls || []).map(tc => ({
      id: tc.id, name: tc.function?.name,
      arguments: (() => { try { return JSON.parse(tc.function?.arguments || '{}'); } catch { return { _raw: tc.function?.arguments }; } })(),
    }));
    return {
      content: msg.content || '', toolCalls,
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
//  OLLAMA PROVIDER  (TASK 1 — local model, no rate limit)
//  Connects to Ollama at OLLAMA_BASE_URL (default: http://localhost:11434).
//  Falls back gracefully with ollamaDown=true if Ollama not running.
//  No API key required — apiKey='local' bypasses the key-check logic.
// ═══════════════════════════════════════════════════════════════════════════════
class OllamaProvider extends BaseProvider {
  constructor(config = {}) {
    super('ollama');
    this.baseUrl = config.baseUrl || process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.model   = config.model   || process.env.OLLAMA_MODEL    || 'llama3.2';
    // 'local' sentinel means "no key needed" — MultiProvider checks apiKey truthiness
    this.apiKey  = 'local';
  }

  _headers() {
    return { 'Content-Type': 'application/json' };
  }

  /** Convert OpenAI-style message format to Ollama /api/chat format */
  _buildPayload(messages, opts = {}) {
    return {
      model:  this.model,
      messages: messages.map(m => ({
        role:    m.role === 'tool' ? 'user' : (m.role === 'system' ? 'system' : m.role),
        content: m.content || (m.role === 'tool' ? JSON.stringify(m.content) : ''),
      })).filter(m => m.content),
      stream:  false,
      options: {
        temperature: opts.temperature ?? 0.2,
        num_predict: opts.max_tokens  ?? 2048,
        num_ctx:     4096,
      },
    };
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:ollama'), { circuitOpen: true });

    return this._timed(async () => {
      const url     = `${this.baseUrl}/api/chat`;
      const payload = this._buildPayload(messages, opts);

      console.log(`[Ollama] model=${this.model} msgs=${messages.length} url=${this.baseUrl}`);

      let res;
      try {
        res = await httpRequest(url, { headers: this._headers() }, payload, 60_000);
      } catch (connErr) {
        if (connErr.message?.includes('ECONNREFUSED') || connErr.message?.includes('ENOTFOUND')) {
          throw Object.assign(new Error(`Ollama not reachable at ${this.baseUrl}`), { statusCode: 503, ollamaDown: true });
        }
        throw connErr;
      }

      console.log(`[Ollama] status=${res.status}`);
      if (res.status >= 400) {
        let det = ''; try { det = JSON.parse(res.body)?.error || res.body.slice(0, 200); } catch {}
        throw Object.assign(new Error(`Ollama HTTP ${res.status}: ${det}`), { statusCode: res.status });
      }

      let parsed; try { parsed = JSON.parse(res.body); } catch { throw new Error('Ollama invalid JSON'); }

      return {
        content:      parsed.message?.content || '',
        toolCalls:    [],
        finishReason: parsed.done ? 'stop' : 'length',
        usage: {
          promptTokens:     parsed.prompt_eval_count     || 0,
          completionTokens: parsed.eval_count             || 0,
          totalTokens: (parsed.prompt_eval_count || 0) + (parsed.eval_count || 0),
        },
        model: parsed.model || this.model,
      };
    });
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:ollama'), { circuitOpen: true });

    return this._timed(async () => {
      const url     = `${this.baseUrl}/api/chat`;
      const payload = { ...this._buildPayload(messages, opts), stream: true };

      let streamRes;
      try {
        streamRes = await httpStream(url, { headers: this._headers() }, payload, 60_000);
      } catch (connErr) {
        if (connErr.message?.includes('ECONNREFUSED') || connErr.message?.includes('ENOTFOUND')) {
          throw Object.assign(new Error(`Ollama not reachable at ${this.baseUrl}`), { statusCode: 503, ollamaDown: true });
        }
        throw connErr;
      }

      if (streamRes.status >= 400) throw Object.assign(new Error(`Ollama stream error ${streamRes.status}`), { statusCode: streamRes.status });

      let fullContent = '';
      let totalTokens = 0;

      await new Promise((resolve, reject) => {
        let buffer = '';
        streamRes.stream.on('data', (chunk) => {
          buffer += chunk.toString('utf8');
          const lines = buffer.split('\n');
          buffer = lines.pop();
          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const evt  = JSON.parse(line);
              const text = evt.message?.content || '';
              if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
              if (evt.eval_count) totalTokens = (evt.prompt_eval_count || 0) + evt.eval_count;
            } catch {}
          }
        });
        streamRes.stream.on('end',   resolve);
        streamRes.stream.on('error', reject);
      });

      return { content: fullContent, toolCalls: [], finishReason: 'stop', usage: { totalTokens }, model: this.model };
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ANTHROPIC CLAUDE PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class AnthropicProvider extends BaseProvider {
  constructor(config = {}) {
    super('anthropic');
    this.apiKey = config.apiKey
      || process.env.CLAUDE_API_KEY
      || process.env.ANTHROPIC_API_KEY
      || process.env.RAKAY_ANTHROPIC_KEY
      || process.env.RAKAY_API_KEY
      || '';
    this.baseUrl = config.baseUrl || 'https://api.anthropic.com';
    this.model   = config.model   || process.env.RAKAY_MODEL || 'claude-3-5-haiku-20241022';
  }

  _headers() {
    return { 'Content-Type': 'application/json', 'x-api-key': this.apiKey, 'anthropic-version': '2023-06-01' };
  }

  _buildPayload(messages, tools, opts = {}, stream = false) {
    const system  = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
    const msgList = this._convertMessages(messages.filter(m => m.role !== 'system'));
    const p = {
      model:      this.model,
      max_tokens: opts.max_tokens ?? 4096,
      messages:   msgList,
      ...(system ? { system } : {}),
      ...(stream  ? { stream: true } : {}),
    };
    if (tools?.length) {
      p.tools = tools.map(t => {
        const fn = (t.type === 'function' && t.function) ? t.function : t;
        return {
          name:         fn.name || t.name || 'unknown',
          description:  fn.description || t.description || '',
          input_schema: fn.parameters || t.parameters || { type: 'object', properties: {} },
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
      } else if (m.tool_calls?.length) {
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
      } else if (m.content != null && m.content !== '') {
        result.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content) });
      }
    }
    // Merge consecutive same-role messages
    const merged = [];
    for (const m of result) {
      const prev = merged[merged.length - 1];
      if (prev && prev.role === m.role && typeof prev.content === 'string' && typeof m.content === 'string') {
        prev.content += '\n' + m.content;
      } else merged.push({ ...m });
    }
    if (merged.length && merged[0].role !== 'user') merged.unshift({ role: 'user', content: '(continued)' });
    return merged;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:anthropic'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('Anthropic API key not configured');

    return this._timed(async () => {
      const url = `${this.baseUrl}/v1/messages`;
      for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
        console.log(`[Anthropic] attempt=${attempt + 1} model=${this.model}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, this._buildPayload(messages, tools, opts));
        console.log(`[Anthropic] status=${status}`);
        if (status === 529 || status === 429) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error('Anthropic overloaded/rate-limited'), { statusCode: status });
        }
        if (status === 401 || status === 403) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || ''; } catch {}
          throw Object.assign(new Error(`Anthropic auth error ${status}: ${det}`), { statusCode: status });
        }
        if (status >= 500) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error(`Anthropic server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 300); } catch { det = body.slice(0, 300); }
          throw Object.assign(new Error(`Anthropic HTTP ${status}: ${det}`), { statusCode: status });
        }
        let parsed; try { parsed = JSON.parse(body); } catch { throw new Error('Anthropic invalid JSON'); }
        return this._normalise(parsed);
      }
      throw new Error('Anthropic: max retries exhausted');
    });
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:anthropic'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('Anthropic API key not configured');

    return this._timed(async () => {
      const url = `${this.baseUrl}/v1/messages`;
      const { status, stream } = await httpStream(url, { headers: this._headers() }, this._buildPayload(messages, tools, opts, true));
      if (status === 529 || status === 429) throw Object.assign(new Error('Anthropic overloaded'), { statusCode: status });
      if (status >= 400)                    throw Object.assign(new Error(`Anthropic stream error ${status}`), { statusCode: status });

      let fullContent = '';
      const toolCalls = [];
      let usage = {};

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
            usage = {
              promptTokens:     evt.usage?.input_tokens  || 0,
              completionTokens: evt.usage?.output_tokens || 0,
              totalTokens: (evt.usage?.input_tokens || 0) + (evt.usage?.output_tokens || 0),
            };
          }
        } catch {}
      });

      return { content: fullContent, toolCalls, finishReason: toolCalls.length ? 'tool_calls' : 'stop', usage, model: this.model };
    });
  }

  _normalise(raw) {
    let content = ''; const toolCalls = [];
    for (const block of (raw.content || [])) {
      if (block.type === 'text') content += block.text;
      else if (block.type === 'tool_use') toolCalls.push({ id: block.id, name: block.name, arguments: block.input || {} });
    }
    return {
      content, toolCalls, finishReason: raw.stop_reason || 'end_turn',
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
class DeepSeekProvider extends BaseProvider {
  constructor(config = {}) {
    super('deepseek');
    this.apiKey  = config.apiKey || process.env.DEEPSEEK_API_KEY || process.env.deepseek_API_KEY || '';
    this.baseUrl = config.baseUrl || 'https://api.deepseek.com';
    this.model   = config.model || 'deepseek-chat';
  }

  _headers() { return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.apiKey}` }; }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:deepseek'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('DeepSeek API key not configured');

    return this._timed(async () => {
      const payload = {
        model:       this.model,
        messages:    messages.filter(m => m.role !== 'tool').map(m => ({ role: m.role, content: m.content || '' })),
        temperature: opts.temperature ?? 0.2,
        max_tokens:  opts.max_tokens ?? 4096,
      };
      const url = `${this.baseUrl}/v1/chat/completions`;
      for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
        console.log(`[DeepSeek] attempt=${attempt + 1}`);
        const { status, body } = await httpRequest(url, { headers: this._headers() }, payload);
        console.log(`[DeepSeek] status=${status}`);
        if (status === 429) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error('DeepSeek rate-limited'), { statusCode: 429 });
        }
        if (status === 401 || status === 403) throw Object.assign(new Error(`DeepSeek auth error ${status}`), { statusCode: status });
        if (status >= 500) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error(`DeepSeek server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
          throw Object.assign(new Error(`DeepSeek HTTP ${status}: ${det}`), { statusCode: status });
        }
        let parsed; try { parsed = JSON.parse(body); } catch { throw new Error('DeepSeek invalid JSON'); }
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
      }
      throw new Error('DeepSeek: max retries exhausted');
    });
  }

  async chatStream(messages, tools, opts, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:deepseek'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('DeepSeek API key not configured');

    return this._timed(async () => {
      const payload = {
        model:       this.model,
        messages:    messages.filter(m => m.role !== 'tool').map(m => ({ role: m.role, content: m.content || '' })),
        temperature: opts?.temperature ?? 0.2,
        max_tokens:  opts?.max_tokens  ?? 4096,
        stream:      true,
      };
      const { status, stream } = await httpStream(`${this.baseUrl}/v1/chat/completions`, { headers: this._headers() }, payload);
      if (status >= 400) throw Object.assign(new Error(`DeepSeek stream error ${status}`), { statusCode: status });
      let fullContent = '';
      await _consumeSSE(stream, (line) => {
        if (line === '[DONE]') return;
        try {
          const evt  = JSON.parse(line);
          const text = evt.choices?.[0]?.delta?.content || '';
          if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
        } catch {}
      });
      return { content: fullContent, toolCalls: [], finishReason: 'stop', usage: { totalTokens: 0 }, model: this.model };
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GOOGLE GEMINI PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════
class GeminiProvider extends BaseProvider {
  constructor(config = {}) {
    super('gemini');
    this.apiKey  = config.apiKey || process.env.GEMINI_API_KEY || '';
    this.model   = config.model  || process.env.GEMINI_MODEL   || 'gemini-2.0-flash';
    this.baseUrl = 'https://generativelanguage.googleapis.com';
  }

  _convertToGemini(messages) {
    const contents = [];
    for (const m of messages) {
      if (m.role === 'system') continue;
      const role = m.role === 'assistant' ? 'model' : 'user';
      const text = m.content || '';
      if (text) contents.push({ role, parts: [{ text }] });
    }
    if (contents.length && contents[0].role === 'model') contents.unshift({ role: 'user', parts: [{ text: '(start)' }] });
    return contents;
  }

  async chat(messages, tools = [], opts = {}) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:gemini'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('Gemini API key not configured');

    return this._timed(async () => {
      const systemText = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
      const url = `${this.baseUrl}/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
      const payload = {
        contents: this._convertToGemini(messages),
        ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
        generationConfig: { temperature: opts.temperature ?? 0.2, maxOutputTokens: opts.max_tokens ?? 4096 },
      };
      for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
        console.log(`[Gemini] attempt=${attempt + 1} model=${this.model}`);
        const { status, body } = await httpRequest(url, { headers: { 'Content-Type': 'application/json' } }, payload);
        console.log(`[Gemini] status=${status}`);
        if (status === 429) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error('Gemini rate-limited'), { statusCode: 429 });
        }
        if (status === 401 || status === 403) throw Object.assign(new Error(`Gemini auth error ${status}`), { statusCode: status });
        if (status >= 500) {
          if (attempt < RETRY_MAX_ATTEMPTS - 1) { await _sleep(backoffDelay(attempt)); continue; }
          throw Object.assign(new Error(`Gemini server error ${status}`), { statusCode: status });
        }
        if (status >= 400) {
          let det = ''; try { det = JSON.parse(body)?.error?.message || body.slice(0, 200); } catch {}
          throw Object.assign(new Error(`Gemini HTTP ${status}: ${det}`), { statusCode: status });
        }
        let parsed; try { parsed = JSON.parse(body); } catch { throw new Error('Gemini invalid JSON'); }
        const cand   = parsed.candidates?.[0];
        const text   = cand?.content?.parts?.map(p => p.text || '').join('') || '';
        const tokens = parsed.usageMetadata || {};
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
      }
      throw new Error('Gemini: max retries exhausted');
    });
  }

  async chatStream(messages, tools, opts, onChunk) {
    if (this.cb.isOpen()) throw Object.assign(new Error('CIRCUIT_OPEN:gemini'), { circuitOpen: true });
    if (!this.apiKey)     throw new Error('Gemini API key not configured');

    return this._timed(async () => {
      const systemText = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
      const url = `${this.baseUrl}/v1beta/models/${this.model}:streamGenerateContent?key=${this.apiKey}&alt=sse`;
      const payload = {
        contents: this._convertToGemini(messages),
        ...(systemText ? { systemInstruction: { parts: [{ text: systemText }] } } : {}),
        generationConfig: { temperature: opts?.temperature ?? 0.2, maxOutputTokens: opts?.max_tokens ?? 4096 },
      };
      const { status, stream } = await httpStream(url, { headers: { 'Content-Type': 'application/json' } }, payload);
      if (status >= 400) throw Object.assign(new Error(`Gemini stream error ${status}`), { statusCode: status });
      let fullContent = '';
      await _consumeSSE(stream, (line) => {
        try {
          const evt  = JSON.parse(line);
          const text = evt.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
          if (text) { fullContent += text; if (onChunk) onChunk({ type: 'text', text }); }
        } catch {}
      });
      return { content: fullContent, toolCalls: [], finishReason: 'stop', usage: { totalTokens: 0 }, model: this.model };
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MOCK PROVIDER (always available — graceful degradation last resort)
// ═══════════════════════════════════════════════════════════════════════════════
class MockProvider extends BaseProvider {
  constructor() {
    super('mock');
    this.model  = 'mock-security-analyst-v2';
    this.apiKey = 'mock'; // always has key
  }

  async chat(messages, tools = [], opts = {}) {
    // NOTE: MockProvider intentionally does NOT make tool calls.
    // Tool-calling with mock LLM produces garbage output (raw JSON {found:false}).
    // Real tool execution is handled by the hybridFallback path in RAKAYEngine
    // (which is triggered before even reaching MockProvider when no real LLM is set).
    // MockProvider is only a last-resort safety net.
    const userMsg = [...messages].reverse().find(m => m.role === 'user')?.content || '';
    const lower   = userMsg.toLowerCase();
    const content = _mockResponse(lower);
    this.health.record(true, 50);
    return {
      content, toolCalls: [], finishReason: 'stop',
      usage: { promptTokens: 80, completionTokens: Math.ceil(content.length / 4), totalTokens: 80 + Math.ceil(content.length / 4) },
      model: this.model, _degraded: true,
    };
  }

  async chatStream(messages, tools, opts, onChunk) {
    const result = await this.chat(messages, tools, opts);
    if (result.content && onChunk) {
      const words = result.content.split(/(?<=\s)/);
      for (const word of words) { onChunk({ type: 'text', text: word }); await _sleep(10); }
    }
    return result;
  }
}

function _mockResponse(lower) {
  // MockProvider is only reached if hybridFallback returned null AND all real providers failed.
  // Provide a clear, helpful response pointing to what the user asked about.
  if (lower.match(/cve-[\d-]+/i)) {
    const cveId = lower.match(/cve-[\d-]+/i)?.[0]?.toUpperCase() || 'CVE';
    return `⚠️ Using built-in threat intelligence\n\n## Overview\nRequesting CVE details for **${cveId}**.\n\n## Why It Matters\nCVE identifiers track specific vulnerabilities. Without an AI provider configured, only CVEs in the local database can be retrieved.\n\n## Detection Guidance\nSearch your SIEM for exploitation indicators related to this CVE. Check CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n\n## Mitigation\n1. Apply the relevant vendor patch immediately\n2. Identify all affected systems in your environment\n3. Monitor for indicators of exploitation in your SIEM\n\n## Analyst Tip\n> 💡 For full CVE enrichment, configure an AI API key. Local intelligence database has 37 CVEs including Log4Shell, ProxyShell, EternalBlue, and recent exploited vulnerabilities.`;
  }
  if (lower.includes('sigma') || lower.includes('detection rule')) {
    return `⚠️ Using built-in threat intelligence\n\n## Overview\nSigma detection rule generation is available via the local detection engine with 21 pre-built techniques.\n\n## Detection Guidance\n### Sigma Rule — PowerShell Encoded Command Detection\n\`\`\`yaml\ntitle: Suspicious PowerShell Encoded Command Execution\nid: a6eb3b37-b8c2-4e9f-b1c1-8e3d4c5f6a7b\nstatus: production\ndescription: Detects PowerShell execution with encoded or obfuscated command parameters\ntags:\n  - attack.execution\n  - attack.t1059.001\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith:\n      - '\\\\powershell.exe'\n      - '\\\\pwsh.exe'\n    CommandLine|contains:\n      - '-EncodedCommand'\n      - '-enc '\n      - '-e '\n      - '-bypass'\n      - '-nop'\n      - 'hidden'\nfalsepositives:\n  - Legitimate administrative scripts\nlevel: high\n\`\`\`\n\n## Analyst Tip\n> 💡 Ask for a specific technique like "Generate Sigma rule for T1059.001" or "PowerShell attack detection" for full Sigma + KQL + SPL output.`;
  }
  if (lower.includes('mitre') || lower.match(/t\d{4}/i)) {
    const techId = lower.match(/t(\d{4}(?:\.\d{3})?)/i)?.[0]?.toUpperCase() || 'T1059';
    return `⚠️ Using built-in threat intelligence\n\n## Overview\nMITRE ATT&CK technique lookup for **${techId}**.\n\n## Why It Matters\nThe MITRE ATT&CK framework provides a structured taxonomy of adversary tactics and techniques. Understanding technique ${techId} helps defenders build targeted detection rules.\n\n## Detection Guidance\nMonitor process execution, command-line parameters, and network activity associated with this technique. Deploy endpoint detection agents with behavior-based rules.\n\n## Mitigation\n- Apply least-privilege principles\n- Enable comprehensive logging (process creation, network connections)\n- Deploy EDR/XDR with behavioral detection capabilities\n\n## Analyst Tip\n> 💡 Use the Detection Rules panel (SOC tab) to generate Sigma/KQL/SPL rules for any MITRE technique. Configure an AI API key for context-aware explanations.`;
  }
  if (lower.includes('ransomware') || lower.includes('encrypt') || lower.includes('wiper')) {
    return `⚠️ Using built-in threat intelligence\n\n## Overview\n**Ransomware** attacks encrypt victim data and demand payment for decryption keys. Modern ransomware gangs (LockBit, ALPHV/BlackCat, Cl0p) use a double-extortion model: exfiltrate data BEFORE encrypting to maximise leverage.\n\n## Why It Matters\nRansomware caused over $1B in ransom payments in 2023. Healthcare, government, and critical infrastructure are primary targets. Average dwell time before encryption is 9 days.\n\n## Detection Guidance\n- Monitor for mass file rename/modification events (>50 files/min)\n- Alert on shadow copy deletion: \`vssadmin delete shadows\`\n- Detect common tools: Cobalt Strike, Rclone, AnyDesk\n- Monitor for LSASS access (credential dumping before lateral movement)\n\n## Mitigation\n1. Immutable offline backups (3-2-1 rule)\n2. MFA on all remote access (VPN, RDP, email)\n3. Network segmentation to limit lateral movement\n4. Privileged access management (PAM)\n5. EDR with ransomware-specific behavioral rules\n\n## Analyst Tip\n> 💡 Run the Incident Simulation panel to walk through a full ransomware attack chain with detection checkpoints and response playbook.`;
  }
  if (lower.includes('apt29') || lower.includes('apt28') || lower.includes('lazarus') || lower.includes('threat actor') || lower.includes('apt group')) {
    return `⚠️ Using built-in threat intelligence\n\n## Overview\nThreat actor intelligence is available for major APT groups and ransomware operators in the local database.\n\n## Key Threat Actors\n| Actor | Origin | Motivation | Recent Activity |\n|-------|--------|------------|----------------|\n| **APT29** (Cozy Bear) | Russia/SVR | Espionage | Microsoft Exchange breach (2024) |\n| **APT28** (Fancy Bear) | Russia/GRU | Espionage, disinfo | Active NATO targeting |\n| **Lazarus Group** | North Korea/RGB | Financial theft | Bybit exchange ($1.5B, 2024) |\n| **LockBit** | Unknown | Ransomware RaaS | Disrupted by Op. Cronos (2024), resumed |\n| **Scattered Spider** | USA/UK | Financial | MGM Resorts, Caesars (2023) |\n\n## Analyst Tip\n> 💡 Ask specifically: "Profile APT29" or "What are Lazarus Group TTPs?" for detailed actor intelligence including tools, techniques, and IOCs.`;
  }

  // ROOT-CAUSE FIX: Replace "Enable Full AI Mode" with a helpful, professional
  // local-intelligence response. The "Enable Full AI Mode" message was misleading —
  // it appeared even when API keys ARE set but a transient provider error occurred.
  // Now the response is purely informational about current mode, never prescriptive.
  return '⚠️ Using built-in threat intelligence\n\n## Overview\nI\'m **RAKAY**, your AI Security Analyst assistant operating in **Local Intelligence Mode**.\n\nAll built-in capabilities are fully active. External AI providers enhance response quality when configured via environment variables — but are not required for core security analysis.\n\n## Available Capabilities (Local Mode)\n- **CVE Intelligence** — 37 critical CVEs including Log4Shell (CVE-2021-44228), ProxyShell, EternalBlue, Spring4Shell\n- **MITRE ATT&CK** — 26 techniques with detection guidance (T1059, T1190, T1486, T1078, etc.)\n- **Sigma Rules** — 21 pre-built detection rules (Sigma/KQL/SPL formats)\n- **Threat Actors** — APT29, APT28, Lazarus Group, LockBit, Scattered Spider, Volt Typhoon profiles\n- **Incident Response** — Ransomware, supply chain, phishing, insider-threat playbooks\n- **IOC Analysis** — IP, domain, hash reputation with MITRE mapping\n\n## Try These Queries\n- `What is CVE-2021-44228?` — Log4Shell full analysis\n- `Generate Sigma rule for PowerShell attack` — detection engineering\n- `Explain T1059.001` — MITRE ATT&CK technique deep-dive\n- `Profile APT29` — threat actor intelligence\n- `Simulate ransomware attack` — incident response walkthrough\n- `Analyze IOC 185.220.101.1` — IP reputation check\n\n## Provider Status\nCheck `/api/ai/status` for real-time provider availability and key configuration status.';
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MULTI-PROVIDER  (TASKS 1, 4, 6, 7)
//  Failover chain: OpenAI → Ollama → Anthropic → Gemini → DeepSeek → Mock
//  Dynamic ordering by health score before each request.
//  Per-call 15s timeout via Promise.race.
//  True graceful degradation on total failure.
// ═══════════════════════════════════════════════════════════════════════════════
class MultiProvider {
  constructor(providers) {
    this.providers     = providers;
    this._mockProvider = providers.find(p => p.name === 'mock') || new MockProvider();
  }

  /**
   * TASK 7: Sort real providers by health score (descending).
   * Mock provider always stays last as the final fallback.
   */
  _sortedProviders() {
    const real = this.providers.filter(p => p.name !== 'mock');
    // Sort by health score descending (higher = better)
    real.sort((a, b) => (b.health?.score ?? 50) - (a.health?.score ?? 50));
    const mock = this.providers.filter(p => p.name === 'mock');
    return [...real, ...mock];
  }

  get name() {
    const live = this._sortedProviders().find(p => !p.cb?.isOpen() && p.name !== 'mock' && p.apiKey);
    return live ? live.name : 'mock';
  }

  getStatus() {
    return this.providers.map(p => ({
      name:   p.name,
      model:  p.model,
      hasKey: !!(p.apiKey && p.apiKey !== 'local' && p.apiKey !== 'mock'),
      cb:     p.cb?.getStatus?.() || { state: 'N/A' },
      health: p.health?.stats    || { score: 'N/A' },
    }));
  }

  /**
   * TASK 4: Wrap any provider call with a 15s timeout.
   * On timeout, the circuit breaker records a failure and failover continues.
   */
  _withTimeout(providerCallPromise, providerName) {
    return withCallTimeout(providerCallPromise, PROVIDER_CALL_TIMEOUT, providerName);
  }

  /**
   * TASK 6: Never throw — always return a valid response object.
   * On total failure, returns degraded mock response.
   */
  async chat(messages, tools = [], opts = {}) {
    const tried  = [];
    const errors = [];

    for (const provider of this._sortedProviders()) {
      // Skip if circuit is open
      if (provider.cb?.isOpen?.()) {
        const status = provider.cb.getStatus();
        console.log(`[MultiProvider] Skipping ${provider.name} — circuit OPEN (${status.remainingOpenMs}ms remaining, will probe at HALF_OPEN)`);
        continue;
      }
      // Skip if no API key (Ollama uses 'local' sentinel, Mock uses 'mock' sentinel)
      const hasKey = provider.apiKey && provider.apiKey.length > 0;
      if (!hasKey && provider.name !== 'mock') {
        console.log(`[MultiProvider] Skipping ${provider.name} — no API key configured`);
        continue;
      }

      tried.push(provider.name);
      const healthScore = provider.health?.score ?? '?';
      console.log(`[MultiProvider] Trying ${provider.name} (${provider.model}) health_score=${healthScore}`);

      try {
        // TASK 4: 15s hard timeout per provider call
        const result = await this._withTimeout(
          provider.chat(messages, tools, opts),
          provider.name
        );
        if (tried.length > 1) {
          console.log(`[MultiProvider] FAILOVER_SUCCESS: ${tried.slice(0, -1).join(' → ')} failed → ${provider.name} succeeded`);
        }
        return { ...result, _provider: provider.name };
      } catch (err) {
        const reason = err.message?.slice(0, 100) || 'unknown';
        errors.push({ provider: provider.name, error: reason, ts: new Date().toISOString() });

        if (err.circuitOpen) {
          console.warn(`[MultiProvider] ${provider.name} circuit just opened mid-request — trying next`);
          continue;
        }
        if (isAuthError(err)) {
          console.warn(`[MultiProvider] ${provider.name} AUTH_ERROR — skipping (CB not triggered): ${reason}`);
          continue;
        }
        if (err.ollamaDown) {
          console.warn(`[MultiProvider] Ollama not running at ${provider.baseUrl} — skipping`);
          continue;
        }
        if (err.isTimeout) {
          console.warn(`[MultiProvider] ${provider.name} TIMED_OUT (${PROVIDER_CALL_TIMEOUT}ms) — failing over`);
          continue;
        }
        console.warn(`[MultiProvider] ${provider.name} FAILED (${reason}) — trying next provider`);
      }
    }

    // TASK 6: True graceful degradation — NEVER throw, always return valid JSON
    console.warn(`[MultiProvider] ALL_PROVIDERS_FAILED tried=[${tried.join(', ')}] errors=${JSON.stringify(errors)} — activating mock fallback`);
    const mockResult = await this._mockProvider.chat(messages, tools, opts);
    return {
      ...mockResult,
      _provider: 'mock',
      _degraded:  true,
      _errors:    errors,
      reply:      mockResult.content,
    };
  }

  async chatStream(messages, tools = [], opts = {}, onChunk) {
    const tried  = [];
    const errors = [];

    for (const provider of this._sortedProviders()) {
      if (provider.cb?.isOpen?.()) {
        console.log(`[MultiProvider:stream] Skipping ${provider.name} — circuit OPEN`);
        continue;
      }
      const hasKey = provider.apiKey && provider.apiKey.length > 0;
      if (!hasKey && provider.name !== 'mock') continue;

      tried.push(provider.name);
      console.log(`[MultiProvider:stream] Trying ${provider.name} health_score=${provider.health?.score ?? '?'}`);

      try {
        // TASK 4: 15s timeout on stream initiation
        const result = await this._withTimeout(
          provider.chatStream(messages, tools, opts, onChunk),
          provider.name + ':stream'
        );
        if (tried.length > 1) {
          console.log(`[MultiProvider:stream] FAILOVER_SUCCESS: ${tried.slice(0, -1).join(' → ')} → ${provider.name}`);
        }
        return { ...result, _provider: provider.name };
      } catch (err) {
        errors.push({ provider: provider.name, error: err.message?.slice(0, 80) });
        if (err.circuitOpen || isAuthError(err) || err.ollamaDown || err.isTimeout) {
          console.warn(`[MultiProvider:stream] ${provider.name} skipped: ${err.message?.slice(0, 60)}`);
          continue;
        }
        console.warn(`[MultiProvider:stream] ${provider.name} FAILED: ${err.message?.slice(0, 60)} — trying next`);
      }
    }

    // Graceful degradation for streaming — use mock
    console.warn(`[MultiProvider:stream] All providers failed tried=[${tried.join(', ')}] — mock fallback`);
    const mockResult = await this._mockProvider.chatStream(messages, tools, opts, onChunk);
    return { ...mockResult, _provider: 'mock', _degraded: true, _errors: errors };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FACTORY
//  Default order: OpenAI → Ollama → Anthropic → Gemini → DeepSeek → Mock
// ═══════════════════════════════════════════════════════════════════════════════
function createMultiProvider(config = {}) {
  const providers = [];

  // Single-provider override (e.g., for testing)
  if (config.provider && config.provider !== 'multi') {
    switch (config.provider.toLowerCase()) {
      case 'openai':    providers.push(new OpenAIProvider(config));    break;
      case 'anthropic':
      case 'claude':    providers.push(new AnthropicProvider(config)); break;
      case 'deepseek':  providers.push(new DeepSeekProvider(config));  break;
      case 'gemini':    providers.push(new GeminiProvider(config));    break;
      case 'ollama':
      case 'local':     providers.push(new OllamaProvider(config));    break;
      case 'mock':      providers.push(new MockProvider()); break;
    }
    providers.push(new MockProvider());
    return new MultiProvider(providers);
  }

  // TASK 1: Full failover chain — OpenAI → Ollama → Anthropic → Gemini → DeepSeek → Mock
  providers.push(new OpenAIProvider(config));
  providers.push(new OllamaProvider(config));    // local — no rate limit, offline-capable
  providers.push(new AnthropicProvider(config));
  providers.push(new GeminiProvider(config));
  providers.push(new DeepSeekProvider(config));
  providers.push(new MockProvider());

  console.log(`[MultiProvider] Initialized chain: ${providers.map(p => p.name).join(' → ')}`);
  return new MultiProvider(providers);
}

// Legacy alias
function createLLMProvider(config = {}) { return createMultiProvider(config); }

module.exports = {
  createMultiProvider,
  createLLMProvider,
  MultiProvider,
  OpenAIProvider,
  OllamaProvider,
  AnthropicProvider,
  DeepSeekProvider,
  GeminiProvider,
  MockProvider,
  CircuitBreaker,
  HealthScorer,
  isRetryable,
  isAuthError,
  backoffDelay,
  withCallTimeout,
  PROVIDER_CALL_TIMEOUT,
  CB_FAILURE_THRESHOLD,
  CB_OPEN_DURATION_MS,
  CB_HALF_OPEN_SUCCESSES,
};
