/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — LLM Input Contract  (Phase 0)
 *  js/llm-contract.js
 *
 *  Faithful TypeScript/JS port of AiSOC v7.6.0
 *  services/agents/app/llm/contract.py
 *
 *  PURPOSE: Fail-closed validator that runs BEFORE every LLM call site in
 *  Wadjet-Eye.  Blocks raw OCSF events, raw log lines, and secrets from ever
 *  reaching the LLM provider (OpenAI, Gemini, Claude, DeepSeek).
 *
 *  DESIGN:
 *  • All logic is side-effect-free (pure functions + module-level state).
 *  • Zero external dependencies — works in browser (ai-orchestrator-v5.js)
 *    and Node.js (backend/routes/ai.js, backend/routes/rag.js, etc.).
 *  • Enforcement is ON by default; disable only for debugging via env var
 *    WE_LLM_CONTRACT_ENFORCED=0 (Node.js) or window.WE_LLM_CONTRACT=false (browser).
 *  • classifyMessage(content) → reason string | null   (null = OK)
 *  • validateLLMMessages(messages[]) → validated[]     (throws on first violation)
 *  • wrapLLMCall(fn)  → fn wrapped with pre-call validation
 *
 *  CALL SITES WRAPPED (Phase 0):
 *  ┌─ FRONTEND ──────────────────────────────────────────────────────────────┐
 *  │  js/ai-orchestrator-v5.js   _callOpenAI()  line ~176                   │
 *  │  js/ai-orchestrator-v5.js   _callClaude()  line ~244                   │
 *  │  js/soc-ai-engine.js        runOpenAIAnalysis()  line ~573              │
 *  │  js/soc-ai-engine.js        chatQuery()  line ~631                      │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *  ┌─ BACKEND ───────────────────────────────────────────────────────────────┐
 *  │  backend/routes/ai.js       callOpenAI()  line ~84                      │
 *  │  backend/routes/ai.js       callGemini()  line ~118                     │
 *  │  backend/routes/ai.js       callOllama()  line ~162                     │
 *  │  backend/routes/rag.js      /copilot POST  line ~406                    │
 *  │  backend/routes/rag.js      /explain-alert POST  line ~552              │
 *  │  backend/services/llm-provider.js  (all providers via .chat())          │
 *  └─────────────────────────────────────────────────────────────────────────┘
 *
 *  FEATURE FLAG: WE_FEATURE_LLM_CONTRACT (default: true)
 *  Set window.WE_FEATURE_LLM_CONTRACT = false or env WE_FEATURE_LLM_CONTRACT=0
 *  to revert to the pre-Phase-0 behaviour (no validation).
 *
 * ══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

/* ── Feature flag ─────────────────────────────────────────────────────────── */
// Allows instant rollback without a redeploy:
//   browser: window.WE_FEATURE_LLM_CONTRACT = false
//   Node.js: WE_FEATURE_LLM_CONTRACT=0 in environment
function _featureFlagEnabled() {
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env.WE_FEATURE_LLM_CONTRACT;
    if (v !== undefined) return v !== '0' && v !== 'false';
  }
  if (typeof window !== 'undefined' && window.WE_FEATURE_LLM_CONTRACT !== undefined) {
    return window.WE_FEATURE_LLM_CONTRACT !== false;
  }
  return true; // ON by default
}

/* ── Enforcement toggle ───────────────────────────────────────────────────── */
// Ported from AiSOC: AISOC_AGENTS_LLM_CONTRACT_ENFORCED env var.
// WE equivalent: WE_LLM_CONTRACT_ENFORCED
function _envDefaultEnforced() {
  if (typeof process !== 'undefined' && process.env) {
    const raw = (process.env.WE_LLM_CONTRACT_ENFORCED || '1').trim();
    return !['0', 'false', 'False', 'no', 'off'].includes(raw);
  }
  return true;
}

let _ENFORCED = _envDefaultEnforced();

/** Check whether the contract is currently enforced. */
function isContractEnforced() {
  return _ENFORCED && _featureFlagEnabled();
}

/** Override enforcement at runtime. Returns the previous value. */
function setContractEnforcement(value) {
  const prev = _ENFORCED;
  _ENFORCED  = Boolean(value);
  return prev;
}

/* ── Constants — ported verbatim from contract.py ────────────────────────── */

const _MAX_MESSAGE_CHARS   = (function () {
  if (typeof process !== 'undefined' && process.env.AISOC_AGENTS_LLM_CONTRACT_MAX_CHARS) {
    return parseInt(process.env.AISOC_AGENTS_LLM_CONTRACT_MAX_CHARS, 10) || 60000;
  }
  return 60000;
})();

const _MAX_JSON_LINE_KEYS = 6; // tuple-of-keys threshold for "looks like a log line"

/** OCSF key blocklist — ported from contract.py _OCSF_KEYS */
const _OCSF_KEYS = new Set([
  'class_uid',
  'category_uid',
  'activity_id',
  'type_uid',
  'metadata',
  'time_dt',
  'observables',
  'raw_data',
]);

/** Raw log key blocklist — ported from contract.py _LOG_KEYS */
const _LOG_KEYS = new Set([
  'Event',
  'EventData',
  'Sysmon',
  'RecordID',
  'EventRecordID',
  'Channel',
  'Provider',
  '_raw',
  '_time',
  'punct',
]);

/**
 * Combined blocklist for dict-key presence checks.
 * Exported so callers can redact nested payloads before building prompts.
 */
const CONTRACT_DICT_KEY_BLOCKLIST = new Set([..._OCSF_KEYS, ..._LOG_KEYS]);

/**
 * Log-shape string patterns — ported from contract.py _LOG_SHAPE_PATTERNS.
 * Scanned against the first 4 000 chars of each message.
 */
const _LOG_SHAPE_PATTERNS = [
  /"class_uid"\s*:\s*\d+/,
  /"activity_id"\s*:\s*\d+/,
  /"EventID"\s*:\s*\d+/,
  /"EventRecordID"\s*:\s*\d+/,
  /<Event xmlns="http:\/\/schemas\.microsoft\.com\/win\//,
  /"_raw"\s*:\s*"/,
  /"sourcetype"\s*:\s*"/,
];

/**
 * Secret patterns — ported from contract.py _SECRET_PATTERNS.
 * Belt-and-braces guard; the vault layer is the primary defence.
 */
const _SECRET_PATTERNS = [
  /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

/* ── LLMContractViolation ─────────────────────────────────────────────────── */

/**
 * Thrown (or returned as an Error) when a message violates the LLM input
 * contract.  Ported from contract.py LLMContractViolation.
 */
class LLMContractViolation extends Error {
  /**
   * @param {string} reason     - human-readable reason for the violation
   * @param {object} [opts]
   * @param {string} [opts.role]     - message role (system/user/assistant)
   * @param {string} [opts.evidence] - first 200 chars of the offending content
   */
  constructor(reason, { role, evidence } = {}) {
    let msg = `[LLMInputContract] ${reason}`;
    if (role)     msg += ` (role=${role})`;
    if (evidence) msg += ` — evidence: ${String(evidence).slice(0, 200)}`;
    super(msg);
    this.name     = 'LLMContractViolation';
    this.reason   = reason;
    this.role     = role   || null;
    this.evidence = evidence || null;
    if (Error.captureStackTrace) Error.captureStackTrace(this, LLMContractViolation);
  }
}

/* ── Internal heuristic helpers ────────────────────────────────────────────── */

/**
 * Return a violation reason if `payload` (a dict) looks like an OCSF event.
 * Ported from contract.py _looks_like_ocsf().
 * @param {object} payload
 * @returns {string|null}
 */
function _looksLikeOCSF(payload) {
  const keys = Object.keys(payload);
  const matched = keys.filter(k => _OCSF_KEYS.has(k));
  if (matched.length > 0) {
    return `OCSF keys present: [${matched.sort().join(', ')}]`;
  }
  const metadata = payload.metadata;
  if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
    if ('product' in metadata && 'version' in metadata) {
      return 'OCSF-style metadata.product/version block';
    }
  }
  return null;
}

/**
 * Return a violation reason if `payload` (a dict) looks like a raw log line.
 * Ported from contract.py _looks_like_raw_log().
 * @param {object} payload
 * @returns {string|null}
 */
function _looksLikeRawLog(payload) {
  const keys = Object.keys(payload);
  const matched = keys.filter(k => _LOG_KEYS.has(k));
  if (matched.length > 0) {
    return `raw-log keys present: [${matched.sort().join(', ')}]`;
  }
  // Windows event-log shape check: EventID (integer) + Channel
  if (Number.isInteger(payload.EventID) && 'Channel' in payload) {
    return 'Windows event-log shape (EventID + Channel)';
  }
  return null;
}

/**
 * Return a violation reason if `text` contains recognisable log-shape strings.
 * Ported from contract.py _looks_like_log_string().
 * Only scans the first 4 000 chars for performance.
 * @param {string} text
 * @returns {string|null}
 */
function _looksLikeLogString(text) {
  const head = text.slice(0, 4000);
  for (const pattern of _LOG_SHAPE_PATTERNS) {
    const m = pattern.exec(head);
    if (m) {
      return `raw-log signature matched: ${m[0].slice(0, 80)}`;
    }
  }
  return null;
}

/**
 * Return a violation reason if `text` contains secret-shaped values.
 * Ported from contract.py _looks_like_secret().
 * @param {string} text
 * @returns {string|null}
 */
function _looksLikeSecret(text) {
  const head = text.slice(0, 4000);
  for (const pattern of _SECRET_PATTERNS) {
    const m = pattern.exec(head);
    if (m) {
      return `secret-shaped value detected: ${m[0].slice(0, 60)}`;
    }
  }
  return null;
}

/**
 * Parse `text` as JSON if it starts with `{` or `[`; return null on failure.
 * Ported from contract.py _try_load_json().
 * @param {string} text
 * @returns {any|null}
 */
function _tryLoadJSON(text) {
  const stripped = text.trim();
  if (!stripped || (stripped[0] !== '{' && stripped[0] !== '[')) return null;
  try {
    return JSON.parse(stripped);
  } catch {
    return null;
  }
}

/* ── Public: classifyMessage ───────────────────────────────────────────────── */

/**
 * Check whether a single message `content` string breaches the LLM input
 * contract.  Returns a human-readable reason string if it does, or `null`
 * if the content is clean.
 *
 * Ported from contract.py classify_message().
 *
 * @param {string} content  - the message content to validate
 * @param {object} [opts]
 * @param {string} [opts.role]  - message role hint (for logging only)
 * @returns {string|null}       - violation reason, or null if clean
 */
function classifyMessage(content, { role = 'user' } = {}) {
  if (typeof content !== 'string') {
    return `non-string message content (type=${typeof content})`;
  }

  if (content.length > _MAX_MESSAGE_CHARS) {
    return `message exceeds size cap (${content.length} > ${_MAX_MESSAGE_CHARS} chars)`;
  }

  // 1) Substring scan — fastest path, catches log shapes embedded in prose.
  const logHit = _looksLikeLogString(content);
  if (logHit) return logHit;

  const secretHit = _looksLikeSecret(content);
  if (secretHit) return secretHit;

  // 2) JSON inspection — only when the message *looks* like JSON.
  const parsed = _tryLoadJSON(content);
  if (parsed !== null) {
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const ocsf = _looksLikeOCSF(parsed);
      if (ocsf) return ocsf;
      const log = _looksLikeRawLog(parsed);
      if (log) return log;
    } else if (Array.isArray(parsed) && parsed.length > 0) {
      const head = parsed[0];
      if (head && typeof head === 'object' && !Array.isArray(head)) {
        const keyCount = Object.keys(head).length;
        if (keyCount > _MAX_JSON_LINE_KEYS && (_looksLikeOCSF(head) || _looksLikeRawLog(head))) {
          return 'raw event array detected (looks like log batch)';
        }
      }
    }
  }

  return null; // clean
}

/* ── Public: validateLLMMessages ──────────────────────────────────────────── */

/**
 * Validate an array of chat messages before they are sent to any LLM.
 * Throws `LLMContractViolation` on the first violation found.
 *
 * When enforcement is disabled (WE_LLM_CONTRACT_ENFORCED=0), the messages
 * are still normalised and returned but no exception is thrown.
 *
 * Ported from contract.py LLMInputContract.validate().
 *
 * @param {Array<{role: string, content: string}|string>} messages
 * @returns {Array<{role: string, content: string}>} normalised messages
 * @throws {LLMContractViolation}
 */
function validateLLMMessages(messages) {
  if (!Array.isArray(messages)) {
    messages = Array.from(messages);
  }

  const normalised = [];

  for (let idx = 0; idx < messages.length; idx++) {
    const msg = messages[idx];
    let role, content;

    // Coerce various message shapes: plain dict, string, tuple-array
    if (msg && typeof msg === 'object' && !Array.isArray(msg)) {
      role    = String(msg.role || 'user');
      content = msg.content;
      if (typeof content !== 'string') {
        try { content = JSON.stringify(content); } catch { content = String(content); }
      }
    } else if (typeof msg === 'string') {
      role    = 'user';
      content = msg;
    } else if (Array.isArray(msg) && msg.length === 2) {
      role    = String(msg[0]);
      content = typeof msg[1] === 'string' ? msg[1] : JSON.stringify(msg[1]);
    } else {
      role    = 'user';
      content = String(msg);
    }

    if (isContractEnforced()) {
      const reason = classifyMessage(content, { role });
      if (reason) {
        throw new LLMContractViolation(
          `message[${idx}] failed contract: ${reason}`,
          { role, evidence: content.slice(0, 200) }
        );
      }
    }

    normalised.push({ role, content });
  }

  return normalised;
}

/* ── Public: wrapLLMCall ──────────────────────────────────────────────────── */

/**
 * Wrap any async function that accepts `(messages, ...rest)` so that it
 * automatically validates the message array before forwarding the call.
 *
 * Usage:
 *   const safeCallOpenAI = wrapLLMCall(_callOpenAI);
 *   const result = await safeCallOpenAI(messages, model);
 *
 * @param {Function} fn  - the LLM-calling function to wrap
 * @returns {Function}   - wrapped function with pre-call validation
 */
function wrapLLMCall(fn) {
  return async function wrappedLLMCall(messages, ...rest) {
    validateLLMMessages(messages); // throws LLMContractViolation if bad
    return fn.call(this, messages, ...rest);
  };
}

/* ── Public: safeCallMessages ─────────────────────────────────────────────── */

/**
 * Validate messages then call `fn(validatedMessages, ...rest)`.
 * Equivalent to AiSOC's safe_ainvoke() — validate first, then dispatch.
 *
 * @param {Function} fn
 * @param {Array} messages
 * @param  {...any} rest
 * @returns {Promise<any>}
 */
async function safeCallMessages(fn, messages, ...rest) {
  const validated = validateLLMMessages(messages);
  return fn(validated, ...rest);
}

/* ── Public: getContractStats ─────────────────────────────────────────────── */

// Internal counters for monitoring — surfaced via getContractStats()
const _stats = {
  checked:   0,
  blocked:   0,
  bypassed:  0, // enforcement disabled
  lastViolation: null,
};

/**
 * Instrumented version of validateLLMMessages that tracks call/block counts.
 * Use this at all call sites instead of raw validateLLMMessages().
 *
 * @param {Array} messages
 * @returns {Array<{role: string, content: string}>}
 * @throws {LLMContractViolation}
 */
function validateAndTrack(messages) {
  _stats.checked++;
  if (!isContractEnforced()) {
    _stats.bypassed++;
    // Still normalise but don't throw
    return validateLLMMessages(messages);
  }
  try {
    return validateLLMMessages(messages);
  } catch (err) {
    if (err instanceof LLMContractViolation) {
      _stats.blocked++;
      _stats.lastViolation = {
        reason:    err.reason,
        role:      err.role,
        timestamp: new Date().toISOString(),
      };
      _log('BLOCKED', err.message);
    }
    throw err;
  }
}

/** Return a snapshot of contract validation counters. */
function getContractStats() {
  return { ..._stats };
}

/** Reset contract stats counters (useful in tests). */
function resetContractStats() {
  _stats.checked  = 0;
  _stats.blocked  = 0;
  _stats.bypassed = 0;
  _stats.lastViolation = null;
}

/* ── Internal: structured logger ──────────────────────────────────────────── */

function _log(level, msg, data) {
  const ts   = typeof Date !== 'undefined' ? new Date().toISOString() : '';
  const line = `[LLMContract] ${level} ${ts} — ${msg}`;
  if (typeof console !== 'undefined') {
    if (level === 'BLOCKED') {
      console.warn(line, data || '');
    } else {
      console.log(line, data || '');
    }
  }
}

/* ── Module exports ───────────────────────────────────────────────────────── */

// Universal module pattern: works as CommonJS (Node.js backend) and as a
// browser global (window.WELLMContract) without bundler tooling.

const WELLMContract = {
  // Core API
  classifyMessage,
  validateLLMMessages,
  validateAndTrack,
  wrapLLMCall,
  safeCallMessages,

  // Enforcement control
  isContractEnforced,
  setContractEnforcement,

  // Observability
  getContractStats,
  resetContractStats,

  // Error class
  LLMContractViolation,

  // Exported constants (allow callers to redact before building prompts)
  OCSF_KEYS:                 _OCSF_KEYS,
  LOG_KEYS:                  _LOG_KEYS,
  CONTRACT_DICT_KEY_BLOCKLIST,
  MAX_MESSAGE_CHARS:         _MAX_MESSAGE_CHARS,
};

if (typeof module !== 'undefined' && module.exports) {
  // Node.js / CommonJS
  module.exports = WELLMContract;
} else if (typeof window !== 'undefined') {
  // Browser global
  window.WELLMContract = WELLMContract;
}
