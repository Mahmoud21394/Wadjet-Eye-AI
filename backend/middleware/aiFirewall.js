/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — AI Security Firewall  v1.0
 *  backend/middleware/aiFirewall.js
 *
 *  ENTERPRISE AUDIT REMEDIATION — AI Security Workstream
 *  ──────────────────────────────────────────────────────────────────────────
 *  Every LLM entry point MUST pass through this firewall. No exceptions.
 *
 *  Architecture — 6 defence layers:
 *
 *  Layer 1: guardInput()       — Prompt injection detection + blocking
 *  Layer 2: wrapUntrusted()    — XML structural isolation of external data
 *  Layer 3: taintPropagate()   — Tracks taint through multi-hop pipelines
 *  Layer 4: guardOutput()      — Post-LLM output validation + PII scrub
 *  Layer 5: aiFirewallMiddleware() — Express middleware for ALL /api/ai* routes
 *  Layer 6: Audit logging      — Every AI call logged to decision ledger
 *
 *  Covers:
 *    • RAG ingestion (rag.js)
 *    • News ingestion (news.js)
 *    • Email analyzer (email-threat.js)
 *    • Agent orchestrator (agents.js)
 *    • AI routes (ai.js)
 *    • Threat intelligence (cti.js, intel.js)
 *    • Malware explanation (malware-analysis.js)
 *    • Copilot (rakay.js, raykan-engine.js)
 *    • Soc intelligence (soc-intelligence.js)
 *    • Adversary simulation (adversary-sim.js)
 * ══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto  = require('crypto');
const logger  = require('../utils/logger');

const _MOD = 'AIFirewall';

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1 — PROMPT INJECTION PATTERN DATABASE
// ─────────────────────────────────────────────────────────────────────────────

const INJECTION_PATTERNS = [
  // Instruction override
  { id: 'PI-001', severity: 'critical', pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)/i },
  { id: 'PI-002', severity: 'critical', pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i },
  { id: 'PI-003', severity: 'critical', pattern: /forget\s+(everything|all)\s+(you\s+)?(know|were\s+told|learned)/i },
  { id: 'PI-004', severity: 'critical', pattern: /new\s+instructions?\s*[:=]\s*/i },
  { id: 'PI-005', severity: 'critical', pattern: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i },

  // Role hijacking
  { id: 'PI-010', severity: 'critical', pattern: /you\s+are\s+now\s+(a\s+)?(different|new|another|evil|unrestricted)/i },
  { id: 'PI-011', severity: 'critical', pattern: /pretend\s+(to\s+be|you\s+are)\s+(?!analyzing|investigating)/i },
  { id: 'PI-012', severity: 'high',     pattern: /act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(hacker|attacker|adversary|DAN|jailbreak)/i },
  { id: 'PI-013', severity: 'high',     pattern: /from\s+now\s+on\s+(you\s+are|behave|act|respond)/i },
  { id: 'PI-014', severity: 'high',     pattern: /your\s+true\s+(self|identity|purpose|goal)\s+is/i },

  // System prompt exfiltration
  { id: 'PI-020', severity: 'critical', pattern: /repeat\s+(your|the)\s+(system\s+prompt|instructions?|rules?)\s+(verbatim|exactly|word\s+for\s+word)/i },
  { id: 'PI-021', severity: 'critical', pattern: /what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions?|prompt|context)/i },
  { id: 'PI-022', severity: 'high',     pattern: /print\s+(the\s+)?(contents?\s+of\s+)?(your\s+)?(system|initial)\s+prompt/i },
  { id: 'PI-023', severity: 'high',     pattern: /reveal\s+(your\s+)?(hidden|secret|system)\s+(instructions?|prompt)/i },
  { id: 'PI-024', severity: 'high',     pattern: /tell\s+me\s+(what|everything)\s+(you\s+)(were|are)\s+told/i },

  // Delimiter injection
  { id: 'PI-030', severity: 'critical', pattern: /```system|```\s*\n\s*system\s+prompt/i },
  { id: 'PI-031', severity: 'high',     pattern: /<system>|<\/system>|<context>|<\/context>/i },
  { id: 'PI-032', severity: 'high',     pattern: /---+\s*system\s*---+/i },
  { id: 'PI-033', severity: 'medium',   pattern: /={5,}\s*new\s+prompt\s*={5,}/i },

  // Jailbreak prefixes
  { id: 'PI-040', severity: 'critical', pattern: /DAN\s+mode|jailbreak\s+mode|developer\s+mode|unrestricted\s+mode/i },
  { id: 'PI-041', severity: 'critical', pattern: /do\s+anything\s+now|evil\s+(AI|assistant|mode)/i },
  { id: 'PI-042', severity: 'high',     pattern: /without\s+(any\s+)?(restrictions?|limitations?|filters?|safety|guidelines?)/i },
  { id: 'PI-043', severity: 'high',     pattern: /bypass\s+(your\s+)?(safety|content|ethics|moral)\s+(filter|check|guard|policy)/i },

  // Data exfiltration
  { id: 'PI-050', severity: 'critical', pattern: /send\s+(this|the)\s+(data|information|content|results?)\s+to\s+https?:\/\//i },
  { id: 'PI-051', severity: 'high',     pattern: /exfiltrat[ei]/i },
  { id: 'PI-052', severity: 'high',     pattern: /leak\s+(the\s+)?(data|keys?|secrets?|credentials?|tokens?)/i },
  { id: 'PI-053', severity: 'high',     pattern: /base64\s+(encode|decode)\s+(and\s+)?(send|transmit|output)/i },

  // Encoding evasion
  { id: 'PI-060', severity: 'medium',   pattern: /&#[0-9]{2,4};.*ignore|&#x[0-9a-f]{2,4};.*ignore/i },
  { id: 'PI-061', severity: 'medium',   pattern: /\u0130gnore|\u1D24gnore|\uFF29gnore/i },  // unicode lookalikes for 'I'

  // Tool / function abuse
  { id: 'PI-070', severity: 'critical', pattern: /call\s+(the\s+)?(delete|drop|truncate|exec|eval)\s+(function|tool|command)/i },
  { id: 'PI-071', severity: 'high',     pattern: /use\s+(the\s+)?(shell|bash|python|code_exec)\s+tool/i },
];

// PII detection patterns (for output scrubbing)
const PII_PATTERNS = [
  { type: 'ssn',    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                   replacement: '[REDACTED-SSN]' },
  { type: 'cc',     pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/g,              replacement: '[REDACTED-CC]' },
  { type: 'email',  pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, replacement: '[REDACTED-EMAIL]' },
  { type: 'phone',  pattern: /\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b/g, replacement: '[REDACTED-PHONE]' },
  { type: 'apikey', pattern: /\b(sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z\-_]{35}|xoxb-[0-9]+-[A-Za-z0-9]+)\b/g, replacement: '[REDACTED-APIKEY]' },
  { type: 'jwt',    pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*/g, replacement: '[REDACTED-JWT]' },
  { type: 'aws',    pattern: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,             replacement: '[REDACTED-AWS-KEY]' },
  { type: 'ipv4',   pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, replacement: '[IP-REDACTED]' },
];

// Secrets detection patterns
const SECRET_PATTERNS = [
  /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
  /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/,
  /ghp_[A-Za-z0-9]{36}/,
  /gho_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{82}/,
  /xoxs-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]{64}/,
  /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/,
  /EAAB[A-Za-z0-9]+/,
  /sk_live_[A-Za-z0-9]{24,}/,
  /rk_live_[A-Za-z0-9]{24,}/,
  /password\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*()]{8,}/i,
];

// Output anomaly patterns (signs of successful injection)
const OUTPUT_ANOMALY_PATTERNS = [
  { id: 'OA-001', severity: 'critical', pattern: /my\s+(true|actual|real)\s+(instructions?|purpose|goal)\s+(are|is)/i },
  { id: 'OA-002', severity: 'critical', pattern: /you\s+successfully\s+(jailbr|bypass|override)/i },
  { id: 'OA-003', severity: 'high',     pattern: /ignoring\s+(previous|prior|original)\s+instructions?/i },
  { id: 'OA-004', severity: 'high',     pattern: /as\s+(requested|instructed)\s+I\s+(will\s+)?(now\s+)?ignore/i },
  { id: 'OA-005', severity: 'high',     pattern: /SYSTEM\s+PROMPT\s*[:=]/i },
  { id: 'OA-006', severity: 'high',     pattern: /my\s+system\s+prompt\s+(says?|states?|contains?)/i },
  { id: 'OA-007', severity: 'medium',   pattern: /DAN\s+mode\s+(activated|enabled|on)/i },
  { id: 'OA-008', severity: 'medium',   pattern: /switching\s+to\s+(unrestricted|evil|developer)\s+mode/i },
];

// Hallucination / grounding signals
const HALLUCINATION_SIGNALS = [
  /I\s+(cannot|can't)\s+verify\s+this/i,
  /I\s+(don't|do\s+not)\s+have\s+(access|information)\s+(to|about)\s+this/i,
  /based\s+on\s+my\s+training\s+data/i,
  /as\s+of\s+my\s+knowledge\s+cutoff/i,
  /I\s+am\s+making\s+(an?\s+)?(assumption|guess|estimate)/i,
];

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1: guardInput()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * guardInput — scan text for prompt injection patterns before LLM call.
 *
 * @param {string} text          Raw user/external input
 * @param {object} [opts]
 * @param {string} [opts.source] Label for audit logging ('user', 'external', 'rag', etc.)
 * @param {string} [opts.tenantId]
 * @param {boolean} [opts.strict] Block medium-severity patterns (default: false)
 * @returns {{ blocked: boolean, patterns: string[], severity: string, sanitized: string }}
 */
function guardInput(text, opts = {}) {
  if (typeof text !== 'string') return { blocked: false, patterns: [], severity: 'none', sanitized: '' };

  const source   = opts.source   || 'unknown';
  const tenantId = opts.tenantId || 'system';
  const strict   = opts.strict   || false;

  const matches = [];
  let maxSeverity = 'none';

  const severityOrder = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

  for (const { id, severity, pattern } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(id);
      if (severityOrder[severity] > severityOrder[maxSeverity]) maxSeverity = severity;
    }
  }

  // Check for secrets in input
  const secretsFound = SECRET_PATTERNS.some(p => p.test(text));
  if (secretsFound) { matches.push('SEC-001'); maxSeverity = 'critical'; }

  const blocked = maxSeverity === 'critical' || maxSeverity === 'high' ||
                  (strict && maxSeverity === 'medium');

  if (blocked) {
    logger.warn(_MOD, 'Input blocked by AI Firewall', {
      source, tenantId, patterns: matches, severity: maxSeverity,
      textLen: text.length, textHash: crypto.createHash('sha256').update(text).digest('hex').slice(0, 16),
    });
  }

  // Sanitize even if not blocked — strip the most dangerous patterns
  let sanitized = text;
  if (!blocked) {
    // Encode injection-prone delimiters
    sanitized = sanitized.replace(/\[INST\]|\[\/INST\]/gi, '[inst-redacted]');
    sanitized = sanitized.replace(/<\|im_start\|>|<\|im_end\|>/gi, '');
    sanitized = sanitized.replace(/```system/gi, '```text');
  }

  return { blocked, patterns: matches, severity: maxSeverity, sanitized };
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2: wrapUntrusted()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * wrapUntrusted — wrap external/untrusted text in XML isolation tags.
 * Creates structural boundary that prevents injected instructions from
 * being treated as system directives by aligned LLMs.
 *
 * @param {string} text      Raw external content
 * @param {string} sourceTag Label identifying the data origin (e.g. 'paste_site', 'news_feed')
 * @returns {string}         Wrapped text safe for inclusion in LLM prompts
 */
function wrapUntrusted(text, sourceTag = 'external_data') {
  if (typeof text !== 'string') return '';
  // Sanitize the tag name — alphanumeric + underscore only
  const safeTag = String(sourceTag).replace(/[^a-z0-9_]/gi, '_').slice(0, 40);
  return `<untrusted_${safeTag}>\n${text}\n</untrusted_${safeTag}>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3: taintPropagate()
// ─────────────────────────────────────────────────────────────────────────────

/** Taint levels in ascending severity */
const TAINT_LEVELS = { clean: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * taintPropagate — track taint through multi-hop pipelines.
 * Taint is monotonically increasing: once high, never drops to low.
 *
 * @param {object} context        Shared pipeline context object
 * @param {string} taintLevel     New taint signal ('clean'|'low'|'medium'|'high'|'critical')
 * @param {string} [source]       Where taint originated
 * @returns {object}              Updated context
 */
function taintPropagate(context, taintLevel, source = 'unknown') {
  if (!context._taint) {
    context._taint = { level: 'clean', sources: [], timestamp: new Date().toISOString() };
  }
  const current = TAINT_LEVELS[context._taint.level] || 0;
  const incoming = TAINT_LEVELS[taintLevel] || 0;
  if (incoming > current) {
    context._taint.level = taintLevel;
    context._taint.escalated = true;
  }
  context._taint.sources.push({ source, level: taintLevel, at: Date.now() });
  return context;
}

/**
 * isTainted — check if pipeline context is tainted above threshold.
 * @param {object} context
 * @param {string} threshold  Minimum level to consider tainted ('medium'|'high'|'critical')
 * @returns {boolean}
 */
function isTainted(context, threshold = 'high') {
  const level = context._taint?.level || 'clean';
  return (TAINT_LEVELS[level] || 0) >= (TAINT_LEVELS[threshold] || 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4: guardOutput()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * guardOutput — post-LLM output validation + PII scrubbing.
 *
 * @param {string} text       Raw LLM output
 * @param {object} [opts]
 * @param {boolean} [opts.scrubPii]      Remove PII from output (default: true)
 * @param {boolean} [opts.scrubIp]       Remove IP addresses (default: false)
 * @param {boolean} [opts.enforceGrounding] Flag if hallucination signals detected (default: false)
 * @param {string}  [opts.tenantId]
 * @returns {{ safe: boolean, suspicious: boolean, patterns: string[], piiFound: string[], hallucinationRisk: boolean, output: string }}
 */
function guardOutput(text, opts = {}) {
  if (typeof text !== 'string') return { safe: true, suspicious: false, patterns: [], piiFound: [], hallucinationRisk: false, output: '' };

  const scrubPii        = opts.scrubPii        !== false; // default true
  const scrubIp         = opts.scrubIp         || false;
  const enforceGrounding= opts.enforceGrounding || false;
  const tenantId        = opts.tenantId        || 'system';

  let output = text;
  const anomalies    = [];
  const piiFound     = [];
  let suspicious     = false;
  let hallucinRisk   = false;

  // Check for output anomalies (injection success signals)
  for (const { id, severity, pattern } of OUTPUT_ANOMALY_PATTERNS) {
    if (pattern.test(text)) {
      anomalies.push(id);
      if (severity === 'critical' || severity === 'high') suspicious = true;
    }
  }

  // Scrub PII
  if (scrubPii) {
    for (const { type, pattern, replacement } of PII_PATTERNS) {
      if (type === 'ipv4' && !scrubIp) continue;
      if (pattern.test(output)) {
        piiFound.push(type);
        output = output.replace(pattern, replacement);
      }
    }
  }

  // Scrub secrets
  for (const p of SECRET_PATTERNS) {
    if (p.test(output)) {
      piiFound.push('secret');
      output = output.replace(p, '[REDACTED-SECRET]');
    }
  }

  // Hallucination detection
  if (enforceGrounding) {
    hallucinRisk = HALLUCINATION_SIGNALS.some(p => p.test(text));
  }

  if (anomalies.length > 0 || piiFound.length > 0) {
    logger.warn(_MOD, 'Output anomalies detected', {
      tenantId, anomalies, piiFound, hallucinRisk, suspicious,
      textLen: text.length,
    });
  }

  return {
    safe:             !suspicious,
    suspicious,
    patterns:         anomalies,
    piiFound,
    hallucinationRisk: hallucinRisk,
    output,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 5: Express Middleware — aiFirewallMiddleware()
// ─────────────────────────────────────────────────────────────────────────────

/**
 * AI request body field paths to scan for injection.
 * Covers all LLM entry points.
 */
const AI_INPUT_FIELDS = [
  'message', 'query', 'prompt', 'content', 'text', 'input',
  'description', 'context', 'data', 'ioc', 'indicator',
  'subject', 'body', 'email_content', 'raw_email',
  'alert_description', 'event_data', 'log_data',
  'threat_description', 'malware_sample', 'report_content',
  'user_message', 'question', 'instruction',
];

/**
 * aiFirewallMiddleware — Express middleware.
 * Applied to ALL /api/ai*, /api/rag*, /api/agents*, /api/copilot* routes.
 *
 * @type {import('express').RequestHandler}
 */
function aiFirewallMiddleware(req, res, next) {
  const tenantId = req.tenantId || req.user?.tenant_id || 'system';
  const userId   = req.user?.id || 'anonymous';
  const path     = req.path;

  // Collect all text fields to scan
  const textFields = [];
  const body = req.body || {};

  for (const field of AI_INPUT_FIELDS) {
    if (typeof body[field] === 'string' && body[field].length > 0) {
      textFields.push({ field, value: body[field] });
    }
  }

  // Also scan top-level string values not in our list (dynamic request bodies)
  for (const [k, v] of Object.entries(body)) {
    if (!AI_INPUT_FIELDS.includes(k) && typeof v === 'string' && v.length > 20) {
      textFields.push({ field: k, value: v });
    }
  }

  // Guard each field
  let blocked    = false;
  let maxSeverity= 'none';
  const allPatterns = [];

  for (const { field, value } of textFields) {
    const check = guardInput(value, { source: `request.body.${field}`, tenantId, strict: false });
    if (check.patterns.length > 0) allPatterns.push(...check.patterns);
    if (check.blocked) {
      blocked = true;
      if (['critical','high','medium','low','none'].indexOf(check.severity) <
          ['critical','high','medium','low','none'].indexOf(maxSeverity)) {
        maxSeverity = check.severity;
      }
    }
  }

  if (blocked) {
    logger.warn(_MOD, 'AI request blocked by firewall', {
      tenantId, userId, path, patterns: allPatterns, severity: maxSeverity,
      ip: req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress,
    });
    return res.status(400).json({
      error:    'Request blocked by AI Security Firewall',
      code:     'AI_FIREWALL_BLOCKED',
      patterns: allPatterns,
      severity: maxSeverity,
      message:  'The request contains patterns identified as potential prompt injection attacks.',
    });
  }

  // Attach taint tracking context to request
  req.aiContext = { _taint: { level: 'clean', sources: [], timestamp: new Date().toISOString() } };

  // Mark external-source requests as tainted
  const externalSource = body.source_url || body.external_url || body.url;
  if (externalSource) {
    taintPropagate(req.aiContext, 'medium', `external_url:${externalSource}`);
  }

  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 6: Tool Allow-List + Agent Permission Enforcement
// ─────────────────────────────────────────────────────────────────────────────

/** Approved tools per agent role */
const TOOL_ALLOWLISTS = {
  analyst:   ['search', 'enrich', 'ioc_lookup', 'threat_intel', 'explain', 'summarize', 'report'],
  responder: ['search', 'enrich', 'ioc_lookup', 'block_ip', 'isolate_host', 'create_case', 'close_alert'],
  hunter:    ['search', 'enrich', 'ioc_lookup', 'sigma_search', 'graph_query', 'yara_scan'],
  admin:     null, // null = all tools permitted
};

/** Approved models per environment */
const MODEL_ALLOWLIST = new Set([
  'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4',
  'gpt-3.5-turbo', 'gpt-3.5-turbo-16k',
  'claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307',
  'gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash',
  'deepseek-chat', 'deepseek-reasoner',
  'qwen3:8b', 'llama3:8b', // local models
]);

/**
 * guardTool — verify an agent is permitted to use a tool.
 * @param {string} toolName
 * @param {string} agentRole
 * @returns {{ allowed: boolean, reason: string }}
 */
function guardTool(toolName, agentRole = 'analyst') {
  const list = TOOL_ALLOWLISTS[agentRole];
  if (list === null) return { allowed: true, reason: 'admin_all_tools' };
  if (!list) return { allowed: false, reason: `unknown_role:${agentRole}` };
  if (list.includes(toolName)) return { allowed: true, reason: 'allowlisted' };
  return { allowed: false, reason: `tool_not_in_allowlist_for_role:${agentRole}` };
}

/**
 * guardModel — verify model is on the approved list.
 * @param {string} modelId
 * @returns {{ allowed: boolean }}
 */
function guardModel(modelId) {
  return { allowed: MODEL_ALLOWLIST.has(modelId) };
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  // Layer 1
  guardInput,
  // Layer 2
  wrapUntrusted,
  // Layer 3
  taintPropagate,
  isTainted,
  // Layer 4
  guardOutput,
  // Layer 5
  aiFirewallMiddleware,
  // Layer 6
  guardTool,
  guardModel,
  // Constants (for testing)
  INJECTION_PATTERNS,
  PII_PATTERNS,
  OUTPUT_ANOMALY_PATTERNS,
  MODEL_ALLOWLIST,
  TOOL_ALLOWLISTS,
};
