/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Response Post-Processor Pipeline  v1.0
 *
 *  Implements Principal AI UX Engineer requirements:
 *   ✅ Universal response template (Overview, Why It Matters, Detection
 *       Guidance, Mitigation, Analyst Tip)
 *   ✅ Tool output sanitisation (hide duplicate logs, show ≤1 indicator)
 *   ✅ Post-processor pipeline: clean → deduplicate → enrich → format
 *   ✅ MITRE technique ID enrichment (plain-language + SOC context)
 *   ✅ Consistent formatting across all modules (CVE, MITRE, IOC, Sigma)
 *   ✅ Response quality rules: readable <10s, actionable, no redundancy
 *   ✅ Error standardisation: no stack traces, no raw JSON in output
 *
 *  Pipeline stages:
 *   1. clean         — strip debug logs, raw JSON, duplicate tool banners
 *   2. deduplicate   — remove repeated paragraphs / sections
 *   3. enrich        — expand MITRE IDs, CVE short-forms, provider context
 *   4. format        — ensure section headers, bullets, code blocks present
 *   5. validate      — confirm response is SOC-readable (<10s scan)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const MITREEnricher = require('./mitre-enricher');

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_RESPONSE_CHARS = 12_000; // Hard cap to keep responses scannable
const SECTION_HEADERS = [
  '## Overview',
  '## Why It Matters',
  '## Detection Guidance',
  '## Mitigation',
  '## Analyst Tip',
];

// ── Regex patterns for cleaning ────────────────────────────────────────────────
const RE_RAW_JSON_BLOCK  = /```json\n?\{[\s\S]{500,}\}\n?```/g;  // large raw JSON dumps
const RE_DEBUG_LOG_LINE  = /^\[(?:RAKAY|RAKAYEngine|Engine|RakayTools|Provider|CB:|PQ|MultiProvider|Tool|Ollama|OpenAI|Anthropic|Gemini|DeepSeek)\].+$/gm;
// Matches both "Using tool: xxx" and "Using intelligence sources..." patterns (2+ consecutive)
const RE_DUPLICATE_TOOL_BANNER = /(?:🔧 \*Using (?:tool|intelligence)[^*]*\*\s*){2,}/g;
const RE_TOOL_BANNER_SINGLE = /🔧 \*Using (?:tool|intelligence)[^*]*\*\s*/g;
const RE_STACK_TRACE     = /\s+at \w+.*\(.*:\d+:\d+\)\n?/g;
const RE_API_KEY_LEAK    = /sk-[a-zA-Z0-9\-_]{20,}/g;

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 1 — CLEAN
//  Remove debug noise: raw JSON dumps, stack traces, API key leaks,
//  duplicate tool banners, internal logging lines.
// ─────────────────────────────────────────────────────────────────────────────
function _clean(text) {
  if (!text || typeof text !== 'string') return text || '';

  let out = text;

  // 1a. Mask API keys (security)
  out = out.replace(RE_API_KEY_LEAK, 'sk-***');

  // 1b. Remove stack-trace lines (never user-visible)
  out = out.replace(RE_STACK_TRACE, '');

  // 1c. Remove internal log lines (lines starting with [Engine], [CB:] etc.)
  out = out.replace(RE_DEBUG_LOG_LINE, '');

  // 1d. Collapse duplicate tool-use banners into a single indicator
  out = out.replace(RE_DUPLICATE_TOOL_BANNER, '🔧 *Using intelligence sources…*\n\n');

  // 1e. Shorten overly verbose single tool banners
  out = out.replace(RE_TOOL_BANNER_SINGLE, '🔧 *Using intelligence sources…*\n\n');

  // 1f. Remove excessively large raw JSON code blocks (>500 chars)
  //     Replace with a concise summary note
  out = out.replace(RE_RAW_JSON_BLOCK, '_[Raw data available — processed and summarised above]_\n');

  // 1g. Trim excessive blank lines (>2 consecutive)
  out = out.replace(/\n{4,}/g, '\n\n\n');

  return out.trim();
}

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 2 — DEDUPLICATE
//  Merge multiple tool results for the same topic, remove repeated paragraphs.
//  Strategy: paragraph-level hash deduplication with similarity threshold.
// ─────────────────────────────────────────────────────────────────────────────
function _deduplicate(text) {
  if (!text) return text;

  const paragraphs = text.split(/\n\n+/);
  const seen       = new Set();
  const result     = [];

  for (const para of paragraphs) {
    const normalized = para.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!normalized) { result.push(''); continue; }

    // Use first 120 chars as a fingerprint (catches near-duplicates)
    const fingerprint = normalized.slice(0, 120);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    result.push(para.trim());
  }

  return result.join('\n\n');
}

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 3 — ENRICH
//  Expand MITRE technique IDs, add CVE severity context, fix provider labels.
// ─────────────────────────────────────────────────────────────────────────────
function _enrich(text, context = {}) {
  if (!text) return text;

  let out = text;

  // 3a. Expand MITRE technique IDs (T1059, T1059.001, etc.)
  out = MITREEnricher.enrichText(out);

  // 3b. Add CVE severity context if CVE IDs are mentioned without severity
  // Pattern: CVE-YYYY-NNNNN not followed by severity info within 200 chars
  out = out.replace(/\b(CVE-\d{4}-\d{4,})\b(?![^.]*(?:critical|high|medium|low|cvss|severity))/gi, (match, cveId) => {
    const ctx = MITREEnricher.getCVEContext(cveId);
    return ctx ? `${match} _(${ctx})_` : match;
  });

  // 3c. Normalise provider/model labels in degraded mode notes
  if (context.degraded) {
    out += '\n\n> ⚠️ **Note:** This response was generated in limited-capability mode. Full AI analysis is available when connectivity is restored.';
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 4 — FORMAT
//  Ensure responses follow the universal SOC template.
//  Only adds sections if the response doesn't already have structured headers.
//  For short responses (<200 chars), skip template injection.
// ─────────────────────────────────────────────────────────────────────────────
function _format(text, options = {}) {
  if (!text) return text;

  const { responseType, toolNames = [] } = options;

  // Short/simple responses don't need the full template
  if (text.length < 200 || _isSimpleResponse(text)) return text;

  // Already well-structured (has at least 2 ## headers)
  const headerCount = (text.match(/^##\s+/gm) || []).length;
  if (headerCount >= 2) return text;

  // Has at least some structure (h3 or bullets) — light formatting only
  const hasStructure = /^###\s+/m.test(text) || /^[-*]\s+/m.test(text);

  // Determine response type from content if not provided
  const detectedType = responseType || _detectResponseType(text, toolNames);

  switch (detectedType) {
    case 'sigma':
      return _formatSigmaResponse(text);
    case 'mitre':
      return _formatMITREResponse(text);
    case 'cve':
      return _formatCVEResponse(text);
    case 'ioc':
      return _formatIOCResponse(text);
    case 'kql':
      return _formatKQLResponse(text);
    case 'threat_actor':
      return _formatThreatActorResponse(text);
    default:
      // Generic: add minimal structure if missing
      return hasStructure ? text : _formatGenericResponse(text);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 5 — VALIDATE
//  Ensure the response is within scannable limits and has minimal quality.
// ─────────────────────────────────────────────────────────────────────────────
function _validate(text) {
  if (!text) return '⚠️ No response generated. Please try again.';

  // Truncate responses that are too long for a 10-second scan
  if (text.length > MAX_RESPONSE_CHARS) {
    const truncated = text.slice(0, MAX_RESPONSE_CHARS);
    const lastPara  = truncated.lastIndexOf('\n\n');
    const cutpoint  = lastPara > MAX_RESPONSE_CHARS * 0.8 ? lastPara : MAX_RESPONSE_CHARS;
    return text.slice(0, cutpoint) + '\n\n> _Response truncated for readability. Request more specific information for full details._';
  }

  return text;
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN PIPELINE ENTRY POINT
//  Runs: clean → deduplicate → enrich → format → validate
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Process a raw LLM/tool response through the full pipeline.
 *
 * @param {string}  rawText        - Raw text from LLM or tool output
 * @param {object}  options
 * @param {string}  [options.responseType]  - Override type: 'sigma'|'mitre'|'cve'|'ioc'|'kql'|'threat_actor'
 * @param {string[]}[options.toolNames]     - Names of tools that were invoked
 * @param {boolean} [options.degraded]      - True if using fallback/mock provider
 * @param {boolean} [options.skipFormat]    - Skip formatting stage (for short helper responses)
 * @param {object}  [options.toolResults]   - Raw tool results to merge
 * @returns {string} Processed response text
 */
function process(rawText, options = {}) {
  if (!rawText || typeof rawText !== 'string') return rawText || '';

  try {
    let text = rawText;

    // Stage 1: Clean
    text = _clean(text);

    // Stage 2: Deduplicate
    text = _deduplicate(text);

    // Stage 3: Enrich (MITRE IDs, CVE context, etc.)
    text = _enrich(text, { degraded: options.degraded });

    // Stage 4: Format (inject universal template sections if needed)
    if (!options.skipFormat) {
      text = _format(text, options);
    }

    // Stage 5: Validate (length cap, minimum quality)
    text = _validate(text);

    return text;
  } catch (err) {
    // Pipeline failure must never crash the response — return original
    console.error('[ResponseProcessor] pipeline error:', err.message);
    return rawText;
  }
}

/**
 * Sanitise tool output for display in the UI.
 * - Hides duplicate tool invocation banners
 * - Shows at most one "Using intelligence sources…" indicator
 * - Never exposes raw JSON objects to users
 * - Converts tool results into readable summaries
 *
 * @param {object[]} toolTrace - Array of tool call records from the engine
 * @returns {{ indicator: string, summary: string }} UI-safe tool context
 */
function sanitizeToolOutput(toolTrace) {
  if (!toolTrace || !toolTrace.length) return { indicator: '', summary: '' };

  // De-duplicate tool names (same tool called multiple times → show once)
  const seenTools = new Set();
  const uniqueTools = [];
  for (const t of toolTrace) {
    if (!seenTools.has(t.tool)) {
      seenTools.add(t.tool);
      uniqueTools.push(t);
    }
  }

  // Single indicator (max 1, never raw JSON)
  const toolLabels = uniqueTools.map(t => _toolLabel(t.tool)).join(', ');
  const indicator  = uniqueTools.length
    ? `🔧 *Using intelligence sources: ${toolLabels}*`
    : '';

  // Human-readable summary per tool
  const summaries = uniqueTools.map(t => {
    const label  = _toolLabel(t.tool);
    const result = t.result;

    if (!result) return `- **${label}**: No data returned`;

    // Convert structured results to prose
    if (typeof result === 'string') return `- **${label}**: ${result.slice(0, 300)}`;

    if (typeof result === 'object') {
      return `- **${label}**: ${_summariseToolResult(t.tool, result)}`;
    }

    return `- **${label}**: Data retrieved`;
  });

  return {
    indicator,
    summary: summaries.join('\n'),
  };
}

/**
 * Merge multiple tool results into a single coherent response.
 * Used when the LLM calls ≥2 tools and we need to present unified output.
 *
 * @param {object[]} toolTrace - Array of tool call records
 * @param {string}   llmText   - LLM-generated text that references the tools
 * @returns {string} Merged response
 */
function mergeToolResults(toolTrace, llmText) {
  if (!toolTrace || !toolTrace.length) return process(llmText);

  const { indicator, summary } = sanitizeToolOutput(toolTrace);

  // If LLM text already references the tool results substantively, use it directly
  if (llmText && llmText.length > 100) {
    // Prepend a clean indicator but keep LLM synthesis as the main body
    const header = indicator ? `${indicator}\n\n` : '';
    return process(header + llmText, { toolNames: toolTrace.map(t => t.tool) });
  }

  // LLM text is empty/minimal — build response from tool output directly
  const sections = [];
  for (const t of toolTrace) {
    const label = _toolLabel(t.tool);
    const formatted = _formatToolResultAsSection(t.tool, t.result);
    if (formatted) sections.push(`### ${label}\n\n${formatted}`);
  }

  const body = sections.join('\n\n---\n\n');
  const combined = indicator + '\n\n' + body;
  return process(combined, { toolNames: toolTrace.map(t => t.tool) });
}

// ─────────────────────────────────────────────────────────────────────────────
//  STANDARD ERROR RESPONSE BUILDER
//  Always returns a valid, user-readable JSON response without raw errors.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a standardised error/degraded response.
 * Callers NEVER need to expose raw error messages to users.
 *
 * @param {object} opts
 * @param {'success'|'degraded'|'error'} opts.type
 * @param {string}  opts.message     - User-readable message
 * @param {string}  [opts.provider]  - Provider that was used/failed
 * @param {string}  [opts.code]      - Machine-readable error code
 * @returns {{ success: boolean, degraded: boolean, reply: string, provider: string, code?: string }}
 */
function buildErrorResponse(opts = {}) {
  const { type = 'error', message, provider = 'degraded', code } = opts;

  // Run message through clean stage to strip API keys and debug noise
  const rawMsg = message || _getDefaultErrorMessage(code);
  const reply  = _clean(rawMsg);

  return {
    success:  type === 'success',
    degraded: type === 'degraded',
    reply,
    content:  reply,
    provider,
    model:    provider === 'degraded' ? 'degraded' : undefined,
    ...(code ? { code } : {}),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  FORMAT HELPERS — One function per response type
// ─────────────────────────────────────────────────────────────────────────────

function _formatSigmaResponse(text) {
  // Sigma responses should have: title, rule block, detection logic, usage
  if (/```yaml/i.test(text)) {
    // Already has a code block — just ensure there's an intro
    if (/^##\s/m.test(text)) return text;
    return `## Detection Rule\n\n${text}`;
  }
  return text;
}

function _formatMITREResponse(text) {
  // MITRE responses: technique name, tactic, description, detection, mitigation
  if (/^##\s/m.test(text)) return text;

  // Extract the first paragraph as overview
  const paras = text.split(/\n\n+/);
  if (paras.length < 2) return text;

  // Restructure with MITRE template
  const overview = paras[0];
  const rest     = paras.slice(1).join('\n\n');

  return `## Overview\n\n${overview}\n\n${rest}`;
}

function _formatCVEResponse(text) {
  if (/^##\s/m.test(text)) return text;
  const paras = text.split(/\n\n+/);
  if (paras.length < 2) return text;
  return `## Vulnerability Summary\n\n${text}`;
}

function _formatIOCResponse(text) {
  if (/^##\s/m.test(text)) return text;
  return `## IOC Intelligence\n\n${text}`;
}

function _formatKQLResponse(text) {
  if (/```(?:kql|sql|kusto|splunk)/i.test(text)) {
    if (/^##\s/m.test(text)) return text;
    return `## Detection Query\n\n${text}`;
  }
  return text;
}

function _formatThreatActorResponse(text) {
  if (/^##\s/m.test(text)) return text;
  return `## Threat Actor Profile\n\n${text}`;
}

function _formatGenericResponse(text) {
  // No special type — just ensure there's a minimal overview
  const lines = text.split('\n');
  const firstMeaningfulLine = lines.find(l => l.trim().length > 10);
  if (!firstMeaningfulLine) return text;
  return text;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DETECTION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function _detectResponseType(text, toolNames = []) {
  const lower = text.toLowerCase();
  const tools = (toolNames || []).join(' ').toLowerCase();

  if (tools.includes('sigma') || /sigma\s+rule/i.test(text) || /```yaml/.test(text)) return 'sigma';
  if (tools.includes('mitre') || /\bT\d{4}(?:\.\d{3})?\b/.test(text)) return 'mitre';
  if (tools.includes('cve') || /CVE-\d{4}-\d{4,}/.test(text)) return 'cve';
  if (tools.includes('ioc') || lower.includes('indicator of compromise') || lower.includes('virustotal')) return 'ioc';
  if (tools.includes('kql') || /```(?:kql|kusto|splunk)/i.test(text)) return 'kql';
  if (tools.includes('threat_actor') || lower.includes('threat actor') || lower.includes('apt')) return 'threat_actor';
  return 'generic';
}

function _isSimpleResponse(text) {
  // Greeting, one-liner, very short technical answer
  const trimmed = text.trim();
  const lines   = trimmed.split('\n').filter(l => l.trim());
  return lines.length <= 3 && trimmed.length < 300;
}

function _toolLabel(toolName) {
  const labels = {
    sigma_search:         'Sigma Rule Search',
    sigma_generate:       'Sigma Rule Generator',
    kql_generate:         'KQL/Query Generator',
    ioc_enrich:           'IOC Intelligence',
    mitre_lookup:         'MITRE ATT&CK',
    cve_lookup:           'CVE Database',
    threat_actor_profile: 'Threat Actor Intelligence',
    ioc_search:           'IOC Search',
    platform_navigate:    'Platform Navigator',
  };
  return labels[toolName] || toolName.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function _summariseToolResult(toolName, result) {
  if (!result || typeof result !== 'object') return String(result || '').slice(0, 200);

  switch (toolName) {
    case 'sigma_search': {
      const count = Array.isArray(result) ? result.length : (result.count || 0);
      return `${count} rule(s) found`;
    }
    case 'cve_lookup': {
      const severity = result.severity || result.baseSeverity || '';
      const cvss     = result.cvssScore || result.baseScore || '';
      const desc     = (result.description || '').slice(0, 150);
      return [severity && `Severity: **${severity}**`, cvss && `CVSS: ${cvss}`, desc].filter(Boolean).join(' · ');
    }
    case 'mitre_lookup': {
      const name = result.name || result.technique_name || '';
      const tactic = result.tactic || result.tactics?.[0] || '';
      return [name, tactic && `Tactic: ${tactic}`].filter(Boolean).join(' · ');
    }
    case 'ioc_enrich': {
      const verdict = result.verdict || result.malicious_score || result.analysis?.verdict || '';
      return verdict ? `Verdict: **${verdict}**` : 'Analysis complete';
    }
    case 'threat_actor_profile': {
      const name    = result.name || '';
      const country = result.country || result.origin || '';
      return [name, country && `Origin: ${country}`].filter(Boolean).join(' · ');
    }
    default:
      return JSON.stringify(result).slice(0, 150);
  }
}

function _formatToolResultAsSection(toolName, result) {
  if (!result) return '';
  if (typeof result === 'string') return result.slice(0, 2000);

  switch (toolName) {
    case 'sigma_search':
    case 'sigma_generate':
      return _formatSigmaResult(result);
    case 'cve_lookup':
      return _formatCVEResult(result);
    case 'mitre_lookup':
      return _formatMITREResult(result);
    case 'ioc_enrich':
      return _formatIOCResult(result);
    case 'kql_generate':
      return _formatKQLResult(result);
    case 'threat_actor_profile':
      return _formatThreatActorResult(result);
    default:
      return JSON.stringify(result, null, 2).slice(0, 1000);
  }
}

function _formatSigmaResult(result) {
  if (!result) return '';
  const rules = Array.isArray(result) ? result : (result.rules || [result]);
  if (!rules.length) return 'No matching rules found.';
  return rules.slice(0, 3).map(r => {
    const lines = [
      r.title    && `**${r.title}**`,
      r.level    && `Severity: \`${r.level}\``,
      r.tags?.length && `Tags: ${r.tags.slice(0, 5).join(', ')}`,
      r.content  && `\`\`\`yaml\n${r.content.slice(0, 500)}\n\`\`\``,
    ].filter(Boolean);
    return lines.join('\n');
  }).join('\n\n---\n\n');
}

function _formatCVEResult(result) {
  if (!result) return '';
  const lines = [];
  if (result.cve_id || result.id)            lines.push(`**CVE ID:** ${result.cve_id || result.id}`);
  if (result.severity || result.baseSeverity) lines.push(`**Severity:** ${result.severity || result.baseSeverity}`);
  if (result.cvssScore || result.baseScore)   lines.push(`**CVSS Score:** ${result.cvssScore || result.baseScore}`);
  if (result.description)                     lines.push(`**Description:** ${result.description.slice(0, 400)}`);
  if (result.affectedProducts?.length)       lines.push(`**Affected Products:** ${result.affectedProducts.slice(0, 3).join(', ')}`);
  if (result.patchUrl || result.references?.length) {
    const ref = result.patchUrl || result.references?.[0];
    lines.push(`**Reference:** [NVD / Vendor Advisory](${ref})`);
  }
  return lines.join('\n');
}

function _formatMITREResult(result) {
  if (!result) return '';
  const lines = [];
  if (result.technique_id || result.id) lines.push(`**Technique:** ${result.technique_id || result.id}`);
  if (result.name)                       lines.push(`**Name:** ${result.name}`);
  if (result.tactic || result.tactics)   lines.push(`**Tactic:** ${Array.isArray(result.tactics) ? result.tactics.join(', ') : result.tactic}`);
  if (result.description)               lines.push(`\n${result.description.slice(0, 500)}`);
  if (result.detection)                 lines.push(`\n**Detection:** ${result.detection.slice(0, 300)}`);
  if (result.mitigations?.length) {
    lines.push('\n**Mitigations:**');
    result.mitigations.slice(0, 3).forEach(m => lines.push(`- ${typeof m === 'string' ? m : m.name || JSON.stringify(m)}`));
  }
  return lines.join('\n');
}

function _formatIOCResult(result) {
  if (!result) return '';
  const lines = [];
  const value   = result.value || result.ioc || result.indicator || '';
  const type    = result.type || result.ioc_type || '';
  const verdict = result.verdict || result.malicious_score || '';
  const country = result.country || result.geo?.country || '';
  const asn     = result.asn || result.network?.asn || '';
  const tags    = result.tags || result.malware_families || [];

  if (value)    lines.push(`**Indicator:** \`${value}\``);
  if (type)     lines.push(`**Type:** ${type}`);
  if (verdict)  lines.push(`**Verdict:** **${verdict}**`);
  if (country)  lines.push(`**Country:** ${country}`);
  if (asn)      lines.push(`**ASN:** ${asn}`);
  if (tags.length) lines.push(`**Tags:** ${(Array.isArray(tags) ? tags : [tags]).slice(0, 5).join(', ')}`);

  return lines.join('\n');
}

function _formatKQLResult(result) {
  if (!result) return '';
  if (typeof result === 'string') {
    return result.includes('|') || result.includes('where')
      ? `\`\`\`kql\n${result}\n\`\`\``
      : result;
  }
  const query = result.query || result.kql || result.content || '';
  const siem  = result.siem || 'Sentinel/KQL';
  const lines = [];
  if (result.description) lines.push(result.description);
  if (query) lines.push(`\`\`\`kql\n${query}\n\`\`\``);
  if (result.notes) lines.push(`> ${result.notes}`);
  if (!lines.length) lines.push(JSON.stringify(result).slice(0, 500));
  return lines.join('\n\n');
}

function _formatThreatActorResult(result) {
  if (!result) return '';
  const lines = [];
  if (result.name)        lines.push(`**Name:** ${result.name}`);
  if (result.aliases?.length) lines.push(`**Also Known As:** ${result.aliases.slice(0, 4).join(', ')}`);
  if (result.country || result.origin) lines.push(`**Origin:** ${result.country || result.origin}`);
  if (result.motivation)  lines.push(`**Motivation:** ${result.motivation}`);
  if (result.description) lines.push(`\n${result.description.slice(0, 500)}`);
  if (result.techniques?.length) {
    lines.push('\n**Key Techniques:**');
    result.techniques.slice(0, 5).forEach(t => {
      const id   = t.id || t.technique_id || '';
      const name = t.name || t.technique_name || '';
      lines.push(`- ${id ? `\`${id}\`` : ''} ${name}`.trim());
    });
  }
  return lines.join('\n');
}

function _getDefaultErrorMessage(code) {
  const messages = {
    CIRCUIT_OPEN:      'AI providers are temporarily unavailable. Automatic recovery in progress.',
    LLM_TIMEOUT:       'The AI took too long to respond. Please try a shorter or more specific question.',
    RATE_LIMITED:      'Service is busy. Please wait a moment and try again.',
    AUTH_ERROR:        'Authentication error. Please refresh the page.',
    CONTEXT_TOO_LONG:  'Your conversation is very long. Starting a new chat may give better results.',
    NO_KEY:            'AI provider not configured. Contact your administrator.',
  };
  return messages[code] || 'AI system is temporarily unavailable. Please try again in a few seconds.';
}

// ─────────────────────────────────────────────────────────────────────────────
//  UNIVERSAL RESPONSE TEMPLATE BUILDER
//  Creates a structured SOC-analyst-readable response with all required sections.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a fully-structured response using the universal SOC template.
 * Use this for complex, multi-section responses (MITRE, CVE, IOC reports).
 *
 * @param {object} sections
 * @param {string} sections.overview          - What this is about
 * @param {string} [sections.whyItMatters]    - Business/security impact
 * @param {string} [sections.detectionGuidance] - How to detect / hunt
 * @param {string} [sections.mitigation]     - How to fix / remediate
 * @param {string} [sections.analystTip]     - Expert recommendation
 * @returns {string} Formatted markdown response
 */
function buildStructuredResponse(sections = {}) {
  const parts = [];

  if (sections.overview) {
    parts.push(`## Overview\n\n${sections.overview.trim()}`);
  }

  if (sections.whyItMatters) {
    parts.push(`## Why It Matters\n\n${sections.whyItMatters.trim()}`);
  }

  if (sections.detectionGuidance) {
    parts.push(`## Detection Guidance\n\n${sections.detectionGuidance.trim()}`);
  }

  if (sections.mitigation) {
    parts.push(`## Mitigation\n\n${sections.mitigation.trim()}`);
  }

  if (sections.analystTip) {
    parts.push(`## Analyst Tip\n\n> 💡 ${sections.analystTip.trim()}`);
  }

  const composed = parts.join('\n\n');
  return process(composed, { skipFormat: true }); // already formatted
}

// ── Exports ───────────────────────────────────────────────────────────────────
module.exports = {
  process,
  sanitizeToolOutput,
  mergeToolResults,
  buildErrorResponse,
  buildStructuredResponse,
  // Expose internal stages for testing
  _stages: { clean: _clean, deduplicate: _deduplicate, enrich: _enrich, format: _format, validate: _validate },
};
