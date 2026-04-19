/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Response Post-Processor Pipeline  v2.0
 *
 *  Pipeline stages:
 *   1. clean         — strip debug logs, raw JSON, ALL tool banners
 *   2. deduplicate   — remove repeated paragraphs / sections
 *   3. enrich        — expand MITRE IDs, CVE short-forms, provider context
 *   4. format        — ensure section headers, bullets, code blocks present
 *   5. validate      — confirm response is SOC-readable (<10s scan)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

let MITREEnricher;
try { MITREEnricher = require('./mitre-enricher'); } catch(e) { MITREEnricher = null; }

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_RESPONSE_CHARS = 12_000;
const SECTION_HEADERS = [
  '## Overview',
  '## Why It Matters',
  '## Detection Guidance',
  '## Mitigation',
  '## Analyst Tip',
];

// ── Regex patterns ─────────────────────────────────────────────────────────────
// ANY size raw JSON blocks
const RE_RAW_JSON_BLOCK_LARGE = /```json\n?\{[\s\S]{300,}\}\n?```/g;
// Raw JSON outside code blocks (objects > 200 chars with typical JSON structure)
const RE_RAW_JSON_INLINE  = /\{\s*"[^"]+"\s*:\s*[\s\S]{200,}?\}/g;
// Internal debug log lines from multiple sources
const RE_DEBUG_LOG_LINE   = /^\[(?:RAKAY|RAKAYEngine|Engine|RakayTools|Provider|CB:|CB |PQ|MultiProvider|Tool|Ollama|OpenAI|Anthropic|Gemini|DeepSeek|LLM|Stream|Queue|Mutex|Session)\].+$/gm;
// ALL tool banner variants — remove completely from user-visible output
const RE_TOOL_BANNER_ALL  = /🔧\s*\*?Using (?:tool|intelligence|tools)[^*\n]*\*?\s*\n?/g;
const RE_TOOL_COLON       = /🔧\s*Using tool:\s*[^\n]+\n?/g;
// Stack traces
const RE_STACK_TRACE      = /\s+at \w+.*\(.*:\d+:\d+\)\n?/g;
// API key leaks
const RE_API_KEY_LEAK     = /sk-[a-zA-Z0-9\-_]{20,}/g;
// Demo mode messages — replace with built-in message
const RE_DEMO_MODE        = /(?:demo mode|mock mode|limited mode|fallback mode|offline mode|degraded mode)/gi;
// Limited capability note (added by old processor)
const RE_LIMITED_CAP_NOTE = />\s*⚠️\s*\*\*Note:\*\*.*limited-capability mode.*\n?/g;
// Tool result raw JSON patterns (found:false, error:false from tool calls)
const RE_TOOL_JSON_RESULT = /\{\s*"(?:error|found|tool)"\s*:\s*(?:false|true|null)[^}]{0,500}\}/g;
// Lines that are just JSON-like tool result dumps
const RE_TOOL_RESULT_LINE = /^The (?:\w+) tool (?:encountered|returned|found)[^\n]*\n?/gm;

// ─────────────────────────────────────────────────────────────────────────────
//  STAGE 1 — CLEAN
//  Remove ALL debug noise: raw JSON, stack traces, API keys, ALL tool banners.
// ─────────────────────────────────────────────────────────────────────────────
function _clean(text) {
  if (!text || typeof text !== 'string') return text || '';

  let out = text;

  // 1a. Mask API keys (security — must be first)
  out = out.replace(RE_API_KEY_LEAK, 'sk-***');

  // 1b. Remove stack-trace lines
  out = out.replace(RE_STACK_TRACE, '');

  // 1c. Remove internal debug log lines
  out = out.replace(RE_DEBUG_LOG_LINE, '');

  // 1d. Remove ALL tool-use banners completely (Task 5 — no tool spam)
  out = out.replace(RE_TOOL_BANNER_ALL, '');
  out = out.replace(RE_TOOL_COLON, '');

  // 1d2. Remove raw tool result JSON objects ({found: false, error: false, tool: "..."})
  out = out.replace(RE_TOOL_JSON_RESULT, '');
  out = out.replace(RE_TOOL_RESULT_LINE, '');

  // 1e. Replace large raw JSON code blocks with truncation marker
  out = out.replace(RE_RAW_JSON_BLOCK_LARGE, '_[json truncated]_');

  // 1f. Remove inline raw JSON objects that are too large
  // (but ONLY outside code blocks — don't touch yaml/kql/spl inside ```)
  out = _stripInlineJSON(out);

  // 1g. Replace "demo mode" / "limited mode" references
  out = out.replace(RE_DEMO_MODE, 'built-in threat intelligence');

  // 1h. Remove old "limited-capability mode" footnotes
  out = out.replace(RE_LIMITED_CAP_NOTE, '');

  // 1i. Trim excessive blank lines (>2 consecutive)
  out = out.replace(/\n{4,}/g, '\n\n\n');

  return out.trim();
}

/**
 * Strip large raw JSON objects that appear OUTSIDE of fenced code blocks.
 * Preserves Sigma/KQL/SPL content inside ``` blocks.
 */
function _stripInlineJSON(text) {
  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, i) => {
    // Even indices = outside code blocks
    if (i % 2 === 0) {
      return part.replace(/\{[\s\S]{300,}?\}/g, match => {
        // Only strip if it looks like JSON (has "key": pattern)
        if (/"[^"]+"\s*:/.test(match)) return '';
        return match;
      });
    }
    return part; // Leave code blocks untouched
  }).join('');
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

  // 3a. Expand MITRE technique IDs (T1059, T1059.001, etc.) — safe fallback if enricher unavailable
  if (MITREEnricher && typeof MITREEnricher.enrichText === 'function') {
    try { out = MITREEnricher.enrichText(out); } catch(e) { /* skip enrichment */ }
  }

  // 3b. Add CVE severity context if CVE IDs are mentioned without severity
  if (MITREEnricher && typeof MITREEnricher.getCVEContext === 'function') {
    out = out.replace(/\b(CVE-\d{4}-\d{4,})\b(?![^.]*(?:critical|high|medium|low|cvss|severity))/gi, (match, cveId) => {
      try {
        const ctx = MITREEnricher.getCVEContext(cveId);
        return ctx ? `${match} _(${ctx})_` : match;
      } catch(e) { return match; }
    });
  }

  // 3c. Degraded mode: show ⚠️ indicator and add limited-capability note
  //     The fallback functions already prepend "⚠️ Using built-in threat intelligence"
  //     so we only add a minimal note if the response doesn't already have one
  if (context.degraded) {
    if (!out.includes('⚠️')) {
      out = `⚠️ Using built-in threat intelligence\n\n${out}`;
    }
    // Add limited-capability mode note if not already present
    if (!out.includes('limited-capability mode')) {
      // ROOT-CAUSE FIX: Removed 'Set API key' call-to-action. Local mode is fully functional.
      // The note was misleading — it appeared even when API keys ARE set but provider had an error.
    }
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
 * Produces a structured 5-section SOC response from tool output.
 *
 * @param {object[]} toolTrace - Array of tool call records
 * @param {string}   llmText   - LLM-generated text that references the tools
 * @returns {string} Merged response in 5-section format
 */
function mergeToolResults(toolTrace, llmText) {
  if (!toolTrace || !toolTrace.length) return process(llmText);

  // Filter out empty/error tool results (found:false, no meaningful content)
  const validTrace = toolTrace.filter(t => {
    if (!t.result) return false;
    if (typeof t.result === 'object') {
      // Skip results that are just {found: false, error: false, ...}
      if (t.result.found === false && t.result.error === false) return false;
      // Skip empty results
      const keys = Object.keys(t.result);
      if (keys.length === 0) return false;
    }
    if (typeof t.result === 'string' && t.result.trim().length < 10) return false;
    return true;
  });

  // If LLM text already contains rich structured content (>=2 ## headers), keep it
  if (llmText && llmText.length > 200) {
    const headerCount = (llmText.match(/^##\s+/gm) || []).length;
    if (headerCount >= 2) {
      return process(llmText, { toolNames: toolTrace.map(t => t.tool) });
    }
  }

  // If LLM text is substantive but not structured, use it with minimal cleanup
  if (llmText && llmText.length > 100) {
    return process(llmText, { toolNames: toolTrace.map(t => t.tool) });
  }

  // Build structured 5-section response from tool results
  if (validTrace.length === 0) {
    // All tools returned empty/not-found — provide a helpful message
    return process(llmText || '⚠️ Using built-in threat intelligence\n\nNo matching intelligence found in the local database for your query. Try a more specific CVE ID, MITRE technique (e.g., T1059.001), or threat scenario.', {});
  }

  const sections = [];

  // Build the overview from the primary tool result
  const primaryTool = validTrace[0];
  const primaryFormatted = _formatToolResultAsSection(primaryTool.tool, primaryTool.result);
  if (primaryFormatted) {
    sections.push(primaryFormatted);
  }

  // Add additional tool results
  for (const t of validTrace.slice(1)) {
    const label = _toolLabel(t.tool);
    const formatted = _formatToolResultAsSection(t.tool, t.result);
    if (formatted) sections.push(`---\n\n### Additional: ${label}\n\n${formatted}`);
  }

  const body = sections.join('\n\n');
  return process(body, { toolNames: toolTrace.map(t => t.tool) });
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

  // If the result already has pre-formatted content (from _formatted field), use it
  if (result._formatted && typeof result._formatted === 'string') {
    return result._formatted.slice(0, 4000);
  }

  if (typeof result === 'string') return result.slice(0, 3000);

  // Skip empty/not-found results
  if (result.found === false || result.error === true) {
    if (result.message) return `> ${result.message}`;
    return '';
  }

  switch (toolName) {
    case 'sigma_search':
    case 'sigma_generate':
      return _formatSigmaResult(result);
    case 'cve_lookup':
      return _formatCVEResult5Section(result);
    case 'mitre_lookup':
      return _formatMITREResult5Section(result);
    case 'ioc_enrich':
      return _formatIOCResult(result);
    case 'kql_generate':
      return _formatKQLResult5Section(result);
    case 'threat_actor_profile':
      return _formatThreatActorResult5Section(result);
    default:
      // For unknown tools, try to create basic readable output
      const str = JSON.stringify(result, null, 2);
      if (str.length < 200) return str;
      return '> Intelligence data retrieved. See analyst response for details.';
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

// ─────────────────────────────────────────────────────────────────────────────
//  5-SECTION FORMAT FUNCTIONS
//  Produce structured SOC-analyst responses in the universal template:
//  Overview → Why It Matters → Detection Guidance → Mitigation → Analyst Tip
// ─────────────────────────────────────────────────────────────────────────────

function _formatCVEResult5Section(result) {
  if (!result) return '';
  const id       = result.id || result.cve_id || 'Unknown CVE';
  const severity = (result.severity || result.baseSeverity || 'UNKNOWN').toUpperCase();
  const cvss     = result.cvss_score || result.cvssScore || result.baseScore || '';
  const desc     = result.description || '';
  const vendor   = result.vendor || '';
  const product  = result.product || '';
  const exploited = result.exploited;
  const refs     = result.references || result.nvd_url ? [result.nvd_url || `https://nvd.nist.gov/vuln/detail/${id}`] : [];
  const mitigation = result.mitigation || '';
  const detection_hint = result.detection_hint || '';
  const published = result.published_date || result.published || '';

  const severityEmoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[severity] || '⚪';
  const exploitedBadge = exploited ? ' **🔴 EXPLOITED IN THE WILD**' : '';

  const parts = [];

  // Overview
  parts.push(`## Overview\n\n**${id}** — ${severityEmoji} **${severity}** (CVSS ${cvss})${exploitedBadge}\n\n${desc ? desc.slice(0, 500) : 'No description available.'}`);
  if (vendor || product) parts[0] += `\n\n**Affected:** ${[vendor, product].filter(Boolean).join(' ')}${published ? ` · Published: ${published}` : ''}`;

  // Why It Matters
  const whyMap = {
    CRITICAL: `This is a **critical severity** vulnerability. Exploitation can lead to full system compromise, unauthenticated remote code execution, or large-scale data breaches. ${exploited ? 'This CVE is actively exploited in the wild — immediate action required.' : 'Prioritise patching immediately.'}`,
    HIGH:     `This **high severity** vulnerability represents significant risk. Exploitation may allow privilege escalation, remote code execution, or unauthorised data access. ${exploited ? 'Active exploitation has been observed.' : 'Patch within 72 hours.'}`,
    MEDIUM:   'This **medium severity** vulnerability requires conditions to exploit (e.g., authenticated access). Monitor and patch within 30 days.',
    LOW:      'This **low severity** vulnerability has limited direct impact. Include in next scheduled maintenance cycle.',
  };
  parts.push(`## Why It Matters\n\n${whyMap[severity] || 'Review this vulnerability and apply available patches.'}`);

  // Detection Guidance
  let detection = detection_hint
    ? `Monitor your environment for exploitation indicators:\n\n- ${detection_hint}\n- Check SIEM for unusual activity related to ${product || 'affected systems'}\n- Review IDS/WAF logs for attack signatures`
    : `Search your SIEM and security tools for exploitation indicators:\n- Unusual authentication failures or privilege escalation events\n- Unexpected process creation from affected services\n- Network connections to/from suspicious IPs after exploitation window`;
  if (exploited) {
    detection += `\n\n> **Check CISA KEV:** This CVE is in the CISA Known Exploited Vulnerabilities catalog — active exploitation is confirmed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog`;
  }
  parts.push(`## Detection Guidance\n\n${detection}`);

  // Mitigation
  const mit = mitigation || `1. Apply the vendor-provided security patch immediately\n2. Identify all affected ${product || 'systems'} in your asset inventory\n3. Monitor for exploitation indicators in SIEM\n4. Apply compensating controls if patching is not immediately possible`;
  const urgencyPrefix = severity === 'CRITICAL' ? '🔴 **IMMEDIATE ACTION REQUIRED** — ' : severity === 'HIGH' ? '🟠 **Patch within 72 hours** — ' : '';
  parts.push(`## Mitigation\n\n${urgencyPrefix}${mit}`);

  // Analyst Tip
  const refLink = refs.length ? refs[0] : `https://nvd.nist.gov/vuln/detail/${id}`;
  parts.push(`## Analyst Tip\n\n> 💡 **Reference:** [NVD — ${id}](${refLink})\n> \n> Use the CVSS vector to understand the attack surface: access vector, complexity, privileges required, and user interaction. For exploited CVEs, cross-reference with threat actor TTPs — many APT groups weaponise these within days of public disclosure.`);

  return parts.join('\n\n');
}

function _formatMITREResult5Section(result) {
  if (!result) return '';

  // Use _formatted if available (from MITREEnricher)
  if (result._formatted) return result._formatted;

  const id       = result.id || '';
  const name     = result.name || id;
  const tactics  = Array.isArray(result.tactic) ? result.tactic : [result.tactic || 'Unknown'].filter(Boolean);
  const severity = result.severity || 'HIGH';
  const desc     = result.description || '';
  const detection = result.detection || '';
  const mits     = result.mitigations || [];
  const soc      = result.soc_context || '';
  const url      = result.url || (id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : '');

  const tacticDisplay = tactics.map(t => t.charAt(0).toUpperCase() + t.slice(1)).join(', ');
  const severityEmoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[severity.toUpperCase()] || '🟠';

  const parts = [];

  // Overview
  parts.push(`## Overview\n\n**MITRE ATT&CK** — **${id ? `[${id}](${url})` : name}** — ${name}\n\n**Tactic:** ${tacticDisplay} · **Severity:** ${severityEmoji} ${severity.toUpperCase()}\n\n${desc.slice(0, 600)}`);

  // Why It Matters
  const whyText = soc || `**${name}** is a ${severity.toLowerCase()}-severity technique used by adversaries during the **${tacticDisplay}** phase of an attack. Detection at this stage prevents further compromise and limits the blast radius of an intrusion. This technique appears in numerous real-world incidents by APT groups and ransomware operators.`;
  parts.push(`## Why It Matters\n\n${whyText}`);

  // Detection Guidance
  const detText = detection || 'Monitor process execution, command-line parameters, script execution events, and network activity associated with this technique. Correlate with parent process relationships.';
  parts.push(`## Detection Guidance\n\n${detText}`);

  // Mitigation
  if (mits.length) {
    const mitList = mits.slice(0, 5).map(m => `- ${typeof m === 'string' ? m : (m.name || JSON.stringify(m))}`).join('\n');
    parts.push(`## Mitigation\n\n${mitList}`);
  } else {
    parts.push(`## Mitigation\n\n- Apply least-privilege principles\n- Enable comprehensive logging and monitoring\n- Deploy EDR with behavioral detection for this technique\n- Patch affected systems and disable unnecessary features`);
  }

  // Analyst Tip
  const tip = url
    ? `> 💡 Open the **ATT&CK Navigator** to visualise your coverage against this technique: ${url}\n> \n> Cross-reference with your EDR/SIEM to identify which hosts and users triggered related alerts in the past 30 days.`
    : `> 💡 Use your SIEM to search for indicators related to this technique. Build a detection hypothesis and test it against known-good baseline activity to tune false positives.`;
  parts.push(`## Analyst Tip\n\n${tip}`);

  return parts.join('\n\n');
}

function _formatKQLResult5Section(result) {
  if (!result) return '';
  if (typeof result === 'string') return result;

  const query       = result.query || result.kql || result.content || '';
  const siem        = result.siem || 'kql';
  const scenario    = result.scenario || '';
  const description = result.description || '';
  const technique   = result.technique || '';
  const notes       = result.notes || '';

  const siemLabel = {
    kql: 'Microsoft Sentinel / Defender XDR (KQL)',
    splunk_spl: 'Splunk (SPL)',
    elastic_lucene: 'Elastic SIEM (Lucene)',
    qradar_aql: 'QRadar (AQL)',
  }[siem] || siem;

  const codeBlock = siem === 'splunk_spl' ? 'splunk' : siem === 'elastic_lucene' ? 'elasticsearch' : 'kql';

  if (!query) return description || 'No query content generated.';

  const parts = [];

  parts.push(`## Overview\n\n**Detection Query** for: ${scenario || description || 'Security Event Detection'}${technique && technique !== 'N/A' ? ` · Technique: \`${technique}\`` : ''}\n\n**Target SIEM:** ${siemLabel}`);

  parts.push(`## Why It Matters\n\n${description || `This query detects ${scenario || 'suspicious security events'} in your SIEM environment. Deploy it as a scheduled alert rule to surface threats in real time.`}`);

  parts.push(`## Detection Guidance\n\n### ${siemLabel}\n\n\`\`\`${codeBlock}\n${query}\n\`\`\``);

  parts.push(`## Mitigation\n\n1. Deploy this query as a **scheduled analytics rule** (run every 5-15 minutes)\n2. Set alert threshold appropriate for your environment\n3. Route alerts to your SOC ticketing system\n4. Tune false positives by adding exclusions for known-good processes/IPs`);

  const analystNote = notes || 'Test this query against historical data before enabling as a live alert. Adjust time windows and thresholds based on your environment baseline.';
  parts.push(`## Analyst Tip\n\n> 💡 ${analystNote}${technique && technique !== 'N/A' ? `\n> \n> Full ATT&CK technique details: https://attack.mitre.org/techniques/${technique.replace('.', '/')}/` : ''}`);

  return parts.join('\n\n');
}

function _formatThreatActorResult5Section(result) {
  if (!result) return '';
  if (result.found === false) return result.message || 'Threat actor not found in local database.';

  const name     = result.name || '';
  const aliases  = result.aliases || [];
  const origin   = result.origin || result.country || '';
  const sponsor  = result.sponsor || '';
  const motivation = Array.isArray(result.motivation) ? result.motivation.join(', ') : (result.motivation || '');
  const targets  = Array.isArray(result.targets) ? result.targets : [];
  const ttps     = Array.isArray(result.ttps) ? result.ttps : [];
  const tools_list = Array.isArray(result.tools) ? result.tools : [];
  const campaigns = Array.isArray(result.notable_campaigns) ? result.notable_campaigns : [];
  const desc     = result.description || '';

  const parts = [];

  // Overview
  let overview = `## Overview\n\n**${name}**`;
  if (aliases.length) overview += ` _(${aliases.slice(0, 3).join(', ')})_`;
  overview += `\n\n**Origin:** ${origin}${sponsor ? ` · **Sponsor:** ${sponsor}` : ''} · **Motivation:** ${motivation}`;
  if (desc) overview += `\n\n${desc.slice(0, 500)}`;
  parts.push(overview);

  // Why It Matters
  const whyText = `**${name}** represents a ${motivation.toLowerCase().includes('espionage') ? 'nation-state espionage' : motivation.toLowerCase().includes('financial') ? 'financially-motivated' : 'sophisticated'} threat. Primary targets include: ${targets.slice(0, 4).join(', ')}${campaigns.length ? `. **Recent campaigns:** ${campaigns.slice(0, 3).join(', ')}` : ''}.`;
  parts.push(`## Why It Matters\n\n${whyText}`);

  // Detection Guidance
  const detLines = [];
  if (ttps.length) {
    detLines.push('**Key MITRE ATT&CK Techniques:**');
    ttps.slice(0, 6).forEach(t => detLines.push(`- \`${t}\` — [ATT&CK Reference](https://attack.mitre.org/techniques/${t.replace('.', '/')})`));
  }
  if (tools_list.length) {
    detLines.push(`\n**Known Tools:** ${tools_list.slice(0, 5).join(', ')}`);
  }
  detLines.push('\n**Detection Approach:**\n- Monitor for TTPs listed above in your SIEM\n- Create threat actor-specific threat hunting hypotheses\n- Subscribe to threat intel feeds tracking this group');
  parts.push(`## Detection Guidance\n\n${detLines.join('\n')}`);

  // Mitigation
  parts.push(`## Mitigation\n\n- Apply MFA across all remote access and identity providers\n- Monitor privileged account usage for anomalies\n- Enable email security with sandboxing (primary initial access vector)\n- Network segmentation to limit lateral movement post-compromise\n- Implement privileged access workstations (PAWs) for admin tasks`);

  // Analyst Tip
  parts.push(`## Analyst Tip\n\n> 💡 Review MITRE's threat actor page for ${name}: https://attack.mitre.org/groups/\n> \n> Cross-reference your recent alerts against the TTPs listed above. Enrich suspicious IPs/domains against known ${name} infrastructure using threat intel feeds.`);

  return parts.join('\n\n');
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
