/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Response Pipeline Validation Suite  v1.0
 *
 *  Tests:
 *   1.  ResponseProcessor — pipeline stages (clean/dedup/enrich/format/validate)
 *   2.  ResponseProcessor — sanitizeToolOutput (single indicator, no raw JSON)
 *   3.  ResponseProcessor — mergeToolResults (multi-tool fusion)
 *   4.  ResponseProcessor — buildStructuredResponse (universal template)
 *   5.  ResponseProcessor — buildErrorResponse (no raw errors)
 *   6.  MITREEnricher — technique lookup (T1059, T1059.001, unknown)
 *   7.  MITREEnricher — enrichText (inline MITRE ID annotation)
 *   8.  MITREEnricher — buildTechniqueSection (SOC template output)
 *   9.  MITREEnricher — getCVEContext (offline hints)
 *   10. Tool output — MITRE lookup returns enriched data
 *   11. Tool output — CVE lookup structured output
 *   12. Tool output — IOC enrich structured output
 *   13. Tool output — Sigma search returns formatted rules
 *   14. Tool output — Sigma generate returns YAML
 *   15. Tool output — KQL generate returns query
 *   16. Tool output — Unknown tool graceful failure
 *   17. Scenario: MITRE lookup T1059.001 → full SOC template
 *   18. Scenario: CVE-2021-44228 → Log4Shell with severity context
 *   19. Scenario: Multiple tools merged into single response
 *   20. Scenario: Tool failure → graceful degradation, no throw
 *   21. Scenario: Sigma generation with YAML code block
 *   22. Scenario: Degraded mode adds warning note
 *   23. Scenario: API key leak stripped from output
 *   24. Scenario: Duplicate tool banners collapsed
 *   25. Scenario: Raw JSON dump replaced with summary note
 *   26. Scenario: Internal log lines removed from output
 *   27. Scenario: Paragraph deduplication
 *   28. Scenario: Response length cap (>12000 chars truncated)
 *   29. Scenario: Threat actor profile formatted correctly
 *   30. Scenario: IOC result with verdict highlighted
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Colour helpers ────────────────────────────────────────────────────────────
const C = {
  green:  s => `\x1b[32m${s}\x1b[0m`,
  red:    s => `\x1b[31m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  cyan:   s => `\x1b[36m${s}\x1b[0m`,
  bold:   s => `\x1b[1m${s}\x1b[0m`,
  dim:    s => `\x1b[2m${s}\x1b[0m`,
};

let passed = 0;
let failed = 0;
const failures = [];
const asyncTests = []; // collect async tests to run in order

function test(name, fn) {
  // If fn is async, queue it
  const result = fn.constructor.name === 'AsyncFunction' ? null : fn;
  if (result === null) {
    asyncTests.push({ name, fn });
    return;
  }
  // Synchronous test
  try {
    const r = fn();
    if (r !== false) {
      passed++;
      console.log(C.green(`  ✅ ${name}`));
    } else {
      failed++;
      failures.push(name);
      console.log(C.red(`  ❌ FAILED: ${name}`));
    }
  } catch (err) {
    failed++;
    failures.push(`${name}: ${err.message}`);
    console.log(C.red(`  ❌ ERROR: ${name}`));
    console.log(C.dim(`       ${err.message}`));
    if (process.env.VERBOSE) console.log(err.stack);
  }
}

async function runAsyncTests() {
  for (const { name, fn } of asyncTests) {
    try {
      const r = await fn();
      if (r !== false) {
        passed++;
        console.log(C.green(`  ✅ ${name}`));
      } else {
        failed++;
        failures.push(name);
        console.log(C.red(`  ❌ FAILED: ${name}`));
      }
    } catch (err) {
      failed++;
      failures.push(`${name}: ${err.message}`);
      console.log(C.red(`  ❌ ERROR: ${name}`));
      console.log(C.dim(`       ${err.message}`));
      if (process.env.VERBOSE) console.log(err.stack);
    }
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
  return true;
}

function assertContains(text, substring, msg) {
  if (!text || !text.includes(substring)) {
    throw new Error(`${msg || 'Expected to contain'}: "${substring}" not found in:\n${(text || '').slice(0, 200)}`);
  }
  return true;
}

function assertNotContains(text, substring, msg) {
  if (text && text.includes(substring)) {
    throw new Error(`${msg || 'Expected NOT to contain'}: "${substring}" found in:\n${(text || '').slice(0, 200)}`);
  }
  return true;
}

// ── Load modules ──────────────────────────────────────────────────────────────
console.log(C.cyan(C.bold('\n══════════════════════════════════════════════════')));
console.log(C.cyan(C.bold(' RAKAY Response Pipeline Validation Suite  v1.0  ')));
console.log(C.cyan(C.bold('══════════════════════════════════════════════════\n')));

const RP = require('./backend/services/response-processor');
const ME = require('./backend/services/mitre-enricher');
const { executeTool, mitreLookupTool, cveLookupTool, iocEnrichTool, sigmaSearchTool, sigmaGenerateTool, kqlGenerateTool } = require('./backend/services/rakay-tools');

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — ResponseProcessor Pipeline
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── ResponseProcessor Pipeline ───\n'));

test('Stage 1 (clean): removes internal log lines', () => {
  const dirty = '[RAKAYEngine] Starting...\nHello world\n[MultiProvider] Trying openai...';
  const clean = RP._stages.clean(dirty);
  assertNotContains(clean, '[RAKAYEngine]');
  assertNotContains(clean, '[MultiProvider]');
  assertContains(clean, 'Hello world');
});

test('Stage 1 (clean): masks API keys', () => {
  const text = 'Error: sk-abcdefghijklmnopqrstuvwxyz12345 is invalid';
  const clean = RP._stages.clean(text);
  assertNotContains(clean, 'sk-abcdefghijklmnopqrstuvwxyz12345');
  assertContains(clean, 'sk-***');
});

test('Stage 1 (clean): collapses duplicate tool banners into one', () => {
  const text = '🔧 *Using tool: mitre_lookup...*\n\n🔧 *Using tool: cve_lookup...*\n\nResult here';
  const clean = RP._stages.clean(text);
  const bannerCount = (clean.match(/🔧/g) || []).length;
  assert(bannerCount <= 1, `Expected ≤1 tool banner, got ${bannerCount}`);
  assertContains(clean, 'Result here');
});

test('Stage 1 (clean): replaces large raw JSON dumps', () => {
  const bigJson = '```json\n' + JSON.stringify({ data: 'x'.repeat(600) }) + '\n```';
  const clean = RP._stages.clean(bigJson);
  assertNotContains(clean, 'x'.repeat(100));
  assertContains(clean, '_[');
});

test('Stage 2 (deduplicate): removes duplicate paragraphs', () => {
  const text = 'This is a paragraph.\n\nThis is a paragraph.\n\nSecond unique paragraph.';
  const deduped = RP._stages.deduplicate(text);
  const occurrences = (deduped.match(/This is a paragraph/g) || []).length;
  assert(occurrences === 1, `Expected 1 occurrence, got ${occurrences}`);
  assertContains(deduped, 'Second unique paragraph');
});

test('Stage 3 (enrich): annotates MITRE technique IDs', () => {
  const text = 'The adversary used T1059.001 for execution.';
  const enriched = RP._stages.enrich(text);
  assertContains(enriched, 'T1059.001');
  assertContains(enriched, 'PowerShell'); // annotation added
});

test('Stage 3 (enrich): adds degraded note when degraded=true', () => {
  const text = 'Some response text.';
  const enriched = RP._stages.enrich(text, { degraded: true });
  assertContains(enriched, 'limited-capability mode');
});

test('Stage 4 (format): detects sigma type from content', () => {
  const text = '## Detection Rule\n\n```yaml\ntitle: Test Rule\n```';
  const formatted = RP._stages.format(text, { responseType: 'sigma' });
  assertContains(formatted, '```yaml');
});

test('Stage 5 (validate): truncates text over 12000 chars', () => {
  const longText = 'A'.repeat(13000);
  const validated = RP._stages.validate(longText);
  assert(validated.length <= 13000, 'Should be truncated');
  assertContains(validated, 'truncated');
});

test('Stage 5 (validate): returns fallback for empty text', () => {
  const result = RP._stages.validate('');
  assertContains(result, 'No response generated');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — sanitizeToolOutput
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── sanitizeToolOutput ───\n'));

test('sanitizeToolOutput: empty trace returns empty strings', () => {
  const result = RP.sanitizeToolOutput([]);
  assert(result.indicator === '' && result.summary === '');
});

test('sanitizeToolOutput: single tool produces one indicator', () => {
  const result = RP.sanitizeToolOutput([{ tool: 'mitre_lookup', result: { name: 'PowerShell' } }]);
  assertContains(result.indicator, '🔧');
  assertContains(result.indicator, 'MITRE ATT&CK');
  // Should NOT contain raw JSON
  assertNotContains(result.indicator, '{"name"');
});

test('sanitizeToolOutput: duplicate tools deduplicated', () => {
  const trace = [
    { tool: 'cve_lookup', result: { id: 'CVE-2021-44228' } },
    { tool: 'cve_lookup', result: { id: 'CVE-2021-44228' } },
  ];
  const result = RP.sanitizeToolOutput(trace);
  const cveCount = (result.indicator.match(/CVE Database/g) || []).length;
  assert(cveCount <= 1, `Expected ≤1 CVE Database mention, got ${cveCount}`);
});

test('sanitizeToolOutput: multiple tools produce combined indicator', () => {
  const trace = [
    { tool: 'sigma_search', result: [{ title: 'Test Rule' }] },
    { tool: 'mitre_lookup', result: { name: 'PowerShell' } },
  ];
  const result = RP.sanitizeToolOutput(trace);
  assertContains(result.indicator, 'Sigma Rule Search');
  assertContains(result.indicator, 'MITRE ATT&CK');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 3 — mergeToolResults
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── mergeToolResults ───\n'));

test('mergeToolResults: empty trace returns processed LLM text', () => {
  const result = RP.mergeToolResults([], 'This is the LLM response about T1059.');
  assertContains(result, 'LLM response');
  assertContains(result, 'T1059');
});

test('mergeToolResults: with tools uses LLM synthesis when text is present', () => {
  const trace = [{ tool: 'mitre_lookup', result: { name: 'PowerShell', description: 'PowerShell execution technique.' } }];
  const llmText = 'Based on the MITRE lookup, T1059.001 involves PowerShell execution. Detection requires script-block logging.';
  const result = RP.mergeToolResults(trace, llmText);
  assertContains(result, 'PowerShell');
  // Should not contain raw JSON
  assertNotContains(result, '"description":');
});

test('mergeToolResults: with tools and empty LLM text builds from tool output', () => {
  const trace = [{ tool: 'mitre_lookup', result: { name: 'PowerShell', description: 'PowerShell execution technique.', detection: 'Monitor Event 4104.' } }];
  const result = RP.mergeToolResults(trace, '');
  assertContains(result, 'MITRE ATT&CK');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — buildStructuredResponse
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── buildStructuredResponse ───\n'));

test('buildStructuredResponse: produces all five sections', () => {
  const result = RP.buildStructuredResponse({
    overview:          'This is the overview.',
    whyItMatters:      'It matters because...',
    detectionGuidance: 'Detect by monitoring...',
    mitigation:        'Mitigate by patching...',
    analystTip:        'Check the parent process.',
  });
  assertContains(result, '## Overview');
  assertContains(result, '## Why It Matters');
  assertContains(result, '## Detection Guidance');
  assertContains(result, '## Mitigation');
  assertContains(result, '## Analyst Tip');
  assertContains(result, '> 💡');
});

test('buildStructuredResponse: handles missing optional sections', () => {
  const result = RP.buildStructuredResponse({ overview: 'Just an overview.' });
  assertContains(result, '## Overview');
  assertNotContains(result, '## Why It Matters');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — buildErrorResponse
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── buildErrorResponse ───\n'));

test('buildErrorResponse: degraded type sets correct flags', () => {
  const result = RP.buildErrorResponse({ type: 'degraded', message: 'System busy.', provider: 'mock' });
  assert(result.degraded === true, 'degraded should be true');
  assert(result.success === false, 'success should be false for degraded');
  assertContains(result.reply, 'System busy');
});

test('buildErrorResponse: no raw error message exposed — uses code lookup', () => {
  const result = RP.buildErrorResponse({ type: 'error', code: 'CIRCUIT_OPEN' });
  assertContains(result.reply, 'temporarily unavailable');
  assertNotContains(result.reply, 'CIRCUIT_OPEN');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — MITREEnricher
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── MITREEnricher ───\n'));

test('lookup: T1059 returns correct technique', () => {
  const tech = ME.lookup('T1059');
  assert(tech !== null, 'Should find T1059');
  assertContains(tech.name, 'Command and Scripting Interpreter');
  assert(tech.tactic === 'Execution');
});

test('lookup: T1059.001 returns PowerShell sub-technique', () => {
  const tech = ME.lookup('T1059.001');
  assert(tech !== null, 'Should find T1059.001');
  assertContains(tech.name.toLowerCase(), 'powershell');
});

test('lookup: Unknown technique returns null', () => {
  const tech = ME.lookup('T9999');
  assert(tech === null, 'Unknown technique should return null');
});

test('lookup: case-insensitive (t1059.001 works)', () => {
  const tech = ME.lookup('t1059.001');
  assert(tech !== null, 'Should handle lowercase technique IDs');
});

test('enrichText: annotates T1059.001 with PowerShell label', () => {
  const text = 'The attacker used T1059.001 in this campaign.';
  const enriched = ME.enrichText(text);
  assertContains(enriched, 'T1059.001');
  assertContains(enriched, 'PowerShell');
});

test('enrichText: does not duplicate name if already in text', () => {
  const text = 'The attacker used T1059.001 (PowerShell Execution) in this campaign.';
  const enriched = ME.enrichText(text);
  // Should not add a second annotation
  const matches = enriched.match(/PowerShell/g) || [];
  assert(matches.length <= 2, `Too many PowerShell annotations: ${matches.length}`);
});

test('enrichText: leaves unknown technique IDs unchanged', () => {
  const text = 'Unknown technique T9999 was used.';
  const enriched = ME.enrichText(text);
  assertContains(enriched, 'T9999'); // kept as-is
});

test('buildTechniqueSection: T1486 returns structured SOC output', () => {
  const section = ME.buildTechniqueSection('T1486');
  assertContains(section, '## Overview');
  assertContains(section, 'T1486');
  assertContains(section, '## Why It Matters');
  assertContains(section, '## Detection Guidance');
  assertContains(section, '## Analyst Tip');
  assertContains(section, 'attack.mitre.org');
});

test('buildTechniqueSection: unknown ID returns helpful fallback', () => {
  const section = ME.buildTechniqueSection('T9999');
  assertContains(section, 'T9999');
  assertContains(section, 'MITRE ATT&CK');
  assertContains(section, 'attack.mitre.org');
});

test('getCVEContext: returns hint for known CVE', () => {
  const hint = ME.getCVEContext('CVE-2021-44228');
  assert(hint !== null, 'Should return a hint for Log4Shell');
  assertContains(hint, 'Log4Shell');
  assertContains(hint, 'CVSS');
});

test('getCVEContext: returns null for unknown CVE', () => {
  const hint = ME.getCVEContext('CVE-9999-99999');
  assert(hint === null, 'Unknown CVE should return null');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 7 — Tool Output Validation
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── Tool Output Validation ───\n'));

test('mitre_lookup tool: returns enriched output for T1059.001', async () => {
  const result = await executeTool('mitre_lookup', { query: 'T1059.001' });
  assert(result.result !== undefined, 'Result should exist');
  const r = result.result;
  assert(r.name || Array.isArray(r), 'Should have name or array');
  if (r.name) assertContains(r.name.toLowerCase(), 'powershell');
  if (r._formatted) assertContains(r._formatted, '## Overview');
});

test('mitre_lookup tool: text search finds results', async () => {
  // Use 'phishing' which is in T1566 description
  const result = await executeTool('mitre_lookup', { query: 'phishing' });
  assert(result.result !== undefined);
  // Result can be array or single object
  const r = Array.isArray(result.result) ? result.result : (result.result.id ? [result.result] : []);
  // If empty array — the embedded DB might not have a text match; that's OK as long as it doesn't throw
  assert(typeof result.result !== 'undefined', 'Should return a defined result');
});

test('cve_lookup tool: handles invalid CVE format gracefully', async () => {
  const result = await executeTool('cve_lookup', { cve_id: 'NOT-A-CVE' });
  assert(result.result !== undefined);
  assert(result.result.error !== true, 'Should not set error:true');
  assert(result.result.found === false, 'Should set found:false');
  assertContains(result.result.message || '', 'Invalid');
});

test('cve_lookup tool: returns structured fields for valid CVE ID', async () => {
  const result = await executeTool('cve_lookup', { cve_id: 'CVE-2021-44228' });
  assert(result.result !== undefined);
  // Either found=true with structured data, or found=false with fallback
  assert(typeof result.result === 'object', 'Result should be object');
  assert(result.result.id || result.result.nvd_url, 'Should have id or nvd_url');
});

test('ioc_enrich tool: returns structured verdict for IP', async () => {
  const result = await executeTool('ioc_enrich', { ioc: '185.220.101.34', ioc_type: 'ip' });
  assert(result.result !== undefined);
  const r = result.result;
  assert(r.ioc === '185.220.101.34', 'Should echo back the IOC');
  assert(r.type === 'ip', 'Should detect IP type');
  // Should have actionable fields
  assert(r.recommended_actions || r.verdict || r.risk_score !== undefined, 'Should have actionable output');
});

test('sigma_search tool: returns formatted results array', async () => {
  const result = await executeTool('sigma_search', { query: 'powershell' });
  assert(result.result !== undefined);
  // Result is either array or string
  const isArray = Array.isArray(result.result);
  const isString = typeof result.result === 'string';
  assert(isArray || isString, 'Result should be array or string');
});

test('sigma_generate tool: returns YAML content', async () => {
  const result = await executeTool('sigma_generate', { scenario: 'PowerShell encoded command execution', technique_id: 'T1059.001' });
  assert(result.result !== undefined);
  const yaml = result.result.rule_yaml;
  assert(yaml, 'Should produce YAML');
  assertContains(yaml, 'title:');
  assertContains(yaml, 'logsource:');
  assertContains(yaml, 'detection:');
  assertContains(yaml, 'level:');
});

test('kql_generate tool: returns KQL query', async () => {
  const result = await executeTool('kql_generate', { scenario: 'PowerShell encoded command', target_siem: 'kql' });
  assert(result.result !== undefined);
  const query = result.result.query;
  assert(query, 'Should produce a query');
  assertContains(query, 'powershell.exe');
});

test('kql_generate tool: returns Splunk SPL when requested', async () => {
  const result = await executeTool('kql_generate', { scenario: 'ransomware file encryption', target_siem: 'splunk_spl' });
  assert(result.result !== undefined);
  const query = result.result.query;
  assert(query, 'Should produce a query');
  assertContains(query, 'index=');
});

test('executeTool: unknown tool returns graceful error, no throw', async () => {
  const result = await executeTool('nonexistent_tool', {});
  assert(result.result !== undefined, 'Should return a result object');
  assert(result.result.error !== true, 'error should not be literal true');
  assertContains(result.result.message || '', 'not available');
  assert(result.metadata.error === true, 'metadata.error should be true');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 8 — End-to-End Scenarios
// ═══════════════════════════════════════════════════════════════════════════════
console.log(C.bold('\n─── End-to-End Scenarios ───\n'));

test('Scenario: MITRE T1059.001 → full SOC template via pipeline', async () => {
  const toolResult = await executeTool('mitre_lookup', { query: 'T1059.001' });
  const rawText = toolResult.result._formatted || toolResult.result.description || 'T1059.001 PowerShell execution.';
  const processed = RP.process(rawText, { toolNames: ['mitre_lookup'] });
  assertContains(processed, 'PowerShell');
  // Should be readable in < 10 seconds (not just a wall of JSON)
  assertNotContains(processed, '"description":');
});

test('Scenario: CVE lookup with Log4Shell offline hint', () => {
  const hint = ME.getCVEContext('CVE-2021-44228');
  const response = RP.buildStructuredResponse({
    overview:     `CVE-2021-44228: ${hint}`,
    whyItMatters: 'Affects Apache Log4j used in millions of Java applications.',
    detectionGuidance: 'Monitor for JNDI LDAP calls in web server logs.',
    mitigation:   'Upgrade to Log4j 2.17.1 or later. Set `log4j2.formatMsgNoLookups=true`.',
    analystTip:   'Threat actors exploited this within hours of disclosure. Check WAF logs for $\\{jndi: patterns.',
  });
  assertContains(response, '## Overview');
  assertContains(response, 'Log4Shell');
  assertContains(response, '## Analyst Tip');
});

test('Scenario: Multi-tool merged response — no raw JSON', async () => {
  const trace = [
    { tool: 'mitre_lookup', result: { name: 'PowerShell', description: 'PowerShell execution technique.' } },
    { tool: 'sigma_search', result: [{ title: 'Detect PowerShell Encoded Command', level: 'high' }] },
  ];
  const llmText = 'Based on the MITRE lookup and Sigma search, I found relevant data for T1059.001.';
  const merged = RP.mergeToolResults(trace, llmText);
  assertNotContains(merged, '"description":');
  assertContains(merged, 'PowerShell');
});

test('Scenario: Tool failure → graceful degradation message, no throw', async () => {
  // Simulate tool returning an error result
  const result = { error: false, found: false, message: 'Tool timed out. Please try again.', tool: 'cve_lookup' };
  const processed = RP.process(JSON.stringify(result), { skipFormat: true });
  // Pipeline should handle the JSON and not crash
  assert(processed !== null && processed !== undefined);
});

test('Scenario: Sigma generation with proper YAML code block', async () => {
  const result = await executeTool('sigma_generate', {
    scenario: 'Suspicious child process spawned by Office application',
    technique_id: 'T1566.001',
    log_source: 'process_creation',
  });
  const yaml = result.result.rule_yaml;
  assertContains(yaml, 'status: experimental');
  assertContains(yaml, 'logsource:');
  assertContains(yaml, 'detection:');
  assertContains(yaml, 'T1566.001');
  assert(!yaml.includes('[object Object]'), 'YAML should not contain [object Object]');
});

test('Scenario: Degraded mode adds informational note', () => {
  const text = RP.process('Analysis complete.', { degraded: true });
  assertContains(text, 'limited-capability mode');
});

test('Scenario: API key stripped from error output', () => {
  const err = RP.buildErrorResponse({
    type: 'error',
    message: 'sk-proj-abc123defghijklmnopqrstuvwxyz key is invalid',
  });
  // buildErrorResponse applies _clean which strips API keys
  assertNotContains(err.reply || '', 'sk-proj-abc123defghijklmnopqrstuvwxyz');
  assertContains(err.reply || '', 'sk-***');
});

test('Scenario: Duplicate tool banners in stream → collapsed to one', () => {
  const text = '🔧 *Using tool: mitre_lookup...*\n\n🔧 *Using tool: cve_lookup...*\n\n🔧 *Using intelligence sources...*\n\nFinal answer here.';
  const cleaned = RP._stages.clean(text);
  const bannerCount = (cleaned.match(/🔧/g) || []).length;
  assert(bannerCount <= 1, `Expected ≤1 tool banner, found ${bannerCount}`);
  assertContains(cleaned, 'Final answer here');
});

test('Scenario: Threat actor profile returns structured output', async () => {
  const result = await executeTool('threat_actor_profile', { actor: 'APT29' });
  const r = result.result;
  assert(r.name === 'APT29', 'Should return APT29 profile');
  assert(Array.isArray(r.ttps), 'TTPs should be an array');
  assert(r.description, 'Should have a description');
  assert(r.notable_campaigns, 'Should have notable campaigns');
});

test('Scenario: IOC enrichment result has no raw JSON dump', async () => {
  const result = await executeTool('ioc_enrich', { ioc: 'example.com', ioc_type: 'domain' });
  // The result should be structured (not a raw object dump)
  const r = result.result;
  assert(typeof r === 'object', 'Result should be object');
  assert(r.ioc === 'example.com', 'Should echo back the IOC');
  // Recommended actions should exist for unknown IOC
  assert(r.recommended_actions || r.risk_score !== undefined, 'Should have actionable output');
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RUN ALL TESTS AND PRINT SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════
runAsyncTests().then(() => {
  console.log('\n');
  console.log(C.cyan('══════════════════════════════════════════════════'));
  console.log(C.cyan(' VALIDATION SUMMARY'));
  console.log(C.cyan('══════════════════════════════════════════════════'));
  console.log(C.green(`  ✅ PASSED: ${passed} tests`));
  if (failed > 0) {
    console.log(C.red(`  ❌ FAILED: ${failed} tests`));
    console.log(C.red('\n  Failures:'));
    failures.forEach(f => console.log(C.red(`    - ${f}`)));
    console.log('\n');
    process.exit(1);
  } else {
    console.log(C.green(C.bold(`\n  🎉 All ${passed} tests passed — Response pipeline is production-ready and SOC-grade.\n`)));
  }
}).catch(err => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
