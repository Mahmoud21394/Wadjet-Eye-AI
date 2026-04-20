/**
 * Unit Tests — RAYKAN Sigma Rule Builder v2.0
 * Run: node backend/tests/sigma-rule-builder.test.js
 */

'use strict';

const {
  sanitizeDescription,
  buildRule,
  validateRuleOutput,
  sigmaQualityCheck,
  toSigmaYaml,
  isValidCommandLine,
  DETECTION_TEMPLATES,
} = require('../services/raykan/sigma-rule-builder');

// ── Mini test harness ──────────────────────────────────────────────
let passed = 0;
let failed = 0;
const BOLD   = '\x1b[1m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET  = '\x1b[0m';

function test(name, fn) {
  try {
    fn();
    console.log(`  ${GREEN}✓${RESET} ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ${RED}✗${RESET} ${name}`);
    console.log(`    ${RED}${e.message}${RESET}`);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

function assertIncludes(arr, item, msg) {
  if (!arr.includes(item)) throw new Error(msg || `Expected array to include "${item}", got: ${JSON.stringify(arr)}`);
}

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§1  Input Sanitizer${RESET}`);

test('Strips instruction verbs (generate, create, write)', () => {
  const r = sanitizeDescription('Please create a Sigma rule to detect ransomware');
  // "create" should be stripped, "ransomware" should be kept
  assert(!r.sanitized.includes('create'), `Expected "create" to be stripped, got: "${r.sanitized}"`);
  assertIncludes(r.keywords, 'ransomware', 'Expected ransomware keyword');
  assert(r.intent === 'impact', `Expected intent=impact, got: ${r.intent}`);
});

test('Strips "generate", "show me", "give me" variations', () => {
  const phrases = [
    'Generate a rule for mimikatz',
    'Show me how to detect psexec',
    'Give me a detection for lsass',
  ];
  for (const p of phrases) {
    const r = sanitizeDescription(p);
    // None of the meta-instruction verbs should survive
    const metaWords = ['generate', 'show me', 'give me', 'how to'];
    for (const mw of metaWords) {
      assert(!r.sanitized.includes(mw), `"${mw}" survived sanitization in: "${r.sanitized}"`);
    }
  }
});

test('Extracts ransomware keywords correctly', () => {
  const r = sanitizeDescription('detect vssadmin delete shadows used by ransomware LockBit');
  assertIncludes(r.keywords, 'vssadmin');
  assertIncludes(r.keywords, 'ransomware');
  assert(r.intent === 'impact' || r.intent === 'ransomware', `Expected impact/ransomware intent, got: ${r.intent}`);
});

test('Extracts credential access keywords', () => {
  const r = sanitizeDescription('mimikatz sekurlsa credential dump from lsass');
  assertIncludes(r.keywords, 'mimikatz');
  assertIncludes(r.keywords, 'sekurlsa');
  assert(r.intent === 'credential_access', `Expected credential_access, got: ${r.intent}`);
});

test('Returns generic intent for unrecognized input', () => {
  const r = sanitizeDescription('something completely unrelated to security');
  assert(r.intent === 'generic', `Expected generic, got: ${r.intent}`);
  assert(r.keywords.length === 0, `Expected no keywords, got: ${JSON.stringify(r.keywords)}`);
});

test('Empty input returns generic safely', () => {
  const r = sanitizeDescription('');
  assert(r.intent === 'generic');
  assert(Array.isArray(r.keywords));
});

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§2  Detection Template Engine${RESET}`);

test('buildRule(ransomware) returns impact template', () => {
  const { rule } = buildRule('detect ransomware shadow copy deletion');
  assert(rule.detection, 'No detection block');
  const det = rule.detection;
  const selKeys = Object.keys(det).filter(k => k !== 'condition');
  assert(selKeys.length >= 2, `Expected ≥2 selections, got ${selKeys.length}: ${selKeys}`);
  // Check we have backup or boot selections
  const hasBackup = selKeys.some(k => k.includes('backup') || k.includes('shadow') || k.includes('selection_backup'));
  assert(hasBackup, `Expected a backup/shadow selection, got: ${selKeys}`);
});

test('buildRule(credential) returns credential_access template', () => {
  const { rule } = buildRule('detect mimikatz credential dumping');
  assert(rule.tags.some(t => t.includes('credential_access') || t.includes('t1003')),
    `Expected credential_access tag, got: ${JSON.stringify(rule.tags)}`);
});

test('All templates have ≥2 selections', () => {
  for (const [phase, tpl] of Object.entries(DETECTION_TEMPLATES)) {
    const det  = tpl.detection || {};
    const keys = Object.keys(det).filter(k => k !== 'condition' && k !== 'timeframe');
    assert(keys.length >= 2,
      `Template "${phase}" has only ${keys.length} selection(s): ${keys}`);
  }
});

test('All templates have compound condition (not single "selection")', () => {
  for (const [phase, tpl] of Object.entries(DETECTION_TEMPLATES)) {
    const cond = tpl.detection?.condition || '';
    assert(cond !== 'selection',
      `Template "${phase}" uses bare single-selection condition: "${cond}"`);
    assert(cond.length > 0,
      `Template "${phase}" has empty condition`);
  }
});

test('All template CommandLine values pass LOLBin check', () => {
  for (const [phase, tpl] of Object.entries(DETECTION_TEMPLATES)) {
    const det = tpl.detection || {};
    for (const [selKey, selVal] of Object.entries(det)) {
      if (selKey === 'condition' || selKey === 'timeframe') continue;
      const cmdLines = selVal?.CommandLine || [];
      for (const cl of cmdLines) {
        assert(isValidCommandLine(cl),
          `Template "${phase}.${selKey}" has invalid CommandLine: "${cl}"`);
      }
    }
  }
});

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§3  Output Validator${RESET}`);

test('Valid rule passes validation', () => {
  const { rule } = buildRule('detect ransomware vssadmin delete shadows');
  const v = validateRuleOutput(rule, 'ransomware detection');
  assert(v.valid, `Expected valid, errors: ${JSON.stringify(v.errors)}`);
});

test('Detects prompt leakage in CommandLine', () => {
  const badRule = {
    title      : 'Test Rule',
    description: 'Test detection',
    level      : 'high',
    logsource  : { category: 'process_creation', product: 'windows' },
    detection  : {
      selection_bad: { CommandLine: ['*generate sigma rule for ransomware*'] },
      condition     : '1 of selection_*',
    },
  };
  const v = validateRuleOutput(badRule, 'generate sigma rule for ransomware');
  assert(!v.valid, 'Expected validation to fail due to prompt leakage');
  assert(v.errors.some(e => e.includes('Prompt leak') || e.includes('meta-word') || e.includes('Invalid')),
    `Expected prompt-leak/meta error, got: ${JSON.stringify(v.errors)}`);
});

test('Detects meta word "generate" in CommandLine', () => {
  const badRule = {
    title      : 'Test',
    description: 'Test',
    level      : 'medium',
    logsource  : { category: 'process_creation', product: 'windows' },
    detection  : {
      selection_x: { CommandLine: ['*generate detection rule*'] },
      condition   : '1 of selection_*',
    },
  };
  const v = validateRuleOutput(badRule, 'test input');
  assert(!v.valid, 'Expected validation to fail on meta-word "generate"');
});

test('Rejects single bare "selection" condition', () => {
  const badRule = {
    title      : 'Test',
    description: 'Test',
    level      : 'high',
    logsource  : { category: 'process_creation', product: 'windows' },
    detection  : {
      selection: { CommandLine: ['*vssadmin*'] },
      condition : 'selection',
    },
  };
  const v = validateRuleOutput(badRule, '');
  assert(!v.valid, 'Expected failure on bare "selection" condition');
  assert(v.errors.some(e => e.includes('single bare') || e.includes('selection')),
    `Expected condition error, got: ${JSON.stringify(v.errors)}`);
});

test('Requires missing fields (title, description, logsource, detection, level)', () => {
  const v = validateRuleOutput({}, '');
  assert(!v.valid);
  assert(v.errors.some(e => e.includes('title')));
  assert(v.errors.some(e => e.includes('detection')));
  assert(v.errors.some(e => e.includes('level')));
});

test('Rejects CommandLine not matching LOLBin patterns', () => {
  const badRule = {
    title      : 'Bad',
    description: 'Bad rule',
    level      : 'high',
    logsource  : { category: 'process_creation', product: 'windows' },
    detection  : {
      selection_a: { CommandLine: ['*totally random string*'] },
      selection_b: { CommandLine: ['*another fake command*'] },
      condition   : '1 of selection_*',
    },
  };
  const v = validateRuleOutput(badRule, '');
  // The random strings should fail LOLBin check
  assert(!v.valid, 'Expected LOLBin validation to fail');
});

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§4  Sigma Quality Checker${RESET}`);

test('Built ransomware rule achieves grade ≥ B', () => {
  const { rule } = buildRule('ransomware shadow copy deletion vssadmin wbadmin');
  const q = sigmaQualityCheck(rule);
  assert(q.score >= 75, `Expected score ≥75, got ${q.score}. Issues: ${JSON.stringify(q.issues)}`);
  assert(['A', 'B'].includes(q.grade), `Expected grade A/B, got ${q.grade}`);
});

test('Single-selection rule gets penalized', () => {
  const weakRule = {
    title      : 'Weak detection rule for testing',
    description: 'A very short desc',
    level      : 'medium',
    status     : 'experimental',
    tags       : ['attack.execution'],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: ['Unknown'],
    detection  : {
      selection: { CommandLine: ['*vssadmin*'] },
      condition : 'selection',
    },
  };
  const q = sigmaQualityCheck(weakRule);
  assert(q.score < 80, `Expected penalized score, got ${q.score}`);
  assert(q.issues.length > 0, 'Expected quality issues');
});

test('Rule missing MITRE tag gets penalized', () => {
  const r = {
    title      : 'Some detection rule that is long enough',
    description: 'This is a moderately long description with enough words to pass the length check',
    level      : 'high',
    status     : 'stable',
    tags       : ['attack.impact'],   // no T#### technique
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: ['Legitimate admin activity during maintenance windows'],
    references : ['https://attack.mitre.org/'],
    detection  : {
      sel_a: { CommandLine: ['*vssadmin*'] },
      sel_b: { CommandLine: ['*bcdedit*'] },
      condition: '1 of sel_*',
    },
  };
  const q = sigmaQualityCheck(r);
  assert(q.issues.some(i => i.includes('MITRE') || i.includes('technique')),
    `Expected MITRE tag warning, got: ${JSON.stringify(q.issues)}`);
});

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§5  YAML Serializer${RESET}`);

test('toSigmaYaml produces parseable YAML structure', () => {
  const { rule } = buildRule('ransomware vssadmin delete shadows');
  const yaml = toSigmaYaml(rule);
  assert(yaml.includes('title:'),       'Missing title field');
  assert(yaml.includes('detection:'),   'Missing detection block');
  assert(yaml.includes('condition:'),   'Missing condition');
  assert(yaml.includes('logsource:'),   'Missing logsource');
  assert(yaml.includes('level:'),       'Missing level');
  assert(yaml.includes('falsepositives:'), 'Missing falsepositives');
});

test('YAML does not contain raw user instruction text', () => {
  const userInput = 'Please create a Sigma rule for ransomware and make it work';
  const { rule } = buildRule(userInput);
  const yaml = toSigmaYaml(rule);
  // The instruction words should not appear in YAML values
  const injectWords = ['please', 'create a', 'make it'];
  for (const w of injectWords) {
    const yamlLower = yaml.toLowerCase();
    // Allow it in comments/description but NOT in CommandLine values
    const cmdLineSection = yaml.split('CommandLine:').slice(1).join('CommandLine:');
    assert(!cmdLineSection.toLowerCase().includes(w),
      `Instruction word "${w}" found in CommandLine YAML section`);
  }
});

// ─────────────────────────────────────────────────────────────────────
console.log(`\n${BOLD}§6  End-to-End: Problematic Prompt Scenarios${RESET}`);

test('E2E: "generate a sigma rule for ransomware impact phase" → safe rule', () => {
  const { rule, validation, meta } = buildRule('generate a sigma rule for ransomware impact phase');
  assert(validation.valid, `Expected valid rule, errors: ${JSON.stringify(validation.errors)}`);
  // CommandLine must NOT contain "generate", "sigma", "rule"
  const det = rule.detection || {};
  for (const [, sel] of Object.entries(det)) {
    const lines = (sel?.CommandLine || []);
    for (const cl of lines) {
      assert(!cl.toLowerCase().includes('generate'), `"generate" leaked into CommandLine: ${cl}`);
      assert(!cl.toLowerCase().includes(' rule '), `"rule" leaked into CommandLine: ${cl}`);
    }
  }
  console.log(`    ${YELLOW}→ intent=${meta.intent}, keywords=[${meta.keywords.join(',')}]${RESET}`);
});

test('E2E: "detect attackers using vssadmin delete shadows and wbadmin" → impact template', () => {
  const { rule, validation, meta } = buildRule('detect attackers using vssadmin delete shadows and wbadmin delete catalog');
  assert(validation.valid, `Expected valid, errors: ${JSON.stringify(validation.errors)}`);
  assert(rule.level === 'critical' || rule.level === 'high',
    `Expected high/critical level, got: ${rule.level}`);
  console.log(`    ${YELLOW}→ intent=${meta.intent}, level=${rule.level}${RESET}`);
});

test('E2E: "powershell encoded command bypass amsi" → defense_evasion template', () => {
  const { rule, validation, meta } = buildRule('powershell encoded command bypass amsi');
  assert(validation.valid, `Expected valid, errors: ${JSON.stringify(validation.errors)}`);
  console.log(`    ${YELLOW}→ intent=${meta.intent}, level=${rule.level}${RESET}`);
});

test('E2E: Completely off-topic input → generic fallback (never crashes)', () => {
  const { rule, validation } = buildRule('I want pizza with extra cheese');
  // Should not throw, should return a safe generic rule
  assert(rule, 'Expected a rule object');
  assert(rule.detection, 'Expected a detection block');
  assert(validation.valid !== undefined, 'Expected validation object');
});

test('E2E: Empty string input → generic fallback', () => {
  const { rule } = buildRule('');
  assert(rule, 'Expected rule even for empty input');
});

// ─────────────────────────────────────────────────────────────────────
// Results
// ─────────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(60)}`);
console.log(`${BOLD}Results: ${GREEN}${passed} passed${RESET}${BOLD}, ${failed > 0 ? RED : GREEN}${failed} failed${RESET}${BOLD} / ${passed + failed} total${RESET}`);
console.log(`${'─'.repeat(60)}\n`);

if (failed > 0) process.exit(1);
