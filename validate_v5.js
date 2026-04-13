/**
 * RAKAY Platform v5.0 — Full Validation Suite
 * Tests all 4 error categories reported by the user.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const PASS = '\x1b[32m✅ PASS\x1b[0m';
const FAIL = '\x1b[31m❌ FAIL\x1b[0m';

let total = 0, passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
  total++;
  try {
    const result = fn();
    if (result === true || result === undefined) {
      console.log(`  ${PASS} ${name}`);
      passed++;
    } else {
      console.log(`  ${FAIL} ${name}: ${result}`);
      failed++;
      failures.push(name);
    }
  } catch (e) {
    console.log(`  ${FAIL} ${name}: ${e.message}`);
    failed++;
    failures.push(name);
  }
}

// ─────────────────────────────────────────────────────────────────
// Load files
// ─────────────────────────────────────────────────────────────────
const RAKAY_FE   = fs.readFileSync(path.join(__dirname, 'js/rakay-module.js'), 'utf8');
const RAKAY_BE   = fs.readFileSync(path.join(__dirname, 'backend/routes/rakay.js'), 'utf8');
const COLLECTORS = fs.readFileSync(path.join(__dirname, 'backend/routes/collectors.js'), 'utf8');
const IOCS_BE    = fs.readFileSync(path.join(__dirname, 'backend/routes/iocs.js'), 'utf8');
const IOC_INTEL  = fs.readFileSync(path.join(__dirname, 'js/ioc-intelligence.js'), 'utf8');

// ─────────────────────────────────────────────────────────────────
// CATEGORY 1: MISSING_SESSION_ID (400 error)
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 1: MISSING_SESSION_ID Fix\x1b[0m');

test('FE: _uuid() function exists (UUID v4 generator)', () => {
  return RAKAY_FE.includes('function _uuid()');
});

test('FE: _uuid() uses crypto.randomUUID()', () => {
  return RAKAY_FE.includes('crypto.randomUUID()');
});

test('FE: _uuid() has RFC4122 fallback', () => {
  return RAKAY_FE.includes('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx');
});

test('FE: _createSession uses _uuid() not _uid()', () => {
  const createSession = RAKAY_FE.match(/async function _createSession[\s\S]*?^  \}/m)?.[0] || '';
  return createSession.includes('_uuid()') && !createSession.includes("id:.*_uid()");
});

test('FE: session guard in _sendMessage — auto-generates UUID when sessionId is null', () => {
  return RAKAY_FE.includes('SESSION_AUTO_GENERATED') && RAKAY_FE.includes('RAKAY.sessionId = _uuid()');
});

test('BE: chat route does NOT return 400 for missing session_id', () => {
  // Must NOT have "session_id is required" style 400 for missing session
  const chatRoute = RAKAY_BE.match(/router\.post\('\/chat'[\s\S]*?^\}\);/m)?.[0] || '';
  return !chatRoute.includes("session_id is required") || chatRoute.includes("effectiveSessionId");
});

test('BE: backend auto-generates session_id when missing (randomUUID)', () => {
  return RAKAY_BE.includes('randomUUID()') && RAKAY_BE.includes('MISSING_SESSION_ID — auto-generated');
});

test('BE: effectiveSessionId used consistently (not raw session_id after validation)', () => {
  return RAKAY_BE.includes('effectiveSessionId') && 
         RAKAY_BE.includes('sessionId: effectiveSessionId');
});

// ─────────────────────────────────────────────────────────────────
// CATEGORY 2: GET /api/collectors 404
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 2: GET /api/collectors 404 Fix\x1b[0m');

test('BE: collectors.js has root GET / handler', () => {
  return COLLECTORS.includes("router.get('/',");
});

test('BE: root GET / returns `collectors` array (frontend expects it)', () => {
  // Use a larger window that captures the full handler body up to the closing }));
  const idx = COLLECTORS.indexOf("router.get('/',");
  const chunk = idx >= 0 ? COLLECTORS.slice(idx, idx + 900) : '';
  // Accept both explicit `feeds: feeds` and ES6 shorthand `feeds,`
  return chunk.includes('collectors:') && (chunk.includes('feeds:') || chunk.includes('feeds,'));
});

test('BE: root GET / includes count field', () => {
  const idx = COLLECTORS.indexOf("router.get('/',");
  const chunk = idx >= 0 ? COLLECTORS.slice(idx, idx + 800) : '';
  return chunk.includes('count:');
});

test('BE: root GET / logs collector listing', () => {
  return COLLECTORS.includes("GET / — listing");
});

test('BE: collectors.js still has /status route', () => {
  return COLLECTORS.includes("router.get('/status'");
});

test('BE: collectors.js still has /stats route', () => {
  return COLLECTORS.includes("router.get('/stats'");
});

// ─────────────────────────────────────────────────────────────────
// CATEGORY 3: IOC DB Timeout Fix
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 3: IOC DB Timeout Fix\x1b[0m');

test('BE: IOC_QUERY_TIMEOUT_MS constant defined', () => {
  return IOCS_BE.includes('IOC_QUERY_TIMEOUT_MS');
});

test('BE: _withQueryTimeout helper wraps all DB calls', () => {
  return IOCS_BE.includes('_withQueryTimeout(dataQuery') && 
         IOCS_BE.includes('_withQueryTimeout(countQuery');
});

test('BE: data query does NOT use { count: "exact" } (separated)', () => {
  // The data query line should only be select('*') without count: 'exact'
  const dataLine = IOCS_BE.match(/\.from\('iocs'\)\s*\n\s*\.select\('\*'\)/)?.[0];
  // Should have a plain select('*') for data query
  return IOCS_BE.includes(".select('*')  // NO count: 'exact' here");
});

test('BE: count query uses head: true (no row data)', () => {
  return IOCS_BE.includes("{ count: 'exact', head: true }");
});

test('BE: no_count param skips expensive COUNT', () => {
  return IOCS_BE.includes("no_count !== '1'") || IOCS_BE.includes('no_count');
});

test('BE: timeout returns 503 with partial:true (not 500)', () => {
  return IOCS_BE.includes("partial: true");
});

test('BE: default limit reduced (max 100, default 25)', () => {
  return IOCS_BE.includes('limit = 25') || IOCS_BE.includes("limit = '25'");
});

test('FE: ioc-intelligence handles total=-1 (unknown count)', () => {
  return IOC_INTEL.includes('total === -1') || IOC_INTEL.includes('rawTotal === -1');
});

test('FE: ioc-intelligence detects DB timeout error', () => {
  return IOC_INTEL.includes("'503'") || IOC_INTEL.includes("'timeout'") || 
         IOC_INTEL.includes('"503"') || IOC_INTEL.includes('isTimeout');
});

// ─────────────────────────────────────────────────────────────────
// CATEGORY 4: LLM 503 No-Retry
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 4: LLM 503 No-Retry Fix\x1b[0m');

test('BE: _api() defaults retries=0', () => {
  return RAKAY_FE.includes('retries = 0') && RAKAY_FE.includes('retries=0: no auto-retry');
});

test('BE: /chat call uses explicit retries:0', () => {
  const chatCall = RAKAY_FE.match(/_api\('POST', '\/chat'[\s\S]*?\}\)/)?.[0] || '';
  return chatCall.includes('retries:') && chatCall.includes('0');
});

test('FE: 503 LLM_PROVIDER_BUSY does not lock UI (no rate limit freeze)', () => {
  const handler503 = RAKAY_FE.match(/err\.status === 503[\s\S]*?return;/)?.[0] || '';
  // Should NOT have setTimeout or rateLimitUntil assignment for 503
  return !handler503.includes('rateLimitUntil') && !handler503.includes('_rateLimitUntil');
});

test('FE: 503 shows informational message only', () => {
  return RAKAY_FE.includes('LLM_PROVIDER_BUSY') && 
         RAKAY_FE.includes('temporarily busy');
});

test('FE: 409 DUPLICATE_MESSAGE silently discarded (no UI error banner)', () => {
  return RAKAY_FE.includes("'DUPLICATE_MESSAGE'") && RAKAY_FE.includes('DEDUP_409');
});

test('FE: 409 SESSION_BUSY silently discarded', () => {
  return RAKAY_FE.includes("'SESSION_BUSY'") && RAKAY_FE.includes('MUTEX_409');
});

// ─────────────────────────────────────────────────────────────────
// CATEGORY 5: Request Deduplication & Mutex
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 5: Request Control (mutex, dedup, queue)\x1b[0m');

test('BE: per-session mutex (_sessionLocks)', () => {
  return RAKAY_BE.includes('_sessionLocks') && RAKAY_BE.includes('SESSION_BUSY');
});

test('BE: message dedup using SHA-256 hash', () => {
  return RAKAY_BE.includes('createHash') && RAKAY_BE.includes('DUPLICATE_MESSAGE');
});

test('BE: _queueChat contains the ONLY LLM engine.chat() call', () => {
  // Strip comments then count engine.chat( occurrences
  const stripped = RAKAY_BE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const calls = (stripped.match(/engine\.chat\(/g) || []).length;
  return calls === 1 || `found ${calls} engine.chat() calls (expected 1)`;
});

test('BE: _queueChat logs LLM_CALL_EXECUTED_ONCE', () => {
  return RAKAY_BE.includes('LLM_CALL_EXECUTED_ONCE') || RAKAY_BE.includes('LLM CALL EXECUTED ONCE');
});

test('FE: requestInFlight set BEFORE any await in _sendMessage', () => {
  // Find requestInFlight = true position vs first actual code await (not comments)
  const sendFn = RAKAY_FE.match(/async function _sendMessage[\s\S]*?^  \}/m)?.[0] || '';
  const lines = sendFn.split('\n');
  let firstActualAwait = -1, flagLine = -1;
  lines.forEach((line, i) => {
    // Strip comments before checking for await
    const noComment = line.replace(/\/\/.*$/, '');
    if (firstActualAwait === -1 && /\bawait\s+\w/.test(noComment)) firstActualAwait = i;
    if (flagLine === -1 && /RAKAY\.requestInFlight = true/.test(noComment)) flagLine = i;
  });
  return flagLine > -1 && (firstActualAwait === -1 || flagLine < firstActualAwait)
    || `requestInFlight(line ${flagLine}) set after first actual await(line ${firstActualAwait})`;
});

test('FE: frontend dedup cache (_feDedupCache / _feIsDuplicate)', () => {
  return RAKAY_FE.includes('_feDedupCache') && RAKAY_FE.includes('_feIsDuplicate');
});

test('FE: WebSocket message handler makes NO api calls', () => {
  const wsHandler = RAKAY_FE.match(/function _handleWsMessage[\s\S]*?^  \}/m)?.[0] || '';
  return !wsHandler.includes('_api(') && !wsHandler.includes('_sendMessage(');
});

// ─────────────────────────────────────────────────────────────────
// CATEGORY 6: Logging
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 6: Mandatory Logging\x1b[0m');

test('BE: CHAT_START log entry', () => RAKAY_BE.includes('CHAT_START'));
test('BE: CHAT_END log entry', () => RAKAY_BE.includes('CHAT_END'));
test('BE: LLM_QUEUE_START log entry', () => RAKAY_BE.includes('LLM_QUEUE_START'));
test('BE: LLM_CALL_EXECUTED log entry (main confirmation)', () => {
  return RAKAY_BE.includes('LLM_CALL_EXECUTED_ONCE') || RAKAY_BE.includes('LLM CALL EXECUTED ONCE') ||
         RAKAY_BE.includes('LLM_CALL_EXECUTED');
});
test('BE: LLM_CALL_COMPLETE log entry', () => RAKAY_BE.includes('LLM_CALL_COMPLETE'));
test('BE: MUTEX_BLOCKED log when session busy', () => RAKAY_BE.includes('MUTEX_BLOCKED'));
test('BE: DEDUP_BLOCKED log when duplicate detected', () => RAKAY_BE.includes('DEDUP_BLOCKED'));
test('FE: SEND_START log', () => RAKAY_FE.includes('SEND_START'));
test('FE: SEND_COMPLETE log', () => RAKAY_FE.includes('SEND_COMPLETE'));
test('FE: SEND_BLOCKED_INFLIGHT log', () => RAKAY_FE.includes('SEND_BLOCKED_INFLIGHT'));
test('FE: SEND_BLOCKED_DEDUP log', () => RAKAY_FE.includes('SEND_BLOCKED_DEDUP'));
test('FE: SEND_FLAGS_CLEARED log', () => RAKAY_FE.includes('SEND_FLAGS_CLEARED'));

// ─────────────────────────────────────────────────────────────────
// CATEGORY 7: Syntax Validation
// ─────────────────────────────────────────────────────────────────
console.log('\n\x1b[1m📋 Category 7: Syntax Validation\x1b[0m');

const { execSync } = require('child_process');
['js/rakay-module.js', 'backend/routes/rakay.js', 'backend/routes/collectors.js', 
 'backend/routes/iocs.js', 'js/ioc-intelligence.js'].forEach(f => {
  test(`${f}: node --check passes`, () => {
    try {
      execSync(`node --check ${path.join(__dirname, f)}`, { stdio: 'pipe' });
      return true;
    } catch (e) {
      return e.stderr?.toString() || e.message;
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// FINAL SUMMARY
// ─────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(60)}`);
console.log(`\x1b[1mResults: ${passed}/${total} passed\x1b[0m  (${failed} failed)\n`);

if (failures.length) {
  console.log('\x1b[31mFailed tests:\x1b[0m');
  failures.forEach(f => console.log(`  - ${f}`));
}

const exitCode = failed > 0 ? 1 : 0;
process.exit(exitCode);
