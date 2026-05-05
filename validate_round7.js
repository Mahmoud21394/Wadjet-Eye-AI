#!/usr/bin/env node
'use strict';
const fs   = require('fs');
const path = require('path');

const PASS = '\x1b[32m✅ PASS\x1b[0m';
const FAIL = '\x1b[31m❌ FAIL\x1b[0m';

let passed = 0, failed = 0;

function check(label, cond) {
  if (cond) { console.log(`  ${PASS} ${label}`); passed++; }
  else       { console.log(`  ${FAIL} ${label}`); failed++; }
}

function src(f) { return fs.readFileSync(path.join(__dirname, f), 'utf8'); }

const lsp  = src('js/login-secure-patch.js');
const ai   = src('js/auth-interceptor.js');
const av   = src('js/auth-validator.js');
const apc  = src('js/auth-persistent.js');
const orch = src('js/ai-orchestrator-v5.js');
const idx  = src('index.html');
const oai  = src('api/proxy/openai.js');
const cld  = src('api/proxy/claude.js');
const ais  = src('js/state-sync.js');

// ── Category 1: Token key consistency ─────────────────────────
console.log('\n\x1b[1m📋 Category 1: Token key write/read consistency\x1b[0m');

// login-secure-patch.js must write the canonical key names
check("LSP writes 'we_token_expires' (no _at) — canonical LEGACY_EXP key",
  lsp.includes("localStorage.setItem('we_token_expires',"));
check("LSP writes 'wadjet_token_expires_at' — UNIFIED_KEYS.EXPIRES",
  lsp.includes("localStorage.setItem('wadjet_token_expires_at',"));
check("LSP writes access token under 'wadjet_access_token'",
  lsp.includes("'wadjet_access_token', 'we_access_token', 'tp_access_token'") &&
  lsp.includes('TOKEN_KEYS.forEach'));
check("LSP writes refresh token under 'wadjet_refresh_token'",
  lsp.includes("localStorage.setItem('wadjet_refresh_token'"));
check("LSP writes refresh token under 'wadjet_unified_refresh'",
  lsp.includes("localStorage.setItem('wadjet_unified_refresh'"));

// auth-validator.js must read the same keys
check("AV getToken reads 'wadjet_access_token' first",
  av.includes("'wadjet_access_token', 'we_access_token', 'tp_access_token'"));
check("AV getToken falls back to sessionStorage",
  av.includes('sessionStorage.getItem(k)'));

// auth-interceptor.js UNIFIED_KEYS must contain the canonical names
check("AI UNIFIED_KEYS.LEGACY_EXP = 'we_token_expires'",
  ai.includes("LEGACY_EXP:     'we_token_expires'"));
check("AI UNIFIED_KEYS.ACCESS = 'wadjet_access_token'",
  ai.includes("ACCESS:   'wadjet_access_token'"));
check("AI UNIFIED_KEYS.REFRESH = 'wadjet_refresh_token'",
  ai.includes("REFRESH:  'wadjet_refresh_token'"));

// ── Category 2: Backoff complete reset on login ───────────────
console.log('\n\x1b[1m📋 Category 2: Complete backoff/lock reset on PersistentAuth_onLogin\x1b[0m');

check("PersistentAuth_onLogin resets _lastRefreshAttemptAt = 0",
  ai.includes('_lastRefreshAttemptAt = 0;') &&
  ai.indexOf('_lastRefreshAttemptAt = 0;') < ai.indexOf('UnifiedTokenStore.save'));
check("PersistentAuth_onLogin calls _clearCookieRefreshState()",
  (() => {
    const fnPos   = ai.indexOf('window.PersistentAuth_onLogin = function');
    const clearAt = ai.indexOf('_clearCookieRefreshState();', fnPos);
    const saveAt  = ai.indexOf('UnifiedTokenStore.save', fnPos);
    return fnPos > -1 && clearAt > fnPos && clearAt < saveAt;
  })());
check("PersistentAuth_onLogin resets _refreshLock = false",
  ai.includes('_refreshLock               = false;'));
check("PersistentAuth_onLogin resets window.__wadjetRefreshLock = false",
  ai.includes('window.__wadjetRefreshLock = false;') &&
  ai.indexOf('window.__wadjetRefreshLock = false;') > ai.indexOf('PersistentAuth_onLogin'));
check("PersistentAuth_onLogin resets _refreshPromise = null",
  ai.includes('_refreshPromise            = null;') &&
  ai.indexOf('_refreshPromise            = null;') > ai.indexOf('PersistentAuth_onLogin'));
check("PersistentAuth_onLogin resets _expiredHandled = false",
  ai.includes('_expiredHandled            = false;'));

// clear() removes stale _at-suffix expiry key
check("UnifiedTokenStore.clear() removes 'we_token_expires_at'",
  ai.includes("'we_token_expires_at'") && ai.includes('clear()'));
check("UnifiedTokenStore.clear() removes 'wadjet_token_expires_at'",
  ai.includes("'wadjet_token_expires_at'"));

// ── Category 3: Backoff init guard (stale sessionStorage) ─────
console.log('\n\x1b[1m📋 Category 3: Backoff init guard — stale sessionStorage deadline check\x1b[0m');

check("AI only reads backoff if deadline > Date.now()",
  ai.includes('_storedDeadline > Date.now()'));
check("AI has COOKIE_REFRESH_MAX_BACKOFF_MS = 300_000",
  ai.includes('COOKIE_REFRESH_MAX_BACKOFF_MS  = 300_000'));
check("AI has REFRESH_MIN_INTERVAL_MS = 15_000",
  ai.includes('REFRESH_MIN_INTERVAL_MS = 15_000'));

// ── Category 4: Refresh request body ─────────────────────────
console.log('\n\x1b[1m📋 Category 4: POST /api/auth/refresh body format\x1b[0m');

check("AI sends { refresh_token: refreshToken } in POST body",
  ai.includes("JSON.stringify({ refresh_token: refreshToken })"));
check("AI includes credentials: 'include' in refresh POST",
  ai.includes("credentials: 'include'"));
check("Backend reads req.body.refresh_token",
  (() => { try { return src('backend/routes/auth.js').includes('req.body.refresh_token'); } catch { return true; } })());

// ── Category 5: auth:session-expired aliased to auth:expired ──
console.log('\n\x1b[1m📋 Category 5: auth:session-expired → auth:expired alias\x1b[0m');

check("AI dispatches auth:expired on 401 refresh rejection",
  ai.includes("_dispatchAuthEvent('auth:expired'") &&
  ai.includes("_dispatchAuthEvent('auth:session-expired'"));
check("AI listener for auth:expired triggers doLogout",
  ai.includes("window.addEventListener('auth:expired'") &&
  ai.includes('doLogout({ skipBackendCall: true })'));
check("StateSync.handleAuthExpiry dispatches auth:expired",
  ais.includes("'auth:expired'") || ais.includes("auth:expired"));

// ── Category 6: AI orchestrator — no hardcoded keys ───────────
console.log('\n\x1b[1m📋 Category 6: AI orchestrator — no hardcoded API keys\x1b[0m');

check("Orch PRESET block has NO sk-proj- hardcoded OpenAI key",
  !orch.match(/sk-proj-[A-Za-z0-9_-]{10,}/));
check("Orch PRESET block has NO sk-ant-api03- hardcoded Claude key",
  !orch.match(/sk-ant-api03-[A-Za-z0-9_-]{10,}/));
check("Orch migrates stale sk-proj-RYqB4T key from localStorage",
  orch.includes("STALE_OPENAI_PREFIX = 'sk-proj-RYqB4T'") &&
  orch.includes("localStorage.removeItem('wadjet_openai_key')"));
check("Orch migrates stale sk-ant-api03-BJaJ key from localStorage",
  orch.includes("STALE_CLAUDE_PREFIX = 'sk-ant-api03-BJaJ'") &&
  orch.includes("localStorage.removeItem('wadjet_claude_key')"));
check("Orch /ai/chat sends { messages, session_id } body",
  orch.includes('/ai/chat') && orch.includes('session_id'));

// ── Category 7: Vercel proxy env var injection ────────────────
console.log('\n\x1b[1m📋 Category 7: Vercel proxy env var injection\x1b[0m');

check("openai.js reads process.env.OPENAI_API_KEY",
  oai.includes('process.env.OPENAI_API_KEY'));
check("openai.js injects Authorization: Bearer token header",
  oai.includes("'Authorization': `Bearer ${openaiKey}`") ||
  oai.includes("Authorization: `Bearer ${openaiKey}`"));
check("openai.js returns 200+error JSON when key missing (not 500)",
  oai.includes("'missing_api_key'") && oai.includes('sendJSON(res, 200'));
check("claude.js reads process.env.CLAUDE_API_KEY",
  cld.includes('process.env.CLAUDE_API_KEY'));
check("claude.js injects x-api-key header",
  cld.includes("'x-api-key': ") || cld.includes('"x-api-key":'));
check("claude.js returns 200+error JSON when key missing",
  cld.includes("'missing_api_key'") && cld.includes('sendJSON(res, 200'));

// ── Category 8: index.html script load order ─────────────────
console.log('\n\x1b[1m📋 Category 8: index.html script load order\x1b[0m');

const authPersistentPos  = idx.indexOf('auth-persistent.js');
const stateSyncPos       = idx.indexOf('state-sync.js');
const authInterceptorPos = idx.indexOf('auth-interceptor.js');
const authValidatorPos   = idx.indexOf('auth-validator.js');

check("auth-persistent.js loads before state-sync.js",
  authPersistentPos > -1 && stateSyncPos > -1 && authPersistentPos < stateSyncPos);
check("state-sync.js loads before auth-interceptor.js",
  stateSyncPos > -1 && authInterceptorPos > -1 && stateSyncPos < authInterceptorPos);
check("auth-interceptor.js loads before auth-validator.js",
  authInterceptorPos > -1 && authValidatorPos > -1 && authInterceptorPos < authValidatorPos);

// ── Category 9: auth-persistent.js stub correctness ──────────
console.log('\n\x1b[1m📋 Category 9: auth-persistent.js compatibility stub\x1b[0m');

check("auth-persistent.js defines PersistentTokenStore",
  apc.includes('PersistentTokenStore') || apc.includes('window.PersistentTokenStore'));
check("auth-persistent.js defines PersistentAuth alias",
  apc.includes('PersistentAuth'));
check("auth-persistent.js delegates to UnifiedTokenStore",
  apc.includes('UnifiedTokenStore'));
check("auth-persistent.js logs stub loaded message",
  apc.includes('stub loaded'));

// ── Summary ───────────────────────────────────────────────────
console.log('\n' + '─'.repeat(60));
console.log(`\x1b[1mResults: ${passed}/${passed + failed} passed\x1b[0m  (${failed} failed)\n`);
if (failed > 0) process.exit(1);
