/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — LLM Contract Middleware  (Phase 0)
 *  backend/middleware/llmContract.js
 *
 *  Express middleware + function-level guard that enforces the LLM Input
 *  Contract on every backend route that forwards messages to an LLM.
 *
 *  Wraps:
 *    POST /api/ai/analyze     backend/routes/ai.js  callOpenAI/callGemini/callOllama
 *    POST /api/ai/chat        backend/routes/ai.js
 *    POST /api/ai/summarize   backend/routes/ai.js
 *    POST /api/rag/copilot    backend/routes/rag.js
 *    POST /api/rag/explain-alert  backend/routes/rag.js
 *    LLMProviderOrchestrator  backend/services/llm-provider.js  (chat method)
 *
 *  Feature flag: WE_FEATURE_LLM_CONTRACT=0 disables enforcement.
 *  All blocks are logged with reason + truncated evidence.  Stats
 *  are exposed via GET /api/ai/contract/stats.
 *
 * ══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const contract = require('../../js/llm-contract.js');

const {
  validateAndTrack,
  LLMContractViolation,
  isContractEnforced,
  getContractStats,
} = contract;

// ── Express middleware: validate req.body.messages ─────────────────────────
//
// Add to any route that receives a `messages` array in the request body.
// Usage in routes/ai.js:
//   router.post('/analyze', llmContractMiddleware, asyncHandler(async (req, res) => { … }))
//
function llmContractMiddleware(req, res, next) {
  const { messages, prompt, content } = req.body || {};

  // Normalise: some routes send `messages`, others send `prompt` or `content`
  let msgs = messages;
  if (!msgs && prompt) {
    msgs = [{ role: 'user', content: String(prompt) }];
  } else if (!msgs && content) {
    msgs = [{ role: 'user', content: String(content) }];
  }

  if (!msgs || !Array.isArray(msgs) || msgs.length === 0) {
    return next(); // no messages to validate — let the route handle missing fields
  }

  try {
    req.body.messages = validateAndTrack(msgs);
    next();
  } catch (err) {
    if (err instanceof LLMContractViolation) {
      console.warn('[LLMContractMiddleware] BLOCKED request:', {
        path:   req.path,
        reason: err.reason,
        role:   err.role,
      });
      return res.status(422).json({
        success: false,
        error: {
          code:    'LLM_CONTRACT_VIOLATION',
          message: 'Request blocked by LLM Input Contract: ' + err.reason,
          reason:  err.reason,
        },
      });
    }
    next(err);
  }
}

// ── Function-level guard: wrap any messages array before passing to LLM ───
//
// Use this inside route handlers when the messages array is built
// programmatically rather than taken directly from req.body.
//
// Usage:
//   const { messages: safeMessages } = guardMessages(builtMessages);
//   const result = await callOpenAI(safeMessages);
//
function guardMessages(messages, context = '') {
  try {
    const validated = validateAndTrack(messages);
    return { messages: validated, blocked: false, reason: null };
  } catch (err) {
    if (err instanceof LLMContractViolation) {
      console.warn(`[LLMContractGuard] BLOCKED${context ? ' (' + context + ')' : ''}:`, err.reason);
      return { messages: null, blocked: true, reason: err.reason };
    }
    throw err; // re-throw unexpected errors
  }
}

// ── Patch for llm-provider.js: wrap the .chat() method ────────────────────
//
// Import this in backend/services/llm-provider.js or call it once at
// server startup to protect every call that goes through LLMProviderOrchestrator.
//
function patchLLMProvider(orchestratorInstance) {
  if (!orchestratorInstance || typeof orchestratorInstance.chat !== 'function') {
    console.warn('[LLMContractPatch] orchestratorInstance.chat is not a function — skipping patch');
    return orchestratorInstance;
  }
  const _originalChat = orchestratorInstance.chat.bind(orchestratorInstance);
  orchestratorInstance.chat = async function contractGuardedChat(messages, opts) {
    const { messages: safeMessages, blocked, reason } = guardMessages(messages, 'LLMProvider.chat');
    if (blocked) {
      throw new LLMContractViolation(`LLMProvider.chat blocked: ${reason}`);
    }
    return _originalChat(safeMessages, opts);
  };
  console.log('[LLMContractPatch] LLMProvider.chat patched with contract guard');
  return orchestratorInstance;
}

// ── Stats endpoint handler ─────────────────────────────────────────────────
//
// Mount as: router.get('/contract/stats', contractStatsHandler)
//
function contractStatsHandler(req, res) {
  res.json({
    success:  true,
    enforced: isContractEnforced(),
    stats:    getContractStats(),
  });
}

module.exports = {
  llmContractMiddleware,
  guardMessages,
  patchLLMProvider,
  contractStatsHandler,
  LLMContractViolation,
};
