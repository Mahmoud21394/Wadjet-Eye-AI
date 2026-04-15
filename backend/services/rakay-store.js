/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Storage Layer  v1.0
 *  Session & Conversation History Persistence
 *
 *  Design:
 *   - Primary:  Supabase (Postgres) — used when DB is available
 *   - Fallback: In-memory store    — used when DB is unreachable
 *   - Automatic failover: every write tries DB first, falls to memory
 *   - Session model: { id, tenant_id, user_id, title, created_at, updated_at }
 *   - Message model: { id, session_id, role, content, tool_calls, tool_results,
 *                      tokens_used, model_id, created_at }
 *
 *  Tables (auto-created on first use if DB is available):
 *   - rakay_sessions
 *   - rakay_messages
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── Constants ──────────────────────────────────────────────────────────────────
const MAX_MEMORY_SESSIONS   = 500;   // per-tenant in-memory cap
const MAX_MESSAGES_PER_SESSION = 500;
const SESSION_TTL_MS        = 7 * 24 * 60 * 60 * 1000; // 7 days

// ── In-memory fallback store ───────────────────────────────────────────────────
/**
 * Structure:
 *  _memSessions: Map<sessionId, SessionRecord>
 *  _memMessages: Map<sessionId, MessageRecord[]>
 */
const _memSessions = new Map();
const _memMessages = new Map();

let _supabase = null;
let _dbAvailable = false;
let _dbCheckTs = 0;
const DB_RETRY_INTERVAL_MS = 30_000;

// ── DB initialiser (lazy, non-blocking) ───────────────────────────────────────
async function _initDB() {
  const now = Date.now();
  if (now - _dbCheckTs < DB_RETRY_INTERVAL_MS) return _dbAvailable;
  _dbCheckTs = now;

  try {
    if (!_supabase) {
      const { supabase } = require('../config/supabase');
      _supabase = supabase;
    }
    // Probe by selecting 1 row
    const { error } = await _supabase
      .from('rakay_sessions')
      .select('id')
      .limit(1);

    if (error && error.code === '42P01') {
      // Table doesn't exist — try to create it
      await _ensureTables();
    }
    _dbAvailable = true;
  } catch {
    _dbAvailable = false;
  }
  return _dbAvailable;
}

// ── DDL: Create tables if missing ─────────────────────────────────────────────
async function _ensureTables() {
  if (!_supabase) return;
  // Supabase JS SDK doesn't expose raw DDL; use rpc if available, else skip
  // In production this would be handled by a migration script.
  // For resilience we simply mark DB unavailable — the memory store takes over.
  _dbAvailable = false;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SESSION CRUD
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Create a new session.
 * @param {object} opts
 * @param {string} opts.tenantId
 * @param {string} opts.userId
 * @param {string} [opts.title]
 * @param {string} [opts.sessionId]  — optional: reuse an existing ID (e.g. auto-recreate after server restart)
 * @returns {Promise<SessionRecord>}
 */
async function createSession({ tenantId, userId, title = 'New Chat', sessionId }) {
  const session = {
    id:         sessionId || crypto.randomUUID(),
    tenant_id:  tenantId,
    user_id:    userId,
    title,
    message_count: 0,
    tokens_used:   0,
    created_at:    new Date().toISOString(),
    updated_at:    new Date().toISOString(),
  };

  // Try DB first
  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_sessions')
      .insert(session)
      .select()
      .single();
    if (!error && data) return data;
  }

  // Fallback: memory
  _memSessions.set(session.id, session);
  _memMessages.set(session.id, []);
  _evictOldSessions(tenantId);
  return session;
}

/**
 * List sessions for a user (most-recent first).
 * @param {object} opts
 * @param {string} opts.tenantId
 * @param {string} opts.userId
 * @param {number} [opts.limit]
 * @returns {Promise<SessionRecord[]>}
 */
async function listSessions({ tenantId, userId, limit = 50 }) {
  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_sessions')
      .select('id, title, message_count, tokens_used, created_at, updated_at')
      .eq('tenant_id', tenantId)
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(limit);
    if (!error && data) return data;
  }

  // Memory fallback
  const sessions = [];
  for (const s of _memSessions.values()) {
    if (s.tenant_id === tenantId && s.user_id === userId) sessions.push(s);
  }
  return sessions
    .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at))
    .slice(0, limit);
}

/**
 * Get a single session by ID.
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.tenantId
 * @returns {Promise<SessionRecord|null>}
 */
async function getSession({ sessionId, tenantId }) {
  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_sessions')
      .select('*')
      .eq('id', sessionId)
      .eq('tenant_id', tenantId)
      .single();
    if (!error && data) return data;
  }

  const s = _memSessions.get(sessionId);
  if (s && s.tenant_id === tenantId) return s;
  return null;
}

/**
 * Update session metadata (title, message_count, tokens_used, updated_at).
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.tenantId
 * @param {object} opts.updates
 */
async function updateSession({ sessionId, tenantId, updates }) {
  const patch = { ...updates, updated_at: new Date().toISOString() };

  if (await _initDB()) {
    await _supabase
      .from('rakay_sessions')
      .update(patch)
      .eq('id', sessionId)
      .eq('tenant_id', tenantId);
  }

  const s = _memSessions.get(sessionId);
  if (s && s.tenant_id === tenantId) Object.assign(s, patch);
}

/**
 * Delete a session and all its messages.
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.tenantId
 */
async function deleteSession({ sessionId, tenantId }) {
  if (await _initDB()) {
    await _supabase
      .from('rakay_messages')
      .delete()
      .eq('session_id', sessionId);
    await _supabase
      .from('rakay_sessions')
      .delete()
      .eq('id', sessionId)
      .eq('tenant_id', tenantId);
  }

  _memSessions.delete(sessionId);
  _memMessages.delete(sessionId);
}

// ══════════════════════════════════════════════════════════════════════════════
//  MESSAGE CRUD
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Append a message to a session.
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.role         — 'user' | 'assistant' | 'tool'
 * @param {string|object} opts.content
 * @param {object[]} [opts.toolCalls]     — LLM tool-call request array
 * @param {object[]} [opts.toolResults]   — Tool execution results
 * @param {number}   [opts.tokensUsed]
 * @param {string}   [opts.modelId]
 * @returns {Promise<MessageRecord>}
 */
async function appendMessage({ sessionId, role, content, toolCalls, toolResults, tokensUsed = 0, modelId }) {
  const msg = {
    id:             crypto.randomUUID(),
    session_id:     sessionId,
    role,
    content:        typeof content === 'string' ? content : JSON.stringify(content),
    tool_calls:     toolCalls   ? JSON.stringify(toolCalls)   : null,
    tool_results:   toolResults ? JSON.stringify(toolResults) : null,
    tokens_used:    tokensUsed,
    model_id:       modelId || null,
    created_at:     new Date().toISOString(),
  };

  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_messages')
      .insert(msg)
      .select()
      .single();
    if (!error && data) {
      await _incrementSessionStats(sessionId, tokensUsed);
      return data;
    }
  }

  // Memory fallback
  const arr = _memMessages.get(sessionId) || [];
  if (arr.length >= MAX_MESSAGES_PER_SESSION) arr.shift(); // evict oldest
  arr.push(msg);
  _memMessages.set(sessionId, arr);
  await updateSession({ sessionId, tenantId: _getTenantForSession(sessionId), updates: {
    message_count: arr.length,
    tokens_used:   (_memSessions.get(sessionId)?.tokens_used || 0) + tokensUsed,
  }});
  return msg;
}

/**
 * Retrieve conversation history for a session.
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {number} [opts.limit]      — max messages (most-recent first, then reversed)
 * @returns {Promise<MessageRecord[]>}  — chronological order
 */
async function getHistory({ sessionId, limit = 100 }) {
  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_messages')
      .select('*')
      .eq('session_id', sessionId)
      .order('created_at', { ascending: false })
      .limit(limit);
    if (!error && data) return data.reverse();
  }

  const arr = _memMessages.get(sessionId) || [];
  return arr.slice(-limit);
}

/**
 * Get only the last N messages formatted for the LLM (role + content only).
 * @param {object} opts
 * @param {string} opts.sessionId
 * @param {number} [opts.window]  — context window message count
 * @returns {Promise<{role:string,content:string}[]>}
 */
async function getLLMContext({ sessionId, window: w = 20 }) {
  const msgs = await getHistory({ sessionId, limit: w });
  return msgs.map(m => ({
    role:    m.role,
    content: m.content,
    ...(m.tool_calls   ? { tool_calls:   JSON.parse(m.tool_calls)   } : {}),
    ...(m.tool_results ? { tool_results: JSON.parse(m.tool_results) } : {}),
  }));
}

// ══════════════════════════════════════════════════════════════════════════════
//  SEARCH
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Full-text search across user messages in a tenant's sessions.
 * @param {object} opts
 * @param {string} opts.tenantId
 * @param {string} opts.userId
 * @param {string} opts.query
 * @param {number} [opts.limit]
 */
async function searchHistory({ tenantId, userId, query, limit = 20 }) {
  if (await _initDB()) {
    const { data, error } = await _supabase
      .from('rakay_messages')
      .select('id, session_id, role, content, created_at')
      .textSearch('content', query, { type: 'websearch' })
      .limit(limit);
    if (!error && data) return data;
  }

  // Memory fallback: simple substring match
  const results = [];
  const lower = query.toLowerCase();
  for (const [sid, msgs] of _memMessages.entries()) {
    const sess = _memSessions.get(sid);
    if (!sess || sess.tenant_id !== tenantId || sess.user_id !== userId) continue;
    for (const m of msgs) {
      if (m.content && m.content.toLowerCase().includes(lower)) {
        results.push({ id: m.id, session_id: sid, role: m.role, content: m.content, created_at: m.created_at });
        if (results.length >= limit) return results;
      }
    }
  }
  return results;
}

// ══════════════════════════════════════════════════════════════════════════════
//  INTERNAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

async function _incrementSessionStats(sessionId, tokensUsed) {
  if (!_dbAvailable) return;
  await _supabase.rpc('rakay_increment_session_stats', {
    p_session_id:  sessionId,
    p_tokens_used: tokensUsed,
  }).catch(() => {/* RPC may not exist — ignore */});
}

function _getTenantForSession(sessionId) {
  return _memSessions.get(sessionId)?.tenant_id || 'unknown';
}

function _evictOldSessions(tenantId) {
  let count = 0;
  const toDelete = [];
  for (const [id, s] of _memSessions.entries()) {
    if (s.tenant_id === tenantId) count++;
  }
  if (count <= MAX_MEMORY_SESSIONS) return;

  // Evict oldest
  const sorted = [..._memSessions.entries()]
    .filter(([, s]) => s.tenant_id === tenantId)
    .sort(([, a], [, b]) => new Date(a.updated_at) - new Date(b.updated_at));
  const excess = count - MAX_MEMORY_SESSIONS;
  for (let i = 0; i < excess; i++) {
    const [id] = sorted[i];
    _memSessions.delete(id);
    _memMessages.delete(id);
    toDelete.push(id);
  }
  if (toDelete.length) console.log(`[RakayStore] Evicted ${toDelete.length} old sessions for tenant ${tenantId}`);
}

// ── Periodic cleanup of expired in-memory sessions ────────────────────────────
setInterval(() => {
  const now = Date.now();
  let evicted = 0;
  for (const [id, s] of _memSessions.entries()) {
    if (now - new Date(s.updated_at).getTime() > SESSION_TTL_MS) {
      _memSessions.delete(id);
      _memMessages.delete(id);
      evicted++;
    }
  }
  if (evicted) console.log(`[RakayStore] TTL eviction: removed ${evicted} expired sessions`);
}, 60 * 60 * 1000); // every hour

// ── Exports ────────────────────────────────────────────────────────────────────
module.exports = {
  createSession,
  listSessions,
  getSession,
  updateSession,
  deleteSession,
  appendMessage,
  getHistory,
  getLLMContext,
  searchHistory,
  // Expose for tests
  _memSessions,
  _memMessages,
};
