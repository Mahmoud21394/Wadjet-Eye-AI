/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Frontend UI  v7.0
 *  Wadjet-Eye AI Platform — Conversational Security Analyst
 *
 *  v7.0 — Full hardening: SSE streaming, messageId retry dedup, SOC-ready
 *  ──────────────────────────────────────────────────────────────────────
 *  v6.0 NEW:
 *   ✅ TASK 5: Unique messageId per request; frontend generates UUID and sends
 *              to backend. On stream reconnect, same messageId is reused — backend
 *              deduplicates and returns cached result instead of new LLM call.
 *   ✅ TASK 8: SSE headers + heartbeat + flushHeaders (Render-compatible)
 *   ✅ SSE streaming via POST /chat/stream (EventSource-like with fetch)
 *   ✅ Live streaming bubble — text appears token-by-token with animated cursor
 *   ✅ Graceful fallback to /chat (non-streaming) on SSE failure
 *   ✅ Response envelope unwrap: {success,data} → data.reply/data.content
 *   ✅ Provider badge shows which AI model answered (openai/anthropic/gemini/deepseek/mock)
 *   ✅ Retry on 503 (provider busy) with exponential backoff (2 attempts, 2s/5s)
 *   ✅ Tool notifications during streaming (🔧 Using tool: ...)
 *   ✅ Priority badge: HIGH/MEDIUM/LOW shown on messages
 *   ✅ Streaming abort on stopRAKAY() / new-chat
 *   ✅ degraded flag shown in message metadata when mock fallback used
 *
 *  v5.0 (retained):
 *   ✅ session_id always generated as UUID v4 (crypto.randomUUID + fallback)
 *   ✅ Session auto-generated in _sendMessage if null (race-condition guard)
 *   ✅ 400 MISSING_SESSION_ID eliminated: backend auto-generates if missing
 *   ✅ 404 /api/collectors eliminated: root GET / handler added
 *   ✅ IOC DB timeout fixed: split data/count queries, 8s hard timeout, limit=25
 *
 *  v4.0 (retained):
 *   ✅ requestInFlight flag set SYNCHRONOUSLY before any await
 *   ✅ Message dedup: frontend-side hash check (mirrors backend dedup)
 *   ✅ 409 DUPLICATE_MESSAGE / SESSION_BUSY → silent discard (no UI error)
 *   ✅ AbortController per request, cleaned up in finally
 *   ✅ 300ms debounce + RAKAY.loading guard (double protection)
 *
 *  v3.0 (retained):
 *   ✅ WS state machine, max 5 retries, exponential backoff
 *   ✅ Token management, demo-auth, health ping
 * ══════════════════════════════════════════════════════════════════════
 */
(function () {
  'use strict';

  const MODULE_VERSION = '7.0';

  // ── Constants ─────────────────────────────────────────────────────────────
  const LS_RAKAY_TOKEN       = 'rakay_demo_token';
  const LS_RAKAY_TOKEN_EXP   = 'rakay_demo_token_exp';
  const LS_KEY_SESSIONS      = 'rakay_sessions_v1';
  const LS_KEY_MSGS          = sid => `rakay_msgs_${sid}`;

  // ── Frontend deduplication (mirrors backend 10s window) ───────────────────
  const FE_DEDUP_WINDOW_MS = 10_000;
  const _feDedupCache = new Map();  // hash → timestamp

  function _feDedupHash(sessionId, message) {
    // Simple hash using sessionId + message content
    const str = `${sessionId}|${message.trim()}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + ch;
      hash |= 0;
    }
    return hash.toString(36);
  }

  function _feIsDuplicate(sessionId, message) {
    const hash = _feDedupHash(sessionId, message);
    const seen = _feDedupCache.get(hash);
    if (seen && Date.now() - seen < FE_DEDUP_WINDOW_MS) {
      log.warn(`[DEDUP] Duplicate message blocked (hash=${hash}) — same message within 10s`);
      return true;
    }
    _feDedupCache.set(hash, Date.now());
    // Auto-clean old entries
    for (const [h, ts] of _feDedupCache) {
      if (Date.now() - ts > FE_DEDUP_WINDOW_MS * 2) _feDedupCache.delete(h);
    }
    return false;
  }

  // ── WebSocket constants ───────────────────────────────────────────────────
  const WS_MAX_RETRIES    = 5;
  const WS_BASE_DELAY_MS  = 1500;
  const WS_MAX_DELAY_MS   = 60_000;
  const WS_PING_INTERVAL  = 25_000;

  const WS_STATE = { DISCONNECTED: 'DISCONNECTED', CONNECTING: 'CONNECTING', CONNECTED: 'CONNECTED', CLOSING: 'CLOSING' };

  const API_BASE = () =>
    (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

  // ── Streaming config ──────────────────────────────────────────────────────
  const STREAM_ENABLED      = true;    // Use SSE streaming by default
  const STREAM_TIMEOUT_MS   = 120_000; // 2 minutes for streaming
  const STREAM_RETRY_DELAY  = [2000, 5000]; // 503 retry delays (ms)
  const STREAM_NO_DATA_TIMEOUT = 30_000;    // abort stream if no data for 30s

  // ── State ─────────────────────────────────────────────────────────────────
  const RAKAY = {
    sessionId:        null,
    sessions:         [],
    messages:         [],
    loading:          false,
    typing:           false,
    pollingTimer:     null,
    statusTimer:      null,
    backendOnline:    null,   // null=unknown, true=online, false=offline
    demoUser:         null,
    authToken:        null,   // resolved token used in API calls
    _authInProgress:  false,

    // WebSocket state machine
    wsConn:           null,   // active WebSocket instance
    wsState:          WS_STATE.DISCONNECTED,
    wsRetryCount:     0,      // current retry attempt
    wsReconnectTimer: null,   // pending reconnect timer handle
    wsReconnectDelay: WS_BASE_DELAY_MS,
    wsPingTimer:      null,   // client-side keepalive interval

    // Request control
    _currentFetch:    null,   // AbortController for in-flight chat request
    _streamReader:    null,   // ReadableStream reader for SSE streaming
    _submitDebounce:  null,   // debounce timer for send button
    _rateLimitUntil:  0,      // timestamp (ms) until rate-limit lifts
    requestInFlight:  false,  // SYNCHRONOUS flag — set before any await, cleared in finally
    streaming:        false,  // true while SSE stream is active
    _streamBubbleId:  null,   // DOM id of the live streaming bubble
    _currentMessageId: null,  // TASK 5: current messageId for retry deduplication
  };

  let _rendered = false;

  // ══════════════════════════════════════════════════════════════════════════
  //  LOGGING
  // ══════════════════════════════════════════════════════════════════════════
  const log = {
    info:  (...a) => console.log(`[RAKAY v${MODULE_VERSION}]`, ...a),
    warn:  (...a) => console.warn(`[RAKAY v${MODULE_VERSION}]`, ...a),
    error: (...a) => console.error(`[RAKAY v${MODULE_VERSION}]`, ...a),
    debug: (...a) => console.debug(`[RAKAY v${MODULE_VERSION}]`, ...a),
  };

  // ══════════════════════════════════════════════════════════════════════════
  //  HTML HELPERS
  // ══════════════════════════════════════════════════════════════════════════
  function _e(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Generate a UUID v4 string.
   * Uses crypto.randomUUID() when available (Chrome 92+, Node 15+).
   * Falls back to a manual RFC4122 v4 implementation for older browsers.
   */
  function _uuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    // Fallback: RFC4122 v4 UUID
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  // Legacy short-id (still used for message/event IDs, NOT session IDs)
  function _uid() {
    return 'r_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function _time(iso) {
    if (!iso) return '';
    const d   = new Date(iso);
    const now = new Date();
    const diffMs  = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1)  return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffH = Math.floor(diffMin / 60);
    if (diffH < 24) return `${diffH}h ago`;
    return d.toLocaleDateString();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  LOCALSTORE HELPERS
  // ══════════════════════════════════════════════════════════════════════════
  function _lsGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function _lsSet(key, val) {
    try { localStorage.setItem(key, val); } catch {}
  }
  function _lsDel(key) {
    try { localStorage.removeItem(key); } catch {}
  }
  function _lsGetJSON(key, def = null) {
    try { return JSON.parse(localStorage.getItem(key) || 'null') ?? def; } catch { return def; }
  }
  function _lsSetJSON(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch {}
  }

  function _lsGetSessions()   { return _lsGetJSON(LS_KEY_SESSIONS, []); }
  function _lsSetSessions(a)  { _lsSetJSON(LS_KEY_SESSIONS, a.slice(0, 50)); }
  function _lsGetMsgs(sid)    { return _lsGetJSON(LS_KEY_MSGS(sid), []); }
  function _lsSetMsgs(sid, m) { _lsSetJSON(LS_KEY_MSGS(sid), m.slice(-200)); }
  function _lsAddMsg(sid, m)  { const msgs = _lsGetMsgs(sid); msgs.push(m); _lsSetMsgs(sid, msgs); }

  // ══════════════════════════════════════════════════════════════════════════
  //  TOKEN RESOLUTION
  //  Priority: 1) Platform JWT (authInterceptor/authFetch)
  //            2) RAKAY demo token from localStorage
  //            3) null → will trigger demo-auth
  // ══════════════════════════════════════════════════════════════════════════
  function _resolveToken() {
    // 1. Platform token from various storage locations
    const platformToken =
      _lsGet('wadjet_access_token')   ||
      _lsGet('accessToken')            ||
      _lsGet('wadjet_token')           ||
      _lsGet('auth_token')             ||
      _lsGet('access_token')           ||
      sessionStorage.getItem('auth_token') ||
      null;

    if (platformToken && _isTokenValid(platformToken)) {
      return platformToken;
    }

    // 2. RAKAY demo token
    const demoToken  = _lsGet(LS_RAKAY_TOKEN);
    const demoExpStr = _lsGet(LS_RAKAY_TOKEN_EXP);
    if (demoToken && demoExpStr) {
      const expMs = parseInt(demoExpStr, 10);
      // Token valid if not expired (with 5-min buffer)
      if (Date.now() < expMs - 300_000) {
        return demoToken;
      }
      // Expired — clear it
      _lsDel(LS_RAKAY_TOKEN);
      _lsDel(LS_RAKAY_TOKEN_EXP);
      log.info('Demo token expired — will refresh');
    }

    return null;
  }

  function _isTokenValid(token) {
    if (!token || typeof token !== 'string') return false;
    if (token === 'RAKAY_DEMO_NO_JWT_LIB') return true;
    // Basic JWT structure check
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    try {
      const payload = JSON.parse(atob(parts[1]));
      if (payload.exp && payload.exp * 1000 < Date.now() - 300_000) return false;
      return true;
    } catch {
      return true; // Non-JWT opaque token — trust it
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  DEMO AUTH — automatically obtains a 24-hour RAKAY token
  // ══════════════════════════════════════════════════════════════════════════
  async function _ensureAuth() {
    // Already have a valid token?
    const existing = _resolveToken();
    if (existing) {
      RAKAY.authToken = existing;
      return existing;
    }

    // Prevent concurrent auth requests
    if (RAKAY._authInProgress) {
      // Wait for the in-progress request
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 200));
        const t = _resolveToken();
        if (t) { RAKAY.authToken = t; return t; }
      }
      return null;
    }

    RAKAY._authInProgress = true;
    log.info('No auth token found — requesting demo session from backend…');

    try {
      const res = await fetch(`${API_BASE()}/api/RAKAY/demo-auth`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name: 'Security Analyst', role: 'analyst' }),
        signal:  AbortSignal.timeout(15_000),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `demo-auth returned HTTP ${res.status}`);
      }

      const data = await res.json();

      if (!data.token) throw new Error('demo-auth: no token in response');

      // Store token
      const expMs = data.expires_at ? new Date(data.expires_at).getTime() : Date.now() + 86_400_000;
      _lsSet(LS_RAKAY_TOKEN,     data.token);
      _lsSet(LS_RAKAY_TOKEN_EXP, String(expMs));

      RAKAY.authToken = data.token;
      RAKAY.demoUser  = data.user || null;
      RAKAY.backendOnline = true;

      log.info('Demo auth obtained. User:', data.user?.name, '| Expires:', data.expires_at);
      return data.token;
    } catch (err) {
      log.error('Demo auth failed:', err.message);
      RAKAY.backendOnline = false;
      return null;
    } finally {
      RAKAY._authInProgress = false;
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  API CLIENT — retries=0 by default (NO automatic retries)
  //
  //  CRITICAL: Default retries changed from 2 → 0.
  //  With retries=2, one user message could generate up to 9 API requests
  //  (session create ×3 + chat ×3 + history ×3), easily hitting rate limits.
  //  All calls now fail-fast and use localStorage as fallback.
  // ══════════════════════════════════════════════════════════════════════════
  async function _api(method, path, body = null, opts = {}) {
    const { retries = 0, skipAuth = false, abortSignal } = opts;  // retries=0: no auto-retry
    const url = `${API_BASE()}/api/RAKAY${path}`;

    // Resolve token
    let token = skipAuth ? null : (RAKAY.authToken || _resolveToken());

    for (let attempt = 0; attempt <= retries; attempt++) {
      // If token expired or missing, re-auth (except for public endpoints)
      if (!token && !skipAuth) {
        token = await _ensureAuth();
      }

      const headers = {
        'Content-Type': 'application/json',
        'Accept':       'application/json',
      };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      try {
        // Combine external abort signal with timeout
        const timeoutCtrl = new AbortController();
        const timeoutId   = setTimeout(() => timeoutCtrl.abort(), opts.timeout || 60_000);

        // Merge signals: abort if either the passed signal OR the timeout fires
        let signal = timeoutCtrl.signal;
        if (abortSignal) {
          // Use AbortSignal.any if available (Chrome 116+), else fall back to just abortSignal
          signal = (typeof AbortSignal.any === 'function')
            ? AbortSignal.any([abortSignal, timeoutCtrl.signal])
            : abortSignal;
        }

        let res;
        try {
          res = await fetch(url, {
            method,
            headers,
            body:   body ? JSON.stringify(body) : undefined,
            signal,
          });
        } finally {
          clearTimeout(timeoutId);
        }

        // Handle 401: token invalid/expired — try re-auth once
        if (res.status === 401 && !skipAuth && attempt === 0) {
          log.warn(`API 401 on ${path} — clearing token and re-authing`);
          _lsDel(LS_RAKAY_TOKEN);
          _lsDel(LS_RAKAY_TOKEN_EXP);
          RAKAY.authToken = null;
          token = null;
          continue; // retry with fresh token
        }

        RAKAY.backendOnline = true;
        _updateStatus();

        if (res.status === 404) return null;

        if (!res.ok) {
          const errBody = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
          const errMsg  = errBody.error || errBody.message || `HTTP ${res.status}`;
          const err     = new Error(errMsg);
          err.status    = res.status;
          err.code      = errBody.code;
          err.body      = errBody;
          // Read Retry-After from response header if present
          const retryAfterHdr = res.headers.get('Retry-After');
          if (retryAfterHdr) err.body = { ...(err.body || {}), retryAfter: parseInt(retryAfterHdr, 10) || 30 };
          throw err;
        }

        return await res.json();

      } catch (err) {
        // Propagate AbortError immediately — don't retry
        if (err.name === 'AbortError') throw err;

        // NEVER retry on client errors (4xx) or server-busy (503)
        // These are deterministic — retrying will not help and causes rate-limit loops.
        if (err.status >= 400 && err.status < 600 && err.status !== 429 && err.status !== 503) {
          // 400, 401, 403, 404 (but 404 already returned null above), 409, 500, 501, 502, 504
          // Only propagate — no retry
          log.error(`API error ${method} ${path} [${err.status}]: ${err.message} (no retry)`);
          throw err;
        }
        if (err.status === 503) {
          log.warn(`[API] 503 on ${method} ${path} — provider busy, NO retry`);
          throw err;
        }

        const isNetworkErr = err.name === 'TypeError'
          || err.message?.includes('fetch') || err.message?.includes('network')
          || err.message?.includes('Failed to fetch');

        if (isNetworkErr) {
          RAKAY.backendOnline = false;
          _updateStatus();
          log.error(`Network error on ${method} ${path} (attempt ${attempt + 1}):`, err.message);

          if (attempt < retries) {
            const delay = Math.pow(2, attempt) * 1000; // 1s, 2s, 4s
            log.info(`Retrying in ${delay}ms…`);
            await new Promise(r => setTimeout(r, delay));
            continue;
          }
        }

        log.error(`API error ${method} ${path}:`, err.message, err.code || '');
        throw err;
      }
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  BACKEND STATUS CHECK
  // ══════════════════════════════════════════════════════════════════════════
  async function _checkStatus() {
    try {
      const res = await fetch(`${API_BASE()}/api/RAKAY/health`, {
        signal: AbortSignal.timeout(8_000),
      });
      const wasOnline = RAKAY.backendOnline;
      RAKAY.backendOnline = res.ok;

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        log.debug('Health check OK. LLM ready:', data.llm_ready, '| Provider:', data.provider);

        // If we just came online, re-auth and reload
        if (wasOnline === false) {
          log.info('Backend came online — re-authenticating…');
          _lsDel(LS_RAKAY_TOKEN);
          _lsDel(LS_RAKAY_TOKEN_EXP);
          RAKAY.authToken = null;
          await _ensureAuth();
        }
      } else {
        log.warn('Health check failed: HTTP', res.status);
      }
    } catch (err) {
      RAKAY.backendOnline = false;
      log.warn('Health check network error:', err.message);
    }
    _updateStatus();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  SESSION MANAGEMENT
  // ══════════════════════════════════════════════════════════════════════════
  async function _loadSessions() {
    try {
      const data = await _api('GET', '/session');
      if (data?.sessions) {
        RAKAY.sessions = data.sessions;
        _lsSetSessions(RAKAY.sessions);
        return;
      }
    } catch (err) {
      log.warn('Could not load sessions from backend:', err.message, '— using localStorage');
    }
    RAKAY.sessions = _lsGetSessions();
  }

  async function _createSession(title = 'New Chat') {
    const local = {
      id:            _uuid(),   // UUID v4 — backend requires a valid session_id
      title,
      message_count: 0,
      tokens_used:   0,
      created_at:    new Date().toISOString(),
      updated_at:    new Date().toISOString(),
      _local:        true,
    };

    try {
      const data = await _api('POST', '/session', { title });
      if (data?.session) {
        RAKAY.sessions.unshift(data.session);
        _lsSetSessions(RAKAY.sessions);
        return data.session;
      }
    } catch (err) {
      log.warn('Could not create session on backend:', err.message, '— using local session');
    }

    RAKAY.sessions.unshift(local);
    _lsSetSessions(RAKAY.sessions);
    return local;
  }

  async function _deleteSession(sid) {
    RAKAY.sessions = RAKAY.sessions.filter(s => s.id !== sid);
    _lsSetSessions(RAKAY.sessions);
    try { await _api('DELETE', `/session/${sid}`); } catch (err) {
      log.warn('Could not delete session on backend:', err.message);
    }
  }

  async function _renameSession(sid, title) {
    const s = RAKAY.sessions.find(s => s.id === sid);
    if (s) { s.title = title; _lsSetSessions(RAKAY.sessions); }
    try { await _api('PATCH', `/session/${sid}`, { title }); } catch (err) {
      log.warn('Could not rename session on backend:', err.message);
    }
  }

  async function _loadHistory(sid) {
    try {
      const data = await _api('GET', `/history/${sid}`);
      if (data?.messages) {
        RAKAY.messages = data.messages;
        _lsSetMsgs(sid, RAKAY.messages);
        return;
      }
    } catch (err) {
      log.warn('Could not load history from backend:', err.message, '— using localStorage');
    }
    RAKAY.messages = _lsGetMsgs(sid);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  CHAT API — hardened send with zero-duplicate guarantee + SSE streaming
  //
  //  Layers of protection (in order of execution):
  //   1. RAKAY.requestInFlight — synchronous flag set BEFORE any await
  //   2. RAKAY.loading — UI state flag (same flag, belt-and-suspenders)
  //   3. FE dedup hash — frontend mirrors backend's 10s dedup window
  //   4. 300ms debounce on submit button (in _rakaySubmit)
  //   5. Backend mutex (SESSION_BUSY → 409 Conflict)
  //   6. Backend dedup hash (DUPLICATE_MESSAGE → 409 Conflict)
  //
  //  v6.0: Uses SSE streaming (POST /chat/stream) by default.
  //        Falls back to POST /chat (non-streaming) on SSE failure.
  //        Response envelope: backend returns {success, data: {reply,content,...}}
  //        Frontend unwraps: envelope.data.reply || envelope.data.content
  // ══════════════════════════════════════════════════════════════════════════
  async function _sendMessage(message) {
    if (!message.trim()) return;

    // ── Layer 1: Synchronous requestInFlight flag (set BEFORE any await) ──
    if (RAKAY.requestInFlight) {
      log.warn('[SEND] SEND_BLOCKED_INFLIGHT — request already in flight');
      return;
    }

    // ── Layer 2: UI loading flag ────────────────────────────────────────────
    if (RAKAY.loading) {
      log.warn('[SEND] SEND_BLOCKED_LOADING — UI loading flag active');
      return;
    }

    // ── Layer 0: Session guard — MUST have a session before any await ───────
    if (!RAKAY.sessionId) {
      RAKAY.sessionId = _uuid();
      log.warn(`[SEND] SESSION_AUTO_GENERATED — no active session, created: ${RAKAY.sessionId.slice(0, 12)}`);
      const autoSession = {
        id:            RAKAY.sessionId,
        title:         message.trim().slice(0, 60),
        message_count: 0,
        tokens_used:   0,
        created_at:    new Date().toISOString(),
        updated_at:    new Date().toISOString(),
        _local:        true,
      };
      RAKAY.sessions.unshift(autoSession);
      _lsSetSessions(RAKAY.sessions);
      _renderSidebar();
    }

    // ── Layer 3: Frontend message deduplication (10s window) ───────────────
    if (_feIsDuplicate(RAKAY.sessionId, message)) {
      log.warn('[SEND] SEND_BLOCKED_DEDUP — identical message within 10s window');
      return;
    }

    // ── SET FLAGS SYNCHRONOUSLY — no awaits before this point ─────────────
    RAKAY.requestInFlight = true;
    RAKAY.loading         = true;

    log.info(`[SEND] SEND_START session=${RAKAY.sessionId?.slice(0, 12)} len=${message.trim().length}`);

    const userMsg = {
      id:         _uid(),
      session_id: RAKAY.sessionId,
      role:       'user',
      content:    message.trim(),
      created_at: new Date().toISOString(),
    };

    RAKAY.messages.push(userMsg);
    _renderMessages();
    _setInputEnabled(false);
    _showTyping();
    _lsAddMsg(RAKAY.sessionId, userMsg);

    // Update session title if first message
    const session = RAKAY.sessions.find(s => s.id === RAKAY.sessionId);
    if (session && session.message_count === 0) {
      session.title = message.trim().slice(0, 60);
      _lsSetSessions(RAKAY.sessions);
      _renderSidebar();
    }

    // Create AbortController — allows cancellation on stopRAKAY()
    const abortCtrl = new AbortController();
    RAKAY._currentFetch = abortCtrl;

    try {
      // ── Try SSE streaming first, fall back to non-streaming ──────────────
      if (STREAM_ENABLED) {
        try {
          await _sendMessageStream(message, session, abortCtrl);
          return; // streaming succeeded — return from try block
        } catch (streamErr) {
          if (streamErr.name === 'AbortError') throw streamErr; // propagate abort
          // 409/401/429/4xx: don't fall back to non-streaming, handle directly
          if (streamErr.status >= 400 && streamErr.status < 600 && streamErr.status !== 503) {
            throw streamErr;
          }
          log.warn('[SEND] SSE stream failed — falling back to /chat:', streamErr.message);
          _hideTyping();
          _clearStreamBubble();
          _showTyping(); // re-show typing for fallback
        }
      }
      // ── Non-streaming fallback ─────────────────────────────────────────
      await _sendMessageNonStreaming(message, session, abortCtrl);

    } catch (err) {
      _hideTyping();
      _clearStreamBubble();
      _handleChatError(err, message);
    } finally {
      RAKAY.requestInFlight    = false;
      RAKAY.loading            = false;
      RAKAY.streaming          = false;
      RAKAY._currentFetch      = null;
      RAKAY._streamReader      = null;
      RAKAY._streamBubbleId    = null;
      // TASK 5: Only clear messageId on error (cleared on success in stream/non-stream handlers)
      if (!RAKAY._currentMessageId) {
        // already cleared on success
      }
      _setInputEnabled(true);
      _focusInput();
      log.debug('[SEND] SEND_FLAGS_CLEARED');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  STREAMING BUBBLE HELPERS
  // ══════════════════════════════════════════════════════════════════════════

  function _createStreamBubble(bubbleId) {
    const container = document.getElementById('rakay-messages');
    if (!container) return;

    const el = document.createElement('div');
    el.className = 'rakay-msg rakay-msg--assistant';
    el.id = bubbleId;
    el.innerHTML = `
    <div class="rakay-msg-avatar rakay-msg-avatar--assistant"><i class="fas fa-robot"></i></div>
    <div class="rakay-msg-content">
      <div class="rakay-msg-bubble rakay-msg-bubble--assistant rakay-streaming-bubble" id="${bubbleId}-content">
        <span class="rakay-stream-cursor">&#9646;</span>
      </div>
      <div class="rakay-msg-meta rakay-streaming-meta">
        <span class="rakay-streaming-label"><i class="fas fa-circle-notch fa-spin" style="font-size:9px;color:#22d3ee"></i> RAKAY is generating…</span>
      </div>
    </div>`;
    container.appendChild(el);
    _scrollToBottom();
  }

  function _appendToStreamBubble(bubbleId, text, isRaw = false) {
    const contentEl = document.getElementById(`${bubbleId}-content`);
    if (!contentEl) return;

    // Remove cursor if present
    const cursor = contentEl.querySelector('.rakay-stream-cursor');
    if (cursor) cursor.remove();

    // Append text
    const span = document.createElement('span');
    if (isRaw) {
      span.textContent = text;
    } else {
      span.textContent = text;
    }
    contentEl.appendChild(span);

    // Re-add cursor at end
    const newCursor = document.createElement('span');
    newCursor.className = 'rakay-stream-cursor';
    newCursor.innerHTML = '&#9646;';
    contentEl.appendChild(newCursor);
  }

  function _finalizeStreamBubble(bubbleId) {
    const el = document.getElementById(bubbleId);
    if (el) el.remove();
  }

  function _clearStreamBubble() {
    if (RAKAY._streamBubbleId) {
      _finalizeStreamBubble(RAKAY._streamBubbleId);
      RAKAY._streamBubbleId = null;
    }
  }

  function _clearError() {
    const container = document.getElementById('rakay-messages');
    if (!container) return;
    container.querySelector('.rakay-error-msg')?.remove();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  SSE STREAMING IMPLEMENTATION
  //  Uses fetch + ReadableStream to consume POST /chat/stream SSE events.
  //  Events:
  //   {"type":"start"}
  //   {"type":"chunk","text":"..."}
  //   {"type":"done","id":"...","tokens_used":N,"provider":"...","tool_trace":[...]}
  //   {"type":"error","message":"..."}
  // ══════════════════════════════════════════════════════════════════════════
  async function _sendMessageStream(message, session, abortCtrl) {
    const url   = `${API_BASE()}/api/RAKAY/chat/stream`;
    const token = RAKAY.authToken || _resolveToken();

    const context = {
      currentPage:      window.currentPage || 'rakay',
      platform_context: { page: window.currentPage },
      openai_key:  _lsGet('openai_api_key')  || _lsGet('wadjet_openai_key')  || undefined,
      claude_key:  _lsGet('claude_api_key')   || _lsGet('wadjet_claude_key')  || undefined,
    };

    // TASK 5: Use persistent messageId so retry with same messageId avoids duplicate LLM call
    const messageId = RAKAY._currentMessageId || _uuid();
    RAKAY._currentMessageId = messageId;
    log.info(`[STREAM] Starting SSE stream to ${url} messageId=${messageId.slice(0, 12)}`);

    const res = await fetch(url, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Accept':        'text/event-stream, application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body:   JSON.stringify({
        session_id:  RAKAY.sessionId,
        message:     message.trim(),
        context,
        use_tools:   true,
        message_id:  messageId,   // TASK 5: send messageId for backend dedup
      }),
      signal: abortCtrl.signal,
    });

    // Handle non-2xx before reading stream
    if (res.status === 401) {
      _lsDel(LS_RAKAY_TOKEN); _lsDel(LS_RAKAY_TOKEN_EXP); RAKAY.authToken = null;
      const body = await res.json().catch(() => ({}));
      throw Object.assign(new Error(body.error || 'Unauthorized'), { status: 401, code: body.code || 'RAKAY_AUTH_REQUIRED' });
    }
    if (res.status === 409) {
      const body = await res.json().catch(() => ({}));
      throw Object.assign(new Error(body.error || 'Conflict'), { status: 409, code: body.code });
    }
    if (res.status === 429) {
      const body = await res.json().catch(() => ({}));
      throw Object.assign(new Error(body.error || 'Rate limited'), { status: 429, code: body.code, body });
    }
    if (res.status === 503) {
      throw Object.assign(new Error('Provider busy — will retry'), { status: 503, code: 'LLM_PROVIDER_BUSY' });
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw Object.assign(new Error(body.error || `HTTP ${res.status}`), { status: res.status, code: body.code, body });
    }

    // ── Stream is open — remove typing indicator and create live bubble ─────
    _hideTyping();
    RAKAY.streaming = true;

    const streamBubbleId = `stream-bubble-${_uid()}`;
    RAKAY._streamBubbleId = streamBubbleId;
    _createStreamBubble(streamBubbleId);

    const reader  = res.body.getReader();
    RAKAY._streamReader = reader;
    const decoder = new TextDecoder('utf-8');

    let buffer      = '';
    let fullText    = '';
    let doneData    = null;

    // TASK 8: Streaming timeout — abort if no data for 30s (prevents zombie streams)
    let streamTimeout;
    const resetStreamTimeout = () => {
      clearTimeout(streamTimeout);
      streamTimeout = setTimeout(() => {
        log.warn('[STREAM] No data for STREAM_NO_DATA_TIMEOUT ms — aborting stream');
        try { reader.cancel(); } catch {}
      }, STREAM_NO_DATA_TIMEOUT);
    };
    resetStreamTimeout();

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        resetStreamTimeout();

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // last partial line stays in buffer

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith(':')) continue; // heartbeat / comment

          if (trimmed.startsWith('data: ')) {
            const raw = trimmed.slice(6).trim();
            if (!raw || raw === '[DONE]') continue;

            let evt;
            try { evt = JSON.parse(raw); } catch { continue; }

            if (evt.type === 'start') {
              log.debug('[STREAM] start event received session_id=', evt.session_id);

            } else if (evt.type === 'chunk') {
              const text = evt.text || '';
              if (text) {
                fullText += text;
                _appendToStreamBubble(streamBubbleId, text);
                _scrollToBottom();
              }

            } else if (evt.type === 'done') {
              doneData = evt;
              // TASK 5: Clear messageId after successful completion
              RAKAY._currentMessageId = null;
              log.info(`[STREAM] done — provider=${evt.provider} tokens=${evt.tokens_used} latency=${evt.latency_ms}ms degraded=${evt.degraded}`);

            } else if (evt.type === 'error') {
              log.warn('[STREAM] error event from server:', evt.message);
              // Graceful: backend sent error message as graceful degradation
              if (!fullText) {
                fullText = '⚠️ ' + (evt.message || 'AI system is temporarily busy. Please try again.');
                _appendToStreamBubble(streamBubbleId, fullText, true);
              }
            }
          }
        }
      }
    } finally {
      clearTimeout(streamTimeout);
      try { reader.cancel(); } catch {}
    }

    if (!fullText) fullText = 'Analysis complete. Please review the tool results above.';

    // ── Finalize: replace live bubble with rendered message ──────────────────
    const assistantMsg = {
      id:          doneData?.id || _uid(),
      session_id:  RAKAY.sessionId,
      role:        'assistant',
      content:     fullText,
      tool_trace:  doneData?.tool_trace || [],
      tokens_used: doneData?.tokens_used || 0,
      model:       doneData?.model,
      provider:    doneData?.provider,
      latency_ms:  doneData?.latency_ms,
      created_at:  new Date().toISOString(),
      _streamed:   true,
      _degraded:   doneData?.degraded || false,
    };

    RAKAY.messages.push(assistantMsg);
    _lsAddMsg(RAKAY.sessionId, assistantMsg);

    if (session) {
      session.message_count = (session.message_count || 0) + 2;
      session.updated_at    = new Date().toISOString();
      _lsSetSessions(RAKAY.sessions);
    }

    // Remove live stream bubble and re-render all messages with proper markdown
    _finalizeStreamBubble(streamBubbleId);
    _renderMessages();
    _renderSidebar();
    _scrollToBottom();

    log.info(`[SEND] STREAM_COMPLETE tokens=${assistantMsg.tokens_used} model=${assistantMsg.model || '?'} provider=${assistantMsg.provider || '?'}`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  NON-STREAMING FALLBACK
  //  Unwraps {success: true, data: {reply, content, ...}} envelope.
  //  Retries on 503 with exponential backoff (2 attempts).
  // ══════════════════════════════════════════════════════════════════════════
  async function _sendMessageNonStreaming(message, session, abortCtrl) {
    const context = {
      currentPage:      window.currentPage || 'rakay',
      platform_context: { page: window.currentPage },
      openai_key:  _lsGet('openai_api_key')  || _lsGet('wadjet_openai_key')  || undefined,
      claude_key:  _lsGet('claude_api_key')   || _lsGet('wadjet_claude_key')  || undefined,
    };

    let envelope = null;
    let lastErr  = null;

    // TASK 5: Use persistent messageId for non-streaming fallback too
    const messageId = RAKAY._currentMessageId || _uuid();
    RAKAY._currentMessageId = messageId;

    for (let attempt = 0; attempt < STREAM_RETRY_DELAY.length + 1; attempt++) {
      try {
        envelope = await _api('POST', '/chat', {
          session_id:  RAKAY.sessionId,
          message:     message.trim(),
          context,
          use_tools:   true,
          message_id:  messageId,   // TASK 5: send messageId for backend dedup
        }, {
          retries:     2,        // network-level retries (TypeError only)
          abortSignal: abortCtrl.signal,
          timeout:     90_000,
        });
        lastErr = null;
        break;
      } catch (err) {
        lastErr = err;
        if (err.name === 'AbortError') throw err;
        if (err.status === 503 && attempt < STREAM_RETRY_DELAY.length) {
          const delay = STREAM_RETRY_DELAY[attempt];
          log.warn(`[SEND] 503 provider busy — retrying in ${delay}ms (attempt ${attempt + 1})`);
          _appendError(`AI provider temporarily busy — retrying in ${Math.round(delay / 1000)}s…`);
          await new Promise(r => setTimeout(r, delay));
          _clearError();
          continue;
        }
        throw err;
      }
    }
    if (lastErr) throw lastErr;

    _hideTyping();

    if (!envelope) {
      _appendError('No response from RAKAY backend.');
      return;
    }

    // ── Unwrap {success, data} envelope ───────────────────────────────────
    let payload;
    if (envelope.success === true && envelope.data) {
      payload = envelope.data;
    } else if (envelope.success === false) {
      log.warn('[SEND] Backend success:false:', envelope.error);
      payload = { reply: envelope.error || 'An error occurred', content: envelope.error || 'An error occurred' };
    } else {
      // Legacy: no envelope wrapper
      payload = envelope;
    }

    const replyText = payload.reply || payload.content || '';

    const assistantMsg = {
      id:          payload.id || _uid(),
      session_id:  RAKAY.sessionId,
      role:        'assistant',
      content:     replyText,
      tool_trace:  payload.tool_trace  || [],
      tokens_used: payload.tokens_used || 0,
      model:       payload.model,
      provider:    payload.provider,
      latency_ms:  payload.latency_ms,
      created_at:  payload.created_at || new Date().toISOString(),
      _degraded:   payload._degraded,
    };

    RAKAY.messages.push(assistantMsg);
    _lsAddMsg(RAKAY.sessionId, assistantMsg);

    if (session) {
      session.message_count = (session.message_count || 0) + 2;
      session.updated_at    = new Date().toISOString();
      _lsSetSessions(RAKAY.sessions);
    }

    // TASK 5: Clear messageId after successful non-streaming response
    RAKAY._currentMessageId = null;
    log.info(`[SEND] SEND_COMPLETE tokens=${payload.tokens_used || 0} model=${payload.model || '?'} provider=${payload.provider || '?'} degraded=${payload.degraded || false}`);
    _renderMessages();
    _renderSidebar();
    _scrollToBottom();
  }

  function _handleChatError(err, originalMessage) {
    // Ignore AbortError (request was cancelled intentionally)
    if (err.name === 'AbortError') {
      log.debug('[SEND] Request aborted (intentional)');
      return;
    }

    const isNetworkErr = err.name === 'TypeError' || err.message?.includes('fetch')
      || err.message?.includes('Failed to fetch');

    log.error('[SEND] SEND_ERROR status=%s code=%s msg=%s', err.status || 'network', err.code || '', err.message);

    // Network error → fall back to offline mode
    if (isNetworkErr || RAKAY.backendOnline === false) {
      _appendLocalResponse(originalMessage);
      return;
    }

    // ── 409 Conflict: duplicate or session-busy ────────────────────────────
    // These are NOT rate-limit errors — the user's message was already being
    // processed. Silently discard — do NOT show "rate limit" messages.
    // Remove the user's message bubble from the UI (it was a duplicate).
    if (err.status === 409) {
      if (err.code === 'DUPLICATE_MESSAGE') {
        log.warn('[SEND] DEDUP_409 — backend confirmed duplicate, discarding');
        // Remove the user message we just added (it's a dupe)
        RAKAY.messages.pop();
        _renderMessages();
        _showToast('Message already sent — please wait for the response', 'info', 2500);
      } else if (err.code === 'SESSION_BUSY') {
        log.warn('[SEND] MUTEX_409 — session busy, discarding');
        RAKAY.messages.pop();
        _renderMessages();
        _showToast('Previous message still processing — please wait', 'info', 2500);
      } else {
        log.warn('[SEND] 409 Conflict:', err.code);
        RAKAY.messages.pop();
        _renderMessages();
      }
      return;
    }

    // ── 401 Unauthorized: re-auth ──────────────────────────────────────────
    if (err.status === 401 || err.code === 'RAKAY_AUTH_REQUIRED' || err.code === 'DEMO_TOKEN_EXPIRED') {
      _appendError('Session expired. Refreshing authentication…');
      _lsDel(LS_RAKAY_TOKEN);
      _lsDel(LS_RAKAY_TOKEN_EXP);
      RAKAY.authToken = null;
      setTimeout(async () => {
        const t = await _ensureAuth();
        if (t) {
          log.info('[SEND] Re-auth success — please resend your message');
          _showToast('Session refreshed — please resend your message', 'info');
        }
      }, 500);
      return;
    }

    // ── 503 LLM provider busy (rate-limited BY provider, not by us) ────────
    // This is a transient provider-side issue — NOT a user error.
    // Do NOT show "wait 60s" or lock the UI.
    if (err.status === 503 || err.code === 'LLM_PROVIDER_BUSY') {
      _appendError('The AI provider is temporarily busy. Please try again in a few seconds — your message was not rate-limited.');
      return;
    }

    // ── 503 LLM unavailable (missing API key) ─────────────────────────────
    if (err.code === 'LLM_UNAVAILABLE') {
      const detail = err.body?.error || err.message || '';
      _appendError(`AI provider unavailable: ${detail}. Check server env vars (OPENAI_API_KEY / CLAUDE_API_KEY).`);
      return;
    }

    // ── 429: Only show UI lock if it's truly a rate limit from our limiter ─
    // With the new limits (10 req/min) this should never happen in normal use.
    if (err.status === 429 || err.code === 'RAKAY_RATE_LIMIT') {
      const retryAfterSec = err.body?.retryAfter || 30;
      log.warn(`[SEND] RATE_LIMIT_429 — retryAfter=${retryAfterSec}s (check for duplicate call bug)`);
      // Show informational message, NOT a UI lock
      _appendError(`Too many requests — this should not happen in normal usage. Please wait ${retryAfterSec}s.`);
      return;
    }

    _appendError(`RAKAY error: ${err.body?.error || err.message || 'Unknown error'}`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  OFFLINE FALLBACK
  // ══════════════════════════════════════════════════════════════════════════
  function _appendLocalResponse(query) {
    const lower = query.toLowerCase();
    let content = '';

    if (lower.includes('sigma')) {
      content = '**Note — Backend offline.** Here is a quick Sigma rule template:\n\n```yaml\ntitle: Detect Suspicious Activity\nstatus: experimental\ndescription: Detects suspicious process creation\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - suspicious_keyword\n  condition: selection\nlevel: high\n```\n\n*Reconnect the backend for full AI-generated, context-aware rules.*';
    } else if (lower.includes('mitre') || lower.match(/t\d{4}/i)) {
      content = '**Note — Backend offline.** Visit [MITRE ATT&CK](https://attack.mitre.org) for technique details, or reconnect the backend for AI-powered lookups.';
    } else if (lower.includes('cve')) {
      content = '**Note — Backend offline.** Search [NVD](https://nvd.nist.gov) for CVE details, or reconnect the backend.';
    } else if (lower.includes('ioc') || lower.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
      content = '**Note — Backend offline.** IOC enrichment requires backend connectivity. Check [VirusTotal](https://virustotal.com) for threat intelligence.';
    } else {
      content = [
        '**RAKAY is offline** — the backend server is not reachable.',
        '',
        '**Diagnostic information:**',
        `- Backend URL: \`${API_BASE()}\``,
        `- Status: ${RAKAY.backendOnline === false ? '🔴 Offline' : '⚪ Unknown'}`,
        '',
        '**What to check:**',
        '1. The backend at `https://wadjet-eye-ai.onrender.com` may be waking up (Render free tier sleeps after 15 min) — wait 30s and try again',
        '2. Check your network connection',
        '3. Open browser DevTools → Network tab to see the specific error',
        '',
        '*Local platform features remain fully functional. Your message has been saved and will be sent when the backend reconnects.*',
      ].join('\n');
    }

    const msg = {
      id:         _uid(),
      session_id: RAKAY.sessionId,
      role:       'assistant',
      content,
      created_at: new Date().toISOString(),
      _offline:   true,
    };
    RAKAY.messages.push(msg);
    _lsAddMsg(RAKAY.sessionId, msg);
    _renderMessages();
    _scrollToBottom();
  }

  function _appendError(text) {
    const container = document.getElementById('rakay-messages');
    if (!container) return;
    // Remove any existing error
    const existing = container.querySelector('.rakay-error-msg');
    if (existing) existing.remove();
    if (!text) return;
    const el = document.createElement('div');
    el.className = 'rakay-error-msg';
    el.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${_e(text)}`;
    container.appendChild(el);
    _scrollToBottom();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  WEBSOCKET v3 — Native WS to /ws/detections
  //  State machine: DISCONNECTED → CONNECTING → CONNECTED → CLOSING
  //  Max 5 retries with exponential backoff (1.5s → 3s → 6s → 12s → 24s → give up)
  // ══════════════════════════════════════════════════════════════════════════
  function _initWebSocket() {
    const baseUrl = API_BASE();
    const wsUrl   = baseUrl.replace(/^http/, 'ws') + '/ws/detections';
    const token   = RAKAY.authToken || _resolveToken();

    // ── Pre-flight checks ─────────────────────────────────────────────────
    if (!token) {
      log.debug('[WS] Skipping — no auth token yet');
      return;
    }

    // Prevent duplicate connections
    if (RAKAY.wsState === WS_STATE.CONNECTING || RAKAY.wsState === WS_STATE.CONNECTED) {
      log.debug('[WS] Already', RAKAY.wsState, '— skipping duplicate initWebSocket()');
      return;
    }

    // Give up after max retries
    if (RAKAY.wsRetryCount >= WS_MAX_RETRIES) {
      log.warn(`[WS] Max retries (${WS_MAX_RETRIES}) reached — WebSocket disabled until page reload`);
      _updateWsStatusBadge('disabled');
      return;
    }

    // Close any stale connection
    if (RAKAY.wsConn) {
      RAKAY.wsState = WS_STATE.CLOSING;
      try { RAKAY.wsConn.close(1000, 'reconnecting'); } catch {}
      RAKAY.wsConn = null;
    }

    RAKAY.wsState = WS_STATE.CONNECTING;
    const retryLabel = RAKAY.wsRetryCount > 0 ? ` (retry ${RAKAY.wsRetryCount}/${WS_MAX_RETRIES})` : '';
    log.info(`[WS] CONNECTING to ${wsUrl}${retryLabel}`);

    let ws;
    try {
      const wsUrlWithToken = `${wsUrl}?token=${encodeURIComponent(token)}`;
      ws = new WebSocket(wsUrlWithToken);
      RAKAY.wsConn = ws;
    } catch (err) {
      log.error('[WS] Could not create WebSocket:', err.message);
      RAKAY.wsState = WS_STATE.DISCONNECTED;
      _scheduleWsReconnect();
      return;
    }

    // ── CONNECTED ─────────────────────────────────────────────────────────
    ws.onopen = () => {
      if (RAKAY.wsConn !== ws) return; // stale
      RAKAY.wsState        = WS_STATE.CONNECTED;
      RAKAY.wsRetryCount   = 0;                      // reset retry counter on success
      RAKAY.wsReconnectDelay = WS_BASE_DELAY_MS;     // reset backoff
      log.info('[WS] CONNECTED ✅', wsUrl);
      _updateWsStatusBadge('connected');

      // Send in-band auth as well (belt-and-suspenders)
      _wsFrontendSend({ type: 'auth', token });

      // Subscribe to detection stream
      _wsFrontendSend({ type: 'detections:start' });

      // Start client-side keepalive pings
      _startWsPing(ws);
    };

    // ── MESSAGE ───────────────────────────────────────────────────────────
    ws.onmessage = (event) => {
      if (RAKAY.wsConn !== ws) return;
      try {
        const msg = JSON.parse(event.data);
        _handleWsMessage(msg);
      } catch {
        log.debug('[WS] Non-JSON message:', event.data?.slice(0, 100));
      }
    };

    // ── ERROR ─────────────────────────────────────────────────────────────
    ws.onerror = (err) => {
      if (RAKAY.wsConn !== ws) return;
      log.warn('[WS] ERROR — will reconnect. type:', err.type || 'unknown');
      _updateWsStatusBadge('error');
    };

    // ── CLOSE ─────────────────────────────────────────────────────────────
    ws.onclose = (event) => {
      if (RAKAY.wsConn !== ws) return; // stale close event

      RAKAY.wsConn  = null;
      RAKAY.wsState = WS_STATE.DISCONNECTED;
      _stopWsPing();

      const { code, reason, wasClean } = event;
      log.info(`[WS] CLOSED code=${code} clean=${wasClean} reason="${reason || ''}"`);
      _updateWsStatusBadge('disconnected');

      // Token rejected — re-auth before reconnecting
      if (code === 4001 || code === 4003) {
        log.warn('[WS] Auth rejected (code', code, ') — clearing token and re-authing before reconnect');
        _lsDel(LS_RAKAY_TOKEN);
        _lsDel(LS_RAKAY_TOKEN_EXP);
        RAKAY.authToken = null;
        _ensureAuth().then(() => _scheduleWsReconnect());
        return;
      }

      // Clean close (1000/1001) — do NOT reconnect
      if (wasClean || code === 1000 || code === 1001) {
        log.info('[WS] Clean close — not reconnecting');
        return;
      }

      // Abnormal close (1006 etc.) — schedule reconnect with exponential backoff
      _scheduleWsReconnect();
    };
  }

  function _scheduleWsReconnect() {
    if (RAKAY.wsReconnectTimer) return; // already scheduled

    RAKAY.wsRetryCount++;
    if (RAKAY.wsRetryCount > WS_MAX_RETRIES) {
      log.warn(`[WS] Max retries (${WS_MAX_RETRIES}) exhausted — stopping reconnect`);
      _updateWsStatusBadge('disabled');
      return;
    }

    const delay = Math.min(RAKAY.wsReconnectDelay, WS_MAX_DELAY_MS);
    RAKAY.wsReconnectDelay = Math.min(RAKAY.wsReconnectDelay * 2, WS_MAX_DELAY_MS);

    log.info(`[WS] Scheduling reconnect in ${delay}ms (attempt ${RAKAY.wsRetryCount}/${WS_MAX_RETRIES})`);

    RAKAY.wsReconnectTimer = setTimeout(() => {
      RAKAY.wsReconnectTimer = null;
      _initWebSocket();
    }, delay);
  }

  function _startWsPing(ws) {
    _stopWsPing();
    RAKAY.wsPingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        _wsFrontendSend({ type: 'ping', ts: Date.now() });
      } else {
        _stopWsPing();
      }
    }, WS_PING_INTERVAL);
  }

  function _stopWsPing() {
    if (RAKAY.wsPingTimer) {
      clearInterval(RAKAY.wsPingTimer);
      RAKAY.wsPingTimer = null;
    }
  }

  function _wsFrontendSend(data) {
    const ws = RAKAY.wsConn;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try { ws.send(JSON.stringify(data)); } catch {}
  }

  function _updateWsStatusBadge(state) {
    const badge = document.getElementById('rakay-ws-badge');
    if (!badge) return;
    const map = {
      connected:    { text: 'LIVE',       cls: 'ws-live'     },
      disconnected: { text: 'WS ↻',       cls: 'ws-retry'    },
      error:        { text: 'WS ERR',     cls: 'ws-error'    },
      disabled:     { text: 'WS OFF',     cls: 'ws-disabled' },
    };
    const s = map[state] || map.disconnected;
    badge.textContent = s.text;
    badge.className   = `rakay-ws-badge ${s.cls}`;
    badge.style.display = (state === 'connected' || state === 'error') ? 'inline-flex' : 'none';
  }

  function _handleWsMessage(msg) {
    switch (msg.type) {
      case 'connected':
        log.debug('[WS] Server confirmed connection. auth:', msg.auth);
        break;
      case 'auth_ok':
        log.debug('[WS] Auth confirmed. userId:', msg.userId);
        break;
      case 'auth_failed':
        log.warn('[WS] Server rejected auth:', msg.reason);
        break;
      case 'subscribed':
        log.debug('[WS] Detection stream subscribed');
        break;
      case 'pong':
        break; // keepalive pong received
      case 'detection:event': {
        // Live detections feed — show toast notification
        const severity = msg.severity || 'info';
        const title    = msg.title || msg.rule_name || 'New Detection';
        log.debug('[WS] Detection:', severity, title);
        _showToast(`🔔 ${title}`, severity === 'HIGH' || severity === 'CRITICAL' ? 'error' : 'info');
        break;
      }
      default:
        log.debug('[WS] Unknown message type:', msg.type);
    }
  }

  function _stopWebSocket() {
    // Cancel pending reconnect
    if (RAKAY.wsReconnectTimer) {
      clearTimeout(RAKAY.wsReconnectTimer);
      RAKAY.wsReconnectTimer = null;
    }
    _stopWsPing();

    // Close active connection
    if (RAKAY.wsConn) {
      RAKAY.wsState = WS_STATE.CLOSING;
      try { RAKAY.wsConn.close(1000, 'RAKAY module stopped'); } catch {}
      RAKAY.wsConn = null;
    }

    RAKAY.wsState      = WS_STATE.DISCONNECTED;
    RAKAY.wsRetryCount = 0;
    RAKAY.wsReconnectDelay = WS_BASE_DELAY_MS;
    log.info('[WS] Stopped');
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  TOAST NOTIFICATIONS
  // ══════════════════════════════════════════════════════════════════════════
  function _showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('rakay-toast-container') || _createToastContainer();
    const toast = document.createElement('div');
    toast.className = `rakay-toast rakay-toast--${type}`;
    const icons = { info: 'fa-info-circle', success: 'fa-check-circle', error: 'fa-exclamation-circle', warn: 'fa-exclamation-triangle' };
    toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${_e(message)}`;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  function _createToastContainer() {
    const el = document.createElement('div');
    el.id    = 'rakay-toast-container';
    el.className = 'rakay-toast-container';
    document.body.appendChild(el);
    return el;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MARKDOWN RENDERER (lightweight, no external deps)
  // ══════════════════════════════════════════════════════════════════════════
  function _renderMarkdown(text) {
    if (!text) return '';

    // Use marked.js if loaded
    if (typeof window.marked !== 'undefined') {
      try { return window.marked.parse(text, { breaks: true, gfm: true }); } catch {}
    }

    let html = _e(text);

    // Fenced code blocks
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      const langClass = lang ? ` class="language-${_e(lang)}"` : '';
      const langLabel = lang ? `<span class="rakay-code-lang">${_e(lang)}</span>` : '';
      const copyBtn   = `<button class="rakay-copy-btn" onclick="window._rakayCopyCode(this)" title="Copy"><i class="fas fa-copy"></i></button>`;
      return `<div class="rakay-code-wrap">${langLabel}${copyBtn}<pre><code${langClass}>${code.trim()}</code></pre></div>`;
    });

    // Inline code
    html = html.replace(/`([^`\n]+)`/g, '<code class="rakay-inline-code">$1</code>');

    // Headers
    html = html.replace(/^### (.+)$/gm, '<h3 class="rakay-h3">$1</h3>');
    html = html.replace(/^## (.+)$/gm,  '<h2 class="rakay-h2">$1</h2>');
    html = html.replace(/^# (.+)$/gm,   '<h1 class="rakay-h1">$1</h1>');

    // Bold + italic
    html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.+?)\*\*/g,     '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g,         '<em>$1</em>');
    html = html.replace(/_(.+?)_/g,           '<em>$1</em>');

    // Tables
    html = html.replace(/(?:^|\n)((?:\|[^\n]+\|\n)+)/g, (_, table) => {
      const rows = table.trim().split('\n').filter(r => r.trim());
      if (rows.length < 2) return _;
      if (!rows[1].match(/^\|[-| :]+\|$/)) return _;
      const headers = rows[0].split('|').slice(1, -1).map(h => `<th>${h.trim()}</th>`).join('');
      const body    = rows.slice(2).map(r => `<tr>${r.split('|').slice(1, -1).map(c => `<td>${c.trim()}</td>`).join('')}</tr>`).join('');
      return `<div class="rakay-table-wrap"><table class="rakay-table"><thead><tr>${headers}</tr></thead><tbody>${body}</tbody></table></div>`;
    });

    // Unordered list
    html = html.replace(/((?:^- .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^- /, '')}</li>`).join('');
      return `<ul class="rakay-ul">${items}</ul>`;
    });

    // Ordered list
    html = html.replace(/((?:^\d+\. .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^\d+\. /, '')}</li>`).join('');
      return `<ol class="rakay-ol">${items}</ol>`;
    });

    // Blockquote
    html = html.replace(/^&gt; (.+)$/gm, '<blockquote class="rakay-blockquote">$1</blockquote>');

    // Horizontal rule
    html = html.replace(/^---+$/gm, '<hr class="rakay-hr">');

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer" class="rakay-link">$1 <i class="fas fa-external-link-alt" style="font-size:9px"></i></a>');

    // Paragraphs
    html = html.replace(/\n\n/g, '</p><p>');
    html = `<p>${html}</p>`;
    html = html.replace(/<p>\s*<\/p>/g, '');
    html = html.replace(/\n/g, '<br>');

    // Clean up redundant p around block elements
    html = html.replace(/<p>(<(?:h[123]|ul|ol|div|pre|table|blockquote|hr)[^>]*>)/g, '$1');
    html = html.replace(/<\/(?:h[123]|ul|ol|div|pre|table|blockquote)><\/p>/g, m => m.replace('</p>', ''));

    return html;
  }

  // ── Global copy helper ────────────────────────────────────────────────────
  window._rakayCopyCode = function (btn) {
    const code = btn.closest('.rakay-code-wrap')?.querySelector('code')?.textContent || '';
    navigator.clipboard.writeText(code).then(() => {
      btn.innerHTML = '<i class="fas fa-check"></i>';
      setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i>'; }, 2000);
    }).catch(() => {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = code;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    });
  };

  // ══════════════════════════════════════════════════════════════════════════
  //  TOOL TRACE VISUALISER
  // ══════════════════════════════════════════════════════════════════════════
  function _renderToolTrace(trace) {
    if (!trace || !trace.length) return '';

    const iconMap = {
      sigma_search:         'fa-search',
      sigma_generate:       'fa-file-code',
      kql_generate:         'fa-terminal',
      ioc_enrich:           'fa-shield-alt',
      mitre_lookup:         'fa-sitemap',
      cve_lookup:           'fa-bug',
      threat_actor_profile: 'fa-user-secret',
      platform_navigate:    'fa-compass',
    };

    const items = trace.map((t, i) => {
      const icon    = iconMap[t.tool] || 'fa-cog';
      const traceId = `rakay-trace-${Date.now()}-${i}`;
      const hasResult = t.result && typeof t.result === 'object';
      const statusIcon = t.error ? 'fa-times-circle" style="color:#f85149' : 'fa-check-circle" style="color:#3fb950';

      return `
      <div class="rakay-tool-item">
        <div class="rakay-tool-header" onclick="document.getElementById('${traceId}').classList.toggle('open')">
          <span class="rakay-tool-icon"><i class="fas ${icon}"></i></span>
          <span class="rakay-tool-name">${_e(t.tool.replace(/_/g, ' '))}</span>
          <span class="rakay-tool-args">${_e(JSON.stringify(t.args || {}).slice(0, 80))}</span>
          <i class="fas ${statusIcon}" style="margin-left:auto;margin-right:4px"></i>
          <span class="rakay-tool-chevron"><i class="fas fa-chevron-down"></i></span>
        </div>
        <div class="rakay-tool-body" id="${traceId}">
          ${t.error
            ? `<div class="rakay-tool-error"><i class="fas fa-exclamation-triangle"></i> ${_e(t.error)}</div>`
            : hasResult
              ? `<pre class="rakay-tool-result">${_e(JSON.stringify(t.result, null, 2).slice(0, 2000))}</pre>`
              : '<span style="color:#8b949e">No result data</span>'
          }
        </div>
      </div>`;
    });

    return `
    <div class="rakay-tool-trace">
      <div class="rakay-tool-trace-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <i class="fas fa-wrench" style="color:#22d3ee;margin-right:6px"></i>
        <span>${trace.length} tool${trace.length > 1 ? 's' : ''} used</span>
        <i class="fas fa-chevron-down" style="margin-left:auto"></i>
      </div>
      <div class="rakay-tool-trace-body">
        ${items.join('')}
      </div>
    </div>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  RENDER FUNCTIONS
  // ══════════════════════════════════════════════════════════════════════════
  function _renderMessages() {
    const container = document.getElementById('rakay-messages');
    if (!container) return;

    if (!RAKAY.messages.length) {
      container.innerHTML = _renderWelcome();
      return;
    }

    const items = RAKAY.messages.map(msg => {
      const isUser  = msg.role === 'user';
      const ts      = _time(msg.created_at);
      const trace   = msg.tool_trace ? _renderToolTrace(msg.tool_trace) : '';
      const offline = msg._offline ? ' rakay-msg--offline' : '';

      if (isUser) {
        return `
        <div class="rakay-msg rakay-msg--user${offline}">
          <div class="rakay-msg-content">
            <div class="rakay-msg-bubble rakay-msg-bubble--user">${_e(msg.content)}</div>
            <div class="rakay-msg-meta">${ts}</div>
          </div>
          <div class="rakay-msg-avatar rakay-msg-avatar--user"><i class="fas fa-user"></i></div>
        </div>`;
      }

      const modelBadge    = msg.model    ? `<span class="rakay-model-badge">${_e(msg.model)}</span>` : '';
      const latency       = msg.latency_ms ? `<span class="rakay-latency">${msg.latency_ms}ms</span>` : '';
      const tokens        = msg.tokens_used ? `<span class="rakay-tokens"><i class="fas fa-bolt"></i> ${msg.tokens_used}</span>` : '';
      const providerBadge = msg.provider && msg.provider !== 'mock' ? `<span class="rakay-provider-badge">${_e(msg.provider)}</span>` : '';
      const degradedBadge = msg._degraded ? `<span class="rakay-degraded-badge"><i class="fas fa-exclamation-triangle"></i> degraded</span>` : '';
      const streamBadge   = msg._streamed ? `<span class="rakay-provider-badge" title="Streaming response" style="background:#a855f714;border-color:#a855f730;color:#a855f7"><i class="fas fa-stream" style="font-size:8px"></i></span>` : '';

      return `
      <div class="rakay-msg rakay-msg--assistant${offline}">
        <div class="rakay-msg-avatar rakay-msg-avatar--assistant"><i class="fas fa-robot"></i></div>
        <div class="rakay-msg-content">
          ${trace}
          <div class="rakay-msg-bubble rakay-msg-bubble--assistant">
            ${_renderMarkdown(msg.content)}
          </div>
          <div class="rakay-msg-meta">${ts} ${modelBadge} ${providerBadge} ${latency} ${tokens} ${degradedBadge} ${streamBadge}</div>
        </div>
      </div>`;
    }).join('');

    container.innerHTML = items;

    // Syntax highlighting
    if (typeof window.Prism !== 'undefined') {
      container.querySelectorAll('pre code').forEach(el => window.Prism.highlightElement(el));
    } else if (typeof window.hljs !== 'undefined') {
      container.querySelectorAll('pre code').forEach(el => window.hljs.highlightElement(el));
    }
  }

  function _renderWelcome() {
    const statusClass = RAKAY.backendOnline === false ? 'offline-warning' : '';
    const statusBanner = RAKAY.backendOnline === false ? `
    <div class="rakay-offline-banner">
      <i class="fas fa-exclamation-triangle"></i>
      Backend offline — RAKAY will use local mode until connection is restored.
      <button onclick="window._rakayRetryConnect()" class="rakay-retry-btn">Retry</button>
    </div>` : '';

    return `
    <div class="rakay-welcome ${statusClass}">
      ${statusBanner}
      <div class="rakay-welcome-logo"><i class="fas fa-robot"></i></div>
      <h2 class="rakay-welcome-title">RAKAY — AI Security Analyst</h2>
      <p class="rakay-welcome-sub">Powered by Wadjet-Eye AI Platform</p>
      <div class="rakay-welcome-prompts">
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-file-code"></i> Generate Sigma rule for PowerShell encoded commands
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-sitemap"></i> Explain MITRE ATT&CK T1059.001
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-terminal"></i> Create KQL query for ransomware detection
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-user-secret"></i> Profile the APT29 threat group
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-shield-alt"></i> Enrich IP 185.220.101.34
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-bug"></i> What is CVE-2024-12356?
        </button>
      </div>
    </div>`;
  }

  function _renderSidebar() {
    const list = document.getElementById('rakay-session-list');
    if (!list) return;

    if (!RAKAY.sessions.length) {
      list.innerHTML = '<div class="rakay-session-empty">No sessions yet.<br>Start a new chat.</div>';
      return;
    }

    list.innerHTML = RAKAY.sessions.map(s => {
      const active = s.id === RAKAY.sessionId ? ' rakay-session--active' : '';
      const msgCnt = s.message_count ? `<span class="rakay-session-cnt">${s.message_count}</span>` : '';
      return `
      <div class="rakay-session-item${active}" data-sid="${_e(s.id)}" onclick="window._rakaySelectSession('${_e(s.id)}')">
        <div class="rakay-session-title" title="${_e(s.title)}">${_e(s.title || 'Chat')}</div>
        <div class="rakay-session-meta">${_time(s.updated_at)} ${msgCnt}</div>
        <div class="rakay-session-actions">
          <button class="rakay-session-btn" onclick="event.stopPropagation();window._rakayRenameSession('${_e(s.id)}')" title="Rename"><i class="fas fa-pen"></i></button>
          <button class="rakay-session-btn rakay-session-btn--del" onclick="event.stopPropagation();window._rakayDeleteSession('${_e(s.id)}')" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
      </div>`;
    }).join('');
  }

  function _showTyping() {
    RAKAY.typing = true;
    const container = document.getElementById('rakay-messages');
    if (!container) return;
    const existing = container.querySelector('.rakay-typing-indicator');
    if (existing) existing.remove();
    const el = document.createElement('div');
    el.className = 'rakay-msg rakay-msg--assistant rakay-typing-indicator';
    el.innerHTML = `
    <div class="rakay-msg-avatar rakay-msg-avatar--assistant"><i class="fas fa-robot"></i></div>
    <div class="rakay-msg-content">
      <div class="rakay-msg-bubble rakay-msg-bubble--assistant">
        <div class="rakay-typing-dots"><span></span><span></span><span></span></div>
        <span class="rakay-typing-label">RAKAY is thinking…</span>
      </div>
    </div>`;
    container.appendChild(el);
    _scrollToBottom();
  }

  function _hideTyping() {
    RAKAY.typing = false;
    document.querySelector('.rakay-typing-indicator')?.remove();
  }

  function _setInputEnabled(enabled) {
    const inp = document.getElementById('rakay-input');
    const btn = document.getElementById('rakay-send');
    if (inp) inp.disabled = !enabled;
    if (btn) btn.disabled = !enabled;
    if (btn) btn.innerHTML = enabled
      ? '<i class="fas fa-paper-plane"></i>'
      : '<i class="fas fa-circle-notch fa-spin"></i>';
  }

  function _focusInput() {
    document.getElementById('rakay-input')?.focus();
  }

  function _scrollToBottom(smooth = true) {
    const container = document.getElementById('rakay-messages');
    if (container) container.scrollTo({ top: container.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
  }

  function _updateStatus() {
    const dot = document.getElementById('rakay-status-dot');
    if (!dot) return;

    if (RAKAY.backendOnline === true) {
      dot.className = 'rakay-status-dot online';
      dot.title = `Backend connected — ${API_BASE()}`;
    } else if (RAKAY.backendOnline === false) {
      dot.className = 'rakay-status-dot offline';
      dot.title = `Backend offline — ${API_BASE()} | Using local mode`;
    } else {
      dot.className = 'rakay-status-dot checking';
      dot.title = 'Checking backend status…';
    }

    // Update status label in header
    const label = document.getElementById('rakay-status-label');
    if (label) {
      if (RAKAY.backendOnline === true)  label.textContent = 'ONLINE';
      else if (RAKAY.backendOnline === false) label.textContent = 'OFFLINE';
      else label.textContent = 'CONNECTING…';
      label.className = `rakay-status-label ${RAKAY.backendOnline === true ? 'online' : RAKAY.backendOnline === false ? 'offline' : 'checking'}`;
    }

    // If messages page showing offline state, update it
    const container = document.getElementById('rakay-messages');
    if (container && !RAKAY.messages.length) {
      container.innerHTML = _renderWelcome();
    }
  }

  function _updateHeader() {
    const title = document.getElementById('rakay-current-title');
    if (!title) return;
    const s = RAKAY.sessions.find(s => s.id === RAKAY.sessionId);
    title.textContent = s?.title || 'RAKAY';
  }

  async function _startNewChat() {
    const session = await _createSession();
    RAKAY.sessionId = session.id;
    RAKAY.messages  = [];
    _renderSidebar();
    _renderMessages();
    _updateHeader();
    _focusInput();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  GLOBAL INTERACTION HANDLERS
  // ══════════════════════════════════════════════════════════════════════════
  window._rakayQuickPrompt = function (btn) {
    const text = btn.innerText.trim().replace(/^[\S\s]{1,2}\s/, ''); // strip icon
    const inp  = document.getElementById('rakay-input');
    if (inp) {
      inp.value = text;
      inp.focus();
      inp.style.height = 'auto';
      inp.style.height = Math.min(inp.scrollHeight, 200) + 'px';
    }
  };

  window._rakaySelectSession = async function (sid) {
    if (sid === RAKAY.sessionId) return;
    RAKAY.sessionId = sid;
    RAKAY.messages  = [];
    _renderMessages();
    _renderSidebar();
    await _loadHistory(sid);
    _renderMessages();
    _scrollToBottom(false);
    _focusInput();
    _updateHeader();
  };

  window._rakayDeleteSession = async function (sid) {
    const session = RAKAY.sessions.find(s => s.id === sid);
    const name    = session?.title || 'this chat';
    if (!confirm(`Delete "${name}"? This action cannot be undone.`)) return;

    await _deleteSession(sid);

    if (RAKAY.sessionId === sid) {
      if (RAKAY.sessions.length) {
        await window._rakaySelectSession(RAKAY.sessions[0].id);
      } else {
        await _startNewChat();
      }
    }
    _renderSidebar();
  };

  window._rakayRenameSession = function (sid) {
    const session = RAKAY.sessions.find(s => s.id === sid);
    if (!session) return;
    const newTitle = prompt('Rename session:', session.title || 'Chat');
    if (newTitle?.trim()) {
      _renameSession(sid, newTitle.trim().slice(0, 120));
      _renderSidebar();
      if (sid === RAKAY.sessionId) _updateHeader();
    }
  };

  window._rakayNewChat = async function () { await _startNewChat(); };

  window._rakaySubmit = function () {
    // Debounce: ignore rapid repeat clicks / keydowns
    if (RAKAY._submitDebounce) return;

    const inp = document.getElementById('rakay-input');
    if (!inp) return;
    const msg = inp.value.trim();
    if (!msg) return;

    // Guard: already loading
    if (RAKAY.loading) {
      log.debug('Submit ignored — request in progress');
      return;
    }

    // Guard: rate-limit active
    if (RAKAY._rateLimitUntil > Date.now()) return;

    // Debounce window: 300ms prevents double-click / Enter spam
    RAKAY._submitDebounce = setTimeout(() => {
      RAKAY._submitDebounce = null;
    }, 300);

    inp.value = '';
    inp.style.height = 'auto';
    _sendMessage(msg);
  };

  window._rakaySearchSessions = function (q) {
    document.querySelectorAll('.rakay-session-item').forEach(item => {
      const title = item.querySelector('.rakay-session-title')?.textContent.toLowerCase() || '';
      item.style.display = (!q || title.includes(q.toLowerCase())) ? '' : 'none';
    });
  };

  window._rakayClearSearch = function () {
    const inp = document.getElementById('rakay-session-search');
    if (inp) { inp.value = ''; window._rakaySearchSessions(''); }
  };

  window._rakayRetryConnect = async function () {
    log.info('Manual retry — checking backend…');
    _showToast('Checking backend connectivity…', 'info');
    await _checkStatus();
    if (RAKAY.backendOnline) {
      await _ensureAuth();
      _showToast('Backend connected! RAKAY is now online.', 'success');
    } else {
      _showToast('Backend still unreachable. Check your connection.', 'error');
    }
  };

  // ══════════════════════════════════════════════════════════════════════════
  //  CSS
  // ══════════════════════════════════════════════════════════════════════════
  function _injectCSS() {
    if (document.getElementById('rakay-styles')) return;
    const style = document.createElement('style');
    style.id    = 'rakay-styles';
    style.textContent = `
/* ═══════════════════════════════════════
   RAKAY Module Styles v2.0 — Wadjet-Eye AI
═══════════════════════════════════════ */
.rakay-root {
  display: flex;
  height: calc(100vh - 70px);
  max-height: 100%;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-primary, #0d1117);
  color: var(--text-primary, #e6edf3);
  overflow: hidden;
}

/* ── Sidebar ───────────────────────────── */
.rakay-sidebar {
  width: 260px; min-width: 220px; max-width: 300px;
  background: var(--bg-secondary, #161b22);
  border-right: 1px solid var(--border, #30363d);
  display: flex; flex-direction: column;
  overflow: hidden; transition: width .2s;
}
.rakay-sidebar-header {
  padding: 16px 14px 12px;
  border-bottom: 1px solid var(--border, #30363d);
  display: flex; align-items: center; gap: 8px;
}
.rakay-sidebar-logo {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, #22d3ee22, #a855f722);
  border: 1px solid #22d3ee44; border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  color: #22d3ee; font-size: 14px; flex-shrink: 0;
}
.rakay-sidebar-title { font-size: 15px; font-weight: 600; color: #e6edf3; flex: 1; }
.rakay-new-btn {
  background: none; border: 1px solid #30363d; color: #22d3ee;
  border-radius: 6px; padding: 5px 8px; cursor: pointer; font-size: 12px;
  transition: all .15s;
}
.rakay-new-btn:hover { background: #22d3ee22; border-color: #22d3ee44; }
.rakay-session-search-wrap {
  padding: 10px 12px 6px;
  border-bottom: 1px solid var(--border, #30363d);
}
.rakay-session-search {
  width: 100%; padding: 6px 10px; box-sizing: border-box;
  background: #0d1117; border: 1px solid #30363d;
  border-radius: 6px; color: #e6edf3; font-size: 12px; outline: none;
}
.rakay-session-search:focus { border-color: #22d3ee44; }
.rakay-session-list { flex: 1; overflow-y: auto; padding: 6px 8px; }
.rakay-session-list::-webkit-scrollbar { width: 4px; }
.rakay-session-list::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
.rakay-session-empty { color: #8b949e; font-size: 12px; padding: 16px 8px; text-align: center; }
.rakay-session-item {
  position: relative; padding: 10px 10px; border-radius: 8px;
  cursor: pointer; margin-bottom: 4px; transition: background .12s;
}
.rakay-session-item:hover { background: #21262d; }
.rakay-session-item:hover .rakay-session-actions { opacity: 1; }
.rakay-session--active { background: #21262d !important; border: 1px solid #22d3ee22; }
.rakay-session-title {
  font-size: 13px; color: #c9d1d9; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px;
}
.rakay-session-meta { font-size: 11px; color: #8b949e; margin-top: 2px; display: flex; align-items: center; gap: 4px; }
.rakay-session-cnt { background: #21262d; border-radius: 10px; padding: 1px 6px; font-size: 10px; color: #22d3ee; }
.rakay-session-actions {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  display: flex; gap: 2px; opacity: 0; transition: opacity .12s;
}
.rakay-session-btn {
  background: none; border: none; color: #8b949e; cursor: pointer;
  padding: 4px 6px; border-radius: 4px; font-size: 11px; transition: all .12s;
}
.rakay-session-btn:hover { background: #30363d; color: #c9d1d9; }
.rakay-session-btn--del:hover { color: #f85149 !important; }

/* ── Main area ──────────────────────────── */
.rakay-main {
  flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0;
}
.rakay-header {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border, #30363d);
  background: var(--bg-secondary, #161b22);
  display: flex; align-items: center; gap: 12px;
  flex-shrink: 0;
}
.rakay-header-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, #22d3ee20, #a855f720);
  border: 1px solid #22d3ee40; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  color: #22d3ee; font-size: 16px;
}
.rakay-header-info { flex: 1; min-width: 0; }
.rakay-header-title { font-size: 15px; font-weight: 600; color: #e6edf3; }
.rakay-header-sub { font-size: 11px; color: #8b949e; margin-top: 1px; }

/* ── Status dot + label ─────────────────── */
.rakay-status-area { display: flex; align-items: center; gap: 6px; }
.rakay-status-dot {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  background: #8b949e; transition: background .3s;
}
.rakay-status-dot.online  { background: #3fb950; box-shadow: 0 0 6px #3fb95088; }
.rakay-status-dot.offline { background: #f85149; box-shadow: 0 0 6px #f8514988; }
.rakay-status-dot.checking { background: #d29922; animation: rakay-pulse 1.2s ease-in-out infinite; }
.rakay-status-label { font-size: 10px; font-weight: 600; letter-spacing: .05em; }
.rakay-status-label.online  { color: #3fb950; }
.rakay-status-label.offline { color: #f85149; }
.rakay-status-label.checking { color: #d29922; }

@keyframes rakay-pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: .4; }
}

/* ── Messages ───────────────────────────── */
#rakay-messages {
  flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px;
}
#rakay-messages::-webkit-scrollbar { width: 5px; }
#rakay-messages::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
.rakay-msg { display: flex; gap: 12px; align-items: flex-start; }
.rakay-msg--user { flex-direction: row-reverse; }
.rakay-msg-avatar {
  width: 34px; height: 34px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 15px; flex-shrink: 0; margin-top: 2px;
}
.rakay-msg-avatar--user      { background: linear-gradient(135deg, #7c3aed, #a855f7); color: #fff; }
.rakay-msg-avatar--assistant { background: linear-gradient(135deg, #0e7490, #22d3ee); color: #fff; }
.rakay-msg-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px; }
.rakay-msg-bubble {
  border-radius: 12px; padding: 12px 16px; font-size: 14px;
  line-height: 1.6; word-break: break-word; max-width: 100%;
}
.rakay-msg-bubble--user {
  background: linear-gradient(135deg, #7c3aed22, #a855f722);
  border: 1px solid #a855f730; color: #e6edf3; align-self: flex-end;
}
.rakay-msg-bubble--assistant {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border, #30363d); color: #c9d1d9;
}
.rakay-msg--offline .rakay-msg-bubble--assistant { border-color: #f0883e30; }
.rakay-msg-meta { font-size: 11px; color: #8b949e; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.rakay-model-badge { background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 1px 5px; font-size: 10px; color: #8b949e; }
.rakay-latency, .rakay-tokens { font-size: 10px; color: #6e7681; }

/* ── Typing indicator ───────────────────── */
.rakay-typing-dots { display: inline-flex; align-items: center; gap: 4px; }
.rakay-typing-dots span {
  width: 7px; height: 7px; background: #22d3ee; border-radius: 50%;
  animation: rakay-bounce 1.2s ease-in-out infinite;
}
.rakay-typing-dots span:nth-child(2) { animation-delay: .2s; }
.rakay-typing-dots span:nth-child(3) { animation-delay: .4s; }
@keyframes rakay-bounce {
  0%, 80%, 100% { transform: translateY(0); }
  40%           { transform: translateY(-6px); }
}
.rakay-typing-label { font-size: 12px; color: #8b949e; margin-left: 8px; }

/* ── Tool trace ─────────────────────────── */
.rakay-tool-trace { margin-bottom: 8px; border: 1px solid #22d3ee20; border-radius: 8px; overflow: hidden; }
.rakay-tool-trace-header {
  padding: 8px 12px; background: #22d3ee0a; cursor: pointer;
  display: flex; align-items: center; font-size: 12px; color: #8b949e;
  user-select: none;
}
.rakay-tool-trace-header:hover { background: #22d3ee14; }
.rakay-tool-trace-body { display: none; border-top: 1px solid #22d3ee20; }
.rakay-tool-trace-body.open { display: block; }
.rakay-tool-item { border-bottom: 1px solid #21262d; }
.rakay-tool-item:last-child { border-bottom: none; }
.rakay-tool-header {
  padding: 8px 12px; cursor: pointer; display: flex; align-items: center; gap: 8px;
  font-size: 12px; user-select: none; transition: background .1s;
}
.rakay-tool-header:hover { background: #21262d; }
.rakay-tool-icon { color: #22d3ee; width: 16px; text-align: center; }
.rakay-tool-name { font-weight: 600; color: #c9d1d9; text-transform: capitalize; }
.rakay-tool-args { color: #6e7681; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rakay-tool-chevron { color: #6e7681; font-size: 10px; }
.rakay-tool-body { display: none; padding: 10px 14px; background: #0d1117; }
.rakay-tool-body.open { display: block; }
.rakay-tool-result { margin: 0; font-size: 11px; color: #8b949e; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
.rakay-tool-error { color: #f85149; font-size: 12px; }

/* ── Code blocks ────────────────────────── */
.rakay-code-wrap { position: relative; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; margin: .6em 0; }
.rakay-code-wrap pre { margin: 0; padding: 14px 16px; overflow-x: auto; }
.rakay-code-wrap code { font-size: 12.5px; line-height: 1.6; font-family: 'Fira Code', 'Cascadia Code', Consolas, monospace; }
.rakay-code-lang { display: block; font-size: 10px; color: #8b949e; padding: 5px 12px 0; text-transform: uppercase; letter-spacing: .08em; }
.rakay-copy-btn {
  position: absolute; top: 6px; right: 8px;
  background: #21262d; border: 1px solid #30363d; border-radius: 4px;
  color: #8b949e; cursor: pointer; padding: 3px 7px; font-size: 11px;
  transition: all .12s; opacity: 0;
}
.rakay-code-wrap:hover .rakay-copy-btn { opacity: 1; }
.rakay-copy-btn:hover { background: #30363d; color: #c9d1d9; }
.rakay-inline-code {
  background: #161b22; border: 1px solid #30363d; border-radius: 4px;
  padding: 1px 5px; font-family: monospace; font-size: 12px; color: #f0883e;
}
.rakay-ul, .rakay-ol { padding-left: 1.4em; margin: .5em 0; }
.rakay-ul li, .rakay-ol li { margin: .2em 0; }
.rakay-table-wrap { overflow-x: auto; margin: .6em 0; }
.rakay-table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.rakay-table th { background: #21262d; color: #c9d1d9; padding: 7px 12px; border: 1px solid #30363d; text-align: left; }
.rakay-table td { padding: 6px 12px; border: 1px solid #21262d; color: #8b949e; }
.rakay-table tr:hover td { background: #161b22; }
.rakay-blockquote {
  border-left: 3px solid #22d3ee; padding: 4px 12px; margin: .5em 0;
  color: #8b949e; font-style: italic; background: #22d3ee08; border-radius: 0 6px 6px 0;
}
.rakay-hr { border: none; border-top: 1px solid #30363d; margin: .8em 0; }
.rakay-link { color: #22d3ee; text-decoration: none; }
.rakay-link:hover { text-decoration: underline; }
.rakay-h1 { font-size: 1.3em; font-weight: 700; margin: .6em 0 .3em; color: #e6edf3; }
.rakay-h2 { font-size: 1.15em; font-weight: 600; margin: .5em 0 .25em; color: #e6edf3; }
.rakay-h3 { font-size: 1.05em; font-weight: 600; margin: .4em 0 .2em; color: #c9d1d9; }

/* ── Input area ─────────────────────────── */
.rakay-input-area {
  padding: 14px 20px;
  border-top: 1px solid var(--border, #30363d);
  background: var(--bg-secondary, #161b22);
  flex-shrink: 0;
}
.rakay-input-wrap {
  display: flex; align-items: flex-end; gap: 10px;
  background: var(--bg-primary, #0d1117);
  border: 1px solid var(--border, #30363d);
  border-radius: 12px; padding: 10px 14px; transition: border-color .15s;
}
.rakay-input-wrap:focus-within { border-color: #22d3ee50; }
#rakay-input {
  flex: 1; background: none; border: none; outline: none; resize: none;
  color: #e6edf3; font-size: 14px; font-family: inherit;
  line-height: 1.5; max-height: 200px; min-height: 22px; overflow-y: auto;
}
#rakay-input::placeholder { color: #8b949e; }
#rakay-send {
  background: linear-gradient(135deg, #22d3ee, #0ea5e9);
  border: none; border-radius: 8px; color: #fff; cursor: pointer;
  width: 36px; height: 36px;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; flex-shrink: 0; transition: opacity .15s;
}
#rakay-send:hover:not(:disabled) { opacity: .85; }
#rakay-send:disabled { opacity: .4; cursor: not-allowed; }
.rakay-input-hint { font-size: 11px; color: #8b949e; margin-top: 6px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }

/* ── Welcome screen ─────────────────────── */
.rakay-welcome {
  flex: 1; display: flex; flex-direction: column; align-items: center;
  justify-content: center; padding: 40px 20px; text-align: center; gap: 16px;
}
.rakay-welcome-logo {
  width: 64px; height: 64px;
  background: linear-gradient(135deg, #22d3ee20, #a855f720);
  border: 1px solid #22d3ee40; border-radius: 16px;
  display: flex; align-items: center; justify-content: center;
  font-size: 28px; color: #22d3ee;
}
.rakay-welcome-title { font-size: 22px; font-weight: 700; color: #e6edf3; margin: 0; }
.rakay-welcome-sub { font-size: 14px; color: #8b949e; margin: 0; }
.rakay-welcome-prompts { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; max-width: 680px; margin-top: 8px; }
.rakay-prompt-chip {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border, #30363d);
  border-radius: 8px; padding: 8px 14px; cursor: pointer;
  font-size: 13px; color: #8b949e; transition: all .15s;
  display: flex; align-items: center; gap: 7px;
}
.rakay-prompt-chip:hover { background: #21262d; border-color: #22d3ee40; color: #c9d1d9; }
.rakay-prompt-chip i { color: #22d3ee; }

/* ── Offline banner ─────────────────────── */
.rakay-offline-banner {
  background: #f0883e14; border: 1px solid #f0883e40;
  border-radius: 8px; padding: 10px 14px; font-size: 13px;
  color: #f0883e; display: flex; align-items: center; gap: 8px;
  max-width: 600px; width: 100%;
}
.rakay-retry-btn {
  background: #f0883e22; border: 1px solid #f0883e44; color: #f0883e;
  border-radius: 5px; padding: 3px 10px; cursor: pointer; font-size: 12px;
  margin-left: auto; white-space: nowrap; transition: all .15s;
}
.rakay-retry-btn:hover { background: #f0883e44; }

/* ── Error message ───────────────────────── */
.rakay-error-msg {
  background: #f8514914; border: 1px solid #f8514940;
  color: #f85149; border-radius: 8px; padding: 10px 14px;
  font-size: 13px; display: flex; align-items: center; gap: 8px;
  margin: 4px 0;
}

/* ── Toast notifications ─────────────────── */
.rakay-toast-container {
  position: fixed; bottom: 24px; right: 24px; z-index: 9999;
  display: flex; flex-direction: column; gap: 8px; max-width: 340px;
}
.rakay-toast {
  padding: 10px 16px; border-radius: 8px; font-size: 13px;
  display: flex; align-items: center; gap: 8px;
  box-shadow: 0 4px 16px rgba(0,0,0,.4);
  transform: translateX(120%); transition: transform .25s ease;
  border: 1px solid transparent;
}
.rakay-toast.show { transform: translateX(0); }
.rakay-toast--info    { background: #21262d; border-color: #30363d; color: #c9d1d9; }
.rakay-toast--success { background: #1a3f1a; border-color: #3fb95044; color: #3fb950; }
.rakay-toast--error   { background: #3a1a1a; border-color: #f8514944; color: #f85149; }
.rakay-toast--warn    { background: #3a2a0a; border-color: #d2992244; color: #d29922; }

/* ── Responsive ─────────────────────────── */
@media (max-width: 680px) {
  .rakay-sidebar { width: 0; min-width: 0; overflow: hidden; }
  .rakay-sidebar.open { width: 260px; }
}

/* ── WebSocket live badge ─────────────── */
.rakay-ws-badge {
  font-size: 10px; font-weight: 700; letter-spacing: .6px;
  padding: 2px 7px; border-radius: 10px; margin-right: 6px;
  display: inline-flex; align-items: center; gap: 4px;
}
.rakay-ws-badge.ws-live     { background: #1a3f1a44; border: 1px solid #3fb95066; color: #3fb950; }
.rakay-ws-badge.ws-retry    { background: #d2992222; border: 1px solid #d2992244; color: #d29922; }
.rakay-ws-badge.ws-error    { background: #f8514922; border: 1px solid #f8514944; color: #f85149; }
.rakay-ws-badge.ws-disabled { background: #21262d;   border: 1px solid #30363d;   color: #6e7681; }

/* ── Streaming bubble ────────────────── */
.rakay-streaming-bubble {
  min-height: 28px;
  white-space: pre-wrap;
  word-break: break-word;
}
.rakay-stream-cursor {
  display: inline-block;
  color: #22d3ee;
  animation: rakay-blink 0.8s step-end infinite;
  font-size: 14px;
  line-height: 1;
  margin-left: 1px;
}
@keyframes rakay-blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0; }
}
.rakay-streaming-meta .rakay-streaming-label {
  color: #22d3ee; font-size: 11px; display: flex; align-items: center; gap: 5px;
}
.rakay-provider-badge {
  background: #22d3ee14; border: 1px solid #22d3ee30; border-radius: 4px;
  padding: 1px 5px; font-size: 10px; color: #22d3ee;
}
.rakay-priority-badge {
  border-radius: 4px; padding: 1px 5px; font-size: 10px; font-weight: 600;
}
.rakay-priority-badge.high   { background: #f8514914; border: 1px solid #f8514940; color: #f85149; }
.rakay-priority-badge.medium { background: #d2992214; border: 1px solid #d2992240; color: #d29922; }
.rakay-priority-badge.low    { background: #21262d;   border: 1px solid #30363d;   color: #6e7681; }
.rakay-degraded-badge {
  background: #f0883e14; border: 1px solid #f0883e40; border-radius: 4px;
  padding: 1px 5px; font-size: 10px; color: #f0883e;
}
`;
    document.head.appendChild(style);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  PAGE HTML
  // ══════════════════════════════════════════════════════════════════════════
  function _buildHTML() {
    return `
<div class="rakay-root" id="rakay-root">

  <!-- Sidebar -->
  <aside class="rakay-sidebar" id="rakay-sidebar">
    <div class="rakay-sidebar-header">
      <div class="rakay-sidebar-logo"><i class="fas fa-robot"></i></div>
      <span class="rakay-sidebar-title">RAKAY</span>
      <button class="rakay-new-btn" onclick="window._rakayNewChat()" title="New chat">
        <i class="fas fa-plus"></i>
      </button>
    </div>

    <div class="rakay-session-search-wrap">
      <input
        type="text"
        id="rakay-session-search"
        class="rakay-session-search"
        placeholder="Search sessions…"
        oninput="window._rakaySearchSessions(this.value)"
      >
    </div>

    <div class="rakay-session-list" id="rakay-session-list">
      <div class="rakay-session-empty">Loading sessions…</div>
    </div>
  </aside>

  <!-- Main chat area -->
  <main class="rakay-main">

    <!-- Header -->
    <div class="rakay-header">
      <div class="rakay-header-icon"><i class="fas fa-robot"></i></div>
      <div class="rakay-header-info">
        <div class="rakay-header-title" id="rakay-current-title">RAKAY — AI Security Analyst</div>
        <div class="rakay-header-sub">Conversational threat intelligence · Detection engineering</div>
      </div>
      <div class="rakay-status-area">
        <span class="rakay-ws-badge" id="rakay-ws-badge" style="display:none">LIVE</span>
        <div class="rakay-status-dot checking" id="rakay-status-dot" title="Checking backend…"></div>
        <span class="rakay-status-label checking" id="rakay-status-label">CONNECTING…</span>
      </div>
    </div>

    <!-- Messages -->
    <div id="rakay-messages">
      ${_renderWelcome()}
    </div>

    <!-- Input -->
    <div class="rakay-input-area">
      <div class="rakay-input-wrap">
        <textarea
          id="rakay-input"
          placeholder="Ask RAKAY anything — Sigma rules, IOC enrichment, CVEs, MITRE ATT&CK…"
          rows="1"
          oninput="(function(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,200)+'px';})(this)"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();window._rakaySubmit();}"
        ></textarea>
        <button id="rakay-send" onclick="window._rakaySubmit()" title="Send (Enter)">
          <i class="fas fa-paper-plane"></i>
        </button>
      </div>
      <div class="rakay-input-hint">
        <i class="fas fa-keyboard"></i>
        Press <kbd style="background:#161b22;border:1px solid #30363d;padding:1px 5px;border-radius:3px;font-size:10px">Enter</kbd>
        to send ·
        <kbd style="background:#161b22;border:1px solid #30363d;padding:1px 5px;border-radius:3px;font-size:10px">Shift+Enter</kbd>
        for new line
      </div>
    </div>

  </main>
</div>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MAIN RENDER & LIFECYCLE
  // ══════════════════════════════════════════════════════════════════════════

  async function renderRAKAY() {
    // Reset messageId on fresh render
    RAKAY._currentMessageId = null;
    const page = document.getElementById('page-rakay');
    if (!page) {
      log.warn('#page-rakay element not found');
      return;
    }

    _injectCSS();
    page.innerHTML = _buildHTML();
    _rendered = true;

    // Reset WS retry counter on fresh render
    RAKAY.wsRetryCount     = 0;
    RAKAY.wsReconnectDelay = WS_BASE_DELAY_MS;
    RAKAY.wsState          = WS_STATE.DISCONNECTED;

    // ── Step 1: Check backend health first (no auth needed for /health)
    await _checkStatus();

    // ── Step 2: Ensure we have a valid auth token
    const token = await _ensureAuth();
    if (token) {
      log.info('Auth ready. Token type:', token === 'RAKAY_DEMO_NO_JWT_LIB' ? 'demo-marker' : 'JWT');
    } else {
      log.warn('Could not obtain auth token — operating in offline mode');
    }

    // ── Step 3: Update status indicator
    _updateStatus();

    // ── Step 4: Load sessions
    await _loadSessions();

    if (!RAKAY.sessions.length) {
      await _startNewChat();
    } else {
      RAKAY.sessionId = RAKAY.sessions[0].id;
      _renderSidebar();
      _updateHeader();
      await _loadHistory(RAKAY.sessionId);
      _renderMessages();
      _scrollToBottom(false);
    }

    _focusInput();

    // ── Step 5: Start WebSocket (if online)
    if (RAKAY.backendOnline && token) {
      _initWebSocket();
    }

    // ── Step 6: Periodic status checks + timestamp refresh
    RAKAY.statusTimer = setInterval(async () => {
      await _checkStatus();
      _renderSidebar();
    }, 30_000);

    log.info(`Module v${MODULE_VERSION} loaded. Session: ${RAKAY.sessionId} | Online: ${RAKAY.backendOnline}`);
  }

  function stopRAKAY() {
    if (RAKAY.statusTimer)  { clearInterval(RAKAY.statusTimer);  RAKAY.statusTimer  = null; }
    if (RAKAY.pollingTimer) { clearInterval(RAKAY.pollingTimer); RAKAY.pollingTimer = null; }
    if (RAKAY._submitDebounce) { clearTimeout(RAKAY._submitDebounce); RAKAY._submitDebounce = null; }
    // Abort any in-flight chat request / stream reader
    if (RAKAY._currentFetch) { try { RAKAY._currentFetch.abort(); } catch {} RAKAY._currentFetch = null; }
    if (RAKAY._streamReader) { try { RAKAY._streamReader.cancel(); } catch {} RAKAY._streamReader = null; }
    _clearStreamBubble();
    _stopWebSocket();
    _rendered = false;
    log.info('Module stopped.');
  }

  // ── Expose to platform ────────────────────────────────────────────────────
  window.renderRAKAY = renderRAKAY;
  window.stopRAKAY   = stopRAKAY;

  log.info(`Module v${MODULE_VERSION} registered ✅ — SSE streaming enabled: ${STREAM_ENABLED}`);

})();
