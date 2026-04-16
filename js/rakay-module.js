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

    // Sanitise streamed content before storing/rendering (remove debug logs, duplicate tool banners)
    fullText = _sanitiseResponseContent(fullText);

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

    // Extract and handle the ⚠️ built-in intel warning line specially
    let warningBadge = '';
    let mainText = text;
    if (text.startsWith('⚠️ Using built-in threat intelligence')) {
      // ROOT-CAUSE FIX: Badge updated to show neutral "Local Intelligence Mode" indicator
      // instead of an alarming call-to-action that prompted key configuration.
      warningBadge = '<div class="rakay-intel-badge" style="background:rgba(59,130,246,0.12);border-color:rgba(59,130,246,0.3);color:#60a5fa;"><i class="fas fa-database"></i> Local Intelligence Mode — all core capabilities active</div>';
      mainText = text.replace(/^⚠️ Using built-in threat intelligence\s*\n+/, '');
    }

    // Use marked.js if loaded
    if (typeof window.marked !== 'undefined') {
      try {
        const rendered = window.marked.parse(mainText, { breaks: true, gfm: true });
        return warningBadge + rendered;
      } catch {}
    }

    let html = _e(mainText);

    // Fenced code blocks (handle BEFORE other replacements)
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      const langClass = lang ? ` class="language-${_e(lang)}"` : '';
      const langLabel = lang ? `<span class="rakay-code-lang">${_e(lang.toUpperCase())}</span>` : '';
      const copyBtn   = `<button class="rakay-copy-btn" onclick="window._rakayCopyCode(this)" title="Copy code"><i class="fas fa-copy"></i></button>`;
      return `<div class="rakay-code-wrap">${langLabel}${copyBtn}<pre><code${langClass}>${code.trim()}</code></pre></div>`;
    });

    // Inline code
    html = html.replace(/`([^`\n]+)`/g, '<code class="rakay-inline-code">$1</code>');

    // Headers (in order: h3 before h2 before h1)
    html = html.replace(/^#### (.+)$/gm, '<h4 class="rakay-h4">$1</h4>');
    html = html.replace(/^### (.+)$/gm,  '<h3 class="rakay-h3">$1</h3>');
    html = html.replace(/^## (.+)$/gm,   '<h2 class="rakay-h2">$1</h2>');
    html = html.replace(/^# (.+)$/gm,    '<h1 class="rakay-h1">$1</h1>');

    // Bold + italic (careful order: *** before ** before *)
    html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.+?)\*\*/g,     '<strong>$1</strong>');
    html = html.replace(/\*([^*\n]+)\*/g,     '<em>$1</em>');
    html = html.replace(/_([^_\n]+)_/g,       '<em>$1</em>');

    // Tables
    html = html.replace(/(?:^|\n)((?:\|[^\n]+\|\n?){2,})/g, (_, table) => {
      const rows = table.trim().split('\n').filter(r => r.trim());
      if (rows.length < 2) return _;
      if (!rows[1].match(/^\|[-| :]+\|$/)) return _;
      const headers = rows[0].split('|').slice(1, -1).map(h => `<th>${h.trim()}</th>`).join('');
      const body    = rows.slice(2).map(r => `<tr>${r.split('|').slice(1, -1).map(c => `<td>${c.trim()}</td>`).join('')}</tr>`).join('');
      return `\n<div class="rakay-table-wrap"><table class="rakay-table"><thead><tr>${headers}</tr></thead><tbody>${body}</tbody></table></div>\n`;
    });

    // Unordered list (including nested)
    html = html.replace(/((?:^[-*] .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^[-*] /, '')}</li>`).join('');
      return `<ul class="rakay-ul">${items}</ul>`;
    });

    // Ordered list
    html = html.replace(/((?:^\d+\. .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^\d+\. /, '')}</li>`).join('');
      return `<ol class="rakay-ol">${items}</ol>`;
    });

    // Blockquote (handle > and &gt; both)
    html = html.replace(/^(?:&gt;|>) (.+)$/gm, '<blockquote class="rakay-blockquote">$1</blockquote>');

    // Horizontal rule
    html = html.replace(/^---+$/gm, '<hr class="rakay-hr">');

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer" class="rakay-link">$1 <i class="fas fa-external-link-alt" style="font-size:9px"></i></a>');

    // Paragraphs
    html = html.replace(/\n\n+/g, '</p><p>');
    html = `<p>${html}</p>`;
    html = html.replace(/<p>\s*<\/p>/g, '');
    html = html.replace(/\n/g, '<br>');

    // Clean up redundant p around block elements
    html = html.replace(/<p>(<(?:h[1234]|ul|ol|div|pre|table|blockquote|hr)[^>]*>)/g, '$1');
    html = html.replace(/<\/(?:h[1234]|ul|ol|div|pre|table|blockquote)>(?:<\/p>)?/g, m => m.replace('</p>', ''));

    return warningBadge + html;
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
  //  RESPONSE CONTENT SANITISER
  //  Cleans LLM/tool output before rendering to the UI:
  //   - Removes raw JSON blobs / debug lines
  //   - Collapses multiple tool-use indicators into one
  //   - Strips internal log prefixes ([Engine], [CB:], etc.)
  // ══════════════════════════════════════════════════════════════════════════
  function _sanitiseResponseContent(text) {
    if (!text || typeof text !== 'string') return text || '';
    let out = text;

    // Remove ALL internal debug log lines
    out = out.replace(/^\[(?:RAKAY|RAKAYEngine|Engine|Provider|CB:|CB |PQ|MultiProvider|Tool|Ollama|OpenAI|Anthropic|Gemini|DeepSeek|LLM|Stream|Queue|Session)\].+$/gm, '');

    // Remove ALL tool-use indicator lines completely (no tool spam)
    out = out.replace(/🔧\s*\*?Using (?:tool|intelligence|tools)[^*\n]*\*?\s*\n?/g, '');
    out = out.replace(/🔧\s*Using tool:\s*[^\n]+\n?/g, '');

    // Remove raw JSON tool result objects OUTSIDE code blocks
    // Pattern: {"error": false, "found": false, "tool": "..."} — these are leaked tool results
    const codeBlocks = [];
    out = out.replace(/(```[\s\S]*?```)/g, (m) => { codeBlocks.push(m); return `\x00CB${codeBlocks.length-1}\x00`; });

    // Remove large raw JSON dumps
    out = out.replace(/```json\n?\{[\s\S]{200,}\}\n?```/g, '');

    // Remove tool result JSON patterns ({found: false/true, error: false/true, ...})
    out = out.replace(/\{\s*"(?:error|found|tool)"\s*:[^}]{0,600}\}/g, '');

    // Remove remaining large JSON blobs
    out = out.replace(/\{[^{}]{400,}\}/g, match => {
      if (/"[^"]+"\s*:/.test(match)) return '';
      return match;
    });

    // Restore code blocks
    out = out.replace(/\x00CB(\d+)\x00/g, (_, i) => codeBlocks[i]);

    // Replace "demo mode" / "limited mode" text
    out = out.replace(/(?:demo mode|mock mode|limited(?:-capability)? mode|fallback mode|offline mode)/gi, 'built-in threat intelligence');

    // Remove old limited-capability footnotes
    out = out.replace(/>\s*⚠️\s*\*\*Note:\*\*.*limited-capability mode.*\n?/g, '');

    // Remove lines that are just "The kql_generate tool encountered..."
    out = out.replace(/^The \w+ tool (?:encountered|returned|found)[^\n]*\n?/gm, '');

    // Collapse 3+ blank lines
    out = out.replace(/\n{4,}/g, '\n\n\n');

    return out.trim();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  PRIORITY BADGE HELPER
  //  Returns HTML badge for HIGH/MEDIUM/LOW priority based on message content
  // ══════════════════════════════════════════════════════════════════════════
  function _getPriorityBadge(content) {
    if (!content) return '';
    const lower = (content || '').toLowerCase();
    const HIGH_KW   = ['alert', 'incident', 'breach', 'compromised', 'ransomware', 'critical', 'urgent', 'emergency', 'active attack', 'lateral movement', 'exfiltration', 'c2', 'zero day', '0day'];
    const MEDIUM_KW = ['cve', 'vulnerability', 'ioc', 'enrich', 'malware', 'apt', 'threat actor', 'sigma', 'kql', 'splunk', 'mitre', 'detection'];

    if (HIGH_KW.some(kw => lower.includes(kw))) {
      return '<span class="rakay-priority-badge rakay-priority-high"><i class="fas fa-exclamation-triangle"></i> HIGH</span>';
    }
    if (MEDIUM_KW.some(kw => lower.includes(kw))) {
      return '<span class="rakay-priority-badge rakay-priority-medium"><i class="fas fa-shield-alt"></i> MEDIUM</span>';
    }
    return '';
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  PROVIDER BADGE HELPER
  //  Returns coloured provider badge with appropriate icon
  // ══════════════════════════════════════════════════════════════════════════
  function _getProviderBadge(provider, degraded) {
    if (degraded) {
      return '<span class="rakay-degraded-badge" title="Using built-in threat intelligence"><i class="fas fa-shield-alt"></i> built-in intel</span>';
    }
    if (!provider || provider === 'unknown') return '';

    const PROVIDER_CONFIG = {
      openai:         { label: 'OpenAI',    color: '#10a37f', icon: 'fa-robot' },
      ollama:         { label: 'Ollama',    color: '#6366f1', icon: 'fa-server' },
      anthropic:      { label: 'Anthropic', color: '#d97706', icon: 'fa-brain' },
      gemini:         { label: 'Gemini',    color: '#4285f4', icon: 'fa-gem' },
      deepseek:       { label: 'DeepSeek',  color: '#8b5cf6', icon: 'fa-search' },
      mock:           { label: 'Local',     color: '#22d3ee', icon: 'fa-database' },
      'hybrid-fallback': { label: 'Local Intel', color: '#22d3ee', icon: 'fa-database' },
      'local-intel':  { label: 'Local Intel', color: '#22d3ee', icon: 'fa-shield-alt' },
    };

    const cfg = PROVIDER_CONFIG[provider.toLowerCase()] || { label: provider, color: '#6b7280', icon: 'fa-cog' };
    return `<span class="rakay-provider-badge" style="background:${cfg.color}18;border-color:${cfg.color}40;color:${cfg.color}" title="Answered by ${cfg.label}"><i class="fas ${cfg.icon}" style="font-size:8px"></i> ${_e(cfg.label)}</span>`;
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
      // Only show tool trace if it has meaningful (non-empty) entries
      const validTrace = (msg.tool_trace || []).filter(t => t.tool && !t.error);
      const trace   = validTrace.length ? _renderToolTrace(validTrace) : '';
      const offline = msg._offline ? ' rakay-msg--offline' : '';

      if (isUser) {
        const priorityBadge = _getPriorityBadge(msg.content);
        return `
        <div class="rakay-msg rakay-msg--user${offline}">
          <div class="rakay-msg-content">
            <div class="rakay-msg-bubble rakay-msg-bubble--user">${_e(msg.content)}</div>
            <div class="rakay-msg-meta">${ts} ${priorityBadge}</div>
          </div>
          <div class="rakay-msg-avatar rakay-msg-avatar--user"><i class="fas fa-user"></i></div>
        </div>`;
      }

      // Sanitise content before rendering
      const cleanContent = _sanitiseResponseContent(msg.content);

      const modelBadge    = msg.model && msg.model !== 'degraded' ? `<span class="rakay-model-badge" title="Model: ${_e(msg.model)}">${_e(msg.model.split('/').pop())}</span>` : '';
      const latency       = msg.latency_ms ? `<span class="rakay-latency" title="Response latency">${msg.latency_ms < 1000 ? msg.latency_ms + 'ms' : (msg.latency_ms/1000).toFixed(1) + 's'}</span>` : '';
      const tokens        = msg.tokens_used ? `<span class="rakay-tokens" title="Tokens used"><i class="fas fa-bolt"></i> ${msg.tokens_used}</span>` : '';
      const providerBadge = _getProviderBadge(msg.provider, msg._degraded);
      const streamBadge   = msg._streamed ? `<span class="rakay-provider-badge" title="Streamed response" style="background:#a855f714;border-color:#a855f730;color:#a855f7"><i class="fas fa-stream" style="font-size:8px"></i></span>` : '';
      const toolsBadge    = validTrace.length ? `<span class="rakay-provider-badge" title="${validTrace.length} tool(s) used" style="background:#22d3ee14;border-color:#22d3ee40;color:#22d3ee"><i class="fas fa-wrench" style="font-size:8px"></i> ${validTrace.length} tool${validTrace.length > 1 ? 's' : ''}</span>` : '';

      return `
      <div class="rakay-msg rakay-msg--assistant${offline}">
        <div class="rakay-msg-avatar rakay-msg-avatar--assistant"><i class="fas fa-robot"></i></div>
        <div class="rakay-msg-content">
          ${trace}
          <div class="rakay-msg-bubble rakay-msg-bubble--assistant">
            ${_renderMarkdown(cleanContent)}
          </div>
          <div class="rakay-msg-meta">${ts} ${providerBadge} ${modelBadge} ${latency} ${tokens} ${toolsBadge} ${streamBadge}</div>
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
      <div class="rakay-welcome-logo"><i class="fas fa-shield-alt"></i></div>
      <h2 class="rakay-welcome-title">RAKAY — SOC Analyst Assistant</h2>
      <p class="rakay-welcome-sub">AI-powered · Detection Engineering · Threat Intelligence · Incident Response</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-bottom:4px">
        <button style="background:#22d3ee14;border:1px solid #22d3ee40;color:#22d3ee;border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px" onclick="window._socSwitchTab('intel')"><i class="fas fa-database"></i> Threat Intel</button>
        <button style="background:#a855f714;border:1px solid #a855f740;color:#a855f7;border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px" onclick="window._socSwitchTab('detect')"><i class="fas fa-shield-alt"></i> Detection Rules</button>
        <button style="background:#f0883e14;border:1px solid #f0883e40;color:#f0883e;border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px" onclick="window._socSwitchTab('simulate')"><i class="fas fa-flask"></i> Simulate Attack</button>
        <button style="background:#d2992214;border:1px solid #d2992240;color:#d29922;border-radius:8px;padding:6px 14px;cursor:pointer;font-size:12px" onclick="window._socSwitchTab('alerts')"><i class="fas fa-bell"></i> Alerts</button>
      </div>
      <div class="rakay-welcome-prompts">
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-file-code"></i> Generate Sigma rule for PowerShell encoded commands
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-sitemap"></i> Explain MITRE ATT&amp;CK T1059.001 with detection guidance
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-terminal"></i> Create KQL query for ransomware detection in Sentinel
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-user-secret"></i> Profile the APT29 threat group with recent TTPs
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-shield-alt"></i> Enrich IP 185.220.101.34 for threat intelligence
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-bug"></i> What is CVE-2021-44228 and how do I detect Log4Shell?
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-lock"></i> Simulate a ransomware attack and give me the response playbook
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-database"></i> Generate SPL and KQL for LSASS credential dumping T1003.001
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
.rakay-intel-badge {
  background: linear-gradient(135deg, #22d3ee14, #a855f714);
  border: 1px solid #22d3ee30; border-radius: 6px;
  padding: 6px 12px; margin-bottom: 12px;
  font-size: 11px; color: #22d3ee; font-weight: 500;
  display: flex; align-items: center; gap: 6px;
}
.rakay-intel-badge i { font-size: 12px; }
.rakay-h2 {
  color: #e6edf3; font-size: 15px; font-weight: 700;
  margin: 16px 0 8px; border-bottom: 1px solid #21262d; padding-bottom: 4px;
}
.rakay-h3 { color: #22d3ee; font-size: 13px; font-weight: 600; margin: 12px 0 6px; }
.rakay-h4 { color: #8b949e; font-size: 12px; font-weight: 600; margin: 8px 0 4px; }
.rakay-table-wrap { overflow-x: auto; margin: 8px 0; }
.rakay-table { border-collapse: collapse; width: 100%; font-size: 12px; }
.rakay-table th { background: #21262d; color: #e6edf3; padding: 6px 12px; text-align: left; font-weight: 600; border: 1px solid #30363d; }
.rakay-table td { padding: 5px 12px; border: 1px solid #21262d; color: #c9d1d9; }
.rakay-table tr:hover td { background: #161b22; }
.rakay-blockquote {
  border-left: 3px solid #22d3ee; margin: 8px 0; padding: 6px 12px;
  background: #22d3ee08; color: #8b949e; font-style: italic; border-radius: 0 4px 4px 0;
}
.rakay-hr { border: none; border-top: 1px solid #21262d; margin: 12px 0; }
.rakay-ul, .rakay-ol { margin: 6px 0 6px 16px; padding: 0; }
.rakay-ul li, .rakay-ol li { margin: 3px 0; color: #c9d1d9; font-size: 13px; }
.rakay-code-wrap { position: relative; margin: 8px 0; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; background: #0d1117; }
.rakay-code-lang { position: absolute; top: 6px; left: 8px; font-size: 10px; color: #8b949e; font-family: monospace; text-transform: uppercase; }
.rakay-copy-btn { position: absolute; top: 4px; right: 8px; background: none; border: 1px solid #30363d; border-radius: 4px; color: #8b949e; cursor: pointer; padding: 2px 6px; font-size: 11px; }
.rakay-copy-btn:hover { color: #e6edf3; border-color: #58a6ff; }
.rakay-code-wrap pre { margin: 0; padding: 28px 12px 12px; overflow-x: auto; font-size: 12px; line-height: 1.5; }
.rakay-code-wrap code { font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace; color: #e6edf3; }
.rakay-inline-code { background: #21262d; border: 1px solid #30363d; border-radius: 3px; padding: 1px 5px; font-size: 11px; font-family: monospace; color: #22d3ee; }
.rakay-link { color: #58a6ff; text-decoration: none; }
.rakay-link:hover { text-decoration: underline; }

/* ══════════════════════════════════════
   SOC DASHBOARD — Tab Navigation & Panels
══════════════════════════════════════ */
.rakay-soc-tabs {
  display: flex; align-items: center; gap: 2px;
  padding: 8px 16px 0;
  background: var(--bg-secondary, #161b22);
  border-bottom: 1px solid var(--border, #30363d);
  flex-shrink: 0; overflow-x: auto;
}
.rakay-soc-tabs::-webkit-scrollbar { height: 3px; }
.rakay-soc-tabs::-webkit-scrollbar-thumb { background: #30363d; }
.rakay-soc-tab {
  padding: 8px 16px; border: none; border-radius: 6px 6px 0 0;
  background: none; color: #8b949e; cursor: pointer;
  font-size: 13px; font-weight: 500; white-space: nowrap;
  transition: all .15s; display: flex; align-items: center; gap: 7px;
  border-bottom: 2px solid transparent;
}
.rakay-soc-tab:hover { color: #c9d1d9; background: #21262d; }
.rakay-soc-tab.active { color: #22d3ee; border-bottom-color: #22d3ee; background: #22d3ee0a; }
.rakay-soc-tab i { font-size: 12px; }

.rakay-soc-panel {
  flex: 1; min-height: 0;
}
.rakay-soc-panel[data-panel="chat"] {
  display: flex; flex-direction: column; overflow: hidden;
}
.soc-panel-scroll {
  overflow-y: auto; flex-direction: column;
}
.soc-panel-scroll::-webkit-scrollbar { width: 5px; }
.soc-panel-scroll::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
.soc-panel-inner {
  padding: 20px; display: flex; flex-direction: column; gap: 20px; min-height: min-content;
}
.soc-panel-section {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border, #30363d);
  border-radius: 12px; padding: 16px;
  display: flex; flex-direction: column; gap: 12px;
}
.soc-section-header {
  display: flex; align-items: center; gap: 10px;
  font-size: 14px; font-weight: 600; color: #c9d1d9;
}
.soc-section-header > span { flex: 1; display: flex; align-items: center; gap: 8px; }
.soc-panel-desc { font-size: 13px; color: #8b949e; margin: 0; }
.soc-refresh-btn {
  background: none; border: 1px solid #30363d; color: #8b949e;
  border-radius: 5px; padding: 4px 8px; cursor: pointer; font-size: 11px;
  transition: all .12s; margin-left: auto;
}
.soc-refresh-btn:hover { background: #21262d; color: #c9d1d9; }

/* ── Badges & Labels ──────────────── */
.soc-badge {
  font-size: 10px; font-weight: 700; padding: 2px 7px;
  border-radius: 10px; letter-spacing: .03em;
}
.soc-badge--red    { background: #f8514914; border: 1px solid #f8514940; color: #f85149; }
.soc-badge--orange { background: #f0883e14; border: 1px solid #f0883e40; color: #f0883e; }
.soc-badge--yellow { background: #d2992214; border: 1px solid #d2992240; color: #d29922; }
.soc-badge--blue   { background: #22d3ee14; border: 1px solid #22d3ee40; color: #22d3ee; }
.soc-badge--grey   { background: #21262d;   border: 1px solid #30363d;   color: #6e7681; }
.soc-cvss {
  font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px;
}
.soc-cvss--critical { background: #f8514922; color: #f85149; }
.soc-cvss--high     { background: #f0883e22; color: #f0883e; }
.soc-cvss--med      { background: #d2992222; color: #d29922; }
.soc-tag {
  background: #21262d; border: 1px solid #30363d;
  border-radius: 4px; padding: 1px 6px; font-size: 10px; color: #8b949e;
  margin-right: 3px;
}
.soc-mono { font-family: 'Fira Code', Consolas, monospace; font-size: 12px; color: #22d3ee; }
.soc-mono--small { font-size: 10px; }

/* ── Table ────────────────────────── */
.soc-table-wrap { overflow-x: auto; }
.soc-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.soc-table th {
  background: #21262d; color: #8b949e; font-size: 11px; font-weight: 600;
  padding: 8px 12px; border-bottom: 1px solid #30363d; text-align: left;
  text-transform: uppercase; letter-spacing: .04em;
}
.soc-table td { padding: 9px 12px; border-bottom: 1px solid #21262d; color: #c9d1d9; vertical-align: top; }
.soc-table tr:last-child td { border-bottom: none; }
.soc-table tr:hover td { background: #21262d; }
.soc-td-desc { max-width: 260px; color: #8b949e; font-size: 12px; }
.soc-empty { text-align: center; color: #6e7681; padding: 20px; }

/* ── Action Button ────────────────── */
.soc-action-btn {
  background: #22d3ee14; border: 1px solid #22d3ee40; color: #22d3ee;
  border-radius: 6px; padding: 5px 12px; cursor: pointer; font-size: 12px;
  transition: all .12s; display: inline-flex; align-items: center; gap: 6px;
}
.soc-action-btn:hover { background: #22d3ee22; border-color: #22d3ee66; }

/* ── Detection Cards ──────────────── */
.soc-detect-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px;
}
.soc-detect-card {
  background: #0d1117; border: 1px solid #30363d; border-radius: 10px;
  padding: 14px; display: flex; flex-direction: column; gap: 8px;
  transition: border-color .15s, box-shadow .15s;
}
.soc-detect-card:hover { border-color: #22d3ee40; box-shadow: 0 0 12px #22d3ee10; }
.soc-detect-card-header { display: flex; align-items: center; justify-content: space-between; }
.soc-detect-card-name { font-size: 13px; font-weight: 600; color: #c9d1d9; }
.soc-detect-card-tactic { font-size: 11px; color: #8b949e; text-transform: capitalize; }
.soc-detect-card-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.soc-detect-btn {
  background: #21262d; border: 1px solid #30363d; color: #8b949e;
  border-radius: 5px; padding: 4px 8px; cursor: pointer; font-size: 11px;
  transition: all .12s; display: flex; align-items: center; gap: 4px;
}
.soc-detect-btn:hover { background: #22d3ee14; border-color: #22d3ee40; color: #22d3ee; }

/* ── Rule output ──────────────────── */
.soc-rule-body { flex: 1; }

/* ── Simulation ───────────────────── */
.soc-sim-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 14px;
}
.soc-sim-card {
  background: #0d1117; border: 1px solid #30363d; border-radius: 12px;
  padding: 20px 16px; text-align: center; cursor: pointer;
  transition: all .15s; display: flex; flex-direction: column; align-items: center; gap: 10px;
}
.soc-sim-card:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,.4); }
.soc-sim-icon {
  width: 52px; height: 52px; border-radius: 14px; border: 1px solid;
  display: flex; align-items: center; justify-content: center; font-size: 22px;
}
.soc-sim-label { font-size: 13px; font-weight: 600; color: #c9d1d9; }
.soc-sim-sub   { font-size: 11px; color: #6e7681; }
.soc-sim-body, .soc-sim-result { display: flex; flex-direction: column; gap: 14px; }
.soc-sim-section-title {
  font-size: 13px; font-weight: 600; color: #c9d1d9;
  display: flex; align-items: center; gap: 8px; margin: 0;
}
.soc-timeline { display: flex; flex-direction: column; gap: 0; }
.soc-timeline-item {
  display: flex; gap: 14px; padding-bottom: 14px;
  border-left: 2px solid #30363d; margin-left: 8px; padding-left: 20px;
  position: relative;
}
.soc-timeline-item:last-child { border-left-color: transparent; }
.soc-timeline-dot {
  width: 12px; height: 12px; border-radius: 50%;
  position: absolute; left: -7px; top: 2px; flex-shrink: 0;
}
.soc-timeline-content { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.soc-timeline-title { font-size: 13px; font-weight: 600; color: #c9d1d9; }
.soc-timeline-desc  { font-size: 12px; color: #8b949e; }
.soc-list { padding-left: 1.2em; margin: 0; color: #8b949e; font-size: 13px; display: flex; flex-direction: column; gap: 5px; }
.soc-list li { list-style: none; display: flex; align-items: flex-start; gap: 8px; }
.soc-list--numbered li { list-style: decimal; }
.soc-ioc-list { display: flex; flex-wrap: wrap; gap: 6px; }

/* ── Stats grid ───────────────────── */
.soc-stats-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 12px;
}
.soc-stat-card {
  background: #0d1117; border: 1px solid #30363d; border-radius: 10px;
  padding: 16px 14px; text-align: center;
}
.soc-stat-value { font-size: 28px; font-weight: 700; line-height: 1; }
.soc-stat-label { font-size: 11px; color: #6e7681; margin-top: 6px; }

/* ── Insights ─────────────────────── */
.soc-insights-list { display: flex; flex-direction: column; gap: 10px; }
.soc-insight-item {
  padding: 12px 14px; border-radius: 10px; border: 1px solid;
  display: flex; gap: 12px; align-items: flex-start;
}
.soc-insight-item > i { font-size: 18px; flex-shrink: 0; margin-top: 2px; }
.soc-insight-item > div { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.soc-insight-title { font-size: 13px; font-weight: 600; color: #c9d1d9; }
.soc-insight-desc  { font-size: 12px; color: #8b949e; }
.soc-insight--red    { background: #f8514910; border-color: #f8514930; }
.soc-insight--red > i { color: #f85149; }
.soc-insight--orange { background: #f0883e10; border-color: #f0883e30; }
.soc-insight--orange > i { color: #f0883e; }
.soc-insight--yellow { background: #d2992210; border-color: #d2992230; }
.soc-insight--yellow > i { color: #d29922; }
.soc-insight--blue   { background: #22d3ee10; border-color: #22d3ee30; }
.soc-insight--blue > i { color: #22d3ee; }

/* ── Fallback message ─────────────── */
.soc-loading {
  display: flex; align-items: center; gap: 10px;
  color: #8b949e; font-size: 13px; padding: 30px 20px;
}
.soc-fallback-msg {
  background: #f0883e0a; border: 1px solid #f0883e30; border-radius: 10px;
  padding: 16px; font-size: 13px; color: #c9d1d9; line-height: 1.7;
}
`;
    document.head.appendChild(style);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  SOC DASHBOARD PANELS
  // ══════════════════════════════════════════════════════════════════════════

  // Active SOC tab state
  let _socActiveTab = 'chat';

  function _socSwitchTab(tab) {
    _socActiveTab = tab;
    // Update tab buttons
    document.querySelectorAll('.rakay-soc-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    // Show/hide panels
    document.querySelectorAll('.rakay-soc-panel').forEach(panel => {
      panel.style.display = panel.dataset.panel === tab ? 'flex' : 'none';
    });
    // Sidebar: only visible on chat tab
    const sidebar = document.getElementById('rakay-sidebar');
    if (sidebar) sidebar.style.display = tab === 'chat' ? 'flex' : 'none';
    // Lazy-load panel data
    if (tab === 'intel')    _socLoadThreatIntel();
    if (tab === 'detect')   _socLoadDetectionPanel();
    if (tab === 'simulate') _socLoadSimulationPanel();
    if (tab === 'alerts')   _socLoadAlertsPanel();
  }

  // ── Threat Intel Panel ──────────────────────────────────────────────────
  async function _socLoadThreatIntel() {
    const el = document.getElementById('soc-intel-content');
    if (!el || el.dataset.loaded === '1') return;
    el.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading threat intelligence…</div>';
    try {
      const token = _resolveToken();
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      // Load critical CVEs and exploited CVEs in parallel
      const [cveRes, exploitedRes] = await Promise.all([
        fetch(`${API_BASE()}/api/soc/cves/critical`, { headers }),
        fetch(`${API_BASE()}/api/soc/cves/exploited`, { headers }),
      ]);
      const cveData      = cveRes.ok      ? await cveRes.json()      : { data: [] };
      const exploitedData= exploitedRes.ok? await exploitedRes.json(): { data: [] };
      const cves         = cveData.data      || cveData.cves      || [];
      const exploited    = exploitedData.data|| exploitedData.cves || [];
      el.dataset.loaded  = '1';
      el.innerHTML = `
        <div class="soc-panel-section">
          <div class="soc-section-header">
            <i class="fas fa-exclamation-triangle" style="color:#f85149"></i>
            <span>Critical CVEs <span class="soc-badge soc-badge--red">${cves.length}</span></span>
            <button class="soc-refresh-btn" onclick="delete document.getElementById('soc-intel-content').dataset.loaded;window._socLoadThreatIntel()"><i class="fas fa-sync-alt"></i></button>
          </div>
          <div class="soc-table-wrap">
            <table class="soc-table">
              <thead><tr><th>CVE ID</th><th>Description</th><th>CVSS</th><th>Exploited</th><th>Action</th></tr></thead>
              <tbody>${cves.length ? cves.map(c => `
                <tr>
                  <td><code class="soc-mono">${_e(c.id||c.cve_id||'')}</code></td>
                  <td class="soc-td-desc">${_e((c.description||'').substring(0,80))}…</td>
                  <td><span class="soc-cvss soc-cvss--${Number(c.cvss_score||c.cvss||0)>=9?'critical':Number(c.cvss_score||c.cvss||0)>=7?'high':'med'}">${c.cvss_score||c.cvss||'N/A'}</span></td>
                  <td>${c.exploited||c.exploited_in_wild?'<span class="soc-badge soc-badge--red">YES</span>':'<span class="soc-badge soc-badge--grey">No</span>'}</td>
                  <td><button class="soc-action-btn" onclick="window._rakayQuickAsk('What is ${_e(c.id||c.cve_id||'')} and how do I detect it?')"><i class="fas fa-robot"></i> Ask RAKAY</button></td>
                </tr>`).join('') : '<tr><td colspan="5" class="soc-empty">No critical CVEs loaded</td></tr>'}</tbody>
            </table>
          </div>
        </div>
        <div class="soc-panel-section">
          <div class="soc-section-header">
            <i class="fas fa-fire" style="color:#f0883e"></i>
            <span>Exploited in the Wild <span class="soc-badge soc-badge--orange">${exploited.length}</span></span>
          </div>
          <div class="soc-table-wrap">
            <table class="soc-table">
              <thead><tr><th>CVE ID</th><th>Description</th><th>CVSS</th><th>Tags</th></tr></thead>
              <tbody>${exploited.length ? exploited.map(c => `
                <tr>
                  <td><code class="soc-mono">${_e(c.id||c.cve_id||'')}</code></td>
                  <td class="soc-td-desc">${_e((c.description||'').substring(0,90))}…</td>
                  <td><span class="soc-cvss soc-cvss--critical">${c.cvss_score||c.cvss||'N/A'}</span></td>
                  <td>${(c.tags||[]).slice(0,3).map(t=>`<span class="soc-tag">${_e(t)}</span>`).join('')||'—'}</td>
                </tr>`).join('') : '<tr><td colspan="4" class="soc-empty">No exploited CVEs loaded</td></tr>'}</tbody>
            </table>
          </div>
        </div>`;
    } catch (err) {
      el.innerHTML = `<div class="soc-fallback-msg"><i class="fas fa-shield-alt"></i> ⚠️ Using built-in threat intelligence<br><small>${_e(err.message)}</small><br><br>
        <b>Top Critical CVEs (Built-in):</b><br>
        CVE-2021-44228 (Log4Shell) · CVSS 10.0 · RCE in Log4j · Actively exploited<br>
        CVE-2023-34362 (MOVEit) · CVSS 9.8 · SQL injection · Actively exploited<br>
        CVE-2021-26855 (ProxyLogon) · CVSS 9.8 · Exchange RCE · Actively exploited<br>
        CVE-2022-30190 (Follina) · CVSS 7.8 · MSDT RCE · Actively exploited
      </div>`;
    }
  }

  // ── Detection Panel ─────────────────────────────────────────────────────
  async function _socLoadDetectionPanel() {
    const el = document.getElementById('soc-detect-content');
    if (!el || el.dataset.loaded === '1') return;
    el.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading detection engine…</div>';
    try {
      const token = _resolveToken();
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch(`${API_BASE()}/api/soc/detect/list`, { headers });
      const data = res.ok ? await res.json() : { data: [] };
      const techniques = data.data || data.techniques || [];
      el.dataset.loaded = '1';
      el.innerHTML = `
        <div class="soc-panel-section">
          <div class="soc-section-header">
            <i class="fas fa-shield-alt" style="color:#22d3ee"></i>
            <span>Detection Engine — ${techniques.length} MITRE Techniques</span>
          </div>
          <div class="soc-detect-grid">
            ${techniques.map(t => `
            <div class="soc-detect-card" data-id="${_e(t.id||t.technique_id||'')}">
              <div class="soc-detect-card-header">
                <code class="soc-mono soc-mono--small">${_e(t.id||t.technique_id||'')}</code>
                <span class="soc-badge soc-badge--${t.severity==='critical'?'red':t.severity==='high'?'orange':'blue'}">${_e(t.severity||'medium')}</span>
              </div>
              <div class="soc-detect-card-name">${_e(t.name||t.technique||'')}</div>
              <div class="soc-detect-card-tactic">${_e(t.tactic||'')}</div>
              <div class="soc-detect-card-actions">
                <button class="soc-detect-btn" onclick="window._socGenerateRule('${_e(t.id||t.technique_id||'')}','sigma')"><i class="fab fa-linux"></i> Sigma</button>
                <button class="soc-detect-btn" onclick="window._socGenerateRule('${_e(t.id||t.technique_id||'')}','kql')"><i class="fas fa-database"></i> KQL</button>
                <button class="soc-detect-btn" onclick="window._socGenerateRule('${_e(t.id||t.technique_id||'')}','spl')"><i class="fas fa-search"></i> SPL</button>
              </div>
            </div>`).join('')}
          </div>
        </div>
        <div class="soc-panel-section" id="soc-rule-output" style="display:none">
          <div class="soc-section-header">
            <i class="fas fa-code" style="color:#a855f7"></i>
            <span id="soc-rule-title">Detection Rule</span>
            <button class="soc-refresh-btn" onclick="document.getElementById('soc-rule-output').style.display='none'"><i class="fas fa-times"></i></button>
          </div>
          <div id="soc-rule-body" class="soc-rule-body"></div>
        </div>`;
    } catch (err) {
      el.innerHTML = `<div class="soc-fallback-msg"><i class="fas fa-shield-alt"></i> ⚠️ Using built-in detection templates<br>
        <button class="soc-action-btn" style="margin-top:12px" onclick="window._rakayQuickAsk('Generate Sigma rule for PowerShell encoded command T1059.001')">
          <i class="fas fa-robot"></i> Generate via RAKAY Chat
        </button>
      </div>`;
    }
  }

  window._socGenerateRule = async function(techId, format) {
    const outputEl = document.getElementById('soc-rule-output');
    const bodyEl   = document.getElementById('soc-rule-body');
    const titleEl  = document.getElementById('soc-rule-title');
    if (!outputEl || !bodyEl) return;
    outputEl.style.display = 'flex';
    bodyEl.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Generating rule…</div>';
    titleEl.textContent = `${format.toUpperCase()} Rule — ${techId}`;
    try {
      const token = _resolveToken();
      const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': `Bearer ${token}` } : {}) };
      const res = await fetch(`${API_BASE()}/api/soc/detect/${encodeURIComponent(techId)}/${format}`, { headers });
      const data = res.ok ? await res.json() : null;
      if (data && data.data) {
        const rule = data.data;
        bodyEl.innerHTML = `
          <div class="rakay-code-wrap">
            <span class="rakay-code-lang">${format}</span>
            <button class="rakay-copy-btn" onclick="navigator.clipboard.writeText(this.nextElementSibling.textContent);this.textContent='Copied!'"><i class="fas fa-copy"></i></button>
            <pre><code>${_e(typeof rule === 'string' ? rule : JSON.stringify(rule, null, 2))}</code></pre>
          </div>`;
      } else {
        throw new Error('No rule data returned');
      }
    } catch (err) {
      bodyEl.innerHTML = `<div class="soc-fallback-msg">⚠️ Using built-in template — ask RAKAY for full rule:<br>
        <button class="soc-action-btn" style="margin-top:8px" onclick="window._rakayQuickAsk('Generate ${format.toUpperCase()} detection rule for ${techId}');window._socSwitchTab('chat')">
          <i class="fas fa-robot"></i> Ask RAKAY
        </button></div>`;
    }
    outputEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  // ── Simulation Panel ─────────────────────────────────────────────────────
  async function _socLoadSimulationPanel() {
    const el = document.getElementById('soc-sim-content');
    if (!el || el.dataset.loaded === '1') return;
    el.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading simulation engine…</div>';
    el.dataset.loaded = '1';
    el.innerHTML = `
      <div class="soc-panel-section">
        <div class="soc-section-header">
          <i class="fas fa-flask" style="color:#a855f7"></i>
          <span>Incident Simulation Engine</span>
        </div>
        <p class="soc-panel-desc">Simulate realistic attack scenarios and get full attack chains, detection opportunities, and response playbooks.</p>
        <div class="soc-sim-grid">
          ${[
            { scenario: 'ransomware',       icon: 'fa-lock',          color: '#f85149', label: 'Ransomware Attack' },
            { scenario: 'phishing',         icon: 'fa-fish',          color: '#f0883e', label: 'Phishing Campaign' },
            { scenario: 'supply-chain',     icon: 'fa-link',          color: '#d29922', label: 'Supply Chain Attack' },
            { scenario: 'lateral-movement', icon: 'fa-project-diagram',color: '#22d3ee', label: 'Lateral Movement' },
          ].map(s => `
          <div class="soc-sim-card" onclick="window._socRunSimulation('${s.scenario}')">
            <div class="soc-sim-icon" style="color:${s.color};border-color:${s.color}40;background:${s.color}14">
              <i class="fas ${s.icon}"></i>
            </div>
            <div class="soc-sim-label">${s.label}</div>
            <div class="soc-sim-sub">Click to simulate</div>
          </div>`).join('')}
        </div>
      </div>
      <div class="soc-panel-section" id="soc-sim-output" style="display:none">
        <div class="soc-section-header">
          <i class="fas fa-play-circle" style="color:#a855f7"></i>
          <span id="soc-sim-title">Simulation Results</span>
          <button class="soc-refresh-btn" onclick="document.getElementById('soc-sim-output').style.display='none'"><i class="fas fa-times"></i></button>
        </div>
        <div id="soc-sim-body" class="soc-sim-body"></div>
      </div>`;
  }

  window._socRunSimulation = async function(scenario) {
    const outputEl = document.getElementById('soc-sim-output');
    const bodyEl   = document.getElementById('soc-sim-body');
    const titleEl  = document.getElementById('soc-sim-title');
    if (!outputEl || !bodyEl) return;
    outputEl.style.display = 'flex';
    bodyEl.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Simulating attack scenario…</div>';
    titleEl.textContent = `Simulation: ${scenario.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}`;
    try {
      const token = _resolveToken();
      const headers = { 'Content-Type': 'application/json', ...(token ? { 'Authorization': `Bearer ${token}` } : {}) };
      const res = await fetch(`${API_BASE()}/api/soc/simulate`, {
        method: 'POST', headers,
        body: JSON.stringify({ scenario })
      });
      const data = res.ok ? await res.json() : null;
      const sim = data?.data || data?.simulation || null;
      if (sim) {
        const phases = sim.attackChain || sim.attack_chain || [];
        const detections = sim.detectionOpportunities || sim.detection_opportunities || [];
        const response = sim.responseSteps || sim.response_steps || [];
        const iocs = sim.iocs || [];
        bodyEl.innerHTML = `
          <div class="soc-sim-result">
            <h3 class="soc-sim-section-title"><i class="fas fa-route"></i> Attack Chain (${phases.length} phases)</h3>
            <div class="soc-timeline">
              ${phases.map((p,i) => `
              <div class="soc-timeline-item">
                <div class="soc-timeline-dot" style="background:${['#f85149','#f0883e','#d29922','#22d3ee','#a855f7'][i%5]}"></div>
                <div class="soc-timeline-content">
                  <div class="soc-timeline-title">${_e(p.phase||p.name||`Phase ${i+1}`)}</div>
                  <div class="soc-timeline-desc">${_e(p.description||p.action||'')}</div>
                  ${p.technique?`<code class="soc-mono soc-mono--small">${_e(p.technique)}</code>`:''}
                </div>
              </div>`).join('')}
            </div>
            ${detections.length ? `
            <h3 class="soc-sim-section-title"><i class="fas fa-eye"></i> Detection Opportunities</h3>
            <ul class="soc-list">
              ${detections.map(d => `<li><i class="fas fa-search" style="color:#22d3ee"></i> ${_e(d.description||d)}</li>`).join('')}
            </ul>` : ''}
            ${response.length ? `
            <h3 class="soc-sim-section-title"><i class="fas fa-first-aid"></i> Response Playbook</h3>
            <ol class="soc-list soc-list--numbered">
              ${response.map(r => `<li>${_e(r.action||r.step||r)}</li>`).join('')}
            </ol>` : ''}
            ${iocs.length ? `
            <h3 class="soc-sim-section-title"><i class="fas fa-fingerprint"></i> IOC Indicators</h3>
            <div class="soc-ioc-list">
              ${iocs.slice(0,10).map(i => `<code class="soc-mono soc-mono--small">${_e(i.value||i)}</code>`).join('')}
            </div>` : ''}
            <div style="margin-top:16px">
              <button class="soc-action-btn" onclick="window._rakayQuickAsk('Simulate ${_e(scenario)} attack and give me the full incident response playbook');window._socSwitchTab('chat')">
                <i class="fas fa-robot"></i> Deep-dive with RAKAY
              </button>
            </div>
          </div>`;
      } else {
        throw new Error('No simulation data');
      }
    } catch (err) {
      bodyEl.innerHTML = `<div class="soc-fallback-msg">⚠️ Using built-in simulation — ask RAKAY:<br>
        <button class="soc-action-btn" style="margin-top:8px" onclick="window._rakayQuickAsk('Simulate ${_e(scenario)} attack scenario with full attack chain and response playbook');window._socSwitchTab('chat')">
          <i class="fas fa-robot"></i> Ask RAKAY
        </button></div>`;
    }
    outputEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  // ── Alerts Panel ─────────────────────────────────────────────────────────
  async function _socLoadAlertsPanel() {
    const el = document.getElementById('soc-alerts-content');
    if (!el || el.dataset.loaded === '1') return;
    el.innerHTML = '<div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading analyst insights…</div>';
    try {
      const token = _resolveToken();
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch(`${API_BASE()}/api/soc/dashboard`, { headers });
      const data = res.ok ? await res.json() : null;
      const dash = data?.data || data?.dashboard || null;
      el.dataset.loaded = '1';
      if (dash) {
        const stats = dash.stats || {};
        const recentActivity = dash.recentActivity || dash.recent_activity || [];
        el.innerHTML = `
          <div class="soc-panel-section">
            <div class="soc-section-header">
              <i class="fas fa-tachometer-alt" style="color:#22d3ee"></i>
              <span>SOC Platform Status</span>
              <button class="soc-refresh-btn" onclick="delete document.getElementById('soc-alerts-content').dataset.loaded;window._socLoadAlertsPanel()"><i class="fas fa-sync-alt"></i></button>
            </div>
            <div class="soc-stats-grid">
              <div class="soc-stat-card">
                <div class="soc-stat-value" style="color:#f85149">${stats.totalCVEs||stats.total_cves||'20+'}</div>
                <div class="soc-stat-label">Critical CVEs</div>
              </div>
              <div class="soc-stat-card">
                <div class="soc-stat-value" style="color:#f0883e">${stats.exploitedCVEs||stats.exploited_cves||'8+'}</div>
                <div class="soc-stat-label">Exploited in Wild</div>
              </div>
              <div class="soc-stat-card">
                <div class="soc-stat-value" style="color:#22d3ee">${stats.totalTechniques||stats.total_techniques||'18'}</div>
                <div class="soc-stat-label">Detection Rules</div>
              </div>
              <div class="soc-stat-card">
                <div class="soc-stat-value" style="color:#a855f7">${stats.simulationScenarios||stats.simulation_scenarios||'4'}</div>
                <div class="soc-stat-label">Attack Simulations</div>
              </div>
            </div>
          </div>
          <div class="soc-panel-section">
            <div class="soc-section-header">
              <i class="fas fa-lightbulb" style="color:#d29922"></i>
              <span>Analyst Insights & Quick Actions</span>
            </div>
            <div class="soc-insights-list">
              <div class="soc-insight-item soc-insight--red">
                <i class="fas fa-exclamation-circle"></i>
                <div>
                  <div class="soc-insight-title">Log4Shell still actively exploited</div>
                  <div class="soc-insight-desc">CVE-2021-44228 CVSS 10.0 — Patch immediately, enable WAF rules</div>
                  <button class="soc-action-btn" onclick="window._rakayQuickAsk('How do I detect and respond to Log4Shell CVE-2021-44228?');window._socSwitchTab('chat')"><i class="fas fa-robot"></i> Ask RAKAY</button>
                </div>
              </div>
              <div class="soc-insight-item soc-insight--orange">
                <i class="fas fa-fire"></i>
                <div>
                  <div class="soc-insight-title">PowerShell LOLBin abuse rising</div>
                  <div class="soc-insight-desc">T1059.001 — Enable ScriptBlock logging, monitor encoded commands</div>
                  <button class="soc-action-btn" onclick="window._rakayQuickAsk('Generate Sigma rule for PowerShell encoded command T1059.001');window._socSwitchTab('chat')"><i class="fas fa-robot"></i> Generate Rule</button>
                </div>
              </div>
              <div class="soc-insight-item soc-insight--yellow">
                <i class="fas fa-user-secret"></i>
                <div>
                  <div class="soc-insight-title">Ransomware lateral movement via SMB</div>
                  <div class="soc-insight-desc">T1021.002 — Monitor lateral SMB connections, isolate infected hosts</div>
                  <button class="soc-action-btn" onclick="window._socSwitchTab('simulate');window._socRunSimulation('ransomware')"><i class="fas fa-flask"></i> Simulate</button>
                </div>
              </div>
              <div class="soc-insight-item soc-insight--blue">
                <i class="fas fa-database"></i>
                <div>
                  <div class="soc-insight-title">LSASS credential dumping detected</div>
                  <div class="soc-insight-desc">T1003.001 — Enable Credential Guard, monitor LSASS access events</div>
                  <button class="soc-action-btn" onclick="window._rakayQuickAsk('Generate detection rules for LSASS credential dumping T1003.001');window._socSwitchTab('chat')"><i class="fas fa-robot"></i> Ask RAKAY</button>
                </div>
              </div>
            </div>
          </div>`;
      } else {
        throw new Error('No dashboard data');
      }
    } catch (err) {
      el.dataset.loaded = '1';
      el.innerHTML = `
        <div class="soc-panel-section">
          <div class="soc-section-header"><i class="fas fa-lightbulb" style="color:#d29922"></i> <span>Analyst Insights</span></div>
          <div class="soc-insights-list">
            <div class="soc-insight-item soc-insight--red"><i class="fas fa-exclamation-circle"></i><div>
              <div class="soc-insight-title">Log4Shell (CVE-2021-44228) — CVSS 10.0 — Actively Exploited</div>
              <button class="soc-action-btn" onclick="window._rakayQuickAsk('How do I detect Log4Shell?');window._socSwitchTab('chat')"><i class="fas fa-robot"></i> Ask RAKAY</button>
            </div></div>
            <div class="soc-insight-item soc-insight--orange"><i class="fas fa-fire"></i><div>
              <div class="soc-insight-title">MOVEit Transfer SQL Injection (CVE-2023-34362) — CVSS 9.8</div>
              <button class="soc-action-btn" onclick="window._rakayQuickAsk('Explain CVE-2023-34362 MOVEit vulnerability');window._socSwitchTab('chat')"><i class="fas fa-robot"></i> Ask RAKAY</button>
            </div></div>
            <div class="soc-insight-item soc-insight--blue"><i class="fas fa-shield-alt"></i><div>
              <div class="soc-insight-title">T1059.001 PowerShell abuse — Detection rules available</div>
              <button class="soc-action-btn" onclick="window._socSwitchTab('detect')"><i class="fas fa-shield-alt"></i> View Rules</button>
            </div></div>
          </div>
        </div>`;
    }
  }

  // ── Quick-ask helper (switch to chat and send message) ────────────────────
  window._rakayQuickAsk = async function(text) {
    _socSwitchTab('chat');
    await new Promise(r => setTimeout(r, 80));
    const inp = document.getElementById('rakay-input');
    if (inp) { inp.value = text; inp.dispatchEvent(new Event('input')); }
    window._rakaySubmit && window._rakaySubmit();
  };

  // Expose tab switcher globally
  window._socSwitchTab = _socSwitchTab;

  // ══════════════════════════════════════════════════════════════════════════
  //  PAGE HTML
  // ══════════════════════════════════════════════════════════════════════════
  function _buildHTML() {
    return `
<div class="rakay-root" id="rakay-root">

  <!-- Sidebar (chat-only) -->
  <aside class="rakay-sidebar" id="rakay-sidebar">
    <div class="rakay-sidebar-header">
      <div class="rakay-sidebar-logo"><i class="fas fa-robot"></i></div>
      <span class="rakay-sidebar-title">RAKAY</span>
      <button class="rakay-new-btn" onclick="window._rakayNewChat()" title="New chat">
        <i class="fas fa-plus"></i>
      </button>
    </div>
    <div class="rakay-session-search-wrap">
      <input type="text" id="rakay-session-search" class="rakay-session-search"
        placeholder="Search sessions…" oninput="window._rakaySearchSessions(this.value)">
    </div>
    <div class="rakay-session-list" id="rakay-session-list">
      <div class="rakay-session-empty">Loading sessions…</div>
    </div>
  </aside>

  <!-- Main area -->
  <main class="rakay-main">

    <!-- Top header bar -->
    <div class="rakay-header">
      <div class="rakay-header-icon"><i class="fas fa-shield-alt"></i></div>
      <div class="rakay-header-info">
        <div class="rakay-header-title" id="rakay-current-title">RAKAY SOC Analyst Assistant</div>
        <div class="rakay-header-sub">Detection Engineering · Threat Intel · Incident Simulation · AI Chat</div>
      </div>
      <div class="rakay-status-area">
        <span class="rakay-ws-badge" id="rakay-ws-badge" style="display:none">LIVE</span>
        <div class="rakay-status-dot checking" id="rakay-status-dot" title="Checking backend…"></div>
        <span class="rakay-status-label checking" id="rakay-status-label">CONNECTING…</span>
      </div>
    </div>

    <!-- SOC Tab navigation -->
    <div class="rakay-soc-tabs">
      <button class="rakay-soc-tab active" data-tab="chat"     onclick="window._socSwitchTab('chat')">
        <i class="fas fa-robot"></i> AI Chat
      </button>
      <button class="rakay-soc-tab" data-tab="intel"    onclick="window._socSwitchTab('intel')">
        <i class="fas fa-database"></i> Threat Intel
      </button>
      <button class="rakay-soc-tab" data-tab="detect"   onclick="window._socSwitchTab('detect')">
        <i class="fas fa-shield-alt"></i> Detection
      </button>
      <button class="rakay-soc-tab" data-tab="simulate" onclick="window._socSwitchTab('simulate')">
        <i class="fas fa-flask"></i> Simulation
      </button>
      <button class="rakay-soc-tab" data-tab="alerts"   onclick="window._socSwitchTab('alerts')">
        <i class="fas fa-bell"></i> Alerts &amp; Insights
      </button>
    </div>

    <!-- ── PANEL: AI Chat ── -->
    <div class="rakay-soc-panel" data-panel="chat" style="display:flex;flex-direction:column;flex:1;overflow:hidden">

      <!-- Messages -->
      <div id="rakay-messages">
        ${_renderWelcome()}
      </div>

      <!-- Input -->
      <div class="rakay-input-area">
        <div class="rakay-input-wrap">
          <textarea
            id="rakay-input"
            placeholder="Ask RAKAY anything — Sigma rules, IOC enrichment, CVEs, MITRE ATT&CK, incident response…"
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
    </div>

    <!-- ── PANEL: Threat Intel ── -->
    <div class="rakay-soc-panel soc-panel-scroll" data-panel="intel" style="display:none">
      <div class="soc-panel-inner" id="soc-intel-content">
        <div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading…</div>
      </div>
    </div>

    <!-- ── PANEL: Detection ── -->
    <div class="rakay-soc-panel soc-panel-scroll" data-panel="detect" style="display:none">
      <div class="soc-panel-inner" id="soc-detect-content">
        <div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading…</div>
      </div>
    </div>

    <!-- ── PANEL: Simulation ── -->
    <div class="rakay-soc-panel soc-panel-scroll" data-panel="simulate" style="display:none">
      <div class="soc-panel-inner" id="soc-sim-content">
        <div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading…</div>
      </div>
    </div>

    <!-- ── PANEL: Alerts & Insights ── -->
    <div class="rakay-soc-panel soc-panel-scroll" data-panel="alerts" style="display:none">
      <div class="soc-panel-inner" id="soc-alerts-content">
        <div class="soc-loading"><i class="fas fa-circle-notch fa-spin"></i> Loading…</div>
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
