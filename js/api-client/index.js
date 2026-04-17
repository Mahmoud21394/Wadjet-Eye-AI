/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Typed Frontend API Client (Phase 2/3)
 *  js/api-client/index.js
 *
 *  Centralised HTTP client for all backend API calls.
 *  Features:
 *   - Single base URL resolution (env → localStorage override)
 *   - Bearer token injected from authStore (never from localStorage directly)
 *   - Normalized response envelopes (success/data/error)
 *   - Automatic 401 → token-refresh → retry (one attempt)
 *   - AbortController support via { signal }
 *   - Request IDs forwarded in X-Request-ID header
 *   - Zero direct API key usage in browser (all calls to backend)
 *
 *  ⚠️  Security: This client NEVER stores or sends AI provider API keys.
 *      All AI calls route through /api/RAKAY/* on the backend.
 * ══════════════════════════════════════════════════════════════════
 */
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ApiClient = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ── Base URL resolution ─────────────────────────────────────────
  // Priority: window.THREATPILOT_API_URL → localStorage override → default
  function _baseUrl() {
    return (
      (typeof window !== 'undefined' && window.THREATPILOT_API_URL) ||
      (typeof localStorage !== 'undefined' && localStorage.getItem('wadjet_api_url')) ||
      'https://wadjet-eye-ai.onrender.com'
    ).replace(/\/+$/, '');
  }

  // ── Token store interface ───────────────────────────────────────
  // Reads from the authStore if available, else from sessionStorage/localStorage.
  // NEVER reads raw API provider keys.
  function _getToken() {
    if (typeof window !== 'undefined') {
      if (window.AuthStore?.getAccessToken) return window.AuthStore.getAccessToken();
      return sessionStorage.getItem('wadjet_access_token') ||
             localStorage.getItem('wadjet_token');
    }
    return null;
  }

  function _getRefreshToken() {
    if (typeof window !== 'undefined') {
      if (window.AuthStore?.getRefreshToken) return window.AuthStore.getRefreshToken();
      return sessionStorage.getItem('wadjet_refresh_token') ||
             localStorage.getItem('wadjet_refresh_token');
    }
    return null;
  }

  function _setToken(accessToken, refreshToken) {
    if (typeof window === 'undefined') return;
    if (window.AuthStore?.setTokens) {
      window.AuthStore.setTokens(accessToken, refreshToken);
      return;
    }
    if (accessToken)  sessionStorage.setItem('wadjet_access_token', accessToken);
    if (refreshToken) sessionStorage.setItem('wadjet_refresh_token', refreshToken);
  }

  // ── Unique request ID generator ─────────────────────────────────
  function _reqId() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  // ── Core fetch wrapper ──────────────────────────────────────────
  let _refreshing = null; // singleton refresh promise to prevent thundering herd

  async function _fetch(path, options = {}, _retryCount = 0) {
    const { body, method = 'GET', signal, headers: extraHeaders = {}, skipAuth = false } = options;
    const token   = _getToken();
    const reqId   = _reqId();
    const url     = `${_baseUrl()}${path}`;

    const headers = {
      'Content-Type':    'application/json',
      'Accept':          'application/json',
      'X-Request-ID':    reqId,
      ...extraHeaders,
    };

    if (token && !skipAuth) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const fetchOptions = { method, headers, signal };
    if (body !== undefined) {
      fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    let res;
    try {
      res = await fetch(url, fetchOptions);
    } catch (networkErr) {
      // Network error — rethrow with context
      const err = new Error(`Network error reaching ${url}: ${networkErr.message}`);
      err.isNetworkError = true;
      err.url = url;
      throw err;
    }

    // 401 → try refresh once
    if (res.status === 401 && _retryCount === 0 && !skipAuth) {
      try {
        await _doRefresh();
        return _fetch(path, options, 1);
      } catch {
        // Refresh failed — clear tokens and let caller handle
        _setToken(null, null);
        const err = new Error('Session expired. Please log in again.');
        err.status = 401;
        err.code   = 'SESSION_EXPIRED';
        throw err;
      }
    }

    // Parse response
    let data;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try { data = await res.json(); } catch { data = null; }
    } else {
      data = await res.text();
    }

    if (!res.ok) {
      const err  = new Error(data?.error || data?.message || `HTTP ${res.status}`);
      err.status = res.status;
      err.code   = data?.code;
      err.data   = data;
      err.reqId  = reqId;
      throw err;
    }

    return data;
  }

  async function _doRefresh() {
    if (_refreshing) return _refreshing;

    _refreshing = (async () => {
      const refreshToken = _getRefreshToken();
      if (!refreshToken) throw new Error('No refresh token');

      const res = await fetch(`${_baseUrl()}/api/auth/refresh`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!res.ok) throw new Error('Refresh failed');

      const data = await res.json();
      _setToken(data.accessToken || data.access_token, data.refreshToken || data.refresh_token);
    })();

    try {
      await _refreshing;
    } finally {
      _refreshing = null;
    }
  }

  // ── HTTP method helpers ──────────────────────────────────────────
  const api = {
    get:    (path, opts = {}) => _fetch(path, { ...opts, method: 'GET' }),
    post:   (path, body, opts = {}) => _fetch(path, { ...opts, method: 'POST', body }),
    put:    (path, body, opts = {}) => _fetch(path, { ...opts, method: 'PUT', body }),
    patch:  (path, body, opts = {}) => _fetch(path, { ...opts, method: 'PATCH', body }),
    delete: (path, opts = {}) => _fetch(path, { ...opts, method: 'DELETE' }),

    // ── Auth endpoints ─────────────────────────────────────────────
    auth: {
      login:   (email, password) => api.post('/api/auth/login', { email, password }, { skipAuth: true }),
      logout:  ()                => api.post('/api/auth/logout', {}),
      refresh: ()                => _doRefresh(),
      me:      ()                => api.get('/api/auth/me'),
    },

    // ── RAKAY AI endpoints ─────────────────────────────────────────
    ai: {
      chat: (payload) => api.post('/api/RAKAY/chat', payload),
      diag: ()        => api.get('/api/RAKAY/diag', { skipAuth: true }),
      health: ()      => api.get('/api/RAKAY/health', { skipAuth: true }),

      /**
       * stream(payload, { onChunk, onDone, onError, signal })
       * Opens an SSE connection to /api/RAKAY/chat/stream and calls
       * onChunk for each streamed token.
       */
      stream(payload, { onChunk, onDone, onError, signal } = {}) {
        const token = _getToken();
        const reqId = _reqId();
        const url   = `${_baseUrl()}/api/RAKAY/chat/stream`;

        const headers = {
          'Content-Type': 'application/json',
          'Accept':       'text/event-stream',
          'X-Request-ID': reqId,
        };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const ctrl = signal ? undefined : new AbortController();
        const sig  = signal || ctrl?.signal;

        fetch(url, {
          method: 'POST',
          headers,
          body:   JSON.stringify(payload),
          signal: sig,
        }).then(async (res) => {
          if (!res.ok) {
            const text = await res.text();
            const err  = new Error(`Stream error HTTP ${res.status}: ${text}`);
            err.status = res.status;
            if (onError) onError(err);
            return;
          }

          const reader = res.body.getReader();
          const dec    = new TextDecoder();
          let   buf    = '';

          while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();

            for (const line of lines) {
              if (!line.trim()) continue;
              if (line.startsWith('data: ')) {
                const raw = line.slice(6).trim();
                if (raw === '[DONE]') { if (onDone) onDone(); continue; }
                try {
                  const evt = JSON.parse(raw);
                  if (onChunk) onChunk(evt);
                } catch { /* non-JSON data line */ }
              }
            }
          }
          if (onDone) onDone();
        }).catch((err) => {
          if (err.name === 'AbortError') return; // intentional cancel
          if (onError) onError(err);
        });

        return ctrl; // caller can call ctrl.abort() to cancel
      },
    },

    // ── IOC endpoints ──────────────────────────────────────────────
    iocs: {
      list:   (params = {}) => {
        const qs = new URLSearchParams(params).toString();
        return api.get(`/api/iocs${qs ? '?' + qs : ''}`);
      },
      get:    (id)    => api.get(`/api/iocs/${id}`),
      create: (data)  => api.post('/api/iocs', data),
      update: (id, d) => api.patch(`/api/iocs/${id}`, d),
      delete: (id)    => api.delete(`/api/iocs/${id}`),
    },

    // ── Alert endpoints ────────────────────────────────────────────
    alerts: {
      list:   (params = {}) => {
        const qs = new URLSearchParams(params).toString();
        return api.get(`/api/alerts${qs ? '?' + qs : ''}`);
      },
      get:    (id)    => api.get(`/api/alerts/${id}`),
      update: (id, d) => api.patch(`/api/alerts/${id}`, d),
    },

    // ── Dashboard ──────────────────────────────────────────────────
    dashboard: {
      summary: () => api.get('/api/dashboard/summary'),
      metrics: () => api.get('/api/dashboard/metrics'),
    },

    // ── Health ──────────────────────────────────────────────────────
    health: () => api.get('/health', { skipAuth: true }),

    // ── Internal helpers ────────────────────────────────────────────
    _baseUrl,
    _setToken,
    _getToken,
  };

  return api;
}));
