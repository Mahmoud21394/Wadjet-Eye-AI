/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — WebSocket Reconnect Client  v1.0
 *  js/ws-reconnect.js
 *
 *  PROBLEM SOLVED
 *  ─────────────────────────────────────────────────────────────────────
 *  Old behaviour:
 *   • Token expires → server closes WS with code 4401 → client gets error event
 *   • Client has no automatic reconnect logic
 *   • User must reload the page to restore the live threat stream
 *
 *  New behaviour (this module):
 *   1. Receives 'auth:expiring' event 2 minutes before expiry
 *      → silently calls /api/auth/refresh to get new token
 *      → sends 'auth' message to server with new token (no reconnect needed)
 *
 *   2. On close with code 4401 (token expired):
 *      → waits for token refresh via UnifiedTokenStore
 *      → reconnects with fresh token using exponential backoff
 *      → max 8 attempts before showing "session expired" UI
 *
 *   3. On unexpected close (network drop, server restart):
 *      → reconnects immediately with existing token
 *      → exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s (max)
 *
 *  REQUIRES:
 *   • js/auth-interceptor.js (UnifiedTokenStore, silentRefresh)
 *   • Loaded AFTER auth-interceptor.js in index.html
 *
 *  USAGE:
 *   const wsClient = new WsReconnectClient({
 *     url: 'wss://your-backend.com/ws/detections',
 *     onMessage:    (data) => handleEvent(data),
 *     onConnect:    ()     => console.log('WS connected'),
 *     onDisconnect: (code) => console.log('WS disconnected', code),
 *     onAuthExpired:()     => showReloginBanner(),
 *   });
 *   wsClient.connect();
 *
 *  To stop:  wsClient.disconnect();
 *  To start detection stream:  wsClient.send({ type: 'detections:start' });
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

  // ──────────────────────────────────────────────────────────────────────────
  //  Constants
  // ──────────────────────────────────────────────────────────────────────────

  const BACKOFF_BASE_MS   = 1000;    // 1 second
  const BACKOFF_MAX_MS    = 60000;   // 60 seconds
  const BACKOFF_FACTOR    = 2;
  const MAX_AUTH_RETRIES  = 8;       // max reconnect attempts on 4401
  const MAX_NET_RETRIES   = 20;      // max reconnect attempts on network error
  const PING_INTERVAL_MS  = 25000;   // send ping every 25s to keep connection alive
  const REFRESH_TIMEOUT_MS= 10000;   // wait up to 10s for token refresh

  // ──────────────────────────────────────────────────────────────────────────
  //  Token helpers — bridge to UnifiedTokenStore from auth-interceptor.js
  // ──────────────────────────────────────────────────────────────────────────

  function _getToken() {
    if (global.UnifiedTokenStore) return global.UnifiedTokenStore.getToken();
    // Fallback: direct localStorage read
    return (
      localStorage.getItem('wadjet_access_token')  ||
      localStorage.getItem('we_access_token')       ||
      localStorage.getItem('tp_access_token')       ||
      null
    );
  }

  function _isTokenExpired() {
    if (global.UnifiedTokenStore) return global.UnifiedTokenStore.isExpired();
    const expStr = localStorage.getItem('wadjet_token_expires_at') ||
                   localStorage.getItem('we_token_expires');
    if (!expStr) return false;
    const exp = new Date(isNaN(Number(expStr)) ? expStr : Number(expStr));
    return exp < new Date();
  }

  /**
   * _refreshToken — attempt a silent token refresh.
   * Uses auth-interceptor.js silentRefresh() if available, otherwise
   * calls /api/auth/refresh-from-cookie directly.
   *
   * @returns {Promise<string|null>}  New access token or null on failure
   */
  async function _refreshToken() {
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => resolve(null), REFRESH_TOKEN_TIMEOUT_MS);

      // Method 1: auth-interceptor silentRefresh()
      if (global.silentRefresh) {
        global.silentRefresh()
          .then(() => {
            clearTimeout(timeoutId);
            resolve(_getToken());
          })
          .catch(() => {
            clearTimeout(timeoutId);
            resolve(null);
          });
        return;
      }

      // Method 2: direct POST to /api/auth/refresh-from-cookie
      const refreshToken = localStorage.getItem('wadjet_refresh_token') ||
                           localStorage.getItem('we_refresh_token');
      if (!refreshToken) {
        clearTimeout(timeoutId);
        resolve(null);
        return;
      }

      fetch('/api/auth/refresh', {
        method:      'POST',
        credentials: 'include',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ refresh_token: refreshToken }),
      })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          clearTimeout(timeoutId);
          if (data?.access_token) {
            // Update storage
            localStorage.setItem('wadjet_access_token', data.access_token);
            if (data.refresh_token) {
              localStorage.setItem('wadjet_refresh_token', data.refresh_token);
            }
            if (data.expires_at) {
              localStorage.setItem('wadjet_token_expires_at', data.expires_at);
            }
            resolve(data.access_token);
          } else {
            resolve(null);
          }
        })
        .catch(() => {
          clearTimeout(timeoutId);
          resolve(null);
        });
    });
  }

  const REFRESH_TOKEN_TIMEOUT_MS = REFRESH_TIMEOUT_MS;

  // ──────────────────────────────────────────────────────────────────────────
  //  WsReconnectClient
  // ──────────────────────────────────────────────────────────────────────────

  class WsReconnectClient {
    /**
     * @param {object}   opts
     * @param {string}   opts.url           WebSocket URL (wss://...)
     * @param {Function} [opts.onMessage]   Called with parsed message data
     * @param {Function} [opts.onConnect]   Called on successful connection
     * @param {Function} [opts.onDisconnect] Called on disconnect with (code, reason)
     * @param {Function} [opts.onAuthExpired] Called when re-auth is not possible
     * @param {Function} [opts.onError]     Called on error events
     * @param {boolean}  [opts.autoStart]   Send detections:start on connect (default: true)
     */
    constructor(opts = {}) {
      this._url            = opts.url || this._defaultUrl();
      this._onMessage      = opts.onMessage      || (() => {});
      this._onConnect      = opts.onConnect      || (() => {});
      this._onDisconnect   = opts.onDisconnect   || (() => {});
      this._onAuthExpired  = opts.onAuthExpired  || (() => {});
      this._onError        = opts.onError        || (() => {});
      this._autoStart      = opts.autoStart !== false;

      this._ws             = null;
      this._pingTimer      = null;
      this._reconnectTimer = null;
      this._authRetries    = 0;
      this._netRetries     = 0;
      this._destroyed      = false;
      this._connected      = false;

      this._messageQueue   = [];  // messages sent before connection established
    }

    _defaultUrl() {
      // Auto-derive WS URL from current page location
      const proto  = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host   = location.host;
      // Try backend URL from environment (set in window.NEXUS_CONFIG or similar)
      const apiBase = (global.NEXUS_CONFIG?.apiBase || '').replace(/^https?:/, '');
      if (apiBase) return `${proto}${apiBase}/ws/detections`;
      return `${proto}//${host}/ws/detections`;
    }

    /**
     * connect — establish the WebSocket connection.
     * Gets the current access token and appends as query param.
     */
    async connect() {
      if (this._destroyed) return;

      // Get fresh token (refresh if needed)
      let token = _getToken();
      if (!token || _isTokenExpired()) {
        console.info('[WsReconnect] Token missing/expired — refreshing before connect...');
        token = await _refreshToken();
      }

      if (!token) {
        console.warn('[WsReconnect] No token available — cannot connect');
        this._onAuthExpired();
        return;
      }

      try {
        const wsUrl = `${this._url}?token=${encodeURIComponent(token)}`;
        this._ws    = new WebSocket(wsUrl);

        this._ws.onopen    = ()      => this._handleOpen();
        this._ws.onmessage = (event) => this._handleMessage(event);
        this._ws.onclose   = (event) => this._handleClose(event.code, event.reason);
        this._ws.onerror   = (err)   => this._handleError(err);

        console.info('[WsReconnect] Connecting to', this._url);
      } catch (err) {
        console.error('[WsReconnect] Failed to create WebSocket:', err.message);
        this._scheduleReconnect(false);
      }
    }

    /**
     * disconnect — cleanly close the connection and stop all reconnect logic.
     */
    disconnect() {
      this._destroyed = true;
      this._clearTimers();
      if (this._ws) {
        try { this._ws.close(1000, 'Client disconnect'); } catch {}
        this._ws = null;
      }
    }

    /**
     * send — send a JSON message to the server.
     * Queues messages if connection not yet established.
     *
     * @param {object} data
     */
    send(data) {
      if (this._ws && this._ws.readyState === WebSocket.OPEN) {
        try {
          this._ws.send(JSON.stringify(data));
        } catch (err) {
          console.warn('[WsReconnect] send failed:', err.message);
        }
      } else {
        // Queue for when connection is established
        this._messageQueue.push(data);
      }
    }

    /** @returns {boolean} */
    get isConnected() { return this._connected; }

    // ── Private: Event handlers ─────────────────────────────────────────────

    _handleOpen() {
      console.info('[WsReconnect] Connected');
      this._connected  = true;
      this._authRetries = 0;
      this._netRetries  = 0;

      // Flush queued messages
      while (this._messageQueue.length > 0) {
        this.send(this._messageQueue.shift());
      }

      // Start detection stream automatically
      if (this._autoStart) {
        this.send({ type: 'detections:start' });
      }

      // Start keepalive pings
      this._startPing();

      this._onConnect();
    }

    _handleMessage(event) {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }

      switch (data.type) {
        case 'auth:expiring': {
          // Server warns token expires soon — proactively refresh and resend
          console.info(`[WsReconnect] Token expiring in ${data.expiresIn}s — refreshing...`);
          this._proactiveRefresh();
          break;
        }

        case 'auth:expired': {
          // Server says token has expired — refresh and let server reconnect handling take over
          console.warn('[WsReconnect] Server: token expired — refreshing...');
          this._proactiveRefresh();
          break;
        }

        case 'auth:refreshed': {
          console.info(`[WsReconnect] Token refresh accepted by server userId=${data.userId}`);
          break;
        }

        case 'auth:refresh_failed': {
          console.warn('[WsReconnect] Token refresh rejected by server:', data.reason);
          // Will be handled by close event
          break;
        }

        case 'auth_failed': {
          console.warn('[WsReconnect] auth_failed — will reconnect with fresh token');
          // The close event will handle reconnect
          break;
        }

        default:
          this._onMessage(data);
      }
    }

    _handleClose(code, reason) {
      this._connected  = false;
      this._clearTimers();
      console.info(`[WsReconnect] Disconnected code=${code} reason="${reason}"`);
      this._onDisconnect(code, reason);

      if (this._destroyed) return;

      const isAuthFailure = code === 4401 || code === 4403;

      if (isAuthFailure) {
        this._authRetries++;
        if (this._authRetries > MAX_AUTH_RETRIES) {
          console.error('[WsReconnect] Max auth retries exceeded — session expired');
          this._onAuthExpired();
          return;
        }
        // Refresh token first, then reconnect
        this._scheduleReconnect(true);
      } else if (code === 1000 || code === 1001) {
        // Normal close — do not reconnect
        console.info('[WsReconnect] Normal close — not reconnecting');
      } else {
        // Network error or server restart — reconnect with existing token
        this._netRetries++;
        if (this._netRetries > MAX_NET_RETRIES) {
          console.error('[WsReconnect] Max network retries exceeded');
          return;
        }
        this._scheduleReconnect(false);
      }
    }

    _handleError(err) {
      console.warn('[WsReconnect] WebSocket error:', err.message || err);
      this._onError(err);
    }

    // ── Private: Reconnect logic ────────────────────────────────────────────

    _scheduleReconnect(needsTokenRefresh) {
      const retries = needsTokenRefresh ? this._authRetries : this._netRetries;
      const delay   = Math.min(
        BACKOFF_BASE_MS * Math.pow(BACKOFF_FACTOR, retries - 1),
        BACKOFF_MAX_MS
      );
      // Add jitter ±20%
      const jitter  = delay * 0.2 * (Math.random() - 0.5);
      const wait    = Math.floor(delay + jitter);

      console.info(
        `[WsReconnect] Reconnecting in ${wait}ms ` +
        `(attempt ${retries} ${needsTokenRefresh ? 'auth-retry' : 'net-retry'})`
      );

      this._reconnectTimer = setTimeout(async () => {
        if (this._destroyed) return;

        if (needsTokenRefresh) {
          const newToken = await _refreshToken();
          if (!newToken) {
            console.warn('[WsReconnect] Token refresh failed — will retry');
          }
        }

        await this.connect();
      }, wait);
    }

    /**
     * _proactiveRefresh — refresh token and notify server without reconnecting.
     * Called when server sends 'auth:expiring' or 'auth:expired'.
     */
    async _proactiveRefresh() {
      const newToken = await _refreshToken();
      if (!newToken) {
        console.warn('[WsReconnect] Proactive refresh failed');
        return;
      }

      // Send new token to server — server validates and updates session
      this.send({ type: 'auth', token: newToken });
      console.info('[WsReconnect] Proactive token refresh sent to server');
    }

    // ── Private: Keepalive ping ─────────────────────────────────────────────

    _startPing() {
      this._stopPing();
      this._pingTimer = setInterval(() => {
        if (this._ws && this._ws.readyState === WebSocket.OPEN) {
          this.send({ type: 'ping' });
        }
      }, PING_INTERVAL_MS);
    }

    _stopPing() {
      clearInterval(this._pingTimer);
      this._pingTimer = null;
    }

    _clearTimers() {
      this._stopPing();
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Expose globally
  // ──────────────────────────────────────────────────────────────────────────
  global.WsReconnectClient = WsReconnectClient;

  console.info('[ws-reconnect.js] WsReconnectClient v1.0 loaded');

})(typeof window !== 'undefined' ? window : global);
