/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Frontend API Client v3.0
 *  Enterprise Edition — Real Auth, No Mock Data
 *
 *  Features:
 *   - Real JWT auth with short-lived access tokens (15 min)
 *   - Automatic silent refresh via /api/auth/refresh
 *   - Axios-style interceptor pattern with retry on 401
 *   - Session persistence across page refresh
 *   - Full API namespace (alerts, cases, iocs, intel, cti, vulns, etc.)
 *   - WebSocket client with auto-reconnect
 * ══════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ════════════════════════════════════════════
   CONFIGURATION
═════════════════════════════════════════════ */
const CONFIG = {
  get BACKEND_URL() {
    return (typeof window !== 'undefined' && window.THREATPILOT_API_URL)
      ? window.THREATPILOT_API_URL.replace(/\/$/, '')
      : 'https://wadjet-eye-ai.onrender.com';
  },
  get WS_URL() {
    return (typeof window !== 'undefined' && window.THREATPILOT_WS_URL)
      ? window.THREATPILOT_WS_URL
      : 'https://wadjet-eye-ai.onrender.com';
  },
};

/* ════════════════════════════════════════════
   TOKEN STORE — sessionStorage + localStorage mirror
   Access token → sessionStorage (cleared on tab close)
   Refresh token → localStorage (persists across refresh)
═════════════════════════════════════════════ */
const TokenStore = {
  _ACCESS_KEY:  'we_access_token',
  _REFRESH_KEY: 'we_refresh_token',
  _USER_KEY:    'we_user',
  _EXP_KEY:     'we_token_expires',

  /** Get access token */
  get()           { return sessionStorage.getItem(this._ACCESS_KEY) || localStorage.getItem(this._ACCESS_KEY); },
  /** Get refresh token (persisted in localStorage) */
  getRefresh()    { return localStorage.getItem(this._REFRESH_KEY); },
  /** Get token expiry timestamp (ms) */
  getExpiry()     { const e = sessionStorage.getItem(this._EXP_KEY); return e ? parseInt(e) : 0; },

  /** Store tokens after login/refresh */
  set(accessToken, refreshToken, expiresAt) {
    if (accessToken) {
      sessionStorage.setItem(this._ACCESS_KEY, accessToken);
      localStorage.setItem(this._ACCESS_KEY, accessToken);
    }
    if (refreshToken) {
      localStorage.setItem(this._REFRESH_KEY, refreshToken);
    }
    if (expiresAt) {
      const ms = typeof expiresAt === 'string'
        ? new Date(expiresAt).getTime()
        : Date.now() + (expiresAt * 1000);
      sessionStorage.setItem(this._EXP_KEY, String(ms));
    }
  },

  /** Clear all tokens (logout) */
  clear() {
    [this._ACCESS_KEY, this._REFRESH_KEY, this._USER_KEY, this._EXP_KEY].forEach(k => {
      sessionStorage.removeItem(k);
      localStorage.removeItem(k);
    });
  },

  /** Get cached user profile */
  getUser() {
    try {
      const raw = sessionStorage.getItem(this._USER_KEY) || localStorage.getItem(this._USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  /** Cache user profile */
  setUser(u) {
    const json = JSON.stringify(u);
    sessionStorage.setItem(this._USER_KEY, json);
    localStorage.setItem(this._USER_KEY, json);
  },

  /** True if access token exists and is not expired (with 30s buffer) */
  isValid() {
    const token = this.get();
    if (!token) return false;
    const exp = this.getExpiry();
    if (!exp) return true; // No expiry info → assume valid
    return Date.now() < (exp - 30000); // 30s buffer
  },

  /** True if we have a refresh token to attempt renewal */
  canRefresh() {
    return !!this.getRefresh();
  },
};

/* ════════════════════════════════════════════
   REFRESH STATE — Prevent concurrent refresh storms
═════════════════════════════════════════════ */
let _refreshing     = false;
let _refreshPromise = null;

async function refreshAccessToken() {
  if (_refreshing) return _refreshPromise;

  _refreshing     = true;
  _refreshPromise = _doRefresh();

  try {
    return await _refreshPromise;
  } finally {
    _refreshing     = false;
    _refreshPromise = null;
  }
}

async function _doRefresh() {
  const rt = TokenStore.getRefresh();
  if (!rt) return false;

  try {
    const res = await fetch(`${CONFIG.BACKEND_URL}/api/auth/refresh`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: rt }),
    });

    if (!res.ok) {
      console.warn('[Auth] Refresh failed:', res.status);
      return false;
    }

    const body = await res.json();
    if (body.token || body.access_token) {
      TokenStore.set(
        body.token || body.access_token,
        body.refreshToken || body.refresh_token,
        body.expiresAt || body.expiresIn,
      );
      // Update CURRENT_USER if user info returned
      if (body.user && typeof window !== 'undefined') {
        TokenStore.setUser(body.user);
        if (window.CURRENT_USER) {
          Object.assign(window.CURRENT_USER, body.user);
        }
      }
      console.info('[Auth] Token refreshed successfully');
      return true;
    }

    return false;
  } catch (err) {
    console.warn('[Auth] Refresh error:', err.message);
    return false;
  }
}

/* ════════════════════════════════════════════
   BASE HTTP CLIENT — with auto-refresh on 401
   This is the single source of truth for ALL API calls.
═════════════════════════════════════════════ */
async function apiRequest(method, path, body = null, opts = {}) {
  // ── 1. Pre-flight token refresh if expiring soon ──────────
  if (!TokenStore.isValid() && TokenStore.canRefresh()) {
    console.info('[Auth] Token expired or expiring — attempting silent refresh…');
    await refreshAccessToken();
  }

  const token = TokenStore.get();
  const url   = `${CONFIG.BACKEND_URL}/api${path}`;

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(opts.headers || {}),
  };

  const fetchOpts = {
    method,
    headers,
    credentials: 'include',  // Send HTTP-only cookies too
    ...(body ? { body: JSON.stringify(body) } : {}),
  };

  let response;
  try {
    response = await fetch(url, fetchOpts);
  } catch (networkErr) {
    throw new Error(`Network error: Cannot reach backend at ${CONFIG.BACKEND_URL}. ${networkErr.message}`);
  }

  // ── 2. Handle 401 → auto-refresh → one retry ─────────────
  if (response.status === 401) {
    if (TokenStore.canRefresh()) {
      console.info('[Auth] 401 received — attempting token refresh…');
      const refreshed = await refreshAccessToken();

      if (refreshed) {
        // Retry original request with new token
        headers['Authorization'] = `Bearer ${TokenStore.get()}`;
        try {
          response = await fetch(url, { ...fetchOpts, headers });
        } catch (retryErr) {
          throw new Error(`Network error on retry: ${retryErr.message}`);
        }
        // If still 401 after refresh, fall through to error handling
      } else {
        // Refresh failed — session invalid
        TokenStore.clear();
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'));
        }
        throw new Error('Session expired. Please log in again.');
      }
    } else {
      // No refresh token — session invalid
      TokenStore.clear();
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('auth:expired'));
      }
      throw new Error('Authentication required. Please log in.');
    }
  }

  // ── 3. Handle 204 No Content ─────────────────────────────
  if (response.status === 204) return null;

  // ── 4. Parse JSON ─────────────────────────────────────────
  let data;
  try {
    data = await response.json();
  } catch {
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    return null;
  }

  if (!response.ok) {
    const errMsg = data?.error || data?.message || `API Error ${response.status}`;
    throw new Error(errMsg);
  }

  return data;
}

/* ════════════════════════════════════════════
   CONVENIENCE WRAPPERS
═════════════════════════════════════════════ */
function buildUrl(path, params) {
  if (!params) return path;
  const qs = new URLSearchParams(
    Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    )
  ).toString();
  return qs ? `${path}?${qs}` : path;
}

const GET    = (path, params)  => apiRequest('GET',    buildUrl(path, params));
const POST   = (path, body)    => apiRequest('POST',   path, body);
const PATCH  = (path, body)    => apiRequest('PATCH',  path, body);
const PUT    = (path, body)    => apiRequest('PUT',    path, body);
const DELETE = (path)          => apiRequest('DELETE', path);

/* ════════════════════════════════════════════
   SESSION RESTORE — Called on page load
   Attempts silent refresh if refresh token exists
   but access token is missing/expired.
═════════════════════════════════════════════ */
async function restoreSession() {
  const user = TokenStore.getUser();

  if (TokenStore.isValid() && user) {
    console.info('[Auth] Session valid — restoring as', user.email);
    return user;
  }

  if (TokenStore.canRefresh()) {
    console.info('[Auth] Access token expired — attempting silent refresh…');
    const refreshed = await refreshAccessToken();

    if (refreshed) {
      const updatedUser = TokenStore.getUser();
      console.info('[Auth] Session restored for', updatedUser?.email);
      return updatedUser;
    }
  }

  console.info('[Auth] No valid session found');
  return null;
}

/* ════════════════════════════════════════════
   API NAMESPACES
═════════════════════════════════════════════ */
const API = {

  /* ── Auth ── */
  auth: {
    async login(email, password, tenant_id) {
      const data = await POST('/auth/login', { email, password, tenant_id });
      if (!data?.token) throw new Error('No token in login response');
      TokenStore.set(data.token, data.refreshToken, data.expiresAt || data.expiresIn);
      if (data.user) TokenStore.setUser(data.user);
      return data;
    },

    async logout() {
      const rt = TokenStore.getRefresh();
      try {
        await POST('/auth/logout', { refresh_token: rt });
      } catch { /* non-fatal */ }
      TokenStore.clear();
    },

    async me()         { return GET('/auth/me'); },
    async sessions()   { return GET('/auth/sessions'); },
    async activity(n)  { return GET('/auth/activity', { limit: n || 20 }); },
    async revokeSession(id) { return DELETE(`/auth/sessions/${id}`); },
    async revokeAllSessions() { return DELETE('/auth/sessions'); },

    async register(data) { return POST('/auth/register', data); },

    currentUser()  { return TokenStore.getUser(); },
    isLoggedIn()   { return !!TokenStore.get(); },
    restore:       restoreSession,
  },

  /* ── Dashboard ── */
  dashboard: {
    get()         { return GET('/dashboard'); },
    stats()       { return GET('/dashboard/stats-live'); },
    trends(days)  { return GET('/dashboard/trends', { days: days || 7 }); },
    kpis()        { return GET('/dashboard/kpis'); },
  },

  /* ── Alerts ── */
  alerts: {
    list(params)         { return GET('/alerts', params); },
    get(id)              { return GET(`/alerts/${id}`); },
    stats()              { return GET('/alerts/stats'); },
    create(data)         { return POST('/alerts', data); },
    update(id, data)     { return PATCH(`/alerts/${id}`, data); },
    delete(id)           { return DELETE(`/alerts/${id}`); },
    assign(id, userId)   { return POST(`/alerts/${id}/assign`, { assigned_to: userId }); },
    escalate(id)         { return POST(`/alerts/${id}/escalate`, {}); },
    resolve(id, notes)   { return PATCH(`/alerts/${id}`, { status: 'resolved', notes }); },
  },

  /* ── Cases ── */
  cases: {
    list(params)         { return GET('/cases', params); },
    get(id)              { return GET(`/cases/${id}`); },
    create(data)         { return POST('/cases', data); },
    update(id, data)     { return PATCH(`/cases/${id}`, data); },
    delete(id)           { return DELETE(`/cases/${id}`); },
    addNote(id, content) { return POST(`/cases/${id}/notes`, { content }); },
    addIOC(id, iocId)    { return POST(`/cases/${id}/iocs`, { ioc_id: iocId }); },
    addEvidence(id, fd)  { return apiRequest('POST', `/cases/${id}/evidence`, null, { body: fd, headers: {} }); },
    timeline(id)         { return GET(`/cases/${id}/timeline`); },
    exportPDF(id)        { return `${CONFIG.BACKEND_URL}/api/cases/${id}/export-pdf?token=${TokenStore.get()}`; },
  },

  /* ── IOCs ── */
  iocs: {
    list(params)         { return GET('/iocs', params); },
    get(id)              { return GET(`/iocs/${id}`); },
    create(data)         { return POST('/iocs', data); },
    update(id, data)     { return PATCH(`/iocs/${id}`, data); },
    delete(id)           { return DELETE(`/iocs/${id}`); },
    bulk(iocs)           { return POST('/iocs/bulk', { iocs }); },
    enrich(id)           { return GET(`/iocs/${id}/enrich`); },
    pivot(field, value)  { return POST('/iocs/pivot', { field, value }); },
    search(q, params)    { return GET('/iocs', { search: q, ...params }); },
    export(params)       { return `${CONFIG.BACKEND_URL}/api/iocs/export?${new URLSearchParams(params || {})}&token=${TokenStore.get()}`; },
  },

  /* ── Threat Intel Enrichment ── */
  intel: {
    virustotal(ioc, type) { return POST('/intel/virustotal', { ioc, type }); },
    abuseipdb(ip)         { return POST('/intel/abuseipdb', { ip }); },
    shodan(ip)            { return POST('/intel/shodan', { ip }); },
    otx(ioc, type)        { return POST('/intel/otx', { ioc, type }); },
    enrich(ioc, type)     { return POST('/intel/enrich', { ioc, type }); },
    feeds()               { return GET('/intel/feeds'); },
  },

  /* ── CTI (Threat Actors, Campaigns, etc.) ── */
  cti: {
    actors: {
      list(params)        { return GET('/cti/actors', params); },
      get(id)             { return GET(`/cti/actors/${id}`); },
      create(data)        { return POST('/cti/actors', data); },
      update(id, data)    { return PATCH(`/cti/actors/${id}`, data); },
      delete(id)          { return DELETE(`/cti/actors/${id}`); },
    },
    campaigns: {
      list(params)        { return GET('/cti/campaigns', params); },
      get(id)             { return GET(`/cti/campaigns/${id}`); },
      create(data)        { return POST('/cti/campaigns', data); },
      update(id, data)    { return PATCH(`/cti/campaigns/${id}`, data); },
      delete(id)          { return DELETE(`/cti/campaigns/${id}`); },
    },
    mitre: {
      coverage()          { return GET('/cti/mitre/coverage'); },
      techniques(params)  { return GET('/cti/mitre/techniques', params); },
      tactic(id)          { return GET(`/cti/mitre/tactics/${id}`); },
      heatmap()           { return GET('/cti/mitre/heatmap'); },
    },
    feedLogs(params)      { return GET('/cti/feed-logs', params); },
    timeline(params)      { return GET('/cti/timeline', params); },
    ingest(feed)          { return POST(`/cti/ingest/${feed || 'all'}`, {}); },
    aiQuery(q, ctx)       { return POST('/cti/ai/query', { query: q, context: ctx }); },
    aiSessions()          { return GET('/cti/ai/sessions'); },
    stats()               { return GET('/cti/stats'); },
  },

  /* ── Vulnerabilities ── */
  vulns: {
    list(params)          { return GET('/vulnerabilities', params); },
    get(cveId)            { return GET(`/vulnerabilities/${cveId}`); },
    stats()               { return GET('/vulnerabilities/stats'); },
    kev(params)           { return GET('/vulnerabilities/kev', params); },
    sync(source, days)    { return POST('/vulnerabilities/sync', { source, days }); },
  },

  /* ── Users ── */
  users: {
    list(params)          { return GET('/users', params); },
    get(id)               { return GET(`/users/${id}`); },
    create(data)          { return POST('/users', data); },
    update(id, data)      { return PATCH(`/users/${id}`, data); },
    delete(id)            { return DELETE(`/users/${id}`); },
    resetPassword(id, pw) { return POST(`/users/${id}/reset-password`, { new_password: pw }); },
    setStatus(id, s)      { return PATCH(`/users/${id}/status`, { status: s }); },
    permissions(id, perms){ return PATCH(`/users/${id}/permissions`, { permissions: perms }); },
  },

  /* ── Tenants ── */
  tenants: {
    list()                { return GET('/tenants'); },
    get(id)               { return GET(`/tenants/${id}`); },
    stats(id)             { return GET(`/tenants/${id}/stats`); },
    create(data)          { return POST('/tenants', data); },
    update(id, data)      { return PATCH(`/tenants/${id}`, data); },
  },

  /* ── Audit Logs ── */
  audit: {
    list(params)          { return GET('/audit', params); },
    byUser(userId)        { return GET(`/audit/user/${userId}`); },
    loginActivity(params) { return GET('/auth/activity', params); },
    export()              { return `${CONFIG.BACKEND_URL}/api/audit/export?token=${TokenStore.get()}`; },
  },

  /* ── Playbooks ── */
  playbooks: {
    list()                { return GET('/playbooks'); },
    get(id)               { return GET(`/playbooks/${id}`); },
    create(data)          { return POST('/playbooks', data); },
    update(id, data)      { return PATCH(`/playbooks/${id}`, data); },
    delete(id)            { return DELETE(`/playbooks/${id}`); },
  },

  /* ── Collectors ── */
  collectors: {
    list()                { return GET('/collectors'); },
    sync(name)            { return POST(`/collectors/sync/${name}`, {}); },
    syncAll()             { return POST('/collectors/sync-all', {}); },
    logs(name, params)    { return GET(`/collectors/logs/${name}`, params); },
    status()              { return GET('/collectors/status'); },
  },

  /* ── Sysmon ── */
  sysmon: {
    sessions(params)      { return GET('/sysmon/sessions', params); },
    session(id)           { return GET(`/sysmon/sessions/${id}`); },
    detections(logId, p)  { return GET(`/sysmon/sessions/${logId}/detections`, p); },
    analyze(formData)     {
      return fetch(`${CONFIG.BACKEND_URL}/api/sysmon/analyze`, {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${TokenStore.get()}` },
        body:    formData,
      }).then(r => r.json());
    },
    rules()               { return GET('/sysmon/rules'); },
    export(logId)         { return `${CONFIG.BACKEND_URL}/api/sysmon/sessions/${logId}/export?token=${TokenStore.get()}`; },
  },

  /* ── Executive Reports ── */
  reports: {
    list()                { return GET('/reports'); },
    generate(params)      { return POST('/reports/generate', params); },
    get(id)               { return GET(`/reports/${id}`); },
    download(id)          { return `${CONFIG.BACKEND_URL}/api/reports/${id}/download?token=${TokenStore.get()}`; },
  },

  /* ── Detections ── */
  detections: {
    list(params)          { return GET('/detections', params); },
    get(id)               { return GET(`/detections/${id}`); },
    timeline(params)      { return GET('/cti/timeline', params); },
  },
};

/* ════════════════════════════════════════════
   WEBSOCKET CLIENT
═════════════════════════════════════════════ */
let _socket = null;

const WS = {
  connect() {
    if (_socket?.connected) return _socket;

    if (typeof io === 'undefined') {
      console.warn('[WS] socket.io not loaded');
      return null;
    }

    _socket = io(CONFIG.WS_URL, {
      auth:                { token: TokenStore.get() },
      transports:          ['websocket', 'polling'],
      reconnection:        true,
      reconnectionAttempts:10,
      reconnectionDelay:   2000,
      timeout:             10000,
    });

    _socket.on('connect', () => {
      console.log('[WS] Connected');
      window.dispatchEvent(new CustomEvent('ws:connected'));
    });

    _socket.on('disconnect', (reason) => {
      console.log('[WS] Disconnected:', reason);
      window.dispatchEvent(new CustomEvent('ws:disconnected', { detail: { reason } }));
    });

    _socket.on('connect_error', (err) => {
      console.warn('[WS] Connection error:', err.message);
    });

    // Forward all backend events as DOM CustomEvents
    ['alert:new', 'alert:updated', 'alert:escalated', 'alert:assigned',
     'case:new',  'case:updated',  'detection:event',
     'ioc:new',   'feed:updated',  'system:status'].forEach(evt => {
      _socket.on(evt, (data) => {
        window.dispatchEvent(new CustomEvent(`ws:${evt}`, { detail: data }));
      });
    });

    return _socket;
  },

  disconnect() {
    _socket?.disconnect();
    _socket = null;
  },

  startDetections() { _socket?.emit('detections:start'); },
  stopDetections()  { _socket?.emit('detections:stop'); },
  subscribeAlerts() { _socket?.emit('alert:subscribe'); },
  subscribeCase(id) { _socket?.emit('case:subscribe', id); },
  unsubscribeCase(id){ _socket?.emit('case:unsubscribe', id); },

  on(event, handler) {
    window.addEventListener(`ws:${event}`, (e) => handler(e.detail));
  },

  isConnected() { return !!_socket?.connected; },
};

/* ════════════════════════════════════════════
   SESSION RESTORE ON PAGE LOAD
   Called automatically when script loads — this
   enables seamless session persistence on refresh.
═════════════════════════════════════════════ */
(async function _autoRestoreSession() {
  // Don't attempt restore if we're already in login screen logic
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _tryRestore);
  } else {
    await _tryRestore();
  }
})();

async function _tryRestore() {
  // Skip if we have a valid session in memory already
  if (typeof window.CURRENT_USER !== 'undefined' && window.CURRENT_USER) return;

  const user = await restoreSession();
  if (user) {
    // Restore CURRENT_USER for the app
    window.CURRENT_USER = {
      id:          user.id,
      email:       user.email,
      name:        user.name || user.email,
      role:        user.role,
      tenant:      user.tenant_slug || user.tenant,
      tenant_name: user.tenant_name || '',
      tenant_id:   user.tenant_id,
      avatar:      user.avatar || (user.name || 'U').split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
      permissions: user.permissions || ['read'],
      mfa_enabled: user.mfa_enabled || false,
    };

    // Dispatch event so the app can show dashboard without login
    window.dispatchEvent(new CustomEvent('auth:restored', { detail: user }));
  }
}

/* ════════════════════════════════════════════
   REAL-TIME EVENT LISTENERS — wire WS to UI
═════════════════════════════════════════════ */
function initRealtime() {
  const socket = WS.connect();
  if (!socket) return;

  WS.on('alert:new', (alert) => {
    if (typeof showToast === 'function')
      showToast(`🚨 New ${alert.severity} Alert: ${alert.title}`, 'warning');
    const nb = document.getElementById('nb-critical');
    if (nb && alert.severity === 'CRITICAL')
      nb.textContent = parseInt(nb.textContent || 0) + 1;
    window.dispatchEvent(new CustomEvent('data:alertsUpdated'));
  });

  WS.on('case:new', (caseData) => {
    if (typeof showToast === 'function')
      showToast(`📁 New case: ${caseData.title}`, 'info');
  });

  WS.on('alert:escalated', (alert) => {
    if (typeof showToast === 'function')
      showToast(`⚠️ Alert ESCALATED: ${alert.title}`, 'error');
  });

  WS.on('feed:updated', (data) => {
    window.dispatchEvent(new CustomEvent('data:feedUpdated', { detail: data }));
  });

  // Auth expiry handler
  window.addEventListener('auth:expired', () => {
    if (typeof showToast === 'function')
      showToast('Session expired. Please log in again.', 'error');
    setTimeout(() => {
      if (typeof doLogout === 'function') doLogout();
    }, 2000);
  });
}

/* ════════════════════════════════════════════
   IOC ENRICHMENT MODAL
═════════════════════════════════════════════ */
async function enrichIOCLive(ioc, type) {
  if (typeof showToast === 'function') showToast(`Enriching ${ioc}…`, 'info');
  try {
    const data = await API.intel.enrich(ioc, type);
    openEnrichmentModal(ioc, type, data);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`Enrichment failed: ${err.message}`, 'error');
  }
}

function openEnrichmentModal(ioc, type, data) {
  const score = data?.aggregate_risk_score || 0;
  const color = score < 10 ? 'var(--accent-green)' : score < 50 ? 'var(--accent-orange)' : 'var(--accent-red)';
  const srcs  = data?.sources || {};

  const html = `
  <div style="padding:24px;">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
      <div style="font-size:20px;font-weight:700;color:var(--text-primary);">🔬 IOC Enrichment</div>
      <div style="background:var(--bg-card);padding:4px 10px;border-radius:6px;font-family:monospace;font-size:13px;">${ioc}</div>
      <div style="background:${color}22;color:${color};padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600;">
        Risk: ${score}/100
      </div>
    </div>
    ${Object.keys(srcs).length === 0
      ? '<div style="color:var(--text-muted);text-align:center;padding:20px;">No enrichment data available</div>'
      : `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;">
          ${Object.entries(srcs).map(([source, r]) => `
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;">
              <div style="font-weight:600;color:var(--text-primary);margin-bottom:8px;">
                ${source === 'virustotal' ? '🦠 VirusTotal'
                  : source === 'abuseipdb' ? '🚨 AbuseIPDB'
                  : source === 'shodan'    ? '🔍 Shodan'
                  : '👁 AlienVault OTX'}
              </div>
              ${r.fromCache ? '<div style="font-size:10px;color:var(--text-muted);">📦 Cached</div>' : ''}
              ${_renderEnrichmentSource(source, r)}
            </div>
          `).join('')}
        </div>`}
  </div>`;

  const modal = document.getElementById('detailModal');
  const body  = document.getElementById('detailModalBody');
  if (body)  body.innerHTML = html;
  if (modal) modal.style.display = 'flex';
}

function _renderEnrichmentSource(source, data) {
  if (!data) return '<div style="font-size:12px;color:var(--text-muted);">No data</div>';

  if (source === 'virustotal') return `
    <div style="font-size:13px;color:var(--text-secondary);">
      <div>Malicious: <strong style="color:var(--accent-red)">${data.malicious_count || 0}/${data.total_engines || 0}</strong></div>
      ${data.country ? `<div>Country: <strong>${data.country}</strong></div>` : ''}
      ${data.asn     ? `<div>ASN: <strong>${data.asn}</strong></div>`         : ''}
    </div>`;

  if (source === 'abuseipdb') return `
    <div style="font-size:13px;color:var(--text-secondary);">
      <div>Abuse Score: <strong style="color:var(--accent-orange)">${data.abuse_score || 0}%</strong></div>
      <div>Reports: <strong>${data.total_reports || 0}</strong></div>
      ${data.isp    ? `<div>ISP: <strong>${data.isp}</strong></div>` : ''}
      ${data.is_tor ? `<div>⚠️ <strong>Tor Exit Node</strong></div>` : ''}
    </div>`;

  if (source === 'shodan') return `
    <div style="font-size:13px;color:var(--text-secondary);">
      <div>Open Ports: <strong>${(data.ports || []).join(', ') || 'None'}</strong></div>
      <div>CVEs: <strong style="color:${(data.vulns||[]).length ? 'var(--accent-red)' : 'var(--text-secondary)'}">${(data.vulns||[]).length}</strong></div>
      ${data.org ? `<div>Org: <strong>${data.org}</strong></div>` : ''}
    </div>`;

  if (source === 'otx') return `
    <div style="font-size:13px;color:var(--text-secondary);">
      <div>Pulses: <strong style="color:${(data.pulse_count||0) > 0 ? 'var(--accent-red)' : 'var(--text-secondary)'}">${data.pulse_count || 0}</strong></div>
      ${(data.pulses||[]).slice(0,2).map(p => `<div style="font-size:11px;color:var(--text-muted);">• ${p.name}</div>`).join('')}
    </div>`;

  return '<div style="font-size:12px;color:var(--text-muted);">No data</div>';
}

/* ════════════════════════════════════════════
   EXPORT — global namespace
═════════════════════════════════════════════ */
window.API             = API;
window.WS              = WS;
window.TokenStore      = TokenStore;
window.enrichIOCLive   = enrichIOCLive;
window.initRealtime    = initRealtime;
window.restoreSession  = restoreSession;

// Legacy compat aliases
window.loadDashboardData = () => API.dashboard.stats().catch(() => null);
window.loadAlerts        = (p) => API.alerts.list(p).then(r => r?.data || []).catch(() => []);
window.loadIOCs          = (p) => API.iocs.list(p).then(r => r?.data || []).catch(() => []);

})(); // end IIFE — scopes _refreshPromise to prevent collision with auth-interceptor.js
