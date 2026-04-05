/**
 * ══════════════════════════════════════════════════════════
 *  ThreatPilot AI — CTI Frontend API Client v3.0
 *  js/cti-api.js
 *
 *  Wraps all /api/cti/* endpoints with clean async methods.
 *  Reads CONFIG.BACKEND_URL from api-client.js (already loaded).
 *
 *  Usage:
 *    const actors = await CTI.actors.list();
 *    const result = await CTI.ai.query("Check IP 1.2.3.4");
 *    await CTI.ingest('otx');
 * ══════════════════════════════════════════════════════════
 */
'use strict';

(function () {
  // ── Base request helper ──────────────────────────────────
  async function ctiRequest(method, path, body = null, params = null) {
    const base = (window.THREATPILOT_API_URL || 'http://localhost:4000').replace(/\/$/, '');
    let url = `${base}/api/cti${path}`;

    if (params) {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== null && v !== undefined && v !== '')
      ).toString();
      if (qs) url += `?${qs}`;
    }

    // Read token from localStorage (persistent) then sessionStorage fallback
    const token = localStorage.getItem('wadjet_access_token')
               || localStorage.getItem('tp_access_token')
               || sessionStorage.getItem('tp_token') || '';

    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    };

    if (body && method !== 'GET' && method !== 'DELETE') {
      opts.body = JSON.stringify(body);
    }

    let resp;
    try {
      resp = await fetch(url, opts);
    } catch (netErr) {
      console.warn(`[CTI API] Network error for ${path}:`, netErr.message);
      return null; // Caller will handle null gracefully
    }

    if (resp.status === 204) return null;

    if (!resp.ok) {
      let errMsg = resp.statusText;
      try { const j = await resp.json(); errMsg = j.error || j.message || errMsg; } catch { /* ignore */ }
      console.warn(`[CTI API] ${method} ${path} → ${resp.status}: ${errMsg}`);
      if (resp.status === 401 || resp.status === 403) {
        throw new Error(`Auth error ${resp.status}: ${errMsg}. Check THREATPILOT_API_URL and your JWT token.`);
      }
      return null;  // other HTTP errors: return null so the UI shows the fallback message
    }

    return await resp.json();
  }

  const get    = (path, params) => ctiRequest('GET',    path, null, params);
  const post   = (path, body)   => ctiRequest('POST',   path, body);
  const patch  = (path, body)   => ctiRequest('PATCH',  path, body);
  const del    = (path)         => ctiRequest('DELETE', path);

  // ══════════════════════════════════════════════════════════
  //  CTI NAMESPACE
  // ══════════════════════════════════════════════════════════
  const CTI = {

    // ── Stats / Overview ─────────────────────────────────
    getStats: () => get('/stats'),

    // ══════════════════════════════════════════════════════
    //  THREAT ACTORS
    // ══════════════════════════════════════════════════════
    actors: {
      list: (params = {}) => get('/actors', params),
      get:  (id) => get(`/actors/${id}`),
      create: (data) => post('/actors', data),
      update: (id, data) => patch(`/actors/${id}`, data),
      delete: (id) => del(`/actors/${id}`),
    },

    // ══════════════════════════════════════════════════════
    //  CAMPAIGNS
    // ══════════════════════════════════════════════════════
    campaigns: {
      list:   (params = {}) => get('/campaigns', params),
      get:    (id) => get(`/campaigns/${id}`),
      create: (data) => post('/campaigns', data),
      update: (id, data) => patch(`/campaigns/${id}`, data),
      delete: (id) => del(`/campaigns/${id}`),
    },

    // ══════════════════════════════════════════════════════
    //  VULNERABILITIES
    // ══════════════════════════════════════════════════════
    vulnerabilities: {
      list:   (params = {}) => get('/vulnerabilities', params),
      get:    (id) => get(`/vulnerabilities/${id}`),
      create: (data) => post('/vulnerabilities', data),
    },

    // ══════════════════════════════════════════════════════
    //  MITRE ATT&CK
    // ══════════════════════════════════════════════════════
    mitre: {
      list:     (params = {}) => get('/mitre', params),
      coverage: () => get('/mitre/coverage'),
    },

    // ══════════════════════════════════════════════════════
    //  RELATIONSHIPS (graph)
    // ══════════════════════════════════════════════════════
    relationships: {
      list:   (params = {}) => get('/relationships', params),
      graph:  (params = {}) => get('/relationships/graph', params),
      create: (data) => post('/relationships', data),
    },

    // ══════════════════════════════════════════════════════
    //  FEED LOGS
    // ══════════════════════════════════════════════════════
    feedLogs: {
      list: (params = {}) => get('/feed-logs', params),
    },

    // ══════════════════════════════════════════════════════
    //  DETECTION TIMELINE
    // ══════════════════════════════════════════════════════
    timeline: {
      list: (params = {}) => get('/timeline', params),
    },

    // ══════════════════════════════════════════════════════
    //  INGESTION TRIGGERS
    // ══════════════════════════════════════════════════════
    ingest: (feed) => post(`/ingest/${feed}`, {}),

    // ══════════════════════════════════════════════════════
    //  RISK SCORING
    // ══════════════════════════════════════════════════════
    riskScore: (iocValue, iocType, enrichmentData) =>
      post('/risk-score', { ioc_value: iocValue, ioc_type: iocType, enrichment_data: enrichmentData }),

    // ══════════════════════════════════════════════════════
    //  AI ORCHESTRATOR
    // ══════════════════════════════════════════════════════
    ai: {
      query:        (queryText, context = {}) => post('/ai/query', { query: queryText, context }),
      savSession:   (title, messages) => post('/ai/sessions', { title, messages }),
      listSessions: () => get('/ai/sessions'),
    },
  };

  // ══════════════════════════════════════════════════════════
  //  LIVE DATA HELPERS (used by tab renderers)
  // ══════════════════════════════════════════════════════════

  CTI.loadCommandCenter = async function () {
    const [stats, recentAlerts, feedStatus, timeline] = await Promise.allSettled([
      CTI.getStats(),
      get('/timeline', { days: 1, limit: 10 }),
      CTI.feedLogs.list({ limit: 5 }),
      CTI.timeline.list({ days: 7, limit: 50 }),
    ]);

    return {
      stats:        stats.value,
      recentAlerts: recentAlerts.value?.data || [],
      feedStatus:   feedStatus.value?.feed_status || [],
      timeline:     timeline.value?.data || [],
    };
  };

  CTI.loadIOCRegistry = async function (page = 1, filters = {}) {
    // Use existing /api/iocs endpoint (already in api-client.js)
    // This wraps it for convenience
    const base = (window.THREATPILOT_API_URL || 'http://localhost:4000').replace(/\/$/, '');
    const token = sessionStorage.getItem('tp_token');

    const params = new URLSearchParams({ page, limit: 50, ...filters }).toString();
    try {
      const resp = await fetch(`${base}/api/iocs?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return resp.ok ? await resp.json() : { data: [], total: 0 };
    } catch (_) {
      return { data: [], total: 0 };
    }
  };

  CTI.loadThreatActors = async function (page = 1, search = '') {
    return CTI.actors.list({ page, limit: 20, search });
  };

  CTI.loadCampaigns = async function (page = 1, status = '') {
    return CTI.campaigns.list({ page, limit: 20, status });
  };

  CTI.loadMITRECoverage = async function () {
    return CTI.mitre.coverage();
  };

  CTI.loadRelationshipGraph = async function () {
    return CTI.relationships.graph({ limit: 300 });
  };

  // ── Expose globally ───────────────────────────────────────
  window.CTI = CTI;

  console.log('[CTI API] v3.0 ready — backend:', window.THREATPILOT_API_URL || 'http://localhost:4000');
})();
