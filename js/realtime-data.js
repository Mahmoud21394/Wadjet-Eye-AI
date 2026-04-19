/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Real-Time Live Data Module v1.0
 *
 *  Replaces ALL static ARGUS_DATA / demo data with live
 *  Supabase reads via the backend API.
 *
 *  Tab priority order (as requested):
 *   1. Command Center (Dashboard)   → /api/dashboard
 *   2. Alerts / Findings            → /api/alerts
 *   3. IOC Registry                 → /api/iocs + /api/intel/enrich
 *   4. Cases                        → /api/cases
 *   5. Playbooks                    → /api/playbooks
 *   6. Collectors                   → /api/collectors (live feeds)
 *   7. Users / Tenants              → /api/users, /api/tenants
 *   8. Audit Logs                   → /api/audit
 * ══════════════════════════════════════════════════════════
 */

'use strict';

/* ════════════════════════════════════════════
   LIVE DATA CACHE (in-memory, TTL-based)
═════════════════════════════════════════════ */
const LiveCache = (() => {
  const _store = {};
  const TTL_MS = {
    dashboard: 30_000,   // 30s
    alerts:    15_000,   // 15s
    iocs:      60_000,   // 60s
    cases:     30_000,
    playbooks: 120_000,  // 2m
    users:     120_000,
    audit:     10_000,
  };

  return {
    get(key) {
      const entry = _store[key];
      if (!entry) return null;
      if (Date.now() - entry.ts > (TTL_MS[key] || 30_000)) {
        delete _store[key];
        return null;
      }
      return entry.data;
    },
    set(key, data)  { _store[key] = { data, ts: Date.now() }; },
    invalidate(key) { delete _store[key]; },
    invalidateAll() { Object.keys(_store).forEach(k => delete _store[k]); },
  };
})();

/* ════════════════════════════════════════════
   BACKEND AVAILABILITY CHECK
═════════════════════════════════════════════ */
let _backendOnline = null;  // null = not checked yet

async function checkBackendOnline() {
  if (_backendOnline !== null) return _backendOnline;
  try {
    const r = await fetch(`${window.THREATPILOT_API_URL || 'http://localhost:4000'}/health`, {
      signal: AbortSignal.timeout(5000)
    });
    const j = await r.json();
    _backendOnline = r.ok && (j.status === 'OK' || j.status === 'ok');
  } catch {
    _backendOnline = false;
  }
  console.info(`[LiveData] Backend online: ${_backendOnline}`);
  return _backendOnline;
}

// Reset online flag every 2 minutes so it re-checks
setInterval(() => { _backendOnline = null; }, 120_000);

/* ════════════════════════════════════════════
   TAB 1 — COMMAND CENTER (Dashboard)
═════════════════════════════════════════════ */
const DashboardData = {

  async load() {
    const cached = LiveCache.get('dashboard');
    if (cached) return cached;

    const online = await checkBackendOnline();
    if (!online) return DashboardData._fallback();

    try {
      const [dash, alertStats] = await Promise.all([
        API.dashboard.get().catch(() => null),
        API.alerts.stats().catch(() => null),
      ]);

      const data = {
        kpis: {
          critical_alerts: dash?.kpis?.critical_alerts ?? alertStats?.critical ?? 0,
          open_cases:      dash?.kpis?.open_cases      ?? 0,
          active_iocs:     dash?.kpis?.active_iocs     ?? 0,
          threat_pressure: dash?.kpis?.threat_pressure ?? 0,
          open_alerts:     alertStats?.total           ?? 0,
        },
        severity_breakdown: dash?.severity_breakdown || alertStats?.by_severity || {},
        recent_alerts:  dash?.recent_alerts  || [],
        recent_cases:   dash?.recent_cases   || [],
        ioc_stats:      dash?.ioc_stats      || {},
        threat_trend:   dash?.threat_trend   || [],
        source:         'live',
      };

      LiveCache.set('dashboard', data);
      return data;
    } catch (err) {
      console.warn('[LiveData][Dashboard] API error, using fallback:', err.message);
      return DashboardData._fallback();
    }
  },

  _fallback() {
    return {
      kpis: { critical_alerts: 0, open_cases: 0, active_iocs: 0, threat_pressure: 0 },
      source: 'offline',
    };
  },

  async render() {
    const data = await DashboardData.load();
    DashboardData._updateKPIs(data.kpis);
    DashboardData._updateBadge(data.source);

    if (data.recent_alerts?.length > 0) {
      DashboardData._renderRecentAlerts(data.recent_alerts);
    }
  },

  _updateKPIs(kpis) {
    const map = {
      'kpi-critical':       kpis.critical_alerts,
      'kpi-cases':          kpis.open_cases,
      'kpi-iocs':           kpis.active_iocs,
      'kpi-threat-pressure':kpis.threat_pressure,
      'nb-critical':        kpis.critical_alerts,
      'stat-open-alerts':   kpis.open_alerts,
    };
    Object.entries(map).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el && val !== undefined) {
        const current = parseInt(el.textContent) || 0;
        if (current !== val) {
          el.textContent = val;
          el.classList.add('kpi-flash');
          setTimeout(() => el.classList.remove('kpi-flash'), 600);
        }
      }
    });
  },

  _updateBadge(source) {
    const badge = document.getElementById('data-source-badge');
    if (badge) {
      badge.textContent = source === 'live' ? '🟢 Live' : '🔴 Offline';
      badge.style.color  = source === 'live' ? '#00ff88' : '#ff4444';
    }
  },

  _renderRecentAlerts(alerts) {
    const container = document.getElementById('recent-alerts-list');
    if (!container) return;

    const severityColors = {
      CRITICAL: '#ff4444', HIGH: '#ff8c00', MEDIUM: '#ffd700', LOW: '#00bcd4'
    };

    container.innerHTML = alerts.slice(0, 8).map(a => `
      <div class="recent-alert-item" data-id="${a.id}" onclick="LiveAlerts.openDetail('${a.id}')">
        <span class="sev-dot" style="background:${severityColors[a.severity]||'#888'}"></span>
        <span class="alert-title">${escapeHtml(a.title)}</span>
        <span class="alert-time">${timeAgo(a.created_at)}</span>
        <span class="alert-status status-${a.status}">${a.status}</span>
      </div>
    `).join('');
  }
};

/* ════════════════════════════════════════════
   TAB 2 — ALERTS / FINDINGS
═════════════════════════════════════════════ */
const LiveAlerts = {

  _page:    1,
  _limit:   25,
  _filters: {},
  _total:   0,

  async load(filters = {}, page = 1) {
    this._filters = filters;
    this._page    = page;

    const online = await checkBackendOnline();
    if (!online) {
      showToast('Backend offline — showing cached data', 'warn');
      return { data: [], total: 0, source: 'offline' };
    }

    try {
      const params = {
        page,
        limit: this._limit,
        ...filters,
      };
      const result = await API.alerts.list(params);
      this._total = result.total || result.data?.length || 0;
      LiveCache.set('alerts', result);
      return { ...result, source: 'live' };
    } catch (err) {
      console.warn('[LiveData][Alerts] load error:', err.message);
      const cached = LiveCache.get('alerts');
      return cached ? { ...cached, source: 'cached' } : { data: [], total: 0, source: 'error' };
    }
  },

  async openDetail(alertId) {
    try {
      const alert = await API.alerts.get(alertId);
      if (typeof renderAlertDetailModal === 'function') {
        renderAlertDetailModal(alert);
      }
    } catch (err) {
      showToast('Failed to load alert details: ' + err.message, 'error');
    }
  },

  async create(data) {
    try {
      const created = await API.alerts.create(data);
      LiveCache.invalidate('alerts');
      LiveCache.invalidate('dashboard');
      showToast('Alert created', 'success');
      return created;
    } catch (err) {
      showToast('Failed to create alert: ' + err.message, 'error');
      throw err;
    }
  },

  async update(id, changes) {
    try {
      const updated = await API.alerts.update(id, changes);
      LiveCache.invalidate('alerts');
      LiveCache.invalidate('dashboard');
      return updated;
    } catch (err) {
      showToast('Failed to update alert: ' + err.message, 'error');
      throw err;
    }
  },

  async resolve(id, notes = '') {
    return this.update(id, { status: 'resolved', notes, resolved_at: new Date().toISOString() });
  },

  async escalate(id) {
    return this.update(id, { status: 'escalated', escalated_at: new Date().toISOString() });
  },

  render(containerId, alerts) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!alerts || alerts.length === 0) {
      el.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-shield-alt"></i>
          <p>No alerts found</p>
          <small>Adjust filters or wait for new detections</small>
        </div>`;
      return;
    }

    const severityBadge = s => `<span class="badge sev-${(s||'').toLowerCase()}">${s}</span>`;
    const statusBadge   = s => `<span class="badge status-${(s||'').replace('_','-')}">${s?.replace('_',' ')}</span>`;

    el.innerHTML = alerts.map(a => `
      <div class="alert-row" data-id="${a.id}" onclick="LiveAlerts.openDetail('${a.id}')">
        <div class="alert-col-sev">${severityBadge(a.severity)}</div>
        <div class="alert-col-title">
          <strong>${escapeHtml(a.title)}</strong>
          ${a.ioc_value ? `<small class="ioc-pill">${escapeHtml(a.ioc_value)}</small>` : ''}
        </div>
        <div class="alert-col-source">${escapeHtml(a.source || 'N/A')}</div>
        <div class="alert-col-status">${statusBadge(a.status)}</div>
        <div class="alert-col-time">${timeAgo(a.created_at)}</div>
        <div class="alert-col-actions">
          <button onclick="event.stopPropagation(); LiveAlerts.escalate('${a.id}')" title="Escalate" class="btn-icon"><i class="fas fa-arrow-up"></i></button>
          <button onclick="event.stopPropagation(); LiveAlerts.resolve('${a.id}')" title="Resolve" class="btn-icon"><i class="fas fa-check"></i></button>
        </div>
      </div>
    `).join('');
  }
};

/* ════════════════════════════════════════════
   TAB 3 — IOC REGISTRY (with live enrichment)
═════════════════════════════════════════════ */
const LiveIOCs = {

  _page: 1,
  _limit: 50,

  async load(filters = {}, page = 1) {
    this._page = page;
    const online = await checkBackendOnline();
    if (!online) return { data: [], total: 0, source: 'offline' };

    try {
      const result = await API.iocs.list({ page, limit: this._limit, ...filters });
      LiveCache.set('iocs', result);
      return { ...result, source: 'live' };
    } catch (err) {
      const cached = LiveCache.get('iocs');
      return cached ? { ...cached, source: 'cached' } : { data: [], total: 0, source: 'error' };
    }
  },

  async enrich(iocId, iocValue, iocType) {
    const btn = document.querySelector(`[data-enrich-id="${iocId}"]`);
    if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>'; btn.disabled = true; }

    try {
      const result = await API.intel.enrich(iocValue, iocType);
      LiveCache.invalidate('iocs');
      LiveIOCs._renderEnrichmentResult(iocId, result);
      showToast(`IOC enriched: risk score ${result.risk_score || 'N/A'}`, 'success');
      return result;
    } catch (err) {
      showToast('Enrichment failed: ' + err.message, 'error');
    } finally {
      if (btn) { btn.innerHTML = '<i class="fas fa-sync"></i>'; btn.disabled = false; }
    }
  },

  async bulkEnrich(iocList) {
    // iocList: [{value, type}]
    showToast(`Enriching ${iocList.length} IOCs...`, 'info');
    const results = [];
    for (const ioc of iocList) {
      try {
        const r = await API.intel.enrich(ioc.value, ioc.type);
        results.push({ ...ioc, result: r });
      } catch { /* skip */ }
      await sleep(200); // rate limit protection
    }
    showToast(`Enrichment complete: ${results.length}/${iocList.length} succeeded`, 'success');
    LiveCache.invalidate('iocs');
    return results;
  },

  async create(iocData) {
    try {
      const ioc = await API.iocs.create(iocData);
      LiveCache.invalidate('iocs');
      showToast('IOC added to registry', 'success');
      return ioc;
    } catch (err) {
      showToast('Failed to add IOC: ' + err.message, 'error');
      throw err;
    }
  },

  async delete(id) {
    if (!confirm('Remove this IOC from the registry?')) return;
    try {
      await API.iocs.delete(id);
      LiveCache.invalidate('iocs');
      showToast('IOC removed', 'info');
    } catch (err) {
      showToast('Failed to remove IOC: ' + err.message, 'error');
    }
  },

  _renderEnrichmentResult(iocId, data) {
    const row = document.querySelector(`[data-ioc-id="${iocId}"]`);
    if (!row) return;
    const scoreEl = row.querySelector('.risk-score');
    if (scoreEl) {
      const score = data.risk_score || 0;
      scoreEl.textContent = score;
      scoreEl.style.color = score >= 80 ? '#ff4444' : score >= 50 ? '#ff8c00' : '#00ff88';
    }
  },

  render(containerId, iocs) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!iocs || iocs.length === 0) {
      el.innerHTML = `<div class="empty-state"><i class="fas fa-database"></i><p>No IOCs in registry</p></div>`;
      return;
    }

    const repColors = { malicious: '#ff4444', suspicious: '#ff8c00', clean: '#00ff88', unknown: '#888' };
    const typeIcons = {
      ip: 'fa-network-wired', domain: 'fa-globe', url: 'fa-link',
      hash_sha256: 'fa-hashtag', hash_md5: 'fa-hashtag', email: 'fa-envelope',
      filename: 'fa-file', cve: 'fa-bug'
    };

    el.innerHTML = iocs.map(ioc => `
      <div class="ioc-row" data-ioc-id="${ioc.id}">
        <div class="ioc-type-icon"><i class="fas ${typeIcons[ioc.type] || 'fa-shield-alt'}"></i></div>
        <div class="ioc-value-col">
          <code class="ioc-value">${escapeHtml(ioc.value)}</code>
          <small class="ioc-type-badge">${ioc.type}</small>
        </div>
        <div class="ioc-rep" style="color:${repColors[ioc.reputation]||'#888'}">
          <i class="fas fa-circle" style="font-size:8px"></i> ${ioc.reputation}
        </div>
        <div class="ioc-score">
          <span class="risk-score" style="color:${(ioc.risk_score||0)>=80?'#ff4444':(ioc.risk_score||0)>=50?'#ff8c00':'#00ff88'}">
            ${ioc.risk_score || 0}
          </span>/100
        </div>
        <div class="ioc-source">${escapeHtml(ioc.source || 'manual')}</div>
        <div class="ioc-actor">${escapeHtml(ioc.threat_actor || '—')}</div>
        <div class="ioc-actions">
          <button data-enrich-id="${ioc.id}" onclick="LiveIOCs.enrich('${ioc.id}','${escapeHtml(ioc.value)}','${ioc.type}')"
            title="Enrich with threat intel" class="btn-icon btn-enrich">
            <i class="fas fa-sync-alt"></i>
          </button>
          <button onclick="LiveIOCs.delete('${ioc.id}')" title="Remove IOC" class="btn-icon btn-danger">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
    `).join('');
  }
};

/* ════════════════════════════════════════════
   TAB 4 — CASES
═════════════════════════════════════════════ */
const LiveCases = {

  async load(filters = {}, page = 1) {
    const online = await checkBackendOnline();
    if (!online) return { data: [], total: 0, source: 'offline' };

    try {
      const result = await API.cases.list({ page, limit: 20, ...filters });
      LiveCache.set('cases', result);
      return { ...result, source: 'live' };
    } catch (err) {
      const cached = LiveCache.get('cases');
      return cached ? { ...cached, source: 'cached' } : { data: [], total: 0, source: 'error' };
    }
  },

  async create(caseData) {
    try {
      const created = await API.cases.create(caseData);
      LiveCache.invalidate('cases');
      LiveCache.invalidate('dashboard');
      showToast('Case created', 'success');
      return created;
    } catch (err) {
      showToast('Failed to create case: ' + err.message, 'error');
      throw err;
    }
  },

  async addNote(caseId, content) {
    try {
      await API.cases.addNote(caseId, content);
      showToast('Note added', 'success');
    } catch (err) {
      showToast('Failed to add note: ' + err.message, 'error');
    }
  },

  async close(caseId, resolution) {
    try {
      await API.cases.update(caseId, {
        status: 'closed',
        resolution,
        closed_at: new Date().toISOString()
      });
      LiveCache.invalidate('cases');
      showToast('Case closed', 'success');
    } catch (err) {
      showToast('Failed to close case: ' + err.message, 'error');
    }
  },

  render(containerId, cases) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!cases || cases.length === 0) {
      el.innerHTML = `<div class="empty-state"><i class="fas fa-folder-open"></i><p>No cases found</p></div>`;
      return;
    }

    const slaDelta = (deadline) => {
      if (!deadline) return '';
      const diff = new Date(deadline) - Date.now();
      if (diff < 0) return `<span style="color:#ff4444">OVERDUE</span>`;
      const h = Math.floor(diff / 3600000);
      return `<span style="color:${h < 4 ? '#ff8c00' : '#00ff88'}">${h}h left</span>`;
    };

    el.innerHTML = cases.map(c => `
      <div class="case-card" data-id="${c.id}">
        <div class="case-header">
          <span class="case-sev sev-${(c.severity||'').toLowerCase()}">${c.severity}</span>
          <span class="case-status status-${(c.status||'').replace('_','-')}">${c.status?.replace('_',' ')}</span>
          <span class="case-sla">${slaDelta(c.sla_deadline)}</span>
        </div>
        <div class="case-title">${escapeHtml(c.title)}</div>
        <div class="case-desc">${escapeHtml((c.description||'').slice(0, 120))}${c.description?.length > 120 ? '…' : ''}</div>
        <div class="case-tags">${(c.tags||[]).map(t => `<span class="tag">${t}</span>`).join('')}</div>
        <div class="case-footer">
          <span><i class="fas fa-clock"></i> ${timeAgo(c.created_at)}</span>
          <button onclick="LiveCases._openDetail('${c.id}')" class="btn-sm">View Case</button>
        </div>
      </div>
    `).join('');
  },

  async _openDetail(caseId) {
    try {
      const caseData = await API.cases.get(caseId);
      if (typeof renderCaseDetailModal === 'function') {
        renderCaseDetailModal(caseData);
      }
    } catch (err) {
      showToast('Failed to load case: ' + err.message, 'error');
    }
  }
};

/* ════════════════════════════════════════════
   TAB 5 — COLLECTORS (Live Threat Feed Ingestion)
═════════════════════════════════════════════ */
const LiveCollectors = {

  _running: false,
  _lastPull: {},

  FEEDS: [
    { id: 'otx',       name: 'AlienVault OTX',   icon: 'fa-satellite-dish', color: '#00bcd4',  endpoint: '/collectors/otx' },
    { id: 'abuseipdb', name: 'AbuseIPDB',         icon: 'fa-ban',            color: '#ff4444',  endpoint: '/collectors/abuseipdb' },
    { id: 'virustotal',name: 'VirusTotal',         icon: 'fa-virus',          color: '#ff8c00',  endpoint: '/collectors/virustotal' },
    { id: 'shodan',    name: 'Shodan',             icon: 'fa-search',         color: '#4fc3f7',  endpoint: '/collectors/shodan' },
  ],

  async pullFeed(feedId) {
    const feed = this.FEEDS.find(f => f.id === feedId);
    if (!feed) return;

    const statusEl = document.getElementById(`collector-status-${feedId}`);
    const countEl  = document.getElementById(`collector-count-${feedId}`);
    if (statusEl) statusEl.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Pulling...';

    try {
      const online = await checkBackendOnline();
      if (!online) throw new Error('Backend offline');

      const resp = await fetch(
        `${window.THREATPILOT_API_URL || 'http://localhost:4000'}/api${feed.endpoint}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(TokenStore.get() ? { 'Authorization': `Bearer ${TokenStore.get()}` } : {})
          }
        }
      );

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const data = await resp.json();
      const count = data.imported || data.count || 0;

      this._lastPull[feedId] = new Date();
      if (statusEl) statusEl.innerHTML = `<span style="color:#00ff88"><i class="fas fa-check"></i> Active</span>`;
      if (countEl)  countEl.textContent = `+${count} IOCs`;
      showToast(`${feed.name}: pulled ${count} new IOCs`, 'success');

      // Invalidate caches so new data shows immediately
      LiveCache.invalidateAll();
      return data;

    } catch (err) {
      if (statusEl) statusEl.innerHTML = `<span style="color:#ff4444"><i class="fas fa-times"></i> Error</span>`;
      showToast(`${feed.name} pull failed: ${err.message}`, 'error');
      console.error(`[Collectors][${feedId}]`, err);
    }
  },

  async pullAll() {
    if (this._running) { showToast('Collection already running…', 'warn'); return; }
    this._running = true;

    const btn = document.getElementById('btn-pull-all');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Pulling all feeds…'; }

    showToast('Pulling all threat feeds…', 'info');
    let totalImported = 0;

    for (const feed of this.FEEDS) {
      const result = await this.pullFeed(feed.id);
      totalImported += result?.imported || result?.count || 0;
      await sleep(500); // stagger requests
    }

    this._running = false;
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-sync-alt"></i> Pull All Feeds'; }
    showToast(`All feeds pulled — ${totalImported} total new IOCs`, 'success');
  },

  renderStatus(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;

    el.innerHTML = this.FEEDS.map(feed => `
      <div class="collector-card" data-feed="${feed.id}">
        <div class="collector-icon" style="color:${feed.color}">
          <i class="fas ${feed.icon}"></i>
        </div>
        <div class="collector-info">
          <div class="collector-name">${feed.name}</div>
          <div class="collector-last">Last pull: ${
            this._lastPull[feed.id]
              ? timeAgo(this._lastPull[feed.id])
              : 'Never'
          }</div>
          <div id="collector-count-${feed.id}" class="collector-count"></div>
        </div>
        <div class="collector-status" id="collector-status-${feed.id}">
          <span style="color:#888"><i class="fas fa-circle"></i> Idle</span>
        </div>
        <button class="btn-sm btn-primary" onclick="LiveCollectors.pullFeed('${feed.id}')">
          <i class="fas fa-download"></i> Pull
        </button>
      </div>
    `).join('');
  }
};

/* ════════════════════════════════════════════
   GLOBAL AUTO-REFRESH
   Refreshes data on the currently active tab
   every 30 seconds
═════════════════════════════════════════════ */
const AutoRefresh = {

  _timer:       null,
  _activeTab:   null,
  _intervalMs:  30_000,
  _subscribers: {},

  setActiveTab(tabId) {
    this._activeTab = tabId;
    this._restartTimer();
  },

  subscribe(tabId, callback) {
    this._subscribers[tabId] = callback;
  },

  _restartTimer() {
    if (this._timer) clearInterval(this._timer);
    this._timer = setInterval(() => this._tick(), this._intervalMs);
  },

  async _tick() {
    if (!this._activeTab) return;
    const fn = this._subscribers[this._activeTab];
    if (typeof fn === 'function') {
      try { await fn(); } catch (err) {
        console.warn('[AutoRefresh] tick error:', err.message);
      }
    }
    // Update live clock
    const clockEl = document.getElementById('live-clock');
    if (clockEl) clockEl.textContent = new Date().toLocaleTimeString();
  },

  start() {
    this._restartTimer();
    console.info('[AutoRefresh] Started — interval:', this._intervalMs, 'ms');
  },

  stop() {
    if (this._timer) clearInterval(this._timer);
  }
};

/* ════════════════════════════════════════════
   LIVE SEARCH (debounced IOC / alert search)
═════════════════════════════════════════════ */
function setupLiveSearch(inputId, dataType, renderFn, containerId) {
  const input = document.getElementById(inputId);
  if (!input) return;

  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const q = input.value.trim();
      if (q.length < 2 && q.length > 0) return;

      let result;
      if (dataType === 'alerts') {
        result = await LiveAlerts.load({ search: q || undefined });
      } else if (dataType === 'iocs') {
        result = await LiveIOCs.load({ search: q || undefined });
      }
      if (result && typeof renderFn === 'function') {
        renderFn(containerId, result.data || []);
      }
    }, 350);
  });
}

/* ════════════════════════════════════════════
   UTILITY HELPERS
═════════════════════════════════════════════ */
function timeAgo(ts) {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 0) return 'just now';
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ════════════════════════════════════════════
   INIT — called after login
═════════════════════════════════════════════ */
async function initLiveData() {
  console.info('[LiveData] Initialising real-time data module…');

  // Wire up auto-refresh subscribers
  AutoRefresh.subscribe('command-center', () => DashboardData.render());
  AutoRefresh.subscribe('alerts',         async () => {
    const r = await LiveAlerts.load(LiveAlerts._filters, LiveAlerts._page);
    LiveAlerts.render('alerts-table-body', r.data || []);
  });
  AutoRefresh.subscribe('ioc-registry',   async () => {
    const r = await LiveIOCs.load();
    LiveIOCs.render('iocs-table-body', r.data || []);
  });
  AutoRefresh.subscribe('cases',          async () => {
    const r = await LiveCases.load();
    LiveCases.render('cases-grid', r.data || []);
  });

  // Start auto-refresh
  AutoRefresh.start();

  // Initial dashboard load
  await DashboardData.render();

  // Set up live searches
  setupLiveSearch('alert-search',  'alerts', LiveAlerts.render.bind(LiveAlerts), 'alerts-table-body');
  setupLiveSearch('ioc-search',    'iocs',   LiveIOCs.render.bind(LiveIOCs),     'iocs-table-body');

  console.info('[LiveData] Ready');
}

/* ════════════════════════════════════════════
   EXPOSE GLOBALS
═════════════════════════════════════════════ */
window.LiveCache      = LiveCache;
window.DashboardData  = DashboardData;
window.LiveAlerts     = LiveAlerts;
window.LiveIOCs       = LiveIOCs;
window.LiveCases      = LiveCases;
window.LiveCollectors = LiveCollectors;
window.AutoRefresh    = AutoRefresh;
window.initLiveData   = initLiveData;
window.timeAgo        = timeAgo;
window.escapeHtml     = escapeHtml;
