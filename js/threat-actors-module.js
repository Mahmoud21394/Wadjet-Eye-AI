/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Actor Intelligence Module v5.2
 *  js/threat-actors-module.js
 *
 *  PRODUCTION — NO MOCK DATA
 *
 *  Features:
 *  ──────────
 *  • Real-time threat actor list from /api/cti/actors
 *  • Search + filter (country, motivation, sophistication, MITRE technique)
 *  • Clickable actor cards → full detail panel with tabs:
 *      Overview | MITRE ATT&CK | IOCs | Campaigns | Timeline
 *  • IOC pivot: click any actor IOC → goes to IOC Registry
 *  • MITRE technique links → navigate to MITRE Navigator
 *  • Ingest from OTX: pulls real actor data from AlienVault OTX
 *  • Risk score + activity heatmap per actor
 *  • Export actor profile to JSON
 *
 *  Data sources:
 *  ─────────────
 *  Primary:   /api/cti/actors            (Supabase - ingested from OTX/MISP)
 *  IOCs:      /api/iocs?threat_actor=:name
 *  Campaigns: /api/cti/campaigns?actor=:name
 *  MITRE:     /api/cti/mitre?technique=:id
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── Module state ───────────────────────────────────────────────*/
const ThreatActors = {
  list:    [],
  total:   0,
  page:    1,
  limit:   24,
  filters: {
    search:         '',
    motivation:     '',
    origin_country: '',
    sophistication: '',
    active_only:    false,
  },
  selectedActor: null,
  detailTab:     'overview',
  loading:       false,
};

/* ── Helpers ────────────────────────────────────────────────────*/
function _esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _apiGet(path, params) {
  const api = window.WadjetAPI || window._legacyApiGet;
  if (window.WadjetAPI) {
    return window.WadjetAPI.get(path, params).then(r => {
      if (!r.ok) throw new Error(r.error || `HTTP error`);
      return r.data;
    });
  }
  // Legacy fallback
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('we_access_token') || '';
  const qs    = params ? '?' + new URLSearchParams(params).toString() : '';
  return fetch(`${base}/api${path}${qs}`, {
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
  }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}: ${r.url}`)));
}

function _apiPost(path, body) {
  if (window.WadjetAPI) {
    return window.WadjetAPI.post(path, body).then(r => {
      if (!r.ok) throw new Error(r.error || `HTTP error`);
      return r.data;
    });
  }
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('we_access_token') || '';
  return fetch(`${base}/api${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)));
}

function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)     return `${s}s ago`;
  if (s < 3600)   return `${Math.floor(s/60)}m ago`;
  if (s < 86400)  return `${Math.floor(s/3600)}h ago`;
  if (s < 86400*30) return `${Math.floor(s/86400)}d ago`;
  return `${Math.floor(s/86400/30)}mo ago`;
}

function _sevColor(level) {
  const m = { critical:'#ff4757', high:'#ff6b35', medium:'#ffa502', low:'#2ed573', unknown:'#636e72' };
  return m[(level||'unknown').toLowerCase()] || '#636e72';
}

function _sophColor(level) {
  const m = {
    'nation-state': '#ff4757', 'advanced': '#ff6b35',
    'high': '#ff6b35', 'medium': '#ffa502',
    'intermediate': '#ffa502', 'low': '#2ed573', 'novice': '#2ed573',
  };
  return m[(level||'').toLowerCase()] || '#636e72';
}

function _motivationIcon(m) {
  const icons = {
    'espionage': '🕵️', 'financial': '💰', 'sabotage': '💣',
    'hacktivism': '✊', 'cyber-crime': '🦹', 'ransomware': '🔐',
    'data-theft': '📂', 'disruption': '⚡', 'unknown': '❓',
  };
  const key = (m||'').toLowerCase();
  for (const [k, v] of Object.entries(icons)) {
    if (key.includes(k)) return v;
  }
  return '⚡';
}

/* ════════════════════════════════════════════════════════════════
   MAIN RENDER: Threat Actors Dashboard
════════════════════════════════════════════════════════════════ */
async function renderThreatActorsDashboard(opts = {}) {
  // Support being called from main.js page router
  const container = document.getElementById('threatActorsContainer')
    || document.getElementById('actorsContainer')
    || document.getElementById('page-threat-actors');

  if (!container) {
    console.warn('[ThreatActors] Container not found');
    return;
  }

  ThreatActors.page    = opts.page    || 1;
  ThreatActors.filters = { ...ThreatActors.filters, ...(opts.filters || {}) };
  ThreatActors.loading = true;

  // Initial skeleton
  container.innerHTML = _renderDashboardShell();

  try {
    // Build query params
    const params = {
      page:  ThreatActors.page,
      limit: ThreatActors.limit,
    };
    if (ThreatActors.filters.search)         params.search         = ThreatActors.filters.search;
    if (ThreatActors.filters.motivation)     params.motivation     = ThreatActors.filters.motivation;
    if (ThreatActors.filters.origin_country) params.origin_country = ThreatActors.filters.origin_country;
    if (ThreatActors.filters.sophistication) params.sophistication = ThreatActors.filters.sophistication;

    const result = await _apiGet('/cti/actors', params);
    const actors = result?.data || (Array.isArray(result) ? result : []);
    const total  = result?.total || result?.count || actors.length;

    ThreatActors.list  = actors;
    ThreatActors.total = total;

    if (!actors.length) {
      _renderEmptyState(container);
      return;
    }

    // Update dashboard with real data
    _renderDashboardContent(container, actors, total);

  } catch (err) {
    console.error('[ThreatActors] Load error:', err.message);
    _renderErrorState(container, err.message);
  } finally {
    ThreatActors.loading = false;
  }
}

/* ── Dashboard shell with filters ──────────────────────────────*/
function _renderDashboardShell() {
  return `
    <div id="ta-root" style="height:100%;display:flex;flex-direction:column;overflow:hidden;background:#0d1117">
      <!-- Header -->
      <div style="padding:20px 20px 0;flex-shrink:0">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
          <div>
            <h2 style="margin:0;font-size:1.4em;color:#e6edf3;display:flex;align-items:center;gap:10px">
              <span style="font-size:1.2em">🕵️</span> Threat Actor Intelligence
            </h2>
            <p id="ta-subtitle" style="margin:4px 0 0;color:#8b949e;font-size:.85em">
              Loading threat actors from intelligence feeds…
            </p>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button onclick="window._taIngestOTX()" id="ta-ingest-btn"
              style="padding:7px 14px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.82em;display:flex;align-items:center;gap:6px">
              <i class="fas fa-sync-alt"></i> Sync OTX Actors
            </button>
            <button onclick="window._taExportAll()"
              style="padding:7px 14px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.82em">
              <i class="fas fa-download"></i> Export
            </button>
          </div>
        </div>

        <!-- KPI Bar -->
        <div id="ta-kpi" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
          ${['Total Actors','Nation-State','Ransomware Groups','Active (30d)'].map(l =>
            `<div style="flex:1;min-width:110px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 12px">
              <div style="font-size:1.3em;font-weight:700;color:#58a6ff" id="ta-kpi-${l.replace(/\W+/g,'-').toLowerCase()}">—</div>
              <div style="font-size:.72em;color:#8b949e;margin-top:2px">${l}</div>
            </div>`
          ).join('')}
        </div>

        <!-- Filters -->
        <div style="display:flex;gap:8px;flex-wrap:wrap;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;margin-bottom:14px">
          <input id="ta-search" type="text" placeholder="🔍 Search actor name, aliases, malware…"
            style="flex:2;min-width:200px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 12px;font-size:.88em"
            oninput="window._taSearch(this.value)" value="${_esc(ThreatActors.filters.search)}" />

          <select onchange="window._taFilter('motivation', this.value)"
            style="flex:1;min-width:140px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
            <option value="">All Motivations</option>
            <option>espionage</option><option>financial</option><option>sabotage</option>
            <option>hacktivism</option><option>cyber-crime</option><option>ransomware</option>
          </select>

          <select id="ta-country-filter" onchange="window._taFilter('origin_country', this.value)"
            style="flex:1;min-width:130px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
            <option value="">All Countries</option>
          </select>

          <select onchange="window._taFilter('sophistication', this.value)"
            style="flex:1;min-width:140px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
            <option value="">All Sophistication</option>
            <option>nation-state</option><option>advanced</option><option>intermediate</option><option>low</option>
          </select>

          <label style="display:flex;align-items:center;gap:6px;color:#8b949e;font-size:.85em;cursor:pointer">
            <input type="checkbox" onchange="window._taFilter('active_only', this.checked)"
              ${ThreatActors.filters.active_only ? 'checked' : ''}
              style="accent-color:#1d6ae5" />
            Active only
          </label>
        </div>
      </div>

      <!-- Content area -->
      <div id="ta-content" style="flex:1;overflow-y:auto;padding:0 20px 20px">
        <!-- Grid skeleton -->
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
          ${[1,2,3,4,5,6].map(() => `
            <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px;animation:shimmer 1.5s infinite">
              <div style="height:18px;background:#21262d;border-radius:4px;margin-bottom:12px;width:70%"></div>
              <div style="height:13px;background:#21262d;border-radius:4px;margin-bottom:8px"></div>
              <div style="height:13px;background:#21262d;border-radius:4px;width:80%"></div>
            </div>`).join('')}
        </div>
      </div>
    </div>`;
}

/* ── Render actors grid ─────────────────────────────────────────*/
function _renderDashboardContent(container, actors, total) {
  // Update subtitle
  const subtitle = container.querySelector('#ta-subtitle');
  if (subtitle) {
    subtitle.textContent = `${total.toLocaleString()} threat actor${total !== 1 ? 's' : ''} tracked across intelligence feeds`;
  }

  // Update KPIs
  const nationState  = actors.filter(a => (a.sophistication || '').toLowerCase().includes('nation')).length;
  const ransomware   = actors.filter(a => (a.motivation || '').toLowerCase().includes('ransom') || (a.tags || []).includes('ransomware')).length;
  const recent30d    = actors.filter(a => a.last_seen && (Date.now() - new Date(a.last_seen)) < 30 * 86400000).length;

  const setKPI = (id, val) => {
    const el = container.querySelector(`#ta-kpi-${id}`);
    if (el) el.textContent = val;
  };
  setKPI('total-actors', total);
  setKPI('nation-state', nationState);
  setKPI('ransomware-groups', ransomware);
  setKPI('active-30d', recent30d);

  // Populate country filter
  const countries = [...new Set(actors.map(a => a.origin_country).filter(Boolean))].sort();
  const countrySelect = container.querySelector('#ta-country-filter');
  if (countrySelect && countrySelect.options.length <= 1) {
    for (const c of countries) {
      const opt = document.createElement('option');
      opt.value = c;
      opt.textContent = c;
      countrySelect.appendChild(opt);
    }
  }

  // Render grid
  const content = container.querySelector('#ta-content');
  if (!content) return;

  const totalPages = Math.ceil(total / ThreatActors.limit);

  content.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:20px" id="ta-grid">
      ${actors.map(actor => _renderActorCard(actor)).join('')}
    </div>
    ${total > ThreatActors.limit ? `
      <div style="display:flex;justify-content:center;align-items:center;gap:12px;padding:16px 0">
        ${ThreatActors.page > 1 ?
          `<button onclick="window._taPage(${ThreatActors.page - 1})"
            style="padding:6px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
            ← Previous
          </button>` : ''}
        <span style="color:#8b949e;font-size:.85em">Page ${ThreatActors.page} of ${totalPages}</span>
        ${ThreatActors.page < totalPages ?
          `<button onclick="window._taPage(${ThreatActors.page + 1})"
            style="padding:6px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
            Next →
          </button>` : ''}
      </div>` : ''}`;
}

/* ── Actor card ─────────────────────────────────────────────────*/
function _renderActorCard(actor) {
  const sophColor   = _sophColor(actor.sophistication);
  const motiveIcon  = _motivationIcon(actor.motivation);
  const isActive    = actor.last_seen && (Date.now() - new Date(actor.last_seen)) < 30 * 86400000;
  const riskScore   = actor.confidence || 50;

  const techniques  = (actor.ttps || actor.mitre_techniques || []).slice(0, 4);
  const malware     = (actor.malware || actor.malware_families || []).slice(0, 3);
  const aliases     = (actor.aliases || []).slice(0, 2);

  return `
    <div class="ta-card" data-actor-id="${_esc(actor.id)}"
      onclick="window._taOpenDetail('${_esc(actor.id)}')"
      style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px;cursor:pointer;
             transition:all 0.2s;position:relative;overflow:hidden"
      onmouseover="this.style.borderColor='#3b82f6';this.style.transform='translateY(-2px)';this.style.boxShadow='0 8px 24px rgba(59,130,246,0.15)'"
      onmouseout="this.style.borderColor='#21262d';this.style.transform='none';this.style.boxShadow='none'">

      <!-- Active indicator -->
      ${isActive ? `<div style="position:absolute;top:12px;right:12px;width:8px;height:8px;border-radius:50%;background:#2ed573;box-shadow:0 0 6px #2ed573" title="Active in last 30 days"></div>` : ''}

      <!-- Header row -->
      <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
        <div style="width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,${sophColor}33,${sophColor}11);
                    border:1px solid ${sophColor}44;display:flex;align-items:center;justify-content:center;font-size:1.4em;flex-shrink:0">
          ${motiveIcon}
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;color:#e6edf3;font-size:.95em;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${_esc(actor.name)}
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${actor.origin_country ? `<span style="font-size:.7em;color:#8b949e">🌐 ${_esc(actor.origin_country)}</span>` : ''}
            ${actor.sophistication ? `
              <span style="background:${sophColor}22;color:${sophColor};border:1px solid ${sophColor}44;
                    padding:1px 6px;border-radius:3px;font-size:.7em;font-weight:600">
                ${_esc(actor.sophistication)}
              </span>` : ''}
          </div>
        </div>
      </div>

      <!-- Aliases -->
      ${aliases.length ? `
        <div style="margin-bottom:8px;font-size:.75em;color:#8b949e">
          Also known as: <span style="color:#58a6ff">${aliases.map(_esc).join(', ')}</span>
          ${(actor.aliases||[]).length > 2 ? `<span style="color:#8b949e">+${(actor.aliases||[]).length - 2} more</span>` : ''}
        </div>` : ''}

      <!-- Description -->
      ${actor.description ? `
        <p style="font-size:.8em;color:#8b949e;margin:0 0 10px;line-height:1.5;
                  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden">
          ${_esc(actor.description)}
        </p>` : ''}

      <!-- Motivation + Target sectors -->
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
        ${actor.motivation ? `
          <span style="background:#1f2937;color:#f3f4f6;padding:2px 8px;border-radius:12px;font-size:.72em">
            ${motiveIcon} ${_esc(actor.motivation)}
          </span>` : ''}
        ${(actor.target_sectors || []).slice(0, 2).map(s => `
          <span style="background:#1f2937;color:#9ca3af;padding:2px 8px;border-radius:12px;font-size:.72em">
            ${_esc(s)}
          </span>`).join('')}
      </div>

      <!-- MITRE techniques preview -->
      ${techniques.length ? `
        <div style="margin-bottom:10px">
          <div style="font-size:.7em;color:#6e7681;margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">
            MITRE ATT&CK
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${techniques.map(t => `
              <span style="background:#1a1f2e;color:#a78bfa;border:1px solid #4c1d9544;
                    padding:1px 6px;border-radius:3px;font-size:.7em;font-family:monospace">
                ${_esc(t)}
              </span>`).join('')}
            ${(actor.ttps||actor.mitre_techniques||[]).length > 4 ?
              `<span style="color:#6e7681;font-size:.7em">+${(actor.ttps||actor.mitre_techniques||[]).length - 4}</span>` : ''}
          </div>
        </div>` : ''}

      <!-- Malware families -->
      ${malware.length ? `
        <div style="margin-bottom:10px">
          <div style="font-size:.7em;color:#6e7681;margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">
            Malware
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${malware.map(m => `
              <span style="background:#1a0a0a;color:#ff6b6b;border:1px solid #ff4d4d33;
                    padding:1px 7px;border-radius:3px;font-size:.72em">
                ${_esc(m)}
              </span>`).join('')}
          </div>
        </div>` : ''}

      <!-- Footer -->
      <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid #21262d;padding-top:10px;margin-top:4px">
        <div style="font-size:.72em;color:#6e7681">
          ${actor.last_seen ? `Last seen: ${_ago(actor.last_seen)}` : (actor.active_since ? `Active since: ${_ago(actor.active_since)}` : 'No date info')}
        </div>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:36px;height:5px;background:#21262d;border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${riskScore}%;background:linear-gradient(90deg,${_sevColor(riskScore>=70?'high':'medium')},${_sevColor(riskScore>=70?'critical':'high')});border-radius:3px"></div>
          </div>
          <span style="font-size:.7em;color:#8b949e">${riskScore}%</span>
        </div>
      </div>
    </div>`;
}

/* ── Empty state ────────────────────────────────────────────────*/
function _renderEmptyState(container) {
  const content = container.querySelector('#ta-content');
  if (!content) return;

  content.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 20px;text-align:center">
      <div style="font-size:4em;margin-bottom:16px">🕵️</div>
      <h3 style="color:#c9d1d9;margin:0 0 8px;font-size:1.1em">No Threat Actors Found</h3>
      <p style="color:#8b949e;margin:0 0 20px;max-width:400px;font-size:.9em;line-height:1.5">
        Threat actors are ingested from AlienVault OTX, MISP, and other intelligence feeds.
        Sync from OTX to populate real actor profiles.
      </p>
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center">
        <button onclick="window._taIngestOTX()"
          style="padding:10px 20px;background:#1d6ae5;border:none;color:#fff;border-radius:6px;cursor:pointer;font-size:.9em">
          🔄 Sync from OTX
        </button>
        <button onclick="window._taCreateManual()"
          style="padding:10px 20px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.9em">
          ➕ Add Actor Manually
        </button>
      </div>
    </div>`;
}

/* ── Error state ────────────────────────────────────────────────*/
function _renderErrorState(container, errMsg) {
  const content = container.querySelector('#ta-content') || container;
  const isAuth  = errMsg.includes('401') || errMsg.includes('auth') || errMsg.includes('token') || errMsg.includes('unauthorized');

  content.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 20px;text-align:center">
      <div style="font-size:3em;margin-bottom:12px">${isAuth ? '🔑' : '⚠️'}</div>
      <h3 style="color:#f85149;margin:0 0 8px">${isAuth ? 'Authentication Required' : 'Failed to Load Actors'}</h3>
      <p style="color:#8b949e;margin:0 0 16px;max-width:440px;font-size:.88em;line-height:1.5">
        ${isAuth
          ? 'Your session may have expired. The token refresh will be attempted automatically. If this persists, please log in again.'
          : _esc(errMsg)}
      </p>
      ${isAuth ? `
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:.82em;color:#8b949e;text-align:left;max-width:440px">
          <strong style="color:#f0f6fc">Troubleshooting:</strong><br>
          1. Check backend is online: <a href="https://wadjet-eye-ai.onrender.com/health" target="_blank" style="color:#58a6ff">health endpoint</a><br>
          2. Verify JWT_SECRET in backend/.env matches Supabase<br>
          3. Check API key storage: DevTools → Application → Local Storage
        </div>` : ''}
      <button onclick="window.renderThreatActors()"
        style="padding:9px 20px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.88em">
        🔄 Retry
      </button>
    </div>`;
}

/* ════════════════════════════════════════════════════════════════
   ACTOR DETAIL PANEL (slide-in from right)
════════════════════════════════════════════════════════════════ */
async function openActorDetail(actorId) {
  ThreatActors.selectedActor = actorId;
  ThreatActors.detailTab     = 'overview';

  // Create or get panel
  let panel = document.getElementById('ta-detail-panel');
  if (!panel) {
    panel = document.createElement('div');
    panel.id = 'ta-detail-panel';
    panel.style.cssText = `
      position:fixed;top:0;right:-100%;width:min(720px,100vw);height:100vh;
      background:#0d1117;border-left:1px solid #21262d;z-index:10000;
      display:flex;flex-direction:column;overflow:hidden;
      transition:right 0.3s cubic-bezier(0.4,0,0.2,1);
      box-shadow:-8px 0 40px rgba(0,0,0,0.6)`;
    document.body.appendChild(panel);
  }

  // Show loading state first
  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:20px;border-bottom:1px solid #21262d;flex-shrink:0">
      <div style="height:20px;background:#21262d;border-radius:4px;width:200px;animation:shimmer 1.5s infinite"></div>
      <button onclick="window._taCloseDetail()" style="background:none;border:none;color:#8b949e;font-size:1.5em;cursor:pointer;padding:4px">✕</button>
    </div>
    <div style="flex:1;display:flex;align-items:center;justify-content:center;color:#8b949e">
      <div style="text-align:center">
        <div style="font-size:2em;margin-bottom:8px">⏳</div>
        <div>Loading actor profile…</div>
      </div>
    </div>`;

  // Slide in
  setTimeout(() => { panel.style.right = '0'; }, 10);

  // Add backdrop
  let backdrop = document.getElementById('ta-backdrop');
  if (!backdrop) {
    backdrop = document.createElement('div');
    backdrop.id = 'ta-backdrop';
    backdrop.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;cursor:pointer';
    backdrop.onclick = () => window._taCloseDetail();
    document.body.appendChild(backdrop);
  }
  backdrop.style.display = '';

  try {
    const actor = await _apiGet(`/cti/actors/${actorId}`);
    const data  = actor?.data || actor;
    if (!data || !data.id) throw new Error('Actor not found');

    // Load parallel data
    const [iocResult, campaignResult] = await Promise.allSettled([
      _apiGet('/iocs', { threat_actor: data.name, limit: 50 }),
      _apiGet('/cti/campaigns', { actor: data.name, limit: 20 }),
    ]);

    const iocs      = iocResult.status === 'fulfilled' ? (iocResult.value?.data || []) : [];
    const campaigns = campaignResult.status === 'fulfilled' ? (campaignResult.value?.data || []) : [];

    _renderDetailPanel(panel, data, iocs, campaigns);

  } catch (err) {
    console.error('[ThreatActors] Detail load error:', err.message);
    // Try finding actor in local cache
    const cached = ThreatActors.list.find(a => a.id === actorId);
    if (cached) {
      _renderDetailPanel(panel, cached, [], []);
    } else {
      panel.innerHTML = `
        <div style="padding:20px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #21262d">
          <h3 style="margin:0;color:#f85149">Failed to load actor</h3>
          <button onclick="window._taCloseDetail()" style="background:none;border:none;color:#8b949e;font-size:1.5em;cursor:pointer">✕</button>
        </div>
        <div style="padding:20px;color:#8b949e">
          <p>Error: ${_esc(err.message)}</p>
          <button onclick="window._taOpenDetail('${_esc(actorId)}')" style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer">
            Retry
          </button>
        </div>`;
    }
  }
}

/* ── Render detail panel content ───────────────────────────────*/
function _renderDetailPanel(panel, actor, iocs, campaigns) {
  const sophColor  = _sophColor(actor.sophistication);
  const motiveIcon = _motivationIcon(actor.motivation);
  const techniques = actor.ttps || actor.mitre_techniques || [];
  const malware    = actor.malware || actor.malware_families || [];
  const aliases    = actor.aliases || [];
  const tools      = actor.tools || [];

  panel.innerHTML = `
    <!-- Panel Header -->
    <div style="padding:20px;border-bottom:1px solid #21262d;flex-shrink:0">
      <div style="display:flex;align-items:flex-start;gap:14px">
        <div style="width:50px;height:50px;border-radius:12px;background:linear-gradient(135deg,${sophColor}44,${sophColor}11);
                    border:1px solid ${sophColor}55;display:flex;align-items:center;justify-content:center;font-size:1.6em;flex-shrink:0">
          ${motiveIcon}
        </div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
            <h2 style="margin:0;font-size:1.15em;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              ${_esc(actor.name)}
            </h2>
            <button onclick="window._taCloseDetail()"
              style="background:none;border:none;color:#8b949e;font-size:1.4em;cursor:pointer;padding:2px;flex-shrink:0;line-height:1">
              ✕
            </button>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
            ${actor.origin_country ? `<span style="font-size:.75em;color:#8b949e">🌐 ${_esc(actor.origin_country)}</span>` : ''}
            ${actor.sophistication ? `
              <span style="background:${sophColor}22;color:${sophColor};border:1px solid ${sophColor}44;
                    padding:1px 8px;border-radius:3px;font-size:.75em;font-weight:600">
                ${_esc(actor.sophistication)}
              </span>` : ''}
            ${actor.motivation ? `
              <span style="background:#1f2937;color:#d1d5db;padding:1px 8px;border-radius:3px;font-size:.75em">
                ${_esc(actor.motivation)}
              </span>` : ''}
            ${aliases.slice(0, 3).map(a => `
              <span style="background:#1f2937;color:#9ca3af;padding:1px 7px;border-radius:3px;font-size:.72em">
                ${_esc(a)}
              </span>`).join('')}
          </div>
        </div>
      </div>

      <!-- Quick stats row -->
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px">
        ${[
          { label: 'IOCs',       value: iocs.length,      color: '#ff6b6b' },
          { label: 'Techniques', value: techniques.length, color: '#a78bfa' },
          { label: 'Campaigns',  value: campaigns.length,  color: '#34d399' },
          { label: 'Confidence', value: `${actor.confidence || 50}%`, color: '#58a6ff' },
        ].map(s => `
          <div style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:8px;text-align:center">
            <div style="font-size:1.15em;font-weight:700;color:${s.color}">${s.value}</div>
            <div style="font-size:.68em;color:#6e7681;margin-top:2px">${s.label}</div>
          </div>`).join('')}
      </div>

      <!-- Tab bar -->
      <div id="ta-tab-bar" style="display:flex;gap:0;margin-top:14px;border-bottom:2px solid #21262d">
        ${['overview','mitre','iocs','campaigns','timeline'].map(tab => `
          <button onclick="window._taTab('${tab}','${_esc(actor.id)}')"
            id="ta-tab-${tab}"
            style="padding:8px 14px;background:none;border:none;color:${ThreatActors.detailTab===tab?'#58a6ff':'#8b949e'};
                   font-size:.82em;cursor:pointer;border-bottom:2px solid ${ThreatActors.detailTab===tab?'#58a6ff':'transparent'};
                   margin-bottom:-2px;transition:color 0.15s;font-weight:${ThreatActors.detailTab===tab?'600':'400'}">
            ${{overview:'📋 Overview', mitre:'🎯 MITRE ATT&CK', iocs:'☣️ IOCs', campaigns:'🗂️ Campaigns', timeline:'📅 Timeline'}[tab]}
          </button>`).join('')}
      </div>
    </div>

    <!-- Tab content -->
    <div id="ta-detail-content" style="flex:1;overflow-y:auto;padding:20px">
      ${_renderTabContent(ThreatActors.detailTab, actor, iocs, campaigns)}
    </div>

    <!-- Action footer -->
    <div style="padding:14px 20px;border-top:1px solid #21262d;display:flex;gap:8px;flex-wrap:wrap;flex-shrink:0;background:#0d1117">
      <button onclick="window._taCreateCase('${_esc(actor.id)}','${_esc(actor.name)}')"
        style="padding:7px 14px;background:#1d6ae5;border:none;color:#fff;border-radius:6px;cursor:pointer;font-size:.82em">
        📁 Create Investigation
      </button>
      <button onclick="window._taHuntIOCs('${_esc(actor.name)}')"
        style="padding:7px 14px;background:#1f2937;border:1px solid #374151;color:#d1d5db;border-radius:6px;cursor:pointer;font-size:.82em">
        🔍 Hunt IOCs
      </button>
      <button onclick="window._taRunSOAR('${_esc(actor.id)}')"
        style="padding:7px 14px;background:#1f2937;border:1px solid #374151;color:#d1d5db;border-radius:6px;cursor:pointer;font-size:.82em">
        ⚡ SOAR Response
      </button>
      <button onclick="window._taExportActor('${_esc(actor.id)}')"
        style="padding:7px 14px;background:#1f2937;border:1px solid #374151;color:#d1d5db;border-radius:6px;cursor:pointer;font-size:.82em;margin-left:auto">
        ↓ Export JSON
      </button>
    </div>`;

  // Store actor data on panel for tab switching
  panel._actorData     = actor;
  panel._actorIOCs     = iocs;
  panel._actorCampaigns = campaigns;
}

/* ── Tab content renderer ───────────────────────────────────────*/
function _renderTabContent(tab, actor, iocs, campaigns) {
  switch (tab) {
    case 'overview':  return _tabOverview(actor);
    case 'mitre':     return _tabMITRE(actor);
    case 'iocs':      return _tabIOCs(actor, iocs);
    case 'campaigns': return _tabCampaigns(actor, campaigns);
    case 'timeline':  return _tabTimeline(actor);
    default:          return _tabOverview(actor);
  }
}

/* ── Tab: Overview ──────────────────────────────────────────────*/
function _tabOverview(actor) {
  const tools   = actor.tools || [];
  const targets = (actor.target_sectors || []).concat(actor.target_countries || []);

  return `
    <!-- Description -->
    ${actor.description ? `
      <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px">
        <div style="font-size:.75em;color:#6e7681;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          Description
        </div>
        <p style="margin:0;color:#c9d1d9;font-size:.9em;line-height:1.7">${_esc(actor.description)}</p>
      </div>` : ''}

    <!-- Info grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
      ${[
        { label: 'Origin Country',  value: actor.origin_country || '—',       icon: '🌐' },
        { label: 'Motivation',      value: actor.motivation || '—',             icon: '⚡' },
        { label: 'Sophistication',  value: actor.sophistication || '—',         icon: '🎓' },
        { label: 'Active Since',    value: actor.active_since || '—',           icon: '📅' },
        { label: 'Last Activity',   value: actor.last_seen ? _ago(actor.last_seen) : '—', icon: '🕐' },
        { label: 'Intelligence Source', value: actor.source || actor.external_source || '—', icon: '📡' },
        { label: 'External ID',     value: actor.external_id || '—',           icon: '🔗' },
        { label: 'Confidence',      value: `${actor.confidence || 50}%`,        icon: '📊' },
      ].map(f => `
        <div style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 12px">
          <div style="font-size:.7em;color:#6e7681;margin-bottom:4px">${f.icon} ${_esc(f.label)}</div>
          <div style="font-size:.88em;color:#e6edf3;font-weight:500">${_esc(String(f.value))}</div>
        </div>`).join('')}
    </div>

    <!-- Target sectors -->
    ${targets.length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.75em;color:#6e7681;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          🎯 Target Sectors & Countries
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${targets.map(t => `
            <span style="background:#1f2937;color:#d1d5db;padding:3px 10px;border-radius:12px;font-size:.78em">
              ${_esc(t)}
            </span>`).join('')}
        </div>
      </div>` : ''}

    <!-- Tools used -->
    ${tools.length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.75em;color:#6e7681;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          🔧 Tools & Infrastructure
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${tools.map(t => `
            <span style="background:#1a2033;color:#93c5fd;border:1px solid #1d4ed844;padding:2px 10px;border-radius:4px;font-size:.78em">
              ${_esc(t)}
            </span>`).join('')}
        </div>
      </div>` : ''}

    <!-- Malware families -->
    ${(actor.malware || []).length ? `
      <div>
        <div style="font-size:.75em;color:#6e7681;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          🦠 Known Malware
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${(actor.malware || []).map(m => `
            <span style="background:#1a0a0a;color:#ff6b6b;border:1px solid #ff4d4d33;padding:2px 10px;border-radius:4px;font-size:.78em">
              ${_esc(m)}
            </span>`).join('')}
        </div>
      </div>` : ''}`;
}

/* ── Tab: MITRE ATT&CK ──────────────────────────────────────────*/
function _tabMITRE(actor) {
  const techniques = actor.ttps || actor.mitre_techniques || [];

  if (!techniques.length) {
    return `
      <div style="text-align:center;padding:40px 20px;color:#8b949e">
        <div style="font-size:2.5em;margin-bottom:12px">🎯</div>
        <p>No MITRE ATT&CK techniques mapped for this actor yet.</p>
        <a href="https://attack.mitre.org" target="_blank" rel="noopener" style="color:#58a6ff;font-size:.88em">
          Browse MITRE ATT&CK Framework →
        </a>
      </div>`;
  }

  // Group by tactic (extract from technique ID prefix)
  const tacticGroups = {};
  for (const ttp of techniques) {
    const match = String(ttp).match(/^T(\d{4})/);
    const tacId = match ? match[1] : 'other';
    const tactic = _techToTactic(ttp);
    if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
    tacticGroups[tactic].push(ttp);
  }

  return `
    <div style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <div style="font-size:.85em;color:#8b949e">${techniques.length} techniques mapped</div>
        <a href="https://attack.mitre.org" target="_blank" rel="noopener"
          style="font-size:.8em;color:#58a6ff;margin-left:auto;text-decoration:none">
          View on MITRE →
        </a>
      </div>
      ${Object.entries(tacticGroups).map(([tactic, ttps]) => `
        <div style="margin-bottom:14px">
          <div style="font-size:.78em;color:#f3f4f6;font-weight:600;margin-bottom:8px;
                      background:#1f2937;display:inline-block;padding:3px 10px;border-radius:4px">
            ${_esc(tactic)}
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${ttps.map(ttp => `
              <a href="https://attack.mitre.org/techniques/${_esc(ttp.replace('.','/'))}/"
                target="_blank" rel="noopener" style="text-decoration:none">
                <span style="background:#1a1f2e;color:#a78bfa;border:1px solid #4c1d9544;
                      padding:4px 10px;border-radius:4px;font-size:.78em;font-family:monospace;
                      cursor:pointer;transition:background 0.15s"
                  onmouseover="this.style.background='#2d1f6e'" onmouseout="this.style.background='#1a1f2e'">
                  ${_esc(ttp)}
                </span>
              </a>`).join('')}
          </div>
        </div>`).join('')}
    </div>`;
}

function _techToTactic(techId) {
  const id = parseInt(String(techId).replace(/^T/, ''));
  if (id < 1100) return 'Reconnaissance';
  if (id < 1200) return 'Resource Development';
  if (id < 1300) return 'Initial Access';
  if (id < 1400) return 'Execution';
  if (id < 1500) return 'Persistence';
  if (id < 1600) return 'Privilege Escalation';
  if (id < 1700) return 'Defense Evasion';
  if (id < 1800) return 'Credential Access';
  if (id < 1900) return 'Discovery';
  if (id < 2000) return 'Lateral Movement';
  if (id < 2100) return 'Collection';
  if (id < 2200) return 'Command and Control';
  if (id < 2400) return 'Exfiltration';
  return 'Impact';
}

/* ── Tab: IOCs ──────────────────────────────────────────────────*/
function _tabIOCs(actor, iocs) {
  if (!iocs.length) {
    return `
      <div style="text-align:center;padding:40px 20px;color:#8b949e">
        <div style="font-size:2.5em;margin-bottom:12px">☣️</div>
        <p>No IOCs currently associated with ${_esc(actor.name)}.</p>
        <button onclick="window._taHuntIOCs('${_esc(actor.name)}')"
          style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;margin-top:8px">
          Search IOC Registry
        </button>
      </div>`;
  }

  const typeColors = {
    ip: '#22d3ee', domain: '#a78bfa', url: '#34d399',
    md5: '#fbbf24', sha256: '#f59e0b', sha1: '#fb923c',
    email: '#e879f9', hostname: '#67e8f9',
  };

  return `
    <div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <div style="font-size:.85em;color:#8b949e">${iocs.length} indicators associated</div>
        <button onclick="window._taHuntIOCs('${_esc(actor.name)}')"
          style="font-size:.78em;color:#58a6ff;background:none;border:none;cursor:pointer">
          View All in IOC Registry →
        </button>
      </div>

      <!-- Type breakdown -->
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">
        ${Object.entries(
          iocs.reduce((acc, ioc) => { acc[ioc.type] = (acc[ioc.type]||0)+1; return acc; }, {})
        ).map(([type, count]) => `
          <span style="background:${typeColors[type]||'#8b949e'}22;color:${typeColors[type]||'#8b949e'};
                border:1px solid ${typeColors[type]||'#8b949e'}44;padding:2px 10px;border-radius:4px;font-size:.75em">
            ${_esc(type)}: ${count}
          </span>`).join('')}
      </div>

      <!-- IOC list -->
      <div style="display:flex;flex-direction:column;gap:4px">
        ${iocs.slice(0, 50).map(ioc => `
          <div style="display:flex;align-items:center;gap:10px;background:#161b22;border:1px solid #21262d;
                      border-radius:6px;padding:8px 12px;font-size:.82em">
            <span style="background:${typeColors[ioc.type]||'#8b949e'}22;color:${typeColors[ioc.type]||'#8b949e'};
                  padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;text-transform:uppercase;
                  flex-shrink:0;min-width:56px;text-align:center">
              ${_esc(ioc.type||'?')}
            </span>
            <span style="flex:1;font-family:monospace;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              ${_esc(ioc.value)}
            </span>
            <span style="color:${ioc.risk_score>=70?'#ff4444':ioc.risk_score>=40?'#ff8800':'#2ed573'};
                  font-weight:700;flex-shrink:0">
              ${ioc.risk_score||0}
            </span>
            <span style="color:#6e7681;flex-shrink:0;font-size:.75em">
              ${_ago(ioc.last_seen)}
            </span>
          </div>`).join('')}
        ${iocs.length > 50 ? `<div style="text-align:center;color:#8b949e;font-size:.82em;padding:8px">
          … and ${iocs.length - 50} more. <a href="#" onclick="window._taHuntIOCs('${_esc(actor.name)}');return false" style="color:#58a6ff">View all →</a>
        </div>` : ''}
      </div>
    </div>`;
}

/* ── Tab: Campaigns ─────────────────────────────────────────────*/
function _tabCampaigns(actor, campaigns) {
  if (!campaigns.length) {
    return `
      <div style="text-align:center;padding:40px 20px;color:#8b949e">
        <div style="font-size:2.5em;margin-bottom:12px">🗂️</div>
        <p>No campaigns currently linked to ${_esc(actor.name)}.</p>
      </div>`;
  }

  return `
    <div style="display:flex;flex-direction:column;gap:10px">
      ${campaigns.map(c => `
        <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px;cursor:pointer"
          onclick="window._openCampaignDetail && window._openCampaignDetail('${_esc(c.id)}')"
          onmouseover="this.style.borderColor='#58a6ff'" onmouseout="this.style.borderColor='#21262d'">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:6px">
            <div style="font-weight:600;color:#e6edf3;font-size:.9em">${_esc(c.name)}</div>
            <span style="background:${_sevColor(c.severity)}22;color:${_sevColor(c.severity)};
                  border:1px solid ${_sevColor(c.severity)}44;padding:1px 8px;border-radius:3px;
                  font-size:.72em;font-weight:600;flex-shrink:0">
              ${_esc(c.severity||'unknown')}
            </span>
          </div>
          ${c.description ? `<p style="margin:0 0 8px;color:#8b949e;font-size:.82em;line-height:1.4">${_esc(c.description.slice(0,120))}…</p>` : ''}
          <div style="display:flex;gap:12px;font-size:.75em;color:#6e7681">
            <span>📦 ${c.findings_count || 0} findings</span>
            <span>☣️ ${c.ioc_count || 0} IOCs</span>
            <span>Status: <strong style="color:${c.status==='active'?'#2ed573':'#8b949e'}">${_esc(c.status||'unknown')}</strong></span>
            <span style="margin-left:auto">${_ago(c.updated_at)}</span>
          </div>
        </div>`).join('')}
    </div>`;
}

/* ── Tab: Timeline ──────────────────────────────────────────────*/
function _tabTimeline(actor) {
  const events = actor.timeline || [];

  // Build synthetic timeline from known dates if no explicit timeline
  const syntheticEvents = [];
  if (actor.active_since) {
    syntheticEvents.push({
      date:  actor.active_since,
      type:  'first-observed',
      label: `${actor.name} first observed`,
      icon:  '👁️',
    });
  }
  if (actor.last_seen) {
    syntheticEvents.push({
      date:  actor.last_seen,
      type:  'last-activity',
      label: `Last known activity`,
      icon:  '⚡',
    });
  }

  const allEvents = [...events, ...syntheticEvents]
    .sort((a, b) => new Date(b.date || b.timestamp || 0) - new Date(a.date || a.timestamp || 0));

  if (!allEvents.length) {
    return `
      <div style="text-align:center;padding:40px 20px;color:#8b949e">
        <div style="font-size:2.5em;margin-bottom:12px">📅</div>
        <p>No timeline data available for this actor.</p>
      </div>`;
  }

  return `
    <div style="position:relative;padding-left:20px">
      <!-- Vertical line -->
      <div style="position:absolute;left:8px;top:8px;bottom:0;width:2px;background:#21262d"></div>

      ${allEvents.map((evt, i) => {
        const date  = evt.date || evt.timestamp || evt.ts;
        const label = evt.label || evt.description || evt.event || JSON.stringify(evt);
        const icon  = evt.icon || '📌';
        const type  = evt.type || 'event';
        const typeColor = {
          'first-observed': '#2ed573',
          'last-activity':  '#ffa502',
          'campaign':       '#58a6ff',
          'malware-release':'#ff4444',
          'attribution':    '#a78bfa',
        }[type] || '#58a6ff';

        return `
          <div style="position:relative;padding-left:20px;padding-bottom:18px">
            <!-- Dot -->
            <div style="position:absolute;left:-16px;top:4px;width:10px;height:10px;border-radius:50%;
                        background:${typeColor};border:2px solid #0d1117;z-index:1"></div>
            <!-- Content -->
            <div style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 12px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                <span>${icon}</span>
                <span style="font-size:.85em;color:#e6edf3;font-weight:500">${_esc(label)}</span>
              </div>
              <div style="font-size:.75em;color:#6e7681">
                ${date ? new Date(date).toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }) : 'Unknown date'}
              </div>
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

/* ════════════════════════════════════════════════════════════════
   GLOBAL ACTION HANDLERS
════════════════════════════════════════════════════════════════ */

window._taSearch = _debounce((value) => {
  ThreatActors.filters.search = value;
  ThreatActors.page = 1;
  renderThreatActorsDashboard();
}, 400);

window._taFilter = (key, value) => {
  ThreatActors.filters[key] = value;
  ThreatActors.page = 1;
  renderThreatActorsDashboard();
};

window._taPage = (page) => {
  ThreatActors.page = page;
  renderThreatActorsDashboard();
};

window._taOpenDetail = (id) => openActorDetail(id);

window._taCloseDetail = () => {
  const panel = document.getElementById('ta-detail-panel');
  if (panel) panel.style.right = '-100%';
  const backdrop = document.getElementById('ta-backdrop');
  if (backdrop) backdrop.style.display = 'none';
  ThreatActors.selectedActor = null;
};

window._taTab = (tab, actorId) => {
  ThreatActors.detailTab = tab;

  // Update tab button styles
  ['overview','mitre','iocs','campaigns','timeline'].forEach(t => {
    const btn = document.getElementById(`ta-tab-${t}`);
    if (btn) {
      btn.style.color        = t === tab ? '#58a6ff' : '#8b949e';
      btn.style.borderBottom = t === tab ? '2px solid #58a6ff' : '2px solid transparent';
      btn.style.fontWeight   = t === tab ? '600' : '400';
    }
  });

  const panel = document.getElementById('ta-detail-panel');
  if (!panel || !panel._actorData) return;

  const content = document.getElementById('ta-detail-content');
  if (content) {
    content.innerHTML = _renderTabContent(tab, panel._actorData, panel._actorIOCs || [], panel._actorCampaigns || []);
  }
};

window._taHuntIOCs = (actorName) => {
  window._taCloseDetail();
  if (window.navigateTo) window.navigateTo('ioc-registry');
  setTimeout(() => {
    const search = document.getElementById('ioc-search') || document.getElementById('iocdb-search');
    if (search) { search.value = actorName; search.dispatchEvent(new Event('input')); }
  }, 500);
};

window._taCreateCase = (actorId, actorName) => {
  window._taCloseDetail();
  if (window.navigateTo) window.navigateTo('case-management');
  // Pre-fill case title
  setTimeout(() => {
    const titleInput = document.querySelector('[placeholder*="case title" i],[placeholder*="case name" i]');
    if (titleInput) titleInput.value = `Investigation: ${actorName}`;
  }, 500);
};

window._taRunSOAR = (actorId) => {
  window._taCloseDetail();
  if (window.navigateTo) window.navigateTo('soar');
};

window._taExportActor = async (actorId) => {
  try {
    const data = await _apiGet(`/cti/actors/${actorId}`);
    const actor = data?.data || data;
    const json  = JSON.stringify(actor, null, 2);
    const blob  = new Blob([json], { type: 'application/json' });
    const a     = document.createElement('a');
    a.href      = URL.createObjectURL(blob);
    a.download  = `actor_${actor.name?.replace(/\W+/g, '_')}_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
  } catch (err) {
    console.error('[ThreatActors] Export error:', err.message);
  }
};

window._taExportAll = async () => {
  try {
    const data   = await _apiGet('/cti/actors', { limit: 1000 });
    const actors = data?.data || [];
    const csv    = ['Name,Aliases,Origin,Motivation,Sophistication,Last Seen,Confidence']
      .concat(actors.map(a => [
        a.name, (a.aliases||[]).join('|'), a.origin_country||'',
        a.motivation||'', a.sophistication||'',
        a.last_seen||'', a.confidence||''
      ].map(f => `"${String(f).replace(/"/g,'""')}"`).join(',')))
      .join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `threat_actors_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  } catch (err) {
    console.error('[ThreatActors] Export error:', err.message);
  }
};

window._taCreateManual = () => {
  // Simple manual actor creation dialog
  const name = prompt('Enter threat actor name:');
  if (!name) return;

  _apiPost('/cti/actors', {
    name,
    description: '',
    motivation:  'unknown',
    source:      'manual',
  }).then(() => {
    renderThreatActorsDashboard();
  }).catch(err => {
    alert('Failed to create actor: ' + err.message);
  });
};

window._taIngestOTX = async () => {
  const btn = document.getElementById('ta-ingest-btn');
  if (btn) { btn.textContent = '⏳ Syncing…'; btn.disabled = true; }

  try {
    // Trigger OTX ingestion + CTI actor sync
    const result = await _apiPost('/ingest/run/otx', {});
    const msg = result?.iocs_new
      ? `✓ Synced ${result.iocs_new} new IOCs from OTX`
      : '✓ OTX sync complete';
    console.info('[ThreatActors]', msg);

    // Wait 2s then reload
    setTimeout(() => renderThreatActorsDashboard(), 2000);
  } catch (err) {
    const isAuth = err.message.includes('401') || err.message.includes('403');
    console.error('[ThreatActors] OTX sync error:', err.message);
    alert(isAuth
      ? 'OTX sync requires ADMIN role. Check your permissions.'
      : `Sync failed: ${err.message}`
    );
  } finally {
    if (btn) { btn.textContent = '🔄 Sync OTX Actors'; btn.disabled = false; }
  }
};

/* ── Debounce helper ────────────────────────────────────────────*/
function _debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/* ════════════════════════════════════════════════════════════════
   BACKEND: Threat Actor ingestion from OTX
   backend/routes/cti.js — GET /api/cti/actors/sync-otx
   (called by the Sync OTX button via POST /api/ingest/run/otx)
════════════════════════════════════════════════════════════════ */

/* ── Expose render function globally ────────────────────────────*/
window.renderThreatActors = (opts) =>
  renderThreatActorsDashboard(opts || {})
    .catch(e => console.warn('[ThreatActors] Render error:', e.message));

// Also override the live-pages version
window.renderThreatActorsLive = window.renderThreatActors;

// Auto-register with PAGE_CONFIG if available
if (window.PAGE_CONFIG) {
  window.PAGE_CONFIG['threat-actors'] = window.PAGE_CONFIG['threat-actors'] || {};
  window.PAGE_CONFIG['threat-actors'].onEnter = () => window.renderThreatActors();
}

console.log('[ThreatActors v5.2] Module loaded — real data only');
