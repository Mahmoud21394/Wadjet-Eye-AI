/**
 * ══════════════════════════════════════════════════════════════════
 *  EYEbot AI — Threat Actor Intelligence Module v5.3
 *  js/threat-actors-v2.js
 *
 *  PRODUCTION — 100% Real API Data. No mock data whatsoever.
 *
 *  This file OVERRIDES the legacy renderThreatActors() from pages.js
 *  which used static ARGUS_DATA.actors. It calls:
 *    GET  /api/threat-actors           (list + search/filter)
 *    GET  /api/threat-actors/stats     (KPI bar)
 *    GET  /api/threat-actors/countries (country filter dropdown)
 *    GET  /api/threat-actors/:id       (actor detail)
 *    GET  /api/threat-actors/:id/iocs  (actor's IOCs)
 *    GET  /api/threat-actors/:id/campaigns
 *    GET  /api/threat-actors/:id/timeline
 *    POST /api/threat-actors/ingest/otx   (sync from AlienVault OTX)
 *    POST /api/threat-actors/ingest/mitre (sync from MITRE ATT&CK)
 *
 *  Features:
 *  ──────────
 *  • Real-time actor list with search + filter (country/motivation/sophistication)
 *  • Clickable actor cards → full detail panel with tabs:
 *      Overview | ATT&CK Techniques | IOCs | Campaigns | Timeline
 *  • KPI bar: Total / Nation-State / Ransomware / Active 30d
 *  • "Sync OTX" and "Sync MITRE" ingest buttons
 *  • Risk score visualization
 *  • Country flag / origin display
 *  • Export actor profile as JSON
 *  • Loading skeletons and proper error states
 *  • No freeze: all fetches async, spinner shown during load
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

/* ── Constants ──────────────────────────────────────────────────*/
const API_BASE = () =>
  (global.THREATPILOT_API_URL || global.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');

/* ── Module State ───────────────────────────────────────────────*/
const _TA = {
  list:          [],
  total:         0,
  page:          1,
  limit:         24,
  loading:       false,
  detailLoading: false,
  filters: {
    search:         '',
    motivation:     '',
    origin_country: '',
    sophistication: '',
    active_only:    false,
  },
  selectedId:   null,
  selectedActor: null,
  detailTab:    'overview',
  _debounceTimer: null,
};

/* ── Auth helper ────────────────────────────────────────────────*/
function _token() {
  // Try all known token storage keys
  return localStorage.getItem('wadjet_access_token')
      || localStorage.getItem('we_access_token')
      || localStorage.getItem('tp_access_token')
      || sessionStorage.getItem('wadjet_access_token')
      || sessionStorage.getItem('we_access_token')
      || sessionStorage.getItem('tp_token')
      || (global.getAuthToken && global.getAuthToken())
      || '';
}

/* ── HTTP helpers ───────────────────────────────────────────────*/
async function _get(path, params) {
  const base  = API_BASE();
  const token = _token();
  const qs    = params ? '?' + new URLSearchParams(params).toString() : '';
  const url   = `${base}/api${path}${qs}`;

  let resp = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  // Attempt silent refresh on 401
  if (resp.status === 401 && global.PersistentAuth_silentRefresh) {
    const ok = await global.PersistentAuth_silentRefresh();
    if (ok) {
      const t2 = _token();
      resp = await fetch(url, {
        headers: { 'Content-Type': 'application/json', ...(t2 ? { Authorization: `Bearer ${t2}` } : {}) },
      });
    }
  }

  if (resp.status === 401) throw new Error('Authentication required. Please log in.');
  if (resp.status === 404) return { data: [], total: 0, _notfound: true };
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`HTTP ${resp.status}${body ? ': ' + body.slice(0, 120) : ''}`);
  }
  return resp.json();
}

async function _post(path, body) {
  const base  = API_BASE();
  const token = _token();
  const url   = `${base}/api${path}`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const errBody = await resp.json().catch(() => ({}));
    throw new Error(errBody.error || `HTTP ${resp.status}`);
  }
  return resp.json();
}

/* ── HTML helpers ───────────────────────────────────────────────*/
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)       return `${s}s ago`;
  if (s < 3600)     return `${Math.floor(s/60)}m ago`;
  if (s < 86400)    return `${Math.floor(s/3600)}h ago`;
  if (s < 86400*30) return `${Math.floor(s/86400)}d ago`;
  if (s < 86400*365)return `${Math.floor(s/86400/30)}mo ago`;
  return `${Math.floor(s/86400/365)}y ago`;
}

const MOTIV_ICONS = {
  espionage:'🕵️', financial:'💰', sabotage:'💣',
  hacktivism:'✊', 'cyber-crime':'🦹', ransomware:'🔐',
  'data-theft':'📂', disruption:'⚡', unknown:'❓',
};

function motivIcon(m) {
  const key = (m||'').toLowerCase();
  for (const [k, v] of Object.entries(MOTIV_ICONS)) if (key.includes(k)) return v;
  return '⚡';
}

const SOPH_COLORS = {
  'nation-state':'#ff4757','advanced':'#ff6b35','intermediate':'#ffa502',
  'medium':'#ffd700','low':'#2ed573','novice':'#2ed573',
};
const MOTIV_COLORS = {
  espionage:'#7c3aed',financial:'#d97706',sabotage:'#dc2626',
  hacktivism:'#0891b2','cyber-crime':'#9333ea',ransomware:'#dc2626',
  'data-theft':'#2563eb',disruption:'#c2410c',
};

function sophBadge(s) {
  const c = SOPH_COLORS[(s||'').toLowerCase()] || '#636e72';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700">${esc(s||'unknown')}</span>`;
}

function motivBadge(m) {
  const c = MOTIV_COLORS[(m||'').toLowerCase()] || '#636e72';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:700">${motivIcon(m)} ${esc(m||'unknown')}</span>`;
}

const FLAG = (cc) => cc ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E0 - 65 + c.charCodeAt(0))) : '';

/* ══════════════════════════════════════════════════════════════
   MAIN RENDER — called by PAGE_CONFIG['threat-actors'].onEnter
══════════════════════════════════════════════════════════════ */
async function renderThreatActors() {
  const container = document.getElementById('threatActorsContainer')
    || document.getElementById('actorsContainer')
    || document.getElementById('page-threat-actors')
    || document.getElementById('threat-actors')
    || document.getElementById('threatActorsLiveContainer');

  if (!container) {
    console.warn('[ThreatActors-v2] Container not found — tried: threatActorsContainer, actorsContainer, page-threat-actors, threat-actors, threatActorsLiveContainer');
    return;
  }

  // If we're inside a page wrapper that's initially hidden, make sure it's visible
  const pageEl = document.getElementById('page-threat-actors');
  if (pageEl) {
    pageEl.style.display = '';
    pageEl.style.visibility = 'visible';
  }

  // Render shell immediately so user sees UI right away
  container.innerHTML = _shellHTML();

  // Run loads in parallel
  await Promise.all([
    _loadStats(),
    _loadCountries(),
    _loadActors(1),
  ]);
}

/* ── Shell HTML (filters + stats + content area) ───────────────*/
function _shellHTML() {
  return `
<div id="ta2-root" style="min-height:calc(100vh - 80px);display:flex;flex-direction:column;overflow:auto;background:#0d1117;padding-bottom:20px">

  <!-- Header -->
  <div style="padding:20px 20px 0;flex-shrink:0">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px">
      <div>
        <h2 style="margin:0;font-size:1.35em;color:#e6edf3;display:flex;align-items:center;gap:10px">
          🕵️ Threat Actor Intelligence
        </h2>
        <p id="ta2-subtitle" style="margin:4px 0 0;color:#8b949e;font-size:.85em">
          Loading live threat actor profiles from intelligence feeds…
        </p>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button id="ta2-sync-otx-btn" onclick="window._ta2SyncOTX()"
          style="padding:7px 13px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.82em;display:flex;align-items:center;gap:5px">
          <i class="fas fa-sync-alt"></i> Sync OTX
        </button>
        <button id="ta2-sync-mitre-btn" onclick="window._ta2SyncMITRE()"
          style="padding:7px 13px;background:#7c3aed;border:1px solid #7c3aed;color:#fff;border-radius:6px;cursor:pointer;font-size:.82em;display:flex;align-items:center;gap:5px">
          <i class="fas fa-shield-alt"></i> Sync MITRE
        </button>
        <button onclick="window._ta2ExportAll()"
          style="padding:7px 13px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.82em">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>

    <!-- KPI Bar -->
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      ${['total-actors','nation-state','ransomware-groups','active-30d'].map((id, i) => {
        const labels = ['Total Actors','Nation-State APTs','Ransomware Groups','Active (30 Days)'];
        const colors = ['#58a6ff','#ff4757','#dc2626','#2ed573'];
        return `<div style="flex:1;min-width:110px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 12px">
          <div id="ta2-kpi-${id}" style="font-size:1.4em;font-weight:700;color:${colors[i]}">—</div>
          <div style="font-size:.72em;color:#8b949e;margin-top:2px">${labels[i]}</div>
        </div>`;
      }).join('')}
    </div>

    <!-- Filters -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;margin-bottom:14px">
      <input id="ta2-search" type="text" placeholder="🔍 Search actor, aliases, malware…"
        style="flex:2;min-width:200px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 12px;font-size:.88em"
        oninput="window._ta2Search(this.value)" />

      <select id="ta2-motiv" onchange="window._ta2Filter('motivation', this.value)"
        style="flex:1;min-width:140px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
        <option value="">All Motivations</option>
        <option>espionage</option><option>financial</option><option>sabotage</option>
        <option>hacktivism</option><option>cyber-crime</option><option>ransomware</option>
      </select>

      <select id="ta2-country" onchange="window._ta2Filter('origin_country', this.value)"
        style="flex:1;min-width:130px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
        <option value="">All Countries</option>
      </select>

      <select id="ta2-soph" onchange="window._ta2Filter('sophistication', this.value)"
        style="flex:1;min-width:140px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:.85em">
        <option value="">All Sophistication</option>
        <option value="nation-state">Nation-State</option>
        <option value="advanced">Advanced</option>
        <option value="intermediate">Intermediate</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>

      <label style="display:flex;align-items:center;gap:6px;color:#8b949e;font-size:.85em;cursor:pointer">
        <input type="checkbox" id="ta2-active-only" onchange="window._ta2Filter('active_only', this.checked)"
          style="accent-color:#1d6ae5" />
        Active only
      </label>

      <button onclick="window._ta2ClearFilters()"
        style="padding:7px 12px;background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:6px;cursor:pointer;font-size:.83em">
        ✕ Clear
      </button>
    </div>
  </div>

  <!-- Content area -->
  <div style="flex:1;overflow:visible;display:flex;gap:0;padding:0 20px 0">
    <!-- Actor grid -->
    <div id="ta2-grid-wrap" style="flex:1;overflow:visible;padding-right:12px">
      <div id="ta2-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">
        ${_skeletonCards(6)}
      </div>
      <div id="ta2-pagination" style="margin-top:16px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap"></div>
    </div>

    <!-- Detail panel (hidden by default) -->
    <div id="ta2-detail-panel" style="display:none;width:460px;flex-shrink:0;background:#161b22;border:1px solid #21262d;border-radius:10px;overflow:hidden;flex-direction:column;max-height:calc(100vh - 180px);position:sticky;top:0;align-self:flex-start">
      <div id="ta2-detail-content" style="overflow-y:auto;height:100%"></div>
    </div>
  </div>

</div>`;
}

function _skeletonCards(n) {
  return Array.from({length: n}, () => `
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:16px;animation:ta2-pulse 1.5s ease-in-out infinite">
      <div style="height:18px;background:#21262d;border-radius:4px;width:60%;margin-bottom:10px"></div>
      <div style="height:12px;background:#21262d;border-radius:4px;width:90%;margin-bottom:6px"></div>
      <div style="height:12px;background:#21262d;border-radius:4px;width:70%;margin-bottom:12px"></div>
      <div style="display:flex;gap:6px">
        <div style="height:20px;background:#21262d;border-radius:10px;width:70px"></div>
        <div style="height:20px;background:#21262d;border-radius:10px;width:80px"></div>
      </div>
    </div>
  `).join('');
}

/* ── Load KPIs ──────────────────────────────────────────────────*/
async function _loadStats() {
  try {
    const stats = await _get('/threat-actors/stats');
    const set = (id, val) => {
      const el = document.getElementById(`ta2-kpi-${id}`);
      if (el) el.textContent = (val ?? 0).toLocaleString();
    };
    set('total-actors',      stats.total);
    set('nation-state',      stats.nation_state);
    set('ransomware-groups', stats.ransomware);
    set('active-30d',        stats.active_30d);
  } catch (err) {
    console.warn('[ThreatActors-v2] Stats error:', err.message);
  }
}

/* ── Load countries for filter ──────────────────────────────────*/
async function _loadCountries() {
  try {
    const res = await _get('/threat-actors/countries');
    const sel = document.getElementById('ta2-country');
    if (!sel) return;
    const countries = res.countries || [];
    countries.forEach(cc => {
      const opt = document.createElement('option');
      opt.value       = cc;
      opt.textContent = `${FLAG(cc)} ${cc}`;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

/* ── Load actors list ───────────────────────────────────────────*/
async function _loadActors(page = 1) {
  if (_TA.loading) return;
  _TA.loading = true;
  _TA.page    = page;

  const grid = document.getElementById('ta2-grid');
  if (grid) grid.innerHTML = _skeletonCards(6);

  try {
    const params = {
      page,
      limit: _TA.limit,
    };
    if (_TA.filters.search)         params.search         = _TA.filters.search;
    if (_TA.filters.motivation)     params.motivation     = _TA.filters.motivation;
    if (_TA.filters.origin_country) params.origin_country = _TA.filters.origin_country;
    if (_TA.filters.sophistication) params.sophistication = _TA.filters.sophistication;
    if (_TA.filters.active_only)    params.active_only    = 'true';

    const result = await _get('/threat-actors', params);
    const actors = result.data || [];
    const total  = result.total || 0;

    _TA.list  = actors;
    _TA.total = total;

    // Update subtitle
    const sub = document.getElementById('ta2-subtitle');
    if (sub) sub.textContent = `${total.toLocaleString()} threat actor${total !== 1 ? 's' : ''} from intelligence feeds`;

    if (!grid) return;

    if (actors.length === 0) {
      grid.innerHTML = _emptyState();
    } else {
      grid.innerHTML = actors.map(_actorCard).join('');
    }

    _renderPagination(total, page);

  } catch (err) {
    const grid2 = document.getElementById('ta2-grid');
    if (grid2) grid2.innerHTML = _errorState(err.message);
    const sub = document.getElementById('ta2-subtitle');
    if (sub) sub.textContent = 'Failed to load threat actors';
  } finally {
    _TA.loading = false;
  }
}

/* ── Actor card HTML ────────────────────────────────────────────*/
function _actorCard(actor) {
  const flag = actor.origin_country ? FLAG(actor.origin_country) : '🌐';
  const ttps = (actor.ttps || []).slice(0, 3);
  const confidence = actor.confidence || 0;
  const confColor = confidence >= 80 ? '#2ed573' : confidence >= 60 ? '#ffa502' : '#ff4757';
  const isSelected = actor.id === _TA.selectedId;

  return `
<div class="ta2-card" onclick="window._ta2ShowDetail('${esc(actor.id)}')"
  style="background:${isSelected ? '#1c2840' : '#161b22'};border:1px solid ${isSelected ? '#1d6ae5' : '#21262d'};border-radius:10px;padding:16px;cursor:pointer;transition:all .15s;position:relative"
  onmouseenter="this.style.borderColor='#30363d';this.style.background='#1c2128'"
  onmouseleave="this.style.borderColor='${isSelected ? '#1d6ae5' : '#21262d'}';this.style.background='${isSelected ? '#1c2840' : '#161b22'}'">

  <!-- Top row -->
  <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px">
    <div style="flex:1;min-width:0">
      <div style="font-size:.98em;font-weight:700;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(actor.name)}">
        ${flag} ${esc(actor.name)}
      </div>
      ${actor.aliases?.length ? `<div style="font-size:.72em;color:#8b949e;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc((actor.aliases||[]).slice(0,2).join(' · '))}</div>` : ''}
    </div>
    <div style="font-size:.7em;color:${confColor};background:${confColor}15;border:1px solid ${confColor}40;padding:2px 7px;border-radius:10px;font-weight:700;white-space:nowrap;margin-left:8px">
      ${confidence}%
    </div>
  </div>

  <!-- Badges -->
  <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
    ${motivBadge(actor.motivation)}
    ${sophBadge(actor.sophistication)}
  </div>

  <!-- Description -->
  ${actor.description ? `<p style="font-size:.78em;color:#8b949e;margin:0 0 10px;line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden">${esc(actor.description)}</p>` : ''}

  <!-- TTPs -->
  ${ttps.length ? `
  <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
    ${ttps.map(t => `<span style="background:#1d6ae520;color:#58a6ff;border:1px solid #1d6ae540;padding:1px 6px;border-radius:3px;font-size:.68em;font-family:monospace">${esc(t)}</span>`).join('')}
    ${(actor.ttps||[]).length > 3 ? `<span style="color:#8b949e;font-size:.68em">+${(actor.ttps||[]).length - 3} more</span>` : ''}
  </div>` : ''}

  <!-- Footer -->
  <div style="display:flex;align-items:center;justify-content:space-between;font-size:.72em;color:#8b949e">
    <span>${actor.origin_country ? `${flag} ${actor.origin_country}` : '🌐 Unknown'}</span>
    <span>Last seen: ${ago(actor.last_seen || actor.updated_at)}</span>
  </div>

  <!-- Source badge -->
  <div style="position:absolute;top:10px;right:10px;font-size:.62em;background:#21262d;color:#8b949e;padding:1px 6px;border-radius:3px">
    ${esc(actor.source || 'manual')}
  </div>
</div>`;
}

/* ── Pagination ─────────────────────────────────────────────────*/
function _renderPagination(total, current) {
  const pag = document.getElementById('ta2-pagination');
  if (!pag) return;

  const pages = Math.ceil(total / _TA.limit);
  if (pages <= 1) { pag.innerHTML = ''; return; }

  const btns = [];
  for (let p = Math.max(1, current - 2); p <= Math.min(pages, current + 2); p++) {
    btns.push(`
      <button onclick="window._ta2GoPage(${p})"
        style="padding:5px 12px;background:${p === current ? '#1d6ae5' : '#21262d'};border:1px solid ${p === current ? '#1d6ae5' : '#30363d'};color:${p === current ? '#fff' : '#e6edf3'};border-radius:5px;cursor:pointer;font-size:.83em">
        ${p}
      </button>`);
  }

  pag.innerHTML = `
    <button onclick="window._ta2GoPage(${current - 1})" ${current <= 1 ? 'disabled' : ''}
      style="padding:5px 12px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:5px;cursor:pointer;font-size:.83em;opacity:${current <= 1 ? 0.4 : 1}">
      ← Prev
    </button>
    ${btns.join('')}
    <button onclick="window._ta2GoPage(${current + 1})" ${current >= pages ? 'disabled' : ''}
      style="padding:5px 12px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:5px;cursor:pointer;font-size:.83em;opacity:${current >= pages ? 0.4 : 1}">
      Next →
    </button>
    <span style="color:#8b949e;font-size:.8em;align-self:center">${total.toLocaleString()} actors, page ${current}/${pages}</span>`;
}

/* ══════════════════════════════════════════════════════════════
   ACTOR DETAIL PANEL
══════════════════════════════════════════════════════════════ */
async function _showDetail(actorId) {
  if (_TA.detailLoading) return;
  _TA.selectedId  = actorId;
  _TA.detailTab   = 'overview';

  const panel   = document.getElementById('ta2-detail-panel');
  const content = document.getElementById('ta2-detail-content');
  if (!panel || !content) return;

  // Show panel
  panel.style.display = 'flex';

  // Loading state
  content.innerHTML = `
    <div style="padding:32px;text-align:center;color:#8b949e">
      <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px;color:#1d6ae5"></i>
      Loading actor profile…
    </div>`;

  // Re-render grid to highlight selected card
  const grid = document.getElementById('ta2-grid');
  if (grid) grid.innerHTML = _TA.list.map(_actorCard).join('');

  _TA.detailLoading = true;
  try {
    const actor = await _get(`/threat-actors/${actorId}`);
    _TA.selectedActor = actor;
    _renderDetailPanel(actor);
  } catch (err) {
    content.innerHTML = `
      <div style="padding:24px;color:#ef4444;text-align:center">
        <i class="fas fa-exclamation-triangle fa-2x" style="display:block;margin-bottom:10px"></i>
        ${esc(err.message)}
      </div>`;
  } finally {
    _TA.detailLoading = false;
  }
}

function _renderDetailPanel(actor) {
  const content = document.getElementById('ta2-detail-content');
  if (!content) return;

  const flag = actor.origin_country ? FLAG(actor.origin_country) : '🌐';
  const tabs = ['overview', 'techniques', 'iocs', 'campaigns', 'timeline'];
  const tabLabels = { overview:'Overview', techniques:'ATT&CK', iocs:'IOCs', campaigns:'Campaigns', timeline:'Timeline' };

  content.innerHTML = `
    <!-- Header -->
    <div style="padding:16px 20px;border-bottom:1px solid #21262d;position:sticky;top:0;background:#161b22;z-index:10">
      <div style="display:flex;align-items:flex-start;justify-content:space-between">
        <div>
          <div style="font-size:1.1em;font-weight:700;color:#e6edf3">${flag} ${esc(actor.name)}</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:3px">
            ${actor.aliases?.length ? esc((actor.aliases||[]).slice(0,3).join(' · ')) : 'No aliases'}
          </div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <button onclick="window._ta2ExportActor('${esc(actor.id)}')"
            style="padding:4px 10px;background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:5px;cursor:pointer;font-size:.75em">
            <i class="fas fa-download"></i>
          </button>
          <button onclick="window._ta2CloseDetail()"
            style="padding:4px 10px;background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:5px;cursor:pointer;font-size:.75em">
            ✕ Close
          </button>
        </div>
      </div>
      <!-- Badges row -->
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">
        ${motivBadge(actor.motivation)}
        ${sophBadge(actor.sophistication)}
        ${actor.origin_country ? `<span style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:2px 8px;border-radius:4px;font-size:.72em">${flag} ${esc(actor.origin_country)}</span>` : ''}
        ${actor.source ? `<span style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:2px 8px;border-radius:4px;font-size:.72em">${esc(actor.source)}</span>` : ''}
      </div>
    </div>

    <!-- Tabs -->
    <div id="ta2-detail-tabs" style="display:flex;gap:0;border-bottom:1px solid #21262d;background:#0d1117;position:sticky;top:75px;z-index:9">
      ${tabs.map(t => `
        <button id="ta2-tab-${t}" onclick="window._ta2SwitchTab('${t}', '${esc(actor.id)}')"
          style="padding:9px 14px;background:${_TA.detailTab === t ? '#161b22' : 'transparent'};border:none;border-bottom:2px solid ${_TA.detailTab === t ? '#1d6ae5' : 'transparent'};color:${_TA.detailTab === t ? '#e6edf3' : '#8b949e'};cursor:pointer;font-size:.82em;transition:all .1s">
          ${tabLabels[t]}
        </button>
      `).join('')}
    </div>

    <!-- Tab content -->
    <div id="ta2-tab-content" style="padding:16px 20px">
      ${_renderTabContent(actor, 'overview')}
    </div>`;
}

function _renderTabContent(actor, tab) {
  switch(tab) {
    case 'overview':   return _tabOverview(actor);
    case 'techniques': return _tabTechniques(actor);
    case 'iocs':       return `<div style="padding:20px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin"></i> Loading IOCs…</div>`;
    case 'campaigns':  return `<div style="padding:20px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin"></i> Loading campaigns…</div>`;
    case 'timeline':   return `<div style="padding:20px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin"></i> Loading timeline…</div>`;
    default:           return '<div>Unknown tab</div>';
  }
}

function _tabOverview(actor) {
  const rows = [
    ['Motivation', motivBadge(actor.motivation)],
    ['Sophistication', sophBadge(actor.sophistication)],
    ['Origin Country', actor.origin_country ? `${FLAG(actor.origin_country)} ${actor.origin_country}` : '—'],
    ['Active Since', actor.active_since ? new Date(actor.active_since).getFullYear() : '—'],
    ['Last Seen', ago(actor.last_seen)],
    ['Confidence', `<span style="color:${actor.confidence>=80?'#2ed573':actor.confidence>=60?'#ffa502':'#ff4757'};font-weight:700">${actor.confidence || 0}%</span>`],
    ['Source', esc(actor.source || 'manual')],
    ['External ID', actor.external_id ? `<code style="background:#21262d;padding:1px 6px;border-radius:3px;font-size:.8em">${esc(actor.external_id)}</code>` : '—'],
  ].filter(([, v]) => v !== '—');

  return `
    ${actor.description ? `<p style="color:#c9d1d9;font-size:.88em;line-height:1.7;margin:0 0 16px">${esc(actor.description)}</p>` : ''}

    <div style="display:grid;grid-template-columns:130px 1fr;gap:8px 12px;margin-bottom:16px">
      ${rows.map(([label, val]) => `
        <div style="color:#8b949e;font-size:.8em;padding:4px 0;border-bottom:1px solid #21262d30">${label}</div>
        <div style="font-size:.82em;padding:4px 0;border-bottom:1px solid #21262d30">${val}</div>
      `).join('')}
    </div>

    ${(actor.target_sectors||[]).length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;font-weight:600">TARGET SECTORS</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(actor.target_sectors||[]).map(s => `<span style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:2px 8px;border-radius:4px;font-size:.75em">${esc(s)}</span>`).join('')}
        </div>
      </div>
    ` : ''}

    ${(actor.target_countries||[]).length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;font-weight:600">TARGET COUNTRIES</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(actor.target_countries||[]).map(c => `<span style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:2px 8px;border-radius:4px;font-size:.75em">${FLAG(c)} ${esc(c)}</span>`).join('')}
        </div>
      </div>
    ` : ''}

    ${(actor.malware||[]).length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;font-weight:600">ASSOCIATED MALWARE</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(actor.malware||[]).map(m => `<span style="background:#ff475715;color:#ff4757;border:1px solid #ff475730;padding:2px 8px;border-radius:4px;font-size:.75em">🦠 ${esc(m)}</span>`).join('')}
        </div>
      </div>
    ` : ''}

    ${(actor.tools||[]).length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;font-weight:600">TOOLS USED</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(actor.tools||[]).map(t => `<span style="background:#1d6ae520;color:#58a6ff;border:1px solid #1d6ae540;padding:2px 8px;border-radius:4px;font-size:.75em">🔧 ${esc(t)}</span>`).join('')}
        </div>
      </div>
    ` : ''}

    ${(actor.tags||[]).length ? `
      <div>
        <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;font-weight:600">TAGS</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(actor.tags||[]).map(t => `<span style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:1px 6px;border-radius:3px;font-size:.72em">${esc(t)}</span>`).join('')}
        </div>
      </div>
    ` : ''}`;
}

function _tabTechniques(actor) {
  const ttps = actor.ttps || [];
  if (!ttps.length) return `<div style="padding:24px;text-align:center;color:#8b949e"><i class="fas fa-shield-alt fa-2x" style="display:block;margin-bottom:10px;opacity:.3"></i>No ATT&CK techniques attributed yet.<br><small>Sync from MITRE to populate techniques.</small></div>`;

  return `
    <div style="margin-bottom:10px;color:#8b949e;font-size:.82em">${ttps.length} ATT&CK technique${ttps.length !== 1 ? 's' : ''} attributed</div>
    <div style="display:flex;flex-direction:column;gap:6px">
      ${ttps.map(ttp => {
        const isMITRE = /^T\d{4}/.test(ttp);
        return `
          <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:8px 12px;display:flex;align-items:center;gap:10px">
            ${isMITRE ? `<span style="background:#7c3aed20;color:#7c3aed;border:1px solid #7c3aed40;padding:2px 7px;border-radius:4px;font-size:.75em;font-family:monospace;font-weight:700">${esc(ttp.split(':')[0])}</span>` : ''}
            <span style="color:#c9d1d9;font-size:.84em">${esc(isMITRE && ttp.includes(':') ? ttp.split(':').slice(1).join(':').trim() : ttp)}</span>
            ${isMITRE ? `<a href="https://attack.mitre.org/techniques/${esc(ttp.split(':')[0])}/" target="_blank" style="margin-left:auto;color:#1d6ae5;font-size:.72em;text-decoration:none">View ↗</a>` : ''}
          </div>`;
      }).join('')}
    </div>`;
}

async function _loadTabContent(tab, actorId) {
  const content = document.getElementById('ta2-tab-content');
  if (!content) return;

  content.innerHTML = `<div style="padding:24px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:10px"></i>Loading ${tab}…</div>`;

  try {
    switch(tab) {
      case 'iocs': {
        const res = await _get(`/threat-actors/${actorId}/iocs`, { limit: 25 });
        content.innerHTML = _tabIOCs(res.data || [], res.total || 0);
        break;
      }
      case 'campaigns': {
        const res = await _get(`/threat-actors/${actorId}/campaigns`);
        content.innerHTML = _tabCampaigns(res.data || []);
        break;
      }
      case 'timeline': {
        const res = await _get(`/threat-actors/${actorId}/timeline`);
        content.innerHTML = _tabTimeline(res.data || []);
        break;
      }
    }
  } catch (err) {
    content.innerHTML = `<div style="padding:20px;color:#ef4444;text-align:center"><i class="fas fa-exclamation-triangle"></i> ${esc(err.message)}</div>`;
  }
}

function _tabIOCs(iocs, total) {
  if (!iocs.length) return `<div style="padding:24px;text-align:center;color:#8b949e"><i class="fas fa-database fa-2x" style="display:block;margin-bottom:10px;opacity:.3"></i>No IOCs attributed to this actor.<br><small>IOCs are linked via threat_actor field during ingestion.</small></div>`;

  const TYPE_COLORS = {ip:'#22d3ee',domain:'#a78bfa',url:'#34d399',md5:'#fbbf24',sha256:'#f59e0b',sha1:'#fb923c'};
  return `
    <div style="margin-bottom:10px;color:#8b949e;font-size:.82em">${total.toLocaleString()} IOC${total !== 1 ? 's' : ''} attributed</div>
    <div style="display:flex;flex-direction:column;gap:5px">
      ${iocs.map(ioc => {
        const tc = TYPE_COLORS[(ioc.type||'').toLowerCase()] || '#8b949e';
        const rc = ioc.risk_score >= 70 ? '#ff4444' : ioc.risk_score >= 40 ? '#ffa502' : '#2ed573';
        return `
          <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:8px 12px;display:flex;align-items:center;gap:8px">
            <span style="background:${tc}20;color:${tc};border:1px solid ${tc}40;padding:1px 6px;border-radius:3px;font-size:.68em;font-weight:700;text-transform:uppercase;white-space:nowrap">${esc(ioc.type)}</span>
            <span style="font-family:monospace;font-size:.8em;color:#c9d1d9;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1" title="${esc(ioc.value)}">${esc(ioc.value)}</span>
            <span style="background:${rc}15;color:${rc};padding:1px 6px;border-radius:4px;font-size:.7em;font-weight:700;white-space:nowrap">${ioc.risk_score || 0}</span>
            <span style="color:#8b949e;font-size:.7em;white-space:nowrap">${ago(ioc.last_seen)}</span>
          </div>`;
      }).join('')}
    </div>
    ${total > 25 ? `<p style="font-size:.78em;color:#8b949e;text-align:center;margin-top:10px">Showing 25 of ${total}. Go to IOC Database for full list.</p>` : ''}`;
}

function _tabCampaigns(campaigns) {
  if (!campaigns.length) return `<div style="padding:24px;text-align:center;color:#8b949e"><i class="fas fa-sitemap fa-2x" style="display:block;margin-bottom:10px;opacity:.3"></i>No campaigns attributed to this actor.</div>`;

  const STATUS_COLORS = { active:'#2ed573', concluded:'#8b949e', suspected:'#ffa502' };
  return `
    <div style="display:flex;flex-direction:column;gap:8px">
      ${campaigns.map(c => {
        const sc = STATUS_COLORS[(c.status||'').toLowerCase()] || '#8b949e';
        return `
          <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
              <div style="font-weight:600;color:#e6edf3;font-size:.9em">${esc(c.name)}</div>
              <span style="background:${sc}20;color:${sc};padding:1px 7px;border-radius:10px;font-size:.7em;font-weight:700">${esc(c.status||'unknown')}</span>
            </div>
            ${c.description ? `<p style="font-size:.78em;color:#8b949e;margin:0 0 8px;line-height:1.5">${esc(c.description.slice(0,120))}</p>` : ''}
            <div style="font-size:.72em;color:#8b949e">
              ${c.start_date ? `Start: ${new Date(c.start_date).toLocaleDateString()}` : ''}
              ${c.target_sectors?.length ? ` · Targets: ${c.target_sectors.slice(0,2).join(', ')}` : ''}
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

function _tabTimeline(events) {
  if (!events.length) return `<div style="padding:24px;text-align:center;color:#8b949e"><i class="fas fa-history fa-2x" style="display:block;margin-bottom:10px;opacity:.3"></i>No timeline events recorded for this actor.</div>`;

  return `
    <div style="display:flex;flex-direction:column;gap:0">
      ${events.map((ev, i) => `
        <div style="display:flex;gap:12px;padding-bottom:14px">
          <div style="display:flex;flex-direction:column;align-items:center">
            <div style="width:10px;height:10px;background:#1d6ae5;border-radius:50%;flex-shrink:0;margin-top:3px"></div>
            ${i < events.length - 1 ? `<div style="width:2px;flex:1;background:#21262d;margin-top:2px"></div>` : ''}
          </div>
          <div style="flex:1">
            <div style="font-size:.82em;font-weight:600;color:#e6edf3;margin-bottom:2px">${esc(ev.event_type || ev.action || 'Event')}</div>
            ${ev.description ? `<div style="font-size:.78em;color:#8b949e;line-height:1.5">${esc(ev.description)}</div>` : ''}
            <div style="font-size:.7em;color:#8b949e;margin-top:3px">${ago(ev.detected_at || ev.created_at)}</div>
          </div>
        </div>
      `).join('')}
    </div>`;
}

/* ── Empty / Error states ───────────────────────────────────────*/
function _emptyState() {
  const hasFilters = Object.values(_TA.filters).some(v => v && v !== false);
  return `
    <div style="grid-column:1/-1;padding:48px 24px;text-align:center;color:#8b949e">
      <div style="font-size:2.5em;margin-bottom:12px">${hasFilters ? '🔍' : '🕵️'}</div>
      <div style="font-size:1em;font-weight:600;margin-bottom:8px">
        ${hasFilters ? 'No actors match your filters' : 'No threat actors in database yet'}
      </div>
      <div style="font-size:.85em;max-width:400px;margin:0 auto 16px">
        ${hasFilters
          ? 'Try clearing some filters to broaden your search.'
          : 'Click <strong>Sync MITRE</strong> to import threat actor groups from MITRE ATT&CK, or <strong>Sync OTX</strong> to pull from AlienVault OTX.'
        }
      </div>
      ${hasFilters
        ? `<button onclick="window._ta2ClearFilters()" style="padding:8px 18px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em">Clear Filters</button>`
        : `<div style="display:flex;gap:10px;justify-content:center">
            <button onclick="window._ta2SyncMITRE()" style="padding:8px 18px;background:#7c3aed;border:1px solid #7c3aed;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em"><i class="fas fa-shield-alt"></i> Sync MITRE ATT&CK</button>
            <button onclick="window._ta2SyncOTX()" style="padding:8px 18px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em"><i class="fas fa-sync-alt"></i> Sync OTX</button>
          </div>`
      }
    </div>`;
}

function _errorState(msg) {
  return `
    <div style="grid-column:1/-1;padding:40px;text-align:center;color:#ef4444">
      <i class="fas fa-exclamation-triangle fa-2x" style="display:block;margin-bottom:12px"></i>
      ${esc(msg)}
      <br><br>
      <button onclick="window._ta2Reload()" style="padding:7px 18px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
        <i class="fas fa-redo"></i> Retry
      </button>
    </div>`;
}

/* ══════════════════════════════════════════════════════════════
   GLOBAL EVENT HANDLERS (attached to window for onclick usage)
══════════════════════════════════════════════════════════════ */

window._ta2Search = function(value) {
  clearTimeout(_TA._debounceTimer);
  _TA._debounceTimer = setTimeout(() => {
    _TA.filters.search = value;
    _loadActors(1);
  }, 350);
};

window._ta2Filter = function(key, value) {
  if (key === 'active_only') {
    _TA.filters.active_only = value === true || value === 'true';
  } else {
    _TA.filters[key] = value;
  }
  _loadActors(1);
};

window._ta2ClearFilters = function() {
  _TA.filters = { search:'', motivation:'', origin_country:'', sophistication:'', active_only:false };
  const fields = ['ta2-search','ta2-motiv','ta2-country','ta2-soph'];
  fields.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const activeOnly = document.getElementById('ta2-active-only');
  if (activeOnly) activeOnly.checked = false;
  _loadActors(1);
};

window._ta2GoPage = function(page) {
  _loadActors(Math.max(1, page));
};

window._ta2Reload = function() {
  _loadActors(_TA.page);
};

window._ta2ShowDetail = function(id) {
  _showDetail(id);
};

window._ta2CloseDetail = function() {
  const panel = document.getElementById('ta2-detail-panel');
  if (panel) panel.style.display = 'none';
  _TA.selectedId    = null;
  _TA.selectedActor = null;
  // Re-render grid to remove selection highlight
  const grid = document.getElementById('ta2-grid');
  if (grid) grid.innerHTML = _TA.list.map(_actorCard).join('');
};

window._ta2SwitchTab = function(tab, actorId) {
  _TA.detailTab = tab;

  // Update tab styles
  ['overview','techniques','iocs','campaigns','timeline'].forEach(t => {
    const btn = document.getElementById(`ta2-tab-${t}`);
    if (!btn) return;
    btn.style.background    = t === tab ? '#161b22' : 'transparent';
    btn.style.borderBottomColor = t === tab ? '#1d6ae5' : 'transparent';
    btn.style.color         = t === tab ? '#e6edf3' : '#8b949e';
  });

  // Render content
  if (tab === 'overview' || tab === 'techniques') {
    const content = document.getElementById('ta2-tab-content');
    if (content && _TA.selectedActor) {
      content.innerHTML = _renderTabContent(_TA.selectedActor, tab);
    }
  } else {
    _loadTabContent(tab, actorId);
  }
};

window._ta2SyncOTX = async function() {
  const btn = document.getElementById('ta2-sync-otx-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Syncing…'; }

  try {
    const res = await _post('/threat-actors/ingest/otx', {});
    if (global.showToast) {
      global.showToast(`✅ OTX Sync: ${res.actors_ingested || 0} actors imported`, 'success');
    }
    await Promise.all([_loadStats(), _loadActors(1)]);
  } catch (err) {
    if (global.showToast) global.showToast(`❌ OTX Sync failed: ${err.message}`, 'error');
    else alert('OTX Sync failed: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-sync-alt"></i> Sync OTX'; }
  }
};

window._ta2SyncMITRE = async function() {
  const btn = document.getElementById('ta2-sync-mitre-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Syncing MITRE…'; }

  try {
    const res = await _post('/threat-actors/ingest/mitre', {});
    if (global.showToast) {
      global.showToast(`✅ MITRE Sync: ${res.actors_ingested || 0} groups imported`, 'success');
    }
    await Promise.all([_loadStats(), _loadActors(1)]);
  } catch (err) {
    if (global.showToast) global.showToast(`❌ MITRE Sync failed: ${err.message}`, 'error');
    else alert('MITRE Sync failed: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-shield-alt"></i> Sync MITRE'; }
  }
};

window._ta2ExportAll = function() {
  const data = _TA.list;
  if (!data.length) return alert('No actors loaded to export.');
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `threat-actors-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
};

window._ta2ExportActor = function(id) {
  const actor = _TA.selectedActor;
  if (!actor) return;
  const blob = new Blob([JSON.stringify(actor, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `actor-${(actor.name||id).replace(/\s+/g,'-').toLowerCase()}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
};

/* ── Animation CSS ──────────────────────────────────────────────*/
if (!document.getElementById('ta2-styles')) {
  const style = document.createElement('style');
  style.id = 'ta2-styles';
  style.textContent = `
    @keyframes ta2-pulse {
      0%, 100% { opacity: .5; }
      50%       { opacity: .9; }
    }
    .ta2-card:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,0,0,.3); }
    .ta2-card { transition: transform .15s, box-shadow .15s; }
  `;
  document.head.appendChild(style);
}

/* ══════════════════════════════════════════════════════════════
   OVERRIDE pages.js renderThreatActors
   This ensures the real module fires instead of the static one.
══════════════════════════════════════════════════════════════ */
global.renderThreatActors = renderThreatActors;

// Also expose for direct calls
global.renderThreatActorsDashboard = renderThreatActors;

console.log('[ThreatActors-v2] ✅ Module loaded — overriding pages.js renderThreatActors with real API module');

})(window);
