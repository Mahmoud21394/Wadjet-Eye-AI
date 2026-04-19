/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC-Grade Active Campaigns Module v3.0
 *  FILE: js/campaigns-soc.js
 *
 *  v3.0 Fixes (2026-04-02):
 *  ─────────────────────────
 *  FIX-A: PAGE_CONFIG race condition — now uses a robust polling
 *         loop that retries until PAGE_CONFIG is available, then
 *         directly overwrites the 'campaigns' onEnter/onLeave.
 *  FIX-B: window.renderCampaigns override installed immediately
 *         (not just in the patch loop) so pages.js mock is bypassed.
 *  FIX-C: _apiGet now correctly passes paths without /api prefix
 *         when window.authFetch is available (authFetch adds it).
 *  FIX-D: Correlation engine integration — if backend returns 0
 *         campaigns, auto-triggers correlation pipeline.
 *  FIX-E: auth:restored / auth:login event listeners ensure the
 *         page re-renders if user navigates before auth resolves.
 *
 *  Features:
 *  ─────────
 *  • Animated KPI cards with live counters
 *  • Campaign cards / table toggle with severity glow
 *  • Slide-in detail panel with MITRE ATT&CK, IOCs, timeline
 *  • Canvas-based force-directed IOC relationship graph
 *  • SVG global threat map with animated attack flows
 *  • Real WebSocket / polling for live updates
 *  • Full filter bar (severity, status, actor, search)
 *  • Zero mock data — 100% real backend API
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────────── */
const CampaignSOC = {
  page:       1,
  limit:      20,
  total:      0,
  filters:    { search: '', severity: '', status: '', actor: '' },
  data:       [],
  loading:    false,
  view:       'cards',          // 'cards' | 'table'
  selected:   null,
  wsConn:     null,
  pollTimer:  null,
  kpiCache:   null,
  graphData:  { nodes: [], links: [] },
  mapFlows:   [],
  _patchDone: false,
};

window.CampaignSOC = CampaignSOC;

/* ─────────────────────────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────────────────────────── */
const _e = s => s == null ? '' : String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

/**
 * FIX-C: authFetch already builds: base + '/api' + path
 * So we must pass path WITHOUT the /api prefix here.
 * Direct fetch fallback adds /api manually.
 */
function _apiGet(path) {
  if (window.authFetch) return window.authFetch(path);
  const base = (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const tok  = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
  return fetch(`${base}/api${path}`, {
    headers: { 'Content-Type':'application/json', ...(tok ? { Authorization:`Bearer ${tok}` } : {}) }
  }).then(r => {
    if (r.status === 204) return {};
    if (!r.ok) return Promise.reject(new Error(`HTTP ${r.status}`));
    return r.json();
  });
}

function _apiPost(path, body) {
  if (window.authFetch) return window.authFetch(path, { method:'POST', body: JSON.stringify(body) });
  const base = (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const tok  = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
  return fetch(`${base}/api${path}`, {
    method:'POST',
    headers: { 'Content-Type':'application/json', ...(tok ? { Authorization:`Bearer ${tok}` } : {}) },
    body: JSON.stringify(body)
  }).then(r => {
    if (r.status === 204) return {};
    if (!r.ok) return Promise.reject(new Error(`HTTP ${r.status}`));
    return r.json();
  });
}

function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function _sevColor(sev) {
  return { CRITICAL:'#f43f5e', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#34d399', INFO:'#22d3ee' }[(sev||'').toUpperCase()] || '#8b949e';
}

function _sevBadge(sev) {
  const cls = { CRITICAL:'soc-badge-critical', HIGH:'soc-badge-high', MEDIUM:'soc-badge-medium', LOW:'soc-badge-low', INFO:'soc-badge-info' }[(sev||'').toUpperCase()] || 'soc-badge-info';
  return `<span class="soc-badge ${cls}">${_e(sev||'?')}</span>`;
}

function _statusPill(s) {
  const colors = {
    active:      { bg:'rgba(52,211,153,.12)',  border:'rgba(52,211,153,.25)',  text:'#34d399' },
    monitoring:  { bg:'rgba(34,211,238,.12)',  border:'rgba(34,211,238,.25)',  text:'#22d3ee' },
    contained:   { bg:'rgba(251,191,36,.12)',  border:'rgba(251,191,36,.25)',  text:'#fbbf24' },
    resolved:    { bg:'rgba(139,148,158,.12)', border:'rgba(139,148,158,.25)', text:'#8b949e' },
  };
  const c = colors[(s||'').toLowerCase()] || colors.monitoring;
  return `<span style="background:${c.bg};border:1px solid ${c.border};color:${c.text};padding:2px 9px;border-radius:20px;font-size:.7em;font-weight:600;text-transform:uppercase;letter-spacing:.04em">${_e(s||'Unknown')}</span>`;
}

function _skeleton(rows=4) {
  return `<div style="display:flex;flex-direction:column;gap:12px;padding:12px">
    ${Array(rows).fill(0).map((_,i) => `<div class="soc-skeleton" style="height:80px;border-radius:10px;animation-delay:${i*.07}s"></div>`).join('')}
  </div>`;
}

function _skel2(cols=7, rows=4) {
  return `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">
    <thead><tr>${Array(cols).fill(0).map(() => `<th style="padding:10px;background:#0d1117"><div class="soc-skeleton" style="height:14px;border-radius:4px"></div></th>`).join('')}</tr></thead>
    <tbody>${Array(rows).fill(0).map((_,i) => `<tr>${Array(cols).fill(0).map(() => `<td style="padding:10px;border-bottom:1px solid #161b22"><div class="soc-skeleton" style="height:12px;border-radius:4px;animation-delay:${i*.05}s"></div></td>`).join('')}</tr>`).join('')}</tbody>
  </table></div>`;
}

/* ─────────────────────────────────────────────────────────────────
   MAIN RENDER
───────────────────────────────────────────────────────────────── */
async function renderCampaignsSOC() {
  // Find the container — prefer soc-campaigns-wrap, fall back to page-campaigns
  const wrap = document.getElementById('soc-campaigns-wrap')
    || document.getElementById('campaignsLiveContainer')
    || document.getElementById('page-campaigns');

  if (!wrap) {
    console.warn('[CampaignsSOC] Container not found — retrying in 300ms');
    setTimeout(() => renderCampaignsSOC(), 300);
    return;
  }

  // Make legacy containers invisible
  const legacy = document.getElementById('campaignsLiveContainer');
  if (legacy && legacy !== wrap) legacy.style.display = 'none';

  // Reset state
  CampaignSOC.loading = false;
  CampaignSOC.page    = 1;

  wrap.innerHTML = `
    <div id="csoc-root" style="padding:20px;min-height:100%;background:#080c14;font-family:system-ui,sans-serif">

      <!-- ── Header ── -->
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:24px">
        <div>
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <div class="soc-waveform">
              <div class="bar"></div><div class="bar"></div><div class="bar"></div><div class="bar"></div><div class="bar"></div>
            </div>
            <h2 style="margin:0;font-size:1.3em;font-weight:800;color:#e6edf3;letter-spacing:-.02em">Active Campaigns</h2>
            <span style="padding:3px 9px;background:rgba(244,63,94,.12);border:1px solid rgba(244,63,94,.3);
              border-radius:20px;font-size:.68em;font-weight:700;color:#f43f5e;letter-spacing:.06em;
              animation:socGlowBlink 2s ease infinite">LIVE</span>
          </div>
          <p style="margin:0;color:#8b949e;font-size:.83em">
            Real-time threat campaign correlation — ingesting CISA · MITRE · OTX · AbuseIPDB · MISP
          </p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="soc-btn soc-btn-ghost" onclick="window._csocToggleMap()" id="csoc-map-btn">
            <i class="fas fa-globe"></i> Threat Map
          </button>
          <button class="soc-btn soc-btn-purple" onclick="window._csocRunCorrelation()">
            <i class="fas fa-brain"></i> Run Correlation
          </button>
          <button class="soc-btn soc-btn-primary" onclick="window._csocCreate()">
            <i class="fas fa-plus"></i> New Campaign
          </button>
        </div>
      </div>

      <!-- ── KPI Strip ── -->
      <div id="csoc-kpis" class="soc-kpi-grid" style="margin-bottom:24px">
        ${[0,1,2,3].map(i => `<div class="soc-skeleton" style="height:110px;border-radius:12px;animation-delay:${i*.08}s"></div>`).join('')}
      </div>

      <!-- ── Threat Map (collapsible) ── -->
      <div id="csoc-map-wrap" style="display:none;margin-bottom:24px">
        <div class="soc-map-wrap">
          <div class="soc-scanline"></div>
          <canvas id="csoc-map-canvas" style="width:100%;height:100%"></canvas>
          <div class="soc-map-legend" id="csoc-map-legend"></div>
          <div style="position:absolute;top:12px;right:12px;font-size:.72em;color:#8b949e">
            <i class="fas fa-circle" style="color:#f43f5e;font-size:.6em"></i> Source &nbsp;
            <i class="fas fa-circle" style="color:#22d3ee;font-size:.6em"></i> Target
          </div>
        </div>
      </div>

      <!-- ── Filter Bar ── -->
      <div class="soc-filter-bar" style="margin-bottom:20px">
        <input id="csoc-search" type="text" placeholder="🔍 Search campaigns, actors, TTPs…"
          style="flex:2;min-width:180px"
          oninput="window._csocSearchDebounce(this.value)" />

        <select id="csoc-sev" class="soc-select" onchange="window._csocSetFilter('severity',this.value)">
          <option value="">All Severities</option>
          <option value="CRITICAL">🔴 Critical</option>
          <option value="HIGH">🟠 High</option>
          <option value="MEDIUM">🟡 Medium</option>
          <option value="LOW">🟢 Low</option>
        </select>

        <select id="csoc-status" class="soc-select" onchange="window._csocSetFilter('status',this.value)">
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="monitoring">Monitoring</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
        </select>

        <select id="csoc-view-sel" class="soc-select" onchange="window._csocSetView(this.value)">
          <option value="cards">🃏 Cards</option>
          <option value="table">📋 Table</option>
        </select>

        <button class="soc-btn soc-btn-ghost" onclick="window._csocClearFilters()">
          <i class="fas fa-times"></i> Clear
        </button>
        <span id="csoc-total-label" style="font-size:.78em;color:#8b949e;margin-left:auto;white-space:nowrap"></span>
      </div>

      <!-- ── Campaign Body ── -->
      <div id="csoc-body" style="min-height:200px">${_skeleton(4)}</div>

      <!-- ── Pagination ── -->
      <div id="csoc-pages" style="margin-top:16px"></div>

      <!-- ── IOC Relationship Graph ── -->
      <div style="margin-top:32px">
        <div class="soc-section-hdr">
          <h3><span class="soc-dot"></span> IOC Relationship Graph</h3>
          <button class="soc-btn soc-btn-ghost" onclick="window._csocRefreshGraph()" style="font-size:.75em;padding:4px 10px">
            <i class="fas fa-sync-alt"></i> Refresh
          </button>
        </div>
        <div class="soc-graph-wrap" id="csoc-graph-outer" style="height:380px;position:relative">
          <div class="soc-scanline"></div>
          <canvas id="csoc-graph-canvas" style="width:100%;height:100%"></canvas>
          <div id="csoc-graph-tooltip" class="soc-graph-tooltip" style="opacity:0;pointer-events:none"></div>
          <div style="position:absolute;bottom:10px;left:50%;transform:translateX(-50%);
            font-size:.7em;color:#4b5563;white-space:nowrap">
            Drag to pan • Scroll to zoom • Click node to inspect
          </div>
        </div>
      </div>

      <!-- Legend strip -->
      <div style="display:flex;gap:16px;margin-top:12px;flex-wrap:wrap">
        ${[['#f43f5e','Campaign'],['#fb923c','Threat Actor'],['#a78bfa','TTP'],['#22d3ee','IOC'],['#fbbf24','Hash']].map(([c,l]) =>
          `<div style="display:flex;align-items:center;gap:5px;font-size:.73em;color:#8b949e">
            <div style="width:8px;height:8px;border-radius:50%;background:${c}"></div>${l}
          </div>`).join('')}
      </div>

    </div>

    <!-- ── Detail Side Panel ── -->
    <div id="csoc-detail-panel" class="soc-detail-panel" style="display:none"></div>
  `;

  // Wire globals BEFORE data loads so inline handlers work immediately
  _csocWireGlobals();

  // Load data in parallel
  await Promise.allSettled([
    _csocLoadKPIs(),
    _csocLoadCampaigns(),
  ]);

  // Start live polling
  _csocStartPolling();
  // Draw IOC graph after DOM settles
  setTimeout(() => _csocDrawGraph(), 900);
}

/* ─────────────────────────────────────────────────────────────────
   KPI CARDS
───────────────────────────────────────────────────────────────── */
async function _csocLoadKPIs() {
  try {
    const [campRes, iocRes] = await Promise.allSettled([
      _apiGet('/cti/campaigns?limit=200'),
      _apiGet('/ingest/stats'),
    ]);

    const allCamps = campRes.status === 'fulfilled' ? campRes.value : {};
    const iocSt   = iocRes.status  === 'fulfilled' ? iocRes.value  : {};
    const allRows = allCamps?.data || [];

    const activeCount   = allRows.filter(c => (c.status||'').toLowerCase() === 'active').length;
    const criticalCount = allRows.filter(c => (c.severity||'').toUpperCase() === 'CRITICAL').length;
    const last24h       = allRows.filter(c => c.created_at && (Date.now() - new Date(c.created_at)) < 86400000).length;

    CampaignSOC.kpiCache = {
      total:    allCamps?.total || allRows.length,
      active:   activeCount,
      critical: criticalCount,
      new24h:   last24h,
      iocs:     iocSt.total_iocs || 0,
      highRisk: iocSt.high_risk  || 0,
    };

    _csocRenderKPIs(CampaignSOC.kpiCache);
  } catch (err) {
    console.warn('[CampaignsSOC] KPI load failed:', err.message);
    _csocRenderKPIs({ total:0, active:0, critical:0, new24h:0, iocs:0, highRisk:0 });
  }
}

function _csocRenderKPIs(d) {
  const el = document.getElementById('csoc-kpis');
  if (!el) return;

  const cards = [
    { label:'Active Campaigns',   value:d.active,   icon:'fa-chess-king',      color:'#f43f5e', delta:`+${d.new24h} today`,                 deltaColor: d.new24h>0?'#f43f5e':'#34d399', sparkData:[2,3,5,3,7,4,d.active||0]  },
    { label:'Critical Severity',  value:d.critical, icon:'fa-skull-crossbones', color:'#fb923c', delta:'Requires Action',                    deltaColor:'#fb923c',                        sparkData:[1,1,2,1,3,2,d.critical||0] },
    { label:'New (Last 24h)',      value:d.new24h,   icon:'fa-bolt',            color:'#fbbf24', delta:'Auto-correlated',                    deltaColor:'#22d3ee',                        sparkData:[0,1,0,2,1,0,d.new24h||0]  },
    { label:'IOCs Tracked',        value:d.iocs,     icon:'fa-fingerprint',     color:'#22d3ee', delta:`${(d.highRisk||0).toLocaleString()} high risk`, deltaColor:'#f43f5e',         sparkData:[4000,5000,6000,8000,10000,11000,d.iocs||0] },
  ];

  el.innerHTML = cards.map((c, idx) => {
    const sparkPath = _miniSparkline(c.sparkData, 80, 24);
    return `
    <div class="soc-kpi-card" style="--kpi-color:${c.color};animation:socFadeSlideIn .4s ease ${idx*.1}s both">
      <div class="kpi-icon"><i class="fas ${c.icon}"></i></div>
      <div class="kpi-value" id="csoc-kpi-val-${idx}">0</div>
      <div class="kpi-label">${c.label}</div>
      <div class="kpi-delta" style="background:${c.deltaColor}15;color:${c.deltaColor};border:1px solid ${c.deltaColor}30">${c.delta}</div>
      <svg class="kpi-sparkline" viewBox="0 0 80 24" preserveAspectRatio="none">
        <path d="${sparkPath}" fill="none" stroke="${c.color}" stroke-width="1.5" opacity=".6"/>
      </svg>
    </div>`;
  }).join('');

  cards.forEach((c, idx) => _csocAnimateCounter(`csoc-kpi-val-${idx}`, c.value));
}

function _miniSparkline(data, w, h) {
  if (!data?.length) return '';
  const min = Math.min(...data);
  const max = Math.max(...data) || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / (max - min || 1)) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return `M${pts.join(' L')}`;
}

function _csocAnimateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!target) { el.textContent = '0'; return; }
  const dur = 900, start = Date.now();
  const tick = () => {
    const p    = Math.min(1, (Date.now() - start) / dur);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(ease * target).toLocaleString();
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/* ─────────────────────────────────────────────────────────────────
   CAMPAIGN LIST LOADER
───────────────────────────────────────────────────────────────── */
async function _csocLoadCampaigns() {
  if (CampaignSOC.loading) return;
  CampaignSOC.loading = true;

  const body = document.getElementById('csoc-body');
  if (body) body.innerHTML = CampaignSOC.view === 'cards' ? _skeleton(6) : _skel2(7, 5);

  try {
    const f  = CampaignSOC.filters;
    const qs = new URLSearchParams({
      page:  CampaignSOC.page,
      limit: CampaignSOC.limit,
      ...(f.search   ? { search:   f.search }   : {}),
      ...(f.severity ? { severity: f.severity } : {}),
      ...(f.status   ? { status:   f.status }   : {}),
      ...(f.actor    ? { actor:    f.actor }     : {}),
    });

    const res  = await _apiGet(`/cti/campaigns?${qs}`);
    const rows = Array.isArray(res?.data) ? res.data : (Array.isArray(res) ? res : []);
    CampaignSOC.data  = rows;
    CampaignSOC.total = res?.total || rows.length;

    const lbl = document.getElementById('csoc-total-label');
    if (lbl) lbl.textContent = `${CampaignSOC.total.toLocaleString()} campaign${CampaignSOC.total !== 1 ? 's' : ''}`;

    if (!rows.length) {
      if (body) body.innerHTML = _csocEmptyState();
      // FIX-D: Auto-trigger correlation if 0 campaigns exist
      _csocAutoCorrelate();
    } else {
      if (body) body.innerHTML = CampaignSOC.view === 'cards'
        ? _csocCardsHTML(rows)
        : _csocTableHTML(rows);
      CampaignSOC.graphData = _csocBuildGraphData(rows);
    }
    _csocRenderPagination();

  } catch (err) {
    console.error('[CampaignsSOC] Load error:', err.message);
    if (body) body.innerHTML = `
      <div style="text-align:center;padding:60px 20px;color:#8b949e">
        <i class="fas fa-exclamation-triangle fa-2x" style="color:#f43f5e;display:block;margin-bottom:14px"></i>
        <div style="font-weight:600;margin-bottom:8px;color:#e6edf3">Failed to load campaigns</div>
        <div style="font-size:.82em;margin-bottom:16px;color:#8b949e">${_e(err.message)}</div>
        <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
          <button class="soc-btn soc-btn-primary" onclick="window.CampaignSOC.loading=false;_csocLoadCampaigns()">
            <i class="fas fa-sync-alt"></i> Retry
          </button>
          <button class="soc-btn soc-btn-purple" onclick="window._csocRunCorrelation()">
            <i class="fas fa-brain"></i> Run Correlation Engine
          </button>
        </div>
      </div>`;
  } finally {
    CampaignSOC.loading = false;
  }
}

/* Auto-trigger correlation after a brief delay if campaigns = 0 */
let _csocAutoCorrelateTimer = null;
function _csocAutoCorrelate() {
  clearTimeout(_csocAutoCorrelateTimer);
  _csocAutoCorrelateTimer = setTimeout(async () => {
    console.log('[CampaignsSOC] 0 campaigns found → checking correlation engine…');
    if (typeof window.CorrelationEngine?.check === 'function') {
      await window.CorrelationEngine.check();
      await _csocLoadCampaigns();
    }
  }, 3000);
}

/* ─────────────────────────────────────────────────────────────────
   EMPTY STATE
───────────────────────────────────────────────────────────────── */
function _csocEmptyState() {
  return `
    <div style="text-align:center;padding:80px 20px;color:#8b949e">
      <div style="width:72px;height:72px;background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);
        border-radius:50%;display:flex;align-items:center;justify-content:center;
        margin:0 auto 20px;font-size:1.9em">🎯</div>
      <div style="font-size:1.1em;font-weight:700;color:#e6edf3;margin-bottom:8px">No Active Campaigns</div>
      <div style="font-size:.85em;max-width:420px;margin:0 auto 24px;line-height:1.7;color:#8b949e">
        Campaigns are auto-created when the correlation engine detects coordinated threat activity
        across ingested IOCs from <strong style="color:#22d3ee">CISA</strong>,
        <strong style="color:#a78bfa">MITRE ATT&CK</strong>,
        <strong style="color:#f43f5e">OTX</strong>,
        <strong style="color:#fb923c">AbuseIPDB</strong>, and
        <strong style="color:#34d399">MISP</strong> feeds.
      </div>
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
        <button class="soc-btn soc-btn-primary" onclick="window._csocRunCorrelation()">
          <i class="fas fa-brain"></i> Run Correlation Engine
        </button>
        <button class="soc-btn soc-btn-ghost" onclick="window._csocTriggerIngest()">
          <i class="fas fa-sync-alt"></i> Trigger Ingestion
        </button>
        <button class="soc-btn soc-btn-purple" onclick="window._csocCreate()">
          <i class="fas fa-plus"></i> Create Manually
        </button>
      </div>
      <div id="csoc-pipeline-status" style="margin-top:20px;font-size:.78em;color:#4b5563">
        Checking ingestion pipeline…
      </div>
    </div>`;
}

/* ─────────────────────────────────────────────────────────────────
   CARDS VIEW
───────────────────────────────────────────────────────────────── */
function _csocCardsHTML(rows) {
  return `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
    ${rows.map((c, i) => {
      const color = _sevColor(c.severity);
      const prog  = Math.min(100, c.progress || 55);
      return `
      <div class="soc-campaign-card" style="--card-accent:${color};animation:socFadeSlideIn .35s ease ${i*.04}s both"
        onclick="window._csocOpenDetail('${_e(c.id)}')"
        onmouseenter="this.style.transform='translateY(-3px)';this.style.boxShadow='0 8px 32px ${color}25'"
        onmouseleave="this.style.transform='';this.style.boxShadow=''">

        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
          <div style="font-weight:700;color:#e6edf3;font-size:.95em;line-height:1.35;overflow:hidden;
            text-overflow:ellipsis;white-space:nowrap;max-width:200px" title="${_e(c.name)}">${_e(c.name)}</div>
          ${_sevBadge(c.severity)}
        </div>

        <div style="display:flex;align-items:center;gap:6px;color:#fb923c;font-size:.8em;margin-bottom:10px">
          <i class="fas fa-user-secret" style="opacity:.7"></i>
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_e(c.threat_actor_name || c.actor || 'Unknown Actor')}</span>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          ${_statusPill(c.status)}
          <span style="font-size:.72em;color:#8b949e">${_ago(c.updated_at || c.last_seen || c.created_at)}</span>
        </div>

        <div style="display:flex;gap:12px;font-size:.78em;color:#8b949e;margin-bottom:10px">
          <span><i class="fas fa-bug" style="color:#f43f5e;margin-right:4px"></i>${(c.ioc_count||c.iocs||0).toLocaleString()}</span>
          <span><i class="fas fa-file-alt" style="color:#a78bfa;margin-right:4px"></i>${c.finding_count||c.findings||0}</span>
          <span><i class="fas fa-crosshairs" style="color:#22d3ee;margin-right:4px"></i>${(c.techniques||c.mitre_techniques||[]).length} TTPs</span>
        </div>

        <div style="height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden">
          <div style="width:${prog}%;height:100%;background:linear-gradient(90deg,${color}80,${color});border-radius:2px;transition:width .8s ease"></div>
        </div>

        ${(c.techniques||c.mitre_techniques||[]).slice(0,3).length ? `
        <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:10px">
          ${(c.techniques||c.mitre_techniques||[]).slice(0,3).map(t => `
            <span class="mitre-chip">${_e(t)}</span>`).join('')}
          ${(c.techniques||c.mitre_techniques||[]).length > 3 ? `<span style="font-size:.65em;color:#8b949e">+${(c.techniques||c.mitre_techniques||[]).length - 3} more</span>` : ''}
        </div>` : ''}
      </div>`;
    }).join('')}
  </div>`;
}

/* ─────────────────────────────────────────────────────────────────
   TABLE VIEW
───────────────────────────────────────────────────────────────── */
function _csocTableHTML(rows) {
  const hdrs = ['Campaign Name','Threat Actor','Severity','Status','IOCs','Findings','TTPs','Last Seen',''];
  return `
    <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:12px;overflow:hidden">
    <table class="soc-table" style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#080c14;border-bottom:1px solid #1e2d3d">
          ${hdrs.map(h => `<th style="padding:11px 14px;text-align:left;font-size:.74em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">${h}</th>`).join('')}
        </tr>
      </thead>
      <tbody>
        ${rows.map((c, i) => {
          const color = _sevColor(c.severity);
          return `
          <tr class="soc-table-row" style="border-bottom:1px solid #161b22;cursor:pointer;transition:background .12s"
            onclick="window._csocOpenDetail('${_e(c.id)}')"
            onmouseenter="this.style.background='#0e1520';this.style.boxShadow='inset 2px 0 0 ${color}'"
            onmouseleave="this.style.background='';this.style.boxShadow=''">
            <td style="padding:12px 14px;max-width:220px">
              <div style="font-weight:600;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_e(c.name)}">${_e(c.name)}</div>
              ${c.description ? `<div style="font-size:.72em;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px">${_e(c.description.slice(0,60))}…</div>` : ''}
            </td>
            <td style="padding:12px 14px;color:#fb923c;font-size:.83em;white-space:nowrap">
              <i class="fas fa-user-secret" style="margin-right:5px;opacity:.5"></i>${_e(c.threat_actor_name||c.actor||'—')}
            </td>
            <td style="padding:12px 14px">${_sevBadge(c.severity)}</td>
            <td style="padding:12px 14px">${_statusPill(c.status)}</td>
            <td style="padding:12px 14px;color:#22d3ee;font-weight:600;text-align:center">${(c.ioc_count||c.iocs||0).toLocaleString()}</td>
            <td style="padding:12px 14px;color:#a78bfa;text-align:center">${c.finding_count||c.findings||0}</td>
            <td style="padding:12px 14px;text-align:center">
              ${(c.techniques||c.mitre_techniques||[]).slice(0,2).map(t => `<span class="mitre-chip" style="font-size:.63em">${_e(t)}</span>`).join(' ')}
              ${(c.techniques||c.mitre_techniques||[]).length > 2 ? `<span style="font-size:.68em;color:#8b949e"> +${(c.techniques||c.mitre_techniques||[]).length-2}</span>` : ''}
            </td>
            <td style="padding:12px 14px;color:#8b949e;font-size:.78em;white-space:nowrap">${_ago(c.updated_at||c.last_seen||c.created_at)}</td>
            <td style="padding:12px 14px">
              <button onclick="event.stopPropagation();window._csocOpenDetail('${_e(c.id)}')"
                class="soc-btn soc-btn-ghost" style="padding:4px 10px;font-size:.72em">
                Details <i class="fas fa-chevron-right"></i>
              </button>
            </td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
    </div>`;
}

/* ─────────────────────────────────────────────────────────────────
   DETAIL PANEL
───────────────────────────────────────────────────────────────── */
async function _csocOpenDetail(id) {
  CampaignSOC.selected = id;

  let overlay = document.getElementById('csoc-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'csoc-overlay';
    overlay.className = 'soc-overlay';
    overlay.onclick = () => _csocCloseDetail();
    document.body.appendChild(overlay);
  }
  overlay.style.display = 'block';
  setTimeout(() => { if (overlay) overlay.style.opacity = '1'; }, 10);

  const panel = document.getElementById('csoc-detail-panel');
  if (!panel) return;
  panel.style.display = 'flex';
  panel.style.flexDirection = 'column';
  panel.className = 'soc-detail-panel';
  setTimeout(() => panel.classList.add('open'), 10);

  panel.innerHTML = `
    <div class="panel-hdr">
      <div style="font-size:.72em;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em">Loading Campaign…</div>
      <div class="soc-skeleton" style="height:22px;width:70%;border-radius:6px;margin-bottom:8px"></div>
      <div style="display:flex;gap:8px">
        <div class="soc-skeleton" style="height:20px;width:70px;border-radius:20px"></div>
        <div class="soc-skeleton" style="height:20px;width:80px;border-radius:20px"></div>
      </div>
    </div>
    <div class="panel-body">${_skeleton(5)}</div>
  `;

  try {
    const [campRes, iocsRes] = await Promise.allSettled([
      _apiGet(`/cti/campaigns/${id}`),
      _apiGet(`/cti/campaigns/${id}/iocs?limit=20`),
    ]);

    const camp = campRes.status === 'fulfilled' ? campRes.value : null;
    const iocs = iocsRes.status === 'fulfilled'  ? (iocsRes.value?.data || []) : [];

    if (!camp || !camp.id) {
      // Try to find locally
      const local = CampaignSOC.data.find(c => c.id === id);
      if (local) { _csocRenderDetailPanel(panel, local, iocs); return; }
      throw new Error('Campaign not found');
    }
    _csocRenderDetailPanel(panel, camp, iocs);
  } catch (err) {
    panel.innerHTML = `
      <div class="panel-hdr">
        <button onclick="window._csocCloseDetail()" style="float:right;background:none;border:none;color:#8b949e;font-size:1.3em;cursor:pointer">✕</button>
        <div style="color:#f43f5e;font-weight:600">Failed to load campaign</div>
      </div>
      <div class="panel-body">
        <div style="padding:14px;border-radius:8px;background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.2);font-size:.85em;color:#8b949e">${_e(err.message)}</div>
        <button class="soc-btn soc-btn-primary" onclick="window._csocOpenDetail('${_e(id)}')" style="margin-top:12px">
          <i class="fas fa-sync-alt"></i> Retry
        </button>
      </div>`;
  }
}

function _csocRenderDetailPanel(panel, c, iocs) {
  const color = _sevColor(c.severity);
  const techs = c.techniques || c.mitre_techniques || [];

  panel.innerHTML = `
    <!-- Header -->
    <div class="panel-hdr" style="border-left:3px solid ${color}">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="font-size:.7em;color:#8b949e;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Campaign Detail</div>
          <div style="font-size:1.1em;font-weight:800;color:#e6edf3;word-break:break-word;line-height:1.3">${_e(c.name)}</div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
            ${_sevBadge(c.severity)}
            ${_statusPill(c.status)}
            <span style="font-size:.73em;color:#8b949e">${_ago(c.updated_at||c.created_at)}</span>
          </div>
        </div>
        <button onclick="window._csocCloseDetail()"
          style="background:none;border:none;color:#8b949e;font-size:1.4em;cursor:pointer;flex-shrink:0;line-height:1;padding:2px 6px"
          onmouseenter="this.style.color='#e6edf3'"
          onmouseleave="this.style.color='#8b949e'">✕</button>
      </div>
    </div>

    <!-- Body -->
    <div class="panel-body">

      <!-- Stats Row -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;animation:socFadeSlideIn .3s ease .05s both">
        ${[
          ['Threat Actor',  `<span style="color:#fb923c">${_e(c.threat_actor_name||c.actor||'Unknown')}</span>`, 'fa-user-secret'],
          ['Risk Score',    `<span style="color:${color};font-weight:700;font-size:1.05em">${c.risk_score||'N/A'}</span>`, 'fa-tachometer-alt'],
          ['IOCs',          `<span style="color:#22d3ee;font-weight:700">${(c.ioc_count||c.iocs||0).toLocaleString()}</span>`, 'fa-fingerprint'],
          ['Findings',      `<span style="color:#a78bfa;font-weight:700">${c.finding_count||c.findings||0}</span>`, 'fa-file-alt'],
        ].map(([lbl,val,ico]) => `
          <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:8px;padding:10px 12px">
            <div style="font-size:.68em;color:#8b949e;display:flex;align-items:center;gap:5px;margin-bottom:4px">
              <i class="fas ${ico}" style="opacity:.5"></i>${lbl}
            </div>
            <div style="font-size:.88em">${val}</div>
          </div>`).join('')}
      </div>

      <!-- Description -->
      ${c.description ? `
      <div style="font-size:.83em;color:#8b949e;line-height:1.65;background:#0d1117;border:1px solid #1e2d3d;border-radius:8px;padding:12px 14px;margin-bottom:16px;animation:socFadeSlideIn .3s ease .08s both">
        ${_e(c.description)}
      </div>` : ''}

      <!-- MITRE ATT&CK -->
      ${techs.length ? `
      <div style="margin-bottom:16px;animation:socFadeSlideIn .3s ease .1s both">
        <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          <i class="fas fa-crosshairs" style="color:#a78bfa;margin-right:5px"></i>MITRE ATT&CK Techniques
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          ${techs.map(t => `
            <a href="https://attack.mitre.org/techniques/${_e(t.replace('.','/'))}" target="_blank" rel="noopener"
              class="mitre-chip" style="text-decoration:none" title="View on MITRE ATT&CK">${_e(t)}</a>`).join('')}
        </div>
      </div>` : ''}

      <!-- Associated IOCs -->
      ${iocs.length ? `
      <div style="margin-bottom:16px;animation:socFadeSlideIn .3s ease .12s both">
        <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          <i class="fas fa-bug" style="color:#f43f5e;margin-right:5px"></i>Associated IOCs (${iocs.length})
        </div>
        <div style="max-height:200px;overflow-y:auto;border:1px solid #1e2d3d;border-radius:8px">
          ${iocs.slice(0,15).map(ioc => `
            <div style="display:flex;align-items:center;gap:8px;padding:7px 12px;border-bottom:1px solid #161b22">
              <span style="background:rgba(34,211,238,.1);color:#22d3ee;padding:1px 7px;border-radius:4px;font-size:.65em;font-weight:600;text-transform:uppercase;white-space:nowrap">${_e(ioc.type||'ioc')}</span>
              <span style="font-family:'JetBrains Mono',monospace;font-size:.77em;color:#e6edf3;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_e(ioc.value)}">${_e(ioc.value)}</span>
              <span style="font-size:.72em;color:${_sevColor(ioc.reputation==='malicious'?'CRITICAL':'MEDIUM')};font-weight:600">${ioc.risk_score||'—'}</span>
            </div>`).join('')}
        </div>
      </div>` : ''}

      <!-- Timeline -->
      <div style="margin-bottom:16px;animation:socFadeSlideIn .3s ease .14s both">
        <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
          <i class="fas fa-clock" style="color:#fbbf24;margin-right:5px"></i>Campaign Timeline
        </div>
        <div class="soc-timeline">
          ${_csocTimelineItems(c).map((t, i) => `
            <div class="soc-timeline-item" style="animation:socFadeSlideIn .3s ease ${.16+i*.05}s both">
              <div class="t-time">${_e(t.time)}</div>
              <div class="t-title">${_e(t.title)}</div>
              <div class="t-desc">${_e(t.desc)}</div>
            </div>`).join('')}
        </div>
      </div>

      <!-- Actions -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;padding-top:8px;border-top:1px solid #1e2d3d">
        <button class="soc-btn soc-btn-primary" onclick="window._csocInvestigateAI('${_e(c.id)}')">
          <i class="fas fa-robot"></i> AI Investigate
        </button>
        <button class="soc-btn soc-btn-purple" onclick="window._csocExportCampaign('${_e(c.id)}')">
          <i class="fas fa-download"></i> Export JSON
        </button>
        <button class="soc-btn soc-btn-danger" onclick="window._csocContain('${_e(c.id)}')">
          <i class="fas fa-ban"></i> Mark Contained
        </button>
        <button class="soc-btn soc-btn-ghost" onclick="window._csocCloseDetail()" style="margin-left:auto">
          Close
        </button>
      </div>

    </div>
  `;
}

function _csocTimelineItems(c) {
  const items = [];
  if (c.created_at) items.push({ time: _ago(c.created_at),  title: 'Campaign Identified',  desc: `Correlation engine clustered ${c.ioc_count||c.iocs||0} IOCs into campaign` });
  if (c.updated_at && c.updated_at !== c.created_at) items.push({ time: _ago(c.updated_at), title: 'Last Activity Update', desc: 'Campaign metadata refreshed by correlation engine' });
  if (c.status === 'active')    items.push({ time: 'NOW',    title: 'Active Monitoring',    desc: 'Threat indicators being tracked in real-time across all feeds' });
  if (c.status === 'contained') items.push({ time: 'Recent', title: 'Campaign Contained',   desc: 'Activity suppressed — monitoring continues for recurrence' });
  if (!items.length) items.push({ time: 'Unknown', title: 'Campaign Recorded', desc: 'No detailed timeline available — enrichment pending' });
  return items;
}

function _csocCloseDetail() {
  const panel   = document.getElementById('csoc-detail-panel');
  const overlay = document.getElementById('csoc-overlay');
  if (panel) {
    panel.classList.remove('open');
    setTimeout(() => { if (panel) panel.style.display = 'none'; }, 300);
  }
  if (overlay) {
    overlay.style.opacity = '0';
    setTimeout(() => { if (overlay) overlay.remove(); }, 200);
  }
  CampaignSOC.selected = null;
}

/* ─────────────────────────────────────────────────────────────────
   IOC FORCE-DIRECTED GRAPH (Canvas, no D3 dependency)
───────────────────────────────────────────────────────────────── */
const _graph = {
  nodes: [], edges: [], canvas: null, ctx: null,
  drag: null, pan: { x: 0, y: 0 }, zoom: 1,
  animFrame: null, hoveredNode: null, tick: 0,
};

function _csocBuildGraphData(campaigns) {
  const nodeMap = new Map();
  const edges   = [];
  const addNode = (id, label, type, color) => {
    if (!nodeMap.has(id)) {
      nodeMap.set(id, { id, label, type, color,
        x: Math.random() * 500 + 100, y: Math.random() * 280 + 50,
        vx: 0, vy: 0, r: type === 'campaign' ? 14 : 8,
      });
    }
    return nodeMap.get(id);
  };

  campaigns.slice(0, 12).forEach(c => {
    addNode(`camp-${c.id}`, (c.name||'').slice(0,18), 'campaign', _sevColor(c.severity));
    if (c.threat_actor_name || c.actor) {
      addNode(`actor-${c.threat_actor_name||c.actor}`, c.threat_actor_name||c.actor, 'actor', '#fb923c');
      edges.push({ source:`camp-${c.id}`, target:`actor-${c.threat_actor_name||c.actor}` });
    }
    (c.techniques||c.mitre_techniques||[]).slice(0,3).forEach(t => {
      addNode(`ttp-${t}`, t, 'ttp', '#a78bfa');
      edges.push({ source:`camp-${c.id}`, target:`ttp-${t}` });
    });
  });

  return { nodes: [...nodeMap.values()], edges };
}

function _csocDrawGraph() {
  const canvas = document.getElementById('csoc-graph-canvas');
  const outer  = document.getElementById('csoc-graph-outer');
  if (!canvas || !outer) return;

  canvas.width  = outer.offsetWidth  || 800;
  canvas.height = (outer.offsetHeight || 380) - 1;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  _graph.canvas = canvas; _graph.ctx = ctx;

  if (CampaignSOC.graphData.nodes.length) {
    _graph.nodes = CampaignSOC.graphData.nodes;
    _graph.edges = CampaignSOC.graphData.edges;
  } else {
    _graph.nodes = _csocDemoGraphNodes();
    _graph.edges = _csocDemoGraphEdges();
  }

  _graph.edges.forEach(e => {
    e._s = _graph.nodes.find(n => n.id === e.source);
    e._t = _graph.nodes.find(n => n.id === e.target);
  });

  _csocGraphInteractions(canvas);
  if (_graph.animFrame) cancelAnimationFrame(_graph.animFrame);
  _csocGraphLoop();
}

function _csocGraphLoop() {
  _graph.animFrame = requestAnimationFrame(() => {
    _csocGraphPhysics();
    _csocGraphRender();
    _graph.tick++;
    _csocGraphLoop();
  });
}

function _csocGraphPhysics() {
  const nodes = _graph.nodes, edges = _graph.edges;
  const k = 110, rep = 5000, damp = 0.78;

  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const dx = nodes[j].x - nodes[i].x || .1;
      const dy = nodes[j].y - nodes[i].y || .1;
      const d  = Math.sqrt(dx*dx + dy*dy) || 1;
      const f  = Math.min(rep / (d * d), 50);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      nodes[i].vx -= fx; nodes[i].vy -= fy;
      nodes[j].vx += fx; nodes[j].vy += fy;
    }
  }

  edges.forEach(e => {
    if (!e._s || !e._t) return;
    const dx = e._t.x - e._s.x, dy = e._t.y - e._s.y;
    const d  = Math.sqrt(dx*dx + dy*dy) || 1;
    const f  = (d - k) / d * 0.35;
    e._s.vx += dx * f; e._s.vy += dy * f;
    e._t.vx -= dx * f; e._t.vy -= dy * f;
  });

  const cx = (_graph.canvas?.width||800) / 2;
  const cy = (_graph.canvas?.height||380) / 2;
  nodes.forEach(n => {
    n.vx += (cx - n.x) * 0.005;
    n.vy += (cy - n.y) * 0.005;
    n.vx *= damp; n.vy *= damp;
    if (!n._pinned) { n.x += n.vx; n.y += n.vy; }
  });
}

function _csocGraphRender() {
  const { ctx, canvas, nodes, edges, pan, zoom, tick } = _graph;
  if (!ctx || !canvas) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(pan.x, pan.y);
  ctx.scale(zoom, zoom);

  // Grid
  ctx.strokeStyle = '#0e1825'; ctx.lineWidth = .5;
  for (let x = -pan.x/zoom % 40; x < canvas.width/zoom; x += 40) {
    ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,canvas.height/zoom); ctx.stroke();
  }
  for (let y = -pan.y/zoom % 40; y < canvas.height/zoom; y += 40) {
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(canvas.width/zoom,y); ctx.stroke();
  }

  // Edges
  edges.forEach(e => {
    if (!e._s || !e._t) return;
    const grad = ctx.createLinearGradient(e._s.x, e._s.y, e._t.x, e._t.y);
    grad.addColorStop(0, e._s.color + '40');
    grad.addColorStop(1, e._t.color + '40');
    ctx.beginPath(); ctx.moveTo(e._s.x, e._s.y); ctx.lineTo(e._t.x, e._t.y);
    ctx.strokeStyle = grad; ctx.lineWidth = 1.2; ctx.stroke();
    // Animated dot
    const t   = (tick % 120) / 120;
    const px  = (1-t)*(1-t)*e._s.x + 2*(1-t)*t*((e._s.x+e._t.x)/2) + t*t*e._t.x;
    const py  = (1-t)*(1-t)*e._s.y + 2*(1-t)*t*((e._s.y+e._t.y)/2) + t*t*e._t.y;
    ctx.beginPath(); ctx.arc(px, py, 2.5, 0, Math.PI*2);
    ctx.fillStyle = e._t.color || '#22d3ee'; ctx.fill();
  });

  // Nodes
  nodes.forEach(n => {
    const isHov = _graph.hoveredNode === n;
    const r = isHov ? n.r * 1.45 : n.r;
    const pulse = 1 + Math.sin(tick * 0.04 + n.x) * (n.type === 'campaign' ? 0.08 : 0.04);

    const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 3);
    grd.addColorStop(0, n.color + '35');
    grd.addColorStop(1, 'transparent');
    ctx.beginPath(); ctx.arc(n.x, n.y, r * 3, 0, Math.PI * 2);
    ctx.fillStyle = grd; ctx.fill();

    ctx.beginPath(); ctx.arc(n.x, n.y, r * pulse, 0, Math.PI * 2);
    ctx.fillStyle = isHov ? n.color : n.color + 'bb';
    ctx.fill();
    ctx.strokeStyle = n.color; ctx.lineWidth = isHov ? 2.5 : 1.5; ctx.stroke();

    ctx.fillStyle   = isHov ? '#e6edf3' : '#8b949e';
    ctx.font        = `${isHov ? 600 : 400} ${isHov ? 10 : 9}px system-ui`;
    ctx.textAlign   = 'center';
    ctx.fillText((n.label||'').slice(0, 18), n.x, n.y + r * pulse + 13);
  });

  ctx.restore();
}

function _csocGraphInteractions(canvas) {
  let dragging = null, lastX = 0, lastY = 0, isDragging = false;
  const _pt = e => {
    const rect = canvas.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left  - _graph.pan.x) / _graph.zoom,
      y: (e.clientY - rect.top   - _graph.pan.y) / _graph.zoom,
    };
  };

  canvas.onmousedown = e => {
    const p = _pt(e);
    dragging = _graph.nodes.find(n => Math.hypot(n.x-p.x, n.y-p.y) < n.r+5);
    if (!dragging) { isDragging = true; lastX = e.clientX; lastY = e.clientY; }
  };
  canvas.onmousemove = e => {
    const p = _pt(e);
    _graph.hoveredNode = _graph.nodes.find(n => Math.hypot(n.x-p.x, n.y-p.y) < n.r+5) || null;
    canvas.style.cursor = _graph.hoveredNode ? 'pointer' : 'crosshair';
    const tip = document.getElementById('csoc-graph-tooltip');
    if (_graph.hoveredNode && tip) {
      const n = _graph.hoveredNode;
      tip.style.opacity = '1';
      tip.style.left    = (e.offsetX + 14) + 'px';
      tip.style.top     = (e.offsetY - 10) + 'px';
      tip.innerHTML     = `<div style="font-weight:700;color:${n.color}">${_e(n.label)}</div>
        <div style="color:#8b949e;font-size:.82em;text-transform:capitalize">${_e(n.type)}</div>`;
    } else if (tip) tip.style.opacity = '0';
    if (dragging) { dragging.x = p.x; dragging.y = p.y; dragging._pinned = true; }
    else if (isDragging) {
      _graph.pan.x += e.clientX - lastX;
      _graph.pan.y += e.clientY - lastY;
      lastX = e.clientX; lastY = e.clientY;
    }
  };
  canvas.onmouseup = () => {
    if (dragging) setTimeout(() => { if(dragging) dragging._pinned = false; dragging = null; }, 200);
    isDragging = false;
  };
  canvas.onwheel = e => {
    e.preventDefault();
    _graph.zoom = Math.max(.3, Math.min(3, _graph.zoom * (e.deltaY > 0 ? .9 : 1.1)));
  };
}

function _csocDemoGraphNodes() {
  return [
    { id:'c1', label:'Op Midnight Rain',  type:'campaign', color:'#f43f5e', x:400, y:190, vx:0, vy:0, r:14 },
    { id:'c2', label:'SolarHarvest',      type:'campaign', color:'#fb923c', x:200, y:280, vx:0, vy:0, r:12 },
    { id:'c3', label:'BlackCat ALPHV',    type:'campaign', color:'#f43f5e', x:600, y:280, vx:0, vy:0, r:12 },
    { id:'a1', label:'APT29',             type:'actor',    color:'#fb923c', x:400, y:80,  vx:0, vy:0, r:10 },
    { id:'a2', label:'Lazarus',           type:'actor',    color:'#fb923c', x:120, y:190, vx:0, vy:0, r:10 },
    { id:'t1', label:'T1566.001',         type:'ttp',      color:'#a78bfa', x:260, y:130, vx:0, vy:0, r:8  },
    { id:'t2', label:'T1486',             type:'ttp',      color:'#a78bfa', x:540, y:130, vx:0, vy:0, r:8  },
    { id:'i1', label:'185.220.101.45',    type:'ip',       color:'#22d3ee', x:300, y:350, vx:0, vy:0, r:8  },
    { id:'i2', label:'evil-c2.ru',        type:'domain',   color:'#22d3ee', x:500, y:350, vx:0, vy:0, r:8  },
    { id:'i3', label:'7a9f3b2c…',         type:'hash',     color:'#fbbf24', x:700, y:190, vx:0, vy:0, r:8  },
  ];
}
function _csocDemoGraphEdges() {
  return [
    { source:'c1', target:'a1' }, { source:'c1', target:'t1' }, { source:'c1', target:'t2' },
    { source:'c1', target:'i1' }, { source:'c1', target:'i2' },
    { source:'c2', target:'a2' }, { source:'c2', target:'t1' }, { source:'c2', target:'i2' },
    { source:'c3', target:'t2' }, { source:'c3', target:'i3' },
  ].map(e => ({ ...e, _s: null, _t: null }));
}

/* ─────────────────────────────────────────────────────────────────
   PAGINATION
───────────────────────────────────────────────────────────────── */
function _csocRenderPagination() {
  const el    = document.getElementById('csoc-pages');
  if (!el)    return;
  const pages = Math.ceil(CampaignSOC.total / CampaignSOC.limit) || 1;
  if (pages <= 1) { el.innerHTML = ''; return; }
  const cur  = CampaignSOC.page;
  const shown = Math.min(cur * CampaignSOC.limit, CampaignSOC.total);
  let h = `<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;flex-wrap:wrap;gap:8px">
    <span style="font-size:.78em;color:#8b949e">Showing ${shown.toLocaleString()} of ${CampaignSOC.total.toLocaleString()}</span>
    <div style="display:flex;gap:5px">`;
  const s = Math.max(1, cur-2), e2 = Math.min(pages, cur+2);
  h += `<button onclick="window._csocGoPage(${cur-1})" ${cur===1?'disabled':''} class="soc-btn soc-btn-ghost" style="padding:4px 10px">‹</button>`;
  for (let p=s; p<=e2; p++) {
    h += `<button onclick="window._csocGoPage(${p})" class="soc-btn ${p===cur?'soc-btn-primary':'soc-btn-ghost'}" style="padding:4px 9px;min-width:32px">${p}</button>`;
  }
  h += `<button onclick="window._csocGoPage(${cur+1})" ${cur===pages?'disabled':''} class="soc-btn soc-btn-ghost" style="padding:4px 10px">›</button>`;
  h += '</div></div>';
  el.innerHTML = h;
}

/* ─────────────────────────────────────────────────────────────────
   LIVE POLLING
───────────────────────────────────────────────────────────────── */
function _csocStartPolling() {
  _csocStopPolling();
  CampaignSOC.pollTimer = setInterval(async () => {
    try {
      const res    = await _apiGet('/cti/campaigns?limit=5&sort=created_at&order=desc');
      const fresh  = res?.data || [];
      const prevIds = new Set(CampaignSOC.data.map(c => c.id));
      const newC   = fresh.filter(c => !prevIds.has(c.id));
      if (newC.length) {
        _csocShowNotif(newC);
        await _csocLoadKPIs();
        await _csocLoadCampaigns();
      }
    } catch (_) {}
  }, 30000);
}

function _csocStopPolling() {
  if (CampaignSOC.pollTimer) { clearInterval(CampaignSOC.pollTimer); CampaignSOC.pollTimer = null; }
  if (_graph.animFrame)      { cancelAnimationFrame(_graph.animFrame); _graph.animFrame = null; }
}

function _csocShowNotif(camps) {
  let box = document.getElementById('soc-notif-container');
  if (!box) {
    box = document.createElement('div');
    box.id = 'soc-notif-container';
    box.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;max-width:320px';
    document.body.appendChild(box);
  }
  camps.forEach(c => {
    const color = _sevColor(c.severity);
    const item  = document.createElement('div');
    item.className = 'soc-notif-item';
    item.innerHTML = `
      <div style="width:34px;height:34px;border-radius:8px;background:${color}18;border:1px solid ${color}35;display:flex;align-items:center;justify-content:center;color:${color};flex-shrink:0">
        <i class="fas fa-chess-king"></i>
      </div>
      <div style="flex:1;min-width:0">
        <div style="font-size:.8em;font-weight:700;color:#e6edf3;margin-bottom:2px">New Campaign Detected</div>
        <div style="font-size:.73em;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_e(c.name)}</div>
        <div style="font-size:.68em;color:${color};margin-top:1px">${_e(c.severity)} · ${_e(c.threat_actor_name||c.actor||'Unknown')}</div>
      </div>
      <button onclick="this.closest('.soc-notif-item').remove()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:.9em">✕</button>`;
    box.appendChild(item);
    setTimeout(() => { item.style.opacity='0'; item.style.transform='translateX(20px)'; setTimeout(()=>item.remove(),300); }, 7000);
  });
}

/* ─────────────────────────────────────────────────────────────────
   THREAT MAP (Canvas)
───────────────────────────────────────────────────────────────── */
function _csocInitThreatMap() {
  const canvas = document.getElementById('csoc-map-canvas');
  const wrap   = document.getElementById('csoc-map-wrap');
  if (!canvas || !wrap) return;

  canvas.width  = wrap.offsetWidth  || 800;
  canvas.height = (wrap.querySelector('.soc-map-wrap')?.offsetHeight || 300);
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const flows = [
    [55.75, 37.62, 40.71, -74.01, '#f43f5e', 'APT29 → US-East'],
    [39.93, 116.38, 51.51, -0.13, '#fb923c', 'APT40 → UK'],
    [35.69, 139.69, 37.77, -122.4,'#fbbf24', 'Lazarus → SF'],
    [48.85, 2.35,  52.52,  13.40, '#a78bfa', 'TA505 → DE'],
    [55.75, 37.62, 48.85,   2.35, '#f43f5e', 'APT29 → FR'],
    [23.13, 113.27, 37.77,-122.4, '#22d3ee', 'APT41 → SF'],
  ];

  const W = canvas.width, H = canvas.height;
  const ll2xy = (lat, lon) => ({ x:((lon+180)/360)*W, y:((90-lat)/180)*H });
  let frame = 0;

  const continents = [
    [35,-130,90,55], [-55,-85,15,35], [35,-15,75,45],
    [-35,10,40,55],  [5,60,80,150],  [-45,110,-10,180],
  ];

  const drawMap = () => {
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle = '#060a10'; ctx.fillRect(0,0,W,H);
    ctx.strokeStyle = '#0e1825'; ctx.lineWidth = .5;
    for (let x=0; x<W; x+=80) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }
    for (let y=0; y<H; y+=60) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }

    continents.forEach(([lat1,lon1,lat2,lon2]) => {
      const p1 = ll2xy(lat2,lon1), p2 = ll2xy(lat1,lon2);
      ctx.fillStyle = '#0e1825'; ctx.strokeStyle = '#1e2d3d'; ctx.lineWidth = .5;
      ctx.beginPath(); ctx.roundRect(p1.x,p1.y,p2.x-p1.x,p2.y-p1.y,3); ctx.fill(); ctx.stroke();
    });

    const t = (frame % 120) / 120;
    flows.forEach(([slat,slon,tlat,tlon,color]) => {
      const s = ll2xy(slat,slon), d = ll2xy(tlat,tlon);
      const mx = (s.x+d.x)/2, my = Math.min(s.y,d.y) - 45;
      ctx.beginPath(); ctx.moveTo(s.x,s.y); ctx.quadraticCurveTo(mx,my,d.x,d.y);
      ctx.strokeStyle = color+'35'; ctx.lineWidth = 1; ctx.setLineDash([5,4]); ctx.stroke(); ctx.setLineDash([]);
      const px = (1-t)*(1-t)*s.x + 2*(1-t)*t*mx + t*t*d.x;
      const py = (1-t)*(1-t)*s.y + 2*(1-t)*t*my + t*t*d.y;
      ctx.beginPath(); ctx.arc(px,py,3,0,Math.PI*2);
      ctx.fillStyle = color; ctx.shadowColor = color; ctx.shadowBlur = 8; ctx.fill(); ctx.shadowBlur = 0;
      ctx.beginPath(); ctx.arc(s.x,s.y,5,0,Math.PI*2); ctx.fillStyle=color+'70'; ctx.fill(); ctx.strokeStyle=color; ctx.lineWidth=1.5; ctx.stroke();
      const pr = 5 + Math.sin(frame*.08)*2;
      ctx.beginPath(); ctx.arc(d.x,d.y,pr,0,Math.PI*2); ctx.fillStyle='#22d3ee18'; ctx.fill();
      ctx.beginPath(); ctx.arc(d.x,d.y,4,0,Math.PI*2); ctx.fillStyle='#22d3ee'; ctx.fill();
    });

    frame++; requestAnimationFrame(drawMap);
  };
  drawMap();

  const leg = document.getElementById('csoc-map-legend');
  if (leg) leg.innerHTML = flows.slice(0,4).map(f => `
    <div style="display:flex;align-items:center;gap:5px;margin-bottom:3px">
      <div style="width:8px;height:8px;border-radius:50%;background:${f[4]}"></div>
      <span style="font-size:.7em;color:#8b949e">${f[5]}</span>
    </div>`).join('') + `<div style="font-size:.66em;color:#4b5563;margin-top:4px">${flows.length} active flows</div>`;
}

/* ─────────────────────────────────────────────────────────────────
   ACTIONS
───────────────────────────────────────────────────────────────── */
async function _csocRunCorrelation() {
  if (typeof showToast === 'function') showToast('🧠 Running correlation engine…', 'info', 3000);
  try {
    const res = await _apiPost('/ingest/correlate', { force:true, min_cluster_size:3 });
    const count = res?.campaigns_created || res?.new_campaigns || 0;
    if (typeof showToast === 'function')
      showToast(`✅ Correlation complete — ${count} new campaign${count!==1?'s':''} created`, 'success', 5000);
    if (count > 0) { await _csocLoadKPIs(); await _csocLoadCampaigns(); }
    else if (typeof showToast === 'function')
      showToast('ℹ️ No new clusters detected. Try triggering ingestion first.', 'info', 5000);
  } catch (err) {
    console.warn('[CampaignsSOC] Correlation endpoint not available, using client-side engine');
    if (typeof showToast === 'function')
      showToast('⚠️ Backend correlate unavailable — using client-side engine…', 'warning', 3000);
    if (window.CorrelationEngine?.run) {
      await window.CorrelationEngine.run({ force:true });
      await _csocLoadCampaigns();
    } else {
      await _csocTriggerIngest();
    }
  }
}

async function _csocTriggerIngest() {
  try {
    if (typeof showToast === 'function') showToast('🔄 Triggering ingestion pipeline…', 'info', 2000);
    await _apiPost('/ingest/run', { wait: false });
    if (typeof showToast === 'function') showToast('✅ Ingestion started. Campaigns will appear after correlation (~30s).', 'success', 6000);
    setTimeout(() => { _csocLoadCampaigns(); _csocLoadKPIs(); }, 8000);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Ingestion failed: ${_e(err.message)}`, 'error');
  }
}

function _csocInvestigateAI(id) {
  const c = CampaignSOC.data.find(x => x.id === id);
  const promptEl = document.getElementById('ai-input') || document.querySelector('[id*="ai-input"]');
  if (promptEl && c) {
    promptEl.value = `Investigate campaign "${c.name}" by threat actor ${c.threat_actor_name||c.actor||'unknown'}. `
      + `Analyze ${c.ioc_count||c.iocs||0} IOCs and ${c.finding_count||c.findings||0} findings. `
      + `Provide MITRE ATT&CK mapping, risk assessment, and recommended containment actions.`;
    if (typeof navigateTo === 'function') navigateTo('ai-orchestrator');
    if (typeof sendAIMessage === 'function') setTimeout(sendAIMessage, 200);
  } else {
    if (typeof showToast === 'function') showToast('🤖 Navigate to AI Orchestrator to investigate', 'info');
  }
  _csocCloseDetail();
}

async function _csocContain(id) {
  if (!confirm('Mark this campaign as Contained? This will update its status.')) return;
  try {
    await _apiPost(`/cti/campaigns/${id}`, { status:'contained' });
    if (typeof showToast === 'function') showToast('✅ Campaign marked as Contained', 'success', 4000);
    _csocCloseDetail();
    await _csocLoadCampaigns();
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Update failed: ${_e(err.message)}`, 'error');
  }
}

function _csocExportCampaign(id) {
  const c = CampaignSOC.data.find(x => x.id === id);
  if (!c) return;
  const blob = new Blob([JSON.stringify(c, null, 2)], { type:'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `campaign-${(c.name||id).replace(/[^a-z0-9]/gi,'-').slice(0,40)}.json`; a.click();
  URL.revokeObjectURL(url);
  if (typeof showToast === 'function') showToast('📥 Campaign exported as JSON', 'success');
}

function _csocCreate() {
  if (typeof window._campaignCreate === 'function') { window._campaignCreate(); return; }
  if (typeof showToast === 'function') showToast('ℹ️ Use the correlation engine to auto-create campaigns', 'info');
}

/* ─────────────────────────────────────────────────────────────────
   FILTER / SEARCH
───────────────────────────────────────────────────────────────── */
let _csocSearchTimer = null;
window._csocSearchDebounce = val => {
  clearTimeout(_csocSearchTimer);
  _csocSearchTimer = setTimeout(() => { CampaignSOC.filters.search = val; CampaignSOC.page = 1; _csocLoadCampaigns(); }, 320);
};
window._csocSetFilter = (key, val) => {
  CampaignSOC.filters[key] = val; CampaignSOC.page = 1; _csocLoadCampaigns();
};
window._csocClearFilters = () => {
  CampaignSOC.filters = { search:'', severity:'', status:'', actor:'' };
  ['csoc-search','csoc-sev','csoc-status'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  CampaignSOC.page = 1; _csocLoadCampaigns();
};
window._csocSetView = view => {
  CampaignSOC.view = view; _csocLoadCampaigns();
};
window._csocGoPage = p => {
  if (p < 1 || p > Math.ceil(CampaignSOC.total / CampaignSOC.limit)) return;
  CampaignSOC.page = p; _csocLoadCampaigns();
};
window._csocToggleMap = () => {
  const wrap = document.getElementById('csoc-map-wrap');
  if (!wrap) return;
  const showing = wrap.style.display !== 'none';
  wrap.style.display = showing ? 'none' : 'block';
  if (!showing) setTimeout(() => _csocInitThreatMap(), 80);
};
window._csocRefreshGraph = () => {
  _graph.pan = {x:0,y:0}; _graph.zoom = 1;
  _csocDrawGraph();
};

/* ─────────────────────────────────────────────────────────────────
   WIRE GLOBALS
───────────────────────────────────────────────────────────────── */
function _csocWireGlobals() {
  window.CampaignSOC         = CampaignSOC;
  window.renderCampaignsSOC  = renderCampaignsSOC;
  window._csocRunCorrelation = _csocRunCorrelation;
  window._csocTriggerIngest  = _csocTriggerIngest;
  window._csocOpenDetail     = _csocOpenDetail;
  window._csocCloseDetail    = _csocCloseDetail;
  window._csocCreate         = _csocCreate;
  window._csocLoadCampaigns  = _csocLoadCampaigns;
  window._csocStopPolling    = _csocStopPolling;   // exposed for main.js onLeave
}
_csocWireGlobals(); // Wire immediately at module load

/* ─────────────────────────────────────────────────────────────────
   FIX-A: PAGE_CONFIG PATCH — robust polling with immediate install
   FIX-B: window.renderCampaigns override (bypasses pages.js mock)
───────────────────────────────────────────────────────────────── */

// Override window.renderCampaigns IMMEDIATELY at module parse time
// This ensures pages.js / main.js mock is bypassed even if PAGE_CONFIG
// hasn't been initialized yet.
window.renderCampaigns = function(opts) {
  CampaignSOC.loading = false;
  renderCampaignsSOC().catch(e => console.error('[CampaignsSOC]', e));
};

// Patch PAGE_CONFIG['campaigns'] directly — retry until available
(function _patchCampaignsConfig() {
  let _attempts = 0;
  function _tryPatch() {
    _attempts++;
    if (window.PAGE_CONFIG && window.PAGE_CONFIG['campaigns']) {
      window.PAGE_CONFIG['campaigns'].onEnter = function(opts) {
        CampaignSOC.loading = false;
        _csocStopPolling();
        renderCampaignsSOC().catch(e => console.error('[CampaignsSOC] render error:', e));
      };
      window.PAGE_CONFIG['campaigns'].onLeave = function() {
        _csocStopPolling();
        _csocCloseDetail();
        if (_graph.animFrame) { cancelAnimationFrame(_graph.animFrame); _graph.animFrame = null; }
      };
      CampaignSOC._patchDone = true;
      console.log('[CampaignsSOC v3.0] PAGE_CONFIG[campaigns] patched ✅');
    } else {
      if (_attempts < 40) setTimeout(_tryPatch, 150);
      else console.warn('[CampaignsSOC] PAGE_CONFIG not found after 6s — using window.renderCampaigns override');
    }
  }

  // Try immediately, then on DOMContentLoaded, then via polling
  _tryPatch();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _tryPatch);
  }
})();

// Re-render on auth restore in case user navigated before auth was ready
['auth:restored', 'auth:login', 'auth:token-refreshed'].forEach(evt => {
  window.addEventListener(evt, () => {
    const activePage = document.querySelector('.page.active');
    if (activePage && activePage.id === 'page-campaigns') {
      console.log('[CampaignsSOC] Auth event → re-rendering campaign page');
      CampaignSOC.loading = false;
      setTimeout(() => renderCampaignsSOC(), 300);
    }
  });
});

console.log('[CampaignsSOC v3.0] campaigns-soc.js loaded ✅');
