/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC-Grade Live Detections Module v3.0
 *  FILE: js/live-detections-soc.js
 *
 *  v3.0 Fixes (2026-04-02):
 *  ─────────────────────────
 *  FIX-A: window.renderDetections override installed IMMEDIATELY
 *         (bypasses pages.js / main.js mock renderDetections).
 *  FIX-B: PAGE_CONFIG['detections'] patched with robust retry loop
 *         instead of a single setTimeout that could fire too early.
 *  FIX-C: stopDetections() override so page-leave doesn't crash.
 *  FIX-D: Auth event listeners re-render if user navigated before
 *         auth was restored.
 *  FIX-E: _dApiGet passes paths correctly for window.authFetch.
 *
 *  Features:
 *  ─────────
 *  • Real-time detection feed (WebSocket + polling fallback)
 *  • Severity color-coded rows with CRITICAL glow pulse
 *  • Animated new-entry slide-in effect
 *  • Severity KPI counters at top
 *  • Filters: severity, type, source, search
 *  • Click-to-expand row detail with IOC + MITRE mapping
 *  • Event rate badge (events/sec)
 *  • Auto-link detections → campaigns → cases
 *  • CSV export
 *  • Zero mock data — 100% real backend
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────────── */
const DetectSOC = {
  page:     1,
  limit:    50,
  total:    0,
  filters:  { severity:'', type:'', search:'', source:'' },
  data:     [],
  loading:  false,
  wsConn:   null,
  pollTimer: null,
  rateCounter: { count:0, lastReset:Date.now(), rate:'0.0' },
  expanded: null,
  paused:   false,
  _patchDone: false,
};

window.DetectSOC = DetectSOC;

/* ─────────────────────────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────────────────────────── */
const _de = s => s == null ? '' : String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

// FIX-E: authFetch adds /api prefix, so pass path WITHOUT /api
function _dApiGet(path) {
  if (window.authFetch) return window.authFetch(path);
  const base = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const tok  = localStorage.getItem('wadjet_access_token') || '';
  return fetch(`${base}/api${path}`, {
    headers: { 'Content-Type':'application/json', ...(tok ? { Authorization:`Bearer ${tok}` } : {}) }
  }).then(r => {
    if (r.status === 204) return {};
    if (!r.ok) return Promise.reject(new Error(`HTTP ${r.status}`));
    return r.json();
  });
}

function _dago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function _dSevColor(sev) {
  return { CRITICAL:'#f43f5e', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#34d399', INFO:'#22d3ee' }[(sev||'').toUpperCase()] || '#8b949e';
}

function _dSevBadge(sev) {
  const c = _dSevColor(sev);
  return `<span style="background:${c}18;border:1px solid ${c}40;color:${c};padding:2px 8px;border-radius:4px;font-size:.68em;font-weight:700;text-transform:uppercase;letter-spacing:.04em">${_de(sev||'?')}</span>`;
}

function _dSkeleton(rows=6) {
  return `<div style="display:flex;flex-direction:column;gap:0">
    ${Array(rows).fill(0).map((_,i) => `
      <div class="soc-skeleton" style="height:48px;border-radius:0;margin-bottom:1px;animation-delay:${i*.04}s"></div>
    `).join('')}
  </div>`;
}

/* ─────────────────────────────────────────────────────────────────
   MAIN RENDER
───────────────────────────────────────────────────────────────── */
async function renderLiveDetectionsSOC() {
  const wrap = document.getElementById('soc-detections-wrap')
    || document.getElementById('detectionsLiveContainer')
    || document.getElementById('page-detections');

  if (!wrap) {
    console.warn('[DetectSOC] Container not found — retrying in 300ms');
    setTimeout(() => renderLiveDetectionsSOC(), 300);
    return;
  }

  // Hide legacy containers
  ['detectionsStream','detectionsLiveContainer'].forEach(id => {
    const el = document.getElementById(id);
    if (el && el !== wrap) el.style.display = 'none';
  });

  DetectSOC.loading = false;
  DetectSOC.paused  = false;

  wrap.innerHTML = `
    <div id="dsoc-root" style="padding:20px;min-height:100%;background:#080c14;font-family:system-ui,sans-serif">

      <!-- ── Header ── -->
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:20px">
        <div>
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <span style="display:flex;align-items:center;gap:2px;height:18px">
              ${[6,12,16,10,8].map((h,i) => `<div style="width:3px;height:${h}px;background:#34d399;border-radius:2px;animation:socWaveform .9s ease ${i*.12}s infinite"></div>`).join('')}
            </span>
            <h2 style="margin:0;font-size:1.3em;font-weight:800;color:#e6edf3;letter-spacing:-.02em">Live Detections</h2>
            <span id="dsoc-rate-badge" style="padding:3px 10px;background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.25);
              border-radius:20px;font-size:.68em;font-weight:700;color:#34d399">
              <span id="dsoc-rate">0.0</span> ev/s
            </span>
          </div>
          <p style="margin:0;color:#8b949e;font-size:.83em">
            Real-time security events across SIEM, EDR, and threat intelligence feeds
          </p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="soc-btn soc-btn-ghost" id="dsoc-pause-btn" onclick="window._dsocTogglePause()">
            <i class="fas fa-pause"></i> Pause
          </button>
          <button class="soc-btn soc-btn-ghost" onclick="window._dsocExportStream()">
            <i class="fas fa-download"></i> Export CSV
          </button>
          <button class="soc-btn soc-btn-ghost" onclick="window._dsocTriggerIngest()">
            <i class="fas fa-sync-alt"></i> Trigger Ingest
          </button>
          <button class="soc-btn soc-btn-primary" onclick="window._dsocRefresh()">
            <i class="fas fa-redo"></i> Refresh
          </button>
        </div>
      </div>

      <!-- ── Severity KPI Strip ── -->
      <div id="dsoc-kpis" style="display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap">
        ${[['critical','CRITICAL','#f43f5e'],['high','HIGH','#fb923c'],['medium','MEDIUM','#fbbf24'],['low','LOW','#34d399'],['info','INFO','#22d3ee']].map(([k,l,c]) => `
          <div style="flex:1;min-width:100px;background:#0d1117;border:1px solid ${c}25;border-radius:10px;padding:12px 14px;cursor:pointer;transition:all .15s"
            onmouseenter="this.style.borderColor='${c}60'" onmouseleave="this.style.borderColor='${c}25'"
            onclick="window._dsocFilter('severity','${l}')">
            <div style="font-size:.68em;color:${c};text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;font-weight:600">${l}</div>
            <div id="dsoc-cnt-${k}" style="font-size:1.5em;font-weight:800;color:#e6edf3">0</div>
          </div>`).join('')}
        <div style="flex:1;min-width:120px;background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:12px 14px">
          <div style="font-size:.68em;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;font-weight:600">Total Events</div>
          <div id="dsoc-total-lbl" style="font-size:1.5em;font-weight:800;color:#e6edf3">0</div>
        </div>
      </div>

      <!-- ── Filter Bar ── -->
      <div class="soc-filter-bar" style="margin-bottom:16px">
        <input id="dsoc-search" type="text" placeholder="🔍 Search events, IOCs, techniques…"
          style="flex:2;min-width:160px"
          oninput="window._dsocSearchDebounce(this.value)" />
        <select id="dsoc-sev" class="soc-select" onchange="window._dsocFilter('severity',this.value)">
          <option value="">All Severities</option>
          <option value="CRITICAL">🔴 Critical</option>
          <option value="HIGH">🟠 High</option>
          <option value="MEDIUM">🟡 Medium</option>
          <option value="LOW">🟢 Low</option>
          <option value="INFO">🔵 Info</option>
        </select>
        <select id="dsoc-type" class="soc-select" onchange="window._dsocFilter('type',this.value)">
          <option value="">All Types</option>
          <option value="malware">Malware</option>
          <option value="intrusion">Intrusion</option>
          <option value="phishing">Phishing</option>
          <option value="data_exfil">Data Exfil</option>
          <option value="lateral">Lateral Movement</option>
          <option value="ransomware">Ransomware</option>
        </select>
        <button class="soc-btn soc-btn-ghost" onclick="window._dsocClearFilters()">
          <i class="fas fa-times"></i> Clear
        </button>
        <span id="dsoc-filter-lbl" style="font-size:.78em;color:#8b949e;margin-left:auto;white-space:nowrap"></span>
      </div>

      <!-- ── Feed Table ── -->
      <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:12px;overflow:hidden">
        <table style="width:100%;border-collapse:collapse;font-size:.83em">
          <thead>
            <tr style="background:#080c14;border-bottom:1px solid #1e2d3d">
              ${['Time','Severity','Type','Description / IOC','Source','MITRE','Campaign','Actions'].map(h =>
                `<th style="padding:10px 12px;text-align:left;font-size:.7em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">${h}</th>`
              ).join('')}
            </tr>
          </thead>
          <tbody id="dsoc-feed-body">
            <tr><td colspan="8" style="padding:0">${_dSkeleton(8)}</td></tr>
          </tbody>
        </table>
      </div>

      <!-- ── Pagination ── -->
      <div id="dsoc-pages" style="margin-top:12px"></div>

      <!-- ── Empty State (hidden by default) ── -->
      <div id="dsoc-empty" style="display:none;text-align:center;padding:70px 20px">
        <div style="font-size:2.5em;margin-bottom:16px">📡</div>
        <div style="font-size:1em;font-weight:700;color:#e6edf3;margin-bottom:8px">No Detections Found</div>
        <div style="font-size:.84em;color:#8b949e;max-width:360px;margin:0 auto 20px;line-height:1.65">
          Live detections are streamed from your SIEM, EDR, and threat intelligence feeds.
          Trigger an ingestion run to populate this feed.
        </div>
        <button class="soc-btn soc-btn-primary" onclick="window._dsocTriggerIngest()">
          <i class="fas fa-sync-alt"></i> Trigger Ingestion
        </button>
      </div>

    </div>
  `;

  // Wire globals immediately
  _dsocWireGlobals();

  // Load data
  await Promise.allSettled([_dsocLoadKPIs(), _dsocLoadFeed()]);

  // Start live polling / WebSocket
  _dsocStartPolling();
}

/* ─────────────────────────────────────────────────────────────────
   KPI COUNTERS
───────────────────────────────────────────────────────────────── */
async function _dsocLoadKPIs() {
  try {
    const res  = await _dApiGet('/cti/detections?limit=200');
    const rows = res?.data || [];
    const counts = { critical:0, high:0, medium:0, low:0, info:0 };
    rows.forEach(r => {
      const k = (r.severity||'').toLowerCase();
      if (counts[k] !== undefined) counts[k]++;
    });
    Object.entries(counts).forEach(([k,v]) => {
      const el = document.getElementById(`dsoc-cnt-${k}`);
      if (el) el.textContent = v.toLocaleString();
    });
    const totEl = document.getElementById('dsoc-total-lbl');
    if (totEl) totEl.textContent = (res?.total || rows.length).toLocaleString();
    DetectSOC.total = res?.total || rows.length;
  } catch (_) {}
}

/* ─────────────────────────────────────────────────────────────────
   FEED LOADER
───────────────────────────────────────────────────────────────── */
async function _dsocLoadFeed() {
  if (DetectSOC.loading) return;
  DetectSOC.loading = true;

  const body = document.getElementById('dsoc-feed-body');
  if (body) body.innerHTML = `<tr><td colspan="8" style="padding:0">${_dSkeleton(8)}</td></tr>`;

  try {
    const f  = DetectSOC.filters;
    const qs = new URLSearchParams({
      page:  DetectSOC.page,
      limit: DetectSOC.limit,
      sort:  'created_at', order: 'desc',
      ...(f.severity ? { severity: f.severity } : {}),
      ...(f.type     ? { type:     f.type }     : {}),
      ...(f.search   ? { search:   f.search }   : {}),
      ...(f.source   ? { source:   f.source }   : {}),
    });

    const res  = await _dApiGet(`/cti/detections?${qs}`);
    const rows = Array.isArray(res?.data) ? res.data : (Array.isArray(res) ? res : []);

    DetectSOC.data  = rows;
    DetectSOC.total = res?.total || rows.length;

    const lbl = document.getElementById('dsoc-filter-lbl');
    if (lbl) lbl.textContent = `${DetectSOC.total.toLocaleString()} events`;

    const empty = document.getElementById('dsoc-empty');

    if (!rows.length) {
      if (body)  body.innerHTML = '';
      if (empty) empty.style.display = 'block';
    } else {
      if (empty) empty.style.display = 'none';
      if (body)  body.innerHTML = rows.map((r, i) => _dsocFeedRow(r, i)).join('');
    }

    _dsocRenderPages();
  } catch (err) {
    console.error('[DetectSOC] Feed load error:', err.message);
    if (document.getElementById('dsoc-feed-body')) {
      document.getElementById('dsoc-feed-body').innerHTML = `
        <tr><td colspan="8" style="padding:40px;text-align:center;color:#8b949e">
          <i class="fas fa-exclamation-triangle" style="color:#f43f5e;font-size:1.5em;display:block;margin-bottom:12px"></i>
          <div style="font-weight:600;color:#e6edf3;margin-bottom:6px">Failed to load detections</div>
          <div style="font-size:.83em;margin-bottom:14px">${_de(err.message)}</div>
          <button class="soc-btn soc-btn-primary" onclick="window.DetectSOC.loading=false;_dsocLoadFeed()">
            <i class="fas fa-sync-alt"></i> Retry
          </button>
        </td></tr>`;
    }
  } finally {
    DetectSOC.loading = false;
  }
}

/* ─────────────────────────────────────────────────────────────────
   FEED ROW RENDERER
───────────────────────────────────────────────────────────────── */
function _dsocFeedRow(r, idx) {
  const sev   = (r.severity || 'INFO').toUpperCase();
  const color = _dSevColor(sev);
  const isCrit = sev === 'CRITICAL';
  const id    = r.id || `r-${idx}`;

  return `
  <tr class="soc-feed-row" id="dsoc-row-${_de(id)}"
    style="border-bottom:1px solid #161b22;cursor:pointer;transition:background .12s;
      ${isCrit ? `animation:socFeedSlide .4s ease ${idx*.02}s both,socCritPulse 3s ease infinite` : `animation:socFeedSlide .4s ease ${idx*.02}s both`}"
    onclick="window._dsocToggleExpand('${_de(id)}')"
    onmouseenter="this.style.background='#0e1520';this.style.boxShadow='inset 2px 0 0 ${color}'"
    onmouseleave="this.style.background='';this.style.boxShadow=''">
    <td style="padding:9px 12px;white-space:nowrap;color:#8b949e;font-size:.77em">${_dago(r.created_at||r.timestamp)}</td>
    <td style="padding:9px 12px">${_dSevBadge(sev)}</td>
    <td style="padding:9px 12px;font-size:.77em;color:#8b949e;text-transform:capitalize;white-space:nowrap">${_de(r.type||r.event_type||'event')}</td>
    <td style="padding:9px 12px;max-width:280px">
      <div style="font-weight:500;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.88em" title="${_de(r.title||r.description||'')}">
        ${_de((r.title||r.description||r.message||'Security Event').slice(0,80))}
      </div>
      ${r.ioc_value ? `<div style="font-family:'JetBrains Mono',monospace;font-size:.73em;color:#22d3ee;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_de(r.ioc_value)}</div>` : ''}
    </td>
    <td style="padding:9px 12px;font-size:.77em;color:#8b949e;white-space:nowrap">${_de(r.source||r.sensor||'—')}</td>
    <td style="padding:9px 12px">
      ${r.mitre_technique ? `<span class="mitre-chip" style="font-size:.63em">${_de(r.mitre_technique)}</span>` : '<span style="color:#4b5563;font-size:.77em">—</span>'}
    </td>
    <td style="padding:9px 12px;font-size:.77em">
      ${r.campaign_name ? `<span style="color:#a78bfa;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;max-width:100px">${_de(r.campaign_name)}</span>` : '<span style="color:#4b5563">—</span>'}
    </td>
    <td style="padding:9px 12px;white-space:nowrap">
      <div style="display:flex;gap:4px">
        <button onclick="event.stopPropagation();window._dsocTagCampaign('${_de(id)}')"
          class="soc-btn soc-btn-ghost" style="padding:3px 7px;font-size:.68em" title="Link to campaign">
          <i class="fas fa-link"></i>
        </button>
        <button onclick="event.stopPropagation();window._dsocCreateCase('${_de(id)}')"
          class="soc-btn soc-btn-ghost" style="padding:3px 7px;font-size:.68em" title="Create case">
          <i class="fas fa-folder-plus"></i>
        </button>
      </div>
    </td>
  </tr>
  <tr id="dsoc-expand-${_de(id)}" style="display:none">
    <td colspan="8" style="padding:0;background:#0b0f1a;border-bottom:1px solid #1e2d3d">
      <!-- Expanded detail loaded on toggle -->
    </td>
  </tr>`;
}

function _dsocBuildExpandDetail(r) {
  const color = _dSevColor(r.severity);
  const techs = r.mitre_techniques || (r.mitre_technique ? [r.mitre_technique] : []);

  return `
    <div style="padding:16px 20px;display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px">
      <!-- Fields -->
      ${[
        ['Event ID',       r.id||'—',                          'fa-hashtag'],
        ['Source IP',      r.src_ip||r.source_ip||'—',         'fa-server'],
        ['Destination',    r.dst_ip||r.destination_ip||'—',    'fa-crosshairs'],
        ['IOC Value',      r.ioc_value||'—',                   'fa-bug'],
        ['IOC Type',       r.ioc_type||'—',                    'fa-tag'],
        ['Sensor/Source',  r.source||r.sensor||'—',            'fa-satellite-dish'],
        ['Campaign',       r.campaign_name||'Not linked',      'fa-chess-king'],
        ['Confidence',     r.confidence ? `${r.confidence}%` : '—', 'fa-percentage'],
      ].map(([l,v,ico]) => `
        <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:7px;padding:9px 12px">
          <div style="font-size:.67em;color:#8b949e;margin-bottom:3px"><i class="fas ${ico}" style="margin-right:4px;opacity:.5"></i>${l}</div>
          <div style="font-size:.83em;color:#e6edf3;word-break:break-all">${_de(v)}</div>
        </div>`).join('')}

      <!-- MITRE -->
      ${techs.length ? `
      <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:7px;padding:9px 12px;grid-column:1/-1">
        <div style="font-size:.67em;color:#8b949e;margin-bottom:6px"><i class="fas fa-crosshairs" style="margin-right:4px;color:#a78bfa;opacity:.7"></i>MITRE ATT&CK</div>
        <div style="display:flex;gap:5px;flex-wrap:wrap">
          ${techs.map(t => `<span class="mitre-chip" style="font-size:.68em">${_de(t)}</span>`).join('')}
        </div>
      </div>` : ''}

      <!-- Description -->
      ${(r.description||r.message) ? `
      <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:7px;padding:9px 12px;grid-column:1/-1">
        <div style="font-size:.67em;color:#8b949e;margin-bottom:4px"><i class="fas fa-align-left" style="margin-right:4px;opacity:.5"></i>Description</div>
        <div style="font-size:.83em;color:#8b949e;line-height:1.6">${_de(r.description||r.message)}</div>
      </div>` : ''}

      <!-- Action Buttons -->
      <div style="grid-column:1/-1;display:flex;gap:8px;flex-wrap:wrap;padding-top:8px;border-top:1px solid #1e2d3d">
        <button class="soc-btn soc-btn-primary" onclick="window._dsocCorrelateEvent('${_de(r.id||'')}')">
          <i class="fas fa-brain"></i> Correlate to Campaign
        </button>
        <button class="soc-btn soc-btn-purple" onclick="window._dsocCreateCase('${_de(r.id||'')}')">
          <i class="fas fa-folder-plus"></i> Create Case
        </button>
        <button class="soc-btn soc-btn-ghost" onclick="window._dsocTagCampaign('${_de(r.id||'')}')">
          <i class="fas fa-tags"></i> Tag Campaign
        </button>
      </div>
    </div>`;
}

/* ─────────────────────────────────────────────────────────────────
   ROW EXPAND / COLLAPSE
───────────────────────────────────────────────────────────────── */
window._dsocToggleExpand = function(id) {
  const expandRow = document.getElementById(`dsoc-expand-${id}`);
  if (!expandRow) return;

  const isOpen = expandRow.style.display !== 'none';
  // Close currently open
  if (DetectSOC.expanded) {
    const prev = document.getElementById(`dsoc-expand-${DetectSOC.expanded}`);
    if (prev) prev.style.display = 'none';
  }

  if (isOpen) {
    DetectSOC.expanded = null;
  } else {
    const r = DetectSOC.data.find(x => (x.id||'').toString() === id.toString());
    if (r) expandRow.querySelector('td').innerHTML = _dsocBuildExpandDetail(r);
    expandRow.style.display = 'table-row';
    expandRow.style.animation = 'socFadeSlideIn .25s ease';
    DetectSOC.expanded = id;
  }
};

/* ─────────────────────────────────────────────────────────────────
   LIVE INJECT (WebSocket / poll new events)
───────────────────────────────────────────────────────────────── */
function _dsocInjectLiveEvent(r) {
  const body = document.getElementById('dsoc-feed-body');
  if (!body || DetectSOC.paused) return;

  DetectSOC.data.unshift(r);
  if (DetectSOC.data.length > 200) DetectSOC.data.pop();
  DetectSOC.total++;

  const html = _dsocFeedRow(r, 0);
  const tmp  = document.createElement('tbody');
  tmp.innerHTML = html;

  // Insert new rows at top
  const firstRow = body.firstElementChild;
  [...tmp.children].reverse().forEach(el => {
    if (firstRow) body.insertBefore(el, firstRow);
    else body.appendChild(el);
  });

  // Trim excess
  const allRows = body.querySelectorAll('.soc-feed-row');
  if (allRows.length > 100) Array.from(allRows).slice(100).forEach(el => {
    const next = el.nextElementSibling;
    el.remove();
    if (next?.id?.startsWith('dsoc-expand-')) next.remove();
  });

  // Update counters
  _dsocUpdateRateBadge(1);
  _dsocUpdateSeverityCount(r.severity);

  // Hide empty state
  const empty = document.getElementById('dsoc-empty');
  if (empty) empty.style.display = 'none';
}

function _dsocUpdateRateBadge(n) {
  const now     = Date.now();
  const elapsed = (now - DetectSOC.rateCounter.lastReset) / 1000;
  DetectSOC.rateCounter.count += n;
  if (elapsed >= 5) {
    DetectSOC.rateCounter.rate = (DetectSOC.rateCounter.count / elapsed).toFixed(1);
    DetectSOC.rateCounter.count = 0;
    DetectSOC.rateCounter.lastReset = now;
  }
  const el = document.getElementById('dsoc-rate');
  if (el) el.textContent = DetectSOC.rateCounter.rate;
  const lbl = document.getElementById('dsoc-total-lbl');
  if (lbl) lbl.textContent = DetectSOC.total.toLocaleString();
}

function _dsocUpdateSeverityCount(sev) {
  if (!sev) return;
  const el = document.getElementById(`dsoc-cnt-${sev.toLowerCase()}`);
  if (el) el.textContent = String(parseInt(el.textContent || '0') + 1);
}

/* ─────────────────────────────────────────────────────────────────
   LIVE POLLING + SOCKET.IO REALTIME
   ROOT CAUSE FIX (v32.1):
   The backend uses Socket.IO (not raw WebSocket). Raw `new WebSocket()`
   to a Socket.IO server fails because Socket.IO uses its own HTTP-upgrade
   handshake at /socket.io/ — it does NOT accept connections at /ws/detections.
   Fix: use the shared `io()` connection from api-client.js WS module
   when socket.io-client is available, with a polling fallback.
───────────────────────────────────────────────────────────────── */

/** Maximum reconnect attempts before falling back permanently to polling */
const _DSOC_MAX_WS_RETRIES = 5;

function _dsocStartPolling() {
  _dsocStopPolling();
  // _dsocConnectWS is async — call without await so it doesn't block render.
  // Polling fallback in the setInterval will cover the gap if WS isn't ready.
  _dsocConnectWS().catch(err => console.warn('[DetectSOC] WS connect error:', err.message));
  // Polling fallback fires every 15 s when Socket.IO is not connected
  DetectSOC.pollTimer = setInterval(() => {
    if (!DetectSOC.paused && !DetectSOC.wsConn) _dsocPollNew();
  }, 15000);
}

/**
 * _dsocConnectWS — connect to the backend real-time stream.
 *
 * Strategy (in priority order):
 *  1. Reuse the shared window.WS socket from api-client.js if already
 *     connected. Uses WS.connectAsync() which refreshes the JWT first.
 *  2. Create a dedicated socket if WS module is unavailable.
 *  3. HTTP polling every 15 s if socket.io-client is not loaded.
 *
 * The backend (v3.2) accepts connections without a valid JWT (guest mode)
 * so a stale token does NOT cause a hard reject.
 */
/**
 * _dsocConnectWS — connect to the backend real-time stream.
 *
 * Strategy (in priority order):
 *  1. Reuse the shared window.WS socket from api-client.js if it is
 *     already connected — subscribe to `detection:event` on it and
 *     emit `detections:start`.  This avoids opening a duplicate socket.
 *  2. If window.WS exists but is not yet connected, call WS.connectAsync()
 *     which refreshes the JWT first, then connects via Socket.IO.
 *  3. If socket.io-client is unavailable, fall back to HTTP polling.
 *
 * The backend (websockets.js v3.2) allows connections without a valid
 * JWT (guest mode), so a stale or missing token will not cause a hard
 * connection failure — the client just gets limited access.
 */
async function _dsocConnectWS() {
  // Guard: already connected
  if (DetectSOC.wsConn) return;

  DetectSOC._wsRetries = DetectSOC._wsRetries || 0;

  // ── Strategy 1 & 2: Socket.IO via shared window.WS ─────────────
  if (typeof io !== 'undefined') {
    try {
      let socket = null;

      if (typeof window.WS !== 'undefined') {
        // Check if the shared socket is already live
        if (window.WS._socket?.connected) {
          socket = window.WS._socket;
          console.log('[DetectSOC] Reusing existing WS connection from api-client.js');
        } else {
          // connectAsync() refreshes token before connecting
          socket = await window.WS.connectAsync();
        }
      }

      // Fallback: create a dedicated socket if WS module is unavailable
      if (!socket) {
        const backendUrl = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
        const tok = _dsocGetToken();
        socket = io(backendUrl, {
          auth:                { token: tok },
          transports:          ['websocket', 'polling'],
          reconnection:        true,
          reconnectionAttempts: _DSOC_MAX_WS_RETRIES,
          reconnectionDelay:   3000,
          reconnectionDelayMax: 15000,
          timeout:             12000,
        });
      }

      // ── Wire up event handlers ────────────────────────────────
      const _onConnect = () => {
        DetectSOC.wsConn    = socket;
        DetectSOC._wsRetries = 0;
        console.log('[DetectSOC] Socket.IO connected ✅');
        socket.emit('detections:start');
        const badge = document.getElementById('dsoc-ws-badge');
        if (badge) { badge.textContent = '● Live'; badge.style.color = '#22c55e'; }
      };

      const _onDetection = evt => {
        if (!DetectSOC.paused && evt && (evt.id || evt.type)) {
          _dsocInjectLiveEvent(evt);
        }
      };

      const _onConnectError = async err => {
        console.warn('[DetectSOC] Socket.IO connect error:', err.message);
        DetectSOC.wsConn = null;
        DetectSOC._wsRetries++;

        // If auth-related, attempt token refresh and push new token to socket
        const isAuthErr = /auth|token|jwt|expired|invalid/i.test(err.message);
        if (isAuthErr && typeof window.TokenStore !== 'undefined' && window.TokenStore.canRefresh()) {
          console.info('[DetectSOC] Auth error — refreshing token…');
          const ok = await (typeof refreshAccessToken === 'function'
            ? refreshAccessToken()
            : window.TokenStore.canRefresh() && false); // no-op if not available
          if (ok && socket) {
            socket.auth = { token: _dsocGetToken() };
          }
        }

        if (DetectSOC._wsRetries >= _DSOC_MAX_WS_RETRIES) {
          console.warn('[DetectSOC] Max WS retries reached — switching to polling');
          try { socket.disconnect(); } catch(_) {}
          const badge = document.getElementById('dsoc-ws-badge');
          if (badge) { badge.textContent = '◌ Polling'; badge.style.color = '#f59e0b'; }
        }
      };

      const _onDisconnect = reason => {
        DetectSOC.wsConn = null;
        console.log('[DetectSOC] Socket.IO disconnected:', reason);
        const badge = document.getElementById('dsoc-ws-badge');
        if (badge) { badge.textContent = '◌ Reconnecting…'; badge.style.color = '#f59e0b'; }
      };

      // Handle server-sent token expiry notification (from websockets.js v3.2)
      const _onTokenExpired = () => {
        console.warn('[DetectSOC] Server notified: token expired — triggering refresh');
        if (typeof window.TokenStore !== 'undefined' && window.TokenStore.canRefresh()) {
          // Use global refreshAccessToken if available (from api-client.js IIFE)
          const refreshFn = typeof refreshAccessToken === 'function'
            ? refreshAccessToken
            : null;
          if (refreshFn) {
            refreshFn().then(ok => {
              if (ok && socket) {
                const tok = _dsocGetToken();
                socket.auth = { token: tok };
                socket.emit('auth:refresh', { token: tok });
              }
            });
          }
        }
      };

      // Only add listeners if not already wired (avoid duplicates on reuse)
      if (socket !== window.WS?._socket || !socket._dsocListened) {
        socket.on('connect',          _onConnect);
        socket.on('detection:event',  _onDetection);
        socket.on('connect_error',    _onConnectError);
        socket.on('disconnect',       _onDisconnect);
        socket.on('auth:token_expired', _onTokenExpired);
        socket._dsocListened = true;
      }

      // If already connected, fire onConnect immediately
      if (socket.connected) _onConnect();

      // Store reference so _dsocStopPolling can close it
      DetectSOC._ioSocket = socket;

      return; // Socket.IO strategy initiated — polling acts as safety net
    } catch (err) {
      console.warn('[DetectSOC] Socket.IO init error:', err.message, '— falling back to polling');
    }
  } else {
    console.warn('[DetectSOC] socket.io-client not loaded — using polling fallback');
  }

  // ── Strategy 3: HTTP polling fallback ──────────────────────────
  const badge = document.getElementById('dsoc-ws-badge');
  if (badge) { badge.textContent = '◌ Polling'; badge.style.color = '#f59e0b'; }
}

/**
 * _dsocGetToken — retrieve the best available auth token.
 * Uses window.TokenStore (api-client.js) as primary source so it
 * is always consistent with the authenticated session.  Falls back
 * to checking all known storage keys directly.
 */
function _dsocGetToken() {
  // Primary: use the shared TokenStore from api-client.js
  if (typeof window.TokenStore !== 'undefined' && window.TokenStore.get) {
    const t = window.TokenStore.get();
    if (t) return t;
  }
  // Fallback: check all known storage keys used by various auth modules
  return sessionStorage.getItem('we_access_token')
      || localStorage.getItem('we_access_token')
      || sessionStorage.getItem('wadjet_access_token')
      || localStorage.getItem('wadjet_access_token')
      || localStorage.getItem('sb-access-token')
      || '';
}

async function _dsocPollNew() {
  try {
    const res     = await _dApiGet('/cti/detections?limit=10&sort=created_at&order=desc');
    const rows    = res?.data || [];
    const prevIds = new Set(DetectSOC.data.map(r => r.id));
    const fresh   = rows.filter(r => !prevIds.has(r.id));
    fresh.forEach(r => _dsocInjectLiveEvent(r));
  } catch (_) {}
}

function _dsocStopPolling() {
  if (DetectSOC.pollTimer) { clearInterval(DetectSOC.pollTimer); DetectSOC.pollTimer = null; }
  // Stop socket.io detection stream
  if (DetectSOC._ioSocket) {
    try { DetectSOC._ioSocket.emit('detections:stop'); } catch(_) {}
    // Only disconnect if we created it (not the shared WS.socket)
    if (DetectSOC._ioSocket !== (typeof window.WS !== 'undefined' ? window.WS._socket : null)) {
      try { DetectSOC._ioSocket.disconnect(); } catch(_) {}
    }
    DetectSOC._ioSocket = null;
  }
  DetectSOC.wsConn = null;
}

/* ─────────────────────────────────────────────────────────────────
   PAGINATION
───────────────────────────────────────────────────────────────── */
function _dsocRenderPages() {
  const el    = document.getElementById('dsoc-pages');
  if (!el)    return;
  const pages = Math.ceil(DetectSOC.total / DetectSOC.limit) || 1;
  if (pages <= 1) { el.innerHTML = ''; return; }
  const cur  = DetectSOC.page;
  let h = `<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;flex-wrap:wrap;gap:8px">
    <span style="font-size:.78em;color:#8b949e">Page ${cur} of ${pages} — ${DetectSOC.total.toLocaleString()} events</span>
    <div style="display:flex;gap:5px">`;
  const s = Math.max(1, cur-2), e2 = Math.min(pages, cur+2);
  h += `<button onclick="window._dsocGoPage(${cur-1})" ${cur===1?'disabled':''} class="soc-btn soc-btn-ghost" style="padding:4px 10px">‹</button>`;
  for (let p=s; p<=e2; p++)
    h += `<button onclick="window._dsocGoPage(${p})" class="soc-btn ${p===cur?'soc-btn-primary':'soc-btn-ghost'}" style="padding:4px 9px;min-width:32px">${p}</button>`;
  h += `<button onclick="window._dsocGoPage(${cur+1})" ${cur===pages?'disabled':''} class="soc-btn soc-btn-ghost" style="padding:4px 10px">›</button>`;
  h += '</div></div>';
  el.innerHTML = h;
}

/* ─────────────────────────────────────────────────────────────────
   ACTIONS
───────────────────────────────────────────────────────────────── */
window._dsocGoPage = p => { DetectSOC.page = p; _dsocLoadFeed(); };

window._dsocTogglePause = function() {
  DetectSOC.paused = !DetectSOC.paused;
  const btn = document.getElementById('dsoc-pause-btn');
  if (btn) {
    btn.innerHTML = DetectSOC.paused
      ? '<i class="fas fa-play"></i> Resume'
      : '<i class="fas fa-pause"></i> Pause';
    btn.className = `soc-btn ${DetectSOC.paused ? 'soc-btn-danger' : 'soc-btn-ghost'}`;
  }
};

window._dsocRefresh = function() {
  DetectSOC.loading = false;
  _dsocLoadFeed();
  _dsocLoadKPIs();
};

window._dsocExportStream = function() {
  if (!DetectSOC.data.length) {
    if (typeof showToast === 'function') showToast('No data to export', 'warning'); return;
  }
  const headers = ['id','severity','type','title','ioc_value','ioc_type','source','mitre_technique','campaign_name','created_at'];
  const rows    = DetectSOC.data.map(r => headers.map(h => `"${String(r[h]||'').replace(/"/g,'""')}"`).join(','));
  const csv     = [headers.join(','), ...rows].join('\n');
  const blob    = new Blob([csv], { type:'text/csv' });
  const url     = URL.createObjectURL(blob);
  const a       = document.createElement('a');
  a.href = url; a.download = `detections-${new Date().toISOString().slice(0,10)}.csv`; a.click();
  URL.revokeObjectURL(url);
  if (typeof showToast === 'function') showToast(`📥 Exported ${DetectSOC.data.length} events`, 'success');
};

window._dsocTriggerIngest = async function() {
  try {
    if (typeof showToast === 'function') showToast('🔄 Triggering ingestion…', 'info', 2000);
    if (window.authFetch) await window.authFetch('/ingest/run', { method:'POST', body: JSON.stringify({ wait:false }) });
    if (typeof showToast === 'function') showToast('✅ Ingestion triggered — events will appear shortly', 'success', 5000);
    setTimeout(() => { _dsocLoadFeed(); _dsocLoadKPIs(); }, 8000);
  } catch (e) {
    if (typeof showToast === 'function') showToast(`❌ ${e.message}`, 'error');
  }
};

window._dsocTagCampaign = async function(id) {
  const row = DetectSOC.data.find(r => (r.id||'').toString() === id.toString());
  if (!row) return;
  if (typeof showToast === 'function') showToast('🔗 Correlating event with campaigns…', 'info', 2000);
  try {
    if (window.authFetch)
      await window.authFetch(`/cti/detections/${id}/correlate`, { method:'POST', body: JSON.stringify({ auto:true }) });
    if (typeof showToast === 'function') showToast('✅ Event correlated to active campaigns', 'success', 3000);
    await _dsocLoadFeed();
  } catch (err) {
    if (typeof showToast === 'function') showToast(`⚠️ ${err.message}`, 'warning');
  }
};

window._dsocCreateCase = function(id) {
  const row = DetectSOC.data.find(r => (r.id||'').toString() === id.toString());
  if (typeof window.createCaseFromFinding === 'function' && row) {
    window.createCaseFromFinding(row);
  } else {
    if (typeof navigateTo === 'function') navigateTo('case-management');
    if (typeof showToast === 'function') showToast('📁 Navigate to Case Management to create a case', 'info');
  }
};

window._dsocCorrelateEvent = async function(id) {
  try {
    if (window.authFetch)
      await window.authFetch(`/cti/detections/${id}/correlate`, { method:'POST', body: JSON.stringify({ auto:true }) });
    if (typeof showToast === 'function') showToast('✅ Event correlated to campaign cluster', 'success');
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Correlation failed: ${err.message}`, 'error');
  }
};

/* ─────────────────────────────────────────────────────────────────
   FILTER / SEARCH
───────────────────────────────────────────────────────────────── */
let _dsocSearchTimer = null;
window._dsocSearchDebounce = val => {
  clearTimeout(_dsocSearchTimer);
  _dsocSearchTimer = setTimeout(() => { DetectSOC.filters.search = val; DetectSOC.page = 1; _dsocLoadFeed(); }, 320);
};
window._dsocFilter = (key, val) => {
  DetectSOC.filters[key] = val; DetectSOC.page = 1; _dsocLoadFeed();
  // Sync the select
  const selMap = { severity:'dsoc-sev', type:'dsoc-type' };
  if (selMap[key]) { const el = document.getElementById(selMap[key]); if(el) el.value = val; }
};
window._dsocClearFilters = () => {
  DetectSOC.filters = { severity:'', type:'', search:'', source:'' };
  ['dsoc-search','dsoc-sev','dsoc-type'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
  DetectSOC.page = 1; _dsocLoadFeed();
};

/* ─────────────────────────────────────────────────────────────────
   WIRE GLOBALS
───────────────────────────────────────────────────────────────── */
function _dsocWireGlobals() {
  window.DetectSOC             = DetectSOC;
  window.renderLiveDetectionsSOC = renderLiveDetectionsSOC;
}
_dsocWireGlobals(); // Wire at module parse time

/* ─────────────────────────────────────────────────────────────────
   FIX-A: Override window.renderDetections IMMEDIATELY
   FIX-B: PAGE_CONFIG['detections'] patch with robust retry
   FIX-C: Override stopDetections safely
───────────────────────────────────────────────────────────────── */

// Override window.renderDetections immediately (bypasses pages.js mock)
window.renderDetections = function() {
  DetectSOC.loading = false;
  renderLiveDetectionsSOC().catch(e => console.error('[DetectSOC]', e));
};

// Override renderLiveDetections (used by live-pages.js)
window.renderLiveDetections = function() {
  DetectSOC.loading = false;
  renderLiveDetectionsSOC().catch(e => console.error('[DetectSOC]', e));
};

// Safe stopDetections override (FIX-C)
window.stopDetections = function() {
  _dsocStopPolling();
};

// PAGE_CONFIG patch with robust retry loop
(function _patchDetectionsConfig() {
  let _attempts = 0;
  function _tryPatch() {
    _attempts++;
    if (window.PAGE_CONFIG && window.PAGE_CONFIG['detections']) {
      window.PAGE_CONFIG['detections'].onEnter = function() {
        DetectSOC.loading = false;
        _dsocStopPolling();
        renderLiveDetectionsSOC().catch(e => console.error('[DetectSOC] render error:', e));
      };
      window.PAGE_CONFIG['detections'].onLeave = function() {
        _dsocStopPolling();
      };
      DetectSOC._patchDone = true;
      console.log('[DetectSOC v3.0] PAGE_CONFIG[detections] patched ✅');
    } else {
      if (_attempts < 40) setTimeout(_tryPatch, 150);
      else console.warn('[DetectSOC] PAGE_CONFIG not found after 6s — using window.renderDetections override');
    }
  }
  _tryPatch();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', _tryPatch);
})();

// FIX-D: Re-render on auth events if on detections page
['auth:restored', 'auth:login', 'auth:token-refreshed', 'auth:token_refreshed'].forEach(evt => {
  window.addEventListener(evt, (e) => {
    // After a token refresh, push the new token to the active WS socket
    if (evt === 'auth:token_refreshed' && DetectSOC._ioSocket) {
      const tok = _dsocGetToken();
      try {
        DetectSOC._ioSocket.auth = { token: tok };
        // Re-authenticate the socket with the server
        DetectSOC._ioSocket.emit('auth:refresh', { token: tok });
      } catch (_) {}
    }

    const activePage = document.querySelector('.page.active');
    if (activePage && activePage.id === 'page-detections') {
      DetectSOC.loading = false;
      setTimeout(() => renderLiveDetectionsSOC(), 300);
    }
  });
});

console.log('[DetectSOC v3.0] live-detections-soc.js loaded ✅');
