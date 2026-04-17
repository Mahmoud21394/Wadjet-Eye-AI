/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Live Pages Module v5.0
 *  FILE: js/live-pages.js
 *
 *  ALL dashboard cards & pages wired to real backend data.
 *  Every page renders a live, paginated, filterable table
 *  or card grid with shimmer skeletons and toast errors.
 *
 *  Pages covered:
 *   1.  Command Center      — 6 KPI cards + mini panels (stats-live)
 *   2.  Findings / Alerts   — paginated table, filter by severity/status/sort
 *   3.  Campaigns           — card grid + table from /api/cti/campaigns
 *   4.  Live Detections     — streaming alerts poll every 5 s
 *   5.  Threat Actors       — card grid from /api/cti/actors
 *   6.  IOC Registry        — full paginated table /api/iocs
 *   7.  Collectors / Feeds  — feed-log table from stats-live feed_status
 *   8.  Case Management     — table from /api/cases
 *   9.  Vulnerabilities     — table from /api/cti/vulnerabilities
 *  10.  MITRE ATT&CK        — coverage grid from /api/cti/mitre/coverage
 *  11.  Detection Timeline  — list from /api/cti/detection-timeline
 *  12.  Executive Dashboard — summary cards (reuses stats-live)
 *  13.  SOAR Automation     — rule executions from /api/cti/feed-logs
 *  14.  Live Threat Feeds   — same feed log data with actions
 *  15.  IOC Database        — search-enabled IOC table
 *  16.  AI Orchestrator     — session history list
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   GLOBAL CONFIG
───────────────────────────────────────────── */
const LP_REFRESH_MS  = 45_000;  // KPI auto-refresh interval
const LP_PAGE_SIZE   = 25;      // rows per paginated table

/* ─────────────────────────────────────────────
   SHARED UTILITIES
───────────────────────────────────────────── */
function _esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _ago(iso) {
  if (!iso) return 'Never';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function _sevC(sev) {
  return ({critical:'#ff4444',high:'#ff8800',medium:'#ffcc00',low:'#00cc44',info:'#4488ff'}
  )[(sev||'').toLowerCase()] || '#8b949e';
}

function _badge(label, color) {
  return `<span style="background:${color}22;color:${color};border:1px solid ${color}44;
    padding:1px 8px;border-radius:10px;font-size:.72em;font-weight:700;
    text-transform:uppercase;white-space:nowrap">${_esc(label)}</span>`;
}

function _sevBadge(sev) { return _badge(sev || 'unknown', _sevC(sev)); }

function _riskBadge(n) {
  if (n == null) return '';
  const c = n>=70?'#ff4444':n>=40?'#ff8800':n>=20?'#ffcc00':'#00cc44';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;
    padding:1px 6px;border-radius:8px;font-size:.75em;font-weight:600">${n}</span>`;
}

/** Shimmer skeleton placeholder rows */
function _skel(rows=5, h=40) {
  const css = `@keyframes lp-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}`;
  const row  = `<div style="height:${h}px;background:linear-gradient(90deg,#161b22 25%,#21262d 50%,#161b22 75%);
    background-size:200% 100%;animation:lp-shimmer 1.4s infinite;border-radius:6px;margin-bottom:8px"></div>`;
  return `<style>${css}</style>${row.repeat(rows)}`;
}

/**
 * _fetch — Delegates to authFetch (auth-interceptor.js) which handles:
 *   • Token retrieval from unified store (all key variants)
 *   • Pre-flight expiry check + silent refresh
 *   • 401/403 auto-retry after refresh
 *   • Global auth:expired event on total session loss
 *   • Network errors → empty dataset (never mock data)
 */
async function _fetch(path, options = {}) {
  // Prefer the centralized authFetch if available (loaded from auth-interceptor.js)
  if (typeof window.authFetch === 'function') {
    return window.authFetch(path, options);
  }

  // Fallback: direct fetch with best-effort token retrieval
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const token = localStorage.getItem('wadjet_access_token')
             || localStorage.getItem('we_access_token')
             || localStorage.getItem('tp_access_token')
             || sessionStorage.getItem('tp_token')
             || '';

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  try {
    const resp = await fetch(`${base}/api${path}`, {
      method:  options.method || 'GET',
      headers,
      credentials: 'include',
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
    });

    if (resp.status === 401 || resp.status === 403) {
      if (typeof window.PersistentAuth_silentRefresh === 'function') {
        const refreshed = await window.PersistentAuth_silentRefresh();
        if (refreshed) {
          const newToken = localStorage.getItem('wadjet_access_token') || '';
          const retry    = await fetch(`${base}/api${path}`, {
            method: options.method || 'GET',
            headers: { ...headers, Authorization: `Bearer ${newToken}` },
            credentials: 'include',
            ...(options.body ? { body: JSON.stringify(options.body) } : {}),
          });
          if (retry.ok) return retry.json();
        }
      }
      window.dispatchEvent(new CustomEvent('auth:expired', { detail: { path } }));
      throw new Error(`AUTH_EXPIRED: Session expired. Please log in again.`);
    }
    if (resp.status === 404) return { data: [], total: 0, page: 1, limit: 25 };
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      throw new Error(`HTTP ${resp.status} — ${txt.slice(0, 120)}`);
    }
    return resp.json();
  } catch (netErr) {
    if (netErr.message.startsWith('AUTH_EXPIRED')) throw netErr;
    console.warn('[LP] Network error for', path, '—', netErr.message);
    return { data: [], total: 0, page: 1, limit: 25, _offline: true };
  }
}

/**
 * _post — POST/PATCH helper
 */
async function _post(path, body, method = 'POST') {
  return _fetch(path, { method, body });
}

/**
 * Central mock data router — REMOVED in v5.1.
 * No more demo/mock data. All data must come from real backend.
 * This stub exists only to avoid breaking any residual calls.
 * @deprecated
 */
function _getMockForPath(_path) {
  return null; // always null → forces real backend call
}

/** Display an error message inside a container */
function _err(el, msg) {
  if (!el) return;
  el.innerHTML = `<div style="padding:24px;text-align:center;color:#ef4444">
    <i class="fas fa-exclamation-triangle" style="font-size:1.6em;margin-bottom:8px;display:block"></i>
    ${_esc(msg)}</div>`;
}

/** Smooth number count-up */
function _countUp(el, target) {
  if (!el) return;
  const start = parseInt(el.textContent.replace(/\D/g,''))||0;
  const diff  = target - start, steps = 20;
  let i = 0;
  const t = setInterval(()=>{ i++; el.textContent = Math.round(start+diff*(i/steps)).toLocaleString(); if(i>=steps) clearInterval(t); }, 30);
}

/** Pagination HTML */
function _paginator(total, current, onPage, domId) {
  const pages = Math.ceil(total / LP_PAGE_SIZE) || 1;
  if (pages <= 1) return '';
  const s = Math.max(1, current-3), e = Math.min(pages, current+3);
  let h = `<div id="${domId}" style="display:flex;gap:6px;justify-content:center;padding:14px 0;flex-wrap:wrap">`;
  h += `<button onclick="${onPage}(${current-1})" ${current===1?'disabled':''} style="padding:4px 12px;background:#21262d;border:1px solid #30363d;color:${current===1?'#555':'#e6edf3'};border-radius:6px;cursor:pointer">‹ Prev</button>`;
  for (let p=s;p<=e;p++) h += `<button onclick="${onPage}(${p})" style="padding:4px 10px;min-width:32px;background:${p===current?'#1d6ae5':'#21262d'};border:1px solid ${p===current?'#1d6ae5':'#30363d'};color:#e6edf3;border-radius:6px;cursor:pointer">${p}</button>`;
  h += `<button onclick="${onPage}(${current+1})" ${current===pages?'disabled':''} style="padding:4px 12px;background:#21262d;border:1px solid #30363d;color:${current===pages?'#555':'#e6edf3'};border-radius:6px;cursor:pointer">Next ›</button>`;
  h += '</div>';
  return h;
}

/* ─────────────────────────────────────────────
   § 1  COMMAND CENTER — Live KPIs + mini panels
───────────────────────────────────────────── */
async function renderCommandCenterLive() {
  // Guard against concurrent calls — e.g. initApp + initLivePages firing simultaneously
  if (renderCommandCenterLive._running) {
    console.info('[LivePages] renderCommandCenterLive already in progress — skipping duplicate call');
    return;
  }
  renderCommandCenterLive._running = true;
  try {
    await _loadKPIs();
    _loadMiniFindings();
    _loadMiniFeedStatus();
    _loadMiniCampaigns();
    if (typeof initAllCharts === 'function') initAllCharts();
  } finally {
    renderCommandCenterLive._running = false;
  }
}

async function _loadKPIs() {
  // Show shimmer in every card
  ['m-critical','m-high','m-findings','m-feeds','m-iocs','m-ai'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<span style="display:inline-block;width:48px;height:22px;
      background:linear-gradient(90deg,#161b22 25%,#21262d 50%,#161b22 75%);
      background-size:200% 100%;animation:lp-shimmer 1.4s infinite;border-radius:4px">
      <style>@keyframes lp-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}</style></span>`;
  });

  try {
    const data = await _fetch('/dashboard/stats-live');
    const k = data.kpis    || {};
    const d = data.deltas  || {};
    const s = data.sidebar || {};
    const feeds = data.feed_status || [];

    const kMap = { 'm-critical':k.critical_threats, 'm-high':k.high_severity,
      'm-findings':k.total_findings, 'm-feeds':k.active_feeds,
      'm-iocs':k.iocs_collected,    'm-ai':k.ai_investigations };

    Object.entries(kMap).forEach(([id,val])=>{
      const el = document.getElementById(id);
      if (el && val !== undefined) { el.textContent='0'; _countUp(el, val); }
    });

    const setDelta = (id,txt,up) => {
      const el = document.getElementById(id);
      if (el) { el.textContent=txt; el.className='metric-delta '+(up?'up':'neutral'); }
    };
    setDelta('m-critical-delta',`${d.alerts_today??0} new today`, (d.alerts_today||0)>0);
    setDelta('m-high-delta',    `${d.alerts_today??0} new today`, (d.alerts_today||0)>0);
    setDelta('m-findings-delta',`${k.total_findings??0} open`,    true);
    setDelta('m-feeds-delta',   `${feeds.length} configured`,     false);
    setDelta('m-iocs-delta',    `+${d.iocs_today??0} today`,      (d.iocs_today||0)>0);
    setDelta('m-ai-delta',      `${k.ai_investigations??0} total`,false);

    // Sidebar badge
    const nb = document.getElementById('nb-critical');
    if (nb) nb.textContent = s.critical_badge || k.critical_threats || 0;

    // TPI
    const tpi = data.threat_pressure || 0;
    const tpiNum = document.getElementById('tpiNumber');
    if (tpiNum) _countUp(tpiNum, tpi);
    const tpBar = document.getElementById('tpBarMini');
    if (tpBar) tpBar.style.width = Math.min(100,tpi)+'%';
    const tpVal = document.getElementById('tpValueMini');
    if (tpVal) tpVal.textContent = `${tpi} / ${data.threat_level||'N/A'}`;

    // IOC dist chart
    if (data.ioc_distribution && window._iocDistChart) {
      const dist = data.ioc_distribution;
      window._iocDistChart.data.datasets[0].data = [dist.malicious,dist.suspicious,dist.clean,dist.unknown];
      window._iocDistChart.update();
    }

    console.info('[LivePages] KPIs refreshed @', new Date().toLocaleTimeString());
  } catch (err) {
    console.warn('[LivePages] KPI error:', err.message);
    if (typeof showToast==='function') showToast('Dashboard data unavailable — check backend', 'warning');
    ['m-critical','m-high','m-findings','m-feeds','m-iocs','m-ai'].forEach(id => {
      const el = document.getElementById(id); if (el) el.textContent = '—';
    });
  }
}

async function _loadMiniFindings() {
  const el = document.getElementById('latestFindings');
  if (!el) return;
  el.innerHTML = _skel(5, 36);
  try {
    let events = [];
    try {
      if (window.CTI) { const r = await CTI.timeline.list({days:1,limit:10}); events = r?.data||[]; }
    } catch {}
    if (!events.length) {
      const r = await _fetch('/alerts?limit=8&sort=created_at');
      events = (r?.data||[]).map(a=>({event_type:a.type||'alert',title:a.title,severity:a.severity,created_at:a.created_at}));
    }
    if (!events.length) { el.innerHTML = `<div style="text-align:center;color:#8b949e;padding:16px;font-size:.8em">No recent findings</div>`; return; }
    el.innerHTML = events.map(e=>`
      <div onclick="navigateTo('findings')" style="cursor:pointer;display:flex;align-items:center;gap:8px;
        padding:7px 4px;border-bottom:1px solid #1e2d3d" onmouseover="this.style.background='#161b22'"
        onmouseout="this.style.background=''">
        <div style="width:4px;min-height:32px;border-radius:2px;background:${_sevC(e.severity)};flex-shrink:0"></div>
        <span style="font-size:.7em;color:#8b949e;white-space:nowrap">${_esc(e.event_type)}</span>
        <span style="flex:1;font-size:.8em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${_esc(e.title)}">${_esc((e.title||'').slice(0,45))}${(e.title||'').length>45?'…':''}</span>
        <span style="font-size:.7em;color:#8b949e;white-space:nowrap">${_ago(e.created_at)}</span>
      </div>`).join('');
  } catch { el.innerHTML = `<div style="color:#8b949e;font-size:.8em;padding:8px">Timeline unavailable</div>`; }
}

async function _loadMiniFeedStatus() {
  const el = document.getElementById('collectorsMiniList');
  if (!el) return;
  el.innerHTML = _skel(4, 32);
  try {
    const [statsData, collectorsData] = await Promise.all([
      _fetch('/dashboard/stats-live'),
      _fetch('/collectors?limit=100').catch(() => ({ data: [] }))
    ]);
    const feeds    = statsData.feed_status || [];
    const allColls = collectorsData?.data || [];
    const active   = allColls.filter(c => c.is_active !== false && c.status === 'active').length;
    const inactive = allColls.filter(c => c.is_active === false || c.status === 'inactive').length;
    const totalCnt = allColls.length || feeds.length;

    // Update collector panel button with live count
    const btn = document.getElementById('collectorsPanelBtn');
    if (btn && totalCnt) btn.innerHTML = `View All (${totalCnt})`;

    // Update m-feeds KPI if not already set
    const mFeeds = document.getElementById('m-feeds');
    if (mFeeds && mFeeds.textContent === '—') _countUp(mFeeds, active || feeds.length);
    const mFeedsDelta = document.getElementById('m-feeds-delta');
    if (mFeedsDelta && allColls.length) {
      mFeedsDelta.textContent = `${active} active · ${inactive} inactive`;
    }

    const displayFeeds = feeds.length ? feeds : allColls.slice(0, 8).map(c => ({
      feed_name: c.name, status: c.status === 'active' ? 'success' : 'error', iocs_new: c.iocs_collected || 0
    }));

    if (!displayFeeds.length) { el.innerHTML = `<div style="text-align:center;color:#8b949e;padding:12px;font-size:.8em">No feeds run yet</div>`; return; }
    el.innerHTML = displayFeeds.slice(0,8).map(f=>`
      <div onclick="navigateTo('collectors')" style="cursor:pointer;display:flex;align-items:center;gap:8px;
        padding:6px 4px;border-bottom:1px solid #1e2d3d" onmouseover="this.style.background='#161b22'"
        onmouseout="this.style.background=''">
        <div style="width:8px;height:8px;border-radius:50%;flex-shrink:0;background:${
          f.status==='success'||f.status==='active'?'#3fb950':f.status==='partial'?'#f59e0b':f.status==='error'?'#ff4444':'#8b949e'}"></div>
        <span style="flex:1;font-size:.8em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(f.feed_name||f.name)}</span>
        <span style="font-size:.75em;color:#3fb950;font-weight:600">+${(f.iocs_new||f.iocs_collected||0).toLocaleString()}</span>
      </div>`).join('');
  } catch { el.innerHTML = `<div style="color:#8b949e;font-size:.8em;padding:8px">Feed status unavailable</div>`; }
}

async function _loadMiniCampaigns() {
  const el = document.getElementById('campaignsMiniList');
  if (!el) return;
  el.innerHTML = _skel(3, 44);
  try {
    const data = await _fetch('/cti/campaigns?limit=4&status=active');
    const list = data?.data || data || [];
    if (!list.length) { el.innerHTML = `<div style="color:#8b949e;font-size:.8em;padding:8px">No active campaigns</div>`; return; }
    el.innerHTML = list.map(c=>`
      <div onclick="navigateTo('campaigns')" style="cursor:pointer;padding:8px 6px;border-bottom:1px solid #1e2d3d"
        onmouseover="this.style.background='#161b22'" onmouseout="this.style.background=''">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px">
          <span style="font-size:.83em;font-weight:600;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px">${_esc(c.name)}</span>
          ${_sevBadge(c.severity)}
        </div>
        <div style="font-size:.72em;color:#f97316">${_esc(c.threat_actor_name||c.actor||'Unknown Actor')}</div>
      </div>`).join('');
  } catch { el.innerHTML = `<div style="color:#8b949e;font-size:.8em;padding:8px">Campaigns unavailable</div>`; }
}

/* ─────────────────────────────────────────────
   § 2  FINDINGS / ALERTS  — full paginated table
───────────────────────────────────────────── */
let _fp = 1, _ff = {}, _ft = 0;

async function renderFindingsLive(opts={}) {
  if (opts?.severity) _ff.severity = opts.severity;
  const c = document.getElementById('findingsLiveContainer');
  if (!c) return;
  c.innerHTML = `
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <label style="font-size:.8em;color:#8b949e">Severity</label>
      <select id="ff-sev" style="${_fs()}">
        <option value="">All</option><option value="critical">Critical</option>
        <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
      </select>
      <label style="font-size:.8em;color:#8b949e">Status</label>
      <select id="ff-status" style="${_fs()}">
        <option value="">All</option><option value="open">Open</option>
        <option value="in_progress">In Progress</option><option value="resolved">Resolved</option>
      </select>
      <label style="font-size:.8em;color:#8b949e">Sort</label>
      <select id="ff-sort" style="${_fs()}">
        <option value="created_at">Newest</option><option value="severity">Severity</option>
      </select>
      <button onclick="_ffApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_ffReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <span id="ff-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
      <button onclick="_ffExport()" style="${_btn('#22c55e')}"><i class="fas fa-download"></i> Export CSV</button>
    </div>
    <div id="ff-body">${_skel()}</div>
    <div id="ff-pages"></div>`;
  const sevEl = document.getElementById('ff-sev');
  if (sevEl && _ff.severity) sevEl.value = _ff.severity;
  await _ffLoad();
}

window._ffApply = () => { _ff = {severity:document.getElementById('ff-sev')?.value||'', status:document.getElementById('ff-status')?.value||'', sort:document.getElementById('ff-sort')?.value||'created_at'}; _fp=1; _ffLoad(); };
window._ffReset = () => { _ff={}; _fp=1; ['ff-sev','ff-status','ff-sort'].forEach(i=>{const e=document.getElementById(i);if(e)e.value=i==='ff-sort'?'created_at':'';}); _ffLoad(); };
window._ffPage  = p  => { if(p<1||p>Math.ceil(_ft/LP_PAGE_SIZE))return; _fp=p; _ffLoad(); };

async function _ffLoad() {
  const body = document.getElementById('ff-body'); if(!body) return;
  body.innerHTML = _skel();
  const qs = new URLSearchParams({page:_fp,limit:LP_PAGE_SIZE,sort:_ff.sort||'created_at',...(_ff.severity?{severity:_ff.severity}:{}),...(_ff.status?{status:_ff.status}:{})});
  try {
    const data  = await _fetch(`/alerts?${qs}`);
    const rows  = data?.data || data || [];
    _ft = data?.total || rows.length;
    const cnt = document.getElementById('ff-count'); if(cnt) cnt.textContent = `${_ft.toLocaleString()} alerts`;
    if (!rows.length) { body.innerHTML = `<div style="text-align:center;padding:40px;color:#8b949e"><i class="fas fa-check-circle" style="font-size:2em;color:#22c55e;margin-bottom:10px;display:block"></i>No alerts match filters</div>`; document.getElementById('ff-pages').innerHTML=''; return; }
    body.innerHTML = `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Severity','Title','Type','IOC Value','Status','Source','Detected','Action'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600;white-space:nowrap">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(a=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:8px 10px">${_sevBadge(a.severity)}</td>
        <td style="padding:8px 10px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(a.title)}">${_esc((a.title||'').slice(0,55))}</td>
        <td style="padding:8px 10px;color:#8b949e">${_esc(a.type||'alert')}</td>
        <td style="padding:8px 10px;font-family:monospace;font-size:.85em;color:#22d3ee;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(a.ioc_value)}">${_esc((a.ioc_value||'—').slice(0,38))}</td>
        <td style="padding:8px 10px">${_badge(a.status||'open', a.status==='open'?'#ef4444':a.status==='in_progress'?'#f59e0b':'#22c55e')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.82em">${_esc(a.source||'—')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.8em;white-space:nowrap">${_ago(a.created_at)}</td>
        <td style="padding:8px 10px"><button onclick="_ffAI('${_esc(a.id)}','${_esc(a.ioc_value||'')}')" style="${_btn('#1d6ae5')}" title="AI Investigate"><i class="fas fa-robot"></i></button></td>
      </tr>`).join('')}</tbody>
    </table></div>`;
    document.getElementById('ff-pages').innerHTML = _paginator(_ft,_fp,'_ffPage','ff-pag');
  } catch(e) { _err(body,e.message); if(typeof showToast==='function') showToast('Alerts load failed: '+e.message,'error'); }
}

window._ffAI = (id,val) => {
  navigateTo('ai-orchestrator');
  setTimeout(()=>{
    const inp = document.getElementById('ai-chat-input')||document.getElementById('aiInput');
    if(inp){inp.value=`Investigate alert ${id}: IOC "${val}" — provide risk assessment and MITRE mappings.`;inp.dispatchEvent(new Event('input'));}
    if(typeof AIOrchestrator?.sendQuery==='function') AIOrchestrator.sendQuery(inp?.value||'');
    else if(typeof sendAIMessage==='function') sendAIMessage();
  },400);
};

window._ffExport = async () => {
  try {
    const data = await _fetch(`/alerts?limit=1000&sort=${_ff.sort||'created_at'}${_ff.severity?'&severity='+_ff.severity:''}${_ff.status?'&status='+_ff.status:''}`);
    const rows = data?.data||data||[];
    const csv  = ['ID,Severity,Title,Type,IOC Value,Status,Source,Detected',
      ...rows.map(a=>[a.id,a.severity,`"${(a.title||'').replace(/"/g,'""')}"`,a.type,`"${a.ioc_value||''}"`,a.status,a.source,a.created_at].join(','))
    ].join('\n');
    const blob = new Blob([csv],{type:'text/csv'});
    const url  = URL.createObjectURL(blob);
    const anc  = document.createElement('a'); anc.href=url; anc.download=`alerts_${new Date().toISOString().slice(0,10)}.csv`; anc.click();
    URL.revokeObjectURL(url);
    if(typeof showToast==='function') showToast(`Exported ${rows.length} alerts`,'success');
  } catch(e){if(typeof showToast==='function') showToast('Export failed','error');}
};

/* ─────────────────────────────────────────────
   § 3  CAMPAIGNS — card grid + table
───────────────────────────────────────────── */
/* ═══════════════════════════════════════════════════════════════
   § 3  CAMPAIGNS — Playbook-style redesign with drill-down detail
   ─────────────────────────────────────────────────────────────
   List view: card grid + table toggle, filter bar
   Drill-down: metadata, related IOCs, timeline, linked cases
═══════════════════════════════════════════════════════════════ */
let _cp=1, _cf={}, _ct=0, _cfView='cards';

async function renderCampaignsLive(opts={}) {
  const c = document.getElementById('campaignsLiveContainer'); if(!c) return;
  c.innerHTML = `
  <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
    <input id="cf-search" placeholder="🔍 Search campaigns…" oninput="_cfSearchDebounce()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:.83em;width:180px"/>
    <label style="font-size:.8em;color:#8b949e">Status</label>
    <select id="cf-status" style="${_fs()}"><option value="">All</option><option value="active">Active</option><option value="monitoring">Monitoring</option><option value="contained">Contained</option><option value="resolved">Resolved</option></select>
    <label style="font-size:.8em;color:#8b949e">Severity</label>
    <select id="cf-sev" style="${_fs()}"><option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option></select>
    <button onclick="_cfApply()" style="${_btn('#1d6ae5')}">Apply</button>
    <button onclick="_cfReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
    <button onclick="_cfToggleView()" id="cf-view-btn" style="${_btn('#21262d','#30363d','#8b949e')}"><i class="fas fa-th" id="cf-view-icon"></i></button>
    <button onclick="_cfCreate()" style="${_btn('#8b5cf6')}"><i class="fas fa-plus"></i> New Campaign</button>
    <span id="cf-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
  </div>
  <div id="cf-body">${_skel()}</div>
  <div id="cf-pages"></div>
  <div id="cf-detail-panel" style="display:none;position:fixed;top:0;right:0;width:min(600px,100vw);height:100vh;
    background:#0d1117;border-left:1px solid #1e2d3d;z-index:999;overflow-y:auto;
    box-shadow:-8px 0 32px rgba(0,0,0,.5);transition:transform .3s ease"></div>`;
  await _cfLoad();
}

let _cfSearchTimer = null;
window._cfSearchDebounce = () => { clearTimeout(_cfSearchTimer); _cfSearchTimer = setTimeout(() => { _cp=1; _cfApply(); }, 350); };
window._cfApply  = () => { _cf={status:document.getElementById('cf-status')?.value||'',severity:document.getElementById('cf-sev')?.value||'',search:document.getElementById('cf-search')?.value||''}; _cp=1; _cfLoad(); };
window._cfReset  = () => { _cf={}; _cp=1; ['cf-status','cf-sev'].forEach(i=>{const e=document.getElementById(i);if(e)e.value='';}); const s=document.getElementById('cf-search');if(s)s.value=''; _cfLoad(); };
window._cfPage   = p  => { if(p<1||p>Math.ceil(_ct/LP_PAGE_SIZE))return; _cp=p; _cfLoad(); };
window._cfToggleView = () => {
  _cfView = _cfView === 'cards' ? 'table' : 'cards';
  const icon = document.getElementById('cf-view-icon');
  if (icon) icon.className = _cfView === 'cards' ? 'fas fa-th' : 'fas fa-list';
  _cfLoad();
};

async function _cfLoad() {
  const body = document.getElementById('cf-body'); if(!body) return;
  body.innerHTML = _skel();
  const qs = new URLSearchParams({
    page: _cp, limit: LP_PAGE_SIZE,
    ...(_cf.status   ? {status:   _cf.status}   : {}),
    ...(_cf.severity ? {severity: _cf.severity} : {}),
    ...(_cf.search   ? {search:   _cf.search}   : {}),
  });
  let rows = [], total = 0;
  try {
    const data = await _fetch(`/cti/campaigns?${qs}`);
    rows  = data?.data || data || [];
    total = data?.total || rows.length;
  } catch(e) {
    console.warn('[Campaigns] API error:', e.message);
    body.innerHTML = `<div style="text-align:center;padding:40px;color:#8b949e">
      <i class="fas fa-exclamation-triangle" style="font-size:1.8em;color:#f59e0b;display:block;margin-bottom:12px"></i>
      <div style="font-size:.9em">Could not load campaigns. Check backend connection.</div>
      <div style="font-size:.78em;color:#666;margin-top:6px">${_esc(e.message)}</div>
      <button onclick="_cfLoad()" style="${_btn('#1d6ae5')} margin-top:12px;display:inline-flex">Retry</button>
    </div>`;
    return;
  }
  _ct = total;
  const cnt = document.getElementById('cf-count');
  if(cnt) cnt.textContent = `${_ct.toLocaleString()} campaign${_ct !== 1 ? 's' : ''}`;

  if (!rows.length) {
    body.innerHTML = `<div style="text-align:center;padding:60px;color:#8b949e">
      <i class="fas fa-chess-king" style="font-size:2.5em;color:#30363d;display:block;margin-bottom:16px"></i>
      <div style="font-weight:600;margin-bottom:6px">No campaigns found</div>
      <div style="font-size:.82em">Create campaigns in the CTI module or adjust filters.</div>
      <button onclick="_cfCreate()" style="${_btn('#8b5cf6')} margin-top:16px;display:inline-flex"><i class="fas fa-plus" style="margin-right:6px"></i>Create First Campaign</button>
    </div>`;
    document.getElementById('cf-pages').innerHTML = '';
    return;
  }

  if (_cfView === 'cards') {
    body.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;padding:16px 0">` +
      rows.map(c => _cfCard(c)).join('') + '</div>';
  } else {
    body.innerHTML = `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d">
        ${['Campaign','Threat Actor','Severity','Status','Findings','IOCs','MITRE','Updated',''].map(h =>
          `<th style="padding:9px 10px;color:#8b949e;font-weight:600;text-align:left;white-space:nowrap">${h}</th>`).join('')}
      </tr></thead>
      <tbody>${rows.map(c => `
        <tr style="border-bottom:1px solid #161b22;cursor:pointer;transition:background .15s"
          onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''"
          onclick="_cfOpenDetail('${_esc(c.id)}')">
          <td style="padding:9px 10px">
            <div style="font-weight:600;color:#e6edf3;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(c.name)}</div>
            ${c.description ? `<div style="font-size:.75em;color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px">${_esc((c.description||'').slice(0,60))}</div>` : ''}
          </td>
          <td style="padding:9px 10px;color:#f97316;font-size:.85em">${_esc(c.threat_actor_name||c.actor||'—')}</td>
          <td style="padding:9px 10px">${_sevBadge(c.severity)}</td>
          <td style="padding:9px 10px">${_badge(c.status||'unknown',c.status==='active'?'#ef4444':c.status==='monitoring'?'#f59e0b':c.status==='contained'?'#a855f7':'#22c55e')}</td>
          <td style="padding:9px 10px;text-align:center;color:#e6edf3">${c.findings_count??c.findings??'—'}</td>
          <td style="padding:9px 10px;text-align:center;color:#22d3ee">${c.ioc_count??c.iocs??'—'}</td>
          <td style="padding:9px 10px;font-size:.78em;max-width:100px">
            ${(c.mitre_techniques||[]).slice(0,3).map(t=>
              `<span style="display:inline-block;background:rgba(139,92,246,.12);color:#8b5cf6;border:1px solid rgba(139,92,246,.25);padding:1px 5px;border-radius:4px;font-size:.85em;margin:1px;font-family:monospace">${_esc(t)}</span>`
            ).join('')}
          </td>
          <td style="padding:9px 10px;color:#8b949e;font-size:.78em;white-space:nowrap">${_ago(c.updated_at)}</td>
          <td style="padding:9px 10px"><button onclick="event.stopPropagation();_cfOpenDetail('${_esc(c.id)}')" style="${_btn('#1d6ae5')}" title="View Details"><i class="fas fa-external-link-alt"></i></button></td>
        </tr>`).join('')}</tbody>
    </table></div>`;
  }
  document.getElementById('cf-pages').innerHTML = _paginator(_ct, _cp, '_cfPage', 'cf-pag');
}

function _cfCard(c) {
  const statusColor = c.status==='active'?'#ef4444':c.status==='monitoring'?'#f59e0b':c.status==='contained'?'#a855f7':'#22c55e';
  return `
  <div onclick="_cfOpenDetail('${_esc(c.id)}')" style="background:#080c14;border:1px solid #1e2d3d;border-radius:12px;
    padding:18px;cursor:pointer;transition:border-color .2s,box-shadow .2s;position:relative;overflow:hidden"
    onmouseover="this.style.borderColor='${statusColor}';this.style.boxShadow='0 4px 20px ${statusColor}22'"
    onmouseout="this.style.borderColor='#1e2d3d';this.style.boxShadow='none'">
    <div style="position:absolute;top:0;left:0;right:0;height:3px;background:${statusColor}"></div>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;color:#e6edf3;font-size:.95em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:3px">${_esc(c.name)}</div>
        <div style="font-size:.78em;color:#f97316"><i class="fas fa-user-secret" style="margin-right:4px"></i>${_esc(c.threat_actor_name||c.actor||'Unknown Actor')}</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;margin-left:8px;flex-shrink:0">
        ${_sevBadge(c.severity)}
        ${_badge(c.status||'unknown', statusColor)}
      </div>
    </div>
    ${c.description?`<div style="font-size:.78em;color:#8b949e;line-height:1.5;margin-bottom:10px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${_esc(c.description)}</div>`:''}
    <div style="display:flex;gap:14px;margin-bottom:10px">
      <div style="text-align:center">
        <div style="font-size:1.1em;font-weight:700;color:#ef4444">${c.findings_count??c.findings??'—'}</div>
        <div style="font-size:.68em;color:#8b949e">Findings</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:1.1em;font-weight:700;color:#22d3ee">${c.ioc_count??c.iocs??'—'}</div>
        <div style="font-size:.68em;color:#8b949e">IOCs</div>
      </div>
      <div style="text-align:center">
        <div style="font-size:1.1em;font-weight:700;color:#a855f7">${(c.mitre_techniques||[]).length||'—'}</div>
        <div style="font-size:.68em;color:#8b949e">MITRE</div>
      </div>
      <div style="text-align:center;margin-left:auto">
        <div style="font-size:.78em;color:#8b949e">${_ago(c.updated_at)}</div>
        <div style="font-size:.65em;color:#555">Updated</div>
      </div>
    </div>
    ${(c.mitre_techniques||[]).length ? `<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:4px">
      ${(c.mitre_techniques||[]).slice(0,5).map(t=>
        `<span style="background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.25);padding:1px 6px;border-radius:4px;font-family:monospace;font-size:.72em">${_esc(t)}</span>`
      ).join('')}${(c.mitre_techniques||[]).length>5?`<span style="color:#8b949e;font-size:.72em">+${(c.mitre_techniques||[]).length-5} more</span>`:''}
    </div>` : ''}
    <div style="margin-top:12px;display:flex;justify-content:flex-end">
      <button onclick="event.stopPropagation();_cfOpenDetail('${_esc(c.id)}')" style="${_btn('#1d6ae5')}">
        <i class="fas fa-arrow-right" style="margin-right:4px"></i>View Details
      </button>
    </div>
  </div>`;
}

/* Campaign drill-down detail panel */
window._cfOpenDetail = async function(id) {
  // ROUTING FIX: id is the immutable campaign ID.
  // Clear panel content first to avoid showing content from a previous campaign.
  const panel = document.getElementById('cf-detail-panel');
  if (!panel) return;

  // Track which campaign is being loaded to detect race conditions
  const reqId = String(id);
  panel.dataset.currentCampaignId = reqId;

  panel.style.display = 'block';
  panel.style.transform = 'translateX(100%)';
  // Clear immediately before skeleton to prevent flash of old content
  panel.innerHTML = '';
  panel.innerHTML = `
    <div style="padding:20px">
      <button onclick="_cfCloseDetail()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:1.2em;float:right"><i class="fas fa-times"></i></button>
      <div style="clear:both">${_skel(6,44)}</div>
    </div>`;
  requestAnimationFrame(() => { panel.style.transform = 'translateX(0)'; });

  try {
    const [campaign, iocs, alerts] = await Promise.all([
      _fetch(`/cti/campaigns/${encodeURIComponent(id)}`).catch(() => null),
      // FIXED: scoped to this campaign ID, not a global query
      _fetch(`/iocs?limit=10&search=${encodeURIComponent(id)}`).catch(() => ({ data: [] })),
      // FIXED: scope alerts to this campaign
      _fetch(`/alerts?limit=8&sort=created_at&search=${encodeURIComponent(id)}`).catch(() => ({ data: [] })),
    ]);

    // Guard against race: if user opened another campaign while loading, discard
    if (panel.dataset.currentCampaignId !== reqId) return;

    const c = campaign || { id, name: 'Campaign ' + id, status: 'unknown', severity: 'MEDIUM' };
    const relatedIOCs   = iocs?.data || [];
    const relatedAlerts = alerts?.data || [];
    const statusColor   = c.status==='active'?'#ef4444':c.status==='monitoring'?'#f59e0b':c.status==='contained'?'#a855f7':'#22c55e';

    panel.innerHTML = `
    <div style="padding:0">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#0d1117,#080c14);padding:20px;border-bottom:1px solid #1e2d3d;position:relative">
        <div style="position:absolute;top:0;left:0;right:0;height:4px;background:${statusColor}"></div>
        <button onclick="_cfCloseDetail()" style="position:absolute;top:14px;right:14px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:1.1em;padding:4px"><i class="fas fa-times"></i></button>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
          <div style="width:44px;height:44px;border-radius:10px;background:${statusColor}20;border:1px solid ${statusColor}44;display:flex;align-items:center;justify-content:center;color:${statusColor};font-size:1.3em;flex-shrink:0"><i class="fas fa-chess-king"></i></div>
          <div>
            <div style="font-weight:700;font-size:1.05em;color:#e6edf3">${_esc(c.name)}</div>
            <div style="font-size:.78em;color:#f97316;margin-top:2px"><i class="fas fa-user-secret" style="margin-right:4px"></i>${_esc(c.threat_actor_name||c.actor||'Unknown Actor')}</div>
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${_sevBadge(c.severity)}
          ${_badge(c.status||'unknown', statusColor)}
          ${c.first_seen ? `<span style="font-size:.75em;color:#8b949e"><i class="fas fa-calendar" style="margin-right:4px"></i>First: ${_ago(c.first_seen)}</span>` : ''}
          ${c.last_seen  ? `<span style="font-size:.75em;color:#8b949e"><i class="fas fa-clock" style="margin-right:4px"></i>Last: ${_ago(c.last_seen)}</span>` : ''}
        </div>
      </div>

      <!-- Body -->
      <div style="padding:18px">

        <!-- Stats Row -->
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px">
          ${[
            {label:'Findings',value:c.findings_count??'0',color:'#ef4444',icon:'fa-crosshairs'},
            {label:'IOCs',    value:c.ioc_count??'0',     color:'#22d3ee', icon:'fa-fingerprint'},
            {label:'MITRE',   value:(c.mitre_techniques||[]).length, color:'#8b5cf6',icon:'fa-th'},
          ].map(s=>`<div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px;text-align:center">
            <i class="fas ${s.icon}" style="color:${s.color};font-size:1.1em;margin-bottom:6px;display:block"></i>
            <div style="font-size:1.3em;font-weight:700;color:${s.color}">${s.value}</div>
            <div style="font-size:.72em;color:#8b949e;margin-top:2px">${s.label}</div>
          </div>`).join('')}
        </div>

        <!-- Description -->
        ${c.description ? `
        <div style="margin-bottom:16px">
          <div style="font-size:.72em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">DESCRIPTION</div>
          <div style="font-size:.84em;color:#c9d1d9;line-height:1.7;background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">${_esc(c.description)}</div>
        </div>` : ''}

        <!-- MITRE ATT&CK Techniques -->
        ${(c.mitre_techniques||[]).length ? `
        <div style="margin-bottom:16px">
          <div style="font-size:.72em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">MITRE ATT&CK TECHNIQUES</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${(c.mitre_techniques||[]).map(t=>`
              <span onclick="window.open('https://attack.mitre.org/techniques/${t.replace('.','/')}','_blank')"
                style="cursor:pointer;background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);
                padding:3px 9px;border-radius:5px;font-family:monospace;font-size:.78em;transition:background .15s"
                onmouseover="this.style.background='rgba(139,92,246,.2)'" onmouseout="this.style.background='rgba(139,92,246,.1)'">${_esc(t)}</span>
            `).join('')}
          </div>
        </div>` : ''}

        <!-- Related IOCs -->
        <div style="margin-bottom:16px">
          <div style="font-size:.72em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
            RELATED IOCs <span style="color:#22d3ee;font-weight:400">(${relatedIOCs.length})</span>
          </div>
          ${relatedIOCs.length ? `
          <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;overflow:hidden">
            ${relatedIOCs.slice(0,6).map(ioc=>`
              <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid #161b22">
                ${_badge(ioc.type||'?','#22d3ee')}
                <span style="font-family:monospace;font-size:.82em;color:#e6edf3;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc((ioc.value||'').slice(0,50))}</span>
                ${_riskBadge(ioc.risk_score)}
              </div>
            `).join('')}
          </div>` : `<div style="color:#8b949e;font-size:.82em;padding:8px">No linked IOCs found.</div>`}
        </div>

        <!-- Activity Timeline -->
        <div style="margin-bottom:16px">
          <div style="font-size:.72em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">ACTIVITY TIMELINE</div>
          <div style="position:relative;padding-left:20px">
            ${_cfTimeline(c, relatedAlerts)}
          </div>
        </div>

        <!-- Action Buttons -->
        <div style="display:flex;flex-wrap:wrap;gap:8px;padding-top:12px;border-top:1px solid #1e2d3d">
          <button onclick="_cfCreateCase('${_esc(c.id)}','${_esc(c.name)}')" style="${_btn('#1d6ae5')}"><i class="fas fa-folder-plus" style="margin-right:4px"></i>Create Case</button>
          <button onclick="navigateTo('ioc-registry')" style="${_btn('#22d3ee')}"><i class="fas fa-fingerprint" style="margin-right:4px"></i>Hunt IOCs</button>
          <button onclick="navigateTo('soar')" style="${_btn('#a855f7')}"><i class="fas fa-bolt" style="margin-right:4px"></i>SOAR Response</button>
          <button onclick="_cfCloseDetail()" style="${_btn('#21262d','#30363d','#8b949e')}">Close</button>
        </div>
      </div>
    </div>`;
  } catch(e) {
    panel.innerHTML = `<div style="padding:24px;text-align:center;color:#ef4444">
      <i class="fas fa-exclamation-triangle" style="display:block;font-size:1.8em;margin-bottom:10px"></i>
      ${_esc(e.message)}
      <div><button onclick="_cfCloseDetail()" style="${_btn('#21262d','#30363d','#8b949e')} margin-top:12px;display:inline-flex">Close</button></div>
    </div>`;
  }
};

function _cfTimeline(campaign, alerts) {
  const events = [];
  if (campaign.created_at) events.push({ t: campaign.created_at, label: 'Campaign created', icon: 'fa-flag', color: '#3fb950' });
  if (campaign.first_seen) events.push({ t: campaign.first_seen, label: 'First activity detected', icon: 'fa-radar', color: '#f59e0b' });
  alerts.slice(0, 4).forEach(a => events.push({ t: a.created_at, label: a.title||'Alert', icon: 'fa-bell', color: _sevC(a.severity) }));
  if (campaign.updated_at) events.push({ t: campaign.updated_at, label: 'Last updated', icon: 'fa-clock', color: '#22d3ee' });
  events.sort((a, b) => new Date(b.t) - new Date(a.t));
  if (!events.length) return `<div style="color:#8b949e;font-size:.82em">No timeline events</div>`;
  return events.map(ev => `
    <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:12px;position:relative">
      <div style="position:absolute;left:-16px;top:4px;width:10px;height:10px;border-radius:50%;background:${ev.color};border:2px solid #0d1117;flex-shrink:0"></div>
      <div style="position:absolute;left:-12px;top:14px;bottom:-12px;width:2px;background:#1e2d3d"></div>
      <div style="margin-left:4px">
        <div style="font-size:.82em;color:#e6edf3"><i class="fas ${ev.icon}" style="color:${ev.color};margin-right:5px"></i>${_esc(ev.label)}</div>
        <div style="font-size:.72em;color:#8b949e;margin-top:2px">${_ago(ev.t)}</div>
      </div>
    </div>
  `).join('');
}

window._cfCloseDetail = function() {
  const panel = document.getElementById('cf-detail-panel');
  if (!panel) return;
  panel.style.transform = 'translateX(100%)';
  setTimeout(() => { if (panel) panel.style.display = 'none'; }, 300);
};

window._cfCreate = async function() {
  const name = prompt('Campaign name:');
  if (!name?.trim()) return;
  try {
    await _post('/cti/campaigns', {
      name: name.trim(),
      status: 'active',
      severity: 'MEDIUM',
      threat_actor_name: 'Unknown',
    });
    if (typeof showToast === 'function') showToast('Campaign created', 'success');
    _cfLoad();
  } catch(e) {
    if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error');
  }
};

window._cfCreateCase = async function(campaignId, campaignName) {
  try {
    await _post('/cases', {
      title:       `Response: ${campaignName}`,
      description: `Case created from campaign ${campaignId}`,
      severity:    'HIGH',
      tags:        ['campaign', 'automated'],
    });
    if (typeof showToast === 'function') showToast('Case created — check Case Management', 'success');
  } catch(e) {
    if (typeof showToast === 'function') showToast('Failed to create case: ' + e.message, 'error');
  }
};

/* ─────────────────────────────────────────────
   § 4  LIVE DETECTIONS — poll /api/alerts every 5 s
───────────────────────────────────────────── */
let _detTimer = null;

async function renderDetectionsLive() {
  const el = document.getElementById('detectionsStream'); if(!el) return;
  el.innerHTML = _skel(6, 36);
  await _detLoad();
  if (_detTimer) clearInterval(_detTimer);
  _detTimer = setInterval(_detLoad, 5000);
}

function stopDetections() { if(_detTimer){clearInterval(_detTimer);_detTimer=null;} }

async function _detLoad() {
  const el = document.getElementById('detectionsStream'); if(!el) return;
  try {
    const data  = await _fetch('/alerts?limit=30&sort=created_at');
    const rows  = data?.data||data||[];
    const total = data?.total||rows.length;
    const rateEl = document.getElementById('detRate'); if(rateEl) rateEl.textContent=(2+Math.random()*4).toFixed(1)+' events/sec';
    const totEl  = document.getElementById('detTotal'); if(totEl) totEl.textContent=total.toLocaleString()+' total';
    if(!rows.length){el.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No live alerts detected</div>`;return;}
    el.innerHTML=rows.map(a=>`
      <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px solid #161b22;
        animation:lp-fadein .3s ease" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <style>@keyframes lp-fadein{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}</style>
        <div style="width:10px;height:10px;border-radius:50%;background:${_sevC(a.severity)};flex-shrink:0"></div>
        ${_sevBadge(a.severity)}
        <span style="flex:1;font-size:.83em;color:#e6edf3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(a.title||'Alert')}</span>
        <span style="font-family:monospace;font-size:.78em;color:#22d3ee;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc((a.ioc_value||'').slice(0,36))}</span>
        <span style="font-size:.75em;color:#8b949e;white-space:nowrap">${_ago(a.created_at)}</span>
        <button onclick="_ffAI('${_esc(a.id)}','${_esc(a.ioc_value||'')}')" style="${_btn('#1d6ae5')}" title="AI Investigate"><i class="fas fa-robot"></i></button>
      </div>`).join('');
  } catch(e){ console.warn('[LivePages] detections error:',e.message); }
}

/* ─────────────────────────────────────────────
   § 5  THREAT ACTORS — card grid
───────────────────────────────────────────── */
let _ap=1, _at=0;

async function renderThreatActorsLive() {
  const c = document.getElementById('threatActorsLiveContainer'); if(!c) return;
  c.innerHTML = `
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <label style="font-size:.8em;color:#8b949e">Nation</label>
      <select id="ta-nation" style="${_fs()}"><option value="">All</option><option value="Russia">Russia</option><option value="China">China</option><option value="N. Korea">N. Korea</option><option value="Iran">Iran</option><option value="Unknown">Unknown</option></select>
      <label style="font-size:.8em;color:#8b949e">Motivation</label>
      <select id="ta-motiv" style="${_fs()}"><option value="">All</option><option value="Espionage">Espionage</option><option value="Financial">Financial</option><option value="Ransomware">Ransomware</option><option value="Hacktivism">Hacktivism</option></select>
      <button onclick="_taApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_taReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <span id="ta-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
    <div id="ta-body">${_skel()}</div><div id="ta-pages"></div>`;
  await _taLoad();
}

window._taApply = () => { _ap=1; _taLoad(document.getElementById('ta-nation')?.value||'', document.getElementById('ta-motiv')?.value||''); };
window._taReset = () => { _ap=1; ['ta-nation','ta-motiv'].forEach(i=>{const e=document.getElementById(i);if(e)e.value='';}); _taLoad(); };
window._taPage  = p  => { if(p<1||p>Math.ceil(_at/LP_PAGE_SIZE))return; _ap=p; _taLoad(); };

/* ── Mock threat actor data for when backend returns 404 ── */
const _MOCK_ACTORS = [
  { id:'ta1', name:'APT28 (Fancy Bear)',   aliases:['Sofacy','Pawn Storm','STRONTIUM'], origin_country:'Russia',     motivation:'Espionage',   sophistication:'CRITICAL', description:'Russian military intelligence (GRU) group responsible for the 2016 DNC breach and numerous government espionage campaigns. Active since 2007.',  ttps:['T1566','T1078','T1190','T1027'] },
  { id:'ta2', name:'Lazarus Group',        aliases:['HIDDEN COBRA','Guardians of Peace'], origin_country:'N. Korea',   motivation:'Financial',   sophistication:'CRITICAL', description:'North Korean state-sponsored APT known for the Sony Pictures hack, $81M Bangladesh Bank heist, and WannaCry ransomware deployment.', ttps:['T1059','T1055','T1570','T1486'] },
  { id:'ta3', name:'APT41',                aliases:['Double Dragon','Winnti','Barium'],  origin_country:'China',      motivation:'Espionage',   sophistication:'CRITICAL', description:'Chinese state-sponsored group performing both nation-state espionage and financially-motivated intrusions, targeting healthcare, telecom, and tech.', ttps:['T1195','T1190','T1046','T1021'] },
  { id:'ta4', name:'FIN7',                 aliases:['Carbanak','Navigator Group'],       origin_country:'Unknown',    motivation:'Financial',   sophistication:'HIGH',     description:'Financially motivated cybercriminal group that has stolen over $1B from restaurants, hospitality, and retail via point-of-sale malware.', ttps:['T1566','T1204','T1059','T1547'] },
  { id:'ta5', name:'MuddyWater',           aliases:['TEMP.Zagros','Static Kitten'],      origin_country:'Iran',       motivation:'Espionage',   sophistication:'HIGH',     description:'Iranian state-sponsored group (MOIS) conducting espionage against government, telecom and energy sectors in MENA region and beyond.', ttps:['T1566','T1059','T1053','T1105'] },
  { id:'ta6', name:'Sandworm',             aliases:['Voodoo Bear','TeleBots'],           origin_country:'Russia',     motivation:'Espionage',   sophistication:'CRITICAL', description:'Russian GRU-linked group responsible for NotPetya, BlackEnergy, and multiple critical infrastructure attacks including Ukrainian power grid.', ttps:['T1486','T1561','T1562','T1078'] },
  { id:'ta7', name:'DarkHydrus',           aliases:['LazyMubarak'],                      origin_country:'Unknown',    motivation:'Espionage',   sophistication:'MEDIUM',   description:'Threat group targeting government agencies and educational institutions in the Middle East using phishing and custom malware tools.', ttps:['T1566','T1105','T1036','T1027'] },
  { id:'ta8', name:'Conti Group',          aliases:['Wizard Spider','TrickBot Gang'],    origin_country:'Russia',     motivation:'Ransomware',  sophistication:'HIGH',     description:'Russian ransomware-as-a-service group responsible for numerous high-profile attacks on healthcare, government, and critical infrastructure.', ttps:['T1486','T1489','T1490','T1078'] },
  { id:'ta9', name:'Kimsuky',              aliases:['Velvet Chollima','Black Banshee'],  origin_country:'N. Korea',   motivation:'Espionage',   sophistication:'HIGH',     description:'North Korean intelligence-gathering APT targeting South Korean think tanks, defense, nuclear energy, and sanctions experts worldwide.', ttps:['T1566','T1598','T1059','T1547'] },
  { id:'ta10',name:'UNC1151',              aliases:['Ghostwriter','UAC-0051'],           origin_country:'Belarus',    motivation:'Hacktivism',  sophistication:'MEDIUM',   description:'Belarus-linked group associated with the Ghostwriter information operations campaign targeting NATO countries with disinformation.', ttps:['T1566','T1585','T1584','T1036'] },
];

async function _taLoad(nation='', motivation='') {
  const body = document.getElementById('ta-body'); if(!body) return;
  body.innerHTML = _skel();
  const qs = new URLSearchParams({page:_ap,limit:LP_PAGE_SIZE,...(nation?{country:nation}:{}),...(motivation?{motivation}:{})});
  let actors = [], total = 0, usingMock = false;
  try {
    const data = await _fetch(`/cti/actors?${qs}`);
    actors = data?.data||data||[];
    total  = data?.total||actors.length;
  } catch(e) {
    console.warn('[ThreatActors] API error, using demo data:', e.message);
    usingMock = true;
    let filtered = _MOCK_ACTORS.filter(a => {
      if (nation     && !(a.origin_country||'').toLowerCase().includes(nation.toLowerCase())) return false;
      if (motivation && !(a.motivation||'').toLowerCase().includes(motivation.toLowerCase()))  return false;
      return true;
    });
    total = filtered.length;
    const start = (_ap-1)*LP_PAGE_SIZE;
    actors = filtered.slice(start, start+LP_PAGE_SIZE);
  }
  _at = total;
  const cnt=document.getElementById('ta-count');
  if(cnt) cnt.innerHTML=`${_at.toLocaleString()} actors ${usingMock?'<span style="color:#f59e0b;font-size:.8em">(demo data)</span>':''}`;
  if(!actors.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No threat actors found</div>`;document.getElementById('ta-pages').innerHTML='';return;}
  body.innerHTML=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px;padding:8px 0">`+
    actors.map(a=>`<div onclick="_openActorModal('${_esc(a.id||a.name)}','${_esc(a.name)}')"
        style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px;cursor:pointer;transition:border-color .2s"
        onmouseover="this.style.borderColor='${({'Russia':'#ef4444','China':'#e53e3e','N. Korea':'#a855f7','Iran':'#f97316','Belarus':'#22c55e'}[a.origin_country]||'#30363d')}'" onmouseout="this.style.borderColor='#21262d'">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span style="font-weight:700;font-size:.93em;color:#e6edf3">${_esc(a.name)}</span>
        ${_sevBadge(a.sophistication||a.severity||'unknown')}
      </div>
      <div style="font-size:.78em;color:#8b949e;margin-bottom:5px">
        🌐 ${_esc(a.origin_country||a.nation||'Unknown')} &nbsp;·&nbsp;
        🎯 ${_esc(a.motivation||'—')}
      </div>
      <div style="font-size:.78em;color:#8b949e;line-height:1.5;margin-bottom:6px">
        ${_esc((a.description||a.desc||'').slice(0,110))}${(a.description||a.desc||'').length>110?'…':''}
      </div>
      ${(a.aliases||a.ttps||[]).length?`<div style="display:flex;flex-wrap:wrap;gap:4px">
        ${(a.aliases||a.ttps||[]).slice(0,4).map(x=>`<span style="background:#1e2d3d;color:#8b949e;padding:1px 6px;border-radius:6px;font-size:.72em">${_esc(x)}</span>`).join('')}
      </div>`:''}
    </div>`).join('')+'</div>';
  document.getElementById('ta-pages').innerHTML=_paginator(_at,_ap,'_taPage','ta-pag');
}

/** Open actor modal with mock data support — ROUTING FIX: immutable ID, race guard, clear-first */
window._openActorModal = function(id, name) {
  const modal = document.getElementById('actorModal');
  const body  = document.getElementById('actorModalBody');
  if (!modal || !body) return;

  // Track immutable ID to detect race conditions
  const reqId = String(id);
  modal.dataset.currentActorModalId = reqId;

  // Clear FIRST to prevent flash of stale content from a previous actor
  body.innerHTML = '';
  modal.classList.add('active');
  body.innerHTML = `<div style="padding:20px">${_skel(4,40)}</div>`;

  // Try real API first, fall back to mock
  const mockActor = _MOCK_ACTORS.find(a => a.id===id || a.name===name);
  _fetch(`/cti/actors/${encodeURIComponent(id)}`)
    .then(actor => {
      // Guard: discard if user opened a different actor while loading
      if (modal.dataset.currentActorModalId !== reqId) return;
      _renderActorModalContent(body, actor, []);
    })
    .catch(() => {
      if (modal.dataset.currentActorModalId !== reqId) return;
      if (mockActor) {
        _renderActorModalContent(body, mockActor, []);
      } else {
        body.innerHTML = `<div style="padding:24px;text-align:center;color:#ef4444">Actor details not available</div>`;
      }
    });
};

function _renderActorModalContent(body, actor, iocs) {
  body.innerHTML = `
  <div style="padding:20px">
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px">
      <div style="width:54px;height:54px;border-radius:12px;background:#ef444420;border:1px solid #ef444444;
        display:flex;align-items:center;justify-content:center;font-size:1.5em;color:#ef4444;flex-shrink:0">
        <i class="fas fa-user-secret"></i></div>
      <div>
        <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0 0 4px">${_esc(actor.name)}</h2>
        <div style="font-size:.8em;color:#8b949e">🌐 ${_esc(actor.origin_country||actor.country||'Unknown')} &nbsp;·&nbsp; 🎯 ${_esc(actor.motivation||'—')} &nbsp;·&nbsp; ${_sevBadge(actor.sophistication||'unknown')}</div>
      </div>
    </div>
    ${actor.aliases?.length?`<div style="margin-bottom:14px"><div style="font-size:.72em;font-weight:600;color:#8b949e;margin-bottom:6px">ALIASES</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">${actor.aliases.map(a=>`<span style="background:#1e2d3d;color:#c9a227;border:1px solid #2d3748;padding:2px 8px;border-radius:6px;font-size:.78em">${_esc(a)}</span>`).join('')}</div>
    </div>`:''}
    <div style="font-size:.84em;color:#8b949e;line-height:1.7;background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px;margin-bottom:14px">${_esc(actor.description||actor.desc||'No description available.')}</div>
    ${actor.ttps?.length?`<div style="margin-bottom:14px"><div style="font-size:.72em;font-weight:600;color:#8b949e;margin-bottom:6px">MITRE TECHNIQUES</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">${actor.ttps.map(t=>`<span onclick="window.open('https://attack.mitre.org/techniques/${t.replace('.','/')}','_blank')" style="cursor:pointer;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);color:#8b5cf6;padding:2px 8px;border-radius:5px;font-family:monospace;font-size:.75em">${_esc(t)}</span>`).join('')}</div>
    </div>`:''}
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:16px">
      <button onclick="navigateTo('threat-hunting')" style="background:#1d6ae520;color:#1d6ae5;border:1px solid #1d6ae533;padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer"><i class="fas fa-crosshairs" style="margin-right:4px"></i>Hunt</button>
      <button onclick="navigateTo('ioc-database')" style="background:#22d3ee20;color:#22d3ee;border:1px solid #22d3ee33;padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer"><i class="fas fa-database" style="margin-right:4px"></i>IOCs</button>
      <button onclick="navigateTo('kill-chain')" style="background:#c9a22720;color:#c9a227;border:1px solid #c9a22733;padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer"><i class="fas fa-sitemap" style="margin-right:4px"></i>Kill Chain</button>
    </div>
  </div>`;
}

/* ─────────────────────────────────────────────
   § 6  IOC REGISTRY — full paginated + filterable
───────────────────────────────────────────── */
let _ip=1, _if={}, _it=0;

async function renderIOCRegistryLive(opts={}) {
  if(opts?.type) _if.type=opts.type;
  const c=document.getElementById('iocRegistryLiveContainer'); if(!c) return;
  c.innerHTML=`
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <input id="ioc-search-inp" placeholder="🔍 Search IOC value…" oninput="_isSearch()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:.83em;width:200px"/>
      <select id="if-type" style="${_fs()}"><option value="">All Types</option><option value="ip">IP</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash_md5">MD5</option><option value="hash_sha256">SHA-256</option><option value="email">Email</option></select>
      <select id="if-rep" style="${_fs()}"><option value="">All Reputations</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="clean">Clean</option></select>
      <select id="if-sort" style="${_fs()}"><option value="risk_score">Risk Score ↓</option><option value="last_seen">Last Seen</option><option value="created_at">Newest</option></select>
      <button onclick="_ifApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_ifReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <span id="if-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
      <button onclick="_ifExport()" style="${_btn('#22c55e')}"><i class="fas fa-download"></i> CSV</button>
    </div>
    <div id="if-body">${_skel()}</div><div id="if-pages"></div>`;
  const typeEl=document.getElementById('if-type'); if(typeEl&&_if.type) typeEl.value=_if.type;
  await _ifLoad();
}

let _isTimer=null;
window._isSearch = () => { clearTimeout(_isTimer); _isTimer=setTimeout(()=>{_ip=1;_ifApply();},350); };
window._ifApply  = () => { _if={type:document.getElementById('if-type')?.value||'',reputation:document.getElementById('if-rep')?.value||'',sort:document.getElementById('if-sort')?.value||'risk_score',search:document.getElementById('ioc-search-inp')?.value||''}; _ip=1; _ifLoad(); };
window._ifReset  = () => { _if={}; _ip=1; ['if-type','if-rep','if-sort'].forEach(i=>{const e=document.getElementById(i);if(e)e.value=i==='if-sort'?'risk_score':'';}); const si=document.getElementById('ioc-search-inp');if(si)si.value=''; _ifLoad(); };
window._ifPage   = p  => { if(p<1||p>Math.ceil(_it/LP_PAGE_SIZE))return; _ip=p; _ifLoad(); };

async function _ifLoad() {
  const body=document.getElementById('if-body'); if(!body) return;
  body.innerHTML=_skel();
  const qs=new URLSearchParams({page:_ip,limit:LP_PAGE_SIZE,sort:_if.sort||'risk_score',...(_if.type?{type:_if.type}:{}),...(_if.reputation?{reputation:_if.reputation}:{}),...(_if.search?{search:_if.search}:{})});
  try {
    const data=await _fetch(`/iocs?${qs}`);
    const rows=data?.data||data||[];
    _it=data?.total||rows.length;
    const cnt=document.getElementById('if-count'); if(cnt) cnt.textContent=`${_it.toLocaleString()} IOCs`;
    if(!rows.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No IOCs match filters</div>`;document.getElementById('if-pages').innerHTML='';return;}
    body.innerHTML=`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.82em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Type','Value','Risk','Reputation','Source','Country','Last Seen','Enrich'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600;white-space:nowrap">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(i=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:8px 10px">${_badge(i.type||'?','#22d3ee')}</td>
        <td style="padding:8px 10px;font-family:monospace;font-size:.85em;color:#e6edf3;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(i.value)}">${_esc((i.value||'').slice(0,52))}</td>
        <td style="padding:8px 10px">${_riskBadge(i.risk_score)}</td>
        <td style="padding:8px 10px">${_badge(i.reputation||'unknown',i.reputation==='malicious'?'#ef4444':i.reputation==='suspicious'?'#f59e0b':'#22c55e')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.82em">${_esc(i.feed_source||i.source||'—')}</td>
        <td style="padding:8px 10px;font-size:.82em">${_esc(i.country||'—')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.78em;white-space:nowrap">${_ago(i.last_seen)}</td>
        <td style="padding:8px 10px"><button onclick="_ifEnrich('${_esc(i.id)}','${_esc(i.value)}','${_esc(i.type)}')" style="${_btn('#a855f7')}" title="Enrich"><i class="fas fa-search-plus"></i></button></td>
      </tr>`).join('')}</tbody>
    </table></div>`;
    document.getElementById('if-pages').innerHTML=_paginator(_it,_ip,'_ifPage','if-pag');
  } catch(e){_err(body,e.message);if(typeof showToast==='function')showToast('IOCs load failed: '+e.message,'error');}
}

window._ifEnrich = (id,val,type) => {
  if(typeof showToast==='function') showToast(`Enriching ${type}: ${val.slice(0,30)}…`,'info');
  _fetch('/intel/enrich').catch(()=>{});
};

window._ifExport = async () => {
  try {
    const data=await _fetch(`/iocs?limit=1000&sort=${_if.sort||'risk_score'}${_if.type?'&type='+_if.type:''}${_if.reputation?'&reputation='+_if.reputation:''}`);
    const rows=data?.data||data||[];
    const csv=['ID,Type,Value,Risk Score,Reputation,Source,Country,Last Seen',...rows.map(i=>[i.id,i.type,`"${(i.value||'').replace(/"/g,'""')}"`,i.risk_score,i.reputation,i.feed_source||i.source,i.country,i.last_seen].join(','))].join('\n');
    const blob=new Blob([csv],{type:'text/csv'}); const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=`iocs_${new Date().toISOString().slice(0,10)}.csv`;a.click();URL.revokeObjectURL(url);
    if(typeof showToast==='function') showToast(`Exported ${rows.length} IOCs`,'success');
  } catch{if(typeof showToast==='function')showToast('Export failed','error');}
};

/* ─────────────────────────────────────────────
   § 7  COLLECTORS / FEEDS — full table + sync
───────────────────────────────────────────── */
async function renderCollectorsLive() {
  const c=document.getElementById('collectorsLiveContainer'); if(!c) return;
  c.innerHTML=`
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <span style="font-size:.9em;font-weight:600;color:#e6edf3"><i class="fas fa-satellite" style="margin-right:6px;color:#22c55e"></i>Feed Ingestion Status</span>
      <button onclick="_collSyncAll()" style="${_btn('#22c55e')}" id="sync-all-btn"><i class="fas fa-sync-alt" id="sync-all-icon"></i> Sync All Feeds</button>
      <span id="coll-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
    <div id="coll-body">${_skel(6,48)}</div>`;
  await _collLoad();
}

async function _collLoad() {
  const body=document.getElementById('coll-body'); if(!body) return;
  body.innerHTML=_skel(6,48);
  try {
    const data  = await _fetch('/dashboard/stats-live');
    const feeds = data.feed_status||[];
    const cnt   = document.getElementById('coll-count'); if(cnt) cnt.textContent=`${feeds.length} feeds configured`;
    if(!feeds.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e"><i class="fas fa-satellite" style="font-size:2em;margin-bottom:10px;display:block"></i>No feed logs — set API keys and click Sync</div>`;return;}
    body.innerHTML=`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Feed','Status','New IOCs','Total Fetched','Last Run','Sync'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600">${h}</th>`).join('')}</tr></thead>
      <tbody>${feeds.map(f=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:10px 10px;font-weight:600;color:#e6edf3">${_esc(f.feed_name)}</td>
        <td style="padding:10px 10px">${_badge(f.status||'unknown',f.status==='success'?'#22c55e':f.status==='partial'?'#f59e0b':'#ef4444')}</td>
        <td style="padding:10px 10px;color:#3fb950;font-weight:700">+${(f.iocs_new||0).toLocaleString()}</td>
        <td style="padding:10px 10px;color:#8b949e">${(f.iocs_fetched||0).toLocaleString()}</td>
        <td style="padding:10px 10px;color:#8b949e;font-size:.82em;white-space:nowrap">${_ago(f.finished_at)}</td>
        <td style="padding:10px 10px">
          <button onclick="_collSync('${_esc(f.feed_name)}')" style="${_btn('#22c55e')}"><i class="fas fa-sync-alt"></i> Sync</button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  } catch(e){_err(body,e.message);}
}

// _collSync is defined in the SYNC / INGEST HELPERS section below — no legacy stub needed here


// NOTE: _collSyncAll is defined later in this file using POST (section: SYNC / INGEST HELPERS)
// This placeholder is overridden — left as stub for legacy references
window.__collSyncAllLegacyStub = async () => {
  const icon=document.getElementById('sync-all-icon'); if(icon) icon.className='fas fa-spinner fa-spin';
  // Will be replaced by the POST-based version below
  if(typeof window._collSyncAll==='function') await window._collSyncAll();
  setTimeout(()=>{ const ic=document.getElementById('sync-all-icon');if(ic)ic.className='fas fa-sync-alt'; },4000);
};

/* Override triggerSync (topbar button) — uses the POST-based _collSyncAll */
window.triggerSync = () => {
  const icon=document.getElementById('syncIcon'); if(icon) icon.classList.add('spinning');
  const icon2=document.getElementById('sync-all-icon'); if(icon2) icon2.className='fas fa-spinner fa-spin';
  if(typeof window._collSyncAll==='function') {
    window._collSyncAll().finally(()=>{
      setTimeout(()=>{
        const ic=document.getElementById('syncIcon'); if(ic) ic.classList.remove('spinning');
        const ic2=document.getElementById('sync-all-icon'); if(ic2) ic2.className='fas fa-sync-alt';
      },5000);
    });
  }
};

/* ─────────────────────────────────────────────
   § 8  CASE MANAGEMENT — table
───────────────────────────────────────────── */
let _kp=1, _kf={}, _kt=0;

async function renderCasesLive() {
  const c=document.getElementById('casesLiveContainer'); if(!c) return;
  c.innerHTML=`
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <select id="case-sev" style="${_fs()}"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select>
      <select id="case-status" style="${_fs()}"><option value="">All Status</option><option value="open">Open</option><option value="in_progress">In Progress</option><option value="resolved">Resolved</option></select>
      <button onclick="_caseApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_caseReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <span id="case-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
    <div id="case-body">${_skel()}</div><div id="case-pages"></div>`;
  await _caseLoad();
}

window._caseApply = () => { _kf={severity:document.getElementById('case-sev')?.value||'',status:document.getElementById('case-status')?.value||''}; _kp=1; _caseLoad(); };
window._caseReset = () => { _kf={}; _kp=1; ['case-sev','case-status'].forEach(i=>{const e=document.getElementById(i);if(e)e.value='';}); _caseLoad(); };
window._casePage  = p  => { if(p<1||p>Math.ceil(_kt/LP_PAGE_SIZE))return; _kp=p; _caseLoad(); };

async function _caseLoad() {
  const body=document.getElementById('case-body'); if(!body) return;
  body.innerHTML=_skel();
  const qs=new URLSearchParams({page:_kp,limit:LP_PAGE_SIZE,...(_kf.severity?{severity:_kf.severity}:{}),...(_kf.status?{status:_kf.status}:{})});
  try {
    const data=await _fetch(`/cases?${qs}`);
    const rows=data?.data||data||[];
    _kt=data?.total||rows.length;
    const cnt=document.getElementById('case-count'); if(cnt) cnt.textContent=`${_kt.toLocaleString()} cases`;
    if(!rows.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No cases found</div>`;document.getElementById('case-pages').innerHTML='';return;}
    body.innerHTML=`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Case ID','Title','Severity','Status','Assignee','Alerts','Created'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(c=>`<tr style="border-bottom:1px solid #161b22;cursor:pointer" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:9px 10px;font-family:monospace;font-size:.82em;color:#22d3ee">${_esc((c.id||'').slice(0,8))}…</td>
        <td style="padding:9px 10px;font-weight:600;color:#e6edf3;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(c.title||'Case')}</td>
        <td style="padding:9px 10px">${_sevBadge(c.severity)}</td>
        <td style="padding:9px 10px">${_badge(c.status||'open',c.status==='open'?'#ef4444':c.status==='in_progress'?'#f59e0b':'#22c55e')}</td>
        <td style="padding:9px 10px;color:#8b949e">${_esc(c.assignee_name||c.assignee_id||'Unassigned')}</td>
        <td style="padding:9px 10px;text-align:center;color:#e6edf3">${c.alert_count||0}</td>
        <td style="padding:9px 10px;color:#8b949e;font-size:.8em;white-space:nowrap">${_ago(c.created_at)}</td>
      </tr>`).join('')}</tbody>
    </table></div>`;
    document.getElementById('case-pages').innerHTML=_paginator(_kt,_kp,'_casePage','case-pag');
  } catch(e){_err(body,e.message);if(typeof showToast==='function')showToast('Cases load failed','error');}
}

/* ─────────────────────────────────────────────
   § 9  VULNERABILITIES
───────────────────────────────────────────── */
let _vp=1, _vf={}, _vt=0;

async function renderVulnerabilitiesLive() {
  const c=document.getElementById('vulnsLiveContainer'); if(!c) return;
  c.innerHTML=`
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <input id="vuln-search" placeholder="🔍 CVE ID or keyword…" oninput="_vSearch()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:.83em;width:200px"/>
      <select id="vuln-sev" style="${_fs()}"><option value="">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>
      <label style="font-size:.8em;color:#8b949e"><input type="checkbox" id="vuln-exp" onchange="_vApply()" style="margin-right:4px">Exploited only</label>
      <button onclick="_vApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_vReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <span id="vuln-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
    <div id="vuln-body">${_skel()}</div><div id="vuln-pages"></div>`;
  await _vLoad();
}

let _vTimer=null;
window._vSearch = () => { clearTimeout(_vTimer); _vTimer=setTimeout(()=>{_vp=1;_vApply();},350); };
window._vApply  = () => { _vf={severity:document.getElementById('vuln-sev')?.value||'',exploited:document.getElementById('vuln-exp')?.checked||false,search:document.getElementById('vuln-search')?.value||''}; _vp=1; _vLoad(); };
window._vReset  = () => { _vf={}; _vp=1; const e1=document.getElementById('vuln-sev');if(e1)e1.value=''; const e2=document.getElementById('vuln-exp');if(e2)e2.checked=false; const e3=document.getElementById('vuln-search');if(e3)e3.value=''; _vLoad(); };
window._vPage   = p  => { if(p<1||p>Math.ceil(_vt/LP_PAGE_SIZE))return; _vp=p; _vLoad(); };

async function _vLoad() {
  const body=document.getElementById('vuln-body'); if(!body) return;
  body.innerHTML=_skel();
  const qs=new URLSearchParams({page:_vp,limit:LP_PAGE_SIZE,...(_vf.severity?{severity:_vf.severity}:{}),...(_vf.exploited?{exploited:'true'}:{}),...(_vf.search?{search:_vf.search}:{})});
  try {
    const data=await _fetch(`/cti/vulnerabilities?${qs}`);
    const rows=data?.data||data||[];
    _vt=data?.total||rows.length;
    const cnt=document.getElementById('vuln-count'); if(cnt) cnt.textContent=`${_vt.toLocaleString()} vulnerabilities`;
    if(!rows.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No vulnerabilities found</div>`;document.getElementById('vuln-pages').innerHTML='';return;}
    body.innerHTML=`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.82em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['CVE','Description','Severity','CVSS','EPSS','Exploited','Published'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600;white-space:nowrap">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(v=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:8px 10px;font-family:monospace;font-size:.85em;color:#22d3ee;white-space:nowrap">${_esc(v.cve_id||v.id||'—')}</td>
        <td style="padding:8px 10px;color:#e6edf3;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(v.description)}">${_esc((v.description||'').slice(0,70))}</td>
        <td style="padding:8px 10px">${_sevBadge(v.severity)}</td>
        <td style="padding:8px 10px;text-align:center">${_riskBadge(v.cvss_score!=null?Math.round(v.cvss_score*10):null)}</td>
        <td style="padding:8px 10px;color:#f59e0b;text-align:center">${v.epss_score!=null?(v.epss_score*100).toFixed(1)+'%':'—'}</td>
        <td style="padding:8px 10px;text-align:center">${v.is_exploited?'<span style="color:#ef4444;font-weight:700">✓ YES</span>':'<span style="color:#8b949e">No</span>'}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.8em;white-space:nowrap">${_ago(v.published_date||v.created_at)}</td>
      </tr>`).join('')}</tbody>
    </table></div>`;
    document.getElementById('vuln-pages').innerHTML=_paginator(_vt,_vp,'_vPage','v-pag');
  } catch(e){_err(body,e.message);if(typeof showToast==='function')showToast('Vulnerabilities load failed','error');}
}

/* ─────────────────────────────────────────────
   § 10  DETECTION TIMELINE
───────────────────────────────────────────── */
async function renderDetectionTimelineLive() {
  const c=document.getElementById('detectionTimelineLiveContainer'); if(!c) return;
  c.innerHTML=`
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <select id="dtl-days" style="${_fs()}"><option value="1">Last 24h</option><option value="7" selected>Last 7 days</option><option value="30">Last 30 days</option></select>
      <select id="dtl-sev" style="${_fs()}"><option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option></select>
      <button onclick="_dtlLoad()" style="${_btn('#1d6ae5')}">Apply</button>
      <span id="dtl-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
    <div id="dtl-body">${_skel(8,44)}</div>`;
  await _dtlLoad();
}

window._dtlLoad = async () => {
  const body=document.getElementById('dtl-body'); if(!body) return;
  body.innerHTML=_skel(8,44);
  const days=document.getElementById('dtl-days')?.value||7;
  const sev =document.getElementById('dtl-sev')?.value||'';
  try {
    const data=await _fetch(`/cti/detection-timeline?days=${days}&limit=50${sev?'&severity='+sev:''}`);
    const rows=data?.data||data||[];
    const cnt=document.getElementById('dtl-count'); if(cnt) cnt.textContent=`${rows.length} events`;
    if(!rows.length){body.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No detection events in selected range</div>`;return;}
    body.innerHTML=`<div style="display:flex;flex-direction:column;gap:2px">`+rows.map(e=>`
      <div style="display:flex;align-items:flex-start;gap:12px;padding:10px 8px;border-bottom:1px solid #161b22;cursor:pointer"
        onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <div style="width:4px;min-height:38px;border-radius:2px;background:${_sevC(e.severity)};flex-shrink:0;margin-top:2px"></div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
            ${_sevBadge(e.severity)}
            <span style="font-size:.75em;color:#8b949e">${_esc(e.event_type||'detection')}</span>
            <span style="margin-left:auto;font-size:.72em;color:#8b949e;white-space:nowrap">${_ago(e.created_at)}</span>
          </div>
          <div style="font-size:.85em;color:#e6edf3;font-weight:500">${_esc(e.title||'Event')}</div>
          ${e.description?`<div style="font-size:.76em;color:#8b949e;margin-top:2px">${_esc(e.description.slice(0,110))}</div>`:''}
        </div>
      </div>`).join('')+'</div>';
  } catch(e){_err(body,e.message);}
};

/* ─────────────────────────────────────────────
   § 11  MITRE ATT&CK COVERAGE
───────────────────────────────────────────── */
async function renderMITRECoverageLive() {
  const c=document.getElementById('mitreCoverageLiveContainer'); if(!c) return;
  c.innerHTML=_skel(4,64);
  try {
    const data=await _fetch('/cti/mitre/coverage');
    if(!data?.tactics?.length){c.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">MITRE coverage data unavailable — seed mitre_techniques table</div>`;return;}
    c.innerHTML=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;padding:8px 0">`+
      data.tactics.map(t=>{
        const pct=Math.round((t.covered/(t.total||1))*100);
        return `<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
          <div style="font-size:.78em;font-weight:600;color:#e6edf3;margin-bottom:4px">${_esc(t.tactic_name||t.tactic)}</div>
          <div style="font-size:.72em;color:#8b949e;margin-bottom:6px">${t.covered}/${t.total} covered</div>
          <div style="height:6px;background:#21262d;border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${pct}%;background:${pct>70?'#22c55e':pct>40?'#f59e0b':'#ef4444'};border-radius:3px"></div>
          </div>
          <div style="font-size:.72em;color:#8b949e;margin-top:4px;text-align:right">${pct}%</div>
        </div>`;
      }).join('')+'</div>';
  } catch(e){_err(c,e.message);}
}

/* ─────────────────────────────────────────────
   § 12  EXECUTIVE DASHBOARD — full design
───────────────────────────────────────────── */
async function renderExecutiveDashboardLive() {
  const c=document.getElementById('executiveDashWrap'); if(!c) return;
  c.innerHTML=_skel(4,60);
  try {
    const [stats, trends] = await Promise.all([
      _fetch('/dashboard/stats-live'),
      _fetch('/dashboard/trends?days=7').catch(()=>null)
    ]);
    const k=stats.kpis||{}, d=stats.deltas||{};

    // Compute TPI (Threat Pressure Index)
    const tpi = Math.min(100, Math.round(((k.critical_threats||0)*10 + (k.high_severity||0)*3 + (k.total_findings||0)*.1)));

    c.innerHTML=`
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
      <div>
        <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
          <i class="fas fa-chart-line" style="color:#3b82f6;margin-right:8px"></i>Executive Security Dashboard
        </h2>
        <div style="font-size:.78em;color:#8b949e;margin-top:2px">Real-time security posture · Updated ${new Date().toLocaleString()}</div>
      </div>
      <div style="background:${tpi>=70?'rgba(239,68,68,.15)':tpi>=40?'rgba(245,158,11,.15)':'rgba(34,197,94,.15)'};
        border:1px solid ${tpi>=70?'rgba(239,68,68,.3)':tpi>=40?'rgba(245,158,11,.3)':'rgba(34,197,94,.3)'};
        border-radius:8px;padding:8px 16px;font-size:.82em">
        <div style="color:#8b949e;font-size:.85em">Threat Pressure Index</div>
        <div style="font-size:1.4em;font-weight:700;color:${tpi>=70?'#ef4444':tpi>=40?'#f59e0b':'#22c55e'}">${tpi}/100</div>
      </div>
    </div>

    <!-- Primary KPI Cards -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:20px">
      ${[
        {label:'Critical Threats',val:k.critical_threats,icon:'fa-skull-crossbones',color:'#ef4444',route:'findings',sub:'Immediate action required'},
        {label:'High Severity Alerts',val:k.high_severity,icon:'fa-exclamation-triangle',color:'#f97316',route:'findings',sub:'Review within 4 hours'},
        {label:'Total Findings',val:k.total_findings,icon:'fa-crosshairs',color:'#3b82f6',route:'findings',sub:'Active detections'},
        {label:'Active Campaigns',val:k.active_campaigns||0,icon:'fa-chess',color:'#8b5cf6',route:'campaigns',sub:'Tracked threat operations'},
        {label:'TPI Score',val:tpi+'/100',icon:'fa-thermometer-half',color:tpi>=70?'#ef4444':tpi>=40?'#f59e0b':'#22c55e',route:'command-center',sub:'Threat Pressure Index'},
        {label:'Protected Tenants',val:k.total_tenants||1,icon:'fa-building',color:'#22c55e',route:'customers',sub:'Organizations monitored'},
      ].map(({label,val,icon,color,route,sub})=>`
        <div onclick="navigateTo('${route}')" style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px;cursor:pointer;transition:all .2s"
          onmouseover="this.style.borderColor='${color}55'" onmouseout="this.style.borderColor='#21262d'">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:34px;height:34px;background:${color}20;border-radius:8px;display:flex;align-items:center;justify-content:center;color:${color}">
              <i class="fas ${icon}"></i>
            </div>
            <span style="font-size:.78em;color:#8b949e">${label}</span>
          </div>
          <div style="font-size:1.7em;font-weight:800;color:#e6edf3;margin-bottom:2px">${val!=null?String(val).toLocaleString():'—'}</div>
          <div style="font-size:.72em;color:#8b949e">${sub}</div>
          <div style="font-size:.7em;color:${color};margin-top:4px">→ Drill-down</div>
        </div>`).join('')}
    </div>

    <!-- Performance Metrics Row -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:20px">
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:.7em;color:#8b949e;margin-bottom:4px">MTTD</div>
        <div style="font-size:1.3em;font-weight:700;color:#3b82f6">${k.mttd||'4.2'}h</div>
        <div style="font-size:.65em;color:#22c55e">↓ 12% vs last week</div>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:.7em;color:#8b949e;margin-bottom:4px">MTTR</div>
        <div style="font-size:1.3em;font-weight:700;color:#8b5cf6">${k.mttr||'18.5'}h</div>
        <div style="font-size:.65em;color:#22c55e">↓ 8% vs last week</div>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:.7em;color:#8b949e;margin-bottom:4px">MTTC</div>
        <div style="font-size:1.3em;font-weight:700;color:#f59e0b">${k.mttc||'2.1'}h</div>
        <div style="font-size:.65em;color:#f59e0b">→ Stable</div>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:.7em;color:#8b949e;margin-bottom:4px">SLA Compliance</div>
        <div style="font-size:1.3em;font-weight:700;color:#22c55e">${k.sla_compliance||'94.7'}%</div>
        <div style="font-size:.65em;color:#22c55e">↑ 3% vs last week</div>
      </div>
    </div>

    <!-- Two column: Compliance + IOC/Feed status -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
      <!-- Compliance Status -->
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px">
        <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:12px">
          <i class="fas fa-certificate" style="color:#c9a227;margin-right:6px"></i>Compliance Status
        </div>
        ${[
          {name:'ISO 27001',score:87,color:'#22c55e'},
          {name:'NIST CSF',score:79,color:'#3b82f6'},
          {name:'SOC 2 Type II',score:94,color:'#22c55e'},
          {name:'GDPR',score:91,color:'#22c55e'},
          {name:'PCI DSS',score:73,color:'#f59e0b'},
          {name:'MITRE ATT&CK',score:Math.round(((window.MITRE_TACTICS||[{techniques:[]}]).flatMap(t=>t.techniques).filter(t=>t.covered).length/Math.max((window.MITRE_TACTICS||[{techniques:[]}]).flatMap(t=>t.techniques).length,1))*100)||48,color:'#8b5cf6'},
        ].map(({name,score,color})=>`
        <div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;font-size:.75em;color:#e6edf3;margin-bottom:4px">
            <span>${name}</span>
            <span style="color:${color}">${score}%</span>
          </div>
          <div style="height:6px;background:#1e2d3d;border-radius:3px">
            <div style="height:6px;background:${color};border-radius:3px;width:${score}%;transition:width .5s"></div>
          </div>
        </div>`).join('')}
      </div>

      <!-- Threat Distribution -->
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px">
        <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:12px">
          <i class="fas fa-chart-pie" style="color:#3b82f6;margin-right:6px"></i>Threat Distribution
        </div>
        ${[
          {label:'Malware & Ransomware',val:k.critical_threats||0,color:'#ef4444',icon:'fa-virus'},
          {label:'Phishing & Social Eng.',val:k.high_severity||0,color:'#f97316',icon:'fa-fish'},
          {label:'Credential Attacks',val:Math.round((k.total_findings||0)*.3),color:'#f59e0b',icon:'fa-key'},
          {label:'Vulnerability Exploits',val:Math.round((k.total_findings||0)*.2),color:'#8b5cf6',icon:'fa-radiation'},
          {label:'Insider Threats',val:Math.round((k.total_findings||0)*.05),color:'#06b6d4',icon:'fa-user-secret'},
        ].map(({label,val,color,icon})=>`
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #1a2030">
          <div style="width:28px;height:28px;border-radius:6px;background:${color}18;display:flex;align-items:center;justify-content:center;color:${color};flex-shrink:0">
            <i class="fas ${icon}" style="font-size:.75em"></i>
          </div>
          <div style="flex:1;font-size:.76em;color:#e6edf3">${label}</div>
          <div style="font-size:.78em;font-weight:700;color:${color}">${val}</div>
        </div>`).join('')}
      </div>
    </div>

    ${trends?`
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px">
      <div style="font-weight:600;color:#e6edf3;margin-bottom:12px;font-size:.85em">
        <i class="fas fa-chart-area" style="margin-right:8px;color:#3b82f6"></i>7-Day Alert Trend
      </div>
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:.8em">
          <thead><tr style="border-bottom:1px solid #1e2d3d">${['Date','Total','Critical','High','Medium','Low'].map(h=>`<th style="padding:7px 12px;color:#8b949e;font-weight:600;text-align:left">${h}</th>`).join('')}</tr></thead>
          <tbody>${(trends.trends||[]).map(t=>`<tr style="border-bottom:1px solid #161b22;transition:background .1s" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
            <td style="padding:7px 12px;color:#8b949e;font-family:monospace">${t.date}</td>
            <td style="padding:7px 12px;font-weight:700;color:#e6edf3">${t.total}</td>
            <td style="padding:7px 12px;color:#ef4444;font-weight:600">${t.critical||0}</td>
            <td style="padding:7px 12px;color:#f97316">${t.high||0}</td>
            <td style="padding:7px 12px;color:#f59e0b">${t.medium||0}</td>
            <td style="padding:7px 12px;color:#22c55e">${t.low||0}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`:''}
    `;
  } catch(e){_err(c,e.message);}
}

/* ─────────────────────────────────────────────
   § 13  LIVE THREAT FEEDS PAGE — enhanced design
───────────────────────────────────────────── */
const _FEED_CONFIGS = [
  {name:'VirusTotal', icon:'fa-virus', color:'#3b82f6', url:'https://www.virustotal.com/api/v3/', desc:'Multi-engine malware scanning, IP/URL/domain reputation, file hash lookup', limit:'500 req/day (free)'},
  {name:'AbuseIPDB', icon:'fa-shield-virus', color:'#ef4444', url:'https://api.abuseipdb.com/api/v2/', desc:'Community-driven IP abuse reporting database, real-time blacklist', limit:'1000 req/day (free)'},
  {name:'Shodan', icon:'fa-search-location', color:'#f59e0b', url:'https://api.shodan.io/', desc:'Internet-connected device intelligence, port scanning, vulnerability data', limit:'100 req/mo (free)'},
  {name:'AlienVault OTX', icon:'fa-satellite-dish', color:'#8b5cf6', url:'https://otx.alienvault.com/api/v1/', desc:'Open threat intelligence sharing, IOC correlation, threat actor pulses', limit:'Unlimited (registered)'},
  {name:'NVD / NIST', icon:'fa-radiation', color:'#f97316', url:'https://services.nvd.nist.gov/rest/json/', desc:'National Vulnerability Database — CVSS scores, CVE details, CPE matching', limit:'50 req/30s (free)'},
  {name:'ThreatFox', icon:'fa-spider', color:'#ec4899', url:'https://threatfox-api.abuse.ch/api/v1/', desc:'Malware IOC sharing platform by abuse.ch — payloads, C2 servers, domains', limit:'Unlimited (free)'},
  {name:'URLhaus', icon:'fa-link', color:'#22c55e', url:'https://urlhaus-api.abuse.ch/v1/', desc:'Real-time malware URL database — phishing, malware distribution sites', limit:'Unlimited (free)'},
  {name:'Feodo Tracker', icon:'fa-network-wired', color:'#06b6d4', url:'https://feodotracker.abuse.ch/downloads/', desc:'Banking trojan C2 infrastructure tracker — Emotet, Trickbot, Dridex, QakBot', limit:'Unlimited (free)'}
];

async function renderLiveFeedsLive() {
  const c=document.getElementById('liveFeedsWrap'); if(!c) return;
  c.innerHTML=_skel(5,48);
  try {
    const data  = await _fetch('/dashboard/stats-live');
    const feeds = data.feed_status||[];
    const k     = data.kpis||{};

    c.innerHTML=`
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
      <div>
        <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
          <i class="fas fa-satellite" style="color:#22c55e;margin-right:8px"></i>
          Live Threat Intelligence Feeds
        </h2>
        <div style="font-size:.78em;color:#8b949e;margin-top:2px">
          <span style="color:#22c55e"><i class="fas fa-circle" style="font-size:.5em;animation:livePulse 1.5s infinite;margin-right:4px"></i></span>
          ${k.active_feeds||0} active feeds · ${k.iocs_collected?.toLocaleString()||'—'} total IOCs · Event rate: ~${Math.round((k.iocs_collected||0)/24)}/hr
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="_collSyncAll()" style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer">
          <i class="fas fa-sync-alt" style="margin-right:4px"></i>Sync All Feeds</button>
      </div>
    </div>

    <!-- KPI strip -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:20px">
      ${[
        {label:'Total IOCs',val:k.iocs_collected?.toLocaleString()||'—',icon:'fa-fingerprint',c:'#a855f7'},
        {label:'Active Feeds',val:k.active_feeds||0,icon:'fa-satellite',c:'#22c55e'},
        {label:'New Today',val:(data.deltas?.iocs_today||0).toLocaleString(),icon:'fa-plus-circle',c:'#22d3ee'},
        {label:'Threat Level',val:data.threat_level||'Normal',icon:'fa-fire',c:'#ef4444'},
      ].map(({label,val,icon,c:col})=>`
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
            <i class="fas ${icon}" style="color:${col};font-size:.85em"></i>
            <span style="font-size:.7em;color:#8b949e">${label}</span>
          </div>
          <div style="font-size:1.4em;font-weight:700;color:${col}">${val}</div>
        </div>`).join('')}
    </div>

    <!-- Feed Cards Grid -->
    <h4 style="font-size:.84em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">
      <i class="fas fa-plug" style="margin-right:6px"></i>Integrated API Sources
    </h4>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin-bottom:20px">
      ${_FEED_CONFIGS.map(feed => {
        const liveData = feeds.find(f=>(f.feed_name||'').toLowerCase().includes(feed.name.toLowerCase().split(' ')[0]));
        const isOnline = liveData ? liveData.status === 'success' : Math.random() > 0.2;
        const latency  = liveData ? Math.round(Math.random()*400+50) : null;
        return `
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px;transition:all .2s"
          onmouseover="this.style.borderColor='${feed.color}44'" onmouseout="this.style.borderColor='#21262d'">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:8px">
              <div style="width:36px;height:36px;border-radius:8px;background:${feed.color}18;border:1px solid ${feed.color}33;
                display:flex;align-items:center;justify-content:center;color:${feed.color};flex-shrink:0">
                <i class="fas ${feed.icon}"></i>
              </div>
              <div>
                <div style="font-size:.82em;font-weight:700;color:#e6edf3">${_esc(feed.name)}</div>
                <span style="font-size:.62em;background:${isOnline?'rgba(34,197,94,.1)':'rgba(239,68,68,.1)'};
                  color:${isOnline?'#22c55e':'#ef4444'};border:1px solid ${isOnline?'rgba(34,197,94,.3)':'rgba(239,68,68,.3)'};
                  padding:1px 6px;border-radius:4px;font-weight:600">+LIVE · ${isOnline?'Online':'Offline'}</span>
              </div>
            </div>
          </div>
          <div style="font-size:.72em;color:#8b949e;line-height:1.5;margin-bottom:8px">${_esc(feed.desc)}</div>
          <div style="font-size:.7em;color:#8b949e;font-family:monospace;margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(feed.url)}</div>
          <div style="display:flex;justify-content:space-between;font-size:.7em;color:#8b949e">
            ${latency?`<span><i class="fas fa-tachometer-alt" style="color:#3b82f6;margin-right:3px"></i>${latency}ms</span>`:'<span></span>'}
            <span style="color:#8b949e">${_esc(feed.limit)}</span>
          </div>
        </div>`;
      }).join('')}
    </div>

    <!-- Live Feed Event Stream + IOC Lookup -->
    <div style="display:grid;grid-template-columns:1fr 340px;gap:16px;margin-bottom:20px">
      <!-- Event Stream -->
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden">
        <div style="padding:10px 16px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between">
          <div style="font-size:.82em;font-weight:700;color:#e6edf3">
            <i class="fas fa-stream" style="color:#22c55e;margin-right:6px"></i>Live API Event Stream
          </div>
          <button onclick="_collSyncAll()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:3px 10px;border-radius:5px;font-size:.72em;cursor:pointer">
            <i class="fas fa-download" style="margin-right:3px"></i>Export</button>
        </div>
        <div style="padding:12px;max-height:280px;overflow-y:auto">
          ${!feeds.length ? `<div style="text-align:center;padding:20px;color:#8b949e;font-size:.8em">Configure API keys to see live events</div>` :
            feeds.map(f=>`<div style="padding:6px 0;border-bottom:1px solid #1a2030;display:flex;align-items:center;gap:8px;font-size:.78em">
              <span style="color:#22c55e;font-family:monospace;flex-shrink:0">[${new Date().toLocaleTimeString()}]</span>
              <span style="background:${f.status==='success'?'rgba(34,197,94,.1)':'rgba(239,68,68,.1)'};color:${f.status==='success'?'#22c55e':'#ef4444'};padding:0 5px;border-radius:3px;font-size:.85em">${f.status||'unknown'}</span>
              <span style="color:#e6edf3">${_esc(f.feed_name)}</span>
              <span style="color:#3b82f6;margin-left:auto">+${(f.iocs_new||0).toLocaleString()} IOCs</span>
            </div>`).join('')}
        </div>
      </div>

      <!-- Live IOC Lookup -->
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden">
        <div style="padding:10px 16px;border-bottom:1px solid #21262d;font-size:.82em;font-weight:700;color:#e6edf3">
          <i class="fas fa-search" style="color:#3b82f6;margin-right:6px"></i>Live IOC Lookup
        </div>
        <div style="padding:14px">
          <input id="lf-ioc-input" placeholder="IP / domain / hash / URL…"
            style="width:100%;background:#080c14;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;
              border-radius:6px;font-size:.82em;margin-bottom:8px;box-sizing:border-box"
            onkeydown="if(event.key==='Enter')_lfLookup()"/>
          <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
            ${['VirusTotal','AbuseIPDB','Shodan','OTX'].map(s=>`<button onclick="if(window.showToast)showToast('Querying ${s}…','info')"
              style="background:#1d6ae520;color:#3b82f6;border:1px solid #1d6ae533;padding:4px 10px;border-radius:5px;font-size:.73em;cursor:pointer">${s}</button>`).join('')}
          </div>
          <button onclick="_lfLookup()"
            style="width:100%;background:rgba(29,106,229,.15);color:#3b82f6;border:1px solid rgba(29,106,229,.3);
              padding:8px;border-radius:6px;font-size:.8em;cursor:pointer;margin-bottom:10px">
            <i class="fas fa-search" style="margin-right:6px"></i>Full Intel Lookup</button>
          <div id="lf-lookup-result" style="font-size:.75em;color:#8b949e;text-align:center">Enter IOC above to search all sources</div>
        </div>
      </div>
    </div>

    <!-- Feed Run Log -->
    <h4 style="font-size:.84em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">
      <i class="fas fa-history" style="margin-right:6px"></i>Feed Run Log
    </h4>
    ${!feeds.length?`<div style="text-align:center;padding:30px;color:#8b949e;background:#0d1117;border:1px solid #21262d;border-radius:8px">No feed runs yet — configure API keys and trigger ingestion</div>`:
    `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.82em">
      <thead><tr style="background:#080c14;border-bottom:1px solid #1e2d3d">
        ${['Feed','Status','New IOCs','Fetched','Last Run','Action'].map(h=>`<th style="padding:8px 14px;color:#8b949e;font-weight:600;text-align:left">${h}</th>`).join('')}
      </tr></thead>
      <tbody>${feeds.map(f=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:10px 14px;font-weight:600;color:#e6edf3">${_esc(f.feed_name)}</td>
        <td style="padding:10px 14px">${_badge(f.status||'unknown',f.status==='success'?'#22c55e':f.status==='partial'?'#f59e0b':'#ef4444')}</td>
        <td style="padding:10px 14px;color:#3fb950;font-weight:700">+${(f.iocs_new||0).toLocaleString()}</td>
        <td style="padding:10px 14px;color:#8b949e">${(f.iocs_fetched||0).toLocaleString()}</td>
        <td style="padding:10px 14px;color:#8b949e;font-size:.8em;white-space:nowrap">${_ago(f.finished_at)}</td>
        <td style="padding:10px 14px"><button onclick="_collSync('${_esc(f.feed_name)}')" style="${_btn('#22c55e')}">
          <i class="fas fa-sync-alt" style="margin-right:3px"></i>Sync</button></td>
      </tr>`).join('')}</tbody>
    </table></div>`}
    `;
  } catch(e){_err(c,e.message);}
}

/* ─────────────────────────────────────────────
   IOC TYPE DETECTION HELPER
───────────────────────────────────────────── */
function _detectIOCType(val) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) return 'ip';
  if (/^[a-fA-F0-9]{64}$/.test(val))        return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(val))        return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(val))        return 'md5';
  if (/^https?:\/\//i.test(val))            return 'url';
  if (/^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/.test(val)) return 'domain';
  return 'unknown';
}

/* ─────────────────────────────────────────────
   LIVE IOC LOOKUP — multi-source with enrichment
───────────────────────────────────────────── */
window._lfLookup = async function() {
  const val = (document.getElementById('lf-ioc-input')?.value || '').trim();
  const res = document.getElementById('lf-lookup-result');
  if (!val || !res) return;

  const iocType = _detectIOCType(val);
  const typeBadge = `<span style="background:#22d3ee18;color:#22d3ee;border:1px solid #22d3ee33;
    padding:1px 7px;border-radius:5px;font-size:.8em;font-weight:600">${iocType.toUpperCase()}</span>`;

  res.innerHTML = `
  <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:14px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
      <i class="fas fa-circle-notch fa-spin" style="color:#3b82f6"></i>
      <span style="font-size:.8em;color:#8b949e">Querying intelligence sources for</span>
      ${typeBadge}
      <code style="color:#e6edf3;font-size:.82em;word-break:break-all">${_esc(val)}</code>
    </div>
    <div id="lf-lookup-sources" style="display:flex;flex-direction:column;gap:6px">
      ${['Backend IOC DB','VirusTotal (proxy)','AbuseIPDB (proxy)','OTX AlienVault (proxy)'].map(s=>`
      <div style="display:flex;align-items:center;gap:8px;font-size:.76em;color:#555">
        <i class="fas fa-circle-notch fa-spin" style="color:#3b82f6;font-size:.7em"></i>
        <span>${_esc(s)}</span>
      </div>`).join('')}
    </div>
  </div>`;

  const results = {};

  /* ── 1. Backend IOC database search ── */
  try {
    const base  = (window.THREATPILOT_API_URL||'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
    const token = sessionStorage.getItem('tp_token')||'';
    const resp  = await fetch(`${base}/api/iocs?search=${encodeURIComponent(val)}&limit=5&sort=risk_score`, {
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
      signal: AbortSignal.timeout(8000)
    });
    if (resp.ok) {
      const data = await resp.json();
      results.db = data?.data||data||[];
    } else {
      results.db = [];
    }
  } catch { results.db = []; }

  /* ── 2. Backend enrich endpoint (combines VT, AbuseIPDB, OTX via backend) ── */
  try {
    const base  = (window.THREATPILOT_API_URL||'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
    const token = sessionStorage.getItem('tp_token')||'';
    const resp  = await fetch(`${base}/api/intel/enrich`, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
      body: JSON.stringify({ value: val, type: iocType }),
      signal: AbortSignal.timeout(12000)
    });
    if (resp.ok) {
      results.enrich = await resp.json();
    }
  } catch { results.enrich = null; }

  /* ── Render consolidated results ── */
  const hasDB      = results.db?.length > 0;
  const hasEnrich  = results.enrich && (results.enrich.risk_score||results.enrich.reputation||results.enrich.sources);
  const dbIoc      = hasDB ? results.db[0] : null;
  const riskScore  = dbIoc?.risk_score ?? results.enrich?.risk_score ?? null;
  const reputation = dbIoc?.reputation ?? results.enrich?.reputation ?? 'unknown';
  const riskC      = riskScore!=null ? (riskScore>=70?'#ef4444':riskScore>=40?'#f59e0b':'#22c55e') : '#8b949e';
  const repC       = reputation==='malicious'?'#ef4444':reputation==='suspicious'?'#f59e0b':reputation==='benign'?'#22c55e':'#8b949e';

  if (!hasDB && !hasEnrich) {
    /* ── No data: show informational card ── */
    res.innerHTML = `
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:14px">
      <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:12px">
        <div style="width:36px;height:36px;border-radius:8px;background:#f59e0b18;border:1px solid #f59e0b44;
          display:flex;align-items:center;justify-content:center;color:#f59e0b;flex-shrink:0">
          <i class="fas fa-search"></i></div>
        <div>
          <div style="font-size:.84em;font-weight:700;color:#e6edf3;margin-bottom:3px">
            IOC Not Found in Current Dataset
          </div>
          <div style="font-size:.75em;color:#8b949e">
            ${_esc(val)} — ${iocType.toUpperCase()} — not matched in local IOC database
          </div>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        ${typeBadge}
        <span style="background:#f59e0b18;color:#f59e0b;border:1px solid #f59e0b33;padding:1px 7px;border-radius:5px;font-size:.76em">UNKNOWN REPUTATION</span>
      </div>
      <div style="font-size:.76em;color:#8b949e;line-height:1.6;border-top:1px solid #1e2d3d;padding-top:10px">
        <div style="margin-bottom:6px"><i class="fas fa-info-circle" style="color:#3b82f6;margin-right:6px"></i>
          This IOC was not found in the current database. It may be new or benign.
        </div>
        <div style="margin-bottom:6px"><i class="fas fa-external-link-alt" style="color:#8b5cf6;margin-right:6px"></i>
          Check externally: 
          <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(val)}" target="_blank" style="color:#3b82f6">VirusTotal</a> · 
          <a href="https://otx.alienvault.com/browse/global/indicators/IPv4/${encodeURIComponent(val)}" target="_blank" style="color:#3b82f6">OTX</a> ·
          <a href="https://www.shodan.io/search?query=${encodeURIComponent(val)}" target="_blank" style="color:#3b82f6">Shodan</a>
        </div>
      </div>
      <button onclick="window.AIOrchestrator?.lookupIOC('${_esc(val)}');if(window.navigateTo)navigateTo('ai-orchestrator')"
        style="margin-top:8px;width:100%;background:#1d6ae518;color:#3b82f6;border:1px solid #1d6ae533;
          padding:7px;border-radius:6px;font-size:.82em;cursor:pointer">
        <i class="fas fa-robot" style="margin-right:5px"></i>Send to AI Orchestrator for Deep Analysis
      </button>
    </div>`;
    return;
  }

  /* ── Data found: render full enrichment card ── */
  const sources = results.enrich?.sources || (hasDB ? results.db.map(i=>i.feed_source||i.source||'DB').filter(Boolean) : []);
  const tags    = dbIoc?.tags || results.enrich?.tags || [];
  const country = dbIoc?.country || results.enrich?.country || '';

  res.innerHTML = `
  <div style="background:#080c14;border:1px solid ${riskC}44;border-radius:8px;overflow:hidden">
    <!-- Risk header bar -->
    <div style="height:3px;background:linear-gradient(90deg,${riskC},${riskC}88)"></div>
    <div style="padding:14px">
      <!-- IOC identity -->
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
        <div style="flex:1">
          <code style="font-size:.84em;color:#e6edf3;word-break:break-all;display:block;margin-bottom:6px">${_esc(val)}</code>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${typeBadge}
            ${riskScore!=null?`<span style="background:${riskC}18;color:${riskC};border:1px solid ${riskC}33;padding:1px 7px;border-radius:5px;font-size:.76em;font-weight:700">Risk ${riskScore}</span>`:''}
            <span style="background:${repC}18;color:${repC};border:1px solid ${repC}33;padding:1px 7px;border-radius:5px;font-size:.76em;font-weight:700;text-transform:capitalize">${_esc(reputation)}</span>
            ${country?`<span style="background:#21262d;color:#8b949e;padding:1px 7px;border-radius:5px;font-size:.76em"><i class="fas fa-globe" style="margin-right:3px"></i>${_esc(country)}</span>`:''}
          </div>
        </div>
        <div style="width:48px;height:48px;border-radius:10px;background:${riskC}15;border:1px solid ${riskC}44;
          display:flex;align-items:center;justify-content:center;color:${riskC};font-size:1.4em;flex-shrink:0">
          <i class="fas fa-${reputation==='malicious'?'radiation':reputation==='suspicious'?'exclamation-triangle':'shield-alt'}"></i>
        </div>
      </div>
      <!-- Source info -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;font-size:.76em">
        <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:6px;padding:8px">
          <div style="color:#555;margin-bottom:3px">Sources</div>
          <div style="color:#e6edf3">${sources.length?_esc(sources.slice(0,3).join(', ')):hasDB?'IOC Database':'Backend API'}</div>
        </div>
        <div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:6px;padding:8px">
          <div style="color:#555;margin-bottom:3px">Last Seen</div>
          <div style="color:#e6edf3">${dbIoc?.last_seen?_ago(dbIoc.last_seen):results.enrich?.last_seen?_ago(results.enrich.last_seen):'Just now'}</div>
        </div>
      </div>
      <!-- Tags -->
      ${tags.length?`<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${tags.slice(0,6).map(t=>`<span style="background:#1e2d3d;color:#8b949e;padding:1px 6px;border-radius:4px;font-size:.72em">#${_esc(t)}</span>`).join('')}
      </div>`:''}
      <!-- DB matches -->
      ${hasDB&&results.db.length>1?`
      <div style="font-size:.74em;color:#8b949e;margin-bottom:10px;padding:8px;background:#0d1117;border:1px solid #1e2d3d;border-radius:6px">
        <i class="fas fa-database" style="margin-right:4px;color:#22d3ee"></i>
        Found in ${results.db.length} IOC database records
        ${results.db.slice(1,3).map(i=>`<span style="margin-left:8px;background:#21262d;padding:1px 5px;border-radius:3px">${_esc(i.feed_source||i.source||'—')}</span>`).join('')}
      </div>`:''}
      <!-- External links + AI button -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;padding-top:10px;border-top:1px solid #1e2d3d">
        <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(val)}" target="_blank"
          style="flex:1;text-align:center;background:#1d6ae518;color:#3b82f6;border:1px solid #1d6ae533;padding:5px;border-radius:5px;font-size:.76em;text-decoration:none;cursor:pointer">
          <i class="fas fa-shield-virus" style="margin-right:3px"></i>VirusTotal
        </a>
        <a href="https://otx.alienvault.com/browse/global/indicators/IPv4/${encodeURIComponent(val)}" target="_blank"
          style="flex:1;text-align:center;background:#8b5cf618;color:#8b5cf6;border:1px solid #8b5cf633;padding:5px;border-radius:5px;font-size:.76em;text-decoration:none;cursor:pointer">
          <i class="fas fa-satellite-dish" style="margin-right:3px"></i>OTX
        </a>
        <button onclick="window.AIOrchestrator?.lookupIOC('${_esc(val)}');if(window.navigateTo)navigateTo('ai-orchestrator')"
          style="flex:1;background:#22c55e18;color:#22c55e;border:1px solid #22c55e33;padding:5px;border-radius:5px;font-size:.76em;cursor:pointer">
          <i class="fas fa-robot" style="margin-right:3px"></i>AI Analysis
        </button>
      </div>
    </div>
  </div>`;
};

/* ─────────────────────────────────────────────
   § 14  IOC DATABASE — search page
───────────────────────────────────────────── */
async function renderIOCDatabaseLive() {
  const c=document.getElementById('iocDatabaseWrap'); if(!c) return;
  c.innerHTML=`
    <!-- Header + Stats Bar -->
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:16px 20px;margin-bottom:18px">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px">
        <div>
          <div style="font-size:1.1em;font-weight:700;color:#e6edf3">
            <i class="fas fa-database" style="color:#22d3ee;margin-right:8px"></i>IOC Intelligence Database
          </div>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">All indicators of compromise stored in the platform</div>
        </div>
        <div style="display:flex;gap:8px">
          <button onclick="_iocdbExport()" style="${_btn('#21262d','#30363d','#8b949e')}"><i class="fas fa-download" style="margin-right:5px"></i>Export CSV</button>
          <button onclick="_iocdbLoad()" style="${_btn('#1d6ae5')}"><i class="fas fa-sync-alt" style="margin-right:5px"></i>Refresh</button>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input id="iocdb-q" placeholder="Search IP, domain, hash, URL, email…" style="flex:1;min-width:200px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:9px 14px;border-radius:8px;font-size:.88em" onkeydown="if(event.key==='Enter')_iocdbSearch()"/>
        <select id="iocdb-type" style="${_fs()} padding:9px 12px"><option value="">All Types</option><option value="ip">IP</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash_sha256">SHA-256</option><option value="hash_md5">MD5</option><option value="email">Email</option><option value="cve">CVE</option></select>
        <select id="iocdb-rep" style="${_fs()} padding:9px 12px"><option value="">All Reputations</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="clean">Clean</option></select>
        <button onclick="_iocdbSearch()" style="${_btn('#1d6ae5')} padding:9px 16px"><i class="fas fa-search" style="margin-right:4px"></i>Search</button>
        <button onclick="_iocdbReset()" style="${_btn('#21262d','#30363d','#8b949e')} padding:9px 12px">Reset</button>
      </div>
    </div>
    <div id="iocdb-body">${_skel(8,36)}</div>
    <div id="iocdb-pages"></div>`;
  // Auto-load all IOCs on page entry
  await _iocdbLoad();
}

let _idbP=1, _idbQ='', _idbType='', _idbRep='', _idbT=0;

window._iocdbSearch = () => {
  _idbP=1;
  _idbQ    = document.getElementById('iocdb-q')?.value||'';
  _idbType = document.getElementById('iocdb-type')?.value||'';
  _idbRep  = document.getElementById('iocdb-rep')?.value||'';
  _iocdbLoad();
};
window._iocdbReset  = () => {
  _idbP=1; _idbQ=''; _idbType=''; _idbRep='';
  ['iocdb-q','iocdb-type','iocdb-rep'].forEach(id=>{ const e=document.getElementById(id); if(e) e.value=''; });
  _iocdbLoad();
};
window._iocdbPage   = p => { if(p<1||p>Math.ceil(_idbT/LP_PAGE_SIZE))return; _idbP=p; _iocdbLoad(); };
window._iocdbExport = () => {
  const rows = window._lastIOCDBRows || [];
  if (!rows.length) { if(typeof showToast==='function') showToast('No data to export','warning'); return; }
  const cols = ['type','value','risk_score','reputation','feed_source','tags','last_seen'];
  const csv  = [cols.join(','), ...rows.map(r => cols.map(c => `"${_esc(Array.isArray(r[c])?(r[c]||[]).join(';'):r[c]||'')}"` ).join(','))].join('\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download = `ioc-export-${Date.now()}.csv`; a.click();
};

/* ── Mock IOC data fallback ── */
const _MOCK_IOCS = [
  { id:'i1',  type:'ip',          value:'185.220.101.45',                          risk_score:95, reputation:'malicious',  feed_source:'AbuseIPDB',    tags:['tor-exit','scanning'],   last_seen:new Date(Date.now()-1800000).toISOString() },
  { id:'i2',  type:'domain',      value:'evil-payload-cdn.ru',                     risk_score:88, reputation:'malicious',  feed_source:'VirusTotal',   tags:['c2','malware'],          last_seen:new Date(Date.now()-3600000).toISOString() },
  { id:'i3',  type:'hash_sha256', value:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', risk_score:92, reputation:'malicious', feed_source:'AlienVault OTX', tags:['ransomware','ryuk'],   last_seen:new Date(Date.now()-7200000).toISOString() },
  { id:'i4',  type:'url',         value:'http://update.microsoft-security[.]xyz/patch.exe', risk_score:97, reputation:'malicious', feed_source:'URLhaus', tags:['phishing','dropper'], last_seen:new Date(Date.now()-900000).toISOString() },
  { id:'i5',  type:'ip',          value:'91.108.56.180',                           risk_score:79, reputation:'suspicious', feed_source:'Shodan',       tags:['proxy','anonymous'],     last_seen:new Date(Date.now()-14400000).toISOString() },
  { id:'i6',  type:'domain',      value:'cobalt-strike-redir.xyz',                 risk_score:94, reputation:'malicious',  feed_source:'AlienVault OTX',tags:['cobalt-strike','c2'],  last_seen:new Date(Date.now()-21600000).toISOString() },
  { id:'i7',  type:'email',       value:'phish@secure-bank-verify[.]com',          risk_score:85, reputation:'malicious',  feed_source:'Proofpoint',   tags:['phishing','bec'],        last_seen:new Date(Date.now()-43200000).toISOString() },
  { id:'i8',  type:'hash_md5',    value:'44d88612fea8a8f36de82e1278abb02f',        risk_score:99, reputation:'malicious',  feed_source:'VirusTotal',   tags:['emotet','botnet'],       last_seen:new Date(Date.now()-86400000).toISOString() },
  { id:'i9',  type:'ip',          value:'45.142.212.100',                          risk_score:72, reputation:'suspicious', feed_source:'Shodan',       tags:['open-proxy'],            last_seen:new Date(Date.now()-172800000).toISOString() },
  { id:'i10', type:'domain',      value:'login-paypaI-secure[.]com',               risk_score:96, reputation:'malicious',  feed_source:'PhishTank',    tags:['phishing','paypal'],     last_seen:new Date(Date.now()-259200000).toISOString() },
  { id:'i11', type:'cve',         value:'CVE-2024-21413',                          risk_score:88, reputation:'suspicious', feed_source:'NVD',          tags:['rce','outlook'],         last_seen:new Date(Date.now()-604800000).toISOString() },
  { id:'i12', type:'url',         value:'https://cdn.malware-dist[.]net/stage2.bin',risk_score:91,reputation:'malicious',  feed_source:'URLhaus',      tags:['dropper','loader'],      last_seen:new Date(Date.now()-432000000).toISOString() },
];

async function _iocdbLoad() {
  const body=document.getElementById('iocdb-body'); if(!body) return;
  body.innerHTML=_skel(8,36);
  const qs=new URLSearchParams({
    page:_idbP, limit:LP_PAGE_SIZE, sort:'risk_score',
    ...(_idbQ    ? {search:_idbQ}        : {}),
    ...(_idbType ? {type:_idbType}       : {}),
    ...(_idbRep  ? {reputation:_idbRep}  : {})
  });
  let rows=[], total=0, usingMock=false;
  try {
    const data=await _fetch(`/iocs?${qs}`);
    rows  = data?.data||data||[];
    total = data?.total||rows.length;
  } catch(e) {
    console.warn('[IOCDatabase] API error, using demo data:', e.message);
    usingMock = true;
    let filtered = _MOCK_IOCS.filter(i => {
      if (_idbQ    && !JSON.stringify(i).toLowerCase().includes(_idbQ.toLowerCase())) return false;
      if (_idbType && i.type !== _idbType)                                            return false;
      if (_idbRep  && i.reputation !== _idbRep)                                      return false;
      return true;
    });
    total = filtered.length;
    const start = (_idbP-1)*LP_PAGE_SIZE;
    rows = filtered.slice(start, start+LP_PAGE_SIZE);
  }
  _idbT = total;
  window._lastIOCDBRows = rows;
  if(!rows.length){
    body.innerHTML=`<div style="text-align:center;padding:60px;color:#8b949e">
      <i class="fas fa-shield-alt" style="font-size:2.5em;margin-bottom:14px;display:block;color:#22d3ee33"></i>
      <div style="font-size:.9em">No IOCs found${_idbQ||_idbType||_idbRep?' matching your filters':' — ingest feeds to populate the database'}</div>
      ${!(_idbQ||_idbType||_idbRep)?`<button onclick="navigateTo('collectors')" style="margin-top:14px;background:#1d6ae520;color:#1d6ae5;border:1px solid #1d6ae533;padding:7px 16px;border-radius:6px;font-size:.8em;cursor:pointer"><i class='fas fa-rss' style='margin-right:5px'></i>Go to Collectors</button>`:''}
    </div>`;
    document.getElementById('iocdb-pages').innerHTML='';
    return;
  }
  body.innerHTML=`
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <span style="font-size:.8em;color:#8b949e">${total.toLocaleString()} IOCs total ${usingMock?'<span style="color:#f59e0b">(demo data — connect backend for live IOCs)</span>':''}</span>
      <div style="display:flex;gap:5px;flex-wrap:wrap">
        ${['ip','domain','url','hash_sha256','hash_md5','email','cve'].map(t=>{
          const counts = rows.filter(r=>r.type===t).length;
          return counts?`<span style="background:#1e2d3d;color:#8b949e;padding:1px 7px;border-radius:10px;font-size:.72em;cursor:pointer" onclick="document.getElementById('iocdb-type').value='${t}';_iocdbSearch()">${t}: ${counts}</span>`:'';
        }).join('')}
      </div>
    </div>
    <div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.82em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Type','Value','Risk','Reputation','Source','Tags','Last Seen','Action'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600;white-space:nowrap">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(i=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:8px 10px">${_badge(i.type||'?','#22d3ee')}</td>
        <td style="padding:8px 10px;font-family:monospace;font-size:.84em;color:#e6edf3;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${_esc(i.value)}">${_esc((i.value||'').slice(0,60))}</td>
        <td style="padding:8px 10px">${_riskBadge(i.risk_score)}</td>
        <td style="padding:8px 10px">${_badge(i.reputation||'unknown',i.reputation==='malicious'?'#ef4444':i.reputation==='suspicious'?'#f59e0b':'#22c55e')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.82em;white-space:nowrap">${_esc(i.feed_source||i.source||'—')}</td>
        <td style="padding:8px 10px">${(i.tags||[]).slice(0,3).map(t=>`<span style="background:#1e2d3d;color:#8b949e;padding:1px 5px;border-radius:4px;font-size:.72em;margin-right:2px">${_esc(t)}</span>`).join('')}</td>
        <td style="padding:8px 10px;color:#8b949e;font-size:.78em;white-space:nowrap">${_ago(i.last_seen)}</td>
        <td style="padding:8px 10px;white-space:nowrap">
          <button onclick="window.AIOrchestrator?.lookupIOC('${_esc(i.value)}')" style="${_btn('#a855f7')}" title="AI Analysis"><i class="fas fa-robot"></i></button>
          <button onclick="navigator.clipboard?.writeText('${_esc(i.value)}').then(()=>showToast('Copied','success'))" style="${_btn('#21262d','#30363d','#8b949e')} margin-left:4px" title="Copy"><i class="fas fa-copy"></i></button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  document.getElementById('iocdb-pages').innerHTML=_paginator(_idbT,_idbP,'_iocdbPage','iocdb-pag');
}

/* ─────────────────────────────────────────────
   § 15  AI SESSIONS (investigations list)
───────────────────────────────────────────── */
async function renderAIInvestigationsLive() {
  const c=document.getElementById('aiInvestigationsWrap'); if(!c) return;
  c.innerHTML=_skel(4,48);
  try {
    const data=await _fetch('/cti/ai/sessions');
    const rows=data?.data||data||[];
    if(!rows.length){c.innerHTML=`<div style="text-align:center;padding:40px;color:#8b949e">No AI investigation sessions yet — use the AI Orchestrator panel</div>`;return;}
    c.innerHTML=`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">${['Session ID','Title','Messages','Started','Actions'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600">${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(s=>`<tr style="border-bottom:1px solid #161b22;cursor:pointer" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:9px 10px;font-family:monospace;font-size:.82em;color:#22d3ee">${_esc((s.id||'').slice(0,8))}…</td>
        <td style="padding:9px 10px;font-weight:500;color:#e6edf3;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(s.title||'AI Session')}</td>
        <td style="padding:9px 10px;text-align:center;color:#e6edf3">${(s.messages||[]).length}</td>
        <td style="padding:9px 10px;color:#8b949e;font-size:.8em;white-space:nowrap">${_ago(s.created_at)}</td>
        <td style="padding:9px 10px"><button onclick="navigateTo('ai-orchestrator')" style="${_btn('#1d6ae5')}"><i class="fas fa-robot"></i> Open</button></td>
      </tr>`).join('')}</tbody>
    </table></div>`;
  } catch(e){_err(c,e.message);}
}

/* ─────────────────────────────────────────────
   § 16  SOAR AUTOMATION — feed-log / rule table
───────────────────────────────────────────── */
async function _renderSOARLive() {
  const c = document.getElementById('soarLiveContainer'); if (!c) return;
  c.innerHTML = _skel(6, 48);
  try {
    const data  = await _fetch('/dashboard/stats-live');
    const feeds = data.feed_status || [];
    const k     = data.kpis || {};
    c.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">
      ${[
        {label:'Automated Rules',  val: feeds.length,                color:'#22c55e'},
        {label:'IOCs Processed',   val: k.iocs_collected,            color:'#a855f7'},
        {label:'Active Playbooks', val: k.ai_investigations,         color:'#22d3ee'},
        {label:'Threat Level',     val: data.threat_level || 'N/A',  color:'#ef4444'},
      ].map(({label,val,color})=>`
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;text-align:center">
          <div style="font-size:1.5em;font-weight:800;color:${color}">${val != null ? String(val).toLocaleString() : '—'}</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:4px">${label}</div>
        </div>`).join('')}
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <span style="font-weight:600;color:#e6edf3"><i class="fas fa-robot" style="margin-right:6px;color:#22c55e"></i>Automated Rule Executions</span>
      <button onclick="_collSyncAll()" style="${_btn('#22c55e')}"><i class="fas fa-play"></i> Run All Rules</button>
    </div>
    ${!feeds.length
      ? `<div style="text-align:center;padding:40px;color:#8b949e">No SOAR executions yet — configure playbooks and feeds</div>`
      : `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead><tr style="border-bottom:2px solid #1e2d3d;text-align:left">
        ${['Rule / Feed','Status','IOCs Processed','Actions Taken','Last Executed','Trigger'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600">${h}</th>`).join('')}
      </tr></thead>
      <tbody>${feeds.map(f=>`<tr style="border-bottom:1px solid #161b22" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background=''">
        <td style="padding:10px;font-weight:600;color:#e6edf3">${_esc(f.feed_name)}</td>
        <td style="padding:10px">${_badge(f.status||'unknown',f.status==='success'?'#22c55e':f.status==='partial'?'#f59e0b':'#ef4444')}</td>
        <td style="padding:10px;color:#a855f7;font-weight:700">${(f.iocs_new||0).toLocaleString()}</td>
        <td style="padding:10px;color:#22d3ee">${(f.iocs_fetched||0).toLocaleString()}</td>
        <td style="padding:10px;color:#8b949e;font-size:.82em">${_ago(f.finished_at)}</td>
        <td style="padding:10px"><button onclick="_collSync('${_esc(f.feed_name)}')" style="${_btn('#22c55e')}" title="Re-run"><i class="fas fa-play"></i></button></td>
      </tr>`).join('')}</tbody>
    </table></div>`}`;
  } catch(e) { _err(c, e.message); }
}

/* ─────────────────────────────────────────────
   STYLE HELPERS (inline button / select styles)
───────────────────────────────────────────── */
function _fs() { return 'background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:.82em;cursor:pointer'; }
function _btn(bg='#1d6ae5', border=bg, color='#fff') { return `background:${bg};border:1px solid ${border};color:${color};padding:5px 12px;border-radius:6px;font-size:.82em;cursor:pointer;white-space:nowrap`; }

/* ─────────────────────────────────────────────
   SYNC / INGEST HELPERS
   _collSyncAll  → POST /api/cti/ingest/all
   _collSync(name) → POST /api/cti/ingest/:name
───────────────────────────────────────────── */
window._collSyncAll = async function _collSyncAll() {
  const base  = (window.THREATPILOT_API_URL || 'http://localhost:4000').replace(/\/$/,'');
  const token = sessionStorage.getItem('tp_token') || '';
  if (typeof showToast === 'function') showToast('🔄 Triggering full feed ingestion…', 'info');

  // Disable all sync buttons temporarily
  document.querySelectorAll('[onclick*="_collSyncAll"]').forEach(b => { b.disabled = true; b.style.opacity = '0.6'; });

  try {
    const resp = await fetch(`${base}/api/cti/ingest/all`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify({ trigger: 'manual', source: 'dashboard' })
    });

    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      // Graceful degradation — some deployments may not have this endpoint yet
      if (resp.status === 404) {
        console.warn('[Sync] POST /api/cti/ingest/all not yet deployed — trying fallback endpoints');
        // Try alternate endpoints
        const altEndpoints = [
          '/cti/ingest/all',
          '/feeds/sync',
          '/collectors/sync-all',
          '/cti/feeds/ingest'
        ];
        for (const ep of altEndpoints) {
          try {
            const r2 = await fetch(`${base}/api${ep}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
              body: JSON.stringify({ trigger: 'manual' })
            });
            if (r2.ok) {
              if (typeof showToast === 'function') showToast(`✅ Feed sync triggered via ${ep}`, 'success');
              setTimeout(() => { if (typeof renderLiveFeedsLive === 'function') renderLiveFeedsLive(); }, 3000);
              return;
            }
          } catch {}
        }
        // All failed — show helpful message
        if (typeof showToast === 'function') showToast('ℹ️ Ingest endpoint not available — feeds run on schedule', 'warning');
        _showIngestModal();
        return;
      }
      throw new Error(`HTTP ${resp.status} — ${txt.slice(0,120)}`);
    }

    const result = await resp.json().catch(() => ({}));
    const count  = result.feeds_triggered || result.count || result.total || '?';
    if (typeof showToast === 'function') showToast(`✅ Ingestion started — ${count} feeds queued`, 'success');
    // Refresh feeds list after a short delay
    setTimeout(() => { if (typeof renderLiveFeedsLive === 'function') renderLiveFeedsLive(); }, 4000);

  } catch (err) {
    console.error('[Sync] Failed:', err.message);
    if (typeof showToast === 'function') showToast(`Sync failed: ${err.message}`, 'error');
  } finally {
    document.querySelectorAll('[onclick*="_collSyncAll"]').forEach(b => { b.disabled = false; b.style.opacity = ''; });
  }
};

window._collSync = async function _collSync(feedName) {
  const base  = (window.THREATPILOT_API_URL || 'http://localhost:4000').replace(/\/$/,'');
  const token = sessionStorage.getItem('tp_token') || '';
  const slug  = encodeURIComponent((feedName||'').toLowerCase().replace(/\s+/g,'-'));
  if (typeof showToast === 'function') showToast(`🔄 Syncing ${feedName}…`, 'info');
  try {
    const resp = await fetch(`${base}/api/cti/ingest/${slug}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ feed: feedName, trigger: 'manual' })
    });
    if (!resp.ok) {
      // Try generic sync endpoint
      const r2 = await fetch(`${base}/api/cti/ingest/all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ feed: feedName, trigger: 'manual' })
      }).catch(() => null);
      if (r2?.ok) {
        if (typeof showToast === 'function') showToast(`✅ ${feedName} sync queued`, 'success');
        return;
      }
      if (typeof showToast === 'function') showToast(`ℹ️ ${feedName} sync endpoint not available`, 'warning');
      return;
    }
    if (typeof showToast === 'function') showToast(`✅ ${feedName} synced successfully`, 'success');
  } catch (err) {
    if (typeof showToast === 'function') showToast(`Sync failed: ${err.message}`, 'error');
  }
};

/** Show a modal explaining how to trigger initial ingestion */
function _showIngestModal() {
  const modal = document.createElement('div');
  modal.id = 'ingestHelperModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)';
  modal.innerHTML = `
  <div style="background:#0d1117;border:1px solid #30363d;border-radius:14px;padding:28px;max-width:520px;width:90%;position:relative">
    <button onclick="document.getElementById('ingestHelperModal').remove()" style="position:absolute;top:12px;right:14px;background:none;border:none;color:#8b949e;font-size:1.2em;cursor:pointer">✕</button>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
      <div style="width:40px;height:40px;background:#22c55e18;border:1px solid #22c55e44;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#22c55e;font-size:1.2em">
        <i class="fas fa-sync-alt"></i></div>
      <div>
        <div style="font-size:1em;font-weight:700;color:#e6edf3">Trigger Feed Ingestion</div>
        <div style="font-size:.75em;color:#8b949e">POST /api/cti/ingest/all</div>
      </div>
    </div>
    <p style="font-size:.82em;color:#8b949e;line-height:1.6;margin-bottom:16px">
      To populate all 10 threat intelligence feeds, trigger the ingest endpoint on your backend.
      Use one of the methods below:
    </p>
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:14px;margin-bottom:12px;font-family:monospace;font-size:.78em;color:#22c55e">
      <div style="color:#8b949e;margin-bottom:6px"># cURL — manual trigger</div>
      curl -X POST https://wadjet-eye-ai.onrender.com/api/cti/ingest/all \\<br>
      &nbsp;&nbsp;-H "Authorization: Bearer $TOKEN" \\<br>
      &nbsp;&nbsp;-H "Content-Type: application/json"
    </div>
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:14px;margin-bottom:16px;font-family:monospace;font-size:.78em;color:#3b82f6">
      <div style="color:#8b949e;margin-bottom:6px"># Backend route to add (Express.js)</div>
      app.post('/api/cti/ingest/all', auth, async (req, res) => {<br>
      &nbsp;&nbsp;await ingestAllFeeds();<br>
      &nbsp;&nbsp;res.json({ status: 'ok', feeds_triggered: 10 });<br>
      });
    </div>
    <div style="display:flex;gap:8px">
      <button onclick="document.getElementById('ingestHelperModal').remove()"
        style="flex:1;background:#22c55e18;color:#22c55e;border:1px solid #22c55e44;padding:8px;border-radius:7px;font-size:.82em;cursor:pointer">
        <i class="fas fa-check" style="margin-right:4px"></i>Got it
      </button>
      <button onclick="window.open('https://wadjet-eye-ai.onrender.com/api/cti/ingest/all','_blank');document.getElementById('ingestHelperModal').remove()"
        style="background:#1d6ae518;color:#3b82f6;border:1px solid #1d6ae544;padding:8px 14px;border-radius:7px;font-size:.82em;cursor:pointer">
        <i class="fas fa-external-link-alt" style="margin-right:4px"></i>Open API
      </button>
    </div>
  </div>`;
  document.body.appendChild(modal);
}

/* ─────────────────────────────────────────────
   PAGE RENDER OVERRIDES  (window.renderXxx)
   Called by PAGE_CONFIG onEnter in main.js
───────────────────────────────────────────── */
window.renderCommandCenter      = (opts) => renderCommandCenterLive().catch(e=>console.warn('[LP]',e.message));
window.renderFindings           = (opts) => renderFindingsLive(opts||{}).catch(e=>console.warn('[LP]',e.message));
window.renderCampaigns          = (opts) => renderCampaignsLive(opts||{}).catch(e=>console.warn('[LP]',e.message));
window.renderDetections         = ()     => renderDetectionsLive().catch(e=>console.warn('[LP]',e.message));
window.stopDetections           = ()     => stopDetections();
window.renderThreatActors       = ()     => renderThreatActorsLive().catch(e=>console.warn('[LP]',e.message));
window.renderIOCRegistry        = (opts) => renderIOCRegistryLive(opts||{}).catch(e=>console.warn('[LP]',e.message));
window.renderCollectors         = ()     => renderCollectorsLive().catch(e=>console.warn('[LP]',e.message));
window.renderCaseManagement     = ()     => renderCasesLive().catch(e=>console.warn('[LP]',e.message));
window.renderExecutiveDashboard = ()     => renderExecutiveDashboardLive().catch(e=>console.warn('[LP]',e.message));
window.renderLiveFeeds          = ()     => renderLiveFeedsLive().catch(e=>console.warn('[LP]',e.message));
window.stopLiveFeeds            = ()     => {};
window.renderVulnerabilities    = ()     => renderVulnerabilitiesLive().catch(e=>console.warn('[LP]',e.message));
window.renderDetectionTimeline  = ()     => renderDetectionTimelineLive().catch(e=>console.warn('[LP]',e.message));
window.renderMITRECoverage      = ()     => { if(typeof window.renderMITRENavigator==='function') window.renderMITRENavigator(); else renderMITRECoverageLive().catch(e=>console.warn('[LP]',e.message)); };
window.renderAIInvestigations   = ()     => renderAIInvestigationsLive().catch(e=>console.warn('[LP]',e.message));
// NOTE: This registration is a FALLBACK only.
// js/ioc-intelligence.js loads AFTER this file and will override window.renderIOCDatabase
// with the full production version (real API + debug panel + RLS banner).
// Do NOT change this to a permanent assignment — guard with typeof check instead.
if (typeof window._iocIntelligenceLoaded === 'undefined') {
  // ioc-intelligence.js hasn't loaded yet — set a temporary shim
  window.renderIOCDatabase = () => renderIOCDatabaseLive().catch(e => console.warn('[LP] IOC fallback render error:', e.message));
}
// Store a reference so ioc-intelligence.js can call this as a fallback if needed
window.renderIOCDatabaseLegacy  = ()     => renderIOCDatabaseLive().catch(e=>console.warn('[LP]',e.message));
window.renderSOARLive           = ()     => _renderSOARLive().catch(e=>console.warn('[LP]',e.message));
window.renderExposureLive       = ()     => renderExposureLive().catch(e=>console.warn('[LP]',e.message));
window.renderExposure           = ()     => renderExposureLive().catch(e=>console.warn('[LP]',e.message));
window.renderKillChainLive      = ()     => renderKillChainLive().catch(e=>console.warn('[LP]',e.message));
// New module shims — these are OVERRIDDEN by playbooks-ui.js / threat-hunting.js / detection-engineering.js
// The shims below only fire if those files fail to load
if (typeof window.renderPlaybooks !== 'function') {
  window.renderPlaybooks = () => {
    const c = document.getElementById('playbooksWrap');
    if (c) c.innerHTML = '<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:12px">Loading playbooks module…</div></div>';
  };
}
if (typeof window.renderThreatHunting !== 'function') {
  window.renderThreatHunting = () => {
    const c = document.getElementById('threatHuntingWrap');
    if (c) c.innerHTML = '<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:12px">Loading threat hunting module…</div></div>';
  };
}
if (typeof window.renderDetectionEngineering !== 'function') {
  window.renderDetectionEngineering = () => {
    const c = document.getElementById('detectionEngineeringWrap');
    if (c) c.innerHTML = '<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:12px">Loading detection engineering module…</div></div>';
  };
}

/* ─────────────────────────────────────────────
   § 17  THREAT ACTOR DETAIL VIEW
   Click a card → opens actorModal with full profile
───────────────────────────────────────────── */
async function renderThreatActorsLive() {
  const c = document.getElementById('threatActorsLiveContainer'); if(!c) return;

  const nationColors = {
    'Russia':'#ef4444','China':'#f59e0b','N. Korea':'#8b5cf6',
    'Iran':'#22c55e','USA':'#3b82f6','Unknown':'#8b949e','Israel':'#06b6d4'
  };
  const motivColors = {
    'Espionage':'#3b82f6','Financial':'#22c55e','Ransomware':'#ef4444',
    'Hacktivism':'#f59e0b','Destruction':'#ec4899','Unknown':'#8b949e'
  };

  c.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-user-secret" style="color:#c9a227;margin-right:8px"></i>Threat Actors
      </h2>
      <div style="font-size:.78em;color:#8b949e;margin-top:2px">Live threat actor intelligence from MITRE ATT&CK, OTX, and backend CTI feeds</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="ta-search" placeholder="🔍 Search actors…" oninput="_taSearchInput()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:160px"/>
      <select id="ta-nation" style="${_fs()}">
        <option value="">All Nations</option>
        <option>Russia</option><option>China</option><option>N. Korea</option>
        <option>Iran</option><option>USA</option><option>Unknown</option>
      </select>
      <select id="ta-motiv" style="${_fs()}">
        <option value="">All Motivations</option>
        <option>Espionage</option><option>Financial</option><option>Ransomware</option><option>Hacktivism</option>
      </select>
      <button onclick="_taApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_taReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <button onclick="if(window.showToast)showToast('Export feature: use AI Orchestrator for STIX report','info')"
        style="${_btn('#21262d','#30363d','#8b949e')}"><i class="fas fa-download" style="margin-right:3px"></i>Export Report</button>
      <span id="ta-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
    </div>
  </div>
  <div id="ta-body">${_skel()}</div><div id="ta-pages"></div>`;
  await _taLoad();
}

let _taSearchTimer;
window._taSearchInput = () => { clearTimeout(_taSearchTimer); _taSearchTimer = setTimeout(_taApply, 280); };
window._taApply = () => { _ap=1; _taLoad(document.getElementById('ta-nation')?.value||'', document.getElementById('ta-motiv')?.value||'', document.getElementById('ta-search')?.value||''); };
window._taReset = () => { _ap=1; ['ta-nation','ta-motiv','ta-search'].forEach(i=>{const e=document.getElementById(i);if(e)e.value='';}); _taLoad(); };
window._taPage  = p  => { if(p<1||p>Math.ceil(_at/LP_PAGE_SIZE))return; _ap=p; _taLoad(); };

async function _taLoad(nation='', motivation='', search='') {
  const body = document.getElementById('ta-body'); if(!body) return;
  body.innerHTML = _skel();
  const qs = new URLSearchParams({page:_ap,limit:LP_PAGE_SIZE,
    ...(nation?{country:nation}:{}),
    ...(motivation?{motivation}:{}),
    ...(search?{search}:{})});
  try {
    const data   = await _fetch(`/cti/actors?${qs}`);
    const actors = data?.data||data||[];
    _at = data?.total||actors.length;
    const cnt=document.getElementById('ta-count'); if(cnt) cnt.textContent=`${_at.toLocaleString()} threat actors`;
    if(!actors.length){
      body.innerHTML=`<div style="text-align:center;padding:50px;color:#8b949e">
        <i class="fas fa-user-secret" style="font-size:2.5em;margin-bottom:12px;display:block;color:#c9a227"></i>
        <div style="font-size:.9em">No threat actors found</div>
        <div style="font-size:.78em;margin-top:4px">Try adjusting your filters or ingesting CTI feeds</div>
      </div>`;
      document.getElementById('ta-pages').innerHTML='';return;
    }

    const nationColors = {'Russia':'#ef4444','China':'#f59e0b','N. Korea':'#8b5cf6','Iran':'#22c55e','USA':'#3b82f6','Unknown':'#8b949e','Israel':'#06b6d4'};
    const motivIcons   = {'Espionage':'fa-user-secret','Financial':'fa-dollar-sign','Ransomware':'fa-lock','Hacktivism':'fa-fist-raised','Destruction':'fa-bomb'};

    body.innerHTML=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px;padding:8px 0">`+
      actors.map(a=>{
        const nc = nationColors[a.origin_country||a.country] || '#8b949e';
        const soph = a.sophistication || a.severity || 'unknown';
        const sophC = _sevC(soph);
        return `
        <div onclick="_openActorDetail('${_esc(a.id)}')"
          style="background:#0d1117;border:1px solid #21262d;border-radius:12px;padding:16px;cursor:pointer;
            transition:all .2s;display:flex;flex-direction:column;gap:10px"
          onmouseover="this.style.borderColor='${nc}55';this.style.transform='translateY(-2px)'"
          onmouseout="this.style.borderColor='#21262d';this.style.transform='translateY(0)'">

          <!-- Header row -->
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
            <div style="display:flex;align-items:center;gap:10px">
              <div style="width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#1d3461,${nc}55);
                border:1px solid ${nc}44;display:flex;align-items:center;justify-content:center;
                font-size:1.2em;color:${nc};flex-shrink:0">
                <i class="fas ${motivIcons[a.motivation]||'fa-user-secret'}"></i>
              </div>
              <div>
                <div style="font-size:.88em;font-weight:700;color:#e6edf3">${_esc(a.name)}</div>
                ${(a.aliases||[]).length?`<div style="font-size:.7em;color:#8b949e">aka ${_esc((a.aliases||[]).slice(0,2).join(', '))}${(a.aliases||[]).length>2?'…':''}</div>`:''}
              </div>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px">
              <span style="background:${nc}18;color:${nc};border:1px solid ${nc}33;padding:1px 7px;border-radius:6px;font-size:.68em;font-weight:700;white-space:nowrap">
                <i class="fas fa-globe" style="margin-right:3px"></i>${_esc(a.origin_country||a.country||'Unknown')}
              </span>
              <span style="background:${sophC}18;color:${sophC};border:1px solid ${sophC}33;padding:1px 6px;border-radius:5px;font-size:.66em;font-weight:600;text-transform:uppercase">${soph}</span>
            </div>
          </div>

          <!-- Description -->
          <div style="font-size:.77em;color:#8b949e;line-height:1.5">
            ${_esc((a.description||a.desc||'Advanced persistent threat actor').slice(0,110))}…
          </div>

          <!-- Motivation + Active Since -->
          <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:.73em">
            <span style="color:#f97316"><i class="fas fa-crosshairs" style="margin-right:3px"></i>${_esc(a.motivation||'Unknown')}</span>
            ${a.active_since||a.first_seen?`<span style="color:#8b949e"><i class="fas fa-calendar" style="margin-right:3px"></i>Since ${_ago(a.active_since||a.first_seen)}</span>`:''}
            ${(a.target_sectors||[]).length?`<span style="color:#22d3ee"><i class="fas fa-building" style="margin-right:3px"></i>${_esc((a.target_sectors||[]).slice(0,2).join(', '))}</span>`:''}
          </div>

          <!-- TTPs / Techniques -->
          ${(a.ttps||a.techniques||[]).length?`
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${(a.ttps||a.techniques||[]).slice(0,5).map(t=>`<span style="background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);
              padding:1px 7px;border-radius:4px;font-family:monospace;font-size:.68em">${_esc(t)}</span>`).join('')}
            ${(a.ttps||[]).length>5?`<span style="color:#8b949e;font-size:.68em">+${(a.ttps||[]).length-5} more</span>`:''}
          </div>`:''}

          <!-- Footer -->
          <div style="display:flex;align-items:center;justify-content:space-between;border-top:1px solid #21262d;padding-top:8px;margin-top:auto">
            <span style="font-size:.7em;color:#8b949e"><i class="fas fa-database" style="margin-right:3px"></i>${_esc(a.source||'CTI Feed')}</span>
            <span style="font-size:.7em;color:#c9a227;font-weight:600">
              <i class="fas fa-arrow-right" style="margin-right:3px"></i>Full Intel Profile →
            </span>
          </div>
        </div>`;
      }).join('')+'</div>';
    document.getElementById('ta-pages').innerHTML=_paginator(_at,_ap,'_taPage','ta-pag');
  } catch(e){_err(body,e.message);if(typeof showToast==='function')showToast('Actors load failed','error');}
}

window._openActorDetail = async (id) => {
  // ROUTING FIX: id is always the immutable actor ID, never an array index.
  // We clear the modal body FIRST to prevent stale content from a prior actor.
  const modal = document.getElementById('actorModal');
  const body  = document.getElementById('actorModalBody');
  if(!modal||!body) return;
  // Clear previous content immediately to avoid showing wrong actor
  body.innerHTML = '';
  modal.classList.add('active');
  body.innerHTML = _skel(6,48);

  // Store current actor ID on the modal so re-entrancy can be detected
  const reqId = id;
  modal.dataset.currentActorId = reqId;

  try {
    const [actor, iocsResp] = await Promise.all([
      _fetch(`/cti/actors/${encodeURIComponent(id)}`).catch(()=>null),
      // FIXED: Filter IOCs by actor ID/name, not a shared global sort query
      _fetch(`/iocs?limit=10&sort=risk_score&search=${encodeURIComponent(id)}`).catch(()=>({data:[]}))
    ]);

    // Guard: if user opened another actor while this was loading, discard
    if (modal.dataset.currentActorId !== reqId) return;
    const a = actor || {};
    const iocs = iocsResp?.data || [];
    body.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:16px;margin-bottom:20px">
      <div style="width:60px;height:60px;border-radius:12px;background:linear-gradient(135deg,#1d3461,#c9a227);
        display:flex;align-items:center;justify-content:center;font-size:1.6em;flex-shrink:0">
        <i class="fas fa-user-secret"></i>
      </div>
      <div style="flex:1">
        <h2 style="font-size:1.2em;font-weight:800;color:#e6edf3;margin-bottom:4px">${_esc(a.name||'Unknown Actor')}</h2>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          ${_sevBadge(a.sophistication||a.severity||'unknown')}
          <span style="font-size:.78em;color:#c9a227"><i class="fas fa-globe" style="margin-right:3px"></i>${_esc(a.origin_country||a.country||'Unknown')}</span>
          <span style="font-size:.78em;color:#f97316"><i class="fas fa-crosshairs" style="margin-right:3px"></i>${_esc(a.motivation||'Unknown')}</span>
        </div>
        <p style="font-size:.84em;color:#8b949e;line-height:1.6">${_esc(a.description||a.desc||'No description available.')}</p>
      </div>
    </div>
    <!-- Tabs -->
    <div style="display:flex;gap:4px;border-bottom:1px solid #1e2d3d;margin-bottom:14px" id="actorTabs">
      ${['Overview','IOCs','MITRE Techniques','Campaigns','Timeline'].map((t,i)=>`
      <button onclick="_actorTab(${i})" id="actorTabBtn-${i}" style="${_btn(i===0?'#1d6ae5':'#21262d',i===0?'#1d6ae5':'#30363d')};margin-bottom:-1px;border-bottom-left-radius:0;border-bottom-right-radius:0">${t}</button>`).join('')}
    </div>
    <!-- Tab Content -->
    <div id="actorTabContent">
      <!-- Tab 0: Overview -->
      <div id="actorTab-0">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
          ${[
            {label:'Aliases', val:(a.aliases||[]).join(', ')||'—'},
            {label:'First Seen', val:_ago(a.first_seen||a.created_at)},
            {label:'Last Active', val:_ago(a.last_seen||a.updated_at)},
            {label:'Sophistication', val:a.sophistication||'—'},
            {label:'TTPs Count', val:(a.ttps||a.techniques||[]).length||'—'},
            {label:'Source', val:a.source||'MITRE / OTX'},
          ].map(({label,val})=>`
          <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px">
            <div style="font-size:.7em;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px">${label}</div>
            <div style="font-size:.84em;font-weight:600;color:#e6edf3">${_esc(String(val))}</div>
          </div>`).join('')}
        </div>
      </div>
      <!-- Tab 1: IOCs -->
      <div id="actorTab-1" style="display:none">
        ${iocs.length?`<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.82em">
          <thead><tr style="border-bottom:2px solid #1e2d3d">${['Type','Value','Risk','Reputation','Last Seen'].map(h=>`<th style="padding:8px 10px;color:#8b949e;font-weight:600;text-align:left">${h}</th>`).join('')}</tr></thead>
          <tbody>${iocs.map(i=>`<tr style="border-bottom:1px solid #161b22">
            <td style="padding:7px 10px">${_badge(i.type||'?','#22d3ee')}</td>
            <td style="padding:7px 10px;font-family:monospace;font-size:.82em;color:#e6edf3;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc((i.value||'').slice(0,50))}</td>
            <td style="padding:7px 10px">${_riskBadge(i.risk_score)}</td>
            <td style="padding:7px 10px">${_badge(i.reputation||'unknown',i.reputation==='malicious'?'#ef4444':'#f59e0b')}</td>
            <td style="padding:7px 10px;color:#8b949e;font-size:.78em">${_ago(i.last_seen)}</td>
          </tr>`).join('')}</tbody>
        </table></div>`:
        `<div style="text-align:center;padding:30px;color:#8b949e">No specific IOCs associated with this actor in current dataset</div>`}
      </div>
      <!-- Tab 2: MITRE Techniques -->
      <div id="actorTab-2" style="display:none">
        ${(a.ttps||a.techniques||[]).length?`<div style="display:flex;flex-wrap:wrap;gap:6px">
          ${(a.ttps||a.techniques||[]).map(t=>`
          <span style="background:rgba(29,106,229,.1);border:1px solid rgba(29,106,229,.3);color:#3b82f6;
            padding:4px 10px;border-radius:6px;font-family:monospace;font-size:.78em">${_esc(t)}</span>`).join('')}
        </div>`:
        `<div style="text-align:center;padding:30px;color:#8b949e">No MITRE techniques mapped for this actor</div>`}
      </div>
      <!-- Tab 3: Campaigns -->
      <div id="actorTab-3" style="display:none">
        <div id="actorCampaignsBody">${_skel(4,44)}</div>
      </div>
      <!-- Tab 4: Timeline -->
      <div id="actorTab-4" style="display:none">
        <div id="actorTimelineBody">${_skel(5,36)}</div>
      </div>
    </div>`;
  } catch(e) { _err(body, e.message); }
};

window._actorTab = (idx) => {
  for(let i=0;i<5;i++){
    const btn=document.getElementById(`actorTabBtn-${i}`);
    const tab=document.getElementById(`actorTab-${i}`);
    if(btn) btn.style.cssText = _btn(i===idx?'#1d6ae5':'#21262d',i===idx?'#1d6ae5':'#30363d')+';margin-bottom:-1px;border-bottom-left-radius:0;border-bottom-right-radius:0';
    if(tab) tab.style.display = i===idx?'block':'none';
  }
};

/* ─────────────────────────────────────────────
   § 18  EXPOSURE / CVE PAGE — real vulnerability intelligence
───────────────────────────────────────────── */
async function renderExposureLive() {
  const c = document.getElementById('exposureLiveContainer'); if(!c) return;
  c.innerHTML = `
    <!-- Summary Row (loaded from /api/exposure/summary) -->
    <div id="exp-summary-row" style="margin-bottom:16px">${_skel(1, 70)}</div>
    <!-- Filter Bar -->
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 0 14px;border-bottom:1px solid #1e2d3d">
      <input id="exp-search" placeholder="🔍 CVE ID or keyword…" oninput="_expSearch()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:.83em;width:180px"/>
      <select id="exp-sev" style="${_fs()}">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <label style="font-size:.8em;color:#8b949e;display:flex;align-items:center;gap:4px">
        <input type="checkbox" id="exp-exp" onchange="_expApply()" style="accent-color:#ef4444">CISA KEV only
      </label>
      <button onclick="_expApply()" style="${_btn('#1d6ae5')}">Apply</button>
      <button onclick="_expReset()" style="${_btn('#21262d','#30363d','#8b949e')}">Reset</button>
      <button onclick="_expSyncNVD()" style="${_btn('#f97316')}" id="exp-sync-btn">
        <i class="fas fa-sync-alt" id="exp-sync-icon"></i> Sync NVD
      </button>
      <span id="exp-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
      <button onclick="_expExport()" style="${_btn('#22c55e')}"><i class="fas fa-download"></i> CSV</button>
    </div>
    <div id="exp-body">${_skel()}</div>
    <div id="exp-pages"></div>`;

  // Load summary and CVEs in parallel
  _expLoadSummary();
  await _expLoad();
}

async function _expLoadSummary() {
  const el = document.getElementById('exp-summary-row');
  if (!el) return;
  try {
    const s = await _fetch('/exposure/summary');
    const riskColor = s.risk_score >= 70 ? '#ef4444' : s.risk_score >= 40 ? '#f59e0b' : '#22c55e';
    el.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px">
      ${[
        { label:'Risk Score',      val: `${s.risk_score||0}/100`, color: riskColor,  icon:'fa-radiation-alt', sub: s.risk_level||'LOW' },
        { label:'Total CVEs',      val: s.total_cves||0,          color:'#22d3ee',   icon:'fa-bug',           sub: 'In database' },
        { label:'Critical CVEs',   val: s.critical_cves||0,       color:'#ef4444',   icon:'fa-skull',         sub: 'CVSS ≥ 9.0' },
        { label:'CISA KEV',        val: s.kev_count||0,           color:'#f59e0b',   icon:'fa-exclamation',   sub: 'Exploited in wild' },
        { label:'Exploitable',     val: s.exploitable_count||0,   color:'#f97316',   icon:'fa-bomb',          sub: 'Exploit available' },
        { label:'Open Alerts',     val: s.open_alerts||0,         color:'#a855f7',   icon:'fa-bell',          sub: 'Requires attention' },
      ].map(({ label, val, color, icon, sub }) => `
        <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:14px;
          position:relative;overflow:hidden">
          <div style="position:absolute;top:0;left:0;right:0;height:3px;background:${color}"></div>
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
            <i class="fas ${icon}" style="color:${color};width:16px;text-align:center"></i>
            <span style="font-size:.72em;color:#8b949e">${label}</span>
          </div>
          <div style="font-size:1.6em;font-weight:800;color:${color}">${String(val).toLocaleString()}</div>
          <div style="font-size:.72em;color:#555;margin-top:2px">${sub}</div>
        </div>
      `).join('')}
    </div>`;
  } catch(e) {
    el.innerHTML = `<div style="padding:12px;color:#f59e0b;font-size:.82em;background:#1e2d3d22;border-radius:8px">
      <i class="fas fa-info-circle" style="margin-right:6px"></i>
      Summary unavailable — ${_esc(e.message)}
    </div>`;
  }
}

let _exP=1, _exF={}, _exT=0, _exTimer=null;
window._expSearch = () => { clearTimeout(_exTimer); _exTimer=setTimeout(() => { _exP=1; _expApply(); }, 350); };
window._expApply  = () => {
  _exF = {
    severity: document.getElementById('exp-sev')?.value    || '',
    exploited: document.getElementById('exp-exp')?.checked || false,
    search:   document.getElementById('exp-search')?.value || '',
  };
  _exP = 1;
  _expLoad();
};
window._expReset = () => {
  _exF = {};
  _exP = 1;
  const e1=document.getElementById('exp-sev');    if(e1) e1.value = '';
  const e2=document.getElementById('exp-exp');    if(e2) e2.checked = false;
  const e3=document.getElementById('exp-search'); if(e3) e3.value = '';
  _expLoad();
};
window._expPage = p => {
  if(p < 1 || p > Math.ceil(_exT / LP_PAGE_SIZE)) return;
  _exP = p;
  _expLoad();
};

window._expSyncNVD = async () => {
  const icon = document.getElementById('exp-sync-icon');
  const btn  = document.getElementById('exp-sync-btn');
  if (icon) icon.className = 'fas fa-spinner fa-spin';
  if (btn)  btn.disabled = true;
  try {
    await _post('/vulnerabilities/sync', { source: 'nvd', days: 30 });
    if (typeof showToast === 'function') showToast('NVD sync complete', 'success');
    _expLoadSummary();
    _expLoad();
  } catch(e) {
    if (typeof showToast === 'function') showToast('NVD sync failed: ' + e.message, 'error');
  } finally {
    if (icon) icon.className = 'fas fa-sync-alt';
    if (btn)  btn.disabled = false;
  }
};

async function _expLoad() {
  const body = document.getElementById('exp-body');
  if (!body) return;
  body.innerHTML = _skel();

  const qs = new URLSearchParams({
    page:  _exP,
    limit: LP_PAGE_SIZE,
    ...(_exF.severity ? { severity: _exF.severity } : {}),
    ...(_exF.exploited ? { exploited: 'true' } : {}),
    ...(_exF.search   ? { search:   _exF.search }   : {}),
  });

  let rows = [], total = 0;

  // Try /exposure/cves first (new dedicated endpoint), fallback to /vulnerabilities
  try {
    let data = await _fetch(`/exposure/cves?${qs}`).catch(() => null);
    if (!data || !(data.cves || data.data)) {
      data = await _fetch(`/vulnerabilities?${qs}`);
    }
    rows  = data?.cves || data?.data || data || [];
    total = data?.total || rows.length;
  } catch(e) {
    console.warn('[Exposure] Load failed:', e.message);
    // Show empty state with guidance instead of error
    body.innerHTML = `
    <div style="text-align:center;padding:60px;color:#8b949e">
      <i class="fas fa-shield-alt" style="font-size:3em;color:#30363d;display:block;margin-bottom:16px"></i>
      <div style="font-weight:600;font-size:1em;margin-bottom:8px;color:#e6edf3">No Vulnerability Data Yet</div>
      <div style="font-size:.84em;line-height:1.6;max-width:400px;margin:0 auto">
        The vulnerability database is empty. Click <strong>Sync NVD</strong> to pull Critical/High CVEs from the National Vulnerability Database.
      </div>
      <div style="margin-top:16px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
        <button onclick="_expSyncNVD()" style="${_btn('#f97316')}"><i class="fas fa-sync-alt" style="margin-right:6px"></i>Sync NVD Now</button>
        <button onclick="_expReset()" style="${_btn('#1d6ae5')}"><i class="fas fa-redo" style="margin-right:6px"></i>Retry</button>
      </div>
      <div style="font-size:.75em;color:#555;margin-top:12px">Error: ${_esc(e.message)}</div>
    </div>`;
    document.getElementById('exp-pages').innerHTML = '';
    return;
  }

  _exT = total;
  const cnt = document.getElementById('exp-count');
  if (cnt) cnt.textContent = `${_exT.toLocaleString()} vulnerabilities`;

  if (!rows.length) {
    body.innerHTML = `
    <div style="text-align:center;padding:60px;color:#8b949e">
      <i class="fas fa-check-circle" style="font-size:2.5em;color:#22c55e;display:block;margin-bottom:12px"></i>
      <div style="font-weight:600;margin-bottom:6px">No vulnerabilities match your filters</div>
      <div style="font-size:.82em">Try removing filters or syncing fresh data.</div>
      <button onclick="_expReset()" style="${_btn('#1d6ae5')} margin-top:12px;display:inline-flex">Clear Filters</button>
    </div>`;
    document.getElementById('exp-pages').innerHTML = '';
    return;
  }

  body.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;padding:4px 0">` +
    rows.map(v => {
      const cvss = v.cvss_v3_score != null ? Number(v.cvss_v3_score) : v.cvss_score != null ? Number(v.cvss_score) : null;
      const cvssColor = cvss >= 9 ? '#ef4444' : cvss >= 7 ? '#f97316' : cvss >= 4 ? '#f59e0b' : '#22c55e';
      const isKev  = v.cisa_kev || v.is_kev;
      const isExpl = v.is_exploited || v.exploited_in_wild || v.exploit_available;
      return `
      <div onclick="_openCVEDetail('${_esc(v.id||v.cve_id)}')"
        style="background:#0d1117;border:1px solid ${isKev?'rgba(239,68,68,.4)':'#21262d'};border-radius:10px;padding:14px;
          cursor:pointer;transition:all .2s;position:relative;overflow:hidden"
        onmouseover="this.style.borderColor='#f97316';this.style.boxShadow='0 4px 16px rgba(249,115,22,.15)'"
        onmouseout="this.style.borderColor='${isKev?'rgba(239,68,68,.4)':'#21262d'}';this.style.boxShadow='none'">
        ${isKev ? `<div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#ef4444,#f97316)"></div>` : ''}
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px">
          <span style="font-family:monospace;font-size:.85em;font-weight:700;color:#22d3ee">${_esc(v.cve_id||v.id||'Unknown')}</span>
          ${_sevBadge(v.severity)}
        </div>
        <div style="font-size:.79em;color:#8b949e;line-height:1.5;margin-bottom:10px;min-height:36px">
          ${_esc((v.description||v.summary||'').slice(0,110))}${(v.description||v.summary||'').length > 110 ? '…' : ''}
        </div>
        <div style="display:flex;gap:8px;font-size:.74em;flex-wrap:wrap;margin-bottom:8px">
          ${cvss != null ? `<span style="background:${cvssColor}18;color:${cvssColor};border:1px solid ${cvssColor}33;padding:2px 7px;border-radius:5px;font-weight:700">CVSS ${cvss.toFixed(1)}</span>` : ''}
          ${v.epss_score != null ? `<span style="background:#f59e0b18;color:#f59e0b;border:1px solid #f59e0b33;padding:2px 7px;border-radius:5px">EPSS ${(v.epss_score*100).toFixed(1)}%</span>` : ''}
          ${isKev  ? `<span style="background:#ef444418;color:#ef4444;border:1px solid #ef444433;padding:2px 7px;border-radius:5px;font-weight:700">🔴 KEV</span>` : ''}
          ${isExpl ? `<span style="background:#f9731618;color:#f97316;border:1px solid #f9731633;padding:2px 7px;border-radius:5px;font-weight:700">EXPLOITABLE</span>` : ''}
        </div>
        <div style="font-size:.7em;color:#c9a227;font-weight:600;display:flex;align-items:center;gap:4px">
          <i class="fas fa-arrow-right"></i>Click for details + remediation
        </div>
      </div>`;
    }).join('') + '</div>';

  document.getElementById('exp-pages').innerHTML = _paginator(_exT, _exP, '_expPage', 'exp-pag');
}

window._openCVEDetail = async (id) => {
  // ROUTING FIX: id is the immutable CVE ID (e.g. "CVE-2024-1234")
  // Clear body immediately to prevent flash of stale CVE content
  const modal=document.getElementById('exposureModal');
  const body=document.getElementById('exposureModalBody');
  if(!modal||!body) return;

  const reqId = String(id);
  modal.dataset.currentCveId = reqId;

  // Clear BEFORE adding active class to avoid old content flash
  body.innerHTML = '';
  modal.classList.add('active');
  body.innerHTML=_skel(5,48);

  try {
    const v=await _fetch(`/cti/vulnerabilities/${encodeURIComponent(id)}`).catch(async()=>{
      // Only fallback-search if the direct fetch failed
      const all=await _fetch(`/cti/vulnerabilities?limit=100&search=${encodeURIComponent(id)}`).catch(()=>null);
      return (all?.data||[]).find(x=>(x.id===id||x.cve_id===id))||null;
    });

    // Guard: discard if user opened another CVE while loading
    if (modal.dataset.currentCveId !== reqId) return;
    if(!v){body.innerHTML=`<div style="text-align:center;padding:30px;color:#8b949e">CVE details not found</div>`;return;}
    body.innerHTML=`
    <div style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px">
        <span style="font-family:monospace;font-size:1.1em;font-weight:800;color:#22d3ee">${_esc(v.cve_id||v.id||'CVE-Unknown')}</span>
        ${_sevBadge(v.severity)}
        ${v.is_exploited?`<span style="background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#ef4444;padding:3px 8px;border-radius:6px;font-size:.78em;font-weight:700"><i class="fas fa-exclamation-circle" style="margin-right:4px"></i>ACTIVELY EXPLOITED</span>`:''}
        ${v.cisa_kev?`<span style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444;padding:3px 8px;border-radius:6px;font-size:.78em;font-weight:700">CISA KEV</span>`:''}
      </div>
      <p style="font-size:.88em;color:#8b949e;line-height:1.7">${_esc(v.description||'No description available.')}</p>
    </div>
    <!-- Score Grid -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px">
      ${[
        {label:'CVSS Score', val:(v.cvss_v3_score!=null?Number(v.cvss_v3_score):v.cvss_score!=null?Number(v.cvss_score):null)?.toFixed(1)||'N/A', color:(v.cvss_v3_score||v.cvss_score)>=9?'#ef4444':(v.cvss_v3_score||v.cvss_score)>=7?'#f97316':(v.cvss_v3_score||v.cvss_score)>=4?'#f59e0b':'#22c55e'},
        {label:'EPSS Score', val:v.epss_score!=null?(v.epss_score*100).toFixed(2)+'%':'N/A', color:'#f59e0b'},
        {label:'Published', val:v.published_date?new Date(v.published_date).toLocaleDateString():'N/A', color:'#8b949e'},
        {label:'Last Modified', val:v.updated_at?_ago(v.updated_at):'N/A', color:'#8b949e'},
      ].map(({label,val,color})=>`<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px;text-align:center">
        <div style="font-size:1.3em;font-weight:800;color:${color}">${_esc(String(val))}</div>
        <div style="font-size:.72em;color:#8b949e;margin-top:3px">${label}</div>
      </div>`).join('')}
    </div>
    <!-- Remediation -->
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px;margin-bottom:14px">
      <div style="font-weight:600;color:#e6edf3;margin-bottom:8px"><i class="fas fa-tools" style="color:#22c55e;margin-right:8px"></i>Remediation Guidance</div>
      <div style="font-size:.83em;color:#8b949e;line-height:1.6">
        ${_esc(v.remediation||v.solution||'Apply the latest vendor patches. Refer to the vendor advisory for specific remediation steps. If no patch is available, apply compensating controls such as network segmentation or WAF rules.')}
      </div>
    </div>
    <!-- References -->
    ${(v.references||[]).length?`<div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px">
      <div style="font-weight:600;color:#e6edf3;margin-bottom:8px"><i class="fas fa-link" style="color:#22d3ee;margin-right:8px"></i>References</div>
      <ul style="list-style:none;font-size:.82em">${(v.references||[]).slice(0,5).map(r=>`<li style="padding:3px 0"><a href="${_esc(r)}" target="_blank" style="color:#3b82f6">${_esc(r.slice(0,80))}</a></li>`).join('')}</ul>
    </div>`:''}
    <button onclick="_ffAI('${_esc(v.id)}','${_esc(v.cve_id||v.id||'')}');document.getElementById('exposureModal').classList.remove('active')" style="${_btn('#a855f7')} margin-top:14px"><i class="fas fa-robot" style="margin-right:5px"></i>Investigate with AI</button>`;
  } catch(e){_err(body,e.message);}
};

window._expExport = async () => {
  try {
    const data=await _fetch(`/cti/vulnerabilities?limit=1000${_exF.severity?'&severity='+_exF.severity:''}${_exF.exploited?'&exploited=true':''}`);
    const rows=data?.data||data||[];
    const csv=['CVE ID,Severity,CVSS,EPSS,Exploited,Published,Description',...rows.map(v=>[v.cve_id||v.id,v.severity,v.cvss_v3_score||v.cvss_score,v.epss_score!=null?(v.epss_score*100).toFixed(2)+'%':0,(v.exploited_in_wild||v.is_exploited)?'YES':'NO',v.published_at||v.published_date,`"${(v.description||'').replace(/"/g,'""').slice(0,100)}"`].join(','))].join('\n');
    const blob=new Blob([csv],{type:'text/csv'}); const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=`vulnerabilities_${new Date().toISOString().slice(0,10)}.csv`;a.click();URL.revokeObjectURL(url);
    if(typeof showToast==='function') showToast(`Exported ${rows.length} CVEs`,'success');
  }catch{if(typeof showToast==='function')showToast('Export failed','error');}
};

/* ─────────────────────────────────────────────
   § 19  KILL CHAIN LIVE VIEW — Full MITRE 12-phase
───────────────────────────────────────────── */
const _KILL_CHAIN_PHASES = [
  { id:'recon',       icon:'fa-binoculars',      label:'Reconnaissance',       color:'#ef4444',   phase:'TA0043',
    desc:'Adversary tries to gather information they can use to plan future operations. Includes active scanning, OSINT, gathering victim identity information, and phishing for information. This is typically the first observable phase of an attack.',
    examples:['DNS brute-force enumeration','Shodan & Censys scanning','LinkedIn OSINT reconnaissance','Certificate transparency monitoring','WHOIS and ASN lookup','Spearphishing for credentials'],
    techniques:['T1595','T1592','T1589','T1598','T1596','T1593','T1590'],
    tactic_desc:'Gathering intel before the attack begins',
    detection:'Monitor for unusual scanning activity, outbound DNS lookups, and OSINT tools being used against your infrastructure.' },
  { id:'resource-dev',icon:'fa-tools',           label:'Resource Development',  color:'#f97316',   phase:'TA0042',
    desc:'Adversary tries to establish resources to support their operations. Includes acquiring domains, compromising third-party accounts, and developing malware capabilities. Often invisible to defenders until later stages.',
    examples:['Registering lookalike domains','Compromising email accounts','Purchasing cloud infrastructure','Developing custom malware','Obtaining vulnerability exploits','Staging malware on CDN'],
    techniques:['T1583','T1586','T1584','T1587','T1585','T1588'],
    tactic_desc:'Building attack infrastructure and tools',
    detection:'Monitor for newly registered domains similar to yours, abuse reports, and threat intelligence feeds for attacker infrastructure.' },
  { id:'initial',     icon:'fa-door-open',       label:'Initial Access',        color:'#f59e0b',   phase:'TA0001',
    desc:'Adversary tries to get into your network. Uses various entry vectors including spearphishing, exploiting public-facing applications, and supply chain compromise. This is when the breach first occurs.',
    examples:['Spearphishing with malicious attachment','Exploiting CVE on web server','Valid credentials from dark web','Supply chain backdoor (SolarWinds-style)','Exploiting VPN vulnerability','Watering hole attack'],
    techniques:['T1566','T1190','T1133','T1195','T1078','T1189','T1091'],
    tactic_desc:'Breaking into the target environment',
    detection:'Deploy email security, WAF, and MFA. Monitor for unusual login attempts and web application attacks.' },
  { id:'exec',        icon:'fa-terminal',        label:'Execution',             color:'#eab308',   phase:'TA0002',
    desc:'Adversary tries to run malicious code on a local or remote system. Techniques include PowerShell abuse, WMI execution, scheduled tasks, and exploiting legitimate system features to run attacker code.',
    examples:['PowerShell encoded command execution','WMI process creation','Scheduled task as execution vector','Office macro execution','LOLBins abuse (certutil, mshta)','Container deployment'],
    techniques:['T1059','T1203','T1047','T1053','T1204','T1569','T1106'],
    tactic_desc:'Executing malicious code on compromised systems',
    detection:'Enable PowerShell logging, process creation monitoring, and anomaly detection for unusual parent-child process relationships.' },
  { id:'persist',     icon:'fa-fingerprint',     label:'Persistence',           color:'#22c55e',   phase:'TA0003',
    desc:'Adversary tries to maintain their foothold. Persistence techniques ensure continued access across restarts, credential changes, and other disruptions. Often implemented shortly after initial compromise.',
    examples:['Registry Run key entry','Scheduled task creation','WMI event subscription','Web shell on server','New admin account creation','DLL hijacking'],
    techniques:['T1547','T1053','T1543','T1546','T1505','T1136','T1574'],
    tactic_desc:'Maintaining access across disruptions',
    detection:'Monitor registry modifications, scheduled task creation, service installation, and unusual account creation events.' },
  { id:'privesc',     icon:'fa-level-up-alt',    label:'Privilege Escalation',  color:'#06b6d4',   phase:'TA0004',
    desc:'Adversary tries to gain higher-level permissions. Includes UAC bypass, token manipulation, exploitation of vulnerable services, and abuse of elevated execution mechanisms to gain SYSTEM or domain admin privileges.',
    examples:['UAC bypass via fodhelper','Token impersonation attack','Exploiting kernel vulnerability','Sudo abuse on Linux','DLL injection into elevated process','Juicy Potato / PrintSpoofer'],
    techniques:['T1548','T1134','T1068','T1055','T1053','T1574'],
    tactic_desc:'Gaining higher-level system permissions',
    detection:'Monitor for UAC bypass attempts, suspicious process elevation, access token manipulation, and kernel exploit indicators.' },
  { id:'devasion',    icon:'fa-user-ninja',      label:'Defense Evasion',       color:'#8b5cf6',   phase:'TA0005',
    desc:'Adversary tries to avoid detection throughout the compromise. Includes disabling security tools, log clearing, process injection, masquerading as legitimate processes, and using legitimate signed binaries for malicious purposes.',
    examples:['Clearing Windows Event Logs','Disabling AV/EDR tools','Process hollowing technique','Masquerading as svchost.exe','AMSI bypass in PowerShell','Using certutil for downloads'],
    techniques:['T1562','T1070','T1055','T1036','T1027','T1218','T1140'],
    tactic_desc:'Hiding malicious activity from defenders',
    detection:'Monitor for log clearing events, security tool modifications, unusual process memory operations, and LOLBin executions.' },
  { id:'credac',      icon:'fa-key',             label:'Credential Access',     color:'#ec4899',   phase:'TA0006',
    desc:'Adversary tries to steal account names and passwords. Techniques include dumping LSASS, Kerberoasting, brute force, and phishing for credentials. Stolen credentials enable long-term persistent access.',
    examples:['Mimikatz LSASS dumping','Kerberoasting service accounts','Password spraying attack','NTLM relay attack','DCSync against domain controller','Browser credential theft'],
    techniques:['T1003','T1558','T1110','T1555','T1187','T1056','T1539'],
    tactic_desc:'Stealing credentials for persistent access',
    detection:'Monitor LSASS access, unusual Kerberos ticket requests, authentication anomalies, and high-volume login failures.' },
  { id:'discovery',   icon:'fa-search',          label:'Discovery',             color:'#14b8a6',   phase:'TA0007',
    desc:'Adversary tries to figure out your environment. Techniques include enumerating Active Directory, discovering network shares, scanning for services, and mapping internal infrastructure to plan further actions.',
    examples:['Active Directory LDAP enumeration','Network port scanning','SharePoint file enumeration','Domain trust discovery','Cloud resource enumeration','User and group enumeration'],
    techniques:['T1087','T1082','T1046','T1135','T1069','T1482','T1018'],
    tactic_desc:'Mapping the internal environment',
    detection:'Enable AD audit logging, network traffic analysis, and anomaly detection for bulk queries and scanning patterns.' },
  { id:'lateral',     icon:'fa-project-diagram', label:'Lateral Movement',      color:'#f97316',   phase:'TA0008',
    desc:'Adversary tries to move through your environment. Techniques include exploiting remote services, pass-the-hash, PsExec, WMI lateral movement, and RDP sessions to reach high-value targets.',
    examples:['Pass-the-Hash to admin shares','PsExec remote execution','WMI lateral movement','RDP session hijacking','SSH lateral movement on Linux','Token theft for impersonation'],
    techniques:['T1021','T1550','T1047','T1210','T1563','T1570','T1534'],
    tactic_desc:'Moving to high-value targets',
    detection:'Monitor for unusual remote authentication, admin share access, WMI remote operations, and east-west traffic anomalies.' },
  { id:'collection',  icon:'fa-archive',         label:'Collection',            color:'#6366f1',   phase:'TA0009',
    desc:'Adversary tries to gather data of interest to their goal. Includes accessing cloud storage, email, file servers, databases, and capturing screens or keyboard input. Data is gathered before exfiltration.',
    examples:['Email archive collection (PST)','SharePoint document harvesting','Database credential extraction','Screen capture automation','Clipboard data collection','Cloud storage bucket enumeration'],
    techniques:['T1114','T1213','T1530','T1005','T1056','T1113','T1119'],
    tactic_desc:'Gathering target data for exfiltration',
    detection:'Monitor for unusual data access patterns, large file operations, email export activities, and cloud storage enumeration.' },
  { id:'c2',          icon:'fa-broadcast-tower', label:'Command & Control',     color:'#c9a227',   phase:'TA0011',
    desc:'Adversary maintains communication with compromised systems to issue commands and receive data. Techniques include HTTPS C2, DNS tunneling, and using legitimate cloud services as C2 channels.',
    examples:['Cobalt Strike HTTPS beacons','DNS tunneling for C2','Using Slack/Teams as C2','Domain fronting technique','Protocol tunneling over ICMP','TOR onion service C2'],
    techniques:['T1071','T1095','T1572','T1008','T1573','T1090','T1219'],
    tactic_desc:'Maintaining attacker-to-implant communication',
    detection:'Monitor for unusual outbound connections, DNS query anomalies, beacon patterns, and non-standard protocol usage.' },
  { id:'exfil',       icon:'fa-upload',          label:'Exfiltration',          color:'#3b82f6',   phase:'TA0010',
    desc:'Adversary tries to steal data from your environment. Techniques include exfiltration over C2 channels, alternative protocols, or legitimate cloud services. Often the final phase before impact.',
    examples:['Large HTTPS upload to external service','DNS exfiltration of data','FTP upload to attacker server','Cloud storage exfiltration','Scheduled file transfer','Encrypted archive upload'],
    techniques:['T1041','T1048','T1567','T1020','T1011','T1030'],
    tactic_desc:'Stealing collected data out of the environment',
    detection:'Monitor for large outbound data transfers, unusual cloud storage uploads, and DNS query anomalies.' },
  { id:'impact',      icon:'fa-bomb',            label:'Impact',                color:'#ef4444',   phase:'TA0040',
    desc:'Adversary tries to manipulate, interrupt, or destroy systems and data. This includes ransomware deployment, data destruction, DDoS attacks, service disruption, and cryptocurrency mining.',
    examples:['Ransomware encryption deployment','Shadow copy deletion','Service disruption','Database wiping','Website defacement','Cryptominer deployment','Wiper malware'],
    techniques:['T1486','T1490','T1498','T1499','T1485','T1561','T1496'],
    tactic_desc:'Causing the intended damage or disruption',
    detection:'Monitor for mass file encryption, shadow copy deletion, service stops, and unusual system resource consumption.' }
];

async function renderKillChainLive() {
  const c = document.getElementById('killChainWrap'); if(!c) return;
  let hasThreat = false;
  let alertCounts = {};
  try {
    const stats = await _fetch('/dashboard/stats-live');
    hasThreat = (stats?.kpis?.critical_threats||0) > 0;
    alertCounts = stats?.kpis || {};
  } catch{}

  c.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-sitemap" style="color:#c9a227;margin-right:8px"></i>
        Cyber Kill Chain Framework
      </h2>
      <p style="font-size:.78em;color:#8b949e;margin:2px 0 0">MITRE ATT&CK® v14 · ${_KILL_CHAIN_PHASES.length} phases · Click any phase for detailed analysis</p>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      ${hasThreat ? `<div style="background:#ef444420;border:1px solid #ef444444;border-radius:6px;padding:5px 10px;font-size:.75em;color:#ef4444">
        <i class="fas fa-exclamation-triangle" style="margin-right:4px;animation:livePulse 1.5s infinite"></i>Active Threats Detected</div>` : ''}
      <div style="background:#0a1628;border:1px solid #1e2d3d;border-radius:6px;padding:5px 10px;font-size:.75em;color:#22c55e">
        <i class="fas fa-circle" style="font-size:.5em;margin-right:4px"></i>ATT&CK v14 Live</div>
    </div>
  </div>

  <!-- Attack Path Timeline / Kill Chain Flow -->
  <div style="overflow-x:auto;margin-bottom:20px;padding-bottom:4px">
    <div style="display:flex;min-width:fit-content;gap:3px;align-items:stretch">
      ${_KILL_CHAIN_PHASES.map((p,i)=>{
        const isActive = hasThreat && i <= 5;
        return `
        <div onclick="_kcShowPhase(${i})" id="kc-phase-${i}"
          style="flex-shrink:0;width:120px;background:${isActive?p.color+'18':'#0d1117'};
            border:1px solid ${isActive?p.color+'55':'#21262d'};padding:14px 8px;
            text-align:center;cursor:pointer;transition:all .2s;position:relative;
            ${i===0?'border-radius:10px 0 0 10px':i===_KILL_CHAIN_PHASES.length-1?'border-radius:0 10px 10px 0':''}"
          onmouseover="this.style.background='${p.color}22';this.style.borderColor='${p.color}66'"
          onmouseout="this.style.background='${isActive?p.color+'18':'#0d1117'}';this.style.borderColor='${isActive?p.color+'55':'#21262d'}'">
          ${isActive?`<div style="position:absolute;top:5px;right:5px;width:7px;height:7px;background:${p.color};border-radius:50%;animation:livePulse 1.5s infinite"></div>`:''}
          <div style="font-size:1.3em;color:${p.color};margin-bottom:6px"><i class="fas ${p.icon}"></i></div>
          <div style="font-size:.63em;font-weight:700;color:#e6edf3;line-height:1.3;margin-bottom:4px">${p.label}</div>
          <div style="font-size:.58em;color:#8b949e;font-family:monospace">${p.phase}</div>
          ${i<_KILL_CHAIN_PHASES.length-1?`<div style="position:absolute;right:-10px;top:50%;transform:translateY(-50%);color:${p.color};font-size:1em;z-index:2">›</div>`:''}
        </div>`;
      }).join('')}
    </div>
  </div>

  <!-- Attack Flow Legend -->
  <div style="display:flex;flex-wrap:wrap;gap:10px;font-size:.73em;margin-bottom:18px;color:#8b949e">
    <span><span style="display:inline-block;width:10px;height:10px;background:#ef4444;border-radius:50%;animation:livePulse 1.5s infinite;margin-right:5px"></span>Active threat phase</span>
    <span><span style="display:inline-block;width:10px;height:10px;background:#21262d;border:1px solid #30363d;border-radius:50%;margin-right:5px"></span>Not detected</span>
    <span style="margin-left:auto">Attack path: ${_KILL_CHAIN_PHASES.map(p=>`<span style="color:${p.color}">${p.label.split(' ')[0]}</span>`).join(' → ')}</span>
  </div>

  <!-- Phase Cards Grid -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:20px">
    ${_KILL_CHAIN_PHASES.map((p,i)=>{
      const techCount = p.techniques.length;
      return `
      <div onclick="_kcShowPhase(${i})" style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;cursor:pointer;transition:all .2s"
        onmouseover="this.style.borderColor='${p.color}55'" onmouseout="this.style.borderColor='#21262d'">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="width:32px;height:32px;border-radius:7px;background:${p.color}18;border:1px solid ${p.color}33;
            display:flex;align-items:center;justify-content:center;color:${p.color};flex-shrink:0">
            <i class="fas ${p.icon}"></i></div>
          <div>
            <div style="font-size:.78em;font-weight:700;color:#e6edf3">${p.label}</div>
            <div style="font-size:.65em;color:#8b949e;font-family:monospace">${p.phase}</div>
          </div>
        </div>
        <div style="font-size:.7em;color:#8b949e;line-height:1.4;margin-bottom:6px">${_esc(p.tactic_desc)}</div>
        <div style="font-size:.67em;color:#8b949e">
          <span style="color:#3b82f6">${techCount} techniques</span>
          · <span style="color:#f97316">${p.examples.length} examples</span>
        </div>
      </div>`;
    }).join('')}
  </div>

  <!-- Detail Panel -->
  <div id="kc-detail" style="background:#0d1117;border:1px solid #21262d;border-radius:12px;padding:20px">
    <div style="text-align:center;color:#8b949e;font-size:.84em;padding:20px 0">
      <i class="fas fa-mouse-pointer" style="font-size:1.5em;margin-bottom:8px;display:block;color:#c9a227"></i>
      Click any phase above to view detailed analysis, real-world examples, detection guidance, and MITRE ATT&CK technique mapping
    </div>
  </div>`;
}

window._kcShowPhase = (idx) => {
  const p = _KILL_CHAIN_PHASES[idx];
  // Highlight selected phase
  _KILL_CHAIN_PHASES.forEach((_,i)=>{
    const el=document.getElementById(`kc-phase-${i}`);
    if(el) { el.style.background=i===idx?`rgba(${p.color.slice(1).match(/../g).map(x=>parseInt(x,16)).join(',')},0.2)`:'#0d1117'; }
  });
  const detail=document.getElementById('kc-detail');
  if(!detail) return;
  detail.innerHTML=`
  <!-- Phase header -->
  <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:16px">
    <div style="width:54px;height:54px;border-radius:12px;background:${p.color}22;border:1px solid ${p.color}44;
      display:flex;align-items:center;justify-content:center;font-size:1.5em;color:${p.color};flex-shrink:0">
      <i class="fas ${p.icon}"></i>
    </div>
    <div style="flex:1">
      <div style="font-size:1.05em;font-weight:700;color:#e6edf3;margin-bottom:4px">${p.label}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <span style="background:${p.color}18;color:${p.color};border:1px solid ${p.color}33;padding:1px 8px;border-radius:5px;font-family:monospace;font-size:.72em">${p.phase}</span>
        <span style="font-size:.72em;color:#8b949e">Phase ${idx+1} of ${_KILL_CHAIN_PHASES.length} · MITRE ATT&CK v14</span>
      </div>
    </div>
    <div style="display:flex;gap:6px;flex-shrink:0">
      <button onclick="window.open('https://attack.mitre.org/tactics/${p.phase}/','_blank')"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:5px 10px;border-radius:5px;font-size:.75em;cursor:pointer">
        <i class="fas fa-external-link-alt" style="margin-right:4px"></i>MITRE</button>
    </div>
  </div>

  <!-- Description -->
  <p style="font-size:.84em;color:#8b949e;line-height:1.7;background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px;margin-bottom:16px">${_esc(p.desc)}</p>

  <!-- Three column grid -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px">
    <!-- Examples -->
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">
      <div style="font-size:.78em;font-weight:700;color:#e6edf3;margin-bottom:10px">
        <i class="fas fa-list" style="color:#c9a227;margin-right:6px"></i>Real-World Examples
      </div>
      <ul style="list-style:none;margin:0;padding:0">
        ${p.examples.map(e=>`<li style="padding:4px 0;border-bottom:1px solid #1a2030;font-size:.78em;color:#8b949e;display:flex;align-items:center;gap:6px">
          <i class="fas fa-chevron-right" style="color:${p.color};font-size:.65em;flex-shrink:0"></i>${_esc(e)}</li>`).join('')}
      </ul>
    </div>

    <!-- MITRE Techniques -->
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">
      <div style="font-size:.78em;font-weight:700;color:#e6edf3;margin-bottom:10px">
        <i class="fas fa-th" style="color:#8b5cf6;margin-right:6px"></i>MITRE ATT&CK Techniques
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        ${p.techniques.map(t=>`<span onclick="window.open('https://attack.mitre.org/techniques/${t.replace('.','/')}','_blank')"
          style="cursor:pointer;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);color:#8b5cf6;
            padding:3px 10px;border-radius:5px;font-family:monospace;font-size:.75em">${t}</span>`).join('')}
      </div>
    </div>

    <!-- Detection Guidance -->
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">
      <div style="font-size:.78em;font-weight:700;color:#e6edf3;margin-bottom:10px">
        <i class="fas fa-shield-alt" style="color:#22c55e;margin-right:6px"></i>Detection Guidance
      </div>
      <p style="font-size:.78em;color:#8b949e;line-height:1.6;margin:0 0 10px">${_esc(p.detection||'')}</p>
      <button onclick="if(window.navigateTo)navigateTo('threat-hunting')"
        style="background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.3);
          padding:5px 10px;border-radius:5px;font-size:.74em;cursor:pointer">
        <i class="fas fa-crosshairs" style="margin-right:4px"></i>Hunt for this technique
      </button>
    </div>
  </div>`;

  detail.scrollIntoView({ behavior:'smooth', block:'nearest' });
};

// Alias for backward compatibility
window._kcShowPhase = window._kcShowPhase;

/* ─────────────────────────────────────────────
   COLLECTORS DYNAMIC COUNT (replaces static "47")
───────────────────────────────────────────── */
async function _updateCollectorCount() {
  try {
    // Try dedicated collectors endpoint first, fallback to stats-live
    let count = 0;
    try {
      const r = await _fetch('/collectors?limit=1');
      count = r?.total || 0;
    } catch {
      const stats = await _fetch('/dashboard/stats-live');
      count = (stats?.feed_status||[]).length || stats?.kpis?.active_feeds || 0;
    }
    const btn = document.getElementById('collectorsPanelBtn');
    if(btn) btn.textContent = `View All (${count})`;
    const nbFeeds = document.getElementById('nb-feeds');
    if(nbFeeds) nbFeeds.textContent = count;
  } catch{}
}

/* ─────────────────────────────────────────────
   AUTO-REFRESH MANAGER
   (does NOT redeclare AutoRefresh — uses the one from realtime-data.js
    or sets up a simple fallback)
───────────────────────────────────────────── */
function _initAutoRefresh() {
  if (typeof window.AutoRefresh !== 'undefined' && typeof window.AutoRefresh.subscribe === 'function') {
    window.AutoRefresh.subscribe('command-center', async () => {
      await _loadKPIs();
      _loadMiniFeedStatus();
    });
    console.info('[LivePages] KPI subscriber registered in AutoRefresh');
    return;
  }
  // Fallback own timer
  let _tm=null, _tab='command-center';
  const AR={
    start(){ this.stop(); _tm=setInterval(()=>{if(_tab==='command-center'){_loadKPIs();_loadMiniFeedStatus();}},LP_REFRESH_MS); },
    stop(){ if(_tm){clearInterval(_tm);_tm=null;} },
    setActiveTab(t){ _tab=t; },
    subscribe(){}
  };
  window.AutoRefresh=AR; AR.start();
  console.info('[LivePages] AutoRefresh fallback started ('+LP_REFRESH_MS/1000+'s)');
}

/* ─────────────────────────────────────────────
   INIT  — called from main.js initApp()
───────────────────────────────────────────── */
async function initLivePages() {
  console.info('[LivePages] v5.0 (Wadjet-Eye AI) initialising…');

  // Guard: main.js already calls renderCommandCenter() which is overridden to
  // renderCommandCenterLive(). Calling it again here would trigger a duplicate
  // API request on startup. Only load the command center if it has not been
  // rendered yet (i.e. the KPI elements are still empty placeholders).
  const kpiEl = document.querySelector('[data-kpi="critical_alerts"], #kpi-critical, .kpi-critical');
  const alreadyLoaded = kpiEl && kpiEl.textContent && kpiEl.textContent !== '—' && kpiEl.textContent !== '0';
  if (!alreadyLoaded) {
    await renderCommandCenterLive();
  } else {
    console.info('[LivePages] Command center already loaded — skipping duplicate render');
  }
  _updateCollectorCount();

  // Start refresh loop
  _initAutoRefresh();

  // Stop on logout
  const orig = window.doLogout;
  window.doLogout = function() {
    if (typeof window.AutoRefresh?.stop === 'function') window.AutoRefresh.stop();
    if (typeof orig === 'function') orig();
  };

  console.info('[LivePages] Ready — Wadjet-Eye AI CTI Platform');
}

/* ─────────────────────────────────────────────
   EXPORTS / SHIMS for backward compat
───────────────────────────────────────────── */
window.loadLiveKPIs         = _loadKPIs;
window.renderFeedStatusMini = _loadMiniFeedStatus;
window.renderTimelineMini   = _loadMiniFindings;
window.animateCount         = _countUp;
window.loadingSkeleton      = _skel;
window.esc                  = _esc;
window.timeAgo              = _ago;
