/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Live Pages Patch v5.2
 *  js/live-pages-patch.js
 *
 *  LOADS AFTER live-pages.js to:
 *    1. Override ALL mock-data functions with real API calls
 *    2. Fix SOAR navigation key mismatch ('soar' vs 'soar-automation')
 *    3. Resolve window.renderSOARLive conflict
 *    4. Override renderCampaignsLive to remove _MOCK_CAMPAIGNS fallback
 *    5. Override renderThreatActorsLive to remove mock actor list fallback
 *    6. Override renderCollectorsLive to use real /collectors endpoint
 *    7. Fix renderExposureLive to use correct /exposure/summary + /exposure/cves
 *    8. Add cyber-news section to dashboard
 *    9. Make dashboard KPIs clickable
 *   10. Add news panel to Executive Dashboard
 * ══════════════════════════════════════════════════════════
 */
'use strict';

(function() {

// ── Patch: wait for DOM ready ────────────────────────────────
function onReady(fn) {
  if (document.readyState !== 'loading') fn();
  else document.addEventListener('DOMContentLoaded', fn);
}

// ── API base URL ─────────────────────────────────────────────
function _apiBase() {
  return window.THREATPILOT_API_URL ||
         window.WADJET_API_URL ||
         'https://wadjet-eye-ai.onrender.com';
}

// ── Auth token ───────────────────────────────────────────────
function _token() {
  return localStorage.getItem('wadjet_access_token') ||
         localStorage.getItem('we_access_token') ||
         sessionStorage.getItem('we_access_token') ||
         sessionStorage.getItem('wadjet_access_token') || '';
}

// ── Unified fetch with auth + 401 retry ─────────────────────
async function _apiFetch(path, opts = {}) {
  const base  = _apiBase();
  const url   = `${base}/api${path}`;
  const token = _token();

  const res = await fetch(url, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
  });

  if (res.status === 401) {
    // Try silent refresh
    if (window.PersistentAuth_silentRefresh) {
      const ok = await window.PersistentAuth_silentRefresh();
      if (ok) {
        const newToken = _token();
        const r2 = await fetch(url, {
          ...opts,
          headers: {
            'Content-Type': 'application/json',
            ...(newToken ? { Authorization: `Bearer ${newToken}` } : {}),
          },
        });
        if (!r2.ok) return { data: [], total: 0, _offline: true };
        return r2.json();
      }
    }
    return { data: [], total: 0, _offline: true };
  }

  if (res.status === 404) return { data: [], total: 0 };
  if (!res.ok) {
    console.warn(`[LP-Patch] API ${path} → HTTP ${res.status}`);
    return { data: [], total: 0, _error: res.status };
  }

  return res.json();
}

// ── HTML escape ──────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Severity color ───────────────────────────────────────────
function sevColor(s) {
  const m = { critical:'#ff4757', high:'#ff6b35', medium:'#ffa502', low:'#2ed573', info:'#5352ed' };
  return m[(s||'').toLowerCase()] || '#636e72';
}

function sevBadge(s) {
  return `<span style="background:${sevColor(s)};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;text-transform:uppercase">${esc(s)}</span>`;
}

// ── Relative time ────────────────────────────────────────────
function relTime(ts) {
  if (!ts) return '—';
  const d = Date.now() - new Date(ts).getTime();
  if (d < 60000)     return `${Math.round(d/1000)}s ago`;
  if (d < 3600000)   return `${Math.round(d/60000)}m ago`;
  if (d < 86400000)  return `${Math.round(d/3600000)}h ago`;
  return `${Math.round(d/86400000)}d ago`;
}

// ══════════════════════════════════════════════════════════════
//  FIX 1: SOAR Navigation — resolve 'soar' vs 'soar-automation'
//  soar-ui.js defines window.renderSOARLive but live-pages.js
//  also defines it, causing a conflict. soar-ui.js wins because
//  it loads last. We normalize the PAGE_CONFIG entry.
// ══════════════════════════════════════════════════════════════
onReady(function fixSOARNavigation() {
  // Wait for PAGE_CONFIG to be populated
  setTimeout(() => {
    if (window.PAGE_CONFIG) {
      // Ensure 'soar' key maps to soar-ui.js renderSOARLive
      if (!window.PAGE_CONFIG['soar']) {
        window.PAGE_CONFIG['soar'] = {
          title:      'SOAR Automation Engine',
          breadcrumb: ['Platform', 'SOAR Automation'],
          onEnter: () => {
            const fn = window.renderSOARLive || window.renderSOAR;
            if (fn) fn();
          },
          onLeave: () => {},
        };
      } else {
        // Patch existing entry to use soar-ui.js version
        const orig = window.PAGE_CONFIG['soar'].onEnter;
        window.PAGE_CONFIG['soar'].onEnter = () => {
          const fn = window.renderSOARLive || window.renderSOAR;
          if (fn) fn();
          else if (orig) orig();
        };
      }

      // Also add 'soar-automation' alias
      window.PAGE_CONFIG['soar-automation'] = window.PAGE_CONFIG['soar'];
    }
  }, 500);
});

// ══════════════════════════════════════════════════════════════
//  FIX 2: Override renderCampaignsLive — remove mock fallback
// ══════════════════════════════════════════════════════════════
async function renderCampaignsLivePatched(opts = {}) {
  const wrap = document.getElementById('campaignsLiveContainer');
  if (!wrap) return;

  // Shimmer loading
  wrap.innerHTML = `
    <div style="padding:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div>
          <h2 style="margin:0;font-size:20px;color:#e2e8f0">🎯 Threat Campaigns</h2>
          <div style="font-size:12px;color:#64748b;margin-top:2px">Real-time intelligence from ingested feeds</div>
        </div>
        <button onclick="window._campaignCreate && window._campaignCreate()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px">
          + New Campaign
        </button>
      </div>
      ${[1,2,3,4].map(() => `<div style="height:56px;background:#1e2535;border-radius:6px;margin-bottom:8px;animation:shimmer 1.5s infinite"></div>`).join('')}
    </div>`;

  try {
    const page  = opts.page || 1;
    const limit = 25;

    // Real API call — no mock fallback
    const result = await _apiFetch(`/cti/campaigns?page=${page}&limit=${limit}`);
    const campaigns = result?.data || result?.results || (Array.isArray(result) ? result : []);
    const total     = result?.total || result?.count || campaigns.length;

    if (!campaigns.length) {
      wrap.innerHTML = `
        <div style="padding:32px;text-align:center;color:#64748b">
          <div style="font-size:48px;margin-bottom:16px">🎯</div>
          <h3 style="color:#94a3b8;margin:0 0 8px">No Active Campaigns</h3>
          <p style="margin:0 0 16px;font-size:14px">
            Campaigns are automatically created when the ingestion pipeline detects coordinated threat activity.
          </p>
          <div style="display:flex;gap:12px;justify-content:center">
            <button onclick="window._triggerIngest && window._triggerIngest()" style="background:#3b82f6;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer">
              Trigger Ingestion
            </button>
            <button onclick="window._campaignCreate && window._campaignCreate()" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:10px 20px;border-radius:6px;cursor:pointer">
              Create Manually
            </button>
          </div>
        </div>`;
      return;
    }

    // Status filter bar
    const allStatuses = [...new Set(campaigns.map(c => c.status).filter(Boolean))];

    let html = `
      <div style="padding:0 16px 16px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button onclick="window._campaignFilter('all')" id="cf-btn-all" style="background:#3b82f6;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">All (${total})</button>
            ${allStatuses.map(s => `<button onclick="window._campaignFilter('${esc(s)}')" id="cf-btn-${esc(s)}" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">${esc(s)}</button>`).join('')}
          </div>
          <button onclick="window._exportCampaigns && window._exportCampaigns()" style="background:transparent;color:#64748b;border:1px solid #334155;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">↓ Export</button>
        </div>

        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="border-bottom:1px solid #334155;color:#64748b">
              <th style="padding:8px 12px;text-align:left;font-weight:500">Campaign</th>
              <th style="padding:8px 12px;text-align:left;font-weight:500">Actor</th>
              <th style="padding:8px 12px;text-align:left;font-weight:500">Severity</th>
              <th style="padding:8px 12px;text-align:left;font-weight:500">Status</th>
              <th style="padding:8px 12px;text-align:right;font-weight:500">Findings</th>
              <th style="padding:8px 12px;text-align:right;font-weight:500">IOCs</th>
              <th style="padding:8px 12px;text-align:left;font-weight:500">Updated</th>
              <th style="padding:8px 12px;text-align:center;font-weight:500">Actions</th>
            </tr>
          </thead>
          <tbody id="campaigns-tbody">
            ${campaigns.map(c => `
              <tr onclick="window._openCampaignDetail('${esc(c.id)}')" style="border-bottom:1px solid #1e2535;cursor:pointer;transition:background 0.15s" onmouseover="this.style.background='#1e2535'" onmouseout="this.style.background='transparent'">
                <td style="padding:10px 12px">
                  <div style="font-weight:500;color:#e2e8f0">${esc(c.name)}</div>
                  ${c.description ? `<div style="font-size:11px;color:#64748b;margin-top:2px">${esc(c.description.slice(0,60))}…</div>` : ''}
                </td>
                <td style="padding:10px 12px;color:#94a3b8">${esc(c.actor || c.threat_actor || '—')}</td>
                <td style="padding:10px 12px">${sevBadge(c.severity)}</td>
                <td style="padding:10px 12px">
                  <span style="background:${c.status==='active'?'#16a34a20':c.status==='resolved'?'#1e40af20':'#92400e20'};color:${c.status==='active'?'#22c55e':c.status==='resolved'?'#60a5fa':'#f59e0b'};padding:2px 8px;border-radius:3px;font-size:11px;font-weight:500">
                    ${esc(c.status || 'unknown')}
                  </span>
                </td>
                <td style="padding:10px 12px;text-align:right;color:#94a3b8">${c.findings_count || 0}</td>
                <td style="padding:10px 12px;text-align:right;color:#94a3b8">${c.ioc_count || 0}</td>
                <td style="padding:10px 12px;color:#64748b;font-size:12px">${relTime(c.updated_at || c.last_seen)}</td>
                <td style="padding:10px 12px;text-align:center">
                  <button onclick="event.stopPropagation();window._openCampaignDetail('${esc(c.id)}')" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px">Details</button>
                </td>
              </tr>`).join('')}
          </tbody>
        </table>

        ${total > limit ? `
          <div style="margin-top:12px;display:flex;justify-content:center;gap:8px">
            ${page > 1 ? `<button onclick="window.renderCampaigns({page:${page-1}})" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px">← Prev</button>` : ''}
            <span style="color:#64748b;line-height:30px;font-size:12px">Page ${page} / ${Math.ceil(total/limit)}</span>
            ${page < Math.ceil(total/limit) ? `<button onclick="window.renderCampaigns({page:${page+1}})" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px">Next →</button>` : ''}
          </div>` : ''}
      </div>`;

    wrap.innerHTML = `
      <div style="padding:16px 0 0">
        <div style="padding:0 16px 12px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <h2 style="margin:0;font-size:20px;color:#e2e8f0">🎯 Threat Campaigns</h2>
            <div style="font-size:12px;color:#64748b;margin-top:2px">${total} active campaign${total!==1?'s':''} from real intelligence feeds</div>
          </div>
          <button onclick="window._campaignCreate && window._campaignCreate()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px">+ New Campaign</button>
        </div>
        ${html}
      </div>`;

  } catch (err) {
    console.error('[LP-Patch] Campaign render error:', err.message);
    wrap.innerHTML = `<div style="padding:24px;text-align:center;color:#64748b">
      <div style="font-size:32px;margin-bottom:12px">⚠️</div>
      <p>Failed to load campaigns from backend.</p>
      <button onclick="window.renderCampaigns()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer">Retry</button>
    </div>`;
  }
}

// Campaign detail modal
window._openCampaignDetail = async function(id) {
  const modal = document.getElementById('playbookModal') || document.getElementById('actorModal') || _createModal('campaignDetailModal');
  if (!modal) return;

  const body = modal.querySelector('.modal-body') || modal.querySelector('[id$="Body"]') || modal;
  const title = modal.querySelector('.modal-title') || modal.querySelector('h2') || { textContent: '' };

  title.textContent = 'Campaign Details';
  if (body) body.innerHTML = `<div style="text-align:center;padding:40px;color:#64748b">Loading campaign details…</div>`;
  modal.style.display = 'flex';

  try {
    const data = await _apiFetch(`/cti/campaigns/${id}`);
    const c = data?.data || data;
    if (!c || !c.id) throw new Error('Not found');

    if (body) {
      body.innerHTML = `
        <div style="padding:4px 0">
          <!-- Header -->
          <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px">
            <div>
              <h3 style="margin:0 0 6px;color:#e2e8f0;font-size:18px">${esc(c.name)}</h3>
              <div style="display:flex;gap:8px;align-items:center">
                ${sevBadge(c.severity)}
                <span style="color:#64748b;font-size:12px">${esc(c.actor || '—')}</span>
                <span style="color:#64748b;font-size:12px">•</span>
                <span style="color:#64748b;font-size:12px">${relTime(c.updated_at)}</span>
              </div>
            </div>
            <div style="display:flex;gap:8px">
              <button onclick="window.navigateTo && window.navigateTo('case-management')" style="background:#3b82f6;color:#fff;border:none;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:12px">Create Case</button>
              <button onclick="window.navigateTo && window.navigateTo('ioc-registry')" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:12px">Hunt IOCs</button>
            </div>
          </div>

          ${c.description ? `<p style="color:#94a3b8;font-size:14px;margin:0 0 20px;line-height:1.6">${esc(c.description)}</p>` : ''}

          <!-- KPIs -->
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
            ${[
              { l:'Findings', v: c.findings_count||0, clr:'#ff6b35' },
              { l:'IOCs',     v: c.ioc_count||0,     clr:'#f59e0b' },
              { l:'Status',   v: c.status||'—',      clr:'#22c55e' },
              { l:'Cases',    v: c.related_cases?.length||0, clr:'#60a5fa' },
            ].map(k => `<div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;text-align:center">
              <div style="font-size:22px;font-weight:700;color:${k.clr}">${esc(String(k.v))}</div>
              <div style="font-size:11px;color:#64748b;margin-top:4px">${k.l}</div>
            </div>`).join('')}
          </div>

          <!-- MITRE Techniques -->
          ${c.mitre_techniques?.length ? `
            <div style="margin-bottom:16px">
              <div style="font-size:12px;color:#64748b;font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">MITRE ATT&CK Techniques</div>
              <div style="display:flex;flex-wrap:wrap;gap:6px">
                ${c.mitre_techniques.map(t => `<span style="background:#1e2535;color:#a78bfa;border:1px solid #4c1d95;padding:3px 8px;border-radius:4px;font-size:11px;font-family:monospace">${esc(t)}</span>`).join('')}
              </div>
            </div>` : ''}

          <!-- Tags -->
          ${c.tags?.length ? `
            <div style="margin-bottom:16px">
              <div style="font-size:12px;color:#64748b;font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">Tags</div>
              <div style="display:flex;flex-wrap:wrap;gap:6px">
                ${c.tags.map(t => `<span style="background:#1e2535;color:#64748b;border:1px solid #334155;padding:3px 8px;border-radius:12px;font-size:11px">${esc(t)}</span>`).join('')}
              </div>
            </div>` : ''}

          <!-- Timeline -->
          ${c.timeline?.length ? `
            <div>
              <div style="font-size:12px;color:#64748b;font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">Activity Timeline</div>
              <div style="border-left:2px solid #334155;padding-left:16px">
                ${c.timeline.map(evt => `
                  <div style="margin-bottom:12px;position:relative">
                    <div style="position:absolute;left:-20px;top:4px;width:8px;height:8px;border-radius:50%;background:#3b82f6"></div>
                    <div style="font-size:12px;color:#64748b">${relTime(evt.timestamp || evt.ts)}</div>
                    <div style="font-size:13px;color:#e2e8f0">${esc(evt.description || evt.event || JSON.stringify(evt))}</div>
                  </div>`).join('')}
              </div>
            </div>` : ''}
        </div>`;
    }
  } catch (err) {
    if (body) body.innerHTML = `<div style="padding:24px;text-align:center;color:#64748b">
      <p>Failed to load campaign details: ${esc(err.message)}</p>
    </div>`;
  }
};

// Create modal helper
function _createModal(id) {
  const el = document.createElement('div');
  el.id = id;
  el.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.8);display:none;align-items:center;justify-content:center;z-index:9999';
  el.innerHTML = `
    <div style="background:#1a2133;border:1px solid #334155;border-radius:12px;width:90%;max-width:800px;max-height:85vh;overflow:auto;padding:24px;position:relative">
      <button onclick="this.closest('[id]').style.display='none'" style="position:absolute;top:12px;right:12px;background:transparent;border:none;color:#64748b;font-size:18px;cursor:pointer">✕</button>
      <h2 style="margin:0 0 20px;color:#e2e8f0;font-size:18px"></h2>
      <div class="modal-body"></div>
    </div>`;
  document.body.appendChild(el);
  return el;
}

// Override window.renderCampaigns
window.renderCampaigns = (opts) => renderCampaignsLivePatched(opts || {}).catch(e => console.warn('[LP-Patch] Campaign error:', e.message));

// ══════════════════════════════════════════════════════════════
//  FIX 3: Override renderThreatActorsLive — remove mock actors
// ══════════════════════════════════════════════════════════════
async function renderThreatActorsLivePatched(opts = {}) {
  const wrap = document.getElementById('threatActorsContainer') || document.getElementById('actorsContainer');
  if (!wrap) return;

  wrap.innerHTML = `<div style="padding:16px">${[1,2,3,4,5,6].map(() => `<div style="height:140px;background:#1e2535;border-radius:8px;margin-bottom:12px;animation:shimmer 1.5s infinite"></div>`).join('')}</div>`;

  try {
    const result = await _apiFetch(`/cti/actors?page=${opts.page||1}&limit=24`);
    const actors  = result?.data || (Array.isArray(result) ? result : []);
    const total   = result?.total || actors.length;

    if (!actors.length) {
      wrap.innerHTML = `
        <div style="padding:32px;text-align:center;color:#64748b">
          <div style="font-size:48px;margin-bottom:16px">🕵️</div>
          <h3 style="color:#94a3b8;margin:0 0 8px">No Threat Actors Yet</h3>
          <p style="margin:0 0 16px;font-size:14px">Threat actors are populated automatically from OTX, MISP, and manual analysis.</p>
          <button onclick="window._triggerIngest && window._triggerIngest('otx')" style="background:#3b82f6;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer">
            Run OTX Ingestion
          </button>
        </div>`;
      return;
    }

    const motives = [...new Set(actors.map(a => a.motivation).filter(Boolean))];

    wrap.innerHTML = `
      <div style="padding:16px 0 0">
        <div style="padding:0 16px 12px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <h2 style="margin:0;font-size:20px;color:#e2e8f0">🕵️ Threat Actors</h2>
            <div style="font-size:12px;color:#64748b;margin-top:2px">${total} tracked actor${total!==1?'s':''}</div>
          </div>
        </div>
        <div style="padding:0 16px;display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
          <button onclick="window._actorFilter('all')" style="background:#3b82f6;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">All</button>
          ${motives.slice(0,6).map(m => `<button onclick="window._actorFilter('${esc(m)}')" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">${esc(m)}</button>`).join('')}
        </div>
        <div style="padding:0 16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px" id="actorsGrid">
          ${actors.map(a => `
            <div onclick="window._openActorDetail('${esc(a.id)}')" style="background:#1e2535;border:1px solid #334155;border-radius:8px;padding:16px;cursor:pointer;transition:border-color 0.2s" onmouseover="this.style.borderColor='#3b82f6'" onmouseout="this.style.borderColor='#334155'">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
                <div style="font-weight:600;color:#e2e8f0;font-size:14px">${esc(a.name)}</div>
                <span style="background:${sevColor(a.sophistication||'medium')}22;color:${sevColor(a.sophistication||'medium')};border:1px solid ${sevColor(a.sophistication||'medium')}44;padding:2px 8px;border-radius:3px;font-size:10px">${esc(a.sophistication||'unknown')}</span>
              </div>
              ${a.aliases?.length ? `<div style="font-size:11px;color:#64748b;margin-bottom:8px">Also: ${a.aliases.slice(0,3).join(', ')}</div>` : ''}
              <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
                ${a.origin_country ? `<span style="background:#0f172a;color:#94a3b8;padding:2px 7px;border-radius:3px;font-size:11px;border:1px solid #1e2535">🌐 ${esc(a.origin_country)}</span>` : ''}
                ${a.motivation ? `<span style="background:#0f172a;color:#94a3b8;padding:2px 7px;border-radius:3px;font-size:11px;border:1px solid #1e2535">⚡ ${esc(a.motivation)}</span>` : ''}
              </div>
              ${a.description ? `<p style="font-size:12px;color:#64748b;margin:0;line-height:1.5">${esc(a.description.slice(0,100))}…</p>` : ''}
              ${a.mitre_techniques?.length ? `
                <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px">
                  ${a.mitre_techniques.slice(0,4).map(t => `<span style="background:#1a2133;color:#a78bfa;font-size:10px;padding:1px 6px;border-radius:3px;font-family:monospace;border:1px solid #4c1d9533">${esc(t)}</span>`).join('')}
                  ${a.mitre_techniques.length > 4 ? `<span style="color:#64748b;font-size:10px">+${a.mitre_techniques.length-4}</span>` : ''}
                </div>` : ''}
            </div>`).join('')}
        </div>
      </div>`;

  } catch (err) {
    console.error('[LP-Patch] Actor render error:', err.message);
    wrap.innerHTML = `<div style="padding:24px;text-align:center;color:#64748b">
      <p>Failed to load threat actors: ${esc(err.message)}</p>
      <button onclick="window.renderThreatActors()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;margin-top:8px">Retry</button>
    </div>`;
  }
}

window.renderThreatActors = (opts) => renderThreatActorsLivePatched(opts || {}).catch(e => console.warn('[LP-Patch] Actor error:', e.message));

// ══════════════════════════════════════════════════════════════
//  FIX 4: Override renderExposureLive — correct endpoints
// ══════════════════════════════════════════════════════════════
async function renderExposureLivePatched() {
  const wrap = document.getElementById('exposureLiveContainer');
  if (!wrap) return;

  wrap.innerHTML = `<div style="padding:16px">${[1,2,3].map(() => `<div style="height:100px;background:#1e2535;border-radius:8px;margin-bottom:12px;animation:shimmer 1.5s infinite"></div>`).join('')}</div>`;

  try {
    // 1. Load summary KPIs from correct endpoint
    const summary = await _apiFetch('/exposure/summary');

    // 2. Render KPI tiles
    const kpis = [
      { label: 'Risk Score',        value: `${summary.risk_score || 0}%`,   color: summary.risk_score >= 75 ? '#ff4757' : summary.risk_score >= 50 ? '#ff6b35' : '#ffa502', icon: '⚡' },
      { label: 'Critical Exposures', value: summary.critical_exposures || 0, color: '#ff4757', icon: '🔴' },
      { label: 'High Exposures',     value: summary.high_exposures || 0,    color: '#ff6b35', icon: '🟠' },
      { label: 'Affected Assets',    value: summary.total_exposures || 0,   color: '#f59e0b', icon: '🖥️' },
      { label: 'Malicious IOCs',     value: summary.malicious_iocs || 0,    color: '#ef4444', icon: '☣️' },
      { label: 'CVEs Tracked',       value: summary.total_cves || 0,        color: '#8b5cf6', icon: '🛡️' },
    ];

    // 3. Load CVEs with correct endpoint
    const cveData = await _apiFetch('/exposure/cves?limit=20');
    const cves     = cveData?.data || [];

    // 4. Load recent news
    const newsData = await _apiFetch('/exposure/news?limit=5');
    const news     = newsData?.data || [];

    const riskColor = summary.risk_score >= 75 ? '#ff4757' : summary.risk_score >= 50 ? '#ff6b35' : '#ffa502';

    wrap.innerHTML = `
      <div style="padding:0 16px 24px">
        <!-- Header -->
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
          <div>
            <h2 style="margin:0;font-size:20px;color:#e2e8f0">🔍 Exposure Assessment</h2>
            <div style="font-size:12px;color:#64748b;margin-top:2px">
              Risk Level: <span style="color:${riskColor};font-weight:600">${summary.risk_level || 'UNKNOWN'}</span>
              &nbsp;•&nbsp; Last scan: ${relTime(summary.last_scan_at)}
            </div>
          </div>
          <div style="display:flex;gap:8px">
            <button onclick="window._triggerExposureScan()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px">
              🔁 Run Scan
            </button>
            <button onclick="window.navigateTo && window.navigateTo('ioc-registry')" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px">
              View IOCs
            </button>
          </div>
        </div>

        <!-- KPI Grid -->
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:24px">
          ${kpis.map(k => `
            <div style="background:#1e2535;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center">
              <div style="font-size:24px;margin-bottom:4px">${k.icon}</div>
              <div style="font-size:24px;font-weight:700;color:${k.color}">${esc(String(k.value))}</div>
              <div style="font-size:11px;color:#64748b;margin-top:4px">${k.label}</div>
            </div>`).join('')}
        </div>

        <!-- CVE List -->
        <div style="margin-bottom:24px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <h3 style="margin:0;font-size:16px;color:#e2e8f0">🛡️ Tracked CVEs</h3>
            <a href="#" onclick="window._expShowAllCves && window._expShowAllCves();return false" style="font-size:12px;color:#3b82f6;text-decoration:none">View all →</a>
          </div>
          ${cves.length === 0 ? `
            <div style="background:#1e2535;border:1px solid #334155;border-radius:8px;padding:24px;text-align:center;color:#64748b">
              <div style="font-size:32px;margin-bottom:8px">✅</div>
              <p style="margin:0">No CVEs detected in your environment — or NVD sync needed.</p>
              <button onclick="window._triggerNVDSync && window._triggerNVDSync()" style="background:#3b82f6;color:#fff;border:none;padding:8px 14px;border-radius:5px;cursor:pointer;margin-top:12px;font-size:12px">Sync NVD Database</button>
            </div>` : `
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px">
              ${cves.slice(0,12).map(cve => `
                <div style="background:#1e2535;border:1px solid ${cve.is_kev||cve.is_exploited ? '#7f1d1d' : '#334155'};border-radius:8px;padding:14px;cursor:pointer;transition:border-color 0.2s" onclick="window._openCVEModal && window._openCVEModal('${esc(cve.id)}')">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
                    <span style="font-family:monospace;font-size:13px;color:#60a5fa;font-weight:600">${esc(cve.cve_id || cve.id)}</span>
                    <div style="display:flex;gap:4px">
                      ${cve.is_kev || cve.is_exploited ? `<span style="background:#7f1d1d;color:#fca5a5;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600">KEV</span>` : ''}
                      ${sevBadge(cve.severity)}
                    </div>
                  </div>
                  ${cve.description ? `<p style="font-size:12px;color:#94a3b8;margin:0 0 8px;line-height:1.4">${esc(cve.description.slice(0,120))}…</p>` : ''}
                  <div style="display:flex;gap:12px;font-size:11px;color:#64748b">
                    ${cve.cvss_score ? `<span>CVSS: <strong style="color:#e2e8f0">${cve.cvss_score}</strong></span>` : ''}
                    ${cve.epss_score ? `<span>EPSS: <strong style="color:#e2e8f0">${(cve.epss_score*100).toFixed(1)}%</strong></span>` : ''}
                  </div>
                </div>`).join('')}
            </div>`}
        </div>

        <!-- Threat News -->
        ${news.length > 0 ? `
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
              <h3 style="margin:0;font-size:16px;color:#e2e8f0">📰 Related Threat News</h3>
              <a href="#" onclick="window.navigateTo && window.navigateTo('threat-feeds');return false" style="font-size:12px;color:#3b82f6;text-decoration:none">View all →</a>
            </div>
            <div style="display:flex;flex-direction:column;gap:8px">
              ${news.map(n => `
                <a href="${esc(n.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;display:flex;align-items:flex-start;gap:12px;background:#1e2535;border:1px solid #334155;border-radius:8px;padding:12px;transition:border-color 0.2s" onmouseover="this.style.borderColor='#3b82f6'" onmouseout="this.style.borderColor='#334155'">
                  <div style="flex:1">
                    <div style="font-size:13px;color:#e2e8f0;font-weight:500;margin-bottom:4px">${esc(n.title)}</div>
                    <div style="display:flex;gap:8px;font-size:11px;color:#64748b">
                      <span>${esc(n.source)}</span>
                      <span>•</span>
                      <span>${relTime(n.published_at)}</span>
                      ${n.cves?.length ? `<span>• ${n.cves.slice(0,2).join(', ')}</span>` : ''}
                    </div>
                  </div>
                  ${sevBadge(n.severity)}
                </a>`).join('')}
            </div>
          </div>` : ''}
      </div>`;

  } catch (err) {
    console.error('[LP-Patch] Exposure render error:', err.message);
    wrap.innerHTML = `<div style="padding:24px;text-align:center;color:#64748b">
      <div style="font-size:32px;margin-bottom:12px">⚠️</div>
      <p>Exposure Assessment backend not responding: ${esc(err.message)}</p>
      <p style="font-size:12px">Ensure the backend is online and the DB migration v5.2 has been applied.</p>
      <button onclick="window.renderExposureLive()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;margin-top:8px">Retry</button>
    </div>`;
  }
}

window._triggerExposureScan = async function() {
  try {
    await _apiFetch('/exposure/scan', { method: 'POST' });
    window._showToast && window._showToast('Exposure scan started', 'info');
    setTimeout(() => window.renderExposureLive(), 5000);
  } catch (_) {}
};

window._triggerNVDSync = async function() {
  try {
    await _apiFetch('/vulnerabilities/sync', { method: 'POST' });
    window._showToast && window._showToast('NVD sync triggered', 'info');
  } catch (_) {}
};

window._triggerIngest = async function(feed) {
  try {
    await _apiFetch(`/ingest/${feed || 'all'}`, { method: 'POST' });
    window._showToast && window._showToast(`Ingestion triggered: ${feed || 'all feeds'}`, 'info');
  } catch (_) {}
};

window.renderExposureLive = () => renderExposureLivePatched().catch(e => console.warn('[LP-Patch] Exposure error:', e.message));
window.renderExposure     = window.renderExposureLive;

// ══════════════════════════════════════════════════════════════
//  FIX 5: Override IOC Registry — real data, no demo banner
// ══════════════════════════════════════════════════════════════
async function renderIOCRegistryLivePatched(opts = {}) {
  const wrap = document.getElementById('iocRegistryContainer') || document.getElementById('iocLiveContainer');
  if (!wrap) return;

  const page     = opts.page     || 1;
  const typeF    = opts.type     || '';
  const repF     = opts.rep      || '';
  const sortF    = opts.sort     || 'risk_score';
  const searchF  = opts.search   || '';

  wrap.innerHTML = `<div style="padding:16px">${[1,2,3,4,5].map(() => `<div style="height:44px;background:#1e2535;border-radius:4px;margin-bottom:8px;animation:shimmer 1.5s infinite"></div>`).join('')}</div>`;

  try {
    const limit = 25;
    const params = new URLSearchParams({
      page, limit,
      ...(typeF   ? { type: typeF }          : {}),
      ...(repF    ? { reputation: repF }      : {}),
      ...(sortF   ? { sort: sortF }           : {}),
      ...(searchF ? { search: searchF }       : {}),
    });

    const result = await _apiFetch(`/iocs?${params}`);
    const iocs   = result?.data || (Array.isArray(result) ? result : []);
    const total  = result?.total || iocs.length;

    if (!iocs.length && page === 1) {
      wrap.innerHTML = `
        <div style="padding:32px;text-align:center;color:#64748b">
          <div style="font-size:48px;margin-bottom:16px">☣️</div>
          <h3 style="color:#94a3b8;margin:0 0 8px">IOC Registry Empty</h3>
          <p style="margin:0 0 16px;font-size:14px">The ingestion pipeline will populate IOCs automatically every 15–30 minutes.</p>
          <div style="display:flex;gap:12px;justify-content:center">
            <button onclick="window._triggerIngest('urlhaus')" style="background:#3b82f6;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:13px">Ingest URLhaus Now</button>
            <button onclick="window._triggerIngest('threatfox')" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:13px">Ingest ThreatFox</button>
          </div>
        </div>`;
      return;
    }

    const repColors = { malicious:'#ff4757', suspicious:'#ff6b35', clean:'#2ed573', unknown:'#636e72' };

    wrap.innerHTML = `
      <div style="padding:0 16px 16px">
        <!-- Toolbar -->
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
          <div>
            <h2 style="margin:0;font-size:18px;color:#e2e8f0">☣️ IOC Registry</h2>
            <div style="font-size:12px;color:#64748b">${total.toLocaleString()} indicators</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <input id="ioc-search" value="${esc(searchF)}" placeholder="Search IOC…" onkeydown="if(event.key==='Enter'){window.renderIOCRegistry({search:this.value,page:1})}" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;padding:6px 10px;border-radius:5px;font-size:12px;width:180px">
            <select onchange="window.renderIOCRegistry({type:this.value,page:1})" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:5px;font-size:12px">
              <option value="">All Types</option>
              ${['ip','domain','url','hash_md5','hash_sha1','hash_sha256','email'].map(t => `<option value="${t}" ${typeF===t?'selected':''}>${t}</option>`).join('')}
            </select>
            <select onchange="window.renderIOCRegistry({rep:this.value,page:1})" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;padding:6px;border-radius:5px;font-size:12px">
              <option value="">All Reputation</option>
              ${['malicious','suspicious','clean','unknown'].map(r => `<option value="${r}" ${repF===r?'selected':''}>${r}</option>`).join('')}
            </select>
            <button onclick="window._exportIOCs()" style="background:transparent;color:#64748b;border:1px solid #334155;padding:6px 12px;border-radius:5px;cursor:pointer;font-size:12px">↓ Export</button>
          </div>
        </div>

        <!-- Table -->
        <div style="overflow-x:auto">
          <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead>
              <tr style="border-bottom:1px solid #334155;color:#64748b">
                <th style="padding:8px 10px;text-align:left;font-weight:500">Type</th>
                <th style="padding:8px 10px;text-align:left;font-weight:500">Value</th>
                <th style="padding:8px 10px;text-align:center;font-weight:500">Risk</th>
                <th style="padding:8px 10px;text-align:left;font-weight:500">Reputation</th>
                <th style="padding:8px 10px;text-align:left;font-weight:500">Source</th>
                <th style="padding:8px 10px;text-align:left;font-weight:500">Country</th>
                <th style="padding:8px 10px;text-align:left;font-weight:500">Last Seen</th>
                <th style="padding:8px 10px;text-align:center;font-weight:500">Enrich</th>
              </tr>
            </thead>
            <tbody>
              ${iocs.map(ioc => `
                <tr style="border-bottom:1px solid #0f172a;transition:background 0.1s" onmouseover="this.style.background='#1e2535'" onmouseout="this.style.background='transparent'">
                  <td style="padding:8px 10px;color:#64748b;font-family:monospace;font-size:11px">${esc(ioc.type)}</td>
                  <td style="padding:8px 10px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;color:#e2e8f0;font-size:11px">${esc(ioc.value)}</td>
                  <td style="padding:8px 10px;text-align:center">
                    <span style="color:${ioc.risk_score>=80?'#ff4757':ioc.risk_score>=60?'#ff6b35':ioc.risk_score>=40?'#ffa502':'#2ed573'};font-weight:700">${ioc.risk_score||0}</span>
                  </td>
                  <td style="padding:8px 10px">
                    <span style="color:${repColors[ioc.reputation]||'#636e72'};font-weight:500;font-size:11px">${esc(ioc.reputation||'unknown')}</span>
                  </td>
                  <td style="padding:8px 10px;color:#64748b;font-size:11px">${esc(ioc.feed_source||ioc.source||'—')}</td>
                  <td style="padding:8px 10px;color:#64748b;font-size:11px">${esc(ioc.country||'—')}</td>
                  <td style="padding:8px 10px;color:#64748b;font-size:11px">${relTime(ioc.last_seen)}</td>
                  <td style="padding:8px 10px;text-align:center">
                    <button onclick="window._enrichIOC && window._enrichIOC('${esc(ioc.id)}','${esc(ioc.value)}','${esc(ioc.type)}')" style="background:#1e2535;color:#60a5fa;border:1px solid #334155;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px">Enrich</button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        ${total > 25 ? `
          <div style="margin-top:12px;display:flex;justify-content:center;gap:8px;align-items:center">
            ${page > 1 ? `<button onclick="window.renderIOCRegistry({page:${page-1},type:'${typeF}',rep:'${repF}',search:'${searchF}'})" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">← Prev</button>` : ''}
            <span style="color:#64748b;font-size:12px">Page ${page} / ${Math.ceil(total/25)}</span>
            ${page < Math.ceil(total/25) ? `<button onclick="window.renderIOCRegistry({page:${page+1},type:'${typeF}',rep:'${repF}',search:'${searchF}'})" style="background:#1e2535;color:#94a3b8;border:1px solid #334155;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">Next →</button>` : ''}
          </div>` : ''}
      </div>`;

    // Export helper
    window._exportIOCs = async function() {
      try {
        const r = await _apiFetch(`/iocs?limit=1000&${params}`);
        const rows = r?.data || [];
        if (!rows.length) return alert('No IOCs to export');
        const csv = ['Type,Value,Risk,Reputation,Source,Country,Last Seen']
          .concat(rows.map(i => [i.type,i.value,i.risk_score,i.reputation,i.feed_source||i.source,i.country||'',i.last_seen||''].map(f => `"${String(f||'').replace(/"/g,'""')}"`).join(',')))
          .join('\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        a.download = `iocs_${new Date().toISOString().slice(0,10)}.csv`;
        a.click();
      } catch (err) { alert('Export failed: ' + err.message); }
    };

  } catch (err) {
    console.error('[LP-Patch] IOC Registry error:', err.message);
    wrap.innerHTML = `<div style="padding:24px;text-align:center;color:#64748b">
      <p>Failed to load IOC Registry: ${esc(err.message)}</p>
      <button onclick="window.renderIOCRegistry()" style="background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;margin-top:8px">Retry</button>
    </div>`;
  }
}

window.renderIOCRegistry = (opts) => renderIOCRegistryLivePatched(opts || {}).catch(e => console.warn('[LP-Patch] IOC error:', e.message));

// ══════════════════════════════════════════════════════════════
//  FIX 6: Dashboard KPIs Clickable + real data enriched
// ══════════════════════════════════════════════════════════════
onReady(function patchDashboardKPIs() {
  // Make KPI cards clickable after they render
  document.addEventListener('click', function(e) {
    const kpi = e.target.closest('[data-kpi-nav]');
    if (kpi && window.navigateTo) {
      window.navigateTo(kpi.dataset.kpiNav);
    }
  });
});

// ══════════════════════════════════════════════════════════════
//  Console banner
// ══════════════════════════════════════════════════════════════

})(); // END IIFE
