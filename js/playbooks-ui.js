/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Playbooks UI Module v3.0
 *  Interactive playbook browser with full detail view
 * ══════════════════════════════════════════════════════════
 */
'use strict';

let _pbFilter = { cat: '', sev: '', search: '' };

/* ── Main renderer ── */
window.renderPlaybooks = function renderPlaybooks() {
  const container = document.getElementById('playbooksWrap');
  if (!container) return;

  const cats   = Object.keys(window.PLAYBOOK_CATEGORIES || {});
  const total  = (window.PLAYBOOKS_DB || []).length;

  container.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:20px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-book-open" style="color:#c9a227;margin-right:8px"></i>
        Automated Response Playbooks
      </h2>
      <div style="font-size:.78em;color:#8b949e;margin-top:2px">${total} playbooks across ${cats.length} categories</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="pb-search" placeholder="🔍 Search playbooks…" oninput="_pbSearch()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:180px"/>
      <select id="pb-cat" onchange="_pbApply()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
        <option value="">All Categories</option>
        ${cats.map(c=>`<option value="${c}">${c}</option>`).join('')}
      </select>
      <select id="pb-sev" onchange="_pbApply()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
      </select>
      <button onclick="_pbReset()"
        style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:6px;font-size:.82em;cursor:pointer">
        <i class="fas fa-redo"></i> Reset
      </button>
    </div>
  </div>

  <!-- Category summary badges -->
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:18px" id="pb-cats"></div>

  <!-- Playbook count -->
  <div id="pb-count" style="font-size:.8em;color:#8b949e;margin-bottom:12px"></div>

  <!-- Grid -->
  <div id="pb-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px"></div>
  `;

  _pbRenderCatBadges();
  _pbApply();
};

function _pbRenderCatBadges() {
  const el = document.getElementById('pb-cats');
  if (!el) return;
  const counts = {};
  (window.PLAYBOOKS_DB || []).forEach(p => { counts[p.category] = (counts[p.category] || 0) + 1; });
  el.innerHTML = Object.entries(counts).map(([cat, n]) => {
    const col = (window.PLAYBOOK_CATEGORIES || {})[cat] || '#8b949e';
    return `<span onclick="_pbFilterCat('${cat}')" style="cursor:pointer;background:${col}18;color:${col};
      border:1px solid ${col}44;padding:3px 10px;border-radius:12px;font-size:.72em;font-weight:600">
      ${cat} <span style="opacity:.7">(${n})</span></span>`;
  }).join('');
}

let _pbSearchTimer;
window._pbSearch = () => { clearTimeout(_pbSearchTimer); _pbSearchTimer = setTimeout(_pbApply, 250); };
window._pbFilterCat = (cat) => {
  const el = document.getElementById('pb-cat');
  if (el) el.value = cat;
  _pbApply();
};
window._pbReset = () => {
  _pbFilter = { cat: '', sev: '', search: '' };
  ['pb-search','pb-cat','pb-sev'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  _pbApply();
};

function _pbApply() {
  _pbFilter.cat    = document.getElementById('pb-cat')?.value    || '';
  _pbFilter.sev    = document.getElementById('pb-sev')?.value    || '';
  _pbFilter.search = document.getElementById('pb-search')?.value || '';
  _pbRenderGrid();
}
window._pbApply = _pbApply;

function _pbRenderGrid() {
  const grid = document.getElementById('pb-grid');
  const cnt  = document.getElementById('pb-count');
  if (!grid) return;

  let pbs = (window.PLAYBOOKS_DB || []);
  if (_pbFilter.cat)    pbs = pbs.filter(p => p.category === _pbFilter.cat);
  if (_pbFilter.sev)    pbs = pbs.filter(p => p.severity === _pbFilter.sev);
  if (_pbFilter.search) {
    const q = _pbFilter.search.toLowerCase();
    pbs = pbs.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      (p.tags||[]).some(t=>t.toLowerCase().includes(q))
    );
  }

  if (cnt) cnt.textContent = `Showing ${pbs.length} of ${(window.PLAYBOOKS_DB||[]).length} playbooks`;

  if (!pbs.length) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:40px;color:#8b949e">
      <i class="fas fa-search" style="font-size:2em;margin-bottom:10px;display:block;color:#30363d"></i>
      No playbooks match your filters</div>`;
    return;
  }

  grid.innerHTML = pbs.map(p => _pbCard(p)).join('');
}

function _pbCard(p) {
  const catColor = (window.PLAYBOOK_CATEGORIES || {})[p.category] || '#8b949e';
  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }[p.severity] || '#8b949e';
  return `
  <div class="pb-card" onclick="openPlaybookDetail('${p.id}')"
    style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px;cursor:pointer;
      transition:all .2s;display:flex;flex-direction:column;gap:10px"
    onmouseover="this.style.borderColor='${catColor}55';this.style.transform='translateY(-2px)'"
    onmouseout="this.style.borderColor='#21262d';this.style.transform='translateY(0)'">

    <!-- Top row: icon + badge -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
      <div style="width:42px;height:42px;border-radius:10px;background:${catColor}18;border:1px solid ${catColor}33;
        display:flex;align-items:center;justify-content:center;font-size:1.2em;color:${catColor};flex-shrink:0">
        <i class="fas ${p.icon}"></i>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end">
        <span style="background:${catColor}18;color:${catColor};border:1px solid ${catColor}33;
          padding:2px 8px;border-radius:10px;font-size:.68em;font-weight:700">${p.category}</span>
        <span style="background:${sevColor}18;color:${sevColor};border:1px solid ${sevColor}33;
          padding:1px 7px;border-radius:8px;font-size:.66em;font-weight:600;text-transform:uppercase">${p.severity}</span>
      </div>
    </div>

    <!-- Title & desc -->
    <div>
      <div style="font-size:.88em;font-weight:700;color:#e6edf3;line-height:1.4;margin-bottom:4px">${_escPb(p.name)}</div>
      <div style="font-size:.76em;color:#8b949e;line-height:1.5">${_escPb(p.description.slice(0,90))}${p.description.length>90?'…':''}</div>
    </div>

    <!-- Stats row -->
    <div style="display:flex;gap:12px;font-size:.72em;color:#8b949e">
      <span><i class="fas fa-list-ol" style="color:#3b82f6;margin-right:3px"></i>${p.steps} steps</span>
      <span><i class="fas fa-th" style="color:#8b5cf6;margin-right:3px"></i>${p.ttps} TTPs</span>
      <span style="margin-left:auto;color:#c9a227"><i class="fas fa-bolt" style="margin-right:3px"></i>Auto</span>
    </div>

    <!-- Tags -->
    <div style="display:flex;flex-wrap:wrap;gap:4px">
      ${(p.tags||[]).slice(0,4).map(t=>`<span style="background:#1e2d3d;color:#8b949e;padding:1px 6px;
        border-radius:4px;font-size:.67em;font-family:monospace">${_escPb(t)}</span>`).join('')}
    </div>

    <!-- Trigger -->
    <div style="font-size:.7em;color:#8b949e;border-top:1px solid #21262d;padding-top:8px">
      <i class="fas fa-bolt" style="color:#c9a227;margin-right:4px"></i>
      <span style="color:#e6edf3">Trigger:</span> ${_escPb(p.trigger)}
    </div>

    <!-- Action icons -->
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button onclick="event.stopPropagation();openPlaybookDetail('${p.id}')"
        style="background:#1d6ae520;color:#3b82f6;border:1px solid #1d6ae533;padding:4px 10px;
          border-radius:6px;font-size:.72em;cursor:pointer">
        <i class="fas fa-play" style="margin-right:4px"></i>Run</button>
      <button onclick="event.stopPropagation();_pbExport('${p.id}')"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px 10px;
          border-radius:6px;font-size:.72em;cursor:pointer">
        <i class="fas fa-download"></i></button>
    </div>
  </div>`;
}

/* ── Detail modal ── */
window.openPlaybookDetail = function(id) {
  const p = (window.PLAYBOOKS_DB || []).find(x => x.id === id);
  if (!p) return;
  const modal = document.getElementById('playbookModal');
  const body  = document.getElementById('playbookModalBody');
  if (!modal || !body) return;

  const catColor = (window.PLAYBOOK_CATEGORIES || {})[p.category] || '#8b949e';
  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }[p.severity] || '#8b949e';

  body.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid #21262d">
    <div style="width:56px;height:56px;border-radius:12px;background:${catColor}18;border:1px solid ${catColor}33;
      display:flex;align-items:center;justify-content:center;font-size:1.5em;color:${catColor};flex-shrink:0">
      <i class="fas ${p.icon}"></i>
    </div>
    <div style="flex:1">
      <div style="font-size:1.05em;font-weight:700;color:#e6edf3;margin-bottom:4px">${_escPb(p.name)}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px">
        <span style="background:${catColor}18;color:${catColor};border:1px solid ${catColor}33;padding:2px 8px;border-radius:8px;font-size:.72em;font-weight:700">${p.category}</span>
        <span style="background:${sevColor}18;color:${sevColor};border:1px solid ${sevColor}33;padding:2px 8px;border-radius:8px;font-size:.72em;font-weight:700;text-transform:uppercase">${p.severity}</span>
        <span style="background:#1e2d3d;color:#8b949e;padding:2px 8px;border-radius:8px;font-size:.72em">${p.steps} steps · ${p.ttps} TTPs</span>
      </div>
      <div style="font-size:.82em;color:#8b949e;line-height:1.6">${_escPb(p.description)}</div>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px">
      <button onclick="_pbExport('${p.id}')"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:6px 12px;border-radius:6px;font-size:.78em;cursor:pointer;white-space:nowrap">
        <i class="fas fa-download" style="margin-right:4px"></i>Export JSON</button>
    </div>
  </div>

  <!-- Trigger -->
  <div style="background:#0a1628;border:1px solid #1e2d3d;border-left:3px solid #c9a227;border-radius:8px;padding:10px 14px;margin-bottom:18px;font-size:.8em">
    <strong style="color:#c9a227"><i class="fas fa-bolt" style="margin-right:6px"></i>Trigger Condition:</strong>
    <span style="color:#e6edf3;margin-left:6px">${_escPb(p.trigger)}</span>
  </div>

  <!-- Two column layout -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px">

    <!-- Steps -->
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:16px">
      <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:12px">
        <i class="fas fa-list-ol" style="color:#3b82f6;margin-right:6px"></i>Response Steps
      </div>
      <ol style="list-style:none;margin:0;padding:0">
        ${(p.steps_detail||[]).map((step, i) => `
        <li style="display:flex;gap:10px;padding:7px 0;border-bottom:1px solid #1a2030;align-items:flex-start">
          <span style="flex-shrink:0;width:22px;height:22px;background:${catColor}18;border:1px solid ${catColor}33;
            color:${catColor};border-radius:50%;font-size:.7em;font-weight:700;display:flex;align-items:center;justify-content:center">${i+1}</span>
          <span style="font-size:.78em;color:#e6edf3;line-height:1.5">${_escPb(step)}</span>
        </li>`).join('')}
      </ol>
    </div>

    <!-- MITRE + Tags -->
    <div style="display:flex;flex-direction:column;gap:12px">
      <!-- MITRE techniques -->
      <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:16px">
        <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:10px">
          <i class="fas fa-th" style="color:#8b5cf6;margin-right:6px"></i>MITRE ATT&CK Techniques
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${(p.mitre_techniques||[]).map(t=>`
          <span style="background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);color:#8b5cf6;
            padding:3px 10px;border-radius:6px;font-family:monospace;font-size:.75em;cursor:pointer"
            onclick="window.open('https://attack.mitre.org/techniques/${t.replace('.','/')}','_blank')">${_escPb(t)}</span>`).join('')}
        </div>
      </div>

      <!-- Tags -->
      <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:16px">
        <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:10px">
          <i class="fas fa-tags" style="color:#c9a227;margin-right:6px"></i>Tags
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${(p.tags||[]).map(t=>`<span style="background:#1e2d3d;color:#8b949e;padding:3px 8px;
            border-radius:4px;font-size:.75em;font-family:monospace">${_escPb(t)}</span>`).join('')}
        </div>
      </div>

      <!-- Action buttons -->
      <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:10px;padding:16px">
        <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:10px">
          <i class="fas fa-rocket" style="color:#22c55e;margin-right:6px"></i>Actions
        </div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <button style="background:rgba(29,106,229,.15);color:#3b82f6;border:1px solid rgba(29,106,229,.3);
            padding:8px 14px;border-radius:6px;font-size:.8em;cursor:pointer;text-align:left"
            onclick="if(window.showToast)showToast('Playbook execution queued','success')">
            <i class="fas fa-play" style="margin-right:6px"></i>Execute Playbook
          </button>
          <button style="background:rgba(200,162,39,.1);color:#c9a227;border:1px solid rgba(200,162,39,.3);
            padding:8px 14px;border-radius:6px;font-size:.8em;cursor:pointer;text-align:left"
            onclick="if(window.showToast)showToast('Opening AI analysis…','info');if(window.navigateTo)setTimeout(()=>navigateTo('ai-orchestrator'),200)">
            <i class="fas fa-robot" style="margin-right:6px"></i>Analyze with AI Orchestrator
          </button>
          <button style="background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);
            padding:8px 14px;border-radius:6px;font-size:.8em;cursor:pointer;text-align:left"
            onclick="_pbExport('${p.id}')">
            <i class="fas fa-file-export" style="margin-right:6px"></i>Export as JSON / STIX
          </button>
        </div>
      </div>
    </div>
  </div>`;

  modal.classList.add('active');
};

/* ── Export playbook ── */
window._pbExport = function(id) {
  const p = (window.PLAYBOOKS_DB || []).find(x => x.id === id);
  if (!p) return;
  const blob = new Blob([JSON.stringify(p, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `playbook_${p.id}.json`; a.click();
  URL.revokeObjectURL(url);
  if (window.showToast) showToast('Playbook exported', 'success');
};

/* ── Utility ── */
function _escPb(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
