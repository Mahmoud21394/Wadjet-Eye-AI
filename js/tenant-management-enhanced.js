/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Tenant & RBAC Management Enhanced v2.0
 *  Functional add/delete/modify tenants via real API
 *  RBAC with permission import/export, role matrix
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── API Helpers ── */
async function _tenantFetch(path, opts = {}) {
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const token = localStorage.getItem('wadjet_access_token')
             || localStorage.getItem('we_access_token')
             || localStorage.getItem('tp_access_token')
             || sessionStorage.getItem('tp_token') || '';

  if (window.authFetch) {
    try { return await window.authFetch(path, opts); } catch(e) {
      if (!e.message?.includes('401')) throw e;
    }
  }

  const r = await fetch(`${base}/api${path}`, {
    method: opts.method || 'GET',
    headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
    credentials: 'include',
    ...(opts.body ? { body: typeof opts.body==='string' ? opts.body : JSON.stringify(opts.body) } : {}),
  });
  if (r.status === 204) return {};
  if (!r.ok) {
    const txt = await r.text().catch(()=>'');
    let msg = `HTTP ${r.status}`;
    try { const j=JSON.parse(txt); msg=j.error||j.message||msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
}

function _tEsc(s) {
  if (s==null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── Tenant color palette ── */
const _TENANT_COLORS = [
  '#22d3ee','#3b82f6','#8b5cf6','#ec4899','#f97316',
  '#22c55e','#eab308','#ef4444','#06b6d4','#a855f7',
];

/* ── Plans for tenant creation ── */
const _TENANT_PLANS = ['Starter', 'Professional', 'Enterprise'];

/* ── State ── */
const _TM = {
  tenants: [],
  loading: false,
  search:  '',
};

/* ══════════════════════════════════════════════════════
   TENANT MANAGEMENT RENDERER
══════════════════════════════════════════════════════ */
window.renderTenantManagement = function() {
  const wrap = document.getElementById('customersWrap')
            || document.getElementById('page-customers')
            || document.getElementById('customersLiveContainer');
  if (!wrap) return;

  wrap.innerHTML = `
  <!-- Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700">
          <i class="fas fa-building" style="color:#22d3ee;margin-right:8px"></i>Tenant Management
        </h2>
        <div style="font-size:.76em;color:#8b949e;margin-top:2px">Create, modify, and manage client tenants and their configurations</div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="enh-btn enh-btn--primary enh-btn--sm" onclick="_tmShowCreateModal()">
          <i class="fas fa-plus"></i> Add Tenant
        </button>
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_tmRefresh()">
          <i class="fas fa-sync-alt" id="tm-refresh-icon"></i> Refresh
        </button>
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_tmExportAll()">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>
  </div>

  <div style="padding:16px">
    <!-- KPIs -->
    <div id="tm-kpis" class="enh-kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(150px,1fr));margin-bottom:16px">
      ${_tmSkel(1,'60px')}
    </div>

    <!-- Search -->
    <div class="enh-filter-bar" style="margin-bottom:16px">
      <div style="position:relative;flex:1">
        <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#4b5563;font-size:.8em;pointer-events:none"></i>
        <input class="enh-input" style="padding-left:30px;width:100%;box-sizing:border-box" id="tm-search"
          placeholder="Search tenants by name, plan, contact…" oninput="_tmFilter()" />
      </div>
      <select class="enh-select" id="tm-plan-filter" onchange="_tmFilter()">
        <option value="">All Plans</option>
        ${_TENANT_PLANS.map(p=>`<option value="${p}">${p}</option>`).join('')}
      </select>
      <select class="enh-select" id="tm-status-filter" onchange="_tmFilter()">
        <option value="">All Status</option>
        <option value="active">Active</option>
        <option value="inactive">Inactive</option>
        <option value="trial">Trial</option>
      </select>
    </div>

    <!-- Tenant Grid -->
    <div id="tm-grid">${_tmSkel(6)}</div>
  </div>

  <!-- Create/Edit Modal -->
  <div id="tm-modal-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);
    backdrop-filter:blur(4px);z-index:9500;display:none;align-items:center;justify-content:center">
    <div id="tm-modal" style="background:#080c14;border:1px solid rgba(34,211,238,.2);border-radius:16px;
      width:min(560px,95vw);max-height:90vh;overflow-y:auto;animation:enh-scaleIn .25s ease;
      box-shadow:0 24px 80px rgba(0,0,0,.8)">
      <div id="tm-modal-body"></div>
    </div>
  </div>
  `;

  _tmLoad();
};

function _tmSkel(n=6, h='100px') {
  return Array(n).fill(`<div style="height:${h};background:linear-gradient(90deg,#0d1421 25%,#131b2a 50%,#0d1421 75%);
    background-size:200% 100%;animation:enh-shimmer 1.4s infinite;border-radius:12px;margin-bottom:8px"></div>`).join('');
}

/* ── Load tenants ── */
async function _tmLoad() {
  _TM.loading = true;
  try {
    const data = await _tenantFetch('/tenants');
    _TM.tenants = data?.data || data || [];
    if (!_TM.tenants.length) {
      // Use ARGUS_DATA as fallback
      _TM.tenants = (window.ARGUS_DATA?.tenants || []).map((t, i) => ({
        id: t.id || `T${String(i+1).padStart(3,'0')}`,
        name: t.name,
        short_name: t.short || t.name.toLowerCase().replace(/\s+/g,'-'),
        plan: t.plan || 'Professional',
        status: 'active',
        user_count: t.users || Math.floor(Math.random()*20)+2,
        ioc_count: t.iocs || Math.floor(Math.random()*5000)+100,
        created_at: t.created || new Date(Date.now() - Math.random()*365*24*60*60*1000).toISOString(),
        risk_level: t.risk || 'MEDIUM',
        contact: t.contact || '',
        color: _TENANT_COLORS[i % _TENANT_COLORS.length],
      }));
    }
    _tmRenderKPIs(_TM.tenants);
    _tmRenderGrid(_TM.tenants);
  } catch {
    const grid = document.getElementById('tm-grid');
    if (grid) grid.innerHTML = `<div style="text-align:center;padding:40px;color:#8b949e">
      <i class="fas fa-exclamation-triangle" style="display:block;margin-bottom:10px;font-size:2em;color:#ef4444"></i>
      Failed to load tenants. Check your connection.
      <br><button onclick="_tmLoad()" class="enh-btn enh-btn--ghost enh-btn--sm" style="margin-top:12px">Retry</button>
    </div>`;
  } finally { _TM.loading = false; }
}

function _tmRenderKPIs(tenants) {
  const el = document.getElementById('tm-kpis');
  if (!el) return;
  const active = tenants.filter(t => t.status === 'active' || !t.status).length;
  const trial  = tenants.filter(t => t.status === 'trial').length;
  const totalUsers = tenants.reduce((s,t) => s+(t.user_count||0), 0);
  const enterprise = tenants.filter(t => (t.plan||'').toLowerCase() === 'enterprise').length;

  el.innerHTML = [
    {label:'Total Tenants',  val:tenants.length, icon:'fa-building',  color:'#22d3ee'},
    {label:'Active',         val:active,         icon:'fa-check',     color:'#22c55e'},
    {label:'Trial',          val:trial,          icon:'fa-clock',     color:'#eab308'},
    {label:'Enterprise',     val:enterprise,     icon:'fa-star',      color:'#f97316'},
    {label:'Total Users',    val:totalUsers,     icon:'fa-users',     color:'#a855f7'},
  ].map((k,i) => `
    <div class="enh-kpi-card enh-stagger-${i+1}" style="--enh-accent:${k.color}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <div style="width:28px;height:28px;background:${k.color}18;border-radius:7px;display:flex;align-items:center;justify-content:center">
          <i class="fas ${k.icon}" style="color:${k.color};font-size:.75em"></i>
        </div>
      </div>
      <div class="enh-kpi-val">${k.val}</div>
      <div class="enh-kpi-label" style="font-size:.72em">${k.label}</div>
    </div>`).join('');
}

function _tmRenderGrid(tenants) {
  const grid = document.getElementById('tm-grid');
  if (!grid) return;

  if (!tenants.length) {
    grid.innerHTML = `<div style="text-align:center;padding:48px;color:#8b949e">
      <i class="fas fa-building fa-2x" style="display:block;margin-bottom:12px;opacity:.2"></i>
      No tenants found. Click "Add Tenant" to create your first client.
    </div>`;
    return;
  }

  grid.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
    ${tenants.map((t, i) => {
      const color = t.color || _TENANT_COLORS[i % _TENANT_COLORS.length];
      const initials = (t.name||'?').split(' ').slice(0,2).map(w=>w[0]).join('').toUpperCase();
      const status = t.status || 'active';
      const planLower = (t.plan||'professional').toLowerCase();
      return `
      <div class="tenant-card enh-stagger-${Math.min(i+1,6)}" style="--tenant-accent:${color}">
        <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
          <div class="tenant-avatar" style="background:${color}18;border:1px solid ${color}30;color:${color}">${initials}</div>
          <div style="flex:1;min-width:0">
            <div style="font-size:.92em;font-weight:700;color:#e6edf3;margin-bottom:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_tEsc(t.name)}</div>
            <div style="font-size:.76em;color:#8b949e;font-family:monospace;margin-bottom:5px">${_tEsc(t.short_name||t.id)}</div>
            <div style="display:flex;gap:5px;align-items:center;flex-wrap:wrap">
              <span class="tenant-plan-badge tenant-plan-badge--${planLower}">${_tEsc(t.plan||'Professional')}</span>
              <span class="enh-badge ${status==='active'?'enh-badge--online':status==='trial'?'enh-badge--medium':'enh-badge--offline'}">
                ${status==='active'?'<span class="enh-dot enh-dot--online"></span>':''}${status.toUpperCase()}
              </span>
            </div>
          </div>
          <div class="tenant-actions">
            <button class="enh-btn enh-btn--ghost enh-btn--icon enh-btn--sm" onclick="_tmEdit('${_tEsc(t.id)}')" title="Edit">
              <i class="fas fa-edit" style="font-size:.8em"></i>
            </button>
            <button class="enh-btn enh-btn--ghost enh-btn--icon enh-btn--sm" onclick="_tmDeleteConfirm('${_tEsc(t.id)}','${_tEsc(t.name)}')" title="Delete" style="color:#ef4444">
              <i class="fas fa-trash" style="font-size:.8em"></i>
            </button>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
          <div style="background:rgba(255,255,255,.04);padding:7px 10px;border-radius:7px">
            <div style="font-size:.68em;color:#8b949e">Users</div>
            <div style="font-size:.9em;font-weight:700;color:#e6edf3">${t.user_count||0}</div>
          </div>
          <div style="background:rgba(255,255,255,.04);padding:7px 10px;border-radius:7px">
            <div style="font-size:.68em;color:#8b949e">IOCs</div>
            <div style="font-size:.9em;font-weight:700;color:#22d3ee">${(t.ioc_count||0).toLocaleString()}</div>
          </div>
          <div style="background:rgba(255,255,255,.04);padding:7px 10px;border-radius:7px">
            <div style="font-size:.68em;color:#8b949e">Risk</div>
            <div style="font-size:.82em;font-weight:700;color:${t.risk_level==='HIGH'||t.risk_level==='CRITICAL'?'#ef4444':t.risk_level==='MEDIUM'?'#f97316':'#22c55e'}">${t.risk_level||'LOW'}</div>
          </div>
          <div style="background:rgba(255,255,255,.04);padding:7px 10px;border-radius:7px">
            <div style="font-size:.68em;color:#8b949e">Since</div>
            <div style="font-size:.8em;color:#8b949e">${t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}</div>
          </div>
        </div>
        ${t.contact ? `<div style="font-size:.74em;color:#6b7280"><i class="fas fa-envelope" style="margin-right:5px"></i>${_tEsc(t.contact)}</div>` : ''}
        <div style="display:flex;gap:6px;margin-top:8px">
          <button class="enh-btn enh-btn--ghost enh-btn--sm" style="flex:1;justify-content:center" onclick="_tmViewDetails('${_tEsc(t.id)}')">
            <i class="fas fa-chart-bar"></i> Details
          </button>
          <button class="enh-btn enh-btn--cyan enh-btn--sm" onclick="_tmEdit('${_tEsc(t.id)}')">
            <i class="fas fa-edit"></i> Edit
          </button>
        </div>
      </div>`;
    }).join('')}
  </div>`;
}

/* ── Filter ── */
window._tmFilter = function() {
  const search = document.getElementById('tm-search')?.value?.toLowerCase() || '';
  const plan   = document.getElementById('tm-plan-filter')?.value || '';
  const status = document.getElementById('tm-status-filter')?.value || '';

  let filtered = _TM.tenants;
  if (search) filtered = filtered.filter(t =>
    (t.name+t.short_name+t.contact+t.plan).toLowerCase().includes(search));
  if (plan)   filtered = filtered.filter(t => (t.plan||'').toLowerCase() === plan.toLowerCase());
  if (status) filtered = filtered.filter(t => (t.status||'active') === status);

  _tmRenderGrid(filtered);
};

/* ── Create modal ── */
window._tmShowCreateModal = function(tenant = null) {
  const overlay = document.getElementById('tm-modal-overlay');
  const body    = document.getElementById('tm-modal-body');
  if (!overlay || !body) return;

  const isEdit  = !!tenant;
  const t = tenant || {};
  const colorIdx = Math.floor(Math.random() * _TENANT_COLORS.length);
  const defaultColor = t.color || _TENANT_COLORS[colorIdx];

  body.innerHTML = `
    <div style="padding:20px 24px;border-bottom:1px solid #1a2535;display:flex;align-items:center;gap:10px">
      <i class="fas ${isEdit?'fa-edit':'fa-plus'}" style="color:#22d3ee"></i>
      <h3 style="margin:0;color:#e6edf3;font-size:.95em;font-weight:700">${isEdit?'Edit':'Create'} Tenant</h3>
      <button onclick="_tmCloseModal()" class="enh-btn enh-btn--ghost enh-btn--sm" style="margin-left:auto">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div style="padding:20px 24px">
      <div id="tm-modal-status"></div>
      <div style="display:grid;gap:14px">
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Tenant Name *</label>
          <input id="tm-new-name" class="enh-input" style="width:100%;box-sizing:border-box"
            placeholder="ACME Security Corp" value="${_tEsc(t.name||'')}" maxlength="100" />
        </div>
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Short Name / Slug</label>
          <input id="tm-new-slug" class="enh-input" style="width:100%;box-sizing:border-box;font-family:monospace"
            placeholder="acme-security" value="${_tEsc(t.short_name||t.short||'')}" maxlength="50"
            oninput="this.value=this.value.toLowerCase().replace(/[^a-z0-9-]/g,'-')" />
        </div>
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Subscription Plan</label>
          <select id="tm-new-plan" class="enh-select" style="width:100%">
            ${_TENANT_PLANS.map(p=>`<option value="${p}" ${t.plan===p?'selected':''}>${p}</option>`).join('')}
          </select>
        </div>
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Contact Email</label>
          <input id="tm-new-contact" type="email" class="enh-input" style="width:100%;box-sizing:border-box"
            placeholder="admin@company.com" value="${_tEsc(t.contact||t.contact_email||'')}" />
        </div>
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Status</label>
          <select id="tm-new-status" class="enh-select" style="width:100%">
            <option value="active" ${(!t.status||t.status==='active')?'selected':''}>Active</option>
            <option value="trial" ${t.status==='trial'?'selected':''}>Trial</option>
            <option value="inactive" ${t.status==='inactive'?'selected':''}>Inactive</option>
          </select>
        </div>
        <div>
          <label style="font-size:.82em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Accent Color</label>
          <div style="display:flex;gap:6px;flex-wrap:wrap" id="tm-color-picker">
            ${_TENANT_COLORS.map(c=>`
              <div onclick="_tmSelectColor('${c}')"
                style="width:28px;height:28px;background:${c};border-radius:6px;cursor:pointer;
                  border:2px solid ${c===defaultColor?'#fff':'transparent'};transition:border-color .15s;flex-shrink:0"
                id="tm-color-${c.replace('#','')}" title="${c}"></div>`).join('')}
          </div>
          <input type="hidden" id="tm-new-color" value="${defaultColor}" />
        </div>
      </div>

      <div style="display:flex;gap:8px;margin-top:20px;justify-content:flex-end">
        <button onclick="_tmCloseModal()" class="enh-btn enh-btn--ghost">Cancel</button>
        <button onclick="_tmSaveTenant(${isEdit?`'${_tEsc(t.id)}'`:'null'})"
          class="enh-btn enh-btn--primary">
          <i class="fas ${isEdit?'fa-save':'fa-plus'}"></i>
          ${isEdit ? 'Save Changes' : 'Create Tenant'}
        </button>
      </div>
    </div>
  `;

  overlay.style.display = 'flex';
};

window._tmSelectColor = function(color) {
  document.querySelectorAll('#tm-color-picker > div').forEach(d => d.style.borderColor = 'transparent');
  const sel = document.getElementById(`tm-color-${color.replace('#','')}`);
  if (sel) sel.style.borderColor = '#fff';
  const inp = document.getElementById('tm-new-color');
  if (inp) inp.value = color;
};

window._tmCloseModal = function() {
  const o = document.getElementById('tm-modal-overlay');
  if (o) o.style.display = 'none';
};

window._tmEdit = function(id) {
  const tenant = _TM.tenants.find(t => t.id === id);
  if (tenant) _tmShowCreateModal(tenant);
};

window._tmSaveTenant = async function(existingId) {
  const name    = document.getElementById('tm-new-name')?.value?.trim();
  const slug    = document.getElementById('tm-new-slug')?.value?.trim();
  const plan    = document.getElementById('tm-new-plan')?.value;
  const contact = document.getElementById('tm-new-contact')?.value?.trim();
  const status  = document.getElementById('tm-new-status')?.value;
  const color   = document.getElementById('tm-new-color')?.value || '#22d3ee';

  const statusEl = document.getElementById('tm-modal-status');

  if (!name) {
    if (statusEl) statusEl.innerHTML = `<div class="settings-status settings-status--error" style="display:flex;margin-bottom:12px"><i class="fas fa-times"></i> Tenant name is required</div>`;
    return;
  }

  const payload = { name, short_name: slug||name.toLowerCase().replace(/\s+/g,'-'), plan, contact_email:contact, status, color };

  try {
    let result;
    if (existingId) {
      result = await _tenantFetch(`/tenants/${existingId}`, { method:'PATCH', body:payload });
      const idx = _TM.tenants.findIndex(t => t.id === existingId);
      if (idx >= 0) _TM.tenants[idx] = { ..._TM.tenants[idx], ...payload, ...result };
    } else {
      result = await _tenantFetch('/tenants', { method:'POST', body:payload });
      _TM.tenants.push({ id:result?.id||'new-'+Date.now(), ...payload, user_count:0, ioc_count:0, ...result });
    }

    // Also update ARGUS_DATA for compatibility
    if (window.ARGUS_DATA?.tenants) {
      if (existingId) {
        const idx = ARGUS_DATA.tenants.findIndex(t=>t.id===existingId);
        if (idx>=0) ARGUS_DATA.tenants[idx] = {...ARGUS_DATA.tenants[idx], ...payload};
      } else {
        ARGUS_DATA.tenants.push({id:result?.id||'new-'+Date.now(),...payload,short:slug,users:0,risk:'LOW'});
      }
    }

    _tmCloseModal();
    _tmRenderKPIs(_TM.tenants);
    _tmRenderGrid(_TM.tenants);
    if (typeof showToast==='function') showToast(existingId?'✅ Tenant updated':'✅ Tenant created','success');
  } catch(err) {
    if (statusEl) statusEl.innerHTML = `<div class="settings-status settings-status--error" style="display:flex;margin-bottom:12px">
      <i class="fas fa-exclamation-triangle"></i> ${_tEsc(err.message)}</div>`;
  }
};

window._tmDeleteConfirm = function(id, name) {
  if (!confirm(`⚠️ Delete tenant "${name}"?\n\nThis will permanently delete all tenant data including users, IOCs, and findings. This action CANNOT be undone.`)) return;
  _tmDelete(id, name);
};

async function _tmDelete(id, name) {
  try {
    await _tenantFetch(`/tenants/${id}`, { method:'DELETE' });
    _TM.tenants = _TM.tenants.filter(t => t.id !== id);
    if (window.ARGUS_DATA?.tenants) ARGUS_DATA.tenants = ARGUS_DATA.tenants.filter(t=>t.id!==id);
    _tmRenderKPIs(_TM.tenants);
    _tmRenderGrid(_TM.tenants);
    if (typeof showToast==='function') showToast(`🗑️ Tenant "${name}" deleted`,'success');
  } catch(err) {
    if (typeof showToast==='function') showToast(`❌ Delete failed: ${err.message}`,'error');
  }
}

window._tmViewDetails = function(id) {
  const t = _TM.tenants.find(t=>t.id===id);
  if (!t) return;
  if (typeof showToast==='function') showToast(`📊 Opening details for ${t.name}…`,'info');
  // TODO: Navigate to tenant detail page
};

window._tmRefresh = function() {
  const icon = document.getElementById('tm-refresh-icon');
  if (icon) { icon.style.animation='enh-spin .8s linear infinite'; setTimeout(()=>icon.style.animation='',1200); }
  _tmLoad();
};

window._tmExportAll = function() {
  const blob = new Blob([JSON.stringify(_TM.tenants, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`tenants-export-${new Date().toISOString().slice(0,10)}.json`; a.click();
  if (typeof showToast==='function') showToast('📊 Tenants exported','success');
};

/* ══════════════════════════════════════════════════════
   RBAC ENHANCED — Permission Import/Export
══════════════════════════════════════════════════════ */
window.exportRBACPermissions = function() {
  const roles = window.RBAC_STORE?.roles || [];
  const exportData = {
    version: '2.0',
    exported: new Date().toISOString(),
    platform: 'EYEbot AI',
    roles: roles.map(r => ({
      id: r.id, name: r.name, slug: r.slug,
      permissions: r.permissions, modules: r.modules,
    }))
  };
  const blob = new Blob([JSON.stringify(exportData, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`rbac-permissions-${new Date().toISOString().slice(0,10)}.json`; a.click();
  if (typeof showToast==='function') showToast('📋 RBAC permissions exported','success');
};

window.importRBACPermissions = function() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = '.json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (!data.roles?.length) throw new Error('Invalid format: no roles found');
        if (window.RBAC_STORE) {
          data.roles.forEach(imported => {
            const existing = RBAC_STORE.roles.find(r => r.slug === imported.slug);
            if (existing) {
              existing.permissions = imported.permissions;
              existing.modules     = imported.modules;
            }
          });
        }
        if (typeof showToast==='function') showToast(`✅ Imported ${data.roles.length} role configurations`,'success');
        // Refresh RBAC UI if visible
        if (typeof window.renderRBAC === 'function') window.renderRBAC();
      } catch(err) {
        if (typeof showToast==='function') showToast(`❌ Import failed: ${err.message}`,'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
};
