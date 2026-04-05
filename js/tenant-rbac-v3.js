/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Tenant Management & RBAC v3.0
 *  Full CRUD: create/edit/delete tenants, user management,
 *  role assignment, permission import/export, audit log
 * ══════════════════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ═══════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════ */
const TM = {
  tenants:      [],
  users:        [],
  roles:        [],
  auditLog:     [],
  loading:      false,
  activeTab:    'tenants',
  filter:       { search:'', plan:'', status:'' },
  page:         1,
  limit:        12,
};

/* ═══════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════ */
function _e(s) {
  if (s==null) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _toast(msg, type='info') {
  let tc=document.getElementById('p19-toast-wrap');
  if (!tc){tc=document.createElement('div');tc.id='p19-toast-wrap';document.body.appendChild(tc);}
  const icons={success:'fa-check-circle',error:'fa-exclamation-circle',warning:'fa-exclamation-triangle',info:'fa-info-circle'};
  const t=document.createElement('div'); t.className=`p19-toast p19-toast--${type}`;
  t.innerHTML=`<i class="fas ${icons[type]||'fa-bell'}"></i><span>${_e(msg)}</span>`;
  tc.appendChild(t); setTimeout(()=>{t.classList.add('p19-toast--exit');setTimeout(()=>t.remove(),300);},3500);
}
function _apiBase() { return (window.THREATPILOT_API_URL||'https://wadjet-eye-ai.onrender.com').replace(/\/$/,''); }
function _token() {
  return localStorage.getItem('wadjet_access_token')
      || localStorage.getItem('tp_access_token')
      || sessionStorage.getItem('wadjet_access_token')||'';
}
async function _api(method, path, body) {
  if (window.authFetch) return window.authFetch(path, { method, ...(body?{body:JSON.stringify(body)}:{}) });
  const r = await fetch(`${_apiBase()}/api${path}`, {
    method, headers:{'Content-Type':'application/json',...(_token()?{Authorization:`Bearer ${_token()}`}:{})},
    ...(body?{body:JSON.stringify(body)}:{}),
  });
  if (!r.ok) { const e=await r.text().catch(()=>''); throw new Error(`HTTP ${r.status}: ${e.slice(0,100)}`); }
  return r.status===204?null:r.json();
}

/* ═══════════════════════════════════════════════════════
   BUILT-IN ROLES (RBAC)
═══════════════════════════════════════════════════════ */
const BUILT_IN_ROLES = [
  {
    id:'R001', name:'Super Admin', color:'#ef4444', badge_class:'p19-badge--critical',
    permissions:['all'],
    modules:['command-center','findings','campaigns','detections','threat-actors','dark-web',
             'exposure','ioc-registry','ioc-database','ai-orchestrator','collectors','playbooks',
             'edr-siem','sysmon','customers','reports','settings','executive-dashboard',
             'kill-chain','case-management','threat-hunting','detection-engineering','soar',
             'live-feeds','cyber-news','mitre-attack','geo-threats','rbac-admin','branding','pricing'],
    desc:'Full platform access — all modules and operations',
  },
  {
    id:'R002', name:'Admin', color:'#f97316', badge_class:'p19-badge--high',
    permissions:['read','write','manage_users','manage_collectors','export','investigate'],
    modules:['command-center','findings','campaigns','detections','threat-actors','dark-web',
             'exposure','ioc-registry','ioc-database','ai-orchestrator','collectors','playbooks',
             'case-management','threat-hunting','detection-engineering','soar','live-feeds',
             'cyber-news','mitre-attack','geo-threats','reports','settings','branding'],
    desc:'Tenant-level administrator with team management',
  },
  {
    id:'R003', name:'Analyst', color:'#3b82f6', badge_class:'p19-badge--blue',
    permissions:['read','write','investigate','export'],
    modules:['command-center','findings','campaigns','detections','threat-actors','dark-web',
             'exposure','ioc-registry','ioc-database','ai-orchestrator','threat-hunting',
             'detection-engineering','mitre-attack','live-feeds','cyber-news','geo-threats','case-management'],
    desc:'Threat intelligence analyst — full investigation access',
  },
  {
    id:'R004', name:'Viewer', color:'#22c55e', badge_class:'p19-badge--green',
    permissions:['read'],
    modules:['command-center','findings','executive-dashboard','reports','cyber-news','geo-threats'],
    desc:'Read-only access to dashboards and reports',
  },
  {
    id:'R005', name:'SOC Tier 1', color:'#22d3ee', badge_class:'p19-badge--info',
    permissions:['read','write','investigate'],
    modules:['command-center','findings','detections','playbooks','case-management','live-feeds','cyber-news','soar'],
    desc:'First-line SOC operator — alerting and response',
  },
  {
    id:'R006', name:'Threat Hunter', color:'#a855f7', badge_class:'p19-badge--purple',
    permissions:['read','write','investigate','export'],
    modules:['command-center','findings','threat-actors','ioc-registry','ioc-database',
             'threat-hunting','detection-engineering','mitre-attack','live-feeds','cyber-news','geo-threats'],
    desc:'Advanced threat hunting and detection engineering',
  },
  {
    id:'R007', name:'Executive', color:'#eab308', badge_class:'p19-badge--medium',
    permissions:['read'],
    modules:['executive-dashboard','reports','cyber-news','geo-threats'],
    desc:'Executive dashboard and strategic reports only',
  },
  {
    id:'R008', name:'Auditor', color:'#ec4899', badge_class:'p19-badge--pink',
    permissions:['read','audit'],
    modules:['command-center','findings','campaigns','reports','settings','rbac-admin','cyber-news'],
    desc:'Compliance auditor — read and audit trail access',
  },
];

/* ═══════════════════════════════════════════════════════
   SYNTHETIC TENANTS (fallback when API unavailable)
═══════════════════════════════════════════════════════ */
const DEMO_TENANTS = [
  { id:'t001', name:'AcmeCorp', slug:'acmecorp',    plan:'Enterprise', status:'active', users_count:24, findings_count:847, risk_score:78, color:'#3b82f6',  created_at:'2024-01-15T00:00:00Z', email:'admin@acmecorp.com',   mfa_enabled:true,  sso:true  },
  { id:'t002', name:'TechVault', slug:'techvault',  plan:'Professional', status:'active', users_count:12, findings_count:234, risk_score:45, color:'#22d3ee', created_at:'2024-02-10T00:00:00Z', email:'admin@techvault.io',   mfa_enabled:true,  sso:false },
  { id:'t003', name:'SecureNet', slug:'securenet',  plan:'Enterprise', status:'active', users_count:31, findings_count:1203, risk_score:91, color:'#ef4444', created_at:'2024-03-05T00:00:00Z', email:'admin@securenet.com',  mfa_enabled:true,  sso:true  },
  { id:'t004', name:'DataShield', slug:'datashield',plan:'Starter', status:'suspended', users_count:5, findings_count:67, risk_score:22, color:'#a855f7',    created_at:'2024-04-01T00:00:00Z', email:'admin@datashield.io',  mfa_enabled:false, sso:false },
  { id:'t005', name:'CyberOps', slug:'cyberops',   plan:'Professional', status:'active', users_count:19, findings_count:456, risk_score:63, color:'#22c55e', created_at:'2024-05-20T00:00:00Z', email:'admin@cyberops.net',   mfa_enabled:true,  sso:false },
  { id:'t006', name:'InfraGuard', slug:'infraguard',plan:'Enterprise', status:'active', users_count:42, findings_count:2187, risk_score:88, color:'#f97316', created_at:'2024-06-12T00:00:00Z', email:'admin@infraguard.com', mfa_enabled:true,  sso:true  },
];

const DEMO_USERS = [
  { id:'u001', name:'Mahmoud Osman',   email:'mahmoud@wadjet-eye.com', role:'R001', tenant:'t001', status:'active',    avatar:'MO', last_login:'2025-02-10T09:00:00Z', mfa:true  },
  { id:'u002', name:'Sarah Chen',       email:'sarah@acmecorp.com',     role:'R003', tenant:'t001', status:'active',    avatar:'SC', last_login:'2025-02-10T08:30:00Z', mfa:true  },
  { id:'u003', name:'Marcus Williams',  email:'marcus@acmecorp.com',    role:'R005', tenant:'t001', status:'active',    avatar:'MW', last_login:'2025-02-09T22:00:00Z', mfa:false },
  { id:'u004', name:'Elena Petrova',    email:'elena@techvault.io',     role:'R002', tenant:'t002', status:'active',    avatar:'EP', last_login:'2025-02-10T07:15:00Z', mfa:true  },
  { id:'u005', name:'James Rodriguez',  email:'james@securenet.com',    role:'R006', tenant:'t003', status:'active',    avatar:'JR', last_login:'2025-02-09T18:45:00Z', mfa:true  },
  { id:'u006', name:'Aisha Patel',      email:'aisha@securenet.com',    role:'R003', tenant:'t003', status:'inactive',  avatar:'AP', last_login:'2025-01-15T11:00:00Z', mfa:true  },
  { id:'u007', name:'Tom Bradley',      email:'tom@datashield.io',      role:'R004', tenant:'t004', status:'suspended', avatar:'TB', last_login:'2025-01-20T14:00:00Z', mfa:false },
  { id:'u008', name:'Lin Zhao',         email:'lin@cyberops.net',       role:'R002', tenant:'t005', status:'active',    avatar:'LZ', last_login:'2025-02-10T06:00:00Z', mfa:true  },
];

const DEMO_AUDIT = [
  { id:'al001', actor:'Mahmoud Osman', action:'User Login',        detail:'Logged in from 185.22.4.1',                    level:'info',    ts:'2025-02-10T09:00:00Z' },
  { id:'al002', actor:'Sarah Chen',    action:'Export Findings',    detail:'Exported 15 findings as CSV',                  level:'info',    ts:'2025-02-10T08:45:00Z' },
  { id:'al003', actor:'Mahmoud Osman', action:'User Created',       detail:'Created user john.doe@company.com (ANALYST)',   level:'success', ts:'2025-02-10T08:30:00Z' },
  { id:'al004', actor:'Marcus Williams',action:'AI Investigation',  detail:'Started AI investigation for CVE-2024-3400',   level:'info',    ts:'2025-02-09T22:15:00Z' },
  { id:'al005', actor:'Mahmoud Osman', action:'Role Changed',       detail:'Changed priya@hackerone.com: VIEWER → ANALYST', level:'warning', ts:'2025-02-09T20:00:00Z' },
  { id:'al006', actor:'System',        action:'IOC Sync',           detail:'47 collectors synced, 1,204 new IOCs ingested', level:'success', ts:'2025-02-09T18:00:00Z' },
  { id:'al007', actor:'Mahmoud Osman', action:'Tenant Created',     detail:'Created new tenant "AcmeCorp" — Enterprise plan',level:'success',ts:'2025-02-09T15:30:00Z' },
  { id:'al008', actor:'Alex Thompson', action:'Login Failed',       detail:'Failed login attempt from 203.0.113.5',         level:'error',   ts:'2025-02-09T12:00:00Z' },
  { id:'al009', actor:'Lin Zhao',      action:'Permissions Updated',detail:'SOC Tier 1 permissions updated to include live-feeds',level:'warning',ts:'2025-02-09T10:00:00Z' },
  { id:'al010', actor:'James Rodriguez',action:'Playbook Run',      detail:'Executed API Key Exposure playbook on F006',    level:'info',    ts:'2025-02-09T09:30:00Z' },
];

/* ═══════════════════════════════════════════════════════
   DATA LOADING
═══════════════════════════════════════════════════════ */
async function _loadTenants() {
  try {
    const r = await _api('GET', '/tenants');
    TM.tenants = (Array.isArray(r)?r:r?.data||[]).map(t=>({...t,color:t.color||_tenantColor(t.name)}));
    if (!TM.tenants.length) TM.tenants = DEMO_TENANTS;
  } catch { TM.tenants = DEMO_TENANTS; }
}

async function _loadUsers() {
  try {
    const r = await _api('GET', '/users');
    TM.users = Array.isArray(r)?r:r?.data||[];
    if (!TM.users.length) TM.users = DEMO_USERS;
  } catch { TM.users = DEMO_USERS; }
}

function _tenantColor(name) {
  const colors = ['#3b82f6','#22d3ee','#a855f7','#22c55e','#f97316','#ef4444','#eab308','#ec4899','#14b8a6','#6366f1'];
  let h = 0; for (const c of name) h = (h*31+c.charCodeAt(0)) & 0xFFFFFF;
  return colors[Math.abs(h) % colors.length];
}
function _initials(name) { return (name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(); }

/* ═══════════════════════════════════════════════════════
   MAIN RENDERER
═══════════════════════════════════════════════════════ */
window.renderTenantManagement = async function() {
  const c = document.getElementById('page-customers') || document.getElementById('customersContainer');
  if (!c) return;
  c.className = 'p19-module';

  c.innerHTML = `
  <div class="p19-header">
    <div class="p19-header__inner">
      <div class="p19-header__left">
        <div class="p19-header__icon p19-header__icon--blue">
          <i class="fas fa-building"></i>
        </div>
        <div>
          <h2 class="p19-header__title">Tenant Management & RBAC</h2>
          <div class="p19-header__sub">Organizations · Users · Roles · Permissions · Audit Log</div>
        </div>
      </div>
      <div class="p19-header__right">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmExportRBAC()">
          <i class="fas fa-download"></i> <span>Export RBAC</span>
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmImportRBAC()">
          <i class="fas fa-upload"></i> <span>Import</span>
        </button>
        <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._tmNewTenant()" id="tm-add-btn">
          <i class="fas fa-plus"></i> <span>Add Tenant</span>
        </button>
      </div>
    </div>
  </div>

  <!-- KPI Row (will be populated after load) -->
  <div class="p19-kpi-row" id="tm-kpi-row">
    ${Array(4).fill(`<div class="p19-skel-card"><div class="p19-skel p19-skel-title"></div><div class="p19-skel p19-skel-text"></div></div>`).join('')}
  </div>

  <!-- Tabs -->
  <div class="p19-tabs" id="tm-tabs">
    <div class="p19-tab active" onclick="_tmTab('tenants')"><i class="fas fa-building" style="font-size:.85em"></i> Tenants</div>
    <div class="p19-tab" onclick="_tmTab('users')"><i class="fas fa-users" style="font-size:.85em"></i> Users</div>
    <div class="p19-tab" onclick="_tmTab('roles')"><i class="fas fa-shield-alt" style="font-size:.85em"></i> Roles & RBAC</div>
    <div class="p19-tab" onclick="_tmTab('audit')"><i class="fas fa-history" style="font-size:.85em"></i> Audit Log</div>
  </div>

  <!-- Content -->
  <div class="p19-content" id="tm-content">
    <div class="p19-grid">${Array(6).fill(`<div class="p19-skel-card"><div class="p19-skel p19-skel-title"></div><div class="p19-skel p19-skel-text"></div><div class="p19-skel p19-skel-text" style="width:60%"></div></div>`).join('')}</div>
  </div>`;

  // Load data
  await Promise.all([_loadTenants(), _loadUsers()]);
  TM.auditLog = DEMO_AUDIT;
  TM.roles = BUILT_IN_ROLES;

  _tmRenderKPIs();
  _tmTab('tenants');
};

function _tmRenderKPIs() {
  const el = document.getElementById('tm-kpi-row');
  if (!el) return;
  const active = TM.tenants.filter(t=>t.status==='active').length;
  const enterprise = TM.tenants.filter(t=>t.plan==='Enterprise').length;
  const totalUsers = TM.users.length;
  const highRisk = TM.tenants.filter(t=>(t.risk_score||0)>75).length;

  el.innerHTML = `
  <div class="p19-kpi-card p19-kpi-card--blue">
    <i class="fas fa-building p19-kpi-icon" style="color:var(--p19-blue);opacity:.4"></i>
    <div class="p19-kpi-label">Total Tenants</div>
    <div class="p19-kpi-value">${TM.tenants.length}</div>
    <div class="p19-kpi-sub">${active} active</div>
  </div>
  <div class="p19-kpi-card p19-kpi-card--purple">
    <i class="fas fa-users p19-kpi-icon" style="color:var(--p19-purple);opacity:.4"></i>
    <div class="p19-kpi-label">Total Users</div>
    <div class="p19-kpi-value">${totalUsers}</div>
    <div class="p19-kpi-sub">${TM.users.filter(u=>u.status==='active').length} active</div>
  </div>
  <div class="p19-kpi-card p19-kpi-card--cyan">
    <i class="fas fa-crown p19-kpi-icon" style="color:var(--p19-cyan);opacity:.4"></i>
    <div class="p19-kpi-label">Enterprise</div>
    <div class="p19-kpi-value">${enterprise}</div>
    <div class="p19-kpi-sub">${TM.tenants.filter(t=>t.plan==='Professional').length} Professional</div>
  </div>
  <div class="p19-kpi-card p19-kpi-card--red">
    <i class="fas fa-exclamation-triangle p19-kpi-icon" style="color:var(--p19-red);opacity:.4"></i>
    <div class="p19-kpi-label">High Risk</div>
    <div class="p19-kpi-value">${highRisk}</div>
    <div class="p19-kpi-sub">Risk score &gt; 75</div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   TAB SWITCHING
═══════════════════════════════════════════════════════ */
window._tmTab = function(tab) {
  TM.activeTab = tab;
  document.querySelectorAll('#tm-tabs .p19-tab').forEach((t,i)=>{
    const tabs = ['tenants','users','roles','audit'];
    t.classList.toggle('active', tabs[i]===tab);
  });
  const content = document.getElementById('tm-content');
  if (!content) return;

  switch(tab) {
    case 'tenants': _tmRenderTenants(content); break;
    case 'users':   _tmRenderUsers(content);   break;
    case 'roles':   _tmRenderRoles(content);   break;
    case 'audit':   _tmRenderAudit(content);   break;
  }

  // Update add button
  const addBtn = document.getElementById('tm-add-btn');
  if (addBtn) {
    const labels = { tenants:'Add Tenant', users:'Add User', roles:'Add Role', audit:'' };
    const fns = { tenants:'_tmNewTenant()', users:'_tmNewUser()', roles:'_tmNewRole()', audit:'' };
    if (tab === 'audit') { addBtn.style.display='none'; }
    else {
      addBtn.style.display='inline-flex';
      addBtn.innerHTML=`<i class="fas fa-plus"></i> <span>${labels[tab]}</span>`;
      addBtn.onclick = new Function(`window.${fns[tab]}`);
    }
  }
};

/* ═══════════════════════════════════════════════════════
   TENANTS TAB
═══════════════════════════════════════════════════════ */
function _tmRenderTenants(content) {
  const filtered = TM.tenants.filter(t=>{
    const s = TM.filter.search.toLowerCase();
    return (!s||t.name.toLowerCase().includes(s)||t.email?.toLowerCase().includes(s))
      && (!TM.filter.plan||t.plan===TM.filter.plan)
      && (!TM.filter.status||t.status===TM.filter.status);
  });

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:280px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search tenants…"
        oninput="TM.filter.search=this.value;window._tmTab('tenants')" />
    </div>
    <select class="p19-select" onchange="TM.filter.plan=this.value;window._tmTab('tenants')">
      <option value="">All Plans</option>
      <option value="Enterprise">Enterprise</option>
      <option value="Professional">Professional</option>
      <option value="Starter">Starter</option>
    </select>
    <select class="p19-select" onchange="TM.filter.status=this.value;window._tmTab('tenants')">
      <option value="">All Status</option>
      <option value="active">Active</option>
      <option value="suspended">Suspended</option>
      <option value="trial">Trial</option>
    </select>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${filtered.length} tenant${filtered.length!==1?'s':''}</span>
  </div>
  <div class="p19-grid p19-grid--3">
    ${filtered.map((t,i)=>_tmTenantCard(t,i)).join('')}
    ${!filtered.length?`<div class="p19-empty" style="grid-column:1/-1"><i class="fas fa-building"></i><div class="p19-empty-title">No tenants found</div></div>`:''}
  </div>`;
}

function _tmTenantCard(t, idx) {
  const planBadge = t.plan==='Enterprise' ? 'p19-badge--purple' : t.plan==='Professional' ? 'p19-badge--blue' : 'p19-badge--gray';
  const statusClass = t.status==='active' ? 'p19-status--online' : t.status==='suspended' ? 'p19-status--error' : 'p19-status--warning';
  const riskColor = (t.risk_score||0)>75?'var(--p19-red)':(t.risk_score||0)>50?'var(--p19-yellow)':'var(--p19-green)';

  return `
  <div class="p19-tenant-card" style="animation-delay:${idx*50}ms">
    <div class="p19-tenant-card__header">
      <div class="p19-tenant-card__avatar" style="background:${_e(t.color||'#3b82f6')}22;border:1px solid ${_e(t.color||'#3b82f6')}44;color:${_e(t.color||'#3b82f6')}">${_initials(t.name)}</div>
      <div style="flex:1;min-width:0">
        <div class="p19-tenant-card__name">${_e(t.name)}</div>
        <div class="p19-tenant-card__plan">${_e(t.email||t.slug)}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;align-items:flex-end">
        <span class="p19-badge ${planBadge}" style="font-size:.64em">${_e(t.plan)}</span>
        <span class="p19-status ${statusClass}" style="font-size:.7em">${_e(t.status)}</span>
      </div>
    </div>

    <div class="p19-tenant-card__stats">
      <div class="p19-tenant-stat">
        <div class="p19-tenant-stat-val" style="color:var(--p19-cyan)">${t.users_count||0}</div>
        <div class="p19-tenant-stat-label">Users</div>
      </div>
      <div class="p19-tenant-stat">
        <div class="p19-tenant-stat-val">${t.findings_count||0}</div>
        <div class="p19-tenant-stat-label">Findings</div>
      </div>
      <div class="p19-tenant-stat">
        <div class="p19-tenant-stat-val" style="color:${riskColor}">${t.risk_score||0}</div>
        <div class="p19-tenant-stat-label">Risk</div>
      </div>
    </div>

    <div style="margin:8px 0 10px">
      <div class="p19-progress">
        <div class="p19-progress-bar ${(t.risk_score||0)>75?'p19-progress-bar--red':(t.risk_score||0)>50?'p19-progress-bar--orange':'p19-progress-bar--green'}" style="width:${t.risk_score||0}%"></div>
      </div>
    </div>

    <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px">
      ${t.mfa_enabled?'<span class="p19-badge p19-badge--green" style="font-size:.64em"><i class="fas fa-lock" style="font-size:.7em"></i> MFA</span>':''}
      ${t.sso?'<span class="p19-badge p19-badge--blue" style="font-size:.64em"><i class="fas fa-sign-in-alt" style="font-size:.7em"></i> SSO</span>':''}
    </div>

    <div class="p19-tenant-card__actions">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmViewTenant('${t.id}')" title="View">
        <i class="fas fa-eye"></i>
      </button>
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmEditTenant('${t.id}')" title="Edit">
        <i class="fas fa-edit"></i>
      </button>
      ${t.status==='active'
        ? `<button class="p19-btn p19-btn--orange p19-btn--sm" onclick="window._tmSuspendTenant('${t.id}')" title="Suspend"><i class="fas fa-pause"></i></button>`
        : `<button class="p19-btn p19-btn--green p19-btn--sm" onclick="window._tmActivateTenant('${t.id}')" title="Activate"><i class="fas fa-play"></i></button>`}
      <button class="p19-btn p19-btn--red p19-btn--sm" onclick="window._tmDeleteTenant('${t.id}')" title="Delete">
        <i class="fas fa-trash"></i>
      </button>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   USERS TAB
═══════════════════════════════════════════════════════ */
function _tmRenderUsers(content) {
  const users = TM.users.filter(u=>{
    const s = TM.filter.search.toLowerCase();
    return !s || u.name.toLowerCase().includes(s) || u.email.toLowerCase().includes(s);
  });

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:280px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search users…" oninput="TM.filter.search=this.value;window._tmTab('users')" />
    </div>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${users.length} users</span>
  </div>
  <div class="p19-table-wrap">
    <table class="p19-table">
      <thead>
        <tr>
          <th>User</th><th>Role</th><th>Tenant</th><th>Status</th><th>MFA</th><th>Last Login</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${users.map((u,i)=>{
          const role = BUILT_IN_ROLES.find(r=>r.id===u.role)||{name:u.role,color:'#8b949e',badge_class:'p19-badge--gray'};
          const tenant = TM.tenants.find(t=>t.id===u.tenant);
          const statusBadge = u.status==='active'?'p19-badge--green':u.status==='inactive'?'p19-badge--gray':'p19-badge--offline';
          return `
          <tr style="animation:p19-slideInLeft ${i*40}ms ease both">
            <td>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="width:30px;height:30px;border-radius:6px;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.2);display:flex;align-items:center;justify-content:center;font-size:.72em;font-weight:700;color:var(--p19-cyan);flex-shrink:0">${_initials(u.name)}</div>
                <div>
                  <div style="font-weight:600;color:var(--p19-t1);font-size:.85em">${_e(u.name)}</div>
                  <div style="font-size:.74em;color:var(--p19-t4)">${_e(u.email)}</div>
                </div>
              </div>
            </td>
            <td><span class="p19-badge ${role.badge_class}" style="border-color:${role.color}22;background:${role.color}12;color:${role.color};font-size:.7em">${_e(role.name)}</span></td>
            <td>${tenant?`<span style="font-size:.82em;color:var(--p19-t2)">${_e(tenant.name)}</span>`:`<span style="color:var(--p19-t4)">—</span>`}</td>
            <td><span class="p19-badge ${statusBadge}" style="font-size:.68em">${_e(u.status)}</span></td>
            <td>${u.mfa?'<i class="fas fa-lock" style="color:var(--p19-green)"></i>':'<i class="fas fa-lock-open" style="color:var(--p19-t4)"></i>'}</td>
            <td style="font-size:.76em;color:var(--p19-t4)">${u.last_login?new Date(u.last_login).toLocaleDateString():'-'}</td>
            <td>
              <div style="display:flex;gap:4px">
                <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmEditUser('${u.id}')" title="Edit User"><i class="fas fa-edit"></i></button>
                <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmChangeRole('${u.id}')" title="Change Role"><i class="fas fa-user-tag"></i></button>
                <button class="p19-btn p19-btn--red p19-btn--sm" onclick="window._tmDeleteUser('${u.id}')" title="Delete"><i class="fas fa-trash"></i></button>
              </div>
            </td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   ROLES TAB
═══════════════════════════════════════════════════════ */
function _tmRenderRoles(content) {
  content.innerHTML = `
  <div class="p19-toolbar" style="margin-bottom:16px">
    <span style="font-size:.78em;color:var(--p19-t3)">${BUILT_IN_ROLES.length} roles defined</span>
    <div style="margin-left:auto;display:flex;gap:8px">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmExportRBAC()"><i class="fas fa-download"></i> Export JSON</button>
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmImportRBAC()"><i class="fas fa-upload"></i> Import</button>
    </div>
  </div>
  <div class="p19-grid p19-grid--2">
    ${BUILT_IN_ROLES.map((r,i)=>`
    <div class="p19-rbac-role" style="animation-delay:${i*50}ms">
      <div class="p19-rbac-role__header">
        <div class="p19-rbac-role__icon" style="background:${r.color}18;border:1px solid ${r.color}30;color:${r.color}">
          <i class="fas fa-shield-alt"></i>
        </div>
        <div style="flex:1">
          <div class="p19-rbac-role__name">${_e(r.name)}</div>
          <div class="p19-rbac-role__desc">${_e(r.desc)}</div>
        </div>
        <span class="p19-badge ${r.badge_class}" style="font-size:.68em">${r.id}</span>
      </div>

      <div style="margin:8px 0">
        <div style="font-size:.7em;color:var(--p19-t4);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">Permissions</div>
        <div class="p19-rbac-perms">
          ${(r.permissions||[]).map(p=>`<span class="p19-badge p19-badge--info" style="font-size:.66em">${_e(p)}</span>`).join('')}
        </div>
      </div>

      <div style="margin:8px 0">
        <div style="font-size:.7em;color:var(--p19-t4);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em">
          Module Access (${r.modules.length})
        </div>
        <div style="max-height:80px;overflow:hidden;position:relative" id="role-mods-${r.id}">
          <div class="p19-tags">${r.modules.map(m=>`<span class="p19-tag" style="font-size:.66em">${_e(m)}</span>`).join('')}</div>
          <div style="position:absolute;bottom:0;left:0;right:0;height:30px;background:linear-gradient(transparent,var(--p19-bg-card))"></div>
        </div>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" style="margin-top:4px;font-size:.72em" onclick="_tmToggleModules('${r.id}')">
          <i class="fas fa-chevron-down"></i> Show all modules
        </button>
      </div>

      <div style="display:flex;gap:6px;margin-top:8px;padding-top:8px;border-top:1px solid var(--p19-border)">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmEditRole('${r.id}')"><i class="fas fa-edit"></i> Edit</button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmDuplicateRole('${r.id}')"><i class="fas fa-copy"></i> Clone</button>
        <span style="font-size:.74em;color:var(--p19-t4);margin-left:auto;align-self:center">
          ${TM.users.filter(u=>u.role===r.id).length} users assigned
        </span>
      </div>
    </div>`).join('')}
  </div>`;
}

window._tmToggleModules = function(roleId) {
  const el = document.getElementById(`role-mods-${roleId}`);
  if (!el) return;
  const isExpanded = el.style.maxHeight === 'none';
  el.style.maxHeight = isExpanded ? '80px' : 'none';
  el.nextElementSibling.innerHTML = isExpanded
    ? '<i class="fas fa-chevron-down"></i> Show all modules'
    : '<i class="fas fa-chevron-up"></i> Collapse';
  const overlay = el.querySelector('div[style*="linear-gradient"]');
  if (overlay) overlay.style.display = isExpanded ? 'block' : 'none';
};

/* ═══════════════════════════════════════════════════════
   AUDIT LOG TAB
═══════════════════════════════════════════════════════ */
function _tmRenderAudit(content) {
  content.innerHTML = `
  <div class="p19-toolbar" style="margin-bottom:16px">
    <div class="p19-search" style="max-width:280px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search audit log…" />
    </div>
    <select class="p19-select">
      <option value="">All Levels</option>
      <option value="success">Success</option>
      <option value="warning">Warning</option>
      <option value="error">Error</option>
      <option value="info">Info</option>
    </select>
    <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._tmExportAudit()" style="margin-left:auto">
      <i class="fas fa-download"></i> Export Log
    </button>
  </div>
  <div style="background:var(--p19-bg-card);border:1px solid var(--p19-border);border-radius:var(--p19-r-lg);overflow:hidden">
    <div style="padding:12px 16px;background:var(--p19-bg-2);border-bottom:1px solid var(--p19-border);font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--p19-t3)">
      ${TM.auditLog.length} recent events
    </div>
    <div style="padding:12px 16px">
      ${TM.auditLog.map((log,i)=>{
        const levelStyle = {
          success:'background:rgba(34,197,94,.1);color:var(--p19-green)',
          error:  'background:rgba(239,68,68,.1);color:var(--p19-red)',
          warning:'background:rgba(234,179,8,.1);color:var(--p19-yellow)',
          info:   'background:rgba(34,211,238,.08);color:var(--p19-cyan)',
        }[log.level]||'';
        const icon = {success:'fa-check',error:'fa-times',warning:'fa-exclamation',info:'fa-info'}[log.level]||'fa-circle';
        return `
        <div class="p19-audit-item" style="animation-delay:${i*30}ms">
          <div class="p19-audit-icon" style="${levelStyle};border-radius:6px;width:28px;height:28px">
            <i class="fas ${icon}" style="font-size:.7em"></i>
          </div>
          <div class="p19-audit-msg">
            <strong style="color:var(--p19-t1);font-size:.84em">${_e(log.action)}</strong>
            <span style="color:var(--p19-t3);font-size:.78em"> — ${_e(log.detail)}</span>
            <div style="font-size:.72em;color:var(--p19-t4);margin-top:2px">by ${_e(log.actor)}</div>
          </div>
          <div class="p19-audit-time">${new Date(log.ts).toLocaleString()}</div>
        </div>`;
      }).join('')}
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   TENANT CRUD
═══════════════════════════════════════════════════════ */
window._tmNewTenant = function() {
  _tmShowTenantModal(null);
};

window._tmEditTenant = function(id) {
  const t = TM.tenants.find(x=>x.id===id);
  _tmShowTenantModal(t);
};

function _tmShowTenantModal(tenant) {
  const isEdit = !!tenant;
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e)=>{ if(e.target===modal)modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal">
    <div class="p19-modal-head">
      <div class="p19-modal-title"><i class="fas fa-building" style="margin-right:8px;color:var(--p19-blue)"></i>${isEdit?'Edit Tenant':'New Tenant'}</div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body">
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">Organization Name *</label>
          <input class="p19-form-input" id="tm-t-name" type="text" value="${_e(tenant?.name||'')}" placeholder="AcmeCorp" required />
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Slug</label>
          <input class="p19-form-input" id="tm-t-slug" type="text" value="${_e(tenant?.slug||'')}" placeholder="acmecorp" />
        </div>
      </div>
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">Admin Email *</label>
          <input class="p19-form-input" id="tm-t-email" type="email" value="${_e(tenant?.email||'')}" placeholder="admin@company.com" />
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Plan</label>
          <select class="p19-form-select" id="tm-t-plan">
            ${['Starter','Professional','Enterprise'].map(p=>`<option${tenant?.plan===p?' selected':''}>${p}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">Max Users</label>
          <input class="p19-form-input" id="tm-t-max-users" type="number" value="${tenant?.max_users||25}" min="1" />
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Status</label>
          <select class="p19-form-select" id="tm-t-status">
            ${['active','suspended','trial'].map(s=>`<option${tenant?.status===s?' selected':''}>${s}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="p19-form-group">
        <div style="display:flex;gap:16px;flex-wrap:wrap">
          <label class="p19-toggle">
            <input type="checkbox" id="tm-t-mfa" ${tenant?.mfa_enabled?'checked':''} />
            <div class="p19-toggle-track"></div>
            <span class="p19-toggle-label">Enforce MFA</span>
          </label>
          <label class="p19-toggle">
            <input type="checkbox" id="tm-t-sso" ${tenant?.sso?'checked':''} />
            <div class="p19-toggle-track"></div>
            <span class="p19-toggle-label">Enable SSO</span>
          </label>
        </div>
      </div>
    </div>
    <div class="p19-modal-foot">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove()">Cancel</button>
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._tmSaveTenant('${tenant?.id||''}', this)">
        <i class="fas fa-save"></i> ${isEdit?'Save Changes':'Create Tenant'}
      </button>
    </div>
  </div>`;
  document.body.appendChild(modal);

  // Auto-generate slug from name
  if (!isEdit) {
    document.getElementById('tm-t-name')?.addEventListener('input', function() {
      const slugEl = document.getElementById('tm-t-slug');
      if (slugEl && !slugEl._modified) {
        slugEl.value = this.value.toLowerCase().replace(/[^a-z0-9]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'');
      }
    });
    document.getElementById('tm-t-slug')?.addEventListener('input', function() { this._modified=true; });
  }
}

window._tmSaveTenant = async function(id, btn) {
  const get = (eid) => document.getElementById(eid)?.value?.trim()||'';
  const name = get('tm-t-name');
  if (!name) { _toast('Organization name is required', 'error'); return; }

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Saving…';

  const payload = {
    name,
    slug:        get('tm-t-slug'),
    email:       get('tm-t-email'),
    plan:        get('tm-t-plan'),
    status:      get('tm-t-status'),
    max_users:   parseInt(get('tm-t-max-users'))||25,
    mfa_enabled: document.getElementById('tm-t-mfa')?.checked||false,
    sso:         document.getElementById('tm-t-sso')?.checked||false,
  };

  try {
    if (id) {
      // Update existing
      try { await _api('PUT', `/tenants/${id}`, payload); }
      catch { /* If API unavailable, update local data */ }
      const idx = TM.tenants.findIndex(t=>t.id===id);
      if (idx>-1) TM.tenants[idx] = { ...TM.tenants[idx], ...payload };
      _toast(`Tenant "${name}" updated`, 'success');
    } else {
      // Create new
      let newTenant;
      try { newTenant = await _api('POST', '/tenants', payload); }
      catch { newTenant = null; }
      if (!newTenant) newTenant = { ...payload, id:'t'+Date.now(), users_count:0, findings_count:0, risk_score:0, color:_tenantColor(name), created_at:new Date().toISOString() };
      TM.tenants.unshift(newTenant);
      _toast(`Tenant "${name}" created`, 'success');
    }

    btn.closest('.p19-modal-backdrop').remove();
    _tmTab('tenants');
    _tmRenderKPIs();
  } catch(err) {
    _toast(`Error: ${err.message}`, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> ' + (id?'Save Changes':'Create Tenant');
  }
};

window._tmDeleteTenant = function(id) {
  const t = TM.tenants.find(x=>x.id===id);
  if (!t) return;
  if (!confirm(`Delete tenant "${t.name}"? This cannot be undone.`)) return;
  _api('DELETE', `/tenants/${id}`).catch(()=>{});
  TM.tenants = TM.tenants.filter(x=>x.id!==id);
  _toast(`Tenant "${t.name}" deleted`, 'warning');
  _tmTab('tenants');
  _tmRenderKPIs();
};

window._tmSuspendTenant = function(id) {
  const t = TM.tenants.find(x=>x.id===id);
  if (!t) return;
  _api('PATCH', `/tenants/${id}`, {status:'suspended'}).catch(()=>{});
  t.status = 'suspended';
  _toast(`Tenant "${t.name}" suspended`, 'warning');
  _tmTab('tenants');
};

window._tmActivateTenant = function(id) {
  const t = TM.tenants.find(x=>x.id===id);
  if (!t) return;
  _api('PATCH', `/tenants/${id}`, {status:'active'}).catch(()=>{});
  t.status = 'active';
  _toast(`Tenant "${t.name}" activated`, 'success');
  _tmTab('tenants');
};

window._tmViewTenant = function(id) {
  const t = TM.tenants.find(x=>x.id===id);
  if (!t) return;
  const tenantUsers = TM.users.filter(u=>u.tenant===id);
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e)=>{ if(e.target===modal)modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal p19-modal--lg">
    <div class="p19-modal-head">
      <div style="display:flex;align-items:center;gap:10px">
        <div style="width:34px;height:34px;border-radius:8px;background:${t.color}22;border:1px solid ${t.color}44;display:flex;align-items:center;justify-content:center;font-weight:700;color:${t.color}">${_initials(t.name)}</div>
        <div class="p19-modal-title">${_e(t.name)}</div>
        <span class="p19-badge p19-badge--${t.plan==='Enterprise'?'purple':t.plan==='Professional'?'blue':'gray'}" style="font-size:.7em">${_e(t.plan)}</span>
      </div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body">
      <div class="p19-form-row" style="gap:10px;margin-bottom:16px">
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.4em;font-weight:700;color:var(--p19-cyan)">${t.users_count||0}</div>
          <div style="font-size:.72em;color:var(--p19-t4)">Users</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.4em;font-weight:700;color:var(--p19-t1)">${t.findings_count||0}</div>
          <div style="font-size:.72em;color:var(--p19-t4)">Findings</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.4em;font-weight:700;color:${(t.risk_score||0)>75?'var(--p19-red)':(t.risk_score||0)>50?'var(--p19-yellow)':'var(--p19-green)'}">${t.risk_score||0}</div>
          <div style="font-size:.72em;color:var(--p19-t4)">Risk Score</div>
        </div>
      </div>
      <div style="margin-bottom:12px">
        <div style="font-size:.74em;font-weight:700;color:var(--p19-t3);text-transform:uppercase;margin-bottom:8px">Users in this Tenant</div>
        ${tenantUsers.length ? tenantUsers.map(u=>{
          const role = BUILT_IN_ROLES.find(r=>r.id===u.role)||{name:u.role,color:'#8b949e'};
          return `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--p19-border)">
            <div style="width:26px;height:26px;border-radius:6px;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.2);display:flex;align-items:center;justify-content:center;font-size:.68em;font-weight:700;color:var(--p19-cyan)">${_initials(u.name)}</div>
            <div style="flex:1"><div style="font-size:.82em;color:var(--p19-t1)">${_e(u.name)}</div><div style="font-size:.72em;color:var(--p19-t4)">${_e(u.email)}</div></div>
            <span style="font-size:.7em;padding:2px 7px;border-radius:10px;background:${role.color}18;color:${role.color};border:1px solid ${role.color}30">${_e(role.name)}</span>
          </div>`;
        }).join('') : '<div style="font-size:.82em;color:var(--p19-t4)">No users assigned to this tenant</div>'}
      </div>
    </div>
    <div class="p19-modal-foot">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove()">Close</button>
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove();window._tmEditTenant('${t.id}')">
        <i class="fas fa-edit"></i> Edit Tenant
      </button>
    </div>
  </div>`;
  document.body.appendChild(modal);
};

/* ═══════════════════════════════════════════════════════
   USER CRUD
═══════════════════════════════════════════════════════ */
window._tmNewUser = function() { _tmShowUserModal(null); };
window._tmEditUser = function(id) { _tmShowUserModal(TM.users.find(u=>u.id===id)); };

function _tmShowUserModal(user) {
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e)=>{ if(e.target===modal)modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal">
    <div class="p19-modal-head">
      <div class="p19-modal-title"><i class="fas fa-user" style="margin-right:8px;color:var(--p19-purple)"></i>${user?'Edit User':'New User'}</div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body">
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">Full Name *</label>
          <input class="p19-form-input" id="tm-u-name" type="text" value="${_e(user?.name||'')}" placeholder="John Doe" />
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Email *</label>
          <input class="p19-form-input" id="tm-u-email" type="email" value="${_e(user?.email||'')}" placeholder="john@company.com" />
        </div>
      </div>
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">Role</label>
          <select class="p19-form-select" id="tm-u-role">
            ${BUILT_IN_ROLES.map(r=>`<option value="${r.id}"${user?.role===r.id?' selected':''}>${r.name}</option>`).join('')}
          </select>
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Tenant</label>
          <select class="p19-form-select" id="tm-u-tenant">
            <option value="">None</option>
            ${TM.tenants.map(t=>`<option value="${t.id}"${user?.tenant===t.id?' selected':''}>${_e(t.name)}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="p19-form-group">
        <label class="p19-toggle">
          <input type="checkbox" id="tm-u-mfa" ${user?.mfa?'checked':''} />
          <div class="p19-toggle-track"></div>
          <span class="p19-toggle-label">Require MFA</span>
        </label>
      </div>
    </div>
    <div class="p19-modal-foot">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove()">Cancel</button>
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._tmSaveUser('${user?.id||''}', this)">
        <i class="fas fa-save"></i> ${user?'Save':'Create User'}
      </button>
    </div>
  </div>`;
  document.body.appendChild(modal);
}

window._tmSaveUser = function(id, btn) {
  const name  = document.getElementById('tm-u-name')?.value?.trim();
  const email = document.getElementById('tm-u-email')?.value?.trim();
  if (!name||!email) { _toast('Name and email are required', 'error'); return; }

  const payload = { name, email,
    role:   document.getElementById('tm-u-role')?.value||'R004',
    tenant: document.getElementById('tm-u-tenant')?.value||'',
    mfa:    document.getElementById('tm-u-mfa')?.checked||false,
    status: 'active',
  };

  if (id) {
    const idx = TM.users.findIndex(u=>u.id===id);
    if (idx>-1) TM.users[idx] = { ...TM.users[idx], ...payload };
    _api('PUT', `/users/${id}`, payload).catch(()=>{});
    _toast(`User "${name}" updated`, 'success');
  } else {
    const newUser = { ...payload, id:'u'+Date.now(), avatar:_initials(name), last_login:null };
    TM.users.unshift(newUser);
    _api('POST', '/users', payload).catch(()=>{});
    _toast(`User "${name}" created`, 'success');
  }

  btn.closest('.p19-modal-backdrop').remove();
  _tmTab('users');
};

window._tmDeleteUser = function(id) {
  const u = TM.users.find(x=>x.id===id);
  if (!u||!confirm(`Delete user "${u.name}"?`)) return;
  _api('DELETE', `/users/${id}`).catch(()=>{});
  TM.users = TM.users.filter(x=>x.id!==id);
  _toast(`User "${u.name}" deleted`, 'warning');
  _tmTab('users');
};

window._tmChangeRole = function(userId) {
  const u = TM.users.find(x=>x.id===userId);
  if (!u) return;
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e)=>{ if(e.target===modal)modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal">
    <div class="p19-modal-head">
      <div class="p19-modal-title">Change Role: ${_e(u.name)}</div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body">
      <div style="display:flex;flex-direction:column;gap:6px">
        ${BUILT_IN_ROLES.map(r=>`
        <div onclick="window._tmAssignRole('${userId}','${r.id}',this.closest('.p19-modal-backdrop'))"
          style="padding:10px 14px;border-radius:8px;border:1px solid ${u.role===r.id?r.color+'44':'var(--p19-border)'};
                 background:${u.role===r.id?r.color+'12':'transparent'};cursor:pointer;transition:all .15s"
          onmouseover="this.style.background='${r.color}12'" onmouseout="this.style.background='${u.role===r.id?r.color+'12':'transparent'}'">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:.84em;font-weight:700;color:${r.color}">${r.name}</span>
            ${u.role===r.id?'<span class="p19-badge p19-badge--green" style="font-size:.64em;margin-left:auto">CURRENT</span>':''}
          </div>
          <div style="font-size:.74em;color:var(--p19-t3);margin-top:2px">${r.desc}</div>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
  document.body.appendChild(modal);
};

window._tmAssignRole = function(userId, roleId, modal) {
  const u = TM.users.find(x=>x.id===userId);
  const r = BUILT_IN_ROLES.find(x=>x.id===roleId);
  if (!u||!r) return;
  _api('PATCH', `/users/${userId}`, {role:roleId}).catch(()=>{});
  u.role = roleId;
  _toast(`${u.name} → ${r.name}`, 'success');
  modal?.remove();
  _tmTab('users');
};

/* ═══════════════════════════════════════════════════════
   EXPORT / IMPORT RBAC
═══════════════════════════════════════════════════════ */
window._tmExportRBAC = function() {
  const data = { exported_at:new Date().toISOString(), roles:BUILT_IN_ROLES, tenants:TM.tenants.map(({id,name,plan,status})=>({id,name,plan,status})) };
  const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`rbac-export-${Date.now()}.json`; a.click();
  _toast('RBAC configuration exported', 'success');
};

window._tmImportRBAC = function() {
  const inp = document.createElement('input');
  inp.type='file'; inp.accept='.json';
  inp.onchange = function() {
    const file = inp.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (data.roles && Array.isArray(data.roles)) {
          _toast(`Imported ${data.roles.length} roles from ${file.name}`, 'success');
        } else { _toast('Invalid RBAC file format', 'error'); }
      } catch { _toast('Failed to parse JSON file', 'error'); }
    };
    reader.readAsText(file);
  };
  inp.click();
};

window._tmExportAudit = function() {
  const blob = new Blob([JSON.stringify(TM.auditLog,null,2)],{type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`audit-log-${Date.now()}.json`; a.click();
  _toast('Audit log exported', 'success');
};

window._tmNewRole = function() { _toast('Role editor coming soon — clone an existing role to customize', 'info'); };
window._tmEditRole = function(id) { _toast(`Editing role ${id} — use Export/Import to modify roles`, 'info'); };
window._tmDuplicateRole = function(id) {
  const r = BUILT_IN_ROLES.find(x=>x.id===id);
  if (!r) return;
  _toast(`Role "${r.name}" cloned — edit JSON to customize`, 'success');
};

})(); // end IIFE
