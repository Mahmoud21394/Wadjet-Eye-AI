/* ══════════════════════════════════════════════════════════
   EYEbot AI — RBAC Module v17.0.0
   Role-Based Access Control: Users, Roles, Permissions,
   Tenant Isolation, Audit Log
   ══════════════════════════════════════════════════════════ */

/* ─── RBAC DATA STORE ─── */
const RBAC_STORE = {
  roles: [
    {
      id: 'R001', name: 'Super Admin', slug: 'super_admin', color: '#ef4444',
      desc: 'Full platform access. Can manage all tenants, users, billing and system config.',
      permissions: ['all'],
      modules: ['command-center','findings','campaigns','detections','threat-actors','dark-web','exposure',
        'ioc-registry','ioc-database','ai-orchestrator','collectors','playbooks','edr-siem','sysmon',
        'customers','reports','settings','executive-dashboard','kill-chain','case-management',
        'threat-hunting','detection-engineering','soar','live-feeds','cyber-news','mitre-attack',
        'geo-threats','rbac-admin','branding','pricing']
    },
    {
      id: 'R002', name: 'Admin', slug: 'admin', color: '#f97316',
      desc: 'Tenant-level admin. Can manage users within their tenant and access all intel modules.',
      permissions: ['read','write','manage_users','manage_collectors','export','investigate'],
      modules: ['command-center','findings','campaigns','detections','threat-actors','dark-web','exposure',
        'ioc-registry','ioc-database','ai-orchestrator','collectors','playbooks','edr-siem',
        'customers','reports','settings','executive-dashboard','kill-chain','case-management',
        'threat-hunting','detection-engineering','soar','live-feeds','cyber-news','mitre-attack','geo-threats']
    },
    {
      id: 'R003', name: 'Analyst', slug: 'analyst', color: '#3b82f6',
      desc: 'Security analyst. Read/write access to intel modules. Cannot manage users or billing.',
      permissions: ['read','write','investigate','export'],
      modules: ['command-center','findings','campaigns','detections','threat-actors','dark-web',
        'ioc-registry','ioc-database','ai-orchestrator','playbooks','case-management',
        'threat-hunting','detection-engineering','cyber-news','mitre-attack','geo-threats','live-feeds']
    },
    {
      id: 'R004', name: 'Viewer', slug: 'viewer', color: '#22c55e',
      desc: 'Read-only access. Can view dashboards and reports but cannot investigate or export.',
      permissions: ['read'],
      modules: ['command-center','findings','campaigns','threat-actors','cyber-news','mitre-attack','geo-threats','reports']
    },
    {
      id: 'R005', name: 'SOC Tier 1', slug: 'soc_t1', color: '#22d3ee',
      desc: 'Tier 1 SOC analyst. Triage findings, run playbooks, monitor live feeds.',
      permissions: ['read','write','investigate'],
      modules: ['command-center','findings','detections','playbooks','case-management','live-feeds','cyber-news','soar']
    },
    {
      id: 'R006', name: 'Threat Hunter', slug: 'hunter', color: '#a855f7',
      desc: 'Dedicated threat hunting analyst. Access to hunting workspace and detection engineering.',
      permissions: ['read','write','investigate','export'],
      modules: ['command-center','findings','threat-actors','ioc-registry','ioc-database',
        'threat-hunting','detection-engineering','mitre-attack','live-feeds','cyber-news','geo-threats']
    },
    {
      id: 'R007', name: 'Executive', slug: 'executive', color: '#f59e0b',
      desc: 'C-level / board view. Executive dashboard, reports, and high-level metrics only.',
      permissions: ['read'],
      modules: ['executive-dashboard','reports','cyber-news','geo-threats']
    },
    {
      id: 'R008', name: 'Auditor', slug: 'auditor', color: '#ec4899',
      desc: 'Compliance and audit access. Read-only across all modules plus audit log.',
      permissions: ['read','audit'],
      modules: ['command-center','findings','campaigns','reports','settings','rbac-admin','cyber-news']
    },
  ],

  audit_log: [
    { id:'AL001', user:'Mahmoud Osman', action:'Login', resource:'Platform', detail:'Successful login from 185.22.4.1', time:'2 min ago', ip:'185.22.4.1', severity:'info' },
    { id:'AL002', user:'James Chen', action:'Export', resource:'Findings', detail:'Exported 15 findings as CSV', time:'15 min ago', ip:'10.0.1.42', severity:'info' },
    { id:'AL003', user:'Maria Santos', action:'Investigate', resource:'F003', detail:'AI investigation started for CVE-2024-3400', time:'32 min ago', ip:'10.0.1.55', severity:'info' },
    { id:'AL004', user:'Mahmoud Osman', action:'Create User', resource:'Users', detail:'Created user john.doe@company.com with ANALYST role', time:'1h ago', ip:'185.22.4.1', severity:'success' },
    { id:'AL005', user:'Mahmoud Osman', action:'Role Change', resource:'Users', detail:'Changed priya@hackerone.com from VIEWER to ANALYST', time:'2h ago', ip:'185.22.4.1', severity:'warning' },
    { id:'AL006', user:'Alex Thompson', action:'Failed Login', resource:'Platform', detail:'Invalid password attempt from 203.0.113.5', time:'3h ago', ip:'203.0.113.5', severity:'error' },
    { id:'AL007', user:'Mahmoud Osman', action:'Tenant Created', resource:'Tenants', detail:'New tenant "AcmeCorp" created with Enterprise plan', time:'4h ago', ip:'185.22.4.1', severity:'success' },
    { id:'AL008', user:'Marcus Williams', action:'Playbook Run', resource:'PB003', detail:'Executed API Key Exposure playbook on F006', time:'5h ago', ip:'10.0.2.11', severity:'info' },
    { id:'AL009', user:'System', action:'Sync Complete', resource:'Collectors', detail:'47 collectors synced — 1,204 new IOCs', time:'6h ago', ip:'127.0.0.1', severity:'success' },
    { id:'AL010', user:'Mahmoud Osman', action:'Permission Update', resource:'Roles', detail:'Updated SOC Tier 1 permissions to include live-feeds', time:'8h ago', ip:'185.22.4.1', severity:'warning' },
    { id:'AL011', user:'James Chen', action:'Dark Web Search', resource:'Dark Web', detail:'Searched dark web for "hackerone credentials"', time:'10h ago', ip:'10.0.1.42', severity:'info' },
    { id:'AL012', user:'System', action:'Alert Triggered', resource:'Notifications', detail:'CRITICAL: CVE-2024-44000 added to KEV catalog', time:'12h ago', ip:'127.0.0.1', severity:'error' },
  ]
};

/* ══════════════════════════════════════════════
   RENDER RBAC ADMIN PAGE
   ══════════════════════════════════════════════ */
function renderRBACAdmin() {
  const container = document.getElementById('rbacAdminWrap');
  if (!container) return;

  const canManage = CURRENT_USER?.role === 'SUPER_ADMIN' || CURRENT_USER?.role === 'ADMIN';

  container.innerHTML = `
    <div style="margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
      <div>
        <h2 style="font-size:18px;font-weight:800;display:flex;align-items:center;gap:8px;">
          <span style="width:32px;height:32px;background:linear-gradient(135deg,#3b82f6,#a855f7);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;">🔐</span>
          Role-Based Access Control
        </h2>
        <p style="font-size:11px;color:var(--text-muted);margin-top:3px;">Manage users, roles, module permissions and tenant isolation · v17.0.0</p>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn-primary" onclick="openAddUserModal()" ${canManage?'':'disabled title="Admin only"'}><i class="fas fa-user-plus"></i> Add User</button>
        <button class="btn-primary" style="background:rgba(168,85,247,0.2);border-color:rgba(168,85,247,0.4);" onclick="openCreateRoleModal()"><i class="fas fa-shield-alt"></i> New Role</button>
        <button class="btn-primary" style="background:rgba(34,197,94,0.15);border-color:rgba(34,197,94,0.3);" onclick="exportRBACReport()"><i class="fas fa-download"></i> Export Report</button>
      </div>
    </div>

    <!-- RBAC Stats -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px;">
      ${[
        {label:'Total Users', val: ARGUS_DATA.users.length, icon:'fa-users', color:'#3b82f6'},
        {label:'Active Roles', val: RBAC_STORE.roles.length, icon:'fa-shield-alt', color:'#a855f7'},
        {label:'Tenants', val: ARGUS_DATA.tenants.length, icon:'fa-building', color:'#22d3ee'},
        {label:'Active Sessions', val: 4, icon:'fa-wifi', color:'#22c55e'},
        {label:'Failed Logins (24h)', val: 1, icon:'fa-ban', color:'#ef4444'},
        {label:'Audit Events', val: RBAC_STORE.audit_log.length, icon:'fa-list-alt', color:'#f59e0b'},
      ].map(s=>`
        <div style="background:${s.color}12;border:1px solid ${s.color}33;border-radius:10px;padding:14px;text-align:center;">
          <i class="fas ${s.icon}" style="color:${s.color};font-size:18px;margin-bottom:6px;display:block;"></i>
          <div style="font-size:22px;font-weight:900;color:${s.color};">${s.val}</div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${s.label}</div>
        </div>`).join('')}
    </div>

    <!-- Tabs -->
    <div class="modal-tabs" style="margin-bottom:16px;">
      <button class="modal-tab active" onclick="switchRBACTab(this,'rbac-users')"><i class="fas fa-users"></i> Users</button>
      <button class="modal-tab" onclick="switchRBACTab(this,'rbac-roles')"><i class="fas fa-shield-alt"></i> Roles & Permissions</button>
      <button class="modal-tab" onclick="switchRBACTab(this,'rbac-audit')"><i class="fas fa-list-alt"></i> Audit Log</button>
      <button class="modal-tab" onclick="switchRBACTab(this,'rbac-sessions')"><i class="fas fa-desktop"></i> Active Sessions</button>
      <button class="modal-tab" onclick="switchRBACTab(this,'rbac-policies')"><i class="fas fa-file-contract"></i> Access Policies</button>
    </div>

    <!-- USERS TAB -->
    <div id="rbac-users" class="rbac-tab-panel active">
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
        <input class="settings-input" style="flex:1;min-width:200px;" placeholder="🔍 Search users by name, email or tenant..." id="rbacUserSearch" oninput="filterRBACUsers(this.value)" />
        <select class="filter-select" id="rbacRoleFilter" onchange="filterRBACUsers(document.getElementById('rbacUserSearch').value)">
          <option value="">All Roles</option>
          ${RBAC_STORE.roles.map(r=>`<option value="${r.slug}">${r.name}</option>`).join('')}
        </select>
        <select class="filter-select" id="rbacTenantFilter" onchange="filterRBACUsers(document.getElementById('rbacUserSearch').value)">
          <option value="">All Tenants</option>
          ${ARGUS_DATA.tenants.map(t=>`<option value="${t.name}">${t.name}</option>`).join('')}
        </select>
      </div>
      <div id="rbacUsersTable">${renderRBACUsersTable(ARGUS_DATA.users)}</div>
    </div>

    <!-- ROLES TAB -->
    <div id="rbac-roles" class="rbac-tab-panel" style="display:none;">
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;">
        ${RBAC_STORE.roles.map(role => `
          <div style="background:var(--bg-card);border:1px solid ${role.color}44;border-radius:12px;padding:16px;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
              <div style="width:36px;height:36px;background:${role.color}22;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;">🛡️</div>
              <div style="flex:1;">
                <div style="font-size:13px;font-weight:800;color:${role.color};">${role.name}</div>
                <div style="font-size:10px;color:var(--text-muted);">${ARGUS_DATA.users.filter(u=>u.role===role.name||u.role===role.slug.toUpperCase()).length} users assigned</div>
              </div>
              <span style="font-size:9px;padding:2px 7px;background:${role.color}22;color:${role.color};border-radius:4px;border:1px solid ${role.color}44;font-family:monospace;">${role.slug}</span>
            </div>
            <p style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;line-height:1.6;">${role.desc}</p>
            <div style="margin-bottom:10px;">
              <div style="font-size:10px;color:var(--text-muted);font-weight:700;margin-bottom:4px;">PERMISSIONS</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;">
                ${(role.permissions.includes('all') ? ['read','write','investigate','export','manage_users','manage_collectors','audit','all'] : role.permissions).map(p=>`
                  <span style="font-size:9px;padding:2px 6px;background:${role.color}18;color:${role.color};border-radius:3px;border:1px solid ${role.color}33;font-family:monospace;">${p}</span>
                `).join('')}
              </div>
            </div>
            <div style="margin-bottom:12px;">
              <div style="font-size:10px;color:var(--text-muted);font-weight:700;margin-bottom:4px;">MODULE ACCESS (${role.modules.length})</div>
              <div style="display:flex;flex-wrap:wrap;gap:3px;max-height:60px;overflow:hidden;" id="modules-${role.id}">
                ${role.modules.slice(0,8).map(m=>`<span style="font-size:9px;padding:1px 5px;background:rgba(59,130,246,0.1);color:#60a5fa;border-radius:3px;">${m}</span>`).join('')}
                ${role.modules.length>8?`<span style="font-size:9px;color:var(--text-muted);">+${role.modules.length-8} more</span>`:''}
              </div>
            </div>
            <div style="display:flex;gap:6px;">
              <button class="btn-primary" style="font-size:11px;flex:1;" onclick="editRole('${role.id}')"><i class="fas fa-edit"></i> Edit Role</button>
              ${role.id!=='R001'?`<button class="tbl-btn" title="Delete Role" onclick="showToast('Cannot delete system roles','warning')"><i class="fas fa-trash"></i></button>`:''}
            </div>
          </div>`).join('')}
        <!-- Add Custom Role Card -->
        <div style="background:var(--bg-card);border:2px dashed var(--border);border-radius:12px;padding:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;cursor:pointer;min-height:200px;" onclick="openCreateRoleModal()">
          <i class="fas fa-plus-circle" style="font-size:32px;color:var(--text-muted);"></i>
          <div style="font-size:12px;color:var(--text-muted);font-weight:600;">Create Custom Role</div>
          <div style="font-size:10px;color:var(--text-muted);text-align:center;">Define granular permissions and module access for your team</div>
        </div>
      </div>
    </div>

    <!-- AUDIT LOG TAB -->
    <div id="rbac-audit" class="rbac-tab-panel" style="display:none;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
        <div style="display:flex;gap:8px;flex:1;flex-wrap:wrap;">
          <input class="settings-input" style="flex:1;min-width:180px;" placeholder="🔍 Filter audit events..." id="auditSearch" oninput="filterAuditLog(this.value)" />
          <select class="filter-select" onchange="filterAuditLog(document.getElementById('auditSearch').value)">
            <option value="">All Actions</option>
            <option>Login</option><option>Failed Login</option><option>Export</option>
            <option>Create User</option><option>Role Change</option><option>Investigate</option>
          </select>
        </div>
        <button class="btn-primary" style="font-size:11px;" onclick="exportAuditLog()"><i class="fas fa-download"></i> Export Log</button>
      </div>
      <div id="auditLogTable">${renderAuditTable(RBAC_STORE.audit_log)}</div>
    </div>

    <!-- SESSIONS TAB -->
    <div id="rbac-sessions" class="rbac-tab-panel" style="display:none;">
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
        <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
          <span style="font-size:13px;font-weight:700;">Active User Sessions</span>
          <button class="btn-primary" style="font-size:11px;background:rgba(239,68,68,0.15);border-color:rgba(239,68,68,0.4);color:#f87171;" onclick="showToast('All other sessions terminated','success')"><i class="fas fa-sign-out-alt"></i> Kill All Other Sessions</button>
        </div>
        <table style="width:100%;border-collapse:collapse;">
          <thead><tr style="background:var(--bg-elevated);">
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">User</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">IP Address</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Location</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Browser</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Started</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Status</th>
            <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Action</th>
          </tr></thead>
          <tbody>
            ${[
              {user:'Mahmoud Osman',email:'mahmoud@mssp.com',ip:'185.22.4.1',loc:'Dubai, UAE 🇦🇪',browser:'Chrome 120',started:'Just now',current:true},
              {user:'James Chen',email:'james@mssp.com',ip:'10.0.1.42',loc:'Singapore 🇸🇬',browser:'Firefox 121',started:'42 min ago',current:false},
              {user:'Maria Santos',email:'maria@mssp.com',ip:'10.0.1.55',loc:'São Paulo, BR 🇧🇷',browser:'Chrome 120',started:'1h 12m ago',current:false},
              {user:'Alex Thompson',email:'alex@hackerone.com',ip:'198.51.100.33',loc:'San Francisco, US 🇺🇸',browser:'Safari 17',started:'2h 05m ago',current:false},
            ].map(s=>`
              <tr style="border-bottom:1px solid var(--border);">
                <td style="padding:10px 14px;">
                  <div style="display:flex;align-items:center;gap:8px;">
                    <div style="width:28px;height:28px;border-radius:7px;background:linear-gradient(135deg,#3b82f6,#a855f7);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;">${s.user.split(' ').map(w=>w[0]).join('')}</div>
                    <div><div style="font-size:12px;font-weight:600;">${s.user}</div><div style="font-size:10px;color:var(--text-muted);">${s.email}</div></div>
                  </div>
                </td>
                <td style="padding:10px 14px;font-family:monospace;font-size:11px;color:var(--accent-cyan);">${s.ip}</td>
                <td style="padding:10px 14px;font-size:11px;color:var(--text-secondary);">${s.loc}</td>
                <td style="padding:10px 14px;font-size:11px;color:var(--text-secondary);">${s.browser}</td>
                <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${s.started}</td>
                <td style="padding:10px 14px;"><span style="font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3);">● Active${s.current?' (You)':''}</span></td>
                <td style="padding:10px 14px;">${!s.current?`<button class="tbl-btn" title="Terminate Session" onclick="showToast('Session for ${s.user} terminated','success')"><i class="fas fa-times"></i></button>`:`<span style="font-size:10px;color:var(--text-muted);">Current</span>`}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- POLICIES TAB -->
    <div id="rbac-policies" class="rbac-tab-panel" style="display:none;">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;">
          <div style="font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px;"><i class="fas fa-lock" style="color:#3b82f6;"></i> Password Policy</div>
          ${renderPolicyToggle('Minimum 8 characters','Enforce strong passwords',true)}
          ${renderPolicyToggle('Require uppercase + numbers','Complexity requirements',true)}
          ${renderPolicyToggle('Password expiry (90 days)','Force periodic resets',false)}
          ${renderPolicyToggle('Prevent password reuse','Block last 5 passwords',true)}
          ${renderPolicyToggle('Lockout after 5 failures','Brute force protection',true)}
        </div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;">
          <div style="font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px;"><i class="fas fa-mobile-alt" style="color:#a855f7;"></i> MFA Policy</div>
          ${renderPolicyToggle('MFA required for Admin roles','Enforce MFA for privileged users',true)}
          ${renderPolicyToggle('MFA required for all users','Platform-wide MFA enforcement',false)}
          ${renderPolicyToggle('TOTP (Authenticator app)','Google/Authy compatible',true)}
          ${renderPolicyToggle('SMS OTP fallback','Mobile number required',false)}
          ${renderPolicyToggle('Hardware key (FIDO2)','YubiKey / passkeys support',false)}
        </div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;">
          <div style="font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px;"><i class="fas fa-user-clock" style="color:#22c55e;"></i> Session Policy</div>
          ${renderPolicyToggle('Auto-logout after 30 min idle','Inactivity timeout',true)}
          ${renderPolicyToggle('Single active session only','Prevent concurrent logins',false)}
          ${renderPolicyToggle('Force re-auth for exports','Critical action verification',true)}
          ${renderPolicyToggle('IP allowlist enforcement','Restrict login to known IPs',false)}
          ${renderPolicyToggle('Session audit logging','Log all session events',true)}
        </div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;">
          <div style="font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px;"><i class="fas fa-database" style="color:#f59e0b;"></i> Data Access Policy</div>
          ${renderPolicyToggle('Tenant data isolation','Cross-tenant data separation',true)}
          ${renderPolicyToggle('Export watermarking','Stamp exports with user info',true)}
          ${renderPolicyToggle('DLP — block PII export','Prevent PII in exports',false)}
          ${renderPolicyToggle('API rate limiting','Prevent bulk data extraction',true)}
          ${renderPolicyToggle('Data retention (365 days)','Auto-purge old records',true)}
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn-primary" onclick="showToast('Access policies saved!','success')"><i class="fas fa-save"></i> Save All Policies</button>
        <button style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;" onclick="showToast('Policies reset to secure defaults','info')">Reset Defaults</button>
      </div>
    </div>
  `;
}

function renderPolicyToggle(label, desc, active) {
  return `<div style="display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border);">
    <div><div style="font-size:12px;font-weight:600;">${label}</div><div style="font-size:10px;color:var(--text-muted);">${desc}</div></div>
    <div class="toggle-switch ${active?'on':''}" onclick="this.classList.toggle('on');showToast('Policy updated','success')"></div>
  </div>`;
}

function renderRBACUsersTable(users) {
  return `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
    <table style="width:100%;border-collapse:collapse;">
      <thead><tr style="background:var(--bg-elevated);">
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">User</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Role</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Tenant</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Modules</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">MFA</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Last Login</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Status</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Actions</th>
      </tr></thead>
      <tbody>
        ${users.map(u => {
          const roleObj = RBAC_STORE.roles.find(r => r.name.toUpperCase().replace(' ','_') === u.role || r.name.toLowerCase() === u.role.toLowerCase() || r.slug.toUpperCase() === u.role);
          const roleColor = roleObj?.color || '#64748b';
          const moduleCount = roleObj?.modules.length || 0;
          return `<tr style="border-bottom:1px solid var(--border);transition:background 0.15s;" onmouseover="this.style.background='var(--bg-elevated)'" onmouseout="this.style.background='transparent'">
            <td style="padding:10px 14px;">
              <div style="display:flex;align-items:center;gap:10px;">
                <div style="width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#a855f7);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0;">${u.avatar}</div>
                <div><div style="font-size:12px;font-weight:700;">${u.name}</div><div style="font-size:10px;color:var(--text-muted);">${u.email}</div></div>
              </div>
            </td>
            <td style="padding:10px 14px;"><span class="role-badge ${u.role.toLowerCase().includes('super')||u.role.toLowerCase().includes('admin')?'admin':u.role.toLowerCase().includes('analyst')||u.role.toLowerCase().includes('soc')||u.role.toLowerCase().includes('hunter')?'analyst':'viewer'}" style="border-color:${roleColor}44;">${u.role}</span></td>
            <td style="padding:10px 14px;font-size:11px;color:var(--text-secondary);">${u.tenant}</td>
            <td style="padding:10px 14px;">
              <div style="display:flex;align-items:center;gap:4px;">
                <div style="width:40px;height:4px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;"><div style="height:100%;background:${roleColor};width:${Math.min(100,moduleCount*4)}%;"></div></div>
                <span style="font-size:10px;color:var(--text-muted);">${moduleCount} modules</span>
              </div>
            </td>
            <td style="padding:10px 14px;">${u.mfa?'<span style="color:#22c55e;font-size:11px;font-weight:600;">✓ Active</span>':'<span style="color:#ef4444;font-size:11px;">✗ Off</span>'}</td>
            <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${u.last_login}</td>
            <td style="padding:10px 14px;"><span style="font-size:10px;padding:2px 7px;border-radius:4px;background:${u.status==='active'?'rgba(34,197,94,0.15)':'rgba(100,116,139,0.15)'};color:${u.status==='active'?'#4ade80':'var(--text-muted)'};">● ${u.status}</span></td>
            <td style="padding:10px 14px;">
              <div style="display:flex;gap:4px;">
                <button class="tbl-btn" title="Edit User & Permissions" onclick="openRBACEditUser('${u.id}')"><i class="fas fa-user-cog"></i></button>
                <button class="tbl-btn" title="Manage Module Access" onclick="openModuleAccessModal('${u.id}')"><i class="fas fa-th"></i></button>
                <button class="tbl-btn" title="Reset Password" onclick="showToast('Reset email sent to ${u.email}','success')"><i class="fas fa-key"></i></button>
                <button class="tbl-btn" title="${u.status==='active'?'Deactivate':'Activate'}" onclick="toggleUserStatus('${u.id}');renderRBACAdmin()"><i class="fas fa-${u.status==='active'?'user-slash':'user-check'}"></i></button>
              </div>
            </td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>`;
}

function renderAuditTable(logs) {
  const sevColors = { info:'#3b82f6', success:'#22c55e', warning:'#f59e0b', error:'#ef4444' };
  return `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
    <table style="width:100%;border-collapse:collapse;">
      <thead><tr style="background:var(--bg-elevated);">
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Time</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">User</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Action</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Resource</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Detail</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">IP</th>
        <th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);text-transform:uppercase;">Sev</th>
      </tr></thead>
      <tbody>
        ${logs.map(l => `
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:9px 14px;font-size:10px;color:var(--text-muted);white-space:nowrap;">${l.time}</td>
            <td style="padding:9px 14px;font-size:11px;font-weight:600;">${l.user}</td>
            <td style="padding:9px 14px;"><span style="font-size:10px;padding:2px 7px;background:${sevColors[l.severity]}18;color:${sevColors[l.severity]};border-radius:4px;border:1px solid ${sevColors[l.severity]}33;font-weight:700;">${l.action}</span></td>
            <td style="padding:9px 14px;font-size:11px;font-family:monospace;color:var(--accent-cyan);">${l.resource}</td>
            <td style="padding:9px 14px;font-size:11px;color:var(--text-secondary);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${l.detail}">${l.detail}</td>
            <td style="padding:9px 14px;font-size:10px;font-family:monospace;color:var(--text-muted);">${l.ip}</td>
            <td style="padding:9px 14px;"><span style="width:8px;height:8px;border-radius:50%;background:${sevColors[l.severity]};display:inline-block;"></span></td>
          </tr>`).join('')}
      </tbody>
    </table>
  </div>`;
}

function switchRBACTab(btn, tabId) {
  btn.closest('.modal-tabs').querySelectorAll('.modal-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.rbac-tab-panel').forEach(p => p.style.display='none');
  const panel = document.getElementById(tabId);
  if (panel) panel.style.display = 'block';
}

function filterRBACUsers(q) {
  q = q.toLowerCase();
  const roleF = document.getElementById('rbacRoleFilter')?.value.toLowerCase() || '';
  const tenF  = document.getElementById('rbacTenantFilter')?.value.toLowerCase() || '';
  const filtered = ARGUS_DATA.users.filter(u => {
    const matchQ = !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
    const matchR = !roleF || u.role.toLowerCase().includes(roleF);
    const matchT = !tenF  || u.tenant.toLowerCase().includes(tenF);
    return matchQ && matchR && matchT;
  });
  const wrap = document.getElementById('rbacUsersTable');
  if (wrap) wrap.innerHTML = renderRBACUsersTable(filtered);
}

function filterAuditLog(q) {
  q = q.toLowerCase();
  const filtered = RBAC_STORE.audit_log.filter(l =>
    l.user.toLowerCase().includes(q) || l.action.toLowerCase().includes(q) ||
    l.detail.toLowerCase().includes(q) || l.resource.toLowerCase().includes(q)
  );
  const wrap = document.getElementById('auditLogTable');
  if (wrap) wrap.innerHTML = renderAuditTable(filtered);
}

function exportAuditLog() {
  const rows = [['Time','User','Action','Resource','Detail','IP','Severity']];
  RBAC_STORE.audit_log.forEach(l => rows.push([l.time,l.user,l.action,l.resource,`"${l.detail}"`,l.ip,l.severity]));
  const csv = rows.map(r => r.join(',')).join('\n');
  downloadFile(`threatpilot_audit_log_${new Date().toISOString().slice(0,10)}.csv`, csv, 'text/csv');
  showToast('Audit log exported as CSV','success');
}

function exportRBACReport() {
  const data = { generated: new Date().toISOString(), users: ARGUS_DATA.users, roles: RBAC_STORE.roles, audit_log: RBAC_STORE.audit_log };
  downloadFile('threatpilot_rbac_report.json', JSON.stringify(data,null,2),'application/json');
  showToast('RBAC report exported','success');
}

function openRBACEditUser(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  const modal = document.createElement('div');
  modal.id = 'rbacEditOverlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:24px;width:480px;max-width:95vw;max-height:90vh;overflow-y:auto;">
      <div style="font-size:16px;font-weight:800;margin-bottom:4px;display:flex;align-items:center;gap:8px;"><i class="fas fa-user-cog" style="color:#3b82f6;"></i> Edit User Access</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:16px;">Manage role, permissions and tenant access for ${u.name}</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">FULL NAME</label>
          <input id="reu_name" value="${u.name}" class="settings-input" style="width:100%;"/></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">EMAIL</label>
          <input id="reu_email" value="${u.email}" class="settings-input" style="width:100%;"/></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">ROLE</label>
          <select id="reu_role" class="settings-input" style="width:100%;">
            ${RBAC_STORE.roles.map(r=>`<option value="${r.name}" ${u.role===r.name?'selected':''}>${r.name}</option>`).join('')}
          </select></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">TENANT</label>
          <select id="reu_tenant" class="settings-input" style="width:100%;">
            ${ARGUS_DATA.tenants.map(t=>`<option ${u.tenant===t.name?'selected':''}>${t.name}</option>`).join('')}
          </select></div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
          <div><div style="font-size:12px;font-weight:600;">MFA Required</div><div style="font-size:10px;color:var(--text-muted);">Enforce multi-factor authentication</div></div>
          <div id="reu_mfa" class="toggle-switch ${u.mfa?'on':''}" onclick="this.classList.toggle('on')"></div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
          <div><div style="font-size:12px;font-weight:600;">API Access</div><div style="font-size:10px;color:var(--text-muted);">Allow REST API token generation</div></div>
          <div class="toggle-switch on" onclick="this.classList.toggle('on')"></div>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn-primary" style="flex:1;" onclick="saveRBACEditUser('${u.id}')"><i class="fas fa-save"></i> Save Changes</button>
        <button onclick="document.getElementById('rbacEditOverlay').remove()" style="padding:7px 16px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if(e.target===modal) modal.remove(); });
}

function saveRBACEditUser(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  const name   = document.getElementById('reu_name')?.value.trim();
  const email  = document.getElementById('reu_email')?.value.trim();
  const role   = document.getElementById('reu_role')?.value;
  const tenant = document.getElementById('reu_tenant')?.value;
  const mfa    = document.getElementById('reu_mfa')?.classList.contains('on');
  if (!name||!email) { showToast('Name and email required','error'); return; }
  Object.assign(u,{name,email,role,tenant,mfa,avatar:name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()});
  RBAC_STORE.audit_log.unshift({id:'AL'+Date.now(),user:CURRENT_USER?.name||'Admin',action:'Role Change',resource:userId,detail:`Updated ${name} — role: ${role}`,time:'Just now',ip:'localhost',severity:'warning'});
  document.getElementById('rbacEditOverlay')?.remove();
  showToast(`User ${name} updated!`,'success');
  renderRBACAdmin();
}

function openModuleAccessModal(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  const roleObj = RBAC_STORE.roles.find(r => r.name === u.role || r.slug.toUpperCase() === u.role);
  const allModules = ['command-center','findings','campaigns','detections','threat-actors','dark-web','exposure','ioc-registry','ioc-database','ai-orchestrator','collectors','playbooks','edr-siem','sysmon','customers','reports','settings','executive-dashboard','kill-chain','case-management','threat-hunting','detection-engineering','soar','live-feeds','cyber-news','mitre-attack','geo-threats','rbac-admin','branding','pricing'];
  const modal = document.createElement('div');
  modal.id = 'moduleAccessOverlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:24px;width:540px;max-width:95vw;max-height:85vh;overflow-y:auto;">
      <div style="font-size:16px;font-weight:800;margin-bottom:4px;"><i class="fas fa-th" style="color:#a855f7;"></i> Module Access — ${u.name}</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:16px;">Select which modules this user can access (inherited from role: ${u.role})</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:16px;">
        ${allModules.map(m => {
          const hasAccess = roleObj?.modules.includes(m);
          return `<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 10px;background:var(--bg-surface);border:1px solid ${hasAccess?'rgba(34,197,94,0.3)':'var(--border)'};border-radius:var(--radius);">
            <span style="font-size:11px;font-weight:${hasAccess?'600':'400'};color:${hasAccess?'var(--text-primary)':'var(--text-muted)'};">${m}</span>
            <div class="toggle-switch ${hasAccess?'on':''}" style="transform:scale(0.8);" onclick="this.classList.toggle('on')"></div>
          </div>`;
        }).join('')}
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn-primary" style="flex:1;" onclick="showToast('Module access saved for ${u.name}','success');document.getElementById('moduleAccessOverlay').remove()"><i class="fas fa-save"></i> Save Access</button>
        <button onclick="document.getElementById('moduleAccessOverlay').remove()" style="padding:7px 16px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if(e.target===modal) modal.remove(); });
}

function openCreateRoleModal() {
  const modal = document.createElement('div');
  modal.id = 'createRoleOverlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:24px;width:480px;max-width:95vw;">
      <div style="font-size:16px;font-weight:800;margin-bottom:16px;"><i class="fas fa-plus-circle" style="color:#a855f7;"></i> Create Custom Role</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">ROLE NAME *</label>
          <input id="cr_name" class="settings-input" style="width:100%;" placeholder="e.g., Dark Web Analyst"/></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">DESCRIPTION</label>
          <textarea id="cr_desc" class="settings-input" style="width:100%;resize:vertical;" rows="2" placeholder="Describe what this role can do..."></textarea></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">BASE PERMISSIONS</label>
          <div style="display:flex;flex-wrap:wrap;gap:6px;">
            ${['read','write','investigate','export','manage_users','manage_collectors','audit'].map(p=>`
              <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:11px;">
                <input type="checkbox" value="${p}" class="cr_perm" ${p==='read'?'checked':''}> ${p}
              </label>`).join('')}
          </div>
        </div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:700;display:block;margin-bottom:4px;">ROLE COLOR</label>
          <div style="display:flex;gap:8px;">
            ${['#ef4444','#f97316','#3b82f6','#22c55e','#a855f7','#22d3ee','#f59e0b','#ec4899'].map(c=>`
              <div onclick="this.parentElement.querySelectorAll('div').forEach(d=>d.style.outline='none');this.style.outline='2px solid white';" style="width:24px;height:24px;border-radius:50%;background:${c};cursor:pointer;"></div>`).join('')}
          </div>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn-primary" style="flex:1;" onclick="createCustomRole()"><i class="fas fa-save"></i> Create Role</button>
        <button onclick="document.getElementById('createRoleOverlay').remove()" style="padding:7px 16px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click',e=>{if(e.target===modal)modal.remove();});
}

function createCustomRole() {
  const name = document.getElementById('cr_name')?.value.trim();
  if (!name) { showToast('Role name is required','error'); return; }
  const perms = [...document.querySelectorAll('.cr_perm:checked')].map(c=>c.value);
  const newRole = {
    id: 'R'+String(RBAC_STORE.roles.length+1).padStart(3,'0'),
    name, slug: name.toLowerCase().replace(/\s+/g,'_'),
    color: '#3b82f6', desc: document.getElementById('cr_desc')?.value || '',
    permissions: perms, modules: ['command-center','findings']
  };
  RBAC_STORE.roles.push(newRole);
  document.getElementById('createRoleOverlay')?.remove();
  showToast(`Role "${name}" created!`,'success');
  renderRBACAdmin();
}

function editRole(roleId) {
  const role = RBAC_STORE.roles.find(r=>r.id===roleId);
  if (!role) return;
  showToast(`Editing role: ${role.name}`,'info');
  openCreateRoleModal();
}
