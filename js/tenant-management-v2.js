/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Tenant Management v2.0 (Full CRUD)
 *  FILE: js/tenant-management-v2.js
 *
 *  Full Create/Read/Update/Delete with DB persistence.
 *  Real-time UI sync. Role-based access controls.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

let _tenantState = {
  tenants: [],
  loading: false,
  editingId: null,
};

const TENANT_PLANS = ['free', 'starter', 'professional', 'enterprise'];
const RISK_LEVELS  = ['low', 'medium', 'high', 'critical'];
const PLAN_COLORS  = { free: '#6b7280', starter: '#3b82f6', professional: '#a855f7', enterprise: '#f59e0b' };

/* ════════════════════════════════════════════════════════════════
   MAIN RENDER
════════════════════════════════════════════════════════════════ */
window.renderTenantsPage = function() {
  const el = document.getElementById('page-customers');
  if (!el) return;

  el.innerHTML = `
  <div style="padding:0;background:#0a0e17;min-height:100vh;font-family:'Inter',sans-serif;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0f172a,#1e293b);border-bottom:1px solid #1e293b;padding:24px 28px 20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
        <div style="display:flex;align-items:center;gap:14px;">
          <div style="width:48px;height:48px;background:linear-gradient(135deg,#3b82f6,#2563eb);border-radius:12px;display:flex;align-items:center;justify-content:center;">
            <i class="fas fa-building" style="color:#fff;font-size:20px;"></i>
          </div>
          <div>
            <h1 style="margin:0;font-size:1.5rem;font-weight:800;color:#f1f5f9;">Tenant Management</h1>
            <div style="font-size:12px;color:#64748b;margin-top:2px;">Multi-tenant isolation · Role-based access · Real-time sync</div>
          </div>
        </div>
        <button onclick="tenantShowCreateModal()"
          style="background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;border:none;padding:10px 20px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px;box-shadow:0 4px 14px rgba(59,130,246,.3);">
          <i class="fas fa-plus"></i> New Tenant
        </button>
      </div>
      <!-- KPIs -->
      <div id="tenant-kpis" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:18px;">
        ${['Total Tenants','Active','Enterprise','Critical Risk'].map(k => `
        <div style="background:rgba(15,23,42,.6);border:1px solid #1e293b;border-radius:10px;padding:14px 16px;">
          <div style="font-size:10px;color:#64748b;font-weight:700;text-transform:uppercase;">${k}</div>
          <div id="kpi-tenant-${k.replace(/ /g,'-').toLowerCase()}" style="font-size:1.8rem;font-weight:800;color:#3b82f6;margin-top:4px;">—</div>
        </div>`).join('')}
      </div>
    </div>

    <!-- Search & Filter Bar -->
    <div style="background:#0f172a;border-bottom:1px solid #1e293b;padding:14px 28px;">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <div style="position:relative;flex:1;min-width:200px;">
          <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#475569;font-size:12px;"></i>
          <input id="tenant-search" type="text" placeholder="Search tenants…" oninput="tenantSearch(this.value)"
            style="width:100%;background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:8px 10px 8px 30px;border-radius:8px;font-size:13px;outline:none;box-sizing:border-box;" />
        </div>
        <select id="tenant-filter-plan" onchange="tenantFilterPlan(this.value)"
          style="background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;cursor:pointer;outline:none;">
          <option value="">All Plans</option>
          ${TENANT_PLANS.map(p => `<option value="${p}">${p.charAt(0).toUpperCase()+p.slice(1)}</option>`).join('')}
        </select>
        <select id="tenant-filter-risk" onchange="tenantFilterRisk(this.value)"
          style="background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;cursor:pointer;outline:none;">
          <option value="">All Risk Levels</option>
          ${RISK_LEVELS.map(r => `<option value="${r}">${r.charAt(0).toUpperCase()+r.slice(1)}</option>`).join('')}
        </select>
        <button onclick="tenantLoadAll()" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:8px 12px;border-radius:8px;cursor:pointer;font-size:13px;">
          <i class="fas fa-sync-alt"></i>
        </button>
      </div>
    </div>

    <!-- Tenant List -->
    <div style="padding:24px 28px;">
      <div id="tenant-list-container">
        ${tenantLoadingSkeleton()}
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <div id="tenant-modal-overlay" onclick="if(event.target===this)tenantCloseModal()"
      style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;overflow-y:auto;padding:20px;">
      <div id="tenant-modal" style="background:#0f172a;border:1px solid #1e293b;border-radius:16px;max-width:600px;margin:0 auto;"></div>
    </div>

    <!-- Delete Confirm Modal -->
    <div id="tenant-delete-overlay" onclick="if(event.target===this)tenantCloseDelete()"
      style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:9999;display:none;align-items:center;justify-content:center;">
      <div id="tenant-delete-modal" style="background:#0f172a;border:1px solid #ef4444;border-radius:16px;max-width:440px;width:100%;margin:20px;padding:28px;"></div>
    </div>
  </div>`;

  tenantLoadAll();
};

/* ════════════════════════════════════════════════════════════════
   LOAD ALL TENANTS
════════════════════════════════════════════════════════════════ */
window.tenantLoadAll = async function() {
  _tenantState.loading = true;
  const container = document.getElementById('tenant-list-container');
  if (container) container.innerHTML = tenantLoadingSkeleton();

  try {
    const data = await window.apiGet?.('/api/tenants') || [];
    _tenantState.tenants = Array.isArray(data) ? data : (data.tenants || []);
    updateTenantKPIs();
    renderTenantList(_tenantState.tenants);
  } catch (e) {
    const container2 = document.getElementById('tenant-list-container');
    if (container2) container2.innerHTML = `<div style="text-align:center;padding:60px;color:#ef4444;">
      <i class="fas fa-exclamation-circle" style="font-size:2rem;margin-bottom:12px;display:block;"></i>
      <strong>Failed to load tenants</strong><br>
      <span style="color:#64748b;font-size:12px;">${e.message}</span>
    </div>`;
  } finally {
    _tenantState.loading = false;
  }
};

function tenantLoadingSkeleton() {
  return `<div>${Array(4).fill(0).map(() => `
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px;margin-bottom:12px;animation:pulse 1.5s infinite;">
    <div style="display:flex;gap:16px;align-items:center;">
      <div style="width:44px;height:44px;background:#1e293b;border-radius:10px;flex-shrink:0;"></div>
      <div style="flex:1;">
        <div style="width:180px;height:14px;background:#1e293b;border-radius:4px;margin-bottom:8px;"></div>
        <div style="width:120px;height:11px;background:#1e293b;border-radius:4px;"></div>
      </div>
    </div>
  </div>`).join('')}</div>`;
}

function updateTenantKPIs() {
  const tenants = _tenantState.tenants;
  const kpis = {
    'total-tenants': tenants.length,
    'active':        tenants.filter(t => t.active !== false).length,
    'enterprise':    tenants.filter(t => t.plan === 'enterprise').length,
    'critical-risk': tenants.filter(t => t.risk_level === 'critical' || t.risk_level === 'high').length,
  };
  for (const [k, v] of Object.entries(kpis)) {
    const el = document.getElementById(`kpi-tenant-${k}`);
    if (el) el.textContent = v;
  }
}

/* ════════════════════════════════════════════════════════════════
   RENDER TENANT LIST
════════════════════════════════════════════════════════════════ */
function renderTenantList(tenants) {
  const container = document.getElementById('tenant-list-container');
  if (!container) return;

  if (!tenants || tenants.length === 0) {
    container.innerHTML = `<div style="text-align:center;padding:80px;color:#475569;">
      <i class="fas fa-building" style="font-size:3rem;margin-bottom:16px;display:block;opacity:.2;"></i>
      <div style="font-size:1rem;font-weight:600;color:#64748b;">No tenants found</div>
      <button onclick="tenantShowCreateModal()" style="margin-top:16px;background:#3b82f6;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;">
        <i class="fas fa-plus" style="margin-right:5px;"></i>Create First Tenant
      </button>
    </div>`;
    return;
  }

  container.innerHTML = tenants.map(t => renderTenantCard(t)).join('');
}

function planBadge(plan) {
  const c = PLAN_COLORS[plan] || '#6b7280';
  return `<span style="background:${c}20;color:${c};border:1px solid ${c}40;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase;">${plan}</span>`;
}
function riskBadge(level) {
  const map = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' };
  const c = map[level] || '#6b7280';
  return `<span style="background:${c}20;color:${c};padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase;">${level}</span>`;
}

function renderTenantCard(t) {
  const initials = (t.short_name || t.name || 'T').slice(0, 2).toUpperCase();
  const isActive = t.active !== false;
  return `
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px;margin-bottom:12px;transition:border-color .2s;"
    onmouseover="this.style.borderColor='#334155'" onmouseout="this.style.borderColor='#1e293b'">
    <div style="display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap;">
      <!-- Avatar -->
      <div style="width:48px;height:48px;background:linear-gradient(135deg,#1e40af,#3b82f6);border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <span style="color:#fff;font-weight:800;font-size:16px;">${initials}</span>
      </div>
      <!-- Info -->
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
          <span style="font-size:16px;font-weight:700;color:#f1f5f9;">${escHtml(t.name)}</span>
          ${!isActive ? `<span style="background:rgba(107,114,128,.2);color:#6b7280;font-size:10px;padding:2px 6px;border-radius:4px;">INACTIVE</span>` : ''}
          ${planBadge(t.plan || 'free')}
          ${riskBadge(t.risk_level || 'low')}
        </div>
        <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:#64748b;">
          ${t.domain ? `<span><i class="fas fa-globe" style="margin-right:4px;color:#3b82f6;"></i>${escHtml(t.domain)}</span>` : ''}
          ${t.contact_email ? `<span><i class="fas fa-envelope" style="margin-right:4px;color:#3b82f6;"></i>${escHtml(t.contact_email)}</span>` : ''}
          ${t.created_at ? `<span><i class="fas fa-calendar" style="margin-right:4px;color:#475569;"></i>Created ${new Date(t.created_at).toLocaleDateString()}</span>` : ''}
        </div>
      </div>
      <!-- Actions -->
      <div style="display:flex;gap:8px;flex-shrink:0;">
        <button onclick="tenantShowEditModal('${t.id}')" title="Edit"
          style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px 12px;border-radius:8px;cursor:pointer;font-size:12px;transition:.15s;"
          onmouseover="this.style.background='#334155'" onmouseout="this.style.background='#1e293b'">
          <i class="fas fa-edit"></i>
        </button>
        <button onclick="tenantToggleActive('${t.id}', ${!isActive})" title="${isActive ? 'Deactivate' : 'Activate'}"
          style="background:#1e293b;color:${isActive?'#22c55e':'#f59e0b'};border:1px solid ${isActive?'#16a34a40':'#d97706'};padding:8px 12px;border-radius:8px;cursor:pointer;font-size:12px;">
          <i class="fas fa-${isActive ? 'pause' : 'play'}"></i>
        </button>
        <button onclick="tenantShowDeleteConfirm('${t.id}', '${escHtml(t.name)}')" title="Delete"
          style="background:#1e293b;color:#ef4444;border:1px solid #ef444440;padding:8px 12px;border-radius:8px;cursor:pointer;font-size:12px;">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    </div>
    <!-- Settings preview -->
    ${t.settings ? `
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid #1e293b;display:flex;gap:10px;flex-wrap:wrap;">
      ${t.settings.alerts_enabled !== undefined ? `<span style="background:#1e293b;color:#64748b;padding:3px 8px;border-radius:6px;font-size:10px;"><i class="fas fa-bell" style="margin-right:3px;color:${t.settings.alerts_enabled?'#22c55e':'#475569'};"></i>Alerts ${t.settings.alerts_enabled?'ON':'OFF'}</span>` : ''}
      ${t.settings.auto_playbooks !== undefined ? `<span style="background:#1e293b;color:#64748b;padding:3px 8px;border-radius:6px;font-size:10px;"><i class="fas fa-bolt" style="margin-right:3px;color:${t.settings.auto_playbooks?'#f59e0b':'#475569'};"></i>Auto Playbooks ${t.settings.auto_playbooks?'ON':'OFF'}</span>` : ''}
    </div>` : ''}
  </div>`;
}

/* ════════════════════════════════════════════════════════════════
   CREATE/EDIT MODAL
════════════════════════════════════════════════════════════════ */
window.tenantShowCreateModal = function() {
  _tenantState.editingId = null;
  openTenantModal(null);
};
window.tenantShowEditModal = function(id) {
  const t = _tenantState.tenants.find(t => t.id === id);
  if (!t) return;
  _tenantState.editingId = id;
  openTenantModal(t);
};

function openTenantModal(tenant) {
  const overlay = document.getElementById('tenant-modal-overlay');
  const modal   = document.getElementById('tenant-modal');
  if (!overlay || !modal) return;
  overlay.style.display = 'block';

  const isEdit = !!tenant;
  modal.innerHTML = `
  <div style="padding:28px;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
      <h2 style="margin:0;font-size:1.2rem;font-weight:800;color:#f1f5f9;">
        <i class="fas fa-${isEdit?'edit':'plus-circle'}" style="color:#3b82f6;margin-right:8px;"></i>
        ${isEdit ? 'Edit Tenant' : 'Create New Tenant'}
      </h2>
      <button onclick="tenantCloseModal()" style="background:none;border:none;color:#64748b;cursor:pointer;font-size:18px;"><i class="fas fa-times"></i></button>
    </div>
    <div id="tenant-form-error" style="display:none;background:rgba(239,68,68,.1);border:1px solid #ef4444;border-radius:8px;padding:10px 14px;color:#ef4444;font-size:13px;margin-bottom:16px;"></div>
    <div style="display:flex;flex-direction:column;gap:16px;">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        ${tgField('name', 'Tenant Name *', tenant?.name || '', 'text', 'Acme Corporation')}
        ${tgField('short_name', 'Short Name', tenant?.short_name || '', 'text', 'ACME')}
      </div>
      ${tgField('domain', 'Domain *', tenant?.domain || '', 'text', 'acme.com')}
      ${tgField('contact_email', 'Contact Email', tenant?.contact_email || '', 'email', 'admin@acme.com')}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
          <label style="display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;">Plan</label>
          <select id="tf-plan" style="width:100%;background:#090d14;border:1px solid #1e293b;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:13px;outline:none;cursor:pointer;">
            ${TENANT_PLANS.map(p => `<option value="${p}" ${tenant?.plan===p?'selected':''}>${p.charAt(0).toUpperCase()+p.slice(1)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label style="display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;">Risk Level</label>
          <select id="tf-risk_level" style="width:100%;background:#090d14;border:1px solid #1e293b;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:13px;outline:none;cursor:pointer;">
            ${RISK_LEVELS.map(r => `<option value="${r}" ${tenant?.risk_level===r?'selected':''}>${r.charAt(0).toUpperCase()+r.slice(1)}</option>`).join('')}
          </select>
        </div>
      </div>
      <div>
        <label style="display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;">Active Status</label>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
          <input type="checkbox" id="tf-active" ${tenant?.active !== false ? 'checked' : ''}
            style="width:16px;height:16px;accent-color:#3b82f6;cursor:pointer;" />
          <span style="font-size:13px;color:#e2e8f0;">Tenant is active</span>
        </label>
      </div>
      <div style="background:#090d14;border:1px solid #1e293b;border-radius:10px;padding:14px;">
        <div style="font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:10px;">Default Settings</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
            <input type="checkbox" id="tf-alerts_enabled" ${(tenant?.settings?.alerts_enabled !== false) ? 'checked' : ''}
              style="width:14px;height:14px;accent-color:#22c55e;cursor:pointer;" />
            <span style="font-size:13px;color:#e2e8f0;">Enable alerts</span>
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
            <input type="checkbox" id="tf-auto_playbooks" ${tenant?.settings?.auto_playbooks ? 'checked' : ''}
              style="width:14px;height:14px;accent-color:#f59e0b;cursor:pointer;" />
            <span style="font-size:13px;color:#e2e8f0;">Auto-run playbooks</span>
          </label>
        </div>
      </div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:24px;">
      <button onclick="tenantCloseModal()" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;">Cancel</button>
      <button id="tenant-save-btn" onclick="tenantSave()" style="background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700;display:flex;align-items:center;gap:6px;">
        <i class="fas fa-save"></i> ${isEdit ? 'Save Changes' : 'Create Tenant'}
      </button>
    </div>
  </div>`;
}

function tgField(id, label, value, type, placeholder) {
  return `<div>
    <label style="display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:6px;">${label}</label>
    <input id="tf-${id}" type="${type}" value="${escHtml(value)}" placeholder="${placeholder}"
      style="width:100%;background:#090d14;border:1px solid #1e293b;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:13px;outline:none;box-sizing:border-box;transition:.15s;"
      onfocus="this.style.borderColor='#3b82f6'" onblur="this.style.borderColor='#1e293b'" />
  </div>`;
}

window.tenantSave = async function() {
  const btn = document.getElementById('tenant-save-btn');
  const errEl = document.getElementById('tenant-form-error');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving…'; }
  if (errEl) errEl.style.display = 'none';

  const v = id => document.getElementById(`tf-${id}`);
  const payload = {
    name:          v('name')?.value?.trim(),
    short_name:    v('short_name')?.value?.trim(),
    domain:        v('domain')?.value?.trim().toLowerCase(),
    contact_email: v('contact_email')?.value?.trim().toLowerCase(),
    plan:          v('plan')?.value,
    risk_level:    v('risk_level')?.value,
    active:        v('active')?.checked ?? true,
    settings: {
      alerts_enabled: v('alerts_enabled')?.checked ?? true,
      auto_playbooks: v('auto_playbooks')?.checked ?? false,
    },
  };

  if (!payload.name) { showTenantFormError('Tenant name is required'); if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-save"></i> Save'; } return; }
  if (!payload.domain) { showTenantFormError('Domain is required'); if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-save"></i> Save'; } return; }

  try {
    const isEdit = !!_tenantState.editingId;
    if (isEdit) {
      await window.apiPatch?.(`/api/tenants/${_tenantState.editingId}`, payload);
    } else {
      await window.apiPost?.('/api/tenants', payload);
    }
    tenantCloseModal();
    await tenantLoadAll();
    window._showToast?.(`Tenant ${isEdit?'updated':'created'} successfully`, 'success');
  } catch (e) {
    showTenantFormError(e.message || 'Failed to save tenant');
    if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-save"></i> Save'; }
  }
};

function showTenantFormError(msg) {
  const errEl = document.getElementById('tenant-form-error');
  if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
}

window.tenantCloseModal = function() {
  const overlay = document.getElementById('tenant-modal-overlay');
  if (overlay) overlay.style.display = 'none';
  _tenantState.editingId = null;
};

/* ════════════════════════════════════════════════════════════════
   TOGGLE ACTIVE
════════════════════════════════════════════════════════════════ */
window.tenantToggleActive = async function(id, newActive) {
  try {
    await window.apiPatch?.(`/api/tenants/${id}`, { active: newActive });
    await tenantLoadAll();
    window._showToast?.(`Tenant ${newActive ? 'activated' : 'deactivated'}`, 'success');
  } catch (e) {
    window._showToast?.(e.message || 'Failed to update tenant', 'error');
  }
};

/* ════════════════════════════════════════════════════════════════
   DELETE
════════════════════════════════════════════════════════════════ */
window.tenantShowDeleteConfirm = function(id, name) {
  const overlay = document.getElementById('tenant-delete-overlay');
  const modal   = document.getElementById('tenant-delete-modal');
  if (!overlay || !modal) return;
  overlay.style.display = 'flex';
  modal.innerHTML = `
  <div style="text-align:center;">
    <div style="width:56px;height:56px;background:rgba(239,68,68,.15);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;">
      <i class="fas fa-exclamation-triangle" style="color:#ef4444;font-size:22px;"></i>
    </div>
    <h3 style="margin:0 0 8px;font-size:1.1rem;font-weight:800;color:#f1f5f9;">Delete Tenant</h3>
    <p style="margin:0 0 6px;font-size:14px;color:#94a3b8;">You are about to permanently delete:</p>
    <p style="margin:0 0 20px;font-size:16px;font-weight:700;color:#ef4444;">"${escHtml(name)}"</p>
    <p style="margin:0 0 24px;font-size:12px;color:#64748b;">This will remove all tenant data, users, alerts, and configurations. This action cannot be undone.</p>
    <div style="display:flex;gap:10px;justify-content:center;">
      <button onclick="tenantCloseDelete()" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;flex:1;">Cancel</button>
      <button onclick="tenantDeleteConfirmed('${id}')" style="background:#ef4444;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700;flex:1;display:flex;align-items:center;justify-content:center;gap:5px;">
        <i class="fas fa-trash"></i> Delete
      </button>
    </div>
  </div>`;
};
window.tenantCloseDelete = function() {
  const overlay = document.getElementById('tenant-delete-overlay');
  if (overlay) overlay.style.display = 'none';
};
window.tenantDeleteConfirmed = async function(id) {
  try {
    await window.apiDelete?.(`/api/tenants/${id}`);
    tenantCloseDelete();
    await tenantLoadAll();
    window._showToast?.('Tenant deleted successfully', 'success');
  } catch (e) {
    window._showToast?.(e.message || 'Failed to delete tenant', 'error');
  }
};

/* ════════════════════════════════════════════════════════════════
   SEARCH & FILTER
════════════════════════════════════════════════════════════════ */
let _tFilter = { plan: '', risk: '', search: '' };
window.tenantSearch = function(q) {
  _tFilter.search = q;
  applyTenantFilters();
};
window.tenantFilterPlan = function(plan) {
  _tFilter.plan = plan;
  applyTenantFilters();
};
window.tenantFilterRisk = function(risk) {
  _tFilter.risk = risk;
  applyTenantFilters();
};
function applyTenantFilters() {
  let filtered = _tenantState.tenants;
  if (_tFilter.search) {
    const q = _tFilter.search.toLowerCase();
    filtered = filtered.filter(t => t.name?.toLowerCase().includes(q) || t.domain?.toLowerCase().includes(q));
  }
  if (_tFilter.plan) filtered = filtered.filter(t => t.plan === _tFilter.plan);
  if (_tFilter.risk) filtered = filtered.filter(t => t.risk_level === _tFilter.risk);
  renderTenantList(filtered);
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
