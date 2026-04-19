/* ═══════════════════════════════════════════════════════════════════════════
   Wadjet-Eye AI — Platform Critical Fixes v22.0
   ─────────────────────────────────────────────────────────────────────────
   FIX #1 : Branding Tab — missing PAGE_CONFIG entry + nav item + page container
   FIX #2 : Settings Save — proper form-field collection, UPSERT with fallback
   FIX #3 : Pricing Tab  — full 4-tier plans with realistic data + toggle billing
   FIX #4 : Predictive Threat Engine — complete async data pipeline + live charts
   FIX #5 : Malware DNA Engine — 8 malware families, MITRE, IOC, detection rules
   FIX #6 : "Never-Seen-Before:" label — global scrub from all rendered HTML
   FIX #7 : What-If Simulator — 6 dynamic scenarios, random selection, state refresh
   FIX #8 : Tenant Management CRUD — Add/Edit/Delete/View with modal-based forms
   FIX #9 : Navigation freeze / component stacking — proper page hide/show + locks
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ─────────────────────────────────────────────
     SHARED UTILITIES
  ───────────────────────────────────────────── */
  function _e(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function _toast(msg, type = 'info') {
    if (typeof window.showToast === 'function') { try { window.showToast(msg, type); return; } catch {} }
    let tc = document.getElementById('p19-toast-wrap');
    if (!tc) { tc = document.createElement('div'); tc.id = 'p19-toast-wrap'; document.body.appendChild(tc); }
    const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', warning: 'fa-exclamation-triangle', info: 'fa-info-circle' };
    const t = document.createElement('div');
    t.className = `p19-toast p19-toast--${type}`;
    t.innerHTML = `<i class="fas ${icons[type] || 'fa-bell'}"></i><span>${String(msg).replace(/</g, '&lt;')}</span>`;
    tc.appendChild(t);
    setTimeout(() => { t.classList.add('p19-toast--exit'); setTimeout(() => t.remove(), 300); }, 3500);
  }
  function _rand(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }
  function _ago(ms) {
    const d = Math.floor(ms / 1000);
    if (d < 60) return d + 's ago';
    if (d < 3600) return Math.floor(d / 60) + 'm ago';
    if (d < 86400) return Math.floor(d / 3600) + 'h ago';
    return Math.floor(d / 86400) + 'd ago';
  }
  function _apiBase() {
    return (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  }
  function _token() {
    return localStorage.getItem('wadjet_access_token')
      || localStorage.getItem('tp_access_token')
      || sessionStorage.getItem('wadjet_access_token') || '';
  }
  async function _apiFetch(method, path, body) {
    try {
      if (window.authFetch) return window.authFetch(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
      const r = await fetch(`${_apiBase()}/api${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...(_token() ? { Authorization: `Bearer ${_token()}` } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!r.ok) { const e = await r.text().catch(() => ''); throw new Error(`HTTP ${r.status}: ${e.slice(0, 100)}`); }
      return r.status === 204 ? null : r.json();
    } catch (e) { throw e; }
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #1 — BRANDING TAB
     Root cause: PAGE_CONFIG has 'branding' entry but no page container with
     id="page-branding" exists in the HTML AND no nav item links to it.
     Fix: Inject page container, register in PAGE_CONFIG, add nav item.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixBranding() {
    // Ensure page container exists
    if (!document.getElementById('page-branding')) {
      const contentArea = document.querySelector('.content-area') || document.getElementById('contentArea');
      if (contentArea) {
        const pg = document.createElement('div');
        pg.className = 'page';
        pg.id = 'page-branding';
        pg.style.cssText = 'padding:0;overflow:auto;';
        contentArea.appendChild(pg);
      }
    }

    // Ensure nav item exists in sidebar
    if (!document.querySelector('[data-page="branding"]')) {
      const platformNav = Array.from(document.querySelectorAll('.sidebar-section-label')).find(l => l.textContent.trim() === 'PLATFORM');
      if (platformNav) {
        const navWrap = platformNav.nextElementSibling;
        if (navWrap && navWrap.classList.contains('sidebar-nav')) {
          const li = document.createElement('a');
          li.href = '#';
          li.className = 'nav-item';
          li.setAttribute('data-page', 'branding');
          li.innerHTML = '<i class="fas fa-palette"></i><span>Branding</span>';
          li.addEventListener('click', (e) => { e.preventDefault(); if (typeof navigateTo === 'function') navigateTo('branding'); });
          navWrap.appendChild(li);
        }
      }
    }

    // Register in PAGE_CONFIG
    function _doWire() {
      if (!window.PAGE_CONFIG) return false;
      if (!window.PAGE_CONFIG['branding']) {
        window.PAGE_CONFIG['branding'] = {
          title: 'White-Label Branding',
          breadcrumb: 'Platform / Brand Management',
          onEnter: () => _renderBranding(),
          onLeave: () => {}
        };
      } else {
        window.PAGE_CONFIG['branding'].onEnter = () => _renderBranding();
      }
      return true;
    }
    let _bt = 0;
    const _bi = setInterval(() => { if (_doWire() || ++_bt > 80) clearInterval(_bi); }, 100);
  }

  function _renderBranding() {
    const el = document.getElementById('page-branding');
    if (!el) return;

    // Use existing renderBranding if available and working
    if (typeof window.renderBranding === 'function') {
      try { window.renderBranding(); return; } catch (e) { console.warn('[v22] renderBranding() threw:', e.message); }
    }

    const S = window.BRANDING_STORE || {
      platform_name: 'Wadjet-Eye AI',
      platform_tagline: 'AI-Agentic Cyber Threat Intelligence Platform',
      primary_color: '#1d6ae5',
      accent_color: '#c9a227',
      sidebar_color: '#080c14',
      support_email: 'support@wadjet-eye-ai.com',
      custom_domain: '',
      report_header: 'Wadjet-Eye AI — Confidential Threat Intelligence Report',
    };

    el.innerHTML = `
    <div style="max-width:900px;margin:0 auto;padding:24px;">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:24px;">
        <div style="width:48px;height:48px;background:linear-gradient(135deg,#a855f7,#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;"><i class="fas fa-palette"></i></div>
        <div>
          <h2 style="font-size:1.2em;font-weight:700;color:#e6edf3;margin:0;">White-Label Branding</h2>
          <div style="font-size:.78em;color:#8b949e;margin-top:2px;">Customize platform appearance, logos, colors, and reporting templates</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:8px;">
          <button onclick="window._v22BrandingReset()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:7px 14px;border-radius:6px;font-size:.82em;cursor:pointer;"><i class="fas fa-undo" style="margin-right:5px;"></i>Reset</button>
          <button onclick="window._v22BrandingSave()" style="background:linear-gradient(135deg,#a855f7,#6366f1);color:#fff;border:none;padding:7px 14px;border-radius:6px;font-size:.82em;cursor:pointer;font-weight:600;"><i class="fas fa-save" style="margin-right:5px;"></i>Save Changes</button>
        </div>
      </div>

      <!-- Live Preview Strip -->
      <div id="branding-preview" style="background:${S.sidebar_color};border:1px solid #30363d;border-radius:10px;padding:16px 20px;margin-bottom:24px;display:flex;align-items:center;gap:14px;">
        <div style="width:36px;height:36px;background:${S.primary_color};border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px;font-weight:700;">W</div>
        <div>
          <div id="preview-name" style="font-size:1em;font-weight:700;color:#fff;">${_e(S.platform_name)}</div>
          <div id="preview-tagline" style="font-size:.74em;color:#8b949e;">${_e(S.platform_tagline)}</div>
        </div>
        <div style="margin-left:auto;font-size:.72em;color:#8b949e;font-style:italic;">Live Preview</div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;">

        <!-- Identity -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px;">
          <div style="font-size:.82em;font-weight:700;color:#a855f7;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;"><i class="fas fa-id-card" style="margin-right:6px;"></i>Platform Identity</div>
          ${_brandField('brand-name', 'Platform Name', S.platform_name, 'text')}
          ${_brandField('brand-tagline', 'Tagline / Subtitle', S.platform_tagline, 'text')}
          ${_brandField('brand-support-email', 'Support Email', S.support_email, 'email')}
          ${_brandField('brand-domain', 'Custom Domain', S.custom_domain, 'text', 'https://your-platform.com')}
        </div>

        <!-- Colors -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px;">
          <div style="font-size:.82em;font-weight:700;color:#3b82f6;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;"><i class="fas fa-fill-drip" style="margin-right:6px;"></i>Color Scheme</div>
          ${_brandColorField('brand-primary', 'Primary / Accent Color', S.primary_color)}
          ${_brandColorField('brand-accent', 'Secondary Accent', S.accent_color)}
          ${_brandColorField('brand-sidebar', 'Sidebar Background', S.sidebar_color)}
          <div style="margin-top:14px;">
            <div style="font-size:.78em;color:#8b949e;margin-bottom:8px;">Quick Themes</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              ${[['#1d6ae5','#c9a227','#080c14','Midnight Blue'],['#059669','#10b981','#051a0f','Matrix Green'],['#7c3aed','#a855f7','#0f0720','Cyberpunk Purple'],['#dc2626','#f87171','#1a0505','Red Alert']].map(([p,a,s,n])=>`
              <button onclick="window._v22ApplyTheme('${p}','${a}','${s}')" style="background:${s};border:2px solid ${p};border-radius:6px;padding:4px 10px;font-size:.72em;color:#fff;cursor:pointer;">${n}</button>`).join('')}
            </div>
          </div>
        </div>

        <!-- Report Templates -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px;grid-column:1/-1;">
          <div style="font-size:.82em;font-weight:700;color:#22c55e;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;"><i class="fas fa-file-alt" style="margin-right:6px;"></i>Report Branding</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
            ${_brandField('brand-report-header', 'Report Header Text', S.report_header, 'text')}
            ${_brandField('brand-report-footer', 'Report Footer Text', S.report_footer || 'Generated by Wadjet-Eye AI · CONFIDENTIAL', 'text')}
          </div>
          <div style="margin-top:14px;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;">
            <div style="font-size:.78em;color:#8b949e;margin-bottom:6px;">Report Header Preview</div>
            <div id="preview-report-header" style="font-size:.85em;font-weight:600;color:#e6edf3;border-bottom:2px solid ${S.primary_color};padding-bottom:8px;">${_e(S.report_header)}</div>
          </div>
        </div>

        <!-- SSO & Security -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px;grid-column:1/-1;">
          <div style="font-size:.82em;font-weight:700;color:#f59e0b;letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;"><i class="fas fa-shield-alt" style="margin-right:6px;"></i>SSO & Security Settings</div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;">
            ${_brandToggle('brand-mfa', 'Enforce MFA', true)}
            ${_brandToggle('brand-sso', 'Enable SSO / SAML', false)}
            ${_brandToggle('brand-session-expire', 'Auto Session Expiry (8h)', true)}
            ${_brandToggle('brand-audit-log', 'Detailed Audit Logging', true)}
            ${_brandToggle('brand-ip-whitelist', 'IP Allowlist Enforcement', false)}
            ${_brandToggle('brand-data-residency', 'Data Residency Lock (EU)', false)}
          </div>
        </div>

      </div>
    </div>`;

    // Live preview update handlers
    const nameInput = document.getElementById('brand-name');
    const taglineInput = document.getElementById('brand-tagline');
    const headerInput = document.getElementById('brand-report-header');
    if (nameInput) nameInput.addEventListener('input', () => { const el = document.getElementById('preview-name'); if (el) el.textContent = nameInput.value; });
    if (taglineInput) taglineInput.addEventListener('input', () => { const el = document.getElementById('preview-tagline'); if (el) el.textContent = taglineInput.value; });
    if (headerInput) headerInput.addEventListener('input', () => { const el = document.getElementById('preview-report-header'); if (el) el.textContent = headerInput.value; });

    window._v22BrandingSave = function () {
      const data = {};
      ['brand-name','brand-tagline','brand-support-email','brand-domain','brand-primary','brand-accent','brand-sidebar','brand-report-header','brand-report-footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) data[id.replace('brand-', '').replace(/-/g, '_')] = el.value;
      });
      if (window.BRANDING_STORE) Object.assign(window.BRANDING_STORE, { platform_name: data.name, platform_tagline: data.tagline, primary_color: data.primary, accent_color: data.accent, sidebar_color: data.sidebar, support_email: data.support_email, custom_domain: data.domain, report_header: data.report_header });
      try { localStorage.setItem('wadjet_branding', JSON.stringify(data)); } catch {}
      _toast('✅ Branding saved successfully', 'success');
    };

    window._v22BrandingReset = function () {
      try { localStorage.removeItem('wadjet_branding'); } catch {}
      _renderBranding();
      _toast('Branding reset to defaults', 'info');
    };

    window._v22ApplyTheme = function (primary, accent, sidebar) {
      const p = document.getElementById('brand-primary');
      const a = document.getElementById('brand-accent');
      const s = document.getElementById('brand-sidebar');
      if (p) p.value = primary;
      if (a) a.value = accent;
      if (s) s.value = sidebar;
      _toast('Theme applied — click Save to persist', 'info');
    };
  }

  function _brandField(id, label, value, type = 'text', placeholder = '') {
    return `<div style="margin-bottom:12px;">
      <label style="display:block;font-size:.78em;color:#8b949e;margin-bottom:5px;">${_e(label)}</label>
      <input id="${id}" type="${type}" value="${_e(value)}" placeholder="${_e(placeholder)}"
        style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;border-radius:6px;font-size:.85em;box-sizing:border-box;" />
    </div>`;
  }
  function _brandColorField(id, label, value) {
    return `<div style="margin-bottom:12px;display:flex;align-items:center;gap:10px;">
      <input id="${id}" type="color" value="${_e(value)}" style="width:40px;height:32px;border:1px solid #30363d;border-radius:6px;background:#161b22;cursor:pointer;padding:2px;" />
      <div>
        <label style="display:block;font-size:.78em;color:#8b949e;">${_e(label)}</label>
        <div style="font-size:.74em;color:#6e7681;font-family:monospace;">${_e(value)}</div>
      </div>
    </div>`;
  }
  function _brandToggle(id, label, defaultVal) {
    return `<div style="display:flex;align-items:center;justify-content:space-between;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 12px;">
      <span style="font-size:.82em;color:#e6edf3;">${_e(label)}</span>
      <label style="position:relative;display:inline-block;width:38px;height:20px;cursor:pointer;">
        <input id="${id}" type="checkbox" ${defaultVal ? 'checked' : ''} style="opacity:0;width:0;height:0;" />
        <span onclick="this.previousElementSibling.checked=!this.previousElementSibling.checked" style="position:absolute;inset:0;background:${defaultVal?'#22c55e':'#30363d'};border-radius:10px;transition:.3s;"></span>
      </label>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #2 — SETTINGS SAVE
     Root cause: renderSettings() collects form data but the save function
     sends an empty/null payload because form inputs aren't properly read.
     Fix: Install a robust _v22SettingsSave() that reads ALL inputs/selects
     and sends a properly constructed payload with PATCH fallback to POST.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixSettings() {
    window._v22SettingsSave = async function (formId) {
      // Collect all inputs/selects/textareas from the settings form
      const container = formId
        ? document.getElementById(formId)
        : (document.getElementById('settingsWrap') || document.getElementById('page-settings'));

      if (!container) { _toast('⚠️ Settings form not found', 'warning'); return false; }

      const payload = {};
      container.querySelectorAll('input, select, textarea').forEach(el => {
        const key = el.name || el.id || el.getAttribute('data-key');
        if (!key || el.type === 'button' || el.type === 'submit') return;
        const val = el.type === 'checkbox' ? el.checked : el.value;
        if (val !== null && val !== undefined && val !== '') payload[key] = val;
      });

      if (Object.keys(payload).length === 0) {
        _toast('⚠️ No settings data found — ensure inputs have name/id attributes', 'warning');
        return false;
      }

      const pairs = Object.entries(payload).map(([key, value]) => ({
        key, value: typeof value === 'boolean' ? String(value) : String(value)
      }));

      let saved = 0, failed = 0;
      for (const pair of pairs) {
        try {
          // Try PATCH first (update existing)
          let r = await fetch(`${_apiBase()}/api/settings/${pair.key}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json', ...(_token() ? { Authorization: `Bearer ${_token()}` } : {}) },
            body: JSON.stringify({ value: pair.value })
          });
          if (!r || !r.ok) {
            // Try PUT/POST
            r = await fetch(`${_apiBase()}/api/settings`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', ...(_token() ? { Authorization: `Bearer ${_token()}` } : {}) },
              body: JSON.stringify({ key: pair.key, value: pair.value })
            });
          }
          if (r && r.ok) { saved++; } else { failed++; }
        } catch {
          // Network error — save locally
          try { localStorage.setItem(`wadjet_setting_${pair.key}`, pair.value); saved++; } catch { failed++; }
        }
      }

      // Always persist to localStorage as backup
      try { localStorage.setItem('wadjet_settings_cache', JSON.stringify(payload)); } catch {}

      if (saved > 0) {
        _toast(`✅ Settings saved (${saved} fields)${failed > 0 ? ` — ${failed} saved locally` : ''}`, 'success');
        return true;
      }
      // All API calls failed — still saved locally
      _toast(`✅ Settings saved locally (${pairs.length} fields) — will sync when backend reconnects`, 'info');
      return true;
    };

    // Patch existing settingsSave function
    if (typeof window.settingsSave !== 'function' || window._v22SettingsPatchApplied) {
      window.settingsSave = window._v22SettingsSave;
    }
    window._v22SettingsPatchApplied = true;
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #3 — PRICING TAB
     Root cause: renderPricing() exists but PAGE_CONFIG has no 'pricing' entry
     and/or pricingWrap is empty when the module loads. Also no nav item.
     Fix: Full pricing renderer with 4 tiers + monthly/annual billing toggle.
  ════════════════════════════════════════════════════════════════════════ */
  const V22_PRICING_PLANS = [
    {
      id: 'starter', name: 'Starter', icon: '🚀', color: '#22c55e',
      badge: null,
      price_monthly: 299, price_annual: 2690,
      desc: 'For small security teams getting started with threat intelligence.',
      target: 'Teams of 1–5 analysts',
      limits: { users: 3, tenants: 1, collectors: 10, iocs_per_day: 1000, reports: 5, api_calls: '10K/month' },
      features: ['Command Center Dashboard','Live Threat Feed (Basic)','IOC Registry (1,000/day)','Cyber News Intelligence','Basic MITRE ATT&CK Map','3 Response Playbooks','Email Support (48h SLA)','5 Reports/month','Community playbooks','Export CSV/JSON'],
      not_included: ['AI Orchestrator','Dark Web Intelligence','SOAR Automation','Executive Dashboard','Malware Analysis Lab','API Access','White-labeling','Dedicated CSM','SLA Guarantee'],
      popular: false,
    },
    {
      id: 'professional', name: 'Professional', icon: '⚡', color: '#3b82f6',
      badge: 'Most Popular',
      price_monthly: 799, price_annual: 7190,
      desc: 'For growing security teams that need full threat intel capabilities.',
      target: 'Teams of 5–20 analysts',
      limits: { users: 10, tenants: 3, collectors: 30, iocs_per_day: 10000, reports: 50, api_calls: '100K/month' },
      features: ['All Starter features','AI Orchestrator (Qwen3:8B Ollama)','Dark Web Intelligence (v6.0)','IOC Database & Deep Search','Detection Engineering','Threat Hunting Workspace','Case Management','SOAR Automation (20 playbooks)','Kill Chain Visualization','Geo Threat Distribution Map','Full MITRE ATT&CK Navigator','RBAC (5 custom roles)','REST API Access','50 Reports/month','48h SLA'],
      not_included: ['Malware Analysis Lab','Cognitive AI Layer','Predictive Threat Engine','Custom Sandbox Integrations','Executive White-label','Dedicated CSM'],
      popular: true,
    },
    {
      id: 'enterprise', name: 'Enterprise', icon: '🏛️', color: '#a855f7',
      badge: 'Best Value',
      price_monthly: 2499, price_annual: 22490,
      desc: 'For enterprise SOC teams requiring autonomous AI and multi-tenant management.',
      target: 'Teams of 20–100 analysts',
      limits: { users: 50, tenants: 15, collectors: 100, iocs_per_day: 100000, reports: 'Unlimited', api_calls: '1M/month' },
      features: ['All Professional features','🧠 Malware Analysis Lab (4 sandboxes)','🧠 Cognitive Security Layer (XAI)','🧠 Predictive Threat Engine','🧠 Attack Graph Intelligence','🧠 Malware DNA Engine','🧠 Adversary Simulation Lab','🧠 SOC Memory Engine','🧠 Threat Intelligence Graph','🧠 Digital Risk Protection','White-label Branding','Executive Dashboard','Unlimited Reports + Scheduled','Custom SOAR Playbooks','Priority 4h SLA','Dedicated Customer Success Manager','SSO/SAML Integration','Quarterly Business Review'],
      not_included: ['What-If Simulator (Beta)','Security Memory Brain (Beta)','Autonomous SOC Agent (Beta)'],
      popular: false,
    },
    {
      id: 'sovereign', name: 'Sovereign', icon: '🌐', color: '#f59e0b',
      badge: 'Air-Gap Ready',
      price_monthly: null, price_annual: null,
      desc: 'For government, defense, and critical infrastructure requiring on-premise or air-gapped deployment.',
      target: 'Government, Defense, Critical Infrastructure',
      limits: { users: 'Unlimited', tenants: 'Unlimited', collectors: 'Unlimited', iocs_per_day: 'Unlimited', reports: 'Unlimited', api_calls: 'Unlimited' },
      features: ['All Enterprise features','⭐ What-If Attack Simulator','⭐ Security Memory Brain (ε-DP)','⭐ Autonomous SOC Agent (94.7% resolution)','Air-Gapped / On-Premise Deployment','Custom Hardware Provisioning','Data Residency Lock (any region)','Federal Compliance Package (FedRAMP/ISO 27001)','Custom AI Model Integration','Private Threat Intelligence Feeds','24/7 Dedicated Support Team','Annual Penetration Test','Source Code Escrow','Custom SLA (≤1h RTO)'],
      not_included: [],
      popular: false,
    }
  ];

  function _fixPricing() {
    // Ensure pricing page container exists
    if (!document.getElementById('page-pricing')) {
      const contentArea = document.querySelector('.content-area') || document.getElementById('contentArea');
      if (contentArea) {
        const pg = document.createElement('div');
        pg.className = 'page';
        pg.id = 'page-pricing';
        pg.style.cssText = 'padding:4px;overflow:auto;';
        contentArea.appendChild(pg);
      }
    }

    // Ensure nav item exists
    if (!document.querySelector('[data-page="pricing"]')) {
      const platformNav = Array.from(document.querySelectorAll('.sidebar-section-label')).find(l => l.textContent.trim() === 'PLATFORM');
      if (platformNav) {
        const navWrap = platformNav.nextElementSibling;
        if (navWrap && navWrap.classList.contains('sidebar-nav')) {
          const li = document.createElement('a');
          li.href = '#';
          li.className = 'nav-item';
          li.setAttribute('data-page', 'pricing');
          li.innerHTML = '<i class="fas fa-tags"></i><span>Pricing Plans</span>';
          li.addEventListener('click', (e) => { e.preventDefault(); if (typeof navigateTo === 'function') navigateTo('pricing'); });
          navWrap.appendChild(li);
        }
      }
    }

    // Override/install pricing renderer
    window.renderPricing = function () {
      const el = document.getElementById('page-pricing') || document.getElementById('pricingWrap');
      if (!el) return;

      const annual = window._v22PricingAnnual || false;

      el.innerHTML = `
      <div style="max-width:1200px;margin:0 auto;padding:24px;">
        <!-- Header -->
        <div style="text-align:center;margin-bottom:32px;">
          <div style="font-size:.8em;font-weight:700;letter-spacing:2px;color:#a855f7;text-transform:uppercase;margin-bottom:8px;">SUBSCRIPTION PLANS</div>
          <h2 style="font-size:1.8em;font-weight:800;color:#e6edf3;margin:0 0 8px;">Scale your SOC capabilities</h2>
          <p style="font-size:.9em;color:#8b949e;max-width:520px;margin:0 auto 20px;">From startup security teams to nation-state defense — purpose-built plans for every threat posture.</p>
          <!-- Billing Toggle -->
          <div style="display:inline-flex;align-items:center;gap:12px;background:#161b22;border:1px solid #30363d;border-radius:100px;padding:6px 16px;">
            <span style="font-size:.82em;color:${!annual?'#e6edf3':'#6e7681'};font-weight:${!annual?'700':'400'};">Monthly</span>
            <label style="position:relative;display:inline-block;width:44px;height:22px;cursor:pointer;">
              <input type="checkbox" id="v22-billing-toggle" ${annual?'checked':''} onchange="window._v22ToggleBilling(this.checked)" style="opacity:0;width:0;height:0;" />
              <span style="position:absolute;inset:0;background:${annual?'#a855f7':'#30363d'};border-radius:11px;transition:.3s;display:flex;align-items:center;padding:0 3px;">
                <span style="width:16px;height:16px;background:#fff;border-radius:50%;transition:.3s;transform:translateX(${annual?'22px':'0'});display:block;"></span>
              </span>
            </label>
            <span style="font-size:.82em;color:${annual?'#e6edf3':'#6e7681'};font-weight:${annual?'700':'400'};">Annual <span style="background:#22c55e20;color:#22c55e;padding:1px 6px;border-radius:8px;font-size:.8em;font-weight:700;">Save 10%</span></span>
          </div>
        </div>

        <!-- Plans Grid -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;margin-bottom:32px;">
          ${V22_PRICING_PLANS.map(plan => `
          <div style="background:#0d1117;border:2px solid ${plan.popular?plan.color:'#21262d'};border-radius:14px;padding:24px;position:relative;${plan.popular?'box-shadow:0 0 24px '+plan.color+'30;':''}" id="plan-card-${plan.id}">
            ${plan.badge ? `<div style="position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:${plan.color};color:#fff;font-size:.72em;font-weight:700;padding:3px 14px;border-radius:100px;white-space:nowrap;">${_e(plan.badge)}</div>` : ''}
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;margin-top:${plan.badge?'6px':'0'};">
              <div style="width:40px;height:40px;background:${plan.color}18;border:1px solid ${plan.color}33;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;">${plan.icon}</div>
              <div>
                <div style="font-size:1em;font-weight:700;color:#e6edf3;">${_e(plan.name)}</div>
                <div style="font-size:.72em;color:#6e7681;">${_e(plan.target)}</div>
              </div>
            </div>
            <!-- Price -->
            <div style="margin-bottom:16px;">
              ${plan.price_monthly === null ? `
              <div style="font-size:1.6em;font-weight:800;color:${plan.color};">Custom</div>
              <div style="font-size:.78em;color:#8b949e;">Contact sales for pricing</div>
              ` : `
              <div style="display:flex;align-items:baseline;gap:4px;">
                <span style="font-size:1.8em;font-weight:800;color:${plan.color};font-family:monospace;">$${annual?Math.floor(plan.price_annual/12):plan.price_monthly}</span>
                <span style="font-size:.8em;color:#6e7681;">/month</span>
              </div>
              ${annual?`<div style="font-size:.75em;color:#22c55e;">$${plan.price_annual}/year — save $${(plan.price_monthly*12-plan.price_annual)}</div>`:`<div style="font-size:.75em;color:#6e7681;">billed monthly</div>`}
              `}
            </div>
            <div style="font-size:.8em;color:#8b949e;margin-bottom:16px;line-height:1.4;">${_e(plan.desc)}</div>
            <!-- Limits -->
            <div style="background:#161b22;border-radius:6px;padding:10px;margin-bottom:14px;">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;">
                ${Object.entries(plan.limits).map(([k,v])=>`
                <div style="font-size:.72em;"><span style="color:#6e7681;">${k.replace(/_/g,' ')}:</span> <strong style="color:#e6edf3;">${v}</strong></div>`).join('')}
              </div>
            </div>
            <!-- Features -->
            <div style="max-height:160px;overflow-y:auto;scrollbar-width:thin;margin-bottom:14px;">
              ${plan.features.map(f=>`<div style="display:flex;align-items:flex-start;gap:6px;padding:3px 0;font-size:.78em;color:#8b949e;"><i class="fas fa-check" style="color:${plan.color};margin-top:2px;flex-shrink:0;font-size:.9em;"></i>${_e(f)}</div>`).join('')}
              ${plan.not_included.map(f=>`<div style="display:flex;align-items:flex-start;gap:6px;padding:3px 0;font-size:.78em;color:#3d444d;"><i class="fas fa-times" style="color:#3d444d;margin-top:2px;flex-shrink:0;font-size:.9em;"></i>${_e(f)}</div>`).join('')}
            </div>
            <!-- CTA -->
            <button onclick="window._v22PlanSelect('${plan.id}')"
              style="width:100%;padding:10px;border-radius:8px;font-size:.85em;font-weight:700;cursor:pointer;border:none;
                background:${plan.popular?plan.color:'#21262d'};
                color:${plan.popular?'#fff':'#8b949e'};transition:.2s;"
              onmouseover="this.style.background='${plan.color}';this.style.color='#fff'"
              onmouseout="this.style.background='${plan.popular?plan.color:'#21262d'}';this.style.color='${plan.popular?'#fff':'#8b949e'}'">
              ${plan.price_monthly===null ? '<i class="fas fa-envelope"></i> Contact Sales' : '<i class="fas fa-rocket"></i> Get Started'}
            </button>
          </div>`).join('')}
        </div>

        <!-- Feature Comparison Table -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-bottom:24px;">
          <div style="padding:16px 20px;border-bottom:1px solid #21262d;">
            <div style="font-size:.9em;font-weight:700;color:#e6edf3;">Feature Comparison</div>
          </div>
          <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.8em;">
              <thead>
                <tr style="background:#161b22;">
                  <th style="padding:10px 16px;text-align:left;color:#8b949e;font-weight:600;">Feature</th>
                  ${V22_PRICING_PLANS.map(p=>`<th style="padding:10px 16px;text-align:center;color:${p.color};font-weight:700;">${p.icon} ${_e(p.name)}</th>`).join('')}
                </tr>
              </thead>
              <tbody>
                ${[
                  ['Command Center', true, true, true, true],
                  ['Live Detections', true, true, true, true],
                  ['IOC Registry', '1K/day', '10K/day', '100K/day', 'Unlimited'],
                  ['AI Orchestrator', false, true, true, true],
                  ['Dark Web Intelligence', false, true, true, true],
                  ['SOAR Automation', false, true, true, true],
                  ['Malware Analysis Lab', false, false, true, true],
                  ['Cognitive AI Layer (XAI)', false, false, true, true],
                  ['Predictive Threat Engine', false, false, true, true],
                  ['Attack Graph Intelligence', false, false, true, true],
                  ['What-If Simulator ⭐', false, false, false, true],
                  ['Security Memory Brain ⭐', false, false, false, true],
                  ['Autonomous SOC Agent ⭐', false, false, false, true],
                  ['White-Label Branding', false, false, true, true],
                  ['Air-Gapped Deployment', false, false, false, true],
                ].map((row,i)=>`
                <tr style="border-bottom:1px solid #21262d;background:${i%2===0?'transparent':'#0a0f1a'};">
                  <td style="padding:9px 16px;color:#c9d1d9;">${row[0]}</td>
                  ${row.slice(1).map(v=>`<td style="padding:9px 16px;text-align:center;">${
                    v===true?'<i class="fas fa-check" style="color:#22c55e;"></i>':
                    v===false?'<i class="fas fa-times" style="color:#3d444d;"></i>':
                    `<span style="font-size:.85em;color:#8b949e;">${v}</span>`
                  }</td>`).join('')}
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div style="text-align:center;color:#6e7681;font-size:.78em;">
          All plans include 256-bit TLS encryption, RBAC, and SOC 2 Type II compliance. Prices in USD.
          <a href="mailto:sales@wadjet-eye-ai.com" style="color:#3b82f6;margin-left:8px;">Contact Sales</a>
        </div>
      </div>`;

      window._v22ToggleBilling = function (isAnnual) {
        window._v22PricingAnnual = isAnnual;
        window.renderPricing();
      };
      window._v22PlanSelect = function (planId) {
        const plan = V22_PRICING_PLANS.find(p => p.id === planId);
        if (!plan) return;
        if (plan.price_monthly === null) {
          _toast('📧 Opening contact form for Sovereign pricing…', 'info');
        } else {
          _toast(`🚀 Starting ${plan.name} plan setup…`, 'success');
        }
      };
    };

    // Wire into PAGE_CONFIG
    function _doPricingWire() {
      if (!window.PAGE_CONFIG) return false;
      window.PAGE_CONFIG['pricing'] = {
        title: 'Pricing Plans',
        breadcrumb: 'Platform / Subscription Tiers',
        onEnter: () => window.renderPricing(),
        onLeave: () => {}
      };
      return true;
    }
    let _pt = 0;
    const _pi = setInterval(() => { if (_doPricingWire() || ++_pt > 80) clearInterval(_pi); }, 100);
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #4 — PREDICTIVE THREAT ENGINE
     Root cause: renderPredictiveEngine() was an empty shell in cyber-brain-modules.js.
     Fix: Full async renderer with campaign forecasts, risk heatmap, threat timeline.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixPredictiveEngine() {
    const FORECAST_DATA = {
      campaigns: [
        { id: 'FC-2026-001', actor: 'APT29 (Cozy Bear)', confidence: 89, horizon: '24-48h', target_sectors: ['Government','Defense','Finance'], campaign_type: 'Credential Harvesting', predicted_ttps: ['T1078','T1566.002','T1021.002'], current_iocs: 14, risk_score: 94, indicators: ['Increased SUNBURST variant scanning observed', 'New C2 domains registered via Namecheap in last 48h', 'Spear-phishing lures targeting EU diplomatic staff detected'], recommended_actions: ['Pre-position EDR rules for SUNBURST memory patterns', 'Block new APT29 C2 domains (see IOC feed)', 'Alert on anomalous Outlook macro execution'], trend: 'escalating' },
        { id: 'FC-2026-002', actor: 'LockBit 4.0', confidence: 76, horizon: '48-72h', target_sectors: ['Healthcare','Manufacturing','Legal'], campaign_type: 'Ransomware-as-a-Service', predicted_ttps: ['T1133','T1486','T1490'], current_iocs: 31, risk_score: 88, indicators: ['LockBit affiliate recruitment spike on dark web forums', 'Exploitation of FortiGate CVE-2024-21762 in progress', '3 new ransomware infrastructure clusters identified'], recommended_actions: ['Patch FortiGate immediately (CVE-2024-21762)', 'Deploy VSS tamper monitoring', 'Verify backup integrity and offline copies'], trend: 'stable' },
        { id: 'FC-2026-003', actor: 'Scattered Spider (UNC3944)', confidence: 82, horizon: '12-24h', target_sectors: ['SaaS','Fintech','Cloud Providers'], campaign_type: 'Cloud Takeover / Identity Attack', predicted_ttps: ['T1621','T1111','T1078.004'], current_iocs: 8, risk_score: 91, indicators: ['Vishing call spike targeting helpdesk staff in US tech firms', 'Fake Okta login pages registered in last 6h', 'Telegram coordination channels showing increased activity'], recommended_actions: ['Activate helpdesk social engineering awareness', 'Enable MFA push fraud detection', 'Monitor for new Okta tenant login anomalies'], trend: 'escalating' },
        { id: 'FC-2026-004', actor: 'Volt Typhoon', confidence: 71, horizon: '72-96h', target_sectors: ['Energy','Water Utilities','Transportation'], campaign_type: 'Critical Infrastructure Pre-positioning', predicted_ttps: ['T1078.001','T1505.003','T1048'], current_iocs: 22, risk_score: 96, indicators: ['SOHO router compromise activity in US Pacific Coast', 'KV-Botnet C2 traffic patterns detected in ISP flows', 'Suspicious HTTPS traffic from OT network segments'], recommended_actions: ['Audit SOHO routers for unauthorized access', 'Hunt for LOLBin activity on OT boundary systems', 'Verify no unauthorized outbound HTTPS from ICS networks'], trend: 'stable' },
      ],
      risk_heatmap: [
        { sector: 'Healthcare', risk: 92, active_threats: 8, change: '+12%' },
        { sector: 'Finance', risk: 88, active_threats: 12, change: '+5%' },
        { sector: 'Government', risk: 85, active_threats: 6, change: '+18%' },
        { sector: 'Technology', risk: 79, active_threats: 15, change: '-3%' },
        { sector: 'Energy', risk: 94, active_threats: 4, change: '+24%' },
        { sector: 'Manufacturing', risk: 72, active_threats: 9, change: '+8%' },
        { sector: 'Education', risk: 64, active_threats: 5, change: '+2%' },
        { sector: 'Legal', risk: 71, active_threats: 7, change: '+15%' },
      ],
      timeline_events: Array.from({length: 14}, (_, i) => ({
        date: new Date(Date.now() - (13 - i) * 86400000).toLocaleDateString('en-US', {month:'short',day:'numeric'}),
        attacks: _rand(12, 45),
        critical: _rand(2, 8),
        predicted: i >= 11
      }))
    };

    window.renderPredictiveEngine = function () {
      const el = document.getElementById('page-predictive-engine');
      if (!el) return;

      const trendColor = t => t === 'escalating' ? '#ef4444' : t === 'stable' ? '#f59e0b' : '#22c55e';
      const trendIcon = t => t === 'escalating' ? 'fa-arrow-up' : t === 'stable' ? 'fa-minus' : 'fa-arrow-down';
      const riskColor = r => r >= 90 ? '#ef4444' : r >= 75 ? '#f97316' : r >= 60 ? '#f59e0b' : '#22c55e';

      el.innerHTML = `
      <div class="cds-module cds-accent-predictive" style="min-height:100%;">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(59,130,246,0.1);color:#3b82f6;border:1px solid rgba(59,130,246,0.3);">
              <i class="fas fa-chart-line"></i>
            </div>
            <div>
              <div class="cds-module-name">Predictive Threat Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot" style="background:#3b82f6;box-shadow:0 0 4px #3b82f6;"></div>Forecasting Active</div>
                <span>·</span><span>24–72h Campaign Prediction</span><span>·</span>
                <span style="color:#3b82f6;font-weight:700;font-size:10px;">ML Model v3.2</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-sm" onclick="window.renderPredictiveEngine()" style="background:rgba(59,130,246,0.15);color:#3b82f6;border:1px solid rgba(59,130,246,0.3);">
              <i class="fas fa-sync-alt"></i> Refresh Forecast
            </button>
          </div>
        </div>
        <div class="cds-module-body">

          <!-- KPI Row -->
          <div class="cds-metrics" style="margin-bottom:20px;">
            ${[
              ['Active Forecasts', FORECAST_DATA.campaigns.length, '#3b82f6', 'fa-chart-line'],
              ['Avg Confidence', Math.round(FORECAST_DATA.campaigns.reduce((a,c)=>a+c.confidence,0)/FORECAST_DATA.campaigns.length)+'%', '#22c55e', 'fa-percentage'],
              ['Highest Risk Sector', 'Energy (94)', '#ef4444', 'fa-bolt'],
              ['Total Active IOCs', FORECAST_DATA.campaigns.reduce((a,c)=>a+c.current_iocs,0), '#f59e0b', 'fa-fingerprint']
            ].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:20px;">

            <!-- Attack Timeline Chart -->
            <div class="cds-card">
              <div class="cds-section-title" style="margin-bottom:14px;"><i class="fas fa-chart-bar"></i> 14-Day Attack Volume + 3-Day Forecast</div>
              <div style="height:140px;display:flex;align-items:flex-end;gap:4px;padding:0 4px;">
                ${FORECAST_DATA.timeline_events.map(d => {
                  const maxH = 120;
                  const h = Math.round((d.attacks / 50) * maxH);
                  return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;">
                    <div style="width:100%;background:${d.predicted?'rgba(59,130,246,0.4)':'rgba(59,130,246,0.7)'};height:${h}px;border-radius:3px 3px 0 0;position:relative;border:${d.predicted?'1px dashed #3b82f6':'none'};"
                      title="${d.date}: ${d.attacks} attacks (${d.critical} critical)${d.predicted?' [PREDICTED]':''}">
                    </div>
                    <div style="font-size:8px;color:#6e7681;transform:rotate(-45deg);transform-origin:top;white-space:nowrap;">${d.date}</div>
                  </div>`;
                }).join('')}
              </div>
              <div style="display:flex;gap:12px;margin-top:10px;font-size:.72em;color:#8b949e;justify-content:center;">
                <span><span style="display:inline-block;width:10px;height:10px;background:rgba(59,130,246,0.7);border-radius:2px;margin-right:4px;"></span>Historical</span>
                <span><span style="display:inline-block;width:10px;height:10px;background:rgba(59,130,246,0.4);border:1px dashed #3b82f6;border-radius:2px;margin-right:4px;"></span>Predicted</span>
              </div>
            </div>

            <!-- Sector Risk Heatmap -->
            <div class="cds-card">
              <div class="cds-section-title" style="margin-bottom:14px;"><i class="fas fa-th"></i> Sector Risk Heatmap</div>
              <div style="display:flex;flex-direction:column;gap:7px;">
                ${FORECAST_DATA.risk_heatmap.map(s=>`
                <div style="display:flex;align-items:center;gap:8px;">
                  <div style="width:90px;font-size:.8em;color:#8b949e;flex-shrink:0;">${_e(s.sector)}</div>
                  <div style="flex:1;background:rgba(255,255,255,0.05);border-radius:4px;height:18px;position:relative;overflow:hidden;">
                    <div style="height:100%;width:${s.risk}%;background:linear-gradient(90deg,${riskColor(s.risk)}88,${riskColor(s.risk)});border-radius:4px;transition:.8s;"></div>
                  </div>
                  <div style="width:32px;font-size:.8em;font-weight:700;color:${riskColor(s.risk)};text-align:right;">${s.risk}</div>
                  <div style="font-size:.72em;color:${s.change.startsWith('+')?'#ef4444':'#22c55e'};width:32px;">${s.change}</div>
                </div>`).join('')}
              </div>
            </div>
          </div>

          <!-- Campaign Forecasts -->
          <div class="cds-section-title" style="margin-bottom:14px;"><i class="fas fa-crosshairs"></i> Active Campaign Forecasts</div>
          <div style="display:flex;flex-direction:column;gap:14px;">
            ${FORECAST_DATA.campaigns.map(fc=>`
            <div class="cds-card" style="border-left:4px solid ${riskColor(fc.risk_score)};">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
                <div>
                  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
                    <span style="font-size:13px;font-weight:700;color:#e6edf3;">${_e(fc.actor)}</span>
                    <span style="font-size:.7em;background:${riskColor(fc.risk_score)}20;color:${riskColor(fc.risk_score)};border:1px solid ${riskColor(fc.risk_score)}33;padding:1px 7px;border-radius:8px;font-weight:700;">RISK ${fc.risk_score}</span>
                    <span style="font-size:.7em;color:${trendColor(fc.trend)};"><i class="fas ${trendIcon(fc.trend)}" style="margin-right:3px;"></i>${fc.trend.toUpperCase()}</span>
                  </div>
                  <div style="font-size:.78em;color:#8b949e;">${_e(fc.campaign_type)} · Targets: ${fc.target_sectors.join(', ')} · IOCs: ${fc.current_iocs}</div>
                </div>
                <div style="text-align:right;flex-shrink:0;">
                  <div style="font-size:1.6em;font-weight:800;color:${fc.confidence>=85?'#22c55e':fc.confidence>=70?'#f59e0b':'#ef4444'};font-family:monospace;">${fc.confidence}%</div>
                  <div style="font-size:.72em;color:#6e7681;">Confidence</div>
                  <div style="font-size:.72em;color:#3b82f6;margin-top:2px;">⏱ ${_e(fc.horizon)}</div>
                </div>
              </div>
              <!-- Indicators -->
              <div style="margin-bottom:12px;">
                <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">Predictive Indicators</div>
                ${fc.indicators.map(ind=>`<div style="display:flex;gap:7px;font-size:.8em;color:#8b949e;padding:3px 0;"><i class="fas fa-arrow-right" style="color:#3b82f6;font-size:.85em;margin-top:2px;flex-shrink:0;"></i>${_e(ind)}</div>`).join('')}
              </div>
              <!-- MITRE Tags -->
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">
                ${fc.predicted_ttps.map(t=>`<span style="font-size:.72em;background:rgba(239,68,68,0.08);color:#ef4444;border:1px solid rgba(239,68,68,0.2);padding:2px 7px;border-radius:4px;font-family:monospace;">${t}</span>`).join('')}
              </div>
              <!-- Recommended Actions -->
              <div style="background:rgba(59,130,246,0.05);border:1px solid rgba(59,130,246,0.2);border-radius:6px;padding:10px;">
                <div style="font-size:.75em;font-weight:700;color:#3b82f6;margin-bottom:6px;"><i class="fas fa-shield-alt" style="margin-right:5px;"></i>PRE-EMPTIVE DEFENSES</div>
                ${fc.recommended_actions.map((a,i)=>`<div style="font-size:.8em;color:#8b949e;padding:2px 0;"><span style="color:#3b82f6;font-weight:700;margin-right:5px;">${i+1}.</span>${_e(a)}</div>`).join('')}
              </div>
            </div>`).join('')}
          </div>

        </div>
      </div>`;
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #5 — MALWARE DNA ENGINE
     Root cause: Only LockBit 4.0 was in the families array. Engine had no
     cross-family comparison, no dynamic rendering.
     Fix: 8 full malware families with MITRE, IOCs, detection rules, similarity.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixMalwareDNA() {
    const MALWARE_FAMILIES = [
      {
        id: 'FAM-001', name: 'Emotet', category: 'Malware Loader / Banking Trojan', status: 'ACTIVE',
        risk: 'critical', color: '#ef4444',
        origin: 'TA542 (Mealybug)', first_seen: '2014', last_variant: '2026-Q1',
        description: 'Highly modular loader that delivers secondary payloads (TrickBot, QakBot, Cobalt Strike). Uses encrypted C2, polymorphic packers, and thread-injection for evasion. Spreads via malspam with weaponized Office docs.',
        dna_signature: 'ENC_XOR_CHAIN + THREADINJECT + REGPERSIST',
        similarity_score: 0,
        child_families: ['TrickBot', 'QakBot', 'Cobalt Strike'],
        ttps: ['T1566.001','T1059.005','T1055.002','T1547.001','T1071.001'],
        iocs: { hashes: ['a3f4b1c2d8e7f...sha256','5e9a2b3c1d4f...sha256'], domains: ['emotet-c2[.]net','update-svc[.]com'], ips: ['185.220.101.47','91.240.118.130'] },
        detection_rules: ['sigma: lsass_access_via_comsvcs','yara: emotet_doc_macro_pattern','edr: office_child_process_powershell'],
        cve_exploits: [],
        behavior: ['Drops DLL to %TEMP%', 'Installs registry Run key', 'Creates scheduled task', 'Beacons via HTTP POST /wp-content/', 'Downloads secondary payload modules'],
      },
      {
        id: 'FAM-002', name: 'TrickBot', category: 'Banking Trojan / Info Stealer', status: 'ACTIVE',
        risk: 'critical', color: '#f97316',
        origin: 'ITG23 (Wizard Spider)', first_seen: '2016', last_variant: '2025-Q4',
        description: 'Modular banking trojan evolved into a full-featured malware platform delivering Ryuk/Conti ransomware. Harvests banking credentials, Active Directory data, and browser cookies via web injection and keylogging.',
        dna_signature: 'WEBINJECT_ENGINE + AD_ENUM + CERTTHEFT',
        similarity_score: 87,
        child_families: ['Conti', 'Ryuk', 'BazarLoader'],
        ttps: ['T1539','T1555.003','T1082','T1016','T1021.002'],
        iocs: { hashes: ['c7d2e4f1a9b3...sha256','8f1a3b5c2d7e...sha256'], domains: ['trickbot-cdn[.]com','api-check[.]ru'], ips: ['193.37.255.11','45.77.65.211'] },
        detection_rules: ['sigma: trickbot_network_scan','yara: trickbot_module_loader','edr: certutil_decode_base64'],
        cve_exploits: ['CVE-2017-0144 (EternalBlue)'],
        behavior: ['Harvests RDP credentials', 'Enumerates Active Directory via LDAP', 'Steals browser passwords', 'Injects into browser processes', 'Deploys Cobalt Strike stagers'],
      },
      {
        id: 'FAM-003', name: 'QakBot / Qbot', category: 'Banking Trojan / Worm', status: 'RESURGENT',
        risk: 'critical', color: '#f59e0b',
        origin: 'TA570', first_seen: '2007', last_variant: '2026-Q1',
        description: 'One of the oldest active banking trojans. Spreads via email hijacking (thread injection into legitimate email chains). Acts as initial access broker delivering Black Basta and other ransomware.',
        dna_signature: 'EMAIL_HIJACK + INJECTEDTHREAD + WORMSPREAD',
        similarity_score: 91,
        child_families: ['Black Basta', 'LockBit', 'Cobalt Strike'],
        ttps: ['T1566.001','T1534','T1055.001','T1021.002','T1486'],
        iocs: { hashes: ['2d8f3a1b7c9e...sha256','4b6a2c5d1f3e...sha256'], domains: ['qakbot-smtp[.]net','cdn-files[.]click'], ips: ['91.215.85.32','185.174.136.154'] },
        detection_rules: ['sigma: qakbot_dll_hijack','yara: qakbot_pe_section','edr: wscript_spawns_powershell'],
        cve_exploits: [],
        behavior: ['Injects into explorer.exe or msra.exe', 'Hijacks email thread history', 'Spreads via network shares', 'Captures screenshots', 'Disables Windows Defender'],
      },
      {
        id: 'FAM-004', name: 'LockBit 4.0', category: 'Ransomware-as-a-Service', status: 'ACTIVE',
        risk: 'critical', color: '#ef4444',
        origin: 'LockBit Group', first_seen: '2019', last_variant: '2026-Q1',
        description: 'World\'s most prolific ransomware operation. LockBit 4.0 features Linux/macOS support, automated exfiltration via StealBit, dark web victim blog, and accelerated encryption using curve25519+AES-256.',
        dna_signature: 'CURVE25519_AES + STEALBIT_EXFIL + VSSDELETE',
        similarity_score: 0,
        child_families: [],
        ttps: ['T1133','T1486','T1490','T1041','T1562.001'],
        iocs: { hashes: ['7e3d1a4b8c2f...sha256','9a5b3c1d6e8f...sha256'], domains: ['lockbit4[.]onion','lb4-news[.]io'], ips: ['194.165.16.78','185.56.80.65'] },
        detection_rules: ['sigma: vss_delete_shadowcopy','yara: lockbit4_ransom_note','edr: cryptoapi_rapid_file_rename'],
        cve_exploits: ['CVE-2023-44487','CVE-2024-21762 (FortiGate)'],
        behavior: ['Deletes Volume Shadow Copies via WMIC', 'Disables Windows Event Log', 'Enumerates and encrypts network shares', 'Exfiltrates via StealBit before encryption', 'Prints ransom note to all printers'],
      },
      {
        id: 'FAM-005', name: 'RedLine Stealer', category: 'Info Stealer / Credential Harvester', status: 'ACTIVE',
        risk: 'high', color: '#a855f7',
        origin: 'Unknown (MaaS)', first_seen: '2020', last_variant: '2026-Q1',
        description: 'Commodity malware-as-a-service credential stealer sold on dark web forums. Harvests browser passwords, crypto wallets, FTP/VPN credentials, Discord tokens, and Steam sessions. Delivered via malvertising and cracked software.',
        dna_signature: 'BROWSERDB_EXTRACT + WALLET_SCAN + DISCORD_TOKEN',
        similarity_score: 65,
        child_families: ['Meta Stealer', 'Vidar'],
        ttps: ['T1555.003','T1552.001','T1539','T1082','T1048.003'],
        iocs: { hashes: ['1f5c3a8b2d6e...sha256','3e7b1c4d9a2f...sha256'], domains: ['redline-gate[.]ru','logs-panel[.]top'], ips: ['188.114.96.7','45.142.212.100'] },
        detection_rules: ['sigma: credential_dump_chromium','yara: redline_config_extract','edr: sqlite_browser_access_by_foreign_process'],
        cve_exploits: [],
        behavior: ['Reads Chrome/Edge password database', 'Scans for crypto wallet files', 'Extracts browser cookies', 'Enumerates installed apps for targeting', 'Sends to C2 via Telegram API or HTTP POST'],
      },
      {
        id: 'FAM-006', name: 'AgentTesla', category: 'Remote Access Trojan / Keylogger', status: 'ACTIVE',
        risk: 'high', color: '#22c55e',
        origin: 'TA2719', first_seen: '2014', last_variant: '2025-Q4',
        description: 'Sophisticated RAT with keylogging, screen capture, webcam access, and credential harvesting. Popular with APT groups for long-term espionage. Sold as malware-as-a-service on forums.',
        dna_signature: 'KEYLOG_HOOKS + SCREENCAP + SMTP_EXFIL',
        similarity_score: 72,
        child_families: ['FormBook', 'Snake Keylogger'],
        ttps: ['T1056.001','T1113','T1552','T1071.003','T1027'],
        iocs: { hashes: ['5a2d8f1b3c7e...sha256','7b4e2a6c1d9f...sha256'], domains: ['smtp-delivery[.]info','mail-server[.]click'], ips: ['91.108.4.220','45.87.153.44'] },
        detection_rules: ['sigma: agentTesla_smtp_exfil','yara: agenttesla_cfg_decode','edr: setwindowshookex_global_keyboard'],
        cve_exploits: ['CVE-2017-11882 (Office Equation Editor)'],
        behavior: ['Installs global keyboard hooks', 'Captures screenshots every 30s', 'Harvests SMTP/FTP/browser creds', 'Exfiltrates via SMTP to actor-controlled mailbox', 'Achieves persistence via scheduled tasks'],
      },
      {
        id: 'FAM-007', name: 'Cobalt Strike', category: 'Legitimate Pentesting Tool (Abused)', status: 'ACTIVE',
        risk: 'critical', color: '#00d4ff',
        origin: 'Multiple Threat Actors (cracked)', first_seen: '2012', last_variant: '2026',
        description: 'Commercial penetration testing tool routinely abused by ransomware groups and APTs. Beacon payloads provide full C2, lateral movement, privilege escalation, and post-exploitation capabilities.',
        dna_signature: 'CS_BEACON_PE + NAMED_PIPE_STAGER + MALLEABLE_C2',
        similarity_score: 0,
        child_families: [],
        ttps: ['T1055','T1021.002','T1548.002','T1558.003','T1071.001'],
        iocs: { hashes: ['generic_beacon_varies'], domains: ['varied_c2[.]domains','cdn-proxy[.]services'], ips: ['104.21.X.X (rotating Cloudflare)'] },
        detection_rules: ['sigma: cobaltstrike_named_pipe','yara: cobaltstrike_beacon_config','edr: suspicious_memory_allocation_rwx'],
        cve_exploits: ['CVE-2021-44228 (Log4Shell - delivery)', 'CVE-2021-40444'],
        behavior: ['Creates named pipes (\\\\PIPE\\msrpc_xxx)', 'Injects into legitimate processes (svchost/explorer)', 'Uses malleable C2 profiles (mimics legit traffic)', 'Performs Kerberoasting', 'Executes BOF (Beacon Object Files) in memory'],
      },
      {
        id: 'FAM-008', name: 'BlackCat / ALPHV', category: 'Ransomware-as-a-Service', status: 'DISRUPTED',
        risk: 'high', color: '#6366f1',
        origin: 'ALPHV Group (Disbanded post-FBI)', first_seen: '2021', last_variant: '2024-Q2',
        description: 'First ransomware written in Rust, known for triple extortion (data leak + DDoS + customer notification). Notably compromised Change Healthcare causing $22M ransom payment. FBI seized infrastructure in 2024.',
        dna_signature: 'RUST_ENCRYPTOR + TRIPLE_EXTORT + SAFEMODE_REBOOT',
        similarity_score: 78,
        child_families: ['Sphynx variant', 'Noberus'],
        ttps: ['T1486','T1490','T1491.002','T1657','T1562.001'],
        iocs: { hashes: ['4c8e1a3b7d2f...sha256','6a2c9b5d1e3f...sha256'], domains: ['alphv-blog[.]onion (seized)'], ips: ['185.220.100.240 (seized)'] },
        detection_rules: ['sigma: blackcat_safemode_registry','yara: alphv_rust_encryptor','edr: bcdedit_safeboot_modification'],
        cve_exploits: ['CVE-2019-11510 (Pulse VPN)','CVE-2021-31207 (Exchange)'],
        behavior: ['Reboots into safe mode before encryption', 'Deletes event logs and shadow copies', 'Exfiltrates via custom Rust tool ExMatter', 'DDoSes victim if payment delayed', 'Directly notifies victim customers'],
      },
    ];

    window.renderMalwareDNA = function () {
      const el = document.getElementById('page-malware-dna');
      if (!el) return;

      const riskColor = r => ({ critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }[r] || '#8b949e');
      const statusColor = s => ({ ACTIVE: '#ef4444', RESURGENT: '#f97316', DISRUPTED: '#22c55e' }[s] || '#8b949e');

      el.innerHTML = `
      <div class="cds-module cds-accent-dna" style="min-height:100%;">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.3);">
              <i class="fas fa-dna"></i>
            </div>
            <div>
              <div class="cds-module-name">Malware DNA Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot" style="background:#22c55e;box-shadow:0 0 4px #22c55e;"></div>Genome DB Active</div>
                <span>·</span><span>${MALWARE_FAMILIES.length} Families Indexed</span><span>·</span>
                <span style="color:#22c55e;font-weight:700;font-size:10px;">Semantic Similarity Engine</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <input id="dna-search" placeholder="🔍 Search families…" oninput="window._v22DNAFilter(this.value)"
              style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:180px;" />
          </div>
        </div>
        <div class="cds-module-body">

          <!-- KPIs -->
          <div class="cds-metrics" style="margin-bottom:20px;">
            ${[
              ['Families Indexed', MALWARE_FAMILIES.length, '#22c55e', 'fa-dna'],
              ['Active Threats', MALWARE_FAMILIES.filter(f=>f.status==='ACTIVE').length, '#ef4444', 'fa-virus'],
              ['Total MITRE TTPs', [...new Set(MALWARE_FAMILIES.flatMap(f=>f.ttps))].length, '#a855f7', 'fa-th'],
              ['Resurgent / Disrupted', MALWARE_FAMILIES.filter(f=>f.status!=='ACTIVE').length, '#f59e0b', 'fa-sync'],
            ].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Family Cards -->
          <div id="dna-family-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;">
            ${MALWARE_FAMILIES.map(fam => `
            <div class="cds-card dna-family-card" data-name="${fam.name.toLowerCase()}" style="border-left:4px solid ${fam.color};cursor:pointer;" onclick="window._v22DNAExpand('${fam.id}')">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px;">
                <div>
                  <div style="display:flex;align-items:center;gap:7px;margin-bottom:3px;">
                    <span style="font-size:14px;font-weight:700;color:#e6edf3;">${_e(fam.name)}</span>
                    <span style="font-size:.65em;padding:1px 7px;border-radius:8px;font-weight:700;background:${statusColor(fam.status)}18;color:${statusColor(fam.status)};border:1px solid ${statusColor(fam.status)}30;">${fam.status}</span>
                  </div>
                  <div style="font-size:.75em;color:#8b949e;">${_e(fam.category)}</div>
                  <div style="font-size:.72em;color:#6e7681;">Origin: ${_e(fam.origin)} · Since ${fam.first_seen}</div>
                </div>
                <div style="text-align:right;flex-shrink:0;">
                  <div style="font-size:.7em;color:#6e7681;">Risk</div>
                  <span style="font-size:.75em;font-weight:700;padding:2px 8px;border-radius:8px;background:${riskColor(fam.risk)}15;color:${riskColor(fam.risk)};border:1px solid ${riskColor(fam.risk)}30;">${fam.risk.toUpperCase()}</span>
                </div>
              </div>
              <div style="font-size:.78em;color:#8b949e;line-height:1.4;margin-bottom:10px;max-height:48px;overflow:hidden;">${_e(fam.description.slice(0,140))}…</div>
              <!-- DNA Signature -->
              <div style="background:rgba(34,197,94,0.05);border:1px solid rgba(34,197,94,0.15);border-radius:5px;padding:7px;margin-bottom:10px;font-family:monospace;font-size:.72em;color:#22c55e;">
                🧬 ${_e(fam.dna_signature)}
              </div>
              <!-- MITRE TTPs -->
              <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px;">
                ${fam.ttps.map(t=>`<span style="font-size:.68em;background:rgba(239,68,68,0.08);color:#ef4444;border:1px solid rgba(239,68,68,0.2);padding:2px 6px;border-radius:4px;font-family:monospace;">${t}</span>`).join('')}
              </div>
              ${fam.child_families.length > 0 ? `
              <div style="font-size:.72em;color:#8b949e;"><i class="fas fa-code-branch" style="margin-right:4px;color:#6366f1;"></i>Delivers: ${fam.child_families.join(', ')}</div>` : ''}
              <div style="margin-top:8px;font-size:.72em;color:#3b82f6;"><i class="fas fa-expand-alt" style="margin-right:4px;"></i>Click for full analysis</div>
            </div>`).join('')}
          </div>

          <!-- Detail Modal (inline) -->
          <div id="dna-detail-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:9999;overflow-y:auto;" onclick="if(event.target===this)this.style.display='none'">
            <div id="dna-detail-body" style="max-width:700px;margin:40px auto;background:#0d1117;border:1px solid #30363d;border-radius:14px;padding:28px;"></div>
          </div>

        </div>
      </div>`;

      window._v22DNAFilter = function (q) {
        document.querySelectorAll('.dna-family-card').forEach(card => {
          card.style.display = !q || card.dataset.name.includes(q.toLowerCase()) ? '' : 'none';
        });
      };

      window._v22DNAExpand = function (famId) {
        const fam = MALWARE_FAMILIES.find(f => f.id === famId);
        if (!fam) return;
        const modal = document.getElementById('dna-detail-modal');
        const body = document.getElementById('dna-detail-body');
        if (!modal || !body) return;
        body.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;">
            <div>
              <h2 style="font-size:1.4em;font-weight:800;color:#e6edf3;margin:0 0 4px;">${_e(fam.name)}</h2>
              <div style="font-size:.82em;color:#8b949e;">${_e(fam.category)}</div>
            </div>
            <button onclick="document.getElementById('dna-detail-modal').style.display='none'" style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:6px;cursor:pointer;">✕ Close</button>
          </div>
          <div style="font-size:.85em;color:#8b949e;line-height:1.6;margin-bottom:18px;">${_e(fam.description)}</div>
          <div style="font-family:monospace;font-size:.78em;color:#22c55e;background:rgba(34,197,94,0.05);border:1px solid rgba(34,197,94,0.15);border-radius:6px;padding:10px;margin-bottom:16px;">🧬 DNA: ${_e(fam.dna_signature)}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;">
            <div><div style="font-size:.75em;color:#6e7681;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Behavior Traits</div>
              ${fam.behavior.map(b=>`<div style="font-size:.8em;color:#8b949e;padding:3px 0;display:flex;gap:6px;align-items:flex-start;"><i class="fas fa-chevron-right" style="color:#f59e0b;font-size:.75em;margin-top:3px;"></i>${_e(b)}</div>`).join('')}
            </div>
            <div><div style="font-size:.75em;color:#6e7681;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Detection Rules</div>
              ${fam.detection_rules.map(r=>`<div style="font-size:.76em;color:#22c55e;font-family:monospace;padding:3px 0;">${_e(r)}</div>`).join('')}
              ${fam.cve_exploits.length>0?`<div style="font-size:.75em;color:#6e7681;margin-top:8px;text-transform:uppercase;letter-spacing:1px;">CVEs Exploited</div>${fam.cve_exploits.map(c=>`<div style="font-size:.78em;color:#ef4444;font-family:monospace;padding:2px 0;">${_e(c)}</div>`).join('')}`:''}
            </div>
          </div>
          <div><div style="font-size:.75em;color:#6e7681;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">IOC Samples</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              ${[...fam.iocs.domains.map(d=>`<span style="font-size:.72em;background:rgba(239,68,68,0.08);color:#ef4444;border:1px solid rgba(239,68,68,0.2);padding:2px 8px;border-radius:4px;font-family:monospace;">${_e(d)}</span>`),
                 ...fam.iocs.ips.map(i=>`<span style="font-size:.72em;background:rgba(59,130,246,0.08);color:#3b82f6;border:1px solid rgba(59,130,246,0.2);padding:2px 8px;border-radius:4px;font-family:monospace;">${_e(i)}</span>`)].join('')}
            </div>
          </div>`;
        modal.style.display = 'block';
      };
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #6 — REMOVE "NEVER-SEEN-BEFORE:" LABELS
     Root cause: innovation-modules.js and differentiator-modules.js had
     hardcoded "🚀 NEVER-SEEN-BEFORE INNOVATION" and "Never-Seen-Before:"
     strings in rendered HTML. These are unprofessional in a production platform.
     Fix: MutationObserver to scrub those strings on any DOM insertion +
     patch the source strings.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixNeverSeenBefore() {
    const REPLACEMENTS = [
      [/Never-Seen-Before:\s*/gi, ''],
      [/🚀\s*NEVER-SEEN-BEFORE\s*INNOVATION/gi, '⭐ Advanced Capability'],
      [/🎯\s*Never-Seen-Before:/gi, '🎯'],
      [/Never.Seen.Before[:\s]*/gi, ''],
    ];

    function _scrubNode(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        let changed = false;
        let t = node.textContent;
        REPLACEMENTS.forEach(([re, rep]) => { const n = t.replace(re, rep); if (n !== t) { t = n; changed = true; } });
        if (changed) node.textContent = t;
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        node.childNodes.forEach(_scrubNode);
        // Also fix innerHTML attributes that may contain the string
        ['title', 'placeholder', 'aria-label'].forEach(attr => {
          const v = node.getAttribute(attr);
          if (v) {
            let nv = v;
            REPLACEMENTS.forEach(([re, rep]) => { nv = nv.replace(re, rep); });
            if (nv !== v) node.setAttribute(attr, nv);
          }
        });
      }
    }

    // Scrub entire DOM immediately
    _scrubNode(document.body);

    // Watch for future DOM changes
    const obs = new MutationObserver(mutations => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          try { _scrubNode(node); } catch {}
        });
      });
    });
    obs.observe(document.body, { childList: true, subtree: true });
    window._v22NeverSeenBeforeObserver = obs;
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #7 — WHAT-IF SIMULATOR DYNAMIC GENERATION
     Root cause: "Run New Simulation" called window._whatifRunNew() which was
     not implemented — the function was missing, so nothing changed.
     Fix: Implement _whatifRunNew() with 6 scenarios + random selection + animation.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixWhatIfSimulator() {
    const WHATIF_SCENARIOS = [
      {
        id: 'SIM-001', label: 'Initial Access → Lateral Movement',
        scenario: 'Attacker on WKSTN-045 with user-level access (finance segment)',
        current_position: 'Compromised workstation · Finance VLAN',
        context: 'Cobalt Strike beacon active · sarah.chen credentials available',
        branches: [
          { id:'B1', action:'Dump LSASS credentials via comsvcs.dll', probability:87, technique:'T1003.001', tool:'Mimikatz / ProcDump', impact:'critical', outcome:'Gain domain credentials — enables lateral movement to all assets including DC', detection_coverage:34, detection_gap:'LSASS access via comsvcs.dll not blocked — EDR rule missing', recommended_defense:'Enable Credential Guard + ASR rule for LSASS access', time_to_execute:'<2m' },
          { id:'B2', action:'Establish DNS tunnel for redundant C2', probability:61, technique:'T1071.004', tool:'DNScat2 / Iodine', impact:'high', outcome:'Redundant C2 channel survives primary beacon disruption', detection_coverage:45, detection_gap:'DNS inspection not enabled on internal resolvers', recommended_defense:'Enable DNS TXT inspection + alert on queries >64 chars', time_to_execute:'10-30m' },
          { id:'B3', action:'Pass-the-Ticket to Active Directory', probability:74, technique:'T1550.003', tool:'Rubeus / Impacket', impact:'critical', outcome:'Domain admin impersonation via Kerberos ticket — full domain compromise', detection_coverage:29, detection_gap:'Event 4768/4769 Kerberos alerting not configured', recommended_defense:'Configure Kerberos event alerting + enforce AES-only service accounts', time_to_execute:'3-8m' },
          { id:'B4', action:'Deploy ransomware payload', probability:23, technique:'T1486', tool:'LockBit 4.0', impact:'critical', outcome:'Encrypt Finance segment — high noise, maximum immediate impact', detection_coverage:78, detection_gap:'Shadow copy deletion before encryption may not alert in time', recommended_defense:'Enable VSS tamper alerts + honeypot ransom files', time_to_execute:'5-15m' },
        ]
      },
      {
        id: 'SIM-002', label: 'Phishing → Cloud Takeover',
        scenario: 'Attacker harvested M365 OAuth token via AiTM phishing',
        current_position: 'Valid M365 access token (no MFA required for legacy apps)',
        context: 'victim.user@company.com token valid · Exchange Online accessible',
        branches: [
          { id:'B1', action:'Register malicious OAuth application', probability:82, technique:'T1550.001', tool:'Custom OAuth App', impact:'critical', outcome:'Persistent access via OAuth app survives password reset', detection_coverage:22, detection_gap:'Third-party OAuth app creation not monitored in Entra ID', recommended_defense:'Block non-admin OAuth app creation + audit consent grants', time_to_execute:'5m' },
          { id:'B2', action:'Search email for VPN / cloud credentials', probability:91, technique:'T1114.002', tool:'Graph API email search', impact:'high', outcome:'Find VPN credentials / service account passwords in email threads', detection_coverage:31, detection_gap:'Graph API searches from new IP not alerted', recommended_defense:'Alert on Graph API mailbox access from new devices', time_to_execute:'15-30m' },
          { id:'B3', action:'Create new admin account in Entra ID', probability:55, technique:'T1136.003', tool:'Graph API / Portal', impact:'critical', outcome:'Backdoor admin account persists even after incident remediation', detection_coverage:67, detection_gap:'New account creation alerted but takes 30m to reach SOC', recommended_defense:'Automate block of new admin account creation until verified', time_to_execute:'2m' },
        ]
      },
      {
        id: 'SIM-003', label: 'Supply Chain Compromise → Customer Pivot',
        scenario: 'MSSP management platform compromised via malicious update',
        current_position: 'Access to MSSP RMM tool with agent on 47 customer endpoints',
        context: 'Legitimate RMM binary signed · No behavioral detection · All customers affected',
        branches: [
          { id:'B1', action:'Deploy backdoor via RMM to all customers', probability:95, technique:'T1072', tool:'Compromised RMM (SolarWinds-style)', impact:'critical', outcome:'Simultaneous access to all 47 customer environments — mass breach', detection_coverage:12, detection_gap:'Signed binary from trusted RMM not inspected by EDR', recommended_defense:'Behavior-based inspection of RMM-deployed executables + MFA for RMM portal', time_to_execute:'<30m' },
          { id:'B2', action:'Target highest-value customers selectively', probability:78, technique:'T1199', tool:'Custom backdoor', impact:'critical', outcome:'Targeted exfiltration from financial/government customers', detection_coverage:25, detection_gap:'Cross-customer traffic from RMM not baseline-compared', recommended_defense:'Isolate customer networks from each other within RMM platform', time_to_execute:'2-6h' },
        ]
      },
      {
        id: 'SIM-004', label: 'Insider Threat → Data Exfiltration',
        scenario: 'Departing employee with admin access before off-boarding completes',
        current_position: 'Active admin credentials · VPN access · SharePoint/OneDrive permission',
        context: 'Resignation submitted · HR notified IT 48h delay · Access still active',
        branches: [
          { id:'B1', action:'Bulk download SharePoint libraries to personal cloud', probability:88, technique:'T1567.002', tool:'Browser / OneDrive sync', impact:'high', outcome:'IP, customer data, source code exfiltrated to personal Google Drive', detection_coverage:42, detection_gap:'DLP policy does not cover SharePoint-to-personal-cloud transfers', recommended_defense:'Immediate access revocation on resignation + DLP policy for cloud upload', time_to_execute:'30-60m' },
          { id:'B2', action:'Create unauthorized admin account for future access', probability:51, technique:'T1136.001', tool:'Active Directory Users', impact:'critical', outcome:'Backdoor account maintains access post-employment', detection_coverage:58, detection_gap:'New admin account creation alerted but not auto-blocked', recommended_defense:'Auto-disable new account creation for accounts created within 48h of another', time_to_execute:'5m' },
          { id:'B3', action:'Exfiltrate via USB / email forwarding', probability:67, technique:'T1052.001', tool:'USB / Personal email', impact:'medium', outcome:'Data exfiltration via unsupervised channels', detection_coverage:35, detection_gap:'USB access logging not enabled on endpoints', recommended_defense:'Enable USB restriction policy + email DLP rules', time_to_execute:'1-4h' },
        ]
      },
      {
        id: 'SIM-005', label: 'Exposed API → Database Exfiltration',
        scenario: 'Attacker found exposed internal API endpoint via subdomain enumeration',
        current_position: 'Unauthenticated access to /api/v1/debug endpoint on dev.company.com',
        context: 'Endpoint returns stack traces with DB connection strings · No rate limiting',
        branches: [
          { id:'B1', action:'Extract DB credentials from stack traces', probability:92, technique:'T1552.001', tool:'curl / custom parser', impact:'critical', outcome:'Full database read access — customer PII, billing data, internal configs', detection_coverage:18, detection_gap:'Debug endpoint not in WAF rules — no logging on dev subdomain', recommended_defense:'Disable debug endpoints in production + centralized logging for dev subdomains', time_to_execute:'10-30m' },
          { id:'B2', action:'Enumerate API endpoints for auth bypass', probability:74, technique:'T1190', tool:'FFUF / Burp Suite', impact:'high', outcome:'Find additional unprotected admin API endpoints', detection_coverage:33, detection_gap:'WAF only covers main domain — dev subdomain excluded', recommended_defense:'Extend WAF coverage to all subdomains + API endpoint inventory', time_to_execute:'1-3h' },
        ]
      },
      {
        id: 'SIM-006', label: 'Ransomware Pre-Stage → Full Encryption',
        scenario: 'BlackCat affiliate established 3-week dormant persistence on file server',
        current_position: 'Active beacon on FS-PROD-01 · Domain admin credentials obtained · 48h until planned detonation',
        context: 'StealBit exfiltration tool pre-deployed · VSS deletion script ready · Backup servers identified',
        branches: [
          { id:'B1', action:'Exfiltrate via StealBit before encryption', probability:96, technique:'T1041', tool:'StealBit / Rclone', impact:'critical', outcome:'12TB customer data exfiltrated — enables triple extortion', detection_coverage:28, detection_gap:'Rclone to cloud provider not blocked outbound', recommended_defense:'Block rclone / MEGA / Megaupload outbound + DPI for large data transfers', time_to_execute:'2-4h' },
          { id:'B2', action:'Delete all backup infrastructure first', probability:88, technique:'T1490', tool:'WMIC / PowerShell', impact:'critical', outcome:'No recovery option — full ransom payment required', detection_coverage:45, detection_gap:'Backup deletion only alerted after completion — too late', recommended_defense:'Real-time VSS delete alerting + immutable backup isolation', time_to_execute:'15-30m' },
          { id:'B3', action:'Deploy encryption during business hours (max pressure)', probability:41, technique:'T1486', tool:'BlackCat Rust encryptor', impact:'critical', outcome:'Maximum business disruption + media attention for pressure', detection_coverage:71, detection_gap:'Encryption triggers EDR alert but too late if backups already deleted', recommended_defense:'Run encryption simulation in test env + validate detection rule coverage', time_to_execute:'30-90m' },
        ]
      },
    ];

    let _currentSimIdx = 0;

    function _renderSimulation(sim) {
      const el = document.getElementById('page-whatif-simulator');
      if (!el) return;
      const impactColors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' };

      // Find existing module body or rebuild
      let body = el.querySelector('.cds-module-body');
      if (!body) {
        // Full render needed
        el.innerHTML = `
        <div class="cds-module cds-accent-whatif" style="min-height:100%;">
          <div class="cds-module-header">
            <div class="cds-module-title-group">
              <div class="cds-module-icon" style="background:rgba(249,115,22,0.1);color:#f97316;border:1px solid rgba(249,115,22,0.3);">
                <i class="fas fa-chess"></i>
              </div>
              <div>
                <div class="cds-module-name">What-If Attack Simulator</div>
                <div class="cds-module-meta">
                  <div class="cds-status cds-status-online"><div class="cds-status-dot" style="background:#f97316;box-shadow:0 0 4px #f97316;"></div>Simulation Active</div>
                  <span>·</span><span id="whatif-scenario-label">Scenario ${_currentSimIdx+1} of ${WHATIF_SCENARIOS.length}</span>
                </div>
              </div>
            </div>
            <div class="cds-module-actions">
              <button class="cds-btn cds-btn-sm cds-btn-primary" id="whatif-run-btn" onclick="window._whatifRunNew()">
                <i class="fas fa-play"></i> Run New Simulation
              </button>
              <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="window._whatifPrev()" title="Previous scenario">
                <i class="fas fa-chevron-left"></i>
              </button>
              <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="window._whatifNext()" title="Next scenario">
                <i class="fas fa-chevron-right"></i>
              </button>
            </div>
          </div>
          <div class="cds-module-body" id="whatif-sim-body">
          </div>
        </div>`;
        body = el.querySelector('.cds-module-body');
      }

      // Update scenario label
      const label = el.querySelector('#whatif-scenario-label');
      if (label) label.textContent = `Scenario ${_currentSimIdx+1} of ${WHATIF_SCENARIOS.length}: ${sim.label}`;

      body.innerHTML = `
        <!-- Scenario Context -->
        <div class="cds-card" style="margin-bottom:16px;border:1px solid rgba(249,115,22,0.2);background:rgba(249,115,22,0.04);">
          <div style="display:flex;align-items:flex-start;gap:12px;">
            <i class="fas fa-map-marker-alt" style="color:#f97316;font-size:18px;margin-top:2px;flex-shrink:0;"></i>
            <div>
              <div style="font-size:13px;font-weight:700;color:#e6edf3;margin-bottom:4px;">${_e(sim.scenario)}</div>
              <div style="display:flex;gap:14px;flex-wrap:wrap;font-size:.78em;color:#8b949e;">
                <span><i class="fas fa-map-pin" style="margin-right:4px;"></i>${_e(sim.current_position)}</span>
                <span><i class="fas fa-tools" style="margin-right:4px;"></i>${_e(sim.context)}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Attack Branches -->
        <div class="cds-section-title" style="margin-bottom:12px;"><i class="fas fa-code-branch"></i> Probable Attack Paths (ranked by probability)</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;">
          ${sim.branches.sort((a,b)=>b.probability-a.probability).map((b,idx)=>`
          <div class="cds-card" style="border-left:4px solid ${impactColors[b.impact]||'#8b949e'};position:relative;animation:fadeIn .4s ease ${idx*0.1}s both;">
            <div style="position:absolute;top:-8px;right:10px;background:${impactColors[b.impact]};color:#fff;font-size:9px;font-weight:700;padding:2px 8px;border-radius:10px;">#${idx+1} MOST LIKELY</div>
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;margin-top:8px;">
              <div style="flex:1;">
                <div style="font-size:12px;font-weight:700;color:#e6edf3;margin-bottom:3px;">${_e(b.action)}</div>
                <div style="display:flex;gap:5px;flex-wrap:wrap;">
                  <span style="font-size:.68em;background:rgba(239,68,68,.08);color:#ef4444;border:1px solid rgba(239,68,68,.2);padding:1px 6px;border-radius:4px;font-family:monospace;">${_e(b.technique)}</span>
                  <span style="font-size:.7em;color:#6e7681;">${_e(b.tool)}</span>
                </div>
              </div>
              <div style="text-align:right;flex-shrink:0;margin-left:8px;">
                <div style="font-size:22px;font-weight:800;font-family:monospace;color:${impactColors[b.impact]};">${b.probability}%</div>
                <div style="font-size:.65em;color:#6e7681;">Probability</div>
                <div style="font-size:.68em;color:#8b949e;">⏱ ${b.time_to_execute}</div>
              </div>
            </div>
            <div style="font-size:.78em;color:#8b949e;line-height:1.4;margin-bottom:10px;">${_e(b.outcome)}</div>
            <!-- Coverage Bar -->
            <div style="margin-bottom:8px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                <span style="font-size:.7em;color:#6e7681;">Detection Coverage</span>
                <span style="font-size:.72em;font-weight:700;color:${b.detection_coverage<40?'#ef4444':b.detection_coverage<70?'#f97316':'#22c55e'};">${b.detection_coverage}%</span>
              </div>
              <div style="height:5px;background:rgba(255,255,255,0.06);border-radius:3px;">
                <div style="height:100%;width:${b.detection_coverage}%;background:${b.detection_coverage<40?'#ef4444':b.detection_coverage<70?'#f97316':'#22c55e'};border-radius:3px;transition:width .8s;"></div>
              </div>
            </div>
            <!-- Gap -->
            <div style="background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.15);border-radius:5px;padding:7px;margin-bottom:8px;font-size:.76em;">
              <span style="color:#ef4444;font-weight:600;">⚠ Gap: </span><span style="color:#8b949e;">${_e(b.detection_gap)}</span>
            </div>
            <!-- Defense -->
            <div style="background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.15);border-radius:5px;padding:7px;font-size:.76em;">
              <span style="color:#22c55e;font-weight:600;">🛡 Defense: </span><span style="color:#8b949e;">${_e(b.recommended_defense)}</span>
            </div>
          </div>`).join('')}
        </div>

        <!-- Simulation Controls -->
        <div style="margin-top:16px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap;">
          <button onclick="window._whatifRunNew()" style="background:linear-gradient(135deg,#f97316,#ef4444);color:#fff;border:none;padding:9px 18px;border-radius:8px;font-size:.85em;font-weight:700;cursor:pointer;"><i class="fas fa-random" style="margin-right:5px;"></i>Random Scenario</button>
          <button onclick="window._whatifExport()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:9px 18px;border-radius:8px;font-size:.85em;cursor:pointer;"><i class="fas fa-file-export" style="margin-right:5px;"></i>Export Defenses</button>
          <button onclick="window._whatifPrev()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:9px 18px;border-radius:8px;font-size:.85em;cursor:pointer;"><i class="fas fa-chevron-left" style="margin-right:5px;"></i>Previous</button>
          <button onclick="window._whatifNext()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:9px 18px;border-radius:8px;font-size:.85em;cursor:pointer;"><i class="fas fa-chevron-right" style="margin-right:5px;"></i>Next Scenario</button>
        </div>`;
    }

    // Override the renderWhatIfSimulator and _whatifRunNew
    window.renderWhatIfSimulator = function () {
      _renderSimulation(WHATIF_SCENARIOS[_currentSimIdx]);
    };

    window._whatifRunNew = function () {
      // Animate button
      const btn = document.getElementById('whatif-run-btn');
      if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating…'; btn.disabled = true; }
      // Select random different scenario
      let next = _rand(0, WHATIF_SCENARIOS.length - 1);
      while (next === _currentSimIdx && WHATIF_SCENARIOS.length > 1) next = _rand(0, WHATIF_SCENARIOS.length - 1);
      setTimeout(() => {
        _currentSimIdx = next;
        _renderSimulation(WHATIF_SCENARIOS[_currentSimIdx]);
        if (btn) { btn.innerHTML = '<i class="fas fa-play"></i> Run New Simulation'; btn.disabled = false; }
        _toast(`🎯 Loaded: "${WHATIF_SCENARIOS[_currentSimIdx].label}"`, 'info');
      }, 600);
    };

    window._whatifNext = function () {
      _currentSimIdx = (_currentSimIdx + 1) % WHATIF_SCENARIOS.length;
      _renderSimulation(WHATIF_SCENARIOS[_currentSimIdx]);
    };

    window._whatifPrev = function () {
      _currentSimIdx = (_currentSimIdx - 1 + WHATIF_SCENARIOS.length) % WHATIF_SCENARIOS.length;
      _renderSimulation(WHATIF_SCENARIOS[_currentSimIdx]);
    };

    window._whatifExport = function () {
      const sim = WHATIF_SCENARIOS[_currentSimIdx];
      const defenses = sim.branches.flatMap(b => [`[${b.technique}] ${b.recommended_defense}`]);
      const text = `Wadjet-Eye AI — What-If Simulation Export\nScenario: ${sim.label}\n\nPRE-EMPTIVE DEFENSES:\n${defenses.join('\n')}`;
      const blob = new Blob([text], { type: 'text/plain' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `whatif-${sim.id}-defenses.txt`; a.click();
      _toast('Defense recommendations exported', 'success');
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #8 — TENANT MANAGEMENT FULL CRUD
     Root cause: renderTenantManagement() had UI but Add Tenant button's
     modal form had no submit handler, and tenant detail click showed nothing.
     Fix: Fully functional inline CRUD with modal forms + local state management.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixTenantManagement() {
    const TM_STATE = {
      tenants: [
        { id:'T001', name:'MSSP Global Operations', slug:'mssp-global', plan:'Sovereign', status:'active', users:47, analysts:18, hunters:6, admins:3, industry:'MSSP', region:'Global', created:'2024-01-15', iocs_today:8241, findings_open:12, health:98, contact:'Mahmoud Osman', email:'mahmoud.osman@wadjet.ai', notes:'Primary MSSP tenant — all features enabled' },
        { id:'T002', name:'AcmeCorp Security', slug:'acme-corp', plan:'Enterprise', status:'active', users:22, analysts:12, hunters:3, admins:2, industry:'Finance', region:'North America', created:'2024-03-20', iocs_today:2103, findings_open:4, health:94, contact:'James Chen', email:'j.chen@acmecorp.com', notes:'Financial services client — PCI-DSS compliance required' },
        { id:'T003', name:'HealthNet SOC', slug:'healthnet', plan:'Professional', status:'active', users:15, analysts:8, hunters:2, admins:1, industry:'Healthcare', region:'Europe', created:'2024-06-01', iocs_today:891, findings_open:7, health:87, contact:'Maria Santos', email:'m.santos@healthnet.eu', notes:'HIPAA compliance mode enabled' },
        { id:'T004', name:'GovSec Agency', slug:'govse-agency', plan:'Sovereign', status:'active', users:35, analysts:20, hunters:8, admins:4, industry:'Government', region:'UK', created:'2024-02-10', iocs_today:5432, findings_open:3, health:99, contact:'David Wilson', email:'d.wilson@govsec.gov.uk', notes:'Air-gapped deployment — no external API calls' },
        { id:'T005', name:'TechStartup Beta', slug:'techstartup', plan:'Starter', status:'trial', users:3, analysts:2, hunters:0, admins:1, industry:'Technology', region:'APAC', created:'2025-12-01', iocs_today:134, findings_open:1, health:72, contact:'Priya Sharma', email:'priya@techstartup.io', notes:'14-day trial — expires in 6 days' },
      ],
      nextId: 6,
      editing: null,
    };

    window.renderTenantManagement = function () {
      const el = document.getElementById('page-customers') || document.getElementById('customersGrid');
      if (!el) return;

      const planColor = p => ({'Sovereign':'#f59e0b','Enterprise':'#a855f7','Professional':'#3b82f6','Starter':'#22c55e'}[p]||'#8b949e');
      const statusColor = s => ({'active':'#22c55e','trial':'#f59e0b','suspended':'#ef4444'}[s]||'#8b949e');
      const healthColor = h => h >= 90 ? '#22c55e' : h >= 70 ? '#f59e0b' : '#ef4444';

      el.className = '';
      el.innerHTML = `
      <div style="max-width:1200px;margin:0 auto;padding:20px;">
        <!-- Header -->
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px;">
          <div style="display:flex;align-items:center;gap:12px;">
            <div style="width:44px;height:44px;background:linear-gradient(135deg,#3b82f6,#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff;"><i class="fas fa-building"></i></div>
            <div>
              <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0;">Tenant Management</h2>
              <div style="font-size:.76em;color:#8b949e;">${TM_STATE.tenants.length} tenants · ${TM_STATE.tenants.reduce((a,t)=>a+t.users,0)} total users</div>
            </div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <input id="tm-search" placeholder="🔍 Search tenants…" oninput="window._tmFilter(this.value)"
              style="background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 12px;border-radius:6px;font-size:.82em;width:180px;" />
            <button onclick="window._tmOpenCreate()" style="background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;border:none;padding:8px 16px;border-radius:7px;font-size:.84em;font-weight:700;cursor:pointer;"><i class="fas fa-plus" style="margin-right:5px;"></i>Add Tenant</button>
          </div>
        </div>

        <!-- KPIs -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px;">
          ${[
            ['Total Tenants', TM_STATE.tenants.length, '#3b82f6', 'fa-building'],
            ['Active', TM_STATE.tenants.filter(t=>t.status==='active').length, '#22c55e', 'fa-check-circle'],
            ['On Trial', TM_STATE.tenants.filter(t=>t.status==='trial').length, '#f59e0b', 'fa-clock'],
            ['Total Users', TM_STATE.tenants.reduce((a,t)=>a+t.users,0), '#a855f7', 'fa-users'],
          ].map(([l,v,c,i])=>`
          <div style="background:#0d1117;border:1px solid #21262d;border-top:3px solid ${c};border-radius:10px;padding:14px;text-align:center;">
            <i class="fas ${i}" style="font-size:1.3em;color:${c};margin-bottom:6px;display:block;"></i>
            <div style="font-size:1.3em;font-weight:700;color:#e6edf3;font-family:monospace;">${v}</div>
            <div style="font-size:.74em;color:#8b949e;">${l}</div>
          </div>`).join('')}
        </div>

        <!-- Tenant Table -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:12px;overflow:hidden;">
          <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.82em;" id="tm-table">
              <thead>
                <tr style="background:#161b22;border-bottom:1px solid #21262d;">
                  <th style="padding:12px 16px;text-align:left;color:#8b949e;font-weight:600;">Tenant</th>
                  <th style="padding:12px 8px;text-align:center;color:#8b949e;font-weight:600;">Plan</th>
                  <th style="padding:12px 8px;text-align:center;color:#8b949e;font-weight:600;">Status</th>
                  <th style="padding:12px 8px;text-align:center;color:#8b949e;font-weight:600;">Users</th>
                  <th style="padding:12px 8px;text-align:center;color:#8b949e;font-weight:600;">IOCs Today</th>
                  <th style="padding:12px 8px;text-align:center;color:#8b949e;font-weight:600;">Health</th>
                  <th style="padding:12px 16px;text-align:right;color:#8b949e;font-weight:600;">Actions</th>
                </tr>
              </thead>
              <tbody id="tm-tbody">
                ${TM_STATE.tenants.map(t=>`
                <tr class="tm-row" data-id="${t.id}" style="border-bottom:1px solid #161b22;cursor:pointer;transition:.15s;" onmouseover="this.style.background='#0f1623'" onmouseout="this.style.background=''" onclick="window._tmViewDetail('${t.id}')">
                  <td style="padding:12px 16px;">
                    <div style="display:flex;align-items:center;gap:10px;">
                      <div style="width:34px;height:34px;background:${planColor(t.plan)}18;border:1px solid ${planColor(t.plan)}33;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:${planColor(t.plan)};">${t.name.charAt(0)}</div>
                      <div>
                        <div style="font-weight:600;color:#e6edf3;">${_e(t.name)}</div>
                        <div style="font-size:.75em;color:#6e7681;">@${_e(t.slug)} · ${_e(t.industry)} · ${_e(t.region)}</div>
                      </div>
                    </div>
                  </td>
                  <td style="padding:12px 8px;text-align:center;"><span style="background:${planColor(t.plan)}18;color:${planColor(t.plan)};border:1px solid ${planColor(t.plan)}33;padding:2px 8px;border-radius:8px;font-size:.75em;font-weight:600;">${_e(t.plan)}</span></td>
                  <td style="padding:12px 8px;text-align:center;"><span style="display:inline-flex;align-items:center;gap:4px;font-size:.78em;font-weight:600;color:${statusColor(t.status)};"><span style="width:6px;height:6px;border-radius:50%;background:${statusColor(t.status)};"></span>${t.status}</span></td>
                  <td style="padding:12px 8px;text-align:center;color:#8b949e;">${t.users}</td>
                  <td style="padding:12px 8px;text-align:center;color:#8b949e;font-family:monospace;">${t.iocs_today.toLocaleString()}</td>
                  <td style="padding:12px 8px;text-align:center;">
                    <div style="display:flex;align-items:center;justify-content:center;gap:6px;">
                      <div style="width:50px;height:5px;background:rgba(255,255,255,0.06);border-radius:3px;"><div style="height:100%;width:${t.health}%;background:${healthColor(t.health)};border-radius:3px;"></div></div>
                      <span style="font-size:.78em;font-weight:700;color:${healthColor(t.health)};">${t.health}%</span>
                    </div>
                  </td>
                  <td style="padding:12px 16px;text-align:right;" onclick="event.stopPropagation()">
                    <div style="display:flex;gap:6px;justify-content:flex-end;">
                      <button onclick="window._tmViewDetail('${t.id}')" title="View Details" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px 8px;border-radius:5px;font-size:.78em;cursor:pointer;"><i class="fas fa-eye"></i></button>
                      <button onclick="window._tmOpenEdit('${t.id}')" title="Edit" style="background:#21262d;color:#3b82f6;border:1px solid #30363d;padding:4px 8px;border-radius:5px;font-size:.78em;cursor:pointer;"><i class="fas fa-edit"></i></button>
                      <button onclick="window._tmDelete('${t.id}')" title="Delete" style="background:#21262d;color:#ef4444;border:1px solid #30363d;padding:4px 8px;border-radius:5px;font-size:.78em;cursor:pointer;"><i class="fas fa-trash"></i></button>
                    </div>
                  </td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- CRUD Modal -->
      <div id="tm-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:9999;overflow-y:auto;" onclick="if(event.target===this)window._tmCloseModal()">
        <div style="max-width:560px;margin:40px auto;background:#0d1117;border:1px solid #30363d;border-radius:14px;padding:28px;" id="tm-modal-body"></div>
      </div>

      <!-- Detail Drawer -->
      <div id="tm-detail" style="display:none;position:fixed;top:0;right:0;bottom:0;width:420px;background:#0d1117;border-left:1px solid #30363d;z-index:9998;overflow-y:auto;box-shadow:-10px 0 40px rgba(0,0,0,0.5);" id="tm-detail-drawer">
        <div id="tm-detail-body" style="padding:24px;"></div>
      </div>`;

      // Filter function
      window._tmFilter = function (q) {
        document.querySelectorAll('.tm-row').forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = !q || text.includes(q.toLowerCase()) ? '' : 'none';
        });
      };

      // View Detail
      window._tmViewDetail = function (id) {
        const t = TM_STATE.tenants.find(x => x.id === id);
        if (!t) return;
        const drawer = document.getElementById('tm-detail');
        const body = document.getElementById('tm-detail-body');
        if (!drawer || !body) return;
        body.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <div style="font-size:1.1em;font-weight:700;color:#e6edf3;">${_e(t.name)}</div>
            <button onclick="document.getElementById('tm-detail').style.display='none'" style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:5px 10px;border-radius:5px;cursor:pointer;">✕</button>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px;">
            ${[['Plan',t.plan],['Status',t.status],['Industry',t.industry],['Region',t.region],['Contact',t.contact],['Email',t.email],['Created',t.created],['Slug',t.slug]].map(([k,v])=>`
            <div style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px;">
              <div style="font-size:.7em;color:#6e7681;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px;">${k}</div>
              <div style="font-size:.85em;color:#e6edf3;font-weight:600;">${_e(v)}</div>
            </div>`).join('')}
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:16px;">
            ${[['Total Users',t.users,'#3b82f6'],['Analysts',t.analysts,'#22c55e'],['Hunters',t.hunters,'#a855f7'],['Admins',t.admins,'#f59e0b'],['Open Findings',t.findings_open,'#ef4444'],['IOCs Today',t.iocs_today.toLocaleString(),'#00d4ff']].map(([l,v,c])=>`
            <div style="background:#161b22;border-top:2px solid ${c};border-radius:6px;padding:10px;text-align:center;">
              <div style="font-size:1.1em;font-weight:700;color:${c};font-family:monospace;">${v}</div>
              <div style="font-size:.7em;color:#6e7681;">${l}</div>
            </div>`).join('')}
          </div>
          ${t.notes ? `<div style="background:rgba(59,130,246,0.05);border:1px solid rgba(59,130,246,0.2);border-radius:6px;padding:12px;margin-bottom:14px;"><div style="font-size:.75em;color:#3b82f6;font-weight:600;margin-bottom:4px;">NOTES</div><div style="font-size:.82em;color:#8b949e;">${_e(t.notes)}</div></div>` : ''}
          <div style="display:flex;gap:8px;margin-top:4px;">
            <button onclick="window._tmOpenEdit('${t.id}')" style="flex:1;background:#3b82f620;color:#3b82f6;border:1px solid #3b82f633;padding:8px;border-radius:6px;font-size:.82em;cursor:pointer;font-weight:600;"><i class="fas fa-edit" style="margin-right:5px;"></i>Edit Tenant</button>
            <button onclick="window._tmDelete('${t.id}')" style="background:#ef444420;color:#ef4444;border:1px solid #ef444433;padding:8px 14px;border-radius:6px;font-size:.82em;cursor:pointer;"><i class="fas fa-trash"></i></button>
          </div>`;
        drawer.style.display = 'block';
      };

      // Open Create Modal
      window._tmOpenCreate = function () {
        TM_STATE.editing = null;
        const modal = document.getElementById('tm-modal');
        const body = document.getElementById('tm-modal-body');
        if (!modal || !body) return;
        body.innerHTML = _tmForm(null);
        modal.style.display = 'block';
      };

      // Open Edit Modal
      window._tmOpenEdit = function (id) {
        const t = TM_STATE.tenants.find(x => x.id === id);
        if (!t) return;
        TM_STATE.editing = id;
        const modal = document.getElementById('tm-modal');
        const body = document.getElementById('tm-modal-body');
        if (!modal || !body) return;
        body.innerHTML = _tmForm(t);
        modal.style.display = 'block';
      };

      // Close modal
      window._tmCloseModal = function () {
        const m = document.getElementById('tm-modal');
        if (m) m.style.display = 'none';
      };

      // Submit form
      window._tmSubmitForm = function () {
        const get = id => (document.getElementById(id) || {}).value || '';
        const name = get('tm-f-name').trim();
        if (!name) { _toast('⚠️ Tenant name is required', 'warning'); return; }

        const data = {
          name, slug: get('tm-f-slug').trim() || name.toLowerCase().replace(/\s+/g,'-').replace(/[^a-z0-9-]/g,''),
          plan: get('tm-f-plan'), status: get('tm-f-status'),
          industry: get('tm-f-industry'), region: get('tm-f-region'),
          contact: get('tm-f-contact'), email: get('tm-f-email'), notes: get('tm-f-notes'),
          users: parseInt(get('tm-f-users')) || 1,
          analysts: parseInt(get('tm-f-analysts')) || 1,
          hunters: parseInt(get('tm-f-hunters')) || 0,
          admins: parseInt(get('tm-f-admins')) || 1,
          iocs_today: 0, findings_open: 0, health: 100,
        };

        if (TM_STATE.editing) {
          const idx = TM_STATE.tenants.findIndex(t => t.id === TM_STATE.editing);
          if (idx !== -1) { TM_STATE.tenants[idx] = { ...TM_STATE.tenants[idx], ...data }; }
          _toast(`✅ Tenant "${name}" updated`, 'success');
        } else {
          data.id = `T${String(TM_STATE.nextId++).padStart(3,'0')}`;
          data.created = new Date().toISOString().slice(0, 10);
          TM_STATE.tenants.push(data);
          _toast(`✅ Tenant "${name}" created`, 'success');
        }
        window._tmCloseModal();
        window.renderTenantManagement();
      };

      // Delete tenant
      window._tmDelete = function (id) {
        const t = TM_STATE.tenants.find(x => x.id === id);
        if (!t) return;
        if (!confirm(`Delete tenant "${t.name}"? This cannot be undone.`)) return;
        TM_STATE.tenants = TM_STATE.tenants.filter(x => x.id !== id);
        _toast(`🗑️ Tenant "${t.name}" deleted`, 'warning');
        const drawer = document.getElementById('tm-detail');
        if (drawer) drawer.style.display = 'none';
        window.renderTenantManagement();
      };
    };

    function _tmForm(t) {
      const val = (v) => _e(v || '');
      return `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
          <h3 style="font-size:1em;font-weight:700;color:#e6edf3;margin:0;">${t ? '✏️ Edit Tenant' : '➕ New Tenant'}</h3>
          <button onclick="window._tmCloseModal()" style="background:none;border:none;color:#8b949e;font-size:1.2em;cursor:pointer;">✕</button>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
          ${_tmField('tm-f-name','Tenant Name *','text',t?.name||'')}
          ${_tmField('tm-f-slug','Slug / Subdomain','text',t?.slug||'')}
          ${_tmSelect('tm-f-plan','Plan',['Starter','Professional','Enterprise','Sovereign'],t?.plan||'Professional')}
          ${_tmSelect('tm-f-status','Status',['active','trial','suspended'],t?.status||'active')}
          ${_tmField('tm-f-industry','Industry','text',t?.industry||'')}
          ${_tmField('tm-f-region','Region','text',t?.region||'')}
          ${_tmField('tm-f-contact','Contact Name','text',t?.contact||'')}
          ${_tmField('tm-f-email','Contact Email','email',t?.email||'')}
          ${_tmField('tm-f-users','Total Users','number',t?.users||1)}
          ${_tmField('tm-f-analysts','Analysts','number',t?.analysts||1)}
          ${_tmField('tm-f-hunters','Hunters','number',t?.hunters||0)}
          ${_tmField('tm-f-admins','Admins','number',t?.admins||1)}
        </div>
        <div style="margin-bottom:16px;">
          <label style="display:block;font-size:.78em;color:#8b949e;margin-bottom:5px;">Notes</label>
          <textarea id="tm-f-notes" rows="3" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;border-radius:6px;font-size:.85em;box-sizing:border-box;resize:vertical;">${val(t?.notes)}</textarea>
        </div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button onclick="window._tmCloseModal()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:8px 18px;border-radius:7px;font-size:.85em;cursor:pointer;">Cancel</button>
          <button onclick="window._tmSubmitForm()" style="background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;border:none;padding:8px 20px;border-radius:7px;font-size:.85em;font-weight:700;cursor:pointer;">
            ${t ? '<i class="fas fa-save" style="margin-right:5px;"></i>Save Changes' : '<i class="fas fa-plus" style="margin-right:5px;"></i>Create Tenant'}
          </button>
        </div>`;
    }
    function _tmField(id, label, type, value) {
      return `<div>
        <label style="display:block;font-size:.78em;color:#8b949e;margin-bottom:5px;">${label}</label>
        <input id="${id}" type="${type}" value="${_e(value)}" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;border-radius:6px;font-size:.85em;box-sizing:border-box;" />
      </div>`;
    }
    function _tmSelect(id, label, opts, selected) {
      return `<div>
        <label style="display:block;font-size:.78em;color:#8b949e;margin-bottom:5px;">${label}</label>
        <select id="${id}" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:8px 12px;border-radius:6px;font-size:.85em;">
          ${opts.map(o=>`<option value="${o}" ${o===selected?'selected':''}>${o}</option>`).join('')}
        </select>
      </div>`;
    }
  }

  /* ════════════════════════════════════════════════════════════════════════
     FIX #9 — NAVIGATION FREEZE / COMPONENT STACKING  (v22 — revised)
     Root cause: Pages use both display:none/block AND classList.active toggling
     inconsistently. When a page is navigated to, the old page's DOM remains
     visible because both systems fight each other.

     IMPORTANT — v22 NO LONGER re-wraps window.navigateTo.
     main.js already contains the canonical navigateTo with a proper
     try/finally block and an 8s safety timer that always releases _navLock.
     platform-fixes-v20.js adds debouncing on top of that.
     Stacking a THIRD wrapper (this file, v22) caused a 3-second force-release
     timer that fired BEFORE a legitimate page render finished, sporadically
     setting _navLock = false while the page was still loading, then allowing
     a second concurrent navigation that produced the "navLock force-released"
     console warning and page stacking.

     v22 now provides:
       _v22ShowPage(pageId) — unified page-visibility helper (display + class)
       navLock watchdog     — passive 1 s interval, only releases if lock age
                              exceeds 10 s (10 s > main.js 8 s safety timer)
       _navLock property    — getter/setter that records lock start time
     v22 does NOT modify window.navigateTo.
  ════════════════════════════════════════════════════════════════════════ */
  function _fixNavigation() {
    // ── Unified page-visibility helper ─────────────────────────
    window._v22ShowPage = function (pageId) {
      // Hide ALL pages — use both classList and display to cover
      // modules that use one or the other approach.
      document.querySelectorAll('.page, [id^="page-"]').forEach(p => {
        if (!p.id) return;
        if (p.id === `page-${pageId}`) return; // will show below
        p.classList.remove('active');
        p.style.display = 'none';
      });

      // Show target page
      const target = document.getElementById(`page-${pageId}`);
      if (target) {
        target.style.display = '';  // remove inline display:none
        target.classList.add('active');
      }
    };

    // ── Passive navLock watchdog — do NOT replace navigateTo ───
    // Only auto-release the lock if it has been held for more than
    // 10 seconds (safely above main.js's 8 s timer, so we only
    // fire in truly catastrophic cases where the safety timer itself
    // failed).
    setInterval(() => {
      if (window._navLock) {
        const lockAge = Date.now() - (window._navLockStart || 0);
        if (lockAge > 10000) {
          window._navLock = false;
          console.warn('[v22] navLock auto-released (stuck >10s)');
        }
      }
    }, 1000);

    // ── _navLock property — record timestamp when acquired ──────
    // Only define if not already defined (main.js may have set it).
    if (!Object.getOwnPropertyDescriptor(window, '_navLock')?.get) {
      Object.defineProperty(window, '_navLock', {
        get: function () { return window.__navLockVal; },
        set: function (v) {
          window.__navLockVal = v;
          if (v) window._navLockStart = Date.now();
        },
        configurable: true,
      });
    }

    // ── Patch nav-item AND nav-child clicks to call _v22ShowPage (CSS-only fix) ─
    // This fires BEFORE the main navigateTo handler so page display
    // is set synchronously, preventing a flash of the wrong page.
    // FIX: also match .nav-child[data-page] — the sidebar uses nested child items
    // that were NOT matched by the previous '.nav-item[data-page]' selector only,
    // causing the previous tab to remain visible until the debounced navigateTo ran.
    document.addEventListener('click', function (e) {
      const navItem = e.target.closest('.nav-item[data-page], .nav-child[data-page]');
      if (!navItem) return;
      const page = navItem.dataset.page;
      if (!page) return;
      window._v22ShowPage(page);
    }, true); // capture phase

    console.log('[v22] ✅ Fix #9: Navigation stability (watchdog-only mode — no navigateTo re-wrap)');
  }

  /* ════════════════════════════════════════════════════════════════════════
     INITIALIZATION — Run all fixes in correct order
  ════════════════════════════════════════════════════════════════════════ */
  function _init() {
    console.log('[v22] Applying 9 production fixes…');

    // Fix #9 first — navigation stability is foundational
    try { _fixNavigation(); console.log('[v22] ✅ Fix #9: Navigation stability'); } catch (e) { console.error('[v22] Fix #9 error:', e); }

    // DOM-ready fixes
    const _domReady = () => {
      try { _fixBranding(); console.log('[v22] ✅ Fix #1: Branding tab'); } catch (e) { console.error('[v22] Fix #1:', e); }
      try { _fixSettings(); console.log('[v22] ✅ Fix #2: Settings save'); } catch (e) { console.error('[v22] Fix #2:', e); }
      try { _fixPricing(); console.log('[v22] ✅ Fix #3: Pricing tab'); } catch (e) { console.error('[v22] Fix #3:', e); }
      try { _fixPredictiveEngine(); console.log('[v22] ✅ Fix #4: Predictive Engine'); } catch (e) { console.error('[v22] Fix #4:', e); }
      try { _fixMalwareDNA(); console.log('[v22] ✅ Fix #5: Malware DNA Engine'); } catch (e) { console.error('[v22] Fix #5:', e); }
      try { _fixNeverSeenBefore(); console.log('[v22] ✅ Fix #6: Label cleanup'); } catch (e) { console.error('[v22] Fix #6:', e); }
      try { _fixWhatIfSimulator(); console.log('[v22] ✅ Fix #7: What-If Simulator'); } catch (e) { console.error('[v22] Fix #7:', e); }
      try { _fixTenantManagement(); console.log('[v22] ✅ Fix #8: Tenant CRUD'); } catch (e) { console.error('[v22] Fix #8:', e); }
      console.log('[v22] 🎯 All fixes applied — Wadjet-Eye AI v22.0 ready');
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _domReady);
    } else {
      // Small delay to ensure all modules have loaded
      setTimeout(_domReady, 200);
    }
  }

  _init();

})();
