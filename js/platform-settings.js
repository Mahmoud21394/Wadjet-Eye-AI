/**
 * ══════════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Platform Settings UI v5.1 (PRODUCTION)
 *  FILE: js/platform-settings.js
 *
 *  Loads and saves real platform configuration via /api/settings.
 *  No static/mock data — all configuration persists to Supabase.
 *
 *  Sections:
 *  ─────────
 *  1. General (name, theme, timezone, session timeout)
 *  2. Threat Feeds (ingest schedule, feed selection)
 *  3. AI Configuration (provider, model, keys)
 *  4. SOAR Automation (thresholds, auto-execute)
 *  5. Notifications (Slack, email/SMTP)
 *  6. Integrations (Jira, ServiceNow)
 *  7. Retention policies
 *
 *  API Key Test:
 *  ─────────────
 *  Each API key field has a "Test" button → POST /api/settings/test-api
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

let _settingsData = {};
let _settingsDirty = false;

/* ─────────────────────────────────────────────
   API HELPERS — all go through auth interceptor
   Root cause fix for 401: token key mismatch and
   no retry on 401 meant settings page always failed.
   Now uses authFetch which handles all token variants
   + silent refresh + retry on 401.
───────────────────────────────────────────── */

/**
 * Unified settings API fetch — uses authFetch (auth-interceptor.js).
 */
async function _settingsFetch(path, opts = {}) {
  if (typeof window.authFetch === 'function') {
    return window.authFetch(path, opts);
  }

  // Fallback with comprehensive token lookup
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
  const token = localStorage.getItem('wadjet_access_token')
             || localStorage.getItem('we_access_token')
             || localStorage.getItem('tp_access_token')
             || sessionStorage.getItem('tp_token')
             || '';

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const r = await fetch(`${base}/api${path}`, {
    method:      opts.method || 'GET',
    headers,
    credentials: 'include',
    ...(opts.body ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) } : {}),
  });

  // 401 handling with silent refresh
  if (r.status === 401 || r.status === 403) {
    if (typeof window.PersistentAuth_silentRefresh === 'function') {
      const refreshed = await window.PersistentAuth_silentRefresh();
      if (refreshed) {
        const newToken = localStorage.getItem('wadjet_access_token') || '';
        const retry = await fetch(`${base}/api${path}`, {
          method: opts.method || 'GET',
          headers: { ...headers, Authorization: `Bearer ${newToken}` },
          credentials: 'include',
          ...(opts.body ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) } : {}),
        });
        if (retry.ok) return retry.json();
      }
    }
    // Check RBAC — 403 may mean insufficient permissions
    if (r.status === 403) {
      throw new Error('Access denied. Platform Settings requires Admin or Super Admin role.');
    }
    throw new Error('Session expired. Please log in again.');
  }

  if (r.status === 204) return null;
  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`HTTP ${r.status}: ${txt.slice(0, 120)}`);
  }
  return r.json();
}

async function _settingsGet(path)         { return _settingsFetch(path, { method: 'GET' }); }
async function _settingsPut(path, body)    { return _settingsFetch(path, { method: 'PUT',  body }); }
async function _settingsPost(path, body)   { return _settingsFetch(path, { method: 'POST', body }); }
async function _settingsPatch(path, body)  { return _settingsFetch(path, { method: 'PATCH', body }); }

async function _settingsTestApi(service, api_key, url) {
  return _settingsPost('/settings/test-api', { service, api_key, url });
}

// Legacy compat aliases
const _settingsApiBase = () => (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/, '');
const _settingsToken   = () => localStorage.getItem('wadjet_access_token')
                            || localStorage.getItem('we_access_token')
                            || sessionStorage.getItem('tp_token') || '';

/* ─────────────────────────────────────────────
   RENDER SETTINGS PAGE
───────────────────────────────────────────── */
async function renderSettings() {
  const wrap = document.getElementById('settingsWrap')
    || document.getElementById('page-settings');
  if (!wrap) return;

  wrap.innerHTML = `
    <div id="settings-root" style="padding:24px;max-width:900px;margin:0 auto;display:flex;flex-direction:column;gap:20px">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div>
          <h2 style="margin:0;color:#e6edf3;font-size:1.3em">
            <i class="fas fa-cog" style="color:#22d3ee;margin-right:8px"></i>Platform Settings
          </h2>
          <p style="margin:4px 0 0;color:#8b949e;font-size:.85em">All settings are saved to your tenant configuration in real-time</p>
        </div>
        <div style="display:flex;gap:10px">
          <button id="settings-save-btn" onclick="settingsSave()" disabled
            style="padding:8px 20px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em;opacity:.5">
            <i class="fas fa-save"></i> Save Changes
          </button>
          <button onclick="settingsReload()"
            style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
            <i class="fas fa-sync-alt"></i> Reload
          </button>
        </div>
      </div>

      <div id="settings-status" style="display:none;padding:10px 16px;border-radius:8px;font-size:.85em;background:#1d6ae520;border:1px solid #1d6ae5;color:#22d3ee"></div>

      <div id="settings-body">
        <div style="padding:48px;text-align:center;color:#8b949e">
          <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px"></i>Loading settings…
        </div>
      </div>
    </div>
  `;

  await settingsReload();
}

async function settingsReload() {
  const body = document.getElementById('settings-body');
  if (!body) return;

  try {
    const res   = await _settingsGet('/settings');
    _settingsData  = res.settings || {};
    _settingsDirty = false;
    _updateSaveBtn();
    body.innerHTML = _buildSettingsForm(_settingsData);
  } catch (err) {
    body.innerHTML = `<div style="padding:32px;text-align:center;color:#ef4444">
      <i class="fas fa-exclamation-triangle fa-2x" style="display:block;margin-bottom:10px"></i>
      Failed to load settings: ${err.message}
      <br><br>
      <button onclick="settingsReload()" style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer">Retry</button>
    </div>`;
  }
}

/* ─────────────────────────────────────────────
   BUILD FORM HTML
───────────────────────────────────────────── */
function _buildSettingsForm(s) {
  return `
    <!-- § General -->
    ${_section('fa-id-card','General', `
      ${_field('Platform Name',            'text',     'platform_name',          s.platform_name)}
      ${_field('Theme',                    'select',   'platform_theme',          s.platform_theme,     ['dark','light'])}
      ${_field('Default Timezone',         'text',     'default_timezone',        s.default_timezone)}
      ${_field('Session Timeout (min)',    'number',   'session_timeout_min',     s.session_timeout_min)}
    `)}

    <!-- § Threat Feeds -->
    ${_section('fa-rss','Threat Feed Ingestion', `
      ${_field('Ingest Interval (min)',    'number',   'ingest_interval_min',     s.ingest_interval_min)}
      ${_field('Auto-Ingest Enabled',     'toggle',   'ingest_enabled',          s.ingest_enabled)}
      <div style="margin-bottom:16px">
        <label style="display:block;font-size:.8em;color:#8b949e;font-weight:600;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Active Feeds</label>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          ${['otx','abuseipdb','urlhaus','threatfox','malwarebazaar'].map(f => `
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:6px 12px;background:#21262d;border:1px solid #30363d;border-radius:6px">
              <input type="checkbox" name="feeds_enabled" value="${f}"
                ${(s.feeds_enabled||[]).includes(f) ? 'checked' : ''}
                onchange="settingsMarkDirty()"
                style="cursor:pointer;accent-color:#22d3ee">
              <span style="font-size:.85em;color:#e6edf3;text-transform:capitalize">${f}</span>
            </label>
          `).join('')}
        </div>
      </div>
    `)}

    <!-- § AI Configuration -->
    ${_section('fa-brain','AI Configuration', `
      ${_field('AI Enabled',               'toggle',   'ai_enabled',              s.ai_enabled)}
      ${_field('Primary AI Provider',      'select',   'ai_provider',             s.ai_provider,         ['openai','gemini','anthropic','ollama'])}
      ${_field('AI Model',                 'text',     'ai_model',                s.ai_model)}
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;font-size:.8em;color:#8b949e;margin-bottom:16px">
        <i class="fas fa-info-circle" style="color:#22d3ee;margin-right:6px"></i>
        AI API keys are configured in your Render environment variables. Use the <strong style="color:#e6edf3">Test Connection</strong> buttons below to verify they work.
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        ${_testBtn('openai',     'Test OpenAI')}
        ${_testBtn('gemini',     'Test Gemini')}
        ${_testBtn('virustotal', 'Test VirusTotal')}
        ${_testBtn('abuseipdb',  'Test AbuseIPDB')}
        ${_testBtn('shodan',     'Test Shodan')}
      </div>
    `)}

    <!-- § SOAR Automation -->
    ${_section('fa-robot','SOAR Automation', `
      ${_field('Auto-Run SOAR Rules',      'toggle',   'soar_auto_run',           s.soar_auto_run)}
      ${_field('Human Approval Required',  'toggle',   'soar_human_approval_required', s.soar_human_approval_required)}
      ${_field('Risk Score Alert Threshold', 'number', 'risk_score_alert_threshold',   s.risk_score_alert_threshold)}
      ${_field('Auto-Case Threshold',      'number',   'critical_auto_case_threshold', s.critical_auto_case_threshold)}
    `)}

    <!-- § Notifications -->
    ${_section('fa-bell','Notifications', `
      ${_field('Slack Webhook URL',        'url',      'slack_webhook_url',        s.slack_webhook_url || '')}
      ${_field('SOAR Webhook URL',         'url',      'soar_webhook_url',         s.soar_webhook_url || '')}
      ${_field('Email Alerts Enabled',     'toggle',   'email_alerts_enabled',     s.email_alerts_enabled)}
      ${_field('SMTP Host',               'text',     'smtp_host',               s.smtp_host || '')}
      ${_field('SMTP Port',               'number',   'smtp_port',               s.smtp_port || 587)}
      ${_field('SMTP User',               'text',     'smtp_user',               s.smtp_user || '')}
      ${_field('From Address',            'email',    'smtp_from',               s.smtp_from || '')}
    `)}

    <!-- § Integrations -->
    ${_section('fa-plug','Integrations (Jira / ServiceNow)', `
      ${_field('Jira URL',                'url',      'jira_url',                 s.jira_url || '')}
      ${_field('Jira Project Key',        'text',     'jira_project_key',         s.jira_project_key || '')}
      ${_field('Jira API Token',          'password', 'jira_api_token',           s.jira_api_token || '')}
      ${_field('ServiceNow URL',          'url',      'servicenow_url',           s.servicenow_url || '')}
      ${_field('ServiceNow User',         'text',     'servicenow_user',          s.servicenow_user || '')}
      ${_field('ServiceNow Token',        'password', 'servicenow_token',         s.servicenow_token || '')}
    `)}

    <!-- § Retention -->
    ${_section('fa-clock','Data Retention Policies', `
      ${_field('IOC Retention (days)',      'number', 'ioc_retention_days',      s.ioc_retention_days)}
      ${_field('Alert Retention (days)',    'number', 'alert_retention_days',    s.alert_retention_days)}
      ${_field('Log Retention (days)',      'number', 'log_retention_days',      s.log_retention_days)}
    `)}
  `;
}

function _section(icon, title, content) {
  return `
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;margin-bottom:16px;overflow:hidden">
      <div style="padding:14px 20px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px;background:#0d1117">
        <i class="fas ${icon}" style="color:#22d3ee;width:16px"></i>
        <span style="font-size:.95em;font-weight:600;color:#e6edf3">${title}</span>
      </div>
      <div style="padding:20px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
        ${content}
      </div>
    </div>
  `;
}

function _field(label, type, key, value, options = []) {
  if (type === 'toggle') {
    return `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;background:#0d1117;border:1px solid #21262d;border-radius:8px">
        <label style="font-size:.85em;color:#e6edf3">${label}</label>
        <label style="position:relative;display:inline-block;width:44px;height:24px;cursor:pointer">
          <input type="checkbox" data-key="${key}" ${value ? 'checked' : ''}
            onchange="settingsFieldChanged('${key}', this.checked)"
            style="opacity:0;width:0;height:0">
          <span style="position:absolute;inset:0;background:${value?'#1d6ae5':'#30363d'};border-radius:12px;transition:.3s" id="tgl-${key}">
            <span style="position:absolute;left:${value?'22px':'2px'};top:2px;width:20px;height:20px;background:#fff;border-radius:50%;transition:.3s" id="tgl-knob-${key}"></span>
          </span>
        </label>
      </div>
    `;
  }

  if (type === 'select') {
    return `
      <div>
        <label style="display:block;font-size:.8em;color:#8b949e;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.04em">${label}</label>
        <select data-key="${key}" onchange="settingsFieldChanged('${key}', this.value)"
          style="width:100%;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.9em">
          ${options.map(o => `<option value="${o}" ${value===o?'selected':''}>${o}</option>`).join('')}
        </select>
      </div>
    `;
  }

  const inputType = type === 'password' ? 'password' : type === 'email' ? 'email' : type === 'url' ? 'url' : type === 'number' ? 'number' : 'text';
  return `
    <div>
      <label style="display:block;font-size:.8em;color:#8b949e;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.04em">${label}</label>
      <input type="${inputType}" data-key="${key}" value="${typeof value === 'string' ? value.replace(/"/g,'&quot;') : (value||'')}"
        oninput="settingsFieldChanged('${key}', ${type==='number' ? 'parseInt(this.value)||0' : 'this.value'})"
        style="width:100%;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.9em;box-sizing:border-box" />
    </div>
  `;
}

function _testBtn(service, label) {
  return `
    <button onclick="settingsTestApi('${service}')"
      id="test-btn-${service}"
      style="padding:7px 14px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.8em;display:flex;align-items:center;gap:6px">
      <i class="fas fa-plug"></i> ${label}
    </button>
  `;
}

/* ─────────────────────────────────────────────
   FIELD CHANGE HANDLER
───────────────────────────────────────────── */
function settingsFieldChanged(key, value) {
  _settingsData[key] = value;

  // Update toggle visual
  const tgl      = document.getElementById(`tgl-${key}`);
  const tglKnob  = document.getElementById(`tgl-knob-${key}`);
  if (tgl && tglKnob) {
    tgl.style.background     = value ? '#1d6ae5' : '#30363d';
    tglKnob.style.left       = value ? '22px' : '2px';
  }

  settingsMarkDirty();
}

function settingsMarkDirty() {
  _settingsDirty = true;
  _updateSaveBtn();
}

function _updateSaveBtn() {
  const btn = document.getElementById('settings-save-btn');
  if (!btn) return;
  btn.disabled = !_settingsDirty;
  btn.style.opacity = _settingsDirty ? '1' : '.5';
  btn.style.cursor  = _settingsDirty ? 'pointer' : 'default';
}

/* ─────────────────────────────────────────────
   SAVE SETTINGS
───────────────────────────────────────────── */
async function settingsSave() {
  const btn = document.getElementById('settings-save-btn');
  const status = document.getElementById('settings-status');

  if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving…'; btn.disabled = true; }

  // Collect feeds_enabled checkboxes
  const feedCheckboxes = document.querySelectorAll('input[name="feeds_enabled"]:checked');
  _settingsData.feeds_enabled = Array.from(feedCheckboxes).map(cb => cb.value);

  try {
    const res = await _settingsPut('/settings', _settingsData);
    _settingsData  = res.settings;
    _settingsDirty = false;
    _updateSaveBtn();

    if (status) {
      status.style.display = 'block';
      status.style.background = '#00cc4420';
      status.style.borderColor = '#00cc44';
      status.style.color = '#00cc44';
      status.textContent = `✅ Settings saved successfully (${res.updated_keys?.length || 0} keys updated)`;
      setTimeout(() => { if (status) status.style.display = 'none'; }, 4000);
    }

    if (typeof showToast === 'function') showToast('✅ Platform settings saved', 'success');
  } catch (err) {
    if (status) {
      status.style.display = 'block';
      status.style.background = '#ff444420';
      status.style.borderColor = '#ff4444';
      status.style.color = '#ff4444';
      status.textContent = `❌ Failed to save: ${err.message}`;
    }
    if (typeof showToast === 'function') showToast(`❌ Save failed: ${err.message}`, 'error');
  }

  if (btn) { btn.innerHTML = '<i class="fas fa-save"></i> Save Changes'; }
}

/* ─────────────────────────────────────────────
   TEST API KEY
───────────────────────────────────────────── */
async function settingsTestApi(service) {
  const btn = document.getElementById(`test-btn-${service}`);
  if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing…'; btn.disabled = true; }

  try {
    const result = await _settingsTestApi(service, null, null);
    const msg    = result.ok ? `✅ ${result.message}` : `❌ ${result.message}`;
    const color  = result.ok ? '#00cc44' : '#ff4444';
    if (typeof showToast === 'function') showToast(msg, result.ok ? 'success' : 'error', 5000);
    if (btn) btn.style.borderColor = color;
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Test failed: ${err.message}`, 'error');
  }

  if (btn) { btn.innerHTML = `<i class="fas fa-plug"></i> Test ${service.charAt(0).toUpperCase()+service.slice(1)}`; btn.disabled = false; }
}

// Export to global scope
window.renderSettings         = renderSettings;
window.settingsReload         = settingsReload;
window.settingsSave           = settingsSave;
window.settingsFieldChanged   = settingsFieldChanged;
window.settingsMarkDirty      = settingsMarkDirty;
window.settingsTestApi        = settingsTestApi;
