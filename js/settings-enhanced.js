/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Platform Settings Fix v2.0
 *  Fixes HTTP 400 save errors, adds proper validation,
 *  enhanced UI with animations, clear error messages
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── State ── */
let _settingsEnhData    = {};
let _settingsEnhDirty   = false;
let _settingsEnhSaving  = false;
let _settingsEnhSection = 'general';

/* ── API helpers ── */
async function _settingsEnhFetch(path, opts = {}) {
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const token = localStorage.getItem('wadjet_access_token')
             || localStorage.getItem('we_access_token')
             || localStorage.getItem('tp_access_token')
             || sessionStorage.getItem('tp_token') || '';

  // Try authFetch first
  if (window.authFetch) {
    try {
      return await window.authFetch(path, opts);
    } catch(e) {
      // Fall through to direct fetch on auth error
      if (!e.message?.includes('401') && !e.message?.includes('expired')) throw e;
    }
  }

  const fetchOpts = {
    method: opts.method || 'GET',
    headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
    credentials: 'include',
  };
  if (opts.body) fetchOpts.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);

  const r = await fetch(`${base}/api${path}`, fetchOpts);

  if (r.status === 204) return {};
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    // Parse JSON error if possible
    let errMsg = `HTTP ${r.status}`;
    try {
      const json = JSON.parse(text);
      errMsg = json.error || json.message || json.detail || errMsg;
    } catch { errMsg = text?.slice(0,120) || errMsg; }
    throw new Error(errMsg);
  }
  return r.json();
}

/* ── Validate settings before save ── */
function _validateSettings(data) {
  const errors = [];

  // Validate platform name
  if (data.platform_name && data.platform_name.length > 100) {
    errors.push('Platform name must be 100 characters or less');
  }

  // Validate session timeout
  if (data.session_timeout_minutes) {
    const n = parseInt(data.session_timeout_minutes);
    if (isNaN(n) || n < 5 || n > 10080) {
      errors.push('Session timeout must be between 5 minutes and 7 days (10080 minutes)');
    }
  }

  // Validate email if provided
  if (data.alert_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.alert_email)) {
    errors.push('Alert email address is invalid');
  }

  // Validate SMTP port
  if (data.smtp_port) {
    const port = parseInt(data.smtp_port);
    if (isNaN(port) || port < 1 || port > 65535) {
      errors.push('SMTP port must be between 1 and 65535');
    }
  }

  // Validate webhook URL
  if (data.webhook_url && data.webhook_url.length > 0) {
    try { new URL(data.webhook_url); } catch {
      errors.push('Webhook URL is not a valid URL');
    }
  }

  // Remove null/undefined/empty string values to avoid HTTP 400
  const cleaned = {};
  Object.entries(data).forEach(([k,v]) => {
    if (v !== null && v !== undefined && v !== '') {
      cleaned[k] = v;
    }
  });

  return { errors, cleaned };
}

/* ── Collect form data ── */
function _collectSettingsFormData() {
  const data = {};
  document.querySelectorAll('[data-setting]').forEach(el => {
    const key = el.getAttribute('data-setting');
    if (!key) return;
    if (el.type === 'checkbox') {
      data[key] = el.checked;
    } else if (el.type === 'number') {
      const n = parseFloat(el.value);
      if (!isNaN(n)) data[key] = n;
    } else {
      if (el.value && el.value.trim()) data[key] = el.value.trim();
    }
  });
  return data;
}

/* ── Save handler (fixes HTTP 400) ── */
window.settingsSaveEnhanced = async function() {
  if (_settingsEnhSaving) return;
  _settingsEnhSaving = true;

  const btn = document.getElementById('settings-save-btn-enh');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Saving…';
  }

  const rawData = _collectSettingsFormData();
  const { errors, cleaned } = _validateSettings(rawData);

  if (errors.length > 0) {
    _settingsShowStatus('error', `Validation failed: ${errors.join('; ')}`);
    _settingsEnhSaving = false;
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-save"></i> Save Changes'; }
    return;
  }

  try {
    // Use PATCH instead of PUT to avoid overwriting fields we didn't include
    await _settingsEnhFetch('/settings', {
      method: 'PATCH',
      body: cleaned,
    });

    _settingsEnhData   = { ..._settingsEnhData, ...cleaned };
    _settingsEnhDirty  = false;
    _settingsShowStatus('success', '✅ Settings saved successfully');
    if (btn) btn.style.opacity = '.5';
  } catch(err) {
    // Try PUT as fallback
    try {
      await _settingsEnhFetch('/settings', {
        method: 'PUT',
        body: { settings: cleaned },
      });
      _settingsEnhData  = { ..._settingsEnhData, ...cleaned };
      _settingsEnhDirty = false;
      _settingsShowStatus('success', '✅ Settings saved successfully');
      if (btn) btn.style.opacity = '.5';
    } catch(err2) {
      // Show clear error message
      const msg = err2.message || err.message || 'Unknown error';
      _settingsShowStatus('error', `Save failed: ${msg}. Please check your permissions and try again.`);
    }
  } finally {
    _settingsEnhSaving = false;
    if (btn) {
      btn.disabled = false;
      if (!_settingsEnhDirty) btn.innerHTML = '<i class="fas fa-check"></i> Saved';
      else btn.innerHTML = '<i class="fas fa-save"></i> Save Changes';
    }
  }
};

function _settingsShowStatus(type, message) {
  const el = document.getElementById('settings-status-enh');
  if (!el) return;
  el.className = `settings-status settings-status--${type}`;
  el.style.display = 'flex';
  el.innerHTML = `
    <i class="fas ${type==='success'?'fa-check-circle':type==='error'?'fa-exclamation-triangle':'fa-info-circle'}"></i>
    <span>${message}</span>
    <button onclick="this.parentElement.style.display='none'" style="margin-left:auto;background:none;border:none;color:inherit;cursor:pointer;padding:0 4px;font-size:1em">
      <i class="fas fa-times"></i>
    </button>
  `;
  if (type === 'success') setTimeout(() => { if (el) el.style.display = 'none'; }, 4000);
}

function _settingsMarkDirty() {
  _settingsEnhDirty = true;
  const btn = document.getElementById('settings-save-btn-enh');
  if (btn) { btn.disabled = false; btn.style.opacity = '1'; btn.innerHTML = '<i class="fas fa-save"></i> Save Changes'; }
}

/* ── Enhanced settings renderer ── */
window.renderSettingsEnhanced = async function() {
  const wrap = document.getElementById('settingsWrap') || document.getElementById('page-settings');
  if (!wrap) return;

  wrap.innerHTML = `
  <!-- Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700">
          <i class="fas fa-cog" style="color:#22d3ee;margin-right:8px"></i>Platform Settings
        </h2>
        <div style="font-size:.76em;color:#8b949e;margin-top:2px">All settings persist to your tenant configuration · PATCH /api/settings</div>
      </div>
      <div style="display:flex;gap:8px">
        <button id="settings-save-btn-enh" onclick="settingsSaveEnhanced()" disabled
          class="enh-btn enh-btn--primary enh-btn--sm" style="opacity:.5">
          <i class="fas fa-save"></i> Save Changes
        </button>
        <button onclick="settingsReloadEnhanced()" class="enh-btn enh-btn--ghost enh-btn--sm">
          <i class="fas fa-sync-alt"></i> Reload
        </button>
      </div>
    </div>
  </div>

  <div style="padding:16px;max-width:900px">
    <!-- Status -->
    <div id="settings-status-enh" style="display:none;margin-bottom:14px"></div>

    <!-- Loading -->
    <div id="settings-body-enh">
      <div style="padding:40px;text-align:center;color:#8b949e">
        <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px;color:#22d3ee"></i>
        Loading settings…
      </div>
    </div>

    <!-- Save Bar -->
    <div class="settings-save-bar">
      <button onclick="settingsReloadEnhanced()" class="enh-btn enh-btn--ghost enh-btn--sm">
        <i class="fas fa-undo"></i> Discard Changes
      </button>
      <button id="settings-save-btn-enh-bottom" onclick="settingsSaveEnhanced()"
        class="enh-btn enh-btn--primary enh-btn--sm">
        <i class="fas fa-save"></i> Save All Changes
      </button>
    </div>
  </div>
  `;

  await settingsReloadEnhanced();
};

/* ── Reload ── */
window.settingsReloadEnhanced = async function() {
  const body = document.getElementById('settings-body-enh');
  if (!body) return;

  body.innerHTML = `<div style="padding:40px;text-align:center;color:#8b949e">
    <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px;color:#22d3ee"></i>
    Loading…
  </div>`;

  try {
    const res = await _settingsEnhFetch('/settings');
    _settingsEnhData  = res?.settings || res || {};
    _settingsEnhDirty = false;
    body.innerHTML = _buildEnhancedForm(_settingsEnhData);
  } catch(err) {
    body.innerHTML = `
      <div class="settings-status settings-status--error" style="display:flex;margin-bottom:14px">
        <i class="fas fa-exclamation-triangle"></i>
        <div>
          <div style="font-weight:700">Failed to load settings</div>
          <div style="font-size:.85em;margin-top:3px">${err.message}</div>
          <div style="font-size:.82em;color:#6b7280;margin-top:6px">
            Possible causes: auth token expired · insufficient permissions · backend offline
          </div>
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <button onclick="settingsReloadEnhanced()" class="enh-btn enh-btn--ghost enh-btn--sm">
          <i class="fas fa-retry"></i> Retry
        </button>
        <button onclick="_settingsLoadOfflineForm()" class="enh-btn enh-btn--cyan enh-btn--sm">
          <i class="fas fa-edit"></i> Edit Offline
        </button>
      </div>`;
  }
};

window._settingsLoadOfflineForm = function() {
  const body = document.getElementById('settings-body-enh');
  if (!body) return;
  _settingsShowStatus('info', '⚠️ Editing in offline mode — changes will be saved when connectivity is restored.');
  body.innerHTML = _buildEnhancedForm({});
};

/* ── Form builder ── */
function _buildEnhancedForm(s) {
  return `
    <!-- General Settings -->
    ${_settingsSection('fa-id-card','General Settings', 1, `
      ${_settingsField('Platform Name','platform_name','text', s.platform_name||'Wadjet-Eye AI','Your platform display name',{maxlength:100})}
      ${_settingsField('Default Theme','theme','select', s.theme||'dark','Platform color theme',{options:['dark','light']})}
      ${_settingsField('Timezone','timezone','select', s.timezone||'UTC','Default timezone for all users',{options:['UTC','US/Eastern','US/Pacific','Europe/London','Europe/Berlin','Asia/Tokyo','Australia/Sydney']})}
      ${_settingsField('Session Timeout (minutes)','session_timeout_minutes','number', s.session_timeout_minutes||480,'Auto-logout after inactivity',{min:5,max:10080})}
      ${_settingsField('Date Format','date_format','select', s.date_format||'YYYY-MM-DD','Display format for dates',{options:['YYYY-MM-DD','MM/DD/YYYY','DD/MM/YYYY','DD.MM.YYYY']})}
    `)}

    <!-- Threat Feed Settings -->
    ${_settingsSection('fa-satellite','Threat Feed Configuration', 2, `
      ${_settingsField('Ingest Schedule','ingest_schedule','select', s.ingest_schedule||'every_6h','How often to pull threat feeds',{options:['every_1h','every_6h','every_12h','every_24h','manual']})}
      ${_settingsToggleField('Enable CISA KEV','enable_cisa_kev', s.enable_cisa_kev!==false,'CISA Known Exploited Vulnerabilities feed')}
      ${_settingsToggleField('Enable MITRE ATT&CK Sync','enable_mitre_sync', s.enable_mitre_sync!==false,'Sync MITRE ATT&CK technique database')}
      ${_settingsToggleField('Enable OTX Pulses','enable_otx', s.enable_otx!==false,'AlienVault OTX threat pulses')}
      ${_settingsToggleField('Enable Abuse.ch Feeds','enable_abusech', s.enable_abusech!==false,'URLhaus, MalwareBazaar, ThreatFox')}
      ${_settingsField('IOC Deduplication Window (hours)','dedup_window_hours','number', s.dedup_window_hours||24,'Ignore duplicate IOCs seen within this window',{min:1,max:168})}
    `)}

    <!-- AI Configuration -->
    ${_settingsSection('fa-robot','AI Configuration', 3, `
      ${_settingsField('AI Provider','ai_provider','select', s.ai_provider||'openai','AI backend for investigation assistant',{options:['openai','anthropic','azure_openai','local']})}
      ${_settingsField('AI Model','ai_model','text', s.ai_model||'gpt-4o-mini','Model identifier (e.g., gpt-4o, claude-3)')}
      ${_settingsField('Max Tokens','ai_max_tokens','number', s.ai_max_tokens||2000,'Maximum tokens per AI response',{min:100,max:32000})}
      ${_settingsToggleField('Auto-Investigate Critical IOCs','ai_auto_investigate', s.ai_auto_investigate||false,'Automatically run AI analysis on critical-severity IOCs')}
      ${_settingsToggleField('AI-Powered Tagging','ai_auto_tag', s.ai_auto_tag!==false,'Use AI to auto-tag findings and campaigns')}
    `)}

    <!-- SOAR Automation -->
    ${_settingsSection('fa-bolt','SOAR Automation', 4, `
      ${_settingsField('Auto-Block Threshold (Risk Score)','soar_block_threshold','number', s.soar_block_threshold||85,'Risk score above which IOCs are auto-blocked',{min:0,max:100})}
      ${_settingsField('Alert Escalation Threshold','soar_escalation_threshold','number', s.soar_escalation_threshold||70,'Risk score for auto-escalation',{min:0,max:100})}
      ${_settingsToggleField('Auto-Execute Playbooks','soar_auto_execute', s.soar_auto_execute||false,'Automatically execute matching playbooks')}
      ${_settingsToggleField('Create Cases from Critical Findings','soar_auto_case', s.soar_auto_case!==false,'Auto-create DFIR case for critical findings')}
    `)}

    <!-- Notifications -->
    ${_settingsSection('fa-bell','Notifications', 5, `
      ${_settingsField('Alert Email','alert_email','email', s.alert_email||'','Email address for security alerts',{placeholder:'security@company.com'})}
      ${_settingsField('Slack Webhook URL','slack_webhook','url', s.slack_webhook||'','Slack incoming webhook for notifications',{placeholder:'https://hooks.slack.com/services/...'})}
      ${_settingsToggleField('Email on Critical Alerts','notify_email_critical', s.notify_email_critical!==false,'Send email when critical severity alert is triggered')}
      ${_settingsToggleField('Slack on New Campaign','notify_slack_campaign', s.notify_slack_campaign||false,'Post to Slack when new campaign is detected')}
      ${_settingsToggleField('Weekly Threat Summary','notify_weekly_summary', s.notify_weekly_summary!==false,'Send weekly threat intelligence digest')}
    `)}

    <!-- Integrations -->
    ${_settingsSection('fa-plug','Integrations', 6, `
      ${_settingsField('Jira URL','jira_url','url', s.jira_url||'','Jira instance URL for case integration',{placeholder:'https://company.atlassian.net'})}
      ${_settingsField('Jira Project Key','jira_project','text', s.jira_project||'','Jira project key (e.g., SEC)',{placeholder:'SEC'})}
      ${_settingsField('ServiceNow Instance','servicenow_instance','text', s.servicenow_instance||'','ServiceNow instance name',{placeholder:'company.service-now.com'})}
      ${_settingsField('Webhook URL','webhook_url','url', s.webhook_url||'','Outgoing webhook for SIEM/SOAR integration',{placeholder:'https://your-siem.com/webhook'})}
    `)}

    <!-- Data Retention -->
    ${_settingsSection('fa-database','Data Retention', 7, `
      ${_settingsField('IOC Retention (days)','ioc_retention_days','number', s.ioc_retention_days||365,'Days to retain IOC records',{min:30,max:3650})}
      ${_settingsField('Finding Retention (days)','finding_retention_days','number', s.finding_retention_days||730,'Days to retain security findings',{min:30,max:3650})}
      ${_settingsField('Audit Log Retention (days)','audit_retention_days','number', s.audit_retention_days||365,'Days to retain audit logs',{min:90,max:3650})}
      ${_settingsToggleField('Auto-Archive Resolved Cases','auto_archive_cases', s.auto_archive_cases||false,'Automatically archive resolved cases after retention period')}
    `)}
  `;
}

/* ── Section builder ── */
let _settingsOpenSections = new Set([1]);

function _settingsSection(icon, title, idx, content) {
  const isOpen = _settingsOpenSections.has(idx);
  return `
    <div class="settings-section enh-stagger-${Math.min(idx,6)}">
      <div class="settings-section__header" onclick="_settingsToggleSection(${idx})">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="width:30px;height:30px;background:rgba(34,211,238,.1);border-radius:7px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <i class="fas ${icon}" style="color:#22d3ee;font-size:.8em"></i>
          </div>
          <div style="font-size:.88em;font-weight:700;color:#e6edf3">${title}</div>
        </div>
        <i class="fas fa-chevron-down" id="settings-section-icon-${idx}"
          style="transition:transform .3s;color:#8b949e;${isOpen?'transform:rotate(180deg)':''}"></i>
      </div>
      <div class="settings-section__body" id="settings-section-body-${idx}"
        style="${isOpen?'':'display:none'}">
        ${content}
      </div>
    </div>
  `;
}

window._settingsToggleSection = function(idx) {
  const body = document.getElementById(`settings-section-body-${idx}`);
  const icon = document.getElementById(`settings-section-icon-${idx}`);
  if (!body) return;
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (icon) icon.style.transform = isOpen ? '' : 'rotate(180deg)';
  if (isOpen) _settingsOpenSections.delete(idx);
  else         _settingsOpenSections.add(idx);
};

/* ── Field builders ── */
function _settingsField(label, key, type, value, desc, attrs = {}) {
  const id = `setting-${key}`;
  let inputHTML;

  if (type === 'select') {
    const options = attrs.options || [];
    inputHTML = `<select id="${id}" data-setting="${key}" class="enh-select" style="width:100%"
        onchange="_settingsMarkDirty()">
        ${options.map(o => `<option value="${o}" ${value===o?'selected':''}>${o}</option>`).join('')}
      </select>`;
  } else {
    const extraAttrs = Object.entries(attrs)
      .filter(([k]) => !['options'].includes(k))
      .map(([k,v]) => `${k}="${v}"`).join(' ');
    inputHTML = `<input id="${id}" data-setting="${key}" type="${type}"
        value="${String(value||'').replace(/"/g,'&quot;')}"
        class="enh-input" style="width:100%;box-sizing:border-box"
        oninput="_settingsMarkDirty()" ${extraAttrs} />`;
  }

  return `
    <div class="settings-field">
      <div class="settings-field__label">
        ${label}
        <div class="settings-field__desc">${desc}</div>
      </div>
      <div>${inputHTML}</div>
    </div>`;
}

function _settingsToggleField(label, key, value, desc) {
  return `
    <div class="settings-field">
      <div class="settings-field__label">
        ${label}
        <div class="settings-field__desc">${desc}</div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;padding-top:6px">
        <input type="checkbox" class="settings-toggle" id="setting-${key}"
          data-setting="${key}" ${value?'checked':''}
          onchange="_settingsMarkDirty()" />
        <label for="setting-${key}" style="font-size:.82em;color:#8b949e;cursor:pointer">
          ${value ? 'Enabled' : 'Disabled'}
        </label>
      </div>
    </div>`;
}
