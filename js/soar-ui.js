/**
 * ══════════════════════════════════════════════════════════════════════════
 *  EYEbot AI — SOAR Automation UI v5.1 (PRODUCTION)
 *  FILE: js/soar-ui.js
 *
 *  Real SOAR engine frontend — connects to /api/soar/* endpoints.
 *
 *  Features:
 *  ─────────
 *  • View all playbooks with enable/disable toggles
 *  • Manually execute any playbook
 *  • View execution history with step-by-step timeline
 *  • Human approval workflow (approve/reject pending actions)
 *  • Live metrics: automation rate, MTTR, actions executed
 *  • Trigger playbook manually from IOC/alert context
 *  • No mock data — all from real /api/soar/* endpoints
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const SOAR_UI = {
  tab:        'executions',  // executions | playbooks | metrics
  execPage:   1,
  execs:      [],
  playbooks:  [],
  metrics:    {},
};

/* ─────────────────────────────────────────────
   API HELPERS — all go through auth interceptor
   Root cause fix: token was read from wrong keys.
   authFetch (from auth-interceptor.js) reads ALL
   token key variants + handles 401 silent refresh.
───────────────────────────────────────────── */

/**
 * Unified fetch for SOAR — uses authFetch (auth-interceptor.js) if available,
 * otherwise falls back to direct fetch with best-effort token retrieval.
 * This fixes the 401 errors that occurred because the token key used here
 * didn't match the key written by auth-persistent.js.
 */
async function _soarFetch(path, opts = {}) {
  // Use the centralized authFetch if loaded (auth-interceptor.js)
  if (typeof window.authFetch === 'function') {
    return window.authFetch(`/soar${path}`, opts);
  }

  // Fallback with unified token lookup
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

  const fetchOpts = {
    method:      opts.method || 'GET',
    headers,
    credentials: 'include',
    ...(opts.body ? { body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) } : {}),
  };

  const r = await fetch(`${base}/api/soar${path}`, fetchOpts);

  // On 401: try silent refresh, then retry
  if (r.status === 401 || r.status === 403) {
    if (typeof window.PersistentAuth_silentRefresh === 'function') {
      const refreshed = await window.PersistentAuth_silentRefresh();
      if (refreshed) {
        const newToken = localStorage.getItem('wadjet_access_token') || '';
        const retry = await fetch(`${base}/api/soar${path}`, {
          ...fetchOpts,
          headers: { ...headers, Authorization: `Bearer ${newToken}` },
        });
        if (retry.ok) return retry.json();
      }
    }
    window.dispatchEvent(new CustomEvent('auth:expired', { detail: { path } }));
    throw new Error(`AUTH_EXPIRED: Session expired. Please log in again.`);
  }

  if (r.status === 204) return null;
  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`HTTP ${r.status}: ${txt.slice(0, 120)}`);
  }
  return r.json();
}

async function _soarGet(path)         { return _soarFetch(path, { method: 'GET' }); }
async function _soarPost(path, body)  { return _soarFetch(path, { method: 'POST',  body }); }
async function _soarPut(path, body)   { return _soarFetch(path, { method: 'PUT',   body }); }

function _esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

/* ─────────────────────────────────────────────
   MAIN RENDER
───────────────────────────────────────────── */
async function renderSOARLive() {
  const wrap = document.getElementById('soarWrap')
    || document.getElementById('page-soar');
  if (!wrap) return;

  wrap.innerHTML = `
    <div id="soar-root" style="padding:20px;height:100%;display:flex;flex-direction:column;gap:16px;overflow:auto">
      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div>
          <h2 style="margin:0;font-size:1.3em;color:#e6edf3">
            <i class="fas fa-robot" style="color:#22d3ee;margin-right:8px"></i>SOAR Automation Engine
          </h2>
          <p style="margin:4px 0 0;color:#8b949e;font-size:.85em">
            Real playbook execution — block IPs, isolate endpoints, create cases, enrich IOCs
          </p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button onclick="soarRunAllRules()"
            style="padding:8px 16px;background:#ff444420;border:1px solid #ff4444;color:#ff4444;border-radius:6px;cursor:pointer;font-size:.85em;display:flex;align-items:center;gap:6px">
            <i class="fas fa-bolt"></i> Run All SOAR Rules
          </button>
          <button onclick="soarRefresh()"
            style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
            <i class="fas fa-sync-alt"></i> Refresh
          </button>
        </div>
      </div>

      <!-- Metrics Strip -->
      <div id="soar-metrics-strip" style="display:flex;gap:12px;flex-wrap:wrap"></div>

      <!-- Tabs -->
      <div style="display:flex;gap:0;border-bottom:1px solid #21262d">
        ${['executions','playbooks','metrics'].map(t =>
          `<button onclick="soarTab('${t}')" id="soar-tab-${t}"
            style="padding:10px 20px;background:none;border:none;border-bottom:2px solid ${t===SOAR_UI.tab?'#22d3ee':'transparent'};color:${t===SOAR_UI.tab?'#22d3ee':'#8b949e'};cursor:pointer;font-size:.85em;font-weight:600;text-transform:capitalize">
            ${t === 'executions' ? '📋 Execution History' : t === 'playbooks' ? '📚 Playbooks' : '📊 Metrics'}
          </button>`
        ).join('')}
      </div>

      <!-- Tab Content -->
      <div id="soar-tab-content" style="flex:1;overflow:auto">
        <div style="padding:40px;text-align:center;color:#8b949e">
          <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px"></i>Loading…
        </div>
      </div>
    </div>
  `;

  await soarLoadMetrics();
  await soarTab(SOAR_UI.tab);
}

/* ─────────────────────────────────────────────
   METRICS STRIP
───────────────────────────────────────────── */
async function soarLoadMetrics() {
  try {
    const m = await _soarGet('/metrics');
    SOAR_UI.metrics = m;
    const strip = document.getElementById('soar-metrics-strip');
    if (!strip) return;
    const kpis = [
      { label:'Executions',       val: m.total_executions  || 0,  color:'#22d3ee' },
      { label:'Actions Executed', val: m.actions_executed  || 0,  color:'#00cc44' },
      { label:'Pending Approval', val: m.pending_approval  || 0,  color:'#ffcc00' },
      { label:'Avg MTTR',         val: m.avg_mttr_min ? `${m.avg_mttr_min}m` : '—', color:'#a78bfa' },
      { label:'Automation Rate',  val: m.automation_rate ? `${m.automation_rate}%` : '—', color:'#1d6ae5' },
    ];
    strip.innerHTML = kpis.map(k => `
      <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
        <div style="font-size:1.5em;font-weight:700;color:${k.color}">${k.val}</div>
        <div style="font-size:.72em;color:#8b949e;margin-top:3px">${k.label}</div>
      </div>
    `).join('');
  } catch (_) {}
}

/* ─────────────────────────────────────────────
   TABS
───────────────────────────────────────────── */
async function soarTab(tab) {
  SOAR_UI.tab = tab;
  // Update tab buttons
  ['executions','playbooks','metrics'].forEach(t => {
    const btn = document.getElementById(`soar-tab-${t}`);
    if (btn) {
      btn.style.borderBottomColor = t === tab ? '#22d3ee' : 'transparent';
      btn.style.color             = t === tab ? '#22d3ee' : '#8b949e';
    }
  });

  const content = document.getElementById('soar-tab-content');
  if (!content) return;
  content.innerHTML = `<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px"></i>Loading…</div>`;

  try {
    if (tab === 'executions') await soarRenderExecutions(content);
    if (tab === 'playbooks')  await soarRenderPlaybooks(content);
    if (tab === 'metrics')    await soarRenderMetrics(content);
  } catch (err) {
    content.innerHTML = `<div style="padding:32px;text-align:center;color:#ef4444"><i class="fas fa-exclamation-triangle fa-2x" style="display:block;margin-bottom:10px"></i>${_esc(err.message)}</div>`;
  }
}

/* ─────────────────────────────────────────────
   EXECUTION HISTORY TAB
───────────────────────────────────────────── */
async function soarRenderExecutions(container) {
  const res = await _soarGet('/executions?limit=50');
  const execs = res.data || res.executions || [];
  SOAR_UI.execs = execs;

  if (execs.length === 0) {
    container.innerHTML = `<div style="padding:48px;text-align:center;color:#8b949e">
      <i class="fas fa-history fa-2x" style="display:block;margin-bottom:12px;opacity:.4"></i>
      No SOAR executions yet.<br>
      <small>Trigger playbooks manually or configure auto-execution rules.</small>
    </div>`;
    return;
  }

  const rows = execs.map(e => {
    const statusColor = {
      completed:'#00cc44', failed:'#ff4444', running:'#22d3ee',
      pending_approval:'#ffcc00', cancelled:'#8b949e'
    }[e.status] || '#8b949e';
    const isPending = e.status === 'pending_approval';

    return `
      <tr style="border-bottom:1px solid #21262d" onclick="soarShowExecution('${_esc(e.id)}')" style="cursor:pointer">
        <td style="padding:10px 12px">
          <div style="color:#e6edf3;font-size:.9em;font-weight:600">${_esc(e.playbook_name)}</div>
          <div style="color:#8b949e;font-size:.75em;margin-top:2px">${_esc(e.trigger_type)} · ${_esc(e.trigger_source || '—')}</div>
        </td>
        <td style="padding:10px 8px">
          <span style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}44;padding:2px 8px;border-radius:8px;font-size:.75em;font-weight:700;text-transform:uppercase">${e.status}</span>
        </td>
        <td style="padding:10px 8px;font-size:.82em;color:#8b949e">${e.actions_executed || 0} actions</td>
        <td style="padding:10px 8px;font-size:.82em;color:#8b949e">${e.duration_ms ? `${Math.round(e.duration_ms/1000)}s` : '—'}</td>
        <td style="padding:10px 8px;font-size:.82em;color:#8b949e">${_ago(e.started_at)}</td>
        <td style="padding:10px 8px" onclick="event.stopPropagation()">
          ${isPending ? `
            <button onclick="soarApprove('${_esc(e.id)}')"
              style="padding:4px 10px;background:#00cc4420;border:1px solid #00cc44;color:#00cc44;border-radius:5px;cursor:pointer;font-size:.75em">
              ✓ Approve
            </button>
          ` : ''}
        </td>
      </tr>
    `;
  });

  container.innerHTML = `
    <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden">
      <table style="width:100%;border-collapse:collapse;font-size:.9em">
        <thead>
          <tr style="border-bottom:2px solid #30363d;background:#0d1117">
            <th style="padding:10px 12px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase">Playbook</th>
            <th style="padding:10px 8px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase">Status</th>
            <th style="padding:10px 8px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase">Actions</th>
            <th style="padding:10px 8px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase">Duration</th>
            <th style="padding:10px 8px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase">Triggered</th>
            <th style="padding:10px 8px;text-align:left;color:#8b949e;font-size:.78em;text-transform:uppercase"></th>
          </tr>
        </thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   PLAYBOOKS TAB
───────────────────────────────────────────── */
async function soarRenderPlaybooks(container) {
  const res = await _soarGet('/playbooks');
  const playbooks = res.data || res.playbooks || [];
  SOAR_UI.playbooks = playbooks;

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:12px">
      <div style="display:flex;justify-content:flex-end">
        <button onclick="soarCreatePlaybook()"
          style="padding:8px 16px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em">
          <i class="fas fa-plus"></i> New Playbook
        </button>
      </div>
      ${playbooks.length === 0 ? `
        <div style="padding:48px;text-align:center;color:#8b949e;background:#161b22;border:1px solid #21262d;border-radius:8px">
          <i class="fas fa-book fa-2x" style="display:block;margin-bottom:12px;opacity:.4"></i>
          No playbooks configured yet.<br>
          <small>Create playbooks to automate your incident response workflows.</small>
        </div>
      ` : playbooks.map(pb => _renderPlaybookCard(pb)).join('')}
    </div>
  `;
}

function _renderPlaybookCard(pb) {
  const isActive  = pb.is_active !== false;
  const actions   = pb.actions || [];
  const triggers  = pb.trigger_conditions || [];

  return `
    <div style="background:#161b22;border:1px solid ${isActive?'#21262d':'#30363d55'};border-radius:10px;padding:18px;opacity:${isActive?1:.7}">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px">
        <div>
          <h4 style="margin:0;color:#e6edf3;font-size:1em;font-weight:600">${_esc(pb.name)}</h4>
          <p style="margin:4px 0 0;color:#8b949e;font-size:.8em">${_esc(pb.description || 'No description')}</p>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span style="background:${isActive?'#00cc4422':'#ff444422'};color:${isActive?'#00cc44':'#ff4444'};border:1px solid ${isActive?'#00cc4444':'#ff444444'};padding:2px 8px;border-radius:8px;font-size:.72em;font-weight:700">
            ${isActive ? 'ACTIVE' : 'DISABLED'}
          </span>
          <button onclick="soarTogglePlaybook('${_esc(pb.id)}', ${!isActive})"
            style="padding:5px 12px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.78em">
            ${isActive ? '⏸ Disable' : '▶ Enable'}
          </button>
          <button onclick="soarExecutePlaybook('${_esc(pb.id)}','${_esc(pb.name)}')"
            style="padding:5px 12px;background:#1d6ae520;border:1px solid #1d6ae5;color:#1d6ae5;border-radius:6px;cursor:pointer;font-size:.78em">
            ▶ Run Now
          </button>
        </div>
      </div>

      <!-- Actions list -->
      ${actions.length > 0 ? `
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
          <span style="font-size:.72em;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.05em;align-self:center">Actions:</span>
          ${actions.map(a => `<span style="background:#1d6ae520;color:#1d6ae5;border:1px solid #1d6ae544;padding:2px 8px;border-radius:6px;font-size:.75em">${_esc(a.type || a)}</span>`).join('')}
        </div>
      ` : ''}

      <!-- Stats -->
      <div style="display:flex;gap:16px;font-size:.78em;color:#8b949e">
        <span><i class="fas fa-play" style="margin-right:4px"></i>${pb.run_count || 0} runs</span>
        ${pb.last_run_at ? `<span><i class="fas fa-clock" style="margin-right:4px"></i>Last: ${_ago(pb.last_run_at)}</span>` : ''}
        ${pb.requires_approval ? `<span><i class="fas fa-user-check" style="color:#ffcc00;margin-right:4px"></i>Requires approval</span>` : ''}
        ${pb.auto_execute ? `<span><i class="fas fa-bolt" style="color:#00cc44;margin-right:4px"></i>Auto-execute</span>` : ''}
      </div>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   METRICS TAB
───────────────────────────────────────────── */
async function soarRenderMetrics(container) {
  const m = await _soarGet('/metrics');

  const breakdownHtml = (m.playbook_stats || []).map(p => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid #21262d">
      <span style="font-size:.85em;color:#e6edf3">${_esc(p.playbook_name)}</span>
      <div style="display:flex;gap:12px;font-size:.8em;color:#8b949e">
        <span>${p.total_runs || 0} runs</span>
        <span style="color:#00cc44">${p.success_rate || 0}% success</span>
        <span style="color:#22d3ee">${p.avg_duration_s || 0}s avg</span>
      </div>
    </div>
  `).join('');

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:16px">
      <!-- KPIs -->
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px">
        ${[
          { label:'Total Executions',   val: m.total_executions || 0,        color:'#22d3ee' },
          { label:'Completed',          val: m.completed || 0,                color:'#00cc44' },
          { label:'Failed',             val: m.failed || 0,                   color:'#ff4444' },
          { label:'Pending Approval',   val: m.pending_approval || 0,         color:'#ffcc00' },
          { label:'Actions Executed',   val: m.actions_executed || 0,         color:'#a78bfa' },
          { label:'Automation Rate',    val: m.automation_rate ? `${m.automation_rate}%` : '—', color:'#1d6ae5' },
          { label:'Avg MTTR',           val: m.avg_mttr_min ? `${m.avg_mttr_min}m` : '—', color:'#f59e0b' },
          { label:'IOCs Blocked',       val: m.iocs_blocked || 0,             color:'#ff4444' },
          { label:'Cases Created',      val: m.cases_created || 0,            color:'#22d3ee' },
          { label:'Alerts Created',     val: m.alerts_created || 0,           color:'#ff8800' },
        ].map(k => `
          <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center">
            <div style="font-size:1.6em;font-weight:700;color:${k.color}">${k.val.toLocaleString()}</div>
            <div style="font-size:.75em;color:#8b949e;margin-top:4px">${k.label}</div>
          </div>
        `).join('')}
      </div>

      <!-- Playbook Breakdown -->
      ${breakdownHtml ? `
        <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden">
          <div style="padding:14px 16px;border-bottom:1px solid #21262d;background:#0d1117">
            <h4 style="margin:0;font-size:.9em;color:#e6edf3">Playbook Performance</h4>
          </div>
          ${breakdownHtml}
        </div>
      ` : ''}
    </div>
  `;
}

/* ─────────────────────────────────────────────
   EXECUTION DETAIL MODAL
───────────────────────────────────────────── */
async function soarShowExecution(execId) {
  try {
    const exec = await _soarGet(`/executions/${execId}`);

    const steps = exec.steps || [];
    const stepsHtml = steps.map((step, i) => {
      const statusColor = step.status === 'completed' ? '#00cc44' : step.status === 'failed' ? '#ff4444' : step.status === 'running' ? '#22d3ee' : '#8b949e';
      return `
        <div style="display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #21262d">
          <div style="width:28px;height:28px;border-radius:50%;background:${statusColor}22;border:2px solid ${statusColor};display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.75em;font-weight:700;color:${statusColor}">${i+1}</div>
          <div style="flex:1">
            <div style="font-size:.85em;font-weight:600;color:#e6edf3">${_esc(step.name || step.action_type || 'Step')}</div>
            <div style="font-size:.78em;color:#8b949e;margin-top:3px">${_esc(step.message || step.result?.message || JSON.stringify(step.result || {}).slice(0,120))}</div>
            ${step.duration_ms ? `<div style="font-size:.72em;color:#8b949e;margin-top:2px">${step.duration_ms}ms</div>` : ''}
          </div>
          <span style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}44;padding:2px 8px;border-radius:6px;font-size:.72em;font-weight:700;align-self:flex-start;text-transform:uppercase">${step.status}</span>
        </div>
      `;
    }).join('');

    const modalHtml = `
      <div id="soar-exec-modal" onclick="if(event.target===this)document.getElementById('soar-exec-modal').remove()"
        style="position:fixed;inset:0;background:#000000cc;display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px">
        <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;max-width:700px;width:100%;max-height:90vh;overflow:auto;padding:28px;position:relative">
          <button onclick="document.getElementById('soar-exec-modal').remove()"
            style="position:absolute;top:16px;right:16px;background:none;border:none;color:#8b949e;font-size:1.4em;cursor:pointer">✕</button>

          <h3 style="margin:0 0 16px;color:#e6edf3;font-size:1.1em;display:flex;align-items:center;gap:10px">
            <i class="fas fa-list-alt" style="color:#22d3ee"></i>
            Execution: ${_esc(exec.playbook_name)}
          </h3>

          <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;margin-bottom:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;font-size:.85em">
            <div><div style="color:#8b949e;font-size:.75em;margin-bottom:3px">STATUS</div><span style="color:${exec.status==='completed'?'#00cc44':exec.status==='failed'?'#ff4444':'#22d3ee'};font-weight:700">${exec.status}</span></div>
            <div><div style="color:#8b949e;font-size:.75em;margin-bottom:3px">TRIGGER</div>${_esc(exec.trigger_type)}</div>
            <div><div style="color:#8b949e;font-size:.75em;margin-bottom:3px">STARTED</div>${_ago(exec.started_at)}</div>
            <div><div style="color:#8b949e;font-size:.75em;margin-bottom:3px">DURATION</div>${exec.duration_ms ? `${Math.round(exec.duration_ms/1000)}s` : '—'}</div>
            <div><div style="color:#8b949e;font-size:.75em;margin-bottom:3px">ACTIONS</div>${exec.actions_executed || 0} executed, ${exec.actions_failed || 0} failed</div>
          </div>

          <!-- Steps -->
          <h4 style="margin:0 0 12px;font-size:.9em;color:#e6edf3">Action Timeline</h4>
          <div style="max-height:350px;overflow:auto">
            ${stepsHtml || '<div style="color:#8b949e;font-size:.85em;padding:12px 0">No step details available</div>'}
          </div>

          <!-- Approval button if pending -->
          ${exec.status === 'pending_approval' ? `
            <div style="margin-top:16px;display:flex;gap:10px;justify-content:flex-end">
              <button onclick="soarApprove('${_esc(exec.id)}');document.getElementById('soar-exec-modal').remove()"
                style="padding:8px 20px;background:#00cc4420;border:1px solid #00cc44;color:#00cc44;border-radius:6px;cursor:pointer;font-size:.85em">
                ✓ Approve Execution
              </button>
              <button onclick="document.getElementById('soar-exec-modal').remove()"
                style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
                Close
              </button>
            </div>
          ` : `
            <div style="margin-top:16px;display:flex;justify-content:flex-end">
              <button onclick="document.getElementById('soar-exec-modal').remove()"
                style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
                Close
              </button>
            </div>
          `}
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Failed to load execution: ${err.message}`, 'error');
  }
}

/* ─────────────────────────────────────────────
   ACTIONS
───────────────────────────────────────────── */
async function soarExecutePlaybook(playbookId, name) {
  if (!confirm(`Execute playbook: "${name}"?\n\nThis will trigger all automated actions defined in the playbook.`)) return;

  try {
    const result = await _soarPost(`/execute/${playbookId}`);
    if (typeof showToast === 'function')
      showToast(`▶ Playbook "${name}" started — Execution ID: ${result.execution_id?.slice(0,8)}…`, 'success', 5000);
    setTimeout(() => soarTab('executions'), 1000);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Execution failed: ${err.message}`, 'error');
  }
}

async function soarTogglePlaybook(playbookId, newState) {
  try {
    await _soarPut(`/playbooks/${playbookId}`, { is_active: newState });
    if (typeof showToast === 'function') showToast(`✅ Playbook ${newState ? 'enabled' : 'disabled'}`, 'success');
    await soarTab('playbooks');
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Failed: ${err.message}`, 'error');
  }
}

async function soarApprove(execId) {
  try {
    await _soarPost(`/approve/${execId}`);
    if (typeof showToast === 'function') showToast('✅ Execution approved and resumed', 'success');
    await soarTab('executions');
    await soarLoadMetrics();
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Approval failed: ${err.message}`, 'error');
  }
}

async function soarRunAllRules() {
  if (!confirm('Run all SOAR automation rules now?\n\nThis will enrich IOCs, flag high-risk indicators, and create cases for critical alerts.')) return;

  try {
    const result = await _soarPost('/trigger', { event_type: 'manual_run_all' });
    if (typeof showToast === 'function')
      showToast(`⚡ SOAR rules executed: ${result.actions_executed || 0} actions taken`, 'success', 5000);
    setTimeout(() => soarRefresh(), 2000);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ SOAR run failed: ${err.message}`, 'error');
  }
}

async function soarCreatePlaybook() {
  // Simple inline form
  const name = prompt('Playbook name:');
  if (!name) return;
  const desc = prompt('Description (optional):') || '';

  try {
    const pb = await _soarPost('/playbooks', {
      name,
      description: desc,
      trigger_conditions: [],
      actions: [],
      is_active: false,
      auto_execute: false,
      requires_approval: true,
    });
    if (typeof showToast === 'function') showToast(`✅ Playbook "${name}" created`, 'success');
    await soarTab('playbooks');
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Create failed: ${err.message}`, 'error');
  }
}

async function soarRefresh() {
  await soarLoadMetrics();
  await soarTab(SOAR_UI.tab);
}

// Export to global scope
window.renderSOARLive        = renderSOARLive;
window.soarTab               = soarTab;
window.soarRefresh           = soarRefresh;
window.soarExecutePlaybook   = soarExecutePlaybook;
window.soarTogglePlaybook    = soarTogglePlaybook;
window.soarApprove           = soarApprove;
window.soarRunAllRules       = soarRunAllRules;
window.soarCreatePlaybook    = soarCreatePlaybook;
window.soarShowExecution     = soarShowExecution;
