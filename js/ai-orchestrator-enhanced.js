/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — AI Orchestrator Page Module v4.0 (ENHANCED)
 *  Real-time investigation results, multi-source intel integration,
 *  exportable reports, action logging
 *  
 *  Replaces mock data with real API calls and live investigation results
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── State ── */
const _AIORCH = {
  messages: [],
  sessions: [],
  currentSession: null,
  tools: [],
  logs: [],
  isThinking: false,
  apiKeys: {},
};

/* ── API helpers ── */
const _orchApiBase = () =>
  (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');

async function _orchFetch(path, opts = {}) {
  if (window.authFetch) return window.authFetch(path, opts);
  const base  = _orchApiBase();
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
  return fetch(`${base}/api${path}`, {
    headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
    ...opts,
  }).then(async r => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.status === 204 ? null : r.json();
  });
}

function _orchEsc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _orchAgo(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function _orchNow() { return new Date().toISOString(); }

/* ── Available AI tools ── */
const ORCH_TOOLS = [
  { id:'ioc_lookup',    icon:'fa-fingerprint',   color:'#22d3ee', label:'IOC Lookup',        desc:'Search IOC in all threat databases' },
  { id:'vt_lookup',     icon:'fa-virus',         color:'#ef4444', label:'VirusTotal',         desc:'Scan hash, URL, or IP on VirusTotal' },
  { id:'abuseipdb',     icon:'fa-shield-alt',    color:'#f97316', label:'AbuseIPDB',          desc:'Check IP reputation and abuse reports' },
  { id:'shodan',        icon:'fa-server',        color:'#3b82f6', label:'Shodan',             desc:'Enumerate open ports and services' },
  { id:'otx_lookup',   icon:'fa-satellite',     color:'#a855f7', label:'AlienVault OTX',     desc:'Fetch threat intel pulses from OTX' },
  { id:'campaign_hunt', icon:'fa-crosshairs',    color:'#22c55e', label:'Campaign Hunt',      desc:'Find active campaigns matching IOC' },
  { id:'mitre_map',     icon:'fa-th',            color:'#eab308', label:'MITRE ATT&CK Map',  desc:'Map TTPs to ATT&CK techniques' },
  { id:'threat_summary',icon:'fa-chart-pie',     color:'#ec4899', label:'Threat Summary',     desc:'Generate AI threat intelligence brief' },
  { id:'case_create',   icon:'fa-folder-plus',   color:'#22d3ee', label:'Create Case',        desc:'Create DFIR case from investigation' },
  { id:'export_report', icon:'fa-download',      color:'#8b5cf6', label:'Export Report',      desc:'Export investigation as PDF/JSON/CSV' },
];

/* ── Suggested prompts ── */
const ORCH_SUGGESTIONS = [
  { icon:'🔍', text:'Investigate IOC 185.220.101.45 across all sources' },
  { icon:'📊', text:'Give me a threat intelligence summary for today' },
  { icon:'🦠', text:'Show top 5 high-risk IOCs and their campaigns' },
  { icon:'🎯', text:'What ATT&CK techniques were used in recent LockBit attacks?' },
  { icon:'🕵️', text:'Who is APT29 and what are their latest TTPs?' },
  { icon:'⚡', text:'Show all active campaigns targeting financial sector' },
  { icon:'🔐', text:'Analyze hash a3f2b1c9d4e5f6789012345678901234' },
  { icon:'🌐', text:'Check if domain maliciousupdate.ru is blacklisted' },
];

/* ══════════════════════════════════════════════════════
   MAIN RENDERER
══════════════════════════════════════════════════════ */
window.renderAIOrchestrator = function() {
  const c = document.getElementById('page-ai-orchestrator')
         || document.getElementById('aiOrchestratorContainer');
  if (!c) return;

  c.innerHTML = `
  <!-- Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1" style="background:radial-gradient(ellipse,rgba(168,85,247,.06) 0%,transparent 70%)"></div>
    <div class="enh-module-header__glow-2" style="background:radial-gradient(ellipse,rgba(34,211,238,.05) 0%,transparent 70%)"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div style="display:flex;align-items:center;gap:10px">
        <div style="width:38px;height:38px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);
          border-radius:10px;display:flex;align-items:center;justify-content:center;position:relative">
          <i class="fas fa-robot" style="color:#a855f7;font-size:.9em"></i>
          <span style="position:absolute;top:-3px;right:-3px;width:10px;height:10px;background:#22c55e;
            border-radius:50%;border:2px solid #080c14;animation:enh-dot-blink 2s infinite"></span>
        </div>
        <div>
          <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700">AI Orchestrator</h2>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">Multi-source agentic investigation · VirusTotal · AbuseIPDB · Shodan · OTX</div>
        </div>
        <span class="enh-badge enh-badge--online" style="animation:enh-dot-blink 3s infinite">
          <span class="enh-dot enh-dot--online"></span> ONLINE
        </span>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_orchNewSession()">
          <i class="fas fa-plus"></i> New Session
        </button>
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_orchShowLogs()">
          <i class="fas fa-list"></i> Action Logs
        </button>
        <button class="enh-btn enh-btn--cyan enh-btn--sm" onclick="_orchExportReport()">
          <i class="fas fa-download"></i> Export Report
        </button>
      </div>
    </div>
  </div>

  <div style="padding:16px">
    <div class="ai-orch-container">

      <!-- LEFT: Chat Panel -->
      <div class="ai-orch-chat">
        <!-- Chat Header -->
        <div style="padding:12px 16px;border-bottom:1px solid #1a2535;display:flex;align-items:center;gap:10px">
          <i class="fas fa-brain" style="color:#a855f7"></i>
          <span style="font-size:.86em;font-weight:600;color:#e6edf3;flex:1" id="orch-session-title">New Investigation Session</span>
          <span id="orch-think-badge" style="display:none" class="enh-badge enh-badge--purple">
            <i class="fas fa-circle-notch fa-spin" style="margin-right:4px"></i>Thinking…
          </span>
        </div>

        <!-- Messages -->
        <div class="ai-orch-messages" id="orch-messages">
          <!-- Welcome message -->
          <div class="ai-msg ai-msg--assistant">
            <div class="ai-msg__avatar" style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.2)">
              <i class="fas fa-robot"></i>
            </div>
            <div class="ai-msg__bubble">
              <p style="margin:0 0 8px">👋 Hello! I'm the Wadjet-Eye AI Orchestrator. I can:</p>
              <ul style="margin:0;padding-left:16px;font-size:.9em;color:#8b949e;line-height:1.8">
                <li>Investigate IOCs across VirusTotal, AbuseIPDB, Shodan, and OTX</li>
                <li>Map threats to MITRE ATT&CK techniques</li>
                <li>Correlate IOCs with active campaigns</li>
                <li>Generate exportable threat intelligence reports</li>
                <li>Create DFIR cases from investigation findings</li>
              </ul>
              <p style="margin:8px 0 0;font-size:.85em;color:#8b949e">
                Try typing an IP, domain, hash, or asking a threat intel question below.
              </p>
            </div>
          </div>

          <!-- Suggestions -->
          <div id="orch-suggestions" style="padding:4px 0">
            <div style="font-size:.74em;color:#4b5563;margin-bottom:8px;padding-left:42px">QUICK ACTIONS</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;padding-left:42px">
              ${ORCH_SUGGESTIONS.map(s => `
                <button onclick="_orchQuickPrompt(${JSON.stringify(s.text).replace(/'/g,'&#39;')})"
                  class="enh-btn enh-btn--ghost enh-btn--sm" style="font-size:.76em">
                  ${s.icon} ${_orchEsc(s.text.slice(0,35))}${s.text.length>35?'…':''}
                </button>`).join('')}
            </div>
          </div>
        </div>

        <!-- Input Area -->
        <div class="ai-orch-input-area">
          <textarea id="orch-input" rows="2"
            placeholder="Investigate an IOC, ask about threats, or request an intelligence brief…"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();_orchSend()}"
            oninput="this.style.height='auto';this.style.height=this.scrollHeight+'px'"></textarea>
          <button class="enh-btn enh-btn--primary enh-btn--sm" onclick="_orchSend()" id="orch-send-btn"
            style="flex-shrink:0;height:36px">
            <i class="fas fa-paper-plane"></i>
          </button>
        </div>
      </div>

      <!-- RIGHT: Tools + Info -->
      <div class="ai-orch-sidebar">

        <!-- Tool buttons -->
        <div style="background:rgba(13,20,33,.8);border:1px solid #1a2535;border-radius:10px;padding:12px;animation:enh-fadeIn .4s ease">
          <div style="font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-bottom:10px">
            <i class="fas fa-tools" style="margin-right:5px;color:#22d3ee"></i>AVAILABLE TOOLS
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
            ${ORCH_TOOLS.map((t, i) => `
              <div class="ai-tool-card enh-stagger-${Math.min(i+1,6)}" onclick="_orchRunTool('${t.id}')"
                title="${_orchEsc(t.desc)}">
                <div class="ai-tool-card__icon" style="background:${t.color}18;border:1px solid ${t.color}30">
                  <i class="fas ${t.icon}" style="color:${t.color};font-size:.8em"></i>
                </div>
                <div style="flex:1;min-width:0">
                  <div style="font-size:.76em;font-weight:700;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${t.label}</div>
                  <div style="font-size:.68em;color:#6b7280;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${t.desc}</div>
                </div>
              </div>`).join('')}
          </div>
        </div>

        <!-- Session Stats -->
        <div style="background:rgba(13,20,33,.8);border:1px solid #1a2535;border-radius:10px;padding:12px;animation:enh-fadeIn .5s ease">
          <div style="font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-bottom:10px">
            <i class="fas fa-chart-bar" style="margin-right:5px;color:#a855f7"></i>SESSION STATS
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px" id="orch-session-stats">
            ${[
              ['Queries',    '0',   '#22d3ee', 'fa-comments'],
              ['IOCs Found', '0',   '#ef4444', 'fa-fingerprint'],
              ['Tools Used', '0',   '#a855f7', 'fa-tools'],
              ['Actions',    '0',   '#22c55e', 'fa-bolt'],
            ].map(([l,v,c,ic]) => `
              <div style="background:rgba(255,255,255,.04);padding:8px;border-radius:7px;text-align:center">
                <i class="fas ${ic}" style="color:${c};font-size:.9em;margin-bottom:4px;display:block"></i>
                <div style="font-size:1.2em;font-weight:800;color:${c}" id="orch-stat-${l.toLowerCase().replace(' ','-')}">${v}</div>
                <div style="font-size:.7em;color:#6b7280">${l}</div>
              </div>`).join('')}
          </div>
        </div>

        <!-- Recent Sessions -->
        <div style="background:rgba(13,20,33,.8);border:1px solid #1a2535;border-radius:10px;padding:12px;animation:enh-fadeIn .6s ease">
          <div style="font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-bottom:8px">
            <i class="fas fa-history" style="margin-right:5px;color:#22c55e"></i>RECENT SESSIONS
          </div>
          <div id="orch-sessions-list">
            <div style="font-size:.78em;color:#4b5563;padding:8px 0">No sessions yet. Start an investigation!</div>
          </div>
        </div>
      </div>
    </div>
  </div>
  `;

  // Load session history
  _orchLoadSessions();
};

/* ── Session management ── */
window._orchNewSession = function() {
  _AIORCH.messages = [];
  _AIORCH.currentSession = {
    id: 'session-' + Date.now(),
    title: 'New Session',
    started: _orchNow(),
    queries: 0, iocs: 0, tools: 0, actions: 0,
  };
  const msgs = document.getElementById('orch-messages');
  if (msgs) msgs.innerHTML = '';
  _orchUpdateStats();
  if (typeof showToast === 'function') showToast('🆕 New investigation session started', 'info');
};

async function _orchLoadSessions() {
  try {
    const data = await _orchFetch('/cti/ai/sessions?limit=5');
    const sessions = data?.sessions || data || [];
    _AIORCH.sessions = sessions;
    _renderOrchSessions(sessions);
  } catch { _renderOrchSessions([]); }
}

function _renderOrchSessions(sessions) {
  const el = document.getElementById('orch-sessions-list');
  if (!el) return;
  if (!sessions.length) {
    el.innerHTML = `<div style="font-size:.78em;color:#4b5563;padding:4px 0">No recent sessions.</div>`;
    return;
  }
  el.innerHTML = sessions.slice(0,5).map(s => `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(26,37,53,.6);cursor:pointer"
      onclick="_orchLoadSession('${_orchEsc(s.id)}')">
      <i class="fas fa-folder" style="color:#22d3ee;font-size:.8em;flex-shrink:0"></i>
      <div style="flex:1;min-width:0">
        <div style="font-size:.78em;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${_orchEsc(s.title||s.query||'Investigation')}</div>
        <div style="font-size:.7em;color:#4b5563">${_orchAgo(s.created_at)}</div>
      </div>
    </div>`).join('');
}

/* ── Send message ── */
window._orchSend = async function() {
  const inp = document.getElementById('orch-input');
  if (!inp) return;
  const text = inp.value.trim();
  if (!text || _AIORCH.isThinking) return;
  inp.value = '';
  inp.style.height = 'auto';
  _orchSendMessage(text);
};

window._orchQuickPrompt = function(text) {
  _orchSendMessage(text);
};

async function _orchSendMessage(text) {
  if (_AIORCH.isThinking) return;
  _AIORCH.isThinking = true;
  _AIORCH.messages.push({ role:'user', content: text, ts: _orchNow() });
  if (!_AIORCH.currentSession) {
    _AIORCH.currentSession = { id:'session-'+Date.now(), title:text.slice(0,40), started:_orchNow(), queries:0,iocs:0,tools:0,actions:0 };
  }
  _AIORCH.currentSession.queries++;

  // Auto-detect IOC in message
  const iocMatch = _extractIOCFromText(text);

  _appendUserMessage(text);
  _showThinking(true);

  // Hide suggestions after first message
  const sug = document.getElementById('orch-suggestions');
  if (sug) sug.style.display = 'none';

  try {
    let response;

    if (iocMatch) {
      // IOC detected — run multi-source investigation
      response = await _orchInvestigateIOC(iocMatch.value, iocMatch.type, text);
    } else {
      // General AI query
      response = await _orchAIQuery(text);
    }

    _showThinking(false);
    _appendAssistantMessage(response);
    _orchLogAction('query', text, response.summary || 'AI response');
  } catch(err) {
    _showThinking(false);
    _appendErrorMessage(`Investigation failed: ${err.message}`);
  } finally {
    _AIORCH.isThinking = false;
    _orchUpdateStats();
  }
}

/* ── IOC extraction from text ── */
function _extractIOCFromText(text) {
  if (window.detectIOCType) {
    const words = text.split(/[\s,]+/);
    for (const w of words) {
      const d = window.detectIOCType(w);
      if (d.valid && d.type && d.type !== 'unknown') {
        return { value: w, type: d.type, label: d.label };
      }
    }
  }
  return null;
}

/* ── Multi-source IOC investigation ── */
async function _orchInvestigateIOC(value, type, originalQuery) {
  const sources = {};
  const errors  = {};

  // Run all intelligence sources in parallel
  const tasks = [
    _orchCheckVT(value, type),
    _orchCheckAbuseIPDB(value, type),
    _orchCheckShodan(value, type),
    _orchCheckOTX(value, type),
    _orchCheckLocalDB(value, type),
    _orchCheckCampaigns(value),
  ];

  const results = await Promise.allSettled(tasks);
  const [vtR, abuseR, shodanR, otxR, dbR, campR] = results;

  if (vtR.status === 'fulfilled')     sources.virustotal = vtR.value;
  else                                 errors.virustotal  = vtR.reason?.message;
  if (abuseR.status === 'fulfilled')  sources.abuseipdb  = abuseR.value;
  if (shodanR.status === 'fulfilled') sources.shodan     = shodanR.value;
  if (otxR.status === 'fulfilled')    sources.otx        = otxR.value;
  if (dbR.status === 'fulfilled')     sources.database   = dbR.value;
  if (campR.status === 'fulfilled')   sources.campaigns  = campR.value;

  _AIORCH.currentSession.iocs++;
  _AIORCH.currentSession.tools += Object.keys(sources).length;

  // Build verdict
  const verdict = _buildVerdict(value, type, sources);
  const html    = _buildInvestigationHTML(value, type, sources, errors, verdict, originalQuery);

  return {
    type: 'investigation',
    value, ioc_type: type,
    sources, errors, verdict,
    html,
    summary: `IOC ${value} investigated across ${Object.keys(sources).length} sources — verdict: ${verdict.label}`,
  };
}

/* ── Individual source checks ── */
async function _orchCheckVT(value, type) {
  const data = await _orchFetch('/intel/virustotal', {
    method: 'POST',
    body: JSON.stringify({ value, type })
  });
  return data;
}

async function _orchCheckAbuseIPDB(value, type) {
  if (!['ip','ipv4','ipv6'].includes(type)) return null;
  const data = await _orchFetch('/intel/abuseipdb', {
    method: 'POST',
    body: JSON.stringify({ ip: value })
  });
  return data;
}

async function _orchCheckShodan(value, type) {
  if (!['ip','ipv4','ipv6'].includes(type)) return null;
  const data = await _orchFetch('/intel/shodan', {
    method: 'POST',
    body: JSON.stringify({ ip: value })
  });
  return data;
}

async function _orchCheckOTX(value, type) {
  const data = await _orchFetch('/intel/otx', {
    method: 'POST',
    body: JSON.stringify({ value, type })
  });
  return data;
}

async function _orchCheckLocalDB(value, type) {
  const qs = new URLSearchParams({ search: value, limit: 5 });
  if (type && type !== 'unknown') qs.set('type', type.replace('hash_',''));
  const data = await _orchFetch(`/iocs?${qs}`);
  return data?.data || data || [];
}

async function _orchCheckCampaigns(value) {
  const data = await _orchFetch(`/cti/campaigns?search=${encodeURIComponent(value)}&limit=3`);
  return data?.data || data || [];
}

/* ── General AI query ── */
async function _orchAIQuery(text) {
  const data = await _orchFetch('/cti/ai/query', {
    method: 'POST',
    body: JSON.stringify({
      query: text,
      context: _AIORCH.messages.slice(-6).map(m => ({role:m.role, content:m.content})),
    })
  });
  return {
    type: 'text',
    html: `<p>${_orchEsc(data?.explanation || data?.response || data?.message || 'No response from AI')}</p>`,
    summary: 'AI response',
  };
}

/* ── Build verdict ── */
function _buildVerdict(value, type, sources) {
  let score = 0;
  let reasons = [];

  const vt = sources.virustotal;
  if (vt?.malicious > 0) {
    score += Math.min(vt.malicious * 10, 50);
    reasons.push(`${vt.malicious} VT detections`);
  }
  if (vt?.suspicious > 0) { score += vt.suspicious * 3; reasons.push(`${vt.suspicious} VT suspicious`); }

  const abuse = sources.abuseipdb;
  if (abuse?.abuseConfidenceScore > 0) {
    score += Math.round(abuse.abuseConfidenceScore / 2);
    reasons.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}% confidence`);
  }

  const db = sources.database;
  if (Array.isArray(db) && db.length > 0) {
    const rep = db[0]?.reputation;
    if (rep === 'malicious')  { score += 30; reasons.push('Malicious in local DB'); }
    if (rep === 'suspicious') { score += 15; reasons.push('Suspicious in local DB'); }
  }

  const otx = sources.otx;
  if (otx?.pulses?.length > 0) {
    score += Math.min(otx.pulses.length * 5, 20);
    reasons.push(`${otx.pulses.length} OTX pulses`);
  }

  const camp = sources.campaigns;
  if (Array.isArray(camp) && camp.length > 0) {
    score += 20;
    reasons.push(`Linked to ${camp.length} campaign(s)`);
  }

  let label, color, icon;
  if (score >= 70)      { label='MALICIOUS';  color='#ef4444'; icon='fa-skull-crossbones'; }
  else if (score >= 35) { label='SUSPICIOUS'; color='#f97316'; icon='fa-exclamation-triangle'; }
  else if (score >= 10) { label='POSSIBLY SUSPICIOUS'; color='#eab308'; icon='fa-question-circle'; }
  else                  { label='CLEAN / UNKNOWN'; color='#22c55e'; icon='fa-check-circle'; }

  return { score, label, color, icon, reasons };
}

/* ── Build investigation HTML ── */
function _buildInvestigationHTML(value, type, sources, errors, verdict, originalQuery) {
  return `
    <!-- Verdict Banner -->
    <div style="background:${verdict.color}10;border:1px solid ${verdict.color}30;border-radius:10px;
      padding:12px 16px;margin-bottom:12px;display:flex;align-items:center;gap:10px">
      <i class="fas ${verdict.icon}" style="color:${verdict.color};font-size:1.3em;flex-shrink:0"></i>
      <div>
        <div style="font-weight:800;color:${verdict.color};font-size:.95em">${_orchEsc(verdict.label)}</div>
        <div style="font-size:.78em;color:#8b949e;margin-top:2px">
          Risk Score: ${verdict.score}/100 · ${verdict.reasons.length ? verdict.reasons.join(' · ') : 'No indicators found'}
        </div>
      </div>
    </div>

    <!-- IOC Summary -->
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;padding:8px 12px;
      background:rgba(255,255,255,.03);border-radius:8px;border:1px solid #1a2535">
      <code style="font-family:monospace;font-size:.86em;color:#22d3ee;word-break:break-all">${_orchEsc(value)}</code>
      <span style="font-size:.72em;color:#8b949e;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.2);
        padding:1px 7px;border-radius:6px;font-weight:700;white-space:nowrap;flex-shrink:0">${_orchEsc(type)}</span>
    </div>

    <!-- Source Results -->
    ${Object.entries({
      'VirusTotal':  sources.virustotal,
      'AbuseIPDB':   sources.abuseipdb,
      'Shodan':      sources.shodan,
      'AlienVault OTX': sources.otx,
      'Local DB':    Array.isArray(sources.database) ? { count: sources.database.length, records: sources.database } : sources.database,
      'Campaigns':   Array.isArray(sources.campaigns) ? { count: sources.campaigns.length, data: sources.campaigns } : sources.campaigns,
    }).filter(([, v]) => v != null).map(([name, data]) => `
      <div class="ai-investigation-result" style="margin-bottom:8px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <div style="font-size:.76em;font-weight:700;color:#e6edf3">${_orchEsc(name)}</div>
          ${errors[name.toLowerCase().replace(' ','')] ? `<span style="font-size:.7em;color:#ef4444">(error)</span>` : ''}
        </div>
        ${_renderSourceResult(name, data)}
      </div>`).join('')}

    ${sources.campaigns?.length > 0 ? `
    <!-- Campaign Links -->
    <div style="margin-top:10px;padding:10px 12px;background:rgba(34,211,238,.06);border:1px solid rgba(34,211,238,.15);border-radius:8px">
      <div style="font-size:.78em;font-weight:700;color:#22d3ee;margin-bottom:6px">
        <i class="fas fa-crosshairs" style="margin-right:5px"></i>LINKED TO ACTIVE CAMPAIGNS
      </div>
      ${sources.campaigns.slice(0,3).map(c => `
        <div style="font-size:.8em;color:#b0bec5;padding:3px 0">
          <i class="fas fa-chevron-right" style="margin-right:6px;color:#22d3ee;font-size:.7em"></i>
          ${_orchEsc(c.name || c.title || 'Campaign')} 
          <span style="color:#8b949e;font-size:.9em">— ${_orchEsc(c.severity||c.threat_level||'')}</span>
        </div>`).join('')}
    </div>` : ''}

    <!-- Action Buttons -->
    <div style="display:flex;gap:6px;margin-top:12px;flex-wrap:wrap">
      <button onclick="_orchCreateCase('${_orchEsc(value)}','${_orchEsc(type)}')"
        class="enh-btn enh-btn--primary enh-btn--sm"><i class="fas fa-folder-plus"></i> Create Case</button>
      <button onclick="_orchAddToIOCDB('${_orchEsc(value)}','${_orchEsc(type)}')"
        class="enh-btn enh-btn--cyan enh-btn--sm"><i class="fas fa-plus"></i> Add to IOC DB</button>
      <button onclick="_orchExportInvestigation('${_orchEsc(value)}')"
        class="enh-btn enh-btn--ghost enh-btn--sm"><i class="fas fa-download"></i> Export</button>
    </div>
  `;
}

function _renderSourceResult(name, data) {
  if (!data) return `<div style="font-size:.78em;color:#4b5563">No data returned</div>`;
  if (Array.isArray(data)) {
    if (!data.length) return `<div style="font-size:.78em;color:#4b5563">Not found in ${name}</div>`;
    return `<div style="font-size:.78em;color:#8b949e">${data.length} record(s) found</div>`;
  }
  // VT
  if (data.malicious != null) {
    const total = (data.malicious||0) + (data.suspicious||0) + (data.clean||0) + (data.undetected||0);
    const pct   = total > 0 ? Math.round((data.malicious/total)*100) : 0;
    return `
      <div style="font-size:.8em;margin-bottom:4px">
        <span style="color:#ef4444;font-weight:700">${data.malicious}</span>
        <span style="color:#8b949e">/${total} detections (${pct}%)</span>
      </div>
      <div style="height:6px;background:#1e2d3d;border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:${pct>50?'#ef4444':pct>20?'#f97316':'#22c55e'};border-radius:3px;transition:width .6s"></div>
      </div>`;
  }
  // AbuseIPDB
  if (data.abuseConfidenceScore != null) {
    return `<div style="font-size:.8em;color:#8b949e">
      Confidence: <span style="color:${data.abuseConfidenceScore>50?'#ef4444':'#f97316'};font-weight:700">${data.abuseConfidenceScore}%</span>
      ${data.totalReports ? ` · ${data.totalReports} total reports` : ''}
      ${data.countryCode ? ` · ${data.countryCode}` : ''}
    </div>`;
  }
  // Shodan
  if (data.ports || data.hostnames) {
    return `<div style="font-size:.8em;color:#8b949e">
      Ports: ${(data.ports||[]).slice(0,8).join(', ')||'—'}
      ${data.org ? ` · ${_orchEsc(data.org)}` : ''}
      ${data.country_name ? ` · ${_orchEsc(data.country_name)}` : ''}
    </div>`;
  }
  // OTX
  if (data.pulses != null) {
    return `<div style="font-size:.8em;color:#8b949e">
      ${data.pulses.length} threat pulse(s)
      ${data.pulses.slice(0,2).map(p => `<div style="color:#b0bec5;margin-top:3px">· ${_orchEsc(p.name||'pulse')}</div>`).join('')}
    </div>`;
  }
  // Generic
  return `<div style="font-size:.78em;color:#8b949e">Data available — ${Object.keys(data).length} fields</div>`;
}

/* ── Message rendering ── */
function _appendUserMessage(text) {
  const msgs = document.getElementById('orch-messages');
  if (!msgs) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg--user';
  div.innerHTML = `
    <div class="ai-msg__avatar" style="background:rgba(37,99,235,.15);color:#3b82f6;border:1px solid rgba(37,99,235,.2)">
      <i class="fas fa-user"></i>
    </div>
    <div class="ai-msg__bubble">${_orchEsc(text)}</div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function _appendAssistantMessage(response) {
  const msgs = document.getElementById('orch-messages');
  if (!msgs) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg--assistant';
  div.innerHTML = `
    <div class="ai-msg__avatar" style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.2)">
      <i class="fas fa-robot"></i>
    </div>
    <div class="ai-msg__bubble">
      ${response.html || `<p>${_orchEsc(response.summary || 'Done.')}</p>`}
    </div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function _appendErrorMessage(text) {
  const msgs = document.getElementById('orch-messages');
  if (!msgs) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg--assistant';
  div.innerHTML = `
    <div class="ai-msg__avatar" style="background:rgba(239,68,68,.1);color:#ef4444">
      <i class="fas fa-exclamation-triangle"></i>
    </div>
    <div class="ai-msg__bubble" style="border-color:rgba(239,68,68,.3)">
      <span style="color:#ef4444"><i class="fas fa-exclamation-triangle" style="margin-right:6px"></i>${_orchEsc(text)}</span>
      <br><small style="color:#8b949e">The backend AI endpoint may be unavailable. Try again or check connectivity.</small>
    </div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function _showThinking(show) {
  const badge = document.getElementById('orch-think-badge');
  if (badge) badge.style.display = show ? 'inline-flex' : 'none';
  const btn = document.getElementById('orch-send-btn');
  if (btn) btn.disabled = show;
}

/* ── Stats ── */
function _orchUpdateStats() {
  const s = _AIORCH.currentSession;
  if (!s) return;
  const map = {'queries': s.queries, 'iocs-found': s.iocs, 'tools-used': s.tools, 'actions': s.actions};
  Object.entries(map).forEach(([key, val]) => {
    const el = document.getElementById(`orch-stat-${key}`);
    if (el) el.textContent = val;
  });
  const title = document.getElementById('orch-session-title');
  if (title && s.queries > 0) title.textContent = s.title || `Session · ${s.queries} queries`;
}

/* ── Run tool dialog ── */
window._orchRunTool = function(toolId) {
  const tool = ORCH_TOOLS.find(t => t.id === toolId);
  if (!tool) return;
  const inp = document.getElementById('orch-input');
  if (!inp) return;
  const prompts = {
    ioc_lookup:    'Look up IOC: ',
    vt_lookup:     'Check VirusTotal for: ',
    abuseipdb:     'AbuseIPDB lookup for IP: ',
    shodan:        'Shodan scan for IP: ',
    otx_lookup:    'OTX lookup for: ',
    campaign_hunt: 'Find campaigns matching: ',
    mitre_map:     'Map MITRE techniques for: ',
    threat_summary:'Generate threat summary for: ',
    case_create:   'Create DFIR case for: ',
    export_report: 'Export investigation report',
  };
  inp.value = prompts[toolId] || '';
  inp.focus();
  inp.selectionStart = inp.selectionEnd = inp.value.length;
};

window._orchLoadSession = function(id) {
  if (typeof showToast === 'function') showToast(`📂 Loading session ${id.slice(-8)}…`, 'info');
};

window._orchShowLogs = function() {
  const logs = _AIORCH.logs;
  if (!logs.length) {
    if (typeof showToast === 'function') showToast('📋 No action logs yet in this session', 'info');
    return;
  }
  // Simple log display toast
  if (typeof showToast === 'function') showToast(`📋 ${logs.length} actions logged in current session`, 'info');
};

window._orchExportReport = function() {
  const report = {
    session: _AIORCH.currentSession,
    messages: _AIORCH.messages,
    logs: _AIORCH.logs,
    exported: _orchNow(),
    platform: 'Wadjet-Eye AI',
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ai-investigation-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  if (typeof showToast === 'function') showToast('📊 Investigation report exported', 'success');
};

window._orchCreateCase = function(value, type) {
  if (typeof showToast === 'function') showToast(`✅ DFIR case created for ${value.slice(0,40)}`, 'success');
  _orchLogAction('case_created', value, `Created case for ${type} IOC`);
  _AIORCH.currentSession && _AIORCH.currentSession.actions++;
  _orchUpdateStats();
};

window._orchAddToIOCDB = function(value, type) {
  if (typeof showToast === 'function') showToast(`📌 ${value.slice(0,40)} added to IOC database`, 'success');
  _orchLogAction('ioc_added', value, `Added ${type} to database`);
};

window._orchExportInvestigation = function(value) {
  if (typeof showToast === 'function') showToast(`📊 Investigation for ${value.slice(0,30)} exported`, 'success');
};

function _orchLogAction(action, subject, detail) {
  _AIORCH.logs.push({
    action, subject, detail,
    timestamp: _orchNow(),
    id: `log-${Date.now()}`,
  });
}
