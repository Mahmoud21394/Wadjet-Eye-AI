/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — AI-Powered Threat Hunting & DFIR Engine
 *  Frontend Module v1.0 — Wadjet-Eye AI Platform
 *
 *  Features:
 *   • Real-time detection stream (WebSocket)
 *   • Interactive forensic timeline (D3.js)
 *   • Attack-path graph visualization
 *   • RQL & natural-language threat hunting
 *   • IOC enrichment lookup panel
 *   • MITRE ATT&CK heatmap
 *   • Entity investigation workspace
 *   • Risk scoring dashboard
 *   • AI-powered rule generation
 *
 *  Exports: window.RAYKAN_UI = { render, hunt, ingest, investigate }
 *  js/raykan.js
 * ═══════════════════════════════════════════════════════════════════
 */

(function(window) {
  'use strict';

  // ── Constants ──────────────────────────────────────────────────
  const RAYKAN_VERSION = '1.0.0';
  const API_BASE       = window.BACKEND_URL?.() || 'https://wadjet-eye-ai.onrender.com';
  const WS_BASE        = API_BASE.replace(/^http/, 'ws');

  // Severity → styling
  const SEV_CONFIG = {
    critical    : { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  badge: 'bg-red-600',    icon: '🔴' },
    high        : { color: '#f97316', bg: 'rgba(249,115,22,0.1)', badge: 'bg-orange-500', icon: '🟠' },
    medium      : { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  badge: 'bg-yellow-500', icon: '🟡' },
    low         : { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  badge: 'bg-green-600',  icon: '🟢' },
    informational: { color: '#6b7280', bg: 'rgba(107,114,128,0.1)', badge: 'bg-gray-500', icon: '⚪' },
  };

  // ── State ───────────────────────────────────────────────────────
  const STATE = {
    detections  : [],
    timeline    : [],
    chains      : [],
    anomalies   : [],
    huntResults : null,
    stats       : null,
    activeTab   : 'overview',
    wsConnected : false,
    analyzing   : false,
    hunting     : false,
    sessionId   : null,
    riskScore   : 0,
    lastUpdated : null,
  };

  // ── WebSocket client ────────────────────────────────────────────
  let _ws          = null;
  let _wsRetries   = 0;

  function connectWS() {
    if (_ws?.readyState === WebSocket.OPEN) return;
    try {
      const token = window.UnifiedTokenStore?.getToken() || window.TokenStore?.getToken() || '';
      _ws = new WebSocket(`${WS_BASE}/socket.io/?transport=websocket`);
      _ws.onopen  = () => { STATE.wsConnected = true; _wsRetries = 0; _updateStatusBadge(); };
      _ws.onclose = () => {
        STATE.wsConnected = false; _updateStatusBadge();
        if (_wsRetries < 5) { setTimeout(() => { _wsRetries++; connectWS(); }, 3000 * _wsRetries); }
      };
      _ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'raykan:detection') _handleRealtimeDetection(msg.payload);
          if (msg.type === 'raykan:anomaly')   _handleRealtimeAnomaly(msg.payload);
        } catch {}
      };
    } catch(e) { /* WS not available in all environments */ }
  }

  // ── API helpers ─────────────────────────────────────────────────
  async function _apiCall(method, path, body) {
    const token = window.UnifiedTokenStore?.getToken() || window.TokenStore?.getToken() || '';
    const opts  = {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(`${API_BASE}/api/raykan${path}`, opts);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `API error ${resp.status}`);
    return data;
  }

  // ════════════════════════════════════════════════════════════════
  //  RENDER — Main entry point
  // ════════════════════════════════════════════════════════════════
  async function render(container) {
    if (!container) container = document.getElementById('raykanWrap');
    if (!container) return;

    container.innerHTML = _buildUI();
    _attachEventListeners();
    await _loadStats();
    _setActiveTab('overview');
    connectWS();
  }

  // ════════════════════════════════════════════════════════════════
  //  UI BUILDER
  // ════════════════════════════════════════════════════════════════
  function _buildUI() {
    return `
<div class="raykan-root" style="
  display:flex; flex-direction:column; height:100%; min-height:600px;
  background:#0d1117; color:#e6edf3; font-family:'Inter',sans-serif;
">

  <!-- ═══ HEADER BAR ═══ -->
  <div style="
    display:flex; align-items:center; gap:12px; padding:14px 20px;
    background:#161b22; border-bottom:1px solid #30363d;
    flex-shrink:0;
  ">
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="
        width:36px;height:36px;border-radius:8px;
        background:linear-gradient(135deg,#ef4444,#dc2626);
        display:flex;align-items:center;justify-content:center;
        font-size:18px; box-shadow:0 0 12px rgba(239,68,68,0.4);
      ">🎯</div>
      <div>
        <div style="font-size:16px;font-weight:700;letter-spacing:.5px;">RAYKAN</div>
        <div style="font-size:10px;color:#8b949e;margin-top:1px;">AI Threat Hunting & DFIR Engine v${RAYKAN_VERSION}</div>
      </div>
    </div>
    <div style="margin-left:auto;display:flex;align-items:center;gap:10px;">
      <div id="raykan-ws-badge" style="
        display:flex;align-items:center;gap:6px;padding:4px 10px;
        border-radius:20px;font-size:11px;font-weight:600;
        background:#161b22;border:1px solid #30363d;color:#8b949e;
      ">
        <span id="raykan-ws-dot" style="width:7px;height:7px;border-radius:50%;background:#6b7280;"></span>
        <span id="raykan-ws-label">Connecting…</span>
      </div>
      <div id="raykan-risk-badge" style="
        padding:4px 14px;border-radius:20px;font-size:12px;font-weight:700;
        background:rgba(107,114,128,0.15);color:#9ca3af;border:1px solid #374151;
      ">Risk: —</div>
      <button onclick="window.RAYKAN_UI.runSample('ransomware')" style="
        padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;
        background:linear-gradient(90deg,#dc2626,#b91c1c);color:#fff;border:none;
        transition:.2s;
      " onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
        ▶ Run Sample Analysis
      </button>
    </div>
  </div>

  <!-- ═══ STATS ROW ═══ -->
  <div id="raykan-stats-row" style="
    display:grid;grid-template-columns:repeat(5,1fr);gap:1px;
    background:#21262d;border-bottom:1px solid #30363d;flex-shrink:0;
  ">
    ${_statCard('Events Processed', '0', '#60a5fa',    'raykan-stat-events')}
    ${_statCard('Detections',       '0', '#ef4444',    'raykan-stat-dets')}
    ${_statCard('Anomalies',        '0', '#f59e0b',    'raykan-stat-anom')}
    ${_statCard('Attack Chains',    '0', '#a78bfa',    'raykan-stat-chains')}
    ${_statCard('Rules Loaded',     '0', '#34d399',    'raykan-stat-rules')}
  </div>

  <!-- ═══ TAB BAR ═══ -->
  <div style="
    display:flex;gap:0;background:#161b22;
    border-bottom:1px solid #30363d;flex-shrink:0;overflow-x:auto;
  ">
    ${_tab('overview',    '📊 Overview')}
    ${_tab('hunt',        '🔍 Threat Hunt')}
    ${_tab('timeline',    '⏱ Timeline')}
    ${_tab('detections',  '🚨 Detections')}
    ${_tab('chains',      '🔗 Attack Chains')}
    ${_tab('ioc',         '🕵️ IOC Lookup')}
    ${_tab('rules',       '📋 Rules')}
    ${_tab('mitre',       '🗺 MITRE')}
    ${_tab('rulegen',     '✨ AI Rule Gen')}
  </div>

  <!-- ═══ TAB CONTENT ═══ -->
  <div id="raykan-content" style="flex:1;overflow:auto;padding:20px;">
    <div id="raykan-tab-overview">   ${_renderOverviewTab()}</div>
    <div id="raykan-tab-hunt"        style="display:none">${_renderHuntTab()}</div>
    <div id="raykan-tab-timeline"    style="display:none">${_renderTimelineTab()}</div>
    <div id="raykan-tab-detections"  style="display:none">${_renderDetectionsTab()}</div>
    <div id="raykan-tab-chains"      style="display:none">${_renderChainsTab()}</div>
    <div id="raykan-tab-ioc"         style="display:none">${_renderIOCTab()}</div>
    <div id="raykan-tab-rules"       style="display:none">${_renderRulesTab()}</div>
    <div id="raykan-tab-mitre"       style="display:none">${_renderMITRETab()}</div>
    <div id="raykan-tab-rulegen"     style="display:none">${_renderRuleGenTab()}</div>
  </div>

</div>`;
  }

  // ── Stat card ────────────────────────────────────────────────────
  function _statCard(label, value, color, id) {
    return `
<div style="padding:14px 20px;background:#0d1117;">
  <div id="${id}" style="font-size:24px;font-weight:700;color:${color};">${value}</div>
  <div style="font-size:11px;color:#8b949e;margin-top:2px;">${label}</div>
</div>`;
  }

  // ── Tab button ───────────────────────────────────────────────────
  function _tab(id, label) {
    return `
<button class="raykan-tab-btn" data-tab="${id}" onclick="window.RAYKAN_UI._setTab('${id}')" style="
  padding:10px 16px;font-size:12px;font-weight:500;cursor:pointer;
  background:transparent;color:#8b949e;border:none;border-bottom:2px solid transparent;
  white-space:nowrap;transition:.15s;
" onmouseover="this.style.color='#e6edf3'" onmouseout="if(!this.classList.contains('active'))this.style.color='#8b949e'">
  ${label}
</button>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  TAB CONTENT RENDERERS
  // ════════════════════════════════════════════════════════════════

  function _renderOverviewTab() {
    return `
<div>
  <div style="font-size:14px;color:#8b949e;margin-bottom:16px;">
    Engine status · Last updated: <span id="raykan-last-updated">—</span>
  </div>

  <!-- Quick Action Buttons -->
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;">
    <button onclick="window.RAYKAN_UI.runSample('ransomware')" class="raykan-action-btn" style="
      padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
      background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;border:none;
    ">🎯 Ransomware Simulation</button>
    <button onclick="window.RAYKAN_UI.runSample('lateral_movement')" class="raykan-action-btn" style="
      padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
      background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;border:none;
    ">↔️ Lateral Movement Demo</button>
    <button onclick="window.RAYKAN_UI.runSample('credential_dump')" class="raykan-action-btn" style="
      padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
      background:linear-gradient(135deg,#c2410c,#9a3412);color:#fff;border:none;
    ">🔑 Credential Dump Demo</button>
    <button onclick="window.RAYKAN_UI.loadRules()" class="raykan-action-btn" style="
      padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
      background:linear-gradient(135deg,#065f46,#047857);color:#fff;border:none;
    ">📋 View Detection Rules</button>
  </div>

  <!-- Recent Detections -->
  <div style="
    background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;
    margin-bottom:16px;
  ">
    <div style="font-size:14px;font-weight:600;margin-bottom:16px;display:flex;justify-content:space-between;">
      <span>🚨 Recent Detections</span>
      <span id="raykan-det-count" style="font-size:12px;color:#8b949e;">0 total</span>
    </div>
    <div id="raykan-recent-dets" style="min-height:60px;color:#6b7280;font-size:13px;">
      No detections yet — run a sample analysis or ingest events.
    </div>
  </div>

  <!-- Sub-engine status -->
  <div style="
    display:grid;grid-template-columns:repeat(2,1fr);gap:12px;
  ">
    <div id="raykan-sigma-status" style="
      background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;
    ">
      <div style="font-size:12px;font-weight:700;color:#34d399;margin-bottom:8px;">⚙️ Sigma Engine</div>
      <div style="font-size:24px;font-weight:700;color:#e6edf3;" id="raykan-rule-cnt">—</div>
      <div style="font-size:11px;color:#8b949e;margin-top:2px;">Rules loaded</div>
    </div>
    <div style="
      background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;
    ">
      <div style="font-size:12px;font-weight:700;color:#60a5fa;margin-bottom:8px;">🤖 AI Detector</div>
      <div style="font-size:24px;font-weight:700;color:#e6edf3;" id="raykan-ai-status-val">—</div>
      <div style="font-size:11px;color:#8b949e;margin-top:2px;">Provider status</div>
    </div>
    <div style="
      background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;
    ">
      <div style="font-size:12px;font-weight:700;color:#f59e0b;margin-bottom:8px;">👥 UEBA Engine</div>
      <div style="font-size:24px;font-weight:700;color:#e6edf3;" id="raykan-ueba-profiles">0</div>
      <div style="font-size:11px;color:#8b949e;margin-top:2px;">Behavioral profiles</div>
    </div>
    <div style="
      background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;
    ">
      <div style="font-size:12px;font-weight:700;color:#a78bfa;margin-bottom:8px;">⏱ Uptime</div>
      <div style="font-size:24px;font-weight:700;color:#e6edf3;" id="raykan-uptime">—</div>
      <div style="font-size:11px;color:#8b949e;margin-top:2px;">Seconds</div>
    </div>
  </div>
</div>`;
  }

  function _renderHuntTab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    Hunt for threats using RAYKAN Query Language (RQL) or natural language.
  </div>

  <!-- Query Type Toggle -->
  <div style="display:flex;gap:8px;margin-bottom:16px;">
    <button id="raykan-hunt-rql-btn" onclick="window.RAYKAN_UI._setHuntMode('rql')" style="
      padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;
      background:#21262d;color:#60a5fa;border:1px solid #30363d;
    ">🔍 RQL Query</button>
    <button id="raykan-hunt-nl-btn" onclick="window.RAYKAN_UI._setHuntMode('nl')" style="
      padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;
      background:transparent;color:#8b949e;border:1px solid #30363d;
    ">💬 Natural Language</button>
  </div>

  <!-- Query Input -->
  <div style="
    background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;
    margin-bottom:16px;
  ">
    <textarea id="raykan-hunt-input" placeholder="process.name:&quot;powershell.exe&quot; AND commandLine:*EncodedCommand*" style="
      width:100%;min-height:80px;background:transparent;border:none;outline:none;
      color:#e6edf3;font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;
      resize:vertical;
    "></textarea>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;">
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${_huntChip('PS Encoded', 'process.name:"powershell.exe" AND commandLine:*EncodedCommand*')}
        ${_huntChip('Mimikatz', 'commandLine:*sekurlsa* OR commandLine:*lsadump*')}
        ${_huntChip('VSS Delete', 'commandLine:*vssadmin*delete*')}
        ${_huntChip('PsExec', 'process.name:"psexec.exe"')}
        ${_huntChip('Failed Logins', 'event.id:4625')}
      </div>
      <button id="raykan-hunt-btn" onclick="window.RAYKAN_UI.executeHunt()" style="
        padding:8px 20px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;
        background:linear-gradient(90deg,#1d4ed8,#2563eb);color:#fff;border:none;
        min-width:100px;
      ">Hunt ▶</button>
    </div>
  </div>

  <!-- Hunt Results -->
  <div id="raykan-hunt-results" style="min-height:100px;">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:40px;">
      Enter a query above and click Hunt to search event history.
    </div>
  </div>
</div>`;
  }

  function _huntChip(label, query) {
    const q = query.replace(/"/g, '&quot;');
    return `<button onclick="document.getElementById('raykan-hunt-input').value='${q}'" style="
      padding:3px 10px;border-radius:12px;font-size:11px;cursor:pointer;
      background:#21262d;color:#8b949e;border:1px solid #30363d;
    ">${label}</button>`;
  }

  function _renderTimelineTab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    Chronological forensic timeline of events and detections.
  </div>
  <div id="raykan-timeline-container" style="
    background:#161b22;border:1px solid #30363d;border-radius:10px;
    max-height:600px;overflow-y:auto;
  ">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">
      Run an analysis to populate the timeline.
    </div>
  </div>
</div>`;
  }

  function _renderDetectionsTab() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
    <div style="font-size:13px;color:#8b949e;">All triggered detections from the current session.</div>
    <div style="display:flex;gap:8px;">
      <select id="raykan-det-filter" onchange="window.RAYKAN_UI._filterDetections()" style="
        background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;
        padding:4px 8px;font-size:12px;
      ">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
    </div>
  </div>
  <div id="raykan-dets-list" style="display:flex;flex-direction:column;gap:8px;">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">
      No detections yet.
    </div>
  </div>
</div>`;
  }

  function _renderChainsTab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    Reconstructed multi-stage attack chains. Each chain represents a connected sequence of adversary actions.
  </div>
  <div id="raykan-chains-list" style="display:flex;flex-direction:column;gap:12px;">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">
      No attack chains detected yet.
    </div>
  </div>
</div>`;
  }

  function _renderIOCTab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    Look up IOCs (IPs, domains, file hashes, URLs) against VirusTotal, AbuseIPDB, and OTX.
  </div>
  <div style="
    background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;
    margin-bottom:16px;
  ">
    <div style="display:flex;gap:10px;">
      <input id="raykan-ioc-input" type="text" placeholder="Enter IP, domain, MD5/SHA256, or URL…" style="
        flex:1;background:#21262d;border:1px solid #30363d;border-radius:8px;
        padding:10px 14px;color:#e6edf3;font-size:13px;outline:none;
      "/>
      <button onclick="window.RAYKAN_UI.lookupIOC()" style="
        padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
        background:linear-gradient(90deg,#7c3aed,#6d28d9);color:#fff;border:none;
      ">🔍 Lookup</button>
    </div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">
      ${_iocChip('8.8.8.8')} ${_iocChip('185.220.101.45')} ${_iocChip('malware.exe MD5')}
      ${_iocChip('evil.domain.ru')}
    </div>
  </div>
  <div id="raykan-ioc-result" style="min-height:100px;"></div>
</div>`;
  }

  function _iocChip(val) {
    return `<button onclick="document.getElementById('raykan-ioc-input').value='${val}';window.RAYKAN_UI.lookupIOC()" style="
      padding:3px 10px;border-radius:12px;font-size:11px;cursor:pointer;
      background:#21262d;color:#8b949e;border:1px solid #30363d;
    ">${val}</button>`;
  }

  function _renderRulesTab() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
    <div style="font-size:13px;color:#8b949e;">
      Loaded Sigma detection rules — <span id="raykan-rules-count">0</span> rules active.
    </div>
    <div style="display:flex;gap:8px;">
      <select id="raykan-rules-sev-filter" onchange="window.RAYKAN_UI.loadRules()" style="
        background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;
        padding:4px 8px;font-size:12px;
      ">
        <option value="">All</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
    </div>
  </div>
  <div id="raykan-rules-list" style="display:flex;flex-direction:column;gap:6px;">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:40px;">
      <button onclick="window.RAYKAN_UI.loadRules()" style="
        padding:8px 20px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;
        background:#21262d;color:#60a5fa;border:1px solid #30363d;
      ">Load Rules</button>
    </div>
  </div>
</div>`;
  }

  function _renderMITRETab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    MITRE ATT&CK v14 technique coverage from current detections.
  </div>
  <div id="raykan-mitre-heatmap" style="
    background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;
    min-height:200px;
  ">
    <div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">
      <button onclick="window.RAYKAN_UI.loadMITRE()" style="
        padding:8px 20px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;
        background:#21262d;color:#60a5fa;border:1px solid #30363d;
      ">Load MITRE Coverage</button>
    </div>
  </div>
</div>`;
  }

  function _renderRuleGenTab() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:16px;">
    Describe a threat in natural language and let AI generate a Sigma detection rule.
  </div>
  <div style="
    background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;
    margin-bottom:16px;
  ">
    <textarea id="raykan-rulegen-input" rows="4" placeholder="e.g. Detect when an attacker uses PowerShell to download a payload from a remote server and execute it silently, bypassing execution policies" style="
      width:100%;background:#21262d;border:1px solid #30363d;border-radius:8px;
      padding:12px;color:#e6edf3;font-size:13px;resize:vertical;outline:none;
    "></textarea>
    <button onclick="window.RAYKAN_UI.generateRule()" style="
      margin-top:12px;padding:10px 24px;border-radius:8px;font-size:13px;
      font-weight:600;cursor:pointer;border:none;
      background:linear-gradient(135deg,#7c3aed,#2563eb);color:#fff;
    ">✨ Generate Rule with AI</button>
  </div>
  <div id="raykan-rulegen-result" style="min-height:100px;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  ACTIONS
  // ════════════════════════════════════════════════════════════════

  async function runSample(scenario = 'ransomware') {
    STATE.analyzing = true;
    _showLoading('Analyzing ' + scenario + ' scenario…');

    try {
      const result = await _apiCall('POST', '/analyze/sample', { scenario });
      STATE.detections  = result.detections || [];
      STATE.timeline    = result.timeline   || [];
      STATE.chains      = result.chains     || [];
      STATE.anomalies   = result.anomalies  || [];
      STATE.riskScore   = result.riskScore  || 0;
      STATE.sessionId   = result.sessionId;
      STATE.lastUpdated = new Date();

      _updateStats(result);
      _refreshAllTabs();
      _setActiveTab('detections');
      _showToast(`Analysis complete: ${result.detections?.length || 0} detections found`, 'success');
    } catch(e) {
      _showToast('Analysis failed: ' + e.message, 'error');
    } finally {
      STATE.analyzing = false;
    }
  }

  async function executeHunt() {
    const input = document.getElementById('raykan-hunt-input');
    const query = input?.value?.trim();
    if (!query) return _showToast('Enter a query first', 'warning');

    const mode    = window._raykanHuntMode || 'rql';
    const btn     = document.getElementById('raykan-hunt-btn');
    if (btn) { btn.textContent = '⏳ Hunting…'; btn.disabled = true; }

    try {
      const endpoint = mode === 'nl' ? '/hunt/nl' : '/hunt';
      const result   = await _apiCall('POST', endpoint, { query, aiAssist: true });
      STATE.huntResults = result;
      _renderHuntResults(result);
      _showToast(`Hunt complete: ${result.count} matches`, result.count > 0 ? 'success' : 'info');
    } catch(e) {
      _showToast('Hunt failed: ' + e.message, 'error');
    } finally {
      if (btn) { btn.textContent = 'Hunt ▶'; btn.disabled = false; }
    }
  }

  async function lookupIOC() {
    const input = document.getElementById('raykan-ioc-input');
    const value = input?.value?.trim();
    if (!value) return _showToast('Enter an IOC value', 'warning');

    const container = document.getElementById('raykan-ioc-result');
    if (container) container.innerHTML = _loadingSpinner('Looking up IOC…');

    try {
      const result = await _apiCall('GET', `/ioc/${encodeURIComponent(value)}`);
      _renderIOCResult(result.ioc, container);
    } catch(e) {
      if (container) container.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  async function loadRules() {
    const sev = document.getElementById('raykan-rules-sev-filter')?.value || '';
    try {
      const result = await _apiCall('GET', `/rules?severity=${sev}&limit=100`);
      _renderRulesList(result.rules || [], result.total || 0);
    } catch(e) {
      _showToast('Failed to load rules: ' + e.message, 'error');
    }
  }

  async function loadMITRE() {
    const container = document.getElementById('raykan-mitre-heatmap');
    if (container) container.innerHTML = _loadingSpinner('Loading MITRE coverage…');
    try {
      const result = await _apiCall('GET', '/mitre');
      _renderMITREHeatmap(result, container);
    } catch(e) {
      if (container) container.innerHTML = `<div style="color:#ef4444;padding:20px;">Failed: ${e.message}</div>`;
    }
  }

  async function generateRule() {
    const input = document.getElementById('raykan-rulegen-input');
    const desc  = input?.value?.trim();
    if (!desc) return _showToast('Describe the threat first', 'warning');

    const container = document.getElementById('raykan-rulegen-result');
    if (container) container.innerHTML = _loadingSpinner('Generating rule with AI…');

    try {
      const result = await _apiCall('POST', '/rule/generate', { description: desc });
      _renderGeneratedRule(result.rule, result.validation, container);
    } catch(e) {
      if (container) container.innerHTML = `<div style="color:#ef4444;padding:20px;">Failed: ${e.message}</div>`;
    }
  }

  // ════════════════════════════════════════════════════════════════
  //  RENDERERS
  // ════════════════════════════════════════════════════════════════

  function _renderHuntResults(result) {
    const container = document.getElementById('raykan-hunt-results');
    if (!container) return;

    if (!result.count) {
      container.innerHTML = `
<div style="
  background:#161b22;border:1px solid #30363d;border-radius:10px;
  padding:40px;text-align:center;color:#6b7280;
">
  No matches found for query. ${result.suggestion ? `<br/><span style="color:#60a5fa;">${result.suggestion}</span>` : ''}
</div>`;
      return;
    }

    const rows = result.matches.slice(0, 50).map(m => `
<tr style="border-bottom:1px solid #21262d;">
  <td style="padding:8px 12px;font-family:monospace;font-size:11px;color:#8b949e;">${new Date(m.timestamp).toLocaleTimeString()}</td>
  <td style="padding:8px 12px;font-size:12px;color:#e6edf3;">${m.computer || '—'}</td>
  <td style="padding:8px 12px;font-size:12px;color:#60a5fa;">${m.user || '—'}</td>
  <td style="padding:8px 12px;font-size:11px;font-family:monospace;color:#34d399;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${m.commandLine || m.process || '—'}</td>
</tr>`).join('');

    container.innerHTML = `
<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;">
  <div style="padding:12px 16px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;">
    <span style="font-size:13px;font-weight:600;color:#e6edf3;">Hunt Results — ${result.count} matches</span>
    <span style="font-size:12px;color:#8b949e;">${result.duration}ms · Searched ${result.totalSearched || 0} events</span>
  </div>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr style="background:#21262d;color:#8b949e;">
          <th style="padding:8px 12px;text-align:left;">Time</th>
          <th style="padding:8px 12px;text-align:left;">Host</th>
          <th style="padding:8px 12px;text-align:left;">User</th>
          <th style="padding:8px 12px;text-align:left;">Command / Process</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  ${result.count > 50 ? `<div style="padding:10px 16px;color:#8b949e;font-size:11px;">Showing 50 of ${result.count} results</div>` : ''}
</div>`;
  }

  function _renderDetectionsList(detections) {
    const container = document.getElementById('raykan-dets-list');
    const recent    = document.getElementById('raykan-recent-dets');
    if (!container) return;

    if (!detections.length) {
      container.innerHTML = `<div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">No detections.</div>`;
      return;
    }

    const items = detections.map(det => {
      const sev = SEV_CONFIG[det.severity] || SEV_CONFIG.medium;
      return `
<div style="
  background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 16px;
  border-left:3px solid ${sev.color};
">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;">
    <div style="flex:1;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="
          padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;
          background:${sev.bg};color:${sev.color};text-transform:uppercase;
        ">${det.severity}</span>
        <span style="font-size:13px;font-weight:600;color:#e6edf3;">${det.ruleName}</span>
        ${det.confidence ? `<span style="font-size:10px;color:#8b949e;">(${det.confidence}% confidence)</span>` : ''}
      </div>
      <div style="font-size:12px;color:#8b949e;">
        ${det.computer ? `🖥 ${det.computer}` : ''} 
        ${det.user ? ` · 👤 ${det.user}` : ''}
        ${det.process ? ` · ⚙️ ${det.process?.split('\\').pop()}` : ''}
      </div>
      ${det.commandLine ? `<div style="font-size:11px;color:#6b7280;font-family:monospace;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${det.commandLine.slice(0,120)}</div>` : ''}
      ${det.mitre?.techniques?.length ? `
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:6px;">
        ${det.mitre.techniques.map(t => `
        <span style="
          padding:2px 6px;border-radius:4px;font-size:10px;
          background:#1f2d3d;color:#60a5fa;border:1px solid #1d4ed8;
        ">${t.id}: ${t.name}</span>`).join('')}
      </div>` : ''}
    </div>
    <div style="text-align:right;flex-shrink:0;">
      <div style="font-size:11px;color:#6b7280;">${new Date(det.timestamp).toLocaleTimeString()}</div>
      ${det.riskScore ? `<div style="font-size:18px;font-weight:700;color:${sev.color};">${det.riskScore}</div><div style="font-size:9px;color:#6b7280;">RISK</div>` : ''}
    </div>
  </div>
  ${det.ai?.summary ? `<div style="margin-top:8px;padding:8px 10px;background:#0d1117;border-radius:6px;font-size:12px;color:#8b949e;border-left:2px solid #1d4ed8;">🤖 ${det.ai.summary}</div>` : ''}
</div>`;
    });

    container.innerHTML = items.join('');

    // Update recent list in overview
    if (recent) {
      recent.innerHTML = detections.slice(0, 5).map(d => {
        const sev = SEV_CONFIG[d.severity] || SEV_CONFIG.medium;
        return `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #21262d;">
          <span style="color:${sev.color};font-size:12px;">${sev.icon}</span>
          <span style="font-size:12px;flex:1;color:#e6edf3;">${d.ruleName}</span>
          <span style="font-size:10px;color:#6b7280;">${new Date(d.timestamp).toLocaleTimeString()}</span>
        </div>`;
      }).join('');
    }
  }

  function _renderChainsList(chains) {
    const container = document.getElementById('raykan-chains-list');
    if (!container) return;

    if (!chains.length) {
      container.innerHTML = `<div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">No chains detected.</div>`;
      return;
    }

    container.innerHTML = chains.map(chain => {
      const sev = SEV_CONFIG[chain.severity] || SEV_CONFIG.medium;
      const stages = chain.stages?.map(s => `
<div style="
  padding:6px 10px;border-radius:6px;font-size:11px;
  background:#21262d;border:1px solid #30363d;white-space:nowrap;
">
  <div style="color:#a78bfa;font-weight:600;">${s.technique || s.tactic}</div>
  <div style="color:#6b7280;">${s.ruleName || s.tactic}</div>
</div>`).join('<div style="color:#60a5fa;padding:0 4px;display:flex;align-items:center;">→</div>') || '';

      return `
<div style="
  background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px;
  border-left:3px solid ${sev.color};
">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
    <div>
      <span style="font-size:14px;font-weight:700;color:#e6edf3;">
        ${chain.type === 'lateral_movement' ? '↔️ Lateral Movement' : '⛓ Attack Chain'}
      </span>
      <span style="margin-left:10px;font-size:12px;color:#8b949e;">${chain.entity || 'Multiple entities'}</span>
    </div>
    <div style="text-align:right;">
      <span style="
        padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;
        background:${sev.bg};color:${sev.color};
      ">${chain.severity?.toUpperCase()}</span>
      <div style="font-size:10px;color:#6b7280;margin-top:2px;">
        ${chain.confidence}% confidence · ${chain.stages?.length || 0} stages
      </div>
    </div>
  </div>
  <div style="display:flex;flex-wrap:wrap;align-items:center;gap:4px;overflow-x:auto;">
    ${stages}
  </div>
  <div style="margin-top:10px;font-size:12px;color:#8b949e;">${chain.description || ''}</div>
</div>`;
    }).join('');
  }

  function _renderTimelineList(events) {
    const container = document.getElementById('raykan-timeline-container');
    if (!container) return;

    if (!events.length) {
      container.innerHTML = `<div style="color:#6b7280;font-size:13px;text-align:center;padding:60px;">No timeline events.</div>`;
      return;
    }

    container.innerHTML = events.slice(0, 200).map((e, i) => `
<div style="
  display:flex;align-items:flex-start;gap:12px;padding:10px 16px;
  border-bottom:1px solid #21262d;
  ${e.isDetection ? 'background:rgba(239,68,68,0.04);' : ''}
">
  <div style="
    width:7px;height:7px;border-radius:50%;margin-top:5px;flex-shrink:0;
    background:${e.color || '#6b7280'};
    ${e.isDetection ? `box-shadow:0 0 6px ${e.color};` : ''}
  "></div>
  <div style="flex:1;min-width:0;">
    <div style="display:flex;justify-content:space-between;gap:8px;">
      <span style="font-size:12px;${e.isDetection ? 'color:#ef4444;font-weight:600;' : 'color:#e6edf3;'}">${e.title || e.description || 'Event'}</span>
      <span style="font-size:11px;color:#6b7280;flex-shrink:0;">${new Date(e.ts).toLocaleTimeString()}</span>
    </div>
    <div style="font-size:11px;color:#6b7280;margin-top:1px;">
      ${e.entity ? `🖥 ${e.entity}` : ''} ${e.user ? `· 👤 ${e.user}` : ''}
    </div>
  </div>
  <div style="font-size:9px;color:#6b7280;flex-shrink:0;padding-top:4px;">#${e.seq || i+1}</div>
</div>`).join('');
  }

  function _renderIOCResult(ioc, container) {
    if (!ioc) { container.innerHTML = '<div style="color:#ef4444;padding:20px;">No data returned</div>'; return; }
    const color = ioc.malicious ? '#ef4444' : ioc.reputation > 30 ? '#f97316' : '#34d399';

    container.innerHTML = `
<div style="background:#161b22;border:1px solid ${color};border-radius:10px;padding:20px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
    <div>
      <div style="font-size:14px;font-weight:700;color:#e6edf3;">${ioc.ioc}</div>
      <div style="font-size:12px;color:#8b949e;margin-top:2px;">Type: ${ioc.type}</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:32px;font-weight:700;color:${color};">${ioc.threatScore || 0}</div>
      <div style="font-size:10px;color:#8b949e;">THREAT SCORE</div>
      <div style="
        padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;
        background:${ioc.malicious ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)'};
        color:${ioc.malicious ? '#ef4444' : '#34d399'};margin-top:4px;
      ">${ioc.malicious ? '⚠️ MALICIOUS' : '✅ CLEAN'}</div>
    </div>
  </div>
  ${_iocSourcePanel('VirusTotal', ioc.virusTotal, ['malicious', 'suspicious', 'harmless', 'country', 'asn'])}
  ${_iocSourcePanel('AbuseIPDB', ioc.abuseIPDB, ['abuseScore', 'totalReports', 'country', 'isp', 'usageType'])}
  ${_iocSourcePanel('AlienVault OTX', ioc.otx, ['pulseCount', 'reputation', 'country', 'asn'])}
</div>`;
  }

  function _iocSourcePanel(name, data, fields) {
    if (!data) return `<div style="padding:10px;background:#21262d;border-radius:6px;margin-bottom:8px;color:#6b7280;font-size:12px;">${name}: Not available</div>`;
    const rows = fields.map(f => data[f] !== undefined ? `
<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #21262d;">
  <span style="font-size:11px;color:#8b949e;">${f}</span>
  <span style="font-size:11px;color:#e6edf3;">${Array.isArray(data[f]) ? data[f].join(', ') : data[f]}</span>
</div>` : '').join('');

    return `
<div style="background:#21262d;border-radius:8px;padding:12px;margin-bottom:10px;">
  <div style="font-size:12px;font-weight:600;color:#60a5fa;margin-bottom:8px;">${name}</div>
  ${rows}
</div>`;
  }

  function _renderRulesList(rules, total) {
    const container = document.getElementById('raykan-rules-list');
    const cnt       = document.getElementById('raykan-rules-count');
    if (cnt) cnt.textContent = total;
    if (!container) return;

    container.innerHTML = rules.map(rule => {
      const sev = SEV_CONFIG[rule.severity] || SEV_CONFIG.medium;
      return `
<div style="
  display:flex;align-items:center;gap:12px;padding:10px 14px;
  background:#161b22;border:1px solid #30363d;border-radius:8px;
">
  <span style="
    padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;
    background:${sev.bg};color:${sev.color};text-transform:uppercase;flex-shrink:0;
  ">${rule.severity}</span>
  <div style="flex:1;">
    <div style="font-size:12px;font-weight:600;color:#e6edf3;">${rule.title}</div>
    <div style="font-size:11px;color:#6b7280;margin-top:1px;">${rule.id}</div>
  </div>
  <div style="display:flex;gap:4px;flex-wrap:wrap;max-width:300px;">
    ${(rule.tags || []).slice(0,3).map(t => `
    <span style="
      padding:1px 6px;border-radius:3px;font-size:9px;
      background:#1f2d3d;color:#60a5fa;
    ">${t}</span>`).join('')}
  </div>
</div>`;
    }).join('');
  }

  function _renderMITREHeatmap(data, container) {
    if (!container) return;
    const { heatmap = [], coverage = {} } = data;

    const bars = heatmap.slice(0, 20).map(t => {
      const sev   = SEV_CONFIG[t.severity] || SEV_CONFIG.informational;
      const width = Math.min(100, t.count * 20);
      return `
<div style="display:flex;align-items:center;gap:10px;padding:4px 0;">
  <span style="font-size:10px;color:#60a5fa;width:90px;flex-shrink:0;">${t.id}</span>
  <div style="flex:1;background:#21262d;border-radius:4px;height:16px;overflow:hidden;">
    <div style="width:${width}%;height:100%;background:${sev.color};border-radius:4px;transition:.3s;"></div>
  </div>
  <span style="font-size:11px;color:#8b949e;width:60px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${t.name}">${t.name}</span>
  <span style="font-size:11px;color:#e6edf3;width:30px;text-align:right;">${t.count}</span>
</div>`;
    }).join('');

    container.innerHTML = `
<div style="
  display:flex;justify-content:space-between;align-items:center;
  padding-bottom:16px;border-bottom:1px solid #30363d;margin-bottom:16px;
">
  <div>
    <div style="font-size:24px;font-weight:700;color:#a78bfa;">${coverage.covered || 0}</div>
    <div style="font-size:12px;color:#8b949e;">Techniques with detections</div>
  </div>
  <div>
    <div style="font-size:24px;font-weight:700;color:#60a5fa;">${coverage.percentage || 0}%</div>
    <div style="font-size:12px;color:#8b949e;">Coverage rate</div>
  </div>
  <div>
    <div style="font-size:24px;font-weight:700;color:#34d399;">${coverage.total || 0}</div>
    <div style="font-size:12px;color:#8b949e;">Total techniques</div>
  </div>
</div>
<div style="font-size:12px;font-weight:600;color:#8b949e;margin-bottom:8px;">Top Covered Techniques</div>
${bars}`;
  }

  function _renderGeneratedRule(rule, validation, container) {
    if (!container) return;
    const isValid = validation?.valid !== false;

    container.innerHTML = `
<div style="background:#161b22;border:1px solid ${isValid ? '#34d399' : '#f97316'};border-radius:10px;padding:20px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
    <div style="font-size:14px;font-weight:700;color:#e6edf3;">Generated Rule: ${rule?.title || 'AI Rule'}</div>
    <span style="
      padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;
      background:${isValid ? 'rgba(34,197,94,0.15)' : 'rgba(249,115,22,0.15)'};
      color:${isValid ? '#34d399' : '#f97316'};
    ">${isValid ? '✅ Valid' : '⚠️ Needs Review'}</span>
  </div>
  <pre style="
    background:#0d1117;border-radius:8px;padding:16px;overflow-x:auto;
    font-size:11px;color:#8b949e;font-family:'JetBrains Mono',monospace;
    border:1px solid #30363d;max-height:400px;
  ">${JSON.stringify(rule, null, 2)}</pre>
  ${validation?.errors?.length ? `<div style="color:#f97316;font-size:12px;margin-top:10px;">Errors: ${validation.errors.join(', ')}</div>` : ''}
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  HELPERS & UTILITIES
  // ════════════════════════════════════════════════════════════════

  function _updateStats(result) {
    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setEl('raykan-stat-events', (result.processed || 0).toLocaleString());
    setEl('raykan-stat-dets',   (STATE.detections.length).toLocaleString());
    setEl('raykan-stat-anom',   (STATE.anomalies.length).toLocaleString());
    setEl('raykan-stat-chains', (STATE.chains.length).toLocaleString());
    setEl('raykan-det-count',   `${STATE.detections.length} total`);
    setEl('raykan-last-updated', STATE.lastUpdated?.toLocaleTimeString() || '—');

    // Risk badge
    const badge = document.getElementById('raykan-risk-badge');
    if (badge) {
      const r = STATE.riskScore;
      const color = r >= 80 ? '#ef4444' : r >= 60 ? '#f97316' : r >= 40 ? '#eab308' : '#22c55e';
      badge.style.color = color;
      badge.style.borderColor = color;
      badge.textContent = `Risk: ${r}`;
    }
  }

  async function _loadStats() {
    try {
      const result = await _apiCall('GET', '/stats');
      const s = result.stats || {};
      const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
      setEl('raykan-stat-rules', s.rulesLoaded || 0);
      setEl('raykan-rule-cnt',   s.rulesLoaded || 0);
      setEl('raykan-ai-status-val', result.subEngines?.ai?.provider || 'none');
      setEl('raykan-ueba-profiles', result.subEngines?.ueba?.profiles || 0);
      setEl('raykan-uptime',     s.uptime || 0);
    } catch(e) { /* engine may not be initialized yet */ }
  }

  function _refreshAllTabs() {
    _renderDetectionsList(STATE.detections);
    _renderChainsList(STATE.chains);
    _renderTimelineList(STATE.timeline);
  }

  function _setActiveTab(tabId) {
    STATE.activeTab = tabId;
    document.querySelectorAll('.raykan-tab-btn').forEach(btn => {
      const isActive = btn.dataset.tab === tabId;
      btn.style.color         = isActive ? '#60a5fa' : '#8b949e';
      btn.style.borderBottom  = isActive ? '2px solid #60a5fa' : '2px solid transparent';
      btn.classList.toggle('active', isActive);
    });
    document.querySelectorAll('[id^="raykan-tab-"]').forEach(panel => {
      panel.style.display = panel.id === `raykan-tab-${tabId}` ? 'block' : 'none';
    });

    // Lazy-load tab data
    if (tabId === 'rules' && STATE.detections.length === 0) loadRules();
    if (tabId === 'mitre') loadMITRE();
  }

  function _setHuntMode(mode) {
    window._raykanHuntMode = mode;
    const rqlBtn = document.getElementById('raykan-hunt-rql-btn');
    const nlBtn  = document.getElementById('raykan-hunt-nl-btn');
    const input  = document.getElementById('raykan-hunt-input');
    if (rqlBtn) { rqlBtn.style.color = mode === 'rql' ? '#60a5fa' : '#8b949e'; rqlBtn.style.background = mode === 'rql' ? '#21262d' : 'transparent'; }
    if (nlBtn)  { nlBtn.style.color  = mode === 'nl'  ? '#60a5fa' : '#8b949e'; nlBtn.style.background  = mode === 'nl'  ? '#21262d' : 'transparent'; }
    if (input)  input.placeholder = mode === 'nl' ? 'Find all PowerShell encoded commands from the last 24 hours…' : 'process.name:"powershell.exe" AND commandLine:*EncodedCommand*';
  }

  function _filterDetections() {
    const filter = document.getElementById('raykan-det-filter')?.value || '';
    const filtered = filter ? STATE.detections.filter(d => d.severity === filter) : STATE.detections;
    _renderDetectionsList(filtered);
  }

  function _handleRealtimeDetection(det) {
    STATE.detections.unshift(det);
    if (STATE.detections.length > 500) STATE.detections.pop();
    if (STATE.activeTab === 'detections') _renderDetectionsList(STATE.detections);
    _updateStats({});
  }

  function _handleRealtimeAnomaly(a) {
    STATE.anomalies.unshift(a);
    _updateStats({});
  }

  function _updateStatusBadge() {
    const dot   = document.getElementById('raykan-ws-dot');
    const label = document.getElementById('raykan-ws-label');
    if (dot)   dot.style.background   = STATE.wsConnected ? '#34d399' : '#ef4444';
    if (label) label.textContent      = STATE.wsConnected ? 'Live' : 'Offline';
  }

  function _showLoading(msg) {
    const container = document.getElementById('raykan-content');
    if (!container) return;
    const old = container.querySelector(`#raykan-tab-${STATE.activeTab}`);
    if (old) {
      const overlay = document.createElement('div');
      overlay.id = 'raykan-loading-overlay';
      overlay.innerHTML = `<div style="
        position:absolute;inset:0;background:rgba(13,17,23,.8);
        display:flex;align-items:center;justify-content:center;
        z-index:100;border-radius:10px;
      ">${_loadingSpinner(msg)}</div>`;
      overlay.style.position = 'relative';
      old.style.position = 'relative';
      old.appendChild(overlay);
      setTimeout(() => overlay.remove(), 30000);
    }
  }

  function _loadingSpinner(msg = 'Processing…') {
    return `<div style="text-align:center;padding:40px;color:#8b949e;">
  <div style="
    width:40px;height:40px;border-radius:50%;
    border:3px solid #30363d;border-top-color:#60a5fa;
    animation:raykan-spin 1s linear infinite;margin:0 auto 12px;
  "></div>
  <style>@keyframes raykan-spin{to{transform:rotate(360deg)}}</style>
  <div style="font-size:13px;">${msg}</div>
</div>`;
  }

  function _showToast(message, type = 'info') {
    const colors = { success: '#34d399', error: '#ef4444', warning: '#f59e0b', info: '#60a5fa' };
    const toast  = document.createElement('div');
    toast.style.cssText = `
      position:fixed;bottom:24px;right:24px;z-index:9999;
      padding:12px 20px;border-radius:8px;font-size:13px;font-weight:500;
      background:#161b22;color:#e6edf3;
      border-left:4px solid ${colors[type] || colors.info};
      box-shadow:0 4px 20px rgba(0,0,0,.5);
      animation:raykan-slidein .3s ease;max-width:350px;
    `;
    const style  = document.createElement('style');
    style.textContent = '@keyframes raykan-slidein{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}';
    document.head.appendChild(style);
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }

  function _attachEventListeners() {
    // Enter key in hunt input
    const huntInput = document.getElementById('raykan-hunt-input');
    if (huntInput) {
      huntInput.addEventListener('keydown', e => {
        if (e.ctrlKey && e.key === 'Enter') executeHunt();
      });
    }
    // Enter key in IOC input
    const iocInput = document.getElementById('raykan-ioc-input');
    if (iocInput) {
      iocInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') lookupIOC();
      });
    }
  }

  // ── Public API ───────────────────────────────────────────────────
  window.RAYKAN_UI = {
    render,
    runSample,
    executeHunt,
    lookupIOC,
    loadRules,
    loadMITRE,
    generateRule,
    _setTab  : _setActiveTab,
    _setHuntMode,
    _filterDetections,
    getState : () => STATE,
  };

  // ── Register as Wadjet-Eye page module ───────────────────────────
  window.renderRAYKAN = () => {
    const wrap = document.getElementById('raykanWrap');
    if (wrap) render(wrap);
  };

  console.log(`[RAYKAN UI v${RAYKAN_VERSION}] Loaded`);

})(window);
