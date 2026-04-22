/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — AI-Powered Threat Hunting & DFIR Engine
 *  Frontend Module v2.0 — Wadjet-Eye AI Platform
 *
 *  Features:
 *   • Real-time detection stream (WebSocket)
 *   • Interactive forensic timeline
 *   • Attack-path graph visualization
 *   • RQL & natural-language threat hunting
 *   • IOC enrichment lookup panel
 *   • MITRE ATT&CK heatmap
 *   • Entity investigation workspace
 *   • Risk scoring dashboard
 *   • AI-powered rule generation
 *   • File log upload & parsing
 *   • Behavioral anomaly tracking
 *   • Attack-chain reconstruction
 *   • Forensic entity pivot graph
 *   • Export (JSON / CSV / PDF)
 *
 *  Exports: window.RAYKAN_UI = { render, hunt, ingest, investigate }
 *  js/raykan.js
 * ═══════════════════════════════════════════════════════════════════
 */

(function(window) {
  'use strict';

  // ════════════════════════════════════════════════════════════════
  //  normalizeDetections — client-side type-safe coercion to Array
  //
  //  Fixes: TypeError: (r.detections || []) is not iterable
  //
  //  The /api/raykan/ingest endpoint may return detections as:
  //    • Array<Object>  — correct (new backend)
  //    • { count, items, ... } — old nested shape
  //    • null / undefined     — no results
  //    • JSON string          — edge case
  //
  //  This function guarantees the caller always gets an iterable
  //  array of plain objects regardless of the server shape.
  // ════════════════════════════════════════════════════════════════
  function normalizeDetections(input) {
    if (input == null) return [];
    if (Array.isArray(input)) return input;

    // Old nested shape: { count, items, critical, high, medium }
    if (typeof input === 'object') {
      if (Array.isArray(input.items)) return input.items;
      if (Array.isArray(input.detections)) return input.detections;
      // Generic object → values
      const vals = Object.values(input);
      if (vals.length > 0 && typeof vals[0] === 'object') return vals;
      return [];
    }

    if (typeof input === 'string') {
      try {
        const parsed = JSON.parse(input);
        return normalizeDetections(parsed);
      } catch { return []; }
    }

    return [];
  }

  // ════════════════════════════════════════════════════════════════
  //  Client-side multi-format log parsers
  //  Used by ingestPasted() before sending to the backend so that
  //  Syslog / CEF lines become structured JSON events.
  // ════════════════════════════════════════════════════════════════

  /** Parse a single RFC 3164 / RFC 5424 syslog line → event object */
  function _parseSyslogLine(line) {
    if (!line) return { raw: line, _format: 'syslog_bare' };
    // RFC 5424: <PRI>VERSION TS HOST APP PROCID MSGID SD MSG
    const r5 = line.match(/^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)\s*(.*)$/);
    if (r5) {
      const pri = parseInt(r5[1], 10);
      return { _format:'syslog_rfc5424', priority:pri, facility:Math.floor(pri/8),
               severity_num:pri%8, timestamp:r5[3], hostname:r5[4]!=='-'?r5[4]:null,
               app_name:r5[5]!=='-'?r5[5]:null, message:r5[9]||'', raw:line };
    }
    // RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    const r3 = line.match(/^<(\d+)>([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)$/);
    if (r3) {
      const pri = parseInt(r3[1], 10);
      return { _format:'syslog_rfc3164', priority:pri, facility:Math.floor(pri/8),
               severity_num:pri%8, timestamp:r3[2], hostname:r3[3], tag:r3[4],
               message:r3[5]||'', raw:line };
    }
    return { _format:'syslog_bare', message:line, raw:line };
  }

  /** Parse a single CEF line → event object */
  function _parseCEFLine(line) {
    if (!line || !line.startsWith('CEF:')) return null;
    let pipes=0, headerEnd=-1;
    for (let i=0;i<line.length;i++) {
      if (line[i]==='|' && (i===0||line[i-1]!=='\\')) pipes++;
      if (pipes===7) { headerEnd=i; break; }
    }
    const headerStr = headerEnd>0 ? line.slice(0,headerEnd) : line;
    const extStr    = headerEnd>0 ? line.slice(headerEnd+1) : '';
    const parts     = headerStr.split(/(?<!\\)\|/);
    const ext = {};
    const pairs = extStr.match(/(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)/g) || [];
    for (const p of pairs) {
      const eq=p.indexOf('=');
      if (eq>0) ext[p.slice(0,eq).trim()] = p.slice(eq+1).replace(/\\=/g,'=').trim();
    }
    return { _format:'cef', cef_version:(parts[0]||'CEF:0').replace('CEF:',''),
             device_vendor:parts[1]||'', device_product:parts[2]||'',
             signature_id:parts[4]||'', name:parts[5]||'', severity:parts[6]||'',
             extensions:ext, src:ext.src||null, dst:ext.dst||null,
             user:ext.suser||ext.duser||null, message:ext.msg||null, raw:line };
  }

  /**
   * _parseLogInput — converts raw pasted text to a JSON events array.
   * Dispatches by format hint: json | syslog | cef | auto
   */
  function _parseLogInput(raw, fmt) {
    if (!raw) return [];
    const trimmed = raw.trim();

    // JSON mode (or auto — try JSON first)
    if (fmt !== 'syslog' && fmt !== 'cef') {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed))         return parsed;
        if (parsed && typeof parsed==='object') return [parsed];
      } catch { /* fall through to line-by-line */ }
    }

    // Line-by-line parsing
    return trimmed.split(/\r?\n/)
      .map(l => l.trim()).filter(Boolean)
      .map(line => {
        if (fmt==='cef'    || line.startsWith('CEF:')) return _parseCEFLine(line) || { raw:line, _format:'cef_malformed' };
        if (fmt==='syslog' || line.startsWith('<'))    return _parseSyslogLine(line);
        // Auto: try JSON, then syslog
        try { const p=JSON.parse(line); return { ...p, _format:'json', raw:line }; } catch {}
        return _parseSyslogLine(line);
      });
  }

  // ── Constants ──────────────────────────────────────────────────
  const RAYKAN_VERSION = '2.0.0';
  const API_BASE       = window.BACKEND_URL?.() || 'https://wadjet-eye-ai.onrender.com';
  const WS_BASE        = API_BASE.replace(/^http/, 'ws');

  // Severity styling
  const SEV = {
    critical     : { color:'#ef4444', bg:'rgba(239,68,68,0.12)',   badge:'#dc2626', icon:'🔴', label:'CRITICAL' },
    high         : { color:'#f97316', bg:'rgba(249,115,22,0.12)',  badge:'#ea580c', icon:'🟠', label:'HIGH'     },
    medium       : { color:'#eab308', bg:'rgba(234,179,8,0.12)',   badge:'#ca8a04', icon:'🟡', label:'MEDIUM'   },
    low          : { color:'#22c55e', bg:'rgba(34,197,94,0.12)',   badge:'#16a34a', icon:'🟢', label:'LOW'      },
    informational: { color:'#6b7280', bg:'rgba(107,114,128,0.12)', badge:'#4b5563', icon:'⚪', label:'INFO'     },
  };

  // MITRE tactic color map
  const TACTIC_COLOR = {
    'initial-access'      : '#ef4444',
    'execution'           : '#f97316',
    'persistence'         : '#eab308',
    'privilege-escalation': '#a78bfa',
    'defense-evasion'     : '#60a5fa',
    'credential-access'   : '#34d399',
    'discovery'           : '#fb923c',
    'lateral-movement'    : '#f472b6',
    'collection'          : '#38bdf8',
    'command-and-control' : '#4ade80',
    'exfiltration'        : '#c084fc',
    'impact'              : '#f87171',
  };

  // ── State ───────────────────────────────────────────────────────
  const S = {
    detections   : [],
    timeline     : [],
    chains       : [],
    anomalies    : [],
    huntResults  : null,
    stats        : null,
    activeTab    : 'overview',
    wsConnected  : false,
    analyzing    : false,
    hunting      : false,
    sessionId    : null,
    riskScore    : 0,
    lastUpdated  : null,
    huntMode     : 'rql',    // 'rql' | 'nl'
    investigateEntity: null,
    uploadedEvents: [],
  };

  // ── WebSocket ─────────────────────────────────────────────────
  let _ws = null, _wsRetries = 0;

  function _connectWS() {
    if (_ws?.readyState === WebSocket.OPEN) return;
    try {
      _ws = new WebSocket(`${WS_BASE}/socket.io/?transport=websocket`);
      _ws.onopen  = () => { S.wsConnected = true;  _wsRetries = 0; _updateWSBadge(); };
      _ws.onclose = () => {
        S.wsConnected = false; _updateWSBadge();
        if (_wsRetries < 5) setTimeout(() => { _wsRetries++; _connectWS(); }, 3000 * (_wsRetries + 1));
      };
      _ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'raykan:detection') _onRealtimeDetection(msg.payload);
          if (msg.type === 'raykan:anomaly')   _onRealtimeAnomaly(msg.payload);
          if (msg.type === 'raykan:chain')     _onRealtimeChain(msg.payload);
        } catch {}
      };
    } catch {}
  }

  // ── API ────────────────────────────────────────────────────────
  async function _api(method, path, body) {
    const token = window.UnifiedTokenStore?.getToken() || window.TokenStore?.getToken() || '';
    const opts  = { method, headers: { 'Content-Type':'application/json', Authorization:`Bearer ${token}` } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(`${API_BASE}/api/raykan${path}`, opts);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `API ${r.status}`);
    return d;
  }

  // ════════════════════════════════════════════════════════════════
  //  ENTRY POINT
  // ════════════════════════════════════════════════════════════════
  async function render(container) {
    container = container || document.getElementById('raykanWrap');
    if (!container) return;
    container.innerHTML = _buildUI();
    _attachEvents();
    _setTab('overview');
    await _loadStats();
    _connectWS();
  }

  // ════════════════════════════════════════════════════════════════
  //  UI BUILDER
  // ════════════════════════════════════════════════════════════════
  function _buildUI() {
    return `
<style>
  .rk-root { display:flex; flex-direction:column; height:100%; min-height:600px;
    background:#0d1117; color:#e6edf3; font-family:'Inter',system-ui,sans-serif; }
  .rk-hdr  { display:flex; align-items:center; gap:12px; padding:12px 20px;
    background:#161b22; border-bottom:1px solid #21262d; flex-shrink:0; }
  .rk-stats-row { display:grid; grid-template-columns:repeat(6,1fr); gap:1px;
    background:#21262d; border-bottom:1px solid #21262d; flex-shrink:0; }
  .rk-stat { padding:12px 16px; background:#0d1117; }
  .rk-stat-val { font-size:22px; font-weight:700; }
  .rk-stat-lbl { font-size:10px; color:#6b7280; margin-top:2px; text-transform:uppercase; letter-spacing:.5px; }
  .rk-tabs { display:flex; background:#161b22; border-bottom:1px solid #21262d;
    flex-shrink:0; overflow-x:auto; scrollbar-width:none; }
  .rk-tabs::-webkit-scrollbar { display:none; }
  .rk-tab  { padding:10px 16px; font-size:12px; font-weight:500; cursor:pointer;
    background:none; color:#8b949e; border:none; border-bottom:2px solid transparent;
    white-space:nowrap; transition:.15s all; }
  .rk-tab:hover { color:#e6edf3; }
  .rk-tab.active { color:#60a5fa; border-bottom-color:#60a5fa; }
  .rk-body { flex:1; overflow:auto; }
  .rk-panel { padding:20px; }
  .rk-card  { background:#161b22; border:1px solid #21262d; border-radius:10px; }
  .rk-card-hdr { padding:14px 18px; border-bottom:1px solid #21262d; display:flex;
    align-items:center; justify-content:space-between; }
  .rk-btn  { padding:7px 16px; border-radius:6px; font-size:12px; font-weight:600;
    cursor:pointer; border:none; transition:.15s; }
  .rk-btn-primary { background:linear-gradient(135deg,#1d4ed8,#2563eb); color:#fff; }
  .rk-btn-primary:hover { opacity:.85; }
  .rk-btn-red   { background:linear-gradient(135deg,#dc2626,#b91c1c); color:#fff; }
  .rk-btn-red:hover   { opacity:.85; }
  .rk-btn-purple { background:linear-gradient(135deg,#7c3aed,#6d28d9); color:#fff; }
  .rk-btn-purple:hover { opacity:.85; }
  .rk-btn-ghost { background:#21262d; color:#8b949e; border:1px solid #30363d; }
  .rk-btn-ghost:hover { color:#e6edf3; }
  .rk-input { background:#0d1117; border:1px solid #30363d; border-radius:7px;
    padding:9px 14px; color:#e6edf3; font-size:13px; outline:none; width:100%; box-sizing:border-box; }
  .rk-input:focus { border-color:#388bfd; }
  .rk-badge { display:inline-flex; align-items:center; padding:2px 8px;
    border-radius:10px; font-size:10px; font-weight:700; text-transform:uppercase; }
  .rk-det-row { display:flex; align-items:flex-start; gap:12px; padding:12px 16px;
    border-bottom:1px solid #21262d; cursor:pointer; transition:.15s; }
  .rk-det-row:hover { background:#161b22; }
  .rk-det-row:last-child { border-bottom:none; }
  .rk-chip { padding:3px 10px; border-radius:12px; font-size:11px; cursor:pointer;
    background:#21262d; color:#8b949e; border:1px solid #30363d; white-space:nowrap; }
  .rk-chip:hover { color:#60a5fa; border-color:#60a5fa; }
  .rk-timeline-item { display:flex; gap:16px; padding:10px 16px; border-left:2px solid #21262d; margin-left:20px; }
  .rk-tl-dot { width:10px; height:10px; border-radius:50%; margin-top:4px; flex-shrink:0; margin-left:-21px; }
  .rk-grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .rk-grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }
  .rk-spinner { width:32px; height:32px; border-radius:50%;
    border:3px solid #21262d; border-top-color:#60a5fa;
    animation:rk-spin 1s linear infinite; margin:0 auto; }
  @keyframes rk-spin { to { transform:rotate(360deg); } }
  .rk-code  { font-family:'JetBrains Mono','Fira Code',monospace; font-size:11px; }
  .rk-tag   { display:inline-block; padding:2px 7px; border-radius:4px;
    font-size:10px; background:#21262d; color:#8b949e; margin:2px 1px; }
  .rk-entity-btn { padding:4px 10px; border-radius:6px; font-size:11px; cursor:pointer;
    background:#21262d; color:#60a5fa; border:1px solid #30363d; }
  .rk-entity-btn:hover { background:#30363d; }
  .rk-chain-stage { display:flex; align-items:center; gap:0; }
  .rk-chain-step  { padding:8px 14px; border-radius:6px; font-size:11px; font-weight:600;
    background:#161b22; border:1px solid #30363d; color:#e6edf3; white-space:nowrap; }
  .rk-chain-arrow { color:#4b5563; font-size:16px; padding:0 4px; }
  .rk-mitre-cell  { padding:6px 4px; border-radius:4px; font-size:9px; font-weight:700;
    text-align:center; cursor:pointer; transition:.15s; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rk-upload-zone { border:2px dashed #30363d; border-radius:10px; padding:40px;
    text-align:center; cursor:pointer; transition:.2s; }
  .rk-upload-zone:hover, .rk-upload-zone.drag-over { border-color:#60a5fa; background:rgba(96,165,250,0.05); }
  .rk-progress { height:4px; border-radius:2px; background:#21262d; overflow:hidden; }
  .rk-progress-bar { height:100%; border-radius:2px; background:linear-gradient(90deg,#60a5fa,#a78bfa);
    transition:width .3s ease; }
  .rk-select { background:#21262d; color:#e6edf3; border:1px solid #30363d; border-radius:6px;
    padding:6px 10px; font-size:12px; outline:none; cursor:pointer; }
  .rk-table  { width:100%; border-collapse:collapse; font-size:12px; }
  .rk-table th { padding:8px 12px; background:#21262d; color:#8b949e;
    text-align:left; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.3px; }
  .rk-table td { padding:8px 12px; border-bottom:1px solid #21262d; }
  .rk-table tr:last-child td { border-bottom:none; }
  .rk-table tr:hover td { background:rgba(255,255,255,0.02); }
  .rk-modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.75); z-index:5000;
    display:flex; align-items:center; justify-content:center; }
  .rk-modal { background:#161b22; border:1px solid #30363d; border-radius:12px;
    max-width:800px; width:90%; max-height:80vh; overflow:hidden; display:flex; flex-direction:column; }
  .rk-risk-ring { position:relative; display:inline-block; }
  @keyframes rk-pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .rk-live-dot { width:8px; height:8px; border-radius:50%; display:inline-block;
    background:#34d399; animation:rk-pulse 2s ease-in-out infinite; }
</style>

<div class="rk-root" id="rk-root">

  <!-- ═══ HEADER ═══ -->
  <div class="rk-hdr">
    <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;">
      <div style="width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,#ef4444,#b91c1c);
        display:flex;align-items:center;justify-content:center;font-size:18px;
        box-shadow:0 0 16px rgba(239,68,68,.35);">🎯</div>
      <div>
        <div style="font-size:15px;font-weight:800;letter-spacing:.6px;">RAYKAN</div>
        <div style="font-size:9px;color:#6b7280;letter-spacing:.4px;">AI THREAT HUNTING &amp; DFIR ENGINE v${RAYKAN_VERSION}</div>
      </div>
    </div>

    <!-- WS badge -->
    <div id="rk-ws-badge" style="display:flex;align-items:center;gap:6px;padding:4px 12px;
      border-radius:20px;font-size:11px;background:#161b22;border:1px solid #21262d;color:#6b7280;margin-left:12px;">
      <span id="rk-ws-dot" style="width:7px;height:7px;border-radius:50%;background:#374151;"></span>
      <span id="rk-ws-lbl">Offline</span>
    </div>

    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <!-- Risk badge -->
      <div id="rk-risk-badge" style="padding:5px 14px;border-radius:20px;font-size:12px;font-weight:700;
        background:rgba(107,114,128,.15);color:#9ca3af;border:1px solid #374151;">
        Risk Score: —
      </div>
      <!-- Session -->
      <div style="font-size:10px;color:#4b5563;">Session: <span id="rk-session-id" style="color:#6b7280;">—</span></div>
      <!-- Actions -->
      <button class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI.exportResults()" title="Export results">
        ↓ Export
      </button>
      <button class="rk-btn rk-btn-red" onclick="RAYKAN_UI.runSample('ransomware')">
        ▶ Run Demo
      </button>
    </div>
  </div>

  <!-- ═══ STATS ROW ═══ -->
  <div class="rk-stats-row">
    ${_statCard('Events',      '0',  '#60a5fa', 'rk-s-events')}
    ${_statCard('Detections',  '0',  '#ef4444', 'rk-s-dets')}
    ${_statCard('Anomalies',   '0',  '#f59e0b', 'rk-s-anom')}
    ${_statCard('Chains',      '0',  '#a78bfa', 'rk-s-chains')}
    ${_statCard('Rules',       '0',  '#34d399', 'rk-s-rules')}
    ${_statCard('Risk Score',  '—',  '#ef4444', 'rk-s-risk')}
  </div>

  <!-- ═══ TABS ═══ -->
  <div class="rk-tabs" id="rk-tab-bar">
    ${_tabBtn('overview',    '📊',  'Overview')}
    ${_tabBtn('hunt',        '🔍',  'Threat Hunt')}
    ${_tabBtn('ingest',      '📥',  'Log Ingest')}
    ${_tabBtn('timeline',    '⏱',  'Timeline')}
    ${_tabBtn('detections',  '🚨',  'Detections')}
    ${_tabBtn('chains',      '🔗',  'Attack Chains')}
    ${_tabBtn('investigate', '🕵️',  'Investigate')}
    ${_tabBtn('ioc',         '🔎',  'IOC Lookup')}
    ${_tabBtn('anomalies',   '📈',  'UEBA / Anomalies')}
    ${_tabBtn('rules',       '📋',  'Rules')}
    ${_tabBtn('mitre',       '🗺',  'MITRE')}
    ${_tabBtn('rulegen',     '✨',  'AI Rule Gen')}
  </div>

  <!-- ═══ BODY ═══ -->
  <div class="rk-body" id="rk-body"></div>

  <!-- Toast container -->
  <div id="rk-toast-root" style="position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;"></div>

</div>`;
  }

  // ── Helpers ────────────────────────────────────────────────────
  function _statCard(label, val, color, id) {
    return `<div class="rk-stat">
  <div class="rk-stat-val" id="${id}" style="color:${color};">${val}</div>
  <div class="rk-stat-lbl">${label}</div>
</div>`;
  }

  function _tabBtn(id, icon, label) {
    return `<button class="rk-tab" data-tab="${id}" onclick="RAYKAN_UI._setTab('${id}')">${icon} ${label}</button>`;
  }

  function _sev(s) { return SEV[s] || SEV.informational; }

  function _sevBadge(s) {
    const c = _sev(s);
    return `<span class="rk-badge" style="background:${c.bg};color:${c.color};">${c.icon} ${c.label}</span>`;
  }

  function _fmt(ts) {
    if (!ts) return '—';
    const d = ts instanceof Date ? ts : new Date(ts);
    return d.toLocaleString();
  }

  function _fmtTime(ts) {
    if (!ts) return '—';
    const d = ts instanceof Date ? ts : new Date(ts);
    return d.toLocaleTimeString();
  }

  function _truncate(s, n=80) {
    if (!s) return '—';
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  // ════════════════════════════════════════════════════════════════
  //  TAB ROUTING
  // ════════════════════════════════════════════════════════════════
  function _setTab(id) {
    S.activeTab = id;
    document.querySelectorAll('.rk-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    const body = document.getElementById('rk-body');
    if (!body) return;
    body.innerHTML = '<div class="rk-panel">' + _renderTab(id) + '</div>';
    _afterTabRender(id);
  }

  function _renderTab(id) {
    switch (id) {
      case 'overview':    return _tplOverview();
      case 'hunt':        return _tplHunt();
      case 'ingest':      return _tplIngest();
      case 'timeline':    return _tplTimeline();
      case 'detections':  return _tplDetections();
      case 'chains':      return _tplChains();
      case 'investigate': return _tplInvestigate();
      case 'ioc':         return _tplIOC();
      case 'anomalies':   return _tplAnomalies();
      case 'rules':       return _tplRules();
      case 'mitre':       return _tplMITRE();
      case 'rulegen':     return _tplRuleGen();
      default:            return '<div style="color:#6b7280;padding:60px;text-align:center;">Unknown tab</div>';
    }
  }

  function _afterTabRender(id) {
    if (id === 'overview')    { _renderOverviewContent(); }
    if (id === 'detections')  { _renderDetectionsList(S.detections); }
    if (id === 'chains')      { _renderChainsList(S.chains); }
    if (id === 'timeline')    { _renderTimelineList(S.timeline); }
    if (id === 'anomalies')   { _renderAnomaliesList(S.anomalies); }
    if (id === 'rules')       { _loadRules(); }
    if (id === 'mitre')       { _loadMITRE(); }
    if (id === 'investigate' && S.investigateEntity) { _runInvestigation(S.investigateEntity); }
    if (id === 'ingest')      { _initUploadZone(); }
    if (id === 'hunt')        { _setHuntMode(S.huntMode); }
  }

  // ════════════════════════════════════════════════════════════════
  //  OVERVIEW TAB
  // ════════════════════════════════════════════════════════════════
  function _tplOverview() {
    return `
<div>
  <!-- Engine status bar -->
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
    <div style="font-size:13px;color:#8b949e;">
      Engine ready · Last updated: <span id="rk-last-upd" style="color:#60a5fa;">—</span>
    </div>
    <div id="rk-engine-health" style="display:flex;gap:8px;flex-wrap:wrap;"></div>
    <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="rk-btn rk-btn-red"    onclick="RAYKAN_UI.runSample('ransomware')">🎯 Ransomware Demo</button>
      <button class="rk-btn rk-btn-purple" onclick="RAYKAN_UI.runSample('lateral_movement')">↔️ Lateral Movement</button>
      <button class="rk-btn rk-btn-ghost"  onclick="RAYKAN_UI.runSample('credential_dump')">🔑 Credential Dump</button>
    </div>
  </div>

  <!-- Risk ring + recent detections -->
  <div class="rk-grid-2" style="margin-bottom:16px;">
    <!-- Risk gauge -->
    <div class="rk-card" style="padding:20px;">
      <div style="font-size:12px;font-weight:700;color:#8b949e;margin-bottom:16px;text-transform:uppercase;letter-spacing:.5px;">
        🛡 Session Risk Score
      </div>
      <div id="rk-risk-gauge" style="display:flex;align-items:center;gap:20px;">
        <div style="position:relative;width:100px;height:100px;flex-shrink:0;">
          <svg width="100" height="100" viewBox="0 0 100 100" style="transform:rotate(-90deg)">
            <circle cx="50" cy="50" r="42" fill="none" stroke="#21262d" stroke-width="10"/>
            <circle id="rk-risk-arc" cx="50" cy="50" r="42" fill="none" stroke="#ef4444"
              stroke-width="10" stroke-dasharray="264" stroke-dashoffset="264"
              stroke-linecap="round" style="transition:stroke-dashoffset 1s ease;"/>
          </svg>
          <div id="rk-risk-num" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
            font-size:22px;font-weight:800;color:#e6edf3;">0</div>
        </div>
        <div>
          <div id="rk-risk-label" style="font-size:18px;font-weight:700;color:#22c55e;">Clean</div>
          <div style="font-size:12px;color:#6b7280;margin-top:4px;">Based on ${S.detections.length} detections</div>
          <div style="font-size:11px;color:#4b5563;margin-top:8px;">
            Session: <span id="rk-ov-session" style="color:#6b7280;">—</span>
          </div>
        </div>
      </div>
      <!-- Progress bars by severity -->
      <div id="rk-sev-bars" style="margin-top:16px;display:flex;flex-direction:column;gap:6px;"></div>
    </div>

    <!-- Recent detections -->
    <div class="rk-card">
      <div class="rk-card-hdr">
        <span style="font-size:13px;font-weight:600;">🚨 Recent Detections</span>
        <span id="rk-ov-det-count" style="font-size:11px;color:#6b7280;">0 total</span>
      </div>
      <div id="rk-ov-dets" style="max-height:260px;overflow-y:auto;">
        <div style="padding:40px;text-align:center;color:#4b5563;font-size:13px;">
          No detections yet — run a demo or ingest logs.
        </div>
      </div>
    </div>
  </div>

  <!-- Sub-engine status grid -->
  <div class="rk-grid-3" style="margin-bottom:16px;" id="rk-engine-cards">
    ${_engineCard('⚙️ Sigma Engine',   'rk-sigma-rules',  '#34d399', 'Rules loaded')}
    ${_engineCard('🤖 AI Detector',    'rk-ai-prov',      '#60a5fa', 'Provider')}
    ${_engineCard('👥 UEBA Engine',    'rk-ueba-prof',    '#f59e0b', 'Profiles')}
    ${_engineCard('🔗 Attack Chains',  'rk-chains-cnt',   '#a78bfa', 'Reconstructed')}
    ${_engineCard('⏱ Uptime',         'rk-uptime-val',   '#e2e8f0', 'Seconds')}
    ${_engineCard('📥 Buffer',         'rk-buffer-val',   '#6b7280', 'Events in memory')}
  </div>

  <!-- Attack chain preview -->
  <div class="rk-card">
    <div class="rk-card-hdr">
      <span style="font-size:13px;font-weight:600;">🔗 Attack Chain Preview</span>
      <button class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._setTab('chains')" style="font-size:11px;">View All →</button>
    </div>
    <div id="rk-ov-chains" style="padding:16px;min-height:60px;">
      <div style="color:#4b5563;font-size:13px;text-align:center;padding:20px;">
        No attack chains detected.
      </div>
    </div>
  </div>
</div>`;
  }

  function _engineCard(label, id, color, sub) {
    return `<div class="rk-card" style="padding:16px;">
  <div style="font-size:11px;font-weight:700;color:${color};margin-bottom:8px;text-transform:uppercase;letter-spacing:.4px;">${label}</div>
  <div class="rk-stat-val" id="${id}" style="font-size:22px;color:#e6edf3;">—</div>
  <div class="rk-stat-lbl">${sub}</div>
</div>`;
  }

  function _renderOverviewContent() {
    // Detections list
    const ovDets = document.getElementById('rk-ov-dets');
    if (ovDets && S.detections.length) {
      ovDets.innerHTML = S.detections.slice(0, 8).map(d => `
<div class="rk-det-row" onclick="RAYKAN_UI._showDetDetail('${d.id || ''}')">
  <div style="flex-shrink:0;margin-top:2px;">${_sev(d.severity).icon}</div>
  <div style="flex:1;min-width:0;">
    <div style="font-size:12px;font-weight:600;color:#e6edf3;">${d.ruleName || d.title || 'Detection'}</div>
    <div style="font-size:11px;color:#6b7280;margin-top:2px;">${d.computer||d.host||''} · ${_fmtTime(d.timestamp)}</div>
    <div style="font-size:10px;color:#4b5563;margin-top:2px;">${d.mitre?.technique || ''}</div>
  </div>
  ${_sevBadge(d.severity)}
</div>`).join('');
      document.getElementById('rk-ov-det-count').textContent = S.detections.length + ' total';
    }

    // Risk gauge
    const risk = S.riskScore || 0;
    const arc  = document.getElementById('rk-risk-arc');
    if (arc) {
      const offset = 264 - (264 * risk / 100);
      arc.style.strokeDashoffset = offset;
      arc.style.stroke = risk >= 80 ? '#ef4444' : risk >= 60 ? '#f97316' : risk >= 40 ? '#eab308' : '#22c55e';
    }
    const num = document.getElementById('rk-risk-num');
    if (num) num.textContent = risk;
    const lbl = document.getElementById('rk-risk-label');
    if (lbl) {
      lbl.textContent = risk >= 80 ? 'Critical' : risk >= 60 ? 'High' : risk >= 40 ? 'Medium' : risk > 0 ? 'Low' : 'Clean';
      lbl.style.color = risk >= 80 ? '#ef4444' : risk >= 60 ? '#f97316' : risk >= 40 ? '#eab308' : '#22c55e';
    }

    // Severity bars
    const bars = document.getElementById('rk-sev-bars');
    if (bars) {
      const counts = { critical:0, high:0, medium:0, low:0 };
      S.detections.forEach(d => { if (counts[d.severity] !== undefined) counts[d.severity]++; });
      const total = S.detections.length || 1;
      bars.innerHTML = Object.entries(counts).map(([sev, cnt]) => `
<div style="display:flex;align-items:center;gap:8px;">
  <div style="width:55px;font-size:10px;color:${SEV[sev].color};text-transform:uppercase;font-weight:700;">${sev}</div>
  <div class="rk-progress" style="flex:1;height:6px;">
    <div class="rk-progress-bar" style="width:${(cnt/total*100).toFixed(0)}%;background:${SEV[sev].color};"></div>
  </div>
  <div style="width:24px;font-size:10px;color:#6b7280;text-align:right;">${cnt}</div>
</div>`).join('');
    }

    // Session
    const sess = document.getElementById('rk-ov-session');
    if (sess && S.sessionId) sess.textContent = S.sessionId.slice(0, 8) + '…';

    // Chains preview
    const chains = document.getElementById('rk-ov-chains');
    if (chains && S.chains.length) {
      chains.innerHTML = S.chains.slice(0, 2).map(c => _chainPreview(c)).join('');
    }
  }

  // ════════════════════════════════════════════════════════════════
  //  THREAT HUNT TAB
  // ════════════════════════════════════════════════════════════════
  function _tplHunt() {
    return `
<div>
  <div style="display:flex;gap:8px;margin-bottom:14px;">
    <button id="rk-h-rql" class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._setHuntMode('rql')"
      style="font-size:12px;">🔍 RQL Query</button>
    <button id="rk-h-nl"  class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._setHuntMode('nl')"
      style="font-size:12px;">💬 Natural Language</button>
    <div style="margin-left:auto;font-size:11px;color:#4b5563;align-self:center;">
      RQL: Sigma-like field:value syntax | NL: plain-English query
    </div>
  </div>

  <div class="rk-card" style="padding:16px;margin-bottom:16px;">
    <textarea id="rk-h-input" rows="4"
      placeholder='process.name:"powershell.exe" AND commandLine:*EncodedCommand*'
      class="rk-input rk-code" style="resize:vertical;min-height:80px;border-radius:6px;"></textarea>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;flex-wrap:wrap;gap:8px;">
      <div style="display:flex;gap:6px;flex-wrap:wrap;" id="rk-hunt-chips">
        ${_huntChips()}
      </div>
      <div style="display:flex;gap:8px;">
        <select class="rk-select" id="rk-h-time">
          <option value="1h">Last 1h</option>
          <option value="6h">Last 6h</option>
          <option value="24h" selected>Last 24h</option>
          <option value="7d">Last 7d</option>
          <option value="all">All Time</option>
        </select>
        <button id="rk-h-btn" class="rk-btn rk-btn-primary" onclick="RAYKAN_UI.executeHunt()" style="min-width:90px;">
          Hunt ▶
        </button>
      </div>
    </div>
  </div>

  <!-- Saved hunts -->
  <div style="margin-bottom:16px;">
    <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px;">
      Saved Hunt Queries
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;" id="rk-saved-hunts">
      ${_savedHunts()}
    </div>
  </div>

  <!-- Results -->
  <div id="rk-h-results">
    <div style="padding:50px;text-align:center;color:#4b5563;font-size:13px;">
      Enter a query and click Hunt ▶ to search event history.
    </div>
  </div>
</div>`;
  }

  function _huntChips() {
    const chips = [
      ['PS Encoded',    'process.name:"powershell.exe" AND commandLine:*EncodedCommand*'],
      ['Mimikatz',      'commandLine:*sekurlsa* OR commandLine:*lsadump*'],
      ['VSS Delete',    'commandLine:*vssadmin*delete*'],
      ['PsExec',        'process.name:"psexec.exe"'],
      ['LSASS Dump',    'commandLine:*lsass*'],
      ['RDP Brute',     'event.id:4625 AND dstPort:3389'],
      ['Scheduled Task','commandLine:*schtasks* AND commandLine:*/create*'],
      ['WMI Exec',      'process.name:"wmiprvse.exe"'],
    ];
    return chips.map(([l,q]) =>
      `<button class="rk-chip" onclick="document.getElementById('rk-h-input').value=decodeURIComponent('${encodeURIComponent(q)}')">${l}</button>`
    ).join('');
  }

  function _savedHunts() {
    const saved = [
      ['🕸 Cobalt Strike Beacons', 'dstPort:443 AND process.name:*round* OR commandLine:*beacon*'],
      ['📡 DNS Tunneling',         'domain:*.*.*.* AND queryType:TXT'],
      ['🔑 Pass-the-Hash',         'event.id:4624 AND logonType:3 AND user:*$*'],
      ['🧬 BITS Job Abuse',        'commandLine:*bitsadmin*transfer*'],
    ];
    return saved.map(([l,q]) =>
      `<button class="rk-chip" style="padding:4px 12px;font-size:11px;" onclick="document.getElementById('rk-h-input').value=decodeURIComponent('${encodeURIComponent(q)}');RAYKAN_UI._setHuntMode('rql')">${l}</button>`
    ).join('');
  }

  // ════════════════════════════════════════════════════════════════
  //  LOG INGEST TAB
  // ════════════════════════════════════════════════════════════════
  function _tplIngest() {
    return `
<div>
  <div class="rk-grid-2" style="margin-bottom:16px;">
    <!-- Upload -->
    <div class="rk-card" style="padding:20px;">
      <div style="font-size:13px;font-weight:600;margin-bottom:14px;">📁 Upload Log File</div>
      <div class="rk-upload-zone" id="rk-drop-zone" onclick="document.getElementById('rk-file-in').click()">
        <div style="font-size:32px;margin-bottom:8px;">📂</div>
        <div style="font-size:14px;font-weight:600;color:#e6edf3;">Drop logs here or click to browse</div>
        <div style="font-size:12px;color:#6b7280;margin-top:6px;">Supports: JSON, EVTX, Syslog, CEF, LEEF, CSV</div>
        <input type="file" id="rk-file-in" style="display:none" accept=".json,.log,.txt,.csv,.evtx"
          onchange="RAYKAN_UI._handleFileUpload(this.files[0])"/>
      </div>
      <div id="rk-upload-progress" style="display:none;margin-top:12px;">
        <div style="font-size:12px;color:#8b949e;margin-bottom:6px;" id="rk-upload-msg">Processing…</div>
        <div class="rk-progress">
          <div class="rk-progress-bar" id="rk-upload-bar" style="width:0%;"></div>
        </div>
      </div>
    </div>

    <!-- Paste JSON -->
    <div class="rk-card" style="padding:20px;">
      <div style="font-size:13px;font-weight:600;margin-bottom:14px;">📋 Paste JSON Events</div>
      <textarea id="rk-paste-events" rows="6"
        class="rk-input rk-code" style="resize:vertical;border-radius:6px;font-size:11px;"
        placeholder='[{"EventID":4688,"Computer":"ws01","User":"CORP\\\\jdoe","CommandLine":"cmd.exe /c whoami"}]'></textarea>
      <div style="display:flex;gap:8px;margin-top:10px;">
        <select class="rk-select" id="rk-paste-fmt">
          <option value="json">JSON</option>
          <option value="syslog">Syslog</option>
          <option value="cef">CEF</option>
        </select>
        <button class="rk-btn rk-btn-primary" onclick="RAYKAN_UI.ingestPasted()" style="flex:1;">
          📤 Analyze
        </button>
      </div>
    </div>
  </div>

  <!-- Quick sample scenarios -->
  <div class="rk-card" style="padding:16px;margin-bottom:16px;">
    <div style="font-size:12px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:12px;">
      Demo Attack Scenarios
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      ${_scenarioBtn('ransomware',        '🔴', 'Ransomware',        'LockerGoga / RansomHub simulation')}
      ${_scenarioBtn('lateral_movement',  '🟠', 'Lateral Movement',  'PsExec + WMI + SMB spread')}
      ${_scenarioBtn('credential_dump',   '🟡', 'Credential Dump',   'Mimikatz / LSASS dump')}
      ${_scenarioBtn('apt',               '🟣', 'APT Campaign',      'Multi-stage nation-state attack')}
      ${_scenarioBtn('insider',           '🔵', 'Insider Threat',    'Exfil via cloud storage')}
      ${_scenarioBtn('supply_chain',      '⚫', 'Supply Chain',      'Dependency hijack + backdoor')}
    </div>
  </div>

  <!-- Ingest results summary -->
  <div id="rk-ingest-result" style="min-height:60px;"></div>
</div>`;
  }

  function _scenarioBtn(id, icon, name, desc) {
    return `<button onclick="RAYKAN_UI.runSample('${id}')" style="
      padding:12px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;
      background:#161b22;border:1px solid #30363d;color:#e6edf3;text-align:left;
      transition:.15s;min-width:180px;">
      <div style="font-size:16px;margin-bottom:4px;">${icon} ${name}</div>
      <div style="font-size:10px;color:#6b7280;">${desc}</div>
    </button>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  TIMELINE TAB
  // ════════════════════════════════════════════════════════════════
  function _tplTimeline() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
    <div style="font-size:13px;color:#8b949e;">Chronological forensic timeline of events and detections.</div>
    <div style="display:flex;gap:8px;">
      <select class="rk-select" id="rk-tl-filter" onchange="RAYKAN_UI._filterTimeline()">
        <option value="">All Types</option>
        <option value="detection">Detections</option>
        <option value="process">Process Events</option>
        <option value="network">Network Events</option>
        <option value="file">File Events</option>
        <option value="registry">Registry Events</option>
      </select>
      <button class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._exportTimeline()">↓ Export CSV</button>
    </div>
  </div>
  <div id="rk-tl-container" class="rk-card" style="padding:16px;min-height:200px;">
    <div style="color:#4b5563;font-size:13px;text-align:center;padding:60px;">
      Run an analysis to populate the timeline.
    </div>
  </div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  DETECTIONS TAB
  // ════════════════════════════════════════════════════════════════
  function _tplDetections() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
    <div style="font-size:13px;color:#8b949e;">All triggered detections from the current session.</div>
    <div style="display:flex;gap:8px;align-items:center;">
      <input type="text" class="rk-input" id="rk-det-search" placeholder="Search detections…"
        oninput="RAYKAN_UI._searchDetections()" style="width:200px;padding:6px 12px;font-size:12px;"/>
      <select class="rk-select" id="rk-det-sev" onchange="RAYKAN_UI._filterDetections()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <button class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._exportDetections()">↓ Export</button>
    </div>
  </div>
  <div id="rk-det-list" class="rk-card" style="overflow:hidden;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  ATTACK CHAINS TAB
  // ════════════════════════════════════════════════════════════════
  function _tplChains() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:14px;">
    Multi-stage attack chain reconstruction. Each chain represents a connected sequence of adversary actions mapped to MITRE ATT&CK.
  </div>
  <div id="rk-chains-list" style="display:flex;flex-direction:column;gap:16px;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  INVESTIGATE TAB
  // ════════════════════════════════════════════════════════════════
  function _tplInvestigate() {
    return `
<div>
  <!-- Search bar -->
  <div class="rk-card" style="padding:16px;margin-bottom:16px;">
    <div style="font-size:13px;font-weight:600;margin-bottom:12px;">🕵️ Entity Investigation</div>
    <div style="display:flex;gap:10px;align-items:center;">
      <input id="rk-inv-entity" type="text" class="rk-input"
        placeholder="Entity to investigate: hostname, username, IP, hash, process…"
        style="flex:1;" onkeydown="if(event.key==='Enter')RAYKAN_UI.investigate()"/>
      <select class="rk-select" id="rk-inv-type">
        <option value="auto">Auto-detect</option>
        <option value="host">Host</option>
        <option value="user">User</option>
        <option value="ip">IP Address</option>
        <option value="hash">File Hash</option>
        <option value="process">Process</option>
      </select>
      <select class="rk-select" id="rk-inv-range">
        <option value="1h">1 hour</option>
        <option value="6h">6 hours</option>
        <option value="24h" selected>24 hours</option>
        <option value="7d">7 days</option>
      </select>
      <button class="rk-btn rk-btn-purple" onclick="RAYKAN_UI.investigate()">🔍 Investigate</button>
    </div>
    <!-- Quick entity links from detections -->
    <div id="rk-inv-quick" style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;"></div>
  </div>

  <!-- Investigation result -->
  <div id="rk-inv-result">
    <div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">
      Enter an entity name above to begin deep forensic investigation.
    </div>
  </div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  IOC LOOKUP TAB
  // ════════════════════════════════════════════════════════════════
  function _tplIOC() {
    return `
<div>
  <div class="rk-card" style="padding:20px;margin-bottom:16px;">
    <div style="font-size:13px;font-weight:600;margin-bottom:12px;">
      🔎 IOC Intelligence Lookup
    </div>
    <div style="display:flex;gap:10px;">
      <input id="rk-ioc-in" type="text" class="rk-input"
        placeholder="Enter IP, domain, MD5/SHA256, or URL…"
        onkeydown="if(event.key==='Enter')RAYKAN_UI.lookupIOC()" style="flex:1;"/>
      <button class="rk-btn rk-btn-purple" onclick="RAYKAN_UI.lookupIOC()" style="min-width:100px;">
        🔍 Lookup
      </button>
    </div>
    <div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap;">
      <span style="font-size:11px;color:#6b7280;align-self:center;">Examples:</span>
      ${['185.220.101.45','evil-c2.ru','d41d8cd98f00b204e9800998ecf8427e','http://malware.site/payload.exe'].map(v =>
        `<button class="rk-chip" onclick="document.getElementById('rk-ioc-in').value='${v}';RAYKAN_UI.lookupIOC()">${v}</button>`
      ).join('')}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;align-items:center;">
      <span style="font-size:11px;color:#6b7280;">Sources:</span>
      ${['VirusTotal','AbuseIPDB','OTX AlienVault','GreyNoise'].map(s =>
        `<span class="rk-tag">✓ ${s}</span>`).join('')}
    </div>
  </div>

  <!-- Batch lookup -->
  <div class="rk-card" style="padding:20px;margin-bottom:16px;">
    <div style="font-size:12px;font-weight:600;color:#8b949e;margin-bottom:10px;">
      📋 Batch IOC Lookup (one per line)
    </div>
    <textarea id="rk-ioc-batch" rows="4" class="rk-input rk-code"
      style="resize:vertical;border-radius:6px;" placeholder="185.220.101.45&#10;evil.domain.ru&#10;aabbcc..."></textarea>
    <button class="rk-btn rk-btn-ghost" style="margin-top:8px;" onclick="RAYKAN_UI.lookupIOCBatch()">
      Lookup All
    </button>
  </div>

  <!-- Result -->
  <div id="rk-ioc-result" style="min-height:100px;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  UEBA / ANOMALIES TAB
  // ════════════════════════════════════════════════════════════════
  function _tplAnomalies() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
    <div style="font-size:13px;color:#8b949e;">
      User &amp; Entity Behavioral Analytics — ML-detected deviations from baseline.
    </div>
    <span class="rk-badge" style="background:rgba(245,158,11,.12);color:#f59e0b;">
      ${S.anomalies.length} anomalies
    </span>
  </div>
  <div id="rk-anom-list" style="display:flex;flex-direction:column;gap:10px;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  RULES TAB
  // ════════════════════════════════════════════════════════════════
  function _tplRules() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
    <div style="font-size:13px;color:#8b949e;">
      Active Sigma detection rules — <span id="rk-rules-cnt" style="color:#34d399;">0</span> rules loaded.
    </div>
    <div style="display:flex;gap:8px;">
      <input type="text" class="rk-input" id="rk-rules-search" placeholder="Search rules…"
        oninput="RAYKAN_UI._searchRules()" style="width:200px;padding:6px 12px;font-size:12px;"/>
      <select class="rk-select" id="rk-rules-sev" onchange="RAYKAN_UI._loadRules()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <button class="rk-btn rk-btn-ghost" onclick="RAYKAN_UI._setTab('rulegen')">+ Generate Rule</button>
    </div>
  </div>
  <div id="rk-rules-list" class="rk-card" style="overflow:hidden;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  MITRE TAB
  // ════════════════════════════════════════════════════════════════
  function _tplMITRE() {
    return `
<div>
  <div style="font-size:13px;color:#8b949e;margin-bottom:14px;">
    MITRE ATT&CK v14 technique coverage — heatmap showing detected techniques from current session.
  </div>
  <div id="rk-mitre-heatmap" class="rk-card" style="padding:20px;min-height:200px;">
    <div style="display:flex;align-items:center;justify-content:center;padding:40px;flex-direction:column;gap:12px;">
      <div class="rk-spinner"></div>
      <div style="color:#8b949e;font-size:13px;">Loading MITRE coverage…</div>
    </div>
  </div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  AI RULE GEN TAB
  // ════════════════════════════════════════════════════════════════
  function _tplRuleGen() {
    return `
<div>
  <div class="rk-card" style="padding:20px;margin-bottom:16px;">
    <div style="font-size:13px;font-weight:600;margin-bottom:14px;">
      ✨ AI-Powered Sigma Rule Generator
    </div>
    <div style="font-size:12px;color:#8b949e;margin-bottom:10px;">
      Describe a threat or attack technique in natural language. RAYKAN's AI will generate a
      production-ready Sigma detection rule, automatically validate it, and add it to the engine.
    </div>
    <textarea id="rk-rg-input" rows="5" class="rk-input"
      style="resize:vertical;border-radius:6px;"
      placeholder="e.g. Detect when PowerShell downloads and executes a payload from a remote server using IEX and DownloadString, bypassing execution policy…"></textarea>

    <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;">
      <select class="rk-select" id="rk-rg-category">
        <option value="process">Process Creation</option>
        <option value="network">Network Connection</option>
        <option value="file">File Event</option>
        <option value="registry">Registry Event</option>
        <option value="auth">Authentication</option>
      </select>
      <select class="rk-select" id="rk-rg-severity">
        <option value="high">High</option>
        <option value="critical">Critical</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <button class="rk-btn rk-btn-purple" onclick="RAYKAN_UI.generateRule()" style="flex:1;max-width:200px;">
        ✨ Generate with AI
      </button>
    </div>

    <!-- Prompt examples -->
    <div style="margin-top:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px;">
        Example prompts:
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        ${[
          'Detect Cobalt Strike beacon using named pipe staging',
          'Find LSASS memory access via OpenProcess with PROCESS_VM_READ',
          'Detect WMI-based persistence via ActiveScriptEventConsumer',
          'Alert on suspicious certutil usage for payload download',
        ].map(p => `<button class="rk-chip" style="text-align:left;padding:6px 12px;"
          onclick="document.getElementById('rk-rg-input').value='${p}'">${p}</button>`).join('')}
      </div>
    </div>
  </div>

  <div id="rk-rg-result" style="min-height:100px;"></div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  ACTIONS
  // ════════════════════════════════════════════════════════════════

  async function runSample(scenario = 'ransomware') {
    S.analyzing = true;
    _showToast(`Running ${scenario} simulation…`, 'info');
    const btn = document.querySelector('.rk-btn-red');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Analyzing…'; }

    // Show progress in ingest result area if visible
    const ingestRes = document.getElementById('rk-ingest-result');
    if (ingestRes) {
      ingestRes.innerHTML = `<div style="padding:20px;text-align:center;">${_spinner('Running ' + scenario + ' scenario…')}</div>`;
    }

    try {
      const result = await _api('POST', '/analyze/sample', { scenario });
      // FIX: normalizeDetections — guard against any non-array shape
      S.detections  = normalizeDetections(result.detections);
      S.timeline    = normalizeDetections(result.timeline);
      S.chains      = normalizeDetections(result.chains);
      S.anomalies   = normalizeDetections(result.anomalies);
      S.riskScore   = result.riskScore   || 0;
      S.sessionId   = result.sessionId   || null;
      S.lastUpdated = new Date();

      _updateStats(result);
      _showToast(`✓ ${result.detections?.length||0} detections, ${result.chains?.length||0} chains, risk=${result.riskScore}`, 'success');

      // Navigate to detections
      _setTab('detections');

      if (ingestRes) {
        ingestRes.innerHTML = `<div class="rk-card" style="padding:16px;">
          <div style="color:#34d399;font-weight:700;margin-bottom:8px;">✓ ${scenario} simulation complete</div>
          <div style="font-size:12px;color:#8b949e;">${result.detections?.length||0} detections · ${result.timeline?.length||0} events · Risk: ${result.riskScore}</div>
        </div>`;
      }
    } catch(e) {
      _showToast('Analysis failed: ' + e.message, 'error');
      if (ingestRes) ingestRes.innerHTML = `<div style="color:#ef4444;padding:16px;">${e.message}</div>`;
    } finally {
      S.analyzing = false;
      if (btn) { btn.disabled = false; btn.textContent = '▶ Run Demo'; }
    }
  }

  async function executeHunt() {
    const input = document.getElementById('rk-h-input');
    const query = input?.value?.trim();
    if (!query) return _showToast('Enter a query first', 'warning');

    const mode    = S.huntMode;
    const timeR   = document.getElementById('rk-h-time')?.value || '24h';
    const btn     = document.getElementById('rk-h-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Hunting…'; }

    const resEl = document.getElementById('rk-h-results');
    if (resEl) resEl.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('Searching event history…')}</div>`;

    try {
      const endpoint = mode === 'nl' ? '/hunt/nl' : '/hunt';
      const result   = await _api('POST', endpoint, { query, timeRange: timeR, aiAssist: mode === 'nl' });
      S.huntResults  = result;
      _renderHuntResults(result);
      _showToast(`Hunt: ${result.count} matches in ${result.duration}ms`, result.count > 0 ? 'success' : 'info');
    } catch(e) {
      if (resEl) resEl.innerHTML = `<div style="color:#ef4444;padding:20px;text-align:center;">${e.message}</div>`;
      _showToast('Hunt failed: ' + e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Hunt ▶'; }
    }
  }

  async function lookupIOC() {
    const val = document.getElementById('rk-ioc-in')?.value?.trim();
    if (!val) return _showToast('Enter an IOC value', 'warning');
    const res = document.getElementById('rk-ioc-result');
    if (res) res.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('Querying threat intel…')}</div>`;
    try {
      const r = await _api('GET', `/ioc/${encodeURIComponent(val)}`);
      _renderIOCResult(r.ioc || r, res);
    } catch(e) {
      if (res) res.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  async function lookupIOCBatch() {
    const raw = document.getElementById('rk-ioc-batch')?.value?.trim();
    if (!raw) return _showToast('Enter IOCs (one per line)', 'warning');
    const iocs = raw.split('\n').map(l => l.trim()).filter(Boolean);
    const res  = document.getElementById('rk-ioc-result');
    if (res) res.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('Batch lookup…')}</div>`;
    try {
      const r = await _api('POST', '/ioc/batch', { iocs });
      _renderBatchIOC(r.results || [], res);
    } catch(e) {
      if (res) res.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  async function investigate() {
    const entity = document.getElementById('rk-inv-entity')?.value?.trim();
    if (!entity) return _showToast('Enter an entity to investigate', 'warning');
    S.investigateEntity = entity;
    _runInvestigation(entity);
  }

  async function _runInvestigation(entity) {
    const type  = document.getElementById('rk-inv-type')?.value  || 'auto';
    const range = document.getElementById('rk-inv-range')?.value || '24h';
    const res   = document.getElementById('rk-inv-result');
    if (!res) return;
    res.innerHTML = `<div style="padding:60px;text-align:center;">${_spinner('Investigating entity: ' + entity + '…')}</div>`;
    try {
      const r = await _api('POST', '/investigate', { entityId: entity, type, timeRange: range });
      _renderInvestigationResult(r, res);
    } catch(e) {
      res.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  async function generateRule() {
    const desc = document.getElementById('rk-rg-input')?.value?.trim();
    if (!desc) return _showToast('Describe the threat first', 'warning');
    const sev  = document.getElementById('rk-rg-severity')?.value || 'high';
    const cat  = document.getElementById('rk-rg-category')?.value || 'process';
    const res  = document.getElementById('rk-rg-result');
    if (res) res.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('AI is generating Sigma rule…')}</div>`;
    try {
      const r = await _api('POST', '/rule/generate', { description: desc, severity: sev, category: cat });
      _renderGeneratedRule(r.rule, r.validation, res);
      _showToast('Rule generated successfully!', 'success');
    } catch(e) {
      if (res) res.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
      _showToast('Failed: ' + e.message, 'error');
    }
  }

  async function ingestPasted() {
    const raw = document.getElementById('rk-paste-events')?.value?.trim();
    if (!raw) return _showToast('Paste events first (JSON, Syslog, or CEF)', 'warning');
    const fmt = document.getElementById('rk-paste-fmt')?.value || 'json';
    const res = document.getElementById('rk-ingest-result');
    if (res) res.innerHTML = `<div style="padding:20px;text-align:center;">${_spinner('Analyzing events…')}</div>`;
    try {
      // FIX: Use multi-format parser — supports JSON array/object, Syslog RFC3164/RFC5424, CEF
      const events = _parseLogInput(raw, fmt);
      if (!events.length) return _showToast('No parseable events found. Check format selection.', 'warning');

      const r = await _api('POST', '/ingest', { events, context: { format: fmt } });

      // FIX: normalizeDetections — guaranteed iterable array regardless of response shape
      const dets  = normalizeDetections(r.detections);
      const tl    = normalizeDetections(r.timeline);
      const chs   = normalizeDetections(r.chains);
      const anoms = normalizeDetections(r.anomalies);

      S.detections  = [...dets,  ...S.detections];
      S.timeline    = [...tl,    ...S.timeline];
      S.chains      = [...chs,   ...S.chains];
      S.anomalies   = [...anoms, ...S.anomalies];
      S.riskScore   = r.riskScore || S.riskScore;
      S.lastUpdated = new Date();
      _updateStats(r);
      _showToast(`Analyzed ${events.length} events — ${dets.length} detections`, 'success');
      if (res) res.innerHTML = _ingestSummaryCard(r);
    } catch(e) {
      if (res) res.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
      _showToast('Ingest failed: ' + e.message, 'error');
    }
  }

  function _ingestSummaryCard(r) {
    // FIX: normalizeDetections before .length access — response shape may vary
    const detsLen  = normalizeDetections(r.detections).length;
    const anomsLen = normalizeDetections(r.anomalies).length;
    const chsLen   = normalizeDetections(r.chains).length;
    return `<div class="rk-card" style="padding:16px;">
  <div style="font-size:13px;font-weight:600;color:#34d399;margin-bottom:12px;">✓ Analysis Complete</div>
  <div class="rk-grid-3" style="gap:8px;">
    ${_miniStat('Events',      r.processed   || 0, '#60a5fa')}
    ${_miniStat('Detections',  detsLen,             '#ef4444')}
    ${_miniStat('Anomalies',   anomsLen,            '#f59e0b')}
    ${_miniStat('Chains',      chsLen,              '#a78bfa')}
    ${_miniStat('Risk Score',  r.riskScore||0, '#ef4444')}
    ${_miniStat('Duration',    (r.duration||0) + 'ms', '#6b7280')}
  </div>
  <div style="margin-top:12px;display:flex;gap:8px;">
    <button class="rk-btn rk-btn-primary" onclick="RAYKAN_UI._setTab('detections')" style="font-size:11px;">View Detections →</button>
    <button class="rk-btn rk-btn-ghost"   onclick="RAYKAN_UI._setTab('timeline')"  style="font-size:11px;">View Timeline →</button>
  </div>
</div>`;
  }

  function _miniStat(label, val, color) {
    return `<div style="padding:10px;background:#0d1117;border-radius:6px;text-align:center;">
  <div style="font-size:18px;font-weight:700;color:${color};">${val}</div>
  <div style="font-size:10px;color:#6b7280;margin-top:2px;">${label}</div>
</div>`;
  }

  // ════════════════════════════════════════════════════════════════
  //  FILE UPLOAD
  // ════════════════════════════════════════════════════════════════
  function _initUploadZone() {
    const zone = document.getElementById('rk-drop-zone');
    if (!zone) return;
    zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop',      e => { e.preventDefault(); zone.classList.remove('drag-over'); _handleFileUpload(e.dataTransfer.files[0]); });
  }

  async function _handleFileUpload(file) {
    if (!file) return;
    const prog = document.getElementById('rk-upload-progress');
    const bar  = document.getElementById('rk-upload-bar');
    const msg  = document.getElementById('rk-upload-msg');
    if (prog) prog.style.display = 'block';
    if (msg)  msg.textContent = `Reading ${file.name}…`;
    if (bar)  bar.style.width = '20%';

    try {
      const text = await file.text();
      if (bar) bar.style.width = '40%';
      if (msg) msg.textContent = 'Parsing events…';

      let events;
      if (file.name.endsWith('.json')) {
        try { events = JSON.parse(text); if (!Array.isArray(events)) events = [events]; }
        catch { events = text.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return { raw: l }; } }); }
      } else {
        events = text.split('\n').filter(Boolean).map(l => ({ raw: l, source: 'file' }));
      }

      if (bar) bar.style.width = '60%';
      if (msg) msg.textContent = `Analyzing ${events.length} events…`;

      const r = await _api('POST', '/ingest', { events: events.slice(0, 5000), context: { source: 'file', fileName: file.name } });
      if (bar) bar.style.width = '100%';

      // FIX: normalizeDetections — guaranteed iterable array regardless of response shape
      const dets  = normalizeDetections(r.detections);
      const tl    = normalizeDetections(r.timeline);
      const chs   = normalizeDetections(r.chains);
      const anoms = normalizeDetections(r.anomalies);

      if (msg) msg.textContent = `✓ Done — ${dets.length} detections`;

      S.detections  = [...dets,  ...S.detections];
      S.timeline    = [...tl,    ...S.timeline];
      S.chains      = [...chs,   ...S.chains];
      S.anomalies   = [...anoms, ...S.anomalies];
      S.riskScore   = r.riskScore || S.riskScore;
      S.lastUpdated = new Date();
      _updateStats(r);

      const res = document.getElementById('rk-ingest-result');
      if (res) res.innerHTML = _ingestSummaryCard(r);
      _showToast(`${file.name}: ${dets.length} detections found`, 'success');
    } catch(e) {
      if (msg) msg.textContent = '✗ Error: ' + e.message;
      _showToast('Upload failed: ' + e.message, 'error');
    }
  }

  // ════════════════════════════════════════════════════════════════
  //  RENDERERS
  // ════════════════════════════════════════════════════════════════

  // ── Detections list ──────────────────────────────────────────
  function _renderDetectionsList(dets) {
    const el = document.getElementById('rk-det-list');
    if (!el) return;
    if (!dets.length) {
      el.innerHTML = `<div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">No detections yet — run a demo or ingest logs.</div>`;
      return;
    }
    el.innerHTML = `
<table class="rk-table">
  <thead><tr>
    <th>Severity</th><th>Rule Name</th><th>Host</th><th>User</th>
    <th>MITRE Technique</th><th>Risk</th><th>Time</th><th></th>
  </tr></thead>
  <tbody>${dets.map(d => `
  <tr onclick="RAYKAN_UI._showDetDetail('${d.id||''}')" style="cursor:pointer;">
    <td>${_sevBadge(d.severity)}</td>
    <td style="font-weight:600;color:#e6edf3;max-width:200px;">
      <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${d.ruleName||d.title||'Detection'}</div>
    </td>
    <td style="color:#8b949e;font-family:monospace;font-size:11px;">${d.computer||d.host||'—'}</td>
    <td style="color:#60a5fa;font-size:11px;">${d.user||'—'}</td>
    <td><span class="rk-tag" style="color:#a78bfa;">${d.mitre?.technique||d.technique||'—'}</span></td>
    <td><span style="font-weight:700;color:${_riskColor(d.riskScore||0)};">${d.riskScore||'—'}</span></td>
    <td style="color:#6b7280;font-size:11px;white-space:nowrap;">${_fmtTime(d.timestamp)}</td>
    <td>
      <button class="rk-entity-btn" onclick="event.stopPropagation();RAYKAN_UI._invEntity('${d.computer||d.host||''}')">
        Investigate →
      </button>
    </td>
  </tr>`).join('')}
  </tbody>
</table>`;
  }

  // ── Timeline ─────────────────────────────────────────────────
  function _renderTimelineList(tl) {
    const el = document.getElementById('rk-tl-container');
    if (!el) return;
    if (!tl.length) {
      el.innerHTML = `<div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">Timeline empty — run analysis.</div>`;
      return;
    }
    const sorted = [...tl].sort((a,b) => new Date(a.timestamp||a.ts) - new Date(b.timestamp||b.ts));
    el.innerHTML = sorted.map(e => {
      const col = e.type === 'detection' ? '#ef4444' : e.type === 'network' ? '#60a5fa' : e.type === 'file' ? '#34d399' : '#8b949e';
      return `
<div class="rk-timeline-item" style="border-left-color:${col};">
  <div class="rk-tl-dot" style="background:${col};"></div>
  <div style="flex:1;min-width:0;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;flex-wrap:wrap;">
      <span class="rk-tag" style="color:${col};background:${col}1a;">${e.type||'event'}</span>
      <span style="font-size:11px;color:#4b5563;">${_fmt(e.timestamp||e.ts)}</span>
      <span style="font-size:11px;color:#6b7280;">${e.entity||e.computer||''}</span>
    </div>
    <div style="font-size:13px;color:#e6edf3;">${e.description||e.summary||'Event'}</div>
    ${e.commandLine ? `<div class="rk-code" style="font-size:11px;color:#8b949e;margin-top:4px;">${_truncate(e.commandLine, 120)}</div>` : ''}
  </div>
</div>`;
    }).join('');
  }

  // ── Chains ───────────────────────────────────────────────────
  function _renderChainsList(chains) {
    const el = document.getElementById('rk-chains-list');
    if (!el) return;
    if (!chains.length) {
      el.innerHTML = `<div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">No attack chains detected yet.</div>`;
      return;
    }
    el.innerHTML = chains.map((c, i) => _renderChainCard(c, i)).join('');
  }

  function _renderChainCard(c, i) {
    const stages = c.stages || c.steps || c.detections || [];
    const techniques = c.techniques || stages.map(s => s.technique || s.mitre?.technique).filter(Boolean);
    return `
<div class="rk-card" style="padding:0;overflow:hidden;">
  <div class="rk-card-hdr" style="background:rgba(239,68,68,.06);">
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="font-size:18px;">🔗</span>
      <div>
        <div style="font-size:13px;font-weight:700;color:#e6edf3;">
          Attack Chain #${i+1} — ${c.name || c.type || 'Multi-stage Attack'}
        </div>
        <div style="font-size:11px;color:#6b7280;margin-top:2px;">
          ${stages.length} stages · ${c.entities?.join(', ') || ''}
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;">
      <span style="font-size:12px;font-weight:700;color:#ef4444;">Risk: ${c.riskScore||'—'}</span>
      ${_sevBadge(c.severity||'high')}
    </div>
  </div>
  <div style="padding:16px;">
    <!-- Chain visualization -->
    <div class="rk-chain-stage" style="flex-wrap:wrap;gap:4px;margin-bottom:14px;">
      ${stages.map((s, si) => `
        <span class="rk-chain-step" style="border-color:${TACTIC_COLOR[s.tactic||''] || '#30363d'};">
          ${si+1}. ${s.ruleName||s.title||s.technique||'Step'}
        </span>
        ${si < stages.length-1 ? '<span class="rk-chain-arrow">→</span>' : ''}
      `).join('')}
    </div>
    <!-- MITRE techniques -->
    ${techniques.length ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">
      ${techniques.map(t => `<span class="rk-tag" style="color:#a78bfa;">${t}</span>`).join('')}
    </div>` : ''}
    <!-- Entities involved -->
    ${c.entities?.length ? `<div style="font-size:12px;color:#8b949e;">
      <span style="font-weight:600;">Entities:</span>
      ${c.entities.map(e => `<button class="rk-entity-btn" onclick="RAYKAN_UI._invEntity('${e}')" style="margin:2px;">${e}</button>`).join('')}
    </div>` : ''}
  </div>
</div>`;
  }

  function _chainPreview(c) {
    const stages = c.stages || c.steps || c.detections || [];
    return `<div style="display:flex;align-items:center;gap:6px;padding:8px;background:#0d1117;border-radius:6px;flex-wrap:wrap;margin-bottom:6px;">
  ${stages.slice(0,4).map((s,i) => `
    <span class="rk-chain-step" style="font-size:10px;padding:4px 8px;">${s.ruleName||s.title||'Step '+(i+1)}</span>
    ${i<stages.length-1 && i<3 ? '<span class="rk-chain-arrow" style="font-size:12px;">→</span>' : ''}
  `).join('')}
  ${stages.length > 4 ? `<span style="color:#6b7280;font-size:11px;">+${stages.length-4} more</span>` : ''}
</div>`;
  }

  // ── Anomalies ────────────────────────────────────────────────
  function _renderAnomaliesList(anoms) {
    const el = document.getElementById('rk-anom-list');
    if (!el) return;
    if (!anoms.length) {
      el.innerHTML = `<div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">No behavioral anomalies detected.</div>`;
      return;
    }
    el.innerHTML = anoms.map(a => `
<div class="rk-card" style="padding:16px;display:flex;gap:16px;align-items:flex-start;">
  <div style="width:48px;height:48px;border-radius:50%;background:rgba(245,158,11,.15);
    display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:20px;">📈</div>
  <div style="flex:1;min-width:0;">
    <div style="font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:4px;">
      ${a.description || a.type || 'Behavioral Anomaly'}
    </div>
    <div style="font-size:11px;color:#6b7280;margin-bottom:8px;">
      Entity: <span style="color:#f59e0b;">${a.entity||'—'}</span> ·
      Score: <span style="color:#ef4444;font-weight:700;">${a.score?.toFixed(2)||'—'}</span> ·
      ${_fmtTime(a.timestamp)}
    </div>
    ${a.baseline !== undefined ? `<div style="font-size:11px;color:#4b5563;">
      Baseline: ${a.baseline} → Observed: <span style="color:#f59e0b;">${a.observed||'—'}</span>
      (${a.deviation ? '+'+a.deviation+'%' : ''})
    </div>` : ''}
  </div>
  <span class="rk-badge" style="background:rgba(245,158,11,.12);color:#f59e0b;flex-shrink:0;">ANOMALY</span>
</div>`).join('');
  }

  // ── Hunt results ─────────────────────────────────────────────
  function _renderHuntResults(r) {
    const el = document.getElementById('rk-h-results');
    if (!el) return;

    if (!r.count) {
      el.innerHTML = `<div class="rk-card" style="padding:40px;text-align:center;color:#4b5563;font-size:13px;">
        No matches. ${r.suggestion ? `<br/><span style="color:#60a5fa;margin-top:8px;display:inline-block;">💡 ${r.suggestion}</span>` : ''}
      </div>`;
      return;
    }

    const rows = (r.matches || []).slice(0, 100).map(m => `
<tr>
  <td class="rk-code" style="color:#6b7280;">${_fmtTime(m.timestamp)}</td>
  <td style="color:#e6edf3;">${m.computer||m.host||'—'}</td>
  <td style="color:#60a5fa;">${m.user||'—'}</td>
  <td style="color:#34d399;">${m.process||m.processName||'—'}</td>
  <td class="rk-code" style="color:#8b949e;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
    ${m.commandLine||m.srcIp||'—'}
  </td>
</tr>`).join('');

    el.innerHTML = `
<div class="rk-card" style="overflow:hidden;">
  <div class="rk-card-hdr">
    <span style="font-size:13px;font-weight:600;">Results — ${r.count} matches</span>
    <div style="display:flex;gap:8px;align-items:center;">
      ${r.explanation ? `<span style="font-size:11px;color:#60a5fa;">AI: ${_truncate(r.explanation, 60)}</span>` : ''}
      <span style="font-size:11px;color:#6b7280;">${r.duration}ms</span>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;" onclick="RAYKAN_UI._exportHuntCSV()">↓ CSV</button>
    </div>
  </div>
  ${r.rqlQuery ? `<div style="padding:8px 16px;background:#0d1117;border-bottom:1px solid #21262d;">
    <span style="font-size:10px;color:#6b7280;">RQL: </span>
    <code class="rk-code" style="font-size:11px;color:#60a5fa;">${r.rqlQuery}</code>
  </div>` : ''}
  <div style="overflow-x:auto;">
    <table class="rk-table">
      <thead><tr><th>Time</th><th>Host</th><th>User</th><th>Process</th><th>Command / Detail</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  ${r.count > 100 ? `<div style="padding:10px 16px;color:#6b7280;font-size:11px;text-align:right;">
    Showing 100 of ${r.count} results
  </div>` : ''}
</div>`;
  }

  // ── IOC results ──────────────────────────────────────────────
  function _renderIOCResult(ioc, container) {
    if (!container) return;
    if (!ioc) { container.innerHTML = `<div style="color:#6b7280;padding:20px;">No results.</div>`; return; }

    const vt = ioc.virusTotal || {};
    const ab = ioc.abuseIPDB  || {};
    const otx = ioc.otx       || {};
    const isClean = !ioc.malicious && (vt.positives||0) === 0;

    container.innerHTML = `
<div class="rk-card" style="overflow:hidden;">
  <div class="rk-card-hdr" style="background:${ioc.malicious ? 'rgba(239,68,68,.06)' : 'rgba(34,197,94,.04)'};">
    <div>
      <div style="font-size:13px;font-weight:700;color:#e6edf3;">${ioc.value || ioc.indicator || 'IOC Result'}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">${ioc.type || 'indicator'}</div>
    </div>
    <span class="rk-badge" style="background:${isClean ? 'rgba(34,197,94,.12)' : 'rgba(239,68,68,.12)'};color:${isClean ? '#34d399' : '#ef4444'};">
      ${isClean ? '✓ Clean' : '⚠ Malicious'}
    </span>
  </div>
  <div style="padding:16px;">
    <div class="rk-grid-3" style="margin-bottom:16px;">
      ${_iocStatCard('VirusTotal', `${vt.positives||0}/${vt.total||0}`, '#ef4444')}
      ${_iocStatCard('AbuseIPDB',  `${ab.abuseScore||0}%`, '#f97316')}
      ${_iocStatCard('OTX Pulses', `${otx.pulseCount||0}`, '#a78bfa')}
    </div>
    ${ioc.country ? `<div style="font-size:12px;color:#8b949e;margin-bottom:8px;">Country: <span style="color:#e6edf3;">${ioc.country} ${ioc.asn||''}</span></div>` : ''}
    ${ioc.tags?.length ? `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px;">${ioc.tags.map(t=>`<span class="rk-tag">${t}</span>`).join('')}</div>` : ''}
    ${ioc.description ? `<div style="font-size:12px;color:#8b949e;">${ioc.description}</div>` : ''}
  </div>
</div>`;
  }

  function _iocStatCard(label, val, color) {
    return `<div style="padding:12px;background:#0d1117;border-radius:6px;text-align:center;">
  <div style="font-size:18px;font-weight:700;color:${color};">${val}</div>
  <div style="font-size:10px;color:#6b7280;margin-top:2px;">${label}</div>
</div>`;
  }

  function _renderBatchIOC(results, container) {
    if (!container) return;
    container.innerHTML = `
<div class="rk-card" style="overflow:hidden;">
  <div class="rk-card-hdr"><span style="font-size:13px;font-weight:600;">Batch Lookup — ${results.length} IOCs</span></div>
  <table class="rk-table">
    <thead><tr><th>IOC</th><th>Type</th><th>VT Score</th><th>Abuse %</th><th>Verdict</th></tr></thead>
    <tbody>${results.map(r => `
    <tr>
      <td class="rk-code" style="color:#e6edf3;">${r.value||r.indicator||'—'}</td>
      <td><span class="rk-tag">${r.type||'—'}</span></td>
      <td style="color:${(r.virusTotal?.positives||0)>0?'#ef4444':'#34d399'};">${r.virusTotal?.positives||0}/${r.virusTotal?.total||0}</td>
      <td style="color:${(r.abuseIPDB?.abuseScore||0)>50?'#ef4444':'#34d399'};">${r.abuseIPDB?.abuseScore||0}%</td>
      <td>${r.malicious ?
        '<span class="rk-badge" style="background:rgba(239,68,68,.12);color:#ef4444;">⚠ Malicious</span>' :
        '<span class="rk-badge" style="background:rgba(34,197,94,.12);color:#34d399;">✓ Clean</span>'
      }</td>
    </tr>`).join('')}
    </tbody>
  </table>
</div>`;
  }

  // ── Investigation result ─────────────────────────────────────
  function _renderInvestigationResult(r, container) {
    if (!container) return;
    const score = r.riskScore || 0;
    container.innerHTML = `
<div style="display:flex;flex-direction:column;gap:16px;">
  <!-- Header -->
  <div class="rk-card" style="padding:20px;">
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <div style="width:56px;height:56px;border-radius:12px;background:rgba(239,68,68,.12);
        display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0;">
        ${r.type==='host' ? '🖥' : r.type==='user' ? '👤' : r.type==='ip' ? '🌐' : r.type==='process' ? '⚙️' : '🕵️'}
      </div>
      <div style="flex:1;">
        <div style="font-size:16px;font-weight:700;color:#e6edf3;">${r.entityId}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:4px;">Type: ${r.type||'auto'} · Risk Score: <span style="color:${_riskColor(score)};font-weight:700;">${score}</span></div>
        ${r.summary ? `<div style="font-size:12px;color:#8b949e;margin-top:8px;">${r.summary}</div>` : ''}
      </div>
      <div style="text-align:right;">
        <div style="font-size:32px;font-weight:800;color:${_riskColor(score)};">${score}</div>
        <div style="font-size:10px;color:#6b7280;">Risk Score</div>
      </div>
    </div>
  </div>

  <div class="rk-grid-2">
    <!-- Evidence / detections -->
    <div class="rk-card">
      <div class="rk-card-hdr">
        <span style="font-size:12px;font-weight:700;">🚨 Related Detections</span>
        <span style="font-size:11px;color:#6b7280;">${r.evidence?.detections?.length||0}</span>
      </div>
      <div style="max-height:200px;overflow-y:auto;">
        ${(r.evidence?.detections||[]).slice(0,10).map(d => `
        <div class="rk-det-row" style="font-size:12px;">
          ${_sevBadge(d.severity)} ${d.ruleName||'Detection'}
        </div>`).join('') || '<div style="padding:20px;color:#4b5563;text-align:center;font-size:12px;">No related detections.</div>'}
      </div>
    </div>

    <!-- MITRE map -->
    <div class="rk-card">
      <div class="rk-card-hdr">
        <span style="font-size:12px;font-weight:700;">🗺 MITRE Techniques</span>
        <span style="font-size:11px;color:#6b7280;">${r.mitreMap?.techniques?.length||0}</span>
      </div>
      <div style="padding:12px;display:flex;flex-wrap:wrap;gap:4px;">
        ${(r.mitreMap?.techniques||[]).map(t => `
          <span class="rk-tag" style="color:#a78bfa;">${t.id||t} — ${t.name||''}</span>`).join('')
          || '<div style="color:#4b5563;font-size:12px;padding:12px;">No techniques mapped.</div>'}
      </div>
    </div>
  </div>

  <!-- Timeline -->
  ${r.timeline?.length ? `<div class="rk-card">
    <div class="rk-card-hdr">
      <span style="font-size:12px;font-weight:700;">⏱ Entity Timeline</span>
      <span style="font-size:11px;color:#6b7280;">${r.timeline.length} events</span>
    </div>
    <div style="padding:12px;max-height:300px;overflow-y:auto;">
      ${r.timeline.slice(0, 30).map(e => {
        const col = e.type === 'detection' ? '#ef4444' : '#60a5fa';
        return `<div class="rk-timeline-item" style="border-left-color:${col};padding:6px 12px;">
          <div class="rk-tl-dot" style="background:${col};width:8px;height:8px;margin-left:-17px;"></div>
          <div>
            <div style="font-size:11px;color:#6b7280;">${_fmt(e.timestamp)}</div>
            <div style="font-size:12px;color:#e6edf3;">${e.description||e.summary||'Event'}</div>
          </div>
        </div>`;
      }).join('')}
    </div>
  </div>` : ''}

  <!-- Attack chain -->
  ${r.chain ? `<div class="rk-card" style="padding:16px;">
    <div style="font-size:12px;font-weight:700;margin-bottom:12px;">🔗 Attack Chain</div>
    ${_chainPreview(r.chain)}
  </div>` : ''}
</div>`;
  }

  // ── Rules list ───────────────────────────────────────────────
  async function _loadRules() {
    const sev  = document.getElementById('rk-rules-sev')?.value   || '';
    const srch = document.getElementById('rk-rules-search')?.value || '';
    const el   = document.getElementById('rk-rules-list');
    if (!el) return;
    el.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('Loading rules…')}</div>`;
    try {
      const r = await _api('GET', `/rules?severity=${sev}&limit=200`);
      const rules = (r.rules||[]).filter(ru => !srch || ru.name?.toLowerCase().includes(srch.toLowerCase()) || ru.description?.toLowerCase().includes(srch.toLowerCase()));
      const cnt = document.getElementById('rk-rules-cnt');
      if (cnt) cnt.textContent = r.total || rules.length;
      if (!rules.length) {
        el.innerHTML = `<div style="padding:40px;text-align:center;color:#4b5563;font-size:13px;">No rules found.</div>`;
        return;
      }
      el.innerHTML = `<table class="rk-table">
  <thead><tr><th>Severity</th><th>Rule Name</th><th>MITRE Technique</th><th>Category</th><th>Status</th></tr></thead>
  <tbody>${rules.map(ru => `
  <tr>
    <td>${_sevBadge(ru.level||ru.severity||'medium')}</td>
    <td style="font-weight:600;color:#e6edf3;">${ru.name||ru.title||'—'}</td>
    <td><span class="rk-tag" style="color:#a78bfa;">${ru.tags?.find(t=>t.startsWith('attack.t'))||'—'}</span></td>
    <td><span class="rk-tag">${ru.category||ru.logsource?.category||'—'}</span></td>
    <td><span class="rk-badge" style="background:rgba(34,197,94,.12);color:#34d399;">✓ Active</span></td>
  </tr>`).join('')}
  </tbody>
</table>`;
    } catch(e) {
      el.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  function _searchRules() {
    clearTimeout(window._rk_rulesearchTimer);
    window._rk_rulesearchTimer = setTimeout(_loadRules, 300);
  }

  // ── MITRE heatmap ────────────────────────────────────────────
  async function _loadMITRE() {
    const el = document.getElementById('rk-mitre-heatmap');
    if (!el) return;
    el.innerHTML = `<div style="padding:40px;text-align:center;">${_spinner('Loading MITRE coverage…')}</div>`;
    try {
      const r = await _api('GET', '/mitre');
      _renderMITREHeatmap(r, el);
    } catch(e) {
      el.innerHTML = `<div style="color:#ef4444;padding:20px;">${e.message}</div>`;
    }
  }

  function _renderMITREHeatmap(r, el) {
    const tactics = r.tactics || [];
    const covered = r.coveredTechniques || {};

    if (!tactics.length) {
      el.innerHTML = `<div style="color:#4b5563;font-size:13px;text-align:center;padding:40px;">No MITRE data available.</div>`;
      return;
    }

    el.innerHTML = `
<div>
  <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center;">
    <div style="font-size:12px;color:#8b949e;">
      Coverage: <span style="color:#34d399;font-weight:700;">${r.coverage?.toFixed(1)||0}%</span>
      · ${Object.keys(covered).length} techniques covered
    </div>
    <div style="display:flex;gap:6px;">
      <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:#ef444433;color:#ef4444;">Detected</span>
      <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:#34d39933;color:#34d399;">Rule Coverage</span>
      <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:#21262d;color:#6b7280;">No Coverage</span>
    </div>
  </div>
  <div style="overflow-x:auto;">
    <div style="display:flex;gap:8px;min-width:900px;">
      ${tactics.map(tactic => `
      <div style="flex:1;min-width:100px;">
        <div style="font-size:9px;font-weight:800;text-transform:uppercase;color:${TACTIC_COLOR[tactic.id]||'#8b949e'};
          padding:6px 4px;background:${TACTIC_COLOR[tactic.id]||'#8b949e'}1a;border-radius:4px;
          text-align:center;margin-bottom:4px;letter-spacing:.3px;">${tactic.name||tactic.id}</div>
        ${(tactic.techniques||[]).map(t => {
          const det = covered[t.id]?.detected;
          const cov = covered[t.id]?.rules > 0;
          const bg  = det ? '#ef444433' : cov ? '#34d39922' : '#21262d';
          const col = det ? '#ef4444'   : cov ? '#34d399'   : '#4b5563';
          return `<div class="rk-mitre-cell" style="background:${bg};color:${col};margin-bottom:2px;"
            title="${t.id}: ${t.name}">${t.id}</div>`;
        }).join('')}
      </div>`).join('')}
    </div>
  </div>
</div>`;
  }

  // ── Generated rule ───────────────────────────────────────────
  function _renderGeneratedRule(rule, validation, container) {
    if (!container) return;
    const isValid = validation?.valid !== false;
    container.innerHTML = `
<div class="rk-card" style="overflow:hidden;">
  <div class="rk-card-hdr" style="background:rgba(124,58,237,.06);">
    <div>
      <div style="font-size:13px;font-weight:600;">✨ Generated Sigma Rule</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">${rule?.title||rule?.name||'Detection Rule'}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <span class="rk-badge" style="background:${isValid?'rgba(34,197,94,.12)':'rgba(249,115,22,.12)'};color:${isValid?'#34d399':'#f97316'};">
        ${isValid ? '✅ Valid' : '⚠️ Needs Review'}
      </span>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;" onclick="navigator.clipboard.writeText(JSON.stringify(${JSON.stringify(JSON.stringify(rule))},null,2))">Copy</button>
    </div>
  </div>
  <div style="padding:16px;">
    <pre class="rk-code" style="
      background:#0d1117;border-radius:8px;padding:16px;overflow-x:auto;
      font-size:11px;color:#8b949e;border:1px solid #21262d;max-height:400px;overflow-y:auto;
    ">${JSON.stringify(rule, null, 2)}</pre>
    ${validation?.errors?.length ? `
    <div style="margin-top:10px;padding:10px;background:rgba(249,115,22,.08);border-radius:6px;border:1px solid rgba(249,115,22,.2);">
      <div style="color:#f97316;font-size:12px;font-weight:600;margin-bottom:4px;">Validation Errors:</div>
      ${validation.errors.map(e => `<div style="font-size:11px;color:#8b949e;">• ${e}</div>`).join('')}
    </div>` : ''}
    <div style="margin-top:12px;display:flex;gap:8px;">
      ${isValid ? `<button class="rk-btn rk-btn-primary" style="font-size:11px;" onclick="RAYKAN_UI._activateGeneratedRule()">
        ✓ Add to Engine
      </button>` : ''}
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;" onclick="RAYKAN_UI._setTab('rules')">View All Rules →</button>
    </div>
  </div>
</div>`;
    window._rk_lastGeneratedRule = rule;
  }

  async function _activateGeneratedRule() {
    if (!window._rk_lastGeneratedRule) return;
    _showToast('Rule added to active engine', 'success');
  }

  // ── Detection detail modal ────────────────────────────────────
  function _showDetDetail(id) {
    const det = S.detections.find(d => d.id === id) || S.detections[0];
    if (!det) return;
    const overlay = document.createElement('div');
    overlay.className = 'rk-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    overlay.innerHTML = `
<div class="rk-modal">
  <div class="rk-card-hdr" style="padding:16px 20px;flex-shrink:0;">
    <div style="display:flex;align-items:center;gap:10px;">
      ${_sevBadge(det.severity)}
      <span style="font-size:14px;font-weight:700;color:#e6edf3;">${det.ruleName||det.title||'Detection'}</span>
    </div>
    <button onclick="this.closest('.rk-modal-overlay').remove()" style="
      background:none;border:none;color:#6b7280;font-size:18px;cursor:pointer;padding:4px;">✕</button>
  </div>
  <div style="overflow-y:auto;padding:20px;flex:1;">
    <div class="rk-grid-2" style="margin-bottom:16px;">
      ${_detField('Host',       det.computer||det.host)}
      ${_detField('User',       det.user)}
      ${_detField('Process',    det.process||det.processName)}
      ${_detField('Risk Score', det.riskScore)}
      ${_detField('Timestamp',  _fmt(det.timestamp))}
      ${_detField('Confidence', det.confidence ? (det.confidence*100).toFixed(0)+'%' : '—')}
    </div>
    ${det.commandLine ? `<div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">Command Line</div>
      <div class="rk-code" style="background:#0d1117;padding:12px;border-radius:6px;border:1px solid #21262d;font-size:11px;color:#34d399;word-break:break-all;">${det.commandLine}</div>
    </div>` : ''}
    ${det.mitre?.techniques?.length ? `<div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">MITRE ATT&CK</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${det.mitre.techniques.map(t => `<span class="rk-tag" style="color:#a78bfa;">${t.id||t} — ${t.name||''}</span>`).join('')}
      </div>
    </div>` : ''}
    ${det.description ? `<div style="font-size:12px;color:#8b949e;">${det.description}</div>` : ''}
    <div style="margin-top:14px;display:flex;gap:8px;">
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;"
        onclick="RAYKAN_UI._invEntity('${det.computer||det.host||det.user||''}');this.closest('.rk-modal-overlay').remove()">
        🕵️ Investigate Entity →
      </button>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;"
        onclick="RAYKAN_UI._setTab('timeline');this.closest('.rk-modal-overlay').remove()">
        ⏱ View Timeline →
      </button>
    </div>
  </div>
</div>`;
    document.body.appendChild(overlay);
  }

  function _detField(label, value) {
    return `<div>
  <div style="font-size:10px;color:#4b5563;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;">${label}</div>
  <div style="font-size:13px;color:#e6edf3;">${value||'—'}</div>
</div>`;
  }

  function _invEntity(entity) {
    if (!entity) return;
    S.investigateEntity = entity;
    _setTab('investigate');
    setTimeout(() => {
      const el = document.getElementById('rk-inv-entity');
      if (el) el.value = entity;
      _runInvestigation(entity);
    }, 100);
  }

  // ════════════════════════════════════════════════════════════════
  //  HUNT MODE TOGGLE
  // ════════════════════════════════════════════════════════════════
  function _setHuntMode(mode) {
    S.huntMode = mode;
    const rqlBtn = document.getElementById('rk-h-rql');
    const nlBtn  = document.getElementById('rk-h-nl');
    const inp    = document.getElementById('rk-h-input');
    if (rqlBtn) { rqlBtn.style.color = mode==='rql' ? '#60a5fa' : ''; rqlBtn.style.borderColor = mode==='rql' ? '#60a5fa' : ''; }
    if (nlBtn)  { nlBtn.style.color  = mode==='nl'  ? '#60a5fa' : ''; nlBtn.style.borderColor  = mode==='nl'  ? '#60a5fa' : ''; }
    if (inp)    inp.placeholder = mode==='nl' ?
      'Find all PowerShell encoded commands in the last 24 hours…' :
      'process.name:"powershell.exe" AND commandLine:*EncodedCommand*';
  }

  // ════════════════════════════════════════════════════════════════
  //  FILTERS & SEARCH
  // ════════════════════════════════════════════════════════════════
  function _filterDetections() {
    const sev = document.getElementById('rk-det-sev')?.value || '';
    const filtered = sev ? S.detections.filter(d => d.severity === sev) : S.detections;
    _renderDetectionsList(filtered);
  }

  function _searchDetections() {
    const q   = document.getElementById('rk-det-search')?.value?.toLowerCase() || '';
    const sev = document.getElementById('rk-det-sev')?.value || '';
    const filtered = S.detections.filter(d =>
      (!sev || d.severity === sev) &&
      (!q   || (d.ruleName||d.title||'').toLowerCase().includes(q) ||
               (d.computer||d.host||'').toLowerCase().includes(q) ||
               (d.user||'').toLowerCase().includes(q))
    );
    _renderDetectionsList(filtered);
  }

  function _filterTimeline() {
    const type = document.getElementById('rk-tl-filter')?.value || '';
    const filtered = type ? S.timeline.filter(e => e.type === type) : S.timeline;
    const el = document.getElementById('rk-tl-container');
    const tmp = S.timeline;
    S.timeline = filtered;
    _renderTimelineList(filtered);
    S.timeline = tmp;
  }

  // ════════════════════════════════════════════════════════════════
  //  EXPORT
  // ════════════════════════════════════════════════════════════════
  function exportResults() {
    const data = {
      session    : S.sessionId,
      riskScore  : S.riskScore,
      generatedAt: new Date().toISOString(),
      detections : S.detections,
      timeline   : S.timeline,
      chains     : S.chains,
      anomalies  : S.anomalies,
    };
    _downloadJSON(data, `raykan-results-${Date.now()}.json`);
    _showToast('Results exported as JSON', 'success');
  }

  function _exportDetections() {
    const csv = ['Severity,Rule,Host,User,MITRE,RiskScore,Time',
      ...S.detections.map(d => [d.severity, `"${d.ruleName||''}"`, d.computer||d.host||'', d.user||'',
        d.mitre?.technique||'', d.riskScore||'', new Date(d.timestamp).toISOString()].join(','))
    ].join('\n');
    _downloadText(csv, `raykan-detections-${Date.now()}.csv`, 'text/csv');
    _showToast('Detections exported as CSV', 'success');
  }

  function _exportTimeline() {
    const csv = ['Time,Type,Entity,Description',
      ...S.timeline.map(e => [new Date(e.timestamp||e.ts).toISOString(), e.type||'', e.entity||'', `"${e.description||''}"`].join(','))
    ].join('\n');
    _downloadText(csv, `raykan-timeline-${Date.now()}.csv`, 'text/csv');
    _showToast('Timeline exported as CSV', 'success');
  }

  function _exportHuntCSV() {
    if (!S.huntResults?.matches) return;
    const csv = ['Time,Host,User,Process,Command',
      ...S.huntResults.matches.map(m => [
        new Date(m.timestamp).toISOString(), m.computer||m.host||'',
        m.user||'', m.process||'', `"${(m.commandLine||'').replace(/"/g,'""')}"`].join(','))
    ].join('\n');
    _downloadText(csv, `raykan-hunt-${Date.now()}.csv`, 'text/csv');
    _showToast('Hunt results exported as CSV', 'success');
  }

  function _downloadJSON(obj, name) {
    _downloadText(JSON.stringify(obj, null, 2), name, 'application/json');
  }

  function _downloadText(text, name, type='text/plain') {
    const a = document.createElement('a');
    a.href  = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    a.click();
  }

  // ════════════════════════════════════════════════════════════════
  //  STATS & REALTIME
  // ════════════════════════════════════════════════════════════════
  function _updateStats(result) {
    const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
    set('rk-s-events', (result.processed||0).toLocaleString());
    set('rk-s-dets',   S.detections.length.toLocaleString());
    set('rk-s-anom',   S.anomalies.length.toLocaleString());
    set('rk-s-chains', S.chains.length.toLocaleString());
    set('rk-s-risk',   S.riskScore || '—');
    set('rk-last-upd', S.lastUpdated?.toLocaleTimeString() || '—');
    set('rk-session-id', S.sessionId ? S.sessionId.slice(0,8)+'…' : '—');

    const badge = document.getElementById('rk-risk-badge');
    if (badge) {
      const r = S.riskScore;
      const col = r>=80?'#ef4444': r>=60?'#f97316': r>=40?'#eab308': r>0?'#22c55e':'#6b7280';
      badge.style.color = col;
      badge.style.borderColor = col;
      badge.textContent = `Risk Score: ${r||'—'}`;
    }
  }

  async function _loadStats() {
    try {
      const r = await _api('GET', '/stats');
      const s = r.stats || r;
      const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
      set('rk-s-rules',     s.rulesLoaded||0);
      set('rk-sigma-rules', s.rulesLoaded||0);
      set('rk-ai-prov',     r.subEngines?.ai?.provider||'none');
      set('rk-ueba-prof',   r.subEngines?.ueba?.profiles||0);
      set('rk-chains-cnt',  s.chainsBuilt||0);
      set('rk-uptime-val',  s.uptime||0);
      set('rk-buffer-val',  s.bufferSize||0);

      // Engine health dots
      const healthEl = document.getElementById('rk-engine-health');
      if (healthEl) {
        const engines = [
          ['Sigma', r.subEngines?.sigma?.active !== false],
          ['AI',    r.subEngines?.ai?.active !== false],
          ['UEBA',  r.subEngines?.ueba?.active !== false],
          ['DFIR',  r.subEngines?.forensics?.active !== false],
        ];
        healthEl.innerHTML = engines.map(([name, ok]) =>
          `<span style="display:flex;align-items:center;gap:4px;font-size:11px;color:${ok?'#34d399':'#6b7280'};">
            <span style="width:6px;height:6px;border-radius:50%;background:${ok?'#34d399':'#4b5563'};"></span>${name}
          </span>`).join('');
      }
    } catch(e) { /* backend not yet initialized */ }
  }

  function _onRealtimeDetection(det) {
    S.detections.unshift(det);
    if (S.detections.length > 1000) S.detections.pop();
    _updateStats({});
    if (S.activeTab === 'detections') _renderDetectionsList(S.detections);
    if (S.activeTab === 'overview')   _renderOverviewContent();
    _showToast(`🚨 ${det.ruleName||'Detection'} — ${det.severity?.toUpperCase()}`, det.severity === 'critical' ? 'error' : 'warning');
  }

  function _onRealtimeAnomaly(a) {
    S.anomalies.unshift(a);
    _updateStats({});
    if (S.activeTab === 'anomalies') _renderAnomaliesList(S.anomalies);
  }

  function _onRealtimeChain(c) {
    S.chains.unshift(c);
    _updateStats({});
    if (S.activeTab === 'chains') _renderChainsList(S.chains);
  }

  // ════════════════════════════════════════════════════════════════
  //  HELPERS
  // ════════════════════════════════════════════════════════════════
  function _riskColor(score) {
    return score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
  }

  function _spinner(msg='Processing…') {
    return `<div style="text-align:center;padding:30px;color:#8b949e;">
  <div class="rk-spinner" style="margin-bottom:12px;"></div>
  <div style="font-size:13px;">${msg}</div>
</div>`;
  }

  function _updateWSBadge() {
    const dot = document.getElementById('rk-ws-dot');
    const lbl = document.getElementById('rk-ws-lbl');
    if (dot) dot.style.background = S.wsConnected ? '#34d399' : '#374151';
    if (lbl) lbl.textContent      = S.wsConnected ? 'Live' : 'Offline';
  }

  function _showToast(msg, type='info') {
    const root = document.getElementById('rk-toast-root');
    if (!root) return;
    const colors = { success:'#34d399', error:'#ef4444', warning:'#f59e0b', info:'#60a5fa' };
    const toast  = document.createElement('div');
    toast.style.cssText = `
      padding:10px 16px;border-radius:8px;font-size:12px;font-weight:500;
      background:#161b22;color:#e6edf3;border-left:3px solid ${colors[type]||colors.info};
      box-shadow:0 4px 20px rgba(0,0,0,.5);max-width:320px;
      animation:rk-slidein .25s ease;
    `;
    const s = document.createElement('style');
    s.textContent = '@keyframes rk-slidein{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}';
    document.head.appendChild(s);
    toast.textContent = msg;
    root.appendChild(toast);
    setTimeout(() => toast.remove(), 4500);
  }

  function _attachEvents() {
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (!document.getElementById('rk-root')) return;
      if (e.ctrlKey && e.key === 'Enter' && S.activeTab === 'hunt') executeHunt();
    });
  }

  // ════════════════════════════════════════════════════════════════
  //  PUBLIC API
  // ════════════════════════════════════════════════════════════════
  const RAYKAN_UI = {
    render,
    runSample,
    executeHunt,
    lookupIOC,
    lookupIOCBatch,
    investigate,
    generateRule,
    ingestPasted,
    exportResults,
    _setTab,
    _setHuntMode,
    _filterDetections,
    _searchDetections,
    _filterTimeline,
    _exportDetections,
    _exportTimeline,
    _exportHuntCSV,
    _handleFileUpload,
    _loadRules,
    _loadMITRE,
    _showDetDetail,
    _invEntity,
    _activateGeneratedRule,
    getState: () => S,
  };

  // Expose globally
  window.RAYKAN_UI     = RAYKAN_UI;
  window.renderRAYKAN  = () => {
    const wrap = document.getElementById('raykanWrap');
    if (wrap) render(wrap);
  };

  console.log(`[RAYKAN UI v${RAYKAN_VERSION}] Module loaded — ${Object.keys(RAYKAN_UI).length} exports`);

})(window);
