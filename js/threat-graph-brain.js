/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Threat Intelligence Graph Brain v2.0
 *  FILE: js/threat-graph-brain.js
 *
 *  Interactive graph visualization of threat actors, malware, 
 *  campaigns, techniques — with real data from DB + MITRE ATT&CK.
 *  Region-based categorization, zoom, click-for-intelligence.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ════════════════════════════════════════════════════════════════
   STATE
════════════════════════════════════════════════════════════════ */
let _tgState = {
  nodes: [],
  edges: [],
  selectedNode: null,
  filter: { type: '', region: '', search: '' },
  zoom: 1,
  pan: { x: 0, y: 0 },
  dragging: false,
  dragNode: null,
  mouseStart: null,
  positions: new Map(),
};

/* ════════════════════════════════════════════════════════════════
   NODE VISUAL CONFIG
════════════════════════════════════════════════════════════════ */
const NODE_CONFIG = {
  threat_actor: { color: '#ef4444', bg: 'rgba(239,68,68,.15)', border: '#ef4444', icon: '👤', size: 48, label: 'Threat Actor' },
  malware:      { color: '#f97316', bg: 'rgba(249,115,22,.15)', border: '#f97316', icon: '🦠', size: 42, label: 'Malware' },
  campaign:     { color: '#a855f7', bg: 'rgba(168,85,247,.15)', border: '#a855f7', icon: '🎯', size: 40, label: 'Campaign' },
  technique:    { color: '#3b82f6', bg: 'rgba(59,130,246,.15)', border: '#3b82f6', icon: '⚙️', size: 36, label: 'Technique' },
  region:       { color: '#22d3ee', bg: 'rgba(34,211,238,.15)', border: '#22d3ee', icon: '🌍', size: 52, label: 'Region' },
  target_sector:{ color: '#f59e0b', bg: 'rgba(245,158,11,.15)', border: '#f59e0b', icon: '🏢', size: 38, label: 'Target Sector' },
  infrastructure:{ color: '#6b7280', bg: 'rgba(107,114,128,.15)', border: '#6b7280', icon: '🖥️', size: 36, label: 'Infrastructure' },
};

/* ════════════════════════════════════════════════════════════════
   MAIN RENDER
════════════════════════════════════════════════════════════════ */
window.renderThreatGraph = function() {
  const el = document.getElementById('page-threat-graph');
  if (!el) return;

  el.innerHTML = `
  <div style="padding:0;background:#070b12;min-height:100vh;font-family:'Inter',sans-serif;display:flex;flex-direction:column;">

    <!-- ── Header ── -->
    <div style="background:linear-gradient(135deg,#0a0e17,#0a1628);border-bottom:1px solid #1e293b;padding:20px 24px 16px;flex-shrink:0;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div style="width:46px;height:46px;background:linear-gradient(135deg,#22d3ee,#3b82f6);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px rgba(34,211,238,.3);">
            <i class="fas fa-project-diagram" style="color:#fff;font-size:20px;"></i>
          </div>
          <div>
            <h1 style="margin:0;font-size:1.4rem;font-weight:800;color:#f1f5f9;">Threat Intelligence Graph</h1>
            <div style="font-size:11px;color:#64748b;">Threat actors · Malware · Campaigns · Techniques · Regions</div>
          </div>
        </div>
        <!-- Legend -->
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
          ${Object.entries(NODE_CONFIG).map(([type, cfg]) => `
          <div onclick="tgFilterType('${type}')" id="legend-${type}"
            style="display:flex;align-items:center;gap:5px;background:#0f172a;border:1px solid #1e293b;padding:5px 10px;border-radius:20px;cursor:pointer;transition:all .2s;"
            onmouseover="this.style.borderColor='${cfg.color}60'" onmouseout="if(!this.classList.contains('active'))this.style.borderColor='#1e293b'">
            <div style="width:8px;height:8px;border-radius:50%;background:${cfg.color};"></div>
            <span style="font-size:10px;color:#64748b;">${cfg.label}</span>
          </div>`).join('')}
          <button onclick="tgClearFilter()"
            style="background:#0f172a;border:1px solid #1e293b;color:#64748b;padding:5px 10px;border-radius:20px;cursor:pointer;font-size:10px;display:flex;align-items:center;gap:4px;">
            <i class="fas fa-times"></i> All
          </button>
        </div>
      </div>

      <!-- Toolbar -->
      <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;align-items:center;">
        <div style="position:relative;flex:1;min-width:200px;max-width:300px;">
          <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#475569;font-size:12px;"></i>
          <input id="tg-search" type="text" placeholder="Search node…"
            oninput="tgSearchNodes(this.value)"
            style="width:100%;background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:7px 10px 7px 30px;border-radius:8px;font-size:12px;outline:none;box-sizing:border-box;" />
        </div>
        <select id="tg-region-filter" onchange="tgFilterRegion(this.value)"
          style="background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:7px 10px;border-radius:8px;font-size:12px;cursor:pointer;outline:none;">
          <option value="">All Regions</option>
          <option value="APAC">APAC</option>
          <option value="EMEA">EMEA</option>
          <option value="AMER">Americas</option>
        </select>
        <div style="display:flex;gap:4px;">
          <button onclick="tgZoom(0.2)" title="Zoom In" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px;">+</button>
          <button onclick="tgZoom(-0.2)" title="Zoom Out" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px;">-</button>
          <button onclick="tgResetView()" title="Reset View" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px;"><i class="fas fa-compress-alt"></i></button>
        </div>
        <button onclick="tgLoadData()" style="background:linear-gradient(135deg,#22d3ee,#3b82f6);color:#fff;border:none;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;display:flex;align-items:center;gap:5px;">
          <i class="fas fa-sync-alt"></i> Refresh
        </button>
        <div id="tg-node-count" style="font-size:11px;color:#475569;padding:7px 10px;background:#0a0e17;border:1px solid #1e293b;border-radius:8px;">Loading…</div>
      </div>
    </div>

    <!-- ── Main graph area ── -->
    <div style="flex:1;display:flex;min-height:0;overflow:hidden;">
      <!-- Canvas -->
      <div id="tg-canvas-wrap" style="flex:1;position:relative;overflow:hidden;background:radial-gradient(ellipse at center,#0d1b2e 0%,#070b12 70%);">
        <canvas id="tg-canvas" style="display:block;cursor:grab;"></canvas>
        <!-- Tooltip -->
        <div id="tg-tooltip" style="display:none;position:absolute;background:rgba(15,23,42,.95);border:1px solid #1e293b;border-radius:10px;padding:12px 14px;max-width:220px;pointer-events:none;z-index:100;box-shadow:0 8px 24px rgba(0,0,0,.5);"></div>
        <!-- Overlay badge -->
        <div style="position:absolute;top:12px;left:12px;background:rgba(15,23,42,.8);border:1px solid #1e293b;border-radius:8px;padding:8px 12px;font-size:11px;color:#475569;">
          <i class="fas fa-mouse-pointer" style="margin-right:5px;"></i>Click node for details · Drag to pan · Scroll to zoom
        </div>
      </div>
      <!-- Node Detail Panel -->
      <div id="tg-detail-panel" style="width:320px;background:#0f172a;border-left:1px solid #1e293b;overflow-y:auto;flex-shrink:0;transition:width .3s;">
        <div style="padding:20px;text-align:center;color:#475569;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <i class="fas fa-mouse-pointer" style="font-size:2rem;margin-bottom:12px;opacity:.3;"></i>
          <div style="font-size:13px;font-weight:600;color:#64748b;">Select a node</div>
          <div style="font-size:11px;color:#334155;margin-top:6px;">Click any node to view threat intelligence details</div>
        </div>
      </div>
    </div>
  </div>`;

  // Initialize canvas
  initThreatGraphCanvas();
  tgLoadData();
};

/* ════════════════════════════════════════════════════════════════
   DATA LOADING
════════════════════════════════════════════════════════════════ */
async function tgLoadData() {
  const countEl = document.getElementById('tg-node-count');
  if (countEl) countEl.textContent = 'Loading…';
  try {
    // Try loading from backend, fall back to seed data
    let nodes = [], edges = [];
    try {
      const data = await window.apiGet?.('/api/threat-graph') || { nodes: [], edges: [] };
      nodes = data.nodes || [];
      edges = data.edges || [];
    } catch (e) { /* Use seed data below */ }

    // Always supplement with built-in seed data if backend empty
    if (nodes.length === 0) {
      nodes = getSeedNodes();
      edges = getSeedEdges();
    }

    _tgState.nodes = nodes;
    _tgState.edges = edges;
    computeLayout();
    if (countEl) countEl.textContent = `${nodes.length} nodes · ${edges.length} edges`;
    drawGraph();
  } catch (e) {
    console.warn('[ThreatGraph] Load error:', e.message);
    _tgState.nodes = getSeedNodes();
    _tgState.edges = getSeedEdges();
    computeLayout();
    drawGraph();
  }
}

/* ════════════════════════════════════════════════════════════════
   SEED DATA (used when no backend data available)
════════════════════════════════════════════════════════════════ */
function getSeedNodes() {
  return [
    { node_id: 'apt28', node_type: 'threat_actor', label: 'APT28', region: 'EMEA', risk_score: 95, data: { country: 'Russia', motivation: 'Espionage', aliases: 'Fancy Bear, Sofacy', active: true, techniques: ['T1566', 'T1027', 'T1078'], campaigns: 3 } },
    { node_id: 'apt29', node_type: 'threat_actor', label: 'APT29', region: 'EMEA', risk_score: 93, data: { country: 'Russia', motivation: 'Espionage', aliases: 'Cozy Bear, Nobelium', active: true, techniques: ['T1566', 'T1195', 'T1550'], campaigns: 5 } },
    { node_id: 'lazarus', node_type: 'threat_actor', label: 'Lazarus Group', region: 'APAC', risk_score: 96, data: { country: 'North Korea', motivation: 'Financial, Espionage', aliases: 'Hidden Cobra, ZINC', active: true, techniques: ['T1059', 'T1486', 'T1041'], campaigns: 8 } },
    { node_id: 'apt41', node_type: 'threat_actor', label: 'APT41', region: 'APAC', risk_score: 91, data: { country: 'China', motivation: 'Espionage, Financial', aliases: 'Double Dragon, Winnti', active: true, techniques: ['T1190', 'T1505', 'T1048'], campaigns: 6 } },
    { node_id: 'carbanak', node_type: 'threat_actor', label: 'FIN7/Carbanak', region: 'EMEA', risk_score: 88, data: { country: 'Eastern Europe', motivation: 'Financial', aliases: 'Anunak, Cobalt Group', active: true, techniques: ['T1566', 'T1059', 'T1041'], campaigns: 4 } },
    { node_id: 'lockbit', node_type: 'malware', label: 'LockBit 3.0', region: null, risk_score: 97, data: { type: 'Ransomware', family: 'LockBit', first_seen: '2019', status: 'Active', iocs: ['*.lockbit extension', 'C2: proxied TOR'] } },
    { node_id: 'blackcat', node_type: 'malware', label: 'BlackCat/ALPHV', region: null, risk_score: 92, data: { type: 'Ransomware', family: 'ALPHV', first_seen: '2021', status: 'Active', iocs: ['*.alphv extension', 'RaaS portal'] } },
    { node_id: 'emotet', node_type: 'malware', label: 'Emotet', region: null, risk_score: 85, data: { type: 'Loader/Trojan', family: 'Emotet', first_seen: '2014', status: 'Active', iocs: ['emotet.exe', 'spam campaigns'] } },
    { node_id: 'cobalt-strike', node_type: 'malware', label: 'Cobalt Strike', region: null, risk_score: 82, data: { type: 'C2 Framework', family: 'CobaltStrike', first_seen: '2012', status: 'Active', iocs: ['Beacon DLL', 'malleable C2'] } },
    { node_id: 'sunburst', node_type: 'malware', label: 'SUNBURST', region: null, risk_score: 94, data: { type: 'Backdoor', family: 'SolarWinds', first_seen: '2020', status: 'Historic', iocs: ['SolarWinds.Orion.Core.BusinessLayer.dll'] } },
    { node_id: 't1566', node_type: 'technique', label: 'T1566: Phishing', region: null, risk_score: 90, data: { tactic: 'Initial Access', mitre_id: 'T1566', description: 'Adversary sends phishing messages to gain access' } },
    { node_id: 't1055', node_type: 'technique', label: 'T1055: Process Injection', region: null, risk_score: 85, data: { tactic: 'Defense Evasion', mitre_id: 'T1055', description: 'Inject code into running processes' } },
    { node_id: 't1059', node_type: 'technique', label: 'T1059: Scripting', region: null, risk_score: 88, data: { tactic: 'Execution', mitre_id: 'T1059', description: 'Execute commands via scripting interpreters' } },
    { node_id: 't1486', node_type: 'technique', label: 'T1486: Data Encrypted', region: null, risk_score: 95, data: { tactic: 'Impact', mitre_id: 'T1486', description: 'Encrypt data for impact (ransomware)' } },
    { node_id: 'reg-apac', node_type: 'region', label: 'APAC', region: 'APAC', risk_score: 85, data: { countries: 'China, North Korea, Japan, South Korea', active_actors: 2, threat_level: 'High' } },
    { node_id: 'reg-emea', node_type: 'region', label: 'EMEA', region: 'EMEA', risk_score: 80, data: { countries: 'Russia, Ukraine, Iran, UK, Germany', active_actors: 3, threat_level: 'High' } },
    { node_id: 'reg-amer', node_type: 'region', label: 'Americas', region: 'AMER', risk_score: 70, data: { countries: 'USA, Brazil, Colombia', active_actors: 1, threat_level: 'Medium' } },
    { node_id: 'finance', node_type: 'target_sector', label: 'Financial', region: null, risk_score: 90, data: { description: 'Banks, payment processors, fintech', primary_threats: 'Lazarus, FIN7, Carbanak' } },
    { node_id: 'govt', node_type: 'target_sector', label: 'Government', region: null, risk_score: 85, data: { description: 'Federal and state government agencies', primary_threats: 'APT28, APT29' } },
    { node_id: 'healthcare', node_type: 'target_sector', label: 'Healthcare', region: null, risk_score: 82, data: { description: 'Hospitals, research, pharma', primary_threats: 'LockBit, APT41' } },
  ];
}
function getSeedEdges() {
  return [
    { source_node: 'apt28', target_node: 'sunburst', relationship: 'deploys', weight: 0.8 },
    { source_node: 'apt29', target_node: 'sunburst', relationship: 'deploys', weight: 0.95 },
    { source_node: 'apt29', target_node: 'cobalt-strike', relationship: 'uses', weight: 0.9 },
    { source_node: 'lazarus', target_node: 'lockbit', relationship: 'deploys', weight: 0.7 },
    { source_node: 'lazarus', target_node: 'blackcat', relationship: 'deploys', weight: 0.8 },
    { source_node: 'apt41', target_node: 'cobalt-strike', relationship: 'uses', weight: 0.85 },
    { source_node: 'carbanak', target_node: 'emotet', relationship: 'distributes', weight: 0.75 },
    { source_node: 'apt28', target_node: 't1566', relationship: 'uses', weight: 0.95 },
    { source_node: 'apt29', target_node: 't1566', relationship: 'uses', weight: 0.9 },
    { source_node: 'carbanak', target_node: 't1566', relationship: 'uses', weight: 0.85 },
    { source_node: 'lazarus', target_node: 't1059', relationship: 'uses', weight: 0.85 },
    { source_node: 'lockbit', target_node: 't1486', relationship: 'employs', weight: 1.0 },
    { source_node: 'lockbit', target_node: 't1055', relationship: 'employs', weight: 0.75 },
    { source_node: 'apt28', target_node: 'reg-emea', relationship: 'originates', weight: 1.0 },
    { source_node: 'apt29', target_node: 'reg-emea', relationship: 'originates', weight: 1.0 },
    { source_node: 'carbanak', target_node: 'reg-emea', relationship: 'originates', weight: 0.8 },
    { source_node: 'lazarus', target_node: 'reg-apac', relationship: 'originates', weight: 1.0 },
    { source_node: 'apt41', target_node: 'reg-apac', relationship: 'originates', weight: 1.0 },
    { source_node: 'lazarus', target_node: 'finance', relationship: 'targets', weight: 0.95 },
    { source_node: 'carbanak', target_node: 'finance', relationship: 'targets', weight: 0.95 },
    { source_node: 'apt28', target_node: 'govt', relationship: 'targets', weight: 0.9 },
    { source_node: 'apt29', target_node: 'govt', relationship: 'targets', weight: 0.9 },
    { source_node: 'lockbit', target_node: 'healthcare', relationship: 'targets', weight: 0.8 },
    { source_node: 'apt41', target_node: 'healthcare', relationship: 'targets', weight: 0.7 },
  ];
}

/* ════════════════════════════════════════════════════════════════
   LAYOUT COMPUTATION — Force-directed-like circular layout
════════════════════════════════════════════════════════════════ */
function computeLayout() {
  const canvas = document.getElementById('tg-canvas');
  if (!canvas) return;
  const W = canvas.offsetWidth || 900;
  const H = canvas.offsetHeight || 600;
  const cx = W / 2, cy = H / 2;

  // Group nodes by type for radial placement
  const groups = {};
  for (const node of _tgState.nodes) {
    if (!groups[node.node_type]) groups[node.node_type] = [];
    groups[node.node_type].push(node);
  }

  const typeOrder = ['region', 'threat_actor', 'malware', 'technique', 'target_sector', 'infrastructure', 'campaign'];
  const radii = [100, 200, 260, 320, 350, 380, 200];

  let posIdx = 0;
  for (const type of typeOrder) {
    const group = groups[type] || [];
    const r = radii[typeOrder.indexOf(type)] || 250;
    group.forEach((node, i) => {
      const angle = (2 * Math.PI / Math.max(group.length, 1)) * i + (posIdx * 0.5);
      _tgState.positions.set(node.node_id, {
        x: cx + r * Math.cos(angle) + (Math.random() - 0.5) * 30,
        y: cy + r * Math.sin(angle) + (Math.random() - 0.5) * 30,
        vx: 0, vy: 0,
      });
      posIdx++;
    });
  }
}

/* ════════════════════════════════════════════════════════════════
   CANVAS INIT & DRAW
════════════════════════════════════════════════════════════════ */
function initThreatGraphCanvas() {
  const wrap = document.getElementById('tg-canvas-wrap');
  const canvas = document.getElementById('tg-canvas');
  if (!wrap || !canvas) return;

  function resize() {
    canvas.width  = wrap.offsetWidth;
    canvas.height = wrap.offsetHeight;
    drawGraph();
  }
  resize();
  window.addEventListener('resize', resize);

  // Mouse events
  canvas.addEventListener('mousedown', tgOnMouseDown);
  canvas.addEventListener('mousemove', tgOnMouseMove);
  canvas.addEventListener('mouseup', tgOnMouseUp);
  canvas.addEventListener('wheel', tgOnWheel, { passive: true });
  canvas.addEventListener('click', tgOnClick);
}

function drawGraph() {
  const canvas = document.getElementById('tg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;

  ctx.clearRect(0, 0, W, H);

  // Apply transform
  ctx.save();
  ctx.translate(_tgState.pan.x, _tgState.pan.y);
  ctx.scale(_tgState.zoom, _tgState.zoom);

  // Filter nodes
  const visibleNodes = getVisibleNodes();
  const visibleIds = new Set(visibleNodes.map(n => n.node_id));

  // Draw edges
  for (const edge of _tgState.edges) {
    if (!visibleIds.has(edge.source_node) || !visibleIds.has(edge.target_node)) continue;
    const srcPos = _tgState.positions.get(edge.source_node);
    const tgtPos = _tgState.positions.get(edge.target_node);
    if (!srcPos || !tgtPos) continue;

    const alpha = (edge.weight || 0.5) * 0.5;
    ctx.strokeStyle = `rgba(34,211,238,${alpha})`;
    ctx.lineWidth = (edge.weight || 0.5) * 1.5;

    ctx.beginPath();
    ctx.moveTo(srcPos.x, srcPos.y);

    // Curved line
    const mx = (srcPos.x + tgtPos.x) / 2;
    const my = (srcPos.y + tgtPos.y) / 2;
    const dx = tgtPos.x - srcPos.x, dy = tgtPos.y - srcPos.y;
    const cpx = mx - dy * 0.15, cpy = my + dx * 0.15;
    ctx.quadraticCurveTo(cpx, cpy, tgtPos.x, tgtPos.y);
    ctx.stroke();

    // Arrow
    const angle = Math.atan2(tgtPos.y - cpy, tgtPos.x - cpx);
    const cfg = NODE_CONFIG[_tgState.nodes.find(n => n.node_id === edge.target_node)?.node_type] || { size: 36 };
    const arrowX = tgtPos.x - Math.cos(angle) * (cfg.size / 2 + 4);
    const arrowY = tgtPos.y - Math.sin(angle) * (cfg.size / 2 + 4);
    ctx.fillStyle = `rgba(34,211,238,${alpha * 1.5})`;
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(arrowX - 8 * Math.cos(angle - 0.4), arrowY - 8 * Math.sin(angle - 0.4));
    ctx.lineTo(arrowX - 8 * Math.cos(angle + 0.4), arrowY - 8 * Math.sin(angle + 0.4));
    ctx.closePath();
    ctx.fill();

    // Relationship label
    const lx = (srcPos.x + tgtPos.x) / 2, ly = (srcPos.y + tgtPos.y) / 2;
    ctx.fillStyle = `rgba(100,116,139,${alpha * 2})`;
    ctx.font = `${Math.round(9 / _tgState.zoom)}px Inter,sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(edge.relationship, lx, ly);
  }

  // Draw nodes
  for (const node of visibleNodes) {
    const pos = _tgState.positions.get(node.node_id);
    if (!pos) continue;
    const cfg = NODE_CONFIG[node.node_type] || NODE_CONFIG.infrastructure;
    const r = cfg.size / 2;
    const isSelected = _tgState.selectedNode?.node_id === node.node_id;
    const isSearch = _tgState.filter.search && node.label.toLowerCase().includes(_tgState.filter.search.toLowerCase());

    // Glow for selected/searched
    if (isSelected || isSearch) {
      ctx.shadowColor = isSelected ? '#22d3ee' : '#f59e0b';
      ctx.shadowBlur = 20;
    }

    // Circle background
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);
    ctx.fillStyle = isSelected ? cfg.border + '40' : cfg.bg;
    ctx.fill();

    // Border
    ctx.strokeStyle = isSelected ? cfg.color : cfg.border + '90';
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.stroke();

    // Reset glow
    ctx.shadowBlur = 0;

    // Icon emoji
    ctx.font = `${Math.round(r * 0.8)}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(cfg.icon, pos.x, pos.y);

    // Label
    const labelSize = Math.max(9, Math.round(11 / _tgState.zoom));
    ctx.font = `600 ${labelSize}px Inter,sans-serif`;
    ctx.fillStyle = isSelected ? '#f1f5f9' : '#94a3b8';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const labelY = pos.y + r + 5;
    ctx.fillText(node.label.length > 14 ? node.label.slice(0, 14) + '…' : node.label, pos.x, labelY);

    // Risk score mini badge
    if (node.risk_score >= 90) {
      ctx.beginPath();
      ctx.arc(pos.x + r * 0.7, pos.y - r * 0.7, 7, 0, Math.PI * 2);
      ctx.fillStyle = '#ef4444';
      ctx.fill();
      ctx.font = `bold 8px Inter`;
      ctx.fillStyle = '#fff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('!', pos.x + r * 0.7, pos.y - r * 0.7);
    }
  }

  ctx.restore();
}

/* ════════════════════════════════════════════════════════════════
   FILTER VISIBLE NODES
════════════════════════════════════════════════════════════════ */
function getVisibleNodes() {
  return _tgState.nodes.filter(n => {
    if (_tgState.filter.type && n.node_type !== _tgState.filter.type) return false;
    if (_tgState.filter.region && n.region && n.region !== _tgState.filter.region) return false;
    if (_tgState.filter.search && !n.label.toLowerCase().includes(_tgState.filter.search.toLowerCase())) {
      // still show if connected to matching node
      return false;
    }
    return true;
  });
}

/* ════════════════════════════════════════════════════════════════
   MOUSE INTERACTION
════════════════════════════════════════════════════════════════ */
function getCanvasCoords(e) {
  const canvas = document.getElementById('tg-canvas');
  const rect = canvas.getBoundingClientRect();
  return {
    x: (e.clientX - rect.left - _tgState.pan.x) / _tgState.zoom,
    y: (e.clientY - rect.top  - _tgState.pan.y) / _tgState.zoom,
  };
}

function findNodeAtCoords(x, y) {
  for (const node of _tgState.nodes) {
    const pos = _tgState.positions.get(node.node_id);
    if (!pos) continue;
    const cfg = NODE_CONFIG[node.node_type] || { size: 36 };
    const r = cfg.size / 2 + 4;
    const dx = x - pos.x, dy = y - pos.y;
    if (dx * dx + dy * dy < r * r) return node;
  }
  return null;
}

function tgOnMouseDown(e) {
  const { x, y } = getCanvasCoords(e);
  const node = findNodeAtCoords(x, y);
  if (node) {
    _tgState.dragNode = node;
  } else {
    _tgState.dragging = true;
    _tgState.mouseStart = { x: e.clientX - _tgState.pan.x, y: e.clientY - _tgState.pan.y };
  }
  e.currentTarget.style.cursor = 'grabbing';
}
function tgOnMouseMove(e) {
  if (_tgState.dragging && _tgState.mouseStart) {
    _tgState.pan.x = e.clientX - _tgState.mouseStart.x;
    _tgState.pan.y = e.clientY - _tgState.mouseStart.y;
    drawGraph();
  } else if (_tgState.dragNode) {
    const { x, y } = getCanvasCoords(e);
    _tgState.positions.set(_tgState.dragNode.node_id, { x, y, vx: 0, vy: 0 });
    drawGraph();
  } else {
    // Tooltip on hover
    const { x, y } = getCanvasCoords(e);
    const node = findNodeAtCoords(x, y);
    const tooltip = document.getElementById('tg-tooltip');
    if (tooltip) {
      if (node) {
        const canvas = document.getElementById('tg-canvas');
        const rect = canvas.getBoundingClientRect();
        tooltip.style.display = 'block';
        tooltip.style.left = (e.clientX - rect.left + 12) + 'px';
        tooltip.style.top  = (e.clientY - rect.top  + 12) + 'px';
        const cfg = NODE_CONFIG[node.node_type] || NODE_CONFIG.infrastructure;
        tooltip.innerHTML = `
        <div style="font-size:10px;color:${cfg.color};font-weight:700;text-transform:uppercase;margin-bottom:4px;">${cfg.label}</div>
        <div style="font-size:13px;font-weight:700;color:#e2e8f0;">${node.label}</div>
        ${node.region ? `<div style="font-size:11px;color:#64748b;margin-top:2px;"><i class="fas fa-globe"></i> ${node.region}</div>` : ''}
        <div style="font-size:11px;color:#ef4444;margin-top:4px;">Risk: ${node.risk_score}/100</div>
        <div style="font-size:10px;color:#475569;margin-top:4px;">Click for details</div>`;
        e.currentTarget.style.cursor = 'pointer';
      } else {
        tooltip.style.display = 'none';
        e.currentTarget.style.cursor = _tgState.dragging ? 'grabbing' : 'grab';
      }
    }
  }
}
function tgOnMouseUp(e) {
  _tgState.dragging = false;
  _tgState.dragNode = null;
  _tgState.mouseStart = null;
  e.currentTarget.style.cursor = 'grab';
}
function tgOnWheel(e) {
  const delta = e.deltaY > 0 ? -0.1 : 0.1;
  tgZoom(delta);
}
function tgOnClick(e) {
  const { x, y } = getCanvasCoords(e);
  const node = findNodeAtCoords(x, y);
  if (node) {
    _tgState.selectedNode = node;
    drawGraph();
    renderNodeDetail(node);
  }
}

/* ════════════════════════════════════════════════════════════════
   ZOOM & PAN
════════════════════════════════════════════════════════════════ */
window.tgZoom = function(delta) {
  _tgState.zoom = Math.max(0.3, Math.min(3, _tgState.zoom + delta));
  drawGraph();
};
window.tgResetView = function() {
  _tgState.zoom = 1;
  _tgState.pan  = { x: 0, y: 0 };
  drawGraph();
};

/* ════════════════════════════════════════════════════════════════
   FILTER CONTROLS
════════════════════════════════════════════════════════════════ */
window.tgFilterType = function(type) {
  _tgState.filter.type = _tgState.filter.type === type ? '' : type;
  document.querySelectorAll('[id^="legend-"]').forEach(el => el.style.borderColor = '#1e293b');
  if (_tgState.filter.type) {
    const el = document.getElementById(`legend-${type}`);
    if (el) el.style.borderColor = NODE_CONFIG[type]?.color || '#22d3ee';
  }
  drawGraph();
};
window.tgClearFilter = function() {
  _tgState.filter = { type: '', region: '', search: '' };
  document.querySelectorAll('[id^="legend-"]').forEach(el => el.style.borderColor = '#1e293b');
  const rf = document.getElementById('tg-region-filter');
  const sr = document.getElementById('tg-search');
  if (rf) rf.value = '';
  if (sr) sr.value = '';
  drawGraph();
};
window.tgFilterRegion = function(region) {
  _tgState.filter.region = region;
  drawGraph();
};
window.tgSearchNodes = function(q) {
  _tgState.filter.search = q;
  drawGraph();
  if (q) {
    const match = _tgState.nodes.find(n => n.label.toLowerCase().includes(q.toLowerCase()));
    if (match) {
      _tgState.selectedNode = match;
      renderNodeDetail(match);
    }
  }
};

/* ════════════════════════════════════════════════════════════════
   NODE DETAIL PANEL
════════════════════════════════════════════════════════════════ */
function renderNodeDetail(node) {
  const panel = document.getElementById('tg-detail-panel');
  if (!panel) return;
  const cfg = NODE_CONFIG[node.node_type] || NODE_CONFIG.infrastructure;
  const d   = node.data || {};

  // Find related nodes
  const relatedEdges = _tgState.edges.filter(e => e.source_node === node.node_id || e.target_node === node.node_id);
  const relatedIds   = new Set(relatedEdges.flatMap(e => [e.source_node, e.target_node]).filter(id => id !== node.node_id));
  const relatedNodes = _tgState.nodes.filter(n => relatedIds.has(n.node_id));

  panel.innerHTML = `
  <div style="padding:20px;">
    <!-- Node header -->
    <div style="background:${cfg.bg};border:1px solid ${cfg.border}40;border-radius:12px;padding:18px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <div style="width:40px;height:40px;background:${cfg.border}20;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;">${cfg.icon}</div>
        <div>
          <div style="font-size:10px;color:${cfg.color};font-weight:700;text-transform:uppercase;letter-spacing:.5px;">${cfg.label}</div>
          <div style="font-size:15px;font-weight:800;color:#f1f5f9;line-height:1.2;">${node.label}</div>
        </div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;color:#64748b;">${node.region || 'Global'}</span>
        <div style="background:${node.risk_score >= 90 ? '#ef4444' : node.risk_score >= 70 ? '#f97316' : '#22c55e'}20;color:${node.risk_score >= 90 ? '#ef4444' : node.risk_score >= 70 ? '#f97316' : '#22c55e'};border-radius:8px;padding:3px 8px;font-size:11px;font-weight:700;">
          Risk: ${node.risk_score}/100
        </div>
      </div>
    </div>

    <!-- Intelligence Data -->
    <div style="margin-bottom:16px;">
      <div style="font-size:11px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:10px;">Intelligence</div>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${Object.entries(d).slice(0, 8).map(([k, v]) => {
          if (typeof v === 'boolean') return '';
          if (typeof v === 'object') return '';
          return `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;padding:8px 10px;background:#090d14;border-radius:6px;">
            <span style="font-size:11px;color:#475569;text-transform:capitalize;flex-shrink:0;">${k.replace(/_/g,' ')}</span>
            <span style="font-size:11px;color:#cbd5e1;text-align:right;">${v}</span>
          </div>`;
        }).join('')}
      </div>
    </div>

    <!-- Related Nodes -->
    ${relatedNodes.length > 0 ? `
    <div style="margin-bottom:16px;">
      <div style="font-size:11px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:10px;">
        Relationships (${relatedNodes.length})
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;max-height:200px;overflow-y:auto;">
        ${relatedNodes.map(rn => {
          const edge = relatedEdges.find(e => (e.source_node === rn.node_id && e.target_node === node.node_id) || (e.source_node === node.node_id && e.target_node === rn.node_id));
          const rCfg = NODE_CONFIG[rn.node_type] || NODE_CONFIG.infrastructure;
          return `<div onclick="tgFocusNode('${rn.node_id}')" style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:#090d14;border-radius:6px;cursor:pointer;transition:.15s;"
            onmouseover="this.style.background='#1e293b'" onmouseout="this.style.background='#090d14'">
            <span style="font-size:14px;">${rCfg.icon}</span>
            <div style="flex:1;min-width:0;">
              <div style="font-size:12px;font-weight:600;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${rn.label}</div>
              <div style="font-size:10px;color:#475569;">${edge?.relationship || 'related'}</div>
            </div>
            <div style="font-size:9px;color:${rCfg.color};flex-shrink:0;">${rCfg.label}</div>
          </div>`;
        }).join('')}
      </div>
    </div>` : ''}

    <!-- External links -->
    ${node.node_type === 'threat_actor' ? `
    <a href="https://attack.mitre.org/groups/" target="_blank" rel="noopener"
      style="display:block;background:#1e293b;color:#22d3ee;text-decoration:none;padding:10px;border-radius:8px;text-align:center;font-size:12px;font-weight:600;">
      <i class="fas fa-external-link-alt" style="margin-right:5px;"></i>View on MITRE ATT&CK
    </a>` : ''}
    ${node.node_type === 'technique' && d.mitre_id ? `
    <a href="https://attack.mitre.org/techniques/${d.mitre_id.replace('.','/')}/" target="_blank" rel="noopener"
      style="display:block;background:#1e293b;color:#22d3ee;text-decoration:none;padding:10px;border-radius:8px;text-align:center;font-size:12px;font-weight:600;">
      <i class="fas fa-external-link-alt" style="margin-right:5px;"></i>${d.mitre_id} — MITRE ATT&CK
    </a>` : ''}
  </div>`;
}

window.tgFocusNode = function(nodeId) {
  const node = _tgState.nodes.find(n => n.node_id === nodeId);
  if (!node) return;
  const pos = _tgState.positions.get(nodeId);
  if (pos) {
    const canvas = document.getElementById('tg-canvas');
    if (canvas) {
      _tgState.pan.x = canvas.width / 2 - pos.x * _tgState.zoom;
      _tgState.pan.y = canvas.height / 2 - pos.y * _tgState.zoom;
    }
  }
  _tgState.selectedNode = node;
  drawGraph();
  renderNodeDetail(node);
};
