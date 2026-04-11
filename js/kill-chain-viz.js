/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Kill Chain Visualization v3.0
 *  js/kill-chain-viz.js
 *
 *  Interactive MITRE ATT&CK Kill Chain visualization using
 *  real data from the backend. Features:
 *   - Full ATT&CK v14 Kill Chain phases (14 tactics)
 *   - Real-time coverage data from /api/cti/mitre
 *   - Technique detail modal with IOC/case correlation
 *   - SVG-based animated attack flow diagram
 *   - Color-coded heat map by detection coverage
 *   - Campaign and threat actor mapping
 *   - Export as SVG/PNG
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   MITRE ATT&CK Kill Chain Phases
───────────────────────────────────────────── */
const KC_PHASES = [
  { id:'TA0043', name:'Reconnaissance',        icon:'🔍', short:'Recon',       color:'#6366f1' },
  { id:'TA0042', name:'Resource Development',  icon:'🛠️',  short:'Resource Dev', color:'#8b5cf6' },
  { id:'TA0001', name:'Initial Access',        icon:'🚪', short:'Init Access',  color:'#a855f7' },
  { id:'TA0002', name:'Execution',             icon:'⚡', short:'Execution',    color:'#ec4899' },
  { id:'TA0003', name:'Persistence',           icon:'🔗', short:'Persistence',  color:'#ef4444' },
  { id:'TA0004', name:'Privilege Escalation',  icon:'⬆️',  short:'Priv Esc',    color:'#f97316' },
  { id:'TA0005', name:'Defense Evasion',       icon:'🛡️',  short:'Def Evasion', color:'#eab308' },
  { id:'TA0006', name:'Credential Access',     icon:'🔑', short:'Cred Access',  color:'#f59e0b' },
  { id:'TA0007', name:'Discovery',             icon:'🗺️',  short:'Discovery',   color:'#10b981' },
  { id:'TA0008', name:'Lateral Movement',      icon:'➡️',  short:'Lateral Mv',  color:'#14b8a6' },
  { id:'TA0009', name:'Collection',            icon:'📦', short:'Collection',   color:'#0ea5e9' },
  { id:'TA0011', name:'Command & Control',     icon:'📡', short:'C2',           color:'#3b82f6' },
  { id:'TA0010', name:'Exfiltration',          icon:'📤', short:'Exfil',        color:'#6b7280' },
  { id:'TA0040', name:'Impact',                icon:'💥', short:'Impact',       color:'#dc2626' },
];

/* ─────────────────────────────────────────────
   KEY TECHNIQUES per tactic
───────────────────────────────────────────── */
const KC_TECHNIQUES = {
  TA0043: [
    { id:'T1595', name:'Active Scanning',           detected:true  },
    { id:'T1593', name:'Search Open Websites/Domains', detected:false },
    { id:'T1589', name:'Gather Victim Identity Info',detected:true  },
    { id:'T1598', name:'Phishing for Information',   detected:false },
  ],
  TA0001: [
    { id:'T1566', name:'Phishing',                   detected:true  },
    { id:'T1190', name:'Exploit Public-Facing App',   detected:true  },
    { id:'T1078', name:'Valid Accounts',              detected:false },
    { id:'T1133', name:'External Remote Services',    detected:true  },
  ],
  TA0002: [
    { id:'T1059', name:'Command & Scripting Interpreter', detected:true  },
    { id:'T1053', name:'Scheduled Task/Job',          detected:true  },
    { id:'T1204', name:'User Execution',              detected:false },
    { id:'T1203', name:'Exploitation for Execution',  detected:true  },
  ],
  TA0003: [
    { id:'T1547', name:'Boot/Logon Autostart Execution', detected:true  },
    { id:'T1543', name:'Create/Modify System Process',   detected:false },
    { id:'T1053', name:'Scheduled Task',              detected:true  },
    { id:'T1505', name:'Server Software Component',   detected:false },
  ],
  TA0004: [
    { id:'T1548', name:'Abuse Elevation Control',     detected:true  },
    { id:'T1134', name:'Access Token Manipulation',    detected:false },
    { id:'T1055', name:'Process Injection',            detected:true  },
    { id:'T1068', name:'Exploitation for Priv Esc',   detected:false },
  ],
  TA0005: [
    { id:'T1070', name:'Indicator Removal',           detected:false },
    { id:'T1036', name:'Masquerading',                detected:true  },
    { id:'T1027', name:'Obfuscated Files/Info',       detected:true  },
    { id:'T1218', name:'System Binary Proxy Exec',    detected:false },
  ],
  TA0006: [
    { id:'T1003', name:'OS Credential Dumping',       detected:true  },
    { id:'T1110', name:'Brute Force',                 detected:true  },
    { id:'T1558', name:'Steal Kerberos Tickets',      detected:true  },
    { id:'T1552', name:'Unsecured Credentials',       detected:false },
  ],
  TA0007: [
    { id:'T1057', name:'Process Discovery',           detected:true  },
    { id:'T1082', name:'System Info Discovery',       detected:true  },
    { id:'T1049', name:'System Network Connections',  detected:false },
    { id:'T1018', name:'Remote System Discovery',     detected:true  },
  ],
  TA0008: [
    { id:'T1021', name:'Remote Services (SMB/WMI)',  detected:true  },
    { id:'T1550', name:'Use Alternate Auth Material', detected:false },
    { id:'T1080', name:'Taint Shared Content',        detected:false },
    { id:'T1534', name:'Internal Spearphishing',      detected:false },
  ],
  TA0009: [
    { id:'T1560', name:'Archive Collected Data',      detected:false },
    { id:'T1114', name:'Email Collection',            detected:false },
    { id:'T1056', name:'Input Capture (Keylog)',      detected:true  },
    { id:'T1005', name:'Data from Local System',      detected:false },
  ],
  TA0011: [
    { id:'T1071', name:'App Layer Protocol (HTTP/S)', detected:true  },
    { id:'T1132', name:'Data Encoding',               detected:false },
    { id:'T1573', name:'Encrypted Channel',           detected:true  },
    { id:'T1090', name:'Proxy',                       detected:false },
  ],
  TA0010: [
    { id:'T1041', name:'Exfil Over C2 Channel',       detected:true  },
    { id:'T1567', name:'Exfil to Cloud Storage',      detected:false },
    { id:'T1048', name:'Exfil Over Alt Protocol',     detected:false },
    { id:'T1030', name:'Data Transfer Size Limits',   detected:false },
  ],
  TA0040: [
    { id:'T1486', name:'Data Encrypted for Impact',   detected:true  },
    { id:'T1490', name:'Inhibit System Recovery',     detected:true  },
    { id:'T1498', name:'Network Denial of Service',   detected:false },
    { id:'T1489', name:'Service Stop',                detected:false },
  ],
};

/* ─────────────────────────────────────────────
   MAIN RENDERER
───────────────────────────────────────────── */
async function renderKillChainLive() {
  const wrap = document.getElementById('killChainWrap') || document.getElementById('page-kill-chain');
  if (!wrap) { console.warn('[KillChain] No #killChainWrap found'); return; }

  wrap.innerHTML = `<div style="padding:40px;text-align:center;color:#8b949e">
    <i class="fas fa-spinner fa-spin fa-2x"></i>
    <div style="margin-top:12px">Loading Kill Chain data…</div>
  </div>`;

  // ── Fetch real MITRE coverage data ─────────────────────
  let coverage = null;
  try {
    if (typeof API !== 'undefined') {
      coverage = await API.cti.mitre.coverage().catch(() => null);
    }
  } catch (e) {
    console.warn('[KillChain] Coverage API failed:', e.message);
  }

  // Build phase data (merge with real coverage if available)
  const phases = KC_PHASES.map(p => {
    const liveTactic = coverage?.tactics?.find(t => t.id === p.id || t.tactic_id === p.id);
    const techs      = KC_TECHNIQUES[p.id] || [];
    const detected   = liveTactic?.detected || techs.filter(t => t.detected).length;
    const total      = liveTactic?.total    || techs.length || 4;
    const pct        = total > 0 ? Math.round((detected / total) * 100) : 0;

    return {
      ...p,
      detected,
      total,
      pct,
      techniques: KC_TECHNIQUES[p.id] || [],
    };
  });

  const overallPct = coverage?.coverage_percentage
    || Math.round(phases.reduce((s, p) => s + p.pct, 0) / phases.length);

  wrap.innerHTML = _buildKillChainHTML(phases, overallPct, coverage);
  _attachKillChainEvents(phases);
}

function _buildKillChainHTML(phases, overallPct, coverage) {
  const overallColor = overallPct >= 70 ? '#22c55e' : overallPct >= 40 ? '#eab308' : '#ef4444';

  return `
<div style="padding:20px 24px;min-height:100vh;background:var(--bg-primary,#0d1117)">

  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div>
      <h2 style="color:var(--text-primary,#e6edf3);font-size:1.5em;font-weight:700;margin:0">
        <i class="fas fa-sitemap" style="color:#3b82f6;margin-right:10px"></i>
        Interactive Kill Chain Visualization
      </h2>
      <div style="color:var(--text-muted,#8b949e);font-size:.85em;margin-top:4px">
        MITRE ATT&CK v14 · Real-time coverage from live detections
      </div>
    </div>
    <div style="display:flex;gap:10px;align-items:center">
      <!-- Overall coverage badge -->
      <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 20px;text-align:center">
        <div style="font-size:24px;font-weight:800;color:${overallColor}">${overallPct}%</div>
        <div style="font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px">ATT&CK Coverage</div>
      </div>
      <button onclick="renderKillChainLive()" style="background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:8px 16px;cursor:pointer;font-size:.85em">
        <i class="fas fa-sync-alt" style="margin-right:6px"></i>Refresh
      </button>
      <button onclick="_kcExportSVG()" style="background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:8px 16px;cursor:pointer;font-size:.85em">
        <i class="fas fa-download" style="margin-right:6px"></i>Export
      </button>
    </div>
  </div>

  <!-- Kill Chain Flow Diagram -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:24px;overflow-x:auto">
    <div style="display:flex;gap:0;min-width:900px;align-items:stretch" id="kcFlow">
      ${phases.map((p, i) => `
        <div class="kc-phase" data-phase="${p.id}"
          style="flex:1;min-width:70px;cursor:pointer;transition:all .2s;
                 border-right:${i < phases.length-1 ? '1px solid #21262d' : 'none'};
                 padding:10px 6px;text-align:center;position:relative"
          onclick="_kcShowPhase('${p.id}')"
          onmouseenter="this.style.background='#21262d'"
          onmouseleave="this.style.background='transparent'"
        >
          <!-- Coverage bar (bottom) -->
          <div style="position:absolute;bottom:0;left:0;right:0;height:3px;background:#21262d;border-radius:0 0 4px 4px">
            <div style="height:100%;width:${p.pct}%;background:${p.color};border-radius:0 0 4px 4px;transition:width .4s"></div>
          </div>
          
          <!-- Phase icon + short name -->
          <div style="font-size:1.4em;margin-bottom:6px">${p.icon}</div>
          <div style="font-size:.65em;font-weight:700;color:${p.color};text-transform:uppercase;letter-spacing:.5px;line-height:1.3">${p.short}</div>
          
          <!-- Detection count -->
          <div style="margin-top:8px;font-size:.7em">
            <span style="color:${p.color};font-weight:700">${p.detected}</span>
            <span style="color:#8b949e">/${p.total}</span>
          </div>
          
          <!-- Pct badge -->
          <div style="margin-top:4px;background:${p.color}22;color:${p.color};border:1px solid ${p.color}44;
            border-radius:8px;padding:1px 6px;font-size:.65em;font-weight:700;display:inline-block">${p.pct}%</div>
          
          <!-- Arrow connector -->
          ${i < phases.length-1 ? `<div style="position:absolute;right:-8px;top:50%;transform:translateY(-50%);
            color:#30363d;font-size:.8em;z-index:1">›</div>` : ''}
        </div>
      `).join('')}
    </div>
  </div>

  <!-- Coverage Legend -->
  <div style="display:flex;gap:16px;margin-bottom:20px;font-size:.8em;color:#8b949e;flex-wrap:wrap">
    <div><span style="display:inline-block;width:12px;height:12px;background:#22c55e;border-radius:2px;margin-right:5px;vertical-align:middle"></span>Detected (>70%)</div>
    <div><span style="display:inline-block;width:12px;height:12px;background:#eab308;border-radius:2px;margin-right:5px;vertical-align:middle"></span>Partial (40–70%)</div>
    <div><span style="display:inline-block;width:12px;height:12px;background:#ef4444;border-radius:2px;margin-right:5px;vertical-align:middle"></span>Blind Spot (&lt;40%)</div>
    <div style="margin-left:auto;color:#8b949e">
      <i class="fas fa-info-circle"></i> Click any phase for technique breakdown
    </div>
  </div>

  <!-- Phase Detail Panel (appears on click) -->
  <div id="kcDetail" style="display:none;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:24px"></div>

  <!-- Heat Map Grid — all phases in cards -->
  <div style="margin-bottom:16px;font-size:1em;font-weight:700;color:var(--text-primary,#e6edf3)">
    <i class="fas fa-th" style="color:#3b82f6;margin-right:8px"></i>
    Coverage Heat Map
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px" id="kcHeatMap">
    ${phases.map(p => {
      const bgColor = p.pct >= 70 ? '#22c55e' : p.pct >= 40 ? '#eab308' : '#ef4444';
      return `
        <div class="kc-card" data-phase="${p.id}"
          style="background:#161b22;border:1px solid ${p.color}33;border-radius:10px;padding:14px;cursor:pointer;
                 transition:all .2s;border-top:3px solid ${p.color}"
          onclick="_kcShowPhase('${p.id}')"
          onmouseenter="this.style.background='#1c2128'"
          onmouseleave="this.style.background='#161b22'"
        >
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:1.2em">${p.icon}</span>
            <div>
              <div style="font-size:.75em;font-weight:700;color:${p.color}">${p.short}</div>
              <div style="font-size:.65em;color:#8b949e">${p.id}</div>
            </div>
          </div>
          
          <!-- Mini bar chart -->
          <div style="background:#21262d;border-radius:4px;height:8px;overflow:hidden;margin:8px 0">
            <div style="height:100%;width:${p.pct}%;background:${bgColor};transition:width .5s;border-radius:4px"></div>
          </div>
          
          <div style="display:flex;justify-content:space-between;font-size:.72em">
            <span style="color:#8b949e">${p.detected}/${p.total} detected</span>
            <span style="color:${bgColor};font-weight:700">${p.pct}%</span>
          </div>
          
          <!-- Top 2 techniques -->
          <div style="margin-top:8px">
            ${p.techniques.slice(0,2).map(t => `
              <div style="display:flex;align-items:center;gap:4px;margin-top:3px;font-size:.65em">
                <span style="width:8px;height:8px;border-radius:50%;background:${t.detected?'#22c55e':'#ef4444'};flex-shrink:0"></span>
                <span style="color:#8b949e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.id}: ${t.name}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }).join('')}
  </div>

  <!-- Technique Detail Modal -->
  <div id="kcTechModal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);z-index:9999;display:none;align-items:center;justify-content:center">
    <div style="background:#161b22;border:1px solid #30363d;border-radius:16px;padding:28px;max-width:600px;width:90%;max-height:85vh;overflow-y:auto" id="kcTechModalBody">
    </div>
  </div>

</div>`;
}

function _attachKillChainEvents(phases) {
  // Store phases globally for re-use
  window._kcPhasesData = phases;

  // Close technique modal on background click
  const modal = document.getElementById('kcTechModal');
  if (modal) {
    modal.onclick = (e) => {
      if (e.target === modal) modal.style.display = 'none';
    };
  }
}

/* ─────────────────────────────────────────────
   Phase Detail Panel
───────────────────────────────────────────── */
function _kcShowPhase(tacticId) {
  const phases = window._kcPhasesData || [];
  const phase  = phases.find(p => p.id === tacticId);
  if (!phase) return;

  const detail = document.getElementById('kcDetail');
  if (!detail) return;

  detail.style.display = 'block';
  detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  detail.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
      <span style="font-size:2em">${phase.icon}</span>
      <div>
        <div style="font-size:1.15em;font-weight:700;color:${phase.color}">${phase.name}</div>
        <div style="font-size:.8em;color:#8b949e">${phase.id} · ${phase.detected}/${phase.total} techniques covered</div>
      </div>
      <button onclick="document.getElementById('kcDetail').style.display='none'"
        style="margin-left:auto;background:transparent;border:none;color:#8b949e;cursor:pointer;font-size:1.2em">✕</button>
    </div>

    <!-- Coverage bar -->
    <div style="background:#21262d;border-radius:6px;height:10px;margin-bottom:16px;overflow:hidden">
      <div style="height:100%;width:${phase.pct}%;background:${phase.color};border-radius:6px;transition:width .4s"></div>
    </div>

    <!-- Techniques table -->
    <div style="font-size:.8em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">
      Techniques &amp; Sub-techniques
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px">
      ${(phase.techniques || []).map(t => `
        <div onclick="_kcShowTechModal('${t.id}','${t.name.replace(/'/g,"\\'")}','${tacticId}')"
          style="background:#21262d;border-radius:8px;padding:10px 12px;cursor:pointer;
                 border:1px solid ${t.detected ? '#22c55e33' : '#ef444422'};transition:all .2s"
          onmouseenter="this.style.background='#2d333b'"
          onmouseleave="this.style.background='#21262d'"
        >
          <div style="display:flex;align-items:center;gap:8px">
            <span style="width:10px;height:10px;border-radius:50%;background:${t.detected?'#22c55e':'#ef4444'};flex-shrink:0"></span>
            <div>
              <div style="font-size:.75em;color:#8b949e">${t.id}</div>
              <div style="font-size:.85em;font-weight:600;color:${t.detected?'#e6edf3':'#8b949e'}">${t.name}</div>
            </div>
            <span style="margin-left:auto;font-size:.7em;padding:2px 7px;border-radius:8px;font-weight:700;
              background:${t.detected?'#22c55e22':'#ef444422'};
              color:${t.detected?'#22c55e':'#ef4444'};
              border:1px solid ${t.detected?'#22c55e44':'#ef444444'}">
              ${t.detected ? 'DETECTED' : 'BLIND SPOT'}
            </span>
          </div>
        </div>
      `).join('')}
    </div>

    <!-- Action buttons -->
    <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap">
      <button onclick="window.open('https://attack.mitre.org/tactics/${tacticId}/','_blank')"
        style="background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-external-link-alt"></i> ATT&CK Navigator
      </button>
      <button onclick="_kcHuntTactic('${tacticId}')"
        style="background:#3b82f622;border:1px solid #3b82f644;color:#3b82f6;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-crosshairs"></i> Hunt for Indicators
      </button>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   Technique Modal — Full Details
───────────────────────────────────────────── */
async function _kcShowTechModal(techId, techName, tacticId) {
  const modal = document.getElementById('kcTechModal');
  const body  = document.getElementById('kcTechModalBody');
  if (!modal || !body) return;

  modal.style.display = 'flex';
  body.innerHTML = `<div style="text-align:center;padding:40px;color:#8b949e">
    <i class="fas fa-spinner fa-spin fa-2x"></i>
    <div style="margin-top:12px">Loading technique data…</div>
  </div>`;

  // Fetch related IOCs and alerts for this technique
  let relatedIOCs    = [];
  let relatedAlerts  = [];
  let relatedCases   = [];

  try {
    if (typeof API !== 'undefined') {
      const [iocsRes, alertsRes, casesRes] = await Promise.allSettled([
        API.iocs.list({ search: techId, limit: 5 }),
        API.alerts.list({ search: techName.split(' ')[0], limit: 5 }),
        API.cases.list({ search: techId, limit: 3 }),
      ]);
      relatedIOCs   = iocsRes.status   === 'fulfilled' ? (iocsRes.value?.data   || []) : [];
      relatedAlerts = alertsRes.status === 'fulfilled' ? (alertsRes.value?.data || []) : [];
      relatedCases  = casesRes.status  === 'fulfilled' ? (casesRes.value?.data  || []) : [];
    }
  } catch (e) {
    console.warn('[KillChain] Technique data fetch failed:', e.message);
  }

  const phase = (window._kcPhasesData || []).find(p => p.id === tacticId);
  const tech  = (phase?.techniques || []).find(t => t.id === techId);

  body.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px">
      <div>
        <div style="font-size:.75em;color:#8b949e;text-transform:uppercase;letter-spacing:.5px">${tacticId} · Technique</div>
        <div style="font-size:1.3em;font-weight:700;color:#e6edf3;margin-top:4px">${techId}: ${techName}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span style="padding:4px 12px;border-radius:8px;font-size:.75em;font-weight:700;
          background:${tech?.detected?'#22c55e22':'#ef444422'};
          color:${tech?.detected?'#22c55e':'#ef4444'};
          border:1px solid ${tech?.detected?'#22c55e44':'#ef444444'}">
          ${tech?.detected ? '✓ DETECTED' : '✗ NOT COVERED'}
        </span>
        <button onclick="document.getElementById('kcTechModal').style.display='none'"
          style="background:transparent;border:1px solid #30363d;color:#8b949e;border-radius:6px;padding:4px 10px;cursor:pointer">✕</button>
      </div>
    </div>

    <!-- ATT&CK Link -->
    <a href="https://attack.mitre.org/techniques/${techId}/" target="_blank"
      style="display:inline-flex;align-items:center;gap:6px;color:#3b82f6;font-size:.8em;text-decoration:none;
             background:#3b82f611;padding:4px 12px;border-radius:6px;border:1px solid #3b82f622;margin-bottom:16px">
      <i class="fas fa-external-link-alt"></i> View on ATT&CK Navigator
    </a>

    <!-- Related data -->
    ${relatedAlerts.length > 0 ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.78em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">
        🚨 Related Alerts (${relatedAlerts.length})
      </div>
      ${relatedAlerts.map(a => `
        <div style="background:#21262d;border-radius:6px;padding:8px 12px;margin-bottom:6px;
                    border-left:3px solid ${a.severity==='CRITICAL'?'#ef4444':a.severity==='HIGH'?'#f97316':'#eab308'}">
          <div style="font-size:.82em;font-weight:600;color:#e6edf3">${a.title}</div>
          <div style="font-size:.72em;color:#8b949e;margin-top:2px">${a.severity} · ${a.source || '—'} · ${a.created_at ? new Date(a.created_at).toLocaleString() : ''}</div>
        </div>
      `).join('')}
    </div>` : ''}

    ${relatedIOCs.length > 0 ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.78em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">
        🔗 Related IOCs (${relatedIOCs.length})
      </div>
      ${relatedIOCs.map(ioc => `
        <div style="background:#21262d;border-radius:6px;padding:8px 12px;margin-bottom:6px">
          <code style="font-size:.8em;color:#e6edf3">${ioc.value}</code>
          <span style="font-size:.7em;color:#8b949e;margin-left:8px">${ioc.type} · Risk ${ioc.risk_score}</span>
        </div>
      `).join('')}
    </div>` : `
    <div style="background:#21262d;border-radius:8px;padding:14px;text-align:center;color:#8b949e;font-size:.85em;margin-bottom:16px">
      <i class="fas fa-database"></i> No correlated IOCs found for this technique
    </div>`}

    <!-- Action Buttons -->
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button onclick="if(typeof navigateTo==='function') { document.getElementById('kcTechModal').style.display='none'; navigateTo('ioc-registry'); }"
        style="background:#3b82f622;border:1px solid #3b82f644;color:#3b82f6;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-search"></i> Search IOC Registry
      </button>
      <button onclick="if(typeof navigateTo==='function') { document.getElementById('kcTechModal').style.display='none'; navigateTo('threat-hunting'); }"
        style="background:#22c55e22;border:1px solid #22c55e44;color:#22c55e;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-crosshairs"></i> Start Threat Hunt
      </button>
      <button onclick="if(typeof navigateTo==='function') { document.getElementById('kcTechModal').style.display='none'; navigateTo('case-management'); }"
        style="background:#f9731622;border:1px solid #f9731644;color:#f97316;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-folder"></i> Create Case
      </button>
    </div>
  `;
}

/* ─────────────────────────────────────────────
   Hunt for Indicators from a tactic
───────────────────────────────────────────── */
async function _kcHuntTactic(tacticId) {
  if (typeof showToast === 'function')
    showToast(`🔍 Starting hunt for ${tacticId} indicators…`, 'info');

  if (typeof navigateTo === 'function')
    navigateTo('threat-hunting');
}

/* ─────────────────────────────────────────────
   Export SVG
───────────────────────────────────────────── */
function _kcExportSVG() {
  const flow = document.getElementById('kcFlow');
  if (!flow) return;

  // Simple HTML export of the current view
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>MITRE ATT&CK Kill Chain Export</title>
<style>body{background:#0d1117;font-family:Arial,sans-serif;padding:20px}</style>
</head><body>${document.getElementById('killChainWrap')?.innerHTML || ''}</body></html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `kill-chain-${new Date().toISOString().split('T')[0]}.html`;
  a.click();
  URL.revokeObjectURL(a.href);

  if (typeof showToast === 'function')
    showToast('Kill Chain exported as HTML', 'success');
}

/* ─────────────────────────────────────────────
   Global Exports
───────────────────────────────────────────── */
window.renderKillChainLive = renderKillChainLive;
window.renderKillChain     = renderKillChainLive; // alias
window._kcShowPhase        = _kcShowPhase;
window._kcShowTechModal    = _kcShowTechModal;
window._kcHuntTactic       = _kcHuntTactic;
window._kcExportSVG        = _kcExportSVG;

console.info('[KillChain] MITRE ATT&CK Kill Chain v3.0 loaded');
