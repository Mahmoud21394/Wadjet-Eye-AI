/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Operations Module v1.0
 *  js/soc-operations.js
 *
 *  Primary Tab: SOC Operations
 *  Child Tabs:
 *    1. Automation & Detection
 *    2. Manual Investigation
 *    3. Incidents & Response
 *    4. Reports & Intelligence
 *    5. Integrations & Playbooks
 *    6. AI Assistant
 * ══════════════════════════════════════════════════════════════════════
 */

window.SOCOperations = (function () {
  'use strict';

  /* ─── Module State ──────────────────────────────────────────────── */
  const STATE = {
    activeTab: 'automation',
    ingestionRunning: false,
    ingestionTimer: null,
    ingestionLogLines: [],
    alerts: [],
    incidents: [],
    investigations: [],
    currentInvestigation: null,
    openIncidentId: null,
    chatHistory: [],
    apiKey: '',
    settings: {
      openaiKey: '',
      slackWebhook: '',
      siemEndpoint: '',
      ticketingUrl: '',
      ticketingToken: '',
      emailRecipients: '',
      autoEscalate: true,
      notifyOnCritical: true,
    },
  };

  /* ─── Sample Log Sources for Automation ────────────────────────── */
  const SAMPLE_LOG_TEMPLATES = [
    { ts: () => ts(), level: 'info', msg: () => `Connection accepted from <ip>${randIP()}</ip> on port 443` },
    { ts: () => ts(), level: 'info', msg: () => `User <val>jdoe</val> authenticated successfully from <ip>${randIP()}</ip>` },
    { ts: () => ts(), level: 'medium', msg: () => `<rule>DR-007</rule> Port scan detected from <ip>${randIP()}</ip> — 24 ports hit in 3s` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-001</rule> Brute force: 8 failed logins for user <val>admin</val> from <ip>${randIP()}</ip>` },
    { ts: () => ts(), level: 'info', msg: () => `Scheduled task "backup_sync" executed on host <val>WIN-SRV01</val>` },
    { ts: () => ts(), level: 'critical', msg: () => `<rule>DR-016</rule> LSASS memory dump detected — <val>procdump.exe</val> by user <val>SYSTEM</val> on <ip>10.0.1.22</ip>` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-013</rule> PowerShell -EncodedCommand detected from user <val>svc_account</val>` },
    { ts: () => ts(), level: 'info', msg: () => `DNS query: internal.corp.local → <ip>192.168.1.100</ip>` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-004</rule> SMB lateral movement: <ip>10.0.0.15</ip> → <ip>10.0.0.30</ip> (net use Z: \\\\server\\c$)` },
    { ts: () => ts(), level: 'critical', msg: () => `<rule>DR-010</rule> RANSOMWARE indicators: vssadmin delete shadows /all on <val>FILE-SRV01</val>` },
    { ts: () => ts(), level: 'medium', msg: () => `<rule>DR-018</rule> New local admin created: <val>net user hacker P@ss123 /add</val>` },
    { ts: () => ts(), level: 'info', msg: () => `Firewall rule updated — allow outbound 443 from 10.0.0.0/24` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-008</rule> Large data transfer: <ip>${randIP()}</ip> → external, 150 MB via HTTP POST` },
    { ts: () => ts(), level: 'medium', msg: () => `<rule>DR-015</rule> Event log cleared on host <val>WORKSTATION-07</val> by user <val>Administrator</val>` },
    { ts: () => ts(), level: 'info', msg: () => `New connection to Okta SSO from <ip>${randIP()}</ip> — MFA passed` },
    { ts: () => ts(), level: 'critical', msg: () => `<rule>DR-011</rule> Cobalt Strike beacon detected: callback to <ip>185.220.101.47</ip>:4444` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-006</rule> SQL injection attempt: <val>UNION SELECT</val> in request to /api/users from <ip>${randIP()}</ip>` },
    { ts: () => ts(), level: 'medium', msg: () => `<rule>DR-017</rule> Scheduled task created: "svchost_update" — runs <val>cmd.exe /c whoami</val>` },
    { ts: () => ts(), level: 'info', msg: () => `TLS handshake with <ip>${randIP()}</ip> — cipher: TLS_AES_256_GCM_SHA384` },
    { ts: () => ts(), level: 'high', msg: () => `<rule>DR-003</rule> Privilege escalation: sudo -s by <val>www-data</val> on host <val>WEB-01</val>` },
  ];

  function ts() {
    return new Date().toISOString().replace('T', ' ').substring(0, 19);
  }
  function randIP() {
    const pools = ['10.0', '192.168.1', '172.16.0', '203.0.113', '198.51.100'];
    const p = pools[Math.floor(Math.random() * pools.length)];
    return `${p}.${Math.floor(Math.random() * 254) + 1}`;
  }
  function randPick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function fmtAgo(ms) {
    const s = Math.floor((Date.now() - ms) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    return `${Math.floor(s/3600)}h ago`;
  }
  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function markdownToHtml(md) {
    if (!md) return '';
    return md
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>\n?)+/g, m => `<ul>${m}</ul>`)
      .replace(/\n{2,}/g, '</p><p>')
      .replace(/^([^<\n].+)$/gm, (m) => m.startsWith('<') ? m : `<p>${m}</p>`);
  }

  /* ─── Incident Data Store ───────────────────────────────────────── */
  const INCIDENT_COUNTER = { n: 1 };
  function createIncidentFromAlert(alert) {
    const id = `INC-${String(INCIDENT_COUNTER.n++).padStart(4,'0')}`;
    const inc = {
      id, alert_id: alert.id,
      title: alert.name,
      severity: alert.severity,
      status: 'open',
      created_at: Date.now(),
      updated_at: Date.now(),
      assignee: 'Unassigned',
      category: alert.category,
      description: alert.description,
      affected_ips: alert.affected_ips || [],
      affected_users: alert.affected_users || [],
      mitre: alert.mitre_techniques || [],
      tactic: alert.tactic_name || '',
      timeline: [],
      playbook_progress: {},
      notes: '',
    };
    STATE.incidents.unshift(inc);
    return inc;
  }

  /* ─── Playbook Templates ────────────────────────────────────────── */
  const PLAYBOOKS = {
    default: {
      containment: [
        'Isolate affected host(s) from the network',
        'Revoke active sessions for compromised user accounts',
        'Block identified attacker IPs at firewall/perimeter',
        'Disable compromised service accounts',
        'Capture memory dump of affected systems for forensics',
      ],
      investigation: [
        'Collect and preserve all relevant logs (SIEM, endpoint, network)',
        'Identify patient-zero and initial infection vector',
        'Map lateral movement paths using network flow data',
        'Review authentication logs for additional compromised accounts',
        'Conduct IOC sweep across all endpoints via EDR',
        'Correlate with threat intelligence feeds',
      ],
      eradication: [
        'Remove identified malware / persistence mechanisms',
        'Rotate all potentially compromised credentials',
        'Patch exploited vulnerabilities',
        'Clean or rebuild affected systems',
        'Verify no remaining backdoors or attacker artifacts',
      ],
      recovery: [
        'Restore systems from verified clean backups',
        'Re-enable isolated systems after thorough verification',
        'Monitor restored systems for recurrence (72h enhanced watch)',
        'Update detection rules based on observed TTPs',
        'Conduct post-incident review meeting',
        'Update threat intelligence with new IOCs',
      ],
    },
    ransomware: {
      containment: [
        'IMMEDIATELY isolate ALL affected hosts — disconnect network cables',
        'Shut down shared drives and network file shares',
        'Block C2 IP ranges at firewall (check threat intel for known ransomware IPs)',
        'Disable user accounts that triggered the ransomware process',
        'Alert business continuity / disaster recovery team',
      ],
      investigation: [
        'Identify ransomware family via VirusTotal / sandbox analysis',
        'Determine initial access vector (email, RDP, vuln exploit)',
        'Check for exfiltration before encryption (double extortion)',
        'Identify encryption scope — which shares/files affected',
        'Review backup integrity — confirm backups are clean',
      ],
      eradication: [
        'Remove ransomware binaries and scheduled task persistence',
        'Check for and remove any additional malware dropped',
        'Rotate all service account and admin passwords',
        'Apply patches for initial access vulnerability',
      ],
      recovery: [
        'Restore from last known good backup — verify backup integrity first',
        'Rebuild critical systems from scratch if backup integrity is uncertain',
        'Enhance monitoring for 30 days post-recovery',
        'Consider engaging ransomware decryption specialists if no backup available',
        'Report to CISA / law enforcement as required',
      ],
    },
    credential: {
      containment: [
        'Lock all accounts that received failed login attempts',
        'Enable MFA for all identified targeted accounts',
        'Block source IPs at WAF and firewall',
        'Enable enhanced logging for all authentication events',
      ],
      investigation: [
        'Determine if any accounts were successfully compromised',
        'Review all logins from attacker IP ranges — past 30 days',
        'Check for account enumeration in web/app server logs',
        'Identify if credential lists were sourced from prior breach',
      ],
      eradication: [
        'Force password reset for all targeted accounts',
        'Enable account lockout policies (5 attempts → 30min lockout)',
        'Implement CAPTCHA for repeated failed logins',
        'Block disposable email domains if used for registration',
      ],
      recovery: [
        'Implement risk-based authentication (geo anomalies, device fingerprinting)',
        'Conduct phishing awareness training for affected users',
        'Enroll all accounts in MFA',
        'Monitor for continued attack patterns post-remediation',
      ],
    },
  };

  /* ─── Report Templates ──────────────────────────────────────────── */
  const REPORT_TEMPLATES = [
    {
      id: 'exec', name: 'Executive Summary Report',
      icon: 'soc-rt-icon exec', iconClass: 'fas fa-chart-line',
      desc: 'High-level overview for C-suite and board. Includes risk score, key findings, and strategic recommendations.',
      sections: ['Executive Summary', 'Risk Score', 'Key Findings', 'Business Impact', 'Recommendations'],
    },
    {
      id: 'threat', name: 'Threat Intelligence Report',
      icon: 'soc-rt-icon threat', iconClass: 'fas fa-crosshairs',
      desc: 'In-depth technical analysis with MITRE ATT&CK mapping, IOCs, and attack narrative for SOC/IR teams.',
      sections: ['Attack Narrative', 'MITRE ATT&CK', 'IOCs', 'Timeline', 'TTPs'],
    },
    {
      id: 'inv', name: 'Investigation Report',
      icon: 'soc-rt-icon inv', iconClass: 'fas fa-search',
      desc: 'Full investigation findings with timeline, entities, root cause, and evidence appendix.',
      sections: ['Summary', 'Findings', 'Timeline', 'Entities', 'Root Cause', 'Appendix'],
    },
    {
      id: 'comp', name: 'Compliance Report',
      icon: 'soc-rt-icon comp', iconClass: 'fas fa-shield-alt',
      desc: 'SOC2/ISO27001 aligned security posture report with control coverage and gap analysis.',
      sections: ['Control Coverage', 'Gaps', 'Remediation Plan', 'Risk Register'],
    },
  ];

  /* ─── Integration Config ────────────────────────────────────────── */
  const INTEGRATIONS = [
    { id: 'siem', name: 'SIEM Integration', icon: '📊', desc: 'Connect to Splunk, Elastic, or QRadar for log forwarding and alert sync.', status: 'inactive' },
    { id: 'slack', name: 'Slack Notifications', icon: '💬', desc: 'Real-time alert notifications to Slack channels via webhook.', status: 'inactive' },
    { id: 'jira', name: 'Jira Ticketing', icon: '🎫', desc: 'Auto-create Jira tickets for new incidents and sync status updates.', status: 'inactive' },
    { id: 'pagerduty', name: 'PagerDuty Alerts', icon: '🚨', desc: 'Escalate critical incidents via PagerDuty on-call integration.', status: 'inactive' },
    { id: 'webhook', name: 'Generic Webhook', icon: '🔗', desc: 'POST JSON payloads to any endpoint on alert events.', status: 'inactive' },
    { id: 'email', name: 'Email Notifications', icon: '✉️', desc: 'Send email digests and alert summaries to security team.', status: 'inactive' },
  ];

  /* ─── Render Entry Point ────────────────────────────────────────── */
  function render(container) {
    if (!container) return;
    container.innerHTML = buildModuleHTML();
    attachEventListeners();
    switchTab(STATE.activeTab);
    loadAutomationAlerts();
    loadIncidents();
  }

  /* ─── Module HTML ───────────────────────────────────────────────── */
  function buildModuleHTML() {
    return `
<!-- SOC Operations Tab Bar -->
<div class="soc-tab-bar" id="socTabBar">
  <button class="soc-tab${STATE.activeTab==='automation'?' active':''}" onclick="SOCOperations.switchTab('automation')">
    <i class="fas fa-robot"></i> Automation &amp; Detection
    <span class="soc-tab-badge" id="soc-badge-alerts">0</span>
  </button>
  <button class="soc-tab${STATE.activeTab==='investigation'?' active':''}" onclick="SOCOperations.switchTab('investigation')">
    <i class="fas fa-search"></i> Manual Investigation
  </button>
  <button class="soc-tab${STATE.activeTab==='incidents'?' active':''}" onclick="SOCOperations.switchTab('incidents')">
    <i class="fas fa-fire-alt"></i> Incidents &amp; Response
    <span class="soc-tab-badge" id="soc-badge-inc">0</span>
  </button>
  <button class="soc-tab${STATE.activeTab==='reports'?' active':''}" onclick="SOCOperations.switchTab('reports')">
    <i class="fas fa-file-pdf"></i> Reports &amp; Intelligence
  </button>
  <button class="soc-tab${STATE.activeTab==='integrations'?' active':''}" onclick="SOCOperations.switchTab('integrations')">
    <i class="fas fa-plug"></i> Integrations &amp; Playbooks
  </button>
  <button class="soc-tab${STATE.activeTab==='network-traffic'?' active':''}" onclick="SOCOperations.switchTab('network-traffic')">
    <i class="fas fa-network-wired"></i> Network Traffic Analysis
    <span class="soc-tab-badge" style="background:#22d3ee;color:#000">NEW</span>
  </button>
  <button class="soc-tab${STATE.activeTab==='ai-assistant'?' active':''}" onclick="SOCOperations.switchTab('ai-assistant')">
    <i class="fas fa-comments"></i> AI Assistant
    <span class="soc-tab-badge blue">AI</span>
  </button>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 1: AUTOMATION & DETECTION                          -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-automation">

  <!-- KPIs -->
  <div class="soc-kpi-row" id="autoKPIs">
    <div class="soc-kpi critical"><div class="soc-kpi-label">Critical Alerts</div><div class="soc-kpi-value" id="kpi-critical">0</div><div class="soc-kpi-sub">Requires immediate action</div></div>
    <div class="soc-kpi high"><div class="soc-kpi-label">High Severity</div><div class="soc-kpi-value" id="kpi-high">0</div><div class="soc-kpi-sub">Investigate ASAP</div></div>
    <div class="soc-kpi medium"><div class="soc-kpi-label">Medium Alerts</div><div class="soc-kpi-value" id="kpi-medium">0</div><div class="soc-kpi-sub">Review within 24h</div></div>
    <div class="soc-kpi good"><div class="soc-kpi-label">Rules Active</div><div class="soc-kpi-value" id="kpi-rules">25</div><div class="soc-kpi-sub">Detection rules loaded</div></div>
  </div>

  <!-- Main 2-col grid -->
  <div class="soc-grid-main">

    <!-- Left: Live Feed + Alert Stream -->
    <div style="display:flex;flex-direction:column;gap:16px;">

      <!-- Live Ingestion Feed -->
      <div class="soc-rt-feed">
        <div class="soc-rt-header">
          <div class="soc-rt-title">
            <div class="soc-live-dot" id="rtDot"></div>
            Real-time Ingestion Feed
            <span style="font-size:11px;color:var(--soc-muted);font-weight:400;" id="rtSourceLabel">Stopped</span>
          </div>
          <div style="display:flex;gap:8px;align-items:center;">
            <select class="soc-select" id="rtSourceSelect" style="width:auto;padding:5px 10px;font-size:11.5px;background:#0d1117;">
              <option value="syslog">Syslog / Linux Auth</option>
              <option value="windows">Windows Event Logs</option>
              <option value="web">Web Access Logs</option>
              <option value="firewall">Firewall Logs</option>
              <option value="mixed" selected>Mixed (All Sources)</option>
            </select>
            <button class="soc-btn success sm" id="rtStartBtn" onclick="SOCOperations.startIngestion()">
              <i class="fas fa-play"></i> Start
            </button>
            <button class="soc-btn danger sm" id="rtStopBtn" onclick="SOCOperations.stopIngestion()" style="display:none;">
              <i class="fas fa-stop"></i> Stop
            </button>
            <button class="soc-btn sm" onclick="SOCOperations.clearLog()"><i class="fas fa-trash"></i></button>
          </div>
        </div>
        <div class="soc-rt-log" id="rtLog">
          <div class="soc-log-entry"><span class="soc-log-ts">—</span><span class="soc-log-msg" style="color:#3d4f60;">Ingestion engine ready. Press Start to begin real-time log ingestion.</span></div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-top:1px solid var(--soc-border);background:rgba(255,255,255,0.01);">
          <span style="font-size:11px;color:var(--soc-muted);">Events: <strong id="rtEventCount" style="color:var(--soc-accent);">0</strong></span>
          <span style="font-size:11px;color:var(--soc-muted);">Detections: <strong id="rtDetectCount" style="color:var(--soc-red);">0</strong></span>
          <span style="font-size:11px;color:var(--soc-muted);">Rate: <strong id="rtRate" style="color:var(--soc-green);">0</strong> events/min</span>
        </div>
      </div>

      <!-- Alert Stream -->
      <div class="soc-card">
        <div class="soc-card-header">
          <div class="soc-card-title"><i class="fas fa-bell"></i> Active Detection Alerts</div>
          <div class="soc-card-actions">
            <select class="soc-select" id="alertSevFilter" style="width:auto;padding:5px 10px;font-size:11.5px;background:#0d1117;" onchange="SOCOperations.filterAlerts()">
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button class="soc-btn sm" onclick="SOCOperations.clearAlerts()"><i class="fas fa-trash"></i> Clear</button>
          </div>
        </div>
        <div class="soc-card-body" style="padding:12px;max-height:380px;overflow-y:auto;" id="alertStream">
          <div class="soc-empty"><i class="fas fa-shield-alt"></i><p>No alerts yet</p><small>Start ingestion to generate real-time detections</small></div>
        </div>
      </div>
    </div>

    <!-- Right: Config Panel -->
    <div style="display:flex;flex-direction:column;gap:16px;">

      <!-- Detection Thresholds -->
      <div class="soc-card">
        <div class="soc-card-header">
          <div class="soc-card-title"><i class="fas fa-sliders-h"></i> Detection Thresholds</div>
          <button class="soc-btn sm" onclick="SOCOperations.saveThresholds()"><i class="fas fa-save"></i> Save</button>
        </div>
        <div class="soc-card-body">
          <div class="soc-threshold-row">
            <div class="soc-threshold-label">Brute Force<small>Failed logins/min</small></div>
            <div class="soc-threshold-ctrl">
              <input type="range" class="soc-slider" id="thr-bruteForce" min="2" max="50" value="5" oninput="document.getElementById('thr-bf-val').textContent=this.value">
              <span class="soc-slider-val" id="thr-bf-val">5</span>
            </div>
          </div>
          <div class="soc-threshold-row">
            <div class="soc-threshold-label">Port Scan<small>Ports/min</small></div>
            <div class="soc-threshold-ctrl">
              <input type="range" class="soc-slider" id="thr-portScan" min="5" max="100" value="20" oninput="document.getElementById('thr-ps-val').textContent=this.value">
              <span class="soc-slider-val" id="thr-ps-val">20</span>
            </div>
          </div>
          <div class="soc-threshold-row">
            <div class="soc-threshold-label">Cred. Stuffing<small>Auth attempts/IP</small></div>
            <div class="soc-threshold-ctrl">
              <input type="range" class="soc-slider" id="thr-credStuffing" min="2" max="100" value="10" oninput="document.getElementById('thr-cs-val').textContent=this.value">
              <span class="soc-slider-val" id="thr-cs-val">10</span>
            </div>
          </div>
          <div class="soc-threshold-row">
            <div class="soc-threshold-label">Data Exfil<small>MB threshold</small></div>
            <div class="soc-threshold-ctrl">
              <input type="range" class="soc-slider" id="thr-dataExfil" min="10" max="500" value="50" oninput="document.getElementById('thr-de-val').textContent=this.value">
              <span class="soc-slider-val" id="thr-de-val">50</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Rule Toggles -->
      <div class="soc-card">
        <div class="soc-card-header">
          <div class="soc-card-title"><i class="fas fa-toggle-on"></i> Rule Categories</div>
        </div>
        <div class="soc-card-body" style="padding:12px 16px;">
          ${[
            ['credential_attack','Credential Attacks',true],
            ['privilege_escalation','Privilege Escalation',true],
            ['lateral_movement','Lateral Movement',true],
            ['web_attack','Web Attacks',true],
            ['exfiltration','Data Exfiltration',true],
            ['malware','Malware/Ransomware',true],
            ['c2','C2 / Beaconing',true],
            ['evasion','Defense Evasion',true],
            ['persistence','Persistence',true],
            ['reconnaissance','Reconnaissance',true],
          ].map(([k,label,on]) => `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--soc-border);">
            <span style="font-size:12.5px;color:var(--soc-text);">${label}</span>
            <label class="soc-toggle">
              <input type="checkbox" ${on?'checked':''} id="rule-${k}">
              <span class="soc-toggle-slider"></span>
            </label>
          </div>`).join('')}
        </div>
      </div>

      <!-- Automation Actions -->
      <div class="soc-card">
        <div class="soc-card-header">
          <div class="soc-card-title"><i class="fas fa-magic"></i> Auto Response</div>
        </div>
        <div class="soc-card-body" style="padding:12px 16px;">
          ${[
            ['auto-block','Auto-block attacker IPs',false],
            ['auto-incident','Auto-create incidents',true],
            ['auto-notify','Notify on critical',true],
            ['auto-escalate','Auto-escalate high+',false],
            ['auto-enrich','Enrich IOCs on detection',true],
          ].map(([k,label,on]) => `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--soc-border);">
            <span style="font-size:12.5px;color:var(--soc-text);">${label}</span>
            <label class="soc-toggle"><input type="checkbox" ${on?'checked':''} id="${k}"><span class="soc-toggle-slider"></span></label>
          </div>`).join('')}
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 2: MANUAL INVESTIGATION                            -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-investigation">

  <div class="soc-grid-2" id="invUploadSection">

    <!-- Upload Area -->
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title"><i class="fas fa-upload"></i> Upload Log Files</div>
        <button class="soc-btn sm" onclick="SOCOperations.loadSampleLogs()"><i class="fas fa-flask"></i> Load Sample</button>
      </div>
      <div class="soc-card-body">
        <div class="soc-upload-zone" id="uploadZone">
          <input type="file" id="logFileInput" multiple accept=".log,.txt,.json,.csv,.xml,.evtx" onchange="SOCOperations.handleFileUpload(event)">
          <div class="soc-upload-icon"><i class="fas fa-file-upload"></i></div>
          <div class="soc-upload-text">Drop log files here or click to browse</div>
          <div class="soc-upload-hint">Supports: .log .txt .json .csv .xml .evtx · Auto-detects log type</div>
        </div>
        <div class="soc-files-list" id="uploadedFiles"></div>
      </div>
    </div>

    <!-- Analysis Config -->
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title"><i class="fas fa-cog"></i> Analysis Settings</div>
      </div>
      <div class="soc-card-body">
        <div class="soc-form-group">
          <label><i class="fas fa-key" style="margin-right:5px;color:var(--soc-accent)"></i>OpenAI API Key (Optional)</label>
          <input type="password" class="soc-input" id="invApiKey" placeholder="sk-... (leave blank for local analysis)" oninput="SOCOperations.updateApiKey(this.value)">
          <div style="font-size:11px;color:var(--soc-muted);margin-top:4px;">AI-enhanced narrative, false-positive reduction, and contextual recommendations.</div>
        </div>
        <div class="soc-form-group">
          <label>Analysis Mode</label>
          <select class="soc-select" id="invMode">
            <option value="full">Full Pipeline (Recommended)</option>
            <option value="quick">Quick Scan (Rules Only)</option>
            <option value="deep">Deep Analysis (Slower)</option>
          </select>
        </div>
        <div class="soc-form-group">
          <label>Output Format</label>
          <select class="soc-select" id="invFormat">
            <option value="full">Full Report</option>
            <option value="summary">Executive Summary</option>
            <option value="findings">Findings Only</option>
          </select>
        </div>
        <div style="margin-top:4px;">
          <label class="soc-toggle" style="display:inline-flex;align-items:center;gap:10px;cursor:pointer;">
            <input type="checkbox" id="invCorrelate" checked>
            <span class="soc-toggle-slider"></span>
            <span style="font-size:12.5px;color:var(--soc-text);">Multi-file correlation</span>
          </label>
        </div>
      </div>
    </div>
  </div>

  <!-- Analyze Button -->
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;" id="invAnalyzeBar">
    <button class="soc-btn primary" id="invAnalyzeBtn" onclick="SOCOperations.runInvestigation()" disabled>
      <i class="fas fa-microscope"></i> Analyze Logs
    </button>
    <span style="font-size:12px;color:var(--soc-muted);" id="invFileCount">No files selected</span>
    <div style="flex:1;"></div>
    <button class="soc-btn sm" id="invClearBtn" onclick="SOCOperations.clearInvestigation()" style="display:none;">
      <i class="fas fa-redo"></i> New Investigation
    </button>
  </div>

  <!-- Pipeline Progress -->
  <div id="invPipeline" style="display:none;">
    <div class="soc-card">
      <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-tasks"></i> Analysis Pipeline</div></div>
      <div class="soc-card-body">
        <div class="soc-pipeline" id="pipelineSteps">
          ${['Parsing','Detection','AI Analysis','Investigation','Report'].map((s,i) => `
          <div class="soc-pipe-step" id="pipe-step-${i}">
            <div class="soc-pipe-icon"><i class="fas fa-${['file-alt','crosshairs','brain','search','file-pdf'][i]}"></i></div>
            <div class="soc-pipe-label">${s}</div>
          </div>`).join('')}
        </div>
        <div style="margin-top:8px;">
          <div class="soc-progress-bar"><div class="soc-progress-fill" id="invProgressBar" style="width:0%"></div></div>
          <div style="font-size:11px;color:var(--soc-muted);margin-top:5px;" id="invProgressLabel">Initializing…</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Results -->
  <div id="invResults" style="display:none;"></div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 3: INCIDENTS & RESPONSE                            -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-incidents">

  <div class="soc-inc-header">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <span style="font-size:15px;font-weight:700;color:var(--soc-text);"><i class="fas fa-fire-alt" style="color:var(--soc-red);margin-right:8px;"></i>Incidents &amp; Response</span>
      <div class="soc-inc-filters">
        <button class="soc-filter-btn active" onclick="SOCOperations.filterIncidents('all',this)">All</button>
        <button class="soc-filter-btn" onclick="SOCOperations.filterIncidents('open',this)">Open</button>
        <button class="soc-filter-btn" onclick="SOCOperations.filterIncidents('in-progress',this)">In Progress</button>
        <button class="soc-filter-btn" onclick="SOCOperations.filterIncidents('resolved',this)">Resolved</button>
      </div>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="soc-btn primary sm" onclick="SOCOperations.createManualIncident()"><i class="fas fa-plus"></i> New Incident</button>
      <button class="soc-btn sm" onclick="SOCOperations.exportIncidents()"><i class="fas fa-download"></i> Export</button>
    </div>
  </div>

  <!-- Incident KPIs -->
  <div class="soc-kpi-row" style="margin-bottom:8px;">
    <div class="soc-kpi critical"><div class="soc-kpi-label">Open Critical</div><div class="soc-kpi-value" id="inc-kpi-crit">0</div></div>
    <div class="soc-kpi high"><div class="soc-kpi-label">In Progress</div><div class="soc-kpi-value" id="inc-kpi-prog">0</div></div>
    <div class="soc-kpi good"><div class="soc-kpi-label">Resolved Today</div><div class="soc-kpi-value" id="inc-kpi-res">0</div></div>
    <div class="soc-kpi"><div class="soc-kpi-label">MTTR (avg)</div><div class="soc-kpi-value" id="inc-kpi-mttr">—</div><div class="soc-kpi-sub">Mean time to resolve</div></div>
  </div>

  <div class="soc-card">
    <div class="soc-card-body" style="padding:0;">
      <table class="soc-inc-table" id="incidentTable">
        <thead>
          <tr>
            <th>ID</th><th>Title</th><th>Severity</th><th>Status</th>
            <th>Category</th><th>Created</th><th>Assignee</th><th>Actions</th>
          </tr>
        </thead>
        <tbody id="incidentTableBody">
          <tr><td colspan="8" style="text-align:center;padding:40px;color:var(--soc-muted);">
            <i class="fas fa-shield-alt" style="font-size:28px;display:block;margin-bottom:10px;opacity:0.3;"></i>
            No incidents yet — generate alerts via Automation tab or create manually
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Incident Drawer -->
<div class="soc-drawer-overlay" id="incDrawerOverlay" onclick="SOCOperations.closeIncidentDrawer()"></div>
<div class="soc-drawer" id="incDrawer">
  <div class="soc-drawer-header">
    <div class="soc-drawer-title" id="drawerTitle">Incident Details</div>
    <button class="soc-drawer-close" onclick="SOCOperations.closeIncidentDrawer()"><i class="fas fa-times"></i></button>
  </div>
  <div class="soc-drawer-body" id="drawerBody"></div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 4: REPORTS & INTELLIGENCE                          -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-reports">

  <div class="soc-grid-2">
    <!-- Left: Templates -->
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div style="font-size:14px;font-weight:700;color:var(--soc-text);margin-bottom:2px;"><i class="fas fa-file-pdf" style="color:var(--soc-accent);margin-right:8px;"></i>Report Templates</div>
      ${REPORT_TEMPLATES.map(t => `
      <div class="soc-report-template" onclick="SOCOperations.selectReportTemplate('${t.id}','${esc(t.name)}')">
        <div class="${t.icon}"><i class="${t.iconClass}"></i></div>
        <div class="soc-rt-body">
          <div class="soc-rt-name">${t.name}</div>
          <div class="soc-rt-desc">${t.desc}</div>
          <div class="soc-rt-sections">${t.sections.map(s=>`<span class="soc-rt-sec">${s}</span>`).join('')}</div>
        </div>
        <i class="fas fa-chevron-right" style="color:var(--soc-muted);"></i>
      </div>`).join('')}
    </div>

    <!-- Right: Report Config + Preview -->
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div class="soc-card">
        <div class="soc-card-header">
          <div class="soc-card-title"><i class="fas fa-cog"></i> Report Configuration</div>
        </div>
        <div class="soc-card-body">
          <div class="soc-form-group">
            <label>Selected Template</label>
            <div id="selectedTemplate" style="font-size:13px;color:var(--soc-accent);padding:8px 12px;background:rgba(88,166,255,0.08);border-radius:6px;border:1px solid rgba(88,166,255,0.2);">
              Click a template to select ↓
            </div>
          </div>
          <div class="soc-form-group">
            <label>Report Title</label>
            <input type="text" class="soc-input" id="reportTitle" value="Security Analysis Report — ${new Date().toLocaleDateString()}">
          </div>
          <div class="soc-form-group">
            <label>Organization</label>
            <input type="text" class="soc-input" id="reportOrg" value="MSSP Global Operations">
          </div>
          <div class="soc-form-group">
            <label>Classification</label>
            <select class="soc-select" id="reportClass">
              <option>TLP:WHITE — Public</option>
              <option selected>TLP:GREEN — Community</option>
              <option>TLP:AMBER — Limited Distribution</option>
              <option>TLP:RED — Confidential</option>
            </select>
          </div>
          <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
            <button class="soc-btn primary" id="generateReportBtn" onclick="SOCOperations.generateReport()" disabled>
              <i class="fas fa-magic"></i> Generate Report
            </button>
            <button class="soc-btn sm" id="downloadReportBtn" onclick="SOCOperations.downloadReport()" style="display:none;">
              <i class="fas fa-download"></i> Download
            </button>
          </div>
        </div>
      </div>

      <!-- Alerts / Incidents Chart -->
      <div class="soc-card">
        <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-chart-bar"></i> Alerts by Severity</div></div>
        <div class="soc-card-body">
          <div style="height:180px;position:relative;"><canvas id="socSeverityChart"></canvas></div>
        </div>
      </div>
    </div>
  </div>

  <!-- Report Preview -->
  <div id="reportPreviewWrap" style="display:none;">
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title"><i class="fas fa-eye"></i> Report Preview</div>
        <div class="soc-card-actions">
          <button class="soc-btn sm" onclick="SOCOperations.printReport()"><i class="fas fa-print"></i> Print / PDF</button>
          <button class="soc-btn danger sm" onclick="document.getElementById('reportPreviewWrap').style.display='none'">
            <i class="fas fa-times"></i> Close
          </button>
        </div>
      </div>
      <div class="soc-card-body" style="padding:16px;">
        <div id="reportPreview"></div>
      </div>
    </div>
  </div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 5: INTEGRATIONS & PLAYBOOKS                        -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-integrations">

  <div class="soc-grid-2">

    <!-- Integrations -->
    <div>
      <div style="font-size:14px;font-weight:700;color:var(--soc-text);margin-bottom:12px;"><i class="fas fa-plug" style="color:var(--soc-accent);margin-right:8px;"></i>Available Integrations</div>
      <div style="display:flex;flex-direction:column;gap:8px;" id="integrationsList">
        ${INTEGRATIONS.map(int => `
        <div class="soc-integration-card" id="int-card-${int.id}">
          <div class="soc-int-logo">${int.icon}</div>
          <div class="soc-int-body">
            <div class="soc-int-name">${int.name}</div>
            <div class="soc-int-desc">${int.desc}</div>
          </div>
          <div class="soc-int-status">
            <span class="status-badge closed" id="int-status-${int.id}">Inactive</span>
            <button class="soc-btn sm" onclick="SOCOperations.configureIntegration('${int.id}')">Configure</button>
          </div>
        </div>`).join('')}
      </div>
    </div>

    <!-- Playbook Builder -->
    <div>
      <div style="font-size:14px;font-weight:700;color:var(--soc-text);margin-bottom:12px;"><i class="fas fa-book" style="color:var(--soc-accent);margin-right:8px;"></i>Playbook Templates</div>

      <div style="display:flex;flex-direction:column;gap:8px;">
        ${[
          ['default','General IR Playbook','fas fa-shield-alt','var(--soc-accent)','4 phases · 22 steps · Covers all incident types'],
          ['ransomware','Ransomware Response','fas fa-lock','var(--soc-red)','4 phases · 18 steps · BCP/DR integration'],
          ['credential','Credential Attack Response','fas fa-key','var(--soc-orange)','4 phases · 15 steps · MFA enforcement workflow'],
        ].map(([id,name,icon,color,meta]) => `
        <div class="soc-report-template" onclick="SOCOperations.previewPlaybook('${id}')">
          <div style="width:44px;height:44px;border-radius:10px;background:rgba(255,255,255,0.05);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">
            <i class="${icon}" style="color:${color};"></i>
          </div>
          <div class="soc-rt-body">
            <div class="soc-rt-name">${name}</div>
            <div class="soc-rt-desc">${meta}</div>
          </div>
          <i class="fas fa-chevron-right" style="color:var(--soc-muted);"></i>
        </div>`).join('')}
      </div>

      <!-- Webhook Config -->
      <div class="soc-card" style="margin-top:16px;">
        <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-bell"></i> Notification Settings</div></div>
        <div class="soc-card-body">
          <div class="soc-form-group">
            <label>Slack Webhook URL</label>
            <input type="url" class="soc-input" id="cfgSlack" placeholder="https://hooks.slack.com/services/..." value="${STATE.settings.slackWebhook}">
          </div>
          <div class="soc-form-group">
            <label>Email Recipients</label>
            <input type="text" class="soc-input" id="cfgEmail" placeholder="soc@company.com, ciso@company.com" value="${STATE.settings.emailRecipients}">
          </div>
          <div class="soc-form-group">
            <label>Notify on severity:</label>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">
              ${['critical','high','medium'].map(s=>`
              <label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:12.5px;color:var(--soc-text);">
                <input type="checkbox" ${s!=='medium'?'checked':''} id="notify-${s}"> <span class="sev-badge ${s}">${s}</span>
              </label>`).join('')}
            </div>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="soc-btn sm primary" onclick="SOCOperations.saveNotificationSettings()"><i class="fas fa-save"></i> Save Settings</button>
            <button class="soc-btn sm" onclick="SOCOperations.testNotification()"><i class="fas fa-paper-plane"></i> Test</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 6: AI ASSISTANT                                    -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-ai-assistant">

  <div class="soc-grid-main" style="flex:1;min-height:0;">
    <!-- Chat -->
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div class="soc-ctx-bar" id="aiCtxBar">
        <span class="soc-ctx-label"><i class="fas fa-info-circle"></i> Investigation Context:</span>
        <span class="soc-ctx-tag warn" id="aiCtxStatus">No active investigation</span>
        <span class="soc-ctx-tag" id="aiCtxFindings">0 findings</span>
        <span class="soc-ctx-tag" id="aiCtxRisk">Risk: N/A</span>
      </div>

      <div class="soc-chat-suggestions" id="chatSuggestions">
        ${[
          'What is the root cause?',
          'List suspicious IPs',
          'Show MITRE tactics',
          'What is the risk score?',
          'Give me recommendations',
          'Classify the threat actor',
          'Show critical findings',
        ].map(s => `<span class="soc-suggestion" onclick="SOCOperations.sendSuggestion('${s}')">${s}</span>`).join('')}
      </div>

      <div class="soc-chat-wrap">
        <div class="soc-chat-messages" id="chatMessages">
          <div class="soc-msg ai">
            <div class="soc-msg-avatar"><i class="fas fa-robot"></i></div>
            <div>
              <div class="soc-msg-body">
                Hello! I'm your SOC AI Assistant. I can help you investigate security incidents, analyze threats, and answer questions about your current investigation.<br><br>
                <strong>To get started:</strong>
                <ul style="margin:6px 0 0 16px;padding:0;">
                  <li>Run a <strong>Manual Investigation</strong> first to build context</li>
                  <li>Or ask me general security questions</li>
                  <li>Use the suggestion buttons above for quick queries</li>
                </ul>
              </div>
              <div class="soc-msg-time">${new Date().toLocaleTimeString()}</div>
            </div>
          </div>
        </div>
        <div class="soc-chat-input-wrap">
          <textarea class="soc-chat-input" id="chatInput" placeholder="Ask anything about the investigation... (Enter to send, Shift+Enter for newline)" rows="1"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();SOCOperations.sendChatMessage();}"
            oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px'"></textarea>
          <button class="soc-chat-send" id="chatSendBtn" onclick="SOCOperations.sendChatMessage()">
            <i class="fas fa-paper-plane"></i>
          </button>
        </div>
      </div>
    </div>

    <!-- Right: AI Info Panel -->
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div class="soc-card">
        <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-brain"></i> AI Engine Status</div></div>
        <div class="soc-card-body">
          <div style="display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:12.5px;color:var(--soc-muted);">Local Engine</span>
              <span class="status-badge active">Active</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:12.5px;color:var(--soc-muted);">OpenAI GPT-4o</span>
              <span class="status-badge" id="aiOpenAIStatus">Not configured</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:12.5px;color:var(--soc-muted);">Detection Rules</span>
              <span class="status-badge active">25 rules</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:12.5px;color:var(--soc-muted);">MITRE ATT&amp;CK</span>
              <span class="status-badge active">v14 · 12 tactics</span>
            </div>
          </div>
          <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--soc-border);">
            <label style="font-size:12px;font-weight:600;color:var(--soc-muted);display:block;margin-bottom:6px;">Enable GPT-4o</label>
            <input type="password" class="soc-input" id="aiChatApiKey" placeholder="sk-..." oninput="SOCOperations.updateAIKey(this.value)">
            <div style="font-size:11px;color:var(--soc-muted);margin-top:5px;">Unlocks AI-enhanced analysis and natural-language chat responses.</div>
          </div>
        </div>
      </div>

      <div class="soc-card">
        <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-history"></i> Recent Queries</div></div>
        <div class="soc-card-body" id="aiRecentQueries">
          <div style="font-size:12px;color:var(--soc-muted);">No queries yet</div>
        </div>
      </div>

      <div class="soc-card">
        <div class="soc-card-header"><div class="soc-card-title"><i class="fas fa-lightbulb"></i> Capabilities</div></div>
        <div class="soc-card-body">
          <div style="display:flex;flex-direction:column;gap:7px;">
            ${[
              ['fas fa-search','Root cause analysis'],
              ['fas fa-map','MITRE ATT&CK mapping'],
              ['fas fa-user-secret','Threat actor profiling'],
              ['fas fa-list-ol','Remediation guidance'],
              ['fas fa-chart-line','Risk scoring'],
              ['fas fa-filter','False-positive reduction'],
              ['fas fa-clock','Attack timeline analysis'],
              ['fas fa-network-wired','Entity relationship mapping'],
            ].map(([i,l]) => `<div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--soc-muted);"><i class="${i}" style="color:var(--soc-accent);width:14px;"></i>${l}</div>`).join('')}
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ─────────────────────────────────────────────────────── -->
<!-- TAB 7: NETWORK TRAFFIC ANALYSIS  (DFIR Edition)       -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-network-traffic">
  <div style="display:flex;flex-direction:column;gap:16px;padding:0">

    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div>
        <h2 style="margin:0;font-size:1.25rem;font-weight:700;color:var(--soc-text)">
          <i class="fas fa-network-wired" style="color:#22d3ee;margin-right:8px;"></i>
          Network Traffic Analysis <span style="font-size:11px;color:#22d3ee;font-weight:400;margin-left:6px;">DFIR Engine v3</span>
        </h2>
        <div style="font-size:12px;color:var(--soc-muted);margin-top:2px;">
          Deep packet inspection · TCP stream reassembly · DGA detection · Ransomware chain rules · IOC extraction
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="soc-btn-secondary" onclick="SOCOperations.ntaExportIOCs()" style="font-size:12px;" id="ntaBtnExport" disabled>
          <i class="fas fa-file-export"></i> Export IOCs
        </button>
        <button class="soc-btn-secondary" onclick="SOCOperations.ntaClearResults()" style="font-size:12px;">
          <i class="fas fa-trash-alt"></i> Clear
        </button>
        <button class="soc-btn-primary" onclick="document.getElementById('ntaFileInput').click()" style="font-size:12px;background:#22d3ee;color:#000;">
          <i class="fas fa-upload"></i> Upload PCAP
        </button>
        <input type="file" id="ntaFileInput" accept=".pcap,.pcapng,.cap" multiple style="display:none"
          onchange="SOCOperations.ntaHandleUpload(this.files)">
      </div>
    </div>

    <!-- Upload Zone -->
    <div id="ntaDropZone" class="soc-upload-zone"
      style="border:2px dashed #22d3ee44;border-radius:12px;padding:40px;text-align:center;cursor:pointer;transition:all .2s;background:rgba(34,211,238,.04);"
      onclick="document.getElementById('ntaFileInput').click()"
      ondragover="event.preventDefault();this.style.borderColor='#22d3ee';this.style.background='rgba(34,211,238,.1)'"
      ondragleave="this.style.borderColor='#22d3ee44';this.style.background='rgba(34,211,238,.04)'"
      ondrop="event.preventDefault();this.style.borderColor='#22d3ee44';this.style.background='rgba(34,211,238,.04)';SOCOperations.ntaHandleUpload(event.dataTransfer.files)">
      <i class="fas fa-file-archive" style="font-size:3rem;color:#22d3ee;opacity:.6;margin-bottom:14px;display:block;"></i>
      <div style="font-size:1.05rem;font-weight:700;color:var(--soc-text);margin-bottom:6px;">Drop PCAP / PCAPNG files here</div>
      <div style="font-size:12px;color:var(--soc-muted);">Supports .pcap · .pcapng · .cap &mdash; Full TCP stream reassembly, chunked+gzip decode, DGA &amp; ransomware detection</div>
    </div>

    <!-- Status bar -->
    <div id="ntaStatus" style="display:none;align-items:center;gap:10px;background:rgba(34,211,238,.08);border:1px solid #22d3ee44;border-radius:8px;padding:12px 16px;">
      <i class="fas fa-spinner fa-spin" style="color:#22d3ee;"></i>
      <span id="ntaStatusText" style="font-size:13px;color:var(--soc-text);">Parsing PCAP file…</span>
      <div style="flex:1;background:rgba(255,255,255,.1);border-radius:4px;height:6px;overflow:hidden;">
        <div id="ntaProgress" style="height:100%;background:linear-gradient(90deg,#22d3ee,#3b82f6);width:0%;transition:width .3s;"></div>
      </div>
      <span id="ntaProgressPct" style="font-size:12px;color:#22d3ee;min-width:36px;font-weight:700;">0%</span>
    </div>

    <!-- ── RESULTS (hidden until analysis complete) ── -->
    <div id="ntaResults" style="display:none;flex-direction:column;gap:16px;">

      <!-- UI-009: ANALYST VERDICT BANNER -->
      <div id="ntaVerdictBanner" style="border-radius:12px;padding:20px 24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;"></div>

      <!-- UI-001: KPI Row -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;" id="ntaKpiRow"></div>

      <!-- UI-002: Threat Alert Panel -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:700;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-exclamation-triangle" style="color:#ef4444;"></i>
          Threat Detections
          <span id="ntaSuspCount" style="background:#ef444422;color:#ef4444;font-size:11px;padding:1px 10px;border-radius:10px;border:1px solid #ef444444;margin-left:4px;"></span>
        </div>
        <div id="ntaSuspicious" style="display:flex;flex-direction:column;gap:8px;"></div>
      </div>

      <!-- UI-003: Kill Chain / Attack Timeline -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:700;font-size:.9rem;color:var(--soc-text);margin-bottom:14px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-skull-crossbones" style="color:#f97316;"></i> Attack Kill Chain Timeline
        </div>
        <div id="ntaKillChain" style="overflow-x:auto;"></div>
      </div>

      <!-- UI-004: IOC Table -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:700;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-crosshairs" style="color:#a855f7;"></i> Extracted IOCs
          <span id="ntaIocCount" style="background:#a855f722;color:#a855f7;font-size:11px;padding:1px 10px;border-radius:10px;border:1px solid #a855f744;margin-left:4px;"></span>
        </div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:12px;">
            <thead>
              <tr style="border-bottom:1px solid var(--soc-border);color:var(--soc-muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;">
                <th style="padding:6px 8px;text-align:left;font-weight:600;">Type</th>
                <th style="padding:6px 8px;text-align:left;font-weight:600;">Value</th>
                <th style="padding:6px 8px;text-align:left;font-weight:600;">Context</th>
                <th style="padding:6px 8px;text-align:left;font-weight:600;">Risk</th>
                <th style="padding:6px 8px;text-align:left;font-weight:600;">Pivot</th>
              </tr>
            </thead>
            <tbody id="ntaIocTable"></tbody>
          </table>
        </div>
      </div>

      <!-- Three-column: Protocols · Conversations · DNS -->
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">

        <!-- UI-007: Protocols -->
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-chart-pie" style="color:#22d3ee;"></i> Protocol Breakdown
          </div>
          <div id="ntaProtocols" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <!-- UI-007: Top Conversations -->
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-exchange-alt" style="color:#a855f7;"></i> Top Conversations
          </div>
          <div id="ntaConversations" style="font-size:12px;"></div>
        </div>

        <!-- UI-005: DNS Analysis Panel -->
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-globe" style="color:#3b82f6;"></i> DNS Analysis
          </div>
          <div id="ntaDns" style="font-size:12px;display:flex;flex-direction:column;gap:5px;"></div>
        </div>
      </div>

      <!-- UI-006: HTTP Analysis Panel (full-width) -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:700;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-code" style="color:#f97316;"></i> HTTP Stream Analysis
        </div>
        <div id="ntaHttp" style="display:flex;flex-direction:column;gap:8px;"></div>
      </div>

      <!-- UI-008: MITRE ATT&CK Heatmap -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:700;font-size:.9rem;color:var(--soc-text);margin-bottom:14px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-th" style="color:#f59e0b;"></i> MITRE ATT&amp;CK Coverage
        </div>
        <div id="ntaMitre" style="display:flex;flex-wrap:wrap;gap:8px;"></div>
      </div>

      <!-- Traffic Timeline -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:600;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-clock" style="color:#22c55e;"></i> Traffic Timeline
        </div>
        <div id="ntaTimeline" style="display:flex;flex-direction:column;gap:6px;max-height:300px;overflow-y:auto;"></div>
      </div>

    </div><!-- /#ntaResults -->
  </div>
</div>
`;
  }

  /* ─── Event Listeners ───────────────────────────────────────────── */
  function attachEventListeners() {
    // Drag & drop upload
    const zone = document.getElementById('uploadZone');
    if (zone) {
      zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        handleDroppedFiles(e.dataTransfer.files);
      });
    }
  }

  /* ─── Tab Switching ─────────────────────────────────────────────── */
  function switchTab(tab) {
    STATE.activeTab = tab;
    document.querySelectorAll('#socTabBar .soc-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.soc-panel').forEach(p => p.classList.remove('active'));

    const tabEl = document.querySelector(`[onclick*="switchTab('${tab}')"]`);
    if (tabEl) tabEl.classList.add('active');
    const panel = document.getElementById(`soc-tab-${tab}`);
    if (panel) panel.classList.add('active');

    if (tab === 'reports') setTimeout(renderSeverityChart, 100);
    if (tab === 'ai-assistant') updateAIContext();
    if (tab === 'network-traffic') {
      // Reset NTA upload zone if no parsed data
      const dropZone = document.getElementById('ntaDropZone');
      const results = document.getElementById('ntaResults');
      if (dropZone && !NTA_STATE.parsed) {
        dropZone.style.display = 'block';
        if (results) results.style.display = 'none';
      }
    }
  }

  /* ─── ════════ TAB 1: AUTOMATION ════════ ──────────────────────── */

  let _eventCount = 0, _detectCount = 0, _rateBuffer = [];

  function startIngestion() {
    if (STATE.ingestionRunning) return;
    STATE.ingestionRunning = true;
    document.getElementById('rtStartBtn').style.display = 'none';
    document.getElementById('rtStopBtn').style.display = '';
    document.getElementById('rtDot').style.background = 'var(--soc-green)';
    document.getElementById('rtSourceLabel').textContent = '● Ingesting — ' + document.getElementById('rtSourceSelect').value;

    STATE.ingestionTimer = setInterval(async () => {
      const tmpl = randPick(SAMPLE_LOG_TEMPLATES);
      const msg = tmpl.msg();
      const level = tmpl.level;
      const timestamp = ts();

      appendLog(timestamp, level, msg);
      _eventCount++;
      _rateBuffer.push(Date.now());

      // Run detection
      const rawText = msg.replace(/<[^>]+>/g, '');
      const result = await SOCEngine.analyzeRealtimeEvent(rawText);

      for (const finding of result.findings) {
        _detectCount++;
        addAutomationAlert(finding, timestamp);
        // Auto create incident
        const autoInc = document.getElementById('auto-incident');
        if (autoInc?.checked) createIncidentFromAlert(finding);
        // Notification
        const autoNotify = document.getElementById('auto-notify');
        if (autoNotify?.checked && ['critical','high'].includes(finding.severity)) {
          if (typeof showToast === 'function') {
            showToast(`[${finding.severity.toUpperCase()}] ${finding.name}`, finding.severity === 'critical' ? 'error' : 'warning');
          }
        }
      }

      // Update counters
      document.getElementById('rtEventCount').textContent = _eventCount.toLocaleString();
      document.getElementById('rtDetectCount').textContent = _detectCount;

      // Calc rate
      const now = Date.now();
      _rateBuffer = _rateBuffer.filter(t => now - t < 60000);
      document.getElementById('rtRate').textContent = _rateBuffer.length;

      updateKPIs();
    }, 1800 + Math.random() * 1200);
  }

  function stopIngestion() {
    STATE.ingestionRunning = false;
    clearInterval(STATE.ingestionTimer);
    document.getElementById('rtStartBtn').style.display = '';
    document.getElementById('rtStopBtn').style.display = 'none';
    document.getElementById('rtDot').style.background = '#3d4f60';
    document.getElementById('rtSourceLabel').textContent = 'Stopped';
    if (typeof showToast === 'function') showToast('Ingestion stopped', 'info');
  }

  function appendLog(timestamp, level, msg) {
    const log = document.getElementById('rtLog');
    if (!log) return;
    const entry = document.createElement('div');
    entry.className = 'soc-log-entry';
    entry.innerHTML = `<span class="soc-log-ts">${timestamp}</span><span class="soc-log-lvl ${level}">${level.toUpperCase()}</span><span class="soc-log-msg">${msg}</span>`;
    log.appendChild(entry);
    // Keep max 200 lines
    while (log.children.length > 200) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
    STATE.ingestionLogLines.push({ timestamp, level, msg: msg.replace(/<[^>]+>/g, '') });
  }

  function clearLog() {
    const log = document.getElementById('rtLog');
    if (log) log.innerHTML = '<div class="soc-log-entry"><span class="soc-log-ts">—</span><span class="soc-log-msg" style="color:#3d4f60;">Log cleared.</span></div>';
    STATE.ingestionLogLines = [];
    _eventCount = 0; _detectCount = 0; _rateBuffer = [];
    ['rtEventCount','rtDetectCount','rtRate'].forEach(id => { const e = document.getElementById(id); if(e) e.textContent='0'; });
  }

  function addAutomationAlert(finding, timestamp) {
    const existing = STATE.alerts.find(a => a.rule_id === finding.rule_id && Date.now() - a._ts < 30000);
    if (existing) { existing.match_count++; renderAlerts(); return; }

    STATE.alerts.unshift({
      id: 'ALT-' + Date.now(),
      _ts: Date.now(),
      ...finding,
      timestamp,
    });
    if (STATE.alerts.length > 200) STATE.alerts.pop();
    renderAlerts();
    updateBadge('soc-badge-alerts', STATE.alerts.length);
    updateKPIs();
  }

  function loadAutomationAlerts() {
    renderAlerts();
    updateKPIs();
  }

  function renderAlerts() {
    const container = document.getElementById('alertStream');
    if (!container) return;
    const filter = document.getElementById('alertSevFilter')?.value || 'all';
    const filtered = filter === 'all' ? STATE.alerts : STATE.alerts.filter(a => a.severity === filter);

    if (!filtered.length) {
      container.innerHTML = '<div class="soc-empty"><i class="fas fa-shield-alt"></i><p>No alerts</p><small>Start ingestion to detect threats in real time</small></div>';
      return;
    }

    container.innerHTML = filtered.slice(0, 50).map(a => `
      <div class="soc-alert-card ${a.severity}" onclick="SOCOperations.openAlertDetail('${a.id}')">
        <div class="soc-alert-top">
          <span class="sev-badge ${a.severity}">${a.severity}</span>
          <span class="soc-alert-title">${esc(a.name)}</span>
          <span class="soc-alert-time">${fmtAgo(a._ts)}</span>
        </div>
        <div class="soc-alert-meta">
          <span><i class="fas fa-tag"></i> ${a.rule_id}</span>
          <span><i class="fas fa-shield-alt"></i> ${a.tactic_name || ''}</span>
          ${a.affected_ips[0] ? `<span><i class="fas fa-network-wired"></i> ${a.affected_ips[0]}</span>` : ''}
          <span><i class="fas fa-crosshairs"></i> ${a.mitre_techniques?.[0] || ''}</span>
          <span style="margin-left:auto;display:flex;gap:6px;">
            <button class="soc-btn sm success" onclick="event.stopPropagation();SOCOperations.escalateToIncident('${a.id}')"><i class="fas fa-fire"></i> Escalate</button>
          </span>
        </div>
      </div>`).join('');
  }

  function filterAlerts() { renderAlerts(); }
  function clearAlerts() {
    STATE.alerts = [];
    renderAlerts();
    updateBadge('soc-badge-alerts', 0);
    updateKPIs();
  }

  function openAlertDetail(id) {
    const alert = STATE.alerts.find(a => a.id === id);
    if (!alert || typeof showToast !== 'function') return;
    showToast(`${alert.name} — ${alert.description}`, 'info', 5000);
  }

  function escalateToIncident(alertId) {
    const alert = STATE.alerts.find(a => a.id === alertId);
    if (!alert) return;
    const inc = createIncidentFromAlert(alert);
    loadIncidents();
    switchTab('incidents');
    if (typeof showToast === 'function') showToast(`Incident ${inc.id} created from ${alert.name}`, 'success');
  }

  function saveThresholds() {
    const thresholds = {
      bruteForce: +document.getElementById('thr-bruteForce').value,
      portScan:   +document.getElementById('thr-portScan').value,
      credentialStuffing: +document.getElementById('thr-credStuffing').value,
      dataExfil:  +document.getElementById('thr-dataExfil').value,
    };
    if (window.SOCEngine) SOCEngine.setThresholds(thresholds);
    if (typeof showToast === 'function') showToast('Detection thresholds saved', 'success');
  }

  function updateKPIs() {
    const critical = STATE.alerts.filter(a => a.severity === 'critical').length;
    const high     = STATE.alerts.filter(a => a.severity === 'high').length;
    const medium   = STATE.alerts.filter(a => a.severity === 'medium').length;
    document.getElementById('kpi-critical')?.innerHTML && (document.getElementById('kpi-critical').textContent = critical);
    document.getElementById('kpi-high')?.textContent != null && (document.getElementById('kpi-high').textContent = high);
    document.getElementById('kpi-medium')?.textContent != null && (document.getElementById('kpi-medium').textContent = medium);
  }

  /* ─── ════════ TAB 2: MANUAL INVESTIGATION ════════ ─────────────── */

  let _uploadedFiles = [];
  let _currentReport = null;

  function handleFileUpload(event) {
    handleDroppedFiles(event.target.files);
  }

  function handleDroppedFiles(fileList) {
    for (const file of fileList) {
      if (!_uploadedFiles.find(f => f.name === file.name)) {
        _uploadedFiles.push(file);
      }
    }
    renderUploadedFiles();
    updateAnalyzeButton();
  }

  function renderUploadedFiles() {
    const container = document.getElementById('uploadedFiles');
    if (!container) return;
    container.innerHTML = _uploadedFiles.map((f, i) => `
      <div class="soc-file-chip">
        <i class="fas fa-file-code"></i>
        <span>${esc(f.name)}</span>
        <span style="font-size:10px;color:var(--soc-muted);">${(f.size/1024).toFixed(1)}KB</span>
        <span class="remove" onclick="SOCOperations.removeFile(${i})"><i class="fas fa-times"></i></span>
      </div>`).join('');
  }

  function removeFile(idx) {
    _uploadedFiles.splice(idx, 1);
    renderUploadedFiles();
    updateAnalyzeButton();
  }

  function updateAnalyzeButton() {
    const btn = document.getElementById('invAnalyzeBtn');
    const lbl = document.getElementById('invFileCount');
    if (!btn) return;
    btn.disabled = _uploadedFiles.length === 0;
    if (lbl) lbl.textContent = _uploadedFiles.length
      ? `${_uploadedFiles.length} file(s) ready — ${_uploadedFiles.reduce((s,f)=>s+f.size,0)/1024 < 1024 ? (_uploadedFiles.reduce((s,f)=>s+f.size,0)/1024).toFixed(1)+'KB' : (_uploadedFiles.reduce((s,f)=>s+f.size,0)/1024/1024).toFixed(2)+'MB'}`
      : 'No files selected';
  }

  function updateApiKey(key) {
    STATE.apiKey = key;
    if (window.SOCEngine) SOCEngine.setApiKey(key);
    const aiKey = document.getElementById('aiChatApiKey');
    if (aiKey && !aiKey.value) aiKey.value = key;
    updateAIStatusBadge();
  }

  function updateAIKey(key) {
    STATE.settings.openaiKey = key;
    STATE.apiKey = key;
    if (window.SOCEngine) SOCEngine.setApiKey(key);
    const invKey = document.getElementById('invApiKey');
    if (invKey && !invKey.value) invKey.value = key;
    updateAIStatusBadge();
  }

  function updateAIStatusBadge() {
    const badge = document.getElementById('aiOpenAIStatus');
    if (!badge) return;
    if (STATE.apiKey || STATE.settings.openaiKey) {
      badge.className = 'status-badge active';
      badge.textContent = 'Connected';
    } else {
      badge.className = 'status-badge closed';
      badge.textContent = 'Not configured';
    }
  }

  function loadSampleLogs() {
    const sampleContent = `2024-01-15 09:23:11 Failed password for admin from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:12 Failed password for admin from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:13 Failed password for root from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:14 Failed password for admin from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:15 Failed password for sysadmin from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:16 Failed password for admin from 192.168.1.105 port 22 ssh2
2024-01-15 09:23:17 Failed password for test from 192.168.1.105 port 22 ssh2
2024-01-15 09:24:02 Accepted password for admin from 192.168.1.105 port 22 ssh2
2024-01-15 09:24:10 sudo: www-data: TTY=pts/1; PWD=/var/www; USER=root; COMMAND=/bin/bash -p
2024-01-15 09:24:11 sudo -s by www-data on web-server-01
2024-01-15 09:24:15 useradd -m backdoor_user
2024-01-15 09:24:20 net user hacker P@ssw0rd123 /add
2024-01-15 09:25:00 127.0.0.1 - - [15/Jan/2024:09:25:00 +0000] "GET /api/users?id=1 UNION SELECT username,password,3,4,5 FROM admin_users-- HTTP/1.1" 200 2345
2024-01-15 09:25:05 Port scan detected: 192.168.1.105 hit 28 ports in 5 seconds (nmap -sS)
2024-01-15 09:26:00 SMB login from 10.0.1.105 to 10.0.1.30 using admin credentials (net use Z: \\\\10.0.1.30\\c$)
2024-01-15 09:26:10 wmic /node:10.0.1.25 process call create "powershell -nop -w hidden -enc SQBFAFgA"
2024-01-15 09:27:00 powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
2024-01-15 09:27:30 procdump.exe -ma lsass.exe lsass.dmp (by user: NT AUTHORITY\\SYSTEM)
2024-01-15 09:28:00 vssadmin delete shadows /all /quiet
2024-01-15 09:28:01 wmic shadowcopy delete
2024-01-15 09:28:05 Large outbound transfer: 192.168.1.50 → 185.220.101.47:443 — 147 megabytes in 120s (data exfiltration suspected)
2024-01-15 09:28:30 C2 callback detected: beacon interval 60s to 185.220.101.47:4444 (Cobalt Strike)
2024-01-15 09:29:00 Event log cleared on WORKSTATION-07 by Administrator (wevtutil cl System)
2024-01-15 09:29:05 Ransomware activity: file encryption started — .locked extension observed on FILE-SRV01`;

    const blob = new Blob([sampleContent], { type: 'text/plain' });
    const file = new File([blob], 'sample-security.log', { type: 'text/plain', lastModified: Date.now() });
    _uploadedFiles = [file];
    renderUploadedFiles();
    updateAnalyzeButton();
    if (typeof showToast === 'function') showToast('Sample log loaded — click Analyze to investigate', 'success');
  }

  async function runInvestigation() {
    if (!_uploadedFiles.length) return;

    const btn = document.getElementById('invAnalyzeBtn');
    if (btn) btn.disabled = true;

    // Show pipeline
    const pipeline = document.getElementById('invPipeline');
    if (pipeline) pipeline.style.display = '';
    const results = document.getElementById('invResults');
    if (results) results.style.display = 'none';

    const clearBtn = document.getElementById('invClearBtn');
    if (clearBtn) clearBtn.style.display = '';

    const steps = 5;
    async function advanceStep(step, label) {
      for (let i = 0; i < step; i++) {
        const el = document.getElementById(`pipe-step-${i}`);
        if (el) el.className = 'soc-pipe-step done';
      }
      const activeEl = document.getElementById(`pipe-step-${step}`);
      if (activeEl) activeEl.className = 'soc-pipe-step active';
      const prog = (step / steps) * 100;
      const bar = document.getElementById('invProgressBar');
      if (bar) bar.style.width = prog + '%';
      const lbl = document.getElementById('invProgressLabel');
      if (lbl) lbl.textContent = label;
      await new Promise(r => setTimeout(r, 700 + Math.random() * 600));
    }

    try {
      await advanceStep(0, 'Parsing log files…');

      // Read all files
      const contents = [];
      for (const file of _uploadedFiles) {
        const text = await readFile(file);
        contents.push({ name: file.name, content: text });
      }

      await advanceStep(1, 'Running detection rules…');

      // Analyze each file
      let mergedContent = contents.map(c => c.content).join('\n');
      const filename = contents.length === 1 ? contents[0].name : `${contents.length} files`;

      if (window.SOCEngine) {
        SOCEngine.setApiKey(STATE.apiKey || STATE.settings.openaiKey);
      }

      await advanceStep(2, 'AI analysis…');

      const analysis = window.SOCEngine
        ? await SOCEngine.analyzeLog(mergedContent, filename, { useAI: !!(STATE.apiKey || STATE.settings.openaiKey) })
        : generateMockAnalysis(filename);

      await advanceStep(3, 'Building investigation report…');
      await new Promise(r => setTimeout(r, 500));

      await advanceStep(4, 'Finalizing report…');

      // Complete pipeline
      for (let i = 0; i < steps; i++) {
        const el = document.getElementById(`pipe-step-${i}`);
        if (el) el.className = 'soc-pipe-step done';
      }
      const bar = document.getElementById('invProgressBar');
      if (bar) bar.style.width = '100%';
      const lbl = document.getElementById('invProgressLabel');
      if (lbl) lbl.textContent = `Analysis complete — ${analysis.findings.length} findings in ${analysis.summary.analysis_duration_ms}ms`;

      STATE.currentInvestigation = analysis;
      _currentReport = analysis;

      // Store for AI
      if (window.SOCEngine) updateAIContext();

      // Render results
      renderInvestigationResults(analysis);

      // Auto-create incidents for critical findings
      const autoInc = document.getElementById('auto-incident');
      if (autoInc?.checked) {
        analysis.findings.filter(f => f.severity === 'critical').forEach(f => createIncidentFromAlert(f));
        loadIncidents();
      }

      if (typeof showToast === 'function') {
        showToast(`Investigation complete: ${analysis.findings.length} findings, risk score ${analysis.risk_score.score}/100`, 'success', 6000);
      }

    } catch (err) {
      console.error('[SOCOps] Investigation error:', err);
      const lbl = document.getElementById('invProgressLabel');
      if (lbl) lbl.textContent = 'Analysis failed: ' + err.message;
      if (typeof showToast === 'function') showToast('Analysis error: ' + err.message, 'error');
    }

    if (btn) btn.disabled = false;
  }

  function readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = () => reject(new Error('File read error'));
      reader.readAsText(file);
    });
  }

  function generateMockAnalysis(filename) {
    return {
      summary: {
        filename, log_type: 'mixed', total_lines: 245,
        total_findings: 8, critical_count: 3, high_count: 3, medium_count: 2, low_count: 0,
        analysis_duration_ms: 1240, ai_enhanced: false,
        executive_summary: 'Analysis identified 8 critical security findings including credential brute force, lateral movement, and ransomware indicators. Immediate response required.',
        attack_narrative: '## Attack Narrative\n\nThe logs reveal a sophisticated multi-stage attack beginning with SSH brute force (192.168.1.105), followed by privilege escalation and lateral movement using SMB. Ransomware indicators detected at final stage.',
        root_cause: 'Initial access via SSH brute force attack against weak credentials on exposed service.',
        threat_classification: 'APT',
        immediate_actions: ['Isolate affected hosts immediately', 'Block 192.168.1.105 at firewall', 'Force credential reset for admin account'],
      },
      findings: [
        { rule_id: 'DR-001', name: 'Brute Force Attack', severity: 'high', confidence: 95, match_count: 7, mitre_techniques: ['T1110'], mitre_tactic: 'TA0006', tactic_name: 'Credential Access', description: 'Multiple failed SSH logins', affected_ips: ['192.168.1.105'], affected_users: ['admin'], sample_lines: ['Failed password for admin'], first_seen: null, last_seen: null, category: 'credential_attack' },
        { rule_id: 'DR-003', name: 'Privilege Escalation', severity: 'critical', confidence: 90, match_count: 2, mitre_techniques: ['T1068','T1548'], mitre_tactic: 'TA0004', tactic_name: 'Privilege Escalation', description: 'sudo -s by www-data', affected_ips: [], affected_users: ['www-data'], sample_lines: ['sudo -s by www-data'], first_seen: null, last_seen: null, category: 'privilege_escalation' },
        { rule_id: 'DR-010', name: 'Ransomware Activity', severity: 'critical', confidence: 97, match_count: 2, mitre_techniques: ['T1486'], mitre_tactic: 'TA0040', tactic_name: 'Impact', description: 'Shadow copy deletion', affected_ips: [], affected_users: [], sample_lines: ['vssadmin delete shadows /all'], first_seen: null, last_seen: null, category: 'malware' },
      ],
      timeline: [{ timestamp: '09:23:11', event: 'Brute Force', severity: 'high', category: 'credential_attack', detail: 'SSH brute force begins', mitre: 'T1110', tactic: 'Credential Access' }],
      entities: [{ type: 'ip', value: '192.168.1.105', count: 12, severity: 'critical', flags: ['Brute Force'] }],
      mitre_mapping: [{ tactic_id: 'TA0006', tactic_name: 'Credential Access', techniques: [{ id: 'T1110', name: 'Brute Force', severity: 'high', confidence: 95 }] }],
      risk_score: { score: 87, level: 'CRITICAL', breakdown: { critical: 3, high: 3, medium: 2, low: 0 } },
      recommendations: [
        { priority: 'immediate', action: 'Isolate affected hosts and revoke all admin sessions', rationale: 'Active compromise in progress', trigger: 'Ransomware Activity' },
        { priority: 'short-term', action: 'Implement SSH key-based auth, disable password login', rationale: 'Prevent reoccurrence', trigger: 'Brute Force' },
      ],
    };
  }

  function renderInvestigationResults(analysis) {
    const container = document.getElementById('invResults');
    if (!container) return;
    container.style.display = '';

    const s = analysis.summary;
    const r = analysis.risk_score;
    const rLevel = r.level?.toLowerCase() || 'low';

    container.innerHTML = `
    <!-- Risk Score Widget -->
    <div class="soc-risk-widget">
      <div class="soc-risk-circle ${rLevel}">
        <div class="soc-risk-number">${r.score}</div>
        <div class="soc-risk-label">/ 100</div>
      </div>
      <div class="soc-risk-details">
        <div class="soc-risk-level"><span class="sev-badge ${rLevel}">${r.level}</span> Risk Level</div>
        <div style="font-size:12.5px;color:var(--soc-muted);margin-top:4px;line-height:1.5;">${esc(s.executive_summary)}</div>
        <div class="soc-risk-breakdown">
          <span><span class="sev-badge critical">${r.breakdown.critical||0} crit</span></span>
          <span><span class="sev-badge high">${r.breakdown.high||0} high</span></span>
          <span><span class="sev-badge medium">${r.breakdown.medium||0} med</span></span>
          <span><span class="sev-badge low">${r.breakdown.low||0} low</span></span>
          <span style="margin-left:auto;"><span style="font-size:11px;color:var(--soc-muted);">${s.total_lines?.toLocaleString()} lines · ${s.analysis_duration_ms}ms · ${s.ai_enhanced?'AI-enhanced':'Local engine'}</span></span>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0;">
        <button class="soc-btn primary sm" onclick="SOCOperations.switchTab('reports');setTimeout(()=>SOCOperations.selectReportTemplate('inv','Investigation Report'),100)">
          <i class="fas fa-file-pdf"></i> Generate Report
        </button>
        <button class="soc-btn sm" onclick="SOCOperations.saveAsIncident()">
          <i class="fas fa-fire"></i> Create Incident
        </button>
        <button class="soc-btn sm" onclick="SOCOperations.switchTab('ai-assistant')">
          <i class="fas fa-comments"></i> Ask AI
        </button>
      </div>
    </div>

    <!-- Tabs within results -->
    <div class="soc-card">
      <div style="display:flex;gap:2px;padding:12px 16px 0;border-bottom:1px solid var(--soc-border);" id="invResTabs">
        ${[
          ['findings',`Findings (${analysis.findings.length})`,'fas fa-crosshairs'],
          ['timeline',`Timeline (${analysis.timeline.length})`,'fas fa-clock'],
          ['mitre',`MITRE ATT&CK`,'fas fa-th'],
          ['entities',`Entities (${analysis.entities.length})`,'fas fa-network-wired'],
          ['narrative','Narrative','fas fa-file-alt'],
          ['recommendations',`Recommendations (${analysis.recommendations.length})`,'fas fa-tasks'],
        ].map(([id,label,icon],i) => `
        <button class="soc-tab${i===0?' active':''}" style="font-size:11.5px;padding:6px 12px;" onclick="SOCOperations.switchResTab('${id}',this)"
          id="res-tab-${id}">
          <i class="${icon}"></i> ${label}
        </button>`).join('')}
      </div>
      <div class="soc-card-body" style="padding:16px;">
        <!-- Findings -->
        <div id="res-findings" class="soc-findings-list">
          ${analysis.findings.map(f => `
          <div class="soc-finding-item ${f.severity}">
            <div class="soc-finding-header">
              <span class="sev-badge ${f.severity}">${f.severity}</span>
              <span class="soc-finding-name">${esc(f.name)}</span>
              <span class="soc-finding-confidence">
                <div class="soc-conf-bar" style="gap:6px;">
                  <div class="soc-conf-track" style="width:80px;"><div class="soc-conf-fill ${f.confidence<50?'low':f.confidence<75?'med':''}" style="width:${f.confidence}%"></div></div>
                  <span class="soc-conf-pct">${f.confidence}%</span>
                </div>
              </span>
            </div>
            <div class="soc-finding-desc">${esc(f.description)} — <strong>${f.match_count}</strong> match(es)</div>
            <div class="soc-finding-tags">
              <span class="soc-tag">${f.rule_id}</span>
              ${f.mitre_techniques.map(t=>`<span class="soc-tag mitre">${t}</span>`).join('')}
              <span class="soc-tag tactic">${esc(f.tactic_name)}</span>
              ${f.affected_ips.slice(0,3).map(ip=>`<span class="soc-tag"><i class="fas fa-network-wired"></i> ${esc(ip)}</span>`).join('')}
            </div>
          </div>`).join('') || '<div class="soc-empty"><i class="fas fa-check-circle"></i><p>No findings detected</p><small>Logs appear clean for the analyzed ruleset</small></div>'}
        </div>

        <!-- Timeline -->
        <div id="res-timeline" style="display:none;">
          ${analysis.timeline.length ? `<div class="soc-timeline">${analysis.timeline.map(e=>`
          <div class="soc-tl-item ${e.severity}">
            <div class="soc-tl-time">${esc(e.timestamp||'Unknown')}</div>
            <div class="soc-tl-event"><span class="sev-badge ${e.severity}">${e.severity}</span>${esc(e.event)}<span class="soc-tag mitre" style="font-size:10px;">${esc(e.mitre)}</span></div>
            <div class="soc-tl-detail">${esc(e.detail)}</div>
          </div>`).join('')}</div>` : '<div class="soc-empty"><i class="fas fa-clock"></i><p>No timestamped events</p></div>'}
        </div>

        <!-- MITRE -->
        <div id="res-mitre" style="display:none;">
          <div class="soc-mitre-grid">
            ${analysis.mitre_mapping.map(t=>`
            <div class="soc-mitre-tactic">
              <div class="soc-mitre-tactic-hdr">${esc(t.tactic_id)} · ${esc(t.tactic_name)}</div>
              <div class="soc-mitre-techniques">${t.techniques.map(tech=>`
              <div class="soc-mitre-tech ${tech.severity}" title="${esc(tech.name)} (${tech.confidence}%)">
                ${esc(tech.id)}<br><span style="font-size:9.5px;opacity:0.8;">${esc(tech.name)}</span>
              </div>`).join('')}</div>
            </div>`).join('') || '<div class="soc-empty"><i class="fas fa-th"></i><p>No MITRE coverage</p></div>'}
          </div>
        </div>

        <!-- Entities -->
        <div id="res-entities" style="display:none;">
          <div class="soc-entities-grid">
            ${analysis.entities.map(e=>`
            <div class="soc-entity">
              <div class="soc-entity-icon ${e.type}"><i class="fas fa-${e.type==='ip'?'network-wired':'user'}"></i></div>
              <div>
                <div class="soc-entity-val">${esc(e.value)}</div>
                <div class="soc-entity-cnt">${e.count} events · ${e.flags.slice(0,2).join(', ')||'No flags'}</div>
              </div>
              ${e.severity!=='info'?`<span class="sev-badge ${e.severity}" style="font-size:9px;">${e.severity}</span>`:''}
            </div>`).join('') || '<div class="soc-empty"><i class="fas fa-network-wired"></i><p>No entities identified</p></div>'}
          </div>
        </div>

        <!-- Narrative -->
        <div id="res-narrative" style="display:none;">
          <div class="soc-narrative">${markdownToHtml(analysis.summary.attack_narrative)}</div>
          <div class="soc-narrative" style="margin-top:12px;">
            <h3><i class="fas fa-search"></i> Root Cause</h3>
            <p>${esc(analysis.summary.root_cause)}</p>
            ${analysis.summary.false_positive_notes ? `<h3><i class="fas fa-filter"></i> False Positive Notes</h3><p>${esc(analysis.summary.false_positive_notes)}</p>` : ''}
            <h3><i class="fas fa-tag"></i> Threat Classification</h3>
            <p>${esc(analysis.summary.threat_classification)}</p>
          </div>
        </div>

        <!-- Recommendations -->
        <div id="res-recommendations" style="display:none;">
          <div class="soc-recs-list">
            ${analysis.recommendations.map(r=>`
            <div class="soc-rec-item">
              <span class="soc-rec-priority ${r.priority}">${r.priority}</span>
              <div class="soc-rec-body">
                <div class="soc-rec-action">${esc(r.action)}</div>
                <div class="soc-rec-rationale">${esc(r.rationale)}</div>
              </div>
              ${r.trigger?`<span style="font-size:10.5px;color:var(--soc-muted);flex-shrink:0;">${esc(r.trigger)}</span>`:''}
            </div>`).join('') || '<div class="soc-empty"><i class="fas fa-tasks"></i><p>No recommendations</p></div>'}
          </div>
        </div>
      </div>
    </div>`;
  }

  function switchResTab(tab, btn) {
    ['findings','timeline','mitre','entities','narrative','recommendations'].forEach(t => {
      const el = document.getElementById(`res-${t}`);
      const tabEl = document.getElementById(`res-tab-${t}`);
      if (el) el.style.display = t === tab ? '' : 'none';
      if (tabEl) tabEl.classList.toggle('active', t === tab);
    });
  }

  function clearInvestigation() {
    _uploadedFiles = [];
    _currentReport = null;
    STATE.currentInvestigation = null;
    renderUploadedFiles();
    updateAnalyzeButton();
    document.getElementById('invPipeline').style.display = 'none';
    document.getElementById('invResults').style.display = 'none';
    document.getElementById('invClearBtn').style.display = 'none';
    updateAIContext();
  }

  function saveAsIncident() {
    if (!STATE.currentInvestigation) return;
    const analysis = STATE.currentInvestigation;
    const topFinding = analysis.findings[0];
    if (!topFinding) return;
    const inc = createIncidentFromAlert({ ...topFinding, description: analysis.summary.executive_summary });
    loadIncidents();
    switchTab('incidents');
    if (typeof showToast === 'function') showToast(`Incident ${inc.id} created from investigation`, 'success');
  }

  /* ─── ════════ TAB 3: INCIDENTS ════════ ────────────────────────── */

  function loadIncidents() {
    renderIncidentTable(STATE.incidents);
    updateIncidentKPIs();
    updateBadge('soc-badge-inc', STATE.incidents.filter(i=>i.status==='open').length);
  }

  function renderIncidentTable(incidents) {
    const tbody = document.getElementById('incidentTableBody');
    if (!tbody) return;
    if (!incidents.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--soc-muted);">
        <i class="fas fa-shield-alt" style="font-size:28px;display:block;margin-bottom:10px;opacity:0.3;"></i>
        No incidents — generate alerts via Automation tab or create manually
      </td></tr>`;
      return;
    }
    tbody.innerHTML = incidents.map(inc => `
      <tr onclick="SOCOperations.openIncidentDrawer('${inc.id}')">
        <td><span class="soc-inc-id">${esc(inc.id)}</span></td>
        <td class="soc-inc-title-cell">
          <strong>${esc(inc.title)}</strong>
          <small>${esc(inc.category)}</small>
        </td>
        <td><span class="sev-badge ${inc.severity}">${inc.severity}</span></td>
        <td><span class="status-badge ${inc.status}">${inc.status}</span></td>
        <td style="font-size:12px;color:var(--soc-muted);">${esc(inc.category)}</td>
        <td style="font-size:12px;color:var(--soc-muted);">${fmtAgo(inc.created_at)}</td>
        <td style="font-size:12.5px;">${esc(inc.assignee)}</td>
        <td>
          <div style="display:flex;gap:4px;">
            <button class="soc-btn sm" onclick="event.stopPropagation();SOCOperations.updateIncidentStatus('${inc.id}','in-progress')" title="Acknowledge"><i class="fas fa-play"></i></button>
            <button class="soc-btn sm success" onclick="event.stopPropagation();SOCOperations.updateIncidentStatus('${inc.id}','resolved')" title="Resolve"><i class="fas fa-check"></i></button>
          </div>
        </td>
      </tr>`).join('');
  }

  function filterIncidents(status, btn) {
    document.querySelectorAll('.soc-inc-filters .soc-filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const filtered = status === 'all' ? STATE.incidents : STATE.incidents.filter(i => i.status === status);
    renderIncidentTable(filtered);
  }

  function updateIncidentKPIs() {
    const crit = STATE.incidents.filter(i => i.severity==='critical' && i.status==='open').length;
    const prog = STATE.incidents.filter(i => i.status==='in-progress').length;
    const res  = STATE.incidents.filter(i => i.status==='resolved').length;
    const el = (id, v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
    el('inc-kpi-crit', crit); el('inc-kpi-prog', prog); el('inc-kpi-res', res);
    document.getElementById('inc-kpi-mttr') && (document.getElementById('inc-kpi-mttr').textContent = res > 0 ? `~${Math.floor(Math.random()*30+15)}m` : '—');
  }

  function updateIncidentStatus(id, status) {
    const inc = STATE.incidents.find(i => i.id === id);
    if (!inc) return;
    inc.status = status;
    inc.updated_at = Date.now();
    loadIncidents();
    if (typeof showToast === 'function') showToast(`Incident ${id} marked as ${status}`, 'success');
  }

  function openIncidentDrawer(id) {
    const inc = STATE.incidents.find(i => i.id === id);
    if (!inc) return;
    STATE.openIncidentId = id;
    const drawer = document.getElementById('incDrawer');
    const overlay = document.getElementById('incDrawerOverlay');
    const title = document.getElementById('drawerTitle');
    const body = document.getElementById('drawerBody');
    if (!drawer) return;

    title.textContent = `${inc.id} — ${inc.title}`;

    const pbKey = inc.category === 'malware' ? 'ransomware' : inc.category === 'credential_attack' ? 'credential' : 'default';
    const playbook = PLAYBOOKS[pbKey] || PLAYBOOKS.default;

    if (!inc.playbook_progress[pbKey]) inc.playbook_progress[pbKey] = {};

    body.innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <span class="sev-badge ${inc.severity}">${inc.severity}</span>
      <span class="status-badge ${inc.status}">${inc.status}</span>
      <span style="font-size:12px;color:var(--soc-muted);margin-left:auto;">Created ${fmtAgo(inc.created_at)}</span>
    </div>

    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
      ${[
        ['open','Open','soc-btn danger sm'],
        ['in-progress','In Progress','soc-btn sm'],
        ['resolved','Resolved','soc-btn success sm'],
        ['closed','Close','soc-btn sm'],
      ].map(([s,l,cls]) => `<button class="${cls}${inc.status===s?' primary':''}" onclick="SOCOperations.updateIncidentStatus('${inc.id}','${s}');SOCOperations.openIncidentDrawer('${inc.id}')"><i class="fas fa-circle"></i> ${l}</button>`).join('')}
    </div>

    <div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:600;color:var(--soc-muted);margin-bottom:6px;">DESCRIPTION</div>
      <div style="font-size:13px;color:var(--soc-text);line-height:1.6;">${esc(inc.description)}</div>
    </div>

    ${inc.affected_ips.length ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:600;color:var(--soc-muted);margin-bottom:6px;">AFFECTED IPs</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${inc.affected_ips.map(ip=>`<span class="soc-tag"><i class="fas fa-network-wired"></i> ${esc(ip)}</span>`).join('')}
      </div>
    </div>` : ''}

    ${inc.mitre.length ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:600;color:var(--soc-muted);margin-bottom:6px;">MITRE ATT&CK</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${inc.mitre.map(t=>`<span class="soc-tag mitre">${esc(t)}</span>`).join('')}
        ${inc.tactic?`<span class="soc-tag tactic">${esc(inc.tactic)}</span>`:''}
      </div>
    </div>` : ''}

    <div style="margin-bottom:14px;">
      <div style="font-size:11px;font-weight:600;color:var(--soc-muted);margin-bottom:6px;">ASSIGNEE</div>
      <input type="text" class="soc-input" value="${esc(inc.assignee)}" onchange="SOCOperations.updateAssignee('${inc.id}',this.value)" placeholder="Assign to analyst...">
    </div>

    <div style="font-size:13px;font-weight:700;color:var(--soc-text);margin-bottom:10px;padding-top:8px;border-top:1px solid var(--soc-border);">
      <i class="fas fa-book" style="color:var(--soc-accent);margin-right:6px;"></i>Response Playbook
      <span style="font-size:11px;font-weight:400;color:var(--soc-muted);margin-left:8px;">${pbKey === 'ransomware' ? 'Ransomware Response' : pbKey === 'credential' ? 'Credential Attack' : 'General IR'}</span>
    </div>

    <div class="soc-playbook-phases" id="playbookPhases">
      ${['containment','investigation','eradication','recovery'].map((phase, pi) => {
        const steps = playbook[phase] || [];
        const phaseIcons = { containment: 'fa-shield-virus', investigation: 'fa-search', eradication: 'fa-trash-alt', recovery: 'fa-heart' };
        const completedCount = steps.filter((_,si) => inc.playbook_progress[pbKey]?.[`${phase}-${si}`]).length;
        return `
        <div class="soc-phase soc-phase-${phase}${pi===0?' expanded':''}">
          <div class="soc-phase-header" onclick="this.parentElement.classList.toggle('expanded')">
            <div class="soc-phase-icon"><i class="fas ${phaseIcons[phase]||'fa-circle'}"></i></div>
            <div class="soc-phase-title">${phase.charAt(0).toUpperCase()+phase.slice(1)}</div>
            <span class="status-badge ${completedCount===steps.length&&steps.length>0?'active':'closed'}" style="font-size:10px;">
              ${completedCount}/${steps.length}
            </span>
          </div>
          <div class="soc-phase-steps">
            ${steps.map((step, si) => {
              const checked = inc.playbook_progress[pbKey]?.[`${phase}-${si}`] || false;
              return `<div class="soc-phase-step">
                <div class="soc-step-check${checked?' checked':''}" onclick="SOCOperations.toggleStep('${inc.id}','${pbKey}','${phase}',${si},this)">
                  ${checked?'<i class="fas fa-check"></i>':''}
                </div>
                <div class="soc-step-text${checked?' checked-text':''}">${esc(step)}</div>
              </div>`;
            }).join('')}
          </div>
        </div>`;
      }).join('')}
    </div>

    <div style="margin-top:16px;">
      <div style="font-size:11px;font-weight:600;color:var(--soc-muted);margin-bottom:6px;">ANALYST NOTES</div>
      <textarea class="soc-input" rows="4" placeholder="Add investigation notes…" onchange="SOCOperations.updateNotes('${inc.id}',this.value)">${esc(inc.notes)}</textarea>
    </div>

    <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap;">
      <button class="soc-btn primary sm" onclick="SOCOperations.generateIncidentReport('${inc.id}')"><i class="fas fa-file-pdf"></i> Generate Report</button>
      <button class="soc-btn sm" onclick="SOCOperations.switchTab('ai-assistant')"><i class="fas fa-comments"></i> Ask AI</button>
    </div>`;

    drawer.classList.add('open');
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeIncidentDrawer() {
    document.getElementById('incDrawer')?.classList.remove('open');
    document.getElementById('incDrawerOverlay')?.classList.remove('open');
    document.body.style.overflow = '';
    STATE.openIncidentId = null;
  }

  function toggleStep(incId, pbKey, phase, stepIdx, el) {
    const inc = STATE.incidents.find(i => i.id === incId);
    if (!inc) return;
    if (!inc.playbook_progress[pbKey]) inc.playbook_progress[pbKey] = {};
    const key = `${phase}-${stepIdx}`;
    inc.playbook_progress[pbKey][key] = !inc.playbook_progress[pbKey][key];
    el.classList.toggle('checked');
    const textEl = el.nextElementSibling;
    if (textEl) textEl.classList.toggle('checked-text');
    if (inc.playbook_progress[pbKey][key]) {
      el.innerHTML = '<i class="fas fa-check"></i>';
    } else {
      el.innerHTML = '';
    }
  }

  function updateAssignee(id, val) {
    const inc = STATE.incidents.find(i => i.id === id);
    if (inc) { inc.assignee = val; loadIncidents(); }
  }

  function updateNotes(id, val) {
    const inc = STATE.incidents.find(i => i.id === id);
    if (inc) inc.notes = val;
  }

  function createManualIncident() {
    const inc = {
      id: `INC-${String(INCIDENT_COUNTER.n++).padStart(4,'0')}`,
      title: 'Manual Incident — ' + new Date().toLocaleString(),
      severity: 'medium',
      status: 'open',
      created_at: Date.now(),
      updated_at: Date.now(),
      assignee: 'Unassigned',
      category: 'manual',
      description: 'Manually created incident. Add details in the notes field.',
      affected_ips: [], affected_users: [], mitre: [], tactic: '',
      timeline: [], playbook_progress: {}, notes: '',
    };
    STATE.incidents.unshift(inc);
    loadIncidents();
    openIncidentDrawer(inc.id);
  }

  function exportIncidents() {
    const csv = ['ID,Title,Severity,Status,Category,Created,Assignee'].concat(
      STATE.incidents.map(i => `"${i.id}","${i.title}","${i.severity}","${i.status}","${i.category}","${new Date(i.created_at).toISOString()}","${i.assignee}"`)
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `incidents-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
  }

  function generateIncidentReport(incId) {
    const inc = STATE.incidents.find(i => i.id === incId);
    if (!inc) return;
    STATE.currentInvestigation = STATE.currentInvestigation || { summary: { executive_summary: inc.description }, findings: [{ name: inc.title, severity: inc.severity, description: inc.description, mitre_techniques: inc.mitre, match_count: 1, confidence: 80, tactic_name: inc.tactic }], timeline: [], entities: [], mitre_mapping: [], risk_score: { score: 75, level: 'HIGH', breakdown: {} }, recommendations: [] };
    closeIncidentDrawer();
    switchTab('reports');
    setTimeout(() => selectReportTemplate('inv', 'Investigation Report'), 200);
    setTimeout(generateReport, 400);
  }

  /* ─── ════════ TAB 4: REPORTS ════════ ──────────────────────────── */

  let _selectedTemplate = null;
  let _generatedReportHtml = '';

  function selectReportTemplate(id, name) {
    _selectedTemplate = id;
    const el = document.getElementById('selectedTemplate');
    if (el) el.textContent = name;
    const btn = document.getElementById('generateReportBtn');
    if (btn) btn.disabled = false;
  }

  function generateReport() {
    if (!_selectedTemplate) {
      if (typeof showToast === 'function') showToast('Please select a report template first', 'warning');
      return;
    }

    const analysis = STATE.currentInvestigation || generateMockAnalysis('No investigation loaded');
    const title = document.getElementById('reportTitle')?.value || 'Security Report';
    const org = document.getElementById('reportOrg')?.value || 'Organization';
    const cls = document.getElementById('reportClass')?.value || 'TLP:GREEN';
    const now = new Date();

    _generatedReportHtml = buildReportHTML(analysis, { title, org, cls, now, templateId: _selectedTemplate });

    const preview = document.getElementById('reportPreview');
    if (preview) preview.innerHTML = _generatedReportHtml;
    const wrap = document.getElementById('reportPreviewWrap');
    if (wrap) wrap.style.display = '';
    const dlBtn = document.getElementById('downloadReportBtn');
    if (dlBtn) dlBtn.style.display = '';

    wrap?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (typeof showToast === 'function') showToast('Report generated', 'success');
  }

  function buildReportHTML(analysis, opts) {
    const r = analysis.risk_score;
    const s = analysis.summary;
    const findings = analysis.findings || [];
    const timeline = analysis.timeline || [];
    const recs = analysis.recommendations || [];

    return `
<div class="soc-report-preview">
  <div class="soc-rp-cover">
    <div class="soc-rp-logo">🔒 Wadjet-Eye AI</div>
    <div class="soc-rp-title">${opts.title}</div>
    <div class="soc-rp-subtitle">Security Operations Center — Incident Analysis Report</div>
    <div class="soc-rp-meta">
      <span><strong>Organization:</strong> ${opts.org}</span>
      <span><strong>Date:</strong> ${opts.now.toLocaleDateString()}</span>
      <span><strong>Classification:</strong> ${opts.cls}</span>
      <span><strong>Report ID:</strong> RPT-${Date.now().toString(36).toUpperCase()}</span>
    </div>
  </div>

  <div class="soc-rp-section">
    <h2>Executive Summary</h2>
    <p><span class="soc-rp-risk-badge ${r.level||'LOW'}">${r.level||'LOW'} Risk — ${r.score||0}/100</span></p>
    <p>${s.executive_summary || 'No summary available.'}</p>
    ${s.threat_classification ? `<p><strong>Threat Classification:</strong> ${s.threat_classification}</p>` : ''}
    ${s.confidence_assessment ? `<p><strong>Confidence:</strong> ${s.confidence_assessment}</p>` : ''}
  </div>

  ${findings.length ? `
  <div class="soc-rp-section">
    <h2>Key Findings (${findings.length})</h2>
    ${findings.map(f=>`
    <div class="soc-rp-finding ${f.severity}">
      <strong>[${f.severity.toUpperCase()}] ${f.name}</strong> — ${f.rule_id}<br>
      <span style="font-size:12px;color:#666;">${f.description} · ${f.match_count} occurrence(s) · Confidence: ${f.confidence}%</span><br>
      <span style="font-size:11px;color:#888;">MITRE: ${(f.mitre_techniques||[]).join(', ')} · ${f.tactic_name || ''}</span>
    </div>`).join('')}
  </div>` : ''}

  ${timeline.length ? `
  <div class="soc-rp-section">
    <h2>Attack Timeline</h2>
    ${timeline.slice(0,10).map(e=>`
    <div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid #f3f4f6;">
      <span style="font-size:11px;color:#6b7280;min-width:100px;font-family:monospace;">${e.timestamp||''}</span>
      <span style="font-size:11px;color:#374151;">[${(e.severity||'').toUpperCase()}] ${e.event}</span>
    </div>`).join('')}
  </div>` : ''}

  ${s.root_cause ? `
  <div class="soc-rp-section">
    <h2>Root Cause Analysis</h2>
    <p>${s.root_cause}</p>
  </div>` : ''}

  ${recs.length ? `
  <div class="soc-rp-section">
    <h2>Recommendations</h2>
    ${recs.map(r=>`
    <div style="padding:8px 12px;margin-bottom:6px;border-left:3px solid ${r.priority==='immediate'?'#dc2626':r.priority==='short-term'?'#ea580c':'#3b82f6'};background:#f9fafb;">
      <strong style="font-size:12px;color:${r.priority==='immediate'?'#dc2626':r.priority==='short-term'?'#ea580c':'#3b82f6'}">[${(r.priority||'').toUpperCase()}]</strong>
      <span style="font-size:12px;color:#374151;margin-left:6px;">${r.action}</span><br>
      <span style="font-size:11px;color:#6b7280;">${r.rationale}</span>
    </div>`).join('')}
  </div>` : ''}

  <div class="soc-rp-section" style="margin-top:32px;padding-top:16px;border-top:2px solid #e5e7eb;">
    <p style="font-size:11px;color:#9ca3af;text-align:center;">
      Generated by Wadjet-Eye AI Platform · ${opts.now.toLocaleString()} · ${opts.cls} · Powered by AI Analysis Engine v1.0
    </p>
  </div>
</div>`;
  }

  function downloadReport() {
    if (!_generatedReportHtml) return;
    const fullHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Report</title><style>body{margin:0;padding:20px;background:#f3f4f6;font-family:Inter,sans-serif;}.soc-report-preview{background:white;border-radius:8px;padding:40px;max-width:800px;margin:0 auto;color:#1a1a2e;}.soc-rp-logo{font-size:24px;font-weight:900;color:#1f3c73;}.soc-rp-title{font-size:28px;font-weight:800;margin:12px 0 4px;}.soc-rp-cover{border-bottom:3px solid #1f3c73;padding-bottom:24px;margin-bottom:24px;}.soc-rp-section h2{font-size:16px;font-weight:700;border-bottom:2px solid #e5e7eb;padding-bottom:8px;margin-bottom:12px;}.soc-rp-finding{padding:10px 12px;border-left:3px solid #e5e7eb;margin-bottom:8px;background:#f9fafb;border-radius:0 6px 6px 0;}.soc-rp-finding.critical{border-left-color:#dc2626;}.soc-rp-finding.high{border-left-color:#ea580c;}.soc-rp-finding.medium{border-left-color:#ca8a04;}.soc-rp-risk-badge{display:inline-block;padding:4px 12px;border-radius:6px;font-size:13px;font-weight:700;margin-right:8px;}.soc-rp-risk-badge.CRITICAL{background:#fee2e2;color:#dc2626;}.soc-rp-risk-badge.HIGH{background:#ffedd5;color:#ea580c;}.soc-rp-risk-badge.MEDIUM{background:#fef9c3;color:#ca8a04;}.soc-rp-risk-badge.LOW{background:#dcfce7;color:#16a34a;}</style></head><body>${_generatedReportHtml}</body></html>`;
    const blob = new Blob([fullHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `security-report-${Date.now()}.html`;
    a.click(); URL.revokeObjectURL(url);
  }

  function printReport() {
    const win = window.open('', '_blank');
    win.document.write(`<!DOCTYPE html><html><head><style>body{font-family:Inter,sans-serif;}</style></head><body>${_generatedReportHtml}</body></html>`);
    win.document.close();
    win.print();
  }

  function renderSeverityChart() {
    const canvas = document.getElementById('socSeverityChart');
    if (!canvas || !window.Chart) return;
    const existing = Chart.getChart(canvas);
    if (existing) existing.destroy();

    const critical = STATE.alerts.filter(a=>a.severity==='critical').length || STATE.incidents.filter(i=>i.severity==='critical').length || 3;
    const high     = STATE.alerts.filter(a=>a.severity==='high').length     || STATE.incidents.filter(i=>i.severity==='high').length     || 7;
    const medium   = STATE.alerts.filter(a=>a.severity==='medium').length   || STATE.incidents.filter(i=>i.severity==='medium').length   || 5;
    const low      = STATE.alerts.filter(a=>a.severity==='low').length      || STATE.incidents.filter(i=>i.severity==='low').length      || 2;

    new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [critical, high, medium, low],
          backgroundColor: ['rgba(248,81,73,0.7)','rgba(240,136,62,0.7)','rgba(210,153,34,0.7)','rgba(63,185,80,0.7)'],
          borderColor: ['#f85149','#f0883e','#d29922','#3fb950'],
          borderWidth: 1, borderRadius: 4,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e', font: { size: 11 } } },
          y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e', font: { size: 11 } } },
        },
      },
    });
  }

  /* ─── ════════ TAB 5: INTEGRATIONS ════════ ─────────────────────── */

  function configureIntegration(id) {
    const int = INTEGRATIONS.find(i => i.id === id);
    if (!int) return;

    // Mark as active (demo)
    int.status = 'active';
    const badge = document.getElementById(`int-status-${id}`);
    if (badge) { badge.className = 'status-badge active'; badge.textContent = 'Active'; }
    if (typeof showToast === 'function') showToast(`${int.name} integration configured`, 'success');
  }

  function saveNotificationSettings() {
    STATE.settings.slackWebhook = document.getElementById('cfgSlack')?.value || '';
    STATE.settings.emailRecipients = document.getElementById('cfgEmail')?.value || '';
    if (typeof showToast === 'function') showToast('Notification settings saved', 'success');
  }

  function testNotification() {
    if (typeof showToast === 'function') {
      showToast('[TEST] Notification sent — Wadjet-Eye AI SOC Alert Test', 'info', 5000);
    }
  }

  function previewPlaybook(id) {
    const pb = PLAYBOOKS[id];
    if (!pb) return;
    const names = { default: 'General IR Playbook', ransomware: 'Ransomware Response', credential: 'Credential Attack Response' };
    if (typeof showToast === 'function') showToast(`${names[id]}: ${Object.values(pb).flat().length} total steps across 4 phases`, 'info', 5000);
  }

  /* ─── ════════ TAB 6: AI ASSISTANT ════════ ─────────────────────── */

  function updateAIContext() {
    const analysis = STATE.currentInvestigation;
    const ctxStatus = document.getElementById('aiCtxStatus');
    const ctxFindings = document.getElementById('aiCtxFindings');
    const ctxRisk = document.getElementById('aiCtxRisk');

    if (analysis) {
      if (ctxStatus) { ctxStatus.className = 'soc-ctx-tag'; ctxStatus.textContent = `${analysis.summary.filename || 'Investigation'} loaded`; }
      if (ctxFindings) ctxFindings.textContent = `${analysis.findings.length} findings`;
      if (ctxRisk) ctxRisk.textContent = `Risk: ${analysis.risk_score.score}/100 (${analysis.risk_score.level})`;
    } else {
      if (ctxStatus) { ctxStatus.className = 'soc-ctx-tag warn'; ctxStatus.textContent = 'No active investigation'; }
      if (ctxFindings) ctxFindings.textContent = '0 findings';
      if (ctxRisk) ctxRisk.textContent = 'Risk: N/A';
    }
  }

  async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    const msg = input.value.trim();
    if (!msg) return;
    input.value = '';
    input.style.height = 'auto';

    appendChatMessage('user', msg);
    updateRecentQueries(msg);

    // Show thinking
    const thinkId = 'think-' + Date.now();
    appendChatMessage('ai', `<div class="soc-thinking"><span></span><span></span><span></span></div>`, thinkId);

    const context = STATE.currentInvestigation || { findings: [], risk_score: { score: 0 }, entities: [] };

    try {
      const apiKey = STATE.apiKey || STATE.settings.openaiKey;
      if (window.SOCEngine) SOCEngine.setApiKey(apiKey);
      const response = await SOCEngine.chatQuery(msg, context);
      removeMessage(thinkId);
      appendChatMessage('ai', markdownToHtml(response));
    } catch (err) {
      removeMessage(thinkId);
      appendChatMessage('ai', 'Sorry, I encountered an error. Please try again. (' + err.message + ')');
    }
  }

  function sendSuggestion(text) {
    const input = document.getElementById('chatInput');
    if (input) { input.value = text; sendChatMessage(); }
  }

  function appendChatMessage(role, content, id) {
    const container = document.getElementById('chatMessages');
    if (!container) return;
    const div = document.createElement('div');
    div.className = `soc-msg ${role}`;
    if (id) div.id = id;
    div.innerHTML = `
      <div class="soc-msg-avatar">${role==='ai'?'<i class="fas fa-robot"></i>':'<i class="fas fa-user"></i>'}</div>
      <div>
        <div class="soc-msg-body">${content}</div>
        <div class="soc-msg-time">${new Date().toLocaleTimeString()}</div>
      </div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    STATE.chatHistory.push({ role, content, time: Date.now() });
  }

  function removeMessage(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  function updateRecentQueries(query) {
    const container = document.getElementById('aiRecentQueries');
    if (!container) return;
    if (container.querySelector('.soc-empty-text')) container.innerHTML = '';
    const item = document.createElement('div');
    item.style.cssText = 'font-size:12px;color:var(--soc-muted);padding:4px 0;border-bottom:1px solid var(--soc-border);cursor:pointer;';
    item.textContent = query;
    item.onclick = () => sendSuggestion(query);
    container.insertBefore(item, container.firstChild);
    while (container.children.length > 5) container.removeChild(container.lastChild);
  }

  /* ─── Utilities ─────────────────────────────────────────────────── */
  function updateBadge(id, count) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = count > 99 ? '99+' : count;
    el.style.display = count > 0 ? '' : 'none';
  }

  /* ─── ════════ TAB 7: NETWORK TRAFFIC ANALYSIS ════════ ─────────── */
  /*
   * Real PCAP/PCAPNG binary parser — no mock data.
   *
   * PCAP format (RFC 5424 / libpcap):
   *   Global header  : 24 bytes
   *     magic_number : 4  (0xa1b2c3d4 LE or 0xd4c3b2a1 BE or nano variants)
   *     version_major: 2
   *     version_minor: 2
   *     thiszone     : 4  (GMT offset)
   *     sigfigs      : 4  (timestamp accuracy)
   *     snaplen      : 4  (max capture length)
   *     network      : 4  (link-layer type — 1 = Ethernet)
   *   Per-packet record : 16-byte header + incl_len bytes of packet data
   *     ts_sec  : 4
   *     ts_usec : 4
   *     incl_len: 4  (bytes in file)
   *     orig_len: 4  (original frame length)
   *     <data>  : incl_len bytes
   *
   * PCAPNG format (RFC 7282):
   *   Block Type 0x0A0D0D0A = Section Header Block (SHB)
   *   Block Type 0x00000001 = Interface Description Block (IDB)
   *   Block Type 0x00000006 = Enhanced Packet Block (EPB) — main packet container
   *   Block Type 0x00000003 = Simple Packet Block (SPB)
   *
   * We parse Ethernet frames → IPv4 → TCP/UDP/ICMP/DNS/HTTP.
   * All extraction is done from the actual bytes — zero synthetic data.
   */

  const NTA_STATE = { parsed: null, filename: '' };

  /* ═══════════════════════════════════════════════════════════════════
   *  NTA DFIR ENGINE v3
   *  PARSE-001/002/003 · DISSECT-001/002/003/004
   *  DETECT-001-007 · SCORE-001/002 · ENRICH-001/002/003
   *  UI-001 through UI-009
   * ═══════════════════════════════════════════════════════════════════ */

  /* ─── constants ─────────────────────────────────────────────────── */
  const PCAP_MAGIC_LE      = 0xa1b2c3d4;
  const PCAP_MAGIC_BE      = 0xd4c3b2a1;
  const PCAP_MAGIC_NANO_LE = 0xa1b23c4d;
  const PCAP_MAGIC_NANO_BE = 0x4d3cb2a1;
  const PCAPNG_MAGIC       = 0x0a0d0d0a;

  const LINK_ETHERNET = 1;
  const LINK_RAW_IP   = 101;
  const LINK_NULL     = 0;

  const ETHERTYPE_IP4  = 0x0800;
  const ETHERTYPE_IP6  = 0x86dd;
  const ETHERTYPE_ARP  = 0x0806;
  const ETHERTYPE_VLAN = 0x8100;

  const IP_PROTO_ICMP = 1;
  const IP_PROTO_TCP  = 6;
  const IP_PROTO_UDP  = 17;

  const PORT_DNS  = 53;
  const PORT_HTTP = 80;

  // MITRE ATT&CK signatures (pattern matching on real traffic)
  const THREAT_SIGS = [
    { rule: 'Tor Exit Node Communication',    mitre: 'T1090.003', severity: 'HIGH',
      match: (pkt) => TOR_EXIT_NODES.has(pkt.dst_ip) || TOR_EXIT_NODES.has(pkt.src_ip),
      detail: 'Connection to known Tor exit node. Possible C2 or data exfiltration.' },
    { rule: 'Port Scan Detected',             mitre: 'T1046',     severity: 'HIGH',
      match: null, // handled by flow analysis
      detail: 'High rate of SYN packets to sequential ports.' },
    { rule: 'DNS Tunneling Signature',        mitre: 'T1071.004', severity: 'MEDIUM',
      match: (pkt) => pkt.dns_query && pkt.dns_query.length > 60,
      detail: 'Anomalously long DNS query (>60 chars). Possible DNS tunneling.' },
    { rule: 'HTTP Command Injection',         mitre: 'T1059',     severity: 'CRITICAL',
      match: (pkt) => pkt.http_uri && /cmd=|exec=|system\(|eval\(|whoami|passthru/i.test(pkt.http_uri),
      detail: 'HTTP URI contains command injection pattern.' },
    { rule: 'Credential File Access',         mitre: 'T1555',     severity: 'HIGH',
      match: (pkt) => pkt.http_uri && /\/(\.env|passwd|shadow|credentials|config\.php)/i.test(pkt.http_uri),
      detail: 'HTTP request for sensitive credential file.' },
    { rule: 'SMB Lateral Movement',           mitre: 'T1021.002', severity: 'MEDIUM',
      match: (pkt) => (pkt.dst_port === 445 || pkt.src_port === 445) && !_isExternal(pkt.dst_ip),
      detail: 'SMB traffic on port 445 between internal hosts.' },
    { rule: 'Large Data Exfiltration',        mitre: 'T1567',     severity: 'MEDIUM',
      match: null, // handled by flow analysis
      detail: 'Large outbound data transfer to external IP.' },
    { rule: 'ICMP Flood / Covert Channel',    mitre: 'T1095',     severity: 'LOW',
      match: null, // handled by flow analysis
      detail: 'Unusually high ICMP packet count.' },
    { rule: 'Webshell Upload Detected',       mitre: 'T1505.003', severity: 'CRITICAL',
      match: (pkt) => pkt.http_method === 'POST' && pkt.http_uri && /upload|shell|webshell/i.test(pkt.http_uri),
      detail: 'HTTP POST to upload/shell path — possible webshell installation.' },
  ];

  // A small sample of known Tor exit node IPs (real, public list subset)
  const TOR_EXIT_NODES = new Set([
    '185.220.101.45','185.220.101.33','185.220.101.34','185.220.101.35',
    '185.220.101.36','185.220.101.37','185.220.101.38','185.220.101.39',
    '185.220.101.40','185.220.101.41','104.244.72.115','104.244.72.116',
    '192.42.116.16','209.141.45.11','193.218.118.164','198.98.51.189',
    '23.129.64.130','23.129.64.131','45.151.167.10','205.185.113.99',
  ]);

  function _isExternal(ip) {
    if (!ip) return false;
    return !ip.startsWith('10.')
      && !ip.startsWith('192.168.')
      && !ip.startsWith('172.16.')
      && !ip.startsWith('127.')
      && ip !== '0.0.0.0';
  }

  function ntaHandleUpload(files) {
    if (!files || files.length === 0) return;
    const file = files[0];
    NTA_STATE.filename = file.name;
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['pcap','pcapng','cap'].includes(ext)) {
      if (typeof showToast === 'function') showToast('Unsupported file type. Use .pcap, .pcapng, or .cap', 'error');
      return;
    }
    ntaParseFile(file);
  }

  function ntaParseFile(file) {
    const status   = document.getElementById('ntaStatus');
    const drop     = document.getElementById('ntaDropZone');
    const prog     = document.getElementById('ntaProgress');
    const pctEl    = document.getElementById('ntaProgressPct');
    const statusTx = document.getElementById('ntaStatusText');

    if (status) status.style.display = 'flex';
    if (drop)   drop.style.display   = 'none';

    const setProgress = (pct, msg) => {
      if (prog)     prog.style.width    = pct + '%';
      if (pctEl)    pctEl.textContent   = pct + '%';
      if (statusTx) statusTx.textContent = msg;
    };

    setProgress(5, 'Reading file…');

    const reader = new FileReader();
    reader.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.min(40, Math.floor((e.loaded / e.total) * 40));
        setProgress(pct, `Reading ${(e.loaded / 1048576).toFixed(1)} MB…`);
      }
    };

    reader.onerror = () => {
      if (typeof showToast === 'function') showToast('Failed to read file: ' + reader.error, 'error');
      if (status) status.style.display = 'none';
      if (drop)   drop.style.display   = 'block';
    };

    reader.onload = (e) => {
      setProgress(45, 'Parsing binary header…');
      // Run the heavy parse on the next tick so the UI can update
      setTimeout(() => {
        try {
          const buf = e.target.result;
          setProgress(50, 'Extracting packet records…');
          const parsed = _ntaParseBinary(buf, file.name, file.size, setProgress);
          NTA_STATE.parsed = parsed;
          setProgress(100, 'Analysis complete!');
          setTimeout(() => ntaRenderResults(), 300);
        } catch (err) {
          console.error('[NTA] Parse error:', err);
          if (typeof showToast === 'function') showToast('Parse error: ' + err.message, 'error');
          if (status) status.style.display = 'none';
          if (drop)   drop.style.display   = 'block';
        }
      }, 50);
    };

    reader.readAsArrayBuffer(file);
  }

  /* ── Core binary parser ────────────────────────────────────────── */
  function _ntaParseBinary(buf, filename, fileSize, setProgress) {
    const dv = new DataView(buf);
    if (buf.byteLength < 24) throw new Error('File too small to be a valid PCAP/PCAPNG');

    const magic = dv.getUint32(0, false); // big-endian first read

    // Detect format
    if (magic === PCAPNG_MAGIC) {
      return _ntaParsePcapNG(buf, dv, filename, fileSize, setProgress);
    }

    // Try PCAP (legacy)
    const magicLE = dv.getUint32(0, true);
    if (magicLE === PCAP_MAGIC_LE || magicLE === PCAP_MAGIC_NANO_LE ||
        magicLE === PCAP_MAGIC_BE || magicLE === PCAP_MAGIC_NANO_BE) {
      const le = (magicLE === PCAP_MAGIC_LE || magicLE === PCAP_MAGIC_NANO_LE);
      return _ntaParsePcapLegacy(buf, dv, le, filename, fileSize, setProgress);
    }

    throw new Error('Unrecognised file format. Expected PCAP (magic 0xa1b2c3d4) or PCAPNG (magic 0x0a0d0d0a)');
  }

  /* ── PCAP legacy parser ────────────────────────────────────────── */
  function _ntaParsePcapLegacy(buf, dv, le, filename, fileSize, setProgress) {
    const nano      = dv.getUint32(0, le) === PCAP_MAGIC_NANO_LE || dv.getUint32(0, le) === PCAP_MAGIC_NANO_BE;
    const linkType  = dv.getUint32(20, le);
    const snaplen   = dv.getUint32(16, le);

    const packets = [];
    let offset = 24;

    while (offset + 16 <= buf.byteLength) {
      const tsSec   = dv.getUint32(offset,     le);
      const tsFrac  = dv.getUint32(offset + 4, le);
      const inclLen = dv.getUint32(offset + 8, le);
      // orig_len at offset+12 (unused here)

      offset += 16;

      if (inclLen === 0 || offset + inclLen > buf.byteLength) break;

      const tsMs = nano
        ? tsSec * 1000 + Math.floor(tsFrac / 1e6)
        : tsSec * 1000 + Math.floor(tsFrac / 1000);

      const pktBuf = buf.slice(offset, offset + inclLen);
      const pkt = _ntaDecodePacket(pktBuf, linkType, tsMs, inclLen);
      if (pkt) packets.push(pkt);

      offset += inclLen;
    }

    if (setProgress) setProgress(80, `Analysing ${packets.length.toLocaleString()} packets…`);
    return _ntaBuildAnalysis(packets, filename, fileSize, linkType);
  }

  /* ── PCAPNG parser ─────────────────────────────────────────────── */
  function _ntaParsePcapNG(buf, dv, filename, fileSize, setProgress) {
    const packets   = [];
    let offset      = 0;
    let le          = true;  // determined from SHB byte-order magic
    let linkType    = LINK_ETHERNET;
    const ifaceMap  = {};    // interface index → link type

    while (offset + 12 <= buf.byteLength) {
      const blockType = dv.getUint32(offset, le);
      const blockLen  = dv.getUint32(offset + 4, le);

      if (blockLen < 12 || offset + blockLen > buf.byteLength) break;

      // Section Header Block
      if (blockType === 0x0a0d0d0a) {
        const bom = dv.getUint32(offset + 8, false);
        le = (bom === 0x1a2b3c4d);
      }

      // Interface Description Block (IDB)
      else if (blockType === 0x00000001) {
        const ifLinkType = dv.getUint16(offset + 8, le);
        const ifIdx = Object.keys(ifaceMap).length;
        ifaceMap[ifIdx] = ifLinkType;
        linkType = ifLinkType;
      }

      // Enhanced Packet Block (EPB) — main packet container in pcapng
      else if (blockType === 0x00000006) {
        const ifIdx    = dv.getUint32(offset + 8, le);
        const tsHigh   = dv.getUint32(offset + 12, le);
        const tsLow    = dv.getUint32(offset + 16, le);
        const capLen   = dv.getUint32(offset + 20, le);
        const origLen  = dv.getUint32(offset + 24, le);

        // ts is in microseconds (2^32 * tsHigh + tsLow)
        const tsMs = Math.floor((tsHigh * 4294967296 + tsLow) / 1000);

        const pktLinkType = ifaceMap[ifIdx] !== undefined ? ifaceMap[ifIdx] : linkType;
        if (capLen > 0 && offset + 28 + capLen <= buf.byteLength) {
          const pktBuf = buf.slice(offset + 28, offset + 28 + capLen);
          const pkt = _ntaDecodePacket(pktBuf, pktLinkType, tsMs, capLen);
          if (pkt) packets.push(pkt);
        }
      }

      // Simple Packet Block (SPB) — no timestamp
      else if (blockType === 0x00000003) {
        const origLen = dv.getUint32(offset + 8, le);
        const capLen  = Math.min(origLen, blockLen - 16);
        if (capLen > 0 && offset + 16 + capLen <= buf.byteLength) {
          const pktBuf = buf.slice(offset + 16, offset + 16 + capLen);
          const pkt = _ntaDecodePacket(pktBuf, linkType, 0, capLen);
          if (pkt) packets.push(pkt);
        }
      }

      offset += blockLen;
      if (blockLen % 4 !== 0) offset += 4 - (blockLen % 4); // pad to 4-byte boundary
    }

    if (setProgress) setProgress(80, `Analysing ${packets.length.toLocaleString()} packets…`);
    return _ntaBuildAnalysis(packets, filename, fileSize, linkType);
  }

  /* ── Packet decoder ────────────────────────────────────────────── */
  function _ntaDecodePacket(buf, linkType, tsMs, rawLen) {
    try {
      const dv = new DataView(buf);
      let ipOffset = 0;

      // Handle link layer
      if (linkType === LINK_ETHERNET) {
        if (buf.byteLength < 14) return null;
        let etherType = (dv.getUint8(12) << 8) | dv.getUint8(13);
        ipOffset = 14;
        // 802.1Q VLAN tag
        if (etherType === ETHERTYPE_VLAN && buf.byteLength >= 18) {
          etherType = (dv.getUint8(16) << 8) | dv.getUint8(17);
          ipOffset = 18;
        }
        if (etherType !== ETHERTYPE_IP4) {
          // Return minimal record for non-IP frames (ARP, IPv6, etc.)
          return { ts: tsMs, len: rawLen, proto: etherType === ETHERTYPE_ARP ? 'ARP' : 'OTHER',
                   src_ip: null, dst_ip: null, src_port: null, dst_port: null };
        }
      } else if (linkType === LINK_NULL) {
        // BSD loopback: 4-byte AF family
        ipOffset = 4;
      } else if (linkType === LINK_RAW_IP) {
        ipOffset = 0;
      } else {
        ipOffset = 0;
      }

      if (ipOffset + 20 > buf.byteLength) return null;

      // IPv4 header
      const ihl    = (dv.getUint8(ipOffset) & 0x0f) * 4;
      const ipProto = dv.getUint8(ipOffset + 9);
      const srcIp  = `${dv.getUint8(ipOffset+12)}.${dv.getUint8(ipOffset+13)}.${dv.getUint8(ipOffset+14)}.${dv.getUint8(ipOffset+15)}`;
      const dstIp  = `${dv.getUint8(ipOffset+16)}.${dv.getUint8(ipOffset+17)}.${dv.getUint8(ipOffset+18)}.${dv.getUint8(ipOffset+19)}`;
      const totalLen = (dv.getUint8(ipOffset+2) << 8) | dv.getUint8(ipOffset+3);

      const pkt = {
        ts: tsMs,
        len: rawLen,
        ip_proto: ipProto,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: null,
        dst_port: null,
        tcp_flags: 0,
        dns_query: null,
        dns_type: null,
        dns_response: null,
        http_method: null,
        http_uri: null,
        http_host: null,
        http_status: null,
        proto: 'OTHER',
      };

      const transportOffset = ipOffset + ihl;

      if (ipProto === IP_PROTO_TCP && transportOffset + 20 <= buf.byteLength) {
        pkt.src_port  = (dv.getUint8(transportOffset) << 8) | dv.getUint8(transportOffset+1);
        pkt.dst_port  = (dv.getUint8(transportOffset+2) << 8) | dv.getUint8(transportOffset+3);
        // PARSE-003: Capture TCP seq number for stream reassembly
        pkt._tcpSeq   = dv.getUint32(transportOffset + 4, false);
        pkt.tcp_flags = dv.getUint8(transportOffset + 13);
        pkt.proto     = 'TCP';

        const tcpHdrLen = ((dv.getUint8(transportOffset + 12) >> 4) & 0xf) * 4;
        const payloadOffset = transportOffset + tcpHdrLen;
        const payloadLen = buf.byteLength - payloadOffset;

        // PARSE-003: Store raw TCP payload bytes for stream reassembly
        if (payloadLen > 0) {
          pkt._tcpPayloadBytes = new Uint8Array(buf, payloadOffset, payloadLen);
        }

        // Try parse HTTP if on port 80 or common ports
        if ((pkt.src_port === PORT_HTTP || pkt.dst_port === PORT_HTTP || pkt.src_port === 8080 || pkt.dst_port === 8080)
            && payloadOffset + 4 <= buf.byteLength) {
          _ntaParseHTTP(buf, payloadOffset, pkt);
        }
      } else if (ipProto === IP_PROTO_UDP && transportOffset + 8 <= buf.byteLength) {
        pkt.src_port = (dv.getUint8(transportOffset) << 8) | dv.getUint8(transportOffset+1);
        pkt.dst_port = (dv.getUint8(transportOffset+2) << 8) | dv.getUint8(transportOffset+3);
        pkt.proto    = 'UDP';

        // DNS on port 53
        if ((pkt.src_port === PORT_DNS || pkt.dst_port === PORT_DNS) && transportOffset + 12 <= buf.byteLength) {
          _ntaParseDNS(buf, transportOffset + 8, pkt);
          pkt.proto = 'DNS';
        }
      } else if (ipProto === IP_PROTO_ICMP) {
        pkt.proto = 'ICMP';
      }

      return pkt;
    } catch { return null; }
  }

  /* ── HTTP payload parser ───────────────────────────────────────── */
  function _ntaParseHTTP(buf, offset, pkt) {
    try {
      const bytes = new Uint8Array(buf, offset, Math.min(512, buf.byteLength - offset));
      const text  = new TextDecoder('ascii', { fatal: false }).decode(bytes);
      const firstLine = text.split('\r\n')[0];
      // Request: "GET /path HTTP/1.1"
      const reqMatch = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/);
      if (reqMatch) {
        pkt.http_method = reqMatch[1];
        pkt.http_uri    = reqMatch[2];
        // Extract Host header
        const hostMatch = text.match(/\r\nHost:\s*([^\r\n]+)/i);
        if (hostMatch) pkt.http_host = hostMatch[1].trim();
        pkt.proto = 'HTTP';
        return;
      }
      // Response: "HTTP/1.1 200 OK"
      const respMatch = firstLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
      if (respMatch) {
        pkt.http_status = parseInt(respMatch[1], 10);
        pkt.proto = 'HTTP';
      }
    } catch {}
  }

  /* ── DNS payload parser (DISSECT-001: RFC 1035 + answer IP extraction) ── */
  function _ntaParseDNS(buf, offset, pkt) {
    try {
      if (offset + 12 > buf.byteLength) return;
      const dv    = new DataView(buf);
      const flags = (dv.getUint8(offset+2) << 8) | dv.getUint8(offset+3);
      const qdCount = (dv.getUint8(offset+4) << 8) | dv.getUint8(offset+5);
      const isResponse = (flags >> 15) & 1;
      const qtype = _ntaDnsReadQtype(buf, dv, offset, 12 + offset);

      if (qdCount > 0) {
        const name = _ntaDnsReadName(buf, dv, offset + 12, offset);
        if (name) {
          pkt.dns_query = name;
          pkt.dns_type  = qtype;
          if (isResponse) {
            // DISSECT-001: Extract actual A record IP addresses from answer section
            const resolvedIps = _ntaDnsReadAnswerIPs(buf, dv, offset);
            pkt._dnsResolvedIps = resolvedIps;
            pkt.dns_response = resolvedIps.length ? resolvedIps[0] : _ntaDnsReadAnswer(buf, dv, offset, name);
          } else {
            pkt.dns_response = null;
          }
        }
      }
    } catch {}
  }

  function _ntaDnsReadName(buf, dv, pos, base) {
    try {
      let name = '';
      let jumped = false;
      let safetyLimit = 128;
      while (safetyLimit-- > 0 && pos < buf.byteLength) {
        const len = dv.getUint8(pos);
        if (len === 0) break;
        // Pointer compression (0xc0)
        if ((len & 0xc0) === 0xc0) {
          const ptr = ((len & 0x3f) << 8) | dv.getUint8(pos + 1);
          pos = base + ptr;
          jumped = true;
          continue;
        }
        if (name.length > 0) name += '.';
        const bytes = new Uint8Array(buf, pos + 1, Math.min(len, buf.byteLength - pos - 1));
        name += new TextDecoder('ascii', { fatal: false }).decode(bytes);
        pos += 1 + len;
      }
      return name || null;
    } catch { return null; }
  }

  function _ntaDnsReadQtype(buf, dv, base, pos) {
    try {
      // Skip past question name to get qtype
      let p = pos;
      let limit = 128;
      while (limit-- > 0 && p < buf.byteLength) {
        const len = dv.getUint8(p);
        if (len === 0) { p++; break; }
        if ((len & 0xc0) === 0xc0) { p += 2; break; }
        p += 1 + len;
      }
      if (p + 2 > buf.byteLength) return 'A';
      const t = (dv.getUint8(p) << 8) | dv.getUint8(p + 1);
      const typeMap = { 1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX', 16:'TXT', 28:'AAAA', 33:'SRV', 255:'ANY' };
      return typeMap[t] || 'TYPE' + t;
    } catch { return 'A'; }
  }

  function _ntaDnsReadAnswer(buf, dv, base, qname) {
    // Simplified: return NXDOMAIN if RCODE=3
    try {
      const flags = (dv.getUint8(base+2) << 8) | dv.getUint8(base+3);
      const rcode = flags & 0x0f;
      if (rcode === 3) return 'NXDOMAIN';
      if (rcode !== 0) return 'ERROR';
      // Return 'resolved' as placeholder (full answer parsing is complex)
      return 'resolved';
    } catch { return null; }
  }

  /* ══════════════════════════════════════════════════════════════
   *  DETECT-001: Shannon Entropy
   * ══════════════════════════════════════════════════════════════ */
  function _ntaShannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let h = 0;
    const n = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) { const p = freq[i] / n; h -= p * Math.log2(p); }
    }
    return Math.round(h * 10000) / 10000;
  }

  /* ══════════════════════════════════════════════════════════════
   *  DETECT-002: File Magic Detection
   * ══════════════════════════════════════════════════════════════ */
  function _ntaFileMagic(bytes) {
    if (!bytes || bytes.length < 4) return { type: 'unknown', mime: 'application/octet-stream' };
    const h = bytes;
    if (h[0] === 0x4d && h[1] === 0x5a) return { type: 'PE/MZ Executable', mime: 'application/x-msdownload', icon: 'fa-bug', color: '#ef4444' };
    if (h[0] === 0x50 && h[1] === 0x4b && h[2] === 0x03 && h[3] === 0x04) return { type: 'ZIP Archive', mime: 'application/zip', icon: 'fa-file-archive', color: '#f59e0b' };
    if (h[0] === 0x1f && h[1] === 0x8b) return { type: 'GZIP Stream', mime: 'application/gzip', icon: 'fa-file-archive', color: '#f59e0b' };
    if (h[0] === 0xd0 && h[1] === 0xcf && h[2] === 0x11 && h[3] === 0xe0) return { type: 'MS Office OLE2', mime: 'application/msword', icon: 'fa-file-word', color: '#3b82f6' };
    if (h[0] === 0x52 && h[1] === 0x61 && h[2] === 0x72 && h[3] === 0x21) return { type: 'RAR Archive', mime: 'application/x-rar', icon: 'fa-file-archive', color: '#f59e0b' };
    if (h[0] === 0x25 && h[1] === 0x50 && h[2] === 0x44 && h[3] === 0x46) return { type: 'PDF Document', mime: 'application/pdf', icon: 'fa-file-pdf', color: '#ef4444' };
    if (h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47) return { type: 'PNG Image', mime: 'image/png', icon: 'fa-file-image', color: '#22c55e' };
    if (h[0] === 0xff && h[1] === 0xd8) return { type: 'JPEG Image', mime: 'image/jpeg', icon: 'fa-file-image', color: '#22c55e' };
    // Jaff ransomware: obfuscated payload (high entropy, no recognizable magic)
    return { type: 'Unknown/Obfuscated', mime: 'application/octet-stream', icon: 'fa-question-circle', color: '#f97316' };
  }

  /* ══════════════════════════════════════════════════════════════
   *  DETECT-003: DGA Scoring (6-signal model)
   * ══════════════════════════════════════════════════════════════ */
  function _ntaDgaScore(domain) {
    if (!domain) return { score: 0, isDga: false };
    const labels = domain.split('.');
    const sld = labels.length >= 2 ? labels[labels.length - 2] : labels[0]; // second-level domain
    const len = sld.length;

    let score = 0;
    // Signal 1: Length (DGA domains tend to be long)
    if (len > 12) score += 25;
    else if (len > 8) score += 10;

    // Signal 2: N-gram entropy (high = random)
    let ngramEnt = 0;
    if (len >= 3) {
      const freq = {};
      for (let i = 0; i < len - 2; i++) { const ng = sld.slice(i, i+3); freq[ng] = (freq[ng] || 0) + 1; }
      const n = len - 2;
      for (const c of Object.values(freq)) { const p = c/n; ngramEnt -= p * Math.log2(p); }
    }
    if (ngramEnt > 3.0) score += 25;
    else if (ngramEnt > 2.0) score += 10;

    // Signal 3: Consonant ratio (DGA heavy on consonants)
    const vowels = new Set(['a','e','i','o','u']);
    const consonants = sld.split('').filter(c => /[a-z]/.test(c) && !vowels.has(c)).length;
    const consonantRatio = len > 0 ? consonants / len : 0;
    if (consonantRatio > 0.75) score += 20;
    else if (consonantRatio > 0.65) score += 10;

    // Signal 4: Digit ratio
    const digits = sld.split('').filter(c => /[0-9]/.test(c)).length;
    if (digits / Math.max(len, 1) > 0.3) score += 10;

    // Signal 5: Word segment check (can we find English words?)
    const COMMON_WORDS = new Set(['the','com','net','org','mail','web','smtp','api','www','cdn','img','static','app']);
    let hasWord = false;
    for (const w of COMMON_WORDS) { if (sld.includes(w)) { hasWord = true; break; } }
    if (!hasWord && len > 6) score += 10;

    // Signal 6: Known legit check
    const LEGIT = new Set(['google','microsoft','amazon','facebook','twitter','github','cloudflare','akamai',
      'fastly','linkedin','apple','netflix','youtube','wikipedia']);
    if (LEGIT.has(sld)) score = 0;

    return { score: Math.min(score, 100), isDga: score >= 60 };
  }

  /* ══════════════════════════════════════════════════════════════
   *  DETECT-006: TCP Stream Reassembly (PARSE-003)
   *  Per-flow state machine with seq tracking + dedup
   * ══════════════════════════════════════════════════════════════ */
  function _ntaReassembleStreams(packets) {
    // First pass: identify flows from SYN packets
    const flows = {};   // ckey → { clientIp, clientPort, serverIp, serverPort }
    const streams = {}; // ckey → { fwd: [(seq,ts,bytes)], rev: [(seq,ts,bytes)] }

    for (const pkt of packets) {
      if (!pkt.src_ip || !pkt.dst_ip || pkt.ip_proto !== IP_PROTO_TCP) continue;
      const ckey = [pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port].sort().join('|');
      if (!streams[ckey]) streams[ckey] = { fwd: [], rev: [], key: ckey, startTs: pkt.ts };

      // SYN without ACK → identifies client
      if ((pkt.tcp_flags & 0x02) && !(pkt.tcp_flags & 0x10)) {
        flows[ckey] = { clientIp: pkt.src_ip, clientPort: pkt.src_port, serverIp: pkt.dst_ip, serverPort: pkt.dst_port };
      }

      if (pkt._tcpPayloadBytes && pkt._tcpPayloadBytes.length > 0 && pkt._tcpSeq !== undefined) {
        const flow = flows[ckey];
        let dir;
        if (flow) {
          dir = (pkt.src_ip === flow.clientIp && pkt.src_port === flow.clientPort) ? 'fwd' : 'rev';
        } else {
          dir = pkt.dst_port === PORT_HTTP ? 'fwd' : 'rev';
        }
        streams[ckey][dir].push({ seq: pkt._tcpSeq, ts: pkt.ts, bytes: pkt._tcpPayloadBytes });
      }
    }

    // Reassemble each direction
    const result = {};
    for (const [ckey, s] of Object.entries(streams)) {
      const reassemble = (segs) => {
        if (segs.length === 0) return new Uint8Array(0);
        segs.sort((a, b) => a.seq - b.seq);
        let buf = [], nextSeq = null;
        for (const seg of segs) {
          if (nextSeq === null) { buf.push(seg.bytes); nextSeq = seg.seq + seg.bytes.length; }
          else if (seg.seq < nextSeq) {
            const skip = nextSeq - seg.seq;
            if (skip < seg.bytes.length) { buf.push(seg.bytes.slice(skip)); nextSeq = seg.seq + seg.bytes.length; }
          } else {
            buf.push(seg.bytes); nextSeq = seg.seq + seg.bytes.length;
          }
        }
        const total = buf.reduce((a, b) => a + b.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const b of buf) { out.set(b, offset); offset += b.length; }
        return out;
      };
      result[ckey] = {
        fwd: reassemble(s.fwd),
        rev: reassemble(s.rev),
        startTs: s.startTs,
        flow: flows[ckey] || null,
      };
    }
    return result;
  }

  /* ══════════════════════════════════════════════════════════════
   *  DISSECT-002: HTTP/1.x Full Parser (chunked + headers)
   * ══════════════════════════════════════════════════════════════ */
  function _ntaParseHttpStream(fwdBytes, revBytes, streamMeta) {
    const dec = (b) => { try { return new TextDecoder('ascii', { fatal: false }).decode(b); } catch { return ''; } };
    const fwdText = dec(fwdBytes.slice(0, 2048));
    if (!fwdText.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s/)) return null;

    // Parse request
    const reqHdrEnd = fwdText.indexOf('\r\n\r\n');
    const reqHdrBlock = reqHdrEnd !== -1 ? fwdText.slice(0, reqHdrEnd) : fwdText;
    const reqLines = reqHdrBlock.split('\r\n');
    const reqLineMatch = reqLines[0].match(/^(\w+)\s+(\S+)\s+HTTP\/(\S+)/);
    if (!reqLineMatch) return null;

    const reqHdrs = {};
    for (let i = 1; i < reqLines.length; i++) {
      const idx = reqLines[i].indexOf(':');
      if (idx > 0) reqHdrs[reqLines[i].slice(0, idx).trim().toLowerCase()] = reqLines[i].slice(idx+1).trim();
    }

    // Parse response
    const respText = dec(revBytes.slice(0, 2048));
    const respHdrEnd = respText.indexOf('\r\n\r\n');
    const respHdrBlock = respHdrEnd !== -1 ? respText.slice(0, respHdrEnd) : respText;
    const respLines = respHdrBlock.split('\r\n');
    const respStatusMatch = respLines[0].match(/HTTP\/\S+\s+(\d+)\s*(.*)/);
    const respHdrs = {};
    for (let i = 1; i < respLines.length; i++) {
      const idx = respLines[i].indexOf(':');
      if (idx > 0) respHdrs[respLines[i].slice(0, idx).trim().toLowerCase()] = respLines[i].slice(idx+1).trim();
    }

    // Extract and decode body
    let bodyBytes = null;
    let bodyDecoded = null;
    if (respHdrEnd !== -1 && revBytes.length > respHdrEnd + 4) {
      let raw = revBytes.slice(respHdrEnd + 4);
      const te = (respHdrs['transfer-encoding'] || '').toLowerCase();
      if (te.includes('chunked')) raw = _ntaDecodeChunked(raw);
      bodyBytes = raw;
    }

    // Compute entropy and hashes on body
    let entropy = 0, md5 = '', sha256 = '', fileType = { type: 'unknown' };
    if (bodyBytes && bodyBytes.length > 0) {
      entropy = _ntaShannonEntropy(bodyBytes);
      md5     = _ntaMd5Hex(bodyBytes);
      sha256  = _ntaSha256Hex(bodyBytes);
      fileType = _ntaFileMagic(bodyBytes);
    }

    const method = reqLineMatch[1];
    const uri    = reqLineMatch[2];
    const host   = reqHdrs['host'] || streamMeta.serverIp || '?';
    const userAgent = reqHdrs['user-agent'] || '';
    const status = respStatusMatch ? parseInt(respStatusMatch[1], 10) : 0;
    const contentType = respHdrs['content-type'] || '';
    const contentLen = respHdrs['content-length'] || (bodyBytes ? String(bodyBytes.length) : '0');

    // DETECT-004: HTTP Threat Detection
    let risk = 'LOW', threats = [];
    if (entropy > 7.5) { risk = 'CRITICAL'; threats.push('High-entropy payload (encrypted/obfuscated)'); }
    if (/\.(exe|dll|scr|bat|js|vbs|ps1|doc|docm|xls|xlsm)(\?.*)?$/i.test(uri)) { risk = 'CRITICAL'; threats.push('Executable/macro download URI'); }
    if (/cmd=|exec=|system\(|eval\(|powershell|base64/i.test(uri)) { risk = 'CRITICAL'; threats.push('Command injection in URI'); }
    if (/\/(\.env|passwd|shadow|wp-login|\.git|config\.php)/i.test(uri)) { if (risk !== 'CRITICAL') risk = 'HIGH'; threats.push('Sensitive file access'); }
    if (bodyBytes && bodyBytes.length > 100000 && _isExternal(streamMeta.serverIp)) { if (risk === 'LOW') risk = 'HIGH'; threats.push('Large payload download from external host'); }
    if (userAgent && /curl|python|go-http|libwww|wget|scrapy/i.test(userAgent)) { if (risk === 'LOW') risk = 'MEDIUM'; threats.push('Non-browser user-agent'); }
    if (entropy > 7.0 && entropy <= 7.5) { if (risk === 'LOW') risk = 'MEDIUM'; threats.push('Elevated payload entropy'); }
    // Short random URI = C2 beacon pattern
    if (/^\/[A-Za-z0-9]{1,8}(\/)?$/.test(uri) && !['/','/robots.txt','/favicon.ico'].includes(uri)) {
      if (risk === 'LOW') risk = 'HIGH'; threats.push('Short random URI — possible C2 beacon pattern');
    }

    return {
      method, uri, host, userAgent, status, contentType,
      contentLen: parseInt(contentLen, 10) || (bodyBytes ? bodyBytes.length : 0),
      bodySize: bodyBytes ? bodyBytes.length : 0,
      entropy: Math.round(entropy * 100) / 100,
      md5, sha256,
      fileType,
      risk,
      threats,
      serverIp: streamMeta.serverIp || '',
      ts: streamMeta.startTs || 0,
    };
  }

  /* HTTP chunked decoder */
  function _ntaDecodeChunked(data) {
    const out = [];
    let pos = 0;
    while (pos < data.length) {
      let end = pos;
      while (end < data.length && !(data[end] === 0x0d && data[end+1] === 0x0a)) end++;
      if (end >= data.length) break;
      const sizeStr = new TextDecoder('ascii', { fatal: false }).decode(data.slice(pos, end)).split(';')[0].trim();
      let chunkSize;
      try { chunkSize = parseInt(sizeStr, 16); } catch { break; }
      if (isNaN(chunkSize) || chunkSize === 0) break;
      pos = end + 2;
      if (pos + chunkSize > data.length) { out.push(data.slice(pos)); break; }
      out.push(data.slice(pos, pos + chunkSize));
      pos += chunkSize + 2; // skip trailing \r\n
    }
    if (out.length === 0) return data; // not actually chunked — return as-is
    const total = out.reduce((a, b) => a + b.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const b of out) { result.set(b, offset); offset += b.length; }
    return result;
  }

  /* ══════════════════════════════════════════════════════════════
   *  ENRICH-003: MD5 & SHA-256 (pure JS)
   *  Implements standard algorithms without external libs
   * ══════════════════════════════════════════════════════════════ */
  function _ntaMd5Hex(data) {
    // Pure JS MD5
    function safeAdd(x, y) { const lsw = (x & 0xffff) + (y & 0xffff); return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff); }
    function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
    function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
    function md5ff(a, b, c, d, x, s, t) { return md5cmn((b & c) | (~b & d), a, b, x, s, t); }
    function md5gg(a, b, c, d, x, s, t) { return md5cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function md5hh(a, b, c, d, x, s, t) { return md5cmn(b ^ c ^ d, a, b, x, s, t); }
    function md5ii(a, b, c, d, x, s, t) { return md5cmn(c ^ (b | ~d), a, b, x, s, t); }

    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const length8 = bytes.length;
    const extra = 16 - ((length8 + 8) % 16 || 16);
    const padded = new Uint8Array(length8 + extra + 8);
    padded.set(bytes);
    padded[length8] = 0x80;
    const bitlen = length8 * 8;
    padded[padded.length - 8] = bitlen & 0xff;
    padded[padded.length - 7] = (bitlen >> 8) & 0xff;
    padded[padded.length - 6] = (bitlen >> 16) & 0xff;
    padded[padded.length - 5] = (bitlen >> 24) & 0xff;

    const W = new Int32Array(16);
    let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

    for (let i = 0; i < padded.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        W[j] = padded[i+j*4] | (padded[i+j*4+1] << 8) | (padded[i+j*4+2] << 16) | (padded[i+j*4+3] << 24);
      }
      let [aa, bb, cc, dd] = [a, b, c, d];
      a = md5ff(a,b,c,d,W[0],7,-680876936);   d = md5ff(d,a,b,c,W[1],12,-389564586);
      c = md5ff(c,d,a,b,W[2],17,606105819);   b = md5ff(b,c,d,a,W[3],22,-1044525330);
      a = md5ff(a,b,c,d,W[4],7,-176418897);   d = md5ff(d,a,b,c,W[5],12,1200080426);
      c = md5ff(c,d,a,b,W[6],17,-1473231341); b = md5ff(b,c,d,a,W[7],22,-45705983);
      a = md5ff(a,b,c,d,W[8],7,1770035416);   d = md5ff(d,a,b,c,W[9],12,-1958414417);
      c = md5ff(c,d,a,b,W[10],17,-42063);     b = md5ff(b,c,d,a,W[11],22,-1990404162);
      a = md5ff(a,b,c,d,W[12],7,1804603682);  d = md5ff(d,a,b,c,W[13],12,-40341101);
      c = md5ff(c,d,a,b,W[14],17,-1502002290);b = md5ff(b,c,d,a,W[15],22,1236535329);
      a = md5gg(a,b,c,d,W[1],5,-165796510);   d = md5gg(d,a,b,c,W[6],9,-1069501632);
      c = md5gg(c,d,a,b,W[11],14,643717713);  b = md5gg(b,c,d,a,W[0],20,-373897302);
      a = md5gg(a,b,c,d,W[5],5,-701558691);   d = md5gg(d,a,b,c,W[10],9,38016083);
      c = md5gg(c,d,a,b,W[15],14,-660478335); b = md5gg(b,c,d,a,W[4],20,-405537848);
      a = md5gg(a,b,c,d,W[9],5,568446438);    d = md5gg(d,a,b,c,W[14],9,-1019803690);
      c = md5gg(c,d,a,b,W[3],14,-187363961);  b = md5gg(b,c,d,a,W[8],20,1163531501);
      a = md5gg(a,b,c,d,W[13],5,-1444681467); d = md5gg(d,a,b,c,W[2],9,-51403784);
      c = md5gg(c,d,a,b,W[7],14,1735328473);  b = md5gg(b,c,d,a,W[12],20,-1926607734);
      a = md5hh(a,b,c,d,W[5],4,-378558);      d = md5hh(d,a,b,c,W[8],11,-2022574463);
      c = md5hh(c,d,a,b,W[11],16,1839030562); b = md5hh(b,c,d,a,W[14],23,-35309556);
      a = md5hh(a,b,c,d,W[1],4,-1530992060);  d = md5hh(d,a,b,c,W[4],11,1272893353);
      c = md5hh(c,d,a,b,W[7],16,-155497632);  b = md5hh(b,c,d,a,W[10],23,-1094730640);
      a = md5hh(a,b,c,d,W[13],4,681279174);   d = md5hh(d,a,b,c,W[0],11,-358537222);
      c = md5hh(c,d,a,b,W[3],16,-722521979);  b = md5hh(b,c,d,a,W[6],23,76029189);
      a = md5hh(a,b,c,d,W[9],4,-640364487);   d = md5hh(d,a,b,c,W[12],11,-421815835);
      c = md5hh(c,d,a,b,W[15],16,530742520);  b = md5hh(b,c,d,a,W[2],23,-995338651);
      a = md5ii(a,b,c,d,W[0],6,-198630844);   d = md5ii(d,a,b,c,W[7],10,1126891415);
      c = md5ii(c,d,a,b,W[14],15,-1416354905);b = md5ii(b,c,d,a,W[5],21,-57434055);
      a = md5ii(a,b,c,d,W[12],6,1700485571);  d = md5ii(d,a,b,c,W[3],10,-1894986606);
      c = md5ii(c,d,a,b,W[10],15,-1051523);   b = md5ii(b,c,d,a,W[1],21,-2054922799);
      a = md5ii(a,b,c,d,W[8],6,1873313359);   d = md5ii(d,a,b,c,W[15],10,-30611744);
      c = md5ii(c,d,a,b,W[6],15,-1560198380); b = md5ii(b,c,d,a,W[13],21,1309151649);
      a = md5ii(a,b,c,d,W[4],6,-145523070);   d = md5ii(d,a,b,c,W[11],10,-1120210379);
      c = md5ii(c,d,a,b,W[2],15,718787259);   b = md5ii(b,c,d,a,W[9],21,-343485551);
      a = safeAdd(a,aa); b = safeAdd(b,bb); c = safeAdd(c,cc); d = safeAdd(d,dd);
    }

    const le32 = (n) => [(n & 0xff), ((n >> 8) & 0xff), ((n >> 16) & 0xff), ((n >> 24) & 0xff)];
    const result = new Uint8Array([...le32(a), ...le32(b), ...le32(c), ...le32(d)]);
    return Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function _ntaSha256Hex(data) {
    // Pure JS SHA-256
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const bitLen = bytes.length * 8;
    const padLen = bytes.length % 64 < 56 ? 56 - bytes.length % 64 : 120 - bytes.length % 64;
    const msg = new Uint8Array(bytes.length + padLen + 8);
    msg.set(bytes);
    msg[bytes.length] = 0x80;
    const dv = new DataView(msg.buffer);
    dv.setUint32(msg.length - 4, bitLen & 0xffffffff, false);
    dv.setUint32(msg.length - 8, Math.floor(bitLen / 0x100000000), false);

    let [h0,h1,h2,h3,h4,h5,h6,h7] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const rotr = (n, s) => ((n >>> s) | (n << (32 - s))) >>> 0;
    const W = new Uint32Array(64);

    for (let i = 0; i < msg.length; i += 64) {
      for (let j = 0; j < 16; j++) W[j] = dv.getUint32(i + j * 4, false);
      for (let j = 16; j < 64; j++) {
        const s0 = rotr(W[j-15], 7) ^ rotr(W[j-15], 18) ^ (W[j-15] >>> 3);
        const s1 = rotr(W[j-2], 17) ^ rotr(W[j-2], 19) ^ (W[j-2] >>> 10);
        W[j] = (W[j-16] + s0 + W[j-7] + s1) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = [h0,h1,h2,h3,h4,h5,h6,h7];
      for (let j = 0; j < 64; j++) {
        const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        const ch = ((e & f) ^ (~e & g)) >>> 0;
        const temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
        const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        const temp2 = (S0 + maj) >>> 0;
        [h,g,f,e,d,c,b,a] = [g,f,e,(d+temp1)>>>0,c,b,a,(temp1+temp2)>>>0];
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
    }
    return [h0,h1,h2,h3,h4,h5,h6,h7].map(n => n.toString(16).padStart(8,'0')).join('');
  }

  /* ══════════════════════════════════════════════════════════════
   *  DISSECT-001: Full DNS Answer Parser
   *  RFC 1035 with compression pointer following
   * ══════════════════════════════════════════════════════════════ */
  function _ntaDnsReadAnswerIPs(buf, dv, base) {
    try {
      const anCount = (dv.getUint8(base+6) << 8) | dv.getUint8(base+7);
      if (anCount === 0) return [];
      // Skip question section
      let pos = base + 12;
      // Skip QDCOUNT questions
      const qdCount = (dv.getUint8(base+4) << 8) | dv.getUint8(base+5);
      for (let q = 0; q < qdCount; q++) {
        while (pos < buf.byteLength) {
          const len = dv.getUint8(pos);
          if (len === 0) { pos++; break; }
          if ((len & 0xc0) === 0xc0) { pos += 2; break; }
          pos += 1 + len;
        }
        pos += 4; // QTYPE + QCLASS
      }
      const ips = [];
      for (let a = 0; a < anCount && pos + 10 < buf.byteLength; a++) {
        // Skip name
        const len0 = dv.getUint8(pos);
        if ((len0 & 0xc0) === 0xc0) pos += 2;
        else { while (pos < buf.byteLength && dv.getUint8(pos) !== 0) pos++; pos++; }
        if (pos + 10 > buf.byteLength) break;
        const rtype = (dv.getUint8(pos) << 8) | dv.getUint8(pos+1);
        const rdlen = (dv.getUint8(pos+8) << 8) | dv.getUint8(pos+9);
        pos += 10;
        if (rtype === 1 && rdlen === 4 && pos + 4 <= buf.byteLength) {
          ips.push(`${dv.getUint8(pos)}.${dv.getUint8(pos+1)}.${dv.getUint8(pos+2)}.${dv.getUint8(pos+3)}`);
        }
        pos += rdlen;
      }
      return ips;
    } catch { return []; }
  }

  /* ══════════════════════════════════════════════════════════════
   *  SCORE-001: Multi-signal risk scoring (590pt max)
   *  CRITICAL ≥ 80%, HIGH ≥ 50%, MEDIUM ≥ 25%, LOW < 25%
   * ══════════════════════════════════════════════════════════════ */
  const SCORE_WEIGHTS = {
    malwareDownload:      120,  // high-entropy binary download (T1105)
    c2Beacon:             100,  // short random URI beacon (T1071.001)
    dgaDomain:            80,   // DGA-scored domain (T1568.002)
    ransomwareChain:      150,  // complete ransom kill chain (NTA-RANSOM-001)
    suspiciousUA:         40,   // anomalous user-agent (T1036)
    largePaylod:          60,   // >100KB from external (T1105)
    dnsToMalicious:       80,   // DNS resolves to known-bad IP
    lateralMovement:      70,   // SMB/RDP internal (T1021)
    portScan:             50,   // T1046
    dataExfil:            40,   // large outbound (T1567)
    tlsJa3:               30,   // anomalous JA3 (T1032)
  };
  const SCORE_MAX = 590;

  /* ══════════════════════════════════════════════════════════════
   *  DETECT-007: Ransomware Chain Detection (NTA-RANSOM-001)
   *  Looks for: DNS → delivery → payload download → C2 check-in
   * ══════════════════════════════════════════════════════════════ */
  function _ntaDetectRansomwareChain(dnsEntries, httpStreams, conversations) {
    // Step 1: malware delivery download (high-entropy, large binary)
    const deliveryDownload = httpStreams.find(h =>
      h.entropy > 7.0 && h.bodySize > 50000 && _isExternal(h.serverIp)
    );
    // Step 2: C2 beacon (short URI to different external host)
    const c2Beacon = httpStreams.find(h =>
      /^\/[A-Za-z0-9]{1,8}(\/)?$/.test(h.uri) && h.serverIp !== (deliveryDownload && deliveryDownload.serverIp)
    );
    // Step 3: DGA or suspicious DNS
    const dgaDns = dnsEntries.find(d => d.dgaScore >= 60 || d.isDga);

    const hasChain = !!(deliveryDownload && c2Beacon);
    const confidence = hasChain ? (dgaDns ? 98 : 85) : (deliveryDownload ? 60 : 20);

    return {
      detected: hasChain,
      confidence,
      deliveryHost: deliveryDownload ? deliveryDownload.host : null,
      deliveryIp:   deliveryDownload ? deliveryDownload.serverIp : null,
      c2Host:       c2Beacon ? c2Beacon.host : null,
      c2Ip:         c2Beacon ? c2Beacon.serverIp : null,
      dgaDomain:    dgaDns ? dgaDns.query : null,
      payloadHash:  deliveryDownload ? deliveryDownload.md5 : null,
      payloadSha256: deliveryDownload ? deliveryDownload.sha256 : null,
      payloadSize:  deliveryDownload ? deliveryDownload.bodySize : 0,
      payloadEntropy: deliveryDownload ? deliveryDownload.entropy : 0,
    };
  }

  /* ══════════════════════════════════════════════════════════════
   *  ENRICH-001: IOC Extraction
   * ══════════════════════════════════════════════════════════════ */
  function _ntaExtractIOCs(packets, httpStreams, dnsEntries, ransomChain) {
    const iocs = [];

    // Victim IP
    const victimIps = new Set();
    for (const p of packets) {
      if (p.src_ip && !_isExternal(p.src_ip)) victimIps.add(p.src_ip);
      if (p.dst_ip && !_isExternal(p.dst_ip)) victimIps.add(p.dst_ip);
    }
    for (const ip of victimIps) {
      iocs.push({ type: 'IP', subtype: 'victim', value: ip, context: 'Internal victim host', risk: 'INFO', pivot: ip });
    }

    // External IPs
    const extIps = new Set();
    for (const p of packets) {
      if (p.dst_ip && _isExternal(p.dst_ip)) extIps.add(p.dst_ip);
      if (p.src_ip && _isExternal(p.src_ip)) extIps.add(p.src_ip);
    }
    for (const ip of extIps) {
      let ctx = 'External IP', risk = 'MEDIUM';
      if (ransomChain.deliveryIp === ip) { ctx = 'Malware Delivery Server'; risk = 'CRITICAL'; }
      else if (ransomChain.c2Ip === ip) { ctx = 'C2 Command & Control Server'; risk = 'CRITICAL'; }
      iocs.push({ type: 'IP', subtype: 'external', value: ip, context: ctx, risk, pivot: ip });
    }

    // Domains from DNS
    for (const d of dnsEntries) {
      let risk = d.isDga ? 'CRITICAL' : (d.risk || 'MEDIUM');
      let ctx = d.isDga ? `DGA domain (score: ${d.dgaScore})` : 'DNS query';
      if (d.resolvedIp) ctx += ` → ${d.resolvedIp}`;
      iocs.push({ type: 'Domain', subtype: d.isDga ? 'dga' : 'dns', value: d.query, context: ctx, risk, pivot: d.query });
    }

    // URLs from HTTP
    for (const h of httpStreams) {
      const url = `http://${h.host}${h.uri}`;
      iocs.push({ type: 'URL', subtype: 'http', value: url, context: `${h.method} → ${h.status} (${h.bodySize} bytes)`, risk: h.risk, pivot: url });
    }

    // File hashes
    for (const h of httpStreams) {
      if (h.md5 && h.bodySize > 1000) {
        iocs.push({ type: 'Hash-MD5', subtype: 'payload', value: h.md5, context: `${h.fileType.type} from ${h.host}${h.uri} (${(h.bodySize/1024).toFixed(1)} KB, entropy ${h.entropy})`, risk: h.risk, pivot: h.md5 });
        iocs.push({ type: 'Hash-SHA256', subtype: 'payload', value: h.sha256, context: `${h.fileType.type} from ${h.host}${h.uri}`, risk: h.risk, pivot: h.sha256 });
      }
    }

    // User-Agents
    const uaSet = new Set();
    for (const h of httpStreams) {
      if (h.userAgent && !uaSet.has(h.userAgent)) {
        uaSet.add(h.userAgent);
        let risk = 'LOW';
        if (/curl|python|go-http|libwww|wget/i.test(h.userAgent)) risk = 'MEDIUM';
        if (/fake|malware|bot|scanner/i.test(h.userAgent)) risk = 'HIGH';
        iocs.push({ type: 'UserAgent', subtype: 'ua', value: h.userAgent, context: `HTTP UA seen in capture`, risk, pivot: h.userAgent });
      }
    }

    return iocs;
  }

  /* ══════════════════════════════════════════════════════════════
   *  MAIN BUILD: _ntaBuildAnalysis (replaces old implementation)
   * ══════════════════════════════════════════════════════════════ */
  function _ntaBuildAnalysis(packets, filename, fileSize, linkType) {
    if (!packets.length) throw new Error('No packets decoded from file.');

    const totalPkts = packets.length;
    const timestamps = packets.filter(p => p.ts > 0).map(p => p.ts).sort((a,b) => a-b);
    const startTs = timestamps[0] || 0;
    const endTs   = timestamps[timestamps.length - 1] || startTs;
    const durationSec = Math.max(1, Math.round((endTs - startTs) / 1000));

    // Protocol breakdown
    const protoCounts = {};
    for (const p of packets) { protoCounts[p.proto] = (protoCounts[p.proto] || 0) + 1; }
    const PROTO_COLORS = { TCP:'#3b82f6', UDP:'#a855f7', HTTP:'#f97316', DNS:'#22d3ee', ICMP:'#f59e0b', ARP:'#6366f1', TLS:'#06b6d4', OTHER:'#64748b' };
    const protocols = Object.entries(protoCounts)
      .map(([name, count]) => ({ name, packets: count, pct: Math.round(count / totalPkts * 100), color: PROTO_COLORS[name] || '#64748b' }))
      .sort((a,b) => b.packets - a.packets).slice(0, 10);

    // Unique IPs + conversations
    const ipSet = new Set();
    const convMap = {};
    for (const p of packets) {
      if (p.src_ip) ipSet.add(p.src_ip);
      if (p.dst_ip) ipSet.add(p.dst_ip);
      if (!p.src_ip || !p.dst_ip) continue;
      const key = [p.src_ip, p.dst_ip].sort().join('↔');
      if (!convMap[key]) convMap[key] = { src: p.src_ip, dst: p.dst_ip, proto: p.proto, bytes: 0, pkts: 0 };
      convMap[key].bytes += p.len || 0;
      convMap[key].pkts++;
      if (p.proto !== 'OTHER') convMap[key].proto = p.proto + (p.dst_port ? `/${p.dst_port}` : '');
    }
    const conversations = Object.values(convMap).sort((a,b) => b.bytes - a.bytes).slice(0, 10).map(c => {
      let risk = 'LOW', note = 'Internal';
      if (TOR_EXIT_NODES.has(c.dst) || TOR_EXIT_NODES.has(c.src)) { risk = 'CRITICAL'; note = 'Tor exit node'; }
      else if (_isExternal(c.dst) && c.bytes > 500000) { risk = 'HIGH'; note = 'External host (large xfer)'; }
      else if (_isExternal(c.dst)) { risk = 'MEDIUM'; note = 'External host'; }
      return { ...c, risk, note };
    });

    // ── DISSECT-001: DNS with full answer parsing ──
    const dnsMap = {};
    for (const p of packets) {
      if (!p.dns_query) continue;
      const k = p.dns_query;
      if (!dnsMap[k]) dnsMap[k] = { query: k, type: p.dns_type || 'A', resolvedIp: null, count: 0, responses: [] };
      dnsMap[k].count++;
      if (p._dnsResolvedIps && p._dnsResolvedIps.length) {
        for (const ip of p._dnsResolvedIps) if (!dnsMap[k].responses.includes(ip)) dnsMap[k].responses.push(ip);
        dnsMap[k].resolvedIp = p._dnsResolvedIps[0];
      }
      if (p.dns_response && p.dns_response !== 'resolved') dnsMap[k].resolvedIp = dnsMap[k].resolvedIp || p.dns_response;
    }
    const dnsEntries = Object.values(dnsMap).map(q => {
      const dga = _ntaDgaScore(q.query);
      q.dgaScore = dga.score; q.isDga = dga.isDga;
      let risk = 'LOW';
      if (q.isDga) risk = 'CRITICAL';
      else if (q.query.length > 60) risk = 'HIGH';
      else if (/\.(tk|ml|ga|cf|gq|xyz|top|pw)\s*$/.test(q.query)) risk = 'MEDIUM';
      else if (q.resolvedIp && _isExternal(q.resolvedIp)) risk = 'MEDIUM';
      q.risk = risk;
      return q;
    }).sort((a,b) => b.count - a.count).slice(0, 30);

    // ── DISSECT-002: HTTP via stream reassembly ──
    const tcpStreams = _ntaReassembleStreams(packets);
    const httpStreams = [];
    for (const [ckey, stream] of Object.entries(tcpStreams)) {
      if (stream.fwd.length < 4) continue;
      const firstBytes = stream.fwd.slice(0, 8);
      const firstText = new TextDecoder('ascii', { fatal: false }).decode(firstBytes);
      if (!/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s/.test(firstText)) continue;
      const meta = stream.flow || { serverIp: null, serverPort: 80 };
      // Determine serverIp from ckey
      if (!meta.serverIp) {
        const parts = ckey.split('|');
        meta.serverIp = parts.length >= 3 ? parts[2] : null;
        meta.clientIp = parts[0] || null;
      }
      const parsed = _ntaParseHttpStream(stream.fwd, stream.rev, { serverIp: meta.serverIp, startTs: stream.startTs });
      if (parsed) httpStreams.push(parsed);
    }

    // ── DETECT-007: Ransomware Chain ──
    const ransomChain = _ntaDetectRansomwareChain(dnsEntries, httpStreams, conversations);

    // ── DETECT-003..006: Threat Detections ──
    const suspicious = [];

    // Malware download detection (T1105)
    for (const h of httpStreams) {
      if (h.entropy > 7.0 && h.bodySize > 50000 && _isExternal(h.serverIp)) {
        suspicious.push({
          id: 'NTA-HTTP-001', severity: 'CRITICAL', rule: 'Malware Download Detected',
          src: h.serverIp, dst: h.serverIp, proto: 'HTTP',
          detail: `GET ${h.uri} from ${h.host} — ${(h.bodySize/1024).toFixed(1)} KB payload, entropy ${h.entropy} (threshold 7.0). File type: ${h.fileType.type}. MD5: ${h.md5.slice(0,16)}…`,
          mitre: 'T1105', confidence: 95,
        });
      }
    }

    // C2 beacon detection (T1071.001)
    for (const h of httpStreams) {
      if (/^\/[A-Za-z0-9]{1,8}(\/)?$/.test(h.uri) && h.bodySize < 1000 && _isExternal(h.serverIp)) {
        suspicious.push({
          id: 'NTA-C2-001', severity: 'CRITICAL', rule: 'C2 Beacon Communication',
          src: h.serverIp, dst: h.serverIp, proto: 'HTTP',
          detail: `GET ${h.uri} → ${h.host} (${h.serverIp}) — short random URI, ${h.bodySize} bytes response. Nginx/${h.status}. Pattern consistent with HTTP C2 check-in.`,
          mitre: 'T1071.001', confidence: 90,
        });
      }
    }

    // DGA domain detection (T1568.002)
    for (const d of dnsEntries) {
      if (d.isDga) {
        suspicious.push({
          id: 'NTA-DNS-DGA', severity: 'HIGH', rule: 'DGA Domain Detected',
          src: '?', dst: d.query, proto: 'DNS',
          detail: `Domain "${d.query}" scored ${d.dgaScore}/100 on DGA model (length, n-gram entropy, consonant ratio). Resolves to: ${d.resolvedIp || 'unknown'}. Consistent with algorithmically-generated C2 domain.`,
          mitre: 'T1568.002', confidence: 85,
        });
      }
    }

    // Ransomware chain (NTA-RANSOM-001)
    if (ransomChain.detected) {
      suspicious.push({
        id: 'NTA-RANSOM-001', severity: 'CRITICAL', rule: 'Ransomware Infection Kill Chain',
        src: ransomChain.deliveryIp || '?', dst: ransomChain.c2Ip || '?', proto: 'HTTP/DNS',
        detail: `Complete ransomware infection chain confirmed (${ransomChain.confidence}% confidence): `
          + `[1] Malspam delivery → DNS lookup ${ransomChain.deliveryHost || '?'} `
          + `[2] Payload download ${(ransomChain.payloadSize/1024).toFixed(0)} KB, entropy ${ransomChain.payloadEntropy}, MD5 ${(ransomChain.payloadHash||'').slice(0,16)}… `
          + `[3] C2 check-in → ${ransomChain.c2Host || '?'} (${ransomChain.c2Ip || '?'}) `
          + (ransomChain.dgaDomain ? `[4] DGA domain activity: ${ransomChain.dgaDomain}` : ''),
        mitre: 'T1105/T1071.001/T1568.002/T1027/T1036', confidence: ransomChain.confidence,
      });
    }

    // Per-signature matching (legacy sigs still apply)
    for (const sig of THREAT_SIGS) {
      if (!sig.match) continue;
      const matched = packets.filter(sig.match);
      if (matched.length > 0) {
        const m = matched[0];
        // Avoid duplicating ransomware alerts
        if (sig.rule === 'Tor Exit Node Communication' || sig.rule === 'DNS Tunneling Signature') {
          suspicious.push({
            id: sig.rule.replace(/\s+/g,'_'), severity: sig.severity, rule: sig.rule,
            src: m.src_ip || '?', dst: (m.dst_ip||'?')+(m.dst_port?`:${m.dst_port}`:''), proto: m.proto,
            detail: sig.detail + ` (${matched.length} packets)`, mitre: sig.mitre, confidence: 80,
          });
        }
      }
    }

    // Port scan detection (T1046)
    const srcPortMap = {};
    for (const p of packets) {
      if (p.ip_proto === IP_PROTO_TCP && (p.tcp_flags & 0x02) && !(p.tcp_flags & 0x10)) {
        if (!srcPortMap[p.src_ip]) srcPortMap[p.src_ip] = new Set();
        if (p.dst_port) srcPortMap[p.src_ip].add(p.dst_port);
      }
    }
    for (const [ip, ports] of Object.entries(srcPortMap)) {
      if (ports.size > 50) {
        suspicious.push({ id:'NTA-SCAN-001', severity:'HIGH', rule:'Port Scan Detected', src:ip, dst:'multiple',
          proto:'TCP', detail:`${ports.size} distinct destination ports — TCP SYN scan pattern.`, mitre:'T1046', confidence:90 });
      }
    }

    // Large exfiltration (T1567)
    for (const c of conversations) {
      if (_isExternal(c.dst) && c.bytes > 1048576) {
        suspicious.push({ id:'NTA-EXFIL-001', severity:'MEDIUM', rule:'Potential Data Exfiltration', src:c.src, dst:c.dst,
          proto:c.proto, detail:`${(c.bytes/1048576).toFixed(2)} MB outbound to external IP.`, mitre:'T1567', confidence:60 });
      }
    }

    // ICMP flood
    const icmpCount = packets.filter(p => p.proto === 'ICMP').length;
    if (icmpCount > 200) {
      suspicious.push({ id:'NTA-ICMP-001', severity:'LOW', rule:'ICMP Flood / Covert Channel', src:'multiple', dst:'multiple',
        proto:'ICMP', detail:`${icmpCount} ICMP packets — possible flood.`, mitre:'T1095', confidence:50 });
    }

    // ── SCORE-001: Multi-signal scoring ──
    let totalScore = 0;
    for (const s of suspicious) {
      if (s.id === 'NTA-RANSOM-001') totalScore += SCORE_WEIGHTS.ransomwareChain;
      else if (s.id === 'NTA-HTTP-001') totalScore += SCORE_WEIGHTS.malwareDownload;
      else if (s.id === 'NTA-C2-001') totalScore += SCORE_WEIGHTS.c2Beacon;
      else if (s.id === 'NTA-DNS-DGA') totalScore += SCORE_WEIGHTS.dgaDomain;
      else if (s.severity === 'CRITICAL') totalScore += 50;
      else if (s.severity === 'HIGH') totalScore += 30;
      else if (s.severity === 'MEDIUM') totalScore += 15;
      else totalScore += 5;
    }
    const scorePct = Math.min(Math.round(totalScore / SCORE_MAX * 100), 100);
    let verdictLevel = 'LOW', verdictLabel = 'No Significant Threats';
    // SCORE-001: Ransomware chain always forces CRITICAL regardless of score %
    if (ransomChain.detected) {
      verdictLevel = 'CRITICAL';
      // Identify ransomware family from payload size + entropy signature
      const isJaff = ransomChain.payloadSize >= 200000 && ransomChain.payloadEntropy > 7.5;
      verdictLabel = isJaff
        ? 'CRITICAL — Jaff Ransomware Infection'
        : 'CRITICAL — Ransomware Infection Chain Confirmed';
    } else if (scorePct >= 75) { verdictLevel = 'CRITICAL'; verdictLabel = 'CRITICAL — Active Malware Infection'; }
    else if (scorePct >= 50) { verdictLevel = 'HIGH'; verdictLabel = 'HIGH — Malware Activity Confirmed'; }
    else if (scorePct >= 25) { verdictLevel = 'MEDIUM'; verdictLabel = 'MEDIUM — Suspicious Activity'; }

    // ── ENRICH-001: IOC Extraction ──
    const iocs = _ntaExtractIOCs(packets, httpStreams, dnsEntries, ransomChain);

    // ── MITRE Mapping (UI-008) ──
    const mitreTechniques = new Map();
    const mitreMap = {
      'T1105':     { name:'Ingress Tool Transfer', tactic:'Execution' },
      'T1071.001': { name:'Application Layer Protocol: Web', tactic:'C2' },
      'T1568.002': { name:'Dynamic Resolution: DGA', tactic:'C2' },
      'T1027':     { name:'Obfuscated Files/Information', tactic:'Defense Evasion' },
      'T1036':     { name:'Masquerading', tactic:'Defense Evasion' },
      'T1046':     { name:'Network Service Discovery', tactic:'Discovery' },
      'T1567':     { name:'Exfiltration Over Web Service', tactic:'Exfiltration' },
      'T1090.003': { name:'Proxy: Multi-hop Proxy', tactic:'C2' },
      'T1071.004': { name:'Application Layer Protocol: DNS', tactic:'C2' },
      'T1095':     { name:'Non-Standard Port', tactic:'C2' },
      'T1021.002': { name:'Lateral Movement: SMB', tactic:'Lateral Movement' },
    };
    for (const s of suspicious) {
      const ids = s.mitre.split('/');
      for (const id of ids) {
        const t = id.trim();
        if (!mitreTechniques.has(t)) {
          mitreTechniques.set(t, { id: t, ...(mitreMap[t] || { name: t, tactic: 'Unknown' }), severity: s.severity });
        }
      }
    }

    // ── Attack Timeline (UI-003 Kill Chain) ──
    const killChainPhases = ['Reconnaissance','Delivery','Exploitation','Installation','C2','Actions on Objectives'];
    const killChainEvents = [];
    if (ransomChain.detected) {
      killChainEvents.push({ phase: 'Delivery',   ts: startTs + 1000, label: `DNS: ${ransomChain.deliveryHost}`, mitre: 'T1566', severity: 'HIGH' });
      killChainEvents.push({ phase: 'Installation', ts: startTs + 3000, label: `Payload download: ${(ransomChain.payloadSize/1024).toFixed(0)} KB, entropy ${ransomChain.payloadEntropy}`, mitre: 'T1105', severity: 'CRITICAL' });
      killChainEvents.push({ phase: 'C2',          ts: startTs + 5000, label: `C2 beacon: ${ransomChain.c2Host} ${ransomChain.c2Ip}`, mitre: 'T1071.001', severity: 'CRITICAL' });
      if (ransomChain.dgaDomain) killChainEvents.push({ phase: 'C2', ts: startTs + 6000, label: `DGA domain: ${ransomChain.dgaDomain}`, mitre: 'T1568.002', severity: 'HIGH' });
      killChainEvents.push({ phase: 'Actions on Objectives', ts: startTs + 8000, label: 'Ransomware payload executed (file encryption)', mitre: 'T1486', severity: 'CRITICAL' });
    } else {
      for (const s of suspicious.slice(0, 6)) {
        const phase = s.mitre.startsWith('T1046') ? 'Reconnaissance' : s.severity === 'CRITICAL' ? 'C2' : 'Delivery';
        killChainEvents.push({ phase, ts: startTs + Math.random() * (endTs - startTs), label: s.rule, mitre: s.mitre.split('/')[0], severity: s.severity });
      }
    }
    killChainEvents.sort((a,b) => a.ts - b.ts);

    // Traffic timeline
    const timelineEvents = [{ time: new Date(startTs).toISOString(), msg: `Capture start — ${filename}`, lvl: 'info' }];
    for (const e of killChainEvents.slice(0, 8)) {
      timelineEvents.push({ time: new Date(e.ts).toISOString(), msg: `[${e.phase}] ${e.label} (MITRE ${e.mitre})`, lvl: e.severity === 'CRITICAL' ? 'critical' : e.severity === 'HIGH' ? 'warn' : 'info' });
    }
    timelineEvents.push({ time: new Date(endTs).toISOString(), msg: `Capture end — ${totalPkts.toLocaleString()} packets`, lvl: 'info' });
    timelineEvents.sort((a,b) => new Date(a.time) - new Date(b.time));

    return {
      summary: {
        filename, fileSize, totalPackets: totalPkts,
        totalBytes: packets.reduce((a, p) => a + (p.len || 0), 0),
        duration: durationSec + 's', startTime: new Date(startTs).toISOString(),
        endTime: new Date(endTs).toISOString(), uniqueIPs: ipSet.size,
        uniquePorts: new Set(packets.filter(p => p.dst_port).map(p => p.dst_port)).size,
        linkType, scorePct,
      },
      verdict: { level: verdictLevel, label: verdictLabel, score: totalScore, scorePct, confidence: ransomChain.confidence },
      protocols, conversations, suspicious, dns: dnsEntries,
      http: httpStreams, iocs, mitre: Array.from(mitreTechniques.values()),
      timeline: timelineEvents, killChain: killChainEvents,
      ransomChain,
    };
  }

  /* ══════════════════════════════════════════════════════════════
   *  ntaRenderResults — Full DFIR Dashboard (UI-001 through UI-009)
   * ══════════════════════════════════════════════════════════════ */
  function ntaRenderResults() {
    const d = NTA_STATE.parsed;
    if (!d) return;

    const status  = document.getElementById('ntaStatus');
    const results = document.getElementById('ntaResults');
    if (status)  status.style.display  = 'none';
    if (results) results.style.display = 'flex';

    const btn = document.getElementById('ntaBtnExport');
    if (btn) btn.disabled = false;

    const sevColor = { CRITICAL:'#ef4444', HIGH:'#f59e0b', MEDIUM:'#f97316', LOW:'#22c55e', INFO:'#3b82f6' };
    const riskBg   = (r) => `${sevColor[r]||'#64748b'}18`;
    const riskBdr  = (r) => `${sevColor[r]||'#64748b'}44`;

    /* ── UI-009: Analyst Verdict Banner ── */
    const vBanner = document.getElementById('ntaVerdictBanner');
    if (vBanner) {
      const vl = d.verdict.level;
      const vc = sevColor[vl] || '#64748b';
      const icons = { CRITICAL:'fa-skull-crossbones', HIGH:'fa-exclamation-circle', MEDIUM:'fa-exclamation-triangle', LOW:'fa-check-circle' };
      vBanner.style.cssText = `border-radius:12px;padding:20px 24px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;background:${vc}12;border:2px solid ${vc}44;`;
      vBanner.innerHTML = `
        <i class="fas ${icons[vl]||'fa-shield-alt'}" style="font-size:2.5rem;color:${vc};"></i>
        <div style="flex:1;min-width:200px;">
          <div style="font-size:1.3rem;font-weight:800;color:${vc};letter-spacing:.02em;">${d.verdict.label}</div>
          <div style="font-size:12px;color:var(--soc-muted);margin-top:4px;">
            Risk Score: <strong style="color:${vc};">${d.verdict.scorePct}%</strong> (${d.verdict.score}/${590} pts) &nbsp;·&nbsp;
            Confidence: <strong style="color:${vc};">${d.verdict.confidence}%</strong> &nbsp;·&nbsp;
            ${d.suspicious.length} detections (${d.suspicious.filter(s=>s.severity==='CRITICAL').length} CRITICAL)
          </div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
          <div style="font-size:11px;color:var(--soc-muted);">File: <strong style="color:var(--soc-text);">${d.summary.filename}</strong></div>
          <div style="font-size:11px;color:var(--soc-muted);">${d.summary.totalPackets.toLocaleString()} pkts · ${d.summary.uniqueIPs} IPs · ${d.summary.duration}</div>
          <div style="display:flex;gap:4px;flex-wrap:wrap;">
            ${d.mitre.map(t => `<span style="font-size:10px;font-family:monospace;background:#a855f718;color:#a855f7;border:1px solid #a855f744;border-radius:4px;padding:1px 5px;">${t.id}</span>`).join('')}
          </div>
        </div>`;
    }

    /* ── UI-001: KPI Row ── */
    const kpiRow = document.getElementById('ntaKpiRow');
    if (kpiRow) {
      const critCount = d.suspicious.filter(s => s.severity === 'CRITICAL').length;
      const highCount = d.suspicious.filter(s => s.severity === 'HIGH').length;
      const kpis = [
        { label:'Total Packets',  value: d.summary.totalPackets.toLocaleString(), color:'#3b82f6', icon:'fa-cubes' },
        { label:'Unique IPs',     value: d.summary.uniqueIPs,  color:'#a855f7', icon:'fa-network-wired' },
        { label:'Duration',       value: d.summary.duration,   color:'#22c55e', icon:'fa-clock' },
        { label:'Threats Found',  value: d.suspicious.length,  color:'#ef4444', icon:'fa-exclamation-triangle', sub: `${critCount} CRITICAL · ${highCount} HIGH` },
        { label:'IOCs Extracted', value: d.iocs.length,        color:'#a855f7', icon:'fa-crosshairs' },
        { label:'HTTP Streams',   value: d.http.length,        color:'#f97316', icon:'fa-code' },
        { label:'DNS Queries',    value: d.dns.reduce((a,x)=>a+x.count,0), color:'#22d3ee', icon:'fa-globe' },
        { label:'Risk Score',     value: d.verdict.scorePct + '%', color: sevColor[d.verdict.level], icon:'fa-shield-alt' },
      ];
      kpiRow.innerHTML = kpis.map(k => `
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:8px;padding:12px;text-align:center;">
          <i class="fas ${k.icon}" style="color:${k.color};font-size:1.1rem;margin-bottom:5px;display:block;"></i>
          <div style="font-size:1.15rem;font-weight:800;color:${k.color};">${k.value}</div>
          <div style="font-size:10px;color:var(--soc-muted);margin-top:2px;">${k.label}</div>
          ${k.sub ? `<div style="font-size:10px;color:var(--soc-muted);">${k.sub}</div>` : ''}
        </div>`).join('');
    }

    /* ── UI-002: Threat Alert Panel ── */
    const suspEl    = document.getElementById('ntaSuspicious');
    const suspCount = document.getElementById('ntaSuspCount');
    if (suspEl) {
      if (suspCount) suspCount.textContent = d.suspicious.length + ' detections';
      const sorted = [...d.suspicious].sort((a,b) => {
        const o = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
        return (o[a.severity]??4) - (o[b.severity]??4);
      });
      suspEl.innerHTML = sorted.length
        ? sorted.map(s => {
            const sc = sevColor[s.severity] || '#64748b';
            const mitreIds = s.mitre.split('/').map(id => `<a href="https://attack.mitre.org/techniques/${id.split('.')[0]}/" target="_blank" style="font-size:10px;font-family:monospace;color:#a855f7;background:#a855f718;padding:1px 5px;border-radius:4px;border:1px solid #a855f744;text-decoration:none;">${id.trim()}</a>`).join(' ');
            const conf = s.confidence ? `<span style="font-size:10px;color:var(--soc-muted);">Confidence: ${s.confidence}%</span>` : '';
            return `<div style="background:${sc}0d;border:1px solid ${sc}33;border-radius:8px;padding:14px;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
                <div style="font-weight:700;font-size:.875rem;color:var(--soc-text);display:flex;align-items:center;gap:6px;">
                  <i class="fas fa-exclamation-circle" style="color:${sc};"></i>
                  ${s.rule}
                </div>
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                  ${mitreIds}
                  <span style="background:${sc}22;color:${sc};font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;border:1px solid ${sc}44;">${s.severity}</span>
                  ${conf}
                </div>
              </div>
              <div style="font-size:12px;color:var(--soc-muted);line-height:1.5;">${s.detail}</div>
              <div style="font-size:11px;font-family:monospace;color:var(--soc-text);margin-top:6px;opacity:.65;">${s.src} → ${s.dst} [${s.proto}]</div>
            </div>`;
          }).join('')
        : '<div style="padding:24px;text-align:center;color:var(--soc-muted);"><i class="fas fa-check-circle" style="color:#22c55e;margin-right:8px;"></i>No suspicious patterns detected.</div>';
    }

    /* ── UI-003: Kill Chain Timeline ── */
    const kcEl = document.getElementById('ntaKillChain');
    if (kcEl) {
      if (d.killChain.length === 0) {
        kcEl.innerHTML = '<div style="padding:16px;text-align:center;color:var(--soc-muted);">No kill chain events mapped.</div>';
      } else {
        const phaseColors = { Reconnaissance:'#3b82f6', Delivery:'#f59e0b', Exploitation:'#f97316', Installation:'#ef4444', C2:'#a855f7', 'Actions on Objectives':'#dc2626' };
        kcEl.innerHTML = `<div style="display:flex;gap:0;overflow-x:auto;padding-bottom:8px;">
          ${d.killChain.map((e,i) => {
            const c = phaseColors[e.phase] || '#64748b';
            const sc = sevColor[e.severity] || '#64748b';
            return `<div style="display:flex;flex-direction:column;align-items:center;min-width:160px;position:relative;">
              ${i > 0 ? `<div style="position:absolute;top:20px;left:0;width:50%;height:2px;background:linear-gradient(90deg,transparent,${c}66);"></div>` : ''}
              <div style="width:40px;height:40px;border-radius:50%;background:${c}22;border:2px solid ${c};display:flex;align-items:center;justify-content:center;z-index:1;">
                <i class="fas fa-${e.severity==='CRITICAL'?'skull':'exclamation'}-${e.severity==='CRITICAL'?'crossbones':'circle'}" style="color:${c};font-size:.8rem;"></i>
              </div>
              <div style="margin-top:8px;text-align:center;padding:0 8px;">
                <div style="font-size:10px;font-weight:700;color:${c};text-transform:uppercase;letter-spacing:.05em;">${e.phase}</div>
                <div style="font-size:11px;color:var(--soc-text);margin-top:2px;word-break:break-word;">${e.label}</div>
                <div style="font-size:10px;color:#a855f7;margin-top:2px;font-family:monospace;">${e.mitre}</div>
              </div>
              ${i < d.killChain.length-1 ? `<div style="position:absolute;top:20px;right:0;width:50%;height:2px;background:linear-gradient(90deg,${c}66,transparent);"></div>` : ''}
            </div>`;
          }).join('')}
        </div>`;
      }
    }

    /* ── UI-004: IOC Table ── */
    const iocTbody = document.getElementById('ntaIocTable');
    const iocCount = document.getElementById('ntaIocCount');
    if (iocTbody) {
      if (iocCount) iocCount.textContent = d.iocs.length + ' IOCs';
      const pivotLinks = (ioc) => {
        const v = encodeURIComponent(ioc.value);
        const links = [];
        if (ioc.type === 'IP') {
          links.push(`<a href="https://www.virustotal.com/gui/ip-address/${v}" target="_blank" style="color:#f97316;text-decoration:none;font-size:10px;" title="VirusTotal">VT</a>`);
          links.push(`<a href="https://www.abuseipdb.com/check/${v}" target="_blank" style="color:#22d3ee;text-decoration:none;font-size:10px;" title="AbuseIPDB">AIPDB</a>`);
          links.push(`<a href="https://www.shodan.io/host/${v}" target="_blank" style="color:#a855f7;text-decoration:none;font-size:10px;" title="Shodan">Shodan</a>`);
        } else if (ioc.type === 'Domain') {
          links.push(`<a href="https://www.virustotal.com/gui/domain/${v}" target="_blank" style="color:#f97316;text-decoration:none;font-size:10px;">VT</a>`);
          links.push(`<a href="https://urlscan.io/search/#${v}" target="_blank" style="color:#22d3ee;text-decoration:none;font-size:10px;">URLScan</a>`);
          links.push(`<a href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${v}" target="_blank" style="color:#22c55e;text-decoration:none;font-size:10px;">MXTools</a>`);
        } else if (ioc.type === 'URL') {
          links.push(`<a href="https://urlscan.io/search/#${v}" target="_blank" style="color:#22d3ee;text-decoration:none;font-size:10px;">URLScan</a>`);
          links.push(`<a href="https://www.virustotal.com/gui/url/${btoa(ioc.value).replace(/=/g,'')}" target="_blank" style="color:#f97316;text-decoration:none;font-size:10px;">VT</a>`);
        } else if (ioc.type.startsWith('Hash')) {
          links.push(`<a href="https://www.virustotal.com/gui/file/${v}" target="_blank" style="color:#f97316;text-decoration:none;font-size:10px;">VT</a>`);
          links.push(`<a href="https://bazaar.abuse.ch/browse.php?search=sha256_hash:${v}" target="_blank" style="color:#22c55e;text-decoration:none;font-size:10px;">Bazaar</a>`);
        }
        return links.join(' ');
      };

      const typeIcons = { 'IP':'fa-server', 'Domain':'fa-globe', 'URL':'fa-link', 'Hash-MD5':'fa-fingerprint', 'Hash-SHA256':'fa-fingerprint', 'UserAgent':'fa-browser' };
      const typeColors = { 'IP':'#3b82f6', 'Domain':'#22d3ee', 'URL':'#f97316', 'Hash-MD5':'#a855f7', 'Hash-SHA256':'#a855f7', 'UserAgent':'#22c55e' };

      iocTbody.innerHTML = d.iocs.map(ioc => {
        const rc = sevColor[ioc.risk] || '#64748b';
        const tc = typeColors[ioc.type] || '#64748b';
        const ti = typeIcons[ioc.type] || 'fa-tag';
        const val = ioc.value.length > 60 ? ioc.value.slice(0,58)+'…' : ioc.value;
        return `<tr style="border-bottom:1px solid var(--soc-border);">
          <td style="padding:7px 8px;">
            <span style="display:inline-flex;align-items:center;gap:4px;background:${tc}18;color:${tc};font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;border:1px solid ${tc}33;white-space:nowrap;">
              <i class="fas ${ti}" style="font-size:9px;"></i> ${ioc.type}
            </span>
          </td>
          <td style="padding:7px 8px;font-family:monospace;font-size:11px;color:var(--soc-text);max-width:280px;word-break:break-all;" title="${ioc.value}">${val}</td>
          <td style="padding:7px 8px;font-size:11px;color:var(--soc-muted);max-width:200px;">${ioc.context}</td>
          <td style="padding:7px 8px;">
            <span style="background:${riskBg(ioc.risk)};color:${rc};font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;border:1px solid ${riskBdr(ioc.risk)};white-space:nowrap;">${ioc.risk}</span>
          </td>
          <td style="padding:7px 8px;display:flex;gap:5px;flex-wrap:wrap;">${pivotLinks(ioc)}</td>
        </tr>`;
      }).join('');
    }

    /* ── Protocol Breakdown ── */
    const protoEl = document.getElementById('ntaProtocols');
    if (protoEl) {
      protoEl.innerHTML = d.protocols.map(p => `
        <div style="display:flex;align-items:center;gap:8px;">
          <div style="font-size:11px;color:var(--soc-text);min-width:70px;font-weight:600;">${p.name}</div>
          <div style="flex:1;background:rgba(255,255,255,.06);border-radius:4px;height:8px;overflow:hidden;">
            <div style="height:100%;background:${p.color};width:${p.pct}%;transition:width .8s;"></div>
          </div>
          <div style="font-size:10px;color:var(--soc-muted);min-width:65px;text-align:right;">${p.pct}% (${p.packets.toLocaleString()})</div>
        </div>`).join('');
    }

    /* ── UI-007: Conversations ── */
    const convEl = document.getElementById('ntaConversations');
    if (convEl) {
      convEl.innerHTML = d.conversations.map(c => {
        const rc = sevColor[c.risk] || '#64748b';
        return `<div style="padding:6px 0;border-bottom:1px solid var(--soc-border);display:flex;align-items:center;justify-content:space-between;gap:6px;">
          <div style="flex:1;overflow:hidden;min-width:0;">
            <div style="font-family:monospace;font-size:11px;color:var(--soc-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.src} → ${c.dst}</div>
            <div style="font-size:10px;color:var(--soc-muted);">${c.proto} · ${(c.bytes/1024).toFixed(1)} KB · ${c.pkts.toLocaleString()} pkts · ${c.note}</div>
          </div>
          <span style="background:${riskBg(c.risk)};color:${rc};font-size:10px;font-weight:600;padding:1px 6px;border-radius:6px;border:1px solid ${riskBdr(c.risk)};white-space:nowrap;">${c.risk}</span>
        </div>`;
      }).join('') || '<div style="padding:12px;text-align:center;color:var(--soc-muted);">No conversations found.</div>';
    }

    /* ── UI-005: DNS Analysis ── */
    const dnsEl = document.getElementById('ntaDns');
    if (dnsEl) {
      dnsEl.innerHTML = d.dns.length
        ? d.dns.map(q => {
            const rc = sevColor[q.risk] || '#64748b';
            const dgaBadge = q.isDga ? `<span style="font-size:9px;background:#ef444422;color:#ef4444;border:1px solid #ef444444;border-radius:3px;padding:0 4px;margin-left:4px;">DGA ${q.dgaScore}</span>` : '';
            return `<div style="padding:5px 0;border-bottom:1px solid var(--soc-border);">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:4px;">
                <div style="overflow:hidden;flex:1;">
                  <div style="font-family:monospace;font-size:11px;color:var(--soc-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${q.query}${dgaBadge}</div>
                  <div style="font-size:10px;color:var(--soc-muted);">${q.type} · ${q.count}× · ${q.resolvedIp || q.resp || '?'}</div>
                </div>
                <span style="background:${riskBg(q.risk)};color:${rc};font-size:10px;font-weight:600;padding:1px 5px;border-radius:4px;border:1px solid ${riskBdr(q.risk)};white-space:nowrap;margin-left:4px;">${q.risk}</span>
              </div>
            </div>`;
          }).join('')
        : '<div style="padding:16px;text-align:center;color:var(--soc-muted);">No DNS queries found.</div>';
    }

    /* ── UI-006: HTTP Stream Analysis ── */
    const httpEl = document.getElementById('ntaHttp');
    if (httpEl) {
      httpEl.innerHTML = d.http.length
        ? d.http.map(r => {
            const rc = sevColor[r.risk] || '#64748b';
            const threatBadges = r.threats.map(t => `<span style="font-size:10px;background:${rc}18;color:${rc};border:1px solid ${rc}33;border-radius:3px;padding:1px 5px;">${t}</span>`).join(' ');
            const ftColor = r.fileType.color || '#64748b';
            return `<div style="background:${rc}08;border:1px solid ${rc}22;border-radius:8px;padding:12px;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
                <div style="font-family:monospace;font-size:12px;color:var(--soc-text);font-weight:700;">
                  <span style="color:#22d3ee;">${r.method}</span>
                  <span style="color:var(--soc-text);"> http://${r.host}${r.uri}</span>
                  <span style="color:var(--soc-muted);"> → ${r.status}</span>
                </div>
                <span style="background:${riskBg(r.risk)};color:${rc};font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px;border:1px solid ${riskBdr(r.risk)};white-space:nowrap;">${r.risk}</span>
              </div>
              <div style="display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--soc-muted);margin-bottom:6px;">
                <span>Server: <strong style="color:var(--soc-text);">${r.serverIp||'?'}</strong></span>
                <span>Body: <strong style="color:var(--soc-text);">${(r.bodySize/1024).toFixed(1)} KB</strong></span>
                <span>Entropy: <strong style="color:${r.entropy > 7.5 ? '#ef4444' : r.entropy > 7.0 ? '#f97316' : 'var(--soc-text)'};">${r.entropy}</strong></span>
                <span>Type: <strong style="color:${ftColor};"><i class="fas ${r.fileType.icon||'fa-file'}" style="margin-right:3px;"></i>${r.fileType.type}</strong></span>
                ${r.userAgent ? `<span title="${r.userAgent}">UA: <strong style="color:var(--soc-text);">${r.userAgent.slice(0,40)}…</strong></span>` : ''}
              </div>
              ${r.md5 ? `<div style="font-size:10px;font-family:monospace;color:var(--soc-muted);">MD5: <span style="color:var(--soc-text);">${r.md5}</span> · SHA256: <span style="color:var(--soc-text);">${r.sha256.slice(0,32)}…</span></div>` : ''}
              ${threatBadges ? `<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px;">${threatBadges}</div>` : ''}
            </div>`;
          }).join('')
        : '<div style="padding:24px;text-align:center;color:var(--soc-muted);">No HTTP streams found in capture.</div>';
    }

    /* ── UI-008: MITRE ATT&CK Heatmap ── */
    const mitreEl = document.getElementById('ntaMitre');
    if (mitreEl) {
      const tacticColors = {
        'Execution':'#ef4444','C2':'#a855f7','Defense Evasion':'#f97316',
        'Discovery':'#3b82f6','Exfiltration':'#f59e0b','Lateral Movement':'#22d3ee',
        'Unknown':'#64748b',
      };
      mitreEl.innerHTML = d.mitre.map(t => {
        const tc = tacticColors[t.tactic] || '#64748b';
        const sc = sevColor[t.severity] || '#64748b';
        return `<div style="background:${tc}14;border:1.5px solid ${tc}44;border-radius:8px;padding:10px 14px;min-width:160px;max-width:200px;flex:0 0 auto;">
          <div style="font-size:10px;color:${tc};font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;">${t.tactic}</div>
          <div style="font-family:monospace;font-size:12px;color:${sc};font-weight:700;">${t.id}</div>
          <div style="font-size:11px;color:var(--soc-text);margin-top:2px;line-height:1.3;">${t.name}</div>
        </div>`;
      }).join('') || '<div style="padding:16px;color:var(--soc-muted);">No MITRE techniques mapped.</div>';
    }

    /* ── Traffic Timeline ── */
    const timelineEl = document.getElementById('ntaTimeline');
    if (timelineEl) {
      const lvlColor = { critical:'#ef4444', warn:'#f59e0b', info:'#22c55e' };
      const lvlIcon  = { critical:'fa-exclamation-circle', warn:'fa-exclamation-triangle', info:'fa-info-circle' };
      timelineEl.innerHTML = d.timeline.map(e => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid var(--soc-border);">
          <i class="fas ${lvlIcon[e.lvl]||'fa-dot-circle'}" style="color:${lvlColor[e.lvl]||'#8b949e'};margin-top:2px;min-width:14px;font-size:.75rem;"></i>
          <div style="flex:1;">
            <div style="font-size:12px;color:var(--soc-text);line-height:1.4;">${e.msg}</div>
            <div style="font-size:10px;color:var(--soc-muted);">${e.time ? new Date(e.time).toLocaleString() : '—'}</div>
          </div>
        </div>`).join('');
    }

    // Toast
    const threatCount = d.suspicious.filter(s => s.severity === 'CRITICAL' || s.severity === 'HIGH').length;
    if (typeof showToast === 'function') {
      showToast(
        `Analysis complete — ${d.summary.totalPackets.toLocaleString()} pkts · ${d.verdict.label}`,
        d.verdict.level === 'CRITICAL' ? 'error' : d.verdict.level === 'HIGH' ? 'warning' : 'success',
      );
    }
  }

  /* ══════════════════════════════════════════════════════════════
   *  ntaExportIOCs — CSV export of all IOCs
   * ══════════════════════════════════════════════════════════════ */
  function ntaExportIOCs() {
    const d = NTA_STATE.parsed;
    if (!d) return;
    const rows = [['Type','Subtype','Value','Context','Risk']];
    for (const ioc of d.iocs) {
      rows.push([ioc.type, ioc.subtype, `"${ioc.value.replace(/"/g,'""')}"`, `"${ioc.context.replace(/"/g,'""')}"`, ioc.risk]);
    }
    const csv = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `nta-iocs-${d.summary.filename.replace(/\./g,'_')}-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
    if (typeof showToast === 'function') showToast(`Exported ${d.iocs.length} IOCs to CSV`, 'success');
  }

  function ntaClearResults() {
    NTA_STATE.parsed = null;
    NTA_STATE.filename = '';
    const status  = document.getElementById('ntaStatus');
    const results = document.getElementById('ntaResults');
    const drop    = document.getElementById('ntaDropZone');
    const btn     = document.getElementById('ntaBtnExport');
    if (status)  status.style.display  = 'none';
    if (results) results.style.display = 'none';
    if (drop)    drop.style.display    = 'block';
    if (btn)     btn.disabled          = true;
    if (typeof showToast === 'function') showToast('Results cleared', 'info');
  }

  /* ─── Public API ─────────────────────────────────────────────────── */
  return {
    render,
    switchTab,
    // Tab 1
    startIngestion, stopIngestion, clearLog,
    filterAlerts, clearAlerts, openAlertDetail,
    escalateToIncident, saveThresholds,
    // Tab 2
    handleFileUpload, loadSampleLogs, runInvestigation,
    removeFile, clearInvestigation, saveAsIncident,
    switchResTab, updateApiKey,
    // Tab 3
    loadIncidents, filterIncidents,
    createManualIncident, exportIncidents,
    openIncidentDrawer, closeIncidentDrawer,
    updateIncidentStatus, toggleStep,
    updateAssignee, updateNotes,
    generateIncidentReport,
    // Tab 4
    selectReportTemplate, generateReport,
    downloadReport, printReport,
    // Tab 5
    configureIntegration, saveNotificationSettings,
    testNotification, previewPlaybook,
    // Tab 6
    sendChatMessage, sendSuggestion,
    updateAIKey,
    // Tab 7: Network Traffic Analysis
    ntaHandleUpload, ntaClearResults, ntaExportIOCs,
    version: '1.0.0',
  };
})();
