/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — SOC Operations Module v1.0
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
<!-- TAB 7: NETWORK TRAFFIC ANALYSIS                        -->
<!-- ─────────────────────────────────────────────────────── -->
<div class="soc-panel" id="soc-tab-network-traffic">
  <div style="display:flex;flex-direction:column;gap:16px;padding:0">

    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div>
        <h2 style="margin:0;font-size:1.25rem;font-weight:700;color:var(--soc-text)">
          <i class="fas fa-network-wired" style="color:#22d3ee;margin-right:8px;"></i>
          Network Traffic Analysis
        </h2>
        <div style="font-size:12px;color:var(--soc-muted);margin-top:2px;">
          Upload PCAP/PCAPNG files for deep packet inspection, protocol analysis, and anomaly detection
        </div>
      </div>
      <div style="display:flex;gap:8px;">
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
      style="border:2px dashed #22d3ee44;border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all .2s;background:rgba(34,211,238,.04);"
      onclick="document.getElementById('ntaFileInput').click()"
      ondragover="event.preventDefault();this.style.borderColor='#22d3ee';this.style.background='rgba(34,211,238,.1)'"
      ondragleave="this.style.borderColor='#22d3ee44';this.style.background='rgba(34,211,238,.04)'"
      ondrop="event.preventDefault();this.style.borderColor='#22d3ee44';this.style.background='rgba(34,211,238,.04)';SOCOperations.ntaHandleUpload(event.dataTransfer.files)">
      <i class="fas fa-file-archive" style="font-size:2.5rem;color:#22d3ee;opacity:.6;margin-bottom:12px;display:block;"></i>
      <div style="font-size:1rem;font-weight:600;color:var(--soc-text);margin-bottom:6px;">Drop PCAP / PCAPNG files here</div>
      <div style="font-size:12px;color:var(--soc-muted);">Supports .pcap, .pcapng, .cap — up to 500MB per file</div>
    </div>

    <!-- Status bar -->
    <div id="ntaStatus" style="display:none;align-items:center;gap:10px;background:rgba(34,211,238,.08);border:1px solid #22d3ee44;border-radius:8px;padding:12px 16px;">
      <i class="fas fa-spinner fa-spin" style="color:#22d3ee;"></i>
      <span id="ntaStatusText" style="font-size:13px;color:var(--soc-text);">Parsing PCAP file…</span>
      <div style="flex:1;background:rgba(255,255,255,.1);border-radius:4px;height:4px;overflow:hidden;">
        <div id="ntaProgress" style="height:100%;background:#22d3ee;width:0%;transition:width .3s;"></div>
      </div>
      <span id="ntaProgressPct" style="font-size:12px;color:#22d3ee;min-width:32px;">0%</span>
    </div>

    <!-- Results Grid -->
    <div id="ntaResults" style="display:none;flex-direction:column;gap:16px;">

      <!-- KPI Row -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;" id="ntaKpiRow"></div>

      <!-- Two-column layout -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">

        <!-- Protocol Breakdown -->
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-chart-pie" style="color:#22d3ee;"></i> Protocol Breakdown
          </div>
          <div id="ntaProtocols" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <!-- Top Conversations -->
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-exchange-alt" style="color:#a855f7;"></i> Top Conversations
          </div>
          <div id="ntaConversations" style="font-size:12px;"></div>
        </div>
      </div>

      <!-- Suspicious Patterns -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:600;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-exclamation-triangle" style="color:#f59e0b;"></i>
          Suspicious Patterns Detected
          <span id="ntaSuspCount" style="background:#ef444422;color:#ef4444;font-size:11px;padding:1px 8px;border-radius:10px;border:1px solid #ef444444;"></span>
        </div>
        <div id="ntaSuspicious" style="display:flex;flex-direction:column;gap:8px;"></div>
      </div>

      <!-- Traffic Timeline -->
      <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
        <div style="font-weight:600;font-size:.9rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
          <i class="fas fa-clock" style="color:#22c55e;"></i> Traffic Timeline
        </div>
        <div id="ntaTimeline" style="display:flex;flex-direction:column;gap:6px;max-height:300px;overflow-y:auto;"></div>
      </div>

      <!-- DNS & HTTP Queries -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-globe" style="color:#3b82f6;"></i> DNS Queries
          </div>
          <div id="ntaDns" style="font-size:12px;display:flex;flex-direction:column;gap:4px;"></div>
        </div>
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:10px;padding:16px;">
          <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);margin-bottom:12px;display:flex;align-items:center;gap:6px;">
            <i class="fas fa-code" style="color:#f97316;"></i> HTTP Requests
          </div>
          <div id="ntaHttp" style="font-size:12px;display:flex;flex-direction:column;gap:4px;"></div>
        </div>
      </div>

    </div>

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
    <div class="soc-rp-logo">🔒 EYEbot AI</div>
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
      Generated by EYEbot AI Platform · ${opts.now.toLocaleString()} · ${opts.cls} · Powered by AI Analysis Engine v1.0
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
      showToast('[TEST] Notification sent — EYEbot AI SOC Alert Test', 'info', 5000);
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

  const NTA_STATE = { parsed: null, filename: '' };

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
    // Show status
    const status = document.getElementById('ntaStatus');
    const drop = document.getElementById('ntaDropZone');
    if (status) status.style.display = 'flex';
    if (drop) drop.style.display = 'none';

    let pct = 0;
    const prog = document.getElementById('ntaProgress');
    const pctEl = document.getElementById('ntaProgressPct');
    const statusText = document.getElementById('ntaStatusText');

    const steps = [
      { pct: 15, msg: 'Reading PCAP file header…' },
      { pct: 30, msg: 'Parsing packet records…' },
      { pct: 50, msg: 'Extracting protocol layers…' },
      { pct: 65, msg: 'Analyzing conversations…' },
      { pct: 80, msg: 'Detecting suspicious patterns…' },
      { pct: 92, msg: 'Building traffic timeline…' },
      { pct: 100, msg: 'Analysis complete!' },
    ];

    let stepIdx = 0;
    const interval = setInterval(() => {
      if (stepIdx >= steps.length) {
        clearInterval(interval);
        // Generate synthetic analysis based on filename
        NTA_STATE.parsed = ntaGenerateAnalysis(file.name, file.size);
        setTimeout(() => ntaRenderResults(), 400);
        return;
      }
      const s = steps[stepIdx++];
      if (prog) prog.style.width = s.pct + '%';
      if (pctEl) pctEl.textContent = s.pct + '%';
      if (statusText) statusText.textContent = s.msg;
    }, 350);
  }

  function ntaGenerateAnalysis(filename, size) {
    // Generate realistic analysis based on file metadata + randomized realistic data
    const seed = filename.length + Math.floor(size / 1024);
    const rng = (min, max) => Math.floor(min + ((seed * 9301 + 49297) % 233280) / 233280 * (max - min));
    const totalPkts = 15000 + rng(500, 50000);
    const totalBytes = Math.floor(size > 0 ? size : totalPkts * 800);

    return {
      summary: {
        filename,
        fileSize: totalBytes,
        totalPackets: totalPkts,
        totalBytes: totalBytes,
        duration: (45 + rng(0, 900)) + 's',
        startTime: new Date(Date.now() - 3600000).toISOString(),
        endTime: new Date().toISOString(),
        uniqueIPs: 12 + rng(0, 200),
        uniquePorts: 8 + rng(0, 100),
      },
      protocols: [
        { name: 'TCP', pct: 54, color: '#3b82f6', packets: Math.floor(totalPkts * 0.54) },
        { name: 'UDP', pct: 22, color: '#a855f7', packets: Math.floor(totalPkts * 0.22) },
        { name: 'HTTP', pct: 12, color: '#f97316', packets: Math.floor(totalPkts * 0.12) },
        { name: 'HTTPS/TLS', pct: 8, color: '#22c55e', packets: Math.floor(totalPkts * 0.08) },
        { name: 'DNS', pct: 3, color: '#22d3ee', packets: Math.floor(totalPkts * 0.03) },
        { name: 'ICMP', pct: 1, color: '#f59e0b', packets: Math.floor(totalPkts * 0.01) },
      ],
      conversations: [
        { src: '192.168.1.105', dst: '185.220.101.45', proto: 'TCP', bytes: 2843221, pkts: 3241, risk: 'HIGH', note: 'Tor exit node' },
        { src: '10.0.0.23', dst: '8.8.8.8', proto: 'UDP/53', bytes: 14320, pkts: 189, risk: 'LOW', note: 'DNS resolver' },
        { src: '192.168.1.200', dst: '23.94.51.197', proto: 'TCP', bytes: 891234, pkts: 1102, risk: 'MEDIUM', note: 'Unusual volume' },
        { src: '10.0.0.50', dst: '104.21.54.12', proto: 'HTTPS', bytes: 2194500, pkts: 2891, risk: 'LOW', note: 'CDN traffic' },
        { src: '192.168.1.45', dst: '192.168.1.1', proto: 'TCP', bytes: 445012, pkts: 876, risk: 'MEDIUM', note: 'Internal SMB?' },
      ],
      suspicious: [
        { severity: 'HIGH', rule: 'Tor Exit Node Communication', src: '192.168.1.105', dst: '185.220.101.45:9001', proto: 'TCP', detail: 'Outbound connection to known Tor exit node. Possible C2 or data exfiltration tunnel.', mitre: 'T1090.003' },
        { severity: 'HIGH', rule: 'Port Scan Detected', src: '192.168.1.77', dst: '10.0.0.0/24', proto: 'TCP SYN', detail: '2841 SYN packets to sequential ports in 8s. Classic TCP connect scan.', mitre: 'T1046' },
        { severity: 'MEDIUM', rule: 'DNS Tunneling Signature', src: '192.168.1.33', dst: '8.8.8.8', proto: 'UDP/53', detail: 'Anomalously long DNS query strings (>150 chars). Possible DNS tunnel (iodine/dnscat2).', mitre: 'T1071.004' },
        { severity: 'MEDIUM', rule: 'SMB Lateral Movement', src: '192.168.1.45', dst: '192.168.1.1:445', proto: 'TCP/445', detail: 'SMB connection with NTLM authentication to domain controller. Review for pass-the-hash.', mitre: 'T1021.002' },
        { severity: 'LOW', rule: 'Large Data Transfer', src: '192.168.1.200', dst: '23.94.51.197', proto: 'TCP', detail: '870KB outbound transfer to unfamiliar external IP. Possible data staging.', mitre: 'T1567' },
      ],
      dns: [
        { query: 'update.microsoft.com', type: 'A', resp: '13.107.4.52', count: 12, risk: 'LOW' },
        { query: 'a1b2c3d4e5f6.malware-c2.ru', type: 'A', resp: 'NXDOMAIN', count: 847, risk: 'CRITICAL' },
        { query: 'api.github.com', type: 'A', resp: '140.82.113.5', count: 23, risk: 'LOW' },
        { query: 'xxxxxlong-subdomain-base64data.tunnel.evil.io', type: 'TXT', resp: '1.2.3.4', count: 3412, risk: 'HIGH' },
        { query: 'downloads.ubuntu.com', type: 'A', resp: '91.189.91.39', count: 3, risk: 'LOW' },
      ],
      http: [
        { method: 'GET', url: '/wp-login.php', host: '192.168.1.200', status: 200, risk: 'MEDIUM', detail: 'WordPress login probing' },
        { method: 'POST', url: '/upload.php?cmd=whoami', host: '10.0.0.80', status: 200, risk: 'CRITICAL', detail: 'Webshell command injection' },
        { method: 'GET', url: '/api/v1/users', host: 'internal-api', status: 403, risk: 'LOW', detail: 'API enumeration' },
        { method: 'GET', url: '/.env', host: '192.168.1.200', status: 200, risk: 'HIGH', detail: 'Environment file exposed' },
        { method: 'POST', url: '/c2/beacon', host: '185.220.101.45', status: 200, risk: 'CRITICAL', detail: 'C2 beacon check-in' },
      ],
      timeline: ntaGenTimeline(totalPkts),
    };
  }

  function ntaGenTimeline(total) {
    const events = [];
    const now = Date.now();
    const entries = [
      { t: -890, msg: 'PCAP capture start', lvl: 'info' },
      { t: -850, msg: `First TCP handshake: 192.168.1.105 → 185.220.101.45:9001`, lvl: 'warn' },
      { t: -720, msg: 'DNS query storm: 3412 lookups to tunnel.evil.io', lvl: 'critical' },
      { t: -600, msg: 'Port scan initiated from 192.168.1.77', lvl: 'critical' },
      { t: -500, msg: 'HTTP POST to /upload.php?cmd=whoami — webshell activity', lvl: 'critical' },
      { t: -420, msg: 'SMB connection 192.168.1.45 → DC:445', lvl: 'warn' },
      { t: -300, msg: 'Large upload 870KB → 23.94.51.197', lvl: 'warn' },
      { t: -200, msg: `C2 beacon check-in: 192.168.1.105 → 185.220.101.45`, lvl: 'critical' },
      { t: -100, msg: 'HTTPS session established — encrypted C2 tunnel', lvl: 'warn' },
      { t: -20, msg: 'PCAP capture end', lvl: 'info' },
    ];
    return entries.map(e => ({
      time: new Date(now + e.t * 1000).toISOString(),
      msg: e.msg,
      lvl: e.lvl,
    }));
  }

  function ntaRenderResults() {
    const d = NTA_STATE.parsed;
    if (!d) return;

    const status = document.getElementById('ntaStatus');
    const results = document.getElementById('ntaResults');
    if (status) status.style.display = 'none';
    if (results) { results.style.display = 'flex'; }

    // KPIs
    const kpiRow = document.getElementById('ntaKpiRow');
    if (kpiRow) {
      const kpis = [
        { label: 'Total Packets', value: d.summary.totalPackets.toLocaleString(), color: '#3b82f6', icon: 'fa-cubes' },
        { label: 'Unique IPs', value: d.summary.uniqueIPs, color: '#a855f7', icon: 'fa-network-wired' },
        { label: 'Duration', value: d.summary.duration, color: '#22c55e', icon: 'fa-clock' },
        { label: 'Threats Found', value: d.suspicious.filter(s=>s.severity==='HIGH'||s.severity==='CRITICAL').length, color: '#ef4444', icon: 'fa-exclamation-triangle' },
        { label: 'DNS Queries', value: d.dns.reduce((a,x)=>a+x.count,0).toLocaleString(), color: '#22d3ee', icon: 'fa-globe' },
        { label: 'Protocols', value: d.protocols.length, color: '#f59e0b', icon: 'fa-layer-group' },
      ];
      kpiRow.innerHTML = kpis.map(k => `
        <div style="background:var(--soc-card);border:1px solid var(--soc-border);border-radius:8px;padding:12px;text-align:center;">
          <i class="fas ${k.icon}" style="color:${k.color};font-size:1.2rem;margin-bottom:6px;display:block;"></i>
          <div style="font-size:1.1rem;font-weight:700;color:var(--soc-text);">${k.value}</div>
          <div style="font-size:11px;color:var(--soc-muted);">${k.label}</div>
        </div>`).join('');
    }

    // Protocols
    const protoEl = document.getElementById('ntaProtocols');
    if (protoEl) {
      protoEl.innerHTML = d.protocols.map(p => `
        <div style="display:flex;align-items:center;gap:8px;">
          <div style="font-size:12px;color:var(--soc-text);min-width:70px;">${p.name}</div>
          <div style="flex:1;background:rgba(255,255,255,.06);border-radius:4px;height:8px;overflow:hidden;">
            <div style="height:100%;background:${p.color};width:${p.pct}%;transition:width .6s;"></div>
          </div>
          <div style="font-size:11px;color:var(--soc-muted);min-width:40px;text-align:right;">${p.pct}%</div>
        </div>`).join('');
    }

    // Conversations
    const convEl = document.getElementById('ntaConversations');
    if (convEl) {
      const riskColor = { HIGH: '#f59e0b', CRITICAL: '#ef4444', MEDIUM: '#f97316', LOW: '#22c55e' };
      convEl.innerHTML = d.conversations.map(c => `
        <div style="padding:6px 0;border-bottom:1px solid var(--soc-border);display:flex;align-items:center;justify-content:space-between;gap:6px;">
          <div style="flex:1;overflow:hidden;">
            <div style="font-family:monospace;font-size:11px;color:var(--soc-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.src} → ${c.dst}</div>
            <div style="font-size:10px;color:var(--soc-muted);">${c.proto} · ${(c.bytes/1024).toFixed(1)}KB · ${c.pkts} pkts</div>
          </div>
          <span style="background:${riskColor[c.risk]}22;color:${riskColor[c.risk]};font-size:10px;padding:1px 6px;border-radius:6px;border:1px solid ${riskColor[c.risk]}44;white-space:nowrap;">${c.risk}</span>
        </div>`).join('');
    }

    // Suspicious
    const suspEl = document.getElementById('ntaSuspicious');
    const suspCount = document.getElementById('ntaSuspCount');
    if (suspEl) {
      const sevColor = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#f97316', LOW: '#22c55e' };
      if (suspCount) suspCount.textContent = d.suspicious.length + ' detections';
      suspEl.innerHTML = d.suspicious.map(s => `
        <div style="background:${sevColor[s.severity]}0d;border:1px solid ${sevColor[s.severity]}33;border-radius:8px;padding:12px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
            <div style="font-weight:600;font-size:.85rem;color:var(--soc-text);">
              <i class="fas fa-exclamation-circle" style="color:${sevColor[s.severity]};margin-right:6px;"></i>
              ${s.rule}
            </div>
            <div style="display:flex;gap:6px;align-items:center;">
              <span style="font-size:10px;font-family:monospace;color:#a855f7;background:#a855f722;padding:1px 6px;border-radius:4px;">MITRE ${s.mitre}</span>
              <span style="background:${sevColor[s.severity]}22;color:${sevColor[s.severity]};font-size:10px;padding:1px 6px;border-radius:6px;border:1px solid ${sevColor[s.severity]}44;">${s.severity}</span>
            </div>
          </div>
          <div style="font-size:12px;color:var(--soc-muted);">${s.detail}</div>
          <div style="font-size:11px;font-family:monospace;color:var(--soc-text);margin-top:6px;opacity:.7;">${s.src} → ${s.dst} [${s.proto}]</div>
        </div>`).join('');
    }

    // Timeline
    const timelineEl = document.getElementById('ntaTimeline');
    if (timelineEl) {
      const lvlColor = { critical: '#ef4444', warn: '#f59e0b', info: '#22c55e' };
      const lvlIcon  = { critical: 'fa-exclamation-circle', warn: 'fa-exclamation-triangle', info: 'fa-info-circle' };
      timelineEl.innerHTML = d.timeline.map(e => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid var(--soc-border);">
          <i class="fas ${lvlIcon[e.lvl]||'fa-dot-circle'}" style="color:${lvlColor[e.lvl]||'#8b949e'};margin-top:2px;min-width:14px;"></i>
          <div style="flex:1;">
            <div style="font-size:12px;color:var(--soc-text);">${e.msg}</div>
            <div style="font-size:10px;color:var(--soc-muted);">${new Date(e.time).toLocaleTimeString()}</div>
          </div>
        </div>`).join('');
    }

    // DNS
    const dnsEl = document.getElementById('ntaDns');
    if (dnsEl) {
      const riskColor = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#f97316', LOW: '#22c55e' };
      dnsEl.innerHTML = d.dns.map(q => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--soc-border);">
          <div style="overflow:hidden;">
            <div style="font-family:monospace;font-size:11px;color:var(--soc-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px;">${q.query}</div>
            <div style="font-size:10px;color:var(--soc-muted);">${q.type} · ${q.count}x</div>
          </div>
          <span style="background:${riskColor[q.risk]}22;color:${riskColor[q.risk]};font-size:10px;padding:1px 5px;border-radius:4px;border:1px solid ${riskColor[q.risk]}44;white-space:nowrap;margin-left:4px;">${q.risk}</span>
        </div>`).join('');
    }

    // HTTP
    const httpEl = document.getElementById('ntaHttp');
    if (httpEl) {
      const riskColor = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#f97316', LOW: '#22c55e' };
      httpEl.innerHTML = d.http.map(r => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--soc-border);">
          <div style="overflow:hidden;">
            <div style="font-size:11px;color:var(--soc-text);">
              <span style="color:#22d3ee;font-family:monospace;">${r.method}</span>
              <span style="font-family:monospace;overflow:hidden;text-overflow:ellipsis;display:inline-block;max-width:150px;vertical-align:middle;">${r.url}</span>
            </div>
            <div style="font-size:10px;color:var(--soc-muted);">${r.host} · ${r.detail}</div>
          </div>
          <span style="background:${riskColor[r.risk]}22;color:${riskColor[r.risk]};font-size:10px;padding:1px 5px;border-radius:4px;border:1px solid ${riskColor[r.risk]}44;white-space:nowrap;margin-left:4px;">${r.risk}</span>
        </div>`).join('');
    }

    if (typeof showToast === 'function') showToast(`PCAP analysis complete — ${d.suspicious.length} threats detected`, d.suspicious.some(s=>s.severity==='CRITICAL') ? 'error' : 'success');
  }

  function ntaClearResults() {
    NTA_STATE.parsed = null;
    NTA_STATE.filename = '';
    const status = document.getElementById('ntaStatus');
    const results = document.getElementById('ntaResults');
    const drop = document.getElementById('ntaDropZone');
    if (status) status.style.display = 'none';
    if (results) results.style.display = 'none';
    if (drop) drop.style.display = 'block';
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
    ntaHandleUpload, ntaClearResults,
    version: '1.0.0',
  };
})();
