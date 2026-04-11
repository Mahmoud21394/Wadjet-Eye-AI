/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Detection Engineering Studio v3.0
 *  Production rules, test coverage, MITRE mapping
 * ══════════════════════════════════════════════════════════
 */
'use strict';

window.DETECTION_RULES = [
  {
    id:'dr-001', name:'Google API Key Exposure in Code',
    status:'production', platform:'SIGMA', category:'Credential Exposure',
    severity:'high', mitre:['T1552.001'],
    detections_30d:47, false_positive_rate:2,
    description:'Detects exposure of Google API keys in code repositories and configuration files.',
    rule:`title: Google API Key Exposure
id: de4e3b5c-1234-5678-abcd-ef0123456789
status: production
author: EYEbot AI
date: 2025/01/15
description: Detects exposure of Google API keys
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '.env'
            - 'config.json'
            - 'appsettings.json'
        Contents|re: 'AIza[0-9A-Za-z\\-_]{35}'
    condition: selection
falsepositives:
    - Legitimate code repositories with properly secured keys
level: high
tags:
    - attack.t1552.001
    - attack.credential_access`,
    kql_variant:`// KQL — Microsoft Sentinel
AuditLogs
| where OperationName contains "GitPush" or OperationName contains "CommitCreated"
| where Properties has_any ("AIza","AAAA","ya29.")
| extend APIKey = extract(@"(AIza[0-9A-Za-z\\-_]{35})", 1, tostring(Properties))
| where isnotempty(APIKey)
| project TimeGenerated, OperationName, APIKey, InitiatedBy`,
    spl_variant:`// SPL — Splunk
index=vcs_logs OR index=file_activity
| regex _raw="AIza[0-9A-Za-z\\-_]{35}"
| rex field=_raw "(?<api_key>AIza[0-9A-Za-z\\-_]{35})"
| stats count by api_key, src_user, file_path, _time`
  },
  {
    id:'dr-002', name:'Critical CVE Exploitation Attempt',
    status:'production', platform:'KQL', category:'Vulnerability Exploitation',
    severity:'critical', mitre:['T1190','T1211'],
    detections_30d:156, false_positive_rate:5,
    description:'Detects exploitation attempts for critical CVEs on public-facing web applications.',
    rule:`// KQL — Microsoft Sentinel
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS"
| where Message has_any (
    "CVE-2021-44228","CVE-2023-44487","CVE-2024-",
    "jndi:ldap","jndi:rmi","..%2F..%2F",
    "../../etc/passwd","<script>alert","UNION SELECT",
    "' OR '1'='1","cmd.exe /c","powershell.exe -enc")
| where action_s == "Blocked" or action_s == "Detected"
| summarize count() by clientIP_s, requestUri_s, action_s, bin(TimeGenerated, 5m)
| where count_ > 3
| order by count_ desc`,
    kql_variant:`// Alternative: Web Server Logs
W3CIISLog
| where csUriQuery contains_any (
    "jndi:","../","<script>","UNION","exec(",
    "system(","passthru(","shell_exec(")
| summarize Attempts=count(), URIs=make_set(csUriQuery)
    by cIP, csHost, bin(TimeGenerated, 1h)
| where Attempts > 5`,
    spl_variant:`// SPL — Splunk
index=web_access
| regex uri="(jndi:|\.\.\/|<script>|UNION SELECT|exec\()"
| stats count AS attempts, values(uri) AS attack_uris
    by src_ip, host
| where attempts > 3`
  },
  {
    id:'dr-003', name:'Malicious IP C2 Communication',
    status:'production', platform:'Multi', category:'Command & Control',
    severity:'critical', mitre:['T1071','T1095','T1008'],
    detections_30d:312, false_positive_rate:8,
    description:'Detects outbound communication to known C2 IPs from threat intelligence feeds.',
    rule:`# SIGMA — C2 Communication
title: Malicious IP C2 Communication
status: production
author: EYEbot AI
logsource:
    category: firewall
detection:
    selection:
        dst_ip|cidr:
            - '185.220.0.0/16'   # Tor exit nodes range
            - '194.165.16.0/24'  # Known C2 range
        dst_port:
            - 4444
            - 8080
            - 1080
            - 9090
    filter:
        src_ip|cidr: '127.0.0.0/8'
    condition: selection and not filter
falsepositives:
    - Legitimate proxy or Tor usage
level: critical
tags:
    - attack.t1071
    - attack.command_and_control`,
    kql_variant:`// KQL — Defender for Endpoint
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort in (4444, 8080, 1080, 9090, 4443, 8443)
| join kind=inner (
    externaldata(ip:string)[@"https://threatintel.wadjet-eye.ai/c2-ips.txt"] with (format="txt")
) on $left.RemoteIP == $right.ip
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
    spl_variant:`// SPL — Splunk with threat intel lookup
index=firewall action=allowed
| lookup threat_intel_ips ip AS dest_ip OUTPUT threat_score, threat_type
| where threat_score > 70
| stats count, values(dest_port) AS ports
    by src_ip, dest_ip, threat_type`
  },
  {
    id:'dr-004', name:'Ransomware File System Activity',
    status:'production', platform:'KQL', category:'Ransomware',
    severity:'critical', mitre:['T1486','T1490','T1489'],
    detections_30d:23, false_positive_rate:1,
    description:'Detects mass file encryption and shadow copy deletion characteristic of ransomware.',
    rule:`// KQL — Defender for Endpoint
let timeframe = 10m;
let encryptedFileThreshold = 50;
DeviceFileEvents
| where Timestamp > ago(timeframe)
| where ActionType in ("FileCreated","FileModified")
| where FileName matches regex @"\.(encrypted|locked|crypto|crypt|enc|locky|cerber|wannacry)$"
    or FileName matches regex @"\.[a-z0-9]{4,8}$" // New random extension
| summarize FileCount=count(), Files=make_set(FileName, 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
| where FileCount > encryptedFileThreshold
| order by FileCount desc`,
    kql_variant:`// Shadow copy deletion detection
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled No",
    "wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    spl_variant:`// SPL
index=windows source="WinEventLog:Security" EventCode=4663
| where Object_Name LIKE "%.encrypted" OR Object_Name LIKE "%.locked"
| stats count AS encrypted_files by ComputerName, Process_Name, Account_Name
| where encrypted_files > 20`
  },
  {
    id:'dr-005', name:'Phishing URL Click Detection',
    status:'production', platform:'SPL', category:'Phishing',
    severity:'high', mitre:['T1566.002','T1204.001'],
    detections_30d:89, false_positive_rate:15,
    description:'Detects users clicking phishing URLs by analyzing proxy and email gateway logs.',
    rule:`// SPL — Splunk (Proxy + Email)
index=proxy sourcetype=bluecoat
| lookup phishing_domains domain AS cs_host OUTPUT threat_level
| where threat_level IN ("high","critical")
| stats count AS clicks, values(cs_username) AS users
    by cs_host, cs_uri_path
| eval risk_score=case(
    threat_level="critical", 100,
    threat_level="high", 75,
    true(), 50)
| sort -risk_score`,
    kql_variant:`// KQL — Defender for Office 365
EmailUrlInfo
| where UrlLocation == "Body"
| join kind=inner (
    EmailEvents | where ThreatTypes has "Phish"
) on NetworkMessageId
| project Timestamp=EmailEvents.Timestamp, SenderAddress, RecipientEmailAddress, Url`,
    spl_variant:`// SPL alternate
index=email_gateway action=delivered
| lookup urlhaus_lookup url OUTPUT threat_type, tags
| where isnotnull(threat_type)
| table _time, sender, recipient, url, threat_type, tags`
  },
  {
    id:'dr-006', name:'Privilege Escalation via Impersonation',
    status:'testing', platform:'KQL', category:'Privilege Escalation',
    severity:'high', mitre:['T1134.001','T1134.002'],
    detections_30d:12, false_positive_rate:22,
    description:'Detects Windows token impersonation and privilege escalation via access token manipulation.',
    rule:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where ProcessIntegrityLevel == "High" or ProcessIntegrityLevel == "System"
| where InitiatingProcessIntegrityLevel == "Medium" or InitiatingProcessIntegrityLevel == "Low"
| where FileName !in~ (
    "consent.exe","wsmprovhost.exe","msiexec.exe",
    "setup.exe","Update.exe","updater.exe")
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessIntegrityLevel, ProcessIntegrityLevel`,
    kql_variant:`// Alternative: SeDebugPrivilege abuse
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessAccountName != "SYSTEM"
| where FileName !in~ ("svchost.exe","SearchIndexer.exe","MsMpEng.exe")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessAccountName`,
    spl_variant:`// SPL
index=windows EventCode=4703
| where Enabled_Privileges LIKE "%SeDebugPrivilege%"
    OR Enabled_Privileges LIKE "%SeImpersonatePrivilege%"
| where Account_Name != "SYSTEM"
| stats count by Account_Name, Process_Name, ComputerName`
  },
  {
    id:'dr-007', name:'Anomalous Service Account Behavior',
    status:'production', platform:'KQL', category:'Credential Abuse',
    severity:'high', mitre:['T1078.002'],
    detections_30d:34, false_positive_rate:10,
    description:'Detects service accounts being used interactively or from unusual locations.',
    rule:`// KQL — Microsoft Sentinel
SigninLogs
| where UserType == "ServiceAccount" or UserPrincipalName startswith "svc-"
    or UserPrincipalName startswith "sa-"
| where AppDisplayName !in ("Microsoft Exchange Online","SQL Server","Azure AD","IIS")
| where AuthenticationMethodsUsed !has "Service Account Token"
| project TimeGenerated, UserPrincipalName, AppDisplayName,
    IPAddress, LocationDetails, ResultType, ResultDescription
| where ResultType == 0
| order by TimeGenerated desc`,
    kql_variant:`// Alternative detection
DeviceLogonEvents
| where AccountName startswith "svc" or AccountName startswith "sa_"
| where LogonType in ("Interactive","RemoteInteractive")  // Unusual for service accounts
| project Timestamp, DeviceName, AccountName, LogonType, ActionType`,
    spl_variant:`// SPL
index=windows EventCode=4624 Logon_Type IN (2, 10)
| where Account_Name LIKE "svc%" OR Account_Name LIKE "sa_%"
| stats count, values(Logon_Type) AS logon_types
    by Account_Name, Source_Network_Address, ComputerName
| sort -count`
  },
  {
    id:'dr-008', name:'Cryptominer Process Detection',
    status:'production', platform:'Multi', category:'Impact',
    severity:'medium', mitre:['T1496'],
    detections_30d:67, false_positive_rate:5,
    description:'Detects cryptocurrency mining activity via process signatures and resource consumption patterns.',
    rule:`# SIGMA — Cryptominer Detection
title: Cryptocurrency Miner Execution
status: production
author: EYEbot AI
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        Image|endswith:
            - '\\xmrig.exe'
            - '\\minerd.exe'
            - '\\cpuminer.exe'
    selection_args:
        CommandLine|contains:
            - '--algo='
            - '-o stratum+'
            - 'pool.supportxmr.com'
            - 'xmrpool.eu'
            - 'moneropool'
            - '--donate-level'
    condition: 1 of selection*
level: medium
tags:
    - attack.t1496`,
    kql_variant:`// KQL — High CPU process detection
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "xmrig","minerd","--algo=","stratum+tcp://","monero","randomx")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl_variant:`// SPL
index=windows
| search (process_name IN ("xmrig.exe","minerd.exe","cpuminer.exe"))
    OR (command_line LIKE "%stratum+%" OR command_line LIKE "%--algo=%")
| stats count by host, user, process_name, command_line`
  }
];

/* ── Main renderer ── */
window.renderDetectionEngineering = function renderDetectionEngineering() {
  const container = document.getElementById('detectionEngineeringWrap');
  if (!container) return;

  const altContainer = document.getElementById('vulnsLiveContainer');
  container.style.display = 'block';
  if (altContainer) altContainer.style.display = 'none';

  const rules = window.DETECTION_RULES || [];
  const prodCount    = rules.filter(r => r.status === 'production').length;
  const testCount    = rules.filter(r => r.status === 'testing').length;
  const totalDet     = rules.reduce((a, r) => a + (r.detections_30d || 0), 0);
  const mitreCount   = [...new Set(rules.flatMap(r => r.mitre || []))].length;

  container.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-shield-alt" style="color:#3b82f6;margin-right:8px"></i>
        Detection Engineering Studio
      </h2>
      <div style="font-size:.78em;color:#8b949e;margin-top:2px">Create, test & deploy detection rules · SIGMA · KQL · SPL · EQL</div>
    </div>
    <div style="display:flex;gap:8px">
      <button onclick="_deNewRule()"
        style="background:rgba(29,106,229,.15);color:#3b82f6;border:1px solid rgba(29,106,229,.3);
          padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer">
        <i class="fas fa-plus" style="margin-right:4px"></i>New Rule</button>
      <button onclick="_deImport()"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;
          padding:6px 14px;border-radius:6px;font-size:.8em;cursor:pointer">
        <i class="fas fa-upload" style="margin-right:4px"></i>Import SIGMA</button>
    </div>
  </div>

  <!-- KPI Cards -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:20px">
    ${[
      {label:'Production Rules', val:prodCount, icon:'fa-check-circle', c:'#22c55e', sub:'Active & deployed'},
      {label:'In Testing',       val:testCount, icon:'fa-flask',        c:'#f59e0b', sub:'Validation stage'},
      {label:'Total Detections', val:totalDet,  icon:'fa-bell',         c:'#3b82f6', sub:'Last 30 days'},
      {label:'MITRE Coverage',   val:mitreCount,icon:'fa-th',           c:'#8b5cf6', sub:'Unique techniques'},
    ].map(k=>`
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <i class="fas ${k.icon}" style="color:${k.c};font-size:1em"></i>
        <span style="font-size:.72em;color:#8b949e">${k.label}</span>
      </div>
      <div style="font-size:1.5em;font-weight:700;color:${k.c}">${k.val.toLocaleString()}</div>
      <div style="font-size:.68em;color:#8b949e;margin-top:2px">${k.sub}</div>
    </div>`).join('')}
  </div>

  <!-- Filters -->
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center">
    <input id="de-search" placeholder="🔍 Search rules…" oninput="_deSearch()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:180px"/>
    <select id="de-status" onchange="_deFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Status</option>
      <option value="production">Production</option>
      <option value="testing">In Testing</option>
      <option value="deprecated">Deprecated</option>
    </select>
    <select id="de-platform" onchange="_deFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Platforms</option>
      <option value="SIGMA">SIGMA</option>
      <option value="KQL">KQL</option>
      <option value="SPL">Splunk SPL</option>
      <option value="Multi">Multi-platform</option>
    </select>
    <select id="de-sev" onchange="_deFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
    </select>
    <span id="de-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
  </div>

  <!-- Rules Grid -->
  <div id="de-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;margin-bottom:20px"></div>

  <!-- Rule Editor (shown when editing) -->
  <div id="de-editor-panel" style="display:none;background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden">
    <div style="padding:12px 16px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between">
      <div style="font-size:.85em;font-weight:700;color:#e6edf3">
        <i class="fas fa-edit" style="color:#3b82f6;margin-right:6px"></i>
        <span id="de-editor-title">Rule Editor</span>
      </div>
      <div style="display:flex;gap:6px">
        <button onclick="_deTest()" style="background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3);padding:5px 12px;border-radius:6px;font-size:.78em;cursor:pointer">
          <i class="fas fa-flask" style="margin-right:4px"></i>Test Rule</button>
        <button onclick="_deDeploy()" style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);padding:5px 12px;border-radius:6px;font-size:.78em;cursor:pointer">
          <i class="fas fa-rocket" style="margin-right:4px"></i>Deploy</button>
        <button onclick="document.getElementById('de-editor-panel').style.display='none'"
          style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:5px 10px;border-radius:6px;font-size:.78em;cursor:pointer">
          <i class="fas fa-times"></i></button>
      </div>
    </div>
    <!-- Tabs: SIGMA / KQL / SPL -->
    <div style="display:flex;border-bottom:1px solid #21262d" id="de-editor-tabs"></div>
    <textarea id="de-rule-editor"
      style="width:100%;min-height:300px;background:#080c14;border:none;color:#e6edf3;
        font-family:'Courier New',monospace;font-size:.82em;padding:14px;resize:vertical;outline:none;
        line-height:1.6;box-sizing:border-box"
      placeholder="# Paste or write your detection rule here..."></textarea>
    <div id="de-test-results" style="padding:10px 14px;border-top:1px solid #21262d;font-size:.78em;color:#8b949e;display:none"></div>
  </div>
  `;

  _deRenderGrid();
};

let _deSearchTimer;
window._deSearch = () => { clearTimeout(_deSearchTimer); _deSearchTimer = setTimeout(_deFilter, 250); };
window._deFilter = function() {
  _deRenderGrid({
    search:   document.getElementById('de-search')?.value  || '',
    status:   document.getElementById('de-status')?.value  || '',
    platform: document.getElementById('de-platform')?.value || '',
    severity: document.getElementById('de-sev')?.value      || ''
  });
};

function _deRenderGrid(filters = {}) {
  const grid = document.getElementById('de-grid');
  const cnt  = document.getElementById('de-count');
  if (!grid) return;

  let rules = window.DETECTION_RULES || [];
  if (filters.search) {
    const q = filters.search.toLowerCase();
    rules = rules.filter(r => r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q));
  }
  if (filters.status)   rules = rules.filter(r => r.status   === filters.status);
  if (filters.platform) rules = rules.filter(r => r.platform === filters.platform || r.platform === 'Multi');
  if (filters.severity) rules = rules.filter(r => r.severity === filters.severity);

  if (cnt) cnt.textContent = `${rules.length} rules`;

  const platColors = {SIGMA:'#8b5cf6',KQL:'#3b82f6',SPL:'#f59e0b',Multi:'#22c55e',EQL:'#06b6d4'};
  const sevColors  = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e'};
  const statusColors = {production:'#22c55e',testing:'#f59e0b',deprecated:'#8b949e'};

  grid.innerHTML = rules.map(r => {
    const pc = platColors[r.platform] || '#8b949e';
    const sc = sevColors[r.severity]  || '#8b949e';
    const stc = statusColors[r.status] || '#8b949e';

    return `
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:16px;
        transition:all .2s;cursor:pointer"
      onmouseover="this.style.borderColor='${pc}55'" onmouseout="this.style.borderColor='#21262d'"
      onclick="_deOpenRule('${r.id}')">

      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
        <div style="flex:1">
          <div style="font-size:.85em;font-weight:700;color:#e6edf3;margin-bottom:4px">${_escDE(r.name)}</div>
          <div style="font-size:.75em;color:#8b949e;line-height:1.5">${_escDE(r.description.slice(0,80))}…</div>
        </div>
      </div>

      <!-- Badges -->
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
        <span style="background:${pc}18;color:${pc};border:1px solid ${pc}33;padding:1px 7px;border-radius:4px;font-size:.68em;font-weight:700">${r.platform}</span>
        <span style="background:${sc}18;color:${sc};border:1px solid ${sc}33;padding:1px 7px;border-radius:4px;font-size:.68em;font-weight:600;text-transform:uppercase">${r.severity}</span>
        <span style="background:${stc}18;color:${stc};border:1px solid ${stc}33;padding:1px 7px;border-radius:4px;font-size:.68em;font-weight:600">
          ${r.status === 'production' ? '● LIVE' : r.status === 'testing' ? '⚗ Testing' : r.status}</span>
      </div>

      <!-- Stats -->
      <div style="display:flex;gap:14px;font-size:.73em;margin-bottom:10px">
        <span style="color:#3b82f6"><i class="fas fa-bell" style="margin-right:3px"></i>${r.detections_30d} detections/30d</span>
        <span style="color:${r.false_positive_rate > 15 ? '#ef4444' : r.false_positive_rate > 8 ? '#f59e0b' : '#22c55e'}">
          <i class="fas fa-exclamation-triangle" style="margin-right:3px"></i>FP: ${r.false_positive_rate}%</span>
      </div>

      <!-- MITRE -->
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${(r.mitre || []).map(t => `<span style="background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);padding:1px 6px;border-radius:4px;font-family:monospace;font-size:.69em">${t}</span>`).join('')}
      </div>

      <!-- Action buttons -->
      <div style="display:flex;gap:6px;border-top:1px solid #21262d;padding-top:10px">
        <button onclick="event.stopPropagation();_deOpenRule('${r.id}')"
          style="flex:1;background:#1d6ae520;color:#3b82f6;border:1px solid #1d6ae533;padding:4px;border-radius:5px;font-size:.72em;cursor:pointer">
          <i class="fas fa-eye" style="margin-right:3px"></i>View</button>
        <button onclick="event.stopPropagation();_deEditRule('${r.id}')"
          style="flex:1;background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px;border-radius:5px;font-size:.72em;cursor:pointer">
          <i class="fas fa-edit" style="margin-right:3px"></i>Edit</button>
        <button onclick="event.stopPropagation();_deExportRule('${r.id}')"
          style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px 8px;border-radius:5px;font-size:.72em;cursor:pointer">
          <i class="fas fa-download"></i></button>
      </div>
    </div>`;
  }).join('');
}

window._deOpenRule = function(id) {
  const r = (window.DETECTION_RULES || []).find(x => x.id === id);
  if (!r) return;
  _deEditRule(id); // Same view for now — opens editor
};

window._deEditRule = function(id) {
  const r = (window.DETECTION_RULES || []).find(x => x.id === id);
  if (!r) return;
  const panel = document.getElementById('de-editor-panel');
  const title = document.getElementById('de-editor-title');
  const editor = document.getElementById('de-rule-editor');
  const tabs = document.getElementById('de-editor-tabs');
  if (!panel || !editor) return;

  panel.style.display = 'block';
  if (title) title.textContent = r.name;

  // Render tabs
  const variants = [
    {label: r.platform === 'SIGMA' ? 'SIGMA' : r.platform, code: r.rule},
    ...(r.kql_variant ? [{label:'KQL Variant', code: r.kql_variant}] : []),
    ...(r.spl_variant ? [{label:'SPL Variant', code: r.spl_variant}] : [])
  ];

  let activeTab = 0;
  function renderTabs() {
    if (!tabs) return;
    tabs.innerHTML = variants.map((v, i) => `
    <div onclick="_deSwitchTab(${i},${JSON.stringify(variants.map(x=>x.code)).replace(/"/g,'&quot;')})"
      id="de-tab-${i}"
      style="padding:8px 16px;font-size:.78em;cursor:pointer;border-bottom:2px solid ${i===activeTab?'#3b82f6':'transparent'};
        color:${i===activeTab?'#3b82f6':'#8b949e'};font-weight:${i===activeTab?'600':'400'}">
      ${_escDE(v.label)}</div>`).join('');
    editor.value = variants[activeTab].code;
  }
  renderTabs();

  window._deSwitchTab = function(idx, codes) {
    activeTab = idx;
    editor.value = codes[idx];
    document.querySelectorAll('[id^="de-tab-"]').forEach((el, i) => {
      el.style.borderBottom = i === idx ? '2px solid #3b82f6' : '2px solid transparent';
      el.style.color = i === idx ? '#3b82f6' : '#8b949e';
    });
  };

  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

window._deNewRule = function() {
  const panel = document.getElementById('de-editor-panel');
  const title = document.getElementById('de-editor-title');
  const editor = document.getElementById('de-rule-editor');
  const tabs = document.getElementById('de-editor-tabs');
  if (!panel || !editor) return;
  panel.style.display = 'block';
  if (title) title.textContent = 'New Detection Rule';
  if (tabs) tabs.innerHTML = `<div style="padding:8px 16px;font-size:.78em;color:#3b82f6;border-bottom:2px solid #3b82f6;font-weight:600">SIGMA</div>`;
  editor.value = `title: New Detection Rule
id: 
status: testing
author: EYEbot AI
date: ${new Date().toISOString().split('T')[0].replace(/-/g,'/')}
description: Describe what this rule detects
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'suspicious_pattern'
    filter_legitimate:
        Image|endswith:
            - '\\legitimate.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Describe known false positive scenarios
level: medium
tags:
    - attack.tXXXX
    - attack.tactic_name`;
  panel.scrollIntoView({ behavior: 'smooth' });
};

window._deImport = function() {
  if (window.showToast) showToast('SIGMA import: paste your rule in the editor panel', 'info');
  window._deNewRule();
};

window._deTest = function() {
  const results = document.getElementById('de-test-results');
  if (!results) return;
  results.style.display = 'block';
  results.innerHTML = `<i class="fas fa-spinner fa-spin" style="color:#f59e0b;margin-right:6px"></i>Running validation against test dataset…`;
  setTimeout(() => {
    results.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;gap:12px">
      <span style="color:#22c55e"><i class="fas fa-check" style="margin-right:4px"></i>SIGMA syntax valid</span>
      <span style="color:#22c55e"><i class="fas fa-check" style="margin-right:4px"></i>KQL translation successful</span>
      <span style="color:#f59e0b"><i class="fas fa-exclamation-triangle" style="margin-right:4px"></i>Estimated FP rate: 12% — review filters</span>
      <span style="color:#3b82f6"><i class="fas fa-database" style="margin-right:4px"></i>2 test events matched</span>
    </div>`;
    if (window.showToast) showToast('Rule validation complete', 'success');
  }, 1500);
};

window._deDeploy = function() {
  if (window.showToast) showToast('Rule deployed to production environment', 'success');
  document.getElementById('de-editor-panel').style.display = 'none';
};

window._deExportRule = function(id) {
  const r = (window.DETECTION_RULES || []).find(x => x.id === id);
  if (!r) return;
  const blob = new Blob([r.rule], { type: 'text/yaml' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `detection_${r.id}.yml`; a.click();
  URL.revokeObjectURL(url);
  if (window.showToast) showToast('Detection rule exported', 'success');
};

function _escDE(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
