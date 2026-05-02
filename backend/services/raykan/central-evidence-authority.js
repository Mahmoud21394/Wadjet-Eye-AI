/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Central Evidence Authority (CEA) v1.0
 *
 *  The single, immutable gate that ALL ATT&CK technique assignments
 *  must pass before they may appear in any detection, report, or
 *  narrative.  No downstream module (sigma, AI, MITRE-mapper, route
 *  handlers, narrative builders) may override a CEA decision.
 *
 *  Design principles:
 *   1. Deterministic — same input always produces same output.
 *   2. Strict — technique is suppressed unless evidence is positive.
 *   3. Centralised — one source of truth; never duplicated.
 *   4. Auditable — every decision is logged with a reason code.
 *   5. Non-bypassable — enforced at the earliest possible point and
 *      re-enforced at MITRE-mapper output stage as a final guard.
 *
 *  Evidence gates per technique:
 *   • T1190  — Exploit Public-Facing App → web-server telemetry required
 *   • T1021  — Remote Services          → remote-execution evidence required
 *   • T1021.002 — SMB/Admin Shares      → SMB port / PsExec / admin-share path
 *   • T1021.006 — WinRM                 → WinRM process / port 5985-5986
 *   • T1550.002 — Pass-the-Hash         → cross-host NTLM correlation
 *   • T1110   — Brute Force             → ≥3 failed logons (4625)
 *   • T1110.001 — Password Guessing     → ≥3 failed logons
 *   • T1110.003 — Password Spraying     → ≥3 target users across failures
 *   • T1136   — Account Creation        → net user /add or group-add EventID
 *   • T1189   — Drive-by Compromise     → web/proxy telemetry required
 *   • T1071.001 — Web Protocols C2      → network/proxy telemetry
 *   • T1071.004 — DNS C2               → DNS telemetry
 *
 *  Public API:
 *   CEA.validateTechnique(tid, evidence)   → { allowed, reason, alternative }
 *   CEA.validateDetection(detection, ctx)  → detection (tags rewritten)
 *   CEA.validateBatch(detections, events)  → detections[] (FPs removed/adjusted)
 *   CEA.buildEvidence(events, detections)  → EvidenceContext object
 *   CEA.getAuditLog()                      → Array<AuditEntry>
 *   CEA.getMetrics()                       → MetricsObject
 *   CEA.resetAuditLog()                    → void
 *
 *  backend/services/raykan/central-evidence-authority.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
//  HARD EVIDENCE REQUIREMENTS
//  Each entry defines the conditions that MUST be satisfied for the technique
//  to be assigned.  requiresAny: at least one item in the array must be true.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_EVIDENCE_RULES = {

  // ── T1190 — Exploit Public-Facing Application ─────────────────────────────
  // Must have web-server telemetry evidence.
  'T1190': {
    label: 'Exploit Public-Facing Application',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'process_match',  field: 'parentProc',  values: ['w3wp.exe', 'httpd.exe', 'nginx.exe', 'php.exe', 'apache.exe', 'tomcat.exe', 'iisexpress.exe', 'lighttpd.exe'] },
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'iis', 'apache', 'nginx', 'http'] },
      { type: 'field_present',  field: 'url' },
      { type: 'field_present',  field: 'raw.cs-uri-stem' },
      { type: 'field_present',  field: 'raw.cs-method' },
    ],
    suppressedAlternative: null,
    reason: 'T1190 requires web-server process parent or HTTP telemetry',
  },

  // ── T1189 — Drive-by Compromise ───────────────────────────────────────────
  'T1189': {
    label: 'Drive-by Compromise',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'proxy', 'http'] },
      { type: 'field_present',  field: 'url' },
    ],
    suppressedAlternative: null,
    reason: 'T1189 requires web/proxy telemetry',
  },

  // ── T1021 — Remote Services (parent technique) ────────────────────────────
  'T1021': {
    label: 'Remote Services',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['psexec.exe', 'psexec64.exe', 'winrm.cmd', 'wmic.exe', 'mstsc.exe'] },
      { type: 'process_match',  field: 'commandLine', values: ['psexec', '\\\\\\\\', 'winrm', 'wmic /node', 'invoke-command'] },
      { type: 'evidence_flag',  flag: 'multi_host_activity' },
      { type: 'port_match',     ports: ['445', '3389', '5985', '5986', '22'] },
    ],
    suppressedAlternative: null,
    reason: 'T1021 requires concrete remote-service evidence',
  },

  // ── T1021.002 — SMB / Windows Admin Shares ───────────────────────────────
  'T1021.002': {
    label: 'SMB/Windows Admin Shares Lateral Movement',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['psexec.exe', 'psexec64.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['\\\\\\\\', 'admin$', 'ipc$', 'c$', 'd$', 'e$', 'psexec'] },
      { type: 'cmd_contains',   field: 'raw.ShareName',  values: ['admin$', 'ipc$', 'c$'] },
      { type: 'cmd_contains',   field: 'raw.ObjectName', values: ['\\\\admin$', '\\\\c$', '\\\\ipc$'] },
      { type: 'port_match',     ports: ['445'] },
      { type: 'evidence_flag',  flag: 'multi_host_activity' },
    ],
    suppressedAlternative: null,
    reason: 'T1021.002 requires SMB/admin-share evidence — LogonType=3 alone is insufficient',
  },

  // ── T1021.001 — Remote Desktop Protocol ──────────────────────────────────
  'T1021.001': {
    label: 'Remote Desktop Protocol',
    requiresAny: [
      { type: 'process_match',  field: 'process',  values: ['mstsc.exe', 'rdpclip.exe', 'tstheme.exe'] },
      { type: 'port_match',     ports: ['3389'] },
      { type: 'logon_type',     types: ['10'] }, // RemoteInteractive
    ],
    suppressedAlternative: null,
    reason: 'T1021.001 requires RDP process or port 3389',
  },

  // ── T1021.006 — Windows Remote Management ────────────────────────────────
  'T1021.006': {
    label: 'Windows Remote Management',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['wsmprovhost.exe', 'winrm.cmd'] },
      { type: 'process_match',  field: 'parentProc', values: ['wsmprovhost.exe'] },
      { type: 'port_match',     ports: ['5985', '5986'] },
      { type: 'channel_match',  channels: ['microsoft-windows-winrm/operational'] },
    ],
    suppressedAlternative: null,
    reason: 'T1021.006 requires WinRM process/port evidence',
  },

  // ── T1550.002 — Pass-the-Hash ─────────────────────────────────────────────
  // LogonType=3 + NTLM alone is NEVER sufficient; requires cross-host evidence
  'T1550.002': {
    label: 'Pass-the-Hash',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'cross_host_ntlm_logon' },
      { type: 'cmd_contains',   field: 'commandLine', values: ['sekurlsa::pth', '-pth', 'wce -s', 'pass.*hash', 'ntlm.*hash', 'pth-winexe', 'mimikatz'] },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1550.002 (PtH) requires cross-host NTLM evidence; single-host LogonType=3+NTLM → T1078',
  },

  // ── T1110 — Brute Force ───────────────────────────────────────────────────
  'T1110': {
    label: 'Brute Force',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_4625_events' },      // Windows
      { type: 'evidence_flag',  flag: 'multiple_ssh_failures' },     // Linux SSH
      { type: 'cmd_contains',   field: 'commandLine', values: ['hydra', 'medusa', 'ncrack', 'crowbar', '-password', '-spray'] },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110 requires ≥3 failed logon events (Windows 4625 or Linux SSH); single failure → T1078',
  },

  // ── T1110.001 — Password Guessing ─────────────────────────────────────────
  'T1110.001': {
    label: 'Password Guessing',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_4625_events' },      // Windows
      { type: 'evidence_flag',  flag: 'multiple_ssh_failures' },     // Linux SSH
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110.001 requires multiple (≥3) failed logon events (Windows 4625 or Linux SSH)',
  },

  // ── T1110.003 — Password Spraying ─────────────────────────────────────────
  'T1110.003': {
    label: 'Password Spraying',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_target_users' },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110.003 requires ≥3 distinct target usernames across failures',
  },

  // ── T1136 — Account Creation ──────────────────────────────────────────────
  'T1136': {
    label: 'Account Creation',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['net user', 'net localgroup', '/add', 'useradd', 'New-LocalUser', 'Add-LocalGroupMember'] },
      { type: 'event_id',       ids: ['4720', '4722', '4728', '4732', '4756'] },
    ],
    suppressedAlternative: null,
    reason: 'T1136 requires account-creation command or Windows account-management EventID',
  },

  // ── T1136.001 — Local Account ─────────────────────────────────────────────
  'T1136.001': {
    label: 'Create Local Account',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['net user', '/add', 'useradd', 'New-LocalUser'] },
      { type: 'event_id',       ids: ['4720'] },
    ],
    suppressedAlternative: null,
    reason: 'T1136.001 requires local account-creation command or EventID 4720',
  },

  // ── T1071.001 — Web Protocols (C2) ────────────────────────────────────────
  'T1071.001': {
    label: 'Application Layer Protocol: Web Protocols',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network_connection', 'proxy', 'web', 'http'] },
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'port_match',     ports: ['80', '443', '8080', '8443'] },
    ],
    suppressedAlternative: null,
    reason: 'T1071.001 requires network/proxy telemetry or HTTP port evidence',
  },

  // ── T1071.004 — DNS (C2) ──────────────────────────────────────────────────
  'T1071.004': {
    label: 'Application Layer Protocol: DNS',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['dns', 'network_connection'] },
      { type: 'field_present',  field: 'domain' },
    ],
    suppressedAlternative: null,
    reason: 'T1071.004 requires DNS or network telemetry',
  },

  // ═══════════════════════════════════════════════════════════════════
  //  LINUX / UNIX TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════

  // ── T1110 (Linux) — SSH Brute Force ──────────────────────────────────────
  // Already defined for Windows; extend via evidence_flag (multi-platform)

  // ── T1021.004 — SSH Lateral Movement ─────────────────────────────────────
  'T1021.004': {
    label: 'Remote Services: SSH',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'ssh_lateral_movement' },
      { type: 'evidence_flag',  flag: 'multi_host_activity' },
      { type: 'logsource_cat',  categories: ['linux', 'syslog', 'auth', 'ssh'] },
      { type: 'process_match',  field: 'process',    values: ['ssh','sshd','openssh','putty','plink'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['ssh ', '-i ', 'StrictHostKeyChecking', 'ssh-agent'] },
      { type: 'port_match',     ports: ['22'] },
    ],
    suppressedAlternative: null,
    reason: 'T1021.004 requires SSH process, port 22, or Linux/SSH telemetry',
  },

  // ── T1059.004 — Unix Shell ────────────────────────────────────────────────
  'T1059.004': {
    label: 'Command and Scripting Interpreter: Unix Shell',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['linux', 'syslog', 'auditd', 'auth'] },
      { type: 'process_match',  field: 'process',    values: ['bash','sh','zsh','ksh','csh','tcsh','dash','fish'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['/bin/sh','/bin/bash','/usr/bin/','/etc/'] },
      { type: 'evidence_flag',  flag: 'has_linux_events' },
    ],
    suppressedAlternative: null,
    reason: 'T1059.004 requires Unix/Linux shell process or Linux telemetry',
  },

  // ── T1548.001 — Setuid/Setgid ─────────────────────────────────────────────
  'T1548.001': {
    label: 'Abuse Elevation Control: Setuid and Setgid',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['linux', 'auditd'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['chmod +s', 'chmod u+s', 'setuid', 'setgid', 'chmod 4', 'chmod 6'] },
      { type: 'evidence_flag',  flag: 'has_linux_events' },
    ],
    suppressedAlternative: null,
    reason: 'T1548.001 requires Linux/auditd telemetry or setuid command',
  },

  // ── T1053.003 — Cron ─────────────────────────────────────────────────────
  'T1053.003': {
    label: 'Scheduled Task/Job: Cron',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['linux', 'syslog', 'auditd', 'cron'] },
      { type: 'process_match',  field: 'process',    values: ['cron','crond','crontab','at','atd'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['crontab','cron.d','cron.daily','cron.hourly','at '] },
      { type: 'evidence_flag',  flag: 'has_linux_events' },
    ],
    suppressedAlternative: null,
    reason: 'T1053.003 requires Linux cron telemetry or crontab command',
  },

  // ── T1078.003 — Local Accounts (Linux) ───────────────────────────────────
  'T1078.003': {
    label: 'Valid Accounts: Local Accounts',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'linux_auth_success' },
      { type: 'evidence_flag',  flag: 'linux_ssh_success' },
      { type: 'logsource_cat',  categories: ['linux', 'syslog', 'auth'] },
      { type: 'cmd_contains',   field: 'message', values: ['Accepted password','Accepted publickey','session opened'] },
    ],
    suppressedAlternative: null,
    reason: 'T1078.003 requires Linux authentication telemetry',
  },

  // ── T1098 — Account Manipulation (Linux) ─────────────────────────────────
  'T1098': {
    label: 'Account Manipulation',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['usermod','chage','passwd','visudo','sudoers','ssh-copy-id'] },
      { type: 'cmd_contains',   field: 'message',     values: ['usermod','chage','visudo'] },
      { type: 'event_id',       ids: ['4738','4781','4782','4740'] },
      { type: 'logsource_cat',  categories: ['linux', 'auditd'] },
    ],
    suppressedAlternative: null,
    reason: 'T1098 requires account manipulation command or telemetry',
  },

  // ── T1562.001 — Disable Security Tools (Linux) ───────────────────────────
  'T1562.001': {
    label: 'Impair Defenses: Disable or Modify Tools',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: [
          'setenforce 0','systemctl stop auditd','service iptables stop',
          'ufw disable','iptables -F','chkconfig --off','systemctl disable',
          'Set-MpPreference -DisableRealtimeMonitoring','sc stop','net stop',
          'bcdedit /set','wbadmin delete',
        ]
      },
      { type: 'event_id',       ids: ['4689','1102'] },
    ],
    suppressedAlternative: null,
    reason: 'T1562.001 requires concrete security-tool-disable command',
  },

  // ═══════════════════════════════════════════════════════════════════
  //  FIREWALL / NETWORK TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════

  // ── T1046 — Network Service Scanning ─────────────────────────────────────
  'T1046': {
    label: 'Network Service Scanning',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network', 'firewall', 'netflow', 'zeek'] },
      { type: 'evidence_flag',  flag: 'has_network_scan' },
      { type: 'cmd_contains',   field: 'commandLine', values: ['nmap','masscan','zmap','nessus','-sV','-sS','-sT','--scan-delay'] },
      { type: 'evidence_flag',  flag: 'port_scan_detected' },
    ],
    suppressedAlternative: null,
    reason: 'T1046 requires network scan telemetry or scanner tool evidence',
  },

  // ── T1498 — Network Denial of Service ────────────────────────────────────
  'T1498': {
    label: 'Network Denial of Service',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network', 'firewall', 'netflow'] },
      { type: 'evidence_flag',  flag: 'high_volume_traffic' },
      { type: 'evidence_flag',  flag: 'connection_rate_spike' },
    ],
    suppressedAlternative: null,
    reason: 'T1498 requires network flow or firewall telemetry showing high volume',
  },

  // ── T1572 — Protocol Tunneling ────────────────────────────────────────────
  'T1572': {
    label: 'Protocol Tunneling',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network', 'firewall', 'dns', 'proxy'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['iodine','dnscat','icmptunnel','ptunnel','chisel','ngrok','cloudflared'] },
      { type: 'evidence_flag',  flag: 'dns_tunneling_detected' },
    ],
    suppressedAlternative: null,
    reason: 'T1572 requires tunneling tool evidence or network telemetry',
  },

  // ── T1048 — Exfiltration Over Alternative Protocol ───────────────────────
  'T1048': {
    label: 'Exfiltration Over Alternative Protocol',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network', 'firewall', 'proxy', 'dns'] },
      { type: 'evidence_flag',  flag: 'high_outbound_data' },
      { type: 'cmd_contains',   field: 'commandLine', values: ['scp ','sftp ','ftp ','curl ','wget ','nc ','ncat ','openssl s_client'] },
    ],
    suppressedAlternative: null,
    reason: 'T1048 requires network/firewall telemetry or exfil tool evidence',
  },

  // ── T1040 — Network Sniffing ──────────────────────────────────────────────
  'T1040': {
    label: 'Network Sniffing',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['tcpdump','wireshark','tshark','windump','networkminer','pktmon','netsh trace'] },
      { type: 'process_match',  field: 'process',    values: ['tcpdump','wireshark','tshark','windump','networkMiner'] },
    ],
    suppressedAlternative: null,
    reason: 'T1040 requires packet-capture tool evidence',
  },

  // ═══════════════════════════════════════════════════════════════════
  //  WEB SERVER / APPLICATION TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════

  // ── T1505.003 — Web Shell ─────────────────────────────────────────────────
  'T1505.003': {
    label: 'Server Software Component: Web Shell',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'has_web_parent_process' },
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'iis', 'apache', 'nginx'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['cmd.exe','powershell','/bin/sh','/bin/bash','whoami','net user'] },
      { type: 'process_match',  field: 'parentProc',  values: ['w3wp.exe','httpd','nginx','php','apache','tomcat'] },
    ],
    suppressedAlternative: null,
    reason: 'T1505.003 requires web-server parent process or web telemetry',
  },

  // ── T1190.001 — SQL Injection (sub-technique, mapped via T1190) ──────────
  // T1190 is the parent — same requirements apply

  // ── T1059.007 — JavaScript / Web Scripts ─────────────────────────────────
  'T1059.007': {
    label: 'Command and Scripting Interpreter: JavaScript',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'proxy'] },
      { type: 'process_match',  field: 'process',    values: ['node','nodejs','wscript.exe','cscript.exe','mshta.exe','jscript'] },
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
    ],
    suppressedAlternative: null,
    reason: 'T1059.007 requires web/script engine process or web telemetry',
  },

  // ═══════════════════════════════════════════════════════════════════
  //  DATABASE TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════

  // ── T1190 (DB variant) — SQL Injection via DB logs ────────────────────────
  // Handled by T1190 above — add db_evidence_flag support

  // ── T1005 — Data from Local System (Database Exfil) ──────────────────────
  'T1005': {
    label: 'Data from Local System',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['database', 'mssql', 'mysql', 'postgresql'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['SELECT ','DUMP ','backup','mysqldump','pg_dump','bcp ','sqlcmd','BULK INSERT'] },
      { type: 'evidence_flag',  flag: 'has_database_exfil' },
    ],
    suppressedAlternative: null,
    reason: 'T1005 requires database telemetry or data-export command',
  },

  // ── T1213 — Data from Information Repositories ────────────────────────────
  'T1213': {
    label: 'Data from Information Repositories',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['database', 'mssql', 'mysql', 'postgresql'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['SELECT ','UNION SELECT','FROM ','WHERE '] },
      { type: 'evidence_flag',  flag: 'has_database_events' },
    ],
    suppressedAlternative: null,
    reason: 'T1213 requires database query telemetry',
  },

  // ── T1078.001 — Default Accounts ─────────────────────────────────────────
  'T1078.001': {
    label: 'Valid Accounts: Default Accounts',
    requiresAny: [
      { type: 'cmd_contains',   field: 'user',    values: ['sa','admin','root','postgres','mysql','oracle','guest','administrator'] },
      { type: 'cmd_contains',   field: 'dstUser', values: ['sa','admin','root','postgres','mysql','oracle'] },
      { type: 'event_id',       ids: ['4624','4625'] }, // combined with default username check
      { type: 'evidence_flag',  flag: 'default_account_logon' },
    ],
    suppressedAlternative: null,
    reason: 'T1078.001 requires evidence of default account usage',
  },

  // ── T1190 (enhanced) — add database parent indicator ─────────────────────
  // (T1190 already defined above; database variant covered by domain classifier)

  // ═══════════════════════════════════════════════════════════════════
  //  CROSS-PLATFORM / COMMON TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════

  // ── T1059.001 — PowerShell ────────────────────────────────────────────────
  'T1059.001': {
    label: 'Command and Scripting Interpreter: PowerShell',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['powershell.exe','pwsh.exe','powershell_ise'] },
      { type: 'process_match',  field: 'parentProc', values: ['powershell.exe','pwsh.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['powershell','pwsh','-encodedcommand','-enc ','invoke-expression','iex ','downloadstring','webclient'] },
    ],
    suppressedAlternative: null,
    reason: 'T1059.001 requires PowerShell process or command-line evidence',
  },

  // ── T1055 — Process Injection ─────────────────────────────────────────────
  'T1055': {
    label: 'Process Injection',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['process_creation', 'windows'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['inject','shellcode','VirtualAlloc','CreateRemoteThread','WriteProcessMemory'] },
      { type: 'event_id',       ids: ['10','8'] }, // Sysmon process access / create_remote_thread
      { type: 'evidence_flag',  flag: 'process_injection_indicator' },
    ],
    suppressedAlternative: null,
    reason: 'T1055 requires process injection telemetry (Sysmon EventID 10/8 or injection command)',
  },

  // ── T1003 — OS Credential Dumping (parent) ────────────────────────────────
  'T1003': {
    label: 'OS Credential Dumping',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['mimikatz','lsass','procdump','wce.exe','fgdump','gsecdump','pwdump'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['sekurlsa','lsadump','mimikatz','procdump -ma lsass','wce -s','fgdump'] },
      { type: 'event_id',       ids: ['4656','4663','10'] }, // Object access / Sysmon LSASS
    ],
    suppressedAlternative: null,
    reason: 'T1003 requires credential-dumping tool process or LSASS access event',
  },

  // ── T1003.001 — LSASS Memory ──────────────────────────────────────────────
  'T1003.001': {
    label: 'OS Credential Dumping: LSASS Memory',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['mimikatz.exe','procdump.exe','wce.exe','lsass.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['sekurlsa::logonpasswords','procdump.*lsass','lsass.dmp','minidump'] },
      { type: 'event_id',       ids: ['10'] }, // Sysmon process access
      { type: 'evidence_flag',  flag: 'lsass_access_detected' },
    ],
    suppressedAlternative: null,
    reason: 'T1003.001 requires LSASS access via Sysmon EID 10 or dumping tool',
  },

  // ── T1486 — Data Encrypted for Impact (Ransomware) ───────────────────────
  'T1486': {
    label: 'Data Encrypted for Impact',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['vssadmin','wbadmin','bcdedit','cipher /w','openssl enc','gpg --encrypt'] },
      { type: 'evidence_flag',  flag: 'ransomware_extensions_detected' },
      { type: 'evidence_flag',  flag: 'shadow_copy_deletion' },
    ],
    suppressedAlternative: null,
    reason: 'T1486 requires encryption/shadow-copy command or ransomware extension evidence',
  },

  // ── T1490 — Inhibit System Recovery ──────────────────────────────────────
  'T1490': {
    label: 'Inhibit System Recovery',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['vssadmin delete shadows','wbadmin delete','bcdedit /set {default} recoveryenabled no','sdelete','wmic shadowcopy delete'] },
      { type: 'evidence_flag',  flag: 'shadow_copy_deletion' },
    ],
    suppressedAlternative: null,
    reason: 'T1490 requires shadow-copy deletion or system-recovery inhibit command',
  },

  // ── T1047 — Windows Management Instrumentation ────────────────────────────
  'T1047': {
    label: 'Windows Management Instrumentation',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['wmic.exe','wmiprvse.exe','wmiapsrv.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['wmic','Invoke-WmiMethod','Get-WmiObject','wmiexec','Win32_Process'] },
    ],
    suppressedAlternative: null,
    reason: 'T1047 requires WMI process or command evidence',
  },

  // ── T1053.005 — Scheduled Task (Windows) ─────────────────────────────────
  'T1053.005': {
    label: 'Scheduled Task/Job: Scheduled Task',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['schtasks.exe','taskschd.msc','at.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['schtasks','Register-ScheduledTask','/create','/sc ','/tr '] },
      { type: 'event_id',       ids: ['4698','4699','4700','4701','4702'] },
    ],
    suppressedAlternative: null,
    reason: 'T1053.005 requires schtasks command or scheduled-task EventID',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  INVALID TECHNIQUE → LOGSOURCE COMBINATIONS
//  Technique CANNOT be assigned when the ONLY evidence is from these sources.
//  This blocks auto-generated rules that match authentication events (4624/4625)
//  for web/lateral-movement techniques.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_BLOCKED_SOURCES = {
  // Web techniques must never fire on pure Windows auth events
  'T1190': {
    blockedEventIds:   new Set(['4624', '4625', '4626', '4627', '4648', '4768', '4769', '4776']),
    blockedLogsources: new Set(['security', 'system', 'application']),
    description: 'Web exploitation techniques must not match Windows authentication events',
    exceptWhen: ['has_webserver_logs', 'has_web_parent_process', 'sqli_patterns_detected'],
  },
  'T1189': {
    blockedEventIds:   new Set(['4624', '4625', '4648', '4768', '4769']),
    blockedLogsources: new Set(['security', 'system', 'application']),
    description: 'Drive-by technique must not match Windows authentication events',
    exceptWhen: ['has_webserver_logs'],
  },
  // Lateral movement techniques must not fire on pure Windows auth events without supporting evidence
  // Note: exceptions include psexec/admin$ presence which overrides the blocked source check
  // via the evidence requirement gate (Gate 2), which runs after Gate 0.
  // Gate 0 only blocks when there is NO additional SMB evidence on the event itself.
  // We deliberately do NOT block T1021.002 on 4624 here — that is handled by Gate 2
  // (the evidence requirement gate), which correctly evaluates process_match for psexec.exe.
  // 'T1021.002': { ... } — REMOVED from blocked sources; handled entirely by Gate 2 evidence rules

  // SSH lateral movement must not fire on Windows events
  'T1021.004': {
    blockedEventIds:   new Set(['4624', '4625', '4648', '4768', '4769']),
    blockedLogsources: new Set(['security']),
    description: 'SSH lateral movement must not fire on Windows authentication events',
    exceptWhen: ['has_linux_events', 'ssh_lateral_movement'],
  },
  // Linux techniques must not fire on Windows events
  'T1059.004': {
    blockedEventIds:   new Set(['4624', '4625', '4688', '4689']),
    blockedLogsources: new Set(['security', 'system']),
    description: 'Unix shell technique must not fire on Windows events',
    exceptWhen: ['has_linux_events'],
  },
  // Cron must not fire on Windows events
  'T1053.003': {
    blockedEventIds:   new Set(['4624', '4625', '4688', '4698', '4699']),
    blockedLogsources: new Set(['security', 'system']),
    description: 'Linux cron technique must not fire on Windows events',
    exceptWhen: ['has_linux_events'],
  },
  // Database techniques must not fire on Windows auth/process events
  'T1005': {
    blockedEventIds:   new Set(['4624', '4625', '4688']),
    blockedLogsources: new Set(['security']),
    description: 'Database data access must not fire on Windows auth events',
    exceptWhen: ['has_database_events', 'has_database_exfil'],
  },
  'T1213': {
    blockedEventIds:   new Set(['4624', '4625', '4688']),
    blockedLogsources: new Set(['security']),
    description: 'Data from repositories must not fire on Windows auth events',
    exceptWhen: ['has_database_events'],
  },
};

// Auth-event IDs that indicate normal logon activity (not lateral movement alone)
const AUTH_ONLY_EVENT_IDS = new Set(['4624', '4625', '4626', '4627', '4634', '4647', '4648',
                                      '4720', '4726', '4728', '4732', '4756', '4768', '4769', '4776']);

// ─────────────────────────────────────────────────────────────────────────────
//  KEYWORD-BASED RULE DETECTION
//  Rules that use keyword selectors matching technique names are unreliable.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_KEYWORD_PATTERNS = [
  /exploit.public.facing/i, /t1190/i,
  /smb.windows.admin/i,     /t1021\.002/i,
  /pass.the.hash/i,         /t1550\.002/i,
  /brute.force/i,           /t1110/i,
  /lateral.movement/i,
];

function isKeywordOnlyRule(rule) {
  const det = rule.detection || {};
  const sel = det.selection || {};
  // Rule uses only keyword-based detection (no field matching)
  if (sel.keywords != null && Object.keys(sel).every(k => k === 'keywords' || k === 'condition')) {
    return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVIDENCE CONTEXT
//  Derived from the event batch — computed ONCE per ingest call and passed
//  to all technique evaluations.
// ─────────────────────────────────────────────────────────────────────────────
class EvidenceContext {
  constructor(events = [], detections = []) {
    this._events     = Array.isArray(events)     ? events     : [];
    this._detections = Array.isArray(detections) ? detections : [];
    this._flags      = null; // lazy
  }

  get flags() {
    if (!this._flags) this._flags = this._buildFlags();
    return this._flags;
  }

  hasFlag(flag) { return !!this.flags[flag]; }

  _buildFlags() {
    const flags = {};
    const evts = this._events;

    // 4625 / 4624 event counts
    const failures  = evts.filter(e => String(e.eventId || e.raw?.EventID) === '4625');
    const successes = evts.filter(e => String(e.eventId || e.raw?.EventID) === '4624');

    flags.multiple_4625_events = failures.length >= 3;
    flags.has_4624_success     = successes.length > 0;

    // Multiple target users (password spray)
    const targetUsers = new Set(
      failures.map(e => (e.raw?.TargetUserName || e.user || '').toLowerCase()).filter(Boolean)
    );
    flags.multiple_target_users = targetUsers.size >= 3;

    // Multi-host: ≥2 distinct computers OR sourceHost/targetHost cross-host signals
    // FIX #3: also detect sourceHost/targetHost EDR-style lateral movement fields
    const computers = new Set(evts.map(e => (e.computer || e.raw?.Computer || '').toLowerCase()).filter(Boolean));
    const eventArr  = evts; // alias for clarity in the lambda below
    flags.multi_host_activity =
      computers.size >= 2 ||
      eventArr.some(e => e.sourceHost && e.targetHost && e.sourceHost !== e.targetHost);

    // Web-server telemetry
    flags.has_webserver_logs = evts.some(e => {
      const src  = (e.source || '').toLowerCase();
      const fmt  = (e.format || '').toLowerCase();
      const chan  = (e.channel || e.raw?.Channel || '').toLowerCase();
      return src.includes('web') || src.includes('iis') || src.includes('apache') ||
             src.includes('nginx') || src.includes('http') ||
             fmt === 'webserver' ||
             chan.includes('w3svc') || chan.includes('httpd') ||
             e.url != null || e.raw?.['cs-uri-stem'] != null || e.raw?.['cs-method'] != null;
    });

    // Web-server as parent process (for web-shell detection)
    flags.has_web_parent_process = evts.some(e => {
      const pp = (e.parentProc || e.raw?.ParentImage || '').toLowerCase();
      return /w3wp|httpd|nginx|php|apache|tomcat|iisexpress|lighttpd/.test(pp);
    });

    // Cross-host NTLM logons (PtH indicator)
    const ntlmLogons = successes.filter(e => {
      const lt = String(e.raw?.LogonType || e.logonType || '');
      const ap = (e.raw?.AuthPackage || e.raw?.AuthenticationPackageName || '').toUpperCase();
      return lt === '3' && ap === 'NTLM';
    });
    if (ntlmLogons.length > 0) {
      const ntlmComputers = new Set(ntlmLogons.map(e => (e.computer || e.raw?.Computer || '').toLowerCase()).filter(Boolean));
      const ntlmSrcIps    = new Set(ntlmLogons.map(e => (e.srcIp || e.raw?.IpAddress || '').toLowerCase()).filter(v => v && v !== '-' && v !== '127.0.0.1' && v !== '::1'));
      flags.cross_host_ntlm_logon = ntlmComputers.size >= 2 || ntlmSrcIps.size >= 2;
    } else {
      flags.cross_host_ntlm_logon = false;
    }

    // ── Linux / SSH flags ─────────────────────────────────────────────────
    const linuxEvts = evts.filter(e => {
      const src  = (e.source  || '').toLowerCase();
      const fmt  = (e.format  || '').toLowerCase();
      const prog = (e.program || e.raw?.program || e.raw?.appname || '').toLowerCase();
      return fmt === 'syslog' || fmt === 'linux' ||
             src.includes('auth.log') || src.includes('secure') || src.includes('/var/log') ||
             /sshd|sudo|cron|auditd|pam_unix|useradd/.test(prog) ||
             e._meta?.domain === 'linux';
    });
    flags.has_linux_events = linuxEvts.length > 0;

    // SSH brute-force: ≥3 'Failed password' syslog entries
    const sshFailures = linuxEvts.filter(e => {
      const msg = (e.message || e.raw?.message || '').toLowerCase();
      return msg.includes('failed password') || msg.includes('invalid user') || msg.includes('authentication failure');
    });
    flags.multiple_ssh_failures = sshFailures.length >= 3;

    // SSH success
    flags.linux_ssh_success = linuxEvts.some(e => {
      const msg = (e.message || e.raw?.message || '').toLowerCase();
      return msg.includes('accepted password') || msg.includes('accepted publickey');
    });
    flags.linux_auth_success = flags.linux_ssh_success;

    // SSH lateral movement: success across multiple source IPs
    if (flags.linux_ssh_success) {
      const sshSuccesses  = linuxEvts.filter(e => {
        const msg = (e.message || e.raw?.message || '').toLowerCase();
        return msg.includes('accepted');
      });
      const sshSrcIps = new Set(sshSuccesses.map(e => (e.srcIp || e.raw?.IpAddress || '')).filter(v => v && v !== '127.0.0.1'));
      flags.ssh_lateral_movement = sshSrcIps.size >= 2;
    } else {
      flags.ssh_lateral_movement = false;
    }

    // ── Firewall / Network flags ──────────────────────────────────────────
    const fwEvts = evts.filter(e => {
      const src = (e.source || '').toLowerCase();
      const fmt = (e.format || '').toLowerCase();
      const eid = String(e.eventId || e.raw?.EventID || '');
      return fmt === 'firewall' || fmt === 'cef_firewall' ||
             /firewall|iptables|asa|fortigate|paloalto/.test(src) ||
             ['5152','5153','5154','5155','5156','5157','5158','5159'].includes(eid) ||
             e._meta?.domain === 'firewall';
    });
    flags.has_firewall_logs = fwEvts.length > 0;

    // Port scan: ≥5 distinct destination ports from same source in firewall logs
    if (fwEvts.length >= 5) {
      const portsByIp = {};
      fwEvts.forEach(e => {
        const src  = (e.srcIp || e.raw?.src_ip || e.raw?.IpAddress || '').toLowerCase();
        const port = String(e.dstPort || e.raw?.dst_port || e.raw?.DestinationPort || '');
        if (src && port) {
          if (!portsByIp[src]) portsByIp[src] = new Set();
          portsByIp[src].add(port);
        }
      });
      flags.port_scan_detected = Object.values(portsByIp).some(s => s.size >= 5);
      flags.has_network_scan   = flags.port_scan_detected;
    }

    // High outbound data (exfiltration indicator)
    const outboundBytes = fwEvts.reduce((sum, e) => {
      const b = parseInt(e.raw?.bytes_sent || e.raw?.BytesSent || e.raw?.['sc-bytes'] || '0', 10);
      return sum + (isNaN(b) ? 0 : b);
    }, 0);
    flags.high_outbound_data = outboundBytes > 100_000_000; // 100MB threshold

    // ── Web server flags ──────────────────────────────────────────────────
    const webEvts = evts.filter(e => {
      const src = (e.source || '').toLowerCase();
      const fmt = (e.format || '').toLowerCase();
      return fmt === 'web' || fmt === 'webserver' || fmt === 'iis' || fmt === 'apache' || fmt === 'nginx' ||
             /apache|nginx|iis|httpd|lighttpd/.test(src) ||
             e.url != null || e.raw?.['cs-uri-stem'] != null || e.raw?.['cs-method'] != null ||
             e._meta?.domain === 'web';
    });
    // has_webserver_logs already set above; update with domain-aware check
    if (webEvts.length > 0) flags.has_webserver_logs = true;

    // SQL injection patterns in web logs
    flags.sqli_patterns_detected = webEvts.some(e => {
      const uri = (e.url || e.uri || e.raw?.['cs-uri-stem'] || e.raw?.RequestURI || '').toLowerCase();
      const qs  = (e.raw?.['cs-uri-query'] || e.raw?.QueryString || '').toLowerCase();
      return /union.select|or.1=1|and.1=0|sleep\(|benchmark\(|xp_cmdshell|load_file/i.test(uri + qs);
    });

    // ── Database flags ────────────────────────────────────────────────────
    const dbEvts = evts.filter(e => {
      const src = (e.source || '').toLowerCase();
      return /mysql|postgresql|mssql|sqlserver|oracle|mongodb|mariadb/.test(src) ||
             e.raw?.query != null || e.raw?.sql_statement != null ||
             e._meta?.domain === 'database';
    });
    flags.has_database_events = dbEvts.length > 0;

    // Database exfil: large SELECT or bulk dump command
    flags.has_database_exfil = dbEvts.some(e => {
      const q = (e.raw?.query || e.raw?.sql_statement || e.commandLine || '').toLowerCase();
      return /select.+into|bulk\s+insert|mysqldump|pg_dump|bcp |sqlcmd/.test(q);
    });

    // Default account logon
    const defaultAccounts = new Set(['sa','administrator','root','postgres','mysql','oracle','guest','admin']);
    flags.default_account_logon = evts.some(e => {
      const u = (e.user || e.raw?.TargetUserName || e.raw?.username || '').toLowerCase();
      return defaultAccounts.has(u);
    });

    // ── Ransomware / Impact flags ─────────────────────────────────────────
    const RANSOMWARE_EXTS = /\.(locked|encrypted|enc|crypt|crypto|cerber|locky|wannacry|petya|zzzzz|vvvv|thor|micro|osiris|zepto|crypted)$/i;
    flags.ransomware_extensions_detected = evts.some(e => {
      const path = (e.raw?.TargetFilename || e.raw?.FileName || e.commandLine || '').toLowerCase();
      return RANSOMWARE_EXTS.test(path);
    });

    flags.shadow_copy_deletion = evts.some(e => {
      const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
      return /vssadmin.*delete|wbadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled/.test(cmd);
    });

    // ── Process injection indicator ───────────────────────────────────────
    flags.process_injection_indicator = evts.some(e => {
      const eid = String(e.eventId || e.raw?.EventID || '');
      const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
      return eid === '10' || eid === '8' || /virtualalloc|createremotethread|writeprocessmemory|inject/i.test(cmd);
    });

    // ── LSASS access ──────────────────────────────────────────────────────
    flags.lsass_access_detected = evts.some(e => {
      const eid     = String(e.eventId || e.raw?.EventID || '');
      const target  = (e.raw?.TargetImage || e.raw?.CallTrace || '').toLowerCase();
      const cmd     = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
      return (eid === '10' && target.includes('lsass')) ||
             /lsass\.dmp|procdump.*lsass|sekurlsa/.test(cmd);
    });

    return flags;
  }

  // Convenience: check if a single event has a web-server parent process
  static eventHasWebParent(evt) {
    const pp = (evt?.parentProc || evt?.raw?.ParentImage || '').toLowerCase();
    return /w3wp|httpd|nginx|php|apache|tomcat|iisexpress|lighttpd/.test(pp);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  AUDIT LOG  (ring buffer, max 10 000 entries)
// ─────────────────────────────────────────────────────────────────────────────
const MAX_AUDIT_ENTRIES = 10_000;
const _auditLog = [];
const _metrics  = {
  total_evaluated    : 0,
  allowed            : 0,
  suppressed         : 0,
  downgraded         : 0,
  blocked_source     : 0,
  keyword_blocked    : 0,
  fp_reason_breakdown: {},
};

function _audit(entry) {
  if (_auditLog.length >= MAX_AUDIT_ENTRIES) _auditLog.shift();
  _auditLog.push({ ts: new Date().toISOString(), ...entry });
}

function _trackMetric(key, reason) {
  _metrics[key] = (_metrics[key] || 0) + 1;
  _metrics.total_evaluated++;
  if (reason) {
    _metrics.fp_reason_breakdown[reason] = (_metrics.fp_reason_breakdown[reason] || 0) + 1;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CORE: validateTechnique
//  Evaluates a single technique against evidence context and optional event.
//
//  @param {string}  tid            — ATT&CK technique ID (e.g. 'T1190')
//  @param {Object}  evidenceCtx    — EvidenceContext instance
//  @param {Object}  [event]        — normalized event (optional)
//  @param {Object}  [detection]    — detection object (optional — for logsource)
//  @param {Object}  [ruleCtx]      — { logsource, ruleId } for logsource checks
//  @returns {{ allowed: boolean, reason: string, alternative: string|null }}
// ─────────────────────────────────────────────────────────────────────────────
function validateTechnique(tid, evidenceCtx, event = {}, detection = {}, ruleCtx = {}) {
  const rules = TECHNIQUE_EVIDENCE_RULES[tid];
  const evt   = event || {};
  const raw   = evt.raw || {};

  // ── Gate 0: Blocked source check ──────────────────────────────────────────
  // Certain technique/EventID combinations are absolutely invalid.
  const blockedSrc = TECHNIQUE_BLOCKED_SOURCES[tid];
  if (blockedSrc) {
    const evtId       = String(evt.eventId || raw.EventID || '');
    const ruleService = (ruleCtx.logsource?.service || detection.logsource?.service || '').toLowerCase();
    const isBlockedId = evtId && blockedSrc.blockedEventIds.has(evtId);
    const isBlockedLS = ruleService && blockedSrc.blockedLogsources.has(ruleService);

    if (isBlockedId || isBlockedLS) {
      // Check exceptions
      const exceptionSatisfied = (blockedSrc.exceptWhen || []).some(f => evidenceCtx.hasFlag(f));
      if (!exceptionSatisfied) {
        const reason = `${tid} blocked: ${blockedSrc.description} (eventId=${evtId}, logsource=${ruleService})`;
        _audit({ tid, decision: 'blocked_source', reason, ruleId: ruleCtx.ruleId || detection.ruleId });
        _trackMetric('blocked_source', `blocked_source:${tid}`);
        return { allowed: false, reason, alternative: null };
      }
    }
  }

  // ── Gate 1: Keyword-only rule check ───────────────────────────────────────
  // Keyword rules matching technique names produce too many FPs.
  if (ruleCtx.isKeywordRule) {
    const reason = `${tid} blocked: keyword-only detection rule (no field matching)`;
    _audit({ tid, decision: 'keyword_blocked', reason, ruleId: ruleCtx.ruleId || detection.ruleId });
    _trackMetric('keyword_blocked', `keyword_rule:${tid}`);
    return { allowed: false, reason, alternative: null };
  }

  // ── Gate 2: Evidence requirement check ────────────────────────────────────
  if (!rules) {
    // No evidence requirements defined — allow through
    _trackMetric('allowed', null);
    return { allowed: true, reason: `${tid} has no CEA evidence requirements — allowed`, alternative: null };
  }

  const satisfied = rules.requiresAny.some(req => _checkEvidenceReq(req, evidenceCtx, evt, raw, detection, ruleCtx));

  if (!satisfied) {
    const reason = rules.reason;
    const alt    = rules.suppressedAlternative;
    _audit({ tid, decision: alt ? 'downgraded' : 'suppressed', reason, alternative: alt, ruleId: ruleCtx.ruleId || detection.ruleId });
    _trackMetric(alt ? 'downgraded' : 'suppressed', `evidence_missing:${tid}`);
    return { allowed: false, reason, alternative: alt };
  }

  _audit({ tid, decision: 'allowed', ruleId: ruleCtx.ruleId || detection.ruleId });
  _trackMetric('allowed', null);
  return { allowed: true, reason: `${tid} evidence requirements satisfied`, alternative: null };
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVIDENCE REQUIREMENT CHECKER
// ─────────────────────────────────────────────────────────────────────────────
function _checkEvidenceReq(req, ctx, evt, raw, detection, ruleCtx) {
  switch (req.type) {

    case 'evidence_flag':
      return ctx.hasFlag(req.flag);

    case 'process_match': {
      const val = String(_getField(req.field, evt, raw) || '').toLowerCase();
      return req.values.some(v => val.includes(v.toLowerCase()) || val.endsWith(v.toLowerCase()));
    }

    case 'cmd_contains': {
      const val = String(_getField(req.field, evt, raw) || '').toLowerCase();
      return req.values.some(v => val.includes(v.toLowerCase()));
    }

    case 'port_match': {
      const dstPort = String(evt.dstPort || raw.DestinationPort || raw.dst_port || '');
      return req.ports.includes(dstPort);
    }

    case 'logon_type': {
      const lt = String(evt.logonType || raw.LogonType || '');
      return req.types.includes(lt);
    }

    case 'logsource_cat': {
      const ruleLS  = (ruleCtx.logsource?.category || detection.logsource?.category || '').toLowerCase();
      const ruleLS2 = (ruleCtx.logsource?.service  || detection.logsource?.service  || '').toLowerCase();
      const evtSrc  = (evt.source  || '').toLowerCase();
      const evtFmt  = (evt.format  || '').toLowerCase();
      const evtChan = (evt.channel || raw.Channel || '').toLowerCase();
      return req.categories.some(cat =>
        ruleLS.includes(cat) || ruleLS2.includes(cat) ||
        evtSrc.includes(cat) || evtFmt.includes(cat)  ||
        evtChan.includes(cat)
      );
    }

    case 'field_present': {
      const val = _getField(req.field, evt, raw);
      return val != null && val !== '';
    }

    case 'event_id': {
      const evtId = String(evt.eventId || raw.EventID || '');
      return req.ids.includes(evtId);
    }

    case 'channel_match': {
      const chan = (evt.channel || raw.Channel || '').toLowerCase();
      return req.channels.some(c => chan.includes(c.toLowerCase()));
    }

    default:
      return false;
  }
}

// Dot-notation field resolver with raw fallback
function _getField(fieldPath, evt, raw) {
  if (!fieldPath) return null;
  const parts = fieldPath.split('.');
  let val = evt;
  for (const p of parts) {
    if (val == null) return null;
    if (p === 'raw') val = raw;
    else val = val[p];
  }
  if (val != null) return val;
  // Try raw directly
  val = raw;
  for (const p of parts) {
    if (val == null) return null;
    val = val[p];
  }
  return val;
}

// ─────────────────────────────────────────────────────────────────────────────
//  validateDetection
//  Applies CEA to a single detection object.  Rewrites tags in place,
//  never adding techniques — only removing or downgrading unsupported ones.
//
//  The CEA decision is FINAL — no downstream module may re-add a suppressed
//  technique (enforced by the _ceaValidated flag + MITRE-mapper guard).
// ─────────────────────────────────────────────────────────────────────────────
function validateDetection(detection, evidenceCtx) {
  if (!detection || typeof detection !== 'object') return detection;

  const tags       = Array.isArray(detection.tags) ? detection.tags : [];
  const logsource  = detection.logsource || {};
  const event      = detection.event || {};
  const ruleCtx    = {
    ruleId       : detection.ruleId,
    logsource,
    isKeywordRule: isKeywordOnlyRule(detection),
  };

  // Extract technique IDs from tags
  const taggedTechniques = [];
  for (const tag of tags) {
    const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
    if (m) taggedTechniques.push(m[1].toUpperCase());
  }

  if (taggedTechniques.length === 0) {
    // No ATT&CK tags — pass through, mark as validated
    return { ...detection, _ceaValidated: true, _ceaWarnings: [] };
  }

  const finalTechniques = [];
  const warnings        = [];

  for (const tid of taggedTechniques) {
    const result = validateTechnique(tid, evidenceCtx, event, detection, ruleCtx);
    if (result.allowed) {
      finalTechniques.push(tid);
    } else {
      warnings.push(result.reason);
      if (result.alternative) {
        // Only add alternative if not already in the set
        if (!finalTechniques.includes(result.alternative)) {
          finalTechniques.push(result.alternative);
          warnings.push(`  → downgraded to ${result.alternative}`);
        }
      }
    }
  }

  const uniqueFinal = [...new Set(finalTechniques)];
  const hadChanges  = uniqueFinal.join(',') !== taggedTechniques.join(',');

  if (!hadChanges) {
    return { ...detection, _ceaValidated: true, _ceaWarnings: [] };
  }

  // Rebuild tags: keep non-technique tags + rewrite technique tags
  const nonTechTags = tags.filter(t => !t.toLowerCase().match(/attack\.t\d+/));
  const newTechTags = uniqueFinal.map(t => `attack.${t.toLowerCase()}`);
  const newTags     = [...nonTechTags, ...newTechTags];

  // Reduce confidence proportionally to suppressed techniques
  const suppressedCount = taggedTechniques.length - uniqueFinal.filter(t => taggedTechniques.includes(t)).length;
  const ratio      = taggedTechniques.length > 0 ? uniqueFinal.length / taggedTechniques.length : 1;
  const newConf    = uniqueFinal.length === 0
    ? Math.max(5, (detection.confidence || 70) - 40)
    : Math.round((detection.confidence || 70) * (0.6 + 0.4 * ratio));

  return {
    ...detection,
    tags          : newTags,
    confidence    : newConf,
    _ceaValidated : true,
    _ceaAdjusted  : true,
    _ceaOrigTags  : tags,
    _ceaFinalTids : uniqueFinal,
    _ceaWarnings  : warnings,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  validateBatch
//  Applies CEA to all detections in a batch.
//  Suppresses detections where ALL techniques were removed AND the detection
//  has no other meaningful content.
//
//  @param {Array}  detections   — array of detection objects
//  @param {Array}  events       — normalized events in the same ingestion call
//  @returns {Array}             — filtered + adjusted detections
// ─────────────────────────────────────────────────────────────────────────────
function validateBatch(detections = [], events = []) {
  const detArr = Array.isArray(detections) ? detections : [];
  const evtArr = Array.isArray(events)     ? events     : [];

  // Build EvidenceContext once for the whole batch
  const ctx     = new EvidenceContext(evtArr, detArr);
  const result  = [];

  for (const det of detArr) {
    // Skip already-validated objects (idempotent)
    if (det._ceaValidated) {
      result.push(det);
      continue;
    }

    const validated = validateDetection(det, ctx);

    // Suppress detection only when:
    //  a) ALL tagged techniques were removed, AND
    //  b) The detection's ONLY claim was via those techniques (pure tag-based),
    //  c) There is no structural evidence in the event itself (e.g. actual PsExec process)
    if (validated._ceaAdjusted && validated._ceaFinalTids?.length === 0) {
      const origTids = (validated._ceaOrigTags || [])
        .map(t => { const m = t.match(/attack\.(t\d+(?:\.\d+)?)/i); return m ? m[1].toUpperCase() : null; })
        .filter(Boolean);

      // Only suppress entirely if ALL techniques were purely tag-based with no field evidence
      const allRequireEvidence = origTids.every(t => TECHNIQUE_EVIDENCE_RULES[t] != null);
      if (allRequireEvidence && origTids.length > 0) {
        console.warn(
          `[CEA] Suppressed detection "${det.ruleName || det.title || det.ruleId}": ` +
          `all techniques (${origTids.join(', ')}) lack supporting evidence`
        );
        continue; // Drop from output
      }
    }

    result.push(validated);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  buildEvidence
//  Constructs an EvidenceContext from an event batch.
//  Call this once per ingest cycle and reuse for all validateTechnique calls.
// ─────────────────────────────────────────────────────────────────────────────
function buildEvidence(events = [], detections = []) {
  return new EvidenceContext(events, detections);
}

// ─────────────────────────────────────────────────────────────────────────────
//  isRuleEligibleForTechnique
//  Pre-compilation check: returns false when a rule should NEVER produce a
//  given technique assignment (e.g. auth-EventID rules tagged as T1190).
//  Used by SigmaEngine._compileRule to strip invalid technique tags at load time.
// ─────────────────────────────────────────────────────────────────────────────
function isRuleEligibleForTechnique(rule, tid) {
  // Keyword-only rules are not eligible for any evidence-gated technique
  if (isKeywordOnlyRule(rule) && TECHNIQUE_EVIDENCE_RULES[tid]) {
    return false;
  }

  // Blocked-source rules
  const blockedSrc = TECHNIQUE_BLOCKED_SOURCES[tid];
  if (blockedSrc) {
    const det     = rule.detection || {};
    const sel     = det.selection  || {};
    const evtIds  = Array.isArray(sel.EventID) ? sel.EventID : [];
    const service = (rule.logsource?.service || '').toLowerCase();

    const allAuthIds = evtIds.length > 0 && evtIds.every(id => blockedSrc.blockedEventIds.has(String(id)));
    const blockedLS  = blockedSrc.blockedLogsources.has(service);

    if (allAuthIds || blockedLS) {
      return false;
    }
  }

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  sanitizeRuleTags
//  Removes technique tags from a rule that would produce invalid assignments.
//  Call during rule compilation to strip bad tags before the rule is indexed.
// ─────────────────────────────────────────────────────────────────────────────
function sanitizeRuleTags(rule) {
  if (!rule || !Array.isArray(rule.tags)) return rule;

  const newTags = rule.tags.filter(tag => {
    const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
    if (!m) return true; // keep non-technique tags
    const tid = m[1].toUpperCase();
    const eligible = isRuleEligibleForTechnique(rule, tid);
    if (!eligible) {
      console.warn(`[CEA] Removed invalid tag "${tag}" from rule "${rule.id || rule.title}" — ${TECHNIQUE_EVIDENCE_RULES[tid]?.reason || TECHNIQUE_BLOCKED_SOURCES[tid]?.description || 'not eligible'}`);
    }
    return eligible;
  });

  if (newTags.length !== rule.tags.length) {
    return { ...rule, tags: newTags, _ceaSanitized: true };
  }
  return rule;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FINAL GUARD — mitreMapperGuard
//  Applied at the MITRE-mapper output stage as a last-resort safety net.
//  Removes any technique that should not have survived to this point.
//
//  @param {Array}  techniques   — output of MitreMapper.mapDetection().techniques
//  @param {Object} evidenceCtx  — EvidenceContext for the current batch
//  @param {Object} [detection]  — the parent detection (for context)
//  @returns {Array}             — filtered techniques
// ─────────────────────────────────────────────────────────────────────────────
function mitreMapperGuard(techniques, evidenceCtx, detection = {}) {
  if (!Array.isArray(techniques) || techniques.length === 0) return techniques;

  const evt     = detection.event || {};
  const ruleCtx = { logsource: detection.logsource || {}, ruleId: detection.ruleId };

  return techniques.filter(t => {
    const result = validateTechnique(t.id, evidenceCtx, evt, detection, ruleCtx);
    if (!result.allowed) {
      console.warn(`[CEA/MitreGuard] Stripped technique ${t.id} from MITRE output: ${result.reason}`);
    }
    return result.allowed;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Core validators
  validateTechnique,
  validateDetection,
  validateBatch,

  // Evidence context
  buildEvidence,
  EvidenceContext,

  // Rule compilation helpers
  isRuleEligibleForTechnique,
  sanitizeRuleTags,
  isKeywordOnlyRule,

  // MITRE-mapper final guard
  mitreMapperGuard,

  // Audit & metrics
  getAuditLog  : ()  => [..._auditLog],
  getMetrics   : ()  => JSON.parse(JSON.stringify(_metrics)),
  resetAuditLog: ()  => { _auditLog.length = 0; },
  resetMetrics : ()  => {
    Object.keys(_metrics).forEach(k => {
      if (typeof _metrics[k] === 'number') _metrics[k] = 0;
      else if (typeof _metrics[k] === 'object') _metrics[k] = {};
    });
  },

  // Exported constants (for testing / downstream consumers)
  TECHNIQUE_EVIDENCE_RULES,
  TECHNIQUE_BLOCKED_SOURCES,
  AUTH_ONLY_EVENT_IDS,
};
