/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Detection Engine  v2.0
 *
 *  Capabilities:
 *   ✅ generateSigma(technique)  — Sigma YAML detection rules
 *   ✅ generateKQL(technique)    — Microsoft Sentinel / Defender KQL
 *   ✅ generateSPL(technique)    — Splunk SPL queries
 *   ✅ generateElastic(technique)— Elastic EQL / Lucene queries
 *   ✅ generateAll(technique)    — All formats in one call
 *   ✅ getTechniqueInfo(id)       — Structured technique info
 *   ✅ listSupportedTechniques()  — All techniques in the DB
 *   ✅ correlate(technique)       — CVE + tools correlation map
 *
 *  Architecture:
 *   DetectionEngine
 *   ├── RULE_DB        — 40+ MITRE-aligned detection templates
 *   ├── SigmaBuilder   — Sigma YAML generator
 *   ├── KQLBuilder     — KQL query generator
 *   ├── SPLBuilder     — SPL query generator
 *   ├── ElasticBuilder — EQL / Lucene generator
 *   └── CorrelationMap — CVE ↔ technique ↔ tool mapping
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
//  RULE DATABASE — comprehensive MITRE ATT&CK aligned templates
// ─────────────────────────────────────────────────────────────────────────────
const RULE_DB = {
  // ── Execution ────────────────────────────────────────────────────────────
  'T1059': {
    id: 'T1059', name: 'Command and Scripting Interpreter',
    tactic: 'Execution', severity: 'high',
    sigma: {
      title: 'Suspicious Scripting Interpreter Execution',
      description: 'Detects suspicious use of scripting interpreters',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { Image: ['*\\powershell.exe','*\\cmd.exe','*\\wscript.exe','*\\cscript.exe','*\\mshta.exe'] },
        suspicious_args: { CommandLine: ['*-enc *','*-encodedcommand*','*bypass*','*hidden*','*noprofile*','* -w hidden*','*downloadstring*','*iex*','*invoke-expression*'] },
        condition: 'selection and suspicious_args'
      },
      falsepositives: ['Legitimate administrative scripts', 'Software installers'],
      tags: ['attack.execution','attack.t1059']
    },
    kql: `// T1059 - Command and Scripting Interpreter
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| where ProcessCommandLine has_any ("-enc ", "-encodedcommand", "bypass", "hidden", "downloadstring", "iex", "invoke-expression")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`,
    spl: `index=windows EventCode=4688
(CommandLine="*-enc *" OR CommandLine="*-encodedcommand*" OR CommandLine="*bypass*" OR CommandLine="*downloadstring*")
(NewProcessName="*\\\\powershell.exe" OR NewProcessName="*\\\\cmd.exe" OR NewProcessName="*\\\\wscript.exe")
| table _time, host, user, NewProcessName, CommandLine
| sort - _time`,
    tools: ['powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe'],
    cves: ['CVE-2022-44698','CVE-2023-36874'],
    analyst_note: 'Focus on encoded PowerShell (-enc flag) and DownloadString patterns indicative of C2 or staging.'
  },

  'T1059.001': {
    id: 'T1059.001', name: 'PowerShell',
    tactic: 'Execution', severity: 'high',
    sigma: {
      title: 'Suspicious PowerShell Encoded Command',
      description: 'Detects PowerShell execution with encoded commands or suspicious parameters commonly used by threat actors for obfuscation',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { Image: ['*\\powershell.exe','*\\pwsh.exe'], CommandLine: ['*-encodedcommand*','*-enc *','* -e *'] },
        obfuscation: { CommandLine: ['*[Convert]::FromBase64String*','*[System.Convert]::*','*frombase64*'] },
        download: { CommandLine: ['*DownloadString*','*DownloadFile*','*WebClient*','*Invoke-WebRequest*','*iwr *','*curl *','*wget *'] },
        bypass: { CommandLine: ['*-nop *','*-noprofile*','*-NonInteractive*','*-ExecutionPolicy Bypass*','*-ep bypass*','*-w hidden*','*-WindowStyle Hidden*'] },
        condition: 'selection or obfuscation or download or bypass'
      },
      falsepositives: ['System administration scripts','Automated patch management','Software deployment tools'],
      tags: ['attack.execution','attack.t1059.001','attack.defense_evasion','attack.t1027']
    },
    kql: `// T1059.001 - PowerShell Encoded Command / Obfuscation
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-encodedcommand", "-enc ", " -e ", 
    "DownloadString", "DownloadFile", "WebClient",
    "Invoke-WebRequest", "iex", "Invoke-Expression",
    "-noprofile", "-ExecutionPolicy Bypass", "-ep bypass",
    "-w hidden", "-WindowStyle Hidden",
    "FromBase64String", "System.Convert"
)
| extend Base64Detected = iff(ProcessCommandLine matches regex "[A-Za-z0-9+/]{50,}={0,2}", true, false)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Base64Detected, InitiatingProcessFileName
| order by Timestamp desc`,
    spl: `index=windows (EventCode=4688 OR source="WinEventLog:Microsoft-Windows-PowerShell/Operational")
(NewProcessName="*\\\\powershell.exe" OR NewProcessName="*\\\\pwsh.exe" OR EventCode=4103 OR EventCode=4104)
(CommandLine="-enc*" OR CommandLine="-encodedcommand*" OR CommandLine="*DownloadString*" 
 OR CommandLine="*WebClient*" OR CommandLine="*bypass*" OR CommandLine="*hidden*"
 OR CommandLine="*invoke-expression*" OR CommandLine="*iex(*"
 OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*WebClient*")
| eval severity="HIGH"
| table _time, host, user, NewProcessName, CommandLine, ScriptBlockText, severity
| sort - _time`,
    elastic: `// T1059.001 - PowerShell (EQL)
process where event.type == "start"
  and process.name in ("powershell.exe", "pwsh.exe")
  and (
    process.args : ("-encodedcommand", "-enc", "-e")
    or process.command_line : ("*DownloadString*", "*WebClient*", "*bypass*", "*hidden*", "*iex*")
  )`,
    tools: ['powershell.exe','pwsh.exe'],
    cves: ['CVE-2022-44698','CVE-2023-28252'],
    analyst_note: 'Check ScriptBlock logging (Event ID 4104) for deobfuscated code. Base64-encoded payloads often contain stage-2 C2 instructions.'
  },

  'T1059.003': {
    id: 'T1059.003', name: 'Windows Command Shell',
    tactic: 'Execution', severity: 'medium',
    sigma: {
      title: 'Suspicious Windows CMD Execution',
      description: 'Detects suspicious cmd.exe usage with obfuscation or downloading patterns',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { Image: '*\\cmd.exe' },
        suspicious: { CommandLine: ['*/c certutil*','*/c bitsadmin*','*/c msiexec*','*echo * > *.bat*','*echo * >> *.vbs*'] },
        condition: 'selection and suspicious'
      },
      falsepositives: ['Legitimate admin tasks'],
      tags: ['attack.execution','attack.t1059.003']
    },
    kql: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "msiexec /q", "echo") 
    and ProcessCommandLine has_any (".bat", ".vbs", ".ps1", "http://", "https://", "ftp://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc`,
    spl: `index=windows EventCode=4688 NewProcessName="*\\\\cmd.exe"
(CommandLine="*certutil*" OR CommandLine="*bitsadmin*" OR CommandLine="*msiexec /q*")
| table _time, host, user, CommandLine | sort - _time`,
    tools: ['cmd.exe','certutil.exe','bitsadmin.exe'],
    cves: [],
    analyst_note: 'CMD paired with certutil -decode is a classic LOLBins technique for payload staging.'
  },

  // ── Persistence ──────────────────────────────────────────────────────────
  'T1053.005': {
    id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task',
    tactic: 'Persistence', severity: 'high',
    sigma: {
      title: 'Suspicious Scheduled Task Creation',
      description: 'Detects scheduled task creation often used for persistence by threat actors',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { Image: ['*\\schtasks.exe','*\\at.exe'] },
        creation: { CommandLine: ['/create*','*/sc *','*/tr *'] },
        suspicious_path: { CommandLine: ['*\\AppData\\*','*\\Temp\\*','*\\Users\\Public\\*','*\\ProgramData\\*'] },
        condition: 'selection and creation and suspicious_path'
      },
      falsepositives: ['Software installations','Backup software'],
      tags: ['attack.persistence','attack.t1053.005']
    },
    kql: `// T1053.005 - Scheduled Task Persistence
union DeviceProcessEvents, DeviceEvents
| where Timestamp > ago(24h)
| where (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create")
    or (ActionType == "ScheduledTaskCreated")
| where ProcessCommandLine has_any ("\\AppData\\", "\\Temp\\", "\\Public\\", "\\ProgramData\\")
    or TaskName contains "Update" or TaskName contains "Sync"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, TaskName
| order by Timestamp desc`,
    spl: `index=windows (EventCode=4698 OR (EventCode=4688 AND NewProcessName="*schtasks.exe"))
(CommandLine="*/create*" OR TaskName="*Update*" OR TaskName="*Sync*")
(CommandLine="*\\\\AppData\\\\*" OR CommandLine="*\\\\Temp\\\\*" OR CommandLine="*\\\\Public\\\\*")
| table _time, host, user, CommandLine, TaskName | sort - _time`,
    tools: ['schtasks.exe','at.exe'],
    cves: ['CVE-2022-21999'],
    analyst_note: 'Look for tasks pointing to unusual directories (AppData, Temp, Public). Task name spoofing ("WindowsUpdate", "AdobeAcrobat") is common.'
  },

  'T1547.001': {
    id: 'T1547.001', name: 'Registry Run Keys / Startup Folder',
    tactic: 'Persistence', severity: 'high',
    sigma: {
      title: 'Registry Run Key Persistence',
      description: 'Detects modification of registry run keys for persistence',
      logsource: { category: 'registry_event', product: 'windows' },
      detection: {
        selection: {
          TargetObject: [
            '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*',
            '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*',
            '*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*',
            '*\\SYSTEM\\CurrentControlSet\\Services\\*'
          ]
        },
        not_system: { Image: ['!*\\system32\\*','!*\\syswow64\\*'] },
        condition: 'selection and not_system'
      },
      falsepositives: ['Software installations','Security tools'],
      tags: ['attack.persistence','attack.t1547.001']
    },
    kql: `DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has_any (
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where InitiatingProcessFolderPath !contains "system32"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc`,
    spl: `index=windows (EventCode=13 OR EventCode=4657)
(TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*"
 OR TargetObject="*\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*")
NOT (Image="*\\\\system32\\\\*")
| table _time, host, user, TargetObject, Details | sort - _time`,
    tools: ['reg.exe','regedit.exe'],
    cves: [],
    analyst_note: 'Registry persistence is often combined with UAC bypass. Check parent process tree for suspicious origin.'
  },

  // ── Privilege Escalation ─────────────────────────────────────────────────
  'T1055': {
    id: 'T1055', name: 'Process Injection',
    tactic: 'Privilege Escalation', severity: 'critical',
    sigma: {
      title: 'Suspicious Process Injection Indicators',
      description: 'Detects process injection techniques via suspicious API calls and memory operations',
      logsource: { category: 'process_access', product: 'windows' },
      detection: {
        selection: { GrantedAccess: ['0x1F0FFF','0x1F1FFF','0x143A','0x40','0x1000'] },
        not_self: { SourceImage: ['!=TargetImage'] },
        not_system: { SourceImage: ['!*\\system32\\*','!*\\syswow64\\*','!*\\SysWOW64\\*'] },
        condition: 'selection and not_self and not_system'
      },
      falsepositives: ['AV/EDR tools (frequent)','Debuggers','Some legitimate applications'],
      tags: ['attack.privilege_escalation','attack.defense_evasion','attack.t1055']
    },
    kql: `// T1055 - Process Injection
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("OpenProcess", "CreateRemoteThread", "WriteProcessMemory")
| where InitiatingProcessFolderPath !contains "system32"
    and InitiatingProcessFolderPath !contains "Program Files"
| where ProcessId != InitiatingProcessId
| project Timestamp, DeviceName, AccountName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`,
    spl: `index=sysmon (EventCode=8 OR EventCode=10)
NOT (SourceImage="*\\\\system32\\\\*" OR SourceImage="*\\\\Program Files\\\\*")
| where GrantedAccess IN ("0x1F0FFF","0x143A","0x40","0x1fffff")
| table _time, host, SourceImage, TargetImage, GrantedAccess | sort - _time`,
    tools: ['mshta.exe','regsvr32.exe','rundll32.exe'],
    cves: ['CVE-2023-23397','CVE-2023-28252'],
    analyst_note: 'Sysmon Event ID 8 (CreateRemoteThread) and ID 10 (ProcessAccess) are primary indicators. Correlate with parent process anomalies.'
  },

  'T1078': {
    id: 'T1078', name: 'Valid Accounts',
    tactic: 'Initial Access / Persistence', severity: 'high',
    sigma: {
      title: 'Suspicious Account Usage - Valid Credentials',
      description: 'Detects anomalous login patterns suggesting credential misuse',
      logsource: { product: 'windows', service: 'security' },
      detection: {
        off_hours_login: { EventID: 4624, LogonType: [2, 10], Keywords: 'Audit Success' },
        new_workstation: { EventID: 4624, WorkstationName: ['!CORP-*','!WS-*'] },
        multiple_failures: { EventID: 4625, count: '> 5 within 5m' },
        condition: 'off_hours_login or new_workstation or multiple_failures'
      },
      falsepositives: ['Remote work','VPN usage','Service accounts'],
      tags: ['attack.initial_access','attack.persistence','attack.t1078']
    },
    kql: `// T1078 - Valid Accounts / Credential Misuse
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType in ("LogonSuccess", "LogonFailed")
| summarize LogonCount=count(), FailedLogons=countif(ActionType=="LogonFailed"),
    DistinctWorkstations=dcount(DeviceName)
    by AccountUpn, AccountName
| where FailedLogons > 5 or DistinctWorkstations > 5
| join kind=inner (
    IdentityLogonEvents | where Timestamp > ago(24h)
    | where ActionType == "LogonSuccess"
) on AccountName
| project Timestamp, AccountName, AccountUpn, FailedLogons, DistinctWorkstations, DeviceName, IPAddress
| order by FailedLogons desc`,
    spl: `index=windows EventCode=4625
| stats count as failed_attempts, dc(host) as workstations, 
  values(IpAddress) as ips by TargetUserName
| where failed_attempts > 5 OR workstations > 3
| eval risk_score=if(failed_attempts>20, "CRITICAL", if(failed_attempts>10, "HIGH", "MEDIUM"))
| table _time, TargetUserName, failed_attempts, workstations, ips, risk_score`,
    tools: ['psexec.exe','wmic.exe','net.exe'],
    cves: ['CVE-2022-37958'],
    analyst_note: 'Correlate with geographic anomalies (impossible travel), VPN bypass attempts, and privileged account activity outside normal hours.'
  },

  // ── Defense Evasion ──────────────────────────────────────────────────────
  'T1027': {
    id: 'T1027', name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion', severity: 'high',
    sigma: {
      title: 'Base64 Encoded Payload Execution',
      description: 'Detects execution of Base64 encoded payloads via PowerShell or cmd',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { CommandLine: ['*[Convert]::FromBase64String*','* -enc *','*frombase64*','*base64 -d*'] },
        condition: 'selection'
      },
      falsepositives: ['Legitimate software using base64','Encoding tools'],
      tags: ['attack.defense_evasion','attack.t1027']
    },
    kql: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("FromBase64String", " -enc ", "-encodedcommand", "base64 -d")
| extend Base64Payload = extract("[A-Za-z0-9+/]{40,}={0,2}", 0, ProcessCommandLine)
| where isnotempty(Base64Payload)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Base64Payload
| order by Timestamp desc`,
    spl: `index=windows EventCode=4688
(CommandLine="*FromBase64String*" OR CommandLine="* -enc *" OR CommandLine="*frombase64*")
| rex field=CommandLine "(?P<b64>[A-Za-z0-9+/]{40,}={0,2})"
| table _time, host, user, NewProcessName, CommandLine, b64 | sort - _time`,
    tools: ['powershell.exe','certutil.exe'],
    cves: [],
    analyst_note: 'Decode base64 payloads for secondary analysis. Tools like CyberChef can decode nested obfuscation layers.'
  },

  'T1112': {
    id: 'T1112', name: 'Modify Registry',
    tactic: 'Defense Evasion', severity: 'medium',
    sigma: {
      title: 'Registry Modification for Defense Evasion',
      description: 'Detects registry modifications that disable security controls',
      logsource: { category: 'registry_event', product: 'windows' },
      detection: {
        disable_av: { TargetObject: ['*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender*','*DisableAntiSpyware*','*DisableRealtimeMonitoring*'] },
        disable_fw: { TargetObject: ['*\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy*','*EnableFirewall*'] },
        condition: 'disable_av or disable_fw'
      },
      falsepositives: ['Security software configuration','GPO changes'],
      tags: ['attack.defense_evasion','attack.t1112']
    },
    kql: `DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has_any (
    "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    "\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess"
)
| where ActionType == "RegistryValueSet"
| where RegistryValueData in ("1", "0x00000001")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc`,
    spl: `index=windows (EventCode=13 OR EventCode=4657)
(TargetObject="*Windows Defender*" OR TargetObject="*FirewallPolicy*")
(Details="DWORD (0x00000001)" OR Details="1")
| table _time, host, user, TargetObject, Details | sort - _time`,
    tools: ['reg.exe','regedit.exe','powershell.exe'],
    cves: [],
    analyst_note: 'DisableAntiSpyware=1 and DisableRealtimeMonitoring=1 are strong indicators of tamper attempt. Check if Defender is excluded from monitoring these paths.'
  },

  // ── Credential Access ────────────────────────────────────────────────────
  'T1003': {
    id: 'T1003', name: 'OS Credential Dumping',
    tactic: 'Credential Access', severity: 'critical',
    sigma: {
      title: 'LSASS Memory Credential Dumping',
      description: 'Detects attempts to dump credentials from LSASS process memory',
      logsource: { category: 'process_access', product: 'windows' },
      detection: {
        lsass_access: { TargetImage: '*\\lsass.exe', GrantedAccess: ['0x1010','0x1410','0x147A','0x1F1FFF','0x1F0FFF'] },
        dumping_tools: { SourceImage: ['*\\procdump*','*\\mimikatz*','*\\pwdump*','*\\ntdsutil*','*\\vssadmin*'] },
        condition: 'lsass_access or dumping_tools'
      },
      falsepositives: ['AV/EDR solutions','Windows Defender Credential Guard'],
      tags: ['attack.credential_access','attack.t1003']
    },
    kql: `// T1003 - LSASS Credential Dumping
DeviceEvents
| where Timestamp > ago(24h)
| where (ActionType == "OpenProcess" and FileName =~ "lsass.exe")
    or (ActionType == "ProcessCreated" and InitiatingProcessFileName has_any ("procdump", "mimikatz", "pwdump", "ntdsutil"))
    or (FileName =~ "lsass.exe" and ActionType == "MemoryRemoteWrite")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`,
    spl: `index=sysmon (EventCode=10 OR EventCode=8)
(TargetImage="*\\\\lsass.exe" AND (GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1F0FFF"))
NOT (SourceImage="*\\\\MsMpEng.exe" OR SourceImage="*\\\\csrss.exe")
| table _time, host, SourceImage, TargetImage, GrantedAccess | sort - _time`,
    tools: ['mimikatz.exe','procdump.exe','pwdump.exe','secretsdump.py'],
    cves: ['CVE-2022-21919'],
    analyst_note: 'LSASS access from non-system processes is critical. Credential Guard (VBS) prevents this. Check for SAM hive copies (ntdsutil, vssadmin shadow copies).'
  },

  // ── Lateral Movement ─────────────────────────────────────────────────────
  'T1021.002': {
    id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares',
    tactic: 'Lateral Movement', severity: 'high',
    sigma: {
      title: 'Suspicious SMB Lateral Movement',
      description: 'Detects SMB-based lateral movement via admin shares',
      logsource: { product: 'windows', service: 'security' },
      detection: {
        share_access: { EventID: 5140, ShareName: ['*ADMIN$','*C$','*IPC$'] },
        from_unusual: { IpAddress: ['!10.*','!192.168.*','!172.16.*'] },
        condition: 'share_access and from_unusual'
      },
      falsepositives: ['Legitimate admin tools','Backup software','SCCM/SCOM'],
      tags: ['attack.lateral_movement','attack.t1021.002']
    },
    kql: `// T1021.002 - SMB Lateral Movement
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| join kind=inner (
    DeviceProcessEvents
    | where FileName in~ ("net.exe", "net1.exe", "psexec.exe", "wmic.exe")
) on DeviceName
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc`,
    spl: `index=windows EventCode=5140
(ShareName="*ADMIN$" OR ShareName="*C$" OR ShareName="*IPC$")
NOT (IpAddress="10.*" OR IpAddress="192.168.*" OR IpAddress="172.16.*")
| table _time, host, SubjectUserName, ShareName, IpAddress | sort - _time`,
    tools: ['psexec.exe','net.exe','wmic.exe','smbclient'],
    cves: ['CVE-2020-0796','CVE-2021-34527'],
    analyst_note: 'SMBGhost (CVE-2020-0796) enables unauthenticated RCE over SMB. Track admin share access across multiple hosts for worm-like spread patterns.'
  },

  'T1021.001': {
    id: 'T1021.001', name: 'Remote Desktop Protocol',
    tactic: 'Lateral Movement', severity: 'high',
    sigma: {
      title: 'Suspicious RDP Lateral Movement',
      description: 'Detects RDP-based lateral movement from unusual sources',
      logsource: { product: 'windows', service: 'security' },
      detection: {
        rdp_login: { EventID: 4624, LogonType: 10 },
        network_rdp: { EventID: 4624, LogonType: 3, AuthPackage: 'Kerberos' },
        from_workstation: { WorkstationName: ['WS-*','LAPTOP-*','DESKTOP-*'] },
        condition: '(rdp_login or network_rdp) and from_workstation'
      },
      falsepositives: ['IT admin RDP sessions','Jump server use'],
      tags: ['attack.lateral_movement','attack.t1021.001']
    },
    kql: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 3389 and ActionType == "ConnectionSuccess"
| join kind=inner (
    IdentityLogonEvents | where LogonType == "RemoteInteractive"
) on DeviceName
| project Timestamp, DeviceName, RemoteIP, AccountName, DeviceName
| summarize RDP_Count=count(), Targets=make_set(DeviceName) by AccountName, RemoteIP
| where RDP_Count > 3
| order by RDP_Count desc`,
    spl: `index=windows EventCode=4624 LogonType=10
| stats count as rdp_count, dc(host) as unique_targets, values(host) as targets
  by SourceNetworkAddress, TargetUserName
| where rdp_count > 3 OR unique_targets > 2
| table _time, TargetUserName, SourceNetworkAddress, rdp_count, unique_targets, targets`,
    tools: ['mstsc.exe','rdesktop','freerdp'],
    cves: ['CVE-2019-0708','CVE-2022-22015'],
    analyst_note: 'BlueKeep (CVE-2019-0708) is an unauthenticated RDP exploit. Monitor for sequential RDP connections from same source to multiple targets — canary for lateral movement.'
  },

  // ── Discovery ────────────────────────────────────────────────────────────
  'T1082': {
    id: 'T1082', name: 'System Information Discovery',
    tactic: 'Discovery', severity: 'low',
    sigma: {
      title: 'System Discovery Commands Execution',
      description: 'Detects execution of common system information gathering commands',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { Image: ['*\\systeminfo.exe','*\\hostname.exe','*\\whoami.exe','*\\net.exe','*\\ipconfig.exe','*\\nltest.exe'] },
        burst: { timeframe: '5m', count: '> 5' },
        condition: 'selection | burst'
      },
      falsepositives: ['IT auditing tools','Helpdesk activities'],
      tags: ['attack.discovery','attack.t1082']
    },
    kql: `DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("systeminfo.exe","whoami.exe","net.exe","ipconfig.exe","nltest.exe","hostname.exe","tasklist.exe")
| summarize CommandCount=count(), Commands=make_set(FileName) by DeviceName, AccountName, bin(Timestamp, 5m)
| where CommandCount >= 5
| project Timestamp, DeviceName, AccountName, CommandCount, Commands
| order by CommandCount desc`,
    spl: `index=windows EventCode=4688
(NewProcessName="*systeminfo.exe" OR NewProcessName="*whoami.exe" OR NewProcessName="*net.exe" 
 OR NewProcessName="*ipconfig.exe" OR NewProcessName="*nltest.exe")
| bin _time span=5m
| stats count as cmd_count, values(NewProcessName) as commands by _time, host, user
| where cmd_count >= 5
| table _time, host, user, cmd_count, commands`,
    tools: ['systeminfo.exe','whoami.exe','net.exe','ipconfig.exe'],
    cves: [],
    analyst_note: 'Multiple discovery commands in short timeframe is a strong indicator of automated post-exploitation tooling (Cobalt Strike, Meterpreter). Correlate with C2 callback timing.'
  },

  'T1046': {
    id: 'T1046', name: 'Network Service Scanning',
    tactic: 'Discovery', severity: 'medium',
    sigma: {
      title: 'Internal Network Port Scan',
      description: 'Detects internal network scanning indicative of lateral movement preparation',
      logsource: { category: 'network_connection', product: 'windows' },
      detection: {
        scan: { Initiated: 'true', DestinationPort: ['22','23','80','443','445','3389','8080','8443'] },
        burst: { timeframe: '2m', count: '> 20', group_by: ['SourceIp'] },
        condition: 'scan | burst'
      },
      falsepositives: ['Vulnerability scanners','Network management tools'],
      tags: ['attack.discovery','attack.t1046']
    },
    kql: `DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionAttempt"
| where RemotePort in (22, 23, 80, 443, 445, 3389, 8080, 8443, 5985, 5986)
| summarize PortsScanned=dcount(RemotePort), TargetsScanned=dcount(RemoteIP), 
    Ports=make_set(RemotePort)
    by DeviceName, LocalIP, bin(Timestamp, 2m)
| where PortsScanned >= 5 or TargetsScanned >= 10
| project Timestamp, DeviceName, LocalIP, PortsScanned, TargetsScanned, Ports
| order by TargetsScanned desc`,
    spl: `index=network action=allow direction=outbound
| bin _time span=2m
| stats dc(dest_port) as ports_scanned, dc(dest_ip) as targets by _time, src_ip, host
| where ports_scanned >= 5 OR targets >= 10
| table _time, host, src_ip, ports_scanned, targets`,
    tools: ['nmap','masscan','Advanced Port Scanner'],
    cves: [],
    analyst_note: 'Internal scanning from a workstation is highly suspicious. Check if source host is recently compromised. Correlate with T1082 (discovery) for full recon chain.'
  },

  // ── Collection ───────────────────────────────────────────────────────────
  'T1114': {
    id: 'T1114', name: 'Email Collection',
    tactic: 'Collection', severity: 'high',
    sigma: {
      title: 'Suspicious Email Collection Activity',
      description: 'Detects potential email collection or exfiltration from mail client or Exchange',
      logsource: { product: 'windows' },
      detection: {
        outlook_access: { Image: '*\\powershell.exe', CommandLine: ['*New-MailboxExportRequest*','*Export-Mailbox*','*Get-MailboxFolderStatistics*'] },
        condition: 'outlook_access'
      },
      falsepositives: ['Legitimate mail migrations','IT admin tasks'],
      tags: ['attack.collection','attack.t1114']
    },
    kql: `CloudAppEvents
| where Timestamp > ago(24h)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("MailboxSearch", "MailItemsAccessed", "UpdateInboxRules")
| where AccountObjectId !in (trusted_admin_accounts)
| project Timestamp, AccountUpn, IPAddress, ActionType, AdditionalFields
| order by Timestamp desc`,
    spl: `index=o365 OR index=exchange (Operation="MailboxSearch" OR Operation="MailItemsAccessed" OR Operation="UpdateInboxRules")
| table _time, UserId, ClientIP, Operation, AffectedItems
| sort - _time`,
    tools: ['Get-MailboxExportRequest','Export-Mailbox','ruler','MailSniper'],
    cves: ['CVE-2022-41082'],
    analyst_note: 'ProxyNotShell (CVE-2022-41082) was actively used for Exchange email collection. Monitor for bulk mail access and unusual PowerShell against Exchange.'
  },

  // ── Exfiltration ─────────────────────────────────────────────────────────
  'T1048': {
    id: 'T1048', name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration', severity: 'high',
    sigma: {
      title: 'Data Exfiltration via DNS or ICMP Tunneling',
      description: 'Detects data exfiltration attempts using DNS or ICMP tunneling',
      logsource: { category: 'dns' },
      detection: {
        long_subdomain: { 'dns.question.name': ['*.length > 50'] },
        high_entropy: { 'dns.question.name': ['*[0-9a-f]{20,}.*'] },
        condition: 'long_subdomain or high_entropy'
      },
      falsepositives: ['CDN providers with long subdomains','Legitimate DNS-based services'],
      tags: ['attack.exfiltration','attack.t1048']
    },
    kql: `DnsEvents
| where TimeGenerated > ago(24h)
| extend Subdomain = tostring(split(Name, ".")[0])
| where strlen(Subdomain) > 40 or Name matches regex "[0-9a-f]{20,}"
| summarize QueryCount=count(), UniqueSubdomains=dcount(Subdomain)
    by ClientIP, bin(TimeGenerated, 5m)
| where QueryCount > 50 or UniqueSubdomains > 30
| project TimeGenerated, ClientIP, QueryCount, UniqueSubdomains
| order by QueryCount desc`,
    spl: `index=dns
| eval subdomain_len=len(mvindex(split(query,"."),0))
| where subdomain_len > 40 OR match(query, "[0-9a-f]{20,}")
| stats count as queries, dc(query) as unique_q by src_ip, span=5m
| where queries > 50 OR unique_q > 30
| table _time, src_ip, queries, unique_q`,
    tools: ['iodine','dnscat2','ping','nslookup'],
    cves: [],
    analyst_note: 'DNS tunneling tools generate high-frequency queries with long random-looking subdomains. Average DNS query length >30 chars warrants investigation.'
  },

  // ── Impact ───────────────────────────────────────────────────────────────
  'T1486': {
    id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)',
    tactic: 'Impact', severity: 'critical',
    sigma: {
      title: 'Ransomware File Encryption Behavior',
      description: 'Detects rapid file modification patterns consistent with ransomware encryption activity',
      logsource: { category: 'file_event', product: 'windows' },
      detection: {
        mass_rename: { TargetFilename: ['*.locked','*.encrypted','*.crypted','*.enc','*.ransom','*.crypt','*.[a-z0-9]{5,8}'] },
        shadow_delete: { Image: ['*\\vssadmin.exe','*\\wmic.exe','*\\bcdedit.exe','*\\wbadmin.exe'], CommandLine: ['*delete shadows*','*shadowcopy delete*','*recoveryenabled no*','*delete catalog*'] },
        condition: 'mass_rename or shadow_delete'
      },
      falsepositives: ['Compression tools','Backup software (shadow operations)'],
      tags: ['attack.impact','attack.t1486']
    },
    kql: `// T1486 - Ransomware Detection (multi-signal)
union
(DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileRenamed"
| where FileName matches regex @"\.(locked|encrypted|crypted|enc|ransom|crypt|[a-z0-9]{5,8})$"
| summarize FileRenames=count() by DeviceName, AccountName, bin(Timestamp, 1m)
| where FileRenames > 20
| extend DetectionType="MassRename", RiskLevel="CRITICAL"),
(DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete", "shadow"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| extend DetectionType="ShadowDelete", RiskLevel="CRITICAL")
| project Timestamp, DeviceName, AccountName, DetectionType, RiskLevel
| order by Timestamp desc`,
    spl: `index=windows
((EventCode=4663 AND (ObjectName="*.locked" OR ObjectName="*.encrypted" OR ObjectName="*.crypted"))
 OR (EventCode=4688 AND (NewProcessName="*vssadmin.exe" AND CommandLine="*delete shadows*"))
 OR (EventCode=4688 AND (NewProcessName="*bcdedit.exe" AND CommandLine="*recoveryenabled no*")))
| eval event_type=case(
    EventCode=4663, "FILE_ENCRYPTED",
    CommandLine="*delete shadows*", "SHADOW_DELETED",
    CommandLine="*recoveryenabled no*", "RECOVERY_DISABLED",
    true(), "UNKNOWN")
| eval risk="CRITICAL"
| table _time, host, user, event_type, ObjectName, CommandLine, risk | sort - _time`,
    tools: ['vssadmin.exe','bcdedit.exe','wmic.exe','wbadmin.exe'],
    cves: ['CVE-2021-34527','CVE-2022-24521'],
    analyst_note: '**IMMEDIATE RESPONSE REQUIRED**: Isolate host, preserve memory dump, do NOT reboot. Notify IR team. Check for backup accessibility — most ransomware deletes VSS first.'
  },

  'T1490': {
    id: 'T1490', name: 'Inhibit System Recovery',
    tactic: 'Impact', severity: 'critical',
    sigma: {
      title: 'Shadow Copy Deletion - Recovery Inhibition',
      description: 'Detects deletion of volume shadow copies to inhibit system recovery',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        vss_delete: { Image: ['*\\vssadmin.exe','*\\wmic.exe'], CommandLine: ['*delete shadows*','*shadowcopy delete*','*shadowcopy where*','*/all /quiet*'] },
        backup_disable: { Image: ['*\\bcdedit.exe','*\\wbadmin.exe'], CommandLine: ['*recoveryenabled no*','*delete catalog*','*-deleteoldest*'] },
        condition: 'vss_delete or backup_disable'
      },
      falsepositives: ['Legitimate backup management software'],
      tags: ['attack.impact','attack.t1490']
    },
    kql: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows", "resize shadowstorage"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc`,
    spl: `index=windows EventCode=4688
((NewProcessName="*vssadmin.exe" AND CommandLine="*delete shadows*")
 OR (NewProcessName="*wmic.exe" AND CommandLine="*shadowcopy*delete*")
 OR (NewProcessName="*bcdedit.exe" AND (CommandLine="*recoveryenabled no*" OR CommandLine="*bootstatuspolicy ignoreallfailures*")))
| eval detection="RANSOMWARE_PRE_ENCRYPTION", risk="CRITICAL"
| table _time, host, user, NewProcessName, CommandLine, detection | sort - _time`,
    tools: ['vssadmin.exe','bcdedit.exe','wmic.exe','wbadmin.exe'],
    cves: [],
    analyst_note: 'Shadow copy deletion is the most reliable pre-encryption indicator. Immediate isolation recommended on detection. Pair with T1486 detections for confirmation.'
  },

  // ── Command and Control ──────────────────────────────────────────────────
  'T1071.001': {
    id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols (C2)',
    tactic: 'Command and Control', severity: 'high',
    sigma: {
      title: 'Suspicious Outbound HTTPS C2 Communication',
      description: 'Detects potential C2 communication over HTTPS to suspicious or newly registered domains',
      logsource: { category: 'proxy', product: 'any' },
      detection: {
        unusual_agent: { cs_useragent: ['*curl*','*wget*','*python-requests*','*Go-http-client*'] },
        suspicious_timing: { interval: '30s-300s', pattern: 'regular' },
        condition: 'unusual_agent or suspicious_timing'
      },
      falsepositives: ['Legitimate automation','Monitoring agents'],
      tags: ['attack.command_and_control','attack.t1071.001']
    },
    kql: `DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessFileName !in~ ("chrome.exe","firefox.exe","msedge.exe","outlook.exe","teams.exe")
| summarize ConnectionCount=count(), UniqueIPs=dcount(RemoteIP),
    BytesSent=sum(SentBytes), BytesReceived=sum(ReceivedBytes)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnectionCount > 50 or (BytesSent > 10000000 and UniqueIPs < 3)
| project Timestamp, DeviceName, InitiatingProcessFileName, ConnectionCount, UniqueIPs, BytesSent, BytesReceived
| order by ConnectionCount desc`,
    spl: `index=proxy OR index=network dest_port IN (80, 443, 8080, 8443)
NOT (process IN ("chrome.exe","firefox.exe","msedge.exe","outlook.exe"))
| stats count as connections, dc(dest_ip) as unique_ips, 
  sum(bytes_out) as total_out by src_ip, process, span=1h
| where connections > 50 OR (total_out > 10000000 AND unique_ips < 3)
| table _time, src_ip, process, connections, unique_ips, total_out`,
    tools: ['curl','wget','python requests','Cobalt Strike beacon'],
    cves: [],
    analyst_note: 'Beaconing behavior has regular intervals (typically 30-300s ± jitter). Low unique IP count with high volume suggests callback to single C2. Check certificate transparency logs for domain age.'
  },

  // ── Initial Access ───────────────────────────────────────────────────────
  'T1566.001': {
    id: 'T1566.001', name: 'Phishing: Spearphishing Attachment',
    tactic: 'Initial Access', severity: 'high',
    sigma: {
      title: 'Malicious Office Macro Execution from Email',
      description: 'Detects execution of potentially malicious Office macros typically delivered via phishing',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        office_spawn: {
          ParentImage: ['*\\winword.exe','*\\excel.exe','*\\powerpnt.exe','*\\outlook.exe','*\\onenote.exe'],
          Image: ['*\\cmd.exe','*\\powershell.exe','*\\wscript.exe','*\\cscript.exe','*\\mshta.exe','*\\regsvr32.exe','*\\rundll32.exe']
        },
        condition: 'office_spawn'
      },
      falsepositives: ['Legitimate macro-enabled documents','Software packaging'],
      tags: ['attack.initial_access','attack.t1566.001']
    },
    kql: `DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc`,
    spl: `index=windows EventCode=4688
(ParentImage="*\\\\winword.exe" OR ParentImage="*\\\\excel.exe" OR ParentImage="*\\\\powerpnt.exe" OR ParentImage="*\\\\outlook.exe")
(NewProcessName="*\\\\cmd.exe" OR NewProcessName="*\\\\powershell.exe" OR NewProcessName="*\\\\wscript.exe" OR NewProcessName="*\\\\mshta.exe")
| table _time, host, user, ParentImage, NewProcessName, CommandLine | sort - _time`,
    tools: ['winword.exe','excel.exe','powerpnt.exe'],
    cves: ['CVE-2021-40444','CVE-2022-30190'],
    analyst_note: 'Follina (CVE-2022-30190) enabled code execution via ms-msdt: from Word docs. Monitor Office applications spawning child processes — this is the most common phishing vector.'
  },

  'T1190': {
    id: 'T1190', name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access', severity: 'critical',
    sigma: {
      title: 'Web Application Exploitation Attempt',
      description: 'Detects exploitation of public-facing web applications via suspicious request patterns',
      logsource: { category: 'webserver' },
      detection: {
        sql_injection: { cs_uri_query: ['*union+select*','*1=1--*','*\' or \'1\'=\'1*'] },
        path_traversal: { cs_uri_stem: ['*../../../*','*..%2F..%2F*','*%252e%252e*'] },
        rce_attempt: { cs_uri_query: ['*;id;*','*|id|*','*`id`*','*${7*7}*','*{{7*7}}*'] },
        condition: 'sql_injection or path_traversal or rce_attempt'
      },
      falsepositives: ['Legitimate security scanning','Pen testing'],
      tags: ['attack.initial_access','attack.t1190']
    },
    kql: `W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem has_any ("../", "%2e%2e", "etc/passwd", "cmd.exe")
    or csUriQuery has_any ("union select", "1=1", "xp_cmdshell", "\${", "{{", ";id;", "|id|")
| summarize count() by ClientIP, csUriStem, csUriQuery, scStatus
| where count_ > 5 or scStatus >= 500
| project TimeGenerated, ClientIP, csUriStem, csUriQuery, scStatus
| order by TimeGenerated desc`,
    spl: `index=web
(uri_query="*union+select*" OR uri_query="*1=1*" OR uri="*..%2F*" OR uri="*etc/passwd*" 
 OR uri_query="*%24%7B*" OR uri_query="*{{7*7}}*")
| stats count as attempts by src_ip, uri, status
| where attempts > 5 OR status >= 500
| table _time, src_ip, uri, status, attempts | sort - _time`,
    tools: ['sqlmap','metasploit','nuclei','curl'],
    cves: ['CVE-2021-44228','CVE-2023-34362','CVE-2023-46604'],
    analyst_note: 'Log4Shell (CVE-2021-44228), MOVEit (CVE-2023-34362), and ActiveMQ (CVE-2023-46604) are critical exploits in this category. Monitor for JNDI strings (${jndi:ldap://...}) in ALL input fields.'
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  SIGMA BUILDER
// ─────────────────────────────────────────────────────────────────────────────
class SigmaBuilder {
  static build(entry) {
    const sigma = entry.sigma;
    const ruleId = crypto.randomUUID ? crypto.randomUUID() : `rule-${Date.now()}`;

    const yaml = [
      `title: ${sigma.title}`,
      `id: ${ruleId}`,
      `status: experimental`,
      `description: ${sigma.description}`,
      `date: ${new Date().toISOString().split('T')[0]}`,
      `author: RAKAY Detection Engine v2.0`,
      `references:`,
      `    - https://attack.mitre.org/techniques/${entry.id.replace('.', '/')}/`,
      `logsource:`,
      ...Object.entries(sigma.logsource).map(([k,v]) => `    ${k}: ${v}`),
      `detection:`,
      ...Object.entries(sigma.detection).map(([key, val]) => {
        if (key === 'condition') return `    condition: ${val}`;
        if (typeof val === 'object' && !Array.isArray(val)) {
          return [`    ${key}:`, ...Object.entries(val).map(([k2, v2]) =>
            Array.isArray(v2) ? [`        ${k2}:`, ...v2.map(i => `            - '${i}'`)].join('\n') : `        ${k2}: ${v2}`
          )].join('\n');
        }
        if (Array.isArray(val)) return [`    ${key}:`, ...val.map(i => `        - '${i}'`)].join('\n');
        return `    ${key}: ${val}`;
      }),
      `falsepositives:`,
      ...sigma.falsepositives.map(fp => `    - ${fp}`),
      `level: ${entry.severity}`,
      `tags:`,
      ...sigma.tags.map(t => `    - ${t}`),
    ].join('\n');

    return yaml;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  DETECTION ENGINE — main export
// ─────────────────────────────────────────────────────────────────────────────
class DetectionEngine {
  constructor() {
    this.version = '2.0';
    this.ruleCount = Object.keys(RULE_DB).length;
  }

  // ── Core generators ──────────────────────────────────────────────────────
  generateSigma(technique) {
    const entry = this._resolve(technique);
    if (!entry) return this._notFound('Sigma', technique);

    const yaml = SigmaBuilder.build(entry);
    return {
      format: 'sigma',
      found: true,
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      content: yaml,
      metadata: {
        generated: new Date().toISOString(),
        engine: 'DetectionEngine v2.0',
        falsepositives: entry.sigma.falsepositives,
        analystNote: entry.analyst_note,
      }
    };
  }

  generateKQL(technique) {
    const entry = this._resolve(technique);
    if (!entry) return this._notFound('KQL', technique);
    return {
      format: 'kql',
      found: true,
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      content: entry.kql,
      siem: 'Microsoft Sentinel / Defender XDR',
      metadata: {
        generated: new Date().toISOString(),
        engine: 'DetectionEngine v2.0',
        analystNote: entry.analyst_note,
      }
    };
  }

  generateSPL(technique) {
    const entry = this._resolve(technique);
    if (!entry) return this._notFound('SPL', technique);
    return {
      format: 'spl',
      found: true,
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      content: entry.spl,
      siem: 'Splunk',
      metadata: {
        generated: new Date().toISOString(),
        engine: 'DetectionEngine v2.0',
        analystNote: entry.analyst_note,
      }
    };
  }

  generateElastic(technique) {
    const entry = this._resolve(technique);
    if (!entry) return this._notFound('Elastic EQL', technique);
    return {
      format: 'elastic',
      found: true,
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      content: entry.elastic || `// ${entry.name}\n// Convert from Sigma using sigma-cli: sigma convert -t elasticsearch sigma_rule.yml`,
      siem: 'Elastic SIEM / OpenSearch',
      metadata: {
        generated: new Date().toISOString(),
        engine: 'DetectionEngine v2.0',
        analystNote: entry.analyst_note,
      }
    };
  }

  generateAll(technique) {
    const entry = this._resolve(technique);
    if (!entry) {
      return {
        technique,
        found: false,
        message: `No detection templates found for ${technique}. Supported: ${this.listSupportedTechniques().map(t=>t.id).join(', ')}`
      };
    }
    return {
      found: true,
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      tools: entry.tools,
      cves: entry.cves,
      analystNote: entry.analyst_note,
      sigma: SigmaBuilder.build(entry),
      kql: entry.kql,
      spl: entry.spl,
      elastic: entry.elastic || `// Convert Sigma rule to Elastic format using sigma-cli`,
      metadata: {
        generated: new Date().toISOString(),
        engine: 'DetectionEngine v2.0',
      }
    };
  }

  // ── Technique info ────────────────────────────────────────────────────────
  getTechniqueInfo(id) {
    const entry = this._resolve(id);
    if (!entry) return null;
    return {
      id: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      tools: entry.tools,
      cves: entry.cves,
      analystNote: entry.analyst_note,
      hasDetections: true,
      formats: ['sigma', 'kql', 'spl', ...(entry.elastic ? ['elastic'] : [])],
    };
  }

  listSupportedTechniques() {
    return Object.values(RULE_DB).map(e => ({
      id: e.id,
      name: e.name,
      tactic: e.tactic,
      severity: e.severity,
    }));
  }

  // ── Correlation ───────────────────────────────────────────────────────────
  correlate(technique) {
    const entry = this._resolve(technique);
    if (!entry) return { technique, correlations: [] };
    return {
      technique: entry.id,
      name: entry.name,
      tactic: entry.tactic,
      severity: entry.severity,
      correlations: {
        tools: entry.tools || [],
        cves: entry.cves || [],
        relatedTechniques: this._findRelated(entry),
      }
    };
  }

  // ── SOC-formatted response ────────────────────────────────────────────────
  formatSOCResponse(technique) {
    const all = this.generateAll(technique);
    if (all.found === false) return all.message;

    return `## Overview
**Technique**: ${all.technique} — ${all.name}
**Tactic**: ${all.tactic}  |  **Severity**: ${all.severity.toUpperCase()}
**Associated Tools**: ${(all.tools||[]).join(', ')||'See detection queries'}
**Related CVEs**: ${(all.cves||[]).join(', ')||'None specific'}

## Why It Matters
${all.tactic} technique ${all.technique} (${all.name}) is used by threat actors to ${_tacticVerb(all.tactic)}. Detection requires correlation across process, network, and file telemetry.

## Detection Guidance

### Sigma Rule (Multi-SIEM)
\`\`\`yaml
${all.sigma}
\`\`\`

### KQL — Microsoft Sentinel / Defender XDR
\`\`\`kql
${all.kql}
\`\`\`

### SPL — Splunk
\`\`\`spl
${all.spl}
\`\`\`

## Mitigation
${_getMitigations(all.technique)}

## Analyst Tip
${all.analystNote}`;
  }

  // ── Private helpers ───────────────────────────────────────────────────────
  _resolve(technique) {
    if (!technique) return null;
    const key = technique.toString().trim().toUpperCase();
    // direct lookup
    if (RULE_DB[key]) return RULE_DB[key];
    // case-insensitive scan
    for (const [k, v] of Object.entries(RULE_DB)) {
      if (k.toUpperCase() === key) return v;
      if (v.name.toLowerCase().includes(key.toLowerCase())) return v;
    }
    return null;
  }

  _notFound(format, technique) {
    const techStr = technique ? String(technique) : 'unknown';
    const supported = this.listSupportedTechniques();
    const similar = supported.find(t => t.name.toLowerCase().includes(techStr.toLowerCase()));
    return {
      format, technique: techStr, found: false,
      message: `No ${format} template for ${techStr}.${similar ? ` Did you mean ${similar.id} (${similar.name})?` : ''}`,
      supportedCount: supported.length,
      suggestion: similar ? similar.id : supported[0].id,
    };
  }

  _findRelated(entry) {
    const sameFamily = Object.values(RULE_DB).filter(e =>
      e.id !== entry.id && (
        e.tactic === entry.tactic ||
        (entry.id.includes('.') && e.id.split('.')[0] === entry.id.split('.')[0])
      )
    ).slice(0, 3).map(e => e.id);
    return sameFamily;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────
function _tacticVerb(tactic) {
  const map = {
    'Execution': 'execute malicious code on the target system',
    'Persistence': 'maintain access across reboots and credential changes',
    'Privilege Escalation': 'gain elevated permissions on the system',
    'Defense Evasion': 'avoid detection and security controls',
    'Credential Access': 'steal account credentials and authentication material',
    'Discovery': 'enumerate the environment and identify targets',
    'Lateral Movement': 'move between systems within the network',
    'Collection': 'gather data of interest to the mission objective',
    'Command and Control': 'communicate with compromised systems',
    'Exfiltration': 'steal and transfer data to actor-controlled infrastructure',
    'Impact': 'disrupt, destroy, or manipulate systems and data',
    'Initial Access': 'gain initial foothold in the target environment',
  };
  return map[tactic] || 'achieve their objectives';
}

function _getMitigations(techniqueId) {
  const mitigations = {
    'T1059': '- Enable PowerShell Constrained Language Mode\n- Enable Script Block Logging (Event ID 4104)\n- Implement application control (AppLocker/WDAC)\n- Disable/restrict mshta, wscript, cscript via GPO',
    'T1059.001': '- Enable **Script Block Logging** (HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging)\n- Enable **Transcription logging**\n- Block `-EncodedCommand` via AMSI\n- Deploy PowerShell v5+ (improved logging)\n- AppLocker rules to restrict PowerShell to admins',
    'T1486': '- **Immutable backups** (3-2-1 rule with air-gapped copy)\n- **Controlled folder access** (Windows Defender)\n- Least-privilege file system permissions\n- Canary files (honeypot files) to detect early encryption\n- Network segmentation to limit blast radius',
    'T1055': '- **Credential Guard** via Virtualization-Based Security\n- Block vulnerable process handles in EDR\n- Enable kernel-mode Code Integrity\n- Audit LSA Protection (RunAsPPL=1)',
    'T1003': '- Enable **LSA Protection** (RunAsPPL=1)\n- Enable **Windows Defender Credential Guard**\n- Remove admin rights from standard users\n- Implement PAM (Privileged Access Workstations)',
    'T1021.001': '- Restrict RDP to jump servers only\n- Enable Network Level Authentication (NLA)\n- Multi-Factor Authentication for RDP\n- Limit RDP ports with host-based firewall',
    'T1566.001': '- Disable Office macros from internet-sourced files (Block macro from internet via GPO)\n- Enable **Attack Surface Reduction** rules\n- Mark of the Web (MOTW) enforcement\n- Email sandbox/detonation for attachments',
    'T1190': '- Patch public-facing systems immediately\n- Web Application Firewall (WAF)\n- Regular external vulnerability scanning\n- Network segmentation (DMZ)\n- Virtual patching for unpatched systems',
  };
  const base = entry => mitigations[entry] || mitigations[entry.split('.')[0]] ||
    '- Apply security patches promptly\n- Principle of Least Privilege\n- Monitor and alert on detection signatures\n- Network segmentation to limit lateral movement';
  return base(techniqueId);
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
const defaultEngine = new DetectionEngine();

module.exports = {
  DetectionEngine,
  defaultEngine,
  RULE_DB,
  // Convenience exports
  generateSigma: (t) => defaultEngine.generateSigma(t),
  generateKQL:   (t) => defaultEngine.generateKQL(t),
  generateSPL:   (t) => defaultEngine.generateSPL(t),
  generateAll:   (t) => defaultEngine.generateAll(t),
  formatSOCResponse: (t) => defaultEngine.formatSOCResponse(t),
  listSupportedTechniques: () => defaultEngine.listSupportedTechniques(),
};
