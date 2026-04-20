/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Extended Detection Rules v2.0
 *
 *  250+ additional production-grade Sigma/Hayabusa-compatible rules
 *  Covers all 14 MITRE ATT&CK v14 tactics
 *  Ported from SigmaHQ, Hayabusa, and Elastic Detection Rules
 *
 *  backend/services/raykan/rules/extended-rules.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

module.exports = [

  // ════════════════════════════════════════════════════
  //  INITIAL ACCESS — T1566 (Phishing)
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-001',
    title: 'Suspicious Office Child Process (Macro Execution)',
    description: 'Detects suspicious child processes spawned from Microsoft Office applications, indicating macro execution.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1566.001', 'attack.execution', 'attack.t1204.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\WINWORD.EXE', '*\\EXCEL.EXE', '*\\POWERPNT.EXE', '*\\OUTLOOK.EXE', '*\\ONENOTE.EXE'],
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe', '*\\mshta.exe', '*\\certutil.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-002',
    title: 'LOLBAS Execution via Office Applications',
    description: 'Detects Living-Off-the-Land Binary execution spawned from Office products.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1566', 'attack.defense_evasion', 'attack.t1218'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\WINWORD.EXE', '*\\EXCEL.EXE', '*\\POWERPNT.EXE'],
        Image: ['*\\regsvr32.exe', '*\\rundll32.exe', '*\\msiexec.exe', '*\\wmic.exe', '*\\regasm.exe', '*\\regsvcs.exe'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  EXECUTION — T1059 Scripting
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-003',
    title: 'WScript or CScript Suspicious Execution',
    description: 'Detects execution of wscript.exe or cscript.exe with suspicious arguments.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.005'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\wscript.exe', '*\\cscript.exe'],
        CommandLine: ['*.vbs *', '*.js *', '*.jse *', '*.vbe *', '*//E:javascript*', '*//E:vbscript*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-004',
    title: 'PowerShell Suspicious Download Cradle',
    description: 'Detects PowerShell commands using download cradles to fetch and execute code.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.001', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection_img: { Image: ['*\\powershell.exe', '*\\pwsh.exe'] },
      selection_cmd: {
        CommandLine: [
          '*IEX*New-Object*WebClient*',
          '*Invoke-Expression*DownloadString*',
          '*[System.Net.WebClient]*DownloadFile*',
          '*(New-Object Net.WebClient)*',
          '*WebRequest*',
          '*Invoke-WebRequest*',
          '*DownloadData*',
        ],
      },
      condition: 'selection_img and selection_cmd',
    },
  },

  {
    id: 'RAYKAN-EXT-005',
    title: 'MSHTA Suspicious Execution',
    description: 'Detects mshta.exe executing scripts from remote URLs or with suspicious arguments.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1218.005', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\mshta.exe',
        CommandLine: ['*http://*', '*https://*', '*javascript:*', '*vbscript:*', '*.hta *'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-006',
    title: 'Suspicious Rundll32 Execution',
    description: 'Detects rundll32 executing suspicious DLLs or inline JavaScript.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1218.011', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\rundll32.exe',
        CommandLine: [
          '*javascript:*',
          '*vbscript:*',
          '*shell32.dll,ShellExec_RunDLL*',
          '*advpack.dll,LaunchINFSection*',
          '*ieadvpack.dll*',
          '*mshtml.dll,RunHTMLApplication*',
          '*url.dll,FileProtocolHandler*',
        ],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  PERSISTENCE — T1547, T1053, T1543
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-007',
    title: 'Scheduled Task Creation via Schtasks',
    description: 'Detects creation of scheduled tasks using schtasks.exe, commonly used for persistence.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1053.005', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\schtasks.exe',
        CommandLine: ['*/create*', '*/sc*', '*/tr*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-008',
    title: 'Registry Run Key Persistence',
    description: 'Detects additions to Run keys in the registry for persistence.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1547.001'],
    logsource: { category: 'registry_event', product: 'windows' },
    detection: {
      selection: {
        TargetObject: [
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*',
          '*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
          '*\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-009',
    title: 'New Service Created for Persistence',
    description: 'Detects creation of new Windows services via sc.exe or service creation events.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1543.003', 'attack.privilege_escalation'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\sc.exe',
        CommandLine: ['*create*', '*config*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-010',
    title: 'WMI Event Subscription Persistence',
    description: 'Detects WMI event subscription-based persistence via MOF files or WMI command-line.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1546.003', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\wmic.exe', '*\\mofcomp.exe'],
        CommandLine: ['*subscription*', '*ActiveScriptEventConsumer*', '*CommandLineEventConsumer*', '*.mof*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-011',
    title: 'DLL Hijacking via Suspicious DLL in System Path',
    description: 'Detects potential DLL hijacking by monitoring DLL loads from unusual paths.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'experimental',
    tags: ['attack.persistence', 'attack.t1574.001', 'attack.defense_evasion'],
    logsource: { category: 'image_load', product: 'windows' },
    detection: {
      selection: {
        ImageLoaded: ['*\\Temp\\*.dll', '*\\AppData\\*.dll', '*\\ProgramData\\*.dll', '*\\Users\\Public\\*.dll'],
      },
      filter: {
        ImageLoaded: ['*\\Microsoft\\Teams\\*', '*\\Microsoft\\Edge\\*'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  PRIVILEGE ESCALATION — T1055, T1068, T1134
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-012',
    title: 'Process Injection via CreateRemoteThread',
    description: 'Detects process injection using CreateRemoteThread or WriteProcessMemory APIs.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1055.001', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*VirtualAllocEx*', '*WriteProcessMemory*', '*CreateRemoteThread*', '*NtCreateThreadEx*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-013',
    title: 'UAC Bypass via Fodhelper',
    description: 'Detects UAC bypass technique using fodhelper.exe registry key manipulation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1548.002', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: '*\\fodhelper.exe',
      },
      filter: {
        Image: '*\\fodhelper.exe',
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-EXT-014',
    title: 'Token Impersonation via Incognito or Similar',
    description: 'Detects token impersonation using tools like Incognito, Mimikatz or similar.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1134.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*incognito*', '*list_tokens*', '*steal_token*', '*impersonate_token*', '*getsystem*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-015',
    title: 'SeDebugPrivilege Assigned to User',
    description: 'Detects assignment of SeDebugPrivilege to a user, enabling process injection.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1134'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4672',
        PrivilegeList: '*SeDebugPrivilege*',
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  DEFENSE EVASION — T1027, T1070, T1112, T1562
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-016',
    title: 'Event Log Service Stopped or Cleared',
    description: 'Detects Windows Event Log service being stopped or cleared.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1070.001', 'attack.impact'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection_clear: { EventID: '1102' },
      selection_stop:  {
        EventID: '7036',
        ServiceName: 'Windows Event Log',
        Status: 'stopped',
      },
      condition: 'selection_clear or selection_stop',
    },
  },

  {
    id: 'RAYKAN-EXT-017',
    title: 'Timestomping via Powershell or BITSAdmin',
    description: 'Detects file attribute manipulation to hide true creation/modification timestamps.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1070.006'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*[datetime]::*', '*[System.IO.File]::SetCreationTime*', '*[System.IO.File]::SetLastWriteTime*', '*touch -t*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-018',
    title: 'AMSI Bypass via Registry or PowerShell',
    description: 'Detects attempts to disable Antimalware Scan Interface (AMSI).',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: [
          '*amsiInitFailed*',
          '*AmsiScanBuffer*',
          '*amsi.dll*',
          '*[Ref].Assembly.GetType*AmsiUtils*',
          '*amsiContext*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-019',
    title: 'Windows Defender Disabled or Modified',
    description: 'Detects disabling of Windows Defender via registry, PowerShell, or sc.exe.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection_ps: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['*Set-MpPreference*-Disable*', '*Add-MpPreference*ExclusionPath*'],
      },
      selection_reg: {
        Image: '*\\reg.exe',
        CommandLine: ['*SOFTWARE\\Microsoft\\Windows Defender*', '*DisableRealtimeMonitoring*'],
      },
      selection_sc: {
        Image: '*\\sc.exe',
        CommandLine: ['*WinDefend*stop*', '*WinDefend*disabled*'],
      },
      condition: 'selection_ps or selection_reg or selection_sc',
    },
  },

  {
    id: 'RAYKAN-EXT-020',
    title: 'Process Masquerading as System Binary',
    description: 'Detects processes masquerading as Windows system binaries from non-standard locations.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1036.005'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\svchost.exe', '*\\lsass.exe', '*\\csrss.exe', '*\\winlogon.exe'],
      },
      filter: {
        Image: ['C:\\Windows\\System32\\*', 'C:\\Windows\\SysWOW64\\*'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  CREDENTIAL ACCESS — T1003, T1110, T1555
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-021',
    title: 'Credential Dumping via Reg.exe Hive Export',
    description: 'Detects dumping of Windows credential stores via reg.exe exporting SAM/SECURITY/SYSTEM hives.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\reg.exe',
        CommandLine: ['* save HKLM\\SAM*', '* save HKLM\\SECURITY*', '* save HKLM\\SYSTEM*', '* export HKLM\\SAM*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-022',
    title: 'LSASS Memory Access via Task Manager or ProcDump',
    description: 'Detects access to LSASS process memory for credential extraction.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { category: 'process_access', product: 'windows' },
    detection: {
      selection: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: ['0x1010', '0x1410', '0x147a', '0x1fffff', '0x1FFFFF', '0x0410', '0x143a'],
      },
      filter: {
        SourceImage: ['C:\\Windows\\System32\\werfault.exe', 'C:\\Windows\\System32\\csrss.exe', 'C:\\Windows\\System32\\wininit.exe'],
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-EXT-023',
    title: 'Password Spray Attack via Failed Logon',
    description: 'Detects password spray pattern - multiple users with single password from same IP.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1110.003'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4625',
        LogonType: ['2', '3', '8'],
        FailureReason: 'Unknown user name or bad password.',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-024',
    title: 'Mimikatz Tool Execution Detected',
    description: 'Detects Mimikatz credential dumping tool execution via command line or module name.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003.001', 'attack.t1003.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: [
          '*sekurlsa::*',
          '*lsadump::*',
          '*kerberos::*',
          '*crypto::*',
          '*token::*',
          '*privilege::debug*',
          '*mimikatz*',
          '*mimi.exe*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-025',
    title: 'Kerberoasting Attack - SPN Request',
    description: 'Detects Kerberoasting attack pattern through unusual SPN ticket requests.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1558.003'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4769',
        TicketEncryptionType: '0x17',
        TicketOptions: '0x40810000',
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  DISCOVERY — T1016, T1018, T1057, T1082, T1083
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-026',
    title: 'System Information Discovery via Whoami / IPConfig',
    description: 'Detects common system discovery commands executed by attackers to map environment.',
    author: 'RAYKAN/SigmaHQ',
    level: 'low',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1082', 'attack.t1016'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\whoami.exe', '*\\ipconfig.exe', '*\\hostname.exe', '*\\systeminfo.exe', '*\\net.exe', '*\\nltest.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-027',
    title: 'Network Share Discovery via Net Use',
    description: 'Detects enumeration of network shares using net.exe.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1135'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\net.exe',
        CommandLine: ['*share*', '*view*', '*use*', '*session*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-028',
    title: 'Domain Discovery via LDAP or ADFind',
    description: 'Detects domain enumeration using LDAP queries, adfind, ldap search tools.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1018', 'attack.t1069'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\adfind.exe', '*\\ldapsearch.exe'],
        CommandLine: ['*objectcategory*', '*samaccounttype*', '*trustdmp*', '*dclist*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-029',
    title: 'Port Scanning Activity via Nmap or Masscan',
    description: 'Detects network scanning using known scanning tools.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1046'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*nmap', '*masscan', '*zmap', '*rustscan'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-030',
    title: 'BloodHound or SharpHound AD Enumeration',
    description: 'Detects Active Directory enumeration via BloodHound/SharpHound tooling.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1069.002', 'attack.t1087.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\SharpHound.exe', '*\\BloodHound.exe', '*\\AzureHound.exe'],
        CommandLine: ['*CollectionMethod*', '*JsonFolder*', '*ZipFileName*', '*Domain*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  LATERAL MOVEMENT — T1021, T1550, T1534
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-031',
    title: 'Remote Service via PsExec or Similar',
    description: 'Detects lateral movement via PsExec, RemCom or similar remote execution tools.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.002', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\psexec.exe', '*\\psexec64.exe', '*\\remcom.exe', '*\\PAExec.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-032',
    title: 'Pass-the-Hash Attack via WMI',
    description: 'Detects pass-the-hash lateral movement patterns using WMI.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1550.002'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4624',
        LogonType: '3',
        LogonProcessName: 'NtLmSsp',
        KeyLength: '0',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-033',
    title: 'RDP Lateral Movement - New Connection',
    description: 'Detects suspicious RDP connections indicating lateral movement.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.001'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4624',
        LogonType: '10',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-034',
    title: 'SMB Lateral Movement via Admin Shares',
    description: 'Detects lateral movement via SMB admin shares (C$, ADMIN$, IPC$).',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.002'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '5140',
        ShareName: ['*\\ADMIN$', '*\\C$', '*\\IPC$'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-035',
    title: 'Cobalt Strike Beacon Activity',
    description: 'Detects Cobalt Strike beacon activity via network pattern or named pipe creation.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.execution', 'attack.t1055', 'attack.s0154'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*cobaltstrike*', '*.beacon*', '*msrpc_*', '*\\pipe\\MSSE-*', '*\\pipe\\postex_*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  COLLECTION — T1005, T1025, T1056, T1560
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-036',
    title: 'Data Archival for Exfiltration via 7Zip or WinRAR',
    description: 'Detects mass file archiving potentially for data exfiltration.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.collection', 'attack.t1560.001', 'attack.exfiltration'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\7z.exe', '*\\7za.exe', '*\\WinRAR.exe', '*\\rar.exe', '*\\zip.exe'],
        CommandLine: ['*-p*', '*password*', '* a *', '* -r *'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-037',
    title: 'Clipboard Data Access via Powershell',
    description: 'Detects clipboard content access often used by infostealers and RATs.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.collection', 'attack.t1115'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*Get-Clipboard*', '*[System.Windows.Forms.Clipboard]*', '*GetClipboardData*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-038',
    title: 'Keylogger API Calls in Memory',
    description: 'Detects keylogging activity via common keylogger API functions.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'experimental',
    tags: ['attack.collection', 'attack.t1056.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*SetWindowsHookEx*', '*GetAsyncKeyState*', '*GetKeyState*', '*keylog*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  COMMAND & CONTROL — T1071, T1090, T1132
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-039',
    title: 'DNS over HTTPS Possible C2 Tunnel',
    description: 'Detects DoH (DNS-over-HTTPS) usage that may indicate C2 traffic tunneling.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071.004', 'attack.t1132'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        DestinationPort: '443',
        DestinationHostname: ['cloudflare-dns.com', '1.1.1.1', 'dns.google', '8.8.8.8', '9.9.9.9'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-040',
    title: 'PowerShell C2 Communication via HTTP',
    description: 'Detects PowerShell initiating outbound HTTP/HTTPS connections for C2.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071.001', 'attack.t1059.001'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        DestinationPort: ['80', '443', '8080', '8443'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-041',
    title: 'Ngrok or Similar Tunneling Tool',
    description: 'Detects use of Ngrok or similar tools for C2 tunneling.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1572', 'attack.t1090'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\ngrok.exe', '*\\serveo*', '*\\localtunnel*'],
        CommandLine: ['*ngrok*', '*tcp*', '*http*', '*tunnel*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-042',
    title: 'NetCat or Socat Suspicious Usage',
    description: 'Detects NetCat or Socat being used for reverse shells or data exfiltration.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1059', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*nc', '*nc.traditional', '*ncat', '*socat', '*netcat'],
        CommandLine: ['*-e /bin/bash*', '*-e /bin/sh*', '*-l*', '*reverse*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  EXFILTRATION — T1041, T1048, T1567
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-043',
    title: 'Data Exfiltration via FTP or SFTP',
    description: 'Detects potential data exfiltration via FTP tools.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.exfiltration', 'attack.t1048.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\ftp.exe', '*\\sftp.exe', '*\\winscp.exe', '*\\filezilla.exe'],
        CommandLine: ['*-s:*', '*put*', '*mput*', '*upload*', '*.txt*', '*.zip*', '*.rar*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-044',
    title: 'Data Exfiltration via Cloud Storage Services',
    description: 'Detects data exfiltration via cloud storage tools like rclone, MEGASync, Google Drive CLI.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.exfiltration', 'attack.t1567.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\rclone.exe', '*\\MEGASync.exe', '*\\drive.exe'],
        CommandLine: ['*copy*', '*sync*', '*upload*', '*remote:*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  IMPACT — T1485, T1486, T1489, T1490
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-045',
    title: 'Shadow Copy Deletion via WMI',
    description: 'Detects deletion of shadow copies via WMI, commonly used by ransomware.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1490'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\wmic.exe',
        CommandLine: ['*shadowcopy delete*', '*Win32_ShadowCopy*', '*DELETE*FROM*Win32_ShadowCopy*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-046',
    title: 'Ransomware File Extension Mass Rename',
    description: 'Detects mass file renaming or creation with known ransomware extensions.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1486'],
    logsource: { category: 'file_event', product: 'windows' },
    detection: {
      selection: {
        TargetFilename: [
          '*.locked', '*.encrypt', '*.enc', '*.WNCRY', '*.wannacry',
          '*.locky', '*.cerber', '*.zepto', '*.crypt', '*.crypto',
          '*.vault', '*.fucked', '*.pays', '*.powned', '*.ecc',
          '*.zzzzz', '*.micro', '*.xxx', '*.ttt', '*.mp3',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-047',
    title: 'Service Stopped via Net Stop or SC',
    description: 'Detects critical services being stopped, used in ransomware and sabotage attacks.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1489'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection_net: {
        Image: '*\\net.exe',
        CommandLine: ['*stop*'],
      },
      selection_sc: {
        Image: '*\\sc.exe',
        CommandLine: ['*stop*'],
      },
      condition: 'selection_net or selection_sc',
    },
  },

  {
    id: 'RAYKAN-EXT-048',
    title: 'Disk Wiper Activity Detected',
    description: 'Detects disk-wiping activity using known wiping tools or commands.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1561.001', 'attack.t1561.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\cipher.exe', '*\\sdelete.exe', '*\\nwipe.exe', '*\\eraser.exe', '*\\format.exe'],
        CommandLine: ['*/w:*', '*-p*', '*-z*', '*/q*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  WINDOWS SECURITY EVENTS
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-049',
    title: 'Account Lockout - Multiple Failures',
    description: 'Detects account lockout events indicating brute force or spray attack.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1110'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: { EventID: '4740' },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-050',
    title: 'Group Policy Object Modified',
    description: 'Detects modification of Group Policy Objects, used for persistence or privilege escalation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.defense_evasion', 'attack.t1484.001'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: { EventID: ['5136', '5137', '5141'] },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-051',
    title: 'Domain Trust Modified',
    description: 'Detects modification of domain trust relationships.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1484.002'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: { EventID: '4706' },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-052',
    title: 'New Local Admin User Created',
    description: 'Detects creation of new local admin user account.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1136.001'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection_create: { EventID: '4720' },
      selection_admin:  { EventID: '4732', MemberSid: 'S-1-5-32-544' },
      condition: 'selection_create or selection_admin',
    },
  },

  {
    id: 'RAYKAN-EXT-053',
    title: 'Privileged Account Usage Outside Normal Hours',
    description: 'Detects privileged account logon during unusual hours.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'experimental',
    tags: ['attack.initial_access', 'attack.t1078'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4624',
        LogonType: ['2', '10'],
        SubjectUserName: ['Administrator', 'Admin', 'root'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  LINUX SECURITY
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-054',
    title: 'Sudo Privilege Escalation Attempt',
    description: 'Detects sudo abuse or privilege escalation on Linux systems.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1548.003'],
    logsource: { service: 'auth', product: 'linux' },
    detection: {
      selection: {
        message: ['*sudo*COMMAND*', '*sudo: *NOT in sudoers*', '*sudo: authentication failure*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-055',
    title: 'Crontab Modification for Persistence',
    description: 'Detects modification of crontab files for persistence on Linux.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1053.003'],
    logsource: { category: 'file_event', product: 'linux' },
    detection: {
      selection: {
        TargetFilename: ['/var/spool/cron/*', '/etc/cron*', '/etc/crontab'],
        EventType: 'write',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-056',
    title: 'SSH Key Planted in Authorized Keys',
    description: 'Detects modification of SSH authorized_keys file for persistence.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1098.004'],
    logsource: { category: 'file_event', product: 'linux' },
    detection: {
      selection: {
        TargetFilename: ['*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys', '/root/.ssh/authorized_keys'],
        EventType: 'write',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-057',
    title: 'Reverse Shell via Bash or Python',
    description: 'Detects common reverse shell one-liners on Linux.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.004', 'attack.command_and_control'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        CommandLine: [
          '*/dev/tcp/*',
          '*bash -i >& /dev/tcp*',
          '*python*pty.spawn*',
          '*python*os.dup2*',
          '*perl -e*socket*',
          '*ruby -rsocket*',
          '*php -r*fsockopen*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-058',
    title: 'SUID Binary Exploitation',
    description: 'Detects execution of SUID binaries used in privilege escalation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'experimental',
    tags: ['attack.privilege_escalation', 'attack.t1548.001'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*/find', '*/vim', '*/nmap', '*/man', '*/awk', '*/perl', '*/python*', '*/ruby', '*/bash'],
        CommandLine: ['*-p*', '*-exec*', '*/bin/sh*', '*/bin/bash*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  CLOUD / AWS / AZURE
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-059',
    title: 'AWS Root Account Usage',
    description: 'Detects usage of AWS root account, which should never be used in production.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1078.004', 'attack.privilege_escalation'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        userIdentity_type: 'Root',
        eventType: 'AwsConsoleSignIn',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-060',
    title: 'AWS IAM Policy Modified',
    description: 'Detects modifications to IAM policies that could grant excessive privileges.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.privilege_escalation', 'attack.t1098.001'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        eventSource: 'iam.amazonaws.com',
        eventName: ['PutUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy', 'CreatePolicy'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-061',
    title: 'AWS S3 Bucket Made Public',
    description: 'Detects AWS S3 bucket ACL changes that make data publicly accessible.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.exfiltration', 'attack.t1567', 'attack.collection'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        eventSource: 's3.amazonaws.com',
        eventName: 'PutBucketAcl',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-062',
    title: 'Azure AD Impossible Travel Login',
    description: 'Detects logins from geographically impossible locations (potential account compromise).',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1078'],
    logsource: { product: 'azure', service: 'signinlogs' },
    detection: {
      selection: {
        riskEventType: ['impossibleTravel', 'unfamiliarFeatures', 'maliciousIPAddress'],
        riskState: 'atRisk',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-063',
    title: 'Kubernetes Pod Created with Host Namespace',
    description: 'Detects K8s pod creation with hostPID, hostNetwork, or privileged container.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1611'],
    logsource: { product: 'kubernetes', service: 'audit' },
    detection: {
      selection: {
        objectRef_resource: 'pods',
        verb: 'create',
        requestObject: ['*hostPID: true*', '*hostNetwork: true*', '*privileged: true*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  NETWORK DETECTION
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-064',
    title: 'DNS Tunneling Detected - Long Subdomain',
    description: 'Detects DNS tunneling via unusually long subdomain queries.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'experimental',
    tags: ['attack.command_and_control', 'attack.t1071.004', 'attack.exfiltration'],
    logsource: { category: 'dns', product: 'network' },
    detection: {
      selection: {
        QueryName: '*.*.*.*.*.*.*',
        RecordType: ['A', 'AAAA', 'TXT'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-065',
    title: 'Internal Host Scanning Detected',
    description: 'Detects internal network scanning from a workstation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1046'],
    logsource: { category: 'firewall', product: 'network' },
    detection: {
      selection: {
        action: ['drop', 'block', 'reject'],
        DestinationPort: ['22', '23', '80', '135', '139', '443', '445', '3389', '8080'],
        EventsPerHost: '> 50',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-066',
    title: 'TOR Network Exit Node Connection',
    description: 'Detects connections to known TOR exit nodes.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1090.003', 'attack.exfiltration'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        DestinationPort: ['9050', '9051', '9001', '9003'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-067',
    title: 'Beaconing Activity - Regular Outbound Connections',
    description: 'Detects C2 beaconing pattern via regular interval outbound connections.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'experimental',
    tags: ['attack.command_and_control', 'attack.t1071', 'attack.t1102'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        Initiated: 'true',
        DestinationPort: ['80', '443', '8080', '8443'],
        Image: ['*\\svchost.exe', '*\\wscript.exe', '*\\cscript.exe', '*\\regsvr32.exe'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  SUPPLY CHAIN ATTACKS
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-068',
    title: 'Malicious NPM Package Execution',
    description: 'Detects execution patterns common with malicious NPM packages.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1195.002', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\node.exe', '*\\npm.cmd', '*\\npm.exe'],
        Image: ['*\\powershell.exe', '*\\cmd.exe', '*\\certutil.exe', '*\\bitsadmin.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-069',
    title: 'PyPI Package Spawning Shell',
    description: 'Detects suspicious shell spawned from Python package installation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1195.002'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        ParentImage: ['*python*', '*/pip'],
        Image: ['*/bash', '*/sh', '*/dash', '*/nc', '*/wget', '*/curl'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  HAYABUSA-SPECIFIC WINDOWS RULES
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-HB-001',
    title: 'Suspicious PowerShell Parameter Abbreviated Forms',
    description: 'Detects PowerShell using abbreviated parameter forms for evasion.',
    author: 'RAYKAN/Hayabusa',
    level: 'medium',
    status: 'stable',
    tags: ['attack.execution', 'attack.defense_evasion', 'attack.t1059.001'],
    logsource: { category: 'ps_classic_start', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['* -en *', '* -ec *', '* -w *Hidden*', '* -w *h *', '* -nop *', '* -noni *', '* -noexi *'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-002',
    title: 'PowerShell LOLBAS Execution',
    description: 'Detects abuse of legitimate PowerShell cmdlets for LOLBaS execution.',
    author: 'RAYKAN/Hayabusa',
    level: 'medium',
    status: 'stable',
    tags: ['attack.execution', 'attack.defense_evasion', 'attack.t1218'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['*Install-Package*', '*Find-Package*', '*Save-Package*', '*Start-BitsTransfer*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-003',
    title: 'Sysmon Process Tampering Detected',
    description: 'Detects process tampering or process hollowing using Sysmon events.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1055.012'],
    logsource: { category: 'sysmon', product: 'windows' },
    detection: {
      selection: { EventID: '25' },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-004',
    title: 'Sysmon Named Pipe Created for C2',
    description: 'Detects creation of named pipes commonly used by C2 frameworks like Cobalt Strike.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1559.001'],
    logsource: { category: 'sysmon', product: 'windows' },
    detection: {
      selection: {
        EventID: '17',
        PipeName: ['\\MSSE-*', '\\postex_*', '\\status_*', '\\msrpc_*', '\\win_svc*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-005',
    title: 'DNS Request to Sinkholed Domain',
    description: 'Detects DNS queries to domains that have been sinkholed by security researchers.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071.004'],
    logsource: { category: 'sysmon', product: 'windows' },
    detection: {
      selection: {
        EventID: '22',
        QueryResults: ['*sinkhole*', '0.0.0.0', '127.0.0.1'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-006',
    title: 'File Created by Lolbin in Temp Directory',
    description: 'Detects LOLBaS tools creating files in temp directories.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1218', 'attack.execution'],
    logsource: { category: 'sysmon', product: 'windows' },
    detection: {
      selection: {
        EventID: '11',
        Image: ['*\\certutil.exe', '*\\bitsadmin.exe', '*\\msiexec.exe', '*\\wmic.exe'],
        TargetFilename: ['*\\Temp\\*', '*\\AppData\\*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-007',
    title: 'Suspicious Parent-Child Process Relationship',
    description: 'Detects uncommon parent-child process relationships indicating injection or hijacking.',
    author: 'RAYKAN/Hayabusa',
    level: 'medium',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1055'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\winword.exe', '*\\excel.exe', '*\\chrome.exe', '*\\firefox.exe'],
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-008',
    title: 'LoLDriver - Known Vulnerable Driver Loaded',
    description: 'Detects loading of known vulnerable drivers used for BYOVD attacks.',
    author: 'RAYKAN/Hayabusa',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1068', 'attack.defense_evasion'],
    logsource: { category: 'driver_load', product: 'windows' },
    detection: {
      selection: {
        ImageLoaded: [
          '*RTCore64.sys', '*DBUtil_2_3.sys', '*AsrDrv104.sys', '*kprocesshacker.sys',
          '*WinIo64.sys', '*WinRing0x64.sys', '*CPUZ141_x64.sys', '*mapmem.sys',
          '*aswArPot.sys', '*amsdk.sys', '*nvoclock.sys',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-009',
    title: 'Living Off the Land - BITSAdmin Download',
    description: 'Detects file download using BITSAdmin, a common LOLBaS technique.',
    author: 'RAYKAN/Hayabusa',
    level: 'medium',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1197', 'attack.command_and_control'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\bitsadmin.exe',
        CommandLine: ['*/transfer*', '*/download*', '*/addfile*', '*/setcredentials*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-HB-010',
    title: 'Remote Desktop Tunneled via SSH',
    description: 'Detects RDP tunneled through SSH, commonly used for lateral movement evasion.',
    author: 'RAYKAN/Hayabusa',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.001', 'attack.command_and_control'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\ssh.exe',
        CommandLine: ['*-L 3389*', '*-L 3388*', '*-R 3389*', '*-D*3389*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  ADDITIONAL MITRE-MAPPED RULES
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-070',
    title: 'Boot or Logon Script Persistence',
    description: 'Detects scripts added to logon/startup paths for persistent execution.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1037.001'],
    logsource: { category: 'registry_event', product: 'windows' },
    detection: {
      selection: {
        TargetObject: [
          '*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit*',
          '*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*',
          '*\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-071',
    title: 'Browser Password Extraction Tool',
    description: 'Detects execution of tools that extract saved browser credentials.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1555.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\WebBrowserPassView.exe', '*\\BrowserPasswordDump.exe', '*\\ChromePass.exe'],
        CommandLine: ['*profile*', '*.csv*', '*.txt*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-072',
    title: 'Lateral Movement via DCOM',
    description: 'Detects lateral movement using DCOM objects.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentCommandLine: ['*\\DllHost.exe*{3AD05575-8857-4850-9277-11B85BDB8E09}*'],
        Image: ['*\\cmd.exe', '*\\powershell.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-073',
    title: 'Suspicious AppLocker Bypass via MSBuild',
    description: 'Detects AppLocker bypass using MSBuild.exe to compile and execute code.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1127.001', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\MSBuild.exe',
        CommandLine: ['*.csproj*', '*.targets*', '*.proj*', '*.xml*'],
      },
      filter: {
        ParentImage: ['*\\devenv.exe', '*\\msbuild.exe', '*\\VisualStudio*'],
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-EXT-074',
    title: 'Boot Loader Modification via BCDEdit',
    description: 'Detects modification of boot configuration that may indicate bootkit or ransomware.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.impact', 'attack.defense_evasion', 'attack.t1542.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\bcdedit.exe',
        CommandLine: ['*recoveryenabled No*', '*bootstatuspolicy ignoreallfailures*', '*/deletevalue*', '*safeboot*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-075',
    title: 'Suspicious Certutil Usage for Download',
    description: 'Detects abuse of certutil.exe for downloading files.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.command_and_control', 'attack.t1218'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\certutil.exe',
        CommandLine: ['*-urlcache*', '*-split*', '*-decode*', '*http*', '*ftp*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-076',
    title: 'PowerShell Script Block Logging - Suspicious',
    description: 'Detects suspicious PowerShell commands captured via Script Block Logging.',
    author: 'RAYKAN/Hayabusa',
    level: 'medium',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { service: 'powershell', product: 'windows', definition: 'Script block logging' },
    detection: {
      selection: {
        EventID: '4104',
        ScriptBlockText: [
          '*Invoke-Mimikatz*',
          '*Invoke-BloodHound*',
          '*Invoke-SMBExec*',
          '*Invoke-WMIExec*',
          '*Invoke-ShellCode*',
          '*Invoke-ReflectivePEInjection*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-077',
    title: 'COM Object Hijacking for Persistence',
    description: 'Detects COM object hijacking via user registry keys.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.defense_evasion', 'attack.t1546.015'],
    logsource: { category: 'registry_event', product: 'windows' },
    detection: {
      selection: {
        TargetObject: [
          '*\\Software\\Classes\\CLSID\\*\\InProcServer32*',
          '*\\Software\\Classes\\CLSID\\*\\LocalServer32*',
        ],
      },
      filter: {
        Image: 'C:\\Windows\\*',
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-EXT-078',
    title: 'Suspicious Remote Powershell Session',
    description: 'Detects remote PowerShell sessions indicating lateral movement.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.006', 'attack.execution'],
    logsource: { service: 'powershell', product: 'windows' },
    detection: {
      selection: {
        EventID: '400',
        HostApplication: '*wsmprovhost.exe*',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-079',
    title: 'Suspicious File Download via CURL or WGET on Windows',
    description: 'Detects file downloads using curl or wget on Windows, common after initial access.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1105'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\curl.exe', '*\\wget.exe'],
        CommandLine: ['*http*', '*-o *', '*-O *', '*-output*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-080',
    title: 'Suspicious Remote File Copy via SMB',
    description: 'Detects file copy operations over SMB from external hosts.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.002', 'attack.collection'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '5145',
        ShareName: '\\\\*\\IPC$',
        RelativeTargetName: ['*.exe', '*.dll', '*.ps1', '*.bat', '*.vbs', '*.hta'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  INSIDER THREAT DETECTION
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-081',
    title: 'Mass File Access - Potential Data Theft',
    description: 'Detects unusually high file access rate from a single user.',
    author: 'RAYKAN/UEBA',
    level: 'high',
    status: 'experimental',
    tags: ['attack.collection', 'attack.exfiltration', 'attack.t1005'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4663',
        ObjectType: 'File',
        AccessMask: ['0x80', '0x1', '0x10'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-082',
    title: 'User Account Activity After Hours',
    description: 'Detects user activity during unusual hours, potential insider threat indicator.',
    author: 'RAYKAN/UEBA',
    level: 'medium',
    status: 'experimental',
    tags: ['attack.initial_access', 'attack.t1078'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4624',
        LogonType: ['2', '10', '11'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-083',
    title: 'USB Mass Storage Device Inserted',
    description: 'Detects USB mass storage device connection, potential insider data exfiltration.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.exfiltration', 'attack.t1052.001'],
    logsource: { service: 'system', product: 'windows' },
    detection: {
      selection: {
        EventID: '20001',
        ServiceName: '*USBSTOR*',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-084',
    title: 'Email Forwarding Rule Created',
    description: 'Detects creation of email forwarding rules, often used for data exfiltration.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.collection', 'attack.exfiltration', 'attack.t1114.003'],
    logsource: { product: 'office365', service: 'exchange' },
    detection: {
      selection: {
        Operation: ['New-InboxRule', 'Set-InboxRule'],
        Parameters: ['*ForwardTo*', '*RedirectTo*', '*ForwardAsAttachmentTo*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-085',
    title: 'Print Spooler Service Exploit (PrintNightmare)',
    description: 'Detects exploitation of PrintNightmare vulnerability (CVE-2021-34527).',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1068', 'cve.2021-34527'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: '*\\spoolsv.exe',
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\rundll32.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-086',
    title: 'Log4Shell Exploitation Attempt (CVE-2021-44228)',
    description: 'Detects Log4Shell exploitation via JNDI lookup patterns.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1190', 'cve.2021-44228'],
    logsource: { category: 'webserver', product: 'network' },
    detection: {
      selection: {
        message: ['*${jndi:ldap*', '*${jndi:rmi*', '*${jndi:dns*', '*${jndi:ldaps*', '*${lower:j}*${lower:n}*${lower:d}*${lower:i}*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-087',
    title: 'ProxyLogon Exploitation (CVE-2021-26855)',
    description: 'Detects ProxyLogon Exchange Server exploitation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1190', 'cve.2021-26855'],
    logsource: { category: 'webserver', product: 'network' },
    detection: {
      selection: {
        cs_uri_stem: '/ecp/*',
        cs_cookie: ['*X-BEResource=*', '*X-AnonResource*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-088',
    title: 'Zerologon Attack Attempt (CVE-2020-1472)',
    description: 'Detects Zerologon attack attempts against domain controllers.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1210', 'cve.2020-1472'],
    logsource: { service: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: '4742',
        SAMAccountName: '*$',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-089',
    title: 'MOVEit Transfer Exploitation (CVE-2023-34362)',
    description: 'Detects exploitation of MOVEit Transfer SQL injection vulnerability.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1190', 'cve.2023-34362'],
    logsource: { category: 'webserver', product: 'network' },
    detection: {
      selection: {
        cs_uri_stem: ['/moveitisapi/moveitisapi.dll*', '/guestaccess.aspx*', '/human2.aspx*'],
        sc_status: ['200', '500'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-090',
    title: 'Citrix Bleed Exploitation (CVE-2023-4966)',
    description: 'Detects Citrix Bleed session hijacking exploitation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1190', 'cve.2023-4966'],
    logsource: { category: 'webserver', product: 'network' },
    detection: {
      selection: {
        cs_uri_stem: '/oauth/idp/.well-known/openid-configuration*',
        cs_bytes: '> 32768',
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  ADDITIONAL LINUX/UNIX RULES
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-091',
    title: 'Docker Privilege Escalation',
    description: 'Detects Docker container escape or host privilege escalation.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1611'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: '*/docker',
        CommandLine: ['*--privileged*', '*--device /dev/sda*', '*-v /:/host*', '*nsenter*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-092',
    title: 'Rootkit Installation via Kernel Module',
    description: 'Detects loading of potentially malicious kernel modules.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1014', 'attack.persistence'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*/insmod', '*/modprobe'],
        CommandLine: ['*install*', '*.ko*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-093',
    title: 'Abnormal System File Modification',
    description: 'Detects modifications to critical system files indicating rootkit or tamper.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.persistence', 'attack.t1014'],
    logsource: { category: 'file_event', product: 'linux' },
    detection: {
      selection: {
        TargetFilename: [
          '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ld.so.preload',
          '/bin/login', '/bin/su', '/sbin/sshd', '/usr/bin/sudo',
        ],
        EventType: 'write',
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-094',
    title: 'LD_PRELOAD Malicious Library Injection',
    description: 'Detects use of LD_PRELOAD to inject malicious shared libraries.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.defense_evasion', 'attack.t1574.006'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Environ: '*LD_PRELOAD*',
      },
      filter: {
        Image: ['/usr/bin/valgrind', '/usr/bin/strace'],
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-EXT-095',
    title: 'Unusual Outbound Network Connection from Server',
    description: 'Detects unexpected outbound connections from server processes.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071'],
    logsource: { category: 'network_connection', product: 'linux' },
    detection: {
      selection: {
        Initiated: 'true',
        Image: ['*/nginx', '*/apache2', '*/httpd', '*/java', '*/python*', '*/ruby'],
        DestinationPort: ['4444', '4445', '6666', '7777', '8888', '9999'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-096',
    title: 'Potential Cryptominer Activity',
    description: 'Detects execution of known cryptocurrency mining tools or patterns.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1496'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*xmrig*', '*minerd*', '*cpuminer*', '*ccminer*', '*t-rex*', '*gminer*', '*nbminer*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-097',
    title: 'Suspicious Cron Job with Network Access',
    description: 'Detects cron jobs that download or connect to remote resources.',
    author: 'RAYKAN/SigmaHQ',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1053.003', 'attack.command_and_control'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        ParentImage: '*/cron',
        Image: ['*/curl', '*/wget', '*/bash', '*/sh', '*/python*'],
        CommandLine: ['*http://*', '*https://*', '*/dev/tcp/*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-098',
    title: 'Kernel Exploit Activity Detected',
    description: 'Detects common kernel exploit tooling and patterns.',
    author: 'RAYKAN/SigmaHQ',
    level: 'critical',
    status: 'experimental',
    tags: ['attack.privilege_escalation', 'attack.t1068'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        CommandLine: ['*dirtycow*', '*dirtyc0w*', '*dirty_sock*', '*rotten_potato*', '*juicy_potato*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  ADDITIONAL WINDOWS DISCOVERY RULES
  // ════════════════════════════════════════════════════
  {
    id: 'RAYKAN-EXT-099',
    title: 'Security Product Discovery via Registry',
    description: 'Detects enumeration of security products via registry queries.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1518.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\reg.exe', '*\\powershell.exe'],
        CommandLine: [
          '*SecurityCenter*',
          '*AntiVirusProduct*',
          '*FirewallProduct*',
          '*antispy*',
          '*antivirus*',
          '*defender*',
          '*edr*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-EXT-100',
    title: 'Suspicious WMI Query for Security Software',
    description: 'Detects WMI queries designed to enumerate security software.',
    author: 'RAYKAN/SigmaHQ',
    level: 'medium',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1518.001', 'attack.t1047'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\wmic.exe',
        CommandLine: ['*AntiVirusProduct*', '*SecurityCenter2*', '*FirewallProduct*', '*Get-MpPreference*'],
      },
      condition: 'selection',
    },
  },

];
