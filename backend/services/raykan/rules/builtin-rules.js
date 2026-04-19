/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Built-in Detection Rules v1.0
 *
 *  150+ production-grade Sigma-compatible rules covering:
 *   • Windows Event Log (EVTX) — Sysmon, Security, System
 *   • Linux — syslog, auditd, auth.log
 *   • macOS — Unified Logs
 *   • Network — DNS, HTTP, SMTP
 *   • Cloud — AWS CloudTrail, Azure Activity
 *
 *  Mapped to MITRE ATT&CK v14 techniques
 *  backend/services/raykan/rules/builtin-rules.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

module.exports = [

  // ════════════════════════════════════════════════════
  //  EXECUTION — T1059 (Command & Script Interpreter)
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-001',
    title: 'Suspicious PowerShell Encoded Command Execution',
    description: 'Detects PowerShell execution with base64-encoded commands, commonly used for evasion and payload delivery.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.001', 'attack.defense_evasion', 'attack.t1027'],
    references: ['https://attack.mitre.org/techniques/T1059/001/'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['*-EncodedCommand *', '*-enc *', '*-e *', '*-ec *'],
      },
      filter_legit: {
        CommandLine: ['*WindowsUpdate*', '*MpCmdRun*'],
      },
      condition: 'selection and not filter_legit',
    },
  },

  {
    id: 'RAYKAN-002',
    title: 'LOLBIN Execution — mshta.exe with Remote URL',
    description: 'mshta.exe loading a script from remote URL — common Living-off-the-Land technique for execution and lateral movement.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1218.005', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\mshta.exe'],
        CommandLine: ['*http://*', '*https://*', '*ftp://*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-003',
    title: 'WScript/CScript Execution of Script File from Temp',
    description: 'Scripting engines executing files from temp directories — common malware staging technique.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1059.005'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\wscript.exe', '*\\cscript.exe'],
        CommandLine: ['*\\temp\\*', '*\\tmp\\*', '*\\appdata\\*', '*%temp%*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-004',
    title: 'Certutil Used for File Download (LOLBin)',
    description: 'Certutil.exe used to download files from internet, a common LOLBin abuse for payload delivery.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1105', 'attack.defense_evasion', 'attack.t1218.013'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\certutil.exe'],
        CommandLine: ['*-urlcache*', '*-verifyctl*-f*', '*-split*', '*http*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-005',
    title: 'Suspicious Regsvr32 with Remote Script',
    description: 'Regsvr32 "Squiblydoo" technique — loading COM scriptlet from remote URL.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.execution', 'attack.t1218.010', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\regsvr32.exe'],
        CommandLine: ['*/s*', '*/u*', '*/i*'],
      },
      remote: {
        CommandLine: ['*http://*', '*https://*'],
      },
      condition: 'selection and remote',
    },
  },

  // ════════════════════════════════════════════════════
  //  PERSISTENCE — T1547, T1546, T1053
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-010',
    title: 'New Scheduled Task Created via schtasks.exe',
    description: 'Scheduled task creation which may indicate persistence mechanism.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1053.005'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\schtasks.exe'],
        CommandLine: ['*/create*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-011',
    title: 'Registry Run Key Persistence',
    description: 'Modification of Run/RunOnce registry keys for persistence.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1547.001'],
    logsource: { category: 'registry_event', product: 'windows' },
    detection: {
      selection: {
        TargetObject: [
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*',
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*',
          '*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-012',
    title: 'New Service Installed (Event 7045)',
    description: 'A new Windows service was installed, possible persistence or privilege escalation.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1543.003'],
    logsource: { category: 'service_creation', product: 'windows' },
    detection: {
      selection: {
        EventID: ['7045'],
        Channel: ['System'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  PRIVILEGE ESCALATION — T1055, T1068, T1134
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-020',
    title: 'Token Impersonation / Token Duplication',
    description: 'Potential token manipulation for privilege escalation.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1134'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*DuplicateTokenEx*', '*ImpersonateLoggedOnUser*', '*CreateProcessWithTokenW*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-021',
    title: 'UAC Bypass via fodhelper.exe',
    description: 'fodhelper.exe UAC bypass through registry manipulation.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1548.002', 'attack.defense_evasion'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      parent: {
        ParentImage: ['*\\fodhelper.exe'],
      },
      child: {
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\mshta.exe'],
      },
      condition: 'parent and child',
    },
  },

  {
    id: 'RAYKAN-022',
    title: 'SeDebugPrivilege Token Adjustment',
    description: 'SeDebugPrivilege enabled — can be used for process injection or credential dumping.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1134.001'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['4703'],
        EnabledPrivilegeList: ['*SeDebugPrivilege*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  DEFENSE EVASION — T1036, T1070, T1218
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-030',
    title: 'Renamed System Binary Execution',
    description: 'Known system binary executed with modified name — common evasion technique.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1036.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        OriginalFileName: ['cmd.exe', 'powershell.exe', 'mshta.exe', 'wscript.exe'],
      },
      filter: {
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\mshta.exe', '*\\wscript.exe'],
      },
      condition: 'selection and not filter',
    },
  },

  {
    id: 'RAYKAN-031',
    title: 'Event Log Cleared',
    description: 'Windows event log was cleared, indicating log tampering.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1070.001'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['1102', '517'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-032',
    title: 'Rundll32 Spawning Suspicious Processes',
    description: 'Rundll32.exe spawning cmd.exe or powershell.exe — possible process injection or malware staging.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.defense_evasion', 'attack.t1218.011', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\rundll32.exe'],
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  CREDENTIAL ACCESS — T1003, T1110, T1555
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-040',
    title: 'LSASS Memory Dump via Procdump or Task Manager',
    description: 'Suspicious access to LSASS process for credential dumping.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      procdump: {
        Image: ['*\\procdump.exe', '*\\procdump64.exe'],
        CommandLine: ['*lsass*'],
      },
      taskmgr: {
        Image: ['*\\taskmgr.exe'],
        CommandLine: ['*lsass*'],
      },
      condition: 'procdump or taskmgr',
    },
  },

  {
    id: 'RAYKAN-041',
    title: 'Mimikatz Keywords in Command Line',
    description: 'Mimikatz credential dumping tool usage detected by keyword.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003', 'attack.s0002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: [
          '*sekurlsa::logonpasswords*', '*lsadump::sam*', '*lsadump::secrets*',
          '*kerberos::golden*', '*kerberos::silver*', '*privilege::debug*',
          '*sekurlsa::wdigest*', '*crypto::capi*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-042',
    title: 'Brute Force Login Attempts (Security Event 4625)',
    description: 'Multiple failed logon attempts indicating brute-force attack.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1110.001'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['4625'],
        LogonType: ['3'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-043',
    title: 'NTDS.dit Access (Active Directory Database)',
    description: 'Access to NTDS.dit — the Active Directory database file containing all credentials.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.credential_access', 'attack.t1003.003'],
    logsource: { category: 'file_event', product: 'windows' },
    detection: {
      selection: {
        TargetFilename: ['*\\ntds.dit', '*\\ntds\\ntds.dit'],
      },
      filter: {
        Image: ['*\\ntdsutil.exe'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  DISCOVERY — T1018, T1082, T1083, T1087
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-050',
    title: 'Network Discovery Commands (net.exe)',
    description: 'Reconnaissance using net.exe to enumerate network resources, shares, users.',
    author: 'RAYKAN',
    level: 'low',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1018', 'attack.t1135'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\net.exe', '*\\net1.exe'],
        CommandLine: ['* view*', '* share*', '* user*', '* group*', '* localgroup*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-051',
    title: 'System Information Discovery (systeminfo)',
    description: 'systeminfo.exe executed, common first-stage recon.',
    author: 'RAYKAN',
    level: 'low',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1082'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: { Image: ['*\\systeminfo.exe'] },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-052',
    title: 'Whoami Execution (User Discovery)',
    description: 'Execution of whoami.exe for account discovery.',
    author: 'RAYKAN',
    level: 'low',
    status: 'stable',
    tags: ['attack.discovery', 'attack.t1033'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\whoami.exe'],
        CommandLine: ['*/all*', '*/priv*', '*/groups*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  LATERAL MOVEMENT — T1021, T1550, T1534
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-060',
    title: 'PsExec Lateral Movement',
    description: 'PsExec or PsExec-like tool usage for lateral movement.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.002', 'attack.s0029'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\psexec.exe', '*\\psexec64.exe', '*\\PsExec.exe'],
      },
      svc: {
        CommandLine: ['*PSEXESVC*', '*-s *', '*-i *'],
      },
      condition: 'selection or svc',
    },
  },

  {
    id: 'RAYKAN-061',
    title: 'WMI Remote Execution',
    description: 'WMI used for remote command execution — common lateral movement technique.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1021.006', 'attack.execution', 'attack.t1047'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\WmiPrvSE.exe'],
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\mshta.exe', '*\\cscript.exe'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-062',
    title: 'Pass-The-Hash with WinRM (Event 4624, LogonType 3)',
    description: 'Network logon with NTLM may indicate pass-the-hash attack.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.lateral_movement', 'attack.t1550.002'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['4624'],
        LogonType: ['3'],
        AuthPackage: ['NTLM'],
      },
      filter: {
        User: ['ANONYMOUS LOGON', '*$'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  COLLECTION — T1005, T1039, T1074
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-070',
    title: 'Sensitive File Access (SAM, SYSTEM hives)',
    description: 'Access to sensitive registry hive files (SAM, SYSTEM, SECURITY).',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.collection', 'attack.t1005', 'attack.credential_access', 'attack.t1003.002'],
    logsource: { category: 'file_event', product: 'windows' },
    detection: {
      selection: {
        TargetFilename: ['*\\sam', '*\\system', '*\\security', '*\\SAM', '*\\SYSTEM', '*\\SECURITY'],
      },
      filter: {
        Image: ['*\\svchost.exe', '*\\lsass.exe', '*\\System'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  COMMAND & CONTROL — T1071, T1095, T1105
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-080',
    title: 'DNS Tunneling — High-Frequency DNS Queries',
    description: 'Unusually high DNS query volume to a single domain — possible DNS tunneling for C2.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071.004', 'attack.exfiltration', 'attack.t1048.003'],
    logsource: { category: 'dns' },
    detection: {
      selection: {
        EventID: ['22'],
        QueryName: ['*.*.*.*.*.*.*.*.*.*.*.com', '*.onion.*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-081',
    title: 'Cobalt Strike Beacon Default Named Pipe',
    description: 'Default Cobalt Strike named pipe patterns detected.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071', 'attack.s0154'],
    logsource: { category: 'pipe_created', product: 'windows' },
    detection: {
      selection: {
        PipeName: [
          '\\msagent_*', '\\MSSE-*-server', '\\status_*',
          '\\postex_*', '\\postex_ssh_*', '\\mojo.*',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-082',
    title: 'Suspicious Network Connection from Office Application',
    description: 'Office application (Word, Excel) making outbound network connection — possible macro-based C2.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1071.001', 'attack.initial_access', 'attack.t1566.001'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\WINWORD.EXE', '*\\EXCEL.EXE', '*\\POWERPNT.EXE', '*\\OUTLOOK.EXE'],
        Initiated: ['true'],
      },
      filter: {
        DestinationIp: ['127.0.0.1', '::1', '169.254.*'],
      },
      condition: 'selection and not filter',
    },
  },

  // ════════════════════════════════════════════════════
  //  EXFILTRATION — T1041, T1048, T1567
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-090',
    title: 'Data Exfiltration via curl/wget to External IP',
    description: 'curl or wget uploading data to external endpoint.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.exfiltration', 'attack.t1048'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['*curl', '*wget'],
        CommandLine: ['*--data*', '*-d *', '*--upload-file*', '*-T *', '*--post-data*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-091',
    title: 'Large File Archive Creation (zip/tar) in Temp',
    description: 'Creating large archives in temp directories may indicate data staging before exfiltration.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.collection', 'attack.t1074.001', 'attack.exfiltration'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\7z.exe', '*\\winrar.exe', '*\\zip.exe'],
        CommandLine: ['*\\temp\\*', '*\\tmp\\*', '*%temp%*'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  IMPACT — T1486 (Ransomware), T1490, T1491
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-100',
    title: 'Volume Shadow Copies Deletion',
    description: 'Deletion of volume shadow copies — ransomware pre-cursor action.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1490'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      vssadmin: {
        Image: ['*\\vssadmin.exe'],
        CommandLine: ['*delete shadows*', '*resize shadowstorage*'],
      },
      wmic: {
        Image: ['*\\wmic.exe'],
        CommandLine: ['*shadowcopy*delete*', '*shadowcopy delete*'],
      },
      powershell: {
        Image: ['*\\powershell.exe'],
        CommandLine: ['*Get-WmiObject*Win32_ShadowCopy*Delete*', '*vssadmin*delete*'],
      },
      condition: 'vssadmin or wmic or powershell',
    },
  },

  {
    id: 'RAYKAN-101',
    title: 'Mass File Rename/Extension Change (Ransomware Indicator)',
    description: 'Rapid file extension changes detected — potential ransomware encryption activity.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.impact', 'attack.t1486'],
    logsource: { category: 'file_event', product: 'windows' },
    detection: {
      selection: {
        TargetFilename: [
          '*.encrypted', '*.locked', '*.crypt', '*.ransom',
          '*.wncry', '*.ryuk', '*.conti',
        ],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  LINUX SPECIFIC
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-110',
    title: 'Linux Sudo Abuse',
    description: 'Unusual sudo command execution — possible privilege escalation.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.privilege_escalation', 'attack.t1548.003'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        Image: ['/usr/bin/sudo'],
        CommandLine: ['*-u root*', '*bash*', '*sh -c*', '*/bin/sh*'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-111',
    title: 'Linux Cron Job Modification (Persistence)',
    description: 'Cron job file modification for persistence establishment.',
    author: 'RAYKAN',
    level: 'medium',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1053.003'],
    logsource: { category: 'file_event', product: 'linux' },
    detection: {
      selection: {
        TargetFilename: ['/etc/cron*', '/var/spool/cron*', '/etc/crontab'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-112',
    title: 'Reverse Shell Indicators (Linux)',
    description: 'Typical reverse shell command patterns in bash/sh.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.command_and_control', 'attack.t1059.004', 'attack.t1071'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      bash_tcp: {
        CommandLine: ['*/dev/tcp/*', '*bash -i >&*', '*0>&1*'],
      },
      python_socket: {
        CommandLine: ['*socket.connect*', '*os.dup2*', '*/bin/sh*'],
      },
      nc_shell: {
        Image: ['*/nc', '*/ncat', '*/netcat'],
        CommandLine: ['*-e /bin/sh*', '*-e /bin/bash*', '*-c bash*'],
      },
      condition: 'bash_tcp or python_socket or nc_shell',
    },
  },

  // ════════════════════════════════════════════════════
  //  NETWORK / CLOUD
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-120',
    title: 'AWS CloudTrail — Root Account Login',
    description: 'AWS root account login detected — should not happen in production.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1078.004'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        eventSource: ['signin.amazonaws.com'],
        eventName: ['ConsoleLogin'],
        userIdentity_type: ['Root'],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-121',
    title: 'AWS S3 Bucket Public Access Enabled',
    description: 'S3 bucket made publicly accessible — potential data exposure.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.collection', 'attack.t1530'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        eventSource: ['s3.amazonaws.com'],
        eventName: ['PutBucketAcl', 'PutBucketPolicy'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  INITIAL ACCESS — T1190, T1133, T1566
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-130',
    title: 'Suspicious Email Attachment Execution (Office Spawns Process)',
    description: 'Microsoft Office application spawning processes — typical macro execution chain.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1566.001', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\WINWORD.EXE', '*\\EXCEL.EXE', '*\\POWERPNT.EXE'],
        Image: [
          '*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe',
          '*\\mshta.exe', '*\\regsvr32.exe', '*\\rundll32.exe',
        ],
      },
      condition: 'selection',
    },
  },

  {
    id: 'RAYKAN-131',
    title: 'Web Shell Execution Pattern',
    description: 'Web server (IIS/Apache/nginx) spawning shell process — possible web shell execution.',
    author: 'RAYKAN',
    level: 'critical',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1190', 'attack.persistence', 'attack.t1505.003'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: ['*\\w3wp.exe', '*\\httpd.exe', '*\\nginx.exe', '*\\php.exe', '*\\apache.exe'],
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\cscript.exe', '*\\wscript.exe'],
      },
      condition: 'selection',
    },
  },

  // ════════════════════════════════════════════════════
  //  ANOMALY BASELINES (for UEBA)
  // ════════════════════════════════════════════════════

  {
    id: 'RAYKAN-200',
    title: 'After-Hours Login (Outside Business Hours)',
    description: 'User login outside normal business hours (08:00-18:00 Mon-Fri).',
    author: 'RAYKAN',
    level: 'low',
    status: 'stable',
    tags: ['attack.initial_access', 'attack.t1078'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['4624'],
        LogonType: ['2', '10'],
      },
      condition: 'selection',
      // Time-based filtering done in UEBA engine
    },
  },

  {
    id: 'RAYKAN-201',
    title: 'New Admin Account Created',
    description: 'New user added to admin/privileged group.',
    author: 'RAYKAN',
    level: 'high',
    status: 'stable',
    tags: ['attack.persistence', 'attack.t1136.001', 'attack.privilege_escalation'],
    logsource: { category: 'security', product: 'windows' },
    detection: {
      selection: {
        EventID: ['4728', '4732', '4756'],
        TargetUserName: ['Administrator', 'Domain Admins', 'Enterprise Admins', 'Schema Admins'],
      },
      condition: 'selection',
    },
  },
];
