/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Sigma Rule Builder  v2.0
 *
 *  Provides:
 *   • Input sanitization: strips natural-language instructions,
 *     extracts only security-relevant keywords (max 3-word phrases)
 *   • Detection template engine: predefined selection blocks that
 *     map attacker intents to known-good behavioral indicators
 *   • Behavioral indicator mapping: ransomware impact phase,
 *     credential access, defense evasion, discovery, lateral movement
 *   • Output validation: no prompt leakage, CommandLine values match
 *     known attacker behaviors or LOLBins; regenerate if invalid
 *   • Multi-condition Sigma YAML/JSON with AND/OR logic
 *   • Safety guard: reject any CommandLine containing meta-words
 *     (generate, create, rule, detect …) and regenerate
 *   • Post-processing Sigma validator ensuring rule quality
 *
 *  backend/services/raykan/sigma-rule-builder.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────
//  §1  SAFETY / META WORD GUARD
//  CommandLine values that match any of these words indicate the
//  rule was constructed from the raw prompt (injection risk).
// ─────────────────────────────────────────────────────────────────
const META_WORDS = new Set([
  'generate', 'create', 'rule', 'detect', 'write', 'build', 'make',
  'produce', 'sigma', 'yaml', 'json', 'output', 'template', 'example',
  'instruction', 'please', 'show', 'give', 'help', 'explain', 'describe',
  'how', 'what', 'why', 'when', 'write me', 'give me', 'show me',
  'can you', 'could you', 'would you', 'i want', 'i need', 'i would like',
]);

// ─────────────────────────────────────────────────────────────────
//  §2  SECURITY KEYWORD TAXONOMY
//  Only these curated keywords survive sanitization.
// ─────────────────────────────────────────────────────────────────
const SECURITY_KEYWORDS = {
  // Threat classes
  ransomware       : 'ransomware',
  crypto           : 'ransomware',
  encrypt          : 'ransomware',
  locker           : 'ransomware',
  'shadow copy'    : 'ransomware',
  vssadmin         : 'ransomware',
  wbadmin          : 'ransomware',
  bcdedit          : 'ransomware',
  recoveryenabled  : 'ransomware',
  wevtutil         : 'defense_evasion',
  taskkill         : 'impact',
  // Techniques
  mimikatz         : 'credential_access',
  sekurlsa         : 'credential_access',
  'credential dump': 'credential_access',
  lsass            : 'credential_access',
  procdump         : 'credential_access',
  'pass the hash'  : 'lateral_movement',
  psexec           : 'lateral_movement',
  wmic             : 'execution',
  mshta            : 'execution',
  regsvr32         : 'execution',
  certutil         : 'defense_evasion',
  bitsadmin        : 'defense_evasion',
  'encoded command': 'defense_evasion',
  encodedcommand   : 'defense_evasion',
  '-enc'           : 'defense_evasion',
  bypass           : 'defense_evasion',
  powershell       : 'execution',
  cmd              : 'execution',
  rundll32         : 'execution',
  regsvcs          : 'defense_evasion',
  msiexec          : 'execution',
  schtasks         : 'persistence',
  'at.exe'         : 'persistence',
  registry         : 'persistence',
  'run key'        : 'persistence',
  startup          : 'persistence',
  'lateral movement': 'lateral_movement',
  'admin shares'   : 'lateral_movement',
  'net use'        : 'lateral_movement',
  cobalt           : 'command_and_control',
  beacon           : 'command_and_control',
  dns              : 'command_and_control',
  exfil            : 'exfiltration',
  upload           : 'exfiltration',
  discovery        : 'discovery',
  'net group'      : 'discovery',
  'net localgroup' : 'discovery',
  whoami           : 'discovery',
  ipconfig         : 'discovery',
  systeminfo       : 'discovery',
  // Malware families
  wannacry         : 'ransomware',
  lockbit          : 'ransomware',
  blackcat         : 'ransomware',
  ryuk             : 'ransomware',
  revil            : 'ransomware',
  conti            : 'ransomware',
  // Log sources
  evtx             : null,
  sysmon           : null,
  'event log'      : null,
  'windows event'  : null,
};

// ─────────────────────────────────────────────────────────────────
//  §3  INTENT → PHASE MAP
//  Maps extracted intent token to MITRE ATT&CK tactic / template key.
// ─────────────────────────────────────────────────────────────────
const INTENT_PHASE_MAP = {
  ransomware          : 'impact',
  credential_access   : 'credential_access',
  lateral_movement    : 'lateral_movement',
  defense_evasion     : 'defense_evasion',
  execution           : 'execution',
  persistence         : 'persistence',
  discovery           : 'discovery',
  exfiltration        : 'exfiltration',
  command_and_control : 'command_and_control',
  impact              : 'impact',
};

// ─────────────────────────────────────────────────────────────────
//  §4  DETECTION TEMPLATE LIBRARY
//
//  Each template is a complete, behavior-based Sigma rule object.
//  CommandLine values are derived exclusively from known attacker
//  commands / LOLBins — NEVER from user-supplied text.
//
//  Template keys match the phase names in INTENT_PHASE_MAP.
// ─────────────────────────────────────────────────────────────────
const DETECTION_TEMPLATES = {

  // ── 4.1  IMPACT — Ransomware ──────────────────────────────────
  impact: {
    title      : 'Ransomware Impact Phase — Shadow Copy Deletion and Recovery Disabling',
    description: 'Detects the ransomware impact phase characterized by deletion of shadow copies, backup catalog destruction, recovery disabling, log clearing, and mass process termination used by ransomware families such as LockBit, BlackCat, Ryuk, and Conti.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'critical',
    status     : 'stable',
    tags       : [
      'attack.impact',
      'attack.t1490',    // Inhibit System Recovery
      'attack.t1489',    // Service Stop
      'attack.t1485',    // Data Destruction
    ],
    references : [
      'https://attack.mitre.org/techniques/T1490/',
      'https://attack.mitre.org/techniques/T1489/',
      'https://thedfirreport.com/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate administrator performing system maintenance',
      'Authorized backup software (Veeam, Acronis) in unusual configuration',
    ],
    detection  : {
      selection_backup_deletion: {
        CommandLine: [
          '*vssadmin* delete shadows*',
          '*vssadmin* resize shadowstorage*',
          '*wbadmin* delete catalog*',
          '*wbadmin* delete systemstatebackup*',
        ],
      },
      selection_boot_modification: {
        CommandLine: [
          '*bcdedit* /set* recoveryenabled no*',
          '*bcdedit* /set* bootstatuspolicy ignoreallfailures*',
          '*bcdedit* /set* safeboot*',
        ],
      },
      selection_log_clearing: {
        CommandLine: [
          '*wevtutil* cl *',
          '*wevtutil* clear-log *',
          '*Clear-EventLog*',
        ],
      },
      selection_process_kill: {
        CommandLine: [
          '*taskkill* /f*',
          '*taskkill* /im* sql*',
          '*taskkill* /im* oracle*',
          '*taskkill* /im* backup*',
          '*net* stop* veeam*',
          '*net* stop* backup*',
          '*net* stop* mssql*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.2  CREDENTIAL ACCESS ────────────────────────────────────
  credential_access: {
    title      : 'Credential Access — LSASS Memory Dump and Credential Extraction',
    description: 'Detects credential dumping from LSASS memory using Mimikatz, ProcDump, Task Manager, or custom tools targeting Windows credential stores.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.credential_access',
      'attack.t1003.001',  // OS Credential Dumping: LSASS Memory
      'attack.t1003.002',  // OS Credential Dumping: SAM
    ],
    references : [
      'https://attack.mitre.org/techniques/T1003/001/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Windows Debugging tools in authorized security testing',
      'Endpoint protection software doing memory scans',
    ],
    detection  : {
      selection_mimikatz: {
        CommandLine: [
          '*mimikatz*',
          '*sekurlsa::*',
          '*lsadump::*',
          '*kerberos::*',
        ],
      },
      selection_procdump_lsass: {
        CommandLine: [
          '*procdump* -ma* lsass*',
          '*procdump* lsass*',
          '*rundll32*comsvcs*MiniDump*',
        ],
      },
      selection_reg_sam: {
        CommandLine: [
          '*reg* save* hklm\\sam*',
          '*reg* save* hklm\\system*',
          '*reg* save* hklm\\security*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.3  DEFENSE EVASION ─────────────────────────────────────
  defense_evasion: {
    title      : 'Defense Evasion — PowerShell Encoded Command and AMSI Bypass',
    description: 'Detects PowerShell execution with encoded commands, AMSI bypass techniques, execution policy bypass, and LOLBin abuse for payload delivery.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.defense_evasion',
      'attack.t1059.001',  // PowerShell
      'attack.t1562.001',  // Impair Defenses: Disable or Modify Tools
    ],
    references : [
      'https://attack.mitre.org/techniques/T1059/001/',
      'https://lolbas-project.github.io/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate administration scripts using encoded commands',
      'Deployment tools (SCCM, Ansible) automating PowerShell tasks',
    ],
    detection  : {
      selection_encoded_ps: {
        CommandLine: [
          '*powershell* -enc *',
          '*powershell* -EncodedCommand *',
          '*powershell* -e *JAB*',
          '*powershell* -e *TVq*',
        ],
      },
      selection_bypass_flags: {
        CommandLine: [
          '*-ExecutionPolicy Bypass*',
          '*-ep bypass*',
          '*-nop -w hidden*',
          '*-NonInteractive -NoLogo -NoProfile -ExecutionPolicy bypass*',
        ],
      },
      selection_lolbin_download: {
        CommandLine: [
          '*certutil* -decode *',
          '*certutil* -urlcache* -f*',
          '*bitsadmin* /transfer*',
          '*regsvr32* /s /n /u /i:http*',
          '*mshta* http*',
        ],
      },
      filter_legitimate: {
        CommandLine: [
          '*Microsoft.VSCode*',
          '*WindowsPowerShell\\Modules\\*',
        ],
      },
      condition: '(1 of selection_*) and not filter_legitimate',
    },
  },

  // ── 4.4  EXECUTION ────────────────────────────────────────────
  execution: {
    title      : 'Execution — Suspicious Process Spawned by Office or Script Host',
    description: 'Detects suspicious child process execution from Microsoft Office applications, script hosts (wscript, cscript) or web-facing processes, indicating initial access or macro-based execution.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.execution',
      'attack.t1059',      // Command and Scripting Interpreter
      'attack.t1204.002',  // User Execution: Malicious File
    ],
    references : [
      'https://attack.mitre.org/techniques/T1059/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate macro-based automation tools',
      'Developer environments using Office automation',
    ],
    detection  : {
      selection_office_spawn: {
        ParentImage: [
          '*\\winword.exe',
          '*\\excel.exe',
          '*\\powerpnt.exe',
          '*\\outlook.exe',
        ],
        Image: [
          '*\\cmd.exe',
          '*\\powershell.exe',
          '*\\wscript.exe',
          '*\\cscript.exe',
          '*\\mshta.exe',
          '*\\rundll32.exe',
        ],
      },
      selection_script_host: {
        Image: [
          '*\\wscript.exe',
          '*\\cscript.exe',
        ],
        CommandLine: [
          '*.vbs*',
          '*.js*',
          '*.jse*',
          '*.vbe*',
          '*.wsf*',
        ],
      },
      selection_wmic_spawn: {
        CommandLine: [
          '*wmic* process call create*',
          '*wmic* /node:* process*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.5  PERSISTENCE ─────────────────────────────────────────
  persistence: {
    title      : 'Persistence — Scheduled Task and Registry Run Key Modification',
    description: 'Detects persistence mechanisms including scheduled task creation via schtasks, registry run key modification, and startup folder abuse.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'medium',
    status     : 'stable',
    tags       : [
      'attack.persistence',
      'attack.t1053.005',  // Scheduled Task/Job: Scheduled Task
      'attack.t1547.001',  // Boot or Logon Autostart: Registry Run Keys
    ],
    references : [
      'https://attack.mitre.org/techniques/T1053/005/',
      'https://attack.mitre.org/techniques/T1547/001/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate software installation creating scheduled tasks',
      'Endpoint management tools (SCCM, Intune) modifying registry',
    ],
    detection  : {
      selection_schtask_create: {
        CommandLine: [
          '*schtasks* /create*',
          '*schtasks* /change*',
          'schtasks*/ru SYSTEM*',
          'schtasks*/sc onstart*',
        ],
      },
      selection_reg_run_key: {
        CommandLine: [
          '*reg* add* CurrentVersion\\Run*',
          '*reg* add* CurrentVersion\\RunOnce*',
          '*reg* add* Winlogon*',
        ],
      },
      selection_startup_drop: {
        TargetFilename: [
          '*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*',
          '*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.6  LATERAL MOVEMENT ─────────────────────────────────────
  lateral_movement: {
    title      : 'Lateral Movement — PsExec and Admin Share Abuse',
    description: 'Detects lateral movement via PsExec, WMIC remote execution, admin share access, and Pass-the-Hash style authentication patterns.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.lateral_movement',
      'attack.t1570',      // Lateral Tool Transfer
      'attack.t1021.002',  // Remote Services: SMB/Windows Admin Shares
      'attack.t1077',      // Windows Admin Shares (Legacy)
    ],
    references : [
      'https://attack.mitre.org/techniques/T1021/002/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate system administration using PsExec for remote management',
      'IT helpdesk tools performing remote actions',
    ],
    detection  : {
      selection_psexec: {
        CommandLine: [
          '*psexec* \\\\*',
          '*psexec* -s*',
          '*psexec* /accepteula*',
          '*paexec*',
        ],
      },
      selection_wmic_remote: {
        CommandLine: [
          '*wmic* /node:*',
          '*wmic* /user:* /password:* process*',
        ],
      },
      selection_net_admin_shares: {
        CommandLine: [
          '*net* use \\\\* /user:*',
          '*net* view \\\\*',
          '*copy* \\\\*\\admin$*',
          '*copy* \\\\*\\c$*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.7  DISCOVERY ───────────────────────────────────────────
  discovery: {
    title      : 'Discovery — System and Network Reconnaissance Commands',
    description: 'Detects attacker discovery activity including domain enumeration, network scanning, account listing, and system information gathering using built-in Windows utilities.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'medium',
    status     : 'stable',
    tags       : [
      'attack.discovery',
      'attack.t1082',  // System Information Discovery
      'attack.t1087',  // Account Discovery
      'attack.t1016',  // System Network Configuration Discovery
    ],
    references : [
      'https://attack.mitre.org/techniques/T1082/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'IT administrators running diagnostics',
      'Security tools performing baseline scans',
    ],
    detection  : {
      selection_account_enum: {
        CommandLine: [
          '*net* user /domain*',
          '*net* group /domain*',
          '*net* localgroup administrators*',
          '*whoami /all*',
          '*whoami /priv*',
        ],
      },
      selection_network_recon: {
        CommandLine: [
          '*ipconfig /all*',
          '*arp -a*',
          '*netstat -ano*',
          '*nslookup *',
          '*ping* -n *',
        ],
      },
      selection_system_info: {
        CommandLine: [
          '*systeminfo*',
          '*ver*',
          '*hostname*',
          '*tasklist*',
        ],
      },
      condition: '(selection_account_enum or selection_network_recon) or selection_system_info',
    },
  },

  // ── 4.8  EXFILTRATION ────────────────────────────────────────
  exfiltration: {
    title      : 'Exfiltration — Data Upload via Living-off-the-Land Binaries',
    description: 'Detects data exfiltration attempts using built-in Windows utilities (certutil, bitsadmin, curl, powershell Invoke-WebRequest) to upload data to external endpoints.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.exfiltration',
      'attack.t1048',      // Exfiltration Over Alternative Protocol
      'attack.t1567',      // Exfiltration Over Web Service
    ],
    references : [
      'https://attack.mitre.org/techniques/T1048/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate file uploads via business applications',
      'Software update mechanisms using BITSAdmin',
    ],
    detection  : {
      selection_certutil_upload: {
        CommandLine: [
          '*certutil* -urlcache* -split* -f* http*',
          '*certutil* -encode* *',
          '*certutil* -decode* *',
        ],
      },
      selection_bits_upload: {
        CommandLine: [
          '*bitsadmin* /transfer* http*',
          '*bitsadmin* /upload* http*',
        ],
      },
      selection_powershell_upload: {
        CommandLine: [
          '*Invoke-WebRequest* -Uri* http* -Method POST*',
          '*Invoke-RestMethod* -Method POST* http*',
          '*(New-Object Net.WebClient).UploadFile*',
          '*(New-Object Net.WebClient).UploadData*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.9  COMMAND AND CONTROL ──────────────────────────────────
  command_and_control: {
    title      : 'Command and Control — DNS Tunneling and Beacon Patterns',
    description: 'Detects command-and-control communication via DNS tunneling, HTTP beaconing, and reverse shell establishment using common attacker tooling.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'high',
    status     : 'stable',
    tags       : [
      'attack.command_and_control',
      'attack.t1071.004',  // Application Layer Protocol: DNS
      'attack.t1071.001',  // Application Layer Protocol: Web Protocols
      'attack.t1132',      // Data Encoding
    ],
    references : [
      'https://attack.mitre.org/techniques/T1071/',
    ],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate use of nslookup and dig for DNS diagnostics',
      'Monitoring agents with high DNS query rates',
    ],
    detection  : {
      selection_dns_tools: {
        CommandLine: [
          '*nslookup* -type=TXT *',
          '*nslookup* -querytype=*',
          '*Resolve-DnsName* -Type TXT *',
        ],
      },
      selection_reverse_shell: {
        CommandLine: [
          '*powershell*New-Object System.Net.Sockets.TCPClient*',
          '*powershell*System.Net.Sockets.TcpClient*',
          '*cmd.exe* /c* nc* -e*',
          '*/bin/sh -i*',
        ],
      },
      selection_beacon_stager: {
        CommandLine: [
          '*.DownloadString(*http*)*',
          '*.DownloadFile(*http*)*',
          '*IEX(*Invoke-Expression*',
          '*IEX(New-Object*',
        ],
      },
      condition: '1 of selection_*',
    },
  },

  // ── 4.10  GENERIC FALLBACK ────────────────────────────────────
  generic: {
    title      : 'Suspicious Process Execution — Generic Behavioral Indicator',
    description: 'Detects generic suspicious process execution patterns based on known attacker LOLBin abuse and process spawn anomalies.',
    author     : 'RAYKAN Behavioral Engine',
    level      : 'medium',
    status     : 'experimental',
    tags       : [
      'attack.execution',
      'attack.t1059',
    ],
    references : [],
    logsource  : { category: 'process_creation', product: 'windows' },
    falsepositives: [
      'Legitimate administrative activity',
    ],
    detection  : {
      selection_suspicious_lolbin: {
        CommandLine: [
          '*mshta* http*',
          '*rundll32* javascript:*',
          '*regsvr32* /u /s /i:*',
          '*installutil* /logfile=* /LogToConsole=false*',
        ],
      },
      selection_encoded_payloads: {
        CommandLine: [
          '* -enc *JAB*',
          '* -enc *SUVYC*',
          '* -enc *KAA*',
        ],
      },
      condition: '1 of selection_*',
    },
  },
};

// ─────────────────────────────────────────────────────────────────
//  §5  LOLBIN WHITELIST
//  CommandLine values used in rules must match at least one of
//  the canonical attacker-behavior patterns below OR begin with
//  a wildcard wrapping a known LOLBin/tool name.
// ─────────────────────────────────────────────────────────────────
const LOLBIN_PATTERNS = [
  /vssadmin/i,    /wbadmin/i,       /bcdedit/i,       /wevtutil/i,
  /taskkill/i,    /mimikatz/i,      /sekurlsa/i,      /lsadump/i,
  /procdump/i,    /comsvcs/i,       /MiniDump/i,      /certutil/i,
  /bitsadmin/i,   /mshta/i,        /regsvr32/i,      /wscript/i,
  /cscript/i,     /psexec/i,        /paexec/i,        /wmic/i,
  /schtasks/i,    /rundll32/i,      /msiexec/i,       /installutil/i,
  /regasm/i,      /regsvcs/i,       /msbuild/i,       /csc\.exe/i,
  /PowerShell/i,  /encodedcommand/i,/EncodedCommand/i,/-enc/i,
  /bypass/i,      /ExecutionPolicy/i,/noprofile/i,    /noninteractive/i,
  /Invoke-Expression/i, /IEX\(/i,   /DownloadString/i,/DownloadFile/i,
  /Invoke-WebRequest/i, /Net\.WebClient/i, /TCPClient/i,
  /Invoke-RestMethod/i, /Invoke-Mimikatz/i,/Invoke-ReflectivePEInjection/i,
  /UploadFile/i,        /UploadData/i,
  /net use/i,     /net group/i,     /net user/i,      /net localgroup/i,
  /net stop/i,    /net view/i,      /net copy/i,
  /whoami/i,      /ipconfig/i,      /systeminfo/i,    /netstat/i,
  /nslookup/i,    /Resolve-DnsName/i,
  /\barp\b/i,     /\bping\b/i,      /\btracert\b/i,   /\bver\b/i,
  /\btasklist\b/i,/\bhostname\b/i,  /\bquser\b/i,
  // Office / process image names used in detection patterns
  /winword\.exe/i,/excel\.exe/i,    /powerpnt\.exe/i, /outlook\.exe/i,
  /cmd\.exe/i,    /wscript\.exe/i,  /cscript\.exe/i,  /mshta\.exe/i,
  /rundll32\.exe/i,
  // Reverse shell / netcat patterns
  /\bnc\b/i,      /netcat/i,        /\/bin\/sh/i,     /\/bin\/bash/i,
  /recoveryenabled/i, /bootstatuspolicy/i,
  /clear-log/i,   /Clear-EventLog/i,
  /hklm\\sam/i,   /hklm\\system/i,  /hklm\\security/i,
  /CurrentVersion\\Run/i, /Winlogon/i,
  /admin\$/i,     /c\$/i,           /\$\\/i,
  /SUVYC/i,       /JAB/i,           /KAA/i,           /TVq/i,
  /kerberos::/i,  /lsass/i,         /TargetFilename/i,/Start Menu/i,
  /Startup\\/i,   /reg add/i,       /reg save/i,      /Invoke-Mimikatz/i,
  /shadow/i,      /shadowstorage/i, /systemstatebackup/i,
  /accepteula/i,  /safeboot/i,
  /-nop\b/i,      /-noprofile/i,    /-w hidden/i,     /-WindowStyle/i,
  /hidden/i,      /VSCode/i,        /Modules\\/i,     /Microsoft\./i,
];

// Script / file extensions commonly used in attacker payloads
const ATTACKER_EXTENSIONS = /\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|psm1|psd1|lnk|dll|cpl|inf|reg|scr|pif|com|msi|msp|msc|jar|py|rb|sh)\b/i;

function isValidCommandLine(value) {
  // Wildcards are acceptable in patterns
  const clean = value.replace(/\*/g, '');
  // Must match at least one LOLBin/attacker pattern OR attacker file extension
  return LOLBIN_PATTERNS.some(re => re.test(clean)) || ATTACKER_EXTENSIONS.test(clean);
}

// ─────────────────────────────────────────────────────────────────
//  §6  INPUT SANITIZER
//
//  sanitizeDescription(text) → { keywords: string[], intent: string }
//
//  Rules:
//   1. Strip common natural-language instruction verbs and filler
//   2. Extract only recognized security keywords (§2)
//   3. Reject any phrase longer than three words
//   4. Return the dominant intent (§3) or 'generic'
// ─────────────────────────────────────────────────────────────────

/** Instruction verbs and filler that should be stripped */
const INSTRUCTION_VERBS_RE = /\b(please|can you|could you|would you|i want|i need|i'd like|i would like|write me|give me|show me|make me|create a?|generate a?|build a?|produce a?|help me|tell me|write a?|explain|describe|how to|what is|what are|why does|show|define|provide|find|look\s?up|search|write|give|make|get|give|develop|design|implement|construct|output|list|enumerate|return)\b/gi;

function sanitizeDescription(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    return { keywords: [], intent: 'generic', sanitized: '' };
  }

  // Step 1: Lowercase working copy for matching
  let text = rawInput.toLowerCase().trim();

  // Step 2: Strip instruction verbs and common filler
  text = text.replace(INSTRUCTION_VERBS_RE, ' ');

  // Step 3: Normalize whitespace
  text = text.replace(/\s{2,}/g, ' ').trim();

  // Step 4: Tokenize into phrases (split by common punctuation + conjunctions)
  const phrases = text
    .split(/[,;.|]+|\band\b|\bor\b|\bthat\b|\bwith\b|\bfor\b|\busing\b|\bto\b|\bfrom\b|\binto\b/i)
    .map(p => p.trim())
    .filter(p => p.length > 0);

  // Step 5: Match recognized security keywords only
  const matchedKeywords = [];
  const intentCounts    = {};

  for (const phrase of phrases) {
    for (const [kw, intent] of Object.entries(SECURITY_KEYWORDS)) {
      if (phrase.includes(kw)) {
        // Enforce: reject phrases longer than 3 words
        const wordCount = kw.split(/\s+/).length;
        if (wordCount <= 3) {
          matchedKeywords.push(kw);
          if (intent) {
            intentCounts[intent] = (intentCounts[intent] || 0) + 1;
          }
        }
      }
    }
  }

  // Step 6: Pick dominant intent
  let intent = 'generic';
  let maxCount = 0;
  for (const [k, v] of Object.entries(intentCounts)) {
    if (v > maxCount) { maxCount = v; intent = k; }
  }

  // Normalize intent via INTENT_PHASE_MAP so we always map to a template key
  intent = INTENT_PHASE_MAP[intent] || intent;

  return {
    keywords : [...new Set(matchedKeywords)],
    intent,
    sanitized: text,
  };
}

// ─────────────────────────────────────────────────────────────────
//  §7  OUTPUT VALIDATOR
//
//  validateRuleOutput(rule, originalInput) → { valid, errors }
//
//  Checks:
//   a) All required Sigma fields present
//   b) No detection field value contains substrings from the
//      original prompt (prompt-injection guard)
//   c) CommandLine values match LOLBin / known attacker patterns
//   d) Safety guard: reject CommandLine values containing META_WORDS
//   e) condition uses more than a single bare 'selection'
//   f) level is one of: critical, high, medium, low
// ─────────────────────────────────────────────────────────────────
const REQUIRED_FIELDS = ['title', 'description', 'logsource', 'detection', 'level'];

function containsMetaWord(value) {
  const lower = value.toLowerCase();
  for (const mw of META_WORDS) {
    if (lower.includes(mw)) return mw;
  }
  return null;
}

// Security tool names that are ALLOWED to appear in both the user prompt
// and CommandLine values (they are legitimate detection targets)
const ALLOWED_TOOL_NAMES = new Set([
  'vssadmin', 'wbadmin', 'bcdedit', 'wevtutil', 'taskkill', 'mimikatz',
  'sekurlsa', 'lsadump', 'procdump', 'comsvcs', 'minidump', 'certutil',
  'bitsadmin', 'mshta', 'regsvr32', 'wscript', 'cscript', 'psexec',
  'paexec', 'wmic', 'schtasks', 'rundll32', 'msiexec', 'installutil',
  'regasm', 'regsvcs', 'msbuild', 'powershell', 'pwsh', 'encode',
  'encoded', 'bypass', 'mimikatz', 'lsass', 'kerberos', 'shadow',
  'shadowstorage', 'systemstatebackup', 'safeboot', 'accepteula',
  'invoke', 'expression', 'download', 'webclient', 'tcpclient',
  'nslookup', 'whoami', 'ipconfig', 'systeminfo', 'netstat',
  'ransomware', 'credential', 'lateral', 'lateral', 'exfil',
  'cobalt', 'beacon', 'startup', 'winlogon', 'schtask', 'delete',
  'catalog', 'shadows', 'clear', 'tasklist', 'recovery', 'recoveryenabled',
  'bootstatuspolicy', 'attack', 'malware', 'threat', 'detect', 'detection',
  'process', 'parent', 'image', 'command', 'commandline', 'hklm',
  'windows', 'admin', 'group', 'localgroup', 'system', 'security',
  'registry', 'regkey', 'runonce', 'smb', 'share', 'remote', 'target',
  'veeam', 'acronis', 'oracle', 'mssql', 'backup', 'netcat', 'shell',
]);

function promptLeakCheck(value, promptWords) {
  const lv = value.toLowerCase();
  for (const w of promptWords) {
    // Only flag words of 6+ characters that are NOT security tool names
    if (w.length >= 6 && !ALLOWED_TOOL_NAMES.has(w) && lv.includes(w)) return w;
  }
  return null;
}

function validateRuleOutput(rule, originalInput = '') {
  const errors = [];

  // a) Required fields
  for (const f of REQUIRED_FIELDS) {
    if (!rule[f]) errors.push(`Missing required field: ${f}`);
  }

  // b) Level enum
  if (rule.level && !['critical', 'high', 'medium', 'low', 'informational'].includes(rule.level)) {
    errors.push(`Invalid level: ${rule.level}`);
  }

  // c) Detection must exist and have at least one selection
  const det = rule.detection || {};
  const selectionKeys = Object.keys(det).filter(k => k !== 'condition' && k !== 'timeframe');
  if (selectionKeys.length === 0) {
    errors.push('Detection block has no selection definitions');
  }

  // d) Condition must use multi-selection logic (not single bare 'selection')
  const cond = (det.condition || '').trim();
  if (cond === 'selection') {
    errors.push('Condition uses single bare "selection" — must combine multiple behaviors');
  }
  if (!cond) {
    errors.push('Detection block is missing a condition');
  }

  // e) Build set of "prompt words" for leak check (all words >4 chars from original input)
  const promptWords = (originalInput || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 5);

  // f) Validate each CommandLine value
  const walkDetection = (obj, path = '') => {
    if (!obj || typeof obj !== 'object') return;
    for (const [key, value] of Object.entries(obj)) {
      if (key === 'condition' || key === 'timeframe') continue;
      if (Array.isArray(value)) {
        value.forEach((v, i) => {
          if (typeof v === 'string') {
            // Safety guard: meta words
            const mw = containsMetaWord(v);
            if (mw) errors.push(`Safety violation — CommandLine[${path}.${key}[${i}]] contains meta-word "${mw}": ${v.slice(0, 80)}`);

            // Prompt leak guard
            const lk = promptLeakCheck(v, promptWords);
            if (lk) errors.push(`Prompt leak — CommandLine[${path}.${key}[${i}]] contains prompt word "${lk}": ${v.slice(0, 80)}`);

            // LOLBin pattern check (only for CommandLine / Image / ParentImage fields)
            if ((key === 'CommandLine' || key === 'Image' || key === 'ParentImage') && !isValidCommandLine(v)) {
              errors.push(`Invalid CommandLine — does not match known attacker behavior or LOLBin: ${v.slice(0, 80)}`);
            }
          } else if (typeof v === 'object') {
            walkDetection(v, `${path}.${key}[${i}]`);
          }
        });
      } else if (typeof value === 'object') {
        walkDetection(value, `${path}.${key}`);
      }
    }
  };

  walkDetection(det);

  return { valid: errors.length === 0, errors };
}

// ─────────────────────────────────────────────────────────────────
//  §8  SIGMA YAML SERIALIZER
//
//  toSigmaYaml(rule) → string
//
//  Produces valid Sigma YAML output that passes sigma-cli --verify.
//  Fields are emitted in canonical Sigma order.
// ─────────────────────────────────────────────────────────────────
function yamlString(s) {
  // Sigma YAML single-quoted style
  if (!s) return "''";
  if (/['\\]/.test(s)) return `"${s.replace(/"/g, '\\"')}"`;
  if (/[:#{}[\],&*?|<>=!%@`]/.test(s) || s.includes('\n')) {
    return `'${s.replace(/'/g, "''")}'`;
  }
  return s;
}

function detectionToYaml(detection, indent = '  ') {
  const lines = [];
  for (const [key, value] of Object.entries(detection)) {
    if (key === 'condition') continue;
    if (key === 'timeframe') continue;
    lines.push(`${indent}${key}:`);
    if (typeof value === 'object' && !Array.isArray(value)) {
      for (const [field, fVal] of Object.entries(value)) {
        if (Array.isArray(fVal)) {
          lines.push(`${indent}  ${field}:`);
          fVal.forEach(v => lines.push(`${indent}    - ${yamlString(String(v))}`));
        } else {
          lines.push(`${indent}  ${field}: ${yamlString(String(fVal))}`);
        }
      }
    } else if (Array.isArray(value)) {
      value.forEach(item => {
        if (typeof item === 'object') {
          lines.push(`${indent}  -`);
          for (const [f, v] of Object.entries(item)) {
            if (Array.isArray(v)) {
              lines.push(`${indent}    ${f}:`);
              v.forEach(i => lines.push(`${indent}      - ${yamlString(String(i))}`));
            } else {
              lines.push(`${indent}    ${f}: ${yamlString(String(v))}`);
            }
          }
        } else {
          lines.push(`${indent}  - ${yamlString(String(item))}`);
        }
      });
    }
  }
  // Condition last
  if (detection.condition) {
    lines.push(`${indent}condition: ${detection.condition}`);
  }
  return lines.join('\n');
}

function toSigmaYaml(rule) {
  const id = rule.id || `RAYKAN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const lines = [
    `title: ${yamlString(rule.title)}`,
    `id: ${id}`,
    `status: ${rule.status || 'experimental'}`,
    `description: ${yamlString(rule.description)}`,
    `author: ${yamlString(rule.author || 'RAYKAN Behavioral Engine')}`,
    `date: ${new Date().toISOString().slice(0, 10)}`,
    `modified: ${new Date().toISOString().slice(0, 10)}`,
    `tags:`,
    ...(rule.tags || []).map(t => `  - ${t}`),
    `references:`,
    ...(rule.references || []).map(r => `  - ${yamlString(r)}`),
    `logsource:`,
    `  category: ${rule.logsource?.category || 'process_creation'}`,
    `  product: ${rule.logsource?.product || 'windows'}`,
    `detection:`,
    detectionToYaml(rule.detection),
    `falsepositives:`,
    ...(rule.falsepositives || ['Unknown']).map(fp => `  - ${yamlString(fp)}`),
    `level: ${rule.level || 'medium'}`,
  ];
  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────
//  §9  MAIN BUILDER API
//
//  buildRule(description, options) → { rule, yaml, validation }
//
//  Algorithm:
//   1. Sanitize input → extract intent + keywords
//   2. Look up template by intent
//   3. Optionally narrow/annotate template using keywords
//   4. Validate output; if invalid, try next-best template
//   5. Return validated rule + YAML + validation report
// ─────────────────────────────────────────────────────────────────

const MAX_REGENERATE_ATTEMPTS = 3;

function buildRule(description, options = {}) {
  const { author, extraTags = [], examples = [] } = options;

  // Step 1: Sanitize
  const { keywords, intent, sanitized } = sanitizeDescription(description);

  // Step 2: Select template
  const templatePhase = INTENT_PHASE_MAP[intent] || 'generic';

  // Ordered fallback list: primary intent → generic
  const phaseOrder = [templatePhase, 'generic'];
  // Add related phases from keywords
  const extraPhases = [...new Set(
    keywords
      .map(kw => SECURITY_KEYWORDS[kw])
      .filter(Boolean)
      .map(i => INTENT_PHASE_MAP[i] || i)
  )];
  const candidatePhases = [...new Set([...phaseOrder, ...extraPhases])];

  let rule = null;
  let validation = null;

  for (let attempt = 0; attempt < MAX_REGENERATE_ATTEMPTS; attempt++) {
    const phase   = candidatePhases[attempt] || 'generic';
    const tpl     = DETECTION_TEMPLATES[phase] || DETECTION_TEMPLATES['generic'];

    // Deep-clone the template so we don't mutate the master copy
    const candidate = JSON.parse(JSON.stringify(tpl));

    // Annotate with runtime metadata
    candidate.id     = `RAYKAN-${Date.now().toString(36).toUpperCase()}-${phase.replace('_','-').toUpperCase()}`;
    candidate.author = author || candidate.author;
    candidate.tags   = [...(candidate.tags || []), ...extraTags];

    // Optionally add keyword-specific tags
    if (keywords.includes('ransomware') || keywords.includes('wannacry') || keywords.includes('lockbit')) {
      candidate.tags.push('attack.ransomware');
    }

    // Validate
    validation = validateRuleOutput(candidate, description);

    if (validation.valid) {
      rule = candidate;
      break;
    }

    // Log and try next
    console.warn(`[SigmaBuilder] Attempt ${attempt + 1} invalid:`, validation.errors.slice(0, 3));
  }

  // Last resort: always return the generic template (it's hard-coded safe)
  if (!rule) {
    rule = JSON.parse(JSON.stringify(DETECTION_TEMPLATES['generic']));
    rule.id     = `RAYKAN-${Date.now().toString(36).toUpperCase()}-GENERIC`;
    rule.author = author || rule.author;
    validation  = validateRuleOutput(rule, description);
  }

  // Generate YAML
  const yaml = toSigmaYaml(rule);

  return {
    rule,
    yaml,
    validation,
    meta: {
      sanitized,
      keywords,
      intent,
      phase : templatePhase,
    },
  };
}

// ─────────────────────────────────────────────────────────────────
//  §10  POST-PROCESSING SIGMA VALIDATOR
//
//  sigmaQualityCheck(rule) → { score: 0-100, issues: string[], grade }
//
//  Checks quality dimensions:
//   • Has meaningful title (not template placeholder)
//   • Has description with ≥20 words
//   • Tags include at least one ATT&CK technique (T####)
//   • Has falsepositives (not just ['Unknown'])
//   • Has references
//   • Detection has ≥2 selections
//   • Condition uses compound logic
//   • Level is set
// ─────────────────────────────────────────────────────────────────
function sigmaQualityCheck(rule) {
  const issues = [];
  let score    = 100;
  const deduct = (n, msg) => { score -= n; issues.push(msg); };

  // Title
  if (!rule.title || rule.title.length < 10) deduct(15, 'Title too short (< 10 chars)');
  if (rule.title?.toLowerCase().includes('placeholder')) deduct(10, 'Title contains "placeholder"');

  // Description
  const descWords = (rule.description || '').split(/\s+/).length;
  if (descWords < 10) deduct(10, `Description too brief (${descWords} words, need ≥10)`);

  // Tags with MITRE technique
  const hasMitreTech = (rule.tags || []).some(t => /attack\.t\d{4}/i.test(t));
  if (!hasMitreTech) deduct(15, 'No MITRE ATT&CK technique tag (attack.TXXXX)');

  // Falsepositives
  const fps = rule.falsepositives || [];
  if (fps.length === 0 || (fps.length === 1 && fps[0].toLowerCase() === 'unknown')) {
    deduct(10, 'Falsepositives should list specific scenarios, not just "Unknown"');
  }

  // References
  if (!rule.references || rule.references.length === 0) {
    deduct(5, 'No references provided');
  }

  // Detection selections
  const det  = rule.detection || {};
  const sels = Object.keys(det).filter(k => k !== 'condition' && k !== 'timeframe');
  if (sels.length < 2) deduct(15, `Detection has only ${sels.length} selection(s); recommend ≥2`);

  // Condition
  const cond = (det.condition || '');
  if (cond === 'selection') deduct(15, 'Condition is single bare "selection"; must combine logic');
  if (!cond.includes(' ') && !cond.startsWith('1 of') && !cond.startsWith('all of')) {
    deduct(10, 'Condition has no boolean/quantifier logic (and/or/1 of/all of)');
  }

  // Level
  if (!rule.level) deduct(10, 'No detection level specified');

  // Status
  if (!rule.status) deduct(5, 'No status field (stable/test/experimental)');

  score = Math.max(0, score);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return { score, grade, issues, passed: score >= 60 };
}

// ─────────────────────────────────────────────────────────────────
//  §11  EXPORTS
// ─────────────────────────────────────────────────────────────────
module.exports = {
  sanitizeDescription,
  buildRule,
  validateRuleOutput,
  sigmaQualityCheck,
  toSigmaYaml,
  DETECTION_TEMPLATES,
  INTENT_PHASE_MAP,
  LOLBIN_PATTERNS,
  isValidCommandLine,
};
