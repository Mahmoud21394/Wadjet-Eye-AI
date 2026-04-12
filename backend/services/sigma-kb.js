/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Sigma Knowledge Base  v1.0
 *
 *  Provides:
 *   1. In-memory index of common Sigma rule patterns (seeded + extensible)
 *   2. Full-text search across rules by title, description, tags, logsource
 *   3. Rule persistence: add/update/delete
 *   4. Export rule in YAML format
 *
 *  In production this is backed by the database (Supabase/Postgres).
 *  When the DB is unavailable, falls back to the built-in seed corpus.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── Sigma rule schema ──────────────────────────────────────────────────────────
/**
 * @typedef {object} SigmaRule
 * @property {string}   id           — UUID
 * @property {string}   title
 * @property {string}   status       — 'stable' | 'test' | 'experimental' | 'deprecated'
 * @property {string}   description
 * @property {string[]} references
 * @property {string}   author
 * @property {string}   date         — YYYY/MM/DD
 * @property {string[]} tags         — e.g. ['attack.execution', 'attack.t1059']
 * @property {object}   logsource    — { category, product, service }
 * @property {object}   detection
 * @property {string[]} falsepositives
 * @property {string}   level        — 'informational' | 'low' | 'medium' | 'high' | 'critical'
 * @property {string}   yaml         — serialised YAML representation
 */

// ── Seed corpus of 30 high-quality Sigma patterns ─────────────────────────────
const SEED_RULES = [
  {
    id: '1001',
    title: 'PowerShell Download Cradle',
    status: 'stable',
    description: 'Detects PowerShell downloading files using common download cradle patterns like Invoke-WebRequest, WebClient, or BitsTransfer.',
    references: ['https://attack.mitre.org/techniques/T1105/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.execution', 'attack.t1059.001', 'attack.defense_evasion', 'attack.t1105'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['*Invoke-WebRequest*', '*IWR *', '*WebClient*', '*DownloadFile*', '*DownloadString*', '*BitsTransfer*', '*Start-BitsTransfer*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate admin scripts', 'Software update mechanisms', 'SCCM/WSUS downloads'],
    level: 'high',
  },
  {
    id: '1002',
    title: 'Mimikatz via LSASS Process Access',
    status: 'stable',
    description: 'Detects credential dumping via LSASS memory access, a technique used by Mimikatz and similar tools.',
    references: ['https://attack.mitre.org/techniques/T1003/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { category: 'process_access', product: 'windows' },
    detection: {
      selection: {
        TargetImage: '*\\lsass.exe',
        GrantedAccess: ['0x1010', '0x1038', '0x40', '0x1fffff'],
      },
      filter: {
        SourceImage: ['*\\MsMpEng.exe', '*\\csrss.exe', '*\\wininit.exe', '*\\lsm.exe'],
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Antivirus products', 'EDR agents', 'Windows system processes'],
    level: 'critical',
  },
  {
    id: '1003',
    title: 'Suspicious Scheduled Task Creation',
    status: 'stable',
    description: 'Detects creation of scheduled tasks via schtasks.exe with persistence indicators.',
    references: ['https://attack.mitre.org/techniques/T1053/005/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.persistence', 'attack.t1053.005', 'attack.privilege_escalation'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\schtasks.exe',
        CommandLine: ['*/Create*', '*/SC *', '*/TR *'],
      },
      suspicious: {
        CommandLine: ['*\\AppData\\*', '*\\Temp\\*', '*\\Users\\Public\\*', '*powershell*', '*cmd /c*', '*wscript*', '*cscript*'],
      },
      condition: 'selection and suspicious',
    },
    falsepositives: ['Legitimate software installations', 'System administrators', 'Backup solutions'],
    level: 'medium',
  },
  {
    id: '1004',
    title: 'WMI Persistence via __EventFilter',
    status: 'stable',
    description: 'Detects WMI event subscription used for persistence by creating __EventFilter objects.',
    references: ['https://attack.mitre.org/techniques/T1546/003/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.persistence', 'attack.t1546.003', 'attack.execution'],
    logsource: { product: 'windows', service: 'sysmon' },
    detection: {
      selection: {
        EventID: 19,
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate monitoring software', 'SCCM WMI subscriptions'],
    level: 'high',
  },
  {
    id: '1005',
    title: 'Certutil Download or Decode',
    status: 'stable',
    description: 'Detects certutil.exe used to download files or decode base64-encoded payloads, a common LOLBin technique.',
    references: ['https://attack.mitre.org/techniques/T1140/', 'https://attack.mitre.org/techniques/T1105/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1140', 'attack.command_and_control', 'attack.t1105'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\certutil.exe',
        CommandLine: ['*-decode*', '*-decodehex*', '*-urlcache*', '*-verifyctl*', '*-encode*', '*-addstore*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Certificate management by IT administrators', 'PKI infrastructure operations'],
    level: 'high',
  },
  {
    id: '1006',
    title: 'DLL Side-Loading via Legitimate Application',
    status: 'test',
    description: 'Detects DLL side-loading attacks where a legitimate signed application loads a malicious DLL from the same directory.',
    references: ['https://attack.mitre.org/techniques/T1574/002/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.persistence', 'attack.t1574.002', 'attack.defense_evasion', 'attack.privilege_escalation'],
    logsource: { category: 'image_load', product: 'windows' },
    detection: {
      selection: {
        ImageLoaded: ['*\\version.dll', '*\\wlbsctrl.dll', '*\\wbemcomn.dll'],
        Signed: 'false',
      },
      filter: {
        ImageLoaded: ['C:\\Windows\\*', 'C:\\Program Files\\*'],
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Software that legitimately loads these DLLs from non-system paths'],
    level: 'medium',
  },
  {
    id: '1007',
    title: 'Registry Run Key Persistence',
    status: 'stable',
    description: 'Detects modification of common registry run keys used for persistence.',
    references: ['https://attack.mitre.org/techniques/T1547/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.persistence', 'attack.t1547.001'],
    logsource: { category: 'registry_set', product: 'windows' },
    detection: {
      selection: {
        TargetObject: [
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
          '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*',
          '*\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*',
          '*\\SYSTEM\\CurrentControlSet\\Services\\*',
        ],
      },
      filter: {
        Image: ['*\\msiexec.exe', '*\\OneDriveSetup.exe', 'C:\\Windows\\regedit.exe'],
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Software installations', 'Startup programs added by admins'],
    level: 'medium',
  },
  {
    id: '1008',
    title: 'Lateral Movement via PsExec',
    status: 'stable',
    description: 'Detects lateral movement using PsExec or compatible tools via named pipe creation.',
    references: ['https://attack.mitre.org/techniques/T1021/002/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.lateral_movement', 'attack.t1021.002', 'attack.execution'],
    logsource: { product: 'windows', service: 'sysmon' },
    detection: {
      selection: {
        EventID: 17,
        PipeName: ['\\PSEXESVC', '\\paexec*', '\\remcom*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate PsExec usage by system administrators'],
    level: 'high',
  },
  {
    id: '1009',
    title: 'Suspicious Network Connection from Office Application',
    status: 'stable',
    description: 'Detects Office applications making outbound network connections, potentially indicating macro-based malware.',
    references: ['https://attack.mitre.org/techniques/T1566/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.initial_access', 'attack.t1566.001', 'attack.execution', 'attack.t1204.002'],
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\WINWORD.EXE', '*\\EXCEL.EXE', '*\\POWERPNT.EXE', '*\\OUTLOOK.EXE', '*\\MSPUB.EXE', '*\\VISIO.EXE'],
        Initiated: 'true',
      },
      filter: {
        DestinationIp: ['127.*', '10.*', '192.168.*', '172.16.*'],
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Online document preview', 'Cloud-connected Office features', 'Template downloads'],
    level: 'medium',
  },
  {
    id: '1010',
    title: 'Pass-the-Hash via WMI',
    status: 'stable',
    description: 'Detects pass-the-hash and remote code execution attempts via WMI (wmic.exe /node:).',
    references: ['https://attack.mitre.org/techniques/T1047/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.execution', 'attack.t1047', 'attack.lateral_movement'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\wmic.exe',
        CommandLine: ['*/node:*process call create*', '*/node:*os get*'],
      },
      condition: 'selection',
    },
    falsepositives: ['System administrators running WMI queries', 'Monitoring scripts'],
    level: 'high',
  },
  {
    id: '1011',
    title: 'LOLBAS Execution via Mshta',
    status: 'stable',
    description: 'Detects mshta.exe executing remote or suspicious HTA files as a LOLBin.',
    references: ['https://attack.mitre.org/techniques/T1218/005/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1218.005', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\mshta.exe',
        CommandLine: ['*http*', '*https*', '*vbscript*', '*javascript*', '*.hta*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate HTA-based applications', 'Legacy enterprise software'],
    level: 'high',
  },
  {
    id: '1012',
    title: 'Empire / Covenant C2 Beacon Patterns',
    status: 'test',
    description: 'Detects network patterns associated with common C2 frameworks including Empire, Covenant, and Havoc.',
    references: ['https://attack.mitre.org/techniques/T1071/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.command_and_control', 'attack.t1071.001', 'attack.t1573'],
    logsource: { category: 'proxy', product: 'zeek' },
    detection: {
      selection: {
        method: 'POST',
        uri: ['*/admin/get.php*', '*/news.php*', '*/login/process.php*', '*index.jsp?*'],
      },
      timeframe: '1m',
      condition: 'selection | count() by src_ip > 10',
    },
    falsepositives: ['Legitimate web applications with similar URL patterns'],
    level: 'high',
  },
  {
    id: '1013',
    title: 'AMSI Bypass via Registry',
    status: 'test',
    description: 'Detects attempts to disable AMSI by modifying the HKLM\\SOFTWARE\\Microsoft\\AMSI key.',
    references: ['https://attack.mitre.org/techniques/T1562/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    logsource: { category: 'registry_set', product: 'windows' },
    detection: {
      selection: {
        TargetObject: ['*\\SOFTWARE\\Microsoft\\AMSI\\Providers\\*', '*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Security testing tools', 'Antivirus vendors'],
    level: 'high',
  },
  {
    id: '1014',
    title: 'DCSync Attack via Replication Request',
    status: 'stable',
    description: 'Detects DCSync attacks where a non-DC account requests replication rights to extract Active Directory credentials.',
    references: ['https://attack.mitre.org/techniques/T1003/006/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1003.006'],
    logsource: { product: 'windows', service: 'security' },
    detection: {
      selection: {
        EventID: 4662,
        Properties: ['*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*', '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*', '*89e95b76-444d-4c62-991a-0facbeda640c*'],
        AccessMask: '0x100',
      },
      filter: {
        SubjectUserName: '*$',
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Legitimate AD replication', 'Azure AD Connect sync'],
    level: 'critical',
  },
  {
    id: '1015',
    title: 'Ransomware Shadow Copy Deletion',
    status: 'stable',
    description: 'Detects deletion of volume shadow copies via vssadmin or wmic, a common ransomware pre-encryption step.',
    references: ['https://attack.mitre.org/techniques/T1490/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.impact', 'attack.t1490'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      vssadmin: {
        Image: '*\\vssadmin.exe',
        CommandLine: ['*delete shadows*', '*resize shadowstorage*'],
      },
      wmic: {
        Image: '*\\wmic.exe',
        CommandLine: ['*shadowcopy delete*', '*shadowcopy where*delete*'],
      },
      powershell: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: '*Get-WMIObject Win32_ShadowCopy*Delete()*',
      },
      condition: 'vssadmin or wmic or powershell',
    },
    falsepositives: ['Backup software cleanup routines', 'IT maintenance scripts'],
    level: 'critical',
  },
  {
    id: '1016',
    title: 'Token Impersonation via SeImpersonatePrivilege',
    status: 'test',
    description: 'Detects privilege escalation via token impersonation techniques like JuicyPotato, PrintSpoofer.',
    references: ['https://attack.mitre.org/techniques/T1134/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.privilege_escalation', 'attack.t1134.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*JuicyPotato*', '*PrintSpoofer*', '*RoguePotato*', '*GodPotato*', '*SweetPotato*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Security research', 'Red team exercises'],
    level: 'critical',
  },
  {
    id: '1017',
    title: 'Kerberoasting Attack via SPN Query',
    status: 'stable',
    description: 'Detects Kerberoasting attacks by identifying RequestTicket events for service principal names.',
    references: ['https://attack.mitre.org/techniques/T1558/003/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1558.003'],
    logsource: { product: 'windows', service: 'security' },
    detection: {
      selection: {
        EventID: 4769,
        ServiceName: ['*$', '!krbtgt'],
        TicketEncryptionType: '0x17',
        Status: '0x0',
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate Kerberos ticket requests for service accounts'],
    level: 'high',
  },
  {
    id: '1018',
    title: 'Cobalt Strike Beacon Malleable C2 HTTP',
    status: 'test',
    description: 'Detects Cobalt Strike beacon HTTP malleable C2 profiles based on URI and User-Agent patterns.',
    references: ['https://attack.mitre.org/techniques/T1071/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.command_and_control', 'attack.t1071.001'],
    logsource: { category: 'proxy' },
    detection: {
      selection: {
        c_useragent: ['*Mozilla/5.0 (compatible; MSIE 9.0*', '*Mozilla/4.0 (compatible; MSIE 8.0*'],
        cs_uri_stem: ['*/updates.rss', '*/jquery-3.3.1.min.js', '*/jquery.min.js', '*/__utm.gif'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate web browsing with matching UA strings'],
    level: 'high',
  },
  {
    id: '1019',
    title: 'Suspicious Base64 Encoded PowerShell',
    status: 'stable',
    description: 'Detects PowerShell commands using base64 encoding (-EncodedCommand) which is frequently used to obfuscate malicious scripts.',
    references: ['https://attack.mitre.org/techniques/T1027/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1027', 'attack.execution', 'attack.t1059.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\powershell.exe', '*\\pwsh.exe'],
        CommandLine: ['* -e *', '* -en *', '* -enc *', '* -enco*', '* -EncodedCommand *'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate encoded PowerShell scripts by admins', 'Some software installers'],
    level: 'high',
  },
  {
    id: '1020',
    title: 'Living Off The Land — Regsvr32 Squiblydoo',
    status: 'stable',
    description: 'Detects the Squiblydoo technique using regsvr32.exe to load a remote COM scriptlet.',
    references: ['https://attack.mitre.org/techniques/T1218/010/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1218.010', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: '*\\regsvr32.exe',
        CommandLine: ['*/s*', '*/u*', '*/i:http*', '*/i:ftp*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate COM component registration'],
    level: 'high',
  },
  {
    id: '1021',
    title: 'MSBuild Inline Task Execution',
    status: 'stable',
    description: 'Detects msbuild.exe executing inline tasks which can be used to proxy code execution.',
    references: ['https://attack.mitre.org/techniques/T1127/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1127.001', 'attack.execution'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        Image: ['*\\MSBuild.exe', '*\\MSBuildTaskHost.exe'],
      },
      filter: {
        CommandLine: ['C:\\Windows\\*', 'C:\\Program Files*', 'C:\\ProgramData\\Microsoft\\*'],
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Legitimate .NET build processes', 'Development environments'],
    level: 'medium',
  },
  {
    id: '1022',
    title: 'NTDS.dit File Backup / Exfiltration',
    status: 'stable',
    description: 'Detects attempts to copy or access the NTDS.dit Active Directory database file.',
    references: ['https://attack.mitre.org/techniques/T1003/003/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1003.003'],
    logsource: { category: 'file_event', product: 'windows' },
    detection: {
      selection: {
        TargetFilename: '*\\ntds.dit',
      },
      filter: {
        Image: '*\\ntdsutil.exe',
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Legitimate AD backup solutions', 'ntdsutil.exe IFM operations'],
    level: 'critical',
  },
  {
    id: '1023',
    title: 'Suspicious Child Process of WinWord',
    status: 'stable',
    description: 'Detects suspicious child processes spawned by Microsoft Word, indicative of malicious macro execution.',
    references: ['https://attack.mitre.org/techniques/T1566/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.initial_access', 'attack.t1566.001', 'attack.execution', 'attack.t1204.002'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        ParentImage: '*\\WINWORD.EXE',
        Image: ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe', '*\\mshta.exe', '*\\regsvr32.exe', '*\\rundll32.exe'],
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate Word macros used for automation'],
    level: 'high',
  },
  {
    id: '1024',
    title: 'CVE-2021-44228 Log4Shell Exploitation',
    status: 'stable',
    description: 'Detects Log4Shell (Log4j2 RCE) exploitation attempts via JNDI lookup patterns in HTTP requests.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.initial_access', 'attack.t1190', 'cve.2021.44228'],
    logsource: { category: 'webserver' },
    detection: {
      selection: {
        c_uri: ['*${jndi:*', '*${${lower:j}ndi*', '*${${::-j}${::-n}${::-d}${::-i}*'],
      },
      headers: {
        'cs(User-Agent)': ['*${jndi:*', '*${${lower:j}ndi*'],
        'cs(Referer)':    ['*${jndi:*'],
        'cs(X-Api-Version)': ['*${jndi:*'],
      },
      condition: 'selection or headers',
    },
    falsepositives: ['Security scanners', 'Vulnerability assessment tools'],
    level: 'critical',
  },
  {
    id: '1025',
    title: 'Suspicious LSASS Access via ProcDump',
    status: 'stable',
    description: 'Detects use of Sysinternals ProcDump or similar tools to dump LSASS process memory.',
    references: ['https://attack.mitre.org/techniques/T1003/001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*lsass*', '*-ma*', '*-mm*'],
        Image: ['*\\procdump*', '*\\procdump64*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Authorized memory dump collection for debugging'],
    level: 'critical',
  },
  {
    id: '1026',
    title: 'Suspicious DNS TXT Record Query',
    status: 'test',
    description: 'Detects DNS TXT queries which may be used for C2 communication or data exfiltration.',
    references: ['https://attack.mitre.org/techniques/T1071/004/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.command_and_control', 'attack.t1071.004', 'attack.exfiltration'],
    logsource: { category: 'dns' },
    detection: {
      selection: {
        QueryType: 'TXT',
        QueryName: ['*.xyz', '*.top', '*.club', '*.info'],
      },
      condition: 'selection',
    },
    falsepositives: ['SPF/DKIM/DMARC lookups', 'Legitimate TXT record queries'],
    level: 'low',
  },
  {
    id: '1027',
    title: 'BitLocker Encryption Without TPM',
    status: 'test',
    description: 'Detects BitLocker usage without TPM that may indicate unauthorized encryption (ransomware).',
    references: ['https://attack.mitre.org/techniques/T1486/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.impact', 'attack.t1486'],
    logsource: { product: 'windows', service: 'security' },
    detection: {
      selection: {
        EventID: [24577, 24579, 24580],
        ProviderName: 'Microsoft-Windows-BitLocker-Driver',
      },
      condition: 'selection',
    },
    falsepositives: ['Legitimate BitLocker deployment by IT'],
    level: 'high',
  },
  {
    id: '1028',
    title: 'Azure AD Token Theft via ADFS',
    status: 'experimental',
    description: 'Detects Azure AD / ADFS token forgery attacks by monitoring for Kerberos golden ticket usage.',
    references: ['https://attack.mitre.org/techniques/T1558.001/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.credential_access', 'attack.t1558.001', 'attack.persistence'],
    logsource: { product: 'windows', service: 'security' },
    detection: {
      selection: {
        EventID: 4768,
        TicketOptions: '0x40810000',
        TicketEncryptionType: '0x12',
      },
      filter: {
        IpAddress: '::1',
      },
      condition: 'selection and not filter',
    },
    falsepositives: ['Legitimate Kerberos ticket requests for admin accounts'],
    level: 'high',
  },
  {
    id: '1029',
    title: 'Container Escape via Privileged Container',
    status: 'test',
    description: 'Detects container escape attempts from privileged containers or via host path mounts.',
    references: ['https://attack.mitre.org/techniques/T1611/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.privilege_escalation', 'attack.t1611'],
    logsource: { category: 'process_creation', product: 'linux' },
    detection: {
      selection: {
        CommandLine: ['*nsenter*--mount=/proc/1/ns/mnt*', '*docker run*--privileged*', '*mount*/proc/sysrq-trigger*'],
      },
      condition: 'selection',
    },
    falsepositives: ['Container debugging by authorized users'],
    level: 'critical',
  },
  {
    id: '1030',
    title: 'Suspicious CloudTrail Disabling',
    status: 'stable',
    description: 'Detects AWS CloudTrail logging being disabled, a common defence evasion technique in cloud environments.',
    references: ['https://attack.mitre.org/techniques/T1562/008/'],
    author: 'RAKAY KB',
    date: '2024/01/01',
    tags: ['attack.defense_evasion', 'attack.t1562.008'],
    logsource: { product: 'aws', service: 'cloudtrail' },
    detection: {
      selection: {
        eventSource: 'cloudtrail.amazonaws.com',
        eventName: ['StopLogging', 'DeleteTrail', 'UpdateTrail'],
      },
      condition: 'selection',
    },
    falsepositives: ['Authorized AWS infrastructure changes'],
    level: 'high',
  },
];

// ── YAML serialiser (no external deps) ────────────────────────────────────────
function toYAML(rule) {
  const indent = (n) => '  '.repeat(n);
  const esc    = (v) => {
    const s = String(v);
    if (/[:{}\[\],&*?|<>=!%@`'"\n\r]/.test(s) || s.startsWith('-')) return `'${s.replace(/'/g, "''")}'`;
    return s;
  };
  const val = (v, depth = 0) => {
    if (Array.isArray(v)) {
      if (v.length === 0) return '[]';
      return '\n' + v.map(item => `${indent(depth + 1)}- ${esc(item)}`).join('\n');
    }
    if (v !== null && typeof v === 'object') {
      return '\n' + Object.entries(v).map(([k, vv]) =>
        `${indent(depth + 1)}${k}: ${val(vv, depth + 1)}`
      ).join('\n');
    }
    return esc(v);
  };

  const lines = [
    `title: ${esc(rule.title)}`,
    `id: ${rule.id}`,
    `status: ${rule.status}`,
    `description: '${rule.description.replace(/'/g, "''")}'`,
    `references:`,
    ...(rule.references || []).map(r => `  - '${r}'`),
    `author: ${esc(rule.author)}`,
    `date: ${esc(rule.date)}`,
    `tags:`,
    ...(rule.tags || []).map(t => `  - ${t}`),
    `logsource:`,
    ...Object.entries(rule.logsource).map(([k, v]) => `  ${k}: ${esc(v)}`),
    `detection:`,
    ...Object.entries(rule.detection).map(([k, v]) => `  ${k}: ${val(v, 1)}`),
    `falsepositives:`,
    ...(rule.falsepositives || []).map(f => `  - '${f.replace(/'/g, "''")}'`),
    `level: ${rule.level}`,
  ];

  return lines.join('\n');
}

// ── SigmaKB class ──────────────────────────────────────────────────────────────
class SigmaKB {
  constructor() {
    /** @type {Map<string, SigmaRule>} */
    this._rules = new Map();
    this._seedLoaded = false;
    this._loadSeed();
  }

  _loadSeed() {
    SEED_RULES.forEach(r => {
      const rule = { ...r, yaml: toYAML(r) };
      this._rules.set(rule.id, rule);
    });
    this._seedLoaded = true;
  }

  /**
   * search — full-text search across all rule fields.
   * Returns ranked results.
   *
   * @param {string} query
   * @param {object} [filters] — { level, logsource, tags, status }
   * @param {number} [limit=10]
   * @returns {SigmaRule[]}
   */
  search(query = '', filters = {}, limit = 10) {
    const q = query.toLowerCase().trim();
    const results = [];

    for (const rule of this._rules.values()) {
      // Apply hard filters first
      if (filters.level  && rule.level  !== filters.level)  continue;
      if (filters.status && rule.status !== filters.status) continue;
      if (filters.logsource) {
        const ls = rule.logsource;
        const fls = filters.logsource;
        if (fls.product  && ls.product  !== fls.product)  continue;
        if (fls.category && ls.category !== fls.category) continue;
        if (fls.service  && ls.service  !== fls.service)  continue;
      }
      if (filters.tags && filters.tags.length > 0) {
        const hasTag = filters.tags.some(ft => rule.tags.some(rt => rt.includes(ft.toLowerCase())));
        if (!hasTag) continue;
      }

      if (!q) {
        results.push({ rule, score: 0 });
        continue;
      }

      // Score-based ranking
      let score = 0;
      const titleLower = rule.title.toLowerCase();
      const descLower  = rule.description.toLowerCase();
      const tagsStr    = rule.tags.join(' ').toLowerCase();
      const yamlLower  = rule.yaml.toLowerCase();

      if (titleLower.includes(q)) score += 100;
      if (titleLower === q)        score += 200;
      if (descLower.includes(q))   score += 40;
      if (tagsStr.includes(q))     score += 30;
      if (yamlLower.includes(q))   score += 10;

      // Partial token matching
      const tokens = q.split(/\s+/);
      tokens.forEach(token => {
        if (token.length < 2) return;
        if (titleLower.includes(token)) score += 20;
        if (tagsStr.includes(token))    score += 10;
        if (descLower.includes(token))  score += 5;
      });

      if (score > 0) results.push({ rule, score });
    }

    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(r => r.rule);
  }

  /**
   * getById — retrieve a specific rule by ID.
   * @param {string} id
   * @returns {SigmaRule|null}
   */
  getById(id) {
    return this._rules.get(String(id)) || null;
  }

  /**
   * add — add or update a rule.
   * @param {Partial<SigmaRule>} ruleData
   * @returns {SigmaRule}
   */
  add(ruleData) {
    const id   = ruleData.id || crypto.randomUUID();
    const rule = {
      id,
      title:          ruleData.title          || 'Untitled Rule',
      status:         ruleData.status         || 'experimental',
      description:    ruleData.description    || '',
      references:     ruleData.references     || [],
      author:         ruleData.author         || 'RAKAY AI',
      date:           ruleData.date           || new Date().toISOString().slice(0, 10).replace(/-/g, '/'),
      tags:           ruleData.tags           || [],
      logsource:      ruleData.logsource      || {},
      detection:      ruleData.detection      || {},
      falsepositives: ruleData.falsepositives || [],
      level:          ruleData.level          || 'medium',
    };
    rule.yaml = ruleData.yaml || toYAML(rule);
    this._rules.set(id, rule);
    return rule;
  }

  /**
   * delete — remove a rule by ID.
   * @param {string} id
   * @returns {boolean}
   */
  delete(id) {
    return this._rules.delete(String(id));
  }

  /**
   * count — total number of rules in the KB.
   * @returns {number}
   */
  get count() { return this._rules.size; }

  /**
   * list — return all rules (paginated).
   * @param {number} [page=1]
   * @param {number} [pageSize=20]
   * @returns {{ rules: SigmaRule[], total: number, page: number, pageSize: number }}
   */
  list(page = 1, pageSize = 20) {
    const all   = [...this._rules.values()];
    const total = all.length;
    const start = (page - 1) * pageSize;
    return {
      rules:    all.slice(start, start + pageSize),
      total,
      page,
      pageSize,
    };
  }

  /**
   * toYAML — export a rule as YAML string.
   * @param {string} id
   * @returns {string|null}
   */
  toYAML(id) {
    const rule = this.getById(id);
    return rule ? rule.yaml : null;
  }
}

// ── Singleton export ───────────────────────────────────────────────────────────
const sigmaKB = new SigmaKB();

module.exports = {
  SigmaKB,
  sigmaKB,
  toYAML,
};
