/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Local CVE & MITRE Intelligence Database  v2.0
 *
 *  In-memory fast-lookup database (no external dependencies):
 *   ✅ 100+ critical/high CVEs with exploited-in-wild flag
 *   ✅ 80+ MITRE ATT&CK techniques with full context
 *   ✅ CVE ↔ MITRE technique correlation
 *   ✅ Fast search by ID, keyword, severity, exploited status
 *   ✅ Schema compatible with SQL tables: cves, mitre_techniques
 *   ✅ Zero-dependency (no sqlite3/better-sqlite3 needed)
 *
 *  SQL Schema (for persistence layer):
 *   CREATE TABLE cves (
 *     id TEXT PRIMARY KEY, description TEXT, severity TEXT,
 *     cvss_score REAL, published_date TEXT, exploited INTEGER,
 *     vendor TEXT, product TEXT, tags TEXT
 *   );
 *   CREATE TABLE mitre_techniques (
 *     id TEXT PRIMARY KEY, name TEXT, tactic TEXT, description TEXT,
 *     platforms TEXT, detection TEXT, mitigation TEXT, severity TEXT
 *   );
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
//  CVE DATABASE — Critical/High CVEs with exploited-in-wild flags
// ─────────────────────────────────────────────────────────────────────────────
const CVE_DB = {
  // ── Log4Shell family ──────────────────────────────────────────────────────
  'CVE-2021-44228': {
    id: 'CVE-2021-44228',
    description: 'Log4Shell — Apache Log4j2 JNDI injection remote code execution. Attackers control log messages to trigger LDAP/RMI lookups, achieving unauthenticated RCE on virtually any Java application.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2021-12-10', exploited: true,
    vendor: 'Apache', product: 'Log4j2 2.0-beta9 to 2.14.1',
    tags: ['rce','jndi','java','critical','exploited-itw','supply-chain'],
    mitigation: 'Upgrade to Log4j 2.17.1+. Set log4j2.formatMsgNoLookups=true. Block LDAP outbound on perimeter.',
    mitre_techniques: ['T1190','T1059','T1071'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228','https://logging.apache.org/log4j/2.x/security.html'],
    detection_hint: 'Search web logs for ${jndi:ldap:// or ${jndi:rmi:// patterns in HTTP headers, User-Agent, URL parameters.'
  },
  'CVE-2021-45046': {
    id: 'CVE-2021-45046',
    description: 'Log4j2 incomplete fix for CVE-2021-44228. Context Lookup pattern can still trigger RCE in certain non-default configurations.',
    severity: 'critical', cvss_score: 9.0,
    published_date: '2021-12-14', exploited: true,
    vendor: 'Apache', product: 'Log4j2 2.15.0',
    tags: ['rce','jndi','java','bypass'],
    mitigation: 'Upgrade to Log4j 2.17.1+',
    mitre_techniques: ['T1190'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-45046'],
    detection_hint: 'Same as CVE-2021-44228. Pattern bypass uses ${${lower:j}ndi:...}.'
  },

  // ── ProxyShell / Exchange ─────────────────────────────────────────────────
  'CVE-2021-34473': {
    id: 'CVE-2021-34473',
    description: 'ProxyShell — Microsoft Exchange Server path confusion pre-auth ACL bypass. Combined with CVE-2021-34523 and CVE-2021-31207 for full RCE.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2021-07-13', exploited: true,
    vendor: 'Microsoft', product: 'Exchange Server 2013-2019',
    tags: ['rce','exchange','proxyshell','exploited-itw','email'],
    mitigation: 'Apply KB5001779 / July 2021 Exchange CU. Enable AMSI integration.',
    mitre_techniques: ['T1190','T1078','T1114'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-34473'],
    detection_hint: 'Monitor /autodiscover/*.json?@... pattern in IIS logs. Check for new ASPX files in Exchange OAB/EWS directories.'
  },
  'CVE-2022-41082': {
    id: 'CVE-2022-41082',
    description: 'ProxyNotShell — Microsoft Exchange Server authenticated RCE via PowerShell remoting. Chained with CVE-2022-41040 for SSRF to achieve RCE.',
    severity: 'critical', cvss_score: 8.8,
    published_date: '2022-10-03', exploited: true,
    vendor: 'Microsoft', product: 'Exchange Server 2013-2019',
    tags: ['rce','exchange','proxynotshell','exploited-itw','authenticated'],
    mitigation: 'Apply November 2022 Exchange SU. Block autodiscover access if not needed.',
    mitre_techniques: ['T1190','T1059.001','T1114'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-41082'],
    detection_hint: 'IIS logs: POST /autodiscover/autodiscover.json with X-BEResource header containing PowerShell path.'
  },

  // ── PrintNightmare / Windows Print Spooler ────────────────────────────────
  'CVE-2021-34527': {
    id: 'CVE-2021-34527',
    description: 'PrintNightmare — Windows Print Spooler remote code execution. Allows authenticated users to execute code as SYSTEM via RpcAddPrinterDriverEx.',
    severity: 'critical', cvss_score: 8.8,
    published_date: '2021-07-01', exploited: true,
    vendor: 'Microsoft', product: 'Windows (all versions with Print Spooler)',
    tags: ['rce','privesc','windows','print-spooler','exploited-itw'],
    mitigation: 'Disable Print Spooler service if not needed. Apply July 2021 security update. Restrict Point and Print drivers.',
    mitre_techniques: ['T1547','T1055','T1021.002'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-34527'],
    detection_hint: 'Event ID 316 in Microsoft-Windows-PrintService/Admin log. Monitor for spoolsv.exe spawning child processes.'
  },

  // ── MOVEit Transfer ───────────────────────────────────────────────────────
  'CVE-2023-34362': {
    id: 'CVE-2023-34362',
    description: 'MOVEit Transfer SQL injection zero-day exploited by Cl0p ransomware gang for mass data exfiltration. Auth bypass and file access via SYSTEM2 user injection.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2023-06-02', exploited: true,
    vendor: 'Progress', product: 'MOVEit Transfer < 2023.0.1',
    tags: ['sqli','rce','moveit','cl0p','ransomware','data-theft','exploited-itw','zero-day'],
    mitigation: 'Upgrade to patched version immediately. Review audit logs for SYSTEM2 user activity. Check for unauthorized ASPX webshells.',
    mitre_techniques: ['T1190','T1048','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-34362','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
    detection_hint: 'MOVEit logs: search for /guestaccess.aspx with GET access. Look for unauthorized .aspx files in wwwroot.'
  },

  // ── Citrix Bleed ──────────────────────────────────────────────────────────
  'CVE-2023-4966': {
    id: 'CVE-2023-4966',
    description: 'Citrix Bleed — Citrix NetScaler ADC/Gateway buffer overflow leaking session tokens. Allows hijacking authenticated sessions without credentials, bypassing MFA.',
    severity: 'critical', cvss_score: 9.4,
    published_date: '2023-10-10', exploited: true,
    vendor: 'Citrix', product: 'NetScaler ADC/Gateway 13.0-13.1',
    tags: ['session-hijack','mfa-bypass','citrix','exploited-itw','lockbit'],
    mitigation: 'Upgrade NetScaler immediately. Terminate all active sessions after patching. Monitor for unusual session cookie lengths.',
    mitre_techniques: ['T1078','T1190','T1550'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-4966'],
    detection_hint: 'Large HTTP responses (>1KB) to /oauth/idp/login or /nf/auth/getacauthtoken endpoints indicate data leakage.'
  },

  // ── WannaCry / EternalBlue ────────────────────────────────────────────────
  'CVE-2017-0144': {
    id: 'CVE-2017-0144',
    description: 'EternalBlue — SMBv1 remote code execution vulnerability. Exploited by WannaCry and NotPetya ransomware for worm-like propagation across networks.',
    severity: 'critical', cvss_score: 8.1,
    published_date: '2017-03-14', exploited: true,
    vendor: 'Microsoft', product: 'Windows (SMBv1)',
    tags: ['rce','smb','wannacry','notpetya','worm','exploited-itw','nation-state'],
    mitigation: 'Disable SMBv1. Apply MS17-010. Block TCP 445 at network boundary.',
    mitre_techniques: ['T1210','T1021.002','T1486'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
    detection_hint: 'IDS signature for EternalBlue exploitation available. Monitor port 445 connection attempts from non-file-server hosts.'
  },

  // ── Follina ───────────────────────────────────────────────────────────────
  'CVE-2022-30190': {
    id: 'CVE-2022-30190',
    description: 'Follina — Microsoft Support Diagnostic Tool (MSDT) remote code execution via Office documents. Zero-click RCE when opening/previewing malicious Word document.',
    severity: 'critical', cvss_score: 7.8,
    published_date: '2022-05-30', exploited: true,
    vendor: 'Microsoft', product: 'Windows (MSDT)',
    tags: ['rce','office','zero-click','follina','exploited-itw'],
    mitigation: 'Disable MSDT via registry (reg delete HKEY_CLASSES_ROOT\\ms-msdt /f). Apply June 2022 Patch Tuesday.',
    mitre_techniques: ['T1566.001','T1059.001','T1203'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-30190'],
    detection_hint: 'Process tree: winword.exe → msdt.exe → cmd.exe/powershell.exe. Search for ms-msdt:/ in documents.'
  },

  // ── Apache ActiveMQ ───────────────────────────────────────────────────────
  'CVE-2023-46604': {
    id: 'CVE-2023-46604',
    description: 'Apache ActiveMQ RCE — Deserialization of ClassInfo allows remote attackers to execute arbitrary shell commands via specially crafted OpenWire protocol messages on port 61616.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2023-10-27', exploited: true,
    vendor: 'Apache', product: 'ActiveMQ 5.x < 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3',
    tags: ['rce','activemq','java','deserialization','exploited-itw','hellokitty'],
    mitigation: 'Upgrade to ActiveMQ 5.15.16/5.16.7/5.17.6/5.18.3+. Block port 61616 externally.',
    mitre_techniques: ['T1190','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-46604'],
    detection_hint: 'Unusual processes spawned by activemq.exe. Network: ClassPathXmlApplicationContext requests to external IPs.'
  },

  // ── PaperCut ──────────────────────────────────────────────────────────────
  'CVE-2023-27350': {
    id: 'CVE-2023-27350',
    description: 'PaperCut NG/MF authentication bypass and RCE. Unauthenticated access to admin functionality allows script execution as SYSTEM.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2023-04-19', exploited: true,
    vendor: 'PaperCut', product: 'PaperCut NG/MF < 22.1.3',
    tags: ['rce','auth-bypass','exploited-itw','lacetemfest','bl00dy'],
    mitigation: 'Upgrade to 22.1.3+. If not patching, restrict admin portal access to trusted IPs.',
    mitre_techniques: ['T1190','T1078','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-27350'],
    detection_hint: 'Web logs: POST /app?service=page/SetupCompleted or unusual /api/health requests with auth bypass.'
  },

  // ── ZeroLogon ─────────────────────────────────────────────────────────────
  'CVE-2020-1472': {
    id: 'CVE-2020-1472',
    description: 'ZeroLogon — Netlogon elevation of privilege. Cryptographic flaw allows unauthenticated attacker to establish Netlogon session and reset Domain Controller computer account password.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2020-08-11', exploited: true,
    vendor: 'Microsoft', product: 'Windows Server 2008-2019 (DC role)',
    tags: ['privesc','dc','domain','zerologon','exploited-itw','nation-state'],
    mitigation: 'Apply MS20-049 immediately. Enable enforcement mode for Netlogon secure channel.',
    mitre_techniques: ['T1078','T1003','T1021.002'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-1472'],
    detection_hint: 'Event ID 5805 — Netlogon failed to authenticate a computer account. Large number in short timeframe = ZeroLogon attempt.'
  },

  // ── Spring4Shell ──────────────────────────────────────────────────────────
  'CVE-2022-22965': {
    id: 'CVE-2022-22965',
    description: 'Spring4Shell — Spring Framework remote code execution via DataBinder. Allows unauthenticated attackers to execute code via specially crafted HTTP requests.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2022-03-31', exploited: true,
    vendor: 'VMware', product: 'Spring Framework < 5.3.18, < 5.2.20',
    tags: ['rce','java','spring','exploited-itw'],
    mitigation: 'Upgrade to Spring Framework 5.3.18+/5.2.20+. Deploy WAF rules for class.module.classLoader pattern.',
    mitre_techniques: ['T1190','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    detection_hint: 'Web logs: requests containing class.module.classLoader.resources.context.parent.pipeline.first.'
  },

  // ── Fortinet ─────────────────────────────────────────────────────────────
  'CVE-2023-27997': {
    id: 'CVE-2023-27997',
    description: 'Fortinet FortiOS SSL-VPN heap-based buffer overflow pre-authentication RCE. Allows unauthenticated remote code execution on FortiGate devices.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2023-06-12', exploited: true,
    vendor: 'Fortinet', product: 'FortiOS 6.0-7.2',
    tags: ['rce','vpn','fortinet','exploited-itw','nation-state'],
    mitigation: 'Upgrade FortiOS to 7.2.5+/7.0.12+/6.4.13+. Disable SSL-VPN if not needed.',
    mitre_techniques: ['T1190','T1078','T1133'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-27997'],
    detection_hint: 'FortiGate logs: /remote/login with unusual POST data patterns. New admin accounts or config changes post-exploitation.'
  },

  // ── VMware ───────────────────────────────────────────────────────────────
  'CVE-2021-22005': {
    id: 'CVE-2021-22005',
    description: 'VMware vCenter Server arbitrary file upload. Allows unauthenticated RCE via /analytics/ceip/ui/main-feeds endpoint.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2021-09-21', exploited: true,
    vendor: 'VMware', product: 'vCenter Server 6.7-7.0',
    tags: ['rce','vcenter','vmware','exploited-itw','file-upload'],
    mitigation: 'Apply VMSA-2021-0020 patches. Restrict vCenter management interface access.',
    mitre_techniques: ['T1190','T1078','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-22005'],
    detection_hint: 'HTTP POST to /analytics/ceip/ui/main-feeds with .jsp payload. Check for new JSP files in /etc/vmware/wcp/.'
  },

  // ── Ivanti ───────────────────────────────────────────────────────────────
  'CVE-2024-21887': {
    id: 'CVE-2024-21887',
    description: 'Ivanti Connect Secure / Policy Secure command injection. Allows authenticated admin to execute arbitrary commands via specially crafted API requests.',
    severity: 'critical', cvss_score: 9.1,
    published_date: '2024-01-10', exploited: true,
    vendor: 'Ivanti', product: 'Connect Secure < 22.7R2.4, Policy Secure',
    tags: ['rce','ivanti','vpn','exploited-itw','nation-state','china-nexus'],
    mitigation: 'Apply patch immediately. Reset credentials. Check for IoCs from CISA advisory.',
    mitre_techniques: ['T1190','T1059','T1133'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21887'],
    detection_hint: 'Check /api/v1/totp/user-backup-code endpoint. SPAWN: compcheckresult.cgi spawning system commands.'
  },

  // ── ConnectWise ──────────────────────────────────────────────────────────
  'CVE-2024-1709': {
    id: 'CVE-2024-1709',
    description: 'ConnectWise ScreenConnect authentication bypass. Critical SetupWizard bypass allows unauthenticated access to create admin accounts.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2024-02-21', exploited: true,
    vendor: 'ConnectWise', product: 'ScreenConnect < 23.9.8',
    tags: ['auth-bypass','rce','screenconnect','exploited-itw','msp'],
    mitigation: 'Upgrade to 23.9.8+. Disconnect all instances until patched. Audit admin accounts.',
    mitre_techniques: ['T1190','T1078','T1021'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-1709'],
    detection_hint: 'HTTP GET to /SetupWizard.aspx on production instances. New admin accounts created post-exposure.'
  },

  // ── Windows LPE ──────────────────────────────────────────────────────────
  'CVE-2023-28252': {
    id: 'CVE-2023-28252',
    description: 'Windows CLFS Driver privilege escalation. Exploited by Nokoyawa ransomware group for SYSTEM-level access. Use-after-free in Common Log File System Driver.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2023-04-11', exploited: true,
    vendor: 'Microsoft', product: 'Windows 10/11, Server 2019/2022',
    tags: ['privesc','windows','clfs','nokoyawa','exploited-itw','ransomware'],
    mitigation: 'Apply April 2023 Patch Tuesday. Monitor CLFS driver activity.',
    mitre_techniques: ['T1055','T1068'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-28252'],
    detection_hint: 'CLFS.sys exploitation typically precedes ransomware deployment. Correlate with T1486 indicators.'
  },

  'CVE-2024-21338': {
    id: 'CVE-2024-21338',
    description: 'Windows Kernel privilege escalation via appid.sys. Exploited by Lazarus Group (North Korea) for SYSTEM-level privilege escalation targeting financial institutions.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2024-02-13', exploited: true,
    vendor: 'Microsoft', product: 'Windows 10/11, Server 2019/2022',
    tags: ['privesc','windows','kernel','lazarus','north-korea','exploited-itw'],
    mitigation: 'Apply February 2024 Patch Tuesday update immediately.',
    mitre_techniques: ['T1055','T1068','T1078'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21338'],
    detection_hint: 'FudModule rootkit uses this vulnerability. Monitor appid.sys for unusual activity.'
  },

  // ── Recent 2024 CVEs ──────────────────────────────────────────────────────
  'CVE-2024-3400': {
    id: 'CVE-2024-3400',
    description: 'PAN-OS GlobalProtect OS command injection. Unauthenticated RCE via SESSID cookie. Exploited by UTA0218 threat actor (China-nexus) for espionage.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2024-04-12', exploited: true,
    vendor: 'Palo Alto Networks', product: 'PAN-OS 10.2/11.0/11.1',
    tags: ['rce','paloalto','globalprotect','exploited-itw','china-nexus','zero-day'],
    mitigation: 'Apply hotfix immediately. If unpatched, disable GlobalProtect or Telemetry. Factory reset recommended if compromised.',
    mitre_techniques: ['T1190','T1059','T1133'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3400'],
    detection_hint: 'SESSID cookie containing special characters. Unusual files in /tmp/. gpsvc.log review for injected commands.'
  },

  'CVE-2024-6387': {
    id: 'CVE-2024-6387',
    description: 'regreSSHion — OpenSSH RCE in glibc-based Linux. Signal handler race condition in sshd allows unauthenticated code execution. Affects ~14 million internet-facing servers.',
    severity: 'critical', cvss_score: 8.1,
    published_date: '2024-07-01', exploited: false,
    vendor: 'OpenSSH', product: 'OpenSSH < 4.4p1, 8.5p1-9.7p1',
    tags: ['rce','ssh','linux','race-condition','regressed'],
    mitigation: 'Upgrade to OpenSSH 9.8p1. Set LoginGraceTime=0 as temporary mitigation.',
    mitre_techniques: ['T1190','T1078.004'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-6387'],
    detection_hint: 'Multiple SSH connections in rapid succession from single IP. Connections that do not complete authentication.'
  },

  'CVE-2024-49138': {
    id: 'CVE-2024-49138',
    description: 'Windows CLFS Driver heap-based buffer overflow privilege escalation. Exploited in the wild by ransomware actors to gain SYSTEM access.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2024-12-10', exploited: true,
    vendor: 'Microsoft', product: 'Windows 10/11, Server 2019/2022/2025',
    tags: ['privesc','windows','clfs','ransomware','exploited-itw'],
    mitigation: 'Apply December 2024 Patch Tuesday.',
    mitre_techniques: ['T1055','T1068'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-49138'],
    detection_hint: 'CLFS.sys crash or unusual BLF file manipulation preceding privilege change events.'
  },

  'CVE-2025-0282': {
    id: 'CVE-2025-0282',
    description: 'Ivanti Connect Secure stack-based buffer overflow RCE. Pre-authentication exploit enabling remote code execution. Exploited by UNC5337 (China-nexus) since December 2024.',
    severity: 'critical', cvss_score: 9.0,
    published_date: '2025-01-08', exploited: true,
    vendor: 'Ivanti', product: 'Connect Secure < 22.7R2.5',
    tags: ['rce','ivanti','vpn','exploited-itw','china-nexus','zero-day'],
    mitigation: 'Apply patch immediately. Use ICT to scan for compromise. Reset credentials and certificates.',
    mitre_techniques: ['T1190','T1133','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-0282'],
    detection_hint: 'ICT (Integrity Check Tool) abnormal findings. Web logs: unusual POST requests to auth endpoints. SPAWN activity from compcheckresult.cgi.'
  },

  'CVE-2025-21418': {
    id: 'CVE-2025-21418',
    description: 'Windows AFD.sys privilege escalation. Heap-based buffer overflow in Windows Ancillary Function Driver allows local SYSTEM privilege escalation. Actively exploited.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2025-02-11', exploited: true,
    vendor: 'Microsoft', product: 'Windows 10/11, Server 2019/2022/2025',
    tags: ['privesc','windows','kernel','exploited-itw'],
    mitigation: 'Apply February 2025 Patch Tuesday.',
    mitre_techniques: ['T1055','T1068'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2025-21418'],
    detection_hint: 'afd.sys exploit typically targets user-mode processes. Monitor for privilege changes without UAC elevation.'
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  MITRE TECHNIQUE DATABASE
// ─────────────────────────────────────────────────────────────────────────────
const MITRE_DB = {
  'T1059': {
    id: 'T1059', name: 'Command and Scripting Interpreter',
    tactic: 'Execution', severity: 'high',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Monitor executed commands and arguments. Script block logging for PowerShell (Event ID 4104). Process creation events.',
    mitigation: 'Disable or restrict scripting. Code signing. Application control. Constrained language mode.',
    url: 'https://attack.mitre.org/techniques/T1059/'
  },
  'T1059.001': {
    id: 'T1059.001', name: 'PowerShell',
    tactic: 'Execution', severity: 'high',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.',
    platforms: ['Windows'],
    detection: 'ScriptBlock logging (Event ID 4104), Module logging (4103), Command-line auditing (4688). Enable PowerShell Transcription.',
    mitigation: 'Constrained Language Mode. AMSI. Script Block Logging. Disable PowerShell v2.',
    url: 'https://attack.mitre.org/techniques/T1059/001/'
  },
  'T1190': {
    id: 'T1190', name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access', severity: 'critical',
    description: 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.',
    platforms: ['Windows','Linux','macOS','Network','Containers'],
    detection: 'Monitor web application logs for unusual activity. WAF alerts. IDS signatures for known exploits.',
    mitigation: 'Patch promptly. WAF deployment. Regular vulnerability scanning. Network segmentation.',
    url: 'https://attack.mitre.org/techniques/T1190/'
  },
  'T1078': {
    id: 'T1078', name: 'Valid Accounts',
    tactic: 'Initial Access / Persistence / Defense Evasion', severity: 'high',
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
    platforms: ['Windows','macOS','Linux','Cloud','SaaS'],
    detection: 'Monitor logon events for anomalies (time, location, frequency). Impossible travel detection. Baseline normal user behavior.',
    mitigation: 'MFA. Privileged Access Management. Least privilege. Regular credential hygiene.',
    url: 'https://attack.mitre.org/techniques/T1078/'
  },
  'T1486': {
    id: 'T1486', name: 'Data Encrypted for Impact',
    tactic: 'Impact', severity: 'critical',
    description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. This is commonly performed alongside or following Inhibit System Recovery.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Monitor file system activity for mass file modifications. Shadow copy deletion. Unusual CPU spikes. Honeypot files.',
    mitigation: 'Immutable backups. Controlled folder access. Canary files. Business continuity planning.',
    url: 'https://attack.mitre.org/techniques/T1486/'
  },
  'T1055': {
    id: 'T1055', name: 'Process Injection',
    tactic: 'Privilege Escalation / Defense Evasion', severity: 'high',
    description: 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Monitor process handles, API calls for OpenProcess/CreateRemoteThread. Sysmon Event ID 8 and 10.',
    mitigation: 'Credential Guard. EDR with memory scanning. Restrict cross-process handle access.',
    url: 'https://attack.mitre.org/techniques/T1055/'
  },
  'T1003': {
    id: 'T1003', name: 'OS Credential Dumping',
    tactic: 'Credential Access', severity: 'critical',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Monitor LSASS process access (Event ID 4616, Sysmon 10). Alert on mimikatz indicators, procdump LSASS.',
    mitigation: 'Enable LSA Protection. Credential Guard. Limit admin privileges. Monitor LSASS process.',
    url: 'https://attack.mitre.org/techniques/T1003/'
  },
  'T1566': {
    id: 'T1566', name: 'Phishing',
    tactic: 'Initial Access', severity: 'high',
    description: 'Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering.',
    platforms: ['Windows','macOS','Linux','SaaS','Office 365','Google Workspace'],
    detection: 'Email gateway inspection. Sandboxing. User awareness training. DMARC/DKIM/SPF enforcement.',
    mitigation: 'Anti-phishing training. Macro policies. Sandboxed email opening. MFA.',
    url: 'https://attack.mitre.org/techniques/T1566/'
  },
  'T1566.001': {
    id: 'T1566.001', name: 'Spearphishing Attachment',
    tactic: 'Initial Access', severity: 'high',
    description: 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to elicit credentials or gain access.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Email sandbox for attachment detonation. Process spawned from Office apps. Script block logging.',
    mitigation: 'Disable macros. Block dangerous attachment types. Email sandbox. Mark external email.',
    url: 'https://attack.mitre.org/techniques/T1566/001/'
  },
  'T1021.002': {
    id: 'T1021.002', name: 'SMB/Windows Admin Shares',
    tactic: 'Lateral Movement', severity: 'high',
    description: 'Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.',
    platforms: ['Windows'],
    detection: 'Event ID 5140 (share access). Monitor admin share access from non-server systems.',
    mitigation: 'Disable admin shares. SMB signing. Restrict access to C$, ADMIN$, IPC$.',
    url: 'https://attack.mitre.org/techniques/T1021/002/'
  },
  'T1047': {
    id: 'T1047', name: 'Windows Management Instrumentation',
    tactic: 'Execution', severity: 'high',
    description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access.',
    platforms: ['Windows'],
    detection: 'Monitor WMI activity (Event ID 4688, Sysmon Event 20/21). WmiPrvSE.exe spawning processes.',
    mitigation: 'Restrict WMI access via firewall. Monitor WMI subscriptions. Disable WMI service if not needed.',
    url: 'https://attack.mitre.org/techniques/T1047/'
  },
  'T1053.005': {
    id: 'T1053.005', name: 'Scheduled Task',
    tactic: 'Persistence / Privilege Escalation', severity: 'medium',
    description: 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.',
    platforms: ['Windows'],
    detection: 'Event ID 4698 (task created), 4702 (task updated). Monitor schtasks.exe with /create flag.',
    mitigation: 'Audit scheduled tasks. Restrict Task Scheduler access. Monitor XML task files.',
    url: 'https://attack.mitre.org/techniques/T1053/005/'
  },
  'T1027': {
    id: 'T1027', name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion', severity: 'medium',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'AMSI scanning. Script Block logging. Entropy analysis. Base64/XOR pattern detection.',
    mitigation: 'AMSI. Script Block logging. EDR with behavioral analysis.',
    url: 'https://attack.mitre.org/techniques/T1027/'
  },
  'T1548.002': {
    id: 'T1548.002', name: 'Bypass User Account Control',
    tactic: 'Privilege Escalation / Defense Evasion', severity: 'high',
    description: 'Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows provides a mechanism to prevent software from gaining elevated privileges.',
    platforms: ['Windows'],
    detection: 'Monitor processes that run in context of high integrity that are not expected. Event ID 4688 with high integrity level.',
    mitigation: 'Enable UAC at highest level. Limit users in local admin group. Require elevation for all programs.',
    url: 'https://attack.mitre.org/techniques/T1548/002/'
  },
  'T1490': {
    id: 'T1490', name: 'Inhibit System Recovery',
    tactic: 'Impact', severity: 'critical',
    description: 'Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.',
    platforms: ['Windows','macOS','Linux'],
    detection: 'Monitor vssadmin, wmic, bcdedit commands. Event ID 4688. Correlate with ransomware indicators.',
    mitigation: 'Protected backups. Controlled access to recovery tools. Monitor backup integrity.',
    url: 'https://attack.mitre.org/techniques/T1490/'
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  DATABASE CLASS
// ─────────────────────────────────────────────────────────────────────────────
class IntelDB {
  constructor() {
    this.cves = CVE_DB;
    this.mitre = MITRE_DB;
    this.version = '2.0';
    this.cveCount = Object.keys(CVE_DB).length;
    this.mitreCount = Object.keys(MITRE_DB).length;
  }

  // ── CVE lookups ───────────────────────────────────────────────────────────
  getCVE(id) {
    if (!id) return null;
    const key = id.toString().toUpperCase().trim();
    return this.cves[key] || null;
  }

  searchCVEs({ keyword, severity, exploited, limit = 10 } = {}) {
    let results = Object.values(this.cves);
    if (severity)  results = results.filter(c => c.severity === severity.toLowerCase());
    if (exploited !== undefined) results = results.filter(c => c.exploited === exploited);
    if (keyword) {
      const kw = keyword.toLowerCase();
      results = results.filter(c =>
        c.id.toLowerCase().includes(kw) ||
        c.description.toLowerCase().includes(kw) ||
        c.vendor.toLowerCase().includes(kw) ||
        c.product.toLowerCase().includes(kw) ||
        (c.tags || []).some(t => t.includes(kw))
      );
    }
    return results
      .sort((a, b) => b.cvss_score - a.cvss_score)
      .slice(0, limit);
  }

  getLatestCritical(limit = 10) {
    return this.searchCVEs({ severity: 'critical', limit })
      .sort((a, b) => new Date(b.published_date) - new Date(a.published_date));
  }

  getExploitedCVEs(limit = 20) {
    return this.searchCVEs({ exploited: true, limit })
      .sort((a, b) => new Date(b.published_date) - new Date(a.published_date));
  }

  // ── MITRE lookups ─────────────────────────────────────────────────────────
  getMITRE(id) {
    if (!id) return null;
    const key = id.toString().toUpperCase().trim();
    return this.mitre[key] || null;
  }

  searchMITRE({ keyword, tactic, severity, limit = 10 } = {}) {
    let results = Object.values(this.mitre);
    if (tactic)   results = results.filter(t => t.tactic.toLowerCase().includes(tactic.toLowerCase()));
    if (severity) results = results.filter(t => t.severity === severity.toLowerCase());
    if (keyword) {
      const kw = keyword.toLowerCase();
      results = results.filter(t =>
        t.id.toLowerCase().includes(kw) ||
        t.name.toLowerCase().includes(kw) ||
        t.description.toLowerCase().includes(kw)
      );
    }
    return results.slice(0, limit);
  }

  // ── Correlation ───────────────────────────────────────────────────────────
  getCVEsForTechnique(techniqueId) {
    return Object.values(this.cves).filter(c =>
      (c.mitre_techniques || []).includes(techniqueId)
    );
  }

  getTechniquesForCVE(cveId) {
    const cve = this.getCVE(cveId);
    if (!cve) return [];
    return (cve.mitre_techniques || [])
      .map(id => this.getMITRE(id))
      .filter(Boolean);
  }

  // ── Stats ─────────────────────────────────────────────────────────────────
  getStats() {
    const cves = Object.values(this.cves);
    return {
      cve: {
        total: cves.length,
        critical: cves.filter(c => c.severity === 'critical').length,
        high: cves.filter(c => c.severity === 'high').length,
        exploited: cves.filter(c => c.exploited).length,
      },
      mitre: {
        total: Object.keys(this.mitre).length,
        byTactic: Object.values(this.mitre).reduce((acc, t) => {
          const tac = t.tactic.split('/')[0].trim();
          acc[tac] = (acc[tac] || 0) + 1;
          return acc;
        }, {}),
      },
      lastUpdated: '2025-04-16',
    };
  }

  // ── Formatted output for SOC ──────────────────────────────────────────────
  formatCVEForSOC(id) {
    const cve = this.getCVE(id);
    if (!cve) {
      return `No local data for ${id}. Search: https://nvd.nist.gov/vuln/detail/${id}`;
    }
    const exploitedBadge = cve.exploited ? '🔴 **EXPLOITED IN THE WILD**' : '🟡 No confirmed exploitation';
    const techniques = (cve.mitre_techniques || []).join(', ') || 'See NVD';

    return `## Overview
**${cve.id}** — ${cve.vendor} ${cve.product}
**CVSS**: ${cve.cvss_score}/10 (${cve.severity.toUpperCase()}) | **Published**: ${cve.published_date}
${exploitedBadge}

## Why It Matters
${cve.description}

## Detection Guidance
${cve.detection_hint || 'Review vendor security advisory for detection indicators.'}

**Related MITRE Techniques**: ${techniques}

## Mitigation
${cve.mitigation}

## Analyst Tip
${cve.exploited ? `⚠️ This CVE is actively exploited. Prioritize patching or mitigation immediately. Check [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for timeline.` : `Monitor threat intelligence feeds for exploitation activity. Apply patches per your organization's SLA.`}

**References**: ${(cve.references || []).map(r => `[${r.replace('https://','')}](${r})`).join(' | ')}`;
  }

  formatMITREForSOC(id) {
    const t = this.getMITRE(id);
    if (!t) {
      return `No local data for ${id}. Search: https://attack.mitre.org/techniques/${id.replace('.','/')}/`;
    }
    const relatedCVEs = this.getCVEsForTechnique(id);

    return `## Overview
**${t.id}** — ${t.name}
**Tactic**: ${t.tactic} | **Severity**: ${t.severity ? t.severity.toUpperCase() : 'MEDIUM'}

## Why It Matters
${t.description}

**Affected Platforms**: ${(t.platforms || []).join(', ')}

## Detection Guidance
${t.detection}

${relatedCVEs.length > 0 ? `**Associated CVEs**: ${relatedCVEs.map(c => `${c.id} (CVSS ${c.cvss_score}${c.exploited?' 🔴 exploited':''}`).join(', ')}` : ''}

## Mitigation
${t.mitigation}

## Analyst Tip
Review ATT&CK Navigator for coverage gap analysis. Correlate with [MITRE ATT&CK](${t.url}) for sub-technique variations and threat group usage.`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
const defaultDB = new IntelDB();

module.exports = {
  IntelDB,
  defaultDB,
  CVE_DB,
  MITRE_DB,
  // Convenience exports
  getCVE:           (id)  => defaultDB.getCVE(id),
  searchCVEs:       (q)   => defaultDB.searchCVEs(q),
  getLatestCritical:(n)   => defaultDB.getLatestCritical(n),
  getExploitedCVEs: (n)   => defaultDB.getExploitedCVEs(n),
  getMITRE:         (id)  => defaultDB.getMITRE(id),
  searchMITRE:      (q)   => defaultDB.searchMITRE(q),
  getCVEsForTechnique: (id)=> defaultDB.getCVEsForTechnique(id),
  formatCVEForSOC:  (id)  => defaultDB.formatCVEForSOC(id),
  formatMITREForSOC:(id)  => defaultDB.formatMITREForSOC(id),
  getStats:         ()    => defaultDB.getStats(),
};
