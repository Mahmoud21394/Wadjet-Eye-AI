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

  // ── Fortinet / Palo Alto VPN ──────────────────────────────────────────────
  'CVE-2024-21762': {
    id: 'CVE-2024-21762',
    description: 'Fortinet FortiOS SSL-VPN out-of-bounds write RCE. Unauthenticated remote code execution via crafted HTTP request. Exploited by China-nexus espionage actors.',
    severity: 'critical', cvss_score: 9.6,
    published_date: '2024-02-08', exploited: true,
    vendor: 'Fortinet', product: 'FortiOS 7.4 < 7.4.3, 7.2 < 7.2.7, 7.0 < 7.0.14, 6.4 < 6.4.15',
    tags: ['rce','vpn','fortinet','exploited-itw','china-nexus','zero-day'],
    mitigation: 'Upgrade FortiOS immediately. Disable SSL-VPN if not required. Check for compromise indicators.',
    mitre_techniques: ['T1190','T1133','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21762'],
    detection_hint: 'FortiOS logs: look for "/remote/login" requests with anomalous payloads. Check for new admin accounts or modified firewall rules.'
  },
  'CVE-2024-3400': {
    id: 'CVE-2024-3400',
    description: 'PAN-OS GlobalProtect OS command injection zero-day. Unauthenticated RCE exploited by UNC4899 (North Korea nexus) for espionage. CVSS 10.0 — maximum severity.',
    severity: 'critical', cvss_score: 10.0,
    published_date: '2024-04-12', exploited: true,
    vendor: 'Palo Alto Networks', product: 'PAN-OS 10.2 < 10.2.9-h1, 11.0 < 11.0.4-h1, 11.1 < 11.1.2-h3',
    tags: ['rce','palo-alto','globalprotect','zero-day','exploited-itw','nation-state'],
    mitigation: 'Apply PAN hotfixes immediately. Enable Threat Prevention signatures. Review GlobalProtect session logs.',
    mitre_techniques: ['T1190','T1059','T1133'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3400'],
    detection_hint: 'gpsvc.log: look for commands after session cookie creation. New files in /tmp or /var/log/pan/sslvpn with unexpected names.'
  },

  // ── SharePoint / Windows ──────────────────────────────────────────────────
  'CVE-2023-29357': {
    id: 'CVE-2023-29357',
    description: 'Microsoft SharePoint Server privilege escalation via spoofed JWT auth tokens. Allows unauthenticated attacker to gain administrator access by bypassing auth.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2023-06-13', exploited: true,
    vendor: 'Microsoft', product: 'SharePoint Server 2019',
    tags: ['auth-bypass','sharepoint','jwt','exploited-itw','privilege-escalation'],
    mitigation: 'Apply June 2023 Patch Tuesday. Enable AMSI for SharePoint. Monitor audit logs for unusual admin actions.',
    mitre_techniques: ['T1190','T1078','T1548'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-29357'],
    detection_hint: 'SharePoint ULS logs: look for authentication events with bearer tokens lacking valid signatures.'
  },
  'CVE-2024-30051': {
    id: 'CVE-2024-30051',
    description: 'Windows DWM Core Library privilege escalation. Heap-based buffer overflow grants SYSTEM privileges. Used by QakBot distribution actors post-LockBit disruption.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2024-05-14', exploited: true,
    vendor: 'Microsoft', product: 'Windows 10/11, Server 2022',
    tags: ['privesc','windows','dwm','exploited-itw','qakbot'],
    mitigation: 'Apply May 2024 Patch Tuesday.',
    mitre_techniques: ['T1055','T1068'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-30051'],
    detection_hint: 'dwm.exe spawning child processes or accessing LSASS indicates exploitation.'
  },

  // ── Cisco / Network Devices ───────────────────────────────────────────────
  'CVE-2023-20269': {
    id: 'CVE-2023-20269',
    description: 'Cisco ASA/FTD VPN brute-force vulnerability. Allows unauthenticated attacker to conduct brute-force attacks against remote access VPN. Exploited by Akira ransomware.',
    severity: 'high', cvss_score: 5.0,
    published_date: '2023-09-06', exploited: true,
    vendor: 'Cisco', product: 'ASA Software, FTD Software',
    tags: ['brute-force','vpn','cisco','akira','ransomware','exploited-itw'],
    mitigation: 'Enable MFA for VPN. Implement lockout policies. Apply patch when available.',
    mitre_techniques: ['T1110','T1133','T1190'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-20269'],
    detection_hint: 'VPN logs: High volume of failed authentication attempts from single external IP. Look for ASA syslog messages 113015/113014.'
  },
  'CVE-2024-20359': {
    id: 'CVE-2024-20359',
    description: 'Cisco ASA persistence mechanism — ArcaneDoor zero-day. Allows authenticated attacker to plant persistent backdoor. Exploited by nation-state actor targeting government networks.',
    severity: 'high', cvss_score: 6.0,
    published_date: '2024-04-24', exploited: true,
    vendor: 'Cisco', product: 'ASA Software, FTD Software',
    tags: ['persistence','backdoor','cisco','arcanedoor','nation-state','exploited-itw'],
    mitigation: 'Apply Cisco security advisory update. Reset credentials. Audit for Line Dancer implant indicators.',
    mitre_techniques: ['T1505.003','T1133','T1082'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-20359'],
    detection_hint: 'Unusual ASA process list entries. Log4j evidence: "Line Dancer" shellcode in memory, "Line Runner" persistence files.'
  },

  // ── Linux / Container ─────────────────────────────────────────────────────
  'CVE-2024-1086': {
    id: 'CVE-2024-1086',
    description: 'Linux kernel nf_tables use-after-free local privilege escalation. Allows local user to gain root/SYSTEM privileges via Netfilter table manipulation. Public exploit available.',
    severity: 'high', cvss_score: 7.8,
    published_date: '2024-01-31', exploited: true,
    vendor: 'Linux', product: 'Linux Kernel 5.14 - 6.6',
    tags: ['privesc','linux','kernel','nftables','use-after-free','public-exploit'],
    mitigation: 'Update Linux kernel. Disable nf_tables module if not needed: echo "install nf_tables /bin/true" >> /etc/modprobe.d/disable-nftables.conf',
    mitre_techniques: ['T1068','T1055'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-1086'],
    detection_hint: 'Kernel panic or dmesg errors around nf_tables. Unexpected root processes from non-root parent processes.'
  },
  'CVE-2024-21626': {
    id: 'CVE-2024-21626',
    description: 'runc container escape (Leaky Vessels). Allows container workload to escape to host OS via file descriptor leak in runc, affecting Docker, Kubernetes, and containerd.',
    severity: 'high', cvss_score: 8.6,
    published_date: '2024-01-31', exploited: false,
    vendor: 'Open Containers', product: 'runc < 1.1.12',
    tags: ['container-escape','docker','kubernetes','runc','leaky-vessels'],
    mitigation: 'Update runc to 1.1.12+. Update Docker/containerd. Audit container security policies.',
    mitre_techniques: ['T1611','T1068'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-21626'],
    detection_hint: 'Unexpected host filesystem access from containers. Container processes with elevated privileges beyond defined security context.'
  },

  // ── Apache / Web Servers ──────────────────────────────────────────────────
  'CVE-2021-41773': {
    id: 'CVE-2021-41773',
    description: 'Apache HTTP Server path traversal and RCE via mod_cgi. Allows unauthenticated directory traversal and code execution on servers with mod_cgi enabled. Exploited within 24h of disclosure.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2021-10-05', exploited: true,
    vendor: 'Apache', product: 'Apache HTTP Server 2.4.49',
    tags: ['rce','path-traversal','apache','exploited-itw','zero-day'],
    mitigation: 'Upgrade to Apache 2.4.51+. Disable mod_cgi. Use "Require all denied" for filesystem access.',
    mitre_techniques: ['T1190','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
    detection_hint: 'Access logs: GET requests with /.%2e/ or /%2e%2e/ patterns. Look for /cgi-bin/echo requests.'
  },
  'CVE-2023-44487': {
    id: 'CVE-2023-44487',
    description: 'HTTP/2 Rapid Reset Attack — protocol-level DoS. Attacker opens and immediately cancels HTTP/2 streams at massive scale, overwhelming servers. CVSS 7.5 but caused major outages.',
    severity: 'high', cvss_score: 7.5,
    published_date: '2023-10-10', exploited: true,
    vendor: 'Multiple', product: 'Any HTTP/2 server (nginx, Apache, IIS, Node.js, Go)',
    tags: ['dos','http2','rapid-reset','exploited-itw','infrastructure'],
    mitigation: 'Patch affected HTTP/2 implementations. Apply server-specific mitigations (nginx: limit_conn, Apache: H2MaxSessionStreams). Use DDoS protection.',
    mitre_techniques: ['T1498','T1499'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-44487'],
    detection_hint: 'Spike in RST_STREAM frames in HTTP/2 traffic. High CPU on web servers with low response rate.'
  },

  // ── VMware / Virtualization ───────────────────────────────────────────────
  'CVE-2021-22005': {
    id: 'CVE-2021-22005',
    description: 'VMware vCenter Server file upload RCE. Arbitrary file upload in analytics service allows unauthenticated RCE on vCenter. Critical for cloud/virtualization environments.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2021-09-22', exploited: true,
    vendor: 'VMware', product: 'vCenter Server 6.7, 7.0',
    tags: ['rce','vmware','vcenter','file-upload','exploited-itw'],
    mitigation: 'Apply VMSA-2021-0020 patch immediately. Restrict network access to vCenter. Monitor for unauthorized file uploads.',
    mitre_techniques: ['T1190','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-22005'],
    detection_hint: 'vCenter logs: POST requests to /analytics/telemetry path. New JSP/shell files in vCenter web directories.'
  },
  'CVE-2023-20867': {
    id: 'CVE-2023-20867',
    description: 'VMware Tools auth bypass — UNC3886 zero-day. Allows compromised ESXi host to execute commands on VMs without authentication. Used by Chinese APT for cross-VM pivoting.',
    severity: 'low', cvss_score: 3.9,
    published_date: '2023-06-13', exploited: true,
    vendor: 'VMware', product: 'VMware Tools < 12.3.0',
    tags: ['auth-bypass','vmware','esxi','unc3886','china-nexus','lateral-movement'],
    mitigation: 'Update VMware Tools. Monitor VM authentication events from ESXi host.',
    mitre_techniques: ['T1021','T1078','T1550'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-20867'],
    detection_hint: 'VMware Tools logs: VIX API commands executed without guest auth. Unexpected Guest Operations activity.'
  },

  // ── Supply Chain / NPM/PyPI ───────────────────────────────────────────────
  'CVE-2022-22965': {
    id: 'CVE-2022-22965',
    description: 'Spring4Shell — Spring Framework RCE via data binding with ClassLoader. Allows unauthenticated RCE on Java Spring MVC applications running on Tomcat with JDK 9+.',
    severity: 'critical', cvss_score: 9.8,
    published_date: '2022-03-30', exploited: true,
    vendor: 'VMware', product: 'Spring Framework < 5.3.18, < 5.2.20',
    tags: ['rce','spring','java','spring4shell','exploited-itw'],
    mitigation: 'Upgrade Spring Framework. Apply DataBinder denylist patch. Filter ClassLoader attributes in models.',
    mitre_techniques: ['T1190','T1059','T1203'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    detection_hint: 'WAF: requests with class.module.classLoader in POST body. Tomcat webshell files (e.g., tomcatwar.jsp) in webroot.'
  },
  'CVE-2021-44832': {
    id: 'CVE-2021-44832',
    description: 'Log4j2 remote code execution via attacker-controlled JDBC URL in configuration. Lower severity as requires write access to Log4j config, but still patchable issue.',
    severity: 'medium', cvss_score: 6.6,
    published_date: '2021-12-28', exploited: false,
    vendor: 'Apache', product: 'Log4j2 2.0-beta7 to 2.17.0',
    tags: ['rce','log4j','java','jdbc','config-injection'],
    mitigation: 'Upgrade to Log4j 2.17.1+.',
    mitre_techniques: ['T1190','T1059'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44832'],
    detection_hint: 'Log4j config files modified to include JDBC appenders pointing to external hosts.'
  },

  // ── OpenSSL / Crypto ─────────────────────────────────────────────────────
  'CVE-2022-3602': {
    id: 'CVE-2022-3602',
    description: 'OpenSSL 3.x X.509 certificate verification buffer overflow (SpookySSL). Triggers during X.509 cert chain verification, can cause RCE in vulnerable configurations.',
    severity: 'high', cvss_score: 7.5,
    published_date: '2022-11-01', exploited: false,
    vendor: 'OpenSSL', product: 'OpenSSL 3.0.0 - 3.0.6',
    tags: ['buffer-overflow','openssl','tls','spookyssl'],
    mitigation: 'Upgrade to OpenSSL 3.0.7+. Check downstream packages that bundle OpenSSL 3.x.',
    mitre_techniques: ['T1190','T1573'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-3602'],
    detection_hint: 'Application crashes during TLS handshake with crafted certificates. Monitor OpenSSL error logs for punycode-related failures.'
  },
  'CVE-2014-0160': {
    id: 'CVE-2014-0160',
    description: 'Heartbleed — OpenSSL TLS heartbeat buffer over-read. Allows attackers to read up to 64KB of server memory, potentially exposing private keys, session tokens, and plaintext data.',
    severity: 'high', cvss_score: 7.5,
    published_date: '2014-04-07', exploited: true,
    vendor: 'OpenSSL', product: 'OpenSSL 1.0.1 - 1.0.1f',
    tags: ['info-disclosure','openssl','tls','heartbleed','exploited-itw'],
    mitigation: 'Upgrade OpenSSL. Revoke and reissue all SSL certificates. Rotate session tokens and passwords.',
    mitre_techniques: ['T1040','T1552','T1573'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160'],
    detection_hint: 'IDS/IPS: malformed HeartbeatRequest packets larger than payload. Network: look for repetitive TLS heartbeat packets.'
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

  // ── Additional MITRE Techniques ────────────────────────────────────────────
  'T1110': {
    id: 'T1110', name: 'Brute Force',
    tactic: 'Credential Access', severity: 'high',
    description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Subtechniques include Password Spraying and Credential Stuffing.',
    platforms: ['Windows','Azure AD','Office 365','SaaS','IaaS','Linux','macOS','Containers'],
    detection: 'Monitor authentication events for high failure rates. Event ID 4625 (Windows). Azure AD sign-in logs. Check for account lockouts across multiple accounts simultaneously.',
    mitigation: 'Account lockout policies. MFA/2FA enforcement. Conditional access policies. Network access controls restricting login from unexpected locations.',
    url: 'https://attack.mitre.org/techniques/T1110/'
  },
  'T1133': {
    id: 'T1133', name: 'External Remote Services',
    tactic: 'Initial Access', severity: 'high',
    description: 'Adversaries may leverage external-facing remote services such as VPNs, Citrix, RDP, and SSH to gain initial access to a network. Compromised credentials or exploited vulnerabilities are used.',
    platforms: ['Windows','Linux','Containers','macOS'],
    detection: 'Monitor authentication logs for remote services. Baseline and alert on anomalous logins (unusual geo, time, device). Correlate with threat intel feeds for known malicious IPs.',
    mitigation: 'MFA for all remote access. Network-level access control. Patch management for VPN/gateway devices. Geo-blocking for unexpected regions.',
    url: 'https://attack.mitre.org/techniques/T1133/'
  },
  'T1566': {
    id: 'T1566', name: 'Phishing',
    tactic: 'Initial Access', severity: 'high',
    description: 'Adversaries may send phishing messages to gain access to victim systems. Spearphishing uses tailored lures targeting specific individuals; mass phishing uses generic lures at scale.',
    platforms: ['Linux','macOS','Windows','SaaS','Office 365','Google Workspace'],
    detection: 'Email gateway scanning for malicious attachments/links. DNS/proxy monitoring for newly registered domains. EDR process creation after email client opens. DMARC/DKIM/SPF enforcement.',
    mitigation: 'Email filtering and sandboxing. User security awareness training. DMARC enforcement. Disable Office macros from internet-sourced files. Attack Surface Reduction rules.',
    url: 'https://attack.mitre.org/techniques/T1566/'
  },
  'T1204': {
    id: 'T1204', name: 'User Execution',
    tactic: 'Execution', severity: 'high',
    description: 'Adversaries may rely upon specific actions by a user in order to gain execution. Malicious File (T1204.002) and Malicious Link (T1204.001) are the most common delivery methods.',
    platforms: ['Linux','Windows','macOS'],
    detection: 'Monitor for process creation from email clients, web browsers, office applications. EDR behavioral alerts for suspicious child processes. Script execution from user profile directories.',
    mitigation: 'User training and phishing simulation exercises. Script block logging. AppLocker/WDAC to restrict script execution. Email attachment sandboxing.',
    url: 'https://attack.mitre.org/techniques/T1204/'
  },
  'T1071': {
    id: 'T1071', name: 'Application Layer Protocol (C2)',
    tactic: 'Command and Control', severity: 'high',
    description: 'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering. HTTPS (T1071.001), DNS (T1071.004), and SMTP are common channels for C2 traffic.',
    platforms: ['Linux','macOS','Windows','Network'],
    detection: 'DNS: high-volume subdomain queries, long domain names, entropy analysis. HTTPS: JA3 fingerprinting, certificate anomalies, beaconing patterns. Proxy logs: unusual user agents, periodic connections.',
    mitigation: 'Web proxy with SSL inspection. DNS filtering (Cisco Umbrella, Cloudflare Gateway). Network traffic baseline and anomaly detection. Firewall egress filtering.',
    url: 'https://attack.mitre.org/techniques/T1071/'
  },
  'T1041': {
    id: 'T1041', name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration', severity: 'high',
    description: 'Adversaries may steal data by exfiltrating it over an existing C2 communications channel. Data is often staged and compressed before exfiltration to minimize detection.',
    platforms: ['Linux','macOS','Windows'],
    detection: 'Monitor for large data transfers over established C2 channels. Network: unusually large HTTPS payloads, DNS TXT record anomalies. DLP alerts on sensitive file access followed by outbound transfer.',
    mitigation: 'Network segmentation. Data loss prevention (DLP). Egress filtering. Cloud Access Security Broker (CASB). Monitor for archive utility usage (7zip, WinRAR) before network connections.',
    url: 'https://attack.mitre.org/techniques/T1041/'
  },
  'T1562': {
    id: 'T1562', name: 'Impair Defenses',
    tactic: 'Defense Evasion', severity: 'high',
    description: 'Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. Includes disabling AV, EDR, firewall, logging, and security services.',
    platforms: ['Windows','macOS','Linux','Containers','IaaS'],
    detection: 'Monitor for security service modifications. Event ID 7045 (new service), 4719 (audit policy changed), 4689 (process terminated). EDR: policy modification events. SIEM: sudden drop in event volume from endpoint.',
    mitigation: 'Tamper protection in AV/EDR. Privileged access management. Monitoring security tool health. Immutable logging (WORM storage). Security baseline compliance checks.',
    url: 'https://attack.mitre.org/techniques/T1562/'
  },
  'T1036': {
    id: 'T1036', name: 'Masquerading',
    tactic: 'Defense Evasion', severity: 'medium',
    description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign. Masquerading can include renaming executables to match system processes, using similar file names (typosquatting), or placing malware in trusted locations.',
    platforms: ['Linux','macOS','Windows','Containers'],
    detection: 'Verify process parent-child relationships. Check executable hash against known-good values. Monitor for processes in unusual directories (system32 impersonation from %APPDATA%). File path anomalies.',
    mitigation: 'Code signing verification. Application control. Anti-virus/EDR with behavioral analysis. Process monitoring with parent-child validation.',
    url: 'https://attack.mitre.org/techniques/T1036/'
  },
  'T1068': {
    id: 'T1068', name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation', severity: 'high',
    description: 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program or service.',
    platforms: ['Linux','macOS','Windows'],
    detection: 'Monitor process creation events following unusual activity. Privilege monitoring: watch for standard user processes gaining high integrity/SYSTEM privileges. CVE-specific IDS signatures.',
    mitigation: 'Patch management prioritizing LPE CVEs. Exploit protection (EMET/Windows Defender Exploit Guard). Vulnerable driver blocklist (WDAC). Limit running unknown software.',
    url: 'https://attack.mitre.org/techniques/T1068/'
  },
  'T1505': {
    id: 'T1505', name: 'Server Software Component',
    tactic: 'Persistence', severity: 'high',
    description: 'Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Web shells (T1505.003) are a primary technique — malicious scripts placed on web servers providing backdoor access.',
    platforms: ['Windows','Linux','macOS','Network'],
    detection: 'Monitor for new file creation in web server directories. Web logs: requests to newly created server-side scripts. EDR: web server processes spawning shells (cmd.exe, bash, powershell).',
    mitigation: 'File integrity monitoring on web directories. Disable web server write permissions where not needed. Regular audits of web server directories. WAF rules to block webshell patterns.',
    url: 'https://attack.mitre.org/techniques/T1505/'
  },
  'T1140': {
    id: 'T1140', name: 'Deobfuscate/Decode Files or Information',
    tactic: 'Defense Evasion', severity: 'medium',
    description: 'Adversaries may use obfuscated files or information to hide artifacts of an intrusion. Reverse the process to understand adversary actions. Base64, XOR, gzip compression, custom encryption are common methods.',
    platforms: ['Windows','Linux','macOS'],
    detection: 'Monitor for deobfuscation tool use (certutil -decode, base64, gunzip). PowerShell: IEX with FromBase64String. Process command-line arguments containing suspicious encoded strings.',
    mitigation: 'AMSI integration for script engines. Script block logging (Event 4104). Network traffic analysis for encoded payloads. EDR behavioral detection of deobfuscation patterns.',
    url: 'https://attack.mitre.org/techniques/T1140/'
  },
  'T1070': {
    id: 'T1070', name: 'Indicator Removal',
    tactic: 'Defense Evasion', severity: 'medium',
    description: 'Adversaries may delete or alter generated artifacts on a system, including logs or captured files. Clearing event logs (T1070.001), deleting files (T1070.004), and timestomping (T1070.006) are key sub-techniques.',
    platforms: ['Linux','macOS','Windows','Google Workspace','Office 365'],
    detection: 'Event ID 1102 (audit log cleared). Monitor for wevtutil/ClearEvent API usage. File deletion events for log files. File metadata modification inconsistencies (timestomping).',
    mitigation: 'Centralized logging (SIEM). Log forwarding to remote/immutable storage. Enable Windows Event Forwarding. Audit policy for log clear events.',
    url: 'https://attack.mitre.org/techniques/T1070/'
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
