/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Comprehensive Cybersecurity Playbooks
 *  All major incident response & threat hunting playbooks
 * ══════════════════════════════════════════════════════════
 */
window.PLAYBOOKS_DB = [
  /* ─────────────── INCIDENT RESPONSE ─────────────── */
  {
    id:'pb-001', category:'Incident Response', severity:'critical',
    name:'Ransomware Incident Response',
    description:'Complete end-to-end playbook for ransomware attack containment, eradication and recovery with MITRE mapping.',
    steps:14, ttps:8, trigger:'Ransomware IOC or file encryption alerts',
    tags:['ransomware','containment','recovery','T1486','T1490'],
    icon:'fa-lock', color:'#ef4444',
    steps_detail:[
      'Immediately isolate infected endpoints from network',
      'Identify patient zero and initial infection vector',
      'Block known ransomware C2 IPs/domains at firewall',
      'Preserve forensic evidence (memory dumps, logs)',
      'Identify scope of encryption and lateral movement',
      'Disable compromised accounts and reset credentials',
      'Restore from clean backups after validation',
      'Deploy EDR signatures for ransomware family',
      'Conduct root cause analysis',
      'Notify stakeholders and legal/compliance',
      'File incident report with CISA if applicable',
      'Implement lessons learned',
      'Patch exploited vulnerability',
      'Post-incident monitoring for 30 days'
    ],
    mitre_techniques:['T1486','T1490','T1489','T1562','T1078','T1021','T1485','T1491']
  },
  {
    id:'pb-002', category:'Incident Response', severity:'critical',
    name:'Data Breach Investigation',
    description:'Structured investigation for data exfiltration incidents including evidence collection, scope determination and notification.',
    steps:12, ttps:6, trigger:'DLP alert, unusual egress traffic, dark web exposure',
    tags:['data-breach','exfiltration','T1041','T1048'],
    icon:'fa-database', color:'#ef4444',
    steps_detail:[
      'Activate incident response team and war room',
      'Identify data types potentially exposed',
      'Review DLP and CASB logs for exfiltration evidence',
      'Analyze egress traffic patterns and volumes',
      'Identify compromised accounts or systems',
      'Collect and preserve forensic artifacts',
      'Scope notification requirements (GDPR, HIPAA, etc.)',
      'Engage legal counsel and privacy team',
      'Notify affected parties within regulatory timeframes',
      'Implement technical remediation measures',
      'Deploy additional monitoring controls',
      'Post-breach security assessment'
    ],
    mitre_techniques:['T1041','T1048','T1071','T1567','T1530','T1537']
  },
  {
    id:'pb-003', category:'Incident Response', severity:'high',
    name:'Phishing Campaign Analysis',
    description:'Multi-stage analysis of phishing campaigns including header analysis, URL inspection, payload detonation, and user impact assessment.',
    steps:10, ttps:5, trigger:'Reported phishing email, URL click alert',
    tags:['phishing','credential-harvest','T1566','T1598'],
    icon:'fa-fish', color:'#f97316',
    steps_detail:[
      'Quarantine all instances of phishing email',
      'Extract and analyze email headers for origin',
      'Decode and analyze URLs (sandboxed environment)',
      'Detonate attachments in isolated sandbox',
      'Identify impersonated brand/entity',
      'Block sender, domain, URLs at email gateway',
      'Identify all recipients and clickers',
      'Reset credentials for users who submitted forms',
      'Check for downstream malware or persistence',
      'Report to anti-phishing organizations'
    ],
    mitre_techniques:['T1566','T1598','T1056','T1539','T1204']
  },
  {
    id:'pb-004', category:'Incident Response', severity:'critical',
    name:'Business Email Compromise (BEC)',
    description:'Response to BEC attacks including account takeover detection, financial fraud prevention, and remediation.',
    steps:11, ttps:7, trigger:'Suspicious email forwarding rules, wire transfer requests',
    tags:['bec','fraud','T1114','T1534'],
    icon:'fa-envelope-open-text', color:'#ef4444',
    steps_detail:[
      'Identify compromised email account(s)',
      'Review email forwarding rules and delegates',
      'Check OAuth application permissions',
      'Analyze login history for anomalous access',
      'Contact financial institutions to halt transfers',
      'Revoke all active sessions',
      'Enable MFA on compromised accounts',
      'Remove malicious forwarding rules',
      'Review all sent emails during compromise period',
      'Notify affected business partners',
      'File FBI IC3 complaint if financial loss'
    ],
    mitre_techniques:['T1114','T1534','T1564','T1098','T1078','T1548','T1136']
  },
  {
    id:'pb-005', category:'Incident Response', severity:'high',
    name:'Insider Threat Investigation',
    description:'Discreet investigation of potential insider threats with legal-compliant evidence collection and monitoring.',
    steps:9, ttps:4, trigger:'Anomalous data access, privilege abuse, DLP alert',
    tags:['insider-threat','data-theft','monitoring'],
    icon:'fa-user-secret', color:'#f97316',
    steps_detail:[
      'Brief legal and HR before proceeding',
      'Enable enhanced logging for subject account',
      'Review data access and exfiltration history',
      'Analyze USB and cloud storage activity',
      'Correlate physical access with logical access',
      'Preserve evidence per legal hold procedures',
      'Conduct privileged access review',
      'Involve HR for employment action',
      'Implement data loss prevention improvements'
    ],
    mitre_techniques:['T1078','T1003','T1113','T1119']
  },
  {
    id:'pb-006', category:'Incident Response', severity:'critical',
    name:'Supply Chain Compromise Response',
    description:'Response to software supply chain attacks including vendor assessment, scope determination, and clean-up procedures.',
    steps:13, ttps:9, trigger:'Vendor alert, compromised software update, SolarWinds-style indicator',
    tags:['supply-chain','T1195','T1553','software-update'],
    icon:'fa-link', color:'#ef4444',
    steps_detail:[
      'Identify all installations of affected software',
      'Immediately isolate systems with affected software',
      'Obtain indicators from vendor/security researchers',
      'Search for backdoor indicators across environment',
      'Analyze outbound connections from affected systems',
      'Identify lateral movement from compromised nodes',
      'Revoke and rotate all credentials on affected systems',
      'Deploy forensic agents to affected endpoints',
      'Coordinate with software vendor on remediation',
      'Rebuild affected systems from clean images',
      'Implement software integrity monitoring',
      'Review and strengthen vendor security requirements',
      'File report with CISA/CERT'
    ],
    mitre_techniques:['T1195','T1553','T1574','T1078','T1021','T1041','T1059','T1547','T1036']
  },

  /* ─────────────── THREAT HUNTING ─────────────── */
  {
    id:'pb-007', category:'Threat Hunting', severity:'high',
    name:'Lateral Movement via SMB Hunt',
    description:'Proactive hunting for lateral movement using SMB protocol anomalies, pass-the-hash, and admin share abuse.',
    steps:8, ttps:5, trigger:'Scheduled hunt or elevated risk posture',
    tags:['lateral-movement','SMB','T1021','T1550'],
    icon:'fa-project-diagram', color:'#8b5cf6',
    steps_detail:[
      'Baseline normal SMB traffic patterns',
      'Hunt for SMB connections to admin shares (C$, ADMIN$)',
      'Identify accounts with unusual remote logon patterns',
      'Search for NTLM authentication anomalies',
      'Hunt for pass-the-hash indicators',
      'Correlate with abnormal time-of-day access',
      'Investigate service creation via SC on remote hosts',
      'Document and report findings'
    ],
    mitre_techniques:['T1021','T1550','T1078','T1075','T1076']
  },
  {
    id:'pb-008', category:'Threat Hunting', severity:'high',
    name:'Unusual PowerShell Execution Hunt',
    description:'Hunt for malicious PowerShell usage including obfuscated commands, encoded payloads, and LOLBins abuse.',
    steps:9, ttps:6, trigger:'Scheduled hunt, IDS/EDR alert',
    tags:['powershell','T1059','T1027','lolbins'],
    icon:'fa-terminal', color:'#8b5cf6',
    steps_detail:[
      'Enable PowerShell ScriptBlock and Module logging',
      'Hunt for Base64-encoded PowerShell commands',
      'Search for PowerShell downloading from internet',
      'Identify PowerShell with -ExecutionPolicy Bypass',
      'Hunt for AMSI bypass techniques',
      'Search for PowerShell spawning from Office apps',
      'Identify constrained language mode bypasses',
      'Hunt for PowerShell remoting anomalies',
      'Correlate with network IOCs'
    ],
    mitre_techniques:['T1059','T1027','T1140','T1562','T1036','T1197']
  },
  {
    id:'pb-009', category:'Threat Hunting', severity:'medium',
    name:'Persistence Mechanism Hunt',
    description:'Hunt for attacker persistence including registry run keys, scheduled tasks, WMI subscriptions, and startup folders.',
    steps:10, ttps:7, trigger:'Post-incident hunt or scheduled quarterly review',
    tags:['persistence','T1547','T1053','T1546'],
    icon:'fa-fingerprint', color:'#8b5cf6',
    steps_detail:[
      'Enumerate all Run/RunOnce registry keys',
      'Review scheduled tasks for anomalies',
      'Hunt for WMI event subscriptions',
      'Check startup folder contents',
      'Review services for unsigned or suspicious binaries',
      'Hunt for DLL hijacking opportunities',
      'Check for browser extension anomalies',
      'Review COM object hijacking potential',
      'Analyze boot sector and MBR integrity',
      'Document baseline and deviations'
    ],
    mitre_techniques:['T1547','T1053','T1546','T1543','T1574','T1176']
  },
  {
    id:'pb-010', category:'Threat Hunting', severity:'high',
    name:'Credential Access Hunt',
    description:'Hunt for credential theft attempts including LSASS dumping, SAM database access, and Kerberoasting.',
    steps:8, ttps:6, trigger:'Scheduled hunt or authentication anomaly',
    tags:['credential-access','T1003','T1558','kerberoasting'],
    icon:'fa-key', color:'#8b5cf6',
    steps_detail:[
      'Hunt for LSASS memory access by non-OS processes',
      'Search for Mimikatz artifacts and signatures',
      'Identify Kerberoasting via SPN enumeration',
      'Hunt for AS-REP roasting indicators',
      'Search for DCSync anomalies in domain controller logs',
      'Review SAM/NTDS.dit access patterns',
      'Hunt for credential dumping via registry',
      'Correlate with brute force authentication logs'
    ],
    mitre_techniques:['T1003','T1558','T1110','T1555','T1212','T1187']
  },

  /* ─────────────── MALWARE ANALYSIS ─────────────── */
  {
    id:'pb-011', category:'Malware Analysis', severity:'critical',
    name:'Advanced Persistent Threat (APT) Analysis',
    description:'Comprehensive APT investigation including attribution, TTP mapping, and infrastructure analysis.',
    steps:12, ttps:10, trigger:'APT IOC match, sophisticated intrusion indicators',
    tags:['APT','attribution','T1027','nation-state'],
    icon:'fa-chess', color:'#ef4444',
    steps_detail:[
      'Establish secure, air-gapped analysis environment',
      'Collect all available IOCs and artifacts',
      'Perform static malware analysis',
      'Perform dynamic analysis in sandbox',
      'Extract network indicators from malware',
      'Analyze C2 infrastructure and registration',
      'Map TTPs to MITRE ATT&CK framework',
      'Compare with known threat actor TTPs',
      'Identify campaign overlaps and victimology',
      'Develop defensive countermeasures',
      'Share IOCs with information sharing communities',
      'Brief executive team on threat landscape'
    ],
    mitre_techniques:['T1027','T1055','T1071','T1082','T1083','T1105','T1112','T1140','T1204','T1219']
  },
  {
    id:'pb-012', category:'Malware Analysis', severity:'high',
    name:'Trojan/RAT Analysis & Response',
    description:'Analysis and containment of Remote Access Trojans with C2 infrastructure takedown coordination.',
    steps:10, ttps:7, trigger:'Suspicious process, outbound C2 connection',
    tags:['RAT','trojan','C2','T1219'],
    icon:'fa-bug', color:'#f97316',
    steps_detail:[
      'Isolate infected system from network',
      'Capture memory dump before shutdown',
      'Extract malware sample for analysis',
      'Identify C2 servers and protocols used',
      'Analyze persistence mechanisms',
      'Review all commands executed via RAT',
      'Identify all data accessed/exfiltrated',
      'Block C2 infrastructure network-wide',
      'Rebuild system from clean image',
      'Submit sample to threat intelligence platforms'
    ],
    mitre_techniques:['T1219','T1071','T1105','T1547','T1082','T1113','T1041']
  },
  {
    id:'pb-013', category:'Malware Analysis', severity:'high',
    name:'Rootkit Detection & Removal',
    description:'Detection and eradication of kernel and user-mode rootkits with validation procedures.',
    steps:9, ttps:5, trigger:'EDR detection, anomalous system behavior, AV alert',
    tags:['rootkit','T1014','kernel','stealth'],
    icon:'fa-ghost', color:'#f97316',
    steps_detail:[
      'Boot from external trusted media for analysis',
      'Scan with offline rootkit detection tools',
      'Compare file system with known-good baseline',
      'Check for hidden processes and network connections',
      'Analyze kernel modules and drivers',
      'Identify bootkit components in MBR/VBR',
      'Extract rootkit samples for reverse engineering',
      'Reimage affected systems — no cleaning attempt',
      'Restore data from pre-infection backups'
    ],
    mitre_techniques:['T1014','T1542','T1553','T1070','T1036']
  },

  /* ─────────────── VULNERABILITY MANAGEMENT ─────────────── */
  {
    id:'pb-014', category:'Vulnerability Management', severity:'critical',
    name:'Critical CVE Emergency Response',
    description:'Rapid response to critical zero-day or CISA KEV vulnerabilities with emergency patch deployment.',
    steps:10, ttps:4, trigger:'CVSS 9.0+ CVE, CISA KEV listing, vendor advisory',
    tags:['CVE','zero-day','patch','T1190'],
    icon:'fa-radiation', color:'#ef4444',
    steps_detail:[
      'Identify all affected systems in asset inventory',
      'Assess exploitability and exposure level',
      'Deploy compensating controls immediately',
      'Test patches in non-production environment',
      'Emergency change management approval',
      'Deploy patches in priority order (internet-facing first)',
      'Validate patch deployment and system integrity',
      'Search for exploitation indicators (compromise assessment)',
      'Update vulnerability scanning signatures',
      'Document patch status for all systems'
    ],
    mitre_techniques:['T1190','T1211','T1210','T1068']
  },
  {
    id:'pb-015', category:'Vulnerability Management', severity:'high',
    name:'API Key / Secret Exposure Response',
    description:'Response to exposed API keys, secrets or credentials discovered in code repositories or dark web.',
    steps:8, ttps:3, trigger:'Secret scanning alert, dark web exposure, SAST finding',
    tags:['secret-exposure','API-key','credential','T1552'],
    icon:'fa-key', color:'#f97316',
    steps_detail:[
      'Immediately revoke exposed credentials/keys',
      'Issue new credentials with restricted scope',
      'Audit all API calls made with exposed key',
      'Check for unauthorized resource access',
      'Remove secrets from all repository history',
      'Implement secret scanning pre-commit hooks',
      'Review and harden secrets management process',
      'Notify affected service providers'
    ],
    mitre_techniques:['T1552','T1078','T1530','T1606']
  },
  {
    id:'pb-016', category:'Vulnerability Management', severity:'high',
    name:'SQL Injection Attack Response',
    description:'Response to SQL injection exploitation including database compromise assessment and remediation.',
    steps:9, ttps:5, trigger:'WAF alert, abnormal DB queries, application log anomaly',
    tags:['SQLi','web-application','T1190','database'],
    icon:'fa-database', color:'#f97316',
    steps_detail:[
      'Block attacker source IPs at WAF/firewall',
      'Enable enhanced database query logging',
      'Analyze database logs for exfiltrated data',
      'Identify all vulnerable parameters',
      'Assess database user privilege abuse',
      'Check for outbound data exfiltration',
      'Deploy WAF rules to block SQLi patterns',
      'Remediate vulnerable code with parameterized queries',
      'Conduct full penetration test of application'
    ],
    mitre_techniques:['T1190','T1212','T1005','T1041','T1059']
  },

  /* ─────────────── NETWORK SECURITY ─────────────── */
  {
    id:'pb-017', category:'Network Security', severity:'critical',
    name:'DDoS Attack Response',
    description:'Coordinated response to DDoS attacks including traffic analysis, upstream mitigation, and service restoration.',
    steps:9, ttps:3, trigger:'Traffic spike, service degradation, ISP alert',
    tags:['DDoS','availability','T1498','T1499'],
    icon:'fa-network-wired', color:'#ef4444',
    steps_detail:[
      'Declare incident and activate response team',
      'Identify attack type (volumetric, protocol, application)',
      'Enable upstream DDoS mitigation/scrubbing',
      'Implement rate limiting and traffic filtering',
      'Activate CDN and anycast routing if available',
      'Coordinate with ISP/upstream providers',
      'Preserve attack traffic samples for analysis',
      'Monitor for attack vector changes',
      'Post-attack capacity and resilience review'
    ],
    mitre_techniques:['T1498','T1499','T1499.003','T1498.001']
  },
  {
    id:'pb-018', category:'Network Security', severity:'high',
    name:'C2 Infrastructure Detection & Response',
    description:'Detection and disruption of Command & Control infrastructure with IOC extraction and threat actor attribution.',
    steps:10, ttps:6, trigger:'DNS anomaly, Beacon detection, NGFW C2 alert',
    tags:['C2','command-control','T1071','T1095'],
    icon:'fa-broadcast-tower', color:'#f97316',
    steps_detail:[
      'Identify infected endpoints communicating with C2',
      'Extract C2 domains, IPs, and protocols',
      'Analyze beacon intervals and jitter patterns',
      'Block C2 infrastructure at DNS/firewall/proxy',
      'Isolate infected endpoints for forensic analysis',
      'Identify all commands issued via C2',
      'Search for lateral movement from infected nodes',
      'Coordinate takedown with hosting providers',
      'Submit IOCs to threat intelligence platforms',
      'Rebuild affected systems'
    ],
    mitre_techniques:['T1071','T1095','T1572','T1008','T1090','T1219']
  },
  {
    id:'pb-019', category:'Network Security', severity:'medium',
    name:'DNS Exfiltration Response',
    description:'Detection and response to DNS tunneling and data exfiltration over DNS protocol.',
    steps:7, ttps:4, trigger:'High DNS query volume, unusual TXT record queries',
    tags:['DNS','exfiltration','T1048','tunneling'],
    icon:'fa-satellite-dish', color:'#f59e0b',
    steps_detail:[
      'Identify sources of anomalous DNS query volumes',
      'Analyze query patterns for tunneling signatures',
      'Block suspicious DNS domains and resolvers',
      'Implement DNS query logging and monitoring',
      'Identify data types being exfiltrated',
      'Remediate infected systems',
      'Implement DNS security controls (RPZ, DNS firewall)'
    ],
    mitre_techniques:['T1048','T1071','T1132','T1041']
  },

  /* ─────────────── CLOUD SECURITY ─────────────── */
  {
    id:'pb-020', category:'Cloud Security', severity:'critical',
    name:'Cloud Account Compromise Response',
    description:'Response to AWS/Azure/GCP account compromise including resource inventory, access revocation, and cleanup.',
    steps:11, ttps:6, trigger:'Unusual API calls, resource creation, billing anomaly',
    tags:['cloud','IAM','T1078','AWS','Azure'],
    icon:'fa-cloud', color:'#ef4444',
    steps_detail:[
      'Enable enhanced CloudTrail/Activity log retention',
      'Identify compromised IAM users, roles, or service accounts',
      'Revoke all credentials and access keys immediately',
      'Inventory all resources created by compromised identity',
      'Identify data accessed and exfiltration paths',
      'Check for crypto mining and ransomware deployment',
      'Review and revoke suspicious OAuth applications',
      'Remove backdoor IAM users/roles created by attacker',
      'Reset root account credentials and enable MFA',
      'Terminate unauthorized resources (EC2, Lambda, etc.)',
      'Enable GuardDuty/Defender for Cloud with all detectors'
    ],
    mitre_techniques:['T1078','T1098','T1530','T1537','T1535','T1619']
  },
  {
    id:'pb-021', category:'Cloud Security', severity:'high',
    name:'S3/Blob Storage Exposure Response',
    description:'Response to publicly exposed cloud storage buckets including data inventory and access restriction.',
    steps:8, ttps:4, trigger:'Misconfiguration scan, bug bounty report, dark web exposure',
    tags:['S3','cloud-storage','misconfiguration','T1530'],
    icon:'fa-folder-open', color:'#f97316',
    steps_detail:[
      'Immediately restrict public access on exposed buckets',
      'Enable access logging on affected storage',
      'Inventory all files in exposed storage',
      'Check access logs for unauthorized downloads',
      'Classify exposed data types and sensitivity',
      'Notify affected parties if PII exposed',
      'Implement preventive guardrails (SCPs, policies)',
      'Deploy automated misconfiguration detection'
    ],
    mitre_techniques:['T1530','T1619','T1040','T1078']
  },
  {
    id:'pb-022', category:'Cloud Security', severity:'high',
    name:'Container Escape & K8s Compromise',
    description:'Response to Kubernetes/container security incidents including namespace enumeration and cluster hardening.',
    steps:10, ttps:6, trigger:'Anomalous container activity, privileged pod creation',
    tags:['kubernetes','container','T1610','T1613'],
    icon:'fa-box', color:'#f97316',
    steps_detail:[
      'Identify compromised pods and containers',
      'Isolate affected namespaces',
      'Check for privileged container creation',
      'Review RBAC for over-privileged service accounts',
      'Hunt for cryptominer or malware in containers',
      'Check for escape attempts via host path mounts',
      'Review API server audit logs',
      'Rotate all service account tokens',
      'Patch and harden container configurations',
      'Enable runtime security (Falco/Sysdig)'
    ],
    mitre_techniques:['T1610','T1613','T1078','T1068','T1611','T1525']
  },

  /* ─────────────── ENDPOINT SECURITY ─────────────── */
  {
    id:'pb-023', category:'Endpoint Security', severity:'high',
    name:'Process Injection Detection & Response',
    description:'Detection and containment of process injection attacks including DLL injection, process hollowing, and shellcode injection.',
    steps:8, ttps:7, trigger:'EDR process injection alert, anomalous memory access',
    tags:['process-injection','T1055','shellcode','EDR'],
    icon:'fa-microchip', color:'#f97316',
    steps_detail:[
      'Identify the injecting and target processes',
      'Capture memory dump of affected processes',
      'Extract injected shellcode or DLL',
      'Analyze injection technique used',
      'Identify persistence mechanisms established',
      'Isolate endpoint from network',
      'Scan for additional compromised processes',
      'Reimage endpoint if rootkit detected'
    ],
    mitre_techniques:['T1055','T1055.001','T1055.002','T1055.012','T1134','T1574']
  },
  {
    id:'pb-024', category:'Endpoint Security', severity:'medium',
    name:'Living Off The Land (LOLBins) Response',
    description:'Detection and response to abuse of legitimate system tools for malicious purposes.',
    steps:7, ttps:8, trigger:'Certutil download, regsvr32 abuse, mshta execution',
    tags:['LOLBins','T1218','T1197','wmic'],
    icon:'fa-cogs', color:'#f59e0b',
    steps_detail:[
      'Identify which LOLBin was abused and how',
      'Extract command line arguments and context',
      'Trace process tree to identify origin',
      'Check for downloaded payloads via LOLBin',
      'Identify persistence established via LOLBins',
      'Block specific abuse patterns via AppLocker/WDAC',
      'Monitor for recurrence with detection rules'
    ],
    mitre_techniques:['T1218','T1197','T1127','T1220','T1059','T1562']
  },

  /* ─────────────── IDENTITY & ACCESS ─────────────── */
  {
    id:'pb-025', category:'Identity & Access', severity:'critical',
    name:'Active Directory Compromise Response',
    description:'Full AD forest compromise response including DCSync detection, Golden Ticket response, and forest rebuild procedures.',
    steps:14, ttps:9, trigger:'DCSync alert, anomalous Kerberos TGT, krbtgt reset alert',
    tags:['AD','kerberos','T1558','golden-ticket','T1003'],
    icon:'fa-shield-alt', color:'#ef4444',
    steps_detail:[
      'Identify scope of AD compromise',
      'Reset krbtgt password twice (24h apart)',
      'Identify all created/modified domain accounts',
      'Remove malicious Group Policy Objects',
      'Identify and remove backdoor domain trusts',
      'Review AdminSDHolder and ACL modifications',
      'Rotate all service account passwords',
      'Audit privileged group memberships',
      'Check for skeleton key malware on DCs',
      'Analyze DC replication traffic for DCSync',
      'Review and clean domain controller logs',
      'Implement AD tiering model post-recovery',
      'Deploy detection rules for future attacks',
      'Consider Purple Team validation exercise'
    ],
    mitre_techniques:['T1558','T1003','T1207','T1484','T1098','T1136','T1222','T1134','T1649']
  },
  {
    id:'pb-026', category:'Identity & Access', severity:'high',
    name:'Privileged Access Abuse Investigation',
    description:'Investigation of privileged account misuse including admin account anomalies and PAM bypass attempts.',
    steps:8, ttps:5, trigger:'UEBA alert, privileged account anomaly, PAM bypass',
    tags:['privileged-access','T1078','PAM','abuse'],
    icon:'fa-user-shield', color:'#f97316',
    steps_detail:[
      'Pull all privileged account activity logs',
      'Identify out-of-band privileged operations',
      'Check for PAM bypass techniques',
      'Review sudo/RunAs commands executed',
      'Correlate with physical and VPN access logs',
      'Interview account owner if not malicious insider',
      'Implement just-in-time access controls',
      'Enable enhanced privileged session recording'
    ],
    mitre_techniques:['T1078','T1548','T1134','T1098','T1068']
  },
  {
    id:'pb-027', category:'Identity & Access', severity:'high',
    name:'OAuth / SSO Compromise Response',
    description:'Response to OAuth token theft, SSO bypass, and identity provider compromise.',
    steps:9, ttps:5, trigger:'Suspicious OAuth app, token theft indicator, SSO anomaly',
    tags:['OAuth','SSO','T1528','T1550','identity'],
    icon:'fa-id-badge', color:'#f97316',
    steps_detail:[
      'Identify affected OAuth applications',
      'Revoke all active OAuth tokens',
      'Remove unauthorized OAuth application grants',
      'Review SAML assertions for manipulation',
      'Force re-authentication for all users',
      'Check for identity provider backdoors',
      'Enable conditional access policies',
      'Audit all SSO-protected application access',
      'Implement FIDO2/hardware key requirements'
    ],
    mitre_techniques:['T1528','T1550','T1606','T1078','T1539']
  },

  /* ─────────────── WEB APPLICATION ─────────────── */
  {
    id:'pb-028', category:'Web Application', severity:'high',
    name:'Web Shell Detection & Removal',
    description:'Detection and removal of web shells including file system scan, access log analysis, and server hardening.',
    steps:9, ttps:4, trigger:'WAF alert, file integrity violation, anomalous web process',
    tags:['web-shell','T1505','T1190','persistence'],
    icon:'fa-globe', color:'#f97316',
    steps_detail:[
      'Scan web roots for known web shell signatures',
      'Review web server access logs for upload patterns',
      'Identify commands executed via web shell',
      'Check for additional backdoors and persistence',
      'Identify initial access vector',
      'Remove web shells and malicious files',
      'Patch exploited web application vulnerability',
      'Implement file integrity monitoring on web roots',
      'Enable WAF rules for web shell activity'
    ],
    mitre_techniques:['T1505','T1190','T1059','T1041','T1083']
  },
  {
    id:'pb-029', category:'Web Application', severity:'high',
    name:'XSS / CSRF Attack Response',
    description:'Response to Cross-Site Scripting and CSRF attacks including payload analysis and user impact assessment.',
    steps:7, ttps:3, trigger:'WAF XSS alert, suspicious session activity, user report',
    tags:['XSS','CSRF','T1185','web-application'],
    icon:'fa-code', color:'#f97316',
    steps_detail:[
      'Identify and block attacker infrastructure',
      'Analyze XSS payload and impact scope',
      'Identify compromised user sessions',
      'Invalidate all active sessions for affected users',
      'Check for credential or token theft',
      'Implement Content Security Policy',
      'Fix vulnerable code with proper encoding'
    ],
    mitre_techniques:['T1185','T1539','T1056','T1190']
  },

  /* ─────────────── SPECIALIZED ─────────────── */
  {
    id:'pb-030', category:'Dark Web', severity:'high',
    name:'Dark Web Exposure Alert Response',
    description:'Response to organization credentials, data, or infrastructure discovered on dark web forums or marketplaces.',
    steps:8, ttps:4, trigger:'Dark web monitoring alert, threat intel feed',
    tags:['dark-web','credential-leak','T1078','exposure'],
    icon:'fa-eye', color:'#c9a227',
    steps_detail:[
      'Validate and assess the dark web exposure',
      'Identify which accounts or data are exposed',
      'Immediately reset all exposed credentials',
      'Check for account compromise indicators',
      'Assess if active breach is ongoing',
      'Engage law enforcement if applicable',
      'Notify affected individuals (regulatory requirement)',
      'Implement continuous dark web monitoring'
    ],
    mitre_techniques:['T1078','T1552','T1589','T1598']
  },
  {
    id:'pb-031', category:'Dark Web', severity:'high',
    name:'Typosquat Domain Response',
    description:'Detection and takedown of typosquatting domains targeting organization brand and users.',
    steps:7, ttps:2, trigger:'Brand monitoring alert, phishing report, user complaint',
    tags:['typosquat','brand-abuse','phishing','T1583'],
    icon:'fa-registered', color:'#c9a227',
    steps_detail:[
      'Confirm typosquat domain and hosting details',
      'Analyze website content and intent',
      'Document evidence for UDRP filing',
      'Submit abuse reports to registrar and hosting',
      'Request blocking from major browsers (Safe Browsing)',
      'Alert users through official channels',
      'File UDRP/URS complaint for domain recovery'
    ],
    mitre_techniques:['T1583','T1566','T1598']
  },
  {
    id:'pb-032', category:'Compliance & Reporting', severity:'medium',
    name:'GDPR Breach Notification Workflow',
    description:'72-hour GDPR breach notification workflow with documentation, DPA notification, and affected party communication.',
    steps:10, ttps:2, trigger:'Data breach involving EU resident personal data',
    tags:['GDPR','compliance','notification','data-breach'],
    icon:'fa-balance-scale', color:'#22c55e',
    steps_detail:[
      'Determine if incident involves EU personal data',
      'Assess likelihood and severity of risk to individuals',
      'Document incident details, scope, and impact',
      'Engage Data Protection Officer immediately',
      'Determine notification requirement (within 72 hours)',
      'Notify supervisory authority (DPA) if required',
      'Draft communication to affected data subjects',
      'Implement measures to address the breach',
      'Document all actions taken',
      'Update data breach register'
    ],
    mitre_techniques:['T1078','T1041']
  },
  {
    id:'pb-033', category:'Threat Intelligence', severity:'high',
    name:'IOC Enrichment & Distribution',
    description:'Automated IOC enrichment workflow with threat intelligence correlation and STIX/TAXII distribution.',
    steps:8, ttps:3, trigger:'New IOC ingested from any source',
    tags:['IOC','STIX','TAXII','threat-intel','enrichment'],
    icon:'fa-search', color:'#22c55e',
    steps_detail:[
      'Receive and normalize raw IOC data',
      'Enrich with VirusTotal, Shodan, AbuseIPDB',
      'Check against existing threat actor profiles',
      'Calculate confidence and risk scores',
      'Correlate with active campaigns',
      'Create STIX objects for sharing',
      'Distribute via TAXII to trust group',
      'Update internal blocking rules'
    ],
    mitre_techniques:['T1071','T1090','T1568']
  },
  {
    id:'pb-034', category:'Forensics', severity:'high',
    name:'Digital Forensics & Evidence Collection',
    description:'Forensically sound evidence collection playbook for legal proceedings with chain of custody procedures.',
    steps:9, ttps:3, trigger:'Legal hold, law enforcement request, severe incident',
    tags:['forensics','evidence','chain-of-custody','legal'],
    icon:'fa-search-plus', color:'#3b82f6',
    steps_detail:[
      'Document legal authorization for collection',
      'Generate cryptographic hashes of all evidence',
      'Capture memory before power-down',
      'Create forensic disk images (not copies)',
      'Document chain of custody for each item',
      'Store evidence in tamper-evident containers',
      'Conduct analysis on copies, not originals',
      'Produce forensically sound analysis reports',
      'Maintain evidence integrity for legal proceedings'
    ],
    mitre_techniques:['T1070','T1027','T1119']
  },
  {
    id:'pb-035', category:'Incident Response', severity:'critical',
    name:'Zero-Day Exploit Response',
    description:'Emergency response to active zero-day exploitation with containment, vendor coordination, and virtual patching.',
    steps:11, ttps:5, trigger:'Novel exploit detection, vendor 0-day advisory',
    tags:['zero-day','T1190','exploit','virtual-patch'],
    icon:'fa-exclamation-triangle', color:'#ef4444',
    steps_detail:[
      'Confirm exploitation is active and novel',
      'Activate emergency response team',
      'Immediately isolate vulnerable systems',
      'Deploy virtual patches via WAF/IPS',
      'Identify all exploitation attempts in logs',
      'Coordinate with affected software vendor',
      'Develop detection signatures',
      'Brief executive leadership',
      'Share IOCs with ISAC/CERT',
      'Deploy vendor patch on emergency timeline',
      'Conduct post-exploitation scope assessment'
    ],
    mitre_techniques:['T1190','T1211','T1210','T1059','T1027']
  },
  {
    id:'pb-036', category:'Endpoint Security', severity:'high',
    name:'SSH Key Exposure & Brute Force Response',
    description:'Response to SSH key compromise or brute force attacks on Linux/Unix systems.',
    steps:8, ttps:4, trigger:'Failed SSH authentication spike, key exposure alert',
    tags:['SSH','brute-force','T1110','T1552'],
    icon:'fa-terminal', color:'#f97316',
    steps_detail:[
      'Identify source IPs and block at firewall',
      'Review authorized_keys files for unauthorized entries',
      'Rotate all SSH keys across affected systems',
      'Check for successful auth with compromised keys',
      'Review sudoers files for unauthorized entries',
      'Enable SSH key attestation and monitoring',
      'Implement fail2ban or similar brute force protection',
      'Enforce SSH certificate-based authentication'
    ],
    mitre_techniques:['T1110','T1552','T1078','T1098']
  }
];

/* Category color map */
window.PLAYBOOK_CATEGORIES = {
  'Incident Response': '#ef4444',
  'Threat Hunting': '#8b5cf6',
  'Malware Analysis': '#f97316',
  'Vulnerability Management': '#f59e0b',
  'Network Security': '#22c55e',
  'Cloud Security': '#3b82f6',
  'Endpoint Security': '#06b6d4',
  'Identity & Access': '#a855f7',
  'Web Application': '#14b8a6',
  'Dark Web': '#c9a227',
  'Compliance & Reporting': '#6ee7b7',
  'Threat Intelligence': '#38bdf8',
  'Forensics': '#818cf8'
};
