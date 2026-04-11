/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Adversary Simulation Lab v2.0
 *  FILE: js/adversary-sim-lab.js
 *
 *  MITRE ATT&CK-based attack simulations with real-world scenarios.
 *  Full attack chain: Initial Access → Exfiltration
 *  Backed by /api/adversary-sim endpoints (DB-persisted sessions).
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ════════════════════════════════════════════════════════════════
   MITRE ATT&CK SCENARIOS — Real-world attack chains
════════════════════════════════════════════════════════════════ */
const ADVERSARY_SCENARIOS = [
  {
    id: 'apt29-solorigate',
    name: 'APT29 — SolarWinds Supply Chain Attack',
    actor: 'APT29 (Cozy Bear / Nobelium)',
    actorCountry: 'Russia',
    difficulty: 'CRITICAL',
    industry: 'Technology / Government',
    duration: '9-18 months',
    description: 'Simulate the historic SolarWinds supply chain compromise used by APT29 to infiltrate US government networks. Full kill chain from build system compromise to exfiltration.',
    icon: 'fa-sun',
    iconColor: '#ef4444',
    phases: [
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1195.002', name: 'Compromise Software Supply Chain', desc: 'Backdoor inserted into SolarWinds Orion build process during compilation.' }],
        timeline: '0h', status: 'entry', icon: 'fa-door-open',
        indicators: ['orion-installer-modified.exe', 'SUNBURST DLL signature'] },
      { id: 'execution', name: 'Execution', tactic: 'TA0002',
        techniques: [{ id: 'T1059.001', name: 'PowerShell', desc: 'SUNBURST malware executes PowerShell through Orion service.' }],
        timeline: '2-14 days', status: 'dormant', icon: 'fa-terminal',
        indicators: ['solarwinds.businesslayerhost.exe → powershell.exe', 'Encoded PS commands'] },
      { id: 'defense-evasion', name: 'Defense Evasion', tactic: 'TA0005',
        techniques: [{ id: 'T1027', name: 'Obfuscated Files/Information', desc: 'SUNBURST obfuscates C2 traffic to blend with legitimate SolarWinds telemetry.' }, { id: 'T1036', name: 'Masquerading', desc: 'Malicious DLL masquerades as legitimate SolarWinds component.' }],
        timeline: '14-21 days', status: 'evasion', icon: 'fa-mask',
        indicators: ['avsvmcloud[.]com DGA domains', 'Delayed execution (14-day dormancy)'] },
      { id: 'discovery', name: 'Discovery', tactic: 'TA0007',
        techniques: [{ id: 'T1018', name: 'Remote System Discovery', desc: 'Enumerate Active Directory and internal network topology.' }, { id: 'T1087', name: 'Account Discovery', desc: 'Map user accounts and privileged service accounts.' }],
        timeline: '21-30 days', status: 'recon', icon: 'fa-search',
        indicators: ['LDAP queries', 'net user /domain', 'bloodhound-style recon'] },
      { id: 'lateral-movement', name: 'Lateral Movement', tactic: 'TA0008',
        techniques: [{ id: 'T1021.002', name: 'SMB/Windows Admin Shares', desc: 'Move laterally using stolen credentials and admin shares.' }, { id: 'T1550.003', name: 'Pass the Ticket', desc: 'Kerberos golden ticket attacks after DC compromise.' }],
        timeline: '30-60 days', status: 'lateral', icon: 'fa-exchange-alt',
        indicators: ['Unusual SMB connections', 'Kerberos ticket anomalies', 'TEARDROP loader'] },
      { id: 'collection', name: 'Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1114.002', name: 'Remote Email Collection', desc: 'Exfiltrate email via Microsoft 365 OAuth tokens.' }, { id: 'T1005', name: 'Data from Local System', desc: 'Collect sensitive documents, credentials, and certificates.' }],
        timeline: '60-120 days', status: 'collection', icon: 'fa-database',
        indicators: ['O365 audit log anomalies', 'Mass email forwarding', 'Unusual file access'] },
      { id: 'exfiltration', name: 'Exfiltration', tactic: 'TA0010',
        techniques: [{ id: 'T1041', name: 'Exfiltration Over C2 Channel', desc: 'Data exfiltrated via HTTPS to attacker-controlled infrastructure.' }, { id: 'T1567', name: 'Exfiltration Over Web Service', desc: 'Data staged and exfiltrated to cloud storage.' }],
        timeline: '120-270 days', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['Large HTTPS uploads to unusual IPs', 'DNS tunneling patterns'] },
    ],
    mitigations: [
      { id: 'M1051', name: 'Update Software', desc: 'Apply SolarWinds patches immediately.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Limit service account privileges.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Isolate SolarWinds server from internet.' },
      { id: 'M1038', name: 'Execution Prevention', desc: 'Block unsigned DLL loading.' },
    ],
    detectionRules: ['SUNBURST DNS pattern: avsvmcloud.com', 'DGA domain detection', 'Orion process spawning PowerShell', 'Golden ticket Kerberos events'],
    cvssEquivalent: 10.0,
    references: ['https://attack.mitre.org/software/S0559/', 'https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain.html'],
  },
  {
    id: 'lazarus-financial',
    name: 'Lazarus Group — Financial Sector Heist',
    actor: 'Lazarus Group (ZINC / Hidden Cobra)',
    actorCountry: 'North Korea',
    difficulty: 'HIGH',
    industry: 'Financial Services',
    duration: '3-6 months',
    description: 'Reproduce the Lazarus Group attack pattern against global banks using SWIFT fraud, watering holes, and custom malware (BLINDINGCAN, BISTROMATH).',
    icon: 'fa-piggy-bank',
    iconColor: '#f59e0b',
    phases: [
      { id: 'recon', name: 'Reconnaissance', tactic: 'TA0043',
        techniques: [{ id: 'T1593', name: 'Search Open Websites/Domains', desc: 'OSINT on target bank employees via LinkedIn, leaked data.' }],
        timeline: '0h', status: 'entry', icon: 'fa-binoculars',
        indicators: ['Targeted phishing list', 'Employee profiles scraped'] },
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'Malicious Word macro documents sent to bank employees.' }],
        timeline: '1-7 days', status: 'phish', icon: 'fa-envelope-open',
        indicators: ['malicious_resume.docx', 'VBA macro execution', 'WMI persistence'] },
      { id: 'persistence', name: 'Persistence', tactic: 'TA0003',
        techniques: [{ id: 'T1053.005', name: 'Scheduled Task/Job', desc: 'BLINDINGCAN backdoor scheduled task for persistence.' }],
        timeline: '7-14 days', status: 'persist', icon: 'fa-anchor',
        indicators: ['Scheduled tasks created by Office', 'BLINDINGCAN DLL signatures'] },
      { id: 'credential-access', name: 'Credential Access', tactic: 'TA0006',
        techniques: [{ id: 'T1003.001', name: 'LSASS Memory', desc: 'Mimikatz-style credential dumping from LSASS process.' }],
        timeline: '14-30 days', status: 'cred', icon: 'fa-key',
        indicators: ['lsass.exe memory reads', 'Procdump execution', 'SAM database access'] },
      { id: 'lateral-movement', name: 'Lateral Movement', tactic: 'TA0008',
        techniques: [{ id: 'T1021.001', name: 'Remote Desktop Protocol', desc: 'Move to SWIFT terminal servers using stolen admin credentials.' }],
        timeline: '30-60 days', status: 'lateral', icon: 'fa-project-diagram',
        indicators: ['RDP from workstations to SWIFT servers', 'Off-hours access patterns'] },
      { id: 'impact', name: 'Impact', tactic: 'TA0040',
        techniques: [{ id: 'T1496', name: 'Resource Hijacking', desc: 'Fraudulent SWIFT transfers initiated from compromised terminals.' }, { id: 'T1485', name: 'Data Destruction', desc: 'Wiper malware deployed to cover tracks.' }],
        timeline: '60-180 days', status: 'impact', icon: 'fa-dollar-sign',
        indicators: ['Anomalous SWIFT messages', 'Disk wiper activity', 'Large fund transfers'] },
    ],
    mitigations: [
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'Enforce MFA on all privileged accounts.' },
      { id: 'M1031', name: 'Network Intrusion Prevention', desc: 'Monitor SWIFT connections.' },
      { id: 'M1050', name: 'Exploit Protection', desc: 'Enable SWIFT customer security programme.' },
    ],
    detectionRules: ['BLINDINGCAN hash detection', 'SWIFT message anomalies', 'LSASS access from Office processes', 'Off-hours RDP to SWIFT servers'],
    cvssEquivalent: 9.5,
    references: ['https://attack.mitre.org/groups/G0032/', 'https://us-cert.cisa.gov/ncas/alerts/aa21-048a'],
  },
  {
    id: 'lockbit-ransomware',
    name: 'LockBit 3.0 — Enterprise Ransomware Campaign',
    actor: 'LockBit Ransomware Group',
    actorCountry: 'International (RaaS)',
    difficulty: 'HIGH',
    industry: 'Healthcare / Manufacturing',
    duration: '2-8 weeks',
    description: 'Simulate a LockBit 3.0 ransomware-as-a-service operation targeting enterprise infrastructure, from initial access through encryption and double extortion.',
    icon: 'fa-lock',
    iconColor: '#ef4444',
    phases: [
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'Exploit CVE-2023-4966 (Citrix Bleed) or VPN vulnerabilities.' }],
        timeline: '0h', status: 'entry', icon: 'fa-door-open',
        indicators: ['CVE-2023-4966 exploitation', 'Unusual VPN auth attempts', 'Initial beacon'] },
      { id: 'execution', name: 'Execution', tactic: 'TA0002',
        techniques: [{ id: 'T1059.003', name: 'Windows Command Shell', desc: 'PowerShell and cmd.exe used to execute LockBit loader.' }],
        timeline: '0-2 hours', status: 'exec', icon: 'fa-terminal',
        indicators: ['PowerShell with -EncodedCommand', 'certutil.exe downloading payloads'] },
      { id: 'defense-evasion', name: 'Defense Evasion', tactic: 'TA0005',
        techniques: [{ id: 'T1562.001', name: 'Disable or Modify Tools', desc: 'Disable Windows Defender, security tools via policy.' }, { id: 'T1070', name: 'Indicator Removal', desc: 'Clear Windows event logs.' }],
        timeline: '2-4 hours', status: 'evasion', icon: 'fa-shield-alt',
        indicators: ['Defender disabled via registry', 'Event log cleared (4688, 4624)', 'Watchdog processes killed'] },
      { id: 'discovery', name: 'Discovery', tactic: 'TA0007',
        techniques: [{ id: 'T1083', name: 'File and Directory Discovery', desc: 'Enumerate file shares, backup locations, databases.' }, { id: 'T1135', name: 'Network Share Discovery', desc: 'Map all accessible network shares.' }],
        timeline: '4-8 hours', status: 'recon', icon: 'fa-search',
        indicators: ['net share', 'dir /s on network paths', 'SMB scanning'] },
      { id: 'lateral-movement', name: 'Lateral Movement', tactic: 'TA0008',
        techniques: [{ id: 'T1570', name: 'Lateral Tool Transfer', desc: 'Spread LockBit payload via SMB to all reachable hosts.' }, { id: 'T1021.002', name: 'SMB/Windows Admin Shares', desc: 'Use domain admin creds for lateral spread.' }],
        timeline: '8-24 hours', status: 'lateral', icon: 'fa-expand-arrows-alt',
        indicators: ['PsExec usage', 'WMI remote execution', 'LockBit spreading via admin$'] },
      { id: 'impact', name: 'Encryption & Extortion', tactic: 'TA0040',
        techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', desc: 'LockBit 3.0 encrypts files with .lockbit extension.' }, { id: 'T1490', name: 'Inhibit System Recovery', desc: 'Delete shadow copies, disable recovery options.' }],
        timeline: '24-72 hours', status: 'impact', icon: 'fa-skull',
        indicators: ['*.lockbit files', 'vssadmin delete shadows', 'bcdedit /set recoveryenabled no', 'Ransom note dropped'] },
    ],
    mitigations: [
      { id: 'M1053', name: 'Data Backup', desc: 'Maintain offline backups tested regularly.' },
      { id: 'M1049', name: 'Antivirus/Antimalware', desc: 'Behavioral detection for ransomware patterns.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Limit domain admin usage.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Segment backup systems from production.' },
    ],
    detectionRules: ['vssadmin delete shadows', 'bcdedit recovery disabled', '*.lockbit extension creation', 'Mass file writes in short time window'],
    cvssEquivalent: 9.8,
    references: ['https://attack.mitre.org/software/S0612/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a'],
  },
  {
    id: 'apt41-espionage',
    name: 'APT41 — Intellectual Property Theft',
    actor: 'APT41 (Double Dragon / Winnti)',
    actorCountry: 'China',
    difficulty: 'CRITICAL',
    industry: 'Pharma / Defense',
    duration: '6-24 months',
    description: 'Multi-stage IP theft campaign combining nation-state espionage with financially-motivated intrusions. Targets research institutions and defense contractors.',
    icon: 'fa-flask',
    iconColor: '#a855f7',
    phases: [
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1133', name: 'External Remote Services', desc: 'Exploit VPN appliance (Citrix, Pulse Secure) vulnerabilities.' }],
        timeline: '0h', status: 'entry', icon: 'fa-plug',
        indicators: ['VPN exploit attempts', 'MESSAGETAP malware', 'Webshell deployment'] },
      { id: 'persistence', name: 'Persistence', tactic: 'TA0003',
        techniques: [{ id: 'T1505.003', name: 'Web Shell', desc: 'HIGHNOON/JUMPALL webshells deployed on web servers.' }],
        timeline: '1-3 days', status: 'persist', icon: 'fa-anchor',
        indicators: ['Webshell activity', 'HIGHNOON DLL signatures', 'IIS unusual child processes'] },
      { id: 'privilege-escalation', name: 'Privilege Escalation', tactic: 'TA0004',
        techniques: [{ id: 'T1068', name: 'Exploitation for Privilege Escalation', desc: 'CVE-2019-3396 / local privilege escalation exploits.' }],
        timeline: '3-14 days', status: 'privesc', icon: 'fa-arrow-up',
        indicators: ['Local exploit binaries', 'Unexpected SYSTEM-level processes'] },
      { id: 'collection', name: 'Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1213', name: 'Data from Information Repositories', desc: 'Collect from SharePoint, Confluence, internal wikis.' }, { id: 'T1560', name: 'Archive Collected Data', desc: 'RAR/7zip archives for staging.' }],
        timeline: '14-90 days', status: 'collect', icon: 'fa-folder-open',
        indicators: ['Unusual SharePoint access', 'rar.exe creating archives in temp', 'Research document access'] },
      { id: 'exfiltration', name: 'Exfiltration', tactic: 'TA0010',
        techniques: [{ id: 'T1048', name: 'Exfiltration Over Alternative Protocol', desc: 'Data exfil via DNS tunneling and custom C2.' }],
        timeline: '90-730 days', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['DNS query volume anomalies', 'BEACON/ACEHASH traffic', 'Outbound to Chinese IP ranges'] },
    ],
    mitigations: [
      { id: 'M1051', name: 'Update Software', desc: 'Patch all VPN and web application vulnerabilities.' },
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Block DNS tunneling patterns.' },
      { id: 'M1042', name: 'Disable or Remove Feature/Program', desc: 'Disable unused remote access services.' },
    ],
    detectionRules: ['MESSAGETAP signatures', 'DNS volume anomalies', 'SharePoint mass download', 'Webshell process spawning'],
    cvssEquivalent: 9.3,
    references: ['https://attack.mitre.org/groups/G0096/', 'https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html'],
  },
  {
    id: 'fin7-retail',
    name: 'FIN7 — Retail POS Compromise',
    actor: 'FIN7 / Carbanak Group',
    actorCountry: 'Eastern Europe',
    difficulty: 'HIGH',
    industry: 'Retail / Hospitality',
    duration: '2-4 months',
    description: 'FIN7 financial crime campaign targeting retail chains with CARBANAK banking malware and POS scraper tools to harvest payment card data at scale.',
    icon: 'fa-credit-card',
    iconColor: '#22d3ee',
    phases: [
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'Fake restaurant/hotel booking emails with malicious Word docs.' }],
        timeline: '0h', status: 'entry', icon: 'fa-envelope',
        indicators: ['Booking confirmation.docx macros', 'CARBANAK loader execution'] },
      { id: 'execution', name: 'Execution & Persistence', tactic: 'TA0002',
        techniques: [{ id: 'T1059.005', name: 'Visual Basic', desc: 'VBScript executes CARBANAK second-stage.' }],
        timeline: '0-24 hours', status: 'exec', icon: 'fa-code',
        indicators: ['wscript.exe spawning', 'CARBANAK DLL injection', 'Registry run keys'] },
      { id: 'lateral-movement', name: 'Lateral Movement to POS', tactic: 'TA0008',
        techniques: [{ id: 'T1021.001', name: 'Remote Desktop Protocol', desc: 'Move to POS terminals from corporate network.' }],
        timeline: '7-30 days', status: 'lateral', icon: 'fa-cash-register',
        indicators: ['RDP from corporate to POS VLAN', 'Off-hours admin sessions'] },
      { id: 'collection', name: 'POS Data Harvesting', tactic: 'TA0009',
        techniques: [{ id: 'T1185', name: 'Browser Session Hijacking', desc: 'DICELOADER POS RAM scraper harvests card track data.' }],
        timeline: '30-90 days', status: 'collect', icon: 'fa-database',
        indicators: ['POS process memory reads', 'Track 1/2 data patterns in memory', 'DICELOADER signatures'] },
      { id: 'exfiltration', name: 'Data Exfiltration', tactic: 'TA0010',
        techniques: [{ id: 'T1041', name: 'Exfiltration Over C2 Channel', desc: 'Harvested card data encrypted and sent to C2 via HTTPS.' }],
        timeline: '90-120 days', status: 'exfil', icon: 'fa-upload',
        indicators: ['Encrypted uploads to Eastern European IPs', 'Large HTTPS payloads from POS terminals'] },
    ],
    mitigations: [
      { id: 'M1037', name: 'Network Segmentation', desc: 'Isolate POS network from corporate network.' },
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'MFA on all RDP access.' },
      { id: 'M1042', name: 'P2PE/E2EE', desc: 'Point-to-point encryption on POS systems.' },
    ],
    detectionRules: ['CARBANAK network signatures', 'Track data regex in memory', 'POS VLAN RDP access', 'DICELOADER process injection'],
    cvssEquivalent: 8.8,
    references: ['https://attack.mitre.org/groups/G0046/', 'https://securelist.com/the-carbanak-apt-the-great-bank-robbery/68732/'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 6: Sandworm — Critical Infrastructure Attack
  // ══════════════════════════════════════════════════════════════
  {
    id: 'sandworm-ics',
    name: 'Sandworm (APT44) — Critical Infrastructure / ICS Attack',
    actor: 'Sandworm / APT44 (Voodoo Bear)',
    actorCountry: 'Russia (GRU)',
    difficulty: 'CRITICAL',
    industry: 'Energy / Utilities / ICS/SCADA',
    duration: '6-18 months',
    description: 'Reproduce Sandworm\'s destructive attacks on Ukrainian power grids (Industroyer/CRASHOVERRIDE) and industrial control systems. Full OT/ICS kill chain from spearphish to power blackout.',
    icon: 'fa-bolt',
    iconColor: '#ef4444',
    phases: [
      { id: 'initial-access', name: 'Initial Access', tactic: 'TA0001',
        techniques: [{ id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'BlackEnergy loader delivered via malicious Office documents to control system operators.' }],
        timeline: '0h', status: 'phish', icon: 'fa-envelope',
        indicators: ['BlackEnergy maldoc', 'OLE macro execution', 'Operator workstation compromise'] },
      { id: 'execution', name: 'Execution', tactic: 'TA0002',
        techniques: [{ id: 'T1059.003', name: 'Windows Command Shell', desc: 'BlackEnergy installs KillDisk wiper and Industroyer C2 backdoor.' }],
        timeline: '1-7 days', status: 'exec', icon: 'fa-terminal',
        indicators: ['BlackEnergy DLL injection', 'KillDisk process creation', 'Backdoor persistence'] },
      { id: 'persistence', name: 'Persistence', tactic: 'TA0003',
        techniques: [{ id: 'T1543.003', name: 'Windows Service', desc: 'Industroyer installs as Windows service for long-term persistence.' }],
        timeline: '7-30 days', status: 'persist', icon: 'fa-anchor',
        indicators: ['New service: "defragsvc"', 'Registry service keys modified', 'Signed binary hijacking'] },
      { id: 'discovery', name: 'OT/ICS Discovery', tactic: 'TA0007',
        techniques: [{ id: 'T0840', name: 'Network Connection Enumeration', desc: 'Map ICS network topology, enumerate PLCs, RTUs, and HMI systems.' }, { id: 'T0888', name: 'Remote System Information Discovery', desc: 'Identify SCADA master stations and substation automation systems.' }],
        timeline: '30-90 days', status: 'recon', icon: 'fa-sitemap',
        indicators: ['IEC 104/61850 protocol scanning', 'DNP3 traffic', 'SCADA host discovery'] },
      { id: 'ics-attack', name: 'ICS/SCADA Attack', tactic: 'TA0104',
        techniques: [{ id: 'T0855', name: 'Unauthorized Command Message', desc: 'Industroyer directly manipulates substation switchgear via IEC 101/104 protocols.' }, { id: 'T0816', name: 'Device Restart/Shutdown', desc: 'Force-restart of protective relays to cause sustained outage.' }],
        timeline: '90-180 days', status: 'impact', icon: 'fa-power-off',
        indicators: ['IEC 101/104 command floods', 'Unexpected breaker switching', 'RTU communication failure'] },
      { id: 'impact', name: 'Destructive Impact', tactic: 'TA0040',
        techniques: [{ id: 'T1485', name: 'Data Destruction', desc: 'KillDisk overwrites MBR/files on operator workstations to prevent recovery.' }, { id: 'T1499', name: 'Endpoint DoS', desc: 'Crash serial-to-Ethernet converters to maintain outage.' }],
        timeline: '180+ days', status: 'impact', icon: 'fa-skull-crossbones',
        indicators: ['MBR overwrite activity', 'Mass disk wipe', 'Serial device communication loss'] },
    ],
    mitigations: [
      { id: 'M1030', name: 'Network Segmentation', desc: 'Air-gap OT/ICS network from corporate IT.' },
      { id: 'M1042', name: 'Disable Protocols', desc: 'Disable Modbus/IEC 104 on unauthorized hosts.' },
      { id: 'M1018', name: 'User Account Management', desc: 'Least privilege for SCADA operator accounts.' },
    ],
    detectionRules: ['Industroyer ICS protocol anomalies', 'KillDisk MBR overwrite patterns', 'BlackEnergy network signatures', 'Unexpected IEC 104 ASDU commands'],
    cvssEquivalent: 10.0,
    references: ['https://attack.mitre.org/groups/G0034/', 'https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 7: Scattered Spider — Social Engineering + Cloud
  // ══════════════════════════════════════════════════════════════
  {
    id: 'scattered-spider-cloud',
    name: 'Scattered Spider — Social Engineering & Cloud Ransomware',
    actor: 'Scattered Spider (UNC3944 / 0ktapus)',
    actorCountry: 'US/UK (Cybercriminal)',
    difficulty: 'HIGH',
    industry: 'Hospitality / Casino / Finance',
    duration: '1-4 weeks',
    description: 'Simulate the MGM Resorts breach: social engineering IT help desk to bypass MFA, Okta tenant hijack, Azure/AWS cloud pivot, ALPHV ransomware deployment.',
    icon: 'fa-spider',
    iconColor: '#a855f7',
    phases: [
      { id: 'recon', name: 'OSINT & Recon', tactic: 'TA0043',
        techniques: [{ id: 'T1591.004', name: 'Identify Roles', desc: 'LinkedIn OSINT to identify IT admins and help desk staff at target.' }],
        timeline: '0h', status: 'recon', icon: 'fa-binoculars',
        indicators: ['Employee profile harvesting', 'Org chart reconstruction', 'OSINT tool activity'] },
      { id: 'initial-access', name: 'Help Desk Vishing', tactic: 'TA0001',
        techniques: [{ id: 'T1598.004', name: 'Social Engineering', desc: 'Call IT help desk impersonating an employee to reset MFA — 10-minute attack.' }],
        timeline: '1-2 hours', status: 'phish', icon: 'fa-phone',
        indicators: ['Help desk ticket: MFA reset', 'New device enrollment', 'Unusual auth geolocation'] },
      { id: 'credential-access', name: 'Okta / Identity Provider Takeover', tactic: 'TA0006',
        techniques: [{ id: 'T1556.006', name: 'Multifactor Authentication Manipulation', desc: 'Disable MFA policies in Okta, add attacker-controlled authenticator.' }, { id: 'T1078.004', name: 'Cloud Accounts', desc: 'Use Okta SSO to access all federated cloud applications.' }],
        timeline: '2-6 hours', status: 'cred', icon: 'fa-id-card',
        indicators: ['Okta policy change', 'New MFA enrollment from unknown device', 'Mass SSO application access'] },
      { id: 'lateral-movement', name: 'Cloud & SaaS Lateral Movement', tactic: 'TA0008',
        techniques: [{ id: 'T1538', name: 'Cloud Service Dashboard', desc: 'Access Azure portal, AWS console, Salesforce, ServiceNow via compromised SSO.' }, { id: 'T1530', name: 'Data from Cloud Storage', desc: 'Enumerate and exfiltrate SharePoint, OneDrive, S3 buckets.' }],
        timeline: '6-24 hours', status: 'lateral', icon: 'fa-cloud',
        indicators: ['Azure subscription enumeration', 'S3 ListBuckets from new IP', 'SharePoint mass download'] },
      { id: 'impact', name: 'ALPHV Ransomware Deployment', tactic: 'TA0040',
        techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', desc: 'ALPHV/BlackCat ransomware deployed to on-prem and cloud-connected systems.' }, { id: 'T1657', name: 'Financial Theft', desc: 'Data theft for double extortion — threaten to leak guest PII and financial data.' }],
        timeline: '1-3 weeks', status: 'impact', icon: 'fa-lock',
        indicators: ['ALPHV encryptor signatures', 'Mass file rename with .sph extension', 'Data exfil to MEGA/Gofile'] },
    ],
    mitigations: [
      { id: 'M1017', name: 'User Training', desc: 'Train help desk on social engineering verification procedures.' },
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'Require phishing-resistant MFA (FIDO2/passkeys).' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Enforce JIT access for cloud admin roles.' },
    ],
    detectionRules: ['Okta policy modifications', 'MFA enrollment from new device post-reset', 'Bulk cloud data access', 'ALPHV ransom note creation'],
    cvssEquivalent: 9.6,
    references: ['https://attack.mitre.org/groups/G1015/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 8: Volt Typhoon — Living off the Land (LoLBins)
  // ══════════════════════════════════════════════════════════════
  {
    id: 'volt-typhoon-lotl',
    name: 'Volt Typhoon — Living off the Land Pre-positioning',
    actor: 'Volt Typhoon (Bronze Silhouette)',
    actorCountry: 'China (PLA)',
    difficulty: 'CRITICAL',
    industry: 'Critical Infrastructure / Telecom / Defense',
    duration: '12-60 months',
    description: 'Chinese state-sponsored pre-positioning in US critical infrastructure using exclusively LoLBins (no custom malware). SOHO router compromise and proxied C2 for future disruption capability.',
    icon: 'fa-shield-virus',
    iconColor: '#22d3ee',
    phases: [
      { id: 'initial-access', name: 'SOHO Router Compromise', tactic: 'TA0001',
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'Exploit CVE-2023-20198 (Cisco IOS XE) or Fortinet VPN vulnerabilities to gain SOHO router access.' }],
        timeline: '0h', status: 'entry', icon: 'fa-router',
        indicators: ['VPN exploit attempts', 'Cisco IOS XE /webui/ requests', 'Unusual outbound HTTPS from router'] },
      { id: 'execution', name: 'LoLBin Execution Chain', tactic: 'TA0002',
        techniques: [{ id: 'T1059.001', name: 'PowerShell', desc: 'Use built-in Windows tools exclusively: net.exe, wmic.exe, ntdsutil.exe.' }, { id: 'T1218', name: 'Signed Binary Proxy Execution', desc: 'LOLBins: mshta.exe, regsvr32.exe, certutil.exe for payload execution.' }],
        timeline: '1-7 days', status: 'exec', icon: 'fa-terminal',
        indicators: ['Unusual netsh usage', 'wmic remote process creation', 'certutil.exe downloading files'] },
      { id: 'persistence', name: 'Stealthy Persistence', tactic: 'TA0003',
        techniques: [{ id: 'T1098', name: 'Account Manipulation', desc: 'Add admin accounts to local groups, modify existing account permissions.' }, { id: 'T1137', name: 'Office Application Startup', desc: 'Office add-ins used for persistent code execution.' }],
        timeline: '7-30 days', status: 'persist', icon: 'fa-anchor',
        indicators: ['New local admin account', 'Group policy modification', 'Office template modification'] },
      { id: 'defense-evasion', name: 'Proxy Network via KV Botnet', tactic: 'TA0005',
        techniques: [{ id: 'T1090.003', name: 'Multi-hop Proxy', desc: 'Route all traffic through compromised SOHO devices (KV-Botnet) to blend into legitimate traffic.' }],
        timeline: '30-90 days', status: 'evasion', icon: 'fa-route',
        indicators: ['Traffic through residential IPs', 'Unusual SOHO router C2 patterns', 'Low-and-slow data flows'] },
      { id: 'collection', name: 'Long-term Intelligence Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1074.002', name: 'Remote Data Staging', desc: 'Collect network diagrams, credentials, operational data over months.' }, { id: 'T1040', name: 'Network Sniffing', desc: 'Deploy passive packet capture on critical network segments.' }],
        timeline: '90-730+ days', status: 'collect', icon: 'fa-database',
        indicators: ['Unexpected packet capture tools', 'Internal network scanning from admin hosts', 'Low-volume data staging'] },
    ],
    mitigations: [
      { id: 'M1051', name: 'Update Software', desc: 'Patch SOHO routers and edge devices immediately.' },
      { id: 'M1037', name: 'Filter Network Traffic', desc: 'Block outbound from SOHO/OT devices to non-business destinations.' },
      { id: 'M1031', name: 'Network Intrusion Prevention', desc: 'Monitor for LoLBin chains.' },
    ],
    detectionRules: ['SOHO device outbound C2', 'certutil.exe external downloads', 'wmic process creation chains', 'ntdsutil.exe usage outside backups'],
    cvssEquivalent: 9.8,
    references: ['https://attack.mitre.org/groups/G1017/', 'https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 9: Clop — MOVEit Zero-Day Mass Exploitation
  // ══════════════════════════════════════════════════════════════
  {
    id: 'clop-moveit-zeronday',
    name: 'Clop — MOVEit Zero-Day Mass Exploitation',
    actor: 'Clop Ransomware (TA505 / FIN11)',
    actorCountry: 'Russia/Eastern Europe',
    difficulty: 'HIGH',
    industry: 'Enterprise SaaS / Government / Healthcare',
    duration: '72 hours (mass exploitation)',
    description: 'Reproduce Clop\'s 2023 campaign exploiting CVE-2023-34362 (MOVEit Transfer SQL injection) affecting 2,000+ organizations in 72 hours. Web-facing SQLi to data theft without ransomware.',
    icon: 'fa-database',
    iconColor: '#f97316',
    phases: [
      { id: 'initial-access', name: 'MOVEit SQLi Exploitation', tactic: 'TA0001',
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'CVE-2023-34362: SQL injection in MOVEit Transfer human.aspx endpoint.' }],
        timeline: '0h', status: 'entry', icon: 'fa-database',
        indicators: ['POST /human.aspx with SQL payload', 'Unusual MOVEit system account activity', 'New DLL files in wwwroot'] },
      { id: 'execution', name: 'LEMURLOOT Webshell Deployment', tactic: 'TA0002',
        techniques: [{ id: 'T1505.003', name: 'Web Shell', desc: 'LEMURLOOT .NET webshell deployed to MOVEit IIS directory for persistent access.' }],
        timeline: '0-2 hours', status: 'exec', icon: 'fa-code',
        indicators: ['human2.aspx or similar webshell', '.NET assembly in wwwroot', 'IIS worker process spawning cmd.exe'] },
      { id: 'collection', name: 'Mass Data Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1213', name: 'Data from Information Repositories', desc: 'Extract all files and metadata from MOVEit database and storage.' }, { id: 'T1005', name: 'Data from Local System', desc: 'Dump MOVEit configuration, stored credentials, and all transferred files.' }],
        timeline: '2-24 hours', status: 'collect', icon: 'fa-folder-open',
        indicators: ['LEMURLOOT file listing commands', 'Large database exports', 'Bulk file access from webshell'] },
      { id: 'exfiltration', name: 'Bulk Data Exfiltration', tactic: 'TA0010',
        techniques: [{ id: 'T1048.003', name: 'Exfiltration Over Unencrypted Protocol', desc: 'Files exfiltrated via HTTP POST to Clop infrastructure before cleanup.' }],
        timeline: '24-72 hours', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['Large POST requests to unknown IPs', 'Bandwidth spike from MOVEit server', 'Webshell deletion (cleanup)'] },
      { id: 'impact', name: 'Double Extortion Announcement', tactic: 'TA0040',
        techniques: [{ id: 'T1657', name: 'Financial Theft', desc: 'Clop dark-web site posts victim list; pay or data gets leaked.' }],
        timeline: '72h+', status: 'impact', icon: 'fa-money-bill-wave',
        indicators: ['Clop.onion victim list', 'Extortion demand email', 'Legal/compliance breach notification'] },
    ],
    mitigations: [
      { id: 'M1051', name: 'Update Software', desc: 'Apply MOVEit Transfer patches immediately.' },
      { id: 'M1042', name: 'Disable or Remove Feature', desc: 'Disable MOVEit if not needed; restrict to allow-listed IPs.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Isolate file transfer server from main network.' },
    ],
    detectionRules: ['MOVEit SQLi patterns in web logs', 'LEMURLOOT webshell IoCs', 'human2.aspx/human.aspx POST requests', 'Large outbound transfers from file server'],
    cvssEquivalent: 9.8,
    references: ['https://attack.mitre.org/software/S1110/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 10: Kimsuky — BEC / Executive Impersonation
  // ══════════════════════════════════════════════════════════════
  {
    id: 'kimsuky-bec',
    name: 'Kimsuky — Business Email Compromise & Nuclear Espionage',
    actor: 'Kimsuky (Thallium / APT43)',
    actorCountry: 'North Korea (RGB)',
    difficulty: 'HIGH',
    industry: 'Think Tanks / Government / Nuclear Research',
    duration: '1-6 months',
    description: 'Kimsuky BEC campaign targeting South Korean government officials, US nuclear researchers, and policy analysts through spearphishing, credential harvesting, and tailored implants (AppleSeed, BabyShark).',
    icon: 'fa-atom',
    iconColor: '#f59e0b',
    phases: [
      { id: 'recon', name: 'Targeted OSINT', tactic: 'TA0043',
        techniques: [{ id: 'T1591.001', name: 'Determine Physical Locations', desc: 'Monitor target on social media, government websites, conference programs.' }],
        timeline: '0h', status: 'recon', icon: 'fa-user-secret',
        indicators: ['Target organization research', 'Policy paper tracking', 'Conference registration monitoring'] },
      { id: 'initial-access', name: 'Spearphishing + Credential Harvest', tactic: 'TA0001',
        techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', desc: 'Google Forms-based credential phishing mimicking academic journals, security portal logins.' }, { id: 'T1598.003', name: 'Spearphishing Link (Credential Collection)', desc: 'Custom phishing pages spoofing Naver, Gmail, government portals.' }],
        timeline: '1-7 days', status: 'phish', icon: 'fa-envelope-open',
        indicators: ['Naver/Gmail phishing page', 'Google Forms credential collection', 'Custom domain impersonation'] },
      { id: 'execution', name: 'AppleSeed Implant', tactic: 'TA0002',
        techniques: [{ id: 'T1059.001', name: 'PowerShell', desc: 'AppleSeed backdoor delivered via malicious CHM or HWP documents.' }],
        timeline: '3-14 days', status: 'exec', icon: 'fa-terminal',
        indicators: ['CHM file execution', 'AppleSeed C2 beacon', 'HWP document macro activity'] },
      { id: 'collection', name: 'Targeted Intelligence Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1114.001', name: 'Local Email Collection', desc: 'Exfiltrate emails with policy documents, nuclear research, diplomatic correspondence.' }, { id: 'T1213', name: 'Data from Information Repositories', desc: 'Access internal wikis, shared drives, and research databases.' }],
        timeline: '14-90 days', status: 'collect', icon: 'fa-envelope',
        indicators: ['Email client data access', 'Large Outlook PST export', 'Document staging in temp directory'] },
      { id: 'exfiltration', name: 'Data Exfiltration via Cloud', tactic: 'TA0010',
        techniques: [{ id: 'T1567.002', name: 'Exfiltration to Cloud Storage', desc: 'Staged data uploaded to OneDrive/Google Drive via compromised accounts.' }],
        timeline: '90+ days', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['OneDrive sync to unknown account', 'Google Drive bulk upload', 'Encrypted archive exfiltration'] },
    ],
    mitigations: [
      { id: 'M1049', name: 'Antivirus/Antimalware', desc: 'Detect AppleSeed/BabyShark signatures.' },
      { id: 'M1054', name: 'Software Configuration', desc: 'Disable CHM and HWP macros in enterprise.' },
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'Enforce FIDO2 MFA on all email and cloud accounts.' },
    ],
    detectionRules: ['AppleSeed C2 domain patterns', 'CHM execution from temp dir', 'BabyShark PowerShell signatures', 'OneDrive sync from unusual locations'],
    cvssEquivalent: 8.5,
    references: ['https://attack.mitre.org/groups/G0094/', 'https://us-cert.cisa.gov/ncas/alerts/aa20-301a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 11: REvil/Kaseya — MSP Supply Chain Ransomware
  // ══════════════════════════════════════════════════════════════
  {
    id: 'revil-kaseya',
    name: 'REvil — Kaseya VSA MSP Supply Chain Ransomware',
    actor: 'REvil (Sodinokibi)',
    actorCountry: 'Russia (RaaS)',
    difficulty: 'CRITICAL',
    industry: 'Managed Service Provider (MSP)',
    duration: '4 hours to 1500+ victims',
    description: 'Reproduce the 2021 Kaseya VSA zero-day supply chain attack: exploit authentication bypass in RMM software, push ransomware to all 1,500 managed customers simultaneously.',
    icon: 'fa-building',
    iconColor: '#ef4444',
    phases: [
      { id: 'initial-access', name: 'Kaseya VSA Zero-Day Exploit', tactic: 'TA0001',
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'CVE-2021-30116: Auth bypass + credential leak in Kaseya VSA on-premise server.' }],
        timeline: '0h', status: 'entry', icon: 'fa-server',
        indicators: ['Kaseya VSA /userFilterTableRpt.asp exploit', 'Auth bypass via cookie tampering', 'VSA agent push unusual payload'] },
      { id: 'execution', name: 'Mass RMM Agent Deployment', tactic: 'TA0002',
        techniques: [{ id: 'T1072', name: 'Software Deployment Tools', desc: 'Kaseya VSA agent (legitimate) used to deploy REvil ransomware to all managed endpoints.' }],
        timeline: '0-2 hours', status: 'exec', icon: 'fa-cogs',
        indicators: ['Kaseya agent.exe deploying encoded PS', 'certutil.exe downloading agent.crt', 'Windows Defender disabled via policy'] },
      { id: 'defense-evasion', name: 'Defender & EDR Bypass', tactic: 'TA0005',
        techniques: [{ id: 'T1562.001', name: 'Impair Defenses', desc: 'Disable Windows Defender real-time protection via Kaseya scripting feature.' }, { id: 'T1218.011', name: 'Rundll32', desc: 'REvil payload executed via rundll32.exe to evade EDR.' }],
        timeline: '0-30 minutes', status: 'evasion', icon: 'fa-shield-alt',
        indicators: ['Defender disabled event 5001', 'rundll32.exe unusual DLL load', 'EDR service stopped'] },
      { id: 'impact', name: 'Mass Ransomware Deployment', tactic: 'TA0040',
        techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', desc: 'REvil encrypts files with .ikhwxb extension across 1,500+ organizations simultaneously.' }, { id: 'T1490', name: 'Inhibit System Recovery', desc: 'Shadow copies deleted, recovery mode disabled on all affected endpoints.' }],
        timeline: '1-4 hours', status: 'impact', icon: 'fa-skull',
        indicators: ['.ikhwxb encrypted extension', 'VSS deletion (vssadmin)', 'kaseya-ransomware note: README.ikhwxb'] },
    ],
    mitigations: [
      { id: 'M1030', name: 'Network Segmentation', desc: 'Restrict Kaseya VSA to management VLAN only.' },
      { id: 'M1051', name: 'Update Software', desc: 'Patch RMM/VSA software immediately and enforce SLA.' },
      { id: 'M1018', name: 'User Account Management', desc: 'Require approval for mass agent scripting jobs.' },
    ],
    detectionRules: ['Kaseya VSA exploit POST patterns', 'Agent.crt download via certutil', 'Mass EDR disable event', 'REvil ransom note creation'],
    cvssEquivalent: 10.0,
    references: ['https://attack.mitre.org/software/S0496/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 12: APT28 — Credential Phishing & Data Theft
  // ══════════════════════════════════════════════════════════════
  {
    id: 'apt28-phishing',
    name: 'APT28 (Fancy Bear) — Credential Phishing & Political Espionage',
    actor: 'APT28 / Fancy Bear (GRU Unit 26165)',
    actorCountry: 'Russia (GRU)',
    difficulty: 'HIGH',
    industry: 'Political / Government / Media',
    duration: '2-8 weeks',
    description: 'APT28 targeting election campaigns, political parties, and media organizations using custom phishing tools (PHISHERY, CHOPSTICK) and password spray attacks on cloud services.',
    icon: 'fa-vote-yea',
    iconColor: '#ef4444',
    phases: [
      { id: 'recon', name: 'Target Reconnaissance', tactic: 'TA0043',
        techniques: [{ id: 'T1589.002', name: 'Email Addresses', desc: 'Harvest target email addresses from public sources and data breaches.' }],
        timeline: '0h', status: 'recon', icon: 'fa-binoculars',
        indicators: ['Email harvesting tools', 'Have I Been Pwned API queries', 'HunterIO usage'] },
      { id: 'initial-access', name: 'Credential Phishing', tactic: 'TA0001',
        techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', desc: 'PHISHERY toolkit: email linking to fake Google/Microsoft auth pages.' }, { id: 'T1110.003', name: 'Password Spraying', desc: 'Low-and-slow password spray against O365/Google Workspace.' }],
        timeline: '1-7 days', status: 'phish', icon: 'fa-envelope-open',
        indicators: ['PHISHERY OAuth phish page', 'Failed O365 auth from Tor IPs', 'OAuth token theft alerts'] },
      { id: 'persistence', name: 'Persistence via Implants', tactic: 'TA0003',
        techniques: [{ id: 'T1546.003', name: 'Windows Management Instrumentation Event Subscription', desc: 'CHOPSTICK uses WMI subscriptions for fileless persistence.' }],
        timeline: '1-5 days', status: 'persist', icon: 'fa-anchor',
        indicators: ['WMI event subscription creation', 'CHOPSTICK C2 signatures', 'Unusual scrcons.exe activity'] },
      { id: 'collection', name: 'Email & Document Collection', tactic: 'TA0009',
        techniques: [{ id: 'T1114.002', name: 'Remote Email Collection', desc: 'IMAP/API access to Gmail/O365 to bulk download emails and attachments.' }],
        timeline: '5-21 days', status: 'collect', icon: 'fa-inbox',
        indicators: ['IMAP login from Russian ASN', 'OAuth app suspicious grant', 'Gmail forwarding rule added'] },
      { id: 'exfiltration', name: 'Strategic Exfiltration & Leak', tactic: 'TA0010',
        techniques: [{ id: 'T1567', name: 'Exfiltration Over Web Service', desc: 'Political data staged for selective leak via WikiLeaks-style front organizations.' }],
        timeline: '21+ days', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['DCLeaks-style staging domains', 'Tor C2 exfiltration', 'Encrypted archive creation'] },
    ],
    mitigations: [
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'Phishing-resistant MFA (FIDO2) for all accounts.' },
      { id: 'M1049', name: 'Antivirus/Antimalware', desc: 'Detect CHOPSTICK WMI persistence patterns.' },
      { id: 'M1054', name: 'Software Configuration', desc: 'Restrict OAuth app permissions and require admin consent.' },
    ],
    detectionRules: ['PHISHERY OAuth phishing indicators', 'Password spray: 1 attempt per 5min per user', 'WMI subscriptions to PowerShell', 'CHOPSTICK C2 domain patterns'],
    cvssEquivalent: 8.8,
    references: ['https://attack.mitre.org/groups/G0007/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-336a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 13: BlackMatter/DarkSide — Critical Infrastructure
  // ══════════════════════════════════════════════════════════════
  {
    id: 'darkside-pipeline',
    name: 'DarkSide — Colonial Pipeline Infrastructure Attack',
    actor: 'DarkSide Ransomware Group',
    actorCountry: 'Russia (Cybercriminal RaaS)',
    difficulty: 'HIGH',
    industry: 'Energy / Pipeline / Critical Infrastructure',
    duration: '2-4 weeks',
    description: 'Reproduce the Colonial Pipeline attack: VPN credential theft, network traversal to OT network, ransomware deployment causing national fuel shortage — and subsequent shutdown.',
    icon: 'fa-oil-can',
    iconColor: '#f97316',
    phases: [
      { id: 'initial-access', name: 'Compromised VPN Credentials', tactic: 'TA0001',
        techniques: [{ id: 'T1078', name: 'Valid Accounts', desc: 'Stolen VPN password (no MFA) found on dark web from previous breach.' }],
        timeline: '0h', status: 'entry', icon: 'fa-key',
        indicators: ['VPN auth from Eastern European IP', 'Legacy VPN account with no MFA', 'Off-hours admin login'] },
      { id: 'discovery', name: 'Network Reconnaissance', tactic: 'TA0007',
        techniques: [{ id: 'T1046', name: 'Network Service Discovery', desc: 'Map IT and OT network segments, find billing and operational systems.' }],
        timeline: '1-7 days', status: 'recon', icon: 'fa-search',
        indicators: ['Internal port scanning', 'SMB enumeration', 'IT/OT network bridge detection'] },
      { id: 'lateral-movement', name: 'IT to Billing System Pivot', tactic: 'TA0008',
        techniques: [{ id: 'T1021.002', name: 'SMB/Windows Admin Shares', desc: 'Move from initial VPN foothold to billing and operational planning systems.' }],
        timeline: '7-14 days', status: 'lateral', icon: 'fa-exchange-alt',
        indicators: ['SMB lateral movement', 'Pass-the-hash activity', 'Billing database access'] },
      { id: 'exfiltration', name: 'Data Exfiltration (Pre-Encryption)', tactic: 'TA0010',
        techniques: [{ id: 'T1048', name: 'Exfiltration Over Alternative Protocol', desc: '100GB of data exfiltrated before encryption for double extortion.' }],
        timeline: '14-18 days', status: 'exfil', icon: 'fa-cloud-upload-alt',
        indicators: ['Large outbound transfers', 'Data staged to Eastern European IP', 'Rclone or similar tool usage'] },
      { id: 'impact', name: 'DarkSide Ransomware + Operational Shutdown', tactic: 'TA0040',
        techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', desc: 'DarkSide encrypts IT network; Colonial PROACTIVELY shuts down OT pipeline.' }],
        timeline: '18-25 days', status: 'impact', icon: 'fa-exclamation-triangle',
        indicators: ['DarkSide ransom note', '5,500 miles of pipeline halted', 'National fuel shortage declaration'] },
    ],
    mitigations: [
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'MFA on ALL VPN accounts, no exceptions.' },
      { id: 'M1030', name: 'Network Segmentation', desc: 'Strict IT/OT air-gap; operational networks must not be reachable from compromised IT.' },
      { id: 'M1017', name: 'User Training', desc: 'Dark web credential monitoring and immediate password reset programs.' },
    ],
    detectionRules: ['VPN auth anomalies (new country, off-hours)', 'SMB lateral movement from VPN segment', 'Rclone data exfiltration', 'DarkSide ransomware signatures'],
    cvssEquivalent: 9.8,
    references: ['https://attack.mitre.org/software/S0603/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 14: ALPHV/BlackCat — Triple Extortion Healthcare
  // ══════════════════════════════════════════════════════════════
  {
    id: 'blackcat-healthcare',
    name: 'ALPHV/BlackCat — Triple Extortion Healthcare Attack',
    actor: 'ALPHV / BlackCat (Ransomware-as-a-Service)',
    actorCountry: 'Russia (RaaS affiliate)',
    difficulty: 'HIGH',
    industry: 'Healthcare / Hospitals / Patient Data',
    duration: '1-3 weeks',
    description: 'ALPHV Rust-based ransomware targeting a hospital network: AD compromise, data exfiltration of patient records, triple extortion (ransom + data leak + DDoS).',
    icon: 'fa-hospital',
    iconColor: '#22c55e',
    phases: [
      { id: 'initial-access', name: 'Exploit VPN/RDP', tactic: 'TA0001',
        techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'Exploit Citrix ADC (CVE-2023-3519) or RDP brute-force hospital gateway.' }],
        timeline: '0h', status: 'entry', icon: 'fa-door-open',
        indicators: ['Citrix ADC exploit attempts', 'RDP brute-force on hospital VPN', 'Initial beacon from healthcare subnet'] },
      { id: 'credential-access', name: 'Active Directory Compromise', tactic: 'TA0006',
        techniques: [{ id: 'T1003.003', name: 'NTDS', desc: 'Dump Active Directory NTDS.dit for all domain credentials.' }, { id: 'T1558.003', name: 'Kerberoasting', desc: 'Request TGS tickets for service accounts to crack offline.' }],
        timeline: '1-5 days', status: 'cred', icon: 'fa-key',
        indicators: ['ntdsutil AD dump', 'Kerberoasting: abnormal TGS requests', 'Domain admin access from workstation'] },
      { id: 'collection', name: 'Patient Record Exfiltration', tactic: 'TA0009',
        techniques: [{ id: 'T1005', name: 'Data from Local System', desc: 'Collect EMR databases (Epic, Cerner), patient PII, billing records, research data.' }],
        timeline: '5-12 days', status: 'collect', icon: 'fa-file-medical',
        indicators: ['EMR database export activity', 'Mass patient record access outside business hours', 'HL7/FHIR bulk export'] },
      { id: 'impact', name: 'ALPHV Triple Extortion', tactic: 'TA0040',
        techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', desc: 'Rust-based ALPHV encrypts files across all hospital systems.' }, { id: 'T1498', name: 'Network Denial of Service', desc: 'DDoS threat adds third extortion vector on top of ransom and data leak.' }],
        timeline: '12-20 days', status: 'impact', icon: 'fa-skull',
        indicators: ['.alphv extension', 'Ransom note: RECOVER-XXXXXXXX-FILES.txt', 'Patient care disruption, systems offline'] },
    ],
    mitigations: [
      { id: 'M1032', name: 'Multi-factor Authentication', desc: 'Enforce MFA on Citrix, RDP, and VPN.' },
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Separate NTDS backup accounts from regular operations.' },
      { id: 'M1053', name: 'Data Backup', desc: 'Maintain air-gapped EMR backups; test quarterly.' },
    ],
    detectionRules: ['ALPHV Rust encryptor signatures', 'NTDS.dit dump via ntdsutil', 'Kerberoasting: unusual TGS volume', 'EMR bulk export outside hours'],
    cvssEquivalent: 9.5,
    references: ['https://attack.mitre.org/software/S1068/', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a'],
  },
  // ══════════════════════════════════════════════════════════════
  //  SCENARIO 15: Storm-0558 — Microsoft Cloud Token Forgery
  // ══════════════════════════════════════════════════════════════
  {
    id: 'storm-0558-cloud-token',
    name: 'Storm-0558 — Cloud Token Forgery & Government Email Access',
    actor: 'Storm-0558 (China-nexus)',
    actorCountry: 'China',
    difficulty: 'CRITICAL',
    industry: 'Government / Diplomatic / Cloud Services',
    duration: '1 month (undetected access)',
    description: 'Reproduce the 2023 Storm-0558 breach: forge Azure AD authentication tokens using stolen MSA signing key to access US government Exchange Online mailboxes.',
    icon: 'fa-envelope-square',
    iconColor: '#3b82f6',
    phases: [
      { id: 'initial-access', name: 'MSA Signing Key Theft', tactic: 'TA0001',
        techniques: [{ id: 'T1649', name: 'Steal or Forge Authentication Certificates', desc: 'Obtain Microsoft consumer MSA signing key from 2021 crash dump exposed in engineering environment.' }],
        timeline: '0h (key already obtained)', status: 'cred', icon: 'fa-certificate',
        indicators: ['Signing key in crash dump artifact', 'Engineer account compromise', 'Key material extracted from memory'] },
      { id: 'execution', name: 'Token Forgery', tactic: 'TA0006',
        techniques: [{ id: 'T1553.006', name: 'Code Signing', desc: 'Forge Azure AD access tokens for any cloud identity using stolen MSA signing key.' }],
        timeline: '0-1 hour', status: 'exec', icon: 'fa-code',
        indicators: ['Tokens signed with consumer MSA key (wrong key type)', 'aud claim mismatch', 'Cross-tenant token usage'] },
      { id: 'collection', name: 'Exchange Online Email Access', tactic: 'TA0009',
        techniques: [{ id: 'T1114.002', name: 'Remote Email Collection', desc: 'Access 25 US government agency Exchange Online mailboxes via Outlook Web Access API.' }],
        timeline: '1-30 days', status: 'collect', icon: 'fa-envelope',
        indicators: ['OWA/EWS API calls with forged tokens', 'Email search by keyword (policy, diplomacy)', 'Mass download State Dept / Commerce mailboxes'] },
      { id: 'discovery', name: 'Lateral Cloud Discovery', tactic: 'TA0007',
        techniques: [{ id: 'T1087.004', name: 'Cloud Account Discovery', desc: 'Enumerate other users, groups, and applications accessible via forged tokens.' }],
        timeline: '1-30 days', status: 'recon', icon: 'fa-cloud',
        indicators: ['MS Graph API enumeration', 'Directory user listing', 'SharePoint site enumeration'] },
    ],
    mitigations: [
      { id: 'M1026', name: 'Privileged Account Management', desc: 'Strict separation of consumer and enterprise signing key environments.' },
      { id: 'M1047', name: 'Audit', desc: 'Monitor token claims for key type mismatches.' },
      { id: 'M1051', name: 'Update Software', desc: 'Rotate signing keys; implement key usage logging.' },
    ],
    detectionRules: ['Token signed by consumer MSA key used in enterprise context', 'Anomalous OWA API access patterns', 'Cross-tenant Graph API calls', 'Unusual Exchange audit logs from diplomatic accounts'],
    cvssEquivalent: 9.1,
    references: ['https://msrc.microsoft.com/blog/2023/07/msft-response-to-storm-0558/', 'https://attack.mitre.org/groups/G1013/'],
  },
];
let _advSimState = {
  activeScenario: null,
  activePhase: null,
  simulating: false,
  results: null,
  sessions: [],
};

/* ════════════════════════════════════════════════════════════════
   DIFFICULTY BADGE
════════════════════════════════════════════════════════════════ */
function advDiffColor(d) {
  return { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e' }[d] || '#6b7280';
}
function advDiffBadge(d) {
  const c = advDiffColor(d);
  return `<span style="background:${c}20;color:${c};border:1px solid ${c}40;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:800;text-transform:uppercase;">${d}</span>`;
}
function phaseStatusIcon(status) {
  const map = { entry: '🎯', dormant: '⏳', evasion: '🥷', recon: '🔍', lateral: '↔️', collection: '📁', exfil: '☁️', persist: '⚓', privesc: '⬆️', cred: '🔑', impact: '💥', phish: '📧', exec: '⚡', collect: '🗂️' };
  return map[status] || '•';
}

/* ════════════════════════════════════════════════════════════════
   MAIN RENDER
════════════════════════════════════════════════════════════════ */
window.renderAdversarySimLab = function() {
  const el = document.getElementById('page-adversary-sim');
  if (!el) return;

  el.innerHTML = `
  <div style="padding:0;background:#0a0e17;min-height:100vh;font-family:'Inter',sans-serif;">

    <!-- ── Header ── -->
    <div style="background:linear-gradient(135deg,#0f0a1e 0%,#1a0a2e 50%,#0a1628 100%);border-bottom:1px solid #1e293b;padding:24px 28px 20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
        <div style="display:flex;align-items:center;gap:14px;">
          <div style="width:52px;height:52px;background:linear-gradient(135deg,#7c3aed,#a855f7);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(168,85,247,.3);">
            <i class="fas fa-user-ninja" style="color:#fff;font-size:22px;"></i>
          </div>
          <div>
            <h1 style="margin:0;font-size:1.5rem;font-weight:800;color:#f1f5f9;">Adversary Simulation Lab</h1>
            <div style="font-size:12px;color:#64748b;margin-top:3px;">
              <i class="fas fa-brain" style="color:#a855f7;margin-right:4px;"></i>
              MITRE ATT&CK-based · Real attack chains · Interactive scenario engine
            </div>
          </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;">
          <div style="background:#0a0e17;border:1px solid #1e293b;padding:8px 14px;border-radius:8px;font-size:12px;color:#64748b;">
            <i class="fas fa-shield-alt" style="color:#22c55e;margin-right:5px;"></i>${ADVERSARY_SCENARIOS.length} Scenarios Available
          </div>
          <button onclick="advSimShowHistory()" style="background:#0f172a;border:1px solid #1e293b;color:#94a3b8;padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer;">
            <i class="fas fa-history"></i> History
          </button>
        </div>
      </div>

      <!-- ── Stats ── -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:18px;">
        ${[
          { label: 'Total Scenarios', value: ADVERSARY_SCENARIOS.length, color: '#a855f7' },
          { label: 'Nation-State APTs', value: ADVERSARY_SCENARIOS.filter(s=>!['International (RaaS)','Eastern Europe','US/UK (Cybercriminal)'].includes(s.actorCountry)).length, color: '#ef4444' },
          { label: 'Ransomware/FIN Crime', value: ADVERSARY_SCENARIOS.filter(s=>s.id.includes('lockbit')||s.id.includes('clop')||s.id.includes('revil')||s.id.includes('darkside')||s.id.includes('blackcat')||s.id.includes('fin7')||s.id.includes('scattered')).length, color: '#f97316' },
          { label: 'MITRE Tactics', value: '14', color: '#22d3ee' },
          { label: 'Techniques Mapped', value: '50+', color: '#22c55e' },
        ].map(s => `
        <div style="background:rgba(15,23,42,.7);border:1px solid #1e293b;border-radius:8px;padding:12px 14px;">
          <div style="font-size:10px;color:#475569;font-weight:700;text-transform:uppercase;letter-spacing:.5px;">${s.label}</div>
          <div style="font-size:1.6rem;font-weight:800;color:${s.color};margin-top:4px;">${s.value}</div>
        </div>`).join('')}
      </div>
    </div>

    <!-- ── Content ── -->
    <div style="padding:24px 28px;">
      <div id="advsim-main-content">
        ${renderScenarioCards()}
      </div>
    </div>
  </div>`;

  loadAdvSimHistory();
};

/* ── Scenario Cards Grid ── */
function renderScenarioCards(filterText) {
  const filtered = filterText
    ? ADVERSARY_SCENARIOS.filter(s =>
        s.name.toLowerCase().includes(filterText.toLowerCase()) ||
        s.actor.toLowerCase().includes(filterText.toLowerCase()) ||
        s.industry.toLowerCase().includes(filterText.toLowerCase()) ||
        s.actorCountry.toLowerCase().includes(filterText.toLowerCase()) ||
        s.difficulty.toLowerCase() === filterText.toLowerCase()
      )
    : ADVERSARY_SCENARIOS;

  return `
  <div style="margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <div>
      <h2 style="margin:0 0 4px;font-size:1.1rem;font-weight:700;color:#e2e8f0;">
        <i class="fas fa-th-large" style="color:#a855f7;margin-right:8px;"></i>Select Attack Scenario
      </h2>
      <p style="margin:0;font-size:12px;color:#475569;">
        ${filtered.length} of ${ADVERSARY_SCENARIOS.length} scenarios · Click any card to view full kill chain and launch simulation
      </p>
    </div>
    <!-- Search & filter -->
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      <div style="position:relative;">
        <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#475569;font-size:12px;"></i>
        <input id="advsim-search" type="text" placeholder="Search scenarios…" value="${filterText||''}"
          style="background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:8px 10px 8px 30px;border-radius:8px;font-size:12px;outline:none;width:200px;"
          oninput="advSimFilterScenarios(this.value)" />
      </div>
      ${['CRITICAL','HIGH','MEDIUM'].map(d => `
        <button onclick="advSimFilterScenarios('${d}')"
          style="background:${advDiffColor(d)}20;color:${advDiffColor(d)};border:1px solid ${advDiffColor(d)}40;padding:6px 10px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;">
          ${d}
        </button>`).join('')}
      <button onclick="advSimFilterScenarios('')"
        style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:6px 10px;border-radius:8px;font-size:11px;cursor:pointer;">
        All
      </button>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:20px;">
    ${filtered.length === 0 ? `
    <div style="grid-column:1/-1;padding:40px;text-align:center;color:#475569;">
      <i class="fas fa-search" style="font-size:2rem;margin-bottom:12px;display:block;opacity:.4;"></i>
      No scenarios match "<em style="color:#64748b">${filterText}</em>"
    </div>` : filtered.map(s => `
    <div onclick="advSimOpenScenario('${s.id}')"
      style="background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:22px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden;"
      onmouseover="this.style.borderColor='${advDiffColor(s.difficulty)}60';this.style.transform='translateY(-2px)';this.style.boxShadow='0 8px 24px rgba(0,0,0,.4)'"
      onmouseout="this.style.borderColor='#1e293b';this.style.transform='translateY(0)';this.style.boxShadow='none'">
      <!-- Accent line -->
      <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,${advDiffColor(s.difficulty)},${advDiffColor(s.difficulty)}60);"></div>
      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;">
        <div style="width:44px;height:44px;background:${advDiffColor(s.difficulty)}20;border-radius:10px;display:flex;align-items:center;justify-content:center;border:1px solid ${advDiffColor(s.difficulty)}30;">
          <i class="fas ${s.icon}" style="color:${s.iconColor};font-size:18px;"></i>
        </div>
        ${advDiffBadge(s.difficulty)}
      </div>
      <!-- Name & actor -->
      <div style="font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:4px;line-height:1.3;">${s.name}</div>
      <div style="font-size:12px;color:#64748b;margin-bottom:12px;display:flex;align-items:center;gap:6px;">
        <i class="fas fa-flag" style="color:#ef4444;font-size:9px;"></i>
        <span>${s.actor}</span>
        <span style="color:#334155;">·</span>
        <span style="background:#1e293b;color:#94a3b8;padding:1px 6px;border-radius:4px;font-size:10px;">${s.actorCountry}</span>
      </div>
      <!-- Description -->
      <div style="font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:14px;max-height:54px;overflow:hidden;">${s.description}</div>
      <!-- Tags -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">
        <span style="background:#1e293b;color:#64748b;padding:3px 8px;border-radius:6px;font-size:10px;">
          <i class="fas fa-industry" style="margin-right:3px;"></i>${s.industry}
        </span>
        <span style="background:#1e293b;color:#64748b;padding:3px 8px;border-radius:6px;font-size:10px;">
          <i class="fas fa-clock" style="margin-right:3px;"></i>${s.duration}
        </span>
        <span style="background:#1e293b;color:#64748b;padding:3px 8px;border-radius:6px;font-size:10px;">
          <i class="fas fa-layer-group" style="margin-right:3px;"></i>${s.phases.length} phases
        </span>
        <span style="background:${s.cvssEquivalent >= 9.5 ? 'rgba(239,68,68,.2)' : 'rgba(249,115,22,.2)'};color:${s.cvssEquivalent >= 9.5 ? '#ef4444' : '#f97316'};padding:3px 8px;border-radius:6px;font-size:10px;font-weight:700;">
          CVSS ${s.cvssEquivalent}
        </span>
      </div>
      <!-- Kill chain preview -->
      <div style="display:flex;align-items:center;gap:4px;overflow-x:auto;padding-bottom:2px;">
        ${s.phases.map((p, i) => `
        <div style="display:flex;align-items:center;gap:3px;">
          ${i > 0 ? `<i class="fas fa-chevron-right" style="color:#1e293b;font-size:8px;"></i>` : ''}
          <span title="${p.name}: ${p.tactic}" style="background:#1e293b;color:#64748b;padding:3px 6px;border-radius:4px;font-size:9px;white-space:nowrap;">${phaseStatusIcon(p.status)}</span>
        </div>`).join('')}
      </div>
      <!-- CTA -->
      <div style="margin-top:16px;display:flex;justify-content:flex-end;">
        <span style="background:${advDiffColor(s.difficulty)}20;color:${advDiffColor(s.difficulty)};border:1px solid ${advDiffColor(s.difficulty)}30;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;">
          <i class="fas fa-play" style="margin-right:5px;"></i>Simulate
        </span>
      </div>
    </div>`).join('')}
  </div>`;
}

/* Filter scenarios by text */
window.advSimFilterScenarios = function(text) {
  const content = document.getElementById('advsim-main-content');
  if (!content) return;
  // Only re-render the cards grid portion
  content.innerHTML = renderScenarioCards(text);
  // If text was typed, also update the search box value
  const srch = document.getElementById('advsim-search');
  if (srch && srch.value !== text) srch.value = text;
};

/* ════════════════════════════════════════════════════════════════
   SCENARIO DETAIL VIEW
════════════════════════════════════════════════════════════════ */
window.advSimOpenScenario = function(scenarioId) {
  const s = ADVERSARY_SCENARIOS.find(sc => sc.id === scenarioId);
  if (!s) return;
  _advSimState.activeScenario = s;
  _advSimState.activePhase = null;
  _advSimState.results = null;

  const content = document.getElementById('advsim-main-content');
  if (!content) return;

  content.innerHTML = `
  <!-- Back -->
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
    <button onclick="renderAdversarySimLab()"
      style="background:#0f172a;border:1px solid #1e293b;color:#94a3b8;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px;">
      <i class="fas fa-arrow-left"></i> Back to Scenarios
    </button>
    <span style="color:#475569;font-size:13px;">/ ${s.name}</span>
  </div>

  <!-- Scenario header -->
  <div style="background:linear-gradient(135deg,#0f172a,#1a0a2e);border:1px solid #1e293b;border-radius:14px;padding:24px 28px;margin-bottom:24px;position:relative;overflow:hidden;">
    <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,${advDiffColor(s.difficulty)},transparent);"></div>
    <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start;">
      <div style="width:60px;height:60px;background:${advDiffColor(s.difficulty)}20;border-radius:14px;display:flex;align-items:center;justify-content:center;border:1px solid ${advDiffColor(s.difficulty)}40;flex-shrink:0;">
        <i class="fas ${s.icon}" style="color:${s.iconColor};font-size:24px;"></i>
      </div>
      <div style="flex:1;">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
          <h2 style="margin:0;font-size:1.3rem;font-weight:800;color:#f1f5f9;">${s.name}</h2>
          ${advDiffBadge(s.difficulty)}
        </div>
        <div style="font-size:13px;color:#a855f7;margin-bottom:10px;font-weight:600;">
          <i class="fas fa-user-secret" style="margin-right:5px;"></i>${s.actor} · ${s.actorCountry}
        </div>
        <p style="margin:0 0 14px;font-size:13px;color:#94a3b8;line-height:1.6;">${s.description}</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <span style="background:#1e293b;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;"><i class="fas fa-industry" style="margin-right:4px;"></i>${s.industry}</span>
          <span style="background:#1e293b;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;"><i class="fas fa-clock" style="margin-right:4px;"></i>${s.duration}</span>
          <span style="background:#1e293b;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;"><i class="fas fa-chart-line" style="margin-right:4px;"></i>CVSS Equiv: ${s.cvssEquivalent}</span>
        </div>
      </div>
      <div>
        <button onclick="advSimRunScenario('${s.id}')" id="advsim-run-btn"
          style="background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;border:none;padding:12px 24px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px;box-shadow:0 4px 16px rgba(168,85,247,.3);">
          <i class="fas fa-play-circle" style="font-size:16px;"></i> Run Simulation
        </button>
      </div>
    </div>
  </div>

  <!-- Kill Chain Visualization -->
  <div style="background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:24px;margin-bottom:24px;">
    <h3 style="margin:0 0 20px;font-size:1rem;font-weight:700;color:#e2e8f0;">
      <i class="fas fa-sitemap" style="color:#22d3ee;margin-right:8px;"></i>Attack Kill Chain
    </h3>
    <!-- Chain visualization -->
    <div style="display:flex;gap:0;overflow-x:auto;padding-bottom:12px;" id="advsim-chain">
      ${s.phases.map((phase, idx) => `
      <div style="flex:0 0 auto;display:flex;align-items:flex-start;gap:0;">
        ${idx > 0 ? `<div style="width:30px;height:2px;background:linear-gradient(90deg,#1e3a5f,#3b82f6);margin-top:32px;flex-shrink:0;"></div>` : ''}
        <div id="phase-card-${idx}" onclick="advSimSelectPhase(${idx})"
          style="width:170px;background:#090d14;border:1px solid #1e293b;border-radius:10px;padding:14px;cursor:pointer;transition:all .2s;"
          onmouseover="this.style.borderColor='${advDiffColor(s.difficulty)}60'"
          onmouseout="this.style.borderColor='#1e293b'">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <div style="width:30px;height:30px;background:${advDiffColor(s.difficulty)}15;border-radius:8px;display:flex;align-items:center;justify-content:center;border:1px solid ${advDiffColor(s.difficulty)}30;font-size:14px;">
              ${phaseStatusIcon(phase.status)}
            </div>
            <div>
              <div style="font-size:8px;color:#475569;font-weight:700;text-transform:uppercase;">${phase.tactic}</div>
            </div>
          </div>
          <div style="font-size:12px;font-weight:700;color:#e2e8f0;margin-bottom:6px;line-height:1.3;">${phase.name}</div>
          <div style="font-size:10px;color:#475569;">${phase.timeline}</div>
          <div style="margin-top:8px;display:flex;flex-direction:column;gap:3px;">
            ${phase.techniques.map(t => `
            <div style="background:#1e293b;border-radius:4px;padding:3px 6px;">
              <span style="font-size:9px;font-family:monospace;color:#22d3ee;">${t.id}</span>
            </div>`).join('')}
          </div>
        </div>
      </div>`).join('')}
    </div>
  </div>

  <!-- Phase Detail (shown on click) -->
  <div id="advsim-phase-detail" style="display:none;background:#0f172a;border:1px solid #3b82f6;border-radius:14px;padding:24px;margin-bottom:24px;animation:fadeIn .3s ease;"></div>

  <!-- Simulation Results -->
  <div id="advsim-results" style="display:none;"></div>

  <!-- Mitigations & Detection -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:24px;">
    <!-- Mitigations -->
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:20px;">
      <h3 style="margin:0 0 16px;font-size:14px;font-weight:700;color:#e2e8f0;">
        <i class="fas fa-shield-alt" style="color:#22c55e;margin-right:8px;"></i>MITRE Mitigations
      </h3>
      <div style="display:flex;flex-direction:column;gap:10px;">
        ${s.mitigations.map(m => `
        <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px 14px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span style="font-family:monospace;font-size:11px;color:#22c55e;background:rgba(34,197,94,.1);padding:2px 6px;border-radius:4px;">${m.id}</span>
            <span style="font-size:13px;font-weight:600;color:#e2e8f0;">${m.name}</span>
          </div>
          <p style="margin:0;font-size:12px;color:#94a3b8;">${m.desc}</p>
        </div>`).join('')}
      </div>
    </div>
    <!-- Detection Rules -->
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:20px;">
      <h3 style="margin:0 0 16px;font-size:14px;font-weight:700;color:#e2e8f0;">
        <i class="fas fa-broadcast-tower" style="color:#22d3ee;margin-right:8px;"></i>Detection Signatures
      </h3>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${s.detectionRules.map(rule => `
        <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:10px 14px;display:flex;align-items:flex-start;gap:10px;">
          <i class="fas fa-search" style="color:#22d3ee;margin-top:2px;font-size:12px;flex-shrink:0;"></i>
          <span style="font-size:12px;color:#cbd5e1;font-family:monospace;">${rule}</span>
        </div>`).join('')}
      </div>
      <div style="margin-top:14px;">
        <a href="https://attack.mitre.org/groups/" target="_blank" rel="noopener"
          style="color:#22d3ee;font-size:12px;text-decoration:none;display:inline-flex;align-items:center;gap:5px;">
          <i class="fas fa-external-link-alt"></i> View on MITRE ATT&CK
        </a>
      </div>
    </div>
  </div>`;
};

/* ── Phase Detail ── */
window.advSimSelectPhase = function(idx) {
  const s = _advSimState.activeScenario;
  if (!s) return;
  const phase = s.phases[idx];
  const detail = document.getElementById('advsim-phase-detail');
  if (!detail) return;

  // Highlight selected card
  s.phases.forEach((_, i) => {
    const card = document.getElementById(`phase-card-${i}`);
    if (card) card.style.borderColor = i === idx ? advDiffColor(s.difficulty) : '#1e293b';
  });

  detail.style.display = 'block';
  detail.innerHTML = `
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
    <div>
      <div style="font-size:10px;color:#3b82f6;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">
        Phase ${idx + 1} · ${phase.tactic}
      </div>
      <h3 style="margin:0;font-size:1.1rem;font-weight:800;color:#f1f5f9;">${phaseStatusIcon(phase.status)} ${phase.name}</h3>
    </div>
    <span style="background:#1e293b;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;">Timeline: ${phase.timeline}</span>
  </div>
  <!-- Techniques -->
  <div style="display:flex;flex-direction:column;gap:12px;margin-bottom:16px;">
    ${phase.techniques.map(t => `
    <div style="background:#090d14;border:1px solid #1e293b;border-radius:10px;padding:14px 16px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <a href="https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/" target="_blank" rel="noopener"
          style="font-family:monospace;font-size:12px;color:#22d3ee;background:rgba(34,211,238,.1);padding:3px 8px;border-radius:4px;text-decoration:none;">${t.id}</a>
        <span style="font-size:14px;font-weight:700;color:#e2e8f0;">${t.name}</span>
      </div>
      <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.6;">${t.desc}</p>
    </div>`).join('')}
  </div>
  <!-- IoCs -->
  <div>
    <div style="font-size:11px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:8px;">Indicators of Compromise</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;">
      ${phase.indicators.map(ioc => `
      <span style="background:#1e293b;color:#f97316;font-family:monospace;font-size:11px;padding:4px 10px;border-radius:6px;border:1px solid #2d3748;">${ioc}</span>`).join('')}
    </div>
  </div>`;
};

/* ── Run Simulation ── */
window.advSimRunScenario = async function(scenarioId) {
  const s = ADVERSARY_SCENARIOS.find(sc => sc.id === scenarioId);
  if (!s || _advSimState.simulating) return;
  _advSimState.simulating = true;

  const btn = document.getElementById('advsim-run-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating…'; }

  const resultsEl = document.getElementById('advsim-results');
  if (resultsEl) {
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
    <div style="background:#0f172a;border:1px solid #a855f7;border-radius:14px;padding:28px;animation:fadeIn .3s;">
      <div style="text-align:center;padding:20px;">
        <div style="font-size:1rem;font-weight:700;color:#a855f7;margin-bottom:12px;">
          <i class="fas fa-spinner fa-spin" style="margin-right:8px;"></i>Running Attack Simulation…
        </div>
        <div style="font-size:12px;color:#64748b;">Executing ${s.phases.length} attack phases against target environment</div>
        <div id="advsim-progress-bar" style="background:#1e293b;border-radius:8px;height:6px;margin-top:16px;overflow:hidden;">
          <div id="advsim-progress-fill" style="background:linear-gradient(90deg,#7c3aed,#a855f7);height:100%;width:0%;transition:width .5s;border-radius:8px;"></div>
        </div>
        <div id="advsim-progress-text" style="font-size:11px;color:#475569;margin-top:8px;">Phase 0/${s.phases.length}</div>
      </div>
    </div>`;
  }

  // Animate through phases
  for (let i = 0; i < s.phases.length; i++) {
    await new Promise(r => setTimeout(r, 600 + Math.random() * 400));
    const pct = Math.round(((i + 1) / s.phases.length) * 100);
    const fill = document.getElementById('advsim-progress-fill');
    const txt  = document.getElementById('advsim-progress-text');
    if (fill) fill.style.width = pct + '%';
    if (txt) txt.textContent = `Phase ${i + 1}/${s.phases.length}: ${s.phases[i].name}`;
  }

  await new Promise(r => setTimeout(r, 500));

  // Generate results
  const detected    = Math.floor(Math.random() * s.phases.length);
  const undetected  = s.phases.length - detected;
  const riskReduction = Math.round(30 + Math.random() * 50);
  const dwellTime   = Math.floor(7 + Math.random() * 180);

  _advSimState.results = {
    scenarioId,
    phasesTotal: s.phases.length,
    phasesDetected: detected,
    phasesUndetected: undetected,
    detectionRate: Math.round((detected / s.phases.length) * 100),
    riskScore: Math.round(s.cvssEquivalent * 10 * (1 - detected / s.phases.length)),
    dwellTimeDays: dwellTime,
    criticalGaps: s.phases.slice(0, undetected).map(p => p.name),
    recommendations: s.mitigations,
    timestamp: new Date().toISOString(),
  };

  // Save to backend
  try {
    await (window.apiPost || (() => Promise.resolve()))('/api/adversary-sim/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scenario_id: scenarioId,
        scenario_name: s.name,
        threat_actor: s.actor,
        mitre_tactics: s.phases.map(p => p.tactic),
        status: 'completed',
        outcome: detected >= s.phases.length * 0.6 ? 'success' : 'partial',
        results: _advSimState.results,
      }),
    });
  } catch (e) { /* Non-blocking */ }

  // Show results
  if (resultsEl) {
    resultsEl.innerHTML = renderSimResults(_advSimState.results, s);
  }
  if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-redo"></i> Run Again'; }
  _advSimState.simulating = false;
};

function renderSimResults(r, s) {
  const rateColor = r.detectionRate >= 80 ? '#22c55e' : r.detectionRate >= 50 ? '#f59e0b' : '#ef4444';
  return `
  <div style="background:#0f172a;border:1px solid ${rateColor}40;border-radius:14px;padding:28px;animation:fadeIn .3s;">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
      <div style="width:48px;height:48px;background:${rateColor}20;border-radius:12px;display:flex;align-items:center;justify-content:center;border:1px solid ${rateColor}40;">
        <i class="fas fa-${r.detectionRate>=70?'check-circle text-green':'exclamation-triangle'}" style="color:${rateColor};font-size:20px;"></i>
      </div>
      <div>
        <h3 style="margin:0;font-size:1.1rem;font-weight:800;color:#f1f5f9;">Simulation Complete</h3>
        <div style="font-size:12px;color:#64748b;">${s.name}</div>
      </div>
      <div style="margin-left:auto;text-align:right;">
        <div style="font-size:2rem;font-weight:800;color:${rateColor};">${r.detectionRate}%</div>
        <div style="font-size:11px;color:#64748b;">Detection Rate</div>
      </div>
    </div>

    <!-- Metrics grid -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px;">
      ${[
        { label: 'Phases Detected', value: `${r.phasesDetected}/${r.phasesTotal}`, color: '#22c55e' },
        { label: 'Undetected Phases', value: r.phasesUndetected, color: '#ef4444' },
        { label: 'Est. Dwell Time', value: `${r.dwellTimeDays} days`, color: '#f97316' },
        { label: 'Risk Score', value: r.riskScore, color: rateColor },
      ].map(m => `
      <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:14px;">
        <div style="font-size:10px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:6px;">${m.label}</div>
        <div style="font-size:1.4rem;font-weight:800;color:${m.color};">${m.value}</div>
      </div>`).join('')}
    </div>

    <!-- Critical Gaps -->
    ${r.criticalGaps.length > 0 ? `
    <div style="background:#090d14;border:1px solid #ef444440;border-radius:10px;padding:16px 18px;margin-bottom:16px;">
      <div style="font-size:11px;color:#ef4444;font-weight:700;text-transform:uppercase;margin-bottom:10px;">
        <i class="fas fa-exclamation-circle" style="margin-right:5px;"></i>Detection Gaps (${r.criticalGaps.length} undetected phases)
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;">
        ${r.criticalGaps.map(gap => `<span style="background:#1e293b;color:#f87171;font-size:12px;padding:4px 10px;border-radius:6px;">${gap}</span>`).join('')}
      </div>
    </div>` : ''}

    <!-- Recommendations -->
    <div>
      <div style="font-size:11px;color:#22c55e;font-weight:700;text-transform:uppercase;margin-bottom:10px;">
        <i class="fas fa-shield-alt" style="margin-right:5px;"></i>Priority Remediations
      </div>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${r.recommendations.slice(0, 4).map((rec, i) => `
        <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:10px 14px;display:flex;gap:10px;align-items:flex-start;">
          <span style="background:#22c55e20;color:#22c55e;font-weight:800;font-size:11px;padding:2px 7px;border-radius:4px;flex-shrink:0;">${i + 1}</span>
          <div>
            <div style="font-size:13px;font-weight:600;color:#e2e8f0;">${rec.name}</div>
            <div style="font-size:11px;color:#64748b;margin-top:2px;">${rec.desc}</div>
          </div>
        </div>`).join('')}
      </div>
    </div>

    <!-- Export -->
    <div style="display:flex;gap:10px;margin-top:18px;flex-wrap:wrap;">
      <button onclick="advSimExportResults()"
        style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:6px;">
        <i class="fas fa-download"></i> Export Report
      </button>
      <button onclick="advSimRunScenario('${s.id}')"
        style="background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;border:none;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;">
        <i class="fas fa-redo"></i> Re-run Simulation
      </button>
    </div>
  </div>`;
}

window.advSimExportResults = function() {
  const r = _advSimState.results;
  const s = _advSimState.activeScenario;
  if (!r || !s) return;
  const txt = `Adversary Simulation Report\n========================\nScenario: ${s.name}\nActor: ${s.actor}\nDate: ${new Date().toISOString()}\n\nDetection Rate: ${r.detectionRate}%\nDwell Time: ${r.dwellTimeDays} days\nUndetected Phases: ${r.criticalGaps.join(', ')}\n\nRecommendations:\n${r.recommendations.map((r,i)=>`${i+1}. ${r.name}: ${r.desc}`).join('\n')}`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain' }));
  a.download = `advsim-${s.id}-${Date.now()}.txt`;
  a.click();
};

window.advSimShowHistory = function() {
  // Placeholder — will load from /api/adversary-sim/sessions
  const content = document.getElementById('advsim-main-content');
  if (!content) return;
  content.innerHTML = `
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
    <button onclick="renderAdversarySimLab()"
      style="background:#0f172a;border:1px solid #1e293b;color:#94a3b8;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px;">
      <i class="fas fa-arrow-left"></i> Back
    </button>
    <span style="font-size:15px;font-weight:700;color:#e2e8f0;">Simulation History</span>
  </div>
  <div id="advsim-history-list" style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px;">
    <div style="text-align:center;color:#475569;padding:40px;">
      <i class="fas fa-spinner fa-spin" style="font-size:1.5rem;margin-bottom:10px;display:block;"></i>
      Loading sessions…
    </div>
  </div>`;
  loadAdvSimHistory(true);
};

async function loadAdvSimHistory(showInUI = false) {
  try {
    const data = await (window.apiGet?.('/api/adversary-sim/sessions') || Promise.resolve({ sessions: [] }));
    _advSimState.sessions = data.sessions || [];
    if (showInUI) {
      const el = document.getElementById('advsim-history-list');
      if (!el) return;
      if (_advSimState.sessions.length === 0) {
        el.innerHTML = `<div style="text-align:center;color:#475569;padding:40px;"><i class="fas fa-history" style="font-size:2rem;margin-bottom:12px;display:block;opacity:.3;"></i>No simulations run yet. Select a scenario and click "Run Simulation".</div>`;
      } else {
        el.innerHTML = `<div style="display:flex;flex-direction:column;gap:10px;">${_advSimState.sessions.slice(0, 20).map(sess => `
        <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <div>
            <div style="font-size:14px;font-weight:600;color:#e2e8f0;">${sess.scenario_name}</div>
            <div style="font-size:11px;color:#475569;margin-top:3px;">${sess.threat_actor} · ${new Date(sess.created_at).toLocaleString()}</div>
          </div>
          <span style="background:${sess.outcome==='success'?'rgba(34,197,94,.2)':'rgba(245,158,11,.2)'};color:${sess.outcome==='success'?'#22c55e':'#f59e0b'};padding:3px 10px;border-radius:8px;font-size:11px;font-weight:700;">${sess.outcome || sess.status}</span>
        </div>`).join('')}</div>`;
      }
    }
  } catch (e) { /* Non-blocking */ }
}
