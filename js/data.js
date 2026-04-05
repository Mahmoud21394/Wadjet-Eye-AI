/* ══════════════════════════════════════════════════════════
   ThreatPilot AI — Mock Data Layer
   All realistic threat intelligence data for demo
   ══════════════════════════════════════════════════════════ */

const ARGUS_DATA = {

  /* ─────────────────────────── FINDINGS ─────────────────────────── */
  findings: [
    { id:'F001', severity:'CRITICAL', type:'API Key', value:'AIzaSyD-REDACTED-8xK9mN3pQ', source:'GitHub Gist', customer:'HackerOne', score:96, mitre:'T1552.001', time:'2m ago', customer_id:'hackerone', matched:'github_api_key', feeds:['GitHub Gist','grep.app'], confidence:99, description:'Google API key exposed in public GitHub Gist. Key has Maps API and Cloud billing access.', evidence:[{src:'github_gist',detail:'Raw gist content matched google_api_key regex at offset 142'},{src:'google_keytest',detail:'Key validated – Maps API access confirmed (HTTP 200)'},{src:'virustotal',detail:'Associated repo has 3 malicious detections'}]},
    { id:'F002', severity:'CRITICAL', type:'Credential', value:'admin:P@ssw0rd123! → corp-vpn.hackerone.com', source:'HudsonRock', customer:'HackerOne', score:94, mitre:'T1078.002', time:'5m ago', customer_id:'hackerone', matched:'stolen_credentials', feeds:['HudsonRock'], confidence:97, description:'Infostealer-exfiltrated VPN credential found in HudsonRock corpus. Breach date: 3 days ago.', evidence:[{src:'hudsonrock',detail:'Match in Redline stealer dump, timestamp 2024-12-14'},{src:'abuseipdb',detail:'VPN IP 203.0.113.45 has 47 abuse reports'},{src:'shodan',detail:'Port 1194/udp open, OpenVPN 2.5.x detected'}]},
    { id:'F003', severity:'CRITICAL', type:'CVE', value:'CVE-2024-3400 (CVSS 10.0)', source:'NVD + CISA KEV', customer:'Bugcrowd', score:100, mitre:'T1190', time:'8m ago', customer_id:'bugcrowd', matched:'critical_cve', feeds:['NVD','CISA KEV','EPSS'], confidence:100, description:'PAN-OS command injection vulnerability actively exploited. CISA KEV entry. EPSS: 97.3%.', evidence:[{src:'nvd',detail:'CVE-2024-3400: CVSS 10.0, PAN-OS GlobalProtect RCE'},{src:'cisa_kev',detail:'Added to KEV catalog 2024-04-12, due-date 2024-04-19'},{src:'epss',detail:'EPSS score 0.973 (97.3% exploitation probability)'},{src:'threatfox',detail:'12 C2 IPs attributed to exploitation campaigns'}]},
    { id:'F004', severity:'HIGH', type:'Domain', value:'maliciousupdate[.]ru', source:'URLhaus + PhishTank', customer:'Synack', score:88, mitre:'T1566.002', time:'12m ago', customer_id:'synack', matched:'malicious_domain', feeds:['URLhaus','PhishTank','OpenPhish'], confidence:92, description:'Typosquatting domain mimicking Windows Update. Active phishing campaign targeting enterprise users.', evidence:[{src:'urlhaus',detail:'Domain added to URLhaus 6 hours ago, category: malware_download'},{src:'phishtank',detail:'PhishTank ID 8423561, verified by 89 users'},{src:'whois',detail:'Registered 2024-12-10, registrar: Namecheap, privacy-protected'}]},
    { id:'F005', severity:'HIGH', type:'IP', value:'185.220.101.45', source:'Feodo + AbuseIPDB', customer:'Cobalt', score:85, mitre:'T1071.001', time:'15m ago', customer_id:'cobalt', matched:'malicious_ip', feeds:['Feodo','AbuseIPDB','ThreatFox'], confidence:89, description:'Known Tor exit node used as C2 proxy. Emotet botnet infrastructure confirmed.', evidence:[{src:'feodo',detail:'Listed in Feodo Tracker C2 blocklist since 2024-11-28'},{src:'abuseipdb',detail:'1,247 reports, confidence score 97%'},{src:'shodan',detail:'Port 443/tcp TLS fingerprint matches Cobalt Strike beacon'}]},
    { id:'F006', severity:'HIGH', type:'API Key', value:'sk-proj-REDACTED-T3BlbkFJ...', source:'grep.app', customer:'Intigriti', score:82, mitre:'T1552.001', time:'18m ago', customer_id:'intigriti', matched:'openai_api_key', feeds:['grep.app','Sourcegraph'], confidence:87, description:'OpenAI API key found in public code repository. Estimated $200+/month burn rate if exploited.', evidence:[{src:'grep_app',detail:'Found in Python script committed 14 hours ago'},{src:'openai_keytest',detail:'Key active – 3 models accessible including GPT-4'},{src:'github',detail:'Repository has 127 stars, public since 2023'}]},
    { id:'F007', severity:'HIGH', type:'Ransomware', value:'BlackCat (ALPHV) IOC cluster', source:'Ransomwatch + RansomFeed', customer:'YesWeHack', score:79, mitre:'T1486', time:'22m ago', customer_id:'yeswehack', matched:'ransomware_ioc', feeds:['Ransomwatch','RansomFeed','VX-Underground'], confidence:84, description:'New ALPHV ransomware sample and associated infrastructure detected. 3 targeted companies listed.', evidence:[{src:'ransomwatch',detail:'New listing on ALPHV dark web site: 3 victims added 2h ago'},{src:'malwarebazaar',detail:'Sample hash SHA256: a3f8d2... matches ALPHV encryptor v4.1'},{src:'threatfox',detail:'C2 domain exfilupload[.]onion tagged ALPHV'}]},
    { id:'F008', severity:'HIGH', type:'Credential', value:'ssh_private_key → dev@prod-api-server', source:'GitHub Secrets', customer:'HackerOne', score:76, mitre:'T1552.004', time:'31m ago', customer_id:'hackerone', matched:'ssh_private_key', feeds:['GitHub Secrets'], confidence:81, description:'RSA 4096-bit SSH private key committed to public repository. Production API server access.', evidence:[{src:'github_secrets',detail:'-----BEGIN RSA PRIVATE KEY----- found at line 23 of deploy.sh'},{src:'shodan',detail:'Host prod-api-server.io: SSH port 22 open, OpenSSH 8.2'},{src:'internal',detail:'Key fingerprint matches production deployment key in CMDB'}]},
    { id:'F009', severity:'MEDIUM', type:'Exposure', value:'Elasticsearch index exposed: 2.1M records', source:'Shodan InternetDB', customer:'Bugcrowd', score:68, mitre:'T1530', time:'45m ago', customer_id:'bugcrowd', matched:'exposed_database', feeds:['Shodan InternetDB'], confidence:76, description:'Unauthenticated Elasticsearch instance containing customer PII. GDPR reportable.', evidence:[{src:'shodan_internetdb',detail:'IP 198.51.100.42:9200 – no auth, 2.1M documents'},{src:'censys',detail:'First seen 2024-11-30, 14 days exposed'},{src:'curl_test',detail:'/_cat/indices returns customer_data index with email,ssn fields'}]},
    { id:'F010', severity:'MEDIUM', type:'URL', value:'http://cdn-update[.]net/flash_installer.exe', source:'URLhaus', customer:'Synack', score:65, mitre:'T1204.002', time:'1h ago', customer_id:'synack', matched:'malware_url', feeds:['URLhaus','MalwareBazaar'], confidence:72, description:'Malware delivery URL masquerading as Flash installer. Contains Raccoon Stealer v2.', evidence:[{src:'urlhaus',detail:'Status: online, tags: raccoon,stealer,exe'},{src:'malwarebazaar',detail:'Hash matches Raccoon Stealer 2.3.1, first seen 12h ago'},{src:'virustotal',detail:'41/71 AV detections'}]},
    { id:'F011', severity:'MEDIUM', type:'Certificate', value:'Wildcard cert: *.internal-corp[.]xyz', source:'crt.sh', customer:'Cobalt', score:61, mitre:'T1553.004', time:'2h ago', customer_id:'cobalt', matched:'suspicious_cert', feeds:['crt.sh'], confidence:68, description:'Suspicious wildcard TLS certificate issued for internal-sounding domain. Potential MITM infrastructure.', evidence:[{src:'crt_sh',detail:'cert logged 3h ago, Let\'s Encrypt, SAN: *.internal-corp.xyz'},{src:'passive_dns',detail:'Domain resolves to Cloudflare IP, recently registered'},{src:'whois',detail:'Domain age: 5 days, privacy-protected registrant'}]},
    { id:'F012', severity:'MEDIUM', type:'Dark Web', value:'hackerone.com employee credentials dump', source:'DarkSearch + Paste Sites', customer:'HackerOne', score:58, mitre:'T1589.001', time:'3h ago', customer_id:'hackerone', matched:'paste_credentials', feeds:['DarkSearch','Paste Sites'], confidence:64, description:'200 employee credential pairs posted on dark web paste site. Mix of current and historical.', evidence:[{src:'darksearch',detail:'Post title: "HackerOne leaked database 2024" – 200 email:hash pairs'},{src:'hibp',detail:'14 emails confirmed in HIBP database from prior breaches'},{src:'pulsedive',detail:'Paste site IP flagged as abuse infrastructure'}]},
    { id:'F013', severity:'LOW', type:'Typosquat', value:'hackeron[.]com (target: hackerone.com)', source:'Typosquat Detector', customer:'HackerOne', score:42, mitre:'T1583.001', time:'4h ago', customer_id:'hackerone', matched:'typosquat', feeds:['Typosquat Detector','crt.sh'], confidence:55, description:'Typosquatting domain registered 2 days ago. No active content yet but cert obtained.', evidence:[{src:'typosquat_detector',detail:'Edit distance 1 from hackerone.com, registered 48h ago'},{src:'crt_sh',detail:'TLS cert issued 36h ago, SAN: hackeron.com'},{src:'whois',detail:'Registrar: GoDaddy, privacy-protected, US nameservers'}]},
    { id:'F014', severity:'LOW', type:'IP', value:'203.0.113.201 (Tor exit node)', source:'ThreatFox', customer:'Intigriti', score:38, mitre:'T1090.003', time:'5h ago', customer_id:'intigriti', matched:'tor_exit', feeds:['ThreatFox','AbuseIPDB'], confidence:49, description:'Known Tor exit node. Low-confidence indicator, monitor for unusual access patterns.', evidence:[{src:'threatfox',detail:'Tagged: tor_exit, last_seen: 2024-12-13'},{src:'abuseipdb',detail:'23 reports, confidence 41%'}]},
    { id:'F015', severity:'HIGH', type:'AWS Key', value:'AKIA4HPREDACTEDXYZ12', source:'grep.app', customer:'YesWeHack', score:91, mitre:'T1552.005', time:'6h ago', customer_id:'yeswehack', matched:'aws_access_key', feeds:['grep.app','GitHub Gist'], confidence:95, description:'AWS Access Key ID found in public repo. GetCallerIdentity confirms active key with admin policy.', evidence:[{src:'grep_app',detail:'Found in .env file committed to public repo 7h ago'},{src:'aws_sts',detail:'Key active – Account ID: 123456789012, UserArn: admin'},{src:'aws_iam',detail:'Policy: AdministratorAccess (Full AWS access)'}]},
  ],

  /* ─────────────────────────── CAMPAIGNS ─────────────────────────── */
  campaigns: [
    { id:'C001', name:'Operation Midnight Rain', actor:'APT29 (Cozy Bear)', severity:'CRITICAL', status:'Active', findings:47, iocs:312, customers:['HackerOne','Bugcrowd'], techniques:['T1566.001','T1078','T1021.002','T1059.001','T1486'], description:'Russian state-sponsored spear-phishing campaign targeting bug bounty platforms. Uses CVE-2024-3400 as initial access.', progress:73, color:'#ef4444' },
    { id:'C002', name:'SilverFox Credential Harvest', actor:'FIN7', severity:'HIGH', status:'Active', findings:28, iocs:189, customers:['Synack','Cobalt'], techniques:['T1589.001','T1078.002','T1539','T1552.001'], description:'Financial crime group harvesting credentials via infostealer malware and dark web marketplaces.', progress:55, color:'#f97316' },
    { id:'C003', name:'ALPHV Ransomware Wave', actor:'ALPHV/BlackCat', severity:'CRITICAL', status:'Active', findings:19, iocs:98, customers:['Intigriti','YesWeHack'], techniques:['T1486','T1490','T1070','T1078'], description:'BlackCat affiliate targeting MSPs and security companies. Double-extortion with data leak threats.', progress:41, color:'#ef4444' },
    { id:'C004', name:'SolarHarvest API Exposure', actor:'Unknown (Automated Scanner)', severity:'HIGH', status:'Monitoring', findings:63, iocs:412, customers:['HackerOne','Bugcrowd','Synack'], techniques:['T1552.001','T1530','T1119'], description:'Automated scanning campaign targeting API key exposure across code repositories. 63 keys harvested.', progress:88, color:'#f97316' },
    { id:'C005', name:'Lazarus Financial Ops', actor:'Lazarus Group (DPRK)', severity:'HIGH', status:'Active', findings:15, iocs:77, customers:['Cobalt','Intigriti'], techniques:['T1566','T1059','T1055','T1027','T1041'], description:'North Korean threat actor targeting fintech and blockchain companies via spear-phishing and supply chain.', progress:29, color:'#a855f7' },
    { id:'C006', name:'Scattered Spider Social Eng', actor:'Scattered Spider (UNC3944)', severity:'MEDIUM', status:'Monitoring', findings:8, iocs:34, customers:['YesWeHack'], techniques:['T1598.003','T1078','T1621'], description:'Social engineering targeting IT help desks. SIM swapping and MFA bypass techniques observed.', progress:62, color:'#f59e0b' },
    { id:'C007', name:'BlackTech Supply Chain', actor:'BlackTech (APT41 affiliate)', severity:'HIGH', status:'Contained', findings:22, iocs:156, customers:['Bugcrowd','Synack'], techniques:['T1195','T1059','T1036','T1562'], description:'Supply chain attack via compromised open-source npm packages. 3 packages identified and removed.', progress:91, color:'#22c55e' },
    { id:'C008', name:'Volt Typhoon Infrastructure', actor:'Volt Typhoon (PRC)', severity:'HIGH', status:'Active', findings:31, iocs:203, customers:['HackerOne','Cobalt','Intigriti'], techniques:['T1133','T1078','T1090','T1071'], description:'Chinese state actor pre-positioning in critical infrastructure networks. Living-off-the-land techniques.', progress:47, color:'#f97316' },
    { id:'C009', name:'DarkSide Energy Sector', actor:'REvil Remnant', severity:'MEDIUM', status:'Monitoring', findings:11, iocs:58, customers:['Synack'], techniques:['T1486','T1490','T1083'], description:'REvil remnant targeting energy sector with ransomware. Ransom demands $2-5M range.', progress:36, color:'#f59e0b' },
    { id:'C010', name:'PhaaS Platform Takedown', actor:'LabHost (Dismantled)', severity:'LOW', status:'Resolved', findings:5, iocs:21, customers:['HackerOne'], techniques:['T1566.002','T1539'], description:'Phishing-as-a-Service platform. LabHost infrastructure seized April 2024. Residual IOCs monitored.', progress:100, color:'#22c55e' },
    { id:'C011', name:'TeamViewer Breach Follow-up', actor:'APT29 (attributed)', severity:'HIGH', status:'Active', findings:9, iocs:44, customers:['Bugcrowd','YesWeHack'], techniques:['T1078','T1550','T1021'], description:'Post-breach activity following TeamViewer incident. Lateral movement via stolen session tokens.', progress:58, color:'#f97316' },
    { id:'C012', name:'Cl0p MOVEit Exploitation', actor:'Cl0p Ransomware', severity:'CRITICAL', status:'Monitoring', findings:38, iocs:267, customers:['Cobalt','Intigriti','YesWeHack'], techniques:['T1190','T1041','T1486','T1619'], description:'MOVEit Transfer zero-day exploitation. SQL injection leading to mass data exfiltration campaign.', progress:82, color:'#ef4444' },
  ],

  /* ─────────────────────────── THREAT ACTORS ─────────────────────────── */
  actors: [
    { id:'A001', name:'APT29', aliases:['Cozy Bear','Midnight Blizzard','NOBELIUM'], nation:'Russia 🇷🇺', emoji:'🐻', desc:'SVR-linked espionage group. Known for SolarWinds, TeamViewer, and Microsoft breaches. Highly sophisticated TTPs.', techniques:['T1566.001','T1078','T1021.002','T1059.001','T1550.001'], motivation:'Espionage', active_since:2008 },
    { id:'A002', name:'APT41', aliases:['Winnti','Wicked Panda','BARIUM'], nation:'China 🇨🇳', emoji:'🐼', desc:'Dual state-sponsored espionage and financially-motivated cybercrime. Active in 14+ countries.', techniques:['T1195.002','T1059','T1027','T1036','T1562'], motivation:'Espionage + Financial', active_since:2012 },
    { id:'A003', name:'FIN7', aliases:['Carbanak','Carbon Spider'], nation:'Unknown/Russia', emoji:'💰', desc:'Financial crime group targeting POS systems, restaurants, and financial institutions. $3B+ stolen globally.', techniques:['T1566.001','T1059.001','T1547','T1055','T1041'], motivation:'Financial', active_since:2015 },
    { id:'A004', name:'Lazarus Group', aliases:['Hidden Cobra','APT38','Labyrinth Chollima'], nation:'N. Korea 🇰🇵', emoji:'🚀', desc:'DPRK state actor. WannaCry, Bangladesh Bank heist, Sony hack. Focus on crypto theft and espionage.', techniques:['T1566','T1059','T1055','T1027','T1041'], motivation:'Financial + Espionage', active_since:2009 },
    { id:'A005', name:'Cl0p', aliases:['TA505','FIN11'], nation:'Russia/Ukraine', emoji:'🦞', desc:'Prolific ransomware operator. MOVEit, GoAnywhere, Accellion FTA exploits. Mass data extortion.', techniques:['T1190','T1041','T1486','T1619','T1567'], motivation:'Financial (Ransomware)', active_since:2019 },
    { id:'A006', name:'Scattered Spider', aliases:['UNC3944','Muddled Libra'], nation:'USA/UK (youth)', emoji:'🕷️', desc:'Social engineering specialists. MGM Resorts breach, Caesars Entertainment. SIM swapping, helpdesk vishing.', techniques:['T1598.003','T1078','T1621','T1539','T1556'], motivation:'Financial', active_since:2022 },
    { id:'A007', name:'Volt Typhoon', aliases:['Bronze Silhouette','VOLTZITE'], nation:'China 🇨🇳', emoji:'⚡', desc:'PRC pre-positioning in critical infrastructure. LOTL techniques, no custom malware. 5-year persistence observed.', techniques:['T1133','T1078','T1090','T1071','T1003'], motivation:'Espionage + Pre-positioning', active_since:2021 },
    { id:'A008', name:'ALPHV/BlackCat', aliases:['NOBERUS','Sphynx'], nation:'Russia', emoji:'🐱', desc:'RaaS operator with Rust-based ransomware. Change Healthcare breach. $22M Bitcoin ransom paid.', techniques:['T1486','T1490','T1070','T1078','T1567.002'], motivation:'Financial (Ransomware)', active_since:2021 },
  ],

  /* ─────────────────────────── COLLECTORS ─────────────────────────── */
  collectors: [
    // FREE
    { id:'COL001', name:'NVD', desc:'National Vulnerability Database - CVE/CVSS data', status:'online', type:'free', iocs_today:1247, iocs_total:89432, last_run:'2m ago', category:'Vulnerability Intel' },
    { id:'COL002', name:'CISA KEV', desc:'Known Exploited Vulnerabilities catalog', status:'online', type:'free', iocs_today:3, iocs_total:1231, last_run:'5m ago', category:'Vulnerability Intel' },
    { id:'COL003', name:'EPSS', desc:'Exploit Prediction Scoring System scores', status:'online', type:'free', iocs_today:892, iocs_total:42100, last_run:'8m ago', category:'Vulnerability Intel' },
    { id:'COL004', name:'MITRE ATT&CK', desc:'TTP framework with technique mappings', status:'online', type:'free', iocs_today:0, iocs_total:625, last_run:'1h ago', category:'Framework' },
    { id:'COL005', name:'OpenPhish', desc:'Real-time phishing intelligence', status:'online', type:'free', iocs_today:284, iocs_total:18920, last_run:'3m ago', category:'Phishing' },
    { id:'COL006', name:'URLhaus', desc:'Malware URL feed from abuse.ch', status:'online', type:'free', iocs_today:892, iocs_total:124500, last_run:'2m ago', category:'Malware URLs' },
    { id:'COL007', name:'PhishTank', desc:'Community-verified phishing URLs', status:'warning', type:'free', iocs_today:156, iocs_total:89300, last_run:'15m ago', category:'Phishing' },
    { id:'COL008', name:'Feodo Tracker', desc:'Botnet C2 IP blocklist', status:'online', type:'free', iocs_today:47, iocs_total:12400, last_run:'4m ago', category:'Botnet C2' },
    { id:'COL009', name:'ThreatFox', desc:'IOC sharing platform from abuse.ch', status:'online', type:'free', iocs_today:312, iocs_total:67800, last_run:'6m ago', category:'Multi-type IOC' },
    { id:'COL010', name:'MalwareBazaar', desc:'Malware sample hash database', status:'online', type:'free', iocs_today:489, iocs_total:234000, last_run:'7m ago', category:'Malware Hashes' },
    { id:'COL011', name:'Abuse.ch', desc:'Swiss non-profit threat intelligence', status:'online', type:'free', iocs_today:1034, iocs_total:445000, last_run:'3m ago', category:'Multi-type IOC' },
    { id:'COL012', name:'CIRCL MISP', desc:'Malware Info Sharing Platform', status:'online', type:'free', iocs_today:78, iocs_total:34200, last_run:'12m ago', category:'Shared Intel' },
    { id:'COL013', name:'grep.app', desc:'109 API key patterns in public code', status:'online', type:'free', iocs_today:234, iocs_total:8900, last_run:'5m ago', category:'Secret Exposure' },
    { id:'COL014', name:'GitHub Gist', desc:'Public gist scanning for secrets', status:'online', type:'free', iocs_today:89, iocs_total:3400, last_run:'8m ago', category:'Secret Exposure' },
    { id:'COL015', name:'Sourcegraph', desc:'Code search for credential exposure', status:'online', type:'free', iocs_today:67, iocs_total:2100, last_run:'11m ago', category:'Secret Exposure' },
    { id:'COL016', name:'Ransomwatch', desc:'Ransomware dark web leak site monitor', status:'online', type:'free', iocs_today:12, iocs_total:4500, last_run:'6m ago', category:'Ransomware' },
    { id:'COL017', name:'RansomFeed', desc:'Ransomware victim tracking feed', status:'online', type:'free', iocs_today:8, iocs_total:2890, last_run:'9m ago', category:'Ransomware' },
    { id:'COL018', name:'VX-Underground', desc:'Malware research and samples', status:'online', type:'free', iocs_today:156, iocs_total:18900, last_run:'14m ago', category:'Malware Research' },
    { id:'COL019', name:'Paste Sites', desc:'Pastebin, Dpaste, Rentry monitoring', status:'warning', type:'free', iocs_today:342, iocs_total:56700, last_run:'20m ago', category:'Credential Leaks' },
    { id:'COL020', name:'RSS Threat Feeds', desc:'Aggregated threat blog RSS feeds', status:'online', type:'free', iocs_today:23, iocs_total:1200, last_run:'30m ago', category:'Threat Intel' },
    { id:'COL021', name:'Pulsedive', desc:'Community threat intelligence platform', status:'online', type:'free', iocs_today:178, iocs_total:24500, last_run:'7m ago', category:'Multi-type IOC' },
    { id:'COL022', name:'DarkSearch', desc:'Dark web search and indexing', status:'online', type:'free', iocs_today:45, iocs_total:8900, last_run:'18m ago', category:'Dark Web' },
    { id:'COL023', name:'Telegram Channels', desc:'Threat actor Telegram monitoring', status:'warning', type:'free', iocs_today:89, iocs_total:3400, last_run:'25m ago', category:'Dark Web' },
    { id:'COL024', name:'crt.sh', desc:'Certificate Transparency log monitoring', status:'online', type:'free', iocs_today:234, iocs_total:45600, last_run:'4m ago', category:'Certificate Intel' },
    { id:'COL025', name:'Shodan InternetDB', desc:'Internet-exposed asset intelligence', status:'online', type:'free', iocs_today:567, iocs_total:89000, last_run:'6m ago', category:'Network Exposure' },
    { id:'COL026', name:'Typosquat Detector', desc:'Domain typosquatting detection', status:'online', type:'free', iocs_today:23, iocs_total:1890, last_run:'10m ago', category:'Domain Intel' },
    // KEYED
    { id:'COL027', name:'VirusTotal', desc:'Multi-AV and threat scanning platform', status:'online', type:'keyed', iocs_today:892, iocs_total:234000, last_run:'2m ago', category:'Multi-type IOC' },
    { id:'COL028', name:'AbuseIPDB', desc:'IP reputation and abuse database', status:'online', type:'keyed', iocs_today:1234, iocs_total:678000, last_run:'3m ago', category:'IP Intel' },
    { id:'COL029', name:'Shodan', desc:'Full Shodan search API', status:'online', type:'keyed', iocs_today:456, iocs_total:123000, last_run:'4m ago', category:'Network Exposure' },
    { id:'COL030', name:'OTX AlienVault', desc:'Open Threat Exchange pulses', status:'online', type:'keyed', iocs_today:678, iocs_total:456000, last_run:'5m ago', category:'Multi-type IOC' },
    { id:'COL031', name:'URLScan.io', desc:'URL scanning and analysis', status:'online', type:'keyed', iocs_today:234, iocs_total:89000, last_run:'7m ago', category:'URL Intel' },
    { id:'COL032', name:'GitHub Secrets', desc:'GitHub Secret Scanning alerts API', status:'warning', type:'keyed', iocs_today:45, iocs_total:3400, last_run:'22m ago', category:'Secret Exposure' },
    { id:'COL033', name:'HudsonRock', desc:'Infostealer credential corpus', status:'online', type:'keyed', iocs_today:89, iocs_total:12400, last_run:'9m ago', category:'Credential Leaks' },
    { id:'COL034', name:'HIBP', desc:'Have I Been Pwned breach database', status:'online', type:'keyed', iocs_today:234, iocs_total:89000, last_run:'11m ago', category:'Credential Leaks' },
    { id:'COL035', name:'LeakIX', desc:'Exposed service and data leak index', status:'online', type:'keyed', iocs_today:123, iocs_total:34000, last_run:'13m ago', category:'Network Exposure' },
    { id:'COL036', name:'GrayHat Warfare', desc:'Exposed S3 bucket intelligence', status:'online', type:'keyed', iocs_today:67, iocs_total:12300, last_run:'16m ago', category:'Cloud Exposure' },
    { id:'COL037', name:'Censys', desc:'Internet-wide scanning and search', status:'online', type:'keyed', iocs_today:345, iocs_total:67800, last_run:'8m ago', category:'Network Exposure' },
    { id:'COL038', name:'IntelX', desc:'Intelligence X search and OSINT', status:'warning', type:'keyed', iocs_today:156, iocs_total:23400, last_run:'28m ago', category:'OSINT' },
    // ADDITIONAL to reach 47
    { id:'COL039', name:'Cisco Talos', desc:'Cisco threat intelligence feeds', status:'online', type:'keyed', iocs_today:234, iocs_total:56700, last_run:'5m ago', category:'Multi-type IOC' },
    { id:'COL040', name:'IBM X-Force', desc:'IBM threat intelligence platform', status:'online', type:'keyed', iocs_today:178, iocs_total:45600, last_run:'7m ago', category:'Multi-type IOC' },
    { id:'COL041', name:'Recorded Future', desc:'AI-powered threat intelligence', status:'online', type:'keyed', iocs_today:312, iocs_total:89000, last_run:'9m ago', category:'Multi-type IOC' },
    { id:'COL042', name:'CIRCL CVE-Search', desc:'CIRCL CVE search service', status:'online', type:'free', iocs_today:89, iocs_total:23400, last_run:'14m ago', category:'Vulnerability Intel' },
    { id:'COL043', name:'Mandiant IOC', desc:'Mandiant threat intelligence', status:'online', type:'keyed', iocs_today:45, iocs_total:12300, last_run:'18m ago', category:'APT Intel' },
    { id:'COL044', name:'CrowdSec CTI', desc:'CrowdSec community IP blocklist', status:'online', type:'free', iocs_today:567, iocs_total:234000, last_run:'4m ago', category:'IP Intel' },
    { id:'COL045', name:'SANS ISC', desc:'SANS Internet Storm Center feeds', status:'online', type:'free', iocs_today:34, iocs_total:8900, last_run:'22m ago', category:'Threat Intel' },
    { id:'COL046', name:'SecureList', desc:'Kaspersky SecureList threat feed', status:'warning', type:'free', iocs_today:23, iocs_total:5600, last_run:'35m ago', category:'APT Intel' },
    { id:'COL047', name:'Twitter/X CTI', desc:'Security community threat sharing', status:'offline', type:'free', iocs_today:0, iocs_total:4500, last_run:'2h ago', category:'Community Intel' },
  ],

  /* ─────────────────────────── DARK WEB ─────────────────────────── */
  darkweb: [
    { id:'DW001', source:'ALPHV Dark Web', title:'New Victim: TechCorp International (3.2TB)', preview:'ALPHV/BlackCat added a new victim: TechCorp International. Files include payroll, customer data, internal communications. Ransom: $4.5M BTC. Deadline: 72 hours.', time:'2h ago', severity:'CRITICAL', type:'Ransomware Listing' },
    { id:'DW002', source:'BreachForums', title:'1.2M HackerOne researcher emails + PII', preview:'User "cyb3r_h4ck3r" posted database dump claiming 1.2 million HackerOne researcher profiles including real names, email addresses, and program activity.', time:'4h ago', severity:'HIGH', type:'Data Breach' },
    { id:'DW003', source:'Telegram (RU-CTI)', title:'0-day exploit for Ivanti VPN for sale - $150K', preview:'Seller offering remote code execution exploit for Ivanti Connect Secure VPN. Claims pre-patch, verified on latest version. Escrow through trusted intermediary.', time:'6h ago', severity:'CRITICAL', type:'Exploit Sale' },
    { id:'DW004', source:'XSS.is Forum', title:'MaaS: Raccoon Stealer v3 - $250/month', preview:'New version of Raccoon Stealer malware-as-a-service offering. Claims improved AV evasion, automatic credential extraction from 60+ browsers and apps.', time:'8h ago', severity:'HIGH', type:'MaaS Offering' },
    { id:'DW005', source:'RansomFeed', title:'Cl0p claims new MOVEit victims: 5 companies', preview:'Cl0p ransomware group added 5 new organizations to their dark web leak site, attributing compromise to unpatched MOVEit instances. Data exfiltration claimed.', time:'10h ago', severity:'CRITICAL', type:'Ransomware Listing' },
    { id:'DW006', source:'Paste Site (rentry.co)', title:'AWS root credentials dump - 47 accounts', preview:'Anonymous paste containing 47 AWS account credentials including root access keys. Mix of personal and enterprise accounts. Includes S3 buckets with sensitive data.', time:'12h ago', severity:'HIGH', type:'Credential Dump' },
    { id:'DW007', source:'DarkSearch.io', title:'Corporate VPN credential market - 2,400 entries', preview:'Dedicated dark web shop selling VPN credentials for Fortune 500 companies. $50-500 per credential depending on access level. SSH keys also available.', time:'1d ago', severity:'HIGH', type:'Credential Market' },
    { id:'DW008', source:'Ransomwatch', title:'LockBit 3.0 emerges after takedown', preview:'New LockBit 3.0 infrastructure detected despite operation Cronos. New dark web site active. 3 new victims listed. Law enforcement takedown appears partially effective.', time:'1d ago', severity:'HIGH', type:'Ransomware Activity' },
  ],

  /* ─────────────────────────── IOC REGISTRY ─────────────────────────── */
  ioc_registry: [
    {
      category: 'API Keys & Tokens',
      color: '#22d3ee',
      types: [
        { name:'google_api_key', status:'proven', regex:'AIza[0-9A-Za-z\\-_]{35}' },
        { name:'openai_api_key', status:'proven', regex:'sk-proj-[A-Za-z0-9_\\-]{50,}' },
        { name:'aws_access_key', status:'proven', regex:'AKIA[0-9A-Z]{16}' },
        { name:'github_pat', status:'proven', regex:'ghp_[A-Za-z0-9]{36}' },
        { name:'github_fine_grained', status:'working', regex:'github_pat_[A-Za-z0-9_]{82}' },
        { name:'sendgrid_api_key', status:'working', regex:'SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}' },
        { name:'stripe_live_key', status:'proven', regex:'sk_live_[A-Za-z0-9]{24,}' },
        { name:'azure_bearer', status:'working', regex:'Bearer eyJ[A-Za-z0-9_\\-]{100,}' },
        { name:'slack_bot_token', status:'proven', regex:'xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}' },
        { name:'twilio_sid', status:'working', regex:'AC[a-fA-F0-9]{32}' },
        { name:'anthropic_key', status:'working', regex:'sk-ant-[A-Za-z0-9_\\-]{95}' },
        { name:'huggingface_token', status:'working', regex:'hf_[A-Za-z]{34}' },
      ]
    },
    {
      category: 'Stolen Credentials',
      color: '#ef4444',
      types: [
        { name:'email_password_pair', status:'proven', regex:'[\\w.]+@[\\w.]+:[A-Za-z0-9!@#$%^&*]{8,}' },
        { name:'ssh_private_key', status:'proven', regex:'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----' },
        { name:'vpn_credential', status:'working', regex:'vpn\\.[A-Za-z0-9\\-]+\\.[a-z]{2,}:[\\w@#$!]+' },
        { name:'database_url', status:'proven', regex:'(mysql|postgres|mongodb|redis):\\/\\/[^:]+:[^@]+@[^/]+' },
        { name:'htpasswd_entry', status:'working', regex:'[\\w.]+:\\$apr1\\$[A-Za-z0-9./]{8}\\$[A-Za-z0-9./]{22}' },
      ]
    },
    {
      category: 'Vulnerability Intel',
      color: '#f97316',
      types: [
        { name:'cve_id', status:'proven', regex:'CVE-\\d{4}-\\d{4,7}' },
        { name:'cisa_kev_entry', status:'proven', regex:'KEV-[0-9]{4}-[0-9]+' },
        { name:'cvss_critical', status:'proven', regex:'CVSS:3\\.1\\/AV:[NALP]\\/AC:[LH]\\/PR:[NLH]\\/UI:[NR]\\/S:[UC]\\/C:[NLH]\\/I:[NLH]\\/A:[NLH]' },
        { name:'epss_score', status:'working', regex:'EPSS:\\s*0\\.(9[0-9]|[89][0-9])[0-9]*' },
        { name:'exploit_db_ref', status:'theoretical', regex:'https:\\/\\/www\\.exploit-db\\.com\\/exploits\\/\\d+' },
      ]
    },
    {
      category: 'Network IOCs',
      color: '#3b82f6',
      types: [
        { name:'malicious_ip', status:'proven', regex:'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' },
        { name:'malicious_domain', status:'proven', regex:'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}' },
        { name:'malicious_url', status:'proven', regex:'https?:\\/\\/[^\\s"\'<>]+' },
        { name:'tor_onion', status:'working', regex:'[a-z2-7]{16,56}\\.onion' },
        { name:'c2_domain', status:'proven', regex:'[a-z0-9]{6,20}\\.(cc|tk|cf|ga|ml|gq)' },
        { name:'ipv6_malicious', status:'theoretical', regex:'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' },
      ]
    },
    {
      category: 'Data Exfiltration',
      color: '#a855f7',
      types: [
        { name:'credit_card', status:'proven', regex:'4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}' },
        { name:'ssn', status:'working', regex:'\\b(?!219-09-9999|078-05-1120)[0-9]{3}-(?!00)[0-9]{2}-(?!0{4})[0-9]{4}\\b' },
        { name:'passport_number', status:'theoretical', regex:'[A-Z]{1,2}[0-9]{6,9}' },
        { name:'bank_iban', status:'working', regex:'[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}' },
        { name:'bitcoin_address', status:'proven', regex:'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}' },
      ]
    },
    {
      category: 'Dark Web & Threat Actors',
      color: '#ec4899',
      types: [
        { name:'ransomware_victim_post', status:'proven', regex:'victim|ransom|leak|extort' },
        { name:'dark_web_market', status:'working', regex:'market|shop|store' },
        { name:'threat_actor_alias', status:'theoretical', regex:'apt[0-9]{1,3}|fin[0-9]|ta[0-9]{3}' },
      ]
    },
  ],

  /* ─────────────────────────── PLAYBOOKS ─────────────────────────── */
  playbooks: [
    { id:'PB001', name:'Critical CVE Response', category:'Vulnerability', desc:'Auto-assess CVSS 9.0+ CVEs against customer asset inventory, prioritize by exposure, generate patch timeline.', steps:7, triggers:['cve_critical','cisa_kev'], mitre_coverage:8 },
    { id:'PB002', name:'API Key Exposure Response', category:'Secret Exposure', desc:'Validate exposed API key, determine access scope, notify customer, generate revocation guide.', steps:5, triggers:['api_key_found'], mitre_coverage:3 },
    { id:'PB003', name:'Credential Leak Investigation', category:'Credentials', desc:'Correlate leaked credentials with customer domains, check active usage, trigger password reset workflow.', steps:6, triggers:['credential_found'], mitre_coverage:4 },
    { id:'PB004', name:'C2 Infrastructure Analysis', category:'Network', desc:'Pivot from C2 IP/domain, map associated infrastructure, attribute to known campaigns, generate blocking list.', steps:9, triggers:['c2_ioc'], mitre_coverage:12 },
    { id:'PB005', name:'Ransomware IOC Response', category:'Ransomware', desc:'Extract ransomware indicators, check customer exposure, generate detection signatures for SIEM/EDR.', steps:8, triggers:['ransomware_ioc'], mitre_coverage:15 },
    { id:'PB006', name:'Phishing Campaign Analysis', category:'Phishing', desc:'Analyze phishing domain, extract lure content, identify target industry, generate employee warnings.', steps:6, triggers:['phishing_url','phishing_domain'], mitre_coverage:6 },
    { id:'PB007', name:'Dark Web Exposure Alert', category:'Dark Web', desc:'Verify dark web mentions, extract relevant data, assess breach scope, notify affected customers.', steps:5, triggers:['darkweb_mention'], mitre_coverage:5 },
    { id:'PB008', name:'Typosquat Domain Response', category:'Brand Protection', desc:'Validate typosquatting, check for active phishing content, initiate DMCA/UDRP process guidance.', steps:4, triggers:['typosquat_detected'], mitre_coverage:3 },
    { id:'PB009', name:'SSH Key Exposure', category:'Credentials', desc:'Identify exposed SSH keys, determine target systems, check key fingerprints against known servers.', steps:5, triggers:['ssh_key_found'], mitre_coverage:4 },
    { id:'PB010', name:'Data Breach Investigation', category:'Data Exfiltration', desc:'Scope breach data, identify affected customers, calculate GDPR notification requirements.', steps:7, triggers:['pii_found','credit_card_found'], mitre_coverage:6 },
    { id:'PB011', name:'Threat Actor Attribution', category:'APT Intel', desc:'Analyze TTPs, infrastructure, and timing to attribute campaign to known threat actor groups.', steps:8, triggers:['apt_ioc'], mitre_coverage:20 },
    { id:'PB012', name:'Supply Chain Compromise', category:'Supply Chain', desc:'Identify compromised packages/dependencies, assess blast radius, generate remediation guidance.', steps:9, triggers:['supply_chain_ioc'], mitre_coverage:10 },
  ],

  /* ─────────────────────────── CUSTOMERS ─────────────────────────── */
  customers: [
    { id:'CUST001', name:'HackerOne', emoji:'🟠', color:'#f97316', plan:'Enterprise', findings:89, critical:3, campaigns:5, collectors_active:47, risk:'HIGH' },
    { id:'CUST002', name:'Bugcrowd', emoji:'🐛', color:'#ef4444', plan:'Enterprise', findings:54, critical:1, campaigns:3, collectors_active:45, risk:'HIGH' },
    { id:'CUST003', name:'Synack', emoji:'🔐', color:'#22d3ee', plan:'Professional', findings:38, critical:0, campaigns:2, collectors_active:38, risk:'MEDIUM' },
    { id:'CUST004', name:'Cobalt', emoji:'💎', color:'#a855f7', plan:'Professional', findings:31, critical:2, campaigns:4, collectors_active:41, risk:'HIGH' },
    { id:'CUST005', name:'Intigriti', emoji:'🎯', color:'#22c55e', plan:'Standard', findings:24, critical:1, campaigns:2, collectors_active:35, risk:'MEDIUM' },
    { id:'CUST006', name:'YesWeHack', emoji:'🏆', color:'#f59e0b', plan:'Standard', findings:11, critical:0, campaigns:1, collectors_active:30, risk:'LOW' },
  ],

  /* ─────────────────────────── EXPOSURE ─────────────────────────── */
  exposure: [
    { title:'Exposed Services', value:'47', desc:'Internet-facing services without proper security controls', color:'#ef4444' },
    { title:'Open Ports', value:'2,341', desc:'Unique open ports across all customer assets', color:'#f97316' },
    { title:'Expired Certificates', value:'23', desc:'TLS certificates expired or expiring within 30 days', color:'#f59e0b' },
    { title:'S3 Buckets', value:'12', desc:'Publicly accessible cloud storage buckets', color:'#a855f7' },
    { title:'GitHub Secrets', value:'34', desc:'Active secrets found in public repositories', color:'#22d3ee' },
    { title:'Dark Web Mentions', value:'156', desc:'Customer brand/domain mentions on dark web', color:'#ec4899' },
  ],

  /* ─────────────────────────── AI INVESTIGATIONS ─────────────────────────── */
  recent_investigations: [
    { query:'Investigate 185.220.101.45 for C2', tools:7, iterations:8, conclusion:'MALICIOUS - Emotet C2, block immediately', time:'5m ago', severity:'HIGH' },
    { query:'Analyze CVE-2024-3400 exploit activity', tools:5, iterations:6, conclusion:'CRITICAL - Active exploitation, patch now', time:'12m ago', severity:'CRITICAL' },
    { query:'Check maliciousupdate[.]ru attribution', tools:9, iterations:11, conclusion:'HIGH - APT29 phishing infrastructure', time:'1h ago', severity:'HIGH' },
    { query:'Summarize HackerOne critical findings', tools:2, iterations:1, conclusion:'3 CRITICAL findings require immediate action', time:'2h ago', severity:'MEDIUM' },
    { query:'Weekly threat brief for all customers', tools:4, iterations:3, conclusion:'Report generated: 247 findings, 3 critical', time:'3h ago', severity:'LOW' },
  ],

  /* ─────────────────────────── TENANTS (RBAC) ─────────────────────────── */
  tenants: [
    { id:'T001', name:'MSSP Global Operations', short:'MSSP Global', emoji:'🌐', color:'#3b82f6', plan:'Enterprise', users:12, collectors:47, risk:'HIGH', active:true, created:'2024-01-15', domain:'mssp.com', siem:'Splunk', edr:'CrowdStrike' },
    { id:'T002', name:'HackerOne Security Team', short:'HackerOne', emoji:'🟠', color:'#f97316', plan:'Enterprise', users:8, collectors:47, risk:'HIGH', active:true, created:'2024-02-01', domain:'hackerone.com', siem:'Elastic SIEM', edr:'SentinelOne' },
    { id:'T003', name:'Bugcrowd Platform', short:'Bugcrowd', emoji:'🐛', color:'#ef4444', plan:'Enterprise', users:6, collectors:45, risk:'HIGH', active:true, created:'2024-02-15', domain:'bugcrowd.com', siem:'Microsoft Sentinel', edr:'Defender' },
    { id:'T004', name:'Synack Red Team', short:'Synack', emoji:'🔐', color:'#22d3ee', plan:'Professional', users:4, collectors:38, risk:'MEDIUM', active:true, created:'2024-03-01', domain:'synack.com', siem:'QRadar', edr:'CarbonBlack' },
    { id:'T005', name:'Cobalt Security', short:'Cobalt', emoji:'💎', color:'#a855f7', plan:'Professional', users:5, collectors:41, risk:'HIGH', active:true, created:'2024-03-10', domain:'cobalt.io', siem:'Splunk', edr:'CrowdStrike' },
    { id:'T006', name:'Intigriti Platform', short:'Intigriti', emoji:'🎯', color:'#22c55e', plan:'Standard', users:3, collectors:35, risk:'MEDIUM', active:true, created:'2024-04-01', domain:'intigriti.com', siem:'Sumo Logic', edr:'Sophos' },
    { id:'T007', name:'YesWeHack', short:'YesWeHack', emoji:'🏆', color:'#f59e0b', plan:'Standard', users:3, collectors:30, risk:'LOW', active:true, created:'2024-04-15', domain:'yeswehack.com', siem:'Graylog', edr:'ESET' },
  ],

  /* ─────────────────────────── RBAC USERS ─────────────────────────── */
  users: [
    { id:'U001', name:'Mahmoud Osman', email:'mahmoud@mssp.com', role:'SUPER_ADMIN', tenant:'MSSP Global Operations', avatar:'MO', last_login:'just now', mfa:true, status:'active', permissions:['all'] },
    { id:'U002', name:'James Chen', email:'james@mssp.com', role:'ADMIN', tenant:'MSSP Global Operations', avatar:'JC', last_login:'1h ago', mfa:true, status:'active', permissions:['read','write','manage_collectors'] },
    { id:'U003', name:'Maria Santos', email:'maria@mssp.com', role:'ANALYST', tenant:'MSSP Global Operations', avatar:'MS', last_login:'3h ago', mfa:false, status:'active', permissions:['read','write'] },
    { id:'U004', name:'Alex Thompson', email:'alex@hackerone.com', role:'ANALYST', tenant:'HackerOne Security Team', avatar:'AT', last_login:'30m ago', mfa:true, status:'active', permissions:['read','write'] },
    { id:'U005', name:'Priya Patel', email:'priya@hackerone.com', role:'VIEWER', tenant:'HackerOne Security Team', avatar:'PP', last_login:'2d ago', mfa:false, status:'inactive', permissions:['read'] },
    { id:'U006', name:'Marcus Williams', email:'marcus@bugcrowd.com', role:'ANALYST', tenant:'Bugcrowd Platform', avatar:'MW', last_login:'5h ago', mfa:true, status:'active', permissions:['read','write'] },
  ],

  /* ─────────────────────────── NOTIFICATIONS ─────────────────────────── */
  notifications: [
    { id:'N001', type:'critical', title:'CRITICAL: Google API Key Exposed', desc:'New API key found in GitHub Gist — HackerOne tenant. Key is ACTIVE.', time:'2 min ago', read:false, page:'findings' },
    { id:'N002', type:'critical', title:'CVE-2024-3400 Active Exploitation', desc:'PAN-OS vulnerability now confirmed in-the-wild. 3 customer assets potentially affected.', time:'5 min ago', read:false, page:'findings' },
    { id:'N003', type:'high', title:'New Ransomware Campaign Detected', desc:'ALPHV added 3 new victims to dark web leak site. Potential impact on Intigriti tenant.', time:'12 min ago', read:false, page:'campaigns' },
    { id:'N004', type:'high', title:'Infostealer Credential Found', desc:'VPN credential for corp-vpn.hackerone.com found in HudsonRock corpus. Breach: 3 days ago.', time:'18 min ago', read:false, page:'findings' },
    { id:'N005', type:'info', title:'Sync Complete — 1,204 new IOCs', desc:'All 47 collectors successfully polled. 44 online, 3 with warnings.', time:'25 min ago', read:false, page:'collectors' },
    { id:'N006', type:'high', title:'APT29 Infrastructure Identified', desc:'Domain maliciousupdate[.]ru attributed to Operation Midnight Rain campaign.', time:'1h ago', read:true, page:'campaigns' },
    { id:'N007', type:'info', title:'AI Investigation Complete', desc:'Qwen3:8B finished 11-iteration analysis of 185.220.101.45. Verdict: MALICIOUS C2.', time:'1h ago', read:true, page:'ai-orchestrator' },
    { id:'N008', type:'success', title:'Playbook Executed: API Key Exposure', desc:'Automated response playbook triggered for F006 (OpenAI key). 5 steps completed.', time:'2h ago', read:true, page:'playbooks' },
    { id:'N009', type:'high', title:'Dark Web Mention: HackerOne', desc:'200 employee credentials posted on dark web paste site.', time:'3h ago', read:true, page:'dark-web' },
    { id:'N010', type:'info', title:'New Tenant Added: YesWeHack', desc:'YesWeHack Standard plan tenant provisioned. 30 collectors assigned.', time:'4h ago', read:true, page:'customers' },
  ],

  /* ─────────────────────────── EDR SIEM ─────────────────────────── */
  edr_siem: [
    { id:'ES001', name:'Splunk Enterprise', type:'SIEM', status:'connected', icon:'🔷', color:'#22d3ee', webhook:'https://threatpilot.ai/api/ingest/splunk', events_today:8934, last_event:'12s ago', mapping:'HEC Token', sample:'{"event":"ProcessCreate","source":"sysmon","host":"WIN-DC01","EventID":1,"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentImage":"powershell.exe"}' },
    { id:'ES002', name:'Microsoft Sentinel', type:'SIEM', status:'connected', icon:'🔵', color:'#3b82f6', webhook:'https://threatpilot.ai/api/ingest/sentinel', events_today:5621, last_event:'45s ago', mapping:'Workspace ID + Key', sample:'{"TimeGenerated":"2024-12-14T10:23:45Z","EventID":4688,"Computer":"WORKSTATION01","SubjectUserName":"jdoe","NewProcessName":"powershell.exe","CommandLine":"-enc JABzAD0..."}' },
    { id:'ES003', name:'CrowdStrike Falcon', type:'EDR', status:'connected', icon:'🦅', color:'#ef4444', webhook:'https://threatpilot.ai/api/ingest/crowdstrike', events_today:2341, last_event:'2m ago', mapping:'API Client ID + Secret', sample:'{"timestamp":"2024-12-14T10:25:12Z","event_type":"ProcessRollup2","ProcessStartTime":1734172912,"ImageFileName":"\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe","CommandLine":"rundll32.exe malicious.dll,DllMain"}' },
    { id:'ES004', name:'SentinelOne', type:'EDR', status:'warning', icon:'🔴', color:'#f97316', webhook:'https://threatpilot.ai/api/ingest/sentinelone', events_today:1876, last_event:'8m ago', mapping:'API Token', sample:'{"agentDetectionInfo":{"machineType":"desktop","computerName":"ENDPOINT01"},"threatInfo":{"threatName":"Ransomware","classification":"Malware","confidenceLevel":"malicious"}}' },
    { id:'ES005', name:'Elastic SIEM', type:'SIEM', status:'connected', icon:'🔶', color:'#f59e0b', webhook:'https://threatpilot.ai/api/ingest/elastic', events_today:12045, last_event:'5s ago', mapping:'API Key', sample:'{"@timestamp":"2024-12-14T10:26:00.000Z","event":{"category":"network","type":"connection"},"source":{"ip":"185.220.101.45","port":443},"destination":{"ip":"10.0.0.45","port":52341}}' },
    { id:'ES006', name:'QRadar', type:'SIEM', status:'disconnected', icon:'⬛', color:'#64748b', webhook:'https://threatpilot.ai/api/ingest/qradar', events_today:0, last_event:'2h ago', mapping:'SEC Token', sample:'{"LogSourceName":"QRadar","EventName":"AUTHENTICATION_FAILURE","SourceIP":"192.168.1.100","Username":"admin","Outcome":"FAILURE"}' },
  ],

  /* ─────────────────────────── SYSMON EVENTS ─────────────────────────── */
  sysmon_events: [
    { id:'SY001', eventId:1, name:'Process Create', ttp:'T1059.001 — PowerShell', fields:{Image:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine:'powershell.exe -EncodedCommand JABzAD0=...', ParentImage:'winword.exe', User:'DOMAIN\\jdoe'}, severity:'HIGH', time:'10:23:45' },
    { id:'SY002', eventId:3, name:'Network Connection', ttp:'T1071.001 — Web Protocols', fields:{Image:'svchost.exe', DestinationIp:'185.220.101.45', DestinationPort:'443', Initiated:'true', User:'NT AUTHORITY\\SYSTEM'}, severity:'CRITICAL', time:'10:24:12' },
    { id:'SY003', eventId:7, name:'Image Loaded', ttp:'T1055 — Process Injection', fields:{Image:'explorer.exe', ImageLoaded:'C:\\Users\\jdoe\\AppData\\Temp\\payload.dll', Signed:'false', Signature:'', Hashes:'SHA256=a3f8d2...'}, severity:'HIGH', time:'10:24:33' },
    { id:'SY004', eventId:11, name:'File Create', ttp:'T1486 — Data Encrypted', fields:{Image:'C:\\Windows\\Temp\\ransomware.exe', TargetFilename:'C:\\Users\\jdoe\\Documents\\important.docx.locked', CreationUtcTime:'2024-12-14 10:24:45'}, severity:'CRITICAL', time:'10:24:45' },
    { id:'SY005', eventId:13, name:'Registry Value Set', ttp:'T1547.001 — Registry Run Keys', fields:{Image:'C:\\Windows\\System32\\reg.exe', TargetObject:'HKU\\S-1-5-21...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', Details:'C:\\Users\\jdoe\\AppData\\Roaming\\persist.exe'}, severity:'MEDIUM', time:'10:25:01' },
    { id:'SY006', eventId:22, name:'DNS Query', ttp:'T1071.004 — DNS', fields:{Image:'svchost.exe', QueryName:'c2-update.maliciousupdate.ru', QueryResults:'185.220.101.45', User:'NT AUTHORITY\\NETWORK SERVICE'}, severity:'HIGH', time:'10:25:15' },
  ],

  /* ─────────────────────────── REPORT TEMPLATES ─────────────────────────── */
  report_templates: [
    { id:'RT001', icon:'📊', name:'Weekly Threat Brief', desc:'Comprehensive weekly summary of all threat intelligence, trends, and recommendations.', type:'Automated', formats:['PDF','CSV','JSON'], sections:['Executive Summary','Critical Findings','Campaign Analysis','IOC Statistics','Recommendations'] },
    { id:'RT002', icon:'🎯', name:'Customer Threat Report', desc:'Per-tenant detailed threat report with findings, risk score, MITRE coverage.', type:'On-demand', formats:['PDF','CSV'], sections:['Tenant Overview','Findings by Severity','Active Campaigns','Exposure Summary','Action Items'] },
    { id:'RT003', icon:'🔴', name:'Critical Findings Alert', desc:'Immediate CRITICAL severity findings report requiring urgent attention.', type:'Triggered', formats:['PDF','JSON'], sections:['Critical Findings','Evidence Trail','Immediate Actions'] },
    { id:'RT004', icon:'📈', name:'IOC Trend Analysis', desc:'Statistical analysis of IOC trends, feed performance, and detection effectiveness.', type:'Automated', formats:['PDF','CSV','JSON'], sections:['IOC Statistics','Feed Performance','Detection Trends','MITRE Coverage'] },
    { id:'RT005', icon:'🏴', name:'Campaign Intelligence', desc:'Deep-dive campaign analysis with actor attribution, TTPs, and defensive recommendations.', type:'On-demand', formats:['PDF','STIX'], sections:['Campaign Overview','Actor Profile','TTPs','Infrastructure','Recommendations'] },
    { id:'RT006', icon:'🛡️', name:'MITRE Coverage Report', desc:'ATT&CK coverage assessment showing detection gaps and improvement opportunities.', type:'Automated', formats:['PDF','JSON'], sections:['Coverage Matrix','Gap Analysis','Top Techniques','Improvement Plan'] },
    { id:'RT007', icon:'💰', name:'Executive Summary', desc:'C-suite facing report with risk score, business impact, and strategic recommendations.', type:'On-demand', formats:['PDF'], sections:['Risk Dashboard','Business Impact','Strategic Priorities','ROI Analysis'] },
    { id:'RT008', icon:'🔍', name:'AI Investigation Summary', desc:'Summary of all AI orchestrator investigations with evidence trails and conclusions.', type:'Automated', formats:['PDF','JSON'], sections:['Investigations List','Evidence Trails','Conclusions','Tool Performance'] },
  ],
};
