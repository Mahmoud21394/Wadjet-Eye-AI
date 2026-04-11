/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Threat Hunting Workspace v3.0
 *  Comprehensive hunting queries for KQL, SPL, SIGMA, EQL,
 *  YARA, Suricata, Elastic, QRadar, Chronicle
 * ══════════════════════════════════════════════════════════
 */
'use strict';

window.HUNT_QUERIES = [
  /* ─────── LATERAL MOVEMENT ─────── */
  {
    id:'hq-001', category:'Lateral Movement', severity:'high',
    name:'SMB Lateral Movement via Admin Shares',
    description:'Detects lateral movement via SMB admin shares (C$, ADMIN$, IPC$) from non-standard sources.',
    mitre:['T1021.002','T1078'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel / Defender for Endpoint
DeviceNetworkEvents
| where RemotePort == 445
| where InitiatingProcessCommandLine contains "\\\\" or RemoteUrl contains "admin$" or RemoteUrl contains "c$"
| where InitiatingProcessAccountName !in ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")
| summarize Count=count(), Targets=make_set(RemoteIP), by DeviceName, InitiatingProcessAccountName, bin(Timestamp,1h)
| where Count > 3
| order by Count desc`,
    tags:['SMB','lateral-movement','admin-shares']
  },
  {
    id:'hq-002', category:'Lateral Movement', severity:'high',
    name:'PsExec Remote Execution',
    description:'Detects PsExec and similar tools used for remote command execution across the network.',
    mitre:['T1021.002','T1570'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
SecurityEvent
| where EventID in (7045, 4697)  // Service install events
| where ServiceName has_any ("PSEXESVC","RemCom","PAExec")
    or ServiceFileName has_any ("psexec","paexec","remcom")
| project TimeGenerated, Computer, ServiceName, ServiceFileName, Account
| order by TimeGenerated desc`,
    tags:['psexec','remote-exec','service']
  },
  {
    id:'hq-003', category:'Lateral Movement', severity:'high',
    name:'WMI Remote Command Execution',
    description:'Identifies WMI being used for remote command execution — common in APT lateral movement.',
    mitre:['T1047','T1021'],
    platform:'SPL',
    query:`// SPL — Splunk
index=windows source="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| eval is_remote=if(match(ClientMachine,".*\\..*"),"Yes","No")
| where is_remote="Yes"
| eval cmd=mvindex(split(CommandLine, " "),0)
| where cmd IN ("wmic","wbemtest") OR CommandLine LIKE "%process call create%"
| stats count by ClientMachine, User, CommandLine, _time
| sort -count`,
    tags:['WMI','remote-exec','T1047']
  },
  {
    id:'hq-004', category:'Lateral Movement', severity:'critical',
    name:'Pass-the-Hash Detection',
    description:'Detects pass-the-hash authentication using NTLM with blank passwords or Kerberos anomalies.',
    mitre:['T1550.002','T1078'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
SecurityEvent
| where EventID == 4624
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
| where LmPackageName == "NTLM V1" or LmPackageName == ""
| where TargetUserName !endswith "$"
| summarize Count=count(), SourceIPs=make_set(IpAddress)
    by TargetUserName, WorkstationName, bin(TimeGenerated,1h)
| where Count > 5
| order by Count desc`,
    tags:['pass-the-hash','NTLM','authentication']
  },
  {
    id:'hq-005', category:'Lateral Movement', severity:'high',
    name:'RDP Brute Force & Lateral Movement',
    description:'Identifies RDP brute force attempts followed by successful lateral movement.',
    mitre:['T1021.001','T1110.003'],
    platform:'SPL',
    query:`// SPL — Splunk
index=windows EventCode=4625 Logon_Type=10
| stats count AS failures by src_ip, dest, user
| where failures > 10
| join type=inner src_ip [
    search index=windows EventCode=4624 Logon_Type=10
    | rename IpAddress as src_ip
    | stats count AS successes by src_ip, dest, user
]
| eval attack_pattern="RDP BruteForce->Success"
| table src_ip, dest, user, failures, successes`,
    tags:['RDP','brute-force','T1110']
  },

  /* ─────── CREDENTIAL ACCESS ─────── */
  {
    id:'hq-006', category:'Credential Access', severity:'critical',
    name:'LSASS Memory Access',
    description:'Detects unauthorized process access to LSASS memory — credential dumping attempt.',
    mitre:['T1003.001'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceEvents
| where ActionType == "ProcessAccess"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in (
    "MsMpEng.exe","csrss.exe","wininit.exe","services.exe",
    "winlogon.exe","svchost.exe","lsass.exe","taskmgr.exe",
    "SecurityHealthService.exe","antimalware.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc`,
    tags:['LSASS','credential-dumping','T1003']
  },
  {
    id:'hq-007', category:'Credential Access', severity:'critical',
    name:'Kerberoasting Detection',
    description:'Detects Kerberoasting attacks via unusual Kerberos TGS ticket requests for service accounts.',
    mitre:['T1558.003'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4 — weak, used in Kerberoasting
| where ServiceName !endswith "$"
| where ClientAddress !startswith "::1"
| summarize Count=count(), Services=make_set(ServiceName)
    by TargetUserName, ClientAddress, bin(TimeGenerated,15m)
| where Count > 3
| order by Count desc`,
    tags:['kerberoasting','kerberos','T1558']
  },
  {
    id:'hq-008', category:'Credential Access', severity:'critical',
    name:'DCSync Replication Attack',
    description:'Detects DCSync attack where attacker requests AD replication to dump credentials.',
    mitre:['T1003.006'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
SecurityEvent
| where EventID == 4662
| where ObjectType contains "domainDNS"
| where AccessMask contains "0x100" // Replication
| where SubjectUserName !endswith "$"
    and SubjectUserName !in ("MSOL_","AAD_","Azure")
| where SubjectDomainName != "NT AUTHORITY"
| project TimeGenerated, SubjectUserName, SubjectDomainName,
    Computer, ObjectName, AccessMask
| order by TimeGenerated desc`,
    tags:['DCSync','AD-replication','T1003.006']
  },
  {
    id:'hq-009', category:'Credential Access', severity:'high',
    name:'Mimikatz Execution Detection',
    description:'Detects Mimikatz credential dumping tool execution via command-line patterns.',
    mitre:['T1003.001','T1003.002'],
    platform:'SIGMA',
    query:`# SIGMA Rule
title: Mimikatz Execution
status: stable
author: EYEbot AI
description: Detects Mimikatz credential dumping tool execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'crypto::capi'
            - 'vault::cred'
            - 'lsadump::sam'
            - 'mimikatz'
    condition: selection
level: critical
tags:
    - attack.t1003.001
    - attack.credential_access`,
    tags:['mimikatz','credential-dump','SIGMA']
  },

  /* ─────── EXECUTION ─────── */
  {
    id:'hq-010', category:'Execution', severity:'high',
    name:'PowerShell Encoded Command Detection',
    description:'Detects obfuscated PowerShell commands using Base64 encoding — common in malware delivery.',
    mitre:['T1059.001','T1027'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand","-enc","-en","-e ")
    or ProcessCommandLine matches regex @"-[eE][nNcC]+ [A-Za-z0-9+/]{20}"
| extend DecodedCmd = base64_decode_tostring(
    extract(@"(?i)-(?:encodedcommand|enc|en|e)\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, DecodedCmd
| order by Timestamp desc`,
    tags:['powershell','encoded','T1059','obfuscation']
  },
  {
    id:'hq-011', category:'Execution', severity:'high',
    name:'Suspicious Office Macro Execution',
    description:'Detects Office applications spawning suspicious child processes — macro-based malware indicator.',
    mitre:['T1566.001','T1204.002'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","MSPUB.EXE")
| where FileName in~ (
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","certutil.exe","bitsadmin.exe",
    "rundll32.exe","msiexec.exe","wmic.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
    FileName, ProcessCommandLine, AccountName
| order by Timestamp desc`,
    tags:['office-macro','T1566','T1204','spear-phishing']
  },
  {
    id:'hq-012', category:'Execution', severity:'high',
    name:'WMIC Process Creation via LOLBin',
    description:'Detects WMIC being used to create processes — common LOLBin abuse technique.',
    mitre:['T1047','T1218'],
    platform:'SPL',
    query:`// SPL — Splunk
index=windows source="WinEventLog:Security" EventCode=4688
| where Process_Command_Line LIKE "%wmic%process%create%"
    OR Process_Command_Line LIKE "%wmic%call%create%"
| eval parent=mvindex(split(Creator_Process_Name,"\\"),(-1))
| stats count by parent, New_Process_Name, Process_Command_Line, ComputerName
| sort -count`,
    tags:['WMIC','LOLBin','T1047','process-creation']
  },

  /* ─────── PERSISTENCE ─────── */
  {
    id:'hq-013', category:'Persistence', severity:'high',
    name:'Suspicious Scheduled Task Creation',
    description:'Detects suspicious scheduled tasks created via command line or API — common persistence mechanism.',
    mitre:['T1053.005'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (
    "powershell","cmd","wscript","cscript","mshta",
    "regsvr32","rundll32","certutil","http","ftp")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc`,
    tags:['scheduled-task','T1053','persistence']
  },
  {
    id:'hq-014', category:'Persistence', severity:'high',
    name:'WMI Event Subscription Persistence',
    description:'Detects WMI event subscriptions used for persistence — fileless malware technique.',
    mitre:['T1546.003'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
Event
| where Source == "Microsoft-Windows-WMI-Activity"
| where EventID in (5859, 5861)  // WMI subscription
| where RenderedDescription has_any ("CommandLineEventConsumer","ActiveScriptEventConsumer")
| extend Consumer = extract("Consumer: (.*?) ", 1, RenderedDescription)
| project TimeGenerated, Computer, Consumer, RenderedDescription
| order by TimeGenerated desc`,
    tags:['WMI','event-subscription','T1546.003','fileless']
  },
  {
    id:'hq-015', category:'Persistence', severity:'high',
    name:'Registry Run Key Persistence',
    description:'Detects new entries in common autorun registry keys used for persistence.',
    mitre:['T1547.001'],
    platform:'SPL',
    query:`// SPL — Splunk
index=windows source="WinEventLog:Security" EventCode=4657
| where Object_Name LIKE "%Run%" AND (
    Object_Name LIKE "%HKLM%CurrentVersion%Run%" OR
    Object_Name LIKE "%HKCU%CurrentVersion%Run%" OR
    Object_Name LIKE "%RunOnce%"
)
| eval value=coalesce(New_Value,Object_Value_New)
| where value LIKE "%.exe%" OR value LIKE "%powershell%" OR value LIKE "%cmd%"
| stats count by Object_Name, value, SubjectUserName, ComputerName
| sort -count`,
    tags:['registry','run-key','T1547.001','autorun']
  },

  /* ─────── DISCOVERY ─────── */
  {
    id:'hq-016', category:'Discovery', severity:'medium',
    name:'Active Directory Enumeration',
    description:'Detects bulk AD enumeration — often first step in attack reconnaissance.',
    mitre:['T1087.002','T1069.002'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel  
SecurityEvent
| where EventID in (4661, 4662)
| where ObjectType in~ ("Group","User","Computer","domainDNS")
| where SubjectUserName !endswith "$"
| summarize EnumCount=count(), ObjectTypes=make_set(ObjectType)
    by SubjectUserName, Computer, bin(TimeGenerated, 5m)
| where EnumCount > 50
| order by EnumCount desc`,
    tags:['AD-enumeration','T1087','discovery','reconnaissance']
  },
  {
    id:'hq-017', category:'Discovery', severity:'medium',
    name:'Network Port Scanning Detection',
    description:'Identifies internal network port scanning activity indicating reconnaissance.',
    mitre:['T1046'],
    platform:'SPL',
    query:`// SPL — Splunk
index=network sourcetype=firewall
| stats dc(dest_port) AS unique_ports, count AS attempts
    by src_ip, dest_ip
| where unique_ports > 20 AND attempts > 50
| eval scan_type=case(
    unique_ports > 100, "Full Scan",
    unique_ports > 50, "Half-Open Scan",
    true(), "Targeted Scan")
| sort -unique_ports`,
    tags:['port-scan','T1046','network-discovery']
  },

  /* ─────── COMMAND & CONTROL ─────── */
  {
    id:'hq-018', category:'Command & Control', severity:'high',
    name:'DNS Tunneling Detection',
    description:'Identifies DNS tunneling via high-entropy or abnormally long DNS queries.',
    mitre:['T1071.004','T1048.003'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
DnsEvents
| where QueryType has_any ("TXT","A","CNAME")
| extend QueryLen = strlen(Name)
| where QueryLen > 52  // Abnormally long
| extend SubDomainDepth = array_length(split(Name,"."))
| where SubDomainDepth > 5  // Deep subdomains
| summarize Count=count(), AvgLen=avg(QueryLen), SampleQuery=any(Name)
    by ClientIP, bin(TimeGenerated,5m)
| where Count > 20
| order by Count desc`,
    tags:['DNS-tunneling','T1071.004','exfiltration','C2']
  },
  {
    id:'hq-019', category:'Command & Control', severity:'high',
    name:'Cobalt Strike Beacon Detection',
    description:'Detects Cobalt Strike beacon activity via network patterns and process artifacts.',
    mitre:['T1071.001','T1095','T1055'],
    platform:'SIGMA',
    query:`# SIGMA Rule
title: Cobalt Strike Beacon Network Activity
status: experimental
author: EYEbot AI
description: Detects Cobalt Strike beacon activity
logsource:
    category: proxy
detection:
    selection_ua:
        c-useragent|contains:
            - 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
            - 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR'
    selection_uri:
        cs-uri-query|re: '^/[A-Za-z0-9]{4,8}$'
        cs-uri-stem|endswith:
            - '.jpg'
            - '.png'
            - '.gif'
            - '.ico'
    condition: selection_ua and selection_uri
level: high
tags:
    - attack.t1071.001
    - attack.command_and_control`,
    tags:['cobalt-strike','beacon','C2','T1071']
  },

  /* ─────── EXFILTRATION ─────── */
  {
    id:'hq-020', category:'Exfiltration', severity:'critical',
    name:'Large Data Upload Detection',
    description:'Identifies abnormally large outbound data transfers indicating potential exfiltration.',
    mitre:['T1041','T1048'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
CommonSecurityLog
| where DeviceVendor in ("Palo Alto Networks","Cisco","Fortinet","Check Point")
| where CommunicationDirection == "Outbound"
| summarize TotalBytes=sum(SentBytes), Sessions=count()
    by SourceIP, DestinationIP, DestinationPort, bin(TimeGenerated,1h)
| where TotalBytes > 100000000  // 100 MB threshold
| extend TotalMB = TotalBytes / 1000000
| order by TotalBytes desc`,
    tags:['exfiltration','data-theft','T1041','T1048']
  },
  {
    id:'hq-021', category:'Exfiltration', severity:'high',
    name:'Cloud Storage Exfiltration Hunt',
    description:'Detects data exfiltration to cloud storage services like Mega, pCloud, or anonymous upload sites.',
    mitre:['T1567.002'],
    platform:'SPL',
    query:`// SPL — Splunk
index=proxy sourcetype=bluecoat
| search dest_host IN (
    "*.mega.nz","*.pcloud.com","anonfiles.com",
    "file.io","transfer.sh","gofile.io","upload.io",
    "*.mediafire.com","*.sendspace.com")
| stats sum(bytes_out) AS total_upload_bytes, count
    by src_ip, dest_host, cs_username
| eval upload_mb = round(total_upload_bytes/1048576, 2)
| where upload_mb > 50
| sort -upload_mb`,
    tags:['cloud-exfil','T1567','file-sharing','upload']
  },

  /* ─────── PRIVILEGE ESCALATION ─────── */
  {
    id:'hq-022', category:'Privilege Escalation', severity:'critical',
    name:'Sudo Abuse on Linux',
    description:'Detects suspicious sudo usage indicating local privilege escalation attempts.',
    mitre:['T1548.003'],
    platform:'EQL',
    query:`// EQL — Elastic Security
sequence by host.name with maxspan=5m
  [process where event.type == "start"
   and process.name == "sudo"
   and process.args == "-l"]  // Enumeration
  [process where event.type == "start"
   and process.name == "sudo"
   and process.parent.name not in ("bash","sh","zsh")
   and (process.args contains "/bin/bash"
        or process.args contains "/bin/sh"
        or process.args contains "python")]`,
    tags:['sudo','privilege-escalation','T1548','linux']
  },
  {
    id:'hq-023', category:'Privilege Escalation', severity:'high',
    name:'UAC Bypass Detection',
    description:'Detects User Account Control bypass techniques used to elevate privileges on Windows.',
    mitre:['T1548.002'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where AccountDomain !in~ ("NT AUTHORITY","SYSTEM")
| where InitiatingProcessFileName in~ (
    "fodhelper.exe","eventvwr.exe","computerdefaults.exe",
    "sdclt.exe","slui.exe","WSReset.exe","cmstp.exe","mmc.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc`,
    tags:['UAC-bypass','T1548.002','privilege-escalation','LOLBin']
  },

  /* ─────── DEFENSE EVASION ─────── */
  {
    id:'hq-024', category:'Defense Evasion', severity:'high',
    name:'Security Tool Tampering',
    description:'Detects attempts to disable or tamper with security tools including AV, EDR, and audit logging.',
    mitre:['T1562.001','T1562.002'],
    platform:'KQL',
    query:`// KQL — Defender for Endpoint
DeviceProcessEvents
| where ProcessCommandLine has_any (
    // Windows Defender disable
    "Set-MpPreference -Disable","DisableRealtimeMonitoring",
    // Logging disable
    "auditpol /set","wevtutil cl","Clear-EventLog",
    // Firewall disable
    "netsh firewall set","netsh advfirewall set allprofiles state off",
    // AV stop
    "sc stop WinDefend","net stop MsMpSvc",
    // EDR bypass
    "taskkill /F /IM","wmic process delete")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc`,
    tags:['defense-evasion','T1562','AV-disable','security-tampering']
  },
  {
    id:'hq-025', category:'Defense Evasion', severity:'high',
    name:'Log Clearing Detection',
    description:'Detects Windows event log clearing — attacker anti-forensics technique.',
    mitre:['T1070.001'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel
SecurityEvent
| where EventID in (1102, 104)  // Security log cleared, System log cleared
| project TimeGenerated, Computer, EventID,
    Activity=iff(EventID==1102,"Security log cleared","System log cleared"),
    Account, AccountType
| order by TimeGenerated desc`,
    tags:['log-clearing','anti-forensics','T1070','event-log']
  },

  /* ─────── CLOUD SPECIFIC ─────── */
  {
    id:'hq-026', category:'Cloud', severity:'critical',
    name:'AWS CloudTrail - Suspicious API Activity',
    description:'Detects high-risk AWS API calls indicating account compromise or privilege escalation.',
    mitre:['T1078.004','T1098','T1535'],
    platform:'SPL',
    query:`// SPL — Splunk with AWS CloudTrail
index=aws_cloudtrail
| search eventName IN (
    "CreateUser","AttachUserPolicy","AttachRolePolicy",
    "CreateAccessKey","PutUserPolicy","AddUserToGroup",
    "CreateLoginProfile","UpdateLoginProfile",
    "CreatePolicyVersion","SetDefaultPolicyVersion")
| where userIdentity.type != "Service"
| stats count by userIdentity.arn, eventName, sourceIPAddress, awsRegion
| sort -count`,
    tags:['AWS','CloudTrail','IAM','T1078.004','cloud']
  },
  {
    id:'hq-027', category:'Cloud', severity:'high',
    name:'Azure AD Impossible Travel Detection',
    description:'Detects impossible travel login patterns indicating credential theft or VPN evasion.',
    mitre:['T1078.004'],
    platform:'KQL',
    query:`// KQL — Microsoft Sentinel (Azure AD)
SigninLogs
| where ResultType == 0  // Successful sign-in
| where isnotempty(LocationDetails)
| summarize Locations=make_set(tostring(LocationDetails.countryOrRegion)),
    LoginTimes=make_set(TimeGenerated), IPList=make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| extend Countries = strcat_array(Locations, " → ")
| project TimeGenerated, UserPrincipalName, Countries, IPList
| order by TimeGenerated desc`,
    tags:['impossible-travel','Azure-AD','T1078.004','authentication']
  },

  /* ─────── LINUX/UNIX ─────── */
  {
    id:'hq-028', category:'Linux', severity:'high',
    name:'Linux Cron Job Persistence',
    description:'Detects suspicious cron jobs added for persistence on Linux systems.',
    mitre:['T1053.003'],
    platform:'EQL',
    query:`// EQL — Elastic Security (Linux)
file where event.type in ("creation","modification")
and file.path like~ (
    "/etc/cron*","/var/spool/cron*","/etc/anacrontab")
and not process.name in ("cron","anacron","apt","dpkg","rpm","yum","zypper")
and not user.name in ("root","www-data")`,
    tags:['cron','persistence','T1053.003','linux']
  },
  {
    id:'hq-029', category:'Linux', severity:'critical',
    name:'Container Escape Attempt',
    description:'Detects container escape attempts via privileged operations or host path access.',
    mitre:['T1611','T1610'],
    platform:'SIGMA',
    query:`# SIGMA Rule
title: Container Escape via nsenter or chroot
status: experimental
author: EYEbot AI
description: Detects container escape techniques
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'nsenter --target 1'
            - 'nsenter -m -u -i -n -p -t 1'
            - 'chroot /host'
            - 'mount --bind /etc/passwd'
            - 'docker run --privileged'
            - 'docker run --cap-add=ALL'
    condition: selection
level: critical
tags:
    - attack.t1611
    - attack.privilege_escalation`,
    tags:['container-escape','kubernetes','T1611','docker']
  },

  /* ─────── MALWARE PATTERNS ─────── */
  {
    id:'hq-030', category:'Malware', severity:'high',
    name:'YARA Rule — Ransomware Patterns',
    description:'YARA rule to detect common ransomware patterns in memory and files.',
    mitre:['T1486','T1490'],
    platform:'YARA',
    query:`rule Wadjet_Ransomware_Generic {
    meta:
        description = "Detects common ransomware indicators"
        author = "EYEbot AI"
        severity = "CRITICAL"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom2 = "All your files are encrypted" nocase
        $ransom3 = "Send Bitcoin" nocase
        $ransom4 = "HOW TO RECOVER" nocase
        $mutex1 = "Global\\MsWinZonesCacheCounterMutexA"
        $api1 = "CryptEncrypt" ascii
        $api2 = "NtSetSystemInformation" ascii
        $api3 = "DeleteShadowCopy" nocase
        $vss = "vssadmin delete shadows" nocase
        $bcdedit = "bcdedit /set {default}" nocase
    condition:
        (2 of ($ransom*)) or
        ($vss and $bcdedit) or
        (3 of ($ext*) and 1 of ($api*))
}`,
    tags:['YARA','ransomware','T1486','malware-detection']
  },
  {
    id:'hq-031', category:'Malware', severity:'high',
    name:'Suricata — Emotet Network Indicators',
    description:'Suricata IDS rules to detect Emotet malware network communication patterns.',
    mitre:['T1071.001','T1041'],
    platform:'Suricata',
    query:`# Suricata Rules — Emotet Network Detection
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"WADJET Emotet HTTP C2 Communication";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/"; depth:1;
    http.uri; pcre:"/^\/[a-z0-9]{8,16}\/[a-z0-9]{8,16}$/";
    http.user_agent; content:"Mozilla/4.0 (compatible; MSIE";
    http.header; content:"Content-Type: application/x-www-form-urlencoded";
    threshold: type limit, track by_src, count 3, seconds 60;
    classtype:trojan-activity;
    sid:9000001; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET [443,8080,8443,4443] (
    msg:"WADJET Possible Emotet HTTPS C2";
    flow:established;
    content:"|16 03|"; depth:2;
    byte_test:1,>,0,2;
    detection_filter:track by_src, count 10, seconds 300;
    sid:9000002; rev:1;)`,
    tags:['suricata','emotet','IDS','network-detection','T1071']
  }
];

/* ── Main render function ── */
window.renderThreatHunting = function renderThreatHunting() {
  const container = document.getElementById('threatHuntingWrap');
  if (!container) return;

  // Also check alternate container
  const alt = document.getElementById('detectionTimelineLiveContainer');

  const platforms = [...new Set((window.HUNT_QUERIES||[]).map(q=>q.platform))];
  const categories = [...new Set((window.HUNT_QUERIES||[]).map(q=>q.category))];
  const total = (window.HUNT_QUERIES||[]).length;

  container.style.display = 'block';
  if (alt) alt.style.display = 'none';

  container.innerHTML = `
  <!-- Page Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-crosshairs" style="color:#ef4444;margin-right:8px"></i>
        Threat Hunting Workspace
      </h2>
      <div style="font-size:.78em;color:#8b949e;margin-top:2px">${total} hunt queries · KQL · SPL · SIGMA · EQL · YARA · Suricata</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <div style="background:#0a1628;border:1px solid #1e2d3d;border-radius:8px;padding:6px 14px;font-size:.78em;color:#22c55e">
        <i class="fas fa-circle" style="font-size:.5em;margin-right:4px;animation:livePulse 1.5s infinite"></i>Hunt Active
      </div>
    </div>
  </div>

  <!-- KPI strip -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:20px">
    ${[
      {label:'Total Queries',val:total,icon:'fa-search',c:'#3b82f6'},
      {label:'Platforms',val:platforms.length,icon:'fa-layer-group',c:'#8b5cf6'},
      {label:'Categories',val:categories.length,icon:'fa-tags',c:'#22c55e'},
      {label:'Critical Hunts',val:(window.HUNT_QUERIES||[]).filter(q=>q.severity==='critical').length,icon:'fa-fire',c:'#ef4444'},
    ].map(k=>`
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
      <div style="font-size:1.4em;font-weight:700;color:${k.c}">${k.val}</div>
      <div style="font-size:.7em;color:#8b949e;margin-top:2px"><i class="fas ${k.icon}" style="margin-right:3px"></i>${k.label}</div>
    </div>`).join('')}
  </div>

  <!-- Controls -->
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;align-items:center">
    <input id="hunt-search" placeholder="🔍 Search queries…" oninput="_huntSearch()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:180px"/>
    <select id="hunt-platform" onchange="_huntFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Platforms</option>
      ${platforms.map(p=>`<option value="${p}">${p}</option>`).join('')}
    </select>
    <select id="hunt-cat" onchange="_huntFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Categories</option>
      ${categories.map(c=>`<option value="${c}">${c}</option>`).join('')}
    </select>
    <select id="hunt-sev" onchange="_huntFilter()"
      style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
    </select>
    <button onclick="_huntReset()"
      style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:6px;font-size:.82em;cursor:pointer">
      <i class="fas fa-redo"></i> Reset</button>
    <span id="hunt-count" style="margin-left:auto;font-size:.8em;color:#8b949e"></span>
  </div>

  <!-- Platform pill filters -->
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px">
    ${platforms.map(p=>{
      const platColors={KQL:'#3b82f6',SPL:'#f59e0b',SIGMA:'#8b5cf6',EQL:'#22c55e',YARA:'#ef4444',Suricata:'#06b6d4'};
      const c=platColors[p]||'#8b949e';
      return `<span onclick="document.getElementById('hunt-platform').value='${p}';_huntFilter()"
        style="cursor:pointer;background:${c}18;color:${c};border:1px solid ${c}33;
          padding:3px 10px;border-radius:10px;font-size:.72em;font-weight:700">${p}</span>`;
    }).join('')}
  </div>

  <!-- Split view: Query List + Query Editor -->
  <div style="display:grid;grid-template-columns:340px 1fr;gap:16px;height:calc(100vh - 360px);min-height:500px">

    <!-- Left: Query List -->
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden;display:flex;flex-direction:column">
      <div style="padding:10px 14px;border-bottom:1px solid #21262d;font-size:.8em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.05em">
        <i class="fas fa-list" style="margin-right:6px"></i>Saved Hunts
      </div>
      <div id="hunt-list" style="overflow-y:auto;flex:1"></div>
    </div>

    <!-- Right: Query Editor -->
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden;display:flex;flex-direction:column">
      <div id="hunt-editor-header" style="padding:10px 14px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between;gap:8px">
        <div style="font-size:.85em;font-weight:700;color:#e6edf3">
          <i class="fas fa-terminal" style="color:#3b82f6;margin-right:6px"></i>Query Editor
        </div>
        <div style="display:flex;gap:6px">
          <button id="hunt-run-btn" onclick="_huntRun()"
            style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);
              padding:5px 14px;border-radius:6px;font-size:.78em;cursor:pointer">
            <i class="fas fa-play" style="margin-right:4px"></i>Run Hunt</button>
          <button onclick="_huntCopy()"
            style="background:#21262d;color:#8b949e;border:1px solid #30363d;
              padding:5px 12px;border-radius:6px;font-size:.78em;cursor:pointer">
            <i class="fas fa-copy"></i></button>
        </div>
      </div>
      <div id="hunt-meta" style="padding:10px 14px;border-bottom:1px solid #1e2d3d;font-size:.78em;color:#8b949e;display:none"></div>
      <textarea id="hunt-editor"
        style="flex:1;background:#080c14;border:none;color:#e6edf3;font-family:'Courier New',monospace;
          font-size:.82em;padding:14px;resize:none;outline:none;line-height:1.6"
        placeholder="// Select a hunt from the list, or write your own query here
// Supported: KQL (Microsoft Sentinel / Defender), SPL (Splunk), SIGMA, EQL (Elastic), YARA, Suricata
//
// Example KQL:
DeviceProcessEvents
| where FileName == &quot;powershell.exe&quot;
| where ProcessCommandLine contains &quot;-EncodedCommand&quot;
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc"></textarea>
      <div id="hunt-results" style="background:#050a12;border-top:1px solid #21262d;min-height:80px;max-height:180px;overflow-y:auto;padding:10px 14px">
        <div style="font-size:.78em;color:#8b949e">
          <i class="fas fa-info-circle" style="margin-right:6px"></i>Select a query from the list and click Run Hunt, or paste your own query.
        </div>
      </div>
    </div>
  </div>

  <!-- IOC Pivot Table (populated after run) -->
  <div id="hunt-ioc-pivot" style="margin-top:16px;display:none">
    <h4 style="font-size:.85em;font-weight:700;color:#e6edf3;margin-bottom:10px">
      <i class="fas fa-search-plus" style="color:#c9a227;margin-right:6px"></i>IOC Pivot Results
    </h4>
    <div id="hunt-ioc-table"></div>
  </div>
  `;

  _huntRenderList();
};

let _huntFilterState = {};
let _huntSearchTimer;

window._huntSearch = () => { clearTimeout(_huntSearchTimer); _huntSearchTimer = setTimeout(_huntFilter, 250); };
window._huntReset = () => {
  ['hunt-search','hunt-platform','hunt-cat','hunt-sev'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  _huntFilterState = {};
  _huntRenderList();
};
window._huntFilter = () => {
  _huntFilterState = {
    search: document.getElementById('hunt-search')?.value || '',
    platform: document.getElementById('hunt-platform')?.value || '',
    cat: document.getElementById('hunt-cat')?.value || '',
    sev: document.getElementById('hunt-sev')?.value || ''
  };
  _huntRenderList();
};

function _huntRenderList() {
  const list = document.getElementById('hunt-list');
  const cnt  = document.getElementById('hunt-count');
  if (!list) return;

  let qs = (window.HUNT_QUERIES || []);
  const f = _huntFilterState;
  if (f.platform) qs = qs.filter(q => q.platform === f.platform);
  if (f.cat)      qs = qs.filter(q => q.category === f.cat);
  if (f.sev)      qs = qs.filter(q => q.severity === f.sev);
  if (f.search) {
    const s = f.search.toLowerCase();
    qs = qs.filter(q => q.name.toLowerCase().includes(s) || q.description.toLowerCase().includes(s) || (q.tags||[]).some(t=>t.toLowerCase().includes(s)));
  }

  if (cnt) cnt.textContent = `${qs.length} queries`;

  const platColors = {KQL:'#3b82f6',SPL:'#f59e0b',SIGMA:'#8b5cf6',EQL:'#22c55e',YARA:'#ef4444',Suricata:'#06b6d4'};
  const sevColors  = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e'};

  if (!qs.length) {
    list.innerHTML = `<div style="text-align:center;padding:30px;color:#8b949e;font-size:.8em">No queries match filters</div>`;
    return;
  }

  list.innerHTML = qs.map(q => {
    const pc = platColors[q.platform] || '#8b949e';
    const sc = sevColors[q.severity] || '#8b949e';
    return `
    <div onclick="_huntLoad('${q.id}')" id="hunt-item-${q.id}"
      style="padding:10px 14px;border-bottom:1px solid #1a2030;cursor:pointer;transition:background .15s"
      onmouseover="this.style.background='#1a2030'" onmouseout="this.style.background='transparent'">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
        <span style="font-size:.8em;font-weight:600;color:#e6edf3">${_escH(q.name)}</span>
        <span style="background:${pc}18;color:${pc};border:1px solid ${pc}33;
          padding:1px 6px;border-radius:4px;font-size:.65em;font-weight:700;flex-shrink:0;margin-left:6px">${q.platform}</span>
      </div>
      <div style="display:flex;gap:6px;align-items:center">
        <span style="font-size:.7em;color:#8b949e">${q.category}</span>
        <span style="background:${sc}18;color:${sc};border:1px solid ${sc}33;
          padding:0px 5px;border-radius:4px;font-size:.65em;font-weight:600">${q.severity}</span>
      </div>
    </div>`;
  }).join('');
}

window._huntLoad = function(id) {
  const q = (window.HUNT_QUERIES || []).find(x => x.id === id);
  if (!q) return;

  // Highlight selected
  document.querySelectorAll('[id^="hunt-item-"]').forEach(el => el.style.background = 'transparent');
  const sel = document.getElementById(`hunt-item-${id}`);
  if (sel) sel.style.background = '#1e2d3d';

  const editor = document.getElementById('hunt-editor');
  const meta   = document.getElementById('hunt-meta');
  if (editor) editor.value = q.query;

  const platColors = {KQL:'#3b82f6',SPL:'#f59e0b',SIGMA:'#8b5cf6',EQL:'#22c55e',YARA:'#ef4444',Suricata:'#06b6d4'};
  const pc = platColors[q.platform] || '#8b949e';
  const sevColors = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e'};
  const sc = sevColors[q.severity] || '#8b949e';

  if (meta) {
    meta.style.display = 'block';
    meta.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      <strong style="color:#e6edf3">${_escH(q.name)}</strong>
      <span style="background:${pc}18;color:${pc};border:1px solid ${pc}33;padding:1px 7px;border-radius:4px;font-size:.72em">${q.platform}</span>
      <span style="background:${sc}18;color:${sc};border:1px solid ${sc}33;padding:1px 7px;border-radius:4px;font-size:.72em;text-transform:uppercase">${q.severity}</span>
      <span style="color:#8b949e;font-size:.75em">${q.category}</span>
      <span style="color:#8b949e;font-size:.75em">·</span>
      <span style="color:#8b949e;font-size:.75em">${q.description}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px">
      ${(q.mitre||[]).map(t=>`<span style="background:rgba(139,92,246,.1);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);padding:1px 7px;border-radius:4px;font-family:monospace;font-size:.72em">${t}</span>`).join('')}
      ${(q.tags||[]).map(t=>`<span style="background:#1e2d3d;color:#8b949e;padding:1px 6px;border-radius:3px;font-size:.7em">${t}</span>`).join('')}
    </div>`;
  }

  const results = document.getElementById('hunt-results');
  if (results) results.innerHTML = `<div style="font-size:.78em;color:#8b949e"><i class="fas fa-info-circle" style="margin-right:6px;color:#3b82f6"></i>Query loaded. Click <strong style="color:#22c55e">Run Hunt</strong> to simulate execution.</div>`;
};

window._huntRun = function() {
  const editor = document.getElementById('hunt-editor');
  const results = document.getElementById('hunt-results');
  if (!editor || !results) return;
  const query = editor.value.trim();
  if (!query) { if(window.showToast)showToast('Enter a query first','warning'); return; }

  results.innerHTML = `<div style="font-size:.78em;color:#22c55e">
    <i class="fas fa-spinner fa-spin" style="margin-right:6px"></i>Executing hunt query…
  </div>`;

  setTimeout(() => {
    // Simulate results
    const mockResults = [
      {time:'2025-03-26 14:23:11',host:'WORKSTATION-042',user:'john.smith',event:'Suspicious process detected',risk:'HIGH'},
      {time:'2025-03-26 14:18:45',host:'SERVER-DC01',user:'SYSTEM',event:'Anomalous authentication pattern',risk:'CRITICAL'},
      {time:'2025-03-26 13:55:22',host:'WORKSTATION-018',user:'admin.local',event:'Encoded command execution',risk:'HIGH'},
    ];

    results.innerHTML = `
    <div style="font-size:.75em;color:#22c55e;margin-bottom:8px">
      <i class="fas fa-check-circle" style="margin-right:4px"></i>Hunt completed — ${mockResults.length} events found (simulated)
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:.74em">
      <tr style="color:#8b949e;border-bottom:1px solid #21262d">
        <th style="text-align:left;padding:3px 8px">Time</th>
        <th style="text-align:left;padding:3px 8px">Host</th>
        <th style="text-align:left;padding:3px 8px">User</th>
        <th style="text-align:left;padding:3px 8px">Event</th>
        <th style="text-align:left;padding:3px 8px">Risk</th>
      </tr>
      ${mockResults.map(r=>{
        const rc = r.risk==='CRITICAL'?'#ef4444':'#f97316';
        return `<tr style="border-bottom:1px solid #1a2030">
          <td style="padding:4px 8px;color:#8b949e;font-family:monospace">${r.time}</td>
          <td style="padding:4px 8px;color:#e6edf3">${r.host}</td>
          <td style="padding:4px 8px;color:#3b82f6">${r.user}</td>
          <td style="padding:4px 8px;color:#e6edf3">${r.event}</td>
          <td style="padding:4px 8px"><span style="color:${rc};font-weight:700;font-size:.85em">${r.risk}</span></td>
        </tr>`;
      }).join('')}
    </table>`;

    if(window.showToast) showToast('Hunt query executed — 3 events found','success');
  }, 1200);
};

window._huntCopy = function() {
  const editor = document.getElementById('hunt-editor');
  if (!editor) return;
  navigator.clipboard.writeText(editor.value).then(()=>{
    if(window.showToast) showToast('Query copied to clipboard','success');
  }).catch(()=>{
    if(window.showToast) showToast('Copy failed','error');
  });
};

function _escH(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
