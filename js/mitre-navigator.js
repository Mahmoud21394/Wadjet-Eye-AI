/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — MITRE ATT&CK Navigator v3.0
 *  Full interactive ATT&CK matrix v14 with tactic/technique
 *  descriptions, manual customization, and coverage overlay
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* Full ATT&CK v14 taxonomy */
window.MITRE_TACTICS = [
  {
    id:'TA0043', name:'Reconnaissance',
    desc:'The adversary is trying to gather information they can use to plan future operations. This includes techniques involving active or passive gathering of information about a target organization, such as gathering victim identity information, gathering victim network information, and gathering victim org information.',
    color:'#ef4444',
    techniques:[
      {id:'T1595',sub:'T1595.001',name:'Active Scanning: Scanning IP Blocks',short:'Active Scanning',desc:'Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic.',covered:true,alerts:12},
      {id:'T1592',sub:'T1592.002',name:'Gather Victim Host Info: Software',short:'Victim Host Info',desc:'Adversaries may gather information about the victim\'s host software that can be used during targeting, including OS type, version, installed applications, and patch level.',covered:true,alerts:3},
      {id:'T1589',sub:'T1589.001',name:'Gather Victim Identity Info: Credentials',short:'Victim Identity Info',desc:'Adversaries may gather credential information about the victim that can be used during targeting, including leaked credentials and account enumeration.',covered:true,alerts:7},
      {id:'T1590',sub:null,name:'Gather Victim Network Information',short:'Network Info',desc:'Adversaries may gather information about the victim\'s networks that can be used during targeting, including network topology, IP ranges, and domain information.',covered:false,alerts:0},
      {id:'T1591',sub:null,name:'Gather Victim Org Information',short:'Org Information',desc:'Adversaries may gather information about the victim\'s organization that can be used during targeting, including org structure, employee information, and business relationships.',covered:false,alerts:0},
      {id:'T1598',sub:'T1598.003',name:'Phishing for Information: Spearphishing Link',short:'Phishing for Info',desc:'Adversaries may send spearphishing messages with a malicious link to elicit sensitive information from the target.',covered:true,alerts:19},
      {id:'T1597',sub:null,name:'Search Closed Sources',short:'Closed Sources',desc:'Adversaries may search and gather information about victims from closed sources such as criminal marketplaces and dark web forums.',covered:false,alerts:0},
      {id:'T1596',sub:null,name:'Search Open Technical Databases',short:'Open Tech Databases',desc:'Adversaries may search freely available technical databases for information about victims, including WHOIS, DNS records, and certificate transparency logs.',covered:false,alerts:0},
      {id:'T1593',sub:null,name:'Search Open Websites/Domains',short:'Open Websites',desc:'Adversaries may search freely available websites and domains to gather information about victims, including social media, job postings, and public repositories.',covered:true,alerts:2},
      {id:'T1594',sub:null,name:'Search Victim-Owned Websites',short:'Victim Websites',desc:'Adversaries may search websites owned by the victim for information that can be used during targeting.',covered:false,alerts:0}
    ]
  },
  {
    id:'TA0042', name:'Resource Development',
    desc:'The adversary is trying to establish resources they can use to support operations. Resource development techniques include acquiring infrastructure like domains, hosting, and accounts, and developing capabilities like malware or exploits.',
    color:'#f97316',
    techniques:[
      {id:'T1583',sub:'T1583.001',name:'Acquire Infrastructure: Domains',short:'Acquire Domains',desc:'Adversaries may acquire domains that can be used during targeting, including typosquatting and lookalike domains for phishing or C2 infrastructure.',covered:true,alerts:8},
      {id:'T1586',sub:'T1586.002',name:'Compromise Accounts: Email Accounts',short:'Compromise Accounts',desc:'Adversaries may compromise accounts with access to trusted third-party services that can be used during targeting.',covered:true,alerts:5},
      {id:'T1584',sub:'T1584.004',name:'Compromise Infrastructure: Server',short:'Compromise Infra',desc:'Adversaries may compromise third-party infrastructure that can be used during targeting, including legitimate servers for C2.',covered:false,alerts:0},
      {id:'T1587',sub:'T1587.001',name:'Develop Capabilities: Malware',short:'Develop Malware',desc:'Adversaries may develop malware and malware components that can be used during targeting.',covered:true,alerts:14},
      {id:'T1585',sub:'T1585.001',name:'Establish Accounts: Social Media Accounts',short:'Establish Accounts',desc:'Adversaries may create and cultivate accounts with services that can be used during targeting.',covered:false,alerts:0},
      {id:'T1588',sub:'T1588.002',name:'Obtain Capabilities: Tool',short:'Obtain Tools',desc:'Adversaries may buy and/or steal capabilities that can be used during targeting, including open-source exploitation frameworks.',covered:false,alerts:0},
      {id:'T1608',sub:'T1608.001',name:'Stage Capabilities: Upload Malware',short:'Stage Malware',desc:'Adversaries may upload malware to third-party or adversary-controlled infrastructure to make it accessible during targeting.',covered:false,alerts:0}
    ]
  },
  {
    id:'TA0001', name:'Initial Access',
    desc:'The adversary is trying to get into your network. Initial Access techniques use various entry vectors to gain their initial foothold within a network, including targeted spearphishing and exploiting weaknesses on public-facing web servers.',
    color:'#f59e0b',
    techniques:[
      {id:'T1189',sub:null,name:'Drive-by Compromise',short:'Drive-by',desc:'Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.',covered:true,alerts:4},
      {id:'T1190',sub:null,name:'Exploit Public-Facing Application',short:'Exploit Web App',desc:'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.',covered:true,alerts:156},
      {id:'T1133',sub:null,name:'External Remote Services',short:'Remote Services',desc:'Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms.',covered:true,alerts:22},
      {id:'T1200',sub:null,name:'Hardware Additions',short:'Hardware',desc:'Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access.',covered:false,alerts:0},
      {id:'T1566',sub:'T1566.001',name:'Phishing: Spearphishing Attachment',short:'Phishing',desc:'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.',covered:true,alerts:89},
      {id:'T1091',sub:null,name:'Replication Through Removable Media',short:'Removable Media',desc:'Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media.',covered:true,alerts:1},
      {id:'T1195',sub:'T1195.002',name:'Supply Chain Compromise: Compromise Software Supply Chain',short:'Supply Chain',desc:'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.',covered:true,alerts:3},
      {id:'T1199',sub:null,name:'Trusted Relationship',short:'Trusted Relationship',desc:'Adversaries may breach or otherwise leverage organizations who have access to intended victims, including IT service providers and managed security service providers.',covered:false,alerts:0},
      {id:'T1078',sub:'T1078.002',name:'Valid Accounts: Domain Accounts',short:'Valid Accounts',desc:'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.',covered:true,alerts:67}
    ]
  },
  {
    id:'TA0002', name:'Execution',
    desc:'The adversary is trying to run malicious code. Execution techniques represent ways that adversaries run their code on a local or remote system.',
    color:'#eab308',
    techniques:[
      {id:'T1059',sub:'T1059.001',name:'Command and Scripting Interpreter: PowerShell',short:'PowerShell',desc:'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.',covered:true,alerts:203},
      {id:'T1609',sub:null,name:'Container Administration Command',short:'Container Cmd',desc:'Adversaries may abuse a container administration service to execute commands within a container.',covered:false,alerts:0},
      {id:'T1610',sub:null,name:'Deploy Container',short:'Deploy Container',desc:'Adversaries may deploy a container into an environment to facilitate execution or evade defenses.',covered:false,alerts:0},
      {id:'T1203',sub:null,name:'Exploitation for Client Execution',short:'Client Exploit',desc:'Adversaries may exploit software vulnerabilities in client applications to execute code.',covered:true,alerts:31},
      {id:'T1559',sub:null,name:'Inter-Process Communication',short:'IPC',desc:'Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution.',covered:false,alerts:0},
      {id:'T1106',sub:null,name:'Native API',short:'Native API',desc:'Adversaries may interact with the native OS application programming interface (API) to execute behaviors.',covered:true,alerts:18},
      {id:'T1053',sub:'T1053.005',name:'Scheduled Task/Job: Scheduled Task',short:'Scheduled Task',desc:'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.',covered:true,alerts:44},
      {id:'T1129',sub:null,name:'Shared Modules',short:'Shared Modules',desc:'Adversaries may execute malicious payloads via loading shared modules.',covered:false,alerts:0},
      {id:'T1072',sub:null,name:'Software Deployment Tools',short:'Deploy Tools',desc:'Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands.',covered:true,alerts:7},
      {id:'T1569',sub:'T1569.002',name:'System Services: Service Execution',short:'Service Exec',desc:'Adversaries may abuse system services or daemons to execute commands or programs.',covered:true,alerts:28},
      {id:'T1204',sub:'T1204.002',name:'User Execution: Malicious File',short:'User Execution',desc:'An adversary may rely upon specific actions by a user in order to gain execution.',covered:true,alerts:62},
      {id:'T1047',sub:null,name:'Windows Management Instrumentation',short:'WMI',desc:'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.',covered:true,alerts:39}
    ]
  },
  {
    id:'TA0003', name:'Persistence',
    desc:'The adversary is trying to maintain their foothold. Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.',
    color:'#22c55e',
    techniques:[
      {id:'T1098',sub:'T1098.001',name:'Account Manipulation: Additional Cloud Credentials',short:'Account Manipulation',desc:'Adversaries may manipulate accounts to maintain access to victim systems.',covered:true,alerts:15},
      {id:'T1197',sub:null,name:'BITS Jobs',short:'BITS Jobs',desc:'Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.',covered:true,alerts:8},
      {id:'T1547',sub:'T1547.001',name:'Boot or Logon Autostart Execution: Registry Run Keys',short:'Autostart Execution',desc:'Adversaries may configure system settings to automatically execute a program during system boot or logon.',covered:true,alerts:56},
      {id:'T1037',sub:null,name:'Boot or Logon Initialization Scripts',short:'Init Scripts',desc:'Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.',covered:true,alerts:9},
      {id:'T1176',sub:null,name:'Browser Extensions',short:'Browser Extensions',desc:'Adversaries may abuse Internet browser extensions to establish persistent access to victim systems.',covered:false,alerts:0},
      {id:'T1554',sub:null,name:'Compromise Client Software Binary',short:'Client Binary',desc:'Adversaries may modify client software binaries to establish persistent access to systems.',covered:false,alerts:0},
      {id:'T1136',sub:'T1136.001',name:'Create Account: Local Account',short:'Create Account',desc:'Adversaries may create an account to maintain access to victim systems.',covered:true,alerts:23},
      {id:'T1543',sub:'T1543.003',name:'Create or Modify System Process: Windows Service',short:'System Process',desc:'Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.',covered:true,alerts:17},
      {id:'T1546',sub:'T1546.003',name:'Event Triggered Execution: Windows Management Instrumentation Event Subscription',short:'Event Triggered',desc:'Adversaries may establish persistence using system mechanisms that trigger execution based on specific events.',covered:true,alerts:12},
      {id:'T1574',sub:'T1574.001',name:'Hijack Execution Flow: DLL Search Order Hijacking',short:'Hijack Execution',desc:'Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs.',covered:true,alerts:28},
      {id:'T1525',sub:null,name:'Implant Internal Image',short:'Implant Image',desc:'Adversaries may implant cloud or container images with malicious code to establish persistence.',covered:false,alerts:0},
      {id:'T1053',sub:'T1053.005',name:'Scheduled Task/Job: Scheduled Task',short:'Sched Task (P)',desc:'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution.',covered:true,alerts:44},
      {id:'T1505',sub:'T1505.003',name:'Server Software Component: Web Shell',short:'Web Shell',desc:'Adversaries may backdoor web servers with web shells to establish persistent access to systems.',covered:true,alerts:19},
      {id:'T1078',sub:'T1078.002',name:'Valid Accounts',short:'Valid Accounts (P)',desc:'Adversaries may obtain and abuse credentials of existing accounts.',covered:true,alerts:67}
    ]
  },
  {
    id:'TA0004', name:'Privilege Escalation',
    desc:'The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network.',
    color:'#06b6d4',
    techniques:[
      {id:'T1548',sub:'T1548.002',name:'Abuse Elevation Control Mechanism: Bypass UAC',short:'UAC Bypass',desc:'Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.',covered:true,alerts:34},
      {id:'T1134',sub:'T1134.001',name:'Access Token Manipulation: Token Impersonation/Theft',short:'Token Manipulation',desc:'Adversaries may modify access tokens to operate under a different user or system security context.',covered:true,alerts:12},
      {id:'T1068',sub:null,name:'Exploitation for Privilege Escalation',short:'Exploit Priv Esc',desc:'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.',covered:true,alerts:47},
      {id:'T1574',sub:'T1574.004',name:'Hijack Execution Flow: Dylib Hijacking',short:'Exec Flow Hijack',desc:'Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs.',covered:true,alerts:28},
      {id:'T1055',sub:'T1055.001',name:'Process Injection: Dynamic-link Library Injection',short:'Process Injection',desc:'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.',covered:true,alerts:78},
      {id:'T1053',sub:'T1053.005',name:'Scheduled Task/Job',short:'Sched Task (PE)',desc:'Adversaries may abuse task scheduling functionality to escalate privileges.',covered:true,alerts:44},
      {id:'T1078',sub:'T1078.003',name:'Valid Accounts: Local Accounts',short:'Valid Accounts (PE)',desc:'Adversaries may obtain and abuse credentials of local accounts.',covered:true,alerts:67}
    ]
  },
  {
    id:'TA0005', name:'Defense Evasion',
    desc:'The adversary is trying to avoid being detected. Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise.',
    color:'#8b5cf6',
    techniques:[
      {id:'T1548',sub:'T1548.002',name:'Abuse Elevation Control: Bypass UAC',short:'Abuse Elevation',desc:'Adversaries may circumvent mechanisms designed to control elevate privileges.',covered:true,alerts:34},
      {id:'T1134',sub:null,name:'Access Token Manipulation',short:'Token Manipulation',desc:'Adversaries may modify access tokens to operate under a different security context.',covered:true,alerts:12},
      {id:'T1197',sub:null,name:'BITS Jobs',short:'BITS Jobs',desc:'Adversaries may abuse BITS jobs to download, execute, and clean up after performing nefarious operations.',covered:true,alerts:8},
      {id:'T1140',sub:null,name:'Deobfuscate/Decode Files or Information',short:'Deobfuscate',desc:'Adversaries may use obfuscated files or information to hide artifacts of an intrusion.',covered:true,alerts:93},
      {id:'T1006',sub:null,name:'Direct Volume Access',short:'Direct Volume',desc:'Adversaries may directly access a volume to bypass file access controls and file system monitoring.',covered:false,alerts:0},
      {id:'T1562',sub:'T1562.001',name:'Impair Defenses: Disable or Modify Tools',short:'Impair Defenses',desc:'Adversaries may maliciously modify components of a victim\'s environment in order to hinder or disable defensive mechanisms.',covered:true,alerts:29},
      {id:'T1070',sub:'T1070.001',name:'Indicator Removal: Clear Windows Event Logs',short:'Indicator Removal',desc:'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.',covered:true,alerts:18},
      {id:'T1036',sub:'T1036.005',name:'Masquerading: Match Legitimate Name or Location',short:'Masquerading',desc:'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.',covered:true,alerts:42},
      {id:'T1027',sub:'T1027.001',name:'Obfuscated Files or Information: Binary Padding',short:'Obfuscation',desc:'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.',covered:true,alerts:67},
      {id:'T1542',sub:null,name:'Pre-OS Boot',short:'Pre-OS Boot',desc:'Adversaries may abuse pre-OS boot mechanisms as a way to establish persistence on a system.',covered:false,alerts:0},
      {id:'T1055',sub:'T1055.012',name:'Process Injection: Process Hollowing',short:'Process Hollow',desc:'Adversaries may inject malicious code into suspended and hollowed processes.',covered:true,alerts:78},
      {id:'T1207',sub:null,name:'Rogue Domain Controller',short:'Rogue DC',desc:'Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.',covered:false,alerts:0},
      {id:'T1553',sub:'T1553.002',name:'Subvert Trust Controls: Code Signing',short:'Subvert Trust',desc:'Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs.',covered:true,alerts:11},
      {id:'T1218',sub:'T1218.011',name:'System Binary Proxy Execution: Rundll32',short:'LOLBins',desc:'Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.',covered:true,alerts:56},
      {id:'T1078',sub:null,name:'Valid Accounts',short:'Valid Accounts (DE)',desc:'Adversaries may obtain and abuse credentials of existing accounts as a means of evading defenses.',covered:true,alerts:67}
    ]
  },
  {
    id:'TA0006', name:'Credential Access',
    desc:'The adversary is trying to steal account names and passwords. Credential Access consists of techniques for stealing credentials like account names and passwords.',
    color:'#ec4899',
    techniques:[
      {id:'T1110',sub:'T1110.003',name:'Brute Force: Password Spraying',short:'Brute Force',desc:'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.',covered:true,alerts:128},
      {id:'T1555',sub:'T1555.003',name:'Credentials from Password Stores: Credentials from Web Browsers',short:'Password Stores',desc:'Adversaries may search for common password storage locations to obtain user credentials.',covered:true,alerts:24},
      {id:'T1212',sub:null,name:'Exploitation for Credential Access',short:'Exploit Creds',desc:'Adversaries may exploit software vulnerabilities in an attempt to collect credentials.',covered:true,alerts:15},
      {id:'T1187',sub:null,name:'Forced Authentication',short:'Forced Auth',desc:'Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information.',covered:true,alerts:8},
      {id:'T1056',sub:'T1056.001',name:'Input Capture: Keylogging',short:'Input Capture',desc:'Adversaries may use methods of capturing user input to obtain credentials or collect information.',covered:true,alerts:12},
      {id:'T1557',sub:'T1557.001',name:'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning',short:'AitM',desc:'Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle technique.',covered:true,alerts:9},
      {id:'T1556',sub:null,name:'Modify Authentication Process',short:'Modify Auth',desc:'Adversaries may modify authentication mechanisms and processes to access user credentials.',covered:false,alerts:0},
      {id:'T1040',sub:null,name:'Network Sniffing',short:'Sniffing',desc:'Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.',covered:true,alerts:6},
      {id:'T1003',sub:'T1003.001',name:'OS Credential Dumping: LSASS Memory',short:'Credential Dumping',desc:'Adversaries may attempt to dump credentials to obtain account login and credential material.',covered:true,alerts:94},
      {id:'T1528',sub:null,name:'Steal Application Access Token',short:'Steal App Token',desc:'Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.',covered:true,alerts:7},
      {id:'T1539',sub:null,name:'Steal Web Session Cookie',short:'Steal Cookie',desc:'An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services.',covered:true,alerts:11},
      {id:'T1558',sub:'T1558.003',name:'Steal or Forge Kerberos Tickets: Kerberoasting',short:'Kerberoasting',desc:'Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets.',covered:true,alerts:33}
    ]
  },
  {
    id:'TA0007', name:'Discovery',
    desc:'The adversary is trying to figure out your environment. Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network.',
    color:'#14b8a6',
    techniques:[
      {id:'T1087',sub:'T1087.002',name:'Account Discovery: Domain Account',short:'Account Discovery',desc:'Adversaries may attempt to get a listing of accounts on a system or within an environment.',covered:true,alerts:45},
      {id:'T1010',sub:null,name:'Application Window Discovery',short:'Window Discovery',desc:'Adversaries may attempt to get a listing of open application windows.',covered:false,alerts:0},
      {id:'T1217',sub:null,name:'Browser Bookmark Discovery',short:'Browser Bookmarks',desc:'Adversaries may enumerate browser bookmarks to learn more about compromised hosts.',covered:false,alerts:0},
      {id:'T1580',sub:null,name:'Cloud Infrastructure Discovery',short:'Cloud Discovery',desc:'An adversary may attempt to discover resources that are available within an infrastructure-as-a-service (IaaS) environment.',covered:true,alerts:12},
      {id:'T1482',sub:null,name:'Domain Trust Discovery',short:'Domain Trust',desc:'Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities.',covered:true,alerts:18},
      {id:'T1083',sub:null,name:'File and Directory Discovery',short:'File Discovery',desc:'Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information.',covered:true,alerts:29},
      {id:'T1046',sub:null,name:'Network Service Discovery',short:'Port Scanning',desc:'Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure.',covered:true,alerts:38},
      {id:'T1135',sub:null,name:'Network Share Discovery',short:'Share Discovery',desc:'Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information.',covered:true,alerts:22},
      {id:'T1040',sub:null,name:'Network Sniffing',short:'Net Sniffing',desc:'Adversaries may sniff network traffic to capture information about an environment.',covered:true,alerts:6},
      {id:'T1201',sub:null,name:'Password Policy Discovery',short:'Password Policy',desc:'Adversaries may attempt to access detailed information about the password policy used within an enterprise network.',covered:false,alerts:0},
      {id:'T1120',sub:null,name:'Peripheral Device Discovery',short:'Peripheral Device',desc:'Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.',covered:false,alerts:0},
      {id:'T1069',sub:'T1069.002',name:'Permission Groups Discovery: Domain Groups',short:'Permission Groups',desc:'Adversaries may attempt to discover group and permission settings.',covered:true,alerts:31},
      {id:'T1057',sub:null,name:'Process Discovery',short:'Process Discovery',desc:'Adversaries may attempt to get information about running processes on a system.',covered:true,alerts:17},
      {id:'T1018',sub:null,name:'Remote System Discovery',short:'Remote Systems',desc:'Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.',covered:true,alerts:26},
      {id:'T1082',sub:null,name:'System Information Discovery',short:'System Info',desc:'An adversary may attempt to get detailed information about the operating system and hardware.',covered:true,alerts:48}
    ]
  },
  {
    id:'TA0008', name:'Lateral Movement',
    desc:'The adversary is trying to move through your environment. Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network.',
    color:'#f97316',
    techniques:[
      {id:'T1210',sub:null,name:'Exploitation of Remote Services',short:'Exploit Remote',desc:'Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.',covered:true,alerts:27},
      {id:'T1534',sub:null,name:'Internal Spearphishing',short:'Internal Phishing',desc:'Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization.',covered:true,alerts:14},
      {id:'T1570',sub:null,name:'Lateral Tool Transfer',short:'Tool Transfer',desc:'Adversaries may transfer tools or other files between systems in a compromised environment.',covered:true,alerts:33},
      {id:'T1563',sub:'T1563.002',name:'Remote Service Session Hijacking: RDP Hijacking',short:'Session Hijack',desc:'Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.',covered:true,alerts:9},
      {id:'T1021',sub:'T1021.002',name:'Remote Services: SMB/Windows Admin Shares',short:'Remote Services',desc:'Adversaries may use Valid Accounts to interact with a remote network share using SMB.',covered:true,alerts:62},
      {id:'T1550',sub:'T1550.002',name:'Use Alternate Authentication Material: Pass the Hash',short:'Pass-the-Hash',desc:'Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens.',covered:true,alerts:45},
      {id:'T1047',sub:null,name:'Windows Management Instrumentation',short:'WMI Lateral',desc:'Adversaries may use Windows Management Instrumentation (WMI) to move laterally.',covered:true,alerts:39}
    ]
  },
  {
    id:'TA0009', name:'Collection',
    desc:'The adversary is trying to gather data of interest to their goal. Collection consists of techniques adversaries may use to gather information and the sources information is collected from.',
    color:'#6366f1',
    techniques:[
      {id:'T1560',sub:'T1560.001',name:'Archive Collected Data: Archive via Utility',short:'Archive Data',desc:'An adversary may compress and/or encrypt data that is collected prior to exfiltration.',covered:true,alerts:19},
      {id:'T1123',sub:null,name:'Audio Capture',short:'Audio Capture',desc:'An adversary can leverage a computer\'s peripheral devices (e.g., microphones and webcams) or applications to capture audio recordings.',covered:false,alerts:0},
      {id:'T1119',sub:null,name:'Automated Collection',short:'Auto Collection',desc:'Once established within a system or network, an adversary may use automated techniques for collecting internal data.',covered:true,alerts:14},
      {id:'T1115',sub:null,name:'Clipboard Data',short:'Clipboard',desc:'Adversaries may collect data stored in the clipboard from users copying information within or between applications.',covered:true,alerts:7},
      {id:'T1530',sub:null,name:'Data from Cloud Storage',short:'Cloud Storage',desc:'Adversaries may access data from cloud storage such as S3 buckets or Azure Blob Storage.',covered:true,alerts:21},
      {id:'T1213',sub:'T1213.002',name:'Data from Information Repositories: Sharepoint',short:'Data from Repos',desc:'Adversaries may leverage information repositories to mine valuable information.',covered:true,alerts:9},
      {id:'T1005',sub:null,name:'Data from Local System',short:'Local Data',desc:'Adversaries may search local system sources to find files of interest and sensitive data.',covered:true,alerts:31},
      {id:'T1039',sub:null,name:'Data from Network Shared Drive',short:'Network Share Data',desc:'Adversaries may search network shares on computers they have compromised to find files of interest.',covered:true,alerts:16},
      {id:'T1025',sub:null,name:'Data from Removable Media',short:'Removable Media',desc:'Adversaries may search connected removable media on computers they have compromised to find files of interest.',covered:false,alerts:0},
      {id:'T1074',sub:'T1074.002',name:'Data Staged: Remote Data Staging',short:'Data Staged',desc:'Adversaries may stage collected data in a central location or directory prior to Exfiltration.',covered:true,alerts:12},
      {id:'T1114',sub:'T1114.002',name:'Email Collection: Remote Email Collection',short:'Email Collection',desc:'Adversaries may target user email to collect sensitive information.',covered:true,alerts:28},
      {id:'T1056',sub:'T1056.001',name:'Input Capture: Keylogging',short:'Keylogging',desc:'Adversaries may use methods of capturing user input to obtain credentials or collect information.',covered:true,alerts:12},
      {id:'T1113',sub:null,name:'Screen Capture',short:'Screen Capture',desc:'Adversaries may attempt to take screen captures of the desktop to gather information.',covered:true,alerts:8},
      {id:'T1125',sub:null,name:'Video Capture',short:'Video Capture',desc:'An adversary can leverage a computer\'s peripheral devices or applications to capture video recordings.',covered:false,alerts:0}
    ]
  },
  {
    id:'TA0011', name:'Command & Control',
    desc:'The adversary is trying to communicate with compromised systems to control them. Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network.',
    color:'#c9a227',
    techniques:[
      {id:'T1071',sub:'T1071.001',name:'Application Layer Protocol: Web Protocols',short:'App Layer Protocol',desc:'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.',covered:true,alerts:134},
      {id:'T1092',sub:null,name:'Communication Through Removable Media',short:'Removable Media C2',desc:'Adversaries can perform command and control between compromised hosts on potentially disconnected networks.',covered:false,alerts:0},
      {id:'T1132',sub:'T1132.001',name:'Data Encoding: Standard Encoding',short:'Data Encoding',desc:'Adversaries may encode data to make the content of command and control traffic more difficult to detect.',covered:true,alerts:22},
      {id:'T1001',sub:null,name:'Data Obfuscation',short:'Data Obfuscation',desc:'Adversaries may obfuscate command and control traffic to make it more difficult to detect.',covered:true,alerts:31},
      {id:'T1568',sub:'T1568.002',name:'Dynamic Resolution: Domain Generation Algorithms',short:'Dynamic DNS',desc:'Adversaries may dynamically establish connections to command and control infrastructure.',covered:true,alerts:18},
      {id:'T1573',sub:'T1573.001',name:'Encrypted Channel: Symmetric Cryptography',short:'Encrypted Channel',desc:'Adversaries may employ a known encryption algorithm to conceal command and control traffic.',covered:true,alerts:47},
      {id:'T1008',sub:null,name:'Fallback Channels',short:'Fallback Channels',desc:'Adversaries may use fallback or alternate communication channels if the primary channel is compromised.',covered:false,alerts:0},
      {id:'T1105',sub:null,name:'Ingress Tool Transfer',short:'Tool Transfer C2',desc:'Adversaries may transfer tools or other files from an external system into a compromised environment.',covered:true,alerts:58},
      {id:'T1104',sub:null,name:'Multi-Stage Channels',short:'Multi-Stage C2',desc:'Adversaries may create multiple stages for command and control that are employed under different conditions.',covered:false,alerts:0},
      {id:'T1095',sub:null,name:'Non-Application Layer Protocol',short:'Non-App Protocol',desc:'Adversaries may use an OSI non-application layer protocol for communication between host and C2 server.',covered:true,alerts:29},
      {id:'T1571',sub:null,name:'Non-Standard Port',short:'Non-Std Port',desc:'Adversaries may communicate using a protocol and port pairing that are typically not associated.',covered:true,alerts:37},
      {id:'T1572',sub:null,name:'Protocol Tunneling',short:'Protocol Tunnel',desc:'Adversaries may tunnel network communications to and from a victim system within a separate protocol.',covered:true,alerts:23},
      {id:'T1090',sub:'T1090.003',name:'Proxy: Multi-hop Proxy',short:'Proxy',desc:'Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.',covered:true,alerts:15},
      {id:'T1219',sub:null,name:'Remote Access Software',short:'Remote Access',desc:'An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel.',covered:true,alerts:44},
      {id:'T1205',sub:null,name:'Traffic Signaling',short:'Traffic Signal',desc:'Adversaries may use traffic signaling to hide open ports or other malicious functionality.',covered:false,alerts:0},
      {id:'T1102',sub:'T1102.002',name:'Web Service: Bidirectional Communication',short:'Web Service C2',desc:'Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.',covered:true,alerts:19}
    ]
  },
  {
    id:'TA0010', name:'Exfiltration',
    desc:'The adversary is trying to steal data. Exfiltration consists of techniques that adversaries may use to steal data from your network.',
    color:'#3b82f6',
    techniques:[
      {id:'T1020',sub:null,name:'Automated Exfiltration',short:'Auto Exfil',desc:'Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered.',covered:true,alerts:16},
      {id:'T1030',sub:null,name:'Data Transfer Size Limits',short:'Size Limits',desc:'An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds.',covered:false,alerts:0},
      {id:'T1048',sub:'T1048.003',name:'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol',short:'Alt Protocol Exfil',desc:'Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.',covered:true,alerts:28},
      {id:'T1041',sub:null,name:'Exfiltration Over C2 Channel',short:'C2 Exfil',desc:'Adversaries may steal data by exfiltrating it over an existing command and control channel.',covered:true,alerts:44},
      {id:'T1011',sub:null,name:'Exfiltration Over Other Network Medium',short:'Other Network',desc:'Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel.',covered:false,alerts:0},
      {id:'T1052',sub:null,name:'Exfiltration Over Physical Medium',short:'Physical Medium',desc:'Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive.',covered:false,alerts:0},
      {id:'T1567',sub:'T1567.002',name:'Exfiltration Over Web Service: Exfiltration to Cloud Storage',short:'Cloud Storage Exfil',desc:'Adversaries may use an existing, legitimate external Web service to exfiltrate data.',covered:true,alerts:33},
      {id:'T1029',sub:null,name:'Scheduled Transfer',short:'Scheduled Transfer',desc:'Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals.',covered:false,alerts:0}
    ]
  },
  {
    id:'TA0040', name:'Impact',
    desc:'The adversary is trying to manipulate, interrupt, or destroy your systems and data. Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes.',
    color:'#ef4444',
    techniques:[
      {id:'T1531',sub:null,name:'Account Access Removal',short:'Account Removal',desc:'Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.',covered:true,alerts:4},
      {id:'T1485',sub:null,name:'Data Destruction',short:'Data Destruction',desc:'Adversaries may destroy data and files on specific systems or in large numbers on a network.',covered:true,alerts:6},
      {id:'T1486',sub:null,name:'Data Encrypted for Impact',short:'Ransomware',desc:'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.',covered:true,alerts:23},
      {id:'T1565',sub:null,name:'Data Manipulation',short:'Data Manipulation',desc:'Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity.',covered:true,alerts:8},
      {id:'T1491',sub:null,name:'Defacement',short:'Defacement',desc:'Adversaries may modify visual content available internally or externally to an enterprise network.',covered:false,alerts:0},
      {id:'T1561',sub:null,name:'Disk Wipe',short:'Disk Wipe',desc:'Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network.',covered:true,alerts:3},
      {id:'T1499',sub:'T1499.003',name:'Endpoint Denial of Service: Application Exhaustion Flood',short:'App DoS',desc:'Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services.',covered:true,alerts:14},
      {id:'T1495',sub:null,name:'Firmware Corruption',short:'Firmware',desc:'Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware.',covered:false,alerts:0},
      {id:'T1490',sub:null,name:'Inhibit System Recovery',short:'No Recovery',desc:'Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery and restoration of a system.',covered:true,alerts:19},
      {id:'T1498',sub:'T1498.001',name:'Network Denial of Service: Direct Network Flood',short:'Network DoS',desc:'Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.',covered:true,alerts:11},
      {id:'T1496',sub:null,name:'Resource Hijacking',short:'Cryptomining',desc:'Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems.',covered:true,alerts:67},
      {id:'T1489',sub:null,name:'Service Stop',short:'Service Stop',desc:'Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.',covered:true,alerts:9}
    ]
  }
];

/* ── User customization state ── */
window.MITRE_USER_COVERAGE = {};  // { techniqueId: { color, note, covered } }

/* ── Main render ── */
window.renderMITRENavigator = function renderMITRENavigator() {
  const container = document.getElementById('mitreAttackWrap');
  if (!container) return;

  const altContainer = document.getElementById('mitreCoverageLiveContainer');
  container.style.display = 'block';
  if (altContainer) altContainer.style.display = 'none';

  const tactics    = window.MITRE_TACTICS || [];
  const allTech    = tactics.flatMap(t => t.techniques);
  const covered    = allTech.filter(t => (window.MITRE_USER_COVERAGE[t.id]?.covered ?? t.covered));
  const withAlerts = allTech.filter(t => (t.alerts || 0) > 0);
  const coverage   = Math.round((covered.length / allTech.length) * 100);

  container.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
    <div>
      <h2 style="font-size:1.1em;font-weight:700;color:#e6edf3;margin:0">
        <i class="fas fa-th" style="color:#8b5cf6;margin-right:8px"></i>
        MITRE ATT&CK® Navigator v14
      </h2>
      <div style="font-size:.78em;color:#8b949e;margin-top:2px">
        Intel Hub / MITRE ATT&CK v14 · Interactive matrix with manual customization
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button onclick="_mitreExport()"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:6px 12px;border-radius:6px;font-size:.78em;cursor:pointer">
        <i class="fas fa-download" style="margin-right:4px"></i>Export JSON</button>
      <button onclick="_mitreResetCustom()"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:6px 12px;border-radius:6px;font-size:.78em;cursor:pointer">
        <i class="fas fa-undo" style="margin-right:4px"></i>Reset Custom</button>
    </div>
  </div>

  <!-- KPI Cards -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px">
    ${[
      {label:'Techniques Covered',val:`${covered.length}/${allTech.length}`,icon:'fa-shield-alt',c:'#22c55e'},
      {label:'Avg Coverage',val:`${coverage}%`,icon:'fa-chart-pie',c:'#3b82f6'},
      {label:'Active Alerts',val:withAlerts.length,icon:'fa-bell',c:'#ef4444'},
      {label:'Tactics',val:tactics.length,icon:'fa-layer-group',c:'#8b5cf6'},
      {label:'Data Sources',val:12,icon:'fa-database',c:'#c9a227'},
    ].map(k=>`
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <i class="fas ${k.icon}" style="color:${k.c};font-size:.9em"></i>
        <span style="font-size:.7em;color:#8b949e">${k.label}</span>
      </div>
      <div style="font-size:1.3em;font-weight:700;color:${k.c}">${k.val}</div>
    </div>`).join('')}
  </div>

  <!-- Legend -->
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;font-size:.74em;align-items:center">
    <span style="color:#8b949e;font-weight:600">Coverage:</span>
    <span style="display:flex;align-items:center;gap:5px"><span style="width:14px;height:14px;background:#22c55e;border-radius:3px;display:inline-block"></span>High (≥5 alerts)</span>
    <span style="display:flex;align-items:center;gap:5px"><span style="width:14px;height:14px;background:#f59e0b;border-radius:3px;display:inline-block"></span>Medium (1-4 alerts)</span>
    <span style="display:flex;align-items:center;gap:5px"><span style="width:14px;height:14px;background:#1e3a5f;border-radius:3px;display:inline-block"></span>Low (covered, no alerts)</span>
    <span style="display:flex;align-items:center;gap:5px"><span style="width:14px;height:14px;background:#161b22;border:1px solid #30363d;border-radius:3px;display:inline-block"></span>Not covered</span>
    <span style="display:flex;align-items:center;gap:5px"><span style="width:14px;height:14px;background:#8b5cf6;border-radius:3px;display:inline-block"></span>Custom marked</span>
  </div>

  <!-- ATT&CK Matrix -->
  <div style="overflow-x:auto;margin-bottom:24px">
    <div style="display:flex;gap:4px;min-width:fit-content">
      ${tactics.map(tactic => `
      <div style="flex-shrink:0;width:120px">
        <!-- Tactic header -->
        <div onclick="_mitreOpenTactic('${tactic.id}')" style="cursor:pointer;background:${tactic.color}22;border:1px solid ${tactic.color}44;
          border-radius:6px 6px 0 0;padding:8px 6px;text-align:center;margin-bottom:3px;
          transition:all .15s" onmouseover="this.style.background='${tactic.color}33'" onmouseout="this.style.background='${tactic.color}22'">
          <div style="font-size:.72em;font-weight:700;color:${tactic.color};line-height:1.3">${tactic.name}</div>
          <div style="font-size:.62em;color:#8b949e;margin-top:2px">${tactic.id}</div>
        </div>
        <!-- Technique cells -->
        <div style="display:flex;flex-direction:column;gap:2px">
          ${tactic.techniques.map(tech => {
            const userCov = window.MITRE_USER_COVERAGE[tech.id];
            const isCovered = userCov ? userCov.covered : tech.covered;
            const alerts    = tech.alerts || 0;
            let cellBg, cellBorder;
            if (userCov?.color) {
              cellBg = userCov.color + '33'; cellBorder = userCov.color;
            } else if (!isCovered) {
              cellBg = '#0d1117'; cellBorder = '#21262d';
            } else if (alerts >= 5) {
              cellBg = '#22c55e22'; cellBorder = '#22c55e66';
            } else if (alerts >= 1) {
              cellBg = '#f59e0b22'; cellBorder = '#f59e0b66';
            } else {
              cellBg = '#1e3a5f33'; cellBorder = '#1e3a5f88';
            }
            return `<div onclick="_mitreOpenTech('${tech.id}','${tactic.id}')"
              id="mitre-cell-${tech.id.replace('.','_')}"
              title="${tech.name}${alerts > 0 ? ' — '+alerts+' alerts' : ''}"
              style="background:${cellBg};border:1px solid ${cellBorder};border-radius:3px;padding:4px 5px;
                cursor:pointer;transition:all .15s;min-height:28px"
              onmouseover="this.style.opacity='.75';this.style.transform='scale(1.02)'"
              onmouseout="this.style.opacity='1';this.style.transform='scale(1)'">
              <div style="font-size:.65em;color:#e6edf3;line-height:1.3;font-family:monospace">${tech.short}</div>
              ${alerts > 0 ? `<div style="font-size:.58em;color:${alerts>=5?'#22c55e':'#f59e0b'};margin-top:1px">${alerts}▲</div>` : ''}
            </div>`;
          }).join('')}
        </div>
      </div>`).join('')}
    </div>
  </div>

  <!-- Technique Coverage Table -->
  <div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;overflow:hidden">
    <div style="padding:12px 16px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div style="font-size:.85em;font-weight:700;color:#e6edf3">
        <i class="fas fa-table" style="color:#3b82f6;margin-right:6px"></i>Technique Coverage Table
      </div>
      <div style="display:flex;gap:6px">
        <input id="mitre-search" placeholder="🔍 Filter techniques…" oninput="_mitreTableFilter()"
          style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 10px;border-radius:5px;font-size:.78em;width:160px"/>
        <select id="mitre-filter-tactic" onchange="_mitreTableFilter()"
          style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 8px;border-radius:5px;font-size:.78em">
          <option value="">All Tactics</option>
          ${tactics.map(t=>`<option value="${t.id}">${t.name}</option>`).join('')}
        </select>
        <select id="mitre-filter-cov" onchange="_mitreTableFilter()"
          style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 8px;border-radius:5px;font-size:.78em">
          <option value="">All Coverage</option>
          <option value="covered">Covered</option>
          <option value="uncovered">Not Covered</option>
          <option value="alerts">Has Alerts</option>
        </select>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="background:#080c14;font-size:.72em;color:#8b949e;text-align:left">
            <th style="padding:8px 14px">Technique</th>
            <th style="padding:8px 14px">Tactic</th>
            <th style="padding:8px 14px">Detection Status</th>
            <th style="padding:8px 14px">Data Source</th>
            <th style="padding:8px 14px">Linked Alerts</th>
            <th style="padding:8px 14px">Coverage %</th>
            <th style="padding:8px 14px">Actions</th>
          </tr>
        </thead>
        <tbody id="mitre-table-body">
          ${_mitreTableRows()}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Detail Panel (hidden until click) -->
  <div id="mitre-detail-panel" style="display:none;background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px;margin-top:16px">
    <div id="mitre-detail-body"></div>
  </div>
  `;
};

function _mitreTableRows(filters = {}) {
  const tactics = window.MITRE_TACTICS || [];
  let rows = [];
  tactics.forEach(tactic => {
    tactic.techniques.forEach(tech => {
      rows.push({...tech, tacticName: tactic.name, tacticId: tactic.id, tacticColor: tactic.color});
    });
  });

  if (filters.search) {
    const q = filters.search.toLowerCase();
    rows = rows.filter(r => r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q));
  }
  if (filters.tactic) rows = rows.filter(r => r.tacticId === filters.tactic);
  if (filters.cov === 'covered') rows = rows.filter(r => r.covered);
  else if (filters.cov === 'uncovered') rows = rows.filter(r => !r.covered);
  else if (filters.cov === 'alerts') rows = rows.filter(r => (r.alerts||0) > 0);

  const dataSources = {
    'T1059':'Process, Script','T1055':'Process','T1003':'File, Process','T1566':'Email, Network',
    'T1190':'Application Log','T1078':'Authentication Log','T1110':'Authentication Log',
    'T1021':'Network, Process','T1486':'File, Process','T1071':'Network Traffic',
    'T1558':'Kerberos Log','T1548':'Process','T1046':'Network Traffic'
  };

  return rows.map(r => {
    const userCov = window.MITRE_USER_COVERAGE[r.id];
    const isCov   = userCov ? userCov.covered : r.covered;
    const alerts  = r.alerts || 0;
    const covPct  = isCov ? (alerts >= 5 ? 85 : alerts >= 1 ? 60 : 30) : 0;
    const covColor= covPct >= 70 ? '#22c55e' : covPct >= 40 ? '#f59e0b' : covPct > 0 ? '#3b82f6' : '#8b949e';
    const status  = isCov ? (alerts > 0 ? 'Active Detection' : 'Covered') : 'Not Covered';
    const statusC = isCov ? (alerts > 0 ? '#22c55e' : '#3b82f6') : '#ef4444';
    const ds = dataSources[r.id.split('.')[0]] || 'Log, Network';

    return `<tr style="border-bottom:1px solid #1a2030;font-size:.78em"
      onmouseover="this.style.background='#1a2030'" onmouseout="this.style.background='transparent'">
      <td style="padding:7px 14px">
        <div style="font-family:monospace;color:#22d3ee;font-size:.88em">${r.id}</div>
        <div style="color:#e6edf3;margin-top:1px">${_escMitre(r.short)}</div>
      </td>
      <td style="padding:7px 14px">
        <span style="background:${r.tacticColor}18;color:${r.tacticColor};border:1px solid ${r.tacticColor}33;
          padding:1px 7px;border-radius:4px;font-size:.85em">${r.tacticName}</span>
      </td>
      <td style="padding:7px 14px">
        <span style="color:${statusC};font-weight:600"><i class="fas ${isCov?'fa-check-circle':'fa-times-circle'}" style="margin-right:4px"></i>${status}</span>
      </td>
      <td style="padding:7px 14px;color:#8b949e">${ds}</td>
      <td style="padding:7px 14px">
        ${alerts > 0 ? `<span style="color:#f97316;font-weight:700">${alerts}</span><span style="color:#8b949e"> alerts</span>` : '<span style="color:#8b949e">—</span>'}
      </td>
      <td style="padding:7px 14px">
        <div style="display:flex;align-items:center;gap:6px">
          <div style="flex:1;background:#1e2d3d;border-radius:3px;height:6px;min-width:60px">
            <div style="height:6px;background:${covColor};border-radius:3px;width:${covPct}%"></div>
          </div>
          <span style="color:${covColor};font-weight:600;font-size:.85em">${covPct}%</span>
        </div>
      </td>
      <td style="padding:7px 14px">
        <div style="display:flex;gap:4px">
          <button onclick="_mitreOpenTech('${r.id}','${r.tacticId}')"
            style="background:#1d6ae520;color:#3b82f6;border:1px solid #1d6ae533;padding:3px 8px;border-radius:4px;font-size:.75em;cursor:pointer">
            <i class="fas fa-eye"></i></button>
          <button onclick="_mitreMarkTech('${r.id}')"
            style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:3px 8px;border-radius:4px;font-size:.75em;cursor:pointer"
            title="Mark/customize coverage">
            <i class="fas fa-paint-brush"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('') || `<tr><td colspan="7" style="text-align:center;padding:20px;color:#8b949e">No techniques match filters</td></tr>`;
}

window._mitreTableFilter = function() {
  const body = document.getElementById('mitre-table-body');
  if (!body) return;
  body.innerHTML = _mitreTableRows({
    search: document.getElementById('mitre-search')?.value || '',
    tactic: document.getElementById('mitre-filter-tactic')?.value || '',
    cov:    document.getElementById('mitre-filter-cov')?.value || ''
  });
};

window._mitreOpenTactic = function(tacticId) {
  const tactic = (window.MITRE_TACTICS || []).find(t => t.id === tacticId);
  if (!tactic) return;
  const panel = document.getElementById('mitre-detail-panel');
  const body  = document.getElementById('mitre-detail-body');
  if (!panel || !body) return;
  panel.style.display = 'block';
  const covTech = tactic.techniques.filter(t => t.covered);
  const alertTech = tactic.techniques.filter(t => (t.alerts||0) > 0);
  body.innerHTML = `
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
    <div style="width:48px;height:48px;border-radius:10px;background:${tactic.color}22;border:1px solid ${tactic.color}44;
      display:flex;align-items:center;justify-content:center;flex-shrink:0">
      <span style="font-size:.75em;font-weight:700;color:${tactic.color}">${tactic.id}</span>
    </div>
    <div>
      <div style="font-size:1.05em;font-weight:700;color:#e6edf3">${tactic.name}</div>
      <div style="font-size:.75em;color:#8b949e">${tactic.techniques.length} techniques · ${covTech.length} covered · ${alertTech.length} with active alerts</div>
    </div>
    <button onclick="document.getElementById('mitre-detail-panel').style.display='none'"
      style="margin-left:auto;background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px 10px;border-radius:5px;cursor:pointer">
      <i class="fas fa-times"></i></button>
  </div>
  <p style="font-size:.84em;color:#8b949e;line-height:1.7;margin-bottom:14px">${_escMitre(tactic.desc)}</p>
  <div style="display:flex;flex-wrap:wrap;gap:5px">
    ${tactic.techniques.map(t => `<span onclick="_mitreOpenTech('${t.id}','${tactic.id}')"
      style="cursor:pointer;background:${t.covered?tactic.color+'22':'#1e2d3d'};color:${t.covered?tactic.color:'#8b949e'};
        border:1px solid ${t.covered?tactic.color+'44':'#30363d'};padding:3px 10px;border-radius:5px;
        font-size:.73em;font-family:monospace">${t.id} ${t.short}</span>`).join('')}
  </div>`;
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

window._mitreOpenTech = function(techId, tacticId) {
  const tactic = (window.MITRE_TACTICS || []).find(t => t.id === tacticId);
  const tech   = tactic ? tactic.techniques.find(t => t.id === techId) : null;
  if (!tactic || !tech) return;
  const panel = document.getElementById('mitre-detail-panel');
  const body  = document.getElementById('mitre-detail-body');
  if (!panel || !body) return;
  panel.style.display = 'block';

  const userCov = window.MITRE_USER_COVERAGE[tech.id];
  const isCov   = userCov ? userCov.covered : tech.covered;
  const alerts  = tech.alerts || 0;
  const covPct  = isCov ? (alerts >= 5 ? 85 : alerts >= 1 ? 60 : 30) : 0;
  const covC    = covPct >= 70 ? '#22c55e' : covPct >= 40 ? '#f59e0b' : covPct > 0 ? '#3b82f6' : '#8b949e';

  body.innerHTML = `
  <!-- Tech header -->
  <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:14px">
    <div style="background:${tactic.color}22;border:1px solid ${tactic.color}44;border-radius:8px;padding:8px 12px;
      font-family:monospace;font-size:.88em;font-weight:700;color:${tactic.color};flex-shrink:0">${tech.id}</div>
    <div style="flex:1">
      <div style="font-size:.98em;font-weight:700;color:#e6edf3">${_escMitre(tech.name)}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px">
        <span style="background:${tactic.color}18;color:${tactic.color};border:1px solid ${tactic.color}33;
          padding:1px 8px;border-radius:5px;font-size:.72em">${tactic.name}</span>
        <span style="color:${isCov?'#22c55e':'#ef4444'};font-size:.72em">
          <i class="fas ${isCov?'fa-check-circle':'fa-times-circle'}" style="margin-right:3px"></i>
          ${isCov?'Covered':'Not Covered'}</span>
        ${alerts > 0 ? `<span style="color:#f97316;font-size:.72em"><i class="fas fa-bell" style="margin-right:3px"></i>${alerts} active alerts</span>` : ''}
      </div>
    </div>
    <div style="display:flex;gap:6px;flex-shrink:0">
      <button onclick="window.open('https://attack.mitre.org/techniques/${techId.replace('.','/')}','_blank')"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:5px 10px;border-radius:5px;font-size:.75em;cursor:pointer">
        <i class="fas fa-external-link-alt" style="margin-right:4px"></i>MITRE</button>
      <button onclick="_mitreMarkTech('${tech.id}')"
        style="background:rgba(139,92,246,.15);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);
          padding:5px 10px;border-radius:5px;font-size:.75em;cursor:pointer">
        <i class="fas fa-paint-brush" style="margin-right:4px"></i>Customize</button>
      <button onclick="document.getElementById('mitre-detail-panel').style.display='none'"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:5px 10px;border-radius:5px;cursor:pointer">
        <i class="fas fa-times"></i></button>
    </div>
  </div>

  <!-- Description -->
  <p style="font-size:.84em;color:#8b949e;line-height:1.7;background:#080c14;border:1px solid #1e2d3d;
    border-radius:8px;padding:12px;margin-bottom:14px">${_escMitre(tech.desc)}</p>

  <!-- Coverage bar + note -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">
      <div style="font-size:.78em;font-weight:700;color:#e6edf3;margin-bottom:8px">
        <i class="fas fa-chart-bar" style="color:${covC};margin-right:6px"></i>Detection Coverage
      </div>
      <div style="font-size:1.6em;font-weight:700;color:${covC};margin-bottom:6px">${covPct}%</div>
      <div style="background:#1e2d3d;border-radius:4px;height:8px">
        <div style="height:8px;background:${covC};border-radius:4px;width:${covPct}%;transition:width .5s"></div>
      </div>
      ${userCov?.note ? `<div style="margin-top:8px;font-size:.75em;color:#c9a227"><i class="fas fa-sticky-note" style="margin-right:4px"></i>${_escMitre(userCov.note)}</div>` : ''}
    </div>
    <div style="background:#080c14;border:1px solid #1e2d3d;border-radius:8px;padding:12px">
      <div style="font-size:.78em;font-weight:700;color:#e6edf3;margin-bottom:8px">
        <i class="fas fa-search" style="color:#3b82f6;margin-right:6px"></i>Detection Hunts Available
      </div>
      <div style="font-size:.78em;color:#8b949e">
        ${(window.HUNT_QUERIES||[]).filter(q=>(q.mitre||[]).some(m=>m.startsWith(tech.id))).length > 0
          ? `<span style="color:#22c55e">${(window.HUNT_QUERIES||[]).filter(q=>(q.mitre||[]).some(m=>m.startsWith(tech.id))).length} hunt queries mapped</span>`
          : 'No specific hunt queries yet'}
      </div>
      <button onclick="navigateTo&&navigateTo('threat-hunting')"
        style="margin-top:8px;background:rgba(29,106,229,.1);color:#3b82f6;border:1px solid rgba(29,106,229,.3);
          padding:4px 10px;border-radius:5px;font-size:.74em;cursor:pointer">
        <i class="fas fa-crosshairs" style="margin-right:4px"></i>Open Hunt Workspace</button>
    </div>
  </div>
  `;
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

window._mitreMarkTech = function(techId) {
  const existing = window.MITRE_USER_COVERAGE[techId] || {};
  const newCovered = !existing.covered;
  window.MITRE_USER_COVERAGE[techId] = {
    ...existing,
    covered: newCovered,
    color: newCovered ? '#8b5cf6' : undefined
  };
  // Re-render matrix cell
  const all = window.MITRE_TACTICS || [];
  let tech;
  all.forEach(t => { const found = t.techniques.find(x => x.id === techId); if(found) tech = found; });
  const cellId = `mitre-cell-${techId.replace('.','_')}`;
  const cell = document.getElementById(cellId);
  if (cell) {
    if (newCovered) {
      cell.style.background = '#8b5cf633';
      cell.style.border = '1px solid #8b5cf6';
    } else {
      cell.style.background = '#0d1117';
      cell.style.border = '1px solid #21262d';
    }
  }
  if (window.showToast) showToast(`Technique ${techId} marked as ${newCovered ? 'covered' : 'not covered'}`, 'success');
};

window._mitreExport = function() {
  const data = {
    name: 'EYEbot AI Coverage Layer',
    version: '4.4',
    domain: 'mitre-attack',
    description: 'EYEbot AI MITRE ATT&CK Coverage',
    techniques: (window.MITRE_TACTICS || []).flatMap(t => t.techniques.filter(tech => tech.covered || window.MITRE_USER_COVERAGE[tech.id]).map(tech => ({
      techniqueID: tech.id, tactic: t.name.toLowerCase().replace(/ /g,'-'),
      color: (window.MITRE_USER_COVERAGE[tech.id]?.color) || (tech.alerts >= 5 ? '#22c55e' : tech.alerts >= 1 ? '#f59e0b' : '#3b82f6'),
      comment: `Alerts: ${tech.alerts || 0}`, enabled: true
    })))
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'wadjet-attack-navigator-layer.json'; a.click();
  URL.revokeObjectURL(url);
  if (window.showToast) showToast('Navigator layer exported', 'success');
};

window._mitreResetCustom = function() {
  window.MITRE_USER_COVERAGE = {};
  window.renderMITRENavigator();
  if (window.showToast) showToast('Custom coverage reset', 'info');
};

function _escMitre(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
