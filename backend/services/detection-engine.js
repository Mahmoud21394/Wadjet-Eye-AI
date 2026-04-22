/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Detection Engine  v1.0
 *  backend/services/detection-engine.js
 *
 *  Generates detection rules in multiple formats for MITRE ATT&CK
 *  techniques without requiring external APIs.
 *
 *  Public API (used by soc-intelligence routes):
 *   engine.generateSigma(techId)    → { found, id, name, content, format:'sigma' }
 *   engine.generateKQL(techId)      → { found, id, name, content, format:'kql' }
 *   engine.generateSPL(techId)      → { found, id, name, content, format:'spl' }
 *   engine.generateElastic(techId)  → { found, id, name, content, format:'elastic' }
 *   engine.generateAll(techId)      → { found, id, name, sigma, kql, spl, elastic }
 *   engine.listSupportedTechniques()→ [{ id, name, tactic }]
 *   engine.ruleCount                → number
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Detection rule templates per MITRE technique ─────────────────
// Each entry: { id, name, tactic, sigma, kql, spl, elastic }
const DETECTION_RULES = {
  'T1190': {
    name: 'Exploit Public-Facing Application',
    tactic: 'initial-access',
    sigma: `title: Exploit Public-Facing Application (T1190)
id: t1190-exploit-public-facing
status: experimental
description: Detects exploitation attempts against internet-facing applications
author: Wadjet-Eye AI
date: 2024/01/01
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  keywords:
    - '../'
    - '/etc/passwd'
    - 'cmd.exe'
    - 'powershell'
    - 'eval('
    - '\${jndi:'
    - 'union select'
    - '<script>'
  condition: keywords
falsepositives:
  - Penetration testing
  - Security scanners
level: high`,
    kql: `// T1190 — Exploit Public-Facing Application
// KQL for Microsoft Sentinel
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "InboundConnectionAccepted"
| join kind=inner (
    DeviceEvents
    | where ActionType in ("ExploitGuardNetworkProtectionBlock","NetworkProtectionUserBypassEvent")
) on DeviceId
| project TimeGenerated, DeviceId, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by TimeGenerated desc`,
    spl: `// T1190 — Exploit Public-Facing Application
// SPL for Splunk SIEM
index=web_logs OR index=firewall
| search uri="*../*" OR uri="*/etc/passwd*" OR uri="*cmd.exe*" OR uri="*\${jndi:*" OR uri="*union+select*"
| stats count by src_ip, uri, status, _time
| where count > 5
| sort -count
| table _time, src_ip, uri, status, count`,
    elastic: `{
  "query": {
    "bool": {
      "should": [
        { "wildcard": { "url.original": "*../*" } },
        { "wildcard": { "url.original": "*/etc/passwd*" } },
        { "wildcard": { "url.original": "*cmd.exe*" } },
        { "wildcard": { "url.original": "*\${jndi:*" } },
        { "wildcard": { "url.original": "*union+select*" } }
      ],
      "minimum_should_match": 1,
      "filter": [{ "range": { "@timestamp": { "gte": "now-1h" } } }]
    }
  }
}`,
  },

  'T1133': {
    name: 'External Remote Services',
    tactic: 'initial-access',
    sigma: `title: External Remote Services Authentication (T1133)
id: t1133-external-remote-services
status: experimental
description: Detects suspicious authentication to external remote services
author: Wadjet-Eye AI
tags:
  - attack.initial_access
  - attack.t1133
logsource:
  category: authentication
detection:
  selection:
    EventID:
      - 4624
      - 4625
    LogonType: 10
  timeframe: 5m
  condition: selection | count() > 10
falsepositives:
  - Legitimate remote administration
level: medium`,
    kql: `// T1133 — External Remote Services
SigninLogs
| where TimeGenerated > ago(1h)
| where AppDisplayName in ("Remote Desktop","VPN","Citrix","TeamViewer")
| where ResultType != "0"
| summarize FailedAttempts=count(), IPAddresses=make_set(IPAddress) by UserPrincipalName, AppDisplayName
| where FailedAttempts > 5
| order by FailedAttempts desc`,
    spl: `index=windows EventCode=4625 LogonType=10
| stats count by src_ip, user, Computer
| where count > 5
| sort -count
| table _time, src_ip, user, Computer, count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4625" } },
        { "term": { "winlog.event_data.LogonType": "10" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "source.ip", "size": 20 }
    }
  }
}`,
  },

  'T1059': {
    name: 'Command and Scripting Interpreter',
    tactic: 'execution',
    sigma: `title: Suspicious Command and Scripting Interpreter Usage (T1059)
id: t1059-command-scripting
status: experimental
description: Detects suspicious use of command interpreters and scripting engines
author: Wadjet-Eye AI
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\cmd.exe'
      - '\\\\wscript.exe'
      - '\\\\cscript.exe'
      - '\\\\mshta.exe'
  suspicious_args:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - 'IEX('
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'bypass'
      - 'hidden'
  condition: selection and suspicious_args
falsepositives:
  - Legitimate admin scripts
  - Software installers
level: high`,
    kql: `// T1059 — Command and Scripting Interpreter
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName in ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| where ProcessCommandLine has_any ("-EncodedCommand","-enc ","IEX(","Invoke-Expression","DownloadString","bypass","hidden")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc`,
    spl: `index=windows EventCode=4688 (process_name="powershell.exe" OR process_name="cmd.exe" OR process_name="wscript.exe")
| search command_line="*-EncodedCommand*" OR command_line="*IEX(*" OR command_line="*DownloadString*" OR command_line="*bypass*"
| table _time, host, user, process_name, command_line
| sort -_time`,
    elastic: `{
  "query": {
    "bool": {
      "must": [
        { "terms": { "process.name": ["powershell.exe","cmd.exe","wscript.exe","cscript.exe"] } },
        { "bool": {
            "should": [
              { "wildcard": { "process.command_line": "*-EncodedCommand*" } },
              { "wildcard": { "process.command_line": "*IEX(*" } },
              { "wildcard": { "process.command_line": "*DownloadString*" } }
            ],
            "minimum_should_match": 1
          }
        }
      ],
      "filter": [{ "range": { "@timestamp": { "gte": "now-1h" } } }]
    }
  }
}`,
  },

  'T1566': {
    name: 'Phishing',
    tactic: 'initial-access',
    sigma: `title: Phishing Email Indicators (T1566)
id: t1566-phishing
status: experimental
description: Detects phishing email patterns including suspicious attachments and links
author: Wadjet-Eye AI
tags:
  - attack.initial_access
  - attack.t1566
logsource:
  category: email
detection:
  selection:
    attachment_extension:
      - '.docm'
      - '.xlsm'
      - '.iso'
      - '.img'
      - '.zip'
      - '.lnk'
    suspicious_subject|contains:
      - 'invoice'
      - 'urgent'
      - 'action required'
      - 'verify'
      - 'suspended'
  condition: selection
falsepositives:
  - Legitimate business emails with attachments
level: medium`,
    kql: `// T1566 — Phishing
EmailEvents
| where TimeGenerated > ago(24h)
| where DeliveryAction != "Delivered"
| where ThreatTypes has_any ("Phish","Malware","Spam")
| summarize count() by SenderMailFromAddress, Subject, ThreatTypes, DeliveryAction
| order by count_ desc`,
    spl: `index=email_logs
| search attachment_type IN ("docm","xlsm","iso","img","lnk") OR subject="*invoice*" OR subject="*urgent*" OR subject="*action required*"
| stats count by src_email, subject, attachment_type, recipient
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "should": [
        { "terms": { "email.attachments.file.extension": [".docm",".xlsm",".iso",".img",".lnk"] } },
        { "wildcard": { "email.subject": "*invoice*" } },
        { "wildcard": { "email.subject": "*urgent*" } },
        { "term": { "event.category": "email" } }
      ],
      "filter": [{ "range": { "@timestamp": { "gte": "now-24h" } } }]
    }
  }
}`,
  },

  'T1486': {
    name: 'Data Encrypted for Impact',
    tactic: 'impact',
    sigma: `title: Ransomware File Encryption Activity (T1486)
id: t1486-ransomware-encryption
status: experimental
description: Detects mass file encryption activity indicative of ransomware
author: Wadjet-Eye AI
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypted'
      - '.crypt'
      - '.enc'
      - '.ransom'
    Initiated|endswith:
      - '\\vssadmin.exe'
      - '\\wmic.exe'
  timeframe: 60s
  condition: selection | count() > 100
falsepositives:
  - Backup software encryption
level: critical`,
    kql: `// T1486 — Data Encrypted for Impact (Ransomware)
DeviceFileEvents
| where TimeGenerated > ago(30m)
| where ActionType in ("FileCreated","FileModified")
| where FileName endswith_cs ".encrypted" or FileName endswith_cs ".locked" or FileName endswith_cs ".crypted"
| summarize EncryptedFiles=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| where EncryptedFiles > 50
| order by EncryptedFiles desc`,
    spl: `index=windows EventCode=4663 object_name="*.encrypted" OR object_name="*.locked" OR object_name="*.crypted"
| stats count by host, user, process_name
| where count > 50
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "should": [
        { "wildcard": { "file.path": "*.encrypted" } },
        { "wildcard": { "file.path": "*.locked" } },
        { "wildcard": { "file.path": "*.crypted" } }
      ],
      "minimum_should_match": 1,
      "filter": [{ "range": { "@timestamp": { "gte": "now-30m" } } }]
    }
  },
  "aggs": {
    "by_host": { "terms": { "field": "host.name", "size": 10 } }
  }
}`,
  },

  'T1078': {
    name: 'Valid Accounts',
    tactic: 'defense-evasion',
    sigma: `title: Suspicious Valid Account Usage (T1078)
id: t1078-valid-accounts
status: experimental
description: Detects unusual account activity that may indicate credential theft
author: Wadjet-Eye AI
tags:
  - attack.defense_evasion
  - attack.t1078
logsource:
  category: authentication
detection:
  selection:
    EventID: 4624
    LogonType:
      - 3
      - 10
  time_filter:
    TimeCreated|before: '06:00:00'
    TimeCreated|after: '22:00:00'
  condition: selection and time_filter
falsepositives:
  - Night-shift workers
  - Automated processes
level: medium`,
    kql: `// T1078 — Valid Accounts
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where hourofday(TimeGenerated) < 6 or hourofday(TimeGenerated) > 22
| summarize Logins=count(), Locations=make_set(Location) by UserPrincipalName, AppDisplayName
| where array_length(Locations) > 2
| order by Logins desc`,
    spl: `index=windows EventCode=4624 LogonType IN (3,10)
| eval hour=strftime(_time,"%H")
| where hour < "06" OR hour > "22"
| stats count by src_ip, user, Computer
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4624" } },
        { "terms": { "winlog.event_data.LogonType": ["3","10"] } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },

  'T1210': {
    name: 'Exploitation of Remote Services',
    tactic: 'lateral-movement',
    sigma: `title: Exploitation of Remote Services (T1210)
id: t1210-remote-service-exploit
status: experimental
description: Detects exploitation attempts against remote services for lateral movement
author: Wadjet-Eye AI
tags:
  - attack.lateral_movement
  - attack.t1210
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 445
      - 135
      - 3389
      - 22
    Initiated: 'true'
  suspicious:
    CommandLine|contains:
      - 'psexec'
      - 'wmic /node'
      - 'smbexec'
      - 'impacket'
  condition: selection and suspicious
falsepositives:
  - Legitimate admin tools
level: high`,
    kql: `// T1210 — Exploitation of Remote Services
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemotePort in (445, 135, 3389, 22)
| where ActionType == "ConnectionSuccess"
| join kind=inner (
    DeviceProcessEvents
    | where FileName in ("psexec.exe","wmic.exe","smbexec.exe")
) on DeviceId
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, FileName, ProcessCommandLine`,
    spl: `index=network dest_port IN (445,135,3389,22) action=allow
| join src_ip [search index=windows process_name IN ("psexec.exe","wmic.exe")]
| table _time, src_ip, dest_ip, dest_port, process_name`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "terms": { "destination.port": [445, 135, 3389, 22] } },
        { "terms": { "process.name": ["psexec.exe","wmic.exe","smbexec.exe"] } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },

  'T1187': {
    name: 'Forced Authentication',
    tactic: 'credential-access',
    sigma: `title: Forced Authentication / NTLM Hash Capture (T1187)
id: t1187-forced-auth
status: experimental
description: Detects coerced authentication attempts for NTLM hash capture
author: Wadjet-Eye AI
tags:
  - attack.credential_access
  - attack.t1187
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4648
    TargetServerName|contains:
      - 'attacker'
      - '\\\\\\\\192.'
      - '\\\\\\\\10.'
      - 'responder'
  condition: selection
falsepositives:
  - Legitimate cross-domain authentication
level: high`,
    kql: `// T1187 — Forced Authentication (NTLM coercion)
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4648
| where TargetServerName startswith "\\\\\\\\"
| where TargetUserName !endswith "$"
| project TimeGenerated, Computer, Account, TargetUserName, TargetServerName, LogonProcessName`,
    spl: `index=windows EventCode=4648
| where like(TargetServerName, "\\\\\\\\%")
| stats count by src_ip, user, TargetServerName, Computer
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4648" } },
        { "wildcard": { "winlog.event_data.TargetServerName": "\\\\\\\\*" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },

  'T1499': {
    name: 'Endpoint Denial of Service',
    tactic: 'impact',
    sigma: `title: Denial of Service Attack (T1499)
id: t1499-dos
status: experimental
description: Detects high-volume traffic patterns indicative of DoS attacks
author: Wadjet-Eye AI
tags:
  - attack.impact
  - attack.t1499
logsource:
  category: network_traffic
detection:
  selection:
    NetworkPackets|gt: 100000
    TimeWindow: 60s
  condition: selection
falsepositives:
  - Legitimate high-traffic services
  - CDN edge nodes
level: high`,
    kql: `// T1499 — Endpoint Denial of Service
CommonSecurityLog
| where TimeGenerated > ago(5m)
| where DeviceAction == "drop" or DeviceAction == "deny"
| summarize DroppedPackets=count(), SourceIPs=dcount(SourceIP) by DestinationIP, DestinationPort
| where DroppedPackets > 10000
| order by DroppedPackets desc`,
    spl: `index=network action=drop OR action=deny earliest=-5m
| stats count by dest_ip, dest_port, src_ip
| where count > 10000
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.action": "drop" } },
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "aggs": {
    "by_dest": {
      "terms": { "field": "destination.ip", "size": 10 },
      "aggs": { "packet_count": { "value_count": { "field": "_id" } } }
    }
  }
}`,
  },

  'T1021': {
    name: 'Remote Services',
    tactic: 'lateral-movement',
    sigma: `title: Suspicious Remote Services Usage (T1021)
id: t1021-remote-services
status: experimental
description: Detects lateral movement via remote services
author: Wadjet-Eye AI
tags:
  - attack.lateral_movement
  - attack.t1021
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4624
      - 4625
    LogonType: 3
  suspicious_source:
    IpAddress|not:
      - '127.0.0.1'
      - '::1'
  condition: selection and suspicious_source
falsepositives:
  - Legitimate network shares access
level: medium`,
    kql: `// T1021 — Remote Services (Lateral Movement)
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where LogonType in ("Network","RemoteInteractive")
| where ActionType == "LogonSuccess"
| summarize count() by DeviceName, AccountName, RemoteIP
| where count_ > 5
| order by count_ desc`,
    spl: `index=windows EventCode=4624 LogonType=3 NOT src_ip IN ("127.0.0.1","::1")
| stats count by src_ip, user, dest_host
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4624" } },
        { "term": { "winlog.event_data.LogonType": "3" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "must_not": [
        { "terms": { "source.ip": ["127.0.0.1","::1"] } }
      ]
    }
  }
}`,
  },

  'T1071': {
    name: 'Application Layer Protocol',
    tactic: 'command-and-control',
    sigma: `title: C2 via Application Layer Protocol (T1071)
id: t1071-app-layer-protocol
status: experimental
description: Detects C2 communication over standard application protocols
author: Wadjet-Eye AI
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: dns
detection:
  selection:
    RecordType: 'TXT'
    QueryLength|gt: 100
  condition: selection | count() > 5
falsepositives:
  - Legitimate TXT record lookups
  - SPF/DKIM verification
level: medium`,
    kql: `// T1071 — Application Layer Protocol (C2)
DnsEvents
| where TimeGenerated > ago(1h)
| where QueryType == "TXT"
| where strlen(Name) > 50
| summarize count() by ClientIP, Name
| where count_ > 10
| order by count_ desc`,
    spl: `index=dns record_type=TXT
| where len(query) > 50
| stats count by src_ip, query
| where count > 10
| sort -count`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "dns.question.type": "TXT" } },
        { "script": { "script": "doc['dns.question.name'].value.length() > 50" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },

  'T1553': {
    name: 'Subvert Trust Controls',
    tactic: 'defense-evasion',
    sigma: `title: Trust Control Subversion (T1553)
id: t1553-subvert-trust
status: experimental
description: Detects attempts to bypass security trust mechanisms
author: Wadjet-Eye AI
tags:
  - attack.defense_evasion
  - attack.t1553
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies'
      - 'SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender'
      - 'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecurityProviders'
  condition: selection
falsepositives:
  - System administration
  - Group policy updates
level: high`,
    kql: `// T1553 — Subvert Trust Controls
DeviceRegistryEvents
| where TimeGenerated > ago(1h)
| where RegistryKey has_any ("Policies\\\\Microsoft\\\\Windows Defender","SecurityProviders","CryptographicMessageSyntax")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| project TimeGenerated, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData`,
    spl: `index=windows EventCode=4657 object_name="*Windows Defender*" OR object_name="*SecurityProviders*"
| table _time, host, user, object_name, new_value`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4657" } },
        { "bool": {
            "should": [
              { "wildcard": { "registry.path": "*Windows Defender*" } },
              { "wildcard": { "registry.path": "*SecurityProviders*" } }
            ],
            "minimum_should_match": 1
          }
        },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },

  'T1203': {
    name: 'Exploitation for Client Execution',
    tactic: 'execution',
    sigma: `title: Client-Side Exploitation (T1203)
id: t1203-client-execution
status: experimental
description: Detects exploitation of client-side applications
author: Wadjet-Eye AI
tags:
  - attack.execution
  - attack.t1203
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\\\\winword.exe'
      - '\\\\excel.exe'
      - '\\\\outlook.exe'
      - '\\\\acrord32.exe'
      - '\\\\iexplore.exe'
    Image|endswith:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
      - '\\\\wscript.exe'
      - '\\\\mshta.exe'
  condition: selection
falsepositives:
  - Macro-enabled documents for legitimate use
level: high`,
    kql: `// T1203 — Exploitation for Client Execution
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName in ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","AcroRd32.exe","iexplore.exe")
| where FileName in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
    spl: `index=windows EventCode=4688 parent_process IN ("winword.exe","excel.exe","outlook.exe","acrord32.exe")
process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| table _time, host, user, parent_process, process_name, command_line`,
    elastic: `{
  "query": {
    "bool": {
      "filter": [
        { "terms": { "process.parent.name": ["WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","AcroRd32.exe"] } },
        { "terms": { "process.name": ["cmd.exe","powershell.exe","wscript.exe","mshta.exe"] } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}`,
  },
};

// ═══════════════════════════════════════════════════════════════════
//  DetectionEngine Class
// ═══════════════════════════════════════════════════════════════════
class DetectionEngine {
  constructor() {
    this._rules = DETECTION_RULES;
    console.info(`[DetectionEngine] Initialized: ${this.ruleCount} rules loaded`);
  }

  get ruleCount() {
    return Object.keys(this._rules).length;
  }

  // ── Internal: normalize technique ID ──────────────────────────
  _resolve(id) {
    if (!id) return null;
    const upper = id.toUpperCase().replace(/\s+/g, '');
    return this._rules[upper] ? upper : null;
  }

  // ── Generate Sigma rule ────────────────────────────────────────
  generateSigma(techId) {
    const key = this._resolve(techId);
    if (!key) return { found: false, id: techId, message: `No Sigma rule for ${techId}` };
    const rule = this._rules[key];
    return { found: true, id: key, name: rule.name, tactic: rule.tactic, format: 'sigma', content: rule.sigma };
  }

  // ── Generate KQL query ─────────────────────────────────────────
  generateKQL(techId) {
    const key = this._resolve(techId);
    if (!key) return { found: false, id: techId, message: `No KQL query for ${techId}` };
    const rule = this._rules[key];
    return { found: true, id: key, name: rule.name, tactic: rule.tactic, format: 'kql', content: rule.kql };
  }

  // ── Generate SPL query ─────────────────────────────────────────
  generateSPL(techId) {
    const key = this._resolve(techId);
    if (!key) return { found: false, id: techId, message: `No SPL query for ${techId}` };
    const rule = this._rules[key];
    return { found: true, id: key, name: rule.name, tactic: rule.tactic, format: 'spl', content: rule.spl };
  }

  // ── Generate Elastic DSL query ─────────────────────────────────
  generateElastic(techId) {
    const key = this._resolve(techId);
    if (!key) return { found: false, id: techId, message: `No Elastic DSL for ${techId}` };
    const rule = this._rules[key];
    return { found: true, id: key, name: rule.name, tactic: rule.tactic, format: 'elastic', content: rule.elastic };
  }

  // ── Generate all formats ───────────────────────────────────────
  generateAll(techId) {
    const key = this._resolve(techId);
    if (!key) return { found: false, id: techId, message: `Technique ${techId} not in detection database` };
    const rule = this._rules[key];
    return {
      found:   true,
      id:      key,
      name:    rule.name,
      tactic:  rule.tactic,
      sigma:   { format: 'sigma',   content: rule.sigma   },
      kql:     { format: 'kql',     content: rule.kql     },
      spl:     { format: 'spl',     content: rule.spl     },
      elastic: { format: 'elastic', content: rule.elastic },
    };
  }

  // ── List all supported techniques ─────────────────────────────
  listSupportedTechniques() {
    return Object.entries(this._rules).map(([id, r]) => ({
      id,
      name:   r.name,
      tactic: r.tactic,
    }));
  }
}

// ── Singleton export ───────────────────────────────────────────────
const defaultEngine = new DetectionEngine();

module.exports = { DetectionEngine, defaultEngine };
