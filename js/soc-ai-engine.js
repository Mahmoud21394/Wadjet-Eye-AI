/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC AI Analysis Engine v1.0
 *  js/soc-ai-engine.js
 *
 *  Provides local rule-based threat analysis + optional OpenAI GPT-4o
 *  integration for:
 *    • Log parsing & normalization
 *    • Threat detection (20+ rule categories)
 *    • MITRE ATT&CK mapping
 *    • Risk scoring
 *    • Natural-language narrative generation
 *    • False-positive reduction
 * ══════════════════════════════════════════════════════════════════════
 */

window.SOCEngine = (function () {
  'use strict';

  /* ─── Configuration ─────────────────────────────────────────────── */
  const CFG = {
    openaiKey: '', // Set via SOCEngine.setApiKey()
    openaiModel: 'gpt-4o',
    openaiEndpoint: 'https://api.openai.com/v1/chat/completions',
    thresholds: {
      bruteForce: 5,          // Failed logins per minute
      credentialStuffing: 10, // Auth attempts from single IP
      portScan: 20,           // Port hits per minute
      dataExfil: 50,          // MB threshold
      privilegeEscalation: 1, // Any occurrence = alert
      lateralMovement: 3,     // Lateral connection attempts
    }
  };

  /* ─── MITRE ATT&CK Full Mapping ─────────────────────────────────── */
  const MITRE_TACTICS = {
    TA0001: { name: 'Initial Access',        techniques: ['T1190','T1133','T1566','T1199','T1195','T1091','T1189','T1200'] },
    TA0002: { name: 'Execution',             techniques: ['T1059','T1203','T1204','T1047','T1053','T1129','T1106','T1569'] },
    TA0003: { name: 'Persistence',           techniques: ['T1098','T1136','T1543','T1546','T1547','T1548','T1574','T1078'] },
    TA0004: { name: 'Privilege Escalation',  techniques: ['T1068','T1548','T1055','T1134','T1484','T1611','T1078','T1053'] },
    TA0005: { name: 'Defense Evasion',       techniques: ['T1070','T1036','T1055','T1112','T1140','T1562','T1078','T1027'] },
    TA0006: { name: 'Credential Access',     techniques: ['T1110','T1003','T1558','T1556','T1539','T1552','T1606','T1040'] },
    TA0007: { name: 'Discovery',             techniques: ['T1087','T1083','T1135','T1046','T1057','T1012','T1018','T1082'] },
    TA0008: { name: 'Lateral Movement',      techniques: ['T1021','T1080','T1550','T1534','T1210','T1570','T1563','T1091'] },
    TA0009: { name: 'Collection',            techniques: ['T1114','T1119','T1005','T1025','T1039','T1074','T1185','T1560'] },
    TA0010: { name: 'Exfiltration',          techniques: ['T1020','T1030','T1048','T1041','T1011','T1052','T1567','T1029'] },
    TA0011: { name: 'Command & Control',     techniques: ['T1071','T1095','T1571','T1572','T1573','T1008','T1105','T1132'] },
    TA0040: { name: 'Impact',                techniques: ['T1485','T1486','T1491','T1498','T1499','T1529','T1561','T1657'] },
  };

  /* ─── Detection Rules ───────────────────────────────────────────── */
  const DETECTION_RULES = [
    {
      id: 'DR-001', name: 'Brute Force Attack', category: 'credential_attack',
      severity: 'high', mitre: ['T1110'], tactic: 'TA0006',
      patterns: [/failed\s+(login|password|auth)/gi, /authentication\s+failure/gi,
                 /invalid\s+(credentials?|password)/gi, /login\s+failed/gi,
                 /wrong\s+password/gi, /account\s+locked/gi],
      threshold: 'bruteForce',
      description: 'Multiple failed authentication attempts indicating brute force attack.'
    },
    {
      id: 'DR-002', name: 'Credential Stuffing', category: 'credential_attack',
      severity: 'high', mitre: ['T1110.004'], tactic: 'TA0006',
      patterns: [/credential\s+stuffing/gi, /account\s+takeover/gi,
                 /multiple.*accounts.*same.*ip/gi, /auth.*attempt.*\d{3,}/gi],
      description: 'High-volume authentication attempts with different username/password combinations.'
    },
    {
      id: 'DR-003', name: 'Privilege Escalation', category: 'privilege_escalation',
      severity: 'critical', mitre: ['T1068','T1548'], tactic: 'TA0004',
      patterns: [/sudo\s+-s/gi, /su\s+root/gi, /privilege\s+escal/gi,
                 /UAC\s+bypass/gi, /token\s+impersonation/gi, /setuid/gi,
                 /runas\s+\/user/gi, /net\s+localgroup\s+administrators/gi,
                 /SeDebugPrivilege/gi, /SeTcbPrivilege/gi],
      description: 'Attempt to gain elevated privileges on target system.'
    },
    {
      id: 'DR-004', name: 'Lateral Movement - SMB', category: 'lateral_movement',
      severity: 'high', mitre: ['T1021.002'], tactic: 'TA0008',
      patterns: [/smb.*login/gi, /net\s+use/gi, /\\\\.*\\.*\$\b/gi,
                 /psexec/gi, /wmic.*\/node/gi, /impacket/gi],
      description: 'SMB-based lateral movement between internal hosts.'
    },
    {
      id: 'DR-005', name: 'Lateral Movement - WinRM', category: 'lateral_movement',
      severity: 'high', mitre: ['T1021.006'], tactic: 'TA0008',
      patterns: [/winrm/gi, /5985|5986/g, /invoke-command.*computername/gi,
                 /enter-pssession/gi, /new-pssession/gi],
      description: 'Windows Remote Management used for lateral movement.'
    },
    {
      id: 'DR-006', name: 'Web Application Attack', category: 'web_attack',
      severity: 'high', mitre: ['T1190'], tactic: 'TA0001',
      patterns: [/sql\s*injection/gi, /union\s+select/gi, /\bxss\b/gi,
                 /<script>/gi, /\bLFI\b|\bRFI\b|\bSSRF\b/gi,
                 /\.\.\/\.\.\/\.\.\//gi, /base64_decode/gi,
                 /cmd\.exe|\/bin\/sh|\/bin\/bash/gi, /exec\(|system\(|eval\(/gi],
      description: 'Web application attack detected including SQLi, XSS, LFI, RFI, SSRF.'
    },
    {
      id: 'DR-007', name: 'Port Scanning', category: 'reconnaissance',
      severity: 'medium', mitre: ['T1046'], tactic: 'TA0007',
      patterns: [/port\s+scan/gi, /nmap/gi, /masscan/gi, /zmap/gi,
                 /syn\s+scan/gi, /stealth\s+scan/gi, /host\s+discovery/gi],
      threshold: 'portScan',
      description: 'Network port scanning activity detected.'
    },
    {
      id: 'DR-008', name: 'Data Exfiltration', category: 'exfiltration',
      severity: 'critical', mitre: ['T1048','T1041'], tactic: 'TA0010',
      patterns: [/data\s+exfil/gi, /dns\s+tunnel/gi, /http\s+exfil/gi,
                 /large.*upload/gi, /outbound.*megabytes?/gi,
                 /curl.*upload/gi, /ftp.*put/gi, /scp.*remote/gi],
      description: 'Potential data exfiltration over DNS, HTTP, or FTP channels.'
    },
    {
      id: 'DR-009', name: 'Malware Indicators', category: 'malware',
      severity: 'critical', mitre: ['T1059','T1055'], tactic: 'TA0002',
      patterns: [/malware|ransomware|trojan|backdoor|rootkit/gi,
                 /c2\s+server|command.*control/gi, /beacon/gi,
                 /powershell.*encodedcommand/gi, /powershell.*-enc\b/gi,
                 /mshta|wscript|cscript/gi, /regsvr32.*\/s.*\/u/gi,
                 /certutil.*-decode/gi, /bitsadmin.*transfer/gi],
      description: 'Malware execution or C2 communication indicators found.'
    },
    {
      id: 'DR-010', name: 'Ransomware Activity', category: 'malware',
      severity: 'critical', mitre: ['T1486'], tactic: 'TA0040',
      patterns: [/ransomware/gi, /file.*encrypt/gi, /\.locked$|\.enc$|\.crypt$/gi,
                 /README.*DECRYPT|HOW_TO_DECRYPT/gi, /shadow\s+copy\s+delete/gi,
                 /vssadmin.*delete/gi, /wmic.*shadowcopy.*delete/gi],
      description: 'Ransomware infection or shadow copy deletion activity detected.'
    },
    {
      id: 'DR-011', name: 'Command & Control Beacon', category: 'c2',
      severity: 'critical', mitre: ['T1071','T1095'], tactic: 'TA0011',
      patterns: [/beacon\s+interval/gi, /c2\s+callback/gi, /heartbeat.*malware/gi,
                 /cobalt\s+strike/gi, /metasploit/gi, /meterpreter/gi,
                 /empire\s+agent/gi, /sliver\s+implant/gi],
      description: 'C2 beacon or implant communication detected.'
    },
    {
      id: 'DR-012', name: 'DNS Tunneling', category: 'c2',
      severity: 'high', mitre: ['T1071.004'], tactic: 'TA0011',
      patterns: [/dns\s+tunnel/gi, /iodine|dnscat|dns2tcp/gi,
                 /txt\s+record.*base64/gi, /high.*entropy.*dns/gi],
      description: 'DNS tunneling used for C2 communications or data exfiltration.'
    },
    {
      id: 'DR-013', name: 'PowerShell Attack', category: 'execution',
      severity: 'high', mitre: ['T1059.001'], tactic: 'TA0002',
      patterns: [/powershell.*-nop/gi, /powershell.*-w\s+hidden/gi,
                 /powershell.*bypass/gi, /invoke-expression/gi, /IEX\s*\(/gi,
                 /-EncodedCommand/gi, /downloadstring/gi, /invoke-webrequest.*exec/gi],
      description: 'Suspicious PowerShell execution with obfuscation or download cradle.'
    },
    {
      id: 'DR-014', name: 'Process Injection', category: 'evasion',
      severity: 'high', mitre: ['T1055'], tactic: 'TA0005',
      patterns: [/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/gi,
                 /process\s+injection/gi, /dll\s+injection/gi,
                 /reflective\s+load/gi, /process\s+hollowing/gi],
      description: 'Code injection into a remote process detected.'
    },
    {
      id: 'DR-015', name: 'Defense Evasion - Log Tampering', category: 'evasion',
      severity: 'high', mitre: ['T1070'], tactic: 'TA0005',
      patterns: [/clear\s+(event\s+)?log/gi, /wevtutil\s+cl/gi,
                 /Remove-EventLog/gi, /auditpol.*disable/gi,
                 /history\s+-c|unset\s+HISTFILE/gi, /shred.*\/var\/log/gi],
      description: 'Attacker attempting to clear or tamper with audit logs.'
    },
    {
      id: 'DR-016', name: 'Credential Dumping', category: 'credential_access',
      severity: 'critical', mitre: ['T1003'], tactic: 'TA0006',
      patterns: [/mimikatz/gi, /sekurlsa/gi, /lsadump/gi, /procdump.*lsass/gi,
                 /task\s+list.*lsass/gi, /comsvcs.*MiniDump/gi,
                 /hashdump/gi, /ntds\.dit/gi, /sam.*hive/gi],
      description: 'Credential dumping tools or LSASS memory access detected.'
    },
    {
      id: 'DR-017', name: 'Persistence - Scheduled Task', category: 'persistence',
      severity: 'medium', mitre: ['T1053'], tactic: 'TA0003',
      patterns: [/schtasks.*create/gi, /cron.*\*/gi, /at\s+\d+:\d+/gi,
                 /New-ScheduledTask/gi, /Register-ScheduledTask/gi],
      description: 'New scheduled task created for persistence.'
    },
    {
      id: 'DR-018', name: 'Account Creation / Modification', category: 'persistence',
      severity: 'medium', mitre: ['T1136'], tactic: 'TA0003',
      patterns: [/net\s+user.*\/add/gi, /useradd\b/gi, /New-LocalUser/gi,
                 /adduser\b/gi, /net\s+localgroup.*\/add/gi,
                 /usermod.*-aG/gi, /passwd\s+root/gi],
      description: 'New user account created or existing account modified.'
    },
    {
      id: 'DR-019', name: 'Suspicious File Access', category: 'collection',
      severity: 'medium', mitre: ['T1005','T1039'], tactic: 'TA0009',
      patterns: [/\/etc\/shadow|\/etc\/passwd/gi, /sam\s+database/gi,
                 /ntds\.dit/gi, /security\.evt/gi, /sensitive.*files?.*accessed/gi,
                 /\.kdbx|keepass/gi, /id_rsa|\.pem$/gi],
      description: 'Access to sensitive credential or key files.'
    },
    {
      id: 'DR-020', name: 'Network Reconnaissance', category: 'reconnaissance',
      severity: 'low', mitre: ['T1046','T1018'], tactic: 'TA0007',
      patterns: [/arp\s+-a/gi, /netstat\s+-a/gi, /ipconfig\s+\/all/gi,
                 /ifconfig\b/gi, /route\s+print/gi, /net\s+view/gi,
                 /ldapsearch/gi, /BloodHound/gi, /SharpHound/gi],
      description: 'Network and domain reconnaissance activity detected.'
    },
    {
      id: 'DR-021', name: 'Suspicious Registry Modification', category: 'persistence',
      severity: 'medium', mitre: ['T1547.001'], tactic: 'TA0003',
      patterns: [/HKLM.*Run/gi, /HKCU.*Run/gi, /reg\s+add.*run/gi,
                 /Set-ItemProperty.*HKLM/gi, /RegSetValueEx/gi],
      description: 'Registry Run key modified for persistence.'
    },
    {
      id: 'DR-022', name: 'LOLBAS / Living-off-the-Land', category: 'evasion',
      severity: 'medium', mitre: ['T1218'], tactic: 'TA0005',
      patterns: [/regsvr32.*\/s\/u/gi, /mshta.*http/gi, /rundll32.*javascript/gi,
                 /certutil.*-urlcache/gi, /bitsadmin.*\/transfer/gi,
                 /wmic.*process.*call.*create/gi, /installutil/gi],
      description: 'Living-off-the-land binary (LOLBAS) abuse detected.'
    },
    {
      id: 'DR-023', name: 'Suspicious Outbound Connection', category: 'c2',
      severity: 'medium', mitre: ['T1571'], tactic: 'TA0011',
      patterns: [/outbound.*\b(4444|1337|31337|6667|6660|8443|4433)\b/gi,
                 /unexpected.*egress/gi, /non-standard\s+port/gi],
      description: 'Outbound connection on unusual or suspicious port.'
    },
    {
      id: 'DR-024', name: 'Phishing / Spearphishing', category: 'initial_access',
      severity: 'high', mitre: ['T1566'], tactic: 'TA0001',
      patterns: [/phishing|spearphish/gi, /malicious.*attachment/gi,
                 /suspicious.*link/gi, /credential.*harvest/gi,
                 /evilginx|gophish|modlishka/gi],
      description: 'Phishing or spearphishing indicators detected.'
    },
    {
      id: 'DR-025', name: 'Supply Chain Compromise', category: 'initial_access',
      severity: 'critical', mitre: ['T1195'], tactic: 'TA0001',
      patterns: [/supply\s+chain/gi, /solarwinds|sunburst/gi,
                 /dependency\s+confusion/gi, /typosquat/gi,
                 /malicious.*package/gi, /backdoor.*library/gi],
      description: 'Supply chain compromise or malicious package indicators.'
    },
  ];

  /* ─── Log Type Detection ─────────────────────────────────────────── */
  function detectLogType(content) {
    const s = content.substring(0, 2000).toLowerCase();
    if (/\beventid\b|\bwinlog\b|<event>|evtx/.test(s)) return 'windows_event';
    if (/\bsyslog\b|\bfacility\b|\bseverity\b|\bproc\b.*\[\d+\]/.test(s)) return 'syslog';
    if (/apache|nginx|http\/\d|"get |"post |"put /.test(s)) return 'web_access';
    if (/\bfirewall\b|\bpolicy\b.*\ballow\b|\bdeny\b.*\bport\b/.test(s)) return 'firewall';
    if (/\bsuricata\b|\bsnort\b|\bsig_id\b|\bsignature\b.*\balert\b/.test(s)) return 'ids_ips';
    if (/\bzeek\b|\bconn\.log\b|\bhttp\.log\b/.test(s)) return 'zeek';
    if (/\bsudo\b|\bpam_unix\b|\bfailed\s+password\b.*\bssh\b/.test(s)) return 'auth';
    if (/"src_ip"|"dst_ip"|"event_type"/.test(s)) return 'json_structured';
    if (/\bpowershell\b|\bpshost\b|\bscriptblock\b/.test(s)) return 'powershell';
    if (/\bprocess\s+create|\bevent\s+id.*4688/.test(s)) return 'process_audit';
    if (/\[WARN\]|\[ERROR\]|\[INFO\]|\[DEBUG\]/.test(s)) return 'application';
    return 'generic';
  }

  /* ─── Log Parser ─────────────────────────────────────────────────── */
  function parseLogs(content, type) {
    const lines = content.split(/\r?\n/).filter(l => l.trim());
    const entries = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const entry = { raw: line, index: i + 1, timestamp: null, source_ip: null,
                      dest_ip: null, user: null, action: null, level: 'info' };

      // Extract timestamp
      const tsPatterns = [
        /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/,
        /(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,
        /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/,
      ];
      for (const p of tsPatterns) {
        const m = line.match(p);
        if (m) { entry.timestamp = m[1]; break; }
      }

      // Extract IPs
      const ipMatches = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
      if (ipMatches) {
        entry.source_ip = ipMatches[0];
        if (ipMatches[1]) entry.dest_ip = ipMatches[1];
      }

      // Extract user
      const userMatch = line.match(/(?:user|username|account)[=:\s]+["']?([a-zA-Z0-9_@.-]{2,50})/i);
      if (userMatch) entry.user = userMatch[1];

      // Detect severity level
      if (/critical|fatal|emerg/i.test(line)) entry.level = 'critical';
      else if (/error|fail|denied|attack/i.test(line)) entry.level = 'error';
      else if (/warn|suspicious|anomal/i.test(line)) entry.level = 'warning';

      entries.push(entry);
    }
    return entries;
  }

  /* ─── Detection Engine ──────────────────────────────────────────── */
  function runDetectionRules(entries, rawContent) {
    const findings = [];
    const ipCounts = {};
    const userFailCounts = {};
    const portHits = [];

    // Count IPs & failures for threshold rules
    for (const e of entries) {
      if (e.source_ip) {
        ipCounts[e.source_ip] = (ipCounts[e.source_ip] || 0) + 1;
      }
      if (/fail|denied|invalid/i.test(e.raw) && e.user) {
        userFailCounts[e.user] = (userFailCounts[e.user] || 0) + 1;
      }
    }

    // Apply each rule
    for (const rule of DETECTION_RULES) {
      const matchedLines = [];

      for (const entry of entries) {
        let matched = false;
        for (const pattern of rule.patterns) {
          if (pattern.test(entry.raw)) {
            matched = true;
            pattern.lastIndex = 0; // reset regex state
            break;
          }
        }
        if (matched) matchedLines.push(entry);
      }

      // Threshold-based check
      let thresholdTriggered = false;
      if (rule.threshold === 'bruteForce') {
        thresholdTriggered = Object.values(ipCounts).some(c => c >= CFG.thresholds.bruteForce)
                           || matchedLines.length >= CFG.thresholds.bruteForce;
      } else if (rule.threshold === 'portScan') {
        thresholdTriggered = matchedLines.length >= 3;
      }

      if (matchedLines.length > 0 || thresholdTriggered) {
        const affectedIPs = [...new Set(matchedLines.map(e => e.source_ip).filter(Boolean))];
        const affectedUsers = [...new Set(matchedLines.map(e => e.user).filter(Boolean))];

        findings.push({
          rule_id: rule.id,
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          confidence: calcConfidence(matchedLines.length, rule),
          mitre_techniques: rule.mitre,
          mitre_tactic: rule.tactic,
          tactic_name: MITRE_TACTICS[rule.tactic]?.name || rule.tactic,
          description: rule.description,
          match_count: matchedLines.length,
          affected_ips: affectedIPs,
          affected_users: affectedUsers,
          sample_lines: matchedLines.slice(0, 5).map(e => e.raw),
          first_seen: matchedLines[0]?.timestamp || null,
          last_seen: matchedLines[matchedLines.length - 1]?.timestamp || null,
        });
      }
    }

    return findings;
  }

  /* ─── Confidence Scoring ────────────────────────────────────────── */
  function calcConfidence(matchCount, rule) {
    let base = Math.min(matchCount / 3, 1) * 0.7;
    // Boost for high severity
    if (rule.severity === 'critical') base = Math.min(base + 0.2, 1);
    else if (rule.severity === 'high') base = Math.min(base + 0.1, 1);
    // Apply false-positive reduction
    if (['DR-017','DR-020','DR-018'].includes(rule.id)) base = Math.max(base - 0.1, 0.1);
    return Math.round(base * 100);
  }

  /* ─── Risk Score Calculator ─────────────────────────────────────── */
  function calcRiskScore(findings) {
    if (!findings.length) return { score: 0, level: 'LOW', breakdown: {} };

    const weights = { critical: 40, high: 20, medium: 10, low: 3 };
    let raw = 0;
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const f of findings) {
      const w = weights[f.severity] || 1;
      raw += w * (f.confidence / 100);
      breakdown[f.severity] = (breakdown[f.severity] || 0) + 1;
    }

    const score = Math.min(Math.round(raw), 100);
    let level = 'LOW';
    if (score >= 80) level = 'CRITICAL';
    else if (score >= 60) level = 'HIGH';
    else if (score >= 35) level = 'MEDIUM';

    return { score, level, breakdown,
             factors: findings.map(f => ({ name: f.name, weight: weights[f.severity], confidence: f.confidence })) };
  }

  /* ─── Timeline Builder ──────────────────────────────────────────── */
  function buildTimeline(entries, findings) {
    const events = [];
    const seen = new Set();

    for (const f of findings) {
      for (const line of f.sample_lines) {
        if (!seen.has(line)) {
          seen.add(line);
          const entry = entries.find(e => e.raw === line);
          events.push({
            timestamp: entry?.timestamp || 'Unknown',
            event: f.name,
            severity: f.severity,
            category: f.category,
            detail: line.substring(0, 200),
            mitre: f.mitre_techniques[0] || '',
            tactic: f.tactic_name,
          });
        }
      }
    }

    // Sort by time
    events.sort((a, b) => {
      if (a.timestamp === 'Unknown') return 1;
      if (b.timestamp === 'Unknown') return -1;
      return new Date(a.timestamp) - new Date(b.timestamp);
    });

    return events.slice(0, 50);
  }

  /* ─── Entity Extraction ─────────────────────────────────────────── */
  function extractEntities(entries, findings) {
    const entities = {};

    for (const entry of entries) {
      if (entry.source_ip) {
        const k = `ip:${entry.source_ip}`;
        if (!entities[k]) entities[k] = { type: 'ip', value: entry.source_ip, count: 0, severity: 'info', flags: [] };
        entities[k].count++;
      }
      if (entry.user) {
        const k = `user:${entry.user}`;
        if (!entities[k]) entities[k] = { type: 'user', value: entry.user, count: 0, severity: 'info', flags: [] };
        entities[k].count++;
      }
    }

    // Flag entities involved in findings
    for (const f of findings) {
      for (const ip of f.affected_ips) {
        const k = `ip:${ip}`;
        if (entities[k]) {
          entities[k].severity = maxSeverity(entities[k].severity, f.severity);
          entities[k].flags.push(f.name);
        }
      }
      for (const user of f.affected_users) {
        const k = `user:${user}`;
        if (entities[k]) {
          entities[k].severity = maxSeverity(entities[k].severity, f.severity);
          entities[k].flags.push(f.name);
        }
      }
    }

    return Object.values(entities)
      .filter(e => e.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 50);
  }

  function maxSeverity(a, b) {
    const order = ['info','low','medium','high','critical'];
    return order.indexOf(a) > order.indexOf(b) ? a : b;
  }

  /* ─── MITRE Coverage Map ─────────────────────────────────────────── */
  function buildMITREMapping(findings) {
    const covered = {};
    for (const f of findings) {
      if (!covered[f.mitre_tactic]) {
        covered[f.mitre_tactic] = {
          tactic_id: f.mitre_tactic,
          tactic_name: f.tactic_name,
          techniques: [],
        };
      }
      for (const t of f.mitre_techniques) {
        if (!covered[f.mitre_tactic].techniques.find(x => x.id === t)) {
          covered[f.mitre_tactic].techniques.push({
            id: t,
            name: f.name,
            severity: f.severity,
            confidence: f.confidence,
          });
        }
      }
    }
    return Object.values(covered);
  }

  /* ─── Local Narrative Generator ─────────────────────────────────── */
  function generateLocalNarrative(summary, findings, riskScore) {
    if (!findings.length) {
      return 'No significant threats detected in the analyzed log data. The logs appear clean or may not contain adversarial activity within the scope of the current detection ruleset.';
    }

    const critical = findings.filter(f => f.severity === 'critical');
    const high = findings.filter(f => f.severity === 'high');
    const tactics = [...new Set(findings.map(f => f.tactic_name))];
    const topIPs = [...new Set(findings.flatMap(f => f.affected_ips))].slice(0, 3);

    let narrative = `## Attack Narrative\n\n`;
    narrative += `Analysis of the provided logs reveals a **${riskScore.level} risk** security incident `;
    narrative += `with an overall risk score of **${riskScore.score}/100**.\n\n`;

    if (critical.length) {
      narrative += `### Critical Threats Detected\n`;
      for (const f of critical) {
        narrative += `- **${f.name}** (${f.rule_id}): ${f.description} `;
        narrative += `Detected ${f.match_count} occurrence(s) with ${f.confidence}% confidence. `;
        narrative += `MITRE: ${f.mitre_techniques.join(', ')} — ${f.tactic_name}.\n`;
      }
      narrative += '\n';
    }

    if (high.length) {
      narrative += `### High Severity Findings\n`;
      for (const f of high) {
        narrative += `- **${f.name}**: ${f.description} (${f.match_count} match(es), ${f.confidence}% confidence)\n`;
      }
      narrative += '\n';
    }

    if (tactics.length) {
      narrative += `### Attack Tactics Observed\n`;
      narrative += `The following MITRE ATT&CK tactics were identified: **${tactics.join(', ')}**.\n\n`;
    }

    if (topIPs.length) {
      narrative += `### Suspicious IP Addresses\n`;
      narrative += `Key source IPs implicated: ${topIPs.map(ip => `\`${ip}\``).join(', ')}.\n\n`;
    }

    narrative += `### Conclusion\n`;
    narrative += `Immediate investigation and response is ${riskScore.score >= 60 ? '**strongly recommended**' : 'recommended'}. `;
    narrative += `Prioritize containment of ${critical.length > 0 ? critical[0].name : (high[0]?.name || 'identified threats')} `;
    narrative += `and review all flagged source IPs and user accounts.`;

    return narrative;
  }

  /* ─── OpenAI Analysis ───────────────────────────────────────────── */
  async function runOpenAIAnalysis(logSample, findings, riskScore) {
    if (!CFG.openaiKey) return null;

    const prompt = `You are a senior SOC analyst. Analyze the following security log data and threat findings.

LOG SAMPLE (first 2000 chars):
${logSample.substring(0, 2000)}

DETECTED FINDINGS (${findings.length} total):
${findings.map(f => `- [${f.severity.toUpperCase()}] ${f.name}: ${f.description} (${f.match_count} occurrences, ${f.confidence}% confidence, MITRE: ${f.mitre_techniques.join(',')})`).join('\n')}

RISK SCORE: ${riskScore.score}/100 (${riskScore.level})

Provide a structured JSON response with these exact fields:
{
  "executive_summary": "2-3 sentence executive summary for CISO",
  "attack_narrative": "detailed markdown narrative of the attack",
  "root_cause": "root cause analysis",
  "false_positive_notes": "any likely false positives and why",
  "immediate_actions": ["action1", "action2", "action3"],
  "recommendations": [
    {"priority": "immediate|short-term|long-term", "action": "...", "rationale": "..."}
  ],
  "threat_classification": "APT|Insider|Script Kiddie|Automated|Unknown",
  "confidence_assessment": "overall analyst confidence note"
}`;

    try {
      const resp = await fetch(CFG.openaiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${CFG.openaiKey}`,
        },
        body: JSON.stringify({
          model: CFG.openaiModel,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.3,
          max_tokens: 1500,
          response_format: { type: 'json_object' },
        }),
      });

      if (!resp.ok) {
        console.warn('[SOCEngine] OpenAI API error:', resp.status);
        return null;
      }

      const data = await resp.json();
      const content = data.choices?.[0]?.message?.content;
      if (content) return JSON.parse(content);
    } catch (err) {
      console.warn('[SOCEngine] OpenAI call failed:', err.message);
    }
    return null;
  }

  /* ─── AI Chat Query ─────────────────────────────────────────────── */
  async function chatQuery(question, context) {
    if (!CFG.openaiKey) {
      return generateLocalChatResponse(question, context);
    }

    const systemPrompt = `You are an expert SOC analyst assistant for Wadjet-Eye AI. 
Answer questions about the current investigation context concisely and accurately.
Context: ${JSON.stringify(context).substring(0, 3000)}`;

    try {
      const resp = await fetch(CFG.openaiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${CFG.openaiKey}`,
        },
        body: JSON.stringify({
          model: CFG.openaiModel,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: question },
          ],
          temperature: 0.4,
          max_tokens: 800,
        }),
      });

      if (!resp.ok) return generateLocalChatResponse(question, context);
      const data = await resp.json();
      return data.choices?.[0]?.message?.content || generateLocalChatResponse(question, context);
    } catch {
      return generateLocalChatResponse(question, context);
    }
  }

  function generateLocalChatResponse(question, context) {
    const q = question.toLowerCase();
    const findings = context?.findings || [];
    const riskScore = context?.risk_score || {};
    const entities = context?.entities || [];

    if (/root cause|why|how did/i.test(q)) {
      const topFinding = findings.find(f => f.severity === 'critical') || findings[0];
      return topFinding
        ? `**Root Cause Analysis**: The most likely root cause is **${topFinding.name}** (${topFinding.rule_id}). ${topFinding.description} This was detected with ${topFinding.confidence}% confidence across ${topFinding.match_count} log entries.`
        : 'No critical findings identified to determine root cause.';
    }

    if (/suspicious ip|attacker ip|source ip/i.test(q)) {
      const ips = entities.filter(e => e.type === 'ip' && e.severity !== 'info');
      return ips.length
        ? `**Suspicious IPs**: ${ips.map(e => `\`${e.value}\` (${e.severity}, ${e.count} events, flags: ${e.flags.slice(0,2).join(', ')})`).join('; ')}`
        : 'No suspicious IPs identified in this investigation.';
    }

    if (/risk score|severity|how bad/i.test(q)) {
      return `**Risk Score**: ${riskScore.score || 0}/100 — Level: **${riskScore.level || 'UNKNOWN'}**. ` +
        `Breakdown: Critical: ${riskScore.breakdown?.critical || 0}, High: ${riskScore.breakdown?.high || 0}, ` +
        `Medium: ${riskScore.breakdown?.medium || 0}, Low: ${riskScore.breakdown?.low || 0}.`;
    }

    if (/mitre|tactic|technique/i.test(q)) {
      const tactics = [...new Set(findings.map(f => f.tactic_name))];
      const techs = [...new Set(findings.flatMap(f => f.mitre_techniques))];
      return tactics.length
        ? `**MITRE Coverage**: Tactics: ${tactics.join(', ')}. Techniques: ${techs.join(', ')}.`
        : 'No MITRE mappings available for current findings.';
    }

    if (/recommend|action|fix|remediat/i.test(q)) {
      const crits = findings.filter(f => ['critical','high'].includes(f.severity));
      if (!crits.length) return 'No critical or high findings requiring immediate action.';
      return `**Immediate Recommendations**:\n` +
        crits.slice(0,3).map((f, i) => `${i+1}. **${f.name}**: Investigate and contain affected IPs (${f.affected_ips.join(', ') || 'unknown'}). Review all associated accounts.`).join('\n');
    }

    if (/finding|detection|alert/i.test(q)) {
      return findings.length
        ? `**${findings.length} findings detected**: ${findings.slice(0,5).map(f => `${f.name} (${f.severity})`).join(', ')}${findings.length > 5 ? ` and ${findings.length-5} more` : ''}.`
        : 'No findings detected in the current analysis.';
    }

    return `I can answer questions about: root cause analysis, suspicious IPs, risk scores, MITRE ATT&CK tactics, recommendations, and findings. What would you like to know about the current investigation?`;
  }

  /* ─── Recommendations Generator ─────────────────────────────────── */
  function generateRecommendations(findings, riskScore) {
    const recs = [];
    const seen = new Set();

    const recMap = {
      credential_attack:    { priority: 'immediate', action: 'Implement account lockout policy and enable MFA for all users', rationale: 'Prevents credential-based attacks' },
      privilege_escalation: { priority: 'immediate', action: 'Review and restrict sudo/admin rights; enforce least privilege', rationale: 'Limits blast radius of compromise' },
      lateral_movement:     { priority: 'immediate', action: 'Isolate affected hosts and review network segmentation', rationale: 'Stops spread of compromise' },
      web_attack:           { priority: 'immediate', action: 'Deploy/tune WAF rules, patch vulnerable web applications', rationale: 'Blocks web-based attack vectors' },
      exfiltration:         { priority: 'immediate', action: 'Block outbound connections from affected hosts, review DLP controls', rationale: 'Prevents data loss' },
      malware:              { priority: 'immediate', action: 'Quarantine affected systems, run full AV/EDR scan', rationale: 'Contains malware spread' },
      c2:                   { priority: 'immediate', action: 'Block C2 infrastructure IPs/domains at firewall/proxy', rationale: 'Cuts attacker communication' },
      evasion:              { priority: 'short-term', action: 'Enable enhanced audit logging; monitor LOLBAS execution', rationale: 'Improves detection coverage' },
      persistence:          { priority: 'short-term', action: 'Audit scheduled tasks, startup items, and new user accounts', rationale: 'Removes attacker footholds' },
      reconnaissance:       { priority: 'short-term', action: 'Review network exposure; consider honeypots for early detection', rationale: 'Detects early-stage attacks' },
      initial_access:       { priority: 'short-term', action: 'Conduct phishing awareness training; review email filtering', rationale: 'Reduces initial access vectors' },
    };

    for (const f of findings) {
      if (!seen.has(f.category) && recMap[f.category]) {
        seen.add(f.category);
        recs.push({ ...recMap[f.category], trigger: f.name });
      }
    }

    // General recommendations
    if (riskScore.score >= 60) {
      recs.push({ priority: 'immediate', action: 'Activate Incident Response team and follow IR playbook', rationale: 'High risk score requires coordinated response', trigger: 'Risk Score' });
    }
    recs.push({ priority: 'long-term', action: 'Deploy SIEM with correlation rules for the detected attack patterns', rationale: 'Improves future detection capability', trigger: 'General' });
    recs.push({ priority: 'long-term', action: 'Schedule red team exercise targeting identified attack paths', rationale: 'Validates security controls', trigger: 'General' });

    return recs;
  }

  /* ─── Main Analysis Orchestrator ────────────────────────────────── */
  async function analyzeLog(content, filename, options = {}) {
    const startTime = Date.now();

    // Step 1: Detect log type
    const logType = detectLogType(content);

    // Step 2: Parse log entries
    const entries = parseLogs(content, logType);

    // Step 3: Run detection rules
    const findings = runDetectionRules(entries, content);

    // Step 4: Calculate risk score
    const riskScore = calcRiskScore(findings);

    // Step 5: Build timeline
    const timeline = buildTimeline(entries, findings);

    // Step 6: Extract entities
    const entities = extractEntities(entries, findings);

    // Step 7: Build MITRE mapping
    const mitreMapping = buildMITREMapping(findings);

    // Step 8: Generate narrative (local first)
    let narrative = generateLocalNarrative(
      { filename, logType, totalLines: entries.length },
      findings, riskScore
    );

    // Step 9: AI enhancement (optional)
    let aiInsights = null;
    if (options.useAI !== false) {
      aiInsights = await runOpenAIAnalysis(content, findings, riskScore);
      if (aiInsights?.attack_narrative) narrative = aiInsights.attack_narrative;
    }

    // Step 10: Build recommendations
    const recommendations = aiInsights?.recommendations || generateRecommendations(findings, riskScore);
    const immediateActions = aiInsights?.immediate_actions || recommendations
      .filter(r => r.priority === 'immediate').map(r => r.action).slice(0, 5);

    const duration = Date.now() - startTime;

    return {
      summary: {
        filename: filename || 'unnamed',
        log_type: logType,
        total_lines: entries.length,
        total_findings: findings.length,
        critical_count: findings.filter(f => f.severity === 'critical').length,
        high_count: findings.filter(f => f.severity === 'high').length,
        medium_count: findings.filter(f => f.severity === 'medium').length,
        low_count: findings.filter(f => f.severity === 'low').length,
        analysis_duration_ms: duration,
        ai_enhanced: !!aiInsights,
        executive_summary: aiInsights?.executive_summary || buildExecSummary(findings, riskScore, entries.length),
        attack_narrative: narrative,
        root_cause: aiInsights?.root_cause || (findings[0] ? `Primary root cause: ${findings[0].name} — ${findings[0].description}` : 'No clear root cause identified.'),
        threat_classification: aiInsights?.threat_classification || classifyThreat(findings),
        false_positive_notes: aiInsights?.false_positive_notes || 'Review low-confidence findings (< 40%) as potential false positives.',
        immediate_actions: immediateActions,
        confidence_assessment: aiInsights?.confidence_assessment || `${Math.round(findings.reduce((s,f) => s + f.confidence, 0) / Math.max(findings.length, 1))}% average detection confidence`,
      },
      findings,
      timeline,
      entities,
      mitre_mapping: mitreMapping,
      risk_score: riskScore,
      recommendations,
    };
  }

  function buildExecSummary(findings, riskScore, lines) {
    if (!findings.length) return `Analysis of ${lines.toLocaleString()} log entries revealed no significant threats. The environment appears normal.`;
    const topThreat = findings[0];
    return `Security analysis of ${lines.toLocaleString()} log entries identified ${findings.length} threat finding(s) with an overall risk score of ${riskScore.score}/100 (${riskScore.level}). The highest severity finding is **${topThreat.name}** mapping to MITRE ATT&CK ${topThreat.mitre_techniques[0]}. Immediate investigation is ${riskScore.score >= 60 ? 'urgently required' : 'recommended'}.`;
  }

  function classifyThreat(findings) {
    const cats = findings.map(f => f.category);
    if (cats.includes('c2') && cats.includes('lateral_movement')) return 'APT';
    if (cats.includes('malware') || cats.includes('ransomware')) return 'Malware Campaign';
    if (cats.includes('credential_attack')) return 'Credential Attack';
    if (cats.includes('web_attack')) return 'Web Application Attack';
    if (cats.includes('reconnaissance')) return 'Reconnaissance / Scanning';
    return 'Unknown Threat Actor';
  }

  /* ─── Real-time Ingestion Analysis ──────────────────────────────── */
  async function analyzeRealtimeEvent(event) {
    const content = typeof event === 'string' ? event : JSON.stringify(event);
    const entries = parseLogs(content, detectLogType(content));
    const findings = runDetectionRules(entries, content);
    return { findings, risk: calcRiskScore(findings), entities: extractEntities(entries, findings) };
  }

  /* ─── Public API ─────────────────────────────────────────────────── */
  return {
    analyzeLog,
    analyzeRealtimeEvent,
    chatQuery,
    detectLogType,
    parseLogs,
    runDetectionRules,
    calcRiskScore,
    buildTimeline,
    extractEntities,
    buildMITREMapping,
    generateRecommendations,
    DETECTION_RULES,
    MITRE_TACTICS,
    setApiKey(key) { CFG.openaiKey = key; console.log('[SOCEngine] API key configured'); },
    setThresholds(t) { Object.assign(CFG.thresholds, t); },
    version: '1.0.0',
  };
})();
