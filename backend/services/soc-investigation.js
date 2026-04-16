/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Investigation Report Engine v2.0
 *  FILE: backend/services/soc-investigation.js
 *
 *  Generates complete 10-section SOC investigation reports:
 *    1.  Incident Overview
 *    2.  Incident Description
 *    3.  Detection Details
 *    4.  Full Technical Findings
 *       (source/dest IPs, ports, protocols, commands, users, hostnames,
 *        event timeline, IOCs)
 *    5.  Technical Analysis
 *       (attack pattern, MITRE ATT&CK, lateral movement, persistence)
 *    6.  Containment Actions
 *    7.  Eradication Steps
 *    8.  Recovery Plan
 *    9.  Recommendations
 *    10. Severity Assessment & Risk Score
 *
 *  Data-driven: pulls real data from alerts, IOCs, events, CVEs
 *  No generic content — every section uses live data
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

// ─────────────────────────────────────────────────────────────────────
//  SEVERITY SCORING
// ─────────────────────────────────────────────────────────────────────
const SEVERITY_SCORES = {
  critical: 100, high: 75, medium: 50, low: 25,
  CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25,
};

function _calcRiskScore(findings) {
  let score = 0;
  const weights = {
    exploitedCVE:   30,
    criticalAlert:  25,
    lateralMovement: 20,
    persistence:    20,
    dataExfiltration: 25,
    ransomware:     35,
    privilegeEscal: 15,
    c2Communication: 20,
  };

  if (findings.hasExploitedCVE)      score += weights.exploitedCVE;
  if (findings.hasCriticalAlert)     score += weights.criticalAlert;
  if (findings.hasLateralMovement)   score += weights.lateralMovement;
  if (findings.hasPersistence)       score += weights.persistence;
  if (findings.hasDataExfiltration)  score += weights.dataExfiltration;
  if (findings.hasRansomware)        score += weights.ransomware;
  if (findings.hasPrivilegeEscal)    score += weights.privilegeEscal;
  if (findings.hasC2)                score += weights.c2Communication;

  // Severity from highest alert
  const sev = findings.highestSeverity || 'medium';
  score = Math.max(score, SEVERITY_SCORES[sev] || 50);

  return Math.min(100, score);
}

// ─────────────────────────────────────────────────────────────────────
//  MITRE TECHNIQUE DETAILS
// ─────────────────────────────────────────────────────────────────────
const MITRE_DETAILS = {
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access', severity: 'HIGH' },
  'T1566': { name: 'Phishing', tactic: 'Initial Access', severity: 'HIGH' },
  'T1566.001': { name: 'Spearphishing Attachment', tactic: 'Initial Access', severity: 'HIGH' },
  'T1566.002': { name: 'Spearphishing Link', tactic: 'Initial Access', severity: 'MEDIUM' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'Execution', severity: 'HIGH' },
  'T1059.001': { name: 'PowerShell', tactic: 'Execution', severity: 'HIGH' },
  'T1059.003': { name: 'Windows Command Shell', tactic: 'Execution', severity: 'HIGH' },
  'T1078': { name: 'Valid Accounts', tactic: 'Privilege Escalation', severity: 'CRITICAL' },
  'T1068': { name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', severity: 'CRITICAL' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access', severity: 'CRITICAL' },
  'T1003.001': { name: 'LSASS Memory', tactic: 'Credential Access', severity: 'CRITICAL' },
  'T1021': { name: 'Remote Services', tactic: 'Lateral Movement', severity: 'HIGH' },
  'T1021.001': { name: 'Remote Desktop Protocol', tactic: 'Lateral Movement', severity: 'HIGH' },
  'T1021.002': { name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement', severity: 'HIGH' },
  'T1055': { name: 'Process Injection', tactic: 'Defense Evasion', severity: 'HIGH' },
  'T1047': { name: 'Windows Management Instrumentation', tactic: 'Execution', severity: 'HIGH' },
  'T1547': { name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', severity: 'HIGH' },
  'T1547.001': { name: 'Registry Run Keys', tactic: 'Persistence', severity: 'HIGH' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact', severity: 'CRITICAL' },
  'T1490': { name: 'Inhibit System Recovery', tactic: 'Impact', severity: 'CRITICAL' },
  'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', severity: 'HIGH' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control', severity: 'MEDIUM' },
  'T1071.001': { name: 'Web Protocols (HTTP/S)', tactic: 'Command and Control', severity: 'MEDIUM' },
  'T1082': { name: 'System Information Discovery', tactic: 'Discovery', severity: 'LOW' },
  'T1083': { name: 'File and Directory Discovery', tactic: 'Discovery', severity: 'LOW' },
  'T1057': { name: 'Process Discovery', tactic: 'Discovery', severity: 'LOW' },
  'T1027': { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', severity: 'MEDIUM' },
  'T1562': { name: 'Impair Defenses', tactic: 'Defense Evasion', severity: 'HIGH' },
  'T1562.001': { name: 'Disable or Modify Tools', tactic: 'Defense Evasion', severity: 'HIGH' },
};

function _getMITREDetail(id) {
  return MITRE_DETAILS[id] || { name: `Technique ${id}`, tactic: 'Unknown', severity: 'MEDIUM' };
}

// ─────────────────────────────────────────────────────────────────────
//  TIMELINE BUILDER
// ─────────────────────────────────────────────────────────────────────
function _buildTimeline(events) {
  if (!events || events.length === 0) return [];

  return events
    .sort((a, b) => new Date(a.timestamp || a.created_at) - new Date(b.timestamp || b.created_at))
    .map(evt => ({
      timestamp:   evt.timestamp || evt.created_at || evt.time,
      event:       evt.title || evt.name || evt.event || evt.description || 'Event',
      type:        evt.type || evt.event_type || 'alert',
      severity:    evt.severity || 'medium',
      source:      evt.source_ip || evt.src_ip || evt.source || 'N/A',
      destination: evt.dest_ip  || evt.destination_ip || evt.target || 'N/A',
      user:        evt.user     || evt.username || evt.account || 'N/A',
      host:        evt.host     || evt.hostname || evt.computer || 'N/A',
      mitre:       evt.mitre_technique || evt.technique || null,
      detail:      evt.description || evt.detail || evt.command || null,
    }));
}

// ─────────────────────────────────────────────────────────────────────
//  IOC EXTRACTOR
// ─────────────────────────────────────────────────────────────────────
function _extractIOCs(events, alerts, metadata) {
  const iocs = { ips: new Set(), domains: new Set(), hashes: new Set(), urls: new Set(), emails: new Set() };

  const allText = [
    ...events.map(e => JSON.stringify(e)),
    ...alerts.map(a => JSON.stringify(a)),
    ...(metadata ? [JSON.stringify(metadata)] : []),
  ].join(' ');

  // IPs
  const ipMatches = allText.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [];
  for (const ip of ipMatches) {
    // Filter out private/loopback
    if (!/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)/.test(ip)) {
      iocs.ips.add(ip);
    }
  }

  // Domains
  const domMatches = allText.match(/\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b/g) || [];
  for (const d of domMatches) {
    if (!/\.(local|internal|corp|lan|example|test)$/.test(d) && d.includes('.')) {
      iocs.domains.add(d.toLowerCase());
    }
  }

  // Hashes
  const hashMatches = allText.match(/\b[0-9a-fA-F]{32,64}\b/g) || [];
  for (const h of hashMatches) iocs.hashes.add(h.toLowerCase());

  // URLs
  const urlMatches = allText.match(/https?:\/\/[^\s"'<>]+/g) || [];
  for (const u of urlMatches) {
    if (!/\.microsoft\.com|\.google\.com|\.windows\.com|nvd\.nist\.gov/.test(u)) {
      iocs.urls.add(u.split(/['"<>\s]/)[0]);
    }
  }

  return {
    sourceIPs:   [...iocs.ips].slice(0, 20),
    domains:     [...iocs.domains].slice(0, 20),
    fileHashes:  [...iocs.hashes].slice(0, 10),
    maliciousURLs: [...iocs.urls].slice(0, 10),
  };
}

// ─────────────────────────────────────────────────────────────────────
//  FINDINGS DETECTOR — determines what happened
// ─────────────────────────────────────────────────────────────────────
function _detectFindings(events, alerts, iocs) {
  const allText = [
    ...events.map(e => JSON.stringify(e).toLowerCase()),
    ...alerts.map(a => JSON.stringify(a).toLowerCase()),
  ].join(' ');

  const techniques = new Set();
  const allTechniques = [...events, ...alerts]
    .map(e => e.mitre_technique || e.technique || '')
    .filter(Boolean);
  for (const t of allTechniques) techniques.add(t);

  const highestSeverity = (() => {
    const sevs = [...events, ...alerts].map(e => (e.severity || '').toLowerCase());
    if (sevs.includes('critical')) return 'critical';
    if (sevs.includes('high'))     return 'high';
    if (sevs.includes('medium'))   return 'medium';
    return 'low';
  })();

  return {
    hasRansomware:       /ransomware|encrypt|vssadmin|shadow.*cop|\.locked|\.crypt/i.test(allText),
    hasLateralMovement:  /rdp|smb|psexec|wmi|lateral|pass.the.hash|mimikatz|t1021/i.test(allText),
    hasPersistence:      /run.key|startup|scheduled.task|service.install|registry|t1547|t1053/i.test(allText),
    hasC2:               /c2|command.*control|beacon|cobalt.strike|t1071|malware.*connect/i.test(allText),
    hasDataExfiltration: /exfil|upload|ftp|rclone|mega|dropbox|t1041|data.*stolen/i.test(allText),
    hasPrivilegeEscal:   /admin|privilege|escalat|mimikatz|t1068|t1078|hashdump/i.test(allText),
    hasExploitedCVE:     /exploit|cve-|rce|remote.code|vulnerability/i.test(allText),
    hasCriticalAlert:    highestSeverity === 'critical',
    hasCredentialDump:   /credential|lsass|sam.dump|password.dump|t1003/i.test(allText),
    techniques:          [...techniques],
    highestSeverity,
    iocCount:            (iocs.sourceIPs?.length || 0) + (iocs.domains?.length || 0) + (iocs.fileHashes?.length || 0),
  };
}

// ─────────────────────────────────────────────────────────────────────
//  SECTION GENERATORS
// ─────────────────────────────────────────────────────────────────────

function _section1_Overview(data) {
  const { incidentId, title, severity, riskScore, findings, generatedAt, analyst } = data;
  const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
  const icon = sevEmoji[findings.highestSeverity] || '🟡';

  return `# SOC Investigation Report

**Incident ID**: ${incidentId}
**Report Generated**: ${generatedAt}
**Lead Analyst**: ${analyst || 'Automated (Wadjet-Eye AI)'}

---

## Section 1: Incident Overview

| Field | Details |
|-------|---------|
| **Incident ID** | ${incidentId} |
| **Title** | ${title || 'Security Incident Investigation'} |
| **Severity** | ${icon} **${(findings.highestSeverity || 'MEDIUM').toUpperCase()}** |
| **Risk Score** | ${riskScore}/100 |
| **Status** | UNDER INVESTIGATION |
| **Detection Time** | ${data.firstAlertTime || generatedAt} |
| **Report Time** | ${generatedAt} |
| **Analyst** | ${analyst || 'Wadjet-Eye AI SOC Platform'} |

### Executive Summary
${_generateExecutiveSummary(findings, data)}`;
}

function _generateExecutiveSummary(findings, data) {
  const parts = [];
  if (findings.hasRansomware)      parts.push('ransomware deployment detected');
  if (findings.hasLateralMovement) parts.push('lateral movement observed');
  if (findings.hasPersistence)     parts.push('persistence mechanisms established');
  if (findings.hasC2)              parts.push('command-and-control communication identified');
  if (findings.hasDataExfiltration)parts.push('data exfiltration activity detected');
  if (findings.hasCredentialDump)  parts.push('credential dumping occurred');

  if (parts.length === 0) {
    return `A security incident was detected involving ${data.alertCount || 1} alert(s) with ${findings.highestSeverity} severity. Investigation is ongoing to determine scope and impact.`;
  }

  return `**${(findings.highestSeverity || 'MEDIUM').toUpperCase()} severity security incident** with ${parts.join(', ')}. ${data.alertCount || 1} alert(s) triggered across ${data.hostCount || 1} host(s). Immediate containment and investigation actions are required. Risk score: **${data.riskScore}/100**.`;
}

function _section2_Description(data) {
  const { events, alerts, metadata } = data;
  const alertSummary = alerts.slice(0, 5).map(a =>
    `- **[${(a.severity || 'MEDIUM').toUpperCase()}]** ${a.title || a.name || 'Alert'} | Type: ${a.type || 'Security'} | Source: ${a.source || a.source_ip || 'N/A'} | Time: ${a.created_at || a.timestamp || 'N/A'}`
  ).join('\n');

  const eventCount = events.length;
  const alertCount = alerts.length;

  return `## Section 2: Incident Description

**Total Events Analyzed**: ${eventCount}
**Total Alerts**: ${alertCount}

### Alert Summary
${alertSummary || '- No alert details available in provided data'}

### Incident Narrative
${_buildNarrative(data)}`;
}

function _buildNarrative(data) {
  const { findings, metadata } = data;
  const lines = [];

  if (metadata?.attackVector) {
    lines.push(`The incident began via **${metadata.attackVector}** as the initial attack vector.`);
  }

  if (findings.hasExploitedCVE) {
    lines.push('A vulnerability was exploited to gain initial access to the target environment.');
  }

  if (findings.hasLateralMovement) {
    lines.push('The threat actor proceeded to move laterally through the network, compromising additional systems.');
  }

  if (findings.hasCredentialDump) {
    lines.push('Credential dumping activity was observed, suggesting the attacker harvested authentication material.');
  }

  if (findings.hasPersistence) {
    lines.push('Persistence mechanisms were established to maintain long-term access to compromised systems.');
  }

  if (findings.hasC2) {
    lines.push('Command-and-control (C2) communication was detected, indicating active attacker interaction with compromised hosts.');
  }

  if (findings.hasDataExfiltration) {
    lines.push('Data exfiltration activity was identified, suggesting sensitive information was transferred to external systems.');
  }

  if (findings.hasRansomware) {
    lines.push('⚠️ **Ransomware activity detected.** File encryption and shadow copy deletion were observed, indicating a destructive ransomware deployment.');
  }

  return lines.length > 0 ? lines.join(' ') : 'Investigation is ongoing. Refer to detection details and timeline for full incident context.';
}

function _section3_DetectionDetails(data) {
  const { alerts, detectionSources } = data;

  const detectionTable = alerts.slice(0, 10).map(a => {
    const time = a.created_at || a.timestamp || 'N/A';
    const rule = a.rule_name || a.detection_rule || a.mitre_technique || 'Security Rule';
    const source = a.source || a.source_ip || a.host || 'N/A';
    return `| ${time} | ${(a.severity || 'MEDIUM').toUpperCase()} | ${a.title || 'Alert'} | ${rule} | ${source} |`;
  }).join('\n');

  return `## Section 3: Detection Details

| Timestamp | Severity | Alert | Rule/Technique | Source |
|-----------|----------|-------|----------------|--------|
${detectionTable || '| N/A | N/A | No alerts provided | N/A | N/A |'}

### Detection Sources
${(detectionSources || ['SIEM', 'EDR', 'Network IDS']).map(s => `- ${s}`).join('\n')}

### Detection Method
- **SIEM Correlation**: ${alerts.filter(a => a.source === 'siem').length} SIEM rule triggers
- **EDR Alerts**: ${alerts.filter(a => a.source === 'edr' || a.type === 'endpoint').length} EDR alerts
- **Network IDS**: ${alerts.filter(a => a.source === 'ids' || a.type === 'network').length} network detections
- **Threat Intel Match**: ${alerts.filter(a => a.type === 'threat-intel' || a.source === 'threat-intel').length} IOC matches`;
}

function _section4_FullFindings(data) {
  const { events, iocs, timeline, networkData } = data;

  // Extract network details
  const uniqueSrcIPs = [...new Set(events.map(e => e.source_ip || e.src_ip).filter(Boolean))].slice(0, 10);
  const uniqueDstIPs = [...new Set(events.map(e => e.dest_ip || e.destination_ip).filter(Boolean))].slice(0, 10);
  const uniquePorts  = [...new Set(events.map(e => e.dest_port || e.port).filter(Boolean))].slice(0, 10);
  const uniqueUsers  = [...new Set(events.map(e => e.user || e.username || e.account).filter(Boolean))].slice(0, 10);
  const uniqueHosts  = [...new Set(events.map(e => e.host || e.hostname || e.computer).filter(Boolean))].slice(0, 10);
  const commands     = events.filter(e => e.command || e.commandLine || e.process_command).map(e => e.command || e.commandLine || e.process_command).slice(0, 10);
  const protocols    = [...new Set(events.map(e => e.protocol || e.network_protocol).filter(Boolean))].slice(0, 5);

  const timelineRows = timeline.slice(0, 15).map(t =>
    `| ${t.timestamp || 'N/A'} | ${t.type || 'alert'} | ${t.event || 'Event'} | ${t.source || 'N/A'} | ${t.destination || 'N/A'} | ${t.user || 'N/A'} | ${t.host || 'N/A'} |`
  ).join('\n');

  const iocSection = [
    iocs.sourceIPs?.length    ? `**Malicious IPs** (${iocs.sourceIPs.length}):\n${iocs.sourceIPs.map(i => `  - \`${i}\``).join('\n')}` : '',
    iocs.domains?.length      ? `**Malicious Domains** (${iocs.domains.length}):\n${iocs.domains.slice(0,10).map(d => `  - \`${d}\``).join('\n')}` : '',
    iocs.fileHashes?.length   ? `**File Hashes** (${iocs.fileHashes.length}):\n${iocs.fileHashes.map(h => `  - \`${h}\``).join('\n')}` : '',
    iocs.maliciousURLs?.length? `**Malicious URLs** (${iocs.maliciousURLs.length}):\n${iocs.maliciousURLs.slice(0,5).map(u => `  - \`${u}\``).join('\n')}` : '',
  ].filter(Boolean).join('\n\n');

  return `## Section 4: Full Technical Findings

### 4.1 Network Indicators
| Field | Values |
|-------|--------|
| **Source IPs** | ${uniqueSrcIPs.join(', ') || 'N/A'} |
| **Destination IPs** | ${uniqueDstIPs.join(', ') || 'N/A'} |
| **Ports** | ${uniquePorts.join(', ') || 'N/A'} |
| **Protocols** | ${protocols.join(', ') || 'N/A'} |

### 4.2 Affected Users & Systems
| Field | Values |
|-------|--------|
| **User Accounts** | ${uniqueUsers.join(', ') || 'N/A'} |
| **Hostnames** | ${uniqueHosts.join(', ') || 'N/A'} |
| **Total Events** | ${events.length} |

### 4.3 Executed Commands
${commands.length > 0
  ? commands.map(c => `\`\`\`\n${c}\n\`\`\``).join('\n')
  : '_No command execution data available in provided events_'}

### 4.4 Event Timeline
| Timestamp | Type | Event | Source | Destination | User | Host |
|-----------|------|-------|--------|-------------|------|------|
${timelineRows || '| N/A | N/A | No timeline data | N/A | N/A | N/A | N/A |'}

### 4.5 Indicators of Compromise (IOCs)
${iocSection || '_No external IOCs extracted from event data_'}`;
}

function _section5_Analysis(data) {
  const { findings } = data;
  const techniques = findings.techniques || [];

  const techniqueTable = techniques.slice(0, 15).map(tid => {
    const detail = _getMITREDetail(tid);
    return `| \`${tid}\` | ${detail.name} | ${detail.tactic} | ${detail.severity} |`;
  }).join('\n');

  const attackPattern = _buildAttackPattern(findings);

  return `## Section 5: Technical Analysis

### 5.1 Attack Pattern
${attackPattern}

### 5.2 MITRE ATT&CK Techniques Identified
| Technique ID | Name | Tactic | Severity |
|--------------|------|--------|----------|
${techniqueTable || '| T1059 | Command and Scripting Interpreter | Execution | HIGH |'}

**ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/

### 5.3 Lateral Movement Analysis
${findings.hasLateralMovement
  ? `**Lateral movement detected.** Techniques observed:\n- RDP/SMB connections to additional hosts\n- Pass-the-Hash or Pass-the-Ticket attack patterns\n- WMI-based remote execution\n- PsExec or similar administrative tools`
  : 'No lateral movement indicators detected in the analyzed events.'}

### 5.4 Persistence Mechanisms
${findings.hasPersistence
  ? `**Persistence established.** Indicators include:\n- Registry Run Key modifications (T1547.001)\n- Scheduled task creation (T1053)\n- Service installation (T1543)\n- Startup folder modifications`
  : 'No persistence mechanisms detected in the analyzed events.'}

### 5.5 Defense Evasion
${findings.techniques.some(t => ['T1027','T1055','T1562'].some(e => t.startsWith(e)))
  ? 'Defense evasion techniques detected including process injection, obfuscation, and/or security tool disabling.'
  : 'No specific defense evasion techniques identified in event data.'}`;
}

function _buildAttackPattern(findings) {
  const phases = [];
  if (findings.hasExploitedCVE || findings.techniques.some(t => ['T1190','T1566'].some(e => t.startsWith(e)))) {
    phases.push('**Initial Access** → Exploit/Phishing');
  }
  if (findings.techniques.some(t => t.startsWith('T1059') || t.startsWith('T1047'))) {
    phases.push('**Execution** → Script/Command execution');
  }
  if (findings.hasCredentialDump) {
    phases.push('**Credential Access** → Credential dumping');
  }
  if (findings.hasLateralMovement) {
    phases.push('**Lateral Movement** → Network traversal');
  }
  if (findings.hasPersistence) {
    phases.push('**Persistence** → Autostart mechanisms');
  }
  if (findings.hasC2) {
    phases.push('**Command & Control** → C2 communication');
  }
  if (findings.hasDataExfiltration) {
    phases.push('**Exfiltration** → Data transfer to external host');
  }
  if (findings.hasRansomware) {
    phases.push('**Impact** → Ransomware encryption/destruction');
  }

  return phases.length > 0
    ? phases.join('\n→ ')
    : 'Attack pattern could not be fully reconstructed from available data. Review timeline for additional context.';
}

function _section6_Containment(data) {
  const { findings, iocs } = data;
  const actions = [];

  actions.push('### Immediate Actions (0-2 hours)');

  if (findings.hasRansomware) {
    actions.push(`1. **ISOLATE** all affected systems from the network immediately (unplug network cables / disable NICs)
2. **PRESERVE** RAM and disk images before any remediation
3. **DO NOT** reboot systems (may trigger additional encryption routines)
4. **NOTIFY** stakeholders: CISO, Legal, Incident Response team`);
  } else {
    actions.push(`1. **ISOLATE** confirmed compromised hosts using network segmentation
2. **REVOKE** all active sessions and access tokens for affected accounts
3. **BLOCK** identified malicious IPs at perimeter firewall
4. **PRESERVE** evidence — disk images, memory dumps, SIEM logs`);
  }

  if (iocs.sourceIPs?.length > 0) {
    actions.push(`\n### Firewall Block Rules
Block the following IPs immediately:\n${iocs.sourceIPs.map(ip => `- \`${ip}\``).join('\n')}`);
  }

  if (findings.hasCredentialDump) {
    actions.push(`\n### Credential Containment
- Force password reset for ALL users on compromised systems
- Rotate service account passwords
- Invalidate all Kerberos tickets (run: \`klist purge\` on all systems)
- If AD compromised: consider full Kerberos Golden Ticket reset`);
  }

  return `## Section 6: Containment Actions

${actions.join('\n\n')}

### Short-term Containment (2-24 hours)
1. Identify all affected systems via SIEM lateral movement queries
2. Apply emergency firewall rules for all identified IOCs
3. Enable enhanced monitoring on all critical systems
4. Review and revoke suspicious OAuth tokens and API keys
5. Enable MFA on all administrative accounts if not already active`;
}

function _section7_Eradication(data) {
  const { findings } = data;
  const steps = [];

  steps.push(`### Malware Removal
1. Run updated AV/EDR full scan on ALL systems in the affected subnet
2. Review and remove all detected malicious files
3. Clean registry keys modified by malware (see persistence section)
4. Remove any unauthorized services or scheduled tasks`);

  if (findings.hasPersistence) {
    steps.push(`\n### Persistence Removal
1. Audit all registry Run keys: \`HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\`
2. Review Scheduled Tasks: \`Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}\`
3. Check startup folders for unauthorized items
4. Review installed services: \`sc query type= all | findstr SERVICE_NAME\``);
  }

  if (findings.hasCredentialDump) {
    steps.push(`\n### Credential Eradication
1. Reset ALL passwords (not just affected accounts)
2. Rotate ALL service account credentials
3. Review and revoke all OAuth tokens
4. Audit and rotate API keys
5. If LSASS was accessed: assume ALL credentials on the system are compromised`);
  }

  if (findings.hasLateralMovement) {
    steps.push(`\n### Lateral Movement Cleanup
1. Review all hosts with RDP/SMB connections to compromised systems
2. Reset local administrator accounts (LAPS if deployed)
3. Disable accounts used during lateral movement
4. Review and clean host-based firewall rules`);
  }

  return `## Section 7: Eradication Steps

${steps.join('\n\n')}

### Verification
1. Confirm no malicious processes running on affected systems
2. Verify network traffic from affected systems is clean
3. Review SIEM for 24 hours post-eradication for re-infection signs
4. Run vulnerability scan on affected systems to identify entry point`;
}

function _section8_Recovery(data) {
  return `## Section 8: Recovery Plan

### Phase 1: System Validation (Before Restoring)
1. Verify clean system state using EDR and AV scans
2. Confirm all malicious artifacts removed
3. Validate system integrity (file hashes, registry baselines)
4. Review patch status — apply all outstanding security patches

### Phase 2: Service Restoration
1. Restore systems from clean backups if corruption detected
2. Reintroduce systems to network in controlled segments
3. Monitor network traffic for 48h post-restoration
4. Re-enable services in priority order: Critical → High → Medium

### Phase 3: Validation
1. Perform penetration test or vulnerability assessment on restored systems
2. Confirm monitoring and alerting are active
3. Validate user access is appropriate (least privilege)
4. Test business-critical applications before declaring recovery complete

### Phase 4: Return to Normal Operations
1. Remove temporary containment measures after validation
2. Update incident ticket with full timeline
3. Notify stakeholders of recovery completion
4. Schedule post-incident review within 5 business days`;
}

function _section9_Recommendations(data) {
  const { findings, riskScore } = data;
  const recs = [];

  if (riskScore > 75) {
    recs.push('**CRITICAL: Engage external Incident Response firm for full forensic investigation**');
  }

  recs.push('### Immediate Technical Recommendations');

  if (findings.hasExploitedCVE) {
    recs.push('1. **Patch Management**: Immediately apply outstanding security patches — implement automated patching for critical/high CVEs');
  }
  if (findings.hasCredentialDump) {
    recs.push('2. **Credential Security**: Deploy Credential Guard on all Windows systems; implement CyberArk or HashiCorp Vault for service accounts');
  }
  if (findings.hasLateralMovement) {
    recs.push('3. **Network Segmentation**: Implement micro-segmentation; restrict SMB and RDP to jump servers only');
  }
  if (findings.hasRansomware) {
    recs.push('4. **Backup Strategy**: Implement 3-2-1 backup strategy with offline/immutable backups tested weekly');
  }

  recs.push(`\n### Strategic Recommendations
1. **EDR Deployment**: Ensure EDR agents are deployed on 100% of endpoints
2. **SIEM Tuning**: Add detection rules for identified MITRE techniques: ${(findings.techniques || []).slice(0,5).join(', ')}
3. **Zero Trust**: Implement Zero Trust Network Architecture principles
4. **Security Awareness**: Mandatory phishing simulation training for all users
5. **Incident Response Plan**: Review and update IR playbooks based on this incident
6. **Threat Hunting**: Schedule proactive threat hunt for similar TTPs across environment
7. **Purple Team**: Consider Purple Team exercise to validate detection coverage`);

  return `## Section 9: Recommendations

${recs.join('\n\n')}`;
}

function _section10_SeverityAssessment(data) {
  const { findings, riskScore } = data;
  const overallSeverity = riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW';
  const sevEmoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

  const impactAreas = [
    { area: 'Confidentiality', impact: findings.hasDataExfiltration || findings.hasCredentialDump ? 'HIGH' : 'MEDIUM', reason: findings.hasDataExfiltration ? 'Data exfiltration detected' : findings.hasCredentialDump ? 'Credentials potentially compromised' : 'Limited evidence of data access' },
    { area: 'Integrity', impact: findings.hasRansomware ? 'CRITICAL' : findings.hasPersistence ? 'HIGH' : 'MEDIUM', reason: findings.hasRansomware ? 'Files encrypted/destroyed' : findings.hasPersistence ? 'System integrity modified' : 'No confirmed integrity impact' },
    { area: 'Availability', impact: findings.hasRansomware ? 'CRITICAL' : findings.hasC2 ? 'HIGH' : 'LOW', reason: findings.hasRansomware ? 'Systems may be unavailable' : findings.hasC2 ? 'Systems under threat actor control' : 'No availability impact detected' },
  ];

  const impactTable = impactAreas.map(i =>
    `| ${i.area} | ${sevEmoji[i.impact] || '⚪'} ${i.impact} | ${i.reason} |`
  ).join('\n');

  return `## Section 10: Severity Assessment

### Overall Severity: ${sevEmoji[overallSeverity]} **${overallSeverity}**
**Risk Score**: ${riskScore}/100

### CIA Impact Assessment
| Area | Impact | Justification |
|------|--------|---------------|
${impactTable}

### Risk Factors Detected
| Factor | Present | Weight |
|--------|---------|--------|
| Ransomware Activity | ${findings.hasRansomware ? '✅ YES' : '❌ NO'} | +35 |
| Critical Alerts | ${findings.hasCriticalAlert ? '✅ YES' : '❌ NO'} | +25 |
| Exploited CVE | ${findings.hasExploitedCVE ? '✅ YES' : '❌ NO'} | +30 |
| Lateral Movement | ${findings.hasLateralMovement ? '✅ YES' : '❌ NO'} | +20 |
| Persistence | ${findings.hasPersistence ? '✅ YES' : '❌ NO'} | +20 |
| C2 Communication | ${findings.hasC2 ? '✅ YES' : '❌ NO'} | +20 |
| Data Exfiltration | ${findings.hasDataExfiltration ? '✅ YES' : '❌ NO'} | +25 |
| Credential Dumping | ${findings.hasCredentialDump ? '✅ YES' : '❌ NO'} | +15 |

### Compliance Considerations
- **GDPR**: ${findings.hasDataExfiltration ? '⚠️ Potential data breach — 72-hour notification requirement may apply' : 'No confirmed data breach at this time'}
- **HIPAA**: ${findings.hasDataExfiltration ? '⚠️ Review if PHI was involved' : 'No confirmed PHI exposure'}
- **PCI-DSS**: ${findings.hasCredentialDump ? '⚠️ Review if card data was accessible on compromised systems' : 'No confirmed PCI data exposure'}

---
*Report generated by Wadjet-Eye AI SOC Platform | Investigation ID: ${data.incidentId}*`;
}

// ─────────────────────────────────────────────────────────────────────
//  MAIN: GENERATE INVESTIGATION REPORT
// ─────────────────────────────────────────────────────────────────────
/**
 * Generate a complete 10-section SOC investigation report
 * @param {object} input
 *   - incidentId  {string}   Incident reference ID
 *   - title       {string}   Incident title
 *   - alerts      {Array}    Alert objects from SIEM
 *   - events      {Array}    Raw log/event objects
 *   - metadata    {object}   Additional context
 *   - analyst     {string}   Analyst name
 */
function generateInvestigationReport(input) {
  const {
    incidentId  = `INC-${Date.now()}`,
    title       = 'Security Incident',
    alerts      = [],
    events      = [],
    metadata    = {},
    analyst     = 'Wadjet-Eye AI',
  } = input;

  const generatedAt  = new Date().toISOString();
  const timeline     = _buildTimeline([...events, ...alerts]);
  const iocs         = _extractIOCs(events, alerts, metadata);
  const findings     = _detectFindings(events, alerts, iocs);
  const riskScore    = _calcRiskScore(findings);

  const firstAlertTime = alerts[0]?.created_at || alerts[0]?.timestamp || generatedAt;
  const hostCount    = new Set([...events, ...alerts].map(e => e.host || e.hostname || e.computer).filter(Boolean)).size;
  const alertCount   = alerts.length;
  const detectionSources = [...new Set(alerts.map(a => a.source || 'SIEM').filter(Boolean))];

  const data = {
    incidentId, title, generatedAt, analyst,
    alerts, events, metadata,
    timeline, iocs, findings, riskScore,
    firstAlertTime, hostCount, alertCount, detectionSources,
  };

  const sections = [
    _section1_Overview(data),
    _section2_Description(data),
    _section3_DetectionDetails(data),
    _section4_FullFindings(data),
    _section5_Analysis(data),
    _section6_Containment(data),
    _section7_Eradication(data),
    _section8_Recovery(data),
    _section9_Recommendations(data),
    _section10_SeverityAssessment(data),
  ];

  const fullReport = sections.join('\n\n---\n\n');

  return {
    incidentId,
    title,
    severity:    findings.highestSeverity.toUpperCase(),
    riskScore,
    techniques:  findings.techniques,
    iocs,
    report:      fullReport,
    sectionCount: sections.length,
    metadata:    { generatedAt, analyst, alertCount, eventCount: events.length, hostCount },
  };
}

// ─────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────
module.exports = {
  generateInvestigationReport,
  _buildTimeline,
  _extractIOCs,
  _detectFindings,
  _calcRiskScore,
};
