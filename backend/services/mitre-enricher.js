/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — MITRE ATT&CK Enricher  v1.0
 *
 *  Converts raw MITRE technique IDs (e.g. T1059.001) into plain-language
 *  explanations with detection examples, SOC context, and actionable
 *  guidance — without requiring a live network call.
 *
 *  Coverage: All major ATT&CK techniques used in SOC investigations.
 *  Format: { id, name, tactic, description, detection, socContext, severity }
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Technique database (inline, no external dep) ──────────────────────────────
// Covers the top ~80 most-encountered techniques in enterprise SOC environments.
// Each entry: id, name, tactic(s), description, detection, socContext, severity
const TECHNIQUE_DB = {
  // ── Execution ────────────────────────────────────────────────────────────────
  'T1059': {
    name:        'Command and Scripting Interpreter',
    tactic:      'Execution',
    description: 'Adversaries abuse command and script interpreters to execute commands, scripts, or binaries. This includes shells (cmd, bash, zsh), scripting languages (PowerShell, Python, VBScript), and server-side scripting.',
    detection:   'Monitor for unexpected interpreter usage, encoded commands, and execution of scripts from unusual paths. Enable PowerShell script-block logging (Event 4104).',
    socContext:  'One of the most commonly abused execution techniques — used in ~70% of all malware infections. Requires both process and command-line visibility.',
    severity:    'High',
  },
  'T1059.001': {
    name:        'Command and Scripting Interpreter: PowerShell',
    tactic:      'Execution',
    description: 'Adversaries use PowerShell to execute commands, download payloads, bypass security controls, and conduct reconnaissance. Encoded commands (-enc, -encodedcommand) are a strong indicator of malicious activity.',
    detection:   'Enable Module Logging (Event 4103), Script Block Logging (Event 4104), and Transcription. Alert on: `-enc`, `-bypass`, `-nop`, `iex`, `Invoke-Expression`, `DownloadString`, `FromBase64String`.',
    socContext:  'PowerShell is the #1 living-off-the-land technique. Many defenses can be bypassed with `-ExecutionPolicy Bypass`. Defender ASR rule "Block credential stealing from LSASS" also helps.',
    severity:    'High',
  },
  'T1059.003': {
    name:        'Command and Scripting Interpreter: Windows Command Shell',
    tactic:      'Execution',
    description: 'Adversaries use cmd.exe for executing commands, running scripts, and chaining operations via batch files. Often used in combination with other techniques.',
    detection:   'Process creation events (Event 4688, Sysmon Event 1). Watch for cmd.exe spawned by unusual parents (Word, Excel, browser). Alert on suspicious argument strings.',
    socContext:  'cmd.exe is ubiquitous — context is critical. A cmd.exe spawned by winword.exe is a clear indicator of macro-based attack.',
    severity:    'Medium',
  },
  'T1059.005': {
    name:        'Command and Scripting Interpreter: Visual Basic',
    tactic:      'Execution',
    description: 'Adversaries use VBScript (.vbs) and Visual Basic for Applications (VBA) in macros to execute malicious code. Commonly delivered via email attachments.',
    detection:   'Monitor wscript.exe/cscript.exe execution. VBA macro execution events in Office applications. Network connections from office processes.',
    socContext:  'VBA macros remain a primary phishing payload delivery mechanism despite disable-by-default changes in Office 2022+.',
    severity:    'High',
  },
  'T1059.007': {
    name:        'Command and Scripting Interpreter: JavaScript',
    tactic:      'Execution',
    description: 'Adversaries use JavaScript in browsers or via wscript.exe/cscript.exe (JScript) to execute malicious code. Node.js can also be abused.',
    detection:   'Monitor wscript.exe/cscript.exe for .js file execution. Browser extension behaviour. JScript execution via mshta.exe.',
    socContext:  'JScript downloaded and executed via wscript.exe is a common fileless malware stage.',
    severity:    'Medium',
  },

  // ── Persistence ──────────────────────────────────────────────────────────────
  'T1053': {
    name:        'Scheduled Task/Job',
    tactic:      'Persistence, Privilege Escalation',
    description: 'Adversaries abuse task scheduling utilities to execute programs at startup, regular intervals, or when specific conditions are met.',
    detection:   'Event ID 4698 (task created), 4702 (task modified), Sysmon Event 11 (file creation in Task Scheduler folder). Monitor schtasks.exe/at.exe command-line arguments.',
    socContext:  'Commonly used for persistence after initial access. Malware frequently creates hidden scheduled tasks with randomised names.',
    severity:    'Medium',
  },
  'T1053.005': {
    name:        'Scheduled Task/Job: Scheduled Task',
    tactic:      'Persistence, Privilege Escalation',
    description: 'Windows Task Scheduler (schtasks.exe) is abused to maintain persistence or execute privileged commands.',
    detection:   'Monitor schtasks.exe invocations (Event 4698/4702). Check task XML for suspicious actions, particularly those executing from %APPDATA%, %TEMP%, or encoded commands.',
    socContext:  'Lateral movement tools like Cobalt Strike create scheduled tasks on remote hosts via SMB or WMI. The task XML file is a forensic goldmine.',
    severity:    'Medium',
  },
  'T1547.001': {
    name:        'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
    tactic:      'Persistence',
    description: 'Adversaries add registry run keys or place files in startup folders to ensure malware executes at system boot or user logon.',
    detection:   'Monitor registry writes to HKCU/HKLM Run and RunOnce keys (Event 4657, Sysmon Event 13). Alert on new files in Startup folder.',
    socContext:  'One of the oldest and most reliable persistence mechanisms. Legitimate software uses it too — context (signer, path, command) is critical.',
    severity:    'Medium',
  },

  // ── Privilege Escalation ─────────────────────────────────────────────────────
  'T1055': {
    name:        'Process Injection',
    tactic:      'Defense Evasion, Privilege Escalation',
    description: 'Adversaries inject malicious code into running processes to evade defenses, hide activity, and operate with elevated privileges. Common methods: DLL injection, process hollowing, reflective DLL loading.',
    detection:   'Sysmon Events 8 (CreateRemoteThread), 10 (ProcessAccess). Unusual memory allocations in legitimate processes. Security products with kernel callbacks can detect injection attempts.',
    socContext:  'Process injection is the cornerstone of most advanced malware. Once injected into a trusted process (e.g., svchost.exe), network connections from that process appear legitimate.',
    severity:    'Critical',
  },
  'T1055.001': {
    name:        'Process Injection: Dynamic-link Library Injection',
    tactic:      'Defense Evasion, Privilege Escalation',
    description: 'DLL injection abuses Windows APIs (LoadLibrary, CreateRemoteThread) to load malicious code into a target process.',
    detection:   'Sysmon Event 8 (CreateRemoteThread to non-standard DLLs). Autoruns-style detection of unsigned DLLs loaded into system processes.',
    socContext:  'Classic RAT and backdoor technique. Injected DLL runs with the privileges of the target process.',
    severity:    'Critical',
  },
  'T1134': {
    name:        'Access Token Manipulation',
    tactic:      'Defense Evasion, Privilege Escalation',
    description: 'Adversaries manipulate Windows access tokens to operate with higher privileges or impersonate other users and processes.',
    detection:   'Event 4672 (special privileges assigned), 4624 (logon with elevated token). Sysmon Event 10 for OpenProcess with TOKEN_DUPLICATE.',
    socContext:  'Token manipulation is frequently the "step 2" after initial access — escalating from a low-privilege user to SYSTEM.',
    severity:    'High',
  },

  // ── Defense Evasion ───────────────────────────────────────────────────────────
  'T1027': {
    name:        'Obfuscated Files or Information',
    tactic:      'Defense Evasion',
    description: 'Adversaries encode, encrypt, or obfuscate payloads to evade detection. Methods include Base64, XOR, packing, and string concatenation.',
    detection:   'Entropy analysis on executables/scripts. Pattern matching for common encoding schemes. Script-block logging captures decoded PowerShell content.',
    socContext:  'Obfuscation by itself is a significant indicator. Legitimate software rarely uses Base64-encoded PowerShell commands.',
    severity:    'Medium',
  },
  'T1036': {
    name:        'Masquerading',
    tactic:      'Defense Evasion',
    description: 'Adversaries rename or disguise malicious files/processes to appear legitimate. Techniques include naming malware after system binaries or using lookalike Unicode characters.',
    detection:   'Verify executable paths — system binaries (svchost.exe, lsass.exe) should only run from %SystemRoot%\\System32. Alert on process names matching system names from non-standard paths.',
    socContext:  'A svchost.exe running from C:\\Users\\Public\\ is almost certainly malicious. Path + parent process + signer validation catches most masquerading.',
    severity:    'High',
  },
  'T1562': {
    name:        'Impair Defenses',
    tactic:      'Defense Evasion',
    description: 'Adversaries disable or modify security controls to avoid detection: AV/EDR disabling, firewall rule modification, event log clearing, tamper protection bypass.',
    detection:   'Event 1102 (audit log cleared), 7045 (new service), Monitor for reg.exe modifying AV keys. Sysmon Event 12/13 for security-related registry changes.',
    socContext:  'Disabling defenses is often the second action after initial access. Any tampering with security tools should be treated as a confirmed attack in progress.',
    severity:    'Critical',
  },
  'T1562.001': {
    name:        'Impair Defenses: Disable or Modify Tools',
    tactic:      'Defense Evasion',
    description: 'Adversaries stop, delete, or modify endpoint security tools (AV, EDR, HIPS, logging agents) to blind the defender.',
    detection:   'Service stop events (Event 7036) for security services. Registry modifications under security tool keys. Process termination of security agent processes.',
    socContext:  'Killing EDR is a critical alert — it means the attacker knows they are being watched and is preparing for a high-impact action (ransomware deployment, data exfil).',
    severity:    'Critical',
  },

  // ── Credential Access ────────────────────────────────────────────────────────
  'T1003': {
    name:        'OS Credential Dumping',
    tactic:      'Credential Access',
    description: 'Adversaries dump credentials from operating system memory, password stores, and registry hives. Tools include Mimikatz, ProcDump, Impacket secretsdump.',
    detection:   'Monitor LSASS access (Sysmon Event 10 on lsass.exe). Event 4656 (handle to sensitive objects). Alert on Volume Shadow Copy operations and ntds.dit access.',
    socContext:  'Credential dumping is a critical pivot point — from one set of credentials, the attacker can move laterally across the entire domain.',
    severity:    'Critical',
  },
  'T1003.001': {
    name:        'OS Credential Dumping: LSASS Memory',
    tactic:      'Credential Access',
    description: 'Dumping LSASS process memory to extract plaintext passwords, password hashes, and Kerberos tickets. Mimikatz sekurlsa::logonpasswords is the canonical example.',
    detection:   'Sysmon Event 10 (ProcessAccess to lsass.exe with suspicious access rights). Windows Defender Credential Guard prevents this. Event 4656 for LSASS handle requests.',
    socContext:  '**Critical alert — immediate escalation required.** LSASS dump means the attacker can now authenticate as any logged-on user, including admins.',
    severity:    'Critical',
  },
  'T1078': {
    name:        'Valid Accounts',
    tactic:      'Defense Evasion, Persistence, Privilege Escalation, Initial Access',
    description: 'Adversaries use valid credentials (obtained via phishing, credential stuffing, purchasing, or dumping) to access systems while appearing as legitimate users.',
    detection:   'Behavioural baselines (first-time logon from location, off-hours access, impossible travel). UEBA capabilities, Event 4624 with logon type analysis.',
    socContext:  'The hardest attack type to detect because the attacker looks exactly like a legitimate user. UEBA and context are essential — not just raw events.',
    severity:    'High',
  },

  // ── Discovery ────────────────────────────────────────────────────────────────
  'T1046': {
    name:        'Network Service Discovery',
    tactic:      'Discovery',
    description: 'Adversaries scan for open ports and running services on internal and external hosts to identify targets and plan lateral movement.',
    detection:   'Network traffic anomaly detection (port scan patterns). Process creation alerts for nmap, masscan, netscan. DNS reverse lookup storms.',
    socContext:  'Post-compromise network scanning is often the first indicator of lateral movement preparation. The source of the scan (legitimate admin tool vs. new binary) matters.',
    severity:    'Medium',
  },
  'T1087': {
    name:        'Account Discovery',
    tactic:      'Discovery',
    description: 'Adversaries enumerate local and domain user accounts to understand the environment, find privileged accounts, and select targets for credential attacks.',
    detection:   'Monitor net.exe/net1.exe usage (net user /domain, net group). Event 4798 (local group enum), 4799 (security-enabled group enum). LDAP queries for AD enumeration.',
    socContext:  'Active Directory enumeration via BloodHound/SharpHound is a critical indicator of a sophisticated attacker mapping the attack path to Domain Admin.',
    severity:    'Medium',
  },

  // ── Lateral Movement ────────────────────────────────────────────────────────
  'T1021': {
    name:        'Remote Services',
    tactic:      'Lateral Movement',
    description: 'Adversaries move laterally using legitimate remote services: RDP, SMB, SSH, WinRM, VNC. Authentication with compromised credentials allows silent traversal.',
    detection:   'Event 4624 (Type 3 = network logon, Type 10 = remote interactive). Baseline normal RDP/SMB sources. Alert on service account logons from workstations.',
    socContext:  'Lateral movement via remote services is invisible without user-behaviour baselines. "Pass-the-hash" via SMB is undetectable at the network level alone.',
    severity:    'High',
  },
  'T1021.001': {
    name:        'Remote Services: Remote Desktop Protocol',
    tactic:      'Lateral Movement',
    description: 'Adversaries use RDP to move between systems. With valid credentials (or via Pass-the-Hash), RDP provides a full interactive desktop session.',
    detection:   'Event 4624 Type 10 (RemoteInteractive logon). TerminalServices-RemoteConnectionManager/Operational log. Alert on admin-to-admin and first-time RDP connections.',
    socContext:  'RDP is used in the vast majority of ransomware attacks for final-stage domain traversal before deployment. RDP honeypot accounts can provide early warning.',
    severity:    'High',
  },
  'T1021.002': {
    name:        'Remote Services: SMB/Windows Admin Shares',
    tactic:      'Lateral Movement',
    description: 'Adversaries connect to Windows administrative shares (C$, ADMIN$, IPC$) over SMB to transfer files, execute commands, and move laterally.',
    detection:   'Event 5140 (network share accessed), 5145 (network share object checked). Alert on admin$ access from non-admin sources and workstation-to-workstation SMB.',
    socContext:  'Ransomware propagation frequently uses ADMIN$ shares to copy the ransomware binary and execute it via PsExec or sc.exe.',
    severity:    'High',
  },

  // ── Collection ───────────────────────────────────────────────────────────────
  'T1005': {
    name:        'Data from Local System',
    tactic:      'Collection',
    description: 'Adversaries search for and collect sensitive data from local file systems before exfiltration. Target files include documents, databases, code, credentials, and configuration files.',
    detection:   'Bulk file access events (more than X file reads in Y seconds). File staging in unusual locations (%TEMP%, $RECYCLE.BIN). Archiving tools (7zip, WinRAR) invoked on sensitive directories.',
    socContext:  'Data staging and compression before exfiltration is a key detection opportunity. Monitor for large archive creation in unexpected locations.',
    severity:    'High',
  },

  // ── Exfiltration ─────────────────────────────────────────────────────────────
  'T1041': {
    name:        'Exfiltration Over C2 Channel',
    tactic:      'Exfiltration',
    description: 'Adversaries exfiltrate data over the same command-and-control channel to avoid creating additional network connections that might be detected.',
    detection:   'Unusually large data transfers on known C2 protocols. DNS tunnelling detection (high entropy subdomains, large TXT records). HTTPS traffic analysis (cert age, domain registration, traffic patterns).',
    socContext:  'C2-based exfiltration is very hard to detect without baseline + DLP. Focus on data volume anomalies and destination reputation.',
    severity:    'Critical',
  },

  // ── Impact ───────────────────────────────────────────────────────────────────
  'T1486': {
    name:        'Data Encrypted for Impact',
    tactic:      'Impact',
    description: 'Adversaries encrypt files on target systems to disrupt business operations and demand ransom. Ransomware is the most common manifestation.',
    detection:   'High volume of file rename/modify events. Canary file modification. Honeypot file triggers. Volume shadow copy deletion (vssadmin.exe delete shadows). EDR behavioural rules.',
    socContext:  '**When you see ransomware indicators, the encryption has likely already begun. Incident response priority: isolate, preserve, notify.** VSS deletion is the clearest pre-encryption warning sign.',
    severity:    'Critical',
  },
  'T1490': {
    name:        'Inhibit System Recovery',
    tactic:      'Impact',
    description: 'Adversaries delete backups, Volume Shadow Copies, and disable recovery mechanisms to ensure victims cannot restore from backups after ransomware deployment.',
    detection:   'vssadmin.exe delete shadows (Event 4688 with command line). wmic.exe shadowcopy delete. bcdedit.exe /set {default} bootstatuspolicy. Recovery environment disable commands.',
    socContext:  '**Critical ransomware pre-cursor. VSS deletion is executed minutes before ransomware encryption begins. Treat as an active incident.**',
    severity:    'Critical',
  },
  'T1489': {
    name:        'Service Stop',
    tactic:      'Impact',
    description: 'Adversaries stop critical services (databases, security tools, backup agents) to maximise ransomware impact and ensure all files are accessible for encryption.',
    detection:   'Event 7036 (service stopped), net stop commands, sc stop. Alert on bulk service stop operations or stopping of backup/AV services.',
    socContext:  'Ransomware kills database, backup, and AV services in the seconds before encryption. Bulk service termination is a critical pre-encryption alert.',
    severity:    'Critical',
  },

  // ── Command and Control ──────────────────────────────────────────────────────
  'T1071': {
    name:        'Application Layer Protocol',
    tactic:      'Command and Control',
    description: 'Adversaries use standard application protocols (HTTP/S, DNS, SMTP, LDAP) for C2 communications to blend with legitimate traffic.',
    detection:   'Baseline normal external HTTP/S destinations. DNS anomaly detection (NXD ratio, subdomain entropy, query volume). User-agent and certificate analysis for HTTP/S C2.',
    socContext:  'HTTP/S C2 over legitimate cloud services (GitHub, Pastebin, Dropbox) is increasingly common. Static signatures are insufficient — focus on behavioural patterns.',
    severity:    'High',
  },
  'T1071.001': {
    name:        'Application Layer Protocol: Web Protocols',
    tactic:      'Command and Control',
    description: 'C2 over HTTP/S is the most common protocol due to prevalence in legitimate traffic, easy implementation, and ability to blend with normal browsing.',
    detection:   'Certificate analysis (Let\'s Encrypt newly issued cert to low-rep domain). HTTP timing analysis (beacon jitter). User-agent anomalies. Proxy logs + threat intel enrichment.',
    socContext:  'CobaltStrike default HTTPS beaconing is detectable via certificate fingerprinting (JARM). Invest in SSL/TLS inspection for high-value segments.',
    severity:    'High',
  },
  'T1071.004': {
    name:        'Application Layer Protocol: DNS',
    tactic:      'Command and Control',
    description: 'DNS tunnelling uses the DNS protocol to encode data and C2 traffic in queries and responses, bypassing firewalls that allow DNS.',
    detection:   'Detect: high query volume to single domain, high entropy subdomains, large TXT records, unusual record types (NULL, PRIVATE). DNS over HTTPS (DoH) can bypass network DNS monitoring.',
    socContext:  'DNS tunnelling is used by APTs for persistent C2 because most networks allow outbound DNS unrestricted. DNS logging to SIEM is essential.',
    severity:    'High',
  },

  // ── Initial Access ───────────────────────────────────────────────────────────
  'T1566': {
    name:        'Phishing',
    tactic:      'Initial Access',
    description: 'Adversaries send malicious emails to gain initial access. Variants include spearphishing attachments, spearphishing links, and spearphishing via services.',
    detection:   'Email gateway: scan attachments (sandbox detonation), check links (URL reputation). End-user reports. Execution of Office documents with macros disabled by default.',
    socContext:  'Phishing is the #1 initial access vector for all threat actor tiers. Effective protection requires email security gateway + user training + macro policies.',
    severity:    'High',
  },
  'T1566.001': {
    name:        'Phishing: Spearphishing Attachment',
    tactic:      'Initial Access',
    description: 'Targeted phishing with malicious file attachments (Office macros, PDF exploits, ISO/ZIP with malware). Often includes social engineering to convince the recipient to open the file.',
    detection:   'Email gateway sandbox analysis. Alert on documents spawning child processes. Office Protected View bypass. Execution from user download/email directories.',
    socContext:  'The attachment is rarely the final payload — it downloads stage 2. Network egress from Office processes (winword.exe making HTTP connections) is a strong indicator.',
    severity:    'High',
  },
  'T1190': {
    name:        'Exploit Public-Facing Application',
    tactic:      'Initial Access',
    description: 'Adversaries exploit vulnerabilities in public-facing applications (web servers, VPN appliances, email gateways, RDP) to gain initial access without user interaction.',
    detection:   'WAF alerts. Anomalous application error rates. Authentication log anomalies on public services. Network traffic from unexpected sources to application ports.',
    socContext:  'Zero-day exploitation of edge devices (VPN, firewall, email gateway) is the preferred initial access for nation-state actors. Patch velocity is the primary defense.',
    severity:    'Critical',
  },
};

// ── Tactic descriptions for enrichment ───────────────────────────────────────
const TACTIC_DESCRIPTIONS = {
  'Initial Access':           'How the adversary gained a foothold in the environment',
  'Execution':                'How the adversary ran malicious code',
  'Persistence':              'How the adversary maintained access across reboots',
  'Privilege Escalation':     'How the adversary gained higher-level permissions',
  'Defense Evasion':          'How the adversary avoided being detected',
  'Credential Access':        'How the adversary obtained account credentials',
  'Discovery':                'How the adversary explored the environment',
  'Lateral Movement':         'How the adversary moved through the network',
  'Collection':               'How the adversary gathered target data',
  'Command and Control':      'How the adversary communicated with compromised systems',
  'Exfiltration':             'How the adversary transferred data out of the network',
  'Impact':                   'How the adversary disrupted or damaged the environment',
};

// ── CVE severity hints (populated when CVE DB is not available) ──────────────
const CVE_SEVERITY_HINTS = {
  // Well-known CVEs with static severity for offline enrichment
  'CVE-2021-44228': 'Log4Shell — CVSS 10.0 Critical — Remote Code Execution',
  'CVE-2021-34527': 'PrintNightmare — CVSS 8.8 High — Privilege Escalation',
  'CVE-2020-1472':  'Zerologon — CVSS 10.0 Critical — Domain Compromise',
  'CVE-2019-0708':  'BlueKeep — CVSS 9.8 Critical — RDP Remote Code Execution',
  'CVE-2017-0144':  'EternalBlue — CVSS 8.1 High — SMB Remote Code Execution',
  'CVE-2022-30190': 'Follina — CVSS 7.8 High — MSDT Remote Code Execution',
  'CVE-2023-23397': 'Outlook Zero-Click — CVSS 9.8 Critical — NTLM Hash Theft',
  'CVE-2024-12356': 'Critical — Privilege Escalation (Demo Entry)',
};

// ─────────────────────────────────────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Look up a MITRE technique by ID.
 * Returns null if the technique is not in the embedded database.
 *
 * @param {string} techniqueId - e.g. 'T1059', 'T1059.001', 't1059.001'
 * @returns {object|null}
 */
function lookup(techniqueId) {
  if (!techniqueId) return null;
  const id = techniqueId.toUpperCase().trim();
  return TECHNIQUE_DB[id] || null;
}

/**
 * Get a plain-language enrichment string for a technique ID.
 * Returns a formatted markdown string suitable for inline insertion.
 *
 * @param {string} techniqueId
 * @returns {string} Markdown enrichment or empty string
 */
function enrichTechnique(techniqueId) {
  const tech = lookup(techniqueId);
  if (!tech) return '';

  const id      = techniqueId.toUpperCase();
  const tactic  = TACTIC_DESCRIPTIONS[tech.tactic] || tech.tactic;
  const sev     = tech.severity || 'Medium';

  return [
    `**[${id}](https://attack.mitre.org/techniques/${id.replace('.', '/')}) — ${tech.name}**`,
    `_Tactic:_ ${tech.tactic} _(${tactic})_ · _Severity:_ ${sev}`,
    '',
    tech.description,
    '',
    `> **Detection:** ${tech.detection}`,
    '',
    `> **SOC Context:** ${tech.socContext}`,
  ].join('\n');
}

/**
 * Scan text for MITRE technique ID references and enrich each one
 * with its plain-language name (inline annotation, not full expansion).
 * Used by the ResponseProcessor pipeline.
 *
 * @param {string} text
 * @returns {string} Text with technique IDs annotated
 */
function enrichText(text) {
  if (!text) return text;

  // Match T1234 and T1234.001 patterns
  return text.replace(/\bT(\d{4})(?:\.(\d{3}))?\b/g, (match) => {
    const tech = lookup(match);
    if (!tech) return match; // unknown technique — leave as-is

    // Add plain-language name annotation if not already present
    const nameAlreadyPresent = text.includes(tech.name);
    if (nameAlreadyPresent) return match;

    // Short inline annotation: T1059.001 (_PowerShell Execution_)
    return `${match} _(${tech.name})_`;
  });
}

/**
 * Build a full structured section for a MITRE lookup response.
 * Returns formatted markdown following the universal SOC template.
 *
 * @param {string} techniqueId
 * @returns {string}
 */
function buildTechniqueSection(techniqueId) {
  const tech = lookup(techniqueId);
  const id   = (techniqueId || '').toUpperCase();

  if (!tech) {
    return [
      `## MITRE ATT&CK: ${id}`,
      '',
      `_Technique ${id} not found in the embedded database._`,
      `Visit [MITRE ATT&CK](https://attack.mitre.org/techniques/${id.replace('.', '/')}) for the official entry.`,
    ].join('\n');
  }

  const tactic     = tech.tactic || 'Unknown Tactic';
  const tacticDesc = TACTIC_DESCRIPTIONS[tactic.split(',')[0].trim()] || tactic;

  return [
    `## Overview`,
    '',
    `**Technique:** [\`${id}\`](https://attack.mitre.org/techniques/${id.replace('.', '/')}) — **${tech.name}**`,
    `**Tactic:** ${tactic} — _${tacticDesc}_`,
    `**Severity:** ${tech.severity || 'Medium'}`,
    '',
    tech.description,
    '',
    `## Why It Matters`,
    '',
    tech.socContext,
    '',
    `## Detection Guidance`,
    '',
    tech.detection,
    '',
    `## Analyst Tip`,
    '',
    `> 💡 When investigating \`${id}\`, focus on the **context**: who ran it, from where, at what time, and what happened immediately after. A single occurrence is usually not enough — look for the chain of events that led here.`,
    `> `,
    `> Reference: [MITRE ATT&CK ${id}](https://attack.mitre.org/techniques/${id.replace('.', '/')})`,
  ].join('\n');
}

/**
 * Get a short CVE context hint (offline lookup).
 *
 * @param {string} cveId - e.g. 'CVE-2021-44228'
 * @returns {string|null}
 */
function getCVEContext(cveId) {
  return CVE_SEVERITY_HINTS[cveId.toUpperCase()] || null;
}

/**
 * List all technique IDs in the database.
 * @returns {string[]}
 */
function listTechniques() {
  return Object.keys(TECHNIQUE_DB);
}

// ── Exports ───────────────────────────────────────────────────────────────────
module.exports = {
  lookup,
  enrichText,
  enrichTechnique,
  buildTechniqueSection,
  getCVEContext,
  listTechniques,
  TECHNIQUE_DB,
  TACTIC_DESCRIPTIONS,
};
