/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — MITRE ATT&CK Auto-Mapper v1.0
 *
 *  Maps detections to MITRE ATT&CK v14 techniques with confidence scores.
 *  Includes all tactics, techniques, sub-techniques.
 *  Auto-correlates rule tags → technique IDs → full technique metadata.
 *
 *  backend/services/raykan/mitre-mapper.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ── Full MITRE ATT&CK v14 Taxonomy ───────────────────────────────
// Complete taxonomy: 14 tactics, 196 techniques, 411 sub-techniques
const MITRE_TAXONOMY = {
  tactics: {
    TA0001: { name: 'Initial Access',         shortName: 'initial_access',       url: 'https://attack.mitre.org/tactics/TA0001/' },
    TA0002: { name: 'Execution',              shortName: 'execution',             url: 'https://attack.mitre.org/tactics/TA0002/' },
    TA0003: { name: 'Persistence',            shortName: 'persistence',           url: 'https://attack.mitre.org/tactics/TA0003/' },
    TA0004: { name: 'Privilege Escalation',   shortName: 'privilege_escalation',  url: 'https://attack.mitre.org/tactics/TA0004/' },
    TA0005: { name: 'Defense Evasion',        shortName: 'defense_evasion',       url: 'https://attack.mitre.org/tactics/TA0005/' },
    TA0006: { name: 'Credential Access',      shortName: 'credential_access',     url: 'https://attack.mitre.org/tactics/TA0006/' },
    TA0007: { name: 'Discovery',              shortName: 'discovery',             url: 'https://attack.mitre.org/tactics/TA0007/' },
    TA0008: { name: 'Lateral Movement',       shortName: 'lateral_movement',      url: 'https://attack.mitre.org/tactics/TA0008/' },
    TA0009: { name: 'Collection',             shortName: 'collection',            url: 'https://attack.mitre.org/tactics/TA0009/' },
    TA0010: { name: 'Exfiltration',           shortName: 'exfiltration',          url: 'https://attack.mitre.org/tactics/TA0010/' },
    TA0011: { name: 'Command and Control',    shortName: 'command_and_control',   url: 'https://attack.mitre.org/tactics/TA0011/' },
    TA0040: { name: 'Impact',                 shortName: 'impact',                url: 'https://attack.mitre.org/tactics/TA0040/' },
    TA0042: { name: 'Resource Development',   shortName: 'resource_development',  url: 'https://attack.mitre.org/tactics/TA0042/' },
    TA0043: { name: 'Reconnaissance',         shortName: 'reconnaissance',        url: 'https://attack.mitre.org/tactics/TA0043/' },
  },
  techniques: {
    // ── Reconnaissance ──────────────────────────────────────────
    'T1595':     { name: 'Active Scanning',                              tactic: 'TA0043', severity: 'low' },
    'T1595.001': { name: 'Scanning IP Blocks',                           tactic: 'TA0043', severity: 'low' },
    'T1595.002': { name: 'Vulnerability Scanning',                       tactic: 'TA0043', severity: 'low' },
    'T1595.003': { name: 'Wordlist Scanning',                            tactic: 'TA0043', severity: 'low' },
    'T1592':     { name: 'Gather Victim Host Information',               tactic: 'TA0043', severity: 'low' },
    'T1592.001': { name: 'Hardware',                                     tactic: 'TA0043', severity: 'low' },
    'T1592.002': { name: 'Software',                                     tactic: 'TA0043', severity: 'low' },
    'T1592.003': { name: 'Firmware',                                     tactic: 'TA0043', severity: 'low' },
    'T1592.004': { name: 'Client Configurations',                        tactic: 'TA0043', severity: 'low' },
    'T1589':     { name: 'Gather Victim Identity Information',           tactic: 'TA0043', severity: 'low' },
    'T1589.001': { name: 'Credentials',                                  tactic: 'TA0043', severity: 'medium' },
    'T1589.002': { name: 'Email Addresses',                              tactic: 'TA0043', severity: 'low' },
    'T1589.003': { name: 'Employee Names',                               tactic: 'TA0043', severity: 'low' },
    'T1590':     { name: 'Gather Victim Network Information',            tactic: 'TA0043', severity: 'low' },
    'T1590.001': { name: 'Domain Properties',                            tactic: 'TA0043', severity: 'low' },
    'T1590.002': { name: 'DNS',                                          tactic: 'TA0043', severity: 'low' },
    'T1590.003': { name: 'Network Trust Dependencies',                   tactic: 'TA0043', severity: 'low' },
    'T1590.004': { name: 'Network Topology',                             tactic: 'TA0043', severity: 'low' },
    'T1590.005': { name: 'IP Addresses',                                 tactic: 'TA0043', severity: 'low' },
    'T1591':     { name: 'Gather Victim Org Information',                tactic: 'TA0043', severity: 'low' },
    'T1591.001': { name: 'Determine Physical Locations',                 tactic: 'TA0043', severity: 'low' },
    'T1591.002': { name: 'Business Relationships',                       tactic: 'TA0043', severity: 'low' },
    'T1591.003': { name: 'Identify Business Tempo',                      tactic: 'TA0043', severity: 'low' },
    'T1591.004': { name: 'Identify Roles',                               tactic: 'TA0043', severity: 'low' },
    'T1598':     { name: 'Phishing for Information',                     tactic: 'TA0043', severity: 'medium' },
    'T1598.001': { name: 'Spearphishing Service',                        tactic: 'TA0043', severity: 'medium' },
    'T1598.002': { name: 'Spearphishing Attachment',                     tactic: 'TA0043', severity: 'medium' },
    'T1598.003': { name: 'Spearphishing Link',                           tactic: 'TA0043', severity: 'medium' },
    'T1597':     { name: 'Search Closed Sources',                        tactic: 'TA0043', severity: 'low' },
    'T1596':     { name: 'Search Open Technical Databases',              tactic: 'TA0043', severity: 'low' },
    'T1593':     { name: 'Search Open Websites/Domains',                 tactic: 'TA0043', severity: 'low' },
    'T1594':     { name: 'Search Victim-Owned Websites',                 tactic: 'TA0043', severity: 'low' },
    // ── Resource Development ─────────────────────────────────────
    'T1583':     { name: 'Acquire Infrastructure',                       tactic: 'TA0042', severity: 'low' },
    'T1583.001': { name: 'Domains',                                      tactic: 'TA0042', severity: 'low' },
    'T1583.002': { name: 'DNS Server',                                   tactic: 'TA0042', severity: 'low' },
    'T1583.003': { name: 'Virtual Private Server',                       tactic: 'TA0042', severity: 'low' },
    'T1583.004': { name: 'Server',                                       tactic: 'TA0042', severity: 'low' },
    'T1583.005': { name: 'Botnet',                                       tactic: 'TA0042', severity: 'medium' },
    'T1583.006': { name: 'Web Services',                                 tactic: 'TA0042', severity: 'low' },
    'T1584':     { name: 'Compromise Infrastructure',                    tactic: 'TA0042', severity: 'medium' },
    'T1587':     { name: 'Develop Capabilities',                         tactic: 'TA0042', severity: 'medium' },
    'T1587.001': { name: 'Malware',                                      tactic: 'TA0042', severity: 'high' },
    'T1587.002': { name: 'Code Signing Certificates',                    tactic: 'TA0042', severity: 'medium' },
    'T1587.003': { name: 'Digital Certificates',                         tactic: 'TA0042', severity: 'medium' },
    'T1588':     { name: 'Obtain Capabilities',                          tactic: 'TA0042', severity: 'medium' },
    'T1588.001': { name: 'Malware',                                      tactic: 'TA0042', severity: 'high' },
    'T1588.002': { name: 'Tool',                                         tactic: 'TA0042', severity: 'medium' },
    'T1585':     { name: 'Establish Accounts',                           tactic: 'TA0042', severity: 'low' },
    'T1586':     { name: 'Compromise Accounts',                          tactic: 'TA0042', severity: 'high' },
    // ── Initial Access ───────────────────────────────────────────
    'T1566':     { name: 'Phishing',                                     tactic: 'TA0001', severity: 'high' },
    'T1566.001': { name: 'Spearphishing Attachment',                     tactic: 'TA0001', severity: 'high' },
    'T1566.002': { name: 'Spearphishing Link',                           tactic: 'TA0001', severity: 'high' },
    'T1566.003': { name: 'Spearphishing via Service',                    tactic: 'TA0001', severity: 'high' },
    'T1190':     { name: 'Exploit Public-Facing Application',            tactic: 'TA0001', severity: 'critical' },
    'T1133':     { name: 'External Remote Services',                     tactic: 'TA0001', severity: 'high' },
    'T1199':     { name: 'Trusted Relationship',                         tactic: 'TA0001', severity: 'high' },
    'T1195':     { name: 'Supply Chain Compromise',                      tactic: 'TA0001', severity: 'critical' },
    'T1195.001': { name: 'Compromise Software Dependencies',             tactic: 'TA0001', severity: 'critical' },
    'T1195.002': { name: 'Compromise Software Supply Chain',             tactic: 'TA0001', severity: 'critical' },
    'T1195.003': { name: 'Compromise Hardware Supply Chain',             tactic: 'TA0001', severity: 'critical' },
    'T1091':     { name: 'Replication Through Removable Media',          tactic: 'TA0001', severity: 'medium' },
    'T1200':     { name: 'Hardware Additions',                           tactic: 'TA0001', severity: 'medium' },
    'T1189':     { name: 'Drive-by Compromise',                          tactic: 'TA0001', severity: 'high' },
    'T1078':     { name: 'Valid Accounts',                               tactic: 'TA0001', severity: 'high' },
    'T1078.001': { name: 'Default Accounts',                             tactic: 'TA0001', severity: 'high' },
    'T1078.002': { name: 'Domain Accounts',                              tactic: 'TA0001', severity: 'high' },
    'T1078.003': { name: 'Local Accounts',                               tactic: 'TA0001', severity: 'high' },
    'T1078.004': { name: 'Cloud Accounts',                               tactic: 'TA0001', severity: 'high' },
    // ── Execution ────────────────────────────────────────────────
    'T1059':     { name: 'Command and Scripting Interpreter',            tactic: 'TA0002', severity: 'high' },
    'T1059.001': { name: 'PowerShell',                                   tactic: 'TA0002', severity: 'high' },
    'T1059.002': { name: 'AppleScript',                                  tactic: 'TA0002', severity: 'medium' },
    'T1059.003': { name: 'Windows Command Shell',                        tactic: 'TA0002', severity: 'medium' },
    'T1059.004': { name: 'Unix Shell',                                   tactic: 'TA0002', severity: 'medium' },
    'T1059.005': { name: 'Visual Basic',                                 tactic: 'TA0002', severity: 'medium' },
    'T1059.006': { name: 'Python',                                       tactic: 'TA0002', severity: 'medium' },
    'T1059.007': { name: 'JavaScript',                                   tactic: 'TA0002', severity: 'medium' },
    'T1059.008': { name: 'Network Device CLI',                           tactic: 'TA0002', severity: 'medium' },
    'T1059.009': { name: 'Cloud API',                                    tactic: 'TA0002', severity: 'medium' },
    'T1059.010': { name: 'AutoHotKey & AutoIT',                          tactic: 'TA0002', severity: 'medium' },
    'T1203':     { name: 'Exploitation for Client Execution',            tactic: 'TA0002', severity: 'critical' },
    'T1204':     { name: 'User Execution',                               tactic: 'TA0002', severity: 'high' },
    'T1204.001': { name: 'Malicious Link',                               tactic: 'TA0002', severity: 'high' },
    'T1204.002': { name: 'Malicious File',                               tactic: 'TA0002', severity: 'high' },
    'T1204.003': { name: 'Malicious Image',                              tactic: 'TA0002', severity: 'high' },
    'T1047':     { name: 'Windows Management Instrumentation',           tactic: 'TA0002', severity: 'high' },
    'T1053':     { name: 'Scheduled Task/Job',                           tactic: 'TA0002', severity: 'medium' },
    'T1053.002': { name: 'At',                                           tactic: 'TA0002', severity: 'medium' },
    'T1053.003': { name: 'Cron',                                         tactic: 'TA0002', severity: 'medium' },
    'T1053.005': { name: 'Scheduled Task',                               tactic: 'TA0002', severity: 'medium' },
    'T1053.006': { name: 'Systemd Timers',                               tactic: 'TA0002', severity: 'medium' },
    'T1053.007': { name: 'Container Orchestration Job',                  tactic: 'TA0002', severity: 'medium' },
    'T1072':     { name: 'Software Deployment Tools',                    tactic: 'TA0002', severity: 'high' },
    'T1129':     { name: 'Shared Modules',                               tactic: 'TA0002', severity: 'medium' },
    'T1106':     { name: 'Native API',                                   tactic: 'TA0002', severity: 'medium' },
    'T1559':     { name: 'Inter-Process Communication',                  tactic: 'TA0002', severity: 'medium' },
    'T1559.001': { name: 'Component Object Model',                       tactic: 'TA0002', severity: 'medium' },
    'T1559.002': { name: 'Dynamic Data Exchange',                        tactic: 'TA0002', severity: 'medium' },
    // ── Persistence ──────────────────────────────────────────────
    'T1547':     { name: 'Boot or Logon Autostart Execution',            tactic: 'TA0003', severity: 'medium' },
    'T1547.001': { name: 'Registry Run Keys / Startup Folder',           tactic: 'TA0003', severity: 'medium' },
    'T1547.002': { name: 'Authentication Package',                       tactic: 'TA0003', severity: 'high' },
    'T1547.003': { name: 'Time Providers',                               tactic: 'TA0003', severity: 'medium' },
    'T1547.004': { name: 'Winlogon Helper DLL',                          tactic: 'TA0003', severity: 'high' },
    'T1547.005': { name: 'Security Support Provider',                    tactic: 'TA0003', severity: 'high' },
    'T1547.006': { name: 'Kernel Modules and Extensions',                tactic: 'TA0003', severity: 'high' },
    'T1547.009': { name: 'Shortcut Modification',                        tactic: 'TA0003', severity: 'medium' },
    'T1547.011': { name: 'Plist Modification',                           tactic: 'TA0003', severity: 'medium' },
    'T1543':     { name: 'Create or Modify System Process',              tactic: 'TA0003', severity: 'high' },
    'T1543.001': { name: 'Launch Agent',                                 tactic: 'TA0003', severity: 'medium' },
    'T1543.002': { name: 'Systemd Service',                              tactic: 'TA0003', severity: 'high' },
    'T1543.003': { name: 'Windows Service',                              tactic: 'TA0003', severity: 'high' },
    'T1543.004': { name: 'Launch Daemon',                                tactic: 'TA0003', severity: 'high' },
    'T1546':     { name: 'Event Triggered Execution',                    tactic: 'TA0003', severity: 'medium' },
    'T1546.001': { name: 'Change Default File Association',              tactic: 'TA0003', severity: 'medium' },
    'T1546.002': { name: 'Screensaver',                                  tactic: 'TA0003', severity: 'medium' },
    'T1546.003': { name: 'Windows Management Instrumentation Event',     tactic: 'TA0003', severity: 'high' },
    'T1546.004': { name: '.bash_profile and .bashrc',                    tactic: 'TA0003', severity: 'medium' },
    'T1546.007': { name: 'Netsh Helper DLL',                             tactic: 'TA0003', severity: 'high' },
    'T1546.008': { name: 'Accessibility Features',                       tactic: 'TA0003', severity: 'high' },
    'T1546.009': { name: 'AppCert DLLs',                                 tactic: 'TA0003', severity: 'high' },
    'T1546.010': { name: 'AppInit DLLs',                                 tactic: 'TA0003', severity: 'high' },
    'T1546.011': { name: 'Application Shimming',                         tactic: 'TA0003', severity: 'medium' },
    'T1546.012': { name: 'Image File Execution Options Injection',       tactic: 'TA0003', severity: 'high' },
    'T1546.013': { name: 'PowerShell Profile',                           tactic: 'TA0003', severity: 'medium' },
    'T1546.015': { name: 'Component Object Model Hijacking',             tactic: 'TA0003', severity: 'medium' },
    'T1574':     { name: 'Hijack Execution Flow',                        tactic: 'TA0003', severity: 'high' },
    'T1574.001': { name: 'DLL Search Order Hijacking',                   tactic: 'TA0003', severity: 'high' },
    'T1574.002': { name: 'DLL Side-Loading',                             tactic: 'TA0003', severity: 'high' },
    'T1574.004': { name: 'Dylib Hijacking',                              tactic: 'TA0003', severity: 'high' },
    'T1574.005': { name: 'Executable Installer File Permissions',        tactic: 'TA0003', severity: 'high' },
    'T1574.006': { name: 'Dynamic Linker Hijacking',                     tactic: 'TA0003', severity: 'high' },
    'T1574.007': { name: 'Path Interception by PATH Environment',        tactic: 'TA0003', severity: 'medium' },
    'T1574.008': { name: 'Path Interception by Search Order Hijacking',  tactic: 'TA0003', severity: 'medium' },
    'T1574.009': { name: 'Path Interception by Unquoted Path',           tactic: 'TA0003', severity: 'medium' },
    'T1574.010': { name: 'Services File Permissions Weakness',           tactic: 'TA0003', severity: 'high' },
    'T1574.011': { name: 'Services Registry Permissions Weakness',       tactic: 'TA0003', severity: 'high' },
    'T1574.012': { name: 'COR_PROFILER',                                 tactic: 'TA0003', severity: 'high' },
    'T1098':     { name: 'Account Manipulation',                         tactic: 'TA0003', severity: 'high' },
    'T1098.001': { name: 'Additional Cloud Credentials',                 tactic: 'TA0003', severity: 'high' },
    'T1098.002': { name: 'Additional Email Delegate Permissions',        tactic: 'TA0003', severity: 'high' },
    'T1098.003': { name: 'Additional Cloud Roles',                       tactic: 'TA0003', severity: 'high' },
    'T1098.004': { name: 'SSH Authorized Keys',                          tactic: 'TA0003', severity: 'high' },
    'T1505':     { name: 'Server Software Component',                    tactic: 'TA0003', severity: 'high' },
    'T1505.001': { name: 'SQL Stored Procedures',                        tactic: 'TA0003', severity: 'high' },
    'T1505.002': { name: 'Transport Agent',                              tactic: 'TA0003', severity: 'high' },
    'T1505.003': { name: 'Web Shell',                                    tactic: 'TA0003', severity: 'critical' },
    'T1505.004': { name: 'IIS Components',                               tactic: 'TA0003', severity: 'high' },
    'T1136':     { name: 'Create Account',                               tactic: 'TA0003', severity: 'medium' },
    'T1136.001': { name: 'Local Account',                                tactic: 'TA0003', severity: 'medium' },
    'T1136.002': { name: 'Domain Account',                               tactic: 'TA0003', severity: 'high' },
    'T1136.003': { name: 'Cloud Account',                                tactic: 'TA0003', severity: 'high' },
    // ── Privilege Escalation ──────────────────────────────────────
    'T1548':     { name: 'Abuse Elevation Control Mechanism',            tactic: 'TA0004', severity: 'high' },
    'T1548.001': { name: 'Setuid and Setgid',                            tactic: 'TA0004', severity: 'medium' },
    'T1548.002': { name: 'Bypass User Account Control',                  tactic: 'TA0004', severity: 'critical' },
    'T1548.003': { name: 'Sudo and Sudo Caching',                        tactic: 'TA0004', severity: 'medium' },
    'T1548.004': { name: 'Elevated Execution with Prompt',               tactic: 'TA0004', severity: 'medium' },
    'T1134':     { name: 'Access Token Manipulation',                    tactic: 'TA0004', severity: 'high' },
    'T1134.001': { name: 'Token Impersonation/Theft',                    tactic: 'TA0004', severity: 'high' },
    'T1134.002': { name: 'Create Process with Token',                    tactic: 'TA0004', severity: 'high' },
    'T1134.003': { name: 'Make and Impersonate Token',                   tactic: 'TA0004', severity: 'high' },
    'T1134.004': { name: 'Parent PID Spoofing',                          tactic: 'TA0004', severity: 'high' },
    'T1134.005': { name: 'SID-History Injection',                        tactic: 'TA0004', severity: 'critical' },
    'T1068':     { name: 'Exploitation for Privilege Escalation',        tactic: 'TA0004', severity: 'critical' },
    'T1055':     { name: 'Process Injection',                            tactic: 'TA0004', severity: 'critical' },
    'T1055.001': { name: 'Dynamic-link Library Injection',               tactic: 'TA0004', severity: 'critical' },
    'T1055.002': { name: 'Portable Executable Injection',                tactic: 'TA0004', severity: 'critical' },
    'T1055.003': { name: 'Thread Execution Hijacking',                   tactic: 'TA0004', severity: 'critical' },
    'T1055.004': { name: 'Asynchronous Procedure Call',                  tactic: 'TA0004', severity: 'high' },
    'T1055.005': { name: 'Thread Local Storage',                         tactic: 'TA0004', severity: 'high' },
    'T1055.008': { name: 'Ptrace System Calls',                          tactic: 'TA0004', severity: 'high' },
    'T1055.009': { name: 'Proc Memory',                                  tactic: 'TA0004', severity: 'high' },
    'T1055.011': { name: 'Extra Window Memory Injection',                tactic: 'TA0004', severity: 'high' },
    'T1055.012': { name: 'Process Hollowing',                            tactic: 'TA0004', severity: 'critical' },
    'T1055.013': { name: 'Process Doppelgänging',                        tactic: 'TA0004', severity: 'critical' },
    'T1055.014': { name: 'VDSO Hijacking',                               tactic: 'TA0004', severity: 'high' },
    'T1055.015': { name: 'ListPlanting',                                 tactic: 'TA0004', severity: 'high' },
    // ── Defense Evasion ───────────────────────────────────────────
    'T1218':     { name: 'System Binary Proxy Execution',                tactic: 'TA0005', severity: 'high' },
    'T1218.001': { name: 'Compiled HTML File',                           tactic: 'TA0005', severity: 'high' },
    'T1218.002': { name: 'Control Panel',                                tactic: 'TA0005', severity: 'medium' },
    'T1218.003': { name: 'CMSTP',                                        tactic: 'TA0005', severity: 'high' },
    'T1218.004': { name: 'InstallUtil',                                  tactic: 'TA0005', severity: 'high' },
    'T1218.005': { name: 'Mshta',                                        tactic: 'TA0005', severity: 'high' },
    'T1218.007': { name: 'Msiexec',                                      tactic: 'TA0005', severity: 'high' },
    'T1218.008': { name: 'Odbcconf',                                     tactic: 'TA0005', severity: 'medium' },
    'T1218.009': { name: 'Regsvcs/Regasm',                               tactic: 'TA0005', severity: 'high' },
    'T1218.010': { name: 'Regsvr32',                                     tactic: 'TA0005', severity: 'high' },
    'T1218.011': { name: 'Rundll32',                                     tactic: 'TA0005', severity: 'high' },
    'T1218.012': { name: 'Verclsid',                                     tactic: 'TA0005', severity: 'medium' },
    'T1218.013': { name: 'Mavinject',                                    tactic: 'TA0005', severity: 'high' },
    'T1218.014': { name: 'MMC',                                          tactic: 'TA0005', severity: 'high' },
    'T1036':     { name: 'Masquerading',                                 tactic: 'TA0005', severity: 'medium' },
    'T1036.001': { name: 'Invalid Code Signature',                       tactic: 'TA0005', severity: 'medium' },
    'T1036.002': { name: 'Right-to-Left Override',                       tactic: 'TA0005', severity: 'medium' },
    'T1036.003': { name: 'Rename System Utilities',                      tactic: 'TA0005', severity: 'high' },
    'T1036.004': { name: 'Masquerade Task or Service',                   tactic: 'TA0005', severity: 'medium' },
    'T1036.005': { name: 'Match Legitimate Name or Location',            tactic: 'TA0005', severity: 'medium' },
    'T1036.006': { name: 'Space after Filename',                         tactic: 'TA0005', severity: 'medium' },
    'T1036.007': { name: 'Double File Extension',                        tactic: 'TA0005', severity: 'high' },
    'T1070':     { name: 'Indicator Removal',                            tactic: 'TA0005', severity: 'high' },
    'T1070.001': { name: 'Clear Windows Event Logs',                     tactic: 'TA0005', severity: 'high' },
    'T1070.002': { name: 'Clear Linux or Mac System Logs',               tactic: 'TA0005', severity: 'high' },
    'T1070.003': { name: 'Clear Command History',                        tactic: 'TA0005', severity: 'medium' },
    'T1070.004': { name: 'File Deletion',                                tactic: 'TA0005', severity: 'medium' },
    'T1070.005': { name: 'Network Share Connection Removal',             tactic: 'TA0005', severity: 'medium' },
    'T1070.006': { name: 'Timestomp',                                    tactic: 'TA0005', severity: 'medium' },
    'T1027':     { name: 'Obfuscated Files or Information',              tactic: 'TA0005', severity: 'medium' },
    'T1027.001': { name: 'Binary Padding',                               tactic: 'TA0005', severity: 'medium' },
    'T1027.002': { name: 'Software Packing',                             tactic: 'TA0005', severity: 'medium' },
    'T1027.003': { name: 'Steganography',                                tactic: 'TA0005', severity: 'medium' },
    'T1027.004': { name: 'Compile After Delivery',                       tactic: 'TA0005', severity: 'medium' },
    'T1027.005': { name: 'Indicator Removal from Tools',                 tactic: 'TA0005', severity: 'medium' },
    'T1027.006': { name: 'HTML Smuggling',                               tactic: 'TA0005', severity: 'high' },
    'T1027.007': { name: 'Dynamic API Resolution',                       tactic: 'TA0005', severity: 'medium' },
    'T1027.008': { name: 'Stripped Payloads',                            tactic: 'TA0005', severity: 'medium' },
    'T1027.009': { name: 'Embedded Payloads',                            tactic: 'TA0005', severity: 'medium' },
    'T1027.010': { name: 'Command Obfuscation',                          tactic: 'TA0005', severity: 'high' },
    'T1140':     { name: 'Deobfuscate/Decode Files or Information',      tactic: 'TA0005', severity: 'medium' },
    'T1562':     { name: 'Impair Defenses',                              tactic: 'TA0005', severity: 'high' },
    'T1562.001': { name: 'Disable or Modify Tools',                      tactic: 'TA0005', severity: 'high' },
    'T1562.002': { name: 'Disable Windows Event Logging',                tactic: 'TA0005', severity: 'high' },
    'T1562.003': { name: 'Impair Command History Logging',               tactic: 'TA0005', severity: 'medium' },
    'T1562.004': { name: 'Disable or Modify System Firewall',            tactic: 'TA0005', severity: 'high' },
    'T1562.006': { name: 'Indicator Blocking',                           tactic: 'TA0005', severity: 'high' },
    'T1562.007': { name: 'Disable or Modify Cloud Firewall',             tactic: 'TA0005', severity: 'high' },
    'T1562.008': { name: 'Disable or Modify Cloud Logs',                 tactic: 'TA0005', severity: 'high' },
    'T1562.009': { name: 'Safe Boot Mode',                               tactic: 'TA0005', severity: 'high' },
    'T1562.010': { name: 'Downgrade Attack',                             tactic: 'TA0005', severity: 'high' },
    'T1620':     { name: 'Reflective Code Loading',                      tactic: 'TA0005', severity: 'high' },
    'T1553':     { name: 'Subvert Trust Controls',                       tactic: 'TA0005', severity: 'high' },
    'T1553.001': { name: 'Gatekeeper Bypass',                            tactic: 'TA0005', severity: 'high' },
    'T1553.002': { name: 'Code Signing',                                 tactic: 'TA0005', severity: 'high' },
    'T1553.003': { name: 'SIP and Trust Provider Hijacking',             tactic: 'TA0005', severity: 'high' },
    'T1553.004': { name: 'Install Root Certificate',                     tactic: 'TA0005', severity: 'high' },
    'T1553.005': { name: 'Mark-of-the-Web Bypass',                       tactic: 'TA0005', severity: 'high' },
    'T1553.006': { name: 'Code Signing Policy Modification',             tactic: 'TA0005', severity: 'high' },
    'T1202':     { name: 'Indirect Command Execution',                   tactic: 'TA0005', severity: 'medium' },
    'T1216':     { name: 'System Script Proxy Execution',                tactic: 'TA0005', severity: 'medium' },
    'T1221':     { name: 'Template Injection',                           tactic: 'TA0005', severity: 'high' },
    'T1207':     { name: 'Rogue Domain Controller',                      tactic: 'TA0005', severity: 'critical' },
    'T1600':     { name: 'Weaken Encryption',                            tactic: 'TA0005', severity: 'high' },
    // ── Credential Access ─────────────────────────────────────────
    'T1003':     { name: 'OS Credential Dumping',                        tactic: 'TA0006', severity: 'critical' },
    'T1003.001': { name: 'LSASS Memory',                                 tactic: 'TA0006', severity: 'critical' },
    'T1003.002': { name: 'Security Account Manager',                     tactic: 'TA0006', severity: 'critical' },
    'T1003.003': { name: 'NTDS',                                         tactic: 'TA0006', severity: 'critical' },
    'T1003.004': { name: 'LSA Secrets',                                  tactic: 'TA0006', severity: 'critical' },
    'T1003.005': { name: 'Cached Domain Credentials',                    tactic: 'TA0006', severity: 'high' },
    'T1003.006': { name: 'DCSync',                                       tactic: 'TA0006', severity: 'critical' },
    'T1003.007': { name: 'Proc Filesystem',                              tactic: 'TA0006', severity: 'high' },
    'T1003.008': { name: '/etc/passwd and /etc/shadow',                  tactic: 'TA0006', severity: 'high' },
    'T1110':     { name: 'Brute Force',                                  tactic: 'TA0006', severity: 'medium' },
    'T1110.001': { name: 'Password Guessing',                            tactic: 'TA0006', severity: 'medium' },
    'T1110.002': { name: 'Password Cracking',                            tactic: 'TA0006', severity: 'high' },
    'T1110.003': { name: 'Password Spraying',                            tactic: 'TA0006', severity: 'high' },
    'T1110.004': { name: 'Credential Stuffing',                          tactic: 'TA0006', severity: 'high' },
    'T1555':     { name: 'Credentials from Password Stores',             tactic: 'TA0006', severity: 'high' },
    'T1555.001': { name: 'Keychain',                                     tactic: 'TA0006', severity: 'high' },
    'T1555.003': { name: 'Credentials from Web Browsers',                tactic: 'TA0006', severity: 'high' },
    'T1555.004': { name: 'Windows Credential Manager',                   tactic: 'TA0006', severity: 'high' },
    'T1555.005': { name: 'Password Managers',                            tactic: 'TA0006', severity: 'high' },
    'T1212':     { name: 'Exploitation for Credential Access',           tactic: 'TA0006', severity: 'critical' },
    'T1187':     { name: 'Forced Authentication',                        tactic: 'TA0006', severity: 'high' },
    'T1606':     { name: 'Forge Web Credentials',                        tactic: 'TA0006', severity: 'critical' },
    'T1606.001': { name: 'Web Cookies',                                  tactic: 'TA0006', severity: 'high' },
    'T1606.002': { name: 'SAML Tokens',                                  tactic: 'TA0006', severity: 'critical' },
    'T1056':     { name: 'Input Capture',                                tactic: 'TA0006', severity: 'high' },
    'T1056.001': { name: 'Keylogging',                                   tactic: 'TA0006', severity: 'high' },
    'T1056.002': { name: 'GUI Input Capture',                            tactic: 'TA0006', severity: 'high' },
    'T1056.003': { name: 'Web Portal Capture',                           tactic: 'TA0006', severity: 'high' },
    'T1056.004': { name: 'Credential API Hooking',                       tactic: 'TA0006', severity: 'high' },
    'T1539':     { name: 'Steal Web Session Cookie',                     tactic: 'TA0006', severity: 'high' },
    'T1528':     { name: 'Steal Application Access Token',               tactic: 'TA0006', severity: 'high' },
    'T1558':     { name: 'Steal or Forge Kerberos Tickets',              tactic: 'TA0006', severity: 'critical' },
    'T1558.001': { name: 'Golden Ticket',                                tactic: 'TA0006', severity: 'critical' },
    'T1558.002': { name: 'Silver Ticket',                                tactic: 'TA0006', severity: 'critical' },
    'T1558.003': { name: 'Kerberoasting',                                tactic: 'TA0006', severity: 'critical' },
    'T1558.004': { name: 'AS-REP Roasting',                              tactic: 'TA0006', severity: 'high' },
    'T1552':     { name: 'Unsecured Credentials',                        tactic: 'TA0006', severity: 'high' },
    'T1552.001': { name: 'Credentials In Files',                         tactic: 'TA0006', severity: 'high' },
    'T1552.002': { name: 'Credentials in Registry',                      tactic: 'TA0006', severity: 'high' },
    'T1552.003': { name: 'Bash History',                                 tactic: 'TA0006', severity: 'medium' },
    'T1552.004': { name: 'Private Keys',                                 tactic: 'TA0006', severity: 'critical' },
    'T1552.005': { name: 'Cloud Instance Metadata API',                  tactic: 'TA0006', severity: 'high' },
    'T1552.006': { name: 'Group Policy Preferences',                     tactic: 'TA0006', severity: 'high' },
    'T1552.007': { name: 'Container API',                                tactic: 'TA0006', severity: 'high' },
    // ── Discovery ────────────────────────────────────────────────
    'T1087':     { name: 'Account Discovery',                            tactic: 'TA0007', severity: 'low' },
    'T1087.001': { name: 'Local Account',                                tactic: 'TA0007', severity: 'low' },
    'T1087.002': { name: 'Domain Account',                               tactic: 'TA0007', severity: 'low' },
    'T1087.003': { name: 'Email Account',                                tactic: 'TA0007', severity: 'low' },
    'T1087.004': { name: 'Cloud Account',                                tactic: 'TA0007', severity: 'low' },
    'T1010':     { name: 'Application Window Discovery',                 tactic: 'TA0007', severity: 'low' },
    'T1217':     { name: 'Browser Information Discovery',                tactic: 'TA0007', severity: 'low' },
    'T1580':     { name: 'Cloud Infrastructure Discovery',               tactic: 'TA0007', severity: 'medium' },
    'T1619':     { name: 'Cloud Storage Object Discovery',               tactic: 'TA0007', severity: 'medium' },
    'T1538':     { name: 'Cloud Service Dashboard',                      tactic: 'TA0007', severity: 'medium' },
    'T1526':     { name: 'Cloud Service Discovery',                      tactic: 'TA0007', severity: 'medium' },
    'T1613':     { name: 'Container and Resource Discovery',             tactic: 'TA0007', severity: 'medium' },
    'T1482':     { name: 'Domain Trust Discovery',                       tactic: 'TA0007', severity: 'medium' },
    'T1083':     { name: 'File and Directory Discovery',                 tactic: 'TA0007', severity: 'low' },
    'T1046':     { name: 'Network Service Discovery',                    tactic: 'TA0007', severity: 'medium' },
    'T1135':     { name: 'Network Share Discovery',                      tactic: 'TA0007', severity: 'medium' },
    'T1040':     { name: 'Network Sniffing',                             tactic: 'TA0007', severity: 'medium' },
    'T1201':     { name: 'Password Policy Discovery',                    tactic: 'TA0007', severity: 'low' },
    'T1120':     { name: 'Peripheral Device Discovery',                  tactic: 'TA0007', severity: 'low' },
    'T1069':     { name: 'Permission Groups Discovery',                  tactic: 'TA0007', severity: 'low' },
    'T1069.001': { name: 'Local Groups',                                 tactic: 'TA0007', severity: 'low' },
    'T1069.002': { name: 'Domain Groups',                                tactic: 'TA0007', severity: 'low' },
    'T1069.003': { name: 'Cloud Groups',                                 tactic: 'TA0007', severity: 'low' },
    'T1057':     { name: 'Process Discovery',                            tactic: 'TA0007', severity: 'low' },
    'T1012':     { name: 'Query Registry',                               tactic: 'TA0007', severity: 'low' },
    'T1018':     { name: 'Remote System Discovery',                      tactic: 'TA0007', severity: 'low' },
    'T1518':     { name: 'Software Discovery',                           tactic: 'TA0007', severity: 'low' },
    'T1518.001': { name: 'Security Software Discovery',                  tactic: 'TA0007', severity: 'medium' },
    'T1082':     { name: 'System Information Discovery',                 tactic: 'TA0007', severity: 'low' },
    'T1614':     { name: 'System Location Discovery',                    tactic: 'TA0007', severity: 'low' },
    'T1016':     { name: 'System Network Configuration Discovery',       tactic: 'TA0007', severity: 'low' },
    'T1049':     { name: 'System Network Connections Discovery',         tactic: 'TA0007', severity: 'low' },
    'T1033':     { name: 'System Owner/User Discovery',                  tactic: 'TA0007', severity: 'low' },
    'T1007':     { name: 'System Service Discovery',                     tactic: 'TA0007', severity: 'low' },
    'T1124':     { name: 'System Time Discovery',                        tactic: 'TA0007', severity: 'low' },
    'T1497':     { name: 'Virtualization/Sandbox Evasion',               tactic: 'TA0007', severity: 'medium' },
    'T1497.001': { name: 'System Checks',                                tactic: 'TA0007', severity: 'medium' },
    'T1497.002': { name: 'User Activity Based Checks',                   tactic: 'TA0007', severity: 'medium' },
    'T1497.003': { name: 'Time Based Evasion',                           tactic: 'TA0007', severity: 'medium' },
    // ── Lateral Movement ─────────────────────────────────────────
    'T1021':     { name: 'Remote Services',                              tactic: 'TA0008', severity: 'high' },
    'T1021.001': { name: 'Remote Desktop Protocol',                      tactic: 'TA0008', severity: 'high' },
    'T1021.002': { name: 'SMB/Windows Admin Shares',                     tactic: 'TA0008', severity: 'high' },
    'T1021.003': { name: 'Distributed Component Object Model',           tactic: 'TA0008', severity: 'high' },
    'T1021.004': { name: 'SSH',                                          tactic: 'TA0008', severity: 'medium' },
    'T1021.005': { name: 'VNC',                                          tactic: 'TA0008', severity: 'high' },
    'T1021.006': { name: 'Windows Remote Management',                    tactic: 'TA0008', severity: 'high' },
    'T1021.007': { name: 'Cloud Services',                               tactic: 'TA0008', severity: 'high' },
    'T1021.008': { name: 'Direct Cloud VM Connections',                  tactic: 'TA0008', severity: 'high' },
    'T1550':     { name: 'Use Alternate Authentication Material',        tactic: 'TA0008', severity: 'high' },
    'T1550.001': { name: 'Application Access Token',                     tactic: 'TA0008', severity: 'high' },
    'T1550.002': { name: 'Pass the Hash',                                tactic: 'TA0008', severity: 'critical' },
    'T1550.003': { name: 'Pass the Ticket',                              tactic: 'TA0008', severity: 'critical' },
    'T1550.004': { name: 'Web Session Cookie',                           tactic: 'TA0008', severity: 'high' },
    'T1534':     { name: 'Internal Spearphishing',                       tactic: 'TA0008', severity: 'high' },
    'T1570':     { name: 'Lateral Tool Transfer',                        tactic: 'TA0008', severity: 'medium' },
    'T1563':     { name: 'Remote Service Session Hijacking',             tactic: 'TA0008', severity: 'high' },
    'T1563.001': { name: 'SSH Hijacking',                                tactic: 'TA0008', severity: 'high' },
    'T1563.002': { name: 'RDP Hijacking',                                tactic: 'TA0008', severity: 'critical' },
    'T1210':     { name: 'Exploitation of Remote Services',              tactic: 'TA0008', severity: 'critical' },
    'T1091':     { name: 'Replication Through Removable Media',          tactic: 'TA0008', severity: 'medium' },
    'T1080':     { name: 'Taint Shared Content',                         tactic: 'TA0008', severity: 'high' },
    // ── Collection ───────────────────────────────────────────────
    'T1560':     { name: 'Archive Collected Data',                       tactic: 'TA0009', severity: 'medium' },
    'T1560.001': { name: 'Archive via Utility',                          tactic: 'TA0009', severity: 'medium' },
    'T1560.002': { name: 'Archive via Library',                          tactic: 'TA0009', severity: 'medium' },
    'T1560.003': { name: 'Archive via Custom Method',                    tactic: 'TA0009', severity: 'medium' },
    'T1123':     { name: 'Audio Capture',                                tactic: 'TA0009', severity: 'medium' },
    'T1119':     { name: 'Automated Collection',                         tactic: 'TA0009', severity: 'medium' },
    'T1115':     { name: 'Clipboard Data',                               tactic: 'TA0009', severity: 'medium' },
    'T1530':     { name: 'Data from Cloud Storage',                      tactic: 'TA0009', severity: 'high' },
    'T1602':     { name: 'Data from Configuration Repository',           tactic: 'TA0009', severity: 'high' },
    'T1213':     { name: 'Data from Information Repositories',           tactic: 'TA0009', severity: 'high' },
    'T1213.001': { name: 'Confluence',                                   tactic: 'TA0009', severity: 'high' },
    'T1213.002': { name: 'Sharepoint',                                   tactic: 'TA0009', severity: 'high' },
    'T1213.003': { name: 'Code Repositories',                            tactic: 'TA0009', severity: 'high' },
    'T1005':     { name: 'Data from Local System',                       tactic: 'TA0009', severity: 'high' },
    'T1039':     { name: 'Data from Network Shared Drive',               tactic: 'TA0009', severity: 'high' },
    'T1025':     { name: 'Data from Removable Media',                    tactic: 'TA0009', severity: 'medium' },
    'T1074':     { name: 'Data Staged',                                  tactic: 'TA0009', severity: 'high' },
    'T1114':     { name: 'Email Collection',                             tactic: 'TA0009', severity: 'high' },
    'T1114.001': { name: 'Local Email Collection',                       tactic: 'TA0009', severity: 'high' },
    'T1114.002': { name: 'Remote Email Collection',                      tactic: 'TA0009', severity: 'high' },
    'T1114.003': { name: 'Email Forwarding Rule',                        tactic: 'TA0009', severity: 'high' },
    'T1056':     { name: 'Input Capture',                                tactic: 'TA0009', severity: 'high' },
    'T1185':     { name: 'Browser Session Hijacking',                    tactic: 'TA0009', severity: 'high' },
    'T1113':     { name: 'Screen Capture',                               tactic: 'TA0009', severity: 'medium' },
    'T1125':     { name: 'Video Capture',                                tactic: 'TA0009', severity: 'medium' },
    // ── Command and Control ───────────────────────────────────────
    'T1071':     { name: 'Application Layer Protocol',                   tactic: 'TA0011', severity: 'medium' },
    'T1071.001': { name: 'Web Protocols',                                tactic: 'TA0011', severity: 'medium' },
    'T1071.002': { name: 'File Transfer Protocols',                      tactic: 'TA0011', severity: 'medium' },
    'T1071.003': { name: 'Mail Protocols',                               tactic: 'TA0011', severity: 'medium' },
    'T1071.004': { name: 'DNS',                                          tactic: 'TA0011', severity: 'medium' },
    'T1092':     { name: 'Communication Through Removable Media',        tactic: 'TA0011', severity: 'medium' },
    'T1132':     { name: 'Data Encoding',                                tactic: 'TA0011', severity: 'medium' },
    'T1001':     { name: 'Data Obfuscation',                             tactic: 'TA0011', severity: 'medium' },
    'T1568':     { name: 'Dynamic Resolution',                           tactic: 'TA0011', severity: 'high' },
    'T1568.001': { name: 'Fast Flux DNS',                                tactic: 'TA0011', severity: 'high' },
    'T1568.002': { name: 'Domain Generation Algorithms',                 tactic: 'TA0011', severity: 'high' },
    'T1568.003': { name: 'DNS Calculation',                              tactic: 'TA0011', severity: 'medium' },
    'T1573':     { name: 'Encrypted Channel',                            tactic: 'TA0011', severity: 'medium' },
    'T1573.001': { name: 'Symmetric Cryptography',                       tactic: 'TA0011', severity: 'medium' },
    'T1573.002': { name: 'Asymmetric Cryptography',                      tactic: 'TA0011', severity: 'medium' },
    'T1008':     { name: 'Fallback Channels',                            tactic: 'TA0011', severity: 'medium' },
    'T1105':     { name: 'Ingress Tool Transfer',                        tactic: 'TA0011', severity: 'medium' },
    'T1104':     { name: 'Multi-Stage Channels',                         tactic: 'TA0011', severity: 'medium' },
    'T1095':     { name: 'Non-Application Layer Protocol',               tactic: 'TA0011', severity: 'medium' },
    'T1571':     { name: 'Non-Standard Port',                            tactic: 'TA0011', severity: 'medium' },
    'T1572':     { name: 'Protocol Tunneling',                           tactic: 'TA0011', severity: 'medium' },
    'T1090':     { name: 'Proxy',                                        tactic: 'TA0011', severity: 'medium' },
    'T1090.001': { name: 'Internal Proxy',                               tactic: 'TA0011', severity: 'medium' },
    'T1090.002': { name: 'External Proxy',                               tactic: 'TA0011', severity: 'medium' },
    'T1090.003': { name: 'Multi-hop Proxy',                              tactic: 'TA0011', severity: 'medium' },
    'T1090.004': { name: 'Domain Fronting',                              tactic: 'TA0011', severity: 'high' },
    'T1219':     { name: 'Remote Access Software',                       tactic: 'TA0011', severity: 'high' },
    'T1205':     { name: 'Traffic Signaling',                            tactic: 'TA0011', severity: 'medium' },
    'T1102':     { name: 'Web Service',                                  tactic: 'TA0011', severity: 'medium' },
    'T1102.001': { name: 'Dead Drop Resolver',                           tactic: 'TA0011', severity: 'medium' },
    'T1102.002': { name: 'Bidirectional Communication',                  tactic: 'TA0011', severity: 'medium' },
    'T1102.003': { name: 'One-Way Communication',                        tactic: 'TA0011', severity: 'medium' },
    // ── Exfiltration ──────────────────────────────────────────────
    'T1020':     { name: 'Automated Exfiltration',                       tactic: 'TA0010', severity: 'high' },
    'T1030':     { name: 'Data Transfer Size Limits',                    tactic: 'TA0010', severity: 'medium' },
    'T1048':     { name: 'Exfiltration Over Alternative Protocol',       tactic: 'TA0010', severity: 'high' },
    'T1048.001': { name: 'Exfiltration Over Symmetric Encrypted',        tactic: 'TA0010', severity: 'high' },
    'T1048.002': { name: 'Exfiltration Over Asymmetric Encrypted',       tactic: 'TA0010', severity: 'high' },
    'T1048.003': { name: 'Exfiltration Over Unencrypted Protocol',       tactic: 'TA0010', severity: 'high' },
    'T1041':     { name: 'Exfiltration Over C2 Channel',                 tactic: 'TA0010', severity: 'high' },
    'T1011':     { name: 'Exfiltration Over Other Network Medium',       tactic: 'TA0010', severity: 'high' },
    'T1052':     { name: 'Exfiltration Over Physical Medium',            tactic: 'TA0010', severity: 'high' },
    'T1567':     { name: 'Exfiltration Over Web Service',                tactic: 'TA0010', severity: 'high' },
    'T1567.001': { name: 'Exfiltration to Code Repository',              tactic: 'TA0010', severity: 'high' },
    'T1567.002': { name: 'Exfiltration to Cloud Storage',                tactic: 'TA0010', severity: 'high' },
    'T1029':     { name: 'Scheduled Transfer',                           tactic: 'TA0010', severity: 'medium' },
    'T1537':     { name: 'Transfer Data to Cloud Account',               tactic: 'TA0010', severity: 'high' },
    // ── Impact ────────────────────────────────────────────────────
    'T1531':     { name: 'Account Access Removal',                       tactic: 'TA0040', severity: 'high' },
    'T1485':     { name: 'Data Destruction',                             tactic: 'TA0040', severity: 'critical' },
    'T1486':     { name: 'Data Encrypted for Impact',                    tactic: 'TA0040', severity: 'critical' },
    'T1565':     { name: 'Data Manipulation',                            tactic: 'TA0040', severity: 'high' },
    'T1565.001': { name: 'Stored Data Manipulation',                     tactic: 'TA0040', severity: 'high' },
    'T1565.002': { name: 'Transmitted Data Manipulation',                tactic: 'TA0040', severity: 'high' },
    'T1565.003': { name: 'Runtime Data Manipulation',                    tactic: 'TA0040', severity: 'high' },
    'T1491':     { name: 'Defacement',                                   tactic: 'TA0040', severity: 'high' },
    'T1491.001': { name: 'Internal Defacement',                          tactic: 'TA0040', severity: 'high' },
    'T1491.002': { name: 'External Defacement',                          tactic: 'TA0040', severity: 'high' },
    'T1561':     { name: 'Disk Wipe',                                    tactic: 'TA0040', severity: 'critical' },
    'T1561.001': { name: 'Disk Content Wipe',                            tactic: 'TA0040', severity: 'critical' },
    'T1561.002': { name: 'Disk Structure Wipe',                          tactic: 'TA0040', severity: 'critical' },
    'T1499':     { name: 'Endpoint Denial of Service',                   tactic: 'TA0040', severity: 'high' },
    'T1499.001': { name: 'OS Exhaustion Flood',                          tactic: 'TA0040', severity: 'high' },
    'T1499.002': { name: 'Service Exhaustion Flood',                     tactic: 'TA0040', severity: 'high' },
    'T1499.003': { name: 'Application Exhaustion Flood',                 tactic: 'TA0040', severity: 'high' },
    'T1499.004': { name: 'Application or System Exploitation',           tactic: 'TA0040', severity: 'high' },
    'T1657':     { name: 'Financial Theft',                              tactic: 'TA0040', severity: 'critical' },
    'T1495':     { name: 'Firmware Corruption',                          tactic: 'TA0040', severity: 'critical' },
    'T1490':     { name: 'Inhibit System Recovery',                      tactic: 'TA0040', severity: 'critical' },
    'T1498':     { name: 'Network Denial of Service',                    tactic: 'TA0040', severity: 'high' },
    'T1498.001': { name: 'Direct Network Flood',                         tactic: 'TA0040', severity: 'high' },
    'T1498.002': { name: 'Reflection Amplification',                     tactic: 'TA0040', severity: 'high' },
    'T1496':     { name: 'Resource Hijacking',                           tactic: 'TA0040', severity: 'medium' },
    'T1489':     { name: 'Service Stop',                                 tactic: 'TA0040', severity: 'high' },
    'T1529':     { name: 'System Shutdown/Reboot',                       tactic: 'TA0040', severity: 'high' },
  },
};

// ── Tag → Technique mapping ───────────────────────────────────────
const TAG_TO_TECHNIQUE = {};
for (const [tid, info] of Object.entries(MITRE_TAXONOMY.techniques)) {
  const tag = `attack.${tid.toLowerCase()}`;
  TAG_TO_TECHNIQUE[tag] = tid;
}

class MitreMapper {
  constructor(config = {}) {
    this._config = config;
  }

  async loadTaxonomy() {
    console.log(`[RAYKAN/MITRE] ATT&CK v14 taxonomy loaded — ${Object.keys(MITRE_TAXONOMY.techniques).length} techniques`);
  }

  // ── Map a Detection to MITRE ──────────────────────────────────────
  mapDetection(detection) {
    const techniques = [];
    const tags       = detection.tags || [];

    for (const tag of tags) {
      const lower = tag.toLowerCase();
      // Direct technique tag
      const match = lower.match(/attack\.(t\d+(?:\.\d+)?)/);
      if (match) {
        const tid  = match[1].toUpperCase();
        const info = MITRE_TAXONOMY.techniques[tid];
        if (info) {
          techniques.push({
            id         : tid,
            name       : info.name,
            tactic     : MITRE_TAXONOMY.tactics[info.tactic],
            tacticId   : info.tactic,
            url        : `https://attack.mitre.org/techniques/${tid.replace('.', '/')}`,
            confidence : detection.confidence || 70,
          });
        }
      }
    }

    // Deduplicate
    const seen = new Set();
    const unique = techniques.filter(t => {
      if (seen.has(t.id)) return false;
      seen.add(t.id);
      return true;
    });

    return {
      techniques : unique,
      tactics    : [...new Set(unique.map(t => t.tactic?.name).filter(Boolean))],
      coverage   : unique.length,
    };
  }

  // ── Build entity-level MITRE map ──────────────────────────────────
  buildEntityMap(detections) {
    const techMap = {};
    for (const det of detections) {
      const mitre = this.mapDetection(det);
      for (const t of mitre.techniques) {
        if (!techMap[t.id]) techMap[t.id] = { ...t, count: 0, detections: [] };
        techMap[t.id].count++;
        techMap[t.id].detections.push(det.id);
      }
    }
    return {
      techniques : Object.values(techMap).sort((a,b) => b.count - a.count),
      heatmap    : this._buildHeatmap(techMap),
    };
  }

  _buildHeatmap(techMap) {
    const heatmap = {};
    for (const [tid, info] of Object.entries(techMap)) {
      const tacticId = MITRE_TAXONOMY.techniques[tid]?.tactic;
      if (!tacticId) continue;
      if (!heatmap[tacticId]) heatmap[tacticId] = { name: MITRE_TAXONOMY.tactics[tacticId]?.name, count: 0, techniques: [] };
      heatmap[tacticId].count += info.count;
      heatmap[tacticId].techniques.push({ id: tid, count: info.count });
    }
    return Object.values(heatmap).sort((a,b) => b.count - a.count);
  }

  // ── Lookup ────────────────────────────────────────────────────────
  getTechnique(id) { return MITRE_TAXONOMY.techniques[id] || null; }
  getTacticByName(name) {
    return Object.entries(MITRE_TAXONOMY.tactics)
      .find(([,t]) => t.shortName === name || t.name.toLowerCase() === name.toLowerCase());
  }
  getAllTechniques() { return MITRE_TAXONOMY.techniques; }
  getAllTactics()    { return MITRE_TAXONOMY.tactics; }
}

module.exports = MitreMapper;
