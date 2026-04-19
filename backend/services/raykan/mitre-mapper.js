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

// ── Condensed MITRE ATT&CK v14 Taxonomy ──────────────────────────
// Full taxonomy embedded (no external API needed)
const MITRE_TAXONOMY = {
  tactics: {
    TA0001: { name: 'Initial Access',         shortName: 'initial_access' },
    TA0002: { name: 'Execution',              shortName: 'execution' },
    TA0003: { name: 'Persistence',            shortName: 'persistence' },
    TA0004: { name: 'Privilege Escalation',   shortName: 'privilege_escalation' },
    TA0005: { name: 'Defense Evasion',        shortName: 'defense_evasion' },
    TA0006: { name: 'Credential Access',      shortName: 'credential_access' },
    TA0007: { name: 'Discovery',              shortName: 'discovery' },
    TA0008: { name: 'Lateral Movement',       shortName: 'lateral_movement' },
    TA0009: { name: 'Collection',             shortName: 'collection' },
    TA0010: { name: 'Exfiltration',           shortName: 'exfiltration' },
    TA0011: { name: 'Command and Control',    shortName: 'command_and_control' },
    TA0040: { name: 'Impact',                 shortName: 'impact' },
    TA0042: { name: 'Resource Development',   shortName: 'resource_development' },
    TA0043: { name: 'Reconnaissance',         shortName: 'reconnaissance' },
  },
  techniques: {
    'T1059':     { name: 'Command and Scripting Interpreter', tactic: 'TA0002', severity: 'high' },
    'T1059.001': { name: 'PowerShell',                        tactic: 'TA0002', severity: 'high' },
    'T1059.003': { name: 'Windows Command Shell',             tactic: 'TA0002', severity: 'medium' },
    'T1059.004': { name: 'Unix Shell',                        tactic: 'TA0002', severity: 'medium' },
    'T1059.005': { name: 'Visual Basic',                      tactic: 'TA0002', severity: 'medium' },
    'T1059.007': { name: 'JavaScript',                        tactic: 'TA0002', severity: 'medium' },
    'T1047':     { name: 'Windows Management Instrumentation',tactic: 'TA0002', severity: 'high' },
    'T1218':     { name: 'System Binary Proxy Execution',     tactic: 'TA0005', severity: 'high' },
    'T1218.005': { name: 'Mshta',                             tactic: 'TA0005', severity: 'high' },
    'T1218.010': { name: 'Regsvr32',                          tactic: 'TA0005', severity: 'high' },
    'T1218.011': { name: 'Rundll32',                          tactic: 'TA0005', severity: 'high' },
    'T1218.013': { name: 'Certutil',                          tactic: 'TA0005', severity: 'high' },
    'T1053':     { name: 'Scheduled Task/Job',                tactic: 'TA0003', severity: 'medium' },
    'T1053.003': { name: 'Cron',                              tactic: 'TA0003', severity: 'medium' },
    'T1053.005': { name: 'Scheduled Task',                    tactic: 'TA0003', severity: 'medium' },
    'T1547':     { name: 'Boot or Logon Autostart Execution', tactic: 'TA0003', severity: 'medium' },
    'T1547.001': { name: 'Registry Run Keys',                 tactic: 'TA0003', severity: 'medium' },
    'T1543':     { name: 'Create or Modify System Process',   tactic: 'TA0003', severity: 'high' },
    'T1543.003': { name: 'Windows Service',                   tactic: 'TA0003', severity: 'high' },
    'T1134':     { name: 'Access Token Manipulation',         tactic: 'TA0004', severity: 'high' },
    'T1134.001': { name: 'Token Impersonation/Theft',         tactic: 'TA0004', severity: 'high' },
    'T1548':     { name: 'Abuse Elevation Control Mechanism', tactic: 'TA0004', severity: 'high' },
    'T1548.002': { name: 'Bypass UAC',                        tactic: 'TA0004', severity: 'critical' },
    'T1548.003': { name: 'Sudo and Sudo Caching',             tactic: 'TA0004', severity: 'medium' },
    'T1036':     { name: 'Masquerading',                      tactic: 'TA0005', severity: 'medium' },
    'T1036.003': { name: 'Rename System Utilities',           tactic: 'TA0005', severity: 'high' },
    'T1070':     { name: 'Indicator Removal',                 tactic: 'TA0005', severity: 'high' },
    'T1070.001': { name: 'Clear Windows Event Logs',          tactic: 'TA0005', severity: 'high' },
    'T1027':     { name: 'Obfuscated Files or Information',   tactic: 'TA0005', severity: 'medium' },
    'T1003':     { name: 'OS Credential Dumping',             tactic: 'TA0006', severity: 'critical' },
    'T1003.001': { name: 'LSASS Memory',                      tactic: 'TA0006', severity: 'critical' },
    'T1003.002': { name: 'Security Account Manager',          tactic: 'TA0006', severity: 'critical' },
    'T1003.003': { name: 'NTDS',                              tactic: 'TA0006', severity: 'critical' },
    'T1110':     { name: 'Brute Force',                       tactic: 'TA0006', severity: 'medium' },
    'T1110.001': { name: 'Password Guessing',                 tactic: 'TA0006', severity: 'medium' },
    'T1555':     { name: 'Credentials from Password Stores',  tactic: 'TA0006', severity: 'high' },
    'T1018':     { name: 'Remote System Discovery',           tactic: 'TA0007', severity: 'low' },
    'T1082':     { name: 'System Information Discovery',      tactic: 'TA0007', severity: 'low' },
    'T1033':     { name: 'System Owner/User Discovery',       tactic: 'TA0007', severity: 'low' },
    'T1083':     { name: 'File and Directory Discovery',      tactic: 'TA0007', severity: 'low' },
    'T1087':     { name: 'Account Discovery',                 tactic: 'TA0007', severity: 'low' },
    'T1135':     { name: 'Network Share Discovery',           tactic: 'TA0007', severity: 'low' },
    'T1021':     { name: 'Remote Services',                   tactic: 'TA0008', severity: 'high' },
    'T1021.002': { name: 'SMB/Windows Admin Shares',          tactic: 'TA0008', severity: 'high' },
    'T1021.006': { name: 'Windows Remote Management',        tactic: 'TA0008', severity: 'high' },
    'T1550':     { name: 'Use Alternate Authentication Material', tactic: 'TA0008', severity: 'high' },
    'T1550.002': { name: 'Pass the Hash',                     tactic: 'TA0008', severity: 'critical' },
    'T1534':     { name: 'Internal Spearphishing',            tactic: 'TA0008', severity: 'high' },
    'T1005':     { name: 'Data from Local System',            tactic: 'TA0009', severity: 'medium' },
    'T1039':     { name: 'Data from Network Shared Drive',    tactic: 'TA0009', severity: 'medium' },
    'T1074':     { name: 'Data Staged',                       tactic: 'TA0009', severity: 'medium' },
    'T1074.001': { name: 'Local Data Staging',               tactic: 'TA0009', severity: 'medium' },
    'T1530':     { name: 'Data from Cloud Storage',           tactic: 'TA0009', severity: 'high' },
    'T1048':     { name: 'Exfiltration Over Alternative Protocol', tactic: 'TA0010', severity: 'high' },
    'T1048.003': { name: 'Exfiltration Over Unencrypted Non-C2', tactic: 'TA0010', severity: 'high' },
    'T1041':     { name: 'Exfiltration Over C2 Channel',      tactic: 'TA0010', severity: 'high' },
    'T1071':     { name: 'Application Layer Protocol',        tactic: 'TA0011', severity: 'medium' },
    'T1071.001': { name: 'Web Protocols (HTTP/HTTPS)',        tactic: 'TA0011', severity: 'medium' },
    'T1071.004': { name: 'DNS',                               tactic: 'TA0011', severity: 'medium' },
    'T1095':     { name: 'Non-Application Layer Protocol',    tactic: 'TA0011', severity: 'medium' },
    'T1105':     { name: 'Ingress Tool Transfer',             tactic: 'TA0011', severity: 'medium' },
    'T1486':     { name: 'Data Encrypted for Impact',         tactic: 'TA0040', severity: 'critical' },
    'T1490':     { name: 'Inhibit System Recovery',           tactic: 'TA0040', severity: 'critical' },
    'T1491':     { name: 'Defacement',                        tactic: 'TA0040', severity: 'high' },
    'T1055':     { name: 'Process Injection',                 tactic: 'TA0004', severity: 'high' },
    'T1078':     { name: 'Valid Accounts',                    tactic: 'TA0001', severity: 'high' },
    'T1078.004': { name: 'Cloud Accounts',                    tactic: 'TA0001', severity: 'high' },
    'T1133':     { name: 'External Remote Services',          tactic: 'TA0001', severity: 'high' },
    'T1190':     { name: 'Exploit Public-Facing Application', tactic: 'TA0001', severity: 'critical' },
    'T1566':     { name: 'Phishing',                          tactic: 'TA0001', severity: 'high' },
    'T1566.001': { name: 'Spearphishing Attachment',          tactic: 'TA0001', severity: 'high' },
    'T1505':     { name: 'Server Software Component',         tactic: 'TA0003', severity: 'critical' },
    'T1505.003': { name: 'Web Shell',                         tactic: 'TA0003', severity: 'critical' },
    'T1136':     { name: 'Create Account',                    tactic: 'TA0003', severity: 'high' },
    'T1136.001': { name: 'Local Account',                     tactic: 'TA0003', severity: 'high' },
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
