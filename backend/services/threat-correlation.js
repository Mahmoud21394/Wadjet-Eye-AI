/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — Threat Correlation Engine  v1.0
 *
 *  Correlates: CVE ↔ MITRE Techniques ↔ Detection Rules ↔ Tools
 *
 *  Capabilities:
 *   ✅ correlate(input)     — unified correlation from any input
 *   ✅ correlateByTool(t)   — find CVEs + techniques for a specific tool
 *   ✅ buildThreatChain()   — construct complete attack chain
 *   ✅ riskScore()          — composite risk scoring
 *   ✅ getHighRiskMap()     — dashboard-ready risk map
 *   ✅ generateHuntingHypothesis() — SOC threat hunting starter
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { defaultDB }     = require('./intel-db');
const { defaultEngine } = require('./detection-engine');

// ─────────────────────────────────────────────────────────────────────────────
//  TOOL → TECHNIQUE MAPPING
// ─────────────────────────────────────────────────────────────────────────────
const TOOL_MAP = {
  'powershell.exe':  ['T1059.001','T1027','T1086','T1548.002'],
  'pwsh.exe':        ['T1059.001'],
  'cmd.exe':         ['T1059.003','T1027'],
  'mshta.exe':       ['T1059','T1218.005'],
  'wscript.exe':     ['T1059','T1204'],
  'cscript.exe':     ['T1059'],
  'regsvr32.exe':    ['T1218.010','T1055'],
  'rundll32.exe':    ['T1218.011','T1055'],
  'certutil.exe':    ['T1140','T1105'],
  'bitsadmin.exe':   ['T1197','T1105'],
  'schtasks.exe':    ['T1053.005'],
  'at.exe':          ['T1053.002'],
  'reg.exe':         ['T1547.001','T1112'],
  'regedit.exe':     ['T1547.001','T1112'],
  'net.exe':         ['T1069','T1082','T1021.002'],
  'net1.exe':        ['T1069','T1082'],
  'nltest.exe':      ['T1482'],
  'ipconfig.exe':    ['T1082'],
  'whoami.exe':      ['T1033'],
  'systeminfo.exe':  ['T1082'],
  'tasklist.exe':    ['T1057'],
  'psexec.exe':      ['T1021.002','T1035'],
  'wmic.exe':        ['T1047','T1490'],
  'mimikatz.exe':    ['T1003','T1055'],
  'procdump.exe':    ['T1003'],
  'ntdsutil.exe':    ['T1003.003'],
  'vssadmin.exe':    ['T1490','T1003.003'],
  'bcdedit.exe':     ['T1490'],
  'wbadmin.exe':     ['T1490'],
  'msiexec.exe':     ['T1218.007'],
  'msdt.exe':        ['T1203'],
  'winword.exe':     ['T1566.001'],
  'excel.exe':       ['T1566.001'],
  'powerpnt.exe':    ['T1566.001'],
  'outlook.exe':     ['T1566'],
  'nmap':            ['T1046'],
  'masscan':         ['T1046'],
  'mstsc.exe':       ['T1021.001'],
  'putty.exe':       ['T1021.004'],
  'sqlmap':          ['T1190'],
  'metasploit':      ['T1190','T1059','T1055'],
  'cobalt strike':   ['T1071.001','T1055','T1059.001','T1547'],
  'meterpreter':     ['T1055','T1059.001','T1082'],
};

// ─────────────────────────────────────────────────────────────────────────────
//  ATTACK CHAIN TEMPLATES
// ─────────────────────────────────────────────────────────────────────────────
const ATTACK_CHAINS = {
  ransomware: {
    name: 'Ransomware Attack Chain',
    description: 'Common ransomware attack pattern observed in LockBit, BlackCat, Cl0p operations',
    phases: [
      { phase: 'Initial Access', technique: 'T1190', tool: 'sqlmap/exploit', description: 'Exploit public-facing application or phishing email' },
      { phase: 'Execution', technique: 'T1059.001', tool: 'powershell.exe', description: 'Execute PowerShell payload to establish foothold' },
      { phase: 'Persistence', technique: 'T1053.005', tool: 'schtasks.exe', description: 'Create scheduled task for persistent access' },
      { phase: 'Privilege Escalation', technique: 'T1055', tool: 'mimikatz.exe', description: 'Process injection for SYSTEM privileges' },
      { phase: 'Defense Evasion', technique: 'T1027', tool: 'powershell.exe', description: 'Obfuscate payloads with Base64 encoding' },
      { phase: 'Credential Access', technique: 'T1003', tool: 'mimikatz.exe', description: 'Dump LSASS credentials for lateral movement' },
      { phase: 'Discovery', technique: 'T1082', tool: 'systeminfo.exe/net.exe', description: 'Enumerate network, systems, and domain info' },
      { phase: 'Lateral Movement', technique: 'T1021.002', tool: 'psexec.exe', description: 'Move laterally via SMB/admin shares' },
      { phase: 'Collection', technique: 'T1074', tool: 'robocopy/rclone', description: 'Stage data for exfiltration' },
      { phase: 'Exfiltration', technique: 'T1048', tool: 'rclone/MEGASync', description: 'Exfiltrate to cloud storage (double extortion)' },
      { phase: 'Impact', technique: 'T1490', tool: 'vssadmin.exe', description: 'Delete shadow copies to prevent recovery' },
      { phase: 'Impact', technique: 'T1486', tool: 'ransomware binary', description: 'Encrypt files across all accessible systems' },
    ],
    iocs: ['vssadmin.exe delete shadows', 'bcdedit /set recoveryenabled no', 'wmic shadowcopy delete'],
    detection_priority: ['T1490','T1486','T1003','T1059.001'],
  },
  apt_espionage: {
    name: 'APT Espionage Campaign',
    description: 'Nation-state espionage pattern (APT29, APT40 style)',
    phases: [
      { phase: 'Initial Access', technique: 'T1566.001', tool: 'malicious_doc', description: 'Spearphishing with weaponized document' },
      { phase: 'Execution', technique: 'T1059.001', tool: 'powershell.exe', description: 'Macro-launched PowerShell stager' },
      { phase: 'Persistence', technique: 'T1547.001', tool: 'reg.exe', description: 'Registry run key for persistence' },
      { phase: 'Defense Evasion', technique: 'T1027', tool: 'powershell.exe', description: 'Obfuscated payloads and living-off-the-land' },
      { phase: 'C2 Communication', technique: 'T1071.001', tool: 'Cobalt Strike/Sliver', description: 'HTTPS C2 beacon to actor infrastructure' },
      { phase: 'Discovery', technique: 'T1082', tool: 'net.exe/nltest.exe', description: 'Domain/network reconnaissance' },
      { phase: 'Credential Access', technique: 'T1003', tool: 'mimikatz.exe', description: 'Credential harvesting from LSASS' },
      { phase: 'Lateral Movement', technique: 'T1021.001', tool: 'mstsc.exe', description: 'RDP lateral movement with stolen credentials' },
      { phase: 'Collection', technique: 'T1114', tool: 'PowerShell', description: 'Email and document collection' },
      { phase: 'Exfiltration', technique: 'T1041', tool: 'HTTPS channel', description: 'Exfil via established C2 channel' },
    ],
    iocs: ['-encodedcommand', 'regsvr32 /s /n /u /i:http', 'rundll32 advpack.dll'],
    detection_priority: ['T1566.001','T1059.001','T1071.001','T1003'],
  },
  supply_chain: {
    name: 'Software Supply Chain Attack',
    description: 'Supply chain compromise (SolarWinds/3CX style)',
    phases: [
      { phase: 'Initial Compromise', technique: 'T1195', tool: 'build_system', description: 'Compromise software build pipeline' },
      { phase: 'Trojanized Update', technique: 'T1195.002', tool: 'update_server', description: 'Trojanized software update distributed' },
      { phase: 'Execution', technique: 'T1059.001', tool: 'legitimate_binary', description: 'Malicious code runs via trusted process' },
      { phase: 'Persistence', technique: 'T1547.001', tool: 'registry', description: 'Persistence via legitimate software services' },
      { phase: 'C2', technique: 'T1071.001', tool: 'HTTPS', description: 'C2 mimicking legitimate software traffic' },
      { phase: 'Discovery', technique: 'T1082', tool: 'built-in tools', description: 'Quiet environment reconnaissance' },
      { phase: 'Lateral Movement', technique: 'T1021.002', tool: 'SMB', description: 'Silent lateral movement over months' },
      { phase: 'Exfiltration', technique: 'T1048', tool: 'covert channel', description: 'Low-and-slow data theft over months' },
    ],
    iocs: ['sunburst', 'teardrop', '*.avsvmcloud.com'],
    detection_priority: ['T1195.002','T1071.001','T1059.001'],
  },
  insider_threat: {
    name: 'Malicious Insider Threat',
    description: 'Insider data theft scenario',
    phases: [
      { phase: 'Reconnaissance', technique: 'T1078', tool: 'valid credentials', description: 'Legitimate access escalated beyond normal scope' },
      { phase: 'Collection', technique: 'T1074', tool: 'USB/cloud', description: 'Mass data staging for exfiltration' },
      { phase: 'Exfiltration', technique: 'T1052', tool: 'USB drive', description: 'Physical or cloud-based exfiltration' },
    ],
    iocs: ['bulk downloads', 'off-hours access', 'USB insertion'],
    detection_priority: ['T1078','T1114','T1048'],
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  THREAT CORRELATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────
class ThreatCorrelationEngine {
  constructor() {
    this.version = '1.0';
    this.db = defaultDB;
    this.detectionEngine = defaultEngine;
  }

  // ── Main correlation entry point ──────────────────────────────────────────
  correlate(input) {
    if (!input) return { error: 'No input provided' };
    const s = input.toString().trim();

    // Detect input type
    if (/^CVE-\d{4}-\d+$/i.test(s)) return this.correlateByCV(s.toUpperCase());
    if (/^T\d{4}(\.\d{3})?$/i.test(s)) return this.correlateByMITRE(s.toUpperCase());
    if (/\.(exe|dll|ps1|bat|vbs)$/i.test(s)) return this.correlateByTool(s.toLowerCase());
    // keyword — find best match
    return this.correlateByKeyword(s);
  }

  // ── Correlate by CVE ─────────────────────────────────────────────────────
  correlateByCV(cveId) {
    const cve = this.db.getCVE(cveId);
    if (!cve) {
      return {
        input: cveId, type: 'cve', found: false,
        message: `${cveId} not in local database. Query NVD: https://nvd.nist.gov/vuln/detail/${cveId}`
      };
    }
    const techniques = this.db.getTechniquesForCVE(cveId);
    const detections = techniques.map(t => {
      const d = this.detectionEngine.generateAll(t.id);
      return d.found === false ? null : { technique: t.id, name: t.name, sigma: d.sigma, kql: d.kql };
    }).filter(Boolean);

    return {
      input: cveId, type: 'cve',
      cve: {
        id: cve.id, description: cve.description,
        severity: cve.severity, cvss: cve.cvss_score,
        exploited: cve.exploited, vendor: cve.vendor,
        mitigation: cve.mitigation,
      },
      techniques: techniques.map(t => ({ id: t.id, name: t.name, tactic: t.tactic })),
      detections,
      riskScore: this._riskScore(cve),
      formatted: this.db.formatCVEForSOC(cveId),
    };
  }

  // ── Correlate by MITRE technique ──────────────────────────────────────────
  correlateByMITRE(techniqueId) {
    const technique = this.db.getMITRE(techniqueId);
    const cves = this.db.getCVEsForTechnique(techniqueId);
    const detection = this.detectionEngine.generateAll(techniqueId);
    const tools = this._toolsForTechnique(techniqueId);

    return {
      input: techniqueId, type: 'mitre',
      technique: technique || { id: techniqueId, name: 'See MITRE ATT&CK', url: `https://attack.mitre.org/techniques/${techniqueId.replace('.','/').replace('T','T')}/` },
      cves: cves.map(c => ({ id: c.id, cvss: c.cvss_score, exploited: c.exploited, severity: c.severity })),
      detection: detection.found === false ? { available: false, suggestion: detection.suggestion } : {
        available: true, sigma: detection.sigma, kql: detection.kql, spl: detection.spl,
      },
      tools,
      riskScore: this._riskScoreForTechnique(techniqueId, cves),
      formatted: this.db.formatMITREForSOC(techniqueId),
    };
  }

  // ── Correlate by tool name ────────────────────────────────────────────────
  correlateByTool(toolName) {
    const techniques = (TOOL_MAP[toolName.toLowerCase()] || []);
    if (!techniques.length) {
      return {
        input: toolName, type: 'tool', found: false,
        message: `No specific correlation for tool "${toolName}". Consider reviewing process creation logs.`
      };
    }

    const techniqueDetails = techniques.map(id => {
      const t = this.db.getMITRE(id);
      const d = this.detectionEngine.getTechniqueInfo(id);
      return { id, name: t ? t.name : id, tactic: t ? t.tactic : '', hasDetection: !!d };
    });

    const allCVEs = [...new Set(techniques.flatMap(id => {
      const cves = this.db.getCVEsForTechnique(id);
      return cves.map(c => c.id);
    }))].map(id => this.db.getCVE(id)).filter(Boolean);

    return {
      input: toolName, type: 'tool',
      tool: toolName,
      techniques: techniqueDetails,
      cves: allCVEs.map(c => ({ id: c.id, cvss: c.cvss_score, exploited: c.exploited })),
      riskLevel: techniques.some(t => ['T1003','T1055','T1486'].includes(t)) ? 'CRITICAL' :
                 techniques.some(t => ['T1059.001','T1190','T1003'].includes(t)) ? 'HIGH' : 'MEDIUM',
    };
  }

  // ── Correlate by keyword ──────────────────────────────────────────────────
  correlateByKeyword(keyword) {
    const kw = keyword.toLowerCase();
    const cves = this.db.searchCVEs({ keyword: kw, limit: 5 });
    const techniques = this.db.searchMITRE({ keyword: kw, limit: 5 });
    const tools = Object.entries(TOOL_MAP)
      .filter(([t]) => t.toLowerCase().includes(kw))
      .map(([t, techs]) => ({ tool: t, techniques: techs }));

    // Check attack chains
    const chains = Object.entries(ATTACK_CHAINS)
      .filter(([k, v]) =>
        k.includes(kw) || v.name.toLowerCase().includes(kw) ||
        v.description.toLowerCase().includes(kw)
      ).map(([k, v]) => ({ id: k, name: v.name }));

    return {
      input: keyword, type: 'keyword',
      cves: cves.map(c => ({ id: c.id, severity: c.severity, exploited: c.exploited, cvss: c.cvss_score })),
      techniques: techniques.map(t => ({ id: t.id, name: t.name, tactic: t.tactic })),
      tools: tools.slice(0, 5),
      attackChains: chains,
      count: { cves: cves.length, techniques: techniques.length, tools: tools.length },
    };
  }

  // ── Build attack chain ────────────────────────────────────────────────────
  buildAttackChain(scenario) {
    const key = scenario.toLowerCase();
    for (const [k, chain] of Object.entries(ATTACK_CHAINS)) {
      if (key.includes(k.replace('_',' ')) || key.includes(k)) {
        return this._enrichChain(chain);
      }
    }
    // fuzzy match
    if (key.includes('ransom')) return this._enrichChain(ATTACK_CHAINS.ransomware);
    if (key.includes('apt') || key.includes('espionage') || key.includes('nation')) return this._enrichChain(ATTACK_CHAINS.apt_espionage);
    if (key.includes('supply') || key.includes('solarwind')) return this._enrichChain(ATTACK_CHAINS.supply_chain);
    if (key.includes('insider')) return this._enrichChain(ATTACK_CHAINS.insider_threat);
    return null;
  }

  _enrichChain(chain) {
    return {
      ...chain,
      phases: chain.phases.map(phase => ({
        ...phase,
        detection: this.detectionEngine.getTechniqueInfo(phase.technique),
        cves: this.db.getCVEsForTechnique(phase.technique)
          .filter(c => c.exploited)
          .map(c => ({ id: c.id, cvss: c.cvss_score })),
      }))
    };
  }

  // ── High risk map ─────────────────────────────────────────────────────────
  getHighRiskMap() {
    const exploitedCVEs = this.db.getExploitedCVEs(10);
    const criticalTechniques = this.db.searchMITRE({ severity: 'critical', limit: 10 });
    return {
      exploitedCVEs: exploitedCVEs.map(c => ({
        id: c.id, vendor: c.vendor, cvss: c.cvss_score,
        exploited: c.exploited, severity: c.severity,
        published: c.published_date,
      })),
      criticalTechniques: criticalTechniques.map(t => ({
        id: t.id, name: t.name, tactic: t.tactic,
      })),
      totalExploited: exploitedCVEs.length,
      lastUpdated: new Date().toISOString(),
    };
  }

  // ── Hunting hypothesis ────────────────────────────────────────────────────
  generateHuntingHypothesis(topic) {
    const correlation = this.correlate(topic);
    const techniqueIds = correlation.techniques
      ? correlation.techniques.map(t => t.id || t)
      : [];

    const hypotheses = techniqueIds.map(tid => {
      const t = this.db.getMITRE(tid);
      const name = t ? t.name : tid;
      return `- **Hypothesis**: Adversary used ${name} (${tid}) to ${t ? t.description.substring(0,80) + '...' : 'execute attack objective'}`;
    });

    return {
      topic,
      hypotheses: hypotheses.length ? hypotheses : [
        `- **Hypothesis**: Investigate ${topic}-related activity in process creation and network logs`,
        `- Look for: suspicious parent-child process relationships, encoded command lines, outbound connections to new domains`,
      ],
      hunting_queries: techniqueIds.slice(0,3).map(id => {
        const kql = this.detectionEngine.generateKQL(id);
        return kql.found === false ? null : { technique: id, kql: kql.content };
      }).filter(Boolean),
      recommendation: `Start with high-fidelity indicators, then expand to behavioral patterns. Use ATT&CK Navigator to identify detection coverage gaps.`,
    };
  }

  // ── Private helpers ───────────────────────────────────────────────────────
  _riskScore(cve) {
    let score = cve.cvss_score * 10;
    if (cve.exploited) score += 20;
    if (cve.severity === 'critical') score += 10;
    const daysSince = (Date.now() - new Date(cve.published_date).getTime()) / 86400000;
    if (daysSince < 30) score += 10;
    return Math.min(Math.round(score), 100);
  }

  _riskScoreForTechnique(id, relatedCVEs) {
    let score = 50;
    const exploited = relatedCVEs.filter(c => c.exploited).length;
    score += exploited * 10;
    const critical = relatedCVEs.filter(c => c.severity === 'critical').length;
    score += critical * 5;
    if (['T1003','T1055','T1486','T1190'].includes(id)) score += 20;
    return Math.min(Math.round(score), 100);
  }

  _toolsForTechnique(techniqueId) {
    return Object.entries(TOOL_MAP)
      .filter(([, techs]) => techs.includes(techniqueId))
      .map(([tool]) => tool);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
const defaultCorrelator = new ThreatCorrelationEngine();

module.exports = {
  ThreatCorrelationEngine,
  defaultCorrelator,
  TOOL_MAP,
  ATTACK_CHAINS,
  correlate:                (input)    => defaultCorrelator.correlate(input),
  correlateByTool:          (tool)     => defaultCorrelator.correlateByTool(tool),
  buildAttackChain:         (scenario) => defaultCorrelator.buildAttackChain(scenario),
  getHighRiskMap:           ()         => defaultCorrelator.getHighRiskMap(),
  generateHuntingHypothesis:(topic)    => defaultCorrelator.generateHuntingHypothesis(topic),
};
