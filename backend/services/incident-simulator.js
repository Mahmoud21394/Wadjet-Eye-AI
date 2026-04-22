/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Incident Simulator  v1.0
 *  backend/services/incident-simulator.js
 *
 *  Generates realistic SOC incident simulations for training,
 *  tabletop exercises, and detection validation.
 *  No external API calls — pure in-memory simulation engine.
 *
 *  Public API (used by soc-intelligence routes):
 *   simulator.simulate(scenario, options) → simulation result
 *   simulator.formatForSOC(result)        → markdown report
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Scenario templates ────────────────────────────────────────────
const SCENARIOS = {
  ransomware: {
    name: 'Ransomware Attack',
    actor: 'LockBit 3.0',
    severity: 'CRITICAL',
    phases: [
      { phase: 'Initial Access', technique: 'T1566', description: 'Spear-phishing email with malicious .docm attachment delivered to finance department.' },
      { phase: 'Execution',      technique: 'T1059', description: 'Macro executes PowerShell to download second-stage payload from C2 server.' },
      { phase: 'Persistence',    technique: 'T1078', description: 'Adversary creates local admin account "svc_backup" for persistence.' },
      { phase: 'Defense Evasion',technique: 'T1553', description: 'Disables Windows Defender via registry modification and GPO.' },
      { phase: 'Lateral Movement',technique:'T1021', description: 'SMB lateral movement to file servers using stolen domain credentials.' },
      { phase: 'Exfiltration',   technique: 'T1071', description: '78 GB of data exfiltrated to Mega.nz over encrypted channel (double extortion).' },
      { phase: 'Impact',         technique: 'T1486', description: 'LockBit ransomware encrypts 1,247 systems. Ransom note demands $4.2M in Bitcoin.' },
    ],
    timeline_hours: 72,
    affected_systems: ['FILE-SRV-01', 'FILE-SRV-02', 'DC-01 (partial)', 'ALL-WORKSTATIONS'],
    iocs: [
      { type: 'hash_sha256', value: 'a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef12345678' },
      { type: 'ip',    value: '185.220.101.47' },
      { type: 'domain',value: 'lock3bit-decrypt.onion' },
      { type: 'url',   value: 'https://mega.nz/file/exfil-path' },
    ],
    response_actions: [
      'Immediately isolate affected network segments at the switch level',
      'Disable SMB shares and block lateral movement paths (port 445)',
      'Snapshot all running VMs for forensic preservation',
      'Engage incident response retainer',
      'Notify legal team for ransom payment assessment and regulatory disclosure',
      'Initiate backup restoration from offline/immutable backup copies',
      'Reset ALL privileged account credentials',
    ],
    lessons_learned: [
      'Macro execution was not disabled in Office settings',
      'No email sandboxing to detonate malicious attachments',
      'Backups were online and connected — also encrypted',
      'Lateral movement went undetected for 48h due to gaps in EDR coverage',
    ],
  },

  phishing: {
    name: 'Business Email Compromise (BEC)',
    actor: 'Scattered Spider',
    severity: 'HIGH',
    phases: [
      { phase: 'Reconnaissance', technique: 'T1591', description: 'Threat actor researches company org chart via LinkedIn to identify CFO and finance team.' },
      { phase: 'Initial Access',  technique: 'T1566', description: 'Spear-phishing email spoofing CEO sent to CFO requesting urgent wire transfer.' },
      { phase: 'Execution',       technique: 'T1059', description: 'CFO opens attachment, macro executes credential harvester.' },
      { phase: 'Credential Access',technique:'T1187', description: 'Harvested VPN credentials allow adversary to access internal systems.' },
      { phase: 'Collection',      technique: 'T1078', description: 'Adversary accesses email and financial systems using legitimate CFO credentials.' },
      { phase: 'Exfiltration',    technique: 'T1071', description: 'Adversary monitors email for 2 weeks before initiating fraudulent $2.3M wire transfer.' },
    ],
    timeline_hours: 336,
    affected_systems: ['CFO-LAPTOP', 'EXCHANGE-SERVER', 'BANKING-PORTAL'],
    iocs: [
      { type: 'email',  value: 'ceo-urgent@company-inc.net' },
      { type: 'ip',     value: '45.142.212.100' },
      { type: 'domain', value: 'company-inc.net' },
    ],
    response_actions: [
      'Contact bank immediately to recall wire transfer',
      'Reset all executive account credentials and MFA tokens',
      'Implement email authentication (DMARC/DKIM/SPF) immediately',
      'Enable conditional access policies for all privileged accounts',
      'Notify FBI IC3 and file insurance claim',
      'Audit all financial transactions in the past 30 days',
    ],
    lessons_learned: [
      'No MFA on executive accounts allowed credential reuse',
      'Wire transfer approval process had no secondary verification',
      'DMARC not enforced — domain spoofing was trivial',
      'No email sandbox to catch credential harvester',
    ],
  },

  'supply-chain': {
    name: 'Supply Chain Compromise',
    actor: 'APT29 (Cozy Bear)',
    severity: 'CRITICAL',
    phases: [
      { phase: 'Initial Access',  technique: 'T1195', description: 'Adversary compromises software vendor build system, injecting backdoor into update package.' },
      { phase: 'Execution',       technique: 'T1059', description: 'Trojanized software update auto-installs on 8,000 enterprise systems.' },
      { phase: 'Persistence',     technique: 'T1078', description: 'SUNBURST malware establishes persistence via Windows service.' },
      { phase: 'Defense Evasion', technique: 'T1553', description: 'Signed binary bypasses code signing checks — certificate stolen from legitimate vendor.' },
      { phase: 'Discovery',       technique: 'T1082', description: 'Adversary performs extensive environment discovery before activating payload.' },
      { phase: 'C2',              technique: 'T1071', description: 'Beacon to DNS C2 via subdomains of legitimate-looking domain (avsvmcloud.com pattern).' },
      { phase: 'Exfiltration',    technique: 'T1048', description: 'Selective exfiltration of email, source code, and network diagrams over 9 months.' },
    ],
    timeline_hours: 6552,
    affected_systems: ['ALL-CORPORATE-SYSTEMS', 'CLOUD-INFRASTRUCTURE', 'EMAIL-SERVERS'],
    iocs: [
      { type: 'hash_sha256', value: 'dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b' },
      { type: 'domain',      value: 'avsvmcloud.com' },
      { type: 'ip',          value: '13.57.184.217' },
    ],
    response_actions: [
      'Isolate all systems running affected software version',
      'Rotate all secrets, certificates, and API keys',
      'Audit all privileged access granted in past 12 months',
      'Block all DNS requests to identified C2 domains',
      'Notify affected customers and partners per contractual obligations',
      'Engage specialized supply chain forensics team',
    ],
    lessons_learned: [
      'No hash verification of software updates allowed trojanized binary to install',
      'DNS monitoring did not alert on abnormal subdomain query patterns',
      'Extended dwell time (9 months) due to lack of behavioral detection',
      'Vendor security assessments did not include build pipeline security',
    ],
  },

  'insider-threat': {
    name: 'Malicious Insider — Data Theft',
    actor: 'Malicious Employee (Privilege Abuse)',
    severity: 'HIGH',
    phases: [
      { phase: 'Collection',  technique: 'T1078', description: 'Disgruntled sysadmin uses legitimate elevated credentials to access sensitive repositories.' },
      { phase: 'Collection',  technique: 'T1213', description: 'Copies 45,000 customer records and IP source code to personal OneDrive account.' },
      { phase: 'Exfiltration',technique: 'T1048', description: 'Uploads compressed archives to personal cloud storage over 3 days.' },
    ],
    timeline_hours: 72,
    affected_systems: ['SOURCE-REPO', 'CRM-DATABASE', 'SHAREPOINT'],
    iocs: [
      { type: 'ip',  value: '192.168.1.45 (internal)' },
      { type: 'url', value: 'https://onedrive.live.com/upload-endpoint' },
    ],
    response_actions: [
      'Immediately suspend user account and badge access',
      'Preserve all logs and evidence without alerting the employee',
      'Engage HR and legal before confronting the employee',
      'Notify affected customers if PII was exfiltrated (regulatory requirement)',
      'Audit all user activity for past 90 days',
      'Review and enforce DLP (Data Loss Prevention) policies',
    ],
    lessons_learned: [
      'No DLP solution to detect mass data downloads',
      'Excessive privilege — sysadmin had access to CRM without business need',
      'No UEBA alerting on anomalous upload volume to cloud storage',
    ],
  },

  'apt-espionage': {
    name: 'APT Nation-State Espionage',
    actor: 'APT28 (Fancy Bear)',
    severity: 'CRITICAL',
    phases: [
      { phase: 'Initial Access',   technique: 'T1190', description: 'Exploit CVE-2024-3400 in unpatched Palo Alto GlobalProtect VPN gateway.' },
      { phase: 'Execution',        technique: 'T1059', description: 'Deploy webshell and execute system enumeration scripts.' },
      { phase: 'Credential Access',technique: 'T1078', description: 'Dump LSASS to harvest Kerberos tickets and NTLM hashes.' },
      { phase: 'Lateral Movement', technique: 'T1210', description: 'Pass-the-Ticket attack to access domain controllers.' },
      { phase: 'Collection',       technique: 'T1213', description: 'Target diplomatic cables, strategic plans, and personnel files.' },
      { phase: 'C2',               technique: 'T1071', description: 'Encrypted C2 over HTTPS mimicking legitimate cloud storage traffic.' },
      { phase: 'Exfiltration',     technique: 'T1048', description: 'Slow exfiltration (< 1 MB/day) to blend with normal traffic.' },
    ],
    timeline_hours: 2160,
    affected_systems: ['VPN-GW-01', 'DC-01', 'DC-02', 'CLASSIFIED-STORAGE'],
    iocs: [
      { type: 'ip',     value: '91.108.4.226' },
      { type: 'domain', value: 'update-microsoft-cdn.com' },
      { type: 'hash_sha256', value: '9f14cc8c6a92fb4c11dd00c6de82cd87a7c5c6de54b0b29c4fa4a6e5e1a1b223' },
    ],
    response_actions: [
      'Patch CVE-2024-3400 immediately on all Palo Alto appliances',
      'Enable Threat Prevention profile with latest signatures',
      'Initiate full network forensics investigation',
      'Notify relevant government agencies (CISA, FBI for US entities)',
      'Assume all secrets on compromised systems are known to adversary',
      'Rebuild all compromised systems from known-good images',
    ],
    lessons_learned: [
      'Patch management failed — CVE-2024-3400 was available 2 weeks before exploitation',
      'No network segmentation between VPN DMZ and internal DC subnet',
      'Slow exfiltration bypassed volumetric DLP thresholds',
    ],
  },
};

// ── Random host/user generators ───────────────────────────────────
const SAMPLE_HOSTS = [
  'WIN-WKSTN-001','WIN-WKSTN-042','WIN-WKSTN-107',
  'SERVER-AD-01','SERVER-FILE-02','SERVER-SQL-03',
  'LAPTOP-EXEC-CFO','LAPTOP-DEV-042','MACBOOK-HR-015',
];
const SAMPLE_USERS = [
  'j.smith','a.patel','m.johnson','s.chen',
  'r.williams','l.garcia','t.nguyen','k.brown',
  'SYSTEM','NT AUTHORITY\\NETWORK',
];

function rndItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rndHosts(n)  { return [...new Set(Array.from({length:n}, () => rndItem(SAMPLE_HOSTS)))]; }
function rndUsers(n)  { return [...new Set(Array.from({length:n}, () => rndItem(SAMPLE_USERS)))]; }

// ── Build timeline events from scenario phases ────────────────────
function buildTimeline(phases, startTime, timelineHours) {
  const interval = (timelineHours * 3600000) / phases.length;
  return phases.map((p, i) => ({
    timestamp: new Date(startTime + i * interval + Math.random() * interval * 0.3).toISOString(),
    phase:      p.phase,
    technique:  p.technique,
    description:p.description,
    host:       rndItem(SAMPLE_HOSTS),
    user:       rndItem(SAMPLE_USERS),
    severity:   p.technique?.startsWith('T1486') || p.technique?.startsWith('T1190') ? 'CRITICAL' : 'HIGH',
  }));
}

// ═══════════════════════════════════════════════════════════════════
//  IncidentSimulator Class
// ═══════════════════════════════════════════════════════════════════
class IncidentSimulator {
  constructor() {
    this._scenarios = SCENARIOS;
    console.info(`[IncidentSimulator] Initialized: ${Object.keys(this._scenarios).length} scenarios loaded`);
  }

  // ── Resolve scenario key ───────────────────────────────────────
  _resolveScenario(name) {
    if (!name) return null;
    const lower = name.toLowerCase().replace(/[\s-_]+/g, '-');

    // Direct match
    if (this._scenarios[lower]) return lower;

    // Fuzzy match
    if (lower.includes('ransom') || lower.includes('lockbit') || lower.includes('crypt')) return 'ransomware';
    if (lower.includes('phish') || lower.includes('bec') || lower.includes('email')) return 'phishing';
    if (lower.includes('supply') || lower.includes('chain') || lower.includes('solarwind')) return 'supply-chain';
    if (lower.includes('insider') || lower.includes('employee') || lower.includes('malicious-insider')) return 'insider-threat';
    if (lower.includes('apt') || lower.includes('nation') || lower.includes('espionage')) return 'apt-espionage';

    return null;
  }

  // ── Main simulate function ────────────────────────────────────
  simulate(scenario, options = {}) {
    const key = this._resolveScenario(scenario);
    const tpl  = key ? this._scenarios[key] : this._scenarios['ransomware'];
    const actualKey = key || 'ransomware';

    const startTime    = Date.now() - (tpl.timeline_hours * 3600000);
    const customHosts  = (options.hosts || []).concat(tpl.affected_systems || []);
    const customUsers  = (options.users || []).concat(rndUsers(3));

    const timeline     = buildTimeline(tpl.phases, startTime, tpl.timeline_hours);
    const techniques   = [...new Set(tpl.phases.map(p => p.technique).filter(Boolean))];

    const incidentId   = `INC-${Date.now().toString(36).toUpperCase()}`;
    const detectionGap = Math.floor(tpl.timeline_hours * 0.6); // detected after 60% of attack

    return {
      incident_id:     incidentId,
      scenario:        actualKey,
      name:            tpl.name,
      actor:           tpl.actor,
      severity:        tpl.severity,
      status:          'SIMULATED',
      detection_gap_hours: detectionGap,
      timeline_hours:  tpl.timeline_hours,
      phases:          tpl.phases,
      timeline:        timeline,
      affected_systems:customHosts.slice(0, 8),
      affected_users:  customUsers.slice(0, 5),
      iocs:            tpl.iocs || [],
      techniques:      techniques,
      mitre_chain:     tpl.phases.map(p => ({ phase: p.phase, technique: p.technique })),
      response_actions:tpl.response_actions || [],
      lessons_learned: tpl.lessons_learned || [],
      metrics: {
        total_phases:    tpl.phases.length,
        techniques_used: techniques.length,
        dwell_time_hours:tpl.timeline_hours,
        systems_affected:customHosts.length,
        data_exfiltrated:tpl.severity === 'CRITICAL' ? 'High' : 'Medium',
      },
      generated_at: new Date().toISOString(),
    };
  }

  // ── Format simulation as SOC report markdown ─────────────────
  formatForSOC(result) {
    const lines = [
      `# 🚨 Incident Report — ${result.incident_id}`,
      `**Scenario:** ${result.name}  |  **Severity:** ${result.severity}  |  **Status:** ${result.status}`,
      `**Threat Actor:** ${result.actor}  |  **Dwell Time:** ${result.timeline_hours}h  |  **Generated:** ${result.generated_at}`,
      '',
      '---',
      '',
      '## Attack Phases (MITRE ATT&CK)',
      '',
      ...result.phases.map((p, i) =>
        `**${i+1}. ${p.phase}** (${p.technique})\n> ${p.description}\n`
      ),
      '',
      '## Affected Systems',
      result.affected_systems.map(s => `- ${s}`).join('\n'),
      '',
      '## Indicators of Compromise',
      result.iocs.map(i => `- **${i.type}**: \`${i.value}\``).join('\n'),
      '',
      '## Response Actions',
      result.response_actions.map((a,i) => `${i+1}. ${a}`).join('\n'),
      '',
      '## Lessons Learned',
      result.lessons_learned.map(l => `- ${l}`).join('\n'),
      '',
      '---',
      `*Generated by Wadjet-Eye AI Incident Simulator — Training Use Only*`,
    ];
    return lines.join('\n');
  }

  // ── List available scenarios ─────────────────────────────────
  listScenarios() {
    return Object.entries(this._scenarios).map(([key, s]) => ({
      key,
      name:     s.name,
      actor:    s.actor,
      severity: s.severity,
      phases:   s.phases.length,
    }));
  }
}

// ── Singleton export ───────────────────────────────────────────────
const defaultSimulator = new IncidentSimulator();

module.exports = { IncidentSimulator, defaultSimulator };
