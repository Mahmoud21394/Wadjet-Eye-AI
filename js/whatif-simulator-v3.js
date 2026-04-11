/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — What-If Attack Simulator v3.0 (FULLY REBUILT)
 *  FILE: js/whatif-simulator-v3.js
 *
 *  Completely rewritten from scratch — no static data, no UI freezes.
 *  User-input-driven scenarios with logic-based outcome prediction.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ════════════════════════════════════════════════════════════════
   SIMULATION SCENARIOS — Comprehensive library
════════════════════════════════════════════════════════════════ */
const WHATIF_SCENARIOS_V3 = [
  {
    id: 'phishing-mfa-bypass',
    name: 'Phishing + MFA Bypass Attack',
    category: 'Identity Attacks',
    icon: 'fa-envelope-open-text',
    iconColor: '#f97316',
    description: 'What happens if an attacker bypasses MFA using an Adversary-in-the-Middle (AiTM) proxy phishing kit?',
    mitre: ['T1566.002', 'T1111', 'T1078'],
    inputs: [
      { id: 'mfa_type', label: 'MFA Type in Use', type: 'select', options: [
        { value: 'sms', label: 'SMS OTP (Vulnerable)' },
        { value: 'totp', label: 'TOTP App (Somewhat Vulnerable)' },
        { value: 'push', label: 'Push Notification (Vulnerable to fatigue)' },
        { value: 'fido2', label: 'FIDO2/Hardware Key (Resistant)' },
        { value: 'none', label: 'No MFA (Critical Risk)' },
      ]},
      { id: 'email_security', label: 'Email Security Controls', type: 'select', options: [
        { value: 'none', label: 'No filtering' },
        { value: 'basic', label: 'Basic spam filter' },
        { value: 'advanced', label: 'Advanced sandbox + ML' },
        { value: 'defender', label: 'Microsoft Defender for O365' },
      ]},
      { id: 'user_training', label: 'Security Awareness Training', type: 'select', options: [
        { value: 'none', label: 'None' },
        { value: 'annual', label: 'Annual' },
        { value: 'quarterly', label: 'Quarterly' },
        { value: 'continuous', label: 'Continuous (monthly + simulations)' },
      ]},
      { id: 'conditional_access', label: 'Conditional Access Policies', type: 'toggle', default: false },
      { id: 'siem_monitoring', label: 'SIEM/EDR Monitoring Active', type: 'toggle', default: true },
    ],
    evaluate: function(vals) {
      let riskScore = 90;
      let dwellDays = 30;
      let outcomes = [];
      let mitigations = [];

      if (vals.mfa_type === 'fido2') { riskScore -= 50; outcomes.push({ level: 'low', msg: 'FIDO2 blocks AiTM token theft — this attack vector is neutralized' }); }
      else if (vals.mfa_type === 'none') { riskScore += 10; dwellDays += 20; outcomes.push({ level: 'critical', msg: 'No MFA: Attacker gains immediate persistent access after credential harvest' }); }
      else if (vals.mfa_type === 'sms') { outcomes.push({ level: 'high', msg: 'SMS OTP intercepted via SIM-swap or AiTM proxy — account compromised within minutes' }); }
      else if (vals.mfa_type === 'push') { outcomes.push({ level: 'high', msg: 'MFA fatigue attack possible — user approves push after repeated attempts' }); }

      if (vals.email_security === 'advanced' || vals.email_security === 'defender') { riskScore -= 20; outcomes.push({ level: 'medium', msg: 'Advanced email security catches 65-80% of phishing URLs' }); }
      else if (vals.email_security === 'none') { riskScore += 10; outcomes.push({ level: 'critical', msg: 'No email filtering — phishing email delivered directly to inbox' }); }

      if (vals.user_training === 'continuous') { riskScore -= 15; outcomes.push({ level: 'low', msg: 'Continuous training reduces click rate to ~2%' }); }
      else if (vals.user_training === 'none') { riskScore += 10; outcomes.push({ level: 'high', msg: 'No training — users likely to click malicious links (28% click rate average)' }); }

      if (vals.conditional_access) { riskScore -= 20; outcomes.push({ level: 'medium', msg: 'Conditional Access limits what attacker can do with stolen token' }); }
      if (vals.siem_monitoring) { dwellDays = Math.max(1, dwellDays - 15); outcomes.push({ level: 'low', msg: 'SIEM detects anomalous login patterns, reducing dwell time' }); }

      mitigations = [
        { priority: 1, action: 'Deploy FIDO2 hardware keys for privileged accounts', impact: 'Eliminates AiTM phishing vector entirely' },
        { priority: 2, action: 'Enable Conditional Access with device compliance checks', impact: 'Prevents token replay from unknown devices' },
        { priority: 3, action: 'Deploy Microsoft Defender for Office 365 or equivalent', impact: 'Catches 70-85% of phishing campaigns before delivery' },
        { priority: 4, action: 'Monthly phishing simulations + immediate training', impact: 'Reduces click rates from 28% to <3%' },
      ];

      return { riskScore: Math.max(5, Math.min(100, riskScore)), dwellDays, outcomes, mitigations, attackSuccess: riskScore > 50 };
    },
  },
  {
    id: 'ransomware-backup',
    name: 'Ransomware vs Backup Strategy',
    category: 'Ransomware',
    icon: 'fa-lock',
    iconColor: '#ef4444',
    description: 'Simulate a LockBit-style ransomware attack against your current backup configuration and recovery posture.',
    mitre: ['T1486', 'T1490', 'T1053'],
    inputs: [
      { id: 'backup_type', label: 'Backup Strategy', type: 'select', options: [
        { value: 'none', label: 'No backups' },
        { value: 'local_only', label: 'Local backups only (same network)' },
        { value: 'cloud_unversioned', label: 'Cloud backup (no versioning)' },
        { value: 'cloud_versioned', label: 'Cloud backup (versioned/immutable)' },
        { value: '321_offline', label: '3-2-1 rule with offline/air-gapped copy' },
      ]},
      { id: 'backup_frequency', label: 'Backup Frequency', type: 'select', options: [
        { value: 'never', label: 'Never / Ad-hoc' },
        { value: 'weekly', label: 'Weekly' },
        { value: 'daily', label: 'Daily' },
        { value: 'hourly', label: 'Hourly' },
      ]},
      { id: 'edr_deployed', label: 'EDR Solution Deployed', type: 'toggle', default: false },
      { id: 'shadow_copies', label: 'VSS Shadow Copies Enabled', type: 'toggle', default: true },
      { id: 'network_seg', label: 'Backup Network Segmented', type: 'toggle', default: false },
      { id: 'rto_tested', label: 'Recovery Procedure Tested <6mo', type: 'toggle', default: false },
    ],
    evaluate: function(vals) {
      let riskScore = 85;
      let recoveryHours = 72;
      let dataLossDays = 7;
      let outcomes = [];
      let mitigations = [];

      if (vals.backup_type === 'none') {
        riskScore = 99; recoveryHours = 9999; dataLossDays = 999;
        outcomes.push({ level: 'critical', msg: 'CRITICAL: No backups — total data loss, pay ransom or rebuild from scratch' });
      } else if (vals.backup_type === 'local_only') {
        riskScore -= 5; dataLossDays = 1;
        outcomes.push({ level: 'critical', msg: 'Local backups on same network WILL be encrypted — effectively no backup protection' });
      } else if (vals.backup_type === 'cloud_versioned' || vals.backup_type === '321_offline') {
        riskScore -= 45; recoveryHours = 8; dataLossDays = 0.1;
        outcomes.push({ level: 'low', msg: 'Immutable/offline backups survive encryption — recovery in hours, not weeks' });
      }

      if (vals.backup_frequency === 'hourly' || vals.backup_frequency === 'daily') { dataLossDays = Math.min(dataLossDays, 1); }
      else if (vals.backup_frequency === 'never') { dataLossDays = 30; riskScore += 10; }

      if (vals.edr_deployed) { riskScore -= 25; recoveryHours = Math.max(4, recoveryHours - 24); outcomes.push({ level: 'medium', msg: 'EDR behavioral detection can stop encryption within seconds of initiation' }); }
      else { outcomes.push({ level: 'high', msg: 'Without EDR, ransomware encrypts undetected for hours before discovery' }); }

      if (vals.shadow_copies && vals.backup_type !== 'none') {
        outcomes.push({ level: 'medium', msg: 'Warning: LockBit 3.0 specifically deletes VSS shadow copies — not a reliable recovery option' });
      }

      if (vals.network_seg) { riskScore -= 15; outcomes.push({ level: 'low', msg: 'Backup network segmentation prevents lateral spread to backup servers' }); }
      if (vals.rto_tested) { recoveryHours = Math.max(4, recoveryHours * 0.5); outcomes.push({ level: 'low', msg: 'Tested recovery procedures significantly reduce actual RTO' }); }

      mitigations = [
        { priority: 1, action: 'Implement 3-2-1-1-0 backup strategy with immutable cloud copy', impact: 'Eliminates ransomware leverage over data' },
        { priority: 2, action: 'Deploy behavioral EDR (CrowdStrike Falcon, SentinelOne)', impact: 'Stop encryption within <10 seconds of initiation' },
        { priority: 3, action: 'Network-isolate backup infrastructure', impact: 'Prevents ransomware from reaching backup servers' },
        { priority: 4, action: 'Test recovery quarterly with documented RTO/RPO', impact: 'Reduces actual recovery time by 50-70%' },
      ];

      const financialImpact = riskScore > 70 ? 'Estimated cost: $500K - $5M (downtime + recovery + ransom pressure)' : 'Recovery cost: $50K - $200K (managed recovery)';

      return { riskScore: Math.max(5, Math.min(100, riskScore)), recoveryHours, dataLossDays, outcomes, mitigations, financialImpact, attackSuccess: riskScore > 50 };
    },
  },
  {
    id: 'insider-threat',
    name: 'Privileged Insider Threat',
    category: 'Insider Threats',
    icon: 'fa-user-tie',
    iconColor: '#a855f7',
    description: 'Simulate a malicious insider (IT admin) exfiltrating sensitive data using privileged access.',
    mitre: ['T1078', 'T1530', 'T1567'],
    inputs: [
      { id: 'pam_solution', label: 'Privileged Access Management (PAM)', type: 'select', options: [
        { value: 'none', label: 'None' },
        { value: 'basic', label: 'Basic (password vault only)' },
        { value: 'full', label: 'Full PAM (session recording, JIT)' },
      ]},
      { id: 'dlp_deployed', label: 'DLP Solution Active', type: 'toggle', default: false },
      { id: 'ueba_monitoring', label: 'UEBA/User Behavior Analytics', type: 'toggle', default: false },
      { id: 'least_privilege', label: 'Least Privilege Enforced', type: 'toggle', default: false },
      { id: 'log_retention', label: 'Audit Logs Retained 90+ Days', type: 'toggle', default: true },
      { id: 'offboarding_process', label: 'Formal Offboarding Process', type: 'toggle', default: true },
    ],
    evaluate: function(vals) {
      let riskScore = 80; let detectionDays = 200; let outcomes = []; let mitigations = [];

      if (vals.pam_solution === 'full') { riskScore -= 30; detectionDays -= 80; outcomes.push({ level: 'low', msg: 'Full PAM with session recording creates audit trail and limits blast radius' }); }
      else if (vals.pam_solution === 'none') { riskScore += 15; outcomes.push({ level: 'critical', msg: 'No PAM: Admin has unrestricted privileged access with no monitoring or accountability' }); }

      if (vals.dlp_deployed) { riskScore -= 25; outcomes.push({ level: 'medium', msg: 'DLP detects large outbound transfers and blocks/alerts on policy violations' }); }
      else { outcomes.push({ level: 'high', msg: 'Without DLP, insider can freely exfiltrate via email, USB, or cloud storage' }); }

      if (vals.ueba_monitoring) { riskScore -= 20; detectionDays -= 90; outcomes.push({ level: 'medium', msg: 'UEBA detects behavioral anomalies (off-hours access, bulk downloads)' }); }
      if (vals.least_privilege) { riskScore -= 20; outcomes.push({ level: 'low', msg: 'Least privilege limits scope — insider can only access data relevant to role' }); }
      if (!vals.log_retention) { riskScore += 10; outcomes.push({ level: 'high', msg: 'Without log retention, forensic investigation impossible after detection' }); }

      mitigations = [
        { priority: 1, action: 'Deploy full PAM with JIT access and session recording', impact: 'Complete audit trail; detect and stop insider activity in real-time' },
        { priority: 2, action: 'Implement DLP across email, endpoints, and cloud', impact: 'Block or alert on bulk data transfers' },
        { priority: 3, action: 'Deploy UEBA to baseline and monitor user behavior', impact: 'Detect anomalies 120 days faster than manual review' },
        { priority: 4, action: 'Enforce strict least-privilege and role-based access', impact: 'Reduces data exposure surface by 60-80%' },
      ];

      return { riskScore: Math.max(5, Math.min(100, riskScore)), detectionDays: Math.max(1, detectionDays), outcomes, mitigations, attackSuccess: riskScore > 50 };
    },
  },
  {
    id: 'zero-day-exploit',
    name: 'Zero-Day Vulnerability Exploitation',
    category: 'Advanced Exploits',
    icon: 'fa-skull-crossbones',
    iconColor: '#22d3ee',
    description: 'What if a state-sponsored actor exploits an unpatched zero-day in your perimeter systems?',
    mitre: ['T1190', 'T1068', 'T1505'],
    inputs: [
      { id: 'patch_cycle', label: 'Patch Management Cycle', type: 'select', options: [
        { value: 'none', label: 'No formal process' },
        { value: 'monthly', label: 'Monthly (standard)' },
        { value: 'weekly', label: 'Weekly' },
        { value: 'automated', label: 'Automated with vulnerability scanning' },
      ]},
      { id: 'network_exposure', label: 'External Attack Surface', type: 'select', options: [
        { value: 'large', label: 'Large (many internet-facing systems)' },
        { value: 'medium', label: 'Medium (web apps + VPN)' },
        { value: 'small', label: 'Small (minimal exposure)' },
        { value: 'zero_trust', label: 'Zero Trust / VPN-less' },
      ]},
      { id: 'waf_deployed', label: 'WAF / Application Firewall', type: 'toggle', default: false },
      { id: 'vuln_scanning', label: 'Continuous Vulnerability Scanning', type: 'toggle', default: false },
      { id: 'honeypots', label: 'Honeypots / Deception Tech Deployed', type: 'toggle', default: false },
      { id: 'ndr_deployed', label: 'Network Detection & Response (NDR)', type: 'toggle', default: false },
    ],
    evaluate: function(vals) {
      let riskScore = 75; let dwellDays = 60; let outcomes = []; let mitigations = [];

      if (vals.network_exposure === 'zero_trust') { riskScore -= 35; outcomes.push({ level: 'low', msg: 'Zero Trust architecture significantly limits lateral movement even after initial compromise' }); }
      else if (vals.network_exposure === 'large') { riskScore += 15; dwellDays += 30; outcomes.push({ level: 'critical', msg: 'Large attack surface = many potential zero-day targets across perimeter' }); }

      if (vals.waf_deployed) { riskScore -= 15; outcomes.push({ level: 'medium', msg: 'WAF can detect/block exploitation attempts for known patterns' }); }
      if (vals.vuln_scanning) { riskScore -= 10; outcomes.push({ level: 'medium', msg: 'Continuous scanning helps identify vulnerable systems before attackers (but not zero-days)' }); }
      if (vals.honeypots) { dwellDays -= 20; riskScore -= 10; outcomes.push({ level: 'low', msg: 'Deception tech triggers alert when attacker moves laterally — dramatically reduces dwell time' }); }
      if (vals.ndr_deployed) { dwellDays -= 25; outcomes.push({ level: 'low', msg: 'NDR detects C2 beaconing and lateral movement regardless of zero-day payload' }); }

      mitigations = [
        { priority: 1, action: 'Adopt Zero Trust Network Architecture', impact: 'Limits blast radius even if zero-day exploited' },
        { priority: 2, action: 'Deploy NDR + honeypots for post-exploitation detection', impact: 'Detect within hours instead of months' },
        { priority: 3, action: 'Minimize internet-facing attack surface', impact: 'Fewer zero-day exposure points' },
        { priority: 4, action: 'Implement automated patching for known vulns', impact: 'Zero-days become isolated vs. compounding issues' },
      ];

      return { riskScore: Math.max(5, Math.min(100, riskScore)), dwellDays: Math.max(1, dwellDays), outcomes, mitigations, attackSuccess: riskScore > 50 };
    },
  },
  {
    id: 'supply-chain',
    name: 'Software Supply Chain Compromise',
    category: 'Supply Chain',
    icon: 'fa-boxes',
    iconColor: '#f59e0b',
    description: 'Model a SolarWinds/XZ Utils-style supply chain attack via a compromised vendor or open-source dependency.',
    mitre: ['T1195.002', 'T1072', 'T1036'],
    inputs: [
      { id: 'vendor_assessment', label: 'Vendor Security Assessment', type: 'select', options: [
        { value: 'none', label: 'None / Trust-based' },
        { value: 'questionnaire', label: 'Annual questionnaire only' },
        { value: 'audit', label: 'Third-party audit / SOC2' },
        { value: 'continuous', label: 'Continuous monitoring + SBOM' },
      ]},
      { id: 'code_signing', label: 'Software Supply Chain Controls', type: 'select', options: [
        { value: 'none', label: 'No code signing verification' },
        { value: 'basic', label: 'Basic hash verification' },
        { value: 'sbom', label: 'SBOM + dependency scanning' },
        { value: 'sigstore', label: 'Sigstore/Cosign + SBOM + scanning' },
      ]},
      { id: 'network_monitoring', label: 'Outbound Network Monitoring', type: 'toggle', default: false },
      { id: 'privileged_isolation', label: 'Privileged Workstation Isolation', type: 'toggle', default: false },
    ],
    evaluate: function(vals) {
      let riskScore = 80; let outcomes = []; let mitigations = []; let dwellDays = 90;

      if (vals.vendor_assessment === 'continuous') { riskScore -= 25; outcomes.push({ level: 'medium', msg: 'Continuous vendor monitoring may detect compromise before deployment' }); }
      else if (vals.vendor_assessment === 'none') { riskScore += 10; outcomes.push({ level: 'critical', msg: 'No vendor assessment — completely blind to compromise in third-party software' }); }

      if (vals.code_signing === 'sigstore') { riskScore -= 30; outcomes.push({ level: 'low', msg: 'Sigstore + SBOM provides cryptographic supply chain integrity verification' }); }
      else if (vals.code_signing === 'none') { riskScore += 15; outcomes.push({ level: 'critical', msg: 'No integrity verification — malicious code indistinguishable from legitimate' }); }
      else if (vals.code_signing === 'sbom') { riskScore -= 20; outcomes.push({ level: 'medium', msg: 'SBOM enables rapid identification of affected systems after compromise disclosure' }); }

      if (vals.network_monitoring) { dwellDays -= 40; outcomes.push({ level: 'medium', msg: 'Outbound monitoring detects C2 beaconing from backdoored software' }); }
      if (vals.privileged_isolation) { riskScore -= 15; outcomes.push({ level: 'low', msg: 'Isolated privileged workstations limit attacker lateral movement post-compromise' }); }

      mitigations = [
        { priority: 1, action: 'Implement SBOM + automated dependency vulnerability scanning', impact: 'Know exactly what\'s in your software stack' },
        { priority: 2, action: 'Require SOC2/ISO27001 + continuous monitoring for critical vendors', impact: 'Detect vendor compromise before impact' },
        { priority: 3, action: 'Monitor all outbound network connections from critical systems', impact: 'Detect C2 callbacks from backdoored software' },
        { priority: 4, action: 'Adopt Zero Trust — assume any vendor software may be compromised', impact: 'Limit blast radius of supply chain attacks' },
      ];

      return { riskScore: Math.max(5, Math.min(100, riskScore)), dwellDays: Math.max(7, dwellDays), outcomes, mitigations, attackSuccess: riskScore > 50 };
    },
  },
];

/* ════════════════════════════════════════════════════════════════
   STATE
════════════════════════════════════════════════════════════════ */
let _wifState = {
  activeScenario: null,
  inputs: {},
  results: null,
  history: [],
};

/* ════════════════════════════════════════════════════════════════
   MAIN RENDER
════════════════════════════════════════════════════════════════ */
window.renderWhatIfSimulatorV3 = function() {
  const el = document.getElementById('page-whatif-simulator');
  if (!el) return;

  el.innerHTML = `
  <div style="padding:0;background:#0a0e17;min-height:100vh;font-family:'Inter',sans-serif;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0a0e17,#1a0a2e);border-bottom:1px solid #1e293b;padding:24px 28px 20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
        <div style="display:flex;align-items:center;gap:14px;">
          <div style="width:52px;height:52px;background:linear-gradient(135deg,#f97316,#ef4444);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(249,115,22,.3);">
            <i class="fas fa-chess" style="color:#fff;font-size:22px;"></i>
          </div>
          <div>
            <h1 style="margin:0;font-size:1.5rem;font-weight:800;color:#f1f5f9;">What-If Attack Simulator</h1>
            <div style="font-size:12px;color:#64748b;margin-top:3px;">
              <i class="fas fa-brain" style="color:#f97316;margin-right:4px;"></i>
              Input-driven · Logic-based outcomes · Real security controls
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Main -->
    <div style="padding:24px 28px;display:grid;grid-template-columns:340px 1fr;gap:20px;min-height:calc(100vh-200px);">

      <!-- Scenario Selector -->
      <div>
        <h3 style="margin:0 0 14px;font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;">Attack Scenarios</h3>
        <div style="display:flex;flex-direction:column;gap:8px;">
          ${WHATIF_SCENARIOS_V3.map(s => `
          <div onclick="wifSelectScenario('${s.id}')" id="wif-btn-${s.id}"
            style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px;cursor:pointer;transition:all .2s;"
            onmouseover="this.style.borderColor='${s.iconColor}60'" onmouseout="wifHoverOut('${s.id}')">
            <div style="display:flex;align-items:flex-start;gap:10px;">
              <div style="width:36px;height:36px;background:${s.iconColor}20;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                <i class="fas ${s.icon}" style="color:${s.iconColor};font-size:15px;"></i>
              </div>
              <div>
                <div style="font-size:13px;font-weight:700;color:#e2e8f0;line-height:1.2;">${s.name}</div>
                <div style="font-size:10px;color:#64748b;margin-top:3px;">${s.category}</div>
              </div>
            </div>
          </div>`).join('')}
        </div>
      </div>

      <!-- Simulation Panel -->
      <div id="wif-sim-panel" style="background:#0f172a;border:1px solid #1e293b;border-radius:14px;overflow:hidden;">
        <div style="padding:60px;text-align:center;color:#475569;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <i class="fas fa-chess" style="font-size:3rem;margin-bottom:16px;opacity:.2;"></i>
          <div style="font-size:1rem;font-weight:700;color:#64748b;">Select a scenario</div>
          <div style="font-size:12px;color:#334155;margin-top:6px;">Choose an attack scenario from the left panel to configure and run a simulation</div>
        </div>
      </div>
    </div>
  </div>`;
};

window.wifHoverOut = function(id) {
  const btn = document.getElementById(`wif-btn-${id}`);
  if (btn && _wifState.activeScenario?.id !== id) btn.style.borderColor = '#1e293b';
};

/* ════════════════════════════════════════════════════════════════
   SELECT SCENARIO
════════════════════════════════════════════════════════════════ */
window.wifSelectScenario = function(id) {
  const s = WHATIF_SCENARIOS_V3.find(sc => sc.id === id);
  if (!s) return;
  _wifState.activeScenario = s;
  _wifState.results = null;
  _wifState.inputs = {};

  // Reset button styles
  WHATIF_SCENARIOS_V3.forEach(sc => {
    const btn = document.getElementById(`wif-btn-${sc.id}`);
    if (btn) btn.style.borderColor = sc.id === id ? sc.iconColor : '#1e293b';
  });

  // Initialize defaults
  s.inputs.forEach(inp => {
    if (inp.type === 'toggle') _wifState.inputs[inp.id] = inp.default ?? false;
    else if (inp.type === 'select') _wifState.inputs[inp.id] = inp.options[0].value;
  });

  renderWifSimPanel(s);
};

function renderWifSimPanel(s) {
  const panel = document.getElementById('wif-sim-panel');
  if (!panel) return;

  panel.innerHTML = `
  <!-- Scenario Header -->
  <div style="background:linear-gradient(135deg,${s.iconColor}20,transparent);border-bottom:1px solid #1e293b;padding:20px 24px;">
    <div style="display:flex;align-items:center;gap:12px;">
      <div style="width:44px;height:44px;background:${s.iconColor}20;border-radius:10px;display:flex;align-items:center;justify-content:center;">
        <i class="fas ${s.icon}" style="color:${s.iconColor};font-size:18px;"></i>
      </div>
      <div>
        <div style="font-size:16px;font-weight:800;color:#f1f5f9;">${s.name}</div>
        <div style="font-size:12px;color:#64748b;margin-top:2px;">${s.description}</div>
      </div>
    </div>
    <div style="display:flex;gap:6px;margin-top:12px;flex-wrap:wrap;">
      ${s.mitre.map(m => `<a href="https://attack.mitre.org/techniques/${m.replace('.','/').replace('.','/')}/" target="_blank" rel="noopener" style="background:#1e293b;color:#22d3ee;font-size:10px;font-family:monospace;padding:2px 8px;border-radius:4px;text-decoration:none;">${m}</a>`).join('')}
    </div>
  </div>

  <!-- Controls -->
  <div style="padding:24px;display:grid;grid-template-columns:1fr 1fr;gap:20px;">

    <!-- Inputs -->
    <div>
      <h3 style="margin:0 0 16px;font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;">Security Controls</h3>
      <div style="display:flex;flex-direction:column;gap:12px;">
        ${s.inputs.map(inp => renderWifInput(inp)).join('')}
      </div>
      <button onclick="wifRunSimulation()" id="wif-run-btn"
        style="margin-top:20px;width:100%;background:linear-gradient(135deg,#f97316,#ef4444);color:#fff;border:none;padding:12px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 16px rgba(249,115,22,.3);">
        <i class="fas fa-play-circle"></i> Run Simulation
      </button>
    </div>

    <!-- Results -->
    <div>
      <h3 style="margin:0 0 16px;font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;">Simulation Results</h3>
      <div id="wif-results-panel" style="background:#090d14;border:1px solid #1e293b;border-radius:10px;padding:40px;text-align:center;color:#475569;">
        <i class="fas fa-chart-bar" style="font-size:2rem;margin-bottom:12px;display:block;opacity:.2;"></i>
        Configure controls and click "Run Simulation"
      </div>
    </div>
  </div>`;
}

function renderWifInput(inp) {
  const val = _wifState.inputs[inp.id];
  if (inp.type === 'toggle') {
    return `<div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;">
      <span style="font-size:13px;color:#e2e8f0;">${inp.label}</span>
      <label style="position:relative;display:inline-block;width:42px;height:22px;cursor:pointer;">
        <input type="checkbox" id="wif-inp-${inp.id}" ${val ? 'checked' : ''} onchange="_wifState.inputs['${inp.id}']=this.checked"
          style="opacity:0;width:0;height:0;" />
        <span id="wif-toggle-${inp.id}" onclick="wifToggle('${inp.id}')"
          style="position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:${val?'#22c55e':'#1e293b'};border-radius:22px;transition:.3s;border:1px solid ${val?'#22c55e':'#334155'};">
          <span style="position:absolute;height:16px;width:16px;left:${val?'22px':'3px'};bottom:2px;background:white;border-radius:50%;transition:.3s;"></span>
        </span>
      </label>
    </div>`;
  }
  if (inp.type === 'select') {
    return `<div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px 14px;">
      <label style="display:block;font-size:11px;color:#64748b;font-weight:600;margin-bottom:6px;">${inp.label}</label>
      <select id="wif-inp-${inp.id}" onchange="_wifState.inputs['${inp.id}']=this.value"
        style="width:100%;background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:7px 10px;border-radius:6px;font-size:12px;outline:none;cursor:pointer;">
        ${inp.options.map(o => `<option value="${o.value}" ${val===o.value?'selected':''}>${o.label}</option>`).join('')}
      </select>
    </div>`;
  }
  return '';
}

window.wifToggle = function(id) {
  _wifState.inputs[id] = !_wifState.inputs[id];
  const span = document.getElementById(`wif-toggle-${id}`);
  const chk = document.getElementById(`wif-inp-${id}`);
  if (chk) chk.checked = _wifState.inputs[id];
  if (span) {
    const v = _wifState.inputs[id];
    span.style.background = v ? '#22c55e' : '#1e293b';
    span.style.borderColor = v ? '#22c55e' : '#334155';
    const dot = span.querySelector('span');
    if (dot) dot.style.left = v ? '22px' : '3px';
  }
};

/* ════════════════════════════════════════════════════════════════
   RUN SIMULATION
════════════════════════════════════════════════════════════════ */
window.wifRunSimulation = function() {
  const s = _wifState.activeScenario;
  if (!s) return;

  const btn = document.getElementById('wif-run-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating…'; }

  // Read latest values from DOM
  s.inputs.forEach(inp => {
    const el = document.getElementById(`wif-inp-${inp.id}`);
    if (!el) return;
    if (inp.type === 'toggle') _wifState.inputs[inp.id] = el.checked;
    else if (inp.type === 'select') _wifState.inputs[inp.id] = el.value;
  });

  // Run evaluation logic
  setTimeout(() => {
    try {
      const results = s.evaluate(_wifState.inputs);
      _wifState.results = results;
      renderWifResults(results, s);
    } catch (e) {
      const rPanel = document.getElementById('wif-results-panel');
      if (rPanel) rPanel.innerHTML = `<div style="color:#ef4444;text-align:center;padding:20px;">Error: ${e.message}</div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-redo"></i> Re-run'; }
    }
  }, 800 + Math.random() * 500);
};

/* ════════════════════════════════════════════════════════════════
   RENDER RESULTS
════════════════════════════════════════════════════════════════ */
function renderWifResults(r, s) {
  const panel = document.getElementById('wif-results-panel');
  if (!panel) return;

  const riskColor = r.riskScore >= 80 ? '#ef4444' : r.riskScore >= 60 ? '#f97316' : r.riskScore >= 40 ? '#f59e0b' : '#22c55e';
  const riskLabel = r.riskScore >= 80 ? 'CRITICAL' : r.riskScore >= 60 ? 'HIGH' : r.riskScore >= 40 ? 'MEDIUM' : 'LOW';

  const outcomeHtml = (r.outcomes || []).map(o => {
    const lc = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e' }[o.level] || '#6b7280';
    return `<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 10px;background:#0a0e17;border-radius:6px;border-left:3px solid ${lc};">
      <i class="fas fa-${o.level==='low'?'check-circle':o.level==='critical'?'skull-crossbones':'exclamation-circle'}" style="color:${lc};margin-top:1px;font-size:12px;flex-shrink:0;"></i>
      <span style="font-size:12px;color:#cbd5e1;line-height:1.4;">${o.msg}</span>
    </div>`;
  }).join('');

  panel.innerHTML = `
  <!-- Risk Score -->
  <div style="text-align:center;margin-bottom:20px;padding:16px;background:#0a0e17;border-radius:10px;">
    <div style="font-size:10px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:8px;">Attack Success Probability</div>
    <div style="font-size:3rem;font-weight:900;color:${riskColor};line-height:1;">${r.riskScore}<span style="font-size:1.5rem;">%</span></div>
    <div style="margin-top:8px;">
      <span style="background:${riskColor}20;color:${riskColor};border:1px solid ${riskColor}40;padding:3px 12px;border-radius:12px;font-size:11px;font-weight:800;">${riskLabel} RISK</span>
    </div>
    ${r.attackSuccess !== undefined ? `<div style="font-size:11px;color:#64748b;margin-top:8px;">${r.attackSuccess ? '⚠️ Attack likely to SUCCEED with current controls' : '✅ Controls LIKELY to prevent / detect this attack'}</div>` : ''}
    <!-- Risk Gauge -->
    <div style="background:#1e293b;border-radius:8px;height:8px;margin-top:14px;overflow:hidden;">
      <div style="background:linear-gradient(90deg,#22c55e,#f59e0b,#ef4444);width:100%;height:100%;"></div>
    </div>
    <div style="background:#0f172a;border-radius:8px;height:8px;margin-top:-8px;width:${100-r.riskScore}%;margin-left:auto;"></div>
  </div>

  <!-- Key Metrics -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;">
    ${r.dwellDays !== undefined ? `<div style="background:#0a0e17;border-radius:8px;padding:10px;text-align:center;"><div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;">Est. Dwell</div><div style="font-size:1.2rem;font-weight:800;color:#f97316;">${r.dwellDays > 999 ? '∞' : r.dwellDays + 'd'}</div></div>` : ''}
    ${r.recoveryHours !== undefined ? `<div style="background:#0a0e17;border-radius:8px;padding:10px;text-align:center;"><div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;">Recovery</div><div style="font-size:1.2rem;font-weight:800;color:#22d3ee;">${r.recoveryHours > 9000 ? '♾️' : r.recoveryHours + 'h'}</div></div>` : ''}
    ${r.dataLossDays !== undefined ? `<div style="background:#0a0e17;border-radius:8px;padding:10px;text-align:center;"><div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;">Data Loss</div><div style="font-size:1.2rem;font-weight:800;color:#ef4444;">${r.dataLossDays > 365 ? '∞' : r.dataLossDays + 'd'}</div></div>` : ''}
    ${r.detectionDays !== undefined ? `<div style="background:#0a0e17;border-radius:8px;padding:10px;text-align:center;"><div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;">Detection</div><div style="font-size:1.2rem;font-weight:800;color:#a855f7;">${r.detectionDays + 'd'}</div></div>` : ''}
  </div>

  <!-- Outcomes -->
  ${outcomeHtml ? `
  <div style="margin-bottom:14px;">
    <div style="font-size:10px;color:#475569;font-weight:700;text-transform:uppercase;margin-bottom:8px;">Predicted Outcomes</div>
    <div style="display:flex;flex-direction:column;gap:6px;">${outcomeHtml}</div>
  </div>` : ''}

  <!-- Financial Impact -->
  ${r.financialImpact ? `<div style="background:#0a0e17;border:1px solid #1e293b;border-radius:8px;padding:10px;margin-bottom:14px;font-size:12px;color:#f59e0b;"><i class="fas fa-dollar-sign" style="margin-right:6px;"></i>${r.financialImpact}</div>` : ''}

  <!-- Top Remediation -->
  ${r.mitigations?.length ? `
  <div>
    <div style="font-size:10px;color:#22c55e;font-weight:700;text-transform:uppercase;margin-bottom:8px;">Top Remediation #1</div>
    <div style="background:#0a0e17;border:1px solid #22c55e30;border-radius:8px;padding:10px;">
      <div style="font-size:12px;font-weight:700;color:#e2e8f0;">${r.mitigations[0].action}</div>
      <div style="font-size:11px;color:#64748b;margin-top:4px;">${r.mitigations[0].impact}</div>
    </div>
  </div>` : ''}

  <!-- Export -->
  <button onclick="wifExportReport()" style="margin-top:14px;width:100%;background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:9px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;">
    <i class="fas fa-download" style="margin-right:5px;"></i>Export Full Report
  </button>`;

  // Save to history
  _wifState.history.unshift({ scenario: s.name, riskScore: r.riskScore, timestamp: new Date().toISOString() });

  // Save to backend (non-blocking)
  window.apiPost?.('/api/whatif/simulations', {
    scenario_id: s.id,
    scenario_name: s.name,
    user_inputs: _wifState.inputs,
    outcome: r.attackSuccess ? 'attack_success' : 'attack_blocked',
    risk_reduction: 100 - r.riskScore,
    recommendations: r.mitigations || [],
  }).catch(() => {});
}

window.wifExportReport = function() {
  const r = _wifState.results;
  const s = _wifState.activeScenario;
  if (!r || !s) return;
  const lines = [
    `What-If Simulation Report`,
    `========================`,
    `Scenario: ${s.name}`,
    `Date: ${new Date().toLocaleString()}`,
    ``,
    `Risk Score: ${r.riskScore}% (${r.riskScore >= 80 ? 'CRITICAL' : r.riskScore >= 60 ? 'HIGH' : r.riskScore >= 40 ? 'MEDIUM' : 'LOW'})`,
    `Attack Success: ${r.attackSuccess ? 'YES' : 'NO'}`,
    r.dwellDays !== undefined ? `Estimated Dwell Time: ${r.dwellDays} days` : '',
    ``,
    `Predicted Outcomes:`,
    ...(r.outcomes || []).map(o => `  [${o.level.toUpperCase()}] ${o.msg}`),
    ``,
    `Recommended Mitigations:`,
    ...(r.mitigations || []).map((m, i) => `  ${i + 1}. ${m.action}\n     Impact: ${m.impact}`),
  ];
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([lines.filter(Boolean).join('\n')], { type: 'text/plain' }));
  a.download = `whatif-${s.id}-${Date.now()}.txt`;
  a.click();
};
