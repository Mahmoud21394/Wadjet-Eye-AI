'use strict';
/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet Nexus — Cyber Risk & Exposure Management Platform
 *  Frontend Module: js/wadjet-nexus.js
 *
 *  Brand: Wadjet Nexus (integrated from XORCISM open-source platform)
 *
 *  Sub-Modules (all rendered in Wadjet-Eye AI design system):
 *    • NEXUS-DASH  — Enterprise Risk Score Dashboard (animated KPIs)
 *    • NEXUS-CTEM  — CTEM/VOC Exposure Dashboard
 *    • NEXUS-VULN  — Vulnerability Management (CVE/KEV/EPSS worklist)
 *    • NEXUS-PATH  — Attack Path Graph (D3.js force-directed)
 *    • NEXUS-GRC   — Governance, Risk & Compliance
 *    • NEXUS-HUNT  — Threat Hunting Workbench
 *    • NEXUS-BAS   — Adversary Emulation / BAS
 *    • NEXUS-DFIR  — Digital Forensics & IR
 *    • NEXUS-TID   — Threat-Informed Defense Cockpit
 *    • NEXUS-MITRE — MITRE ATT&CK Navigator (interactive)
 *    • NEXUS-KILL  — Kill Chain Visualization
 *    • NEXUS-RISK  — Risk Register (FAIR/CRQ)
 *    • NEXUS-TPRM  — Third-Party Risk Management
 *    • NEXUS-SBOM  — SBOM / Software Composition Analysis
 *    • NEXUS-CRISIS — Crisis Management & Tabletop Exercises
 *    • NEXUS-CONN  — 1,200+ Security Connectors Catalog
 *    • NEXUS-RANSOM — Ransomware Scenario (FAIR + ATT&CK)
 *    • NEXUS-AOI   — Adversary Opportunity Index
 *    • NEXUS-INSURE — Cyber Insurance Readiness
 *    • NEXUS-PQCMM — Post-Quantum Crypto Maturity Model
 *    • NEXUS-PENTEST — Pentest Engagements
 *    • NEXUS-SIGMA — Sigma Detection Rules Library
 *    • NEXUS-YARA  — YARA Rules Library
 *    • NEXUS-EBIOS — EBIOS RM (5-workshop method)
 *    • NEXUS-NIST  — NIST 800-30 Risk Assessment
 *    • NEXUS-BIA   — Business Impact Analysis
 *    • NEXUS-DISC  — Attack Surface Discovery (OSINT)
 *    • NEXUS-POLICY — Policies & Documents
 *    • NEXUS-JOBS  — Background Scheduler (XSCHEDULE)
 *    • NEXUS-IDENT — Identity Management
 *
 *  Design: Wadjet-Eye AI dark theme, premium enterprise visualizations
 *  Viz: D3.js force-directed graphs, animated KPIs, MITRE matrix, kill-chain
 * ══════════════════════════════════════════════════════════════════════════════
 */

(function (global) {

// ── Design System Constants ──────────────────────────────────────────────────
const DS = {
  bg:       '#080e1a',
  bgCard:   '#0d1526',
  bgPanel:  '#111c30',
  accent:   '#3b82f6',
  accentG:  '#1d4ed8',
  green:    '#22c55e',
  yellow:   '#eab308',
  orange:   '#f97316',
  red:      '#ef4444',
  purple:   '#a855f7',
  cyan:     '#06b6d4',
  text:     '#e2e8f0',
  textMuted:'#94a3b8',
  border:   'rgba(59,130,246,0.15)',
  glow:     'rgba(59,130,246,0.3)',
};

const SEVERITY_COLOR = { critical: DS.red, high: DS.orange, medium: DS.yellow, low: DS.green, informational: DS.cyan, unknown: DS.textMuted };
const SEVERITY_ICON  = { critical: 'fa-skull', high: 'fa-exclamation-triangle', medium: 'fa-exclamation', low: 'fa-info-circle', informational: 'fa-circle-info', unknown: 'fa-question-circle' };

// ── API Client ────────────────────────────────────────────────────────────────
// nexusApi() — returns rich mock data for all endpoints so the platform
// renders fully without a live backend.  When window.NEXUS_LIVE_API === true
// and window.API_BASE_URL is set, it falls through to real HTTP calls.
// ─────────────────────────────────────────────────────────────────────────────
const API_BASE = (typeof window !== 'undefined' && window.API_BASE_URL) ? window.API_BASE_URL : '';

// ── Rich demo data seed ───────────────────────────────────────────────────────
const _MOCK = {
  // helpers
  _asset: (i) => ({ id: 'ast-' + i, hostname: ['web-prod-0'+i,'db-core-0'+i,'api-gw-0'+i,'k8s-node-0'+i,'vpn-gw-0'+i][i%5],
    ip_address: '10.0.' + i + '.'+((i*7)%254+1), criticality: ['critical','high','medium','low'][i%4],
    risk_score: 30 + (i*13)%60, internet_exposed: i%3===0, asset_type: ['server','container','network','endpoint'][i%4] }),
  _cve: (i) => {
    const ids = ['CVE-2024-3400','CVE-2023-44487','CVE-2024-21762','CVE-2023-46604','CVE-2024-1709','CVE-2023-20198','CVE-2024-4577','CVE-2023-42793','CVE-2024-6387','CVE-2023-48788'];
    const titles = ['PAN-OS Command Injection (CVSS 10)','HTTP/2 Rapid Reset DoS','Fortinet OTP Bypass','Apache ActiveMQ RCE','ConnectWise Auth Bypass','Cisco IOS XE Priv Esc','PHP CGI Arg Injection','JetBrains TeamCity Auth Bypass','OpenSSH regreSSHion RCE','Fortinet FortiClient EMS SQLi'];
    return { id:'vuln-'+i, cve_id: ids[i%10], title: titles[i%10], severity:['critical','high','high','medium','critical','high','medium','critical','critical','high'][i%10],
      cvss_score:[10,7.5,9.8,10,10,10,9.8,9.8,9.8,9.8][i%10], epss_score: 0.1+((i*0.09)%0.89),
      is_kev: i%3===0, has_exploit: i%2===0, published_at: '2024-'+(String(i%12+1).padStart(2,'0'))+'-'+(String(i%28+1).padStart(2,'0')) };
  },
  '/dashboard': () => ({
    success:true, data:{
      kpis:{ enterprise_risk_score:62, total_assets:2847, internet_exposed:312,
        total_vulns:4193, critical_vulns:287, kev_vulns:43, open_hunts:8,
        controls_pct:74, controls_implemented:1482, controls_total:2000,
        critical_assets:89, high_vulns:891, asset_hygiene_score:81,
        open_risk_score:38, compliance_debt:26 },
      severity_breakdown:{ critical:287, high:891, medium:1934, low:1081 },
      top_risky_assets: Array.from({length:6},(_,i)=>_MOCK._asset(i+1)),
      recent_risk_score:{ maturity_radar:{ detection:72,mitigation:68,validation:55,compliance:74,crisis_ready:61,risk_treated:80 } }
    }
  }),
  '/vulnerabilities': () => ({success:true, data: Array.from({length:50},(_,i)=>_MOCK._cve(i)), total:4193}),
  '/exposure-worklist': () => ({success:true, data: Array.from({length:20},(_,i)=>({
    id:'wl-'+i, fusion_score: 95-i*3, sla_breached: i<4, sla_due_at: new Date(Date.now()+(i-3)*86400000).toISOString(),
    nexus_vulnerabilities: _MOCK._cve(i), asset_inventory: _MOCK._asset(i)
  })), total:20}),
  '/attack-surface-graph': () => ({success:true, data:{
    nodes: [
      {id:'n1',label:'web-prod-01',type:'entry',risk_score:82},{id:'n2',label:'api-gw-01',type:'internal',risk_score:65},
      {id:'n3',label:'db-core-01',type:'crown_jewel',risk_score:91},{id:'n4',label:'auth-svc',type:'choke_point',risk_score:78},
      {id:'n5',label:'k8s-node-01',type:'internal',risk_score:55},{id:'n6',label:'vpn-gw-01',type:'entry',risk_score:73},
      {id:'n7',label:'backup-srv',type:'crown_jewel',risk_score:88},{id:'n8',label:'ldap-dc01',type:'choke_point',risk_score:85},
    ],
    edges:[
      {source:'n1',target:'n2',weight:12},{source:'n2',target:'n4',weight:8},
      {source:'n4',target:'n3',weight:5},{source:'n6',target:'n4',weight:15},
      {source:'n4',target:'n8',weight:7},{source:'n8',target:'n7',weight:9},
      {source:'n5',target:'n2',weight:11},{source:'n1',target:'n5',weight:6},
    ],
    choke_points:['n4','n8']
  }}),
  '/attack-paths': () => ({success:true, data: Array.from({length:12},(_,i)=>({
    id:'path-'+i, source_asset_id:'asset-'+Math.floor(Math.random()*100),
    target_asset_id:'crown-'+Math.floor(Math.random()*10),
    path_cost:20+(i*8)%80, blast_radius:(i+1)*350000, choke_point_ids:['n4','n8'].slice(0,i%3)
  })), total:12}),
  '/voc/kpis': () => ({success:true, data:{open_vulns:4193,sla_breached:127,sla_compliance_pct:89,mttr_days:14}}),
  '/voc/campaigns': () => ({success:true, data:[
    {id:'c1',name:'Q3 Critical CVE Remediation',status:'active',owner_email:'alice@corp.com',target_date:'2024-09-30'},
    {id:'c2',name:'KEV 30-Day Patch Cycle',status:'active',owner_email:'bob@corp.com',target_date:'2024-08-15'},
    {id:'c3',name:'Cloud Exposure Reduction',status:'planned',owner_email:'carol@corp.com',target_date:'2024-10-31'},
    {id:'c4',name:'Legacy TLS Deprecation',status:'completed',owner_email:'dave@corp.com',target_date:'2024-07-01'},
  ]}),
  '/ctem': () => ({success:true, data: Array.from({length:18},(_,i)=>({
    id:'exp-'+i, exposure_id:'EXP-'+String(1000+i), name:['Internet-Exposed RDP','Unpatched Exchange','Stale Admin Account','Shadow IT Asset','Exposed S3 Bucket','Weak VPN Config','Outdated SSL Cert'][i%7],
    stage:['discover','prioritize','remediate'][i%3], severity:['critical','high','medium'][i%3],
    asset_inventory:{hostname:'svc-'+i+'.corp.com'}
  }))}),
  '/tid/summary': () => ({success:true, data:{
    detect_covered:312, detect_partial:89, detect_none:241, false_coverage:44,
    test_validated:178, avg_program_score:73, total_techniques:686
  }}),
  '/tid/coverage': () => ({success:true, data: [
    {technique_id:'T1059',tactic:'Execution',detect_status:'covered',test_status:'validated',adversary_prevalence:0.91,detection_drift:false},
    {technique_id:'T1566',tactic:'Initial Access',detect_status:'covered',test_status:'validated',adversary_prevalence:0.88,detection_drift:false},
    {technique_id:'T1190',tactic:'Initial Access',detect_status:'partial',test_status:'none',adversary_prevalence:0.76,detection_drift:true},
    {technique_id:'T1486',tactic:'Impact',detect_status:'covered',test_status:'validated',adversary_prevalence:0.72,detection_drift:false},
    {technique_id:'T1078',tactic:'Initial Access',detect_status:'none',test_status:'none',adversary_prevalence:0.85,detection_drift:false},
    {technique_id:'T1021',tactic:'Lateral Movement',detect_status:'partial',test_status:'none',adversary_prevalence:0.68,detection_drift:false},
    {technique_id:'T1110',tactic:'Credential Access',detect_status:'covered',test_status:'validated',adversary_prevalence:0.79,detection_drift:false},
    {technique_id:'T1048',tactic:'Exfiltration',detect_status:'none',test_status:'none',adversary_prevalence:0.54,detection_drift:true},
    {technique_id:'T1055',tactic:'Defense Evasion',detect_status:'partial',test_status:'none',adversary_prevalence:0.61,detection_drift:false},
    {technique_id:'T1547',tactic:'Persistence',detect_status:'covered',test_status:'validated',adversary_prevalence:0.58,detection_drift:false},
  ], total:686}),
  '/kill-chain': () => ({success:true, data:{phases:[
    {phase:'Reconnaissance',technique_count:8,covered:6,uncovered:2,techniques:[{technique_id:'T1595'},{technique_id:'T1592'}]},
    {phase:'Weaponization',technique_count:7,covered:4,uncovered:3,techniques:[{technique_id:'T1587'},{technique_id:'T1588'}]},
    {phase:'Delivery',technique_count:9,covered:7,uncovered:2,techniques:[{technique_id:'T1566'},{technique_id:'T1195'}]},
    {phase:'Exploitation',technique_count:12,covered:5,uncovered:7,techniques:[{technique_id:'T1190'},{technique_id:'T1203'}]},
    {phase:'Installation',technique_count:10,covered:8,uncovered:2,techniques:[{technique_id:'T1547'},{technique_id:'T1543'}]},
    {phase:'C2',technique_count:8,covered:6,uncovered:2,techniques:[{technique_id:'T1071'},{technique_id:'T1573'}]},
    {phase:'Actions on Objectives',technique_count:11,covered:4,uncovered:7,techniques:[{technique_id:'T1486'},{technique_id:'T1485'}]},
  ]}}),
  '/hunts': () => ({success:true, data:[
    {id:'h1',title:'Living-off-the-Land Binaries',hypothesis:'TA using LOLBins to evade AV on workstations',status:'in_progress',priority:'high',technique_ids:['T1218','T1059'],hunter_email:'alice@corp.com',created_at:new Date(Date.now()-3*86400000)},
    {id:'h2',title:'Kerberoasting Activity',hypothesis:'SPN scanning from non-service accounts',status:'open',priority:'critical',technique_ids:['T1558'],hunter_email:'bob@corp.com',created_at:new Date(Date.now()-1*86400000)},
    {id:'h3',title:'Lateral Movement via SMB',hypothesis:'Unusual ADMIN$ share access patterns',status:'escalated',priority:'high',technique_ids:['T1021'],hunter_email:'carol@corp.com',created_at:new Date(Date.now()-6*86400000)},
    {id:'h4',title:'DNS Tunneling Detection',hypothesis:'Long subdomain queries from internal hosts',status:'closed',priority:'medium',technique_ids:['T1071'],hunter_email:'dave@corp.com',created_at:new Date(Date.now()-10*86400000)},
    {id:'h5',title:'Credential Stuffing in Auth Logs',hypothesis:'Velocity anomalies in SSO login failures',status:'open',priority:'high',technique_ids:['T1110'],hunter_email:'alice@corp.com',created_at:new Date(Date.now()-2*86400000)},
    {id:'h6',title:'PowerShell Encoded Commands',hypothesis:'Base64 encoded PS exec from scheduled tasks',status:'in_progress',priority:'critical',technique_ids:['T1059'],hunter_email:'bob@corp.com',created_at:new Date(Date.now()-4*86400000)},
  ], total:6}),
  '/emulation/scenarios': () => ({success:true, data:[
    {id:'s1',name:'APT29 Cozy Bear TTPs',threat_actor:'APT29',test_count:42,status:'ready',last_run_at:new Date(Date.now()-2*86400000)},
    {id:'s2',name:'Ransomware Kill Chain (LockBit)',threat_actor:'LockBit 3.0',test_count:31,status:'ready',last_run_at:new Date(Date.now()-7*86400000)},
    {id:'s3',name:'Supply Chain Compromise',threat_actor:'APT41',test_count:18,status:'ready',last_run_at:null},
    {id:'s4',name:'Cloud Jacking — Azure AD',threat_actor:'Storm-0558',test_count:24,status:'running',last_run_at:new Date(Date.now()-1*86400000)},
    {id:'s5',name:'HAFNIUM Exchange Exploit Chain',threat_actor:'HAFNIUM',test_count:14,status:'ready',last_run_at:new Date(Date.now()-14*86400000)},
  ]}),
  '/emulation/results': () => ({success:true, data:[
    {id:'r1',nexus_emulation_scenarios:{name:'APT29 Cozy Bear TTPs'},total_tests:42,detected:34,undetected:8,coverage_pct:81,run_at:new Date(Date.now()-2*86400000)},
    {id:'r2',nexus_emulation_scenarios:{name:'Ransomware Kill Chain (LockBit)'},total_tests:31,detected:19,undetected:12,coverage_pct:61,run_at:new Date(Date.now()-7*86400000)},
    {id:'r3',nexus_emulation_scenarios:{name:'HAFNIUM Exchange Exploit Chain'},total_tests:14,detected:12,undetected:2,coverage_pct:86,run_at:new Date(Date.now()-14*86400000)},
  ]}),
  '/controls': () => ({success:true, data:[
    {id:'c1',control_id:'ISO-A.12.6.1',name:'Management of Technical Vulnerabilities',framework:'ISO 27001',status:'implemented'},
    {id:'c2',control_id:'NIST-SI-2',name:'Flaw Remediation',framework:'NIST 800-53',status:'implemented'},
    {id:'c3',control_id:'SOC2-CC7.1',name:'Logical and Physical Access Controls',framework:'SOC 2',status:'partial'},
    {id:'c4',control_id:'PCI-6.3.3',name:'Security Patches/Updates',framework:'PCI DSS 4.0',status:'implemented'},
    {id:'c5',control_id:'DORA-ICT.3.4',name:'ICT Risk Management Framework',framework:'DORA',status:'partial'},
    {id:'c6',control_id:'NIST-IR-4',name:'Incident Handling',framework:'NIST 800-53',status:'implemented'},
    {id:'c7',control_id:'ISO-A.16.1.1',name:'Incident Management Responsibilities',framework:'ISO 27001',status:'implemented'},
    {id:'c8',control_id:'CIS-18.1',name:'Security Awareness Training',framework:'CIS v8',status:'partial'},
    {id:'c9',control_id:'SOC2-CC9.1',name:'Risk Mitigation Activities',framework:'SOC 2',status:'planned'},
    {id:'c10',control_id:'NIST-SC-7',name:'Boundary Protection',framework:'NIST 800-53',status:'implemented'},
    {id:'c11',control_id:'PCI-11.3.1',name:'External Vulnerability Scanning',framework:'PCI DSS 4.0',status:'implemented'},
    {id:'c12',control_id:'CIS-7.1',name:'Vulnerability Management Process',framework:'CIS v8',status:'implemented'},
  ], total:1482}),
  '/audits': () => ({success:true, data:[
    {id:'a1',title:'ISO 27001 Surveillance Audit 2024',audit_type:'certification',status:'completed',score:87},
    {id:'a2',title:'PCI DSS QSA Assessment',audit_type:'external',status:'in_progress',score:null},
    {id:'a3',title:'SOC 2 Type II Readiness',audit_type:'readiness',status:'completed',score:79},
    {id:'a4',title:'DORA Gap Analysis',audit_type:'gap_analysis',status:'completed',score:65},
    {id:'a5',title:'Penetration Test Q2 2024',audit_type:'pentest',status:'completed',score:72},
  ]}),
  '/dfir/cases': () => ({success:true, data:[
    {id:'f1',title:'Ransomware Incident — Finance BU',status:'active',severity:'critical',lead_analyst:'alice@corp.com',timeline:[1,2,3,4,5],artifacts:[1,2,3,4],created_at:new Date(Date.now()-3*86400000)},
    {id:'f2',title:'Phishing Campaign — Executive Team',status:'contained',severity:'high',lead_analyst:'bob@corp.com',timeline:[1,2,3],artifacts:[1,2],created_at:new Date(Date.now()-8*86400000)},
    {id:'f3',title:'Insider Threat — Data Exfiltration',status:'closed',severity:'high',lead_analyst:'carol@corp.com',timeline:[1,2,3,4,5,6],artifacts:[1,2,3],created_at:new Date(Date.now()-21*86400000)},
    {id:'f4',title:'Supply Chain Backdoor Discovery',status:'active',severity:'critical',lead_analyst:'dave@corp.com',timeline:[1,2],artifacts:[1],created_at:new Date(Date.now()-1*86400000)},
    {id:'f5',title:'Business Email Compromise — Finance',status:'closed',severity:'medium',lead_analyst:'alice@corp.com',timeline:[1,2,3],artifacts:[1,2],created_at:new Date(Date.now()-35*86400000)},
  ]}),
  '/risk-register': () => ({success:true, data:[
    {id:'r1',title:'Ransomware Attack on Core Systems',category:'Cyber',inherent_likelihood:'critical',residual_likelihood:'high',treatment_strategy:'mitigate',ale_estimate:4200000,priority_score:94},
    {id:'r2',title:'Third-Party Data Breach',category:'Vendor',inherent_likelihood:'high',residual_likelihood:'medium',treatment_strategy:'transfer',ale_estimate:1800000,priority_score:72},
    {id:'r3',title:'Cloud Misconfiguration Exposure',category:'Cloud',inherent_likelihood:'high',residual_likelihood:'low',treatment_strategy:'mitigate',ale_estimate:950000,priority_score:61},
    {id:'r4',title:'Regulatory Non-Compliance (GDPR)',category:'Compliance',inherent_likelihood:'medium',residual_likelihood:'low',treatment_strategy:'accept',ale_estimate:500000,priority_score:45},
    {id:'r5',title:'DDoS on Public-Facing Services',category:'Availability',inherent_likelihood:'high',residual_likelihood:'medium',treatment_strategy:'mitigate',ale_estimate:720000,priority_score:58},
    {id:'r6',title:'Insider Threat — Privileged Access',category:'People',inherent_likelihood:'medium',residual_likelihood:'medium',treatment_strategy:'mitigate',ale_estimate:1100000,priority_score:67},
  ], total:6}),
  '/connectors': () => ({success:true, data:[
    {id:'co1',name:'crowdstrike',display_name:'CrowdStrike Falcon',category:'edr',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-900000),results_count:12483},
    {id:'co2',name:'sentinel',display_name:'Microsoft Sentinel',category:'siem',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-300000),results_count:89234},
    {id:'co3',name:'tenable',display_name:'Tenable.io',category:'vm',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-3600000),results_count:4193},
    {id:'co4',name:'splunk',display_name:'Splunk SIEM',category:'siem',connector_type:'api',enabled:false,last_run_at:new Date(Date.now()-86400000),results_count:0},
    {id:'co5',name:'qualys',display_name:'Qualys VMDR',category:'vm',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-7200000),results_count:3847},
    {id:'co6',name:'servicenow',display_name:'ServiceNow ITSM',category:'ticketing',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-1800000),results_count:267},
    {id:'co7',name:'jira',display_name:'Jira / Atlassian',category:'ticketing',connector_type:'api',enabled:false,last_run_at:null,results_count:0},
    {id:'co8',name:'aws_security_hub',display_name:'AWS Security Hub',category:'cloud',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-600000),results_count:1923},
    {id:'co9',name:'azure_defender',display_name:'Microsoft Defender for Cloud',category:'cloud',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-120000),results_count:3312},
    {id:'co10',name:'virustotal',display_name:'VirusTotal Enterprise',category:'threat_intel',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-450000),results_count:891},
    {id:'co11',name:'shodan',display_name:'Shodan',category:'osint',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-21600000),results_count:312},
    {id:'co12',name:'misp',display_name:'MISP Threat Intel',category:'threat_intel',connector_type:'api',enabled:true,last_run_at:new Date(Date.now()-3600000),results_count:5621},
  ], total:1247}),
  '/ransomware': () => ({success:true, data:[
    {id:'rs1',threat_actor:'LockBit 3.0',computed_at:new Date(Date.now()-86400000),total_sle:8400000,total_ale:1680000,residual_with_controls:420000,aro_estimate:0.2,blast_radius_count:187,
     affected_assets:[{asset_name:'ERP-Core-Prod',value_at_risk:3200000,internet_exposed:false},{asset_name:'web-prod-01',value_at_risk:890000,internet_exposed:true},{asset_name:'db-finance',value_at_risk:2100000,internet_exposed:false},{asset_name:'backup-nas',value_at_risk:1500000,internet_exposed:false}]},
    {id:'rs2',threat_actor:'BlackCat (ALPHV)',computed_at:new Date(Date.now()-7*86400000),total_sle:6100000,total_ale:1220000,residual_with_controls:305000,aro_estimate:0.2,blast_radius_count:142},
    {id:'rs3',threat_actor:'Royal Ransomware',computed_at:new Date(Date.now()-14*86400000),total_sle:3900000,total_ale:780000,residual_with_controls:195000,aro_estimate:0.2,blast_radius_count:98},
  ]}),
  '/aoi': () => ({success:true, data: Array.from({length:30},(_,i)=>({
    id:'aoi-'+i, aoi_score: 580-(i*8)+(Math.sin(i)*40), computed_at:new Date(Date.now()-i*86400000),
    choke_points:i===0?['n4','n8']:[], attack_path_gaps:i===0?['T1190','T1021','T1078']:[]
  }))}),
  '/sigma-rules': () => ({success:true, data:[
    {id:'sg1',title:'Suspicious PowerShell Download Cradle',level:'high',status:'stable',attack_techniques:['T1059.001'],source:'sigma-community',enabled:true},
    {id:'sg2',title:'Mimikatz LSASS Dump Detection',level:'critical',status:'stable',attack_techniques:['T1003.001'],source:'sigma-community',enabled:true},
    {id:'sg3',title:'Kerberoasting via SetSPN',level:'high',status:'stable',attack_techniques:['T1558.003'],source:'sigma-community',enabled:true},
    {id:'sg4',title:'Abnormal WMI Activity',level:'medium',status:'test',attack_techniques:['T1047'],source:'custom',enabled:true},
    {id:'sg5',title:'Pass-the-Hash via NTLM',level:'high',status:'stable',attack_techniques:['T1550.002'],source:'sigma-community',enabled:true},
    {id:'sg6',title:'Living-off-the-Land Binary (LOLBin)',level:'high',status:'stable',attack_techniques:['T1218'],source:'sigma-community',enabled:true},
    {id:'sg7',title:'DNS Tunneling via Long Subdomains',level:'medium',status:'experimental',attack_techniques:['T1071.004'],source:'ai-generated',enabled:false},
    {id:'sg8',title:'RDP Brute Force Detection',level:'medium',status:'stable',attack_techniques:['T1110.001'],source:'sigma-community',enabled:true},
    {id:'sg9',title:'Cobalt Strike Beacon via Named Pipe',level:'critical',status:'stable',attack_techniques:['T1573'],source:'sigma-community',enabled:true},
    {id:'sg10',title:'Azure AD Suspicious OAuth App',level:'high',status:'test',attack_techniques:['T1550.001'],source:'custom',enabled:true},
    {id:'sg11',title:'Scheduled Task Creation for Persistence',level:'medium',status:'stable',attack_techniques:['T1053.005'],source:'sigma-community',enabled:true},
    {id:'sg12',title:'Credential Dumping via ProcDump',level:'high',status:'stable',attack_techniques:['T1003'],source:'sigma-community',enabled:false},
  ], total:3750}),
  '/crisis/scenarios': () => ({success:true, data:[
    {id:'cs1',name:'Ransomware Outbreak — Hospital BU',scenario_type:'ransomware'},
    {id:'cs2',name:'Mega-DDoS on Payment Gateway',scenario_type:'ddos'},
    {id:'cs3',name:'Insider Data Exfiltration',scenario_type:'insider_threat'},
    {id:'cs4',name:'Supply Chain Software Backdoor',scenario_type:'supply_chain'},
    {id:'cs5',name:'Critical Infrastructure Attack (OT)',scenario_type:'ot_attack'},
    {id:'cs6',name:'Nation-State APT Breach',scenario_type:'apt'},
  ]}),
  '/crisis/exercises': () => ({success:true, data:[
    {id:'ce1',title:'Ransomware Response TTX Q2 2024',status:'completed',readiness_score:78,created_at:new Date(Date.now()-30*86400000)},
    {id:'ce2',title:'DDoS Playbook Validation',status:'completed',readiness_score:84,created_at:new Date(Date.now()-60*86400000)},
    {id:'ce3',title:'GDPR Breach Notification Drill',status:'in_progress',readiness_score:62,created_at:new Date(Date.now()-5*86400000)},
    {id:'ce4',title:'OT/ICS Incident Response',status:'planned',readiness_score:0,created_at:new Date(Date.now()-1*86400000)},
  ]}),
  '/tprm/vendors': () => ({success:true, data:[
    {id:'v1',name:'Acme Cloud Services',vendor_type:'cloud_provider',risk_tier:'critical',risk_score:72,assessment_status:'completed'},
    {id:'v2',name:'DataSync Analytics',vendor_type:'data_processor',risk_tier:'high',risk_score:58,assessment_status:'in_progress'},
    {id:'v3',name:'SecureComm Ltd',vendor_type:'security_tool',risk_tier:'medium',risk_score:34,assessment_status:'completed'},
    {id:'v4',name:'GlobalPay Processor',vendor_type:'payment',risk_tier:'critical',risk_score:81,assessment_status:'overdue'},
    {id:'v5',name:'DevBridge Outsourcing',vendor_type:'software_dev',risk_tier:'high',risk_score:64,assessment_status:'pending'},
    {id:'v6',name:'NetGuard ISP',vendor_type:'network',risk_tier:'medium',risk_score:28,assessment_status:'completed'},
  ]}),
  '/sbom': () => ({success:true, data:[
    {id:'sb1',name:'ERP Core v4.2 SBOM',sbom_format:'SPDX',component_count:1847,vuln_count:23,license_issues:4},
    {id:'sb2',name:'Payment Service SBOM',sbom_format:'CycloneDX',component_count:634,vuln_count:8,license_issues:1},
    {id:'sb3',name:'Mobile App v3.1 SBOM',sbom_format:'CycloneDX',component_count:892,vuln_count:31,license_issues:7},
    {id:'sb4',name:'API Gateway SBOM',sbom_format:'SPDX',component_count:412,vuln_count:5,license_issues:2},
    {id:'sb5',name:'Data Pipeline SBOM',sbom_format:'CycloneDX',component_count:1123,vuln_count:14,license_issues:3},
  ]}),
  '/insurance-readiness': () => ({success:true, data:{
    overall_score:73, policy_limit:10000000, coverage_adequate:true,
    controls_status:{mfa:true,edr:true,backups:true,segmentation:false,patch_mgmt:true,ir_plan:true,encryption:true,phishing_training:false,privileged_access_mgmt:true,logging_monitoring:true}
  }}),
  '/pqcmm': () => ({success:true, data:[
    {id:'pq1',name:'TLS/PKI Infrastructure',current_level:2,target_level:4,quantum_vulnerable:true,cbom_present:false},
    {id:'pq2',name:'Email Encryption (S/MIME)',current_level:1,target_level:3,quantum_vulnerable:true,cbom_present:false},
    {id:'pq3',name:'VPN Gateway',current_level:2,target_level:4,quantum_vulnerable:true,cbom_present:true},
    {id:'pq4',name:'Key Management Service',current_level:3,target_level:5,quantum_vulnerable:false,cbom_present:true},
  ]}),
  '/ebios': () => ({success:true, data:[
    {id:'eb1',name:'Digital Banking Platform Risk Study',status:'Workshop 3 — Strategic Scenarios',express_mode:false,owner_email:'alice@corp.com',updated_at:new Date(Date.now()-2*86400000)},
    {id:'eb2',name:'Supply Chain Express Assessment',status:'Completed',express_mode:true,owner_email:'bob@corp.com',updated_at:new Date(Date.now()-7*86400000)},
  ]}),
  '/nist-800-30': () => ({success:true, data:[
    {id:'ni1',name:'Cloud Infrastructure Risk Assessment',status:'completed',owner_email:'carol@corp.com',updated_at:new Date(Date.now()-14*86400000)},
    {id:'ni2',name:'Endpoint Security Threat Assessment',status:'in_progress',owner_email:'dave@corp.com',updated_at:new Date(Date.now()-3*86400000)},
  ]}),
  '/bia': () => ({success:true, data:[
    {id:'bia1',name:'Core Banking System',criticality:'critical',rto_hours:4,rpo_hours:1,financial_impact:2500000},
    {id:'bia2',name:'Payment Processing',criticality:'critical',rto_hours:2,rpo_hours:0.5,financial_impact:5000000},
    {id:'bia3',name:'Customer Portal',criticality:'high',rto_hours:8,rpo_hours:4,financial_impact:800000},
    {id:'bia4',name:'HR Platform',criticality:'medium',rto_hours:24,rpo_hours:8,financial_impact:150000},
  ]}),
  '/discovery': () => ({success:true, data:[
    {id:'d1',seed_domain:'corp.com',status:'completed',discovered_hosts:312,new_assets:28,run_mode:'passive',started_at:new Date(Date.now()-86400000)},
    {id:'d2',seed_domain:'api.corp.com',status:'completed',discovered_hosts:47,new_assets:4,run_mode:'passive',started_at:new Date(Date.now()-3*86400000)},
    {id:'d3',seed_domain:'legacy.corp.com',status:'failed',discovered_hosts:0,new_assets:0,run_mode:'live',started_at:new Date(Date.now()-7*86400000)},
  ]}),
  '/policies': () => ({success:true, data:[
    {id:'p1',title:'Information Security Policy',policy_type:'master',framework:'ISO 27001',status:'approved',owner_email:'ciso@corp.com',review_date:'2025-01-01'},
    {id:'p2',title:'Acceptable Use Policy',policy_type:'operational',framework:'ISO 27001',status:'approved',owner_email:'hr@corp.com',review_date:'2025-03-01'},
    {id:'p3',title:'Data Classification Policy',policy_type:'data',framework:'GDPR',status:'under_review',owner_email:'dpo@corp.com',review_date:'2024-12-01'},
    {id:'p4',title:'Incident Response Plan',policy_type:'procedure',framework:'NIST',status:'approved',owner_email:'soc@corp.com',review_date:'2025-06-01'},
    {id:'p5',title:'Business Continuity Plan',policy_type:'continuity',framework:'ISO 22301',status:'approved',owner_email:'bcm@corp.com',review_date:'2025-02-01'},
  ]}),
  '/jobs': () => ({success:true, data:[
    {id:'j1',name:'CVE Importer (NVD+CISA)',job_type:'cve_import',cron_expression:'0 * * * *',last_status:'success',last_run_at:new Date(Date.now()-3600000),enabled:true},
    {id:'j2',name:'Risk Score Compute',job_type:'risk_score',cron_expression:'*/30 * * * * *',last_status:'success',last_run_at:new Date(Date.now()-30000),enabled:true},
    {id:'j3',name:'Attack Path Recompute',job_type:'attack_paths',cron_expression:'*/15 * * * *',last_status:'success',last_run_at:new Date(Date.now()-900000),enabled:true},
    {id:'j4',name:'SLA Breach Check',job_type:'sla_check',cron_expression:'*/5 * * * *',last_status:'success',last_run_at:new Date(Date.now()-300000),enabled:true},
    {id:'j5',name:'TID Coverage Sync',job_type:'tid_sync',cron_expression:'0 0 * * *',last_status:'success',last_run_at:new Date(Date.now()-86400000),enabled:true},
  ]}),
  '/identities': () => ({success:true, data:[
    {id:'i1',display_name:'Alice Chen',identity_type:'human',email:'alice@corp.com',source:'EntraID',is_stale:false,mfa_enabled:true},
    {id:'i2',display_name:'Bob Kumar',identity_type:'human',email:'bob@corp.com',source:'EntraID',is_stale:false,mfa_enabled:true},
    {id:'i3',display_name:'svc-backup-agent',identity_type:'service',email:null,source:'local',is_stale:false,mfa_enabled:false},
    {id:'i4',display_name:'john.doe (departed)',identity_type:'human',email:'john.doe@corp.com',source:'EntraID',is_stale:true,mfa_enabled:false},
    {id:'i5',display_name:'k8s-sa-deploy',identity_type:'service',email:null,source:'kubernetes',is_stale:false,mfa_enabled:false},
    {id:'i6',display_name:'Carol Martinez',identity_type:'human',email:'carol@corp.com',source:'EntraID',is_stale:false,mfa_enabled:true},
  ]}),
  '/risk-score/compute': () => ({success:true, data:{enterprise_risk_score:59}}),
  '/attack-paths/compute': () => ({success:true, data:{paths_computed:14}}),
  '/vulnerabilities/match-assets': () => ({success:true, data:{matched:312}}),
  '/aoi/compute': () => ({success:true, data:{aoi_score:547}}),
  '/insurance-readiness/assess': () => ({success:true, data:{overall_score:76}}),
  '/discovery/run': () => ({success:true, data:{status:'started'}}),
};

// ── Mock resolver — matches path prefix to data generator ─────────────────────
function _mockResolve(path) {
  // Strip query string for matching
  const base = path.split('?')[0];
  // Exact match
  if (_MOCK[base]) return _MOCK[base]();
  // Prefix match (e.g. /connectors/xxx/run)
  for (const key of Object.keys(_MOCK)) {
    if (base.startsWith(key + '/') || base === key) return _MOCK[key]();
  }
  // Unknown → empty success
  return { success: true, data: [], total: 0 };
}

async function nexusApi(path, opts = {}) {
  // ── Demo mode: return mock data immediately, no network call ──────────────
  // Set window.NEXUS_LIVE_API = true and window.API_BASE_URL to enable real calls.
  const liveMode = (typeof window !== 'undefined' && window.NEXUS_LIVE_API === true && window.API_BASE_URL);
  if (!liveMode) {
    // Simulate ~60ms network latency for realism
    await new Promise(r => setTimeout(r, 60));
    return _mockResolve(path);
  }

  // ── Live mode (backend available) ────────────────────────────────────────
  const token    = localStorage.getItem('wadjet_token') || localStorage.getItem('auth_token');
  const tenantId = localStorage.getItem('tenant_id');
  const headers  = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (token)    headers['Authorization']  = `Bearer ${token}`;
  if (tenantId) headers['X-Tenant-ID']    = tenantId;

  const url = `${API_BASE}/api/nexus${path}`;
  const response = await fetch(url, { ...opts, headers });

  if (!response.ok) {
    const errData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    throw new Error(errData.error || `API error ${response.status}`);
  }
  return response.json();
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function h(s) { return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtNum(n, dec = 0) { return (n ?? 0).toLocaleString('en-US', { maximumFractionDigits: dec }); }
function fmtCurrency(n) { return '$' + fmtNum(n, 0); }
function fmtPct(n) { return `${Math.round(n ?? 0)}%`; }
function ago(ts) {
  if (!ts) return 'Never';
  const d = Date.now() - new Date(ts).getTime();
  if (d < 60000) return 'Just now';
  if (d < 3600000) return `${Math.round(d/60000)}m ago`;
  if (d < 86400000) return `${Math.round(d/3600000)}h ago`;
  return `${Math.round(d/86400000)}d ago`;
}
function sev(s) {
  const col = SEVERITY_COLOR[s] || DS.textMuted;
  return `<span style="color:${col};font-weight:600;text-transform:uppercase;font-size:11px;">${h(s)}</span>`;
}
function badge(label, color = DS.accent, bg = 'rgba(59,130,246,0.15)') {
  return `<span style="background:${bg};color:${color};padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;">${h(label)}</span>`;
}
function scoreRing(score, max = 100, color = DS.accent) {
  const pct = Math.min(100, (score / max) * 100);
  const r = 28; const c = 2 * Math.PI * r;
  const dash = (pct / 100) * c;
  return `<svg width="68" height="68" viewBox="0 0 68 68">
    <circle cx="34" cy="34" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="6"/>
    <circle cx="34" cy="34" r="${r}" fill="none" stroke="${color}" stroke-width="6"
      stroke-dasharray="${dash} ${c}" stroke-dashoffset="${c * 0.25}" stroke-linecap="round"
      style="transition:stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)"/>
    <text x="34" y="39" text-anchor="middle" fill="${DS.text}" font-size="13" font-weight="700">${Math.round(score)}</text>
  </svg>`;
}

// ── State ─────────────────────────────────────────────────────────────────────
const NX = {
  tab: 'nexus-dashboard',
  currentEl: null,         // the active page-nexus-* div
  data: {},
  filters: {},
  loading: {},
  d3Graphs: {},
};

// ── Module Container ──────────────────────────────────────────────────────────
// Single-hub architecture: all 16 nav items point to one 'page-nexus' div.
// The platform (main.js) only manages ONE page toggle (nexus ↔ other pages).
// The Nexus module's own sidebar handles all internal sub-navigation.
//
// Container resolution priority:
//  1. An element explicitly passed by PAGE_CONFIG onEnter (page-nexus div)
//  2. The cached NX.currentEl from the last explicit call
//  3. The active .page.active element whose id starts with page-nexus
//  4. The single #page-nexus hub div
function getContainer(explicitEl) {
  if (explicitEl && explicitEl.nodeType === 1) return explicitEl;
  if (NX.currentEl && NX.currentEl.nodeType === 1) return NX.currentEl;
  const active = document.querySelector('.page.active[id^="page-nexus"]');
  if (active) return active;
  // Single-hub fallback: the one hub div
  return document.getElementById('page-nexus') ||
         document.querySelector('[id^="page-nexus"]');
}

// ══════════════════════════════════════════════════════════════════════════════
//  MAIN RENDER DISPATCH
// ══════════════════════════════════════════════════════════════════════════════
// renderNexusPage(page, el)
//   page  — internal sub-page key (e.g. 'nexus-dashboard')
//   el    — the page-nexus div passed by PAGE_CONFIG onEnter
//
// ⚠ CRITICAL: NEVER use container.style.cssText — it replaces ALL inline styles
// and will erase the display:'' that main.js sets so .page.active{display:block}
// can take effect.  Always use individual style property assignments.
function renderNexusPage(page, el) {
  const container = getContainer(el);
  if (!container) {
    console.warn('[NexusModule] No container found for page:', page);
    return;
  }
  NX.currentEl = container;
  NX.tab = page;

  // ── Apply layout styles without touching display ──────────────────────────
  // MUST use individual properties — cssText would wipe the display:'' set by
  // main.js navigateTo(), causing the browser to fall back to the CSS rule
  // .page { display:none } and hide the entire page.
  container.style.overflowY  = 'auto';
  container.style.height     = '100%';
  container.style.minHeight  = '400px';
  container.style.padding    = '0';
  container.style.background = DS.bg;

  container.innerHTML = `<div class="nexus-wrapper" style="display:flex;min-height:100%;background:${DS.bg};">${nexusShell(page)}</div>`;
  dispatchPage(page);
}

function nexusShell(page) {
  const tabs = [
    { id: 'nexus-dashboard',    icon: 'fa-shield-halved',    label: 'Risk Dashboard',      group: 'executive' },
    { id: 'nexus-ctem',         icon: 'fa-bullseye',          label: 'CTEM / VOC',          group: 'executive' },
    { id: 'nexus-aoi',          icon: 'fa-crosshairs',        label: 'Adversary Index',     group: 'executive' },
    { id: 'nexus-vuln',         icon: 'fa-bug',               label: 'Vulnerabilities',     group: 'exposure' },
    { id: 'nexus-path',         icon: 'fa-diagram-project',   label: 'Attack Paths',        group: 'exposure' },
    { id: 'nexus-disc',         icon: 'fa-radar',             label: 'Attack Surface',      group: 'exposure' },
    { id: 'nexus-hunt',         icon: 'fa-magnifying-glass',  label: 'Threat Hunting',      group: 'detection' },
    { id: 'nexus-sigma',        icon: 'fa-file-code',         label: 'Sigma Rules',         group: 'detection' },
    { id: 'nexus-tid',          icon: 'fa-chess-king',        label: 'TID Cockpit',         group: 'detection' },
    { id: 'nexus-mitre',        icon: 'fa-table',             label: 'MITRE ATT&CK',        group: 'detection' },
    { id: 'nexus-kill',         icon: 'fa-link',              label: 'Kill Chain',          group: 'detection' },
    { id: 'nexus-bas',          icon: 'fa-flask-vial',        label: 'BAS / Emulation',     group: 'offense' },
    { id: 'nexus-pentest',      icon: 'fa-terminal',          label: 'Pentests',            group: 'offense' },
    { id: 'nexus-dfir',         icon: 'fa-microscope',        label: 'DFIR Forensics',      group: 'response' },
    { id: 'nexus-risk',         icon: 'fa-scale-balanced',    label: 'Risk Register',       group: 'grc' },
    { id: 'nexus-grc',          icon: 'fa-certificate',       label: 'GRC Controls',        group: 'grc' },
    { id: 'nexus-ebios',        icon: 'fa-sitemap',           label: 'EBIOS RM',            group: 'grc' },
    { id: 'nexus-nist',         icon: 'fa-landmark',          label: 'NIST 800-30',         group: 'grc' },
    { id: 'nexus-policy',       icon: 'fa-file-shield',       label: 'Policies',            group: 'grc' },
    { id: 'nexus-tprm',         icon: 'fa-handshake',         label: 'TPRM',                group: 'grc' },
    { id: 'nexus-sbom',         icon: 'fa-cubes',             label: 'SBOM / SCA',          group: 'supply' },
    { id: 'nexus-pqcmm',        icon: 'fa-atom',              label: 'Quantum Readiness',   group: 'grc' },
    { id: 'nexus-ransom',       icon: 'fa-lock',              label: 'Ransomware Scenario', group: 'risk' },
    { id: 'nexus-insure',       icon: 'fa-umbrella',          label: 'Insurance Readiness', group: 'risk' },
    { id: 'nexus-fairmam',      icon: 'fa-chart-bar',         label: 'FAIR-MAM',            group: 'risk' },
    { id: 'nexus-crisis',       icon: 'fa-triangle-exclamation', label: 'Crisis Mgmt',      group: 'response' },
    { id: 'nexus-bia',          icon: 'fa-building-shield',   label: 'BIA',                 group: 'response' },
    { id: 'nexus-ident',        icon: 'fa-user-shield',       label: 'Identities',          group: 'iam' },
    { id: 'nexus-conn',         icon: 'fa-plug',              label: 'Connectors',          group: 'integrations' },
    { id: 'nexus-jobs',         icon: 'fa-clock',             label: 'Scheduler',           group: 'integrations' },
    { id: 'nexus-yara',         icon: 'fa-code',              label: 'YARA Rules',          group: 'detection' },
  ];

  const groups = {
    executive: { label: 'Executive', icon: 'fa-chart-pie' },
    exposure:  { label: 'Exposure Management', icon: 'fa-eye' },
    detection: { label: 'Detection & Hunting', icon: 'fa-radar' },
    offense:   { label: 'Offense & Validation', icon: 'fa-sword' },
    response:  { label: 'Response & Recovery', icon: 'fa-shield' },
    grc:       { label: 'GRC & Compliance', icon: 'fa-certificate' },
    supply:    { label: 'Supply Chain', icon: 'fa-box' },
    risk:      { label: 'Risk Quantification', icon: 'fa-balance-scale' },
    iam:       { label: 'Identity', icon: 'fa-user-lock' },
    integrations: { label: 'Integrations', icon: 'fa-plug' },
  };

  const groupedTabs = {};
  tabs.forEach(t => {
    if (!groupedTabs[t.group]) groupedTabs[t.group] = [];
    groupedTabs[t.group].push(t);
  });

  const navHTML = Object.entries(groups).map(([grp, grpData]) => {
    if (!groupedTabs[grp]) return '';
    const children = groupedTabs[grp].map(t => `
      <button onclick="NexusModule.goto('${t.id}')"
        class="nx-tab${page === t.id ? ' nx-tab--active' : ''}"
        data-tab="${t.id}">
        <i class="fas ${t.icon}" style="width:16px;text-align:center;"></i>
        <span>${t.label}</span>
      </button>
    `).join('');
    return `
      <div class="nx-nav-group">
        <div class="nx-nav-group-header">
          <i class="fas ${grpData.icon}"></i>${grpData.label}
        </div>
        ${children}
      </div>`;
  }).join('');

  return `
    <style>
      .nexus-wrapper { display:flex; gap:0; font-family:'Inter',system-ui,sans-serif; }
      .nx-sidebar {
        width:220px; min-width:220px; background:${DS.bgCard};
        border-right:1px solid ${DS.border};
        min-height:100%; height:auto;
        overflow-y:auto; padding:12px 8px;
        align-self:stretch;
        scrollbar-width:thin; scrollbar-color:${DS.border} transparent;
      }
      .nx-sidebar-brand {
        display:flex; align-items:center; gap:10px; padding:12px 8px 20px;
        border-bottom:1px solid ${DS.border}; margin-bottom:12px;
      }
      .nx-sidebar-logo { font-size:20px; color:${DS.accent}; }
      .nx-sidebar-name { font-size:14px; font-weight:700; color:${DS.text};
        letter-spacing:0.5px; }
      .nx-sidebar-sub  { font-size:10px; color:${DS.textMuted}; letter-spacing:1px;
        text-transform:uppercase; }
      .nx-nav-group { margin-bottom:4px; }
      .nx-nav-group-header {
        font-size:10px; text-transform:uppercase; letter-spacing:1px;
        color:${DS.textMuted}; padding:8px 8px 4px; display:flex;
        align-items:center; gap:6px;
      }
      .nx-tab {
        display:flex; align-items:center; gap:8px; width:100%;
        padding:7px 10px; border:none; background:transparent; cursor:pointer;
        color:${DS.textMuted}; font-size:12px; border-radius:6px;
        transition:all 0.15s; text-align:left;
      }
      .nx-tab:hover { background:rgba(59,130,246,0.1); color:${DS.text}; }
      .nx-tab--active { background:rgba(59,130,246,0.18); color:${DS.accent};
        font-weight:600; }
      .nx-content {
        flex:1; min-width:0; padding:0 24px 24px; overflow-y:auto;
        min-height:400px; height:100%;
      }
      .nx-page-header {
        display:flex; align-items:center; gap:12px; padding:20px 0 16px;
        border-bottom:1px solid ${DS.border}; margin-bottom:24px;
      }
      .nx-page-title { font-size:20px; font-weight:700; color:${DS.text}; }
      .nx-page-sub   { font-size:12px; color:${DS.textMuted}; margin-top:2px; }
      .nx-page-icon  { width:40px; height:40px; border-radius:10px;
        background:rgba(59,130,246,0.15); display:flex; align-items:center;
        justify-content:center; font-size:18px; color:${DS.accent}; flex-shrink:0; }
      .nx-card {
        background:${DS.bgCard}; border:1px solid ${DS.border}; border-radius:12px;
        padding:20px; margin-bottom:16px;
      }
      .nx-card-title { font-size:13px; font-weight:600; color:${DS.text};
        margin-bottom:16px; display:flex; align-items:center; gap:8px; }
      .nx-grid { display:grid; gap:16px; }
      .nx-grid-2 { grid-template-columns:repeat(2,1fr); }
      .nx-grid-3 { grid-template-columns:repeat(3,1fr); }
      .nx-grid-4 { grid-template-columns:repeat(4,1fr); }
      .nx-kpi {
        background:${DS.bgCard}; border:1px solid ${DS.border}; border-radius:12px;
        padding:18px 20px; position:relative; overflow:hidden;
        transition:border-color 0.2s, box-shadow 0.2s;
      }
      .nx-kpi:hover { border-color:${DS.accent}; box-shadow:0 0 20px ${DS.glow}; }
      .nx-kpi::before {
        content:''; position:absolute; top:0; left:0; right:0; height:2px;
        background:linear-gradient(90deg,${DS.accent},${DS.purple});
      }
      .nx-kpi-val { font-size:28px; font-weight:800; color:${DS.text};
        font-variant-numeric:tabular-nums; }
      .nx-kpi-label { font-size:11px; color:${DS.textMuted}; text-transform:uppercase;
        letter-spacing:0.8px; margin-top:4px; }
      .nx-kpi-trend { font-size:12px; margin-top:8px; }
      .nx-table { width:100%; border-collapse:collapse; }
      .nx-table th { font-size:11px; text-transform:uppercase; letter-spacing:0.8px;
        color:${DS.textMuted}; padding:10px 12px; text-align:left;
        border-bottom:1px solid ${DS.border}; font-weight:600; }
      .nx-table td { padding:11px 12px; border-bottom:1px solid rgba(255,255,255,0.04);
        font-size:13px; color:${DS.text}; }
      .nx-table tr:hover td { background:rgba(59,130,246,0.05); }
      .nx-table tr:last-child td { border-bottom:none; }
      .nx-btn {
        display:inline-flex; align-items:center; gap:6px; padding:8px 16px;
        border-radius:8px; border:none; cursor:pointer; font-size:13px;
        font-weight:600; transition:all 0.15s;
      }
      .nx-btn-primary { background:${DS.accent}; color:#fff; }
      .nx-btn-primary:hover { background:${DS.accentG}; box-shadow:0 0 16px ${DS.glow}; }
      .nx-btn-ghost { background:transparent; color:${DS.accent};
        border:1px solid ${DS.border}; }
      .nx-btn-ghost:hover { background:rgba(59,130,246,0.1); }
      .nx-btn-danger { background:rgba(239,68,68,0.15); color:${DS.red};
        border:1px solid rgba(239,68,68,0.3); }
      .nx-search {
        background:rgba(255,255,255,0.05); border:1px solid ${DS.border};
        border-radius:8px; padding:8px 14px; color:${DS.text}; font-size:13px;
        width:260px; outline:none;
      }
      .nx-search:focus { border-color:${DS.accent}; box-shadow:0 0 0 3px ${DS.glow}; }
      .nx-select {
        background:${DS.bgPanel}; border:1px solid ${DS.border}; border-radius:8px;
        padding:8px 12px; color:${DS.text}; font-size:13px; cursor:pointer; outline:none;
      }
      .nx-progress { height:6px; border-radius:3px; background:rgba(255,255,255,0.08);
        overflow:hidden; }
      .nx-progress-fill { height:100%; border-radius:3px; transition:width 1s ease; }
      .nx-risk-ring { display:flex; flex-direction:column; align-items:center; gap:8px; }
      .nx-loader { display:flex; align-items:center; justify-content:center;
        padding:60px 0; color:${DS.textMuted}; gap:12px; font-size:14px; }
      .nx-empty { text-align:center; padding:60px 0; color:${DS.textMuted}; }
      .nx-timeline { list-style:none; padding:0; position:relative; }
      .nx-timeline::before { content:''; position:absolute; left:16px; top:0; bottom:0;
        width:2px; background:${DS.border}; }
      .nx-timeline-item { display:flex; gap:16px; margin-bottom:16px; position:relative; }
      .nx-timeline-dot { width:32px; height:32px; border-radius:50%; flex-shrink:0;
        display:flex; align-items:center; justify-content:center; font-size:12px;
        position:relative; z-index:1; }
      .nx-badge { display:inline-flex; align-items:center; gap:4px; padding:3px 10px;
        border-radius:20px; font-size:11px; font-weight:600; }
      .nx-badge-critical { background:rgba(239,68,68,0.15); color:${DS.red}; }
      .nx-badge-high { background:rgba(249,115,22,0.15); color:${DS.orange}; }
      .nx-badge-medium { background:rgba(234,179,8,0.15); color:${DS.yellow}; }
      .nx-badge-low { background:rgba(34,197,94,0.15); color:${DS.green}; }
      .nx-badge-info { background:rgba(6,182,212,0.15); color:${DS.cyan}; }
      .nx-heatmap-cell { border-radius:4px; cursor:pointer; transition:opacity 0.15s; }
      .nx-heatmap-cell:hover { opacity:0.8; }
      @keyframes nx-pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
      .nx-pulse { animation:nx-pulse 2s infinite; }
      @keyframes nx-slide-in { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
      .nx-slide-in { animation:nx-slide-in 0.3s ease; }
      @media (max-width:768px) {
        .nexus-wrapper { flex-direction:column; }
        .nx-sidebar { width:100%; height:auto; position:static; }
        .nx-grid-4 { grid-template-columns:repeat(2,1fr); }
        .nx-grid-3 { grid-template-columns:repeat(2,1fr); }
      }
    </style>

    <div class="nx-sidebar">
      <div class="nx-sidebar-brand">
        <div class="nx-sidebar-logo"><i class="fas fa-shield-halved"></i></div>
        <div>
          <div class="nx-sidebar-name">Wadjet Nexus</div>
          <div class="nx-sidebar-sub">Cyber Risk Platform</div>
        </div>
      </div>
      ${navHTML}
    </div>
    <div class="nx-content" id="nx-content">
      <div class="nx-loader"><i class="fas fa-spinner fa-spin"></i> Loading module...</div>
    </div>`;
}

function dispatchPage(page) {
  const map = {
    // ── Internal short-keys (used by within-module NexusModule.goto() calls) ──
    'nexus-dashboard':    renderDashboard,
    'nexus-ctem':         renderCTEM,
    'nexus-vuln':         renderVulnerabilities,
    'nexus-path':         renderAttackPaths,
    'nexus-grc':          renderGRC,
    'nexus-hunt':         renderThreatHunting,
    'nexus-bas':          renderBAS,
    'nexus-dfir':         renderDFIR,
    'nexus-tid':          renderTID,
    'nexus-mitre':        renderMITRE,
    'nexus-kill':         renderKillChain,
    'nexus-risk':         renderRiskRegister,
    'nexus-tprm':         renderTPRM,
    'nexus-sbom':         renderSBOM,
    'nexus-crisis':       renderCrisis,
    'nexus-conn':         renderConnectors,
    'nexus-ransom':       renderRansomware,
    'nexus-aoi':          renderAOI,
    'nexus-insure':       renderInsurance,
    'nexus-pqcmm':        renderPQCMM,
    'nexus-pentest':      renderPentest,
    'nexus-sigma':        renderSigma,
    'nexus-yara':         renderYARA,
    'nexus-ebios':        renderEBIOS,
    'nexus-nist':         renderNIST,
    'nexus-bia':          renderBIA,
    'nexus-disc':         renderDiscovery,
    'nexus-policy':       renderPolicies,
    'nexus-jobs':         renderJobs,
    'nexus-ident':        renderIdentities,
    'nexus-fairmam':      renderFAIRMAM,
    // ── Full page-IDs used by the sidebar nav & PAGE_CONFIG wiring ──
    // These map the data-page values (e.g. "nexus-vulnerabilities") to renderers
    'nexus-vulnerabilities': renderVulnerabilities,
    'nexus-attack-paths':    renderAttackPaths,
    'nexus-threat-hunting':  renderThreatHunting,
    'nexus-risk-register':   renderRiskRegister,
    'nexus-connectors':      renderConnectors,
    'nexus-kill-chain':      renderKillChain,
    'nexus-ransomware':      renderRansomware,
    'nexus-insurance':       renderInsurance,
    'nexus-identities':      renderIdentities,
    'nexus-fair-mam':        renderFAIRMAM,
    'nexus-discovery':       renderDiscovery,
    'nexus-policies':        renderPolicies,
    'nexus-scheduler':       renderJobs,
    'nexus-ai-guardrails':   renderPolicies,   // reuse Policies layout until dedicated renderer added
  };
  const fn = map[page];
  if (fn) fn();
  else setContent(`<div class="nx-empty"><i class="fas fa-construction" style="font-size:48px;color:${DS.textMuted};margin-bottom:16px;display:block;"></i>Module coming soon</div>`);
}

function setContent(html) {
  // Primary: the inner #nx-content div rendered by nexusShell
  let el = document.getElementById('nx-content');
  // Fallback: write directly into the current page container
  // ⚠ DO NOT use cssText — individual properties only, to preserve display:''
  if (!el && NX.currentEl) {
    el = NX.currentEl;
    el.style.overflowY  = 'auto';
    el.style.height     = '100%';
    el.style.minHeight  = '400px';
    el.style.padding    = '24px';
    el.style.background = DS.bg;
  }
  if (el) { el.innerHTML = html; el.classList.add('nx-slide-in'); }
}

function pageHeader(icon, title, subtitle, actions = '') {
  return `<div class="nx-page-header">
    <div class="nx-page-icon"><i class="fas ${icon}"></i></div>
    <div style="flex:1">
      <div class="nx-page-title">${title}</div>
      <div class="nx-page-sub">${subtitle}</div>
    </div>
    <div style="display:flex;gap:8px;">${actions}</div>
  </div>`;
}

function loader() {
  return `<div class="nx-loader"><i class="fas fa-spinner fa-spin" style="color:${DS.accent};"></i> Loading...</div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  NEXUS DASHBOARD — Enterprise Risk Score
// ══════════════════════════════════════════════════════════════════════════════
async function renderDashboard() {
  setContent(pageHeader('fa-shield-halved', 'Nexus Risk Dashboard', 'Enterprise-wide cyber risk posture & exposure management') + loader());

  try {
    const { data } = await nexusApi('/dashboard');
    const kpis = data.kpis || {};
    const sevBreak = data.severity_breakdown || {};
    const topAssets = data.top_risky_assets || [];
    const riskScore = kpis.enterprise_risk_score || 0;

    const riskColor = riskScore > 70 ? DS.red : riskScore > 40 ? DS.orange : DS.green;
    const riskLabel = riskScore > 70 ? 'Critical' : riskScore > 40 ? 'Elevated' : 'Managed';

    const html = `
    ${pageHeader('fa-shield-halved', 'Nexus Risk Dashboard', 'Enterprise-wide cyber risk posture & exposure management',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.recomputeRisk()">
        <i class="fas fa-sync-alt"></i> Recompute Risk
      </button>`
    )}

    <!-- Enterprise Risk Score Banner -->
    <div class="nx-card" style="background:linear-gradient(135deg,${DS.bgCard} 0%,${DS.bgPanel} 100%);
      border-color:${riskColor}40;margin-bottom:24px;">
      <div style="display:flex;align-items:center;gap:32px;flex-wrap:wrap;">
        <div class="nx-risk-ring">
          ${scoreRing(riskScore, 100, riskColor)}
          <div style="font-size:11px;color:${DS.textMuted};text-transform:uppercase;letter-spacing:1px;">Enterprise Risk</div>
        </div>
        <div style="flex:1;">
          <div style="font-size:28px;font-weight:800;color:${riskColor};">${riskLabel} Risk</div>
          <div style="font-size:14px;color:${DS.textMuted};margin-top:4px;">
            Score ${riskScore}/100 — Computed continuously every 30 seconds
          </div>
          <div style="display:flex;gap:24px;margin-top:16px;flex-wrap:wrap;">
            ${[
              { label: 'Asset Hygiene', val: Math.round(kpis.asset_hygiene_score || 80), color: DS.green },
              { label: 'Open Risk', val: Math.round(kpis.open_risk_score || 30), color: DS.orange },
              { label: 'Compliance', val: Math.round(100 - (kpis.compliance_debt || 0)), color: DS.cyan },
            ].map(m => `<div>
              <div style="font-size:11px;color:${DS.textMuted};margin-bottom:4px;">${m.label}</div>
              <div style="font-size:20px;font-weight:700;color:${m.color};">${m.val}%</div>
            </div>`).join('')}
          </div>
        </div>
        <!-- Maturity Radar placeholder -->
        <div id="nx-maturity-radar" style="width:140px;height:140px;"></div>
      </div>
    </div>

    <!-- KPI Grid -->
    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      ${[
        { icon: 'fa-server', label: 'Total Assets', val: fmtNum(kpis.total_assets), sub: `${kpis.internet_exposed} internet-exposed`, color: DS.accent },
        { icon: 'fa-bug',    label: 'Open Vulnerabilities', val: fmtNum(kpis.total_vulns), sub: `${kpis.critical_vulns} critical`, color: DS.red },
        { icon: 'fa-fire',   label: 'CISA KEV', val: fmtNum(kpis.kev_vulns), sub: 'Actively exploited', color: DS.orange },
        { icon: 'fa-search', label: 'Active Hunts', val: fmtNum(kpis.open_hunts), sub: 'Open / in-progress', color: DS.purple },
        { icon: 'fa-certificate', label: 'Controls', val: fmtPct(kpis.controls_pct), sub: `${kpis.controls_implemented}/${kpis.controls_total} implemented`, color: DS.cyan },
        { icon: 'fa-triangle-exclamation', label: 'Critical Assets', val: fmtNum(kpis.critical_assets), sub: 'High-value targets', color: DS.yellow },
        { icon: 'fa-exclamation-triangle', label: 'High Severity', val: fmtNum(kpis.high_vulns), sub: 'CVEs requiring action', color: DS.orange },
        { icon: 'fa-eye', label: 'Exposure Score', val: Math.round(riskScore), sub: riskLabel + ' level', color: riskColor },
      ].map(k => `
        <div class="nx-kpi">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
            <i class="fas ${k.icon}" style="color:${k.color};font-size:16px;"></i>
            <span style="font-size:11px;color:${DS.textMuted};text-transform:uppercase;letter-spacing:0.8px;">${k.label}</span>
          </div>
          <div class="nx-kpi-val" style="color:${k.color};">${k.val}</div>
          <div style="font-size:11px;color:${DS.textMuted};margin-top:6px;">${k.sub}</div>
        </div>
      `).join('')}
    </div>

    <!-- Severity Breakdown + Top Risky Assets -->
    <div class="nx-grid nx-grid-2" style="margin-bottom:24px;">
      <div class="nx-card">
        <div class="nx-card-title"><i class="fas fa-chart-pie" style="color:${DS.accent};"></i> Vulnerability Severity Breakdown</div>
        <div id="nx-sev-chart" style="height:220px;display:flex;flex-direction:column;gap:12px;justify-content:center;">
          ${Object.entries(sevBreak).map(([sev, cnt]) => {
            const total = Object.values(sevBreak).reduce((s, c) => s + c, 0) || 1;
            const pct = Math.round((cnt / total) * 100);
            return `
            <div>
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:12px;color:${DS.text};text-transform:capitalize;">${sev}</span>
                <span style="font-size:12px;color:${SEVERITY_COLOR[sev] || DS.textMuted};font-weight:700;">${cnt} (${pct}%)</span>
              </div>
              <div class="nx-progress">
                <div class="nx-progress-fill" style="width:${pct}%;background:${SEVERITY_COLOR[sev] || DS.accent};"></div>
              </div>
            </div>`;
          }).join('')}
        </div>
      </div>

      <div class="nx-card">
        <div class="nx-card-title"><i class="fas fa-exclamation-circle" style="color:${DS.red};"></i> Top Risky Assets</div>
        <table class="nx-table">
          <thead><tr>
            <th>Asset</th><th>Risk Score</th><th>Criticality</th><th>Exposed</th>
          </tr></thead>
          <tbody>
            ${topAssets.slice(0, 6).map(a => `<tr>
              <td style="font-family:monospace;font-size:12px;">${h(a.hostname || a.ip_address || 'Unknown')}</td>
              <td><span style="color:${(a.risk_score||0) > 70 ? DS.red : (a.risk_score||0) > 40 ? DS.orange : DS.green};font-weight:700;">${Math.round(a.risk_score || 0)}</span></td>
              <td>${sev(a.criticality)}</td>
              <td>${a.internet_exposed ? `<span style="color:${DS.red};">&#9679; YES</span>` : `<span style="color:${DS.green};">&#9675; No</span>`}</td>
            </tr>`).join('')}
            ${topAssets.length === 0 ? '<tr><td colspan="4" class="nx-empty">No assets found</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-bolt" style="color:${DS.yellow};"></i> Quick Actions</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <button class="nx-btn nx-btn-primary" onclick="NexusModule.goto('nexus-vuln')">
          <i class="fas fa-bug"></i> Vulnerability Worklist
        </button>
        <button class="nx-btn nx-btn-primary" onclick="NexusModule.goto('nexus-path')">
          <i class="fas fa-diagram-project"></i> Attack Paths
        </button>
        <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-hunt')">
          <i class="fas fa-magnifying-glass"></i> Start Hunt
        </button>
        <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-tid')">
          <i class="fas fa-chess-king"></i> TID Cockpit
        </button>
        <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-ransom')">
          <i class="fas fa-lock"></i> Ransomware Scenario
        </button>
        <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-grc')">
          <i class="fas fa-certificate"></i> GRC Controls
        </button>
      </div>
    </div>`;

    setContent(html);
    drawMaturityRadar(data.recent_risk_score?.maturity_radar || {});

  } catch (e) {
    setContent(`<div class="nx-empty"><i class="fas fa-exclamation-circle" style="color:${DS.red};font-size:32px;margin-bottom:12px;display:block;"></i>Error loading dashboard: ${h(e.message)}</div>`);
  }
}

function drawMaturityRadar(data) {
  const el = document.getElementById('nx-maturity-radar');
  if (!el) return;
  const keys = ['detection', 'mitigation', 'validation', 'compliance', 'crisis_ready', 'risk_treated'];
  const labels = ['Detect', 'Mitigate', 'Validate', 'Comply', 'Crisis', 'Risk'];
  const vals = keys.map(k => Math.min(100, data[k] || 0));
  const n = keys.length;
  const cx = 70, cy = 70, R = 55;
  const angleStep = (2 * Math.PI) / n;

  const points = vals.map((v, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const r = (v / 100) * R;
    return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
  });

  const polyPts = points.map(p => p.join(',')).join(' ');
  const gridLines = [0.25, 0.5, 0.75, 1].map(f => {
    const ps = keys.map((_, i) => {
      const angle = i * angleStep - Math.PI / 2;
      return [cx + f * R * Math.cos(angle), cy + f * R * Math.sin(angle)].join(',');
    });
    return `<polygon points="${ps.join(' ')}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>`;
  }).join('');
  const axes = keys.map((_, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const lx = cx + R * Math.cos(angle), ly = cy + R * Math.sin(angle);
    const tx = cx + (R + 14) * Math.cos(angle), ty = cy + (R + 14) * Math.sin(angle);
    return `<line x1="${cx}" y1="${cy}" x2="${lx}" y2="${ly}" stroke="rgba(255,255,255,0.12)" stroke-width="1"/>
      <text x="${tx}" y="${ty + 4}" text-anchor="middle" fill="${DS.textMuted}" font-size="9">${labels[i]}</text>`;
  }).join('');

  el.innerHTML = `<svg width="140" height="140" viewBox="0 0 140 140">
    ${gridLines}${axes}
    <polygon points="${polyPts}" fill="rgba(59,130,246,0.25)" stroke="${DS.accent}" stroke-width="2"/>
    ${points.map(p => `<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="${DS.accent}"/>`).join('')}
  </svg>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  VULNERABILITY MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
async function renderVulnerabilities() {
  setContent(pageHeader('fa-bug', 'Vulnerability Management', 'CVE/KEV/EPSS triage & exposure worklist') + loader());

  try {
    const [vulnResp, worklistResp] = await Promise.all([
      nexusApi('/vulnerabilities?limit=50'),
      nexusApi('/exposure-worklist?limit=20'),
    ]);

    const vulns    = vulnResp.data || [];
    const worklist = worklistResp.data || [];

    const html = `
    ${pageHeader('fa-bug', 'Vulnerability Management', 'CVE/KEV/EPSS fusion-scored triage and remediation worklist',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.matchCVEs()">
        <i class="fas fa-link"></i> Match to Assets
      </button>`
    )}

    <!-- Fusion Worklist (Top Priority) -->
    <div class="nx-card" style="margin-bottom:24px;">
      <div class="nx-card-title">
        <i class="fas fa-list-ol" style="color:${DS.red};"></i>
        Exposure Worklist — Fix This First
        <span style="margin-left:auto;font-size:11px;color:${DS.textMuted};">${badge('FUSION SCORE', DS.red, 'rgba(239,68,68,0.1)')}</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="nx-table">
          <thead><tr>
            <th>CVE</th><th>Asset</th><th>Fusion Score</th><th>Severity</th>
            <th>CVSS</th><th>EPSS</th><th>KEV</th><th>Exploit</th><th>SLA</th>
          </tr></thead>
          <tbody>
            ${worklist.map(w => {
              const v = w.nexus_vulnerabilities || {};
              const a = w.asset_inventory || {};
              const fusion = Math.round(w.fusion_score || 0);
              const fColor = fusion > 80 ? DS.red : fusion > 50 ? DS.orange : fusion > 25 ? DS.yellow : DS.green;
              return `<tr>
                <td style="font-family:monospace;font-size:12px;color:${DS.accent};">${h(v.cve_id || 'N/A')}</td>
                <td style="font-size:12px;">${h(a.hostname || a.ip_address || 'Unknown')}</td>
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <div class="nx-progress" style="width:60px;">
                      <div class="nx-progress-fill" style="width:${fusion}%;background:${fColor};"></div>
                    </div>
                    <span style="color:${fColor};font-weight:700;">${fusion}</span>
                  </div>
                </td>
                <td>${sev(v.severity)}</td>
                <td style="color:${DS.text};">${v.cvss_score || '—'}</td>
                <td style="color:${DS.cyan};">${v.epss_score ? (v.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                <td>${v.is_kev ? `<span class="nx-badge nx-badge-critical">KEV</span>` : '—'}</td>
                <td>${v.has_exploit ? `<span class="nx-badge nx-badge-high">YES</span>` : '—'}</td>
                <td style="font-size:11px;color:${w.sla_breached ? DS.red : DS.textMuted};">
                  ${w.sla_breached ? '<i class="fas fa-exclamation-circle"></i> BREACHED' : (w.sla_due_at ? new Date(w.sla_due_at).toLocaleDateString() : '—')}
                </td>
              </tr>`;
            }).join('')}
            ${worklist.length === 0 ? `<tr><td colspan="9" class="nx-empty">No open vulnerabilities</td></tr>` : ''}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Full CVE Library -->
    <div class="nx-card">
      <div class="nx-card-title">
        <i class="fas fa-database" style="color:${DS.accent};"></i> CVE Library
        <div style="margin-left:auto;display:flex;gap:8px;">
          <input id="nx-vuln-search" class="nx-search" placeholder="Search CVE..." style="width:200px;"
            oninput="NexusModule.searchVulns(this.value)">
          <select class="nx-select" onchange="NexusModule.filterVulns('severity', this.value)">
            <option value="">All Severities</option>
            <option>critical</option><option>high</option><option>medium</option><option>low</option>
          </select>
          <select class="nx-select" onchange="NexusModule.filterVulns('kev', this.value)">
            <option value="">All</option>
            <option value="true">KEV Only</option>
          </select>
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table class="nx-table" id="nx-vuln-table">
          <thead><tr>
            <th>CVE ID</th><th>Title</th><th>Severity</th><th>CVSS</th>
            <th>EPSS</th><th>KEV</th><th>Published</th>
          </tr></thead>
          <tbody>
            ${vulns.map(v => `<tr>
              <td style="font-family:monospace;color:${DS.accent};font-size:12px;">${h(v.cve_id)}</td>
              <td style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                title="${h(v.title)}">${h(v.title || 'N/A')}</td>
              <td>${sev(v.severity)}</td>
              <td style="color:${(v.cvss_score||0) >= 9 ? DS.red : (v.cvss_score||0) >= 7 ? DS.orange : DS.text};">
                ${v.cvss_score || '—'}
              </td>
              <td style="color:${DS.cyan};">${v.epss_score ? (v.epss_score * 100).toFixed(2) + '%' : '—'}</td>
              <td>${v.is_kev ? `<span class="nx-badge nx-badge-critical">&#9679; KEV</span>` : ''}</td>
              <td style="font-size:11px;color:${DS.textMuted};">${v.published_at || '—'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ATTACK PATH GRAPH (D3.js Force-Directed)
// ══════════════════════════════════════════════════════════════════════════════
async function renderAttackPaths() {
  setContent(pageHeader('fa-diagram-project', 'Attack Path Analysis', 'Force-directed asset graph — easiest paths to crown jewels') + loader());

  try {
    const [graphResp, pathsResp] = await Promise.all([
      nexusApi('/attack-surface-graph'),
      nexusApi('/attack-paths'),
    ]);

    const graphData = graphResp.data || { nodes: [], edges: [] };
    const paths     = pathsResp.data || [];

    const html = `
    ${pageHeader('fa-diagram-project', 'Attack Path Analysis', 'Dijkstra-weighted reachability graph across your asset estate',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.computeAttackPaths()">
        <i class="fas fa-sync-alt"></i> Recompute Paths
      </button>
      <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-aoi')">
        <i class="fas fa-crosshairs"></i> View AOI
      </button>`
    )}

    <div class="nx-grid nx-grid-2" style="margin-bottom:16px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.red};">${paths.length}</div>
        <div class="nx-kpi-label">Attack Paths Found</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.orange};">${graphData.choke_points?.length || 0}</div>
        <div class="nx-kpi-label">Choke Points</div>
        <div style="font-size:11px;color:${DS.textMuted};margin-top:4px;">Highest-impact single fixes</div>
      </div>
    </div>

    <!-- D3 Force Graph -->
    <div class="nx-card" style="margin-bottom:16px;">
      <div class="nx-card-title">
        <i class="fas fa-project-diagram" style="color:${DS.accent};"></i> Asset Attack Surface Graph
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center;">
          <span style="font-size:11px;color:${DS.textMuted};">
            <span style="color:${DS.red};">&#9650;</span> Entry Point &nbsp;
            <span style="color:${DS.yellow};">&#9670;</span> Choke Point &nbsp;
            <span style="color:${DS.purple};">&#9733;</span> Crown Jewel &nbsp;
            <span style="color:${DS.textMuted};">&#9679;</span> Internal
          </span>
        </div>
      </div>
      <div id="nx-attack-graph" style="height:480px;background:${DS.bg};border-radius:8px;overflow:hidden;position:relative;">
        <svg id="nx-attack-svg" width="100%" height="100%"></svg>
        <div style="position:absolute;bottom:12px;left:12px;font-size:11px;color:${DS.textMuted};">
          Drag nodes to explore • Scroll to zoom
        </div>
      </div>
    </div>

    <!-- Path Table -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-route" style="color:${DS.orange};"></i> Computed Attack Paths</div>
      <table class="nx-table">
        <thead><tr><th>Entry Asset</th><th>Crown Jewel</th><th>Path Cost</th><th>Blast Radius</th><th>Choke Points</th></tr></thead>
        <tbody>
          ${paths.slice(0, 15).map(p => `<tr>
            <td style="font-size:12px;color:${DS.red};">&#9650; ${h(p.source_asset_id?.substring(0, 8) + '...' || 'Unknown')}</td>
            <td style="font-size:12px;color:${DS.purple};">&#9733; ${h(p.target_asset_id?.substring(0, 8) + '...' || 'Unknown')}</td>
            <td style="color:${DS.orange};">${Math.round(p.path_cost || 0)}</td>
            <td style="color:${DS.accent};">${fmtCurrency(p.blast_radius)}</td>
            <td>${(p.choke_point_ids || []).length} points</td>
          </tr>`).join('')}
          ${paths.length === 0 ? `<tr><td colspan="5" class="nx-empty">No paths computed — click "Recompute Paths"</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
    drawAttackGraph(graphData);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

function drawAttackGraph(graphData) {
  const svgEl = document.getElementById('nx-attack-svg');
  if (!svgEl || !graphData.nodes) return;

  const nodes = graphData.nodes.map(n => ({ ...n }));
  const edges = graphData.edges.map(e => ({ ...e }));

  const container = document.getElementById('nx-attack-graph');
  const W = container.offsetWidth || 800;
  const H = container.offsetHeight || 480;

  svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const nodeColor = (n) => {
    if (n.type === 'entry')      return DS.red;
    if (n.type === 'crown_jewel') return DS.purple;
    if (n.type === 'choke_point') return DS.yellow;
    return DS.accent;
  };
  const nodeShape = (n) => {
    if (n.type === 'crown_jewel') return 'star';
    if (n.type === 'entry')       return 'triangle';
    return 'circle';
  };

  // Simple force simulation (no D3 dependency needed)
  nodes.forEach((n, i) => {
    n.x = W * 0.1 + Math.random() * W * 0.8;
    n.y = H * 0.1 + Math.random() * H * 0.8;
    n.vx = 0; n.vy = 0;
  });

  const nodeMap = {};
  nodes.forEach(n => { nodeMap[n.id] = n; });

  function tick(iterations = 80) {
    for (let iter = 0; iter < iterations; iter++) {
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
          const d = Math.sqrt(dx * dx + dy * dy) || 1;
          const f = 2000 / (d * d);
          nodes[i].vx -= f * dx / d; nodes[i].vy -= f * dy / d;
          nodes[j].vx += f * dx / d; nodes[j].vy += f * dy / d;
        }
      }
      // Attraction
      edges.forEach(e => {
        const s = nodeMap[e.source], t = nodeMap[e.target];
        if (!s || !t) return;
        const dx = t.x - s.x, dy = t.y - s.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - 120) * 0.01;
        s.vx += f * dx / d; s.vy += f * dy / d;
        t.vx -= f * dx / d; t.vy -= f * dy / d;
      });
      // Centering
      nodes.forEach(n => {
        n.vx += (W / 2 - n.x) * 0.005;
        n.vy += (H / 2 - n.y) * 0.005;
        n.x = Math.max(20, Math.min(W - 20, n.x + n.vx * 0.5));
        n.y = Math.max(20, Math.min(H - 20, n.y + n.vy * 0.5));
        n.vx *= 0.7; n.vy *= 0.7;
      });
    }
  }

  tick();

  const edgesHTML = edges.map(e => {
    const s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t) return '';
    return `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"
      stroke="rgba(239,68,68,0.3)" stroke-width="1.5" stroke-dasharray="4,3">
      <title>Attack path — cost ${Math.round(e.weight || 0)}</title>
    </line>`;
  }).join('');

  const nodesHTML = nodes.map(n => {
    const color = nodeColor(n);
    const r = n.type === 'crown_jewel' ? 12 : n.type === 'entry' ? 10 : 8;
    return `<g class="nx-graph-node" style="cursor:pointer;">
      <circle cx="${n.x}" cy="${n.y}" r="${r + 4}" fill="${color}" opacity="0.15"/>
      <circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${color}" stroke="${DS.bgCard}" stroke-width="2"/>
      <text x="${n.x}" y="${n.y + r + 12}" text-anchor="middle"
        fill="${DS.textMuted}" font-size="9" font-family="monospace">
        ${h((n.label || '').substring(0, 12))}
      </text>
      <title>${h(n.label)} — ${n.type} — Risk: ${Math.round(n.risk_score || 0)}</title>
    </g>`;
  }).join('');

  svgEl.innerHTML = `
    <defs>
      <filter id="glow-effect">
        <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
        <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    </defs>
    <g id="nx-edges">${edgesHTML}</g>
    <g id="nx-nodes">${nodesHTML}</g>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CTEM / VOC
// ══════════════════════════════════════════════════════════════════════════════
async function renderCTEM() {
  setContent(pageHeader('fa-bullseye', 'CTEM / VOC', 'Continuous Threat Exposure Management & Vulnerability Operations') + loader());

  try {
    const [kpiResp, campaignResp, exposureResp] = await Promise.all([
      nexusApi('/voc/kpis'),
      nexusApi('/voc/campaigns'),
      nexusApi('/ctem'),
    ]);

    const kpis      = kpiResp.data || {};
    const campaigns = campaignResp.data || [];
    const exposures = exposureResp.data || [];

    const html = `
    ${pageHeader('fa-bullseye', 'CTEM / VOC', 'Continuous Threat Exposure Management — Discover → Prioritize → Remediate',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newCampaign()">
        <i class="fas fa-plus"></i> New Campaign
      </button>`
    )}

    <!-- VOC KPIs -->
    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.red};">${fmtNum(kpis.open_vulns)}</div>
        <div class="nx-kpi-label">Open Vulnerabilities</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.orange};">${fmtNum(kpis.sla_breached)}</div>
        <div class="nx-kpi-label">SLA Breached</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.green};">${fmtPct(kpis.sla_compliance_pct)}</div>
        <div class="nx-kpi-label">SLA Compliance</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.cyan};">${kpis.mttr_days || 0}d</div>
        <div class="nx-kpi-label">MTTR</div>
        <div style="font-size:11px;color:${DS.textMuted};margin-top:4px;">Mean Time To Remediate</div>
      </div>
    </div>

    <!-- CTEM Pipeline -->
    <div class="nx-card" style="margin-bottom:16px;">
      <div class="nx-card-title"><i class="fas fa-arrow-right-arrow-left" style="color:${DS.accent};"></i> CTEM Exposure Pipeline</div>
      <div style="display:flex;gap:0;margin-bottom:20px;">
        ${['discover', 'prioritize', 'remediate'].map((stage, i) => {
          const cnt = exposures.filter(e => e.stage === stage).length;
          const colors = [DS.orange, DS.red, DS.green];
          const labels = ['Discover', 'Prioritize', 'Remediate'];
          return `<div style="flex:1;padding:16px;background:rgba(255,255,255,0.03);
            ${i > 0 ? 'border-left:1px solid ' + DS.border + ';' : ''}
            ${i === 0 ? 'border-radius:8px 0 0 8px;' : i === 2 ? 'border-radius:0 8px 8px 0;' : ''}">
            <div style="font-size:24px;font-weight:800;color:${colors[i]};">${cnt}</div>
            <div style="font-size:12px;color:${DS.textMuted};margin-top:4px;text-transform:uppercase;letter-spacing:0.8px;">${labels[i]}</div>
            ${i < 2 ? `<div style="position:absolute;right:-12px;top:50%;transform:translateY(-50%);
              color:${DS.textMuted};font-size:20px;z-index:1;">→</div>` : ''}
          </div>`;
        }).join('')}
      </div>
      <table class="nx-table">
        <thead><tr><th>Exposure ID</th><th>Name</th><th>Stage</th><th>Severity</th><th>Asset</th></tr></thead>
        <tbody>
          ${exposures.slice(0, 10).map(e => `<tr>
            <td style="font-family:monospace;font-size:11px;color:${DS.textMuted};">${h(e.exposure_id || e.id?.substring(0, 8))}</td>
            <td style="font-size:12px;">${h(e.name)}</td>
            <td>${badge(e.stage, e.stage === 'remediate' ? DS.green : e.stage === 'prioritize' ? DS.red : DS.orange)}</td>
            <td>${sev(e.severity)}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${h(e.asset_inventory?.hostname || '—')}</td>
          </tr>`).join('')}
          ${exposures.length === 0 ? `<tr><td colspan="5" class="nx-empty">No CTEM exposures tracked</td></tr>` : ''}
        </tbody>
      </table>
    </div>

    <!-- Remediation Campaigns -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-flag-checkered" style="color:${DS.green};"></i> Remediation Campaigns</div>
      <table class="nx-table">
        <thead><tr><th>Campaign</th><th>Status</th><th>Owner</th><th>Target Date</th></tr></thead>
        <tbody>
          ${campaigns.map(c => `<tr>
            <td style="font-weight:600;">${h(c.name)}</td>
            <td>${badge(c.status, c.status === 'completed' ? DS.green : c.status === 'active' ? DS.accent : DS.yellow)}</td>
            <td style="font-size:12px;">${h(c.owner_email || '—')}</td>
            <td style="font-size:12px;">${c.target_date ? new Date(c.target_date).toLocaleDateString() : '—'}</td>
          </tr>`).join('')}
          ${campaigns.length === 0 ? `<tr><td colspan="4" class="nx-empty">No campaigns</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  THREAT-INFORMED DEFENSE COCKPIT
// ══════════════════════════════════════════════════════════════════════════════
async function renderTID() {
  setContent(pageHeader('fa-chess-king', 'Threat-Informed Defense', 'ATT&CK coverage × adversary prevalence × detection proof') + loader());

  try {
    const [summaryResp, coverageResp] = await Promise.all([
      nexusApi('/tid/summary'),
      nexusApi('/tid/coverage?limit=50'),
    ]);

    const summary  = summaryResp.data || {};
    const coverage = coverageResp.data || [];

    const html = `
    ${pageHeader('fa-chess-king', 'TID Cockpit', 'Threat-Informed Defense — close the detect → test → validate loop',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.exportNavigatorLayer()">
        <i class="fas fa-download"></i> ATT&CK Navigator Layer
      </button>`
    )}

    <!-- TID KPIs -->
    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.green};">${summary.detect_covered || 0}</div>
        <div class="nx-kpi-label">Techniques Covered</div>
        <div style="font-size:11px;color:${DS.textMuted};margin-top:4px;">Detection rules proven</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.red};">${summary.detect_none || 0}</div>
        <div class="nx-kpi-label">Detection Gaps</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.orange};">${summary.false_coverage || 0}</div>
        <div class="nx-kpi-label">False Coverage</div>
        <div style="font-size:11px;color:${DS.textMuted};margin-top:4px;">Rules that never fired</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.cyan};">${Math.round(summary.avg_program_score || 0)}%</div>
        <div class="nx-kpi-label">Program Score</div>
      </div>
    </div>

    <!-- Detect/Test/Validate Bar -->
    <div class="nx-card" style="margin-bottom:16px;">
      <div class="nx-card-title"><i class="fas fa-chart-bar" style="color:${DS.accent};"></i> Coverage by Status</div>
      <div style="display:flex;height:32px;border-radius:8px;overflow:hidden;margin-bottom:16px;">
        ${[
          { key: 'detect_covered', label: 'Covered', color: DS.green },
          { key: 'detect_partial', label: 'Partial', color: DS.yellow },
          { key: 'false_coverage', label: 'False', color: DS.orange },
          { key: 'detect_none',   label: 'None', color: DS.red },
        ].map(s => {
          const cnt   = summary[s.key] || 0;
          const total = summary.total_techniques || 1;
          const pct   = (cnt / total * 100).toFixed(1);
          return `<div style="flex:${pct};background:${s.color};min-width:${cnt > 0 ? '4px' : '0'};
            display:flex;align-items:center;justify-content:center;font-size:10px;color:#fff;
            font-weight:700;" title="${s.label}: ${cnt} (${pct}%)">
            ${pct > 5 ? s.label : ''}
          </div>`;
        }).join('')}
      </div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;">
        ${[
          { color: DS.green, label: 'Covered', cnt: summary.detect_covered },
          { color: DS.yellow, label: 'Partial', cnt: summary.detect_partial },
          { color: DS.orange, label: 'False Coverage', cnt: summary.false_coverage },
          { color: DS.red, label: 'No Detection', cnt: summary.detect_none },
          { color: DS.cyan, label: 'Validated (BAS)', cnt: summary.test_validated },
        ].map(s => `<div style="display:flex;align-items:center;gap:6px;">
          <div style="width:10px;height:10px;border-radius:50%;background:${s.color};"></div>
          <span style="font-size:12px;color:${DS.textMuted};">${s.label}: </span>
          <span style="font-size:12px;color:${DS.text};font-weight:600;">${s.cnt || 0}</span>
        </div>`).join('')}
      </div>
    </div>

    <!-- Technique Coverage Table -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-table" style="color:${DS.accent};"></i> Technique Coverage Details</div>
      <table class="nx-table">
        <thead><tr><th>Technique</th><th>Tactic</th><th>Detect</th><th>Test</th><th>Prevalence</th><th>Drift</th></tr></thead>
        <tbody>
          ${coverage.map(t => {
            const dColor = { covered: DS.green, partial: DS.yellow, none: DS.red, false_coverage: DS.orange }[t.detect_status] || DS.textMuted;
            return `<tr>
              <td style="font-family:monospace;font-size:12px;color:${DS.accent};">${h(t.technique_id)}</td>
              <td style="font-size:11px;color:${DS.textMuted};">${h(t.tactic || '—')}</td>
              <td><span style="color:${dColor};font-weight:600;font-size:11px;text-transform:uppercase;">${h(t.detect_status)}</span></td>
              <td><span style="font-size:11px;color:${DS.textMuted};">${h(t.test_status || 'none')}</span></td>
              <td>
                <div class="nx-progress" style="width:60px;">
                  <div class="nx-progress-fill" style="width:${Math.round((t.adversary_prevalence || 0) * 100)}%;background:${DS.accent};"></div>
                </div>
              </td>
              <td>${t.detection_drift ? `<span class="nx-badge nx-badge-critical nx-pulse">DRIFT</span>` : '—'}</td>
            </tr>`;
          }).join('')}
          ${coverage.length === 0 ? `<tr><td colspan="6" class="nx-empty">No TID coverage data. Import ATT&CK data to begin.</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  MITRE ATT&CK NAVIGATOR (Interactive Matrix)
// ══════════════════════════════════════════════════════════════════════════════
async function renderMITRE() {
  setContent(pageHeader('fa-table', 'MITRE ATT&CK Navigator', 'Interactive ATT&CK matrix with detection coverage overlay') + loader());

  try {
    const { data: coverage } = await nexusApi('/tid/coverage?limit=500');

    const coverageMap = {};
    (coverage || []).forEach(t => { coverageMap[t.technique_id] = t; });

    const tactics = [
      { id: 'TA0043', name: 'Reconnaissance',      key: 'reconnaissance', techniques: ['T1595','T1592','T1589','T1590','T1591','T1596','T1593','T1594'] },
      { id: 'TA0042', name: 'Resource Dev',         key: 'resource-development', techniques: ['T1583','T1586','T1584','T1587','T1585','T1588','T1608'] },
      { id: 'TA0001', name: 'Initial Access',       key: 'initial-access', techniques: ['T1189','T1190','T1133','T1200','T1566','T1091','T1195','T1199'] },
      { id: 'TA0002', name: 'Execution',            key: 'execution', techniques: ['T1059','T1203','T1559','T1106','T1129','T1072','T1569','T1204','T1047'] },
      { id: 'TA0003', name: 'Persistence',          key: 'persistence', techniques: ['T1098','T1197','T1547','T1037','T1176','T1554','T1136','T1543','T1546'] },
      { id: 'TA0004', name: 'Privilege Escalation', key: 'privilege-escalation', techniques: ['T1548','T1134','T1547','T1037','T1543','T1546','T1574','T1055'] },
      { id: 'TA0005', name: 'Defense Evasion',      key: 'defense-evasion', techniques: ['T1548','T1134','T1197','T1140','T1610','T1006','T1484','T1480'] },
      { id: 'TA0006', name: 'Credential Access',    key: 'credential-access', techniques: ['T1110','T1555','T1212','T1187','T1606','T1056','T1557','T1528'] },
      { id: 'TA0007', name: 'Discovery',            key: 'discovery', techniques: ['T1087','T1010','T1217','T1482','T1083','T1046','T1135','T1040','T1201'] },
      { id: 'TA0008', name: 'Lateral Movement',     key: 'lateral-movement', techniques: ['T1210','T1534','T1570','T1563','T1021','T1091','T1072','T1550'] },
      { id: 'TA0009', name: 'Collection',           key: 'collection', techniques: ['T1557','T1560','T1123','T1119','T1115','T1530','T1213','T1005','T1039'] },
      { id: 'TA0011', name: 'C2',                   key: 'command-and-control', techniques: ['T1071','T1092','T1132','T1001','T1568','T1573','T1008','T1105'] },
      { id: 'TA0010', name: 'Exfiltration',         key: 'exfiltration', techniques: ['T1020','T1030','T1048','T1041','T1011','T1052','T1567','T1029'] },
      { id: 'TA0040', name: 'Impact',               key: 'impact', techniques: ['T1531','T1485','T1486','T1491','T1561','T1499','T1495','T1490','T1498'] },
    ];

    const html = `
    ${pageHeader('fa-table', 'MITRE ATT&CK Navigator', 'Enterprise ATT&CK matrix with live detection coverage overlay',
      `<button class="nx-btn nx-btn-ghost" onclick="NexusModule.exportNavigatorLayer()">
        <i class="fas fa-download"></i> Export Layer
      </button>
      <button class="nx-btn nx-btn-ghost" onclick="NexusModule.goto('nexus-tid')">
        <i class="fas fa-chess-king"></i> TID Cockpit
      </button>`
    )}

    <!-- Legend -->
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;padding:12px;background:${DS.bgCard};border-radius:8px;border:1px solid ${DS.border};">
      ${[
        { color: DS.green,    label: 'Covered (Sigma)' },
        { color: DS.yellow,   label: 'Partial' },
        { color: DS.orange,   label: 'False Coverage' },
        { color: DS.red,      label: 'No Detection' },
        { color: DS.textMuted, label: 'Not Assessed' },
      ].map(l => `<div style="display:flex;align-items:center;gap:6px;">
        <div style="width:14px;height:14px;border-radius:3px;background:${l.color};opacity:0.8;"></div>
        <span style="font-size:11px;color:${DS.textMuted};">${l.label}</span>
      </div>`).join('')}
    </div>

    <div style="overflow-x:auto;">
      <div style="display:flex;gap:2px;min-width:${tactics.length * 100}px;">
        ${tactics.map(tactic => `
          <div style="flex:1;min-width:90px;">
            <div style="background:${DS.accent};color:#fff;padding:6px 4px;border-radius:4px 4px 0 0;
              font-size:10px;font-weight:700;text-align:center;text-transform:uppercase;letter-spacing:0.5px;
              white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${tactic.name}">
              ${tactic.name}
            </div>
            <div style="display:flex;flex-direction:column;gap:2px;margin-top:2px;">
              ${tactic.techniques.map(techId => {
                const cov = coverageMap[techId];
                const color = cov ? ({ covered: DS.green, partial: DS.yellow, false_coverage: DS.orange, none: DS.red }[cov.detect_status] || DS.textMuted) : 'rgba(255,255,255,0.05)';
                return `<div class="nx-heatmap-cell" style="background:${color}20;border:1px solid ${color}40;
                  padding:4px;border-radius:3px;font-size:9px;color:${color};font-family:monospace;
                  text-align:center;cursor:pointer;"
                  title="${techId}${cov ? ' — ' + cov.detect_status : ' — not assessed'}"
                  onclick="NexusModule.showTechnique('${techId}')">
                  ${techId}
                </div>`;
              }).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  KILL CHAIN VISUALIZATION
// ══════════════════════════════════════════════════════════════════════════════
async function renderKillChain() {
  setContent(pageHeader('fa-link', 'Kill Chain Visualization', 'ATT&CK tactics as kill chain phases with detection overlay') + loader());

  try {
    const { data } = await nexusApi('/kill-chain');
    const phases = data.phases || [];

    const html = `
    ${pageHeader('fa-link', 'Kill Chain Visualization', 'Kill chain phases with detection coverage and adversary mapping')}

    <div style="overflow-x:auto;padding-bottom:16px;">
      <div style="display:flex;gap:0;min-width:${phases.length * 120}px;">
        ${phases.map((phase, i) => {
          const pct = phase.technique_count > 0 ? Math.round((phase.covered / phase.technique_count) * 100) : 0;
          const barColor = pct > 70 ? DS.green : pct > 40 ? DS.yellow : DS.red;
          const isLast = i === phases.length - 1;

          return `
          <div style="flex:1;min-width:110px;position:relative;${!isLast ? 'padding-right:0;' : ''}">
            <!-- Arrow connector -->
            ${!isLast ? `<div style="position:absolute;right:-8px;top:50%;transform:translateY(-50%);
              width:16px;height:16px;z-index:2;color:${DS.accent};font-size:14px;line-height:1;">→</div>` : ''}

            <div style="background:${DS.bgCard};border:1px solid ${DS.border};
              border-radius:8px;padding:12px 10px;margin-right:${!isLast ? '8px' : '0'};
              transition:border-color 0.2s;"
              onmouseover="this.style.borderColor='${DS.accent}'"
              onmouseout="this.style.borderColor='${DS.border}'">
              <div style="font-size:11px;font-weight:700;color:${DS.text};margin-bottom:8px;
                white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${h(phase.phase)}">
                ${h(phase.phase)}
              </div>
              <div style="font-size:22px;font-weight:800;color:${barColor};margin-bottom:4px;">${pct}%</div>
              <div style="font-size:10px;color:${DS.textMuted};margin-bottom:8px;">
                ${phase.covered}/${phase.technique_count} detected
              </div>
              <div class="nx-progress">
                <div class="nx-progress-fill" style="width:${pct}%;background:${barColor};"></div>
              </div>
              <!-- Mini technique list -->
              <div style="margin-top:8px;">
                ${(phase.techniques || []).slice(0, 3).map(t => `
                  <div style="font-size:9px;color:${DS.textMuted};font-family:monospace;margin-top:2px;">
                    ${h(t.technique_id)}
                  </div>
                `).join('')}
              </div>
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>

    <!-- Kill Chain Coverage Summary -->
    <div class="nx-card" style="margin-top:16px;">
      <div class="nx-card-title"><i class="fas fa-chart-line" style="color:${DS.accent};"></i> Kill Chain Coverage Summary</div>
      <table class="nx-table">
        <thead><tr><th>Phase</th><th>Total Techniques</th><th>Detected</th><th>Gaps</th><th>Coverage</th></tr></thead>
        <tbody>
          ${phases.map(p => {
            const pct = p.technique_count > 0 ? Math.round((p.covered / p.technique_count) * 100) : 0;
            return `<tr>
              <td style="font-weight:600;">${h(p.phase)}</td>
              <td>${p.technique_count}</td>
              <td style="color:${DS.green};">${p.covered}</td>
              <td style="color:${DS.red};">${p.uncovered}</td>
              <td>
                <div style="display:flex;align-items:center;gap:8px;">
                  <div class="nx-progress" style="width:80px;">
                    <div class="nx-progress-fill" style="width:${pct}%;background:${pct > 70 ? DS.green : pct > 40 ? DS.yellow : DS.red};"></div>
                  </div>
                  <span style="font-size:12px;color:${DS.text};">${pct}%</span>
                </div>
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  THREAT HUNTING
// ══════════════════════════════════════════════════════════════════════════════
async function renderThreatHunting() {
  setContent(pageHeader('fa-magnifying-glass', 'Threat Hunting', 'Hypothesis-driven hunting with IOC pivoting & AI assist') + loader());

  try {
    const { data: hunts, total } = await nexusApi('/hunts?limit=50');

    const html = `
    ${pageHeader('fa-magnifying-glass', 'Threat Hunting', 'Hunt workspace — hypothesis-driven investigation with ATT&CK correlation',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newHunt()">
        <i class="fas fa-plus"></i> New Hunt
      </button>`
    )}

    <!-- Hunt KPIs -->
    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      ${[
        { label: 'Open Hunts', val: (hunts || []).filter(h => h.status === 'open').length, color: DS.orange },
        { label: 'In Progress', val: (hunts || []).filter(h => h.status === 'in_progress').length, color: DS.accent },
        { label: 'Escalated', val: (hunts || []).filter(h => h.status === 'escalated').length, color: DS.red },
        { label: 'Closed', val: (hunts || []).filter(h => h.status === 'closed').length, color: DS.green },
      ].map(k => `<div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${k.color};">${k.val}</div>
        <div class="nx-kpi-label">${k.label}</div>
      </div>`).join('')}
    </div>

    <!-- Hunt List -->
    <div class="nx-card">
      <div class="nx-card-title">
        <i class="fas fa-list" style="color:${DS.accent};"></i> Active Hunt Queue
        <div style="margin-left:auto;display:flex;gap:8px;">
          <select class="nx-select" onchange="NexusModule.filterHunts('status', this.value)">
            <option value="">All Status</option>
            <option>open</option><option>in_progress</option><option>escalated</option><option>closed</option>
          </select>
        </div>
      </div>
      <table class="nx-table">
        <thead><tr><th>Hunt Title</th><th>Hypothesis</th><th>Status</th><th>Priority</th><th>Techniques</th><th>Hunter</th><th>Created</th></tr></thead>
        <tbody>
          ${(hunts || []).map(hunt => `<tr>
            <td style="font-weight:600;font-size:13px;">${h(hunt.title)}</td>
            <td style="font-size:11px;color:${DS.textMuted};max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
              title="${h(hunt.hypothesis)}">${h(hunt.hypothesis)}</td>
            <td>${badge(hunt.status, hunt.status === 'open' ? DS.orange : hunt.status === 'in_progress' ? DS.accent : hunt.status === 'escalated' ? DS.red : DS.green)}</td>
            <td>${sev(hunt.priority)}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${(hunt.technique_ids || []).slice(0, 2).join(', ') || '—'}</td>
            <td style="font-size:11px;">${h(hunt.hunter_email || '—')}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(hunt.created_at)}</td>
          </tr>`).join('')}
          ${!(hunts || []).length ? `<tr><td colspan="7" class="nx-empty">No hunts. Create your first hypothesis.</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ADVERSARY EMULATION / BAS
// ══════════════════════════════════════════════════════════════════════════════
async function renderBAS() {
  setContent(pageHeader('fa-flask-vial', 'BAS / Adversary Emulation', 'Safe-by-design atomic test execution with ATT&CK coverage') + loader());

  try {
    const [scenarioResp, resultResp] = await Promise.all([
      nexusApi('/emulation/scenarios'),
      nexusApi('/emulation/results'),
    ]);

    const scenarios = scenarioResp.data || [];
    const results   = resultResp.data || [];

    const html = `
    ${pageHeader('fa-flask-vial', 'BAS / Adversary Emulation', 'Breach & Attack Simulation — curated safe-by-design atomic tests',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newScenario()">
        <i class="fas fa-plus"></i> New Scenario
      </button>`
    )}

    <!-- Last Run Summary -->
    ${results.length > 0 ? (() => {
      const last = results[0];
      const coverage = last.coverage_pct || 0;
      const coverageColor = coverage > 70 ? DS.green : coverage > 40 ? DS.yellow : DS.red;
      return `<div class="nx-card" style="margin-bottom:24px;border-color:${coverageColor}40;">
        <div class="nx-card-title"><i class="fas fa-check-circle" style="color:${coverageColor};"></i> Latest Run Results</div>
        <div class="nx-grid nx-grid-4">
          <div class="nx-kpi">
            <div class="nx-kpi-val" style="color:${DS.accent};">${last.total_tests}</div>
            <div class="nx-kpi-label">Total Tests</div>
          </div>
          <div class="nx-kpi">
            <div class="nx-kpi-val" style="color:${DS.green};">${last.detected}</div>
            <div class="nx-kpi-label">Detected</div>
          </div>
          <div class="nx-kpi">
            <div class="nx-kpi-val" style="color:${DS.red};">${last.undetected}</div>
            <div class="nx-kpi-label">Undetected</div>
          </div>
          <div class="nx-kpi">
            <div class="nx-kpi-val" style="color:${coverageColor};">${coverage}%</div>
            <div class="nx-kpi-label">Detection Coverage</div>
          </div>
        </div>
      </div>`;
    })() : ''}

    <!-- Scenarios -->
    <div class="nx-card" style="margin-bottom:16px;">
      <div class="nx-card-title"><i class="fas fa-list" style="color:${DS.accent};"></i> Emulation Scenarios</div>
      <table class="nx-table">
        <thead><tr><th>Scenario</th><th>Threat Actor</th><th>Tests</th><th>Status</th><th>Last Run</th><th>Actions</th></tr></thead>
        <tbody>
          ${scenarios.map(s => `<tr>
            <td style="font-weight:600;">${h(s.name)}</td>
            <td style="font-size:12px;color:${DS.orange};">${h(s.threat_actor || '—')}</td>
            <td>${s.test_count || 0}</td>
            <td>${badge(s.status, s.status === 'ready' ? DS.green : s.status === 'running' ? DS.accent : DS.textMuted)}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(s.last_run_at)}</td>
            <td>
              <button class="nx-btn nx-btn-primary" style="padding:4px 10px;font-size:11px;"
                onclick="NexusModule.runScenario('${s.id}')">
                <i class="fas fa-play"></i> Run
              </button>
            </td>
          </tr>`).join('')}
          ${scenarios.length === 0 ? `<tr><td colspan="6" class="nx-empty">No scenarios. Create your first emulation plan.</td></tr>` : ''}
        </tbody>
      </table>
    </div>

    <!-- Run History -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-history" style="color:${DS.textMuted};"></i> Run History</div>
      <table class="nx-table">
        <thead><tr><th>Scenario</th><th>Tests</th><th>Detected</th><th>Coverage</th><th>Run At</th></tr></thead>
        <tbody>
          ${results.slice(0, 10).map(r => {
            const cov = r.coverage_pct || 0;
            return `<tr>
              <td style="font-size:12px;">${h(r.nexus_emulation_scenarios?.name || 'Unknown')}</td>
              <td>${r.total_tests}</td>
              <td style="color:${DS.green};">${r.detected}</td>
              <td>
                <div style="display:flex;align-items:center;gap:8px;">
                  <div class="nx-progress" style="width:60px;">
                    <div class="nx-progress-fill" style="width:${cov}%;background:${cov > 70 ? DS.green : cov > 40 ? DS.yellow : DS.red};"></div>
                  </div>
                  <span style="font-size:12px;">${cov}%</span>
                </div>
              </td>
              <td style="font-size:11px;color:${DS.textMuted};">${ago(r.run_at)}</td>
            </tr>`;
          }).join('')}
          ${results.length === 0 ? `<tr><td colspan="5" class="nx-empty">No runs yet</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  GRC — CONTROLS
// ══════════════════════════════════════════════════════════════════════════════
async function renderGRC() {
  setContent(pageHeader('fa-certificate', 'GRC Controls', 'Compliance frameworks, controls, audits & findings') + loader());

  try {
    const { data: controls, total } = await nexusApi('/controls?limit=100');
    const { data: audits } = await nexusApi('/audits');

    const ctrlList = controls || [];
    const frameworks = [...new Set(ctrlList.map(c => c.framework))];
    const byStatus = {
      implemented: ctrlList.filter(c => c.status === 'implemented').length,
      partial: ctrlList.filter(c => c.status === 'partial').length,
      planned: ctrlList.filter(c => c.status === 'planned').length,
      not_assessed: ctrlList.filter(c => c.status === 'not_assessed').length,
    };

    const html = `
    ${pageHeader('fa-certificate', 'GRC Controls', 'Live compliance telemetry — controls proven from security signals',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newAudit()">
        <i class="fas fa-plus"></i> New Audit
      </button>`
    )}

    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.green};">${byStatus.implemented}</div>
        <div class="nx-kpi-label">Implemented</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.yellow};">${byStatus.partial}</div>
        <div class="nx-kpi-label">Partial</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.orange};">${byStatus.planned}</div>
        <div class="nx-kpi-label">Planned</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.textMuted};">${byStatus.not_assessed}</div>
        <div class="nx-kpi-label">Not Assessed</div>
      </div>
    </div>

    <div class="nx-grid nx-grid-2">
      <!-- Controls Table -->
      <div class="nx-card">
        <div class="nx-card-title">
          <i class="fas fa-shield-check" style="color:${DS.accent};"></i> Controls Library
          <div style="margin-left:auto;">
            <select class="nx-select" onchange="NexusModule.filterControls('framework', this.value)">
              <option value="">All Frameworks</option>
              ${frameworks.map(f => `<option>${h(f)}</option>`).join('')}
            </select>
          </div>
        </div>
        <table class="nx-table" style="font-size:12px;">
          <thead><tr><th>Control ID</th><th>Name</th><th>Framework</th><th>Status</th></tr></thead>
          <tbody>
            ${ctrlList.slice(0, 20).map(c => `<tr>
              <td style="font-family:monospace;color:${DS.accent};">${h(c.control_id)}</td>
              <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${h(c.name)}">${h(c.name)}</td>
              <td style="font-size:10px;color:${DS.textMuted};">${h(c.framework)}</td>
              <td>
                <span style="color:${c.status === 'implemented' ? DS.green : c.status === 'partial' ? DS.yellow : DS.textMuted};font-size:10px;font-weight:600;text-transform:uppercase;">
                  ${h(c.status)}
                </span>
              </td>
            </tr>`).join('')}
            ${ctrlList.length === 0 ? `<tr><td colspan="4" class="nx-empty">No controls. Seed defaults via API.</td></tr>` : ''}
          </tbody>
        </table>
      </div>

      <!-- Audits -->
      <div class="nx-card">
        <div class="nx-card-title"><i class="fas fa-clipboard-check" style="color:${DS.green};"></i> Audits</div>
        <table class="nx-table" style="font-size:12px;">
          <thead><tr><th>Title</th><th>Type</th><th>Status</th><th>Score</th></tr></thead>
          <tbody>
            ${(audits || []).slice(0, 15).map(a => `<tr>
              <td style="font-weight:600;">${h(a.title)}</td>
              <td style="font-size:11px;text-transform:capitalize;">${h(a.audit_type)}</td>
              <td>${badge(a.status, a.status === 'completed' ? DS.green : DS.accent)}</td>
              <td style="color:${(a.score || 0) > 70 ? DS.green : (a.score || 0) > 40 ? DS.yellow : DS.red};">
                ${a.score ? a.score + '%' : '—'}
              </td>
            </tr>`).join('')}
            ${!(audits || []).length ? `<tr><td colspan="4" class="nx-empty">No audits yet</td></tr>` : ''}
          </tbody>
        </table>
      </div>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  DFIR
// ══════════════════════════════════════════════════════════════════════════════
async function renderDFIR() {
  setContent(pageHeader('fa-microscope', 'DFIR Forensics', 'Digital forensics, incident reconstruction & artifact correlation') + loader());

  try {
    const { data: cases } = await nexusApi('/dfir/cases');

    const html = `
    ${pageHeader('fa-microscope', 'DFIR — Digital Forensics & Incident Response', 'Forensic evidence timelines, artifact correlation & chain-of-custody',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newForensicCase()">
        <i class="fas fa-plus"></i> New Case
      </button>`
    )}

    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-folder-open" style="color:${DS.accent};"></i> Forensic Cases</div>
      <table class="nx-table">
        <thead><tr><th>Case Title</th><th>Status</th><th>Severity</th><th>Lead Analyst</th><th>Timeline Events</th><th>Artifacts</th><th>Created</th></tr></thead>
        <tbody>
          ${(cases || []).map(c => `<tr>
            <td style="font-weight:600;cursor:pointer;color:${DS.accent};"
              onclick="NexusModule.openCase('${c.id}')">${h(c.title)}</td>
            <td>${badge(c.status, c.status === 'active' ? DS.orange : c.status === 'contained' ? DS.yellow : DS.green)}</td>
            <td>${sev(c.severity)}</td>
            <td style="font-size:12px;">${h(c.lead_analyst || '—')}</td>
            <td style="color:${DS.cyan};">${(c.timeline || []).length}</td>
            <td style="color:${DS.textMuted};">${(c.artifacts || []).length}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(c.created_at)}</td>
          </tr>`).join('')}
          ${!(cases || []).length ? `<tr><td colspan="7" class="nx-empty">No forensic cases</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RISK REGISTER
// ══════════════════════════════════════════════════════════════════════════════
async function renderRiskRegister() {
  setContent(pageHeader('fa-scale-balanced', 'Risk Register', 'FAIR/CRQ quantitative risk register with ALE computation') + loader());

  try {
    const { data: risks, total } = await nexusApi('/risk-register?limit=50');

    const html = `
    ${pageHeader('fa-scale-balanced', 'Risk Register', 'Quantitative risk management — inherent → current → residual → treatment',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newRisk()">
        <i class="fas fa-plus"></i> Add Risk
      </button>`
    )}

    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-table" style="color:${DS.accent};"></i> Risk Register</div>
      <table class="nx-table">
        <thead><tr><th>Risk</th><th>Category</th><th>Inherent</th><th>Residual</th><th>Treatment</th><th>ALE</th><th>Priority</th></tr></thead>
        <tbody>
          ${(risks || []).map(r => `<tr>
            <td style="font-weight:600;">${h(r.title)}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${h(r.category || '—')}</td>
            <td>${sev(r.inherent_likelihood)}</td>
            <td>${sev(r.residual_likelihood)}</td>
            <td>${badge(r.treatment_strategy || 'mitigate', DS.accent)}</td>
            <td style="color:${DS.accent};font-size:12px;">${r.ale_estimate ? fmtCurrency(r.ale_estimate) : '—'}</td>
            <td>
              <div style="display:flex;align-items:center;gap:6px;">
                <div class="nx-progress" style="width:50px;">
                  <div class="nx-progress-fill" style="width:${Math.min(100, r.priority_score || 0)}%;
                    background:${(r.priority_score || 0) > 60 ? DS.red : (r.priority_score || 0) > 30 ? DS.orange : DS.green};"></div>
                </div>
                <span style="font-size:11px;">${r.priority_score || 0}</span>
              </div>
            </td>
          </tr>`).join('')}
          ${!(risks || []).length ? `<tr><td colspan="7" class="nx-empty">No risks registered</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  CONNECTORS CATALOG
// ══════════════════════════════════════════════════════════════════════════════
async function renderConnectors() {
  setContent(pageHeader('fa-plug', 'Security Connectors', '1,200+ security tool integrations — scan, ingest, enrich') + loader());

  try {
    const { data: connectors, total } = await nexusApi('/connectors?limit=100');

    const categories = [...new Set((connectors || []).map(c => c.category))];
    const enabled = (connectors || []).filter(c => c.enabled).length;

    const html = `
    ${pageHeader('fa-plug', 'Security Connectors Catalog', '1,200+ security tool integrations — one click to activate',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.addConnector()">
        <i class="fas fa-plus"></i> Add Connector
      </button>`
    )}

    <div class="nx-grid nx-grid-3" style="margin-bottom:24px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.text};">${total || (connectors || []).length}</div>
        <div class="nx-kpi-label">Total Connectors</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.green};">${enabled}</div>
        <div class="nx-kpi-label">Enabled</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.accent};">${categories.length}</div>
        <div class="nx-kpi-label">Categories</div>
      </div>
    </div>

    <div class="nx-card">
      <div class="nx-card-title">
        <i class="fas fa-grid" style="color:${DS.accent};"></i> Connector Library
        <div style="margin-left:auto;display:flex;gap:8px;">
          <input class="nx-search" placeholder="Search connectors..." style="width:200px;"
            oninput="NexusModule.searchConnectors(this.value)">
          <select class="nx-select" onchange="NexusModule.filterConnectors('category', this.value)">
            <option value="">All Categories</option>
            ${categories.map(c => `<option>${h(c)}</option>`).join('')}
          </select>
        </div>
      </div>
      <table class="nx-table" id="nx-conn-table">
        <thead><tr><th>Connector</th><th>Category</th><th>Type</th><th>Status</th><th>Last Run</th><th>Results</th><th>Actions</th></tr></thead>
        <tbody>
          ${(connectors || []).map(c => `<tr>
            <td style="font-weight:600;">${h(c.display_name || c.name)}</td>
            <td>${badge(c.category || 'general', DS.textMuted, 'rgba(255,255,255,0.05)')}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${h(c.connector_type || 'api')}</td>
            <td>${c.enabled
              ? `<span style="color:${DS.green};font-size:11px;"><i class="fas fa-circle"></i> Active</span>`
              : `<span style="color:${DS.textMuted};font-size:11px;"><i class="far fa-circle"></i> Inactive</span>`}
            </td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(c.last_run_at)}</td>
            <td style="font-size:12px;">${fmtNum(c.results_count)}</td>
            <td>
              <button class="nx-btn nx-btn-ghost" style="padding:4px 10px;font-size:11px;"
                onclick="NexusModule.runConnector('${c.id}')">
                <i class="fas fa-play"></i>
              </button>
            </td>
          </tr>`).join('')}
          ${!(connectors || []).length ? `<tr><td colspan="7" class="nx-empty">No connectors configured</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  RANSOMWARE SCENARIO
// ══════════════════════════════════════════════════════════════════════════════
async function renderRansomware() {
  setContent(pageHeader('fa-lock', 'Ransomware Scenario', 'FAIR + ATT&CK kill-chain dollar impact quantification') + loader());

  try {
    const { data: scenarios } = await nexusApi('/ransomware');
    const latest = scenarios?.[0];

    const html = `
    ${pageHeader('fa-lock', 'Ransomware Scenario', 'Replay ATT&CK ransomware group TTPs across your estate — compute $ impact',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.computeRansomware()">
        <i class="fas fa-calculator"></i> Compute Scenario
      </button>`
    )}

    ${latest ? `
    <!-- Latest Scenario -->
    <div class="nx-card" style="margin-bottom:24px;border-color:${DS.red}40;">
      <div class="nx-card-title">
        <i class="fas fa-exclamation-triangle" style="color:${DS.red};"></i>
        ${h(latest.threat_actor)} Ransomware Scenario
        <span style="margin-left:auto;font-size:11px;color:${DS.textMuted};">Computed ${ago(latest.computed_at)}</span>
      </div>
      <div class="nx-grid nx-grid-4" style="margin-bottom:20px;">
        <div class="nx-kpi" style="border-color:${DS.red}40;">
          <div class="nx-kpi-val" style="color:${DS.red};">${fmtCurrency(latest.total_sle)}</div>
          <div class="nx-kpi-label">Single Loss Expectancy</div>
          <div style="font-size:10px;color:${DS.textMuted};margin-top:4px;">Primary + ransom + recovery</div>
        </div>
        <div class="nx-kpi" style="border-color:${DS.orange}40;">
          <div class="nx-kpi-val" style="color:${DS.orange};">${fmtCurrency(latest.total_ale)}</div>
          <div class="nx-kpi-label">Annualized Loss Expectancy</div>
          <div style="font-size:10px;color:${DS.textMuted};margin-top:4px;">SLE × ARO (${((latest.aro_estimate || 0) * 100).toFixed(0)}% annual)</div>
        </div>
        <div class="nx-kpi" style="border-color:${DS.green}40;">
          <div class="nx-kpi-val" style="color:${DS.green};">${fmtCurrency(latest.residual_with_controls)}</div>
          <div class="nx-kpi-label">Residual with Controls</div>
          <div style="font-size:10px;color:${DS.textMuted};margin-top:4px;">After backups + segmentation</div>
        </div>
        <div class="nx-kpi">
          <div class="nx-kpi-val" style="color:${DS.accent};">${latest.blast_radius_count}</div>
          <div class="nx-kpi-label">Blast Radius Assets</div>
        </div>
      </div>

      <!-- Affected Assets -->
      <table class="nx-table">
        <thead><tr><th>Asset</th><th>Value at Risk</th><th>Internet Exposed</th></tr></thead>
        <tbody>
          ${(latest.affected_assets || []).slice(0, 8).map(a => `<tr>
            <td style="font-size:12px;">${h(a.asset_name)}</td>
            <td style="color:${DS.accent};">${fmtCurrency(a.value_at_risk)}</td>
            <td>${a.internet_exposed ? `<span class="nx-badge nx-badge-critical">Exposed</span>` : '—'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}

    <!-- Scenario History -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-history" style="color:${DS.textMuted};"></i> Scenario History</div>
      <table class="nx-table">
        <thead><tr><th>Threat Actor</th><th>SLE</th><th>ALE</th><th>Residual</th><th>Assets</th><th>Computed</th></tr></thead>
        <tbody>
          ${scenarios.map(s => `<tr>
            <td style="color:${DS.orange};">${h(s.threat_actor)}</td>
            <td>${fmtCurrency(s.total_sle)}</td>
            <td>${fmtCurrency(s.total_ale)}</td>
            <td style="color:${DS.green};">${fmtCurrency(s.residual_with_controls)}</td>
            <td>${s.blast_radius_count}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(s.computed_at)}</td>
          </tr>`).join('')}
          ${!scenarios.length ? `<tr><td colspan="6" class="nx-empty">No scenarios computed</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  AOI — ADVERSARY OPPORTUNITY INDEX
// ══════════════════════════════════════════════════════════════════════════════
async function renderAOI() {
  setContent(pageHeader('fa-crosshairs', 'Adversary Opportunity Index', 'Attacker-eye threat debt — one 0-1000 score') + loader());

  try {
    const { data: records } = await nexusApi('/aoi');
    const latest = records?.[0];

    const aoiScore = latest?.aoi_score || 0;
    const aoiColor = aoiScore > 700 ? DS.red : aoiScore > 400 ? DS.orange : aoiScore > 200 ? DS.yellow : DS.green;

    const html = `
    ${pageHeader('fa-crosshairs', 'Adversary Opportunity Index', '"Threat debt" — the true adversary opportunity across your estate',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.computeAOI()">
        <i class="fas fa-sync-alt"></i> Recompute AOI
      </button>`
    )}

    <!-- AOI Score -->
    <div class="nx-card" style="margin-bottom:24px;border-color:${aoiColor}40;">
      <div style="display:flex;align-items:center;gap:40px;">
        <div class="nx-risk-ring">
          ${scoreRing(aoiScore, 1000, aoiColor)}
          <div style="font-size:11px;color:${DS.textMuted};text-transform:uppercase;letter-spacing:1px;">AOI Score</div>
        </div>
        <div style="flex:1;">
          <div style="font-size:32px;font-weight:800;color:${aoiColor};">${Math.round(aoiScore)}<span style="font-size:16px;color:${DS.textMuted};">/1000</span></div>
          <div style="font-size:14px;color:${DS.textMuted};margin-top:8px;">
            Adversary Opportunity: ${aoiScore > 700 ? 'CRITICAL — Immediate action required' : aoiScore > 400 ? 'HIGH — Multiple viable attack paths' : aoiScore > 200 ? 'MEDIUM — Controlled exposure' : 'LOW — Well defended'}
          </div>
          <div style="margin-top:16px;display:flex;gap:16px;">
            <div>
              <div style="font-size:11px;color:${DS.textMuted};">Choke Points</div>
              <div style="font-size:20px;font-weight:700;color:${DS.yellow};">${(latest?.choke_points || []).length}</div>
            </div>
            <div>
              <div style="font-size:11px;color:${DS.textMuted};">Attack Path Gaps</div>
              <div style="font-size:20px;font-weight:700;color:${DS.red};">${(latest?.attack_path_gaps || []).length}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- History -->
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-chart-line" style="color:${DS.accent};"></i> AOI History</div>
      <div style="height:100px;display:flex;align-items:flex-end;gap:4px;padding:8px 0;">
        ${records.slice(0, 30).reverse().map(r => {
          const pct = Math.min(100, (r.aoi_score / 1000) * 100);
          const col = pct > 70 ? DS.red : pct > 40 ? DS.orange : DS.green;
          return `<div style="flex:1;height:${pct}%;background:${col};border-radius:2px 2px 0 0;opacity:0.8;min-width:4px;"
            title="AOI: ${Math.round(r.aoi_score)} — ${new Date(r.computed_at).toLocaleDateString()}"></div>`;
        }).join('')}
      </div>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  SIGMA RULES
// ══════════════════════════════════════════════════════════════════════════════
async function renderSigma() {
  setContent(pageHeader('fa-file-code', 'Sigma Detection Rules', '3,750+ curated Sigma rules linked to ATT&CK techniques') + loader());

  try {
    const { data: rules, total } = await nexusApi('/sigma-rules?limit=100');

    const html = `
    ${pageHeader('fa-file-code', 'Sigma Rule Library', `${total || (rules || []).length} detection rules — community, custom & AI-generated`,
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.createSigmaRule()">
        <i class="fas fa-plus"></i> New Rule
      </button>`
    )}

    <div class="nx-grid nx-grid-4" style="margin-bottom:24px;">
      ${['stable', 'test', 'experimental', 'all'].map((status, i) => {
        const cnt = status === 'all' ? (rules || []).length : (rules || []).filter(r => r.status === status).length;
        const colors = [DS.green, DS.yellow, DS.orange, DS.accent];
        return `<div class="nx-kpi">
          <div class="nx-kpi-val" style="color:${colors[i]};">${cnt}</div>
          <div class="nx-kpi-label">${status.charAt(0).toUpperCase() + status.slice(1)}</div>
        </div>`;
      }).join('')}
    </div>

    <div class="nx-card">
      <div class="nx-card-title">
        <i class="fas fa-search" style="color:${DS.accent};"></i> Rule Library
        <div style="margin-left:auto;display:flex;gap:8px;">
          <input class="nx-search" placeholder="Search rules..." style="width:200px;">
          <select class="nx-select">
            <option value="">All Levels</option>
            <option>critical</option><option>high</option><option>medium</option><option>low</option>
          </select>
        </div>
      </div>
      <table class="nx-table">
        <thead><tr><th>Title</th><th>Level</th><th>Status</th><th>Techniques</th><th>Source</th><th>Enabled</th></tr></thead>
        <tbody>
          ${(rules || []).slice(0, 30).map(r => `<tr>
            <td style="font-weight:600;font-size:12px;">${h(r.title)}</td>
            <td>${sev(r.level)}</td>
            <td>${badge(r.status, r.status === 'stable' ? DS.green : r.status === 'test' ? DS.yellow : DS.orange)}</td>
            <td style="font-size:10px;color:${DS.cyan};">${(r.attack_techniques || []).slice(0, 2).join(', ') || '—'}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${h(r.source || 'community')}</td>
            <td>${r.enabled
              ? `<span style="color:${DS.green};"><i class="fas fa-check-circle"></i></span>`
              : `<span style="color:${DS.textMuted};"><i class="fas fa-times-circle"></i></span>`}
            </td>
          </tr>`).join('')}
          ${!(rules || []).length ? `<tr><td colspan="6" class="nx-empty">No Sigma rules loaded</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  CRISIS MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
async function renderCrisis() {
  setContent(pageHeader('fa-triangle-exclamation', 'Crisis Management', 'Tabletop exercises, crisis scenarios & after-action reports') + loader());

  try {
    const [scenarioResp, exerciseResp] = await Promise.all([
      nexusApi('/crisis/scenarios'),
      nexusApi('/crisis/exercises'),
    ]);

    const scenarios = scenarioResp.data || [];
    const exercises = exerciseResp.data || [];

    const html = `
    ${pageHeader('fa-triangle-exclamation', 'Crisis Management & Tabletop Exercises', 'Run TTX against seeded crisis scenarios — ransomware, breach, DDoS, insider...',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.newScenario2()">
        <i class="fas fa-plus"></i> New Scenario
      </button>`
    )}

    <div class="nx-grid nx-grid-2" style="margin-bottom:16px;">
      <!-- Scenarios -->
      <div class="nx-card">
        <div class="nx-card-title"><i class="fas fa-fire" style="color:${DS.red};"></i> Crisis Scenarios</div>
        <table class="nx-table" style="font-size:12px;">
          <thead><tr><th>Scenario</th><th>Type</th><th>Actions</th></tr></thead>
          <tbody>
            ${scenarios.map(s => `<tr>
              <td style="font-weight:600;">${h(s.name)}</td>
              <td>${badge(s.scenario_type, DS.orange, 'rgba(249,115,22,0.1)')}</td>
              <td>
                <button class="nx-btn nx-btn-primary" style="padding:3px 8px;font-size:10px;"
                  onclick="NexusModule.launchExercise('${s.id}')">
                  <i class="fas fa-play"></i> Launch TTX
                </button>
              </td>
            </tr>`).join('')}
            ${!scenarios.length ? `<tr><td colspan="3" class="nx-empty">No scenarios</td></tr>` : ''}
          </tbody>
        </table>
      </div>

      <!-- Exercises -->
      <div class="nx-card">
        <div class="nx-card-title"><i class="fas fa-clipboard-list" style="color:${DS.accent};"></i> Tabletop Exercises</div>
        <table class="nx-table" style="font-size:12px;">
          <thead><tr><th>Exercise</th><th>Status</th><th>Readiness</th><th>Date</th></tr></thead>
          <tbody>
            ${exercises.map(e => `<tr>
              <td style="font-weight:600;">${h(e.title)}</td>
              <td>${badge(e.status, e.status === 'completed' ? DS.green : e.status === 'in_progress' ? DS.accent : DS.textMuted)}</td>
              <td style="color:${(e.readiness_score || 0) > 70 ? DS.green : DS.orange};">
                ${Math.round(e.readiness_score || 0)}%
              </td>
              <td style="color:${DS.textMuted};">${ago(e.created_at)}</td>
            </tr>`).join('')}
            ${!exercises.length ? `<tr><td colspan="4" class="nx-empty">No exercises yet</td></tr>` : ''}
          </tbody>
        </table>
      </div>
    </div>`;

    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  GENERIC SIMPLE RENDERERS (stubs that render from API data)
// ══════════════════════════════════════════════════════════════════════════════
async function renderGenericList(icon, title, subtitle, endpoint, columns) {
  setContent(pageHeader(icon, title, subtitle) + loader());
  try {
    const { data } = await nexusApi(endpoint);
    const rows = data || [];
    const html = `
    ${pageHeader(icon, title, subtitle)}
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas ${icon}" style="color:${DS.accent};"></i> ${title}</div>
      <table class="nx-table">
        <thead><tr>${columns.map(c => `<th>${h(c.label)}</th>`).join('')}</tr></thead>
        <tbody>
          ${rows.map(r => `<tr>${columns.map(c => `<td style="font-size:12px;">${h(c.fn ? c.fn(r) : (r[c.key] || '—'))}</td>`).join('')}</tr>`).join('')}
          ${!rows.length ? `<tr><td colspan="${columns.length}" class="nx-empty">No data found</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;
    setContent(html);
  } catch (e) {
    setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`);
  }
}

function renderTPRM() {
  renderGenericList('fa-handshake', 'TPRM', 'Third-party risk assessments & vendor questionnaires', '/tprm/vendors', [
    { key: 'name', label: 'Vendor' },
    { key: 'vendor_type', label: 'Type' },
    { key: 'risk_tier', label: 'Risk Tier', fn: r => r.risk_tier?.toUpperCase() },
    { key: 'risk_score', label: 'Risk Score' },
    { key: 'assessment_status', label: 'Status' },
  ]);
}

function renderSBOM() {
  renderGenericList('fa-cubes', 'SBOM / SCA', 'Software Bill of Materials & composition analysis', '/sbom', [
    { key: 'name', label: 'SBOM' },
    { key: 'sbom_format', label: 'Format' },
    { key: 'component_count', label: 'Components' },
    { key: 'vuln_count', label: 'Vulnerable' },
    { key: 'license_issues', label: 'License Issues' },
  ]);
}

function renderPolicies() {
  renderGenericList('fa-file-shield', 'Policies & Documents', 'Policy lifecycle management with governance scoring', '/policies', [
    { key: 'title', label: 'Policy' },
    { key: 'policy_type', label: 'Type' },
    { key: 'framework', label: 'Framework' },
    { key: 'status', label: 'Status' },
    { key: 'owner_email', label: 'Owner' },
    { key: 'review_date', label: 'Review' },
  ]);
}

function renderInsurance() {
  setContent(pageHeader('fa-umbrella', 'Insurance Readiness', 'Cyber insurance readiness against FAIR-modeled ransomware loss') + loader());
  nexusApi('/insurance-readiness').then(({ data }) => {
    const d = data || {};
    const score = d.overall_score || 0;
    const html = `
    ${pageHeader('fa-umbrella', 'Cyber Insurance Readiness', 'Insurer\'s view — standard ransomware-supplemental control checklist',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.assessInsurance()">
        <i class="fas fa-calculator"></i> Assess
      </button>`
    )}
    <div class="nx-grid nx-grid-3" style="margin-bottom:24px;">
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${score > 70 ? DS.green : score > 40 ? DS.yellow : DS.red};">${Math.round(score)}%</div>
        <div class="nx-kpi-label">Readiness Score</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${DS.accent};">${d.policy_limit ? fmtCurrency(d.policy_limit) : 'N/A'}</div>
        <div class="nx-kpi-label">Policy Limit</div>
      </div>
      <div class="nx-kpi">
        <div class="nx-kpi-val" style="color:${d.coverage_adequate ? DS.green : DS.red};">
          ${d.coverage_adequate ? 'Adequate' : 'Gap'}
        </div>
        <div class="nx-kpi-label">Coverage vs FAIR Loss</div>
      </div>
    </div>
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-shield-alt" style="color:${DS.accent};"></i> Control Checklist</div>
      ${Object.entries(d.controls_status || {}).map(([ctrl, ok]) => `
        <div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid ${DS.border};">
          <i class="fas ${ok ? 'fa-check-circle' : 'fa-times-circle'}" style="color:${ok ? DS.green : DS.red};font-size:18px;"></i>
          <span style="font-size:13px;text-transform:capitalize;">${ctrl.replace(/_/g, ' ')}</span>
        </div>
      `).join('')}
      ${!Object.keys(d.controls_status || {}).length ? `<div class="nx-empty">No assessment performed yet</div>` : ''}
    </div>`;
    setContent(html);
  }).catch(e => setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`));
}

function renderPQCMM() {
  renderGenericList('fa-atom', 'Post-Quantum Readiness', 'PQCMM — PKI Consortium Post-Quantum Cryptography Maturity Model', '/pqcmm', [
    { key: 'name', label: 'Product/Service' },
    { key: 'current_level', label: 'Current Level (0-5)' },
    { key: 'target_level', label: 'Target Level' },
    { key: 'quantum_vulnerable', label: 'Vulnerable', fn: r => r.quantum_vulnerable ? '⚠️ YES' : 'No' },
    { key: 'cbom_present', label: 'CBOM', fn: r => r.cbom_present ? '✓' : '—' },
  ]);
}

function renderEBIOS() {
  renderGenericList('fa-sitemap', 'EBIOS RM', '5-workshop ANSSI EBIOS Risk Manager method', '/ebios', [
    { key: 'name', label: 'Study' },
    { key: 'status', label: 'Workshop' },
    { key: 'express_mode', label: 'Mode', fn: r => r.express_mode ? 'Express' : 'Full' },
    { key: 'owner_email', label: 'Owner' },
    { key: 'updated_at', label: 'Updated', fn: r => ago(r.updated_at) },
  ]);
}

function renderNIST() {
  renderGenericList('fa-landmark', 'NIST 800-30', 'NIST SP 800-30 risk assessment — threat sources, events & determinations', '/nist-800-30', [
    { key: 'name', label: 'Assessment' },
    { key: 'status', label: 'Status' },
    { key: 'owner_email', label: 'Owner' },
    { key: 'updated_at', label: 'Updated', fn: r => ago(r.updated_at) },
  ]);
}

function renderBIA() {
  renderGenericList('fa-building-shield', 'Business Impact Analysis', 'BIA entries with dependency graph and RTO/RPO tracking', '/bia', [
    { key: 'name', label: 'Process/System' },
    { key: 'criticality', label: 'Criticality' },
    { key: 'rto_hours', label: 'RTO (h)' },
    { key: 'rpo_hours', label: 'RPO (h)' },
    { key: 'financial_impact', label: 'Financial Impact', fn: r => fmtCurrency(r.financial_impact) },
  ]);
}

function renderDiscovery() {
  setContent(pageHeader('fa-radar', 'Attack Surface Discovery', 'OSINT-driven continuous attack surface monitoring') + loader());
  nexusApi('/discovery').then(({ data }) => {
    const runs = data || [];
    const html = `
    ${pageHeader('fa-radar', 'Attack Surface Discovery', 'OSINT chain: subfinder → theHarvester → Shodan → httpx → nmap → auto-populate inventory',
      `<button class="nx-btn nx-btn-primary" onclick="NexusModule.runDiscovery()">
        <i class="fas fa-search"></i> Start Discovery
      </button>`
    )}
    <div class="nx-card">
      <div class="nx-card-title"><i class="fas fa-history" style="color:${DS.accent};"></i> Discovery Runs</div>
      <table class="nx-table">
        <thead><tr><th>Seed Domain</th><th>Status</th><th>Discovered Hosts</th><th>New Assets</th><th>Mode</th><th>Started</th></tr></thead>
        <tbody>
          ${runs.map(r => `<tr>
            <td style="font-family:monospace;color:${DS.accent};">${h(r.seed_domain)}</td>
            <td>${badge(r.status, r.status === 'completed' ? DS.green : r.status === 'running' ? DS.accent : DS.red)}</td>
            <td>${r.discovered_hosts || 0}</td>
            <td style="color:${DS.green};">${r.new_assets || 0}</td>
            <td style="font-size:11px;">${badge(r.run_mode, r.run_mode === 'live' ? DS.red : DS.textMuted)}</td>
            <td style="font-size:11px;color:${DS.textMuted};">${ago(r.started_at)}</td>
          </tr>`).join('')}
          ${!runs.length ? `<tr><td colspan="6" class="nx-empty">No discovery runs</td></tr>` : ''}
        </tbody>
      </table>
    </div>`;
    setContent(html);
  }).catch(e => setContent(`<div class="nx-empty">Error: ${h(e.message)}</div>`));
}

function renderJobs() {
  renderGenericList('fa-clock', 'Background Scheduler', 'XSCHEDULE — CVE importer, risk score, attack paths, BAS runs', '/jobs', [
    { key: 'name', label: 'Job Name' },
    { key: 'job_type', label: 'Type' },
    { key: 'cron_expression', label: 'Schedule' },
    { key: 'last_status', label: 'Last Status' },
    { key: 'last_run_at', label: 'Last Run', fn: r => ago(r.last_run_at) },
    { key: 'enabled', label: 'Enabled', fn: r => r.enabled ? '✓ Active' : '✗ Off' },
  ]);
}

function renderIdentities() {
  renderGenericList('fa-user-shield', 'Identities', 'Human & non-human identities — Entra ID sync, stale/orphaned detection', '/identities', [
    { key: 'display_name', label: 'Identity' },
    { key: 'identity_type', label: 'Type' },
    { key: 'email', label: 'Email' },
    { key: 'source', label: 'Source' },
    { key: 'is_stale', label: 'Stale', fn: r => r.is_stale ? '⚠️ Stale' : '—' },
    { key: 'mfa_enabled', label: 'MFA', fn: r => r.mfa_enabled ? '✓' : '✗' },
  ]);
}

function renderYARA() {
  renderGenericList('fa-code', 'YARA Rules', 'YARA malware detection rules for endpoint scanning', '/yara-rules', [
    { key: 'name', label: 'Rule Name' },
    { key: 'severity', label: 'Severity' },
    { key: 'malware_family', label: 'Malware Family' },
    { key: 'source', label: 'Source' },
    { key: 'match_count', label: 'Matches' },
    { key: 'enabled', label: 'Enabled', fn: r => r.enabled ? '✓' : '✗' },
  ]);
}

function renderPentest() {
  renderGenericList('fa-terminal', 'Pentest Engagements', 'Scoped penetration tests with ROE, findings & PDF reports', '/pentest', [
    { key: 'title', label: 'Engagement' },
    { key: 'pentest_type', label: 'Type' },
    { key: 'status', label: 'Status' },
    { key: 'lead_tester', label: 'Lead Tester' },
    { key: 'critical_count', label: 'Critical Findings' },
    { key: 'start_date', label: 'Start Date' },
  ]);
}

function renderFAIRMAM() {
  renderGenericList('fa-chart-bar', 'FAIR-MAM Materiality', 'FAIR Institute Materiality Assessment Model — 10 cost categories, PERT ranges', '/fair-mam', [
    { key: 'name', label: 'Assessment' },
    { key: 'expected_sle', label: 'Expected SLE', fn: r => fmtCurrency(r.expected_sle) },
    { key: 'primary_loss', label: 'Primary Loss', fn: r => fmtCurrency(r.primary_loss) },
    { key: 'is_material', label: 'Material', fn: r => r.is_material ? `<span style="color:${DS.red};">YES</span>` : 'No' },
    { key: 'updated_at', label: 'Updated', fn: r => ago(r.updated_at) },
  ]);
}

// ══════════════════════════════════════════════════════════════════════════════
//  ACTION HANDLERS
// ══════════════════════════════════════════════════════════════════════════════
async function recomputeRisk() {
  showToast('Recomputing enterprise risk score...', 'info');
  try {
    const { data } = await nexusApi('/risk-score/compute', { method: 'POST' });
    showToast(`Risk score: ${Math.round(data.enterprise_risk_score)}/100`, 'success');
    renderDashboard();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function computeAttackPaths() {
  showToast('Computing attack paths...', 'info');
  try {
    const { data } = await nexusApi('/attack-paths/compute', { method: 'POST' });
    showToast(`${data.paths_computed} paths computed`, 'success');
    renderAttackPaths();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function matchCVEs() {
  showToast('Matching CVEs to assets...', 'info');
  try {
    const { data } = await nexusApi('/vulnerabilities/match-assets', { method: 'POST' });
    showToast(`${data.matched} asset-CVE links created`, 'success');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function computeRansomware() {
  showToast('Computing ransomware scenario...', 'info');
  try {
    const { data } = await nexusApi('/ransomware/compute', {
      method: 'POST',
      body: JSON.stringify({ threat_actor: 'LockBit 3.0', aro_estimate: 0.15 }),
    });
    showToast(`ALE: ${fmtCurrency(data.total_ale)}`, 'success');
    renderRansomware();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function computeAOI() {
  showToast('Computing Adversary Opportunity Index...', 'info');
  try {
    const { data } = await nexusApi('/aoi/compute', { method: 'POST' });
    showToast(`AOI Score: ${Math.round(data.aoi_score)}/1000`, 'success');
    renderAOI();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function runScenario(scenarioId) {
  showToast('Running emulation scenario...', 'info');
  try {
    const { data } = await nexusApi(`/emulation/scenarios/${scenarioId}/run`, { method: 'POST' });
    showToast(`Coverage: ${data.coverage_pct}%`, 'success');
    renderBAS();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function runConnector(connectorId) {
  showToast('Running connector...', 'info');
  try {
    const { data } = await nexusApi(`/connectors/${connectorId}/run`, { method: 'POST' });
    showToast(`Job queued: ${data.job_id}`, 'success');
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function launchExercise(scenarioId) {
  showToast('Launching tabletop exercise...', 'info');
  try {
    await nexusApi(`/crisis/scenarios/${scenarioId}/launch-exercise`, { method: 'POST' });
    showToast('Exercise launched!', 'success');
    renderCrisis();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function exportNavigatorLayer() {
  try {
    const token    = localStorage.getItem('wadjet_token') || localStorage.getItem('auth_token');
    const tenantId = localStorage.getItem('tenant_id');
    const url = `${API_BASE}/api/nexus/tid/navigator-export`;
    const resp = await fetch(url, { headers: { 'Authorization': `Bearer ${token}`, 'X-Tenant-ID': tenantId } });
    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'nexus_tid_layer.json';
    a.click();
    showToast('Navigator layer exported', 'success');
  } catch (e) {
    showToast(`Export error: ${e.message}`, 'error');
  }
}

async function assessInsurance() {
  showToast('Running insurance readiness assessment...', 'info');
  try {
    const { data } = await nexusApi('/insurance-readiness/assess', {
      method: 'POST',
      body: JSON.stringify({ controls_status: { mfa: true, backups: true, edr_siem: true, pam: false, patching: true, tested_ir: false, segmentation: false } }),
    });
    showToast(`Readiness: ${Math.round(data.overall_score)}%`, 'success');
    renderInsurance();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

async function runDiscovery() {
  const domain = prompt('Enter seed domain for discovery (e.g. example.com):');
  if (!domain) return;
  showToast('Starting attack surface discovery...', 'info');
  try {
    const { data } = await nexusApi('/discovery/run', {
      method: 'POST',
      body: JSON.stringify({ seed_domain: domain, run_mode: 'simulate' }),
    });
    showToast(`Discovered ${data.discovered?.length || 0} hosts`, 'success');
    renderDiscovery();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

function showTechnique(techId) {
  showToast(`Technique ${techId} — opens TID Cockpit`, 'info');
}

// Stubs for new modals
function newHunt() { showToast('New Hunt — form coming soon', 'info'); }
function newRisk() { showToast('New Risk — form coming soon', 'info'); }
function newCampaign() { showToast('New Campaign — form coming soon', 'info'); }
function newScenario() { showToast('New BAS Scenario — form coming soon', 'info'); }
function newScenario2() { showToast('New Crisis Scenario — form coming soon', 'info'); }
function newForensicCase() { showToast('New DFIR Case — form coming soon', 'info'); }
function newAudit() { showToast('New Audit — form coming soon', 'info'); }
function addConnector() { showToast('Add Connector — form coming soon', 'info'); }
function openCase(id) { showToast(`Opening case ${id}...`, 'info'); }
function createSigmaRule() { showToast('New Sigma Rule — form coming soon', 'info'); }
function filterHunts() {}
function filterControls() {}
function filterConnectors() {}
function searchVulns() {}
function searchConnectors() {}
function filterVulns() {}

// ── Toast Notifications ───────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const colors = { success: DS.green, error: DS.red, info: DS.accent, warning: DS.yellow };
  const icons  = { success: 'fa-check-circle', error: 'fa-times-circle', info: 'fa-info-circle', warning: 'fa-exclamation-circle' };

  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:99999;
    background:${DS.bgPanel};border:1px solid ${colors[type] || DS.border};
    border-left:4px solid ${colors[type] || DS.accent};
    padding:12px 20px;border-radius:8px;
    display:flex;align-items:center;gap:10px;
    font-size:13px;color:${DS.text};font-family:Inter,sans-serif;
    box-shadow:0 8px 32px rgba(0,0,0,0.5);
    animation:nx-slide-in 0.3s ease;max-width:360px;
  `;
  toast.innerHTML = `<i class="fas ${icons[type] || 'fa-info-circle'}" style="color:${colors[type]};"></i>${h(message)}`;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity 0.3s'; setTimeout(() => toast.remove(), 300); }, 3500);
}

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════════════════════════════════════════
const NexusModule = {
  init:   renderNexusPage,
  goto:   renderNexusPage,   // goto(page, el?) — el is the page-nexus-* div
  render: renderNexusPage,

  // Dashboard
  recomputeRisk,

  // Vulnerability
  matchCVEs, searchVulns, filterVulns,

  // Attack Paths
  computeAttackPaths,

  // BAS
  runScenario, newScenario,

  // Connectors
  runConnector, addConnector, searchConnectors, filterConnectors,

  // TID
  exportNavigatorLayer, showTechnique,

  // Risk
  computeRansomware, computeAOI, assessInsurance,

  // Discovery
  runDiscovery,

  // Hunt
  newHunt, filterHunts,

  // GRC
  newAudit, filterControls,

  // Risk Register
  newRisk,

  // DFIR
  newForensicCase, openCase,

  // Crisis
  launchExercise, newScenario2,

  // Sigma
  createSigmaRule,

  // Insurance
  assessInsurance,
};

// Expose globally for onclick handlers in HTML attributes
if (typeof window !== 'undefined') { window.NexusModule = NexusModule; }

// CommonJS export — guarded so it doesn't throw in a browser context
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NexusModule;
}

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
