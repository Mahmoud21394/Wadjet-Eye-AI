/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Intel DB  v1.0
 *  backend/services/intel-db.js
 *
 *  Provides in-memory CVE + MITRE ATT&CK intelligence database
 *  populated from CISA KEV, NVD, and the embedded MITRE dataset.
 *  No external API calls at construction time — data is loaded
 *  lazily from Supabase or from bundled JSON seeds.
 *
 *  Public API (used by soc-intelligence routes):
 *   db.getCVE(id)                    → CVE object | null
 *   db.getMITRE(id)                  → MITRE technique | null
 *   db.getLatestCritical(n)          → CVE[]
 *   db.getExploitedCVEs(n)           → CVE[]
 *   db.searchCVEs({keyword,severity,exploited,limit}) → CVE[]
 *   db.searchMITRE({keyword,tactic,limit})            → Technique[]
 *   db.getTechniquesForCVE(cveId)    → Technique[]
 *   db.getCVEsForTechnique(techId)   → CVE[]
 *   db.formatCVEForSOC(id)           → formatted string
 *   db.formatMITREForSOC(id)         → formatted string
 *   db.getStats()                    → { cve:{total,exploited,critical}, mitre:{total} }
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Supabase (optional — falls back to in-memory seeds) ───────────
let supabase = null;
try { supabase = require('../config/supabase').supabase; } catch (_) {}

// ── Severity → CVSS thresholds ────────────────────────────────────
const SEVERITY_MAP = {
  CRITICAL: { min: 9.0, max: 10.0 },
  HIGH:     { min: 7.0, max: 8.9  },
  MEDIUM:   { min: 4.0, max: 6.9  },
  LOW:      { min: 0.1, max: 3.9  },
};

function cvssToSeverity(score) {
  const s = parseFloat(score) || 0;
  if (s >= 9.0) return 'CRITICAL';
  if (s >= 7.0) return 'HIGH';
  if (s >= 4.0) return 'MEDIUM';
  return 'LOW';
}

// ── Embedded seed data (always-available fallback) ────────────────
// A curated set of high-profile CVEs and MITRE techniques
const SEED_CVES = [
  { id:'CVE-2024-3400', vendor:'Palo Alto Networks', product:'PAN-OS', cvss_score:10.0, severity:'CRITICAL', exploited:true, description:'Command injection in GlobalProtect Gateway. Requires no auth.', published_date:'2024-04-12', cwe:'CWE-77', mitre_techniques:['T1190'] },
  { id:'CVE-2024-21762', vendor:'Fortinet', product:'FortiOS', cvss_score:9.6, severity:'CRITICAL', exploited:true, description:'Out-of-bounds write in SSL VPN allows RCE without authentication.', published_date:'2024-02-08', cwe:'CWE-787', mitre_techniques:['T1190'] },
  { id:'CVE-2023-44487', vendor:'IETF', product:'HTTP/2 Protocol', cvss_score:7.5, severity:'HIGH', exploited:true, description:'HTTP/2 Rapid Reset Attack enables DDoS amplification.', published_date:'2023-10-10', cwe:'CWE-400', mitre_techniques:['T1499'] },
  { id:'CVE-2023-34048', vendor:'VMware', product:'vCenter Server', cvss_score:9.8, severity:'CRITICAL', exploited:true, description:'Out-of-bounds write in DCERPC protocol implementation.', published_date:'2023-10-25', cwe:'CWE-787', mitre_techniques:['T1210'] },
  { id:'CVE-2024-1709',  vendor:'ConnectWise', product:'ScreenConnect', cvss_score:10.0, severity:'CRITICAL', exploited:true, description:'Authentication bypass allows unauthenticated RCE.', published_date:'2024-02-21', cwe:'CWE-288', mitre_techniques:['T1190','T1133'] },
  { id:'CVE-2024-6387',  vendor:'OpenSSH', product:'OpenSSH', cvss_score:8.1, severity:'HIGH', exploited:false, description:'regreSSHion: Race condition in signal handler allows unauthenticated RCE.', published_date:'2024-07-01', cwe:'CWE-364', mitre_techniques:['T1210'] },
  { id:'CVE-2021-44228', vendor:'Apache', product:'Log4j 2', cvss_score:10.0, severity:'CRITICAL', exploited:true, description:'Log4Shell: JNDI injection enables unauthenticated RCE.', published_date:'2021-12-09', cwe:'CWE-917', mitre_techniques:['T1190','T1059'] },
  { id:'CVE-2022-30190', vendor:'Microsoft', product:'Windows MSDT', cvss_score:7.8, severity:'HIGH', exploited:true, description:'Follina: MSDT code execution from Word documents.', published_date:'2022-05-30', cwe:'CWE-610', mitre_techniques:['T1203','T1566'] },
  { id:'CVE-2023-23397', vendor:'Microsoft', product:'Outlook', cvss_score:9.8, severity:'CRITICAL', exploited:true, description:'Zero-click NTLM hash theft via specially crafted email.', published_date:'2023-03-14', cwe:'CWE-294', mitre_techniques:['T1187','T1566'] },
  { id:'CVE-2024-38213', vendor:'Microsoft', product:'Windows', cvss_score:6.5, severity:'MEDIUM', exploited:true, description:'Mark-of-the-Web bypass allows SmartScreen evasion.', published_date:'2024-08-13', cwe:'CWE-693', mitre_techniques:['T1553','T1566'] },
];

const SEED_MITRE = [
  { id:'T1190', name:'Exploit Public-Facing Application', tactic:'initial-access', severity:'critical', description:'Adversaries exploit weaknesses in internet-facing software to gain initial access.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic','Application Log'], detection:'Monitor for unexpected inbound connections to internal services and patch aggressively.' },
  { id:'T1133', name:'External Remote Services', tactic:'initial-access', severity:'high', description:'Adversaries leverage external-facing remote services such as VPNs and RDP.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic','Authentication Logs'], detection:'Enforce MFA on all external remote services. Monitor failed auth attempts.' },
  { id:'T1566', name:'Phishing', tactic:'initial-access', severity:'high', description:'Send malicious messages to gain initial access via user interaction.', platforms:['Linux','Windows','macOS'], data_sources:['Email Gateway','Endpoint'], detection:'Email filtering, user training, DMARC/DKIM enforcement.' },
  { id:'T1059', name:'Command and Scripting Interpreter', tactic:'execution', severity:'high', description:'Abuse command-line interfaces and scripting engines to execute commands.', platforms:['Linux','Windows','macOS'], data_sources:['Process Creation','Command History'], detection:'Script-block logging, PowerShell AMSI, restrict shell access.' },
  { id:'T1203', name:'Exploitation for Client Execution', tactic:'execution', severity:'high', description:'Exploit client-side software vulnerabilities to execute code.', platforms:['Linux','Windows','macOS'], data_sources:['Process Creation','Application Log'], detection:'Application sandboxing, keep software patched.' },
  { id:'T1210', name:'Exploitation of Remote Services', tactic:'lateral-movement', severity:'critical', description:'Exploit remote services to move laterally within the network.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic','Process Creation'], detection:'Segment network, apply patches, monitor for lateral movement indicators.' },
  { id:'T1187', name:'Forced Authentication', tactic:'credential-access', severity:'high', description:'Coerce systems to authenticate to attacker-controlled resources for hash capture.', platforms:['Windows'], data_sources:['Network Traffic','Authentication Logs'], detection:'Block outbound SMB, use credential guard, monitor for unusual NTLM traffic.' },
  { id:'T1499', name:'Endpoint Denial of Service', tactic:'impact', severity:'high', description:'Disrupt availability via resource exhaustion or traffic floods.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic','Infrastructure Logs'], detection:'Rate limiting, DDoS protection services, anomaly-based network monitoring.' },
  { id:'T1553', name:'Subvert Trust Controls', tactic:'defense-evasion', severity:'medium', description:'Bypass security controls by manipulating trust mechanisms.', platforms:['Windows','macOS'], data_sources:['File Creation','Process Creation'], detection:'Monitor for certificate store modifications and Mark-of-the-Web bypass attempts.' },
  { id:'T1078', name:'Valid Accounts', tactic:'defense-evasion', severity:'high', description:'Use legitimate credentials to maintain access and blend in with normal traffic.', platforms:['Linux','Windows','macOS'], data_sources:['Authentication Logs','Cloud Logs'], detection:'Behavioral analytics, MFA, privileged access management.' },
  { id:'T1021', name:'Remote Services', tactic:'lateral-movement', severity:'high', description:'Use remote services such as RDP, SSH, SMB for lateral movement.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic','Authentication Logs'], detection:'Restrict RDP/SSH access, use jump hosts, monitor for unusual sessions.' },
  { id:'T1486', name:'Data Encrypted for Impact', tactic:'impact', severity:'critical', description:'Encrypt data on target systems to interrupt availability (ransomware).', platforms:['Linux','Windows','macOS'], data_sources:['File Monitoring','Process Creation'], detection:'Monitor for mass file encryption, backup critical data, EDR behavioral detection.' },
  { id:'T1071', name:'Application Layer Protocol', tactic:'command-and-control', severity:'medium', description:'Use standard application layer protocols for C2 communications.', platforms:['Linux','Windows','macOS'], data_sources:['Network Traffic'], detection:'Deep packet inspection, DNS monitoring, proxy for egress traffic.' },
];

// ═══════════════════════════════════════════════════════════════════
//  IntelDB Class
// ═══════════════════════════════════════════════════════════════════
class IntelDB {
  constructor() {
    this._cves      = new Map(); // id → CVE object
    this._mitre     = new Map(); // id → technique object
    this._cveTech   = new Map(); // cve_id → Set<tech_id>
    this._techCVE   = new Map(); // tech_id → Set<cve_id>
    this._initialized = false;
    this._init();
  }

  // ── Bootstrap from seeds synchronously ─────────────────────────
  _init() {
    for (const cve of SEED_CVES) {
      this._cves.set(cve.id, { ...cve });
      for (const techId of (cve.mitre_techniques || [])) {
        if (!this._cveTech.has(cve.id)) this._cveTech.set(cve.id, new Set());
        this._cveTech.get(cve.id).add(techId);
        if (!this._techCVE.has(techId)) this._techCVE.set(techId, new Set());
        this._techCVE.get(techId).add(cve.id);
      }
    }
    for (const tech of SEED_MITRE) {
      this._mitre.set(tech.id, { ...tech });
    }
    this._initialized = true;
    console.info(`[IntelDB] Initialized: ${this._cves.size} CVEs, ${this._mitre.size} MITRE techniques`);
    // Async enrich from DB — non-blocking
    this._enrichFromDB().catch(() => {});
  }

  // ── Async enrich from Supabase (if available) ──────────────────
  async _enrichFromDB() {
    if (!supabase) return;
    try {
      const { data: cves } = await supabase
        .from('vulnerabilities')
        .select('cve_id,title,description,severity,cvss_v3_score,exploited_in_wild,published_at')
        .limit(1000);
      if (cves) {
        for (const c of cves) {
          if (!c.cve_id) continue;
          const id = c.cve_id.toUpperCase();
          if (!this._cves.has(id)) {
            this._cves.set(id, {
              id,
              vendor:        c.vendor || 'Unknown',
              product:       c.product || c.title || '',
              cvss_score:    c.cvss_v3_score || 0,
              severity:      c.severity || cvssToSeverity(c.cvss_v3_score),
              exploited:     c.exploited_in_wild || false,
              description:   c.description || '',
              published_date:c.published_at ? c.published_at.slice(0,10) : null,
              mitre_techniques: [],
            });
          }
        }
        console.info(`[IntelDB] DB enrichment: added ${cves.length} CVEs from Supabase`);
      }
    } catch (err) {
      console.warn('[IntelDB] DB enrichment skipped:', err.message);
    }
  }

  // ── Public getters ──────────────────────────────────────────────
  getCVE(id) {
    return this._cves.get(id?.toUpperCase()) || null;
  }

  getMITRE(id) {
    return this._mitre.get(id?.toUpperCase()) || null;
  }

  getLatestCritical(n = 10) {
    return [...this._cves.values()]
      .filter(c => c.severity === 'CRITICAL' || c.cvss_score >= 9.0)
      .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
      .slice(0, n);
  }

  getExploitedCVEs(n = 20) {
    return [...this._cves.values()]
      .filter(c => c.exploited)
      .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
      .slice(0, n);
  }

  searchCVEs({ keyword, severity, exploited, limit = 10 } = {}) {
    let results = [...this._cves.values()];
    if (keyword) {
      const kw = keyword.toLowerCase();
      results = results.filter(c =>
        c.id?.toLowerCase().includes(kw) ||
        c.description?.toLowerCase().includes(kw) ||
        c.vendor?.toLowerCase().includes(kw) ||
        c.product?.toLowerCase().includes(kw)
      );
    }
    if (severity) {
      results = results.filter(c => c.severity?.toUpperCase() === severity.toUpperCase());
    }
    if (exploited !== undefined) {
      results = results.filter(c => !!c.exploited === !!exploited);
    }
    return results
      .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
      .slice(0, Math.min(limit, 50));
  }

  searchMITRE({ keyword, tactic, severity, limit = 10 } = {}) {
    let results = [...this._mitre.values()];
    if (keyword) {
      const kw = keyword.toLowerCase();
      results = results.filter(t =>
        t.id?.toLowerCase().includes(kw) ||
        t.name?.toLowerCase().includes(kw) ||
        t.description?.toLowerCase().includes(kw) ||
        t.tactic?.toLowerCase().includes(kw)
      );
    }
    if (tactic) {
      results = results.filter(t => t.tactic?.toLowerCase() === tactic.toLowerCase());
    }
    if (severity) {
      results = results.filter(t => t.severity?.toLowerCase() === severity.toLowerCase());
    }
    return results.slice(0, Math.min(limit, 50));
  }

  getTechniquesForCVE(cveId) {
    const techIds = this._cveTech.get(cveId?.toUpperCase()) || new Set();
    return [...techIds].map(id => this._mitre.get(id)).filter(Boolean);
  }

  getCVEsForTechnique(techId) {
    const cveIds = this._techCVE.get(techId?.toUpperCase()) || new Set();
    return [...cveIds].map(id => this._cves.get(id)).filter(Boolean);
  }

  formatCVEForSOC(id) {
    const cve = this.getCVE(id);
    if (!cve) return null;
    const techs = this.getTechniquesForCVE(id).map(t => `${t.id} (${t.name})`).join(', ') || 'None mapped';
    return [
      `## ${cve.id} — ${cve.vendor} ${cve.product}`,
      `**Severity:** ${cve.severity} (CVSS ${cve.cvss_score})`,
      `**Exploited:** ${cve.exploited ? '🔴 YES — Actively exploited in the wild' : '⚪ No confirmed exploitation'}`,
      `**Published:** ${cve.published_date || 'Unknown'}`,
      `**Description:** ${cve.description}`,
      `**MITRE Techniques:** ${techs}`,
      `**NVD:** https://nvd.nist.gov/vuln/detail/${cve.id}`,
    ].join('\n');
  }

  formatMITREForSOC(id) {
    const t = this.getMITRE(id);
    if (!t) return null;
    return [
      `## ${t.id} — ${t.name}`,
      `**Tactic:** ${t.tactic}  |  **Severity:** ${t.severity?.toUpperCase()}`,
      `**Platforms:** ${(t.platforms || []).join(', ')}`,
      `**Description:** ${t.description}`,
      `**Detection:** ${t.detection}`,
      `**Data Sources:** ${(t.data_sources || []).join(', ')}`,
      `**ATT&CK URL:** https://attack.mitre.org/techniques/${t.id}/`,
    ].join('\n');
  }

  getStats() {
    const cves = [...this._cves.values()];
    return {
      cve: {
        total:    cves.length,
        exploited:cves.filter(c => c.exploited).length,
        critical: cves.filter(c => c.severity === 'CRITICAL' || c.cvss_score >= 9.0).length,
      },
      mitre: {
        total: this._mitre.size,
      },
    };
  }
}

// ── Singleton export ───────────────────────────────────────────────
const defaultDB = new IntelDB();

module.exports = { IntelDB, defaultDB };
