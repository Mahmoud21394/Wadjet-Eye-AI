/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Correlator  v1.0
 *  backend/services/threat-correlation.js
 *
 *  Correlates IOCs, CVEs, threat actor TTPs, and behavioral
 *  indicators against the in-memory intelligence database.
 *  No external API calls — pure in-memory analytics.
 *
 *  Public API (used by soc-intelligence routes):
 *   correlator.correlate(input)              → correlation result
 *   correlator.getHighRiskMap()              → risk map object
 *   correlator.generateHuntingHypothesis(topic) → hunt hypothesis
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Optional: load IntelDB for richer cross-linking ───────────────
let intelDB = null;
try { intelDB = require('./intel-db').defaultDB; } catch (_) {}

// ── Known threat actor TTP mappings ──────────────────────────────
const ACTOR_TTPS = {
  'APT28': { country: 'Russia', alias: ['Fancy Bear','Sofacy'], techniques: ['T1566','T1059','T1078','T1021','T1071'], campaigns: ['Election interference','NATO espionage'] },
  'APT29': { country: 'Russia', alias: ['Cozy Bear','Nobelium'], techniques: ['T1078','T1071','T1021','T1133','T1190'], campaigns: ['SolarWinds','COVID-19 vaccine research'] },
  'APT41': { country: 'China',  alias: ['Winnti','Barium'],     techniques: ['T1190','T1059','T1078','T1210','T1486'], campaigns: ['Supply chain attacks','Healthcare'] },
  'Lazarus':{ country: 'DPRK', alias: ['Hidden Cobra'],         techniques: ['T1566','T1203','T1059','T1486','T1190'], campaigns: ['SWIFT banking','Cryptocurrency theft'] },
  'BlackCat':{ country: 'Unknown', alias: ['ALPHV'],            techniques: ['T1486','T1078','T1210','T1059'],        campaigns: ['Ransomware-as-a-Service'] },
  'LockBit': { country: 'Unknown', alias: ['LockBit 3.0'],      techniques: ['T1486','T1210','T1078','T1021'],        campaigns: ['Global ransomware operations'] },
  'Scattered Spider':{ country: 'Unknown', alias: ['UNC3944'],  techniques: ['T1566','T1078','T1133','T1059'],        campaigns: ['MGM Resorts','Caesars Entertainment'] },
};

// ── IOC type pattern matchers ─────────────────────────────────────
const IOC_PATTERNS = {
  ip:       /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
  domain:   /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i,
  hash_md5: /^[a-fA-F0-9]{32}$/,
  hash_sha1:/^[a-fA-F0-9]{40}$/,
  hash_sha256:/^[a-fA-F0-9]{64}$/,
  url:      /^https?:\/\//,
  email:    /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  cve:      /^CVE-\d{4}-\d{4,}$/i,
};

// ── Risk scoring weights ───────────────────────────────────────────
const RISK_WEIGHTS = {
  known_malicious_ip:    90,
  known_malicious_domain:85,
  known_actor_technique: 80,
  critical_cve:          95,
  ransomware_technique:  88,
  lateral_movement:      75,
  exfiltration:          70,
};

// ── Hunting hypotheses templates ──────────────────────────────────
const HUNT_TEMPLATES = {
  ransomware: {
    hypothesis: 'Ransomware actors may have established persistence and are staging for encryption',
    techniques: ['T1486','T1078','T1210','T1021'],
    data_sources: ['File Integrity Monitoring','EDR process events','Network flow logs'],
    hunt_steps: [
      'Hunt for mass file rename/write events (>50 files/min per process)',
      'Look for VSS deletion: vssadmin.exe or wmic.exe with "shadow" arguments',
      'Identify unusual lateral movement patterns (T1021) in the 48h before encryption',
      'Check for credential dumping artifacts (LSASS access) preceding ransomware',
      'Correlate remote logins from non-standard IPs with file encryption activity',
    ],
    detection_queries: ['T1486','T1078','T1021'],
  },
  phishing: {
    hypothesis: 'Spear-phishing campaign targeting users with malicious attachments or links',
    techniques: ['T1566','T1203','T1059'],
    data_sources: ['Email gateway logs','Endpoint process events','DNS logs'],
    hunt_steps: [
      'Review emails with .docm/.xlsm/.iso/.img attachments in last 7 days',
      'Look for Office spawning cmd.exe or PowerShell (T1203)',
      'Hunt for encoded PowerShell execution (-EncodedCommand, IEX)',
      'Check DNS for newly registered domains within last 30 days used in emails',
      'Correlate clicked links with subsequent PowerShell or wscript activity',
    ],
    detection_queries: ['T1566','T1203','T1059'],
  },
  'lateral-movement': {
    hypothesis: 'Adversary has foothold and is moving laterally via remote services',
    techniques: ['T1021','T1210','T1078','T1187'],
    data_sources: ['Windows Security Event Logs','Network flow data','Authentication logs'],
    hunt_steps: [
      'Map all SMB connections (port 445) between workstations (not server-to-server)',
      'Look for PsExec, WMI, and DCOM lateral movement artifacts',
      'Hunt for account logons from unusual source IPs',
      'Check for NTLM authentication to external IPs (hash relay attacks)',
      'Correlate privileged account usage across multiple systems in short timeframe',
    ],
    detection_queries: ['T1021','T1210','T1187'],
  },
  'credential-theft': {
    hypothesis: 'Adversary is harvesting credentials for privilege escalation or persistence',
    techniques: ['T1078','T1187','T1059'],
    data_sources: ['LSASS access logs','Registry monitoring','Process creation logs'],
    hunt_steps: [
      'Hunt for LSASS process access (Event 10 in Sysmon) by non-system processes',
      'Look for Mimikatz indicators: sekurlsa::, lsadump::, kerberos:: in command lines',
      'Check for DCSync activity: replication directory changes from non-DC machines',
      'Hunt for credential dumping via comsvcs.dll (Task Manager dump)',
      'Look for Kerberoasting: unusual TGS requests for service accounts',
    ],
    detection_queries: ['T1078','T1187'],
  },
  'command-and-control': {
    hypothesis: 'Implant communicating with C2 infrastructure over common protocols',
    techniques: ['T1071','T1059','T1190'],
    data_sources: ['DNS logs','Proxy/HTTP logs','NetFlow data'],
    hunt_steps: [
      'Hunt for beaconing patterns: consistent intervals (±5%) to same external IP',
      'Look for DNS TXT record queries with high entropy names',
      'Check for large outbound transfers to uncommon geographies',
      'Hunt for HTTPS to IPs without valid SNI (possible C2 via IP)',
      'Look for process making unusual outbound connections (svchost → external IPs)',
    ],
    detection_queries: ['T1071'],
  },
};

// ═══════════════════════════════════════════════════════════════════
//  ThreatCorrelator Class
// ═══════════════════════════════════════════════════════════════════
class ThreatCorrelator {
  constructor() {
    console.info('[ThreatCorrelator] Initialized');
  }

  // ── Detect IOC type ────────────────────────────────────────────
  _detectIOCType(value) {
    if (!value) return 'unknown';
    const v = value.trim();
    for (const [type, re] of Object.entries(IOC_PATTERNS)) {
      if (re.test(v)) return type;
    }
    return 'unknown';
  }

  // ── Parse mixed input (IOCs, CVEs, technique IDs, actor names) ─
  _parseInput(input) {
    const tokens = typeof input === 'string'
      ? input.split(/[\s,;|\n]+/).map(t => t.trim()).filter(Boolean)
      : Array.isArray(input) ? input : [String(input)];

    const iocs        = [];
    const cves        = [];
    const techniques  = [];
    const actors      = [];

    for (const tok of tokens) {
      if (/^CVE-\d{4}-\d+$/i.test(tok)) {
        cves.push(tok.toUpperCase());
      } else if (/^T\d{4}(\.\d{3})?$/i.test(tok)) {
        techniques.push(tok.toUpperCase());
      } else if (ACTOR_TTPS[tok] || Object.values(ACTOR_TTPS).some(a => a.alias?.map(x=>x.toLowerCase()).includes(tok.toLowerCase()))) {
        actors.push(tok);
      } else {
        const type = this._detectIOCType(tok);
        if (type !== 'unknown') {
          iocs.push({ value: tok, type });
        }
      }
    }

    return { iocs, cves, techniques, actors, raw: tokens };
  }

  // ── Correlate input against threat intelligence ────────────────
  correlate(input) {
    const parsed    = this._parseInput(input);
    const findings  = [];
    const relatedTechniques = new Set();
    const relatedActors     = [];
    let   maxRisk   = 0;

    // ── CVE correlation ─────────────────────────────────────────
    for (const cveId of parsed.cves) {
      const cve = intelDB?.getCVE(cveId);
      if (cve) {
        const risk = cve.severity === 'CRITICAL' ? 95 : cve.severity === 'HIGH' ? 75 : 50;
        maxRisk = Math.max(maxRisk, risk);
        findings.push({
          type:     'cve_match',
          severity: cve.severity,
          risk_score: risk,
          detail:   `${cveId}: ${cve.description?.slice(0,120)} — CVSS ${cve.cvss_score}`,
          exploited:cve.exploited,
          mitre:    cve.mitre_techniques || [],
        });
        for (const t of (cve.mitre_techniques || [])) relatedTechniques.add(t);
      } else {
        findings.push({ type: 'cve_unknown', cve: cveId, risk_score: 30, detail: `${cveId} not in local database — check NVD` });
      }
    }

    // ── MITRE technique correlation ──────────────────────────────
    for (const techId of parsed.techniques) {
      const tech = intelDB?.getMITRE(techId);
      const risk = tech?.severity === 'critical' ? 85 : tech?.severity === 'high' ? 70 : 50;
      maxRisk = Math.max(maxRisk, risk);
      relatedTechniques.add(techId);
      findings.push({
        type:     'technique_match',
        id:       techId,
        name:     tech?.name || techId,
        tactic:   tech?.tactic || 'unknown',
        risk_score: risk,
        detail:   tech?.description?.slice(0,120) || `${techId} identified`,
      });
    }

    // ── Threat actor correlation ─────────────────────────────────
    for (const actor of parsed.actors) {
      const canonKey = Object.keys(ACTOR_TTPS).find(k =>
        k.toLowerCase() === actor.toLowerCase() ||
        ACTOR_TTPS[k].alias?.some(a => a.toLowerCase() === actor.toLowerCase())
      );
      if (canonKey) {
        const ttp = ACTOR_TTPS[canonKey];
        maxRisk = Math.max(maxRisk, 88);
        relatedActors.push({ name: canonKey, country: ttp.country, alias: ttp.alias });
        for (const t of ttp.techniques) relatedTechniques.add(t);
        findings.push({
          type:       'actor_match',
          actor:      canonKey,
          country:    ttp.country,
          risk_score: 88,
          techniques: ttp.techniques,
          campaigns:  ttp.campaigns,
          detail:     `Known threat actor ${canonKey} (${ttp.country}) — ${ttp.campaigns[0]}`,
        });
      }
    }

    // ── IOC type risk assessment ─────────────────────────────────
    for (const ioc of parsed.iocs) {
      const risk = ioc.type === 'hash_sha256' ? 80 :
                   ioc.type === 'ip' ? 65 :
                   ioc.type === 'domain' ? 60 :
                   ioc.type === 'url' ? 70 : 40;
      maxRisk = Math.max(maxRisk, risk);
      findings.push({
        type:     'ioc_parsed',
        ioc_type: ioc.type,
        value:    ioc.value,
        risk_score: risk,
        detail:   `IOC: ${ioc.type} — ${ioc.value} — Recommend enrichment via VirusTotal / AbuseIPDB`,
      });
    }

    // ── Determine overall verdict ────────────────────────────────
    const verdict = maxRisk >= 80 ? 'MALICIOUS' :
                    maxRisk >= 60 ? 'SUSPICIOUS' :
                    maxRisk >= 30 ? 'LOW_RISK' : 'BENIGN';

    // ── Recommend techniques to hunt ────────────────────────────
    const huntTechniques = [...relatedTechniques].slice(0, 5);

    return {
      input_summary: {
        iocs:       parsed.iocs.length,
        cves:       parsed.cves.length,
        techniques: parsed.techniques.length,
        actors:     parsed.actors.length,
        tokens:     parsed.raw.length,
      },
      verdict,
      risk_score: maxRisk,
      confidence: findings.length > 0 ? Math.min(95, 50 + findings.length * 8) : 10,
      findings,
      related_techniques: huntTechniques.map(id => ({
        id,
        name:   intelDB?.getMITRE(id)?.name || id,
        tactic: intelDB?.getMITRE(id)?.tactic || 'unknown',
      })),
      related_actors: relatedActors,
      recommendations: this._buildRecommendations(verdict, huntTechniques),
      analyzed_at: new Date().toISOString(),
    };
  }

  // ── Build actionable recommendations ─────────────────────────
  _buildRecommendations(verdict, techniques) {
    const recs = [];
    if (verdict === 'MALICIOUS') {
      recs.push('Isolate affected endpoints immediately');
      recs.push('Block identified IOCs at perimeter firewall and proxy');
      recs.push('Initiate incident response playbook');
    }
    if (verdict === 'SUSPICIOUS') {
      recs.push('Escalate to SOC Tier 2 analyst for review');
      recs.push('Enrich IOCs via VirusTotal / AbuseIPDB');
    }
    for (const tid of techniques.slice(0, 3)) {
      const t = intelDB?.getMITRE(tid);
      if (t?.detection) recs.push(`Detect ${tid}: ${t.detection.slice(0,100)}`);
    }
    return recs;
  }

  // ── High-risk map for dashboard ───────────────────────────────
  getHighRiskMap() {
    const actors = Object.entries(ACTOR_TTPS).map(([name, data]) => ({
      name,
      country:    data.country,
      alias:      data.alias,
      technique_count: data.techniques.length,
      risk_level: 'HIGH',
      campaigns:  data.campaigns.slice(0, 2),
    }));

    const tactics = {};
    for (const [, data] of Object.entries(ACTOR_TTPS)) {
      for (const tid of data.techniques) {
        const tech = intelDB?.getMITRE(tid);
        if (tech) {
          tactics[tech.tactic] = (tactics[tech.tactic] || 0) + 1;
        }
      }
    }

    return {
      active_actors:       actors.length,
      tracked_techniques:  new Set(Object.values(ACTOR_TTPS).flatMap(a => a.techniques)).size,
      top_actors:          actors.slice(0, 6),
      tactic_coverage:     Object.entries(tactics)
        .sort((a,b) => b[1]-a[1])
        .map(([tactic, count]) => ({ tactic, actor_count: count })),
      last_updated:        new Date().toISOString(),
    };
  }

  // ── Generate threat hunting hypothesis ───────────────────────
  generateHuntingHypothesis(topic) {
    const topicLower = (topic || '').toLowerCase();

    // Find the best matching template
    let key = Object.keys(HUNT_TEMPLATES).find(k => topicLower.includes(k));
    if (!key) {
      // Fuzzy match
      if (topicLower.includes('ransom') || topicLower.includes('crypt'))       key = 'ransomware';
      else if (topicLower.includes('phish') || topicLower.includes('email'))   key = 'phishing';
      else if (topicLower.includes('lateral') || topicLower.includes('move'))  key = 'lateral-movement';
      else if (topicLower.includes('cred') || topicLower.includes('pass'))     key = 'credential-theft';
      else if (topicLower.includes('c2') || topicLower.includes('beacon'))     key = 'command-and-control';
      else key = 'phishing'; // default
    }

    const tpl = HUNT_TEMPLATES[key];
    const techniques = tpl.techniques.map(id => ({
      id,
      name:   intelDB?.getMITRE(id)?.name || id,
      tactic: intelDB?.getMITRE(id)?.tactic || 'unknown',
    }));

    return {
      topic,
      hypothesis:      tpl.hypothesis,
      techniques,
      data_sources:    tpl.data_sources,
      hunt_steps:      tpl.hunt_steps,
      detection_queries: tpl.detection_queries,
      priority:        'HIGH',
      estimated_effort:'2-4 hours',
      generated_at:    new Date().toISOString(),
    };
  }
}

// ── Singleton export ───────────────────────────────────────────────
const defaultCorrelator = new ThreatCorrelator();

module.exports = { ThreatCorrelator, defaultCorrelator };
