/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Unified Behavioral Correlation Engine (BCE) v2.0
 *  Wadjet-Eye AI Platform
 *
 *  The CENTRALIZED behavioral correlation layer.  Treats:
 *    Authentication → Privilege Escalation → Persistence → Lateral Movement
 *  as ONE unified chain across ALL telemetry domains simultaneously.
 *
 *  Design goals:
 *   1. Cross-domain correlation — links firewall, web, OS, and database
 *      events into cohesive multi-stage attack chains.
 *   2. Evidence-gated technique assignment — every technique the BCE emits
 *      is pre-validated against CEA before being returned.
 *   3. Deterministic — same input batch always produces same chains.
 *   4. Non-bypassable — downstream modules receive fully validated results;
 *      no module may add techniques suppressed by BCE/CEA.
 *   5. Domain-aware — separate correlation pipelines per telemetry domain,
 *      unified into a single attack timeline at the end.
 *
 *  Supported attack chains:
 *   A. Windows: Auth → Privilege Escalation → Persistence
 *   B. Windows: Brute-Force → PtH → SMB Lateral Movement
 *   C. Linux:   SSH Brute-Force → Root Escalation → Cron Persistence
 *   D. Web:     Reconnaissance → Exploitation (SQLi/LFI/RCE) → Web Shell
 *   E. Firewall: Port Scan → Service Exploitation → Data Exfiltration
 *   F. Database: Unauthorized Query → Bulk Dump → Exfiltration
 *   G. Cross-domain: Firewall block → Web exploit → Process spawn → Lateral Move
 *
 *  Public API:
 *   BCE.correlate(events, detections, ceaCtx) → CorrelationResult
 *   BCE.getMetrics()                           → MetricsObject
 *   BCE.resetMetrics()                         → void
 *
 *  backend/services/raykan/behavioral-correlation-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const { validateTechnique, EvidenceContext, buildEvidence } = require('./central-evidence-authority');
const GLC = require('./global-log-classifier');

// ─────────────────────────────────────────────────────────────────────────────
//  CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────
const CORRELATION_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MIN_CHAIN_SCORE       = 30;              // minimum confidence to emit a chain
const MAX_CHAIN_LENGTH      = 20;              // maximum events per chain

// ─────────────────────────────────────────────────────────────────────────────
//  ATTACK STAGE DEFINITIONS
//  Each stage defines which domain events contribute to it and which
//  ATT&CK techniques map to it.
// ─────────────────────────────────────────────────────────────────────────────
const ATTACK_STAGES = {
  RECONNAISSANCE    : { order: 0, label: 'Reconnaissance',         tactics: ['reconnaissance', 'discovery'] },
  INITIAL_ACCESS    : { order: 1, label: 'Initial Access',          tactics: ['initial-access'] },
  EXECUTION         : { order: 2, label: 'Execution',               tactics: ['execution'] },
  PERSISTENCE       : { order: 3, label: 'Persistence',             tactics: ['persistence'] },
  PRIVILEGE_ESC     : { order: 4, label: 'Privilege Escalation',    tactics: ['privilege-escalation'] },
  DEFENSE_EVASION   : { order: 5, label: 'Defense Evasion',         tactics: ['defense-evasion'] },
  CREDENTIAL_ACCESS : { order: 6, label: 'Credential Access',       tactics: ['credential-access'] },
  LATERAL_MOVEMENT  : { order: 7, label: 'Lateral Movement',        tactics: ['lateral-movement'] },
  COLLECTION        : { order: 8, label: 'Collection',              tactics: ['collection'] },
  EXFILTRATION      : { order: 9, label: 'Exfiltration',            tactics: ['exfiltration'] },
  IMPACT            : { order: 10, label: 'Impact',                 tactics: ['impact'] },
};

// Technique → stage mapping (for chain ordering)
const TECHNIQUE_STAGE_MAP = {
  'T1595'  : ATTACK_STAGES.RECONNAISSANCE,
  'T1046'  : ATTACK_STAGES.RECONNAISSANCE,
  'T1190'  : ATTACK_STAGES.INITIAL_ACCESS,
  'T1189'  : ATTACK_STAGES.INITIAL_ACCESS,
  'T1078'  : ATTACK_STAGES.INITIAL_ACCESS,
  'T1078.001': ATTACK_STAGES.INITIAL_ACCESS,
  'T1078.003': ATTACK_STAGES.INITIAL_ACCESS,
  'T1110'  : ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1110.001': ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1110.003': ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1110.004': ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1550.002': ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1021'  : ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1021.001': ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1021.002': ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1021.004': ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1021.006': ATTACK_STAGES.LATERAL_MOVEMENT,
  'T1059.001': ATTACK_STAGES.EXECUTION,
  'T1059.004': ATTACK_STAGES.EXECUTION,
  'T1059.007': ATTACK_STAGES.EXECUTION,
  'T1047'  : ATTACK_STAGES.EXECUTION,
  'T1055'  : ATTACK_STAGES.DEFENSE_EVASION,
  'T1548.001': ATTACK_STAGES.PRIVILEGE_ESC,
  'T1548.002': ATTACK_STAGES.PRIVILEGE_ESC,
  'T1003'  : ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1003.001': ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1003.002': ATTACK_STAGES.CREDENTIAL_ACCESS,
  'T1136'  : ATTACK_STAGES.PERSISTENCE,
  'T1136.001': ATTACK_STAGES.PERSISTENCE,
  'T1053.003': ATTACK_STAGES.PERSISTENCE,
  'T1053.005': ATTACK_STAGES.PERSISTENCE,
  'T1098'  : ATTACK_STAGES.PERSISTENCE,
  'T1505.003': ATTACK_STAGES.PERSISTENCE,
  'T1071.001': ATTACK_STAGES.EXFILTRATION,
  'T1071.004': ATTACK_STAGES.EXFILTRATION,
  'T1048'  : ATTACK_STAGES.EXFILTRATION,
  'T1572'  : ATTACK_STAGES.EXFILTRATION,
  'T1005'  : ATTACK_STAGES.COLLECTION,
  'T1213'  : ATTACK_STAGES.COLLECTION,
  'T1040'  : ATTACK_STAGES.COLLECTION,
  'T1486'  : ATTACK_STAGES.IMPACT,
  'T1490'  : ATTACK_STAGES.IMPACT,
  'T1498'  : ATTACK_STAGES.IMPACT,
  'T1562.001': ATTACK_STAGES.DEFENSE_EVASION,
};

// ─────────────────────────────────────────────────────────────────────────────
//  METRICS
// ─────────────────────────────────────────────────────────────────────────────
const _metrics = {
  batches_processed   : 0,
  chains_detected     : 0,
  techniques_emitted  : 0,
  techniques_suppressed: 0,
  cross_domain_chains : 0,
  domain_breakdown    : {},
};

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN: correlate()
//
//  @param {Array}          events     — classified + normalized events (post-GLC)
//  @param {Array}          detections — existing detections (from Sigma / UEBA)
//  @param {EvidenceContext} ceaCtx    — pre-built CEA evidence context
//  @returns {CorrelationResult}
// ─────────────────────────────────────────────────────────────────────────────
function correlate(events, detections, ceaCtx) {
  events     = Array.isArray(events)     ? events     : [];
  detections = Array.isArray(detections) ? detections : [];
  ceaCtx     = ceaCtx || buildEvidence(events, detections);

  _metrics.batches_processed++;

  // Ensure all events are GLC-classified
  const classifiedEvents = events.map(e => e._meta?.classified ? e : GLC.classify(e));

  // Build entity index (user → events, host → events, IP → events)
  const entityIndex = _buildEntityIndex(classifiedEvents);

  // Run per-domain correlation pipelines
  const windowsChains  = _correlateWindows(classifiedEvents, entityIndex, ceaCtx);
  const linuxChains    = _correlateLinux(classifiedEvents,   entityIndex, ceaCtx);
  const webChains      = _correlateWeb(classifiedEvents,     entityIndex, ceaCtx);
  const firewallChains = _correlateFirewall(classifiedEvents, entityIndex, ceaCtx);
  const databaseChains = _correlateDatabase(classifiedEvents, entityIndex, ceaCtx);

  // Run cross-domain correlation (links chains across domains)
  const crossDomainChains = _correlateCrossDomain(
    classifiedEvents, entityIndex, ceaCtx,
    { windowsChains, linuxChains, webChains, firewallChains, databaseChains }
  );

  // Merge all chains
  const allChains = [
    ...windowsChains, ...linuxChains, ...webChains,
    ...firewallChains, ...databaseChains, ...crossDomainChains,
  ];

  // De-duplicate and validate all emitted techniques through CEA
  const validatedChains = allChains
    .filter(c => c.confidence >= MIN_CHAIN_SCORE)
    .map(chain => _validateChainTechniques(chain, ceaCtx, classifiedEvents))
    .filter(c => c.techniques.length > 0);

  // Build correlated detections from chains (for downstream MITRE mapping)
  const correlatedDetections = _buildCorrelatedDetections(validatedChains, classifiedEvents, detections);

  _metrics.chains_detected     += validatedChains.length;
  _metrics.techniques_emitted  += validatedChains.reduce((s, c) => s + c.techniques.length, 0);
  _metrics.cross_domain_chains += crossDomainChains.length;

  return {
    chains               : validatedChains,
    correlatedDetections,
    entityIndex          : _serializeEntityIndex(entityIndex),
    stats: {
      totalChains     : validatedChains.length,
      crossDomainChains: crossDomainChains.length,
      techniquesFound  : [...new Set(validatedChains.flatMap(c => c.techniques.map(t => t.id)))],
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  ENTITY INDEX
//  Groups events by entity (user, host, IP) for fast correlation.
// ─────────────────────────────────────────────────────────────────────────────
function _buildEntityIndex(events) {
  const byUser = {};
  const byHost = {};
  const byIp   = {};

  for (const e of events) {
    const user = (e.user || e.raw?.TargetUserName || e.raw?.username || '').toLowerCase();
    const host = (e.computer || e.raw?.Computer || e.raw?.hostname || '').toLowerCase();
    const ip   = (e.srcIp || e.raw?.IpAddress || e.raw?.src_ip || '').toLowerCase();

    if (user) { if (!byUser[user]) byUser[user] = []; byUser[user].push(e); }
    if (host) { if (!byHost[host]) byHost[host] = []; byHost[host].push(e); }
    if (ip && ip !== '-' && ip !== '127.0.0.1' && ip !== '::1') {
      if (!byIp[ip]) byIp[ip] = [];
      byIp[ip].push(e);
    }
  }

  return { byUser, byHost, byIp };
}

function _serializeEntityIndex(index) {
  return {
    users : Object.keys(index.byUser),
    hosts : Object.keys(index.byHost),
    ips   : Object.keys(index.byIp),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  WINDOWS CORRELATION PIPELINE
//  Detects: Auth → Privilege Escalation → Persistence
//           Brute-Force → PtH → SMB Lateral Movement
//           Credential Dump → Lateral Movement
// ─────────────────────────────────────────────────────────────────────────────
function _correlateWindows(events, entityIndex, ceaCtx) {
  const chains = [];
  const winEvts = events.filter(e => GLC.isWindowsDomain(e));
  if (winEvts.length === 0) return chains;

  const failures  = winEvts.filter(e => String(e.eventId || e.raw?.EventID) === '4625');
  const successes = winEvts.filter(e => String(e.eventId || e.raw?.EventID) === '4624');
  const processes = winEvts.filter(e => ['4688','1'].includes(String(e.eventId || e.raw?.EventID)));
  const privUse   = winEvts.filter(e => String(e.eventId || e.raw?.EventID) === '4672');

  // ── Chain W1: Brute-Force → Success → Privilege Use ───────────────────────
  if (failures.length >= 3 && successes.length > 0) {
    const targetUsers = new Set(failures.map(e => (e.raw?.TargetUserName || e.user || '').toLowerCase()));
    const isSpray     = targetUsers.size >= 3;
    const tid         = isSpray ? 'T1110.003' : 'T1110.001';

    const chain = _buildChain('WIN-BRUTEFORCE', [
      { id: tid,      confidence: 85, evidence: `${failures.length} failed logons${isSpray ? ' across ' + targetUsers.size + ' users' : ''}` },
      { id: 'T1078',  confidence: 70, evidence: 'Successful logon after failures' },
    ], [...failures.slice(0, 5), ...successes.slice(0, 3)], 'windows_security');

    if (privUse.length > 0) {
      chain.techniques.push({ id: 'T1134', confidence: 75, evidence: 'Privileged token assigned (4672)' });
    }

    chains.push(chain);
  }

  // ── Chain W2: NTLM Lateral Movement (PtH candidate) ──────────────────────
  const ntlmSuccesses = successes.filter(e => {
    const lt = String(e.raw?.LogonType || e.logonType || '');
    const ap = (e.raw?.AuthenticationPackageName || e.raw?.AuthPackage || '').toUpperCase();
    return lt === '3' && ap === 'NTLM';
  });

  if (ntlmSuccesses.length >= 2) {
    const hosts = new Set(ntlmSuccesses.map(e => (e.computer || e.raw?.Computer || '').toLowerCase()));
    const srcIps = new Set(ntlmSuccesses.map(e => (e.srcIp || e.raw?.IpAddress || '').toLowerCase())
                    .filter(v => v && v !== '-' && v !== '127.0.0.1'));

    if (hosts.size >= 2 || srcIps.size >= 2) {
      const chain = _buildChain('WIN-PTH', [
        { id: 'T1550.002', confidence: 80, evidence: `Cross-host NTLM logons: ${hosts.size} hosts, ${srcIps.size} source IPs` },
        { id: 'T1021.002', confidence: 75, evidence: 'Network logon indicating lateral movement' },
      ], ntlmSuccesses, 'windows_security');
      chains.push(chain);
    }
  }

  // ── Chain W3: Credential Dump → Lateral Movement ─────────────────────────
  const dumpProcs = processes.filter(e => {
    const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
    const img = (e.process     || e.raw?.Image       || '').toLowerCase();
    return /mimikatz|procdump.*lsass|sekurlsa|lsadump|wce\s+-s/.test(cmd) ||
           /mimikatz|procdump|wce\.exe/.test(img);
  });

  if (dumpProcs.length > 0 && (ntlmSuccesses.length > 0 || successes.length > 0)) {
    const chain = _buildChain('WIN-CRED-DUMP-LATERAL', [
      { id: 'T1003.001', confidence: 90, evidence: `Credential dump tool detected: ${dumpProcs[0].process || dumpProcs[0].raw?.Image}` },
      { id: 'T1550.002', confidence: 70, evidence: 'Subsequent NTLM logon after credential dump' },
    ], [...dumpProcs, ...ntlmSuccesses.slice(0, 3)], 'windows_process');
    chains.push(chain);
  }

  // ── Chain W4: Process Execution → Persistence ─────────────────────────────
  const persistenceProcs = processes.filter(e => {
    const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
    return /schtasks.*(\/create|register)|sc\s+create|reg\s+add.*run|New-Service|Add-MpPreference/.test(cmd);
  });

  if (persistenceProcs.length > 0) {
    const chain = _buildChain('WIN-PERSISTENCE', [
      { id: 'T1053.005', confidence: 80, evidence: 'Scheduled task or service creation detected' },
    ], persistenceProcs, 'windows_process');

    // Check if preceded by privilege escalation
    if (privUse.length > 0 || ntlmSuccesses.length > 0) {
      chain.techniques.unshift({ id: 'T1134', confidence: 70, evidence: 'Privilege token before persistence' });
    }
    chains.push(chain);
  }

  // ── Chain W5: Account Creation after Auth ─────────────────────────────────
  const accountEvts = winEvts.filter(e => {
    const eid = String(e.eventId || e.raw?.EventID);
    const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
    return eid === '4720' || /net\s+user.*\/add|new-localuser/.test(cmd);
  });

  if (accountEvts.length > 0 && successes.length > 0) {
    const chain = _buildChain('WIN-ACCOUNT-CREATION', [
      { id: 'T1136.001', confidence: 85, evidence: 'Local account creation detected (EventID 4720 or net user /add)' },
    ], [...successes.slice(0, 2), ...accountEvts], 'windows_security');
    chains.push(chain);
  }

  // ── Chain W6: Ransomware pattern ──────────────────────────────────────────
  const shadowDelete = processes.filter(e => {
    const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
    return /vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|wmic.*shadowcopy.*delete/.test(cmd);
  });

  if (shadowDelete.length > 0) {
    const chain = _buildChain('WIN-RANSOMWARE', [
      { id: 'T1490', confidence: 90, evidence: 'Shadow copy deletion / backup inhibition detected' },
      { id: 'T1486', confidence: 75, evidence: 'Likely ransomware impact chain' },
    ], shadowDelete, 'windows_process');
    chains.push(chain);
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  LINUX CORRELATION PIPELINE
//  Detects: SSH Brute-Force → Auth Success → Root Escalation → Cron Persistence
// ─────────────────────────────────────────────────────────────────────────────
function _correlateLinux(events, entityIndex, ceaCtx) {
  const chains  = [];
  const linuxEvts = events.filter(e => GLC.isLinuxDomain(e));
  if (linuxEvts.length === 0) return chains;

  const getMsgField = e => (e.message || e.raw?.message || e.raw?.msg || '').toLowerCase();

  // Auth events
  const sshFailures = linuxEvts.filter(e => {
    const msg = getMsgField(e);
    return msg.includes('failed password') || msg.includes('invalid user') || msg.includes('authentication failure');
  });
  const sshSuccesses = linuxEvts.filter(e => {
    const msg = getMsgField(e);
    return msg.includes('accepted password') || msg.includes('accepted publickey');
  });

  // ── Chain L1: SSH Brute-Force ─────────────────────────────────────────────
  if (sshFailures.length >= 3) {
    const srcIps = new Set(sshFailures.map(e => (e.srcIp || e.raw?.IpAddress || '').toLowerCase())
                            .filter(v => v && v !== '127.0.0.1'));
    const targetUsers = new Set(sshFailures.map(e => {
      const msg = getMsgField(e);
      const m   = msg.match(/for (?:invalid user )?(\S+)/);
      return m ? m[1] : '';
    }).filter(Boolean));

    const isSpray = targetUsers.size >= 3;
    const tid     = isSpray ? 'T1110.003' : 'T1110.001';

    const chain = _buildChain('LINUX-SSH-BRUTEFORCE', [
      { id: tid,      confidence: 85, evidence: `${sshFailures.length} SSH failures from ${srcIps.size} IPs${isSpray ? ' targeting ' + targetUsers.size + ' users' : ''}` },
    ], sshFailures.slice(0, 10), 'linux');

    if (sshSuccesses.length > 0) {
      chain.techniques.push({ id: 'T1078.003', confidence: 75, evidence: 'SSH success after brute-force' });
      chain.confidence += 10;
    }
    chains.push(chain);
  }

  // ── Chain L2: SSH Success → Sudo/Root Escalation ─────────────────────────
  if (sshSuccesses.length > 0) {
    const sudoEvts = linuxEvts.filter(e => {
      const msg = getMsgField(e);
      const prog = (e.program || e.raw?.program || '').toLowerCase();
      return prog.includes('sudo') || msg.includes('sudo:') || msg.includes('su:');
    });

    if (sudoEvts.length > 0) {
      const chain = _buildChain('LINUX-SSH-PRIVESC', [
        { id: 'T1021.004', confidence: 80, evidence: 'SSH access from external IP' },
        { id: 'T1548.001', confidence: 70, evidence: 'Sudo/su elevation after SSH login' },
      ], [...sshSuccesses.slice(0, 3), ...sudoEvts.slice(0, 3)], 'linux');
      chains.push(chain);
    }
  }

  // ── Chain L3: Cron Persistence ────────────────────────────────────────────
  const cronEvts = linuxEvts.filter(e => {
    const prog = (e.program || e.raw?.program || '').toLowerCase();
    const cmd  = (e.commandLine || e.raw?.CommandLine || getMsgField(e)).toLowerCase();
    return prog.includes('cron') || /crontab|cron\.d|cron\.daily/.test(cmd);
  });

  if (cronEvts.length > 0 && (sshSuccesses.length > 0)) {
    const chain = _buildChain('LINUX-CRON-PERSISTENCE', [
      { id: 'T1053.003', confidence: 80, evidence: 'Cron job modification after SSH access' },
    ], [...sshSuccesses.slice(0, 2), ...cronEvts], 'linux');
    chains.push(chain);
  }

  // ── Chain L4: Account Manipulation ───────────────────────────────────────
  const accountEvts = linuxEvts.filter(e => {
    const cmd = (e.commandLine || getMsgField(e)).toLowerCase();
    return /useradd|userdel|usermod|passwd|visudo|sudoers/.test(cmd);
  });

  if (accountEvts.length > 0) {
    const chain = _buildChain('LINUX-ACCOUNT-MANIP', [
      { id: 'T1098', confidence: 80, evidence: `Account manipulation: ${accountEvts[0].commandLine || getMsgField(accountEvts[0])}` },
    ], accountEvts, 'linux');
    chains.push(chain);
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEB CORRELATION PIPELINE
//  Detects: Recon → SQLi/LFI/RCE → Web Shell → OS Execution
// ─────────────────────────────────────────────────────────────────────────────
function _correlateWeb(events, entityIndex, ceaCtx) {
  const chains  = [];
  const webEvts = events.filter(e => GLC.isWebDomain(e));
  if (webEvts.length === 0) return chains;

  const getUri    = e => (e.url || e.uri || e.raw?.['cs-uri-stem'] || e.raw?.RequestURI || '').toLowerCase();
  const getMethod = e => (e.httpMethod || e.raw?.['cs-method'] || e.raw?.method || '').toUpperCase();
  const getStatus = e => String(e.statusCode || e.raw?.['sc-status'] || e.raw?.status_code || '');

  // Scan / probe events (4xx responses to unusual URIs)
  const errorEvts = webEvts.filter(e => {
    const sc = parseInt(getStatus(e), 10);
    return sc >= 400 && sc < 500;
  });

  // Exploitation indicators
  const sqliEvts = webEvts.filter(e => {
    const uri = getUri(e) + (e.raw?.['cs-uri-query'] || e.raw?.QueryString || '').toLowerCase();
    return /union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*0|sleep\s*\(|benchmark\s*\(|xp_cmdshell|load_file\s*\(/i.test(uri);
  });

  const lfiEvts = webEvts.filter(e => {
    const uri = getUri(e);
    return /\.\.\/|\.\.\\|%2e%2e%2f|%252e|\/etc\/passwd|\/windows\/system32|boot\.ini/i.test(uri);
  });

  const rceEvts = webEvts.filter(e => {
    const uri = getUri(e);
    const ua  = (e.userAgent || e.raw?.['cs(User-Agent)'] || '').toLowerCase();
    return /cmd=|exec=|system\(|passthru\(|eval\(|phpinfo\(|\bping\s+-c|\bwhoami\b/i.test(uri) ||
           /nikto|sqlmap|nessus|burpsuite|metasploit/i.test(ua);
  });

  // ── Chain WEB1: SQL Injection ─────────────────────────────────────────────
  if (sqliEvts.length > 0) {
    const chain = _buildChain('WEB-SQLI', [
      { id: 'T1190',   confidence: 85, evidence: `SQL injection attempt detected in ${sqliEvts.length} requests` },
      { id: 'T1213',   confidence: 70, evidence: 'Possible data extraction via SQLi' },
    ], sqliEvts, 'web');
    chains.push(chain);
  }

  // ── Chain WEB2: LFI/Path Traversal ───────────────────────────────────────
  if (lfiEvts.length > 0) {
    const chain = _buildChain('WEB-LFI', [
      { id: 'T1190',   confidence: 80, evidence: `LFI/path traversal in ${lfiEvts.length} requests` },
      { id: 'T1005',   confidence: 65, evidence: 'Possible local file read' },
    ], lfiEvts, 'web');
    chains.push(chain);
  }

  // ── Chain WEB3: RCE / Web Shell ───────────────────────────────────────────
  if (rceEvts.length > 0) {
    const chain = _buildChain('WEB-RCE', [
      { id: 'T1190',     confidence: 90, evidence: `RCE attempt detected (${rceEvts.length} requests)` },
      { id: 'T1505.003', confidence: 75, evidence: 'Possible web shell interaction' },
    ], rceEvts, 'web');
    chains.push(chain);
  }

  // ── Chain WEB4: Recon → Exploit ───────────────────────────────────────────
  if (errorEvts.length >= 10 && (sqliEvts.length > 0 || lfiEvts.length > 0 || rceEvts.length > 0)) {
    const exploitEvts = [...sqliEvts, ...lfiEvts, ...rceEvts];
    const chain = _buildChain('WEB-RECON-EXPLOIT', [
      { id: 'T1595',   confidence: 75, evidence: `${errorEvts.length} probe requests (4xx responses)` },
      { id: 'T1190',   confidence: 85, evidence: 'Exploitation attempt following reconnaissance' },
    ], [...errorEvts.slice(0, 5), ...exploitEvts.slice(0, 5)], 'web');
    chains.push(chain);
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FIREWALL CORRELATION PIPELINE
//  Detects: Port Scan → Denied Connections → Exploitation
// ─────────────────────────────────────────────────────────────────────────────
function _correlateFirewall(events, entityIndex, ceaCtx) {
  const chains = [];
  const fwEvts = events.filter(e => GLC.isFirewallDomain(e));
  if (fwEvts.length === 0) return chains;

  // ── Chain FW1: Port Scan ──────────────────────────────────────────────────
  const portsByIp = {};
  for (const e of fwEvts) {
    const srcIp  = (e.srcIp  || e.raw?.src_ip  || e.raw?.IpAddress || '').toLowerCase();
    const dstPort = String(e.dstPort || e.raw?.dst_port || e.raw?.DestinationPort || '');
    const action  = (e.raw?.action || e.raw?.Action || '').toLowerCase();

    if (srcIp && dstPort && srcIp !== '127.0.0.1') {
      if (!portsByIp[srcIp]) portsByIp[srcIp] = { ports: new Set(), events: [] };
      portsByIp[srcIp].ports.add(dstPort);
      portsByIp[srcIp].events.push(e);
    }
  }

  for (const [srcIp, data] of Object.entries(portsByIp)) {
    if (data.ports.size >= 5) {
      const chain = _buildChain('FW-PORT-SCAN', [
        { id: 'T1046', confidence: 85, evidence: `Port scan from ${srcIp}: ${data.ports.size} distinct ports probed` },
      ], data.events.slice(0, 10), 'firewall');
      chain.metadata = { srcIp, portsScanned: [...data.ports] };
      chains.push(chain);
    }
  }

  // ── Chain FW2: High-volume Outbound (Exfiltration) ────────────────────────
  const outboundByIp = {};
  for (const e of fwEvts) {
    const dstIp   = (e.dstIp || e.raw?.dst_ip || e.raw?.DestinationIp || '').toLowerCase();
    const bytes   = parseInt(e.raw?.bytes_sent || e.raw?.BytesSent || e.raw?.['sc-bytes'] || '0', 10);
    if (dstIp && !isNaN(bytes) && bytes > 0) {
      outboundByIp[dstIp] = (outboundByIp[dstIp] || 0) + bytes;
    }
  }

  for (const [dstIp, totalBytes] of Object.entries(outboundByIp)) {
    if (totalBytes > 50_000_000) { // 50MB per destination
      const chain = _buildChain('FW-EXFIL', [
        { id: 'T1048', confidence: 75, evidence: `High outbound transfer: ${Math.round(totalBytes/1_000_000)}MB to ${dstIp}` },
      ], fwEvts.slice(0, 5), 'firewall');
      chains.push(chain);
    }
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DATABASE CORRELATION PIPELINE
//  Detects: Unauthorized Query → Bulk Dump → Exfiltration
// ─────────────────────────────────────────────────────────────────────────────
function _correlateDatabase(events, entityIndex, ceaCtx) {
  const chains  = [];
  const dbEvts  = events.filter(e => GLC.isDatabaseDomain(e));
  if (dbEvts.length === 0) return chains;

  const getQuery = e => (e.raw?.query || e.raw?.sql_statement || e.commandLine || '').toLowerCase();

  // ── Chain DB1: SQL Injection at DB layer ──────────────────────────────────
  const sqliEvts = dbEvts.filter(e => {
    const q = getQuery(e);
    return /union\s+select|or\s+1\s*=\s*1|xp_cmdshell|load_file|information_schema/i.test(q);
  });

  if (sqliEvts.length > 0) {
    const chain = _buildChain('DB-SQLI', [
      { id: 'T1190', confidence: 85, evidence: `SQL injection detected in DB logs: ${sqliEvts.length} queries` },
      { id: 'T1213', confidence: 75, evidence: 'Unauthorized data access via injection' },
    ], sqliEvts, 'database');
    chains.push(chain);
  }

  // ── Chain DB2: Bulk Data Dump ─────────────────────────────────────────────
  const dumpEvts = dbEvts.filter(e => {
    const q = getQuery(e);
    return /select\s+\*\s+from|select.+into\s+outfile|mysqldump|pg_dump|bcp\s|bulk\s+insert/i.test(q);
  });

  if (dumpEvts.length > 0) {
    const chain = _buildChain('DB-BULK-DUMP', [
      { id: 'T1005', confidence: 80, evidence: `Bulk data dump detected: ${dumpEvts.length} queries` },
      { id: 'T1048', confidence: 65, evidence: 'Possible data exfiltration from database' },
    ], dumpEvts, 'database');
    chains.push(chain);
  }

  // ── Chain DB3: Default Account Logon ─────────────────────────────────────
  const defaultAccountEvts = dbEvts.filter(e => {
    const user = (e.user || e.raw?.db_user || e.raw?.username || '').toLowerCase();
    return ['sa','admin','root','postgres','mysql','oracle'].includes(user);
  });

  if (defaultAccountEvts.length > 0) {
    const chain = _buildChain('DB-DEFAULT-ACCOUNT', [
      { id: 'T1078.001', confidence: 75, evidence: `Default database account used: ${defaultAccountEvts.map(e => e.user || e.raw?.db_user).join(', ')}` },
    ], defaultAccountEvts, 'database');
    chains.push(chain);
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CROSS-DOMAIN CORRELATION PIPELINE
//  Links events across firewall, web, OS, and database into unified chains.
// ─────────────────────────────────────────────────────────────────────────────
function _correlateCrossDomain(events, entityIndex, ceaCtx, domainChains) {
  const chains = [];

  // ── Chain X1: Firewall scan → Web exploit → Process spawn ─────────────────
  const fwScans  = domainChains.firewallChains.filter(c => c.id === 'FW-PORT-SCAN');
  const webExploit = domainChains.webChains.filter(c => ['WEB-SQLI','WEB-RCE','WEB-LFI','WEB-RECON-EXPLOIT'].includes(c.id));
  const winProcess = domainChains.windowsChains.filter(c =>
    ['WIN-PERSISTENCE','WIN-CRED-DUMP-LATERAL','WIN-PTH'].includes(c.id));

  // Also check: web parent process in events is a strong cross-domain indicator
  const hasWebParentProcess = events.some(e => {
    const pp = (e.parentProc || e.raw?.ParentImage || '').toLowerCase();
    return /w3wp|httpd|nginx|php|apache|tomcat|iisexpress/.test(pp);
  });
  const hasWebDomainEvents = events.some(e => e._meta?.domain === 'web');
  const hasFwEvents = events.some(e => e._meta?.domain === 'firewall');

  if (fwScans.length > 0 && (webExploit.length > 0 || (hasWebDomainEvents && hasWebParentProcess))) {
    const chain = _buildChain('CROSS-FW-WEB-OS', [
      { id: 'T1046',   confidence: 80, evidence: 'Network reconnaissance (firewall logs)' },
      { id: 'T1190',   confidence: 85, evidence: 'Web application exploitation' },
    ], [], 'cross_domain');

    if (winProcess.length > 0 || hasWebParentProcess) {
      chain.techniques.push({ id: 'T1505.003', confidence: 75, evidence: 'Post-exploitation process execution via web parent' });
    }

    chain.linkedChains = [
      ...(fwScans.map(c => c.id)),
      ...(webExploit.map(c => c.id)),
      ...(winProcess.map(c => c.id)),
    ];
    chain.confidence = 82;
    chains.push(chain);
    _metrics.cross_domain_chains++;
  }

  // ── Chain X2: SSH brute-force → Cron persistence → Data exfil ────────────
  const sshBrute = domainChains.linuxChains.filter(c => c.id === 'LINUX-SSH-BRUTEFORCE');
  const cronPersist = domainChains.linuxChains.filter(c => c.id === 'LINUX-CRON-PERSISTENCE');
  const fwExfil  = domainChains.firewallChains.filter(c => c.id === 'FW-EXFIL');

  if (sshBrute.length > 0 && (cronPersist.length > 0 || fwExfil.length > 0)) {
    const chain = _buildChain('CROSS-LINUX-EXFIL', [
      { id: 'T1110.001', confidence: 85, evidence: 'SSH brute-force (Linux logs)' },
      { id: 'T1078.003', confidence: 75, evidence: 'SSH auth success' },
    ], [], 'cross_domain');

    if (cronPersist.length > 0) {
      chain.techniques.push({ id: 'T1053.003', confidence: 80, evidence: 'Cron persistence after SSH compromise' });
    }
    if (fwExfil.length > 0) {
      chain.techniques.push({ id: 'T1048', confidence: 70, evidence: 'Data exfiltration detected in firewall logs' });
    }

    chain.linkedChains = [
      ...(sshBrute.map(c => c.id)),
      ...(cronPersist.map(c => c.id)),
      ...(fwExfil.map(c => c.id)),
    ];
    chain.confidence = 78;
    chains.push(chain);
  }

  // ── Chain X3: Windows PtH → Linux SSH pivot ────────────────────────────────
  const pthChains  = domainChains.windowsChains.filter(c => c.id === 'WIN-PTH');
  const sshSuccess = domainChains.linuxChains.filter(c =>
    c.techniques.some(t => t.id === 'T1078.003' || t.id === 'T1021.004'));

  if (pthChains.length > 0 && sshSuccess.length > 0) {
    const chain = _buildChain('CROSS-WIN-LINUX-PIVOT', [
      { id: 'T1550.002', confidence: 80, evidence: 'Windows PtH lateral movement' },
      { id: 'T1021.004', confidence: 75, evidence: 'SSH pivot to Linux systems' },
    ], [], 'cross_domain');
    chain.linkedChains = [
      ...(pthChains.map(c => c.id)),
      ...(sshSuccess.map(c => c.id)),
    ];
    chain.confidence = 75;
    chains.push(chain);
  }

  // ── Chain X4: Web Shell → Windows Process → Lateral Movement ─────────────
  const webShell = domainChains.webChains.filter(c => c.id === 'WEB-RCE');
  const winLateral = domainChains.windowsChains.filter(c =>
    c.techniques.some(t => ['T1550.002','T1021.002'].includes(t.id)));

  if (webShell.length > 0 && winLateral.length > 0) {
    const chain = _buildChain('CROSS-WEBSHELL-LATERAL', [
      { id: 'T1190',     confidence: 88, evidence: 'Web application exploitation (web logs)' },
      { id: 'T1505.003', confidence: 80, evidence: 'Web shell deployed' },
      { id: 'T1021.002', confidence: 72, evidence: 'SMB lateral movement from web-compromised host' },
    ], [], 'cross_domain');
    chain.linkedChains = [
      ...(webShell.map(c => c.id)),
      ...(winLateral.map(c => c.id)),
    ];
    chain.confidence = 82;
    chains.push(chain);
  }

  // ── Chain X5: DB SQLi → Bulk Dump → Firewall Exfil ───────────────────────
  const dbSqli = domainChains.databaseChains.filter(c => c.id === 'DB-SQLI');
  const dbDump = domainChains.databaseChains.filter(c => c.id === 'DB-BULK-DUMP');

  if (dbSqli.length > 0 && dbDump.length > 0 && fwExfil.length > 0) {
    const chain = _buildChain('CROSS-DB-EXFIL', [
      { id: 'T1190', confidence: 85, evidence: 'SQL injection (database logs)' },
      { id: 'T1005', confidence: 80, evidence: 'Bulk data dump' },
      { id: 'T1048', confidence: 75, evidence: 'Exfiltration via network (firewall logs)' },
    ], [], 'cross_domain');
    chain.linkedChains = [
      ...(dbSqli.map(c => c.id)),
      ...(dbDump.map(c => c.id)),
      ...(fwExfil.map(c => c.id)),
    ];
    chain.confidence = 83;
    chains.push(chain);
  }

  return chains;
}

// ─────────────────────────────────────────────────────────────────────────────
//  VALIDATE CHAIN TECHNIQUES THROUGH CEA
//  Every technique a chain produces MUST pass the CEA gate.
// ─────────────────────────────────────────────────────────────────────────────
function _validateChainTechniques(chain, ceaCtx, events) {
  const evt     = chain.events[0] || {};
  const ruleCtx = { logsource: { category: chain.domain }, ruleId: chain.id };

  const validatedTechniques = [];
  for (const tech of chain.techniques) {
    const result = validateTechnique(tech.id, ceaCtx, evt, {}, ruleCtx);
    if (result.allowed) {
      validatedTechniques.push(tech);
    } else {
      _metrics.techniques_suppressed++;
      if (result.alternative) {
        // Only add alternative if not already present
        if (!validatedTechniques.some(t => t.id === result.alternative)) {
          validatedTechniques.push({
            id: result.alternative,
            confidence: Math.max(40, tech.confidence - 15),
            evidence: `Downgraded from ${tech.id}: ${result.reason}`,
          });
        }
      }
    }
  }

  return { ...chain, techniques: validatedTechniques };
}

// ─────────────────────────────────────────────────────────────────────────────
//  BUILD CORRELATED DETECTIONS
//  Convert validated chains into detection objects for the MITRE mapper.
// ─────────────────────────────────────────────────────────────────────────────
function _buildCorrelatedDetections(chains, events, existingDetections) {
  const existingRuleIds = new Set(existingDetections.map(d => d.ruleId || d.rule_id || ''));
  const result = [];

  for (const chain of chains) {
    // Don't duplicate detections already generated by Sigma
    if (existingRuleIds.has(chain.id)) continue;

    const topTechnique = chain.techniques[0];
    if (!topTechnique) continue;

    const detection = {
      ruleId      : `BCE-${chain.id}`,
      title       : `[BCE] ${chain.label}`,
      severity    : chain.confidence >= 85 ? 'critical' : chain.confidence >= 70 ? 'high' : 'medium',
      confidence  : chain.confidence,
      tags        : chain.techniques.map(t => `attack.${t.id.toLowerCase()}`),
      techniques  : chain.techniques,
      domain      : chain.domain,
      linkedChains: chain.linkedChains || [],
      eventCount  : chain.events.length,
      timestamp   : chain.startTime || new Date().toISOString(),
      _ceaValidated: true,                // Chain techniques already validated
      _bceChain    : true,
      source       : 'behavioral_correlation_engine',
    };

    result.push(detection);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CHAIN BUILDER HELPER
// ─────────────────────────────────────────────────────────────────────────────
function _buildChain(id, techniques, events, domain) {
  const timestamps = events
    .map(e => e.timestamp || e.raw?.TimeGenerated || e.raw?.timestamp)
    .filter(Boolean)
    .sort();

  const totalConf = techniques.reduce((s, t) => s + t.confidence, 0);
  const avgConf   = techniques.length > 0 ? Math.round(totalConf / techniques.length) : 50;

  return {
    id,
    label       : id.replace(/-/g, ' ').replace(/([A-Z]+)/g, ' $1').trim(),
    techniques,
    events      : events.slice(0, MAX_CHAIN_LENGTH),
    domain,
    confidence  : avgConf,
    startTime   : timestamps[0]  || null,
    endTime     : timestamps[timestamps.length - 1] || null,
    linkedChains: [],
    metadata    : {},
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────
function getMetrics() {
  return JSON.parse(JSON.stringify(_metrics));
}

function resetMetrics() {
  Object.keys(_metrics).forEach(k => {
    if (typeof _metrics[k] === 'number') _metrics[k] = 0;
    else if (typeof _metrics[k] === 'object') _metrics[k] = {};
  });
}

module.exports = {
  correlate,
  getMetrics,
  resetMetrics,
  ATTACK_STAGES,
  TECHNIQUE_STAGE_MAP,
};
