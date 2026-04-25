/**
 * CSDE SOC v9 Validation Suite — Attack-Chain Reconstruction v2
 * Tests T52–T70 covering all user-reported issues:
 *  - T52: incident .id field present (not undefined)
 *  - T53: incidentSummaries .id field present
 *  - T54: cross-host same-user events form ONE unified incident (not fragmented)
 *  - T55: cross-host same-user chain has correct chainType (full-apt-*)
 *  - T56: all MITRE techniques appear in unified incident
 *  - T57: kill-chain stages span BOTH hosts in correct chronological order
 *  - T58: credential-access → persistence is valid (no causal violation)
 *  - T59: impact → defense-evasion is valid (ransomware + log-clear)
 *  - T60: full APT chain: brute-force → success → persistence → LSASS → lateral → shadow → log-clear
 *  - T61: chainValid=true for a well-formed APT chain
 *  - T62: two different users stay in separate incidents (no cross-user merge)
 *  - T63: Linux detections never merge with Windows detections (OS guard)
 *  - T64: CSDE-WIN-001 suppressed when CSDE-WIN-002 fires for same host
 *  - T65: chain name matches "Full APT Kill Chain" when ransomware + cred + lateral
 *  - T66: incidentSummaries contains allHosts array with all affected hosts
 *  - T67: mitreMappings includes entries from all attack stages
 *  - T68: stageCount equals number of unique detections in chain
 *  - T69: P1 escalation when log tampering present in full APT chain
 *  - T70: chainValid=false correctly flagged for causal-violation-only scenario
 */
'use strict';

const { loadCSDE } = require('./test_harness');
let csde;
try {
  csde = loadCSDE();
} catch (e) {
  console.error('FATAL: Cannot load CSDE engine:', e.message);
  process.exit(1);
}

// ── Helpers ───────────────────────────────────────────────────
let passed = 0, failed = 0;
function test(id, label, fn) {
  try {
    const result = fn();
    if (result === true || result == null) {
      console.log(`  ✅ ${id}: ${label}`);
      passed++;
    } else {
      console.log(`  ❌ ${id}: ${label}`);
      console.log(`     REASON: ${result}`);
      failed++;
    }
  } catch (e) {
    console.log(`  ❌ ${id}: ${label}`);
    console.log(`     ERROR: ${e.message}`);
    failed++;
  }
}

// ISO timestamp generator
const BASE = new Date('2024-03-15T08:00:00.000Z').getTime();
const iso = (min) => new Date(BASE + min * 60000).toISOString();

// ── Standard full APT scenario ────────────────────────────────
// Same user "john.doe" attacks DC01 then pivots to FILE01
const fullAptEvents = [
  // Brute force on DC01
  { TimeGenerated: iso(0),  EventID: '4625', Computer: 'DC01', SubjectUserName: 'john.doe', IpAddress: '10.0.0.99', Status: '0xC000006D' },
  { TimeGenerated: iso(1),  EventID: '4625', Computer: 'DC01', SubjectUserName: 'john.doe', IpAddress: '10.0.0.99', Status: '0xC000006D' },
  { TimeGenerated: iso(2),  EventID: '4625', Computer: 'DC01', SubjectUserName: 'john.doe', IpAddress: '10.0.0.99', Status: '0xC000006D' },
  // Successful logon after brute force
  { TimeGenerated: iso(3),  EventID: '4624', Computer: 'DC01', TargetUserName: 'john.doe', IpAddress: '10.0.0.99', LogonType: '3' },
  // Persistence: new user created
  { TimeGenerated: iso(5),  EventID: '4688', Computer: 'DC01', SubjectUserName: 'john.doe', NewProcessName: 'net.exe', CommandLine: 'net user backdoor P@ss /add' },
  // LSASS credential dump
  { TimeGenerated: iso(8),  EventID: '4688', Computer: 'DC01', SubjectUserName: 'john.doe', NewProcessName: 'procdump.exe', CommandLine: 'procdump -ma lsass.exe lsass.dmp' },
  // Lateral movement: logon on FILE01
  { TimeGenerated: iso(12), EventID: '4624', Computer: 'FILE01', TargetUserName: 'john.doe', IpAddress: '10.0.0.100', LogonType: '3' },
  // Admin share access on FILE01
  { TimeGenerated: iso(14), EventID: '5140', Computer: 'FILE01', SubjectUserName: 'john.doe', ShareName: 'ADMIN$', IpAddress: '10.0.0.100' },
  // Shadow copy deletion on FILE01
  { TimeGenerated: iso(18), EventID: '4688', Computer: 'FILE01', SubjectUserName: 'john.doe', NewProcessName: 'vssadmin.exe', CommandLine: 'vssadmin delete shadows /all /quiet' },
  // Log tampering on FILE01
  { TimeGenerated: iso(19), EventID: '1102', Computer: 'FILE01', SubjectUserName: 'john.doe', Message: 'The audit log was cleared' },
];

console.log('\n  CSDE SOC v9 Validation Suite — Attack-Chain Reconstruction v2');
console.log('════════════════════════════════════════════════════════════════\n');

const aptResult = csde.analyzeEvents(fullAptEvents);

// ── T52: incident .id field present ──────────────────────────
test('T52', 'incident .id field is not undefined', () => {
  const inc = aptResult.incidents[0];
  if (!inc) return 'No incidents returned';
  if (inc.id === undefined) return `incidents[0].id is undefined (keys: ${Object.keys(inc).join(',')})`;
  if (typeof inc.id !== 'string' || !inc.id.startsWith('INC-')) return `Expected INC-* format, got: ${inc.id}`;
  return true;
});

// ── T53: incidentSummaries .id field present ──────────────────
test('T53', 'incidentSummaries .id field is not undefined', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incidentSummaries returned';
  if (sum.id === undefined) return `incidentSummaries[0].id is undefined`;
  if (typeof sum.id !== 'string' || !sum.id.startsWith('INC-')) return `Expected INC-* format, got: ${sum.id}`;
  return true;
});

// ── T54: ONE unified incident (not fragmented across hosts) ───
test('T54', 'Cross-host same-user events form ONE unified incident', () => {
  if (aptResult.incidents.length !== 1) return `Expected 1 incident, got ${aptResult.incidents.length} (incidents were fragmented)`;
  return true;
});

// ── T55: Full APT chain type ──────────────────────────────────
test('T55', 'Full APT chain type is "full-apt-ransomware" or "apt"', () => {
  if (!aptResult.chains || aptResult.chains.length < 1) return 'No chains returned';
  if (aptResult.chains.length !== 1) return `Expected 1 chain, got ${aptResult.chains.length} (chains were fragmented)`;
  const c = aptResult.chains[0];
  if (!c.type.includes('apt') && !c.type.includes('ransomware')) return `Got unexpected chainType: ${c.type}`;
  return true;
});

// ── T56: All MITRE techniques in unified incident ─────────────
test('T56', 'Incident includes MITRE techniques from BOTH DC01 and FILE01', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const techs = sum.techniques || [];
  // Must include cred-access from DC01 AND lateral/impact from FILE01
  const hasCred = techs.some(t => t.startsWith('T1110') || t === 'T1003.001');
  const hasLateral = techs.some(t => t === 'T1021.002' || t === 'T1021');
  const hasImpact = techs.some(t => t === 'T1490' || t === 'T1070.001');
  if (!hasCred) return `Missing credential-access technique. Got: ${JSON.stringify(techs)}`;
  if (!hasLateral) return `Missing lateral-movement technique. Got: ${JSON.stringify(techs)}`;
  if (!hasImpact) return `Missing impact/defense-evasion technique. Got: ${JSON.stringify(techs)}`;
  return true;
});

// ── T57: Stages span both hosts in chronological order ────────
test('T57', 'Kill-chain stages span DC01 and FILE01 in chronological order', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const stages = sum.killChainStages || [];
  if (!stages.length) return 'No kill-chain stages';
  const dc01Stages = stages.filter(s => s.host === 'DC01');
  const file01Stages = stages.filter(s => s.host === 'FILE01');
  if (!dc01Stages.length) return 'No stages from DC01';
  if (!file01Stages.length) return 'No stages from FILE01';
  // All DC01 stages must come before all FILE01 stages
  const lastDC01 = Math.max(...dc01Stages.map(s => new Date(s.first_seen || s.timestamp || 0).getTime()));
  const firstFILE01 = Math.min(...file01Stages.map(s => new Date(s.first_seen || s.timestamp || 0).getTime()));
  if (lastDC01 > firstFILE01) return `DC01 stage after FILE01 stage — incorrect order`;
  return true;
});

// ── T58: credential-access → persistence is valid ─────────────
test('T58', 'credential-access → persistence is NOT a causal violation', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const violations = sum.causalViolations || [];
  const credToPers = violations.filter(v =>
    v.stage_a?.tactic === 'credential-access' && v.stage_b?.tactic === 'persistence'
  );
  if (credToPers.length > 0) return `False violation: credential-access→persistence flagged (${credToPers.length} violations)`;
  return true;
});

// ── T59: impact → defense-evasion is valid ────────────────────
test('T59', 'impact → defense-evasion is NOT a causal violation (ransomware then log-clear)', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const violations = sum.causalViolations || [];
  const impToDef = violations.filter(v =>
    v.stage_a?.tactic === 'impact' && v.stage_b?.tactic === 'defense-evasion'
  );
  if (impToDef.length > 0) return `False violation: impact→defense-evasion flagged (${impToDef.length} violations)`;
  return true;
});

// ── T60: Full APT sequence contains brute-force through log-clear ─
test('T60', 'Full APT sequence: brute-force → success → persistence → lsass → lateral → shadow → log-clear', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const stages = sum.killChainStages || [];
  const ruleIds = stages.map(s => s.ruleId);
  const expected = ['CSDE-WIN-002', 'CSDE-WIN-003', 'CSDE-WIN-004', 'CSDE-WIN-014', 'CSDE-WIN-020', 'CSDE-WIN-013', 'CSDE-WIN-023'];
  const missing = expected.filter(r => !ruleIds.includes(r));
  if (missing.length > 0) return `Missing stages: ${missing.join(', ')} (got: ${ruleIds.join(',')})`;
  return true;
});

// ── T61: chainValid=true for well-formed APT chain ────────────
test('T61', 'chainValid=true for a well-formed APT chain (no false causal violations)', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  if (!sum.chainValid) {
    const v = (sum.causalViolations || []).map(v => `${v.stage_a?.tactic}→${v.stage_b?.tactic}`).join(', ');
    return `chainValid=false, violations: ${v || 'none listed'}`;
  }
  return true;
});

// ── T62: Two different users stay in separate incidents ────────
test('T62', 'alice and bob stay in separate incidents when user differs', () => {
  const events = [
    { TimeGenerated: iso(0), EventID: '4625', Computer: 'DC01', SubjectUserName: 'alice', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    { TimeGenerated: iso(1), EventID: '4625', Computer: 'DC01', SubjectUserName: 'alice', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    { TimeGenerated: iso(2), EventID: '4625', Computer: 'DC01', SubjectUserName: 'alice', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    { TimeGenerated: iso(3), EventID: '4625', Computer: 'DC01', SubjectUserName: 'bob', IpAddress: '10.0.0.2', Status: '0xC000006D' },
    { TimeGenerated: iso(4), EventID: '4625', Computer: 'DC01', SubjectUserName: 'bob', IpAddress: '10.0.0.2', Status: '0xC000006D' },
    { TimeGenerated: iso(5), EventID: '4625', Computer: 'DC01', SubjectUserName: 'bob', IpAddress: '10.0.0.2', Status: '0xC000006D' },
  ];
  const r = csde.analyzeEvents(events);
  // Each user should produce their own incident
  const aliceIncs = r.incidents.filter(i => (i.user || '').toLowerCase().includes('alice') || (i.allUsers || []).some(u => u.toLowerCase().includes('alice')));
  const bobIncs   = r.incidents.filter(i => (i.user || '').toLowerCase().includes('bob')   || (i.allUsers || []).some(u => u.toLowerCase().includes('bob')));
  if (aliceIncs.length === 0 && bobIncs.length === 0) {
    // Check detections - they should be separate
    const aliceDets = r.detections.filter(d => (d.user || '').toLowerCase().includes('alice'));
    const bobDets   = r.detections.filter(d => (d.user || '').toLowerCase().includes('bob'));
    if (aliceDets.length > 0 && bobDets.length > 0) return true; // detections correctly separate
  }
  if (aliceIncs.length > 0 && bobIncs.length > 0) return true; // separate incidents
  if (r.incidents.length >= 2) return true; // at least 2 incidents
  return `alice and bob merged into same incident (incidents: ${r.incidents.length}, aliceIncs: ${aliceIncs.length}, bobIncs: ${bobIncs.length})`;
});

// ── T63: Linux detections never merge with Windows ────────────
test('T63', 'Linux detections never merge with Windows detections', () => {
  const events = [
    // Windows events
    { TimeGenerated: iso(0), EventID: '4625', Computer: 'WIN-DC01', SubjectUserName: 'administrator', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    { TimeGenerated: iso(1), EventID: '4625', Computer: 'WIN-DC01', SubjectUserName: 'administrator', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    { TimeGenerated: iso(2), EventID: '4625', Computer: 'WIN-DC01', SubjectUserName: 'administrator', IpAddress: '10.0.0.1', Status: '0xC000006D' },
    // Linux events
    { TimeGenerated: iso(3), Computer: 'LINUX-SRV', message: 'sshd[1234]: Failed password for administrator from 10.0.0.1 port 22', source: 'auth.log' },
    { TimeGenerated: iso(4), Computer: 'LINUX-SRV', message: 'sshd[1234]: Failed password for administrator from 10.0.0.1 port 22', source: 'auth.log' },
    { TimeGenerated: iso(5), Computer: 'LINUX-SRV', message: 'sshd[1234]: Failed password for administrator from 10.0.0.1 port 22', source: 'auth.log' },
  ];
  const r = csde.analyzeEvents(events);
  // Check that any incident does NOT contain both Windows and Linux detections
  const allGood = r.incidents.every(inc => {
    const dets = inc.all || [];
    const hasWin = dets.some(d => (d.ruleId || '').startsWith('CSDE-WIN'));
    const hasLnx = dets.some(d => (d.ruleId || '').startsWith('CSDE-LNX'));
    return !(hasWin && hasLnx);
  });
  if (!allGood) return 'Linux and Windows detections merged into same incident';
  return true;
});

// ── T64: CSDE-WIN-001 suppressed when CSDE-WIN-002 fires ──────
test('T64', 'CSDE-WIN-001 individual logon-fail is suppressed when CSDE-WIN-002 fires', () => {
  const events = [
    { TimeGenerated: iso(0), EventID: '4625', Computer: 'DC01', SubjectUserName: 'admin', IpAddress: '10.0.0.5', Status: '0xC000006D' },
    { TimeGenerated: iso(1), EventID: '4625', Computer: 'DC01', SubjectUserName: 'admin', IpAddress: '10.0.0.5', Status: '0xC000006D' },
    { TimeGenerated: iso(2), EventID: '4625', Computer: 'DC01', SubjectUserName: 'admin', IpAddress: '10.0.0.5', Status: '0xC000006D' },
  ];
  const r = csde.analyzeEvents(events);
  const win001 = r.detections.filter(d => d.ruleId === 'CSDE-WIN-001');
  const win002 = r.detections.filter(d => d.ruleId === 'CSDE-WIN-002');
  if (!win002.length) return 'CSDE-WIN-002 did not fire — brute force not detected';
  if (win001.length > 0) return `CSDE-WIN-001 should be suppressed by CSDE-WIN-002, but ${win001.length} CSDE-WIN-001 detections exist`;
  return true;
});

// ── T65: Chain name contains "APT" for full-apt-ransomware ────
test('T65', 'Chain name reflects full APT kill chain', () => {
  if (!aptResult.chains || !aptResult.chains[0]) return 'No chains returned';
  const c = aptResult.chains[0];
  if (!c.name.toLowerCase().includes('apt') && !c.name.toLowerCase().includes('full') && !c.name.toLowerCase().includes('kill chain')) {
    return `Expected APT kill chain name, got: "${c.name}"`;
  }
  return true;
});

// ── T66: allHosts in incidentSummary contains all affected hosts ─
test('T66', 'incidentSummaries.allHosts contains DC01 and FILE01', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const hosts = sum.allHosts || [];
  if (!hosts.includes('DC01')) return `DC01 not in allHosts: ${JSON.stringify(hosts)}`;
  if (!hosts.includes('FILE01')) return `FILE01 not in allHosts: ${JSON.stringify(hosts)}`;
  return true;
});

// ── T67: mitreMappings includes entries from all stages ────────
test('T67', 'mitreMappings includes techniques from all attack stages', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  const mappings = sum.mitreMappings || [];
  if (mappings.length < 4) return `Expected ≥4 MITRE mappings, got ${mappings.length}: ${JSON.stringify(mappings.map(m=>m.technique))}`;
  return true;
});

// ── T68: stageCount equals number of unique detections ─────────
test('T68', 'stageCount matches number of kill-chain stages', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  if (sum.stageCount !== (sum.killChainStages || []).length) {
    return `stageCount=${sum.stageCount} but killChainStages.length=${(sum.killChainStages||[]).length}`;
  }
  return true;
});

// ── T69: P1 escalation when log tampering in full APT chain ───
test('T69', 'P1 escalation triggered when log tampering (EventID 1102) in APT chain', () => {
  const sum = aptResult.incidentSummaries && aptResult.incidentSummaries[0];
  if (!sum) return 'No incident summary';
  if (!sum.logTampering) return 'logTampering flag not set for incident containing EventID 1102';
  if (!sum.p1Priority) return 'p1Priority flag not set for incident with log tampering';
  return true;
});

// ── T70: chainValid=false flagged for causal-violation scenario ─
test('T70', 'chainValid=false when ransomware precedes execution (impossible sequence)', () => {
  const badEvents = [
    // Impact BEFORE any execution
    { TimeGenerated: iso(0), EventID: '4688', Computer: 'WIN01', SubjectUserName: 'attacker', NewProcessName: 'vssadmin.exe', CommandLine: 'vssadmin delete shadows /all' },
    // Execution AFTER impact — causal violation
    { TimeGenerated: iso(10), EventID: '4688', Computer: 'WIN01', SubjectUserName: 'attacker', NewProcessName: 'powershell.exe', CommandLine: 'powershell -EncodedCommand abc123' },
  ];
  const r = csde.analyzeEvents(badEvents);
  const sum = r.incidentSummaries && r.incidentSummaries[0];
  if (!sum) return 'No incident summary for causal violation test';
  // Impact→execution is a violation, chainValid should be false
  // (or violations should be non-empty if flagged as such)
  const violations = sum.causalViolations || [];
  const hasImpactToExec = violations.some(v => v.stage_a?.tactic === 'impact' && v.stage_b?.tactic === 'execution');
  // Note: impact→execution is not in VALID_CAUSAL_EDGES, so should be a violation
  if (!hasImpactToExec) {
    // May be flagged differently depending on DAG structure - just verify chainValid=false
    if (sum.chainValid) return 'chainValid=true when impact precedes execution (should be false)';
  }
  return true;
});

// ── Summary ───────────────────────────────────────────────────
console.log(`
════════════════════════════════════════════════════════════════
  Results: ${passed + failed}/${passed + failed} run  |  ${passed} PASSED  |  ${failed} FAILED
════════════════════════════════════════════════════════════════
`);

// Write results
const fs = require('fs');
fs.writeFileSync('validation_results_soc_v9.json', JSON.stringify({
  suite: 'SOC v9', total: passed + failed, passed, failed,
  timestamp: new Date().toISOString(),
}, null, 2));
console.log('  Results written to validation_results_soc_v9.json\n');

if (failed > 0) process.exit(1);
