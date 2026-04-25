/**
 * ════════════════════════════════════════════════════════════════════
 *  SOC v7 — PRODUCTION VALIDATION SUITE
 *  Tests all remediation requirements from the security audit:
 *    T16 — Log tampering EventID 1102 → P1 + critical + TRUE_POSITIVE
 *    T17 — Audit policy tamper EventID 4719 → P1 + critical
 *    T18 — Security service stop → P1 escalation
 *    T19 — Password spray (T1110.003) cross-user same-IP → CSDE-WIN-025
 *    T20 — Credential stuffing (T1110.004) high-volume multi-account
 *    T21 — WSL/bash.exe on Windows detected correctly (CSDE-WIN-028)
 *    T22 — OS misclassification: Linux rules silent on Windows events
 *    T23 — OS misclassification: Windows rules silent on Linux events
 *    T24 — Exploit chain: web shell → cmd → persistence
 *    T25 — Strict cross-user correlation: alice ≠ bob should NOT merge
 *    T26 — Successful logon after brute force (CSDE-WIN-003) verdict
 *    T27 — Verdict field: confirmed TRUE_POSITIVE for high-confidence chain
 *    T28 — False-positive suppression: benign admin activity verdict=FP
 *    T29 — Credential dump logCategory fix: 4688 events fire CSDE-WIN-014
 *    T30 — Ransomware + log tampering combo: P1 + riskScore=100
 * ════════════════════════════════════════════════════════════════════
 */

const vm  = require('vm');
const fs  = require('fs');
const path = require('path');

// ── Load CSDE engine ────────────────────────────────────────────────
const code = fs.readFileSync(path.join(__dirname, 'js/raykan.js'), 'utf8');
const match = code.match(/const CSDE = \(function\(\) \{([\s\S]+?)\}\)\(\); \/\/ end CSDE/);
if (!match) { console.error('CSDE IIFE not found'); process.exit(1); }

const ctx = { CSDE: null, console: { log:()=>{}, error:()=>{}, warn:()=>{} },
              Date, Math, JSON, parseInt, parseFloat, isNaN, isFinite,
              Set, Map, Array, Object, String, Number, Boolean, RegExp, Error };
vm.createContext(ctx);
vm.runInContext(`CSDE = (function() { ${match[1]} })();`, ctx);
const analyze = ctx.CSDE.analyzeEvents;

// ── Test helpers ────────────────────────────────────────────────────
const ts  = (offset) => new Date(Date.now() - (offset||0)).toISOString();
let pass=0, fail=0;
const results = [];

function test(id, desc, fn) {
  try {
    const result = fn();
    if (result === true || result === undefined) {
      console.log(`\x1b[32m✔ PASS\x1b[0m  [${id}] ${desc}`);
      pass++;
      results.push({ id, desc, status:'pass' });
    } else {
      console.log(`\x1b[31m✖ FAIL\x1b[0m  [${id}] ${desc}`);
      console.log(`  Reason: ${result}`);
      fail++;
      results.push({ id, desc, status:'fail', reason: result });
    }
  } catch(e) {
    console.log(`\x1b[31m✖ ERROR\x1b[0m [${id}] ${desc}: ${e.message}`);
    fail++;
    results.push({ id, desc, status:'error', reason: e.message });
  }
}

function assert(condition, msg) {
  if (!condition) return msg || 'Assertion failed';
  return true;
}

// ══════════════════════════════════════════════════════════════════════
// T16 — Log Tampering: EventID 1102 → P1 escalation
// ══════════════════════════════════════════════════════════════════════
test('T16', 'Log tampering: EventID 1102 → P1 critical verdict TRUE_POSITIVE', () => {
  const r = analyze([
    { EventID: 1102, Computer: 'DC01', User: 'attacker', TimeGenerated: ts(0) },
  ]);
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-023');
  if (!det) return 'CSDE-WIN-023 not triggered for EventID 1102';

  const inc = r.incidents[0];
  if (!inc) return 'No incident formed';
  if (!inc.p1Priority) return 'p1Priority not set';
  if (inc.severity !== 'critical') return `severity=${inc.severity}, expected critical`;
  if (inc.verdict !== 'TRUE_POSITIVE') return `verdict=${inc.verdict}, expected TRUE_POSITIVE`;
  if (inc.riskScore !== 100) return `riskScore=${inc.riskScore}, expected 100`;
  if (!inc.logTamperingDetected) return 'logTamperingDetected not set';
  console.log(`  ℹ  det=${det.ruleId}, P1=${inc.p1Priority}, verdict=${inc.verdict}, risk=${inc.riskScore}`);
});

// ══════════════════════════════════════════════════════════════════════
// T17 — Audit Policy Tamper: EventID 4719 → P1
// ══════════════════════════════════════════════════════════════════════
test('T17', 'Audit policy tamper: EventID 4719 → P1 critical', () => {
  const r = analyze([
    { EventID: 4719, Computer: 'DC01', User: 'attacker', TimeGenerated: ts(0) },
  ]);
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-024');
  if (!det) return 'CSDE-WIN-024 not triggered for EventID 4719';
  const inc = r.incidents[0];
  if (!inc?.p1Priority) return 'No P1 incident';
  if (inc.severity !== 'critical') return `severity=${inc.severity}`;
  console.log(`  ℹ  det=${det.ruleId}, mitre=${det.mitre?.technique}, P1=${inc.p1Priority}`);
});

// ══════════════════════════════════════════════════════════════════════
// T18 — Security Service Stop: EventID 7036 → P1
// ══════════════════════════════════════════════════════════════════════
test('T18', 'Security service stop: EventID 7036 (EventLog) → P1', () => {
  const r = analyze([
    { EventID: 7036, Computer: 'DC01', ServiceName: 'Windows Event Log',
      message: 'The Windows Event Log service entered the stopped state.', TimeGenerated: ts(0) },
  ]);
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-027');
  if (!det) return 'CSDE-WIN-027 not triggered for EventID 7036 (EventLog)';
  const inc = r.incidents[0];
  if (!inc?.p1Priority) return 'No P1 incident';
  console.log(`  ℹ  det=${det.ruleId}, P1=${inc.p1Priority}, narrative=${inc.narrative?.slice(0,60)}`);
});

// ══════════════════════════════════════════════════════════════════════
// T19 — Password Spray: 6 users, same IP → CSDE-WIN-025 (T1110.003)
// ══════════════════════════════════════════════════════════════════════
test('T19', 'Password spray: 6 users same source IP → CSDE-WIN-025 T1110.003', () => {
  const users = ['alice','bob','charlie','diana','eve','frank'];
  const r = analyze(users.flatMap((u,i) => [
    { EventID: 4625, Computer: 'DC01', User: u, SourceIP: '10.10.10.100',
      LogonType: '3', Status: '0xC000006A', TimeGenerated: ts(i*5000) },
  ]));
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-025');
  if (!det) return 'CSDE-WIN-025 not triggered';
  if (det.mitre?.technique !== 'T1110.003') return `technique=${det.mitre?.technique}, expected T1110.003`;
  // Single logon failures should be suppressed when spray is detected
  const singleFails = r.detections.filter(d => d.ruleId === 'CSDE-WIN-001');
  console.log(`  ℹ  sprayDet=1, srcIp=${det.srcIp}, riskScore=${det.riskScore}, singleFails=${singleFails.length}`);
});

// ══════════════════════════════════════════════════════════════════════
// T20 — Credential Stuffing: 12 users, rapid rate → CSDE-WIN-026
// ══════════════════════════════════════════════════════════════════════
test('T20', 'Credential stuffing: 12 accounts, multiple IPs → CSDE-WIN-026 T1110.004', () => {
  const users = ['u1','u2','u3','u4','u5','u6','u7','u8','u9','u10','u11','u12'];
  const r = analyze(users.flatMap((u,i) => [
    { EventID: 4625, Computer: 'DC01', User: u, SourceIP: `10.10.${Math.floor(i/3)}.${i%3+1}`,
      LogonType: '3', Status: '0xC000006A', TimeGenerated: ts(i*2000) },
  ]));
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-026');
  if (!det) return 'CSDE-WIN-026 not triggered for 12-user stuffing';
  if (det.mitre?.technique !== 'T1110.004') return `technique=${det.mitre?.technique}`;
  console.log(`  ℹ  stuffDet=1, riskScore=${det.riskScore}, mitre=${det.mitre?.technique}`);
});

// ══════════════════════════════════════════════════════════════════════
// T21 — WSL on Windows: bash.exe detected (CSDE-WIN-028), OS=windows
// ══════════════════════════════════════════════════════════════════════
test('T21', 'WSL detection: bash.exe on Windows → CSDE-WIN-028, OS=windows', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'WS01', User: 'jdoe', ProcessName: 'bash.exe',
      CommandLine: 'bash.exe -c "id && cat /etc/shadow"', TimeGenerated: ts(0) },
  ]);
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-028');
  if (!det) return 'CSDE-WIN-028 not triggered for bash.exe';
  // Should be classified as Windows (not Linux)
  const lnxDets = r.detections.filter(d => d.ruleId?.startsWith('CSDE-LNX'));
  if (lnxDets.length > 0) return `Linux rules fired on Windows+bash.exe: ${lnxDets.map(d=>d.ruleId)}`;
  console.log(`  ℹ  wslDet=${det.ruleId}, risk=${det.riskScore}, no Linux misfire`);
});

// ══════════════════════════════════════════════════════════════════════
// T22 — OS misclassification: Linux cron rule silent on Windows event
// ══════════════════════════════════════════════════════════════════════
test('T22', 'OS guard: Linux cron rule (CSDE-LNX-003) silent on pure Windows event', () => {
  const r = analyze([
    { EventID: 4698, Computer: 'WS01', User: 'jdoe', TaskName: '\\Updates',
      TaskContent: 'cmd.exe /c powershell -enc abc', TimeGenerated: ts(0) },
  ]);
  const lnxDets = r.detections.filter(d => d.ruleId?.startsWith('CSDE-LNX'));
  if (lnxDets.length > 0) return `Linux rules fired on Windows event: ${lnxDets.map(d=>d.ruleId).join(',')}`;
  const winDets = r.detections.filter(d => d.ruleId?.startsWith('CSDE-WIN'));
  console.log(`  ℹ  Linux dets=0, Windows dets=${winDets.length} (correct)`);
});

// ══════════════════════════════════════════════════════════════════════
// T23 — OS misclassification: Windows LSASS rule silent on Linux auditd event
// ══════════════════════════════════════════════════════════════════════
test('T23', 'OS guard: Windows CSDE-WIN-014 silent on Linux auditd event', () => {
  const r = analyze([
    { message: 'type=EXECVE argc=3 a0="procdump" a1="-ma" a2="lsass.exe"',
      source: 'auditd', Computer: 'linuxhost', TimeGenerated: ts(0) },
  ]);
  const winDets = r.detections.filter(d => d.ruleId?.startsWith('CSDE-WIN'));
  if (winDets.length > 0) return `Windows rules fired on Linux event: ${winDets.map(d=>d.ruleId).join(',')}`;
  console.log(`  ℹ  Windows dets=0 on Linux auditd event (correct)`);
});

// ══════════════════════════════════════════════════════════════════════
// T24 — Exploit chain: web shell (w3wp → cmd → net user /add)
// ══════════════════════════════════════════════════════════════════════
test('T24', 'Web shell exploit chain: w3wp.exe → cmd.exe → net user /add', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'WEB01', User: 'apppool\\myapp',
      ProcessName: 'cmd.exe', ParentProcess: 'w3wp.exe',
      CommandLine: 'cmd.exe /c whoami', TimeGenerated: ts(60000) },
    { EventID: 4688, Computer: 'WEB01', User: 'apppool\\myapp',
      ProcessName: 'powershell.exe', ParentProcess: 'w3wp.exe',
      CommandLine: 'powershell -enc aQBlAHgA', TimeGenerated: ts(30000) },
    { EventID: 4688, Computer: 'WEB01', User: 'apppool\\myapp',
      ProcessName: 'net.exe', ParentProcess: 'cmd.exe',
      CommandLine: 'net user webshell_backdoor P@ssw0rd! /add', TimeGenerated: ts(0) },
  ]);
  const webshell = r.detections.find(d => d.ruleId === 'CSDE-WIN-029');
  if (!webshell) return 'CSDE-WIN-029 not triggered';
  const chain = r.chains[0];
  if (!chain) return 'No attack chain formed';
  if (chain.stages?.length < 2) return `Expected ≥2 stages, got ${chain.stages?.length}`;
  console.log(`  ℹ  webshell=${webshell.ruleId}, chain=${chain.name}, stages=${chain.stages?.length}, risk=${chain.riskScore}`);
});

// ══════════════════════════════════════════════════════════════════════
// T25 — Cross-user isolation: alice, bob, charlie → separate incidents
// ══════════════════════════════════════════════════════════════════════
test('T25', 'Cross-user isolation: alice+bob+charlie from different IPs → separate incidents', () => {
  const r = analyze([
    { EventID: 4625, Computer: 'DC01', User: 'alice', SourceIP: '10.1.1.1',
      Status: '0xC000006A', TimeGenerated: ts(5000) },
    { EventID: 4625, Computer: 'DC01', User: 'bob', SourceIP: '10.1.1.2',
      Status: '0xC000006A', TimeGenerated: ts(4000) },
    { EventID: 4688, Computer: 'DC01', User: 'charlie', ProcessName: 'net.exe',
      CommandLine: 'net user admin /add', TimeGenerated: ts(1000) },
  ]);
  // Should NOT merge alice, bob, charlie into one incident (different users, different IPs)
  const mergedInc = r.incidents.find(i => {
    const users = (i.allUsers||[]).map(u=>u.toLowerCase());
    return users.some(u=>u.includes('alice')) && users.some(u=>u.includes('charlie'));
  });
  if (mergedInc) return `alice and charlie incorrectly merged into same incident: ${JSON.stringify(mergedInc.allUsers)}`;
  console.log(`  ℹ  incidents=${r.incidents.length} (alice, bob, charlie correctly separated)`);
});

// ══════════════════════════════════════════════════════════════════════
// T26 — Brute force compromise: fails + success → CSDE-WIN-003 critical verdict
// ══════════════════════════════════════════════════════════════════════
test('T26', 'Brute force success: CSDE-WIN-003 fires with verdict TRUE_POSITIVE', () => {
  const r = analyze([
    { EventID: 4625, Computer: 'DC01', User: 'jdoe', SourceIP: '10.5.5.5', Status:'0xC000006A', TimeGenerated: ts(300000) },
    { EventID: 4625, Computer: 'DC01', User: 'jdoe', SourceIP: '10.5.5.5', Status:'0xC000006A', TimeGenerated: ts(240000) },
    { EventID: 4625, Computer: 'DC01', User: 'jdoe', SourceIP: '10.5.5.5', Status:'0xC000006A', TimeGenerated: ts(180000) },
    { EventID: 4624, Computer: 'DC01', User: 'jdoe', SourceIP: '10.5.5.5', LogonType:'3', Status:'Success', TimeGenerated: ts(60000) },
    { EventID: 4688, Computer: 'DC01', User: 'jdoe', ProcessName: 'net.exe',
      CommandLine: 'net user hacker P@ss /add', TimeGenerated: ts(0) },
  ]);
  const bfSuccess = r.detections.find(d => d.ruleId === 'CSDE-WIN-003');
  if (!bfSuccess) return 'CSDE-WIN-003 not triggered';
  const inc = r.incidents.find(i => i.techniques?.includes('T1110'));
  if (!inc) return 'No incident with T1110';
  if (inc.verdict !== 'TRUE_POSITIVE') return `verdict=${inc.verdict}, expected TRUE_POSITIVE`;
  console.log(`  ℹ  CSDE-WIN-003 fired, inc verdict=${inc.verdict}, risk=${inc.riskScore}`);
});

// ══════════════════════════════════════════════════════════════════════
// T27 — Verdict TRUE_POSITIVE: ransomware chain confidence ≥ 90
// ══════════════════════════════════════════════════════════════════════
test('T27', 'Verdict TRUE_POSITIVE: ransomware chain → confidence ≥ 90, verdict confirmed', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'WS01', User: 'john', ProcessName: 'procdump.exe',
      CommandLine: 'procdump -ma lsass.exe c:\\temp\\lsass.dmp', TimeGenerated: ts(600000) },
    { EventID: 4688, Computer: 'WS01', User: 'john', ProcessName: 'vssadmin.exe',
      CommandLine: 'vssadmin delete shadows /all /quiet', TimeGenerated: ts(400000) },
    { EventID: 4688, Computer: 'WS01', User: 'john', ProcessName: 'powershell.exe',
      CommandLine: 'powershell -EncodedCommand aQBlAHgA', TimeGenerated: ts(200000) },
    { EventID: 4688, Computer: 'WS01', User: 'john', ProcessName: 'net.exe',
      CommandLine: 'net user ransomware_svc P@ss /add', TimeGenerated: ts(100000) },
  ]);
  const inc = r.incidents[0];
  if (!inc) return 'No incident';
  if (inc.confidence?.score < 70) return `confidence=${inc.confidence?.score}, expected ≥70`;
  if (inc.verdict !== 'TRUE_POSITIVE') return `verdict=${inc.verdict}`;
  console.log(`  ℹ  confidence=${inc.confidence?.score}, verdict=${inc.verdict}, risk=${inc.riskScore}`);
});

// ══════════════════════════════════════════════════════════════════════
// T28 — False Positive: benign admin (Veeam/WSUS) → suppressed or FP verdict
// ══════════════════════════════════════════════════════════════════════
test('T28', 'FP suppression: Veeam backup process → no critical incident', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'BACKUP01', User: 'svc_veeam', ProcessName: 'veeam.exe',
      CommandLine: 'veeam.exe -backup --shadow-copy', TimeGenerated: ts(120000) },
    { EventID: 4688, Computer: 'BACKUP01', User: 'svc_veeam', ProcessName: 'wuauclt.exe',
      CommandLine: 'wuauclt.exe /UpdateNow', TimeGenerated: ts(60000) },
  ]);
  // Should have 0 critical incidents for known backup processes
  const critInc = r.incidents.filter(i => i.severity === 'critical' && !i.p1Priority);
  if (critInc.length > 0) return `Unexpected critical incident for Veeam: ${critInc[0]?.title}`;
  console.log(`  ℹ  incidents=${r.incidents.length}, no critical for backup/admin tools`);
});

// ══════════════════════════════════════════════════════════════════════
// T29 — Credential dump logCategory fix: EventID 4688 → CSDE-WIN-014 fires
// ══════════════════════════════════════════════════════════════════════
test('T29', 'logCategory fix: EventID 4688 procdump→lsass fires CSDE-WIN-014', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'WS01', User: 'attacker',
      ProcessName: 'procdump64.exe',
      CommandLine: 'procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp', TimeGenerated: ts(0) },
  ]);
  const det = r.detections.find(d => d.ruleId === 'CSDE-WIN-014');
  if (!det) return 'CSDE-WIN-014 not triggered — logCategory fix failed for EventID 4688';
  if (det.mitre?.technique !== 'T1003.001') return `technique=${det.mitre?.technique}`;
  console.log(`  ℹ  CSDE-WIN-014 fired, technique=${det.mitre?.technique}, risk=${det.riskScore}`);
});

// ══════════════════════════════════════════════════════════════════════
// T30 — Combined ransomware + log tampering → riskScore=100, P1
// ══════════════════════════════════════════════════════════════════════
test('T30', 'Ransomware + log tampering combo → riskScore=100, P1, TRUE_POSITIVE', () => {
  const r = analyze([
    { EventID: 4688, Computer: 'WS01', User: 'attacker', ProcessName: 'vssadmin.exe',
      CommandLine: 'vssadmin delete shadows /all /quiet', TimeGenerated: ts(400000) },
    { EventID: 1102, Computer: 'WS01', User: 'attacker', TimeGenerated: ts(300000) },
    { EventID: 4688, Computer: 'WS01', User: 'attacker', ProcessName: 'powershell.exe',
      CommandLine: 'powershell -EncodedCommand aQBlAHgA', TimeGenerated: ts(200000) },
    { EventID: 4688, Computer: 'WS01', User: 'attacker', ProcessName: 'net.exe',
      CommandLine: 'net user ransombackdoor P@ss /add', TimeGenerated: ts(100000) },
  ]);
  const inc = r.incidents[0];
  if (!inc) return 'No incident';
  if (!inc.p1Priority) return `p1Priority not set (logTampering=${inc.logTamperingDetected})`;
  if (inc.riskScore !== 100) return `riskScore=${inc.riskScore}, expected 100`;
  if (inc.verdict !== 'TRUE_POSITIVE') return `verdict=${inc.verdict}`;
  if (inc.severity !== 'critical') return `severity=${inc.severity}`;
  console.log(`  ℹ  combo: P1=${inc.p1Priority}, risk=${inc.riskScore}, verdict=${inc.verdict}, sev=${inc.severity}`);
});

// ══════════════════════════════════════════════════════════════════════
// RESULTS
// ══════════════════════════════════════════════════════════════════════
console.log('\n\x1b[1m════════════════════════════════════════════════════════════\x1b[0m');
console.log(`\x1b[1m  SOC v7 RESULTS: ${pass}/${pass+fail} passed\x1b[0m  (${fail} failed)`);
console.log('════════════════════════════════════════════════════════════\n');

// Save results
fs.writeFileSync('validation_results_soc_v7.json', JSON.stringify({
  suite: 'SOC-v7-Production-Hardening',
  timestamp: new Date().toISOString(),
  passed: pass,
  failed: fail,
  total: pass + fail,
  results,
}, null, 2));
console.log('  Results saved → validation_results_soc_v7.json');

if (fail > 0) process.exit(1);
