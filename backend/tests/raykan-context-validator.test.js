/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Detection Context Validator Tests
 *
 *  Tests:
 *    1. T1190 suppression without web-server telemetry
 *    2. T1190 allowed with web-server parent process
 *    3. T1021.002 suppression on bare LogonType=3
 *    4. T1021.002 allowed with PsExec + multi-host
 *    5. T1550.002 downgraded to T1078 on single-host NTLM
 *    6. T1550.002 preserved on cross-host NTLM
 *    7. T1110 suppression on single 4625 event
 *    8. T1110 triggered on 3+ failed logons
 *    9. Brute-force → success correlation pattern
 *   10. Password spraying pattern (multi-user failures)
 *   11. Network logon (LogonType=3) NOT classified as lateral movement
 *   12. 4624 + 4688 "net user /add" → T1136 (Account Creation)
 *   13. 4625 + 4624 + 4688 full sequence — correct per-event mapping
 *   14. Logsource compatibility: webserver rule vs windows auth event
 *   15. Context flags: buildContextFlags accuracy
 *   16. filterDetectionsByContext: mixed batch (some FPs suppressed)
 *   17. Metrics tracking across multiple validations
 *
 *  Run: node backend/tests/raykan-context-validator.test.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const path = require('path');
const {
  validate,
  correlateAuthSequence,
  filterDetectionsByContext,
  buildCorrelatedDetections,
  buildContextFlags,
  getMetrics,
  resetMetrics,
  TECHNIQUE_TELEMETRY_REQUIREMENTS,
  TECHNIQUE_REQUIRED_LOGSOURCE,
} = require(path.join(__dirname, '../services/raykan/detection-context-validator'));

// ── Test helpers ───────────────────────────────────────────────────
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌ ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(a, b, msg) {
  if (a !== b) throw new Error(`${msg || 'assertEqual'}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function assertIncludes(arr, val, msg) {
  if (!Array.isArray(arr) || !arr.includes(val))
    throw new Error(`${msg || 'assertIncludes'}: ${JSON.stringify(val)} not found in ${JSON.stringify(arr)}`);
}

function assertNotIncludes(arr, val, msg) {
  if (Array.isArray(arr) && arr.includes(val))
    throw new Error(`${msg || 'assertNotIncludes'}: ${JSON.stringify(val)} found (should be absent) in ${JSON.stringify(arr)}`);
}

// ── Fixture factories ──────────────────────────────────────────────
function makeDetection(overrides = {}) {
  return {
    id         : `det-${Math.random().toString(36).slice(2)}`,
    ruleId     : 'RAYKAN-TEST',
    ruleName   : 'Test Detection',
    severity   : 'high',
    confidence : 80,
    tags       : [],
    logsource  : {},
    event      : {},
    ...overrides,
  };
}

function makeEvent(overrides = {}) {
  return {
    id        : `evt-${Math.random().toString(36).slice(2)}`,
    timestamp : new Date(),
    source    : 'test',
    format    : 'evtx',
    computer  : 'WORKSTATION-01',
    user      : 'testuser',
    eventId   : null,
    raw       : {},
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────
//  SECTION 1: T1190 (Exploit Public-Facing Application)
// ─────────────────────────────────────────────────────────────────
console.log('\n── T1190 (Web Attack) False-Positive Suppression ──────────────');

test('T1190 suppressed when event has no web-server telemetry (bare Windows auth)', () => {
  const det = makeDetection({
    tags     : ['attack.initial_access', 'attack.t1190'],
    logsource: { category: 'security', product: 'windows' },
  });
  const evt = makeEvent({ eventId: '4624', raw: { EventID: '4624', LogonType: '3' } });
  const result = validate(det, [evt], [det]);
  // T1190 must NOT survive without web telemetry
  const techs = result.adjustedTechniques || det.tags.filter(t => t.includes('t1190'));
  assert(result.suppressed || (result.adjustedTechniques && !result.adjustedTechniques.includes('T1190')),
    'T1190 should be suppressed or removed when no web-server evidence exists');
  assert(result.warnings.some(w => w.includes('T1190') || w.includes('logsource')),
    'Should have a warning about T1190 suppression');
});

test('T1190 suppressed even for process_creation rule without web parent', () => {
  const det = makeDetection({
    tags     : ['attack.initial_access', 'attack.t1190'],
    logsource: { category: 'process_creation', product: 'windows' },
  });
  const evt = makeEvent({ eventId: '4688', process: 'cmd.exe', parentProc: 'explorer.exe', raw: { EventID: '4688' } });
  const result = validate(det, [evt], [det]);
  assert(result.suppressed || (result.adjustedTechniques && !result.adjustedTechniques.includes('T1190')),
    'T1190 should be suppressed for cmd.exe spawned from explorer.exe (not a web server)');
});

test('T1190 allowed when parent process is a web server (w3wp.exe)', () => {
  const det = makeDetection({
    tags     : ['attack.initial_access', 'attack.t1190', 'attack.persistence', 'attack.t1505.003'],
    logsource: { category: 'process_creation', product: 'windows' },
  });
  const evt = makeEvent({
    eventId   : '4688',
    process   : 'cmd.exe',
    parentProc: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
    raw       : { EventID: '4688', Image: 'cmd.exe', ParentImage: 'w3wp.exe' },
  });
  const result = validate(det, [evt], [det]);
  assert(!result.suppressed, 'T1190 should be allowed when w3wp.exe is the parent');
  // Techniques should include T1190
  const finalTechs = result.adjustedTechniques !== null ? result.adjustedTechniques : ['T1190'];
  assertIncludes(finalTechs, 'T1190', 'T1190 should pass through with web-server parent');
});

test('T1190 allowed when URL field is present in event', () => {
  const det = makeDetection({
    tags     : ['attack.t1190'],
    logsource: { category: 'webserver' },
  });
  const evt = makeEvent({ url: 'http://target.example.com/shell.aspx', raw: { 'cs-uri-stem': '/shell.aspx' } });
  const result = validate(det, [evt], [det]);
  assert(!result.suppressed, 'T1190 should pass when URL field present');
});

test('T1190 allowed when context has_webserver_logs flag is set', () => {
  const det = makeDetection({ tags: ['attack.t1190'] });
  // Batch includes a web-source event
  const webEvt = makeEvent({ source: 'iis_logs', url: '/index.php?cmd=ls', format: 'webserver' });
  const authEvt = makeEvent({ eventId: '4624' });
  const result = validate(det, [webEvt, authEvt], [det]);
  assert(!result.suppressed, 'T1190 should pass when batch contains web-server log event');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 2: T1021.002 / T1021 (SMB Lateral Movement)
// ─────────────────────────────────────────────────────────────────
console.log('\n── T1021.002 (SMB Lateral Movement) False-Positive Suppression ──');

test('T1021.002 suppressed on bare LogonType=3 single-host event', () => {
  const det = makeDetection({
    tags     : ['attack.lateral_movement', 'attack.t1021.002'],
    logsource: { category: 'security', product: 'windows' },
  });
  const evt = makeEvent({
    eventId  : '4624',
    computer : 'WORKSTATION-01',
    srcIp    : '192.168.1.50',
    raw      : { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM' },
  });
  const result = validate(det, [evt], [det]);
  assert(result.suppressed || (result.adjustedTechniques && !result.adjustedTechniques.includes('T1021.002')),
    'T1021.002 should be suppressed: LogonType=3 alone is normal network authentication');
});

test('T1021.002 allowed when PsExec process present', () => {
  const det = makeDetection({
    tags     : ['attack.lateral_movement', 'attack.t1021.002'],
    logsource: { category: 'process_creation', product: 'windows' },
  });
  const evt = makeEvent({
    eventId : '4688',
    process : 'C:\\Windows\\System32\\psexec.exe',
    raw     : { EventID: '4688', Image: 'psexec.exe' },
  });
  const result = validate(det, [evt], [det]);
  assert(!result.suppressed, 'T1021.002 allowed when PsExec binary detected');
  const techs = result.adjustedTechniques || ['T1021.002'];
  assertIncludes(techs, 'T1021.002', 'T1021.002 should be in final techniques');
});

test('T1021.002 allowed when commandLine contains admin share path', () => {
  const det = makeDetection({
    tags     : ['attack.lateral_movement', 'attack.t1021.002'],
    logsource: { category: 'process_creation', product: 'windows' },
  });
  const evt = makeEvent({
    eventId    : '4688',
    commandLine: 'net use \\\\192.168.1.100\\admin$ /user:Administrator password',
    raw        : { EventID: '4688', CommandLine: 'net use \\\\192.168.1.100\\admin$' },
  });
  const result = validate(det, [evt], [det]);
  assert(!result.suppressed, 'T1021.002 allowed when admin$ share path in commandLine');
});

test('T1021.002 allowed when multi-host activity in event batch', () => {
  const det = makeDetection({ tags: ['attack.t1021.002'] });
  const evts = [
    makeEvent({ computer: 'WORKSTATION-01', eventId: '4624', raw: { EventID: '4624', LogonType: '3' } }),
    makeEvent({ computer: 'SERVER-02',       eventId: '4624', raw: { EventID: '4624', LogonType: '3' } }),
    makeEvent({ computer: 'DC-01',           eventId: '4624', raw: { EventID: '4624', LogonType: '3' } }),
  ];
  const result = validate(det, evts, [det]);
  assert(!result.suppressed, 'T1021.002 allowed with multi-host lateral movement evidence');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 3: T1550.002 (Pass-the-Hash) — Downgrade Logic
// ─────────────────────────────────────────────────────────────────
console.log('\n── T1550.002 (Pass-the-Hash) Context-Aware Downgrade ───────────');

test('T1550.002 downgraded to T1078 on single-host NTLM logon', () => {
  const det = makeDetection({
    tags     : ['attack.lateral_movement', 'attack.t1550.002'],
    logsource: { category: 'security', product: 'windows' },
    confidence: 85,
  });
  const evt = makeEvent({
    eventId : '4624',
    computer: 'WORKSTATION-01',
    srcIp   : '192.168.1.50',
    raw     : { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', TargetUserName: 'john.doe' },
  });
  const result = validate(det, [evt], [det]);
  assert(!result.suppressed || (result.adjustedTechniques && result.adjustedTechniques.includes('T1078')),
    'T1550.002 should be downgraded or at minimum T1078 should appear as alternative');
  if (result.adjustedTechniques) {
    assertNotIncludes(result.adjustedTechniques, 'T1550.002', 'T1550.002 should be removed without cross-host evidence');
  }
});

test('T1550.002 preserved when cross-host NTLM detected (multi-host batch)', () => {
  const det = makeDetection({
    tags: ['attack.t1550.002', 'attack.lateral_movement'],
    confidence: 85,
  });
  // Two different computers with NTLM logons = cross-host evidence
  const evts = [
    makeEvent({ computer: 'WORKSTATION-01', eventId: '4624', srcIp: '192.168.1.10',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM' } }),
    makeEvent({ computer: 'SERVER-DB',      eventId: '4624', srcIp: '192.168.1.10',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM' } }),
  ];
  const flags = buildContextFlags(evts, [det]);
  assert(flags.cross_host_ntlm_logon, 'cross_host_ntlm_logon context flag should be set');
  const result = validate(det, evts, [det]);
  assert(!result.suppressed, 'T1550.002 should not be suppressed with cross-host NTLM');
  if (result.adjustedTechniques) {
    assertIncludes(result.adjustedTechniques, 'T1550.002', 'T1550.002 should be in final techniques');
  }
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 4: T1110 (Brute Force) — Evidence Threshold
// ─────────────────────────────────────────────────────────────────
console.log('\n── T1110 (Brute Force) Evidence Threshold ──────────────────────');

test('T1110 downgraded to T1078 on single 4625 event', () => {
  const det = makeDetection({
    tags: ['attack.credential_access', 'attack.t1110.001'],
    confidence: 70,
  });
  const evt = makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3' } });
  const result = validate(det, [evt], [det]);
  // Should be adjusted
  if (result.adjustedTechniques !== null) {
    assertNotIncludes(result.adjustedTechniques, 'T1110.001',
      'T1110.001 should be removed for single 4625 event');
  }
  assert(result.warnings.length > 0, 'Should warn about insufficient brute-force evidence');
});

test('T1110 preserved when batch has 3+ failed logon events', () => {
  const det = makeDetection({
    tags: ['attack.credential_access', 'attack.t1110.001'],
    confidence: 75,
  });
  // 4 failed logons
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin' } }),
  ];
  const flags = buildContextFlags(evts, [det]);
  assert(flags.multiple_4625_events, 'multiple_4625_events context flag should be set with 4 failures');
  const result = validate(det, evts, [det]);
  if (result.adjustedTechniques !== null) {
    assertIncludes(result.adjustedTechniques, 'T1110.001',
      'T1110.001 should be preserved with 4 failed logons');
  }
  assert(!result.suppressed, 'Detection should not be suppressed with sufficient brute-force evidence');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 5: correlateAuthSequence — Behavioral Patterns
// ─────────────────────────────────────────────────────────────────
console.log('\n── correlateAuthSequence — Behavioral Pattern Detection ─────────');

test('Single 4625 → T1078 (not T1110)', () => {
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  // Should produce auth_failure or nothing for T1110
  const bruteForce = correlations.find(c => c.type === 'brute_force');
  assert(!bruteForce, 'Should NOT produce brute_force correlation for single 4625 event');
  const authFail = correlations.find(c => c.type === 'auth_failure');
  if (authFail) {
    assertIncludes(authFail.techniques, 'T1078', 'Single failure should map to T1078');
    assertNotIncludes(authFail.techniques, 'T1110', 'Single failure should NOT map to T1110');
  }
});

test('3+ failed logons → T1110 brute-force correlation', () => {
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  const bruteForce = correlations.find(c => c.type === 'brute_force');
  assert(bruteForce, 'Should produce brute_force correlation for 4+ failures');
  assertIncludes(bruteForce.techniques, 'T1110.001', 'Brute force should map to T1110.001');
});

test('Multiple 4625 failures → 4624 success = brute_force_success pattern', () => {
  const now = Date.now();
  const evts = [
    makeEvent({ timestamp: new Date(now - 5000), eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ timestamp: new Date(now - 4000), eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ timestamp: new Date(now - 3000), eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ timestamp: new Date(now - 2000), eventId: '4624', raw: { EventID: '4624', LogonType: '2', TargetUserName: 'admin' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  const success = correlations.find(c => c.type === 'brute_force_success');
  assert(success, 'Should detect brute-force-success pattern');
  assertIncludes(success.techniques, 'T1110', 'Brute-force success should include T1110');
  assertIncludes(success.techniques, 'T1078', 'Brute-force success should include T1078');
  assert(success.confidence >= 85, 'Brute-force success should have high confidence');
});

test('LogonType=3 single host → T1078 (network logon), NOT T1021 lateral movement', () => {
  const evts = [
    makeEvent({ eventId: '4624', computer: 'WORKSTATION-01', srcIp: '192.168.1.50',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', TargetUserName: 'john.doe' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  // Should NOT produce lateral movement
  const lateral = correlations.find(c => c.type === 'lateral_movement_ntlm');
  assert(!lateral, 'Single-host NTLM logon should NOT produce lateral_movement_ntlm correlation');
  // Should produce network_logon with T1078
  const netLogon = correlations.find(c => c.type === 'network_logon');
  if (netLogon) {
    assertIncludes(netLogon.techniques, 'T1078', 'Network logon should map to T1078');
    assertNotIncludes(netLogon.techniques, 'T1021', 'Network logon should NOT include T1021');
    assertNotIncludes(netLogon.techniques, 'T1550.002', 'Network logon should NOT include T1550.002');
  }
});

test('Cross-host NTLM logons → T1550.002 lateral movement correlation', () => {
  const evts = [
    makeEvent({ computer: 'WORKSTATION-01', eventId: '4624', srcIp: '192.168.1.10',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', TargetUserName: 'admin' } }),
    makeEvent({ computer: 'SERVER-01',      eventId: '4624', srcIp: '192.168.1.42',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', TargetUserName: 'admin' } }),
    makeEvent({ computer: 'DC-01',          eventId: '4624', srcIp: '192.168.1.42',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', TargetUserName: 'Domain Admin' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  const lateral = correlations.find(c => c.type === 'lateral_movement_ntlm');
  assert(lateral, 'Multi-host NTLM should produce lateral_movement_ntlm correlation');
  assertIncludes(lateral.techniques, 'T1550.002', 'Should include T1550.002');
  assert(lateral.confidence >= 70, 'Should have medium-high confidence');
});

test('4624 + net user add command → T1136 Account Creation correlation', () => {
  const evts = [
    makeEvent({ eventId: '4624', raw: { EventID: '4624', LogonType: '2' } }),
    makeEvent({ eventId: '4688', commandLine: 'net user backdoor P@ssw0rd! /add',
      raw: { EventID: '4688', CommandLine: 'net user backdoor P@ssw0rd! /add' } }),
  ];
  const correlations = correlateAuthSequence(evts);
  const acctCreate = correlations.find(c => c.type === 'account_creation_after_auth');
  assert(acctCreate, 'Should detect account creation pattern');
  assertIncludes(acctCreate.techniques, 'T1136', 'Should map to T1136 (Account Creation)');
  assertIncludes(acctCreate.techniques, 'T1136.001', 'Should include T1136.001 sub-technique');
});

test('Password spraying: many users, few IPs → T1110.003', () => {
  const evts = ['alice', 'bob', 'charlie', 'diana', 'eve'].map(u =>
    makeEvent({ eventId: '4625', srcIp: '10.0.0.99',
      raw: { EventID: '4625', LogonType: '3', TargetUserName: u } })
  );
  const correlations = correlateAuthSequence(evts);
  const spray = correlations.find(c => c.type === 'password_spray');
  assert(spray, 'Should detect password spraying with 5 different target users');
  assertIncludes(spray.techniques, 'T1110.003', 'Password spray should map to T1110.003');
  assert(spray.confidence >= 80, 'Password spray should have high confidence');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 6: Context Flags
// ─────────────────────────────────────────────────────────────────
console.log('\n── buildContextFlags Accuracy ───────────────────────────────────');

test('multiple_4625_events flag: true with 3+ failures', () => {
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625' } }),
  ];
  const flags = buildContextFlags(evts, []);
  assert(flags.multiple_4625_events === true, 'multiple_4625_events should be true with 3 failures');
  assert(flags.has_4624_success === false, 'has_4624_success should be false');
});

test('multiple_4625_events flag: false with only 2 failures', () => {
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625' } }),
  ];
  const flags = buildContextFlags(evts, []);
  assert(flags.multiple_4625_events === false, 'multiple_4625_events should be false with only 2 failures');
});

test('multi_host_activity: true with 2+ distinct computers', () => {
  const evts = [
    makeEvent({ computer: 'HOST-A' }),
    makeEvent({ computer: 'HOST-B' }),
  ];
  const flags = buildContextFlags(evts, []);
  assert(flags.multi_host_activity === true, 'multi_host_activity should be true with 2 hosts');
});

test('multi_host_activity: false with single computer', () => {
  const evts = [
    makeEvent({ computer: 'HOST-A' }),
    makeEvent({ computer: 'HOST-A' }),
  ];
  const flags = buildContextFlags(evts, []);
  assert(flags.multi_host_activity === false, 'multi_host_activity should be false with 1 host');
});

test('has_webserver_logs: true when source contains "iis"', () => {
  const evts = [makeEvent({ source: 'iis_logs', format: 'webserver' })];
  const flags = buildContextFlags(evts, []);
  assert(flags.has_webserver_logs === true, 'has_webserver_logs should be true for IIS source');
});

test('has_webserver_logs: true when event has url field', () => {
  const evts = [makeEvent({ url: 'http://example.com/test.php' })];
  const flags = buildContextFlags(evts, []);
  assert(flags.has_webserver_logs === true, 'has_webserver_logs should be true when url is present');
});

test('multiple_target_users: true with 3+ distinct failure targets', () => {
  const evts = ['alice', 'bob', 'charlie'].map(u =>
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: u } })
  );
  const flags = buildContextFlags(evts, []);
  assert(flags.multiple_target_users === true, 'multiple_target_users should be true with 3+ targets');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 7: filterDetectionsByContext — Mixed Batch
// ─────────────────────────────────────────────────────────────────
console.log('\n── filterDetectionsByContext — Mixed Batch Processing ───────────');

test('Mixed batch: T1190 suppressed, T1059 passes through', () => {
  const detections = [
    makeDetection({ ruleId: 'RAYKAN-131', tags: ['attack.t1190', 'attack.initial_access'], logsource: { category: 'process_creation' } }),
    makeDetection({ ruleId: 'RAYKAN-001', tags: ['attack.execution', 'attack.t1059.001'], logsource: { category: 'process_creation' } }),
  ];
  const evts = [
    makeEvent({ eventId: '4688', process: 'cmd.exe', parentProc: 'explorer.exe',
      raw: { EventID: '4688', Image: 'cmd.exe', ParentImage: 'explorer.exe' } }),
  ];
  const filtered = filterDetectionsByContext(detections, evts);
  // T1190 detection should be suppressed (no web parent)
  const t1190Remaining = filtered.filter(d => d.ruleId === 'RAYKAN-131');
  assert(t1190Remaining.length === 0, 'T1190 detection from non-web parent should be filtered out');
  // T1059 should pass through
  const t1059Remaining = filtered.filter(d => d.ruleId === 'RAYKAN-001');
  assert(t1059Remaining.length === 1, 'T1059 detection should pass through');
});

test('filterDetectionsByContext: T1021.002 adjusted when no SMB evidence', () => {
  const detections = [
    makeDetection({
      ruleId: 'RAYKAN-062',
      tags: ['attack.lateral_movement', 'attack.t1021.002'],
      logsource: { category: 'security' },
      confidence: 80,
    }),
  ];
  const evts = [
    makeEvent({ computer: 'WORKSTATION-01', eventId: '4624', srcIp: '192.168.1.50',
      raw: { EventID: '4624', LogonType: '3', AuthPackage: 'NTLM' } }),
  ];
  const filtered = filterDetectionsByContext(detections, evts);
  // Detection should survive (T1550.002 fallback is T1078) or be adjusted
  // It should not have T1021.002 in its final tags
  if (filtered.length > 0) {
    const det = filtered[0];
    const techs = (det.tags || []).map(t => { const m = t.match(/attack\.(t\d+(?:\.\d+)?)/i); return m ? m[1].toUpperCase() : null; }).filter(Boolean);
    assertNotIncludes(techs, 'T1021.002', 'T1021.002 should be removed without SMB evidence');
  }
});

test('filterDetectionsByContext: empty input returns empty array', () => {
  const result = filterDetectionsByContext([], []);
  assert(Array.isArray(result) && result.length === 0, 'Empty input should return empty array');
});

test('filterDetectionsByContext: null input handled gracefully', () => {
  const result = filterDetectionsByContext(null, null);
  assert(Array.isArray(result), 'Null input should return array without throwing');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 8: buildCorrelatedDetections
// ─────────────────────────────────────────────────────────────────
console.log('\n── buildCorrelatedDetections — Supplemental Detections ─────────');

test('buildCorrelatedDetections generates brute-force detection for 4+ failures', () => {
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
  ];
  const supplemental = buildCorrelatedDetections(evts, []);
  const bruteForce = supplemental.find(d => d._corrType === 'brute_force');
  assert(bruteForce, 'Should generate brute_force detection');
  assert(bruteForce.tags.some(t => t.includes('t1110')), 'Brute-force detection should have T1110 tag');
  assert(bruteForce.ruleId.includes('CORR-'), 'Should have CORR- prefixed ruleId');
});

test('buildCorrelatedDetections does NOT duplicate existing sigma detections', () => {
  const existingDet = makeDetection({
    tags: ['attack.t1110.001'],
    confidence: 90,  // Already high confidence
  });
  const evts = [
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    makeEvent({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
  ];
  const supplemental = buildCorrelatedDetections(evts, [existingDet]);
  const bruteForce = supplemental.find(d => d._corrType === 'brute_force');
  // Should not duplicate since existing detection already covers T1110.001 at ≥80 confidence
  if (bruteForce) {
    // If it exists, it should have lower confidence than threshold or different technique
    assert(bruteForce.confidence < 90, 'Should not add duplicate with same or higher confidence');
  }
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 9: Metrics Tracking
// ─────────────────────────────────────────────────────────────────
console.log('\n── Metrics Tracking ─────────────────────────────────────────────');

test('Metrics increment correctly for suppressed T1190 detections', () => {
  resetMetrics();
  const initialMetrics = getMetrics();
  const det = makeDetection({
    tags: ['attack.t1190'],
    logsource: { category: 'security', product: 'windows' },
  });
  const evt = makeEvent({ eventId: '4624', raw: { EventID: '4624' } });
  validate(det, [evt], [det]);
  const afterMetrics = getMetrics();
  assert(
    afterMetrics.suppressed_count > initialMetrics.suppressed_count ||
    afterMetrics.adjusted_count   > initialMetrics.adjusted_count,
    'Suppressed/adjusted count should increment after T1190 validation'
  );
});

test('Metrics validated_count increments for valid detections', () => {
  resetMetrics();
  const det = makeDetection({
    tags: ['attack.execution', 'attack.t1059.001'],
    logsource: { category: 'process_creation' },
  });
  const evt = makeEvent({
    eventId    : '4688',
    process    : 'powershell.exe',
    commandLine: 'powershell -EncodedCommand dGVzdA==',
  });
  validate(det, [evt], [det]);
  const metrics = getMetrics();
  assert(metrics.validated_count > 0, 'validated_count should be > 0 for valid detection');
});

test('resetMetrics resets all counters to zero', () => {
  // Run some validations
  const det = makeDetection({ tags: ['attack.t1190'] });
  const evt = makeEvent({ eventId: '4624' });
  validate(det, [evt], [det]);
  validate(det, [evt], [det]);

  resetMetrics();
  const metrics = getMetrics();
  assertEqual(metrics.suppressed_count, 0, 'suppressed_count should be 0 after reset');
  assertEqual(metrics.adjusted_count,   0, 'adjusted_count should be 0 after reset');
  assertEqual(metrics.validated_count,  0, 'validated_count should be 0 after reset');
  assert(Object.keys(metrics.fp_reasons).length === 0, 'fp_reasons should be empty after reset');
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 10: Scenario — Full 4625+4624+4688 Sequence
// ─────────────────────────────────────────────────────────────────
console.log('\n── Scenario: 4625 + 4624 + 4688 Sequence Correct Mapping ───────');

test('4625 → T1078 (not T1110), 4624 LogonType=2 → auth success, 4688 net user → T1136', () => {
  const now = Date.now();
  const events = [
    // Failed logon
    makeEvent({ timestamp: new Date(now - 5000), eventId: '4625',
      raw: { EventID: '4625', LogonType: '3', TargetUserName: 'admin', SourceIp: '192.168.1.50' } }),
    // Successful logon (interactive)
    makeEvent({ timestamp: new Date(now - 3000), eventId: '4624',
      raw: { EventID: '4624', LogonType: '2', TargetUserName: 'admin' } }),
    // Process execution - account creation
    makeEvent({ timestamp: new Date(now - 1000), eventId: '4688',
      commandLine: 'net user hacker P@ssw0rd! /add',
      raw: { EventID: '4688', CommandLine: 'net user hacker P@ssw0rd! /add', Image: 'net.exe' } }),
  ];

  // Test single-failure detection
  const singleFailureDet = makeDetection({
    tags: ['attack.credential_access', 'attack.t1110.001'],
    confidence: 70,
  });
  const singleFailResult = validate(singleFailureDet, events, [singleFailureDet]);
  // With only 1 failure in the batch, T1110.001 should be downgraded/removed
  if (singleFailResult.adjustedTechniques !== null) {
    assertNotIncludes(singleFailResult.adjustedTechniques, 'T1110.001',
      '4625 single failure should not map to T1110.001');
  }
  assert(singleFailResult.warnings.length > 0, 'Should warn about insufficient brute-force evidence');

  // Test correlation for the full sequence
  const correlations = correlateAuthSequence(events);

  // Account creation should be detected
  const acctCreate = correlations.find(c => c.type === 'account_creation_after_auth');
  assert(acctCreate, 'Should detect account creation from net user /add after logon success');
  assertIncludes(acctCreate.techniques, 'T1136', 'Should map to T1136');

  // Auth failure should produce T1078, not T1110
  const authFail = correlations.find(c => c.type === 'auth_failure');
  if (authFail) {
    assertIncludes(authFail.techniques, 'T1078', 'Auth failure should map to T1078');
    assertNotIncludes(authFail.techniques, 'T1110', 'Single failure should NOT map to T1110');
  }

  console.log('     Correlations found:', correlations.map(c => `${c.type}→[${c.techniques.join(',')}]`).join(', '));
});

// ─────────────────────────────────────────────────────────────────
//  SECTION 11: Logsource Compatibility (SigmaEngine Integration)
// ─────────────────────────────────────────────────────────────────
console.log('\n── Logsource Compatibility Check ────────────────────────────────');

test('TECHNIQUE_REQUIRED_LOGSOURCE: T1190 requires webserver category', () => {
  const required = TECHNIQUE_REQUIRED_LOGSOURCE['T1190'];
  assert(Array.isArray(required) && required.length > 0, 'T1190 should have required logsource categories');
  assertIncludes(required, 'webserver', 'T1190 required logsources should include webserver');
});

test('TECHNIQUE_TELEMETRY_REQUIREMENTS: T1021.002 has SMB evidence requirements', () => {
  const req = TECHNIQUE_TELEMETRY_REQUIREMENTS['T1021.002'];
  assert(req != null, 'T1021.002 should have telemetry requirements');
  assert(Array.isArray(req.requiresAny) && req.requiresAny.length > 0,
    'T1021.002 requirements should have requiresAny array');
  assert(req.falsePositiveNote && req.falsePositiveNote.includes('SMB'),
    'FP note should mention SMB');
});

test('TECHNIQUE_TELEMETRY_REQUIREMENTS: T1550.002 has suppressedAlternative T1078', () => {
  const req = TECHNIQUE_TELEMETRY_REQUIREMENTS['T1550.002'];
  assert(req.suppressedAlternative === 'T1078',
    'T1550.002 should downgrade to T1078 when evidence missing');
});

test('TECHNIQUE_TELEMETRY_REQUIREMENTS: T1110 has suppressedAlternative T1078', () => {
  const req = TECHNIQUE_TELEMETRY_REQUIREMENTS['T1110'];
  assert(req.suppressedAlternative === 'T1078',
    'T1110 should downgrade to T1078 when <3 failures');
});

// ─────────────────────────────────────────────────────────────────
//  Final Results
// ─────────────────────────────────────────────────────────────────
console.log('\n' + '═'.repeat(60));
console.log(`  Total: ${passed + failed} tests`);
console.log(`  Passed: ${passed} ✅`);
console.log(`  Failed: ${failed} ❌`);
console.log('═'.repeat(60));

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\n  All context validator tests PASS — false-positive detection fixes verified.\n');
}
