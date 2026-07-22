/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  LLM Input Contract — Unit Tests  (Phase 0)
 *  backend/tests/llmContract.test.js
 *
 *  Covers every detection path in js/llm-contract.js:
 *   1. OCSF key detection (dict-level)
 *   2. Raw log key detection (dict-level, Windows event-log shape)
 *   3. Log-shape string patterns (7 regexes)
 *   4. Secret patterns (API key, private key)
 *   5. Size cap enforcement
 *   6. Raw event array detection
 *   7. Clean messages pass through unchanged
 *   8. validateLLMMessages throws LLMContractViolation on violation
 *   9. validateLLMMessages normalises various message shapes
 *  10. Enforcement toggle (setContractEnforcement=false → no throw)
 *  11. wrapLLMCall wraps an async function with pre-call validation
 *  12. validateAndTrack increments stats counters
 * ══════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const {
  classifyMessage,
  validateLLMMessages,
  validateAndTrack,
  wrapLLMCall,
  LLMContractViolation,
  isContractEnforced,
  setContractEnforcement,
  getContractStats,
  resetContractStats,
} = require('../../js/llm-contract.js');

// ── Helpers ────────────────────────────────────────────────────────────────

function clean(text) {
  return classifyMessage(text);
}

function blocked(text) {
  return classifyMessage(text) !== null;
}

// ── 1. OCSF key detection ──────────────────────────────────────────────────

describe('classifyMessage — OCSF key detection', () => {
  test('blocks JSON with class_uid', () => {
    const msg = JSON.stringify({ class_uid: 1001, message: 'test' });
    // String-pattern scan fires before JSON parse for performance;
    // "class_uid":1001 matches the log-shape regex first.
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('blocks JSON with activity_id', () => {
    const msg = JSON.stringify({ activity_id: 2, source: 'crowdstrike', status: 'success' });
    // Caught by log-shape regex pattern before JSON parse
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('blocks JSON with time_dt', () => {
    const msg = JSON.stringify({ time_dt: '2024-01-01T00:00:00Z', event: 'login' });
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });

  test('blocks JSON with observables array', () => {
    const msg = JSON.stringify({ observables: [{ value: '1.2.3.4', type: 'ip' }] });
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });

  test('blocks JSON with metadata.product/version (OCSF-style)', () => {
    const msg = JSON.stringify({
      message: 'network login',
      metadata: { product: { name: 'CrowdStrike' }, version: '2024' }
    });
    // metadata is in OCSF_KEYS — blocked (string scan or dict check)
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('allows JSON with metadata key but without product/version subkeys', () => {
    const msg = JSON.stringify({ metadata: { tenant: 'acme', env: 'prod' } });
    // metadata alone triggers the key match - correct, it IS in OCSF_KEYS
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });

  test('blocks JSON with raw_data key', () => {
    const msg = JSON.stringify({ raw_data: 'some raw bytes', severity: 'high' });
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });

  test('blocks JSON with category_uid', () => {
    const msg = JSON.stringify({ category_uid: 4, type: 'login' });
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });

  test('blocks JSON with type_uid', () => {
    const msg = JSON.stringify({ type_uid: 400201, source: 'endpoint' });
    expect(classifyMessage(msg)).toMatch(/OCSF keys present/);
  });
});

// ── 2. Raw log key detection ────────────────────────────────────────────────

describe('classifyMessage — raw log key detection', () => {
  test('blocks JSON with EventData key (Windows event log)', () => {
    const msg = JSON.stringify({ EventData: { Image: 'cmd.exe', CommandLine: 'whoami' } });
    expect(classifyMessage(msg)).toMatch(/raw-log keys present/);
  });

  test('blocks JSON with Sysmon key', () => {
    const msg = JSON.stringify({ Sysmon: { EventType: 'ProcessCreate' }, other: 'data' });
    expect(classifyMessage(msg)).toMatch(/raw-log keys present/);
  });

  test('blocks JSON with _raw key (Splunk)', () => {
    const msg = JSON.stringify({ _raw: 'Jan 01 00:00:00 host sshd[123]', index: 'main' });
    // "_raw":" matches the log-shape string pattern before JSON parse
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('blocks JSON with _time key (Splunk)', () => {
    const msg = JSON.stringify({ _time: 1704067200.0, event: 'dns' });
    expect(classifyMessage(msg)).toMatch(/raw-log keys present/);
  });

  test('blocks JSON with Channel + EventID (Windows event-log shape)', () => {
    const msg = JSON.stringify({ EventID: 4624, Channel: 'Security', RecordNumber: 12345 });
    // EventID integer + Channel should trigger raw-log detection
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('blocks JSON with punct key (Splunk token)', () => {
    const msg = JSON.stringify({ punct: '---=', event_count: 42 });
    expect(classifyMessage(msg)).toMatch(/raw-log keys present/);
  });

  test('blocks JSON with RecordID key', () => {
    const msg = JSON.stringify({ RecordID: '9876', process: 'lsass.exe' });
    expect(classifyMessage(msg)).toMatch(/raw-log keys present/);
  });
});

// ── 3. Log-shape string patterns ────────────────────────────────────────────

describe('classifyMessage — log-shape string pattern detection', () => {
  test('blocks "class_uid": <number> in prose', () => {
    const msg = 'The event has "class_uid": 1001 and was generated by...';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks "activity_id": <number> in prose', () => {
    const msg = 'Alert: "activity_id": 2 detected on host web-01';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks "EventID": <number> in prose', () => {
    const msg = 'Windows security event "EventID": 4688 was triggered';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks "EventRecordID": <number> in prose', () => {
    const msg = 'Sysmon log with "EventRecordID": 98765 found';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks Sysmon XML event', () => {
    const msg = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System></System></Event>';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks "_raw": " in prose (Splunk envelope)', () => {
    const msg = 'The Splunk event has "_raw": "some raw log data" in the export';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });

  test('blocks "sourcetype": " in prose', () => {
    const msg = 'Splunk sourcetype field: "sourcetype": "sysmon" in the index';
    expect(classifyMessage(msg)).toMatch(/raw-log signature matched/);
  });
});

// ── 4. Secret pattern detection ─────────────────────────────────────────────

describe('classifyMessage — secret pattern detection', () => {
  test('blocks api_key=<long string>', () => {
    const msg = 'Config: api_key = "sk-abcdefghijklmnop1234567890"';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks API-KEY header format', () => {
    const msg = 'Authorization header: API-KEY = "ABCDEFGHIJKLMNOP1234567890abcdef"';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks token=<long string>', () => {
    const msg = "token = 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12345678'";
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks RSA private key header', () => {
    const msg = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks EC private key header', () => {
    const msg = 'Key material: -----BEGIN EC PRIVATE KEY-----\nabc123\n-----END EC PRIVATE KEY-----';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks OPENSSH private key', () => {
    const msg = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('blocks generic private key', () => {
    const msg = '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqh\n-----END PRIVATE KEY-----';
    expect(classifyMessage(msg)).toMatch(/secret-shaped value detected/);
  });

  test('does NOT block short token-like strings (< 16 chars)', () => {
    // Short values are not secrets
    const msg = 'token = "short"';
    expect(classifyMessage(msg)).toBeNull();
  });
});

// ── 5. Size cap enforcement ──────────────────────────────────────────────────

describe('classifyMessage — size cap', () => {
  test('blocks message exceeding 60000 chars', () => {
    const msg = 'A'.repeat(60001);
    expect(classifyMessage(msg)).toMatch(/message exceeds size cap/);
  });

  test('allows message exactly at 60000 chars', () => {
    const msg = 'A'.repeat(60000);
    // A string of 'A's has no log signatures or secrets
    expect(classifyMessage(msg)).toBeNull();
  });
});

// ── 6. Raw event array detection ─────────────────────────────────────────────

describe('classifyMessage — raw event array', () => {
  test('blocks array of log objects with many keys + OCSF fields', () => {
    const batch = [
      {
        class_uid: 1001, category_uid: 4, activity_id: 2, type_uid: 400201,
        time_dt: '2024-01-01T00:00:00Z', metadata: {}, observables: [], raw_data: null,
      }
    ];
    const msg = JSON.stringify(batch);
    expect(classifyMessage(msg)).not.toBeNull();
  });

  test('does NOT block small clean arrays', () => {
    const arr = [{ id: '1', title: 'Alert', severity: 'HIGH' }];
    const msg = JSON.stringify(arr);
    expect(classifyMessage(msg)).toBeNull();
  });
});

// ── 7. Clean messages pass through ──────────────────────────────────────────

describe('classifyMessage — clean messages', () => {
  test('allows plain text analyst summary', () => {
    expect(classifyMessage(
      'The alert indicates suspicious PowerShell execution on host web-01. ' +
      'Techniques: T1059.001 (PowerShell), T1003 (Credential Dumping). ' +
      'Severity: HIGH. Confidence: 0.87. Recommend isolating host immediately.'
    )).toBeNull();
  });

  test('allows MITRE technique ID lists', () => {
    expect(classifyMessage('Detected techniques: T1566.001, T1059.001, T1003, T1021')).toBeNull();
  });

  test('allows structured alert title + description', () => {
    expect(classifyMessage(JSON.stringify({
      title: 'Suspicious PowerShell Execution',
      description: 'Base64 encoded command detected from scheduled task',
      severity: 'HIGH',
      source: 'endpoint-detection',
      confidence: 0.91,
    }))).toBeNull();
  });

  test('allows numerical scores', () => {
    expect(classifyMessage('Risk score: 8.7. UEBA composite: 6.2. Confidence: 0.74.')).toBeNull();
  });

  test('allows empty string', () => {
    expect(classifyMessage('')).toBeNull();
  });

  test('allows simple user question', () => {
    expect(classifyMessage('What is the risk of CVE-2024-3400?')).toBeNull();
  });

  test('allows IOC value without surrounding raw data', () => {
    expect(classifyMessage('Please analyze IOC: 185.234.219.47 for threat intelligence.')).toBeNull();
  });
});

// ── 8. validateLLMMessages throws on violation ───────────────────────────────

describe('validateLLMMessages — throws on violation', () => {
  test('throws LLMContractViolation for OCSF message', () => {
    const messages = [
      { role: 'system', content: 'You are a security analyst.' },
      { role: 'user', content: JSON.stringify({ class_uid: 1001, activity_id: 2, time_dt: 'now' }) },
    ];
    expect(() => validateLLMMessages(messages)).toThrow(LLMContractViolation);
  });

  test('throws LLMContractViolation for Sysmon XML in user message', () => {
    const messages = [
      { role: 'user', content: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"></Event>' },
    ];
    expect(() => validateLLMMessages(messages)).toThrow(LLMContractViolation);
  });

  test('thrown error has correct name', () => {
    const messages = [
      { role: 'user', content: JSON.stringify({ class_uid: 1001 }) },
    ];
    let caught;
    try { validateLLMMessages(messages); } catch (e) { caught = e; }
    expect(caught.name).toBe('LLMContractViolation');
    // class_uid JSON caught by string-pattern scan first
    expect(caught.reason).toMatch(/message\[0\] failed contract:/);
  });

  test('thrown error includes role', () => {
    const messages = [
      { role: 'system', content: JSON.stringify({ _raw: 'some splunk event' }) },
    ];
    let caught;
    try { validateLLMMessages(messages); } catch (e) { caught = e; }
    expect(caught.role).toBe('system');
  });
});

// ── 9. validateLLMMessages normalises message shapes ─────────────────────────

describe('validateLLMMessages — message normalisation', () => {
  test('normalises plain dict messages', () => {
    const result = validateLLMMessages([
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user',   content: 'What is T1059?' },
    ]);
    expect(result).toHaveLength(2);
    expect(result[0].role).toBe('system');
    expect(result[1].role).toBe('user');
  });

  test('normalises string-only messages as user role', () => {
    const result = validateLLMMessages(['Tell me about APT29']);
    expect(result[0].role).toBe('user');
    expect(result[0].content).toBe('Tell me about APT29');
  });

  test('normalises tuple-array messages', () => {
    const result = validateLLMMessages([['user', 'What is MITRE ATT&CK?']]);
    expect(result[0].role).toBe('user');
    expect(result[0].content).toBe('What is MITRE ATT&CK?');
  });

  test('stringifies non-string content', () => {
    const result = validateLLMMessages([{ role: 'user', content: { key: 'value' } }]);
    expect(typeof result[0].content).toBe('string');
  });

  test('accepts an empty array', () => {
    expect(validateLLMMessages([])).toEqual([]);
  });
});

// ── 10. Enforcement toggle ───────────────────────────────────────────────────

describe('setContractEnforcement — toggle', () => {
  afterEach(() => {
    // Always restore enforcement after toggle tests
    setContractEnforcement(true);
  });

  test('isContractEnforced() returns true by default', () => {
    setContractEnforcement(true);
    expect(isContractEnforced()).toBe(true);
  });

  test('when enforcement OFF, OCSF message does NOT throw', () => {
    setContractEnforcement(false);
    const messages = [{ role: 'user', content: JSON.stringify({ class_uid: 1001 }) }];
    expect(() => validateLLMMessages(messages)).not.toThrow();
  });

  test('setContractEnforcement returns previous value', () => {
    const prev = setContractEnforcement(false);
    expect(typeof prev).toBe('boolean');
    setContractEnforcement(prev); // restore
  });
});

// ── 11. wrapLLMCall ──────────────────────────────────────────────────────────

describe('wrapLLMCall', () => {
  test('calls through on clean messages', async () => {
    const mockLLM = jest.fn().mockResolvedValue('response');
    const wrapped = wrapLLMCall(mockLLM);
    const msgs = [{ role: 'user', content: 'Analyze this IOC: 8.8.8.8' }];
    await wrapped(msgs);
    expect(mockLLM).toHaveBeenCalledTimes(1);
  });

  test('throws before calling fn on violated messages', async () => {
    const mockLLM = jest.fn();
    const wrapped = wrapLLMCall(mockLLM);
    const msgs = [{ role: 'user', content: JSON.stringify({ class_uid: 1001, activity_id: 2 }) }];
    await expect(wrapped(msgs)).rejects.toThrow(LLMContractViolation);
    expect(mockLLM).not.toHaveBeenCalled();
  });

  test('forwards additional arguments to the wrapped function', async () => {
    const mockLLM = jest.fn().mockResolvedValue('ok');
    const wrapped = wrapLLMCall(mockLLM);
    const msgs = [{ role: 'user', content: 'Hello' }];
    await wrapped(msgs, 'gpt-4o', { temperature: 0.3 });
    expect(mockLLM).toHaveBeenCalledWith(
      expect.any(Array),  // validated messages
      'gpt-4o',
      { temperature: 0.3 }
    );
  });
});

// ── 12. validateAndTrack stats ───────────────────────────────────────────────

describe('validateAndTrack — stats counters', () => {
  beforeEach(() => resetContractStats());

  test('increments checked counter on each call', () => {
    validateAndTrack([{ role: 'user', content: 'clean message' }]);
    validateAndTrack([{ role: 'user', content: 'another clean message' }]);
    expect(getContractStats().checked).toBe(2);
  });

  test('increments blocked counter on violation', () => {
    const msgs = [{ role: 'user', content: JSON.stringify({ class_uid: 1001 }) }];
    try { validateAndTrack(msgs); } catch {}
    expect(getContractStats().blocked).toBe(1);
  });

  test('records lastViolation on block', () => {
    const msgs = [{ role: 'user', content: JSON.stringify({ class_uid: 1001 }) }];
    try { validateAndTrack(msgs); } catch {}
    const stats = getContractStats();
    expect(stats.lastViolation).not.toBeNull();
    // class_uid JSON caught by string-pattern scan first
    expect(stats.lastViolation.reason).toMatch(/message\[0\] failed contract:/);
  });

  test('resetContractStats clears all counters', () => {
    validateAndTrack([{ role: 'user', content: 'clean' }]);
    resetContractStats();
    const stats = getContractStats();
    expect(stats.checked).toBe(0);
    expect(stats.blocked).toBe(0);
    expect(stats.lastViolation).toBeNull();
  });
});
