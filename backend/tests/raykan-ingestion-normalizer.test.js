/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN Ingestion Normalizer — Validation Test Suite
 *  backend/tests/raykan-ingestion-normalizer.test.js
 *
 *  Tests cover:
 *   1. normalizeDetections — all input types
 *   2. parseSyslogLine    — RFC 3164, RFC 5424, bare text
 *   3. parseCEFLine       — valid CEF, malformed, non-CEF
 *   4. parseRawInput      — JSON array/object/string, syslog, CEF, mixed
 *   5. processEvent       — full pipeline with handleDetection callback
 *   6. Metrics            — counters increment correctly
 *
 *  Run: node backend/tests/raykan-ingestion-normalizer.test.js
 *  Exit: 0 = all pass, 1 = failures
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const {
  normalizeDetections,
  parseSyslogLine,
  parseCEFLine,
  parseRawInput,
  processEvent,
  metrics,
  resetMetrics,
} = require('../services/raykan/ingestion-normalizer');

// ── Minimal test harness (no external deps) ───────────────────────
let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, testName, detail) {
  if (condition) {
    passed++;
    process.stdout.write(`  ✅ PASS  ${testName}\n`);
  } else {
    failed++;
    const msg = detail ? `${testName} — ${detail}` : testName;
    failures.push(msg);
    process.stdout.write(`  ❌ FAIL  ${msg}\n`);
  }
}

function assertEqual(a, b, testName) {
  const ok = JSON.stringify(a) === JSON.stringify(b);
  if (!ok) {
    assert(false, testName, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
  } else {
    assert(true, testName);
  }
}

function section(name) {
  process.stdout.write(`\n━━━ ${name} ━━━\n`);
}

// ════════════════════════════════════════════════════════════════════
//  1. normalizeDetections
// ════════════════════════════════════════════════════════════════════
section('normalizeDetections');

resetMetrics();

// null / undefined
assert(Array.isArray(normalizeDetections(null)),      'null → []');
assert(normalizeDetections(null).length === 0,         'null → length 0');
assert(Array.isArray(normalizeDetections(undefined)),  'undefined → []');
assert(normalizeDetections(undefined).length === 0,    'undefined → length 0');

// plain array
const arr = [{ id: 1 }, { id: 2 }];
assertEqual(normalizeDetections(arr), arr,             'array pass-through');

// array with non-objects — should be filtered
const mixed = [{ id: 1 }, null, 'string', 42, { id: 2 }];
const filteredMixed = normalizeDetections(mixed);
assert(filteredMixed.length === 2,                     'array: non-objects filtered out');
assert(filteredMixed.every(x => typeof x === 'object'), 'array: only objects remain');

// old nested shape { count, items }
const nested = { count: 1, items: [{ id: 'a' }], critical: 1, high: 0, medium: 0 };
const fromNested = normalizeDetections(nested);
assert(Array.isArray(fromNested),                      'nested {items} → array');
assert(fromNested.length === 1 && fromNested[0].id === 'a', 'nested {items}: correct item');

// object with .detections key
const withDets = { detections: [{ id: 'b' }] };
const fromDets = normalizeDetections(withDets);
assert(fromDets.length === 1 && fromDets[0].id === 'b', 'object.detections → array');

// generic plain object (single detection wrapped) → [obj]
const plain = { id: 'c', severity: 'high' };
const fromPlain = normalizeDetections(plain);
assert(Array.isArray(fromPlain) && fromPlain.length === 1, 'plain object → [obj]');

// JSON string (array)
const jsonArr = JSON.stringify([{ id: 'x' }, { id: 'y' }]);
const fromJsonArr = normalizeDetections(jsonArr);
assert(Array.isArray(fromJsonArr) && fromJsonArr.length === 2, 'JSON string (array) → array');

// JSON string (object)
const jsonObj = JSON.stringify({ id: 'z', severity: 'low' });
const fromJsonObj = normalizeDetections(jsonObj);
assert(Array.isArray(fromJsonObj) && fromJsonObj.length === 1, 'JSON string (object) → [obj]');

// malformed JSON string → []
const malformed = 'not valid json { broken';
const fromMalformed = normalizeDetections(malformed);
assert(Array.isArray(fromMalformed) && fromMalformed.length === 0, 'malformed string → []');

// empty string → []
assert(normalizeDetections('').length === 0, 'empty string → []');

// number → []
assert(normalizeDetections(42).length === 0, 'number → []');

// boolean → []
assert(normalizeDetections(true).length === 0, 'boolean → []');

// empty array → []
assert(normalizeDetections([]).length === 0, 'empty array → []');

// metrics incremented for non-array
resetMetrics();
normalizeDetections({ id: 'x' }); // plain object → fallback
assert(metrics.normalization_fallback_count >= 1, 'metrics: fallback counted for plain object');

// ════════════════════════════════════════════════════════════════════
//  2. parseSyslogLine
// ════════════════════════════════════════════════════════════════════
section('parseSyslogLine');

// RFC 5424
const rfc5424Line = '<34>1 2024-04-22T10:00:00Z mymachine.example.com su - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...';
const r5 = parseSyslogLine(rfc5424Line);
assert(r5._format === 'syslog_rfc5424',      'RFC5424: correct _format');
assert(r5.facility === 4,                     'RFC5424: facility = 4 (34/8)');
assert(r5.severity_num === 2,                 'RFC5424: severity_num = 2 (34%8)');
assert(r5.hostname === 'mymachine.example.com', 'RFC5424: hostname parsed');
assert(r5.app_name === 'su',                  'RFC5424: app_name parsed');
assert(r5.raw === rfc5424Line,                'RFC5424: raw preserved');

// RFC 3164
const rfc3164Line = '<13>Apr 22 10:00:00 myhost kernel: Something happened';
const r3 = parseSyslogLine(rfc3164Line);
assert(r3._format === 'syslog_rfc3164',      'RFC3164: correct _format');
assert(r3.facility === 1,                     'RFC3164: facility = 1 (13/8)');
assert(r3.severity_num === 5,                 'RFC3164: severity_num = 5 (13%8)');
assert(r3.hostname === 'myhost',              'RFC3164: hostname parsed');
assert(r3.tag === 'kernel',                   'RFC3164: tag parsed');
assert(r3.message === 'Something happened',   'RFC3164: message parsed');

// RFC 5424 with dash fields
const dashLine = '<13>1 2024-04-22T10:00:00Z - - - - - Test message';
const rDash = parseSyslogLine(dashLine);
assert(rDash._format === 'syslog_rfc5424',    'RFC5424 dashes: correct _format');
assert(rDash.hostname === null,               'RFC5424 dashes: hostname is null');
assert(rDash.app_name === null,               'RFC5424 dashes: app_name is null');

// Syslog with embedded JSON in message
const embeddedJSON = '<134>1 2024-04-22T10:00:00Z host app - - - {"event":"login","user":"alice","status":"fail"}';
const rEmbed = parseSyslogLine(embeddedJSON);
assert(rEmbed._format === 'syslog_rfc5424',   'syslog+JSON: format remains syslog_rfc5424');
assert(rEmbed.event === 'login',               'syslog+JSON: embedded JSON field extracted');
assert(rEmbed.user === 'alice',                'syslog+JSON: user field extracted');

// Bare syslog (no PRI)
const bare = 'This is a plain log message';
const rBare = parseSyslogLine(bare);
assert(rBare._format === 'syslog_bare',       'bare syslog: correct _format');
assert(rBare.message === bare,                'bare syslog: message preserved');

// null / non-string
const rNull = parseSyslogLine(null);
assert(rNull._format === 'syslog_bare',       'null input: returns syslog_bare');

// ════════════════════════════════════════════════════════════════════
//  3. parseCEFLine
// ════════════════════════════════════════════════════════════════════
section('parseCEFLine');

// Valid CEF
const cefLine = 'CEF:0|SecurityVendor|IDS|1.0|1234|SQL Injection Attempt|7|src=192.168.1.100 dst=10.0.0.5 spt=52316 dpt=3306 msg=SQL injection detected';
const cef = parseCEFLine(cefLine);
assert(cef !== null,                                'CEF: parsed (not null)');
assert(cef._format === 'cef',                      'CEF: correct _format');
assert(cef.cef_version === '0',                    'CEF: version parsed');
assert(cef.device_vendor === 'SecurityVendor',     'CEF: device_vendor');
assert(cef.device_product === 'IDS',               'CEF: device_product');
assert(cef.signature_id === '1234',                'CEF: signature_id');
assert(cef.name === 'SQL Injection Attempt',       'CEF: name');
assert(cef.severity === '7',                       'CEF: severity');
assert(cef.src === '192.168.1.100',                'CEF: src from extensions.src');
assert(cef.dst === '10.0.0.5',                     'CEF: dst from extensions.dst');
assert(cef.srcPort === '52316',                    'CEF: srcPort from extensions.spt');
assert(cef.dstPort === '3306',                     'CEF: dstPort from extensions.dpt');
assert(cef.message === 'SQL injection detected',   'CEF: message from extensions.msg');
assert(cef.raw === cefLine,                        'CEF: raw preserved');

// CEF with no extensions
const cefNoExt = 'CEF:0|Vendor|Product|1.0|sig|Event Name|5|';
const cefN = parseCEFLine(cefNoExt);
assert(cefN !== null,                              'CEF no ext: parsed');
assert(cefN.device_vendor === 'Vendor',           'CEF no ext: vendor');
assert(cefN.extensions !== null,                   'CEF no ext: extensions object');

// CEF with escaped pipes in fields
const cefEsc = 'CEF:0|Vendor\\|Inc|Product|1.0|sig|My Event|3|';
const cefE = parseCEFLine(cefEsc);
assert(cefE !== null,                              'CEF escaped: parsed');
assert(cefE.device_vendor.includes('Vendor'),      'CEF escaped: vendor contains Vendor');

// Non-CEF input → null
assert(parseCEFLine('not CEF') === null,           'non-CEF string → null');
assert(parseCEFLine('') === null,                  'empty string → null');
assert(parseCEFLine(null) === null,                'null → null');
assert(parseCEFLine({ obj: 1 }) === null,          'object → null');

// Malformed CEF (starts with CEF: but wrong structure)
const cefMalform = 'CEF:only-one-field';
const cefMF = parseCEFLine(cefMalform);
// Should not throw, may return a partial or cef_malformed object
assert(cefMF !== null,                             'malformed CEF: no throw, returns object');

// ════════════════════════════════════════════════════════════════════
//  4. parseRawInput
// ════════════════════════════════════════════════════════════════════
section('parseRawInput');

// JSON array (most common case)
const jsonArrayStr = '[{"id":"a","severity":"high"},{"id":"b","severity":"low"}]';
const piJson = parseRawInput(jsonArrayStr);
assert(Array.isArray(piJson) && piJson.length === 2, 'parseRawInput: JSON array string');
assert(piJson[0].id === 'a',                         'parseRawInput: JSON array first item');

// JSON object (single event wrapped)
const jsonObjStr = '{"id":"c","type":"login"}';
const piObj = parseRawInput(jsonObjStr);
assert(Array.isArray(piObj) && piObj.length === 1,   'parseRawInput: JSON object string → [obj]');

// Already an array
const alreadyArr = [{ id: 1 }, { id: 2 }];
const piArr = parseRawInput(alreadyArr);
assert(piArr.length === 2,                           'parseRawInput: array pass-through');

// Plain object
const plainObj = { id: 'x', host: 'server1' };
const piPlain = parseRawInput(plainObj);
assert(piPlain.length === 1,                         'parseRawInput: plain object → [obj]');

// Multi-line Syslog
const syslogBlob = `<13>Apr 22 10:00:00 myhost kernel: Event 1
<14>Apr 22 10:00:01 myhost kernel: Event 2`;
const piSyslog = parseRawInput(syslogBlob, 'syslog');
assert(piSyslog.length === 2,                        'parseRawInput: syslog multiline → 2 events');
assert(piSyslog[0]._format === 'syslog_rfc3164',     'parseRawInput: syslog lines → rfc3164');

// Multi-line CEF
const cefBlob = `CEF:0|Vendor|Prod|1.0|1|Event1|5|src=1.1.1.1
CEF:0|Vendor|Prod|1.0|2|Event2|7|src=2.2.2.2`;
const piCef = parseRawInput(cefBlob, 'cef');
assert(piCef.length === 2,                           'parseRawInput: CEF multiline → 2 events');
assert(piCef[0]._format === 'cef',                   'parseRawInput: CEF lines → cef format');
assert(piCef[1].signature_id === '2',                'parseRawInput: CEF second event correct');

// Auto detection: mixed JSON lines
const jsonLines = `{"id":"j1","type":"process"}
{"id":"j2","type":"network"}`;
const piAutoJson = parseRawInput(jsonLines);
assert(piAutoJson.length === 2,                      'parseRawInput: auto JSON lines → 2 events');

// Auto detection: syslog lines (no JSON)
const syslogLines = '<13>Apr 22 10:00:00 host sshd: Failed password';
const piAutoSyslog = parseRawInput(syslogLines);
assert(piAutoSyslog.length === 1,                    'parseRawInput: auto syslog line → 1 event');
assert(piAutoSyslog[0]._format === 'syslog_rfc3164', 'parseRawInput: auto syslog → rfc3164');

// null → []
assert(parseRawInput(null).length === 0,             'parseRawInput: null → []');
assert(parseRawInput(undefined).length === 0,        'parseRawInput: undefined → []');
assert(parseRawInput('').length === 0,               'parseRawInput: empty string → []');

// JSON hint but invalid JSON → line-by-line fallback
const notJson = 'this is not json at all';
const piJsonHintFail = parseRawInput(notJson, 'json');
assert(Array.isArray(piJsonHintFail),                'parseRawInput: json hint + bad JSON → array (no crash)');

// ════════════════════════════════════════════════════════════════════
//  5. processEvent — unified pipeline
// ════════════════════════════════════════════════════════════════════
section('processEvent');

// JSON array with no detections on events
const events1 = [{ id: 1, type: 'process' }, { id: 2, type: 'network' }];
const r1 = processEvent(JSON.stringify(events1));
assert(!r1.error,                                    'processEvent: no error on valid JSON array');
assert(r1.events.length === 2,                       'processEvent: 2 events parsed');
assert(Array.isArray(r1.detections),                 'processEvent: detections is array');

// JSON object with detections as array
const withDetArray = { EventID: '1', detections: [{ id: 'det1', severity: 'high' }, { id: 'det2', severity: 'low' }] };
const r2 = processEvent(withDetArray);
assert(r2.detections.length === 2,                   'processEvent: detections from array');
assert(r2.detections[0].id === 'det1',               'processEvent: first detection preserved');
assert(r2.detections[0].severity === 'high',         'processEvent: severity preserved');

// JSON object with detections as nested object (old shape)
const withDetNested = {
  EventID: '2',
  detections: { count: 1, items: [{ id: 'det3', severity: 'critical' }] }
};
const rNested = processEvent(withDetNested);
assert(rNested.detections.length === 1,              'processEvent: detections from nested {items}');
assert(rNested.detections[0].id === 'det3',          'processEvent: nested detection id correct');

// JSON object with detections as string (JSON)
const withDetStr = {
  EventID: '3',
  detections: JSON.stringify([{ id: 'det4', severity: 'medium' }])
};
const rDetStr = processEvent(withDetStr);
assert(rDetStr.detections.length === 1,              'processEvent: detections from JSON string');
assert(rDetStr.detections[0].id === 'det4',          'processEvent: string detection id correct');

// null input → no crash
const rNull2 = processEvent(null);
assert(!rNull2.error,                                'processEvent: null → no crash');
assert(rNull2.events.length === 0,                   'processEvent: null → empty events');
assert(rNull2.detections.length === 0,               'processEvent: null → empty detections');

// undefined input → no crash
const rUndef = processEvent(undefined);
assert(!rUndef.error,                                'processEvent: undefined → no crash');

// Empty string → no crash
const rEmpty = processEvent('');
assert(!rEmpty.error,                                'processEvent: empty string → no crash');

// Syslog RFC 3164 line
const rSys = processEvent('<13>Apr 22 10:00:00 host sshd: Failed password for user root', { hint: 'syslog' });
assert(rSys.events.length === 1,                     'processEvent: syslog line → 1 event');
assert(rSys.events[0]._format === 'syslog_rfc3164', 'processEvent: syslog event has correct format');

// Valid CEF line
const rCEF = processEvent('CEF:0|Vendor|Product|1.0|100|Test Event|5|src=10.0.0.1 dst=10.0.0.2');
assert(rCEF.events.length === 1,                     'processEvent: CEF line → 1 event');
assert(rCEF.events[0]._format === 'cef',             'processEvent: CEF event format');
assert(rCEF.events[0].src === '10.0.0.1',            'processEvent: CEF src extracted');

// handleDetection callback is called for each detection
let callbackCount = 0;
const evtWithDets = { detections: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] };
processEvent(evtWithDets, {
  handleDetection: (det) => { callbackCount++; }
});
assert(callbackCount === 3,                          'processEvent: handleDetection called for each detection');

// handleDetection callback error is swallowed (no crash)
let cbError = null;
try {
  processEvent({ detections: [{ id: 'x' }] }, {
    handleDetection: () => { throw new Error('callback error'); }
  });
  cbError = null;
} catch (e) {
  cbError = e;
}
assert(cbError === null,                             'processEvent: handleDetection error swallowed');

// Malformed payload → no crash, returns gracefully
const rMalform = processEvent('not json { bad');
// Should not throw — may parse as syslog_bare
assert(!rMalform.error || typeof rMalform.error === 'string', 'processEvent: malformed → no uncaught throw');
assert(Array.isArray(rMalform.detections),           'processEvent: malformed → detections is array');

// ════════════════════════════════════════════════════════════════════
//  6. Metrics
// ════════════════════════════════════════════════════════════════════
section('Metrics');

resetMetrics();
assert(metrics.invalid_detection_format_count === 0,  'resetMetrics: invalid_count = 0');
assert(metrics.normalization_fallback_count === 0,     'resetMetrics: fallback_count = 0');
assert(metrics.parse_error_count === 0,               'resetMetrics: parse_error_count = 0');
assert(metrics.events_processed === 0,                'resetMetrics: events_processed = 0');

// normalizeDetections increments counters on fallback
normalizeDetections({ id: 'x' }); // plain obj → fallback
assert(metrics.normalization_fallback_count >= 1,     'metrics: fallback counted after object coercion');
assert(metrics.invalid_detection_format_count >= 1,   'metrics: invalid_count counted after object coercion');

// malformed string increments parse_error_count
normalizeDetections('not { valid json');
assert(metrics.parse_error_count >= 1,               'metrics: parse_error incremented on bad JSON string');

// processEvent increments events_processed
resetMetrics();
processEvent([{ id: 1 }, { id: 2 }]);
assert(metrics.events_processed === 2,               'metrics: events_processed = 2 after processEvent');

// ════════════════════════════════════════════════════════════════════
//  Summary
// ════════════════════════════════════════════════════════════════════
console.log('\n' + '═'.repeat(72));
console.log(`RAYKAN Ingestion Normalizer — Test Results`);
console.log('═'.repeat(72));
console.log(`  Total  : ${passed + failed}`);
console.log(`  Passed : ${passed}  ✅`);
console.log(`  Failed : ${failed}  ${failed > 0 ? '❌' : '✅'}`);
if (failures.length > 0) {
  console.log('\nFailed tests:');
  failures.forEach(f => console.log(`  • ${f}`));
}
console.log('═'.repeat(72));

process.exit(failed > 0 ? 1 : 0);
