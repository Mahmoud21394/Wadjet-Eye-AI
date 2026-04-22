/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN Ingestion Normalizer v1.0
 *  Wadjet-Eye AI Platform
 *
 *  Provides a robust, schema-tolerant ingestion + normalization layer
 *  that handles ALL input types without throwing at runtime.
 *
 *  Key guarantees:
 *   1. normalizeDetections(x) — NEVER throws; always returns Array<Object>
 *      regardless of x being array, object, string (JSON), null, undefined.
 *   2. parseSyslogLine(line)   — RFC 3164 and RFC 5424 → structured event
 *   3. parseCEFLine(line)      — ArcSight CEF header + extensions → event
 *   4. parseRawInput(raw)      — Unified multi-format dispatcher
 *   5. processEvent(raw)       — Full pipeline: parse → normalize → handle
 *
 *  Observability:
 *   • console.warn on every non-array coercion
 *   • Exported metrics object (live counters, reset-able)
 *     - invalid_detection_format_count
 *     - normalization_fallback_count
 *     - parse_error_count
 *     - events_processed
 *
 *  Constraints:
 *   • No breaking changes to existing detection pipeline
 *   • Pure Node.js (no external deps)
 *   • Safe for both CommonJS require() and ES module import
 *
 *  backend/services/raykan/ingestion-normalizer.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ════════════════════════════════════════════════════════════════════
//  Live metrics — exported for monitoring / health-check endpoints
// ════════════════════════════════════════════════════════════════════
const metrics = {
  invalid_detection_format_count : 0,
  normalization_fallback_count   : 0,
  parse_error_count              : 0,
  events_processed               : 0,
};

/** Reset all counters — useful between test runs or per-session resets */
function resetMetrics() {
  metrics.invalid_detection_format_count = 0;
  metrics.normalization_fallback_count   = 0;
  metrics.parse_error_count              = 0;
  metrics.events_processed              = 0;
}

// ════════════════════════════════════════════════════════════════════
//  normalizeDetections — type-safe coercion to Array<Object>
//
//  Handles:
//    • null / undefined          → []
//    • Array<Object>             → input (pass-through, validated)
//    • plain Object              → tries .items, .detections, Object.values()
//    • JSON string               → recursive call on parsed value
//    • any other scalar          → []
//    • Array with non-objects    → filtered to objects only (no crash)
//
//  @param {*}      input   — any value (detections field from API response)
//  @param {string} label   — context label for log warnings (default 'detections')
//  @returns {Array<Object>}
// ════════════════════════════════════════════════════════════════════
function normalizeDetections(input, label) {
  label = label || 'detections';

  // Fast path: null / undefined → empty array
  if (input == null) return [];

  // Fast path: already a proper array
  if (Array.isArray(input)) {
    // Filter out non-object entries to ensure safe property access downstream
    const safe = input.filter(item => item != null && typeof item === 'object');
    if (safe.length !== input.length) {
      const skipped = input.length - safe.length;
      metrics.invalid_detection_format_count++;
      console.warn(`[RAYKAN][normalizeDetections] ${label}: skipped ${skipped} non-object entries`);
    }
    return safe;
  }

  // Non-array — coercion required
  metrics.normalization_fallback_count++;
  metrics.invalid_detection_format_count++;
  console.warn(`[RAYKAN][normalizeDetections] ${label}: received ${typeof input} instead of array — coercing`);

  if (typeof input === 'object') {
    // Legacy nested shape: { count, items, critical, high, medium }
    if (Array.isArray(input.items))      return normalizeDetections(input.items, label);
    if (Array.isArray(input.detections)) return normalizeDetections(input.detections, label);
    if (Array.isArray(input.results))    return normalizeDetections(input.results, label);
    // Generic plain object — wrap in array
    return [input];
  }

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return [];
    try {
      const parsed = JSON.parse(trimmed);
      return normalizeDetections(parsed, label);
    } catch {
      metrics.parse_error_count++;
      console.warn(`[RAYKAN][normalizeDetections] ${label}: string is not valid JSON → []`);
      return [];
    }
  }

  // Boolean, number, symbol, function — not iterable
  return [];
}

// ════════════════════════════════════════════════════════════════════
//  parseSyslogLine — RFC 3164 / RFC 5424
//
//  RFC 5424 format:
//    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//
//  RFC 3164 format:
//    <PRI>TIMESTAMP HOSTNAME TAG: MSG
//
//  Returns a flat structured event object. Never throws.
//  @param {string} line
//  @returns {Object}
// ════════════════════════════════════════════════════════════════════
function parseSyslogLine(line) {
  if (!line || typeof line !== 'string') {
    return { _format: 'syslog_bare', raw: line, message: String(line || '') };
  }

  // RFC 5424: <PRI>VERSION TS HOST APP PROCID MSGID [SD] MSG
  const rfc5424Re = /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)\s*(.*)$/;
  const m5 = line.match(rfc5424Re);
  if (m5) {
    const pri = parseInt(m5[1], 10);
    const evt = {
      _format         : 'syslog_rfc5424',
      priority        : pri,
      facility        : Math.floor(pri / 8),
      severity_num    : pri % 8,
      syslog_version  : parseInt(m5[2], 10),
      timestamp       : m5[3],
      hostname        : m5[4] !== '-' ? m5[4] : null,
      app_name        : m5[5] !== '-' ? m5[5] : null,
      proc_id         : m5[6] !== '-' ? m5[6] : null,
      msg_id          : m5[7] !== '-' ? m5[7] : null,
      structured_data : m5[8] !== '-' ? m5[8] : null,
      message         : m5[9] || '',
      raw             : line,
    };
    // Attempt to parse embedded JSON in the message body
    const embedded = _tryParseJSON(evt.message);
    if (embedded) Object.assign(evt, embedded, { _format: 'syslog_rfc5424', raw: line });
    return evt;
  }

  // RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
  const rfc3164Re = /^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)$/;
  const m3 = line.match(rfc3164Re);
  if (m3) {
    const pri = parseInt(m3[1], 10);
    const evt = {
      _format      : 'syslog_rfc3164',
      priority     : pri,
      facility     : Math.floor(pri / 8),
      severity_num : pri % 8,
      timestamp    : m3[2],
      hostname     : m3[3],
      tag          : m3[4],
      message      : m3[5] || '',
      raw          : line,
    };
    const embedded = _tryParseJSON(evt.message);
    if (embedded) Object.assign(evt, embedded, { _format: 'syslog_rfc3164', raw: line });
    return evt;
  }

  // Bare syslog / plain text — still surfaced as an event with type syslog_event
  return {
    _format : 'syslog_bare',
    type    : 'syslog_event',
    message : line,
    raw     : line,
  };
}

// ════════════════════════════════════════════════════════════════════
//  parseCEFLine — ArcSight Common Event Format (CEF:0 spec)
//
//  Format:
//    CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|[Extensions]
//
//  Extensions: space-separated key=value pairs (backslash-escaped = and |)
//
//  Returns null for non-CEF input; never throws.
//  @param {string} line
//  @returns {Object|null}
// ════════════════════════════════════════════════════════════════════
function parseCEFLine(line) {
  if (!line || typeof line !== 'string') return null;
  const trimmed = line.trim();
  if (!trimmed.startsWith('CEF:')) return null;

  try {
    // Locate the 7th pipe (marks start of extension block)
    // Must not count escaped pipes (\|)
    let pipes = 0;
    let headerEnd = -1;
    for (let i = 0; i < trimmed.length; i++) {
      if (trimmed[i] === '|' && (i === 0 || trimmed[i - 1] !== '\\')) pipes++;
      if (pipes === 7) { headerEnd = i; break; }
    }

    const headerStr = headerEnd > 0 ? trimmed.slice(0, headerEnd) : trimmed;
    const extStr    = headerEnd > 0 ? trimmed.slice(headerEnd + 1).trim() : '';

    // Split header on unescaped |
    const parts = headerStr.split(/(?<!\\)\|/);
    const unescape = s => (s || '').replace(/\\\|/g, '|').replace(/\\\\/g, '\\');

    // Parse extension key=value pairs
    // Pattern: word= ... next_word= or EOL
    const ext = {};
    if (extStr) {
      const extRe = /(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)/g;
      let match;
      while ((match = extRe.exec(extStr)) !== null) {
        const key = match[1].trim();
        const val = match[2].replace(/\\=/g, '=').replace(/\\\\/g, '\\').trim();
        ext[key] = val;
      }
    }

    // Map common CEF extension field aliases to canonical names
    const canonicalize = (obj) => ({
      src      : obj.src  || obj.sourceAddress       || null,
      dst      : obj.dst  || obj.destinationAddress  || null,
      srcPort  : obj.spt  || obj.sourcePort          || null,
      dstPort  : obj.dpt  || obj.destinationPort     || null,
      user     : obj.suser || obj.duser              || null,
      fileName : obj.fname || obj.filePath           || null,
      fileHash : obj.fileHash || obj.cs5             || null,
      message  : obj.msg  || obj.reason              || null,
    });

    const cef = {
      _format        : 'cef',
      cef_version    : unescape(parts[0] || 'CEF:0').replace(/^CEF:/i, ''),
      device_vendor  : unescape(parts[1] || ''),
      device_product : unescape(parts[2] || ''),
      device_version : unescape(parts[3] || ''),
      signature_id   : unescape(parts[4] || ''),
      name           : unescape(parts[5] || ''),
      severity       : unescape(parts[6] || ''),
      extensions     : ext,
      raw            : line,
    };

    // Merge canonical fields at top level for engine normalizer compatibility
    const canonical = canonicalize(ext);
    Object.assign(cef, canonical);

    return cef;
  } catch (err) {
    metrics.parse_error_count++;
    console.warn(`[RAYKAN][parseCEFLine] parse error: ${err.message}`);
    return { _format: 'cef_malformed', raw: line };
  }
}

// ════════════════════════════════════════════════════════════════════
//  parseRawInput — unified multi-format dispatcher
//
//  Accepts any of:
//    • Array<Object>    — pass-through (already structured)
//    • plain Object     — wrap in [obj]
//    • JSON string      — parse to array or object
//    • multi-line text  — split and dispatch each line by format
//    • null / undefined → []
//
//  @param {*}      raw    — input blob
//  @param {string} hint   — 'json' | 'syslog' | 'cef' | 'auto' (default)
//  @returns {Array<Object>}
// ════════════════════════════════════════════════════════════════════
function parseRawInput(raw, hint) {
  hint = (hint || 'auto').toLowerCase();

  if (raw == null) return [];

  // Already an array of events
  if (Array.isArray(raw)) {
    return raw.map((item, i) => _coerceToEvent(item, `item[${i}]`));
  }

  // Plain object
  if (typeof raw === 'object') {
    return [_coerceToEvent(raw, 'object')];
  }

  if (typeof raw !== 'string') return [];

  const trimmed = raw.trim();
  if (!trimmed) return [];

  // ── JSON mode (or auto — try JSON first) ──────────────────────
  if (hint !== 'syslog' && hint !== 'cef') {
    const jsonResult = _tryParseJSON(trimmed);
    if (jsonResult !== null) {
      if (Array.isArray(jsonResult)) {
        return jsonResult.map((item, i) => _coerceToEvent(item, `json[${i}]`));
      }
      return [_coerceToEvent(jsonResult, 'json_object')];
    }
    // JSON hint but not parseable — fall through to line-by-line
    if (hint === 'json') {
      metrics.parse_error_count++;
      console.warn('[RAYKAN][parseRawInput] hint=json but input is not valid JSON; falling back to line-by-line');
    }
  }

  // ── Line-by-line multi-format parsing ─────────────────────────
  return trimmed
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean)
    .map(line => _parseRawLine(line, hint));
}

// ════════════════════════════════════════════════════════════════════
//  processEvent — Unified pipeline entry point
//
//  Accepts a raw event in ANY format (JSON object, Syslog string,
//  CEF string, JSON string, or blob) and returns normalized result:
//    {
//      events     : Array<Object>,   // parsed & normalized events
//      detections : Array<Object>,   // safe for iteration (may be empty)
//      format     : string,          // detected format
//      error      : string | null,   // parse error message if any
//    }
//
//  Uses handleDetection callback for each detection (safe iteration).
//
//  @param {*}        raw             — any input
//  @param {Object}   opts
//  @param {string}   opts.hint       — format hint (default 'auto')
//  @param {Function} opts.handleDetection — callback(det) for each detection
//  @returns {Object}
// ════════════════════════════════════════════════════════════════════
function processEvent(raw, opts) {
  opts = opts || {};
  const hint            = opts.hint || 'auto';
  const handleDetection = typeof opts.handleDetection === 'function'
    ? opts.handleDetection
    : null;

  let events = [];
  let detections = [];
  let detectedFormat = 'unknown';
  let parseErr = null;

  try {
    events = parseRawInput(raw, hint);
    metrics.events_processed += events.length;

    if (events.length > 0) {
      detectedFormat = events[0]._format || 'json';
    }

    // ── Safe detection extraction ─────────────────────────────
    // r.detections may be: array, object, string, null, undefined
    // normalizeDetections guarantees an iterable array regardless
    for (const evt of events) {
      if (!evt || typeof evt !== 'object') continue;

      const rawDets = normalizeDetections(evt.detections, `processEvent.${detectedFormat}`);

      for (const det of rawDets) {
        if (!det || typeof det !== 'object') continue;

        // Ensure each detection has required shape fields
        const normalized = _normalizeDetectionObject(det, evt);
        detections.push(normalized);

        // Call handler if provided (safe — wrapped in try/catch)
        if (handleDetection) {
          try {
            handleDetection(normalized);
          } catch (handlerErr) {
            console.warn(`[RAYKAN][processEvent] handleDetection threw: ${handlerErr.message}`);
          }
        }
      }
    }
  } catch (err) {
    parseErr = err.message;
    metrics.parse_error_count++;
    console.error(`[RAYKAN][processEvent] pipeline error: ${err.message}`, err.stack || '');
  }

  return {
    events,
    detections,
    format : detectedFormat,
    error  : parseErr,
  };
}

// ════════════════════════════════════════════════════════════════════
//  Private helpers
// ════════════════════════════════════════════════════════════════════

/** Attempt JSON.parse; return parsed value or null on failure */
function _tryParseJSON(str) {
  if (typeof str !== 'string' || !str.trim()) return null;
  try { return JSON.parse(str); } catch { return null; }
}

/** Dispatch a single text line to the correct format parser */
function _parseRawLine(line, hint) {
  // CEF
  if (hint === 'cef' || line.startsWith('CEF:')) {
    return parseCEFLine(line) || { _format: 'cef_malformed', raw: line };
  }

  // Syslog (starts with <PRI>)
  if (hint === 'syslog' || /^<\d{1,3}>/.test(line)) {
    return parseSyslogLine(line);
  }

  // Auto: try JSON, then syslog
  const asJSON = _tryParseJSON(line);
  if (asJSON !== null && typeof asJSON === 'object') {
    return { ...asJSON, _format: asJSON._format || 'json', raw: line };
  }

  return parseSyslogLine(line);
}

/** Coerce an item to a plain event object; wrap primitives */
function _coerceToEvent(item, label) {
  if (item == null) {
    metrics.invalid_detection_format_count++;
    return { _format: 'null_event', raw: null };
  }
  if (typeof item === 'object') return item;

  // Primitive wrapped in object
  metrics.normalization_fallback_count++;
  console.warn(`[RAYKAN][parseRawInput] ${label}: primitive (${typeof item}) wrapped as event`);
  return { _format: 'raw_primitive', value: item, raw: item };
}

/**
 * Ensure a detection object has the minimum required fields.
 * Fills in defaults to prevent downstream crashes on property access.
 */
function _normalizeDetectionObject(det, parentEvent) {
  return {
    id          : det.id          || det.ruleId || null,
    type        : det.type        || (parentEvent && parentEvent._format) || 'unknown',
    severity    : det.severity    || 'informational',
    title       : det.title       || det.name   || det.ruleName || 'Detection',
    raw         : det.raw         || (parentEvent && parentEvent.raw) || null,
    timestamp   : det.timestamp   || (parentEvent && parentEvent.timestamp) || new Date().toISOString(),
    riskScore   : typeof det.riskScore === 'number' ? det.riskScore : 0,
    confidence  : typeof det.confidence === 'number' ? det.confidence : 50,
    mitre       : det.mitre       || null,
    tags        : Array.isArray(det.tags) ? det.tags : [],
    ...det,       // preserve all original fields (last — overrides defaults)
  };
}

// ════════════════════════════════════════════════════════════════════
//  Exports
// ════════════════════════════════════════════════════════════════════
module.exports = {
  // Core normalizer (primary fix for TypeError)
  normalizeDetections,

  // Format parsers
  parseSyslogLine,
  parseCEFLine,
  parseRawInput,

  // Unified pipeline
  processEvent,

  // Observability
  metrics,
  resetMetrics,
};
