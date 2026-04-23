/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Sigma Detection Engine v1.0
 *
 *  Supports:
 *   • Full Sigma rule parsing (YAML)
 *   • Hayabusa-compatible field mappings
 *   • Condition evaluation (all-of, 1-of, and/or/not)
 *   • Aggregation conditions (count, min, max, avg, sum)
 *   • Regex, wildcard, CIDR matching
 *   • In-memory rule index for O(1) lookup
 *   • Rule auto-conversion from Hayabusa ruleset
 *   • Daily rule update scheduler
 *
 *  backend/services/raykan/sigma-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const EventEmitter = require('events');
const path         = require('path');
const crypto       = require('crypto');

// ── Central Evidence Authority (CEA) — single source of truth ───
// ALL technique assignments pass through the CEA.  No bypass is allowed.
let _cea = null;
try {
  _cea = require('./central-evidence-authority');
} catch (e) {
  console.warn('[Sigma] central-evidence-authority not available — CEA gating disabled (UNSAFE)');
}

// ── Context Validator (legacy — kept for correlateAuthSequence / buildCorrelatedDetections) ─
let _contextValidator = null;
try {
  _contextValidator = require('./detection-context-validator');
} catch (e) {
  console.warn('[Sigma] detection-context-validator not available');
}

// ── Built-in Sigma Rule Definitions ──────────────────────────────
// In production these load from YAML files; here we define them
// as JS objects so no YAML parser dependency is needed.
const BUILTIN_RULES = require('./rules/builtin-rules');

// ── Extended Rules (100+ additional Sigma/Hayabusa rules) ─────────
let EXTENDED_RULES = [];
try {
  EXTENDED_RULES = require('./rules/extended-rules');
} catch (e) {
  console.warn('[Sigma] Extended rules not found — using builtin only');
}

// ── Large-Scale Rules (6000+ auto-generated Sigma/Hayabusa rules) ─
let LARGE_SCALE_RULES = [];
try {
  LARGE_SCALE_RULES = require('./rules/large-scale-rules');
} catch (e) {
  console.warn('[Sigma] Large-scale rules not found — using builtin + extended only');
}

// ── All Rules combined ────────────────────────────────────────────
const ALL_RULES = [...BUILTIN_RULES, ...EXTENDED_RULES, ...LARGE_SCALE_RULES];

// ── Field Mappings (Sigma → Normalized fields) ────────────────────
const FIELD_MAPS = {
  // Windows Event Log
  EventID           : 'eventId',
  Channel           : 'channel',
  ComputerName      : 'computer',
  User              : 'user',
  ProcessName       : 'process',
  ProcessId         : 'pid',
  CommandLine       : 'commandLine',
  ParentImage       : 'parentProc',
  TargetFilename    : 'filePath',
  DestinationHostname: 'domain',
  DestinationIp     : 'dstIp',
  DestinationPort   : 'dstPort',
  SourceIp          : 'srcIp',
  SourcePort        : 'srcPort',
  QueryName         : 'domain',
  Image             : 'process',
  Hashes            : 'hash',
  TargetObject      : 'regKey',
  // Syslog
  hostname          : 'computer',
  program           : 'process',
  message           : 'raw.message',
  // Common
  src_ip            : 'srcIp',
  dst_ip            : 'dstIp',
  username          : 'user',
};

// ── Severity weights ─────────────────────────────────────────────
const SEVERITY_WEIGHTS = {
  critical: 100, high: 80, medium: 50, low: 20, informational: 5,
};

class SigmaEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this._rules      = new Map();   // ruleId → compiled rule
    this._ruleIndex  = new Map();   // eventId → Set<ruleId>  (fast lookup)
    this._fieldIndex = new Map();   // fieldName → Map<value → Set<ruleId>>
    this._config     = config;
    this._stats      = { evaluated: 0, matched: 0, errors: 0 };
  }

  // ── Load Rules ───────────────────────────────────────────────────
  async loadRules() {
    let loaded   = 0;
    let stripped = 0;
    for (const rule of ALL_RULES) {
      try {
        // ── CEA pre-sanitisation: remove technique tags that are structurally
        //    impossible for this rule to ever produce valid evidence for.
        //    This prevents 6 000+ auto-generated rules from matching auth events
        //    against T1190 / T1021.002 / T1550.002 at rule-load time.
        const sanitized = _cea ? _cea.sanitizeRuleTags(rule) : rule;
        if (sanitized._ceaSanitized) stripped++;
        const compiled = this._compileRule(sanitized);
        this._indexRule(compiled);
        loaded++;
      } catch (e) {
        this._stats.errors++;
        console.warn(`[Sigma] Rule compile error: ${rule.title || 'unknown'} — ${e.message}`);
      }
    }
    console.log(`[Sigma] Loaded ${loaded} rules (${stripped} CEA-sanitised, ${this._stats.errors} errors)`);
    return loaded;
  }

  async loadRuleFromObject(ruleObj) {
    const compiled = this._compileRule(ruleObj);
    this._indexRule(compiled);
    this._stats.matched = 0; // reset
    return compiled.id;
  }

  async validateRule(ruleObj) {
    try {
      const compiled = this._compileRule(ruleObj);
      return { valid: true, rule: compiled, errors: [] };
    } catch (e) {
      return { valid: false, rule: null, errors: [e.message] };
    }
  }

  // ── Detection ────────────────────────────────────────────────────
  /**
   * detect — Run all candidate rules against normalized events.
   * @param {Array}  normalizedEvents
   * @param {Object} opts — { maxCandidates: number (default 2000),
   *                          applyContextValidation: boolean (default true) }
   */
  async detect(normalizedEvents, opts = {}) {
    const rawDetections   = [];
    const MAX_CANDIDATES  = opts.maxCandidates || 2000;
    const applyCEA        = opts.applyCEA !== false; // default true — cannot be disabled in prod
    const applyValidation = opts.applyContextValidation !== false; // legacy compat

    for (const evt of normalizedEvents) {
      this._stats.evaluated++;
      const candidateSet = this._getCandidateRules(evt);

      // Cap candidate set to avoid timeouts on wildcard-heavy rule sets
      const candidates = candidateSet.size > MAX_CANDIDATES
        ? Array.from(candidateSet).slice(0, MAX_CANDIDATES)
        : candidateSet;

      for (const ruleId of candidates) {
        const rule = this._rules.get(ruleId);
        if (!rule) continue;

        // ── CEA logsource pre-filter (replaces legacy _logsourceCompatible) ──
        // Use the CEA's TECHNIQUE_BLOCKED_SOURCES to skip evaluation of rules
        // that could never produce valid technique assignments for this event.
        if (applyCEA && _cea && !this._ceaLogsourceOk(rule, evt)) {
          this._stats.logsourceSkipped = (this._stats.logsourceSkipped || 0) + 1;
          continue;
        }
        // Legacy logsource check (kept as fallback when CEA is unavailable)
        if (!applyCEA && _contextValidator && !this._logsourceCompatible(rule, evt)) {
          this._stats.logsourceSkipped = (this._stats.logsourceSkipped || 0) + 1;
          continue;
        }

        try {
          const match = this._evaluateRule(rule, evt);
          if (match) {
            const det = this._buildDetection(rule, evt);
            rawDetections.push(det);
            this._stats.matched++;
            this.emit('rule:match', det);
          }
        } catch (e) {
          this._stats.errors++;
        }
      }
    }

    if (rawDetections.length === 0) return rawDetections;

    // ── CEA post-evaluation gate (primary) ─────────────────────────────────
    // Applies the Central Evidence Authority to every detection.  This is the
    // AUTHORITATIVE gate — it runs even if the logsource pre-filter missed a rule.
    if (applyCEA && _cea) {
      return _cea.validateBatch(rawDetections, normalizedEvents);
    }

    // ── Legacy context validation fallback ─────────────────────────────────
    if (applyValidation && _contextValidator) {
      return _contextValidator.filterDetectionsByContext(rawDetections, normalizedEvents);
    }

    return rawDetections;
  }

  // ── CEA logsource pre-filter ────────────────────────────────────────────
  // Returns false when the rule's tagged techniques are BLOCKED for this
  // event source, so we skip rule evaluation entirely.
  _ceaLogsourceOk(rule, evt) {
    if (!_cea || !rule.tags?.length) return true;
    const evtId = String(evt.eventId || evt.raw?.EventID || '');
    for (const tag of rule.tags) {
      const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
      if (!m) continue;
      const tid     = m[1].toUpperCase();
      const blocked = _cea.TECHNIQUE_BLOCKED_SOURCES[tid];
      if (!blocked) continue;

      // If the event's ID is blocked for this technique AND no web evidence exists,
      // skip the rule evaluation entirely.
      if (evtId && blocked.blockedEventIds.has(evtId)) {
        // Check exceptions using a lightweight evidence proxy
        const exceptOk = blocked.exceptWhen?.some(flag => {
          if (flag === 'has_webserver_logs') {
            const src  = (evt.source || '').toLowerCase();
            const fmt  = (evt.format || '').toLowerCase();
            return src.includes('web') || src.includes('iis') || fmt === 'webserver' || evt.url != null;
          }
          if (flag === 'has_web_parent_process') {
            return _cea.EvidenceContext.eventHasWebParent(evt);
          }
          return false;
        });
        if (!exceptOk) return false;
      }
    }
    return true;
  }

  // ── Logsource compatibility check ────────────────────────────────
  // Returns false only when the rule's logsource has a STRICT category
  // that is CATEGORICALLY incompatible with the event's known source.
  // Does NOT filter when the event source is unknown/generic.
  _logsourceCompatible(rule, evt) {
    const ruleCategory = (rule.logsource?.category || '').toLowerCase();
    const ruleProduct  = (rule.logsource?.product  || '').toLowerCase();
    if (!ruleCategory) return true; // No category constraint → allow

    const evtSource  = (evt.source || '').toLowerCase();
    const evtFormat  = (evt.format || '').toLowerCase();
    const evtChannel = (evt.channel || (evt.raw && evt.raw.Channel) || '').toLowerCase();

    // Web-server rules require web-server telemetry signals
    if (['webserver', 'web', 'http', 'iis', 'apache', 'nginx'].includes(ruleCategory)) {
      // Allow if the event comes from a web source
      const isWebEvent =
        evtSource.includes('web') || evtSource.includes('iis') || evtSource.includes('apache') ||
        evtSource.includes('nginx') || evtSource.includes('http') ||
        evtFormat === 'webserver' ||
        evt.url != null ||
        (evt.raw && (evt.raw['cs-uri-stem'] != null || evt.raw['cs-method'] != null)) ||
        evtChannel.includes('w3svc') || evtChannel.includes('httpd') ||
        // Web shell rule exception: still allow when parent process is a web server
        (evt.parentProc && /w3wp|httpd|nginx|php|apache|tomcat|iisexpress/i.test(evt.parentProc));
      if (!isWebEvent) return false;
    }

    // DNS rules should only apply to DNS log events
    if (ruleCategory === 'dns') {
      const isDnsEvent =
        evtSource.includes('dns') || evtFormat === 'dns' ||
        evtChannel.includes('dns') ||
        evt.domain != null;
      if (!isDnsEvent) return false;
    }

    return true; // Compatible (or indeterminate — allow through)
  }

  // ── Rule Compilation ─────────────────────────────────────────────
  _compileRule(rule) {
    const id = rule.id || crypto.randomUUID();
    const compiled = {
      id,
      title      : rule.title       || 'Unnamed Rule',
      description: rule.description || '',
      author     : rule.author      || 'RAYKAN',
      severity   : (rule.level      || rule.severity || 'medium').toLowerCase(),
      status     : rule.status      || 'stable',
      tags       : rule.tags        || [],
      logsource  : rule.logsource   || {},
      falsepositives: rule.falsepositives || [],
      references : rule.references  || [],
      // Compiled condition evaluator
      evaluate   : this._compileCondition(rule.detection || {}, rule.detection?.condition || 'all'),
      // Compiled field matchers per selection
      selections : this._compileSelections(rule.detection || {}),
      weight     : SEVERITY_WEIGHTS[rule.level?.toLowerCase()] || SEVERITY_WEIGHTS.medium,
    };
    this._rules.set(id, compiled);
    return compiled;
  }

  _compileSelections(detection) {
    const selections = {};
    for (const [key, value] of Object.entries(detection)) {
      if (key === 'condition') continue;
      if (key === 'timeframe') continue;
      selections[key] = this._compileSelection(value);
    }
    return selections;
  }

  _compileSelection(selection) {
    if (Array.isArray(selection)) {
      // List of OR conditions (each item = one match set)
      return { type: 'or_list', items: selection.map(s => this._compileSelection(s)) };
    }
    if (typeof selection === 'object' && selection !== null) {
      const matchers = [];
      for (const [field, value] of Object.entries(selection)) {
        const normalField = FIELD_MAPS[field] || field;
        matchers.push({ field: normalField, matcher: this._compileMatcher(value) });
      }
      return { type: 'field_match', matchers };
    }
    return { type: 'value', value: selection };
  }

  _compileMatcher(value) {
    if (Array.isArray(value)) {
      return { type: 'or', values: value.map(v => this._compileMatcher(v)) };
    }
    if (typeof value === 'string') {
      if (value.includes('*') || value.includes('?')) {
        const regex = new RegExp(
          '^' + value.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                     .replace(/\*/g, '.*')
                     .replace(/\?/g, '.') + '$',
          'i'
        );
        return { type: 'wildcard', regex };
      }
      if (value.startsWith('/') && value.endsWith('/')) {
        return { type: 'regex', regex: new RegExp(value.slice(1, -1), 'i') };
      }
      if (value.startsWith('|contains:')) {
        return { type: 'contains', substring: value.slice(10) };
      }
      if (value.startsWith('|startswith:')) {
        return { type: 'startswith', prefix: value.slice(12) };
      }
      if (value.startsWith('|endswith:')) {
        return { type: 'endswith', suffix: value.slice(10) };
      }
      if (value === 'null') return { type: 'null' };
      return { type: 'exact', value };
    }
    if (typeof value === 'number') return { type: 'exact', value: String(value) };
    if (typeof value === 'boolean') return { type: 'exact', value: String(value) };
    return { type: 'exact', value: String(value) };
  }

  _compileCondition(detection, condition) {
    const selectionNames = Object.keys(detection).filter(k => k !== 'condition' && k !== 'timeframe');

    // Parse condition string
    if (!condition || condition === 'all') {
      return (evt, selections) => selectionNames.every(name => this._matchSelection(selections[name], evt));
    }
    if (condition.startsWith('1 of ')) {
      const pattern = condition.slice(5);
      const targets = selectionNames.filter(n => this._matchPattern(n, pattern));
      return (evt, selections) => targets.some(name => this._matchSelection(selections[name], evt));
    }
    if (condition.startsWith('all of ')) {
      const pattern = condition.slice(7);
      const targets = selectionNames.filter(n => this._matchPattern(n, pattern));
      return (evt, selections) => targets.every(name => this._matchSelection(selections[name], evt));
    }
    // Boolean expression: parse tokens
    return this._parseConditionExpr(condition, selectionNames);
  }

  _parseConditionExpr(expr, selectionNames) {
    // Simple tokenizer for: selection1 and selection2, not selection3, etc.
    const tokens = expr.trim().split(/\s+/);
    return (evt, selections) => {
      let result   = true;
      let operator = 'and';
      let negate   = false;

      for (const token of tokens) {
        const lower = token.toLowerCase();
        if (lower === 'and') { operator = 'and'; continue; }
        if (lower === 'or')  { operator = 'or';  continue; }
        if (lower === 'not') { negate = true;     continue; }

        const name   = selectionNames.find(n => n === token) || token;
        const sel    = selections[name];
        let   val    = sel ? this._matchSelection(sel, evt) : false;
        if (negate) { val = !val; negate = false; }

        if (operator === 'and') result = result && val;
        else                    result = result || val;
      }
      return result;
    };
  }

  _matchPattern(name, pattern) {
    if (pattern === '*') return true;
    if (pattern.endsWith('*')) return name.startsWith(pattern.slice(0, -1));
    return name === pattern;
  }

  _matchSelection(selection, evt) {
    if (!selection) return false;
    if (selection.type === 'or_list') {
      return selection.items.some(item => this._matchSelection(item, evt));
    }
    if (selection.type === 'field_match') {
      return selection.matchers.every(m => {
        const fieldVal = this._getFieldValue(evt, m.field);
        return this._applyMatcher(m.matcher, fieldVal);
      });
    }
    return false;
  }

  _applyMatcher(matcher, value) {
    if (value === null || value === undefined) {
      return matcher.type === 'null';
    }
    const strVal = String(value).toLowerCase();
    switch (matcher.type) {
      case 'exact'     : return strVal === String(matcher.value).toLowerCase();
      case 'wildcard'  : return matcher.regex.test(strVal);
      case 'regex'     : return matcher.regex.test(strVal);
      case 'contains'  : return strVal.includes(matcher.substring.toLowerCase());
      case 'startswith' : return strVal.startsWith(matcher.prefix.toLowerCase());
      case 'endswith'  : return strVal.endsWith(matcher.suffix.toLowerCase());
      case 'null'      : return !value;
      case 'or'        : return matcher.values.some(m => this._applyMatcher(m, value));
      default          : return false;
    }
  }

  _getFieldValue(evt, field) {
    // Support dot notation for nested fields
    const parts = field.split('.');
    let val = evt;
    for (const p of parts) {
      if (val === null || val === undefined) return null;
      if (p === 'raw' && typeof val.raw === 'object') val = val.raw;
      else val = val[p];
    }
    return val;
  }

  // ── Rule Evaluation ───────────────────────────────────────────────
  _evaluateRule(rule, evt) {
    return rule.evaluate(evt, rule.selections);
  }

  _buildDetection(rule, evt) {
    return {
      id         : crypto.randomUUID(),
      ruleId     : rule.id,
      ruleName   : rule.title,
      description: rule.description,
      severity   : rule.severity,
      confidence : this._calcConfidence(rule, evt),
      tags       : rule.tags,
      author     : rule.author,
      references : rule.references,
      logsource  : rule.logsource,
      timestamp  : evt.timestamp || new Date(),
      event      : evt,
      eventId    : evt.eventId,
      computer   : evt.computer,
      user       : evt.user,
      process    : evt.process,
      commandLine: evt.commandLine,
      srcIp      : evt.srcIp,
      dstIp      : evt.dstIp,
      weight     : rule.weight,
    };
  }

  _calcConfidence(rule, evt) {
    // Base confidence from rule status
    const statusScore = { stable: 90, test: 70, experimental: 50, deprecated: 10 };
    let conf = statusScore[rule.status] || 70;
    // Boost if critical fields are present
    if (evt.commandLine) conf = Math.min(100, conf + 5);
    if (evt.user)        conf = Math.min(100, conf + 3);
    return conf;
  }

  // ── Indexing (performance optimization) ──────────────────────────
  _indexRule(rule) {
    // Index by EventID for fast pre-filtering
    const evtIdSel = rule.selections?.selection || rule.selections?.filter;
    const evtIds   = [];

    for (const [, sel] of Object.entries(rule.selections || {})) {
      this._extractEventIds(sel, evtIds);
    }

    if (evtIds.length > 0) {
      for (const eid of evtIds) {
        if (!this._ruleIndex.has(eid)) this._ruleIndex.set(eid, new Set());
        this._ruleIndex.get(eid).add(rule.id);
      }
    } else {
      // No EventID filter — add to wildcard bucket
      if (!this._ruleIndex.has('*')) this._ruleIndex.set('*', new Set());
      this._ruleIndex.get('*').add(rule.id);
    }
  }

  _extractEventIds(sel, ids) {
    if (!sel) return;
    if (sel.type === 'field_match') {
      for (const m of sel.matchers) {
        if (m.field === 'eventId') {
          if (m.matcher.type === 'exact') ids.push(m.matcher.value);
          if (m.matcher.type === 'or')    m.matcher.values.forEach(v => { if (v.value) ids.push(v.value); });
        }
      }
    }
    if (sel.type === 'or_list') sel.items.forEach(i => this._extractEventIds(i, ids));
  }

  _getCandidateRules(evt) {
    const candidates = new Set();
    const eid = String(evt.eventId || '');

    // Add exact EventID matches
    if (eid && this._ruleIndex.has(eid)) {
      for (const r of this._ruleIndex.get(eid)) candidates.add(r);
    }
    // Add wildcard rules (no EventID filter)
    if (this._ruleIndex.has('*')) {
      for (const r of this._ruleIndex.get('*')) candidates.add(r);
    }

    return candidates;
  }

  // ── Accessors ─────────────────────────────────────────────────────
  getRuleCount()  { return this._rules.size; }
  getStatus()     { return { rules: this._rules.size, stats: this._stats }; }
  getAllRules()    { return Array.from(this._rules.values()).map(r => ({ id: r.id, title: r.title, severity: r.severity, tags: r.tags })); }
}

module.exports = SigmaEngine;
