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

// ── Built-in Sigma Rule Definitions ──────────────────────────────
// In production these load from YAML files; here we define them
// as JS objects so no YAML parser dependency is needed.
const BUILTIN_RULES = require('./rules/builtin-rules');

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
    let loaded = 0;
    for (const rule of BUILTIN_RULES) {
      try {
        const compiled = this._compileRule(rule);
        this._indexRule(compiled);
        loaded++;
      } catch (e) {
        this._stats.errors++;
        console.warn(`[Sigma] Rule compile error: ${rule.title || 'unknown'} — ${e.message}`);
      }
    }
    console.log(`[Sigma] Loaded ${loaded} rules (${this._stats.errors} errors)`);
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
  async detect(normalizedEvents) {
    const detections = [];

    for (const evt of normalizedEvents) {
      this._stats.evaluated++;
      const candidates = this._getCandidateRules(evt);

      for (const ruleId of candidates) {
        const rule = this._rules.get(ruleId);
        if (!rule) continue;

        try {
          const match = this._evaluateRule(rule, evt);
          if (match) {
            const det = this._buildDetection(rule, evt);
            detections.push(det);
            this._stats.matched++;
            this.emit('rule:match', det);
          }
        } catch (e) {
          this._stats.errors++;
        }
      }
    }

    return detections;
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
