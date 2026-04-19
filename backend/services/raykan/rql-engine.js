/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN Query Language (RQL) Engine v1.0
 *
 *  Syntax: KQL-like + Sigma-extended
 *   field:value           — exact match (case-insensitive)
 *   field:"exact phrase"  — phrase match
 *   field:value*          — wildcard suffix
 *   field:*value          — wildcard prefix
 *   field:/regex/         — regex
 *   field:>100            — numeric comparison (>, <, >=, <=)
 *   AND / OR / NOT        — boolean operators
 *   (group)               — parenthesized groups
 *   event.id:4624         — dotted field access
 *   time.range:1h/24h/7d  — time filter shorthand
 *
 *  Examples:
 *   process.name:"powershell.exe" AND commandLine:*encodedcommand*
 *   user.name:admin* AND event.id:4724 AND NOT computer:"DC01"
 *   srcIp:192.168.* OR srcIp:10.0.* AND dstPort:>1024
 *   time.range:1h AND severity:critical
 *
 *  backend/services/raykan/rql-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const EventEmitter = require('events');

// ── Field aliases (RQL → normalized) ─────────────────────────────
const FIELD_ALIASES = {
  'process.name'  : 'process',
  'process.cmd'   : 'commandLine',
  'process.pid'   : 'pid',
  'user.name'     : 'user',
  'host.name'     : 'computer',
  'host.ip'       : 'srcIp',
  'event.id'      : 'eventId',
  'net.src.ip'    : 'srcIp',
  'net.dst.ip'    : 'dstIp',
  'net.dst.port'  : 'dstPort',
  'net.src.port'  : 'srcPort',
  'file.path'     : 'filePath',
  'file.hash'     : 'hash',
  'reg.key'       : 'regKey',
  'dns.query'     : 'domain',
  'url'           : 'url',
  'severity'      : 'severity',
  'source'        : 'source',
  'channel'       : 'channel',
};

class RQLEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this._config = config;
  }

  // ── Execute a query ───────────────────────────────────────────────
  async execute(query, events, options = {}) {
    if (!query || !events?.length) {
      return { matches: [], count: 0, suggestion: null };
    }

    const startTs  = Date.now();
    const maxResults = options.maxResults || 500;

    // Apply time range filter first
    let filtered = this._applyTimeRange(events, options.timeRange || this._extractTimeRange(query));
    // Remove time.range token from query
    const cleanQuery = query.replace(/time\.range:\S+/gi, '').trim();

    // Parse and compile query
    let compiled;
    try {
      compiled = this._parse(cleanQuery);
    } catch (e) {
      return {
        matches  : [],
        count    : 0,
        error    : `Query parse error: ${e.message}`,
        suggestion: this._suggestFix(cleanQuery),
      };
    }

    // Execute query on filtered events
    const matches = [];
    for (const evt of filtered) {
      if (matches.length >= maxResults) break;
      if (this._evaluate(compiled, evt)) {
        matches.push(evt);
      }
    }

    return {
      matches,
      count    : matches.length,
      totalSearched: filtered.length,
      duration : Date.now() - startTs,
      query    : cleanQuery,
      suggestion: null,
    };
  }

  // ── Parser (recursive descent) ────────────────────────────────────
  _parse(query) {
    const tokens = this._tokenize(query);
    const parser = { tokens, pos: 0 };
    const ast    = this._parseExpr(parser);
    return ast;
  }

  _tokenize(query) {
    const tokens = [];
    const re     = /\s*(AND|OR|NOT|and|or|not|\(|\)|"[^"]*"|[^\s()]+)\s*/g;
    let m;
    while ((m = re.exec(query)) !== null) {
      const t = m[1];
      if (t) tokens.push(t);
    }
    return tokens;
  }

  _parseExpr(parser) {
    return this._parseOr(parser);
  }

  _parseOr(parser) {
    let left = this._parseAnd(parser);
    while (this._peek(parser)?.toUpperCase() === 'OR') {
      this._consume(parser);
      const right = this._parseAnd(parser);
      left = { type: 'OR', left, right };
    }
    return left;
  }

  _parseAnd(parser) {
    let left = this._parseUnary(parser);
    while (['AND', 'and'].includes(this._peek(parser))) {
      this._consume(parser);
      const right = this._parseUnary(parser);
      left = { type: 'AND', left, right };
    }
    // Implicit AND
    const next = this._peek(parser);
    if (next && !['OR', 'or', ')', 'AND', 'and'].includes(next) && next?.toUpperCase() !== 'OR') {
      const right = this._parseUnary(parser);
      if (right) left = { type: 'AND', left, right };
    }
    return left;
  }

  _parseUnary(parser) {
    if (['NOT', 'not'].includes(this._peek(parser))) {
      this._consume(parser);
      const operand = this._parsePrimary(parser);
      return { type: 'NOT', operand };
    }
    return this._parsePrimary(parser);
  }

  _parsePrimary(parser) {
    const token = this._peek(parser);
    if (!token) return null;

    if (token === '(') {
      this._consume(parser);
      const expr = this._parseExpr(parser);
      if (this._peek(parser) === ')') this._consume(parser);
      return expr;
    }

    // field:value
    if (token.includes(':') && !['AND','OR','NOT'].includes(token.toUpperCase())) {
      this._consume(parser);
      const colonIdx = token.indexOf(':');
      const rawField = token.slice(0, colonIdx);
      const rawValue = token.slice(colonIdx + 1);
      const field    = FIELD_ALIASES[rawField] || rawField;
      return { type: 'MATCH', field, matcher: this._buildMatcher(rawValue) };
    }

    this._consume(parser);
    return { type: 'TEXT', value: token };
  }

  _peek(parser)    { return parser.tokens[parser.pos]; }
  _consume(parser) { return parser.tokens[parser.pos++]; }

  // ── Matcher Construction ─────────────────────────────────────────
  _buildMatcher(value) {
    // Quoted phrase
    if (value.startsWith('"') && value.endsWith('"')) {
      return { type: 'phrase', value: value.slice(1, -1).toLowerCase() };
    }
    // Numeric comparison
    if (/^[><]=?\d+$/.test(value)) {
      const op  = value.match(/^([><]=?)/)[1];
      const num = parseFloat(value.replace(/[><]=?/, ''));
      return { type: 'numeric', op, num };
    }
    // Regex
    if (value.startsWith('/') && value.endsWith('/')) {
      return { type: 'regex', re: new RegExp(value.slice(1, -1), 'i') };
    }
    // Wildcard
    if (value.includes('*') || value.includes('?')) {
      const regex = new RegExp(
        '^' + value.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$',
        'i'
      );
      return { type: 'wildcard', re: regex };
    }
    // Exact
    return { type: 'exact', value: value.toLowerCase() };
  }

  // ── Query Evaluation ─────────────────────────────────────────────
  _evaluate(node, evt) {
    if (!node) return true;
    switch (node.type) {
      case 'AND'   : return this._evaluate(node.left, evt) && this._evaluate(node.right, evt);
      case 'OR'    : return this._evaluate(node.left, evt) || this._evaluate(node.right, evt);
      case 'NOT'   : return !this._evaluate(node.operand, evt);
      case 'MATCH' : return this._matchField(node.field, node.matcher, evt);
      case 'TEXT'  : return this._fullTextMatch(node.value, evt);
      default      : return false;
    }
  }

  _matchField(field, matcher, evt) {
    const value = this._getField(evt, field);
    if (value === null || value === undefined) return false;
    const strVal = String(value);

    switch (matcher.type) {
      case 'exact'  : return strVal.toLowerCase() === matcher.value;
      case 'phrase' : return strVal.toLowerCase().includes(matcher.value);
      case 'wildcard': return matcher.re.test(strVal);
      case 'regex'  : return matcher.re.test(strVal);
      case 'numeric': {
        const num = parseFloat(strVal);
        if (isNaN(num)) return false;
        switch (matcher.op) {
          case '>'  : return num >  matcher.num;
          case '<'  : return num <  matcher.num;
          case '>=' : return num >= matcher.num;
          case '<=' : return num <= matcher.num;
          default   : return false;
        }
      }
      default: return false;
    }
  }

  _fullTextMatch(value, evt) {
    const lower = value.toLowerCase();
    const haystack = JSON.stringify(evt).toLowerCase();
    return haystack.includes(lower);
  }

  _getField(evt, field) {
    if (field.includes('.')) {
      const parts = field.split('.');
      let val = evt;
      for (const p of parts) {
        if (val === null || val === undefined) return null;
        val = val[p];
      }
      return val;
    }
    return evt[field] !== undefined ? evt[field] : (evt.raw?.[field] ?? null);
  }

  // ── Time Range Filter ─────────────────────────────────────────────
  _extractTimeRange(query) {
    const m = query.match(/time\.range:(\S+)/i);
    return m ? m[1] : null;
  }

  _applyTimeRange(events, range) {
    if (!range) return events;
    const now     = Date.now();
    const msMap   = { h: 3600000, d: 86400000, w: 604800000, m: 2592000000 };
    const match   = range.match(/^(\d+)([hdwm])$/);
    if (!match) return events;
    const cutoff  = now - parseInt(match[1]) * (msMap[match[2]] || 3600000);
    return events.filter(e => {
      const t = e.timestamp instanceof Date ? e.timestamp.getTime() : new Date(e.timestamp).getTime();
      return t >= cutoff;
    });
  }

  _suggestFix(query) {
    if (!query.includes(':')) {
      return `Did you mean to search with a field? Try: process.name:"${query}" or commandLine:*${query}*`;
    }
    return null;
  }

  getStatus() { return { ready: true }; }
}

module.exports = RQLEngine;
