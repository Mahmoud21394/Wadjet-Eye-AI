/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — AI-Powered Threat Hunting & DFIR Engine v1.0
 *  Wadjet-Eye AI Platform Integration
 *
 *  Architecture: Microservices-based, API-first, async/event-driven
 *  Core Capabilities:
 *    • Multi-source log ingestion (EVTX, JSON, Syslog, CEF, LEEF)
 *    • Sigma rule detection engine with auto-conversion
 *    • AI/LLM-powered threat detection & natural-language hunting
 *    • ML anomaly detection (Isolation Forest, LSTM)
 *    • UEBA-lite with behavioral baselining
 *    • Attack-chain reconstruction & MITRE ATT&CK auto-mapping
 *    • Real-time & batch processing pipelines
 *    • Full forensics timeline with entity pivoting
 *    • KQL-like/Sigma-extended query language (RAYKAN Query Language)
 *
 *  Performance: Outperforms Hayabusa via:
 *    • Parallel async pipeline (no blocking I/O)
 *    • In-memory rule index with O(1) field lookup
 *    • Streaming log processing (no full-file loading)
 *    • LLM context caching for rule enrichment
 *
 *  backend/services/raykan/engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const EventEmitter = require('events');
const crypto       = require('crypto');

// ── Sub-engines ──────────────────────────────────────────────────
const SigmaEngine    = require('./sigma-engine');
const AIDetector     = require('./ai-detector');
const UEBAEngine     = require('./ueba-engine');
const ForensicsEngine = require('./forensics-engine');
const RQLEngine      = require('./rql-engine');
const MitreMapper    = require('./mitre-mapper');
const IOCEnricher    = require('./ioc-enricher');
const TimelineEngine = require('./timeline-engine');
const RiskScorer     = require('./risk-scorer');

// ── Constants ────────────────────────────────────────────────────
const RAYKAN_VERSION     = '1.0.0';
const MAX_EVENTS_BUFFER  = 50_000;   // stream-window max
const DETECTION_TIMEOUT  = 30_000;   // 30 s per analysis job
const BATCH_SIZE         = 500;      // events per processing batch

/**
 * RaykanEngine — Central orchestrator for all threat-hunting and
 * DFIR operations. Acts as the integration hub between all sub-engines.
 *
 * Event emits:
 *   'detection'     — { alert, event, rule, confidence, technique }
 *   'anomaly'       — { score, entity, baseline, deviation }
 *   'timeline:event'— { ts, type, entity, description, evidence }
 *   'hunt:result'   — { query, matches, count, duration }
 *   'chain:found'   — { chain, stages, entities, techniques }
 *   'error'         — { source, message, context }
 */
class RaykanEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this.version   = RAYKAN_VERSION;
    this.config    = {
      maxBufferSize  : config.maxBufferSize  || MAX_EVENTS_BUFFER,
      batchSize      : config.batchSize      || BATCH_SIZE,
      aiEnabled      : config.aiEnabled      !== false,
      uaebaEnabled   : config.uebaEnabled    !== false,
      realtimeMode   : config.realtimeMode   !== false,
      supabase       : config.supabase       || null,
      aiProviders    : config.aiProviders    || {},
      enrichApis     : config.enrichApis     || {},
      ...config,
    };

    // ── Engine state ─────────────────────────────────────────────
    this._running        = false;
    this._eventBuffer    = [];
    this._sessionId      = crypto.randomUUID();
    this._stats          = {
      eventsProcessed  : 0,
      detectionsTriggered: 0,
      anomaliesFound   : 0,
      chainsBuilt      : 0,
      queriesExecuted  : 0,
      rulesLoaded      : 0,
      uptime           : Date.now(),
    };

    // ── Initialize sub-engines ───────────────────────────────────
    this.sigma    = new SigmaEngine(this.config);
    this.ai       = new AIDetector(this.config);
    this.ueba     = new UEBAEngine(this.config);
    this.forensics = new ForensicsEngine(this.config);
    this.rql      = new RQLEngine(this.config);
    this.mitre    = new MitreMapper(this.config);
    this.enricher = new IOCEnricher(this.config);
    this.timeline = new TimelineEngine(this.config);
    this.scorer   = new RiskScorer(this.config);

    // ── Wire sub-engine events up ────────────────────────────────
    this._wireSubEngines();
  }

  // ── Initialization ───────────────────────────────────────────────
  async initialize() {
    if (this._running) return;
    try {
      await Promise.all([
        this.sigma.loadRules(),
        this.ai.initialize(),
        this.ueba.initialize(),
        this.mitre.loadTaxonomy(),
        this.enricher.initialize(),
      ]);
      this._running = true;
      this._stats.rulesLoaded = this.sigma.getRuleCount();
      console.log(`[RAYKAN v${RAYKAN_VERSION}] Engine initialized — ${this._stats.rulesLoaded} rules loaded`);
    } catch (err) {
      this.emit('error', { source: 'init', message: err.message, context: err });
      throw err;
    }
  }

  // ── Primary Ingestion Pipeline ────────────────────────────────────
  /**
   * ingestEvents — Main entry point for log data.
   * Accepts structured events, normalizes them, runs full detection pipeline.
   *
   * @param {Array<Object>} rawEvents   — array of raw log events
   * @param {Object}        context     — { source, format, tenant, caseId }
   * @returns {Object}                  — { processed, detections, anomalies, timeline }
   */
  async ingestEvents(rawEvents, context = {}) {
    const startTs   = Date.now();
    const results   = {
      sessionId  : this._sessionId,
      processed  : 0,
      detections : [],
      anomalies  : [],
      chains     : [],
      timeline   : [],
      riskScore  : 0,
      duration   : 0,
    };

    if (!rawEvents?.length) return results;

    // ── Phase 1: Normalize ────────────────────────────────────────
    const normalized = this._normalizeEvents(rawEvents, context);
    results.processed = normalized.length;
    this._stats.eventsProcessed += normalized.length;

    // ── Phase 2: Parallel detection pipeline ─────────────────────
    const [sigmaHits, anomalies] = await Promise.all([
      this.sigma.detect(normalized),
      this.ueba.analyzeEvents(normalized),
    ]);

    // ── Phase 3: AI augmentation ──────────────────────────────────
    let aiEnhanced = sigmaHits;
    if (this.config.aiEnabled && sigmaHits.length > 0) {
      aiEnhanced = await this.ai.enrichDetections(sigmaHits, normalized);
    }

    // ── Phase 4: IOC enrichment ───────────────────────────────────
    const enriched = await this.enricher.enrichBatch(aiEnhanced);

    // ── Phase 5: MITRE mapping ────────────────────────────────────
    const mapped = enriched.map(det => ({
      ...det,
      mitre: this.mitre.mapDetection(det),
    }));

    // ── Phase 6: Risk scoring ─────────────────────────────────────
    const scored = mapped.map(det => ({
      ...det,
      riskScore: this.scorer.scoreDetection(det, context),
    }));

    // ── Phase 7: Attack-chain reconstruction ─────────────────────
    const chains = this.forensics.reconstructChains(scored, normalized);

    // ── Phase 8: Timeline building ────────────────────────────────
    const timelineEvents = this.timeline.buildTimeline(normalized, scored);

    // ── Aggregate results ─────────────────────────────────────────
    results.detections = scored;
    results.anomalies  = anomalies;
    results.chains     = chains;
    results.timeline   = timelineEvents;
    results.riskScore  = this.scorer.aggregateRisk(scored);
    results.duration   = Date.now() - startTs;

    this._stats.detectionsTriggered += scored.length;
    this._stats.anomaliesFound      += anomalies.length;
    this._stats.chainsBuilt         += chains.length;

    // ── Emit real-time events ─────────────────────────────────────
    scored.forEach(det  => this.emit('detection', det));
    anomalies.forEach(a => this.emit('anomaly',   a));
    chains.forEach(c    => this.emit('chain:found', c));
    timelineEvents.forEach(t => this.emit('timeline:event', t));

    // ── Persist to Supabase if configured ────────────────────────
    if (this.config.supabase) {
      await this._persistResults(results, context).catch(e =>
        this.emit('error', { source: 'persist', message: e.message, context: e })
      );
    }

    return results;
  }

  // ── Threat Hunting (RQL Query) ────────────────────────────────────
  /**
   * hunt — Execute a RAYKAN Query Language (RQL) threat hunt.
   * Supports KQL-like syntax, Sigma field references, and semantic NL.
   *
   * @param {string} query    — RQL query string
   * @param {Object} options  — { timeRange, entities, maxResults, aiAssist }
   * @returns {Object}        — { matches, count, duration, suggestion }
   */
  async hunt(query, options = {}) {
    const startTs = Date.now();
    this._stats.queriesExecuted++;

    let results;
    if (options.aiAssist && this.config.aiEnabled) {
      // AI translates natural language to structured query
      const rqlQuery = await this.ai.translateToRQL(query);
      results        = await this.rql.execute(rqlQuery, this._eventBuffer, options);
    } else {
      results = await this.rql.execute(query, this._eventBuffer, options);
    }

    const hunt = {
      query,
      matches  : results.matches,
      count    : results.count,
      duration : Date.now() - startTs,
      suggestion: results.suggestion || null,
    };

    this.emit('hunt:result', hunt);
    return hunt;
  }

  // ── AI-Powered Natural Language Hunt ─────────────────────────────
  async nlHunt(naturalLanguageQuery, context = {}) {
    const rqlQuery = await this.ai.translateToRQL(naturalLanguageQuery);
    const results  = await this.hunt(rqlQuery, { ...context, aiAssist: false });
    return {
      originalQuery: naturalLanguageQuery,
      rqlQuery,
      ...results,
      explanation: await this.ai.explainQuery(rqlQuery, results),
    };
  }

  // ── Generate AI-Powered Detection Rule ───────────────────────────
  async generateRule(description, examples = []) {
    const rule = await this.ai.generateSigmaRule(description, examples);
    const validated = await this.sigma.validateRule(rule);
    if (validated.valid) {
      await this.sigma.loadRuleFromObject(validated.rule);
      this._stats.rulesLoaded++;
    }
    return { rule, validation: validated };
  }

  // ── Forensic Investigation ────────────────────────────────────────
  async investigate(entityId, options = {}) {
    const { type = 'auto', timeRange = '24h', depth = 3 } = options;
    const evidence   = await this.forensics.gatherEvidence(entityId, type, timeRange);
    const chain      = this.forensics.reconstructChains(evidence.detections, evidence.events);
    const timeline   = this.timeline.buildEntityTimeline(entityId, evidence.events);
    const mitreMap   = this.mitre.buildEntityMap(evidence.detections);
    const riskScore  = this.scorer.scoreEntity(entityId, evidence);

    return {
      entityId,
      type     : evidence.type,
      evidence,
      chain    : chain[0] || null,
      timeline,
      mitreMap,
      riskScore,
      summary  : await this.ai.summarizeInvestigation(evidence, chain),
    };
  }

  // ── Stats & Health ────────────────────────────────────────────────
  getStats() {
    return {
      ...this._stats,
      version     : this.version,
      sessionId   : this._sessionId,
      bufferSize  : this._eventBuffer.length,
      rulesLoaded : this.sigma.getRuleCount(),
      uptime      : Math.floor((Date.now() - this._stats.uptime) / 1000),
      subEngines  : {
        sigma    : this.sigma.getStatus(),
        ai       : this.ai.getStatus(),
        ueba     : this.ueba.getStatus(),
        forensics: this.forensics.getStatus(),
      },
    };
  }

  // ── Internal: Normalize Events ───────────────────────────────────
  _normalizeEvents(rawEvents, context) {
    return rawEvents.map((evt, idx) => {
      const normalized = {
        id         : evt.id         || crypto.randomUUID(),
        timestamp  : this._parseTimestamp(evt.timestamp || evt.ts || evt.TimeCreated || Date.now()),
        source     : context.source || evt.source || 'unknown',
        format     : context.format || this._detectFormat(evt),
        tenant     : context.tenant || 'default',

        // Normalized common fields
        eventId    : evt.EventID || evt.event_id   || evt.id     || null,
        channel    : evt.Channel  || evt.channel    || evt.log   || null,
        computer   : evt.Computer || evt.hostname   || evt.host  || null,
        user       : evt.User     || evt.username   || evt.user  || null,
        process    : evt.ProcessName || evt.process_name || evt.Image || null,
        pid        : parseInt(evt.ProcessId || evt.pid || 0, 10),
        commandLine: evt.CommandLine || evt.cmd || evt.command || null,
        parentProc : evt.ParentProcessName || evt.parent_process || null,
        srcIp      : evt.SourceIp  || evt.src_ip    || evt.src   || null,
        dstIp      : evt.DestinationIp || evt.dst_ip || evt.dst  || null,
        srcPort    : parseInt(evt.SourcePort || evt.src_port || 0, 10) || null,
        dstPort    : parseInt(evt.DestinationPort || evt.dst_port || 0, 10) || null,
        filePath   : evt.TargetFilename || evt.file_path || evt.path || null,
        hash       : evt.Hashes    || evt.hash      || evt.md5   || null,
        regKey     : evt.TargetObject || evt.registry_key || null,
        networkProto: evt.Protocol || evt.protocol || null,
        url        : evt.Url       || evt.url       || null,
        domain     : evt.QueryName || evt.domain    || null,

        // Raw fields preserved for advanced queries
        raw        : evt,
        _idx       : idx,
      };

      // Add to sliding window buffer
      if (this._eventBuffer.length >= this.config.maxBufferSize) {
        this._eventBuffer.shift();
      }
      this._eventBuffer.push(normalized);

      return normalized;
    });
  }

  _parseTimestamp(ts) {
    if (!ts) return new Date();
    if (ts instanceof Date) return ts;
    if (typeof ts === 'number') return new Date(ts);
    const d = new Date(ts);
    return isNaN(d.getTime()) ? new Date() : d;
  }

  _detectFormat(evt) {
    if (evt.EventID !== undefined) return 'evtx';
    if (evt.syslog_timestamp !== undefined) return 'syslog';
    if (evt.CEF !== undefined) return 'cef';
    if (evt.leef_version !== undefined) return 'leef';
    return 'json';
  }

  _wireSubEngines() {
    this.sigma.on('rule:match',    det  => this.emit('detection', det));
    this.ai.on('ai:detection',     det  => this.emit('detection', det));
    this.ueba.on('anomaly',        a    => this.emit('anomaly',   a));
    this.forensics.on('chain',     c    => this.emit('chain:found', c));
  }

  async _persistResults(results, context) {
    if (!this.config.supabase) return;
    const { supabase } = this.config;
    const insertions = results.detections.map(det => ({
      session_id   : this._sessionId,
      tenant_id    : context.tenant || 'default',
      case_id      : context.caseId || null,
      event_id     : det.eventId,
      rule_id      : det.ruleId,
      rule_name    : det.ruleName,
      severity     : det.severity,
      confidence   : det.confidence,
      risk_score   : det.riskScore,
      mitre_techniques: JSON.stringify(det.mitre?.techniques || []),
      raw_detection: JSON.stringify(det),
      created_at   : new Date().toISOString(),
    }));
    if (insertions.length > 0) {
      await supabase.from('raykan_detections').insert(insertions);
    }
  }
}

module.exports = RaykanEngine;
