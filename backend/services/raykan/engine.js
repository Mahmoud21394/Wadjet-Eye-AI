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

const EventEmitter   = require('events');
const crypto         = require('crypto');
const {
  normalizeDetections,
  parseRawInput,
  processEvent,
  metrics: normalizerMetrics,
} = require('./ingestion-normalizer');

// ── Central Evidence Authority (CEA) — mandatory global gate ─────────────────
// All technique assignments MUST pass through the CEA.  No downstream module
// (AI enricher, MITRE mapper, narrative builder) may re-add a suppressed tag.
let cea = null;
try {
  cea = require('./central-evidence-authority');
  console.log('[RAYKAN/engine] Central Evidence Authority loaded — global evidence gating ACTIVE');
} catch (e) {
  console.error('[RAYKAN/engine] CRITICAL: central-evidence-authority not found — CEA gating DISABLED');
}

// ── Global Log Classifier (GLC) — domain classification + logsource gating ────
let glc = null;
try {
  glc = require('./global-log-classifier');
  console.log('[RAYKAN/engine] Global Log Classifier loaded — source-aware domain classification ACTIVE');
} catch (e) {
  console.error('[RAYKAN/engine] WARNING: global-log-classifier not found — domain gating DISABLED');
}

// ── Behavioral Correlation Engine (BCE) — unified cross-domain chain detection ─
let bce = null;
try {
  bce = require('./behavioral-correlation-engine');
  console.log('[RAYKAN/engine] Behavioral Correlation Engine loaded — cross-domain attack chains ACTIVE');
} catch (e) {
  console.warn('[RAYKAN/engine] behavioral-correlation-engine not found — BCE disabled');
}

// ── Context Validator (behavioral correlation — supplemental) ─────────────────
let contextValidator = null;
try {
  contextValidator = require('./detection-context-validator');
} catch (e) {
  console.warn('[RAYKAN/engine] detection-context-validator not found — behavioral correlation disabled');
}

// ── ARCH #2 — Schema Registry (field-alias profiles per source type) ─────────
let schemaRegistry = null;
try {
  schemaRegistry = require('./schema-registry');
  console.log('[RAYKAN/engine] Schema Registry loaded — multi-source field normalization ACTIVE');
} catch (e) {
  console.warn('[RAYKAN/engine] schema-registry not found — using built-in alias table only');
}

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
const RAYKAN_VERSION     = '2.0.0'; // v2.0: Global Detection Pipeline
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
   * Schema-tolerant: rawEvents may be array, object, string, null, or undefined.
   *
   * @param {*}      rawEvents   — events (any shape; normalized internally)
   * @param {Object} context     — { source, format, tenant, caseId }
   * @returns {Object}           — { processed, detections, anomalies, timeline }
   */
  async ingestEvents(rawEvents, context = {}) {
    // ── FIX #8 / ARCH-1: Reset session state before every new ingest ──
    // Prevents UEBA profiles, risk caches, and IOC caches from leaking
    // between independent analysis sessions.
    this.resetSession();

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

    // ── Guard: accept any input shape for rawEvents ──────────────
    // parseRawInput converts null/object/string/array → Array<Object>
    const safeEvents = Array.isArray(rawEvents)
      ? rawEvents
      : parseRawInput(rawEvents, context.format || 'auto');

    if (!safeEvents.length) return results;

    // ════════════════════════════════════════════════════════════════
    //  GLOBAL DETECTION PIPELINE v2.0
    //  Stage 1: Log Classification  (GLC)
    //  Stage 2: Normalize
    //  Stage 3: CEA Evidence Context build
    //  Stage 4: Logsource Gate (enforced in SigmaEngine via GLC)
    //  Stage 5: Detection (Sigma + UEBA)
    //  Stage 6: Behavioral Correlation Engine (BCE) — unified chains
    //  Stage 7: CEA Batch Validation (all detections)
    //  Stage 8: AI Enrichment + CEA re-validation
    //  Stage 9: IOC Enrichment
    //  Stage 10: MITRE Mapping (CEA final guard)
    //  Stage 11: Risk Scoring
    //  Stage 12: Attack Chain Reconstruction
    //  Stage 13: Timeline Building
    // ════════════════════════════════════════════════════════════════

    // ── Stage 1: Log Classification (GLC) ───────────────────────────
    // Every event gets a _meta block with { domain, subDomain, confidence }
    // This metadata is IMMUTABLE — downstream modules cannot change it.
    let classified;
    if (glc) {
      classified = glc.classifyBatch(safeEvents);
      const domainBreakdown = glc.getMetrics().domain_breakdown;
      console.log(`[RAYKAN/engine] GLC classified ${classified.length} events:`, JSON.stringify(domainBreakdown));
    } else {
      classified = safeEvents;
    }

    // ── Stage 2: Normalize (schema-tolerant) ────────────────────────
    const normalized = this._normalizeEvents(classified, context);
    results.processed = normalized.length;
    this._stats.eventsProcessed += normalized.length;

    // ── Stage 3: Build CEA EvidenceContext ──────────────────────────
    // Build ONCE per ingest call; ALL downstream stages reuse it.
    // This is the immutable evidence snapshot for this entire batch.
    const evidenceCtx = cea ? cea.buildEvidence(normalized) : null;
    results.evidenceFlags = evidenceCtx ? evidenceCtx.flags : {};

    // ── Stage 4 + 5: Parallel detection (Logsource Gate inside Sigma) ─
    // SigmaEngine enforces GLC logsource compatibility internally.
    // CEA post-evaluation is also applied inside sigma.detect().
    const [sigmaHits, anomalies] = await Promise.all([
      this.sigma.detect(normalized, { evidenceCtx }),
      this.ueba.analyzeEvents(normalized),
    ]);

    // ── Stage 6: Behavioral Correlation Engine (BCE) ──────────────────
    // BCE is the SINGLE global behavioral pipeline:
    //   Auth → Privilege Escalation → Persistence (Windows)
    //   SSH Brute → Root → Cron (Linux)
    //   Recon → Web Exploit → Shell (Web)
    //   Port Scan → Service Exploit → Exfil (Firewall)
    //   SQLi → Dump → Exfil (Database)
    //   Cross-domain chains linking all of the above
    // BCE emits CEA-pre-validated correlated detections.
    let bceResult = null;
    let bceDetections = [];
    if (bce) {
      try {
        bceResult = bce.correlate(normalized, sigmaHits, evidenceCtx);
        bceDetections = bceResult.correlatedDetections || [];

        if (bceResult.chains.length > 0) {
          console.log(`[RAYKAN/engine] BCE found ${bceResult.chains.length} behavioral chain(s), ` +
            `${bceResult.stats.crossDomainChains} cross-domain`);
          this._stats.bceChains = (this._stats.bceChains || 0) + bceResult.chains.length;
        }
      } catch (e) {
        console.warn('[RAYKAN/engine] BCE error:', e.message);
      }
    }

    // Supplemental correlation from context validator (Windows auth sequences)
    let contextCorrelated = [];
    if (contextValidator) {
      try {
        const rawCorr = contextValidator.buildCorrelatedDetections(normalized, sigmaHits);
        contextCorrelated = cea ? cea.validateBatch(rawCorr, normalized) : rawCorr;
      } catch (e) {
        console.warn('[RAYKAN/engine] Context validator correlation failed:', e.message);
      }
    }

    // ── Merge all detection streams ───────────────────────────────────
    // Order: Sigma → BCE → Context Validator supplemental
    const allRawDetections = [
      ...sigmaHits,
      ...bceDetections,
      ...contextCorrelated,
    ];

    // ── Stage 7: CEA Batch Validation (ALL detections) ────────────────
    // This is the PRIMARY enforcement point.
    // Every detection from every source passes through CEA.
    // No downstream module may re-add a CEA-suppressed technique.
    const ceaVerified = cea
      ? cea.validateBatch(allRawDetections, normalized)
      : allRawDetections;

    // ── Stage 8: AI Enrichment + CEA re-validation ────────────────────
    let aiEnhanced = ceaVerified;
    if (this.config.aiEnabled && ceaVerified.length > 0) {
      const aiRaw = await this.ai.enrichDetections(ceaVerified, normalized);
      // Re-apply CEA — AI cannot override CEA decisions
      aiEnhanced  = cea ? cea.validateBatch(aiRaw, normalized) : aiRaw;
    }

    // ── Stage 9: IOC enrichment ───────────────────────────────────────
    const enriched = await this.enricher.enrichBatch(aiEnhanced);

    // ── Stage 10: MITRE Mapping (CEA final guard inside mapDetection) ──
    const mapped = enriched.map(det => ({
      ...det,
      mitre: this.mitre.mapDetection(det, evidenceCtx),
    }));

    // ── ARCH-1: Detection deduplication (before risk scoring) ─────────
    // Deduplicate on composite key (eventId + techniqueId), keeping the
    // higher-confidence variant.  Prevents duplicate detections from
    // Sigma + BCE both firing on the same event+technique pair.
    const dedupedMapped = this._deduplicateDetections(mapped);

    // ── Stage 11: Risk Scoring ────────────────────────────────────────
    const scored = dedupedMapped.map(det => ({
      ...det,
      riskScore: this.scorer.scoreDetection(det, context),
    }));

    // ── Stage 12: Attack-chain reconstruction ─────────────────────────
    // Merge BCE chains with forensics-engine chains
    const forensicsChains = this.forensics.reconstructChains(scored, normalized);
    const bceChainsFinal  = bceResult ? bceResult.chains : [];
    const allChains       = [
      ...forensicsChains,
      ...bceChainsFinal.map(c => ({
        id          : c.id,
        label       : c.label,
        stages      : c.techniques.map(t => t.id),
        techniques  : c.techniques,
        domain      : c.domain,
        confidence  : c.confidence,
        eventCount  : c.events.length,
        crossDomain : c.domain === 'cross_domain',
        source      : 'bce',
      })),
    ];

    // ── Stage 13: Timeline building ───────────────────────────────────
    const timelineEvents = this.timeline.buildTimeline(normalized, scored);

    // ── Aggregate results — always plain arrays (never null/object) ───
    results.detections = normalizeDetections(scored,         'engine.scored');
    results.anomalies  = normalizeDetections(anomalies,      'engine.anomalies');
    results.chains     = normalizeDetections(allChains,      'engine.chains');
    results.timeline   = normalizeDetections(timelineEvents, 'engine.timeline');
    results.riskScore  = this.scorer.aggregateRisk(scored);
    results.duration   = Date.now() - startTs;

    // Observability: surface GLC, CEA, BCE metrics
    results.ceaMetrics = cea ? cea.getMetrics() : null;
    results.glcMetrics = glc ? glc.getMetrics()  : null;
    results.bceStats   = bceResult ? bceResult.stats : null;

    this._stats.detectionsTriggered += results.detections.length;
    this._stats.anomaliesFound      += results.anomalies.length;
    this._stats.chainsBuilt         += results.chains.length;

    // ── Emit real-time events — safe iteration on guaranteed arrays ──
    results.detections.forEach(det => this.emit('detection', det));
    results.anomalies.forEach(a    => this.emit('anomaly',   a));
    results.chains.forEach(c       => this.emit('chain:found', c));
    results.timeline.forEach(t     => this.emit('timeline:event', t));

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

  // ── Generate AI-Powered Detection Rule (v2.0 — prompt-safe) ─────
  async generateRule(description, examples = []) {
    const { buildRule, validateRuleOutput, sigmaQualityCheck, toSigmaYaml } =
      require('./sigma-rule-builder');

    // The AI detector now returns a fully validated rule (or safe template)
    const rule = await this.ai.generateSigmaRule(description, examples);

    // Post-process: Sigma structural validation via SigmaEngine
    const validated = await this.sigma.validateRule(rule);
    if (validated.valid) {
      await this.sigma.loadRuleFromObject(validated.rule);
      this._stats.rulesLoaded++;
    }

    // Quality check
    const quality = sigmaQualityCheck(rule);

    // Generate YAML if not already present
    const yaml = rule._yaml || toSigmaYaml(rule);

    return {
      rule,
      yaml,
      validation : validated,
      quality,
      builderMeta: rule._builderMeta || null,
    };
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
    const cvMetrics  = contextValidator ? contextValidator.getMetrics() : null;
    const ceaMetrics = cea ? cea.getMetrics() : null;
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
      ceaGating: ceaMetrics ? {
        active              : true,
        total_evaluated     : ceaMetrics.total_evaluated,
        allowed             : ceaMetrics.allowed,
        suppressed          : ceaMetrics.suppressed,
        downgraded          : ceaMetrics.downgraded,
        blocked_source      : ceaMetrics.blocked_source,
        keyword_blocked     : ceaMetrics.keyword_blocked,
        fp_reason_breakdown : ceaMetrics.fp_reason_breakdown,
      } : { active: false, reason: 'CEA module not loaded' },
      contextValidation: cvMetrics ? {
        suppressed_fp_count     : cvMetrics.suppressed_count,
        adjusted_detection_count: cvMetrics.adjusted_count,
        validated_count         : cvMetrics.validated_count,
        fp_reason_breakdown     : cvMetrics.fp_reasons,
      } : { available: false },
    };
  }

  // ── Internal: Normalize Events ───────────────────────────────────
  // Schema-tolerant: skips null/non-object entries without crashing
  _normalizeEvents(rawEvents, context) {
    return rawEvents
      .filter((evt) => {
        if (evt == null || typeof evt !== 'object') {
          console.warn('[RAYKAN][engine._normalizeEvents] skipping non-object event entry');
          return false;
        }
        return true;
      })
      .map((evt, idx) => {
      // ARCH #2 — Apply schema-registry profile FIRST so that any source-specific
      // aliases are promoted to top-level before the manual alias table runs.
      // This is non-destructive: applyProfile() returns a shallow copy.
      const evtR = schemaRegistry ? schemaRegistry.applyProfile(evt) : evt;

      const normalized = {
        id         : evtR.id         || crypto.randomUUID(),
        timestamp  : this._parseTimestamp(evtR.timestamp || evtR.ts || evtR.TimeCreated || Date.now()),
        source     : context.source || evtR.source || 'unknown',
        format     : context.format || this._detectFormat(evtR),
        tenant     : context.tenant || 'default',
        _schemaSource: evtR._schemaSource || 'unknown',  // schema registry stamp

        // Normalized common fields
        channel    : evtR.Channel  || evtR.channel    || evtR.log   || null,
        computer   : evtR.Computer || evtR.hostname   || evtR.host  || null,
        user       : evtR.User     || evtR.username   || evtR.user  || null,
        process    : evtR.ProcessName || evtR.process_name || evtR.Image
                   || evtR.process   || evtR.source_process || null,
        pid        : parseInt(evtR.ProcessId || evtR.pid || 0, 10),
        commandLine: evtR.CommandLine || evtR.cmd || evtR.command || null,
        parentProc : evtR.ParentProcessName || evtR.parent_process || null,
        srcIp      : evtR.SourceIp  || evtR.src_ip    || evtR.src   || null,
        dstIp      : evtR.DestinationIp || evtR.dest_ip || evtR.dst_ip || evtR.dst || null,
        srcPort    : parseInt(evtR.SourcePort || evtR.src_port || 0, 10) || null,
        dstPort    : parseInt(evtR.DestinationPort || evtR.dest_port || evtR.dst_port || 0, 10) || null,
        filePath   : evtR.TargetFilename || evtR.file_path || evtR.path || null,
        hash       : evtR.Hashes    || evtR.hash      || evtR.md5   || null,
        regKey     : evtR.TargetObject || evtR.registry_key || null,
        networkProto: evtR.Protocol || evtR.protocol || null,
        url        : evtR.Url       || evtR.url       || null,
        domain     : evtR.QueryName || evtR.domain    || null,

        // ── FIX #1 — EDR-style field aliases (v29-audit) ──────────────
        // Fields present in custom EDR telemetry but previously unmapped.
        // Without these, GLC classifies all custom events as 'unknown'
        // domain which blocks the Sigma logsource gate entirely.
        eventCategory : evtR.event_type        || evtR.eventCategory    || null,
        bytesSent     : parseInt(evtR.bytes_sent || 0, 10)              || null,
        targetProcess : evtR.target_process    || null,
        accessType    : evtR.access_type       || null,
        fileName      : evtR.file_name         || evtR.TargetFilename   || null,
        sourceHost    : evtR.source_host       || null,
        targetHost    : evtR.target_host       || evtR.dest_host        || null,

        // Raw fields preserved for advanced queries
        raw        : evt,   // keep original (pre-profile) raw for forensic fidelity
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

  // ── ARCH-1: Detection Deduplication ────────────────────────────────
  // Collapses detections sharing the same (eventId + techniqueId) pair,
  // keeping the higher-confidence variant.  Called before risk scoring.
  _deduplicateDetections(detections) {
    const seen    = new Map();
    const result  = [];

    for (const det of detections) {
      const techniques = det.mitre?.techniques || det.techniques || [];
      // Build one composite key per technique on this detection
      const techIds = techniques.length > 0
        ? techniques.map(t => t.id || t)
        : ['__no_technique__'];

      const evtId = det.eventId || det.event?.id || '';

      let dominated = false;
      for (const tid of techIds) {
        const key = `${evtId}|${tid}`;
        if (seen.has(key)) {
          // Replace existing entry only if this one has higher confidence
          const existingIdx = seen.get(key);
          if ((det.confidence || 0) > (result[existingIdx]?.confidence || 0)) {
            result[existingIdx] = det;
          }
          dominated = true;
        } else {
          seen.set(key, result.length);
        }
      }
      if (!dominated) result.push(det);
    }

    return result;
  }

  // ── ARCH-1: resetSession ─────────────────────────────────────────────
  // Clears all session-scoped state on sub-engines before each new ingest
  // call so that state from run N cannot bleed into run N+1.
  resetSession() {
    this._eventBuffer = [];
    this._sessionId   = (typeof crypto !== 'undefined' && crypto.randomUUID)
                        ? crypto.randomUUID() : Date.now().toString(36);
    this.ueba?.reset?.();
    this.scorer?.reset?.();
    this.enricher?.resetCache?.();
    normalizerMetrics?.reset?.();
    cea?.resetAuditLog?.();
    glc?.resetMetrics?.();
    bce?.resetMetrics?.();
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
    // normalizeDetections guarantees safe iteration even if shape changes
    const safeDets = normalizeDetections(results.detections, 'persist.detections');
    const insertions = safeDets.map(det => ({
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

// ── Static exports: utilities accessible as engine properties ────────────────
RaykanEngine.normalizeDetections = normalizeDetections;
RaykanEngine.parseRawInput       = parseRawInput;
RaykanEngine.processEvent        = processEvent;
RaykanEngine.normalizerMetrics   = normalizerMetrics;
RaykanEngine.contextValidator    = contextValidator;
RaykanEngine.cea                 = cea;  // Central Evidence Authority

module.exports = RaykanEngine;
