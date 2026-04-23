/**
 * ETI-AARE Main Orchestrator v1.0
 * Email Threat Intelligence, Analysis & Autonomous Response Engine
 * Coordinates all microservices in the detection pipeline
 */

'use strict';

const EventEmitter = require('events');
const { EmailParser } = require('./email-parser');
const { ThreatDetectionEngine } = require('./threat-detection-engine');
const { ThreatIntelEnrichmentService } = require('./threat-intel-enrichment');
const { RiskScoringEngine } = require('./risk-scoring-engine');
const { SOARResponseEngine } = require('./soar-response-engine');
const { AIExplainabilityEngine, AttackGraphEngine, BehavioralIdentityFingerprinter } = require('./innovative-features');

class ETIAAREngine extends EventEmitter {
  constructor(config = {}) {
    super();

    this.version = '1.0.0';
    this.config = config;

    // ── Initialize all service layers ──
    this.parser = new EmailParser();  // Static class, used directly

    this.detector = new ThreatDetectionEngine({
      enableAI: config.enableAI !== false,
      llmProvider: config.llmProvider || null,
      customRules: config.customRules || []
    });

    this.enricher = new ThreatIntelEnrichmentService({
      virustotal_api_key: config.virustotal_api_key || process.env.VIRUSTOTAL_API_KEY,
      abuseipdb_api_key: config.abuseipdb_api_key || process.env.ABUSEIPDB_API_KEY,
      urlscan_api_key: config.urlscan_api_key || process.env.URLSCAN_API_KEY
    });

    this.riskScorer = new RiskScoringEngine(config.riskConfig || {});

    this.soar = new SOARResponseEngine({
      auto_response_enabled: config.auto_response_enabled !== false,
      dry_run: config.dry_run || false,
      integrations: { realtime: this }  // Use EventEmitter for real-time events
    });

    this.explainer = new AIExplainabilityEngine();
    this.attackGraph = new AttackGraphEngine();
    this.fingerprinter = new BehavioralIdentityFingerprinter();

    // ── Statistics ──
    this.stats = {
      total_analyzed: 0,
      threats_detected: 0,
      clean: 0,
      by_tier: { critical: 0, high: 0, medium: 0, low: 0, clean: 0 },
      by_type: {},
      avg_processing_time: 0,
      start_time: new Date().toISOString()
    };

    this.initialized = true;
    this.emit('ready', { version: this.version });
  }

  /**
   * Primary analysis pipeline — process a single email through all layers
   * @param {Object} rawEmail - Raw email from any source (M365, Gmail, .eml, manual)
   * @param {string} source - Source identifier
   * @returns {Object} Complete analysis result
   */
  async analyze(rawEmail, source = 'manual') {
    const startTime = Date.now();
    const analysisId = `ETI-${Date.now().toString(36).toUpperCase()}`;

    try {
      // ═══ PHASE 1: Parse ═══
      const parsedEmail = EmailParser.parse(rawEmail, source);

      // ═══ PHASE 2: Behavioral Fingerprinting ═══
      const behavioralResult = this.fingerprinter.processEmail(parsedEmail);

      // ═══ PHASE 3: Threat Detection ═══
      const detectionResult = await this.detector.detect(parsedEmail);

      // ═══ PHASE 4: Threat Intel Enrichment ═══
      const enrichmentResult = await this.enricher.enrich(parsedEmail);

      // ═══ PHASE 5: Risk Scoring ═══
      const riskScore = this.riskScorer.score(parsedEmail, detectionResult, enrichmentResult);

      // ═══ PHASE 6: AI Explainability ═══
      const explanation = this.explainer.explain(parsedEmail, detectionResult, riskScore, enrichmentResult);

      // ═══ PHASE 7: Attack Graph ═══
      const graphResult = this.attackGraph.addEmail(parsedEmail, detectionResult, enrichmentResult);

      // ═══ PHASE 8: SOAR Response ═══
      const soarResponse = await this.soar.respond(parsedEmail, detectionResult, riskScore, enrichmentResult);

      // ═══ ASSEMBLE RESULT ═══
      const result = {
        analysis_id: analysisId,
        source,
        email: {
          message_id: parsedEmail.message_id,
          from: parsedEmail.sender?.address,
          from_display: parsedEmail.sender?.display_name,
          subject: parsedEmail.subject,
          received_at: parsedEmail.received_at,
          auth: parsedEmail.auth,
          routing_hops: parsedEmail.routing?.hop_count,
          attachment_count: parsedEmail.attachments?.length,
          url_count: parsedEmail.body?.urls?.length,
          indicators: parsedEmail.indicators
        },
        detection: {
          rules_triggered: detectionResult.detections,
          ai_classification: detectionResult.ai_classification,
          bec_analysis: detectionResult.bec_analysis,
          mitre_techniques: detectionResult.mitre_techniques,
          final_verdict: detectionResult.final_verdict
        },
        enrichment: enrichmentResult,
        risk: riskScore,
        explanation,
        behavioral: behavioralResult,
        attack_graph: graphResult,
        response: soarResponse,
        processing_time_ms: Date.now() - startTime,
        analyzed_at: new Date().toISOString()
      };

      // ── Update statistics ──
      this._updateStats(result);

      // ── Emit real-time event ──
      this.emit('analysis:complete', {
        analysis_id: analysisId,
        tier: riskScore.tier,
        score: riskScore.final_score,
        type: detectionResult.final_verdict?.primary_type,
        from: parsedEmail.sender?.address
      });

      if (riskScore.tier === 'critical' || riskScore.tier === 'high') {
        this.emit('threat:detected', result);
      }

      return result;
    } catch (err) {
      this.emit('error', { analysis_id: analysisId, error: err.message, source });
      throw err;
    }
  }

  /**
   * Batch analysis for multiple emails
   */
  async analyzeBatch(emails, source = 'batch') {
    const results = await Promise.allSettled(
      emails.map(e => this.analyze(e, source))
    );

    return {
      total: emails.length,
      successful: results.filter(r => r.status === 'fulfilled').length,
      failed: results.filter(r => r.status === 'rejected').length,
      results: results.map((r, i) => ({
        index: i,
        success: r.status === 'fulfilled',
        data: r.status === 'fulfilled' ? r.value : null,
        error: r.status === 'rejected' ? r.reason?.message : null
      }))
    };
  }

  /**
   * Get current system statistics
   */
  getStats() {
    const detector_stats = this.detector.getStats();
    const fingerprint_stats = this.fingerprinter.getStats();
    const cache_stats = this.enricher.getCacheStats();

    return {
      ...this.stats,
      detector: detector_stats,
      fingerprinting: fingerprint_stats,
      cache: cache_stats,
      blocklists: this.soar.getBlocklists().totals,
      quarantine_count: this.soar.getQuarantine().length,
      open_incidents: this.soar.getIncidents().filter(i => i.status === 'open').length,
      attack_graph: {
        nodes: this.attackGraph.nodes.size,
        edges: this.attackGraph.edges.length,
        campaigns: this.attackGraph.campaigns.size
      }
    };
  }

  _updateStats(result) {
    this.stats.total_analyzed++;
    const tier = result.risk?.tier;
    if (tier === 'clean') this.stats.clean++;
    else this.stats.threats_detected++;

    if (tier) this.stats.by_tier[tier] = (this.stats.by_tier[tier] || 0) + 1;

    const type = result.detection?.final_verdict?.primary_type;
    if (type) this.stats.by_type[type] = (this.stats.by_type[type] || 0) + 1;

    const totalTime = this.stats.avg_processing_time * (this.stats.total_analyzed - 1) + result.processing_time_ms;
    this.stats.avg_processing_time = Math.round(totalTime / this.stats.total_analyzed);
  }
}

// Singleton instance
let _instance = null;
function getInstance(config) {
  if (!_instance) _instance = new ETIAAREngine(config);
  return _instance;
}

module.exports = { ETIAAREngine, getInstance };
