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
      // ── RFC 2047 subject decode (pure function, unit-testable) ──
      const subjectDecoded = _decodeRfc2047(parsedEmail.subject || '');

      // ── Body content score from social engineering signals ──
      const bodySignals   = _extractBodySignals(parsedEmail);
      const bodyScore     = Math.min(bodySignals.reduce((a, s) => a + s.weight, 0), 100);

      // ── Forensic timeline from routing hops ──
      const forensicTimeline = (parsedEmail.routing?.hops || []).map((h, i) => ({
        hop:         i + 1,
        from_server: h.from_host || h.by_host || '(unknown)',
        from_ip:     h.from_ip || null,
        to_server:   h.by_host || '(destination)',
        timestamp:   h.timestamp || parsedEmail.received_at,
        delay_ms:    h.delay_seconds ? h.delay_seconds * 1000 : 0,
        suspicious:  h.is_suspicious || false
      }));

      const result = {
        analysis_id: analysisId,
        source,
        email: {
          message_id:        parsedEmail.message_id,
          from:              parsedEmail.sender?.address,
          from_display:      parsedEmail.sender?.display_name,
          subject:           parsedEmail.subject,
          subject_decoded:   subjectDecoded,
          subject_analysis:  parsedEmail.subject_analysis,
          received_at:       parsedEmail.received_at,
          auth:              parsedEmail.auth,
          routing_hops:      parsedEmail.routing?.hop_count,
          attachment_count:  parsedEmail.attachments?.length,
          url_count:         parsedEmail.body?.urls?.length,
          indicators:        parsedEmail.indicators,
          // FIX-001: recipients
          recipients: {
            to:            parsedEmail.recipients?.to   || [],
            cc:            parsedEmail.recipients?.cc   || [],
            bcc:           parsedEmail.recipients?.bcc  || [],
            reply_to:      parsedEmail.sender?.reply_to || '',
            x_original_to: parsedEmail.headers?.['x-original-to'] || ''
          },
          // FIX-003: body content analysis
          body_content_score: bodyScore,
          body_signals:       bodySignals,
          body_plain:         parsedEmail.body?.text || '',
          decoded_body:       parsedEmail.body?.html || parsedEmail.body?.text || '',
          // FIX-004: MIME tree
          mime_parts: (parsedEmail.attachments || []).map((a, i) => ({
            part:              i + 2,
            content_type:      a.content_type || 'application/octet-stream',
            transfer_encoding: a.encoding     || 'base64',
            size_bytes:        a.size         || 0,
            filename:          a.filename     || null
          })),
          // ENHANCE-002: Forensic timeline
          forensic_timeline: forensicTimeline,
          // Raw headers string
          raw_headers: _buildRawHeaders(parsedEmail)
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

// ── Pure Helper Functions (unit-testable) ────────────────────────────────────

/**
 * RFC 2047 encoded-word decoder
 * Handles =?charset?B?base64?= and =?charset?Q?quoted-printable?=
 * @param {string} str - Raw header value
 * @returns {string} Decoded string
 */
function _decodeRfc2047(str) {
  if (!str || !str.includes('=?')) return str;
  return str.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (match, charset, encoding, encoded) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        // Base64
        return Buffer.from(encoded, 'base64').toString('utf8');
      } else {
        // Quoted-Printable
        const qp = encoded.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16)));
        return qp;
      }
    } catch {
      return match; // leave as-is on decode error
    }
  });
}

/**
 * Extract body content signals for Content Intent Score
 * Signal IDs follow CS-{CATEGORY}-{SEQ} convention
 * @param {Object} parsedEmail - Parsed email from EmailParser
 * @returns {Array<{id, signal, text, weight, fp_risk}>}
 */
function _extractBodySignals(parsedEmail) {
  const signals = [];
  const text = (parsedEmail.body?.text || parsedEmail.body?.html || '').toLowerCase();
  if (!text) return signals;

  // Financial urgency signals — weight 15, low FP risk
  const financialPatterns = [
    { pattern: /wire transfer|bank transfer|western union|money gram/,  id: 'CS-FIN-001', signal: 'wire_transfer_request',    weight: 25, fp_risk: 'low'    },
    { pattern: /invoice|payment (due|required|overdue)/,               id: 'CS-FIN-002', signal: 'invoice_payment_demand',   weight: 15, fp_risk: 'medium' },
    { pattern: /gift card|itunes card|amazon card/,                    id: 'CS-FIN-003', signal: 'gift_card_scam',           weight: 20, fp_risk: 'low'    },
    { pattern: /account (will be|has been) (suspended|terminated|locked)/, id: 'CS-FIN-004', signal: 'account_suspension_threat', weight: 15, fp_risk: 'low' }
  ];

  // Authority impersonation — weight 20, low FP risk
  const authPatterns = [
    { pattern: /ceo|chief executive|president|director/,               id: 'CS-AUTH-001', signal: 'authority_invocation',   weight: 15, fp_risk: 'medium' },
    { pattern: /microsoft|google|apple|paypal|amazon security/,        id: 'CS-AUTH-002', signal: 'brand_impersonation',    weight: 20, fp_risk: 'low'    },
    { pattern: /it (department|support|helpdesk)|security team/,       id: 'CS-AUTH-003', signal: 'it_authority_claim',     weight: 12, fp_risk: 'medium' }
  ];

  // Secrecy/urgency — weight 10-15
  const urgencyPatterns = [
    { pattern: /confidential|do not (share|discuss|tell)/,             id: 'CS-SEC-001', signal: 'secrecy_demand',          weight: 20, fp_risk: 'low'    },
    { pattern: /urgent|immediately|as soon as possible|asap/,          id: 'CS-URG-001', signal: 'urgency_keywords',        weight: 10, fp_risk: 'medium' },
    { pattern: /within (24|48|72) hours|deadline|expire/,              id: 'CS-URG-002', signal: 'deadline_pressure',       weight: 12, fp_risk: 'medium' },
    { pattern: /click (here|the link|below)|verify (your|account)/,    id: 'CS-ACT-001', signal: 'action_demanded',         weight: 18, fp_risk: 'low'    },
    { pattern: /confirm (your|account|identity|details)/,              id: 'CS-ACT-002', signal: 'identity_confirmation',   weight: 15, fp_risk: 'low'    }
  ];

  const allPatterns = [...financialPatterns, ...authPatterns, ...urgencyPatterns];
  for (const p of allPatterns) {
    const m = text.match(p.pattern);
    if (m) {
      // Extract the matched text snippet (up to 60 chars)
      const idx   = text.indexOf(m[0]);
      const snip  = text.substring(Math.max(0, idx - 5), Math.min(text.length, idx + m[0].length + 5)).trim();
      signals.push({ id: p.id, signal: p.signal, text: snip.substring(0, 60), weight: p.weight, fp_risk: p.fp_risk });
    }
  }

  // Also include social engineering flags from parser
  (parsedEmail.body?.social_engineering_flags || []).forEach((f, i) => {
    const name = typeof f === 'string' ? f : (f.flag || 'social_engineering');
    if (!signals.some(s => s.signal === name)) {
      signals.push({ id: `CS-SE-${String(i+1).padStart(3,'0')}`, signal: name, text: '', weight: 10, fp_risk: 'medium' });
    }
  });

  return signals;
}

/**
 * Reconstruct a simplified raw headers string from parsedEmail
 * @param {Object} parsedEmail
 * @returns {string}
 */
function _buildRawHeaders(parsedEmail) {
  const lines = [];
  const h = parsedEmail.headers || {};
  const push = (name, val) => { if (val) lines.push(`${name}: ${val}`); };
  push('From',                   parsedEmail.sender?.raw || parsedEmail.sender?.address);
  push('To',                     (parsedEmail.recipients?.to || []).map(r => r.raw || r.address).join(', '));
  push('Reply-To',               parsedEmail.sender?.reply_to);
  push('Subject',                parsedEmail.subject);
  push('Date',                   parsedEmail.received_at);
  push('Message-ID',             parsedEmail.message_id);
  push('Authentication-Results', h['authentication-results']);
  push('Received',               h['received']);
  push('Return-Path',            h['return-path']);
  push('X-Mailer',               parsedEmail.sender?.x_mailer);
  push('X-Originating-IP',       parsedEmail.sender?.x_originating_ip);
  return lines.join('\r\n');
}

module.exports = { ETIAAREngine, getInstance, _decodeRfc2047, _extractBodySignals };
