/**
 * ETI-AARE Dynamic Risk Scoring Engine v1.0
 * Weighted multi-dimensional risk model combining:
 * - Rule-based detection signals
 * - AI confidence scores
 * - Threat intel reputation data
 * - Behavioral patterns
 * - Contextual factors
 */

'use strict';

// ─── Risk Dimension Weights ──────────────────────────────────────────────────
const RISK_WEIGHTS = {
  // Primary signals
  auth_failure:          { base: 25, spf_fail: 8, dkim_fail: 8, dmarc_fail: 12 },
  rule_detections:       { critical: 35, high: 20, medium: 10, low: 3 },
  ai_confidence:         0.35,  // AI score multiplier
  threat_intel:          { malicious_hash: 50, malicious_ip: 30, malicious_domain: 25, malicious_url: 35 },

  // Supporting signals
  sender_anomalies:      { display_mismatch: 15, reply_to_mismatch: 20, spf_fail: 10, no_auth: 8 },
  social_engineering:    { bec_pattern: 25, financial_lure: 20, credential_harvesting: 22, urgency: 10 },
  attachment:            { critical: 40, high: 25, double_ext: 30, macro: 20 },
  url:                   { homograph: 30, ip_url: 20, redirect: 15, lookalike: 35 },
  routing:               { suspicious_hops: 5 },  // per hop

  // Context amplifiers
  amplifiers: {
    multiple_indicators:  1.3,  // >3 different indicator types
    targeted_attack:      1.4,  // spear-phishing signals
    bec_confirmed:        1.5,  // confirmed BEC pattern
    malware_combo:        1.3,  // attachment + URL combo
    auth_all_fail:        1.25  // all three auth protocols failed
  },

  // Max cap
  max_score: 100
};

// ─── Risk Tiers ──────────────────────────────────────────────────────────────
const RISK_TIERS = [
  { level: 'critical', min: 80, color: '#ff2d55', action: 'quarantine_and_block', sla_minutes: 15 },
  { level: 'high',     min: 60, color: '#ff6b35', action: 'quarantine',           sla_minutes: 30 },
  { level: 'medium',   min: 35, color: '#ffd60a', action: 'flag_for_review',      sla_minutes: 120 },
  { level: 'low',      min: 15, color: '#30d158', action: 'monitor',              sla_minutes: 480 },
  { level: 'clean',    min: 0,  color: '#636366', action: 'allow',                sla_minutes: null }
];

// ─── Risk Scoring Engine ──────────────────────────────────────────────────────
class RiskScoringEngine {
  constructor(config = {}) {
    this.weights = { ...RISK_WEIGHTS, ...config.weights };
    this.tiers = config.tiers || RISK_TIERS;
    this.history = new Map(); // sender history for behavioral scoring
  }

  /**
   * Compute comprehensive risk score from all available signals
   */
  score(parsedEmail, detectionResult, enrichmentResult) {
    const breakdown = {};
    let rawScore = 0;

    // ── 1. Authentication Failures ──
    breakdown.auth = this._scoreAuth(parsedEmail.auth);
    rawScore += breakdown.auth.score;

    // ── 2. Rule Detection Score ──
    breakdown.rules = this._scoreRuleDetections(detectionResult?.detections || []);
    rawScore += breakdown.rules.score;

    // ── 3. AI Classification Score ──
    breakdown.ai = this._scoreAI(detectionResult?.ai_classification);
    rawScore += breakdown.ai.score;

    // ── 4. Threat Intelligence Score ──
    breakdown.threat_intel = this._scoreThreatIntel(enrichmentResult?.summary);
    rawScore += breakdown.threat_intel.score;

    // ── 5. Sender Anomaly Score ──
    breakdown.sender = this._scoreSenderAnomalies(parsedEmail.sender?.anomalies || []);
    rawScore += breakdown.sender.score;

    // ── 6. Social Engineering Score ──
    breakdown.social_eng = this._scoreSocialEngineering(
      parsedEmail.body?.social_engineering_flags || [],
      parsedEmail.body?.urgency_score || 0
    );
    rawScore += breakdown.social_eng.score;

    // ── 7. Attachment Score ──
    breakdown.attachments = this._scoreAttachments(parsedEmail.attachments || []);
    rawScore += breakdown.attachments.score;

    // ── 8. URL Score ──
    breakdown.urls = this._scoreUrls(parsedEmail.body?.urls || []);
    rawScore += breakdown.urls.score;

    // ── 9. Routing Score ──
    breakdown.routing = this._scoreRouting(parsedEmail.routing);
    rawScore += breakdown.routing.score;

    // ── 10. BEC Behavioral Score ──
    breakdown.bec = this._scoreBEC(detectionResult?.bec_analysis);
    rawScore += breakdown.bec.score;

    // ── Apply Amplifiers ──
    const amplifier = this._computeAmplifier(parsedEmail, detectionResult, breakdown);
    const amplifiedScore = rawScore * amplifier.factor;
    breakdown.amplifier = amplifier;

    // ── Final Score ──
    const finalScore = Math.min(Math.round(amplifiedScore), this.weights.max_score);

    // ── Determine Risk Tier ──
    const tier = this._getTier(finalScore);

    // ── Confidence Intervals ──
    const confidence = this._computeConfidence(breakdown, detectionResult);

    // ── Behavioral Context ──
    const behavioral = this._behavioralContext(parsedEmail, finalScore);

    return {
      final_score: finalScore,
      raw_score: Math.round(rawScore),
      amplified_score: Math.round(amplifiedScore),
      amplifier: amplifier.factor,
      tier: tier.level,
      color: tier.color,
      recommended_action: tier.action,
      sla_minutes: tier.sla_minutes,
      confidence: confidence,
      breakdown,
      behavioral,
      scored_at: new Date().toISOString(),
      score_version: '1.0'
    };
  }

  _scoreAuth(auth) {
    if (!auth) return { score: 0, details: {} };
    const w = this.weights.auth_failure;
    let score = 0;
    const details = {};

    if (auth.spf === 'fail') { score += w.spf_fail; details.spf = 'fail'; }
    else if (auth.spf === 'softfail') { score += w.spf_fail * 0.5; details.spf = 'softfail'; }
    if (auth.dkim === 'fail') { score += w.dkim_fail; details.dkim = 'fail'; }
    if (auth.dmarc === 'fail') { score += w.dmarc_fail; details.dmarc = 'fail'; }
    if (auth.spf === 'none' && auth.dkim === 'none') { score += 5; details.note = 'no_auth'; }

    return { score: Math.min(score, 30), details, label: 'Authentication Failures' };
  }

  _scoreRuleDetections(detections) {
    const w = this.weights.rule_detections;
    let score = 0;
    const by_severity = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const d of detections) {
      const sev = d.severity;
      if (by_severity[sev] !== undefined) by_severity[sev]++;
    }

    // Score with diminishing returns
    score += Math.min(by_severity.critical * w.critical, 50);
    score += Math.min(by_severity.high * w.high, 30);
    score += Math.min(by_severity.medium * w.medium, 15);
    score += Math.min(by_severity.low * w.low, 5);

    return {
      score: Math.min(score, 55),
      by_severity,
      total_rules: detections.length,
      label: 'Rule Detections'
    };
  }

  _scoreAI(aiClass) {
    if (!aiClass || !aiClass.confidence) return { score: 0, label: 'AI Classification' };
    const multiplier = this.weights.ai_confidence;
    const threatTypes = ['phishing', 'bec', 'malware_delivery', 'suspicious'];
    const isThreat = threatTypes.includes(aiClass.threat_type);
    const score = isThreat ? aiClass.confidence * multiplier : 0;

    return {
      score: Math.min(Math.round(score), 35),
      ai_confidence: aiClass.confidence,
      threat_type: aiClass.threat_type,
      label: 'AI Classification'
    };
  }

  _scoreThreatIntel(summary) {
    if (!summary) return { score: 0, label: 'Threat Intel' };
    const w = this.weights.threat_intel;
    let score = 0;

    score += summary.malicious_hashes * w.malicious_hash;
    score += summary.malicious_ips * w.malicious_ip;
    score += summary.malicious_domains * w.malicious_domain;
    score += summary.malicious_urls * w.malicious_url;

    return {
      score: Math.min(score, 60),
      malicious_count: summary.malicious_ips + summary.malicious_domains + summary.malicious_urls + summary.malicious_hashes,
      intel_score: summary.threat_intel_score || 0,
      label: 'Threat Intelligence'
    };
  }

  _scoreSenderAnomalies(anomalies) {
    const w = this.weights.sender_anomalies;
    let score = 0;
    const types = anomalies.map(a => a.type);

    if (types.includes('display_name_domain_mismatch')) score += w.display_mismatch;
    if (types.includes('from_reply_to_domain_mismatch')) score += w.reply_to_mismatch;
    if (types.includes('spf_fail')) score += w.spf_fail;
    if (types.includes('no_authentication')) score += w.no_auth;
    if (types.includes('dmarc_fail')) score += 12;

    return { score: Math.min(score, 30), anomaly_count: anomalies.length, label: 'Sender Anomalies' };
  }

  _scoreSocialEngineering(seFlags, urgencyScore) {
    const w = this.weights.social_engineering;
    let score = 0;

    for (const flag of seFlags) {
      const flagName = flag.flag || flag;
      if (flagName === 'bec_pattern') score += w.bec_pattern;
      else if (flagName === 'financial_lure') score += w.financial_lure;
      else if (flagName === 'credential_harvesting') score += w.credential_harvesting;
      else score += 5;
    }

    score += (urgencyScore / 100) * w.urgency;

    return {
      score: Math.min(score, 35),
      urgency_score: urgencyScore,
      flag_count: seFlags.length,
      label: 'Social Engineering'
    };
  }

  _scoreAttachments(attachments) {
    const w = this.weights.attachment;
    let score = 0;

    for (const att of attachments) {
      if (att.threat_level === 'critical') score += w.critical;
      else if (att.threat_level === 'high') score += w.high;
      if (att.flags?.includes('double_extension_attack')) score += w.double_ext;
      if (att.extension === 'docm' || att.extension === 'xlsm') score += w.macro;
    }

    return {
      score: Math.min(score, 50),
      attachment_count: attachments.length,
      critical_count: attachments.filter(a => a.threat_level === 'critical').length,
      label: 'Attachments'
    };
  }

  _scoreUrls(urls) {
    const w = this.weights.url;
    let score = 0;

    for (const url of urls) {
      const techniques = url.techniques || [];
      if (techniques.includes('homograph_domain')) score += w.homograph;
      if (techniques.includes('ip_url')) score += w.ip_url;
      if (techniques.includes('redirect_service')) score += w.redirect;
      if (url.is_suspicious) score += 5;
    }

    // Domain risk
    // handled in rule detections for lookalike

    return {
      score: Math.min(score, 40),
      url_count: urls.length,
      suspicious_count: urls.filter(u => u.is_suspicious).length,
      label: 'URL Analysis'
    };
  }

  _scoreRouting(routing) {
    if (!routing) return { score: 0, label: 'Routing' };
    const score = (routing.suspicious_hops || 0) * this.weights.routing.suspicious_hops;
    return { score: Math.min(score, 15), suspicious_hops: routing.suspicious_hops, label: 'Email Routing' };
  }

  _scoreBEC(becAnalysis) {
    if (!becAnalysis?.is_bec) return { score: 0, label: 'BEC Analysis' };
    const score = Math.min(becAnalysis.confidence * 0.3, 30);
    return {
      score: Math.round(score),
      intents: becAnalysis.intents_detected,
      confidence: becAnalysis.confidence,
      label: 'BEC Behavioral Analysis'
    };
  }

  _computeAmplifier(email, detection, breakdown) {
    const amp = this.weights.amplifiers;
    let factor = 1.0;
    const applied = [];

    // Multiple malicious indicators
    const indicatorTypes = [breakdown.threat_intel.malicious_count > 0,
      breakdown.auth.score > 20, breakdown.attachments.critical_count > 0,
      breakdown.urls.suspicious_count > 0].filter(Boolean).length;
    if (indicatorTypes >= 3) { factor *= amp.multiple_indicators; applied.push('multiple_indicators'); }

    // All auth failed
    if (email.auth?.spf === 'fail' && email.auth?.dkim === 'fail' && email.auth?.dmarc === 'fail') {
      factor *= amp.auth_all_fail; applied.push('auth_all_fail');
    }

    // BEC confirmed
    if (detection?.bec_analysis?.is_bec && detection?.detections?.some(d => d.type === 'bec')) {
      factor *= amp.bec_confirmed; applied.push('bec_confirmed');
    }

    // Attachment + URL combo (dropper pattern)
    if (breakdown.attachments.attachment_count > 0 && breakdown.urls.url_count > 0 && breakdown.attachments.score > 20) {
      factor *= amp.malware_combo; applied.push('malware_combo');
    }

    // Spear-phishing signals
    const spearPhishingRules = (detection?.detections || []).filter(d => d.type === 'bec' || d.rule_id === 'ETI-SPOOF-003');
    if (spearPhishingRules.length > 0) { factor *= amp.targeted_attack; applied.push('targeted_attack'); }

    return { factor: Math.round(factor * 100) / 100, applied };
  }

  _computeConfidence(breakdown, detection) {
    // Confidence = consistency of signals
    const signalCount = Object.values(breakdown).filter(b => b?.score > 0).length;
    const aiConf = detection?.ai_classification?.confidence || 0;
    const baseConf = Math.min(signalCount * 15, 70);
    const combined = Math.min(baseConf + aiConf * 0.3, 95);
    return Math.round(combined);
  }

  _behavioralContext(email, score) {
    const senderKey = email.sender?.domain || email.sender?.address;
    let history = this.history.get(senderKey) || { seen_count: 0, threat_count: 0, avg_score: 0 };

    history.seen_count++;
    if (score > 35) history.threat_count++;
    history.avg_score = Math.round((history.avg_score * (history.seen_count - 1) + score) / history.seen_count);
    this.history.set(senderKey, history);

    return {
      sender_history: {
        total_emails: history.seen_count,
        threat_emails: history.threat_count,
        threat_rate: history.seen_count > 0 ? Math.round((history.threat_count / history.seen_count) * 100) : 0,
        avg_risk_score: history.avg_score
      },
      is_repeat_offender: history.threat_count > 2,
      first_seen: history.first_seen || new Date().toISOString()
    };
  }

  _getTier(score) {
    return this.tiers.find(t => score >= t.min) || this.tiers[this.tiers.length - 1];
  }

  getScoreTiers() { return this.tiers; }
}

module.exports = { RiskScoringEngine, RISK_WEIGHTS, RISK_TIERS };
