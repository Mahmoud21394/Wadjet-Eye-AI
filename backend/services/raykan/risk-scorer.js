/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Risk Scorer v1.0
 *
 *  Computes composite risk scores for:
 *   • Individual detections (0-100)
 *   • Entities (users, hosts, IPs, processes)
 *   • Active sessions / investigations
 *
 *  Scoring factors:
 *   • Sigma rule severity + confidence
 *   • MITRE technique criticality
 *   • IOC enrichment (VirusTotal hits, AbuseIPDB score)
 *   • UEBA anomaly signals
 *   • Attack-chain context (multi-stage = higher risk)
 *   • Peer-group comparison
 *   • Time-of-day multiplier (after-hours boost)
 *
 *  backend/services/raykan/risk-scorer.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ── Base severity weights ─────────────────────────────────────────
const SEVERITY_BASE = { critical: 90, high: 70, medium: 45, low: 20, informational: 5 };

// ── MITRE technique risk bonuses ──────────────────────────────────
const TECHNIQUE_BONUS = {
  'T1003.001': 25, // LSASS dump
  'T1486'    : 30, // Ransomware
  'T1550.002': 20, // Pass-the-hash
  'T1548.002': 18, // UAC bypass
  'T1190'    : 20, // RCE exploit
  'T1505.003': 25, // Web shell
  'T1059.001': 10, // PowerShell
  'T1490'    : 25, // Shadow copy deletion
  // FIX #6 — additional technique bonuses for APT kill-chain techniques
  'T1041'    : 20, // Exfiltration Over C2 Channel
  'T1560.001': 15, // Archive via Utility (staging before exfil)
};

class RiskScorer {
  constructor(config = {}) {
    this._config = config;
    this._entityRiskCache = new Map();
  }

  // ── Score a single detection ─────────────────────────────────────
  scoreDetection(detection, context = {}) {
    let score = SEVERITY_BASE[detection.severity] || 45;

    // Confidence modifier
    const confMod = (detection.confidence - 70) / 100;  // ±0.3 range
    score        += score * confMod;

    // MITRE technique bonus
    const techs = detection.mitre?.techniques || [];
    for (const tech of techs) {
      score += TECHNIQUE_BONUS[tech.id] || 0;
    }

    // FIX #6 — Volume-based risk multiplier (large byte transfers = higher risk)
    const bytes = parseInt(detection.bytesSent || detection.raw?.bytes_sent || 0, 10) || 0;
    if      (bytes > 100_000_000) score += 25;   // >100 MB
    else if (bytes > 10_000_000)  score += 12;   // >10 MB

    // IOC enrichment bonus
    if (detection.externalThreat > 50)  score += 15;
    if (detection.maliciousIOCs > 0)    score += 20;
    if (detection.iocEnrichments) {
      const maxScore = Math.max(...Object.values(detection.iocEnrichments).map(e => e?.threatScore || 0));
      score += maxScore * 0.2;
    }

    // AI verdict modifier
    if (detection.ai?.isMalicious === true)  score *= 1.2;
    if (detection.ai?.isMalicious === false) score *= 0.7;

    // After-hours multiplier
    if (context.afterHours) score *= 1.15;

    // Attack chain context
    if (context.inChain)    score *= 1.25;

    return Math.round(Math.min(100, Math.max(0, score)));
  }

  // ── Aggregate risk score for a list of detections ─────────────────
  aggregateRisk(detections) {
    if (!detections?.length) return 0;

    // Weighted sum (critical counts more)
    const weights  = detections.map(d => d.riskScore || this.scoreDetection(d));
    const maxScore = Math.max(...weights);
    const avgScore = weights.reduce((a,b) => a+b, 0) / weights.length;

    // Combine max and average (max dominates for critical threats)
    const combined = maxScore * 0.6 + avgScore * 0.4;

    // Multi-detection boost (more detections = higher overall risk)
    const countBoost = Math.min(20, detections.length * 2);

    return Math.round(Math.min(100, combined + countBoost));
  }

  // ── Score an entity ───────────────────────────────────────────────
  scoreEntity(entityId, evidence) {
    const detections = evidence.detections || [];
    const anomalies  = evidence.anomalies  || [];

    let score = this.aggregateRisk(detections);

    // Anomaly boost
    for (const a of anomalies) {
      score = Math.max(score, score + a.score * 0.2);
    }

    // Cache and return
    const result = Math.round(Math.min(100, score));
    this._entityRiskCache.set(entityId, { score: result, updatedAt: Date.now() });
    return result;
  }

  // ── Risk classification ───────────────────────────────────────────
  static classify(score) {
    if (score >= 80) return { label: 'Critical',   color: '#ef4444', priority: 1 };
    if (score >= 60) return { label: 'High',       color: '#f97316', priority: 2 };
    if (score >= 40) return { label: 'Medium',     color: '#eab308', priority: 3 };
    if (score >= 20) return { label: 'Low',        color: '#22c55e', priority: 4 };
    return              { label: 'Informational', color: '#6b7280', priority: 5 };
  }

  getEntityRisk(entityId) {
    return this._entityRiskCache.get(entityId) || null;
  }

  // FIX #8 — Session state reset
  reset() {
    this._entityRiskCache.clear();
  }
}

module.exports = RiskScorer;
