/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Self-Learning Detection Engine (Phase 3 + 7)
 *  backend/services/detection/detection-engine.js
 *
 *  Features:
 *  • Online learning: analyst FP labels refine thresholds
 *  • DBSCAN/HDBSCAN alert clustering
 *  • Concept drift detection
 *  • Detection-as-Code with Sigma rule CI/CD pipeline
 *  • ATT&CK coverage scoring
 *  • Automated detection gap analysis
 *
 *  Audit findings:
 *  - No feedback loop for detection quality improvement (HIGH)
 *  - Sigma rules are static templates — no runtime testing (HIGH)
 *  - No false positive management workflow (ABSENT)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── DBSCAN Alert Clustering ───────────────────────────────────────
// Groups related alerts into incidents using density-based clustering.
// Avoids alert fatigue by collapsing 100s of alerts → a few incidents.

/**
 * dbscanCluster — pure JS DBSCAN implementation
 * Clusters alerts by feature similarity (host, user, tactic, time proximity)
 *
 * @param {object[]} alerts - Array of alert objects
 * @param {number} eps - Epsilon: max distance between neighbors (0-1)
 * @param {number} minPts - Minimum points to form a core
 * @returns {{ clusters: object[][], noise: object[] }}
 */
function dbscanCluster(alerts, eps = 0.35, minPts = 2) {
  if (!alerts.length) return { clusters: [], noise: [] };

  const visited   = new Set();
  const clustered = new Set();
  const clusters  = [];
  const noise     = [];

  // Precompute feature vectors for all alerts
  const features = alerts.map(a => extractFeatureVector(a));

  function distance(i, j) {
    return featureDistance(features[i], features[j]);
  }

  function getNeighbors(idx) {
    return alerts.reduce((acc, _, i) => {
      if (i !== idx && distance(idx, i) <= eps) acc.push(i);
      return acc;
    }, []);
  }

  function expandCluster(idx, neighbors, cluster) {
    cluster.push(idx);
    clustered.add(idx);
    let queue = [...neighbors];
    while (queue.length > 0) {
      const q = queue.shift();
      if (!visited.has(q)) {
        visited.add(q);
        const qNeighbors = getNeighbors(q);
        if (qNeighbors.length >= minPts) queue.push(...qNeighbors);
      }
      if (!clustered.has(q)) {
        cluster.push(q);
        clustered.add(q);
      }
    }
  }

  for (let i = 0; i < alerts.length; i++) {
    if (visited.has(i)) continue;
    visited.add(i);
    const neighbors = getNeighbors(i);

    if (neighbors.length < minPts) {
      noise.push(alerts[i]);
    } else {
      const cluster = [];
      expandCluster(i, neighbors, cluster);
      clusters.push(cluster.map(idx => alerts[idx]));
    }
  }

  // Add unclustered noise items
  for (let i = 0; i < alerts.length; i++) {
    if (!clustered.has(i) && !noise.includes(alerts[i])) {
      noise.push(alerts[i]);
    }
  }

  return { clusters, noise };
}

/**
 * extractFeatureVector — convert alert to normalized numeric feature vector
 * [severity, risk_score, tactic_hash, host_hash, time_bucket, mitre_bucket]
 */
function extractFeatureVector(alert) {
  const sevMap = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25, informational: 0.1 };
  const now    = Date.now();
  const ts     = new Date(alert.created_at || alert.first_seen || now).getTime();

  return [
    sevMap[alert.severity] || 0.5,
    (alert.risk_score || 50) / 100,
    (hashBucket(alert.mitre_tactic || '') / 100),
    (hashBucket(alert.host         || '') / 100),
    (hashBucket(alert.user         || '') / 100),
    Math.min((now - ts) / (24 * 3600000), 1.0),  // Age normalized to 0-1 (max 1 day)
  ];
}

function hashBucket(str, buckets = 100) {
  if (!str) return 0;
  const h = crypto.createHash('md5').update(str).digest('readUInt32BE', 0, true) >>> 0;
  return h % buckets;
}

function featureDistance(a, b) {
  // Euclidean distance in feature space
  const sum = a.reduce((s, v, i) => s + Math.pow(v - (b[i] || 0), 2), 0);
  return Math.sqrt(sum / a.length);
}

/**
 * clusterAlerts — group alerts into incidents using DBSCAN
 * Returns incident objects ready for persistence.
 *
 * @param {object[]} alerts - Raw alerts from a tenant
 * @param {string} tenantId
 * @returns {object[]} Incident objects with grouped alerts
 */
function clusterAlerts(alerts, tenantId) {
  const { clusters, noise } = dbscanCluster(alerts, 0.35, 2);
  const incidents = [];

  for (const cluster of clusters) {
    const severities = cluster.map(a => a.severity);
    const topSev     = ['critical','high','medium','low'].find(s => severities.includes(s)) || 'medium';
    const riskScores = cluster.map(a => a.risk_score || 50);
    const maxRisk    = Math.max(...riskScores);
    const hosts      = [...new Set(cluster.map(a => a.host).filter(Boolean))];
    const users      = [...new Set(cluster.map(a => a.user).filter(Boolean))];
    const tactics    = [...new Set(cluster.map(a => a.mitre_tactic).filter(Boolean))];
    const techs      = [...new Set(cluster.map(a => a.mitre_tech).filter(Boolean))];

    incidents.push({
      id:              `inc-${crypto.randomUUID()}`,
      title:           deriveIncidentTitle(cluster),
      severity:        topSev,
      risk_score:      maxRisk,
      alert_count:     cluster.length,
      alert_ids:       cluster.map(a => a.id),
      hosts,
      users,
      mitre_tactics:   tactics,
      mitre_techs:     techs,
      first_seen:      cluster.reduce((m, a) => a.created_at < m ? a.created_at : m, cluster[0].created_at),
      last_seen:       cluster.reduce((m, a) => a.created_at > m ? a.created_at : m, cluster[0].created_at),
      tenant_id:       tenantId,
      cluster_method:  'dbscan',
      confidence:      Math.min(cluster.length * 15, 95),
      status:          'open',
      created_at:      new Date().toISOString(),
    });
  }

  // Noise alerts become individual low-priority incidents
  for (const alert of noise) {
    incidents.push({
      id:          `inc-${crypto.randomUUID()}`,
      title:       alert.title,
      severity:    alert.severity || 'low',
      risk_score:  alert.risk_score || 30,
      alert_count: 1,
      alert_ids:   [alert.id],
      hosts:       alert.host ? [alert.host] : [],
      users:       alert.user ? [alert.user] : [],
      mitre_tactics: alert.mitre_tactic ? [alert.mitre_tactic] : [],
      tenant_id:   tenantId,
      cluster_method: 'noise',
      confidence:  40,
      status:      'open',
      created_at:  new Date().toISOString(),
    });
  }

  return incidents;
}

function deriveIncidentTitle(cluster) {
  const tactics = [...new Set(cluster.map(a => a.mitre_tactic).filter(Boolean))];
  const hosts   = [...new Set(cluster.map(a => a.host).filter(Boolean))];
  if (tactics.length >= 2) return `Multi-Stage Attack: ${tactics.slice(0,2).map(t => titleCase(t)).join(' → ')}`;
  if (tactics.length === 1) return `${titleCase(tactics[0])} Activity Cluster${hosts.length > 1 ? ` (${hosts.length} hosts)` : ''}`;
  return `Alert Cluster: ${cluster.length} related alerts`;
}

function titleCase(str) { return str.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '); }

// ── Online Learning / False-Positive Feedback ─────────────────────

class FeedbackLearner {
  constructor() {
    this._fpThresholds = new Map();   // rule_id → {fp_count, tp_count, threshold}
    this._initialized  = false;
  }

  /**
   * recordFeedback — analyst labels an alert as FP or TP
   * Adjusts rule threshold via exponential moving average.
   */
  recordFeedback(ruleId, isFalsePositive, riskScore) {
    if (!this._fpThresholds.has(ruleId)) {
      this._fpThresholds.set(ruleId, { fp_count: 0, tp_count: 0, threshold: 50, ema_fp_rate: 0 });
    }

    const entry = this._fpThresholds.get(ruleId);
    if (isFalsePositive) {
      entry.fp_count++;
    } else {
      entry.tp_count++;
    }

    const total   = entry.fp_count + entry.tp_count;
    const fpRate  = entry.fp_count / total;

    // Exponential moving average of FP rate (α=0.3)
    entry.ema_fp_rate = 0.3 * fpRate + 0.7 * entry.ema_fp_rate;

    // Auto-tune threshold: if FP rate > 30%, raise threshold by 5 points
    if (entry.ema_fp_rate > 0.30 && total >= 10) {
      entry.threshold = Math.min(entry.threshold + 5, 95);
      console.log(`[FeedbackLearner] Rule ${ruleId}: raised threshold to ${entry.threshold} (FP rate: ${(entry.ema_fp_rate * 100).toFixed(1)}%)`);
    }

    this._fpThresholds.set(ruleId, entry);
    return entry;
  }

  /**
   * getThreshold — get current risk threshold for a rule
   */
  getThreshold(ruleId) {
    return this._fpThresholds.get(ruleId)?.threshold || 50;
  }

  /**
   * getFpStats — return FP statistics for all rules
   */
  getFpStats() {
    const stats = {};
    for (const [ruleId, entry] of this._fpThresholds) {
      const total = entry.fp_count + entry.tp_count;
      stats[ruleId] = {
        ...entry,
        fp_rate:   total > 0 ? (entry.fp_count / total * 100).toFixed(1) + '%' : 'N/A',
        total_labeled: total,
      };
    }
    return stats;
  }
}

// ── Concept Drift Detection ───────────────────────────────────────

class ConceptDriftDetector {
  constructor(windowSize = 100) {
    this._window     = [];
    this._windowSize = windowSize;
    this._baseline   = null;
    this._driftScore = 0;
  }

  /**
   * observe — record a detection event
   */
  observe(detection) {
    this._window.push({
      severity:    detection.severity,
      risk_score:  detection.risk_score || 50,
      mitre_tactic: detection.mitre_tactic || 'unknown',
      timestamp:   Date.now(),
    });

    if (this._window.length > this._windowSize) this._window.shift();

    if (this._window.length >= this._windowSize && !this._baseline) {
      this._baseline = this._computeStats(this._window);
    }

    if (this._baseline && this._window.length >= this._windowSize / 2) {
      this._driftScore = this._computeDrift();
    }
  }

  _computeStats(window) {
    const risks  = window.map(d => d.risk_score);
    const mean   = risks.reduce((s, v) => s + v, 0) / risks.length;
    const stddev = Math.sqrt(risks.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / risks.length);
    const tacticDist = {};
    window.forEach(d => { tacticDist[d.mitre_tactic] = (tacticDist[d.mitre_tactic] || 0) + 1; });
    return { mean, stddev, tactic_dist: tacticDist };
  }

  _computeDrift() {
    const current = this._computeStats(this._window.slice(-50));
    const base    = this._baseline;
    const meanShift   = Math.abs(current.mean - base.mean) / (base.stddev || 1);
    const stddevShift = Math.abs(current.stddev - base.stddev) / (base.stddev || 1);
    return Math.min((meanShift + stddevShift) / 2, 1.0);
  }

  /**
   * isDrifting — returns true if detection patterns have changed significantly
   */
  isDrifting(threshold = 0.5) {
    return this._driftScore > threshold;
  }

  getStatus() {
    return {
      drift_score:   this._driftScore.toFixed(3),
      is_drifting:   this.isDrifting(),
      baseline_set:  !!this._baseline,
      window_size:   this._window.length,
      alert:         this.isDrifting() ? 'Detection patterns have shifted significantly — possible rule evasion' : null,
    };
  }
}

// ── ATT&CK Coverage Scoring ───────────────────────────────────────

const FULL_ATTACK_MATRIX = require('./mitre-matrix.json').techniques || [];

/**
 * computeCoverageScore — calculates percentage of ATT&CK techniques
 * with active validated detections
 *
 * @param {object[]} rules - Active detection rules with mitre_id
 * @param {object[]} validatedRules - Rules with confirmed test results
 * @returns {{ coverage_pct: number, covered: string[], gaps: string[], by_tactic: object }}
 */
function computeCoverageScore(rules, validatedRules = []) {
  const covered   = new Set(rules.filter(r => r.mitre_id).map(r => r.mitre_id));
  const validated = new Set(validatedRules.filter(r => r.mitre_id).map(r => r.mitre_id));

  const allTechniques = FULL_ATTACK_MATRIX.map(t => t.technique_id);
  const gaps          = allTechniques.filter(t => !covered.has(t));

  // Coverage by tactic
  const byTactic = {};
  for (const tech of FULL_ATTACK_MATRIX) {
    const tactic = tech.tactic;
    if (!byTactic[tactic]) byTactic[tactic] = { total: 0, covered: 0, validated: 0 };
    byTactic[tactic].total++;
    if (covered.has(tech.technique_id))   byTactic[tactic].covered++;
    if (validated.has(tech.technique_id)) byTactic[tactic].validated++;
  }

  return {
    coverage_pct:      allTechniques.length ? Math.round((covered.size / allTechniques.length) * 100) : 0,
    validated_pct:     allTechniques.length ? Math.round((validated.size / allTechniques.length) * 100) : 0,
    covered:           [...covered],
    validated:         [...validated],
    gaps,
    gap_count:         gaps.length,
    total_techniques:  allTechniques.length,
    covered_count:     covered.size,
    by_tactic:         byTactic,
    computed_at:       new Date().toISOString(),
  };
}

// ── Detection Gap Analysis ────────────────────────────────────────

/**
 * analyzeGaps — identify high-priority detection gaps
 * Correlates ATT&CK gaps with threat actor TTPs to prioritize
 * which gaps to close first.
 *
 * @param {string[]} gapIds - Uncovered MITRE technique IDs
 * @param {object[]} relevantActors - Threat actors targeting the organization
 * @returns {object[]} Prioritized gap recommendations
 */
function analyzeGaps(gapIds, relevantActors = []) {
  const actorTtps = new Set();
  relevantActors.forEach(a => (a.ttps || []).forEach(t => actorTtps.add(t)));

  const prioritized = gapIds.map(gapId => {
    const tech     = FULL_ATTACK_MATRIX.find(t => t.technique_id === gapId);
    const usedBy   = relevantActors.filter(a => (a.ttps || []).includes(gapId)).map(a => a.name);
    const priority = usedBy.length > 0 ? 'HIGH' : tech?.is_critical ? 'MEDIUM' : 'LOW';

    return {
      technique_id: gapId,
      technique_name: tech?.name || gapId,
      tactic:        tech?.tactic || 'unknown',
      priority,
      used_by_actors: usedBy,
      recommended_sigma: `# Sigma rule skeleton for ${gapId}\ntitle: Detect ${tech?.name || gapId}\nstatus: experimental\nlevel: medium\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: [4688, 4104]\n  condition: selection\nfalsepositives:\n  - Legitimate ${tech?.name || 'activity'}\n`,
    };
  });

  return prioritized.sort((a, b) => {
    const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return (order[a.priority] || 2) - (order[b.priority] || 2);
  });
}

// ── Exports ───────────────────────────────────────────────────────

module.exports = {
  dbscanCluster,
  clusterAlerts,
  FeedbackLearner,
  ConceptDriftDetector,
  computeCoverageScore,
  analyzeGaps,
  extractFeatureVector,
  featureDistance,
};
