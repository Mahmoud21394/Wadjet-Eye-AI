/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Self-Learning Detection Engine (Phase 3)
 *  backend/services/detection/self-learning.js
 *
 *  Implements:
 *  • Analyst feedback loop (TP/FP labeling → rule weight adjustment)
 *  • Automated detection tuning (threshold drift, suppression)
 *  • Baseline deviation learning (normal vs. anomalous behaviour)
 *  • Rule effectiveness scoring
 *  • Auto-suppress high-FP rules pending review
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── Rule weight store (in-memory cache + persistent via DB) ───────
class RuleWeightStore {
  constructor() {
    this._cache   = new Map();  // ruleId → { weight, fp_count, tp_count, last_updated }
    this._dirty   = new Set();  // rule IDs needing DB flush
  }

  get(ruleId) {
    return this._cache.get(ruleId) || { weight: 1.0, fp_count: 0, tp_count: 0, suppressed: false };
  }

  update(ruleId, delta) {
    const current  = this.get(ruleId);
    const updated  = { ...current, ...delta, last_updated: new Date().toISOString() };
    this._cache.set(ruleId, updated);
    this._dirty.add(ruleId);
    return updated;
  }

  markSuppressed(ruleId, suppressed = true) {
    const current = this.get(ruleId);
    return this.update(ruleId, { ...current, suppressed, suppressed_at: suppressed ? new Date().toISOString() : null });
  }

  dirtyEntries() {
    return [...this._dirty].map(id => ({ rule_id: id, ...this._cache.get(id) }));
  }

  clearDirty() {
    this._dirty.clear();
  }

  async loadFromDb(db) {
    if (!db) return;
    const { data } = await db.from('rule_weights').select('*');
    if (data) {
      for (const row of data) {
        this._cache.set(row.rule_id, {
          weight:       row.weight,
          fp_count:     row.fp_count,
          tp_count:     row.tp_count,
          suppressed:   row.suppressed,
          last_updated: row.last_updated,
        });
      }
    }
  }

  async flushToDb(db) {
    if (!db || this._dirty.size === 0) return;
    const entries = this.dirtyEntries();
    const { error } = await db
      .from('rule_weights')
      .upsert(entries, { onConflict: 'rule_id' });
    if (!error) this.clearDirty();
    return error;
  }
}

const weightStore = new RuleWeightStore();

// ── Process analyst feedback ──────────────────────────────────────
// Called when analyst labels an alert as TP, FP, benign, or escalated
async function processFeedback(alertId, feedback, db) {
  const { outcome, analyst_id, rule_ids = [], confidence_override = null } = feedback;

  const results = [];

  for (const ruleId of rule_ids) {
    const current = weightStore.get(ruleId);

    let newWeight  = current.weight;
    let fp_count   = current.fp_count;
    let tp_count   = current.tp_count;

    // Bayesian weight update
    switch (outcome) {
      case 'true_positive':
        tp_count++;
        // Increase weight (up to max 2.0)
        newWeight = Math.min(2.0, current.weight + 0.05);
        break;
      case 'false_positive':
        fp_count++;
        // Decrease weight (down to min 0.1)
        newWeight = Math.max(0.1, current.weight - 0.1);
        break;
      case 'benign':
        // Small decrease — not truly FP but not valuable
        newWeight = Math.max(0.3, current.weight - 0.03);
        break;
      case 'escalated':
        tp_count++;
        newWeight = Math.min(2.0, current.weight + 0.08);
        break;
    }

    const total    = tp_count + fp_count;
    const fp_rate  = total > 0 ? fp_count / total : 0;

    // Auto-suppress: if FP rate > 70% and total >= 10 samples
    const autoSuppress = fp_rate > 0.7 && total >= 10;

    const updated = weightStore.update(ruleId, {
      weight:    Math.round(newWeight * 1000) / 1000,
      fp_count,
      tp_count,
      suppressed: autoSuppress || current.suppressed,
    });

    results.push({
      rule_id:      ruleId,
      outcome,
      new_weight:   updated.weight,
      fp_rate:      Math.round(fp_rate * 100),
      auto_suppressed: autoSuppress,
      recommendation: _tuningRecommendation(ruleId, updated, fp_rate),
    });
  }

  // Persist feedback to DB
  if (db) {
    await Promise.allSettled([
      db.from('alert_feedback').insert({
        alert_id:    alertId,
        analyst_id,
        outcome,
        rule_ids:    JSON.stringify(rule_ids),
        labeled_at:  new Date().toISOString(),
      }),
      weightStore.flushToDb(db),
    ]);
  }

  return {
    alert_id: alertId,
    feedback_processed: results,
    timestamp: new Date().toISOString(),
  };
}

// ── Tuning recommendation ─────────────────────────────────────────
function _tuningRecommendation(ruleId, entry, fpRate) {
  if (entry.suppressed) {
    return `SUPPRESS: Rule ${ruleId} auto-suppressed (FP rate ${Math.round(fpRate * 100)}%). Requires analyst review before re-enabling.`;
  }
  if (fpRate > 0.5) {
    return `TUNE: High FP rate (${Math.round(fpRate * 100)}%) — consider tightening threshold or adding exclusions for rule ${ruleId}.`;
  }
  if (fpRate < 0.1 && entry.tp_count >= 5) {
    return `PROMOTE: Low FP rate — rule ${ruleId} performing well. Consider increasing sensitivity.`;
  }
  return null;
}

// ── Anomaly baseline engine ────────────────────────────────────────
class BaselineLearner {
  constructor(opts = {}) {
    this.windowDays  = opts.windowDays  || 14;
    this.stdDevMult  = opts.stdDevMult  || 3.0;   // z-score threshold
    this._baselines  = new Map();  // metricKey → { mean, stdDev, count, lastUpdated }
  }

  // ── Update baseline for a metric ─────────────────────────────
  update(key, value) {
    const current = this._baselines.get(key) || { mean: value, stdDev: 0, count: 0, sum: 0, sumSq: 0 };

    current.count++;
    current.sum   += value;
    current.sumSq += value * value;
    current.mean   = current.sum / current.count;
    current.stdDev = current.count > 1
      ? Math.sqrt((current.sumSq / current.count) - current.mean ** 2)
      : 0;
    current.lastUpdated = new Date().toISOString();

    this._baselines.set(key, current);
    return current;
  }

  // ── Check if value is anomalous ───────────────────────────────
  isAnomaly(key, value) {
    const baseline = this._baselines.get(key);
    if (!baseline || baseline.count < 30) {
      return { anomalous: false, reason: 'Insufficient baseline data' };
    }

    const zScore    = baseline.stdDev > 0
      ? Math.abs(value - baseline.mean) / baseline.stdDev
      : 0;
    const anomalous = zScore > this.stdDevMult;

    return {
      anomalous,
      z_score:    Math.round(zScore * 100) / 100,
      threshold:  this.stdDevMult,
      baseline_mean:   Math.round(baseline.mean * 100) / 100,
      baseline_stddev: Math.round(baseline.stdDev * 100) / 100,
      current_value:   value,
      deviation_pct:   baseline.mean > 0 ? Math.round(((value - baseline.mean) / baseline.mean) * 100) : null,
    };
  }

  // ── UEBA: check user behaviour anomaly ───────────────────────
  checkUserAnomaly(userId, metric, value) {
    const key = `user:${userId}:${metric}`;
    this.update(key, value);
    const result = this.isAnomaly(key, value);
    return { user_id: userId, metric, ...result };
  }

  // ── Network anomaly detection ────────────────────────────────
  checkNetworkAnomaly(srcIp, metric, value) {
    const key = `net:${srcIp}:${metric}`;
    this.update(key, value);
    const result = this.isAnomaly(key, value);
    return { src_ip: srcIp, metric, ...result };
  }

  getBaselines() {
    const out = {};
    for (const [key, val] of this._baselines) {
      out[key] = {
        mean:    Math.round(val.mean * 100) / 100,
        stdDev:  Math.round(val.stdDev * 100) / 100,
        count:   val.count,
        lastUpdated: val.lastUpdated,
      };
    }
    return out;
  }
}

const baselineLearner = new BaselineLearner();

// ── Rule effectiveness report ────────────────────────────────────
async function computeRuleEffectiveness(db, windowDays = 30) {
  if (!db) return [];
  const since = new Date(Date.now() - windowDays * 86_400_000).toISOString();

  const { data: alerts } = await db
    .from('alerts')
    .select('rule_id, outcome, severity, created_at')
    .gte('created_at', since)
    .not('outcome', 'is', null);

  if (!alerts || alerts.length === 0) return [];

  const ruleMap = {};
  for (const alert of alerts) {
    const rid = alert.rule_id;
    if (!rid) continue;
    if (!ruleMap[rid]) ruleMap[rid] = { rule_id: rid, total: 0, tp: 0, fp: 0, critical: 0, high: 0 };
    ruleMap[rid].total++;
    if (alert.outcome === 'true_positive')  ruleMap[rid].tp++;
    if (alert.outcome === 'false_positive') ruleMap[rid].fp++;
    if (alert.severity === 'CRITICAL') ruleMap[rid].critical++;
    if (alert.severity === 'HIGH')     ruleMap[rid].high++;
  }

  return Object.values(ruleMap).map(r => {
    const fp_rate  = r.total > 0 ? Math.round((r.fp / r.total) * 100) : null;
    const tp_rate  = r.total > 0 ? Math.round((r.tp / r.total) * 100) : null;
    const weight   = weightStore.get(r.rule_id);

    return {
      ...r,
      fp_rate,
      tp_rate,
      current_weight: weight.weight,
      suppressed:     weight.suppressed || false,
      health:         fp_rate !== null && fp_rate > 60 ? 'NEEDS_TUNING' : fp_rate !== null && fp_rate < 20 ? 'HEALTHY' : 'ACCEPTABLE',
    };
  }).sort((a, b) => (b.fp_rate || 0) - (a.fp_rate || 0));
}

// ── Automated threshold tuning suggestions ────────────────────────
function generateTuningSuggestions(ruleEffectiveness) {
  const suggestions = [];

  for (const rule of ruleEffectiveness) {
    if (rule.suppressed) {
      suggestions.push({
        rule_id:    rule.rule_id,
        type:       'REVIEW_SUPPRESSED',
        priority:   'HIGH',
        action:     `Review suppressed rule ${rule.rule_id} — it was auto-suppressed due to high FP rate.`,
        fp_rate:    rule.fp_rate,
      });
    } else if (rule.fp_rate > 60 && rule.total >= 10) {
      suggestions.push({
        rule_id:    rule.rule_id,
        type:       'TIGHTEN_THRESHOLD',
        priority:   'HIGH',
        action:     `Rule ${rule.rule_id} has ${rule.fp_rate}% FP rate. Add exclusions or increase confidence threshold by 10-20%.`,
        fp_rate:    rule.fp_rate,
        tp_rate:    rule.tp_rate,
      });
    } else if (rule.fp_rate < 5 && rule.tp_rate > 80 && rule.total >= 20) {
      suggestions.push({
        rule_id:    rule.rule_id,
        type:       'INCREASE_SENSITIVITY',
        priority:   'LOW',
        action:     `Rule ${rule.rule_id} is highly accurate (${rule.tp_rate}% TP). Consider lowering threshold to catch more variants.`,
        fp_rate:    rule.fp_rate,
        tp_rate:    rule.tp_rate,
      });
    }
  }

  return suggestions.sort((a, b) => (a.priority === 'HIGH' ? -1 : 1));
}

module.exports = {
  weightStore,
  baselineLearner,
  processFeedback,
  computeRuleEffectiveness,
  generateTuningSuggestions,
  RuleWeightStore,
  BaselineLearner,
};
