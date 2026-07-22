/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 *  js/ueba.js — UEBA / Anomaly Detection  (Phase 2, AiSOC v7.6.0 port)
 *  Ported from:
 *    services/ueba/app/services/baseline.py   — Welford online algorithm
 *    services/ueba/app/services/scoring.py    — composite score, risk levels
 *    services/ueba/app/services/peer_group.py — peer-group deviation
 *
 *  This is a NATIVE TypeScript-compatible ES5/CJS rewrite.
 *  No Python, no new services, no containers.
 *  DB backend: Supabase table `we_entity_baselines` + `we_peer_groups`
 *              + `we_ueba_anomalies`  (see we_phase2_fusion_ueba.sql)
 *
 *  Feature flag: process.env.ENABLE_UEBA  (default FALSE → shadow mode)
 *  Shadow mode:  anomalies written to we_ueba_anomalies with shadow_mode=TRUE
 *                and we_ueba_composite / we_ueba_risk_level written back to
 *                the alert row; NO suppression / escalation action taken.
 *
 *  Exports (CommonJS / browser window.WEUEBA):
 *    welfordUpdate(stats, feature, value)   → updated stats object
 *    computeZScore(stats, feature, value)   → float
 *    compositeScore(scoredFeatures)         → float [0–10]
 *    riskLevel(score, threshold)            → 'critical'|'high'|'medium'|'low'
 *    scoreEntityEvent(opts)                 → Promise<UEBAScoringResult>
 *    updateEntityBaseline(opts)             → Promise<void>
 *    getOrCreateBaseline(opts)              → Promise<BaselineRow>
 *    getOrCreatePeerGroup(opts)             → Promise<PeerGroupRow>
 *    updatePeerGroup(opts)                  → Promise<void>
 *    peerGroupDeviationScore(opts)          → Promise<float|null>
 *    isUEBAEnabled()                        → boolean
 *
 *  Anomaly threshold default: 2.0  (matches AiSOC settings.anomaly_threshold)
 *  Peer group min size default: 5   (matches AiSOC settings.peer_group_min_size)
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

/* ─────────────────────────────────────────────────────────────────────────────
   Feature flag
───────────────────────────────────────────────────────────────────────────── */

/**
 * Returns true only when the env var is explicitly set to a truthy string.
 * Default is FALSE — every anomaly is written in shadow mode until
 * operators review baselines and perform the go/no-go.
 */
function isUEBAEnabled() {
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env.ENABLE_UEBA;
    return v === '1' || v === 'true' || v === 'TRUE';
  }
  if (typeof window !== 'undefined' && window.ENABLE_UEBA !== undefined) {
    return Boolean(window.ENABLE_UEBA);
  }
  return false;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Constants  (match AiSOC config/settings defaults)
───────────────────────────────────────────────────────────────────────────── */

const ANOMALY_THRESHOLD    = 2.0;   // medium risk floor
const PEER_GROUP_MIN_SIZE  = 5;     // minimum observations before peer dev is trusted
const COMPOSITE_SCORE_CAP  = 10.0;  // max composite (matches _composite_score cap)

/* ─────────────────────────────────────────────────────────────────────────────
   Welford Online Algorithm
   Ported verbatim from baseline.py::_welford_update()
───────────────────────────────────────────────────────────────────────────── */

/**
 * Update the running Welford statistics for one feature with a new value.
 *
 * stats shape (matches we_entity_baselines.feature_stats JSONB):
 *   { "<feature>": { "n": int, "mean": float, "M2": float, "std": float } }
 *
 * NOTE: AiSOC source uses the key "count"; we normalise to "n" here (matches
 * the migration column comment) but keep a "count" alias for read compat.
 *
 * @param {Object} stats   - mutable stats object (will be modified in-place)
 * @param {string} feature - feature name
 * @param {number} value   - new observation
 * @returns {Object} the same stats object (mutated)
 */
function welfordUpdate(stats, feature, value) {
  if (!stats[feature]) {
    stats[feature] = { n: 0, mean: 0.0, M2: 0.0, std: 0.0 };
  }

  const s = stats[feature];
  s.n += 1;
  const n     = s.n;
  const delta  = value - s.mean;
  s.mean      += delta / n;
  const delta2 = value - s.mean;   // uses the UPDATED mean — per Welford
  s.M2        += delta * delta2;

  // Variance only meaningful for n > 1
  const variance = n > 1 ? s.M2 / (n - 1) : 0.0;
  s.std = Math.sqrt(variance);

  // Backwards compat alias: AiSOC Python source calls it "count"
  s.count = s.n;

  return stats;
}

/**
 * Compute z-score of value given the stored baseline stats for one feature.
 * Returns 0 when the feature is unknown or std < epsilon (stable baseline).
 * Ported from baseline.py::compute_z_score()
 *
 * @param {Object} stats   - feature_stats object from we_entity_baselines
 * @param {string} feature
 * @param {number} value
 * @returns {number}
 */
function computeZScore(stats, feature, value) {
  if (!stats || !stats[feature]) return 0.0;
  const s   = stats[feature];
  const std = s.std !== undefined ? s.std : 0.0;
  if (std < 1e-9) return 0.0;
  return Math.abs(value - s.mean) / std;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Composite Score  (ported from scoring.py::_composite_score)
───────────────────────────────────────────────────────────────────────────── */

/**
 * Root-sum-of-squares of per-feature z-scores, capped at 10.
 *
 * scoredFeatures shape: { "<feature>": { z_score: float, ... }, ... }
 *
 * @param {Object} scoredFeatures
 * @returns {number} composite score in [0, 10]
 */
function compositeScore(scoredFeatures) {
  if (!scoredFeatures || Object.keys(scoredFeatures).length === 0) return 0.0;

  const sumSq = Object.values(scoredFeatures).reduce((acc, f) => {
    const z = typeof f.z_score === 'number' ? f.z_score : 0;
    return acc + z * z;
  }, 0);

  return Math.min(Math.sqrt(sumSq), COMPOSITE_SCORE_CAP);
}

/* ─────────────────────────────────────────────────────────────────────────────
   Risk Level  (ported from scoring.py::_risk_level)
───────────────────────────────────────────────────────────────────────────── */

/**
 * Map composite score → risk label.
 * Thresholds: ≥6.0=critical, ≥4.0=high, ≥threshold=medium, else low
 *
 * @param {number} score
 * @param {number} [threshold=ANOMALY_THRESHOLD]
 * @returns {'critical'|'high'|'medium'|'low'}
 */
function riskLevel(score, threshold) {
  const t = typeof threshold === 'number' ? threshold : ANOMALY_THRESHOLD;
  if (score >= 6.0) return 'critical';
  if (score >= 4.0) return 'high';
  if (score >= t)   return 'medium';
  return 'low';
}

/* ─────────────────────────────────────────────────────────────────────────────
   Supabase helpers — baseline
───────────────────────────────────────────────────────────────────────────── */

/**
 * Fetch or create a we_entity_baselines row.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase   - Supabase service-role client
 * @param {string} opts.tenantId
 * @param {string} opts.entityType - e.g. 'user', 'host', 'ip'
 * @param {string} opts.entityId   - the actual identifier value
 * @returns {Promise<Object>} the row
 */
async function getOrCreateBaseline({ supabase, tenantId, entityType, entityId }) {
  const { data, error } = await supabase
    .from('we_entity_baselines')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('entity_type', entityType)
    .eq('entity_id', entityId)
    .maybeSingle();

  if (error) throw new Error(`UEBA getOrCreateBaseline: ${error.message}`);

  if (data) return data;

  // Create new baseline row with empty stats
  const now = new Date().toISOString();
  const { data: created, error: insErr } = await supabase
    .from('we_entity_baselines')
    .insert({
      tenant_id:    tenantId,
      entity_type:  entityType,
      entity_id:    entityId,
      feature_stats: {},
      window_start:  now,
      window_end:    now,
    })
    .select()
    .single();

  if (insErr) {
    // Race condition — another request created it; re-fetch
    const { data: refetch } = await supabase
      .from('we_entity_baselines')
      .select('*')
      .eq('tenant_id', tenantId)
      .eq('entity_type', entityType)
      .eq('entity_id', entityId)
      .single();
    if (refetch) return refetch;
    throw new Error(`UEBA getOrCreateBaseline insert: ${insErr.message}`);
  }

  return created;
}

/**
 * Incrementally update the entity baseline with new feature observations.
 * Uses Welford in-place; upserts the full feature_stats JSONB back.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase
 * @param {string} opts.tenantId
 * @param {string} opts.entityType
 * @param {string} opts.entityId
 * @param {Object} opts.features  - { featureName: numericValue, ... }
 */
async function updateEntityBaseline({ supabase, tenantId, entityType, entityId, features }) {
  const row   = await getOrCreateBaseline({ supabase, tenantId, entityType, entityId });
  // Deep-copy so we can mutate freely
  const stats = JSON.parse(JSON.stringify(row.feature_stats || {}));

  for (const [feat, val] of Object.entries(features)) {
    welfordUpdate(stats, feat, Number(val));
  }

  const { error } = await supabase
    .from('we_entity_baselines')
    .update({
      feature_stats: stats,
      window_end:    new Date().toISOString(),
    })
    .eq('tenant_id', tenantId)
    .eq('entity_type', entityType)
    .eq('entity_id', entityId);

  if (error) throw new Error(`UEBA updateEntityBaseline: ${error.message}`);
}

/**
 * Score an event's features against the stored baseline (non-mutating read).
 * Returns per-feature z-scores with supporting stats.
 *
 * @param {Object} opts
 * @returns {Promise<Object>}  { featureName: { value, mean, std, z_score }, ... }
 */
async function scoreEntityFeatures({ supabase, tenantId, entityType, entityId, features }) {
  const row   = await getOrCreateBaseline({ supabase, tenantId, entityType, entityId });
  const stats = row.feature_stats || {};
  const scored = {};

  for (const [feat, val] of Object.entries(features)) {
    const z       = computeZScore(stats, feat, Number(val));
    const fStats  = stats[feat] || {};
    scored[feat]  = {
      value:   Number(val),
      mean:    fStats.mean  || 0.0,
      std:     fStats.std   || 0.0,
      z_score: z,
    };
  }

  return scored;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Supabase helpers — peer group
───────────────────────────────────────────────────────────────────────────── */

/**
 * Fetch or create a we_peer_groups row.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase
 * @param {string} opts.tenantId
 * @param {string} opts.entityType
 * @param {string} opts.peerGroupLabel  - the group label / external ID
 * @returns {Promise<Object>}
 */
async function getOrCreatePeerGroup({ supabase, tenantId, entityType, peerGroupLabel }) {
  const { data, error } = await supabase
    .from('we_peer_groups')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('entity_type', entityType)
    .eq('label', peerGroupLabel)
    .maybeSingle();

  if (error) throw new Error(`UEBA getOrCreatePeerGroup: ${error.message}`);
  if (data) return data;

  const { data: created, error: insErr } = await supabase
    .from('we_peer_groups')
    .insert({
      tenant_id:     tenantId,
      entity_type:   entityType,
      label:         peerGroupLabel,
      member_count:  0,
      feature_stats: {},
    })
    .select()
    .single();

  if (insErr) {
    // Race — re-fetch
    const { data: refetch } = await supabase
      .from('we_peer_groups')
      .select('*')
      .eq('tenant_id', tenantId)
      .eq('entity_type', entityType)
      .eq('label', peerGroupLabel)
      .single();
    if (refetch) return refetch;
    throw new Error(`UEBA getOrCreatePeerGroup insert: ${insErr.message}`);
  }

  return created;
}

/**
 * Add one member's observations to the peer-group aggregate.
 * Ported from peer_group.py::PeerGroupService.update()
 */
async function updatePeerGroup({ supabase, tenantId, entityType, peerGroupLabel, features }) {
  const row   = await getOrCreatePeerGroup({ supabase, tenantId, entityType, peerGroupLabel });
  const stats = JSON.parse(JSON.stringify(row.feature_stats || {}));

  for (const [feat, val] of Object.entries(features)) {
    welfordUpdate(stats, feat, Number(val));
  }

  // member_count = n of the first feature (consistent with AiSOC source)
  const firstFeat = Object.keys(stats)[0];
  const memberCount = firstFeat ? (stats[firstFeat].n || 0) : row.member_count;

  const { error } = await supabase
    .from('we_peer_groups')
    .update({
      feature_stats: stats,
      member_count:  memberCount,
    })
    .eq('tenant_id', tenantId)
    .eq('entity_type', entityType)
    .eq('label', peerGroupLabel);

  if (error) throw new Error(`UEBA updatePeerGroup: ${error.message}`);
}

/**
 * Return a composite deviation score [0–10] for how far the given features
 * deviate from the peer group mean.
 * Returns null if group doesn't exist or hasn't reached minimum sample size.
 * Ported from peer_group.py::PeerGroupService.deviation_score()
 *
 * @param {Object} opts
 * @returns {Promise<number|null>}
 */
async function peerGroupDeviationScore({ supabase, tenantId, peerGroupLabel, features }) {
  const { data: group, error } = await supabase
    .from('we_peer_groups')
    .select('feature_stats, member_count')
    .eq('tenant_id', tenantId)
    .eq('label', peerGroupLabel)
    .maybeSingle();

  if (error || !group) return null;

  const stats = group.feature_stats || {};
  if (!Object.keys(stats).length) return null;

  // Check minimum sample size against the first feature's n
  const firstStatN = Object.values(stats)[0].n || 0;
  if (firstStatN < PEER_GROUP_MIN_SIZE) return null;

  // Compute RSS of z-scores vs. peer group
  const zScores = Object.entries(features)
    .filter(([feat]) => stats[feat])
    .map(([feat, val]) => computeZScore(stats, feat, Number(val)));

  if (!zScores.length) return null;

  const rss = Math.sqrt(zScores.reduce((s, z) => s + z * z, 0));
  return Math.min(rss, COMPOSITE_SCORE_CAP);
}

/* ─────────────────────────────────────────────────────────────────────────────
   Main scoring entry point
   Ported from scoring.py::ScoringService.score_event()
───────────────────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} UEBAScoringResult
 * @property {string}      entityType
 * @property {string}      entityId
 * @property {string|null} alertId
 * @property {Object}      scoredFeatures   - per-feature z-scores
 * @property {number}      personalComposite
 * @property {number|null} peerDeviation
 * @property {number}      blendedScore
 * @property {string}      riskLevel        - 'critical'|'high'|'medium'|'low'
 * @property {boolean}     isAnomalous
 * @property {boolean}     shadowMode
 * @property {string|null} anomalyId        - UUID of inserted we_ueba_anomalies row (null if below threshold)
 */

/**
 * Full scoring pipeline for one entity event.
 *
 * Steps (mirroring AiSOC ScoringService.score_event):
 *   1. Score features against personal baseline (non-mutating)
 *   2. Update personal baseline with this event's observations
 *   3. If peerGroupLabel given: compute peer deviation, blend
 *   4. If peerGroupLabel given: update peer group aggregate
 *   5. Classify risk level
 *   6. If composite >= threshold: persist anomaly row (shadow_mode by default)
 *   7. Return full result for alert-fusion to attach
 *
 * @param {Object}      opts
 * @param {Object}      opts.supabase
 * @param {string}      opts.tenantId
 * @param {string}      opts.entityType       - 'user' | 'host' | 'ip' | etc.
 * @param {string}      opts.entityId
 * @param {Object}      opts.features         - { featureName: numericValue, ... }
 * @param {string}      [opts.alertId]        - UUID of the parent alert (for FK)
 * @param {string}      [opts.peerGroupLabel] - optional peer group
 * @param {number}      [opts.anomalyThreshold=2.0]
 * @param {boolean}     [opts.forceActive=false] - bypass shadow when true (go/no-go flip)
 * @returns {Promise<UEBAScoringResult>}
 */
async function scoreEntityEvent({
  supabase,
  tenantId,
  entityType,
  entityId,
  features,
  alertId        = null,
  peerGroupLabel = null,
  anomalyThreshold = ANOMALY_THRESHOLD,
  forceActive    = false,
}) {
  // --- 1. Score against personal baseline (read-only) ---
  const scoredFeatures   = await scoreEntityFeatures({ supabase, tenantId, entityType, entityId, features });
  let personalComposite  = compositeScore(scoredFeatures);

  // --- 2. Update personal baseline (Welford in-place) ---
  await updateEntityBaseline({ supabase, tenantId, entityType, entityId, features });

  // --- 3. Peer-group deviation + blend ---
  let peerDeviation = null;
  if (peerGroupLabel) {
    peerDeviation = await peerGroupDeviationScore({ supabase, tenantId, peerGroupLabel, features });
    if (peerDeviation !== null) {
      // blend = (personal + peer) / 2  — same formula as AiSOC scoring.py
      personalComposite = (personalComposite + peerDeviation) / 2;
    }

    // --- 4. Update peer group aggregate ---
    await updatePeerGroup({ supabase, tenantId, entityType, peerGroupLabel, features });
  }

  const blendedScore = personalComposite;
  const risk         = riskLevel(blendedScore, anomalyThreshold);
  const isAnomalous  = blendedScore >= anomalyThreshold;

  // --- 5. shadow vs. active ---
  // shadowMode=TRUE unless:
  //   • forceActive flag is set, OR
  //   • ENABLE_UEBA env var is set (opt-in after operator review)
  const shadowMode = !(forceActive || isUEBAEnabled());

  // --- 6. Persist anomaly if above threshold ---
  let anomalyId = null;
  if (isAnomalous) {
    const insertPayload = {
      tenant_id:       tenantId,
      entity_type:     entityType,
      entity_id:       entityId,
      alert_id:        alertId || null,
      feature_z_scores: scoredFeatures,
      composite_score:  parseFloat(blendedScore.toFixed(3)),
      blended_score:    parseFloat(blendedScore.toFixed(3)),
      risk_level:       risk,
      features:         features,
      shadow_mode:      shadowMode,
    };

    const { data: anomalyRow, error: anomErr } = await supabase
      .from('we_ueba_anomalies')
      .insert(insertPayload)
      .select('id')
      .single();

    if (anomErr) {
      // Non-fatal — log and continue so alert insertion is never blocked
      console.error('[UEBA] anomaly insert error:', anomErr.message);
    } else {
      anomalyId = anomalyRow.id;
    }
  }

  return {
    entityType,
    entityId,
    alertId,
    scoredFeatures,
    personalComposite: parseFloat(personalComposite.toFixed(3)),
    peerDeviation:     peerDeviation !== null ? parseFloat(peerDeviation.toFixed(3)) : null,
    blendedScore:      parseFloat(blendedScore.toFixed(3)),
    riskLevel:         risk,
    isAnomalous,
    shadowMode,
    anomalyId,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Feature extractor helper
   Converts a WE alert body into a numeric feature map for UEBA scoring.
   These features mirror the types of features used in AiSOC UEBA.
───────────────────────────────────────────────────────────────────────────── */

/**
 * Extract numeric features from a raw WE alert body.
 * Returns an object suitable for passing to scoreEntityEvent().
 *
 * @param {Object} alertBody - the raw POST body from /api/alerts
 * @returns {Object}  { featureName: number, ... }
 */
function extractAlertFeatures(alertBody) {
  const {
    severity,
    mitre_technique,
    affected_assets,
    metadata = {},
  } = alertBody;

  // Severity → numeric (matches AiSOC SEVERITY_CONTRIBUTION ordering)
  const SEVERITY_NUM = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const sevNum = SEVERITY_NUM[(severity || '').toUpperCase()] || 2;

  return {
    severity_score:     sevNum,
    has_mitre:          mitre_technique ? 1 : 0,
    asset_count:        Array.isArray(affected_assets) ? affected_assets.length : 0,
    risk_score:         typeof metadata.risk_score === 'number' ? metadata.risk_score : 0,
    ioc_count:          typeof metadata.ioc_count  === 'number' ? metadata.ioc_count  : 0,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Module export  (Universal: Node.js CommonJS + browser window)
───────────────────────────────────────────────────────────────────────────── */

const WEUEBA = {
  // Pure algorithms (no I/O — usable in tests without Supabase)
  welfordUpdate,
  computeZScore,
  compositeScore,
  riskLevel,
  extractAlertFeatures,

  // DB-backed operations
  getOrCreateBaseline,
  updateEntityBaseline,
  scoreEntityFeatures,
  getOrCreatePeerGroup,
  updatePeerGroup,
  peerGroupDeviationScore,

  // Main entry point
  scoreEntityEvent,

  // Observability
  isUEBAEnabled,

  // Constants (exported for tests and callers)
  ANOMALY_THRESHOLD,
  PEER_GROUP_MIN_SIZE,
  COMPOSITE_SCORE_CAP,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = WEUEBA;
} else if (typeof window !== 'undefined') {
  window.WEUEBA = WEUEBA;
}
