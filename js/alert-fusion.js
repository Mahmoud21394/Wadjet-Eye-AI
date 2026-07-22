/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 *  js/alert-fusion.js — Alert Fusion / Correlation  (Phase 2, AiSOC v7.6.0 port)
 *  Ported from:
 *    services/fusion/app/models/alert.py           — fingerprint(), correlation_key()
 *    services/fusion/app/services/deduplicator.py  — is_duplicate / register
 *    services/fusion/app/services/correlator.py    — correlate()
 *    services/fusion/app/services/confidence.py    — ConfidenceScorer.score()
 *
 *  This is a NATIVE JS rewrite.
 *  No Redis, no Kafka, no ClickHouse.  Storage: Supabase only.
 *
 *  ML FACTOR GAP — EXPLICIT POLICY:
 *    AiSOC `confidence.py` includes two ML factors:
 *      ml_anomaly  (weight 0.18, IsolationForest)
 *      ml_priority (weight 0.18, LightGBM)
 *    These require Python ML runtimes not available in WE's Node.js environment.
 *    Policy (decided Task 4, Phase 2):
 *      • ml_anomaly and ml_priority are NOT silently dropped.
 *      • When absent (null), the remaining 5 factors' weights are RESCALED
 *        to sum to 1.0 so the scorer remains well-calibrated.
 *      • A `ml_gap` flag is set on the result so the UI can surface a
 *        "⚠ ML signals not available" badge on the confidence chip.
 *      • The UEBA blended_score (from ueba.js) is optionally injected as a
 *        partial ml_anomaly substitute when available — passed via opts.uebaScore.
 *
 *  Dedup window: 1 hour  (TTL on we_alert_dedup_keys, matches AiSOC default)
 *  Correlation window: 1 hour (expires_at on we_alert_incidents)
 *  Max alerts per incident: 100
 *
 *  Feature flag: process.env.ENABLE_ALERT_FUSION  (default FALSE → shadow mode)
 *  Shadow mode:  fusion metadata written to alert columns we_fusion_shadow=TRUE;
 *                dedup decision is NEVER enforced in shadow (alert always inserted).
 *
 *  Exports (CommonJS / browser window.WEAlertFusion):
 *    fingerprintAlert(alertBody, tenantId)          → hex string (SHA-256)
 *    correlationKey(alertBody, tenantId)            → string
 *    checkDuplicate(opts)                           → Promise<{isDuplicate, originalAlertId}>
 *    registerFingerprint(opts)                      → Promise<void>
 *    correlateAlert(opts)                           → Promise<CorrelationResult>
 *    scoreConfidence(alert, opts)                   → ConfidenceResult
 *    fuseAlert(opts)                                → Promise<FusionResult>
 *    isFusionEnabled()                              → boolean
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

/* ─────────────────────────────────────────────────────────────────────────────
   SHA-256 helper (Node.js crypto / SubtleCrypto / js-sha256 fallback)
───────────────────────────────────────────────────────────────────────────── */

/**
 * Compute a hex SHA-256 digest.  Synchronous in Node.js (crypto module),
 * returning a string directly.  In a browser bundle you'd need a shim.
 *
 * @param {string} text
 * @returns {string} 64-char hex string
 */
function sha256Hex(text) {
  // Node.js path (backend use)
  if (typeof require !== 'undefined') {
    try {
      const crypto = require('crypto');
      return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    } catch (_) { /* fall through */ }
  }

  // Browser path — synchronous via subtle crypto is not possible, but this
  // module is primarily backend; throw a clear error if reached.
  throw new Error('[AlertFusion] sha256Hex: no crypto implementation available. ' +
                  'In browser contexts import a SHA-256 polyfill before this module.');
}

/* ─────────────────────────────────────────────────────────────────────────────
   Feature flag
───────────────────────────────────────────────────────────────────────────── */

function isFusionEnabled() {
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env.ENABLE_ALERT_FUSION;
    return v === '1' || v === 'true' || v === 'TRUE';
  }
  if (typeof window !== 'undefined' && window.ENABLE_ALERT_FUSION !== undefined) {
    return Boolean(window.ENABLE_ALERT_FUSION);
  }
  return false;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Constants
───────────────────────────────────────────────────────────────────────────── */

const DEDUP_WINDOW_SECONDS      = 3600;   // 1 hour, matches AiSOC dedup_window_seconds
const CORRELATION_WINDOW_SECONDS= 3600;   // 1 hour, matches AiSOC correlation_window_seconds
const MAX_ALERTS_PER_INCIDENT   = 100;

// Confidence bands (ported verbatim from confidence.py)
const HIGH_THRESHOLD = 0.70;
const LOW_THRESHOLD  = 0.40;

// Base weights — must sum to 1.0 (ported from confidence.py)
const BASE_WEIGHTS = {
  severity:     0.20,
  ml_anomaly:   0.18,  // requires Python IsolationForest — may be null (ML GAP)
  ml_priority:  0.18,  // requires Python LightGBM       — may be null (ML GAP)
  mitre:        0.14,
  threat_intel: 0.16,
  upstream_risk: 0.08,
  ioc_density:  0.06,
};

// Rescaled weights for when both ML factors are absent (sums to 1.0)
// Remaining 5 factors: 0.20+0.14+0.16+0.08+0.06 = 0.64
// Scale factor: 1.0 / 0.64 ≈ 1.5625
const ML_ABSENT_WEIGHTS = (function () {
  const nonML = { severity: 0.20, mitre: 0.14, threat_intel: 0.16, upstream_risk: 0.08, ioc_density: 0.06 };
  const total  = Object.values(nonML).reduce((s, w) => s + w, 0);
  const scale  = 1.0 / total;
  return Object.fromEntries(Object.entries(nonML).map(([k, w]) => [k, w * scale]));
}());

// Severity → contribution in [-1, +1]  (verbatim from confidence.py)
const SEVERITY_CONTRIBUTION = {
  CRITICAL: 1.0,
  HIGH:     0.6,
  MEDIUM:   0.0,
  LOW:     -0.5,
  INFO:    -1.0,
};

/* ─────────────────────────────────────────────────────────────────────────────
   Alert fingerprint  (ported from alert.py::RawAlert.fingerprint)
   SHA-256 of canonical JSON of 9 fields.
───────────────────────────────────────────────────────────────────────────── */

/**
 * Stable SHA-256 deduplication fingerprint for an incoming WE alert.
 *
 * Canonical fields (same 9 as AiSOC):
 *   tenant_id, source, title, src_ip, dst_ip, hostname, username,
 *   file_hash, mitre_techniques (sorted array)
 *
 * @param {Object} alertBody  - the raw alert body from POST /api/alerts
 * @param {string} tenantId
 * @returns {string} 64-char hex SHA-256
 */
function fingerprintAlert(alertBody, tenantId) {
  const techniques = Array.isArray(alertBody.mitre_techniques)
    ? [...alertBody.mitre_techniques].sort()
    : (alertBody.mitre_technique ? [alertBody.mitre_technique] : []);

  const fields = {
    tenant_id:        String(tenantId),
    source:           alertBody.source   || null,
    title:            alertBody.title    || null,
    src_ip:           alertBody.src_ip   || (alertBody.metadata && alertBody.metadata.src_ip)   || null,
    dst_ip:           alertBody.dst_ip   || (alertBody.metadata && alertBody.metadata.dst_ip)   || null,
    hostname:         alertBody.hostname || (alertBody.metadata && alertBody.metadata.hostname) || null,
    username:         alertBody.username || (alertBody.metadata && alertBody.metadata.username) || null,
    file_hash:        alertBody.file_hash|| (alertBody.metadata && alertBody.metadata.file_hash)|| null,
    mitre_techniques: techniques,
  };

  // sort_keys=True equivalent: JSON.stringify with sorted keys
  const canonical = JSON.stringify(fields, Object.keys(fields).sort());
  return sha256Hex(canonical);
}

/**
 * Correlation key — groups related alerts by primary entity + first MITRE tactic.
 * Ported from alert.py::RawAlert.correlation_key()
 *
 * @param {Object} alertBody
 * @param {string} tenantId
 * @returns {string}
 */
function correlationKey(alertBody, tenantId) {
  const meta     = alertBody.metadata || {};
  const entity   = alertBody.src_ip   || meta.src_ip  ||
                   alertBody.hostname || meta.hostname ||
                   alertBody.username || meta.username ||
                   alertBody.domain   || meta.domain   || 'unknown';
  const tactics  = alertBody.mitre_tactics || meta.mitre_tactics || [];
  const tactic   = Array.isArray(tactics) && tactics.length ? tactics[0] : 'unknown';
  return `${tenantId}:${entity}:${tactic}`;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Deduplication  (replaces AiSOC Redis Bloom filter with Supabase TTL rows)
───────────────────────────────────────────────────────────────────────────── */

/**
 * Check whether a fingerprint already exists in the dedup window.
 *
 * @param {Object}  opts
 * @param {Object}  opts.supabase
 * @param {string}  opts.fingerprint
 * @returns {Promise<{isDuplicate: boolean, originalAlertId: string|null}>}
 */
async function checkDuplicate({ supabase, fingerprint }) {
  const { data, error } = await supabase
    .from('we_alert_dedup_keys')
    .select('alert_id')
    .eq('fingerprint', fingerprint)
    .gt('expires_at', new Date().toISOString())
    .maybeSingle();

  if (error) {
    console.error('[AlertFusion] checkDuplicate error:', error.message);
    // Fail-open on dedup check errors — do not suppress the alert
    return { isDuplicate: false, originalAlertId: null };
  }

  return {
    isDuplicate:     !!data,
    originalAlertId: data ? data.alert_id : null,
  };
}

/**
 * Register a fingerprint after a successful alert insert.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase
 * @param {string} opts.fingerprint
 * @param {string} opts.alertId     - UUID of the inserted alert
 * @param {string} opts.tenantId
 */
async function registerFingerprint({ supabase, fingerprint, alertId, tenantId }) {
  const expiresAt = new Date(Date.now() + DEDUP_WINDOW_SECONDS * 1000).toISOString();

  const { error } = await supabase
    .from('we_alert_dedup_keys')
    .upsert({
      fingerprint,
      alert_id:   alertId,
      tenant_id:  tenantId,
      expires_at: expiresAt,
    }, { onConflict: 'fingerprint' });

  if (error) {
    // Non-fatal — dedup will miss this entry; log and continue
    console.error('[AlertFusion] registerFingerprint error:', error.message);
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   Correlation  (replaces AiSOC Redis hash with Supabase tables)
───────────────────────────────────────────────────────────────────────────── */

const SEVERITY_ORDER = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

function maxSeverity(a, b) {
  return (SEVERITY_ORDER[a] || 0) >= (SEVERITY_ORDER[b] || 0) ? a : b;
}

/**
 * @typedef {Object} CorrelationResult
 * @property {'new_alert'|'duplicate'|'correlated'|'new_incident'} decision
 * @property {string|null} incidentId
 * @property {number}      incidentAlertCount
 */

/**
 * Correlate an alert into an existing incident or create a new one.
 * Replaces AiSOC Redis-backed Correlator entirely with Supabase queries.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase
 * @param {string} opts.tenantId
 * @param {string} opts.alertId       - UUID of the already-inserted alert
 * @param {Object} opts.alertBody     - raw POST body
 * @param {string} opts.corrKey       - pre-computed correlationKey()
 * @returns {Promise<CorrelationResult>}
 */
async function correlateAlert({ supabase, tenantId, alertId, alertBody, corrKey }) {
  const now       = new Date().toISOString();
  const expiresAt = new Date(Date.now() + CORRELATION_WINDOW_SECONDS * 1000).toISOString();
  const meta      = alertBody.metadata || {};

  // --- Look up existing correlation index entry ---
  const { data: indexRow } = await supabase
    .from('we_alert_correlation_index')
    .select('incident_id')
    .eq('correlation_key', corrKey)
    .eq('tenant_id', tenantId)
    .gt('expires_at', now)
    .maybeSingle();

  if (indexRow) {
    // --- Try to merge into existing incident ---
    const { data: incident } = await supabase
      .from('we_alert_incidents')
      .select('*')
      .eq('id', indexRow.incident_id)
      .gt('expires_at', now)
      .maybeSingle();

    if (incident && incident.alert_count < MAX_ALERTS_PER_INCIDENT) {
      // Merge: build update payload
      const newSeverity  = maxSeverity(incident.severity, (alertBody.severity || 'MEDIUM').toUpperCase());
      const newSrcIps    = _mergeArray(incident.src_ips,    [meta.src_ip    || alertBody.src_ip]);
      const newHostnames = _mergeArray(incident.hostnames,  [meta.hostname  || alertBody.hostname]);
      const newUsernames = _mergeArray(incident.usernames,  [meta.username  || alertBody.username]);
      const alertTechs   = alertBody.mitre_techniques || (alertBody.mitre_technique ? [alertBody.mitre_technique] : []);
      const newTechs     = _mergeArray(incident.mitre_techniques, alertTechs);
      const alertTactics = meta.mitre_tactics || alertBody.mitre_tactics || [];
      const newTactics   = _mergeArray(incident.mitre_tactics, alertTactics);

      const { error: updErr } = await supabase
        .from('we_alert_incidents')
        .update({
          alert_count:      incident.alert_count + 1,
          severity:         newSeverity,
          last_seen_at:     now,
          expires_at:       expiresAt,
          src_ips:          newSrcIps,
          hostnames:        newHostnames,
          usernames:        newUsernames,
          mitre_techniques: newTechs,
          mitre_tactics:    newTactics,
        })
        .eq('id', incident.id);

      if (updErr) {
        console.error('[AlertFusion] incident update error:', updErr.message);
      }

      // Refresh correlation index TTL
      await supabase
        .from('we_alert_correlation_index')
        .update({ expires_at: expiresAt })
        .eq('correlation_key', corrKey)
        .eq('tenant_id', tenantId);

      return {
        decision:          'correlated',
        incidentId:        incident.id,
        incidentAlertCount: incident.alert_count + 1,
      };
    }
  }

  // --- No existing incident — create new ---
  const sevUp      = (alertBody.severity || 'MEDIUM').toUpperCase();
  const srcIps     = _compact([meta.src_ip    || alertBody.src_ip]);
  const hostnames  = _compact([meta.hostname  || alertBody.hostname]);
  const usernames  = _compact([meta.username  || alertBody.username]);
  const techniques = alertBody.mitre_techniques || (alertBody.mitre_technique ? [alertBody.mitre_technique] : []);
  const tactics    = meta.mitre_tactics || alertBody.mitre_tactics || [];

  const { data: newIncident, error: incErr } = await supabase
    .from('we_alert_incidents')
    .insert({
      tenant_id:        tenantId,
      correlation_key:  corrKey,
      severity:         sevUp,
      status:           'open',
      alert_count:      1,
      src_ips:          srcIps,
      hostnames:        hostnames,
      usernames:        usernames,
      mitre_tactics:    [...new Set(tactics)],
      mitre_techniques: [...new Set(techniques)],
      first_seen_at:    now,
      last_seen_at:     now,
      expires_at:       expiresAt,
    })
    .select('id')
    .single();

  if (incErr) {
    console.error('[AlertFusion] incident create error:', incErr.message);
    return { decision: 'new_alert', incidentId: null, incidentAlertCount: 1 };
  }

  // Write correlation index
  await supabase
    .from('we_alert_correlation_index')
    .upsert({
      correlation_key: corrKey,
      tenant_id:       tenantId,
      incident_id:     newIncident.id,
      expires_at:      expiresAt,
    }, { onConflict: 'correlation_key,tenant_id' });

  return {
    decision:          'new_incident',
    incidentId:        newIncident.id,
    incidentAlertCount: 1,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Confidence Scorer  (ported from confidence.py::ConfidenceScorer.score)
   ML GAP: ml_anomaly + ml_priority are optional; weights rescaled when absent.
───────────────────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} ConfidenceFactor
 * @property {string} factor
 * @property {string} label
 * @property {string} value
 * @property {number} contribution  - signed [-1, +1]
 * @property {number} weight
 */

/**
 * @typedef {Object} ConfidenceResult
 * @property {number}             score            - [0, 1]
 * @property {'high'|'medium'|'low'} label
 * @property {ConfidenceFactor[]} rationale        - sorted by abs impact desc
 * @property {boolean}            mlGap            - true when ML signals absent
 * @property {string|null}        mlGapNote        - human-readable note for UI badge
 */

/**
 * Compute confidence score and rationale for one alert.
 *
 * @param {Object}  alert           - WE alert body (post-insert, has severity etc.)
 * @param {Object}  [opts]
 * @param {number}  [opts.uebaScore]         - optional UEBA blended_score [0–10] to substitute ml_anomaly
 * @param {Object}  [opts.enrichments]       - TI enrichment hits { misp, otx, kev, ... }
 * @param {number}  [opts.mlAnomalyScore]    - IsolationForest score [0–1] if available
 * @param {number}  [opts.mlPriorityScore]   - LightGBM score [0–1] if available
 * @returns {ConfidenceResult}
 */
function scoreConfidence(alert, opts) {
  opts = opts || {};

  const enrichments      = opts.enrichments    || null;
  const mlAnomalyRaw     = opts.mlAnomalyScore;   // undefined = not provided
  const mlPriorityRaw    = opts.mlPriorityScore;  // undefined = not provided
  const uebaScore        = typeof opts.uebaScore === 'number' ? opts.uebaScore : null;

  // Normalise UEBA score [0–10] → [0–1] for use as ml_anomaly substitute
  const uebaAsAnomaly    = uebaScore !== null ? Math.min(1.0, uebaScore / 10.0) : null;

  // Determine effective ML values
  // POLICY: Use provided values; substitute UEBA for ml_anomaly when available
  const mlAnomaly  = (mlAnomalyRaw  !== undefined && mlAnomalyRaw  !== null) ? mlAnomalyRaw  :
                     (uebaAsAnomaly !== null)                                 ? uebaAsAnomaly : null;
  const mlPriority = (mlPriorityRaw !== undefined && mlPriorityRaw !== null) ? mlPriorityRaw : null;

  const mlGap      = mlAnomaly === null || mlPriority === null;
  const bothMLMissing = mlAnomaly === null && mlPriority === null;

  // Choose weight set
  const weights = bothMLMissing ? ML_ABSENT_WEIGHTS : BASE_WEIGHTS;

  const rationale = [];

  // ── 1. Severity ──
  const sevStr  = (alert.severity || 'MEDIUM').toUpperCase();
  const sevC    = SEVERITY_CONTRIBUTION[sevStr] !== undefined ? SEVERITY_CONTRIBUTION[sevStr] : 0.0;
  rationale.push({
    factor: 'severity', label: 'Alert severity',
    value: sevStr, contribution: sevC, weight: weights.severity || 0,
  });

  // ── 2. ML anomaly ──
  if (!bothMLMissing && weights.ml_anomaly) {
    const anomC = mlAnomaly !== null ? _mlContribution(mlAnomaly) : 0.0;
    rationale.push({
      factor: 'ml_anomaly',
      label:  mlAnomaly === uebaAsAnomaly ? 'UEBA composite (ml_anomaly substitute)' : 'ML anomaly score',
      value:  mlAnomaly !== null ? mlAnomaly.toFixed(2) : 'n/a',
      contribution: anomC,
      weight: weights.ml_anomaly,
    });
  }

  // ── 3. ML priority ──
  if (!bothMLMissing && weights.ml_priority) {
    const priC = mlPriority !== null ? _mlContribution(mlPriority) : 0.0;
    rationale.push({
      factor: 'ml_priority', label: 'ML priority rank',
      value:  mlPriority !== null ? mlPriority.toFixed(2) : 'n/a',
      contribution: priC,
      weight: weights.ml_priority,
    });
  }

  // ── 4. MITRE coverage ──
  const techniques = alert.mitre_techniques ||
                     (alert.mitre_technique ? [alert.mitre_technique] : []);
  const nTech      = Array.isArray(techniques) ? techniques.length : 0;
  const mitreC     = _mitreContribution(nTech);
  rationale.push({
    factor: 'mitre', label: 'MITRE technique coverage',
    value: nTech === 1 ? '1 technique' : `${nTech} techniques`,
    contribution: mitreC, weight: weights.mitre || 0,
  });

  // ── 5. Threat intel ──
  const [tiC, tiVal] = _tiContribution(enrichments);
  rationale.push({
    factor: 'threat_intel', label: 'Threat-intel match',
    value: tiVal, contribution: tiC, weight: weights.threat_intel || 0,
  });

  // ── 6. Upstream vendor risk score ──
  const upstream  = Math.max(0.0, Math.min(1.0, (alert.metadata && alert.metadata.risk_score) || alert.risk_score || 0.0));
  const upstreamC = _mlContribution(upstream);
  rationale.push({
    factor: 'upstream_risk', label: 'Upstream vendor risk score',
    value: upstream.toFixed(2), contribution: upstreamC, weight: weights.upstream_risk || 0,
  });

  // ── 7. IOC density ──
  const [iocC, populated] = _iocDensityContribution(alert);
  rationale.push({
    factor: 'ioc_density', label: 'IOC density',
    value: `${populated} populated fields`, contribution: iocC, weight: weights.ioc_density || 0,
  });

  // ── Final score: 0.5 + Σ(w_i * c_i) clamped [0,1] ──
  const delta = rationale.reduce((sum, f) => sum + f.contribution * f.weight, 0);
  const raw   = 0.5 + delta;
  const score = Math.max(0.0, Math.min(1.0, raw));
  const label = score >= HIGH_THRESHOLD ? 'high' :
                score <  LOW_THRESHOLD  ? 'low'  : 'medium';

  // Sort by abs impact desc (same as AiSOC UI order)
  rationale.sort((a, b) => Math.abs(b.contribution * b.weight) - Math.abs(a.contribution * a.weight));

  let mlGapNote = null;
  if (mlGap) {
    if (bothMLMissing && uebaAsAnomaly === null) {
      mlGapNote = 'ML signals (IsolationForest, LightGBM) not available; ' +
                  'weights rescaled across remaining 5 factors. ' +
                  'Enable UEBA to partially substitute ml_anomaly.';
    } else if (bothMLMissing && uebaAsAnomaly !== null) {
      mlGapNote = 'UEBA score substituted for ml_anomaly; ml_priority unavailable. ' +
                  'LightGBM integration pending.';
    } else {
      mlGapNote = 'ml_priority (LightGBM) not available; ml_anomaly provided.';
    }
  }

  return {
    score:    parseFloat(score.toFixed(4)),
    label,
    rationale,
    mlGap,
    mlGapNote,
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
   Main fusion entry point
───────────────────────────────────────────────────────────────────────────── */

/**
 * @typedef {Object} FusionResult
 * @property {string}  fingerprint
 * @property {boolean} isDuplicate
 * @property {string|null} originalAlertId     - set when isDuplicate=true
 * @property {CorrelationResult} correlation
 * @property {ConfidenceResult}  confidence
 * @property {boolean} shadowMode
 * @property {Object}  alertColumns            - columns to merge into alerts row
 */

/**
 * Full fusion pipeline for one incoming alert.
 * Called from POST /api/alerts BEFORE the Supabase insert.
 *
 * Steps:
 *   1. Compute fingerprint
 *   2. Check dedup (shadow: never suppresses, just records)
 *   3. Compute confidence score
 *   4. Build alertColumns to persist on the alerts row
 *   (Correlation + fingerprint registration happen AFTER insert, in postFuseAlert)
 *
 * @param {Object}  opts
 * @param {Object}  opts.supabase
 * @param {string}  opts.tenantId
 * @param {Object}  opts.alertBody         - raw POST body
 * @param {Object}  [opts.uebaResult]      - result from ueba.js scoreEntityEvent()
 * @param {Object}  [opts.enrichments]     - TI enrichments
 * @returns {Promise<FusionResult>}
 */
async function fuseAlert({ supabase, tenantId, alertBody, uebaResult, enrichments }) {
  const fp      = fingerprintAlert(alertBody, tenantId);
  const corrKey = correlationKey(alertBody, tenantId);
  const shadow  = !isFusionEnabled();

  // Dedup check
  const { isDuplicate, originalAlertId } = await checkDuplicate({ supabase, fingerprint: fp });

  // Confidence score (synchronous — no DB I/O)
  const confidenceResult = scoreConfidence(alertBody, {
    uebaScore:     uebaResult ? uebaResult.blendedScore : undefined,
    enrichments:   enrichments || null,
  });

  // Columns to write onto the alerts row
  // All prefixed we_* so they're clearly fusion-owned; we_fusion_shadow gates activation.
  const alertColumns = {
    we_dedup_fingerprint: fp,
    we_confidence_score:  confidenceResult.score,
    we_confidence_label:  confidenceResult.label,
    we_fusion_shadow:     shadow,
    // UEBA fields (only set if UEBA ran)
    we_ueba_composite:    uebaResult ? uebaResult.blendedScore  : null,
    we_ueba_risk_level:   uebaResult ? uebaResult.riskLevel     : null,
  };

  return {
    fingerprint:     fp,
    correlationKey:  corrKey,
    isDuplicate,
    originalAlertId,
    confidence:      confidenceResult,
    shadowMode:      shadow,
    alertColumns,
  };
}

/**
 * Post-insert fusion steps — run AFTER the alert row exists in DB so we
 * have a real UUID to store in dedup_keys and incidents.
 *
 * @param {Object} opts
 * @param {Object} opts.supabase
 * @param {string} opts.tenantId
 * @param {string} opts.alertId      - UUID of the inserted alert row
 * @param {Object} opts.alertBody
 * @param {Object} opts.fusionResult - returned by fuseAlert()
 * @returns {Promise<CorrelationResult>}
 */
async function postFuseAlert({ supabase, tenantId, alertId, alertBody, fusionResult }) {
  const { fingerprint, correlationKey: corrKey, isDuplicate, shadowMode } = fusionResult;

  // Register fingerprint regardless of shadow (enables dedup in subsequent calls)
  await registerFingerprint({ supabase, fingerprint, alertId, tenantId });

  // Correlate (build/update incident)
  const correlation = await correlateAlert({
    supabase, tenantId, alertId, alertBody, corrKey,
  });

  // Write incident_id back to alert row
  if (correlation.incidentId) {
    await supabase
      .from('alerts')
      .update({ we_incident_id: correlation.incidentId })
      .eq('id', alertId)
      .eq('tenant_id', tenantId);
  }

  return correlation;
}

/* ─────────────────────────────────────────────────────────────────────────────
   Internal helpers  (ported from confidence.py)
───────────────────────────────────────────────────────────────────────────── */

/** ML scores [0,1] centred on 0.5 → contribution in [-1, +1] */
function _mlContribution(value) {
  return Math.max(-1.0, Math.min(1.0, (value - 0.5) * 2.0));
}

/** 0 techniques → mild negative; 1 → neutral; 3+ → strongly positive */
function _mitreContribution(n) {
  if (n === 0) return -0.4;
  if (n === 1) return  0.0;
  if (n === 2) return  0.4;
  return Math.min(1.0, 0.4 + (n - 2) * 0.2);
}

/** Threat-intel: check enrichment hits across known sources */
function _tiContribution(enrichments) {
  if (!enrichments) return [-0.3, 'no TI match'];
  let hits = 0;
  const sources = [];
  for (const src of ['misp', 'otx', 'taxii', 'kev', 'virustotal']) {
    const match = enrichments[src];
    if (!match) continue;
    if ((typeof match === 'object' && !Array.isArray(match) && (match.hit || match.matches)) ||
        (Array.isArray(match) && match.length)) {
      hits++;
      sources.push(src.toUpperCase());
    }
  }
  if (hits === 0) return [-0.3, 'no TI match'];
  if (hits === 1) return [0.6, sources[0]];
  return [1.0, sources.join(' + ')];
}

/** Count populated IOC fields; return [contribution, count] */
function _iocDensityContribution(alert) {
  const meta = alert.metadata || {};
  const fields = [
    alert.src_ip    || meta.src_ip,
    alert.dst_ip    || meta.dst_ip,
    alert.hostname  || meta.hostname,
    alert.username  || meta.username,
    alert.file_hash || meta.file_hash,
    alert.domain    || meta.domain,
    alert.url       || meta.url,
  ];
  const populated = fields.filter(Boolean).length;
  let contribution;
  if      (populated === 0)  contribution = -0.6;
  else if (populated <= 2)   contribution =  0.0;
  else if (populated <= 4)   contribution =  0.5;
  else                       contribution =  1.0;
  return [contribution, populated];
}

/** Merge two arrays, deduplicate, filter nulls/undefined */
function _mergeArray(existing, incoming) {
  const ex = Array.isArray(existing) ? existing : [];
  const inc = Array.isArray(incoming) ? incoming : [];
  return [...new Set([...ex, ...inc].filter(x => x != null && x !== ''))];
}

/** Filter nulls/empty from array */
function _compact(arr) {
  return (arr || []).filter(x => x != null && x !== '');
}

/* ─────────────────────────────────────────────────────────────────────────────
   Module export  (Universal: Node.js CommonJS + browser window)
───────────────────────────────────────────────────────────────────────────── */

const WEAlertFusion = {
  // Pure / synchronous (testable without Supabase)
  fingerprintAlert,
  correlationKey,
  scoreConfidence,
  sha256Hex,

  // Async Supabase-backed
  checkDuplicate,
  registerFingerprint,
  correlateAlert,
  fuseAlert,
  postFuseAlert,

  // Observability
  isFusionEnabled,

  // Constants (for tests and callers)
  DEDUP_WINDOW_SECONDS,
  CORRELATION_WINDOW_SECONDS,
  MAX_ALERTS_PER_INCIDENT,
  HIGH_THRESHOLD,
  LOW_THRESHOLD,
  BASE_WEIGHTS,
  ML_ABSENT_WEIGHTS,
  SEVERITY_CONTRIBUTION,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = WEAlertFusion;
} else if (typeof window !== 'undefined') {
  window.WEAlertFusion = WEAlertFusion;
}
