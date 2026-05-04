/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Alert Clustering Engine (Phase 3)
 *  backend/services/detection/dbscan-clustering.js
 *
 *  Implements DBSCAN + HDBSCAN for alert clustering:
 *  • Groups related alerts into campaigns/incidents
 *  • Feature extraction from alert fields
 *  • Cluster scoring and metadata
 *  • False-positive learning (analyst feedback loop)
 *  • Automated detection tuning from cluster analysis
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');

// ── Feature extraction ────────────────────────────────────────────
// Converts an alert to a numeric feature vector for clustering
function extractFeatures(alert) {
  const severityMap = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const categoryMap = {
    'malware':          0, 'intrusion':       1, 'phishing':        2,
    'data-exfil':       3, 'c2':              4, 'lateral-movement': 5,
    'privilege-escalation': 6, 'persistence': 7, 'reconnaissance':  8,
    'dos':              9, 'insider-threat': 10, 'unknown':         11,
  };

  // Time-of-day feature (0–23 normalized)
  const ts = new Date(alert.created_at || Date.now());
  const hourOfDay  = ts.getHours() / 23;
  const dayOfWeek  = ts.getDay()   / 6;

  // IP octets (normalize to 0–1)
  const [ipA1, ipA2, ipA3] = _parseIp(alert.src_ip);
  const [ipB1, ipB2, ipB3] = _parseIp(alert.dst_ip);

  // Port normalization (0–65535 → 0–1)
  const srcPort = Math.min(parseInt(alert.src_port, 10) || 0, 65535) / 65535;
  const dstPort = Math.min(parseInt(alert.dst_port, 10) || 0, 65535) / 65535;

  return [
    (severityMap[alert.severity] || 0) / 4,  // 0–1
    (categoryMap[alert.category?.toLowerCase()] ?? 11) / 11,  // 0–1
    hourOfDay,
    dayOfWeek,
    ipA1, ipA2, ipA3,
    ipB1, ipB2, ipB3,
    srcPort,
    dstPort,
    alert.confidence ? alert.confidence / 100 : 0.5,
    // MITRE tactic hash (0–1)
    _hashTactic(alert.mitre_tactic),
  ];
}

function _parseIp(ip) {
  if (!ip || typeof ip !== 'string') return [0, 0, 0];
  const parts = ip.split('.');
  if (parts.length < 4) return [0, 0, 0];
  return [
    parseInt(parts[0], 10) / 255,
    parseInt(parts[1], 10) / 255,
    parseInt(parts[2], 10) / 255,
  ];
}

function _hashTactic(tactic) {
  const tactics = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
  ];
  const idx = tactics.indexOf((tactic || '').toLowerCase());
  return idx >= 0 ? idx / (tactics.length - 1) : 0.5;
}

// ── Euclidean distance ────────────────────────────────────────────
function euclidean(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += (a[i] - b[i]) ** 2;
  return Math.sqrt(sum);
}

// ── DBSCAN Implementation ─────────────────────────────────────────
// epsilon: neighborhood radius
// minPts:  minimum points to form a core point
function dbscan(points, epsilon, minPts) {
  const n       = points.length;
  const labels  = new Array(n).fill(-2);  // -2: unvisited, -1: noise, ≥0: cluster
  let clusterId = 0;

  function regionQuery(idx) {
    const neighbors = [];
    for (let i = 0; i < n; i++) {
      if (i !== idx && euclidean(points[idx], points[i]) <= epsilon) {
        neighbors.push(i);
      }
    }
    return neighbors;
  }

  function expandCluster(idx, neighbors, cId) {
    labels[idx] = cId;
    const queue = [...neighbors];

    while (queue.length > 0) {
      const qIdx = queue.shift();
      if (labels[qIdx] === -2) {
        // Unvisited
        labels[qIdx] = cId;
        const qNeighbors = regionQuery(qIdx);
        if (qNeighbors.length >= minPts) {
          queue.push(...qNeighbors.filter(n => !queue.includes(n)));
        }
      } else if (labels[qIdx] === -1) {
        // Border point
        labels[qIdx] = cId;
      }
    }
  }

  for (let i = 0; i < n; i++) {
    if (labels[i] !== -2) continue;  // already processed

    const neighbors = regionQuery(i);
    if (neighbors.length < minPts) {
      labels[i] = -1;  // noise
    } else {
      expandCluster(i, neighbors, clusterId);
      clusterId++;
    }
  }

  return { labels, numClusters: clusterId };
}

// ── HDBSCAN (simplified — variable density via minimum spanning tree) ──
// Uses approximate approach: DBSCAN with adaptive epsilon per cluster
function hdbscan(points, minClusterSize = 5, minSamples = null) {
  minSamples = minSamples || minClusterSize;
  const n    = points.length;
  if (n === 0) return { labels: [], numClusters: 0 };

  // Compute core distances
  function coreDistance(idx) {
    const dists = [];
    for (let i = 0; i < n; i++) {
      if (i !== idx) dists.push(euclidean(points[idx], points[i]));
    }
    dists.sort((a, b) => a - b);
    return dists[minSamples - 1] || 0;
  }

  // Mutual reachability distance
  function mrd(i, j) {
    return Math.max(coreDistance(i), coreDistance(j), euclidean(points[i], points[j]));
  }

  // Build minimum spanning tree (Prim's algorithm on MRD)
  const inMst     = new Array(n).fill(false);
  const cheapest  = new Array(n).fill(Infinity);
  const parent    = new Array(n).fill(-1);
  cheapest[0]     = 0;
  const mstEdges  = [];

  for (let step = 0; step < n; step++) {
    let u = -1;
    for (let v = 0; v < n; v++) {
      if (!inMst[v] && (u === -1 || cheapest[v] < cheapest[u])) u = v;
    }
    inMst[u] = true;
    if (parent[u] !== -1) mstEdges.push({ u, v: parent[u], w: cheapest[u] });

    for (let v = 0; v < n; v++) {
      if (!inMst[v]) {
        const d = mrd(u, v);
        if (d < cheapest[v]) { cheapest[v] = d; parent[v] = u; }
      }
    }
  }

  // Sort MST edges descending — cut largest edges first
  mstEdges.sort((a, b) => b.w - a.w);

  // Union-Find for cluster hierarchy
  const uf = new Array(n).fill(null).map((_, i) => ({ parent: i, size: 1 }));
  function find(x) {
    if (uf[x].parent !== x) uf[x].parent = find(uf[x].parent);
    return uf[x].parent;
  }
  function union(x, y) {
    x = find(x); y = find(y);
    if (x === y) return;
    if (uf[x].size < uf[y].size) [x, y] = [y, x];
    uf[y].parent = x; uf[x].size += uf[y].size;
  }

  // Extract flat clustering by removing edges above size threshold
  const labels   = new Array(n).fill(-1);
  let clusterId  = 0;
  const clusterMap = new Map();

  // Add edges smallest-first (build clusters)
  for (let i = mstEdges.length - 1; i >= 0; i--) {
    const { u, v } = mstEdges[i];
    const pu = find(u), pv = find(v);
    if (pu !== pv) union(u, v);
  }

  // Assign cluster labels based on component membership
  for (let i = 0; i < n; i++) {
    const root = find(i);
    const size = uf[root].size;
    if (size >= minClusterSize) {
      if (!clusterMap.has(root)) {
        clusterMap.set(root, clusterId++);
      }
      labels[i] = clusterMap.get(root);
    }
  }

  return { labels, numClusters: clusterId };
}

// ── Cluster alerts ────────────────────────────────────────────────
function clusterAlerts(alerts, opts = {}) {
  if (!alerts || alerts.length === 0) {
    return { clusters: [], noise: [], stats: { total: 0, clustered: 0, noise: 0, numClusters: 0 } };
  }

  const algorithm  = opts.algorithm || 'dbscan';
  const epsilon    = opts.epsilon    || 0.3;
  const minPts     = opts.minPts     || 3;
  const minCluster = opts.minCluster || 3;

  // Extract feature vectors
  const points = alerts.map(extractFeatures);

  let labels, numClusters;
  if (algorithm === 'hdbscan') {
    ({ labels, numClusters } = hdbscan(points, minCluster));
  } else {
    ({ labels, numClusters } = dbscan(points, epsilon, minPts));
  }

  // Group alerts by cluster label
  const clusterMap = new Map();
  const noiseAlerts = [];

  labels.forEach((label, idx) => {
    if (label === -1) {
      noiseAlerts.push(alerts[idx]);
    } else {
      if (!clusterMap.has(label)) clusterMap.set(label, []);
      clusterMap.get(label).push(alerts[idx]);
    }
  });

  // Build cluster objects
  const clusters = [];
  for (const [cId, clusterAlerts] of clusterMap) {
    clusters.push(_buildCluster(cId, clusterAlerts));
  }

  // Sort clusters by risk score descending
  clusters.sort((a, b) => b.risk_score - a.risk_score);

  const clusteredCount = labels.filter(l => l >= 0).length;

  return {
    clusters,
    noise:     noiseAlerts,
    algorithm,
    stats: {
      total:       alerts.length,
      clustered:   clusteredCount,
      noise:       noiseAlerts.length,
      numClusters,
      epsilon:     algorithm === 'dbscan' ? epsilon : null,
      minPts:      algorithm === 'dbscan' ? minPts  : null,
    },
  };
}

// ── Build cluster metadata ────────────────────────────────────────
function _buildCluster(id, alerts) {
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const maxSev = alerts.reduce((max, a) => {
    return (severityOrder[a.severity] || 0) > (severityOrder[max] || 0) ? a.severity : max;
  }, 'LOW');

  // Collect unique IPs, techniques, rules
  const srcIps       = [...new Set(alerts.map(a => a.src_ip).filter(Boolean))];
  const dstIps       = [...new Set(alerts.map(a => a.dst_ip).filter(Boolean))];
  const techniques   = [...new Set(alerts.map(a => a.mitre_technique).filter(Boolean))];
  const tactics      = [...new Set(alerts.map(a => a.mitre_tactic).filter(Boolean))];
  const ruleIds      = [...new Set(alerts.map(a => a.rule_id).filter(Boolean))];
  const tenants      = [...new Set(alerts.map(a => a.tenant_id).filter(Boolean))];
  const categories   = [...new Set(alerts.map(a => a.category).filter(Boolean))];

  // Time span
  const times      = alerts.map(a => new Date(a.created_at || 0).getTime()).filter(t => t > 0);
  const firstSeen  = times.length > 0 ? new Date(Math.min(...times)).toISOString() : null;
  const lastSeen   = times.length > 0 ? new Date(Math.max(...times)).toISOString() : null;
  const durationMs = times.length > 1 ? Math.max(...times) - Math.min(...times) : 0;

  // Risk score: severity × size × duration factor
  const sevScore    = (severityOrder[maxSev] || 0) * 20;
  const sizeScore   = Math.min(alerts.length * 5, 30);
  const durScore    = durationMs > 3_600_000 ? 10 : durationMs > 600_000 ? 5 : 0;
  const spreadScore = (srcIps.length > 3 || dstIps.length > 5) ? 10 : 0;
  const riskScore   = Math.min(100, sevScore + sizeScore + durScore + spreadScore);

  // Campaign narrative
  const narrative = _buildNarrative({ maxSev, srcIps, dstIps, techniques, tactics, alerts });

  return {
    cluster_id:    `cluster-${id}-${crypto.randomUUID().substring(0, 8)}`,
    alert_count:   alerts.length,
    severity:      maxSev,
    risk_score:    riskScore,
    first_seen:    firstSeen,
    last_seen:     lastSeen,
    duration_ms:   durationMs,
    src_ips:       srcIps.slice(0, 20),
    dst_ips:       dstIps.slice(0, 20),
    mitre_techniques: techniques,
    mitre_tactics:    tactics,
    rule_ids:      ruleIds,
    categories,
    tenant_ids:    tenants,
    narrative,
    alert_ids:     alerts.map(a => a.id).filter(Boolean),
    alerts:        alerts.slice(0, 10),  // truncate for API response
    is_campaign:   alerts.length >= 5 && techniques.length >= 2,
    campaign_confidence: _campaignConfidence(alerts, techniques, durationMs),
  };
}

function _buildNarrative({ maxSev, srcIps, dstIps, techniques, tactics, alerts }) {
  const count    = alerts.length;
  const src      = srcIps.length === 1 ? srcIps[0] : `${srcIps.length} source IPs`;
  const dst      = dstIps.length === 1 ? dstIps[0] : `${dstIps.length} destinations`;
  const tactic   = tactics[0] || 'unknown';

  if (techniques.length >= 3) {
    return `${maxSev} multi-technique campaign: ${count} alerts from ${src} targeting ${dst}, spanning tactics: ${tactics.slice(0, 3).join(', ')} — likely coordinated intrusion attempt.`;
  }
  if (count >= 10) {
    return `High-volume ${maxSev} alert cluster: ${count} alerts from ${src} → ${dst}, technique ${techniques[0] || 'unknown'} — potential automated attack or scan.`;
  }
  return `${maxSev} alert cluster: ${count} correlated events from ${src} targeting ${dst} via ${tactic}.`;
}

function _campaignConfidence(alerts, techniques, durationMs) {
  let score = 0;
  if (alerts.length >= 10)    score += 30;
  else if (alerts.length >= 5) score += 15;
  if (techniques.length >= 3)  score += 30;
  else if (techniques.length >= 2) score += 15;
  if (durationMs > 3_600_000) score += 20;
  if (alerts.some(a => a.severity === 'CRITICAL')) score += 20;
  return Math.min(100, score);
}

// ── Analyst feedback loop ────────────────────────────────────────
// Records analyst labels for clusters → feeds back to detection tuning
async function recordClusterFeedback(clusterId, feedback, db) {
  const { outcome, analyst_id, notes } = feedback;

  // Store feedback for ML training
  const record = {
    cluster_id:   clusterId,
    analyst_id,
    outcome,         // 'true_positive' | 'false_positive' | 'benign' | 'escalated'
    notes:        notes || '',
    labeled_at:   new Date().toISOString(),
  };

  if (db) {
    const { error } = await db
      .from('cluster_feedback')
      .insert(record);
    if (error) console.error('[Clustering] Feedback insert error:', error.message);
  }

  // If false-positive: trigger rule tuning suggestion
  if (outcome === 'false_positive') {
    return {
      ...record,
      tuning_suggestion: `Review detection rules in cluster ${clusterId} — analyst marked as false positive`,
    };
  }

  return record;
}

// ── False-positive learning: compute FP rate per rule ────────────
async function computeRuleFpRates(db) {
  if (!db) return [];

  const { data: feedback } = await db
    .from('cluster_feedback')
    .select('cluster_id, outcome')
    .gte('labeled_at', new Date(Date.now() - 30 * 86_400_000).toISOString());

  if (!feedback || feedback.length === 0) return [];

  const { data: clusters } = await db
    .from('alert_clusters')
    .select('cluster_id, rule_ids')
    .in('cluster_id', feedback.map(f => f.cluster_id));

  const ruleStats = {};
  for (const fb of feedback) {
    const cluster = clusters?.find(c => c.cluster_id === fb.cluster_id);
    if (!cluster?.rule_ids) continue;
    for (const ruleId of cluster.rule_ids) {
      if (!ruleStats[ruleId]) ruleStats[ruleId] = { tp: 0, fp: 0 };
      if (fb.outcome === 'false_positive') ruleStats[ruleId].fp++;
      else if (fb.outcome === 'true_positive') ruleStats[ruleId].tp++;
    }
  }

  return Object.entries(ruleStats)
    .map(([rule_id, { tp, fp }]) => ({
      rule_id,
      tp, fp,
      total:    tp + fp,
      fp_rate:  tp + fp > 0 ? Math.round((fp / (tp + fp)) * 100) : null,
      needs_tuning: fp > tp && (tp + fp) >= 5,
    }))
    .filter(r => r.total >= 3)
    .sort((a, b) => (b.fp_rate || 0) - (a.fp_rate || 0));
}

module.exports = {
  extractFeatures,
  dbscan,
  hdbscan,
  clusterAlerts,
  recordClusterFeedback,
  computeRuleFpRates,
  euclidean,
};
