/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Neo4j Attack-Chain Graph Routes (Phase 4)
 *  backend/routes/graph.js
 *
 *  GET  /api/graph/attack-chain/:alertId   — Reconstruct attack chain
 *  GET  /api/graph/threat-actor/:name      — Threat actor graph
 *  GET  /api/graph/lateral-movement/:host  — Lateral movement paths
 *  POST /api/graph/ingest                  — Ingest events into graph
 *  GET  /api/graph/blast-radius/:nodeId    — Blast radius analysis
 *  GET  /api/graph/community-detection     — Find attack clusters
 *  GET  /api/graph/stats                   — Graph database statistics
 *  POST /api/graph/query                   — Raw Cypher query (admin)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const neo4jService = require('../services/graph/neo4j-service');
const { supabase } = require('../config/supabase');
const { z } = require('zod');

router.use(verifyToken);

// ── Schemas ───────────────────────────────────────────────────────
const IngestSchema = z.object({
  events: z.array(z.object({
    event_id:   z.string().max(128),
    event_type: z.string().max(100),
    timestamp:  z.string().datetime({ offset: true }),
    source_ip:  z.string().optional(),
    dest_ip:    z.string().optional(),
    host:       z.string().max(253).optional(),
    username:   z.string().max(255).optional(),
    process:    z.string().max(500).optional(),
    mitre_technique: z.string().max(50).optional(),
    alert_id:   z.string().optional(),
    metadata:   z.record(z.unknown()).optional(),
  })).min(1).max(1000),
  tenant_id: z.string().uuid().optional(),
});

const CypherSchema = z.object({
  query:  z.string().min(1).max(5000),
  params: z.record(z.unknown()).optional(),
  limit:  z.number().int().min(1).max(10000).default(1000),
});

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/graph/attack-chain/:alertId
 * Reconstruct full attack chain for an alert from Neo4j
 */
router.get('/attack-chain/:alertId', asyncHandler(async (req, res) => {
  const { alertId } = req.params;
  const tenantId    = req.tenantId;
  const depth       = Math.min(parseInt(req.query.depth || '5', 10), 15);
  const timeWindow  = parseInt(req.query.time_window_hours || '24', 10);

  // Verify alert belongs to tenant
  const { data: alert } = await supabase
    .from('alerts')
    .select('id, title, severity, host, username, source_ip, event_time, created_at, mitre_tactic, mitre_technique')
    .eq('id', alertId)
    .eq('tenant_id', tenantId)
    .single();

  if (!alert) throw createError(404, 'Alert not found');

  const chain = await neo4jService.reconstructAttackChain(alertId, {
    depth,
    timeWindowHours: timeWindow,
    tenantId,
  });

  // Cache attack chain in alert record
  if (chain?.nodes?.length > 0) {
    await supabase
      .from('alerts')
      .update({
        enrichment_data: { ...(alert.enrichment_data || {}), attack_chain: chain },
        updated_at:      new Date().toISOString(),
      })
      .eq('id', alertId);
  }

  res.json({
    success:    true,
    alert_id:   alertId,
    alert:      { title: alert.title, severity: alert.severity },
    chain: {
      nodes:       chain.nodes       || [],
      edges:       chain.edges       || [],
      root_node:   chain.root_node   || null,
      leaf_nodes:  chain.leaf_nodes  || [],
      depth:       chain.depth       || 0,
      total_events: chain.total_events || 0,
    },
    mitre_path:  chain.mitre_path || [],
    timeline:    chain.timeline   || [],
  });
}));

/**
 * GET /api/graph/threat-actor/:name
 * Get threat actor subgraph: TTPs, campaigns, targets, IOCs
 */
router.get('/threat-actor/:name', asyncHandler(async (req, res) => {
  const { name } = req.params;
  const tenantId = req.tenantId;
  const depth    = Math.min(parseInt(req.query.depth || '3', 10), 8);

  const graph = await neo4jService.getThreatActorGraph(name, {
    depth,
    tenantId,
    includeIocs: req.query.include_iocs !== 'false',
    includeTtps: req.query.include_ttps !== 'false',
  });

  if (!graph || graph.nodes?.length === 0) {
    return res.json({
      success:      true,
      actor:        name,
      found:        false,
      nodes:        [],
      edges:        [],
      message:      `No graph data found for threat actor: ${name}`,
    });
  }

  res.json({
    success:     true,
    actor:       name,
    found:       true,
    nodes:       graph.nodes,
    edges:       graph.edges,
    ttps:        graph.ttps || [],
    campaigns:   graph.campaigns || [],
    target_sectors: graph.target_sectors || [],
    ioc_count:   graph.ioc_count || 0,
  });
}));

/**
 * GET /api/graph/lateral-movement/:host
 * Map lateral movement paths from/to a host
 */
router.get('/lateral-movement/:host', asyncHandler(async (req, res) => {
  const { host } = req.params;
  const tenantId  = req.tenantId;
  const hours     = Math.min(parseInt(req.query.hours || '72', 10), 720);

  const paths = await neo4jService.getLateralMovementPaths(host, {
    tenantId,
    hours,
    maxPaths: 50,
  });

  res.json({
    success:      true,
    host,
    time_window:  `${hours}h`,
    paths:        paths.paths || [],
    compromised_hosts: paths.compromised_hosts || [],
    entry_points: paths.entry_points || [],
    path_count:   paths.paths?.length || 0,
    blast_radius: paths.compromised_hosts?.length || 0,
  });
}));

/**
 * POST /api/graph/ingest
 * Ingest raw security events into Neo4j graph
 */
router.post(
  '/ingest',
  requireRole(['ADMIN', 'SUPER_ADMIN', 'ANALYST']),
  asyncHandler(async (req, res) => {
    const parsed = IngestSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { events } = parsed.data;
    const tenantId   = req.tenantId;

    const result = await neo4jService.ingestEvents(events, tenantId);

    res.json({
      success:        true,
      events_ingested: result.ingested || 0,
      nodes_created:  result.nodes_created || 0,
      edges_created:  result.edges_created || 0,
      duration_ms:    result.duration_ms,
    });
  })
);

/**
 * GET /api/graph/blast-radius/:nodeId
 * Calculate blast radius from a compromised node
 */
router.get('/blast-radius/:nodeId', asyncHandler(async (req, res) => {
  const { nodeId } = req.params;
  const tenantId   = req.tenantId;
  const maxDepth   = Math.min(parseInt(req.query.depth || '5', 10), 10);

  const result = await neo4jService.calculateBlastRadius(nodeId, {
    tenantId,
    maxDepth,
    includeAssets: req.query.include_assets !== 'false',
  });

  res.json({
    success:    true,
    node_id:    nodeId,
    blast_radius: {
      directly_compromised:  result.directly_compromised  || [],
      potentially_reachable: result.potentially_reachable || [],
      critical_assets_at_risk: result.critical_assets    || [],
      estimated_impact_score: result.impact_score         || 0,
    },
    containment_suggestions: result.containment || [],
    graph: {
      nodes: result.nodes || [],
      edges: result.edges || [],
    },
  });
}));

/**
 * GET /api/graph/community-detection
 * Detect attack clusters / communities in the graph
 */
router.get('/community-detection', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const hours    = Math.min(parseInt(req.query.hours || '168', 10), 720);  // Default 7 days
  const minSize  = Math.max(parseInt(req.query.min_size || '3', 10), 2);

  const communities = await neo4jService.detectCommunities({
    tenantId,
    hours,
    minCommunitySize: minSize,
    algorithm: req.query.algorithm || 'louvain',
  });

  res.json({
    success:           true,
    time_window:       `${hours}h`,
    community_count:   communities.length,
    communities:       communities,
    largest_community: communities[0] || null,
  });
}));

/**
 * GET /api/graph/stats
 * Graph database statistics
 */
router.get('/stats', asyncHandler(async (req, res) => {
  const stats = await neo4jService.getGraphStats(req.tenantId);

  res.json({
    success: true,
    data:    stats,
    healthy: stats.connected || false,
  });
}));

/**
 * POST /api/graph/query
 * Execute raw Cypher query (SUPER_ADMIN only)
 */
router.post(
  '/query',
  requireRole(['SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = CypherSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const { query, params, limit } = parsed.data;

    // Safety: block write operations from this endpoint
    const upperQuery = query.trim().toUpperCase();
    const WRITE_OPS  = ['CREATE ', 'DELETE ', 'MERGE ', 'SET ', 'DETACH ', 'REMOVE ', 'DROP '];
    if (WRITE_OPS.some(op => upperQuery.includes(op))) {
      throw createError(403, 'Write operations not allowed via /graph/query endpoint. Use /graph/ingest instead.');
    }

    // Enforce limit
    const limitedQuery = query.trimEnd().endsWith(`LIMIT ${limit}`)
      ? query
      : `${query.replace(/LIMIT\s+\d+/i, '')} LIMIT ${limit}`;

    const result = await neo4jService.runCypher(limitedQuery, params || {}, req.tenantId);

    res.json({
      success:    true,
      row_count:  result.records?.length || 0,
      data:       result.records || [],
      metadata:   result.metadata || {},
    });
  })
);

/**
 * GET /api/graph/timeline/:alertId
 * Get temporal event timeline for an alert/incident from graph
 */
router.get('/timeline/:alertId', asyncHandler(async (req, res) => {
  const { alertId } = req.params;
  const tenantId    = req.tenantId;
  const hours       = Math.min(parseInt(req.query.hours || '24', 10), 168);

  // Verify alert access
  const { data: alert } = await supabase
    .from('alerts')
    .select('id, host, username, source_ip, event_time')
    .eq('id', alertId)
    .eq('tenant_id', tenantId)
    .single();

  if (!alert) throw createError(404, 'Alert not found');

  const timeline = await neo4jService.getEventTimeline(alertId, {
    tenantId,
    hours,
    seedHost:    alert.host,
    seedUser:    alert.username,
    seedIp:      alert.source_ip,
  });

  res.json({
    success:     true,
    alert_id:    alertId,
    time_window: `${hours}h`,
    event_count: timeline.events?.length || 0,
    timeline:    timeline.events || [],
    key_moments: timeline.key_moments || [],
  });
}));

module.exports = router;
