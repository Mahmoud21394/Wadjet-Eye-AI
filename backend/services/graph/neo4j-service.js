/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Neo4j Graph Intelligence Engine (Phase 2C)
 *  backend/services/graph/neo4j-service.js
 *
 *  Replaces flat-table IOC storage with a graph model for
 *  attack chain traversal and IOC relationship mapping.
 *
 *  Nodes: IP, Domain, Hash, Email, Actor, Campaign, TTP, CVE, Asset, User
 *  Edges: USES, ATTRIBUTED_TO, OBSERVED_IN, EXPLOITS, TARGETS, RELATED_TO
 *
 *  Audit finding: No graph database for IOC relationship mapping (HIGH)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const neo4j = require('neo4j-driver');

// ── Connection ────────────────────────────────────────────────────
const NEO4J_URI      = process.env.NEO4J_URI      || 'bolt://neo4j:7687';
const NEO4J_USER     = process.env.NEO4J_USER     || 'neo4j';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'password';

let driver = null;

function getDriver() {
  if (!driver) {
    driver = neo4j.driver(
      NEO4J_URI,
      neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD),
      {
        maxConnectionPoolSize: 50,
        connectionAcquisitionTimeout: 10000,
        maxTransactionRetryTime:      15000,
        logging: { level: 'warn', logger: (level, msg) => console.warn(`[Neo4j] ${level}: ${msg}`) },
      }
    );
    console.log(`[Neo4j] Driver initialized → ${NEO4J_URI}`);
  }
  return driver;
}

async function getSession(database = 'neo4j') {
  return getDriver().session({ database, defaultAccessMode: neo4j.session.WRITE });
}

// ── Schema initialization ─────────────────────────────────────────

/**
 * initSchema — create indexes and constraints on first startup
 */
async function initSchema() {
  const session = await getSession();
  try {
    const constraints = [
      'CREATE CONSTRAINT ioc_value_unique IF NOT EXISTS FOR (n:IOC) REQUIRE n.value IS UNIQUE',
      'CREATE CONSTRAINT actor_name_unique IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.name IS UNIQUE',
      'CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS FOR (n:Campaign) REQUIRE n.stix_id IS UNIQUE',
      'CREATE CONSTRAINT ttp_id_unique IF NOT EXISTS FOR (n:TTP) REQUIRE n.mitre_id IS UNIQUE',
      'CREATE CONSTRAINT cve_id_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE',
      'CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (n:Asset) REQUIRE n.asset_id IS UNIQUE',
    ];

    const indexes = [
      'CREATE INDEX ioc_type IF NOT EXISTS FOR (n:IOC) ON (n.type)',
      'CREATE INDEX ioc_risk_score IF NOT EXISTS FOR (n:IOC) ON (n.risk_score)',
      'CREATE INDEX ioc_tenant IF NOT EXISTS FOR (n:IOC) ON (n.tenant_id)',
      'CREATE INDEX actor_sophistication IF NOT EXISTS FOR (n:ThreatActor) ON (n.sophistication)',
      'CREATE INDEX ttp_tactic IF NOT EXISTS FOR (n:TTP) ON (n.tactic)',
    ];

    for (const stmt of [...constraints, ...indexes]) {
      try { await session.run(stmt); }
      catch (err) { if (!err.message.includes('already exists')) console.warn('[Neo4j] Schema warning:', err.message); }
    }

    console.log('[Neo4j] Schema initialized');
  } finally {
    await session.close();
  }
}

// ── IOC Graph Operations ──────────────────────────────────────────

/**
 * upsertIoc — merge IOC node into graph
 */
async function upsertIoc(ioc) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MERGE (n:IOC { value: $value })
       SET n.type        = $type,
           n.risk_score  = $risk_score,
           n.confidence  = $confidence,
           n.malicious   = $malicious,
           n.first_seen  = $first_seen,
           n.last_seen   = datetime(),
           n.tenant_id   = $tenant_id,
           n.tags        = $tags,
           n.tlp         = $tlp,
           n.description = $description
       RETURN n`,
      {
        value:       ioc.value,
        type:        ioc.type || 'unknown',
        risk_score:  neo4j.int(ioc.risk_score || 0),
        confidence:  neo4j.int(ioc.confidence || 50),
        malicious:   ioc.malicious || false,
        first_seen:  ioc.first_seen || new Date().toISOString(),
        tenant_id:   ioc.tenant_id || 'system',
        tags:        ioc.tags || [],
        tlp:         ioc.tlp || 'AMBER',
        description: ioc.description || '',
      }
    );
    return result.records[0]?.get('n').properties;
  } finally {
    await session.close();
  }
}

/**
 * linkIocToActor — create ATTRIBUTED_TO relationship
 */
async function linkIocToActor(iocValue, actorName, opts = {}) {
  const session = await getSession();
  try {
    await session.run(
      `MERGE (ioc:IOC { value: $iocValue })
       MERGE (actor:ThreatActor { name: $actorName })
       MERGE (ioc)-[r:ATTRIBUTED_TO]->(actor)
       SET r.confidence    = $confidence,
           r.source        = $source,
           r.created_at    = datetime()
       RETURN ioc, actor, r`,
      {
        iocValue,
        actorName,
        confidence: neo4j.int(opts.confidence || 50),
        source:     opts.source || 'analyst',
      }
    );
  } finally {
    await session.close();
  }
}

/**
 * linkIocToTtp — create USES relationship between IOC and TTP
 */
async function linkIocToTtp(iocValue, mitreId, tacticName, opts = {}) {
  const session = await getSession();
  try {
    await session.run(
      `MERGE (ioc:IOC { value: $iocValue })
       MERGE (ttp:TTP { mitre_id: $mitreId })
       SET ttp.tactic      = $tacticName,
           ttp.name        = $ttpName
       MERGE (ioc)-[r:USES]->(ttp)
       SET r.confidence    = $confidence,
           r.created_at    = datetime()`,
      {
        iocValue,
        mitreId,
        tacticName,
        ttpName: opts.ttpName || mitreId,
        confidence: neo4j.int(opts.confidence || 50),
      }
    );
  } finally {
    await session.close();
  }
}

/**
 * linkIocToAsset — record that an IOC was OBSERVED_IN an asset
 */
async function linkIocToAsset(iocValue, assetId, assetHost, opts = {}) {
  const session = await getSession();
  try {
    await session.run(
      `MERGE (ioc:IOC { value: $iocValue })
       MERGE (asset:Asset { asset_id: $assetId })
       SET asset.host      = $assetHost,
           asset.tenant_id = $tenantId
       MERGE (ioc)-[r:OBSERVED_IN]->(asset)
       SET r.first_seen    = $firstSeen,
           r.last_seen     = datetime(),
           r.event_count   = COALESCE(r.event_count, 0) + 1`,
      {
        iocValue, assetId, assetHost,
        tenantId:  opts.tenantId || 'system',
        firstSeen: opts.firstSeen || new Date().toISOString(),
      }
    );
  } finally {
    await session.close();
  }
}

// ── Attack Chain Reconstruction ───────────────────────────────────

/**
 * reconstructAttackChain — given an initial IOC or asset, traverse
 * the graph to reconstruct the full attack chain
 *
 * @param {string} startValue - IOC value or asset ID
 * @param {number} depth - Traversal depth (default 4 hops)
 * @param {string} tenantId - Tenant isolation
 * @returns {{ nodes: object[], edges: object[], chain: object[] }}
 */
async function reconstructAttackChain(startValue, depth = 4, tenantId) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MATCH path = (start { value: $startValue })-[*1..${depth}]-(end)
       WHERE start.tenant_id = $tenantId OR start.tenant_id = 'system'
       RETURN path
       LIMIT 200`,
      { startValue, tenantId }
    );

    const nodes = new Map();
    const edges  = [];

    for (const record of result.records) {
      const path = record.get('path');
      for (const segment of path.segments) {
        const startNode = nodeToObj(segment.start);
        const endNode   = nodeToObj(segment.end);
        nodes.set(startNode.id, startNode);
        nodes.set(endNode.id,   endNode);
        edges.push({
          id:     segment.relationship.identity.toString(),
          source: segment.start.identity.toString(),
          target: segment.end.identity.toString(),
          type:   segment.relationship.type,
          props:  segment.relationship.properties,
        });
      }
    }

    // Sort nodes into kill-chain order
    const TACTIC_ORDER = ['initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','exfiltration','impact'];
    const chain = Array.from(nodes.values())
      .filter(n => n.labels?.includes('TTP'))
      .sort((a, b) => TACTIC_ORDER.indexOf(a.tactic) - TACTIC_ORDER.indexOf(b.tactic));

    return {
      nodes:  Array.from(nodes.values()),
      edges,
      chain,
      depth_reached: depth,
      start_value:   startValue,
    };
  } finally {
    await session.close();
  }
}

/**
 * findRelatedIocs — find IOCs related to a given IOC via shared TTPs/actors
 */
async function findRelatedIocs(iocValue, limit = 20) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MATCH (start:IOC { value: $iocValue })-[:ATTRIBUTED_TO|USES|RELATED_TO*1..3]-(related:IOC)
       WHERE related.value <> $iocValue
       RETURN DISTINCT related, count(*) AS relevance
       ORDER BY relevance DESC
       LIMIT $limit`,
      { iocValue, limit: neo4j.int(limit) }
    );

    return result.records.map(r => ({
      ...r.get('related').properties,
      relevance: r.get('relevance').toNumber(),
    }));
  } finally {
    await session.close();
  }
}

/**
 * getActorProfile — full graph profile of a threat actor
 */
async function getActorProfile(actorName) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MATCH (actor:ThreatActor { name: $actorName })
       OPTIONAL MATCH (ioc:IOC)-[:ATTRIBUTED_TO]->(actor)
       OPTIONAL MATCH (actor)-[:USES]->(ttp:TTP)
       OPTIONAL MATCH (actor)-[:TARGETS]->(target)
       RETURN actor,
              collect(DISTINCT ioc)    AS iocs,
              collect(DISTINCT ttp)    AS ttps,
              collect(DISTINCT target) AS targets`,
      { actorName }
    );

    if (!result.records.length) return null;
    const rec = result.records[0];
    return {
      actor:   rec.get('actor').properties,
      iocs:    rec.get('iocs').map(n => n.properties),
      ttps:    rec.get('ttps').map(n => n.properties),
      targets: rec.get('targets').map(n => n.properties),
    };
  } finally {
    await session.close();
  }
}

/**
 * getIocGraph — get subgraph around a single IOC for visualization
 */
async function getIocGraph(iocValue, hops = 2) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MATCH (center:IOC { value: $iocValue })
       CALL apoc.path.subgraphAll(center, { maxLevel: $hops, limit: 150 })
       YIELD nodes, relationships
       RETURN nodes, relationships`,
      { iocValue, hops: neo4j.int(hops) }
    );

    if (!result.records.length) {
      // Fallback without APOC
      return reconstructAttackChain(iocValue, hops);
    }

    const rec   = result.records[0];
    const nodes = rec.get('nodes').map(nodeToObj);
    const edges = rec.get('relationships').map(r => ({
      id:     r.identity.toString(),
      source: r.start.toString(),
      target: r.end.toString(),
      type:   r.type,
    }));

    return { nodes, edges };
  } finally {
    await session.close();
  }
}

/**
 * getMitreHeatmap — aggregate TTP coverage across all tenant alerts
 */
async function getMitreHeatmap(tenantId) {
  const session = await getSession();
  try {
    const result = await session.run(
      `MATCH (ioc:IOC { tenant_id: $tenantId })-[:USES]->(ttp:TTP)
       RETURN ttp.mitre_id AS mitre_id,
              ttp.tactic   AS tactic,
              ttp.name     AS name,
              count(ioc)   AS hit_count
       ORDER BY hit_count DESC`,
      { tenantId }
    );

    return result.records.map(r => ({
      mitre_id:  r.get('mitre_id'),
      tactic:    r.get('tactic'),
      name:      r.get('name'),
      hit_count: r.get('hit_count').toNumber(),
    }));
  } finally {
    await session.close();
  }
}

// ── Helpers ───────────────────────────────────────────────────────

function nodeToObj(node) {
  return {
    id:     node.identity.toString(),
    labels: node.labels,
    ...node.properties,
  };
}

// ── Health check ──────────────────────────────────────────────────
async function healthCheck() {
  const session = await getSession();
  try {
    const result = await session.run('RETURN 1 AS alive');
    return { healthy: true, alive: result.records[0]?.get('alive')?.toNumber() === 1 };
  } catch (err) {
    return { healthy: false, error: err.message };
  } finally {
    await session.close();
  }
}

async function disconnect() {
  if (driver) { await driver.close(); driver = null; }
}

module.exports = {
  initSchema,
  upsertIoc,
  linkIocToActor,
  linkIocToTtp,
  linkIocToAsset,
  reconstructAttackChain,
  findRelatedIocs,
  getActorProfile,
  getIocGraph,
  getMitreHeatmap,
  healthCheck,
  disconnect,
  getDriver,
};
