/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — STIX/TAXII 2.1 Routes (Phase 6)
 *  backend/routes/stix.js
 *
 *  TAXII 2.1 Server endpoints + STIX bundle operations:
 *
 *  TAXII Discovery:
 *    GET  /api/stix/taxii/                  — TAXII discovery
 *    GET  /api/stix/taxii/collections/      — List collections
 *    GET  /api/stix/taxii/collections/:id/objects/ — Get STIX objects
 *    POST /api/stix/taxii/collections/:id/objects/ — Add STIX objects
 *
 *  STIX Operations:
 *    POST /api/stix/ingest              — Ingest STIX 2.1 bundle
 *    GET  /api/stix/bundle/:id          — Export bundle
 *    POST /api/stix/search             — Search STIX objects
 *    GET  /api/stix/indicators          — All indicators
 *    GET  /api/stix/threat-actors       — All threat actors
 *    POST /api/stix/ioc/export          — Export IOCs as STIX bundle
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { validateBody, validateQuery } = require('../schemas/validation');
const stixService = require('../services/stix/stix-service');
const { supabase } = require('../config/supabase');
const { z } = require('zod');

// ── Schemas ───────────────────────────────────────────────────────
const IngestBundleSchema = z.object({
  type:    z.literal('bundle'),
  id:      z.string().startsWith('bundle--'),
  objects: z.array(z.record(z.unknown())).min(1).max(10000),
  spec_version: z.enum(['2.0', '2.1']).optional(),
});

const StixSearchSchema = z.object({
  type:        z.string().optional(),
  query:       z.string().max(500).optional(),
  tags:        z.array(z.string()).optional(),
  tlp:         z.enum(['WHITE','GREEN','AMBER','RED']).optional(),
  page:        z.coerce.number().int().min(1).default(1),
  limit:       z.coerce.number().int().min(1).max(500).default(50),
  since:       z.string().datetime({ offset: true }).optional(),
  until:       z.string().datetime({ offset: true }).optional(),
  source_feed: z.string().max(100).optional(),
});

// ── TAXII 2.1 Media Type ──────────────────────────────────────────
const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';

function taxiiResponse(res, data, status = 200) {
  return res.status(status)
    .set('Content-Type', TAXII_CONTENT_TYPE)
    .json(data);
}

// ══════════════════════════════════════════════════════════════════
//  TAXII 2.1 DISCOVERY
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/stix/taxii/
 * TAXII 2.1 Discovery endpoint
 */
router.get('/taxii/', asyncHandler(async (req, res) => {
  return taxiiResponse(res, {
    title:       'Wadjet-Eye AI TAXII Server',
    description: 'Wadjet-Eye AI Threat Intelligence TAXII 2.1 Server',
    contact:     'platform@wadjet-eye.io',
    default:     `${req.protocol}://${req.hostname}/api/stix/taxii/`,
    api_roots: [
      `${req.protocol}://${req.hostname}/api/stix/taxii/`,
    ],
  });
}));

/**
 * GET /api/stix/taxii/collections/
 * List available TAXII collections
 */
router.get('/taxii/collections/', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const collections = [
    {
      id:          `${tenantId}-indicators`,
      title:       'Threat Indicators',
      description: 'STIX 2.1 indicator objects (IOCs)',
      can_read:    true,
      can_write:   ['ADMIN','SUPER_ADMIN'].includes(req.user?.role),
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id:          `${tenantId}-threat-actors`,
      title:       'Threat Actors',
      description: 'STIX 2.1 threat actor and intrusion set objects',
      can_read:    true,
      can_write:   ['ADMIN','SUPER_ADMIN'].includes(req.user?.role),
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id:          `${tenantId}-malware`,
      title:       'Malware',
      description: 'STIX 2.1 malware objects',
      can_read:    true,
      can_write:   ['ADMIN','SUPER_ADMIN'].includes(req.user?.role),
      media_types: ['application/stix+json;version=2.1'],
    },
    {
      id:          `${tenantId}-vulnerabilities`,
      title:       'Vulnerabilities',
      description: 'STIX 2.1 vulnerability objects (CVEs)',
      can_read:    true,
      can_write:   false,
      media_types: ['application/stix+json;version=2.1'],
    },
  ];

  return taxiiResponse(res, { collections });
}));

/**
 * GET /api/stix/taxii/collections/:collectionId/objects/
 * Retrieve STIX objects from a collection
 */
router.get('/taxii/collections/:collectionId/objects/', verifyToken, asyncHandler(async (req, res) => {
  const { collectionId } = req.params;
  const tenantId  = req.tenantId;
  const limit     = Math.min(parseInt(req.query.limit || '100', 10), 1000);
  const added_after = req.query.added_after;

  // Validate collection belongs to this tenant
  if (!collectionId.startsWith(tenantId)) {
    throw createError(403, 'Access denied to this collection');
  }

  // Determine STIX type from collection ID suffix
  let stixType = null;
  if (collectionId.endsWith('-indicators'))    stixType = 'indicator';
  if (collectionId.endsWith('-threat-actors')) stixType = 'threat-actor';
  if (collectionId.endsWith('-malware'))       stixType = 'malware';
  if (collectionId.endsWith('-vulnerabilities')) stixType = 'vulnerability';

  // Query Supabase threat_intel table
  let query = supabase
    .from('threat_intel')
    .select('*')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (stixType)    query = query.eq('stix_type', stixType);
  if (added_after) query = query.gte('created_at', added_after);

  const { data, error } = await query;
  if (error) throw createError(500, `TAXII query failed: ${error.message}`);

  // Convert DB rows to STIX objects
  const stixObjects = (data || []).map(row => row.raw_stix || {
    type:            row.stix_type,
    id:              row.stix_id,
    spec_version:    '2.1',
    name:            row.name,
    description:     row.description,
    confidence:      row.confidence,
    created:         row.created_at,
    modified:        row.modified_at,
    valid_from:      row.valid_from,
    valid_until:     row.valid_until,
    pattern:         row.pattern,
    pattern_type:    row.pattern_type,
    kill_chain_phases: row.kill_chain_phases,
    external_references: row.external_refs,
    labels:          row.tags,
    object_marking_refs: tlpToStixRef(row.tlp),
  });

  return taxiiResponse(res, {
    objects:    stixObjects,
    next:       null,   // Pagination cursor (implement for production)
    more:       false,
  });
}));

/**
 * POST /api/stix/taxii/collections/:collectionId/objects/
 * Add STIX objects to a collection (TAXII write)
 */
router.post(
  '/taxii/collections/:collectionId/objects/',
  verifyToken,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { collectionId } = req.params;
    const tenantId = req.tenantId;

    if (!collectionId.startsWith(tenantId)) {
      throw createError(403, 'Write access denied to this collection');
    }

    // Validate STIX bundle format
    const bundle = req.body;
    if (!bundle || bundle.type !== 'bundle' || !Array.isArray(bundle.objects)) {
      throw createError(400, 'Request body must be a valid STIX bundle');
    }

    const result = await stixService.ingestBundle(bundle, tenantId);

    return taxiiResponse(res, {
      id:      `status--${Date.now()}`,
      status:  'complete',
      request_timestamp: new Date().toISOString(),
      total_count:     bundle.objects.length,
      success_count:   result.ingested || 0,
      failure_count:   result.errors?.length || 0,
      pending_count:   0,
      failures:        result.errors || [],
    }, 202);
  })
);

// ══════════════════════════════════════════════════════════════════
//  STIX BUNDLE OPERATIONS
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/stix/ingest
 * Ingest a STIX 2.1 bundle
 */
router.post(
  '/ingest',
  verifyToken,
  requireRole(['ADMIN', 'SUPER_ADMIN', 'ANALYST']),
  asyncHandler(async (req, res) => {
    const parsed = IngestBundleSchema.safeParse(req.body);
    if (!parsed.success) {
      throw createError(400, `Invalid STIX bundle: ${parsed.error.message}`);
    }

    const result = await stixService.ingestBundle(parsed.data, req.tenantId);

    res.json({
      success:   true,
      bundle_id: parsed.data.id,
      ingested:  result.ingested,
      skipped:   result.skipped,
      errors:    result.errors,
      duration_ms: result.duration_ms,
    });
  })
);

/**
 * GET /api/stix/bundle/:bundleId
 * Export all STIX objects from a bundle as STIX 2.1 JSON
 */
router.get('/bundle/:bundleId', verifyToken, asyncHandler(async (req, res) => {
  const { bundleId } = req.params;
  const tenantId = req.tenantId;

  const { data, error } = await supabase
    .from('threat_intel')
    .select('*')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .contains('external_refs', JSON.stringify([{ bundle_id: bundleId }]));

  if (error) throw createError(500, error.message);

  if (!data || data.length === 0) {
    throw createError(404, `Bundle ${bundleId} not found`);
  }

  const bundle = stixService.buildBundle(data, bundleId);
  res.set('Content-Type', 'application/stix+json;version=2.1')
     .json(bundle);
}));

/**
 * POST /api/stix/search
 * Search STIX threat intelligence objects
 */
router.post('/search', verifyToken, asyncHandler(async (req, res) => {
  const parsed = StixSearchSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const params = parsed.data;
  const tenantId = req.tenantId;
  const offset = (params.page - 1) * params.limit;

  let query = supabase
    .from('threat_intel')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .order('created_at', { ascending: false })
    .range(offset, offset + params.limit - 1);

  if (params.type)        query = query.eq('stix_type', params.type);
  if (params.tlp)         query = query.eq('tlp', params.tlp);
  if (params.source_feed) query = query.eq('source_feed', params.source_feed);
  if (params.since)       query = query.gte('created_at', params.since);
  if (params.until)       query = query.lte('created_at', params.until);
  if (params.query) {
    query = query.or(`name.ilike.%${params.query}%,description.ilike.%${params.query}%`);
  }
  if (params.tags?.length) {
    query = query.overlaps('tags', params.tags);
  }

  const { data, error, count } = await query;
  if (error) throw createError(500, error.message);

  res.json({
    success:      true,
    total:        count || 0,
    page:         params.page,
    limit:        params.limit,
    data:         data || [],
    pages:        Math.ceil((count || 0) / params.limit),
  });
}));

/**
 * GET /api/stix/indicators
 * List all active STIX indicators (IOC patterns)
 */
router.get('/indicators', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit    = Math.min(parseInt(req.query.limit || '100', 10), 1000);
  const active   = req.query.active !== 'false';

  let query = supabase
    .from('threat_intel')
    .select('stix_id, name, description, pattern, pattern_type, valid_from, valid_until, confidence, tags, tlp, source_feed, created_at')
    .eq('stix_type', 'indicator')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .order('confidence', { ascending: false })
    .limit(limit);

  if (active) {
    query = query.or(`valid_until.is.null,valid_until.gt.${new Date().toISOString()}`);
  }

  const { data, error } = await query;
  if (error) throw createError(500, error.message);

  res.json({ success: true, count: (data || []).length, indicators: data || [] });
}));

/**
 * GET /api/stix/threat-actors
 * List all threat actor STIX objects
 */
router.get('/threat-actors', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);

  const { data, error } = await supabase
    .from('threat_intel')
    .select('*')
    .in('stix_type', ['threat-actor', 'intrusion-set', 'campaign'])
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .order('confidence', { ascending: false })
    .limit(limit);

  if (error) throw createError(500, error.message);

  res.json({ success: true, count: (data || []).length, threat_actors: data || [] });
}));

/**
 * POST /api/stix/ioc/export
 * Export IOCs from Supabase as a STIX 2.1 bundle
 */
router.post(
  '/ioc/export',
  verifyToken,
  requireRole(['ANALYST', 'TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const tenantId = req.tenantId;
    const { severity, tags, limit = 500 } = req.body || {};

    let query = supabase
      .from('iocs')
      .select('*')
      .eq('tenant_id', tenantId)
      .eq('active', true)
      .eq('false_positive', false)
      .order('risk_score', { ascending: false })
      .limit(Math.min(limit, 5000));

    if (severity) query = query.eq('severity', severity);
    if (tags?.length) query = query.overlaps('tags', tags);

    const { data, error } = await query;
    if (error) throw createError(500, error.message);

    // Convert IOCs to STIX indicators
    const stixObjects = (data || []).map(ioc => stixService.iocToStixIndicator(ioc));
    const bundle      = stixService.buildBundle(stixObjects);

    res.set('Content-Disposition', `attachment; filename="wadjet-eye-iocs-${Date.now()}.json"`)
       .set('Content-Type', 'application/stix+json;version=2.1')
       .json(bundle);
  })
);

/**
 * GET /api/stix/feeds
 * List configured TAXII feed subscriptions
 */
router.get('/feeds', verifyToken, asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('collectors')
    .select('id, name, collector_type, enabled, last_run_at, last_success_at, config')
    .eq('tenant_id', req.tenantId)
    .eq('collector_type', 'taxii');

  if (error) throw createError(500, error.message);

  res.json({ success: true, feeds: data || [] });
}));

/**
 * POST /api/stix/feeds/sync
 * Trigger immediate TAXII feed synchronization
 */
router.post(
  '/feeds/sync',
  verifyToken,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { feed_id } = req.body || {};

    const result = await stixService.syncTaxiiFeeds(req.tenantId, feed_id);

    res.json({
      success: true,
      synced_feeds: result.synced,
      objects_ingested: result.total_ingested,
      errors: result.errors,
    });
  })
);

// ── Helper ────────────────────────────────────────────────────────
function tlpToStixRef(tlp) {
  const TLP_REFS = {
    WHITE: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    GREEN: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    AMBER: 'marking-definition--f88d31f6-1088-4efe-bc86-7f5ac0756dce',
    RED:   'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
  };
  return TLP_REFS[tlp] ? [TLP_REFS[tlp]] : [];
}

module.exports = router;
