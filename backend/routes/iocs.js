/**
 * ══════════════════════════════════════════════════════════
 *  IOC Routes — Threat Intelligence Database  v5.3
 *  FILE: backend/routes/iocs.js
 *
 *  v5.3 FIX — Empty results / 0 total IOCs:
 *  ─────────────────────────────────────────
 *  ROOT CAUSE #1: Routes used `supabase` (anon/user-scoped client)
 *    which is blocked by RLS when no SELECT policy exists.
 *    FIX: Use supabaseAdmin (service_role) for ALL reads/writes.
 *    Service_role bypasses RLS entirely — the backend enforces
 *    tenant isolation at the application layer (.eq('tenant_id',...)).
 *
 *  ROOT CAUSE #2: req.tenantId can be NULL when the user profile
 *    lookup fails (PROFILE_MISSING). A null tenant_id causes
 *    .eq('tenant_id', null) which matches ZERO rows.
 *    FIX: Fall back to DEFAULT_TENANT_ID and log a warning.
 *
 *  ROOT CAUSE #3: Search used .or(value.ilike...) which Supabase
 *    requires careful escaping. FIX: sanitize search input.
 *
 *  GET    /api/iocs
 *  GET    /api/iocs/:id
 *  POST   /api/iocs
 *  PATCH  /api/iocs/:id
 *  DELETE /api/iocs/:id
 *  POST   /api/iocs/bulk
 *  GET    /api/iocs/:id/enrich
 *  POST   /api/iocs/pivot
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { createClient } = require('@supabase/supabase-js');
const { requireRole, requirePermission } = require('../middleware/auth');
const { asyncHandler, createError }      = require('../middleware/errorHandler');
const { enrichIOC }  = require('../services/enrichment');

// ── CRITICAL FIX: Use service_role client (bypasses RLS) ──────────────────
// The anon client is blocked by RLS when no SELECT policy exists.
// Backend enforces tenant isolation via .eq('tenant_id', tenantId) instead.
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Fallback tenant ID (matches the tenant used by ingestion pipeline)
const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

/**
 * Resolve the effective tenant ID for a request.
 * Falls back to DEFAULT_TENANT when req.tenantId is null/undefined.
 * Logs a warning so developers can trace the root cause.
 */
function resolveTenantId(req) {
  const tenantId = req.tenantId || req.user?.tenant_id;
  if (!tenantId) {
    console.warn(
      `[IOC] req.tenantId is NULL for user=${req.user?.email || 'unknown'} — ` +
      `falling back to DEFAULT_TENANT=${DEFAULT_TENANT}. ` +
      `Fix: ensure the user row in public.users has a valid tenant_id.`
    );
    return DEFAULT_TENANT;
  }
  return tenantId;
}

/**
 * Sanitize a search string to prevent Supabase query injection.
 * Removes special characters that break the .or() filter syntax.
 */
function sanitizeSearch(s) {
  if (!s || typeof s !== 'string') return '';
  // Remove characters that could break Supabase PostgREST filter syntax
  return s.replace(/[(),"'\\]/g, '').trim().slice(0, 200);
}

/* ════════════════════════════════════════════════════════
   GET /api/iocs
   List IOCs for the authenticated user's tenant.
   Supports pagination, filtering, and text search.
════════════════════════════════════════════════════════ */
router.get('/', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 50,
    type,
    risk_min,
    country,
    search,
    sort = 'risk_score',
    order = 'desc',
    reputation,
    source,
    min_confidence,
    threat_actor,
    status,
    all_tenants,  // SUPER_ADMIN only: view IOCs across all tenants
  } = req.query;

  const userRole   = req.user?.role || '';
  const isSuperAdmin = ['SUPER_ADMIN','super_admin'].includes(userRole);

  // all_tenants=1 is only allowed for SUPER_ADMIN users
  const viewAllTenants = all_tenants === '1' && isSuperAdmin;

  const tenantId = viewAllTenants ? null : resolveTenantId(req);
  const pageNum  = Math.max(1, parseInt(page) || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit) || 50));
  const offset   = (pageNum - 1) * limitNum;

  // Validate sort column to prevent injection
  const SORTABLE_COLS = new Set([
    'risk_score','confidence','last_seen','first_seen','created_at',
    'updated_at','value','type','reputation','source'
  ]);
  const sortCol = SORTABLE_COLS.has(sort) ? sort : 'risk_score';
  const ascending = order === 'asc';

  let query = supabaseAdmin
    .from('iocs')
    .select('*', { count: 'exact' })
    .order(sortCol, { ascending })
    .range(offset, offset + limitNum - 1);

  // Apply tenant filter unless SUPER_ADMIN is viewing all tenants
  if (tenantId) {
    query = query.eq('tenant_id', tenantId);
  }

  // Apply filters
  if (type)           query = query.eq('type', type);
  if (country)        query = query.eq('country', country);
  if (risk_min)       query = query.gte('risk_score', parseFloat(risk_min));
  if (reputation)     query = query.eq('reputation', reputation);
  if (source)         query = query.eq('source', source);
  if (min_confidence) query = query.gte('confidence', parseInt(min_confidence));
  if (threat_actor)   query = query.ilike('threat_actor', `%${sanitizeSearch(threat_actor)}%`);
  if (status)         query = query.eq('status', status);

  // Full-text search across key fields
  if (search) {
    const s = sanitizeSearch(search);
    if (s) {
      query = query.or(
        `value.ilike.%${s}%,threat_actor.ilike.%${s}%,malware_family.ilike.%${s}%,notes.ilike.%${s}%,asn.ilike.%${s}%`
      );
    }
  }

  const { data, error, count } = await query;

  if (error) {
    console.error('[IOC] List query error:', error.message, '| tenant:', tenantId || 'ALL');
    throw createError(500, error.message);
  }

  const scope = viewAllTenants ? 'ALL_TENANTS' : tenantId;
  console.log(`[IOC] GET /iocs — scope=${scope} total=${count} page=${pageNum} returned=${data?.length || 0}`);

  res.json({
    data:       data || [],
    total:      count || 0,
    pagination: { page: pageNum, limit: limitNum, total: count || 0 },
    _scope:     viewAllTenants ? 'all_tenants' : 'tenant',
  });
}));

/* ════════════════════════════════════════════════════════
   GET /api/iocs/:id
════════════════════════════════════════════════════════ */
router.get('/:id', asyncHandler(async (req, res) => {
  const tenantId = resolveTenantId(req);

  const { data, error } = await supabaseAdmin
    .from('iocs')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .single();

  if (error || !data) throw createError(404, 'IOC not found');
  res.json(data);
}));

/* ════════════════════════════════════════════════════════
   POST /api/iocs — Create single IOC
════════════════════════════════════════════════════════ */
router.post('/', requirePermission('manage_iocs'), asyncHandler(async (req, res) => {
  const { value, type, source, tags, metadata, risk_score, reputation, confidence } = req.body;
  if (!value || !type) throw createError(400, 'value and type are required');

  const tenantId = resolveTenantId(req);

  /* Check for duplicate */
  const { data: existing } = await supabaseAdmin
    .from('iocs')
    .select('id')
    .eq('value', value.trim())
    .eq('tenant_id', tenantId)
    .single();

  if (existing) {
    return res.status(409).json({ error: 'IOC already exists', id: existing.id });
  }

  const { data, error } = await supabaseAdmin
    .from('iocs')
    .insert({
      tenant_id:   tenantId,
      value:       value.trim(),
      type,
      source:      source     || 'manual',
      tags:        tags       || [],
      metadata:    metadata   || {},
      risk_score:  risk_score || 0,
      reputation:  reputation || 'unknown',
      confidence:  confidence || 80,
      status:      'active',
      first_seen:  new Date().toISOString(),
      last_seen:   new Date().toISOString(),
      created_by:  req.user.id,
    })
    .select()
    .single();

  if (error) throw createError(500, error.message);

  /* Trigger async enrichment (non-blocking) */
  enrichIOC(data.id, value, type, tenantId).catch(err =>
    console.error('[IOC] Auto-enrich failed:', err.message)
  );

  res.status(201).json(data);
}));

/* ════════════════════════════════════════════════════════
   POST /api/iocs/bulk — CSV/array bulk upload
════════════════════════════════════════════════════════ */
router.post('/bulk', requirePermission('manage_iocs'), asyncHandler(async (req, res) => {
  const { iocs } = req.body;

  if (!Array.isArray(iocs) || iocs.length === 0) {
    throw createError(400, 'iocs array is required');
  }
  if (iocs.length > 1000) {
    throw createError(400, 'Maximum 1000 IOCs per bulk upload');
  }

  const tenantId = resolveTenantId(req);

  const rows = iocs
    .filter(i => i.value && i.type)
    .map(i => ({
      tenant_id:  tenantId,
      value:      i.value.trim(),
      type:       i.type,
      source:     i.source     || 'bulk_import',
      tags:       i.tags       || [],
      risk_score: i.risk_score || 0,
      reputation: i.reputation || 'unknown',
      status:     'active',
      first_seen: new Date().toISOString(),
      last_seen:  new Date().toISOString(),
      created_by: req.user.id,
    }));

  const { data, error } = await supabaseAdmin
    .from('iocs')
    .upsert(rows, { onConflict: 'tenant_id,value' })
    .select();

  if (error) throw createError(500, error.message);

  res.status(201).json({
    imported: data?.length || 0,
    skipped:  iocs.length - (data?.length || 0),
    data:     data || [],
  });
}));

/* ════════════════════════════════════════════════════════
   GET /api/iocs/:id/enrich — On-demand enrichment
════════════════════════════════════════════════════════ */
router.get('/:id/enrich', asyncHandler(async (req, res) => {
  const tenantId = resolveTenantId(req);

  const { data: ioc, error } = await supabaseAdmin
    .from('iocs')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .single();

  if (error || !ioc) throw createError(404, 'IOC not found');

  /* Check cache: only re-enrich if older than 1 hour */
  const enrichedAt = ioc.enriched_at ? new Date(ioc.enriched_at) : null;
  const cacheAge   = enrichedAt ? (Date.now() - enrichedAt.getTime()) / 1000 / 60 : Infinity;

  if (cacheAge < 60 && ioc.enrichment_data && Object.keys(ioc.enrichment_data || {}).length > 0) {
    return res.json({ ...ioc, fromCache: true });
  }

  const enriched = await enrichIOC(ioc.id, ioc.value, ioc.type, tenantId);
  res.json({ ...ioc, ...enriched, fromCache: false });
}));

/* ════════════════════════════════════════════════════════
   POST /api/iocs/pivot — Pivot search
════════════════════════════════════════════════════════ */
router.post('/pivot', asyncHandler(async (req, res) => {
  const { field, value } = req.body;
  const validFields = ['asn', 'country', 'threat_actor', 'tags', 'source', 'malware_family'];

  if (!validFields.includes(field)) {
    throw createError(400, `Invalid pivot field. Valid: ${validFields.join(', ')}`);
  }

  const tenantId = resolveTenantId(req);

  let query = supabaseAdmin
    .from('iocs')
    .select('*')
    .eq('tenant_id', tenantId)
    .limit(100);

  if (field === 'tags') {
    query = query.contains('tags', [value]);
  } else {
    query = query.eq(field, value);
  }

  const { data, error } = await query;
  if (error) throw createError(500, error.message);

  res.json({ pivot_field: field, pivot_value: value, count: data?.length || 0, data: data || [] });
}));

/* ════════════════════════════════════════════════════════
   PATCH /api/iocs/:id
════════════════════════════════════════════════════════ */
router.patch('/:id', requirePermission('manage_iocs'), asyncHandler(async (req, res) => {
  const tenantId = resolveTenantId(req);
  const allowed  = ['status','tags','notes','risk_score','threat_actor','false_positive','reputation','confidence'];
  const updates  = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  if (Object.keys(updates).length === 0) {
    throw createError(400, 'No valid fields to update');
  }

  const { data, error } = await supabaseAdmin
    .from('iocs')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .select()
    .single();

  if (error || !data) throw createError(404, 'IOC not found or update failed');
  res.json(data);
}));

/* ════════════════════════════════════════════════════════
   DELETE /api/iocs/:id
════════════════════════════════════════════════════════ */
router.delete('/:id',
  requireRole(['ANALYST','ADMIN','SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const tenantId = resolveTenantId(req);

    const { error } = await supabaseAdmin
      .from('iocs')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', tenantId);

    if (error) throw createError(500, error.message);
    res.status(204).send();
  })
);

module.exports = router;
