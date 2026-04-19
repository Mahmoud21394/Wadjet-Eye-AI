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

   v5.4 FIX — DB Timeout (statement timeout):
   ────────────────────────────────────────────
   ROOT CAUSE: select('*', { count: 'exact' }) performs a full-table
   count via COUNT(*) on every request. On large tables (>10k rows)
   this times out after 30s on Render free tier.

   FIXES:
   1. Split into two separate queries: data fetch + head-only count
   2. count query uses { count: 'exact', head: true } — returns only
      the count, no row data, much faster
   3. Default limit reduced to 25 (was 50) to reduce data transfer
   4. Hard timeout: both queries run with Promise.race() 8s timeout
   5. On timeout: return partial data (data without count) with
      `total: -1` so the frontend handles gracefully
════════════════════════════════════════════════════════ */
const IOC_QUERY_TIMEOUT_MS = 8_000;  // 8-second hard limit per query

/** Wrap a Supabase promise with a hard timeout */
function _withQueryTimeout(promise, label = 'query') {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`DB timeout (${label} > ${IOC_QUERY_TIMEOUT_MS / 1000}s)`)), IOC_QUERY_TIMEOUT_MS)
    ),
  ]);
}

router.get('/', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 25,       // Reduced from 50 → 25 to cut data transfer time
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
    no_count,     // pass no_count=1 to skip the expensive COUNT query
  } = req.query;

  const userRole     = req.user?.role || '';
  const isSuperAdmin = ['SUPER_ADMIN','super_admin'].includes(userRole);

  const viewAllTenants = all_tenants === '1' && isSuperAdmin;

  const tenantId = viewAllTenants ? null : resolveTenantId(req);
  const pageNum  = Math.max(1, parseInt(page) || 1);
  const limitNum = Math.min(100, Math.max(1, parseInt(limit) || 25));  // max 100 (was 200)
  const offset   = (pageNum - 1) * limitNum;

  const SORTABLE_COLS = new Set([
    'risk_score','confidence','last_seen','first_seen','created_at',
    'updated_at','value','type','reputation','source'
  ]);
  const sortCol  = SORTABLE_COLS.has(sort) ? sort : 'risk_score';
  const ascending = order === 'asc';

  // ── Build base filter function (reused for both data + count queries) ──────
  function _applyFilters(q) {
    if (tenantId) q = q.eq('tenant_id', tenantId);
    if (type)           q = q.eq('type', type);
    if (country)        q = q.eq('country', country);
    if (risk_min)       q = q.gte('risk_score', parseFloat(risk_min));
    if (reputation)     q = q.eq('reputation', reputation);
    if (source)         q = q.eq('source', source);
    if (min_confidence) q = q.gte('confidence', parseInt(min_confidence));
    if (threat_actor)   q = q.ilike('threat_actor', `%${sanitizeSearch(threat_actor)}%`);
    if (status)         q = q.eq('status', status);
    if (search) {
      const s = sanitizeSearch(search);
      if (s) q = q.or(`value.ilike.%${s}%,threat_actor.ilike.%${s}%,malware_family.ilike.%${s}%,notes.ilike.%${s}%,asn.ilike.%${s}%`);
    }
    return q;
  }

  // ── Data query: fetch rows only (no COUNT) ────────────────────────────────
  let dataQuery = supabaseAdmin
    .from('iocs')
    .select('*')  // NO count: 'exact' here — that's the slow part
    .order(sortCol, { ascending })
    .range(offset, offset + limitNum - 1);
  dataQuery = _applyFilters(dataQuery);

  let data, count;

  try {
    const { data: rows, error: dataErr } = await _withQueryTimeout(dataQuery, 'data');
    if (dataErr) {
      // Check for statement timeout specifically
      if (dataErr.message?.includes('timeout') || dataErr.code === '57014') {
        console.warn(`[IOC] STATEMENT_TIMEOUT on data query — tenant=${tenantId} page=${pageNum}`);
        return res.status(503).json({
          error:   'Database query timed out. Try a smaller page size or add filters.',
          code:    'INTERNAL_ERROR',
          path:    '/api/iocs',
          partial: true,
        });
      }
      console.error('[IOC] List query error:', dataErr.message, '| tenant:', tenantId || 'ALL');
      throw createError(500, dataErr.message);
    }
    data = rows || [];
  } catch (err) {
    if (err.message?.startsWith('DB timeout')) {
      console.warn(`[IOC] QUERY_TIMEOUT data — ${err.message}`);
      return res.status(503).json({
        error:   'Database query timed out. The IOC table may be very large. Try adding filters.',
        code:    'INTERNAL_ERROR',
        path:    '/api/iocs',
        partial: true,
      });
    }
    throw err;
  }

  // ── Count query: head-only (no data transfer) — skipped on no_count=1 ──────
  // HEAD-only count is 3-5× faster than COUNT(*) with data.
  count = -1; // -1 means unknown
  if (no_count !== '1') {
    try {
      let countQuery = supabaseAdmin
        .from('iocs')
        .select('*', { count: 'exact', head: true });  // head: true = count only, no rows
      countQuery = _applyFilters(countQuery);

      const { count: cnt, error: cntErr } = await _withQueryTimeout(countQuery, 'count');
      if (!cntErr) count = cnt || 0;
      else console.warn('[IOC] Count query error (non-fatal):', cntErr.message);
    } catch (e) {
      console.warn('[IOC] Count query timeout (non-fatal) — returning count=-1:', e.message);
      // count stays -1; frontend should handle unknown total gracefully
    }
  }

  const scope = viewAllTenants ? 'ALL_TENANTS' : tenantId;
  console.log(`[IOC] GET /iocs — scope=${scope} total=${count} page=${pageNum} returned=${data.length}`);

  res.json({
    data,
    total:      count,
    pagination: { page: pageNum, limit: limitNum, total: count },
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
