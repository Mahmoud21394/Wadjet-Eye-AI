'use strict';

const router = require('express').Router();
const { createClient } = require('@supabase/supabase-js');
const { requireRole, requirePermission } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

function resolveTenantId(req) {
  return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT;
}

function sanitize(s) {
  return (s || '').replace(/[(),"'\\]/g, '').trim().slice(0, 100);
}

const SORTABLE = new Set([
  'risk_score','last_seen','created_at','value','type','reputation'
]);

/* ════════════════════════════════════════════════════════
   🚀 HIGH PERFORMANCE GET /api/iocs
   Cursor-based + NO COUNT + optimized filters
════════════════════════════════════════════════════════ */
router.get('/', asyncHandler(async (req, res) => {
  const {
    limit = 50,
    cursor,              // last_seen cursor
    sort = 'last_seen',
    order = 'desc',
    type,
    reputation,
    source,
    search,
    risk_min
  } = req.query;

  const tenantId = resolveTenantId(req);
  const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

  const sortCol = SORTABLE.has(sort) ? sort : 'last_seen';
  const ascending = order === 'asc';

  let query = supabaseAdmin
    .from('iocs')
    .select(`
      id,value,type,risk_score,reputation,
      source,country,threat_actor,
      last_seen,created_at
    `)
    .eq('tenant_id', tenantId)
    .order(sortCol, { ascending })
    .limit(limitNum + 1); // +1 to detect next page

  // 🔥 CURSOR PAGINATION (NO OFFSET)
  if (cursor) {
    query = ascending
      ? query.gt(sortCol, cursor)
      : query.lt(sortCol, cursor);
  }

  // Filters
  if (type)        query = query.eq('type', type);
  if (reputation)  query = query.eq('reputation', reputation);
  if (source)      query = query.eq('source', source);
  if (risk_min)    query = query.gte('risk_score', Number(risk_min));

  // 🔥 OPTIMIZED SEARCH (NO .or)
  if (search) {
    const s = sanitize(search);
    if (s) {
      query = query.ilike('value', `%${s}%`);
    }
  }

  const { data, error } = await query;

  if (error) {
    console.error('[IOC] Query error:', error.message);
    throw createError(500, error.message);
  }

  // Detect next page
  const hasMore = data.length > limitNum;
  const results = hasMore ? data.slice(0, limitNum) : data;

  const nextCursor = hasMore
    ? results[results.length - 1][sortCol]
    : null;

  res.json({
    data: results,
    pagination: {
      limit: limitNum,
      next_cursor: nextCursor,
      has_more: hasMore
    }
  });
}));

/* ════════════════════════════════════════════════════════
   ⚡ FAST STATS (NO FULL SCAN)
════════════════════════════════════════════════════════ */
router.get('/stats', asyncHandler(async (req, res) => {
  const tenantId = resolveTenantId(req);

  const { data, error } = await supabaseAdmin
    .rpc('ioc_stats_fast', { tenant: tenantId });

  if (error) {
    console.warn('[IOC] stats fallback:', error.message);
    return res.json({
      total: 0,
      malicious: 0,
      note: 'Stats unavailable (function missing)'
    });
  }

  res.json(data);
}));

/* ════════════════════════════════════════════════════════
   🚀 GET SINGLE IOC (FAST)
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
   ⚡ BULK UPSERT (HIGH PERFORMANCE)
════════════════════════════════════════════════════════ */
router.post('/bulk', requirePermission('manage_iocs'),
asyncHandler(async (req, res) => {
  const { iocs } = req.body;
  const tenantId = resolveTenantId(req);

  if (!Array.isArray(iocs) || iocs.length === 0) {
    throw createError(400, 'Invalid IOC array');
  }

  const rows = iocs.slice(0, 1000).map(i => ({
    tenant_id: tenantId,
    value: i.value,
    type: i.type,
    risk_score: i.risk_score || 0,
    reputation: i.reputation || 'unknown',
    source: i.source || 'bulk',
    last_seen: new Date().toISOString()
  }));

  const { error } = await supabaseAdmin
    .from('iocs')
    .upsert(rows, {
      onConflict: 'tenant_id,value'
    });

  if (error) throw createError(500, error.message);

  res.json({ imported: rows.length });
}));

module.exports = router;
