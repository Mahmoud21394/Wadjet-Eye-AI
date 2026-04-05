/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber Threat News API v5.2
 *  backend/routes/news.js
 *
 *  GET  /api/news          — Latest cyber threat news
 *  POST /api/news/ingest   — Trigger manual news ingestion
 *  GET  /api/news/:id      — Article details
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const express  = require('express');
const router   = express.Router();
const { supabase }    = require('../config/supabase');
const { verifyToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { ingestCyberNews, getRecentNews } = require('../services/news-ingestion');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

router.use(verifyToken);

function tid(req) {
  return req.tenantId || req.user?.tenant_id || DEFAULT_TENANT;
}

// ── GET /api/news ────────────────────────────────────────────
router.get('/', asyncHandler(async (req, res) => {
  const tenantId = tid(req);
  const limit    = Math.min(100, parseInt(req.query.limit) || 20);
  const page     = Math.max(1, parseInt(req.query.page) || 1);
  const from     = (page - 1) * limit;
  const { severity, search, source, actor, cve } = req.query;

  let q = supabase
    .from('news_articles')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tenantId},tenant_id.eq.${DEFAULT_TENANT}`)
    .order('published_at', { ascending: false })
    .range(from, from + limit - 1);

  if (severity) q = q.eq('severity', severity);
  if (source)   q = q.eq('source', source);
  if (search)   q = q.ilike('title', `%${search}%`);
  if (actor)    q = q.contains('threat_actors', [actor]);
  if (cve)      q = q.contains('cves', [cve.toUpperCase()]);

  const { data, count, error } = await q;
  if (error) throw error;

  res.json({
    data:  data || [],
    total: count || 0,
    page,
    limit,
    _real_data: true,
  });
}));

// ── GET /api/news/:id ─────────────────────────────────────────
router.get('/:id', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  const { data, error } = await supabase
    .from('news_articles')
    .select('*')
    .eq('id', req.params.id)
    .or(`tenant_id.eq.${tenantId},tenant_id.eq.${DEFAULT_TENANT}`)
    .single();

  if (error || !data) return res.status(404).json({ error: 'Article not found' });

  res.json(data);
}));

// ── POST /api/news/ingest ─────────────────────────────────────
router.post('/ingest', asyncHandler(async (req, res) => {
  const tenantId = tid(req);

  // Only admins/analysts can trigger
  if (!['SUPER_ADMIN','ADMIN','ANALYST'].includes(req.user?.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }

  res.json({ status: 'started', message: 'News ingestion initiated' });

  setImmediate(async () => {
    try {
      const result = await ingestCyberNews(tenantId);
      console.info('[News] Manual ingest complete:', result);
    } catch (err) {
      console.error('[News] Manual ingest error:', err.message);
    }
  });
}));

module.exports = router;
