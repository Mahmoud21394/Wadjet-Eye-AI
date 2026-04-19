/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News API Routes v6.0
 *  FILE: backend/routes/news.js
 *
 *  Endpoints:
 *    GET  /api/news                    — Paginated news feed with filters
 *    GET  /api/news/categories         — Category listing with article counts
 *    GET  /api/news/feeds              — RSS feed source status
 *    GET  /api/news/:id                — Article detail
 *    POST /api/news/ingest             — Trigger manual ingestion
 *    GET  /api/news/stats              — News stats
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express = require('express');
const router  = express.Router();
const { asyncHandler }  = require('../middleware/errorHandler');

// News ingestion service
let newsService;
try {
  newsService = require('../services/news-ingestion');
} catch (err) {
  console.warn('[News Route] news-ingestion not available:', err.message);
}

// Supabase for DB queries
let supabase;
try { ({ supabase } = require('../config/supabase')); } catch (_) {}

// Token verification (optional — news can be public in demo mode)
let verifyToken;
try { ({ verifyToken } = require('../middleware/auth')); } catch (_) { verifyToken = (req, res, next) => next(); }

/* ══════════════════════════════════════════════════════════
   GET /api/news — Paginated feed with category/severity filters
══════════════════════════════════════════════════════════ */
router.get('/', asyncHandler(async (req, res) => {
  const {
    category,
    severity,
    search,
    page    = 1,
    limit   = 30,
    refresh = false,
  } = req.query;

  const tenantId = req.user?.tenant_id;

  if (!newsService) {
    return res.status(503).json({ error: 'News service not available.', articles: [], total: 0 });
  }

  // Force refresh if requested
  if (refresh === 'true') {
    await newsService.ingestCyberNews(tenantId, { forceRefresh: true });
  }

  const result = await newsService.getRecentNews(tenantId, {
    category,
    severity,
    search,
    page:  parseInt(page),
    limit: Math.min(100, parseInt(limit)),
  });

  res.json({
    articles:   result.articles,
    total:      result.total,
    page:       result.page,
    limit:      result.limit,
    totalPages: result.totalPages,
    categories: result.categories,
    fetchedAt:  new Date().toISOString(),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/news/categories — Category listing
══════════════════════════════════════════════════════════ */
router.get('/categories', asyncHandler(async (req, res) => {
  if (!newsService) {
    return res.json({ categories: [], error: 'News service unavailable' });
  }

  const stats = newsService.getCacheStats();
  const cats  = newsService.NEWS_CATEGORIES;

  const categories = Object.values(cats).map(cat => {
    const byCatEntry = stats.byCategory?.[cat.id];
    // byCategory can hold either a count (number) or an array of articles
    const articleCount = Array.isArray(byCatEntry) ? byCatEntry.length : (byCatEntry || 0);
    return {
      id:           cat.id,
      label:        cat.label,
      icon:         cat.icon,
      color:        cat.color,
      articleCount,
    };
  }).sort((a, b) => b.articleCount - a.articleCount);

  res.json({
    categories,
    totalArticles: stats.totalArticles,
    lastUpdated:   stats.lastFetch,
    cacheAgeSeconds: Math.floor((stats.cacheAgeMs || 0) / 1000),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/news/feeds — RSS feed source status
══════════════════════════════════════════════════════════ */
router.get('/feeds', asyncHandler(async (req, res) => {
  if (!newsService) {
    return res.json({ feeds: [], error: 'News service unavailable' });
  }

  const feeds = newsService.RSS_FEEDS.map(f => ({
    id:       f.id,
    name:     f.name,
    category: f.category,
    logo:     f.logo,
    priority: f.priority,
    urlCount: f.urls.length,
  }));

  const stats = newsService.getCacheStats();

  res.json({
    feeds,
    totalFeeds:    feeds.length,
    lastFetch:     stats.lastFetch,
    fetchCount:    stats.fetchCount,
    totalArticles: stats.totalArticles,
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/news/stats — News statistics
══════════════════════════════════════════════════════════ */
router.get('/stats', asyncHandler(async (req, res) => {
  if (!newsService) {
    return res.json({ error: 'News service unavailable', stats: {} });
  }

  const stats = newsService.getCacheStats();
  res.json({
    ...stats,
    feedList: newsService.RSS_FEEDS.map(f => f.name),
    categoriesList: Object.values(newsService.NEWS_CATEGORIES).map(c => c.label),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/news/debug — Category distribution debug endpoint
   PUBLIC — no auth required.
   Returns per-category article counts, feed-to-category mapping,
   and sample articles from each category.  Used to verify the
   category classification is working correctly.
══════════════════════════════════════════════════════════ */
router.get('/debug', asyncHandler(async (req, res) => {
  if (!newsService) {
    return res.json({ error: 'News service unavailable' });
  }

  const tenantId = req.user?.tenant_id;
  const result   = await newsService.getRecentNews(tenantId, { limit: 500 });
  const articles = result.articles || [];

  // Per-category distribution
  const distribution = {};
  for (const cat of Object.values(newsService.NEWS_CATEGORIES)) {
    const catArticles = articles.filter(a => a.category === cat.id);
    distribution[cat.id] = {
      label:       cat.label,
      count:       catArticles.length,
      // Sample: first 3 titles from each category
      samples:     catArticles.slice(0, 3).map(a => ({
        title:    a.title,
        source:   a.source,
        severity: a.severity,
      })),
    };
  }

  // Feed → category mapping
  const feedMapping = newsService.RSS_FEEDS.map(f => ({
    id:       f.id,
    name:     f.name,
    declaredCategory: f.category,
    priority: f.priority,
  }));

  res.json({
    totalArticles:    articles.length,
    distribution,
    feedMapping,
    categories:       newsService.NEWS_CATEGORIES,
    cacheStats:       newsService.getCacheStats(),
    timestamp:        new Date().toISOString(),
  });
}));

/* ══════════════════════════════════════════════════════════
   POST /api/news/ingest — Manual ingestion trigger
   Requires ADMIN or ANALYST role
══════════════════════════════════════════════════════════ */
router.post('/ingest', asyncHandler(async (req, res) => {
  const userRole = req.user?.role;
  if (userRole && !['ADMIN', 'SUPER_ADMIN', 'ANALYST', 'analyst', 'admin'].includes(userRole)) {
    return res.status(403).json({ error: 'Insufficient permissions. Requires ADMIN or ANALYST role.' });
  }

  if (!newsService) {
    return res.status(503).json({ error: 'News service not available.' });
  }

  const tenantId = req.user?.tenant_id;
  const { feedIds } = req.body;

  // Run async — respond immediately
  const resultPromise = newsService.ingestCyberNews(tenantId, { forceRefresh: true, feedIds });

  // Wait up to 3s for immediate result
  const result = await Promise.race([
    resultPromise,
    new Promise(r => setTimeout(() => r({ articles: [], inProgress: true }), 3000)),
  ]);

  res.json({
    success:   true,
    message:   result.inProgress ? 'Ingestion started (running in background)' : 'Ingestion complete',
    articles:  result.articles?.length || 0,
    byCategory: result.byCategory || {},
    durationMs: result.durationMs || 0,
    triggeredAt: new Date().toISOString(),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/news/:id — Article detail by ID or URL-encoded link
══════════════════════════════════════════════════════════ */
router.get('/:id', asyncHandler(async (req, res) => {
  const articleId = req.params.id;

  // Search in cache
  if (newsService) {
    const all = (await newsService.getRecentNews(req.user?.tenant_id, { limit: 1000 })).articles;
    const article = all.find(a => a.id === articleId || a.guid === articleId);

    if (article) return res.json(article);
  }

  // Try DB if supabase available
  if (supabase) {
    const tenantId = req.user?.tenant_id;
    const { data } = await supabase
      .from('news_articles')
      .select('*')
      .or(`id.eq.${articleId},external_guid.eq.${decodeURIComponent(articleId)}`)
      .eq('tenant_id', tenantId)
      .maybeSingle();

    if (data) return res.json(data);
  }

  res.status(404).json({ error: 'Article not found.' });
}));

module.exports = router;
