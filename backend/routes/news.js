/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News API v6.0
 *  FILE: backend/routes/news.js
 *
 *  Public endpoints — no JWT required.
 *  Category tabs: threat-intelligence | vulnerabilities | cyber-attacks
 *
 *  GET  /api/news              — list with filters
 *  GET  /api/news/categories   — category counts
 *  POST /api/news/ingest       — manual trigger (admin only)
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express   = require('express');
const router    = express.Router();
const { ingestCyberNews, getRecentNews, RSS_FEEDS } = require('../services/news-ingestion');

// In-memory news cache per category key
const newsCache  = new Map();
const NEWS_CACHE_TTL = 5 * 60 * 1000; // 5 min

function ncGet(key) {
  const e = newsCache.get(key);
  if (!e) return null;
  if (Date.now() - e.ts > NEWS_CACHE_TTL) { newsCache.delete(key); return null; }
  return e.data;
}
function ncSet(key, data) {
  newsCache.set(key, { data, ts: Date.now() });
  if (newsCache.size > 100) {
    const now = Date.now();
    for (const [k, v] of newsCache.entries()) {
      if (now - v.ts > NEWS_CACHE_TTL) newsCache.delete(k);
    }
  }
}

// Helper — tenant from request
function tid(req) {
  return req.tenantId
    || req.user?.tenantId
    || req.user?.tenant_id
    || process.env.DEFAULT_TENANT_ID
    || '00000000-0000-0000-0000-000000000001';
}

// ── Clean HTML entities + strip tags from text ────────────────────────
function cleanText(t) {
  return String(t == null ? '' : t)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&[a-z]{2,8};/gi, '')
    .replace(/&#\d+;/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

// ── Validate image URL is a real image ───────────────────────────────
function validateImageUrl(url) {
  if (!url || typeof url !== 'string') return null;
  if (!/^https?:\/\//i.test(url)) return null;
  if (/1x1|pixel|track|beacon|spacer/i.test(url)) return null;
  return url;
}

// ════════════════════════════════════════════════════════════════
//  GET /api/news — list news with optional filters
//  Query: category, severity, search, page, limit, source
// ════════════════════════════════════════════════════════════════
router.get('/', async (req, res) => {
  const {
    category, severity, search, source,
    page  = 1,
    limit = 20,
  } = req.query;

  const pageNum  = Math.max(1, parseInt(page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(limit) || 20));

  // Validate category
  const VALID_CATS = ['threat-intelligence', 'vulnerabilities', 'cyber-attacks'];
  const cat = VALID_CATS.includes(category) ? category : undefined;

  const cacheKey = `news:${cat}:${severity}:${search}:${pageNum}:${pageSize}:${source}`;
  const cached   = ncGet(cacheKey);
  if (cached) {
    return res.json({ ...cached, _cached: true });
  }

  try {
    const tenantId = tid(req);
    const result   = await getRecentNews(tenantId, {
      limit: pageSize, page: pageNum, category: cat, severity, search,
    });

    // Apply source filter client-side if present
    let articles = result.articles || [];
    if (source) {
      articles = articles.filter(a =>
        (a.source || a.source_name || '').toLowerCase().includes(source.toLowerCase())
      );
    }

    // Normalize article shape for frontend
    const normalized = articles.map(a => ({
      id:          a.id           || a.external_guid || a.guid || a.link,
      title:       cleanText(a.title || ''),
      url:         a.url          || a.link          || '#',
      source:      cleanText(a.source || a.source_name || 'Unknown'),
      category:    a.category     || 'threat-intelligence',
      summary:     cleanText(a.summary || a.description || '').slice(0, 600),
      imageUrl:    validateImageUrl(a.image_url || a.imageUrl || null),
      severity:    a.severity     || 'medium',
      cves:        Array.isArray(a.cves) ? a.cves : [],
      threatActors: Array.isArray(a.threat_actors) ? a.threat_actors : (Array.isArray(a.actors) ? a.actors : []),
      malware:     Array.isArray(a.malware_families) ? a.malware_families : (Array.isArray(a.malware) ? a.malware : []),
      tags:        Array.isArray(a.tags) ? a.tags : [],
      publishedAt: a.published_at || a.pubDate || new Date().toISOString(),
    }));

    const response = {
      data:       normalized,
      total:      result.total || normalized.length,
      page:       pageNum,
      limit:      pageSize,
      totalPages: Math.ceil((result.total || normalized.length) / pageSize),
      filters:    { category: cat, severity, search, source },
      source:     result.source || 'cache',
      _real_data: true,
    };

    ncSet(cacheKey, response);
    res.json(response);
  } catch (err) {
    console.error('[News API] Error:', err.message);
    res.status(503).json({
      error:    'News service temporarily unavailable.',
      data:     [],
      total:    0,
      _cached:  false,
    });
  }
});

// ════════════════════════════════════════════════════════════════
//  GET /api/news/categories — category counts / metadata
// ════════════════════════════════════════════════════════════════
router.get('/categories', async (req, res) => {
  const cacheKey = 'categories';
  const cached   = ncGet(cacheKey);
  if (cached) return res.json(cached);

  try {
    const tenantId = tid(req);
    const allResult = await getRecentNews(tenantId, { limit: 500, page: 1 });
    const articles  = allResult.articles || [];

    const counts = {
      'threat-intelligence': 0,
      'vulnerabilities':     0,
      'cyber-attacks':       0,
    };
    for (const a of articles) {
      const cat = a.category || 'threat-intelligence';
      if (counts[cat] !== undefined) counts[cat]++;
      else counts['threat-intelligence']++;
    }

    const result = {
      categories: [
        { id: 'threat-intelligence', label: 'Threat Intelligence', count: counts['threat-intelligence'], icon: 'shield-alt' },
        { id: 'vulnerabilities',     label: 'Vulnerabilities',     count: counts['vulnerabilities'],     icon: 'bug' },
        { id: 'cyber-attacks',       label: 'Cyber Attacks',       count: counts['cyber-attacks'],       icon: 'bolt' },
      ],
      total:     articles.length,
      sources:   RSS_FEEDS.map(f => ({ name: f.name, category: f.category })),
      updatedAt: new Date().toISOString(),
    };

    ncSet(cacheKey, result);
    res.json(result);
  } catch (err) {
    console.error('[News API] Categories error:', err.message);
    res.status(503).json({ error: 'Categories service unavailable.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  POST /api/news/ingest — manual trigger (checks role if auth present)
// ════════════════════════════════════════════════════════════════
router.post('/ingest', async (req, res) => {
  // Check if user is authenticated and has admin/analyst role
  if (req.user) {
    const role = req.user.role || '';
    if (!['admin', 'super_admin', 'analyst', 'soc_l3', 'soc_l2'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions to trigger ingestion.' });
    }
  }

  // Clear cache
  newsCache.clear();

  res.json({ status: 'started', message: 'News ingestion initiated.' });

  // Run in background
  const tenantId = tid(req);
  ingestCyberNews(tenantId)
    .then(r => console.info('[News] Manual ingest done:', r))
    .catch(e => console.error('[News] Manual ingest error:', e.message));
});

module.exports = router;
