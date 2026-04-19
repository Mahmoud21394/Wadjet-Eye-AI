/**
 * ══════════════════════════════════════════════════════════
 *  Vulnerabilities Routes v4.0 — NVD + CISA KEV
 *  backend/routes/vulnerabilities.js
 *
 *  GET  /api/vulnerabilities          — List with filters
 *  GET  /api/vulnerabilities/:cve_id  — Single CVE detail
 *  GET  /api/vulnerabilities/stats    — Summary statistics
 *  POST /api/vulnerabilities/sync     — Trigger NVD sync (Admin)
 *  GET  /api/vulnerabilities/kev      — CISA KEV list only
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase } = require('../config/supabase');
const { requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const { syncNVD, syncCISAKEV } = require('../services/ingestion/nvd');

/* ────────────────────────────────────────────────────────
   GET /api/vulnerabilities
   Query params: severity, cvss_min, exploited, kev, search,
                 sort, order, page, limit, date_from, date_to
────────────────────────────────────────────────────────── */
router.get('/', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 25,
    severity,
    cvss_min,
    exploited,
    kev,
    search,
    sort    = 'published_at',
    order   = 'desc',
    date_from,
    date_to,
    attack_vector,
  } = req.query;

  const offset = (parseInt(page) - 1) * parseInt(limit);

  let q = supabase
    .from('vulnerabilities')
    .select('cve_id, title, severity, cvss_v3_score, exploited, in_cisa_kev, published_at, affected_products, attack_vector', { count: 'exact' })
    .order(sort, { ascending: order === 'asc' })
    .range(offset, offset + parseInt(limit) - 1);

  if (severity)      q = q.eq('severity', severity.toUpperCase());
  if (cvss_min)      q = q.gte('cvss_v3_score', parseFloat(cvss_min));
  if (exploited === 'true')  q = q.eq('exploited', true);
  if (kev === 'true')        q = q.eq('in_cisa_kev', true);
  if (attack_vector) q = q.eq('attack_vector', attack_vector);
  if (date_from)     q = q.gte('published_at', date_from);
  if (date_to)       q = q.lte('published_at', date_to);
  if (search)        q = q.or(`cve_id.ilike.%${search}%,title.ilike.%${search}%,description.ilike.%${search}%`);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({
    data: data || [],
    total: count || 0,
    page: +page,
    limit: +limit,
  });
}));

/* ────────────────────────────────────────────────────────
   GET /api/vulnerabilities/stats
────────────────────────────────────────────────────────── */
router.get('/stats', asyncHandler(async (req, res) => {
  const [total, critical, exploited, kev, recent] = await Promise.all([
    supabase.from('vulnerabilities').select('id', { count: 'exact', head: true }),
    supabase.from('vulnerabilities').select('id', { count: 'exact', head: true }).eq('severity', 'CRITICAL'),
    supabase.from('vulnerabilities').select('id', { count: 'exact', head: true }).eq('exploited', true),
    supabase.from('vulnerabilities').select('id', { count: 'exact', head: true }).eq('in_cisa_kev', true),
    supabase.from('vulnerabilities')
      .select('cve_id, severity, cvss_v3_score, published_at')
      .order('published_at', { ascending: false })
      .limit(5),
  ]);

  // Severity breakdown
  const { data: bySev } = await supabase.rpc('count_vulns_by_severity').catch(() => ({ data: null }));

  res.json({
    total:          total.count    || 0,
    critical:       critical.count || 0,
    exploited:      exploited.count || 0,
    in_cisa_kev:    kev.count      || 0,
    recent:         recent.data    || [],
    severity_breakdown: bySev || null,
  });
}));

/* ────────────────────────────────────────────────────────
   GET /api/vulnerabilities/kev — CISA KEV only
────────────────────────────────────────────────────────── */
router.get('/kev', asyncHandler(async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const { data, error, count } = await supabase
    .from('vulnerabilities')
    .select('*', { count: 'exact' })
    .eq('in_cisa_kev', true)
    .order('cisa_kev_date', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (error) throw createError(500, error.message);
  res.json({ data: data || [], total: count || 0, page: +page, limit: +limit });
}));

/* ────────────────────────────────────────────────────────
   GET /api/vulnerabilities/:cve_id — Full CVE detail
────────────────────────────────────────────────────────── */
router.get('/:cve_id', asyncHandler(async (req, res) => {
  const cveId = req.params.cve_id.toUpperCase();

  const { data, error } = await supabase
    .from('vulnerabilities')
    .select('*')
    .eq('cve_id', cveId)
    .single();

  if (error || !data) {
    // Try to fetch live from NVD if not in DB
    try {
      const axios = require('axios');
      const resp  = await axios.get(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
        { timeout: 10000, headers: { 'User-Agent': 'WadjetEye-AI/4.0' } }
      );
      const vul = resp.data?.vulnerabilities?.[0];
      if (vul) return res.json(_parseNVDEntry(vul));
    } catch { /* fall through to 404 */ }
    throw createError(404, `CVE ${cveId} not found`);
  }

  res.json(data);
}));

/* ────────────────────────────────────────────────────────
   POST /api/vulnerabilities/sync — Trigger live sync
────────────────────────────────────────────────────────── */
router.post('/sync',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { source = 'all', days = 7 } = req.body;

    res.json({ message: 'Sync started', source, days });

    // Non-blocking — run after response sent
    setImmediate(async () => {
      try {
        if (source === 'all' || source === 'nvd')      await syncNVD({ days: parseInt(days) });
        if (source === 'all' || source === 'cisa_kev') await syncCISAKEV();
        console.log('[Vulns] Sync completed');
      } catch (err) {
        console.error('[Vulns] Sync failed:', err.message);
      }
    });
  })
);

/* ────────────────────────────────────────────────────────
   NVD ENTRY PARSER — for on-demand single CVE lookup
────────────────────────────────────────────────────────── */
function _parseNVDEntry(entry) {
  const cve = entry.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
  const cvssData = metrics?.cvssData;

  return {
    cve_id:       cve.id,
    title:        cve.descriptions?.find(d => d.lang === 'en')?.value?.slice(0, 200) || cve.id,
    description:  cve.descriptions?.find(d => d.lang === 'en')?.value || '',
    severity:     (metrics?.baseSeverity || 'UNKNOWN').toUpperCase(),
    cvss_v3_score: cvssData?.baseScore || null,
    cvss_vector:   cvssData?.vectorString || null,
    attack_vector: cvssData?.attackVector || null,
    exploited:     false,
    in_cisa_kev:   false,
    published_at:  cve.published?.split('T')[0],
    modified_at:   cve.lastModified?.split('T')[0],
    source:        'NVD_LIVE',
  };
}

module.exports = router;
