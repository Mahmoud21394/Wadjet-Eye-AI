/**
 * Prometheus Metrics Endpoint  v1.0
 * GET /metrics — Prometheus scrape endpoint (no auth — internal use only)
 * GET /api/v2/telemetry — Telemetry summary (requires admin auth)
 */
'use strict';

const router     = require('express').Router();
const telemetry  = require('../services/telemetry');
const { requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// Prometheus scrape endpoint — no auth (restrict by IP at load balancer level)
router.get('/', (req, res) => {
  // Only allow from localhost or metrics scraper IPs
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || '';
  const allowed = process.env.NODE_ENV !== 'production' ||
    ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('127.') ||
    process.env.METRICS_SCRAPER_IP?.includes(ip);

  if (!allowed) return res.status(403).json({ error: 'Metrics endpoint restricted to internal network' });

  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(telemetry.getMetrics());
});

// Human-readable telemetry summary for admins
router.get('/summary', requireRole(['ADMIN', 'SUPER_ADMIN', 'admin', 'super_admin']), asyncHandler(async (req, res) => {
  res.json({ metrics: telemetry.getMetrics(), timestamp: new Date().toISOString() });
}));

module.exports = router;
