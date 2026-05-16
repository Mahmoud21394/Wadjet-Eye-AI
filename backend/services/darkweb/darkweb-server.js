/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Dark Web Monitor Microservice HTTP Server
 *  backend/services/darkweb/darkweb-server.js
 *
 *  ARCH-001: Minimal HTTP server for the isolated darkweb container.
 *  Exposes:
 *    GET  /health   — liveness probe (K8s readiness/liveness)
 *    GET  /metrics  — Prometheus-compatible metrics
 *    POST /scan     — trigger a manual scan cycle (internal only)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const http   = require('http');
const crypto = require('crypto');

// Lazy-require monitor (avoids crashing if Tor is unavailable at startup)
let monitor  = null;
function getMonitor() {
  if (!monitor) monitor = require('./darkweb-monitor');
  return monitor;
}

const PORT         = parseInt(process.env.DARKWEB_HEALTH_PORT || '8081', 10);
const START_TIME   = Date.now();
const _metrics     = { scansTotal: 0, findingsTotal: 0, criticalTotal: 0, lastScanAt: null, lastScanDurationMs: 0, errors: 0 };

// ── Start the background monitor ──────────────────────────────────
getMonitor().startMonitor({
  onFindings: async (result) => {
    _metrics.scansTotal++;
    _metrics.findingsTotal    += result.totalFindings;
    _metrics.criticalTotal    += result.critical;
    _metrics.lastScanAt        = result.endTime;
    _metrics.lastScanDurationMs = result.durationMs;
  },
}).catch(err => {
  console.error('[DarkWeb Server] Monitor start failed:', err.message);
  _metrics.errors++;
});

// ── HTTP server ───────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  if (url === '/health' && method === 'GET') {
    const uptimeSec = Math.floor((Date.now() - START_TIME) / 1000);
    const status    = { status: 'healthy', uptime_sec: uptimeSec, last_scan: _metrics.lastScanAt, errors: _metrics.errors };
    const body      = JSON.stringify(status);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
    return;
  }

  if (url === '/metrics' && method === 'GET') {
    const uptimeSec = Math.floor((Date.now() - START_TIME) / 1000);
    // Prometheus text format
    const metrics = [
      `# HELP darkweb_scans_total Total scan cycles completed`,
      `# TYPE darkweb_scans_total counter`,
      `darkweb_scans_total ${_metrics.scansTotal}`,
      `# HELP darkweb_findings_total Total findings across all scans`,
      `# TYPE darkweb_findings_total counter`,
      `darkweb_findings_total ${_metrics.findingsTotal}`,
      `# HELP darkweb_critical_findings_total Critical severity findings`,
      `# TYPE darkweb_critical_findings_total counter`,
      `darkweb_critical_findings_total ${_metrics.criticalTotal}`,
      `# HELP darkweb_last_scan_duration_ms Duration of last scan in milliseconds`,
      `# TYPE darkweb_last_scan_duration_ms gauge`,
      `darkweb_last_scan_duration_ms ${_metrics.lastScanDurationMs}`,
      `# HELP darkweb_errors_total Monitor errors`,
      `# TYPE darkweb_errors_total counter`,
      `darkweb_errors_total ${_metrics.errors}`,
      `# HELP darkweb_uptime_seconds Container uptime`,
      `# TYPE darkweb_uptime_seconds gauge`,
      `darkweb_uptime_seconds ${uptimeSec}`,
    ].join('\n') + '\n';

    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4', 'Content-Length': Buffer.byteLength(metrics) });
    res.end(metrics);
    return;
  }

  if (url === '/scan' && method === 'POST') {
    // Manual scan trigger — restricted to internal network (K8s RBAC + NetworkPolicy)
    const result = await getMonitor().runScanCycle().catch(err => ({ error: err.message }));
    _metrics.scansTotal++;
    if (!result.error) {
      _metrics.findingsTotal += result.totalFindings || 0;
      _metrics.criticalTotal += result.critical || 0;
      _metrics.lastScanAt     = result.endTime;
    } else {
      _metrics.errors++;
    }
    const body = JSON.stringify(result);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
    return;
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[DarkWeb Server] Listening on :${PORT} (PID ${process.pid})`);
});

// ── Graceful shutdown ─────────────────────────────────────────────
const shutdown = (signal) => {
  console.log(`[DarkWeb Server] Received ${signal} — shutting down gracefully`);
  getMonitor().stopMonitor();
  server.close(() => {
    console.log('[DarkWeb Server] HTTP server closed');
    process.exit(0);
  });
  setTimeout(() => { console.error('[DarkWeb Server] Forced exit after timeout'); process.exit(1); }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
