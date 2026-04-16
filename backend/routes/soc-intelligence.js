/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY — SOC Intelligence API Routes  v1.0
 *
 *  Endpoints:
 *   GET  /api/soc/health           — system health + DB stats
 *   GET  /api/soc/dashboard        — high-risk map for dashboard
 *   GET  /api/soc/cve/:id          — CVE lookup with SOC format
 *   GET  /api/soc/cves/critical    — latest critical CVEs
 *   GET  /api/soc/cves/exploited   — exploited-in-wild CVEs
 *   POST /api/soc/cves/search      — search CVEs by keyword
 *   GET  /api/soc/mitre/:id        — MITRE technique lookup
 *   POST /api/soc/mitre/search     — search MITRE techniques
 *   POST /api/soc/detect           — generate detection rules (all formats)
 *   GET  /api/soc/detect/:id/sigma — Sigma rule
 *   GET  /api/soc/detect/:id/kql   — KQL query
 *   GET  /api/soc/detect/:id/spl   — SPL query
 *   GET  /api/soc/detect/list      — all supported techniques
 *   POST /api/soc/correlate        — threat correlation
 *   POST /api/soc/simulate         — incident simulation
 *   POST /api/soc/hunt             — threat hunting hypothesis
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express    = require('express');
const router     = express.Router();
const rateLimit  = require('express-rate-limit');

// ── Load engines (with graceful fallback) ─────────────────────────────────────
let detectionEngine, intelDB, correlator, simulator;

try { detectionEngine = require('../services/detection-engine').defaultEngine; } catch(e) {
  console.warn('[SOC Routes] detection-engine unavailable:', e.message);
}
try { intelDB = require('../services/intel-db').defaultDB; } catch(e) {
  console.warn('[SOC Routes] intel-db unavailable:', e.message);
}
try { correlator = require('../services/threat-correlation').defaultCorrelator; } catch(e) {
  console.warn('[SOC Routes] threat-correlation unavailable:', e.message);
}
try { simulator = require('../services/incident-simulator').defaultSimulator; } catch(e) {
  console.warn('[SOC Routes] incident-simulator unavailable:', e.message);
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
const socLimiter = rateLimit({
  windowMs: 60_000, max: 100,
  message: { error: 'Rate limit exceeded. Please slow down.' },
  standardHeaders: true, legacyHeaders: false,
});

const detectLimiter = rateLimit({
  windowMs: 60_000, max: 60,
  message: { error: 'Detection generation rate limit exceeded.' },
});

// ── Helper: safe handler wrapper ──────────────────────────────────────────────
function safe(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (err) {
      console.error('[SOC Route Error]', err.message);
      res.status(500).json({
        success: false,
        error: '⚠️ Using built-in threat intelligence',
        message: 'Service temporarily unavailable. Local intelligence is still active.',
      });
    }
  };
}

// ── Require engine middleware ─────────────────────────────────────────────────
function requireEngine(engineRef, name) {
  return (req, res, next) => {
    if (!engineRef) {
      return res.status(503).json({
        success: false,
        error: `${name} engine not loaded. Check backend configuration.`,
      });
    }
    next();
  };
}

// ═════════════════════════════════════════════════════════════════════════════
//  HEALTH & DASHBOARD
// ═════════════════════════════════════════════════════════════════════════════
router.get('/health', socLimiter, safe(async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    engines: {
      detection_engine: !!detectionEngine,
      intel_db: !!intelDB,
      threat_correlator: !!correlator,
      incident_simulator: !!simulator,
    },
  };
  if (intelDB) health.db_stats = intelDB.getStats();
  if (detectionEngine) health.rule_count = detectionEngine.ruleCount;
  res.json({ success: true, ...health });
}));

router.get('/dashboard', socLimiter, safe(async (req, res) => {
  const data = {};
  if (intelDB) {
    data.critical_cves = intelDB.getLatestCritical(8).map(c => ({
      id: c.id, vendor: c.vendor, product: c.product,
      cvss: c.cvss_score, severity: c.severity,
      exploited: c.exploited, published: c.published_date,
    }));
    data.exploited_cves = intelDB.getExploitedCVEs(5).map(c => ({
      id: c.id, cvss: c.cvss_score, vendor: c.vendor, published: c.published_date,
    }));
    data.stats = intelDB.getStats();
  }
  if (correlator) {
    data.high_risk_map = correlator.getHighRiskMap();
  }
  if (detectionEngine) {
    data.supported_techniques = detectionEngine.listSupportedTechniques().slice(0, 20);
  }
  res.json({ success: true, ...data });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  CVE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════
router.get('/cve/:id', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const id = req.params.id.toUpperCase();
  const cve = intelDB.getCVE(id);
  if (!cve) {
    return res.status(404).json({
      success: false,
      message: `${id} not in local database.`,
      nvd_url: `https://nvd.nist.gov/vuln/detail/${id}`,
      cve_url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}`,
    });
  }
  const formatted = intelDB.formatCVEForSOC(id);
  const techniques = intelDB.getTechniquesForCVE(id);
  res.json({
    success: true,
    cve,
    techniques: techniques.map(t => ({ id: t.id, name: t.name, tactic: t.tactic })),
    formatted_soc: formatted,
  });
}));

router.get('/cves/critical', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '10'), 50);
  const cves = intelDB.getLatestCritical(limit);
  res.json({ success: true, count: cves.length, cves });
}));

router.get('/cves/exploited', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '20'), 50);
  const cves = intelDB.getExploitedCVEs(limit);
  res.json({ success: true, count: cves.length, cves });
}));

router.post('/cves/search', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const { keyword, severity, exploited, limit = 10 } = req.body || {};
  const results = intelDB.searchCVEs({ keyword, severity, exploited, limit: Math.min(limit, 50) });
  res.json({ success: true, count: results.length, results });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  MITRE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════
router.get('/mitre/:id', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const id = req.params.id.toUpperCase();
  const technique = intelDB.getMITRE(id);
  if (!technique) {
    return res.status(404).json({
      success: false,
      message: `${id} not in local database.`,
      mitre_url: `https://attack.mitre.org/techniques/${id.replace('.','/').replace('T','T')}/`,
    });
  }
  const formatted = intelDB.formatMITREForSOC(id);
  const relatedCVEs = intelDB.getCVEsForTechnique(id);
  let detection = null;
  if (detectionEngine) {
    const d = detectionEngine.generateAll(id);
    if (d.found !== false) detection = { sigma: d.sigma, kql: d.kql, spl: d.spl };
  }
  res.json({
    success: true,
    technique,
    related_cves: relatedCVEs.map(c => ({ id: c.id, cvss: c.cvss_score, exploited: c.exploited })),
    detection,
    formatted_soc: formatted,
  });
}));

router.post('/mitre/search', socLimiter, requireEngine(intelDB, 'Intel DB'), safe(async (req, res) => {
  const { keyword, tactic, severity, limit = 10 } = req.body || {};
  const results = intelDB.searchMITRE({ keyword, tactic, severity, limit: Math.min(limit, 50) });
  res.json({ success: true, count: results.length, results });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  DETECTION ENGINE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════
router.get('/detect/list', socLimiter, requireEngine(detectionEngine, 'Detection Engine'), safe(async (req, res) => {
  res.json({
    success: true,
    techniques: detectionEngine.listSupportedTechniques(),
    count: detectionEngine.ruleCount,
  });
}));

router.post('/detect', detectLimiter, requireEngine(detectionEngine, 'Detection Engine'), safe(async (req, res) => {
  const { technique, format } = req.body || {};
  if (!technique) return res.status(400).json({ success: false, error: 'technique is required' });

  const result = format === 'sigma'   ? detectionEngine.generateSigma(technique) :
                 format === 'kql'     ? detectionEngine.generateKQL(technique) :
                 format === 'spl'     ? detectionEngine.generateSPL(technique) :
                 format === 'elastic' ? detectionEngine.generateElastic(technique) :
                 detectionEngine.generateAll(technique);

  if (result.found === false) {
    return res.status(404).json({ success: false, ...result });
  }
  res.json({ success: true, ...result });
}));

router.get('/detect/:id/sigma', detectLimiter, requireEngine(detectionEngine, 'Detection Engine'), safe(async (req, res) => {
  const result = detectionEngine.generateSigma(req.params.id.toUpperCase());
  if (result.found === false) return res.status(404).json({ success: false, ...result });
  // Return raw YAML for copy-paste
  if (req.query.raw === '1') {
    res.setHeader('Content-Type', 'text/plain');
    return res.send(result.content);
  }
  res.json({ success: true, ...result });
}));

router.get('/detect/:id/kql', detectLimiter, requireEngine(detectionEngine, 'Detection Engine'), safe(async (req, res) => {
  const result = detectionEngine.generateKQL(req.params.id.toUpperCase());
  if (result.found === false) return res.status(404).json({ success: false, ...result });
  if (req.query.raw === '1') {
    res.setHeader('Content-Type', 'text/plain');
    return res.send(result.content);
  }
  res.json({ success: true, ...result });
}));

router.get('/detect/:id/spl', detectLimiter, requireEngine(detectionEngine, 'Detection Engine'), safe(async (req, res) => {
  const result = detectionEngine.generateSPL(req.params.id.toUpperCase());
  if (result.found === false) return res.status(404).json({ success: false, ...result });
  if (req.query.raw === '1') {
    res.setHeader('Content-Type', 'text/plain');
    return res.send(result.content);
  }
  res.json({ success: true, ...result });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  THREAT CORRELATION ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════
router.post('/correlate', socLimiter, requireEngine(correlator, 'Threat Correlator'), safe(async (req, res) => {
  const { input } = req.body || {};
  if (!input) return res.status(400).json({ success: false, error: 'input is required' });
  const result = correlator.correlate(input);
  res.json({ success: true, ...result });
}));

router.get('/correlate/risk-map', socLimiter, requireEngine(correlator, 'Threat Correlator'), safe(async (req, res) => {
  const riskMap = correlator.getHighRiskMap();
  res.json({ success: true, ...riskMap });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  INCIDENT SIMULATION ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════
router.post('/simulate', socLimiter, requireEngine(simulator, 'Incident Simulator'), safe(async (req, res) => {
  const { scenario, format = 'structured', hosts, users } = req.body || {};
  if (!scenario) return res.status(400).json({ success: false, error: 'scenario is required' });

  const result = simulator.simulate(scenario, { hosts, users });

  if (format === 'markdown') {
    const markdown = simulator.formatForSOC(result);
    return res.json({ success: true, scenario: result.scenario, markdown });
  }

  res.json({ success: true, ...result });
}));

// ═════════════════════════════════════════════════════════════════════════════
//  THREAT HUNTING ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════
router.post('/hunt', socLimiter, requireEngine(correlator, 'Threat Correlator'), safe(async (req, res) => {
  const { topic } = req.body || {};
  if (!topic) return res.status(400).json({ success: false, error: 'topic is required' });
  const result = correlator.generateHuntingHypothesis(topic);
  res.json({ success: true, ...result });
}));

module.exports = router;
