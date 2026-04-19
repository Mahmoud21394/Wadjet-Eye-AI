/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN Engine API Routes v1.0
 *  Wadjet-Eye AI Platform Integration
 *
 *  Base path: /api/raykan
 *
 *  Endpoints:
 *   POST /ingest          — Ingest log events for analysis
 *   POST /hunt            — Execute RQL threat hunt
 *   POST /hunt/nl         — Natural language threat hunt
 *   POST /investigate     — Forensic investigation on entity
 *   POST /rule/generate   — AI-generate Sigma rule
 *   POST /rule/validate   — Validate Sigma rule
 *   GET  /rules           — List all loaded rules
 *   GET  /timeline        — Get current analysis timeline
 *   GET  /graph           — Get attack graph data (D3-compatible)
 *   GET  /mitre           — MITRE ATT&CK coverage heatmap
 *   GET  /stats           — Engine statistics and health
 *   GET  /ioc/:value      — IOC lookup (VirusTotal + AbuseIPDB + OTX)
 *   POST /ioc/batch       — Batch IOC lookup
 *   POST /analyze/file    — Analyze uploaded log file
 *   GET  /session/:id     — Get session results
 *   WS   /ws              — WebSocket for real-time detections
 *
 *  Auth: JWT required (verifyToken middleware)
 *  Rate: 100 req/15min
 *
 *  backend/routes/raykan-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const express       = require('express');
const rateLimit     = require('express-rate-limit');
const crypto        = require('crypto');
const RaykanEngine  = require('../services/raykan/engine');
const TimelineEngine = require('../services/raykan/timeline-engine');
const MitreMapper   = require('../services/raykan/mitre-mapper');
const IOCEnricher   = require('../services/raykan/ioc-enricher');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// ── Rate limiter ─────────────────────────────────────────────────
const raykanLimiter = rateLimit({
  windowMs : 15 * 60 * 1000,
  max      : 200,
  message  : { error: 'RAYKAN rate limit exceeded', code: 'RATE_LIMIT', retryIn: 15 },
  standardHeaders: true,
  legacyHeaders  : false,
  skip: (req) => process.env.NODE_ENV === 'development',
});

// ── Engine singleton (initialized lazily) ────────────────────────
let _engine       = null;
let _initPromise  = null;

async function getEngine(req) {
  if (_engine) return _engine;
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    // Collect AI providers from env vars
    const aiProviders = {};
    if (process.env.OPENAI_API_KEY)     aiProviders.openai   = { apiKey: process.env.OPENAI_API_KEY };
    if (process.env.CLAUDE_API_KEY)     aiProviders.claude   = { apiKey: process.env.CLAUDE_API_KEY };
    if (process.env.GEMINI_API_KEY)     aiProviders.gemini   = { apiKey: process.env.GEMINI_API_KEY };
    if (process.env.DEEPSEEK_API_KEY)   aiProviders.deepseek = { apiKey: process.env.DEEPSEEK_API_KEY };
    if (process.env.ANTHROPIC_API_KEY)  aiProviders.claude   = { apiKey: process.env.ANTHROPIC_API_KEY };
    if (process.env.OLLAMA_URL)         aiProviders.ollama   = { baseUrl: process.env.OLLAMA_URL };

    const enrichApis = {
      virusTotal: process.env.VIRUSTOTAL_API_KEY,
      abuseIPDB : process.env.ABUSEIPDB_API_KEY,
      otx       : process.env.OTX_API_KEY,
    };

    // Get supabase from parent module if available
    let supabase = null;
    try {
      const { getSupabaseClient } = require('../config/supabase');
      supabase = getSupabaseClient();
    } catch (e) { /* optional */ }

    _engine = new RaykanEngine({
      aiProviders,
      enrichApis,
      supabase,
      aiEnabled  : Object.keys(aiProviders).length > 0,
      uebaEnabled: true,
      realtimeMode: true,
    });

    await _engine.initialize();
    console.log('[RAYKAN] Engine ready — attached to /api/raykan');
    return _engine;
  })();

  return _initPromise;
}

// ── Apply rate limiter to all RAYKAN routes ───────────────────────
router.use(raykanLimiter);

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/ingest
//  Ingest log events for full analysis pipeline
// ════════════════════════════════════════════════════════════════
router.post('/ingest', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { events, source, format, caseId } = req.body;

  if (!events || !Array.isArray(events)) {
    return res.status(400).json({ error: 'events must be an array', code: 'INVALID_INPUT' });
  }

  if (events.length > 10000) {
    return res.status(400).json({ error: 'Max 10,000 events per request', code: 'TOO_MANY_EVENTS' });
  }

  const context = {
    source : source || 'api',
    format : format || 'json',
    tenant : req.user?.tenant_id || 'default',
    userId : req.user?.id,
    caseId,
  };

  const results = await engine.ingestEvents(events, context);

  res.json({
    success  : true,
    sessionId: results.sessionId,
    processed: results.processed,
    detections: {
      count      : results.detections.length,
      critical   : results.detections.filter(d => d.severity === 'critical').length,
      high       : results.detections.filter(d => d.severity === 'high').length,
      medium     : results.detections.filter(d => d.severity === 'medium').length,
      items      : results.detections.slice(0, 100), // cap at 100 in response
    },
    anomalies: {
      count: results.anomalies.length,
      items: results.anomalies,
    },
    chains: {
      count: results.chains.length,
      items: results.chains,
    },
    timeline    : results.timeline.slice(0, 500),
    riskScore   : results.riskScore,
    duration    : results.duration,
    timestamp   : new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/hunt
//  Execute RQL threat hunt
// ════════════════════════════════════════════════════════════════
router.post('/hunt', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { query, timeRange, entities, maxResults, aiAssist } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({ error: 'query is required', code: 'INVALID_QUERY' });
  }

  const results = await engine.hunt(query, {
    timeRange  : timeRange  || '24h',
    entities,
    maxResults : Math.min(maxResults || 200, 1000),
    aiAssist   : aiAssist   !== false,
  });

  res.json({
    success : true,
    query   : results.query,
    count   : results.count,
    matches : results.matches,
    duration: results.duration,
    suggestion: results.suggestion,
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/hunt/nl
//  Natural language threat hunt
// ════════════════════════════════════════════════════════════════
router.post('/hunt/nl', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { query, context } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'query required', code: 'INVALID_INPUT' });
  }

  const results = await engine.nlHunt(query, context || {});

  res.json({
    success       : true,
    originalQuery : results.originalQuery,
    rqlQuery      : results.rqlQuery,
    count         : results.count,
    matches       : results.matches,
    duration      : results.duration,
    explanation   : results.explanation,
    timestamp     : new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/investigate
//  Forensic investigation on entity
// ════════════════════════════════════════════════════════════════
router.post('/investigate', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { entityId, type, timeRange, depth } = req.body;

  if (!entityId) {
    return res.status(400).json({ error: 'entityId required', code: 'INVALID_INPUT' });
  }

  const result = await engine.investigate(entityId, { type, timeRange, depth });

  res.json({
    success : true,
    ...result,
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/rule/generate
//  AI-generate a Sigma detection rule
// ════════════════════════════════════════════════════════════════
router.post('/rule/generate', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { description, examples } = req.body;

  if (!description) {
    return res.status(400).json({ error: 'description required', code: 'INVALID_INPUT' });
  }

  const result = await engine.generateRule(description, examples || []);

  res.json({
    success   : true,
    rule      : result.rule,
    validation: result.validation,
    timestamp : new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/rule/validate
//  Validate a Sigma rule object
// ════════════════════════════════════════════════════════════════
router.post('/rule/validate', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { rule } = req.body;

  if (!rule) {
    return res.status(400).json({ error: 'rule required', code: 'INVALID_INPUT' });
  }

  const result = await engine.sigma.validateRule(rule);
  res.json({ success: true, ...result, timestamp: new Date().toISOString() });
}));

// ════════════════════════════════════════════════════════════════
//  GET /api/raykan/rules
//  List all loaded rules
// ════════════════════════════════════════════════════════════════
router.get('/rules', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { severity, tag, page = 1, limit = 50 } = req.query;

  let rules = engine.sigma.getAllRules();

  if (severity) rules = rules.filter(r => r.severity === severity);
  if (tag)      rules = rules.filter(r => r.tags?.some(t => t.includes(tag)));

  const total   = rules.length;
  const start   = (parseInt(page) - 1) * parseInt(limit);
  const paged   = rules.slice(start, start + parseInt(limit));

  res.json({
    success: true,
    total,
    page   : parseInt(page),
    limit  : parseInt(limit),
    rules  : paged,
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  GET /api/raykan/mitre
//  MITRE ATT&CK coverage heatmap
// ════════════════════════════════════════════════════════════════
router.get('/mitre', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);

  // Build coverage from loaded rules
  const rules     = engine.sigma.getAllRules();
  const mapper    = engine.mitre;
  const fakeDetections = rules.map(r => ({ ...r, mitre: mapper.mapDetection(r), confidence: 80 }));

  const timeline  = new TimelineEngine();
  const heatmap   = timeline.buildMitreHeatmap(fakeDetections);

  res.json({
    success   : true,
    heatmap,
    techniques: mapper.getAllTechniques(),
    tactics   : mapper.getAllTactics(),
    coverage  : {
      total     : Object.keys(mapper.getAllTechniques()).length,
      covered   : heatmap.length,
      percentage: Math.round(heatmap.length / Object.keys(mapper.getAllTechniques()).length * 100),
    },
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  GET /api/raykan/stats
//  Engine stats and health
// ════════════════════════════════════════════════════════════════
router.get('/stats', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const stats  = engine.getStats();

  res.json({
    success : true,
    version : stats.version,
    sessionId: stats.sessionId,
    stats   : {
      eventsProcessed     : stats.eventsProcessed,
      detectionsTriggered : stats.detectionsTriggered,
      anomaliesFound      : stats.anomaliesFound,
      chainsBuilt         : stats.chainsBuilt,
      queriesExecuted     : stats.queriesExecuted,
      rulesLoaded         : stats.rulesLoaded,
      uptime              : stats.uptime,
      bufferSize          : stats.bufferSize,
    },
    subEngines: stats.subEngines,
    timestamp : new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  GET /api/raykan/ioc/:value
//  Single IOC lookup
// ════════════════════════════════════════════════════════════════
router.get('/ioc/:value', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { value } = req.params;
  const { type  } = req.query;

  const result = await engine.enricher.lookupIOC(
    decodeURIComponent(value),
    type || null
  );

  res.json({
    success: true,
    ioc    : result,
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/ioc/batch
//  Batch IOC lookup
// ════════════════════════════════════════════════════════════════
router.post('/ioc/batch', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);
  const { iocs } = req.body;

  if (!Array.isArray(iocs) || iocs.length > 50) {
    return res.status(400).json({ error: 'iocs must be array of max 50', code: 'INVALID_INPUT' });
  }

  const results = await Promise.all(
    iocs.map(i => engine.enricher.lookupIOC(i.value || i, i.type || null))
  );

  res.json({
    success: true,
    count  : results.length,
    results,
    timestamp: new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/analyze/sample
//  Analyze sample events (demo/testing)
// ════════════════════════════════════════════════════════════════
router.post('/analyze/sample', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);

  // Generate realistic sample events
  const sampleEvents = _generateSampleEvents(req.body?.scenario || 'ransomware');

  const results = await engine.ingestEvents(sampleEvents, {
    source: 'sample',
    format: 'evtx',
    tenant: req.user?.tenant_id || 'demo',
  });

  const timelineEngine = new TimelineEngine();
  const graph = timelineEngine.buildAttackGraph(results.detections, results.chains);

  res.json({
    success     : true,
    scenario    : req.body?.scenario || 'ransomware',
    processed   : results.processed,
    detections  : results.detections,
    anomalies   : results.anomalies,
    chains      : results.chains,
    timeline    : results.timeline,
    graph,
    riskScore   : results.riskScore,
    duration    : results.duration,
    timestamp   : new Date().toISOString(),
  });
}));

// ════════════════════════════════════════════════════════════════
//  GET /api/raykan/health
//  Quick health check (no auth required)
// ════════════════════════════════════════════════════════════════
router.get('/health', (req, res) => {
  res.json({
    ok       : true,
    engine   : _engine ? 'running' : 'not_initialized',
    version  : '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ── Sample event generator ────────────────────────────────────────
function _generateSampleEvents(scenario) {
  const base = { Computer: 'WORKSTATION-42', User: 'john.doe', timestamp: new Date() };

  const scenarios = {
    ransomware: [
      { ...base, EventID: '4688', Image: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'cmd.exe /c powershell -EncodedCommand dABlAHMAdAA=', ProcessName: 'cmd.exe' },
      { ...base, EventID: '1',    Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -EncodedCommand dABlAHMAdAA=' },
      { ...base, EventID: '12',   TargetObject: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware' },
      { ...base, EventID: '1',    Image: 'C:\\Users\\john.doe\\AppData\\Local\\Temp\\payload.exe', CommandLine: 'payload.exe --encrypt C:\\Users' },
      { ...base, EventID: '4688', Image: 'C:\\Windows\\System32\\vssadmin.exe', CommandLine: 'vssadmin delete shadows /all /quiet', ProcessName: 'vssadmin.exe' },
      { ...base, EventID: '11',   TargetFilename: 'C:\\Users\\john.doe\\Documents\\report.docx.encrypted' },
    ],
    lateral_movement: [
      { ...base, EventID: '4624', LogonType: '3', AuthPackage: 'NTLM', SourceIp: '192.168.1.50' },
      { ...base, EventID: '1',    Image: 'C:\\Windows\\System32\\cmd.exe', ParentImage: 'C:\\Windows\\System32\\WmiPrvSE.exe', CommandLine: 'cmd.exe /c whoami' },
      { ...base, EventID: '4688', Image: 'C:\\Windows\\System32\\net.exe', CommandLine: 'net view /domain', ProcessName: 'net.exe' },
    ],
    credential_dump: [
      { ...base, EventID: '4688', Image: 'C:\\Tools\\procdump64.exe', CommandLine: 'procdump64.exe -ma lsass.exe lsass.dmp' },
      { ...base, EventID: '4624', LogonType: '9', User: 'Administrator' },
    ],
  };

  return scenarios[scenario] || scenarios.ransomware;
}

module.exports = router;
