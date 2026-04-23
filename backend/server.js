/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Production Backend Server v3.2.0
 *  Node.js + Express + Supabase + WebSockets
 *
 *  Frontend: https://wadjet-eye-ai.vercel.app
 *  Backend:  https://wadjet-eye-ai.onrender.com
 *  Health:   https://wadjet-eye-ai.onrender.com/health
 *
 *  Allowed Origins:
 *    https://wadjet-eye-ai.vercel.app
 *    https://www.genspark.ai
 *    http://localhost:3000
 *
 *  Supabase: miywxnplaltduuscjfmq.supabase.co
 * ══════════════════════════════════════════════════════════
 */

'use strict';

// ── Load .env FIRST before any other module ─────────────────────
require('dotenv').config();

// ── Production console silence (drop_console equivalent) ─────────
// In production, override console.log/info/debug to no-ops.
// Only error and warn pass through (captured by centralized logger).
// This blocks: module-load banners, health-check spam, debug traces.
if (process.env.NODE_ENV === 'production') {
  console.log   = () => {};
  console.info  = () => {};
  console.debug = () => {};
  // console.warn and console.error are preserved — surfaced via logger
}

// ── Centralized logger — must be imported AFTER dotenv.config() ──
const logger = require('./utils/logger');
const _SRV   = 'Server';

// ── Environment validation (Phase 0+1 security hardening) ───────
// CRITICAL env vars — fail-fast in production only:
const CRITICAL_ENV = ['JWT_SECRET'];
// Recommended (warn-only — AI routes work without Supabase):
const RECOMMENDED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SUPABASE_ANON_KEY'];
// AI providers — warn if ALL are absent (platform falls back to mock):
const AI_PROVIDER_ENV = [
  'OPENAI_API_KEY', 'CLAUDE_API_KEY', 'GEMINI_API_KEY',
  'DEEPSEEK_API_KEY', 'RAKAY_OPENAI_KEY', 'ANTHROPIC_API_KEY',
];

// Fail-fast for truly critical vars in production
if (process.env.NODE_ENV === 'production') {
  const missingCritical = CRITICAL_ENV.filter(k => !process.env[k]);
  if (missingCritical.length) {
    logger.error(_SRV, `🚨 CRITICAL: Missing required env vars in production: ${missingCritical.join(', ')}`);
    logger.error(_SRV, 'Set these in Render Dashboard → Environment → Add Environment Variable');
    process.exit(1);
  }
}

const missingRecommended = RECOMMENDED_ENV.filter(k => !process.env[k]);
if (missingRecommended.length > 0) {
  logger.warn(_SRV, `Missing recommended env vars: ${missingRecommended.join(', ')}`);
  logger.warn(_SRV, 'DB-dependent routes may fail. Copy backend/.env.example → backend/.env');
}

const hasAnyAIKey = AI_PROVIDER_ENV.some(k => !!process.env[k]);
if (!hasAnyAIKey) {
  logger.warn(_SRV, 'No AI provider keys detected — RAKAY will use Local Intelligence Mode.');
}

// Phase 0 security audit — detect hardcoded key patterns at startup
(function _securityAudit() {
  const SUSPICIOUS_PATTERNS = [/sk-proj-[A-Za-z0-9_-]{20,}/, /sk-ant-api03-/, /AIzaSy[A-Za-z0-9_-]{33}/];
  const envValues = Object.values(process.env);
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (envValues.some(v => pattern.test(v))) {
      logger.warn('Security', '⚠️  AI key pattern detected in env — ensure keys are not committed to source control.');
      break;
    }
  }
})();

// ── Core imports (after env validation) ──────────────────────────
const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const cookieParser   = require('cookie-parser');
const crypto         = require('crypto');
const morgan         = require('morgan');
const rateLimit      = require('express-rate-limit');
const compression    = require('compression');
const { createServer } = require('http');
const { Server }     = require('socket.io');

// ── Internal modules ─────────────────────────────────────────────
const { verifyToken }    = require('./middleware/auth');
const { auditLog }       = require('./middleware/audit');
const { errorHandler }   = require('./middleware/errorHandler');

// ── Routes ───────────────────────────────────────────────────────
const authRoutes      = require('./routes/auth');
const alertRoutes     = require('./routes/alerts');
const caseRoutes      = require('./routes/cases');
const iocRoutes       = require('./routes/iocs');
const userRoutes      = require('./routes/users');
const auditRoutes     = require('./routes/auditLogs');
const intelRoutes     = require('./routes/intel');
const tenantRoutes    = require('./routes/tenants');
const dashboardRoutes = require('./routes/dashboard');
const playbookRoutes    = require('./routes/playbooks');
const collectorRoutes   = require('./routes/collectors');
const ctiRoutes         = require('./routes/cti');
const vulnRoutes        = require('./routes/vulnerabilities');
const reportRoutes      = require('./routes/reports');
// ── v5.1 New Routes ───────────────────────────────────────────────
const exposureRoutes    = require('./routes/exposure');
const soarEngineRoutes  = require('./routes/soar-engine');
const aiRoutes          = require('./routes/ai');
const ingestRoutes      = require('./routes/ioc-ingestion');
const settingsRoutes    = require('./routes/settings');
// ── v5.2 New Routes ───────────────────────────────────────────────
const newsRoutes          = require('./routes/news');
// ── v5.3 New Routes ───────────────────────────────────────────────
// ── v6.0 New Routes ───────────────────────────────────────────────
const rakayRoutes         = require('./routes/rakay');
const socIntelRoutes      = require('./routes/soc-intelligence');   // ← SOC v2.0
// ── RAYKAN AI Threat Hunting & DFIR Engine v1.0 ──────────────────
const raykanEngineRoutes  = require('./routes/raykan-engine');       // ← RAYKAN v1.0

// ── Realtime ─────────────────────────────────────────────────────
const { initWebSockets } = require('./realtime/websockets');
const { startScheduler } = require('./services/scheduler');

// ════════════════════════════════════════════════════════════════
//  PROCESS-LEVEL CRASH GUARDS
//  These prevent the entire Node process from dying on an
//  unhandled promise rejection or a thrown error in an async
//  callback that wasn't wrapped with asyncHandler.
// ════════════════════════════════════════════════════════════════
process.on('uncaughtException', (err) => {
  logger.error('FATAL', `Uncaught Exception — server will continue: ${err.message}`);
  logger.error('FATAL', err.stack || err.message);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('FATAL', `Unhandled Promise Rejection: ${reason}`);
});

// ════════════════════════════════════════════════════════════════
//  EXPRESS APP SETUP
// ════════════════════════════════════════════════════════════════
const app        = express();
const httpServer = createServer(app);

// ── Build allowed origins from environment ───────────────────────
const allowedOrigins = (
  process.env.ALLOWED_ORIGINS ||
  'https://wadjet-eye-ai.vercel.app,https://www.genspark.ai,http://localhost:3000,http://localhost:5500,http://127.0.0.1:5500'
)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// ── Wildcard: allow all e2b/genspark/novita sandbox preview origins ──────────
// These are the *.e2b.dev and *.novita.ai preview URLs used during development
const _sandboxOriginRegex = /^https?:\/\/[^/]*\.(e2b\.dev|genspark\.ai|vercel\.app|render\.com|novita\.ai|sandbox\.novita\.ai)$/;
function _isSandboxOrigin(origin) {
  return _sandboxOriginRegex.test(origin);
}

logger.info(_SRV, `CORS allowed origins: ${allowedOrigins.join(', ')}`);

// ── Socket.IO — configured BEFORE middleware ─────────────────────
const io = new Server(httpServer, {
  cors: {
    origin:         allowedOrigins,
    methods:        ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 'Authorization', 'X-Tenant-ID',
      'X-Access-Token', 'X-RAKAY-KEY', 'X-Requested-With',
      'Cache-Control', 'Pragma',
    ],
    credentials: true,
  },
  // Allow both polling and websocket — Render's proxy may block raw WS upgrades
  // Polling ensures the handshake completes even when WS is blocked
  transports:   ['polling', 'websocket'],
  allowUpgrades: true,
  // Ping timeout/interval tuned for Render's 55s idle-close window
  pingTimeout:  60000,
  pingInterval: 25000,
  // Render free-tier keeps connections alive; path explicitly set
  path: '/socket.io/',
});

// Make io available inside route handlers via req.app.get('io')
app.set('io', io);

// ════════════════════════════════════════════════════════════════
//  SECURITY MIDDLEWARE
// ════════════════════════════════════════════════════════════════

// ── Helmet — security headers ────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      imgSrc:      ["'self'", "data:", "https:"],
      // connectSrc must include the BACKEND URL itself so the
      // browser's CSP doesn't block WebSocket / fetch to Render
      connectSrc:  [
        "'self'",
        'https://wadjet-eye-ai.onrender.com',
        'wss://wadjet-eye-ai.onrender.com',
        ...allowedOrigins,
      ],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
    },
  },
  hsts: {
    maxAge:            31536000,
    includeSubDomains: true,
    preload:           true,
  },
  // Required for Render's reverse proxy
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — single definition, no duplicate ───────────────────────
const corsOptions = {
  origin(origin, callback) {
    // Allow Postman / curl / server-to-server calls (no Origin header sent)
    if (!origin) return callback(null, true);

    // Allow if origin is in the whitelist OR we're in local development
    if (allowedOrigins.includes(origin) ||
        _isSandboxOrigin(origin) ||
        process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }

    // Reject — log and return false so Express sends a proper CORS error
    // (returning false causes the cors middleware to omit ACAO header → browser
    //  shows a CORS block, but Express still returns 200/204 not 500)
    logger.warn('CORS', `Blocked origin: "${origin}" — not in ALLOWED_ORIGINS`);
    logger.warn('CORS', `Current whitelist: ${allowedOrigins.join(', ')}`);
    return callback(null, false);
  },
  credentials:    true,
  methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  // allowedHeaders must include every header the Vercel frontend sends:
  //   Authorization  — Bearer JWT
  //   X-Tenant-ID    — multi-tenant routing
  //   X-Access-Token — legacy token field used in auth.js
  //   X-RAKAY-KEY    — RAKAY service-key bypass
  //   X-Requested-With — Axios / jQuery convention; some proxies require it
  //   Cache-Control / Pragma — sent by fetch() with cache:'no-cache'
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Tenant-ID',
    'X-Access-Token',
    'X-RAKAY-KEY',
    'X-Requested-With',
    'Cache-Control',
    'Pragma',
    // Malware Analysis Lab — API key passthrough headers
    'X-VT-Key',
    'X-HA-Key',
    'X-Intezer-Key',
    'X-Anyrun-Key',
    'X-Debug-Mode',
  ],
  exposedHeaders: ['X-RateLimit-Remaining', 'X-Request-ID'],
  optionsSuccessStatus: 200,   // 200 avoids IE11 / some proxy issues with 204
};

// ── Global OPTIONS preflight must be registered BEFORE any route ────
// This handles all preflight (OPTIONS) requests across every endpoint.
app.options('*', cors(corsOptions));
app.use(cors(corsOptions));

// ── Trust proxy for correct IP behind Render's load balancer ─────
app.set('trust proxy', 1);

// ════════════════════════════════════════════════════════════════
//  RATE LIMITING
// ════════════════════════════════════════════════════════════════
const globalLimiter = rateLimit({
  windowMs:       15 * 60 * 1000,  // 15 min
  max:            500,
  message:        { error: 'Too many requests. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:  false,
  // Skip rate limiting for health checks
  skip: (req) => req.path === '/health',
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,                    // 10 login attempts per 15 min
  message:  { error: 'Too many login attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false,
  // Only apply strict limit to login and register (not to refresh/me)
  skip: (req) => ['/api/auth/refresh', '/api/auth/refresh-from-cookie', '/api/auth/me', '/api/auth/logout'].includes(req.path),
});

// Separate, more permissive limiter for token-refresh endpoints.
// Silent refresh fires proactively at 80% TTL, so it should be allowed
// up to ~20x per 15-min window (much less than login spam).
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      30,                    // 30 refresh attempts per 15 min per IP
  message:  { error: 'Too many token refresh requests. Please wait before retrying.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

const intelLimiter = rateLimit({
  windowMs: 60 * 1000,             // 1 min
  max:      30,                    // 30 threat intel lookups/min
  message:  { error: 'Threat intel rate limit reached. Max 30 requests/minute.' },
});

app.use(globalLimiter);

// ════════════════════════════════════════════════════════════════
//  GENERAL MIDDLEWARE
// ════════════════════════════════════════════════════════════════
app.use(compression());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ── httpOnly cookie parser (Phase 1: secure token storage) ───────
app.use(cookieParser());

// ── Request ID middleware (Phase 5: observability) ───────────────
// Assigns a unique correlation ID to every request for log tracing.
app.use((req, _res, next) => {
  req.id = req.headers['x-request-id'] || crypto.randomUUID();
  next();
});

// ── Request logging ───────────────────────────────────────────────
// In production use 'combined' (Apache-style), dev use 'dev' (colorful)
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK — No auth required
//  Render uses this endpoint to verify the service is alive
// ════════════════════════════════════════════════════════════════
app.get('/health', async (req, res) => {
  const health = {
    status:      'OK',
    service:     'Wadjet-Eye AI Backend',
    version:     '3.1.0',
    timestamp:   new Date().toISOString(),
    environment: process.env.NODE_ENV,
    uptime_s:    Math.floor(process.uptime()),
    memory_mb:   Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  };

  // Optional: quick Supabase ping (non-blocking)
  try {
    const { supabase } = require('./config/supabase');
    const start = Date.now();
    await supabase.from('tenants').select('id').limit(1);
    health.db_latency_ms = Date.now() - start;
    health.db = 'connected';
  } catch {
    health.db = 'unreachable';
  }

  res.status(200).json(health);
});

// ── /api/health alias (same as /health, no JWT required) ──────
app.get('/api/health', async (req, res) => {
  const health = {
    status:      'OK',
    service:     'Wadjet-Eye AI Backend',
    version:     '3.1.0',
    timestamp:   new Date().toISOString(),
    uptime_s:    Math.floor(process.uptime()),
    memory_mb:   Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  };
  try {
    const { supabase } = require('./config/supabase');
    const start = Date.now();
    await supabase.from('tenants').select('id').limit(1);
    health.db_latency_ms = Date.now() - start;
    health.db = 'connected';
  } catch { health.db = 'unreachable'; }
  res.status(200).json(health);
});

// ── /api/ping — ultra-fast liveness check, no DB, no JWT ────────────────────
// Used by the frontend wake-up pinger on page load to trigger Render warm-up.
app.get('/api/ping', (req, res) => {
  res.status(200).json({ ok: true, t: Date.now() });
});


// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES — No JWT required
// ════════════════════════════════════════════════════════════════
// Apply strict login limiter for login/register, permissive refresh limiter for refresh endpoints
app.use('/api/auth/refresh', refreshLimiter);
app.use('/api/auth/refresh-from-cookie', refreshLimiter);
app.use('/api/auth', authLimiter, authRoutes);

// ── v5.4 RAKAY AI Analyst Module (self-contained auth — must be BEFORE global verifyToken) ──
// RAKAY handles its own 3-tier auth: JWT | RAKAY service key | demo token
// Do NOT move below app.use(verifyToken) — the global JWT guard blocks demo auth.
app.use('/api/RAKAY', rakayRoutes);
// ── v6.1 SOC Intelligence API (no JWT required — uses RAKAY demo auth) ──────
app.use('/api/soc', socIntelRoutes);

// ── v7.0 Specific public GET endpoints (no JWT required) ─────────────────────
// These MUST be registered BEFORE app.use(verifyToken).
// /api/rbac/health  — returns platform role schema (no sensitive data)
app.get('/api/rbac/health', (req, res) => {
  const roles = [
    { id: 'super_admin', name: 'Super Admin',       slug: 'super_admin', level: 10, color: '#ef4444' },
    { id: 'admin',       name: 'Admin',             slug: 'admin',       level: 9,  color: '#f97316' },
    { id: 'soc_l3',      name: 'SOC Analyst L3',    slug: 'soc_l3',      level: 7,  color: '#dc2626' },
    { id: 'soc_l2',      name: 'SOC Analyst L2',    slug: 'soc_l2',      level: 6,  color: '#3b82f6' },
    { id: 'soc_l1',      name: 'SOC Analyst L1',    slug: 'soc_l1',      level: 5,  color: '#22d3ee' },
    { id: 'ir',          name: 'Incident Responder', slug: 'ir',          level: 7,  color: '#7c3aed' },
    { id: 'threat_hunter', name: 'Threat Hunter',   slug: 'threat_hunter', level: 7, color: '#10b981' },
    { id: 'viewer',      name: 'Viewer (Read-Only)', slug: 'viewer',      level: 1,  color: '#6b7280' },
  ];
  const permissions = ['read','write','delete','export','investigate','hunt','build_detections','contain','manage_users','manage_roles','manage_settings'];
  const modules = ['dashboard','alerts','iocs','cases','reports','users','settings','collectors',
                   'threat-hunting','detection-engineering','playbooks','mitre-attack','forensics',
                   'threat-intel','vulnerabilities','exposure','soar','ai','news','rbac'];
  res.json({
    status:          'operational',
    roles,
    roleCount:       roles.length,
    permissions,
    permissionCount: permissions.length,
    moduleCount:     modules.length,
    modules,
    schemaVersion:   '3.0',
    timestamp:       new Date().toISOString(),
  });
});

// /api/rbac/schema — alias for /api/rbac/health (frontend compatibility, no sensitive data)
app.get('/api/rbac/schema', (req, res) => res.redirect('/api/rbac/health'));

// /api/rbac/roles — public role list (id, name, slug, level, color — used by login forms)
app.get('/api/rbac/roles', (req, res) => {
  const roles = [
    { id: 'super_admin',   name: 'Super Admin',        slug: 'super_admin',   level: 10, color: '#ef4444' },
    { id: 'admin',         name: 'Admin',              slug: 'admin',         level: 9,  color: '#f97316' },
    { id: 'soc_l3',        name: 'SOC Analyst L3',     slug: 'soc_l3',        level: 7,  color: '#dc2626' },
    { id: 'soc_l2',        name: 'SOC Analyst L2',     slug: 'soc_l2',        level: 6,  color: '#3b82f6' },
    { id: 'soc_l1',        name: 'SOC Analyst L1',     slug: 'soc_l1',        level: 5,  color: '#22d3ee' },
    { id: 'ir',            name: 'Incident Responder', slug: 'ir',            level: 7,  color: '#7c3aed' },
    { id: 'threat_hunter', name: 'Threat Hunter',      slug: 'threat_hunter', level: 7,  color: '#10b981' },
    { id: 'analyst',       name: 'Analyst',            slug: 'analyst',       level: 5,  color: '#2563eb' },
    { id: 'viewer',        name: 'Viewer',             slug: 'viewer',        level: 1,  color: '#6b7280' },
    { id: 'auditor',       name: 'Auditor',            slug: 'auditor',       level: 3,  color: '#ec4899' },
    { id: 'executive',     name: 'Executive',          slug: 'executive',     level: 2,  color: '#f59e0b' },
  ];
  res.json({ roles, total: roles.length, timestamp: new Date().toISOString() });
});

// ── RAYKAN v1.0 — AI Threat Hunting & DFIR Engine (PUBLIC — no JWT required) ──
// Demo-mode access: all /api/raykan/* endpoints are public for integration & UI testing.
// NOTE: Must be BEFORE app.use(verifyToken) below.
app.use('/api/raykan', raykanEngineRoutes);

// ETI-AARE Email Threat Intelligence Engine v1.0 — public for demo/testing
const emailThreatRoutes = require('./routes/email-threat');
app.use('/api/email-threat', emailThreatRoutes);

// /api/email-analysis — alias health check endpoint for the frontend
// GET /api/email-analysis/health — returns engine status (no auth required)
app.get('/api/email-analysis/health', (req, res) => {
  try {
    const { getInstance } = require('./services/email-threat/eti-aare-engine');
    const engine = getInstance({ enableAI: false });
    const rules  = engine.detector?.getRules?.()?.length || 0;
    res.json({
      status:    'ok',
      healthy:   true,
      success:   true,
      service:   'ETI-AARE Email Threat Intelligence Engine',
      version:   '2.0.0',
      timestamp: new Date().toISOString(),
      details:   { detector_rules: rules, fingerprinter: true, scorer: true, soar: true }
    });
  } catch (e) {
    res.json({
      status:    'degraded',
      healthy:   false,
      success:   false,
      service:   'ETI-AARE Email Threat Intelligence Engine',
      version:   '2.0.0',
      timestamp: new Date().toISOString(),
      error:     e.message
    });
  }
});

// /api/news — Cyber News is public (no user-specific data in news articles).
// Registered before verifyToken so unauthenticated clients (demo mode, public
// dashboard) can read news. The POST /ingest endpoint inside newsRoutes does its
// own role-check, so it's safe to expose the whole router publicly.
app.use('/api/news', newsRoutes);

// /api/cve — CVE Threat Engine is public; results come from NVD, not tenant data.
// API keys are kept server-side; the frontend never sees them.
const cveRoutes = require('./routes/cve-intelligence');
app.use('/api/cve', cveRoutes);

// ── Malware Analysis Lab v3.0 — PUBLIC proxy (API keys supplied per-request via X-* headers)
// All actual API keys are passed by the browser in request headers and forwarded
// server-side to avoid CORS restrictions. No keys are stored server-side.
// Registered before verifyToken so unauthenticated users can submit samples.
const malwareAnalysisRoutes = require('./routes/malware-analysis');
app.use('/api/malware', malwareAnalysisRoutes);

// ════════════════════════════════════════════════════════════════
//  PROTECTED ROUTES — JWT required
//  verifyToken attaches req.user + req.tenantId to every request
// ════════════════════════════════════════════════════════════════
app.use(verifyToken);  // All routes BELOW this line require a valid JWT
app.use(auditLog);     // Automatically log every mutating request

app.use('/api/alerts',    alertRoutes);
app.use('/api/cases',     caseRoutes);
app.use('/api/iocs',      iocRoutes);
app.use('/api/users',     userRoutes);
app.use('/api/audit',     auditRoutes);
app.use('/api/tenants',   tenantRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/playbooks', playbookRoutes);
app.use('/api/intel',      intelLimiter, intelRoutes);
app.use('/api/collectors', collectorRoutes);
app.use('/api/cti',            ctiRoutes);
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/reports',         reportRoutes);
// ── v5.1 New Routes ───────────────────────────────────────────────
app.use('/api/exposure',  exposureRoutes);
app.use('/api/soar',      soarEngineRoutes);
app.use('/api/ai',        aiRoutes);
app.use('/api/ingest',    ingestRoutes);
app.use('/api/settings',  settingsRoutes);
// ── v5.2 New Routes ───────────────────────────────────────────────
// NOTE: /api/news is mounted BEFORE verifyToken (see PUBLIC ROUTES section above)
//       so it is accessible without JWT.  Do NOT re-mount here.
// ── v5.3 New Routes ───────────────────────────────────────────────
// ── v7.0 New Routes ───────────────────────────────────────────────
const rbacRoutes = require('./routes/rbac');
app.use('/api/rbac',           rbacRoutes);
// NOTE: /api/raykan is mounted BEFORE verifyToken (see PUBLIC ROUTES section above)
//       so it is accessible without JWT for demo mode and frontend integration.
// ════════════════════════════════════════════════════════════════
//  404 HANDLER — catches all unmatched routes
//  Must be placed AFTER all route registrations
// ════════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({
    error: `Route not found: ${req.method} ${req.path}`,
    code:  'ROUTE_NOT_FOUND',
  });
});

// ════════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLER — must be LAST middleware
// ════════════════════════════════════════════════════════════════
app.use(errorHandler);

// ════════════════════════════════════════════════════════════════
//  WEBSOCKETS
// ════════════════════════════════════════════════════════════════
initWebSockets(io, httpServer);

// ════════════════════════════════════════════════════════════════
//  SCHEDULER — starts CTI ingestion + SOAR cron jobs
// ════════════════════════════════════════════════════════════════
startScheduler();

// ════════════════════════════════════════════════════════════════
//  GRACEFUL SHUTDOWN
//  Render sends SIGTERM before restarting. This closes connections
//  cleanly instead of dropping in-flight requests.
// ════════════════════════════════════════════════════════════════
function gracefulShutdown(signal) {
  logger.warn(_SRV, `${signal} received — starting graceful shutdown...`);

  httpServer.close((err) => {
    if (err) {
      logger.error(_SRV, `Error during shutdown: ${err.message}`);
      process.exit(1);
    }
    logger.warn(_SRV, 'HTTP server closed — exiting cleanly.');
    process.exit(0);
  });

  // Force-kill if shutdown takes longer than 10 seconds
  setTimeout(() => {
    logger.error(_SRV, 'Forced shutdown after timeout.');
    process.exit(1);
  }, 10_000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ════════════════════════════════════════════════════════════════
//  START SERVER
// ════════════════════════════════════════════════════════════════
const PORT = parseInt(process.env.PORT, 10) || 4000;

httpServer.listen(PORT, '0.0.0.0', () => {
  // ── Startup summary: INFO level (visible in dev, suppressed in production) ──
  const env     = process.env.NODE_ENV || 'development';
  const supaOk  = !!process.env.SUPABASE_URL;

  logger.info(_SRV, `Wadjet-Eye AI Backend v4.1.0 — port ${PORT} — env: ${env} — supabase: ${supaOk ? 'configured' : 'not configured'}`);

  // ── AI Provider Key Diagnostics — INFO level ──────────────────────────────
  const openaiKey   = process.env.OPENAI_API_KEY   || process.env.RAKAY_OPENAI_KEY   || '';
  const claudeKey   = process.env.CLAUDE_API_KEY   || process.env.ANTHROPIC_API_KEY  || process.env.RAKAY_API_KEY || '';
  const geminiKey   = process.env.GEMINI_API_KEY   || '';
  const deepseekKey = process.env.DEEPSEEK_API_KEY || process.env.deepseek_API_KEY   || '';
  const hasAny      = !!(openaiKey || claudeKey || geminiKey || deepseekKey);

  if (!hasAny) {
    // WARN level — operator needs to know even in production
    logger.warn('STARTUP', 'No AI provider keys detected — RAKAY will use Local Intelligence Mode. Add OPENAI_API_KEY / CLAUDE_API_KEY / GEMINI_API_KEY to env.');
  } else {
    logger.info('STARTUP', `AI providers active — mode: EXTERNAL LLM`);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
//  KEEP-ALIVE SELF-PINGER
//  Render free tier spins down after 15 min of inactivity.
//  This pings /api/ping every 14 minutes to keep the server warm.
//  NOTE: This only helps if the server is already running (won't wake from
//        cold start by itself). Use an external uptime monitor (e.g. UptimeRobot)
//        to also ping the service from outside.
// ═══════════════════════════════════════════════════════════════════════════
if (process.env.NODE_ENV === 'production') {
  const _keepAliveInterval = 14 * 60 * 1000;  // 14 min
  setInterval(() => {
    const selfUrl = `http://localhost:${process.env.PORT || 4000}/api/ping`;
    fetch(selfUrl, { signal: AbortSignal.timeout(5000) })
      .then(() => {})
      .catch(() => {}); // Silent — if we're down we can't self-ping anyway
  }, _keepAliveInterval);
}

module.exports = { app, httpServer, io };
