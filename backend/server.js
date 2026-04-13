/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Production Backend Server v3.1.0
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

// ── Validate required environment variables on startup ───────────
const REQUIRED_ENV = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_KEY',
  'SUPABASE_ANON_KEY',
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error(`\n❌ [Server] Missing required environment variables:\n   ${missingEnv.join(', ')}`);
  console.error('   Copy backend/.env.example → backend/.env and fill in your values.\n');
  process.exit(1);
}

// ── Core imports (after env validation) ──────────────────────────
const express        = require('express');
const cors           = require('cors');          // ← Single declaration (was duplicated in v2.0.0)
const helmet         = require('helmet');
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
const sysmonRoutes      = require('./routes/sysmon');
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
const threatActorRoutes   = require('./routes/threat-actors');
// ── v6.0 New Routes ───────────────────────────────────────────────
const cveIntelRoutes      = require('./routes/cve-intelligence');
const adversarySimRoutes  = require('./routes/adversary-sim');
const threatGraphRoutes   = require('./routes/threat-graph');
const whatifRoutes        = require('./routes/whatif');
const rakayRoutes         = require('./routes/rakay');

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
  console.error('[FATAL] Uncaught Exception — server will continue:', err.message);
  console.error(err.stack);
  // Do NOT exit — Render will restart automatically if we do
  // In production, alert your monitoring (e.g. Sentry) here
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled Promise Rejection at:', promise);
  console.error('[FATAL] Reason:', reason);
  // Same — log and continue; don't crash in production
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

console.log('[CORS] Allowed origins:', allowedOrigins);

// ── Socket.IO — configured BEFORE middleware ─────────────────────
const io = new Server(httpServer, {
  cors: {
    origin:      allowedOrigins,
    methods:     ['GET', 'POST'],
    credentials: true,
  },
  // Ping timeout/interval for Render's load balancer
  pingTimeout:  60000,
  pingInterval: 25000,
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
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "https:"],
      connectSrc: ["'self'", ...allowedOrigins],
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
    if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }

    // Reject — return null (NOT new Error) so Express returns 204 not 500
    console.warn(`[CORS] Blocked origin: "${origin}" — not in ALLOWED_ORIGINS`);
    console.warn(`[CORS] Current whitelist: ${allowedOrigins.join(', ')}`);
    return callback(null, false);
  },
  credentials:    true,
  methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  exposedHeaders: ['X-RateLimit-Remaining'],
  optionsSuccessStatus: 204,   // Some browsers (IE11) choke on 204 — use 200 if needed
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle all preflight requests

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

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES — No JWT required
// ════════════════════════════════════════════════════════════════
app.use('/api/auth', authLimiter, authRoutes);

// ── v5.4 RAKAY AI Analyst Module (self-contained auth — must be BEFORE global verifyToken) ──
// RAKAY handles its own 3-tier auth: JWT | RAKAY service key | demo token
// Do NOT move below app.use(verifyToken) — the global JWT guard blocks demo auth.
app.use('/api/RAKAY', rakayRoutes);

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
app.use('/api/sysmon',          sysmonRoutes);
app.use('/api/reports',         reportRoutes);
// ── v5.1 New Routes ───────────────────────────────────────────────
app.use('/api/exposure',  exposureRoutes);
app.use('/api/soar',      soarEngineRoutes);
app.use('/api/ai',        aiRoutes);
app.use('/api/ingest',    ingestRoutes);
app.use('/api/settings',  settingsRoutes);
// ── v5.2 New Routes ───────────────────────────────────────────────
app.use('/api/news',           newsRoutes);
// ── v5.3 New Routes ───────────────────────────────────────────────
app.use('/api/threat-actors',  threatActorRoutes);
app.use('/api/cve',            cveIntelRoutes);
app.use('/api/adversary-sim',  adversarySimRoutes);
app.use('/api/threat-graph',   threatGraphRoutes);
app.use('/api/whatif',         whatifRoutes);
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
initWebSockets(io);

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
  console.log(`\n[Server] ${signal} received — starting graceful shutdown...`);

  httpServer.close((err) => {
    if (err) {
      console.error('[Server] Error during shutdown:', err.message);
      process.exit(1);
    }
    console.log('[Server] HTTP server closed — exiting cleanly.');
    process.exit(0);
  });

  // Force-kill if shutdown takes longer than 10 seconds
  setTimeout(() => {
    console.error('[Server] Forced shutdown after timeout.');
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
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log(`║  Wadjet-Eye AI Backend v4.0.0 (Enterprise)           ║`);  // updated
  console.log(`║  Port:        ${String(PORT).padEnd(39)}║`);
  console.log(`║  Environment: ${(process.env.NODE_ENV || 'development').padEnd(39)}║`);
  console.log(`║  Supabase:    ${(process.env.SUPABASE_URL ? 'Connected ✓' : '⚠️  Not configured').padEnd(39)}║`);
  console.log(`║  CORS:        ${allowedOrigins.join(', ').slice(0,38).padEnd(39)}║`);
  console.log('╚══════════════════════════════════════════════════════╝\n');
});

module.exports = { app, httpServer, io };
