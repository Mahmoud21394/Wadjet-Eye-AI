/**
 * ETI-AARE API Routes v1.0
 * REST API endpoints for Email Threat Intelligence engine
 */

'use strict';

const express = require('express');
const router = express.Router();
const { getInstance } = require('../services/email-threat/eti-aare-engine');

// Initialize engine (lazy singleton)
function getEngine(req) {
  return getInstance({
    enableAI: false, // Disable LLM for now (no API key)
    auto_response_enabled: true,
    virustotal_api_key: process.env.VIRUSTOTAL_API_KEY,
    abuseipdb_api_key: process.env.ABUSEIPDB_API_KEY,
    urlscan_api_key: process.env.URLSCAN_API_KEY
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ─── Analysis Endpoints ───────────────────────────────────────────────────────

/**
 * POST /api/email-threat/analyze
 * Analyze a single email
 * Body: { email: rawEmailObject, source: 'manual' }
 */
router.post('/analyze', asyncHandler(async (req, res) => {
  const { email, source = 'manual' } = req.body;
  if (!email) return res.status(400).json({ error: 'email object required' });

  const engine = getEngine(req);
  const result = await engine.analyze(email, source);

  res.json({ success: true, data: result });
}));

/**
 * POST /api/email-threat/analyze-batch
 * Analyze multiple emails
 */
router.post('/analyze-batch', asyncHandler(async (req, res) => {
  const { emails, source = 'batch' } = req.body;
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ error: 'emails array required' });
  }
  if (emails.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 emails per batch' });
  }

  const engine = getEngine(req);
  const result = await engine.analyzeBatch(emails, source);
  res.json({ success: true, data: result });
}));

/**
 * POST /api/email-threat/analyze-demo
 * Analyze a demo/sample email for testing the UI
 */
router.post('/analyze-demo', asyncHandler(async (req, res) => {
  const { scenario = 'phishing' } = req.body;
  const engine = getEngine(req);

  const scenarios = {
    phishing: getDemoPhishingEmail(),
    bec: getDemoBECEmail(),
    malware: getDemoMalwareEmail(),
    clean: getDemoCleanEmail()
  };

  const demoEmail = scenarios[scenario] || scenarios.phishing;
  const result = await engine.analyze(demoEmail, 'demo');
  res.json({ success: true, scenario, data: result });
}));

// ─── SOAR/Response Endpoints ──────────────────────────────────────────────────

/**
 * GET /api/email-threat/quarantine
 * Get quarantined emails
 */
router.get('/quarantine', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const quarantine = engine.soar.getQuarantine();
  res.json({ success: true, data: quarantine, count: quarantine.length });
}));

/**
 * POST /api/email-threat/quarantine/:messageId/release
 * Release email from quarantine
 */
router.post('/quarantine/:messageId/release', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const result = engine.soar.releaseFromQuarantine(
    decodeURIComponent(req.params.messageId),
    req.body.note
  );
  res.json({ success: result.success, data: result });
}));

/**
 * GET /api/email-threat/incidents
 * Get all incidents
 */
router.get('/incidents', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const incidents = engine.soar.getIncidents();
  const { status, severity } = req.query;

  let filtered = incidents;
  if (status) filtered = filtered.filter(i => i.status === status);
  if (severity) filtered = filtered.filter(i => i.severity === severity.toUpperCase());

  res.json({ success: true, data: filtered, count: filtered.length });
}));

/**
 * GET /api/email-threat/blocklists
 * Get current blocklists
 */
router.get('/blocklists', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const blocklists = engine.soar.getBlocklists();
  res.json({ success: true, data: blocklists });
}));

/**
 * POST /api/email-threat/blocklists/add
 * Manually add to blocklist
 */
router.post('/blocklists/add', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const { type, value } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });

  if (!engine.soar.blocklists[type + 's']) {
    return res.status(400).json({ error: 'Invalid type. Use: sender, domain, ip, url' });
  }
  engine.soar.blocklists[type + 's'].add(value);
  res.json({ success: true, message: `Added ${value} to ${type} blocklist` });
}));

// ─── Analytics Endpoints ──────────────────────────────────────────────────────

/**
 * GET /api/email-threat/stats
 * Get system statistics
 *
 * RC-FIX v3.0: Added safe fallback when engine.getStats() throws or returns
 * undefined.  The route is already mounted BEFORE verifyToken in server.js
 * (line 482) so it requires NO authentication token — 401 errors are NOT
 * expected.  If you see 401 it means the frontend is sending an expired token
 * and the verifyToken middleware is intercepting it incorrectly; check that
 * emailThreatRoutes is still above app.use(verifyToken) in server.js.
 */
router.get('/stats', asyncHandler(async (req, res) => {
  try {
    const engine = getEngine(req);
    const stats  = engine.getStats?.() ?? {
      total_analyzed: 0,
      by_tier: { critical: 0, high: 0, medium: 0, low: 0, clean: 0 },
    };
    res.json({ success: true, data: stats });
  } catch (e) {
    // Return a safe empty-stats object rather than 500
    res.json({
      success: true,
      data: {
        total_analyzed: 0,
        by_tier: { critical: 0, high: 0, medium: 0, low: 0, clean: 0 },
      },
      _warning: e.message,
    });
  }
}));

/**
 * GET /api/email-threat/attack-graph
 * Get attack graph for visualization
 */
router.get('/attack-graph', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const limit = parseInt(req.query.limit) || 200;
  const graph = engine.attackGraph.exportForVisualization(limit);
  res.json({ success: true, data: graph });
}));

/**
 * GET /api/email-threat/campaigns
 * Get detected attack campaigns
 */
router.get('/campaigns', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const campaigns = engine.attackGraph.getCampaigns();
  res.json({ success: true, data: campaigns, count: campaigns.length });
}));

/**
 * GET /api/email-threat/behavioral-alerts
 * Get behavioral identity alerts
 */
router.get('/behavioral-alerts', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const limit = parseInt(req.query.limit) || 50;
  const alerts = engine.fingerprinter.getAlerts(limit);
  res.json({ success: true, data: alerts, count: alerts.length });
}));

/**
 * GET /api/email-threat/sender-profile/:address
 * Get sender behavioral profile
 */
router.get('/sender-profile/:address', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const profile = engine.fingerprinter.getProfile(decodeURIComponent(req.params.address));
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  res.json({ success: true, data: profile });
}));

/**
 * GET /api/email-threat/rules
 * Get all detection rules
 */
router.get('/rules', asyncHandler(async (req, res) => {
  const engine = getEngine(req);
  const rules = engine.detector.getRules();
  res.json({ success: true, data: rules, count: rules.length });
}));

// ─── Demo Data Generators ─────────────────────────────────────────────────────

function getDemoPhishingEmail() {
  return {
    id: 'demo-phish-001',
    subject: 'URGENT: Your Microsoft 365 Account Will Be Suspended - Action Required Immediately',
    from: { emailAddress: { address: 'admin-noreply@m1cr0soft-security.tk', name: 'Microsoft Security Team' } },
    toRecipients: [{ emailAddress: { address: 'victim@company.com', name: 'John Employee' } }],
    receivedDateTime: new Date().toISOString(),
    hasAttachments: false,
    body: {
      contentType: 'html',
      content: `<html><body>
<div style="font-family: Arial;">
<p>Dear User,</p>
<p><strong>URGENT ACTION REQUIRED</strong></p>
<p>Your Microsoft 365 account has been flagged for unusual activity. Your account will be <strong>SUSPENDED WITHIN 24 HOURS</strong> unless you verify your identity immediately.</p>
<p>To prevent suspension, please click the link below and sign in to confirm your account:</p>
<p><a href="https://m1cr0s0ft-secure-login.xyz/verify?user=victim@company.com&token=abc123">Click Here to Verify Your Account Now</a></p>
<p>If you do not verify within 24 hours, you will lose access to all Microsoft services.</p>
<p>Thank you,<br>Microsoft Security Team</p>
<p style="color: #ffffff; font-size: 1px;">Microsoft Corporation security notification legitimate</p>
</div>
</body></html>`
    },
    internetMessageHeaders: [
      { name: 'Authentication-Results', value: 'mx.company.com; spf=fail (sender IP not authorized) smtp.mailfrom=m1cr0soft-security.tk; dkim=fail; dmarc=fail' },
      { name: 'Received', value: 'from unknown (185.234.219.123) by mx.company.com; ' + new Date().toUTCString() },
      { name: 'Received', value: 'from mail.m1cr0soft-security.tk (185.234.219.123) by unknown; ' + new Date().toUTCString() },
      { name: 'Return-Path', value: '<bounces@m1cr0soft-security.tk>' },
      { name: 'Reply-To', value: 'support@account-recovery-help.ml' },
      { name: 'X-Mailer', value: 'PHPMailer 6.5.0' }
    ]
  };
}

function getDemoBECEmail() {
  return {
    id: 'demo-bec-001',
    subject: 'Urgent Wire Transfer Request',
    from: { emailAddress: { address: 'ceo.johnson@company-corp.com', name: 'Robert Johnson (CEO)' } },
    toRecipients: [{ emailAddress: { address: 'cfo@company.com', name: 'Finance Team' } }],
    receivedDateTime: new Date().toISOString(),
    hasAttachments: false,
    body: {
      contentType: 'text/plain',
      content: `Hi,

I need you to process an urgent wire transfer today. We are closing a confidential acquisition deal and need to move funds immediately. Please keep this confidential - do not discuss with anyone else in the office.

Wire transfer details:
Amount: $487,500
Bank: First National Bank
Routing Number: 021000021
Account Number: 1234567890
Beneficiary: Apex Holdings LLC

This is extremely time sensitive. Please confirm once the transfer is initiated. I'm in a board meeting and unavailable by phone, but respond to this email and I'll check between sessions.

Best regards,
Robert Johnson
CEO`
    },
    internetMessageHeaders: [
      { name: 'Authentication-Results', value: 'mx.company.com; spf=pass; dkim=pass; dmarc=fail' },
      { name: 'Received', value: 'from gmail.com by mx.company.com; ' + new Date().toUTCString() },
      { name: 'Reply-To', value: 'rjohnson.ceo2024@gmail.com' },
      { name: 'X-Mailer', value: 'Gmail' }
    ]
  };
}

function getDemoMalwareEmail() {
  return {
    id: 'demo-mal-001',
    subject: 'Invoice #INV-2024-8847 - Payment Due',
    from: { emailAddress: { address: 'accounting@legitimate-vendor.com', name: 'Accounts Payable' } },
    toRecipients: [{ emailAddress: { address: 'accounts@company.com' } }],
    receivedDateTime: new Date().toISOString(),
    hasAttachments: true,
    body: {
      contentType: 'text/plain',
      content: 'Please find attached invoice #INV-2024-8847 for services rendered. The document is password protected. Password: invoice2024\n\nPlease process payment at your earliest convenience.'
    },
    attachments: [
      {
        filename: 'Invoice_2024-8847.pdf.exe',
        contentType: 'application/x-msdownload',
        size: 245760,
        content: Buffer.from('MZ' + 'A'.repeat(100)).toString('base64')
      }
    ],
    internetMessageHeaders: [
      { name: 'Authentication-Results', value: 'mx.company.com; spf=fail; dkim=none; dmarc=fail' },
      { name: 'Received', value: 'from 195.123.45.67 by mx.company.com; ' + new Date().toUTCString() },
      { name: 'X-Mailer', value: 'Mass Mailer Pro' }
    ]
  };
}

function getDemoCleanEmail() {
  return {
    id: 'demo-clean-001',
    subject: 'Q3 Sales Report - Internal Distribution',
    from: { emailAddress: { address: 'reports@company.com', name: 'Reports System' } },
    toRecipients: [{ emailAddress: { address: 'management@company.com' } }],
    receivedDateTime: new Date().toISOString(),
    hasAttachments: false,
    body: {
      contentType: 'text/plain',
      content: 'Please find the Q3 sales report attached for review. Total revenue: $2.4M. Meeting scheduled for Thursday at 2pm.'
    },
    internetMessageHeaders: [
      { name: 'Authentication-Results', value: 'mx.company.com; spf=pass; dkim=pass; dmarc=pass' },
      { name: 'Received', value: 'from mail.company.com by mx.company.com; ' + new Date().toUTCString() }
    ]
  };
}

/**
 * GET /api/email-threat/health
 * Health check for ETI-AARE engine
 */
router.get('/health', asyncHandler(async (req, res) => {
  let engineStatus = 'ok';
  let details = {};
  try {
    const engine = getEngine(req);
    details = {
      detector_rules:  engine.detector?.getRules?.()?.length || 0,
      fingerprinter:   typeof engine.fingerprinter !== 'undefined',
      scorer:          typeof engine.scorer !== 'undefined',
      soar:            typeof engine.soar !== 'undefined',
      enrichment:      typeof engine.enricher !== 'undefined'
    };
  } catch (e) {
    engineStatus = 'degraded';
    details.error = e.message;
  }

  res.json({
    status:   engineStatus,
    healthy:  engineStatus === 'ok',
    success:  true,
    service:  'ETI-AARE Email Threat Intelligence Engine',
    version:  '2.0.0',
    timestamp: new Date().toISOString(),
    details
  });
}));

// ─── Error Handler ────────────────────────────────────────────────────────────
router.use((err, req, res, next) => {
  console.error('[ETI-AARE API Error]', err.message);
  res.status(500).json({ success: false, error: err.message || 'Internal server error' });
});

module.exports = router;
