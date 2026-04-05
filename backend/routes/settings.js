/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Platform Settings v5.1 (PRODUCTION)
 *  FILE: backend/routes/settings.js
 *
 *  Persists real platform configuration to Supabase.
 *  All settings are per-tenant and require ADMIN/SUPER_ADMIN role.
 *
 *  Endpoints:
 *  ──────────
 *  GET  /api/settings          — Load all settings for current tenant
 *  PUT  /api/settings          — Save/update settings for current tenant
 *  GET  /api/settings/:key     — Get a single setting value
 *  PUT  /api/settings/:key     — Set a single setting value
 *  POST /api/settings/test-api — Test an API key connection
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const axios  = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

/* ════════════════════════════════════════════════
   DEFAULTS — settings that ship with the platform
═══════════════════════════════════════════════ */
const DEFAULT_SETTINGS = {
  platform_name:       'Wadjet-Eye AI',
  platform_logo_url:   '',
  platform_theme:      'dark',
  default_timezone:    'UTC',
  session_timeout_min: 480,
  ingest_interval_min: 60,
  ingest_enabled:      true,
  feeds_enabled:       ['otx', 'abuseipdb', 'urlhaus', 'threatfox', 'malwarebazaar'],
  risk_score_alert_threshold:    70,
  critical_auto_case_threshold:  85,
  soar_auto_run:                 true,
  soar_human_approval_required:  false,
  ai_provider:        'openai',
  ai_model:           'gpt-4o',
  ai_enabled:         true,
  slack_webhook_url:   '',
  soar_webhook_url:    '',
  email_alerts_enabled: false,
  smtp_host:           '',
  smtp_port:           587,
  smtp_user:           '',
  smtp_from:           '',
  jira_url:            '',
  jira_project_key:    '',
  jira_api_token:      '',
  servicenow_url:      '',
  servicenow_user:     '',
  servicenow_token:    '',
  ioc_retention_days:   90,
  alert_retention_days: 365,
  log_retention_days:   30,
};

const REDACTED_KEYS = new Set([
  'jira_api_token', 'servicenow_token', 'smtp_pass',
]);

function redactSettings(settings) {
  const out = { ...settings };
  for (const key of REDACTED_KEYS) {
    if (key in out && out[key]) out[key] = '••••••••';
  }
  return out;
}

async function getSettings(tenantId) {
  const { data, error } = await supabaseAdmin
    .from('platform_settings')
    .select('settings')
    .eq('tenant_id', tenantId)
    .single();

  if (error || !data) return { ...DEFAULT_SETTINGS };
  return { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
}

async function saveSettings(tenantId, updates) {
  const current = await getSettings(tenantId);
  const merged  = { ...current, ...updates };

  const { error } = await supabaseAdmin
    .from('platform_settings')
    .upsert(
      { tenant_id: tenantId, settings: merged, updated_at: new Date().toISOString() },
      { onConflict: 'tenant_id' }
    );

  if (error) throw new Error(`Failed to save settings: ${error.message}`);
  return merged;
}

/* ════════════════════════════════════════════════
   ROUTES
═══════════════════════════════════════════════ */

router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const settings = await getSettings(req.user.tenant_id);
  res.json({ settings: redactSettings(settings) });
}));

router.put('/', verifyToken, requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const updates = req.body;
  if (!updates || typeof updates !== 'object') {
    return res.status(400).json({ error: 'Request body must be a JSON object' });
  }
  const allowedKeys = new Set(Object.keys(DEFAULT_SETTINGS));
  const filtered = {};
  for (const [k, v] of Object.entries(updates)) {
    if (allowedKeys.has(k)) filtered[k] = v;
  }
  const saved = await saveSettings(req.user.tenant_id, filtered);
  res.json({ success: true, settings: redactSettings(saved), updated_keys: Object.keys(filtered) });
}));

router.get('/:key', verifyToken, asyncHandler(async (req, res) => {
  const settings = await getSettings(req.user.tenant_id);
  const key = req.params.key;
  if (!(key in DEFAULT_SETTINGS)) {
    return res.status(404).json({ error: `Setting '${key}' not found` });
  }
  const value = REDACTED_KEYS.has(key) ? '••••••••' : settings[key];
  res.json({ key, value });
}));

router.put('/:key', verifyToken, requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const key   = req.params.key;
  const value = req.body?.value;
  if (!(key in DEFAULT_SETTINGS)) {
    return res.status(404).json({ error: `Setting '${key}' not found` });
  }
  if (value === undefined) {
    return res.status(400).json({ error: 'Missing "value" in request body' });
  }
  await saveSettings(req.user.tenant_id, { [key]: value });
  res.json({ success: true, key, value: REDACTED_KEYS.has(key) ? '••••••••' : value });
}));

router.post('/test-api', verifyToken, requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { service, api_key, url } = req.body;

  const tests = {
    async openai(key) {
      const r = await axios.get('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${key}` }, timeout: 8000
      }).catch(e => ({ data: null, error: e.message }));
      return r.data?.object === 'list'
        ? { ok: true, message: 'OpenAI API key valid' }
        : { ok: false, message: r.error || 'Invalid OpenAI API key' };
    },
    async gemini(key) {
      const r = await axios.get(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${key}`,
        { timeout: 8000 }
      ).catch(e => ({ data: null, error: e.message }));
      return r.data?.models?.length
        ? { ok: true, message: 'Gemini API key valid' }
        : { ok: false, message: r.error || 'Invalid Gemini API key' };
    },
    async virustotal(key) {
      const r = await axios.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', {
        headers: { 'x-apikey': key }, timeout: 8000
      }).catch(e => ({ data: null, error: e.message }));
      return r.data?.data
        ? { ok: true, message: 'VirusTotal API key valid' }
        : { ok: false, message: r.error || 'Invalid VirusTotal API key' };
    },
    async abuseipdb(key) {
      const r = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        headers: { Key: key, Accept: 'application/json' },
        params: { ipAddress: '8.8.8.8' }, timeout: 8000
      }).catch(e => ({ data: null, error: e.message }));
      return r.data?.data
        ? { ok: true, message: 'AbuseIPDB API key valid' }
        : { ok: false, message: r.error || 'Invalid AbuseIPDB API key' };
    },
    async shodan(key) {
      const r = await axios.get(`https://api.shodan.io/api-info?key=${key}`, { timeout: 8000 })
        .catch(e => ({ data: null, error: e.message }));
      return r.data?.query_credits !== undefined
        ? { ok: true, message: `Shodan valid — ${r.data.query_credits} credits remaining` }
        : { ok: false, message: r.error || 'Invalid Shodan API key' };
    },
    async slack(webhookUrl) {
      const r = await axios.post(webhookUrl, { text: '✅ Wadjet-Eye AI: Slack integration test successful.' }, { timeout: 8000 })
        .catch(e => ({ data: null, error: e.message }));
      return r.data === 'ok' || r.data
        ? { ok: true, message: 'Slack webhook working' }
        : { ok: false, message: r.error || 'Slack webhook failed' };
    },
  };

  const testFn = tests[service?.toLowerCase()];
  if (!testFn) {
    return res.status(400).json({ error: `Unknown service: ${service}`, available: Object.keys(tests) });
  }

  const result = await testFn(api_key || url).catch(err => ({ ok: false, message: err.message }));
  res.json({ service, ...result });
}));

module.exports = router;
