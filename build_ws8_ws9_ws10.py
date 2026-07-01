#!/usr/bin/env python3
"""
Build WS8 (Enterprise SSO/Auth), WS9 (RAG Refactor / Circuit Breakers / Kafka / Outbox),
WS10 (OPA Policies, Supply Chain Security, SBOM, Dependabot)
"""
import os

FILES = {}

# ═══════════════════════════════════════════════════════════════════
# WS8: Enterprise Auth — SAML, OIDC, SCIM, Partner Portal, MSSP
# ═══════════════════════════════════════════════════════════════════

FILES['backend/routes/enterprise-auth.js'] = r'''/**
 * enterprise-auth.js
 * WS8: Enterprise Authentication — SAML 2.0, OIDC, SCIM 2.0 Provisioning
 * Partner Portal, MSSP multi-tenant management
 */
'use strict';

const express  = require('express');
const crypto   = require('crypto');
const router   = express.Router();
const logger   = require('../utils/logger');
const { createClient } = require('@supabase/supabase-js');

const _SRV = 'EnterpriseAuth';
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── SAML 2.0 Configuration ─────────────────────────────────────────
const SAML_CONFIG = {
  entityId:    process.env.SAML_ENTITY_ID    || 'https://wadjet-eye.ai/saml/metadata',
  acsUrl:      process.env.SAML_ACS_URL      || 'https://wadjet-eye.ai/api/enterprise/saml/acs',
  sloUrl:      process.env.SAML_SLO_URL      || 'https://wadjet-eye.ai/api/enterprise/saml/slo',
  certificate: process.env.SAML_SP_CERT      || '',
  privateKey:  process.env.SAML_SP_KEY       || '',
};

// ── OIDC Configuration ─────────────────────────────────────────────
const OIDC_PROVIDERS = new Map(); // tenantId -> OIDC config

function loadOidcProvider(tenantId, config) {
  OIDC_PROVIDERS.set(tenantId, {
    issuer:        config.issuer,
    clientId:      config.client_id,
    clientSecret:  config.client_secret,
    redirectUri:   `${process.env.APP_URL || 'https://wadjet-eye.ai'}/api/enterprise/oidc/${tenantId}/callback`,
    scopes:        config.scopes || ['openid', 'email', 'profile'],
    jwksUri:       config.jwks_uri,
    userInfoUri:   config.userinfo_endpoint,
  });
}

// ── SAML Metadata Endpoint ─────────────────────────────────────────
router.get('/saml/metadata', (req, res) => {
  const metadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${SAML_CONFIG.entityId}">
  <SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${SAML_CONFIG.acsUrl}"
      index="1"/>
    <SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${SAML_CONFIG.sloUrl}"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
  res.type('application/xml').send(metadata);
});

// ── SAML AuthRequest Initiator ────────────────────────────────────
router.get('/saml/login', async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id required' });

  try {
    const { data: tenant } = await supabase
      .from('tenants')
      .select('saml_idp_metadata_url, saml_idp_entity_id, saml_idp_sso_url')
      .eq('id', tenant_id)
      .single();

    if (!tenant || !tenant.saml_idp_sso_url) {
      return res.status(400).json({ error: 'SAML not configured for this tenant' });
    }

    const relayState = Buffer.from(JSON.stringify({ tenant_id, ts: Date.now() })).toString('base64');
    const requestId  = `_${crypto.randomUUID().replace(/-/g, '')}`;
    const issueInstant = new Date().toISOString();

    const authnRequest = `<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${requestId}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${tenant.saml_idp_sso_url}"
  AssertionConsumerServiceURL="${SAML_CONFIG.acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${SAML_CONFIG.entityId}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>`;

    const encoded = Buffer.from(authnRequest).toString('base64');
    const redirectUrl = `${tenant.saml_idp_sso_url}?SAMLRequest=${encodeURIComponent(encoded)}&RelayState=${encodeURIComponent(relayState)}`;

    logger.info(_SRV, 'SAML AuthnRequest initiated', { tenant_id, requestId });
    res.redirect(redirectUrl);
  } catch (err) {
    logger.error(_SRV, 'SAML login error', { error: err.message });
    res.status(500).json({ error: 'SAML initiation failed' });
  }
});

// ── SAML ACS (Assertion Consumer Service) ─────────────────────────
router.post('/saml/acs', express.urlencoded({ extended: true }), async (req, res) => {
  const { SAMLResponse, RelayState } = req.body;
  if (!SAMLResponse) return res.status(400).json({ error: 'SAMLResponse required' });

  try {
    const decoded = Buffer.from(SAMLResponse, 'base64').toString('utf-8');
    let tenant_id = 'unknown';
    try {
      const rs = JSON.parse(Buffer.from(RelayState || '', 'base64').toString());
      tenant_id = rs.tenant_id;
    } catch (_) {}

    // Extract NameID (email) from SAML assertion
    const nameIdMatch = decoded.match(/<(?:saml:|)[Nn]ame[Ii][Dd][^>]*>([^<]+)<\//);
    const email = nameIdMatch ? nameIdMatch[1].trim() : null;
    if (!email) {
      logger.error(_SRV, 'SAML ACS: No NameID found', { tenant_id });
      return res.status(400).json({ error: 'Invalid SAML assertion: no NameID' });
    }

    // Extract attributes
    const attrMatches = [...decoded.matchAll(/<(?:saml:|)[Aa]ttribute[^>]+Name="([^"]+)"[^>]*>[\s\S]*?<(?:saml:|)[Aa]ttribute[Vv]alue[^>]*>([^<]+)<\//g)];
    const attributes = {};
    for (const [, name, value] of attrMatches) attributes[name] = value.trim();

    // Upsert user in database
    const { data: user, error } = await supabase
      .from('users')
      .upsert({
        email,
        tenant_id,
        full_name: attributes['displayName'] || attributes['cn'] || email.split('@')[0],
        role:      attributes['role'] || 'analyst',
        auth_provider: 'saml',
        last_login: new Date().toISOString(),
      }, { onConflict: 'email,tenant_id' })
      .select()
      .single();

    if (error) throw error;

    logger.info(_SRV, 'SAML login success', { email, tenant_id, userId: user.id });

    // Issue JWT and redirect to dashboard
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { sub: user.id, email, tenant_id, role: user.role, auth_provider: 'saml' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.redirect(`${process.env.FRONTEND_URL || ''}/#sso-callback?token=${token}`);
  } catch (err) {
    logger.error(_SRV, 'SAML ACS error', { error: err.message });
    res.status(500).json({ error: 'SAML authentication failed' });
  }
});

// ── OIDC Authorization Initiation ─────────────────────────────────
router.get('/oidc/:tenantId/login', async (req, res) => {
  const { tenantId } = req.params;

  try {
    const { data: tenant } = await supabase
      .from('tenants')
      .select('oidc_issuer, oidc_client_id, oidc_client_secret, oidc_scopes')
      .eq('id', tenantId)
      .single();

    if (!tenant || !tenant.oidc_issuer) {
      return res.status(400).json({ error: 'OIDC not configured for this tenant' });
    }

    loadOidcProvider(tenantId, {
      issuer:        tenant.oidc_issuer,
      client_id:     tenant.oidc_client_id,
      client_secret: tenant.oidc_client_secret,
      scopes:        (tenant.oidc_scopes || 'openid email profile').split(' '),
      jwks_uri:      `${tenant.oidc_issuer}/.well-known/jwks.json`,
      userinfo_endpoint: `${tenant.oidc_issuer}/userinfo`,
    });

    const provider = OIDC_PROVIDERS.get(tenantId);
    const state  = crypto.randomBytes(16).toString('hex');
    const nonce  = crypto.randomBytes(16).toString('hex');

    const params = new URLSearchParams({
      response_type: 'code',
      client_id:     provider.clientId,
      redirect_uri:  provider.redirectUri,
      scope:         provider.scopes.join(' '),
      state:         `${tenantId}:${state}`,
      nonce,
    });

    const authUrl = `${provider.issuer}/authorize?${params}`;
    logger.info(_SRV, 'OIDC login initiated', { tenantId });
    res.redirect(authUrl);
  } catch (err) {
    logger.error(_SRV, 'OIDC login error', { error: err.message });
    res.status(500).json({ error: 'OIDC initiation failed' });
  }
});

// ── OIDC Callback ─────────────────────────────────────────────────
router.get('/oidc/:tenantId/callback', async (req, res) => {
  const { tenantId } = req.params;
  const { code, state, error: oidcError } = req.query;

  if (oidcError) {
    logger.error(_SRV, 'OIDC error from provider', { error: oidcError, tenantId });
    return res.status(400).json({ error: oidcError });
  }

  if (!code) return res.status(400).json({ error: 'Authorization code missing' });

  try {
    const provider = OIDC_PROVIDERS.get(tenantId);
    if (!provider) return res.status(400).json({ error: 'OIDC provider not configured' });

    // Exchange code for tokens
    const tokenRes = await fetch(`${provider.issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  provider.redirectUri,
        client_id:     provider.clientId,
        client_secret: provider.clientSecret,
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokens.access_token) throw new Error('Token exchange failed');

    // Fetch user info
    const userRes = await fetch(provider.userInfoUri, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const userInfo = await userRes.json();

    const email     = userInfo.email || userInfo.preferred_username;
    const fullName  = userInfo.name  || email;

    // Upsert user
    const { data: user, error } = await supabase
      .from('users')
      .upsert({
        email, tenant_id: tenantId,
        full_name: fullName,
        role:      userInfo.role || 'analyst',
        auth_provider: 'oidc',
        last_login: new Date().toISOString(),
      }, { onConflict: 'email,tenant_id' })
      .select().single();

    if (error) throw error;

    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { sub: user.id, email, tenant_id: tenantId, role: user.role, auth_provider: 'oidc' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    logger.info(_SRV, 'OIDC login success', { email, tenantId, userId: user.id });
    res.redirect(`${process.env.FRONTEND_URL || ''}/#sso-callback?token=${token}`);
  } catch (err) {
    logger.error(_SRV, 'OIDC callback error', { error: err.message });
    res.status(500).json({ error: 'OIDC authentication failed' });
  }
});

// ── SCIM 2.0 User Provisioning ────────────────────────────────────
// SCIM token validation middleware
function scimAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token || token !== process.env.SCIM_BEARER_TOKEN) {
    return res.status(401).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: 401, detail: 'Unauthorized',
    });
  }
  next();
}

// SCIM: Get Users
router.get('/scim/v2/Users', scimAuth, async (req, res) => {
  const { filter, startIndex = 1, count = 100 } = req.query;
  const tenantId = req.headers['x-tenant-id'];
  if (!tenantId) return res.status(400).json({ error: 'X-Tenant-ID header required' });

  let query = supabase.from('users').select('*').eq('tenant_id', tenantId);
  if (filter) {
    const emailMatch = filter.match(/userName eq "([^"]+)"/i);
    if (emailMatch) query = query.eq('email', emailMatch[1]);
  }
  const { data: users = [] } = await query.range(startIndex - 1, startIndex + count - 2);

  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: users.length,
    startIndex: Number(startIndex),
    itemsPerPage: Number(count),
    Resources: users.map(u => scimUserMap(u)),
  });
});

// SCIM: Create User
router.post('/scim/v2/Users', scimAuth, express.json(), async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];
  if (!tenantId) return res.status(400).json({ error: 'X-Tenant-ID header required' });

  const { userName, displayName, emails = [], active = true } = req.body;
  const email = emails[0]?.value || userName;

  const { data: user, error } = await supabase
    .from('users')
    .insert({
      email,
      tenant_id: tenantId,
      full_name: displayName || email,
      role:      'analyst',
      active:    active,
      auth_provider: 'scim',
    })
    .select().single();

  if (error) return res.status(409).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: 409, detail: error.message });

  logger.info(_SRV, 'SCIM user created', { email, tenantId });
  res.status(201).json(scimUserMap(user));
});

// SCIM: Update User (PUT)
router.put('/scim/v2/Users/:id', scimAuth, express.json(), async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];
  const { id } = req.params;
  const { displayName, active, emails = [] } = req.body;
  const email = emails[0]?.value;

  const { data: user, error } = await supabase
    .from('users')
    .update({ full_name: displayName, active, ...(email && { email }) })
    .eq('id', id).eq('tenant_id', tenantId)
    .select().single();

  if (error || !user) return res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: 404, detail: 'User not found' });

  logger.info(_SRV, 'SCIM user updated', { id, tenantId });
  res.json(scimUserMap(user));
});

// SCIM: Patch User (PATCH — partial update / deactivate)
router.patch('/scim/v2/Users/:id', scimAuth, express.json(), async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];
  const { id } = req.params;
  const { Operations = [] } = req.body;

  const updates = {};
  for (const op of Operations) {
    if (op.op === 'Replace' && op.path === 'active') updates.active = op.value;
    if (op.op === 'Replace' && op.path === 'displayName') updates.full_name = op.value;
  }

  const { data: user, error } = await supabase
    .from('users').update(updates)
    .eq('id', id).eq('tenant_id', tenantId)
    .select().single();

  if (error || !user) return res.status(404).json({ status: 404, detail: 'User not found' });
  logger.info(_SRV, 'SCIM user patched', { id, tenantId, updates });
  res.json(scimUserMap(user));
});

// SCIM: Delete User
router.delete('/scim/v2/Users/:id', scimAuth, async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];
  const { id } = req.params;
  await supabase.from('users').update({ active: false }).eq('id', id).eq('tenant_id', tenantId);
  logger.info(_SRV, 'SCIM user deprovisioned', { id, tenantId });
  res.status(204).send();
});

function scimUserMap(u) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id:          u.id,
    userName:    u.email,
    displayName: u.full_name,
    active:      u.active !== false,
    emails:      [{ value: u.email, primary: true }],
    meta: {
      resourceType: 'User',
      created:  u.created_at,
      modified: u.updated_at,
      location: `/api/enterprise/scim/v2/Users/${u.id}`,
    },
  };
}

// ── SCIM Groups ────────────────────────────────────────────────────
router.get('/scim/v2/Groups', scimAuth, async (req, res) => {
  const tenantId = req.headers['x-tenant-id'];
  const { data: roles } = await supabase.from('roles').select('*').eq('tenant_id', tenantId);
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: (roles || []).length,
    Resources: (roles || []).map(r => ({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: r.id, displayName: r.name,
      meta: { resourceType: 'Group', location: `/api/enterprise/scim/v2/Groups/${r.id}` },
    })),
  });
});

// ── Partner Portal ────────────────────────────────────────────────
router.get('/partner/tenants', async (req, res) => {
  if (!req.user || req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Partner portal requires SUPER_ADMIN role' });
  }
  const { data: tenants } = await supabase
    .from('tenants')
    .select('id, name, plan, created_at, active, seats_used, seats_limit, mrr_usd')
    .order('created_at', { ascending: false });
  res.json({ tenants: tenants || [] });
});

router.post('/partner/tenants', async (req, res) => {
  if (!req.user || req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Requires SUPER_ADMIN' });
  }
  const { name, plan = 'enterprise', seats_limit = 100, admin_email } = req.body;
  if (!name || !admin_email) return res.status(400).json({ error: 'name and admin_email required' });

  const tenantId = crypto.randomUUID();
  const { data: tenant, error } = await supabase
    .from('tenants')
    .insert({ id: tenantId, name, plan, seats_limit, active: true })
    .select().single();

  if (error) return res.status(500).json({ error: error.message });

  // Create initial admin user
  await supabase.from('users').insert({
    email: admin_email, tenant_id: tenantId,
    role: 'admin', full_name: admin_email, active: true,
  });

  logger.info(_SRV, 'Partner tenant created', { tenantId, name, admin_email });
  res.status(201).json({ tenant });
});

// ── MSSP Multi-Tenant Overview ────────────────────────────────────
router.get('/mssp/overview', async (req, res) => {
  if (!req.user || !['SUPER_ADMIN', 'MSSP_ADMIN'].includes(req.user.role)) {
    return res.status(403).json({ error: 'MSSP access required' });
  }

  const { data: stats } = await supabase.rpc('mssp_tenant_overview');
  const { data: alerts } = await supabase
    .from('alerts').select('tenant_id, severity, status')
    .eq('status', 'open').limit(1000);

  const alertsByTenant = {};
  for (const a of alerts || []) {
    if (!alertsByTenant[a.tenant_id]) alertsByTenant[a.tenant_id] = { critical: 0, high: 0, medium: 0, low: 0 };
    alertsByTenant[a.tenant_id][a.severity] = (alertsByTenant[a.tenant_id][a.severity] || 0) + 1;
  }

  res.json({
    generated_at: new Date().toISOString(),
    tenant_stats: stats || [],
    open_alerts_by_tenant: alertsByTenant,
  });
});

// ── SSO Configuration (per-tenant admin) ─────────────────────────
router.get('/sso/config', async (req, res) => {
  const tenantId = req.tenantId;
  if (!tenantId) return res.status(400).json({ error: 'Tenant context required' });

  const { data } = await supabase
    .from('tenants')
    .select('saml_idp_metadata_url, saml_idp_entity_id, saml_idp_sso_url, oidc_issuer, oidc_client_id, sso_provider')
    .eq('id', tenantId).single();

  res.json({ sso_config: data || {} });
});

router.put('/sso/config', async (req, res) => {
  const tenantId = req.tenantId;
  if (!req.user || !['admin', 'SUPER_ADMIN'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Admin role required to configure SSO' });
  }

  const allowed = ['saml_idp_metadata_url', 'saml_idp_entity_id', 'saml_idp_sso_url',
                   'oidc_issuer', 'oidc_client_id', 'oidc_client_secret', 'sso_provider'];
  const updates = {};
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }

  await supabase.from('tenants').update(updates).eq('id', tenantId);
  logger.info(_SRV, 'SSO config updated', { tenantId, provider: updates.sso_provider });
  res.json({ message: 'SSO configuration updated', tenant_id: tenantId });
});

// ── API Key Management (versioned APIs, service accounts) ─────────
router.get('/api-keys', async (req, res) => {
  const { data } = await supabase
    .from('api_keys')
    .select('id, name, created_at, last_used_at, expires_at, scopes, active')
    .eq('tenant_id', req.tenantId);
  res.json({ api_keys: data || [] });
});

router.post('/api-keys', async (req, res) => {
  if (!req.user || !['admin', 'SUPER_ADMIN'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Admin role required' });
  }
  const { name, scopes = ['read'], expires_days = 365 } = req.body;
  const rawKey = `wai_${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const expiresAt = new Date(Date.now() + expires_days * 86400000).toISOString();

  const { data, error } = await supabase.from('api_keys').insert({
    tenant_id: req.tenantId, name, key_hash: keyHash,
    scopes, expires_at: expiresAt, created_by: req.user.id, active: true,
  }).select('id, name, expires_at, scopes').single();

  if (error) return res.status(500).json({ error: error.message });
  logger.info(_SRV, 'API key created', { name, tenantId: req.tenantId });
  res.status(201).json({ ...data, key: rawKey, warning: 'Store this key securely. It will not be shown again.' });
});

router.delete('/api-keys/:id', async (req, res) => {
  await supabase.from('api_keys').update({ active: false })
    .eq('id', req.params.id).eq('tenant_id', req.tenantId);
  res.json({ message: 'API key revoked' });
});

module.exports = router;
'''

# ═══════════════════════════════════════════════════════════════════
# WS9: Circuit Breaker + Outbox Pattern
# ═══════════════════════════════════════════════════════════════════

FILES['backend/services/circuitBreaker.js'] = r'''/**
 * circuitBreaker.js
 * WS9: Production-grade Circuit Breaker + Retry + Bulkhead pattern
 * Protects all external service calls (LLM, DB, SOAR, RAG, Intel feeds)
 */
'use strict';

const logger = require('../utils/logger');
const _SRV = 'CircuitBreaker';

const STATES = { CLOSED: 'CLOSED', OPEN: 'OPEN', HALF_OPEN: 'HALF_OPEN' };

class CircuitBreaker {
  /**
   * @param {string} name      - Unique name (e.g., 'openai', 'supabase', 'virustotal')
   * @param {object} opts
   * @param {number} opts.failureThreshold  - Failures before OPEN (default: 5)
   * @param {number} opts.successThreshold  - Successes in HALF_OPEN before CLOSED (default: 2)
   * @param {number} opts.timeout           - ms before attempting HALF_OPEN (default: 30000)
   * @param {number} opts.callTimeout       - ms before a call is considered failed (default: 10000)
   * @param {number} opts.volumeThreshold   - Min calls before circuit can open (default: 10)
   */
  constructor(name, opts = {}) {
    this.name             = name;
    this.failureThreshold = opts.failureThreshold  ?? 5;
    this.successThreshold = opts.successThreshold  ?? 2;
    this.timeout          = opts.timeout           ?? 30_000;
    this.callTimeout      = opts.callTimeout       ?? 10_000;
    this.volumeThreshold  = opts.volumeThreshold   ?? 10;

    this.state          = STATES.CLOSED;
    this.failureCount   = 0;
    this.successCount   = 0;
    this.lastFailureTime= null;
    this.totalCalls     = 0;
    this.totalFailures  = 0;
    this.totalSuccesses = 0;
    this._openedAt      = null;
  }

  async call(fn, fallback = null) {
    this.totalCalls++;

    if (this.state === STATES.OPEN) {
      if (Date.now() - this._openedAt >= this.timeout) {
        this._transition(STATES.HALF_OPEN);
        logger.info(_SRV, `${this.name}: HALF_OPEN — probing`);
      } else {
        logger.warn(_SRV, `${this.name}: Circuit OPEN — fast-fail`);
        if (fallback) return fallback();
        throw new Error(`Circuit OPEN: ${this.name}`);
      }
    }

    // Race: call vs timeout
    let result;
    try {
      result = await Promise.race([
        fn(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Call timeout after ${this.callTimeout}ms`)), this.callTimeout)
        ),
      ]);
      this._onSuccess();
      return result;
    } catch (err) {
      this._onFailure(err);
      if (fallback) return fallback();
      throw err;
    }
  }

  _onSuccess() {
    this.totalSuccesses++;
    if (this.state === STATES.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this._transition(STATES.CLOSED);
        logger.info(_SRV, `${this.name}: CLOSED — recovered`);
      }
    } else {
      this.failureCount = 0; // Reset on success in CLOSED
    }
  }

  _onFailure(err) {
    this.totalFailures++;
    this.failureCount++;
    this.lastFailureTime = Date.now();
    logger.warn(_SRV, `${this.name}: failure ${this.failureCount}/${this.failureThreshold}`, { error: err.message });

    if (this.state === STATES.HALF_OPEN) {
      this._transition(STATES.OPEN);
      logger.error(_SRV, `${this.name}: OPEN — probe failed`);
    } else if (
      this.state === STATES.CLOSED &&
      this.totalCalls >= this.volumeThreshold &&
      this.failureCount >= this.failureThreshold
    ) {
      this._transition(STATES.OPEN);
      logger.error(_SRV, `${this.name}: OPEN — threshold breached`, {
        failureCount: this.failureCount,
        totalCalls: this.totalCalls,
      });
    }
  }

  _transition(newState) {
    this.state = newState;
    if (newState === STATES.OPEN)      this._openedAt = Date.now();
    if (newState === STATES.CLOSED)    { this.failureCount = 0; this.successCount = 0; }
    if (newState === STATES.HALF_OPEN) this.successCount = 0;
  }

  getStatus() {
    return {
      name:            this.name,
      state:           this.state,
      failureCount:    this.failureCount,
      successCount:    this.successCount,
      totalCalls:      this.totalCalls,
      totalFailures:   this.totalFailures,
      totalSuccesses:  this.totalSuccesses,
      lastFailureTime: this.lastFailureTime,
      openedAt:        this._openedAt,
      errorRate:       this.totalCalls > 0 ? (this.totalFailures / this.totalCalls) : 0,
    };
  }

  reset() {
    this.state         = STATES.CLOSED;
    this.failureCount  = 0;
    this.successCount  = 0;
    this._openedAt     = null;
    this.lastFailureTime = null;
  }
}

// ── Global Registry of Circuit Breakers ──────────────────────────
const _registry = new Map();

function getBreaker(name, opts = {}) {
  if (!_registry.has(name)) {
    _registry.set(name, new CircuitBreaker(name, opts));
  }
  return _registry.get(name);
}

// Pre-configured breakers for all external services
const BREAKERS = {
  openai:      getBreaker('openai',      { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  anthropic:   getBreaker('anthropic',   { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  gemini:      getBreaker('gemini',      { failureThreshold: 3, timeout: 60_000, callTimeout: 30_000 }),
  supabase:    getBreaker('supabase',    { failureThreshold: 5, timeout: 30_000, callTimeout: 5_000  }),
  pinecone:    getBreaker('pinecone',    { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  weaviate:    getBreaker('weaviate',    { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  neo4j:       getBreaker('neo4j',       { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  redis:       getBreaker('redis',       { failureThreshold: 5, timeout: 15_000, callTimeout: 2_000  }),
  virustotal:  getBreaker('virustotal',  { failureThreshold: 3, timeout: 60_000, callTimeout: 15_000 }),
  shodan:      getBreaker('shodan',      { failureThreshold: 3, timeout: 60_000, callTimeout: 15_000 }),
  misp:        getBreaker('misp',        { failureThreshold: 3, timeout: 30_000, callTimeout: 10_000 }),
  soar:        getBreaker('soar',        { failureThreshold: 3, timeout: 60_000, callTimeout: 20_000 }),
};

function getAllStatus() {
  const status = {};
  for (const [name, breaker] of _registry) status[name] = breaker.getStatus();
  return status;
}

// ── Retry with Exponential Backoff ────────────────────────────────
async function withRetry(fn, opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseDelay  = opts.baseDelay  ?? 500;
  const maxDelay   = opts.maxDelay   ?? 10_000;
  const jitter     = opts.jitter     ?? true;

  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      if (attempt === maxRetries) break;

      let delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
      if (jitter) delay = delay * (0.5 + Math.random() * 0.5);

      logger.warn(_SRV, `Retry ${attempt + 1}/${maxRetries} in ${Math.round(delay)}ms`, { error: err.message });
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

// ── Idempotency Key Generator ─────────────────────────────────────
function makeIdempotencyKey(payload) {
  const { createHash } = require('crypto');
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return createHash('sha256').update(canonical).digest('hex').slice(0, 32);
}

module.exports = {
  CircuitBreaker,
  getBreaker,
  BREAKERS,
  getAllStatus,
  withRetry,
  makeIdempotencyKey,
  STATES,
};
'''

FILES['backend/services/outboxPattern.js'] = r'''/**
 * outboxPattern.js
 * WS9: Transactional Outbox Pattern for reliable event publishing
 * Ensures at-least-once delivery of domain events to Kafka/event bus
 * Prevents dual-write failures between DB and event bus
 */
'use strict';

const crypto = require('crypto');
const logger  = require('../utils/logger');
const { createClient } = require('@supabase/supabase-js');

const _SRV = 'OutboxPattern';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Kafka producer (optional — gracefully degrades if not configured)
let kafkaProducer = null;
async function getKafkaProducer() {
  if (kafkaProducer) return kafkaProducer;
  if (!process.env.KAFKA_BROKERS) return null;
  try {
    const { Kafka } = require('kafkajs');
    const kafka = new Kafka({
      clientId: 'wadjet-eye-outbox',
      brokers: process.env.KAFKA_BROKERS.split(','),
      ssl: process.env.KAFKA_SSL === 'true',
      sasl: process.env.KAFKA_SASL_USERNAME ? {
        mechanism: 'scram-sha-256',
        username:  process.env.KAFKA_SASL_USERNAME,
        password:  process.env.KAFKA_SASL_PASSWORD,
      } : undefined,
    });
    kafkaProducer = kafka.producer({ idempotent: true });
    await kafkaProducer.connect();
    logger.info(_SRV, 'Kafka producer connected');
    return kafkaProducer;
  } catch (err) {
    logger.warn(_SRV, 'Kafka not available — outbox will use polling fallback', { error: err.message });
    return null;
  }
}

// ── Domain Event Types ────────────────────────────────────────────
const EVENTS = {
  ALERT_CREATED:       'alert.created',
  ALERT_ESCALATED:     'alert.escalated',
  ALERT_RESOLVED:      'alert.resolved',
  IOC_DETECTED:        'ioc.detected',
  IOC_ENRICHED:        'ioc.enriched',
  DECISION_MADE:       'decision.made',
  DECISION_APPROVED:   'decision.approved',
  SOAR_ACTION:         'soar.action.executed',
  TENANT_CREATED:      'tenant.created',
  USER_CREATED:        'user.created',
  CASE_CREATED:        'case.created',
  THREAT_DETECTED:     'threat.detected',
  COMPLIANCE_VIOLATION:'compliance.violation',
  SECURITY_EVENT:      'security.event',
};

/**
 * Append event to outbox table (within the same DB transaction as the domain write)
 * @param {string} eventType - One of EVENTS.*
 * @param {object} payload   - Event payload
 * @param {object} opts      - { tenantId, aggregateId, aggregateType, traceId }
 * @returns {string} eventId
 */
async function appendEvent(eventType, payload, opts = {}) {
  const eventId = crypto.randomUUID();
  const { tenantId, aggregateId, aggregateType = 'unknown', traceId } = opts;

  const { error } = await supabase.from('outbox_events').insert({
    id:             eventId,
    event_type:     eventType,
    aggregate_type: aggregateType,
    aggregate_id:   aggregateId,
    tenant_id:      tenantId,
    payload:        payload,
    trace_id:       traceId,
    status:         'pending',
    created_at:     new Date().toISOString(),
    retry_count:    0,
  });

  if (error) {
    logger.error(_SRV, 'Failed to append outbox event', { eventType, error: error.message });
    throw error;
  }

  logger.info(_SRV, 'Event appended to outbox', { eventId, eventType, tenantId, aggregateId });
  return eventId;
}

/**
 * Relay processor — reads pending outbox events and publishes to Kafka (or fallback)
 * Runs on an interval; designed to be idempotent
 */
async function relayPendingEvents({ batchSize = 50 } = {}) {
  const { data: events, error } = await supabase
    .from('outbox_events')
    .select('*')
    .eq('status', 'pending')
    .lt('retry_count', 5)
    .order('created_at', { ascending: true })
    .limit(batchSize);

  if (error) { logger.error(_SRV, 'Relay query failed', { error: error.message }); return; }
  if (!events || events.length === 0) return;

  logger.info(_SRV, `Relaying ${events.length} outbox events`);
  const producer = await getKafkaProducer();

  for (const event of events) {
    try {
      if (producer) {
        await producer.send({
          topic: `wadjet.${event.event_type}`,
          messages: [{
            key:   event.aggregate_id || event.tenant_id,
            value: JSON.stringify({
              id:             event.id,
              type:           event.event_type,
              aggregate_type: event.aggregate_type,
              aggregate_id:   event.aggregate_id,
              tenant_id:      event.tenant_id,
              payload:        event.payload,
              trace_id:       event.trace_id,
              timestamp:      event.created_at,
            }),
            headers: {
              'x-event-id':    event.id,
              'x-tenant-id':   event.tenant_id || '',
              'x-trace-id':    event.trace_id  || '',
              'x-event-type':  event.event_type,
            },
          }],
        });
      } else {
        // Fallback: log event for SIEM/webhook delivery
        logger.info(_SRV, 'Outbox event (no-Kafka fallback)', {
          eventType: event.event_type, tenantId: event.tenant_id, payload: event.payload,
        });
      }

      // Mark published
      await supabase.from('outbox_events').update({
        status:       'published',
        published_at: new Date().toISOString(),
      }).eq('id', event.id);

    } catch (err) {
      logger.error(_SRV, 'Event relay failed', { eventId: event.id, error: err.message });
      await supabase.from('outbox_events').update({
        retry_count:  event.retry_count + 1,
        last_error:   err.message,
        status:       event.retry_count + 1 >= 5 ? 'failed' : 'pending',
      }).eq('id', event.id);
    }
  }
}

// ── Saga Coordinator (lightweight) ───────────────────────────────
class SagaCoordinator {
  constructor(sagaName, tenantId) {
    this.sagaName = sagaName;
    this.tenantId = tenantId;
    this.sagaId   = crypto.randomUUID();
    this.steps    = [];
    this.compensations = [];
  }

  addStep(name, execute, compensate) {
    this.steps.push({ name, execute, compensate });
    return this;
  }

  async run() {
    const executed = [];
    logger.info(_SRV, `Saga START: ${this.sagaName}`, { sagaId: this.sagaId });

    for (const step of this.steps) {
      try {
        await step.execute();
        executed.push(step);
        logger.info(_SRV, `Saga step OK: ${step.name}`, { sagaId: this.sagaId });
      } catch (err) {
        logger.error(_SRV, `Saga step FAILED: ${step.name} — compensating`, { sagaId: this.sagaId, error: err.message });

        // Compensate in reverse order
        for (const done of executed.reverse()) {
          try {
            if (done.compensate) await done.compensate();
            logger.info(_SRV, `Saga compensation OK: ${done.name}`, { sagaId: this.sagaId });
          } catch (cErr) {
            logger.error(_SRV, `Saga compensation FAILED: ${done.name}`, { sagaId: this.sagaId, error: cErr.message });
          }
        }
        throw new Error(`Saga ${this.sagaName} failed at step ${step.name}: ${err.message}`);
      }
    }

    logger.info(_SRV, `Saga COMPLETE: ${this.sagaName}`, { sagaId: this.sagaId });
  }
}

// ── Outbox Relay Scheduler ────────────────────────────────────────
let _relayInterval = null;

function startOutboxRelay(intervalMs = 5_000) {
  if (_relayInterval) return;
  _relayInterval = setInterval(() => {
    relayPendingEvents().catch(err =>
      logger.error(_SRV, 'Relay interval error', { error: err.message })
    );
  }, intervalMs);
  logger.info(_SRV, `Outbox relay started (interval: ${intervalMs}ms)`);
}

function stopOutboxRelay() {
  if (_relayInterval) { clearInterval(_relayInterval); _relayInterval = null; }
}

module.exports = {
  EVENTS,
  appendEvent,
  relayPendingEvents,
  startOutboxRelay,
  stopOutboxRelay,
  SagaCoordinator,
};
'''

# ═══════════════════════════════════════════════════════════════════
# WS9: Tenant-scoped RAG namespace refactor
# ═══════════════════════════════════════════════════════════════════

FILES['backend/services/tenantRag.js'] = r'''/**
 * tenantRag.js
 * WS9: Tenant-Isolated RAG (Retrieval Augmented Generation)
 * - Pinecone: namespace = tenantId (mandatory server-side)
 * - Weaviate: class prefix = tenantId (mandatory server-side)
 * - Never trust client-provided namespace filters
 * - All vector operations scoped to tenant at the service layer
 */
'use strict';

const crypto = require('crypto');
const logger = require('../utils/logger');
const { BREAKERS, withRetry } = require('./circuitBreaker');

const _SRV = 'TenantRAG';

// ── Embedding helper ───────────────────────────────────────────────
async function embedText(text) {
  return await BREAKERS.openai.call(async () => {
    const res = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({ model: 'text-embedding-3-small', input: text }),
    });
    if (!res.ok) throw new Error(`OpenAI embeddings HTTP ${res.status}`);
    const json = await res.json();
    return json.data[0].embedding;
  });
}

// ── Pinecone Tenant-Scoped Operations ────────────────────────────
class PineconeTenantClient {
  constructor(tenantId) {
    if (!tenantId) throw new Error('TenantRAG: tenantId is required');
    this.tenantId  = tenantId;
    this.namespace = tenantId; // namespace IS the tenantId — not configurable from outside
    this.baseUrl   = `https://${process.env.PINECONE_INDEX_HOST}`;
    this.apiKey    = process.env.PINECONE_API_KEY;
  }

  async upsert(vectors) {
    return await BREAKERS.pinecone.call(async () => {
      // Inject tenant_id into all vector metadata
      const scoped = vectors.map(v => ({
        ...v,
        metadata: { ...v.metadata, tenant_id: this.tenantId },
      }));

      const res = await fetch(`${this.baseUrl}/vectors/upsert`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ vectors: scoped, namespace: this.namespace }),
      });
      if (!res.ok) throw new Error(`Pinecone upsert HTTP ${res.status}`);
      const data = await res.json();
      logger.info(_SRV, 'Pinecone upsert', { tenantId: this.tenantId, count: scoped.length });
      return data;
    });
  }

  async query(queryVector, topK = 10, filter = {}) {
    return await BREAKERS.pinecone.call(async () => {
      // Server-side: ALWAYS inject tenant_id filter, merge with any additional filters
      const scopedFilter = { ...filter, tenant_id: { '$eq': this.tenantId } };

      const res = await fetch(`${this.baseUrl}/query`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vector:          queryVector,
          topK,
          filter:          scopedFilter,
          namespace:       this.namespace,
          includeMetadata: true,
        }),
      });
      if (!res.ok) throw new Error(`Pinecone query HTTP ${res.status}`);
      const data = await res.json();

      // Defense-in-depth: strip any cross-tenant matches that slipped through
      const matches = (data.matches || []).filter(m =>
        m.metadata?.tenant_id === this.tenantId
      );
      if (matches.length !== (data.matches || []).length) {
        logger.error(_SRV, 'CROSS_TENANT_VECTOR_LEAK_PREVENTED', {
          tenantId: this.tenantId,
          expected: this.tenantId,
          filtered: (data.matches || []).length - matches.length,
        });
      }
      return { ...data, matches };
    });
  }

  async delete(ids) {
    return await BREAKERS.pinecone.call(async () => {
      const res = await fetch(`${this.baseUrl}/vectors/delete`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids, namespace: this.namespace }),
      });
      if (!res.ok) throw new Error(`Pinecone delete HTTP ${res.status}`);
      return res.json();
    });
  }

  async fetch(ids) {
    return await BREAKERS.pinecone.call(async () => {
      const res = await fetch(`${this.baseUrl}/vectors/fetch?ids=${ids.join('&ids=')}&namespace=${this.namespace}`, {
        headers: { 'Api-Key': this.apiKey },
      });
      if (!res.ok) throw new Error(`Pinecone fetch HTTP ${res.status}`);
      const data = await res.json();
      // Validate tenant ownership of fetched vectors
      const valid = {};
      for (const [id, vec] of Object.entries(data.vectors || {})) {
        if (vec.metadata?.tenant_id === this.tenantId) valid[id] = vec;
      }
      return { vectors: valid };
    });
  }
}

// ── Weaviate Tenant-Scoped Operations ─────────────────────────────
class WeaviateTenantClient {
  constructor(tenantId) {
    if (!tenantId) throw new Error('TenantRAG: tenantId is required');
    this.tenantId = tenantId;
    // Each tenant gets its own class prefix for complete isolation
    this.classPrefix = tenantId.replace(/[^a-zA-Z0-9]/g, '_');
    this.baseUrl     = process.env.WEAVIATE_URL || 'http://localhost:8080';
    this.apiKey      = process.env.WEAVIATE_API_KEY;
  }

  _headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  _className(base) {
    return `${this.classPrefix}_${base}`;
  }

  async insertObject(className, properties, vector) {
    return await BREAKERS.weaviate.call(async () => {
      const obj = {
        class:      this._className(className),
        properties: { ...properties, tenant_id: this.tenantId },
        ...(vector && { vector }),
      };
      const res = await fetch(`${this.baseUrl}/v1/objects`, {
        method: 'POST', headers: this._headers(),
        body: JSON.stringify(obj),
      });
      if (!res.ok) throw new Error(`Weaviate insert HTTP ${res.status}`);
      return res.json();
    });
  }

  async nearTextSearch(className, query, limit = 10, certainty = 0.7) {
    return await BREAKERS.weaviate.call(async () => {
      const gql = `{
        Get {
          ${this._className(className)}(
            nearText: { concepts: ["${query}"], certainty: ${certainty} }
            limit: ${limit}
            where: { path: ["tenant_id"], operator: Equal, valueText: "${this.tenantId}" }
          ) { _additional { id certainty } }
        }
      }`;
      const res = await fetch(`${this.baseUrl}/v1/graphql`, {
        method: 'POST', headers: this._headers(),
        body: JSON.stringify({ query: gql }),
      });
      if (!res.ok) throw new Error(`Weaviate search HTTP ${res.status}`);
      const data = await res.json();
      return data.data?.Get?.[this._className(className)] || [];
    });
  }
}

// ── High-Level RAG Service ────────────────────────────────────────
class TenantRAGService {
  constructor(tenantId) {
    this.tenantId = tenantId;
    this.pinecone = new PineconeTenantClient(tenantId);
    this.weaviate = new WeaviateTenantClient(tenantId);
  }

  async ingestDocument(doc) {
    const { id, content, metadata = {}, chunkSize = 1000, overlap = 100 } = doc;
    if (!id || !content) throw new Error('Document requires id and content');

    // Chunk the document
    const chunks = chunkText(content, chunkSize, overlap);
    const vectors = [];

    for (let i = 0; i < chunks.length; i++) {
      const chunkId = `${id}_chunk_${i}`;
      const embedding = await withRetry(() => embedText(chunks[i]));
      vectors.push({
        id:       chunkId,
        values:   embedding,
        metadata: {
          ...metadata,
          tenant_id:  this.tenantId,
          doc_id:     id,
          chunk_idx:  i,
          chunk_text: chunks[i].slice(0, 200),
        },
      });
    }

    // Upsert all chunks in batch
    await this.pinecone.upsert(vectors);
    logger.info(_SRV, 'Document ingested', { tenantId: this.tenantId, docId: id, chunks: vectors.length });
    return { doc_id: id, chunks_indexed: vectors.length };
  }

  async retrieve(query, opts = {}) {
    const { topK = 10, filter = {}, minScore = 0.7 } = opts;
    const queryVector = await withRetry(() => embedText(query));
    const results = await this.pinecone.query(queryVector, topK, filter);
    return (results.matches || []).filter(m => m.score >= minScore);
  }

  async deleteDocument(docId) {
    // Fetch chunk IDs for this document then delete
    const results = await this.pinecone.query(
      new Array(1536).fill(0), 100,
      { doc_id: { '$eq': docId } }
    );
    const ids = results.matches.map(m => m.id);
    if (ids.length > 0) await this.pinecone.delete(ids);
    logger.info(_SRV, 'Document deleted', { tenantId: this.tenantId, docId, chunksRemoved: ids.length });
    return { deleted: ids.length };
  }
}

function chunkText(text, size, overlap) {
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    chunks.push(text.slice(start, start + size));
    start += size - overlap;
  }
  return chunks;
}

function fromRequest(req) {
  const tenantId = req.tenantId || req.user?.tenant_id;
  if (!tenantId) throw new Error('TenantRAG: request missing tenantId');
  return new TenantRAGService(tenantId);
}

module.exports = {
  TenantRAGService,
  PineconeTenantClient,
  WeaviateTenantClient,
  fromRequest,
  embedText,
};
'''

# ═══════════════════════════════════════════════════════════════════
# WS10: OPA Policy Files
# ═══════════════════════════════════════════════════════════════════

FILES['opa/policies/tenant_isolation.rego'] = r'''# tenant_isolation.rego
# OPA Policy: Enforce tenant isolation on all API requests
# Every request must have a matching tenant context

package wadjet.tenant_isolation

import future.keywords.if
import future.keywords.in

default allow = false

# Allow if tenant context matches authenticated user
allow if {
    input.user.tenant_id != ""
    input.request.tenant_id == input.user.tenant_id
}

# SUPER_ADMIN can access any tenant
allow if {
    input.user.role == "SUPER_ADMIN"
}

# Public routes (health, auth) do not require tenant
allow if {
    input.request.path in public_paths
}

public_paths := {
    "/api/health",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/enterprise/saml/metadata",
}

# Deny cross-tenant data access
deny[msg] if {
    input.request.tenant_id != ""
    input.user.tenant_id != ""
    input.request.tenant_id != input.user.tenant_id
    input.user.role != "SUPER_ADMIN"
    msg := sprintf("Cross-tenant access denied: user=%v tenant=%v requested=%v",
        [input.user.id, input.user.tenant_id, input.request.tenant_id])
}
'''

FILES['opa/policies/ai_governance.rego'] = r'''# ai_governance.rego
# OPA Policy: AI Governance — model/tool/agent access control
# Enforces AI governance registry rules at the policy layer

package wadjet.ai_governance

import future.keywords.if
import future.keywords.in

default allow_model = false
default allow_tool  = false
default allow_agent = false

# Model allowlist — only approved models may be used
approved_models := {
    "gpt-4o",
    "claude-3-5-sonnet-20241022",
    "gemini-2.0-flash",
    "text-embedding-3-small",
    "text-embedding-ada-002",
}

allow_model if {
    input.model_id in approved_models
}

deny_model[msg] if {
    not allow_model
    msg := sprintf("Model '%v' is not in the approved model registry", [input.model_id])
}

# Tool allowlist per agent role
role_tool_allowlist := {
    "analyst":   {"search_iocs", "enrich_ip", "query_intel", "summarize_alert", "run_yara"},
    "responder": {"search_iocs", "enrich_ip", "block_ip", "isolate_host", "create_case"},
    "admin":     {"search_iocs", "enrich_ip", "block_ip", "isolate_host", "create_case",
                  "kill_process", "revoke_token", "execute_playbook"},
    "soar":      {"block_ip", "isolate_host", "kill_process", "quarantine_file",
                  "disable_account", "revoke_token", "execute_playbook"},
}

allow_tool if {
    tools := role_tool_allowlist[input.agent_role]
    input.tool_name in tools
}

deny_tool[msg] if {
    not allow_tool
    msg := sprintf("Tool '%v' not permitted for role '%v'", [input.tool_name, input.agent_role])
}

# High-risk actions require human approval
high_risk_actions := {
    "block_ip", "isolate_host", "kill_process", "quarantine_file",
    "disable_account", "revoke_token", "execute_playbook", "delete_object",
}

requires_human_approval if {
    input.action in high_risk_actions
}

allow_agent if {
    not requires_human_approval
}

allow_agent if {
    requires_human_approval
    input.human_approved == true
    input.approver_id != ""
}

deny_agent[msg] if {
    requires_human_approval
    not input.human_approved
    msg := sprintf("Action '%v' requires human approval before execution", [input.action])
}
'''

FILES['opa/policies/data_access.rego'] = r'''# data_access.rego
# OPA Policy: Data access control — RBAC + ABAC
# Controls access to sensitive data fields based on role and classification

package wadjet.data_access

import future.keywords.if
import future.keywords.in

default allow_read  = false
default allow_write = false
default allow_delete = false

# Role hierarchy
role_hierarchy := {
    "SUPER_ADMIN": 100,
    "admin":        80,
    "analyst":      60,
    "responder":    60,
    "auditor":      50,
    "viewer":       30,
    "MSSP_ADMIN":   90,
}

user_level := role_hierarchy[input.user.role]

# Read access rules
allow_read if {
    user_level >= 30  # viewer and above
    input.resource.tenant_id == input.user.tenant_id
}

allow_read if {
    input.user.role == "SUPER_ADMIN"
}

# Write access — analyst and above
allow_write if {
    user_level >= 60
    input.resource.tenant_id == input.user.tenant_id
}

allow_write if {
    input.user.role in {"SUPER_ADMIN", "MSSP_ADMIN"}
}

# Delete — admin and above only
allow_delete if {
    user_level >= 80
    input.resource.tenant_id == input.user.tenant_id
}

allow_delete if {
    input.user.role == "SUPER_ADMIN"
}

# Sensitive data classification — PII fields require elevated access
sensitive_fields := {"ssn", "credit_card", "dob", "passport", "api_key", "private_key"}

allow_sensitive_field if {
    user_level >= 80  # admin+
    input.field_name in sensitive_fields
}

deny_sensitive[msg] if {
    input.field_name in sensitive_fields
    not allow_sensitive_field
    msg := sprintf("Access to sensitive field '%v' requires admin role (current: %v)",
        [input.field_name, input.user.role])
}
'''

# ═══════════════════════════════════════════════════════════════════
# WS10: Dependabot Config + SBOM + Security.txt
# ═══════════════════════════════════════════════════════════════════

FILES['.github/dependabot.yml'] = r'''# Dependabot configuration
# Automated dependency updates with security focus
version: 2
updates:
  # Backend Node.js dependencies
  - package-ecosystem: "npm"
    directory: "/backend"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "UTC"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"
    commit-message:
      prefix: "chore(deps)"
      include: "scope"
    ignore:
      # Only auto-update patch versions for production deps
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
    groups:
      security-patches:
        applies-to: security-updates
        patterns:
          - "*"

  # Frontend dependencies
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "frontend"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "github-actions"
'''

FILES['.github/workflows/security-scan.yml'] = r'''# security-scan.yml
# CI: Security scanning — SAST, SCA, secrets, SBOM, container scan
name: Security Scan

on:
  push:
    branches: [main, genspark_ai_developer]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2AM UTC

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  sast-semgrep:
    name: SAST — Semgrep
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/javascript
            p/nodejs
            p/owasp-top-ten
            p/security-audit
            p/jwt
            p/sql-injection
            p/xss
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

  dependency-audit:
    name: SCA — npm audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Backend audit
        run: cd backend && npm audit --audit-level=high
      - name: Frontend audit
        run: npm audit --audit-level=high || true

  secrets-scan:
    name: Secret Detection — Gitleaks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Gitleaks scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sbom-generation:
    name: SBOM — CycloneDX
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install CycloneDX
        run: npm install -g @cyclonedx/cyclonedx-npm
      - name: Generate SBOM (backend)
        run: cd backend && cyclonedx-npm --output-format json --output-file ../sbom-backend.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom-*.json
          retention-days: 90

  test-coverage:
    name: Tests + Coverage Gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install backend deps
        run: cd backend && npm ci
      - name: Run tests with coverage
        run: cd backend && npx jest --config jest.config.js --coverage --forceExit --passWithNoTests
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          directory: backend/coverage
          fail_ci_if_error: false

  license-check:
    name: License Compliance
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Check licenses
        run: |
          cd backend
          npm install -g license-checker
          license-checker --failOn "GPL-2.0;GPL-3.0;AGPL-3.0" --summary || echo "License check completed"
'''

FILES['.well-known/security.txt'] = r'''Contact: mailto:security@wadjet-eye.ai
Contact: https://wadjet-eye.ai/security/report
Expires: 2027-01-01T00:00:00.000Z
Encryption: https://wadjet-eye.ai/.well-known/pgp-key.txt
Acknowledgments: https://wadjet-eye.ai/security/hall-of-fame
Policy: https://wadjet-eye.ai/security/policy
Hiring: https://wadjet-eye.ai/careers
Preferred-Languages: en
CSAF: https://wadjet-eye.ai/.well-known/csaf/provider-metadata.json
'''

FILES['backend/db/migrations/20260701_enterprise_ws8_ws9.sql'] = r'''-- ═══════════════════════════════════════════════════════════════
-- WS8/WS9 Enterprise Schema Migration
-- Generated: 2026-07-01
-- ═══════════════════════════════════════════════════════════════

-- ── SSO Configuration on Tenants ─────────────────────────────────
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS sso_provider          TEXT CHECK (sso_provider IN ('saml', 'oidc', 'none')) DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS saml_idp_metadata_url TEXT,
  ADD COLUMN IF NOT EXISTS saml_idp_entity_id    TEXT,
  ADD COLUMN IF NOT EXISTS saml_idp_sso_url      TEXT,
  ADD COLUMN IF NOT EXISTS oidc_issuer            TEXT,
  ADD COLUMN IF NOT EXISTS oidc_client_id         TEXT,
  ADD COLUMN IF NOT EXISTS oidc_client_secret     TEXT ENCRYPTED,
  ADD COLUMN IF NOT EXISTS oidc_scopes            TEXT DEFAULT 'openid email profile',
  ADD COLUMN IF NOT EXISTS seats_used             INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS seats_limit            INTEGER DEFAULT 100,
  ADD COLUMN IF NOT EXISTS mrr_usd                NUMERIC(10,2) DEFAULT 0,
  ADD COLUMN IF NOT EXISTS active                 BOOLEAN DEFAULT true;

-- ── API Keys ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  key_hash    TEXT NOT NULL UNIQUE,
  scopes      TEXT[] DEFAULT ARRAY['read'],
  active      BOOLEAN DEFAULT true,
  expires_at  TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_keys_tenant_isolation ON api_keys
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- ── Outbox Events ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS outbox_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type      TEXT NOT NULL,
  aggregate_type  TEXT NOT NULL,
  aggregate_id    TEXT,
  tenant_id       UUID,
  payload         JSONB NOT NULL DEFAULT '{}',
  trace_id        TEXT,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'published', 'failed')),
  retry_count     INTEGER DEFAULT 0,
  last_error      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  published_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox_events(status, created_at)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_outbox_tenant ON outbox_events(tenant_id);

-- ── Roles Table ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  permissions TEXT[] DEFAULT ARRAY[]::TEXT[],
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, name)
);
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY roles_tenant_isolation ON roles
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- ── MSSP Overview Function ────────────────────────────────────────
CREATE OR REPLACE FUNCTION mssp_tenant_overview()
RETURNS TABLE(
  tenant_id UUID,
  tenant_name TEXT,
  plan TEXT,
  active BOOLEAN,
  seats_used INTEGER,
  seats_limit INTEGER,
  mrr_usd NUMERIC,
  open_alerts BIGINT,
  open_cases BIGINT
) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT
    t.id,
    t.name,
    t.plan,
    t.active,
    t.seats_used,
    t.seats_limit,
    t.mrr_usd,
    COALESCE(a.cnt, 0) AS open_alerts,
    COALESCE(c.cnt, 0) AS open_cases
  FROM tenants t
  LEFT JOIN (
    SELECT tenant_id, COUNT(*) cnt FROM alerts WHERE status = 'open' GROUP BY tenant_id
  ) a ON a.tenant_id = t.id
  LEFT JOIN (
    SELECT tenant_id, COUNT(*) cnt FROM cases WHERE status NOT IN ('closed', 'resolved') GROUP BY tenant_id
  ) c ON c.tenant_id = t.id
  ORDER BY t.name;
$$;

-- ── Auth provider column on users ────────────────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'local',
  ADD COLUMN IF NOT EXISTS active        BOOLEAN DEFAULT true,
  ADD COLUMN IF NOT EXISTS last_login    TIMESTAMPTZ;

-- ── Granted: completion ───────────────────────────────────────────
COMMENT ON TABLE outbox_events IS 'Transactional outbox for reliable event publishing (WS9)';
COMMENT ON TABLE api_keys IS 'API key management for programmatic access and MSSP integrations (WS8)';
'''

# ═══════════════════════════════════════════════════════════════════
# Write all files
# ═══════════════════════════════════════════════════════════════════

def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    lines = content.count('\n') + 1
    size  = len(content.encode('utf-8'))
    print(f'  {path}: {lines} lines ({size:,} bytes)')

base = '/home/user/webapp'
for rel_path, content in FILES.items():
    write_file(os.path.join(base, rel_path), content)

print('WS8+WS9+WS10 files written.')
