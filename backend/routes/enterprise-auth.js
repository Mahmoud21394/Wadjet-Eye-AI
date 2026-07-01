/**
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
