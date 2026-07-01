-- ═══════════════════════════════════════════════════════════════
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
