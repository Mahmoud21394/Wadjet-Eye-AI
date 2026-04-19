-- ══════════════════════════════════════════════════════════
--  ThreatPilot AI — Supabase Production Schema
--  Version 2.1.0 | PostgreSQL via Supabase
--
--  HOW TO USE:
--  1. Open Supabase → SQL Editor
--  2. Paste this entire file
--  3. Click "Run"
--
--  SAFE TO RE-RUN: All statements use IF NOT EXISTS / ON CONFLICT
-- ══════════════════════════════════════════════════════════

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ──────────────────────────────────────────────
-- 1. TENANTS
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.tenants (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name            TEXT NOT NULL,
  short_name      TEXT NOT NULL UNIQUE,
  domain          TEXT,
  plan            TEXT NOT NULL DEFAULT 'starter'
                  CHECK (plan IN ('starter','professional','enterprise')),
  siem_type       TEXT,
  edr_type        TEXT,
  risk_level      TEXT DEFAULT 'medium'
                  CHECK (risk_level IN ('low','medium','high','critical')),
  contact_email   TEXT,
  branding        JSONB DEFAULT '{}',
  settings        JSONB DEFAULT '{"alerts_enabled":true,"auto_playbooks":false,"dark_web_monitoring":false}',
  active          BOOLEAN DEFAULT true,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ──────────────────────────────────────────────
-- 2. USERS  (profile table — extends auth.users)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  auth_id         UUID UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  role            TEXT NOT NULL DEFAULT 'ANALYST'
                  CHECK (role IN ('SUPER_ADMIN','ADMIN','ANALYST','VIEWER')),
  avatar          TEXT DEFAULT 'U',
  permissions     TEXT[] DEFAULT ARRAY['read'],
  status          TEXT DEFAULT 'active'
                  CHECK (status IN ('active','suspended','pending')),
  mfa_enabled     BOOLEAN DEFAULT false,
  last_login      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_tenant  ON public.users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email   ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_auth_id ON public.users(auth_id);

-- ──────────────────────────────────────────────
-- 3. ALERTS
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.alerts (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        TEXT NOT NULL DEFAULT 'MEDIUM'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status          TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','in_progress','escalated','resolved','false_positive')),
  type            TEXT DEFAULT 'threat',
  ioc_value       TEXT,
  ioc_type        TEXT,
  source          TEXT DEFAULT 'manual',
  mitre_technique TEXT,
  affected_assets TEXT[] DEFAULT '{}',
  metadata        JSONB DEFAULT '{}',
  assigned_to     UUID REFERENCES public.users(id),
  created_by      UUID REFERENCES public.users(id),
  resolved_at     TIMESTAMPTZ,
  resolved_by     UUID REFERENCES public.users(id),
  escalated_at    TIMESTAMPTZ,
  escalated_by    UUID REFERENCES public.users(id),
  notes           TEXT,
  resolution      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant   ON public.alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON public.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON public.alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ioc      ON public.alerts(ioc_value);

-- Full-text search
CREATE INDEX IF NOT EXISTS idx_alerts_fts ON public.alerts
  USING gin(to_tsvector('english',
    coalesce(title,'') || ' ' || coalesce(description,'') || ' ' || coalesce(ioc_value,'')
  ));

-- ──────────────────────────────────────────────
-- 4. IOCs  ← MUST be before case_iocs (FK dependency)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.iocs (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  value            TEXT NOT NULL,
  type             TEXT NOT NULL
                   CHECK (type IN (
                     'ip','domain','url','hash_md5','hash_sha1','hash_sha256',
                     'email','filename','registry','mutex','asn','cve'
                   )),
  reputation       TEXT DEFAULT 'unknown'
                   CHECK (reputation IN ('clean','suspicious','malicious','unknown')),
  risk_score       NUMERIC(5,2) DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  source           TEXT DEFAULT 'manual',
  status           TEXT DEFAULT 'active'
                   CHECK (status IN ('active','inactive','false_positive')),
  country          TEXT,
  asn              TEXT,
  threat_actor     TEXT,
  tags             TEXT[] DEFAULT '{}',
  notes            TEXT,
  false_positive   BOOLEAN DEFAULT false,
  enrichment_data  JSONB DEFAULT '{}',
  enriched_at      TIMESTAMPTZ,
  first_seen       TIMESTAMPTZ DEFAULT NOW(),
  last_seen        TIMESTAMPTZ DEFAULT NOW(),
  created_by       UUID REFERENCES public.users(id),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_tenant ON public.iocs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type   ON public.iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_risk   ON public.iocs(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_value  ON public.iocs USING gin(value gin_trgm_ops);

-- ──────────────────────────────────────────────
-- 5. CASES
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.cases (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        TEXT NOT NULL DEFAULT 'MEDIUM'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status          TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','in_progress','monitoring','closed','false_positive')),
  assigned_to     UUID REFERENCES public.users(id),
  created_by      UUID REFERENCES public.users(id),
  tags            TEXT[] DEFAULT '{}',
  alert_ids       UUID[] DEFAULT '{}',
  evidence        JSONB[] DEFAULT '{}',
  sla_deadline    TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  resolution      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_tenant   ON public.cases(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cases_status   ON public.cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assigned ON public.cases(assigned_to);

-- Case notes
CREATE TABLE IF NOT EXISTS public.case_notes (
  id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  content     TEXT NOT NULL,
  created_by  UUID REFERENCES public.users(id),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON public.case_notes(case_id);

-- Case IOC links  ← iocs table now exists above ✓
CREATE TABLE IF NOT EXISTS public.case_iocs (
  id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  ioc_id      UUID NOT NULL REFERENCES public.iocs(id) ON DELETE CASCADE,
  added_by    UUID REFERENCES public.users(id),
  added_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(case_id, ioc_id)
);

-- Case timeline
CREATE TABLE IF NOT EXISTS public.case_timeline (
  id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  case_id     UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  event_type  TEXT NOT NULL,
  description TEXT NOT NULL,
  actor       TEXT,
  metadata    JSONB DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_case_timeline ON public.case_timeline(case_id, created_at);

-- ──────────────────────────────────────────────
-- 6. AUDIT LOGS
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id           UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id    UUID REFERENCES public.tenants(id),
  user_id      UUID REFERENCES public.users(id),
  user_email   TEXT,
  user_role    TEXT,
  action       TEXT NOT NULL,
  resource     TEXT,
  resource_id  TEXT,
  method       TEXT,
  path         TEXT,
  status_code  INTEGER,
  ip_address   TEXT,
  user_agent   TEXT,
  duration_ms  INTEGER,
  request_body TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON public.audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user   ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON public.audit_logs(action);

-- ──────────────────────────────────────────────
-- 7. PLAYBOOKS
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.playbooks (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  description      TEXT,
  category         TEXT,
  steps            JSONB[] DEFAULT '{}',
  trigger          TEXT,
  mitre_techniques TEXT[] DEFAULT '{}',
  active           BOOLEAN DEFAULT true,
  execution_count  INTEGER DEFAULT 0,
  last_executed    TIMESTAMPTZ,
  created_by       UUID REFERENCES public.users(id),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant ON public.playbooks(tenant_id);

-- ──────────────────────────────────────────────
-- 8. IOC ENRICHMENT CACHE
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.ioc_enrichment_cache (
  id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  cache_key   TEXT NOT NULL UNIQUE,
  data        JSONB NOT NULL,
  expires_at  TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours'),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cache_key     ON public.ioc_enrichment_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON public.ioc_enrichment_cache(expires_at);

-- ──────────────────────────────────────────────
-- 9. THREAT FEEDS (collector results)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.threat_feeds (
  id           UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id    UUID REFERENCES public.tenants(id),
  feed_name    TEXT NOT NULL,
  feed_type    TEXT NOT NULL CHECK (feed_type IN ('otx','abuseipdb','virustotal','shodan','greynoise','manual')),
  ioc_value    TEXT NOT NULL,
  ioc_type     TEXT NOT NULL,
  risk_score   NUMERIC(5,2) DEFAULT 0,
  reputation   TEXT DEFAULT 'unknown',
  raw_data     JSONB DEFAULT '{}',
  processed    BOOLEAN DEFAULT false,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feeds_tenant  ON public.threat_feeds(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feeds_type    ON public.threat_feeds(feed_type);
CREATE INDEX IF NOT EXISTS idx_feeds_ioc     ON public.threat_feeds(ioc_value);

-- ══════════════════════════════════════════════════════════
--  AUTO-UPDATE TRIGGERS
-- ══════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_tenants   BEFORE UPDATE ON public.tenants   FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_users     BEFORE UPDATE ON public.users     FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_alerts    BEFORE UPDATE ON public.alerts    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_cases     BEFORE UPDATE ON public.cases     FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_iocs      BEFORE UPDATE ON public.iocs      FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_playbooks BEFORE UPDATE ON public.playbooks FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ══════════════════════════════════════════════════════════
--  ROW LEVEL SECURITY (RLS)
-- ══════════════════════════════════════════════════════════

ALTER TABLE public.tenants           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cases             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.case_notes        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.case_iocs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.case_timeline     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.iocs              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.playbooks         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_feeds      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ioc_enrichment_cache ENABLE ROW LEVEL SECURITY;

-- Helper functions to extract claims from JWT
CREATE OR REPLACE FUNCTION public.get_tenant_id()
RETURNS UUID AS $$
  SELECT NULLIF((auth.jwt() -> 'user_metadata' ->> 'tenant_id'), '')::UUID;
$$ LANGUAGE sql STABLE SECURITY DEFINER;

CREATE OR REPLACE FUNCTION public.get_user_role()
RETURNS TEXT AS $$
  SELECT COALESCE((auth.jwt() -> 'user_metadata' ->> 'role'), 'VIEWER');
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- Drop existing policies before recreating (safe re-run)
DO $$ BEGIN
  DROP POLICY IF EXISTS tenant_isolation           ON public.tenants;
  DROP POLICY IF EXISTS users_tenant_isolation     ON public.users;
  DROP POLICY IF EXISTS alerts_tenant_isolation    ON public.alerts;
  DROP POLICY IF EXISTS cases_tenant_isolation     ON public.cases;
  DROP POLICY IF EXISTS case_notes_isolation       ON public.case_notes;
  DROP POLICY IF EXISTS case_iocs_isolation        ON public.case_iocs;
  DROP POLICY IF EXISTS case_timeline_isolation    ON public.case_timeline;
  DROP POLICY IF EXISTS iocs_tenant_isolation      ON public.iocs;
  DROP POLICY IF EXISTS audit_logs_admin_only      ON public.audit_logs;
  DROP POLICY IF EXISTS playbooks_tenant_isolation ON public.playbooks;
  DROP POLICY IF EXISTS threat_feeds_isolation     ON public.threat_feeds;
  DROP POLICY IF EXISTS cache_service_only         ON public.ioc_enrichment_cache;
END $$;

-- RLS Policies
CREATE POLICY tenant_isolation ON public.tenants
  USING (id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY users_tenant_isolation ON public.users
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY alerts_tenant_isolation ON public.alerts
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY cases_tenant_isolation ON public.cases
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY case_notes_isolation ON public.case_notes
  USING (case_id IN (
    SELECT id FROM public.cases
    WHERE tenant_id = public.get_tenant_id()
       OR public.get_user_role() = 'SUPER_ADMIN'
  ));

CREATE POLICY case_iocs_isolation ON public.case_iocs
  USING (case_id IN (
    SELECT id FROM public.cases
    WHERE tenant_id = public.get_tenant_id()
       OR public.get_user_role() = 'SUPER_ADMIN'
  ));

CREATE POLICY case_timeline_isolation ON public.case_timeline
  USING (case_id IN (
    SELECT id FROM public.cases
    WHERE tenant_id = public.get_tenant_id()
       OR public.get_user_role() = 'SUPER_ADMIN'
  ));

CREATE POLICY iocs_tenant_isolation ON public.iocs
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY audit_logs_admin_only ON public.audit_logs
  USING (
    tenant_id = public.get_tenant_id()
    AND public.get_user_role() IN ('ADMIN','SUPER_ADMIN')
  );

CREATE POLICY playbooks_tenant_isolation ON public.playbooks
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

CREATE POLICY threat_feeds_isolation ON public.threat_feeds
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

-- Cache readable by service role (no anon access)
CREATE POLICY cache_service_only ON public.ioc_enrichment_cache
  USING (false);  -- Only service role (bypasses RLS) can access

-- ══════════════════════════════════════════════════════════
--  SEED DATA  (safe to re-run — uses ON CONFLICT DO NOTHING)
--  short_name values MATCH frontend dropdown option values
-- ══════════════════════════════════════════════════════════

INSERT INTO public.tenants (id, name, short_name, domain, plan, risk_level, active, settings)
VALUES
  (
    '00000000-0000-0000-0000-000000000001',
    'MSSP Global Operations',
    'mssp-global',
    'mssp.threatpilot.ai',
    'enterprise',
    'high',
    true,
    '{"alerts_enabled":true,"auto_playbooks":true,"dark_web_monitoring":true}'
  ),
  (
    '00000000-0000-0000-0000-000000000002',
    'HackerOne Security',
    'hackerone',
    'h1.threatpilot.ai',
    'professional',
    'medium',
    true,
    '{"alerts_enabled":true,"auto_playbooks":false,"dark_web_monitoring":true}'
  ),
  (
    '00000000-0000-0000-0000-000000000003',
    'Bugcrowd Platform',
    'bugcrowd',
    'bc.threatpilot.ai',
    'starter',
    'low',
    true,
    '{"alerts_enabled":true,"auto_playbooks":false,"dark_web_monitoring":false}'
  )
ON CONFLICT (id) DO UPDATE SET
  short_name = EXCLUDED.short_name,
  name       = EXCLUDED.name,
  settings   = EXCLUDED.settings;

-- NOTE: Users must be seeded via `node backend/scripts/seed.js`
-- because they require Supabase Auth user creation (GoTrue API).
-- The seed.js script creates auth users + profile rows in one step.
