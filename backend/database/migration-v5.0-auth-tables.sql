-- ══════════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Missing Tables Migration v5.0
--  FILE: backend/database/migration-v5.0-auth-tables.sql
--
--  PURPOSE:
--  Adds all tables referenced by auth.js, middleware/auth.js, and
--  seed-mahmoud.js that are MISSING from schema.sql:
--    1. refresh_tokens   ← used by /api/auth/login, /refresh, /sessions
--    2. login_activity   ← used by auth.js logActivity()
--    3. sysmon_sessions  ← used by /api/sysmon routes
--    4. sysmon_detections← used by /api/sysmon routes
--    5. vulnerabilities  ← used by /api/vulnerabilities routes
--    6. cti_actors       ← used by /api/cti routes
--    7. cti_campaigns    ← used by /api/cti routes
--    8. reports          ← used by /api/reports routes
--
--  HOW TO RUN:
--  ──────────
--  1. Open Supabase Dashboard → SQL Editor
--  2. Paste this ENTIRE file
--  3. Click "Run"
--  4. Then run: node backend/scripts/seed-mahmoud.js
--
--  SAFE TO RE-RUN: All statements use IF NOT EXISTS
-- ══════════════════════════════════════════════════════════════════════════

-- Ensure uuid extension is active
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ──────────────────────────────────────────────────────────
-- TABLE: refresh_tokens
-- Referenced by: backend/routes/auth.js (storeRefreshToken, rotateRefreshToken)
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
  id            UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  tenant_id     UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL,              -- SHA-256 hash of the raw token
  device_info   JSONB DEFAULT '{}',         -- IP, user-agent, browser, OS
  is_revoked    BOOLEAN DEFAULT false,
  last_used_at  TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_token_hash  ON public.refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_rt_user_id     ON public.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires     ON public.refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_rt_revoked     ON public.refresh_tokens(is_revoked);

-- ──────────────────────────────────────────────────────────
-- TABLE: login_activity
-- Referenced by: backend/routes/auth.js (logActivity)
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.login_activity (
  id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id        UUID REFERENCES public.users(id) ON DELETE SET NULL,
  tenant_id      UUID REFERENCES public.tenants(id) ON DELETE SET NULL,
  email          TEXT,
  action         TEXT NOT NULL,             -- LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, TOKEN_REFRESH, etc.
  ip_address     TEXT,
  user_agent     TEXT,
  device_info    JSONB DEFAULT '{}',
  success        BOOLEAN DEFAULT true,
  failure_reason TEXT,
  session_id     UUID,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_la_user_id    ON public.login_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_la_tenant_id  ON public.login_activity(tenant_id);
CREATE INDEX IF NOT EXISTS idx_la_action     ON public.login_activity(action);
CREATE INDEX IF NOT EXISTS idx_la_created    ON public.login_activity(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_la_ip         ON public.login_activity(ip_address);

-- ──────────────────────────────────────────────────────────
-- TABLE: sysmon_sessions
-- Referenced by: backend/routes/sysmon.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.sysmon_sessions (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  file_name       TEXT NOT NULL,
  file_size       INTEGER,
  log_type        TEXT,                      -- sysmon, evtx, json, csv, etc.
  status          TEXT DEFAULT 'processing'
                  CHECK (status IN ('processing','completed','failed')),
  total_events    INTEGER DEFAULT 0,
  detection_count INTEGER DEFAULT 0,
  risk_score      NUMERIC(5,2) DEFAULT 0,
  summary         JSONB DEFAULT '{}',
  created_by      UUID REFERENCES public.users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sysmon_tenant  ON public.sysmon_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sysmon_created ON public.sysmon_sessions(created_at DESC);

-- ──────────────────────────────────────────────────────────
-- TABLE: sysmon_detections
-- Referenced by: backend/routes/sysmon.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.sysmon_detections (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  session_id      UUID NOT NULL REFERENCES public.sysmon_sessions(id) ON DELETE CASCADE,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  rule_id         TEXT,
  rule_name       TEXT NOT NULL,
  severity        TEXT NOT NULL DEFAULT 'MEDIUM'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  mitre_technique TEXT,
  mitre_tactic    TEXT,
  description     TEXT,
  raw_event       JSONB DEFAULT '{}',
  event_time      TIMESTAMPTZ,
  process_name    TEXT,
  process_id      INTEGER,
  parent_process  TEXT,
  command_line    TEXT,
  network_dst     TEXT,
  network_port    INTEGER,
  file_path       TEXT,
  registry_key    TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sysmon_det_session  ON public.sysmon_detections(session_id);
CREATE INDEX IF NOT EXISTS idx_sysmon_det_severity ON public.sysmon_detections(severity);
CREATE INDEX IF NOT EXISTS idx_sysmon_det_mitre    ON public.sysmon_detections(mitre_technique);

-- ──────────────────────────────────────────────────────────
-- TABLE: vulnerabilities
-- Referenced by: backend/routes/vulnerabilities.js, backend/services/ingestion/nvd.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  cve_id          TEXT NOT NULL UNIQUE,
  title           TEXT,
  description     TEXT,
  severity        TEXT DEFAULT 'MEDIUM'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL','NONE')),
  cvss_score      NUMERIC(4,2),
  cvss_vector     TEXT,
  cvss_version    TEXT DEFAULT '3.1',
  cwe_ids         TEXT[] DEFAULT '{}',
  affected_products JSONB DEFAULT '[]',
  references      TEXT[] DEFAULT '{}',
  exploit_available BOOLEAN DEFAULT false,
  patch_available BOOLEAN DEFAULT false,
  is_kev          BOOLEAN DEFAULT false,    -- CISA Known Exploited Vulnerability
  kev_date_added  DATE,
  published_at    TIMESTAMPTZ,
  modified_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve      ON public.vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON public.vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cvss     ON public.vulnerabilities(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_kev      ON public.vulnerabilities(is_kev);
CREATE INDEX IF NOT EXISTS idx_vulns_exploit  ON public.vulnerabilities(exploit_available);
CREATE INDEX IF NOT EXISTS idx_vulns_pub      ON public.vulnerabilities(published_at DESC);

-- Full-text search on CVE
CREATE INDEX IF NOT EXISTS idx_vulns_fts ON public.vulnerabilities
  USING gin(to_tsvector('english',
    coalesce(cve_id,'') || ' ' || coalesce(title,'') || ' ' || coalesce(description,'')
  ));

-- ──────────────────────────────────────────────────────────
-- TABLE: cti_actors (Threat Actor profiles)
-- Referenced by: backend/routes/cti.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.cti_actors (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  aliases         TEXT[] DEFAULT '{}',
  nation_state    TEXT,
  motivation      TEXT[] DEFAULT '{}',    -- financial, espionage, sabotage, etc.
  sophistication  TEXT DEFAULT 'intermediate'
                  CHECK (sophistication IN ('novice','intermediate','expert','nation-state')),
  active          BOOLEAN DEFAULT true,
  description     TEXT,
  mitre_groups    TEXT[] DEFAULT '{}',    -- G0001, etc.
  ttps            TEXT[] DEFAULT '{}',    -- T1234, etc.
  iocs            TEXT[] DEFAULT '{}',
  targets         TEXT[] DEFAULT '{}',    -- sectors / regions
  first_seen      TIMESTAMPTZ,
  last_seen       TIMESTAMPTZ,
  source          TEXT DEFAULT 'manual',
  confidence      INTEGER DEFAULT 70 CHECK (confidence BETWEEN 0 AND 100),
  created_by      UUID REFERENCES public.users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cti_actors_tenant ON public.cti_actors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cti_actors_name   ON public.cti_actors(name);

-- ──────────────────────────────────────────────────────────
-- TABLE: cti_campaigns
-- Referenced by: backend/routes/cti.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.cti_campaigns (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  actor_id        UUID REFERENCES public.cti_actors(id) ON DELETE SET NULL,
  status          TEXT DEFAULT 'active'
                  CHECK (status IN ('active','historical','suspected','mitigated')),
  severity        TEXT DEFAULT 'HIGH'
                  CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  start_date      TIMESTAMPTZ,
  end_date        TIMESTAMPTZ,
  targets         TEXT[] DEFAULT '{}',
  mitre_techniques TEXT[] DEFAULT '{}',
  iocs            TEXT[] DEFAULT '{}',
  source          TEXT DEFAULT 'manual',
  confidence      INTEGER DEFAULT 70,
  created_by      UUID REFERENCES public.users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cti_campaigns_tenant ON public.cti_campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cti_campaigns_actor  ON public.cti_campaigns(actor_id);

-- ──────────────────────────────────────────────────────────
-- TABLE: reports (Executive reports)
-- Referenced by: backend/routes/reports.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.reports (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  report_type     TEXT DEFAULT 'executive'
                  CHECK (report_type IN ('executive','threat_intel','investigation','compliance','custom')),
  period_start    TIMESTAMPTZ,
  period_end      TIMESTAMPTZ,
  status          TEXT DEFAULT 'generating'
                  CHECK (status IN ('generating','ready','failed','archived')),
  summary         JSONB DEFAULT '{}',
  sections        JSONB DEFAULT '[]',     -- Array of report sections
  kpis            JSONB DEFAULT '{}',     -- KPI metrics snapshot
  file_path       TEXT,                   -- Path to generated PDF
  file_size       INTEGER,
  generated_by    UUID REFERENCES public.users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant  ON public.reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_type    ON public.reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created ON public.reports(created_at DESC);

-- ──────────────────────────────────────────────────────────
-- TABLE: collectors (Threat feed collector status)
-- Referenced by: backend/routes/collectors.js
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.collectors (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  display_name    TEXT,
  feed_type       TEXT,
  status          TEXT DEFAULT 'active'
                  CHECK (status IN ('active','inactive','error','rate_limited')),
  last_run        TIMESTAMPTZ,
  last_success    TIMESTAMPTZ,
  run_count       INTEGER DEFAULT 0,
  error_count     INTEGER DEFAULT 0,
  iocs_ingested   INTEGER DEFAULT 0,
  last_error      TEXT,
  config          JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collectors_name   ON public.collectors(name);
CREATE INDEX IF NOT EXISTS idx_collectors_status ON public.collectors(status);

-- ──────────────────────────────────────────────────────────
-- TABLE: cti_feed_logs (Collector run history)
-- Referenced by: backend/routes/cti.js (feedLogs)
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.cti_feed_logs (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  feed_name       TEXT NOT NULL,
  status          TEXT DEFAULT 'success'
                  CHECK (status IN ('success','error','partial','rate_limited')),
  iocs_fetched    INTEGER DEFAULT 0,
  iocs_new        INTEGER DEFAULT 0,
  iocs_updated    INTEGER DEFAULT 0,
  duration_ms     INTEGER,
  error_message   TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feed_logs_feed    ON public.cti_feed_logs(feed_name);
CREATE INDEX IF NOT EXISTS idx_feed_logs_created ON public.cti_feed_logs(created_at DESC);

-- ──────────────────────────────────────────────────────────
-- TABLE: dark_web_mentions
-- Referenced by: js/darkweb.js backend integration
-- ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.dark_web_mentions (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  type            TEXT DEFAULT 'forum_post'
                  CHECK (type IN ('forum_post','leak','marketplace','ransomware_site','paste')),
  source          TEXT,
  title           TEXT,
  excerpt         TEXT,
  url             TEXT,
  risk_score      INTEGER DEFAULT 50 CHECK (risk_score BETWEEN 0 AND 100),
  keywords_matched TEXT[] DEFAULT '{}',
  is_verified     BOOLEAN DEFAULT false,
  is_resolved     BOOLEAN DEFAULT false,
  discovered_at   TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dark_web_tenant   ON public.dark_web_mentions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dark_web_type     ON public.dark_web_mentions(type);
CREATE INDEX IF NOT EXISTS idx_dark_web_risk     ON public.dark_web_mentions(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_dark_web_created  ON public.dark_web_mentions(created_at DESC);

-- ──────────────────────────────────────────────────────────
-- UPDATE TRIGGERS for new tables
-- ──────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_sysmon_sessions
    BEFORE UPDATE ON public.sysmon_sessions
    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_vulnerabilities
    BEFORE UPDATE ON public.vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_cti_actors
    BEFORE UPDATE ON public.cti_actors
    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_cti_campaigns
    BEFORE UPDATE ON public.cti_campaigns
    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_reports
    BEFORE UPDATE ON public.reports
    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ──────────────────────────────────────────────────────────
-- ROW LEVEL SECURITY — Enable for all tables
-- (Service role bypasses RLS; user JWT respects it)
-- ──────────────────────────────────────────────────────────
ALTER TABLE public.refresh_tokens   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_activity   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sysmon_sessions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sysmon_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cti_actors       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cti_campaigns    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collectors       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cti_feed_logs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dark_web_mentions ENABLE ROW LEVEL SECURITY;

-- Allow service role full access (bypasses RLS)
-- All backend calls use service role key, so these policies aren't needed
-- for backend. They protect against direct Supabase client calls from frontend.

-- Tenant-scoped read policy for authenticated users
CREATE POLICY IF NOT EXISTS "tenant_read_sysmon_sessions" ON public.sysmon_sessions
  FOR SELECT USING (tenant_id IN (
    SELECT tenant_id FROM public.users WHERE auth_id = auth.uid()
  ));

CREATE POLICY IF NOT EXISTS "tenant_read_vulnerabilities" ON public.vulnerabilities
  FOR SELECT USING (true);  -- Vulnerabilities are global (not tenant-specific)

CREATE POLICY IF NOT EXISTS "tenant_read_cti_actors" ON public.cti_actors
  FOR SELECT USING (
    tenant_id IS NULL OR
    tenant_id IN (SELECT tenant_id FROM public.users WHERE auth_id = auth.uid())
  );

CREATE POLICY IF NOT EXISTS "tenant_read_cti_campaigns" ON public.cti_campaigns
  FOR SELECT USING (
    tenant_id IS NULL OR
    tenant_id IN (SELECT tenant_id FROM public.users WHERE auth_id = auth.uid())
  );

-- ──────────────────────────────────────────────────────────
-- SEED DEFAULT COLLECTORS
-- ──────────────────────────────────────────────────────────
INSERT INTO public.collectors (name, display_name, feed_type, status) VALUES
  ('otx',          'AlienVault OTX',    'threat_intel', 'active'),
  ('abuseipdb',    'AbuseIPDB',         'threat_intel', 'active'),
  ('virustotal',   'VirusTotal',        'threat_intel', 'active'),
  ('urlhaus',      'URLhaus',           'malware',      'active'),
  ('threatfox',    'ThreatFox',         'malware',      'active'),
  ('feodo',        'Feodo Tracker',     'botnet',       'active'),
  ('cisa_kev',     'CISA KEV',          'cve',          'active'),
  ('openphish',    'OpenPhish',         'phishing',     'active'),
  ('malwarebazaar','MalwareBazaar',     'malware',      'active'),
  ('ransomware_live','Ransomware.live', 'ransomware',   'active'),
  ('nvd',          'NVD CVE',           'cve',          'active'),
  ('shodan',       'Shodan',            'network_intel','active')
ON CONFLICT (name) DO UPDATE SET
  status     = EXCLUDED.status,
  updated_at = NOW();

-- ──────────────────────────────────────────────────────────
-- VERIFICATION — Count all tables
-- ──────────────────────────────────────────────────────────
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
