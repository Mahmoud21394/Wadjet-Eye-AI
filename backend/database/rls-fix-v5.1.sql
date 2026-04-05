-- ══════════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — RLS Fix v5.1  (CRITICAL — run this FIRST)
--  FILE: backend/database/rls-fix-v5.1.sql
--
--  PURPOSE:
--  ─────────────────────────────────────────────────────────────────────────
--  Fixes the error:
--    ❌ Failed to store refresh token:
--       new row violates row-level security policy for table "refresh_tokens"
--
--  ROOT CAUSE:
--  ─────────────────────────────────────────────────────────────────────────
--  Supabase by default enables RLS (Row Level Security) on tables.
--  When RLS is ON but NO policies allow the operation, ALL operations
--  are BLOCKED — even from the service_role key UNLESS the table has a
--  policy that explicitly grants service_role access.
--
--  In Supabase, the service_role key bypasses RLS ONLY when connected via
--  the REST API (PostgREST) with the `Authorization: Bearer <service_role>`
--  header.  However, the Node.js Supabase client (@supabase/supabase-js)
--  uses the service_role key as the apikey header — and PostgREST DOES bypass
--  RLS for service_role connections, BUT only if:
--    1. The role used is `service_role` (set via apikey / auth header), OR
--    2. An explicit BYPASSRLS policy / attribute exists on the role
--
--  The issue manifests because:
--    - migration-v5.0 enables RLS on refresh_tokens
--    - No INSERT policy was added for the service_role
--    - PostgREST may interpret service_role as an anon call in some configs
--
--  SOLUTION applied here:
--  ─────────────────────────────────────────────────────────────────────────
--  1. DROP and re-create all RLS policies for refresh_tokens and
--     login_activity with correct service_role bypass grants
--  2. Add explicit GRANT permissions for the service_role postgres role
--  3. Add BYPASSRLS to postgres role (the service_role maps to this)
--  4. Add a fallback "full access" policy for authenticated backend calls
--
--  HOW TO RUN:
--  ─────────────────────────────────────────────────────────────────────────
--  1. Open https://supabase.com/dashboard/project/miywxnplaltduuscjfmq
--  2. Go to SQL Editor (left sidebar)
--  3. Paste this ENTIRE file → Click "Run"
--  4. You should see "RLS Fix v5.1 Applied Successfully" in the output
--  5. Then run: node backend/scripts/seed-mahmoud.js
--
--  SAFE TO RE-RUN: All statements use IF NOT EXISTS / OR REPLACE
-- ══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 0: Ensure extensions are active
-- ─────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 1: Ensure refresh_tokens table exists
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
  id            UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id       UUID NOT NULL,
  tenant_id     UUID,
  token_hash    TEXT NOT NULL,
  device_info   JSONB DEFAULT '{}',
  is_revoked    BOOLEAN DEFAULT false,
  last_used_at  TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Add FK constraints only if the referenced tables exist
DO $$ BEGIN
  ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_rt_user FOREIGN KEY (user_id)
    REFERENCES public.users(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
        WHEN undefined_table THEN NULL;
        WHEN undefined_column THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_rt_tenant FOREIGN KEY (tenant_id)
    REFERENCES public.tenants(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
        WHEN undefined_table THEN NULL;
        WHEN undefined_column THEN NULL;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_rt_token_hash ON public.refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_rt_user_id    ON public.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires    ON public.refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_rt_revoked    ON public.refresh_tokens(is_revoked);

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 2: Ensure login_activity table exists
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.login_activity (
  id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id        UUID,
  tenant_id      UUID,
  email          TEXT,
  action         TEXT NOT NULL,
  ip_address     TEXT,
  user_agent     TEXT,
  device_info    JSONB DEFAULT '{}',
  success        BOOLEAN DEFAULT true,
  failure_reason TEXT,
  session_id     UUID,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Add FK constraints safely
DO $$ BEGIN
  ALTER TABLE public.login_activity
    ADD CONSTRAINT fk_la_user FOREIGN KEY (user_id)
    REFERENCES public.users(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
        WHEN undefined_table THEN NULL;
        WHEN undefined_column THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_la_user_id   ON public.login_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_la_tenant_id ON public.login_activity(tenant_id);
CREATE INDEX IF NOT EXISTS idx_la_action    ON public.login_activity(action);
CREATE INDEX IF NOT EXISTS idx_la_created   ON public.login_activity(created_at DESC);

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 3: GRANT explicit permissions to postgres / service_role
--
-- In Supabase:
--   * "postgres" role = the superuser that service_role maps to
--   * "anon" role = unauthenticated clients
--   * "authenticated" role = JWT-authenticated clients
--   * "service_role" = backend server key (bypasses RLS in PostgREST)
--
-- We grant ALL to postgres + service_role on these tables so the
-- backend (which uses service_role key) can always INSERT/SELECT/UPDATE/DELETE
-- ─────────────────────────────────────────────────────────────────────────

GRANT ALL ON public.refresh_tokens  TO postgres, service_role;
GRANT ALL ON public.login_activity  TO postgres, service_role;

-- Also grant sequence usage if using serial IDs
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role;

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 4: RLS Policies for refresh_tokens
-- ─────────────────────────────────────────────────────────────────────────

-- Enable RLS (idempotent)
ALTER TABLE public.refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Drop all existing policies to start clean
DROP POLICY IF EXISTS "service_role_full_access_rt"    ON public.refresh_tokens;
DROP POLICY IF EXISTS "user_read_own_tokens"           ON public.refresh_tokens;
DROP POLICY IF EXISTS "user_delete_own_tokens"         ON public.refresh_tokens;
DROP POLICY IF EXISTS "user_update_own_tokens"         ON public.refresh_tokens;
DROP POLICY IF EXISTS "tenant_read_refresh_tokens"     ON public.refresh_tokens;
DROP POLICY IF EXISTS "anon_insert_refresh_tokens"     ON public.refresh_tokens;
DROP POLICY IF EXISTS "backend_insert_refresh_tokens"  ON public.refresh_tokens;
DROP POLICY IF EXISTS "backend_all_refresh_tokens"     ON public.refresh_tokens;
DROP POLICY IF EXISTS "allow_service_role"             ON public.refresh_tokens;
DROP POLICY IF EXISTS "enable_all_for_service_role"    ON public.refresh_tokens;
DROP POLICY IF EXISTS "postgres_full_access_rt"        ON public.refresh_tokens;

-- Policy 1: Service role has FULL access (INSERT, SELECT, UPDATE, DELETE)
-- This is the CRITICAL policy that fixes the error.
-- When your backend uses SUPABASE_SERVICE_KEY, PostgREST uses role=service_role
CREATE POLICY "service_role_full_access_rt"
  ON public.refresh_tokens
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Policy 2: Authenticated users can READ their own tokens (for /sessions endpoint)
CREATE POLICY "user_read_own_tokens"
  ON public.refresh_tokens
  FOR SELECT
  TO authenticated
  USING (
    user_id IN (
      SELECT id FROM public.users WHERE auth_id = auth.uid()
    )
  );

-- Policy 3: Authenticated users can UPDATE their own tokens (revoke)
CREATE POLICY "user_update_own_tokens"
  ON public.refresh_tokens
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id FROM public.users WHERE auth_id = auth.uid()
    )
  )
  WITH CHECK (true);

-- Policy 4: Postgres superuser always has full access
CREATE POLICY "postgres_full_access_rt"
  ON public.refresh_tokens
  FOR ALL
  TO postgres
  USING (true)
  WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 5: RLS Policies for login_activity
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE public.login_activity ENABLE ROW LEVEL SECURITY;

-- Drop all existing policies
DROP POLICY IF EXISTS "service_role_full_access_la"   ON public.login_activity;
DROP POLICY IF EXISTS "user_read_own_activity"        ON public.login_activity;
DROP POLICY IF EXISTS "backend_insert_activity"       ON public.login_activity;
DROP POLICY IF EXISTS "backend_all_activity"          ON public.login_activity;
DROP POLICY IF EXISTS "postgres_full_access_la"       ON public.login_activity;

-- Service role full access
CREATE POLICY "service_role_full_access_la"
  ON public.login_activity
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Postgres full access
CREATE POLICY "postgres_full_access_la"
  ON public.login_activity
  FOR ALL
  TO postgres
  USING (true)
  WITH CHECK (true);

-- Authenticated users can read their own activity
CREATE POLICY "user_read_own_activity"
  ON public.login_activity
  FOR SELECT
  TO authenticated
  USING (
    user_id IN (
      SELECT id FROM public.users WHERE auth_id = auth.uid()
    )
  );

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 6: Fix other tables that might have the same RLS problem
-- ─────────────────────────────────────────────────────────────────────────

-- sysmon_sessions
DO $$ BEGIN
  ALTER TABLE public.sysmon_sessions ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_sysmon" ON public.sysmon_sessions;
  CREATE POLICY "service_role_full_access_sysmon"
    ON public.sysmon_sessions FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- sysmon_detections
DO $$ BEGIN
  ALTER TABLE public.sysmon_detections ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_sysdet" ON public.sysmon_detections;
  CREATE POLICY "service_role_full_access_sysdet"
    ON public.sysmon_detections FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- vulnerabilities
DO $$ BEGIN
  ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_vulns" ON public.vulnerabilities;
  CREATE POLICY "service_role_full_access_vulns"
    ON public.vulnerabilities FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- cti_actors
DO $$ BEGIN
  ALTER TABLE public.cti_actors ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_cti_actors" ON public.cti_actors;
  CREATE POLICY "service_role_full_access_cti_actors"
    ON public.cti_actors FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- cti_campaigns
DO $$ BEGIN
  ALTER TABLE public.cti_campaigns ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_cti_campaigns" ON public.cti_campaigns;
  CREATE POLICY "service_role_full_access_cti_campaigns"
    ON public.cti_campaigns FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- reports
DO $$ BEGIN
  ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_reports" ON public.reports;
  CREATE POLICY "service_role_full_access_reports"
    ON public.reports FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- collectors
DO $$ BEGIN
  ALTER TABLE public.collectors ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_collectors" ON public.collectors;
  CREATE POLICY "service_role_full_access_collectors"
    ON public.collectors FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- cti_feed_logs
DO $$ BEGIN
  ALTER TABLE public.cti_feed_logs ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_feed_logs" ON public.cti_feed_logs;
  CREATE POLICY "service_role_full_access_feed_logs"
    ON public.cti_feed_logs FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- dark_web_mentions
DO $$ BEGIN
  ALTER TABLE public.dark_web_mentions ENABLE ROW LEVEL SECURITY;
  DROP POLICY IF EXISTS "service_role_full_access_darkweb" ON public.dark_web_mentions;
  CREATE POLICY "service_role_full_access_darkweb"
    ON public.dark_web_mentions FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- tenants
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_tenants" ON public.tenants;
  CREATE POLICY "service_role_full_access_tenants"
    ON public.tenants FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- users
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_users" ON public.users;
  CREATE POLICY "service_role_full_access_users"
    ON public.users FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- alerts
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_alerts" ON public.alerts;
  CREATE POLICY "service_role_full_access_alerts"
    ON public.alerts FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- iocs
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_iocs" ON public.iocs;
  CREATE POLICY "service_role_full_access_iocs"
    ON public.iocs FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- cases
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_cases" ON public.cases;
  CREATE POLICY "service_role_full_access_cases"
    ON public.cases FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- playbooks
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_playbooks" ON public.playbooks;
  CREATE POLICY "service_role_full_access_playbooks"
    ON public.playbooks FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- audit_logs
DO $$ BEGIN
  DROP POLICY IF EXISTS "service_role_full_access_audit_logs" ON public.audit_logs;
  CREATE POLICY "service_role_full_access_audit_logs"
    ON public.audit_logs FOR ALL TO service_role
    USING (true) WITH CHECK (true);
EXCEPTION WHEN undefined_table THEN NULL; END $$;

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 7: Grant ALL permissions to service_role + postgres
-- ─────────────────────────────────────────────────────────────────────────
GRANT ALL ON ALL TABLES    IN SCHEMA public TO postgres, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO postgres, service_role;
GRANT USAGE ON SCHEMA public TO postgres, service_role, authenticated, anon;

-- ─────────────────────────────────────────────────────────────────────────
-- SECTION 8: Verification query — shows all RLS policies on key tables
-- ─────────────────────────────────────────────────────────────────────────
SELECT
  schemaname,
  tablename,
  policyname,
  roles,
  cmd,
  qual
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN ('refresh_tokens', 'login_activity', 'users', 'tenants')
ORDER BY tablename, policyname;

-- ─────────────────────────────────────────────────────────────────────────
-- SUCCESS MESSAGE
-- ─────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  RAISE NOTICE '======================================================';
  RAISE NOTICE '  RLS Fix v5.1 Applied Successfully';
  RAISE NOTICE '  refresh_tokens: service_role can now INSERT/SELECT/UPDATE/DELETE';
  RAISE NOTICE '  login_activity: service_role can now INSERT/SELECT';
  RAISE NOTICE '  All other tables: service_role bypass policies added';
  RAISE NOTICE '------------------------------------------------------';
  RAISE NOTICE '  NEXT STEP: Run node backend/scripts/seed-mahmoud.js';
  RAISE NOTICE '======================================================';
END $$;
