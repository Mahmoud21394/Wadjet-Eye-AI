-- ══════════════════════════════════════════════════════════════════════════════
--  migration-auth-fk-rls-fix.sql
--  Wadjet-Eye AI — Auth FK Ambiguity + RLS Fix  (v18.0)
--
--  PURPOSE
--  ───────
--  Fixes two root causes that together produce the DB errors observed in logs:
--
--   1.  PGRST200 / PGRST201 — "Could not embed because more than one relationship
--       was found for 'refresh_tokens' and 'users'"
--       Caused by a second (stale) foreign-key constraint on refresh_tokens that
--       points to users.  PostgREST cannot resolve the embed without an explicit
--       FK hint.  This migration drops the ambiguous second FK, leaving only the
--       canonical user_id → users(id) constraint.
--
--   2.  42501 — "new row violates row-level security policy for table
--       'refresh_tokens'"
--       Even when calling through the service_role client, a missing or
--       misconfigured policy can block inserts.  This migration enables RLS
--       (idempotent) and creates a single blanket service_role_full_access
--       policy that lets the backend's service-role client do everything.
--
--  IDEMPOTENT
--  ──────────
--  All statements use IF EXISTS / IF NOT EXISTS / OR REPLACE guards so the
--  script can be run multiple times without error.
--
--  HOW TO RUN
--  ──────────
--  Option A — Supabase SQL Editor (recommended):
--    Paste the full script into the SQL Editor and click "Run".
--
--  Option B — psql:
--    psql "$DATABASE_URL" -f migration-auth-fk-rls-fix.sql
--
--  VERIFICATION
--  ────────────
--  After running, execute the verification queries at the bottom of this file.
--  Expected results:
--    • fk_count = 1   (only one FK from refresh_tokens to users)
--    • rls_enabled = true
--    • service_role_policy = present
-- ══════════════════════════════════════════════════════════════════════════════

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 1: Drop the ambiguous second foreign key on refresh_tokens → users
-- ─────────────────────────────────────────────────────────────────────────────
-- The original migration-v5.0-auth-tables.sql creates the canonical FK:
--   user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE
-- which PostgreSQL names automatically as  refresh_tokens_user_id_fkey.
--
-- If a second FK was later added (e.g. created_by → users(id), or a duplicate
-- user_id FK under a different name), PostgREST PGRST200/PGRST201 is triggered
-- on every embed query.  The block below identifies and drops any FK whose
-- name is NOT the canonical  refresh_tokens_user_id_fkey  and whose target
-- table is public.users.  The canonical FK is left untouched.
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
  _rec RECORD;
BEGIN
  FOR _rec IN
    SELECT tc.constraint_name
    FROM   information_schema.table_constraints  tc
    JOIN   information_schema.referential_constraints rc
           ON  rc.constraint_name    = tc.constraint_name
           AND rc.constraint_schema  = tc.constraint_schema
    JOIN   information_schema.table_constraints tc2
           ON  tc2.constraint_name   = rc.unique_constraint_name
           AND tc2.table_schema      = 'public'
           AND tc2.table_name        = 'users'
    WHERE  tc.constraint_type  = 'FOREIGN KEY'
    AND    tc.table_schema     = 'public'
    AND    tc.table_name       = 'refresh_tokens'
    AND    tc.constraint_name <> 'refresh_tokens_user_id_fkey'
  LOOP
    RAISE NOTICE 'Dropping ambiguous FK constraint: %', _rec.constraint_name;
    EXECUTE format(
      'ALTER TABLE public.refresh_tokens DROP CONSTRAINT IF EXISTS %I',
      _rec.constraint_name
    );
  END LOOP;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 2: Ensure the canonical FK exists with the expected name
-- ─────────────────────────────────────────────────────────────────────────────
-- If the canonical FK was accidentally dropped (or was named differently),
-- re-create it.  The IF NOT EXISTS guard makes this a no-op when it already
-- exists under the correct name.
-- ─────────────────────────────────────────────────────────────────────────────

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM   information_schema.table_constraints
    WHERE  constraint_name  = 'refresh_tokens_user_id_fkey'
    AND    table_schema     = 'public'
    AND    table_name       = 'refresh_tokens'
    AND    constraint_type  = 'FOREIGN KEY'
  ) THEN
    RAISE NOTICE 'Canonical FK missing — re-creating refresh_tokens_user_id_fkey';
    ALTER TABLE public.refresh_tokens
      ADD CONSTRAINT refresh_tokens_user_id_fkey
      FOREIGN KEY (user_id)
      REFERENCES public.users(id)
      ON DELETE CASCADE;
  ELSE
    RAISE NOTICE 'Canonical FK refresh_tokens_user_id_fkey already exists — no action needed';
  END IF;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 3: Enable Row-Level Security (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_activity  ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 4: Grant table privileges to service_role and postgres
-- ─────────────────────────────────────────────────────────────────────────────
-- The service_role bypasses RLS by default in Supabase, but explicit GRANT
-- is required in projects that have had REVOKE ALL run against them.
-- ─────────────────────────────────────────────────────────────────────────────

GRANT ALL ON public.refresh_tokens TO postgres, service_role;
GRANT ALL ON public.login_activity  TO postgres, service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 5: service_role_full_access policy (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────
-- Drop all known previous policy names first so there are no duplicates, then
-- create the single canonical policy.
--
-- NOTE: In Supabase the service_role client has BYPASSRLS=on by default.
-- This policy is an explicit safety net for projects where that default was
-- overridden, or where a Supabase upgrade changed the role behaviour.
-- ─────────────────────────────────────────────────────────────────────────────

-- refresh_tokens ──────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "service_role_full_access"       ON public.refresh_tokens;
DROP POLICY IF EXISTS "service_role_full_access_rt"    ON public.refresh_tokens;
DROP POLICY IF EXISTS "allow_service_role"             ON public.refresh_tokens;
DROP POLICY IF EXISTS "enable_all_for_service_role"    ON public.refresh_tokens;
DROP POLICY IF EXISTS "postgres_full_access_rt"        ON public.refresh_tokens;
DROP POLICY IF EXISTS "backend_all_refresh_tokens"     ON public.refresh_tokens;
DROP POLICY IF EXISTS "backend_insert_refresh_tokens"  ON public.refresh_tokens;
DROP POLICY IF EXISTS "anon_insert_refresh_tokens"     ON public.refresh_tokens;

CREATE POLICY "service_role_full_access"
  ON public.refresh_tokens
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Allow authenticated users to read / delete their own tokens (optional but
-- enables the /sessions and DELETE /sessions endpoints to function without
-- the service-role client for those specific reads).
DROP POLICY IF EXISTS "user_read_own_tokens"   ON public.refresh_tokens;
DROP POLICY IF EXISTS "user_delete_own_tokens" ON public.refresh_tokens;
DROP POLICY IF EXISTS "user_update_own_tokens" ON public.refresh_tokens;

CREATE POLICY "user_read_own_tokens"
  ON public.refresh_tokens
  FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "user_delete_own_tokens"
  ON public.refresh_tokens
  FOR DELETE
  TO authenticated
  USING (user_id = auth.uid());

-- login_activity ──────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS "service_role_full_access"    ON public.login_activity;
DROP POLICY IF EXISTS "service_role_full_access_la" ON public.login_activity;

CREATE POLICY "service_role_full_access"
  ON public.login_activity
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────────
-- SECTION 6: Ensure required indexes exist (idempotent)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_rt_token_hash ON public.refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_rt_user_id    ON public.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires    ON public.refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_rt_revoked    ON public.refresh_tokens(is_revoked);

COMMIT;

-- ─────────────────────────────────────────────────────────────────────────────
-- VERIFICATION QUERIES  (run manually after the migration to confirm success)
-- ─────────────────────────────────────────────────────────────────────────────

/*
-- 1. Confirm exactly ONE FK from refresh_tokens → users  (fk_count must be 1)
SELECT COUNT(*) AS fk_count
FROM   information_schema.table_constraints  tc
JOIN   information_schema.referential_constraints rc
       ON  rc.constraint_name   = tc.constraint_name
       AND rc.constraint_schema = tc.constraint_schema
JOIN   information_schema.table_constraints tc2
       ON  tc2.constraint_name  = rc.unique_constraint_name
       AND tc2.table_schema     = 'public'
       AND tc2.table_name       = 'users'
WHERE  tc.constraint_type = 'FOREIGN KEY'
AND    tc.table_schema    = 'public'
AND    tc.table_name      = 'refresh_tokens';
-- Expected: 1

-- 2. Confirm RLS is enabled on refresh_tokens  (relrowsecurity must be true)
SELECT relname, relrowsecurity AS rls_enabled
FROM   pg_class
JOIN   pg_namespace ON pg_namespace.oid = pg_class.relnamespace
WHERE  pg_namespace.nspname = 'public'
AND    relname IN ('refresh_tokens', 'login_activity');
-- Expected: both rows show rls_enabled = true

-- 3. Confirm the service_role_full_access policy exists
SELECT polname, polroles::regrole[], polcmd
FROM   pg_policy
JOIN   pg_class   ON pg_class.oid   = pg_policy.polrelid
JOIN   pg_namespace ON pg_namespace.oid = pg_class.relnamespace
WHERE  pg_namespace.nspname = 'public'
AND    relname = 'refresh_tokens';
-- Expected: row with polname = 'service_role_full_access', polroles = {service_role}, polcmd = *

-- 4. Confirm the canonical FK name
SELECT constraint_name
FROM   information_schema.table_constraints
WHERE  constraint_type = 'FOREIGN KEY'
AND    table_schema    = 'public'
AND    table_name      = 'refresh_tokens';
-- Expected: refresh_tokens_user_id_fkey  (only one row)
*/
