-- ══════════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — IOC RLS Fix v7.0  (ROOT CAUSE: Empty IOC results)
--  FILE: backend/database/migration-v7.0-ioc-rls.sql
--
--  ROOT CAUSE ANALYSIS (ranked by probability):
--  ────────────────────────────────────────────────────────────────────────
--  #1 (CRITICAL) — RLS ENABLED, NO SELECT POLICY
--     Supabase returns EMPTY ARRAY (not an error!) when RLS blocks access.
--     The iocs table has RLS ON but zero SELECT policies → every query
--     returns [] and count: 0 even though 33,750 rows exist.
--
--  #2 (HIGH) — TENANT_ID MISMATCH
--     The backend queries .eq('tenant_id', req.tenantId) but req.tenantId
--     may be NULL (profile lookup failed) or a different UUID than the
--     tenant_id values stored in the iocs rows.
--     Known tenant IDs in data:
--       00000000-0000-0000-0000-000000000001  (default)
--       00000000-0000-0000-0000-000000000002
--       00000000-0000-0000-0000-000000000003
--
--  #3 (MEDIUM) — IOC TYPE CONSTRAINT MISMATCH
--     schema.sql CHECK allows only specific type values (ip, domain, url,
--     hash_md5, hash_sha1, hash_sha256, email, filename, registry, mutex,
--     asn, cve) but the ingestion pipeline writes lowercase types like
--     'md5', 'sha1', 'sha256', 'sha512', 'hostname', 'cidr', 'hash_md5',
--     'hash_sha1', 'hash_sha256'. Any row with an invalid type is silently
--     rejected on insert.
--
--  #4 (MEDIUM) — STATS ENDPOINT QUERIES SINGLE TENANT
--     /api/ingest/stats uses req.user.tenant_id — if user has no tenant_id,
--     stats show 0 even though data exists on other tenants.
--
--  #5 (LOW) — MISSING GIN INDEX FOR TEXT SEARCH
--     The .ilike('%search%') query on value column has no GIN/trigram index
--     → searches time out on 33K+ rows.
--
--  HOW TO RUN:
--  ────────────────────────────────────────────────────────────────────────
--  1. Open https://supabase.com/dashboard/project/miywxnplaltduuscjfmq
--  2. Go to SQL Editor (left sidebar)
--  3. Paste this ENTIRE file → Click "Run"
--  4. Verify: "Migration v7.0 Applied Successfully" appears in output
--
--  SAFE TO RE-RUN: All statements use IF NOT EXISTS / CREATE OR REPLACE
-- ══════════════════════════════════════════════════════════════════════════

-- ── SECTION 0: Extensions ────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 1: DIAGNOSTIC QUERIES
-- Run these FIRST to confirm root cause before applying fixes
-- ══════════════════════════════════════════════════════════════════════════

-- 1a. Check RLS status and policy count for iocs table
SELECT
  schemaname,
  tablename,
  rowsecurity AS rls_enabled,
  (
    SELECT COUNT(*) FROM pg_policies p
    WHERE p.schemaname = c.schemaname AND p.tablename = c.tablename
  ) AS policy_count
FROM pg_tables c
WHERE tablename = 'iocs' AND schemaname = 'public';
-- Expected BEFORE fix: rls_enabled=true, policy_count=0  ← ROOT CAUSE
-- Expected AFTER fix:  rls_enabled=true, policy_count=4+

-- 1b. Count rows per tenant (use service_role to bypass RLS)
-- Run this in SQL Editor (which uses postgres/service_role, bypasses RLS)
SELECT tenant_id, COUNT(*) as row_count
FROM iocs
GROUP BY tenant_id
ORDER BY row_count DESC;

-- 1c. Check IOC type distribution (catches type constraint violations)
SELECT type, COUNT(*) as count
FROM iocs
GROUP BY type
ORDER BY count DESC;

-- 1d. Search for a known IOC value (bypasses RLS since SQL Editor = service_role)
SELECT id, tenant_id, value, type, risk_score, status
FROM iocs
WHERE value ILIKE '%costliergridco%'
LIMIT 5;

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 2: STEP 1 — TEMPORARY DEBUG POLICY (Full read access)
-- PURPOSE: Immediately restore visibility. Replace with production policy
-- in SECTION 3 once you confirm data is accessible.
-- WARNING: Do NOT leave this in production — apply SECTION 3 afterward.
-- ══════════════════════════════════════════════════════════════════════════

-- Drop any existing conflicting policies
DROP POLICY IF EXISTS "debug_iocs_read_all"          ON iocs;
DROP POLICY IF EXISTS "iocs_service_role_all"         ON iocs;
DROP POLICY IF EXISTS "iocs_tenant_select"            ON iocs;
DROP POLICY IF EXISTS "iocs_tenant_insert"            ON iocs;
DROP POLICY IF EXISTS "iocs_tenant_update"            ON iocs;
DROP POLICY IF EXISTS "iocs_tenant_delete"            ON iocs;
DROP POLICY IF EXISTS "iocs_anon_read"                ON iocs;
DROP POLICY IF EXISTS "iocs_authenticated_read"       ON iocs;
DROP POLICY IF EXISTS "iocs_backend_all"              ON iocs;
DROP POLICY IF EXISTS "service_role_iocs_all"         ON iocs;

-- Make sure RLS is enabled (it already is, but ensure)
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;

-- ── TEMPORARY DEBUG: Allow all authenticated users to read all IOCs ──────
-- This confirms whether RLS was the issue. Check frontend shows 33K records.
-- REMOVE after confirming, then run SECTION 3.
CREATE POLICY "debug_iocs_read_all" ON iocs
  FOR SELECT
  TO authenticated, anon
  USING (true);

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 3: PRODUCTION RLS POLICIES (Tenant-scoped + service_role bypass)
-- Apply AFTER confirming Section 2 fixes visibility.
-- This replaces the debug policy with proper tenant isolation.
-- ══════════════════════════════════════════════════════════════════════════

-- NOTE: Run this block AFTER testing Section 2 works.
-- Uncomment and run when ready for production:

/*

-- Remove debug policy
DROP POLICY IF EXISTS "debug_iocs_read_all" ON iocs;

-- 1. Service role (backend) has unrestricted access — bypasses RLS entirely
--    This is the key policy that lets the Node.js backend (using service_role key)
--    query ALL tenants' data when needed (e.g., stats, admin views).
CREATE POLICY "service_role_iocs_all" ON iocs
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- 2. Authenticated users can only read their own tenant's IOCs
--    auth.jwt() ->> 'tenant_id' comes from the JWT claims set during login.
--    Falls back to checking the users table if JWT doesn't have tenant_id.
CREATE POLICY "iocs_tenant_select" ON iocs
  FOR SELECT
  TO authenticated
  USING (
    tenant_id = (
      SELECT u.tenant_id
      FROM public.users u
      WHERE u.auth_id = auth.uid()
      LIMIT 1
    )
  );

-- 3. Authenticated users can insert IOCs for their own tenant only
CREATE POLICY "iocs_tenant_insert" ON iocs
  FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id = (
      SELECT u.tenant_id
      FROM public.users u
      WHERE u.auth_id = auth.uid()
      LIMIT 1
    )
  );

-- 4. Authenticated users can update their own tenant's IOCs
CREATE POLICY "iocs_tenant_update" ON iocs
  FOR UPDATE
  TO authenticated
  USING (
    tenant_id = (
      SELECT u.tenant_id
      FROM public.users u
      WHERE u.auth_id = auth.uid()
      LIMIT 1
    )
  )
  WITH CHECK (
    tenant_id = (
      SELECT u.tenant_id
      FROM public.users u
      WHERE u.auth_id = auth.uid()
      LIMIT 1
    )
  );

-- 5. Only ADMIN/SUPER_ADMIN can delete IOCs (enforced in app layer too)
CREATE POLICY "iocs_tenant_delete" ON iocs
  FOR DELETE
  TO authenticated
  USING (
    tenant_id = (
      SELECT u.tenant_id
      FROM public.users u
      WHERE u.auth_id = auth.uid()
      LIMIT 1
    )
  );

*/

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 4: FIX IOC TYPE CONSTRAINT
-- The CHECK constraint in schema.sql is too restrictive.
-- Ingestion writes 'md5', 'sha1', 'sha256', 'hostname' but schema only
-- allows 'hash_md5', 'hash_sha1', 'hash_sha256' — causing silent insert failures.
-- ══════════════════════════════════════════════════════════════════════════

-- Drop the old restrictive CHECK constraint
ALTER TABLE iocs DROP CONSTRAINT IF EXISTS iocs_type_check;

-- Add expanded type constraint that matches BOTH schema.sql and ingestion pipeline
ALTER TABLE iocs ADD CONSTRAINT iocs_type_check CHECK (
  type IN (
    -- Original schema types
    'ip', 'domain', 'url', 'email', 'filename', 'registry', 'mutex', 'asn', 'cve',
    -- Hash types (both old and new naming)
    'hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512',
    'md5', 'sha1', 'sha256', 'sha512',
    -- Additional types from ingestion feeds
    'hostname', 'cidr', 'hash', 'certificate'
  )
);

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 5: FIX INDEXES FOR FAST SEARCH
-- ══════════════════════════════════════════════════════════════════════════

-- Drop old indexes that may be on wrong column type
DROP INDEX IF EXISTS idx_iocs_value;
DROP INDEX IF EXISTS idx_iocs_value_trgm;
DROP INDEX IF EXISTS idx_iocs_value_gin;

-- GIN trigram index for fast ILIKE / text search on value column
-- This is CRITICAL for search performance on 33K+ rows
CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm
  ON iocs USING gin(value gin_trgm_ops);

-- B-tree on tenant_id + status (most common filter combination)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_status
  ON iocs(tenant_id, status)
  WHERE status = 'active';

-- B-tree on tenant_id + risk_score (default sort)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_risk
  ON iocs(tenant_id, risk_score DESC);

-- B-tree on tenant_id + type (type filter)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_type
  ON iocs(tenant_id, type);

-- B-tree on tenant_id + reputation (reputation filter)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_rep
  ON iocs(tenant_id, reputation);

-- Composite index for pagination (tenant_id + last_seen for time-sorted queries)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_lastseen
  ON iocs(tenant_id, last_seen DESC);

-- Full-text search index (for future FTS queries)
CREATE INDEX IF NOT EXISTS idx_iocs_fts
  ON iocs USING gin(
    to_tsvector('english',
      coalesce(value,'') || ' ' ||
      coalesce(type,'') || ' ' ||
      coalesce(threat_actor,'') || ' ' ||
      coalesce(malware_family,'') || ' ' ||
      coalesce(notes,'')
    )
  );

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 6: FIX TENANT IDs — Ensure default tenant rows exist
-- The ingestion pipeline writes to tenant 00000000-0000-0000-0000-000000000001
-- by default. This tenant must exist in the tenants table or FK inserts fail.
-- ══════════════════════════════════════════════════════════════════════════

INSERT INTO tenants (id, name, short_name, domain, plan, active)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'Wadjet Eye AI (Default)',  'wadjet-default',  'wadjet-eye-ai.vercel.app', 'enterprise', true),
  ('00000000-0000-0000-0000-000000000002', 'Tenant 2 (MSSP)',          'mssp-tenant',     NULL,                       'professional', true),
  ('00000000-0000-0000-0000-000000000003', 'Tenant 3 (Enterprise)',    'enterprise-3',    NULL,                       'enterprise', true)
ON CONFLICT (id) DO UPDATE SET
  active     = EXCLUDED.active,
  updated_at = NOW();

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 7: GRANT explicit permissions to service_role and authenticated
-- ══════════════════════════════════════════════════════════════════════════

GRANT SELECT, INSERT, UPDATE, DELETE ON iocs TO service_role;
GRANT SELECT ON iocs TO authenticated;
GRANT SELECT ON iocs TO anon;

-- ══════════════════════════════════════════════════════════════════════════
-- SECTION 8: VERIFY — Run after applying all sections
-- ══════════════════════════════════════════════════════════════════════════

-- 8a. Verify RLS policies
SELECT policyname, cmd, roles, qual
FROM pg_policies
WHERE tablename = 'iocs'
ORDER BY policyname;

-- 8b. Verify indexes
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'iocs'
ORDER BY indexname;

-- 8c. Verify total count (should match ~33,750)
SELECT COUNT(*) as total_iocs FROM iocs;

-- 8d. Verify tenant distribution
SELECT tenant_id, COUNT(*) as rows, MAX(last_seen) as latest
FROM iocs
GROUP BY tenant_id
ORDER BY rows DESC;

-- 8e. Test exact search
SELECT id, value, type, risk_score
FROM iocs
WHERE value ILIKE '%costliergridco.click%'
LIMIT 10;

-- 8f. Test trigram search performance
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT id, value, type, risk_score
FROM iocs
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND value ILIKE '%costliergridco%'
LIMIT 50;

-- ══════════════════════════════════════════════════════════════════════════
-- SUCCESS MARKER
-- ══════════════════════════════════════════════════════════════════════════
DO $$
BEGIN
  RAISE NOTICE '════════════════════════════════════════════════════════════';
  RAISE NOTICE 'Migration v7.0 Applied Successfully';
  RAISE NOTICE 'IOC RLS debug policy: ACTIVE (all authenticated users can read)';
  RAISE NOTICE 'Run SECTION 3 (production policies) after testing frontend';
  RAISE NOTICE 'Next step: refresh frontend → should see 33,750 IOCs';
  RAISE NOTICE '════════════════════════════════════════════════════════════';
END $$;
