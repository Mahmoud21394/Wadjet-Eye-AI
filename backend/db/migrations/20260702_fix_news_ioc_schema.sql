-- ══════════════════════════════════════════════════════════════════════════════
-- Wadjet-Eye AI — Fix News + IOC schema errors
-- backend/db/migrations/20260702_fix_news_ioc_schema.sql
--
-- Fixes these runtime errors:
--   [News] image_url column missing
--   [News] there is no unique or exclusion constraint matching ON CONFLICT
--   [Correlate] IOC fetch error: canceling statement due to statement timeout
--   [Ingestion] upsert error: canceling statement due to statement timeout
--   [News] DB upsert error: invalid input value for enum severity_level
--   [Exposure] Failed to fetch assets: column asset_inventory.name does not exist
--
-- Run in: Supabase Dashboard → SQL Editor → paste → Run
-- Safe to run multiple times (all use IF NOT EXISTS / DO $$ blocks)
-- ══════════════════════════════════════════════════════════════════════════════

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 1: news_articles — add image_url column
-- Error: [News] image_url column missing — retrying without it
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE news_articles
  ADD COLUMN IF NOT EXISTS image_url TEXT;

-- Ensure external_guid column exists (required for unique index below)
ALTER TABLE news_articles
  ADD COLUMN IF NOT EXISTS external_guid TEXT;

-- Ensure tenant_id column exists
ALTER TABLE news_articles
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 2: news_articles — unique index for ON CONFLICT (tenant_id, external_guid)
-- Error: there is no unique or exclusion constraint matching ON CONFLICT specification
-- The news ingestion upsert uses: { onConflict: 'tenant_id,external_guid' }
-- PostgreSQL requires a real UNIQUE index for this to work.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS uq_news_articles_tenant_guid
  ON news_articles (tenant_id, external_guid);

-- Single-column fallback index (used by ignoreDuplicates fallback path)
CREATE UNIQUE INDEX IF NOT EXISTS uq_news_articles_guid
  ON news_articles (external_guid)
  WHERE tenant_id IS NULL;

-- Performance indexes for news list queries
CREATE INDEX IF NOT EXISTS idx_news_articles_tenant_published
  ON news_articles (tenant_id, published_at DESC);

CREATE INDEX IF NOT EXISTS idx_news_articles_tenant_category
  ON news_articles (tenant_id, category);

CREATE INDEX IF NOT EXISTS idx_news_articles_tenant_severity
  ON news_articles (tenant_id, severity);

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 3: iocs — indexes to eliminate statement timeouts
--
-- Error: [Correlate] IOC fetch error: canceling statement due to statement timeout
-- Query: SELECT ... FROM iocs
--          WHERE tenant_id=? AND status='active' AND created_at>=?
--          ORDER BY risk_score DESC LIMIT 500
-- Without an index this does a sequential scan of the entire iocs table.
--
-- Error: [Ingestion] upsert error: canceling statement due to statement timeout
-- Upsert: { onConflict: 'tenant_id,value' }
-- Requires a UNIQUE index on (tenant_id, value) — without it PostgreSQL
-- falls back to a full table scan for conflict detection.
-- ─────────────────────────────────────────────────────────────────────────────

-- 3a. UNIQUE index for ingestion upsert ON CONFLICT (tenant_id, value)
--     MOST CRITICAL — eliminates full-table scan on every IOC upsert
CREATE UNIQUE INDEX IF NOT EXISTS uq_iocs_tenant_value
  ON iocs (tenant_id, value);

-- 3b. Composite index covering the Correlate query exactly
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_status_date_risk
  ON iocs (tenant_id, status, created_at DESC, risk_score DESC);

-- 3c. General tenant + status filter index
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_status
  ON iocs (tenant_id, status);

-- 3d. Tenant + date range scans
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_created
  ON iocs (tenant_id, created_at DESC);

-- 3e. Value lookups (enrichment / dedup queries)
CREATE INDEX IF NOT EXISTS idx_iocs_value
  ON iocs (value);

-- 3f. Type filter (common in list/filter queries)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_type
  ON iocs (tenant_id, type);

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 4: outbox_events table (WS9 — stops [OutboxPattern] relay errors)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS outbox_events (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type      TEXT        NOT NULL,
  aggregate_type  TEXT        NOT NULL,
  aggregate_id    TEXT,
  tenant_id       UUID,
  payload         JSONB       NOT NULL DEFAULT '{}',
  trace_id        TEXT,
  status          TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'published', 'failed')),
  retry_count     INTEGER     DEFAULT 0,
  last_error      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  published_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending
  ON outbox_events (status, created_at)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_outbox_tenant
  ON outbox_events (tenant_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 5: news_articles.severity — convert from ENUM to TEXT
--
-- Error: [News] DB upsert error: invalid input value for enum severity_level: "medium"
--
-- Root cause: In some deployments the news_articles.severity column was created
-- with the severity_level ENUM type, but the production enum instance differs
-- from the migration definition, causing valid values like 'medium'/'high'/'low'
-- to be rejected with "invalid input value for enum severity_level".
--
-- Fix: Convert the column to plain TEXT. The application already validates
-- severity values via classifySeverity() which only returns valid values.
-- A CHECK constraint is added for defence-in-depth.
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
  -- Only convert if the column is currently an enum type (not TEXT already)
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name  = 'news_articles'
      AND column_name = 'severity'
      AND data_type   = 'USER-DEFINED'
  ) THEN
    -- Cast to TEXT (preserves existing data, removes enum constraint)
    ALTER TABLE news_articles
      ALTER COLUMN severity TYPE TEXT USING severity::TEXT;

    RAISE NOTICE 'news_articles.severity converted from ENUM to TEXT';
  ELSE
    RAISE NOTICE 'news_articles.severity is already TEXT — no conversion needed';
  END IF;
END $$;

-- Add CHECK constraint so only valid values are accepted at the DB layer
-- (defence-in-depth — the app layer also validates via classifySeverity())
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'news_articles'::regclass
      AND conname  = 'news_articles_severity_check'
  ) THEN
    ALTER TABLE news_articles
      ADD CONSTRAINT news_articles_severity_check
      CHECK (severity IN ('critical','high','medium','low','informational','unknown'));
    RAISE NOTICE 'news_articles_severity_check constraint added';
  ELSE
    RAISE NOTICE 'news_articles_severity_check already exists — skipping';
  END IF;
END $$;

-- Set a sensible default for rows that have NULL severity
UPDATE news_articles
  SET severity = 'medium'
  WHERE severity IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- FIX 6: asset_inventory.name — add missing column
--
-- Error: [Exposure] Failed to fetch assets: column asset_inventory.name does not exist
--
-- Root cause: The asset_inventory table was created without the `name` column
-- in some deployment paths (the column is defined in migration-v5.2-live-cti.sql
-- as NOT NULL, but that migration may not have run, or the table was created
-- differently).
--
-- Fix: Add the column with a safe default (NOT NULL default 'Unknown Asset').
-- Existing rows get default='Unknown Asset'; new rows must supply a real name.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE asset_inventory
  ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT 'Unknown Asset';

-- Also ensure hostname column exists (used in exposure correlation)
ALTER TABLE asset_inventory
  ADD COLUMN IF NOT EXISTS hostname TEXT;

-- Performance index for the ilike search in GET /api/exposure/assets?search=
CREATE INDEX IF NOT EXISTS idx_asset_inventory_name_trgm
  ON asset_inventory USING GIN (name gin_trgm_ops);

COMMIT;

-- ══════════════════════════════════════════════════════════════════════════════
-- VERIFY — run these queries after the migration to confirm everything worked:
--
-- 1. Check news_articles columns (should include image_url, external_guid):
--    SELECT column_name, data_type
--    FROM information_schema.columns
--    WHERE table_name = 'news_articles'
--    ORDER BY ordinal_position;
--
-- 2. Confirm news_articles.severity is now TEXT (not USER-DEFINED):
--    SELECT column_name, data_type, udt_name
--    FROM information_schema.columns
--    WHERE table_name = 'news_articles' AND column_name = 'severity';
--
-- 3. Check news_articles indexes (should include uq_news_articles_tenant_guid):
--    SELECT indexname, indexdef
--    FROM pg_indexes
--    WHERE tablename = 'news_articles';
--
-- 4. Check iocs indexes (should include uq_iocs_tenant_value):
--    SELECT indexname, indexdef
--    FROM pg_indexes
--    WHERE tablename = 'iocs';
--
-- 5. Confirm outbox_events exists:
--    SELECT COUNT(*) FROM outbox_events;
--
-- 6. Confirm asset_inventory has name column:
--    SELECT column_name, data_type, column_default
--    FROM information_schema.columns
--    WHERE table_name = 'asset_inventory' AND column_name = 'name';
-- ══════════════════════════════════════════════════════════════════════════════
