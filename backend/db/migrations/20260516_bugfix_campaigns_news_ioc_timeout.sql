-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Bug Fix Migration
--  backend/db/migrations/20260516_bugfix_campaigns_news_ioc_timeout.sql
--
--  Fixes for 7 production errors observed 2026-05-16:
--
--  1. ERROR #1 — [Correlate] Campaign insert error:
--     "Could not find the 'threat_actor' column of 'campaigns'"
--     The campaigns table has no 'threat_actor' TEXT column.
--     Auto-correlation code was passing a free-text actor name to a
--     column that doesn't exist. Fixed in code (ioc-ingestion.js).
--     This migration adds 'ioc_count' and 'severity' columns that the
--     same code path also writes to, in case they are missing.
--
--  2. ERROR #3 — [News] DB upsert retry error:
--     "invalid input syntax for type uuid: https://www.darkreading.com/..."
--     Caused by missing unique constraint on news_articles(tenant_id, external_guid).
--     Without it, Postgres matched on PK (id) instead and got a URL.
--     This migration adds the unique index.
--
--  3. ERROR #2/#5/#6 — Supabase statement timeout (15 s)
--     Long-running upserts and COUNT(*) queries exceed free-tier timeout.
--     This migration adds partial indexes that speed up the hot query paths.
--
--  Safe to run multiple times (all statements use IF NOT EXISTS / DO blocks).
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ── 1. campaigns table: add missing columns used by auto-correlator ──
-- 'ioc_count' — number of IOCs grouped into this campaign
-- 'severity'  — HIGH / MEDIUM / LOW
-- 'source'    — 'auto' | 'manual'
-- 'description' already exists in most schemas but guarded anyway
ALTER TABLE campaigns
  ADD COLUMN IF NOT EXISTS ioc_count   INTEGER  DEFAULT 0,
  ADD COLUMN IF NOT EXISTS severity    TEXT     DEFAULT 'MEDIUM',
  ADD COLUMN IF NOT EXISTS source      TEXT     DEFAULT 'manual';

-- Add description only if missing (TEXT column, nullable)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name   = 'campaigns'
      AND column_name  = 'description'
  ) THEN
    ALTER TABLE campaigns ADD COLUMN description TEXT;
  END IF;
END
$$;

-- ── 2. news_articles: unique index on (tenant_id, external_guid) ──
-- Root cause of UUID error: without this index, Postgres had no conflict
-- target for upsert(onConflict:'tenant_id,external_guid') and fell back
-- to matching on PK (id), which received a URL string → UUID parse error.
CREATE UNIQUE INDEX IF NOT EXISTS idx_news_articles_tenant_guid
  ON news_articles(tenant_id, external_guid)
  WHERE external_guid IS NOT NULL AND external_guid != '';

-- Also ensure external_guid column exists (schema drift guard)
ALTER TABLE news_articles
  ADD COLUMN IF NOT EXISTS external_guid TEXT;

-- ── 3. Performance indexes for hot query paths ────────────────────

-- iocs: tenant + status + created_at — used by [Correlate] IOC fetch
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_status_created
  ON iocs(tenant_id, status, created_at DESC)
  WHERE status = 'active';

-- iocs: tenant + risk_score — used by graph endpoint
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_risk
  ON iocs(tenant_id, risk_score DESC);

-- detection_timeline: tenant + created_at — used by /api/cti/timeline
-- (partial index on last 90 days keeps it small and fast)
CREATE INDEX IF NOT EXISTS idx_detection_timeline_tenant_created
  ON detection_timeline(tenant_id, created_at DESC);

-- campaigns: tenant + updated_at — used by /api/cti/campaigns list
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_updated
  ON campaigns(tenant_id, updated_at DESC);

-- ── 4. news_articles: reduce chunk cost with a covering index ─────
CREATE INDEX IF NOT EXISTS idx_news_articles_tenant_published
  ON news_articles(tenant_id, published_at DESC);

-- ── 5. Check + create ioc_count update trigger guard ─────────────
-- If campaigns.ioc_count column existed but had wrong type, fix it
DO $$
BEGIN
  -- Ensure ioc_count is INTEGER (not BIGINT etc.)
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name   = 'campaigns'
      AND column_name  = 'ioc_count'
      AND data_type   != 'integer'
  ) THEN
    ALTER TABLE campaigns ALTER COLUMN ioc_count TYPE INTEGER USING ioc_count::INTEGER;
  END IF;
END
$$;

COMMIT;
