-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Database Migration v5.3
--  backend/database/migration-v5.3-threat-actors.sql
--
--  WHAT THIS MIGRATION DOES:
--  ─────────────────────────
--  1. Adds missing columns to threat_actors table
--  2. Adds unique constraint on (tenant_id, name) for upsert
--  3. Creates indexes for filtering performance
--  4. Grants service_role bypass for all new tables
--  5. RLS policies for threat_actors so frontend can read
--  6. Feed auth validation table for tracking API key errors
--
--  HOW TO APPLY:
--  ─────────────
--  Option A — Supabase Dashboard:
--    1. Go to https://supabase.com/dashboard/project/miywxnplaltduuscjfmq
--    2. Navigate to SQL Editor
--    3. Paste this entire file and click Run
--
--  Option B — CLI:
--    psql $DATABASE_URL < backend/database/migration-v5.3-threat-actors.sql
-- ══════════════════════════════════════════════════════════════════

-- ── Enable required extensions ───────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ══════════════════════════════════════════════════════════════════
--  1. THREAT ACTORS TABLE — ensure all columns exist
-- ══════════════════════════════════════════════════════════════════

-- Create table if it doesn't exist
CREATE TABLE IF NOT EXISTS threat_actors (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  name             TEXT NOT NULL,
  description      TEXT,
  motivation       TEXT,
  sophistication   TEXT,
  origin_country   TEXT,
  active_since     TIMESTAMPTZ,
  last_seen        TIMESTAMPTZ,
  target_sectors   TEXT[]    DEFAULT '{}',
  target_countries TEXT[]    DEFAULT '{}',
  ttps             TEXT[]    DEFAULT '{}',
  tools            TEXT[]    DEFAULT '{}',
  malware          TEXT[]    DEFAULT '{}',
  aliases          TEXT[]    DEFAULT '{}',
  tags             TEXT[]    DEFAULT '{}',
  confidence       INTEGER   DEFAULT 50,
  source           TEXT      DEFAULT 'manual',
  external_id      TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Add missing columns (safe — uses IF NOT EXISTS)
DO $$
BEGIN
  -- source column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='source') THEN
    ALTER TABLE threat_actors ADD COLUMN source TEXT DEFAULT 'manual';
  END IF;

  -- external_id column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='external_id') THEN
    ALTER TABLE threat_actors ADD COLUMN external_id TEXT;
  END IF;

  -- confidence column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='confidence') THEN
    ALTER TABLE threat_actors ADD COLUMN confidence INTEGER DEFAULT 50;
  END IF;

  -- aliases array column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='aliases') THEN
    ALTER TABLE threat_actors ADD COLUMN aliases TEXT[] DEFAULT '{}';
  END IF;

  -- malware array column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='malware') THEN
    ALTER TABLE threat_actors ADD COLUMN malware TEXT[] DEFAULT '{}';
  END IF;

  -- tools array column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='tools') THEN
    ALTER TABLE threat_actors ADD COLUMN tools TEXT[] DEFAULT '{}';
  END IF;

  -- ttps array column
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='threat_actors' AND column_name='ttps') THEN
    ALTER TABLE threat_actors ADD COLUMN ttps TEXT[] DEFAULT '{}';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- ── Unique constraint on (tenant_id, name) for upsert ────────────
-- Drop existing constraint if it has a different name
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'threat_actors_tenant_name_unique'
  ) THEN
    ALTER TABLE threat_actors
      ADD CONSTRAINT threat_actors_tenant_name_unique
      UNIQUE (tenant_id, name);
  END IF;
EXCEPTION WHEN duplicate_table THEN NULL;
END;
$$ LANGUAGE plpgsql;

-- ── Indexes for performance ───────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_threat_actors_tenant_id     ON threat_actors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_threat_actors_motivation    ON threat_actors (motivation);
CREATE INDEX IF NOT EXISTS idx_threat_actors_sophistication ON threat_actors (sophistication);
CREATE INDEX IF NOT EXISTS idx_threat_actors_origin_country ON threat_actors (origin_country);
CREATE INDEX IF NOT EXISTS idx_threat_actors_last_seen     ON threat_actors (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_threat_actors_source        ON threat_actors (source);
CREATE INDEX IF NOT EXISTS idx_threat_actors_name_trgm     ON threat_actors USING gin (name gin_trgm_ops);

-- ── Auto-update updated_at ────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_threat_actors_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_threat_actors_updated_at ON threat_actors;
CREATE TRIGGER trg_threat_actors_updated_at
  BEFORE UPDATE ON threat_actors
  FOR EACH ROW EXECUTE FUNCTION update_threat_actors_updated_at();

-- ══════════════════════════════════════════════════════════════════
--  2. RLS POLICIES — allow reads + service_role writes
-- ══════════════════════════════════════════════════════════════════

ALTER TABLE threat_actors ENABLE ROW LEVEL SECURITY;

-- Drop old policies
DROP POLICY IF EXISTS "threat_actors_select" ON threat_actors;
DROP POLICY IF EXISTS "threat_actors_insert" ON threat_actors;
DROP POLICY IF EXISTS "threat_actors_update" ON threat_actors;
DROP POLICY IF EXISTS "threat_actors_delete" ON threat_actors;
DROP POLICY IF EXISTS "service_role_bypass_threat_actors" ON threat_actors;

-- Allow authenticated users to read actors for their tenant (or global)
CREATE POLICY "threat_actors_select"
  ON threat_actors FOR SELECT
  TO authenticated
  USING (
    tenant_id::text = current_setting('request.jwt.claims', true)::json->>'tenant_id'
    OR tenant_id = '00000000-0000-0000-0000-000000000001'::uuid
  );

-- Service role can do everything (bypasses RLS for backend ingestion)
CREATE POLICY "service_role_bypass_threat_actors"
  ON threat_actors
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Authenticated users can insert (for manual creation)
CREATE POLICY "threat_actors_insert"
  ON threat_actors FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- Authenticated users can update their own tenant's actors
CREATE POLICY "threat_actors_update"
  ON threat_actors FOR UPDATE
  TO authenticated
  USING (
    tenant_id::text = current_setting('request.jwt.claims', true)::json->>'tenant_id'
  );

-- ══════════════════════════════════════════════════════════════════
--  3. FEED AUTH LOG TABLE — track API key validation results
-- ══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS feed_auth_log (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  feed_name   TEXT NOT NULL,
  auth_type   TEXT,           -- 'api-key', 'bearer', 'no-auth', etc.
  env_key     TEXT,           -- env variable name (not value!)
  key_present BOOLEAN NOT NULL DEFAULT false,
  valid       BOOLEAN,        -- NULL = not tested, true/false = test result
  http_status INTEGER,
  error       TEXT,
  tested_at   TIMESTAMPTZ DEFAULT NOW(),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feed_auth_log_feed_name ON feed_auth_log (feed_name);
CREATE INDEX IF NOT EXISTS idx_feed_auth_log_tested_at ON feed_auth_log (tested_at DESC);

ALTER TABLE feed_auth_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_bypass_feed_auth_log"
  ON feed_auth_log TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "feed_auth_log_select"
  ON feed_auth_log FOR SELECT TO authenticated USING (true);

-- ══════════════════════════════════════════════════════════════════
--  4. ENSURE IOC TABLE HAS threat_actor COLUMN
-- ══════════════════════════════════════════════════════════════════

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='iocs' AND column_name='threat_actor') THEN
    ALTER TABLE iocs ADD COLUMN threat_actor TEXT;
  END IF;
END;
$$ LANGUAGE plpgsql;

CREATE INDEX IF NOT EXISTS idx_iocs_threat_actor ON iocs (threat_actor);

-- ══════════════════════════════════════════════════════════════════
--  5. ENSURE CAMPAIGNS TABLE HAS actor_id FK
-- ══════════════════════════════════════════════════════════════════

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_name='campaigns' AND column_name='actor_id') THEN
    ALTER TABLE campaigns ADD COLUMN actor_id UUID REFERENCES threat_actors(id) ON DELETE SET NULL;
  END IF;
END;
$$ LANGUAGE plpgsql;

CREATE INDEX IF NOT EXISTS idx_campaigns_actor_id ON campaigns (actor_id);

-- ══════════════════════════════════════════════════════════════════
--  6. CTI FEED LOGS — ensure cti_feed_logs table exists
--     (Some deployments use 'feed_logs', others 'cti_feed_logs')
-- ══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cti_feed_logs (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  feed_name    TEXT NOT NULL,
  action       TEXT NOT NULL DEFAULT 'ingest',
  status       TEXT NOT NULL DEFAULT 'success',  -- 'success' | 'error' | 'empty'
  iocs_fetched INTEGER DEFAULT 0,
  iocs_new     INTEGER DEFAULT 0,
  error        TEXT,
  auth_error   BOOLEAN DEFAULT false,
  metadata     JSONB DEFAULT '{}',
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ DEFAULT NOW(),
  duration_ms  INTEGER,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cti_feed_logs_tenant     ON cti_feed_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cti_feed_logs_feed_name  ON cti_feed_logs (feed_name);
CREATE INDEX IF NOT EXISTS idx_cti_feed_logs_finished   ON cti_feed_logs (finished_at DESC);

ALTER TABLE cti_feed_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_bypass_cti_feed_logs"
  ON cti_feed_logs TO service_role USING (true) WITH CHECK (true);
CREATE POLICY IF NOT EXISTS "cti_feed_logs_select"
  ON cti_feed_logs FOR SELECT TO authenticated USING (true);

-- ══════════════════════════════════════════════════════════════════
--  7. IOC ENRICHMENT QUEUE — track pending enrichments
-- ══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ioc_enrichment_queue (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  ioc_id      UUID REFERENCES iocs(id) ON DELETE CASCADE,
  ioc_value   TEXT NOT NULL,
  ioc_type    TEXT NOT NULL,
  priority    INTEGER DEFAULT 50,  -- 0=highest, 100=lowest
  status      TEXT DEFAULT 'pending',  -- 'pending'|'processing'|'done'|'failed'
  attempts    INTEGER DEFAULT 0,
  error       TEXT,
  enriched_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrich_queue_status    ON ioc_enrichment_queue (status, priority);
CREATE INDEX IF NOT EXISTS idx_enrich_queue_tenant    ON ioc_enrichment_queue (tenant_id);
CREATE INDEX IF NOT EXISTS idx_enrich_queue_ioc_value ON ioc_enrichment_queue (ioc_value);

ALTER TABLE ioc_enrichment_queue ENABLE ROW LEVEL SECURITY;
CREATE POLICY "service_role_bypass_enrichment_queue"
  ON ioc_enrichment_queue TO service_role USING (true) WITH CHECK (true);

-- ══════════════════════════════════════════════════════════════════
--  8. IOC STATS VIEW — fast summary stats for dashboard
-- ══════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW ioc_stats_view AS
SELECT
  tenant_id,
  COUNT(*) FILTER (WHERE status = 'active')                   AS total_active,
  COUNT(*) FILTER (WHERE reputation = 'malicious')            AS total_malicious,
  COUNT(*) FILTER (WHERE risk_score >= 70)                    AS total_high_risk,
  COUNT(DISTINCT source)                                       AS active_feeds,
  COUNT(DISTINCT type)                                         AS ioc_types,
  MAX(created_at)                                              AS last_ingested_at,
  jsonb_object_agg(type, cnt) FILTER (WHERE type IS NOT NULL) AS by_type
FROM (
  SELECT
    tenant_id, type, reputation, risk_score, status, source, created_at,
    COUNT(*) OVER (PARTITION BY tenant_id, type) AS cnt
  FROM iocs
) sub
GROUP BY tenant_id;

-- ══════════════════════════════════════════════════════════════════
--  9. THREAT ACTOR STATS VIEW
-- ══════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW threat_actor_stats_view AS
SELECT
  tenant_id,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE sophistication = 'nation-state') AS nation_state,
  COUNT(*) FILTER (WHERE motivation ILIKE '%ransomware%')  AS ransomware,
  COUNT(*) FILTER (WHERE last_seen >= NOW() - INTERVAL '30 days') AS active_30d
FROM threat_actors
GROUP BY tenant_id;

-- ══════════════════════════════════════════════════════════════════
--  10. GRANT PERMISSIONS
-- ══════════════════════════════════════════════════════════════════

GRANT ALL ON threat_actors        TO service_role;
GRANT ALL ON cti_feed_logs        TO service_role;
GRANT ALL ON feed_auth_log        TO service_role;
GRANT ALL ON ioc_enrichment_queue TO service_role;

GRANT SELECT ON threat_actors           TO anon, authenticated;
GRANT SELECT ON cti_feed_logs           TO anon, authenticated;
GRANT SELECT ON ioc_stats_view          TO anon, authenticated;
GRANT SELECT ON threat_actor_stats_view TO anon, authenticated;

-- ══════════════════════════════════════════════════════════════════
--  VERIFY
-- ══════════════════════════════════════════════════════════════════
DO $$
BEGIN
  RAISE NOTICE '✅ Migration v5.3 complete.';
  RAISE NOTICE '   Tables: threat_actors, cti_feed_logs, feed_auth_log, ioc_enrichment_queue';
  RAISE NOTICE '   Views: ioc_stats_view, threat_actor_stats_view';
  RAISE NOTICE '   Constraint: threat_actors(tenant_id,name) unique — needed for OTX/MITRE upsert';
  RAISE NOTICE '   Run: POST /api/threat-actors/ingest/mitre to populate 100+ APT groups';
END;
$$ LANGUAGE plpgsql;
