-- ══════════════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Production Reliability Migration v1.0
--  File: backend/db/migrations/20260720_production_reliability_v1.sql
--
--  ROOT CAUSES ADDRESSED:
--  ─────────────────────────────────────────────────────────────────────────
--  1. PostgreSQL Statement Timeouts
--     • Missing UNIQUE INDEX on iocs(tenant_id,value) → every upsert did full
--       sequential scan → exceeded 15s Supabase free-tier statement_timeout
--     • Missing composite indexes on high-cardinality query patterns
--     • Missing pg_trgm GIN indexes needed by hash / text lookups
--
--  2. Schema Drift
--     • asset_inventory.open_ports column missing
--     • asset_inventory.services, .vulnerabilities missing (referenced in app)
--     • feed_logs table missing (startFeedLog/finishFeedLog crash without it)
--     • outbox_events missing (WS relay fails)
--     • detection_timeline missing required columns
--     • ioc_queue table needed by new queue-based ingestion pipeline
--
--  3. Constraint Gaps
--     • No UNIQUE constraint enforcing onConflict column set
--     • No CHECK constraints on critical numeric ranges
--
--  SAFE TO RE-RUN: All statements use IF NOT EXISTS / DO $$ / ADD COLUMN IF NOT EXISTS
--  Run in Supabase SQL Editor → copy-paste entire file → Run
-- ══════════════════════════════════════════════════════════════════════════════

BEGIN;

-- ── Extensions ────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 1: CRITICAL IOC INDEXES — Fixes statement timeout on upsert
--
--  Root cause: .upsert(onConflict:'tenant_id,value') with Supabase JS v2
--  requires a UNIQUE INDEX on (tenant_id, value) to use the conflict path.
--  Without it, PostgreSQL does a full sequential scan per upsert row.
--  On tables with 50k+ IOCs, this exceeds the 15s statement_timeout.
-- ══════════════════════════════════════════════════════════════════════════════

-- 1a. Primary UNIQUE index for upsert deduplication (THE critical fix)
CREATE UNIQUE INDEX IF NOT EXISTS uq_iocs_tenant_value
  ON public.iocs (tenant_id, value);

-- 1b. Type + tenant composite (feed queries filter by type)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_type
  ON public.iocs (tenant_id, type);

-- 1c. Status filter + tenant (dashboard active IOC queries)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_status
  ON public.iocs (tenant_id, status)
  WHERE status = 'active';

-- 1d. Risk score descending (sorted dashboards, most dangerous first)
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_risk_desc
  ON public.iocs (tenant_id, risk_score DESC);

-- 1e. Feed source deduplication (per-feed ingestion checks)
CREATE INDEX IF NOT EXISTS idx_iocs_feed_source
  ON public.iocs (tenant_id, feed_source)
  WHERE feed_source IS NOT NULL;

-- 1f. last_seen timestamp sort (recency queries, purge old IOCs)
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen_desc
  ON public.iocs (tenant_id, last_seen DESC);

-- 1g. GIN trigram index for hash/value text search
CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm
  ON public.iocs USING gin (value gin_trgm_ops);

-- 1h. GIN for tags array containment queries
CREATE INDEX IF NOT EXISTS idx_iocs_tags_gin
  ON public.iocs USING gin (tags);

-- 1i. Hash type fast lookup (MD5/SHA256 matching)
CREATE INDEX IF NOT EXISTS idx_iocs_hash_lookup
  ON public.iocs (tenant_id, value, type)
  WHERE type IN ('hash_md5', 'hash_sha1', 'hash_sha256');

-- 1j. Malware family grouping (threat correlation)
CREATE INDEX IF NOT EXISTS idx_iocs_malware_family
  ON public.iocs (tenant_id, malware_family)
  WHERE malware_family IS NOT NULL;

-- 1k. Reputation filter (quick malicious/suspicious counts)
CREATE INDEX IF NOT EXISTS idx_iocs_reputation
  ON public.iocs (tenant_id, reputation);

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 2: MISSING COLUMNS — Schema drift fixes
-- ══════════════════════════════════════════════════════════════════════════════

-- 2a. iocs: missing columns referenced by ingestion workers
ALTER TABLE public.iocs
  ADD COLUMN IF NOT EXISTS feed_source      TEXT,
  ADD COLUMN IF NOT EXISTS malware_family   TEXT,
  ADD COLUMN IF NOT EXISTS confidence       NUMERIC(5,2) DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS threat_type      TEXT,
  ADD COLUMN IF NOT EXISTS kill_chain_phase TEXT,
  ADD COLUMN IF NOT EXISTS expiry_at        TIMESTAMPTZ;

-- 2b. asset_inventory: the reported missing column + related missing columns
ALTER TABLE public.asset_inventory
  ADD COLUMN IF NOT EXISTS open_ports       JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS services         JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS vulnerabilities  JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS last_scanned_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS scan_source      TEXT DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS hostname         TEXT,
  ADD COLUMN IF NOT EXISTS fqdn             TEXT,
  ADD COLUMN IF NOT EXISTS network_zone     TEXT,
  ADD COLUMN IF NOT EXISTS asset_group      TEXT,
  ADD COLUMN IF NOT EXISTS criticality      TEXT DEFAULT 'medium'
                           CHECK (criticality IN ('low','medium','high','critical')),
  ADD COLUMN IF NOT EXISTS compliance_tags  TEXT[] DEFAULT '{}';

-- 2c. alerts: missing columns referenced in NVD/enrichment workers
ALTER TABLE public.alerts
  ADD COLUMN IF NOT EXISTS ioc_id           UUID REFERENCES public.iocs(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS cve_id           TEXT,
  ADD COLUMN IF NOT EXISTS cvss_score       NUMERIC(4,2),
  ADD COLUMN IF NOT EXISTS feed_source      TEXT,
  ADD COLUMN IF NOT EXISTS auto_resolved    BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS false_positive_reason TEXT;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 3: FEED LOGS TABLE
--  Required by startFeedLog() / finishFeedLog() in ingestion/index.js.
--  Missing = every feed worker crashes on INSERT to non-existent table.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.feed_logs (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  feed_name        TEXT NOT NULL,
  feed_type        TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running','success','partial','error','skipped')),
  started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at      TIMESTAMPTZ,
  duration_ms      INTEGER DEFAULT 0,
  iocs_fetched     INTEGER DEFAULT 0,
  iocs_new         INTEGER DEFAULT 0,
  iocs_updated     INTEGER DEFAULT 0,
  iocs_duplicate   INTEGER DEFAULT 0,
  errors_count     INTEGER DEFAULT 0,
  error_message    TEXT,
  metadata         JSONB DEFAULT '{}',
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feed_logs_tenant       ON public.feed_logs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_logs_type_status  ON public.feed_logs(feed_type, status);
CREATE INDEX IF NOT EXISTS idx_feed_logs_recent       ON public.feed_logs(started_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 4: DETECTION TIMELINE TABLE
--  Required by logTimelineEvent() in ingestion/index.js.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.detection_timeline (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  event_type       TEXT NOT NULL,
  title            TEXT NOT NULL,
  description      TEXT,
  severity         TEXT DEFAULT 'INFO'
                   CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  source           TEXT DEFAULT 'manual',
  metadata         JSONB DEFAULT '{}',
  ioc_id           UUID REFERENCES public.iocs(id) ON DELETE SET NULL,
  alert_id         UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_timeline_tenant         ON public.detection_timeline(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_event_type     ON public.detection_timeline(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_timeline_severity       ON public.detection_timeline(tenant_id, severity)
  WHERE severity IN ('HIGH','CRITICAL');

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 5: OUTBOX EVENTS TABLE
--  Required by WebSocket relay. WS events are written here by DB triggers;
--  the WS server polls/subscribes and broadcasts to connected clients.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.outbox_events (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  event_type       TEXT NOT NULL,
  payload          JSONB NOT NULL DEFAULT '{}',
  published        BOOLEAN DEFAULT FALSE,
  published_at     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  retry_count      INTEGER DEFAULT 0,
  last_error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON public.outbox_events(tenant_id, created_at)
  WHERE published = FALSE;
CREATE INDEX IF NOT EXISTS idx_outbox_tenant_recent ON public.outbox_events(tenant_id, created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 6: IOC QUEUE TABLE (new queue-based ingestion pipeline)
--  Replaces the circuit-breaker pattern. Supports:
--   - Dead-letter queue (failed IOCs with error tracking)
--   - Exponential backoff retry
--   - Per-feed batch isolation
--   - Resume on restart (pending rows survive crashes)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.ioc_queue (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id        UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  batch_id         UUID NOT NULL,           -- groups IOCs from same feed run
  feed_source      TEXT NOT NULL,
  ioc_value        TEXT NOT NULL,
  ioc_type         TEXT NOT NULL,
  payload          JSONB NOT NULL DEFAULT '{}',
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','processing','done','failed','dead_letter')),
  priority         INTEGER DEFAULT 5,       -- lower = higher priority
  attempts         INTEGER DEFAULT 0,
  max_attempts     INTEGER DEFAULT 5,
  next_attempt_at  TIMESTAMPTZ DEFAULT NOW(),
  last_error       TEXT,
  error_history    JSONB DEFAULT '[]',
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  processed_at     TIMESTAMPTZ,
  UNIQUE(tenant_id, batch_id, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_queue_pending
  ON public.ioc_queue(tenant_id, priority, next_attempt_at)
  WHERE status IN ('pending','processing');

CREATE INDEX IF NOT EXISTS idx_ioc_queue_batch
  ON public.ioc_queue(batch_id, status);

CREATE INDEX IF NOT EXISTS idx_ioc_queue_dead_letter
  ON public.ioc_queue(tenant_id, created_at DESC)
  WHERE status = 'dead_letter';

CREATE INDEX IF NOT EXISTS idx_ioc_queue_feed_source
  ON public.ioc_queue(tenant_id, feed_source, status);

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 7: VULNERABILITIES TABLE INDEXES
--  NVD upsert uses onConflict:'cve_id' — needs unique index.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
  id                UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id         UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  cve_id            TEXT NOT NULL UNIQUE,
  title             TEXT,
  description       TEXT,
  severity          TEXT DEFAULT 'NONE'
                    CHECK (severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  cvss_v3_score     NUMERIC(4,2),
  cvss_v2_score     NUMERIC(4,2),
  cvss_v3_vector    TEXT,
  cwe_ids           TEXT[] DEFAULT '{}',
  affected_products JSONB DEFAULT '[]',
  references        JSONB DEFAULT '[]',
  exploit_available BOOLEAN DEFAULT FALSE,
  patch_available   BOOLEAN DEFAULT FALSE,
  exploited_in_wild BOOLEAN DEFAULT FALSE,
  kev_listed        BOOLEAN DEFAULT FALSE,
  epss_score        NUMERIC(6,5),
  published_at      TIMESTAMPTZ,
  modified_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vuln_cve_id       ON public.vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity     ON public.vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_kev          ON public.vulnerabilities(kev_listed) WHERE kev_listed = TRUE;
CREATE INDEX IF NOT EXISTS idx_vuln_exploit      ON public.vulnerabilities(exploit_available) WHERE exploit_available = TRUE;
CREATE INDEX IF NOT EXISTS idx_vuln_score_desc   ON public.vulnerabilities(cvss_v3_score DESC) WHERE cvss_v3_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vuln_tenant       ON public.vulnerabilities(tenant_id) WHERE tenant_id IS NOT NULL;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 8: ALERTS TABLE INDEXES (for NVD alert upsert)
--  NVD upsert uses onConflict:'tenant_id,ioc_value' — needs unique index.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_ioc_value
  ON public.alerts(tenant_id, ioc_value)
  WHERE ioc_value IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status
  ON public.alerts(tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_severity
  ON public.alerts(tenant_id, severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_cve_id
  ON public.alerts(cve_id)
  WHERE cve_id IS NOT NULL;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 9: CAMPAIGNS TABLE INDEXES
--  Campaign queries join IOCs and are frequently sorted by created_at/severity.
-- ══════════════════════════════════════════════════════════════════════════════

-- Ensure campaigns table has needed columns (from 20260516 migration)
ALTER TABLE public.campaigns
  ADD COLUMN IF NOT EXISTS ioc_count    INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS severity     TEXT DEFAULT 'MEDIUM',
  ADD COLUMN IF NOT EXISTS source       TEXT,
  ADD COLUMN IF NOT EXISTS description  TEXT,
  ADD COLUMN IF NOT EXISTS tags         TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS mitre_ttps   JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS actor_name   TEXT,
  ADD COLUMN IF NOT EXISTS status       TEXT DEFAULT 'active'
                           CHECK (status IN ('active','monitoring','closed','false_positive'));

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_created
  ON public.campaigns(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_severity
  ON public.campaigns(tenant_id, severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_status
  ON public.campaigns(tenant_id, status)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_campaigns_actor
  ON public.campaigns(tenant_id, actor_name)
  WHERE actor_name IS NOT NULL;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 10: NEWS ARTICLES TABLE INDEXES
--  Deduplication uses onConflict:'tenant_id,external_guid' — needs unique index.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE UNIQUE INDEX IF NOT EXISTS uq_news_articles_tenant_guid
  ON public.news_articles(tenant_id, external_guid)
  WHERE external_guid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_news_tenant_published
  ON public.news_articles(tenant_id, published_at DESC);

CREATE INDEX IF NOT EXISTS idx_news_tenant_severity
  ON public.news_articles(tenant_id, severity, published_at DESC)
  WHERE severity IN ('HIGH','CRITICAL');

CREATE INDEX IF NOT EXISTS idx_news_fts
  ON public.news_articles
  USING gin(to_tsvector('english',
    coalesce(title,'') || ' ' || coalesce(summary,'')
  ));

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 11: THREAT ACTORS TABLE
--  Required by Ransomware.live worker (upsert on 'name').
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.threat_actors (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  aliases          TEXT[] DEFAULT '{}',
  motivation       TEXT,
  sophistication   TEXT DEFAULT 'unknown',
  origin_country   TEXT,
  target_sectors   TEXT[] DEFAULT '{}',
  ttps             JSONB DEFAULT '[]',
  source           TEXT DEFAULT 'manual',
  external_id      TEXT UNIQUE,
  tags             TEXT[] DEFAULT '{}',
  confidence       INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  active           BOOLEAN DEFAULT TRUE,
  first_seen       TIMESTAMPTZ DEFAULT NOW(),
  last_seen        TIMESTAMPTZ DEFAULT NOW(),
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_actors_name    ON public.threat_actors(name);
CREATE INDEX IF NOT EXISTS idx_threat_actors_active  ON public.threat_actors(active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_actors_tags    ON public.threat_actors USING gin(tags);

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 12: USERS TABLE — missing columns for auth middleware
--  auth.js reads 'inactive' status; schema only has 'suspended'/'pending'.
-- ══════════════════════════════════════════════════════════════════════════════
DO $$
BEGIN
  -- Widen status CHECK constraint to include 'inactive'
  ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_status_check;
  ALTER TABLE public.users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active','suspended','pending','inactive'));
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'users_status_check constraint update: %', SQLERRM;
END $$;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS last_refresh_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS refresh_token_hash TEXT,
  ADD COLUMN IF NOT EXISTS failed_login_count INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS locked_until      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS login_ip          TEXT;

CREATE INDEX IF NOT EXISTS idx_users_auth_id    ON public.users(auth_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON public.users(tenant_id, role);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON public.users(lower(email));

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 13: SESSION / REFRESH TOKEN TABLE
--  Enables secure server-side JWT refresh without Supabase round-trip.
--  Backend issues short-lived access tokens (15min) + longer refresh tokens
--  stored server-side. Frontend calls /api/auth/refresh with refresh token.
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
  id               UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id          UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  tenant_id        UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  token_hash       TEXT NOT NULL UNIQUE,   -- SHA-256 of the actual token
  device_hint      TEXT,                  -- user-agent snippet for display
  ip_address       TEXT,
  issued_at        TIMESTAMPTZ DEFAULT NOW(),
  expires_at       TIMESTAMPTZ NOT NULL,
  revoked          BOOLEAN DEFAULT FALSE,
  revoked_at       TIMESTAMPTZ,
  revoked_reason   TEXT,
  last_used_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
  ON public.refresh_tokens(user_id, revoked, expires_at);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash
  ON public.refresh_tokens(token_hash)
  WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expired
  ON public.refresh_tokens(expires_at)
  WHERE revoked = FALSE;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 14: AUTO-UPDATE TRIGGERS for new tables
-- ══════════════════════════════════════════════════════════════════════════════

-- Reuse existing handle_updated_at function
DO $$ BEGIN
  CREATE TRIGGER set_updated_at_vulnerabilities
    BEFORE UPDATE ON public.vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TRIGGER set_updated_at_threat_actors
    BEFORE UPDATE ON public.threat_actors
    FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 15: PERFORMANCE HELPER FUNCTIONS
--  pg_stat_statements-compatible named queries for EXPLAIN ANALYZE baseline.
-- ══════════════════════════════════════════════════════════════════════════════

-- Function to safely upsert IOC with proper conflict handling
CREATE OR REPLACE FUNCTION public.upsert_ioc(
  p_tenant_id     UUID,
  p_value         TEXT,
  p_type          TEXT,
  p_reputation    TEXT DEFAULT 'unknown',
  p_risk_score    NUMERIC DEFAULT 0,
  p_confidence    NUMERIC DEFAULT 0,
  p_source        TEXT DEFAULT 'manual',
  p_feed_source   TEXT DEFAULT NULL,
  p_tags          TEXT[] DEFAULT '{}',
  p_notes         TEXT DEFAULT NULL,
  p_malware_family TEXT DEFAULT NULL,
  p_enrichment    JSONB DEFAULT '{}'
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_existing_id UUID;
  v_result      JSONB;
BEGIN
  -- Check if IOC exists
  SELECT id INTO v_existing_id
    FROM public.iocs
   WHERE tenant_id = p_tenant_id AND value = p_value
   LIMIT 1;

  IF v_existing_id IS NOT NULL THEN
    -- Update existing
    UPDATE public.iocs SET
      reputation     = CASE WHEN p_reputation != 'unknown' THEN p_reputation ELSE reputation END,
      risk_score     = GREATEST(risk_score, p_risk_score),
      confidence     = GREATEST(confidence, p_confidence),
      last_seen      = NOW(),
      tags           = array(SELECT DISTINCT unnest(tags || p_tags)),
      feed_source    = COALESCE(p_feed_source, feed_source),
      malware_family = COALESCE(p_malware_family, malware_family),
      notes          = COALESCE(p_notes, notes),
      enrichment_data= enrichment_data || p_enrichment,
      updated_at     = NOW()
    WHERE id = v_existing_id;
    v_result := jsonb_build_object('action', 'updated', 'id', v_existing_id);
  ELSE
    -- Insert new
    INSERT INTO public.iocs (
      tenant_id, value, type, reputation, risk_score, confidence,
      source, feed_source, tags, notes, malware_family, enrichment_data,
      first_seen, last_seen, status
    ) VALUES (
      p_tenant_id, p_value, p_type, p_reputation, p_risk_score, p_confidence,
      p_source, p_feed_source, p_tags, p_notes, p_malware_family, p_enrichment,
      NOW(), NOW(), 'active'
    )
    RETURNING id INTO v_existing_id;
    v_result := jsonb_build_object('action', 'inserted', 'id', v_existing_id);
  END IF;

  RETURN v_result;
EXCEPTION WHEN unique_violation THEN
  -- Race condition: another worker inserted between our check and insert
  SELECT id INTO v_existing_id FROM public.iocs
   WHERE tenant_id = p_tenant_id AND value = p_value LIMIT 1;
  RETURN jsonb_build_object('action', 'race_updated', 'id', v_existing_id);
END;
$$;

-- Function to get pending IOC queue batch for processing
CREATE OR REPLACE FUNCTION public.claim_ioc_queue_batch(
  p_tenant_id  UUID,
  p_batch_size INTEGER DEFAULT 50
) RETURNS SETOF public.ioc_queue
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  UPDATE public.ioc_queue
     SET status         = 'processing',
         attempts       = attempts + 1,
         next_attempt_at= NOW() + (INTERVAL '1 second' * POWER(2, attempts) * 5)
   WHERE id IN (
     SELECT id FROM public.ioc_queue
      WHERE tenant_id       = p_tenant_id
        AND status          = 'pending'
        AND next_attempt_at <= NOW()
        AND attempts        < max_attempts
      ORDER BY priority ASC, next_attempt_at ASC
      LIMIT p_batch_size
      FOR UPDATE SKIP LOCKED
   )
  RETURNING *;
END;
$$;

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 16: STATEMENT TIMEOUT CONFIGURATION HINTS
--  Cannot ALTER DATABASE on Supabase free tier without superuser.
--  Use SET LOCAL in transactions instead (applied per-session).
--  These are documented here for reference; apply via Supabase Dashboard
--  → Settings → Database → Additional Config if available.
-- ══════════════════════════════════════════════════════════════════════════════

-- The following settings should be applied in Supabase Dashboard:
--   statement_timeout = '30s'        (up from 15s default on free tier)
--   idle_in_transaction_session_timeout = '60s'
--   lock_timeout = '10s'

-- ══════════════════════════════════════════════════════════════════════════════
--  SECTION 17: ANALYZE — refresh planner statistics after index creation
-- ══════════════════════════════════════════════════════════════════════════════
ANALYZE public.iocs;
ANALYZE public.alerts;
ANALYZE public.campaigns;

COMMIT;

-- ══════════════════════════════════════════════════════════════════════════════
--  POST-MIGRATION VERIFICATION QUERIES
--  Run these in Supabase SQL Editor after the migration to confirm success:
--
--  1. Check all critical indexes exist:
--     SELECT indexname FROM pg_indexes
--     WHERE tablename = 'iocs' ORDER BY indexname;
--
--  2. Confirm uq_iocs_tenant_value is UNIQUE:
--     SELECT indexname, indexdef FROM pg_indexes
--     WHERE indexname = 'uq_iocs_tenant_value';
--
--  3. Verify open_ports column exists:
--     SELECT column_name, data_type FROM information_schema.columns
--     WHERE table_name = 'asset_inventory' AND column_name = 'open_ports';
--
--  4. Check feed_logs table:
--     SELECT COUNT(*) FROM feed_logs;
--
--  5. Run EXPLAIN ANALYZE on a typical IOC upsert (should show Index Scan):
--     EXPLAIN ANALYZE SELECT id FROM iocs WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND value = 'test.com';
-- ══════════════════════════════════════════════════════════════════════════════
