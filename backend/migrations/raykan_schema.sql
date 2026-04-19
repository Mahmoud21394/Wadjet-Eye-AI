-- =============================================================================
--  RAYKAN AI Threat Hunting & DFIR Engine — Supabase Schema Migration
--  Wadjet-Eye AI Platform v2.0
--
--  Run via: Supabase SQL Editor or psql
--
--  Tables:
--    raykan_sessions    — Hunting/analysis sessions per tenant
--    raykan_detections  — All triggered detections (persisted)
--    raykan_chains      — Reconstructed attack chains
--    raykan_anomalies   — UEBA behavioral anomalies
--    raykan_ioc_cache   — Cached IOC lookup results (VT/AbuseIPDB/OTX)
--    raykan_rules       — Custom/generated Sigma rules per tenant
--    raykan_hunts       — Saved threat hunt queries
--    raykan_timeline    — Forensic event timeline entries
-- =============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_sessions
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_sessions (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  session_id      TEXT        NOT NULL UNIQUE,
  scenario        TEXT,                           -- 'ransomware', 'apt', etc.
  source          TEXT,                           -- 'file', 'sample', 'api', 'realtime'
  events_processed INTEGER    DEFAULT 0,
  detections_count INTEGER    DEFAULT 0,
  anomalies_count  INTEGER    DEFAULT 0,
  chains_count     INTEGER    DEFAULT 0,
  risk_score      SMALLINT    DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  duration_ms     INTEGER,
  status          TEXT        DEFAULT 'completed', -- 'running' | 'completed' | 'failed'
  metadata        JSONB       DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_sessions_tenant     ON public.raykan_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_sessions_created_at ON public.raykan_sessions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_raykan_sessions_risk       ON public.raykan_sessions (risk_score DESC);

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_detections
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_detections (
  id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id          TEXT        NOT NULL,
  tenant_id           TEXT        NOT NULL DEFAULT 'default',
  case_id             TEXT,                         -- linked case (if any)
  rule_id             TEXT        NOT NULL,
  rule_name           TEXT        NOT NULL,
  severity            TEXT        NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  confidence          DECIMAL(3,2) DEFAULT 0.0,
  risk_score          SMALLINT    DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  event_id            TEXT,
  computer            TEXT,                         -- hostname
  user_name           TEXT,
  process_name        TEXT,
  command_line        TEXT,
  parent_process      TEXT,
  src_ip              INET,
  dst_ip              INET,
  file_path           TEXT,
  registry_key        TEXT,
  mitre_techniques    JSONB       DEFAULT '[]',     -- [{id,name,tactic}]
  ioc_enrichment      JSONB       DEFAULT '{}',     -- VT/AbuseIPDB results
  ai_analysis         TEXT,                         -- LLM explanation
  raw_detection       JSONB       DEFAULT '{}',
  timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_dets_session    ON public.raykan_detections (session_id);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_tenant     ON public.raykan_detections (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_severity   ON public.raykan_detections (severity);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_timestamp  ON public.raykan_detections (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_risk       ON public.raykan_detections (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_computer   ON public.raykan_detections (computer);
CREATE INDEX IF NOT EXISTS idx_raykan_dets_case       ON public.raykan_detections (case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_raykan_dets_mitre      ON public.raykan_detections USING GIN (mitre_techniques);

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_chains
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_chains (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id    TEXT        NOT NULL,
  tenant_id     TEXT        NOT NULL DEFAULT 'default',
  chain_id      TEXT        NOT NULL UNIQUE,
  name          TEXT,
  severity      TEXT        CHECK (severity IN ('critical','high','medium','low','informational')),
  risk_score    SMALLINT    DEFAULT 0,
  stages        JSONB       DEFAULT '[]',           -- [{ruleName,tactic,technique,timestamp}]
  entities      JSONB       DEFAULT '[]',           -- [host,user,ip,...]
  techniques    JSONB       DEFAULT '[]',           -- [T1059,T1003,...]
  indicators    JSONB       DEFAULT '[]',           -- IOCs within chain
  timeline_start TIMESTAMPTZ,
  timeline_end   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_chains_session  ON public.raykan_chains (session_id);
CREATE INDEX IF NOT EXISTS idx_raykan_chains_tenant   ON public.raykan_chains (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_chains_severity ON public.raykan_chains (severity);

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_anomalies
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_anomalies (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id      TEXT        NOT NULL,
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  anomaly_type    TEXT        NOT NULL,             -- 'login_time', 'data_volume', 'process_exec', etc.
  entity          TEXT        NOT NULL,             -- user/host/ip
  entity_type     TEXT,                             -- 'user' | 'host' | 'ip' | 'process'
  score           DECIMAL(5,4) DEFAULT 0.0,         -- anomaly score 0..1
  baseline        JSONB       DEFAULT '{}',
  observed        JSONB       DEFAULT '{}',
  deviation_pct   DECIMAL(7,2),
  description     TEXT,
  timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_anom_session ON public.raykan_anomalies (session_id);
CREATE INDEX IF NOT EXISTS idx_raykan_anom_entity  ON public.raykan_anomalies (entity);
CREATE INDEX IF NOT EXISTS idx_raykan_anom_score   ON public.raykan_anomalies (score DESC);

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_ioc_cache  (TTL-style: cache IOC lookups for 24h)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_ioc_cache (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  indicator       TEXT        NOT NULL UNIQUE,      -- IP, domain, hash, URL
  indicator_type  TEXT        NOT NULL,             -- 'ip' | 'domain' | 'hash' | 'url'
  is_malicious    BOOLEAN     DEFAULT FALSE,
  vt_positives    SMALLINT    DEFAULT 0,
  vt_total        SMALLINT    DEFAULT 0,
  abuse_score     SMALLINT    DEFAULT 0,
  otx_pulses      SMALLINT    DEFAULT 0,
  country         CHAR(2),
  asn             TEXT,
  tags            TEXT[]      DEFAULT '{}',
  raw_data        JSONB       DEFAULT '{}',
  cached_at       TIMESTAMPTZ DEFAULT NOW(),
  expires_at      TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE INDEX IF NOT EXISTS idx_raykan_ioc_indicator  ON public.raykan_ioc_cache (indicator);
CREATE INDEX IF NOT EXISTS idx_raykan_ioc_malicious  ON public.raykan_ioc_cache (is_malicious);
CREATE INDEX IF NOT EXISTS idx_raykan_ioc_expires    ON public.raykan_ioc_cache (expires_at);

-- Auto-delete expired IOC cache entries (requires pg_cron or background job)
-- SELECT cron.schedule('raykan-ioc-cleanup','0 */6 * * *','DELETE FROM raykan_ioc_cache WHERE expires_at < NOW()');

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_rules  (custom / AI-generated Sigma rules per tenant)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_rules (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  rule_id         TEXT        NOT NULL,
  name            TEXT        NOT NULL,
  description     TEXT,
  author          TEXT        DEFAULT 'RAYKAN AI',
  severity        TEXT        NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  category        TEXT,
  tags            TEXT[]      DEFAULT '{}',
  logsource       JSONB       DEFAULT '{}',
  detection       JSONB       DEFAULT '{}',
  condition       TEXT,
  false_positives TEXT[]      DEFAULT '{}',
  sigma_yaml      TEXT,                             -- raw YAML for export/import
  is_active       BOOLEAN     DEFAULT TRUE,
  hit_count       INTEGER     DEFAULT 0,
  last_hit_at     TIMESTAMPTZ,
  created_by      TEXT,                             -- user_id who created
  ai_generated    BOOLEAN     DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_raykan_rules_tenant    ON public.raykan_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_rules_severity  ON public.raykan_rules (severity);
CREATE INDEX IF NOT EXISTS idx_raykan_rules_active    ON public.raykan_rules (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_raykan_rules_ai        ON public.raykan_rules (ai_generated) WHERE ai_generated = TRUE;

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_hunts  (saved threat hunt queries per tenant/user)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_hunts (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  user_id         TEXT,
  name            TEXT        NOT NULL,
  description     TEXT,
  query           TEXT        NOT NULL,
  query_type      TEXT        NOT NULL CHECK (query_type IN ('rql','nl','sigma')),
  category        TEXT,
  tags            TEXT[]      DEFAULT '{}',
  last_run_at     TIMESTAMPTZ,
  last_hit_count  INTEGER     DEFAULT 0,
  run_count       INTEGER     DEFAULT 0,
  is_scheduled    BOOLEAN     DEFAULT FALSE,
  schedule_cron   TEXT,                             -- cron expression if scheduled
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_hunts_tenant ON public.raykan_hunts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_hunts_user   ON public.raykan_hunts (user_id) WHERE user_id IS NOT NULL;

-- ────────────────────────────────────────────────────────────────────────────
--  raykan_timeline  (persisted forensic timeline events)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.raykan_timeline (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  session_id      TEXT        NOT NULL,
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  event_type      TEXT        NOT NULL,             -- 'detection','process','network','file','registry','auth'
  entity          TEXT,
  description     TEXT        NOT NULL,
  command_line    TEXT,
  src_ip          INET,
  dst_ip          INET,
  file_path       TEXT,
  user_name       TEXT,
  computer        TEXT,
  severity        TEXT,
  is_detection    BOOLEAN     DEFAULT FALSE,
  detection_id    UUID        REFERENCES public.raykan_detections (id) ON DELETE SET NULL,
  evidence        JSONB       DEFAULT '{}',
  timestamp       TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_raykan_tl_session   ON public.raykan_timeline (session_id);
CREATE INDEX IF NOT EXISTS idx_raykan_tl_tenant    ON public.raykan_timeline (tenant_id);
CREATE INDEX IF NOT EXISTS idx_raykan_tl_timestamp ON public.raykan_timeline (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_raykan_tl_entity    ON public.raykan_timeline (entity) WHERE entity IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_raykan_tl_type      ON public.raykan_timeline (event_type);

-- ────────────────────────────────────────────────────────────────────────────
--  Row-Level Security (RLS) — Multi-tenant isolation
-- ────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.raykan_sessions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_chains     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_anomalies  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_rules      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_hunts      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.raykan_timeline   ENABLE ROW LEVEL SECURITY;

-- RLS policies (service-role key bypasses these; JWT-authenticated users get tenant isolation)
DO $$
DECLARE tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['raykan_sessions','raykan_detections','raykan_chains',
                              'raykan_anomalies','raykan_rules','raykan_hunts','raykan_timeline']
  LOOP
    EXECUTE format('
      CREATE POLICY IF NOT EXISTS %I_tenant_isolation ON public.%I
      FOR ALL USING (tenant_id = current_setting(''app.current_tenant'', TRUE)
                     OR current_setting(''app.current_tenant'', TRUE) IS NULL)',
      tbl, tbl, tbl);
  END LOOP;
END $$;

-- ────────────────────────────────────────────────────────────────────────────
--  updated_at triggers
-- ────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DO $$
DECLARE tbl TEXT;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['raykan_sessions','raykan_rules','raykan_hunts']
  LOOP
    EXECUTE format('
      DROP TRIGGER IF EXISTS trg_%s_upd ON public.%s;
      CREATE TRIGGER trg_%s_upd BEFORE UPDATE ON public.%s
      FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();',
      tbl, tbl, tbl, tbl);
  END LOOP;
END $$;

-- ────────────────────────────────────────────────────────────────────────────
--  Materialized View — Risk summary per tenant (refresh nightly)
-- ────────────────────────────────────────────────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS public.raykan_risk_summary AS
SELECT
  d.tenant_id,
  DATE_TRUNC('day', d.timestamp)       AS day,
  COUNT(*)                             AS total_detections,
  COUNT(*) FILTER (WHERE d.severity = 'critical') AS critical_count,
  COUNT(*) FILTER (WHERE d.severity = 'high')     AS high_count,
  COUNT(*) FILTER (WHERE d.severity = 'medium')   AS medium_count,
  COUNT(*) FILTER (WHERE d.severity = 'low')      AS low_count,
  ROUND(AVG(d.risk_score), 1)         AS avg_risk_score,
  MAX(d.risk_score)                   AS max_risk_score,
  COUNT(DISTINCT d.computer)          AS unique_hosts,
  COUNT(DISTINCT d.user_name)         AS unique_users
FROM public.raykan_detections d
GROUP BY d.tenant_id, DATE_TRUNC('day', d.timestamp);

CREATE UNIQUE INDEX IF NOT EXISTS idx_raykan_risk_summary
  ON public.raykan_risk_summary (tenant_id, day);

-- Refresh command (schedule daily):
-- REFRESH MATERIALIZED VIEW CONCURRENTLY public.raykan_risk_summary;

-- ────────────────────────────────────────────────────────────────────────────
--  Grant permissions (update 'authenticated' to match your Supabase role)
-- ────────────────────────────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO authenticated;
GRANT SELECT                         ON ALL TABLES    IN SCHEMA public TO anon;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- ════════════════════════════════════════════════════════════════════════════
--  DONE — RAYKAN schema ready.
--  Next step: run `node backend/services/raykan/engine.js` to initialize
--  engine and auto-seed built-in rules into raykan_rules table.
-- ════════════════════════════════════════════════════════════════════════════
