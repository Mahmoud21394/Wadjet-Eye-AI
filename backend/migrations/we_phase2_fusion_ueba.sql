-- ============================================================================
--  Wadjet-Eye AI — Phase 2: Alert Fusion + UEBA Schema
--  backend/migrations/we_phase2_fusion_ueba.sql
--
--  Ported from AiSOC v7.6.0:
--    services/ueba/app/services/baseline.py   — EntityBaseline ORM
--    services/ueba/app/services/scoring.py    — UEBAAnomaly ORM
--    services/ueba/app/services/peer_group.py — PeerGroup ORM
--    services/fusion/app/services/deduplicator.py — Redis → Postgres dedup
--    services/fusion/app/services/correlator.py   — Redis → Postgres correlation
--
--  Tables:
--    we_entity_baselines        — Welford running stats per entity+feature
--    we_peer_groups             — Peer-group aggregates for z-score blending
--    we_ueba_anomalies          — Scored anomaly events
--    we_alert_dedup_keys        — Fingerprint dedup (replaces Redis Bloom filter)
--    we_alert_correlation_index — Correlation window (replaces Redis hash)
--    we_alert_incidents         — Correlated alert groups
--
--  Dedup window: same as AiSOC default — 3600s (1 hour), configurable via
--  WE_DEDUP_WINDOW_SECONDS env var.  GC: periodic DELETE WHERE expires_at < NOW().
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────────────
--  we_entity_baselines
--  Stores Welford running statistics per (tenant, entity_type, entity_id, feature).
--  Ported from AiSOC EntityBaseline ORM (baseline.py).
--
--  feature_stats JSONB shape:
--    { "<feature_name>": { "n": int, "mean": float, "M2": float } }
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_entity_baselines (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     TEXT        NOT NULL DEFAULT 'default',
  entity_type   TEXT        NOT NULL,        -- 'user', 'host', 'service', 'ip'
  entity_id     TEXT        NOT NULL,        -- username, hostname, IP, etc.
  feature_stats JSONB       NOT NULL DEFAULT '{}',
  window_start  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  window_end    TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_we_baselines_entity
  ON public.we_entity_baselines (tenant_id, entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_we_baselines_window
  ON public.we_entity_baselines (window_end)
  WHERE window_end < NOW() + INTERVAL '1 day';  -- for baseline expiry queries

-- ─────────────────────────────────────────────────────────────────────────────
--  we_peer_groups
--  Aggregated Welford stats for a group of similar entities (e.g. "finance_users").
--  Ported from AiSOC PeerGroup ORM (peer_group.py).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_peer_groups (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     TEXT        NOT NULL DEFAULT 'default',
  entity_type   TEXT        NOT NULL,
  label         TEXT        NOT NULL,        -- group label, e.g. "finance_dept"
  member_count  INTEGER     NOT NULL DEFAULT 0,
  feature_stats JSONB       NOT NULL DEFAULT '{}',
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, entity_type, label)
);

CREATE INDEX IF NOT EXISTS idx_we_peer_groups_entity
  ON public.we_peer_groups (tenant_id, entity_type, label);

-- ─────────────────────────────────────────────────────────────────────────────
--  we_ueba_anomalies
--  One row per scored anomaly event.
--  Ported from AiSOC UEBAAnomaly (scoring.py ScoringService.score_event()).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_ueba_anomalies (
  id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id         TEXT        NOT NULL DEFAULT 'default',
  entity_type       TEXT        NOT NULL,
  entity_id         TEXT        NOT NULL,
  alert_id          UUID,                          -- linked alert (if any)
  event_ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Per-feature z-scores (JSONB): { "<feature>": z_score_float }
  feature_z_scores  JSONB       NOT NULL DEFAULT '{}',
  -- Composite RSS score: sqrt(sum(z²)) capped at 10.0 (scoring.py _composite_score)
  composite_score   NUMERIC(6,3) NOT NULL DEFAULT 0.0,
  -- Peer-group deviation blended composite: (personal + peer) / 2
  blended_score     NUMERIC(6,3),
  -- Risk level: critical(≥6.0) | high(≥4.0) | medium(≥2.0) | low
  risk_level        TEXT        NOT NULL DEFAULT 'low'
                    CHECK (risk_level IN ('critical','high','medium','low')),

  -- Raw features used to compute z-scores
  features          JSONB       NOT NULL DEFAULT '{}',
  -- Shadow mode: true during validation window (not surfaced in UI)
  shadow_mode       BOOLEAN     NOT NULL DEFAULT TRUE,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_we_ueba_entity
  ON public.we_ueba_anomalies (tenant_id, entity_id, event_ts DESC);

CREATE INDEX IF NOT EXISTS idx_we_ueba_risk
  ON public.we_ueba_anomalies (tenant_id, risk_level)
  WHERE shadow_mode = FALSE;

CREATE INDEX IF NOT EXISTS idx_we_ueba_alert
  ON public.we_ueba_anomalies (alert_id)
  WHERE alert_id IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
--  we_alert_dedup_keys
--  Fingerprint-based dedup table, replacing AiSOC's Redis Bloom filter.
--  Ported from AiSOC Deduplicator (fusion/app/services/deduplicator.py).
--
--  Dedup window default: 3600s (1 hour), matching AiSOC dedup_window_seconds.
--  GC: DELETE FROM we_alert_dedup_keys WHERE expires_at < NOW()
--      (run by a scheduled Postgres cron job or Edge Function)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_alert_dedup_keys (
  fingerprint   TEXT        PRIMARY KEY,    -- SHA-256 of canonical alert fields
  alert_id      UUID,                       -- first alert that registered this fingerprint
  tenant_id     TEXT        NOT NULL DEFAULT 'default',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour')
);

-- Index for TTL GC queries
CREATE INDEX IF NOT EXISTS idx_we_dedup_expires
  ON public.we_alert_dedup_keys (expires_at);

-- Index for tenant-scoped lookups
CREATE INDEX IF NOT EXISTS idx_we_dedup_tenant
  ON public.we_alert_dedup_keys (tenant_id, created_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
--  we_alert_incidents
--  Correlated groups of related alerts (formerly a Redis hash in AiSOC).
--  Ported from AiSOC correlator.py _create_incident().
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_alert_incidents (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  correlation_key TEXT        NOT NULL,     -- {tenant_id}:{entity}:{tactic}
  title           TEXT        NOT NULL DEFAULT '',
  severity        TEXT        NOT NULL DEFAULT 'MEDIUM'
                  CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  status          TEXT        NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','investigating','contained','closed')),
  alert_count     INTEGER     NOT NULL DEFAULT 1,
  src_ips         TEXT[]      NOT NULL DEFAULT '{}',
  hostnames       TEXT[]      NOT NULL DEFAULT '{}',
  usernames       TEXT[]      NOT NULL DEFAULT '{}',
  mitre_tactics   TEXT[]      NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[]     NOT NULL DEFAULT '{}',
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Window expiry for correlation (default 1 hour, matching AiSOC correlation_window_seconds)
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour'),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_we_incidents_key
  ON public.we_alert_incidents (tenant_id, correlation_key, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_we_incidents_status
  ON public.we_alert_incidents (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_we_incidents_expires
  ON public.we_alert_incidents (expires_at);

-- ─────────────────────────────────────────────────────────────────────────────
--  we_alert_correlation_index
--  Maps correlation_key → active incident_id for fast lookups.
--  Separate from we_alert_incidents to allow atomic upsert pattern.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_alert_correlation_index (
  correlation_key TEXT        NOT NULL,
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  incident_id     UUID        NOT NULL REFERENCES public.we_alert_incidents(id) ON DELETE CASCADE,
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour'),
  PRIMARY KEY (correlation_key, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_we_corr_index_expires
  ON public.we_alert_correlation_index (expires_at);

-- ─────────────────────────────────────────────────────────────────────────────
--  Shadow mode column on alerts table (added non-destructively)
--  Phase 2 shadow mode: store fusion output alongside existing alert without
--  changing the UI until go/no-go.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.alerts
  ADD COLUMN IF NOT EXISTS we_dedup_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS we_incident_id       UUID,
  ADD COLUMN IF NOT EXISTS we_confidence_score  NUMERIC(4,3),
  ADD COLUMN IF NOT EXISTS we_confidence_label  TEXT,
  ADD COLUMN IF NOT EXISTS we_ueba_composite    NUMERIC(6,3),
  ADD COLUMN IF NOT EXISTS we_ueba_risk_level   TEXT,
  ADD COLUMN IF NOT EXISTS we_fusion_shadow     BOOLEAN DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_alerts_we_fingerprint
  ON public.alerts (we_dedup_fingerprint)
  WHERE we_dedup_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_we_incident
  ON public.alerts (we_incident_id)
  WHERE we_incident_id IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
--  Realtime publication for UEBA anomalies
-- ─────────────────────────────────────────────────────────────────────────────
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'we_ueba_anomalies'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.we_ueba_anomalies;
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Dedup GC function (called by scheduled Edge Function / cron)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.fn_we_dedup_gc()
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE deleted_count INTEGER;
BEGIN
  -- Remove expired dedup keys
  WITH deleted AS (
    DELETE FROM public.we_alert_dedup_keys WHERE expires_at < NOW() RETURNING fingerprint
  )
  SELECT COUNT(*) INTO deleted_count FROM deleted;

  -- Remove expired correlation index entries
  DELETE FROM public.we_alert_correlation_index WHERE expires_at < NOW();

  -- Remove expired incidents (that have no active correlation index)
  DELETE FROM public.we_alert_incidents
  WHERE expires_at < NOW()
    AND id NOT IN (SELECT incident_id FROM public.we_alert_correlation_index);

  RETURN deleted_count;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Smoke test
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE t TEXT;
BEGIN
  FOR t IN SELECT unnest(ARRAY[
    'we_entity_baselines','we_peer_groups','we_ueba_anomalies',
    'we_alert_dedup_keys','we_alert_correlation_index','we_alert_incidents'
  ]) LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = t AND schemaname = 'public') THEN
      RAISE EXCEPTION '[Phase2 Migration] Table % was not created', t;
    END IF;
  END LOOP;
  RAISE NOTICE '[Phase2 Migration] ✅ All tables created successfully';
END $$;
