-- ============================================================================
--  Wadjet-Eye AI — Phase 1: Investigation Pipeline Schema
--  backend/migrations/we_phase1_investigation_pipeline.sql
--
--  Ported from AiSOC v7.6.0:
--    services/api/app/models/investigation.py  (ORM schema + immutability)
--    services/agents/app/investigator/orchestrator.py (ledger write pattern)
--
--  Tables:
--    we_investigation_runs    — one row per investigation invocation
--    we_investigation_events  — append-only step ledger (trigger blocks mutations)
--    we_investigation_artifacts — binary/text outputs per step
--
--  Append-only enforcement (AiSOC pattern):
--    we_investigation_events has a BEFORE UPDATE OR DELETE trigger that raises
--    an exception, matching the comment in investigation.py:
--    "Append-only — the SQL migration enforces immutability."
--
--  Run via: Supabase SQL Editor → paste and execute
--  Idempotent: all CREATE statements use IF NOT EXISTS
-- ============================================================================

-- Enable UUID extension (already enabled in raykan_schema.sql, safe to repeat)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid() and encode()

-- ─────────────────────────────────────────────────────────────────────────────
--  we_investigation_runs
--  One row per investigation invocation.  Status flows:
--    pending → running → completed | failed
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_investigation_runs (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       TEXT        NOT NULL DEFAULT 'default',
  case_id         UUID,                                    -- optional FK to cases table
  alert_id        UUID,                                    -- optional FK to alerts table
  alert_summary   TEXT        NOT NULL DEFAULT '',         -- analyst-authored / LLM-produced title
  raw_alert       JSONB       NOT NULL DEFAULT '{}',       -- original alert payload (stored, not sent to LLM)
  model_used      TEXT        NOT NULL DEFAULT 'gpt-4o',
  status          TEXT        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'completed', 'failed', 'aborted')),
  error           TEXT,                                    -- null unless status=failed
  total_tokens    INTEGER     NOT NULL DEFAULT 0,
  total_cost_usd  NUMERIC(10,6) NOT NULL DEFAULT 0.0,      -- running cost accumulator
  iterations      SMALLINT    NOT NULL DEFAULT 0,          -- pipeline re-runs (auto-triage retries)
  feature_flag    TEXT        NOT NULL DEFAULT 'ENABLE_PIPELINE_INVESTIGATION',
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_we_inv_runs_tenant_started
  ON public.we_investigation_runs (tenant_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_we_inv_runs_case
  ON public.we_investigation_runs (case_id)
  WHERE case_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_we_inv_runs_status
  ON public.we_investigation_runs (status)
  WHERE status IN ('pending', 'running');

-- ─────────────────────────────────────────────────────────────────────────────
--  we_investigation_events
--  Append-only step ledger — one row per pipeline stage execution.
--  Ported from AiSOC investigation.py InvestigationEvent ORM.
--  Immutability enforced by trigger below.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_investigation_events (
  id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  run_id      UUID        NOT NULL REFERENCES public.we_investigation_runs(id) ON DELETE CASCADE,
  tenant_id   TEXT        NOT NULL DEFAULT 'default',
  seq         SMALLINT    NOT NULL,       -- monotonic step index within run (0-based)
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Stage kind — one of: auto_triage, triage, enrichment, investigation, attack_path,
  --              swarm_hypothesis, early_exit, pipeline_error, cost_checkpoint
  kind        VARCHAR(40) NOT NULL,
  -- Agent / sub-module name (e.g. "auto_triage_agent", "swarm:T1059")
  agent       VARCHAR(80) NOT NULL DEFAULT 'pipeline',
  summary     TEXT        NOT NULL DEFAULT '',           -- human-readable one-liner
  payload     JSONB       NOT NULL DEFAULT '{}',         -- full stage output
  -- SHA-256 hashes of the input/output state for tamper evidence
  -- Ported from AiSOC InvestigationEvent.input_hash / output_hash
  input_hash  VARCHAR(64),                               -- sha256(input_state_json)
  output_hash VARCHAR(64),                               -- sha256(output_state_json)
  duration_ms INTEGER     NOT NULL DEFAULT 0,
  tokens_used INTEGER     NOT NULL DEFAULT 0,
  cost_usd    NUMERIC(10,6) NOT NULL DEFAULT 0.0,
  UNIQUE (run_id, seq)                                   -- ported from UniqueConstraint in ORM
);

CREATE INDEX IF NOT EXISTS idx_we_inv_events_run
  ON public.we_investigation_events (run_id, seq ASC);

CREATE INDEX IF NOT EXISTS idx_we_inv_events_tenant_ts
  ON public.we_investigation_events (tenant_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_we_inv_events_kind
  ON public.we_investigation_events (kind);

-- ── Append-only trigger (ported from AiSOC: "SQL migration enforces immutability") ──
-- Blocks all UPDATE and DELETE on we_investigation_events.
-- INSERT is always allowed.  DROP TABLE is not blocked (for migrations).
CREATE OR REPLACE FUNCTION public.fn_we_investigation_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION
    '[WE] we_investigation_events is append-only: % on row id=% run_id=% seq=% is forbidden',
    TG_OP, OLD.id, OLD.run_id, OLD.seq
    USING ERRCODE = 'restrict_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_we_investigation_events_immutable
  ON public.we_investigation_events;

CREATE TRIGGER trg_we_investigation_events_immutable
  BEFORE UPDATE OR DELETE ON public.we_investigation_events
  FOR EACH ROW EXECUTE FUNCTION public.fn_we_investigation_events_immutable();

-- ─────────────────────────────────────────────────────────────────────────────
--  we_investigation_artifacts
--  Binary/text outputs attached to a specific event (e.g. attack graph JSON,
--  timeline markdown, hypothesis detail).
--  Ported from AiSOC InvestigationArtifact ORM.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_investigation_artifacts (
  id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  run_id      UUID        NOT NULL REFERENCES public.we_investigation_runs(id) ON DELETE CASCADE,
  event_id    UUID        REFERENCES public.we_investigation_events(id) ON DELETE SET NULL,
  tenant_id   TEXT        NOT NULL DEFAULT 'default',
  -- kind: attack_path | hypothesis | timeline | report | raw_output
  kind        VARCHAR(40) NOT NULL DEFAULT 'raw_output',
  content     TEXT        NOT NULL DEFAULT '',
  sha256      VARCHAR(64) NOT NULL DEFAULT '',           -- sha256(content) for integrity
  size_bytes  INTEGER     NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_we_inv_artifacts_run
  ON public.we_investigation_artifacts (run_id);

CREATE INDEX IF NOT EXISTS idx_we_inv_artifacts_event
  ON public.we_investigation_artifacts (event_id)
  WHERE event_id IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
--  Row-Level Security (RLS)
--  Pattern ported from AiSOC rls.py — tenant_id isolation.
--  The backend uses the service role key (bypasses RLS).
--  Frontend uses anon/user-scoped client; RLS enforces tenant boundary.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.we_investigation_runs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.we_investigation_events    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.we_investigation_artifacts ENABLE ROW LEVEL SECURITY;

-- Policy: service role bypasses RLS (used by backend/routes/*.js)
DO $$ BEGIN
  -- investigation_runs
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename='we_investigation_runs' AND policyname='we_inv_runs_tenant_isolation'
  ) THEN
    CREATE POLICY we_inv_runs_tenant_isolation ON public.we_investigation_runs
      USING (tenant_id = current_setting('app.tenant_id', true));
  END IF;
  -- investigation_events
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename='we_investigation_events' AND policyname='we_inv_events_tenant_isolation'
  ) THEN
    CREATE POLICY we_inv_events_tenant_isolation ON public.we_investigation_events
      USING (tenant_id = current_setting('app.tenant_id', true));
  END IF;
  -- investigation_artifacts
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename='we_investigation_artifacts' AND policyname='we_inv_artifacts_tenant_isolation'
  ) THEN
    CREATE POLICY we_inv_artifacts_tenant_isolation ON public.we_investigation_artifacts
      USING (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Realtime publication
--  Enables Supabase Realtime postgres_changes subscriptions on the events
--  table so the frontend investigation panel can subscribe to run_id = X
--  and receive each step as it is appended.
-- ─────────────────────────────────────────────────────────────────────────────
DO $$ BEGIN
  -- Add tables to supabase_realtime publication if not already there
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND tablename = 'we_investigation_events'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.we_investigation_events;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND tablename = 'we_investigation_runs'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.we_investigation_runs;
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Smoke test (safe to run — SELECTs only)
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
  t TEXT;
  trig_count INT;
BEGIN
  -- Verify tables exist
  FOR t IN SELECT unnest(ARRAY['we_investigation_runs','we_investigation_events','we_investigation_artifacts']) LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = t AND schemaname = 'public') THEN
      RAISE EXCEPTION '[Phase1 Migration] Table % was not created', t;
    END IF;
  END LOOP;
  -- Verify append-only trigger exists
  SELECT COUNT(*) INTO trig_count
  FROM pg_trigger
  WHERE tgname = 'trg_we_investigation_events_immutable';
  IF trig_count = 0 THEN
    RAISE EXCEPTION '[Phase1 Migration] Append-only trigger not found on we_investigation_events';
  END IF;
  RAISE NOTICE '[Phase1 Migration] ✅ All tables and triggers created successfully';
END $$;
