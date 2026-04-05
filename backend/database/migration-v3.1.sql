-- ══════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — DB Migration v3.1
--  Fixes: cvss_score alias, detection_timeline table, collector stats
--
--  HOW TO USE:
--    Supabase → SQL Editor → paste → Run
--    Safe to re-run (all IF NOT EXISTS / DO $$ guards)
-- ══════════════════════════════════════════════════════════════════════

-- ────────────────────────────────────────────────
-- 1. Add cvss_score alias column to vulnerabilities
--    (backend previously queried cvss_score which doesn't exist;
--     the real column is cvss_v3_score — add a generated alias)
-- ────────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE public.vulnerabilities
    ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(4,1)
      GENERATED ALWAYS AS (cvss_v3_score) STORED;
  RAISE NOTICE 'vulnerabilities.cvss_score alias added';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'cvss_score alias skipped: %', SQLERRM;
END $$;

-- ────────────────────────────────────────────────
-- 2. Ensure detection_timeline table exists
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.detection_timeline (
  id           UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id    UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  event_type   TEXT NOT NULL DEFAULT 'detection',
  title        TEXT NOT NULL,
  description  TEXT,
  severity     TEXT DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
  source       TEXT,
  ioc_value    TEXT,
  ioc_type     TEXT,
  alert_id     UUID,
  mitre_id     TEXT,
  raw_data     JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dtl_tenant   ON public.detection_timeline(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dtl_created  ON public.detection_timeline(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dtl_severity ON public.detection_timeline(severity);

-- RLS for detection_timeline
ALTER TABLE public.detection_timeline ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dtl_isolation ON public.detection_timeline;
CREATE POLICY dtl_isolation ON public.detection_timeline
  USING (tenant_id = (current_setting('app.tenant_id', true))::UUID);

-- ────────────────────────────────────────────────
-- 3. Ensure collectors table has health/status fields
-- ────────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE public.collectors ADD COLUMN IF NOT EXISTS health       TEXT DEFAULT 'healthy';
  ALTER TABLE public.collectors ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ;
  ALTER TABLE public.collectors ADD COLUMN IF NOT EXISTS iocs_collected INTEGER DEFAULT 0;
  ALTER TABLE public.collectors ADD COLUMN IF NOT EXISTS is_active    BOOLEAN DEFAULT true;
  RAISE NOTICE 'collectors extended';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'collectors extend skipped: %', SQLERRM;
END $$;

-- ────────────────────────────────────────────────
-- 4. Trigger for detection_timeline updated_at
-- ────────────────────────────────────────────────
DROP TRIGGER IF EXISTS upd_dtl ON public.detection_timeline;
CREATE TRIGGER upd_dtl
  BEFORE UPDATE ON public.detection_timeline
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

RAISE NOTICE 'Migration v3.1 complete';
