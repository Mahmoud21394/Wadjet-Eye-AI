-- ══════════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — v5.1 Schema Migration
--  FILE: backend/database/migration-v5.1-settings-soar.sql
--
--  Run this in Supabase SQL Editor to add missing tables for v5.1.
-- ══════════════════════════════════════════════════════════════════════

-- ── Platform Settings (per-tenant) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_settings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  settings    JSONB NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_platform_settings_tenant ON platform_settings(tenant_id);

-- RLS
ALTER TABLE platform_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS "service_role_full_access_settings"
  ON platform_settings FOR ALL
  TO service_role
  USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS "tenant_read_settings"
  ON platform_settings FOR SELECT
  USING (tenant_id IN (
    SELECT tenant_id FROM users WHERE id = auth.uid()
  ));

CREATE POLICY IF NOT EXISTS "admin_write_settings"
  ON platform_settings FOR ALL
  USING (tenant_id IN (
    SELECT tenant_id FROM users WHERE id = auth.uid() AND role IN ('ADMIN','SUPER_ADMIN')
  ));

-- ── SOAR Executions (playbook run history) ────────────────────────────
CREATE TABLE IF NOT EXISTS soar_executions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  playbook_id     UUID,
  playbook_name   TEXT NOT NULL,
  trigger_type    TEXT NOT NULL DEFAULT 'manual',  -- manual|automatic|scheduled
  trigger_source  TEXT,
  trigger_data    JSONB DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'running',  -- running|completed|failed|pending_approval|cancelled
  steps           JSONB DEFAULT '[]',
  results         JSONB DEFAULT '{}',
  error           TEXT,
  started_at      TIMESTAMPTZ DEFAULT NOW(),
  completed_at    TIMESTAMPTZ,
  created_by      UUID REFERENCES users(id),
  approved_by     UUID REFERENCES users(id),
  approved_at     TIMESTAMPTZ,
  duration_ms     INTEGER,
  actions_executed INTEGER DEFAULT 0,
  actions_failed   INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_soar_executions_tenant    ON soar_executions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_soar_executions_status    ON soar_executions(status);
CREATE INDEX IF NOT EXISTS idx_soar_executions_started   ON soar_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook  ON soar_executions(playbook_id);

ALTER TABLE soar_executions ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS "service_role_full_access_soar_exec"
  ON soar_executions FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS "tenant_read_soar_exec"
  ON soar_executions FOR SELECT
  USING (tenant_id IN (SELECT tenant_id FROM users WHERE id = auth.uid()));

-- ── Playbooks — ensure extended columns exist ─────────────────────────
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS trigger_conditions JSONB DEFAULT '[]';
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS actions            JSONB DEFAULT '[]';
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS is_active          BOOLEAN DEFAULT true;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS run_count          INTEGER DEFAULT 0;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS last_run_at        TIMESTAMPTZ;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS auto_execute       BOOLEAN DEFAULT false;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS requires_approval  BOOLEAN DEFAULT false;

-- ── IOC columns — add missing columns ─────────────────────────────────
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS confidence      INTEGER DEFAULT 80;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS malware_family  TEXT;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS first_seen      TIMESTAMPTZ;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS relationship_data JSONB DEFAULT '{}';

-- ── IOC stats RPC helper ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION get_ioc_stats_by_type(p_tenant_id UUID)
RETURNS TABLE (type TEXT, count BIGINT, avg_risk_score NUMERIC) AS $$
BEGIN
  RETURN QUERY
  SELECT
    i.type,
    COUNT(*) as count,
    ROUND(AVG(i.risk_score)::NUMERIC, 1) as avg_risk_score
  FROM iocs i
  WHERE i.tenant_id = p_tenant_id
    AND i.status = 'active'
  GROUP BY i.type
  ORDER BY count DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ── Verify ────────────────────────────────────────────────────────────
SELECT
  table_name,
  pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) AS size
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('platform_settings','soar_executions','iocs','playbooks')
ORDER BY table_name;
