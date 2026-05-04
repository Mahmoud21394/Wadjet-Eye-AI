-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Migration 002: RLS Policies, Indexes & Partitioning
--  backend/db/migrations/002_rls_policies_indexes.sql
--
--  Implements:
--    - Row-Level Security (RLS) for all tenant-scoped tables
--    - Performance indexes (BRIN, GIN, BTREE composite)
--    - TimescaleDB hypertable partitioning for time-series tables
--    - Partial indexes for common filter patterns
--
--  Run AFTER 001_initial_schema.sql
--  Run: psql $DATABASE_URL -f migrations/002_rls_policies_indexes.sql
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ════════════════════════════════════════════════════════════════
--  HELPER: current_tenant_id() — reads from session variable
--  set by the API layer: SET LOCAL app.tenant_id = '…'
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::UUID;
$$;

-- ════════════════════════════════════════════════════════════════
--  ROW-LEVEL SECURITY
-- ════════════════════════════════════════════════════════════════

-- ── alerts ────────────────────────────────────────────────────────
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY alerts_tenant_isolation ON alerts
  USING (tenant_id = current_tenant_id());

CREATE POLICY alerts_insert_tenant ON alerts
  FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- ── cases ─────────────────────────────────────────────────────────
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;

CREATE POLICY cases_tenant_isolation ON cases
  USING (tenant_id = current_tenant_id());

CREATE POLICY cases_insert_tenant ON cases
  FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- ── iocs ──────────────────────────────────────────────────────────
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;

CREATE POLICY iocs_tenant_isolation ON iocs
  USING (tenant_id = current_tenant_id());

CREATE POLICY iocs_insert_tenant ON iocs
  FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- ── audit_logs ────────────────────────────────────────────────────
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_tenant_isolation ON audit_logs
  USING (tenant_id = current_tenant_id());

-- Super admins can read all tenant audit logs
CREATE POLICY audit_logs_super_admin ON audit_logs
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
        AND u.role = 'SUPER_ADMIN'
    )
  );

-- ── threat_intel ──────────────────────────────────────────────────
ALTER TABLE threat_intel ENABLE ROW LEVEL SECURITY;

CREATE POLICY threat_intel_tenant_isolation ON threat_intel
  USING (tenant_id = current_tenant_id() OR is_global = true);

CREATE POLICY threat_intel_insert_tenant ON threat_intel
  FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- ── playbooks ─────────────────────────────────────────────────────
ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY playbooks_tenant_isolation ON playbooks
  USING (tenant_id = current_tenant_id() OR is_global = true);

-- ── users ─────────────────────────────────────────────────────────
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Users can only see their own tenant's users
CREATE POLICY users_tenant_isolation ON users
  USING (tenant_id = current_tenant_id());

-- Users can read their own record regardless of tenant setting
CREATE POLICY users_self_read ON users
  FOR SELECT USING (id = auth.uid());

-- ── soc_metrics ───────────────────────────────────────────────────
ALTER TABLE soc_metrics ENABLE ROW LEVEL SECURITY;

CREATE POLICY soc_metrics_tenant_isolation ON soc_metrics
  USING (tenant_id = current_tenant_id());

-- ── stix_objects ──────────────────────────────────────────────────
ALTER TABLE stix_objects ENABLE ROW LEVEL SECURITY;

CREATE POLICY stix_objects_tenant_isolation ON stix_objects
  USING (tenant_id = current_tenant_id() OR is_public = true);

-- ── agent_tasks ───────────────────────────────────────────────────
ALTER TABLE agent_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_tasks_tenant_isolation ON agent_tasks
  USING (tenant_id = current_tenant_id());

-- ── agent_decisions ───────────────────────────────────────────────
ALTER TABLE agent_decisions ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_decisions_tenant_isolation ON agent_decisions
  USING (tenant_id = current_tenant_id());

-- ── detection_rules ───────────────────────────────────────────────
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY detection_rules_tenant_isolation ON detection_rules
  USING (tenant_id = current_tenant_id() OR is_global = true);

-- ── alert_clusters ────────────────────────────────────────────────
ALTER TABLE alert_clusters ENABLE ROW LEVEL SECURITY;

CREATE POLICY alert_clusters_tenant_isolation ON alert_clusters
  USING (tenant_id = current_tenant_id());

-- ── threat_graph_nodes ────────────────────────────────────────────
ALTER TABLE threat_graph_nodes ENABLE ROW LEVEL SECURITY;

CREATE POLICY threat_graph_nodes_tenant ON threat_graph_nodes
  USING (tenant_id = current_tenant_id());

-- ── threat_graph_edges ────────────────────────────────────────────
ALTER TABLE threat_graph_edges ENABLE ROW LEVEL SECURITY;

CREATE POLICY threat_graph_edges_tenant ON threat_graph_edges
  USING (tenant_id = current_tenant_id());

-- ── whatif_simulations ────────────────────────────────────────────
ALTER TABLE whatif_simulations ENABLE ROW LEVEL SECURITY;

CREATE POLICY whatif_simulations_tenant ON whatif_simulations
  USING (tenant_id = current_tenant_id());

-- ── adversary_sim_sessions ────────────────────────────────────────
ALTER TABLE adversary_sim_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY adversary_sim_sessions_tenant ON adversary_sim_sessions
  USING (tenant_id = current_tenant_id());

-- ════════════════════════════════════════════════════════════════
--  TIMESCALEDB HYPERTABLES (time-series partitioning)
-- ════════════════════════════════════════════════════════════════

-- Only apply if TimescaleDB extension is available
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    -- Alerts partitioned by created_at (7-day chunks)
    PERFORM create_hypertable('alerts', 'created_at',
      chunk_time_interval => INTERVAL '7 days',
      if_not_exists => TRUE
    );

    -- SOC Metrics partitioned by recorded_at (1-day chunks)
    PERFORM create_hypertable('soc_metrics', 'recorded_at',
      chunk_time_interval => INTERVAL '1 day',
      if_not_exists => TRUE
    );

    -- Audit logs partitioned by created_at (1-day chunks)
    PERFORM create_hypertable('audit_logs', 'created_at',
      chunk_time_interval => INTERVAL '1 day',
      if_not_exists => TRUE
    );

    RAISE NOTICE 'TimescaleDB hypertables created successfully';
  ELSE
    RAISE NOTICE 'TimescaleDB not available — skipping hypertables';
  END IF;
END $$;

-- ════════════════════════════════════════════════════════════════
--  PERFORMANCE INDEXES
-- ════════════════════════════════════════════════════════════════

-- ── alerts ────────────────────────────────────────────────────────
-- Composite index for common list queries (tenant + status + severity)
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status_severity
  ON alerts (tenant_id, status, severity, created_at DESC);

-- Partial index for open/in-progress alerts (the hot path)
CREATE INDEX IF NOT EXISTS idx_alerts_open
  ON alerts (tenant_id, created_at DESC)
  WHERE status IN ('open', 'in_progress', 'escalated');

-- GIN index for JSONB metadata searches
CREATE INDEX IF NOT EXISTS idx_alerts_metadata_gin
  ON alerts USING GIN (metadata jsonb_path_ops);

-- BRIN index for time-range scans (very cheap for append-only data)
CREATE INDEX IF NOT EXISTS idx_alerts_created_brin
  ON alerts USING BRIN (created_at) WITH (pages_per_range = 128);

-- Source IP full-text search
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
  ON alerts (source_ip) WHERE source_ip IS NOT NULL;

-- MITRE ATT&CK technique lookup
CREATE INDEX IF NOT EXISTS idx_alerts_mitre_gin
  ON alerts USING GIN (mitre_techniques);

-- ── iocs ──────────────────────────────────────────────────────────
-- Value lookup (the most common query)
CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm
  ON iocs USING GIN (value gin_trgm_ops);

-- Composite for tenant + type + active filter
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_type_active
  ON iocs (tenant_id, ioc_type, is_active, last_seen DESC);

-- Hash lookups (SHA256 most common)
CREATE INDEX IF NOT EXISTS idx_iocs_hash_sha256
  ON iocs (value) WHERE ioc_type = 'hash_sha256';

-- Expiry cleanup index
CREATE INDEX IF NOT EXISTS idx_iocs_expires_at
  ON iocs (expires_at) WHERE expires_at IS NOT NULL;

-- ── cases ─────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_cases_tenant_status
  ON cases (tenant_id, status, priority, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cases_assigned_to
  ON cases (assigned_to) WHERE assigned_to IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_open
  ON cases (tenant_id, created_at DESC)
  WHERE status IN ('open', 'investigating', 'contained');

-- ── audit_logs ────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created
  ON audit_logs (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action
  ON audit_logs (user_id, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource
  ON audit_logs (resource_type, resource_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_brin
  ON audit_logs USING BRIN (created_at) WITH (pages_per_range = 64);

-- ── threat_intel ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_threat_intel_tenant_type
  ON threat_intel (tenant_id, intel_type, confidence DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intel_tags_gin
  ON threat_intel USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_threat_intel_source
  ON threat_intel (source, created_at DESC);

-- ── stix_objects ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_stix_objects_type
  ON stix_objects (tenant_id, stix_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stix_objects_stix_id
  ON stix_objects (stix_id);

CREATE INDEX IF NOT EXISTS idx_stix_objects_labels_gin
  ON stix_objects USING GIN (labels);

-- ── detection_rules ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant_active
  ON detection_rules (tenant_id, is_active, severity);

CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre
  ON detection_rules USING GIN (mitre_techniques);

-- ── agent_tasks ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_agent_tasks_tenant_status
  ON agent_tasks (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_alert_id
  ON agent_tasks (alert_id) WHERE alert_id IS NOT NULL;

-- ── agent_decisions ───────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_agent_decisions_tenant
  ON agent_decisions (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_decisions_pending
  ON agent_decisions (tenant_id, created_at DESC)
  WHERE status = 'pending_approval';

-- ── soc_metrics ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_soc_metrics_tenant_recorded
  ON soc_metrics (tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_soc_metrics_recorded_brin
  ON soc_metrics USING BRIN (recorded_at) WITH (pages_per_range = 32);

-- ── alert_clusters ────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_alert_clusters_tenant_created
  ON alert_clusters (tenant_id, created_at DESC);

-- ── threat_graph ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_threat_graph_nodes_tenant
  ON threat_graph_nodes (tenant_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_threat_graph_edges_tenant
  ON threat_graph_edges (tenant_id, source_node_id, target_node_id);

-- ── users ─────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_tenant_role
  ON users (tenant_id, role, is_active);

CREATE INDEX IF NOT EXISTS idx_users_email
  ON users (email);

-- ════════════════════════════════════════════════════════════════
--  COMPRESSION POLICIES (TimescaleDB)
-- ════════════════════════════════════════════════════════════════
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    -- Compress audit_logs older than 30 days
    PERFORM add_compression_policy('audit_logs',
      compress_after => INTERVAL '30 days');

    -- Compress soc_metrics older than 7 days
    PERFORM add_compression_policy('soc_metrics',
      compress_after => INTERVAL '7 days');

    RAISE NOTICE 'TimescaleDB compression policies applied';
  END IF;
END $$;

-- ════════════════════════════════════════════════════════════════
--  DATA RETENTION POLICIES
-- ════════════════════════════════════════════════════════════════
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    -- Drop audit logs older than 365 days (compliance retention)
    PERFORM add_retention_policy('audit_logs',
      drop_after => INTERVAL '365 days');

    -- Drop raw SOC metrics older than 90 days (aggregates kept in views)
    PERFORM add_retention_policy('soc_metrics',
      drop_after => INTERVAL '90 days');

    RAISE NOTICE 'TimescaleDB retention policies applied';
  END IF;
END $$;

COMMIT;
