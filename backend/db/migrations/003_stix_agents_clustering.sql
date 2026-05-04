-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Migration 003: STIX Objects, Agent Tasks,
--                                 Alert Clustering & Purple-Team
--  backend/db/migrations/003_stix_agents_clustering.sql
--
--  Adds tables for:
--    - stix_objects & stix_relationships (Phase 6 STIX/TAXII 2.1)
--    - agent_tasks & agent_decisions (Phase 5 Autonomous SOC Agents)
--    - alert_clusters (Phase 7 DBSCAN clustering)
--    - detection_feedback (Phase 7 self-learning feedback loop)
--    - purple_team_sessions & adversary_sim_sessions (Phase 9)
--    - whatif_simulations (Phase 9)
--    - rag_documents & rag_queries (Phase 3 RAG pipeline)
--    - predictive_threat_scores (Phase 8 forecasting)
--
--  Run AFTER 002_rls_policies_indexes.sql
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ════════════════════════════════════════════════════════════════
--  ENUMS
-- ════════════════════════════════════════════════════════════════

DO $$ BEGIN
  CREATE TYPE stix_object_type AS ENUM (
    'attack-pattern', 'campaign', 'course-of-action', 'grouping',
    'identity', 'indicator', 'infrastructure', 'intrusion-set',
    'location', 'malware', 'malware-analysis', 'note', 'observed-data',
    'opinion', 'report', 'threat-actor', 'tool', 'vulnerability',
    'relationship', 'sighting', 'bundle'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE agent_task_status AS ENUM (
    'queued', 'running', 'completed', 'failed',
    'pending_approval', 'approved', 'rejected', 'cancelled'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE agent_type AS ENUM (
    'triage', 'investigation', 'response', 'enrichment', 'hunting'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE feedback_label AS ENUM (
    'true_positive', 'false_positive', 'true_negative', 'false_negative'
  );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE cluster_algo AS ENUM ('dbscan', 'hdbscan', 'kmeans', 'optics');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ════════════════════════════════════════════════════════════════
--  STIX 2.1 OBJECTS
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS stix_objects (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stix_id         TEXT NOT NULL,                    -- e.g. indicator--uuid
  stix_type       stix_object_type NOT NULL,
  spec_version    TEXT NOT NULL DEFAULT '2.1',
  is_public       BOOLEAN NOT NULL DEFAULT FALSE,   -- shared across tenants
  name            TEXT,
  description     TEXT,
  labels          TEXT[]  DEFAULT '{}',
  confidence      SMALLINT DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  lang            TEXT DEFAULT 'en',
  external_refs   JSONB DEFAULT '[]',
  object_marking  TEXT[]  DEFAULT '{}',
  granular_markings JSONB DEFAULT '[]',
  raw_stix        JSONB NOT NULL,                   -- full STIX object
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  modified_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_from      TIMESTAMPTZ,
  valid_until     TIMESTAMPTZ,
  revoked         BOOLEAN DEFAULT FALSE,
  UNIQUE (tenant_id, stix_id)
);

COMMENT ON TABLE stix_objects IS
  'STIX 2.1 objects ingested via TAXII or manual import. '
  'raw_stix stores the full object for faithful export.';

-- ── STIX Relationships (separate for fast graph traversal) ────────
CREATE TABLE IF NOT EXISTS stix_relationships (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stix_id         TEXT NOT NULL,
  rel_type        TEXT NOT NULL,     -- 'uses', 'indicates', 'mitigates' …
  source_ref      TEXT NOT NULL,     -- stix_id of source object
  target_ref      TEXT NOT NULL,     -- stix_id of target object
  description     TEXT,
  confidence      SMALLINT DEFAULT 50,
  start_time      TIMESTAMPTZ,
  stop_time       TIMESTAMPTZ,
  raw_stix        JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, stix_id)
);

CREATE INDEX IF NOT EXISTS idx_stix_rels_tenant_type
  ON stix_relationships (tenant_id, rel_type);
CREATE INDEX IF NOT EXISTS idx_stix_rels_source
  ON stix_relationships (source_ref);
CREATE INDEX IF NOT EXISTS idx_stix_rels_target
  ON stix_relationships (target_ref);

-- ── TAXII Collections ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS taxii_collections (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  alias           TEXT,
  can_read        BOOLEAN DEFAULT TRUE,
  can_write       BOOLEAN DEFAULT FALSE,
  media_types     TEXT[] DEFAULT ARRAY['application/taxii+json;version=2.1'],
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════════
--  AUTONOMOUS SOC AGENT TASKS & DECISIONS
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS agent_tasks (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_type      agent_type NOT NULL,
  status          agent_task_status NOT NULL DEFAULT 'queued',
  alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
  case_id         UUID REFERENCES cases(id)  ON DELETE SET NULL,
  priority        SMALLINT DEFAULT 50 CHECK (priority BETWEEN 0 AND 100),
  input_context   JSONB NOT NULL DEFAULT '{}',   -- alert/case snapshot
  agent_output    JSONB DEFAULT '{}',            -- raw LLM response
  tool_calls      JSONB DEFAULT '[]',            -- tool invocations log
  tokens_used     INTEGER DEFAULT 0,
  model_used      TEXT,
  execution_ms    INTEGER,
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE agent_tasks IS
  'Each row is one autonomous-agent invocation. '
  'agent_output and tool_calls capture the full reasoning trace.';

CREATE TABLE IF NOT EXISTS agent_decisions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  task_id         UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
  agent_type      agent_type NOT NULL,
  decision        agent_decision NOT NULL,
  reasoning       TEXT NOT NULL,
  confidence      NUMERIC(5,2) DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
  recommended_actions JSONB DEFAULT '[]',
  evidence        JSONB DEFAULT '[]',             -- supporting evidence
  risk_assessment JSONB DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'pending_approval'
                  CHECK (status IN ('pending_approval','approved','rejected','auto_applied')),
  reviewed_by     UUID REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at     TIMESTAMPTZ,
  review_notes    TEXT,
  applied_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════════
--  ALERT CLUSTERING (DBSCAN / HDBSCAN — Phase 7)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS alert_clusters (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cluster_label   INTEGER NOT NULL,              -- -1 = noise
  algorithm       cluster_algo NOT NULL DEFAULT 'dbscan',
  alert_ids       UUID[] NOT NULL DEFAULT '{}', -- member alert IDs
  centroid        JSONB DEFAULT '{}',            -- feature-space centroid
  feature_vector  JSONB DEFAULT '{}',            -- avg feature values
  size            INTEGER NOT NULL DEFAULT 0,
  avg_severity    NUMERIC(5,2) DEFAULT 0,
  dominant_tactic TEXT,
  dominant_source TEXT,
  eps             NUMERIC(6,4),                  -- DBSCAN eps param
  min_samples     INTEGER,                       -- DBSCAN min_samples param
  silhouette_score NUMERIC(6,4),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  run_id          UUID NOT NULL DEFAULT uuid_generate_v4()  -- clustering run
);

COMMENT ON TABLE alert_clusters IS
  'Results of each DBSCAN/HDBSCAN clustering run on the alert feature space. '
  'cluster_label=-1 means noise (unclustered) alerts.';

-- ── Cluster membership (alert ↔ cluster) ──────────────────────────
CREATE TABLE IF NOT EXISTS alert_cluster_members (
  alert_id        UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  cluster_id      UUID NOT NULL REFERENCES alert_clusters(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL,
  distance        NUMERIC(8,6) DEFAULT 0,  -- distance from centroid
  is_core_point   BOOLEAN DEFAULT FALSE,
  PRIMARY KEY (alert_id, cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_members_cluster
  ON alert_cluster_members (cluster_id);

-- ════════════════════════════════════════════════════════════════
--  DETECTION FEEDBACK (Phase 7 Self-Learning)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS detection_feedback (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_id        UUID REFERENCES alerts(id)    ON DELETE SET NULL,
  rule_id         UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
  analyst_id      UUID REFERENCES users(id)     ON DELETE SET NULL,
  label           feedback_label NOT NULL,
  confidence      NUMERIC(5,2) DEFAULT 100,
  rationale       TEXT,
  feature_snapshot JSONB DEFAULT '{}',    -- alert features at feedback time
  model_version   TEXT,                   -- which model was active
  applied_to_model BOOLEAN DEFAULT FALSE, -- has feedback been ingested?
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE detection_feedback IS
  'Analyst feedback on alert classifications used to retrain '
  'the self-learning detection model.';

CREATE INDEX IF NOT EXISTS idx_detection_feedback_tenant_unapplied
  ON detection_feedback (tenant_id, created_at)
  WHERE applied_to_model = FALSE;

CREATE INDEX IF NOT EXISTS idx_detection_feedback_rule
  ON detection_feedback (rule_id, label);

-- ── Model versions registry ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_model_versions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  model_name      TEXT NOT NULL,
  version         TEXT NOT NULL,
  algorithm       TEXT NOT NULL,
  hyperparams     JSONB DEFAULT '{}',
  metrics         JSONB DEFAULT '{}',   -- precision, recall, F1, AUC
  training_samples INTEGER DEFAULT 0,
  feature_names   TEXT[] DEFAULT '{}',
  model_path      TEXT,                 -- S3/blob path to serialised model
  is_active       BOOLEAN DEFAULT FALSE,
  deployed_at     TIMESTAMPTZ,
  trained_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  trained_by      UUID REFERENCES users(id) ON DELETE SET NULL
);

-- ════════════════════════════════════════════════════════════════
--  PURPLE TEAM & ADVERSARY SIMULATION (Phase 9)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS purple_team_sessions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  red_team_lead   UUID REFERENCES users(id) ON DELETE SET NULL,
  blue_team_lead  UUID REFERENCES users(id) ON DELETE SET NULL,
  status          TEXT NOT NULL DEFAULT 'planned'
                  CHECK (status IN ('planned','active','completed','cancelled')),
  scope           JSONB DEFAULT '{}',
  objectives      TEXT[] DEFAULT '{}',
  findings        JSONB DEFAULT '[]',
  mitre_coverage  JSONB DEFAULT '{}',  -- technique_id → detected/missed
  detection_rate  NUMERIC(5,2) DEFAULT 0,
  mttr_minutes    INTEGER DEFAULT 0,
  start_time      TIMESTAMPTZ,
  end_time        TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS adversary_sim_sessions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario_id     TEXT NOT NULL,
  scenario_name   TEXT NOT NULL,
  threat_actor    TEXT,
  mitre_tactics   TEXT[] DEFAULT '{}',
  attack_chain    JSONB DEFAULT '[]',
  status          TEXT NOT NULL DEFAULT 'completed'
                  CHECK (status IN ('running','completed','failed','aborted')),
  outcome         TEXT CHECK (outcome IN ('success','partial','failed','detected')),
  results         JSONB DEFAULT '{}',
  detection_events JSONB DEFAULT '[]',
  alerts_generated INTEGER DEFAULT 0,
  detections_missed INTEGER DEFAULT 0,
  start_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  end_time        TIMESTAMPTZ,
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE adversary_sim_sessions IS
  'Each adversary simulation run (scenario execution) with full '
  'attack chain replay and detection-rate results.';

CREATE INDEX IF NOT EXISTS idx_adversary_sim_tenant
  ON adversary_sim_sessions (tenant_id, created_at DESC);

-- ── What-If Simulations ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS whatif_simulations (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario_id     TEXT NOT NULL,
  scenario_name   TEXT NOT NULL,
  user_inputs     JSONB NOT NULL DEFAULT '{}',
  outcome         TEXT,
  risk_reduction  NUMERIC(5,2) DEFAULT 0,
  recommendations JSONB DEFAULT '[]',
  cost_estimate   NUMERIC(12,2),
  roi_score       NUMERIC(5,2),
  run_by          UUID REFERENCES users(id) ON DELETE SET NULL,
  run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_whatif_simulations_tenant
  ON whatif_simulations (tenant_id, run_at DESC);

-- ════════════════════════════════════════════════════════════════
--  RAG PIPELINE DOCUMENTS & QUERIES (Phase 3)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS rag_documents (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  doc_type        TEXT NOT NULL CHECK (doc_type IN (
                    'threat_report','mitre_technique','cve_advisory',
                    'sigma_rule','playbook','incident_report','custom')),
  title           TEXT NOT NULL,
  source_url      TEXT,
  source          TEXT,
  content_hash    TEXT NOT NULL,      -- SHA-256 of raw content
  chunk_count     INTEGER DEFAULT 0,
  vector_indexed  BOOLEAN DEFAULT FALSE,
  vector_store    TEXT DEFAULT 'pinecone',
  index_name      TEXT,
  tags            TEXT[] DEFAULT '{}',
  metadata        JSONB DEFAULT '{}',
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_docs_tenant_type
  ON rag_documents (tenant_id, doc_type, ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_rag_docs_hash
  ON rag_documents (content_hash);

-- ── RAG Query Log ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rag_queries (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  query_text      TEXT NOT NULL,
  query_vector    JSONB,               -- embedding (stored for reuse)
  retrieved_docs  JSONB DEFAULT '[]', -- [{doc_id, score, chunk}]
  llm_response    TEXT,
  model_used      TEXT,
  tokens_in       INTEGER DEFAULT 0,
  tokens_out      INTEGER DEFAULT 0,
  latency_ms      INTEGER,
  feedback        TEXT CHECK (feedback IN ('helpful','not_helpful','incorrect')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_queries_tenant_created
  ON rag_queries (tenant_id, created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  PREDICTIVE THREAT SCORES (Phase 8)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS predictive_threat_scores (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  entity_type     TEXT NOT NULL CHECK (entity_type IN (
                    'ip','domain','asn','threat_actor','malware_family','cve')),
  entity_value    TEXT NOT NULL,
  threat_score    NUMERIC(5,2) NOT NULL CHECK (threat_score BETWEEN 0 AND 100),
  confidence      NUMERIC(5,2) DEFAULT 50,
  forecast_horizon TEXT DEFAULT '24h', -- '24h','7d','30d'
  contributing_signals JSONB DEFAULT '[]',
  model_version   TEXT,
  valid_until     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, entity_type, entity_value, forecast_horizon)
);

CREATE INDEX IF NOT EXISTS idx_predictive_scores_tenant
  ON predictive_threat_scores (tenant_id, threat_score DESC, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_predictive_scores_entity
  ON predictive_threat_scores (entity_type, entity_value);

-- ════════════════════════════════════════════════════════════════
--  SYSMON / EDR EVENT INGESTION (Phase 4)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sysmon_events (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  event_id        INTEGER NOT NULL,    -- Sysmon Event ID (1=process, 3=network…)
  event_type      TEXT NOT NULL,
  hostname        TEXT,
  username        TEXT,
  process_guid    TEXT,
  process_id      INTEGER,
  process_name    TEXT,
  parent_guid     TEXT,
  parent_name     TEXT,
  command_line    TEXT,
  image_path      TEXT,
  hash_md5        TEXT,
  hash_sha256     TEXT,
  dest_ip         INET,
  dest_port       INTEGER,
  src_ip          INET,
  src_port        INTEGER,
  protocol        TEXT,
  raw_event       JSONB NOT NULL DEFAULT '{}',
  rule_name       TEXT,
  alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
  event_time      TIMESTAMPTZ NOT NULL,
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE sysmon_events IS
  'Sysmon / EDR telemetry events ingested from Windows endpoints. '
  'Partitioned by ingested_at for time-series performance.';

CREATE INDEX IF NOT EXISTS idx_sysmon_events_tenant_time
  ON sysmon_events (tenant_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_sysmon_events_host
  ON sysmon_events (hostname, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_sysmon_events_hash
  ON sysmon_events (hash_sha256) WHERE hash_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sysmon_events_dest_ip
  ON sysmon_events (dest_ip) WHERE dest_ip IS NOT NULL;

-- ── TimescaleDB hypertable for sysmon ─────────────────────────────
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    PERFORM create_hypertable('sysmon_events', 'ingested_at',
      chunk_time_interval => INTERVAL '1 day',
      if_not_exists => TRUE
    );
    RAISE NOTICE 'sysmon_events hypertable created';
  END IF;
END $$;

-- ════════════════════════════════════════════════════════════════
--  THREAT ACTOR PROFILES (Phase 6 intelligence)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS threat_actors (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  stix_object_id  UUID REFERENCES stix_objects(id) ON DELETE SET NULL,
  name            TEXT NOT NULL,
  aliases         TEXT[] DEFAULT '{}',
  actor_type      TEXT CHECK (actor_type IN (
                    'nation-state','criminal','hacktivism','insider',
                    'terrorist','unknown')),
  sophistication  TEXT CHECK (sophistication IN (
                    'none','minimal','intermediate','advanced',
                    'expert','innovator','strategic')),
  motivation      TEXT[] DEFAULT '{}',
  country_of_origin TEXT,
  first_seen      DATE,
  last_seen       DATE,
  active          BOOLEAN DEFAULT TRUE,
  ttps            JSONB DEFAULT '[]',   -- [{technique_id, tactic}]
  targeted_sectors TEXT[] DEFAULT '{}',
  targeted_regions TEXT[] DEFAULT '{}',
  description     TEXT,
  references      JSONB DEFAULT '[]',
  confidence      SMALLINT DEFAULT 50,
  source          TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_actors_tenant
  ON threat_actors (tenant_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_threat_actors_name_trgm
  ON threat_actors USING GIN (name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_threat_actors_sectors
  ON threat_actors USING GIN (targeted_sectors);

-- ════════════════════════════════════════════════════════════════
--  ROW-LEVEL SECURITY FOR NEW TABLES
-- ════════════════════════════════════════════════════════════════

ALTER TABLE stix_objects             ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_relationships       ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxii_collections        ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_tasks              ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_decisions          ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_clusters           ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_cluster_members    ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_feedback       ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_model_versions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE purple_team_sessions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE adversary_sim_sessions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE whatif_simulations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_documents            ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_queries              ENABLE ROW LEVEL SECURITY;
ALTER TABLE predictive_threat_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE sysmon_events            ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_actors            ENABLE ROW LEVEL SECURITY;

-- Generic tenant-isolation policy macro applied to each table
CREATE POLICY stix_objects_rls             ON stix_objects             USING (tenant_id = current_tenant_id() OR is_public = TRUE);
CREATE POLICY stix_rels_rls               ON stix_relationships       USING (tenant_id = current_tenant_id());
CREATE POLICY taxii_collections_rls       ON taxii_collections        USING (tenant_id = current_tenant_id());
CREATE POLICY agent_tasks_rls             ON agent_tasks              USING (tenant_id = current_tenant_id());
CREATE POLICY agent_decisions_rls         ON agent_decisions          USING (tenant_id = current_tenant_id());
CREATE POLICY alert_clusters_rls          ON alert_clusters           USING (tenant_id = current_tenant_id());
CREATE POLICY alert_cluster_members_rls   ON alert_cluster_members    USING (tenant_id = current_tenant_id());
CREATE POLICY detection_feedback_rls      ON detection_feedback       USING (tenant_id = current_tenant_id());
CREATE POLICY ml_model_versions_rls       ON ml_model_versions        USING (tenant_id = current_tenant_id());
CREATE POLICY purple_team_rls             ON purple_team_sessions     USING (tenant_id = current_tenant_id());
CREATE POLICY adversary_sim_rls           ON adversary_sim_sessions   USING (tenant_id = current_tenant_id());
CREATE POLICY whatif_simulations_rls      ON whatif_simulations       USING (tenant_id = current_tenant_id());
CREATE POLICY rag_documents_rls           ON rag_documents            USING (tenant_id = current_tenant_id());
CREATE POLICY rag_queries_rls             ON rag_queries              USING (tenant_id = current_tenant_id());
CREATE POLICY predictive_scores_rls       ON predictive_threat_scores USING (tenant_id = current_tenant_id());
CREATE POLICY sysmon_events_rls           ON sysmon_events            USING (tenant_id = current_tenant_id());
CREATE POLICY threat_actors_rls           ON threat_actors            USING (tenant_id = current_tenant_id());

COMMIT;
