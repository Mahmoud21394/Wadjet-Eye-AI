-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — PostgreSQL / Supabase Schema (Phase 10)
--  data/migrations/001_initial_schema.sql
--
--  Full schema for all platform features:
--  Phase 1:  users, tenants, mfa, audit_logs
--  Phase 2:  kafka_offsets, event_streams
--  Phase 3:  alerts, cases, iocs, detections, cluster_feedback
--  Phase 4:  dark_web_findings, threat_actors, campaigns
--  Phase 5:  agent_tasks, agent_decisions, hitl_checkpoints
--  Phase 6:  stix_objects, taxii_collections, siem_connectors
--  Phase 7:  purple_team_runs, detection_gaps, rule_weights
--  Phase 8:  executive_reports, incident_reports, investigations
--  Phase 9:  soc_metrics_snapshots, analyst_workload, case_assignments
--
--  Apply: psql $DATABASE_URL -f data/migrations/001_initial_schema.sql
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ── Extensions ─────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";       -- composite GIN indexes

-- ── Enum types ─────────────────────────────────────────────────
DO $$ BEGIN
  CREATE TYPE severity_level AS ENUM ('CRITICAL','HIGH','MEDIUM','LOW','INFO');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE alert_status AS ENUM ('open','investigating','escalated','closed','suppressed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE case_status AS ENUM ('open','in_progress','escalated','resolved','closed','archived');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE alert_outcome AS ENUM ('true_positive','false_positive','true_negative','false_negative','benign','escalated','undecided');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE ioc_type AS ENUM ('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','filename','registry','user_agent','asn','cidr');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE mfa_method AS ENUM ('totp','backup_code','sms','email_otp');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE agent_decision AS ENUM ('auto_close','auto_escalate','needs_review','respond','investigate','suppress');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ════════════════════════════════════════════════════════════════
--  PHASE 1 — IDENTITY & ACCESS
-- ════════════════════════════════════════════════════════════════

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name          TEXT NOT NULL,
  slug          TEXT UNIQUE NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'enterprise',
  config        JSONB NOT NULL DEFAULT '{}',
  mfa_enforced  BOOLEAN NOT NULL DEFAULT false,
  ip_allowlist  TEXT[],
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active     BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- Users
CREATE TABLE IF NOT EXISTS users (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  email            TEXT UNIQUE NOT NULL,
  display_name     TEXT,
  role             TEXT NOT NULL DEFAULT 'analyst',
  permissions      TEXT[] NOT NULL DEFAULT '{}',
  mfa_enabled      BOOLEAN NOT NULL DEFAULT false,
  mfa_secret       TEXT,                         -- TOTP secret (encrypted at rest)
  mfa_backup_codes TEXT[],                       -- hashed backup codes
  last_login_at    TIMESTAMPTZ,
  last_login_ip    INET,
  failed_logins    INT NOT NULL DEFAULT 0,
  locked_until     TIMESTAMPTZ,
  is_active        BOOLEAN NOT NULL DEFAULT true,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant    ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role      ON users(tenant_id, role);

-- MFA challenges (for TOTP verification state)
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  challenge    TEXT NOT NULL,
  method       mfa_method NOT NULL DEFAULT 'totp',
  verified     BOOLEAN NOT NULL DEFAULT false,
  expires_at   TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id, expires_at);

-- Audit log (immutable)
CREATE TABLE IF NOT EXISTS audit_logs (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    UUID REFERENCES tenants(id),
  user_id      UUID REFERENCES users(id),
  action       TEXT NOT NULL,
  resource     TEXT,
  resource_id  TEXT,
  ip_address   INET,
  user_agent   TEXT,
  request_id   TEXT,
  status_code  INT,
  details      JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Audit log partitions (monthly)
CREATE TABLE IF NOT EXISTS audit_logs_2025_01 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_02 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_03 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_04 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_05 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_06 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_q3 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE IF NOT EXISTS audit_logs_2025_q4 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026    PARTITION OF audit_logs
  FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user_ts   ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_logs(action, created_at DESC);

-- Rule for immutability (no UPDATE/DELETE on audit_logs)
CREATE OR REPLACE RULE audit_no_update AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_no_delete AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- ════════════════════════════════════════════════════════════════
--  PHASE 3 — DETECTION & ALERTING
-- ════════════════════════════════════════════════════════════════

-- Detection rules
CREATE TABLE IF NOT EXISTS detection_rules (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  description      TEXT,
  rule_type        TEXT NOT NULL DEFAULT 'sigma',  -- sigma | yara | custom | ml
  source_format    TEXT NOT NULL DEFAULT 'sigma',
  rule_content     TEXT NOT NULL,
  enabled          BOOLEAN NOT NULL DEFAULT true,
  severity         severity_level NOT NULL DEFAULT 'MEDIUM',
  mitre_tactics    TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  tags             TEXT[] NOT NULL DEFAULT '{}',
  false_positive_rate NUMERIC(5,2),
  true_positive_rate  NUMERIC(5,2),
  weight           NUMERIC(4,3) NOT NULL DEFAULT 1.000,
  suppressed       BOOLEAN NOT NULL DEFAULT false,
  suppressed_at    TIMESTAMPTZ,
  suppressed_reason TEXT,
  created_by       UUID REFERENCES users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rules_tenant   ON detection_rules(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_rules_type     ON detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_rules_mitre    ON detection_rules USING GIN(mitre_techniques);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  rule_id          UUID REFERENCES detection_rules(id),
  title            TEXT NOT NULL,
  description      TEXT,
  severity         severity_level NOT NULL,
  category         TEXT,
  status           alert_status NOT NULL DEFAULT 'open',
  outcome          alert_outcome,
  confidence       INT CHECK (confidence BETWEEN 0 AND 100),
  risk_score       INT CHECK (risk_score BETWEEN 0 AND 100),
  src_ip           INET,
  dst_ip           INET,
  src_port         INT,
  dst_port         INT,
  protocol         TEXT,
  source_host      TEXT,
  dest_host        TEXT,
  process_name     TEXT,
  username         TEXT,
  mitre_tactic     TEXT,
  mitre_technique  TEXT,
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  iocs             JSONB NOT NULL DEFAULT '[]',
  raw_event        JSONB,
  enrichment       JSONB NOT NULL DEFAULT '{}',
  cluster_id       TEXT,
  case_id          UUID,
  ticket_id        TEXT,
  ticket_created_at TIMESTAMPTZ,
  event_time       TIMESTAMPTZ,
  first_seen       TIMESTAMPTZ,
  last_seen        TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS alerts_2025_q1 PARTITION OF alerts FOR VALUES FROM ('2025-01-01') TO ('2025-04-01');
CREATE TABLE IF NOT EXISTS alerts_2025_q2 PARTITION OF alerts FOR VALUES FROM ('2025-04-01') TO ('2025-07-01');
CREATE TABLE IF NOT EXISTS alerts_2025_q3 PARTITION OF alerts FOR VALUES FROM ('2025-07-01') TO ('2025-10-01');
CREATE TABLE IF NOT EXISTS alerts_2025_q4 PARTITION OF alerts FOR VALUES FROM ('2025-10-01') TO ('2026-01-01');
CREATE TABLE IF NOT EXISTS alerts_2026     PARTITION OF alerts FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_ts  ON alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_cluster    ON alerts(cluster_id) WHERE cluster_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_outcome    ON alerts(outcome) WHERE outcome IS NOT NULL;

-- Alert clusters
CREATE TABLE IF NOT EXISTS alert_clusters (
  cluster_id       TEXT PRIMARY KEY,
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  alert_count      INT NOT NULL DEFAULT 0,
  severity         severity_level,
  risk_score       INT,
  first_seen       TIMESTAMPTZ,
  last_seen        TIMESTAMPTZ,
  src_ips          INET[],
  dst_ips          INET[],
  mitre_techniques TEXT[],
  rule_ids         UUID[],
  narrative        TEXT,
  is_campaign      BOOLEAN NOT NULL DEFAULT false,
  campaign_confidence INT,
  analyst_verdict  alert_outcome,
  analyst_id       UUID REFERENCES users(id),
  verdict_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_clusters_tenant ON alert_clusters(tenant_id, created_at DESC);

-- Cluster feedback
CREATE TABLE IF NOT EXISTS cluster_feedback (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cluster_id   TEXT REFERENCES alert_clusters(cluster_id),
  analyst_id   UUID REFERENCES users(id),
  outcome      alert_outcome NOT NULL,
  notes        TEXT,
  labeled_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Alert feedback
CREATE TABLE IF NOT EXISTS alert_feedback (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  alert_id    UUID,  -- no FK since alerts are partitioned
  analyst_id  UUID REFERENCES users(id),
  outcome     alert_outcome NOT NULL,
  rule_ids    JSONB NOT NULL DEFAULT '[]',
  labeled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feedback_analyst ON alert_feedback(analyst_id, labeled_at DESC);

-- Rule weights (self-learning)
CREATE TABLE IF NOT EXISTS rule_weights (
  rule_id      UUID PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
  weight       NUMERIC(4,3) NOT NULL DEFAULT 1.000,
  fp_count     INT NOT NULL DEFAULT 0,
  tp_count     INT NOT NULL DEFAULT 0,
  suppressed   BOOLEAN NOT NULL DEFAULT false,
  suppressed_at TIMESTAMPTZ,
  last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- IOCs
CREATE TABLE IF NOT EXISTS iocs (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    UUID REFERENCES tenants(id) ON DELETE CASCADE,
  type         ioc_type NOT NULL,
  value        TEXT NOT NULL,
  value_hash   TEXT GENERATED ALWAYS AS (encode(sha256(value::bytea), 'hex')) STORED,
  severity     severity_level NOT NULL DEFAULT 'MEDIUM',
  confidence   INT CHECK (confidence BETWEEN 0 AND 100) DEFAULT 80,
  source       TEXT,
  tags         TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,
  is_active    BOOLEAN NOT NULL DEFAULT true,
  enrichment   JSONB NOT NULL DEFAULT '{}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, type, value_hash)
);
CREATE INDEX IF NOT EXISTS idx_iocs_tenant_type ON iocs(tenant_id, type, is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_value_hash  ON iocs(value_hash);
CREATE INDEX IF NOT EXISTS idx_iocs_tags        ON iocs USING GIN(tags);

-- Cases / Incidents
CREATE TABLE IF NOT EXISTS cases (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        severity_level NOT NULL DEFAULT 'MEDIUM',
  priority        TEXT NOT NULL DEFAULT 'P2',  -- P1,P2,P3,P4
  status          case_status NOT NULL DEFAULT 'open',
  assignee_id     UUID REFERENCES users(id),
  escalated       BOOLEAN NOT NULL DEFAULT false,
  escalated_at    TIMESTAMPTZ,
  escalated_to    UUID REFERENCES users(id),
  alert_ids       UUID[] NOT NULL DEFAULT '{}',
  ioc_ids         UUID[] NOT NULL DEFAULT '{}',
  tags            TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  sla_due_at      TIMESTAMPTZ,
  sla_breached    BOOLEAN NOT NULL DEFAULT false,
  closed_at       TIMESTAMPTZ,
  resolution      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_status ON cases(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_assignee       ON cases(assignee_id, status);
CREATE INDEX IF NOT EXISTS idx_cases_sla            ON cases(sla_due_at) WHERE status NOT IN ('closed','archived');

-- Case assignments
CREATE TABLE IF NOT EXISTS case_assignments (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id      UUID REFERENCES cases(id) ON DELETE CASCADE,
  analyst_id   UUID REFERENCES users(id),
  analyst_name TEXT,
  assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  unassigned_at TIMESTAMPTZ,
  is_current   BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_assignments_case     ON case_assignments(case_id, is_current);
CREATE INDEX IF NOT EXISTS idx_assignments_analyst  ON case_assignments(analyst_id, is_current);

-- Investigations
CREATE TABLE IF NOT EXISTS investigations (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id             UUID REFERENCES cases(id) ON DELETE CASCADE,
  analyst_id          UUID REFERENCES users(id),
  tenant_id           UUID REFERENCES tenants(id),
  priority            TEXT,
  timeline            JSONB NOT NULL DEFAULT '[]',
  iocs                JSONB NOT NULL DEFAULT '[]',
  attack_vector       TEXT,
  affected_assets     TEXT[],
  root_cause          TEXT,
  recommendations     JSONB NOT NULL DEFAULT '[]',
  mitre_techniques    TEXT[],
  lateral_movement_traced   BOOLEAN DEFAULT false,
  persistence_checked       BOOLEAN DEFAULT false,
  data_exfil_assessed       BOOLEAN DEFAULT false,
  outcome             alert_outcome,
  peer_review_score   INT CHECK (peer_review_score BETWEEN 0 AND 100),
  escalated           BOOLEAN DEFAULT false,
  completed_at        TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_investigations_case ON investigations(case_id);
CREATE INDEX IF NOT EXISTS idx_investigations_analyst ON investigations(analyst_id, created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  PHASE 4 — ADVANCED INTELLIGENCE
-- ════════════════════════════════════════════════════════════════

-- Dark web findings
CREATE TABLE IF NOT EXISTS dark_web_findings (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    UUID REFERENCES tenants(id),
  source       TEXT NOT NULL,  -- 'ransomware_leak' | 'paste_site' | 'forum'
  group_name   TEXT,
  url          TEXT,
  severity     severity_level NOT NULL DEFAULT 'HIGH',
  relevance    INT CHECK (relevance BETWEEN 0 AND 100),
  finding_type TEXT,           -- 'ORG_MENTION' | 'CREDENTIAL_DUMP' | 'NEW_VICTIM'
  iocs         JSONB NOT NULL DEFAULT '{}',
  credentials  JSONB NOT NULL DEFAULT '[]',
  snippet      TEXT,
  scan_id      TEXT,
  acknowledged BOOLEAN NOT NULL DEFAULT false,
  discovered   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_darkweb_tenant     ON dark_web_findings(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_darkweb_severity   ON dark_web_findings(severity, acknowledged);

-- Threat actors
CREATE TABLE IF NOT EXISTS threat_actors (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name             TEXT UNIQUE NOT NULL,
  aliases          TEXT[] NOT NULL DEFAULT '{}',
  nation_state     TEXT,
  motivation       TEXT,
  sophistication   TEXT,
  target_sectors   TEXT[] NOT NULL DEFAULT '{}',
  target_countries TEXT[] NOT NULL DEFAULT '{}',
  ttps             TEXT[] NOT NULL DEFAULT '{}',
  tools            TEXT[] NOT NULL DEFAULT '{}',
  description      TEXT,
  stix_id          TEXT,
  first_seen       DATE,
  last_active      DATE,
  is_active        BOOLEAN NOT NULL DEFAULT true,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_actors_name ON threat_actors USING GIN(to_tsvector('english', name));

-- Campaigns
CREATE TABLE IF NOT EXISTS campaigns (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  threat_actor_id UUID REFERENCES threat_actors(id),
  name            TEXT NOT NULL,
  description     TEXT,
  start_date      DATE,
  end_date        DATE,
  target_sectors  TEXT[] NOT NULL DEFAULT '{}',
  target_countries TEXT[] NOT NULL DEFAULT '{}',
  ttps            TEXT[] NOT NULL DEFAULT '{}',
  ioc_ids         UUID[] NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Geopolitical risk snapshots
CREATE TABLE IF NOT EXISTS geo_risk_snapshots (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  generated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  risk_score     INT,
  threat_themes  JSONB NOT NULL DEFAULT '[]',
  hotspots       JSONB NOT NULL DEFAULT '[]',
  key_articles   JSONB NOT NULL DEFAULT '[]',
  raw_response   JSONB
);
CREATE INDEX IF NOT EXISTS idx_geo_risk_ts ON geo_risk_snapshots(generated_at DESC);

-- ════════════════════════════════════════════════════════════════
--  PHASE 5 — AUTONOMOUS AGENTS
-- ════════════════════════════════════════════════════════════════

-- Agent tasks
CREATE TABLE IF NOT EXISTS agent_tasks (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id      UUID REFERENCES tenants(id),
  alert_id       UUID,
  case_id        UUID REFERENCES cases(id),
  agent_type     TEXT NOT NULL,  -- 'triage' | 'investigation' | 'response'
  status         TEXT NOT NULL DEFAULT 'pending',
  input          JSONB NOT NULL DEFAULT '{}',
  output         JSONB,
  decision       agent_decision,
  confidence     INT CHECK (confidence BETWEEN 0 AND 100),
  reasoning      TEXT,
  actions_taken  JSONB NOT NULL DEFAULT '[]',
  hitl_required  BOOLEAN NOT NULL DEFAULT false,
  hitl_approved  BOOLEAN,
  hitl_analyst   UUID REFERENCES users(id),
  hitl_note      TEXT,
  hitl_at        TIMESTAMPTZ,
  model_used     TEXT,
  tokens_used    INT,
  duration_ms    INT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_tenant ON agent_tasks(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_hitl   ON agent_tasks(hitl_required, hitl_approved) WHERE hitl_required;

-- HITL checkpoints queue
CREATE TABLE IF NOT EXISTS hitl_checkpoints (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_id       UUID REFERENCES agent_tasks(id) ON DELETE CASCADE,
  tenant_id     UUID REFERENCES tenants(id),
  analyst_id    UUID REFERENCES users(id),
  decision_type TEXT NOT NULL,
  context       JSONB NOT NULL DEFAULT '{}',
  proposed_action TEXT NOT NULL,
  risk_level    TEXT,
  approved      BOOLEAN,
  reviewed_at   TIMESTAMPTZ,
  reviewer_note TEXT,
  expires_at    TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '2 hours'),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hitl_pending ON hitl_checkpoints(tenant_id, approved) WHERE approved IS NULL;

-- ════════════════════════════════════════════════════════════════
--  PHASE 6 — ENTERPRISE INTEGRATIONS
-- ════════════════════════════════════════════════════════════════

-- STIX objects store
CREATE TABLE IF NOT EXISTS stix_objects (
  id           TEXT PRIMARY KEY,             -- STIX UUID format
  tenant_id    UUID REFERENCES tenants(id),
  type         TEXT NOT NULL,               -- indicator, malware, threat-actor, etc.
  spec_version TEXT NOT NULL DEFAULT '2.1',
  created      TIMESTAMPTZ NOT NULL,
  modified     TIMESTAMPTZ NOT NULL,
  object_data  JSONB NOT NULL,
  collection   TEXT NOT NULL DEFAULT 'default',
  source       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_stix_tenant_type ON stix_objects(tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_stix_collection  ON stix_objects(collection, modified DESC);
CREATE INDEX IF NOT EXISTS idx_stix_data        ON stix_objects USING GIN(object_data);

-- SIEM connector config
CREATE TABLE IF NOT EXISTS siem_connectors (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,  -- 'splunk' | 'sentinel' | 'xsoar' | 'elastic' | 'qradar'
  name        TEXT NOT NULL,
  config      JSONB NOT NULL DEFAULT '{}',  -- encrypted at application layer
  enabled     BOOLEAN NOT NULL DEFAULT true,
  last_sync   TIMESTAMPTZ,
  sync_status TEXT,
  sync_error  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON siem_connectors(tenant_id, enabled);

-- CEF/Syslog received events
CREATE TABLE IF NOT EXISTS collected_events (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    UUID REFERENCES tenants(id),
  source_ip    INET,
  source_port  INT,
  protocol     TEXT NOT NULL DEFAULT 'udp',
  raw          TEXT,
  parsed       JSONB NOT NULL DEFAULT '{}',
  event_type   TEXT,         -- 'cef' | 'syslog_rfc5424' | 'syslog_rfc3164' | 'unknown'
  severity     INT,
  facility     INT,
  processed    BOOLEAN NOT NULL DEFAULT false,
  alert_id     UUID,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (received_at);

CREATE TABLE IF NOT EXISTS collected_events_current PARTITION OF collected_events
  FOR VALUES FROM (CURRENT_DATE) TO (CURRENT_DATE + INTERVAL '7 days');

CREATE INDEX IF NOT EXISTS idx_events_unprocessed ON collected_events(processed, received_at) WHERE NOT processed;

-- ════════════════════════════════════════════════════════════════
--  PHASE 7 — PURPLE TEAM
-- ════════════════════════════════════════════════════════════════

-- Purple team simulation runs
CREATE TABLE IF NOT EXISTS purple_team_runs (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id         UUID REFERENCES tenants(id),
  run_name          TEXT NOT NULL,
  technique_ids     TEXT[] NOT NULL DEFAULT '{}',
  adversary_id      TEXT,
  total_techniques  INT NOT NULL DEFAULT 0,
  detected          INT NOT NULL DEFAULT 0,
  detection_rate    INT,
  results           JSONB NOT NULL DEFAULT '[]',
  status            TEXT NOT NULL DEFAULT 'pending',
  created_by        UUID REFERENCES users(id),
  started_at        TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_purple_runs_tenant ON purple_team_runs(tenant_id, created_at DESC);

-- Detection gap analysis
CREATE TABLE IF NOT EXISTS detection_gaps (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id),
  run_id           UUID REFERENCES purple_team_runs(id),
  technique_id     TEXT NOT NULL,
  technique_name   TEXT,
  tactic           TEXT,
  status           TEXT NOT NULL,  -- 'NOT_COVERED' | 'PARTIAL' | 'COVERED' | 'COVERAGE_GAP'
  rule_count       INT NOT NULL DEFAULT 0,
  priority         INT,
  recommendation   TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_gaps_tenant_tech ON detection_gaps(tenant_id, technique_id);

-- ════════════════════════════════════════════════════════════════
--  PHASE 8 — REPORTING
-- ════════════════════════════════════════════════════════════════

-- Executive reports
CREATE TABLE IF NOT EXISTS executive_reports (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  report_type      TEXT NOT NULL DEFAULT 'incident', -- incident | executive | soc_metrics | threat_intel
  period_start     DATE,
  period_end       DATE,
  status           TEXT NOT NULL DEFAULT 'generating',
  file_path        TEXT,
  file_size        BIGINT,
  kpi_snapshot     JSONB NOT NULL DEFAULT '{}',
  classification   TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
  created_by       UUID REFERENCES users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at     TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '90 days')
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON executive_reports(tenant_id, created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  PHASE 9 — SOC METRICS
-- ════════════════════════════════════════════════════════════════

-- SOC metrics snapshots (daily)
CREATE TABLE IF NOT EXISTS soc_metrics_snapshots (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id) ON DELETE CASCADE,
  snapshot_date    DATE NOT NULL,
  window_days      INT NOT NULL DEFAULT 30,
  mttd_mean        NUMERIC(10,2),
  mttd_median      NUMERIC(10,2),
  mttd_p95         NUMERIC(10,2),
  mttr_mean        NUMERIC(10,2),
  mttr_median      NUMERIC(10,2),
  mttr_p95         NUMERIC(10,2),
  alert_to_ticket_mean NUMERIC(10,2),
  sla_compliance   NUMERIC(5,2),
  fpr              NUMERIC(5,2),
  tpr              NUMERIC(5,2),
  precision        NUMERIC(5,2),
  total_alerts     INT,
  total_cases      INT,
  open_cases       INT,
  critical_alerts  INT,
  avg_quality_score INT,
  analysts_at_risk  INT,
  raw_metrics      JSONB NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_soc_metrics_tenant_date ON soc_metrics_snapshots(tenant_id, snapshot_date DESC);

-- Analyst workload snapshots
CREATE TABLE IF NOT EXISTS analyst_workload (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID REFERENCES tenants(id),
  analyst_id       UUID REFERENCES users(id),
  snapshot_date    DATE NOT NULL DEFAULT CURRENT_DATE,
  open_cases       INT NOT NULL DEFAULT 0,
  total_cases      INT NOT NULL DEFAULT 0,
  critical_cases   INT NOT NULL DEFAULT 0,
  workload_score   INT,
  burnout_risk     TEXT,
  avg_age_hours    NUMERIC(10,2),
  oldest_case_hours NUMERIC(10,2),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, analyst_id, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_workload_tenant_date ON analyst_workload(tenant_id, snapshot_date DESC);

-- ════════════════════════════════════════════════════════════════
--  UPDATED_AT TRIGGERS
-- ════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DO $$ DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'tenants','users','detection_rules','cases','investigations',
    'iocs','threat_actors','campaigns','siem_connectors'
  ] LOOP
    EXECUTE format(
      'DROP TRIGGER IF EXISTS trg_%I_updated_at ON %I;
       CREATE TRIGGER trg_%I_updated_at
       BEFORE UPDATE ON %I
       FOR EACH ROW EXECUTE FUNCTION set_updated_at();',
      t, t, t, t
    );
  END LOOP;
END $$;

-- ════════════════════════════════════════════════════════════════
--  ROW-LEVEL SECURITY (TENANT ISOLATION)
-- ════════════════════════════════════════════════════════════════

ALTER TABLE alerts        ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases         ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_tasks   ENABLE ROW LEVEL SECURITY;
ALTER TABLE stix_objects  ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policies (service role bypasses RLS)
CREATE POLICY tenant_isolation_alerts ON alerts
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_cases ON cases
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_iocs ON iocs
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_investigations ON investigations
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_agent_tasks ON agent_tasks
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

COMMIT;
