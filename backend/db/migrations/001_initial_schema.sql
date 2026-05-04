-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — PostgreSQL/Supabase Schema Migration 001
--  backend/db/migrations/001_initial_schema.sql
--
--  Creates all core tables for the Wadjet-Eye AI platform.
--  Supports: Multi-tenancy, RBAC, Alerts, Cases, IOCs, Threat Intel,
--            STIX, SOC Metrics, Audit Log, MFA, Kafka events.
--
--  Run: psql $DATABASE_URL -f migrations/001_initial_schema.sql
--       OR apply via Supabase SQL editor
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ── Extensions ────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- Fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- Composite GIN indexes
CREATE EXTENSION IF NOT EXISTS "timescaledb" CASCADE; -- Time-series (optional)

-- ── Enum types ────────────────────────────────────────────────────
CREATE TYPE severity_level AS ENUM
  ('critical', 'high', 'medium', 'low', 'informational', 'unknown');

CREATE TYPE alert_status AS ENUM
  ('open', 'in_progress', 'escalated', 'closed', 'false_positive',
   'true_positive', 'duplicate');

CREATE TYPE case_status AS ENUM
  ('open', 'investigating', 'contained', 'remediated', 'closed', 'archived');

CREATE TYPE ioc_type AS ENUM
  ('ip', 'ipv6', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256',
   'hash_sha512', 'email', 'cve', 'asn', 'cidr', 'filename', 'registry',
   'mutex', 'bitcoin_address', 'other');

CREATE TYPE user_role AS ENUM
  ('SUPER_ADMIN', 'ADMIN', 'TEAM_LEAD', 'ANALYST', 'READ_ONLY', 'API_USER');

CREATE TYPE playbook_status AS ENUM
  ('draft', 'active', 'deprecated', 'testing');

CREATE TYPE report_status AS ENUM
  ('queued', 'generating', 'completed', 'failed');

CREATE TYPE agent_decision AS ENUM
  ('auto_closed', 'auto_escalated', 'needs_review', 'ticket_created',
   'playbook_triggered', 'insufficient_data');

-- ══════════════════════════════════════════════════════════════════
--  TENANTS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE tenants (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name            TEXT NOT NULL UNIQUE,
  slug            TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{3,63}$'),
  plan            TEXT NOT NULL DEFAULT 'enterprise',
  max_users       INTEGER NOT NULL DEFAULT 100,
  max_alerts_day  INTEGER NOT NULL DEFAULT 100000,
  api_rate_limit  INTEGER NOT NULL DEFAULT 1000,    -- requests/minute
  mfa_required    BOOLEAN NOT NULL DEFAULT TRUE,
  allowed_ips     TEXT[],                            -- IP allowlist (NULL = any)
  settings        JSONB NOT NULL DEFAULT '{}',
  active          BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants (slug);
CREATE INDEX idx_tenants_active ON tenants (active);

-- ══════════════════════════════════════════════════════════════════
--  USERS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email           TEXT NOT NULL,
  display_name    TEXT,
  password_hash   TEXT NOT NULL,
  role            user_role NOT NULL DEFAULT 'ANALYST',
  active          BOOLEAN NOT NULL DEFAULT TRUE,
  mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret      TEXT,                              -- AES-256 encrypted
  mfa_backup_codes TEXT[],                           -- Encrypted backup codes
  last_login_at   TIMESTAMPTZ,
  last_login_ip   INET,
  failed_logins   INTEGER NOT NULL DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  password_changed_at TIMESTAMPTZ DEFAULT NOW(),
  must_change_pw  BOOLEAN NOT NULL DEFAULT FALSE,
  session_data    JSONB NOT NULL DEFAULT '{}',       -- Active session tokens
  preferences     JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant    ON users (tenant_id);
CREATE INDEX idx_users_email     ON users (email);
CREATE INDEX idx_users_role      ON users (role);
CREATE INDEX idx_users_active    ON users (active);
CREATE INDEX idx_users_last_login ON users (last_login_at DESC NULLS LAST);

-- ══════════════════════════════════════════════════════════════════
--  ALERTS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE alerts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        severity_level NOT NULL DEFAULT 'medium',
  status          alert_status NOT NULL DEFAULT 'open',
  risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  confidence      NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),

  -- Detection metadata
  rule_id         TEXT,
  rule_name       TEXT,
  detection_source TEXT,                             -- 'raykan' | 'sigma' | 'custom' | 'manual'
  category        TEXT,

  -- MITRE ATT&CK
  mitre_tactic    TEXT,
  mitre_technique TEXT,
  mitre_subtechnique TEXT,

  -- Entities
  host            TEXT,
  host_ip         INET,
  username        TEXT,
  source_ip       INET,
  dest_ip         INET,
  process_name    TEXT,
  process_hash    TEXT,

  -- Grouping
  incident_id     UUID,
  cluster_id      TEXT,
  parent_alert_id UUID REFERENCES alerts(id),

  -- Assignment
  assignee_id     UUID REFERENCES users(id),
  outcome         TEXT,                              -- 'true_positive' | 'false_positive' etc.

  -- Timestamps
  event_time      TIMESTAMPTZ,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ticket_created_at TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,

  -- Enrichment
  ioc_count       INTEGER NOT NULL DEFAULT 0,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  enriched        BOOLEAN NOT NULL DEFAULT FALSE,
  enrichment_data JSONB NOT NULL DEFAULT '{}',
  raw_event_ids   TEXT[] NOT NULL DEFAULT '{}',
  evidence        JSONB NOT NULL DEFAULT '[]',

  -- AI
  ai_summary      TEXT,
  ai_recommended_actions TEXT[],

  -- SOAR
  playbook_triggered BOOLEAN NOT NULL DEFAULT FALSE,
  soar_case_id    TEXT,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant          ON alerts (tenant_id);
CREATE INDEX idx_alerts_status          ON alerts (status);
CREATE INDEX idx_alerts_severity        ON alerts (severity);
CREATE INDEX idx_alerts_risk            ON alerts (risk_score DESC);
CREATE INDEX idx_alerts_created         ON alerts (created_at DESC);
CREATE INDEX idx_alerts_assignee        ON alerts (assignee_id);
CREATE INDEX idx_alerts_incident        ON alerts (incident_id);
CREATE INDEX idx_alerts_mitre_tactic    ON alerts (mitre_tactic);
CREATE INDEX idx_alerts_tenant_status   ON alerts (tenant_id, status, created_at DESC);
CREATE INDEX idx_alerts_tenant_severity ON alerts (tenant_id, severity, created_at DESC);
CREATE INDEX idx_alerts_host            ON alerts USING gin (host gin_trgm_ops);
CREATE INDEX idx_alerts_tags            ON alerts USING gin (tags);

-- ══════════════════════════════════════════════════════════════════
--  INCIDENTS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE incidents (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        severity_level NOT NULL DEFAULT 'medium',
  status          case_status NOT NULL DEFAULT 'open',
  risk_score      NUMERIC(5,2) DEFAULT 0,
  alert_count     INTEGER NOT NULL DEFAULT 0,
  mitre_tactics   TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
  affected_hosts  TEXT[] NOT NULL DEFAULT '{}',
  affected_users  TEXT[] NOT NULL DEFAULT '{}',
  assignee_id     UUID REFERENCES users(id),
  lead_analyst_id UUID REFERENCES users(id),
  cluster_id      TEXT,
  attack_chain    JSONB,                             -- Neo4j attack chain snapshot
  ai_narrative    TEXT,                              -- LLM-generated incident narrative
  executive_summary TEXT,
  containment_actions JSONB NOT NULL DEFAULT '[]',
  remediation_steps   JSONB NOT NULL DEFAULT '[]',
  lessons_learned TEXT,
  first_event_time TIMESTAMPTZ,
  last_event_time  TIMESTAMPTZ,
  detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  contained_at    TIMESTAMPTZ,
  resolved_at     TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_tenant   ON incidents (tenant_id);
CREATE INDEX idx_incidents_status   ON incidents (status);
CREATE INDEX idx_incidents_severity ON incidents (severity);
CREATE INDEX idx_incidents_created  ON incidents (created_at DESC);

-- ══════════════════════════════════════════════════════════════════
--  IOCs (Indicators of Compromise)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE iocs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  value           TEXT NOT NULL,
  type            ioc_type NOT NULL,
  severity        severity_level NOT NULL DEFAULT 'medium',
  confidence      NUMERIC(5,2) NOT NULL DEFAULT 50,
  risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0,
  malicious       BOOLEAN,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  tlp             TEXT NOT NULL DEFAULT 'AMBER' CHECK (tlp IN ('WHITE','GREEN','AMBER','RED')),
  source          TEXT,
  source_url      TEXT,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ,
  active          BOOLEAN NOT NULL DEFAULT TRUE,
  enrichment_data JSONB NOT NULL DEFAULT '{}',
  stix_id         TEXT,
  stix_bundle_id  TEXT,
  related_ioc_ids UUID[],
  false_positive  BOOLEAN NOT NULL DEFAULT FALSE,
  fp_reported_by  UUID REFERENCES users(id),
  fp_reported_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, value, type)
);

CREATE INDEX idx_iocs_tenant     ON iocs (tenant_id);
CREATE INDEX idx_iocs_type       ON iocs (type);
CREATE INDEX idx_iocs_severity   ON iocs (severity);
CREATE INDEX idx_iocs_malicious  ON iocs (malicious);
CREATE INDEX idx_iocs_value_trgm ON iocs USING gin (value gin_trgm_ops);
CREATE INDEX idx_iocs_active     ON iocs (active);
CREATE INDEX idx_iocs_stix       ON iocs (stix_id);
CREATE INDEX idx_iocs_tags       ON iocs USING gin (tags);

-- ══════════════════════════════════════════════════════════════════
--  CASES (Investigation workbench)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE cases (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        severity_level NOT NULL DEFAULT 'medium',
  status          case_status NOT NULL DEFAULT 'open',
  priority        INTEGER NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
  assignee_id     UUID REFERENCES users(id),
  incident_id     UUID REFERENCES incidents(id),
  alert_ids       UUID[] NOT NULL DEFAULT '{}',
  ioc_ids         UUID[] NOT NULL DEFAULT '{}',
  tags            TEXT[] NOT NULL DEFAULT '{}',
  timeline        JSONB NOT NULL DEFAULT '[]',
  notes           JSONB NOT NULL DEFAULT '[]',
  artifacts       JSONB NOT NULL DEFAULT '[]',
  playbook_id     UUID,
  soar_case_id    TEXT,
  sla_due_at      TIMESTAMPTZ,
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cases_tenant   ON cases (tenant_id);
CREATE INDEX idx_cases_status   ON cases (status);
CREATE INDEX idx_cases_assignee ON cases (assignee_id);
CREATE INDEX idx_cases_created  ON cases (created_at DESC);

-- ══════════════════════════════════════════════════════════════════
--  PLAYBOOKS (SOAR automation)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE playbooks (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  version         TEXT NOT NULL DEFAULT '1.0.0',
  status          playbook_status NOT NULL DEFAULT 'draft',
  trigger_conditions JSONB NOT NULL DEFAULT '{}',
  steps           JSONB NOT NULL DEFAULT '[]',
  tags            TEXT[] NOT NULL DEFAULT '{}',
  mitre_tactics   TEXT[] NOT NULL DEFAULT '{}',
  auto_execute    BOOLEAN NOT NULL DEFAULT FALSE,
  min_confidence  NUMERIC(5,2) NOT NULL DEFAULT 80,
  created_by      UUID REFERENCES users(id),
  approved_by     UUID REFERENCES users(id),
  approved_at     TIMESTAMPTZ,
  last_run_at     TIMESTAMPTZ,
  run_count       INTEGER NOT NULL DEFAULT 0,
  success_count   INTEGER NOT NULL DEFAULT 0,
  failure_count   INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_playbooks_tenant ON playbooks (tenant_id);
CREATE INDEX idx_playbooks_status ON playbooks (status);

-- ══════════════════════════════════════════════════════════════════
--  DETECTION RULES
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE detection_rules (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL = global rule
  rule_id         TEXT NOT NULL UNIQUE,              -- Sigma rule ID or custom
  name            TEXT NOT NULL,
  description     TEXT,
  rule_type       TEXT NOT NULL DEFAULT 'sigma' CHECK (rule_type IN ('sigma','custom','ml','composite')),
  severity        severity_level NOT NULL DEFAULT 'medium',
  mitre_tactic    TEXT,
  mitre_technique TEXT,
  logic           JSONB NOT NULL DEFAULT '{}',       -- Parsed Sigma YAML or custom logic
  sigma_yaml      TEXT,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  threshold       NUMERIC(5,2) NOT NULL DEFAULT 50,  -- Min confidence score to fire
  false_positive_rate NUMERIC(5,4) NOT NULL DEFAULT 0, -- Learned FP rate
  true_positive_rate  NUMERIC(5,4) NOT NULL DEFAULT 0, -- Learned TP rate
  trigger_count   INTEGER NOT NULL DEFAULT 0,
  fp_count        INTEGER NOT NULL DEFAULT 0,
  tp_count        INTEGER NOT NULL DEFAULT 0,
  last_triggered  TIMESTAMPTZ,
  last_tuned_at   TIMESTAMPTZ,
  auto_tune       BOOLEAN NOT NULL DEFAULT TRUE,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_tenant    ON detection_rules (tenant_id);
CREATE INDEX idx_rules_enabled   ON detection_rules (enabled);
CREATE INDEX idx_rules_severity  ON detection_rules (severity);
CREATE INDEX idx_rules_mitre     ON detection_rules (mitre_tactic, mitre_technique);

-- ══════════════════════════════════════════════════════════════════
--  ANALYST FEEDBACK (self-learning loop)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE analyst_feedback (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
  rule_id         TEXT,
  analyst_id      UUID NOT NULL REFERENCES users(id),
  outcome         TEXT NOT NULL CHECK (outcome IN ('true_positive','false_positive','duplicate','benign')),
  confidence      NUMERIC(5,2),
  notes           TEXT,
  features        JSONB,                             -- Alert features at time of feedback
  model_version   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_feedback_tenant  ON analyst_feedback (tenant_id);
CREATE INDEX idx_feedback_rule    ON analyst_feedback (rule_id);
CREATE INDEX idx_feedback_outcome ON analyst_feedback (outcome);
CREATE INDEX idx_feedback_created ON analyst_feedback (created_at DESC);

-- ══════════════════════════════════════════════════════════════════
--  THREAT INTELLIGENCE (STIX objects cache)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE threat_intel (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL = global
  stix_id         TEXT NOT NULL UNIQUE,
  stix_type       TEXT NOT NULL,                     -- 'indicator' | 'malware' | 'threat-actor' etc.
  name            TEXT,
  description     TEXT,
  confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
  severity        severity_level,
  tlp             TEXT NOT NULL DEFAULT 'AMBER',
  source          TEXT,
  source_feed     TEXT,
  valid_from      TIMESTAMPTZ,
  valid_until     TIMESTAMPTZ,
  pattern         TEXT,                              -- STIX pattern expression
  pattern_type    TEXT DEFAULT 'stix',
  kill_chain_phases JSONB,
  external_refs   JSONB NOT NULL DEFAULT '[]',
  tags            TEXT[] NOT NULL DEFAULT '{}',
  raw_stix        JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  modified_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ti_stix_type   ON threat_intel (stix_type);
CREATE INDEX idx_ti_tenant      ON threat_intel (tenant_id);
CREATE INDEX idx_ti_source      ON threat_intel (source_feed);
CREATE INDEX idx_ti_valid       ON threat_intel (valid_until);
CREATE INDEX idx_ti_name_trgm   ON threat_intel USING gin (name gin_trgm_ops);
CREATE INDEX idx_ti_tags        ON threat_intel USING gin (tags);

-- ══════════════════════════════════════════════════════════════════
--  RAG DOCUMENTS (vector DB document registry)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE rag_documents (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title           TEXT NOT NULL,
  doc_type        TEXT NOT NULL,                     -- 'mitre' | 'cve' | 'threat_report' | 'playbook' | 'sigma'
  source          TEXT,
  source_url      TEXT,
  chunk_id        TEXT NOT NULL UNIQUE,              -- Pinecone/Weaviate vector ID
  chunk_index     INTEGER NOT NULL DEFAULT 0,
  chunk_text      TEXT NOT NULL,
  token_count     INTEGER,
  embedding_model TEXT NOT NULL DEFAULT 'text-embedding-3-large',
  metadata        JSONB NOT NULL DEFAULT '{}',
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rag_type     ON rag_documents (doc_type);
CREATE INDEX idx_rag_source   ON rag_documents (source);
CREATE INDEX idx_rag_chunk    ON rag_documents (chunk_id);
CREATE INDEX idx_rag_text_trgm ON rag_documents USING gin (chunk_text gin_trgm_ops);

-- ══════════════════════════════════════════════════════════════════
--  AGENT DECISIONS (autonomous SOC log)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE agent_decisions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_id        UUID REFERENCES alerts(id) ON DELETE SET NULL,
  incident_id     UUID REFERENCES incidents(id) ON DELETE SET NULL,
  agent_type      TEXT NOT NULL,                     -- 'triage' | 'investigation' | 'response'
  decision        agent_decision NOT NULL,
  confidence      NUMERIC(5,2),
  reasoning       TEXT,
  actions_taken   JSONB NOT NULL DEFAULT '[]',
  human_approved  BOOLEAN,
  approved_by     UUID REFERENCES users(id),
  approved_at     TIMESTAMPTZ,
  override_reason TEXT,
  execution_ms    INTEGER,
  llm_model       TEXT,
  prompt_tokens   INTEGER,
  completion_tokens INTEGER,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_tenant   ON agent_decisions (tenant_id);
CREATE INDEX idx_agent_type     ON agent_decisions (agent_type);
CREATE INDEX idx_agent_decision ON agent_decisions (decision);
CREATE INDEX idx_agent_created  ON agent_decisions (created_at DESC);

-- ══════════════════════════════════════════════════════════════════
--  REPORTS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE reports (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  report_type     TEXT NOT NULL,                     -- 'incident' | 'executive' | 'threat_intel' | 'soc_metrics'
  status          report_status NOT NULL DEFAULT 'queued',
  format          TEXT NOT NULL DEFAULT 'pdf',
  parameters      JSONB NOT NULL DEFAULT '{}',
  ai_summary      TEXT,
  file_path       TEXT,
  file_size_bytes INTEGER,
  file_hash_sha256 TEXT,
  generated_by    UUID REFERENCES users(id),
  delivered_to    TEXT[],                            -- Email addresses
  error           TEXT,
  expires_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_reports_tenant  ON reports (tenant_id);
CREATE INDEX idx_reports_status  ON reports (status);
CREATE INDEX idx_reports_type    ON reports (report_type);
CREATE INDEX idx_reports_created ON reports (created_at DESC);

-- ══════════════════════════════════════════════════════════════════
--  SOC METRICS SNAPSHOTS (time-series)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE soc_metrics (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  period_start    TIMESTAMPTZ NOT NULL,
  period_end      TIMESTAMPTZ NOT NULL,
  period_type     TEXT NOT NULL DEFAULT 'daily' CHECK (period_type IN ('hourly','daily','weekly','monthly')),

  -- Detection metrics
  total_alerts    INTEGER NOT NULL DEFAULT 0,
  open_alerts     INTEGER NOT NULL DEFAULT 0,
  closed_alerts   INTEGER NOT NULL DEFAULT 0,
  fp_alerts       INTEGER NOT NULL DEFAULT 0,
  tp_alerts       INTEGER NOT NULL DEFAULT 0,
  fp_rate         NUMERIC(5,4) DEFAULT 0,
  tp_rate         NUMERIC(5,4) DEFAULT 0,

  -- Time metrics (seconds)
  avg_mttd        NUMERIC(10,2),                     -- Mean Time to Detect
  avg_mttr        NUMERIC(10,2),                     -- Mean Time to Respond
  p50_mttd        NUMERIC(10,2),
  p95_mttd        NUMERIC(10,2),
  p50_mttr        NUMERIC(10,2),
  p95_mttr        NUMERIC(10,2),

  -- SLA
  sla_met_count   INTEGER NOT NULL DEFAULT 0,
  sla_breached_count INTEGER NOT NULL DEFAULT 0,
  sla_compliance_pct NUMERIC(5,2),

  -- Analyst workload
  total_analysts  INTEGER NOT NULL DEFAULT 0,
  alerts_per_analyst NUMERIC(10,2),
  active_cases    INTEGER NOT NULL DEFAULT 0,

  -- Incidents
  total_incidents INTEGER NOT NULL DEFAULT 0,
  critical_incidents INTEGER NOT NULL DEFAULT 0,

  -- Rule performance
  top_rules       JSONB NOT NULL DEFAULT '[]',
  mitre_coverage  JSONB NOT NULL DEFAULT '{}',

  -- Extra data
  raw_data        JSONB NOT NULL DEFAULT '{}',
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metrics_tenant  ON soc_metrics (tenant_id);
CREATE INDEX idx_metrics_period  ON soc_metrics (period_start DESC);
CREATE INDEX idx_metrics_type    ON soc_metrics (period_type);

-- ══════════════════════════════════════════════════════════════════
--  AUDIT LOG (tamper-evident append-only)
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE audit_log (
  id              BIGSERIAL PRIMARY KEY,
  tenant_id       UUID REFERENCES tenants(id) ON DELETE SET NULL,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  user_email      TEXT,
  action          TEXT NOT NULL,                     -- 'CREATE_ALERT' | 'LOGIN' etc.
  resource_type   TEXT,
  resource_id     TEXT,
  changes         JSONB,
  ip_address      INET,
  user_agent      TEXT,
  request_id      TEXT,
  status          TEXT NOT NULL DEFAULT 'success',
  error           TEXT,
  prev_hash       TEXT,                              -- SHA-256 chain for tamper detection
  event_hash      TEXT,                              -- SHA-256 of this record
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant   ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_user     ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_action   ON audit_log (action);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);

-- Prevent updates/deletes on audit_log (append-only)
CREATE RULE no_update_audit AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- ══════════════════════════════════════════════════════════════════
--  MFA SESSIONS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE mfa_sessions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  session_token   TEXT NOT NULL UNIQUE,              -- JWT session token reference
  mfa_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip_address      INET,
  user_agent      TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked         BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_user     ON mfa_sessions (user_id);
CREATE INDEX idx_mfa_token    ON mfa_sessions (session_token);
CREATE INDEX idx_mfa_expires  ON mfa_sessions (expires_at);

-- ══════════════════════════════════════════════════════════════════
--  COLLECTOR CONFIGURATIONS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE collectors (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  collector_type  TEXT NOT NULL,                     -- 'otx' | 'vt' | 'abuseipdb' | 'syslog' | 'kafka' | 'custom'
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  config          JSONB NOT NULL DEFAULT '{}',       -- Collector-specific config (no secrets here)
  secret_ref      TEXT,                              -- Vault secret path
  schedule        TEXT,                              -- Cron expression
  last_run_at     TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error      TEXT,
  run_count       INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_collectors_tenant  ON collectors (tenant_id);
CREATE INDEX idx_collectors_type    ON collectors (collector_type);
CREATE INDEX idx_collectors_enabled ON collectors (enabled);

-- ══════════════════════════════════════════════════════════════════
--  SIEM INTEGRATIONS
-- ══════════════════════════════════════════════════════════════════
CREATE TABLE siem_integrations (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  siem_type       TEXT NOT NULL CHECK (siem_type IN ('splunk','sentinel','qradar','xsoar','elastic','chronicle','generic')),
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  endpoint        TEXT NOT NULL,
  config          JSONB NOT NULL DEFAULT '{}',
  secret_ref      TEXT,                              -- Vault path for API key/token
  forward_alerts  BOOLEAN NOT NULL DEFAULT TRUE,
  forward_incidents BOOLEAN NOT NULL DEFAULT TRUE,
  last_forwarded_at TIMESTAMPTZ,
  error_count     INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_siem_tenant ON siem_integrations (tenant_id);

-- ══════════════════════════════════════════════════════════════════
--  UPDATED_AT TRIGGER (auto-update timestamps)
-- ══════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
  t TEXT;
BEGIN
  FOR t IN SELECT unnest(ARRAY[
    'tenants','users','alerts','incidents','iocs','cases','playbooks',
    'detection_rules','analyst_feedback','threat_intel','rag_documents',
    'reports','collectors','siem_integrations'
  ]) LOOP
    EXECUTE format(
      'CREATE TRIGGER trg_%s_updated_at
       BEFORE UPDATE ON %s
       FOR EACH ROW EXECUTE FUNCTION update_updated_at()',
      t, t
    );
  END LOOP;
END $$;

-- ══════════════════════════════════════════════════════════════════
--  ROW-LEVEL SECURITY (Multi-tenant isolation)
-- ══════════════════════════════════════════════════════════════════
ALTER TABLE tenants       ENABLE ROW LEVEL SECURITY;
ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts        ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents     ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases         ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks     ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyst_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel  ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports       ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_metrics   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log     ENABLE ROW LEVEL SECURITY;
ALTER TABLE collectors    ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_integrations ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (used by backend service account)
-- Individual tenant policies enforce isolation for all other roles.
CREATE POLICY tenant_isolation ON alerts
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation ON users
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation ON incidents
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

CREATE POLICY tenant_isolation ON iocs
  USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ══════════════════════════════════════════════════════════════════
--  SEED: Default system tenant
-- ══════════════════════════════════════════════════════════════════
INSERT INTO tenants (id, name, slug, plan, max_users, max_alerts_day, mfa_required)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  'Wadjet-Eye System',
  'system',
  'internal',
  10,
  1000000,
  FALSE
) ON CONFLICT DO NOTHING;

COMMIT;
