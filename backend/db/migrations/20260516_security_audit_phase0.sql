-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Security Audit Phase 0 DB Migration
--  backend/db/migrations/20260516_security_audit_phase0.sql
--
--  Changes:
--  1. agent_decisions — add is_mock, injection_detected, output_anomaly columns
--  2. agent_feedback  — add injection_context column
--  3. rag_documents   — add provenance, ingested_at, ttl_hours, expires_at, source_hash
--  4. darkweb_scans   — add opsec_errors, tor_proxies_used
--  5. audit_log       — add security_event_type for P0 security events
-- ══════════════════════════════════════════════════════════════════

BEGIN;

-- ── 1. agent_decisions: AI-FIX-002 fields ────────────────────────
ALTER TABLE agent_decisions
  ADD COLUMN IF NOT EXISTS is_mock               BOOLEAN  DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS injection_detected    BOOLEAN  DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS output_anomaly        BOOLEAN  DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS requires_human_review BOOLEAN  DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS injection_patterns    JSONB    DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS consensus_checked     BOOLEAN  DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS consensus_agrees      BOOLEAN  DEFAULT NULL;

-- Index for querying mock decisions (monitoring / audit)
CREATE INDEX IF NOT EXISTS idx_agent_decisions_is_mock
  ON agent_decisions(is_mock)
  WHERE is_mock = TRUE;

CREATE INDEX IF NOT EXISTS idx_agent_decisions_injection
  ON agent_decisions(injection_detected)
  WHERE injection_detected = TRUE;

-- ── 2. agent_feedback: track injection context ────────────────────
ALTER TABLE agent_feedback
  ADD COLUMN IF NOT EXISTS injection_context JSONB DEFAULT NULL;

-- ── 3. rag_documents: AI-FIX-003 provenance + freshness ──────────
-- Create table if it doesn't exist yet
CREATE TABLE IF NOT EXISTS rag_documents (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_id       TEXT         NOT NULL UNIQUE,
  title        TEXT,
  namespace    TEXT         NOT NULL,
  source       TEXT,
  provenance   TEXT,
  ingested_at  TIMESTAMPTZ  DEFAULT NOW(),
  ttl_hours    INTEGER      DEFAULT 720,
  expires_at   TIMESTAMPTZ,
  source_hash  TEXT,
  doc_version  INTEGER      DEFAULT 1,
  chunk_count  INTEGER      DEFAULT 0,
  status       TEXT         DEFAULT 'active',
  created_at   TIMESTAMPTZ  DEFAULT NOW(),
  updated_at   TIMESTAMPTZ  DEFAULT NOW()
);

-- Add columns to existing table if it already exists
ALTER TABLE rag_documents
  ADD COLUMN IF NOT EXISTS provenance   TEXT,
  ADD COLUMN IF NOT EXISTS ingested_at  TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS ttl_hours    INTEGER     DEFAULT 720,
  ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS source_hash  TEXT,
  ADD COLUMN IF NOT EXISTS doc_version  INTEGER     DEFAULT 1;

-- Index for freshness queries
CREATE INDEX IF NOT EXISTS idx_rag_documents_expires_at
  ON rag_documents(expires_at)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_rag_documents_namespace_expires
  ON rag_documents(namespace, expires_at);

-- ── 4. darkweb_scans: FIX-005 OPSEC fields ───────────────────────
CREATE TABLE IF NOT EXISTS darkweb_scans (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         TEXT        NOT NULL UNIQUE,
  started_at      TIMESTAMPTZ DEFAULT NOW(),
  ended_at        TIMESTAMPTZ,
  duration_ms     INTEGER,
  total_findings  INTEGER     DEFAULT 0,
  critical        INTEGER     DEFAULT 0,
  high            INTEGER     DEFAULT 0,
  tor_proxies     INTEGER     DEFAULT 1,
  opsec_errors    INTEGER     DEFAULT 0,
  status          TEXT        DEFAULT 'completed',
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE darkweb_scans
  ADD COLUMN IF NOT EXISTS opsec_errors    INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tor_proxies     INTEGER DEFAULT 1;

-- ── 5. audit_log: security event tracking (P0) ───────────────────
CREATE TABLE IF NOT EXISTS security_audit_log (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type          TEXT        NOT NULL,
  severity            TEXT        NOT NULL DEFAULT 'INFO',
  user_id             TEXT,
  tenant_id           TEXT,
  source_ip           TEXT,
  request_path        TEXT,
  event_data          JSONB       DEFAULT '{}'::jsonb,
  fix_reference       TEXT,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Index for querying by event type and time
CREATE INDEX IF NOT EXISTS idx_security_audit_log_event_type
  ON security_audit_log(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_severity
  ON security_audit_log(severity, created_at DESC)
  WHERE severity IN ('CRITICAL', 'HIGH');

-- Row-level security: only admin/security roles can read security events
ALTER TABLE security_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS security_audit_log_admin_read
  ON security_audit_log
  FOR SELECT
  USING (
    auth.jwt() ->> 'role' IN ('admin', 'security_analyst', 'SUPER_ADMIN')
  );

COMMENT ON TABLE security_audit_log IS 'P0 Security Audit Phase 0 event log — tracks auth failures, injection attempts, SSRF blocks, CORS rejections, rate limit violations';

COMMIT;
