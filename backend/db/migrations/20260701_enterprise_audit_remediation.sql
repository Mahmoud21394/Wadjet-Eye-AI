-- ══════════════════════════════════════════════════════════════════════════════
-- Wadjet-Eye AI — Enterprise Audit Remediation Migration  v1.0
-- backend/db/migrations/20260701_enterprise_audit_remediation.sql
--
-- WS3: Autonomous Decision Ledger (append-only, signed, hash-chained)
-- WS2: Tenant isolation enforcement helpers
-- WS4: AI Governance audit tables
-- ══════════════════════════════════════════════════════════════════════════════

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- WS3: DECISION LEDGER — Append-only, cryptographically signed
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS decision_ledger (
  id              BIGSERIAL PRIMARY KEY,
  decision_id     UUID        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  agent_id        TEXT        NOT NULL,
  tenant_id       UUID        NOT NULL,
  action          TEXT        NOT NULL,
  confidence      NUMERIC(5,4) NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
  risk_score      NUMERIC(5,1) NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
  requires_human  BOOLEAN     NOT NULL DEFAULT false,
  status          TEXT        NOT NULL DEFAULT 'signed'
                  CHECK (status IN ('signed','pending_human_approval','approved','rejected',
                                    'executed','execution_failed','blocked:missing_signature',
                                    'blocked:requires_human_approval','blocked:decision_rejected',
                                    'blocked:signature_invalid')),
  signature       TEXT        NOT NULL,         -- Ed25519 signature (base64)
  key_id          TEXT        NOT NULL,         -- signing key version/identifier
  canonical_hash  TEXT        NOT NULL,         -- SHA-256 of canonical payload
  input_hash      TEXT        NOT NULL,         -- SHA-256 of decision input (anti-substitution)
  chain_prev      TEXT        NOT NULL DEFAULT 'genesis', -- SHA-256 of previous entry (hash chain)
  metadata        JSONB       DEFAULT '{}',
  input           JSONB       DEFAULT '{}',
  output          JSONB       DEFAULT '{}',
  approved_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
  approved_at     TIMESTAMPTZ,
  rejected_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
  rejected_at     TIMESTAMPTZ,
  rejection_reason TEXT,
  timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Append-only constraint: prevent UPDATE/DELETE on executed decisions
-- (implemented at application layer via status checks + no DELETE route)
CREATE INDEX IF NOT EXISTS idx_decision_ledger_tenant      ON decision_ledger (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_decision_ledger_status      ON decision_ledger (status, tenant_id);
CREATE INDEX IF NOT EXISTS idx_decision_ledger_agent       ON decision_ledger (agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_decision_ledger_action      ON decision_ledger (action, tenant_id);
CREATE INDEX IF NOT EXISTS idx_decision_ledger_decision_id ON decision_ledger (decision_id);

-- RLS: tenants can only see their own decisions
ALTER TABLE decision_ledger ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS decision_ledger_tenant_isolation
  ON decision_ledger
  FOR ALL
  USING (tenant_id = (
    SELECT tenant_id FROM users WHERE auth_id = auth.uid()
  ));

CREATE POLICY IF NOT EXISTS decision_ledger_super_admin
  ON decision_ledger
  FOR ALL
  USING ((
    SELECT role FROM users WHERE auth_id = auth.uid()
  ) = 'SUPER_ADMIN');

-- ─────────────────────────────────────────────────────────────────────────────
-- WS4: AI AUDIT LOG — Every AI call tracked
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_audit_log (
  id            BIGSERIAL PRIMARY KEY,
  trace_id      TEXT        NOT NULL,
  tenant_id     UUID        NOT NULL,
  user_id       UUID,
  agent_id      TEXT,
  model_id      TEXT        NOT NULL,
  prompt_id     TEXT,
  route         TEXT        NOT NULL,
  tokens_input  INTEGER     DEFAULT 0,
  tokens_output INTEGER     DEFAULT 0,
  cost_usd      NUMERIC(10,6) DEFAULT 0,
  latency_ms    INTEGER,
  success       BOOLEAN     DEFAULT true,
  blocked       BOOLEAN     DEFAULT false,
  block_reason  TEXT,
  pii_detected  BOOLEAN     DEFAULT false,
  taint_level   TEXT        DEFAULT 'clean',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant   ON ai_audit_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_model    ON ai_audit_log (model_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_audit_blocked  ON ai_audit_log (blocked, tenant_id);

ALTER TABLE ai_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS ai_audit_tenant_isolation ON ai_audit_log FOR ALL
  USING (tenant_id = (SELECT tenant_id FROM users WHERE auth_id = auth.uid()));

-- ─────────────────────────────────────────────────────────────────────────────
-- WS2: TENANT ISOLATION — Ensure all key tables have tenant_id
-- ─────────────────────────────────────────────────────────────────────────────

-- Add tenant_id to tables that might be missing it
DO $$
BEGIN
  -- alerts
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='tenant_id') THEN
    ALTER TABLE alerts ADD COLUMN tenant_id UUID;
    COMMENT ON COLUMN alerts.tenant_id IS 'Required for tenant isolation — TenantDbClient enforces this';
  END IF;

  -- cases
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cases' AND column_name='tenant_id') THEN
    ALTER TABLE cases ADD COLUMN tenant_id UUID;
  END IF;

  -- iocs
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='tenant_id') THEN
    ALTER TABLE iocs ADD COLUMN tenant_id UUID;
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- WS5: COMPLIANCE EVIDENCE TABLE
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_evidence (
  id            BIGSERIAL PRIMARY KEY,
  tenant_id     UUID        NOT NULL,
  framework     TEXT        NOT NULL,  -- 'SOC2', 'ISO27001', 'OWASP_LLM', etc.
  control_id    TEXT        NOT NULL,  -- e.g. 'CC6.1', 'A.8.5'
  status        TEXT        NOT NULL CHECK (status IN ('implemented','partial','not_applicable','planned')),
  evidence_type TEXT,
  evidence_url  TEXT,
  collected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  collected_by  UUID,
  notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_compliance_tenant    ON compliance_evidence (tenant_id, framework);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_evidence (framework, control_id);

COMMIT;
