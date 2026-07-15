-- ══════════════════════════════════════════════════════════════════════════════
--  Wadjet Nexus — Cyber Risk & Exposure Management Platform
--  Database Migration: XORCISM Integration
--  File: backend/db/migrations/20260715_nexus_integration.sql
--
--  This migration adds all Wadjet Nexus module tables derived from XORCISM:
--    • Asset Management (CTEM)
--    • Vulnerability Management & VOC
--    • Attack Path Analysis
--    • Cyber Threat Intelligence (CTI extended)
--    • GRC / Compliance (extended)
--    • Risk Quantification (FAIR/CRQ)
--    • TPRM
--    • SBOM / SCA
--    • Purple Team / BAS
--    • Adversary Emulation
--    • DFIR Forensics
--    • Enterprise Risk Score
--    • Connectors Catalog
--    • AI Guardrails
--    • Background Jobs (XSCHEDULE)
--    • Configuration Management (OVAL)
--    • Business Impact Analysis (BIA)
--    • EBIOS RM
--    • NIST 800-30
--    • Kill Chain mapping
--    • Sigma Rule Library
--    • YARA Rule Library
--    • Ransomware Scenario
--    • Adversary Opportunity Index
--    • Insurance Readiness
--    • PQCMM Quantum Readiness
--    • Threat Modeling (STRIDE)
--    • Crisis Management
--    • VOC SLA / Remediation
--    • CTEM Exposure Taxonomy
--    • FAIR-MAM Materiality
--
--  Multi-tenant: ALL tables have tenant_id FK → tenants(id)
--  Run in Supabase SQL Editor
-- ══════════════════════════════════════════════════════════════════════════════

BEGIN;

-- ── Extensions (already exist in most envs — safe to re-run) ────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ══════════════════════════════════════════════════════════════════════════════
--  1. ASSET MANAGEMENT (extended from existing asset_inventory)
-- ══════════════════════════════════════════════════════════════════════════════
-- Extend existing asset_inventory with Nexus fields
ALTER TABLE asset_inventory
  ADD COLUMN IF NOT EXISTS owner_id         UUID,
  ADD COLUMN IF NOT EXISTS owner_email      TEXT,
  ADD COLUMN IF NOT EXISTS business_value   NUMERIC(15,2) DEFAULT 0,
  ADD COLUMN IF NOT EXISTS financial_value  NUMERIC(15,2) DEFAULT 0,
  ADD COLUMN IF NOT EXISTS asset_class      TEXT DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS location         TEXT,
  ADD COLUMN IF NOT EXISTS department       TEXT,
  ADD COLUMN IF NOT EXISTS environment      TEXT DEFAULT 'production',
  ADD COLUMN IF NOT EXISTS internet_exposed BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS os_name          TEXT,
  ADD COLUMN IF NOT EXISTS os_version       TEXT,
  ADD COLUMN IF NOT EXISTS cpe_list         TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS technology_tags  TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS risk_score       NUMERIC(5,2) DEFAULT 0,
  ADD COLUMN IF NOT EXISTS risk_score_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS classification   TEXT DEFAULT 'internal',
  ADD COLUMN IF NOT EXISTS subnet           TEXT,
  ADD COLUMN IF NOT EXISTS mac_address      TEXT,
  ADD COLUMN IF NOT EXISTS last_seen_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS discovery_source TEXT DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS status           TEXT DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS confidence       NUMERIC(3,2) DEFAULT 1.0;

CREATE INDEX IF NOT EXISTS idx_asset_inv_tenant     ON asset_inventory (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_inv_risk_score ON asset_inventory (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_inv_exposed     ON asset_inventory (internet_exposed) WHERE internet_exposed = TRUE;
CREATE INDEX IF NOT EXISTS idx_asset_inv_cpe         ON asset_inventory USING GIN (cpe_list);
CREATE INDEX IF NOT EXISTS idx_asset_inv_tags        ON asset_inventory USING GIN (technology_tags);

-- ══════════════════════════════════════════════════════════════════════════════
--  2. VULNERABILITY MANAGEMENT (CVE, KEV, EPSS, CVSS)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_vulnerabilities (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cve_id          TEXT NOT NULL,
  title           TEXT,
  description     TEXT,
  cvss_score      NUMERIC(4,2),
  cvss_vector     TEXT,
  cvss_version    TEXT DEFAULT 'CVSS:3.1',
  epss_score      NUMERIC(6,5),
  epss_percentile NUMERIC(6,5),
  is_kev          BOOLEAN DEFAULT FALSE,
  kev_date_added  DATE,
  has_exploit     BOOLEAN DEFAULT FALSE,
  exploit_db_ids  TEXT[] DEFAULT '{}',
  published_at    DATE,
  modified_at     DATE,
  cpe_affected    TEXT[] DEFAULT '{}',
  references_json JSONB DEFAULT '[]',
  severity        TEXT DEFAULT 'unknown',
  status          TEXT DEFAULT 'open',
  cisa_severity   TEXT,
  nvd_status      TEXT,
  osv_data        JSONB,
  circl_data      JSONB,
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_nexus_vuln_tenant   ON nexus_vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_cve      ON nexus_vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_cvss     ON nexus_vulnerabilities (cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_epss     ON nexus_vulnerabilities (epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_kev      ON nexus_vulnerabilities (is_kev) WHERE is_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_severity ON nexus_vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_nexus_vuln_status   ON nexus_vulnerabilities (status);

-- Asset ↔ Vulnerability mapping (many-to-many)
CREATE TABLE IF NOT EXISTS nexus_asset_vulnerabilities (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_id          UUID NOT NULL REFERENCES asset_inventory(id) ON DELETE CASCADE,
  vulnerability_id  UUID NOT NULL REFERENCES nexus_vulnerabilities(id) ON DELETE CASCADE,
  match_source      TEXT DEFAULT 'cpe',   -- cpe | tag | manual | scan
  match_confidence  NUMERIC(3,2) DEFAULT 1.0,
  fusion_score      NUMERIC(5,2) DEFAULT 0,
  status            TEXT DEFAULT 'open',  -- open | accepted | remediated | fp
  accepted_reason   TEXT,
  remediated_at     TIMESTAMPTZ,
  sla_due_at        TIMESTAMPTZ,
  sla_breached      BOOLEAN DEFAULT FALSE,
  scanner_data      JSONB,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, asset_id, vulnerability_id)
);

CREATE INDEX IF NOT EXISTS idx_nexus_av_tenant  ON nexus_asset_vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_av_asset   ON nexus_asset_vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS idx_nexus_av_vuln    ON nexus_asset_vulnerabilities (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_nexus_av_fusion  ON nexus_asset_vulnerabilities (fusion_score DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  3. VULNERABILITY OPERATIONS CENTER (VOC) — SLA + Remediation Campaigns
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_voc_policies (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  critical_days   INTEGER DEFAULT 7,
  high_days       INTEGER DEFAULT 30,
  medium_days     INTEGER DEFAULT 90,
  low_days        INTEGER DEFAULT 180,
  informational_days INTEGER DEFAULT 365,
  active          BOOLEAN DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_remediation_campaigns (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  status          TEXT DEFAULT 'active',  -- active | completed | paused
  target_date     DATE,
  owner_email     TEXT,
  vuln_filter     JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_risk_acceptances (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vulnerability_id UUID REFERENCES nexus_vulnerabilities(id) ON DELETE SET NULL,
  asset_id        UUID REFERENCES asset_inventory(id) ON DELETE SET NULL,
  justification   TEXT NOT NULL,
  approved_by     TEXT,
  expires_at      DATE,
  risk_level      TEXT DEFAULT 'medium',
  status          TEXT DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
--  4. ATTACK PATH ANALYSIS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_attack_paths (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_asset_id UUID REFERENCES asset_inventory(id) ON DELETE CASCADE,
  target_asset_id UUID REFERENCES asset_inventory(id) ON DELETE CASCADE,
  path_nodes      JSONB DEFAULT '[]',       -- ordered array of asset_ids + edge cost
  path_cost       NUMERIC(10,4) DEFAULT 0,  -- Dijkstra weighted cost
  choke_point_ids UUID[] DEFAULT '{}',      -- asset_ids that are choke points
  exploitability  NUMERIC(5,2) DEFAULT 0,   -- fusion exploitability
  blast_radius    NUMERIC(5,2) DEFAULT 0,   -- business value at risk
  status          TEXT DEFAULT 'active',
  computed_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_ap_tenant ON nexus_attack_paths (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_ap_source ON nexus_attack_paths (source_asset_id);
CREATE INDEX IF NOT EXISTS idx_nexus_ap_target ON nexus_attack_paths (target_asset_id);
CREATE INDEX IF NOT EXISTS idx_nexus_ap_cost   ON nexus_attack_paths (path_cost);

-- Asset surface drift snapshots
CREATE TABLE IF NOT EXISTS nexus_surface_snapshots (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  snapshot_data   JSONB NOT NULL DEFAULT '[]',
  diff_data       JSONB DEFAULT '{}',       -- appeared/vanished/newly_exposed
  snapshot_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
--  5. ENTERPRISE RISK SCORE
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_risk_scores (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  enterprise_risk_score NUMERIC(5,2) DEFAULT 0,  -- 0–1000
  asset_hygiene_score   NUMERIC(5,2) DEFAULT 0,
  open_risk_score       NUMERIC(5,2) DEFAULT 0,
  incident_score        NUMERIC(5,2) DEFAULT 0,
  compliance_debt       NUMERIC(5,2) DEFAULT 0,
  assurance_credits     NUMERIC(5,2) DEFAULT 0,
  contributors          JSONB DEFAULT '{}',
  maturity_radar        JSONB DEFAULT '{}',       -- detection/mitigation/validation/compliance/crisis/risk
  risk_heatmap          JSONB DEFAULT '[]',       -- probability × impact cells
  computed_at           TIMESTAMPTZ DEFAULT NOW(),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_rs_tenant ON nexus_risk_scores (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_rs_at     ON nexus_risk_scores (computed_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  6. GRC — CONTROLS, AUDITS, FINDINGS, COMPLIANCE FRAMEWORKS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_controls (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  control_id      TEXT NOT NULL,   -- e.g. ISO-A.5.1, NIST-AC-1
  framework       TEXT NOT NULL,   -- ISO27001 | NIST_CSF | NIST_800_53 | CIS | NIS2 | DORA | SOC2
  name            TEXT NOT NULL,
  description     TEXT,
  category        TEXT,
  status          TEXT DEFAULT 'not_assessed',  -- implemented | partial | planned | not_assessed
  evidence        JSONB DEFAULT '[]',
  owner_email     TEXT,
  review_date     DATE,
  telemetry_proven BOOLEAN DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, control_id, framework)
);

CREATE INDEX IF NOT EXISTS idx_nexus_ctrl_tenant    ON nexus_controls (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_ctrl_framework ON nexus_controls (framework);
CREATE INDEX IF NOT EXISTS idx_nexus_ctrl_status    ON nexus_controls (status);

CREATE TABLE IF NOT EXISTS nexus_audits (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  audit_type      TEXT DEFAULT 'internal',  -- internal | external | pentest | tabletop
  framework       TEXT,
  scope           TEXT,
  status          TEXT DEFAULT 'planned',   -- planned | in_progress | completed | cancelled
  start_date      DATE,
  end_date        DATE,
  auditor         TEXT,
  summary         TEXT,
  findings_count  INTEGER DEFAULT 0,
  score           NUMERIC(5,2),
  report_url      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_audit_findings (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  audit_id        UUID REFERENCES nexus_audits(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  severity        TEXT DEFAULT 'medium',
  status          TEXT DEFAULT 'open',
  recommendation  TEXT,
  evidence        JSONB DEFAULT '[]',
  owner_email     TEXT,
  due_date        DATE,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
--  7. RISK REGISTER (CRQ / FAIR)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_risk_register (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title               TEXT NOT NULL,
  description         TEXT,
  category            TEXT,
  threat_source       TEXT,
  inherent_likelihood TEXT DEFAULT 'medium',
  inherent_impact     TEXT DEFAULT 'medium',
  inherent_score      NUMERIC(5,2) DEFAULT 0,
  current_likelihood  TEXT DEFAULT 'medium',
  current_impact      TEXT DEFAULT 'medium',
  current_score       NUMERIC(5,2) DEFAULT 0,
  residual_likelihood TEXT DEFAULT 'medium',
  residual_impact     TEXT DEFAULT 'medium',
  residual_score      NUMERIC(5,2) DEFAULT 0,
  treatment_strategy  TEXT DEFAULT 'mitigate',  -- mitigate | accept | transfer | avoid
  treatment_plan      TEXT,
  treatment_owner     TEXT,
  review_date         DATE,
  ale_estimate        NUMERIC(15,2),    -- Annualized Loss Expectancy
  sle_estimate        NUMERIC(15,2),    -- Single Loss Expectancy
  aro_estimate        NUMERIC(5,4),     -- Annual Rate of Occurrence
  fair_data           JSONB DEFAULT '{}',
  status              TEXT DEFAULT 'open',
  priority_score      INTEGER DEFAULT 0,
  tags                TEXT[] DEFAULT '{}',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_rr_tenant   ON nexus_risk_register (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_rr_score    ON nexus_risk_register (current_score DESC);
CREATE INDEX IF NOT EXISTS idx_nexus_rr_priority ON nexus_risk_register (priority_score DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  8. TPRM — THIRD-PARTY RISK MANAGEMENT
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_third_parties (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  vendor_type     TEXT,
  website         TEXT,
  contact_email   TEXT,
  risk_tier       TEXT DEFAULT 'medium',   -- critical | high | medium | low
  risk_score      NUMERIC(5,2) DEFAULT 0,
  assessment_status TEXT DEFAULT 'pending',
  last_assessed_at  TIMESTAMPTZ,
  next_review_at    TIMESTAMPTZ,
  contract_data   JSONB DEFAULT '{}',
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_tprm_assessments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  vendor_id       UUID REFERENCES nexus_third_parties(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  questions       JSONB DEFAULT '[]',
  responses       JSONB DEFAULT '{}',
  score           NUMERIC(5,2),
  status          TEXT DEFAULT 'pending',
  due_date        DATE,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
--  9. SBOM / SOFTWARE COMPOSITION ANALYSIS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_sboms (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_id        UUID REFERENCES asset_inventory(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  sbom_format     TEXT DEFAULT 'cyclonedx',   -- cyclonedx | spdx
  version         TEXT,
  component_count INTEGER DEFAULT 0,
  vuln_count      INTEGER DEFAULT 0,
  license_issues  INTEGER DEFAULT 0,
  raw_data        JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_sbom_components (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  sbom_id         UUID REFERENCES nexus_sboms(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  version         TEXT,
  purl            TEXT,
  cpe             TEXT,
  license         TEXT,
  supplier        TEXT,
  hash_sha256     TEXT,
  component_type  TEXT DEFAULT 'library',
  is_vulnerable   BOOLEAN DEFAULT FALSE,
  vuln_cves       TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_sbom_tenant ON nexus_sboms (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_sbom_comp_vuln ON nexus_sbom_components (is_vulnerable) WHERE is_vulnerable = TRUE;

-- ══════════════════════════════════════════════════════════════════════════════
--  10. SIGMA RULE LIBRARY
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_sigma_rules (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  rule_id         TEXT,
  title           TEXT NOT NULL,
  description     TEXT,
  status          TEXT DEFAULT 'experimental',  -- stable | test | experimental
  level           TEXT DEFAULT 'medium',         -- critical | high | medium | low | informational
  author          TEXT,
  tags            TEXT[] DEFAULT '{}',
  attack_techniques TEXT[] DEFAULT '{}',         -- ATT&CK technique IDs
  logsource       JSONB DEFAULT '{}',
  detection       JSONB DEFAULT '{}',
  condition_text  TEXT,
  falsepositives  TEXT[] DEFAULT '{}',
  raw_yaml        TEXT,
  source          TEXT DEFAULT 'community',       -- community | custom | ai_generated
  enabled         BOOLEAN DEFAULT TRUE,
  last_validated_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_sigma_tenant    ON nexus_sigma_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_sigma_level     ON nexus_sigma_rules (level);
CREATE INDEX IF NOT EXISTS idx_nexus_sigma_status    ON nexus_sigma_rules (status);
CREATE INDEX IF NOT EXISTS idx_nexus_sigma_techniques ON nexus_sigma_rules USING GIN (attack_techniques);
CREATE INDEX IF NOT EXISTS idx_nexus_sigma_title     ON nexus_sigma_rules USING GIN (title gin_trgm_ops);

-- ══════════════════════════════════════════════════════════════════════════════
--  11. YARA RULE LIBRARY
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_yara_rules (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  rule_content    TEXT NOT NULL,
  tags            TEXT[] DEFAULT '{}',
  malware_family  TEXT,
  severity        TEXT DEFAULT 'medium',
  source          TEXT DEFAULT 'community',
  enabled         BOOLEAN DEFAULT TRUE,
  match_count     INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_yara_tenant ON nexus_yara_rules (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  12. ADVERSARY EMULATION / BAS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_emulation_scenarios (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  threat_actor    TEXT,
  attack_phases   TEXT[] DEFAULT '{}',
  technique_ids   TEXT[] DEFAULT '{}',
  test_count      INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'draft',   -- draft | ready | running | completed
  schedule_cron   TEXT,
  last_run_at     TIMESTAMPTZ,
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_emulation_tests (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario_id     UUID REFERENCES nexus_emulation_scenarios(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  technique_id    TEXT,
  tactic          TEXT,
  executor        TEXT DEFAULT 'manual',   -- powershell | bash | cmd | manual
  command         TEXT,
  cleanup_command TEXT,
  safe_by_design  BOOLEAN DEFAULT TRUE,
  is_destructive  BOOLEAN DEFAULT FALSE,
  status          TEXT DEFAULT 'pending',  -- pending | running | passed | failed | skipped
  result          TEXT,
  detection_status TEXT,                   -- detected | logged | undetected | prevented
  raw_output      TEXT,
  ran_at          TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_emulation_results (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario_id     UUID REFERENCES nexus_emulation_scenarios(id) ON DELETE CASCADE,
  run_id          UUID NOT NULL DEFAULT uuid_generate_v4(),
  total_tests     INTEGER DEFAULT 0,
  passed          INTEGER DEFAULT 0,
  failed          INTEGER DEFAULT 0,
  skipped         INTEGER DEFAULT 0,
  detected        INTEGER DEFAULT 0,
  undetected      INTEGER DEFAULT 0,
  coverage_pct    NUMERIC(5,2) DEFAULT 0,
  technique_results JSONB DEFAULT '[]',
  summary         TEXT,
  run_at          TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_emu_tenant ON nexus_emulation_scenarios (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_emu_results_tenant ON nexus_emulation_results (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  13. THREAT HUNTING
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_hunts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  hypothesis      TEXT NOT NULL,
  technique_ids   TEXT[] DEFAULT '{}',
  status          TEXT DEFAULT 'open',   -- open | in_progress | closed | escalated
  hunter_email    TEXT,
  priority        TEXT DEFAULT 'medium',
  ioc_hits        JSONB DEFAULT '[]',
  sigma_rule_ids  UUID[] DEFAULT '{}',
  findings        TEXT,
  ai_analysis     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_nexus_hunts_tenant ON nexus_hunts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_hunts_status ON nexus_hunts (status);

-- ══════════════════════════════════════════════════════════════════════════════
--  14. DFIR — DIGITAL FORENSICS & INCIDENT RESPONSE
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_forensic_cases (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id     UUID,  -- references cases table if applicable
  title           TEXT NOT NULL,
  description     TEXT,
  status          TEXT DEFAULT 'active',   -- active | contained | closed
  lead_analyst    TEXT,
  severity        TEXT DEFAULT 'high',
  timeline        JSONB DEFAULT '[]',      -- array of {ts, event, analyst}
  artifacts       JSONB DEFAULT '[]',
  ioc_hits        JSONB DEFAULT '[]',
  attack_narrative TEXT,
  chain_of_custody JSONB DEFAULT '[]',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS nexus_forensic_artifacts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id         UUID REFERENCES nexus_forensic_cases(id) ON DELETE CASCADE,
  artifact_type   TEXT NOT NULL,   -- file | process | netconn | registry | log | memdump
  name            TEXT NOT NULL,
  description     TEXT,
  hash_sha256     TEXT,
  file_path       TEXT,
  size_bytes      BIGINT,
  collected_at    TIMESTAMPTZ DEFAULT NOW(),
  collector       TEXT,
  analysis_result TEXT,
  malicious       BOOLEAN,
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_forensic_tenant ON nexus_forensic_cases (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_forensic_status ON nexus_forensic_cases (status);

-- ══════════════════════════════════════════════════════════════════════════════
--  15. SECURITY CONNECTORS CATALOG
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_connectors (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  display_name    TEXT,
  description     TEXT,
  category        TEXT NOT NULL,   -- vuln_scanner | siem | cti | pentest | osint | cloud | identity | edr
  connector_type  TEXT DEFAULT 'api',  -- api | agent | file | webhook
  enabled         BOOLEAN DEFAULT FALSE,
  config          JSONB DEFAULT '{}',   -- encrypted connector config (API keys, URLs)
  last_run_at     TIMESTAMPTZ,
  last_status     TEXT DEFAULT 'never_run',
  last_error      TEXT,
  run_count       INTEGER DEFAULT 0,
  results_count   INTEGER DEFAULT 0,
  schedule_cron   TEXT,
  vendor          TEXT,
  icon_url        TEXT,
  docs_url        TEXT,
  version         TEXT DEFAULT '1.0.0',
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_conn_tenant   ON nexus_connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_conn_category ON nexus_connectors (category);
CREATE INDEX IF NOT EXISTS idx_nexus_conn_enabled  ON nexus_connectors (enabled) WHERE enabled = TRUE;

-- ══════════════════════════════════════════════════════════════════════════════
--  16. BACKGROUND JOB SCHEDULER (XSCHEDULE)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_scheduled_jobs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  job_type        TEXT NOT NULL,   -- cve_import | risk_score | oval_scan | bas_emulation | cti_pull | asset_discovery
  name            TEXT NOT NULL,
  description     TEXT,
  cron_expression TEXT NOT NULL,
  enabled         BOOLEAN DEFAULT TRUE,
  connector_id    UUID REFERENCES nexus_connectors(id) ON DELETE SET NULL,
  config          JSONB DEFAULT '{}',
  last_run_at     TIMESTAMPTZ,
  last_status     TEXT DEFAULT 'pending',
  last_error      TEXT,
  next_run_at     TIMESTAMPTZ,
  run_count       INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_jobs_tenant  ON nexus_scheduled_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_jobs_enabled ON nexus_scheduled_jobs (enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_nexus_jobs_next    ON nexus_scheduled_jobs (next_run_at);

-- ══════════════════════════════════════════════════════════════════════════════
--  17. THREAT MODELING (STRIDE)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_threat_models (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  scope           TEXT,
  assets_in_scope TEXT[] DEFAULT '{}',
  threats         JSONB DEFAULT '[]',   -- array of {id, category(STRIDE), description, likelihood, impact, controls[]}
  controls        JSONB DEFAULT '[]',
  status          TEXT DEFAULT 'active',
  owner_email     TEXT,
  review_date     DATE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_tm_tenant ON nexus_threat_models (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  18. BUSINESS IMPACT ANALYSIS (BIA)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_bia_entries (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  criticality     TEXT DEFAULT 'medium',  -- critical | high | medium | low
  rto_hours       INTEGER DEFAULT 24,     -- Recovery Time Objective
  rpo_hours       INTEGER DEFAULT 8,      -- Recovery Point Objective
  mtpd_hours      INTEGER DEFAULT 72,     -- Maximum Tolerable Period of Disruption
  dependencies    UUID[] DEFAULT '{}',    -- other bia_entry IDs
  asset_ids       UUID[] DEFAULT '{}',    -- linked asset_inventory IDs
  owner_email     TEXT,
  financial_impact NUMERIC(15,2) DEFAULT 0,
  reputational_impact TEXT DEFAULT 'medium',
  regulatory_impact TEXT DEFAULT 'low',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_bia_tenant ON nexus_bia_entries (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  19. EBIOS RM
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_ebios_studies (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  scope           TEXT,
  status          TEXT DEFAULT 'w1_framing',  -- w1_framing|w2_risk_sources|w3_strategic|w4_operational|w5_treatment
  business_values JSONB DEFAULT '[]',
  supporting_assets JSONB DEFAULT '[]',
  feared_events   JSONB DEFAULT '[]',   -- DICT: Disponibility/Integrity/Confidentiality/Traceability
  risk_sources    JSONB DEFAULT '[]',
  strategic_scenarios JSONB DEFAULT '[]',
  operational_scenarios JSONB DEFAULT '[]',
  treatment_plan  JSONB DEFAULT '{}',
  express_mode    BOOLEAN DEFAULT FALSE,
  owner_email     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_ebios_tenant ON nexus_ebios_studies (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  20. NIST 800-30 RISK ASSESSMENT
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_nist_assessments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  status          TEXT DEFAULT 'active',
  threat_sources  JSONB DEFAULT '[]',   -- adversarial & non-adversarial
  threat_events   JSONB DEFAULT '[]',
  vulnerabilities JSONB DEFAULT '[]',
  predisposing_conditions JSONB DEFAULT '[]',
  risk_determinations JSONB DEFAULT '[]',  -- likelihood × impact on 800-30 scale
  owner_email     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_nist_tenant ON nexus_nist_assessments (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  21. PQCMM — POST-QUANTUM CRYPTOGRAPHY MATURITY MODEL
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_pqcmm_assessments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  asset_type      TEXT DEFAULT 'product',  -- product | service | asset
  current_level   INTEGER DEFAULT 0,  -- 0-5 PQCMM levels
  target_level    INTEGER DEFAULT 3,
  crypto_deps     JSONB DEFAULT '[]',
  quantum_vulnerable BOOLEAN DEFAULT TRUE,
  cbom_present    BOOLEAN DEFAULT FALSE,
  notes           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_pqcmm_tenant ON nexus_pqcmm_assessments (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  22. CRISIS MANAGEMENT & TABLETOP EXERCISES
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_crisis_scenarios (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  scenario_type   TEXT DEFAULT 'ransomware',  -- ransomware|data_breach|ddos|insider|supply_chain|cloud|bec
  injects         JSONB DEFAULT '[]',  -- timed scenario injects
  participants    JSONB DEFAULT '[]',  -- {role, email}
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_crisis_exercises (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario_id     UUID REFERENCES nexus_crisis_scenarios(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  status          TEXT DEFAULT 'planned',  -- planned | in_progress | completed
  start_date      DATE,
  end_date        DATE,
  participants    JSONB DEFAULT '[]',
  observations    JSONB DEFAULT '[]',
  improvement_actions JSONB DEFAULT '[]',
  after_action_report TEXT,
  readiness_score NUMERIC(5,2) DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_crisis_tenant    ON nexus_crisis_scenarios (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_exercise_tenant  ON nexus_crisis_exercises (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  23. RANSOMWARE SCENARIO (FAIR + ATT&CK)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_ransomware_scenarios (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  threat_actor    TEXT NOT NULL,
  description     TEXT,
  ttps            TEXT[] DEFAULT '{}',  -- ATT&CK technique IDs
  kill_chain_phases TEXT[] DEFAULT '{}',
  affected_assets JSONB DEFAULT '[]',   -- {asset_id, asset_name, value_at_risk}
  total_sle       NUMERIC(15,2) DEFAULT 0,  -- Single Loss Expectancy
  total_ale       NUMERIC(15,2) DEFAULT 0,  -- Annualized Loss Expectancy
  residual_with_controls NUMERIC(15,2) DEFAULT 0,
  ransom_estimate NUMERIC(15,2) DEFAULT 0,
  recovery_cost   NUMERIC(15,2) DEFAULT 0,
  aro_estimate    NUMERIC(5,4) DEFAULT 0.1,
  d3fend_mitigations JSONB DEFAULT '[]',
  blast_radius_count INTEGER DEFAULT 0,
  computed_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_ransom_tenant ON nexus_ransomware_scenarios (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  24. ADVERSARY OPPORTUNITY INDEX (AOI)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_aoi_records (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  aoi_score       NUMERIC(7,2) DEFAULT 0,   -- 0-1000
  paid_down       NUMERIC(7,2) DEFAULT 0,   -- reductions this period
  accrued         NUMERIC(7,2) DEFAULT 0,   -- new opportunities this period
  choke_points    JSONB DEFAULT '[]',
  attack_path_gaps JSONB DEFAULT '[]',
  ledger_items    JSONB DEFAULT '[]',
  computed_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_aoi_tenant ON nexus_aoi_records (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_aoi_at     ON nexus_aoi_records (computed_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
--  25. CYBER INSURANCE READINESS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_insurance_readiness (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  overall_score   NUMERIC(5,2) DEFAULT 0,   -- 0-100
  controls_status JSONB DEFAULT '{}',       -- {mfa, backups, edr_siem, pam, patching, tested_ir, segmentation}
  policy_limit    NUMERIC(15,2),
  fair_ransomware_loss NUMERIC(15,2),
  coverage_adequate BOOLEAN DEFAULT FALSE,
  renewal_date    DATE,
  insurer         TEXT,
  premium_estimate NUMERIC(15,2),
  computed_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_insure_tenant ON nexus_insurance_readiness (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  26. AI GUARDRAILS MANAGEMENT
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_ai_guardrail_assessments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_id        UUID REFERENCES asset_inventory(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  ai_app_type     TEXT DEFAULT 'llm_app',   -- llm_app | ai_agent | mcp_server | langchain | crewai | ollama
  controls_status JSONB DEFAULT '{}',       -- 12 guardrail controls
  score           NUMERIC(5,2) DEFAULT 0,
  risk_level      TEXT DEFAULT 'medium',
  findings        JSONB DEFAULT '[]',
  prompt_injection_detected BOOLEAN DEFAULT FALSE,
  last_scanned_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_aig_tenant ON nexus_ai_guardrail_assessments (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  27. CTEM EXPOSURE TAXONOMY
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_ctem_exposures (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  exposure_id     TEXT,   -- ctem.org identifier (e.g. EXP-0001)
  category        TEXT,   -- 8 categories from ctem.org standard
  name            TEXT NOT NULL,
  description     TEXT,
  stage           TEXT DEFAULT 'discover',  -- discover | prioritize | remediate
  asset_id        UUID REFERENCES asset_inventory(id) ON DELETE SET NULL,
  status          TEXT DEFAULT 'active',
  severity        TEXT DEFAULT 'medium',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_ctem_tenant ON nexus_ctem_exposures (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_ctem_stage  ON nexus_ctem_exposures (stage);

-- ══════════════════════════════════════════════════════════════════════════════
--  28. CONFIGURATION MANAGEMENT (OVAL/SCAP)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_config_baselines (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  framework       TEXT DEFAULT 'CIS',  -- CIS | STIG | NIST | custom
  os_family       TEXT,
  version         TEXT,
  check_count     INTEGER DEFAULT 0,
  pass_count      INTEGER DEFAULT 0,
  fail_count      INTEGER DEFAULT 0,
  health_score    NUMERIC(5,2) DEFAULT 0,
  oval_definitions JSONB DEFAULT '[]',
  last_scanned_at TIMESTAMPTZ,
  status          TEXT DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_config_tenant ON nexus_config_baselines (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  29. POLICIES & DOCUMENTS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_policies (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  policy_type     TEXT DEFAULT 'policy',   -- policy | standard | procedure | guideline
  framework       TEXT,
  status          TEXT DEFAULT 'draft',    -- draft | in_review | approved | published | retired
  version         TEXT DEFAULT '1.0',
  owner_email     TEXT,
  reviewer_email  TEXT,
  approved_by     TEXT,
  approved_at     TIMESTAMPTZ,
  published_at    TIMESTAMPTZ,
  review_date     DATE,
  content         TEXT,
  governance_score NUMERIC(5,2) DEFAULT 0,
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_policies_tenant ON nexus_policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_policies_status ON nexus_policies (status);

-- ══════════════════════════════════════════════════════════════════════════════
--  30. THREAT-INFORMED DEFENSE COVERAGE
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_tid_coverage (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  technique_id    TEXT NOT NULL,  -- ATT&CK technique ID (T1234)
  tactic          TEXT,
  technique_name  TEXT,
  adversary_prevalence NUMERIC(5,4) DEFAULT 0,   -- 0-1 ecosystem prevalence
  local_cti_boost NUMERIC(5,4) DEFAULT 0,         -- boost from local CTI
  detect_status   TEXT DEFAULT 'none',   -- covered | partial | none | false_coverage | drift
  mitigate_status TEXT DEFAULT 'none',
  test_status     TEXT DEFAULT 'none',   -- defined | executed | validated | regression
  program_score   NUMERIC(5,2) DEFAULT 0,
  sigma_rule_ids  UUID[] DEFAULT '{}',
  d3fend_ids      TEXT[] DEFAULT '{}',
  emulation_ids   UUID[] DEFAULT '{}',
  detection_drift BOOLEAN DEFAULT FALSE,
  last_validated_at TIMESTAMPTZ,
  navigator_export JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_nexus_tid_tenant    ON nexus_tid_coverage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_tid_technique ON nexus_tid_coverage (technique_id);
CREATE INDEX IF NOT EXISTS idx_nexus_tid_detect    ON nexus_tid_coverage (detect_status);

-- ══════════════════════════════════════════════════════════════════════════════
--  31. BUG BOUNTY
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_bug_bounty_programs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  scope           JSONB DEFAULT '[]',
  bounty_ranges   JSONB DEFAULT '{}',  -- {critical, high, medium, low}
  status          TEXT DEFAULT 'active',
  platform        TEXT,
  start_date      DATE,
  end_date        DATE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nexus_bug_bounty_submissions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  program_id      UUID REFERENCES nexus_bug_bounty_programs(id) ON DELETE CASCADE,
  vulnerability_id UUID REFERENCES nexus_vulnerabilities(id) ON DELETE SET NULL,
  title           TEXT NOT NULL,
  reporter        TEXT,
  severity        TEXT DEFAULT 'medium',
  status          TEXT DEFAULT 'triaging',  -- triaging | accepted | rejected | duplicate | paid
  bounty_paid     NUMERIC(10,2),
  description     TEXT,
  poc_url         TEXT,
  submitted_at    TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════════════════════
--  32. ATTACK SURFACE MONITORING (OSINT + Discovery)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_discovery_runs (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  seed_domain     TEXT NOT NULL,
  status          TEXT DEFAULT 'running',  -- running | completed | failed
  discovered_hosts INTEGER DEFAULT 0,
  new_assets      INTEGER DEFAULT 0,
  exposed_services INTEGER DEFAULT 0,
  results         JSONB DEFAULT '[]',
  tools_used      TEXT[] DEFAULT '{}',
  run_mode        TEXT DEFAULT 'simulate',  -- simulate | live
  started_at      TIMESTAMPTZ DEFAULT NOW(),
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_disc_tenant ON nexus_discovery_runs (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  33. FAIR-MAM MATERIALITY ASSESSMENT
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_fair_mam_assessments (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  loss_event      TEXT,
  cost_categories JSONB DEFAULT '{}',  -- 10 FAIR-MAM categories with PERT ranges
  expected_sle    NUMERIC(15,2) DEFAULT 0,
  primary_loss    NUMERIC(15,2) DEFAULT 0,
  secondary_loss  NUMERIC(15,2) DEFAULT 0,
  materiality_threshold NUMERIC(15,2),
  is_material     BOOLEAN DEFAULT FALSE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_fairmam_tenant ON nexus_fair_mam_assessments (tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
--  34. IDENTITY & DEVICE SYNC (Entra ID / NHI)
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_identities (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  identity_type   TEXT DEFAULT 'human',  -- human | service_principal | managed_identity | device
  display_name    TEXT NOT NULL,
  email           TEXT,
  external_id     TEXT,   -- Entra ID object ID
  source          TEXT DEFAULT 'manual',  -- entra_id | ldap | manual
  mfa_enabled     BOOLEAN,
  is_stale        BOOLEAN DEFAULT FALSE,
  is_orphaned     BOOLEAN DEFAULT FALSE,
  last_activity_at TIMESTAMPTZ,
  risk_score      NUMERIC(5,2) DEFAULT 0,
  attributes      JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_identity_tenant ON nexus_identities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nexus_identity_type   ON nexus_identities (identity_type);
CREATE INDEX IF NOT EXISTS idx_nexus_identity_stale  ON nexus_identities (is_stale) WHERE is_stale = TRUE;

-- ══════════════════════════════════════════════════════════════════════════════
--  35. PENTEST ENGAGEMENTS
-- ══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nexus_pentest_engagements (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  scope_asset_ids UUID[] DEFAULT '{}',
  roe_document    TEXT,   -- Rules of Engagement
  status          TEXT DEFAULT 'planned',  -- planned | active | completed | reported
  pentest_type    TEXT DEFAULT 'external',  -- external | internal | web | mobile | api | red_team
  start_date      DATE,
  end_date        DATE,
  lead_tester     TEXT,
  executive_summary TEXT,
  findings_count  INTEGER DEFAULT 0,
  critical_count  INTEGER DEFAULT 0,
  high_count      INTEGER DEFAULT 0,
  report_pdf_url  TEXT,
  tools_used      TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nexus_pentest_tenant ON nexus_pentest_engagements (tenant_id);

COMMIT;

-- ══════════════════════════════════════════════════════════════════════════════
--  SEED DATA: Default Sigma rules starter set, Connector catalog, SLA policies
-- ══════════════════════════════════════════════════════════════════════════════

-- Note: Seed data should be inserted per-tenant post-migration.
-- Use the /api/nexus/seed/:tenant_id endpoint to populate defaults.

COMMENT ON TABLE nexus_vulnerabilities IS 'CVE/KEV/EPSS vulnerability library — Wadjet Nexus CTEM module';
COMMENT ON TABLE nexus_asset_vulnerabilities IS 'Asset↔CVE mapping with fusion scoring';
COMMENT ON TABLE nexus_attack_paths IS 'Dijkstra attack paths across asset estate';
COMMENT ON TABLE nexus_risk_scores IS 'Enterprise Risk Score time-series';
COMMENT ON TABLE nexus_sigma_rules IS 'Sigma detection rule library (3750+ rules)';
COMMENT ON TABLE nexus_tid_coverage IS 'Threat-Informed Defense ATT&CK coverage cockpit';
COMMENT ON TABLE nexus_emulation_results IS 'BAS/AEV emulation run results';
