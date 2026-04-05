-- ══════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Enterprise Migration v4.0
--  backend/database/migration-v4.0-enterprise.sql
--
--  Changes:
--    1. refresh_tokens table (secure session persistence)
--    2. login_activity table (audit trail)
--    3. vulnerabilities table (NVD/CISA KEV live data)
--    4. sysmon_logs table (Sysmon analyzer results)
--    5. sysmon_detections table (mapped MITRE techniques)
--    6. case_evidence table (file attachments)
--    7. executive_reports table (generated PDFs)
--    8. Indexes for performance
--    9. RLS policies
-- ══════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────
-- 1. REFRESH TOKENS — Secure session management
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,   -- SHA-256 of the actual token
    device_info  JSONB DEFAULT '{}',     -- {ua, ip, device, browser, os}
    is_revoked   BOOLEAN DEFAULT FALSE,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Automatically purge expired tokens daily (via pg_cron if available, else scheduled)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('purge-expired-tokens', '0 4 * * *', $$DELETE FROM refresh_tokens WHERE expires_at < NOW()$$);

-- ─────────────────────────────────────────────────────────
-- 2. LOGIN ACTIVITY — Complete audit trail
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS login_activity (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    tenant_id   UUID,
    email       TEXT,
    action      TEXT NOT NULL,   -- LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, TOKEN_REFRESH, SESSION_EXPIRED
    ip_address  INET,
    user_agent  TEXT,
    device_info JSONB DEFAULT '{}',
    location    JSONB DEFAULT '{}', -- {country, city, org} from IP lookup
    success     BOOLEAN DEFAULT TRUE,
    failure_reason TEXT,
    session_id  UUID,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_activity_user_id   ON login_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_login_activity_tenant_id ON login_activity(tenant_id);
CREATE INDEX IF NOT EXISTS idx_login_activity_created   ON login_activity(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_activity_action    ON login_activity(action);

-- ─────────────────────────────────────────────────────────
-- 3. VULNERABILITIES — Live NVD + CISA KEV data
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          TEXT UNIQUE NOT NULL,
    title           TEXT,
    description     TEXT,
    severity        TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    cvss_v3_score   NUMERIC(4,1),
    cvss_v2_score   NUMERIC(4,1),
    cvss_vector     TEXT,
    exploited       BOOLEAN DEFAULT FALSE,
    in_cisa_kev     BOOLEAN DEFAULT FALSE,
    cisa_kev_date   DATE,
    cisa_remediation_due DATE,
    affected_products JSONB DEFAULT '[]',
    references      JSONB DEFAULT '[]',
    cwe_ids         TEXT[],
    attack_vector   TEXT,
    attack_complexity TEXT,
    privileges_required TEXT,
    user_interaction TEXT,
    scope           TEXT,
    published_at    DATE,
    modified_at     DATE,
    source          TEXT DEFAULT 'NVD',
    raw_data        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve_id      ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity    ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cvss_score  ON vulnerabilities(cvss_v3_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_exploited   ON vulnerabilities(exploited);
CREATE INDEX IF NOT EXISTS idx_vulns_kev         ON vulnerabilities(in_cisa_kev);
CREATE INDEX IF NOT EXISTS idx_vulns_published   ON vulnerabilities(published_at DESC);

-- ─────────────────────────────────────────────────────────
-- 4. SYSMON LOGS — Upload + parse results
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sysmon_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    filename      TEXT NOT NULL,
    uploaded_by   UUID REFERENCES users(id),
    file_size     BIGINT,
    format        TEXT DEFAULT 'evtx',   -- evtx | json | xml
    status        TEXT DEFAULT 'queued', -- queued | processing | completed | failed
    total_events  INTEGER DEFAULT 0,
    parsed_events INTEGER DEFAULT 0,
    detections    INTEGER DEFAULT 0,
    high_risk     INTEGER DEFAULT 0,
    processing_ms BIGINT,
    error_message TEXT,
    uploaded_at   TIMESTAMPTZ DEFAULT NOW(),
    processed_at  TIMESTAMPTZ,
    raw_sample    JSONB DEFAULT '{}',   -- First 5 events for preview
    summary       JSONB DEFAULT '{}'    -- Aggregated detection summary
);

CREATE INDEX IF NOT EXISTS idx_sysmon_tenant  ON sysmon_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sysmon_status  ON sysmon_logs(status);
CREATE INDEX IF NOT EXISTS idx_sysmon_upload  ON sysmon_logs(uploaded_at DESC);

-- ─────────────────────────────────────────────────────────
-- 5. SYSMON DETECTIONS — Individual event detections
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sysmon_detections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id          UUID NOT NULL REFERENCES sysmon_logs(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    event_id        INTEGER,             -- Sysmon Event ID (1=Process, 3=Network, etc.)
    event_type      TEXT,               -- ProcessCreate, NetworkConnect, etc.
    severity        TEXT DEFAULT 'MEDIUM',
    rule_name       TEXT,               -- Detection rule that fired
    rule_id         TEXT,               -- Sigma rule ID
    mitre_tactic    TEXT,               -- e.g. TA0002
    mitre_technique TEXT,               -- e.g. T1055
    mitre_subtechnique TEXT,            -- e.g. T1055.012
    process_name    TEXT,
    process_path    TEXT,
    command_line    TEXT,
    parent_process  TEXT,
    user_name       TEXT,
    hostname        TEXT,
    remote_ip       TEXT,
    remote_port     INTEGER,
    hash_md5        TEXT,
    hash_sha256     TEXT,
    raw_event       JSONB DEFAULT '{}',
    confidence      NUMERIC(3,2) DEFAULT 0.75, -- 0.0 to 1.0
    false_positive  BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sysmon_det_log    ON sysmon_detections(log_id);
CREATE INDEX IF NOT EXISTS idx_sysmon_det_tenant ON sysmon_detections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sysmon_det_sev    ON sysmon_detections(severity);
CREATE INDEX IF NOT EXISTS idx_sysmon_det_mitre  ON sysmon_detections(mitre_technique);

-- ─────────────────────────────────────────────────────────
-- 6. CASE EVIDENCE — File attachments
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_evidence (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL,
    filename    TEXT NOT NULL,
    file_type   TEXT,
    file_size   BIGINT,
    storage_url TEXT,          -- Supabase Storage URL
    description TEXT,
    uploaded_by UUID REFERENCES users(id),
    uploaded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON case_evidence(case_id);

-- ─────────────────────────────────────────────────────────
-- 7. EXECUTIVE REPORTS — PDF generation history
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS executive_reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL,
    title          TEXT NOT NULL,
    report_type    TEXT DEFAULT 'executive_summary',
    period_start   DATE,
    period_end     DATE,
    generated_by   UUID REFERENCES users(id),
    storage_url    TEXT,              -- Link to generated PDF
    status         TEXT DEFAULT 'generating',
    kpi_snapshot   JSONB DEFAULT '{}',
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant ON executive_reports(tenant_id);

-- ─────────────────────────────────────────────────────────
-- 8. Ensure cases has proper evidence + sla columns
-- ─────────────────────────────────────────────────────────
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_hours     INTEGER DEFAULT 72;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_deadline  TIMESTAMPTZ;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_breached  BOOLEAN DEFAULT FALSE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_at     TIMESTAMPTZ;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS escalated_at  TIMESTAMPTZ;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS resolution    TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[] DEFAULT '{}';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS kill_chain_phase TEXT;

-- ─────────────────────────────────────────────────────────
-- 9. Feed logs — ensure all columns exist
-- ─────────────────────────────────────────────────────────
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_fetched  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_new      INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_updated  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_skipped  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS duration_ms   INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS error_message TEXT;

-- ─────────────────────────────────────────────────────────
-- 10. Add updated_at trigger for vulnerabilities
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_vulns_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─────────────────────────────────────────────────────────
-- 11. RLS Policies
-- ─────────────────────────────────────────────────────────
ALTER TABLE refresh_tokens   ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_activity   ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities  ENABLE ROW LEVEL SECURITY;
ALTER TABLE sysmon_logs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE sysmon_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_evidence    ENABLE ROW LEVEL SECURITY;
ALTER TABLE executive_reports ENABLE ROW LEVEL SECURITY;

-- refresh_tokens: user sees only own tokens
CREATE POLICY "users_own_refresh_tokens" ON refresh_tokens
    FOR ALL USING (user_id = auth.uid()::UUID);

-- login_activity: users see own activity, admins see tenant
CREATE POLICY "user_own_login_activity" ON login_activity
    FOR SELECT USING (user_id = auth.uid()::UUID);

-- vulnerabilities: readable by all authenticated users
CREATE POLICY "authed_read_vulns" ON vulnerabilities
    FOR SELECT USING (auth.role() = 'authenticated');

-- sysmon: tenant-scoped
CREATE POLICY "tenant_sysmon_logs" ON sysmon_logs
    FOR ALL USING (tenant_id = (SELECT tenant_id FROM users WHERE auth_id = auth.uid()));

CREATE POLICY "tenant_sysmon_detections" ON sysmon_detections
    FOR ALL USING (tenant_id = (SELECT tenant_id FROM users WHERE auth_id = auth.uid()));

CREATE POLICY "tenant_case_evidence" ON case_evidence
    FOR ALL USING (tenant_id = (SELECT tenant_id FROM users WHERE auth_id = auth.uid()));

CREATE POLICY "tenant_exec_reports" ON executive_reports
    FOR ALL USING (tenant_id = (SELECT tenant_id FROM users WHERE auth_id = auth.uid()));

-- ─────────────────────────────────────────────────────────
-- 12. Grant service role all permissions (bypass RLS)
-- ─────────────────────────────────────────────────────────
GRANT ALL ON refresh_tokens    TO service_role;
GRANT ALL ON login_activity    TO service_role;
GRANT ALL ON vulnerabilities   TO service_role;
GRANT ALL ON sysmon_logs       TO service_role;
GRANT ALL ON sysmon_detections TO service_role;
GRANT ALL ON case_evidence     TO service_role;
GRANT ALL ON executive_reports TO service_role;

-- ─────────────────────────────────────────────────────────
-- 13. Seed: ensure default MSSP tenant exists
-- ─────────────────────────────────────────────────────────
INSERT INTO tenants (id, name, short_name, active, created_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'MSSP Global Operations',
    'mssp-global',
    true,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Done
SELECT 'Migration v4.0 complete' AS status;
