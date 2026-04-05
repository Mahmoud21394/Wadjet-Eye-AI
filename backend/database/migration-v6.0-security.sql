-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — Security Hardening Migration v6.0
--  backend/database/migration-v6.0-security.sql
--
--  Run in: Supabase Dashboard → SQL Editor
--  Applies: MFA tables, break-glass audit tables, IOC validation
--           error logging, and security hardening columns
--
--  Order: Run AFTER migration-v5.2-live-cti.sql
-- ══════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────
-- 1. MFA TABLES
-- ─────────────────────────────────────────────────────────────────

-- Add TOTP columns to users table
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS totp_secret         TEXT,           -- AES-256-GCM encrypted
  ADD COLUMN IF NOT EXISTS totp_secret_pending TEXT,           -- Unconfirmed during enrollment
  ADD COLUMN IF NOT EXISTS totp_enrolled_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mfa_enforced        BOOLEAN DEFAULT FALSE;

-- Update mfa_enabled column (already exists, ensure default)
ALTER TABLE users ALTER COLUMN mfa_enabled SET DEFAULT FALSE;

-- Force MFA enforcement flag for privileged roles
UPDATE users
SET mfa_enforced = TRUE
WHERE role IN ('ADMIN', 'SUPER_ADMIN', 'super_admin', 'admin');

-- MFA challenge tokens (pre-auth step during login)
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pre_auth_token   TEXT NOT NULL UNIQUE,   -- SHA-256 hash of the challenge token
  expires_at       TIMESTAMPTZ NOT NULL,
  used             BOOLEAN NOT NULL DEFAULT FALSE,
  used_at          TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_token
  ON mfa_challenges (pre_auth_token)
  WHERE used = FALSE;

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires
  ON mfa_challenges (expires_at);

-- Auto-expire: delete challenges older than 1 hour
-- (Run as a scheduled Supabase function or pg_cron)

-- ─────────────────────────────────────────────────────────────────
-- 2. BREAK-GLASS ACCESS TABLES
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS break_glass_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email    TEXT NOT NULL,
  otp_hash       TEXT NOT NULL,         -- SHA-256(otp + email)
  ip_address     INET,
  expires_at     TIMESTAMPTZ NOT NULL,
  status         TEXT NOT NULL DEFAULT 'PENDING'
                   CHECK (status IN ('PENDING', 'USED', 'EXPIRED', 'SUPERSEDED')),
  attempt_count  INTEGER DEFAULT 0,
  used_at        TIMESTAMPTZ,
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS break_glass_sessions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email         TEXT NOT NULL,
  session_token_hash  TEXT NOT NULL UNIQUE,   -- SHA-256 of the session token
  ip_address          INET,
  expires_at          TIMESTAMPTZ NOT NULL,
  active              BOOLEAN NOT NULL DEFAULT TRUE,
  revoked_at          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Immutable audit log for all break-glass events
CREATE TABLE IF NOT EXISTS break_glass_audit (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event        TEXT NOT NULL,
  admin_email  TEXT NOT NULL,
  ip_address   INET,
  metadata     JSONB,
  timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No UPDATE or DELETE on audit log (append-only via RLS)
ALTER TABLE break_glass_audit ENABLE ROW LEVEL SECURITY;

CREATE POLICY "break_glass_audit_insert_only" ON break_glass_audit
  FOR INSERT TO service_role WITH CHECK (true);

CREATE POLICY "break_glass_audit_select_admins" ON break_glass_audit
  FOR SELECT TO service_role USING (true);

-- Prevent any UPDATE or DELETE (no policy = denied)

-- ─────────────────────────────────────────────────────────────────
-- 3. IOC VALIDATION ERROR LOG
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ioc_validation_errors (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed         TEXT,
  raw_value    TEXT,
  raw_type     TEXT,
  error        TEXT NOT NULL,
  detected_type TEXT,
  occurred_at  TIMESTAMPTZ DEFAULT NOW(),
  tenant_id    UUID
);

CREATE INDEX IF NOT EXISTS idx_ioc_val_errors_feed
  ON ioc_validation_errors (feed, occurred_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 4. SESSION SECURITY ENHANCEMENTS
-- ─────────────────────────────────────────────────────────────────

-- Track active sessions with device fingerprint
ALTER TABLE refresh_tokens
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_used_ip INET,
  ADD COLUMN IF NOT EXISTS user_agent   TEXT;

-- Impossible travel detection support
ALTER TABLE login_activity
  ADD COLUMN IF NOT EXISTS country_code TEXT,
  ADD COLUMN IF NOT EXISTS city         TEXT,
  ADD COLUMN IF NOT EXISTS risk_flags   JSONB;

-- ─────────────────────────────────────────────────────────────────
-- 5. RLS POLICIES FOR NEW TABLES
-- ─────────────────────────────────────────────────────────────────

ALTER TABLE mfa_challenges         ENABLE ROW LEVEL SECURITY;
ALTER TABLE break_glass_requests   ENABLE ROW LEVEL SECURITY;
ALTER TABLE break_glass_sessions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_validation_errors  ENABLE ROW LEVEL SECURITY;

-- Service role has full access (backend only)
CREATE POLICY "service_role_mfa_challenges" ON mfa_challenges
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_break_glass_requests" ON break_glass_requests
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_break_glass_sessions" ON break_glass_sessions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_ioc_val_errors" ON ioc_validation_errors
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Anon has no access to any of these tables
-- (no policy = implicit deny for anon role)

-- ─────────────────────────────────────────────────────────────────
-- 6. SECURITY VIEW: IOC type distribution audit
-- ─────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW ioc_type_consistency_audit AS
SELECT
  type,
  COUNT(*)                                            AS total,
  COUNT(*) FILTER (WHERE type_subtype IS NOT NULL)    AS with_subtype,
  COUNT(*) FILTER (WHERE value ~ '^[a-fA-F0-9]{64}$'
    AND type = 'ip')                                  AS hash_typed_as_ip,  -- data quality flag
  COUNT(*) FILTER (WHERE value ~ '^(\d{1,3}\.){3}\d{1,3}$'
    AND type != 'ip')                                 AS ip_typed_wrong,    -- data quality flag
  MIN(created_at)                                     AS oldest,
  MAX(created_at)                                     AS newest
FROM iocs
GROUP BY type
ORDER BY total DESC;

COMMENT ON VIEW ioc_type_consistency_audit IS
  'Data quality view: flags IOCs where value pattern contradicts declared type. Run periodically.';

-- ─────────────────────────────────────────────────────────────────
-- 7. CLEAN UP EXISTING TYPE MISMATCHES
-- ─────────────────────────────────────────────────────────────────

-- Move existing hash-typed-as-IP records to correct type
-- (Review these manually before running in production)
/*
UPDATE iocs
SET type = 'hash', type_subtype = 'sha256'
WHERE type = 'ip'
  AND value ~ '^[a-fA-F0-9]{64}$';

UPDATE iocs
SET type = 'hash', type_subtype = 'md5'
WHERE type = 'ip'
  AND value ~ '^[a-fA-F0-9]{32}$'
  AND value !~ '^(\d{1,3}\.){3}\d{1,3}$';
*/

-- ─────────────────────────────────────────────────────────────────
-- Migration complete
-- ─────────────────────────────────────────────────────────────────
DO $$ BEGIN
  RAISE NOTICE 'Migration v6.0-security applied successfully';
  RAISE NOTICE 'Next steps:';
  RAISE NOTICE '  1. Deploy backend with new routes/mfa.js, services/break-glass.js';
  RAISE NOTICE '  2. Set TOTP_ENCRYPTION_KEY in Render env vars';
  RAISE NOTICE '  3. Set BREAK_GLASS_ALLOWED_IPS in Render env vars';
  RAISE NOTICE '  4. Enroll all ADMIN/SUPER_ADMIN users in TOTP MFA';
  RAISE NOTICE '  5. Rotate credentials for all accounts in old _EMERGENCY_ACCOUNTS list';
END $$;
