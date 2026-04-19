-- ══════════════════════════════════════════════════════════════════════
--  ThreatPilot AI — Extended CTI Schema v3.0
--  EXTENDS existing schema — run after schema.sql v2.1
--
--  New tables:
--    threat_actors · campaigns · vulnerabilities
--    mitre_techniques · ioc_relationships · feed_logs
--    ai_sessions · soar_rules · soar_executions
--
--  HOW TO USE:
--    Supabase → SQL Editor → paste → Run
--    Safe to re-run (all IF NOT EXISTS)
-- ══════════════════════════════════════════════════════════════════════

-- ────────────────────────────────────────────────
-- EXTEND existing iocs table with CTI fields
-- (ALTER TABLE is safe — adds only if column missing)
-- ────────────────────────────────────────────────
DO $$ BEGIN
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS confidence      INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100);
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS tlp             TEXT DEFAULT 'WHITE' CHECK (tlp IN ('WHITE','GREEN','AMBER','RED'));
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS kill_chain_phase TEXT;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS campaign_id     UUID;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS actor_id        UUID;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS feed_source     TEXT;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS external_id     TEXT;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS malware_family  TEXT;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS ttl_days        INTEGER DEFAULT 90;
  ALTER TABLE public.iocs ADD COLUMN IF NOT EXISTS expired_at      TIMESTAMPTZ;
  RAISE NOTICE 'iocs table extended';
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'iocs extend skipped: %', SQLERRM;
END $$;

-- ────────────────────────────────────────────────
-- 1. THREAT ACTORS
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.threat_actors (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  aliases         TEXT[] DEFAULT '{}',
  description     TEXT,
  motivation      TEXT CHECK (motivation IN (
    'financial','espionage','hacktivism','sabotage','unknown','ransomware'
  )),
  sophistication  TEXT DEFAULT 'medium' CHECK (sophistication IN (
    'minimal','novice','intermediate','advanced','expert','innovator'
  )),
  origin_country  TEXT,
  active_since    DATE,
  last_seen       TIMESTAMPTZ,
  target_sectors  TEXT[] DEFAULT '{}',
  target_countries TEXT[] DEFAULT '{}',
  ttps            TEXT[] DEFAULT '{}',  -- MITRE technique IDs
  tools           TEXT[] DEFAULT '{}',
  malware         TEXT[] DEFAULT '{}',
  source          TEXT DEFAULT 'manual',
  external_id     TEXT,                 -- e.g. MITRE G0001
  confidence      INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  tags            TEXT[] DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_actors_tenant ON public.threat_actors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_actors_name   ON public.threat_actors USING gin(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_actors_ttps   ON public.threat_actors USING gin(ttps);

-- ────────────────────────────────────────────────
-- 2. CAMPAIGNS
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.campaigns (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','historical','suspected')),
  actor_id        UUID REFERENCES public.threat_actors(id),
  start_date      DATE,
  end_date        DATE,
  target_sectors  TEXT[] DEFAULT '{}',
  target_countries TEXT[] DEFAULT '{}',
  ioc_count       INTEGER DEFAULT 0,
  ttps            TEXT[] DEFAULT '{}',
  malware         TEXT[] DEFAULT '{}',
  tags            TEXT[] DEFAULT '{}',
  external_id     TEXT,
  confidence      INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  source          TEXT DEFAULT 'manual',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON public.campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_actor  ON public.campaigns(actor_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON public.campaigns(status);

-- ────────────────────────────────────────────────
-- 3. VULNERABILITIES (CVE data from NVD)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.vulnerabilities (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id),
  cve_id          TEXT NOT NULL UNIQUE,
  title           TEXT,
  description     TEXT,
  cvss_v3_score   NUMERIC(4,1),
  cvss_v2_score   NUMERIC(4,1),
  cvss_v3_vector  TEXT,
  severity        TEXT CHECK (severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),
  cwe_ids         TEXT[] DEFAULT '{}',
  affected_products JSONB DEFAULT '[]',
  references      TEXT[] DEFAULT '{}',
  exploited_in_wild BOOLEAN DEFAULT false,
  exploit_available BOOLEAN DEFAULT false,
  patch_available   BOOLEAN DEFAULT false,
  epss_score        NUMERIC(6,4),      -- Exploit Prediction Scoring System
  kev_listed        BOOLEAN DEFAULT false, -- CISA Known Exploited Vulnerabilities
  published_at    TIMESTAMPTZ,
  modified_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vulns_cve    ON public.vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cvss   ON public.vulnerabilities(cvss_v3_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_kev    ON public.vulnerabilities(kev_listed) WHERE kev_listed = true;
CREATE INDEX IF NOT EXISTS idx_vulns_tenant ON public.vulnerabilities(tenant_id);

-- ────────────────────────────────────────────────
-- 4. MITRE ATT&CK TECHNIQUES
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mitre_techniques (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  technique_id    TEXT NOT NULL UNIQUE,    -- e.g. T1071.001
  name            TEXT NOT NULL,
  tactic          TEXT NOT NULL,           -- e.g. command-and-control
  description     TEXT,
  platforms       TEXT[] DEFAULT '{}',    -- Windows, Linux, macOS, Cloud
  data_sources    TEXT[] DEFAULT '{}',
  detection       TEXT,
  mitigations     TEXT[] DEFAULT '{}',
  sub_techniques  TEXT[] DEFAULT '{}',
  parent_id       TEXT,
  url             TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mitre_tech_id  ON public.mitre_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic   ON public.mitre_techniques(tactic);
CREATE INDEX IF NOT EXISTS idx_mitre_name     ON public.mitre_techniques USING gin(name gin_trgm_ops);

-- ────────────────────────────────────────────────
-- 5. IOC RELATIONSHIPS (graph links)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.ioc_relationships (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  -- Source node
  source_type     TEXT NOT NULL CHECK (source_type IN (
    'ioc','alert','case','campaign','actor','vulnerability','malware'
  )),
  source_id       TEXT NOT NULL,
  source_value    TEXT,
  -- Target node
  target_type     TEXT NOT NULL CHECK (target_type IN (
    'ioc','alert','case','campaign','actor','vulnerability','malware','technique'
  )),
  target_id       TEXT NOT NULL,
  target_value    TEXT,
  -- Relationship metadata
  relationship    TEXT NOT NULL CHECK (relationship IN (
    'resolves_to','communicates_with','downloads','drops','uses',
    'attributed_to','targets','exploits','related_to','part_of',
    'hosted_on','redirects_to','command_and_control'
  )),
  confidence      INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  source          TEXT DEFAULT 'manual',
  first_seen      TIMESTAMPTZ DEFAULT NOW(),
  last_seen       TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, source_type, source_id, target_type, target_id, relationship)
);
CREATE INDEX IF NOT EXISTS idx_rel_tenant  ON public.ioc_relationships(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rel_source  ON public.ioc_relationships(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_rel_target  ON public.ioc_relationships(target_type, target_id);

-- ────────────────────────────────────────────────
-- 6. FEED LOGS (ingestion audit trail)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.feed_logs (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  feed_name       TEXT NOT NULL,
  feed_type       TEXT NOT NULL CHECK (feed_type IN (
    'otx','abuseipdb','virustotal','shodan','urlhaus',
    'threatfox','circl','nvd','manual','greynoise'
  )),
  tenant_id       UUID REFERENCES public.tenants(id),
  status          TEXT NOT NULL CHECK (status IN ('running','success','partial','error')),
  started_at      TIMESTAMPTZ DEFAULT NOW(),
  finished_at     TIMESTAMPTZ,
  duration_ms     INTEGER,
  iocs_fetched    INTEGER DEFAULT 0,
  iocs_new        INTEGER DEFAULT 0,
  iocs_updated    INTEGER DEFAULT 0,
  iocs_duplicate  INTEGER DEFAULT 0,
  errors_count    INTEGER DEFAULT 0,
  error_message   TEXT,
  metadata        JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_feed_logs_name    ON public.feed_logs(feed_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_logs_status  ON public.feed_logs(status);
CREATE INDEX IF NOT EXISTS idx_feed_logs_tenant  ON public.feed_logs(tenant_id);

-- ────────────────────────────────────────────────
-- 7. AI ORCHESTRATOR SESSIONS
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.ai_sessions (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id),
  user_id         UUID REFERENCES public.users(id),
  session_type    TEXT DEFAULT 'chat' CHECK (session_type IN ('chat','analysis','hunt','report')),
  messages        JSONB[] DEFAULT '{}',
  tools_used      TEXT[] DEFAULT '{}',
  context         JSONB DEFAULT '{}',
  total_tokens    INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'active' CHECK (status IN ('active','completed','error')),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_tenant ON public.ai_sessions(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_user   ON public.ai_sessions(user_id);

-- ────────────────────────────────────────────────
-- 8. SOAR RULES (automation rules)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.soar_rules (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  enabled         BOOLEAN DEFAULT true,
  trigger_type    TEXT NOT NULL CHECK (trigger_type IN (
    'new_ioc','high_risk_ioc','new_alert','alert_severity',
    'feed_ingestion','manual','schedule'
  )),
  conditions      JSONB NOT NULL DEFAULT '{}',  -- e.g. { "risk_score": { "gte": 80 } }
  actions         JSONB[] DEFAULT '{}',          -- e.g. [{ "type": "create_alert", "params": {...} }]
  priority        INTEGER DEFAULT 50,
  execution_count INTEGER DEFAULT 0,
  last_executed   TIMESTAMPTZ,
  created_by      UUID REFERENCES public.users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soar_rules_tenant  ON public.soar_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_soar_rules_trigger ON public.soar_rules(trigger_type);
CREATE INDEX IF NOT EXISTS idx_soar_rules_enabled ON public.soar_rules(enabled) WHERE enabled = true;

-- ────────────────────────────────────────────────
-- 9. SOAR EXECUTION LOG
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.soar_executions (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  rule_id         UUID REFERENCES public.soar_rules(id),
  tenant_id       UUID REFERENCES public.tenants(id),
  trigger_entity  TEXT,             -- ID of the IOC/alert that triggered this
  trigger_type    TEXT,
  actions_taken   JSONB[] DEFAULT '{}',
  success         BOOLEAN DEFAULT true,
  error_message   TEXT,
  duration_ms     INTEGER,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soar_exec_rule   ON public.soar_executions(rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_exec_tenant ON public.soar_executions(tenant_id, created_at DESC);

-- ────────────────────────────────────────────────
-- 10. DETECTION TIMELINE (real-time events)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.detection_timeline (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL CHECK (event_type IN (
    'ioc_detected','ioc_enriched','alert_created','alert_escalated',
    'case_opened','feed_pulled','soar_triggered','ai_query',
    'threat_actor_linked','campaign_detected','cve_matched'
  )),
  title           TEXT NOT NULL,
  description     TEXT,
  severity        TEXT DEFAULT 'INFO' CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  entity_type     TEXT,
  entity_id       TEXT,
  entity_value    TEXT,
  source          TEXT DEFAULT 'system',
  metadata        JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_timeline_tenant  ON public.detection_timeline(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_type    ON public.detection_timeline(event_type);
CREATE INDEX IF NOT EXISTS idx_timeline_sev     ON public.detection_timeline(severity);

-- ────────────────────────────────────────────────
-- 11. MITRE COVERAGE MAP (per tenant)
-- ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.mitre_coverage (
  id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  tenant_id       UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
  technique_id    TEXT NOT NULL REFERENCES public.mitre_techniques(technique_id) ON DELETE CASCADE,
  coverage_level  TEXT DEFAULT 'none' CHECK (coverage_level IN (
    'none','partial','full','tested'
  )),
  detection_count INTEGER DEFAULT 0,
  last_detected   TIMESTAMPTZ,
  notes           TEXT,
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_mitre_cov_tenant ON public.mitre_coverage(tenant_id);

-- ────────────────────────────────────────────────
-- EXTEND feed_logs + enable RLS
-- ────────────────────────────────────────────────
ALTER TABLE public.threat_actors      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.campaigns          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ioc_relationships  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feed_logs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_sessions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_rules         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soar_executions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.detection_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mitre_coverage     ENABLE ROW LEVEL SECURITY;

-- RLS policies (tenant isolation)
DO $$ BEGIN
  DROP POLICY IF EXISTS actors_isolation    ON public.threat_actors;
  DROP POLICY IF EXISTS campaigns_isolation ON public.campaigns;
  DROP POLICY IF EXISTS vulns_isolation     ON public.vulnerabilities;
  DROP POLICY IF EXISTS rel_isolation       ON public.ioc_relationships;
  DROP POLICY IF EXISTS feedlogs_isolation  ON public.feed_logs;
  DROP POLICY IF EXISTS ai_isolation        ON public.ai_sessions;
  DROP POLICY IF EXISTS soar_isolation      ON public.soar_rules;
  DROP POLICY IF EXISTS soarex_isolation    ON public.soar_executions;
  DROP POLICY IF EXISTS timeline_isolation  ON public.detection_timeline;
  DROP POLICY IF EXISTS mitrecov_isolation  ON public.mitre_coverage;
END $$;

CREATE POLICY actors_isolation    ON public.threat_actors
  USING (tenant_id IS NULL OR tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY campaigns_isolation ON public.campaigns
  USING (tenant_id IS NULL OR tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY vulns_isolation     ON public.vulnerabilities
  USING (tenant_id IS NULL OR tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY rel_isolation       ON public.ioc_relationships
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY feedlogs_isolation  ON public.feed_logs
  USING (tenant_id IS NULL OR tenant_id = public.get_tenant_id() OR public.get_user_role() IN ('ADMIN','SUPER_ADMIN'));
CREATE POLICY ai_isolation        ON public.ai_sessions
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY soar_isolation      ON public.soar_rules
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY soarex_isolation    ON public.soar_executions
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY timeline_isolation  ON public.detection_timeline
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');
CREATE POLICY mitrecov_isolation  ON public.mitre_coverage
  USING (tenant_id = public.get_tenant_id() OR public.get_user_role() = 'SUPER_ADMIN');

-- Auto-update triggers for new tables
DO $$ BEGIN
  CREATE TRIGGER upd_actors    BEFORE UPDATE ON public.threat_actors    FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
  CREATE TRIGGER upd_campaigns BEFORE UPDATE ON public.campaigns         FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
  CREATE TRIGGER upd_vulns     BEFORE UPDATE ON public.vulnerabilities   FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
  CREATE TRIGGER upd_mitre     BEFORE UPDATE ON public.mitre_techniques  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
  CREATE TRIGGER upd_soar      BEFORE UPDATE ON public.soar_rules        FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
  CREATE TRIGGER upd_ai        BEFORE UPDATE ON public.ai_sessions       FOR EACH ROW EXECUTE FUNCTION handle_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ────────────────────────────────────────────────
-- SEED: MITRE ATT&CK Core Techniques (subset)
-- Full dataset loaded by ingestion worker
-- ────────────────────────────────────────────────
INSERT INTO public.mitre_techniques (technique_id, name, tactic, description, platforms, url)
VALUES
  ('T1071',     'Application Layer Protocol',      'command-and-control', 'Adversaries may communicate using application layer protocols', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1071'),
  ('T1071.001', 'Web Protocols',                   'command-and-control', 'HTTP/HTTPS for C2 communications', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1071/001'),
  ('T1059',     'Command and Scripting Interpreter','execution',          'Adversaries may abuse command interpreters', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1059'),
  ('T1059.001', 'PowerShell',                      'execution',          'Adversaries may abuse PowerShell commands and scripts', ARRAY['Windows'], 'https://attack.mitre.org/techniques/T1059/001'),
  ('T1003',     'OS Credential Dumping',            'credential-access',  'Adversaries may attempt to dump credentials', ARRAY['Windows','Linux','macOS'], 'https://attack.mitre.org/techniques/T1003'),
  ('T1003.001', 'LSASS Memory',                    'credential-access',  'Adversaries may attempt to access LSASS memory', ARRAY['Windows'], 'https://attack.mitre.org/techniques/T1003/001'),
  ('T1486',     'Data Encrypted for Impact',       'impact',             'Adversaries may encrypt data on target systems', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1486'),
  ('T1190',     'Exploit Public-Facing Application','initial-access',     'Adversaries may exploit internet-facing applications', ARRAY['Linux','Windows','macOS','Network'], 'https://attack.mitre.org/techniques/T1190'),
  ('T1566',     'Phishing',                        'initial-access',     'Adversaries may send phishing messages', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1566'),
  ('T1566.001', 'Spearphishing Attachment',        'initial-access',     'Adversaries may send emails with malicious attachments', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1566/001'),
  ('T1566.002', 'Spearphishing Link',              'initial-access',     'Adversaries may send emails with malicious links', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1566/002'),
  ('T1550',     'Use Alternate Authentication Material','lateral-movement','Adversaries may use alternate authentication material', ARRAY['Windows','AWS','GCP','Azure','Office 365'], 'https://attack.mitre.org/techniques/T1550'),
  ('T1550.002', 'Pass the Hash',                   'lateral-movement',   'Adversaries may pass the hash to authenticate', ARRAY['Windows'], 'https://attack.mitre.org/techniques/T1550/002'),
  ('T1078',     'Valid Accounts',                  'defense-evasion',    'Adversaries may obtain and abuse credentials', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1078'),
  ('T1027',     'Obfuscated Files or Information', 'defense-evasion',    'Adversaries may obfuscate content of files', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1027'),
  ('T1046',     'Network Service Scanning',        'discovery',          'Adversaries may attempt to get a listing of services', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1046'),
  ('T1110',     'Brute Force',                     'credential-access',  'Adversaries may use brute force techniques', ARRAY['Linux','Windows','macOS','AWS','GCP','Azure'], 'https://attack.mitre.org/techniques/T1110'),
  ('T1055',     'Process Injection',               'privilege-escalation','Adversaries may inject code into processes', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1055'),
  ('T1021',     'Remote Services',                 'lateral-movement',   'Adversaries may use legitimate remote services', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1021'),
  ('T1083',     'File and Directory Discovery',    'discovery',          'Adversaries may enumerate files and directories', ARRAY['Linux','Windows','macOS'], 'https://attack.mitre.org/techniques/T1083')
ON CONFLICT (technique_id) DO NOTHING;

-- SEED: Known Threat Actors
INSERT INTO public.threat_actors (name, aliases, motivation, sophistication, origin_country, target_sectors, ttps, external_id, source, confidence)
VALUES
  ('APT29', ARRAY['Cozy Bear','The Dukes','YTTRIUM','Midnight Blizzard'], 'espionage', 'expert',
   'RU', ARRAY['Government','Think Tanks','Healthcare','Defense'],
   ARRAY['T1071.001','T1566.002','T1078','T1003.001','T1027'],
   'G0016', 'MITRE ATT&CK', 95),
  ('APT28', ARRAY['Fancy Bear','Sofacy','STRONTIUM','Forest Blizzard'], 'espionage', 'expert',
   'RU', ARRAY['Government','Military','Defense','Media'],
   ARRAY['T1059.001','T1566.001','T1550.002','T1078','T1046'],
   'G0007', 'MITRE ATT&CK', 95),
  ('Lazarus Group', ARRAY['HIDDEN COBRA','Zinc','Diamond Sleet'], 'financial', 'advanced',
   'KP', ARRAY['Financial','Cryptocurrency','Defense','Media'],
   ARRAY['T1059','T1486','T1003','T1021'],
   'G0032', 'MITRE ATT&CK', 90),
  ('LockBit', ARRAY['LockBit 3.0','LockBit 4.0'], 'financial', 'advanced',
   'Unknown', ARRAY['Healthcare','Manufacturing','Finance','Legal'],
   ARRAY['T1486','T1490','T1489','T1078','T1021'],
   NULL, 'manual', 85),
  ('Sandworm', ARRAY['Voodoo Bear','IRIDIUM','Seashell Blizzard'], 'sabotage', 'innovator',
   'RU', ARRAY['Energy','Government','Media'],
   ARRAY['T1059','T1486','T1190','T1078'],
   'G0034', 'MITRE ATT&CK', 95)
ON CONFLICT DO NOTHING;

-- Verify
SELECT
  'threat_actors'       AS "table", COUNT(*) AS rows FROM public.threat_actors
UNION ALL SELECT 'mitre_techniques',  COUNT(*) FROM public.mitre_techniques
UNION ALL SELECT 'campaigns',         COUNT(*) FROM public.campaigns
UNION ALL SELECT 'vulnerabilities',   COUNT(*) FROM public.vulnerabilities
UNION ALL SELECT 'ioc_relationships', COUNT(*) FROM public.ioc_relationships
UNION ALL SELECT 'feed_logs',         COUNT(*) FROM public.feed_logs
UNION ALL SELECT 'ai_sessions',       COUNT(*) FROM public.ai_sessions
UNION ALL SELECT 'soar_rules',        COUNT(*) FROM public.soar_rules
UNION ALL SELECT 'detection_timeline',COUNT(*) FROM public.detection_timeline
ORDER BY "table";
