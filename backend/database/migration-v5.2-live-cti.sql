-- ══════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — DB Migration v5.2
--  Real-Time CTI Pipeline Schema
--  File: backend/database/migration-v5.2-live-cti.sql
--
--  New tables:
--    news_articles        — ingested cyber threat news
--    ioc_enrichment_queue — async enrichment job queue
--    asset_inventory      — internal assets for exposure correlation
--    exposure_mapping     — IOC ↔ asset correlation results
--    campaigns_v2         — enhanced campaign tracking
--    ingestion_metrics    — per-feed performance metrics
--
--  Altered tables:
--    iocs         — add enriched_at, enrichment_data, kill_chain_phase
--    feed_logs    — add metadata column
--    threat_actors — add attribution_confidence, last_active
--
--  Indexes: GIN for arrays, B-tree for tenant+value, partial for active
-- ══════════════════════════════════════════════════════════════

-- ── Enable required extensions ─────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- GIN on scalars

-- ══════════════════════════════════════════════════════════════
--  1. ALTER TABLE iocs — Add missing columns if not exists
-- ══════════════════════════════════════════════════════════════

DO $$ BEGIN
  -- enrichment tracking
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='enriched_at') THEN
    ALTER TABLE iocs ADD COLUMN enriched_at TIMESTAMPTZ DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='kill_chain_phase') THEN
    ALTER TABLE iocs ADD COLUMN kill_chain_phase TEXT DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='malware_family') THEN
    ALTER TABLE iocs ADD COLUMN malware_family TEXT DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='threat_actor') THEN
    ALTER TABLE iocs ADD COLUMN threat_actor TEXT DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='feed_source') THEN
    ALTER TABLE iocs ADD COLUMN feed_source TEXT DEFAULT 'collector';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='asn') THEN
    ALTER TABLE iocs ADD COLUMN asn TEXT DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='country') THEN
    ALTER TABLE iocs ADD COLUMN country TEXT DEFAULT NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='notes') THEN
    ALTER TABLE iocs ADD COLUMN notes TEXT DEFAULT NULL;
  END IF;

  -- enrichment_data may already exist as JSON — ensure it's JSONB
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='enrichment_data') THEN
    ALTER TABLE iocs ADD COLUMN enrichment_data JSONB DEFAULT '{}';
  END IF;

END $$;

-- ══════════════════════════════════════════════════════════════
--  2. INDEXES on iocs
-- ══════════════════════════════════════════════════════════════

-- Existing unique constraint (tenant_id, value) — skip if exists
CREATE UNIQUE INDEX IF NOT EXISTS iocs_tenant_value_uniq
  ON iocs(tenant_id, value);

-- Partial index: active IOCs only
CREATE INDEX IF NOT EXISTS iocs_active_tenant_idx
  ON iocs(tenant_id, risk_score DESC)
  WHERE status = 'active';

-- Type filter
CREATE INDEX IF NOT EXISTS iocs_type_idx ON iocs(type);

-- Source/feed filter
CREATE INDEX IF NOT EXISTS iocs_feed_source_idx ON iocs(feed_source);

-- GIN index for tags array
CREATE INDEX IF NOT EXISTS iocs_tags_gin_idx ON iocs USING GIN(tags);

-- Enrichment queue (unenriched IOCs)
CREATE INDEX IF NOT EXISTS iocs_enriched_at_idx ON iocs(enriched_at NULLS FIRST)
  WHERE status = 'active';

-- Full-text search on value
CREATE INDEX IF NOT EXISTS iocs_value_trgm_idx ON iocs USING GIN(value gin_trgm_ops);

-- ══════════════════════════════════════════════════════════════
--  3. feed_logs — Add metadata column
-- ══════════════════════════════════════════════════════════════

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feed_logs' AND column_name='metadata') THEN
    ALTER TABLE feed_logs ADD COLUMN metadata JSONB DEFAULT '{}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feed_logs' AND column_name='iocs_duplicate') THEN
    ALTER TABLE feed_logs ADD COLUMN iocs_duplicate INTEGER DEFAULT 0;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feed_logs' AND column_name='errors_count') THEN
    ALTER TABLE feed_logs ADD COLUMN errors_count INTEGER DEFAULT 0;
  END IF;
END $$;

-- ══════════════════════════════════════════════════════════════
--  4. news_articles — Cyber threat news from RSS feeds
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS news_articles (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  title            TEXT NOT NULL,
  url              TEXT NOT NULL,
  source           TEXT NOT NULL,   -- 'The Hacker News', 'BleepingComputer', etc.
  category         TEXT DEFAULT 'security-news',
  summary          TEXT,
  severity         TEXT DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low','info')),

  -- Extracted entities
  cves             TEXT[]  DEFAULT '{}',
  threat_actors    TEXT[]  DEFAULT '{}',
  malware_families TEXT[]  DEFAULT '{}',
  tags             TEXT[]  DEFAULT '{}',

  -- Media
  image_url        TEXT,            -- optional thumbnail/preview image from RSS feed

  -- Metadata
  published_at     TIMESTAMPTZ DEFAULT NOW(),
  external_guid    TEXT,            -- RSS guid / URL for dedup
  raw_html         TEXT,            -- optional full content
  processed        BOOLEAN DEFAULT FALSE,

  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Dedup constraint
ALTER TABLE news_articles
  DROP CONSTRAINT IF EXISTS news_articles_tenant_guid_uniq;
ALTER TABLE news_articles
  ADD CONSTRAINT news_articles_tenant_guid_uniq
  UNIQUE(tenant_id, external_guid);

-- Indexes
CREATE INDEX IF NOT EXISTS news_severity_idx       ON news_articles(severity);
CREATE INDEX IF NOT EXISTS news_published_idx      ON news_articles(published_at DESC);
CREATE INDEX IF NOT EXISTS news_source_idx         ON news_articles(source);
CREATE INDEX IF NOT EXISTS news_cves_gin_idx        ON news_articles USING GIN(cves);
CREATE INDEX IF NOT EXISTS news_actors_gin_idx      ON news_articles USING GIN(threat_actors);
CREATE INDEX IF NOT EXISTS news_malware_gin_idx     ON news_articles USING GIN(malware_families);
CREATE INDEX IF NOT EXISTS news_title_trgm_idx      ON news_articles USING GIN(title gin_trgm_ops);

-- RLS
ALTER TABLE news_articles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS news_tenant_policy ON news_articles;
CREATE POLICY news_tenant_policy ON news_articles
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid
      OR tenant_id = '00000000-0000-0000-0000-000000000001');

-- ══════════════════════════════════════════════════════════════
--  5. ioc_enrichment_queue — Async enrichment job tracking
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ioc_enrichment_queue (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ioc_id      UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  tenant_id   UUID NOT NULL,
  status      TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','done','failed')),
  priority    INTEGER DEFAULT 5,  -- 1=highest, 10=lowest
  attempts    INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  error       TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  started_at  TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS enrichment_queue_status_idx ON ioc_enrichment_queue(status, priority)
  WHERE status IN ('pending','running');
CREATE INDEX IF NOT EXISTS enrichment_queue_ioc_idx ON ioc_enrichment_queue(ioc_id);

-- ══════════════════════════════════════════════════════════════
--  6. asset_inventory — Internal assets for exposure correlation
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS asset_inventory (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id       UUID NOT NULL,
  name            TEXT NOT NULL,
  type            TEXT NOT NULL CHECK (type IN (
    'server','workstation','network_device','cloud_instance',
    'container','iot_device','mobile','service','database','application'
  )),
  ip_address      INET,
  hostname        TEXT,
  os              TEXT,
  os_version      TEXT,
  criticality     TEXT DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
  owner           TEXT,
  department      TEXT,
  location        TEXT,
  cloud_provider  TEXT,
  tags            TEXT[]  DEFAULT '{}',
  open_ports      INTEGER[] DEFAULT '{}',
  services        JSONB DEFAULT '[]',
  last_scan_at    TIMESTAMPTZ,
  status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','decommissioned')),
  metadata        JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS asset_tenant_idx      ON asset_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS asset_ip_idx          ON asset_inventory(ip_address);
CREATE INDEX IF NOT EXISTS asset_criticality_idx ON asset_inventory(criticality);
CREATE INDEX IF NOT EXISTS asset_type_idx        ON asset_inventory(type);
CREATE INDEX IF NOT EXISTS asset_tags_gin_idx    ON asset_inventory USING GIN(tags);

-- RLS
ALTER TABLE asset_inventory ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS asset_tenant_policy ON asset_inventory;
CREATE POLICY asset_tenant_policy ON asset_inventory
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ══════════════════════════════════════════════════════════════
--  7. exposure_mapping — IOC ↔ Asset correlation
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS exposure_mapping (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     UUID NOT NULL,
  ioc_id        UUID REFERENCES iocs(id)            ON DELETE CASCADE,
  asset_id      UUID REFERENCES asset_inventory(id) ON DELETE CASCADE,
  cve_id        TEXT,   -- direct CVE reference (optional)
  match_type    TEXT NOT NULL CHECK (match_type IN (
    'ip_match','domain_match','hash_match','cve_match','port_match','service_match'
  )),
  risk_score    INTEGER DEFAULT 50,
  severity      TEXT    DEFAULT 'medium',
  status        TEXT    DEFAULT 'open' CHECK (status IN ('open','mitigated','accepted','false_positive')),
  first_seen    TIMESTAMPTZ DEFAULT NOW(),
  last_seen     TIMESTAMPTZ DEFAULT NOW(),
  metadata      JSONB DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS exposure_tenant_idx    ON exposure_mapping(tenant_id);
CREATE INDEX IF NOT EXISTS exposure_ioc_idx       ON exposure_mapping(ioc_id);
CREATE INDEX IF NOT EXISTS exposure_asset_idx     ON exposure_mapping(asset_id);
CREATE INDEX IF NOT EXISTS exposure_severity_idx  ON exposure_mapping(severity);
CREATE INDEX IF NOT EXISTS exposure_status_idx    ON exposure_mapping(status);

-- RLS
ALTER TABLE exposure_mapping ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS exposure_tenant_policy ON exposure_mapping;
CREATE POLICY exposure_tenant_policy ON exposure_mapping
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ══════════════════════════════════════════════════════════════
--  8. campaigns_v2 — Enhanced campaign tracking
-- ══════════════════════════════════════════════════════════════

DO $$ BEGIN
  -- Add missing columns to existing campaigns table if it exists
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='campaigns') THEN

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campaigns' AND column_name='mitre_techniques') THEN
      ALTER TABLE campaigns ADD COLUMN mitre_techniques TEXT[] DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campaigns' AND column_name='ioc_count') THEN
      ALTER TABLE campaigns ADD COLUMN ioc_count INTEGER DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campaigns' AND column_name='affected_tenants') THEN
      ALTER TABLE campaigns ADD COLUMN affected_tenants TEXT[] DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campaigns' AND column_name='timeline') THEN
      ALTER TABLE campaigns ADD COLUMN timeline JSONB DEFAULT '[]';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campaigns' AND column_name='related_cases') THEN
      ALTER TABLE campaigns ADD COLUMN related_cases UUID[] DEFAULT '{}';
    END IF;

  ELSE
    -- Create fresh if missing
    CREATE TABLE campaigns (
      id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      tenant_id        UUID NOT NULL,
      name             TEXT NOT NULL,
      description      TEXT,
      actor            TEXT,
      severity         TEXT DEFAULT 'medium',
      status           TEXT DEFAULT 'active',
      start_date       TIMESTAMPTZ,
      end_date         TIMESTAMPTZ,
      findings_count   INTEGER DEFAULT 0,
      ioc_count        INTEGER DEFAULT 0,
      mitre_techniques TEXT[]  DEFAULT '{}',
      affected_tenants TEXT[]  DEFAULT '{}',
      timeline         JSONB DEFAULT '[]',
      related_cases    UUID[]  DEFAULT '{}',
      tags             TEXT[]  DEFAULT '{}',
      metadata         JSONB DEFAULT '{}',
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS campaigns_tenant_idx   ON campaigns(tenant_id);
CREATE INDEX IF NOT EXISTS campaigns_severity_idx ON campaigns(severity);
CREATE INDEX IF NOT EXISTS campaigns_status_idx   ON campaigns(status);
CREATE INDEX IF NOT EXISTS campaigns_actor_idx    ON campaigns(actor);

-- ══════════════════════════════════════════════════════════════
--  9. ingestion_metrics — Per-feed performance tracking
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ingestion_metrics (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  feed_name     TEXT NOT NULL,
  feed_type     TEXT NOT NULL,
  date          DATE NOT NULL DEFAULT CURRENT_DATE,
  total_runs    INTEGER DEFAULT 0,
  success_runs  INTEGER DEFAULT 0,
  failed_runs   INTEGER DEFAULT 0,
  iocs_ingested INTEGER DEFAULT 0,
  iocs_new      INTEGER DEFAULT 0,
  avg_duration_ms INTEGER DEFAULT 0,
  last_run_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ingestion_metrics_uniq
  ON ingestion_metrics(tenant_id, feed_name, date);

-- ══════════════════════════════════════════════════════════════
--  10. Seed asset inventory with demo data for testing
-- ══════════════════════════════════════════════════════════════

INSERT INTO asset_inventory (id, tenant_id, name, type, ip_address, hostname, os, criticality, department, open_ports, services, status)
VALUES
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'DC-01', 'server', '10.0.1.10', 'dc01.corp.local', 'Windows Server 2022', 'critical', 'IT Infrastructure', ARRAY[53,88,389,636,3268,3389], '[{"port":3389,"service":"RDP"},{"port":389,"service":"LDAP"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'WEB-01', 'server', '10.0.1.20', 'web01.corp.local', 'Ubuntu 22.04', 'high', 'Engineering', ARRAY[80,443,22,8080], '[{"port":443,"service":"HTTPS"},{"port":22,"service":"SSH"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'DB-PROD-01', 'database', '10.0.1.30', 'dbprod01.corp.local', 'PostgreSQL 16 on Linux', 'critical', 'Engineering', ARRAY[5432,22], '[{"port":5432,"service":"PostgreSQL"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'FW-EDGE-01', 'network_device', '203.0.113.1', 'fw01.corp.local', 'Palo Alto PAN-OS 11', 'critical', 'Network', ARRAY[443,22], '[{"port":443,"service":"Admin Console"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'APP-SERVER-02', 'server', '10.0.2.15', 'app02.corp.local', 'Windows Server 2019', 'high', 'Finance', ARRAY[80,443,3389,445], '[{"port":445,"service":"SMB"},{"port":3389,"service":"RDP"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'K8S-NODE-01', 'cloud_instance', '10.0.3.10', 'k8s-node-01', 'Ubuntu 22.04 (EKS)', 'high', 'DevOps', ARRAY[22,6443,10250], '[{"port":6443,"service":"Kubernetes API"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'VPN-GW-01', 'network_device', '203.0.113.10', 'vpn01.corp.local', 'Cisco AnyConnect', 'critical', 'IT Infrastructure', ARRAY[443,1194,4500], '[{"port":443,"service":"SSL-VPN"}]'::jsonb, 'active'),
  (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001', 'WORKSTATION-CFO', 'workstation', '10.0.4.50', 'ws-cfo.corp.local', 'Windows 11 Pro', 'critical', 'Executive', ARRAY[3389], '[{"port":3389,"service":"RDP"}]'::jsonb, 'active')
ON CONFLICT DO NOTHING;

-- ══════════════════════════════════════════════════════════════
--  11. Exposure Assessment view
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW exposure_summary_view AS
SELECT
  em.tenant_id,
  COUNT(DISTINCT em.id)        AS total_exposures,
  COUNT(DISTINCT em.asset_id)  AS affected_assets,
  COUNT(DISTINCT em.ioc_id)    AS matched_iocs,
  SUM(CASE WHEN em.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
  SUM(CASE WHEN em.severity = 'high'     THEN 1 ELSE 0 END) AS high_count,
  SUM(CASE WHEN em.severity = 'medium'   THEN 1 ELSE 0 END) AS medium_count,
  SUM(CASE WHEN em.severity = 'low'      THEN 1 ELSE 0 END) AS low_count,
  LEAST(100, GREATEST(0,
    SUM(CASE WHEN em.severity = 'critical' THEN 25 WHEN em.severity = 'high' THEN 10
             WHEN em.severity = 'medium' THEN 3 ELSE 1 END)
  )) AS risk_score
FROM exposure_mapping em
WHERE em.status = 'open'
GROUP BY em.tenant_id;

-- ══════════════════════════════════════════════════════════════
--  12. IOC statistics view (for dashboard KPIs)
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW ioc_stats_view AS
SELECT
  tenant_id,
  COUNT(*)                                                      AS total_iocs,
  SUM(CASE WHEN reputation = 'malicious'  THEN 1 ELSE 0 END)  AS malicious_count,
  SUM(CASE WHEN reputation = 'suspicious' THEN 1 ELSE 0 END)  AS suspicious_count,
  SUM(CASE WHEN reputation = 'clean'      THEN 1 ELSE 0 END)  AS clean_count,
  SUM(CASE WHEN type = 'ip'               THEN 1 ELSE 0 END)  AS ip_count,
  SUM(CASE WHEN type = 'domain'           THEN 1 ELSE 0 END)  AS domain_count,
  SUM(CASE WHEN type = 'url'              THEN 1 ELSE 0 END)  AS url_count,
  SUM(CASE WHEN type LIKE 'hash%'         THEN 1 ELSE 0 END)  AS hash_count,
  AVG(risk_score)                                               AS avg_risk_score,
  MAX(last_seen)                                                AS latest_ioc_at
FROM iocs
WHERE status = 'active'
GROUP BY tenant_id;

-- ══════════════════════════════════════════════════════════════
--  13. news_articles — Grant Supabase service role access
-- ══════════════════════════════════════════════════════════════

GRANT ALL ON news_articles     TO service_role;
GRANT ALL ON asset_inventory   TO service_role;
GRANT ALL ON exposure_mapping  TO service_role;
GRANT ALL ON ingestion_metrics TO service_role;
GRANT ALL ON ioc_enrichment_queue TO service_role;

GRANT SELECT ON news_articles  TO anon, authenticated;
GRANT SELECT ON asset_inventory TO authenticated;
GRANT SELECT ON exposure_mapping TO authenticated;

-- Also grant access to views
GRANT SELECT ON exposure_summary_view TO anon, authenticated, service_role;
GRANT SELECT ON ioc_stats_view        TO anon, authenticated, service_role;

-- ══════════════════════════════════════════════════════════════
--  END OF MIGRATION v5.2
-- ══════════════════════════════════════════════════════════════
SELECT 'Migration v5.2 applied successfully' AS status;
