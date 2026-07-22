-- ═══════════════════════════════════════════════════════════════════════════
--  Wadjet-Eye Phase 3 Migration
--  we_phase3_threatintel_compliance.sql
--
--  Domains:
--    A) Compliance Evidence  — append-only hash-chain table
--       (ports AiSOC aisoc_compliance_evidence + _compute_hash logic)
--    B) Threat Intelligence  — IOC catalog + poll-log
--       (replaces AiSOC Redis + OpenSearch + Qdrant with pure Postgres)
--
--  Naming conventions: we_*, idx_we_*, fn_we_*, trg_we_*
--  All tables: CREATE TABLE IF NOT EXISTS; all indexes: CREATE INDEX IF NOT EXISTS
-- ═══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────────
--  SECTION A — Compliance Evidence
-- ─────────────────────────────────────────────────────────────────────────────

-- A.1  Main evidence table (one row per evidence item, append-only enforced)
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_compliance_evidence (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,

    -- Relationship to WE case (optional — set on case closure trigger)
    case_id         UUID        REFERENCES cases(id) ON DELETE SET NULL,

    -- Framework / control metadata (ported from AiSOC compliance.py FRAMEWORKS dict)
    framework       TEXT        NOT NULL CHECK (framework <> ''),
    control_id      TEXT        NOT NULL CHECK (control_id <> ''),
    control_title   TEXT,

    -- Evidence details
    evidence_kind   TEXT        NOT NULL DEFAULT 'alert'
                                CHECK (evidence_kind IN
                                    ('alert','log','screenshot','attestation',
                                     'policy','runbook','case_closure','other')),
    summary         TEXT        NOT NULL CHECK (length(summary) >= 5),
    raw_payload     JSONB       NOT NULL DEFAULT '{}',

    -- Hash chain (ported from AiSOC _compute_hash):
    --   payload_hash = SHA-256( (prev_hash||'') || summary || json_agg(raw_payload, sort_keys) )
    payload_hash    TEXT        NOT NULL,          -- SHA-256 hex (64 chars)
    prev_hash       TEXT,                          -- NULL for the first record per tenant+framework

    -- Review workflow
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','accepted','rejected')),
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,

    -- Audit
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_we_compliance_tenant_fw
    ON public.we_compliance_evidence (tenant_id, framework);
CREATE INDEX IF NOT EXISTS idx_we_compliance_tenant_case
    ON public.we_compliance_evidence (tenant_id, case_id)
    WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_we_compliance_collected
    ON public.we_compliance_evidence (collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_we_compliance_status
    ON public.we_compliance_evidence (tenant_id, status);

-- A.2  Append-only trigger — no updates or deletes allowed after insert
--      (same semantics as we_investigation_events immutability trigger)
-- ────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_we_compliance_evidence_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        '[Phase3] we_compliance_evidence is append-only. '
        'Attempted % on row id=%. '
        'To correct an error, insert a new evidence item.',
        TG_OP, OLD.id
    USING ERRCODE = 'restrict_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_we_compliance_evidence_immutable
    ON public.we_compliance_evidence;

CREATE TRIGGER trg_we_compliance_evidence_immutable
    BEFORE UPDATE OR DELETE ON public.we_compliance_evidence
    FOR EACH ROW EXECUTE FUNCTION fn_we_compliance_evidence_immutable();

-- A.3  Helper view: latest hash per (tenant, framework) for hash-chain linking
-- ────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW public.we_compliance_chain_head AS
SELECT DISTINCT ON (tenant_id, framework)
    tenant_id,
    framework,
    id            AS head_id,
    payload_hash  AS head_hash,
    collected_at  AS head_collected_at
FROM public.we_compliance_evidence
ORDER BY tenant_id, framework, collected_at DESC;

-- ─────────────────────────────────────────────────────────────────────────────
--  SECTION B — Threat Intelligence IOC Catalog
-- ─────────────────────────────────────────────────────────────────────────────

-- B.1  IOC catalog — normalised across all feed sources
--      Replaces AiSOC's Redis Bloom + OpenSearch storage with Postgres.
--      Dedup key = (source_ref) — one row per unique indicator-source pair.
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_ioc_catalog (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,       -- NULL = global/shared across all tenants

    -- IOC identity
    ioc_type        TEXT        NOT NULL
                                CHECK (ioc_type IN (
                                    'ip','domain','url','file_hash','email',
                                    'vulnerability','username','asn','cidr',
                                    'mutex','registry_key','other')),
    ioc_value       TEXT        NOT NULL CHECK (ioc_value <> ''),

    -- Feed provenance
    source          TEXT        NOT NULL CHECK (source IN
                                    ('cisa-kev','otx','misp','taxii','manual','other')),
    source_ref      TEXT        NOT NULL UNIQUE,  -- e.g. "cisa-kev:CVE-2024-1234"

    -- Enrichment fields (ported from CisaKevClient.to_ioc() + OTX normaliser)
    description     TEXT,
    vendor_project  TEXT,
    product         TEXT,
    required_action TEXT,
    due_date        TEXT,
    date_added      TEXT,
    known_ransomware TEXT,
    tlp             TEXT        NOT NULL DEFAULT 'white'
                                CHECK (tlp IN ('white','green','amber','red')),
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    confidence      SMALLINT    NOT NULL DEFAULT 50
                                CHECK (confidence BETWEEN 0 AND 100),

    -- Lifecycle
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,          -- NULL = no expiry

    -- Raw payload preserved for replay / re-enrichment
    raw_payload     JSONB       NOT NULL DEFAULT '{}'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_we_ioc_value
    ON public.we_ioc_catalog (ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_we_ioc_source
    ON public.we_ioc_catalog (source, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_we_ioc_active
    ON public.we_ioc_catalog (is_active, ioc_type)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_we_ioc_tags
    ON public.we_ioc_catalog USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_we_ioc_tenant
    ON public.we_ioc_catalog (tenant_id)
    WHERE tenant_id IS NOT NULL;
-- Full-text search over value + description
CREATE INDEX IF NOT EXISTS idx_we_ioc_fts
    ON public.we_ioc_catalog
    USING GIN (to_tsvector('english',
        coalesce(ioc_value,'') || ' ' || coalesce(description,'')));

-- B.2  Poll log — one row per feed-poll attempt
--      Gives operators visibility into feed health and last-seen timestamps
--      without querying the IOC catalog.
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_ti_poll_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_name       TEXT        NOT NULL,    -- 'cisa-kev', 'otx', 'misp', 'taxii:...'
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          TEXT        NOT NULL DEFAULT 'running'
                                CHECK (status IN ('running','success','error','skipped')),
    iocs_fetched    INT         NOT NULL DEFAULT 0,
    iocs_new        INT         NOT NULL DEFAULT 0,
    iocs_updated    INT         NOT NULL DEFAULT 0,
    iocs_skipped    INT         NOT NULL DEFAULT 0,
    error_message   TEXT,
    metadata        JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_we_ti_poll_feed
    ON public.we_ti_poll_log (feed_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_we_ti_poll_status
    ON public.we_ti_poll_log (status, started_at DESC);

-- B.3  IOC-alert enrichment cross-reference
--      Records when a newly-inserted alert matches a known IOC.
--      Written by the alert-insert path when TI enrichment is enabled.
-- ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.we_ioc_alert_hits (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    alert_id    UUID        REFERENCES alerts(id)  ON DELETE CASCADE,
    ioc_id      UUID        REFERENCES we_ioc_catalog(id) ON DELETE CASCADE,
    match_field TEXT        NOT NULL,   -- which alert field triggered: 'src_ip','file_hash',etc.
    match_value TEXT        NOT NULL,
    matched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (alert_id, ioc_id, match_field)
);

CREATE INDEX IF NOT EXISTS idx_we_ioc_hits_tenant
    ON public.we_ioc_alert_hits (tenant_id, matched_at DESC);
CREATE INDEX IF NOT EXISTS idx_we_ioc_hits_alert
    ON public.we_ioc_alert_hits (alert_id);

-- ─────────────────────────────────────────────────────────────────────────────
--  SECTION C — ALTER alerts: add TI-enrichment column
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS we_ti_enrichments  JSONB    DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS we_ti_hit_count    INT      DEFAULT 0;

-- ─────────────────────────────────────────────────────────────────────────────
--  SECTION D — GC function for expired IOCs
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_we_ti_gc()
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    -- Mark expired IOCs inactive (soft-delete to preserve history)
    UPDATE public.we_ioc_catalog
    SET    is_active = FALSE
    WHERE  expires_at IS NOT NULL
      AND  expires_at < NOW()
      AND  is_active  = TRUE;

    -- Clean up poll log entries older than 90 days
    DELETE FROM public.we_ti_poll_log
    WHERE  finished_at < NOW() - INTERVAL '90 days';
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Supabase Realtime publications
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    -- compliance evidence (for live evidence-trail UI)
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime'
          AND tablename = 'we_compliance_evidence'
    ) THEN
        ALTER PUBLICATION supabase_realtime ADD TABLE public.we_compliance_evidence;
    END IF;
EXCEPTION WHEN others THEN
    NULL; -- publication may not exist in local dev
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
--  Smoke test
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY[
        'we_compliance_evidence',
        'we_ioc_catalog',
        'we_ti_poll_log',
        'we_ioc_alert_hits'
    ]) LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_tables
            WHERE tablename = t AND schemaname = 'public'
        ) THEN
            RAISE EXCEPTION '[Phase3 Migration] Table % was not created', t;
        END IF;
    END LOOP;
    RAISE NOTICE '[Phase3 Migration] ✅ All tables created successfully';
END $$;
