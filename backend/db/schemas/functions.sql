-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — PostgreSQL Stored Functions & Triggers
--  backend/db/schemas/functions.sql
--
--  Contains:
--    - set_updated_at()       trigger to auto-stamp updated_at
--    - refresh_soc_kpi()      wrapper to REFRESH MATERIALIZED VIEW
--    - get_mttd_mttr()        fast tenant MTTD/MTTR calculation
--    - close_alert()          atomic alert close + SLA stamp
--    - prune_expired_iocs()   scheduled expiry cleanup
--    - compute_risk_score()   composite IOC risk scorer
--    - fn_alert_to_cluster()  assign alert → nearest cluster
--
--  Apply: psql $DATABASE_URL -f backend/db/schemas/functions.sql
-- ══════════════════════════════════════════════════════════════════

-- ════════════════════════════════════════════════════════════════
--  TRIGGER: auto-stamp updated_at on every UPDATE
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

-- Apply trigger to all tables with updated_at column
DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOR tbl IN
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND column_name   = 'updated_at'
      AND table_name   != 'schema_migrations'
  LOOP
    EXECUTE format(
      'DROP TRIGGER IF EXISTS trg_set_updated_at ON %I; '
      'CREATE TRIGGER trg_set_updated_at '
      'BEFORE UPDATE ON %I '
      'FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();',
      tbl, tbl
    );
  END LOOP;
END $$;

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: refresh_soc_kpi()
--  Called by Node.js scheduler every 5 minutes
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION refresh_soc_kpi()
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_soc_kpi_snapshot;
END;
$$;

COMMENT ON FUNCTION refresh_soc_kpi() IS
  'Refreshes SOC KPI snapshot materialized view concurrently. '
  'Safe to call while reads are in progress.';

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: get_mttd_mttr(p_tenant_id, p_days)
--  Returns MTTD/MTTR stats for the last N days
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION get_mttd_mttr(
  p_tenant_id UUID,
  p_days      INTEGER DEFAULT 30
)
RETURNS TABLE (
  period_start         TIMESTAMPTZ,
  total_alerts         BIGINT,
  closed_alerts        BIGINT,
  avg_mttd_minutes     NUMERIC,
  median_mttd_minutes  NUMERIC,
  avg_mttr_minutes     NUMERIC,
  median_mttr_minutes  NUMERIC,
  sla_breach_count     BIGINT,
  fpr_pct              NUMERIC
) LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN QUERY
  SELECT
    NOW() - (p_days || ' days')::INTERVAL               AS period_start,
    COUNT(*)                                             AS total_alerts,
    COUNT(*) FILTER (WHERE a.status = 'closed')          AS closed_alerts,
    ROUND(AVG(
      CASE WHEN a.first_touched_at IS NOT NULL
        THEN EXTRACT(EPOCH FROM (a.first_touched_at - a.created_at)) / 60
      END
    )::NUMERIC, 2)                                       AS avg_mttd_minutes,
    ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY
      EXTRACT(EPOCH FROM (a.first_touched_at - a.created_at)) / 60
    ) FILTER (WHERE a.first_touched_at IS NOT NULL)
    ::NUMERIC, 2)                                        AS median_mttd_minutes,
    ROUND(AVG(
      CASE WHEN a.closed_at IS NOT NULL
        THEN EXTRACT(EPOCH FROM (a.closed_at - a.created_at)) / 60
      END
    )::NUMERIC, 2)                                       AS avg_mttr_minutes,
    ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY
      EXTRACT(EPOCH FROM (a.closed_at - a.created_at)) / 60
    ) FILTER (WHERE a.closed_at IS NOT NULL)
    ::NUMERIC, 2)                                        AS median_mttr_minutes,
    COUNT(*) FILTER (
      WHERE a.severity IN ('critical','high')
        AND a.status NOT IN ('closed','false_positive')
        AND NOW() - a.created_at > INTERVAL '24 hours'
    )                                                    AS sla_breach_count,
    ROUND(
      COUNT(*) FILTER (WHERE a.status = 'false_positive')::NUMERIC /
      NULLIF(COUNT(*) FILTER (WHERE a.status IN ('closed','false_positive','true_positive')), 0)
      * 100, 2
    )                                                    AS fpr_pct
  FROM alerts a
  WHERE a.tenant_id  = p_tenant_id
    AND a.created_at > NOW() - (p_days || ' days')::INTERVAL;
END;
$$;

COMMENT ON FUNCTION get_mttd_mttr(UUID, INTEGER) IS
  'Returns MTTD/MTTR KPIs for a tenant over the last N days.';

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: close_alert(p_alert_id, p_user_id, p_outcome, p_notes)
--  Atomically closes an alert and stamps closed_at + outcome
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION close_alert(
  p_alert_id  UUID,
  p_user_id   UUID,
  p_outcome   TEXT DEFAULT 'true_positive',  -- true_positive | false_positive | duplicate
  p_notes     TEXT DEFAULT NULL
)
RETURNS alerts LANGUAGE plpgsql AS $$
DECLARE
  v_alert alerts;
BEGIN
  -- Validate outcome value
  IF p_outcome NOT IN ('true_positive','false_positive','duplicate','informational') THEN
    RAISE EXCEPTION 'Invalid outcome: %. Must be true_positive|false_positive|duplicate|informational', p_outcome;
  END IF;

  UPDATE alerts
  SET
    status     = CASE p_outcome
                   WHEN 'false_positive' THEN 'false_positive'::alert_status
                   ELSE 'closed'::alert_status
                 END,
    closed_at  = NOW(),
    closed_by  = p_user_id,
    resolution_notes = p_notes,
    updated_at = NOW()
  WHERE id = p_alert_id
  RETURNING * INTO v_alert;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert % not found', p_alert_id;
  END IF;

  RETURN v_alert;
END;
$$;

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: prune_expired_iocs()
--  Marks expired IOCs inactive; called by Node.js scheduler
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION prune_expired_iocs()
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE iocs
  SET is_active  = FALSE,
      updated_at = NOW()
  WHERE is_active   = TRUE
    AND expires_at IS NOT NULL
    AND expires_at  < NOW();

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

COMMENT ON FUNCTION prune_expired_iocs() IS
  'Marks IOCs with past expires_at as inactive. Returns count of updated rows.';

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: compute_risk_score(p_ioc_value, p_tenant_id)
--  Composite risk: confidence + predictive score + alert hits
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION compute_risk_score(
  p_ioc_value TEXT,
  p_tenant_id UUID
)
RETURNS NUMERIC LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_confidence     NUMERIC := 50;
  v_pred_score     NUMERIC := 50;
  v_alert_hits     INTEGER := 0;
  v_composite      NUMERIC;
BEGIN
  -- Get IOC confidence
  SELECT COALESCE(confidence, 50)
  INTO v_confidence
  FROM iocs
  WHERE value = p_ioc_value AND tenant_id = p_tenant_id
  LIMIT 1;

  -- Get predictive score (24h horizon)
  SELECT COALESCE(threat_score, 50)
  INTO v_pred_score
  FROM predictive_threat_scores
  WHERE entity_value = p_ioc_value
    AND tenant_id    = p_tenant_id
    AND forecast_horizon = '24h'
  ORDER BY created_at DESC
  LIMIT 1;

  -- Count recent alert hits (last 30 days)
  SELECT COUNT(*)
  INTO v_alert_hits
  FROM alerts
  WHERE tenant_id = p_tenant_id
    AND (source_ip::TEXT = p_ioc_value OR dest_ip::TEXT = p_ioc_value)
    AND created_at > NOW() - INTERVAL '30 days';

  -- Composite: 35% confidence + 45% predictive + 20% alert frequency (capped)
  v_composite := ROUND(
    v_confidence * 0.35 +
    v_pred_score * 0.45 +
    LEAST(v_alert_hits * 5, 100) * 0.20,
    2
  );

  RETURN LEAST(v_composite, 100);
END;
$$;

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: fn_alert_to_cluster(p_alert_id, p_run_id)
--  Assigns an alert to its nearest cluster in a given run
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION fn_alert_to_cluster(
  p_alert_id UUID,
  p_run_id   UUID
)
RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE
  v_cluster_id UUID;
BEGIN
  -- Find the cluster for this run that contains this alert
  SELECT c.id INTO v_cluster_id
  FROM alert_clusters c
  WHERE c.run_id  = p_run_id
    AND p_alert_id = ANY(c.alert_ids)
  LIMIT 1;

  IF v_cluster_id IS NOT NULL THEN
    INSERT INTO alert_cluster_members (alert_id, cluster_id, tenant_id)
    SELECT p_alert_id, v_cluster_id, tenant_id
    FROM alert_clusters WHERE id = v_cluster_id
    ON CONFLICT (alert_id, cluster_id) DO NOTHING;
  END IF;

  RETURN v_cluster_id;
END;
$$;

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: get_tenant_dashboard(p_tenant_id)
--  Single-query dashboard payload
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION get_tenant_dashboard(p_tenant_id UUID)
RETURNS JSONB LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_result JSONB;
BEGIN
  SELECT jsonb_build_object(
    'alerts', jsonb_build_object(
      'total',    COUNT(*),
      'critical', COUNT(*) FILTER (WHERE severity = 'critical'),
      'high',     COUNT(*) FILTER (WHERE severity = 'high'),
      'open',     COUNT(*) FILTER (WHERE status IN ('open','in_progress')),
      'sla_breach', COUNT(*) FILTER (
        WHERE severity IN ('critical','high')
          AND status NOT IN ('closed','false_positive')
          AND NOW() - created_at > INTERVAL '24 hours'
      )
    ),
    'mttd_minutes', ROUND(AVG(
      CASE WHEN first_touched_at IS NOT NULL
        THEN EXTRACT(EPOCH FROM (first_touched_at - created_at)) / 60
      END
    )::NUMERIC, 0),
    'mttr_minutes', ROUND(AVG(
      CASE WHEN closed_at IS NOT NULL
        THEN EXTRACT(EPOCH FROM (closed_at - created_at)) / 60
      END
    )::NUMERIC, 0),
    'fpr_pct', ROUND(
      COUNT(*) FILTER (WHERE status = 'false_positive')::NUMERIC /
      NULLIF(COUNT(*) FILTER (WHERE status != 'open'), 0) * 100, 1
    ),
    'generated_at', NOW()
  )
  INTO v_result
  FROM alerts
  WHERE tenant_id  = p_tenant_id
    AND created_at > NOW() - INTERVAL '7 days';

  RETURN v_result;
END;
$$;

-- ════════════════════════════════════════════════════════════════
--  FUNCTION: log_audit_event(...)
--  Insert into audit_logs from application layer
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION log_audit_event(
  p_tenant_id    UUID,
  p_user_id      UUID,
  p_action       TEXT,
  p_resource     TEXT,
  p_resource_id  TEXT  DEFAULT NULL,
  p_old_data     JSONB DEFAULT NULL,
  p_new_data     JSONB DEFAULT NULL,
  p_ip_address   INET  DEFAULT NULL,
  p_metadata     JSONB DEFAULT '{}'
)
RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE
  v_id UUID;
BEGIN
  INSERT INTO audit_logs (
    tenant_id, user_id, action, resource_type, resource_id,
    old_data, new_data, ip_address, metadata
  ) VALUES (
    p_tenant_id, p_user_id, p_action, p_resource, p_resource_id,
    p_old_data, p_new_data, p_ip_address, p_metadata
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

-- ════════════════════════════════════════════════════════════════
--  TRIGGER: auto-touch first_touched_at when alert is assigned
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION fn_stamp_first_touched()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  -- Set first_touched_at only once (when assigned_to goes from NULL → value)
  IF OLD.assigned_to IS NULL AND NEW.assigned_to IS NOT NULL
     AND OLD.first_touched_at IS NULL THEN
    NEW.first_touched_at := NOW();
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_stamp_first_touched ON alerts;
CREATE TRIGGER trg_stamp_first_touched
  BEFORE UPDATE ON alerts
  FOR EACH ROW EXECUTE FUNCTION fn_stamp_first_touched();

-- ════════════════════════════════════════════════════════════════
--  TRIGGER: invalidate mv_soc_kpi_snapshot on alert change
--  Uses pg_notify so the app layer can schedule a refresh
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION fn_notify_alert_change()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('alert_changed', NEW.tenant_id::TEXT);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_notify_alert_change ON alerts;
CREATE TRIGGER trg_notify_alert_change
  AFTER INSERT OR UPDATE ON alerts
  FOR EACH ROW EXECUTE FUNCTION fn_notify_alert_change();
