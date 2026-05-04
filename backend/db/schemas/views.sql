-- ══════════════════════════════════════════════════════════════════
--  Wadjet-Eye AI — PostgreSQL Views & Materialized Views
--  backend/db/schemas/views.sql
--
--  Performance-optimised views for dashboard, SOC metrics, and
--  reporting queries. Replaces expensive ad-hoc JOINs in API layer.
--
--  Apply: psql $DATABASE_URL -f backend/db/schemas/views.sql
-- ══════════════════════════════════════════════════════════════════

-- ════════════════════════════════════════════════════════════════
--  ALERT SUMMARY VIEW
--  Used by: dashboard, SOC metrics, MTTD/MTTR calculations
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_alert_summary AS
SELECT
  a.id,
  a.tenant_id,
  a.title,
  a.severity,
  a.status,
  a.source,
  a.source_ip,
  a.dest_ip,
  a.mitre_techniques,
  a.created_at,
  a.updated_at,
  a.closed_at,
  a.assigned_to,
  u.full_name          AS assigned_to_name,
  -- MTTD: minutes from alert creation to first analyst touch
  EXTRACT(EPOCH FROM (a.first_touched_at - a.created_at)) / 60
                       AS mttd_minutes,
  -- MTTR: minutes from creation to close
  CASE WHEN a.closed_at IS NOT NULL
    THEN EXTRACT(EPOCH FROM (a.closed_at - a.created_at)) / 60
  END                  AS mttr_minutes,
  -- SLA breach flag (24h = 1440 min for critical/high)
  CASE
    WHEN a.severity IN ('critical', 'high')
      AND a.status NOT IN ('closed', 'false_positive')
      AND NOW() - a.created_at > INTERVAL '24 hours'
    THEN TRUE
    WHEN a.severity IN ('medium')
      AND a.status NOT IN ('closed', 'false_positive')
      AND NOW() - a.created_at > INTERVAL '72 hours'
    THEN TRUE
    ELSE FALSE
  END                  AS sla_breached,
  ac.cluster_label,
  ac.run_id            AS cluster_run_id
FROM alerts a
LEFT JOIN users u              ON u.id  = a.assigned_to
LEFT JOIN alert_cluster_members acm ON acm.alert_id = a.id
LEFT JOIN alert_clusters ac        ON ac.id = acm.cluster_id;

COMMENT ON VIEW v_alert_summary IS
  'Enriched alert view with MTTD/MTTR, SLA breach flag, '
  'analyst name, and cluster membership.';

-- ════════════════════════════════════════════════════════════════
--  MATERIALIZED VIEW: SOC KPI SNAPSHOT
--  Refreshed every 5 minutes by the scheduler
-- ════════════════════════════════════════════════════════════════
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_soc_kpi_snapshot AS
SELECT
  tenant_id,
  DATE_TRUNC('hour', created_at)            AS hour_bucket,
  COUNT(*)                                  AS total_alerts,
  COUNT(*) FILTER (WHERE severity = 'critical')  AS critical_count,
  COUNT(*) FILTER (WHERE severity = 'high')      AS high_count,
  COUNT(*) FILTER (WHERE severity = 'medium')    AS medium_count,
  COUNT(*) FILTER (WHERE severity = 'low')       AS low_count,
  COUNT(*) FILTER (WHERE status = 'false_positive') AS false_positives,
  COUNT(*) FILTER (WHERE status = 'true_positive')  AS true_positives,
  COUNT(*) FILTER (WHERE status = 'closed')         AS closed_count,
  ROUND(
    COUNT(*) FILTER (WHERE status = 'false_positive')::NUMERIC /
    NULLIF(COUNT(*), 0) * 100, 2
  )                                         AS fpr_pct,
  ROUND(AVG(
    CASE WHEN first_touched_at IS NOT NULL
      THEN EXTRACT(EPOCH FROM (first_touched_at - created_at)) / 60
    END
  )::NUMERIC, 2)                            AS avg_mttd_minutes,
  ROUND(AVG(
    CASE WHEN closed_at IS NOT NULL
      THEN EXTRACT(EPOCH FROM (closed_at - created_at)) / 60
    END
  )::NUMERIC, 2)                            AS avg_mttr_minutes,
  COUNT(*) FILTER (
    WHERE severity IN ('critical', 'high')
      AND status NOT IN ('closed', 'false_positive')
      AND NOW() - created_at > INTERVAL '24 hours'
  )                                         AS sla_breach_count
FROM alerts
GROUP BY tenant_id, DATE_TRUNC('hour', created_at)
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_soc_kpi_tenant_hour
  ON mv_soc_kpi_snapshot (tenant_id, hour_bucket);

COMMENT ON MATERIALIZED VIEW mv_soc_kpi_snapshot IS
  'Hourly SOC KPI snapshot. Refresh with: '
  'REFRESH MATERIALIZED VIEW CONCURRENTLY mv_soc_kpi_snapshot';

-- ════════════════════════════════════════════════════════════════
--  MITRE ATT&CK COVERAGE VIEW
--  Shows which techniques have detections and coverage gaps
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_mitre_coverage AS
WITH technique_alerts AS (
  SELECT
    tenant_id,
    UNNEST(mitre_techniques) AS technique_id,
    COUNT(*)                 AS alert_count,
    MAX(created_at)          AS last_seen
  FROM alerts
  GROUP BY tenant_id, technique_id
),
technique_rules AS (
  SELECT
    tenant_id,
    UNNEST(mitre_techniques) AS technique_id,
    COUNT(*)                 AS rule_count
  FROM detection_rules
  WHERE is_active = TRUE
  GROUP BY tenant_id, technique_id
)
SELECT
  COALESCE(ta.tenant_id, tr.tenant_id) AS tenant_id,
  COALESCE(ta.technique_id, tr.technique_id) AS technique_id,
  COALESCE(ta.alert_count, 0)           AS alert_count,
  COALESCE(tr.rule_count, 0)            AS rule_count,
  ta.last_seen,
  CASE
    WHEN tr.rule_count > 0 AND ta.alert_count > 0 THEN 'covered_active'
    WHEN tr.rule_count > 0 AND ta.alert_count = 0 THEN 'covered_silent'
    WHEN tr.rule_count IS NULL AND ta.alert_count > 0 THEN 'gap_detected_no_rule'
    ELSE 'gap'
  END AS coverage_status
FROM technique_alerts  ta
FULL OUTER JOIN technique_rules tr
  ON ta.tenant_id = tr.tenant_id AND ta.technique_id = tr.technique_id;

-- ════════════════════════════════════════════════════════════════
--  ANALYST WORKLOAD VIEW
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_analyst_workload AS
SELECT
  u.tenant_id,
  u.id            AS analyst_id,
  u.full_name     AS analyst_name,
  u.role,
  COUNT(a.id) FILTER (WHERE a.status IN ('open','in_progress')) AS open_alerts,
  COUNT(a.id) FILTER (WHERE a.severity = 'critical' AND a.status IN ('open','in_progress')) AS critical_open,
  COUNT(a.id) FILTER (WHERE a.status = 'closed'
    AND a.closed_at > NOW() - INTERVAL '24 hours') AS closed_today,
  ROUND(AVG(
    CASE WHEN a.closed_at IS NOT NULL
      THEN EXTRACT(EPOCH FROM (a.closed_at - a.created_at)) / 60
    END
  )::NUMERIC, 2) AS avg_resolution_minutes,
  -- Simple workload score (0–100)
  LEAST(100, COUNT(a.id) FILTER (
    WHERE a.status IN ('open','in_progress')
  ) * 5 + COUNT(a.id) FILTER (
    WHERE a.severity = 'critical' AND a.status IN ('open','in_progress')
  ) * 20) AS workload_score
FROM users u
LEFT JOIN alerts a ON a.assigned_to = u.id
WHERE u.role IN ('ANALYST','TEAM_LEAD')
  AND u.is_active = TRUE
GROUP BY u.tenant_id, u.id, u.full_name, u.role;

-- ════════════════════════════════════════════════════════════════
--  AGENT PERFORMANCE VIEW
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_agent_performance AS
SELECT
  at2.tenant_id,
  at2.agent_type,
  DATE_TRUNC('day', at2.created_at)   AS day_bucket,
  COUNT(*)                             AS tasks_total,
  COUNT(*) FILTER (WHERE at2.status = 'completed')  AS tasks_completed,
  COUNT(*) FILTER (WHERE at2.status = 'failed')     AS tasks_failed,
  ROUND(AVG(at2.execution_ms)::NUMERIC / 1000, 2)   AS avg_execution_sec,
  SUM(at2.tokens_used)                              AS tokens_consumed,
  -- Accuracy: approved decisions / total decisions (HITL)
  COUNT(ad.id) FILTER (WHERE ad.status = 'approved')  AS decisions_approved,
  COUNT(ad.id) FILTER (WHERE ad.status = 'rejected')  AS decisions_rejected,
  ROUND(
    COUNT(ad.id) FILTER (WHERE ad.status = 'approved')::NUMERIC /
    NULLIF(COUNT(ad.id) FILTER (WHERE ad.status IN ('approved','rejected')), 0) * 100, 2
  ) AS approval_rate_pct
FROM agent_tasks at2
LEFT JOIN agent_decisions ad ON ad.task_id = at2.id
GROUP BY at2.tenant_id, at2.agent_type, DATE_TRUNC('day', at2.created_at);

-- ════════════════════════════════════════════════════════════════
--  DETECTION FEEDBACK STATS VIEW
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_detection_feedback_stats AS
SELECT
  df.tenant_id,
  df.rule_id,
  dr.name                AS rule_name,
  dr.severity            AS rule_severity,
  COUNT(*)               AS total_feedback,
  COUNT(*) FILTER (WHERE df.label = 'true_positive')  AS true_positives,
  COUNT(*) FILTER (WHERE df.label = 'false_positive') AS false_positives,
  COUNT(*) FILTER (WHERE df.label = 'true_negative')  AS true_negatives,
  COUNT(*) FILTER (WHERE df.label = 'false_negative') AS false_negatives,
  ROUND(
    COUNT(*) FILTER (WHERE df.label = 'true_positive')::NUMERIC /
    NULLIF(COUNT(*), 0) * 100, 2
  ) AS precision_pct,
  ROUND(
    COUNT(*) FILTER (WHERE df.label IN ('true_positive','false_negative'))::NUMERIC /
    NULLIF(
      COUNT(*) FILTER (WHERE df.label IN ('true_positive','false_negative','true_negative','false_positive')),
      0
    ) * 100, 2
  ) AS recall_pct,
  MAX(df.created_at)     AS last_feedback_at
FROM detection_feedback df
LEFT JOIN detection_rules dr ON dr.id = df.rule_id
GROUP BY df.tenant_id, df.rule_id, dr.name, dr.severity;

-- ════════════════════════════════════════════════════════════════
--  IOC THREAT SCORE VIEW
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_ioc_threat_scores AS
SELECT
  i.id,
  i.tenant_id,
  i.ioc_type,
  i.value,
  i.confidence,
  i.severity,
  i.is_active,
  i.last_seen,
  i.first_seen,
  pts.threat_score       AS predictive_score,
  pts.forecast_horizon,
  pts.valid_until        AS score_valid_until,
  -- Composite risk: weighted average of confidence + predictive score
  ROUND(
    (COALESCE(i.confidence, 50) * 0.4 +
     COALESCE(pts.threat_score, 50) * 0.6)::NUMERIC, 2
  ) AS composite_risk_score,
  COUNT(a.id)            AS alert_hit_count
FROM iocs i
LEFT JOIN predictive_threat_scores pts
  ON pts.tenant_id = i.tenant_id
  AND pts.entity_value = i.value
  AND pts.forecast_horizon = '24h'
LEFT JOIN alerts a
  ON a.tenant_id = i.tenant_id
  AND (
    a.source_ip::TEXT = i.value OR
    a.dest_ip::TEXT   = i.value OR
    a.metadata->>'domain' = i.value
  )
  AND a.created_at > NOW() - INTERVAL '30 days'
WHERE i.is_active = TRUE
GROUP BY i.id, i.tenant_id, i.ioc_type, i.value, i.confidence,
         i.severity, i.is_active, i.last_seen, i.first_seen,
         pts.threat_score, pts.forecast_horizon, pts.valid_until;

-- ════════════════════════════════════════════════════════════════
--  STIX COVERAGE VIEW
-- ════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW v_stix_coverage AS
SELECT
  so.tenant_id,
  so.stix_type,
  COUNT(*)                              AS object_count,
  AVG(so.confidence)                    AS avg_confidence,
  MAX(so.created_at)                    AS latest_ingested,
  COUNT(*) FILTER (WHERE so.revoked)    AS revoked_count,
  COUNT(sr.id)                          AS relationship_count
FROM stix_objects so
LEFT JOIN stix_relationships sr
  ON sr.tenant_id = so.tenant_id
  AND (sr.source_ref = so.stix_id OR sr.target_ref = so.stix_id)
GROUP BY so.tenant_id, so.stix_type;
