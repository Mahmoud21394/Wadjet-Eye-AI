/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Zod Input Validation Schemas (SEC-005 Fix)
 *  backend/schemas/validation.js
 *
 *  Strict Zod schemas for every API input surface.
 *  Applied via validateBody/validateQuery/validateParams middleware.
 *
 *  Audit finding: SEC-005 — SQL/NoSQL injection via unvalidated IOC values
 *  OWASP: A03:2021 Injection
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { z } = require('zod');

// ── Primitive re-usable types ─────────────────────────────────────

const uuid      = z.string().uuid('Invalid UUID format');
const tenantId  = z.string().uuid('Invalid tenant ID');
const email     = z.string().email().max(320).toLowerCase();
const safeStr   = (maxLen = 255) => z.string().trim().max(maxLen).regex(/^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$/, 'Control characters not allowed');
const posInt    = z.number().int().positive();
const nonNegInt = z.number().int().min(0);
const page      = z.coerce.number().int().min(1).max(10000).default(1);
const pageSize  = z.coerce.number().int().min(1).max(500).default(50);
const severity  = z.enum(['critical', 'high', 'medium', 'low', 'informational', 'unknown']);
const isoDate   = z.string().datetime({ offset: true });

// ── IOC value validators ──────────────────────────────────────────
// Each validator strips dangerous characters and enforces format.

/** IPv4 address */
const ipv4 = z.string()
  .regex(/^(\d{1,3}\.){3}\d{1,3}$/, 'Invalid IPv4 address')
  .refine(ip => ip.split('.').every(oct => Number(oct) <= 255), 'Invalid IPv4 octet');

/** IPv6 address (simplified) */
const ipv6 = z.string().regex(
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?)$/,
  'Invalid IPv6 address'
);

/** Domain name */
const domain = z.string()
  .max(253)
  .regex(/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/, 'Invalid domain name');

/** URL */
const urlValue = z.string()
  .max(2048)
  .url('Invalid URL')
  .refine(u => ['http:', 'https:'].includes(new URL(u).protocol), 'Only http/https URLs allowed');

/** File hash (MD5/SHA1/SHA256/SHA512) */
const fileHash = z.string()
  .regex(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/, 'Invalid hash format (MD5/SHA1/SHA256/SHA512)');

/** IOC value — discriminated union based on type */
const iocValue = z.union([ipv4, ipv6, domain, urlValue, fileHash, email, safeStr(512)]);

/** IOC type enum */
const iocType = z.enum(['ip', 'domain', 'url', 'hash', 'email', 'cve', 'mutex', 'registry', 'filepath', 'useragent', 'asn', 'unknown']);

// ── Auth schemas ──────────────────────────────────────────────────

const LoginSchema = z.object({
  email:    email,
  password: z.string().min(8).max(128),
  mfa_code: z.string().regex(/^\d{6}$/, 'MFA code must be 6 digits').optional(),
  device_id: safeStr(128).optional(),
});

const RegisterSchema = z.object({
  email:     email,
  password:  z.string().min(12).max(128)
    .regex(/[A-Z]/, 'Password must contain uppercase')
    .regex(/[a-z]/, 'Password must contain lowercase')
    .regex(/\d/,    'Password must contain digit')
    .regex(/[^A-Za-z0-9]/, 'Password must contain special character'),
  name:      safeStr(100),
  tenant_id: tenantId.optional(),
  role:      z.enum(['ANALYST', 'SENIOR_ANALYST', 'TEAM_LEAD', 'ADMIN']).default('ANALYST'),
});

const MfaSetupSchema = z.object({
  totp_code: z.string().regex(/^\d{6}$/, 'Must be 6 digits'),
});

const MfaVerifySchema = z.object({
  totp_code: z.string().regex(/^\d{6}$/, 'Must be 6 digits'),
  user_id:   uuid,
});

// ── IOC schemas ───────────────────────────────────────────────────

const IocLookupSchema = z.object({
  value:      iocValue,
  type:       iocType.optional(),
  sources:    z.array(z.enum(['vt', 'shodan', 'abuseipdb', 'otx', 'urlhaus', 'nvd'])).optional(),
  force_refresh: z.boolean().default(false),
});

const IocBulkSchema = z.object({
  iocs:      z.array(z.object({ value: iocValue, type: iocType })).max(100, 'Max 100 IOCs per request'),
  sources:   z.array(z.enum(['vt', 'shodan', 'abuseipdb', 'otx'])).optional(),
});

const IocCreateSchema = z.object({
  value:       iocValue,
  type:        iocType,
  severity:    severity.optional(),
  confidence:  z.number().min(0).max(100).optional(),
  tags:        z.array(safeStr(64)).max(20).optional(),
  description: safeStr(2048).optional(),
  source:      safeStr(128).optional(),
  tlp:         z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).default('AMBER'),
  expiry_date: isoDate.optional(),
  mitre_ttps:  z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/, 'Invalid MITRE TTP ID')).max(20).optional(),
});

// ── Alert/Incident schemas ────────────────────────────────────────

const AlertCreateSchema = z.object({
  title:        safeStr(512),
  description:  safeStr(4096).optional(),
  severity:     severity,
  rule_id:      uuid.optional(),
  source:       safeStr(128),
  raw_event:    z.record(z.unknown()).optional(),
  tenant_id:    tenantId,
  host:         safeStr(256).optional(),
  user:         safeStr(256).optional(),
  mitre_tactic: safeStr(128).optional(),
  mitre_tech:   z.string().regex(/^T\d{4}(\.\d{3})?$/).optional(),
  risk_score:   z.number().min(0).max(100).optional(),
  iocs:         z.array(iocValue).max(50).optional(),
});

const AlertUpdateSchema = z.object({
  status:      z.enum(['open', 'investigating', 'resolved', 'false_positive', 'suppressed']).optional(),
  severity:    severity.optional(),
  assignee_id: uuid.optional(),
  notes:       safeStr(4096).optional(),
  resolution:  safeStr(2048).optional(),
});

const IncidentCreateSchema = z.object({
  title:       safeStr(512),
  description: safeStr(8192).optional(),
  severity:    severity,
  alert_ids:   z.array(uuid).min(1).max(500),
  tenant_id:   tenantId,
  assignee_id: uuid.optional(),
  priority:    z.enum(['P1', 'P2', 'P3', 'P4']).default('P3'),
  tags:        z.array(safeStr(64)).max(20).optional(),
});

// ── Detection/Rule schemas ────────────────────────────────────────

const SigmaRuleSchema = z.object({
  title:       safeStr(256),
  description: safeStr(2048).optional(),
  status:      z.enum(['stable', 'test', 'experimental', 'deprecated']).default('experimental'),
  author:      safeStr(128).optional(),
  level:       z.enum(['critical', 'high', 'medium', 'low', 'informational']),
  logsource:   z.object({
    product:   safeStr(64).optional(),
    service:   safeStr(64).optional(),
    category:  safeStr(64).optional(),
  }),
  detection:   z.record(z.unknown()),   // Flexible Sigma detection block
  falsepositives: z.array(safeStr(256)).optional(),
  tags:        z.array(z.string().regex(/^attack\..+$|^car\..+$|^cve\..+$/)).optional(),
  mitre_id:    z.string().regex(/^T\d{4}(\.\d{3})?$/).optional(),
});

// ── Query/Pagination schemas ──────────────────────────────────────

const PaginationSchema = z.object({
  page,
  limit:  pageSize,
  sort:   safeStr(64).optional(),
  order:  z.enum(['asc', 'desc']).default('desc'),
});

const DateRangeSchema = z.object({
  start_date: isoDate.optional(),
  end_date:   isoDate.optional(),
  tenant_id:  tenantId.optional(),
}).refine(
  data => !(data.start_date && data.end_date) || new Date(data.start_date) <= new Date(data.end_date),
  { message: 'start_date must be before end_date', path: ['start_date'] }
);

// ── LLM / AI request schemas ──────────────────────────────────────

const LlmQuerySchema = z.object({
  query:      z.string().min(1).max(4096).trim(),
  context:    z.record(z.unknown()).optional(),
  session_id: safeStr(128).optional(),
  provider:   z.enum(['openai', 'claude', 'gemini', 'auto']).default('auto'),
  max_tokens: z.number().int().min(100).max(32000).default(2000),
  temperature: z.number().min(0).max(2).default(0.3),
  stream:     z.boolean().default(false),
});

const RagQuerySchema = z.object({
  query:         z.string().min(1).max(2048).trim(),
  namespaces:    z.array(z.enum(['mitre', 'cve', 'threat_reports', 'incidents', 'iocs'])).optional(),
  top_k:         z.number().int().min(1).max(20).default(5),
  min_score:     z.number().min(0).max(1).default(0.7),
  include_source: z.boolean().default(true),
});

// ── STIX schemas ──────────────────────────────────────────────────

const StixBundleIngestSchema = z.object({
  bundle:      z.object({ type: z.literal('bundle'), objects: z.array(z.record(z.unknown())).max(10000) }),
  source:      safeStr(128),
  tlp:         z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).default('AMBER'),
  auto_enrich: z.boolean().default(false),
});

// ── Webhook schemas ───────────────────────────────────────────────

const WebhookSchema = z.object({
  name:        safeStr(128),
  url:         urlValue,
  events:      z.array(z.enum(['alert.created', 'incident.created', 'ioc.matched', 'rule.fired', 'case.updated'])).min(1),
  secret:      safeStr(256).optional(),
  active:      z.boolean().default(true),
  headers:     z.record(safeStr(512)).optional(),
  retry_count: z.number().int().min(0).max(5).default(3),
});

// ── Agent schemas (Phase 5) ───────────────────────────────────────

const AgentTriageSchema = z.object({
  alert_id:    uuid,
  priority:    z.number().int().min(0).max(100).default(50),
  context:     z.record(z.unknown()).optional(),
  auto_apply:  z.boolean().default(false),
});

const AgentInvestigateSchema = z.object({
  alert_id:    uuid,
  case_id:     uuid.optional(),
  depth:       z.enum(['shallow', 'standard', 'deep']).default('standard'),
  context:     z.record(z.unknown()).optional(),
  auto_apply:  z.boolean().default(false),
});

const AgentRespondSchema = z.object({
  decision_id: uuid,
  alert_id:    uuid.optional(),
  actions:     z.array(z.object({
    type:      z.enum(['block_ip', 'isolate_host', 'close_alert', 'create_ticket', 'run_playbook', 'notify']),
    target:    safeStr(512),
    params:    z.record(z.unknown()).optional(),
  })).min(1).max(20),
  auto_apply:  z.boolean().default(false),
});

const AgentDecisionReviewSchema = z.object({
  action:      z.enum(['approve', 'reject']),
  notes:       safeStr(2048).optional(),
  modified_actions: z.array(z.record(z.unknown())).optional(),
});

// ── Detection engine schemas (Phase 3 + 7) ────────────────────────

const DetectionRuleCreateSchema = z.object({
  name:           safeStr(256),
  description:    safeStr(4096).optional(),
  rule_type:      z.enum(['sigma', 'yara', 'eql', 'custom', 'ml']),
  rule_content:   z.string().min(1).max(65536),
  severity:       severity,
  mitre_techniques: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).max(20).optional(),
  tags:           z.array(safeStr(64)).max(20).optional(),
  enabled:        z.boolean().default(true),
  false_positive_notes: safeStr(2048).optional(),
  threshold:      z.number().int().min(1).default(1),
  window_minutes: z.number().int().min(1).max(1440).default(5),
});

const DetectionRuleUpdateSchema = DetectionRuleCreateSchema.partial().extend({
  is_active: z.boolean().optional(),
});

const DetectionFeedbackSchema = z.object({
  alert_id:   uuid,
  rule_id:    uuid.optional(),
  label:      z.enum(['true_positive', 'false_positive', 'true_negative', 'false_negative']),
  confidence: z.number().min(0).max(100).default(100),
  rationale:  safeStr(2048).optional(),
});

const ClusterRequestSchema = z.object({
  alert_ids:   z.array(uuid).min(2).max(5000),
  algorithm:   z.enum(['dbscan', 'hdbscan', 'kmeans']).default('hdbscan'),
  eps:         z.number().min(0.01).max(10).optional(),
  min_samples: z.number().int().min(2).max(100).optional(),
  features:    z.array(z.enum(['severity', 'source_ip', 'mitre_tactic', 'time', 'rule_id', 'dest_ip'])).optional(),
});

// ── RAG pipeline schemas (Phase 3) ───────────────────────────────

const RagIngestSchema = z.object({
  doc_type:  z.enum(['threat_report', 'mitre_technique', 'cve_advisory', 'sigma_rule', 'playbook', 'incident_report', 'custom']),
  title:     safeStr(512),
  content:   z.string().min(10).max(524288),   // max 512 KB
  source_url: urlValue.optional(),
  source:    safeStr(128).optional(),
  tags:      z.array(safeStr(64)).max(20).optional(),
  metadata:  z.record(z.unknown()).optional(),
  namespace: z.enum(['mitre', 'cve', 'threat_reports', 'incidents', 'iocs', 'custom']).default('custom'),
});

// ── Purple-team / adversary sim schemas (Phase 9) ─────────────────

const PurpleTeamSessionSchema = z.object({
  name:           safeStr(256),
  description:    safeStr(2048).optional(),
  objectives:     z.array(safeStr(512)).max(20).optional(),
  scope:          z.record(z.unknown()).optional(),
  red_team_lead:  uuid.optional(),
  blue_team_lead: uuid.optional(),
});

const AdversarySimSessionSchema = z.object({
  scenario_id:   safeStr(128),
  scenario_name: safeStr(256).optional(),
  threat_actor:  safeStr(128).optional(),
  mitre_tactics: z.array(safeStr(64)).max(50).optional(),
  attack_chain:  z.array(z.record(z.unknown())).max(100).optional(),
  status:        z.enum(['running', 'completed', 'failed', 'aborted']).default('completed'),
  outcome:       z.enum(['success', 'partial', 'failed', 'detected']).optional(),
  results:       z.record(z.unknown()).optional(),
});

// ── What-if simulation schema (Phase 9) ──────────────────────────

const WhatifSimulationSchema = z.object({
  scenario_id:    safeStr(128),
  scenario_name:  safeStr(256).optional(),
  user_inputs:    z.record(z.unknown()),
  outcome:        safeStr(512).optional(),
  risk_reduction: z.number().min(0).max(100).optional(),
  recommendations: z.array(z.record(z.unknown())).max(50).optional(),
});

// ── Sysmon / EDR event ingest schema (Phase 4) ───────────────────

const SysmonEventSchema = z.object({
  event_id:     z.number().int().min(1).max(100),
  event_type:   safeStr(128),
  hostname:     safeStr(253).optional(),
  username:     safeStr(256).optional(),
  process_name: safeStr(512).optional(),
  command_line: safeStr(4096).optional(),
  image_path:   safeStr(1024).optional(),
  hash_sha256:  z.string().regex(/^[a-fA-F0-9]{64}$/).optional(),
  dest_ip:      z.union([ipv4, ipv6]).optional(),
  dest_port:    z.number().int().min(1).max(65535).optional(),
  src_ip:       z.union([ipv4, ipv6]).optional(),
  raw_event:    z.record(z.unknown()).optional(),
  event_time:   isoDate,
});

const SysmonBulkIngestSchema = z.object({
  events:    z.array(SysmonEventSchema).min(1).max(1000),
  source:    safeStr(128).optional(),
  tenant_id: tenantId.optional(),
});

// ── Threat actor schemas (Phase 6) ───────────────────────────────

const ThreatActorCreateSchema = z.object({
  name:           safeStr(256),
  aliases:        z.array(safeStr(128)).max(20).optional(),
  actor_type:     z.enum(['nation-state', 'criminal', 'hacktivism', 'insider', 'terrorist', 'unknown']).optional(),
  sophistication: z.enum(['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic']).optional(),
  motivation:     z.array(safeStr(64)).max(10).optional(),
  country_of_origin: safeStr(64).optional(),
  targeted_sectors: z.array(safeStr(128)).max(30).optional(),
  targeted_regions: z.array(safeStr(128)).max(20).optional(),
  description:    safeStr(8192).optional(),
  confidence:     z.number().int().min(0).max(100).default(50),
  source:         safeStr(256).optional(),
  ttps:           z.array(z.object({
    technique_id: z.string().regex(/^T\d{4}(\.\d{3})?$/),
    tactic:       safeStr(64).optional(),
  })).max(200).optional(),
});

// ── SOC Metrics / KPI schemas (Phase 8) ──────────────────────────

const MetricsQuerySchema = z.object({
  start_date: isoDate.optional(),
  end_date:   isoDate.optional(),
  granularity: z.enum(['hour', 'day', 'week', 'month']).default('day'),
  analyst_id: uuid.optional(),
  severity:   severity.optional(),
}).extend({ page, limit: pageSize });

// ── Predictive / Forecasting schemas (Phase 8) ───────────────────

const ForecastRequestSchema = z.object({
  entity_type:  z.enum(['ip', 'domain', 'asn', 'threat_actor', 'malware_family', 'cve']),
  entity_value: safeStr(512),
  horizon:      z.enum(['24h', '7d', '30d']).default('24h'),
  include_signals: z.boolean().default(true),
});

// ── Middleware factory ────────────────────────────────────────────

/**
 * validate — Zod validation middleware factory
 * @param {z.ZodSchema} schema - Zod schema to validate against
 * @param {'body'|'query'|'params'} source - Request object property to validate
 */
function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const errors = result.error.errors.map(e => ({
        field:   e.path.join('.'),
        message: e.message,
        code:    e.code,
      }));
      console.warn(`[Validation] ${req.method} ${req.path} — ${errors.length} error(s):`, errors[0]);
      return res.status(400).json({
        error:  'Validation failed',
        code:   'VALIDATION_ERROR',
        errors,
      });
    }
    req[source] = result.data;  // Replace with parsed+coerced data
    next();
  };
}

const validateBody   = (schema) => validate(schema, 'body');
const validateQuery  = (schema) => validate(schema, 'query');
const validateParams = (schema) => validate(schema, 'params');

module.exports = {
  // ── Auth ──────────────────────────────────────────────────────────
  LoginSchema,
  RegisterSchema,
  MfaSetupSchema,
  MfaVerifySchema,
  // ── IOC ──────────────────────────────────────────────────────────
  IocLookupSchema,
  IocBulkSchema,
  IocCreateSchema,
  // ── Alert / Incident ─────────────────────────────────────────────
  AlertCreateSchema,
  AlertUpdateSchema,
  IncidentCreateSchema,
  // ── Detection & Rules ────────────────────────────────────────────
  SigmaRuleSchema,
  DetectionRuleCreateSchema,
  DetectionRuleUpdateSchema,
  DetectionFeedbackSchema,
  ClusterRequestSchema,
  // ── Query helpers ─────────────────────────────────────────────────
  PaginationSchema,
  DateRangeSchema,
  MetricsQuerySchema,
  // ── AI / LLM / RAG ───────────────────────────────────────────────
  LlmQuerySchema,
  RagQuerySchema,
  RagIngestSchema,
  // ── STIX / Threat Intel ──────────────────────────────────────────
  StixBundleIngestSchema,
  ThreatActorCreateSchema,
  // ── Agents (Phase 5) ─────────────────────────────────────────────
  AgentTriageSchema,
  AgentInvestigateSchema,
  AgentRespondSchema,
  AgentDecisionReviewSchema,
  // ── Purple-team / Simulation (Phase 9) ───────────────────────────
  PurpleTeamSessionSchema,
  AdversarySimSessionSchema,
  WhatifSimulationSchema,
  // ── EDR / Sysmon (Phase 4) ────────────────────────────────────────
  SysmonEventSchema,
  SysmonBulkIngestSchema,
  // ── Forecasting (Phase 8) ─────────────────────────────────────────
  ForecastRequestSchema,
  // ── Webhook ──────────────────────────────────────────────────────
  WebhookSchema,
  // ── Primitives ───────────────────────────────────────────────────
  iocValue, iocType, severity, uuid, email, safeStr,
  page, pageSize, isoDate, ipv4, ipv6, domain, urlValue, fileHash,
  // ── Middleware ───────────────────────────────────────────────────
  validate, validateBody, validateQuery, validateParams,
};
