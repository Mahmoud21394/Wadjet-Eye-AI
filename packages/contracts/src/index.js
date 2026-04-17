/**
 * @wadjet-eye/contracts
 * Shared API contracts and Zod schemas for the Wadjet-Eye AI platform.
 *
 * These schemas define the single source of truth for API request/response shapes.
 * Used by both the backend (validation) and frontend (type checking).
 *
 * Phase 2 deliverable: typed contracts shared across apps.
 */
'use strict';

const { z } = require('zod');

// ── Auth ───────────────────────────────────────────────────────────
const LoginRequestSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(8).max(128),
});

const LoginResponseSchema = z.object({
  success:      z.boolean(),
  accessToken:  z.string(),
  refreshToken: z.string(),
  user: z.object({
    id:          z.string().uuid(),
    email:       z.string().email(),
    name:        z.string(),
    role:        z.enum(['SUPER_ADMIN', 'ADMIN', 'ANALYST', 'VIEWER']),
    tenant_id:   z.string(),
    permissions: z.record(z.boolean()).optional(),
    mfa_enabled: z.boolean().optional(),
  }),
});

// ── Chat ───────────────────────────────────────────────────────────
const ChatRequestSchema = z.object({
  message:    z.string().min(1, 'Message is required').max(8000, 'Message too long'),
  sessionId:  z.string().uuid().optional().nullable(),
  tenantId:   z.string().max(64).optional(),
  userId:     z.string().max(64).optional(),
  priority:   z.enum(['LOW', 'MEDIUM', 'HIGH']).default('MEDIUM'),
});

const ChatResponseSchema = z.object({
  success:     z.boolean(),
  message_id:  z.string().uuid(),
  session_id:  z.string().uuid(),
  content:     z.string(),
  provider:    z.string(),
  model:       z.string(),
  degraded:    z.boolean(),
  latency_ms:  z.number().int(),
  tokens_used: z.object({
    prompt:     z.number().int(),
    completion: z.number().int(),
    total:      z.number().int(),
  }).optional(),
});

// ── IOC ────────────────────────────────────────────────────────────
const IOCTypeEnum = z.enum(['ip', 'domain', 'url', 'hash', 'email']);
const SeverityEnum = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const IOCSchema = z.object({
  id:          z.string().uuid().optional(),
  type:        IOCTypeEnum,
  value:       z.string().min(1).max(512),
  severity:    SeverityEnum.optional(),
  source:      z.string().max(200).optional(),
  tenant_id:   z.string().optional(),
  risk_score:  z.number().int().min(0).max(100).optional(),
  tags:        z.array(z.string()).optional(),
  created_at:  z.string().datetime().optional(),
  last_seen:   z.string().datetime().optional(),
});

// ── Standard response envelope ─────────────────────────────────────
const SuccessEnvelopeSchema = z.object({
  success: z.literal(true),
  data:    z.unknown(),
});

const ErrorEnvelopeSchema = z.object({
  success: z.literal(false),
  error:   z.string(),
  code:    z.string().optional(),
  errors:  z.array(z.object({
    part:   z.string(),
    issues: z.array(z.object({
      path:    z.string(),
      message: z.string(),
      code:    z.string().optional(),
    })),
  })).optional(),
  requestId: z.string().optional(),
});

// ── Provider status ────────────────────────────────────────────────
const ProviderStatusSchema = z.object({
  provider:    z.string(),
  model:       z.string(),
  hasKey:      z.boolean(),
  cbStatus:    z.enum(['CLOSED', 'OPEN', 'HALF_OPEN']).optional(),
  healthScore: z.number().optional(),
});

// ── Pagination ─────────────────────────────────────────────────────
const PaginationQuerySchema = z.object({
  page:  z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(20),
});

module.exports = {
  // Schemas
  LoginRequestSchema,
  LoginResponseSchema,
  ChatRequestSchema,
  ChatResponseSchema,
  IOCSchema,
  IOCTypeEnum,
  SeverityEnum,
  SuccessEnvelopeSchema,
  ErrorEnvelopeSchema,
  ProviderStatusSchema,
  PaginationQuerySchema,
  // Re-export zod for convenience
  z,
};
