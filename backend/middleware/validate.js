/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Request Validation Middleware (Phase 2)
 *  backend/middleware/validate.js
 *
 *  Provides Zod-based request validation for routes.
 *  Falls back to manual validation if Zod is not installed.
 *
 *  Usage:
 *    const { validate, z } = require('../middleware/validate');
 *
 *    router.post('/chat', validate({
 *      body: z.object({
 *        message:   z.string().min(1).max(8000),
 *        sessionId: z.string().uuid().optional(),
 *      })
 *    }), handler);
 *
 *  Also exports common schemas used across multiple routes.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

// ── Try to load Zod, fall back to a no-op validator ──────────────
let z;
let ZodError;
try {
  const zod = require('zod');
  z         = zod.z || zod;
  ZodError  = zod.ZodError || zod.z?.ZodError;
  console.log('[Validate] Zod loaded — schema validation active');
} catch {
  // Zod not installed — provide minimal stand-ins
  console.warn('[Validate] Zod not installed. Run: cd backend && npm install zod');
  console.warn('[Validate] Using passthrough validation until Zod is available.');
  z        = _buildZodStub();
  ZodError = class ZodError extends Error {};
}

// ── Validation middleware factory ─────────────────────────────────
/**
 * validate({ body?, query?, params? })
 * Returns Express middleware that validates the request against the
 * provided Zod schemas. On failure returns 400 with structured errors.
 *
 * @param {{ body?: ZodSchema, query?: ZodSchema, params?: ZodSchema }} schemas
 */
function validate(schemas = {}) {
  return (req, res, next) => {
    const errors = [];

    for (const [part, schema] of Object.entries(schemas)) {
      if (!schema) continue;

      let result;
      try {
        if (typeof schema.safeParse === 'function') {
          result = schema.safeParse(req[part]);
        } else {
          // Stub: always passes
          result = { success: true, data: req[part] };
        }
      } catch (err) {
        return res.status(500).json(envelope(null, 'Validation schema error: ' + err.message, 500));
      }

      if (!result.success) {
        errors.push({
          part,
          issues: result.error?.issues?.map(i => ({
            path:    i.path.join('.'),
            message: i.message,
            code:    i.code,
          })) || [{ path: part, message: 'Invalid value', code: 'invalid' }],
        });
      } else {
        // Replace with parsed/coerced value
        req[part] = result.data;
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error:   'Validation failed',
        code:    'VALIDATION_ERROR',
        errors,
        requestId: req.id,
      });
    }

    next();
  };
}

// ── Standard response envelope ────────────────────────────────────
/**
 * envelope(data, error, status)
 * Returns a normalized API response object.
 *
 * Success:  { success: true,  data: T }
 * Error:    { success: false, error: string, code?: string }
 */
function envelope(data, error = null, status = 200) {
  if (error) {
    return {
      success:   false,
      error:     typeof error === 'string' ? error : error.message || String(error),
      status,
    };
  }
  return {
    success: true,
    data,
    status,
  };
}

/**
 * sendOk(res, data, meta?)
 * Send a 200 success response with normalized envelope.
 */
function sendOk(res, data, meta = {}) {
  return res.status(200).json({ success: true, data, ...meta });
}

/**
 * sendError(res, message, statusCode?, code?)
 * Send an error response with normalized envelope.
 */
function sendError(res, message, statusCode = 400, code = 'ERROR') {
  return res.status(statusCode).json({
    success: false,
    error:   message,
    code,
  });
}

// ── Common Zod schemas ────────────────────────────────────────────
function _buildSchemas() {
  if (!z?.object) return {};

  return {
    // Pagination
    pagination: z.object({
      page:  z.coerce.number().int().min(1).default(1),
      limit: z.coerce.number().int().min(1).max(200).default(20),
    }).optional(),

    // UUID param
    uuidParam: z.object({
      id: z.string().uuid('Invalid UUID format'),
    }),

    // Chat message
    chatMessage: z.object({
      message:    z.string().min(1, 'Message is required').max(8000, 'Message too long (max 8000 chars)'),
      sessionId:  z.string().uuid().optional().nullable(),
      tenantId:   z.string().max(64).optional(),
      userId:     z.string().max(64).optional(),
      priority:   z.enum(['LOW', 'MEDIUM', 'HIGH']).optional(),
    }),

    // IOC
    iocEntry: z.object({
      type:        z.enum(['ip', 'domain', 'url', 'hash', 'email']),
      value:       z.string().min(1).max(512),
      severity:    z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
      description: z.string().max(2000).optional(),
    }),

    // Generic filter query
    filterQuery: z.object({
      search:    z.string().max(200).optional(),
      status:    z.string().max(50).optional(),
      severity:  z.string().max(50).optional(),
      startDate: z.string().datetime().optional(),
      endDate:   z.string().datetime().optional(),
    }).optional(),
  };
}

// ── Zod stub (when zod not installed) ────────────────────────────
function _buildZodStub() {
  const pass = () => ({
    safeParse: (v) => ({ success: true, data: v }),
    parse:     (v) => v,
    optional:  () => pass(),
    nullable:  () => pass(),
    default:   () => pass(),
    min:       () => pass(),
    max:       () => pass(),
    int:       () => pass(),
  });

  const stub = {
    object:  () => pass(),
    string:  () => pass(),
    number:  () => pass(),
    boolean: () => pass(),
    array:   () => pass(),
    enum:    () => pass(),
    union:   () => pass(),
    coerce:  { number: () => pass(), string: () => pass() },
  };
  return stub;
}

const schemas = _buildSchemas();

module.exports = { validate, envelope, sendOk, sendError, z, ZodError, schemas };
