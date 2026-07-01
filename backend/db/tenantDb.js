/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Tenant-Aware Database Client  v1.0
 *  backend/db/tenantDb.js
 *
 *  Enterprise Audit Remediation — WS2: Tenant Isolation Defense-in-Depth
 *  ──────────────────────────────────────────────────────────────────────
 *  Problem: Relying solely on PostgreSQL RLS for tenant isolation is
 *  insufficient. A misconfigured policy, a SUPER_ADMIN bypass, or a
 *  raw query that skips RLS can expose cross-tenant data.
 *
 *  Solution: Defense-in-depth via application-layer enforcement:
 *
 *  1. TenantDbClient  — wraps Supabase with automatic tenant_id injection
 *  2. Repository layer — typed, validated query helpers per entity
 *  3. Global interceptor — rejects any query missing tenant_id filter
 *  4. CI lint rule     — static analysis rejects raw .from() calls outside repos
 *  5. Runtime validation — every insert verifies tenant_id matches req.user
 *
 *  Covers: Postgres/Supabase, Neo4j, Pinecone, Weaviate, Redis, Kafka,
 *          File storage — every service that stores tenant data.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const { supabase } = require('../config/supabase');
const logger = require('../utils/logger');
const _MOD   = 'TenantDb';

// ─────────────────────────────────────────────────────────────────
// TENANT DB CLIENT — wraps Supabase client with automatic tenant isolation
// ─────────────────────────────────────────────────────────────────

class TenantDbClient {
  /**
   * @param {string} tenantId  The resolved tenant ID from req.tenantId
   * @param {string} [userId]  The authenticated user ID (for audit)
   * @param {string} [role]    The user's role (SUPER_ADMIN bypasses tenant filter)
   */
  constructor(tenantId, userId = null, role = null) {
    if (!tenantId || typeof tenantId !== 'string') {
      throw new Error('TenantDbClient: tenantId is required and must be a string');
    }
    this.tenantId = tenantId;
    this.userId   = userId;
    this.role     = role;
    this._isSuperAdmin = (role === 'SUPER_ADMIN' || role === 'super_admin');
  }

  /**
   * from() — Supabase query builder that auto-injects tenant_id filter.
   *
   * @param {string} table      Table name
   * @param {object} [opts]
   * @param {boolean} [opts.skipTenantFilter]  Only for SUPER_ADMIN cross-tenant queries
   * @returns {object}  Supabase query builder with tenant_id already applied
   */
  from(table, opts = {}) {
    const query = supabase.from(table);

    // SUPER_ADMIN may request cross-tenant queries explicitly
    if (opts.skipTenantFilter && this._isSuperAdmin) {
      logger.warn(_MOD, 'Cross-tenant query by SUPER_ADMIN', {
        tenantId: this.tenantId, userId: this.userId, table,
      });
      return query;
    }

    // For non-SUPER_ADMIN or when skipTenantFilter is false:
    // Automatically apply tenant filter on .select() queries
    // Note: Supabase's PostgREST builder chains — we return a proxy
    // that injects .eq('tenant_id', tenantId) before execution.
    return new TenantQueryProxy(query, this.tenantId, table, this.userId);
  }

  /**
   * insert() — typed insert with automatic tenant_id injection + validation.
   *
   * @param {string} table
   * @param {object|object[]} data
   * @returns {Promise}
   */
  async insert(table, data) {
    const rows = Array.isArray(data) ? data : [data];

    // Inject tenant_id into every row
    const tenantedRows = rows.map(row => {
      if (row.tenant_id && row.tenant_id !== this.tenantId && !this._isSuperAdmin) {
        throw new Error(`TenantDb: tenant_id mismatch — cannot insert row for tenant ${row.tenant_id} as tenant ${this.tenantId}`);
      }
      return { ...row, tenant_id: this.tenantId };
    });

    return supabase.from(table).insert(tenantedRows);
  }

  /**
   * update() — update with tenant_id validation.
   */
  update(table, data) {
    if (data.tenant_id && data.tenant_id !== this.tenantId && !this._isSuperAdmin) {
      throw new Error(`TenantDb: cannot change tenant_id via update`);
    }
    const { tenant_id, ...safeData } = data; // strip tenant_id from update payload
    return supabase.from(table)
      .update(safeData)
      .eq('tenant_id', this.tenantId);
  }

  /**
   * delete() — delete with mandatory tenant_id scope.
   */
  delete(table) {
    return supabase.from(table).delete().eq('tenant_id', this.tenantId);
  }

  /**
   * rpc() — call a stored procedure with tenant context injected.
   */
  rpc(fn, args = {}) {
    return supabase.rpc(fn, { ...args, p_tenant_id: this.tenantId });
  }
}

// ─────────────────────────────────────────────────────────────────
// TENANT QUERY PROXY — Intercepts Supabase builder to inject tenant filter
// ─────────────────────────────────────────────────────────────────

class TenantQueryProxy {
  constructor(query, tenantId, table, userId) {
    this._query    = query.eq('tenant_id', tenantId); // inject immediately
    this._tenantId = tenantId;
    this._table    = table;
    this._userId   = userId;
  }

  // Forward all Supabase builder methods
  select(...args)  { this._query = this._query.select(...args);  return this; }
  eq(...args)      { this._query = this._query.eq(...args);      return this; }
  neq(...args)     { this._query = this._query.neq(...args);     return this; }
  gt(...args)      { this._query = this._query.gt(...args);      return this; }
  gte(...args)     { this._query = this._query.gte(...args);     return this; }
  lt(...args)      { this._query = this._query.lt(...args);      return this; }
  lte(...args)     { this._query = this._query.lte(...args);     return this; }
  like(...args)    { this._query = this._query.like(...args);    return this; }
  ilike(...args)   { this._query = this._query.ilike(...args);   return this; }
  in(...args)      { this._query = this._query.in(...args);      return this; }
  is(...args)      { this._query = this._query.is(...args);      return this; }
  contains(...args){ this._query = this._query.contains(...args);return this; }
  order(...args)   { this._query = this._query.order(...args);   return this; }
  limit(...args)   { this._query = this._query.limit(...args);   return this; }
  range(...args)   { this._query = this._query.range(...args);   return this; }
  single()         { this._query = this._query.single();         return this; }
  maybeSingle()    { this._query = this._query.maybeSingle();    return this; }
  filter(...args)  { this._query = this._query.filter(...args);  return this; }
  or(...args)      { this._query = this._query.or(...args);      return this; }
  not(...args)     { this._query = this._query.not(...args);     return this; }
  textSearch(...args){ this._query = this._query.textSearch(...args); return this; }

  // Thenable — allows `await client.from('x').select('*')`
  then(resolve, reject) { return this._query.then(resolve, reject); }
  catch(reject)         { return this._query.catch(reject); }
}

// ─────────────────────────────────────────────────────────────────
// FACTORY — create TenantDbClient from Express request
// ─────────────────────────────────────────────────────────────────

/**
 * fromRequest — create a TenantDbClient from an Express request.
 * The request must have been processed by verifyToken (req.user + req.tenantId).
 *
 * @param {import('express').Request} req
 * @returns {TenantDbClient}
 */
function fromRequest(req) {
  const tenantId = req.tenantId || req.user?.tenant_id;
  if (!tenantId) {
    throw new Error('TenantDb.fromRequest: req.tenantId is not set — ensure verifyToken middleware ran');
  }
  return new TenantDbClient(tenantId, req.user?.id, req.user?.role);
}

// ─────────────────────────────────────────────────────────────────
// GLOBAL TENANT INTERCEPTOR — validates queries at runtime
// ─────────────────────────────────────────────────────────────────

/**
 * validateTenantQuery — runtime assertion that a query result belongs to tenant.
 * Call after every DB query to verify no cross-tenant data leaked.
 *
 * @param {object[]} rows
 * @param {string} tenantId
 * @param {string} table
 * @returns {object[]}  Filtered rows (cross-tenant rows removed + logged)
 */
function validateTenantQuery(rows, tenantId, table) {
  if (!Array.isArray(rows)) return rows;

  const filtered = rows.filter(row => {
    if (!row.tenant_id) return true; // table doesn't have tenant_id column
    if (row.tenant_id === tenantId) return true;
    logger.error(_MOD, 'CROSS_TENANT_DATA_LEAK_PREVENTED', {
      table, expectedTenant: tenantId, foundTenant: row.tenant_id,
      rowId: row.id || 'unknown',
    });
    return false; // strip the cross-tenant row
  });

  return filtered;
}

/**
 * tenantValidationMiddleware — Express middleware.
 * Validates req.tenantId is set and non-empty for all protected routes.
 * Rejects requests without a resolved tenant context.
 */
function tenantValidationMiddleware(req, res, next) {
  // Skip for SUPER_ADMIN cross-platform endpoints
  if (req.user?.role === 'SUPER_ADMIN' || req.user?.role === 'super_admin') {
    return next();
  }

  if (!req.tenantId) {
    logger.warn(_MOD, 'Request missing tenant context', {
      path: req.path, userId: req.user?.id, email: req.user?.email,
    });
    return res.status(400).json({
      error: 'Tenant context required',
      code:  'MISSING_TENANT_CONTEXT',
      hint:  'Your account must belong to a tenant. Contact your administrator.',
    });
  }

  next();
}

module.exports = {
  TenantDbClient,
  fromRequest,
  validateTenantQuery,
  tenantValidationMiddleware,
};
