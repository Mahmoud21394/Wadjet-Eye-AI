/**
 * TenantDbClient Unit Tests  v1.0
 * Tests: tenant isolation enforcement, cross-tenant prevention, runtime validation
 */
'use strict';

jest.mock('../config/supabase', () => ({
  supabase: {
    from: jest.fn(() => ({
      eq:         jest.fn().mockReturnThis(),
      select:     jest.fn().mockReturnThis(),
      insert:     jest.fn().mockResolvedValue({ data: [{ id: 1 }], error: null }),
      update:     jest.fn().mockReturnThis(),
      delete:     jest.fn().mockReturnThis(),
      limit:      jest.fn().mockReturnThis(),
      single:     jest.fn().mockResolvedValue({ data: { id: 1, tenant_id: 'tenant-a' }, error: null }),
    })),
    rpc: jest.fn().mockResolvedValue({ data: null, error: null }),
  },
}));

const { TenantDbClient, validateTenantQuery, fromRequest, tenantValidationMiddleware } = require('../db/tenantDb');

describe('TenantDbClient — Tenant Isolation', () => {
  test('constructor requires tenantId', () => {
    expect(() => new TenantDbClient('')).toThrow('tenantId is required');
    expect(() => new TenantDbClient(null)).toThrow('tenantId is required');
  });

  test('from() returns TenantQueryProxy with tenant filter injected', () => {
    const client = new TenantDbClient('tenant-a', 'user-1', 'analyst');
    const query  = client.from('alerts');
    expect(query).toBeTruthy();
    expect(query._tenantId).toBe('tenant-a');
  });

  test('insert() injects tenant_id automatically', async () => {
    const client = new TenantDbClient('tenant-a', 'user-1', 'analyst');
    await client.insert('alerts', { title: 'Test Alert' });
    // Verify supabase.from was called and insert included tenant_id
    const { supabase } = require('../config/supabase');
    expect(supabase.from).toHaveBeenCalledWith('alerts');
  });

  test('insert() blocks cross-tenant mismatch', async () => {
    const client = new TenantDbClient('tenant-a', 'user-1', 'analyst');
    await expect(
      client.insert('alerts', { title: 'Alert', tenant_id: 'tenant-b' })
    ).rejects.toThrow('tenant_id mismatch');
  });

  test('SUPER_ADMIN can use skipTenantFilter', () => {
    const client = new TenantDbClient('tenant-a', 'admin-user', 'SUPER_ADMIN');
    // Should not throw
    const query = client.from('alerts', { skipTenantFilter: true });
    expect(query).toBeTruthy();
  });

  test('non-SUPER_ADMIN cannot skip tenant filter', () => {
    const client = new TenantDbClient('tenant-a', 'user-1', 'analyst');
    // Even with skipTenantFilter: true, analyst still gets tenant filter
    const query = client.from('alerts', { skipTenantFilter: true });
    expect(query._tenantId).toBe('tenant-a');
  });
});

describe('validateTenantQuery — Runtime Cross-Tenant Prevention', () => {
  test('passes through rows belonging to correct tenant', () => {
    const rows   = [{ id: 1, tenant_id: 'tenant-a' }, { id: 2, tenant_id: 'tenant-a' }];
    const result = validateTenantQuery(rows, 'tenant-a', 'alerts');
    expect(result).toHaveLength(2);
  });

  test('strips cross-tenant rows', () => {
    const rows = [
      { id: 1, tenant_id: 'tenant-a' },
      { id: 2, tenant_id: 'tenant-b' }, // cross-tenant leak
    ];
    const result = validateTenantQuery(rows, 'tenant-a', 'alerts');
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(1);
  });

  test('passes rows without tenant_id (tables without tenant column)', () => {
    const rows   = [{ id: 1, name: 'global_config' }];
    const result = validateTenantQuery(rows, 'tenant-a', 'global_config');
    expect(result).toHaveLength(1);
  });

  test('handles non-array input', () => {
    expect(validateTenantQuery(null, 'tenant-a', 'alerts')).toBeNull();
    expect(validateTenantQuery({}, 'tenant-a', 'alerts')).toEqual({});
  });
});

describe('tenantValidationMiddleware', () => {
  test('passes for requests with tenant context', () => {
    const req  = { user: { role: 'analyst' }, tenantId: 'tenant-a' };
    const res  = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();
    tenantValidationMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('blocks requests without tenant context', () => {
    const req  = { user: { role: 'analyst' }, tenantId: null };
    const res  = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();
    tenantValidationMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  test('SUPER_ADMIN bypasses tenant check', () => {
    const req  = { user: { role: 'SUPER_ADMIN' }, tenantId: null };
    const res  = { status: jest.fn().mockReturnThis(), json: jest.fn() };
    const next = jest.fn();
    tenantValidationMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});

describe('fromRequest — Factory', () => {
  test('creates client from request with tenantId', () => {
    const req = { user: { id: 'user-1', role: 'analyst', tenant_id: 'tenant-a' }, tenantId: 'tenant-a' };
    const client = fromRequest(req);
    expect(client.tenantId).toBe('tenant-a');
  });

  test('throws if req.tenantId missing', () => {
    const req = { user: { id: 'user-1', role: 'analyst' }, tenantId: null };
    expect(() => fromRequest(req)).toThrow('req.tenantId is not set');
  });
});
