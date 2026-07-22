/**
 * threatIntel.test.js — Unit tests for backend/services/threatIntelPoller.js (Phase 3)
 *
 * Tests cover pure-algorithm functions only (no network, no Supabase I/O):
 *   - normalizeKevEntry()       — CISA KEV normalization (ported from CisaKevClient.to_ioc())
 *   - normalizeOtxIndicator()   — OTX indicator normalization
 *   - isPollingEnabled()        — feature flag (default FALSE)
 *   - _hashShort()              — deterministic 8-char hex FNV-1a
 *   - upsertIoc()               — mocked Supabase: new vs update paths
 *   - enrichAlertWithTI()       — mocked Supabase: IOC matching
 *   - OTX_TYPE_MAP coverage     — all supported indicator types map correctly
 */
'use strict';

const TI = require('../services/threatIntelPoller.js');

const {
  normalizeKevEntry,
  normalizeOtxIndicator,
  isPollingEnabled,
  upsertIoc,
  enrichAlertWithTI,
  _OTX_TYPE_MAP,
  _CISA_KEV_URL,
  _OTX_BASE_URL,
  _hashShort,
} = TI;

/* ════════════════════════════════════════════════════════════════
   isPollingEnabled — feature flag (default FALSE)
════════════════════════════════════════════════════════════════ */
describe('isPollingEnabled', () => {
  const original = process.env.ENABLE_THREAT_INTEL_POLLING;
  afterEach(() => {
    if (original === undefined) delete process.env.ENABLE_THREAT_INTEL_POLLING;
    else process.env.ENABLE_THREAT_INTEL_POLLING = original;
  });

  test('returns false by default (not set)', () => {
    delete process.env.ENABLE_THREAT_INTEL_POLLING;
    expect(isPollingEnabled()).toBe(false);
  });

  test('returns false when ENABLE_THREAT_INTEL_POLLING=false', () => {
    process.env.ENABLE_THREAT_INTEL_POLLING = 'false';
    expect(isPollingEnabled()).toBe(false);
  });

  test('returns false when ENABLE_THREAT_INTEL_POLLING=0', () => {
    process.env.ENABLE_THREAT_INTEL_POLLING = '0';
    expect(isPollingEnabled()).toBe(false);
  });

  test('returns true when ENABLE_THREAT_INTEL_POLLING=true', () => {
    process.env.ENABLE_THREAT_INTEL_POLLING = 'true';
    expect(isPollingEnabled()).toBe(true);
  });

  test('returns true when ENABLE_THREAT_INTEL_POLLING=1', () => {
    process.env.ENABLE_THREAT_INTEL_POLLING = '1';
    expect(isPollingEnabled()).toBe(true);
  });

  test('returns true when ENABLE_THREAT_INTEL_POLLING=yes', () => {
    process.env.ENABLE_THREAT_INTEL_POLLING = 'yes';
    expect(isPollingEnabled()).toBe(true);
  });
});

/* ════════════════════════════════════════════════════════════════
   Constants
════════════════════════════════════════════════════════════════ */
describe('Constants', () => {
  test('CISA_KEV_URL points to CISA feed', () => {
    expect(_CISA_KEV_URL).toContain('cisa.gov');
    expect(_CISA_KEV_URL).toContain('known_exploited_vulnerabilities.json');
  });

  test('OTX_BASE_URL points to AlienVault OTX', () => {
    expect(_OTX_BASE_URL).toContain('alienvault.com');
  });
});

/* ════════════════════════════════════════════════════════════════
   _hashShort — deterministic FNV-1a 8-char hex
════════════════════════════════════════════════════════════════ */
describe('_hashShort', () => {
  test('returns an 8-character hex string', () => {
    const h = _hashShort('192.168.1.1');
    expect(h).toHaveLength(8);
    expect(h).toMatch(/^[0-9a-f]{8}$/);
  });

  test('is deterministic', () => {
    expect(_hashShort('example.com')).toBe(_hashShort('example.com'));
  });

  test('different inputs produce different outputs', () => {
    expect(_hashShort('abc')).not.toBe(_hashShort('xyz'));
  });

  test('empty string does not throw', () => {
    expect(() => _hashShort('')).not.toThrow();
    expect(_hashShort('')).toHaveLength(8);
  });
});

/* ════════════════════════════════════════════════════════════════
   normalizeKevEntry — ported from CisaKevClient.to_ioc()
════════════════════════════════════════════════════════════════ */
describe('normalizeKevEntry', () => {
  const SAMPLE_ENTRY = {
    cveID:            'CVE-2024-12345',
    vulnerabilityName: 'Test Vulnerability in Widget v1.0',
    shortDescription: 'Allows RCE via crafted request',
    vendorProject:    'WidgetCo',
    product:          'Widget',
    requiredAction:   'Apply patch immediately',
    dueDate:          '2024-03-15',
    dateAdded:        '2024-01-01',
    knownRansomwareCampaignUse: 'Known',
  };

  test('returns an object with correct ioc_type=vulnerability', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc).not.toBeNull();
    expect(ioc.ioc_type).toBe('vulnerability');
  });

  test('ioc_value is the CVE ID', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.ioc_value).toBe('CVE-2024-12345');
  });

  test('source is cisa-kev', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.source).toBe('cisa-kev');
  });

  test('source_ref follows format cisa-kev:{cveID}', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.source_ref).toBe('cisa-kev:CVE-2024-12345');
  });

  test('tlp is white', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.tlp).toBe('white');
  });

  test('tags contain kev, cisa, exploited', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.tags).toContain('kev');
    expect(ioc.tags).toContain('cisa');
    expect(ioc.tags).toContain('exploited');
  });

  test('confidence is 90 (high-confidence CISA KEV)', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.confidence).toBe(90);
  });

  test('known_ransomware is "known" when knownRansomwareCampaignUse=Known', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.known_ransomware).toBe('known');
  });

  test('known_ransomware maps case-insensitively', () => {
    const ioc = normalizeKevEntry({ ...SAMPLE_ENTRY, knownRansomwareCampaignUse: 'KNOWN' });
    expect(ioc.known_ransomware).toBe('known');
  });

  test('unknown ransomware use preserves original value', () => {
    const ioc = normalizeKevEntry({ ...SAMPLE_ENTRY, knownRansomwareCampaignUse: 'Unknown' });
    expect(ioc.known_ransomware).toBe('Unknown');
  });

  test('vendor_project is populated', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.vendor_project).toBe('WidgetCo');
  });

  test('product is populated', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.product).toBe('Widget');
  });

  test('due_date is populated', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.due_date).toBe('2024-03-15');
  });

  test('raw_payload is the original entry', () => {
    const ioc = normalizeKevEntry(SAMPLE_ENTRY);
    expect(ioc.raw_payload).toBe(SAMPLE_ENTRY);
  });

  test('returns null for entry without cveID', () => {
    const ioc = normalizeKevEntry({ vulnerabilityName: 'No CVE' });
    expect(ioc).toBeNull();
  });

  test('returns null for null input', () => {
    expect(normalizeKevEntry(null)).toBeNull();
  });

  test('returns null for non-object input', () => {
    expect(normalizeKevEntry('string')).toBeNull();
    expect(normalizeKevEntry(42)).toBeNull();
  });

  test('handles alternative cve_id field name', () => {
    const ioc = normalizeKevEntry({ cve_id: 'CVE-2024-99999' });
    expect(ioc).not.toBeNull();
    expect(ioc.ioc_value).toBe('CVE-2024-99999');
    expect(ioc.source_ref).toBe('cisa-kev:CVE-2024-99999');
  });

  test('trims whitespace from CVE ID', () => {
    const ioc = normalizeKevEntry({ cveID: '  CVE-2024-11111  ' });
    expect(ioc.ioc_value).toBe('CVE-2024-11111');
    expect(ioc.source_ref).toBe('cisa-kev:CVE-2024-11111');
  });
});

/* ════════════════════════════════════════════════════════════════
   normalizeOtxIndicator — ported from OtxClient
════════════════════════════════════════════════════════════════ */
describe('normalizeOtxIndicator', () => {
  const SAMPLE_PULSE = {
    id:       'pulse-abc-123',
    name:     'Test Threat Pulse',
    TLP:      'green',
    tags:     ['apt', 'ransomware'],
    created:  '2024-06-01T12:00:00Z',
    modified: '2024-06-10T12:00:00Z',
  };

  const IP_IND = { indicator: '192.0.2.1', type: 'IPv4', description: 'C2 server' };
  const DOMAIN_IND = { indicator: 'evil.example.com', type: 'domain' };
  const URL_IND    = { indicator: 'http://evil.example.com/payload', type: 'URL' };
  const SHA256_IND = { indicator: 'a'.repeat(64), type: 'FileHash-SHA256' };
  const CVE_IND    = { indicator: 'CVE-2024-9999', type: 'CVE' };

  test('returns null for null indicator', () => {
    expect(normalizeOtxIndicator(null, SAMPLE_PULSE)).toBeNull();
  });

  test('returns null for indicator without indicator field', () => {
    expect(normalizeOtxIndicator({ type: 'IPv4' }, SAMPLE_PULSE)).toBeNull();
  });

  test('returns null for unsupported indicator type', () => {
    expect(normalizeOtxIndicator({ indicator: 'x', type: 'UNSUPPORTED_TYPE' }, SAMPLE_PULSE)).toBeNull();
  });

  test('IPv4 maps to ioc_type=ip', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc).not.toBeNull();
    expect(ioc.ioc_type).toBe('ip');
  });

  test('IPv6 maps to ioc_type=ip', () => {
    const ioc = normalizeOtxIndicator({ indicator: '::1', type: 'IPv6' }, SAMPLE_PULSE);
    expect(ioc.ioc_type).toBe('ip');
  });

  test('domain maps to ioc_type=domain', () => {
    const ioc = normalizeOtxIndicator(DOMAIN_IND, SAMPLE_PULSE);
    expect(ioc.ioc_type).toBe('domain');
  });

  test('URL maps to ioc_type=url', () => {
    const ioc = normalizeOtxIndicator(URL_IND, SAMPLE_PULSE);
    expect(ioc.ioc_type).toBe('url');
  });

  test('FileHash-SHA256 maps to ioc_type=file_hash', () => {
    const ioc = normalizeOtxIndicator(SHA256_IND, SAMPLE_PULSE);
    expect(ioc.ioc_type).toBe('file_hash');
  });

  test('CVE maps to ioc_type=vulnerability', () => {
    const ioc = normalizeOtxIndicator(CVE_IND, SAMPLE_PULSE);
    expect(ioc.ioc_type).toBe('vulnerability');
  });

  test('source is otx', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.source).toBe('otx');
  });

  test('source_ref follows otx:{pulseId}:{hash} format', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.source_ref).toMatch(/^otx:pulse-abc-123:[0-9a-f]{8}$/);
  });

  test('two different indicators from same pulse have different source_refs (dedup)', () => {
    const ioc1 = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    const ioc2 = normalizeOtxIndicator(DOMAIN_IND, SAMPLE_PULSE);
    expect(ioc1.source_ref).not.toBe(ioc2.source_ref);
  });

  test('same indicator from same pulse always produces same source_ref (determinism)', () => {
    const ioc1 = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    const ioc2 = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc1.source_ref).toBe(ioc2.source_ref);
  });

  test('tlp is mapped from pulse.TLP (case-insensitive)', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.tlp).toBe('green');
  });

  test('invalid TLP falls back to white', () => {
    const ioc = normalizeOtxIndicator(IP_IND, { ...SAMPLE_PULSE, TLP: 'PURPLE' });
    expect(ioc.tlp).toBe('white');
  });

  test('tags include "otx" plus pulse tags', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.tags).toContain('otx');
    expect(ioc.tags).toContain('apt');
    expect(ioc.tags).toContain('ransomware');
  });

  test('description falls back to pulse name when indicator has no description', () => {
    const ioc = normalizeOtxIndicator(DOMAIN_IND, SAMPLE_PULSE);
    expect(ioc.description).toBe('Test Threat Pulse');
  });

  test('indicator description is preferred over pulse name', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.description).toBe('C2 server');
  });

  test('date_added is extracted from pulse.created (YYYY-MM-DD)', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.date_added).toBe('2024-06-01');
  });

  test('ioc_value is the indicator string', () => {
    const ioc = normalizeOtxIndicator(IP_IND, SAMPLE_PULSE);
    expect(ioc.ioc_value).toBe('192.0.2.1');
  });

  test('works with null pulse (graceful degradation)', () => {
    const ioc = normalizeOtxIndicator(IP_IND, null);
    expect(ioc).not.toBeNull();
    expect(ioc.ioc_type).toBe('ip');
    expect(ioc.source_ref).toMatch(/^otx:unknown:[0-9a-f]{8}$/);
  });
});

/* ════════════════════════════════════════════════════════════════
   OTX_TYPE_MAP coverage
════════════════════════════════════════════════════════════════ */
describe('OTX_TYPE_MAP', () => {
  test('all required indicator types are mapped', () => {
    const required = ['IPv4','IPv6','domain','hostname','URL',
                      'FileHash-MD5','FileHash-SHA1','FileHash-SHA256',
                      'email','CVE'];
    for (const type of required) {
      expect(_OTX_TYPE_MAP[type]).toBeDefined();
    }
  });

  test('all mapped values are valid ioc_type strings', () => {
    const validTypes = ['ip','domain','url','file_hash','email','vulnerability',
                        'username','asn','cidr','mutex','registry_key','other'];
    for (const [, v] of Object.entries(_OTX_TYPE_MAP)) {
      expect(validTypes).toContain(v);
    }
  });
});

/* ════════════════════════════════════════════════════════════════
   upsertIoc — mocked Supabase: new vs update paths
════════════════════════════════════════════════════════════════ */
describe('upsertIoc', () => {
  const SAMPLE_IOC = {
    ioc_type:    'vulnerability',
    ioc_value:   'CVE-2024-12345',
    source:      'cisa-kev',
    source_ref:  'cisa-kev:CVE-2024-12345',
    description: 'Test CVE',
    tlp:         'white',
    tags:        ['kev'],
    confidence:  90,
    raw_payload: {},
  };

  function _mockSBNew () {
    // No existing record — insert path
    return {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: () => Promise.resolve({ data: null, error: null }),
          }),
        }),
        insert: (row) => ({
          select: () => ({}),
          // Fire-and-forget — just needs to not reject
          then: undefined,
          // Simple success
          error: null,
        }),
        update: () => ({ eq: () => ({ error: null }) }),
      }),
    };
  }

  function _mockSBUpdate () {
    // Existing record — update path
    const existing = { id: 'existing-id', last_seen_at: '2024-01-01T00:00:00Z' };
    return {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: () => Promise.resolve({ data: existing, error: null }),
          }),
        }),
        insert: () => ({ error: null }),
        update: () => ({
          eq: () => Promise.resolve({ error: null }),
        }),
      }),
    };
  }

  test('returns { isNew: true, isUpdated: false } for new IOC', async () => {
    // Build a proper mock that handles insert correctly
    const sb = {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: () => Promise.resolve({ data: null, error: null }),
          }),
        }),
        insert: (row) => Promise.resolve({ error: null }),
        update: () => ({ eq: () => Promise.resolve({ error: null }) }),
      }),
    };

    const result = await upsertIoc(sb, SAMPLE_IOC);
    expect(result.isNew).toBe(true);
    expect(result.isUpdated).toBe(false);
  });

  test('returns { isNew: false, isUpdated: true } for existing IOC', async () => {
    const existing = { id: 'ex-id', last_seen_at: '2024-01-01T00:00:00Z' };
    const sb = {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: () => Promise.resolve({ data: existing, error: null }),
          }),
        }),
        insert: (row) => Promise.resolve({ error: null }),
        update: () => ({
          eq: () => Promise.resolve({ error: null }),
        }),
      }),
    };

    const result = await upsertIoc(sb, SAMPLE_IOC);
    expect(result.isNew).toBe(false);
    expect(result.isUpdated).toBe(true);
  });

  test('returns { isNew: false, isUpdated: false } for null/empty IOC', async () => {
    const sb = { from: () => ({}) };
    const result = await upsertIoc(sb, null);
    expect(result.isNew).toBe(false);
    expect(result.isUpdated).toBe(false);
  });

  test('returns { isNew: false, isUpdated: false } for IOC without source_ref', async () => {
    const sb = { from: () => ({}) };
    const result = await upsertIoc(sb, { ioc_type: 'ip', ioc_value: '1.2.3.4' });
    expect(result.isNew).toBe(false);
    expect(result.isUpdated).toBe(false);
  });

  test('throws on Supabase insert error', async () => {
    const sb = {
      from: () => ({
        select: () => ({
          eq: () => ({
            maybeSingle: () => Promise.resolve({ data: null, error: null }),
          }),
        }),
        insert: () => Promise.resolve({ error: { message: 'DB insert failed' } }),
        update: () => ({ eq: () => Promise.resolve({ error: null }) }),
      }),
    };

    await expect(upsertIoc(sb, SAMPLE_IOC)).rejects.toThrow('upsertIoc insert failed');
  });
});

/* ════════════════════════════════════════════════════════════════
   enrichAlertWithTI — mocked Supabase IOC matching
════════════════════════════════════════════════════════════════ */
describe('enrichAlertWithTI', () => {
  const MOCK_IOC = {
    id:          'ioc-1',
    ioc_type:    'ip',
    ioc_value:   '192.0.2.1',
    source:      'cisa-kev',
    source_ref:  'cisa-kev:CVE-2024-1',
    description: 'Test C2',
    tlp:         'white',
    tags:        ['kev'],
    confidence:  90,
    due_date:    null,
  };

  function _mockSBHit (hits) {
    return {
      from: () => ({
        select: () => ({
          in: () => ({
            eq: () => ({
              limit: () => Promise.resolve({ data: hits, error: null }),
            }),
          }),
        }),
      }),
    };
  }

  test('returns hits when alert ioc_value matches catalog', async () => {
    const sb = _mockSBHit([MOCK_IOC]);
    const result = await enrichAlertWithTI(sb, { ioc_value: '192.0.2.1', ioc_type: 'ip' });
    expect(result.hitCount).toBe(1);
    expect(result.hits).toHaveLength(1);
    expect(result.hits[0].ioc_value).toBe('192.0.2.1');
  });

  test('returns empty hits when no candidates (empty alert)', async () => {
    const sb = _mockSBHit([]);
    const result = await enrichAlertWithTI(sb, {});
    expect(result.hitCount).toBe(0);
    expect(result.hits).toHaveLength(0);
  });

  test('extracts src_ip from alert body', async () => {
    const sb = _mockSBHit([MOCK_IOC]);
    const result = await enrichAlertWithTI(sb, { src_ip: '192.0.2.1' });
    expect(result.hitCount).toBe(1);
  });

  test('extracts dst_ip from alert body', async () => {
    const sb = _mockSBHit([MOCK_IOC]);
    const result = await enrichAlertWithTI(sb, { dst_ip: '192.0.2.1' });
    expect(result.hitCount).toBe(1);
  });

  test('extracts file_hash from alert body', async () => {
    const hashIoc = { ...MOCK_IOC, ioc_value: 'abc123', ioc_type: 'file_hash' };
    const sb = _mockSBHit([hashIoc]);
    const result = await enrichAlertWithTI(sb, { file_hash: 'abc123' });
    expect(result.hitCount).toBe(1);
  });

  test('extracts CVE from metadata.cve_id', async () => {
    const cveIoc = { ...MOCK_IOC, ioc_value: 'CVE-2024-12345', ioc_type: 'vulnerability' };
    const sb = _mockSBHit([cveIoc]);
    const result = await enrichAlertWithTI(sb, { metadata: { cve_id: 'CVE-2024-12345' } });
    expect(result.hitCount).toBe(1);
  });

  test('returns { hits:[], hitCount:0 } on Supabase error (non-fatal)', async () => {
    const sb = {
      from: () => ({
        select: () => ({
          in: () => ({
            eq: () => ({
              limit: () => Promise.resolve({ data: null, error: { message: 'DB error' } }),
            }),
          }),
        }),
      }),
    };
    const result = await enrichAlertWithTI(sb, { ioc_value: '1.2.3.4' });
    expect(result.hitCount).toBe(0);
    expect(result.hits).toHaveLength(0);
  });

  test('deduplicates candidate values (ioc_value === src_ip)', async () => {
    // If ioc_value and src_ip are the same, should only appear once in query
    const sb = {
      from: () => ({
        select: () => ({
          in: (col, values) => {
            // The values array should have unique entries
            const unique = new Set(values);
            expect(unique.size).toBe(values.length);
            return {
              eq: () => ({
                limit: () => Promise.resolve({ data: [], error: null }),
              }),
            };
          },
        }),
      }),
    };
    await enrichAlertWithTI(sb, { ioc_value: '1.2.3.4', src_ip: '1.2.3.4' });
  });
});

/* ════════════════════════════════════════════════════════════════
   In-Postgres dedup design contract
════════════════════════════════════════════════════════════════ */
describe('In-Postgres dedup contract', () => {
  test('KEV source_ref is always cisa-kev:{cveID}', () => {
    const entry = { cveID: 'CVE-2024-42000' };
    const ioc   = normalizeKevEntry(entry);
    expect(ioc.source_ref).toBe('cisa-kev:CVE-2024-42000');
  });

  test('two KEV entries with same CVE produce same source_ref (unique constraint)', () => {
    const e1 = normalizeKevEntry({ cveID: 'CVE-2024-1111', vendorProject: 'VendorA' });
    const e2 = normalizeKevEntry({ cveID: 'CVE-2024-1111', vendorProject: 'VendorB' });
    expect(e1.source_ref).toBe(e2.source_ref);
  });

  test('two OTX indicators with same value+pulse produce same source_ref', () => {
    const pulse = { id: 'p1', name: 'pulse' };
    const ind   = { indicator: '10.0.0.1', type: 'IPv4' };
    const ioc1  = normalizeOtxIndicator(ind, pulse);
    const ioc2  = normalizeOtxIndicator(ind, pulse);
    expect(ioc1.source_ref).toBe(ioc2.source_ref);
  });

  test('two OTX indicators with different values produce different source_refs', () => {
    const pulse = { id: 'p1', name: 'pulse' };
    const ioc1  = normalizeOtxIndicator({ indicator: '10.0.0.1', type: 'IPv4' }, pulse);
    const ioc2  = normalizeOtxIndicator({ indicator: '10.0.0.2', type: 'IPv4' }, pulse);
    expect(ioc1.source_ref).not.toBe(ioc2.source_ref);
  });
});
