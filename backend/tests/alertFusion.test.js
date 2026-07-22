/**
 * alertFusion.test.js — Unit tests for js/alert-fusion.js (Phase 2)
 *
 * Covers pure/synchronous functions only:
 *   fingerprintAlert, correlationKey, scoreConfidence, sha256Hex
 * DB-backed functions (checkDuplicate, correlateAlert, fuseAlert, postFuseAlert)
 * are covered via integration tests / manual QA.
 */
'use strict';

const Fusion = require('../../js/alert-fusion.js');

const {
  fingerprintAlert,
  correlationKey,
  scoreConfidence,
  sha256Hex,
  BASE_WEIGHTS,
  ML_ABSENT_WEIGHTS,
  HIGH_THRESHOLD,
  LOW_THRESHOLD,
  SEVERITY_CONTRIBUTION,
} = Fusion;

/* ─────────────────────────────────────────────────────────────
   sha256Hex
───────────────────────────────────────────────────────────── */
describe('sha256Hex', () => {
  test('returns 64-char hex string', () => {
    const h = sha256Hex('hello');
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]+$/);
  });

  test('is deterministic — same input → same digest', () => {
    expect(sha256Hex('test')).toBe(sha256Hex('test'));
  });

  test('known SHA-256 of empty string', () => {
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  test('different inputs produce different digests', () => {
    expect(sha256Hex('a')).not.toBe(sha256Hex('b'));
  });
});

/* ─────────────────────────────────────────────────────────────
   fingerprintAlert  (9-field canonical SHA-256)
───────────────────────────────────────────────────────────── */
describe('fingerprintAlert', () => {
  const BASE_ALERT = {
    source:    'siem',
    title:     'Suspicious login',
    metadata:  { src_ip: '1.2.3.4', dst_ip: '5.6.7.8', username: 'alice' },
  };
  const TENANT = 'tenant-abc';

  test('returns 64-char hex', () => {
    const fp = fingerprintAlert(BASE_ALERT, TENANT);
    expect(fp).toHaveLength(64);
    expect(fp).toMatch(/^[0-9a-f]+$/);
  });

  test('same alert + tenant → same fingerprint (deterministic)', () => {
    expect(fingerprintAlert(BASE_ALERT, TENANT)).toBe(fingerprintAlert(BASE_ALERT, TENANT));
  });

  test('different tenant → different fingerprint', () => {
    expect(fingerprintAlert(BASE_ALERT, 'tenant-xyz')).not.toBe(fingerprintAlert(BASE_ALERT, TENANT));
  });

  test('different title → different fingerprint', () => {
    const alt = { ...BASE_ALERT, title: 'Other alert' };
    expect(fingerprintAlert(alt, TENANT)).not.toBe(fingerprintAlert(BASE_ALERT, TENANT));
  });

  test('mitre_techniques are sorted before hashing (order-independent)', () => {
    const a = { ...BASE_ALERT, mitre_techniques: ['T1059', 'T1003'] };
    const b = { ...BASE_ALERT, mitre_techniques: ['T1003', 'T1059'] };
    expect(fingerprintAlert(a, TENANT)).toBe(fingerprintAlert(b, TENANT));
  });

  test('mitre_technique (singular) is included when mitre_techniques absent', () => {
    const a = { ...BASE_ALERT, mitre_technique: 'T1059' };
    const b = { ...BASE_ALERT, mitre_techniques: ['T1059'] };
    expect(fingerprintAlert(a, TENANT)).toBe(fingerprintAlert(b, TENANT));
  });

  test('null optional fields produce stable fingerprint (no undefined coercion)', () => {
    const sparse = { source: 'test', title: 'X' };
    const fp = fingerprintAlert(sparse, TENANT);
    expect(fp).toHaveLength(64);
  });

  test('same alert different sources → different fingerprints', () => {
    const a = { ...BASE_ALERT, source: 'siem' };
    const b = { ...BASE_ALERT, source: 'edr' };
    expect(fingerprintAlert(a, TENANT)).not.toBe(fingerprintAlert(b, TENANT));
  });
});

/* ─────────────────────────────────────────────────────────────
   correlationKey
───────────────────────────────────────────────────────────── */
describe('correlationKey', () => {
  test('format is tenantId:entity:tactic', () => {
    const key = correlationKey(
      { metadata: { src_ip: '10.0.0.1', mitre_tactics: ['TA0001'] } },
      'tid1'
    );
    expect(key).toBe('tid1:10.0.0.1:TA0001');
  });

  test('falls back to hostname when src_ip absent', () => {
    const key = correlationKey(
      { metadata: { hostname: 'workstation1' } },
      'tid1'
    );
    expect(key).toContain('workstation1');
  });

  test('falls back to username when both src_ip and hostname absent', () => {
    const key = correlationKey(
      { metadata: { username: 'bob' } },
      'tid1'
    );
    expect(key).toContain('bob');
  });

  test('uses "unknown" entity + tactic when no entity fields present', () => {
    const key = correlationKey({}, 'tid1');
    expect(key).toBe('tid1:unknown:unknown');
  });

  test('uses only first tactic from array', () => {
    const key = correlationKey(
      { metadata: { src_ip: '1.1.1.1', mitre_tactics: ['TA0002', 'TA0003'] } },
      'tid1'
    );
    expect(key).toBe('tid1:1.1.1.1:TA0002');
  });
});

/* ─────────────────────────────────────────────────────────────
   scoreConfidence — bands
───────────────────────────────────────────────────────────── */
describe('scoreConfidence — label bands', () => {
  test('critical severity + TI hit → HIGH confidence', () => {
    const result = scoreConfidence(
      { severity: 'CRITICAL', mitre_techniques: ['T1059', 'T1003', 'T1055'] },
      { enrichments: { kev: { hit: true } } }
    );
    expect(result.label).toBe('high');
    expect(result.score).toBeGreaterThanOrEqual(HIGH_THRESHOLD);
  });

  test('low severity + no TI + no mitre → LOW confidence', () => {
    const result = scoreConfidence(
      { severity: 'LOW', mitre_techniques: [] },
      {}
    );
    expect(result.label).toBe('low');
    expect(result.score).toBeLessThan(LOW_THRESHOLD);
  });

  test('medium severity + TI hit → MEDIUM confidence', () => {
    // MEDIUM severity (contribution=0) + single TI hit + 1 MITRE technique
    // should lift score above LOW_THRESHOLD and below HIGH_THRESHOLD.
    const result = scoreConfidence(
      { severity: 'MEDIUM', mitre_techniques: ['T1059'] },
      { enrichments: { otx: [{ id: '1' }] } }
    );
    expect(result.label).toBe('medium');
    expect(result.score).toBeGreaterThanOrEqual(LOW_THRESHOLD);
    expect(result.score).toBeLessThan(HIGH_THRESHOLD);
  });
});

/* ─────────────────────────────────────────────────────────────
   scoreConfidence — score arithmetic
───────────────────────────────────────────────────────────── */
describe('scoreConfidence — score arithmetic', () => {
  test('score is always in [0, 1]', () => {
    const cases = [
      { severity: 'CRITICAL' },
      { severity: 'INFO' },
      { severity: 'MEDIUM', mitre_techniques: ['T1059'] },
    ];
    cases.forEach(alert => {
      const { score } = scoreConfidence(alert, {});
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(1);
    });
  });

  test('formula: 0.5 + Σ(w_i * c_i) clamped to [0,1]', () => {
    // Pure severity=MEDIUM (contribution=0), all other factors neutral/negative
    // With ML gap: both ml_anomaly and ml_priority absent → rescaled weights
    const result = scoreConfidence({ severity: 'MEDIUM' }, {});
    // severity contribution = 0, no TI (-0.3*w), no mitre (-0.4*w), no IOC (-0.6*w)
    // Score will be < 0.5
    expect(result.score).toBeLessThan(0.5);
  });

  test('rationale array is sorted by abs(contribution * weight) descending', () => {
    const result = scoreConfidence(
      { severity: 'CRITICAL', mitre_techniques: ['T1059', 'T1003'] },
      { enrichments: { kev: { hit: true } } }
    );
    const impacts = result.rationale.map(f => Math.abs(f.contribution * f.weight));
    for (let i = 1; i < impacts.length; i++) {
      expect(impacts[i - 1]).toBeGreaterThanOrEqual(impacts[i]);
    }
  });

  test('rationale contains known factor keys', () => {
    const result = scoreConfidence({ severity: 'HIGH' }, {});
    const keys = result.rationale.map(f => f.factor);
    expect(keys).toContain('severity');
    expect(keys).toContain('mitre');
    expect(keys).toContain('threat_intel');
    expect(keys).toContain('upstream_risk');
    expect(keys).toContain('ioc_density');
  });
});

/* ─────────────────────────────────────────────────────────────
   scoreConfidence — ML gap handling
───────────────────────────────────────────────────────────── */
describe('scoreConfidence — ML gap', () => {
  test('mlGap=true when ml factors absent', () => {
    const result = scoreConfidence({ severity: 'HIGH' }, {});
    expect(result.mlGap).toBe(true);
  });

  test('mlGapNote is a non-empty string when mlGap=true', () => {
    const result = scoreConfidence({ severity: 'HIGH' }, {});
    expect(typeof result.mlGapNote).toBe('string');
    expect(result.mlGapNote.length).toBeGreaterThan(0);
  });

  test('ML_ABSENT_WEIGHTS sum to 1.0 (rescaling is correct)', () => {
    const total = Object.values(ML_ABSENT_WEIGHTS).reduce((s, w) => s + w, 0);
    expect(total).toBeCloseTo(1.0, 5);
  });

  test('BASE_WEIGHTS sum to 1.0', () => {
    const total = Object.values(BASE_WEIGHTS).reduce((s, w) => s + w, 0);
    expect(total).toBeCloseTo(1.0, 5);
  });

  test('mlGap=false when mlAnomalyScore and mlPriorityScore provided', () => {
    const result = scoreConfidence(
      { severity: 'HIGH' },
      { mlAnomalyScore: 0.7, mlPriorityScore: 0.6 }
    );
    expect(result.mlGap).toBe(false);
    expect(result.mlGapNote).toBeNull();
  });

  test('UEBA score substitutes ml_anomaly and reduces mlGap impact', () => {
    const withUEBA    = scoreConfidence({ severity: 'HIGH' }, { uebaScore: 6.0 });
    const withoutUEBA = scoreConfidence({ severity: 'HIGH' }, {});
    // With high UEBA score, confidence should be >= without UEBA
    expect(withUEBA.score).toBeGreaterThanOrEqual(withoutUEBA.score);
  });

  test('mlGapNote mentions UEBA when uebaScore provided but ml_priority still absent', () => {
    const result = scoreConfidence({ severity: 'MEDIUM' }, { uebaScore: 5.0 });
    expect(result.mlGapNote).toMatch(/UEBA|ml_priority/i);
  });
});

/* ─────────────────────────────────────────────────────────────
   scoreConfidence — IOC density
───────────────────────────────────────────────────────────── */
describe('scoreConfidence — IOC density', () => {
  test('0 IOC fields → negative contribution', () => {
    const result = scoreConfidence({ severity: 'MEDIUM' }, {});
    const ioc = result.rationale.find(f => f.factor === 'ioc_density');
    expect(ioc.contribution).toBeLessThan(0);
  });

  test('5+ IOC fields → positive contribution', () => {
    const alert = {
      severity: 'MEDIUM',
      metadata: {
        src_ip: '1.1.1.1', dst_ip: '2.2.2.2', hostname: 'h1',
        username: 'alice', file_hash: 'abc123', domain: 'evil.com',
      },
    };
    const result = scoreConfidence(alert, {});
    const ioc = result.rationale.find(f => f.factor === 'ioc_density');
    expect(ioc.contribution).toBeGreaterThan(0);
  });
});

/* ─────────────────────────────────────────────────────────────
   scoreConfidence — threat intel
───────────────────────────────────────────────────────────── */
describe('scoreConfidence — threat intel enrichments', () => {
  test('single TI source hit → positive contribution', () => {
    const result = scoreConfidence(
      { severity: 'MEDIUM' },
      { enrichments: { kev: { hit: true } } }
    );
    const ti = result.rationale.find(f => f.factor === 'threat_intel');
    expect(ti.contribution).toBeGreaterThan(0);
  });

  test('multiple TI source hits → max contribution', () => {
    const result = scoreConfidence(
      { severity: 'MEDIUM' },
      { enrichments: { kev: { hit: true }, misp: [{ id: '1' }] } }
    );
    const ti = result.rationale.find(f => f.factor === 'threat_intel');
    expect(ti.contribution).toBe(1.0);
  });

  test('no enrichments → negative contribution', () => {
    const result = scoreConfidence({ severity: 'MEDIUM' }, { enrichments: null });
    const ti = result.rationale.find(f => f.factor === 'threat_intel');
    expect(ti.contribution).toBeLessThan(0);
  });
});

/* ─────────────────────────────────────────────────────────────
   SEVERITY_CONTRIBUTION coverage
───────────────────────────────────────────────────────────── */
describe('SEVERITY_CONTRIBUTION constants', () => {
  test('CRITICAL maps to 1.0', () => expect(SEVERITY_CONTRIBUTION.CRITICAL).toBe(1.0));
  test('HIGH maps to 0.6',     () => expect(SEVERITY_CONTRIBUTION.HIGH).toBe(0.6));
  test('MEDIUM maps to 0.0',   () => expect(SEVERITY_CONTRIBUTION.MEDIUM).toBe(0.0));
  test('LOW maps to -0.5',     () => expect(SEVERITY_CONTRIBUTION.LOW).toBe(-0.5));
  test('INFO maps to -1.0',    () => expect(SEVERITY_CONTRIBUTION.INFO).toBe(-1.0));
});
