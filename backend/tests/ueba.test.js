/**
 * ueba.test.js — Unit tests for js/ueba.js (Phase 2)
 *
 * Tests cover pure-algorithm functions only (no Supabase I/O).
 * DB-backed functions are validated via integration tests / manual QA.
 */
'use strict';

const UEBA = require('../../js/ueba.js');

const {
  welfordUpdate,
  computeZScore,
  compositeScore,
  riskLevel,
  extractAlertFeatures,
  ANOMALY_THRESHOLD,
  COMPOSITE_SCORE_CAP,
  PEER_GROUP_MIN_SIZE,
} = UEBA;

/* ─────────────────────────────────────────────────────────────
   welfordUpdate
───────────────────────────────────────────────────────────── */
describe('welfordUpdate', () => {
  test('initialises a new feature entry on first observation', () => {
    const stats = {};
    welfordUpdate(stats, 'login_count', 10);
    expect(stats.login_count).toBeDefined();
    expect(stats.login_count.n).toBe(1);
    expect(stats.login_count.mean).toBeCloseTo(10);
    expect(stats.login_count.M2).toBe(0);
    expect(stats.login_count.std).toBe(0);  // std=0 for n=1
  });

  test('returns 0 std after identical observations', () => {
    const stats = {};
    for (let i = 0; i < 5; i++) welfordUpdate(stats, 'x', 7);
    expect(stats.x.mean).toBeCloseTo(7);
    expect(stats.x.std).toBeCloseTo(0);
  });

  test('Welford mean converges correctly for [2, 4, 4, 4, 5, 5, 7, 9]', () => {
    // Classic Welford example — population mean=5, population std=2
    const stats = {};
    [2, 4, 4, 4, 5, 5, 7, 9].forEach(v => welfordUpdate(stats, 'v', v));
    expect(stats.v.mean).toBeCloseTo(5.0);
    // Sample variance = 4.571…, std ≈ 2.138
    expect(stats.v.std).toBeCloseTo(2.138, 1);
  });

  test('correctly tracks n increments for each call', () => {
    const stats = {};
    for (let i = 1; i <= 10; i++) welfordUpdate(stats, 'cnt', i);
    expect(stats.cnt.n).toBe(10);
    expect(stats.cnt.count).toBe(10);  // alias
  });

  test('second observation updates mean properly', () => {
    const stats = {};
    welfordUpdate(stats, 'a', 0);
    welfordUpdate(stats, 'a', 10);
    expect(stats.a.mean).toBeCloseTo(5.0);
    expect(stats.a.n).toBe(2);
  });

  test('M2 accumulates correctly for two values [0, 10]', () => {
    // Welford M2 after [0, 10]: delta1=0-0=0 → mean=0; delta2=10-0=10 → mean=5;
    // delta_final = 10 - 5 = 5; M2 = 0*10=0 + ... → M2=50; var=M2/1=50; std=√50≈7.07
    const stats = {};
    welfordUpdate(stats, 'v', 0);
    welfordUpdate(stats, 'v', 10);
    expect(stats.v.std).toBeCloseTo(7.071, 2);
  });

  test('operates independently per feature key', () => {
    const stats = {};
    welfordUpdate(stats, 'featureA', 1);
    welfordUpdate(stats, 'featureB', 100);
    expect(stats.featureA.mean).toBeCloseTo(1);
    expect(stats.featureB.mean).toBeCloseTo(100);
  });

  test('returns the same stats object (mutation in place)', () => {
    const stats = {};
    const returned = welfordUpdate(stats, 'x', 5);
    expect(returned).toBe(stats);
  });
});

/* ─────────────────────────────────────────────────────────────
   computeZScore
───────────────────────────────────────────────────────────── */
describe('computeZScore', () => {
  test('returns 0 for unknown feature', () => {
    expect(computeZScore({}, 'unknown', 99)).toBe(0.0);
  });

  test('returns 0 when std < epsilon (stable baseline)', () => {
    const stats = {};
    for (let i = 0; i < 5; i++) welfordUpdate(stats, 'x', 42);
    expect(computeZScore(stats, 'x', 42)).toBe(0.0);
    expect(computeZScore(stats, 'x', 100)).toBe(0.0); // std still ~0
  });

  test('returns correct z-score for 2-std deviation', () => {
    // Build baseline: mean=5, std≈2.138 from [2,4,4,4,5,5,7,9]
    const stats = {};
    [2, 4, 4, 4, 5, 5, 7, 9].forEach(v => welfordUpdate(stats, 'v', v));
    // value = 9.276 → z ≈ (9.276-5)/2.138 ≈ 2.0
    const z = computeZScore(stats, 'v', 9.276);
    expect(z).toBeCloseTo(2.0, 0);
  });

  test('returns absolute value (always non-negative)', () => {
    const stats = {};
    [10, 10, 10, 10, 10, 12].forEach(v => welfordUpdate(stats, 'v', v)); // slight variance
    // value far below mean — z still positive
    const z = computeZScore(stats, 'v', 1);
    expect(z).toBeGreaterThan(0);
  });

  test('returns 0.0 when stats is null', () => {
    expect(computeZScore(null, 'feat', 5)).toBe(0.0);
  });
});

/* ─────────────────────────────────────────────────────────────
   compositeScore
───────────────────────────────────────────────────────────── */
describe('compositeScore', () => {
  test('returns 0 for empty features', () => {
    expect(compositeScore({})).toBe(0.0);
    expect(compositeScore(null)).toBe(0.0);
  });

  test('RSS of single z_score=3.0 → 3.0', () => {
    const scored = { a: { z_score: 3.0 } };
    expect(compositeScore(scored)).toBeCloseTo(3.0);
  });

  test('RSS of [3, 4] → 5 (Pythagorean triple)', () => {
    const scored = { a: { z_score: 3 }, b: { z_score: 4 } };
    expect(compositeScore(scored)).toBeCloseTo(5.0);
  });

  test('caps at COMPOSITE_SCORE_CAP (10.0)', () => {
    const scored = {};
    for (let i = 0; i < 20; i++) scored[`f${i}`] = { z_score: 5.0 };
    expect(compositeScore(scored)).toBe(COMPOSITE_SCORE_CAP);
  });

  test('handles missing z_score key gracefully (treats as 0)', () => {
    const scored = { a: { value: 5 } };  // no z_score
    expect(compositeScore(scored)).toBe(0.0);
  });
});

/* ─────────────────────────────────────────────────────────────
   riskLevel
───────────────────────────────────────────────────────────── */
describe('riskLevel', () => {
  test('returns critical for score >= 6.0', () => {
    expect(riskLevel(6.0)).toBe('critical');
    expect(riskLevel(9.5)).toBe('critical');
    expect(riskLevel(10.0)).toBe('critical');
  });

  test('returns high for score in [4.0, 6.0)', () => {
    expect(riskLevel(4.0)).toBe('high');
    expect(riskLevel(5.9)).toBe('high');
  });

  test('returns medium for score in [threshold, 4.0) with default threshold 2.0', () => {
    expect(riskLevel(2.0)).toBe('medium');
    expect(riskLevel(3.9)).toBe('medium');
    expect(riskLevel(ANOMALY_THRESHOLD)).toBe('medium');
  });

  test('returns low for score below threshold', () => {
    expect(riskLevel(0.0)).toBe('low');
    expect(riskLevel(1.9)).toBe('low');
    expect(riskLevel(ANOMALY_THRESHOLD - 0.01)).toBe('low');
  });

  test('respects custom threshold parameter', () => {
    expect(riskLevel(3.0, 3.0)).toBe('medium');
    expect(riskLevel(2.9, 3.0)).toBe('low');
    expect(riskLevel(4.5, 3.0)).toBe('high');
  });
});

/* ─────────────────────────────────────────────────────────────
   extractAlertFeatures
───────────────────────────────────────────────────────────── */
describe('extractAlertFeatures', () => {
  test('produces numeric feature map from alert body', () => {
    const body = {
      severity: 'HIGH',
      mitre_technique: 'T1059',
      affected_assets: ['host1', 'host2'],
      metadata: { risk_score: 0.8, ioc_count: 3 },
    };
    const features = extractAlertFeatures(body);
    expect(typeof features.severity_score).toBe('number');
    expect(features.severity_score).toBe(3);   // HIGH → 3
    expect(features.has_mitre).toBe(1);
    expect(features.asset_count).toBe(2);
    expect(features.risk_score).toBeCloseTo(0.8);
    expect(features.ioc_count).toBe(3);
  });

  test('handles missing fields without throwing', () => {
    const features = extractAlertFeatures({ severity: 'MEDIUM' });
    expect(features.has_mitre).toBe(0);
    expect(features.asset_count).toBe(0);
    expect(features.risk_score).toBe(0);
    expect(features.ioc_count).toBe(0);
  });

  test('CRITICAL severity maps to 4', () => {
    const features = extractAlertFeatures({ severity: 'CRITICAL' });
    expect(features.severity_score).toBe(4);
  });

  test('LOW severity maps to 1', () => {
    const features = extractAlertFeatures({ severity: 'LOW' });
    expect(features.severity_score).toBe(1);
  });

  test('unknown severity defaults to MEDIUM (2)', () => {
    const features = extractAlertFeatures({ severity: 'BANANAS' });
    expect(features.severity_score).toBe(2);
  });
});

/* ─────────────────────────────────────────────────────────────
   Constants
───────────────────────────────────────────────────────────── */
describe('exported constants', () => {
  test('ANOMALY_THRESHOLD is 2.0', () => expect(ANOMALY_THRESHOLD).toBe(2.0));
  test('COMPOSITE_SCORE_CAP is 10.0', () => expect(COMPOSITE_SCORE_CAP).toBe(10.0));
  test('PEER_GROUP_MIN_SIZE is 5', () => expect(PEER_GROUP_MIN_SIZE).toBe(5));
});

/* ─────────────────────────────────────────────────────────────
   Full Welford round-trip (integration-style, no DB)
───────────────────────────────────────────────────────────── */
describe('Welford round-trip: baseline → score → composite → riskLevel', () => {
  test('anomaly detected after stable baseline + spike', () => {
    // Build baseline with variance: observations centred on 5 with small spread.
    // We need n>1 and non-zero M2 so that std > 0 before we check the spike.
    const stats = {};
    const baseline = [4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6];
    baseline.forEach(v => welfordUpdate(stats, 'logins', v));

    // Verify baseline has meaningful variance (std > 0)
    expect(stats.logins.std).toBeGreaterThan(0);

    // Spike: value = 50 — far above mean (~5) relative to std (~0.33)
    const z = computeZScore(stats, 'logins', 50);
    expect(z).toBeGreaterThan(ANOMALY_THRESHOLD);

    const scored    = { logins: { z_score: z } };
    const composite = compositeScore(scored);
    const risk      = riskLevel(composite);
    expect(['medium', 'high', 'critical']).toContain(risk);
  });

  test('no anomaly for value within 1 std of mean', () => {
    const stats = {};
    [10, 10, 10, 10, 10, 11, 9, 10].forEach(v => welfordUpdate(stats, 'v', v));
    const z = computeZScore(stats, 'v', 10.5); // well within 1 std
    expect(z).toBeLessThan(ANOMALY_THRESHOLD);
    const scored    = { v: { z_score: z } };
    const composite = compositeScore(scored);
    expect(riskLevel(composite)).toBe('low');
  });
});
