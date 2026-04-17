/**
 * @wadjet-eye/shared
 * Shared utilities used across all apps and packages.
 */
'use strict';

const crypto = require('crypto');

// ── Secret masking ────────────────────────────────────────────────
const SECRET_PATTERNS = [
  { re: /(sk-proj-[A-Za-z0-9_-]{10})[A-Za-z0-9_-]*/g,      mask: '$1***' },
  { re: /(sk-ant-api03-[A-Za-z0-9_-]{8})[A-Za-z0-9_-]*/g,  mask: '$1***' },
  { re: /(AIzaSy[A-Za-z0-9_-]{8})[A-Za-z0-9_-]*/g,         mask: '$1***' },
  { re: /(Bearer\s+[A-Za-z0-9._-]{8})[A-Za-z0-9._-]*/g,    mask: '$1***' },
  { re: /("password"\s*:\s*")[^"]+/g,                        mask: '$1[REDACTED]' },
  { re: /("api_key"\s*:\s*")[^"]+/g,                         mask: '$1[REDACTED]' },
];

function maskSecrets(str) {
  if (typeof str !== 'string') {
    try { str = JSON.stringify(str); } catch { return '[unserializable]'; }
  }
  for (const { re, mask } of SECRET_PATTERNS) {
    str = str.replace(re, mask);
  }
  return str;
}

// ── Correlation ID ────────────────────────────────────────────────
function genCorrelationId() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return crypto.randomBytes(16).toString('hex');
}

// ── Safe JSON parse ───────────────────────────────────────────────
function safeJson(str, fallback = null) {
  try { return JSON.parse(str); } catch { return fallback; }
}

// ── Sleep helper ─────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Exponential backoff ───────────────────────────────────────────
function backoff(attempt, baseMs = 500, maxMs = 30000) {
  const delay = Math.min(baseMs * Math.pow(2, attempt), maxMs);
  return delay * (0.8 + Math.random() * 0.4); // ±20% jitter
}

// ── Constants ─────────────────────────────────────────────────────
const SEVERITY_LEVELS = Object.freeze({
  LOW:      1,
  MEDIUM:   2,
  HIGH:     3,
  CRITICAL: 4,
});

const IOC_TYPES = Object.freeze(['ip', 'domain', 'url', 'hash', 'email']);

module.exports = {
  maskSecrets,
  genCorrelationId,
  safeJson,
  sleep,
  backoff,
  SEVERITY_LEVELS,
  IOC_TYPES,
};
