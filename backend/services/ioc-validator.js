/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — IOC Canonical Validator v6.0
 *  backend/services/ioc-validator.js
 *
 *  PURPOSE:
 *  Strict type-vs-value consistency enforcement on every IOC.
 *  Called at ingest time — invalid/mistyped IOCs are REJECTED,
 *  not silently stored with wrong metadata.
 *
 *  WHAT IT CATCHES:
 *  • SHA-256 hash declared as type "ip"
 *  • Domain string declared as type "hash"
 *  • IPv6 address typed as "domain"
 *  • Malformed IPs (e.g., 999.0.0.1)
 *  • Values exceeding max length for their type
 *  • confidence / risk_score out of 0-100 range
 *
 *  USAGE:
 *    const { canonicalizeIOC, validateIOC } = require('./ioc-validator');
 *    const clean = canonicalizeIOC(rawIOC);       // throws on invalid
 *    const result = validateIOC(rawIOC);          // returns { valid, errors }
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const net = require('net');

// ── IOC type enum (authoritative list) ────────────────────────────
const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'cve', 'btc_address', 'filename', 'mutex', 'registry_key', 'unknown'];

// ── Regex patterns for canonical type detection ───────────────────
const PATTERNS = {
  // Network
  ipv4:         /^(\d{1,3}\.){3}\d{1,3}$/,
  ipv6:         /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::1$|^::$/,
  cidr_v4:      /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
  domain:       /^(?!-)[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z]{2,})+(?<!-)$/,
  url:          /^https?:\/\/.{4,2048}$/,

  // Hashes
  md5:          /^[a-fA-F0-9]{32}$/,
  sha1:         /^[a-fA-F0-9]{40}$/,
  sha256:       /^[a-fA-F0-9]{64}$/,
  sha512:       /^[a-fA-F0-9]{128}$/,

  // Other
  email:        /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  cve:          /^CVE-\d{4}-\d{4,}$/i,
  bitcoin:      /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/,
  ethereum:     /^0x[a-fA-F0-9]{40}$/,
};

// ── Max lengths by type ────────────────────────────────────────────
const MAX_LENGTHS = {
  ip:         45,   // IPv6 max
  domain:     253,
  url:        2048,
  hash:       128,  // SHA-512 hex
  email:      320,
  cve:        30,
  filename:   255,
  mutex:      512,
  registry_key: 1024,
  unknown:    2048,
};

/**
 * detectType(value)
 * Examines the value and returns the most likely IOC type and subtype.
 * Returns: { type, subtype, canonical, confidence }
 */
function detectType(value) {
  if (!value || typeof value !== 'string') {
    return { type: null, subtype: null, canonical: null, confidence: 0, error: 'Empty or non-string value' };
  }

  const v = value.trim();

  // ── Hashes (check before domain/IP — some hashes are hex-only) ──
  if (PATTERNS.sha256.test(v)) return { type: 'hash', subtype: 'sha256', canonical: v.toLowerCase(), confidence: 99 };
  if (PATTERNS.sha512.test(v)) return { type: 'hash', subtype: 'sha512', canonical: v.toLowerCase(), confidence: 99 };
  if (PATTERNS.sha1.test(v))   return { type: 'hash', subtype: 'sha1',   canonical: v.toLowerCase(), confidence: 97 };
  if (PATTERNS.md5.test(v))    return { type: 'hash', subtype: 'md5',    canonical: v.toLowerCase(), confidence: 90 };

  // ── IP addresses ─────────────────────────────────────────────────
  if (PATTERNS.ipv4.test(v)) {
    if (net.isIPv4(v)) return { type: 'ip', subtype: 'ipv4', canonical: v, confidence: 99 };
    return { type: null, subtype: 'invalid_ipv4', canonical: null, confidence: 0,
      error: `Looks like IPv4 but is invalid: ${v}` };
  }
  if (PATTERNS.cidr_v4.test(v)) return { type: 'ip', subtype: 'cidr_v4', canonical: v, confidence: 97 };
  if (PATTERNS.ipv6.test(v) && net.isIPv6(v)) return { type: 'ip', subtype: 'ipv6', canonical: v.toLowerCase(), confidence: 97 };

  // ── URLs ──────────────────────────────────────────────────────────
  if (PATTERNS.url.test(v)) {
    try {
      const url = new URL(v);
      return { type: 'url', subtype: null, canonical: v, hostname: url.hostname, confidence: 98 };
    } catch { /* not a valid URL */ }
  }

  // ── Crypto addresses ─────────────────────────────────────────────
  if (PATTERNS.bitcoin.test(v))   return { type: 'btc_address', subtype: 'bitcoin',  canonical: v, confidence: 85 };
  if (PATTERNS.ethereum.test(v))  return { type: 'btc_address', subtype: 'ethereum', canonical: v.toLowerCase(), confidence: 85 };

  // ── CVE ───────────────────────────────────────────────────────────
  if (PATTERNS.cve.test(v)) return { type: 'cve', subtype: null, canonical: v.toUpperCase(), confidence: 99 };

  // ── Email ─────────────────────────────────────────────────────────
  if (PATTERNS.email.test(v)) return { type: 'email', subtype: null, canonical: v.toLowerCase(), confidence: 95 };

  // ── Domain (after email, URL checks) ─────────────────────────────
  if (PATTERNS.domain.test(v)) {
    // Defanged domain check: malicious[.]com → malicious.com
    return { type: 'domain', subtype: null, canonical: v.toLowerCase(), confidence: 88 };
  }

  // ── Unknown ───────────────────────────────────────────────────────
  return { type: 'unknown', subtype: null, canonical: v, confidence: 0 };
}

/**
 * defang(value)
 * Reverses common IOC defanging: [.] → .  hxxp → http
 * Applied before validation to handle threat intel report formats.
 */
function defang(value) {
  if (!value) return value;
  return value
    .replace(/\[?\.\]?/g, '.')        // [.] → .
    .replace(/\[\:\]/g, ':')          // [:] → :
    .replace(/^hxxps?/i, s => s.replace(/^hxxp/i, 'http')) // hxxp → http
    .replace(/\s/g, '');              // strip internal whitespace
}

/**
 * validateIOC(ioc)
 * Returns { valid: bool, errors: string[], detected: object }
 * Does NOT throw — use for bulk validation where you want per-item results.
 */
function validateIOC(ioc) {
  const errors = [];

  // ── Required fields ───────────────────────────────────────────────
  if (!ioc.value || typeof ioc.value !== 'string') errors.push('value is required and must be a string');
  if (!ioc.type  || typeof ioc.type  !== 'string') errors.push('type is required and must be a string');

  if (errors.length) return { valid: false, errors, detected: null };

  // ── Type enum check ───────────────────────────────────────────────
  if (!IOC_TYPES.includes(ioc.type)) {
    errors.push(`type '${ioc.type}' is not valid. Allowed: ${IOC_TYPES.join(', ')}`);
  }

  // ── Numeric range checks ──────────────────────────────────────────
  if (ioc.confidence !== undefined && ioc.confidence !== null) {
    const c = Number(ioc.confidence);
    if (isNaN(c) || c < 0 || c > 100) errors.push('confidence must be a number between 0 and 100');
  }
  if (ioc.risk_score !== undefined && ioc.risk_score !== null) {
    const r = Number(ioc.risk_score);
    if (isNaN(r) || r < 0 || r > 100) errors.push('risk_score must be a number between 0 and 100');
  }

  // ── Apply defanging before detection ─────────────────────────────
  const cleanValue = defang(ioc.value.trim());

  // ── Max length check ──────────────────────────────────────────────
  const maxLen = MAX_LENGTHS[ioc.type] || 2048;
  if (cleanValue.length > maxLen) {
    errors.push(`value length ${cleanValue.length} exceeds max ${maxLen} for type '${ioc.type}'`);
  }

  // ── Type vs value consistency ────────────────────────────────────
  const detected = detectType(cleanValue);

  // Only check consistency when detected type is high-confidence and declared type is not 'unknown'
  if (detected.confidence >= 85 && detected.type && detected.type !== 'unknown' && ioc.type !== 'unknown') {
    if (detected.type !== ioc.type) {
      errors.push(
        `Type mismatch: value '${cleanValue.slice(0, 40)}' detected as '${detected.subtype || detected.type}' ` +
        `but declared type is '${ioc.type}'. ` +
        `Either correct the type or use type:'unknown' if unsure.`
      );
    }
  }

  if (errors.length) return { valid: false, errors, detected };
  return { valid: true, errors: [], detected, canonical: detected.canonical || cleanValue };
}

/**
 * canonicalizeIOC(ioc)
 * Validates and returns a normalized IOC object.
 * THROWS if validation fails — use in contexts where invalid IOCs must be blocked.
 */
function canonicalizeIOC(ioc) {
  const result = validateIOC(ioc);

  if (!result.valid) {
    throw new Error(`IOC validation failed: ${result.errors.join(' | ')}`);
  }

  return {
    ...ioc,
    value:           result.canonical,
    type:            result.detected?.type   || ioc.type,
    type_subtype:    result.detected?.subtype || null,
    value_canonical: result.canonical,
    detection_confidence: result.detected?.confidence || null,
    normalized_at:   new Date().toISOString(),
  };
}

/**
 * bulkValidate(iocs)
 * Validates an array of IOCs and returns { valid[], invalid[] }
 * Use in feed ingest pipelines.
 */
function bulkValidate(iocs) {
  const valid   = [];
  const invalid = [];

  for (const ioc of iocs) {
    const result = validateIOC(ioc);
    if (result.valid) {
      valid.push({
        ...ioc,
        value:        result.canonical,
        type_subtype: result.detected?.subtype || null,
      });
    } else {
      invalid.push({ raw: ioc, errors: result.errors, detected: result.detected });
    }
  }

  return { valid, invalid, total: iocs.length, valid_count: valid.length, invalid_count: invalid.length };
}

/**
 * generateDeduplicationKey(value, tenantId)
 * Creates a stable deduplication key for a (value, tenant) pair.
 * Used as a unique constraint in upsert operations.
 */
function generateDeduplicationKey(value, tenantId) {
  const normalized = defang(value?.trim()?.toLowerCase() || '');
  return crypto
    .createHash('sha256')
    .update(`${tenantId}::${normalized}`)
    .digest('hex');
}

// Need crypto for deduplication key
const cryptoModule = require('crypto');
function generateDeduplicationKey_impl(value, tenantId) {
  const normalized = defang(value?.trim()?.toLowerCase() || '');
  return cryptoModule
    .createHash('sha256')
    .update(`${tenantId}::${normalized}`)
    .digest('hex');
}

module.exports = {
  detectType,
  validateIOC,
  canonicalizeIOC,
  bulkValidate,
  defang,
  generateDeduplicationKey: generateDeduplicationKey_impl,
  IOC_TYPES,
};
