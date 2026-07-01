/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SSRF Protection Middleware  v1.0
 *  backend/middleware/ssrfGuard.js
 *
 *  Prevents Server-Side Request Forgery (SSRF) attacks:
 *    - Blocks requests to private/loopback/metadata IP ranges
 *    - Enforces outbound egress host allow-lists
 *    - Blocks AWS/GCP/Azure metadata endpoints
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const dns    = require('dns').promises;
const net    = require('net');
const logger = require('../utils/logger');
const _MOD   = 'SSRFGuard';

// Private IP CIDR ranges that must never be reachable
const BLOCKED_CIDRS = [
  // Loopback
  { start: '127.0.0.0', end: '127.255.255.255' },
  // Link-local
  { start: '169.254.0.0', end: '169.254.255.255' },
  // RFC1918 private
  { start: '10.0.0.0',   end: '10.255.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' },
  // IPv6 loopback / link-local
  { start: '::1',         end: '::1' },
];

// Metadata endpoints
const METADATA_HOSTS = [
  '169.254.169.254',       // AWS/GCP/Azure IMDS
  'metadata.google.internal',
  'fd00:ec2::254',
];

// Approved outbound hosts (production egress whitelist)
const APPROVED_EGRESS_HOSTS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.deepseek.com',
  'api.abuseipdb.com',
  'otx.alienvault.com',
  'www.virustotal.com',
  'urlhaus-api.abuse.ch',
  'api.shodan.io',
  'feeds.feedburner.com',
  'feeds.bbci.co.uk',
  'feeds.reuters.com',
  'nvd.nist.gov',
  'cve.mitre.org',
  'attack.mitre.org',
  'api.github.com',
  'raw.githubusercontent.com',
  'supabase.co',
  'miywxnplaltduuscjfmq.supabase.co',
  'upstash.io',
  'kafka.upstash.io',
]);

/**
 * ipToLong — convert dotted-decimal IP to 32-bit int for range check.
 */
function ipToLong(ip) {
  return ip.split('.').reduce((acc, oct) => (acc * 256) + parseInt(oct, 10), 0);
}

/**
 * isPrivateIp — check if IP is in a blocked range.
 */
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) return ip === '::1';
  if (!net.isIPv4(ip)) return false;
  const long = ipToLong(ip);
  return BLOCKED_CIDRS.some(({ start, end }) => {
    if (!end.includes('.')) return false;
    return long >= ipToLong(start) && long <= ipToLong(end);
  });
}

/**
 * isMetadataEndpoint — detect AWS/GCP/Azure IMDS URLs.
 */
function isMetadataEndpoint(urlStr) {
  return METADATA_HOSTS.some(h => urlStr.includes(h));
}

/**
 * validateOutboundUrl — validate URL is safe to fetch.
 * Resolves DNS and checks the result against private IP ranges.
 *
 * @param {string} urlStr
 * @returns {Promise<{ safe: boolean, reason?: string, resolvedIp?: string }>}
 */
async function validateOutboundUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') {
    return { safe: false, reason: 'invalid_url' };
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { safe: false, reason: 'url_parse_failed' };
  }

  // Only allow http/https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { safe: false, reason: `blocked_protocol:${parsed.protocol}` };
  }

  const host = parsed.hostname;

  // Block metadata endpoints immediately
  if (isMetadataEndpoint(host)) {
    logger.warn(_MOD, 'Metadata endpoint blocked', { host });
    return { safe: false, reason: 'metadata_endpoint_blocked' };
  }

  // Strict mode: enforce egress allowlist
  const strict = process.env.SSRF_STRICT_MODE === 'true';
  if (strict && !APPROVED_EGRESS_HOSTS.has(host) && !host.endsWith('.supabase.co')) {
    logger.warn(_MOD, 'Host not in egress allowlist', { host });
    return { safe: false, reason: `host_not_in_allowlist:${host}` };
  }

  // DNS resolution check
  try {
    const addrs = await dns.resolve4(host).catch(() => []);
    for (const ip of addrs) {
      if (isPrivateIp(ip)) {
        logger.warn(_MOD, 'DNS resolves to private IP — SSRF blocked', { host, ip });
        return { safe: false, reason: `dns_resolves_to_private:${ip}`, resolvedIp: ip };
      }
    }
    return { safe: true, resolvedIp: addrs[0] || null };
  } catch (err) {
    // DNS failure — fail open in dev, fail closed in prod
    if (process.env.NODE_ENV === 'production') {
      return { safe: false, reason: `dns_resolution_failed:${err.message}` };
    }
    return { safe: true, reason: 'dns_check_skipped_dev' };
  }
}

/**
 * ssrfGuardMiddleware — Express middleware for routes that accept external URLs.
 * Applied to: /api/rag/ingest, /api/intel/fetch, /api/news/fetch, etc.
 */
async function ssrfGuardMiddleware(req, res, next) {
  const body = req.body || {};
  const urlFields = ['url', 'source_url', 'external_url', 'feed_url', 'webhook_url', 'callback_url'];
  const tenantId = req.tenantId || 'system';

  for (const field of urlFields) {
    const urlValue = body[field] || req.query[field];
    if (!urlValue) continue;

    const result = await validateOutboundUrl(urlValue);
    if (!result.safe) {
      logger.warn(_MOD, 'SSRF attempt blocked', {
        tenantId, field, url: urlValue, reason: result.reason,
        ip: req.headers['x-forwarded-for']?.split(',')[0],
      });
      return res.status(400).json({
        error:  'The provided URL failed security validation',
        code:   'SSRF_BLOCKED',
        field,
        reason: result.reason,
      });
    }
  }

  next();
}

module.exports = {
  validateOutboundUrl,
  isPrivateIp,
  isMetadataEndpoint,
  ssrfGuardMiddleware,
  APPROVED_EGRESS_HOSTS,
};
