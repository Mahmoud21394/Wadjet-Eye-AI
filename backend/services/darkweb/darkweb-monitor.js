/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Dark Web Intelligence Monitor (Phase 4)
 *  backend/services/darkweb/darkweb-monitor.js
 *
 *  Monitors:
 *  • Paste sites (Pastebin, Ghostbin, Rentry, Privatebin)
 *  • Ransomware leak sites (LockBit, ALPHV/BlackCat, Cl0p, Play, etc.)
 *  • Dark web forums (via Tor SOCKS5 proxy)
 *  • Org-mention alerts with scoring
 *  • Credential dump detection
 *
 *  Architecture:
 *  • All Tor requests route through socks5://tor:9050
 *  • Results published to Kafka topic: dark-web-intel
 *  • High-confidence findings create IOCs automatically
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const config = require('../../config');

// ── Known ransomware group onion sites (updated 2025) ─────────────
const RANSOMWARE_SITES = [
  { group: 'LockBit',       url: 'http://lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd.onion', type: 'clearweb_mirror' },
  { group: 'ALPHV/BlackCat', url: 'https://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion', type: 'tor' },
  { group: 'Cl0p',          url: 'http://santat7kpllt6iyvqbr7q4amdv6dzgoi3dq4iyhsf53skqshbehq7sid.onion', type: 'tor' },
  { group: 'Play',          url: 'http://mbrlkbtq5jonaqkurkmbxnxiczdngkwwl5uqah74n2muqeha5bz4yrqd.onion', type: 'tor' },
  { group: 'Hunters Int',   url: 'http://hunt777z2amemnyogyx4qo4rp6p6hjgjmn2axrjkwv7upz2atuz7vlad.onion', type: 'tor' },
  { group: 'RansomHub',     url: 'http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion', type: 'tor' },
  { group: 'Akira',         url: 'http://akirabaaz46b6ux57pu7qhuxcnpqv5sqgolonkv4a5wbotcxbhxk5ead.onion', type: 'tor' },
  { group: 'Rhysida',       url: 'http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4312gjdbid.onion', type: 'tor' },
];

// ── Paste-site endpoints (clearweb) ──────────────────────────────
const PASTE_SITES = [
  { name: 'Pastebin',   url: 'https://scrape.pastebin.com/api_scraping.php?limit=100', requires_key: true },
  { name: 'Pastecord',  url: 'https://pastecord.com/api/recent', requires_key: false },
  { name: 'Ghostbin',   url: 'https://ghostbin.com/api/v1/recent', requires_key: false },
];

// ── Credential-leak regex patterns ───────────────────────────────
const CREDENTIAL_PATTERNS = [
  /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:[^\s]{6,}/g,
  /\b(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
  /\b(?:api[_\-]?key|apikey|secret[_\-]?key)\s*[:=]\s*['""]?[A-Za-z0-9_\-]{20,}/gi,
];

// ── IOC extraction patterns ───────────────────────────────────────
const IOC_PATTERNS = {
  ipv4:    /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  domain:  /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|onion|ru|cn|xyz|top|info|biz)\b/gi,
  md5:     /\b[a-fA-F0-9]{32}\b/g,
  sha1:    /\b[a-fA-F0-9]{40}\b/g,
  sha256:  /\b[a-fA-F0-9]{64}\b/g,
  btcAddr: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  monero:  /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g,
};

// ── HTTP via Tor SOCKS5 proxy ─────────────────────────────────────
async function torRequest(url, opts = {}) {
  if (!config.darkweb.enabled) {
    return { success: false, error: 'Dark web monitoring disabled', data: null };
  }

  const SocksProxyAgent = (() => {
    try { return require('socks-proxy-agent').SocksProxyAgent; }
    catch { return null; }
  })();

  if (!SocksProxyAgent) {
    return { success: false, error: 'socks-proxy-agent not installed', data: null };
  }

  const agent = new SocksProxyAgent(config.darkweb.torProxy);
  const timeout = opts.timeout || 30000;

  return new Promise((resolve) => {
    const parsed   = new URL(url);
    const reqLib   = parsed.protocol === 'https:' ? https : http;
    const options  = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      agent,
      timeout,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
        ...opts.headers,
      },
    };

    const req = reqLib.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ success: true, status: res.statusCode, data: raw });
      });
    });

    req.on('error', err => resolve({ success: false, error: err.message, data: null }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'Tor request timeout', data: null });
    });
    req.end();
  });
}

// ── Clearweb HTTPS request ────────────────────────────────────────
async function clearwebRequest(url, opts = {}) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || 443,
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      timeout:  opts.timeout || 15000,
      headers: {
        'User-Agent': 'WadjetEye-ThreatIntelBot/2.0',
        ...opts.headers,
      },
    };

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({ success: true, status: res.statusCode, data: Buffer.concat(chunks).toString('utf8') });
      });
    });

    req.on('error', err => resolve({ success: false, error: err.message, data: null }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'Timeout', data: null }); });
    req.end();
  });
}

// ── Extract IOCs from text ────────────────────────────────────────
function extractIocs(text) {
  const iocs = {};
  for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
    const matches = [...new Set(text.matchAll(new RegExp(pattern.source, pattern.flags)))];
    if (matches.length > 0) {
      iocs[type] = matches.map(m => m[0]).slice(0, 50);
    }
  }
  return iocs;
}

// ── Extract credentials from text ────────────────────────────────
function extractCredentials(text) {
  const creds = [];
  for (const pattern of CREDENTIAL_PATTERNS) {
    const matches = text.matchAll(new RegExp(pattern.source, pattern.flags));
    for (const m of matches) {
      creds.push(m[0].substring(0, 200));
      if (creds.length >= 100) break;
    }
  }
  return [...new Set(creds)];
}

// ── Score relevance for org mentions ─────────────────────────────
function scoreRelevance(text, orgKeywords) {
  if (!orgKeywords || orgKeywords.length === 0) return 0;
  let score = 0;
  const lower = text.toLowerCase();
  for (const kw of orgKeywords) {
    const kwLower = kw.toLowerCase();
    const count   = (lower.match(new RegExp(kwLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
    score += count * 10;
  }
  return Math.min(score, 100);
}

// ── Monitor ransomware leak sites ─────────────────────────────────
async function scanRansomwareSites(orgKeywords = []) {
  const findings = [];

  for (const site of RANSOMWARE_SITES) {
    let result;
    if (site.type === 'tor') {
      result = await torRequest(site.url);
    } else {
      continue; // skip clearweb mirrors for now
    }

    if (!result.success || !result.data) continue;

    const text      = result.data;
    const iocs      = extractIocs(text);
    const relevance = scoreRelevance(text, orgKeywords);
    const hasOrgMention = relevance > 20;

    if (hasOrgMention || Object.keys(iocs).length > 0) {
      findings.push({
        id:          crypto.randomUUID(),
        source:      'ransomware_leak',
        group:       site.group,
        url:         site.url,
        severity:    hasOrgMention ? 'CRITICAL' : 'HIGH',
        relevance,
        iocs,
        snippet:     text.substring(0, 500),
        discovered:  new Date().toISOString(),
        type:        hasOrgMention ? 'ORG_MENTION' : 'NEW_VICTIM',
      });
    }
  }

  return findings;
}

// ── Monitor paste sites ───────────────────────────────────────────
async function scanPasteSites(orgKeywords = []) {
  const findings = [];

  for (const site of PASTE_SITES) {
    if (site.requires_key && !process.env.PASTEBIN_API_KEY) continue;

    const url = site.requires_key
      ? `${site.url}&scrape_key=${process.env.PASTEBIN_API_KEY}`
      : site.url;

    const result = await clearwebRequest(url);
    if (!result.success || !result.data) continue;

    let pastes = [];
    try {
      pastes = JSON.parse(result.data);
      if (!Array.isArray(pastes)) pastes = [pastes];
    } catch { continue; }

    for (const paste of pastes.slice(0, 50)) {
      const content = paste.content || paste.value || paste.text || '';
      if (!content) continue;

      const creds     = extractCredentials(content);
      const iocs      = extractIocs(content);
      const relevance = scoreRelevance(content, orgKeywords);

      if (creds.length > 0 || relevance > 30 || (iocs.sha256 && iocs.sha256.length > 0)) {
        findings.push({
          id:         crypto.randomUUID(),
          source:     'paste_site',
          siteName:   site.name,
          pasteKey:   paste.key || paste.id || 'unknown',
          pasteUrl:   paste.full_url || paste.url || url,
          severity:   relevance > 60 ? 'CRITICAL' : creds.length > 0 ? 'HIGH' : 'MEDIUM',
          relevance,
          credentials: creds.slice(0, 10),
          iocs,
          snippet:    content.substring(0, 300),
          discovered: new Date().toISOString(),
          type:       creds.length > 0 ? 'CREDENTIAL_DUMP' : 'ORG_MENTION',
        });
      }
    }
  }

  return findings;
}

// ── Full scan cycle ───────────────────────────────────────────────
async function runScanCycle(opts = {}) {
  const orgKeywords = opts.orgKeywords || (process.env.DARKWEB_ORG_KEYWORDS || '').split(',').map(s => s.trim()).filter(Boolean);
  const startTime   = Date.now();

  const [ransomFindings, pasteFindings] = await Promise.allSettled([
    scanRansomwareSites(orgKeywords),
    scanPasteSites(orgKeywords),
  ]);

  const findings = [
    ...(ransomFindings.status === 'fulfilled' ? ransomFindings.value : []),
    ...(pasteFindings.status  === 'fulfilled' ? pasteFindings.value  : []),
  ];

  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));

  return {
    scanId:      crypto.randomUUID(),
    startTime:   new Date(startTime).toISOString(),
    endTime:     new Date().toISOString(),
    durationMs:  Date.now() - startTime,
    totalFindings: findings.length,
    critical:    findings.filter(f => f.severity === 'CRITICAL').length,
    high:        findings.filter(f => f.severity === 'HIGH').length,
    findings,
  };
}

// ── Scheduled monitor ─────────────────────────────────────────────
let _scanInterval = null;

function startMonitor(opts = {}) {
  if (_scanInterval) return;
  const interval = opts.interval || config.darkweb.scanInterval;

  console.log(`[DarkWeb] Monitor started — interval: ${interval / 1000}s`);

  async function _scan() {
    try {
      const result = await runScanCycle(opts);
      console.log(`[DarkWeb] Scan complete — ${result.totalFindings} findings (${result.critical} critical)`);

      if (result.findings.length > 0 && opts.onFindings) {
        await opts.onFindings(result);
      }
    } catch (err) {
      console.error('[DarkWeb] Scan error:', err.message);
    }
  }

  _scan(); // immediate first run
  _scanInterval = setInterval(_scan, interval);
  return _scanInterval;
}

function stopMonitor() {
  if (_scanInterval) {
    clearInterval(_scanInterval);
    _scanInterval = null;
    console.log('[DarkWeb] Monitor stopped');
  }
}

module.exports = {
  runScanCycle,
  scanRansomwareSites,
  scanPasteSites,
  extractIocs,
  extractCredentials,
  scoreRelevance,
  startMonitor,
  stopMonitor,
};
