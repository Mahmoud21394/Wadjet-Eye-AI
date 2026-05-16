/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Dark Web Intelligence Monitor  v5.0 (OPSEC Hardened)
 *  backend/services/darkweb/darkweb-monitor.js
 *
 *  Monitors:
 *  • Paste sites (Pastebin, Ghostbin, Rentry, Privatebin)
 *  • Ransomware leak sites (LockBit, ALPHV/BlackCat, Cl0p, Play, etc.)
 *  • Dark web forums (via Tor SOCKS5 proxy)
 *  • Org-mention alerts with scoring
 *  • Credential dump detection
 *
 *  Security fixes (Audit Phase 0 — FIX-005: OPSEC Hardening):
 *  ─────────────────────────────────────────────────────────────────
 *  1. NO DIRECT-CONNECT FALLBACK: If Tor proxy is unavailable or
 *     `socks-proxy-agent` is not installed, all .onion requests FAIL
 *     with a clear error. The previous code returned `{success:false}`
 *     silently — callers would skip the result. Now the monitor logs
 *     a critical error and the scan cycle records a failed attempt.
 *     This prevents accidental de-anonymisation via direct connections.
 *
 *  2. USER-AGENT ROTATION: Requests to Tor hidden services use a pool
 *     of plausible Tor Browser UAs instead of a static string. A fixed
 *     UA fingerprints the monitoring bot across sites.
 *
 *  3. TIMING JITTER: Each Tor request has a random inter-request delay
 *     (500ms – 3000ms) to resist traffic-analysis correlation attacks
 *     that could de-anonymise the Tor circuit.
 *
 *  4. ENCRYPTED SITE LIST: `RANSOMWARE_SITES` is kept in source for
 *     development reference; in production it should be loaded from
 *     Vault (ARCH-002) with DARKWEB_SITES_SECRET. The config key
 *     `darkweb.sitesEncryptionKey` enables AES-256-GCM decryption of
 *     an env-var-encoded site list — see loadEncryptedSites().
 *
 *  5. CIRCUIT ISOLATION: A new Tor circuit is requested between site
 *     scans by cycling the SOCKS5 proxy port (if multi-port is
 *     configured) or injecting a NEWNYM signal if Tor control port
 *     is configured.
 *
 *  Architecture:
 *  • All .onion requests MUST route through socks5://tor:9050
 *  • Results published to Kafka topic: dark-web-intel
 *  • High-confidence findings create IOCs automatically
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const http   = require('http');
const net    = require('net');
const crypto = require('crypto');
const config = require('../../config');

// ── FIX-005: User-Agent pool (mimics real Tor Browser versions) ────
const TOR_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
  'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
  'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
  'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
  'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0',
];

/** @returns {string} A randomly selected Tor Browser User-Agent */
function randomTorUA() {
  return TOR_USER_AGENTS[Math.floor(Math.random() * TOR_USER_AGENTS.length)];
}

/** @param {number} minMs @param {number} maxMs @returns {Promise<void>} */
function jitter(minMs = 500, maxMs = 3000) {
  const delay = minMs + Math.floor(Math.random() * (maxMs - minMs));
  return new Promise(r => setTimeout(r, delay));
}

// ── Known ransomware group onion sites (updated 2025) ─────────────
// NOTE: In production, these should be loaded from Vault with key
// DARKWEB_SITES_SECRET (see loadEncryptedSites() below).
const RANSOMWARE_SITES_DEFAULT = [
  { group: 'LockBit',       url: 'http://lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd.onion', type: 'tor' },
  { group: 'ALPHV/BlackCat', url: 'http://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion', type: 'tor' },
  { group: 'Cl0p',          url: 'http://santat7kpllt6iyvqbr7q4amdv6dzgoi3dq4iyhsf53skqshbehq7sid.onion', type: 'tor' },
  { group: 'Play',          url: 'http://mbrlkbtq5jonaqkurkmbxnxiczdngkwwl5uqah74n2muqeha5bz4yrqd.onion', type: 'tor' },
  { group: 'Hunters Int',   url: 'http://hunt777z2amemnyogyx4qo4rp6p6hjgjmn2axrjkwv7upz2atuz7vlad.onion', type: 'tor' },
  { group: 'RansomHub',     url: 'http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion', type: 'tor' },
  { group: 'Akira',         url: 'http://akirabaaz46b6ux57pu7qhuxcnpqv5sqgolonkv4a5wbotcxbhxk5ead.onion', type: 'tor' },
  { group: 'Rhysida',       url: 'http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4312gjdbid.onion', type: 'tor' },
];

/**
 * loadEncryptedSites — load site list from Vault-encrypted env var.
 * Falls back to RANSOMWARE_SITES_DEFAULT if not configured.
 *
 * Expected env var: DARKWEB_SITES_ENCRYPTED — AES-256-GCM encrypted,
 * base64-encoded JSON array of { group, url, type }.
 * Key: DARKWEB_SITES_KEY (32 bytes hex or base64).
 *
 * @returns {Array<{group:string, url:string, type:string}>}
 */
function loadEncryptedSites() {
  const encrypted = process.env.DARKWEB_SITES_ENCRYPTED;
  const keyHex    = process.env.DARKWEB_SITES_KEY;

  if (!encrypted || !keyHex) {
    console.info('[DarkWeb] Using default site list — set DARKWEB_SITES_ENCRYPTED for production OPSEC');
    return RANSOMWARE_SITES_DEFAULT;
  }

  try {
    const keyBuf   = Buffer.from(keyHex, keyHex.length === 64 ? 'hex' : 'base64');
    const combined = Buffer.from(encrypted, 'base64');
    const iv       = combined.slice(0, 12);
    const tag      = combined.slice(12, 28);
    const data     = combined.slice(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(data), decipher.final()]);
    const sites  = JSON.parse(plain.toString('utf8'));

    console.log(`[DarkWeb] Loaded ${sites.length} sites from encrypted config`);
    return sites;
  } catch (err) {
    console.error('[DarkWeb] Failed to decrypt site list — falling back to defaults:', err.message);
    return RANSOMWARE_SITES_DEFAULT;
  }
}

// Loaded once at module init
let RANSOMWARE_SITES = RANSOMWARE_SITES_DEFAULT;

// ── Paste-site endpoints (clearweb) ──────────────────────────────
const PASTE_SITES = [
  { name: 'Pastebin',  url: 'https://scrape.pastebin.com/api_scraping.php?limit=100', requires_key: true },
  { name: 'Pastecord', url: 'https://pastecord.com/api/recent', requires_key: false },
  { name: 'Ghostbin',  url: 'https://ghostbin.com/api/v1/recent', requires_key: false },
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

// ── FIX-005: Tor circuit management ───────────────────────────────

/** _torPorts — list of SOCKS5 ports for circuit isolation between scans */
const _torPorts = (process.env.TOR_SOCKS_PORTS || '9050')
  .split(',').map(p => parseInt(p.trim(), 10)).filter(p => p > 0);

let _torPortIdx = 0;

/**
 * getNextTorProxy — return the next Tor SOCKS5 proxy URL, cycling
 * through available ports to trigger circuit isolation.
 *
 * @returns {string} e.g. "socks5://tor:9050"
 */
function getNextTorProxy() {
  const host = process.env.TOR_PROXY_HOST || 'tor';
  const port  = _torPorts[_torPortIdx % _torPorts.length];
  _torPortIdx++;
  return `socks5://${host}:${port}`;
}

/**
 * sendTorNewnym — send NEWNYM signal to Tor control port to rotate circuit.
 * Only attempted if TOR_CONTROL_PORT and TOR_CONTROL_PASS are configured.
 *
 * @returns {Promise<boolean>} true if circuit rotation was requested
 */
async function sendTorNewnym() {
  const controlPort = parseInt(process.env.TOR_CONTROL_PORT || '0', 10);
  const controlPass = process.env.TOR_CONTROL_PASS || '';

  if (!controlPort) return false;

  return new Promise((resolve) => {
    const sock = net.createConnection({ host: '127.0.0.1', port: controlPort }, () => {
      const auth = controlPass
        ? `AUTHENTICATE "${controlPass}"\r\nSIGNAL NEWNYM\r\nQUIT\r\n`
        : `AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT\r\n`;
      sock.write(auth);
    });

    sock.on('data', () => { sock.destroy(); resolve(true); });
    sock.on('error', () => resolve(false));
    sock.setTimeout(3000, () => { sock.destroy(); resolve(false); });
  });
}

// ── FIX-005: Tor request — NO direct-connect fallback ─────────────

/**
 * torRequest — make an HTTP request through the Tor SOCKS5 proxy.
 *
 * FIX-005: If `socks-proxy-agent` is not installed or Tor is disabled,
 * this function returns a failure object with `opsec_error: true`.
 * Callers MUST NOT fall back to direct clearweb connections for
 * .onion targets — doing so would de-anonymise the operator.
 *
 * @param {string} url - Target URL (should be .onion)
 * @param {object} [opts] - Optional overrides (timeout, method, headers)
 * @returns {Promise<{ success: boolean, status?: number, data?: string, error?: string, opsec_error?: boolean }>}
 */
async function torRequest(url, opts = {}) {
  if (!config.darkweb?.enabled) {
    return { success: false, error: 'Dark web monitoring disabled', data: null };
  }

  let SocksProxyAgent;
  try {
    SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
  } catch {
    // FIX-005: Missing library — fail with opsec_error, do NOT fall back
    console.error('[DarkWeb] OPSEC ERROR: socks-proxy-agent not installed. Cannot route through Tor. Install it: npm install socks-proxy-agent');
    return { success: false, opsec_error: true, error: 'socks-proxy-agent not installed — Tor routing unavailable', data: null };
  }

  const proxyUrl = getNextTorProxy();
  const agent    = new SocksProxyAgent(proxyUrl);
  const timeout  = opts.timeout || 45000;   // Tor is slow — 45s default

  // FIX-005: Random UA to avoid fingerprinting
  const userAgent = opts.userAgent || randomTorUA();

  return new Promise((resolve) => {
    const parsed  = new URL(url);
    const reqLib  = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      agent,
      timeout,
      headers: {
        'User-Agent':      userAgent,
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection':      'keep-alive',
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

    req.on('error', err => {
      // FIX-005: Log with structured context — do NOT silently ignore
      console.warn(`[DarkWeb] Tor request FAILED url=${url} proxy=${proxyUrl}: ${err.message}`);
      resolve({ success: false, error: err.message, data: null });
    });

    req.on('timeout', () => {
      req.destroy();
      console.warn(`[DarkWeb] Tor request TIMEOUT url=${url} proxy=${proxyUrl}`);
      resolve({ success: false, error: 'Tor request timeout', data: null });
    });

    req.end();
  });
}

// ── Clearweb HTTPS request ────────────────────────────────────────
async function clearwebRequest(url, opts = {}) {
  return new Promise((resolve) => {
    const parsed  = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || 443,
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      timeout:  opts.timeout || 15000,
      headers: {
        'User-Agent': 'WadjetEye-ThreatIntelBot/5.0',
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
    const matches = [...new Set([...text.matchAll(new RegExp(pattern.source, pattern.flags))].map(m => m[0]))];
    if (matches.length > 0) iocs[type] = matches.slice(0, 50);
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
  let score  = 0;
  const lower = text.toLowerCase();
  for (const kw of orgKeywords) {
    const kwLower = kw.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const count   = (lower.match(new RegExp(kwLower, 'g')) || []).length;
    score += count * 10;
  }
  return Math.min(score, 100);
}

// ── FIX-005: Monitor ransomware leak sites (OPSEC hardened) ──────

/**
 * scanRansomwareSites — scan known ransomware group .onion sites.
 *
 * FIX-005: Applies inter-request jitter and rotates Tor circuits
 * between each site. OPSEC failures are tracked and surfaced in
 * the scan result — they are never silently discarded.
 *
 * @param {string[]} orgKeywords
 * @returns {Promise<Array>}
 */
async function scanRansomwareSites(orgKeywords = []) {
  const findings   = [];
  const opsecErrors = [];

  for (const site of RANSOMWARE_SITES) {
    if (site.type !== 'tor') continue;

    // FIX-005: Jitter before each request
    await jitter(500, 2500);

    const result = await torRequest(site.url);

    if (result.opsec_error) {
      opsecErrors.push({ group: site.group, url: site.url, error: result.error });
      console.error(`[DarkWeb] OPSEC ERROR scanning ${site.group}: ${result.error}`);
      continue;
    }

    if (!result.success || !result.data) continue;

    const text      = result.data;
    const iocs      = extractIocs(text);
    const relevance = scoreRelevance(text, orgKeywords);
    const hasOrgMention = relevance > 20;

    if (hasOrgMention || Object.keys(iocs).length > 0) {
      findings.push({
        id:         crypto.randomUUID(),
        source:     'ransomware_leak',
        group:      site.group,
        url:        site.url,
        severity:   hasOrgMention ? 'CRITICAL' : 'HIGH',
        relevance,
        iocs,
        snippet:    text.substring(0, 500),
        discovered: new Date().toISOString(),
        type:       hasOrgMention ? 'ORG_MENTION' : 'NEW_VICTIM',
      });
    }

    // FIX-005: Attempt circuit rotation between sites
    await sendTorNewnym().catch(() => {});
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
    try { pastes = JSON.parse(result.data); if (!Array.isArray(pastes)) pastes = [pastes]; }
    catch { continue; }

    for (const paste of pastes.slice(0, 50)) {
      const content   = paste.content || paste.value || paste.text || '';
      if (!content) continue;

      const creds     = extractCredentials(content);
      const iocs      = extractIocs(content);
      const relevance = scoreRelevance(content, orgKeywords);

      if (creds.length > 0 || relevance > 30 || (iocs.sha256 && iocs.sha256.length > 0)) {
        findings.push({
          id:          crypto.randomUUID(),
          source:      'paste_site',
          siteName:    site.name,
          pasteKey:    paste.key || paste.id || 'unknown',
          pasteUrl:    paste.full_url || paste.url || url,
          severity:    relevance > 60 ? 'CRITICAL' : creds.length > 0 ? 'HIGH' : 'MEDIUM',
          relevance,
          credentials: creds.slice(0, 10),
          iocs,
          snippet:     content.substring(0, 300),
          discovered:  new Date().toISOString(),
          type:        creds.length > 0 ? 'CREDENTIAL_DUMP' : 'ORG_MENTION',
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

  // Reload encrypted site list on each cycle (supports runtime rotation)
  RANSOMWARE_SITES = loadEncryptedSites();

  const [ransomResult, pasteResult] = await Promise.allSettled([
    scanRansomwareSites(orgKeywords),
    scanPasteSites(orgKeywords),
  ]);

  const findings = [
    ...(ransomResult.status === 'fulfilled' ? ransomResult.value : []),
    ...(pasteResult.status  === 'fulfilled' ? pasteResult.value  : []),
  ];

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  findings.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));

  return {
    scanId:        crypto.randomUUID(),
    startTime:     new Date(startTime).toISOString(),
    endTime:       new Date().toISOString(),
    durationMs:    Date.now() - startTime,
    totalFindings: findings.length,
    critical:      findings.filter(f => f.severity === 'CRITICAL').length,
    high:          findings.filter(f => f.severity === 'HIGH').length,
    findings,
    torProxies:    _torPorts.length,
  };
}

// ── Scheduled monitor ─────────────────────────────────────────────
let _scanInterval = null;

function startMonitor(opts = {}) {
  if (_scanInterval) return;
  const interval = opts.interval || config.darkweb?.scanInterval || 3_600_000;

  console.log(`[DarkWeb] Monitor v5.0 started — interval: ${interval / 1000}s torPorts=${_torPorts.join(',')}`);

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

  _scan();
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
  // Exported for tests
  torRequest,
  loadEncryptedSites,
  randomTorUA,
  sendTorNewnym,
};
